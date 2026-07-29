import { Buffer } from "node:buffer";
import type { KeyObject } from "node:crypto";
import { isProxy } from "node:util/types";
import {
  parseBoundedJson,
  type BoundedJsonLimits,
  type ByteChunkSource,
} from "../bounded-input.js";
import { canonicalJsonBytes } from "../determinism.js";
import {
  createStudyPayloadIdentity,
  type KeyedPayloadIdentity,
} from "../references.js";
import {
  sanitizeErrorForPersistence,
  type PersistedError,
} from "../redaction.js";
import {
  normalizeRuntimeInvocationHttpLimits,
} from "../runtime-http-limits.js";
import {
  DEFAULT_RUNTIME_HTTP_LIMITS,
  RuntimeWireError,
  withBoundedHttpResponse,
  type BoundedRuntimeHttpResponse,
  type RuntimeHttpLimits,
  type RuntimeSecretHeaderFactory,
  type RuntimeWireDispatchState,
  type RuntimeWireTiming,
} from "./http.js";
import {
  authorizeCollectorRequest,
  fingerprintCollectorEndpointBinding,
  pinAuthorizedCollectorRequest,
  type CollectorTrustPolicy,
} from "./network-policy.js";
import { parseEndpointDescriptor } from "./orchestration.js";
import {
  getRuntimeProfile,
  parseRuntimeInstanceIdentity,
} from "./profiles.js";
import {
  verifyRuntimeCapabilityAuthorization,
  type RuntimeCapabilityAuthorization,
} from "./probe.js";
import {
  DEFAULT_NDJSON_STREAM_LIMITS,
  parseBoundedNdjsonStream,
  type NdjsonStreamParseResult,
} from "./ndjson.js";
import {
  DEFAULT_SSE_LIMITS,
  parseBoundedJsonSse,
  parseBoundedSse,
  type JsonSseParseResult,
  type RuntimeStreamIdentity,
  type RuntimeStreamTiming,
  type SseParseResult,
} from "./sse.js";
import type {
  EndpointDescriptor,
  RuntimeInferenceRoute,
  RuntimeInstanceIdentity,
  RuntimeProfileId,
} from "./types.js";

export type { RuntimeCapabilityAuthorization } from "./probe.js";

export const RUNTIME_INVOCATION_VERSION =
  "tasc-runtime-invocation-v1" as const;
export const PREPARED_RUNTIME_INVOCATION_VERSION =
  "tasc-prepared-runtime-invocation-v1" as const;
export const RUNTIME_INVOCATION_DESCRIPTION_VERSION =
  "tasc-runtime-invocation-description-v1" as const;

export type RuntimeInvocationRoute =
  | "chatCompletions"
  | "completions"
  | "responses"
  | "nativeChat"
  | "nativeGenerate";

export interface RuntimeRequestedModel {
  readonly id: string;
  readonly revision: string;
}

export interface RuntimeChatMessage {
  readonly role: "system" | "user" | "assistant";
  readonly content: string;
}

export interface RuntimeGenerationRequest {
  readonly model: RuntimeRequestedModel;
  readonly stream: boolean;
  readonly n: 1;
  readonly messages?: readonly RuntimeChatMessage[];
  readonly prompt?: string;
  readonly maxTokens: number;
  readonly temperature?: number;
  readonly topP?: number;
  readonly seed?: number;
  readonly stop?: string | readonly string[];
}

export interface RuntimeInvocationInput {
  readonly policy: CollectorTrustPolicy;
  readonly endpointAlias: string;
  readonly endpointDescriptor?: EndpointDescriptor;
  readonly instance: RuntimeInstanceIdentity;
  readonly capabilityAuthorizations?: readonly RuntimeCapabilityAuthorization[];
  readonly route: RuntimeInvocationRoute;
  readonly generation: RuntimeGenerationRequest;
  readonly identity: RuntimeStreamIdentity;
  readonly totalDeadlineMs: number;
  readonly authenticationReference?: string;
  readonly secretHeaderFactory?: RuntimeSecretHeaderFactory;
  readonly signal?: AbortSignal;
  readonly httpLimits?: Partial<RuntimeHttpLimits>;
}

/**
 * Durable, payload-free dispatch-intent material.
 *
 * Visible fields are metadata only. Dispatch authority remains in a
 * module-private WeakMap and cannot survive cloning or serialization.
 */
export interface PreparedRuntimeInvocation {
  readonly schemaVersion: typeof PREPARED_RUNTIME_INVOCATION_VERSION;
  readonly endpointBindingDigest: string;
  readonly profile: {
    readonly id: RuntimeProfileId;
    readonly build: string;
  };
  readonly route: RuntimeInvocationRoute;
  readonly requestedModel: RuntimeRequestedModel;
  readonly requestIdentity: KeyedPayloadIdentity;
  readonly requestByteCount: number;
}

/**
 * Exact payload-free request metadata with no dispatch authority.
 *
 * This is safe for whole-run work admission, including for a conditional
 * route whose live capability authorization has not been minted.
 */
export interface RuntimeInvocationDescription {
  readonly schemaVersion: typeof RUNTIME_INVOCATION_DESCRIPTION_VERSION;
  readonly endpointBindingDigest: string;
  readonly profile: {
    readonly id: RuntimeProfileId;
    readonly build: string;
  };
  readonly route: RuntimeInvocationRoute;
  readonly requestedModel: RuntimeRequestedModel;
  readonly requestIdentity: KeyedPayloadIdentity;
  readonly requestByteCount: number;
}

export interface RuntimeProviderUsage {
  readonly inputTokens: number | null;
  readonly outputTokens: number | null;
  readonly totalTokens: number | null;
}

export interface RuntimeProviderTiming {
  readonly totalDurationNs?: number;
  readonly loadDurationNs?: number;
  readonly promptEvaluationDurationNs?: number;
  readonly evaluationDurationNs?: number;
}

export interface RuntimeInvocationOutput {
  /** Ephemeral normalized output. Do not persist this object directly. */
  readonly text: string;
  readonly metadata: {
    readonly choiceCount: 1;
    readonly logprobsObserved: boolean;
  };
}

export type RuntimeInvocationStatus =
  | "completed"
  | "incomplete"
  | "failed";

export type RuntimeAbortLifecycle =
  | "not-aborted"
  | "caller-cancelled-before-dispatch"
  | "caller-cancelled-after-dispatch-ambiguous"
  | "deadline-exceeded";

export interface RuntimeInvocationPersistence {
  readonly schemaVersion: "tasc-runtime-invocation-persistence-v1";
  readonly status: RuntimeInvocationStatus;
  readonly endpointBindingDigest: string;
  readonly profile: {
    readonly id: RuntimeProfileId;
    readonly build: string;
  };
  readonly route: RuntimeInvocationRoute;
  readonly requestedModel: RuntimeRequestedModel;
  readonly resolvedModel: {
    readonly id: string;
    readonly revision: string | null;
    readonly verification: "provider-reported";
  } | null;
  readonly requestIdentity: KeyedPayloadIdentity;
  readonly responseIdentity: KeyedPayloadIdentity | null;
  readonly eventStreamIdentity: KeyedPayloadIdentity | null;
  readonly terminalOutputIdentity: KeyedPayloadIdentity | null;
  readonly finishReason: string | null;
  readonly providerUsage: RuntimeProviderUsage | null;
  readonly providerTiming: RuntimeProviderTiming;
  readonly finalUsage: "present" | "missing";
  readonly partialOutput: boolean;
  readonly dispatchState: RuntimeWireDispatchState;
  readonly abortLifecycle: RuntimeAbortLifecycle;
  readonly wireTiming: RuntimeWireTiming | null;
  readonly streamTiming: RuntimeStreamTiming | null;
  readonly error: PersistedError | null;
}

export interface RuntimeInvocationOutcome {
  readonly schemaVersion: typeof RUNTIME_INVOCATION_VERSION;
  readonly status: RuntimeInvocationStatus;
  readonly output: RuntimeInvocationOutput | null;
  readonly persistence: RuntimeInvocationPersistence;
}

export type RuntimeInvocationInputErrorCode =
  | "INVALID_INPUT"
  | "ENDPOINT_BINDING_MISMATCH"
  | "UNSUPPORTED_ROUTE"
  | "CONDITIONAL_CAPABILITY_REQUIRES_AUTHORIZATION"
  | "CAPABILITY_AUTHORIZATION_REJECTED"
  | "PREPARED_INVOCATION_EXPIRED"
  | "PREPARED_INVOCATION_REJECTED";

const INPUT_ERROR_MESSAGES: Readonly<
  Record<RuntimeInvocationInputErrorCode, string>
> = Object.freeze({
  INVALID_INPUT: "Runtime invocation input is invalid.",
  ENDPOINT_BINDING_MISMATCH:
    "Runtime invocation instance does not match the authorized endpoint.",
  UNSUPPORTED_ROUTE: "Runtime invocation route is not supported.",
  CONDITIONAL_CAPABILITY_REQUIRES_AUTHORIZATION:
    "Runtime invocation requires an authentic live capability authorization.",
  CAPABILITY_AUTHORIZATION_REJECTED:
    "Runtime invocation capability authorization was rejected.",
  PREPARED_INVOCATION_EXPIRED:
    "Prepared runtime invocation deadline expired before dispatch.",
  PREPARED_INVOCATION_REJECTED:
    "Prepared runtime invocation authority was rejected.",
});

/** A constant-safe boundary failure that never represents a sent request. */
export class RuntimeInvocationInputError extends Error {
  readonly code: RuntimeInvocationInputErrorCode;
  readonly dispatchState = "not_sent" as const;
  readonly persistedError: PersistedError;

  constructor(code: RuntimeInvocationInputErrorCode) {
    super(INPUT_ERROR_MESSAGES[code]);
    this.name = "RuntimeInvocationInputError";
    this.code = code;
    this.persistedError = sanitizeErrorForPersistence({
      category:
        code === "PREPARED_INVOCATION_EXPIRED"
          ? "timeout"
          : code === "CONDITIONAL_CAPABILITY_REQUIRES_AUTHORIZATION"
          || code === "CAPABILITY_AUTHORIZATION_REJECTED"
          || code === "PREPARED_INVOCATION_REJECTED"
          ? "authorization"
          : "internal",
    });
    Object.freeze(this);
  }
}

interface NormalizedInvocation {
  readonly policy: CollectorTrustPolicy;
  readonly endpointAlias: string;
  readonly endpointDescriptor?: EndpointDescriptor;
  readonly instance: RuntimeInstanceIdentity;
  readonly profileId: RuntimeProfileId;
  readonly profileBuild: string;
  readonly routeKey: RuntimeInvocationRoute;
  readonly route: RuntimeInferenceRoute;
  readonly capabilityAuthorization?: RuntimeCapabilityAuthorization;
  readonly requestPath: string;
  readonly generation: RuntimeGenerationRequest;
  readonly identity: RuntimeStreamIdentity;
  readonly endpointBindingDigest: string;
  readonly requestBytes: Uint8Array;
  readonly requestIdentity: KeyedPayloadIdentity;
  readonly framing: "json" | "sse" | "ndjson";
  readonly totalDeadlineMs: number;
  readonly authenticationReference?: string;
  readonly secretHeaderFactory?: RuntimeSecretHeaderFactory;
  readonly signal?: AbortSignal;
  readonly httpLimits: RuntimeHttpLimits;
}

interface PreparedInvocationAuthority {
  readonly invocation: NormalizedInvocation;
  readonly expiresAtNs: bigint;
  consumed: boolean;
}

const preparedInvocationAuthorities = new WeakMap<
  PreparedRuntimeInvocation,
  PreparedInvocationAuthority
>();

interface NormalizedProviderResult {
  readonly text: string;
  readonly resolvedModelId: string | null;
  readonly finishReason: string | null;
  readonly usage: RuntimeProviderUsage | null;
  readonly providerTiming: RuntimeProviderTiming;
  readonly logprobsObserved: boolean;
  readonly terminal:
    | "complete"
    | "truncated"
    | "provider-error"
    | "invalid";
  readonly finalUsage: "present" | "missing";
  readonly streamTiming: RuntimeStreamTiming | null;
}

interface DecodedHttpResponse {
  readonly normalized: NormalizedProviderResult;
  readonly responseIdentity: KeyedPayloadIdentity;
  readonly eventStreamIdentity: KeyedPayloadIdentity | null;
}

const MAX_REQUEST_BYTES = 1024 * 1024;
const MAX_RESPONSE_BYTES = 8 * 1024 * 1024;
const MAX_TEXT_LENGTH = 512 * 1024;
const MAX_MESSAGES = 64;
const MAX_STOP_ITEMS = 8;
const MAX_PROVIDER_DURATION_NS = 86_400_000_000_000;
const ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._+:/-]{0,511}$/;
const OPAQUE_ID_PATTERN =
  /^[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?$/;
const SAFE_FINISH_REASONS = new Set([
  "abort",
  "cancelled",
  "completed",
  "content_filter",
  "eos_token",
  "error",
  "function_call",
  "length",
  "load",
  "stop",
  "stop_sequence",
  "tool_calls",
  "unload",
]);
const ABORT_SIGNAL_ABORTED_GETTER = Reflect.getOwnPropertyDescriptor(
  AbortSignal.prototype,
  "aborted",
)?.get;
const NO_CAPTURED_SOURCE_FAILURE = Symbol("no-captured-source-failure");

const REQUEST_JSON_LIMITS: Readonly<BoundedJsonLimits> = Object.freeze({
  maxBytes: MAX_REQUEST_BYTES,
  maxDepth: 24,
  maxObjectKeys: 8_192,
  maxArrayItems: 8_192,
  maxTokens: 131_072,
  maxDecodedStringLength: MAX_TEXT_LENGTH,
  maxNumericTokenLength: 128,
  maxDiagnosticSnippetLength: 0,
});

const RESPONSE_JSON_LIMITS: Readonly<BoundedJsonLimits> = Object.freeze({
  maxBytes: MAX_RESPONSE_BYTES,
  maxDepth: 32,
  maxObjectKeys: 65_536,
  maxArrayItems: 65_536,
  maxTokens: 524_288,
  maxDecodedStringLength: MAX_RESPONSE_BYTES,
  maxNumericTokenLength: 128,
  maxDiagnosticSnippetLength: 0,
});

const STREAM_EVENT_JSON_LIMITS: Readonly<BoundedJsonLimits> = Object.freeze({
  ...RESPONSE_JSON_LIMITS,
  maxBytes: DEFAULT_SSE_LIMITS.maxEventBytes,
  maxDecodedStringLength: DEFAULT_SSE_LIMITS.maxEventBytes,
});

const INPUT_KEYS = new Set([
  "policy",
  "endpointAlias",
  "endpointDescriptor",
  "instance",
  "capabilityAuthorizations",
  "route",
  "generation",
  "identity",
  "totalDeadlineMs",
  "authenticationReference",
  "secretHeaderFactory",
  "signal",
  "httpLimits",
]);
const GENERATION_KEYS = new Set([
  "model",
  "stream",
  "n",
  "messages",
  "prompt",
  "maxTokens",
  "temperature",
  "topP",
  "seed",
  "stop",
]);
const MODEL_KEYS = new Set(["id", "revision"]);
const MESSAGE_KEYS = new Set(["role", "content"]);
const IDENTITY_KEYS = new Set(["studyId", "keyId", "key"]);
const HTTP_LIMIT_KEYS = new Set(Object.keys(DEFAULT_RUNTIME_HTTP_LIMITS));
function inputFail(
  code: RuntimeInvocationInputErrorCode = "INVALID_INPUT",
): never {
  throw new RuntimeInvocationInputError(code);
}

function deepFreeze<T>(value: T): T {
  if (value === null || typeof value !== "object" || Object.isFrozen(value)) {
    return value;
  }
  for (const descriptor of Object.values(
    Object.getOwnPropertyDescriptors(value),
  )) {
    if (Object.hasOwn(descriptor, "value")) {
      deepFreeze(descriptor.value);
    }
  }
  return Object.freeze(value);
}

function snapshotRecord(
  input: unknown,
  allowedKeys: ReadonlySet<string>,
): Readonly<Record<string, unknown>> {
  if (
    input === null
    || typeof input !== "object"
    || isProxy(input)
    || (
      Reflect.getPrototypeOf(input) !== Object.prototype
      && Reflect.getPrototypeOf(input) !== null
    )
  ) {
    inputFail();
  }
  const keys = Reflect.ownKeys(input);
  if (keys.some((key) => typeof key !== "string" || !allowedKeys.has(key))) {
    inputFail();
  }
  const snapshot: Record<string, unknown> = Object.create(null);
  for (const key of keys) {
    const descriptor = Reflect.getOwnPropertyDescriptor(input, key);
    if (
      descriptor === undefined
      || !descriptor.enumerable
      || !Object.hasOwn(descriptor, "value")
    ) {
      inputFail();
    }
    snapshot[key as string] = descriptor.value;
  }
  return Object.freeze(snapshot);
}

function snapshotArray(
  input: unknown,
  maximum: number,
): readonly unknown[] {
  if (
    input === null
    || typeof input !== "object"
    || isProxy(input)
    || !Array.isArray(input)
    || Reflect.getPrototypeOf(input) !== Array.prototype
  ) {
    inputFail();
  }
  const length = Reflect.getOwnPropertyDescriptor(input, "length")?.value;
  if (
    typeof length !== "number"
    || !Number.isSafeInteger(length)
    || length < 0
    || length > maximum
  ) {
    inputFail();
  }
  const allowed = new Set(["length"]);
  const result: unknown[] = [];
  for (let index = 0; index < length; index += 1) {
    const key = String(index);
    allowed.add(key);
    const descriptor = Reflect.getOwnPropertyDescriptor(input, key);
    if (
      descriptor === undefined
      || !descriptor.enumerable
      || !Object.hasOwn(descriptor, "value")
    ) {
      inputFail();
    }
    result.push(descriptor.value);
  }
  if (
    Reflect.ownKeys(input).some(
      (key) => typeof key !== "string" || !allowed.has(key),
    )
  ) {
    inputFail();
  }
  return Object.freeze(result);
}

function boundedString(
  value: unknown,
  maximum = MAX_TEXT_LENGTH,
): string {
  if (
    typeof value !== "string"
    || value.length < 1
    || value.length > maximum
    || value.trim() !== value
    || /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(value)
  ) {
    inputFail();
  }
  return value;
}

function boundedModelPart(value: unknown): string {
  const result = boundedString(value, 512);
  if (!ID_PATTERN.test(result)) inputFail();
  return result;
}

function finiteNumber(
  value: unknown,
  minimum: number,
  maximum: number,
): number {
  if (
    typeof value !== "number"
    || !Number.isFinite(value)
    || value < minimum
    || value > maximum
  ) {
    inputFail();
  }
  return value;
}

function safeInteger(
  value: unknown,
  minimum: number,
  maximum: number,
): number {
  if (
    typeof value !== "number"
    || !Number.isSafeInteger(value)
    || value < minimum
    || value > maximum
  ) {
    inputFail();
  }
  return value;
}

function parseModel(input: unknown): RuntimeRequestedModel {
  const snapshot = snapshotRecord(input, MODEL_KEYS);
  if (Reflect.ownKeys(snapshot).length !== MODEL_KEYS.size) inputFail();
  return Object.freeze({
    id: boundedModelPart(snapshot.id),
    revision: boundedModelPart(snapshot.revision),
  });
}

function parseMessages(input: unknown): readonly RuntimeChatMessage[] {
  const values = snapshotArray(input, MAX_MESSAGES);
  if (values.length < 1) inputFail();
  let totalLength = 0;
  return Object.freeze(values.map((value) => {
    const snapshot = snapshotRecord(value, MESSAGE_KEYS);
    if (Reflect.ownKeys(snapshot).length !== MESSAGE_KEYS.size) inputFail();
    if (
      snapshot.role !== "system"
      && snapshot.role !== "user"
      && snapshot.role !== "assistant"
    ) {
      inputFail();
    }
    const content = boundedString(snapshot.content, 64 * 1024);
    totalLength += content.length;
    if (totalLength > MAX_TEXT_LENGTH) inputFail();
    return Object.freeze({
      role: snapshot.role,
      content,
    });
  }));
}

function parseStop(input: unknown): string | readonly string[] {
  if (typeof input === "string") return boundedString(input, 256);
  const values = snapshotArray(input, MAX_STOP_ITEMS);
  if (values.length < 1) inputFail();
  const parsed = values.map((value) => boundedString(value, 256));
  if (new Set(parsed).size !== parsed.length) inputFail();
  return Object.freeze(parsed);
}

function parseGeneration(input: unknown): RuntimeGenerationRequest {
  const snapshot = snapshotRecord(input, GENERATION_KEYS);
  for (const required of ["model", "stream", "n", "maxTokens"]) {
    if (!Object.hasOwn(snapshot, required)) inputFail();
  }
  if (typeof snapshot.stream !== "boolean" || snapshot.n !== 1) inputFail();
  const hasMessages = Object.hasOwn(snapshot, "messages");
  const hasPrompt = Object.hasOwn(snapshot, "prompt");
  if (hasMessages === hasPrompt) inputFail();
  const generation = {
    model: parseModel(snapshot.model),
    stream: snapshot.stream,
    n: 1 as const,
    ...(hasMessages ? { messages: parseMessages(snapshot.messages) } : {}),
    ...(hasPrompt ? { prompt: boundedString(snapshot.prompt) } : {}),
    maxTokens: safeInteger(snapshot.maxTokens, 1, 1_000_000),
    ...(Object.hasOwn(snapshot, "temperature")
      ? { temperature: finiteNumber(snapshot.temperature, 0, 2) }
      : {}),
    ...(Object.hasOwn(snapshot, "topP")
      ? { topP: finiteNumber(snapshot.topP, 0, 1) }
      : {}),
    ...(Object.hasOwn(snapshot, "seed")
      ? {
        seed: safeInteger(
          snapshot.seed,
          Number.MIN_SAFE_INTEGER,
          Number.MAX_SAFE_INTEGER,
        ),
      }
      : {}),
    ...(Object.hasOwn(snapshot, "stop")
      ? { stop: parseStop(snapshot.stop) }
      : {}),
  };
  return deepFreeze(generation);
}

function parseIdentity(input: unknown): RuntimeStreamIdentity {
  const snapshot = snapshotRecord(input, IDENTITY_KEYS);
  if (Reflect.ownKeys(snapshot).length !== IDENTITY_KEYS.size) inputFail();
  const identity = Object.freeze({
    studyId: snapshot.studyId as string,
    keyId: snapshot.keyId as string,
    key: snapshot.key as KeyObject,
  });
  createStudyPayloadIdentity(
    identity.studyId,
    identity.keyId,
    identity.key,
    new Uint8Array(0),
  );
  return identity;
}

function parseAbortSignal(input: unknown): AbortSignal | undefined {
  if (input === undefined) return undefined;
  if (
    input === null
    || typeof input !== "object"
    || isProxy(input)
    || Reflect.getPrototypeOf(input) !== AbortSignal.prototype
    || ABORT_SIGNAL_ABORTED_GETTER === undefined
    || Reflect.ownKeys(input).some((key) => typeof key === "string")
  ) {
    inputFail();
  }
  try {
    if (
      typeof Reflect.apply(ABORT_SIGNAL_ABORTED_GETTER, input, [])
        !== "boolean"
    ) {
      inputFail();
    }
  } catch {
    inputFail();
  }
  return input as AbortSignal;
}

function abortSignalIsAborted(signal: AbortSignal): boolean {
  return Reflect.apply(
    ABORT_SIGNAL_ABORTED_GETTER!,
    signal,
    [],
  ) as boolean;
}

function parseHttpLimits(input: unknown): RuntimeHttpLimits {
  try {
    const snapshot = input === undefined
      ? undefined
      : snapshotRecord(input, HTTP_LIMIT_KEYS);
    return normalizeRuntimeInvocationHttpLimits(snapshot);
  } catch {
    inputFail();
  }
}

function requireRouteInputShape(
  routeKey: RuntimeInvocationRoute,
  generation: RuntimeGenerationRequest,
): void {
  const chatRoute = routeKey === "chatCompletions" || routeKey === "nativeChat";
  if (
    (chatRoute && generation.messages === undefined)
    || (!chatRoute && generation.prompt === undefined)
  ) {
    inputFail();
  }
  if (
    routeKey === "responses"
    && (generation.seed !== undefined || generation.stop !== undefined)
  ) {
    inputFail();
  }
}

function buildLmStudioNativeChatRequest(
  generation: RuntimeGenerationRequest,
): unknown {
  if (
    generation.seed !== undefined
    || generation.stop !== undefined
    || (
      generation.temperature !== undefined
      && generation.temperature > 1
    )
  ) {
    inputFail();
  }
  const messages = generation.messages;
  if (messages === undefined) inputFail();
  let systemPrompt: string | undefined;
  const input: { readonly type: "message"; readonly content: string }[] = [];
  for (const message of messages) {
    if (message.role === "system") {
      if (systemPrompt !== undefined || input.length > 0) inputFail();
      systemPrompt = message.content;
      continue;
    }
    if (message.role !== "user") inputFail();
    input.push(Object.freeze({
      type: "message",
      content: message.content,
    }));
  }
  if (input.length < 1) inputFail();
  return {
    model: generation.model.id,
    input,
    ...(systemPrompt === undefined
      ? {}
      : { system_prompt: systemPrompt }),
    stream: generation.stream,
    ...(generation.temperature === undefined
      ? {}
      : { temperature: generation.temperature }),
    ...(generation.topP === undefined
      ? {}
      : { top_p: generation.topP }),
    max_output_tokens: generation.maxTokens,
    // The native API defaults this to true. The inference adapter is
    // intentionally stateless and must never create server-side chat state.
    store: false,
  };
}

function buildRequestBody(
  route: RuntimeInferenceRoute,
  generation: RuntimeGenerationRequest,
): unknown {
  const sampling = {
    ...(generation.temperature === undefined
      ? {}
      : { temperature: generation.temperature }),
    ...(generation.topP === undefined ? {} : { top_p: generation.topP }),
    ...(generation.seed === undefined ? {} : { seed: generation.seed }),
  };
  switch (route.wireProtocol) {
    case "ollama-native-chat":
      return {
        model: generation.model.id,
        messages: generation.messages,
        stream: generation.stream,
        options: {
          num_predict: generation.maxTokens,
          ...sampling,
          ...(generation.stop === undefined ? {} : { stop: generation.stop }),
        },
      };
    case "ollama-native-generate":
      return {
        model: generation.model.id,
        prompt: generation.prompt,
        stream: generation.stream,
        options: {
          num_predict: generation.maxTokens,
          ...sampling,
          ...(generation.stop === undefined ? {} : { stop: generation.stop }),
        },
      };
    case "tgi-native-generate": {
      const doSample = generation.temperature !== undefined
        && generation.temperature > 0;
      return {
        inputs: generation.prompt,
        parameters: {
          details: true,
          do_sample: doSample,
          max_new_tokens: generation.maxTokens,
          return_full_text: false,
          ...(doSample ? { temperature: generation.temperature } : {}),
          ...(generation.topP === undefined ? {} : { top_p: generation.topP }),
          ...(generation.seed === undefined ? {} : { seed: generation.seed }),
          ...(generation.stop === undefined ? {} : { stop: generation.stop }),
        },
      };
    }
    case "openai-responses":
      return {
        model: generation.model.id,
        input: generation.prompt,
        stream: generation.stream,
        max_output_tokens: generation.maxTokens,
        ...(generation.temperature === undefined
          ? {}
          : { temperature: generation.temperature }),
        ...(generation.topP === undefined ? {} : { top_p: generation.topP }),
      };
    case "openai-chat-completions":
      return {
        model: generation.model.id,
        messages: generation.messages,
        stream: generation.stream,
        n: 1,
        max_tokens: generation.maxTokens,
        ...sampling,
        ...(generation.stop === undefined ? {} : { stop: generation.stop }),
        ...(generation.stream
          ? { stream_options: { include_usage: true } }
          : {}),
      };
    case "openai-completions":
      return {
        model: generation.model.id,
        prompt: generation.prompt,
        stream: generation.stream,
        n: 1,
        max_tokens: generation.maxTokens,
        ...sampling,
        ...(generation.stop === undefined ? {} : { stop: generation.stop }),
        ...(generation.stream
          ? { stream_options: { include_usage: true } }
          : {}),
      };
    case "lm-studio-native-chat":
      return buildLmStudioNativeChatRequest(generation);
  }
}

function routeFraming(
  route: RuntimeInferenceRoute,
  stream: boolean,
): "json" | "sse" | "ndjson" {
  let framing: "json" | "sse" | "ndjson";
  if (!stream) {
    framing = "json";
  } else if (
    route.wireProtocol === "ollama-native-chat"
    || route.wireProtocol === "ollama-native-generate"
  ) {
    framing = "ndjson";
  } else if (
    route.wireProtocol === "openai-chat-completions"
    || route.wireProtocol === "openai-completions"
    || route.wireProtocol === "openai-responses"
    || route.wireProtocol === "lm-studio-native-chat"
  ) {
    framing = "sse";
  } else {
    inputFail("UNSUPPORTED_ROUTE");
  }
  if (!route.responseFraming.includes(framing)) inputFail("UNSUPPORTED_ROUTE");
  return framing;
}

function prefixedRuntimePath(
  endpointDescriptor: EndpointDescriptor | undefined,
  routePath: string,
): string {
  const basePath = endpointDescriptor?.basePath ?? "/";
  if (basePath === "/") return routePath;
  if (routePath === "/") return basePath;
  return `${basePath}${routePath}`;
}

function normalizeInvocation(
  input: RuntimeInvocationInput,
  allowUnauthorisedConditionalDescription = false,
): NormalizedInvocation {
  const snapshot = snapshotRecord(input, INPUT_KEYS);
  for (const required of [
    "policy",
    "endpointAlias",
    "instance",
    "route",
    "generation",
    "identity",
    "totalDeadlineMs",
  ]) {
    if (!Object.hasOwn(snapshot, required)) inputFail();
  }
  if (
    snapshot.route !== "chatCompletions"
    && snapshot.route !== "completions"
    && snapshot.route !== "responses"
    && snapshot.route !== "nativeChat"
    && snapshot.route !== "nativeGenerate"
  ) {
    inputFail("UNSUPPORTED_ROUTE");
  }
  const routeKey = snapshot.route;
  const instance = parseRuntimeInstanceIdentity(snapshot.instance);
  const profile = getRuntimeProfile(instance.runtime.profileId);
  if (instance.runtime.build !== profile.runtime.build) {
    inputFail("UNSUPPORTED_ROUTE");
  }
  const endpointAlias = boundedString(snapshot.endpointAlias, 128);
  if (!OPAQUE_ID_PATTERN.test(endpointAlias)) inputFail();
  let endpointDescriptor: EndpointDescriptor | undefined;
  if (snapshot.endpointDescriptor !== undefined) {
    try {
      endpointDescriptor = parseEndpointDescriptor(
        snapshot.endpointDescriptor,
      );
    } catch {
      inputFail();
    }
  }
  const policy = snapshot.policy as CollectorTrustPolicy;
  let endpointBindingDigest: string;
  try {
    endpointBindingDigest = fingerprintCollectorEndpointBinding(
      policy,
      endpointAlias,
      endpointDescriptor,
    );
  } catch {
    inputFail();
  }
  if (instance.endpointDescriptorDigest !== endpointBindingDigest) {
    inputFail("ENDPOINT_BINDING_MISMATCH");
  }
  if (
    profile.locality === "local-only"
    && policy.localMode !== "literal-loopback-only"
  ) {
    inputFail("UNSUPPORTED_ROUTE");
  }
  const route = profile.endpoints.inference[routeKey];
  if (route === undefined) inputFail("UNSUPPORTED_ROUTE");
  const staticCapability = profile.capabilities[route.capability];
  if (
    staticCapability.state === "unsupported"
    || staticCapability.state === "unknown"
  ) {
    inputFail("UNSUPPORTED_ROUTE");
  }
  const authorizations = snapshot.capabilityAuthorizations === undefined
    ? Object.freeze([]) as readonly unknown[]
    : snapshotArray(
      snapshot.capabilityAuthorizations,
      16,
    );
  if (staticCapability.state === "conditional") {
    if (
      authorizations.length === 0
      && !allowUnauthorisedConditionalDescription
    ) {
      inputFail("CONDITIONAL_CAPABILITY_REQUIRES_AUTHORIZATION");
    }
    if (authorizations.length > 1) {
      inputFail("CAPABILITY_AUTHORIZATION_REJECTED");
    }
  } else if (authorizations.length !== 0) {
    inputFail("CAPABILITY_AUTHORIZATION_REJECTED");
  }
  const generation = parseGeneration(snapshot.generation);
  if (
    generation.model.id !== instance.model.id
    || generation.model.revision !== instance.model.revision
  ) {
    inputFail();
  }
  requireRouteInputShape(routeKey, generation);
  const framing = routeFraming(route, generation.stream);
  if (
    generation.stream
    && profile.capabilities.streaming.state !== "supported"
  ) {
    inputFail("UNSUPPORTED_ROUTE");
  }
  const identity = parseIdentity(snapshot.identity);
  const requestPath = prefixedRuntimePath(
    endpointDescriptor,
    route.path,
  );
  const requestBytes = canonicalJsonBytes(
    buildRequestBody(route, generation),
  );
  if (requestBytes.byteLength > MAX_REQUEST_BYTES) inputFail();
  parseBoundedJson(requestBytes, REQUEST_JSON_LIMITS);
  const requestIdentity = createStudyPayloadIdentity(
    identity.studyId,
    identity.keyId,
    identity.key,
    requestBytes,
  );
  const totalDeadlineMs = safeInteger(
    snapshot.totalDeadlineMs,
    1,
    300_000,
  );
  if (
    totalDeadlineMs > policy.maximumRequestDurationMs
  ) {
    inputFail();
  }
  const signal = parseAbortSignal(snapshot.signal);
  if (
    Object.hasOwn(snapshot, "secretHeaderFactory")
    && (
      typeof snapshot.secretHeaderFactory !== "function"
      || isProxy(snapshot.secretHeaderFactory)
    )
  ) {
    inputFail();
  }
  return Object.freeze({
    policy,
    endpointAlias,
    ...(endpointDescriptor === undefined
      ? {}
      : { endpointDescriptor }),
    instance,
    profileId: profile.id,
    profileBuild: profile.runtime.build,
    routeKey,
    route,
    ...(staticCapability.state === "conditional"
        && authorizations[0] !== undefined
      ? {
        capabilityAuthorization:
          authorizations[0] as RuntimeCapabilityAuthorization,
      }
      : {}),
    requestPath,
    generation,
    identity,
    endpointBindingDigest,
    requestBytes: Uint8Array.prototype.slice.call(requestBytes) as Uint8Array,
    requestIdentity,
    framing,
    totalDeadlineMs,
    ...(snapshot.authenticationReference === undefined
      ? {}
      : {
        authenticationReference: boundedString(
          snapshot.authenticationReference,
          128,
        ),
      }),
    ...(snapshot.secretHeaderFactory === undefined
      ? {}
      : {
        secretHeaderFactory:
          snapshot.secretHeaderFactory as RuntimeSecretHeaderFactory,
      }),
    ...(signal === undefined
      ? {}
      : { signal }),
    httpLimits: parseHttpLimits(snapshot.httpLimits),
  });
}

class InvalidRuntimeResponse extends Error {}

function record(value: unknown): Readonly<Record<string, unknown>> | null {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Readonly<Record<string, unknown>>
    : null;
}

function tokenCount(value: unknown): number {
  if (
    typeof value !== "number"
    || !Number.isSafeInteger(value)
    || value < 0
  ) {
    throw new InvalidRuntimeResponse();
  }
  return value;
}

function safeFinishReason(value: unknown): string {
  if (
    typeof value !== "string"
    || value.length < 1
    || value.length > 128
  ) {
    throw new InvalidRuntimeResponse();
  }
  return SAFE_FINISH_REASONS.has(value) ? value : "other";
}

function parseOpenAiUsage(value: unknown): RuntimeProviderUsage | null {
  if (value === undefined || value === null) return null;
  const usage = record(value);
  if (usage === null) throw new InvalidRuntimeResponse();
  if (
    Object.hasOwn(usage, "input_tokens")
    || Object.hasOwn(usage, "output_tokens")
  ) {
    throw new InvalidRuntimeResponse();
  }
  const inputTokens = tokenCount(usage.prompt_tokens);
  const outputTokens = tokenCount(usage.completion_tokens);
  const totalTokens = tokenCount(usage.total_tokens);
  if (totalTokens !== inputTokens + outputTokens) {
    throw new InvalidRuntimeResponse();
  }
  return Object.freeze({ inputTokens, outputTokens, totalTokens });
}

function parseResponsesUsage(value: unknown): RuntimeProviderUsage | null {
  if (value === undefined || value === null) return null;
  const usage = record(value);
  if (usage === null) throw new InvalidRuntimeResponse();
  if (
    Object.hasOwn(usage, "prompt_tokens")
    || Object.hasOwn(usage, "completion_tokens")
  ) {
    throw new InvalidRuntimeResponse();
  }
  const inputTokens = tokenCount(usage.input_tokens);
  const outputTokens = tokenCount(usage.output_tokens);
  const totalTokens = tokenCount(usage.total_tokens);
  if (totalTokens !== inputTokens + outputTokens) {
    throw new InvalidRuntimeResponse();
  }
  return Object.freeze({ inputTokens, outputTokens, totalTokens });
}

function parseOllamaUsage(value: Readonly<Record<string, unknown>>):
RuntimeProviderUsage | null {
  const hasInput = Object.hasOwn(value, "prompt_eval_count");
  const hasOutput = Object.hasOwn(value, "eval_count");
  if (!hasInput && !hasOutput) return null;
  if (!hasInput || !hasOutput) throw new InvalidRuntimeResponse();
  const inputTokens = tokenCount(value.prompt_eval_count);
  const outputTokens = tokenCount(value.eval_count);
  const totalTokens = inputTokens + outputTokens;
  if (!Number.isSafeInteger(totalTokens)) {
    throw new InvalidRuntimeResponse();
  }
  return Object.freeze({
    inputTokens,
    outputTokens,
    totalTokens,
  });
}

function boundedProviderDuration(value: unknown): number {
  if (
    typeof value !== "number"
    || !Number.isSafeInteger(value)
    || value < 0
    || value > MAX_PROVIDER_DURATION_NS
  ) {
    throw new InvalidRuntimeResponse();
  }
  return value;
}

function parseOllamaTiming(
  value: Readonly<Record<string, unknown>>,
): RuntimeProviderTiming {
  const mappings = [
    ["total_duration", "totalDurationNs"],
    ["load_duration", "loadDurationNs"],
    ["prompt_eval_duration", "promptEvaluationDurationNs"],
    ["eval_duration", "evaluationDurationNs"],
  ] as const;
  const timing: Record<string, number> = {};
  for (const [providerKey, normalizedKey] of mappings) {
    if (Object.hasOwn(value, providerKey)) {
      timing[normalizedKey] = boundedProviderDuration(value[providerKey]);
    }
  }
  return Object.freeze(timing);
}

function validateResolvedModel(
  value: unknown,
  requested: string,
): string | null {
  if (value === undefined || value === null) return null;
  if (typeof value !== "string" || value !== requested) {
    throw new InvalidRuntimeResponse();
  }
  return value;
}

function oneOpenAiChoice(
  json: Readonly<Record<string, unknown>>,
): Readonly<Record<string, unknown>> {
  if (!Array.isArray(json.choices) || json.choices.length !== 1) {
    throw new InvalidRuntimeResponse();
  }
  const choice = record(json.choices[0]);
  if (
    choice === null
    || (
      Object.hasOwn(choice, "index")
      && choice.index !== 0
    )
  ) {
    throw new InvalidRuntimeResponse();
  }
  return choice;
}

function normalizeOpenAiJson(
  value: unknown,
  route: RuntimeInvocationRoute,
  requestedModel: string,
): NormalizedProviderResult {
  const json = record(value);
  if (json === null) throw new InvalidRuntimeResponse();
  if (Object.hasOwn(json, "error")) {
    return Object.freeze({
      text: "",
      resolvedModelId: null,
      finishReason: null,
      usage: null,
      providerTiming: Object.freeze({}),
      logprobsObserved: false,
      terminal: "provider-error",
      finalUsage: "missing",
      streamTiming: null,
    });
  }
  const choice = oneOpenAiChoice(json);
  let text: unknown;
  if (route === "chatCompletions") {
    const message = record(choice.message);
    text = message?.content;
  } else {
    text = choice.text;
  }
  if (typeof text !== "string" || text.length > MAX_TEXT_LENGTH) {
    throw new InvalidRuntimeResponse();
  }
  const finishReason = safeFinishReason(choice.finish_reason);
  const usage = parseOpenAiUsage(json.usage);
  return Object.freeze({
    text,
    resolvedModelId: validateResolvedModel(json.model, requestedModel),
    finishReason,
    usage,
    providerTiming: Object.freeze({}),
    logprobsObserved:
      Object.hasOwn(choice, "logprobs") && choice.logprobs !== null,
    terminal: "complete",
    finalUsage: usage === null ? "missing" : "present",
    streamTiming: null,
  });
}

function responsesOutputText(value: unknown): string {
  if (!Array.isArray(value) || value.length !== 1) {
    throw new InvalidRuntimeResponse();
  }
  const message = record(value[0]);
  if (
    message === null
    || message.type !== "message"
    || message.role !== "assistant"
    || !Array.isArray(message.content)
    || message.content.length < 1
  ) {
    throw new InvalidRuntimeResponse();
  }
  let text = "";
  for (const value of message.content) {
    const content = record(value);
    if (
      content === null
      || content.type !== "output_text"
      || typeof content.text !== "string"
    ) {
      throw new InvalidRuntimeResponse();
    }
    text += content.text;
    if (text.length > MAX_TEXT_LENGTH) throw new InvalidRuntimeResponse();
  }
  return text;
}

function normalizeResponsesJson(
  value: unknown,
  requestedModel: string,
): NormalizedProviderResult {
  const json = record(value);
  if (json === null) throw new InvalidRuntimeResponse();
  if (Object.hasOwn(json, "error")) {
    return Object.freeze({
      text: "",
      resolvedModelId: null,
      finishReason: null,
      usage: null,
      providerTiming: Object.freeze({}),
      logprobsObserved: false,
      terminal: "provider-error",
      finalUsage: "missing",
      streamTiming: null,
    });
  }
  if (json.status !== "completed") throw new InvalidRuntimeResponse();
  const usage = parseResponsesUsage(json.usage);
  return Object.freeze({
    text: responsesOutputText(json.output),
    resolvedModelId: validateResolvedModel(json.model, requestedModel),
    finishReason: "completed",
    usage,
    providerTiming: Object.freeze({}),
    logprobsObserved: false,
    terminal: "complete",
    finalUsage: usage === null ? "missing" : "present",
    streamTiming: null,
  });
}

interface LmStudioNativeOutput {
  readonly text: string;
  readonly reasoning: string;
}

const LM_STUDIO_ERROR_TYPES = new Set([
  "invalid_request",
  "unknown",
  "mcp_connection_error",
  "plugin_connection_error",
  "not_implemented",
  "model_not_found",
  "job_not_found",
  "internal_error",
]);

function boundedProviderNumber(
  value: unknown,
  maximum: number,
): number {
  if (
    typeof value !== "number"
    || !Number.isFinite(value)
    || value < 0
    || value > maximum
  ) {
    throw new InvalidRuntimeResponse();
  }
  return value;
}

function boundedProviderText(
  value: unknown,
  maximum = MAX_TEXT_LENGTH,
): string {
  if (typeof value !== "string" || value.length > maximum) {
    throw new InvalidRuntimeResponse();
  }
  return value;
}

function validateLmStudioError(value: unknown): void {
  const error = record(value);
  if (
    error === null
    || typeof error.type !== "string"
    || !LM_STUDIO_ERROR_TYPES.has(error.type)
    || typeof error.message !== "string"
    || error.message.length < 1
    || error.message.length > 4_096
  ) {
    throw new InvalidRuntimeResponse();
  }
  for (const key of ["code", "param"]) {
    if (
      Object.hasOwn(error, key)
      && (
        typeof error[key] !== "string"
        || (error[key] as string).length < 1
        || (error[key] as string).length > 512
      )
    ) {
      throw new InvalidRuntimeResponse();
    }
  }
}

function parseLmStudioOutput(value: unknown): LmStudioNativeOutput {
  if (
    !Array.isArray(value)
    || value.length < 1
    || value.length > MAX_MESSAGES
  ) {
    throw new InvalidRuntimeResponse();
  }
  let text = "";
  let reasoning = "";
  let messageCount = 0;
  for (const outputItem of value) {
    const item = record(outputItem);
    if (item === null) throw new InvalidRuntimeResponse();
    if (item.type === "message") {
      messageCount += 1;
      if (messageCount > 1) throw new InvalidRuntimeResponse();
      text = boundedProviderText(item.content);
    } else if (item.type === "reasoning") {
      reasoning += boundedProviderText(item.content);
      if (reasoning.length > MAX_TEXT_LENGTH) {
        throw new InvalidRuntimeResponse();
      }
    } else {
      // No integrations are sent by this adapter. Tool calls, invalid tool
      // calls, and unknown output types are therefore ambiguous evidence.
      throw new InvalidRuntimeResponse();
    }
  }
  if (messageCount !== 1) throw new InvalidRuntimeResponse();
  return Object.freeze({ text, reasoning });
}

function parseLmStudioUsage(value: unknown): RuntimeProviderUsage {
  const stats = record(value);
  if (stats === null) throw new InvalidRuntimeResponse();
  const inputTokens = tokenCount(stats.input_tokens);
  const outputTokens = tokenCount(stats.total_output_tokens);
  const reasoningTokens = tokenCount(stats.reasoning_output_tokens);
  if (reasoningTokens > outputTokens) throw new InvalidRuntimeResponse();
  boundedProviderNumber(stats.tokens_per_second, 1_000_000_000);
  boundedProviderNumber(
    stats.time_to_first_token_seconds,
    MAX_PROVIDER_DURATION_NS / 1_000_000_000,
  );
  if (Object.hasOwn(stats, "model_load_time_seconds")) {
    boundedProviderNumber(
      stats.model_load_time_seconds,
      MAX_PROVIDER_DURATION_NS / 1_000_000_000,
    );
  }
  const totalTokens = inputTokens + outputTokens;
  if (!Number.isSafeInteger(totalTokens)) {
    throw new InvalidRuntimeResponse();
  }
  return Object.freeze({ inputTokens, outputTokens, totalTokens });
}

function normalizeLmStudioJson(
  value: unknown,
  requestedModel: string,
  options?: {
    readonly expectedText: string;
    readonly expectedReasoning: string;
    readonly streamTiming: RuntimeStreamTiming;
  },
): NormalizedProviderResult {
  const json = record(value);
  if (json === null) throw new InvalidRuntimeResponse();
  if (Object.hasOwn(json, "error")) {
    validateLmStudioError(json.error);
    if (options !== undefined) throw new InvalidRuntimeResponse();
    return Object.freeze({
      text: "",
      resolvedModelId: null,
      finishReason: null,
      usage: null,
      providerTiming: Object.freeze({}),
      logprobsObserved: false,
      terminal: "provider-error",
      finalUsage: "missing",
      streamTiming: null,
    });
  }
  // `store: false` must not produce a stateful response identifier.
  if (Object.hasOwn(json, "response_id")) {
    throw new InvalidRuntimeResponse();
  }
  const resolvedModelId = validateResolvedModel(
    json.model_instance_id,
    requestedModel,
  );
  if (resolvedModelId === null) throw new InvalidRuntimeResponse();
  const output = parseLmStudioOutput(json.output);
  if (
    options !== undefined
    && (
      output.text !== options.expectedText
      || output.reasoning !== options.expectedReasoning
    )
  ) {
    throw new InvalidRuntimeResponse();
  }
  const usage = parseLmStudioUsage(json.stats);
  return Object.freeze({
    text: output.text,
    resolvedModelId,
    finishReason: "completed",
    usage,
    providerTiming: Object.freeze({}),
    logprobsObserved: false,
    terminal: "complete",
    finalUsage: "present",
    streamTiming: options?.streamTiming ?? null,
  });
}

type LmStudioLifecycle = "not-started" | "started" | "ended";

function lmStudioStreamTiming(
  parsed: SseParseResult,
  firstMeaningfulAtMs: number | null,
): RuntimeStreamTiming {
  const timing = parsed.summary.timing;
  return Object.freeze({
    ...timing,
    firstMeaningfulAtMs,
    timeToFirstMeaningfulMs: firstMeaningfulAtMs === null
      ? null
      : firstMeaningfulAtMs - timing.startedAtMs,
  });
}

function requireLmStudioStreamModel(
  json: Readonly<Record<string, unknown>>,
  requestedModel: string,
): void {
  if (
    validateResolvedModel(json.model_instance_id, requestedModel) === null
  ) {
    throw new InvalidRuntimeResponse();
  }
}

function normalizeLmStudioSse(
  parsed: SseParseResult,
  requestedModel: string,
): NormalizedProviderResult {
  let chatStarted = false;
  let chatEnded = false;
  let providerError = false;
  let modelLoad: LmStudioLifecycle = "not-started";
  let promptProcessing: LmStudioLifecycle = "not-started";
  let reasoningLifecycle: LmStudioLifecycle = "not-started";
  let messageLifecycle: LmStudioLifecycle = "not-started";
  let modelLoadProgress = 0;
  let promptProgress = 0;
  let reasoning = "";
  let text = "";
  let firstMeaningfulAtMs: number | null = null;
  let terminal: NormalizedProviderResult | null = null;

  for (const event of parsed.events) {
    if (event.kind !== "event" || chatEnded) {
      throw new InvalidRuntimeResponse();
    }
    const json = record(parseBoundedJson(
      new TextEncoder().encode(event.data),
      STREAM_EVENT_JSON_LIMITS,
    ));
    if (
      json === null
      || typeof json.type !== "string"
      || event.event !== json.type
      || (providerError && json.type !== "chat.end")
    ) {
      throw new InvalidRuntimeResponse();
    }

    switch (json.type) {
      case "chat.start":
        if (event.index !== 0 || chatStarted) {
          throw new InvalidRuntimeResponse();
        }
        requireLmStudioStreamModel(json, requestedModel);
        chatStarted = true;
        break;
      case "model_load.start":
        if (
          !chatStarted
          || modelLoad !== "not-started"
          || promptProcessing !== "not-started"
          || reasoningLifecycle !== "not-started"
          || messageLifecycle !== "not-started"
        ) {
          throw new InvalidRuntimeResponse();
        }
        requireLmStudioStreamModel(json, requestedModel);
        modelLoad = "started";
        break;
      case "model_load.progress": {
        if (modelLoad !== "started") throw new InvalidRuntimeResponse();
        requireLmStudioStreamModel(json, requestedModel);
        const progress = boundedProviderNumber(json.progress, 1);
        if (progress < modelLoadProgress) throw new InvalidRuntimeResponse();
        modelLoadProgress = progress;
        break;
      }
      case "model_load.end":
        if (modelLoad !== "started") throw new InvalidRuntimeResponse();
        requireLmStudioStreamModel(json, requestedModel);
        boundedProviderNumber(
          json.load_time_seconds,
          MAX_PROVIDER_DURATION_NS / 1_000_000_000,
        );
        modelLoad = "ended";
        break;
      case "prompt_processing.start":
        if (
          !chatStarted
          || modelLoad === "started"
          || promptProcessing !== "not-started"
          || reasoningLifecycle !== "not-started"
          || messageLifecycle !== "not-started"
        ) {
          throw new InvalidRuntimeResponse();
        }
        promptProcessing = "started";
        break;
      case "prompt_processing.progress": {
        if (promptProcessing !== "started") {
          throw new InvalidRuntimeResponse();
        }
        const progress = boundedProviderNumber(json.progress, 1);
        if (progress < promptProgress) throw new InvalidRuntimeResponse();
        promptProgress = progress;
        break;
      }
      case "prompt_processing.end":
        if (promptProcessing !== "started") {
          throw new InvalidRuntimeResponse();
        }
        promptProcessing = "ended";
        break;
      case "reasoning.start":
        if (
          !chatStarted
          || modelLoad === "started"
          || promptProcessing === "started"
          || reasoningLifecycle !== "not-started"
          || messageLifecycle !== "not-started"
        ) {
          throw new InvalidRuntimeResponse();
        }
        reasoningLifecycle = "started";
        break;
      case "reasoning.delta":
        if (reasoningLifecycle !== "started") {
          throw new InvalidRuntimeResponse();
        }
        reasoning += boundedProviderText(json.content);
        if (reasoning.length > MAX_TEXT_LENGTH) {
          throw new InvalidRuntimeResponse();
        }
        break;
      case "reasoning.end":
        if (reasoningLifecycle !== "started") {
          throw new InvalidRuntimeResponse();
        }
        reasoningLifecycle = "ended";
        break;
      case "message.start":
        if (
          !chatStarted
          || modelLoad === "started"
          || promptProcessing === "started"
          || reasoningLifecycle === "started"
          || messageLifecycle !== "not-started"
        ) {
          throw new InvalidRuntimeResponse();
        }
        messageLifecycle = "started";
        break;
      case "message.delta": {
        if (messageLifecycle !== "started") {
          throw new InvalidRuntimeResponse();
        }
        const content = boundedProviderText(json.content);
        text += content;
        if (text.length > MAX_TEXT_LENGTH) {
          throw new InvalidRuntimeResponse();
        }
        if (content.length > 0 && firstMeaningfulAtMs === null) {
          firstMeaningfulAtMs = event.observedAtMs;
        }
        break;
      }
      case "message.end":
        if (messageLifecycle !== "started") {
          throw new InvalidRuntimeResponse();
        }
        messageLifecycle = "ended";
        break;
      case "error":
        if (!chatStarted || providerError) {
          throw new InvalidRuntimeResponse();
        }
        validateLmStudioError(json.error);
        providerError = true;
        break;
      case "chat.end": {
        if (
          !chatStarted
          || event.index !== parsed.events.length - 1
          || (!providerError && (
            modelLoad === "started"
            || promptProcessing === "started"
            || reasoningLifecycle === "started"
            || messageLifecycle !== "ended"
          ))
        ) {
          throw new InvalidRuntimeResponse();
        }
        const streamTiming = lmStudioStreamTiming(
          parsed,
          firstMeaningfulAtMs,
        );
        terminal = normalizeLmStudioJson(
          json.result,
          requestedModel,
          {
            expectedText: text,
            expectedReasoning: reasoning,
            streamTiming,
          },
        );
        chatEnded = true;
        break;
      }
      default:
        throw new InvalidRuntimeResponse();
    }
  }

  const streamTiming = lmStudioStreamTiming(
    parsed,
    firstMeaningfulAtMs,
  );
  if (
    terminal !== null
    && parsed.summary.trailingIncompleteEvent === false
  ) {
    if (!providerError) return terminal;
    return Object.freeze({
      ...terminal,
      finishReason: null,
      terminal: "provider-error",
      streamTiming,
    });
  }
  if (terminal !== null || parsed.summary.trailingIncompleteEvent) {
    throw new InvalidRuntimeResponse();
  }
  return Object.freeze({
    text,
    resolvedModelId: chatStarted ? requestedModel : null,
    finishReason: null,
    usage: null,
    providerTiming: Object.freeze({}),
    logprobsObserved: false,
    terminal: providerError ? "provider-error" : "truncated",
    finalUsage: "missing",
    streamTiming,
  });
}

function normalizeOllamaJson(
  value: unknown,
  route: RuntimeInvocationRoute,
  requestedModel: string,
): NormalizedProviderResult {
  const json = record(value);
  if (json === null) throw new InvalidRuntimeResponse();
  if (Object.hasOwn(json, "error")) {
    return Object.freeze({
      text: "",
      resolvedModelId: null,
      finishReason: null,
      usage: null,
      providerTiming: Object.freeze({}),
      logprobsObserved: false,
      terminal: "provider-error",
      finalUsage: "missing",
      streamTiming: null,
    });
  }
  let text: unknown;
  if (route === "nativeGenerate") {
    text = json.response;
  } else if (route === "nativeChat") {
    text = record(json.message)?.content;
  } else {
    throw new InvalidRuntimeResponse();
  }
  if (
    json.done !== true
    || typeof text !== "string"
    || text.length > MAX_TEXT_LENGTH
  ) {
    throw new InvalidRuntimeResponse();
  }
  const finishReason = safeFinishReason(json.done_reason);
  const usage = parseOllamaUsage(json);
  return Object.freeze({
    text,
    resolvedModelId: validateResolvedModel(json.model, requestedModel),
    finishReason,
    usage,
    providerTiming: parseOllamaTiming(json),
    logprobsObserved: false,
    terminal: "complete",
    finalUsage: usage === null ? "missing" : "present",
    streamTiming: null,
  });
}

function parseTgiUsage(
  details: Readonly<Record<string, unknown>>,
): RuntimeProviderUsage | null {
  if (!Object.hasOwn(details, "generated_tokens")) return null;
  const outputTokens = tokenCount(details.generated_tokens);
  const inputTokens = Object.hasOwn(details, "input_tokens")
    ? tokenCount(details.input_tokens)
    : null;
  const totalTokens = Object.hasOwn(details, "total_tokens")
    ? tokenCount(details.total_tokens)
    : null;
  if (
    inputTokens !== null
    && totalTokens !== null
    && totalTokens !== inputTokens + outputTokens
  ) {
    throw new InvalidRuntimeResponse();
  }
  return Object.freeze({ inputTokens, outputTokens, totalTokens });
}

function normalizeTgiJson(
  value: unknown,
  requestedModel: string,
): NormalizedProviderResult {
  const json = record(value);
  if (json === null) throw new InvalidRuntimeResponse();
  if (Object.hasOwn(json, "error")) {
    return Object.freeze({
      text: "",
      resolvedModelId: null,
      finishReason: null,
      usage: null,
      providerTiming: Object.freeze({}),
      logprobsObserved: false,
      terminal: "provider-error",
      finalUsage: "missing",
      streamTiming: null,
    });
  }
  const details = record(json.details);
  if (
    typeof json.generated_text !== "string"
    || json.generated_text.length > MAX_TEXT_LENGTH
    || details === null
  ) {
    throw new InvalidRuntimeResponse();
  }
  const usage = parseTgiUsage(details);
  return Object.freeze({
    text: json.generated_text,
    resolvedModelId: validateResolvedModel(json.model, requestedModel),
    finishReason: safeFinishReason(details.finish_reason),
    usage,
    providerTiming: Object.freeze({}),
    logprobsObserved: false,
    terminal: "complete",
    finalUsage: usage === null ? "missing" : "present",
    streamTiming: null,
  });
}

function normalizeOpenAiSse(
  parsed: JsonSseParseResult,
  route: RuntimeInvocationRoute,
  requestedModel: string,
): NormalizedProviderResult {
  let text = "";
  let finishReason: string | null = null;
  let resolvedModelId: string | null = null;
  let usage: RuntimeProviderUsage | null = null;
  let logprobsObserved = false;
  let finishSeen = false;
  let usageSeen = false;
  for (const event of parsed.events) {
    if (event.kind === "done" || event.json === null) continue;
    if (event.providerError) break;
    const json = record(event.json);
    if (json === null) throw new InvalidRuntimeResponse();
    const reportedModel = validateResolvedModel(json.model, requestedModel);
    if (reportedModel !== null) resolvedModelId = reportedModel;
    if (!Array.isArray(json.choices)) throw new InvalidRuntimeResponse();
    if (json.choices.length === 0) {
      if (
        !finishSeen
        || usageSeen
        || json.usage === undefined
        || json.usage === null
      ) {
        throw new InvalidRuntimeResponse();
      }
      usage = parseOpenAiUsage(json.usage);
      if (usage === null) throw new InvalidRuntimeResponse();
      usageSeen = true;
      continue;
    }
    if (
      finishSeen
      || usageSeen
      || (json.usage !== undefined && json.usage !== null)
    ) {
      throw new InvalidRuntimeResponse();
    }
    const choice = oneOpenAiChoice(json);
    let piece: unknown;
    if (route === "chatCompletions") {
      piece = record(choice.delta)?.content;
    } else {
      piece = choice.text;
    }
    if (piece !== undefined && piece !== null) {
      if (typeof piece !== "string") throw new InvalidRuntimeResponse();
      text += piece;
      if (text.length > MAX_TEXT_LENGTH) throw new InvalidRuntimeResponse();
    }
    if (choice.finish_reason !== undefined && choice.finish_reason !== null) {
      const candidate = safeFinishReason(choice.finish_reason);
      if (finishReason !== null && finishReason !== candidate) {
        throw new InvalidRuntimeResponse();
      }
      finishReason = candidate;
      finishSeen = true;
    }
    logprobsObserved ||= Object.hasOwn(choice, "logprobs")
      && choice.logprobs !== null;
  }
  return Object.freeze({
    text,
    resolvedModelId,
    finishReason,
    usage,
    providerTiming: Object.freeze({}),
    logprobsObserved,
    terminal: parsed.summary.terminal === "provider-error"
      ? "provider-error"
      : parsed.summary.terminal === "truncated"
        ? "truncated"
        : "complete",
    finalUsage: usageSeen && parsed.summary.finalUsage === "present"
      ? "present"
      : "missing",
    streamTiming: parsed.summary.timing,
  });
}

function responsesStreamIdentifier(
  value: unknown,
): string {
  if (
    typeof value !== "string"
    || !ID_PATTERN.test(value)
  ) {
    throw new InvalidRuntimeResponse();
  }
  return value;
}

function requireResponsesStreamIndex(
  json: Readonly<Record<string, unknown>>,
  key: "output_index" | "content_index",
): void {
  if (json[key] !== 0) throw new InvalidRuntimeResponse();
}

function requireResponsesStreamTextPart(
  value: unknown,
  expectedText: string,
): void {
  const part = record(value);
  if (
    part === null
    || part.type !== "output_text"
    || part.text !== expectedText
    || !Array.isArray(part.annotations)
    || part.annotations.length !== 0
    || (
      Object.hasOwn(part, "logprobs")
      && part.logprobs !== null
      && !Array.isArray(part.logprobs)
    )
  ) {
    throw new InvalidRuntimeResponse();
  }
}

function requireResponsesStreamMessage(
  value: unknown,
  expectedStatus: "in_progress" | "completed",
  expectedText: string | null,
  expectedItemId?: string,
): string {
  const message = record(value);
  if (
    message === null
    || message.type !== "message"
    || message.role !== "assistant"
    || message.status !== expectedStatus
    || !Array.isArray(message.content)
  ) {
    throw new InvalidRuntimeResponse();
  }
  const itemId = responsesStreamIdentifier(message.id);
  if (expectedItemId !== undefined && itemId !== expectedItemId) {
    throw new InvalidRuntimeResponse();
  }
  if (expectedText === null) {
    if (message.content.length !== 0) throw new InvalidRuntimeResponse();
  } else {
    if (message.content.length !== 1) throw new InvalidRuntimeResponse();
    requireResponsesStreamTextPart(message.content[0], expectedText);
  }
  return itemId;
}

function requireInitialResponsesStreamResponse(
  value: unknown,
  requestedModel: string,
  expectedResponseId?: string,
): string {
  const response = record(value);
  if (
    response === null
    || response.object !== "response"
    || response.status !== "in_progress"
    || !Number.isSafeInteger(response.created_at)
    || (response.created_at as number) < 0
    || !Array.isArray(response.output)
    || response.output.length !== 0
    || response.usage !== null
    || validateResolvedModel(response.model, requestedModel) === null
  ) {
    throw new InvalidRuntimeResponse();
  }
  const responseId = responsesStreamIdentifier(response.id);
  if (
    expectedResponseId !== undefined
    && responseId !== expectedResponseId
  ) {
    throw new InvalidRuntimeResponse();
  }
  return responseId;
}

function requireCompletedResponsesStreamResponse(
  value: unknown,
  requestedModel: string,
  responseId: string,
  expectedText: string,
): {
  readonly resolvedModelId: string;
  readonly usage: RuntimeProviderUsage;
} {
  const response = record(value);
  if (
    response === null
    || response.id !== responseId
    || response.object !== "response"
    || response.status !== "completed"
    || !Array.isArray(response.output)
    || response.output.length !== 1
  ) {
    throw new InvalidRuntimeResponse();
  }
  requireResponsesStreamMessage(
    response.output[0],
    "completed",
    expectedText,
  );
  const resolvedModelId = validateResolvedModel(
    response.model,
    requestedModel,
  );
  const usage = parseResponsesUsage(response.usage);
  if (resolvedModelId === null || usage === null) {
    throw new InvalidRuntimeResponse();
  }
  return Object.freeze({ resolvedModelId, usage });
}

type ResponsesTextStreamPhase =
  | "created"
  | "in-progress"
  | "output-item-added"
  | "content-part-added"
  | "text-delta"
  | "content-part-done"
  | "output-item-done"
  | "response-completed"
  | "terminal";

function normalizeResponsesSse(
  parsed: JsonSseParseResult,
  requestedModel: string,
): NormalizedProviderResult {
  let phase: ResponsesTextStreamPhase = "created";
  let sequenceNumber = 0;
  let responseId: string | null = null;
  let itemId: string | null = null;
  let text = "";
  let resolvedModelId: string | null = null;
  let usage: RuntimeProviderUsage | null = null;
  for (const event of parsed.events) {
    if (event.kind === "done" || event.json === null) {
      throw new InvalidRuntimeResponse();
    }
    const json = record(event.json);
    if (
      json === null
      || typeof json.type !== "string"
      || json.type !== event.type
      || event.event !== json.type
    ) {
      throw new InvalidRuntimeResponse();
    }
    if (event.providerError) {
      if (
        event.type !== "error"
        && event.type !== "response.failed"
      ) {
        throw new InvalidRuntimeResponse();
      }
      return Object.freeze({
        text,
        resolvedModelId,
        finishReason: null,
        usage: null,
        providerTiming: Object.freeze({}),
        logprobsObserved: false,
        terminal: "provider-error",
        finalUsage: "missing",
        streamTiming: parsed.summary.timing,
      });
    }
    if (json.sequence_number !== sequenceNumber) {
      throw new InvalidRuntimeResponse();
    }
    sequenceNumber += 1;
    if (Object.hasOwn(json, "usage")) {
      throw new InvalidRuntimeResponse();
    }

    switch (event.type) {
      case "response.created":
        if (phase !== "created") throw new InvalidRuntimeResponse();
        responseId = requireInitialResponsesStreamResponse(
          json.response,
          requestedModel,
        );
        phase = "in-progress";
        break;
      case "response.in_progress":
        if (phase !== "in-progress" || responseId === null) {
          throw new InvalidRuntimeResponse();
        }
        requireInitialResponsesStreamResponse(
          json.response,
          requestedModel,
          responseId,
        );
        phase = "output-item-added";
        break;
      case "response.output_item.added":
        if (phase !== "output-item-added") {
          throw new InvalidRuntimeResponse();
        }
        requireResponsesStreamIndex(json, "output_index");
        itemId = requireResponsesStreamMessage(
          json.item,
          "in_progress",
          null,
        );
        phase = "content-part-added";
        break;
      case "response.content_part.added":
        if (phase !== "content-part-added" || itemId === null) {
          throw new InvalidRuntimeResponse();
        }
        requireResponsesStreamIndex(json, "output_index");
        requireResponsesStreamIndex(json, "content_index");
        if (json.item_id !== itemId) throw new InvalidRuntimeResponse();
        requireResponsesStreamTextPart(json.part, "");
        phase = "text-delta";
        break;
      case "response.output_text.delta":
        if (phase !== "text-delta" || itemId === null) {
          throw new InvalidRuntimeResponse();
        }
        requireResponsesStreamIndex(json, "output_index");
        requireResponsesStreamIndex(json, "content_index");
        if (
          json.item_id !== itemId
          || typeof json.delta !== "string"
          || json.delta.length < 1
          || !Array.isArray(json.logprobs)
        ) {
          throw new InvalidRuntimeResponse();
        }
        text += json.delta;
        if (text.length > MAX_TEXT_LENGTH) {
          throw new InvalidRuntimeResponse();
        }
        break;
      case "response.output_text.done":
        if (
          phase !== "text-delta"
          || itemId === null
          || text.length < 1
        ) {
          throw new InvalidRuntimeResponse();
        }
        requireResponsesStreamIndex(json, "output_index");
        requireResponsesStreamIndex(json, "content_index");
        if (
          json.item_id !== itemId
          || json.text !== text
          || !Array.isArray(json.logprobs)
        ) {
          throw new InvalidRuntimeResponse();
        }
        phase = "content-part-done";
        break;
      case "response.content_part.done":
        if (phase !== "content-part-done" || itemId === null) {
          throw new InvalidRuntimeResponse();
        }
        requireResponsesStreamIndex(json, "output_index");
        requireResponsesStreamIndex(json, "content_index");
        if (json.item_id !== itemId) throw new InvalidRuntimeResponse();
        requireResponsesStreamTextPart(json.part, text);
        phase = "output-item-done";
        break;
      case "response.output_item.done":
        if (phase !== "output-item-done" || itemId === null) {
          throw new InvalidRuntimeResponse();
        }
        requireResponsesStreamIndex(json, "output_index");
        requireResponsesStreamMessage(
          json.item,
          "completed",
          text,
          itemId,
        );
        phase = "response-completed";
        break;
      case "response.completed": {
        if (phase !== "response-completed" || responseId === null) {
          throw new InvalidRuntimeResponse();
        }
        const terminal = requireCompletedResponsesStreamResponse(
          json.response,
          requestedModel,
          responseId,
          text,
        );
        resolvedModelId = terminal.resolvedModelId;
        usage = terminal.usage;
        phase = "terminal";
        break;
      }
      default:
        throw new InvalidRuntimeResponse();
    }
  }
  const completed = phase === "terminal"
    && resolvedModelId !== null
    && usage !== null;
  return Object.freeze({
    text,
    resolvedModelId,
    finishReason: completed ? "completed" : null,
    usage,
    providerTiming: Object.freeze({}),
    logprobsObserved: false,
    terminal: parsed.summary.terminal === "provider-error"
      ? "provider-error"
      : parsed.summary.terminal === "response.completed"
        ? completed ? "complete" : "invalid"
        : "truncated",
    finalUsage:
      completed && parsed.summary.finalUsage === "present"
        ? "present"
        : "missing",
    streamTiming: parsed.summary.timing,
  });
}

function normalizeOllamaNdjson(
  parsed: NdjsonStreamParseResult,
  route: RuntimeInvocationRoute,
  requestedModel: string,
): NormalizedProviderResult {
  let text = "";
  let resolvedModelId: string | null = null;
  let finishReason: string | null = null;
  let usage: RuntimeProviderUsage | null = null;
  let providerTiming: RuntimeProviderTiming = Object.freeze({});
  for (const item of parsed.items) {
    if (item.providerError) break;
    const json = record(item.json);
    if (json === null) throw new InvalidRuntimeResponse();
    if (
      Object.hasOwn(json, "done")
      && typeof json.done !== "boolean"
    ) {
      throw new InvalidRuntimeResponse();
    }
    const reportedModel = validateResolvedModel(json.model, requestedModel);
    if (reportedModel !== null) resolvedModelId = reportedModel;
    if (route === "nativeGenerate") {
      if (
        Object.hasOwn(json, "response")
        && typeof json.response !== "string"
      ) {
        throw new InvalidRuntimeResponse();
      }
      if (typeof json.response === "string") {
        text += json.response;
        if (text.length > MAX_TEXT_LENGTH) throw new InvalidRuntimeResponse();
      }
    } else if (route === "nativeChat" && Object.hasOwn(json, "message")) {
      const message = record(json.message);
      if (message === null) throw new InvalidRuntimeResponse();
      if (Object.hasOwn(message, "content")) {
        if (typeof message.content !== "string") {
          throw new InvalidRuntimeResponse();
        }
        text += message.content;
        if (text.length > MAX_TEXT_LENGTH) throw new InvalidRuntimeResponse();
      }
    } else if (route !== "nativeChat") {
      throw new InvalidRuntimeResponse();
    }
    if (item.done) {
      finishReason = safeFinishReason(json.done_reason);
      usage = parseOllamaUsage(json);
      providerTiming = parseOllamaTiming(json);
    }
  }
  return Object.freeze({
    text,
    resolvedModelId,
    finishReason,
    usage,
    providerTiming,
    logprobsObserved: false,
    terminal: parsed.summary.terminal === "provider-error"
      ? "provider-error"
      : parsed.summary.terminal === "truncated"
        ? "truncated"
        : "complete",
    finalUsage: parsed.summary.finalUsage === "present"
      ? "present"
      : "missing",
    streamTiming: parsed.summary.timing,
  });
}

interface CapturedBody {
  readonly source: ByteChunkSource;
  readonly bytes: () => Uint8Array;
  readonly complete: () => boolean;
  readonly sourceFailure: () => unknown;
}

function captureBody(source: ByteChunkSource): CapturedBody {
  const chunks: Buffer[] = [];
  let total = 0;
  let complete = false;
  let started = false;
  let sourceFailure: unknown = NO_CAPTURED_SOURCE_FAILURE;
  const captured = Object.freeze({
    [Symbol.asyncIterator]: async function* (): AsyncGenerator<
      Uint8Array,
      void,
      undefined
    > {
      if (started) throw new InvalidRuntimeResponse();
      started = true;
      try {
        for await (const chunk of source as AsyncIterable<Uint8Array>) {
          const copy = Buffer.from(chunk);
          total += copy.byteLength;
          if (total > MAX_RESPONSE_BYTES) throw new InvalidRuntimeResponse();
          chunks.push(copy);
          yield copy;
        }
        complete = true;
      } catch (error) {
        sourceFailure = error;
        throw error;
      }
    },
  });
  return Object.freeze({
    source: captured,
    bytes: (): Uint8Array => {
      if (!complete) throw new InvalidRuntimeResponse();
      return Buffer.concat(chunks, total);
    },
    complete: () => complete,
    sourceFailure: () => sourceFailure,
  });
}

async function drain(source: ByteChunkSource): Promise<void> {
  for await (const _chunk of source as AsyncIterable<Uint8Array>) {
    // Bounded by the transport and capture wrapper.
  }
}

function contentTypeMatches(
  framing: NormalizedInvocation["framing"],
  response: BoundedRuntimeHttpResponse,
): boolean {
  const typeMatches = framing === "json"
    ? response.contentType === "application/json"
    : framing === "sse"
      ? response.contentType === "text/event-stream"
      : response.contentType === "application/x-ndjson";
  if (!typeMatches) return false;
  const parameters = response.contentTypeParameters ?? [];
  return parameters.length === 0
    || (
      parameters.length === 1
      && parameters[0]?.name === "charset"
      && parameters[0].value.toLowerCase() === "utf-8"
    );
}

async function decodeResponse(
  response: BoundedRuntimeHttpResponse,
  invocation: NormalizedInvocation,
): Promise<DecodedHttpResponse> {
  const capture = captureBody(response.body);
  let normalized: NormalizedProviderResult;
  try {
    if (!contentTypeMatches(invocation.framing, response)) {
      await drain(capture.source);
      throw new InvalidRuntimeResponse();
    }
    if (invocation.framing === "json") {
      await drain(capture.source);
      const json = parseBoundedJson(capture.bytes(), RESPONSE_JSON_LIMITS);
      switch (invocation.route.wireProtocol) {
        case "openai-chat-completions":
        case "openai-completions":
          normalized = normalizeOpenAiJson(
            json,
            invocation.routeKey,
            invocation.generation.model.id,
          );
          break;
        case "ollama-native-chat":
        case "ollama-native-generate":
          normalized = normalizeOllamaJson(
            json,
            invocation.routeKey,
            invocation.generation.model.id,
          );
          break;
        case "tgi-native-generate":
          normalized = normalizeTgiJson(
            json,
            invocation.generation.model.id,
          );
          break;
        case "openai-responses":
          normalized = normalizeResponsesJson(
            json,
            invocation.generation.model.id,
          );
          break;
        case "lm-studio-native-chat":
          normalized = normalizeLmStudioJson(
            json,
            invocation.generation.model.id,
          );
          break;
      }
    } else if (invocation.framing === "sse") {
      if (invocation.route.wireProtocol === "lm-studio-native-chat") {
        const parsed = await parseBoundedSse(capture.source, {
          limits: DEFAULT_SSE_LIMITS,
          identity: invocation.identity,
        });
        normalized = normalizeLmStudioSse(
          parsed,
          invocation.generation.model.id,
        );
      } else {
        const parsed = await parseBoundedJsonSse(capture.source, {
          limits: DEFAULT_SSE_LIMITS,
          identity: invocation.identity,
          jsonLimits: STREAM_EVENT_JSON_LIMITS,
          protocol: invocation.route.wireProtocol === "openai-responses"
            ? "openai-responses"
            : "openai-chat-completions",
        });
        if (invocation.route.wireProtocol === "openai-responses") {
          normalized = normalizeResponsesSse(
            parsed,
            invocation.generation.model.id,
          );
        } else {
          normalized = normalizeOpenAiSse(
            parsed,
            invocation.routeKey,
            invocation.generation.model.id,
          );
        }
      }
    } else {
      const parsed = await parseBoundedNdjsonStream(capture.source, {
        limits: DEFAULT_NDJSON_STREAM_LIMITS,
        identity: invocation.identity,
        protocol: "ollama",
      });
      normalized = normalizeOllamaNdjson(
        parsed,
        invocation.routeKey,
        invocation.generation.model.id,
      );
    }
  } catch (error) {
    const sourceFailure = capture.sourceFailure();
    if (sourceFailure !== NO_CAPTURED_SOURCE_FAILURE) {
      throw sourceFailure;
    }
    if (!capture.complete()) throw error;
    normalized = Object.freeze({
      text: "",
      resolvedModelId: null,
      finishReason: null,
      usage: null,
      providerTiming: Object.freeze({}),
      logprobsObserved: false,
      terminal: "invalid",
      finalUsage: "missing",
      streamTiming: null,
    });
  }
  const raw = capture.bytes();
  const responseIdentity = createStudyPayloadIdentity(
    invocation.identity.studyId,
    invocation.identity.keyId,
    invocation.identity.key,
    raw,
  );
  return Object.freeze({
    normalized,
    responseIdentity,
    eventStreamIdentity: invocation.framing === "json"
      ? null
      : responseIdentity,
  });
}

function persistedError(
  category: "transport" | "invalid-response" | "cancelled" | "timeout",
  profileId: RuntimeProfileId,
  status?: number,
): PersistedError {
  return sanitizeErrorForPersistence({
    category,
    runtime: profileId,
    ...(status === undefined ? {} : { status }),
  });
}

function abortLifecycleForError(
  error: RuntimeWireError,
): RuntimeAbortLifecycle {
  if (error.code === "CALLER_CANCELLED") {
    return error.dispatchState === "not_sent"
      ? "caller-cancelled-before-dispatch"
      : "caller-cancelled-after-dispatch-ambiguous";
  }
  if (
    error.code === "DEADLINE_EXCEEDED"
    || error.code === "CONNECT_TIMEOUT"
    || error.code === "HEADERS_TIMEOUT"
    || error.code === "BODY_TIMEOUT"
  ) {
    return "deadline-exceeded";
  }
  return "not-aborted";
}

function buildOutcome(input: {
  readonly invocation: NormalizedInvocation;
  readonly status: RuntimeInvocationStatus;
  readonly normalized?: NormalizedProviderResult;
  readonly responseIdentity?: KeyedPayloadIdentity;
  readonly eventStreamIdentity?: KeyedPayloadIdentity | null;
  readonly dispatchState: RuntimeWireDispatchState;
  readonly abortLifecycle: RuntimeAbortLifecycle;
  readonly wireTiming?: RuntimeWireTiming;
  readonly error?: PersistedError;
}): RuntimeInvocationOutcome {
  const normalized = input.normalized;
  const output = normalized === undefined
    || normalized.text.length === 0
    ? null
    : deepFreeze<RuntimeInvocationOutput>({
      text: normalized.text,
      metadata: {
        choiceCount: 1,
        logprobsObserved: normalized.logprobsObserved,
      },
    });
  const terminalOutputIdentity =
    normalized === undefined || input.status !== "completed"
      ? null
      : createStudyPayloadIdentity(
        input.invocation.identity.studyId,
        input.invocation.identity.keyId,
        input.invocation.identity.key,
        Buffer.from(normalized.text, "utf8"),
      );
  const persistence = deepFreeze<RuntimeInvocationPersistence>({
    schemaVersion: "tasc-runtime-invocation-persistence-v1",
    status: input.status,
    endpointBindingDigest: input.invocation.endpointBindingDigest,
    profile: {
      id: input.invocation.profileId,
      build: input.invocation.profileBuild,
    },
    route: input.invocation.routeKey,
    requestedModel: input.invocation.generation.model,
    resolvedModel: normalized?.resolvedModelId === null
      || normalized?.resolvedModelId === undefined
      ? null
      : {
        id: normalized.resolvedModelId,
        revision: null,
        verification: "provider-reported",
      },
    requestIdentity: input.invocation.requestIdentity,
    responseIdentity: input.responseIdentity ?? null,
    eventStreamIdentity: input.eventStreamIdentity ?? null,
    terminalOutputIdentity,
    finishReason: normalized?.finishReason ?? null,
    providerUsage: normalized?.usage ?? null,
    providerTiming: normalized?.providerTiming ?? Object.freeze({}),
    finalUsage: normalized?.finalUsage ?? "missing",
    partialOutput:
      normalized !== undefined
      && normalized.text.length > 0
      && input.status !== "completed",
    dispatchState: input.dispatchState,
    abortLifecycle: input.abortLifecycle,
    wireTiming: input.wireTiming ?? null,
    streamTiming: normalized?.streamTiming ?? null,
    error: input.error ?? null,
  });
  return deepFreeze({
    schemaVersion: RUNTIME_INVOCATION_VERSION,
    status: input.status,
    output,
    persistence,
  });
}

function capabilityLeaseIsAuthentic(
  invocation: NormalizedInvocation,
  minimumRemainingMs = invocation.totalDeadlineMs,
): boolean {
  return invocation.capabilityAuthorization === undefined
    || verifyRuntimeCapabilityAuthorization(
      invocation.capabilityAuthorization,
      {
        instance: invocation.instance,
        capability: invocation.route.capability,
        route: invocation.routeKey,
        minimumRemainingMs,
      },
    );
}

function remainingPreparedDeadlineMs(
  authority: PreparedInvocationAuthority,
): number {
  const remainingNs = authority.expiresAtNs - process.hrtime.bigint();
  if (remainingNs <= 0n) return 0;
  return Number(remainingNs / 1_000_000n);
}

function httpLimitsWithinPreparedDeadline(
  limits: RuntimeHttpLimits,
  remainingDeadlineMs: number,
): RuntimeHttpLimits {
  const deadlineMs = Math.min(limits.deadlineMs, remainingDeadlineMs);
  return Object.freeze({
    ...limits,
    deadlineMs,
    connectTimeoutMs: Math.min(limits.connectTimeoutMs, deadlineMs),
    headersTimeoutMs: Math.min(limits.headersTimeoutMs, deadlineMs),
    bodyTimeoutMs: Math.min(limits.bodyTimeoutMs, deadlineMs),
  });
}

function endpointBindingIsAuthentic(
  invocation: NormalizedInvocation,
): boolean {
  try {
    const digest = fingerprintCollectorEndpointBinding(
      invocation.policy,
      invocation.endpointAlias,
      invocation.endpointDescriptor,
    );
    return digest === invocation.endpointBindingDigest
      && digest === invocation.instance.endpointDescriptorDigest;
  } catch {
    return false;
  }
}

/**
 * Describe the exact canonical wire request without minting dispatch power.
 *
 * Conditional capability leases are deliberately not required here: the
 * returned immutable object cannot be consumed by the dispatcher.
 */
export function describeRuntimeInvocation(
  input: RuntimeInvocationInput,
): RuntimeInvocationDescription {
  const invocation = normalizeInvocation(input, true);
  return deepFreeze({
    schemaVersion: RUNTIME_INVOCATION_DESCRIPTION_VERSION,
    endpointBindingDigest: invocation.endpointBindingDigest,
    profile: {
      id: invocation.profileId,
      build: invocation.profileBuild,
    },
    route: invocation.routeKey,
    requestedModel: invocation.generation.model,
    requestIdentity: invocation.requestIdentity,
    requestByteCount: invocation.requestBytes.byteLength,
  });
}

/**
 * Validate and freeze one exact request without authorizing or performing I/O.
 *
 * No DNS resolution, network contact, secret lookup, or capability consumption
 * occurs here. The returned object is payload-free and only the exact object
 * minted by this function can be dispatched.
 */
export function prepareRuntimeInvocation(
  input: RuntimeInvocationInput,
): PreparedRuntimeInvocation {
  const startedAtNs = process.hrtime.bigint();
  const invocation = normalizeInvocation(input);
  if (!capabilityLeaseIsAuthentic(invocation)) {
    inputFail("CAPABILITY_AUTHORIZATION_REJECTED");
  }
  const prepared = deepFreeze<PreparedRuntimeInvocation>({
    schemaVersion: PREPARED_RUNTIME_INVOCATION_VERSION,
    endpointBindingDigest: invocation.endpointBindingDigest,
    profile: {
      id: invocation.profileId,
      build: invocation.profileBuild,
    },
    route: invocation.routeKey,
    requestedModel: invocation.generation.model,
    requestIdentity: invocation.requestIdentity,
    requestByteCount: invocation.requestBytes.byteLength,
  });
  preparedInvocationAuthorities.set(prepared, {
    invocation,
    expiresAtNs:
      startedAtNs + BigInt(invocation.totalDeadlineMs) * 1_000_000n,
    consumed: false,
  });
  return prepared;
}

/**
 * Consume exactly one authentic prepared invocation and perform its one
 * profile-declared request.
 */
export async function dispatchPreparedRuntimeInvocation(
  prepared: PreparedRuntimeInvocation,
): Promise<RuntimeInvocationOutcome> {
  const authority =
    prepared !== null
      && typeof prepared === "object"
      && !isProxy(prepared)
      ? preparedInvocationAuthorities.get(prepared)
      : undefined;
  if (authority === undefined || authority.consumed) {
    inputFail("PREPARED_INVOCATION_REJECTED");
  }
  authority.consumed = true;
  const invocation = authority.invocation;
  const remainingBeforeAuthorization =
    remainingPreparedDeadlineMs(authority);
  if (remainingBeforeAuthorization < 1) {
    inputFail("PREPARED_INVOCATION_EXPIRED");
  }
  if (!endpointBindingIsAuthentic(invocation)) {
    inputFail("ENDPOINT_BINDING_MISMATCH");
  }
  if (
    !capabilityLeaseIsAuthentic(
      invocation,
      remainingBeforeAuthorization,
    )
  ) {
    inputFail("CAPABILITY_AUTHORIZATION_REJECTED");
  }
  let authorization;
  try {
    authorization = authorizeCollectorRequest(invocation.policy, {
      endpointAlias: invocation.endpointAlias,
      runtime: {
        profileId: invocation.profileId,
        build: invocation.profileBuild,
      },
      method: invocation.route.method,
      path: invocation.requestPath,
      ...(invocation.authenticationReference === undefined
        ? {}
        : {
          authenticationReference: invocation.authenticationReference,
        }),
    });
  } catch {
    inputFail();
  }

  const pinBudgetMs = remainingPreparedDeadlineMs(authority);
  if (pinBudgetMs < 1) {
    inputFail("PREPARED_INVOCATION_EXPIRED");
  }
  if (!capabilityLeaseIsAuthentic(invocation, pinBudgetMs)) {
    inputFail("CAPABILITY_AUTHORIZATION_REJECTED");
  }
  let pin: Awaited<ReturnType<typeof pinAuthorizedCollectorRequest>>;
  try {
    pin = await pinAuthorizedCollectorRequest(authorization, {
      totalDeadlineMs: pinBudgetMs,
      ...(invocation.signal === undefined
        ? {}
        : { signal: invocation.signal }),
    });
  } catch {
    const callerCancelled = invocation.signal !== undefined
      && abortSignalIsAborted(invocation.signal);
    const deadlineExceeded = !callerCancelled
      && remainingPreparedDeadlineMs(authority) < 1;
    return buildOutcome({
      invocation,
      status: "failed",
      dispatchState: "not_sent",
      abortLifecycle: callerCancelled
        ? "caller-cancelled-before-dispatch"
        : deadlineExceeded ? "deadline-exceeded" : "not-aborted",
      error: persistedError(
        callerCancelled
          ? "cancelled"
          : deadlineExceeded ? "timeout" : "transport",
        invocation.profileId,
      ),
    });
  }

  const bindingAuthentic = endpointBindingIsAuthentic(invocation);
  const transportBudgetMs = remainingPreparedDeadlineMs(authority);
  if (transportBudgetMs < 1) {
    inputFail("PREPARED_INVOCATION_EXPIRED");
  }
  const leaseAuthentic = capabilityLeaseIsAuthentic(
    invocation,
    transportBudgetMs,
  );
  if (!bindingAuthentic || !leaseAuthentic) {
    inputFail(
      bindingAuthentic
        ? "CAPABILITY_AUTHORIZATION_REJECTED"
        : "ENDPOINT_BINDING_MISMATCH",
    );
  }

  try {
    const result = await withBoundedHttpResponse(
      pin,
      {
        accept: invocation.framing === "json"
          ? "application/json"
          : invocation.framing === "sse"
            ? "text/event-stream"
            : "application/x-ndjson",
        body: invocation.requestBytes,
        limits: httpLimitsWithinPreparedDeadline(
          invocation.httpLimits,
          transportBudgetMs,
        ),
        ...(invocation.signal === undefined
          ? {}
          : { signal: invocation.signal }),
        ...(invocation.secretHeaderFactory === undefined
          ? {}
          : {
            secretHeaderFactory: invocation.secretHeaderFactory,
          }),
      },
      (response) => decodeResponse(response, invocation),
    );
    const decoded = result.value;
    if (remainingPreparedDeadlineMs(authority) < 1) {
      return buildOutcome({
        invocation,
        status: "failed",
        responseIdentity: decoded.responseIdentity,
        eventStreamIdentity: decoded.eventStreamIdentity,
        dispatchState: "completed",
        abortLifecycle: "deadline-exceeded",
        wireTiming: result.timing,
        error: persistedError(
          "timeout",
          invocation.profileId,
          result.statusCode,
        ),
      });
    }
    const normalized = decoded.normalized;
    const complete = normalized.terminal === "complete"
      && normalized.finishReason !== null
      && normalized.finalUsage === "present"
      && normalized.resolvedModelId !== null;
    const failed = normalized.terminal === "provider-error"
      || normalized.terminal === "invalid";
    const status: RuntimeInvocationStatus = failed
      ? "failed"
      : complete ? "completed" : "incomplete";
    return buildOutcome({
      invocation,
      status,
      normalized,
      responseIdentity: decoded.responseIdentity,
      eventStreamIdentity: decoded.eventStreamIdentity,
      dispatchState: "completed",
      abortLifecycle: "not-aborted",
      wireTiming: result.timing,
      ...(status === "completed"
        ? {}
        : {
          error: persistedError(
            "invalid-response",
            invocation.profileId,
            result.statusCode,
          ),
        }),
    });
  } catch (error) {
    if (error instanceof RuntimeWireError) {
      return buildOutcome({
        invocation,
        status: "failed",
        dispatchState: error.dispatchState,
        abortLifecycle: abortLifecycleForError(error),
        wireTiming: error.timing,
        error: error.persistedError,
      });
    }
    return buildOutcome({
      invocation,
      status: "failed",
      dispatchState: "not_sent",
      abortLifecycle: "not-aborted",
      error: persistedError("transport", invocation.profileId),
    });
  }
}

/**
 * Compatibility helper: prepare a durable intent and immediately dispatch it.
 */
export async function invokeRuntime(
  input: RuntimeInvocationInput,
): Promise<RuntimeInvocationOutcome> {
  return dispatchPreparedRuntimeInvocation(prepareRuntimeInvocation(input));
}
