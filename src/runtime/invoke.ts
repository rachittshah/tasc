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
  type JsonSseParseResult,
  type RuntimeStreamIdentity,
  type RuntimeStreamTiming,
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

export type RuntimeInvocationRoute =
  | "chatCompletions"
  | "completions"
  | "nativeChat";

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

export interface RuntimeProviderUsage {
  readonly inputTokens: number;
  readonly outputTokens: number;
  readonly totalTokens: number;
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
  | "CAPABILITY_AUTHORIZATION_REJECTED";

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
});

/** A constant-safe failure raised before any request is pinned or dispatched. */
export class RuntimeInvocationInputError extends Error {
  readonly code: RuntimeInvocationInputErrorCode;
  readonly persistedError: PersistedError;

  constructor(code: RuntimeInvocationInputErrorCode) {
    super(INPUT_ERROR_MESSAGES[code]);
    this.name = "RuntimeInvocationInputError";
    this.code = code;
    this.persistedError = sanitizeErrorForPersistence({
      category:
        code === "CONDITIONAL_CAPABILITY_REQUIRES_AUTHORIZATION"
          || code === "CAPABILITY_AUTHORIZATION_REJECTED"
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
  "content_filter",
  "error",
  "function_call",
  "length",
  "load",
  "stop",
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
const MAXIMUM_HTTP_LIMITS: Readonly<RuntimeHttpLimits> = Object.freeze({
  maxRequestBytes: 16_777_216,
  maxResponseHeaderBytes: 16_384,
  maxResponseHeaders: 256,
  maxResponseBytes: 16_777_216,
  maxResponseChunks: 16_384,
  maxSecretHeaderBytes: 16_384,
  connectTimeoutMs: 30_000,
  headersTimeoutMs: 60_000,
  bodyTimeoutMs: 60_000,
  deadlineMs: 300_000,
});

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
  if (input === undefined) return DEFAULT_RUNTIME_HTTP_LIMITS;
  const snapshot = snapshotRecord(input, HTTP_LIMIT_KEYS);
  const limits: Record<string, number> = {
    ...DEFAULT_RUNTIME_HTTP_LIMITS,
  };
  for (const [key, value] of Object.entries(snapshot)) {
    limits[key] = safeInteger(value, 1, Number.MAX_SAFE_INTEGER);
    if (
      limits[key]! > MAXIMUM_HTTP_LIMITS[key as keyof RuntimeHttpLimits]
    ) {
      inputFail();
    }
  }
  if (
    limits.maxRequestBytes! > MAX_REQUEST_BYTES
    || limits.maxResponseBytes! > MAX_RESPONSE_BYTES
  ) {
    inputFail();
  }
  return Object.freeze(limits) as unknown as RuntimeHttpLimits;
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
}

function buildRequestBody(
  profileId: RuntimeProfileId,
  routeKey: RuntimeInvocationRoute,
  generation: RuntimeGenerationRequest,
): unknown {
  const sampling = {
    ...(generation.temperature === undefined
      ? {}
      : { temperature: generation.temperature }),
    ...(generation.topP === undefined ? {} : { top_p: generation.topP }),
    ...(generation.seed === undefined ? {} : { seed: generation.seed }),
  };
  if (routeKey === "nativeChat" && profileId === "ollama") {
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
  }
  if (routeKey === "chatCompletions") {
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
  }
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
}

function routeFraming(
  route: RuntimeInferenceRoute,
  stream: boolean,
): "json" | "sse" | "ndjson" {
  const framing = stream
    ? route.wireProtocol.startsWith("ollama-") ? "ndjson" : "sse"
    : "json";
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

function normalizeInvocation(input: RuntimeInvocationInput): NormalizedInvocation {
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
    && snapshot.route !== "nativeChat"
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
  const endpointBindingDigest = fingerprintCollectorEndpointBinding(
    snapshot.policy as CollectorTrustPolicy,
    endpointAlias,
    endpointDescriptor,
  );
  if (instance.endpointDescriptorDigest !== endpointBindingDigest) {
    inputFail("ENDPOINT_BINDING_MISMATCH");
  }
  if (
    profile.locality === "local-only"
    && (snapshot.policy as CollectorTrustPolicy).localMode
      !== "literal-loopback-only"
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
    if (authorizations.length === 0) {
      inputFail("CONDITIONAL_CAPABILITY_REQUIRES_AUTHORIZATION");
    }
    if (authorizations.length !== 1) {
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
    buildRequestBody(profile.id, routeKey, generation),
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
    totalDeadlineMs
      > (snapshot.policy as CollectorTrustPolicy).maximumRequestDurationMs
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
    policy: snapshot.policy as CollectorTrustPolicy,
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

function normalizeOllamaJson(
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
  const message = record(json.message);
  if (
    json.done !== true
    || typeof message?.content !== "string"
    || message.content.length > MAX_TEXT_LENGTH
  ) {
    throw new InvalidRuntimeResponse();
  }
  const finishReason = safeFinishReason(json.done_reason);
  const usage = parseOllamaUsage(json);
  return Object.freeze({
    text: message.content,
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

function normalizeOllamaNdjson(
  parsed: NdjsonStreamParseResult,
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
    if (Object.hasOwn(json, "message")) {
      const message = record(json.message);
      if (message === null) throw new InvalidRuntimeResponse();
      if (Object.hasOwn(message, "content")) {
        if (typeof message.content !== "string") {
          throw new InvalidRuntimeResponse();
        }
        text += message.content;
        if (text.length > MAX_TEXT_LENGTH) throw new InvalidRuntimeResponse();
      }
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
  contentType: string | undefined,
): boolean {
  if (framing === "json") return contentType === "application/json";
  if (framing === "sse") return contentType === "text/event-stream";
  return contentType === "application/x-ndjson";
}

async function decodeResponse(
  response: BoundedRuntimeHttpResponse,
  invocation: NormalizedInvocation,
): Promise<DecodedHttpResponse> {
  const capture = captureBody(response.body);
  let normalized: NormalizedProviderResult;
  try {
    if (!contentTypeMatches(invocation.framing, response.contentType)) {
      await drain(capture.source);
      throw new InvalidRuntimeResponse();
    }
    if (invocation.framing === "json") {
      await drain(capture.source);
      const json = parseBoundedJson(capture.bytes(), RESPONSE_JSON_LIMITS);
      normalized = invocation.route.wireProtocol.startsWith("ollama-")
        ? normalizeOllamaJson(json, invocation.generation.model.id)
        : normalizeOpenAiJson(
          json,
          invocation.routeKey,
          invocation.generation.model.id,
        );
    } else if (invocation.framing === "sse") {
      const parsed = await parseBoundedJsonSse(capture.source, {
        limits: DEFAULT_SSE_LIMITS,
        identity: invocation.identity,
        jsonLimits: STREAM_EVENT_JSON_LIMITS,
        protocol: "openai-chat-completions",
      });
      normalized = normalizeOpenAiSse(
        parsed,
        invocation.routeKey,
        invocation.generation.model.id,
      );
    } else {
      const parsed = await parseBoundedNdjsonStream(capture.source, {
        limits: DEFAULT_NDJSON_STREAM_LIMITS,
        identity: invocation.identity,
        protocol: "ollama",
      });
      normalized = normalizeOllamaNdjson(
        parsed,
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

/**
 * Perform exactly one profile-declared inference request.
 *
 * Invalid DTOs, endpoint bindings, unsupported routes, and unauthorised
 * conditional capabilities throw before pinning. Once authorization succeeds,
 * pin/transport/provider failures become immutable Task-13-friendly outcomes.
 */
export async function invokeRuntime(
  input: RuntimeInvocationInput,
): Promise<RuntimeInvocationOutcome> {
  const invocation = normalizeInvocation(input);
  if (
    invocation.capabilityAuthorization !== undefined
    && !verifyRuntimeCapabilityAuthorization(
      invocation.capabilityAuthorization,
      {
        instance: invocation.instance,
        capability: invocation.route.capability,
        route: invocation.routeKey,
        minimumRemainingMs: invocation.totalDeadlineMs,
      },
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

  const pinStartedAtNs = process.hrtime.bigint();
  let pin: Awaited<ReturnType<typeof pinAuthorizedCollectorRequest>>;
  try {
    pin = await pinAuthorizedCollectorRequest(authorization, {
      totalDeadlineMs: invocation.totalDeadlineMs,
      ...(invocation.signal === undefined
        ? {}
        : { signal: invocation.signal }),
    });
  } catch {
    const callerCancelled = invocation.signal !== undefined
      && abortSignalIsAborted(invocation.signal);
    const elapsedMs =
      Number(process.hrtime.bigint() - pinStartedAtNs) / 1_000_000;
    const deadlineExceeded = !callerCancelled
      && elapsedMs + 1 >= invocation.totalDeadlineMs;
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

  if (
    invocation.capabilityAuthorization !== undefined
    && !verifyRuntimeCapabilityAuthorization(
      invocation.capabilityAuthorization,
      {
        instance: invocation.instance,
        capability: invocation.route.capability,
        route: invocation.routeKey,
        minimumRemainingMs: invocation.totalDeadlineMs,
      },
    )
  ) {
    inputFail("CAPABILITY_AUTHORIZATION_REJECTED");
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
        limits: invocation.httpLimits,
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
