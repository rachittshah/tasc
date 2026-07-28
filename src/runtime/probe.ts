import { Buffer } from "node:buffer";
import { isProxy } from "node:util/types";
import {
  parseBoundedJson,
  type BoundedJsonLimits,
} from "../bounded-input.js";
import {
  sanitizeErrorForPersistence,
  type PersistedError,
} from "../redaction.js";
import {
  RuntimeWireError,
  withBoundedHttpResponse,
  type BoundedRuntimeHttpResponse,
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
import type {
  EndpointDescriptor,
  RuntimeCapability,
  RuntimeCapabilityIdentityVerification,
  RuntimeCapabilityProbeEvidence,
  RuntimeInferenceRoute,
  RuntimeInstanceIdentity,
} from "./types.js";

export const RUNTIME_PROBE_VERSION = "tasc-runtime-probe-v1" as const;
export const RUNTIME_CAPABILITY_AUTHORIZATION_VERSION =
  "tasc-runtime-capability-authorization-v1" as const;

export type RuntimeProbeCapability =
  | "modelDiscovery"
  | "chatCompletions"
  | "completions"
  | "responses"
  | "nativeChat"
  | "nativeGenerate";

export type RuntimeProbeObservationEffect =
  | "non-mutating"
  | "inference-canary";

export interface RuntimeCapabilityProbeInput {
  readonly policy: CollectorTrustPolicy;
  readonly endpointAlias: string;
  readonly endpointDescriptor?: EndpointDescriptor;
  readonly instance: RuntimeInstanceIdentity;
  readonly capability: RuntimeProbeCapability;
  /**
   * Inference probes are real, billable model calls. They require this explicit
   * effect marker and use only a library-owned one-token "ping" request.
   */
  readonly observationEffect: RuntimeProbeObservationEffect;
  readonly totalDeadlineMs: number;
  readonly authorizationTtlMs?: number;
  readonly authenticationReference?: string;
  readonly secretHeaderFactory?: RuntimeSecretHeaderFactory;
  readonly signal?: AbortSignal;
}

/**
 * The visible fields are diagnostic only. Authenticity and expiry live in a
 * module-private WeakMap, so a structural copy or JSON round trip has no power.
 */
export interface RuntimeCapabilityAuthorization {
  readonly schemaVersion: typeof RUNTIME_CAPABILITY_AUTHORIZATION_VERSION;
  readonly capability: RuntimeProbeCapability;
  readonly route: RuntimeProbeCapability | null;
  readonly endpointDescriptorDigest: string;
}

export interface RuntimeCapabilityAuthorizationExpectation {
  readonly instance: RuntimeInstanceIdentity;
  readonly capability: RuntimeProbeCapability;
  readonly route: RuntimeProbeCapability | null;
  /**
   * The opaque lease must remain valid for the complete bounded operation,
   * including asynchronous secret resolution before socket dispatch.
   */
  readonly minimumRemainingMs: number;
}

export interface RuntimeProbeObservation {
  readonly effect: RuntimeProbeObservationEffect;
  readonly dispatchState: RuntimeWireDispatchState;
  readonly statusCode: number | null;
  readonly wireTiming: RuntimeWireTiming | null;
  readonly error: PersistedError | null;
}

export interface RuntimeCapabilityProbeResult {
  readonly schemaVersion: typeof RUNTIME_PROBE_VERSION;
  readonly evidence: RuntimeCapabilityProbeEvidence;
  readonly authorization: RuntimeCapabilityAuthorization | null;
  readonly observation: RuntimeProbeObservation;
}

export type RuntimeProbeInputErrorCode =
  | "INVALID_INPUT"
  | "ENDPOINT_BINDING_MISMATCH"
  | "UNSUPPORTED_PROBE";

const INPUT_ERROR_MESSAGES: Readonly<
  Record<RuntimeProbeInputErrorCode, string>
> = Object.freeze({
  INVALID_INPUT: "Runtime probe input is invalid.",
  ENDPOINT_BINDING_MISMATCH:
    "Runtime probe instance does not match the authorized endpoint.",
  UNSUPPORTED_PROBE: "Runtime probe is not supported for this profile.",
});

/** Constant-safe pre-dispatch input failure. */
export class RuntimeProbeInputError extends Error {
  readonly code: RuntimeProbeInputErrorCode;
  readonly persistedError: PersistedError;

  constructor(code: RuntimeProbeInputErrorCode) {
    super(INPUT_ERROR_MESSAGES[code]);
    this.name = "RuntimeProbeInputError";
    this.code = code;
    this.persistedError = sanitizeErrorForPersistence({
      category: "internal",
    });
    Object.freeze(this);
  }
}

interface CapabilityAuthority {
  readonly instance: RuntimeInstanceIdentity;
  readonly identityVerification: RuntimeCapabilityIdentityVerification;
  readonly capability: RuntimeProbeCapability;
  readonly route: RuntimeProbeCapability | null;
  readonly expiresAtNs: bigint;
}

interface NormalizedProbe {
  readonly policy: CollectorTrustPolicy;
  readonly endpointAlias: string;
  readonly endpointDescriptor?: EndpointDescriptor;
  readonly instance: RuntimeInstanceIdentity;
  readonly capability: RuntimeProbeCapability;
  readonly observationEffect: RuntimeProbeObservationEffect;
  readonly method: "GET" | "POST";
  readonly path: string;
  readonly requestBody?: Uint8Array;
  readonly wireProtocol: RuntimeInferenceRoute["wireProtocol"] | "model-list";
  readonly totalDeadlineMs: number;
  readonly authorizationTtlMs: number;
  readonly authenticationReference?: string;
  readonly secretHeaderFactory?: RuntimeSecretHeaderFactory;
  readonly signal?: AbortSignal;
}

const authorizationAuthorities = new WeakMap<
  RuntimeCapabilityAuthorization,
  CapabilityAuthority
>();

const INPUT_KEYS = new Set([
  "policy",
  "endpointAlias",
  "endpointDescriptor",
  "instance",
  "capability",
  "observationEffect",
  "totalDeadlineMs",
  "authorizationTtlMs",
  "authenticationReference",
  "secretHeaderFactory",
  "signal",
]);
const EXPECTATION_KEYS = new Set([
  "instance",
  "capability",
  "route",
  "minimumRemainingMs",
]);
const PROBE_CAPABILITIES = new Set<RuntimeProbeCapability>([
  "modelDiscovery",
  "chatCompletions",
  "completions",
  "responses",
  "nativeChat",
  "nativeGenerate",
]);
const INFERENCE_CAPABILITIES = new Set<RuntimeProbeCapability>([
  "chatCompletions",
  "completions",
  "responses",
  "nativeChat",
  "nativeGenerate",
]);
const MAX_JSON_BYTES = 1024 * 1024;
const MAX_MODEL_ID_LENGTH = 512;
const MAX_AUTHORIZATION_TTL_MS = 5 * 60 * 1_000;
const OPAQUE_ID_PATTERN =
  /^[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?$/;
const RESPONSE_JSON_LIMITS: Readonly<BoundedJsonLimits> = Object.freeze({
  maxBytes: MAX_JSON_BYTES,
  maxDepth: 24,
  maxObjectKeys: 16_384,
  maxArrayItems: 16_384,
  maxTokens: 131_072,
  maxDecodedStringLength: MAX_JSON_BYTES,
  maxNumericTokenLength: 128,
  maxDiagnosticSnippetLength: 0,
});
const ABORTED_GETTER =
  Reflect.getOwnPropertyDescriptor(AbortSignal.prototype, "aborted")?.get;

function fail(
  code: RuntimeProbeInputErrorCode = "INVALID_INPUT",
): never {
  throw new RuntimeProbeInputError(code);
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
    fail();
  }
  const keys = Reflect.ownKeys(input);
  if (keys.some((key) => typeof key !== "string" || !allowedKeys.has(key))) {
    fail();
  }
  const snapshot: Record<string, unknown> = Object.create(null);
  for (const key of keys) {
    const descriptor = Reflect.getOwnPropertyDescriptor(input, key);
    if (
      descriptor === undefined
      || !descriptor.enumerable
      || !Object.hasOwn(descriptor, "value")
    ) {
      fail();
    }
    snapshot[key as string] = descriptor.value;
  }
  return Object.freeze(snapshot);
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
    fail();
  }
  return value;
}

function boundedOpaqueId(value: unknown): string {
  if (
    typeof value !== "string"
    || !OPAQUE_ID_PATTERN.test(value)
  ) {
    fail();
  }
  return value;
}

function boundedText(value: unknown, maximum: number): string {
  if (
    typeof value !== "string"
    || value.length < 1
    || value.length > maximum
    || value.trim() !== value
    || /[\u0000-\u001f\u007f]/.test(value)
  ) {
    fail();
  }
  return value;
}

function parseAbortSignal(value: unknown): AbortSignal | undefined {
  if (value === undefined) return undefined;
  if (
    value === null
    || typeof value !== "object"
    || isProxy(value)
    || Reflect.getPrototypeOf(value) !== AbortSignal.prototype
    || ABORTED_GETTER === undefined
    || Reflect.ownKeys(value).some((key) => typeof key === "string")
  ) {
    fail();
  }
  try {
    if (typeof Reflect.apply(ABORTED_GETTER, value, []) !== "boolean") {
      fail();
    }
  } catch (error) {
    if (error instanceof RuntimeProbeInputError) throw error;
    fail();
  }
  return value as AbortSignal;
}

function signalIsAborted(signal: AbortSignal | undefined): boolean {
  return signal !== undefined
    && Reflect.apply(ABORTED_GETTER!, signal, []) as boolean;
}

function prefixedPath(
  endpointDescriptor: EndpointDescriptor | undefined,
  routePath: string,
): string {
  const basePath = endpointDescriptor?.basePath ?? "/";
  if (basePath === "/") return routePath;
  if (routePath === "/") return basePath;
  return `${basePath}${routePath}`;
}

function canaryBody(
  route: RuntimeInferenceRoute,
  modelId: string,
): Uint8Array {
  let body: unknown;
  switch (route.wireProtocol) {
    case "openai-chat-completions":
      body = {
        model: modelId,
        messages: [{ role: "user", content: "ping" }],
        stream: false,
        n: 1,
        max_tokens: 1,
        temperature: 0,
      };
      break;
    case "openai-completions":
      body = {
        model: modelId,
        prompt: "ping",
        stream: false,
        n: 1,
        max_tokens: 1,
        temperature: 0,
      };
      break;
    case "openai-responses":
      body = {
        model: modelId,
        input: "ping",
        stream: false,
        max_output_tokens: 1,
      };
      break;
    case "ollama-native-chat":
      body = {
        model: modelId,
        messages: [{ role: "user", content: "ping" }],
        stream: false,
        options: { num_predict: 1, temperature: 0 },
      };
      break;
    case "ollama-native-generate":
      body = {
        model: modelId,
        prompt: "ping",
        stream: false,
        options: { num_predict: 1, temperature: 0 },
      };
      break;
    case "tgi-native-generate":
      body = {
        inputs: "ping",
        parameters: { do_sample: false, max_new_tokens: 1 },
      };
      break;
    case "lm-studio-native-chat":
      body = {
        model: modelId,
        input: "ping",
        stream: false,
        store: false,
        max_output_tokens: 1,
      };
      break;
  }
  const bytes = Buffer.from(JSON.stringify(body), "utf8");
  parseBoundedJson(bytes, RESPONSE_JSON_LIMITS);
  return bytes;
}

function normalizeProbe(input: RuntimeCapabilityProbeInput): NormalizedProbe {
  const snapshot = snapshotRecord(input, INPUT_KEYS);
  for (const required of [
    "policy",
    "endpointAlias",
    "instance",
    "capability",
    "observationEffect",
    "totalDeadlineMs",
  ]) {
    if (!Object.hasOwn(snapshot, required)) fail();
  }
  if (
    typeof snapshot.capability !== "string"
    || !PROBE_CAPABILITIES.has(
      snapshot.capability as RuntimeProbeCapability,
    )
  ) {
    fail("UNSUPPORTED_PROBE");
  }
  const capability = snapshot.capability as RuntimeProbeCapability;
  const endpointAlias = boundedOpaqueId(snapshot.endpointAlias);
  const endpointDescriptor = snapshot.endpointDescriptor === undefined
    ? undefined
    : parseEndpointDescriptor(snapshot.endpointDescriptor);
  const instance = parseRuntimeInstanceIdentity(snapshot.instance);
  const profile = getRuntimeProfile(instance.runtime.profileId);
  if (profile.runtime.build !== instance.runtime.build) {
    fail("UNSUPPORTED_PROBE");
  }
  const endpointDescriptorDigest = fingerprintCollectorEndpointBinding(
    snapshot.policy as CollectorTrustPolicy,
    endpointAlias,
    endpointDescriptor,
  );
  if (endpointDescriptorDigest !== instance.endpointDescriptorDigest) {
    fail("ENDPOINT_BINDING_MISMATCH");
  }
  if (
    profile.locality === "local-only"
    && (snapshot.policy as CollectorTrustPolicy).localMode
      !== "literal-loopback-only"
  ) {
    fail("UNSUPPORTED_PROBE");
  }

  let method: "GET" | "POST";
  let path: string;
  let requestBody: Uint8Array | undefined;
  let wireProtocol: NormalizedProbe["wireProtocol"];
  if (capability === "modelDiscovery") {
    if (snapshot.observationEffect !== "non-mutating") fail();
    const route = profile.endpoints.models.list;
    if (route === undefined) fail("UNSUPPORTED_PROBE");
    method = route.method;
    path = prefixedPath(endpointDescriptor, route.path);
    wireProtocol = "model-list";
  } else {
    if (
      snapshot.observationEffect !== "inference-canary"
      || !INFERENCE_CAPABILITIES.has(capability)
    ) {
      fail();
    }
    const route = profile.endpoints.inference[capability];
    if (route === undefined) fail("UNSUPPORTED_PROBE");
    const expectation = profile.capabilities[route.capability];
    if (
      expectation.state === "unsupported"
      || expectation.state === "unknown"
    ) {
      fail("UNSUPPORTED_PROBE");
    }
    method = route.method;
    path = prefixedPath(endpointDescriptor, route.path);
    wireProtocol = route.wireProtocol;
    requestBody = canaryBody(route, instance.model.id);
  }

  if (
    Object.hasOwn(snapshot, "secretHeaderFactory")
    && (
      typeof snapshot.secretHeaderFactory !== "function"
      || isProxy(snapshot.secretHeaderFactory)
    )
  ) {
    fail();
  }
  const totalDeadlineMs = safeInteger(
    snapshot.totalDeadlineMs,
    1,
    Math.min(300_000, (snapshot.policy as CollectorTrustPolicy)
      .maximumRequestDurationMs),
  );
  const maximumAuthorizationTtlMs = Math.min(
    MAX_AUTHORIZATION_TTL_MS,
    (snapshot.policy as CollectorTrustPolicy).maximumRequestDurationMs,
  );
  const authorizationTtlMs = snapshot.authorizationTtlMs === undefined
    ? Math.min(60_000, maximumAuthorizationTtlMs)
    : safeInteger(
      snapshot.authorizationTtlMs,
      1,
      maximumAuthorizationTtlMs,
    );
  const signal = parseAbortSignal(snapshot.signal);

  return Object.freeze({
    policy: snapshot.policy as CollectorTrustPolicy,
    endpointAlias,
    ...(endpointDescriptor === undefined ? {} : { endpointDescriptor }),
    instance,
    capability,
    observationEffect: snapshot.observationEffect,
    method,
    path,
    ...(requestBody === undefined
      ? {}
      : {
        requestBody:
          Uint8Array.prototype.slice.call(requestBody) as Uint8Array,
      }),
    wireProtocol,
    totalDeadlineMs,
    authorizationTtlMs,
    ...(snapshot.authenticationReference === undefined
      ? {}
      : {
        authenticationReference: boundedOpaqueId(
          snapshot.authenticationReference,
        ),
      }),
    ...(snapshot.secretHeaderFactory === undefined
      ? {}
      : {
        secretHeaderFactory:
          snapshot.secretHeaderFactory as RuntimeSecretHeaderFactory,
      }),
    ...(signal === undefined ? {} : { signal }),
  });
}

function record(
  value: unknown,
): Readonly<Record<string, unknown>> | null {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Readonly<Record<string, unknown>>
    : null;
}

async function readJson(
  response: BoundedRuntimeHttpResponse,
): Promise<unknown> {
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of response.body) {
    total += chunk.byteLength;
    if (total > MAX_JSON_BYTES) throw new Error("invalid probe response");
    chunks.push(Buffer.from(chunk));
  }
  if (response.contentType !== "application/json") {
    throw new Error("invalid probe response");
  }
  return parseBoundedJson(
    Buffer.concat(chunks, total),
    RESPONSE_JSON_LIMITS,
  );
}

function identityVerification(input: {
  readonly probe: NormalizedProbe;
  readonly providerModelId?: string;
  readonly providerModelRevision?: string;
  readonly providerRuntimeBuild?: string;
}): RuntimeCapabilityIdentityVerification {
  return deepFreeze({
    endpointBinding: "operator-policy",
    runtimeBuild: input.providerRuntimeBuild === undefined
      ? {
        basis: "operator-policy",
        observed: null,
      }
      : {
        basis: "provider-reported",
        observed: input.providerRuntimeBuild,
      },
    backend: {
      basis: "unverified",
      observed: null,
    },
    modelId: input.providerModelId === undefined
      ? {
        basis: "unverified",
        observed: null,
      }
      : {
        basis: "provider-reported",
        observed: input.providerModelId,
      },
    modelRevision: input.providerModelRevision === undefined
      ? {
        basis: "unverified",
        observed: null,
      }
      : {
        basis: "provider-reported",
        observed: input.providerModelRevision,
      },
    configurationDigest: {
      basis: "unverified",
      observed: null,
    },
  });
}

function validateModelList(
  value: unknown,
  probe: NormalizedProbe,
): RuntimeCapabilityIdentityVerification {
  const json = record(value);
  if (json === null) throw new Error("invalid probe response");
  if (probe.instance.runtime.profileId === "ollama") {
    if (!Array.isArray(json.models)) throw new Error("invalid probe response");
    let exact = 0;
    let observedRevision: string | undefined;
    for (const item of json.models) {
      const model = record(item);
      if (model === null || typeof model.name !== "string") {
        throw new Error("invalid probe response");
      }
      if (model.name === probe.instance.model.id) {
        exact += 1;
        if (
          typeof model.digest !== "string"
          || !/^[a-f0-9]{64}$/.test(model.digest)
          || (
            probe.instance.model.revision !== model.digest
            && probe.instance.model.revision !== `sha256:${model.digest}`
          )
        ) {
          throw new Error("probe model identity mismatch");
        }
        observedRevision = probe.instance.model.revision;
      }
    }
    if (exact !== 1) throw new Error("probe model identity mismatch");
    return identityVerification({
      probe,
      providerModelId: probe.instance.model.id,
      providerModelRevision: observedRevision,
    });
  }
  if (json.object !== "list" || !Array.isArray(json.data)) {
    throw new Error("invalid probe response");
  }
  let exact = 0;
  const seen = new Set<string>();
  for (const item of json.data) {
    const model = record(item);
    if (
      model === null
      || typeof model.id !== "string"
      || model.id.length < 1
      || model.id.length > MAX_MODEL_ID_LENGTH
      || seen.has(model.id)
    ) {
      throw new Error("invalid probe response");
    }
    seen.add(model.id);
    if (model.id === probe.instance.model.id) exact += 1;
  }
  if (exact !== 1) throw new Error("probe model identity mismatch");
  return identityVerification({
    probe,
    providerModelId: probe.instance.model.id,
  });
}

function validateOpenAiChoice(value: unknown): void {
  const json = record(value);
  if (json === null || !Array.isArray(json.choices)) {
    throw new Error("invalid probe response");
  }
  if (json.choices.length !== 1) throw new Error("invalid probe response");
  const choice = record(json.choices[0]);
  if (
    choice === null
    || (Object.hasOwn(choice, "index") && choice.index !== 0)
    || typeof choice.finish_reason !== "string"
    || choice.finish_reason.length < 1
    || choice.finish_reason.length > 128
  ) {
    throw new Error("invalid probe response");
  }
  const message = record(choice.message);
  if (
    typeof choice.text !== "string"
    && typeof message?.content !== "string"
  ) {
    throw new Error("invalid probe response");
  }
}

function validateCanary(
  value: unknown,
  probe: NormalizedProbe,
): RuntimeCapabilityIdentityVerification {
  const json = record(value);
  if (json === null || Object.hasOwn(json, "error")) {
    throw new Error("invalid probe response");
  }
  switch (probe.wireProtocol) {
    case "openai-chat-completions":
    case "openai-completions":
      if (json.model !== probe.instance.model.id) {
        throw new Error("probe model identity mismatch");
      }
      validateOpenAiChoice(json);
      return identityVerification({
        probe,
        providerModelId: probe.instance.model.id,
      });
    case "openai-responses":
      if (
        json.model !== probe.instance.model.id
        || json.status !== "completed"
        || (
          !Array.isArray(json.output)
          && typeof json.output_text !== "string"
        )
      ) {
        throw new Error("invalid probe response");
      }
      return identityVerification({
        probe,
        providerModelId: probe.instance.model.id,
      });
    case "ollama-native-chat": {
      const message = record(json.message);
      if (
        json.model !== probe.instance.model.id
        || json.done !== true
        || typeof json.done_reason !== "string"
        || typeof message?.content !== "string"
      ) {
        throw new Error("invalid probe response");
      }
      return identityVerification({
        probe,
        providerModelId: probe.instance.model.id,
      });
    }
    case "ollama-native-generate":
      if (
        json.model !== probe.instance.model.id
        || json.done !== true
        || typeof json.done_reason !== "string"
        || typeof json.response !== "string"
      ) {
        throw new Error("invalid probe response");
      }
      return identityVerification({
        probe,
        providerModelId: probe.instance.model.id,
      });
    case "tgi-native-generate":
      if (typeof json.generated_text !== "string") {
        throw new Error("invalid probe response");
      }
      return identityVerification({ probe });
    case "lm-studio-native-chat":
      if (
        json.model !== probe.instance.model.id
        && json.model_instance_id !== probe.instance.model.id
      ) {
        throw new Error("probe model identity mismatch");
      }
      if (!Array.isArray(json.output) && typeof json.output !== "string") {
        throw new Error("invalid probe response");
      }
      return identityVerification({
        probe,
        providerModelId: probe.instance.model.id,
      });
    case "model-list":
      throw new Error("invalid probe response");
  }
}

function capabilityEvidence(
  probe: NormalizedProbe,
  state: RuntimeCapabilityProbeEvidence["state"],
  verification: RuntimeCapabilityIdentityVerification,
): RuntimeCapabilityProbeEvidence {
  return deepFreeze({
    schemaVersion: "tasc-runtime-capability-probe-v1",
    source: "live-probe",
    capability: probe.capability as RuntimeCapability,
    state,
    probedAt: new Date().toISOString(),
    identityVerification: verification,
    endpointDescriptorDigest: probe.instance.endpointDescriptorDigest,
    runtime: probe.instance.runtime,
    backend: probe.instance.backend,
    model: probe.instance.model,
    configurationDigest: probe.instance.configurationDigest,
  });
}

function issueAuthorization(
  probe: NormalizedProbe,
  verification: RuntimeCapabilityIdentityVerification,
): RuntimeCapabilityAuthorization {
  const authorization = Object.freeze({
    schemaVersion: RUNTIME_CAPABILITY_AUTHORIZATION_VERSION,
    capability: probe.capability,
    route: probe.capability,
    endpointDescriptorDigest: probe.instance.endpointDescriptorDigest,
  });
  authorizationAuthorities.set(authorization, {
    instance: probe.instance,
    identityVerification: verification,
    capability: probe.capability,
    route: probe.capability,
    expiresAtNs:
      process.hrtime.bigint()
      + BigInt(probe.authorizationTtlMs) * 1_000_000n,
  });
  return authorization;
}

function sameInstance(
  left: RuntimeInstanceIdentity,
  right: RuntimeInstanceIdentity,
): boolean {
  return left.endpointDescriptorDigest === right.endpointDescriptorDigest
    && left.runtime.profileId === right.runtime.profileId
    && left.runtime.build === right.runtime.build
    && left.backend.name === right.backend.name
    && left.backend.build === right.backend.build
    && left.model.id === right.model.id
    && left.model.revision === right.model.revision
    && left.configurationDigest === right.configurationDigest;
}

/**
 * Authenticate a route-scoped live-probe token.
 *
 * This function deliberately returns only a boolean. It does not reveal token
 * internals, extend expiry, or turn persisted probe evidence into authority.
 */
export function verifyRuntimeCapabilityAuthorization(
  authorization: RuntimeCapabilityAuthorization,
  expectationInput: RuntimeCapabilityAuthorizationExpectation,
): boolean {
  try {
    if (
      authorization === null
      || typeof authorization !== "object"
      || isProxy(authorization)
    ) {
      return false;
    }
    const authority = authorizationAuthorities.get(authorization);
    if (authority === undefined) return false;
    if (process.hrtime.bigint() >= authority.expiresAtNs) {
      authorizationAuthorities.delete(authorization);
      return false;
    }
    const expectation = snapshotRecord(
      expectationInput,
      EXPECTATION_KEYS,
    );
    if (Reflect.ownKeys(expectation).length !== EXPECTATION_KEYS.size) {
      return false;
    }
    if (
      typeof expectation.capability !== "string"
      || !PROBE_CAPABILITIES.has(
        expectation.capability as RuntimeProbeCapability,
      )
      || (
        expectation.route !== null
        && (
          typeof expectation.route !== "string"
          || !PROBE_CAPABILITIES.has(
            expectation.route as RuntimeProbeCapability,
          )
        )
      )
    ) {
      return false;
    }
    const instance = parseRuntimeInstanceIdentity(expectation.instance);
    if (
      typeof expectation.minimumRemainingMs !== "number"
      || !Number.isSafeInteger(expectation.minimumRemainingMs)
      || expectation.minimumRemainingMs < 0
      || expectation.minimumRemainingMs > 300_000
    ) {
      return false;
    }
    const remainingNs = authority.expiresAtNs - process.hrtime.bigint();
    if (
      remainingNs
      < BigInt(expectation.minimumRemainingMs) * 1_000_000n
    ) {
      return false;
    }
    return authority.capability === expectation.capability
      && authority.route === expectation.route
      && sameInstance(authority.instance, instance);
  } catch {
    return false;
  }
}

function observation(
  probe: NormalizedProbe,
  dispatchState: RuntimeWireDispatchState,
  statusCode: number | null,
  wireTiming: RuntimeWireTiming | null,
  error: PersistedError | null,
): RuntimeProbeObservation {
  return deepFreeze({
    effect: probe.observationEffect,
    dispatchState,
    statusCode,
    wireTiming,
    error,
  });
}

function result(
  probe: NormalizedProbe,
  state: RuntimeCapabilityProbeEvidence["state"],
  verification: RuntimeCapabilityIdentityVerification,
  authorization: RuntimeCapabilityAuthorization | null,
  probeObservation: RuntimeProbeObservation,
): RuntimeCapabilityProbeResult {
  return deepFreeze({
    schemaVersion: RUNTIME_PROBE_VERSION,
    evidence: capabilityEvidence(probe, state, verification),
    authorization,
    observation: probeObservation,
  });
}

/**
 * Perform exactly one profile-owned capability observation.
 *
 * Passive discovery and explicit inference canaries both traverse the same
 * operator policy, fresh DNS pin, and bounded HTTP transport. No retry,
 * routing, scoring, evaluator, deployment, or arbitrary request behavior is
 * present here.
 */
export async function probeRuntimeCapability(
  input: RuntimeCapabilityProbeInput,
): Promise<RuntimeCapabilityProbeResult> {
  const probe = normalizeProbe(input);
  const startedAtNs = process.hrtime.bigint();
  const unverified = identityVerification({ probe });
  if (signalIsAborted(probe.signal)) {
    return result(
      probe,
      "unknown",
      unverified,
      null,
      observation(
        probe,
        "not_sent",
        null,
        null,
        sanitizeErrorForPersistence({
          category: "cancelled",
          runtime: probe.instance.runtime.profileId,
        }),
      ),
    );
  }
  let collectorAuthorization;
  try {
    collectorAuthorization = authorizeCollectorRequest(probe.policy, {
      endpointAlias: probe.endpointAlias,
      runtime: probe.instance.runtime,
      method: probe.method,
      path: probe.path,
      ...(probe.authenticationReference === undefined
        ? {}
        : {
          authenticationReference: probe.authenticationReference,
        }),
    });
  } catch {
    fail();
  }

  try {
    const pin = await pinAuthorizedCollectorRequest(
      collectorAuthorization,
      {
        totalDeadlineMs: probe.totalDeadlineMs,
        ...(probe.signal === undefined ? {} : { signal: probe.signal }),
      },
    );
    const response = await withBoundedHttpResponse(
      pin,
      {
        accept: "application/json",
        ...(probe.requestBody === undefined
          ? {}
          : { body: probe.requestBody }),
        ...(probe.signal === undefined ? {} : { signal: probe.signal }),
        ...(probe.secretHeaderFactory === undefined
          ? {}
          : { secretHeaderFactory: probe.secretHeaderFactory }),
      },
      async (wireResponse) => {
        const json = await readJson(wireResponse);
        return probe.capability === "modelDiscovery"
          ? validateModelList(json, probe)
          : validateCanary(json, probe);
      },
    );
    const authority = probe.capability === "modelDiscovery"
      ? null
      : issueAuthorization(probe, response.value);
    return result(
      probe,
      "supported",
      response.value,
      authority,
      observation(
        probe,
        "completed",
        response.statusCode,
        response.timing,
        null,
      ),
    );
  } catch (error) {
    if (error instanceof RuntimeWireError) {
      const unsupported =
        error.code === "PROVIDER_ERROR"
        && error.statusCode === 404
        && error.dispatchState === "completed";
      return result(
        probe,
        unsupported ? "unsupported" : "unknown",
        unverified,
        null,
        observation(
          probe,
          error.dispatchState,
          error.statusCode ?? null,
          error.timing,
          error.persistedError,
        ),
      );
    }
    const elapsedMs = Number(
      process.hrtime.bigint() - startedAtNs,
    ) / 1_000_000;
    const category = signalIsAborted(probe.signal)
      ? "cancelled"
      : elapsedMs >= Math.max(0, probe.totalDeadlineMs - 1)
        ? "timeout"
        : "transport";
    return result(
      probe,
      "unknown",
      unverified,
      null,
      observation(
        probe,
        "not_sent",
        null,
        null,
        sanitizeErrorForPersistence({
          category,
          runtime: probe.instance.runtime.profileId,
        }),
      ),
    );
  }
}
