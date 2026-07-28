import { Buffer } from "node:buffer";
import { isIP, type LookupFunction } from "node:net";
import {
  isProxy,
  isSharedArrayBuffer,
  isUint8Array,
} from "node:util/types";
import { Client, errors } from "undici";
import {
  sanitizeErrorForPersistence,
  type PersistedError,
  type PersistedErrorCategory,
} from "../redaction.js";
import {
  consumePinnedCollectorRequest,
  type PinnedCollectorRequest,
  type PinnedHttpRequestTarget,
} from "./network-policy.js";

export type RuntimeWireDispatchState =
  | "not_sent"
  | "sent_unknown"
  | "completed";

export type RuntimeWireErrorCode =
  | "INVALID_REQUEST"
  | "AUTHORIZATION_REJECTED"
  | "AUTHENTICATION_UNAVAILABLE"
  | "AUTHENTICATION_REJECTED"
  | "CALLER_CANCELLED"
  | "DEADLINE_EXCEEDED"
  | "CONNECT_TIMEOUT"
  | "HEADERS_TIMEOUT"
  | "BODY_TIMEOUT"
  | "CONNECT_FAILED"
  | "INVALID_RESPONSE_HEADERS"
  | "COMPRESSED_RESPONSE"
  | "REDIRECT_DENIED"
  | "PROVIDER_ERROR"
  | "RESPONSE_TOO_LARGE"
  | "RESPONSE_CHUNK_LIMIT"
  | "RESPONSE_TRUNCATED"
  | "RESPONSE_NOT_CONSUMED"
  | "RESPONSE_REJECTED";

export interface RuntimeWireTiming {
  readonly startedAt: string;
  readonly headersMs?: number;
  readonly firstByteMs?: number;
  readonly completedMs: number;
}

export interface RuntimeWireTargetMetadata {
  readonly endpointAlias: string;
  readonly runtime: {
    readonly profileId: PinnedHttpRequestTarget["runtime"]["profileId"];
    readonly build: string;
  };
}

const RUNTIME_WIRE_ERROR_TOKEN = Symbol("tasc.runtime-wire-error");
const runtimeWireErrorOwners = new WeakMap<object, object>();

export class RuntimeWireError extends Error {
  readonly code: RuntimeWireErrorCode;
  readonly dispatchState: RuntimeWireDispatchState;
  readonly statusCode?: number;
  readonly timing: RuntimeWireTiming;
  readonly target?: RuntimeWireTargetMetadata;
  readonly persistedError: PersistedError;

  constructor(input: {
    readonly code: RuntimeWireErrorCode;
    readonly diagnostic: string;
    readonly dispatchState: RuntimeWireDispatchState;
    readonly statusCode?: number;
    readonly timing: RuntimeWireTiming;
    readonly target?: RuntimeWireTargetMetadata;
    readonly persistedError: PersistedError;
  }, authenticationToken?: symbol, owner?: object) {
    super(input.diagnostic);
    this.name = "RuntimeWireError";
    this.code = input.code;
    this.dispatchState = input.dispatchState;
    this.statusCode = input.statusCode;
    this.timing = Object.freeze({ ...input.timing });
    this.target = input.target;
    this.persistedError = input.persistedError;
    if (
      authenticationToken === RUNTIME_WIRE_ERROR_TOKEN &&
      owner !== undefined
    ) {
      runtimeWireErrorOwners.set(this, owner);
    }
    Object.freeze(this);
  }
}

function isAuthenticRuntimeWireError(
  value: unknown,
  owner: object,
): value is RuntimeWireError {
  return (
    value !== null &&
    typeof value === "object" &&
    runtimeWireErrorOwners.get(value) === owner
  );
}

export interface RuntimeHttpLimits {
  readonly maxRequestBytes: number;
  readonly maxResponseHeaderBytes: number;
  readonly maxResponseHeaders: number;
  readonly maxResponseBytes: number;
  readonly maxResponseChunks: number;
  readonly maxSecretHeaderBytes: number;
  readonly connectTimeoutMs: number;
  readonly headersTimeoutMs: number;
  readonly bodyTimeoutMs: number;
  readonly deadlineMs: number;
}

export const DEFAULT_RUNTIME_HTTP_LIMITS: RuntimeHttpLimits = Object.freeze({
  maxRequestBytes: 1_048_576,
  maxResponseHeaderBytes: 16_384,
  maxResponseHeaders: 64,
  maxResponseBytes: 8_388_608,
  maxResponseChunks: 4_096,
  maxSecretHeaderBytes: 8_192,
  connectTimeoutMs: 5_000,
  headersTimeoutMs: 10_000,
  bodyTimeoutMs: 10_000,
  deadlineMs: 30_000,
});

export type RuntimeSecretHeaderName = "authorization" | "x-api-key";
export type RuntimeSecretHeaders = readonly (
  readonly [RuntimeSecretHeaderName, string]
)[];
export type RuntimeSecretHeaderFactory = (
  authenticationReference: string,
  signal: AbortSignal,
) => RuntimeSecretHeaders | Promise<RuntimeSecretHeaders>;

export const RUNTIME_HTTP_ACCEPT_VALUES = Object.freeze([
  "application/json",
  "text/event-stream",
  "application/x-ndjson",
  "text/plain; version=0.0.4",
] as const);
export type RuntimeHttpAccept =
  typeof RUNTIME_HTTP_ACCEPT_VALUES[number];

export interface RuntimeHttpRequest {
  readonly accept?: RuntimeHttpAccept;
  readonly body?: Uint8Array;
  readonly limits?: Partial<RuntimeHttpLimits>;
  readonly signal?: AbortSignal;
  readonly secretHeaderFactory?: RuntimeSecretHeaderFactory;
}

export interface BoundedRuntimeHttpResponse {
  readonly statusCode: number;
  readonly contentType?: string;
  readonly contentTypeParameters?: readonly RuntimeContentTypeParameter[];
  readonly body: AsyncIterable<Uint8Array>;
  readonly signal: AbortSignal;
}

export interface RuntimeContentTypeParameter {
  readonly name: string;
  readonly value: string;
}

export interface BoundedRuntimeHttpResult<T> {
  readonly value: T;
  readonly statusCode: number;
  readonly responseBytes: number;
  readonly responseChunks: number;
  readonly timing: RuntimeWireTiming;
  readonly target: RuntimeWireTargetMetadata;
}

interface MutableTiming {
  readonly startedAt: string;
  readonly startedNs: bigint;
  headersMs?: number;
  firstByteMs?: number;
  target?: RuntimeWireTargetMetadata;
}

interface LifecycleState {
  dispatchState: RuntimeWireDispatchState;
  responseStatusCode?: number;
  responseComplete: boolean;
  responseBytes: number;
  responseChunks: number;
}

class OperationAbort extends Error {}
type OperationAbortSource =
  | "caller"
  | "deadline"
  | "connect"
  | "headers"
  | "body";

const MAXIMUM_LIMITS: RuntimeHttpLimits = Object.freeze({
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

const LIMIT_KEYS = Object.freeze(
  Object.keys(DEFAULT_RUNTIME_HTTP_LIMITS) as readonly (
    keyof RuntimeHttpLimits
  )[],
);

const EVENT_TARGET_ADD_EVENT_LISTENER =
  EventTarget.prototype.addEventListener;
const EVENT_TARGET_REMOVE_EVENT_LISTENER =
  EventTarget.prototype.removeEventListener;
const ABORT_SIGNAL_ABORTED_GETTER = Reflect.getOwnPropertyDescriptor(
  AbortSignal.prototype,
  "aborted",
)?.get;
const TYPED_ARRAY_PROTOTYPE =
  Reflect.getPrototypeOf(Uint8Array.prototype) ?? Uint8Array.prototype;
const TYPED_ARRAY_BUFFER_GETTER = Reflect.getOwnPropertyDescriptor(
  TYPED_ARRAY_PROTOTYPE,
  "buffer",
)?.get;
const TYPED_ARRAY_BYTE_OFFSET_GETTER = Reflect.getOwnPropertyDescriptor(
  TYPED_ARRAY_PROTOTYPE,
  "byteOffset",
)?.get;
const TYPED_ARRAY_BYTE_LENGTH_GETTER = Reflect.getOwnPropertyDescriptor(
  TYPED_ARRAY_PROTOTYPE,
  "byteLength",
)?.get;

function abortSignalIsAborted(signal: AbortSignal): boolean {
  if (ABORT_SIGNAL_ABORTED_GETTER === undefined) {
    return true;
  }
  return Reflect.apply(ABORT_SIGNAL_ABORTED_GETTER, signal, []) as boolean;
}

function hasAbortSignalBrand(value: object): value is AbortSignal {
  if (ABORT_SIGNAL_ABORTED_GETTER === undefined) {
    return false;
  }
  try {
    return typeof Reflect.apply(
      ABORT_SIGNAL_ABORTED_GETTER,
      value,
      [],
    ) === "boolean";
  } catch {
    return false;
  }
}

function addAbortListener(
  signal: AbortSignal,
  listener: () => void,
): void {
  Reflect.apply(EVENT_TARGET_ADD_EVENT_LISTENER, signal, [
    "abort",
    listener,
    { once: true },
  ]);
}

function removeAbortListener(
  signal: AbortSignal,
  listener: () => void,
): void {
  Reflect.apply(EVENT_TARGET_REMOVE_EVENT_LISTENER, signal, [
    "abort",
    listener,
  ]);
}

function snapshotDataRecord<const TKey extends string>(
  input: unknown,
  allowedKeys: readonly TKey[],
  timing: MutableTiming,
  diagnostic: string,
): Partial<Record<TKey, unknown>> {
  try {
    if (
      input === null ||
      typeof input !== "object" ||
      isProxy(input)
    ) {
      throw new Error();
    }
    const prototype = Reflect.getPrototypeOf(input);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new Error();
    }

    const allowed = new Set<string>(allowedKeys);
    const result: Partial<Record<TKey, unknown>> = Object.create(null);
    for (const key of Reflect.ownKeys(input)) {
      if (typeof key !== "string" || !allowed.has(key)) {
        throw new Error();
      }
      const descriptor = Reflect.getOwnPropertyDescriptor(input, key);
      if (
        descriptor === undefined ||
        !descriptor.enumerable ||
        !Object.hasOwn(descriptor, "value")
      ) {
        throw new Error();
      }
      result[key as TKey] = descriptor.value;
    }
    return result;
  } catch {
    throw wireError(
      timing,
      "INVALID_REQUEST",
      diagnostic,
      "not_sent",
    );
  }
}

function snapshotDenseTuple(
  input: unknown,
  expectedLength: number,
  timing: MutableTiming,
): readonly unknown[] {
  try {
    if (
      !Array.isArray(input) ||
      isProxy(input) ||
      Reflect.getPrototypeOf(input) !== Array.prototype
    ) {
      throw new Error();
    }
    const length = Reflect.getOwnPropertyDescriptor(input, "length");
    if (
      length === undefined ||
      !Object.hasOwn(length, "value") ||
      length.value !== expectedLength
    ) {
      throw new Error();
    }
    const result: unknown[] = [];
    for (const key of Reflect.ownKeys(input)) {
      if (key === "length") {
        continue;
      }
      if (
        typeof key !== "string" ||
        !/^(0|[1-9][0-9]*)$/.test(key) ||
        Number(key) >= expectedLength
      ) {
        throw new Error();
      }
      const descriptor = Reflect.getOwnPropertyDescriptor(input, key);
      if (
        descriptor === undefined ||
        !descriptor.enumerable ||
        !Object.hasOwn(descriptor, "value")
      ) {
        throw new Error();
      }
      result[Number(key)] = descriptor.value;
    }
    if (result.length !== expectedLength) {
      throw new Error();
    }
    for (let index = 0; index < expectedLength; index += 1) {
      if (!Object.hasOwn(result, index)) {
        throw new Error();
      }
    }
    return result;
  } catch {
    throw wireError(
      timing,
      "AUTHENTICATION_REJECTED",
      "Runtime authentication material was rejected.",
      "not_sent",
    );
  }
}

function snapshotSecretHeaderList(
  input: unknown,
  timing: MutableTiming,
): readonly unknown[] {
  try {
    if (!Array.isArray(input) || isProxy(input)) {
      throw new Error();
    }
    const descriptor = Reflect.getOwnPropertyDescriptor(input, "length");
    if (
      descriptor === undefined ||
      !Object.hasOwn(descriptor, "value") ||
      (descriptor.value !== 1 && descriptor.value !== 2)
    ) {
      throw new Error();
    }
    return snapshotDenseTuple(input, descriptor.value as number, timing);
  } catch (error) {
    if (isAuthenticRuntimeWireError(error, timing)) {
      throw error;
    }
    throw wireError(
      timing,
      "AUTHENTICATION_REJECTED",
      "Runtime authentication material was rejected.",
      "not_sent",
    );
  }
}

function elapsedMs(timing: MutableTiming): number {
  return Number(process.hrtime.bigint() - timing.startedNs) / 1_000_000;
}

function timingSnapshot(timing: MutableTiming): RuntimeWireTiming {
  return Object.freeze({
    startedAt: timing.startedAt,
    ...(timing.headersMs === undefined
      ? {}
      : { headersMs: timing.headersMs }),
    ...(timing.firstByteMs === undefined
      ? {}
      : { firstByteMs: timing.firstByteMs }),
    completedMs: elapsedMs(timing),
  });
}

function persistedCategory(
  code: RuntimeWireErrorCode,
  statusCode: number | undefined,
): PersistedErrorCategory {
  if (
    code === "AUTHENTICATION_UNAVAILABLE" ||
    code === "AUTHENTICATION_REJECTED" ||
    statusCode === 401
  ) {
    return "authentication";
  }
  if (code === "AUTHORIZATION_REJECTED" || statusCode === 403) {
    return "authorization";
  }
  if (
    code === "DEADLINE_EXCEEDED" ||
    code === "CONNECT_TIMEOUT" ||
    code === "HEADERS_TIMEOUT" ||
    code === "BODY_TIMEOUT"
  ) {
    return "timeout";
  }
  if (code === "CALLER_CANCELLED") {
    return "cancelled";
  }
  if (statusCode === 429) {
    return "rate-limit";
  }
  if (
    code === "CONNECT_FAILED" ||
    code === "RESPONSE_TRUNCATED"
  ) {
    return "transport";
  }
  if (code === "INVALID_REQUEST" || code === "RESPONSE_NOT_CONSUMED") {
    return "internal";
  }
  return "invalid-response";
}

function wireError(
  timing: MutableTiming,
  code: RuntimeWireErrorCode,
  diagnostic: string,
  dispatchState: RuntimeWireDispatchState,
  statusCode?: number,
): RuntimeWireError {
  const category = persistedCategory(code, statusCode);
  return new RuntimeWireError(
    {
      code,
      diagnostic,
      dispatchState,
      ...(statusCode === undefined ? {} : { statusCode }),
      timing: timingSnapshot(timing),
      ...(timing.target === undefined ? {} : { target: timing.target }),
      persistedError: sanitizeErrorForPersistence({
        category,
        status: statusCode,
        runtime: timing.target?.runtime.profileId,
      }),
    },
    RUNTIME_WIRE_ERROR_TOKEN,
    timing,
  );
}

function parseLimits(
  input: unknown,
  timing: MutableTiming,
): RuntimeHttpLimits {
  const result = { ...DEFAULT_RUNTIME_HTTP_LIMITS };
  if (input !== undefined) {
    const snapshot = snapshotDataRecord(
      input,
      LIMIT_KEYS,
      timing,
      "Runtime HTTP limits are invalid.",
    );

    for (const key of LIMIT_KEYS) {
      const value = snapshot[key];
      if (value === undefined) {
        continue;
      }
      if (
        typeof value !== "number" ||
        !Number.isSafeInteger(value) ||
        value <= 0 ||
        value > MAXIMUM_LIMITS[key]
      ) {
        throw wireError(
          timing,
          "INVALID_REQUEST",
          "Runtime HTTP limits are invalid.",
          "not_sent",
        );
      }
      result[key] = value;
    }
  }

  if (result.headersTimeoutMs > result.deadlineMs) {
    result.headersTimeoutMs = result.deadlineMs;
  }
  if (result.bodyTimeoutMs > result.deadlineMs) {
    result.bodyTimeoutMs = result.deadlineMs;
  }
  if (result.connectTimeoutMs > result.deadlineMs) {
    result.connectTimeoutMs = result.deadlineMs;
  }
  return Object.freeze(result);
}

function clampLimitsToPinnedDeadline(
  limits: RuntimeHttpLimits,
  remainingDeadlineMs: number,
): RuntimeHttpLimits {
  const deadlineMs = Math.max(
    1,
    Math.floor(Math.min(limits.deadlineMs, remainingDeadlineMs)),
  );
  return Object.freeze({
    ...limits,
    deadlineMs,
    connectTimeoutMs: Math.min(limits.connectTimeoutMs, deadlineMs),
    headersTimeoutMs: Math.min(limits.headersTimeoutMs, deadlineMs),
    bodyTimeoutMs: Math.min(limits.bodyTimeoutMs, deadlineMs),
  });
}

const REQUEST_KEYS = Object.freeze([
  "accept",
  "body",
  "limits",
  "signal",
  "secretHeaderFactory",
] as const);

interface RuntimeHttpRequestSnapshot {
  readonly accept?: RuntimeHttpAccept;
  readonly body?: Uint8Array;
  readonly limits?: unknown;
  readonly signal?: AbortSignal;
  readonly secretHeaderFactory?: RuntimeSecretHeaderFactory;
}

function snapshotRequest(
  input: unknown,
  timing: MutableTiming,
): RuntimeHttpRequestSnapshot {
  const snapshot = snapshotDataRecord(
    input,
    REQUEST_KEYS,
    timing,
    "Runtime HTTP request is invalid.",
  );
  const signal = snapshot.signal;
  const secretHeaderFactory = snapshot.secretHeaderFactory;
  if (
    (snapshot.accept !== undefined &&
      (
        typeof snapshot.accept !== "string" ||
        !RUNTIME_HTTP_ACCEPT_VALUES.includes(
          snapshot.accept as RuntimeHttpAccept,
        )
      )) ||
    (signal !== undefined &&
      (typeof signal !== "object" ||
        signal === null ||
        isProxy(signal) ||
        Reflect.getPrototypeOf(signal) !== AbortSignal.prototype ||
        !hasAbortSignalBrand(signal) ||
        Reflect.ownKeys(signal).some((key) => typeof key === "string"))) ||
    (secretHeaderFactory !== undefined &&
      (typeof secretHeaderFactory !== "function" ||
        isProxy(secretHeaderFactory)))
  ) {
    throw wireError(
      timing,
      "INVALID_REQUEST",
      "Runtime HTTP request is invalid.",
      "not_sent",
    );
  }
  return Object.freeze({
    ...(snapshot.accept === undefined
      ? {}
      : { accept: snapshot.accept as RuntimeHttpAccept }),
    ...(snapshot.body === undefined
      ? {}
      : { body: snapshot.body as Uint8Array }),
    ...(snapshot.limits === undefined ? {} : { limits: snapshot.limits }),
    ...(signal === undefined ? {} : { signal: signal as AbortSignal }),
    ...(secretHeaderFactory === undefined
      ? {}
      : {
        secretHeaderFactory:
          secretHeaderFactory as RuntimeSecretHeaderFactory,
      }),
  });
}

function validateTarget(
  target: PinnedHttpRequestTarget,
  timing: MutableTiming,
): URL {
  try {
    if (
      target.schemaVersion !== "tasc-pinned-http-request-v1" ||
      target.authority.kind !== "collector-trust-policy" ||
      !/^sha256:[a-f0-9]{64}$/.test(target.authority.policyDigest) ||
      !/^sha256:[a-f0-9]{64}$/.test(
        target.authority.authorizationDigest,
      ) ||
      (target.method !== "GET" && target.method !== "POST") ||
      !Number.isSafeInteger(target.port) ||
      target.port < 1 ||
      target.port > 65_535 ||
      (target.family !== 4 && target.family !== 6) ||
      isIP(target.address) !== target.family ||
      typeof target.endpointAlias !== "string" ||
      target.endpointAlias.length > 128 ||
      !/^[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?$/.test(
        target.endpointAlias,
      ) ||
      target.endpointAlias.includes("..") ||
      typeof target.runtime !== "object" ||
      target.runtime === null ||
      ![
        "llama.cpp",
        "lm-studio",
        "mlx-lm",
        "ollama",
        "sglang",
        "tensorrt-llm",
        "tgi",
        "vllm",
      ].includes(target.runtime.profileId) ||
      typeof target.runtime.build !== "string" ||
      !/^[A-Za-z0-9][A-Za-z0-9._+-]{0,255}$/.test(
        target.runtime.build,
      ) ||
      target.runtime.build.includes("..") ||
      typeof target.remainingDeadlineMs !== "number" ||
      !Number.isFinite(target.remainingDeadlineMs) ||
      target.remainingDeadlineMs <= 0 ||
      target.remainingDeadlineMs > MAXIMUM_LIMITS.deadlineMs
    ) {
      throw new Error();
    }

    const url = new URL(target.url);
    const expectedPort =
      url.port === "" ? (url.protocol === "https:" ? 443 : 80) : Number(url.port);
    const expectedPath = `${url.pathname}${url.search}`;
    const hostnameWithoutBrackets =
      url.hostname.startsWith("[") && url.hostname.endsWith("]")
        ? url.hostname.slice(1, -1)
        : url.hostname;
    const hostnameIsIp = isIP(hostnameWithoutBrackets) !== 0;

    if (
      (url.protocol !== "http:" && url.protocol !== "https:") ||
      url.username !== "" ||
      url.password !== "" ||
      url.hash !== "" ||
      target.url !== url.href ||
      target.origin !== url.origin ||
      target.hostname !== url.hostname ||
      target.path !== expectedPath ||
      target.port !== expectedPort ||
      (hostnameIsIp && target.servername !== undefined) ||
      (!hostnameIsIp &&
        target.servername !== undefined &&
        target.servername !== target.hostname)
    ) {
      throw new Error();
    }

    timing.target = Object.freeze({
      endpointAlias: target.endpointAlias,
      runtime: Object.freeze({ ...target.runtime }),
    });
    return url;
  } catch {
    throw wireError(
      timing,
      "INVALID_REQUEST",
      "Pinned runtime request is invalid.",
      "not_sent",
    );
  }
}

function parseRequestBody(
  method: "GET" | "POST",
  body: Uint8Array | undefined,
  limits: RuntimeHttpLimits,
  timing: MutableTiming,
): Buffer | undefined {
  if (body === undefined) {
    return undefined;
  }
  try {
    if (
      isProxy(body) ||
      !isUint8Array(body) ||
      TYPED_ARRAY_BUFFER_GETTER === undefined ||
      TYPED_ARRAY_BYTE_OFFSET_GETTER === undefined ||
      TYPED_ARRAY_BYTE_LENGTH_GETTER === undefined
    ) {
      throw new Error();
    }
    const buffer = Reflect.apply(
      TYPED_ARRAY_BUFFER_GETTER,
      body,
      [],
    ) as ArrayBufferLike;
    const byteOffset = Reflect.apply(
      TYPED_ARRAY_BYTE_OFFSET_GETTER,
      body,
      [],
    ) as number;
    const byteLength = Reflect.apply(
      TYPED_ARRAY_BYTE_LENGTH_GETTER,
      body,
      [],
    ) as number;
    if (isSharedArrayBuffer(buffer)) {
      throw new Error();
    }
    if (method === "GET" || byteLength > limits.maxRequestBytes) {
      throw new Error();
    }
    const source = new Uint8Array(buffer as ArrayBuffer, byteOffset, byteLength);
    const copy = new Uint8Array(byteLength);
    Reflect.apply(Uint8Array.prototype.set, copy, [source]);
    return Buffer.from(copy.buffer, copy.byteOffset, copy.byteLength);
  } catch {
    throw wireError(
      timing,
      "INVALID_REQUEST",
      "Runtime HTTP request body is invalid.",
      "not_sent",
    );
  }
}

function createPinnedLookup(
  address: string,
  family: 4 | 6,
): LookupFunction {
  return (_hostname, options, callback): void => {
    queueMicrotask(() => {
      if (options.all) {
        callback(null, [{ address, family }], family);
      } else {
        callback(null, address, family);
      }
    });
  };
}

function countResponseHeaders(
  headers: Readonly<Record<string, string | readonly string[] | undefined>>,
  limits: RuntimeHttpLimits,
  timing: MutableTiming,
): void {
  let count = 0;
  let bytes = 0;
  for (const [name, value] of Object.entries(headers)) {
    if (value === undefined) {
      continue;
    }
    const values = Array.isArray(value) ? value : [value];
    count += values.length;
    bytes += Buffer.byteLength(name, "utf8");
    for (const item of values) {
      bytes += Buffer.byteLength(item, "utf8") + 4;
    }
    if (
      count > limits.maxResponseHeaders ||
      bytes > limits.maxResponseHeaderBytes
    ) {
      throw wireError(
        timing,
        "INVALID_RESPONSE_HEADERS",
        "Runtime response headers exceeded a configured limit.",
        "sent_unknown",
      );
    }
  }
}

function oneHeader(
  headers: Readonly<Record<string, string | readonly string[] | undefined>>,
  name: string,
  timing: MutableTiming,
): string | undefined {
  const value = headers[name];
  if (value === undefined) {
    return undefined;
  }
  if (typeof value === "string") {
    return value;
  }
  if (value.length !== 1) {
    throw wireError(
      timing,
      "INVALID_RESPONSE_HEADERS",
      "Runtime response headers are invalid.",
      "sent_unknown",
    );
  }
  return value[0];
}

function parseContentType(
  headers: Readonly<Record<string, string | readonly string[] | undefined>>,
  timing: MutableTiming,
): {
  readonly mediaType: string;
  readonly parameters: readonly RuntimeContentTypeParameter[];
} | undefined {
  const raw = oneHeader(headers, "content-type", timing);
  if (raw === undefined) {
    return undefined;
  }
  if (raw.length > 512) {
    throw wireError(
      timing,
      "INVALID_RESPONSE_HEADERS",
      "Runtime response headers are invalid.",
      "sent_unknown",
    );
  }
  const parts = raw.split(";");
  const mediaType = parts.shift()?.trim().toLowerCase();
  if (
    mediaType === undefined ||
    mediaType.length === 0 ||
    mediaType.length > 127 ||
    !/^[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+$/.test(mediaType)
  ) {
    throw wireError(
      timing,
      "INVALID_RESPONSE_HEADERS",
      "Runtime response headers are invalid.",
      "sent_unknown",
    );
  }
  const parameters: RuntimeContentTypeParameter[] = [];
  const names = new Set<string>();
  const token = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;
  for (const part of parts) {
    const equals = part.indexOf("=");
    const name = part.slice(0, equals).trim().toLowerCase();
    const value = equals < 0 ? "" : part.slice(equals + 1).trim();
    if (
      equals < 1
      || name.length > 127
      || value.length < 1
      || value.length > 127
      || !token.test(name)
      || !token.test(value)
      || names.has(name)
    ) {
      throw wireError(
        timing,
        "INVALID_RESPONSE_HEADERS",
        "Runtime response headers are invalid.",
        "sent_unknown",
      );
    }
    names.add(name);
    parameters.push(Object.freeze({ name, value }));
  }
  return Object.freeze({
    mediaType,
    parameters: Object.freeze(parameters),
  });
}

function assertIdentityEncoding(
  headers: Readonly<Record<string, string | readonly string[] | undefined>>,
  timing: MutableTiming,
): void {
  const encoding = oneHeader(headers, "content-encoding", timing);
  if (encoding !== undefined && encoding.trim().toLowerCase() !== "identity") {
    throw wireError(
      timing,
      "COMPRESSED_RESPONSE",
      "Compressed runtime responses are not accepted.",
      "sent_unknown",
    );
  }
}

function assertContentLength(
  headers: Readonly<Record<string, string | readonly string[] | undefined>>,
  limits: RuntimeHttpLimits,
  timing: MutableTiming,
): void {
  const raw = oneHeader(headers, "content-length", timing);
  if (raw === undefined) {
    return;
  }
  if (!/^(0|[1-9][0-9]*)$/.test(raw)) {
    throw wireError(
      timing,
      "INVALID_RESPONSE_HEADERS",
      "Runtime response headers are invalid.",
      "sent_unknown",
    );
  }
  const value = Number(raw);
  if (!Number.isSafeInteger(value)) {
    throw wireError(
      timing,
      "INVALID_RESPONSE_HEADERS",
      "Runtime response headers are invalid.",
      "sent_unknown",
    );
  }
  if (value > limits.maxResponseBytes) {
    throw wireError(
      timing,
      "RESPONSE_TOO_LARGE",
      "Runtime response exceeded the configured byte limit.",
      "sent_unknown",
    );
  }
}

function parseSecretHeaders(
  input: unknown,
  limits: RuntimeHttpLimits,
  timing: MutableTiming,
): Record<string, string> {
  const entries = snapshotSecretHeaderList(input, timing);
  const result: Record<string, string> = {};
  let totalBytes = 0;
  for (const entry of entries) {
    const pair = snapshotDenseTuple(entry, 2, timing);
    const [rawName, value] = pair;
    if (typeof rawName !== "string" || typeof value !== "string") {
      throw wireError(
        timing,
        "AUTHENTICATION_REJECTED",
        "Runtime authentication material was rejected.",
        "not_sent",
      );
    }
    const name = rawName.toLowerCase();
    if (
      (name !== "authorization" && name !== "x-api-key") ||
      Object.hasOwn(result, name) ||
      value.length === 0 ||
      /[\u0000-\u001f\u007f]/.test(value)
    ) {
      throw wireError(
        timing,
        "AUTHENTICATION_REJECTED",
        "Runtime authentication material was rejected.",
        "not_sent",
      );
    }
    totalBytes += Buffer.byteLength(name, "utf8");
    totalBytes += Buffer.byteLength(value, "utf8");
    if (totalBytes > limits.maxSecretHeaderBytes) {
      throw wireError(
        timing,
        "AUTHENTICATION_REJECTED",
        "Runtime authentication material was rejected.",
        "not_sent",
      );
    }
    result[name] = value;
  }
  return result;
}

function classifyTransportError(
  error: unknown,
  timing: MutableTiming,
  state: LifecycleState,
  abortSource: OperationAbortSource | undefined,
): RuntimeWireError {
  if (isAuthenticRuntimeWireError(error, timing)) {
    if (
      error.statusCode === undefined
      && state.responseStatusCode !== undefined
    ) {
      return wireError(
        timing,
        error.code,
        error.message,
        error.dispatchState,
        state.responseStatusCode,
      );
    }
    return error;
  }
  if (abortSource === "caller") {
    return wireError(
      timing,
      "CALLER_CANCELLED",
      "Runtime request was cancelled by the caller.",
      state.dispatchState,
      state.responseStatusCode,
    );
  }
  if (abortSource === "deadline") {
    return wireError(
      timing,
      "DEADLINE_EXCEEDED",
      "Runtime request exceeded its total deadline.",
      state.dispatchState,
      state.responseStatusCode,
    );
  }
  if (abortSource === "connect") {
    return wireError(
      timing,
      "CONNECT_TIMEOUT",
      "Runtime connection timed out.",
      state.dispatchState,
      state.responseStatusCode,
    );
  }
  if (abortSource === "headers") {
    return wireError(
      timing,
      "HEADERS_TIMEOUT",
      "Runtime response headers timed out.",
      state.dispatchState,
      state.responseStatusCode,
    );
  }
  if (abortSource === "body") {
    return wireError(
      timing,
      "BODY_TIMEOUT",
      "Runtime response body timed out.",
      state.dispatchState,
      state.responseStatusCode,
    );
  }
  if (error instanceof errors.ConnectTimeoutError) {
    return wireError(
      timing,
      "CONNECT_TIMEOUT",
      "Runtime connection timed out.",
      state.dispatchState,
      state.responseStatusCode,
    );
  }
  if (error instanceof errors.HeadersTimeoutError) {
    return wireError(
      timing,
      "HEADERS_TIMEOUT",
      "Runtime response headers timed out.",
      state.dispatchState,
      state.responseStatusCode,
    );
  }
  if (error instanceof errors.HeadersOverflowError) {
    return wireError(
      timing,
      "INVALID_RESPONSE_HEADERS",
      "Runtime response headers exceeded a configured limit.",
      state.dispatchState,
      state.responseStatusCode,
    );
  }
  if (error instanceof errors.InvalidArgumentError) {
    return wireError(
      timing,
      "INVALID_REQUEST",
      "Runtime HTTP request is invalid.",
      "not_sent",
    );
  }
  if (error instanceof errors.BodyTimeoutError) {
    return wireError(
      timing,
      "BODY_TIMEOUT",
      "Runtime response body timed out.",
      state.dispatchState,
      state.responseStatusCode,
    );
  }
  if (error instanceof errors.ResponseExceededMaxSizeError) {
    return wireError(
      timing,
      "RESPONSE_TOO_LARGE",
      "Runtime response exceeded the configured byte limit.",
      state.dispatchState,
      state.responseStatusCode,
    );
  }
  if (error instanceof errors.ResponseContentLengthMismatchError) {
    return wireError(
      timing,
      "RESPONSE_TRUNCATED",
      "Runtime response ended before its declared length.",
      state.dispatchState,
      state.responseStatusCode,
    );
  }
  if (
    timing.headersMs !== undefined &&
    (error instanceof errors.SocketError ||
      error instanceof errors.HTTPParserError)
  ) {
    return wireError(
      timing,
      "RESPONSE_TRUNCATED",
      "Runtime response transport ended unexpectedly.",
      state.dispatchState,
      state.responseStatusCode,
    );
  }
  if (state.dispatchState === "not_sent") {
    return wireError(
      timing,
      "CONNECT_FAILED",
      "Runtime connection failed.",
      "not_sent",
    );
  }
  if (timing.headersMs === undefined) {
    return wireError(
      timing,
      "CONNECT_FAILED",
      "Runtime connection failed.",
      state.dispatchState,
    );
  }
  return wireError(
    timing,
    "RESPONSE_REJECTED",
    "Runtime response processing failed.",
    state.responseComplete ? "completed" : state.dispatchState,
    state.responseStatusCode,
  );
}

async function resolveSecretHeaders(
  target: PinnedHttpRequestTarget,
  request: RuntimeHttpRequestSnapshot,
  limits: RuntimeHttpLimits,
  timing: MutableTiming,
  signal: AbortSignal,
  abortPromise: Promise<never>,
): Promise<Record<string, string>> {
  if (target.authenticationReference === undefined) {
    if (request.secretHeaderFactory !== undefined) {
      throw wireError(
        timing,
        "INVALID_REQUEST",
        "A secret header factory requires an authorized reference.",
        "not_sent",
      );
    }
    return {};
  }
  if (request.secretHeaderFactory === undefined) {
    throw wireError(
      timing,
      "AUTHENTICATION_UNAVAILABLE",
      "Runtime authentication material is unavailable.",
      "not_sent",
    );
  }

  try {
    const headers = await Promise.race([
      Promise.resolve(
        request.secretHeaderFactory(
          target.authenticationReference,
          signal,
        ),
      ),
      abortPromise,
    ]);
    return parseSecretHeaders(headers, limits, timing);
  } catch (error) {
    if (error instanceof OperationAbort || abortSignalIsAborted(signal)) {
      throw error;
    }
    if (isAuthenticRuntimeWireError(error, timing)) {
      throw error;
    }
    throw wireError(
      timing,
      "AUTHENTICATION_UNAVAILABLE",
      "Runtime authentication material is unavailable.",
      "not_sent",
    );
  }
}

export async function withBoundedHttpResponse<T>(
  pin: PinnedCollectorRequest,
  request: RuntimeHttpRequest,
  consume: (
    response: BoundedRuntimeHttpResponse,
  ) => T | Promise<T>,
): Promise<BoundedRuntimeHttpResult<T>> {
  const timing: MutableTiming = {
    startedAt: new Date().toISOString(),
    startedNs: process.hrtime.bigint(),
  };
  const state: LifecycleState = {
    dispatchState: "not_sent",
    responseComplete: false,
    responseBytes: 0,
    responseChunks: 0,
  };

  let target: PinnedHttpRequestTarget;
  let url: URL;
  try {
    target = consumePinnedCollectorRequest(pin);
    url = validateTarget(target, timing);
  } catch (error) {
    if (isAuthenticRuntimeWireError(error, timing)) {
      throw error;
    }
    throw wireError(
      timing,
      "AUTHORIZATION_REJECTED",
      "Runtime request authorization was rejected.",
      "not_sent",
    );
  }

  const safeRequest = snapshotRequest(request, timing);
  if (typeof consume !== "function" || isProxy(consume)) {
    throw wireError(
      timing,
      "INVALID_REQUEST",
      "Runtime response consumer is invalid.",
      "not_sent",
    );
  }
  const parsedLimits = parseLimits(safeRequest.limits, timing);
  const remainingDeadlineMs =
    target.remainingDeadlineMs - elapsedMs(timing);
  if (remainingDeadlineMs < 1) {
    throw wireError(
      timing,
      "DEADLINE_EXCEEDED",
      "Runtime request exceeded its total deadline.",
      "not_sent",
    );
  }
  const limits = clampLimitsToPinnedDeadline(
    parsedLimits,
    remainingDeadlineMs,
  );

  const operationAbort = new AbortController();
  let abortSource: OperationAbortSource | undefined;
  const abortOperation = (source: OperationAbortSource): void => {
    if (abortSource === undefined) {
      abortSource = source;
      operationAbort.abort(new OperationAbort());
    }
  };
  const markCallerAbort = (): void => {
    abortOperation("caller");
  };
  if (
    safeRequest.signal !== undefined &&
    abortSignalIsAborted(safeRequest.signal)
  ) {
    markCallerAbort();
  } else if (safeRequest.signal !== undefined) {
    addAbortListener(safeRequest.signal, markCallerAbort);
  }

  const deadlineTimer = setTimeout(() => {
    abortOperation("deadline");
  }, limits.deadlineMs);
  deadlineTimer.unref();
  let connectTimer: NodeJS.Timeout | undefined;
  let headersTimer: NodeJS.Timeout | undefined;
  let bodyTimer: NodeJS.Timeout | undefined;
  const clearPhaseTimer = (
    timer: NodeJS.Timeout | undefined,
  ): undefined => {
    if (timer !== undefined) {
      clearTimeout(timer);
    }
    return undefined;
  };
  const resetBodyTimer = (): void => {
    bodyTimer = clearPhaseTimer(bodyTimer);
    bodyTimer = setTimeout(
      () => abortOperation("body"),
      limits.bodyTimeoutMs,
    );
    bodyTimer.unref();
  };

  const abortPromise = new Promise<never>((_resolve, reject) => {
    const rejectAbort = (): void => {
      reject(new OperationAbort());
    };
    if (abortSignalIsAborted(operationAbort.signal)) {
      rejectAbort();
    } else {
      addAbortListener(operationAbort.signal, rejectAbort);
    }
  });

  let client: Client | undefined;
  try {
    if (abortSignalIsAborted(operationAbort.signal)) {
      throw new OperationAbort();
    }
    const body = parseRequestBody(
      target.method,
      safeRequest.body,
      limits,
      timing,
    );
    const secretHeaders = await resolveSecretHeaders(
      target,
      safeRequest,
      limits,
      timing,
      operationAbort.signal,
      abortPromise,
    );

    const headers: Record<string, string> = {
      accept: safeRequest.accept
        ?? "application/json, text/event-stream, application/x-ndjson",
      "accept-encoding": "identity",
      ...secretHeaders,
    };
    if (body !== undefined) {
      headers["content-type"] = "application/json";
    }

    client = new Client(target.origin, {
      allowH2: false,
      pipelining: 0,
      maxRequestsPerClient: 1,
      strictContentLength: true,
      autoSelectFamily: false,
      maxHeaderSize: limits.maxResponseHeaderBytes,
      maxResponseSize: limits.maxResponseBytes,
      connectTimeout: limits.connectTimeoutMs,
      headersTimeout: limits.headersTimeoutMs,
      bodyTimeout: limits.bodyTimeoutMs,
      connect: {
        lookup: createPinnedLookup(target.address, target.family),
        ...(url.protocol === "https:" &&
        target.servername !== undefined
          ? { servername: target.servername }
          : {}),
      },
    });

    client.once("connect", () => {
      connectTimer = clearPhaseTimer(connectTimer);
      state.dispatchState = "sent_unknown";
      headersTimer = setTimeout(
        () => abortOperation("headers"),
        limits.headersTimeoutMs,
      );
      headersTimer.unref();
    });
    connectTimer = setTimeout(
      () => abortOperation("connect"),
      limits.connectTimeoutMs,
    );
    connectTimer.unref();
    const response = await Promise.race([
      client.request({
        path: target.path,
        method: target.method,
        ...(body === undefined ? {} : { body }),
        headers,
        idempotent: false,
        blocking: true,
        headersTimeout: limits.headersTimeoutMs,
        bodyTimeout: limits.bodyTimeoutMs,
        signal: operationAbort.signal,
      }),
      abortPromise,
    ]);
    state.responseStatusCode = response.statusCode;
    connectTimer = clearPhaseTimer(connectTimer);
    headersTimer = clearPhaseTimer(headersTimer);
    state.dispatchState = "sent_unknown";
    timing.headersMs = elapsedMs(timing);

    if (response.statusCode >= 300 && response.statusCode <= 399) {
      state.dispatchState = "completed";
      throw wireError(
        timing,
        "REDIRECT_DENIED",
        "Runtime provider redirects are not accepted.",
        "completed",
        response.statusCode,
      );
    }
    if (response.statusCode < 200 || response.statusCode > 299) {
      state.dispatchState = "completed";
      throw wireError(
        timing,
        "PROVIDER_ERROR",
        "Runtime provider returned a non-success status.",
        "completed",
        response.statusCode,
      );
    }

    countResponseHeaders(response.headers, limits, timing);
    assertIdentityEncoding(response.headers, timing);
    assertContentLength(response.headers, limits, timing);
    const parsedContentType = parseContentType(response.headers, timing);
    resetBodyTimer();

    let bodyTaken = false;
    const boundedBody: AsyncIterable<Uint8Array> = Object.freeze({
      [Symbol.asyncIterator]: async function* (): AsyncGenerator<
        Uint8Array,
        void,
        undefined
      > {
        if (bodyTaken) {
          throw wireError(
            timing,
            "RESPONSE_REJECTED",
            "Runtime response body may only be consumed once.",
            state.dispatchState,
          );
        }
        bodyTaken = true;
        try {
          for await (const chunk of response.body) {
            resetBodyTimer();
            if (chunk.byteLength === 0) {
              continue;
            }
            if (timing.firstByteMs === undefined) {
              timing.firstByteMs = elapsedMs(timing);
            }
            state.responseChunks += 1;
            state.responseBytes += chunk.byteLength;
            if (state.responseChunks > limits.maxResponseChunks) {
              throw wireError(
                timing,
                "RESPONSE_CHUNK_LIMIT",
                "Runtime response exceeded the configured chunk limit.",
                "sent_unknown",
              );
            }
            if (state.responseBytes > limits.maxResponseBytes) {
              throw wireError(
                timing,
                "RESPONSE_TOO_LARGE",
                "Runtime response exceeded the configured byte limit.",
                "sent_unknown",
              );
            }
            yield chunk;
          }
          bodyTimer = clearPhaseTimer(bodyTimer);
          state.responseComplete = true;
          state.dispatchState = "completed";
        } catch (error) {
          throw classifyTransportError(
            error,
            timing,
            state,
            abortSource,
          );
        }
      },
    });

    const value = await Promise.race([
      Promise.resolve(
        consume(
          Object.freeze({
            statusCode: response.statusCode,
            ...(parsedContentType === undefined
              ? {}
              : {
                contentType: parsedContentType.mediaType,
                contentTypeParameters: parsedContentType.parameters,
              }),
            body: boundedBody,
            signal: operationAbort.signal,
          }),
        ),
      ),
      abortPromise,
    ]);

    if (!bodyTaken || !state.responseComplete) {
      throw wireError(
        timing,
        "RESPONSE_NOT_CONSUMED",
        "Runtime response body was not consumed completely.",
        "sent_unknown",
      );
    }

    return Object.freeze({
      value,
      statusCode: response.statusCode,
      responseBytes: state.responseBytes,
      responseChunks: state.responseChunks,
      timing: timingSnapshot(timing),
      target: timing.target as RuntimeWireTargetMetadata,
    });
  } catch (error) {
    throw classifyTransportError(
      error,
      timing,
      state,
      abortSource,
    );
  } finally {
    clearTimeout(deadlineTimer);
    connectTimer = clearPhaseTimer(connectTimer);
    headersTimer = clearPhaseTimer(headersTimer);
    bodyTimer = clearPhaseTimer(bodyTimer);
    if (safeRequest.signal !== undefined) {
      removeAbortListener(safeRequest.signal, markCallerAbort);
    }
    if (client !== undefined) {
      await client.destroy().catch(() => undefined);
    }
  }
}
