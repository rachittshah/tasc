import type { KeyObject } from "node:crypto";
import {
  isProxy,
  isSharedArrayBuffer,
  isUint8Array,
} from "node:util/types";
import {
  parseBoundedJson,
  type BoundedJsonLimits,
  type ByteChunkSource,
} from "../bounded-input.js";
import {
  createStudyPayloadIdentity,
  MAX_PAYLOAD_IDENTITY_BYTES,
  type KeyedPayloadIdentity,
} from "../references.js";

export type RuntimeCodecErrorCode =
  | "invalid-options"
  | "invalid-source"
  | "input-stream"
  | "invalid-chunk"
  | "chunk-limit"
  | "byte-limit"
  | "invalid-utf8"
  | "utf8-bom"
  | "line-limit"
  | "line-byte-limit"
  | "event-limit"
  | "event-byte-limit"
  | "field-byte-limit"
  | "item-limit"
  | "blank-line"
  | "invalid-json"
  | "terminal-order"
  | "sample-limit"
  | "label-limit"
  | "duplicate-sample"
  | "unsupported-syntax"
  | "nonfinite-value"
  | "clock";

const CODEC_ERROR_MESSAGES: Readonly<Record<RuntimeCodecErrorCode, string>> =
  Object.freeze({
    "invalid-options": "runtime codec options are invalid",
    "invalid-source": "runtime codec source must be a bounded byte iterable",
    "input-stream": "runtime codec input stream failed",
    "invalid-chunk": "runtime codec received an invalid or empty byte chunk",
    "chunk-limit": "runtime codec exceeded its configured chunk limit",
    "byte-limit": "runtime codec exceeded its configured total byte limit",
    "invalid-utf8": "runtime codec input is not valid UTF-8",
    "utf8-bom": "runtime codec input must not begin with a UTF-8 byte-order mark",
    "line-limit": "runtime codec exceeded its configured line limit",
    "line-byte-limit": "runtime codec exceeded its configured line byte limit",
    "event-limit": "runtime codec exceeded its configured event limit",
    "event-byte-limit": "runtime codec exceeded its configured event byte limit",
    "field-byte-limit": "runtime codec exceeded its configured field byte limit",
    "item-limit": "runtime codec exceeded its configured item limit",
    "blank-line": "runtime codec input contains a blank record",
    "invalid-json": "runtime codec event does not contain one valid JSON value",
    "terminal-order": "runtime codec received data after a terminal event",
    "sample-limit": "runtime codec exceeded its configured metric sample limit",
    "label-limit": "runtime codec exceeded its configured metric label limit",
    "duplicate-sample": "runtime codec contains a duplicate metric sample",
    "unsupported-syntax": "runtime codec input uses unsupported syntax",
    "nonfinite-value": "runtime codec metric value must be finite",
    "clock": "runtime codec clock must return finite monotonic milliseconds",
  });

/** A bounded, payload-redacted codec failure. */
export class RuntimeCodecError extends Error {
  readonly code: RuntimeCodecErrorCode;

  constructor(code: RuntimeCodecErrorCode) {
    super(CODEC_ERROR_MESSAGES[code]);
    this.name = "RuntimeCodecError";
    this.code = code;
  }
}

export interface RuntimeStreamIdentity {
  readonly studyId: string;
  readonly keyId: string;
  readonly key: KeyObject;
}

export interface RuntimeStreamTiming {
  readonly startedAtMs: number;
  readonly firstByteAtMs: number | null;
  readonly firstMeaningfulAtMs: number | null;
  readonly completedAtMs: number;
  readonly timeToFirstByteMs: number | null;
  readonly timeToFirstMeaningfulMs: number | null;
  readonly durationMs: number;
}

export interface BoundedSseLimits {
  readonly maxTotalBytes: number;
  readonly maxChunks: number;
  readonly maxLines: number;
  readonly maxLineBytes: number;
  readonly maxEvents: number;
  readonly maxEventBytes: number;
  readonly maxFieldBytes: number;
  readonly maxRetryMs: number;
}

export const MAX_SSE_TOTAL_BYTES = MAX_PAYLOAD_IDENTITY_BYTES;
export const MAX_SSE_CHUNKS = 16_384;
export const MAX_SSE_LINES = 262_144;
export const MAX_SSE_LINE_BYTES = 1024 * 1024;
export const MAX_SSE_EVENTS = 65_536;
export const MAX_SSE_EVENT_BYTES = MAX_PAYLOAD_IDENTITY_BYTES;
export const MAX_SSE_FIELD_BYTES = 1024 * 1024;
export const MAX_SSE_RETRY_MS = 7 * 24 * 60 * 60 * 1_000;

export const DEFAULT_SSE_LIMITS: Readonly<BoundedSseLimits> = Object.freeze({
  maxTotalBytes: 8 * 1024 * 1024,
  maxChunks: 16_384,
  maxLines: 65_536,
  maxLineBytes: 256 * 1024,
  maxEvents: 32_768,
  maxEventBytes: 1024 * 1024,
  maxFieldBytes: 256 * 1024,
  maxRetryMs: 24 * 60 * 60 * 1_000,
});

export interface BoundedSseOptions {
  readonly limits: BoundedSseLimits;
  readonly identity: RuntimeStreamIdentity;
  readonly clock?: () => number;
  readonly startedAtMs?: number;
}

export interface SseEvent {
  readonly index: number;
  readonly kind: "event" | "done";
  readonly event: string | null;
  readonly data: string;
  readonly id: string;
  readonly retryMs: number | null;
  readonly comments: readonly string[];
  readonly rawFrameIdentity: KeyedPayloadIdentity;
  readonly observedAtMs: number;
}

export interface SseParseSummary {
  readonly terminal: "eof" | "done-sentinel";
  readonly trailingIncompleteEvent: boolean;
  readonly totalBytes: number;
  readonly totalChunks: number;
  readonly totalLines: number;
  readonly timing: RuntimeStreamTiming;
}

export interface SseParseResult {
  readonly events: readonly SseEvent[];
  readonly summary: SseParseSummary;
}

export type JsonSseProtocol =
  | "generic-json-sse"
  | "openai-chat-completions"
  | "openai-responses";

export interface BoundedJsonSseOptions extends BoundedSseOptions {
  readonly jsonLimits: BoundedJsonLimits;
  readonly protocol: JsonSseProtocol;
}

export interface JsonSseEvent extends SseEvent {
  readonly json: unknown | null;
  readonly type: string | null;
  readonly providerError: boolean;
  readonly usagePresent: boolean;
  readonly meaningfulOutput: boolean;
}

export interface JsonSseSummary
  extends Omit<SseParseSummary, "terminal" | "timing"> {
  readonly protocol: JsonSseProtocol;
  readonly terminal:
    | "eof"
    | "done-sentinel"
    | "response.completed"
    | "provider-error"
    | "truncated";
  readonly finalUsage: "present" | "missing" | "not-required";
  readonly timing: RuntimeStreamTiming;
}

export interface JsonSseParseResult {
  readonly events: readonly JsonSseEvent[];
  readonly summary: JsonSseSummary;
}

interface NormalizedSseOptions {
  readonly limits: Readonly<BoundedSseLimits>;
  readonly identity: Readonly<RuntimeStreamIdentity>;
  readonly clock: () => number;
  readonly startedAtMs: number;
}

interface ChunkMark {
  readonly endOffset: number;
  readonly atMs: number;
}

interface CollectedStream {
  readonly bytes: Uint8Array;
  readonly marks: readonly ChunkMark[];
  readonly totalChunks: number;
  readonly startedAtMs: number;
  readonly firstByteAtMs: number | null;
  readonly completedAtMs: number;
}

const TYPED_ARRAY_PROTOTYPE =
  Reflect.getPrototypeOf(Uint8Array.prototype) as object;
const BUFFER_GETTER =
  Reflect.getOwnPropertyDescriptor(TYPED_ARRAY_PROTOTYPE, "buffer")?.get;
const BYTE_OFFSET_GETTER =
  Reflect.getOwnPropertyDescriptor(TYPED_ARRAY_PROTOTYPE, "byteOffset")?.get;
const BYTE_LENGTH_GETTER =
  Reflect.getOwnPropertyDescriptor(TYPED_ARRAY_PROTOTYPE, "byteLength")?.get;

function fail(code: RuntimeCodecErrorCode): never {
  throw new RuntimeCodecError(code);
}

function inspectBytes(input: unknown): Uint8Array | undefined {
  if (
    input === null
    || typeof input !== "object"
    || isProxy(input)
    || !isUint8Array(input)
    || BUFFER_GETTER === undefined
    || BYTE_OFFSET_GETTER === undefined
    || BYTE_LENGTH_GETTER === undefined
  ) {
    return undefined;
  }
  try {
    const buffer = Reflect.apply(BUFFER_GETTER, input, []) as ArrayBufferLike;
    if (isSharedArrayBuffer(buffer)) return undefined;
    const byteOffset = Reflect.apply(BYTE_OFFSET_GETTER, input, []) as number;
    const byteLength = Reflect.apply(BYTE_LENGTH_GETTER, input, []) as number;
    return new Uint8Array(buffer, byteOffset, byteLength);
  } catch {
    return undefined;
  }
}

function snapshotRecord(
  input: unknown,
  allowed: ReadonlySet<string>,
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
    fail("invalid-options");
  }
  const keys = Reflect.ownKeys(input);
  if (
    keys.some((key) => typeof key !== "string" || !allowed.has(key))
  ) {
    fail("invalid-options");
  }
  const snapshot: Record<string, unknown> = Object.create(null);
  for (const key of keys) {
    const descriptor = Reflect.getOwnPropertyDescriptor(input, key);
    if (
      descriptor === undefined
      || !descriptor.enumerable
      || !Object.hasOwn(descriptor, "value")
    ) {
      fail("invalid-options");
    }
    snapshot[key as string] = descriptor.value;
  }
  return Object.freeze(snapshot);
}

function requireSafeLimit(value: unknown, allowZero = false): number {
  if (
    typeof value !== "number"
    || !Number.isSafeInteger(value)
    || value < (allowZero ? 0 : 1)
  ) {
    fail("invalid-options");
  }
  return value;
}

function requireFiniteTime(value: unknown): number {
  if (typeof value !== "number" || !Number.isFinite(value)) fail("clock");
  return value;
}

const SSE_LIMIT_KEYS = new Set([
  "maxTotalBytes",
  "maxChunks",
  "maxLines",
  "maxLineBytes",
  "maxEvents",
  "maxEventBytes",
  "maxFieldBytes",
  "maxRetryMs",
]);
const IDENTITY_KEYS = new Set(["studyId", "keyId", "key"]);
const SSE_OPTION_KEYS = new Set(["limits", "identity", "clock", "startedAtMs"]);
const JSON_SSE_OPTION_KEYS = new Set([
  ...SSE_OPTION_KEYS,
  "jsonLimits",
  "protocol",
]);
const JSON_LIMIT_KEYS = new Set([
  "maxBytes",
  "maxDepth",
  "maxObjectKeys",
  "maxArrayItems",
  "maxTokens",
  "maxDecodedStringLength",
  "maxNumericTokenLength",
  "maxDiagnosticSnippetLength",
]);

function normalizeSseOptions(
  input: BoundedSseOptions,
  allowedKeys: ReadonlySet<string> = SSE_OPTION_KEYS,
): NormalizedSseOptions {
  const options = snapshotRecord(input, allowedKeys);
  if (!Object.hasOwn(options, "limits") || !Object.hasOwn(options, "identity")) {
    fail("invalid-options");
  }
  const rawLimits = snapshotRecord(options.limits, SSE_LIMIT_KEYS);
  if (Reflect.ownKeys(rawLimits).length !== SSE_LIMIT_KEYS.size) {
    fail("invalid-options");
  }
  const limits = Object.freeze({
    maxTotalBytes: requireSafeLimit(rawLimits.maxTotalBytes),
    maxChunks: requireSafeLimit(rawLimits.maxChunks),
    maxLines: requireSafeLimit(rawLimits.maxLines),
    maxLineBytes: requireSafeLimit(rawLimits.maxLineBytes),
    maxEvents: requireSafeLimit(rawLimits.maxEvents),
    maxEventBytes: requireSafeLimit(rawLimits.maxEventBytes),
    maxFieldBytes: requireSafeLimit(rawLimits.maxFieldBytes),
    maxRetryMs: requireSafeLimit(rawLimits.maxRetryMs, true),
  });
  if (
    limits.maxEventBytes > limits.maxTotalBytes
    || limits.maxTotalBytes > MAX_SSE_TOTAL_BYTES
    || limits.maxChunks > MAX_SSE_CHUNKS
    || limits.maxLines > MAX_SSE_LINES
    || limits.maxLineBytes > MAX_SSE_LINE_BYTES
    || limits.maxEvents > MAX_SSE_EVENTS
    || limits.maxEventBytes > MAX_SSE_EVENT_BYTES
    || limits.maxFieldBytes > MAX_SSE_FIELD_BYTES
    || limits.maxRetryMs > MAX_SSE_RETRY_MS
    || limits.maxLineBytes > limits.maxEventBytes
    || limits.maxFieldBytes > limits.maxLineBytes
  ) {
    fail("invalid-options");
  }

  const rawIdentity = snapshotRecord(options.identity, IDENTITY_KEYS);
  if (Reflect.ownKeys(rawIdentity).length !== IDENTITY_KEYS.size) {
    fail("invalid-options");
  }
  const identity = Object.freeze({
    studyId: rawIdentity.studyId as string,
    keyId: rawIdentity.keyId as string,
    key: rawIdentity.key as KeyObject,
  });
  // Validate the opaque identifiers and secret KeyObject before awaiting input.
  createStudyPayloadIdentity(
    identity.studyId,
    identity.keyId,
    identity.key,
    new Uint8Array(0),
  );

  const clock = Object.hasOwn(options, "clock")
    ? options.clock
    : Date.now;
  if (typeof clock !== "function" || isProxy(clock)) fail("invalid-options");
  const startedAtMs = Object.hasOwn(options, "startedAtMs")
    ? requireFiniteTime(options.startedAtMs)
    : requireFiniteTime(Reflect.apply(clock, undefined, []));
  return Object.freeze({
    limits,
    identity,
    clock: clock as () => number,
    startedAtMs,
  });
}

function snapshotJsonLimits(
  input: unknown,
  maximumEventBytes: number,
): Readonly<BoundedJsonLimits> {
  const raw = snapshotRecord(input, JSON_LIMIT_KEYS);
  if (Reflect.ownKeys(raw).length !== JSON_LIMIT_KEYS.size) {
    fail("invalid-options");
  }
  const limits = Object.freeze({
    maxBytes: requireSafeLimit(raw.maxBytes),
    maxDepth: requireSafeLimit(raw.maxDepth, true),
    maxObjectKeys: requireSafeLimit(raw.maxObjectKeys, true),
    maxArrayItems: requireSafeLimit(raw.maxArrayItems, true),
    maxTokens: requireSafeLimit(raw.maxTokens),
    maxDecodedStringLength: requireSafeLimit(
      raw.maxDecodedStringLength,
      true,
    ),
    maxNumericTokenLength: requireSafeLimit(raw.maxNumericTokenLength),
    maxDiagnosticSnippetLength: requireSafeLimit(
      raw.maxDiagnosticSnippetLength,
      true,
    ),
  });
  if (
    limits.maxBytes > maximumEventBytes
    || limits.maxDepth > 64
    || limits.maxObjectKeys > 131_072
    || limits.maxArrayItems > 131_072
    || limits.maxTokens > 1_048_576
    || limits.maxDecodedStringLength > MAX_SSE_EVENT_BYTES
    || limits.maxNumericTokenLength > 1_024
    || limits.maxDiagnosticSnippetLength > 1_024
  ) {
    fail("invalid-options");
  }
  return limits;
}

function readClock(
  clock: () => number,
  previous: number,
): number {
  let current: unknown;
  try {
    current = Reflect.apply(clock, undefined, []);
  } catch {
    fail("clock");
  }
  const time = requireFiniteTime(current);
  if (time < previous) fail("clock");
  return time;
}

async function collectStream(
  source: ByteChunkSource,
  options: NormalizedSseOptions,
): Promise<CollectedStream> {
  if (source === null || typeof source !== "object" || isProxy(source)) {
    fail("invalid-source");
  }

  const { maxChunks, maxTotalBytes } = options.limits;
  let storage = new Uint8Array(Math.min(maxTotalBytes, 1_024));
  let totalBytes = 0;
  let totalChunks = 0;
  let firstByteAtMs: number | null = null;
  let previousTime = options.startedAtMs;
  const marks: ChunkMark[] = [];
  let ownFailure: RuntimeCodecError | undefined;

  const accept = (candidate: unknown): void => {
    if (totalChunks >= maxChunks) fail("chunk-limit");
    const view = inspectBytes(candidate);
    if (view === undefined || view.byteLength === 0) fail("invalid-chunk");
    if (view.byteLength > maxTotalBytes - totalBytes) fail("byte-limit");
    const snapshot = view.slice();

    const observedAt = readClock(options.clock, previousTime);
    previousTime = observedAt;
    if (firstByteAtMs === null) firstByteAtMs = observedAt;
    const required = totalBytes + view.byteLength;
    if (required > storage.byteLength) {
      let capacity = Math.max(1, storage.byteLength);
      while (capacity < required) {
        capacity = Math.min(
          maxTotalBytes,
          Math.max(required, capacity * 2),
        );
      }
      const expanded = new Uint8Array(capacity);
      expanded.set(storage.subarray(0, totalBytes));
      storage = expanded;
    }
    storage.set(snapshot, totalBytes);
    totalBytes = required;
    totalChunks += 1;
    marks.push(Object.freeze({ endOffset: totalBytes, atMs: observedAt }));
  };

  try {
    const ownAsyncDescriptor = Reflect.getOwnPropertyDescriptor(
      source,
      Symbol.asyncIterator,
    );
    const ownSyncDescriptor = Reflect.getOwnPropertyDescriptor(
      source,
      Symbol.iterator,
    );
    if (
      (
        ownAsyncDescriptor !== undefined
        && !Object.hasOwn(ownAsyncDescriptor, "value")
      )
      || (
        ownSyncDescriptor !== undefined
        && !Object.hasOwn(ownSyncDescriptor, "value")
      )
    ) {
      fail("invalid-source");
    }
    const asyncFactory = (source as AsyncIterable<Uint8Array>)[Symbol.asyncIterator];
    if (typeof asyncFactory === "function") {
      for await (const chunk of source as AsyncIterable<Uint8Array>) {
        try {
          accept(chunk);
        } catch (error) {
          if (error instanceof RuntimeCodecError) ownFailure = error;
          throw error;
        }
      }
    } else {
      const syncFactory = (source as Iterable<Uint8Array>)[Symbol.iterator];
      if (typeof syncFactory !== "function") fail("invalid-source");
      for (const chunk of source as Iterable<Uint8Array>) {
        try {
          accept(chunk);
        } catch (error) {
          if (error instanceof RuntimeCodecError) ownFailure = error;
          throw error;
        }
      }
    }
  } catch (error) {
    if (ownFailure !== undefined && error === ownFailure) throw ownFailure;
    if (error instanceof RuntimeCodecError) throw error;
    fail("input-stream");
  }

  const completedAtMs = readClock(options.clock, previousTime);
  const bytes = storage.slice(0, totalBytes);
  try {
    const decoder = new TextDecoder("utf-8", {
      fatal: true,
      ignoreBOM: true,
    });
    // Streaming validation covers code points split at arbitrary source chunks.
    let start = 0;
    for (const mark of marks) {
      decoder.decode(bytes.subarray(start, mark.endOffset), { stream: true });
      start = mark.endOffset;
    }
    decoder.decode();
  } catch {
    fail("invalid-utf8");
  }

  return Object.freeze({
    bytes,
    marks: Object.freeze(marks),
    totalChunks,
    startedAtMs: options.startedAtMs,
    firstByteAtMs,
    completedAtMs,
  });
}

function observedAtOffset(
  marks: readonly ChunkMark[],
  offset: number,
  fallback: number,
): number {
  let low = 0;
  let high = marks.length - 1;
  while (low <= high) {
    const middle = low + Math.floor((high - low) / 2);
    const mark = marks[middle];
    if (mark === undefined) break;
    if (mark.endOffset >= offset) {
      high = middle - 1;
    } else {
      low = middle + 1;
    }
  }
  return marks[low]?.atMs ?? fallback;
}

function decodeUtf8(bytes: Uint8Array): string {
  try {
    return new TextDecoder("utf-8", {
      fatal: true,
      ignoreBOM: true,
    }).decode(bytes);
  } catch {
    fail("invalid-utf8");
  }
}

function timing(
  stream: CollectedStream,
  firstMeaningfulAtMs: number | null,
): RuntimeStreamTiming {
  return Object.freeze({
    startedAtMs: stream.startedAtMs,
    firstByteAtMs: stream.firstByteAtMs,
    firstMeaningfulAtMs,
    completedAtMs: stream.completedAtMs,
    timeToFirstByteMs: stream.firstByteAtMs === null
      ? null
      : stream.firstByteAtMs - stream.startedAtMs,
    timeToFirstMeaningfulMs: firstMeaningfulAtMs === null
      ? null
      : firstMeaningfulAtMs - stream.startedAtMs,
    durationMs: stream.completedAtMs - stream.startedAtMs,
  });
}

interface ParsedSse {
  readonly events: readonly SseEvent[];
  readonly totalLines: number;
  readonly trailingIncompleteEvent: boolean;
}

function parseSseBytes(
  stream: CollectedStream,
  options: NormalizedSseOptions,
): ParsedSse {
  const { bytes } = stream;
  const events: SseEvent[] = [];
  let totalLines = 0;
  let frameStart = 0;
  let frameHasFields = false;
  let eventName = "";
  let dataParts: string[] = [];
  let lastEventId = "";
  let retryMs: number | null = null;
  let comments: string[] = [];
  const hasLeadingBom = bytes.byteLength >= 3
    && bytes[0] === 0xef
    && bytes[1] === 0xbb
    && bytes[2] === 0xbf;
  let lineStart = hasLeadingBom ? 3 : 0;
  frameStart = lineStart;
  let terminalSeen = false;

  const resetFrame = (nextFrameStart: number): void => {
    frameStart = nextFrameStart;
    frameHasFields = false;
    eventName = "";
    dataParts = [];
    retryMs = null;
    comments = [];
  };

  const dispatch = (observedOffset: number): void => {
    if (dataParts.length === 0) {
      resetFrame(observedOffset);
      return;
    }
    if (events.length >= options.limits.maxEvents) fail("event-limit");
    // Include the exact terminating blank-line delimiter. LF and CRLF frames
    // with otherwise identical semantics intentionally have distinct IDs.
    const frameBytes = bytes.subarray(frameStart, observedOffset);
    if (frameBytes.byteLength > options.limits.maxEventBytes) {
      fail("event-byte-limit");
    }
    const data = dataParts.join("\n");
    const isDone = data === "[DONE]";
    if (terminalSeen) fail("terminal-order");
    const event = Object.freeze({
      index: events.length,
      kind: isDone ? "done" : "event",
      event: eventName === "" ? null : eventName,
      data,
      id: lastEventId,
      retryMs,
      comments: Object.freeze([...comments]),
      rawFrameIdentity: createStudyPayloadIdentity(
        options.identity.studyId,
        options.identity.keyId,
        options.identity.key,
        frameBytes,
      ),
      observedAtMs: observedAtOffset(
        stream.marks,
        observedOffset,
        stream.completedAtMs,
      ),
    } satisfies SseEvent);
    events.push(event);
    terminalSeen = isDone;
    resetFrame(observedOffset);
  };

  const processLine = (
    contentStart: number,
    contentEnd: number,
    delimiterEnd: number,
  ): void => {
    totalLines += 1;
    if (totalLines > options.limits.maxLines) fail("line-limit");
    const lineLength = contentEnd - contentStart;
    if (lineLength > options.limits.maxLineBytes) fail("line-byte-limit");
    if (delimiterEnd - frameStart > options.limits.maxEventBytes) {
      fail("event-byte-limit");
    }
    if (lineLength === 0) {
      dispatch(delimiterEnd);
      return;
    }

    frameHasFields = true;
    const line = bytes.subarray(contentStart, contentEnd);
    if (line[0] === 0x3a) {
      const commentBytes = line.subarray(1);
      if (commentBytes.byteLength > options.limits.maxFieldBytes) {
        fail("field-byte-limit");
      }
      comments.push(decodeUtf8(commentBytes));
      return;
    }

    let colon = -1;
    for (let index = 0; index < line.byteLength; index += 1) {
      if (line[index] === 0x3a) {
        colon = index;
        break;
      }
    }
    const nameBytes = colon === -1 ? line : line.subarray(0, colon);
    let valueBytes = colon === -1
      ? line.subarray(line.byteLength)
      : line.subarray(colon + 1);
    if (valueBytes[0] === 0x20) valueBytes = valueBytes.subarray(1);
    if (
      nameBytes.byteLength > options.limits.maxFieldBytes
      || valueBytes.byteLength > options.limits.maxFieldBytes
    ) {
      fail("field-byte-limit");
    }
    const name = decodeUtf8(nameBytes);
    const value = decodeUtf8(valueBytes);

    switch (name) {
      case "event":
        eventName = value;
        break;
      case "data":
        dataParts.push(value);
        break;
      case "id":
        if (!value.includes("\u0000")) lastEventId = value;
        break;
      case "retry":
        if (/^[0-9]+$/.test(value)) {
          const parsed = Number(value);
          if (
            Number.isSafeInteger(parsed)
            && parsed <= options.limits.maxRetryMs
          ) {
            retryMs = parsed;
          }
        }
        break;
      default:
        // WHATWG event streams explicitly ignore unknown fields.
        break;
    }
  };

  for (let cursor = 0; cursor < bytes.byteLength;) {
    const byte = bytes[cursor];
    if (byte !== 0x0a && byte !== 0x0d) {
      cursor += 1;
      continue;
    }
    const delimiterEnd = byte === 0x0d && bytes[cursor + 1] === 0x0a
      ? cursor + 2
      : cursor + 1;
    processLine(lineStart, cursor, delimiterEnd);
    lineStart = delimiterEnd;
    cursor = delimiterEnd;
  }
  if (lineStart < bytes.byteLength) {
    processLine(lineStart, bytes.byteLength, bytes.byteLength);
  }

  const trailingIncompleteEvent = frameHasFields || dataParts.length > 0;
  if (terminalSeen && trailingIncompleteEvent) fail("terminal-order");
  return Object.freeze({
    events: Object.freeze(events),
    totalLines,
    trailingIncompleteEvent,
  });
}

/** Parse a byte/chunk/event-bounded WHATWG event stream. */
export async function parseBoundedSse(
  source: ByteChunkSource,
  inputOptions: BoundedSseOptions,
): Promise<SseParseResult> {
  const options = normalizeSseOptions(inputOptions);
  const stream = await collectStream(source, options);
  const parsed = parseSseBytes(stream, options);
  const firstMeaningful = parsed.events.find(({ kind }) => kind === "event")
    ?.observedAtMs ?? null;
  const terminal = parsed.events.at(-1)?.kind === "done"
    ? "done-sentinel"
    : "eof";
  return Object.freeze({
    events: parsed.events,
    summary: Object.freeze({
      terminal,
      trailingIncompleteEvent: parsed.trailingIncompleteEvent,
      totalBytes: stream.bytes.byteLength,
      totalChunks: stream.totalChunks,
      totalLines: parsed.totalLines,
      timing: timing(stream, firstMeaningful),
    }),
  });
}

function isRecord(value: unknown): value is Readonly<Record<string, unknown>> {
  return value !== null
    && typeof value === "object"
    && !Array.isArray(value);
}

function ownString(
  value: Readonly<Record<string, unknown>>,
  key: string,
): string | null {
  const candidate = Object.hasOwn(value, key) ? value[key] : undefined;
  return typeof candidate === "string" ? candidate : null;
}

function responseEventType(
  json: unknown,
  eventName: string | null,
): string | null {
  if (isRecord(json)) {
    const type = ownString(json, "type");
    if (type !== null) return type;
  }
  return eventName;
}

function isProviderError(
  json: unknown,
  eventName: string | null,
  type: string | null,
): boolean {
  if (eventName === "error" || type === "error" || type?.endsWith(".error")) {
    return true;
  }
  return isRecord(json) && Object.hasOwn(json, "error");
}

function hasUsage(json: unknown): boolean {
  if (!isRecord(json)) return false;
  if (Object.hasOwn(json, "usage") && json.usage !== null) return true;
  const response = json.response;
  return isRecord(response)
    && Object.hasOwn(response, "usage")
    && response.usage !== null;
}

function hasNonEmptyText(value: unknown): boolean {
  return typeof value === "string" && value.length > 0;
}

function meaningfulChatEvent(json: unknown): boolean {
  if (!isRecord(json)) return false;
  if (hasNonEmptyText(json.text) || hasNonEmptyText(json.content)) return true;
  const choices = json.choices;
  if (!Array.isArray(choices)) return false;
  return choices.some((choice) => {
    if (!isRecord(choice)) return false;
    if (hasNonEmptyText(choice.text)) return true;
    const delta = choice.delta;
    if (isRecord(delta) && hasNonEmptyText(delta.content)) return true;
    const message = choice.message;
    return isRecord(message) && hasNonEmptyText(message.content);
  });
}

function meaningfulResponsesEvent(
  json: unknown,
  type: string | null,
): boolean {
  if (!isRecord(json)) return false;
  return type === "response.output_text.delta"
    && hasNonEmptyText(json.delta);
}

function protocolMeaningful(
  protocol: JsonSseProtocol,
  json: unknown,
  type: string | null,
  providerError: boolean,
): boolean {
  if (providerError) return false;
  switch (protocol) {
    case "openai-chat-completions":
      return meaningfulChatEvent(json);
    case "openai-responses":
      return meaningfulResponsesEvent(json, type);
    case "generic-json-sse":
      return true;
  }
}

/** Parse SSE data fields as bounded, duplicate-key-rejecting JSON values. */
export async function parseBoundedJsonSse(
  source: ByteChunkSource,
  inputOptions: BoundedJsonSseOptions,
): Promise<JsonSseParseResult> {
  const rawOptions = snapshotRecord(inputOptions, JSON_SSE_OPTION_KEYS);
  if (
    !Object.hasOwn(rawOptions, "jsonLimits")
    || !Object.hasOwn(rawOptions, "protocol")
    || (
      rawOptions.protocol !== "generic-json-sse"
      && rawOptions.protocol !== "openai-chat-completions"
      && rawOptions.protocol !== "openai-responses"
    )
  ) {
    fail("invalid-options");
  }
  const options = normalizeSseOptions(
    inputOptions,
    JSON_SSE_OPTION_KEYS,
  );
  const jsonLimits = snapshotJsonLimits(
    rawOptions.jsonLimits,
    options.limits.maxEventBytes,
  );

  const stream = await collectStream(source, options);
  const parsed = parseSseBytes(stream, options);
  const protocol = rawOptions.protocol as JsonSseProtocol;
  const events: JsonSseEvent[] = [];
  let providerErrorSeen = false;
  let responseCompletedSeen = false;
  let responseCompletedUsagePresent = false;
  let firstMeaningfulAtMs: number | null = null;
  let semanticTerminalSeen = false;

  for (const event of parsed.events) {
    if (semanticTerminalSeen) fail("terminal-order");
    let json: unknown | null = null;
    if (event.kind !== "done") {
      try {
        json = parseBoundedJson(
          new TextEncoder().encode(event.data),
          jsonLimits,
        );
      } catch {
        fail("invalid-json");
      }
    }
    const type = responseEventType(json, event.event);
    const providerError = isProviderError(json, event.event, type);
    const eventUsage = hasUsage(json);
    const meaningfulOutput = event.kind === "event"
      && protocolMeaningful(protocol, json, type, providerError);
    if (meaningfulOutput && firstMeaningfulAtMs === null) {
      firstMeaningfulAtMs = event.observedAtMs;
    }
    providerErrorSeen ||= providerError;
    responseCompletedSeen ||= type === "response.completed";
    if (type === "response.completed") {
      responseCompletedUsagePresent = eventUsage;
    }
    semanticTerminalSeen = providerError
      || event.kind === "done"
      || (
        protocol === "openai-responses"
        && type === "response.completed"
      );
    events.push(Object.freeze({
      ...event,
      json,
      type,
      providerError,
      usagePresent: eventUsage,
      meaningfulOutput,
    }));
  }
  if (semanticTerminalSeen && parsed.trailingIncompleteEvent) {
    fail("terminal-order");
  }

  const doneSeen = events.at(-1)?.kind === "done";
  let terminal: JsonSseSummary["terminal"];
  if (providerErrorSeen) {
    terminal = "provider-error";
  } else if (protocol === "openai-responses") {
    terminal = responseCompletedSeen ? "response.completed" : "truncated";
  } else if (protocol === "openai-chat-completions") {
    terminal = doneSeen ? "done-sentinel" : "truncated";
  } else {
    terminal = doneSeen ? "done-sentinel" : "eof";
  }

  let finalUsage: JsonSseSummary["finalUsage"];
  if (protocol === "generic-json-sse") {
    finalUsage = "not-required";
  } else if (protocol === "openai-responses") {
    finalUsage = (
      !providerErrorSeen
      && responseCompletedSeen
      && responseCompletedUsagePresent
    ) ? "present" : "missing";
  } else {
    const doneIndex = doneSeen ? events.length - 1 : -1;
    finalUsage = (
      !providerErrorSeen
      && doneIndex > 0
      && events[doneIndex - 1]?.usagePresent === true
    ) ? "present" : "missing";
  }
  return Object.freeze({
    events: Object.freeze(events),
    summary: Object.freeze({
      protocol,
      terminal,
      finalUsage,
      trailingIncompleteEvent: parsed.trailingIncompleteEvent,
      totalBytes: stream.bytes.byteLength,
      totalChunks: stream.totalChunks,
      totalLines: parsed.totalLines,
      timing: timing(stream, firstMeaningfulAtMs),
    }),
  });
}
