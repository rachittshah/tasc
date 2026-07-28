import type { KeyObject } from "node:crypto";
import {
  isProxy,
  isSharedArrayBuffer,
  isUint8Array,
} from "node:util/types";
import {
  parseBoundedJson,
  type BoundedNdjsonLimits,
  type ByteChunkSource,
} from "../bounded-input.js";
import {
  createStudyPayloadIdentity,
  MAX_PAYLOAD_IDENTITY_BYTES,
  type KeyedPayloadIdentity,
} from "../references.js";
import {
  RuntimeCodecError,
  type RuntimeStreamIdentity,
  type RuntimeStreamTiming,
} from "./sse.js";

export interface BoundedNdjsonStreamLimits extends BoundedNdjsonLimits {
  readonly maxChunks: number;
}

export const MAX_NDJSON_TOTAL_BYTES = MAX_PAYLOAD_IDENTITY_BYTES;
export const MAX_NDJSON_CHUNKS = 16_384;
export const MAX_NDJSON_LINES = 65_536;
export const MAX_NDJSON_LINE_BYTES = MAX_PAYLOAD_IDENTITY_BYTES;
export const MAX_NDJSON_DEPTH = 64;
export const MAX_NDJSON_OBJECT_KEYS = 131_072;
export const MAX_NDJSON_ARRAY_ITEMS = 131_072;
export const MAX_NDJSON_TOKENS = 1_048_576;
export const MAX_NDJSON_STRING_LENGTH = MAX_PAYLOAD_IDENTITY_BYTES;
export const MAX_NDJSON_NUMERIC_TOKEN_LENGTH = 1_024;
export const MAX_NDJSON_DIAGNOSTIC_LENGTH = 1_024;

export const DEFAULT_NDJSON_STREAM_LIMITS:
Readonly<BoundedNdjsonStreamLimits> = Object.freeze({
  maxBytes: 8 * 1024 * 1024,
  maxDepth: 16,
  maxObjectKeys: 512,
  maxArrayItems: 4_096,
  maxTokens: 32_768,
  maxDecodedStringLength: 1024 * 1024,
  maxNumericTokenLength: 128,
  maxDiagnosticSnippetLength: 0,
  maxLineBytes: 1024 * 1024,
  maxItems: 32_768,
  maxChunks: 16_384,
});

export type NdjsonProtocol = "generic-ndjson" | "ollama";

export interface BoundedNdjsonStreamOptions {
  readonly limits: BoundedNdjsonStreamLimits;
  readonly identity: RuntimeStreamIdentity;
  readonly protocol: NdjsonProtocol;
  readonly clock?: () => number;
  readonly startedAtMs?: number;
}

export interface NdjsonStreamItem {
  readonly index: number;
  readonly json: unknown;
  readonly rawLineIdentity: KeyedPayloadIdentity;
  readonly observedAtMs: number;
  readonly done: boolean;
  readonly providerError: boolean;
  readonly usagePresent: boolean;
  readonly meaningfulOutput: boolean;
}

export interface NdjsonStreamSummary {
  readonly protocol: NdjsonProtocol;
  readonly terminal: "eof" | "done" | "provider-error" | "truncated";
  readonly finalUsage: "present" | "missing" | "not-required";
  readonly totalBytes: number;
  readonly totalChunks: number;
  readonly totalLines: number;
  readonly timing: RuntimeStreamTiming;
}

export interface NdjsonStreamParseResult {
  readonly items: readonly NdjsonStreamItem[];
  readonly summary: NdjsonStreamSummary;
}

interface ChunkMark {
  readonly endOffset: number;
  readonly atMs: number;
}

interface NormalizedOptions {
  readonly limits: Readonly<BoundedNdjsonStreamLimits>;
  readonly identity: Readonly<RuntimeStreamIdentity>;
  readonly protocol: NdjsonProtocol;
  readonly clock: () => number;
  readonly startedAtMs: number;
}

interface CollectedBytes {
  readonly bytes: Uint8Array;
  readonly marks: readonly ChunkMark[];
  readonly totalChunks: number;
  readonly firstByteAtMs: number | null;
  readonly completedAtMs: number;
}

const OPTION_KEYS = new Set([
  "limits",
  "identity",
  "protocol",
  "clock",
  "startedAtMs",
]);
const IDENTITY_KEYS = new Set(["studyId", "keyId", "key"]);
const LIMIT_KEYS = new Set([
  "maxBytes",
  "maxDepth",
  "maxObjectKeys",
  "maxArrayItems",
  "maxTokens",
  "maxDecodedStringLength",
  "maxNumericTokenLength",
  "maxDiagnosticSnippetLength",
  "maxLineBytes",
  "maxItems",
  "maxChunks",
]);

const TYPED_ARRAY_PROTOTYPE =
  Reflect.getPrototypeOf(Uint8Array.prototype) as object;
const BUFFER_GETTER =
  Reflect.getOwnPropertyDescriptor(TYPED_ARRAY_PROTOTYPE, "buffer")?.get;
const BYTE_OFFSET_GETTER =
  Reflect.getOwnPropertyDescriptor(TYPED_ARRAY_PROTOTYPE, "byteOffset")?.get;
const BYTE_LENGTH_GETTER =
  Reflect.getOwnPropertyDescriptor(TYPED_ARRAY_PROTOTYPE, "byteLength")?.get;

function fail(code: ConstructorParameters<typeof RuntimeCodecError>[0]): never {
  throw new RuntimeCodecError(code);
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
    fail("invalid-options");
  }
  const ownKeys = Reflect.ownKeys(input);
  if (
    ownKeys.some(
      (key) => typeof key !== "string" || !allowedKeys.has(key),
    )
  ) {
    fail("invalid-options");
  }
  const snapshot: Record<string, unknown> = Object.create(null);
  for (const key of ownKeys) {
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

function safeInteger(
  value: unknown,
  allowZero = false,
): number {
  if (
    typeof value !== "number"
    || !Number.isSafeInteger(value)
    || value < (allowZero ? 0 : 1)
  ) {
    fail("invalid-options");
  }
  return value;
}

function finiteTime(value: unknown): number {
  if (typeof value !== "number" || !Number.isFinite(value)) fail("clock");
  return value;
}

function normalizeOptions(
  input: BoundedNdjsonStreamOptions,
): NormalizedOptions {
  const raw = snapshotRecord(input, OPTION_KEYS);
  if (
    !Object.hasOwn(raw, "limits")
    || !Object.hasOwn(raw, "identity")
    || (
      raw.protocol !== "generic-ndjson"
      && raw.protocol !== "ollama"
    )
  ) {
    fail("invalid-options");
  }
  const rawLimits = snapshotRecord(raw.limits, LIMIT_KEYS);
  if (Reflect.ownKeys(rawLimits).length !== LIMIT_KEYS.size) {
    fail("invalid-options");
  }
  const limits = Object.freeze({
    maxBytes: safeInteger(rawLimits.maxBytes),
    maxDepth: safeInteger(rawLimits.maxDepth, true),
    maxObjectKeys: safeInteger(rawLimits.maxObjectKeys, true),
    maxArrayItems: safeInteger(rawLimits.maxArrayItems, true),
    maxTokens: safeInteger(rawLimits.maxTokens),
    maxDecodedStringLength: safeInteger(
      rawLimits.maxDecodedStringLength,
      true,
    ),
    maxNumericTokenLength: safeInteger(rawLimits.maxNumericTokenLength),
    maxDiagnosticSnippetLength: safeInteger(
      rawLimits.maxDiagnosticSnippetLength,
      true,
    ),
    maxLineBytes: safeInteger(rawLimits.maxLineBytes),
    maxItems: safeInteger(rawLimits.maxItems),
    maxChunks: safeInteger(rawLimits.maxChunks),
  });
  if (
    limits.maxLineBytes > limits.maxBytes
    || limits.maxBytes > MAX_NDJSON_TOTAL_BYTES
    || limits.maxChunks > MAX_NDJSON_CHUNKS
    || limits.maxItems > MAX_NDJSON_LINES
    || limits.maxLineBytes > MAX_NDJSON_LINE_BYTES
    || limits.maxDepth > MAX_NDJSON_DEPTH
    || limits.maxObjectKeys > MAX_NDJSON_OBJECT_KEYS
    || limits.maxArrayItems > MAX_NDJSON_ARRAY_ITEMS
    || limits.maxTokens > MAX_NDJSON_TOKENS
    || limits.maxDecodedStringLength > MAX_NDJSON_STRING_LENGTH
    || limits.maxNumericTokenLength > MAX_NDJSON_NUMERIC_TOKEN_LENGTH
    || limits.maxDiagnosticSnippetLength > MAX_NDJSON_DIAGNOSTIC_LENGTH
  ) {
    fail("invalid-options");
  }

  const rawIdentity = snapshotRecord(raw.identity, IDENTITY_KEYS);
  if (Reflect.ownKeys(rawIdentity).length !== IDENTITY_KEYS.size) {
    fail("invalid-options");
  }
  const identity = Object.freeze({
    studyId: rawIdentity.studyId as string,
    keyId: rawIdentity.keyId as string,
    key: rawIdentity.key as KeyObject,
  });
  createStudyPayloadIdentity(
    identity.studyId,
    identity.keyId,
    identity.key,
    new Uint8Array(0),
  );
  const clock = Object.hasOwn(raw, "clock") ? raw.clock : Date.now;
  if (typeof clock !== "function" || isProxy(clock)) fail("invalid-options");
  const startedAtMs = Object.hasOwn(raw, "startedAtMs")
    ? finiteTime(raw.startedAtMs)
    : finiteTime(Reflect.apply(clock, undefined, []));
  return Object.freeze({
    limits,
    identity,
    protocol: raw.protocol as NdjsonProtocol,
    clock: clock as () => number,
    startedAtMs,
  });
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
    const offset = Reflect.apply(BYTE_OFFSET_GETTER, input, []) as number;
    const length = Reflect.apply(BYTE_LENGTH_GETTER, input, []) as number;
    return new Uint8Array(buffer, offset, length);
  } catch {
    return undefined;
  }
}

function readClock(
  clock: () => number,
  previous: number,
): number {
  let value: unknown;
  try {
    value = Reflect.apply(clock, undefined, []);
  } catch {
    fail("clock");
  }
  const time = finiteTime(value);
  if (time < previous) fail("clock");
  return time;
}

async function collect(
  source: ByteChunkSource,
  options: NormalizedOptions,
): Promise<CollectedBytes> {
  if (source === null || typeof source !== "object" || isProxy(source)) {
    fail("invalid-source");
  }
  let storage = new Uint8Array(Math.min(options.limits.maxBytes, 1_024));
  let totalBytes = 0;
  let totalChunks = 0;
  let firstByteAtMs: number | null = null;
  let previousTime = options.startedAtMs;
  let ownFailure: RuntimeCodecError | undefined;
  const marks: ChunkMark[] = [];

  const accept = (candidate: unknown): void => {
    if (totalChunks >= options.limits.maxChunks) fail("chunk-limit");
    const view = inspectBytes(candidate);
    if (view === undefined || view.byteLength === 0) fail("invalid-chunk");
    if (view.byteLength > options.limits.maxBytes - totalBytes) {
      fail("byte-limit");
    }
    const snapshot = view.slice();
    const observedAtMs = readClock(options.clock, previousTime);
    previousTime = observedAtMs;
    firstByteAtMs ??= observedAtMs;
    const required = totalBytes + view.byteLength;
    if (required > storage.byteLength) {
      let capacity = Math.max(1, storage.byteLength);
      while (capacity < required) {
        capacity = Math.min(
          options.limits.maxBytes,
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
    marks.push(Object.freeze({ endOffset: totalBytes, atMs: observedAtMs }));
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
  if (
    bytes.byteLength >= 3
    && bytes[0] === 0xef
    && bytes[1] === 0xbb
    && bytes[2] === 0xbf
  ) {
    fail("utf8-bom");
  }
  try {
    const decoder = new TextDecoder("utf-8", {
      fatal: true,
      ignoreBOM: true,
    });
    let offset = 0;
    for (const mark of marks) {
      decoder.decode(bytes.subarray(offset, mark.endOffset), { stream: true });
      offset = mark.endOffset;
    }
    decoder.decode();
  } catch {
    fail("invalid-utf8");
  }
  return Object.freeze({
    bytes,
    marks: Object.freeze(marks),
    totalChunks,
    firstByteAtMs,
    completedAtMs,
  });
}

function observedAt(
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

function isBlank(bytes: Uint8Array): boolean {
  if (bytes.byteLength === 0) return true;
  return bytes.every((byte) =>
    byte === 0x20 || byte === 0x09 || byte === 0x0d);
}

function isRecord(value: unknown): value is Readonly<Record<string, unknown>> {
  return value !== null
    && typeof value === "object"
    && !Array.isArray(value);
}

function isNonEmptyString(value: unknown): boolean {
  return typeof value === "string" && value.length > 0;
}

function ollamaMeaningful(value: unknown): boolean {
  if (!isRecord(value)) return false;
  if (isNonEmptyString(value.response)) return true;
  const message = value.message;
  return isRecord(message) && isNonEmptyString(message.content);
}

function ollamaUsage(value: unknown): boolean {
  if (!isRecord(value)) return false;
  const prompt = value.prompt_eval_count;
  const output = value.eval_count;
  return (
    typeof prompt === "number"
    && Number.isSafeInteger(prompt)
    && prompt >= 0
  ) && (
    typeof output === "number"
    && Number.isSafeInteger(output)
    && output >= 0
  );
}

function streamTiming(
  options: NormalizedOptions,
  collected: CollectedBytes,
  firstMeaningfulAtMs: number | null,
): RuntimeStreamTiming {
  return Object.freeze({
    startedAtMs: options.startedAtMs,
    firstByteAtMs: collected.firstByteAtMs,
    firstMeaningfulAtMs,
    completedAtMs: collected.completedAtMs,
    timeToFirstByteMs: collected.firstByteAtMs === null
      ? null
      : collected.firstByteAtMs - options.startedAtMs,
    timeToFirstMeaningfulMs: firstMeaningfulAtMs === null
      ? null
      : firstMeaningfulAtMs - options.startedAtMs,
    durationMs: collected.completedAtMs - options.startedAtMs,
  });
}

/**
 * Parse a byte-, line-, item-, and chunk-bounded NDJSON stream.
 *
 * Ollama terminal interpretation is deliberately explicit; the generic mode
 * treats a clean EOF as terminal and makes no provider-schema claim.
 */
export async function parseBoundedNdjsonStream(
  source: ByteChunkSource,
  inputOptions: BoundedNdjsonStreamOptions,
): Promise<NdjsonStreamParseResult> {
  const options = normalizeOptions(inputOptions);
  const collected = await collect(source, options);
  const jsonLimits = Object.freeze({
    maxBytes: options.limits.maxLineBytes,
    maxDepth: options.limits.maxDepth,
    maxObjectKeys: options.limits.maxObjectKeys,
    maxArrayItems: options.limits.maxArrayItems,
    maxTokens: options.limits.maxTokens,
    maxDecodedStringLength: options.limits.maxDecodedStringLength,
    maxNumericTokenLength: options.limits.maxNumericTokenLength,
    maxDiagnosticSnippetLength: options.limits.maxDiagnosticSnippetLength,
  });
  const items: NdjsonStreamItem[] = [];
  let lineStart = 0;
  let totalLines = 0;
  let terminalSeen = false;
  let providerErrorSeen = false;
  let terminalUsagePresent = false;
  let firstMeaningfulAtMs: number | null = null;

  const parseLine = (rawEnd: number, observedOffset: number): void => {
    let contentEnd = rawEnd;
    if (
      contentEnd > lineStart
      && collected.bytes[contentEnd - 1] === 0x0d
    ) {
      contentEnd -= 1;
    }
    const rawLine = collected.bytes.subarray(lineStart, contentEnd);
    totalLines += 1;
    if (rawLine.byteLength > options.limits.maxLineBytes) {
      fail("line-byte-limit");
    }
    if (isBlank(rawLine)) fail("blank-line");
    if (items.length >= options.limits.maxItems) fail("item-limit");
    if (terminalSeen) fail("terminal-order");

    let json: unknown;
    try {
      json = parseBoundedJson(rawLine, jsonLimits);
    } catch {
      fail("invalid-json");
    }
    const providerError = isRecord(json) && Object.hasOwn(json, "error");
    const done = options.protocol === "ollama"
      && isRecord(json)
      && json.done === true;
    const usagePresent = options.protocol === "ollama" && ollamaUsage(json);
    const meaningfulOutput = !providerError && !done && (
      options.protocol === "ollama" ? ollamaMeaningful(json) : true
    );
    const itemObservedAtMs = observedAt(
      collected.marks,
      observedOffset,
      collected.completedAtMs,
    );
    if (meaningfulOutput && firstMeaningfulAtMs === null) {
      firstMeaningfulAtMs = itemObservedAtMs;
    }
    items.push(Object.freeze({
      index: items.length,
      json,
      rawLineIdentity: createStudyPayloadIdentity(
        options.identity.studyId,
        options.identity.keyId,
        options.identity.key,
        collected.bytes.subarray(lineStart, observedOffset),
      ),
      observedAtMs: itemObservedAtMs,
      done,
      providerError,
      usagePresent,
      meaningfulOutput,
    }));
    providerErrorSeen ||= providerError;
    if (done) terminalUsagePresent = usagePresent;
    terminalSeen = providerError || done;
  };

  for (let cursor = 0; cursor < collected.bytes.byteLength; cursor += 1) {
    if (collected.bytes[cursor] !== 0x0a) continue;
    parseLine(cursor, cursor + 1);
    lineStart = cursor + 1;
  }
  if (lineStart < collected.bytes.byteLength) {
    parseLine(collected.bytes.byteLength, collected.bytes.byteLength);
  }

  let terminal: NdjsonStreamSummary["terminal"];
  if (providerErrorSeen) {
    terminal = "provider-error";
  } else if (options.protocol === "ollama") {
    terminal = items.at(-1)?.done === true ? "done" : "truncated";
  } else {
    terminal = "eof";
  }
  const finalUsage = options.protocol === "generic-ndjson"
    ? "not-required"
    : terminalUsagePresent ? "present" : "missing";
  return Object.freeze({
    items: Object.freeze(items),
    summary: Object.freeze({
      protocol: options.protocol,
      terminal,
      finalUsage,
      totalBytes: collected.bytes.byteLength,
      totalChunks: collected.totalChunks,
      totalLines,
      timing: streamTiming(options, collected, firstMeaningfulAtMs),
    }),
  });
}
