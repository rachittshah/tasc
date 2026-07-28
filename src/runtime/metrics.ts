import type { KeyObject } from "node:crypto";
import {
  isProxy,
  isSharedArrayBuffer,
  isUint8Array,
} from "node:util/types";
import {
  createStudyPayloadIdentity,
  type KeyedPayloadIdentity,
} from "../references.js";
import {
  RuntimeCodecError,
  type RuntimeStreamIdentity,
} from "./sse.js";

export interface BoundedPrometheusLimits {
  readonly maxBytes: number;
  readonly maxLines: number;
  readonly maxLineBytes: number;
  readonly maxSamples: number;
  readonly maxSelectedSamples: number;
  readonly maxLabelsPerSample: number;
  readonly maxMetricNameLength: number;
  readonly maxLabelNameLength: number;
  readonly maxLabelValueLength: number;
  readonly maxSelectedMetricNames: number;
}

export const MAX_PROMETHEUS_BYTES = 8 * 1024 * 1024;
export const MAX_PROMETHEUS_LINES = 100_000;
export const MAX_PROMETHEUS_LINE_BYTES = 64 * 1024;
export const MAX_PROMETHEUS_SAMPLES = 100_000;
export const MAX_PROMETHEUS_SELECTED_SAMPLES = 65_536;
export const MAX_PROMETHEUS_LABELS = 64;
export const MAX_PROMETHEUS_METRIC_NAME_LENGTH = 1_024;
export const MAX_PROMETHEUS_LABEL_NAME_LENGTH = 1_024;
export const MAX_PROMETHEUS_LABEL_VALUE_LENGTH = 65_536;
export const MAX_PROMETHEUS_SELECTED_NAMES = 256;

export const DEFAULT_PROMETHEUS_LIMITS:
Readonly<BoundedPrometheusLimits> = Object.freeze({
  maxBytes: 4 * 1024 * 1024,
  maxLines: 65_536,
  maxLineBytes: 64 * 1024,
  maxSamples: 65_536,
  maxSelectedSamples: 8_192,
  maxLabelsPerSample: 32,
  maxMetricNameLength: 256,
  maxLabelNameLength: 128,
  maxLabelValueLength: 4_096,
  maxSelectedMetricNames: 64,
});

export interface PrometheusTextOptions {
  readonly limits: BoundedPrometheusLimits;
  readonly selectedMetricNames: readonly string[];
  readonly identity: RuntimeStreamIdentity;
}

export interface PrometheusLabel {
  readonly name: string;
  readonly value: string;
}

export interface PrometheusSample {
  readonly metric: string;
  readonly labels: readonly PrometheusLabel[];
  readonly value: number;
  /** Canonical signed-int64 decimal milliseconds; a string avoids precision loss. */
  readonly timestampMs: string | null;
  readonly rawSampleIdentity: KeyedPayloadIdentity;
}

export interface PrometheusParseSummary {
  readonly totalBytes: number;
  readonly totalLines: number;
  readonly totalSamples: number;
  readonly selectedSamples: number;
  readonly ignoredSamples: number;
  readonly commentLines: number;
}

export interface PrometheusParseResult {
  readonly samples: readonly PrometheusSample[];
  readonly summary: PrometheusParseSummary;
}

interface NormalizedOptions {
  readonly limits: Readonly<BoundedPrometheusLimits>;
  readonly selectedMetricNames: ReadonlySet<string>;
  readonly identity: Readonly<RuntimeStreamIdentity>;
}

const OPTION_KEYS = new Set([
  "limits",
  "selectedMetricNames",
  "identity",
]);
const LIMIT_KEYS = new Set([
  "maxBytes",
  "maxLines",
  "maxLineBytes",
  "maxSamples",
  "maxSelectedSamples",
  "maxLabelsPerSample",
  "maxMetricNameLength",
  "maxLabelNameLength",
  "maxLabelValueLength",
  "maxSelectedMetricNames",
]);
const IDENTITY_KEYS = new Set(["studyId", "keyId", "key"]);
const METRIC_NAME = /^[A-Za-z_:][A-Za-z0-9_:]*$/;
const LABEL_NAME = /^[A-Za-z_][A-Za-z0-9_]*$/;
const FINITE_NUMBER =
  /^[+-]?(?:(?:\d+(?:\.\d*)?)|(?:\.\d+))(?:[eE][+-]?\d+)?$/;
const NONFINITE_NUMBER = /^[+-]?(?:Inf|Infinity|NaN)$/i;
const TIMESTAMP = /^[+-]?\d+$/;
const MIN_SIGNED_INT64 = -(2n ** 63n);
const MAX_SIGNED_INT64 = (2n ** 63n) - 1n;
const CLASSIC_METRIC_TYPES = new Set([
  "counter",
  "gauge",
  "histogram",
  "summary",
  "untyped",
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

function safeInteger(value: unknown, allowZero = false): number {
  if (
    typeof value !== "number"
    || !Number.isSafeInteger(value)
    || value < (allowZero ? 0 : 1)
  ) {
    fail("invalid-options");
  }
  return value;
}

function inspectBytes(input: unknown): Uint8Array {
  if (
    input === null
    || typeof input !== "object"
    || isProxy(input)
    || !isUint8Array(input)
    || BUFFER_GETTER === undefined
    || BYTE_OFFSET_GETTER === undefined
    || BYTE_LENGTH_GETTER === undefined
  ) {
    fail("invalid-source");
  }
  try {
    const buffer = Reflect.apply(BUFFER_GETTER, input, []) as ArrayBufferLike;
    if (isSharedArrayBuffer(buffer)) fail("invalid-source");
    const offset = Reflect.apply(BYTE_OFFSET_GETTER, input, []) as number;
    const length = Reflect.apply(BYTE_LENGTH_GETTER, input, []) as number;
    return new Uint8Array(buffer, offset, length);
  } catch (error) {
    if (error instanceof RuntimeCodecError) throw error;
    fail("invalid-source");
  }
}

function snapshotMetricNames(
  input: unknown,
  limits: Readonly<BoundedPrometheusLimits>,
): ReadonlySet<string> {
  if (
    input === null
    || typeof input !== "object"
    || isProxy(input)
    || !Array.isArray(input)
    || Reflect.getPrototypeOf(input) !== Array.prototype
  ) {
    fail("invalid-options");
  }
  const lengthDescriptor = Reflect.getOwnPropertyDescriptor(input, "length");
  const length = lengthDescriptor?.value;
  if (
    typeof length !== "number"
    || !Number.isSafeInteger(length)
    || length < 1
    || length > limits.maxSelectedMetricNames
  ) {
    fail("invalid-options");
  }
  const names = new Set<string>();
  const allowedKeys = new Set(["length"]);
  for (let index = 0; index < length; index += 1) {
    const key = String(index);
    allowedKeys.add(key);
    const descriptor = Reflect.getOwnPropertyDescriptor(input, key);
    if (
      descriptor === undefined
      || !Object.hasOwn(descriptor, "value")
      || !descriptor.enumerable
      || typeof descriptor.value !== "string"
      || descriptor.value.length > limits.maxMetricNameLength
      || !METRIC_NAME.test(descriptor.value)
      || names.has(descriptor.value)
    ) {
      fail("invalid-options");
    }
    names.add(descriptor.value);
  }
  if (
    Reflect.ownKeys(input).some(
      (key) => typeof key !== "string" || !allowedKeys.has(key),
    )
  ) {
    fail("invalid-options");
  }
  return names;
}

function normalizeOptions(input: PrometheusTextOptions): NormalizedOptions {
  const raw = snapshotRecord(input, OPTION_KEYS);
  if (
    !Object.hasOwn(raw, "limits")
    || !Object.hasOwn(raw, "selectedMetricNames")
    || !Object.hasOwn(raw, "identity")
  ) {
    fail("invalid-options");
  }
  const rawLimits = snapshotRecord(raw.limits, LIMIT_KEYS);
  if (Reflect.ownKeys(rawLimits).length !== LIMIT_KEYS.size) {
    fail("invalid-options");
  }
  const limits = Object.freeze({
    maxBytes: safeInteger(rawLimits.maxBytes),
    maxLines: safeInteger(rawLimits.maxLines),
    maxLineBytes: safeInteger(rawLimits.maxLineBytes),
    maxSamples: safeInteger(rawLimits.maxSamples),
    maxSelectedSamples: safeInteger(rawLimits.maxSelectedSamples),
    maxLabelsPerSample: safeInteger(rawLimits.maxLabelsPerSample, true),
    maxMetricNameLength: safeInteger(rawLimits.maxMetricNameLength),
    maxLabelNameLength: safeInteger(rawLimits.maxLabelNameLength),
    maxLabelValueLength: safeInteger(rawLimits.maxLabelValueLength, true),
    maxSelectedMetricNames: safeInteger(rawLimits.maxSelectedMetricNames),
  });
  if (
    limits.maxLineBytes > limits.maxBytes
    || limits.maxBytes > MAX_PROMETHEUS_BYTES
    || limits.maxLines > MAX_PROMETHEUS_LINES
    || limits.maxLineBytes > MAX_PROMETHEUS_LINE_BYTES
    || limits.maxSamples > MAX_PROMETHEUS_SAMPLES
    || limits.maxSelectedSamples > MAX_PROMETHEUS_SELECTED_SAMPLES
    || limits.maxLabelsPerSample > MAX_PROMETHEUS_LABELS
    || limits.maxMetricNameLength > MAX_PROMETHEUS_METRIC_NAME_LENGTH
    || limits.maxLabelNameLength > MAX_PROMETHEUS_LABEL_NAME_LENGTH
    || limits.maxLabelValueLength > MAX_PROMETHEUS_LABEL_VALUE_LENGTH
    || limits.maxSelectedMetricNames > MAX_PROMETHEUS_SELECTED_NAMES
    || limits.maxSelectedSamples > limits.maxSamples
  ) {
    fail("invalid-options");
  }
  const selectedMetricNames = snapshotMetricNames(
    raw.selectedMetricNames,
    limits,
  );
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
  return Object.freeze({ limits, selectedMetricNames, identity });
}

function decodeUtf8(input: Uint8Array): string {
  try {
    return new TextDecoder("utf-8", {
      fatal: true,
      ignoreBOM: true,
    }).decode(input);
  } catch {
    fail("invalid-utf8");
  }
}

function skipHorizontalWhitespace(value: string, start: number): number {
  let cursor = start;
  while (value[cursor] === " " || value[cursor] === "\t") cursor += 1;
  return cursor;
}

interface ParsedLabels {
  readonly labels: readonly PrometheusLabel[];
  readonly end: number;
}

function parseLabels(
  line: string,
  start: number,
  limits: Readonly<BoundedPrometheusLimits>,
): ParsedLabels {
  const labels: PrometheusLabel[] = [];
  const names = new Set<string>();
  let cursor = start + 1;
  cursor = skipHorizontalWhitespace(line, cursor);
  if (line[cursor] === "}") {
    return Object.freeze({ labels: Object.freeze([]), end: cursor + 1 });
  }

  while (cursor < line.length) {
    if (labels.length >= limits.maxLabelsPerSample) fail("label-limit");
    const nameStart = cursor;
    while (/[A-Za-z0-9_]/.test(line[cursor] ?? "")) cursor += 1;
    const name = line.slice(nameStart, cursor);
    if (
      name.length < 1
      || name.length > limits.maxLabelNameLength
      || !LABEL_NAME.test(name)
      || names.has(name)
    ) {
      if (names.has(name)) fail("duplicate-sample");
      fail("unsupported-syntax");
    }
    cursor = skipHorizontalWhitespace(line, cursor);
    if (line[cursor] !== "=") fail("unsupported-syntax");
    cursor = skipHorizontalWhitespace(line, cursor + 1);
    if (line[cursor] !== "\"") fail("unsupported-syntax");
    cursor += 1;

    let decoded = "";
    let closed = false;
    while (cursor < line.length) {
      const character = line[cursor];
      if (character === "\"") {
        closed = true;
        cursor += 1;
        break;
      }
      if (character === "\\") {
        const escaped = line[cursor + 1];
        if (escaped === "\\" || escaped === "\"") {
          decoded += escaped;
        } else if (escaped === "n") {
          decoded += "\n";
        } else {
          fail("unsupported-syntax");
        }
        cursor += 2;
      } else {
        if (
          character === undefined
          || character === "\r"
          || character === "\n"
          || character === "\u0000"
        ) {
          fail("unsupported-syntax");
        }
        decoded += character;
        cursor += 1;
      }
      if (decoded.length > limits.maxLabelValueLength) fail("label-limit");
    }
    if (!closed) fail("unsupported-syntax");
    names.add(name);
    labels.push(Object.freeze({ name, value: decoded }));

    cursor = skipHorizontalWhitespace(line, cursor);
    if (line[cursor] === "}") {
      cursor += 1;
      break;
    }
    if (line[cursor] !== ",") fail("unsupported-syntax");
    cursor = skipHorizontalWhitespace(line, cursor + 1);
    if (line[cursor] === "}") fail("unsupported-syntax");
  }
  if (line[cursor - 1] !== "}") fail("unsupported-syntax");
  labels.sort((left, right) =>
    left.name < right.name ? -1 : left.name > right.name ? 1 : 0);
  return Object.freeze({ labels: Object.freeze(labels), end: cursor });
}

interface ParsedSample {
  readonly metric: string;
  readonly labels: readonly PrometheusLabel[];
  readonly value: number;
  readonly timestampMs: string | null;
}

function parseSampleLine(
  line: string,
  limits: Readonly<BoundedPrometheusLimits>,
): ParsedSample {
  let cursor = 0;
  while (
    cursor < line.length
    && line[cursor] !== "{"
    && line[cursor] !== " "
    && line[cursor] !== "\t"
  ) {
    cursor += 1;
  }
  const metric = line.slice(0, cursor);
  if (
    metric.length < 1
    || metric.length > limits.maxMetricNameLength
    || !METRIC_NAME.test(metric)
  ) {
    fail("unsupported-syntax");
  }

  let labels: readonly PrometheusLabel[] = Object.freeze([]);
  if (line[cursor] === "{") {
    const parsedLabels = parseLabels(line, cursor, limits);
    labels = parsedLabels.labels;
    cursor = parsedLabels.end;
  }
  if (line[cursor] !== " " && line[cursor] !== "\t") {
    fail("unsupported-syntax");
  }
  cursor = skipHorizontalWhitespace(line, cursor);
  const valueStart = cursor;
  while (
    cursor < line.length
    && line[cursor] !== " "
    && line[cursor] !== "\t"
  ) {
    cursor += 1;
  }
  const valueToken = line.slice(valueStart, cursor);
  if (NONFINITE_NUMBER.test(valueToken)) fail("nonfinite-value");
  if (!FINITE_NUMBER.test(valueToken)) fail("unsupported-syntax");
  const value = Number(valueToken);
  if (!Number.isFinite(value)) fail("nonfinite-value");

  cursor = skipHorizontalWhitespace(line, cursor);
  let timestampMs: string | null = null;
  if (cursor < line.length) {
    const timestampToken = line.slice(cursor);
    if (timestampToken.length > 32 || !TIMESTAMP.test(timestampToken)) {
      fail("unsupported-syntax");
    }
    let timestamp: bigint;
    try {
      timestamp = BigInt(timestampToken);
    } catch {
      fail("unsupported-syntax");
    }
    if (timestamp < MIN_SIGNED_INT64 || timestamp > MAX_SIGNED_INT64) {
      fail("unsupported-syntax");
    }
    timestampMs = timestamp.toString();
  }
  return Object.freeze({ metric, labels, value, timestampMs });
}

function validateComment(
  line: string,
  seenHelp: Set<string>,
  seenType: Set<string>,
  maxMetricNameLength: number,
): void {
  if (line === "# EOF") fail("unsupported-syntax");
  if (line.startsWith("# HELP ")) {
    const rest = line.slice("# HELP ".length);
    const separator = rest.indexOf(" ");
    if (separator < 1) fail("unsupported-syntax");
    const metric = rest.slice(0, separator);
    if (
      metric.length > maxMetricNameLength
      || !METRIC_NAME.test(metric)
      || seenHelp.has(metric)
    ) {
      fail("unsupported-syntax");
    }
    seenHelp.add(metric);
    return;
  }
  if (line.startsWith("# TYPE ")) {
    const parts = line.slice("# TYPE ".length).split(/[ \t]+/u);
    if (
      parts.length !== 2
      || (parts[0]?.length ?? 0) > maxMetricNameLength
      || !METRIC_NAME.test(parts[0] ?? "")
      || !CLASSIC_METRIC_TYPES.has(parts[1] ?? "")
      || seenType.has(parts[0] ?? "")
    ) {
      fail("unsupported-syntax");
    }
    seenType.add(parts[0] as string);
    return;
  }
  if (line.startsWith("# UNIT ")) fail("unsupported-syntax");
  // Ordinary comments are part of the classic text format and are ignored.
}

function sampleKey(sample: ParsedSample): string {
  return JSON.stringify([
    sample.metric,
    sample.labels.map(({ name, value }) => [name, value]),
  ]);
}

/**
 * Parse bounded Prometheus 0.0.4 text exposition and retain only selected
 * metrics. Every sample is still syntax-checked and counted before selection.
 */
export function parsePrometheusText(
  input: Uint8Array,
  inputOptions: PrometheusTextOptions,
): PrometheusParseResult {
  const options = normalizeOptions(inputOptions);
  const bytes = inspectBytes(input);
  if (bytes.byteLength > options.limits.maxBytes) fail("byte-limit");
  if (
    bytes.byteLength >= 3
    && bytes[0] === 0xef
    && bytes[1] === 0xbb
    && bytes[2] === 0xbf
  ) {
    fail("utf8-bom");
  }
  // Validate the complete byte sequence before materializing any selected row.
  decodeUtf8(bytes);

  const samples: PrometheusSample[] = [];
  const sampleKeys = new Set<string>();
  const seenHelp = new Set<string>();
  const seenType = new Set<string>();
  let lineStart = 0;
  let totalLines = 0;
  let totalSamples = 0;
  let commentLines = 0;

  const processLine = (contentEndInput: number, framedEnd: number): void => {
    totalLines += 1;
    if (totalLines > options.limits.maxLines) fail("line-limit");
    let contentEnd = contentEndInput;
    if (contentEnd > lineStart && bytes[contentEnd - 1] === 0x0d) {
      contentEnd -= 1;
    }
    const lineBytes = bytes.subarray(lineStart, contentEnd);
    if (lineBytes.byteLength > options.limits.maxLineBytes) {
      fail("line-byte-limit");
    }
    if (lineBytes.byteLength === 0) return;
    const line = decodeUtf8(lineBytes);
    if (line.startsWith("#")) {
      commentLines += 1;
      validateComment(
        line,
        seenHelp,
        seenType,
        options.limits.maxMetricNameLength,
      );
      return;
    }

    if (totalSamples >= options.limits.maxSamples) fail("sample-limit");
    const parsed = parseSampleLine(line, options.limits);
    totalSamples += 1;
    const key = sampleKey(parsed);
    if (sampleKeys.has(key)) fail("duplicate-sample");
    sampleKeys.add(key);
    if (!options.selectedMetricNames.has(parsed.metric)) return;
    if (samples.length >= options.limits.maxSelectedSamples) {
      fail("sample-limit");
    }
    samples.push(Object.freeze({
      ...parsed,
      rawSampleIdentity: createStudyPayloadIdentity(
        options.identity.studyId,
        options.identity.keyId,
        options.identity.key,
        bytes.subarray(lineStart, framedEnd),
      ),
    }));
  };

  for (let cursor = 0; cursor < bytes.byteLength; cursor += 1) {
    if (bytes[cursor] !== 0x0a) continue;
    processLine(cursor, cursor + 1);
    lineStart = cursor + 1;
  }
  if (lineStart < bytes.byteLength) {
    processLine(bytes.byteLength, bytes.byteLength);
  }

  return Object.freeze({
    samples: Object.freeze(samples),
    summary: Object.freeze({
      totalBytes: bytes.byteLength,
      totalLines,
      totalSamples,
      selectedSamples: samples.length,
      ignoredSamples: totalSamples - samples.length,
      commentLines,
    }),
  });
}
