import { isProxy, isSharedArrayBuffer, isUint8Array } from "node:util/types";

/**
 * Caller-owned limits for one JSON document.
 *
 * `maxObjectKeys` is document-wide. `maxDepth` counts open object/array
 * containers (a root primitive has depth zero). `maxTokens` counts JSON lexical
 * tokens, including punctuation. Decoded string length uses JavaScript UTF-16
 * code units, matching the length of the value returned by `JSON.parse`.
 */
export interface BoundedJsonLimits {
  readonly maxBytes: number;
  readonly maxDepth: number;
  readonly maxObjectKeys: number;
  readonly maxArrayItems: number;
  readonly maxTokens: number;
  readonly maxDecodedStringLength: number;
  readonly maxNumericTokenLength: number;
  readonly maxDiagnosticSnippetLength: number;
}

/**
 * Caller-owned limits for an NDJSON document.
 *
 * JSON grammar limits apply independently to each record. `maxBytes` and
 * `maxItems` apply to the complete input; `maxLineBytes` excludes LF/CRLF.
 */
export interface BoundedNdjsonLimits extends BoundedJsonLimits {
  readonly maxLineBytes: number;
  readonly maxItems: number;
}

export type BoundedInputErrorCode =
  | "byte-limit"
  | "depth-limit"
  | "object-key-limit"
  | "array-item-limit"
  | "token-limit"
  | "decoded-string-limit"
  | "numeric-token-limit"
  | "number-range"
  | "duplicate-key"
  | "invalid-unicode"
  | "invalid-utf8"
  | "utf8-bom"
  | "invalid-json"
  | "line-byte-limit"
  | "item-limit"
  | "blank-line"
  | "chunk-limit"
  | "invalid-chunk"
  | "input-stream";

/**
 * Defense-in-depth work cap for hostile iterables. Byte limits alone do not
 * bound iterator overhead when a source yields one byte per chunk.
 */
export const MAX_BOUNDED_INPUT_CHUNKS = 16_384;

const ERROR_MESSAGES: Readonly<Record<BoundedInputErrorCode, string>> = Object.freeze({
  "byte-limit": "input exceeds the configured byte limit",
  "depth-limit": "JSON exceeds the configured container depth limit",
  "object-key-limit": "JSON exceeds the configured object key limit",
  "array-item-limit": "JSON array exceeds the configured per-array item limit",
  "token-limit": "JSON exceeds the configured lexical token limit",
  "decoded-string-limit": "JSON string exceeds the configured decoded length limit",
  "numeric-token-limit": "JSON number exceeds the configured token length limit",
  "number-range": "JSON number is outside the finite JavaScript number range",
  "duplicate-key": "JSON object contains a duplicate key",
  "invalid-unicode": "JSON string contains a non-Unicode-scalar value",
  "invalid-utf8": "input is not valid UTF-8",
  "utf8-bom": "input must not begin with a UTF-8 byte-order mark",
  "invalid-json": "input is not exactly one valid JSON value",
  "line-byte-limit": "NDJSON record exceeds the configured line byte limit",
  "item-limit": "NDJSON exceeds the configured item limit",
  "blank-line": "NDJSON contains a blank record",
  "chunk-limit": "input stream exceeds the bounded chunk work limit",
  "invalid-chunk": "input stream yielded an invalid or empty byte chunk",
  "input-stream": "input stream failed",
});

const REDACTED_DIAGNOSTIC = "<input-redacted>";

/** A deterministic parse failure that never contains bytes from the input. */
export class BoundedInputError extends Error {
  readonly code: BoundedInputErrorCode;
  readonly diagnosticSnippet: string;
  readonly line: number | undefined;

  constructor(
    code: BoundedInputErrorCode,
    maxDiagnosticSnippetLength: number,
    line?: number,
  ) {
    const safeCode = Object.hasOwn(ERROR_MESSAGES, code) ? code : "invalid-json";
    const safeLine = Number.isSafeInteger(line) && (line ?? 0) >= 1 ? line : undefined;
    const lineSuffix = safeLine === undefined ? "" : ` at line ${safeLine}`;
    super(`${ERROR_MESSAGES[safeCode]}${lineSuffix}`);
    this.name = "BoundedInputError";
    this.code = safeCode;
    this.diagnosticSnippet = REDACTED_DIAGNOSTIC.slice(
      0,
      Number.isSafeInteger(maxDiagnosticSnippetLength)
        ? Math.max(0, maxDiagnosticSnippetLength)
        : 0,
    );
    this.line = safeLine;
  }
}

interface NormalizedJsonLimits extends BoundedJsonLimits {}

interface NormalizedNdjsonLimits extends BoundedNdjsonLimits {}

const JSON_LIMIT_NAMES = [
  "maxBytes",
  "maxDepth",
  "maxObjectKeys",
  "maxArrayItems",
  "maxTokens",
  "maxDecodedStringLength",
  "maxNumericTokenLength",
  "maxDiagnosticSnippetLength",
] as const satisfies readonly (keyof BoundedJsonLimits)[];

const NDJSON_LIMIT_NAMES = [
  ...JSON_LIMIT_NAMES,
  "maxLineBytes",
  "maxItems",
] as const satisfies readonly (keyof BoundedNdjsonLimits)[];

function assertSafeLimit(value: number, name: string): void {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new RangeError(`${name} must be a safe non-negative integer`);
  }
}

function snapshotExactLimitRecord(
  limits: unknown,
  expectedNames: readonly string[],
): Readonly<Record<string, number>> {
  if (
    limits === null
    || typeof limits !== "object"
    || isProxy(limits)
  ) {
    throw new TypeError("limits must be a plain, non-proxied limit record");
  }
  const prototype = Object.getPrototypeOf(limits) as object | null;
  if (prototype !== Object.prototype && prototype !== null) {
    throw new TypeError("limits must be a plain, non-proxied limit record");
  }

  const ownKeys = Reflect.ownKeys(limits);
  const expected = new Set(expectedNames);
  if (
    ownKeys.length !== expectedNames.length
    || ownKeys.some((key) => typeof key !== "string" || !expected.has(key))
  ) {
    throw new TypeError("limits must be an exact limit record");
  }

  const descriptors = Object.getOwnPropertyDescriptors(limits);
  const snapshot: Record<string, number> = Object.create(null) as Record<string, number>;
  for (const name of expectedNames) {
    const descriptor = descriptors[name];
    if (
      descriptor === undefined
      || !descriptor.enumerable
      || !("value" in descriptor)
    ) {
      throw new TypeError(`${name} must be an enumerable data property`);
    }
    const value = descriptor.value as number;
    assertSafeLimit(value, name);
    snapshot[name] = value;
  }
  return Object.freeze(snapshot);
}

function normalizeJsonLimits(limits: BoundedJsonLimits): NormalizedJsonLimits {
  const snapshot = snapshotExactLimitRecord(limits, JSON_LIMIT_NAMES);
  return Object.freeze({
    maxBytes: snapshot.maxBytes,
    maxDepth: snapshot.maxDepth,
    maxObjectKeys: snapshot.maxObjectKeys,
    maxArrayItems: snapshot.maxArrayItems,
    maxTokens: snapshot.maxTokens,
    maxDecodedStringLength: snapshot.maxDecodedStringLength,
    maxNumericTokenLength: snapshot.maxNumericTokenLength,
    maxDiagnosticSnippetLength: snapshot.maxDiagnosticSnippetLength,
  }) as NormalizedJsonLimits;
}

function normalizeNdjsonLimits(limits: BoundedNdjsonLimits): NormalizedNdjsonLimits {
  const snapshot = snapshotExactLimitRecord(limits, NDJSON_LIMIT_NAMES);
  return Object.freeze({
    maxBytes: snapshot.maxBytes,
    maxDepth: snapshot.maxDepth,
    maxObjectKeys: snapshot.maxObjectKeys,
    maxArrayItems: snapshot.maxArrayItems,
    maxTokens: snapshot.maxTokens,
    maxDecodedStringLength: snapshot.maxDecodedStringLength,
    maxNumericTokenLength: snapshot.maxNumericTokenLength,
    maxDiagnosticSnippetLength: snapshot.maxDiagnosticSnippetLength,
    maxLineBytes: snapshot.maxLineBytes,
    maxItems: snapshot.maxItems,
  }) as NormalizedNdjsonLimits;
}

function fail(
  code: BoundedInputErrorCode,
  limits: NormalizedJsonLimits,
  line?: number,
): never {
  throw new BoundedInputError(code, limits.maxDiagnosticSnippetLength, line);
}

const TYPED_ARRAY_PROTOTYPE = Object.getPrototypeOf(Uint8Array.prototype) as object;
const TYPED_ARRAY_BUFFER_GETTER =
  Object.getOwnPropertyDescriptor(TYPED_ARRAY_PROTOTYPE, "buffer")?.get;
const TYPED_ARRAY_BYTE_OFFSET_GETTER =
  Object.getOwnPropertyDescriptor(TYPED_ARRAY_PROTOTYPE, "byteOffset")?.get;
const TYPED_ARRAY_BYTE_LENGTH_GETTER =
  Object.getOwnPropertyDescriptor(TYPED_ARRAY_PROTOTYPE, "byteLength")?.get;

interface InspectedByteView {
  readonly view: Uint8Array;
  readonly byteLength: number;
}

function inspectByteView(input: unknown): InspectedByteView | undefined {
  if (
    isProxy(input)
    || !isUint8Array(input)
    || TYPED_ARRAY_BUFFER_GETTER === undefined
    || TYPED_ARRAY_BYTE_OFFSET_GETTER === undefined
    || TYPED_ARRAY_BYTE_LENGTH_GETTER === undefined
  ) {
    return undefined;
  }
  try {
    const buffer = TYPED_ARRAY_BUFFER_GETTER.call(input) as ArrayBufferLike;
    if (isSharedArrayBuffer(buffer)) return undefined;
    const byteOffset = TYPED_ARRAY_BYTE_OFFSET_GETTER.call(input) as number;
    const byteLength = TYPED_ARRAY_BYTE_LENGTH_GETTER.call(input) as number;
    return Object.freeze({
      view: new Uint8Array(buffer, byteOffset, byteLength),
      byteLength,
    });
  } catch {
    return undefined;
  }
}

function requireByteInput(input: unknown): InspectedByteView {
  const inspected = inspectByteView(input);
  if (inspected === undefined) {
    throw new TypeError("input must be a genuine Uint8Array backed by non-shared memory");
  }
  return inspected;
}

function assertTotalByteLimit(
  byteLength: number,
  limits: NormalizedJsonLimits,
  line?: number,
): void {
  if (byteLength > limits.maxBytes) {
    fail("byte-limit", limits, line);
  }
}

function decodeFatalUtf8(
  input: Uint8Array,
  limits: NormalizedJsonLimits,
  line?: number,
): string {
  let decoded: string;
  try {
    decoded = new TextDecoder("utf-8", {
      fatal: true,
      // Preserve rather than silently strip a BOM so the explicit rejection
      // below remains visible and consistent across JSON and NDJSON.
      ignoreBOM: true,
    }).decode(input);
  } catch {
    fail("invalid-utf8", limits, line);
  }
  if (decoded.charCodeAt(0) === 0xfeff) {
    fail("utf8-bom", limits, line);
  }
  return decoded;
}

type ObjectState = "key-or-end" | "colon" | "value" | "comma-or-end";
type ArrayState = "value-or-end" | "comma-or-end";

interface ObjectFrame {
  readonly kind: "object";
  state: ObjectState;
  allowEnd: boolean;
  readonly keys: Set<string>;
}

interface ArrayFrame {
  readonly kind: "array";
  state: ArrayState;
  allowEnd: boolean;
  items: number;
}

type JsonFrame = ObjectFrame | ArrayFrame;

interface Scanner {
  readonly source: string;
  readonly limits: NormalizedJsonLimits;
  readonly line: number | undefined;
  readonly frames: JsonFrame[];
  index: number;
  tokens: number;
  objectKeys: number;
  rootComplete: boolean;
}

function isJsonWhitespace(code: number): boolean {
  return code === 0x20 || code === 0x09 || code === 0x0a || code === 0x0d;
}

function skipWhitespace(scanner: Scanner): void {
  while (
    scanner.index < scanner.source.length
    && isJsonWhitespace(scanner.source.charCodeAt(scanner.index))
  ) {
    scanner.index += 1;
  }
}

function consumeToken(scanner: Scanner): void {
  scanner.tokens += 1;
  if (scanner.tokens > scanner.limits.maxTokens) {
    fail("token-limit", scanner.limits, scanner.line);
  }
}

function consumePunctuation(scanner: Scanner, expected: string): void {
  if (scanner.source[scanner.index] !== expected) {
    fail("invalid-json", scanner.limits, scanner.line);
  }
  consumeToken(scanner);
  scanner.index += 1;
}

function decodedStringUnit(scanner: Scanner, count: number): void {
  if (count > scanner.limits.maxDecodedStringLength) {
    fail("decoded-string-limit", scanner.limits, scanner.line);
  }
}

function consumeDecodedCodeUnit(
  scanner: Scanner,
  codeUnit: number,
  state: { pendingHighSurrogate: boolean },
): void {
  const isHigh = codeUnit >= 0xd800 && codeUnit <= 0xdbff;
  const isLow = codeUnit >= 0xdc00 && codeUnit <= 0xdfff;
  if (state.pendingHighSurrogate) {
    if (!isLow) {
      fail("invalid-unicode", scanner.limits, scanner.line);
    }
    state.pendingHighSurrogate = false;
    return;
  }
  if (isLow) {
    fail("invalid-unicode", scanner.limits, scanner.line);
  }
  state.pendingHighSurrogate = isHigh;
}

interface ScannedString {
  readonly nextIndex: number;
  readonly decoded?: string;
}

function hexValue(code: number): number {
  if (code >= 0x30 && code <= 0x39) return code - 0x30;
  if (code >= 0x41 && code <= 0x46) return code - 0x41 + 10;
  if (code >= 0x61 && code <= 0x66) return code - 0x61 + 10;
  return -1;
}

function scanString(scanner: Scanner, capture: boolean): ScannedString {
  const { source, limits, line } = scanner;
  let index = scanner.index + 1;
  let decodedUnits = 0;
  let segmentStart = index;
  const chunks: string[] | undefined = capture ? [] : undefined;
  const unicodeState = { pendingHighSurrogate: false };

  while (index < source.length) {
    const code = source.charCodeAt(index);
    if (code === 0x22) {
      if (unicodeState.pendingHighSurrogate) {
        fail("invalid-unicode", limits, line);
      }
      if (chunks !== undefined) chunks.push(source.slice(segmentStart, index));
      return {
        nextIndex: index + 1,
        ...(chunks === undefined ? {} : { decoded: chunks.join("") }),
      };
    }
    if (code < 0x20) {
      fail("invalid-json", limits, line);
    }
    if (code !== 0x5c) {
      consumeDecodedCodeUnit(scanner, code, unicodeState);
      decodedUnits += 1;
      decodedStringUnit(scanner, decodedUnits);
      index += 1;
      continue;
    }

    if (chunks !== undefined) chunks.push(source.slice(segmentStart, index));
    index += 1;
    if (index >= source.length) fail("invalid-json", limits, line);

    const escape = source.charCodeAt(index);
    let decodedEscape: string;
    switch (escape) {
      case 0x22:
        decodedEscape = '"';
        index += 1;
        break;
      case 0x5c:
        decodedEscape = "\\";
        index += 1;
        break;
      case 0x2f:
        decodedEscape = "/";
        index += 1;
        break;
      case 0x62:
        decodedEscape = "\b";
        index += 1;
        break;
      case 0x66:
        decodedEscape = "\f";
        index += 1;
        break;
      case 0x6e:
        decodedEscape = "\n";
        index += 1;
        break;
      case 0x72:
        decodedEscape = "\r";
        index += 1;
        break;
      case 0x74:
        decodedEscape = "\t";
        index += 1;
        break;
      case 0x75: {
        if (index + 4 >= source.length) fail("invalid-json", limits, line);
        let value = 0;
        for (let offset = 1; offset <= 4; offset += 1) {
          const digit = hexValue(source.charCodeAt(index + offset));
          if (digit < 0) fail("invalid-json", limits, line);
          value = (value * 16) + digit;
        }
        decodedEscape = String.fromCharCode(value);
        index += 5;
        break;
      }
      default:
        fail("invalid-json", limits, line);
    }

    decodedUnits += 1;
    decodedStringUnit(scanner, decodedUnits);
    consumeDecodedCodeUnit(
      scanner,
      decodedEscape.charCodeAt(0),
      unicodeState,
    );
    if (chunks !== undefined) chunks.push(decodedEscape);
    segmentStart = index;
  }

  fail("invalid-json", limits, line);
}

function isDigit(code: number): boolean {
  return code >= 0x30 && code <= 0x39;
}

function consumeNumberCharacter(scanner: Scanner, start: number): void {
  scanner.index += 1;
  if (scanner.index - start > scanner.limits.maxNumericTokenLength) {
    fail("numeric-token-limit", scanner.limits, scanner.line);
  }
}

function scanNumber(scanner: Scanner): void {
  const start = scanner.index;
  const { source, limits, line } = scanner;

  if (source.charCodeAt(scanner.index) === 0x2d) {
    consumeNumberCharacter(scanner, start);
  }
  if (scanner.index >= source.length) fail("invalid-json", limits, line);

  const firstIntegerCode = source.charCodeAt(scanner.index);
  if (firstIntegerCode === 0x30) {
    consumeNumberCharacter(scanner, start);
  } else if (firstIntegerCode >= 0x31 && firstIntegerCode <= 0x39) {
    do {
      consumeNumberCharacter(scanner, start);
    } while (
      scanner.index < source.length
      && isDigit(source.charCodeAt(scanner.index))
    );
  } else {
    fail("invalid-json", limits, line);
  }

  if (source.charCodeAt(scanner.index) === 0x2e) {
    consumeNumberCharacter(scanner, start);
    if (!isDigit(source.charCodeAt(scanner.index))) fail("invalid-json", limits, line);
    do {
      consumeNumberCharacter(scanner, start);
    } while (
      scanner.index < source.length
      && isDigit(source.charCodeAt(scanner.index))
    );
  }

  const exponent = source.charCodeAt(scanner.index);
  if (exponent === 0x65 || exponent === 0x45) {
    consumeNumberCharacter(scanner, start);
    const sign = source.charCodeAt(scanner.index);
    if (sign === 0x2b || sign === 0x2d) {
      consumeNumberCharacter(scanner, start);
    }
    if (!isDigit(source.charCodeAt(scanner.index))) fail("invalid-json", limits, line);
    do {
      consumeNumberCharacter(scanner, start);
    } while (
      scanner.index < source.length
      && isDigit(source.charCodeAt(scanner.index))
    );
  }

  const numericToken = source.slice(start, scanner.index);
  if (!Number.isFinite(Number(numericToken))) {
    fail("number-range", limits, line);
  }
}

function scanLiteral(scanner: Scanner, literal: "true" | "false" | "null"): void {
  if (!scanner.source.startsWith(literal, scanner.index)) {
    fail("invalid-json", scanner.limits, scanner.line);
  }
  scanner.index += literal.length;
}

function pushFrame(scanner: Scanner, frame: JsonFrame): void {
  if (scanner.frames.length + 1 > scanner.limits.maxDepth) {
    fail("depth-limit", scanner.limits, scanner.line);
  }
  scanner.frames.push(frame);
}

function scanValue(scanner: Scanner): void {
  const code = scanner.source.charCodeAt(scanner.index);
  consumeToken(scanner);
  if (code === 0x7b) {
    scanner.index += 1;
    pushFrame(scanner, {
      kind: "object",
      state: "key-or-end",
      allowEnd: true,
      keys: new Set<string>(),
    });
    return;
  }
  if (code === 0x5b) {
    scanner.index += 1;
    pushFrame(scanner, {
      kind: "array",
      state: "value-or-end",
      allowEnd: true,
      items: 0,
    });
    return;
  }
  if (code === 0x22) {
    scanner.index = scanString(scanner, false).nextIndex;
    return;
  }
  if (code === 0x74) {
    scanLiteral(scanner, "true");
    return;
  }
  if (code === 0x66) {
    scanLiteral(scanner, "false");
    return;
  }
  if (code === 0x6e) {
    scanLiteral(scanner, "null");
    return;
  }
  if (code === 0x2d || isDigit(code)) {
    scanNumber(scanner);
    return;
  }
  fail("invalid-json", scanner.limits, scanner.line);
}

function completeFrame(scanner: Scanner): void {
  scanner.frames.pop();
}

function scanObject(scanner: Scanner, frame: ObjectFrame): void {
  const { source, limits, line } = scanner;
  switch (frame.state) {
    case "key-or-end": {
      if (source[scanner.index] === "}") {
        if (!frame.allowEnd) fail("invalid-json", limits, line);
        consumePunctuation(scanner, "}");
        completeFrame(scanner);
        return;
      }
      if (source[scanner.index] !== '"') fail("invalid-json", limits, line);
      consumeToken(scanner);
      const scanned = scanString(scanner, true);
      scanner.index = scanned.nextIndex;
      scanner.objectKeys += 1;
      if (scanner.objectKeys > limits.maxObjectKeys) {
        fail("object-key-limit", limits, line);
      }
      const key = scanned.decoded;
      if (key === undefined) throw new Error("internal bounded JSON key invariant failed");
      if (frame.keys.has(key)) fail("duplicate-key", limits, line);
      frame.keys.add(key);
      frame.state = "colon";
      return;
    }
    case "colon":
      consumePunctuation(scanner, ":");
      frame.state = "value";
      return;
    case "value":
      frame.state = "comma-or-end";
      scanValue(scanner);
      return;
    case "comma-or-end":
      if (source[scanner.index] === ",") {
        consumePunctuation(scanner, ",");
        frame.state = "key-or-end";
        frame.allowEnd = false;
        return;
      }
      if (source[scanner.index] === "}") {
        consumePunctuation(scanner, "}");
        completeFrame(scanner);
        return;
      }
      fail("invalid-json", limits, line);
  }
}

function scanArray(scanner: Scanner, frame: ArrayFrame): void {
  const { source, limits, line } = scanner;
  switch (frame.state) {
    case "value-or-end":
      if (source[scanner.index] === "]") {
        if (!frame.allowEnd) fail("invalid-json", limits, line);
        consumePunctuation(scanner, "]");
        completeFrame(scanner);
        return;
      }
      frame.items += 1;
      if (frame.items > limits.maxArrayItems) {
        fail("array-item-limit", limits, line);
      }
      frame.state = "comma-or-end";
      scanValue(scanner);
      return;
    case "comma-or-end":
      if (source[scanner.index] === ",") {
        consumePunctuation(scanner, ",");
        frame.state = "value-or-end";
        frame.allowEnd = false;
        return;
      }
      if (source[scanner.index] === "]") {
        consumePunctuation(scanner, "]");
        completeFrame(scanner);
        return;
      }
      fail("invalid-json", limits, line);
  }
}

function validateJsonGrammar(
  source: string,
  limits: NormalizedJsonLimits,
  line?: number,
): void {
  const scanner: Scanner = {
    source,
    limits,
    line,
    frames: [],
    index: 0,
    tokens: 0,
    objectKeys: 0,
    rootComplete: false,
  };

  while (true) {
    skipWhitespace(scanner);
    if (scanner.frames.length === 0) {
      if (!scanner.rootComplete) {
        if (scanner.index >= source.length) fail("invalid-json", limits, line);
        scanner.rootComplete = true;
        scanValue(scanner);
        continue;
      }
      if (scanner.index !== source.length) fail("invalid-json", limits, line);
      return;
    }
    if (scanner.index >= source.length) fail("invalid-json", limits, line);

    const frame = scanner.frames[scanner.frames.length - 1];
    if (frame === undefined) throw new Error("internal bounded JSON frame invariant failed");
    if (frame.kind === "object") {
      scanObject(scanner, frame);
    } else {
      scanArray(scanner, frame);
    }
  }
}

function parseJsonBytes(
  input: Uint8Array,
  limits: NormalizedJsonLimits,
  line?: number,
): unknown {
  assertTotalByteLimit(input.byteLength, limits, line);
  const source = decodeFatalUtf8(input, limits, line);
  validateJsonGrammar(source, limits, line);
  try {
    return freezeJsonValue(JSON.parse(source) as unknown);
  } catch {
    // The independent scanner is the authority. This catch keeps diagnostics
    // constant-safe if the platform parser nevertheless rejects the value.
    fail("invalid-json", limits, line);
  }
}

function freezeJsonValue(value: unknown): unknown {
  if (value === null || typeof value !== "object") return value;

  const pending: object[] = [value];
  const visited = new WeakSet<object>();
  while (pending.length > 0) {
    const current = pending.pop();
    if (current === undefined || visited.has(current)) continue;
    visited.add(current);

    const descriptors = Object.getOwnPropertyDescriptors(current);
    for (const descriptor of Object.values(descriptors)) {
      if (!("value" in descriptor)) continue;
      const child = descriptor.value as unknown;
      if (child !== null && typeof child === "object") {
        pending.push(child);
      }
    }
    Object.freeze(current);
  }
  return value;
}

/** Parse exactly one byte-bounded, fatal-UTF-8 JSON value. */
export function parseBoundedJson(
  input: Uint8Array,
  limits: BoundedJsonLimits,
): unknown {
  const normalized = normalizeJsonLimits(limits);
  const inspected = requireByteInput(input);
  return parseJsonBytes(inspected.view, normalized);
}

function isBlankNdjsonLine(input: Uint8Array, start: number, end: number): boolean {
  if (start === end) return true;
  for (let index = start; index < end; index += 1) {
    const byte = input[index];
    if (byte !== 0x20 && byte !== 0x09 && byte !== 0x0d) return false;
  }
  return true;
}

/**
 * Parse a byte-bounded NDJSON document.
 *
 * A single final LF/CRLF is a terminator rather than an empty record. All other
 * empty or ASCII-whitespace-only records are rejected.
 */
export function parseBoundedNdjson(
  input: Uint8Array,
  limits: BoundedNdjsonLimits,
): readonly unknown[] {
  const normalized = normalizeNdjsonLimits(limits);
  const inspected = requireByteInput(input);
  const safeInput = inspected.view;
  assertTotalByteLimit(inspected.byteLength, normalized);
  if (inspected.byteLength === 0) return Object.freeze([]);

  const items: unknown[] = [];
  let lineStart = 0;
  let line = 1;

  for (let cursor = 0; cursor <= inspected.byteLength; cursor += 1) {
    const atEnd = cursor === inspected.byteLength;
    if (!atEnd && safeInput[cursor] !== 0x0a) continue;
    if (atEnd && lineStart === inspected.byteLength) break;

    let lineEnd = cursor;
    if (
      !atEnd
      && lineEnd > lineStart
      && safeInput[lineEnd - 1] === 0x0d
    ) {
      lineEnd -= 1;
    }
    const lineBytes = lineEnd - lineStart;
    if (lineBytes > normalized.maxLineBytes) {
      fail("line-byte-limit", normalized, line);
    }
    if (isBlankNdjsonLine(safeInput, lineStart, lineEnd)) {
      fail("blank-line", normalized, line);
    }
    if (items.length >= normalized.maxItems) {
      fail("item-limit", normalized, line);
    }

    const record = safeInput.subarray(lineStart, lineEnd);
    items.push(parseJsonBytes(record, normalized, line));
    if (atEnd) break;
    lineStart = cursor + 1;
    line += 1;
  }

  return Object.freeze(items);
}

/** A Node stream, async generator, or in-memory sequence of byte chunks. */
export type ByteChunkSource =
  | AsyncIterable<Uint8Array>
  | Iterable<Uint8Array>;

async function collectBoundedBytes(
  source: ByteChunkSource,
  limits: NormalizedJsonLimits,
): Promise<Uint8Array> {
  let collected = new Uint8Array(0);
  let totalBytes = 0;
  let chunksAccepted = 0;
  let collectorFailure: BoundedInputError | undefined;

  const rejectCollectorInput = (code: BoundedInputErrorCode): never => {
    const error = new BoundedInputError(
      code,
      limits.maxDiagnosticSnippetLength,
    );
    collectorFailure = error;
    throw error;
  };

  const ensureCapacity = (required: number): void => {
    if (required <= collected.byteLength) return;
    let capacity = collected.byteLength === 0
      ? Math.min(limits.maxBytes, Math.max(required, 1_024))
      : collected.byteLength;
    while (capacity < required) {
      capacity = Math.min(
        limits.maxBytes,
        Math.max(required, capacity * 2),
      );
    }
    const expanded = new Uint8Array(capacity);
    if (totalBytes > 0) {
      expanded.set(collected.subarray(0, totalBytes));
    }
    collected = expanded;
  };

  const acceptChunk = (candidate: unknown): void => {
    if (chunksAccepted >= MAX_BOUNDED_INPUT_CHUNKS) {
      return rejectCollectorInput("chunk-limit");
    }
    const inspected = inspectByteView(candidate);
    if (inspected === undefined) {
      return rejectCollectorInput("invalid-chunk");
    }
    if (inspected.byteLength === 0) {
      return rejectCollectorInput("invalid-chunk");
    }
    if (inspected.byteLength > limits.maxBytes - totalBytes) {
      return rejectCollectorInput("byte-limit");
    }

    // Copy only after the checked cumulative bound. This prevents caller
    // mutation between asynchronous yields from changing the collected input.
    // A single geometric slab also prevents per-chunk object amplification.
    ensureCapacity(totalBytes + inspected.byteLength);
    collected.set(inspected.view, totalBytes);
    totalBytes += inspected.byteLength;
    chunksAccepted += 1;
  };

  try {
    if (isProxy(source)) fail("input-stream", limits);
    const asyncFactory = (source as AsyncIterable<Uint8Array>)[Symbol.asyncIterator];
    if (typeof asyncFactory === "function") {
      for await (const candidate of source as AsyncIterable<Uint8Array>) {
        acceptChunk(candidate);
      }
    } else {
      // Do not use `for await` for synchronous iterables: the language's
      // async-from-sync adapter probes each value for `.then`, which would
      // trigger traps on a proxied chunk before our brand check.
      for (const candidate of source as Iterable<Uint8Array>) {
        acceptChunk(candidate);
      }
    }
  } catch (error) {
    if (collectorFailure !== undefined && error === collectorFailure) {
      throw collectorFailure;
    }
    fail("input-stream", limits);
  }

  return collected.subarray(0, totalBytes);
}

/** Collect and parse byte-bounded JSON from a Node stream or other chunk source. */
export async function readBoundedJson(
  source: ByteChunkSource,
  limits: BoundedJsonLimits,
): Promise<unknown> {
  const normalized = normalizeJsonLimits(limits);
  const input = await collectBoundedBytes(source, normalized);
  return parseJsonBytes(input, normalized);
}

/** Collect and parse byte-bounded NDJSON from a Node stream or other chunk source. */
export async function readBoundedNdjson(
  source: ByteChunkSource,
  limits: BoundedNdjsonLimits,
): Promise<readonly unknown[]> {
  const normalized = normalizeNdjsonLimits(limits);
  const input = await collectBoundedBytes(source, normalized);
  return parseBoundedNdjson(input, normalized);
}
