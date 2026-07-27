import { Buffer } from "node:buffer";

/** The canonical identity format used by this release. */
export const CANONICAL_JSON_VERSION = "rfc8785-jcs-v1" as const;

/**
 * Compare strings by their UTF-16 code units. This deliberately avoids locale-sensitive
 * collation so identities, ordering, and tie-breaking are portable across processes.
 */
export function compareCodeUnits(left: string, right: string): number {
  const sharedLength = Math.min(left.length, right.length);
  for (let index = 0; index < sharedLength; index += 1) {
    const difference = left.charCodeAt(index) - right.charCodeAt(index);
    if (difference !== 0) return difference;
  }
  return left.length - right.length;
}

function assertWellFormedUnicode(value: string): void {
  for (let index = 0; index < value.length; index += 1) {
    const codeUnit = value.charCodeAt(index);
    if (codeUnit < 0xd800 || codeUnit > 0xdfff) continue;
    const next = value.charCodeAt(index + 1);
    const isHighSurrogate = codeUnit <= 0xdbff;
    const hasMatchingPair = isHighSurrogate
      ? next >= 0xdc00 && next <= 0xdfff
      : false;
    if (!hasMatchingPair) {
      throw new Error("JCS only accepts I-JSON strings with valid Unicode scalar values");
    }
    index += 1;
  }
}

function isPlainJsonObject(value: object): value is Record<string, unknown> {
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function canonicalize(value: unknown, stack: Set<object>): string {
  if (value === null) return "null";
  if (typeof value === "string") {
    assertWellFormedUnicode(value);
    return JSON.stringify(value);
  }
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("JCS only accepts finite I-JSON numbers");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    if (stack.has(value)) throw new Error("JCS only accepts acyclic I-JSON values");
    stack.add(value);
    const elements: string[] = [];
    for (let index = 0; index < value.length; index += 1) {
      if (!Object.hasOwn(value, index)) {
        throw new Error("JCS only accepts JSON-compatible arrays without holes");
      }
      elements.push(canonicalize(value[index], stack));
    }
    stack.delete(value);
    return `[${elements.join(",")}]`;
  }
  if (typeof value === "object") {
    if (!isPlainJsonObject(value)) {
      throw new Error("JCS only accepts plain JSON-compatible objects");
    }
    if (Object.getOwnPropertySymbols(value).length > 0) {
      throw new Error("JCS only accepts JSON-compatible string-keyed objects");
    }
    if (stack.has(value)) throw new Error("JCS only accepts acyclic I-JSON values");
    stack.add(value);
    const fields = Object.keys(value)
      .sort(compareCodeUnits)
      .map((key) => {
        assertWellFormedUnicode(key);
        return `${JSON.stringify(key)}:${canonicalize(value[key], stack)}`;
      });
    stack.delete(value);
    return `{${fields.join(",")}}`;
  }
  throw new Error("JCS only accepts JSON-compatible I-JSON values");
}

/** Serialize an I-JSON value using RFC 8785 JSON Canonicalization Scheme semantics. */
export function canonicalJson(value: unknown): string {
  return canonicalize(value, new Set<object>());
}

/** UTF-8 bytes of the versioned JCS canonical representation. */
export function canonicalJsonBytes(value: unknown): Buffer {
  return Buffer.from(canonicalJson(value), "utf8");
}
