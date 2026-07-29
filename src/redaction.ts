import { isNativeError, isProxy } from "node:util/types";

export const PERSISTED_ERROR_VERSION = "tasc-persisted-error-v1" as const;

export type PersistedErrorCategory =
  | "authentication"
  | "authorization"
  | "timeout"
  | "rate-limit"
  | "transport"
  | "invalid-response"
  | "cancelled"
  | "internal"
  | "unknown";

export interface PersistedError {
  readonly version: typeof PERSISTED_ERROR_VERSION;
  readonly category: PersistedErrorCategory;
  readonly message: string;
  readonly status: number | null;
  readonly runtime: string | null;
  readonly requestId: string | null;
}

const CONSTANT_SAFE_MESSAGES = Object.freeze({
  authentication: "Inference runtime authentication failed.",
  authorization: "Inference runtime authorization failed.",
  timeout: "Inference request timed out.",
  "rate-limit": "Inference runtime rate limit was reached.",
  transport: "Inference transport failed.",
  "invalid-response": "Inference runtime returned an invalid response.",
  cancelled: "Inference request was cancelled.",
  internal: "Inference runtime failed.",
  unknown: "Inference request failed.",
} satisfies Readonly<Record<PersistedErrorCategory, string>>);

const CATEGORIES = new Set<PersistedErrorCategory>(
  Object.keys(CONSTANT_SAFE_MESSAGES) as PersistedErrorCategory[],
);
const ALLOWLISTED_INPUT_KEYS = [
  "category",
  "status",
  "runtime",
  "requestId",
] as const;
const MAX_SAFE_METADATA_TEXT = 128;
const SAFE_METADATA_PATTERN =
  /^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$/;
const OBVIOUS_CREDENTIAL_PATTERN =
  /(?:\b(?:bearer|basic)\b)|(?:api[-_ ]?key)|(?:password|passwd|secret)|(?:\bsk-[A-Za-z0-9_-]{8,}\b)/i;

type AllowlistedInputKey = typeof ALLOWLISTED_INPUT_KEYS[number];
type MetadataSnapshot = Partial<Record<AllowlistedInputKey, unknown>>;

function genericPersistedError(): PersistedError {
  return Object.freeze({
    version: PERSISTED_ERROR_VERSION,
    category: "unknown",
    message: CONSTANT_SAFE_MESSAGES.unknown,
    status: null,
    runtime: null,
    requestId: null,
  });
}

/**
 * Take a four-field, data-descriptor-only snapshot. This deliberately does not
 * enumerate the input: provider-owned message, stack, cause, headers, URL,
 * body, and JSON properties are neither read nor copied.
 */
function snapshotAllowlistedMetadata(input: unknown): MetadataSnapshot | null {
  if (input === null || typeof input !== "object") return null;

  try {
    // Proxy traps can run arbitrary provider code. Node can identify a proxy
    // without invoking those traps, so a proxy is never inspected.
    if (isProxy(input) || isNativeError(input)) return null;
    const prototype = Reflect.getPrototypeOf(input);
    if (prototype !== Object.prototype && prototype !== null) return null;

    const snapshot: MetadataSnapshot = Object.create(null);
    for (const key of ALLOWLISTED_INPUT_KEYS) {
      const descriptor = Reflect.getOwnPropertyDescriptor(input, key);
      if (descriptor === undefined) continue;
      if (!descriptor.enumerable || !Object.hasOwn(descriptor, "value")) {
        return null;
      }
      snapshot[key] = descriptor.value;
    }
    return snapshot;
  } catch {
    return null;
  }
}

function sanitizeCategory(value: unknown): PersistedErrorCategory {
  return typeof value === "string" && CATEGORIES.has(value as PersistedErrorCategory)
    ? value as PersistedErrorCategory
    : "unknown";
}

function sanitizeStatus(value: unknown): number | null {
  return typeof value === "number"
      && Number.isInteger(value)
      && value >= 100
      && value <= 599
    ? value
    : null;
}

function sanitizeMetadataText(value: unknown): string | null {
  if (
    typeof value !== "string"
    || value.length < 1
    || value.length > MAX_SAFE_METADATA_TEXT
    || value.trim() !== value
    || !SAFE_METADATA_PATTERN.test(value)
    || OBVIOUS_CREDENTIAL_PATTERN.test(value)
  ) {
    return null;
  }
  return value;
}

/**
 * Convert an arbitrary runtime/provider failure into the only error shape that
 * is safe to persist. Messages are constants owned by TASC, never text derived
 * from the supplied value.
 */
export function sanitizeErrorForPersistence(input: unknown): PersistedError {
  const snapshot = snapshotAllowlistedMetadata(input);
  if (snapshot === null) return genericPersistedError();

  const category = sanitizeCategory(snapshot.category);
  return Object.freeze({
    version: PERSISTED_ERROR_VERSION,
    category,
    message: CONSTANT_SAFE_MESSAGES[category],
    status: sanitizeStatus(snapshot.status),
    runtime: sanitizeMetadataText(snapshot.runtime),
    requestId: sanitizeMetadataText(snapshot.requestId),
  });
}
