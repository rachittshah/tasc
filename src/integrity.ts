import { createHash } from "node:crypto";
import { canonicalJson } from "./determinism.js";

/**
 * Compatibility alias for the versioned RFC 8785 JCS identity format.
 *
 * `stableJson` retains its legacy name for callers, but its v1 semantics are exactly
 * `canonicalJson` with `CANONICAL_JSON_VERSION === "rfc8785-jcs-v1"`.
 */
export function stableJson(value: unknown): string {
  return canonicalJson(value);
}

export function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}
