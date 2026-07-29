import { z } from "zod";
import {
  deepFreezeContract,
  domainSeparatedDigest,
  snapshotBoundedContractInput,
} from "./evidence.js";

const RUNTIME_INVOCATION_HTTP_LIMITS_DIGEST_DOMAIN =
  "tasc/runtime-invocation-http-limits/v1";

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

export const DEFAULT_RUNTIME_HTTP_LIMITS: Readonly<RuntimeHttpLimits> =
  Object.freeze({
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

const safePositiveInteger = (maximum: number) =>
  z.number().int().min(1).max(maximum);

/**
 * These are the stricter inference-invocation ceilings. The lower-level HTTP
 * transport supports a wider byte envelope for non-inference callers.
 */
const runtimeInvocationHttpLimitsInputSchema = z.object({
  maxRequestBytes: safePositiveInteger(1_048_576).optional(),
  maxResponseHeaderBytes: safePositiveInteger(16_384).optional(),
  maxResponseHeaders: safePositiveInteger(256).optional(),
  maxResponseBytes: safePositiveInteger(8_388_608).optional(),
  maxResponseChunks: safePositiveInteger(16_384).optional(),
  maxSecretHeaderBytes: safePositiveInteger(16_384).optional(),
  connectTimeoutMs: safePositiveInteger(30_000).optional(),
  headersTimeoutMs: safePositiveInteger(60_000).optional(),
  bodyTimeoutMs: safePositiveInteger(60_000).optional(),
  deadlineMs: safePositiveInteger(300_000).optional(),
}).strict();

/**
 * Canonicalize the complete limits object used by one inference invocation.
 * Missing fields are filled from immutable defaults before the value is
 * fingerprinted or passed across the P0/P1 boundary.
 */
export function normalizeRuntimeInvocationHttpLimits(
  input?: unknown,
): Readonly<RuntimeHttpLimits> {
  const snapshot = input === undefined
    ? Object.freeze({})
    : snapshotBoundedContractInput(input);
  const parsed = runtimeInvocationHttpLimitsInputSchema.parse(snapshot);
  return deepFreezeContract({
    ...DEFAULT_RUNTIME_HTTP_LIMITS,
    ...parsed,
  });
}

/** Fingerprint the exact normalized/defaulted inference HTTP-limits contract. */
export function fingerprintRuntimeInvocationHttpLimits(
  input?: unknown,
): string {
  return domainSeparatedDigest(
    RUNTIME_INVOCATION_HTTP_LIMITS_DIGEST_DOMAIN,
    normalizeRuntimeInvocationHttpLimits(input),
  );
}
