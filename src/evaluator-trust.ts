import {
  createPublicKey,
  verify as verifySignature,
  type KeyObject,
} from "node:crypto";
import { z } from "zod";
import {
  parseAssessmentContext,
  type AssessmentContext,
} from "./assessment-context.js";
import {
  contractDigestSchema,
  contractSlugSchema,
  contractTimestampSchema,
  deepFreezeContract,
  domainSeparatedDigest,
  fingerprintNormalizedEvaluatorEvidence,
  normalizeEvaluatorEvidence,
  normalizedEvaluatorEvidenceSigningBytes,
  rubricIdentitySchema,
  snapshotBoundedContractInput,
  type DeepReadonly,
  type EvaluatorEvidence,
} from "./evidence.js";

const safeDurationSchema = z.number()
  .int()
  .min(0)
  .max(365 * 24 * 60 * 60 * 1_000);

const canonicalBase64UrlSchema = z.string()
  .min(1)
  .max(256)
  .regex(/^[A-Za-z0-9_-]+$/, "must be unpadded canonical base64url");

const evaluatorTrustKeySchema = z.object({
  keyId: contractSlugSchema,
  purpose: z.literal("evaluator-evidence"),
  algorithm: z.literal("ed25519"),
  publicKeySpki: canonicalBase64UrlSchema,
  evaluatorId: contractSlugSchema,
  producerId: contractSlugSchema,
  authorizedRubricVersions: z.array(rubricIdentitySchema).min(1).max(64),
  authorizedCalibrationDigests: z.array(contractDigestSchema).min(1).max(64),
  validFrom: contractTimestampSchema,
  validUntil: contractTimestampSchema,
}).strict();

const evaluatorRevocationSchema = z.object({
  keyId: contractSlugSchema,
  revokedAt: contractTimestampSchema,
  reasonCode: contractSlugSchema,
}).strict();

export const evaluatorTrustSnapshotSchema = z.object({
  version: z.literal("tasc-evaluator-trust-snapshot-v1"),
  freshness: z.object({
    maximumEvidenceAgeMs: safeDurationSchema,
    maximumFutureSkewMs: safeDurationSchema.max(24 * 60 * 60 * 1_000),
  }).strict(),
  keys: z.array(evaluatorTrustKeySchema).min(1).max(128),
  revocations: z.array(evaluatorRevocationSchema).max(256),
}).strict();

type MutableEvaluatorTrustSnapshot = z.infer<typeof evaluatorTrustSnapshotSchema>;
export type EvaluatorTrustSnapshot = DeepReadonly<MutableEvaluatorTrustSnapshot>;

export type EvaluatorTrustStatus =
  | "trusted"
  | "context-mismatch"
  | "unknown-key"
  | "revoked"
  | "stale"
  | "future-dated"
  | "key-not-yet-valid"
  | "key-expired"
  | "malformed-signature"
  | "invalid-signature"
  | "unauthorized-evidence";

export interface EvaluatorEvidenceVerification {
  readonly status: EvaluatorTrustStatus;
  readonly trusted: boolean;
  readonly evidence: EvaluatorEvidence;
  readonly evidenceDigest: string;
  readonly assessedAt: string;
  readonly assessmentContextDigest: string;
  readonly operatorTrustPolicySnapshotDigest: string;
  readonly evaluatorRevocationSnapshotDigest: string;
  readonly keyId: string;
  readonly reason: string;
}

const authenticVerificationReceipts = new WeakSet<object>();

function unique(values: readonly string[], label: string): void {
  const seen = new Set<string>();
  for (const value of values) {
    if (seen.has(value)) throw new Error(`duplicate ${label} "${value}"`);
    seen.add(value);
  }
}

function decodeCanonicalBase64Url(value: string): Buffer | undefined {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) return undefined;
  try {
    const decoded = Buffer.from(value, "base64url");
    if (decoded.toString("base64url") !== value) return undefined;
    return decoded;
  } catch {
    return undefined;
  }
}

function importEd25519PublicKey(encoded: string): KeyObject | undefined {
  const bytes = decodeCanonicalBase64Url(encoded);
  if (bytes === undefined) return undefined;
  try {
    const key = createPublicKey({ key: bytes, type: "spki", format: "der" });
    if (key.asymmetricKeyType !== "ed25519") return undefined;
    const canonical = key.export({ type: "spki", format: "der" });
    return Buffer.isBuffer(canonical) && canonical.equals(bytes) ? key : undefined;
  } catch {
    return undefined;
  }
}

function assertSnapshotSemantics(snapshot: MutableEvaluatorTrustSnapshot): void {
  unique(snapshot.keys.map(({ keyId }) => keyId), "evaluator key id");
  unique(snapshot.revocations.map(({ keyId }) => keyId), "revoked evaluator key id");
  const publicKeys = new Set<string>();
  for (const key of snapshot.keys) {
    unique(key.authorizedRubricVersions, `rubric authorization for key ${key.keyId}`);
    unique(
      key.authorizedCalibrationDigests,
      `calibration authorization for key ${key.keyId}`,
    );
    if (Date.parse(key.validUntil) <= Date.parse(key.validFrom)) {
      throw new Error(`evaluator key "${key.keyId}" validity end must be after its start`);
    }
    if (importEd25519PublicKey(key.publicKeySpki) === undefined) {
      throw new Error(`evaluator key "${key.keyId}" is not a canonical Ed25519 SPKI key`);
    }
    if (publicKeys.has(key.publicKeySpki)) {
      throw new Error("duplicate evaluator public key material is not allowed");
    }
    publicKeys.add(key.publicKeySpki);
  }
}

export function parseEvaluatorTrustSnapshot(input: unknown): EvaluatorTrustSnapshot {
  const inputSnapshot = snapshotBoundedContractInput(input);
  const snapshot = evaluatorTrustSnapshotSchema.parse(inputSnapshot);
  assertSnapshotSemantics(snapshot);
  return deepFreezeContract(snapshot);
}

/** Digest the operator-controlled keys and freshness policy, excluding revocations. */
export function fingerprintNormalizedEvaluatorTrustPolicy(
  snapshot: EvaluatorTrustSnapshot,
): string {
  return domainSeparatedDigest("tasc/operator-evaluator-trust-policy-snapshot/v1", {
    version: snapshot.version,
    freshness: snapshot.freshness,
    keys: snapshot.keys,
  });
}

export function fingerprintEvaluatorTrustPolicy(snapshot: unknown): string {
  return fingerprintNormalizedEvaluatorTrustPolicy(
    parseEvaluatorTrustSnapshot(snapshot),
  );
}

/** Digest the separately versioned revocation view bound into an assessment context. */
export function fingerprintNormalizedEvaluatorRevocations(
  snapshot: EvaluatorTrustSnapshot,
): string {
  return domainSeparatedDigest("tasc/evaluator-revocation-snapshot/v1", {
    version: snapshot.version,
    revocations: snapshot.revocations,
  });
}

export function fingerprintEvaluatorRevocations(snapshot: unknown): string {
  return fingerprintNormalizedEvaluatorRevocations(
    parseEvaluatorTrustSnapshot(snapshot),
  );
}

function verificationResult(
  status: EvaluatorTrustStatus,
  reason: string,
  evidence: EvaluatorEvidence,
  context: AssessmentContext,
): EvaluatorEvidenceVerification {
  const result = deepFreezeContract({
    status,
    trusted: status === "trusted",
    evidence,
    evidenceDigest: fingerprintNormalizedEvaluatorEvidence(evidence),
    assessedAt: context.asOf,
    assessmentContextDigest: context.contextDigest,
    operatorTrustPolicySnapshotDigest: context.operatorTrustPolicySnapshotDigest,
    evaluatorRevocationSnapshotDigest: context.evaluatorRevocationSnapshotDigest,
    keyId: evidence.keyId,
    reason,
  });
  authenticVerificationReceipts.add(result);
  return result;
}

/**
 * Join admission is intentionally identity-based: a structurally compatible
 * producer object is not a receipt emitted by this process's verifier.
 */
export function isAuthenticEvaluatorEvidenceVerification(
  value: unknown,
): value is EvaluatorEvidenceVerification {
  return (
    value !== null
    && typeof value === "object"
    && authenticVerificationReceipts.has(value)
  );
}

/**
 * Derive evidence trust from an explicit operator snapshot and assessment time.
 * No producer-supplied trust flag and no process wall clock participates.
 */
export function verifyEvaluatorEvidence(
  evidence: EvaluatorEvidence,
  trustSnapshot: EvaluatorTrustSnapshot,
  assessmentContext: AssessmentContext,
): EvaluatorEvidenceVerification {
  const normalizedEvidence = normalizeEvaluatorEvidence(evidence);
  const normalizedTrustSnapshot = parseEvaluatorTrustSnapshot(trustSnapshot);
  const normalizedAssessmentContext = parseAssessmentContext(assessmentContext);

  if (
    fingerprintNormalizedEvaluatorTrustPolicy(normalizedTrustSnapshot)
      !== normalizedAssessmentContext.operatorTrustPolicySnapshotDigest
    || fingerprintNormalizedEvaluatorRevocations(normalizedTrustSnapshot)
      !== normalizedAssessmentContext.evaluatorRevocationSnapshotDigest
  ) {
    return verificationResult(
      "context-mismatch",
      "assessment context does not bind the supplied trust and revocation snapshots",
      normalizedEvidence,
      normalizedAssessmentContext,
    );
  }

  const key = normalizedTrustSnapshot.keys.find(
    ({ keyId }) => keyId === normalizedEvidence.keyId,
  );
  if (key === undefined) {
    return verificationResult(
      "unknown-key",
      "evidence key is absent from the operator trust snapshot",
      normalizedEvidence,
      normalizedAssessmentContext,
    );
  }

  const signature = decodeCanonicalBase64Url(normalizedEvidence.signature);
  if (signature === undefined || signature.length !== 64) {
    return verificationResult(
      "malformed-signature",
      "evidence signature is not a canonical 64-byte Ed25519 signature",
      normalizedEvidence,
      normalizedAssessmentContext,
    );
  }
  const publicKey = importEd25519PublicKey(key.publicKeySpki);
  if (publicKey === undefined) {
    return verificationResult(
      "malformed-signature",
      "trusted evaluator key material is malformed",
      normalizedEvidence,
      normalizedAssessmentContext,
    );
  }
  const validSignature = verifySignature(
    null,
    normalizedEvaluatorEvidenceSigningBytes(normalizedEvidence),
    publicKey,
    signature,
  );
  if (!validSignature) {
    return verificationResult(
      "invalid-signature",
      "Ed25519 signature does not cover the canonical evidence",
      normalizedEvidence,
      normalizedAssessmentContext,
    );
  }

  const asOf = Date.parse(normalizedAssessmentContext.asOf);
  const revocation = normalizedTrustSnapshot.revocations.find(
    ({ keyId, revokedAt }) =>
      keyId === normalizedEvidence.keyId && Date.parse(revokedAt) <= asOf,
  );
  if (revocation !== undefined) {
    return verificationResult(
      "revoked",
      `evidence key was revoked: ${revocation.reasonCode}`,
      normalizedEvidence,
      normalizedAssessmentContext,
    );
  }

  const producedAt = Date.parse(normalizedEvidence.producedAt);
  if (
    producedAt - asOf
      > normalizedTrustSnapshot.freshness.maximumFutureSkewMs
  ) {
    return verificationResult(
      "future-dated",
      "evidence production time exceeds the allowed assessment-time skew",
      normalizedEvidence,
      normalizedAssessmentContext,
    );
  }
  if (
    asOf - producedAt
      > normalizedTrustSnapshot.freshness.maximumEvidenceAgeMs
  ) {
    return verificationResult(
      "stale",
      "evidence exceeds the operator freshness window",
      normalizedEvidence,
      normalizedAssessmentContext,
    );
  }
  if (producedAt < Date.parse(key.validFrom)) {
    return verificationResult(
      "key-not-yet-valid",
      "evidence predates the trusted key validity interval",
      normalizedEvidence,
      normalizedAssessmentContext,
    );
  }
  if (producedAt > Date.parse(key.validUntil)) {
    return verificationResult(
      "key-expired",
      "evidence postdates the trusted key validity interval",
      normalizedEvidence,
      normalizedAssessmentContext,
    );
  }

  const authorized = key.purpose === "evaluator-evidence"
    && key.evaluatorId === normalizedEvidence.evaluator.evaluatorId
    && key.producerId === normalizedEvidence.evaluator.producer.producerId
    && key.authorizedRubricVersions.includes(normalizedEvidence.evaluator.rubricVersion)
    && key.authorizedCalibrationDigests.includes(
      normalizedEvidence.evaluator.calibrationDigest,
    );
  if (!authorized) {
    return verificationResult(
      "unauthorized-evidence",
      "trusted key is not authorized for this evaluator, producer, rubric, or calibration",
      normalizedEvidence,
      normalizedAssessmentContext,
    );
  }

  return verificationResult(
    "trusted",
    "canonical Ed25519 evidence is current and authorized",
    normalizedEvidence,
    normalizedAssessmentContext,
  );
}
