import {
  createPublicKey,
  verify as verifySignature,
  type KeyObject,
} from "node:crypto";
import { z } from "zod";
import {
  fingerprintAssessmentContext,
  type AssessmentContext,
} from "./assessment-context.js";
import {
  assertBoundedContractInput,
  contractDigestSchema,
  contractSlugSchema,
  contractTimestampSchema,
  deepFreezeContract,
  domainSeparatedDigest,
  evaluatorEvidenceSigningBytes,
  fingerprintEvaluatorEvidence,
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
  authorizedRubricVersions: z.array(contractSlugSchema).min(1).max(64),
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
    return key.asymmetricKeyType === "ed25519" ? key : undefined;
  } catch {
    return undefined;
  }
}

function assertSnapshotSemantics(snapshot: MutableEvaluatorTrustSnapshot): void {
  unique(snapshot.keys.map(({ keyId }) => keyId), "evaluator key id");
  unique(snapshot.revocations.map(({ keyId }) => keyId), "revoked evaluator key id");
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
  }
}

export function parseEvaluatorTrustSnapshot(input: unknown): EvaluatorTrustSnapshot {
  assertBoundedContractInput(input);
  const snapshot = evaluatorTrustSnapshotSchema.parse(input);
  assertSnapshotSemantics(snapshot);
  return deepFreezeContract(snapshot);
}

function parsedSnapshot(input: unknown): MutableEvaluatorTrustSnapshot {
  assertBoundedContractInput(input);
  const snapshot = evaluatorTrustSnapshotSchema.parse(input);
  assertSnapshotSemantics(snapshot);
  return snapshot;
}

/** Digest the operator-controlled keys and freshness policy, excluding revocations. */
export function fingerprintEvaluatorTrustPolicy(snapshot: unknown): string {
  const parsed = parsedSnapshot(snapshot);
  return domainSeparatedDigest("tasc/operator-evaluator-trust-policy-snapshot/v1", {
    version: parsed.version,
    freshness: parsed.freshness,
    keys: parsed.keys,
  });
}

/** Digest the separately versioned revocation view bound into an assessment context. */
export function fingerprintEvaluatorRevocations(snapshot: unknown): string {
  const parsed = parsedSnapshot(snapshot);
  return domainSeparatedDigest("tasc/evaluator-revocation-snapshot/v1", {
    version: parsed.version,
    revocations: parsed.revocations,
  });
}

function verificationResult(
  status: EvaluatorTrustStatus,
  reason: string,
  evidence: EvaluatorEvidence,
  context: AssessmentContext,
): EvaluatorEvidenceVerification {
  return deepFreezeContract({
    status,
    trusted: status === "trusted",
    evidence,
    evidenceDigest: fingerprintEvaluatorEvidence(evidence),
    assessedAt: context.asOf,
    assessmentContextDigest: context.contextDigest,
    operatorTrustPolicySnapshotDigest: context.operatorTrustPolicySnapshotDigest,
    evaluatorRevocationSnapshotDigest: context.evaluatorRevocationSnapshotDigest,
    keyId: evidence.keyId,
    reason,
  });
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
  if (fingerprintAssessmentContext(assessmentContext) !== assessmentContext.contextDigest) {
    return verificationResult(
      "context-mismatch",
      "assessment context self-digest does not match its content",
      evidence,
      assessmentContext,
    );
  }
  if (
    fingerprintEvaluatorTrustPolicy(trustSnapshot)
      !== assessmentContext.operatorTrustPolicySnapshotDigest
    || fingerprintEvaluatorRevocations(trustSnapshot)
      !== assessmentContext.evaluatorRevocationSnapshotDigest
  ) {
    return verificationResult(
      "context-mismatch",
      "assessment context does not bind the supplied trust and revocation snapshots",
      evidence,
      assessmentContext,
    );
  }

  const key = trustSnapshot.keys.find(({ keyId }) => keyId === evidence.keyId);
  if (key === undefined) {
    return verificationResult(
      "unknown-key",
      "evidence key is absent from the operator trust snapshot",
      evidence,
      assessmentContext,
    );
  }

  const asOf = Date.parse(assessmentContext.asOf);
  const revocation = trustSnapshot.revocations.find(
    ({ keyId, revokedAt }) => keyId === evidence.keyId && Date.parse(revokedAt) <= asOf,
  );
  if (revocation !== undefined) {
    return verificationResult(
      "revoked",
      `evidence key was revoked: ${revocation.reasonCode}`,
      evidence,
      assessmentContext,
    );
  }

  const producedAt = Date.parse(evidence.producedAt);
  if (producedAt - asOf > trustSnapshot.freshness.maximumFutureSkewMs) {
    return verificationResult(
      "future-dated",
      "evidence production time exceeds the allowed assessment-time skew",
      evidence,
      assessmentContext,
    );
  }
  if (asOf - producedAt > trustSnapshot.freshness.maximumEvidenceAgeMs) {
    return verificationResult(
      "stale",
      "evidence exceeds the operator freshness window",
      evidence,
      assessmentContext,
    );
  }
  if (producedAt < Date.parse(key.validFrom)) {
    return verificationResult(
      "key-not-yet-valid",
      "evidence predates the trusted key validity interval",
      evidence,
      assessmentContext,
    );
  }
  if (producedAt > Date.parse(key.validUntil)) {
    return verificationResult(
      "key-expired",
      "evidence postdates the trusted key validity interval",
      evidence,
      assessmentContext,
    );
  }

  const signature = decodeCanonicalBase64Url(evidence.signature);
  if (signature === undefined || signature.length !== 64) {
    return verificationResult(
      "malformed-signature",
      "evidence signature is not a canonical 64-byte Ed25519 signature",
      evidence,
      assessmentContext,
    );
  }
  const publicKey = importEd25519PublicKey(key.publicKeySpki);
  if (publicKey === undefined) {
    return verificationResult(
      "malformed-signature",
      "trusted evaluator key material is malformed",
      evidence,
      assessmentContext,
    );
  }
  const validSignature = verifySignature(
    null,
    evaluatorEvidenceSigningBytes(evidence),
    publicKey,
    signature,
  );
  if (!validSignature) {
    return verificationResult(
      "invalid-signature",
      "Ed25519 signature does not cover the canonical evidence",
      evidence,
      assessmentContext,
    );
  }

  const authorized = key.purpose === "evaluator-evidence"
    && key.evaluatorId === evidence.evaluator.evaluatorId
    && key.producerId === evidence.evaluator.producer.producerId
    && key.authorizedRubricVersions.includes(evidence.evaluator.rubricVersion)
    && key.authorizedCalibrationDigests.includes(evidence.evaluator.calibrationDigest);
  if (!authorized) {
    return verificationResult(
      "unauthorized-evidence",
      "trusted key is not authorized for this evaluator, producer, rubric, or calibration",
      evidence,
      assessmentContext,
    );
  }

  return verificationResult(
    "trusted",
    "canonical Ed25519 evidence is current and authorized",
    evidence,
    assessmentContext,
  );
}
