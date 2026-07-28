import {
  createHash,
  createPublicKey,
  verify as verifySignature,
  type KeyObject,
} from "node:crypto";
import { isProxy } from "node:util/types";
import { z } from "zod";
import {
  parseBoundedJson,
  type BoundedJsonLimits,
} from "./bounded-input.js";
import { canonicalJsonBytes, compareCodeUnits } from "./determinism.js";
import {
  parseControlledReference,
  type ControlledReference,
} from "./references.js";
import {
  assertWithinWorkBudget,
  estimateAssessmentWork,
  type WorkBudget,
} from "./work-budget.js";

const MAX_PROFILES = 16;
const MAX_IDENTIFIERS = 128;
const MAX_ATTEMPTS = 8;
const MAX_METRICS = 32;
const MAX_SUBSCORES = 64;
const MAX_BUCKETS = 256;
const MAX_TEXT = 256;
const MAX_CONTRACT_DEPTH = 16;
const MAX_CONTRACT_NODES = 32_768;
const MAX_CONTRACT_OBJECT_KEYS = 64;
const MAX_CONTRACT_PROPERTY_KEY_LENGTH = 1_024;

export type DeepReadonly<T> =
  T extends (...args: never[]) => unknown ? T
    : T extends readonly (infer Item)[] ? readonly DeepReadonly<Item>[]
      : T extends object ? { readonly [Key in keyof T]: DeepReadonly<T[Key]> }
        : T;

const finiteNumberSchema = z.number().finite();
const finiteNonNegativeSchema = finiteNumberSchema.nonnegative();
const probabilitySchema = finiteNumberSchema.min(0).max(1);
const safeNonNegativeIntegerSchema = z.number().int().min(0).max(Number.MAX_SAFE_INTEGER);
const safePositiveIntegerSchema = safeNonNegativeIntegerSchema.min(1);

/** Strict machine identity: no normalization or whitespace rewriting is performed. */
export const contractSlugSchema = z.string()
  .min(1)
  .max(128)
  .regex(/^[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?$/, "must be a lowercase contract slug");

export const contractDigestSchema = z.string()
  .length(71)
  .regex(/^sha256:[a-f0-9]{64}$/, "must be a sha256: digest");

export const contractTimestampSchema = z.string()
  .length(24)
  .regex(
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/,
    "must be an exact UTC RFC 3339 millisecond timestamp",
  )
  .refine((value) => {
    const milliseconds = Date.parse(value);
    return Number.isFinite(milliseconds) && new Date(milliseconds).toISOString() === value;
  }, "must be a real UTC timestamp");

const boundedTextSchema = z.string()
  .min(1)
  .max(MAX_TEXT)
  .refine((value) => value.trim() === value, "must not contain leading or trailing whitespace");

/** Rubric identities are shared verbatim by protocols, evidence, and operator authorization. */
export const rubricIdentitySchema = boundedTextSchema;

const canonicalBase64UrlSchema = z.string()
  .min(1)
  .max(512)
  .regex(/^[A-Za-z0-9_-]+$/, "must be unpadded canonical base64url");

// Narrow defense-in-depth for identity fields, not content scanning. Task 8
// owns byte-level secret detection, redaction, and covert-channel policy.
const obviousCredentialPattern =
  /(?:\b(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]+)|(?:\b(?:api[-_ ]?key|authorization|password|passwd|secret)\b\s*[:=])|(?:\bsk-[A-Za-z0-9_-]{8,}\b)/i;

const persistedTraceIdentityTextSchema = boundedTextSchema.refine(
  (value) => !obviousCredentialPattern.test(value),
  "obvious credential-like text is not allowed in persisted trace identity fields",
);

const hexIdentitySchema = z.string()
  .length(64)
  .regex(/^[a-f0-9]{64}$/, "must contain 64 lowercase hexadecimal characters");

const keyedIdentitySchema = z.object({
  algorithm: z.literal("hmac-sha256"),
  keyId: contractSlugSchema,
  value: hexIdentitySchema,
}).strict();

const controlledReferenceSchema: z.ZodType<
  ControlledReference,
  z.ZodTypeDef,
  unknown
> = z.unknown().transform((value, context) => {
  try {
    return parseControlledReference(value);
  } catch {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      message: "invalid controlled payload reference",
    });
    return z.NEVER;
  }
});

const payloadIdentitySchema = z.union([
  keyedIdentitySchema,
  controlledReferenceSchema,
]);

const runtimeIdentitySchema = z.object({
  name: contractSlugSchema,
  build: boundedTextSchema,
}).strict();

const backendIdentitySchema = z.object({
  name: contractSlugSchema,
  build: boundedTextSchema,
}).strict();

const revisionIdentitySchema = z.object({
  id: boundedTextSchema,
  revision: boundedTextSchema,
}).strict();

const hardwareIdentitySchema = z.object({
  architecture: contractSlugSchema,
  accelerator: contractSlugSchema,
  acceleratorCount: safePositiveIntegerSchema.max(1_024),
}).strict();

const quantizationIdentitySchema = z.object({
  format: contractSlugSchema,
  configurationDigest: contractDigestSchema,
}).strict();

const orchestrationIdentitySchema = z.object({
  kind: z.enum(["direct", "ray-serve", "skypilot", "skyserve", "kubernetes", "other"]),
  configurationDigest: contractDigestSchema,
}).strict();

export const executionProfileSchema = z.object({
  id: contractSlugSchema,
  runtime: runtimeIdentitySchema,
  backend: backendIdentitySchema,
  model: revisionIdentitySchema,
  tokenizer: revisionIdentitySchema,
  hardware: hardwareIdentitySchema,
  quantization: quantizationIdentitySchema,
  chatTemplateDigest: contractDigestSchema,
  orchestration: orchestrationIdentitySchema,
  deploymentConfigurationDigest: contractDigestSchema,
}).strict();

type MutableExecutionProfile = z.infer<typeof executionProfileSchema>;
export type ExecutionProfile = DeepReadonly<MutableExecutionProfile>;

const splitMembershipSchema = z.object({
  algorithm: z.literal("tasc-seeded-sha256-group-bucket-v1"),
  seed: contractSlugSchema,
  bucketCount: safePositiveIntegerSchema.min(2).max(MAX_BUCKETS),
  developmentBuckets: z.array(safeNonNegativeIntegerSchema).min(1).max(MAX_BUCKETS),
  holdoutBuckets: z.array(safeNonNegativeIntegerSchema).min(1).max(MAX_BUCKETS),
}).strict();

const onlineWindowMembershipSchema = z.object({
  algorithm: z.literal("tasc-seeded-sha256-case-replicate-basis-points-v1"),
  seed: contractSlugSchema,
  sampleBasisPoints: safeNonNegativeIntegerSchema.max(10_000),
}).strict();

const routeSignalDefinitionSchema = z.object({
  definitionId: contractSlugSchema,
  version: persistedTraceIdentityTextSchema,
  minimum: finiteNumberSchema,
  maximum: finiteNumberSchema,
  direction: z.enum(["higher-is-more-confident", "lower-is-more-confident"]),
  calibrationDigest: contractDigestSchema,
}).strict();

const evaluatorDefinitionSchema = z.object({
  evaluatorId: contractSlugSchema,
  rubricVersion: rubricIdentitySchema,
  calibrationDigest: contractDigestSchema,
  producerKind: z.enum(["human", "deterministic", "external-model"]),
  producerId: contractSlugSchema,
  producerVersion: boundedTextSchema,
  requiredTrustedKeyIds: z.array(contractSlugSchema).min(1).max(32),
}).strict();

const policyPredicateSchema = z.object({
  signalDefinitionId: contractSlugSchema,
  operator: z.enum(["less-than", "less-than-or-equal", "greater-than", "greater-than-or-equal"]),
  threshold: finiteNumberSchema,
  routeToProfileId: contractSlugSchema,
}).strict();

const candidatePolicySpaceSchema = z.object({
  version: z.literal("tasc-declarative-policy-space-v1"),
  maxCandidates: safePositiveIntegerSchema.max(10_000),
  predicates: z.array(policyPredicateSchema).min(1).max(MAX_IDENTIFIERS),
}).strict();

const serviceCapacityGateSchema = z.discriminatedUnion("kind", [
  z.object({
    kind: z.literal("disabled"),
  }).strict(),
  z.object({
    kind: z.literal("minimum-measured-window-throughput"),
    metric: z.literal("aggregate-output-tokens-per-second"),
    minimum: finiteNumberSchema.gt(0),
  }).strict(),
]);

const gatesSchema = z.object({
  minimumMeanScore: probabilitySchema,
  nonInferiorityMargin: finiteNumberSchema.min(-1).max(0),
  maximumFailureRate: probabilitySchema,
  maximumP95TtftMs: finiteNonNegativeSchema,
  maximumP95EndToEndMs: finiteNonNegativeSchema,
  maximumCostPerThousandRequestsUsd: finiteNonNegativeSchema,
  minimumEvidenceCoverage: probabilitySchema,
  minimumIndependentGroups: safePositiveIntegerSchema,
  minimumCriticalSliceGroups: safeNonNegativeIntegerSchema,
  serviceCapacity: serviceCapacityGateSchema,
}).strict();

const bootstrapSchema = z.object({
  algorithm: z.literal("paired-group-percentile-v1"),
  seed: contractSlugSchema,
  iterations: safePositiveIntegerSchema.max(1_000_000),
  alpha: finiteNumberSchema.gt(0).lt(1),
}).strict();

const shadowCollectionSchema = z.object({
  maximumLogicalExecutions: safePositiveIntegerSchema,
  maximumConcurrency: safePositiveIntegerSchema.max(10_000),
  attemptTimeoutMs: safePositiveIntegerSchema,
  maximumAttempts: safePositiveIntegerSchema.max(MAX_ATTEMPTS),
  payloadPolicy: z.literal("keyed-identities-only"),
}).strict();

const protocolCostAllocationSchema = z.discriminatedUnion("kind", [
  z.object({
    kind: z.literal("unavailable"),
  }).strict(),
  z.object({
    kind: z.literal("modeled"),
    modelDigest: contractDigestSchema,
    currency: z.literal("USD"),
  }).strict(),
]);

const endpointRequirementSchema = z.object({
  runtimeName: contractSlugSchema,
  endpointAlias: contractSlugSchema,
  transport: z.enum(["https", "loopback-http"]),
}).strict();

const dispatchAuthoritySchema = z.object({
  keyId: contractSlugSchema,
  algorithm: z.literal("ed25519"),
  publicKeySpki: canonicalBase64UrlSchema,
}).strict();

export const experimentProtocolSchema = z.object({
  version: z.literal("tasc-experiment-protocol-v2"),
  studyId: contractSlugSchema,
  protocolVersion: contractSlugSchema,
  owner: boundedTextSchema,
  createdAt: contractTimestampSchema,
  expiresAt: contractTimestampSchema,
  dispatchAuthority: dispatchAuthoritySchema,
  splitMembership: splitMembershipSchema,
  onlineWindowMembership: onlineWindowMembershipSchema,
  profiles: z.array(executionProfileSchema).min(2).max(MAX_PROFILES),
  championProfileId: contractSlugSchema,
  candidateProfileIds: z.array(contractSlugSchema).min(1).max(MAX_PROFILES - 1),
  routeSignal: routeSignalDefinitionSchema,
  evaluator: evaluatorDefinitionSchema,
  candidatePolicySpace: candidatePolicySpaceSchema,
  gates: gatesSchema,
  criticalSlices: z.array(contractSlugSchema).max(64),
  bootstrap: bootstrapSchema,
  shadowCollection: shadowCollectionSchema,
  costAllocation: protocolCostAllocationSchema,
  endpointRequirements: z.array(endpointRequirementSchema).max(MAX_PROFILES),
  requiredCapabilities: z.array(contractSlugSchema).max(MAX_IDENTIFIERS),
}).strict();

type MutableExperimentProtocol = z.infer<typeof experimentProtocolSchema>;
export type ExperimentProtocol = DeepReadonly<MutableExperimentProtocol>;

const observedRouteSchema = z.object({
  selectedProfileId: contractSlugSchema,
  decisionId: contractSlugSchema,
}).strict();

const workloadSchema = z.object({
  mode: contractSlugSchema,
  declaredTrafficWeight: finiteNumberSchema.gt(0),
  inputTokenEstimate: safeNonNegativeIntegerSchema.nullable(),
}).strict();

const routeSignalObservationSchema = z.object({
  definitionId: contractSlugSchema,
  version: persistedTraceIdentityTextSchema,
  calibrationDigest: contractDigestSchema,
  value: finiteNumberSchema,
  provenance: z.object({
    kind: z.literal("route-signal-observation"),
    sourceId: contractSlugSchema,
    observedAt: contractTimestampSchema,
  }).strict(),
}).strict();

const dispatchIntentUnsignedSchema = z.object({
  version: z.literal("tasc-dispatch-intent-v1"),
  issuedAt: contractTimestampSchema,
  authorityKeyId: contractSlugSchema,
  signatureAlgorithm: z.literal("ed25519"),
}).strict();

const dispatchIntentSchema = dispatchIntentUnsignedSchema.extend({
  signature: canonicalBase64UrlSchema,
}).strict();

const dispatchIntentPayloadSchema = z.object({
  studyId: contractSlugSchema,
  protocolDigest: contractDigestSchema,
  traceId: contractSlugSchema,
  caseId: contractSlugSchema,
  groupId: contractSlugSchema,
  replicateId: contractSlugSchema,
  split: z.enum(["dev", "holdout", "online"]),
  collectionWindowId: contractSlugSchema.nullable(),
  collectionWindowMembershipDigest: contractDigestSchema.nullable(),
  sourceMode: z.enum(["imported", "observed", "shadow"]),
  profileId: contractSlugSchema,
  executionProfileDigest: contractDigestSchema,
  policyDigest: contractDigestSchema,
  observedRoute: observedRouteSchema,
  workload: workloadSchema,
  slices: z.array(contractSlugSchema).max(64),
  routeSignal: routeSignalObservationSchema.nullable(),
  dispatchIntent: dispatchIntentUnsignedSchema,
}).strict();

const observerTimingsSchema = z.object({
  startedAt: contractTimestampSchema,
  headersAt: contractTimestampSchema.nullable(),
  firstByteAt: contractTimestampSchema.nullable(),
  firstMeaningfulTokenAt: contractTimestampSchema.nullable(),
  completedAt: contractTimestampSchema,
}).strict();

const requestedModelSchema = z.object({
  id: persistedTraceIdentityTextSchema,
  revision: persistedTraceIdentityTextSchema,
}).strict();

const resolvedModelSchema = z.discriminatedUnion("source", [
  z.object({
    id: persistedTraceIdentityTextSchema,
    revision: persistedTraceIdentityTextSchema,
    source: z.literal("provider-reported"),
  }).strict(),
  z.object({
    id: persistedTraceIdentityTextSchema,
    revision: z.null(),
    source: z.literal("provider-id-only"),
  }).strict(),
]);

const tokenUsageValueSchema = z.object({
  value: safeNonNegativeIntegerSchema,
  source: z.enum(["observer-derived", "provider-reported", "modeled"]),
  semantics: contractSlugSchema,
  tokenizerDigest: contractDigestSchema.optional(),
}).strict();

const tokenUsageSchema = z.object({
  input: tokenUsageValueSchema.nullable(),
  output: tokenUsageValueSchema.nullable(),
  total: tokenUsageValueSchema.nullable(),
}).strict();

const providerTimingSchema = z.object({
  name: contractSlugSchema,
  valueMs: finiteNonNegativeSchema,
  source: z.literal("provider-reported"),
}).strict();

const providerMetricSchema = z.object({
  name: contractSlugSchema.refine(
    (value) => !/(?:^|[._-])(?:evaluator|judge|quality|reward|score|task[._-]?score)(?:$|[._-])/.test(value),
    "reserved evaluator/score metric namespaces are not operational provider metrics",
  ),
  value: finiteNumberSchema,
  unit: contractSlugSchema,
  source: z.literal("provider-reported"),
}).strict();

const providerReportedSchema = z.object({
  timings: z.array(providerTimingSchema).max(MAX_METRICS),
  metrics: z.array(providerMetricSchema).max(MAX_METRICS),
}).strict();

const attemptCostSchema = z.discriminatedUnion("kind", [
  z.object({
    kind: z.literal("unavailable"),
  }).strict(),
  z.object({
    kind: z.literal("measured"),
    amount: finiteNonNegativeSchema,
    currency: z.literal("USD"),
    evidenceDigest: contractDigestSchema,
  }).strict(),
  z.object({
    kind: z.literal("modeled"),
    amount: finiteNonNegativeSchema,
    currency: z.literal("USD"),
    modelDigest: contractDigestSchema,
  }).strict(),
  z.object({
    kind: z.literal("provider-reported"),
    amount: finiteNonNegativeSchema,
    currency: z.literal("USD"),
  }).strict(),
]);

const attemptSchema = z.object({
  attemptId: contractSlugSchema,
  attemptNumber: safePositiveIntegerSchema.max(MAX_ATTEMPTS),
  dispatchState: z.enum(["not_sent", "sent_unknown", "completed"]),
  observerTimings: observerTimingsSchema,
  status: z.enum(["success", "failure", "aborted"]),
  finishReason: contractSlugSchema.nullable(),
  partialOutput: z.boolean(),
  abortLifecycle: z.enum([
    "not-aborted",
    "abort-requested",
    "abort-confirmed",
    "abort-ambiguous",
  ]),
  failureCategory: contractSlugSchema.nullable(),
  requestedModel: requestedModelSchema,
  resolvedModel: resolvedModelSchema.nullable(),
  tokenUsage: tokenUsageSchema,
  providerReported: providerReportedSchema,
  cost: attemptCostSchema,
  payloads: z.object({
    request: payloadIdentitySchema,
    response: payloadIdentitySchema.nullable(),
    eventStream: payloadIdentitySchema.nullable(),
  }).strict(),
}).strict();

export const traceEnvelopeSchema = z.object({
  version: z.literal("tasc-trace-envelope-v2"),
  studyId: contractSlugSchema,
  protocolDigest: contractDigestSchema,
  traceId: contractSlugSchema,
  caseId: contractSlugSchema,
  groupId: contractSlugSchema,
  replicateId: contractSlugSchema,
  split: z.enum(["dev", "holdout", "online"]),
  collectionWindowId: contractSlugSchema.nullable(),
  collectionWindowMembershipDigest: contractDigestSchema.nullable(),
  sourceMode: z.enum(["imported", "observed", "shadow"]),
  profileId: contractSlugSchema,
  executionProfileDigest: contractDigestSchema,
  policyDigest: contractDigestSchema,
  observedRoute: observedRouteSchema,
  workload: workloadSchema,
  slices: z.array(contractSlugSchema).max(64),
  routeSignal: routeSignalObservationSchema.nullable(),
  dispatchIntent: dispatchIntentSchema,
  attempts: z.array(attemptSchema).min(1).max(MAX_ATTEMPTS),
  terminalOutputId: keyedIdentitySchema.nullable(),
  collectorVersion: persistedTraceIdentityTextSchema,
}).strict();

type MutableTraceEnvelope = z.infer<typeof traceEnvelopeSchema>;
export type TraceEnvelope = DeepReadonly<MutableTraceEnvelope>;

/**
 * Canonical pre-dispatch authorization bytes. The signature binds every
 * caller-controlled routing/workload field that can affect replay or
 * inference, while deliberately excluding attempts and outputs that do not
 * exist yet when dispatch is authorized.
 */
export function dispatchIntentSigningBytes(input: unknown): Buffer {
  const snapshot = snapshotBoundedContractInput(input);
  if (snapshot === null || typeof snapshot !== "object") {
    throw new Error("dispatch intent signing input must be a trace object");
  }
  const trace = snapshot as Record<string, unknown>;
  const binding = trace.dispatchIntent;
  if (binding === null || typeof binding !== "object") {
    throw new Error("trace dispatch intent must be an object");
  }
  const intent = binding as Record<string, unknown>;
  const payload = dispatchIntentPayloadSchema.parse({
    studyId: trace.studyId,
    protocolDigest: trace.protocolDigest,
    traceId: trace.traceId,
    caseId: trace.caseId,
    groupId: trace.groupId,
    replicateId: trace.replicateId,
    split: trace.split,
    collectionWindowId: trace.collectionWindowId,
    collectionWindowMembershipDigest:
      trace.collectionWindowMembershipDigest,
    sourceMode: trace.sourceMode,
    profileId: trace.profileId,
    executionProfileDigest: trace.executionProfileDigest,
    policyDigest: trace.policyDigest,
    observedRoute: trace.observedRoute,
    workload: trace.workload,
    slices: trace.slices,
    routeSignal: trace.routeSignal,
    dispatchIntent: {
      version: intent.version,
      issuedAt: intent.issuedAt,
      authorityKeyId: intent.authorityKeyId,
      signatureAlgorithm: intent.signatureAlgorithm,
    },
  });
  return canonicalJsonBytes({
    domain: "tasc/dispatch-intent-signature/v1",
    intent: payload,
  });
}

/**
 * Verify one signed dispatch intent against the exact frozen protocol.
 *
 * Inputs are independently snapshotted and parsed before any ordinary
 * property access. The returned trace is the verified immutable snapshot;
 * caller-owned objects, accessors, proxies, and diagnostic text never cross
 * this trust boundary.
 */
export function verifyTraceDispatchIntent(
  traceInput: unknown,
  protocolInput: unknown,
): TraceEnvelope {
  let protocol: ExperimentProtocol;
  try {
    const snapshot = snapshotProxyFreeContractInput(protocolInput);
    const parsed = experimentProtocolSchema.parse(snapshot);
    assertProtocolSemantics(parsed);
    protocol = deepFreezeContract(parsed);
  } catch {
    throw new Error("Dispatch-intent protocol is invalid.");
  }

  let trace: TraceEnvelope;
  try {
    const snapshot = snapshotProxyFreeContractInput(traceInput);
    const parsed = traceEnvelopeSchema.parse(snapshot);
    assertTraceSemantics(parsed);
    trace = deepFreezeContract(parsed);
  } catch {
    throw new Error("Dispatch-intent trace is invalid.");
  }

  if (
    trace.studyId !== protocol.studyId
    || trace.protocolDigest !== fingerprintNormalizedProtocol(protocol)
  ) {
    throw new Error("Dispatch intent conflicts with the protocol.");
  }
  if (
    trace.dispatchIntent.authorityKeyId
      !== protocol.dispatchAuthority.keyId
    || trace.dispatchIntent.signatureAlgorithm
      !== protocol.dispatchAuthority.algorithm
  ) {
    throw new Error("Dispatch intent conflicts with the protocol authority.");
  }

  const issuedAt = Date.parse(trace.dispatchIntent.issuedAt);
  if (
    issuedAt < Date.parse(protocol.createdAt)
    || issuedAt >= Date.parse(protocol.expiresAt)
  ) {
    throw new Error(
      "Dispatch intent is outside the protocol validity interval.",
    );
  }

  const signature = Buffer.from(
    trace.dispatchIntent.signature,
    "base64url",
  );
  let authentic = false;
  try {
    authentic =
      signature.toString("base64url") === trace.dispatchIntent.signature
      && verifySignature(
        null,
        dispatchIntentSigningBytes(trace),
        importCanonicalDispatchAuthorityKey(
          protocol.dispatchAuthority.publicKeySpki,
        ),
        signature,
      );
  } catch {
    authentic = false;
  }
  if (!authentic) {
    throw new Error("Invalid dispatch-intent signature.");
  }
  return trace;
}

const evaluatorProducerSchema = z.object({
  kind: z.enum(["human", "deterministic", "external-model"]),
  producerId: contractSlugSchema,
  version: boundedTextSchema,
}).strict();

const evaluatorIdentitySchema = z.object({
  evaluatorId: contractSlugSchema,
  rubricVersion: rubricIdentitySchema,
  calibrationDigest: contractDigestSchema,
  producer: evaluatorProducerSchema,
}).strict();

const scoreRangeSchema = z.object({
  minimum: finiteNumberSchema,
  maximum: finiteNumberSchema,
}).strict();

const scoredOutcomeSchema = z.object({
  kind: z.literal("scored"),
  score: finiteNumberSchema,
  range: scoreRangeSchema,
  subscores: z.array(z.object({
    id: contractSlugSchema,
    score: finiteNumberSchema,
    range: scoreRangeSchema,
  }).strict()).max(MAX_SUBSCORES),
}).strict();

const nonScoreOutcomeSchemas = [
  z.object({
    kind: z.literal("missing"),
    reasonCode: contractSlugSchema,
  }).strict(),
  z.object({
    kind: z.literal("invalid"),
    reasonCode: contractSlugSchema,
  }).strict(),
  z.object({
    kind: z.literal("abstained"),
    reasonCode: contractSlugSchema,
  }).strict(),
] as const;

const evaluatorOutcomeSchema = z.discriminatedUnion("kind", [
  scoredOutcomeSchema,
  ...nonScoreOutcomeSchemas,
]);

const evaluatorSourceSchema = z.union([
  z.object({
    kind: z.literal("digest"),
    digest: contractDigestSchema,
  }).strict(),
  controlledReferenceSchema,
]);

export const evaluatorEvidenceUnsignedSchema = z.object({
  version: z.literal("tasc-evaluator-evidence-v2"),
  studyId: contractSlugSchema,
  protocolDigest: contractDigestSchema,
  traceId: contractSlugSchema,
  caseId: contractSlugSchema,
  replicateId: contractSlugSchema,
  profileId: contractSlugSchema,
  split: z.enum(["dev", "holdout", "online"]),
  terminalOutputId: keyedIdentitySchema,
  evaluator: evaluatorIdentitySchema,
  outcome: evaluatorOutcomeSchema,
  source: evaluatorSourceSchema,
  producedAt: contractTimestampSchema,
  keyId: contractSlugSchema,
  signatureAlgorithm: z.literal("ed25519"),
}).strict();

export const evaluatorEvidenceSchema = evaluatorEvidenceUnsignedSchema.extend({
  signature: canonicalBase64UrlSchema,
}).strict();

type MutableEvaluatorEvidenceUnsigned = z.infer<typeof evaluatorEvidenceUnsignedSchema>;
type MutableEvaluatorEvidence = z.infer<typeof evaluatorEvidenceSchema>;
export type EvaluatorEvidenceUnsigned = DeepReadonly<MutableEvaluatorEvidenceUnsigned>;
export type EvaluatorEvidence = DeepReadonly<MutableEvaluatorEvidence>;

function unique(values: readonly string[], label: string): void {
  const seen = new Set<string>();
  for (const value of values) {
    if (seen.has(value)) throw new Error(`duplicate ${label} "${value}"`);
    seen.add(value);
  }
}

function assertScoreRange(
  value: number,
  range: { minimum: number; maximum: number },
  label: string,
): void {
  if (range.maximum <= range.minimum) {
    throw new Error(`${label} score range maximum must exceed minimum`);
  }
  if (value < range.minimum || value > range.maximum) {
    throw new Error(`${label} score must be within its declared range`);
  }
}

function importCanonicalDispatchAuthorityKey(encoded: string): KeyObject {
  try {
    const bytes = Buffer.from(encoded, "base64url");
    const key = createPublicKey({
      key: bytes,
      type: "spki",
      format: "der",
    });
    const canonical = key.export({ type: "spki", format: "der" });
    if (
      encoded !== bytes.toString("base64url")
      || key.asymmetricKeyType !== "ed25519"
      || !Buffer.isBuffer(canonical)
      || !canonical.equals(bytes)
    ) {
      throw new Error("noncanonical or non-Ed25519 dispatch key");
    }
    return key;
  } catch {
    throw new Error(
      "dispatch authority must contain canonical Ed25519 SPKI",
    );
  }
}

function assertProtocolSemantics(protocol: MutableExperimentProtocol): void {
  importCanonicalDispatchAuthorityKey(
    protocol.dispatchAuthority.publicKeySpki,
  );
  if (Date.parse(protocol.expiresAt) <= Date.parse(protocol.createdAt)) {
    throw new Error("protocol expiry must be after creation");
  }
  if (protocol.routeSignal.maximum <= protocol.routeSignal.minimum) {
    throw new Error("route-signal maximum must exceed minimum");
  }

  unique(protocol.profiles.map(({ id }) => id), "profile id");
  unique(protocol.candidateProfileIds, "candidate profile id");
  unique(protocol.evaluator.requiredTrustedKeyIds, "required trusted key id");
  unique(protocol.requiredCapabilities, "required capability");
  unique(protocol.criticalSlices, "critical slice");
  unique(
    protocol.candidatePolicySpace.predicates.map((predicate) =>
      domainSeparatedDigest(
        "tasc/declarative-policy-predicate/v1",
        predicate,
      )
    ),
    "candidate predicate",
  );
  if (
    protocol.criticalSlices.length === 0
    && protocol.gates.minimumCriticalSliceGroups > 0
  ) {
    throw new Error(
      "critical-slice group minimum must be zero when no critical slices are declared",
    );
  }
  unique(protocol.endpointRequirements.map(({ endpointAlias }) => endpointAlias), "endpoint alias");

  const profileIds = new Set(protocol.profiles.map(({ id }) => id));
  if (!profileIds.has(protocol.championProfileId)) {
    throw new Error(`champion profile "${protocol.championProfileId}" is missing`);
  }
  for (const candidateId of protocol.candidateProfileIds) {
    if (!profileIds.has(candidateId)) {
      throw new Error(`candidate profile "${candidateId}" is missing`);
    }
    if (candidateId === protocol.championProfileId) {
      throw new Error("champion profile cannot also be a candidate profile");
    }
  }
  const declaredRoleIds = new Set([
    protocol.championProfileId,
    ...protocol.candidateProfileIds,
  ]);
  for (const profileId of profileIds) {
    if (!declaredRoleIds.has(profileId)) {
      throw new Error(`profile "${profileId}" has no champion or candidate role`);
    }
  }

  const development = new Set<number>();
  for (const bucket of protocol.splitMembership.developmentBuckets) {
    if (bucket >= protocol.splitMembership.bucketCount) {
      throw new Error(`development bucket ${bucket} is outside the configured bucket count`);
    }
    if (development.has(bucket)) throw new Error(`duplicate development bucket ${bucket}`);
    development.add(bucket);
  }
  const holdout = new Set<number>();
  for (const bucket of protocol.splitMembership.holdoutBuckets) {
    if (bucket >= protocol.splitMembership.bucketCount) {
      throw new Error(`holdout bucket ${bucket} is outside the configured bucket count`);
    }
    if (development.has(bucket)) throw new Error(`split bucket overlap at ${bucket}`);
    if (holdout.has(bucket)) throw new Error(`duplicate holdout bucket ${bucket}`);
    holdout.add(bucket);
  }
  if (development.size + holdout.size !== protocol.splitMembership.bucketCount) {
    throw new Error("split buckets must form a complete partition with no missing bucket");
  }

  for (const predicate of protocol.candidatePolicySpace.predicates) {
    if (predicate.signalDefinitionId !== protocol.routeSignal.definitionId) {
      throw new Error(`predicate references unknown route-signal "${predicate.signalDefinitionId}"`);
    }
    if (!profileIds.has(predicate.routeToProfileId)) {
      throw new Error(`predicate references missing profile "${predicate.routeToProfileId}"`);
    }
    if (predicate.routeToProfileId !== protocol.championProfileId) {
      throw new Error(
        "v1 declarative policy predicates must route directly to the champion profile",
      );
    }
    if (
      predicate.threshold < protocol.routeSignal.minimum
      || predicate.threshold > protocol.routeSignal.maximum
    ) {
      throw new Error("predicate threshold is outside the route-signal range");
    }
  }
  const candidateCount = protocol.candidateProfileIds.length
    * (protocol.candidatePolicySpace.predicates.length + 1);
  if (candidateCount > protocol.candidatePolicySpace.maxCandidates) {
    throw new Error(
      `declarative candidate count ${candidateCount} exceeds maxCandidates `
      + protocol.candidatePolicySpace.maxCandidates,
    );
  }

  const runtimeNames = new Set(protocol.profiles.map(({ runtime }) => runtime.name));
  for (const endpoint of protocol.endpointRequirements) {
    if (!runtimeNames.has(endpoint.runtimeName)) {
      throw new Error(`endpoint requirement references unknown runtime "${endpoint.runtimeName}"`);
    }
  }
}

function assertAttemptSemantics(
  attempt: z.infer<typeof attemptSchema>,
  index: number,
): void {
  if (attempt.attemptNumber !== index + 1) {
    throw new Error("attemptNumber values must be contiguous and ordered from one");
  }
  const orderedTimings: Array<[string, string | null]> = [
    ["startedAt", attempt.observerTimings.startedAt],
    ["headersAt", attempt.observerTimings.headersAt],
    ["firstByteAt", attempt.observerTimings.firstByteAt],
    ["firstMeaningfulTokenAt", attempt.observerTimings.firstMeaningfulTokenAt],
    ["completedAt", attempt.observerTimings.completedAt],
  ];
  let previous: [string, number] | undefined;
  for (const [name, timestamp] of orderedTimings) {
    if (timestamp === null) continue;
    const milliseconds = Date.parse(timestamp);
    if (previous && milliseconds < previous[1]) {
      throw new Error(
        `attempt ${attempt.attemptNumber} timing ${name} precedes ${previous[0]}`,
      );
    }
    previous = [name, milliseconds];
  }

  if (attempt.status === "success") {
    if (
      attempt.dispatchState !== "completed"
      || attempt.failureCategory !== null
      || attempt.abortLifecycle !== "not-aborted"
      || attempt.partialOutput
    ) {
      throw new Error("success attempt has inconsistent dispatch, failure, abort, or partial-output state");
    }
    if (attempt.finishReason === null || attempt.resolvedModel === null) {
      throw new Error("success attempt requires a finish reason and resolved model");
    }
    return;
  }
  if (attempt.failureCategory === null) {
    throw new Error(`${attempt.status} attempt requires a failureCategory`);
  }
  if (attempt.status === "aborted" && attempt.abortLifecycle === "not-aborted") {
    throw new Error("aborted attempt requires an explicit abort lifecycle");
  }
}

function assertTraceSemantics(trace: MutableTraceEnvelope): void {
  if (trace.observedRoute.selectedProfileId !== trace.profileId) {
    throw new Error("observed selected profile must match the top-level profile");
  }
  if (
    trace.split === "online"
    && (
      trace.collectionWindowId === null
      || trace.collectionWindowMembershipDigest === null
    )
  ) {
    throw new Error("online traces require a collection window id and membership digest");
  }
  if (
    trace.split !== "online"
    && (
      trace.collectionWindowId !== null
      || trace.collectionWindowMembershipDigest !== null
    )
  ) {
    throw new Error(
      "development and holdout traces cannot claim an online collection window or membership digest",
    );
  }
  unique(trace.slices, "slice");
  unique(trace.attempts.map(({ attemptId }) => attemptId), "attempt id");
  if (
    Date.parse(trace.dispatchIntent.issuedAt)
      > Date.parse(trace.attempts[0].observerTimings.startedAt)
  ) {
    throw new Error(
      "dispatch intent must be issued no later than the first attempt starts",
    );
  }
  if (
    trace.routeSignal !== null
    && Date.parse(trace.routeSignal.provenance.observedAt)
      > Date.parse(trace.dispatchIntent.issuedAt)
  ) {
    throw new Error(
      "route signal must be observed before dispatch intent issuance",
    );
  }

  let priorCompletion = Number.NEGATIVE_INFINITY;
  trace.attempts.forEach((attempt, index) => {
    assertAttemptSemantics(attempt, index);
    const startedAt = Date.parse(attempt.observerTimings.startedAt);
    if (startedAt < priorCompletion) {
      throw new Error("retry attempts must be ordered after the prior attempt completes");
    }
    priorCompletion = Date.parse(attempt.observerTimings.completedAt);
    if (index < trace.attempts.length - 1 && attempt.status === "success") {
      throw new Error("a successful attempt must be the final attempt");
    }
  });

  const terminal = trace.attempts[trace.attempts.length - 1];
  if (terminal.status === "success" && trace.terminalOutputId === null) {
    throw new Error("successful trace requires a keyed terminal output id");
  }
  if (terminal.status !== "success" && trace.terminalOutputId !== null) {
    throw new Error("failed or aborted trace cannot claim a terminal output id");
  }
}

function assertEvaluatorOutcomeSemantics(
  outcome: MutableEvaluatorEvidenceUnsigned["outcome"],
): void {
  if (outcome.kind !== "scored") return;
  if (
    outcome.range.minimum !== 0
    || outcome.range.maximum !== 1
  ) {
    throw new Error(
      "primary evaluator score range must use the canonical 0 to 1 interval",
    );
  }
  assertScoreRange(outcome.score, outcome.range, "evaluator");
  unique(outcome.subscores.map(({ id }) => id), "subscore id");
  for (const subscore of outcome.subscores) {
    assertScoreRange(subscore.score, subscore.range, `subscore "${subscore.id}"`);
  }
}

function assertEvaluatorEvidenceSemantics(evidence: MutableEvaluatorEvidence): void {
  assertEvaluatorOutcomeSemantics(evidence.outcome);
}

function requireWorkBudget(budget: WorkBudget | undefined): WorkBudget {
  if (budget === undefined) throw new Error("caller work budget is required");
  return budget;
}

interface SnapshotState {
  nodes: number;
  readonly ancestors: Set<object>;
  readonly rejectProxies: boolean;
}

function hasWellFormedUnicode(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const codeUnit = value.charCodeAt(index);
    if (codeUnit < 0xd800 || codeUnit > 0xdfff) continue;
    if (
      codeUnit > 0xdbff
      || index + 1 >= value.length
      || value.charCodeAt(index + 1) < 0xdc00
      || value.charCodeAt(index + 1) > 0xdfff
    ) {
      return false;
    }
    index += 1;
  }
  return true;
}

function snapshotContractValue(
  value: unknown,
  depth: number,
  state: SnapshotState,
): unknown {
  state.nodes += 1;
  if (state.nodes > MAX_CONTRACT_NODES) {
    throw new Error("bounded contract input exceeds the node limit");
  }
  if (depth > MAX_CONTRACT_DEPTH) {
    throw new Error("bounded contract input exceeds the nesting-depth limit");
  }
  if (typeof value === "string" && value.length > 1_024) {
    throw new Error("bounded contract input string exceeds the coarse length limit");
  }
  if (value === null || typeof value !== "object") return value;
  if (state.rejectProxies && isProxy(value)) {
    throw new Error("bounded contract input cannot be a proxy");
  }
  if (state.ancestors.has(value)) {
    throw new Error("bounded contract input must be an acyclic I-JSON value");
  }

  const isArray = Array.isArray(value);
  const prototype = Object.getPrototypeOf(value);
  if (
    (isArray && prototype !== Array.prototype)
    || (!isArray && prototype !== Object.prototype && prototype !== null)
  ) {
    throw new Error("bounded contract input requires plain JSON objects and arrays");
  }

  const ownKeys = Reflect.ownKeys(value);
  if (ownKeys.some((key) => typeof key === "symbol")) {
    throw new Error("bounded contract input cannot contain symbol properties");
  }
  if (isArray && ownKeys.length > MAX_BUCKETS + 1) {
    throw new Error("bounded contract input array exceeds the key limit");
  }
  if (!isArray && ownKeys.length > MAX_CONTRACT_OBJECT_KEYS) {
    throw new Error("bounded contract input object exceeds the key limit");
  }

  const stringKeys = ownKeys as string[];
  for (const key of stringKeys) {
    if (key.length > MAX_CONTRACT_PROPERTY_KEY_LENGTH) {
      throw new Error("bounded contract input property key exceeds the length limit");
    }
    if (!hasWellFormedUnicode(key)) {
      throw new Error(
        "bounded contract input property key must contain valid Unicode scalar values",
      );
    }
  }

  const descriptors = new Map<string, PropertyDescriptor>();
  for (const key of stringKeys) {
    const descriptor = Reflect.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined) {
      throw new Error("bounded contract input properties changed during snapshot");
    }
    descriptors.set(key, descriptor);
  }

  state.ancestors.add(value);
  try {
    if (isArray) {
      const lengthDescriptor = descriptors.get("length");
      const length = lengthDescriptor?.value;
      if (!Number.isSafeInteger(length) || length < 0 || length > MAX_BUCKETS) {
        throw new Error("bounded contract input array exceeds the coarse length limit");
      }
      const allowedKeys = new Set<string>(["length"]);
      const snapshot: unknown[] = new Array(length);
      for (let index = 0; index < length; index += 1) {
        const key = String(index);
        allowedKeys.add(key);
        const descriptor = descriptors.get(key);
        if (descriptor === undefined) {
          throw new Error("bounded contract input arrays cannot contain holes");
        }
        if (!Object.hasOwn(descriptor, "value")) {
          throw new Error("bounded contract input accessor properties are not allowed");
        }
        snapshot[index] = snapshotContractValue(descriptor.value, depth + 1, state);
      }
      for (const key of stringKeys) {
        if (!allowedKeys.has(key)) {
          throw new Error("bounded contract input arrays cannot contain extra properties");
        }
      }
      return snapshot;
    }

    const snapshot = Object.create(null) as Record<string, unknown>;
    for (const key of stringKeys) {
      const descriptor = descriptors.get(key);
      if (descriptor === undefined) {
        throw new Error("bounded contract input properties changed during snapshot");
      }
      if (!Object.hasOwn(descriptor, "value")) {
        throw new Error("bounded contract input accessor properties are not allowed");
      }
      if (!descriptor.enumerable) {
        throw new Error("bounded contract input cannot contain hidden non-enumerable properties");
      }
      snapshot[key] = snapshotContractValue(descriptor.value, depth + 1, state);
    }
    return snapshot;
  } finally {
    state.ancestors.delete(value);
  }
}

/**
 * Read each caller-owned data property exactly once into a bounded data-only
 * snapshot. Canonical validation and every subsequent schema read use this
 * immutable snapshot, never the caller's object graph.
 */
export function snapshotBoundedContractInput(input: unknown): unknown {
  const snapshot = snapshotContractValue(input, 0, {
    nodes: 0,
    ancestors: new Set<object>(),
    rejectProxies: false,
  });
  canonicalJsonBytes(snapshot);
  return deepFreezeContract(snapshot);
}

function snapshotProxyFreeContractInput(input: unknown): unknown {
  const snapshot = snapshotContractValue(input, 0, {
    nodes: 0,
    ancestors: new Set<object>(),
    rejectProxies: true,
  });
  canonicalJsonBytes(snapshot);
  return deepFreezeContract(snapshot);
}

function assertProtocolWorkBudget(protocol: ExperimentProtocol, budget: WorkBudget): void {
  assertWithinWorkBudget(estimateAssessmentWork({
    candidateCount: protocol.candidatePolicySpace.maxCandidates,
    traceRows: 1,
    evidenceRows: 1,
    bootstrapDraws: protocol.bootstrap.iterations,
    independentGroups: Math.max(
      protocol.gates.minimumIndependentGroups,
      protocol.gates.minimumCriticalSliceGroups,
    ),
  }), budget);
}

function assertSingleRowBudget(kind: "trace" | "evidence", budget: WorkBudget): void {
  assertWithinWorkBudget(estimateAssessmentWork({
    candidateCount: 1,
    traceRows: kind === "trace" ? 1 : 0,
    evidenceRows: kind === "evidence" ? 1 : 0,
    bootstrapDraws: 0,
    independentGroups: 0,
  }), budget);
}

/** Recursively freeze parsed contracts so a verified identity cannot be rewritten in place. */
export function deepFreezeContract<T>(value: T): DeepReadonly<T> {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) deepFreezeContract(child);
    Object.freeze(value);
  }
  return value as DeepReadonly<T>;
}

/** Hash a JCS object with an explicit protocol domain in the canonical preimage. */
export function domainSeparatedDigest(domain: string, value: unknown): string {
  const bytes = canonicalJsonBytes({ domain, value });
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

export function fingerprintExecutionProfile(profile: unknown): string {
  const snapshot = snapshotBoundedContractInput(profile);
  const parsed = executionProfileSchema.parse(snapshot);
  return domainSeparatedDigest("tasc/execution-profile/v2", parsed);
}

export function normalizeExperimentProtocol(protocol: unknown): ExperimentProtocol {
  const snapshot = snapshotBoundedContractInput(protocol);
  const parsed = experimentProtocolSchema.parse(snapshot);
  assertProtocolSemantics(parsed);
  return deepFreezeContract(parsed);
}

export function fingerprintNormalizedProtocol(protocol: ExperimentProtocol): string {
  return domainSeparatedDigest("tasc/experiment-protocol/v2", protocol);
}

export function fingerprintProtocol(protocol: unknown): string {
  return fingerprintNormalizedProtocol(normalizeExperimentProtocol(protocol));
}

export function normalizeEvaluatorEvidence(evidence: unknown): EvaluatorEvidence {
  const snapshot = snapshotBoundedContractInput(evidence);
  const parsed = evaluatorEvidenceSchema.parse(snapshot);
  assertEvaluatorEvidenceSemantics(parsed);
  return deepFreezeContract(parsed);
}

export function fingerprintNormalizedEvaluatorEvidence(evidence: EvaluatorEvidence): string {
  return domainSeparatedDigest("tasc/evaluator-evidence/v2", evidence);
}

export function fingerprintEvaluatorEvidence(evidence: unknown): string {
  return fingerprintNormalizedEvaluatorEvidence(normalizeEvaluatorEvidence(evidence));
}

export function normalizedEvaluatorEvidenceSigningBytes(
  evidence: EvaluatorEvidence,
): Buffer {
  const { signature: _signature, ...withoutSignature } = evidence;
  return canonicalJsonBytes({
    domain: "tasc/evaluator-evidence-signature/v2",
    evidence: withoutSignature,
  });
}

/**
 * Canonical signature preimage. The signature is the only omitted evidence field;
 * the signature algorithm and every producer-controlled value remain covered.
 */
export function evaluatorEvidenceSigningBytes(evidence: unknown): Buffer {
  const snapshot = snapshotBoundedContractInput(evidence);
  let unsigned: MutableEvaluatorEvidenceUnsigned;
  if (
    snapshot !== null
    && typeof snapshot === "object"
    && Object.hasOwn(snapshot, "signature")
  ) {
    const parsed = evaluatorEvidenceSchema.parse(snapshot);
    assertEvaluatorEvidenceSemantics(parsed);
    const { signature: _signature, ...withoutSignature } = parsed;
    unsigned = withoutSignature;
  } else {
    unsigned = evaluatorEvidenceUnsignedSchema.parse(snapshot);
    assertEvaluatorOutcomeSemantics(unsigned.outcome);
  }
  return canonicalJsonBytes({
    domain: "tasc/evaluator-evidence-signature/v2",
    evidence: unsigned,
  });
}

export function parseExperimentProtocol(
  input: unknown,
  workBudget: WorkBudget,
): ExperimentProtocol {
  const protocol = normalizeExperimentProtocol(input);
  assertProtocolWorkBudget(protocol, requireWorkBudget(workBudget));
  return protocol;
}

export function parseTraceEnvelope(
  input: unknown,
  workBudget: WorkBudget,
): TraceEnvelope {
  assertSingleRowBudget("trace", requireWorkBudget(workBudget));
  return parseTraceEnvelopeValue(input);
}

/**
 * Parse one bounded trace value with the complete semantic contract. Keeping
 * this separate from work-budget admission lets internal public helpers reuse
 * semantic validation instead of falling back to shape-only parsing.
 */
export function parseTraceEnvelopeValue(input: unknown): TraceEnvelope {
  const snapshot = snapshotBoundedContractInput(input);
  const trace = traceEnvelopeSchema.parse(snapshot);
  assertTraceSemantics(trace);
  return deepFreezeContract(trace);
}

export function parseEvaluatorEvidence(
  input: unknown,
  workBudget: WorkBudget,
): EvaluatorEvidence {
  assertSingleRowBudget("evidence", requireWorkBudget(workBudget));
  return normalizeEvaluatorEvidence(input);
}

/** Byte-level admission followed by the existing semantic protocol contract. */
export function parseExperimentProtocolJson(
  input: Uint8Array,
  limits: BoundedJsonLimits,
  workBudget: WorkBudget,
): ExperimentProtocol {
  return parseExperimentProtocol(
    parseBoundedJson(input, limits),
    workBudget,
  );
}

/** Byte-level admission followed by the existing semantic trace contract. */
export function parseTraceEnvelopeJson(
  input: Uint8Array,
  limits: BoundedJsonLimits,
  workBudget: WorkBudget,
): TraceEnvelope {
  return parseTraceEnvelope(
    parseBoundedJson(input, limits),
    workBudget,
  );
}

/** Byte-level admission followed by the existing semantic evidence contract. */
export function parseEvaluatorEvidenceJson(
  input: Uint8Array,
  limits: BoundedJsonLimits,
  workBudget: WorkBudget,
): EvaluatorEvidence {
  return parseEvaluatorEvidence(
    parseBoundedJson(input, limits),
    workBudget,
  );
}

/** Portable ordering helper for later joins without locale-sensitive collation. */
export function compareEvidenceIdentities(left: string, right: string): number {
  return compareCodeUnits(left, right);
}
