import { z } from "zod";
import { compareCodeUnits, canonicalJson } from "./determinism.js";
import { sha256 } from "./integrity.js";
import {
  contractDigestSchema,
  contractSlugSchema,
  contractTimestampSchema,
  deepFreezeContract,
  domainSeparatedDigest,
  fingerprintNormalizedProtocol,
  normalizeExperimentProtocol,
  snapshotBoundedContractInput,
  type DeepReadonly,
  type ExperimentProtocol,
} from "./evidence.js";
import {
  assertMeasurementMatrix,
  parseInferenceSpec,
  parseMeasurementSet,
  snapshotPlainDataTree,
} from "./schema.js";
import type {
  FailedObservation,
  InferenceSpec,
  MeasurementCase,
  MeasurementSet,
  Observation,
  ResolvedInferenceSpec,
  SuccessfulObservation,
} from "./schema.js";

export interface InferencePolicy {
  version: "tasc-policy-v1";
  id: string;
  kind: "expert-only" | "fast-only" | "cascade";
  primaryProfileId: string;
  expertProfileId: string;
  confidenceThreshold?: number;
  inputTokenThreshold?: number;
  criticalSlices: string[];
}

const canonicalPolicyText = z.string()
  .min(1)
  .refine((value) => value === value.trim(), "must not contain surrounding whitespace");
const policyBaseShape = {
  version: z.literal("tasc-policy-v1"),
  id: canonicalPolicyText,
  primaryProfileId: canonicalPolicyText,
  expertProfileId: canonicalPolicyText,
  criticalSlices: z.array(canonicalPolicyText).max(64),
};
const inferencePolicySchema: z.ZodType<InferencePolicy> = z.discriminatedUnion("kind", [
  z.object({
    ...policyBaseShape,
    kind: z.literal("expert-only"),
    confidenceThreshold: z.undefined().optional(),
    inputTokenThreshold: z.undefined().optional(),
  }).strict(),
  z.object({
    ...policyBaseShape,
    kind: z.literal("fast-only"),
    confidenceThreshold: z.undefined().optional(),
    inputTokenThreshold: z.undefined().optional(),
  }).strict(),
  z.object({
    ...policyBaseShape,
    kind: z.literal("cascade"),
    confidenceThreshold: z.number().finite().min(0).max(1),
    inputTokenThreshold: z.number().int().finite().safe().nonnegative(),
  }).strict(),
]).superRefine((policy, context) => {
  const uniqueSlices = new Set(policy.criticalSlices);
  if (uniqueSlices.size !== policy.criticalSlices.length) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      path: ["criticalSlices"],
      message: "must not contain duplicate labels",
    });
  }
});

function parseInferencePolicy(input: unknown): InferencePolicy {
  const policy = inferencePolicySchema.parse(snapshotPlainDataTree(input, "policy"));
  if (policy.kind === "cascade") return policy;
  const {
    confidenceThreshold: _confidenceThreshold,
    inputTokenThreshold: _inputTokenThreshold,
    ...canonical
  } = policy;
  return canonical;
}

export interface ReplayedRow {
  policyId: string;
  /** Explicit on newly replayed rows; omitted legacy direct rows are treated conservatively. */
  policyKind?: InferencePolicy["kind"];
  caseId: string;
  groupId: string;
  replicateIndex: number;
  status: "success" | "failure";
  selectedProfileId: string;
  attemptedProfileIds: string[];
  escalated: boolean;
  taskScore: number;
  confidence?: number;
  ttftMs: number;
  endToEndLatencyMs: number;
  outputTokens: number;
  perceivedTokensPerSecond: number;
  serviceThroughput?: {
    kind: "measured";
    tokensPerSecond: number;
  } | {
    kind: "unavailable";
    reason: string;
  };
  /**
   * @deprecated Kept for legacy TypeScript callers only. This value is never accepted as
   * an exact-policy service-capacity observation.
   */
  totalTokensPerSecond?: number;
  costUsd: number;
  cacheHit?: boolean;
  failureCode?: string;
  trafficWeight: number;
  slices: string[];
  critical: boolean;
}

type PolicyBody = Omit<InferencePolicy, "id">;

function withStableId(body: PolicyBody): InferencePolicy {
  const id = `${body.kind}-${sha256(canonicalJson(body)).slice(0, 16)}`;
  return { ...body, id };
}

const CASCADE_THROUGHPUT_UNAVAILABLE = Object.freeze({
  kind: "unavailable" as const,
  reason: "legacy cascade has no exact-policy window service-capacity observation",
});

function normalizedCriticalSlices(slices: readonly string[]): string[] {
  return [...new Set(slices)].sort(compareCodeUnits);
}

/** A policy digest is order-insensitive for object keys and stable across processes. */
export function fingerprintPolicy(policy: InferencePolicy): string {
  return sha256(canonicalJson(policy));
}

/** The expert-only control policy is deliberately kept outside the candidate space. */
/** @internal Use championPolicy at public boundaries. */
export function championPolicyForResolvedSpec(spec: ResolvedInferenceSpec): InferencePolicy {
  return withStableId({
    version: "tasc-policy-v1",
    kind: "expert-only",
    primaryProfileId: spec.primaryProfileId,
    expertProfileId: spec.championProfileId,
    criticalSlices: normalizedCriticalSlices(spec.criticalSlices),
  });
}

export function championPolicy(spec: InferenceSpec): InferencePolicy {
  return championPolicyForResolvedSpec(parseInferenceSpec(spec));
}

/**
 * Enumerate only preregistered candidate thresholds. Sorting and de-duplicating protects
 * deterministic selection even when a hand-authored spec repeats an equivalent threshold.
 */
/** @internal Use generateCandidatePolicies at public boundaries. */
export function generateCandidatePoliciesForResolvedSpec(spec: ResolvedInferenceSpec): InferencePolicy[] {
  const confidenceThresholds = [...new Set(spec.candidateSpace.confidenceThresholds)].sort((a, b) => a - b);
  const inputTokenThresholds = [...new Set(spec.candidateSpace.inputTokenThresholds)].sort((a, b) => a - b);
  const candidates: InferencePolicy[] = [];

  for (const confidenceThreshold of confidenceThresholds) {
    for (const inputTokenThreshold of inputTokenThresholds) {
      candidates.push(withStableId({
        version: "tasc-policy-v1",
        kind: "cascade",
        primaryProfileId: spec.primaryProfileId,
        expertProfileId: spec.championProfileId,
        confidenceThreshold,
        inputTokenThreshold,
        criticalSlices: normalizedCriticalSlices(spec.criticalSlices),
      }));
    }
  }

  if (spec.candidateSpace.includeFastOnly) {
    candidates.push(withStableId({
      version: "tasc-policy-v1",
      kind: "fast-only",
      primaryProfileId: spec.primaryProfileId,
      expertProfileId: spec.championProfileId,
      criticalSlices: normalizedCriticalSlices(spec.criticalSlices),
    }));
  }

  return candidates.sort((left, right) => compareCodeUnits(left.id, right.id));
}

export function generateCandidatePolicies(spec: InferenceSpec): InferencePolicy[] {
  return generateCandidatePoliciesForResolvedSpec(parseInferenceSpec(spec));
}

function elapsedMs(observation: Observation): number {
  return observation.status === "success" ? observation.endToEndLatencyMs : observation.elapsedMs;
}

function replayedSuccess(
  policy: InferencePolicy,
  measurementCase: MeasurementCase,
  replicateIndex: number,
  selectedProfileId: string,
  observation: SuccessfulObservation,
  overrides: Partial<Pick<ReplayedRow, "attemptedProfileIds" | "escalated" | "ttftMs" | "endToEndLatencyMs" | "costUsd">> = {},
): ReplayedRow {
  return {
    policyId: policy.id,
    policyKind: policy.kind,
    caseId: measurementCase.id,
    groupId: measurementCase.groupId,
    replicateIndex,
    status: "success",
    selectedProfileId,
    attemptedProfileIds: [selectedProfileId],
    escalated: false,
    taskScore: observation.taskScore,
    ...(observation.confidence === undefined ? {} : { confidence: observation.confidence }),
    ttftMs: observation.ttftMs,
    endToEndLatencyMs: observation.endToEndLatencyMs,
    outputTokens: observation.outputTokens,
    perceivedTokensPerSecond: observation.perceivedTokensPerSecond,
    serviceThroughput: policy.kind === "cascade"
      ? CASCADE_THROUGHPUT_UNAVAILABLE
      : { kind: "measured", tokensPerSecond: observation.totalTokensPerSecond },
    costUsd: observation.costUsd,
    ...(observation.cacheHit === undefined ? {} : { cacheHit: observation.cacheHit }),
    trafficWeight: measurementCase.trafficWeight,
    slices: [...measurementCase.slices],
    critical: measurementCase.critical,
    ...overrides,
  };
}

function replayedFailure(
  policy: InferencePolicy,
  measurementCase: MeasurementCase,
  replicateIndex: number,
  selectedProfileId: string,
  observation: FailedObservation,
  overrides: Partial<Pick<ReplayedRow, "attemptedProfileIds" | "escalated" | "ttftMs" | "endToEndLatencyMs" | "costUsd">> = {},
): ReplayedRow {
  return {
    policyId: policy.id,
    policyKind: policy.kind,
    caseId: measurementCase.id,
    groupId: measurementCase.groupId,
    replicateIndex,
    status: "failure",
    selectedProfileId,
    attemptedProfileIds: [selectedProfileId],
    escalated: false,
    taskScore: 0,
    ttftMs: observation.elapsedMs,
    endToEndLatencyMs: observation.elapsedMs,
    outputTokens: 0,
    perceivedTokensPerSecond: 0,
    serviceThroughput: policy.kind === "cascade"
      ? CASCADE_THROUGHPUT_UNAVAILABLE
      : { kind: "unavailable", reason: "failed execution has no measured service-throughput observation" },
    costUsd: observation.costUsd,
    failureCode: observation.failureCode,
    trafficWeight: measurementCase.trafficWeight,
    slices: [...measurementCase.slices],
    critical: measurementCase.critical,
    ...overrides,
  };
}

function rowFromObservation(
  policy: InferencePolicy,
  measurementCase: MeasurementCase,
  replicateIndex: number,
  selectedProfileId: string,
  observation: Observation,
): ReplayedRow {
  return observation.status === "success"
    ? replayedSuccess(policy, measurementCase, replicateIndex, selectedProfileId, observation)
    : replayedFailure(policy, measurementCase, replicateIndex, selectedProfileId, observation);
}

function shouldEscalate(policy: InferencePolicy, measurementCase: MeasurementCase, primary: Observation): boolean {
  if (primary.status === "failure") return true;
  if (primary.confidence === undefined || primary.confidence < (policy.confidenceThreshold ?? 0)) return true;
  if (measurementCase.inputTokens >= (policy.inputTokenThreshold ?? Number.POSITIVE_INFINITY)) return true;
  return measurementCase.slices.some((slice) => policy.criticalSlices.includes(slice));
}

function assertPolicyMatchesSpec(policy: InferencePolicy, spec: ResolvedInferenceSpec): void {
  if (policy.version !== "tasc-policy-v1") throw new Error(`unsupported policy version "${policy.version}"`);
  if (policy.primaryProfileId !== spec.primaryProfileId || policy.expertProfileId !== spec.championProfileId) {
    throw new Error(`policy "${policy.id}" does not match the spec's primary and champion profiles`);
  }
  if (policy.kind === "cascade" && (policy.confidenceThreshold === undefined || policy.inputTokenThreshold === undefined)) {
    throw new Error(`cascade policy "${policy.id}" is missing an escalation threshold`);
  }
}

/**
 * Replay an already measured matrix. This function never estimates an outcome or mutates
 * its inputs; every returned value is copied from one or two paired observations.
 */
export function replayPolicy(
  policy: InferencePolicy,
  spec: InferenceSpec,
  measurements: MeasurementSet,
): ReplayedRow[] {
  const policySnapshot = parseInferencePolicy(policy);
  return replayPolicyForResolvedSpec(
    policySnapshot,
    parseInferenceSpec(spec),
    parseMeasurementSet(measurements),
  );
}

/** @internal Use replayPolicy at public boundaries. */
export function replayPolicyForResolvedSpec(
  policy: InferencePolicy,
  spec: ResolvedInferenceSpec,
  measurements: MeasurementSet,
): ReplayedRow[] {
  assertPolicyMatchesSpec(policy, spec);
  assertMeasurementMatrix(spec, measurements);
  const rows: ReplayedRow[] = [];

  for (const measurementCase of measurements.cases) {
    const observations = new Map(measurementCase.observations.map((set) => [set.profileId, set.replicates]));
    const primaryReplicates = observations.get(policy.primaryProfileId)!;
    const expertReplicates = observations.get(policy.expertProfileId)!;

    for (let replicateIndex = 0; replicateIndex < primaryReplicates.length; replicateIndex += 1) {
      const primary = primaryReplicates[replicateIndex];
      const expert = expertReplicates[replicateIndex];
      if (policy.kind === "expert-only") {
        rows.push(rowFromObservation(policy, measurementCase, replicateIndex, policy.expertProfileId, expert));
      } else if (policy.kind === "fast-only" || !shouldEscalate(policy, measurementCase, primary)) {
        rows.push(rowFromObservation(policy, measurementCase, replicateIndex, policy.primaryProfileId, primary));
      } else if (expert.status === "success") {
        rows.push(replayedSuccess(policy, measurementCase, replicateIndex, policy.expertProfileId, expert, {
          attemptedProfileIds: [policy.primaryProfileId, policy.expertProfileId],
          escalated: true,
          costUsd: primary.costUsd + expert.costUsd,
          ttftMs: elapsedMs(primary) + expert.ttftMs,
          endToEndLatencyMs: elapsedMs(primary) + expert.endToEndLatencyMs,
        }));
      } else {
        const serialElapsed = elapsedMs(primary) + expert.elapsedMs;
        rows.push(replayedFailure(policy, measurementCase, replicateIndex, policy.expertProfileId, expert, {
          attemptedProfileIds: [policy.primaryProfileId, policy.expertProfileId],
          escalated: true,
          costUsd: primary.costUsd + expert.costUsd,
          ttftMs: serialElapsed,
          endToEndLatencyMs: serialElapsed,
        }));
      }
    }
  }
  return rows;
}

const policyBundlePredicateSchema = z.object({
  signalDefinitionId: contractSlugSchema,
  operator: z.enum([
    "less-than",
    "less-than-or-equal",
    "greater-than",
    "greater-than-or-equal",
  ]),
  threshold: z.number().finite(),
  routeToProfileId: contractSlugSchema,
}).strict();

const policyBundleSignerSchema = z.object({
  keyId: contractSlugSchema,
  signatureAlgorithm: z.literal("ed25519"),
}).strict();

const policyBundleBodySchema = z.object({
  version: z.literal("tasc-policy-bundle-v2"),
  compatibilityVersion: z.literal("tasc-policy-replay-v2"),
  kind: z.enum(["expert-only", "fast-only", "cascade"]),
  primaryProfileId: contractSlugSchema,
  expertProfileId: contractSlugSchema,
  predicates: z.array(policyBundlePredicateSchema).max(1),
  fallbackProfileId: contractSlugSchema.nullable(),
  protocolDigest: contractDigestSchema,
  issuedAt: contractTimestampSchema,
  expiresAt: contractTimestampSchema,
  signer: policyBundleSignerSchema.nullable(),
}).strict();

const policyBundleSchema = policyBundleBodySchema.extend({
  policyDigest: contractDigestSchema,
}).strict();

type MutablePolicyBundlePredicate = z.infer<
  typeof policyBundlePredicateSchema
>;
type MutablePolicyBundleBody = z.infer<typeof policyBundleBodySchema>;
type MutablePolicyBundle = z.infer<typeof policyBundleSchema>;

export type PolicyBundlePredicate = DeepReadonly<
  MutablePolicyBundlePredicate
>;
export type PolicyBundleBody = DeepReadonly<MutablePolicyBundleBody>;
export type PolicyBundle = DeepReadonly<MutablePolicyBundle>;

function assertPolicyBundleSemantics(
  policy: MutablePolicyBundleBody,
): void {
  if (Date.parse(policy.expiresAt) <= Date.parse(policy.issuedAt)) {
    throw new Error("policy expiry must be after issue time");
  }
  if (policy.kind === "cascade") {
    if (policy.predicates.length !== 1) {
      throw new Error("cascade policy requires exactly one routing predicate");
    }
    if (policy.fallbackProfileId !== policy.expertProfileId) {
      throw new Error("cascade policy fallback must be its expert profile");
    }
    if (
      policy.predicates[0].routeToProfileId !== policy.expertProfileId
    ) {
      throw new Error("cascade predicate must route to its expert profile");
    }
    return;
  }
  if (policy.predicates.length !== 0) {
    throw new Error(`${policy.kind} policy cannot contain routing predicates`);
  }
  if (policy.fallbackProfileId !== null) {
    throw new Error(`${policy.kind} policy cannot contain a fallback profile`);
  }
  if (
    policy.kind === "expert-only"
    && policy.primaryProfileId !== policy.expertProfileId
  ) {
    throw new Error("expert-only policy must select its expert profile");
  }
}

function policyBodyWithoutDigest(
  policy: MutablePolicyBundle,
): MutablePolicyBundleBody {
  const { policyDigest: _policyDigest, ...body } = policy;
  return body;
}

function digestPolicyBundleBody(
  policy: MutablePolicyBundleBody,
): string {
  return domainSeparatedDigest("tasc/policy-bundle/v2", policy);
}

/**
 * Fingerprint a strict declarative v2 policy. A supplied self-digest is
 * deliberately omitted from its own canonical preimage.
 */
export function fingerprintPolicyBundle(input: unknown): string {
  const snapshot = snapshotBoundedContractInput(input);
  const withDigest = policyBundleSchema.safeParse(snapshot);
  const body = withDigest.success
    ? policyBodyWithoutDigest(withDigest.data)
    : policyBundleBodySchema.parse(snapshot);
  assertPolicyBundleSemantics(body);
  return digestPolicyBundleBody(body);
}

/** Validate a policy's self-digest and return a recursively immutable value. */
export function parsePolicyBundleValue(input: unknown): PolicyBundle {
  const snapshot = snapshotBoundedContractInput(input);
  const policy = policyBundleSchema.parse(snapshot);
  const body = policyBodyWithoutDigest(policy);
  assertPolicyBundleSemantics(body);
  if (policy.policyDigest !== digestPolicyBundleBody(body)) {
    throw new Error("policy digest does not match canonical policy content");
  }
  return deepFreezeContract(policy);
}

/**
 * Prove that a self-consistent bundle is one of the alternatives authorized by
 * the exact frozen protocol. This validates one policy without expanding the
 * development candidate space.
 */
export function assertPolicyBundleMatchesProtocol(
  policyInput: PolicyBundle,
  protocolInput: ExperimentProtocol,
): void {
  const policy = parsePolicyBundleValue(policyInput);
  const protocol = normalizeExperimentProtocol(protocolInput);
  if (policy.protocolDigest !== fingerprintNormalizedProtocol(protocol)) {
    throw new Error("policy bundle protocol digest mismatch");
  }
  if (
    policy.expertProfileId !== protocol.championProfileId
    || policy.expiresAt !== protocol.expiresAt
    || Date.parse(policy.issuedAt) < Date.parse(protocol.createdAt)
    || Date.parse(policy.issuedAt) >= Date.parse(protocol.expiresAt)
  ) {
    throw new Error("policy bundle profile or validity does not match protocol");
  }
  if (policy.kind === "expert-only") {
    if (policy.primaryProfileId !== protocol.championProfileId) {
      throw new Error("expert policy is not authorized by protocol");
    }
    return;
  }
  if (!protocol.candidateProfileIds.includes(policy.primaryProfileId)) {
    throw new Error("policy primary profile is not a protocol candidate");
  }
  if (policy.kind === "cascade") {
    const predicate = canonicalJson(policy.predicates[0]);
    if (!protocol.candidatePolicySpace.predicates.some(
      (candidate) => canonicalJson(candidate) === predicate,
    )) {
      throw new Error("policy predicate is not declared by the protocol");
    }
  }
}

function makePolicyBundle(body: MutablePolicyBundleBody): PolicyBundle {
  assertPolicyBundleSemantics(body);
  return parsePolicyBundleValue({
    ...body,
    policyDigest: digestPolicyBundleBody(body),
  });
}

export interface ProtocolPolicySpace {
  readonly control: PolicyBundle;
  readonly candidates: readonly PolicyBundle[];
}

function policyBundleBase(
  protocol: ExperimentProtocol,
  protocolDigest: string,
  issuedAt: string,
): Pick<
  MutablePolicyBundleBody,
  | "version"
  | "compatibilityVersion"
  | "expertProfileId"
  | "protocolDigest"
  | "issuedAt"
  | "expiresAt"
  | "signer"
> {
  return {
    version: "tasc-policy-bundle-v2",
    compatibilityVersion: "tasc-policy-replay-v2",
    expertProfileId: protocol.championProfileId,
    protocolDigest,
    issuedAt,
    expiresAt: protocol.expiresAt,
    signer: null,
  };
}

function normalizePolicyBundleInputs(
  protocolInput: ExperimentProtocol,
  protocolDigest: string,
  issuedAt: string,
): {
  readonly protocol: ExperimentProtocol;
  readonly protocolDigest: string;
  readonly issuedAt: string;
} {
  const protocol = normalizeExperimentProtocol(protocolInput);
  const normalizedProtocolDigest = contractDigestSchema.parse(
    snapshotBoundedContractInput(protocolDigest),
  );
  if (normalizedProtocolDigest !== fingerprintNormalizedProtocol(protocol)) {
    throw new Error("policy-space protocol digest does not match protocol content");
  }
  const normalizedIssuedAt = contractTimestampSchema.parse(
    snapshotBoundedContractInput(issuedAt),
  );
  if (
    Date.parse(normalizedIssuedAt) < Date.parse(protocol.createdAt)
    || Date.parse(normalizedIssuedAt) >= Date.parse(protocol.expiresAt)
  ) {
    throw new Error(
      "policy issue time must be within the protocol validity interval",
    );
  }
  return {
    protocol,
    protocolDigest: normalizedProtocolDigest,
    issuedAt: normalizedIssuedAt,
  };
}

/** Build only the expert control without expanding the development space. */
export function protocolControlPolicyBundle(
  protocolInput: ExperimentProtocol,
  protocolDigest: string,
  issuedAt: string,
): PolicyBundle {
  const normalized = normalizePolicyBundleInputs(
    protocolInput,
    protocolDigest,
    issuedAt,
  );
  const base = policyBundleBase(
    normalized.protocol,
    normalized.protocolDigest,
    normalized.issuedAt,
  );
  return makePolicyBundle({
    ...base,
    kind: "expert-only",
    primaryProfileId: normalized.protocol.championProfileId,
    predicates: [],
    fallbackProfileId: null,
  });
}

/**
 * Exact finite v2 mapping: one fast policy per candidate profile plus one
 * single-predicate cascade for every candidate-profile/predicate pair. The
 * expert control is separate and never consumes a candidate slot.
 */
export function enumerateProtocolPolicyBundles(
  protocolInput: ExperimentProtocol,
  protocolDigest: string,
  issuedAt: string,
): DeepReadonly<ProtocolPolicySpace> {
  const normalized = normalizePolicyBundleInputs(
    protocolInput,
    protocolDigest,
    issuedAt,
  );
  const protocol = normalized.protocol;
  const candidateCount = protocol.candidateProfileIds.length
    * (protocol.candidatePolicySpace.predicates.length + 1);
  if (candidateCount > protocol.candidatePolicySpace.maxCandidates) {
    throw new Error(
      `declarative candidate count ${candidateCount} exceeds maxCandidates `
      + protocol.candidatePolicySpace.maxCandidates,
    );
  }
  const candidates = new Array<PolicyBundle>(candidateCount);
  const base = policyBundleBase(
    protocol,
    normalized.protocolDigest,
    normalized.issuedAt,
  );
  let index = 0;
  for (
    const primaryProfileId of [...protocol.candidateProfileIds]
      .sort(compareCodeUnits)
  ) {
    candidates[index] = makePolicyBundle({
      ...base,
      kind: "fast-only",
      primaryProfileId,
      predicates: [],
      fallbackProfileId: null,
    });
    index += 1;
    for (
      const predicate of [...protocol.candidatePolicySpace.predicates]
        .sort((left, right) => {
          const leftKey = canonicalJson(left);
          const rightKey = canonicalJson(right);
          return compareCodeUnits(leftKey, rightKey);
        })
    ) {
      candidates[index] = makePolicyBundle({
        ...base,
        kind: "cascade",
        primaryProfileId,
        predicates: [{ ...predicate }],
        fallbackProfileId: protocol.championProfileId,
      });
      index += 1;
    }
  }
  if (index !== candidateCount) {
    throw new Error("declarative policy enumeration cardinality drift");
  }
  candidates.sort((left, right) =>
    compareCodeUnits(left.policyDigest, right.policyDigest)
  );
  const control = protocolControlPolicyBundle(
    protocol,
    normalized.protocolDigest,
    normalized.issuedAt,
  );
  return deepFreezeContract({ control, candidates });
}
