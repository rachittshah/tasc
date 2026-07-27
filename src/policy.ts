import { compareCodeUnits, canonicalJson } from "./determinism.js";
import { sha256 } from "./integrity.js";
import {
  assertMeasurementMatrix,
  parseInferenceSpec,
  parseMeasurementSet,
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
  return replayPolicyForResolvedSpec(
    policy,
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
