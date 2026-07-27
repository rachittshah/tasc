import { createHmac, timingSafeEqual } from "node:crypto";
import {
  bootstrapGroupedWeightedMeanCI,
  median,
  type BootstrapCI,
  type GroupedCaseEffect,
} from "./statistics.js";
import { canonicalJson, compareCodeUnits } from "./determinism.js";
import { sha256 } from "./integrity.js";
import { assertMeasurementMatrix, type InferenceSpec, type MeasurementSet } from "./schema.js";
import {
  assertWithinWorkBudget,
  estimateAssessmentWork,
  type WorkBudget,
} from "./work-budget.js";
import {
  championPolicy,
  fingerprintPolicy,
  generateCandidatePolicies,
  replayPolicy,
  type InferencePolicy,
  type ReplayedRow,
} from "./policy.js";

export interface PolicyMetrics {
  meanTaskScore: number;
  successRate: number;
  errorRate: number;
  p50TtftMs: number;
  p95TtftMs: number;
  p50EndToEndLatencyMs: number;
  p95EndToEndLatencyMs: number;
  p99EndToEndLatencyMs: number;
  p10PerceivedTokensPerSecond: number;
  p50TotalTokensPerSecond: number | null;
  costPerRequestUsd: number;
  costPerThousandRequestsUsd: number;
  escalationRate: number;
  criticalSliceTaskScore: Record<string, number | null>;
}

export interface GateResult {
  id: string;
  pass: boolean;
  actual: number | null;
  threshold: number;
  comparison: ">=" | "<=";
  reason: string;
}

export interface PairedQualityResult {
  method: "paired-group-percentile-v1";
  alpha: number;
  caseCount: number;
  replicateCount: number;
  groupCount: number;
  effectiveTrafficMass: number;
  deltas: number[];
  replicateDeltas: Array<{
    caseId: string;
    replicateId: string;
    delta: number;
  }>;
  caseEffects: GroupedCaseEffect[];
  criticalSliceGroupCoverage: Record<string, number>;
  estimate: number;
  interval: {
    lo: number | null;
    hi: number | null;
  };
  iterations: number;
  seed: number;
  inferenceAvailable: boolean;
  unavailableReason?: string;
  /** Compatibility projection for existing v1 artifact readers. */
  bootstrap: Omit<BootstrapCI, "lo" | "hi"> & {
    lo: number | null;
    hi: number | null;
  };
}

export interface PolicyEvaluation {
  candidateMetrics: PolicyMetrics;
  championMetrics: PolicyMetrics;
  pairedQuality: PairedQualityResult;
  costImprovement: number | null;
  gates: GateResult[];
  passed: boolean;
}

export interface CandidateEvaluation {
  policy: InferencePolicy;
  evaluation: PolicyEvaluation;
}

export interface EvaluationOptions {
  /** Optional tighter caller limit; omitted callers receive a bounded safe default. */
  workBudget?: WorkBudget;
}

export interface AttestationOptions extends EvaluationOptions {
  attestationKey?: string;
}

/** Bounded defaults preserve the synthetic CLI/demo call shape without allowing unbounded work. */
export const DEFAULT_ASSESSMENT_WORK_BUDGET: Readonly<WorkBudget> = Object.freeze({
  maxCandidates: 10_000,
  maxTraceRows: 100_000,
  maxEvidenceRows: 100_000,
  maxBootstrapDraws: 100_000,
  maxIndependentGroups: 100_000,
  maxAssessmentWork: 100_000_000,
});

export interface NominationAttestation {
  algorithm: "hmac-sha256";
  digest: string;
}

export interface NominationArtifact {
  version: "tasc-nomination-v1";
  specDigest: string;
  developmentDatasetDigest: string;
  evaluator: MeasurementSet["evaluator"];
  developmentGroupIds: string[];
  developmentSynthetic: boolean;
  policy: InferencePolicy;
  policyDigest: string;
  candidateMetrics: PolicyMetrics;
  championMetrics: PolicyMetrics;
  gates: GateResult[];
  decisionDigest: string;
  selfDigest: string;
  attestation?: NominationAttestation;
}

export interface NominationResult {
  status: "NOMINATED" | "NO_CANDIDATE";
  evaluations: CandidateEvaluation[];
  frontier: string[];
  nomination?: NominationArtifact;
}

export interface ConfirmationResult {
  version: "tasc-confirmation-v1";
  status: "DEMO_ONLY" | "HOLD";
  specDigest: string;
  holdoutDatasetDigest: string;
  nominationDigest: string;
  evaluator: MeasurementSet["evaluator"];
  holdoutGroupIds: string[];
  policy: InferencePolicy;
  policyDigest: string;
  evaluation: PolicyEvaluation;
  attestationVerified: boolean;
  statusReason: string;
  decisionDigest: string;
}

interface WeightedValue {
  value: number;
  weight: number;
}

function checkedAdd(left: number, right: number, name: string): number {
  if (!Number.isSafeInteger(left) || !Number.isSafeInteger(right) || left > Number.MAX_SAFE_INTEGER - right) {
    throw new Error(`${name} exceeds safe integer range`);
  }
  return left + right;
}

function candidatePolicyCount(spec: InferenceSpec): number {
  const confidenceCount = new Set(spec.candidateSpace.confidenceThresholds).size;
  const inputTokenCount = new Set(spec.candidateSpace.inputTokenThresholds).size;
  if (confidenceCount > 0 && inputTokenCount > Number.MAX_SAFE_INTEGER / confidenceCount) {
    throw new Error("candidate count exceeds safe integer range");
  }
  return checkedAdd(
    confidenceCount * inputTokenCount,
    spec.candidateSpace.includeFastOnly ? 1 : 0,
    "candidate count",
  );
}

function observationRowCount(measurements: MeasurementSet): number {
  let count = 0;
  for (const measurementCase of measurements.cases) {
    for (const observationSet of measurementCase.observations) {
      count = checkedAdd(count, observationSet.replicates.length, "measurement row count");
    }
  }
  return count;
}

/** Enforce work limits before candidate arrays or bootstrap result arrays can be allocated. */
function assertAssessmentWorkBudget(spec: InferenceSpec, measurements: MeasurementSet, budget: WorkBudget): void {
  const rows = observationRowCount(measurements);
  const input = {
    candidateCount: candidatePolicyCount(spec),
    traceRows: rows,
    evidenceRows: rows,
    bootstrapDraws: spec.bootstrap.iterations,
  };
  assertWithinWorkBudget(estimateAssessmentWork({ ...input, independentGroups: 0 }), budget);
  const groups = new Set<string>();
  for (const measurementCase of measurements.cases) groups.add(measurementCase.groupId);
  const estimate = estimateAssessmentWork({ ...input, independentGroups: groups.size });
  assertWithinWorkBudget(estimate, budget);
}

/** Bound the public row-level evaluator before its bootstrap result array is allocated. */
function assertDirectEvaluationWorkBudget(
  candidateRows: readonly ReplayedRow[],
  championRows: readonly ReplayedRow[],
  spec: InferenceSpec,
  budget: WorkBudget,
): void {
  const input = {
    candidateCount: 1,
    traceRows: candidateRows.length,
    evidenceRows: championRows.length,
    bootstrapDraws: spec.bootstrap.iterations,
  };
  assertWithinWorkBudget(estimateAssessmentWork({ ...input, independentGroups: 0 }), budget);
  const groups = new Set<string>();
  for (const row of candidateRows) groups.add(row.groupId);
  for (const row of championRows) groups.add(row.groupId);
  const estimate = estimateAssessmentWork({ ...input, independentGroups: groups.size });
  assertWithinWorkBudget(estimate, budget);
}

function effectiveWeightedRows(rows: readonly ReplayedRow[]): Array<{ row: ReplayedRow; weight: number }> {
  const replicatesByCase = new Map<string, number>();
  const orderedRows = [...rows].sort((left, right) => (
    compareCodeUnits(left.caseId, right.caseId)
    || left.replicateIndex - right.replicateIndex
  ));
  for (const row of orderedRows) {
    replicatesByCase.set(row.caseId, (replicatesByCase.get(row.caseId) ?? 0) + 1);
  }
  return orderedRows.map((row) => ({
    row,
    weight: row.trafficWeight / replicatesByCase.get(row.caseId)!,
  }));
}

function weightedMean(values: readonly WeightedValue[]): number {
  let totalWeight = 0;
  let numerator = 0;
  for (const entry of values) {
    totalWeight += entry.weight;
    numerator += entry.value * entry.weight;
    if (!Number.isFinite(totalWeight) || !Number.isFinite(numerator)) {
      throw new Error("weighted metric accumulation exceeds the finite numeric range");
    }
  }
  if (totalWeight === 0) return 0;
  return numerator / totalWeight;
}

/**
 * Deterministic inverse-CDF weighted quantile. Effective traffic weights, rather than
 * raw replicate counts, determine how much probability mass each recorded outcome owns.
 */
function weightedQuantile(values: readonly WeightedValue[], q: number): number {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((left, right) => left.value - right.value);
  const totalWeight = sorted.reduce((sum, entry) => sum + entry.weight, 0);
  if (totalWeight === 0) return sorted[0].value;
  const target = Math.min(1, Math.max(0, q)) * totalWeight;
  let cumulative = 0;
  for (const entry of sorted) {
    cumulative += entry.weight;
    if (cumulative >= target) return entry.value;
  }
  return sorted[sorted.length - 1].value;
}

export function computePolicyMetrics(rows: ReplayedRow[], criticalSlices: string[]): PolicyMetrics {
  const weightedRows = effectiveWeightedRows(rows);
  const values = (select: (row: ReplayedRow) => number): WeightedValue[] => (
    weightedRows.map(({ row, weight }) => ({ value: select(row), weight }))
  );
  const scoreValues = values((row) => row.status === "failure" ? 0 : row.taskScore);
  const costPerRequestUsd = weightedMean(values((row) => row.costUsd));
  const criticalSliceTaskScore: Record<string, number | null> = {};
  const serviceThroughputValues: WeightedValue[] = [];
  let serviceThroughputUnavailable = false;
  for (const { row, weight } of weightedRows) {
    const observation = row.serviceThroughput;
    if (
      observation?.kind === "measured"
      && Number.isFinite(observation.tokensPerSecond)
      && observation.tokensPerSecond >= 0
    ) {
      serviceThroughputValues.push({ value: observation.tokensPerSecond, weight });
    } else {
      serviceThroughputUnavailable = true;
    }
  }

  for (const slice of criticalSlices) {
    const sliceRows = weightedRows
      .filter(({ row }) => row.slices.includes(slice))
      .map(({ row, weight }) => ({ value: row.status === "failure" ? 0 : row.taskScore, weight }));
    criticalSliceTaskScore[slice] = sliceRows.length === 0 ? null : weightedMean(sliceRows);
  }

  return {
    meanTaskScore: weightedMean(scoreValues),
    successRate: weightedMean(values((row) => row.status === "success" ? 1 : 0)),
    errorRate: weightedMean(values((row) => row.status === "failure" ? 1 : 0)),
    p50TtftMs: weightedQuantile(values((row) => row.ttftMs), 0.5),
    p95TtftMs: weightedQuantile(values((row) => row.ttftMs), 0.95),
    p50EndToEndLatencyMs: weightedQuantile(values((row) => row.endToEndLatencyMs), 0.5),
    p95EndToEndLatencyMs: weightedQuantile(values((row) => row.endToEndLatencyMs), 0.95),
    p99EndToEndLatencyMs: weightedQuantile(values((row) => row.endToEndLatencyMs), 0.99),
    p10PerceivedTokensPerSecond: weightedQuantile(
      values((row) => row.status === "failure" ? 0 : row.perceivedTokensPerSecond),
      0.1,
    ),
    p50TotalTokensPerSecond: serviceThroughputUnavailable
      ? null
      : weightedQuantile(serviceThroughputValues, 0.5),
    costPerRequestUsd,
    costPerThousandRequestsUsd: costPerRequestUsd * 1_000,
    escalationRate: weightedMean(values((row) => row.escalated ? 1 : 0)),
    criticalSliceTaskScore,
  };
}

function gate(
  id: string,
  actual: number | null,
  threshold: number,
  comparison: ">=" | "<=",
  absentReason?: string,
): GateResult {
  const pass = actual !== null && (comparison === ">=" ? actual >= threshold : actual <= threshold);
  const reason = actual === null
    ? (absentReason ?? `${id} has no measured value`)
    : `${id}: ${actual} ${pass ? "meets" : "does not meet"} required ${comparison} ${threshold}`;
  return { id, pass, actual, threshold, comparison, reason };
}

function serviceThroughputGate(actual: number | null, threshold: number): GateResult {
  if (actual === null && threshold === 0) {
    return {
      id: "p50_total_tps",
      pass: true,
      actual: null,
      threshold,
      comparison: ">=",
      reason: "p50_total_tps is unavailable and the zero threshold explicitly disables the capacity requirement",
    };
  }
  return gate(
    "p50_total_tps",
    actual,
    threshold,
    ">=",
    "p50_total_tps is unavailable for the exact policy and the required capacity gate fails closed",
  );
}

interface PairedCase {
  caseId: string;
  groupId: string;
  trafficWeight: number;
  slices: string[];
  critical: boolean;
  replicateDeltas: Array<{
    caseId: string;
    replicateId: string;
    delta: number;
  }>;
}

function normalizedSlices(row: ReplayedRow, label: string): string[] {
  if (!Array.isArray(row.slices)) throw new Error(`${label} slices must be an array`);
  const slices = [...row.slices].sort(compareCodeUnits);
  if (new Set(slices).size !== slices.length) {
    throw new Error(`${label} has duplicate slice labels`);
  }
  return slices;
}

function rowScore(row: ReplayedRow, label: string): number {
  if (row.status === "failure") return 0;
  if (!Number.isFinite(row.taskScore) || row.taskScore < 0 || row.taskScore > 1) {
    throw new Error(`${label} successful row is missing a finite task score in [0, 1]`);
  }
  return row.taskScore;
}

function assertRowIdentity(row: ReplayedRow, label: string): void {
  if (typeof row.caseId !== "string" || row.caseId.length === 0) {
    throw new Error(`${label} caseId must be non-empty`);
  }
  if (!Number.isSafeInteger(row.replicateIndex) || row.replicateIndex < 0) {
    throw new Error(`${label} replicateIndex must be a safe non-negative integer`);
  }
  if (typeof row.groupId !== "string" || row.groupId.length === 0) {
    throw new Error(`${label} groupId must be non-empty`);
  }
  if (!Number.isFinite(row.trafficWeight) || row.trafficWeight <= 0) {
    throw new Error(`${label} trafficWeight must be finite and positive`);
  }
  if (typeof row.critical !== "boolean") throw new Error(`${label} critical must be boolean`);
  normalizedSlices(row, label);
  rowScore(row, label);
}

function sameSlices(left: ReplayedRow, right: ReplayedRow, label: string): boolean {
  const leftSlices = normalizedSlices(left, `${label} candidate`);
  const rightSlices = normalizedSlices(right, `${label} champion`);
  return (
    leftSlices.length === rightSlices.length
    && leftSlices.every((slice, index) => slice === rightSlices[index])
  );
}

function assertLineage(left: ReplayedRow, right: ReplayedRow, label: string): void {
  if (left.groupId !== right.groupId) throw new Error(`${label} has group lineage drift`);
  if (left.trafficWeight !== right.trafficWeight) throw new Error(`${label} has traffic-weight lineage drift`);
  if (!sameSlices(left, right, label)) throw new Error(`${label} has slice-set lineage drift`);
  if (left.critical !== right.critical) throw new Error(`${label} has critical lineage drift`);
}

function indexRows(rows: readonly ReplayedRow[], label: string): Map<string, Map<number, ReplayedRow>> {
  const byCase = new Map<string, Map<number, ReplayedRow>>();
  const caseBaseline = new Map<string, ReplayedRow>();
  for (const row of rows) {
    assertRowIdentity(row, label);
    const baseline = caseBaseline.get(row.caseId);
    if (baseline === undefined) caseBaseline.set(row.caseId, row);
    else assertLineage(row, baseline, `${label} case "${row.caseId}"`);
    const byReplicate = byCase.get(row.caseId) ?? new Map<number, ReplayedRow>();
    if (byReplicate.has(row.replicateIndex)) {
      throw new Error(
        `${label} has duplicate (caseId, replicateIndex) pair ("${row.caseId}", ${row.replicateIndex})`,
      );
    }
    byReplicate.set(row.replicateIndex, row);
    byCase.set(row.caseId, byReplicate);
  }
  return byCase;
}

function pairRows(
  candidateRows: readonly ReplayedRow[],
  championRows: readonly ReplayedRow[],
): PairedCase[] {
  const candidateByCase = indexRows(candidateRows, "candidate");
  const championByCase = indexRows(championRows, "champion");
  const caseIds = [...new Set([...candidateByCase.keys(), ...championByCase.keys()])].sort(compareCodeUnits);
  const pairedCases: PairedCase[] = [];
  for (const caseId of caseIds) {
    const candidateReplicates = candidateByCase.get(caseId);
    const championReplicates = championByCase.get(caseId);
    if (candidateReplicates === undefined || championReplicates === undefined) {
      throw new Error(`missing paired case-replicate rows for case "${caseId}"`);
    }
    const replicateIndexes = [...new Set([
      ...candidateReplicates.keys(),
      ...championReplicates.keys(),
    ])].sort((left, right) => left - right);
    const replicateDeltas: PairedCase["replicateDeltas"] = [];
    let baseline: ReplayedRow | undefined;
    for (const replicateIndex of replicateIndexes) {
      const candidate = candidateReplicates.get(replicateIndex);
      const champion = championReplicates.get(replicateIndex);
      if (candidate === undefined || champion === undefined) {
        throw new Error(
          `missing (caseId, replicateIndex) pair ("${caseId}", ${replicateIndex})`,
        );
      }
      assertLineage(candidate, champion, `paired case "${caseId}" replicate ${replicateIndex}`);
      if (baseline === undefined) baseline = candidate;
      else assertLineage(candidate, baseline, `candidate case "${caseId}"`);
      replicateDeltas.push({
        caseId,
        replicateId: `legacy-replicate-${replicateIndex}`,
        delta: rowScore(candidate, "candidate") - rowScore(champion, "champion"),
      });
    }
    const row = baseline!;
    pairedCases.push({
      caseId,
      groupId: row.groupId,
      trafficWeight: row.trafficWeight,
      slices: normalizedSlices(row, `case "${caseId}"`),
      critical: row.critical,
      replicateDeltas,
    });
  }
  return pairedCases;
}

function evaluatePolicyInternal(
  candidateRows: ReplayedRow[],
  championRows: ReplayedRow[],
  spec: InferenceSpec,
  requireDevelopmentCostImprovement: boolean,
): PolicyEvaluation {
  const criticalSlices = [...new Set(spec.criticalSlices)].sort(compareCodeUnits);
  const pairedCases = pairRows(candidateRows, championRows);
  if (pairedCases.length === 0) throw new Error("at least one exact paired case is required");
  const replicateDeltas = pairedCases.flatMap((pairedCase) => pairedCase.replicateDeltas);
  const deltas = replicateDeltas.map(({ delta }) => delta);
  const caseEffects: GroupedCaseEffect[] = pairedCases.map((pairedCase) => ({
    caseId: pairedCase.caseId,
    groupId: pairedCase.groupId,
    effect: median(pairedCase.replicateDeltas.map(({ delta }) => delta)),
    trafficWeight: pairedCase.trafficWeight,
  }));
  const groupCount = new Set(pairedCases.map(({ groupId }) => groupId)).size;
  const criticalSliceGroupCoverage = Object.fromEntries(criticalSlices
    .map((slice): [string, number] => [
      slice,
      new Set(pairedCases.filter((pairedCase) => pairedCase.slices.includes(slice))
        .map(({ groupId }) => groupId)).size,
    ])
    .sort(([left], [right]) => compareCodeUnits(left, right)));
  const coverageFailures = [
    ...(groupCount < spec.constraints.minimumIndependentGroups
      ? [`independent groups ${groupCount} < ${spec.constraints.minimumIndependentGroups}`]
      : []),
    ...criticalSlices
      .filter((slice) => criticalSliceGroupCoverage[slice] < spec.constraints.minimumCriticalSliceGroups)
      .map((slice) => (
        `critical slice "${slice}" groups ${criticalSliceGroupCoverage[slice]}`
        + ` < ${spec.constraints.minimumCriticalSliceGroups}`
      )),
  ];
  const inferenceAvailable = coverageFailures.length === 0;
  const groupedBootstrap = inferenceAvailable
    ? bootstrapGroupedWeightedMeanCI(caseEffects, {
      alpha: spec.bootstrap.alpha,
      seed: spec.bootstrap.seed,
      iters: spec.bootstrap.iterations,
    })
    : undefined;
  let effectiveTrafficMass = 0;
  let weightedEffect = 0;
  for (const effect of caseEffects) {
    effectiveTrafficMass += effect.trafficWeight;
    weightedEffect += effect.effect * effect.trafficWeight;
    if (!Number.isFinite(effectiveTrafficMass) || !Number.isFinite(weightedEffect)) {
      throw new Error("paired-quality traffic accumulation exceeds the finite numeric range");
    }
  }
  const estimate = groupedBootstrap?.estimate ?? weightedEffect / effectiveTrafficMass;
  const bootstrap = {
    mean: estimate,
    lo: groupedBootstrap?.interval.lo ?? null,
    hi: groupedBootstrap?.interval.hi ?? null,
    iters: spec.bootstrap.iterations,
    positive: (groupedBootstrap?.interval.lo ?? Number.NEGATIVE_INFINITY) > 0,
  };
  const pairedQuality: PairedQualityResult = {
    method: "paired-group-percentile-v1",
    alpha: spec.bootstrap.alpha,
    caseCount: pairedCases.length,
    replicateCount: replicateDeltas.length,
    groupCount,
    effectiveTrafficMass,
    deltas,
    replicateDeltas,
    caseEffects,
    criticalSliceGroupCoverage,
    estimate,
    interval: {
      lo: groupedBootstrap?.interval.lo ?? null,
      hi: groupedBootstrap?.interval.hi ?? null,
    },
    iterations: spec.bootstrap.iterations,
    seed: spec.bootstrap.seed,
    inferenceAvailable,
    ...(inferenceAvailable ? {} : { unavailableReason: `Coverage failed before inference: ${coverageFailures.join("; ")}` }),
    bootstrap,
  };
  const candidateMetrics = computePolicyMetrics(candidateRows, criticalSlices);
  const championMetrics = computePolicyMetrics(championRows, criticalSlices);
  const championCost = championMetrics.costPerRequestUsd;
  const costImprovement = championCost === 0
    ? null
    : (championCost - candidateMetrics.costPerRequestUsd) / championCost;

  const gates: GateResult[] = [
    gate(
      "paired_quality_non_inferiority",
      pairedQuality.interval.lo,
      spec.constraints.nonInferiorityMargin,
      ">=",
      pairedQuality.unavailableReason,
    ),
    gate(
      "minimum_independent_groups",
      groupCount,
      spec.constraints.minimumIndependentGroups,
      ">=",
    ),
    ...criticalSlices.map((slice) => gate(
      `critical_slice_groups:${slice}`,
      criticalSliceGroupCoverage[slice],
      spec.constraints.minimumCriticalSliceGroups,
      ">=",
    )),
    gate("mean_task_score", candidateMetrics.meanTaskScore, spec.constraints.taskScoreFloor, ">="),
    ...criticalSlices.map((slice) => gate(
      `critical_slice:${slice}`,
      candidateMetrics.criticalSliceTaskScore[slice],
      spec.constraints.criticalSliceScoreFloor,
      ">=",
      `critical_slice:${slice} has no replayed rows and fails closed`,
    )),
    gate("p95_ttft", candidateMetrics.p95TtftMs, spec.constraints.maxP95TtftMs, "<="),
    gate(
      "p95_end_to_end_latency",
      candidateMetrics.p95EndToEndLatencyMs,
      spec.constraints.maxP95EndToEndLatencyMs,
      "<=",
    ),
    gate(
      "p10_perceived_tps",
      candidateMetrics.p10PerceivedTokensPerSecond,
      spec.constraints.minP10PerceivedTokensPerSecond,
      ">=",
    ),
    serviceThroughputGate(
      candidateMetrics.p50TotalTokensPerSecond,
      spec.constraints.minP50TotalTokensPerSecond,
    ),
    gate("error_rate", candidateMetrics.errorRate, spec.constraints.maxErrorRate, "<="),
    gate(
      "cost_per_thousand",
      candidateMetrics.costPerThousandRequestsUsd,
      spec.constraints.maxCostPerThousandRequests,
      "<=",
    ),
  ];

  if (requireDevelopmentCostImprovement) {
    const developmentCostGate = gate(
      "development_cost_improvement",
      costImprovement,
      spec.constraints.minimumCostImprovement,
      ">=",
      championCost === 0
        ? "development_cost_improvement is undefined because champion cost is zero and fails closed"
        : undefined,
    );
    gates.push(developmentCostGate);
  }

  return {
    candidateMetrics,
    championMetrics,
    pairedQuality,
    costImprovement,
    gates,
    passed: gates.every((result) => result.pass),
  };
}

export function evaluatePolicy(
  candidateRows: ReplayedRow[],
  championRows: ReplayedRow[],
  spec: InferenceSpec,
  options: EvaluationOptions = {},
): PolicyEvaluation {
  assertDirectEvaluationWorkBudget(
    candidateRows,
    championRows,
    spec,
    options.workBudget ?? DEFAULT_ASSESSMENT_WORK_BUDGET,
  );
  return evaluatePolicyInternal(candidateRows, championRows, spec, true);
}

function digest(value: unknown): string {
  return sha256(canonicalJson(value));
}

function normalizedSpecForDigest(spec: InferenceSpec): InferenceSpec {
  const normalized = structuredClone(spec);
  normalized.profiles.sort((left, right) => compareCodeUnits(left.id, right.id));
  normalized.candidateSpace.confidenceThresholds = [
    ...new Set(normalized.candidateSpace.confidenceThresholds),
  ].sort((left, right) => left - right);
  normalized.candidateSpace.inputTokenThresholds = [
    ...new Set(normalized.candidateSpace.inputTokenThresholds),
  ].sort((left, right) => left - right);
  normalized.criticalSlices = [...new Set(normalized.criticalSlices)].sort(compareCodeUnits);
  return normalized;
}

function specDigest(spec: InferenceSpec): string {
  return digest(normalizedSpecForDigest(spec));
}

function legacySpecProjection(spec: InferenceSpec): unknown {
  const legacy = structuredClone(spec);
  const legacyConstraints = legacy.constraints as unknown as Record<string, unknown>;
  const legacyBootstrap = legacy.bootstrap as unknown as Record<string, unknown>;
  delete legacyConstraints.minimumIndependentGroups;
  delete legacyConstraints.minimumCriticalSliceGroups;
  delete legacyBootstrap.alpha;
  return legacy;
}

function hasLegacyDefaultInferenceControls(spec: InferenceSpec): boolean {
  return (
    spec.bootstrap.alpha === 0.05
    && spec.constraints.minimumIndependentGroups === 3
    && spec.constraints.minimumCriticalSliceGroups === (spec.criticalSlices.length === 0 ? 0 : 1)
  );
}

function normalizedMeasurementsForDigest(measurements: MeasurementSet): MeasurementSet {
  const normalized = structuredClone(measurements);
  normalized.cases = normalized.cases
    .map((measurementCase) => ({
      ...measurementCase,
      slices: [...measurementCase.slices].sort(compareCodeUnits),
      observations: [...measurementCase.observations]
        .sort((left, right) => compareCodeUnits(left.profileId, right.profileId)),
    }))
    .sort((left, right) => compareCodeUnits(left.id, right.id));
  return normalized;
}

function measurementDigest(measurements: MeasurementSet): string {
  return digest(normalizedMeasurementsForDigest(measurements));
}

function dominates(left: PolicyMetrics, right: PolicyMetrics): boolean {
  const higherIsBetter: Array<keyof PolicyMetrics> = [
    "meanTaskScore",
    "p10PerceivedTokensPerSecond",
    "p50TotalTokensPerSecond",
  ];
  const lowerIsBetter: Array<keyof PolicyMetrics> = [
    "errorRate",
    "p95TtftMs",
    "p95EndToEndLatencyMs",
    "costPerRequestUsd",
  ];
  const comparable = (value: unknown): value is number => typeof value === "number" && Number.isFinite(value);
  const neverWorse = (
    higherIsBetter.every((key) => (
      comparable(left[key]) && comparable(right[key]) && left[key] >= right[key]
    ))
    && lowerIsBetter.every((key) => (
      comparable(left[key]) && comparable(right[key]) && left[key] <= right[key]
    ))
  );
  const strictlyBetter = (
    higherIsBetter.some((key) => (
      comparable(left[key]) && comparable(right[key]) && left[key] > right[key]
    ))
    || lowerIsBetter.some((key) => (
      comparable(left[key]) && comparable(right[key]) && left[key] < right[key]
    ))
  );
  return neverWorse && strictlyBetter;
}

type NominationArtifactBody = Omit<NominationArtifact, "selfDigest" | "attestation">;

function artifactSelfDigest(artifact: NominationArtifactBody): string {
  return digest(artifact);
}

function validatedAttestationKey(key: string): Buffer {
  const bytes = Buffer.from(key, "utf8");
  if (bytes.byteLength < 32) {
    throw new Error("attestation key must be at least 32 UTF-8 bytes");
  }
  return bytes;
}

function attestationDigest(artifact: Omit<NominationArtifact, "attestation">, key: Buffer): string {
  return createHmac("sha256", key).update(canonicalJson(artifact)).digest("hex");
}

export function nominatePolicy(
  spec: InferenceSpec,
  dev: MeasurementSet,
  options: AttestationOptions = {},
): NominationResult {
  const attestationKey = options.attestationKey === undefined
    ? undefined
    : validatedAttestationKey(options.attestationKey);
  if (dev.dataset.split !== "dev") {
    throw new Error(`nomination requires development split "dev"; received "${dev.dataset.split}"`);
  }
  assertAssessmentWorkBudget(spec, dev, options.workBudget ?? DEFAULT_ASSESSMENT_WORK_BUDGET);
  assertMeasurementMatrix(spec, dev);

  const champion = championPolicy(spec);
  const championRows = replayPolicy(champion, spec, dev);
  const evaluations = generateCandidatePolicies(spec).map((policy): CandidateEvaluation => ({
    policy,
    evaluation: evaluatePolicy(replayPolicy(policy, spec, dev), championRows, spec, options),
  }));
  const passers = evaluations.filter(({ evaluation }) => evaluation.passed);
  const frontierEntries = passers.filter((candidate) => (
    !passers.some((other) => (
      other.policy.id !== candidate.policy.id
      && dominates(other.evaluation.candidateMetrics, candidate.evaluation.candidateMetrics)
    ))
  ));
  const orderedFrontier = [...frontierEntries].sort((left, right) => (
    left.evaluation.candidateMetrics.costPerRequestUsd
      - right.evaluation.candidateMetrics.costPerRequestUsd
    || left.evaluation.candidateMetrics.p95EndToEndLatencyMs
      - right.evaluation.candidateMetrics.p95EndToEndLatencyMs
    || compareCodeUnits(left.policy.id, right.policy.id)
  ));
  const frontier = frontierEntries.map(({ policy }) => policy.id).sort(compareCodeUnits);

  if (orderedFrontier.length === 0) {
    return { status: "NO_CANDIDATE", evaluations, frontier, nomination: undefined };
  }

  const selected = orderedFrontier[0];
  const resolvedSpecDigest = specDigest(spec);
  const policyDigest = fingerprintPolicy(selected.policy);
  const decisionDigest = digest({
    evaluations,
    frontier,
    selectedPolicyId: selected.policy.id,
  });
  const artifactBody: NominationArtifactBody = {
    version: "tasc-nomination-v1",
    specDigest: resolvedSpecDigest,
    developmentDatasetDigest: measurementDigest(dev),
    evaluator: structuredClone(dev.evaluator),
    developmentGroupIds: [...new Set(dev.cases.map((measurementCase) => measurementCase.groupId))]
      .sort(compareCodeUnits),
    developmentSynthetic: dev.dataset.synthetic,
    policy: structuredClone(selected.policy),
    policyDigest,
    candidateMetrics: structuredClone(selected.evaluation.candidateMetrics),
    championMetrics: structuredClone(selected.evaluation.championMetrics),
    gates: structuredClone(selected.evaluation.gates),
    decisionDigest,
  };
  const unsignedArtifact: Omit<NominationArtifact, "attestation"> = {
    ...artifactBody,
    selfDigest: artifactSelfDigest(artifactBody),
  };

  return {
    status: "NOMINATED",
    evaluations,
    frontier,
    nomination: {
      ...unsignedArtifact,
      ...(attestationKey === undefined ? {} : {
        attestation: {
          algorithm: "hmac-sha256",
          digest: attestationDigest(unsignedArtifact, attestationKey),
        } satisfies NominationAttestation,
      }),
    },
  };
}

function assertNominationSelfDigest(nomination: NominationArtifact): void {
  const { selfDigest, attestation: _attestation, ...body } = nomination;
  if (selfDigest !== artifactSelfDigest(body)) {
    throw new Error("nomination self-digest mismatch: artifact was edited after development selection");
  }
}

function verifyNominationAttestation(nomination: NominationArtifact, key: Buffer): void {
  const { attestation, ...unsignedArtifact } = nomination;
  const suppliedDigest = attestation?.digest;
  const expectedDigest = attestationDigest(unsignedArtifact, key);
  if (
    attestation?.algorithm !== "hmac-sha256"
    || suppliedDigest === undefined
    || !/^[a-f0-9]{64}$/.test(suppliedDigest)
  ) {
    throw new Error("nomination attestation mismatch");
  }
  const suppliedBytes = Buffer.from(suppliedDigest, "hex");
  const expectedBytes = Buffer.from(expectedDigest, "hex");
  if (!timingSafeEqual(suppliedBytes, expectedBytes)) {
    throw new Error("nomination attestation mismatch");
  }
}

function evaluatorMatches(
  left: MeasurementSet["evaluator"],
  right: MeasurementSet["evaluator"],
): boolean {
  return (
    left.id === right.id
    && left.version === right.version
    && left.kind === right.kind
    && left.validated === right.validated
  );
}

function isRegisteredLegacyCandidate(policy: InferencePolicy, spec: InferenceSpec): boolean {
  if (
    policy.version !== "tasc-policy-v1"
    || policy.kind === "expert-only"
    || policy.primaryProfileId !== spec.primaryProfileId
    || policy.expertProfileId !== spec.championProfileId
    || policy.criticalSlices.length !== spec.criticalSlices.length
    || policy.criticalSlices.some((slice, index) => slice !== spec.criticalSlices[index])
  ) {
    return false;
  }
  if (
    policy.kind === "fast-only"
      ? (
        !spec.candidateSpace.includeFastOnly
        || policy.confidenceThreshold !== undefined
        || policy.inputTokenThreshold !== undefined
      )
      : (
        policy.confidenceThreshold === undefined
        || policy.inputTokenThreshold === undefined
        || !spec.candidateSpace.confidenceThresholds.includes(policy.confidenceThreshold)
        || !spec.candidateSpace.inputTokenThresholds.includes(policy.inputTokenThreshold)
      )
  ) {
    return false;
  }
  const { id: _id, ...body } = policy;
  return policy.id === `${policy.kind}-${sha256(canonicalJson(body)).slice(0, 16)}`;
}

export function confirmNomination(
  spec: InferenceSpec,
  holdout: MeasurementSet,
  nomination: NominationArtifact,
  options: AttestationOptions = {},
): ConfirmationResult {
  const attestationKey = options.attestationKey === undefined
    ? undefined
    : validatedAttestationKey(options.attestationKey);
  if (holdout.dataset.split !== "holdout") {
    throw new Error(`confirmation requires holdout split "holdout"; received "${holdout.dataset.split}"`);
  }
  if (attestationKey !== undefined) {
    verifyNominationAttestation(nomination, attestationKey);
  }
  assertNominationSelfDigest(nomination);
  const attestationVerified = attestationKey !== undefined;
  assertAssessmentWorkBudget(spec, holdout, options.workBudget ?? DEFAULT_ASSESSMENT_WORK_BUDGET);

  const resolvedSpecDigest = specDigest(spec);
  const matchesLegacySpecDigest = (
    hasLegacyDefaultInferenceControls(spec)
    && nomination.specDigest === digest(legacySpecProjection(spec))
  );
  if (nomination.specDigest !== resolvedSpecDigest && !matchesLegacySpecDigest) {
    throw new Error("spec digest mismatch: nomination was produced from a different inference spec");
  }
  if (nomination.policyDigest !== fingerprintPolicy(nomination.policy)) {
    throw new Error("policy digest mismatch: nominated policy body was edited");
  }

  const regenerated = generateCandidatePolicies(spec).find((candidate) => (
    candidate.id === nomination.policy.id
    && fingerprintPolicy(candidate) === nomination.policyDigest
    && canonicalJson(candidate) === canonicalJson(nomination.policy)
  )) ?? (
    matchesLegacySpecDigest && isRegisteredLegacyCandidate(nomination.policy, spec)
      ? structuredClone(nomination.policy)
      : undefined
  );
  if (!regenerated) {
    throw new Error("policy drift: nomination does not exactly match a regenerated candidate");
  }
  if (!evaluatorMatches(nomination.evaluator, holdout.evaluator)) {
    throw new Error("evaluator drift: holdout evaluator identity, version, kind, and validation must match development");
  }

  const developmentGroups = new Set(nomination.developmentGroupIds);
  const leakedGroups = [...new Set(
    holdout.cases
      .map((measurementCase) => measurementCase.groupId)
      .filter((groupId) => developmentGroups.has(groupId)),
  )].sort(compareCodeUnits);
  if (leakedGroups.length > 0) {
    throw new Error(`development/holdout group leakage: ${leakedGroups.join(", ")}`);
  }
  assertMeasurementMatrix(spec, holdout);

  const championRows = replayPolicy(championPolicy(spec), spec, holdout);
  const candidateRows = replayPolicy(regenerated, spec, holdout);
  const evaluation = evaluatePolicyInternal(candidateRows, championRows, spec, false);
  let status: ConfirmationResult["status"];
  let statusReason: string;
  if (!evaluation.passed) {
    status = "HOLD";
    const failedGateIds = evaluation.gates.filter((gateResult) => !gateResult.pass).map((gateResult) => gateResult.id);
    statusReason = `Holdout hard gates failed: ${failedGateIds.join(", ")}`
      + (
        nomination.developmentSynthetic || holdout.dataset.synthetic
          ? ""
          : "; legacy v1 migration to a registered v2 protocol is required for any production recommendation"
      );
  } else if (nomination.developmentSynthetic || holdout.dataset.synthetic) {
    status = "DEMO_ONLY";
    statusReason = "Passing gates are demo-only because development or holdout evidence is synthetic";
  } else {
    status = "HOLD";
    statusReason = attestationVerified
      ? "Passing real legacy v1 evidence is capped at HOLD; migrate to a registered v2 protocol for any production recommendation"
      : "Production readiness requires migration from legacy v1 to a registered v2 protocol with verified attestation provenance";
  }
  const confirmationBody = {
    version: "tasc-confirmation-v1" as const,
    status,
    specDigest: resolvedSpecDigest,
    holdoutDatasetDigest: measurementDigest(holdout),
    nominationDigest: nomination.selfDigest,
    evaluator: structuredClone(holdout.evaluator),
    holdoutGroupIds: [...new Set(holdout.cases.map((measurementCase) => measurementCase.groupId))]
      .sort(compareCodeUnits),
    policy: structuredClone(regenerated),
    policyDigest: nomination.policyDigest,
    evaluation,
    attestationVerified,
    statusReason,
  };
  return {
    ...confirmationBody,
    decisionDigest: digest(confirmationBody),
  };
}
