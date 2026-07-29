import { canonicalJson, compareCodeUnits } from "./determinism.js";
import {
  deepFreezeContract,
  fingerprintExecutionProfile,
  fingerprintNormalizedProtocol,
  normalizeExperimentProtocol,
  snapshotBoundedContractInput,
  type DeepReadonly,
  type ExperimentProtocol,
} from "./evidence.js";
import {
  isAuthenticAssessmentDataset,
  type AssessmentDataset,
  type AssessmentExecutionRow,
  type DevelopmentAssessmentDataset,
  type EvidenceVerificationProvenance,
  type HoldoutAssessmentDataset,
  type OnlineAssessmentDataset,
} from "./evidence-join.js";
import {
  parseAssessmentContext,
  type AssessmentContext,
} from "./assessment-context.js";
import {
  fingerprintAssessmentDecisionContract,
  MAX_ASSESSMENT_DECISION_NODES,
  MAX_ASSESSMENT_DECISION_REPLAY_ROWS,
  parseAssessmentDecisionContract,
} from "./assessment-contract.js";
import {
  assertPolicyBundleMatchesProtocol,
  enumerateProtocolPolicyBundles,
  fingerprintPolicyBundle,
  parsePolicyBundleValue,
  protocolControlPolicyBundle,
  type PolicyBundle,
} from "./policy.js";
import {
  bootstrapGroupedWeightedMeanCI,
  bootstrapSeedFromString,
  median,
  weightedQuantile,
  type GroupedWeightedBootstrapCI,
  type WeightedValue,
} from "./statistics.js";
import {
  assertAcceptedEvaluatorEvidenceWithinWindowWatermark,
  assertTraceBelongsToWindow,
  assertWindowManifestMatchesProtocol,
  fingerprintWindowManifest,
  parseWindowManifest,
  type WindowManifest,
} from "./window.js";
import type { WorkBudget } from "./work-budget.js";

export type AssessmentPhase = "development" | "holdout" | "window";
export type AssessmentStatus =
  | "INSUFFICIENT_EVIDENCE"
  | "NO_CANDIDATE"
  | "NOMINATED"
  | "PASS"
  | "HOLD"
  | "STALE";
export type EvidenceClass =
  | "measured"
  | "reported"
  | "modeled"
  | "unavailable";

export interface AssessmentMetric {
  readonly value: number | null;
  readonly evidenceClass: EvidenceClass;
  readonly sourceDigest?: string;
  readonly reason?: string;
}

export interface AssessmentMetrics {
  readonly meanScore: AssessmentMetric;
  readonly failureRate: AssessmentMetric;
  readonly ttftMs: AssessmentMetric;
  readonly endToEndLatencyMs: AssessmentMetric;
  readonly costPerThousandRequestsUsd: AssessmentMetric;
  readonly evidenceCoverage: AssessmentMetric;
  readonly serviceCapacity: AssessmentMetric;
}

export interface AssessmentGate {
  readonly id: string;
  readonly operator: ">=" | "<=";
  readonly threshold: number;
  readonly actual: number | null;
  readonly evidenceClass: EvidenceClass;
  readonly passed: boolean;
  readonly reason?: string;
}

export interface PolicyReplayRow {
  readonly caseId: string;
  readonly replicateId: string;
  readonly groupId: string;
  readonly attemptedProfileIds: readonly string[];
  readonly selectedProfileId: string;
  readonly status: "success" | "failure";
  readonly escalated: boolean;
  readonly score: number | null;
  readonly scoreEvidenceClass: EvidenceClass;
  readonly trafficWeight: number;
  readonly slices: readonly string[];
  readonly ttftMs: number;
  readonly endToEndLatencyMs: number;
  readonly costUsd: number | null;
}

export interface CandidateAssessment {
  readonly policy: PolicyBundle;
  readonly policyDigest: string;
  readonly status: "PASS" | "HOLD" | "INSUFFICIENT_EVIDENCE" | "STALE";
  readonly replay: readonly PolicyReplayRow[];
  readonly metrics: AssessmentMetrics;
  readonly gates: readonly AssessmentGate[];
  readonly coverage: AssessmentCoverage;
  readonly inference: GroupedWeightedBootstrapCI | null;
  readonly insufficiencyReasons: readonly string[];
  readonly rejectionReasons: readonly string[];
}

export interface AssessmentEstimator {
  readonly method: "paired-group-percentile-v1";
  readonly alpha: number;
  readonly iterations: number;
  readonly seed: number;
}

export interface AssessmentCoverage {
  readonly caseCount: number;
  readonly replicateCount: number;
  readonly groupCount: number;
  readonly effectiveTrafficMass: number;
  readonly criticalSliceGroups: readonly {
    readonly sliceId: string;
    readonly groupCount: number;
  }[];
  readonly failureCount: number;
  readonly missingEvidenceCount: number;
  readonly evidenceCoverage: number;
}

export interface AssessmentDecision {
  readonly version: "tasc-assessment-decision-v2";
  readonly engineVersion: "tasc-assessment-engine-v2";
  readonly phase: AssessmentPhase;
  readonly status: AssessmentStatus;
  readonly assessmentContextDigest: string;
  readonly protocolDigest: string;
  readonly datasetDigest: string;
  readonly traceSetDigest: string;
  readonly evaluatorSetDigest: string;
  readonly windowManifestDigest: string | null;
  readonly estimator: AssessmentEstimator;
  readonly control: CandidateAssessment;
  readonly candidates: readonly CandidateAssessment[];
  readonly selectedPolicy: PolicyBundle | null;
  readonly selectedPolicyDigest: string | null;
  readonly staleReasons: readonly string[];
  readonly warnings: readonly string[];
  readonly unavailableMetrics: readonly string[];
  readonly attestation: "unattested";
  readonly decisionDigest: string;
}

type DevelopmentAssessmentDecisionBase = Omit<
  AssessmentDecision,
  | "phase"
  | "status"
  | "windowManifestDigest"
  | "selectedPolicy"
  | "selectedPolicyDigest"
> & {
  readonly phase: "development";
  readonly windowManifestDigest: null;
};

export type DevelopmentNomination = DevelopmentAssessmentDecisionBase & {
  readonly status: "NOMINATED";
  readonly selectedPolicy: PolicyBundle;
  readonly selectedPolicyDigest: string;
};

export type DevelopmentNonNomination =
  DevelopmentAssessmentDecisionBase & {
    readonly status:
      | "NO_CANDIDATE"
      | "INSUFFICIENT_EVIDENCE"
      | "STALE";
    readonly selectedPolicy: null;
    readonly selectedPolicyDigest: null;
  };

export type DevelopmentAssessmentDecision =
  | DevelopmentNomination
  | DevelopmentNonNomination;

export type HoldoutAssessmentDecision = Omit<
  AssessmentDecision,
  | "phase"
  | "status"
  | "windowManifestDigest"
  | "selectedPolicy"
  | "selectedPolicyDigest"
> & {
  readonly phase: "holdout";
  readonly status: "PASS" | "HOLD" | "INSUFFICIENT_EVIDENCE" | "STALE";
  readonly windowManifestDigest: null;
  readonly selectedPolicy: PolicyBundle;
  readonly selectedPolicyDigest: string;
};

export type WindowAssessmentDecision = Omit<
  AssessmentDecision,
  | "phase"
  | "status"
  | "windowManifestDigest"
  | "selectedPolicy"
  | "selectedPolicyDigest"
> & {
  readonly phase: "window";
  readonly status: "PASS" | "HOLD" | "INSUFFICIENT_EVIDENCE" | "STALE";
  readonly windowManifestDigest: string;
  readonly selectedPolicy: PolicyBundle;
  readonly selectedPolicyDigest: string;
};

export type FrozenAssessmentDecision = DeepReadonly<AssessmentDecision>;
export type FrozenDevelopmentAssessmentDecision = DeepReadonly<
  DevelopmentAssessmentDecision
>;
export type FrozenDevelopmentNomination = DeepReadonly<
  DevelopmentNomination
>;
export type FrozenHoldoutAssessmentDecision = DeepReadonly<
  HoldoutAssessmentDecision
>;
export type FrozenWindowAssessmentDecision = DeepReadonly<
  WindowAssessmentDecision
>;

type FrozenDecision = FrozenAssessmentDecision;

interface InternalReplayRow extends PolicyReplayRow {
  readonly scoreAvailable: boolean;
  readonly scoreEvidenceClass: EvidenceClass;
  readonly evidenceReason: string | null;
  readonly ttftEvidenceClass: EvidenceClass;
  readonly endToEndEvidenceClass: EvidenceClass;
  readonly costEvidenceClass: EvidenceClass;
}

interface ExecutionOperational {
  readonly ttftMs: number;
  readonly ttftEvidenceClass: EvidenceClass;
  readonly endToEndLatencyMs: number;
  readonly costUsd: number | null;
  readonly costEvidenceClass: EvidenceClass;
}

interface PolicyReplay {
  readonly rows: readonly InternalReplayRow[];
  readonly reasons: readonly string[];
}

interface ReplaySource {
  readonly byIdentity: ReadonlyMap<string, AssessmentExecutionRow>;
  readonly pairs: readonly {
    readonly caseId: string;
    readonly replicateId: string;
  }[];
}

const authenticAssessmentDecisions = new WeakSet<object>();

function checkedAdd(left: number, right: number, label: string): number {
  const value = left + right;
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error(`${label} arithmetic overflow`);
  }
  return value;
}

function checkedMultiply(
  left: number,
  right: number,
  label: string,
): number {
  if (
    !Number.isSafeInteger(left)
    || left < 0
    || !Number.isSafeInteger(right)
    || right < 0
    || (left !== 0 && right > Number.MAX_SAFE_INTEGER / left)
  ) {
    throw new Error(`${label} arithmetic overflow`);
  }
  return left * right;
}

function boundedSortFactor(length: number): number {
  if (!Number.isSafeInteger(length) || length < 0) {
    throw new Error("sort work length must be a safe non-negative integer");
  }
  let factor = 1;
  let capacity = 1;
  while (capacity < length) {
    capacity *= 2;
    factor += 1;
  }
  return factor;
}

function requireBudget(budget: WorkBudget): WorkBudget {
  const snapshot = snapshotBoundedContractInput(budget) as Record<
    string,
    unknown
  >;
  const keys = [
    "maxCandidates",
    "maxTraceRows",
    "maxEvidenceRows",
    "maxBootstrapDraws",
    "maxIndependentGroups",
    "maxAssessmentWork",
  ] as const;
  if (
    Object.keys(snapshot).length !== keys.length
    || keys.some((key) => (
      !Number.isSafeInteger(snapshot[key])
      || (snapshot[key] as number) < 0
    ))
  ) {
    throw new Error("assessment work budget must contain bounded integer limits");
  }
  return snapshot as unknown as WorkBudget;
}

function assertLimit(value: number, limit: number, label: string): void {
  if (value > limit) {
    throw new Error(
      `${label} exceeds caller work budget: ${value} > ${limit}`,
    );
  }
}

function assertAssessmentWorkBudget(
  protocol: ExperimentProtocol,
  dataset: AssessmentDataset,
  candidateCount: number,
  inputBudget: WorkBudget,
): void {
  const budget = requireBudget(inputBudget);
  const traceRows = dataset.counts.traceRows;
  const evidenceRows = dataset.counts.evidenceRows;
  const independentGroups = dataset.counts.groups;
  const bootstrapDraws = protocol.bootstrap.iterations;
  assertLimit(candidateCount, budget.maxCandidates, "candidate count");
  assertLimit(traceRows, budget.maxTraceRows, "trace rows");
  assertLimit(evidenceRows, budget.maxEvidenceRows, "evidence rows");
  assertLimit(bootstrapDraws, budget.maxBootstrapDraws, "bootstrap draws");
  assertLimit(
    independentGroups,
    budget.maxIndependentGroups,
    "independent groups",
  );

  // Every assessment computes one control plus each candidate/frozen policy.
  // The control replay is shared, so both modeled work and implementation have
  // exactly C + 1 replay and bootstrap passes.
  const assessmentCount = checkedAdd(
    candidateCount,
    1,
    "assessment count",
  );
  // Additive validation/output work remains charged when a dimension is zero.
  const validationWork = [
    traceRows,
    traceRows,
    evidenceRows,
    assessmentCount,
    independentGroups,
    dataset.counts.caseReplicates,
  ].reduce(
    (total, value) => checkedAdd(total, value, "assessment work"),
    0,
  );
  const pairSortWork = checkedMultiply(
    dataset.counts.caseReplicates,
    boundedSortFactor(dataset.counts.caseReplicates),
    "assessment pair sort work",
  );
  const candidateSortWork = checkedMultiply(
    candidateCount,
    boundedSortFactor(candidateCount),
    "assessment candidate sort work",
  );
  const indexedValidationWork = checkedAdd(
    checkedAdd(
      validationWork,
      pairSortWork,
      "assessment validation work",
    ),
    candidateSortWork,
    "assessment validation work",
  );
  // Replay, paired-coverage, operational-metric, gate, and digest preparation
  // each revisit bounded row sets. Charge a conservative fixed pass count plus
  // one full pass per critical slice instead of pretending replay is one scan.
  const rowPasses = checkedAdd(
    checkedAdd(
      24,
      protocol.criticalSlices.length,
      "assessment row passes",
    ),
    checkedMultiply(
      3,
      boundedSortFactor(dataset.counts.caseReplicates),
      "assessment row sort passes",
    ),
    "assessment row passes",
  );
  const replayWork = checkedMultiply(
    checkedMultiply(
      assessmentCount,
      dataset.counts.caseReplicates,
      "assessment replay work",
    ),
    rowPasses,
    "assessment replay work",
  );
  const bootstrapWork = checkedMultiply(
    assessmentCount,
    bootstrapDraws,
    "assessment bootstrap work",
  );
  const bootstrapPasses = checkedAdd(
    Math.max(1, independentGroups),
    boundedSortFactor(bootstrapDraws),
    "assessment bootstrap passes",
  );
  const groupedBootstrapWork = checkedMultiply(
    bootstrapWork,
    bootstrapPasses,
    "assessment bootstrap work",
  );
  const outputWork = checkedMultiply(
    assessmentCount,
    Math.max(1, dataset.counts.caseReplicates),
    "assessment output work",
  );
  const replayOutputRows = checkedMultiply(
    assessmentCount,
    dataset.counts.caseReplicates,
    "assessment replay output rows",
  );
  if (replayOutputRows > MAX_ASSESSMENT_DECISION_REPLAY_ROWS) {
    throw new Error(
      "assessment replay output exceeds the decision contract limit: "
      + `${replayOutputRows} > ${MAX_ASSESSMENT_DECISION_REPLAY_ROWS}`,
    );
  }
  const perAssessmentNodes = checkedAdd(
    512,
    checkedMultiply(
      protocol.criticalSlices.length,
      16,
      "assessment decision node estimate",
    ),
    "assessment decision node estimate",
  );
  const estimatedDecisionNodes = checkedAdd(
    checkedAdd(
      1_024,
      checkedMultiply(
        assessmentCount,
        perAssessmentNodes,
        "assessment decision node estimate",
      ),
      "assessment decision node estimate",
    ),
    checkedMultiply(
      replayOutputRows,
      128,
      "assessment decision node estimate",
    ),
    "assessment decision node estimate",
  );
  if (estimatedDecisionNodes > MAX_ASSESSMENT_DECISION_NODES) {
    throw new Error(
      "assessment output exceeds the decision contract node limit: "
      + `${estimatedDecisionNodes} > ${MAX_ASSESSMENT_DECISION_NODES}`,
    );
  }
  const outputContractWork = checkedMultiply(
    estimatedDecisionNodes,
    6,
    "assessment output contract work",
  );
  const total = checkedAdd(
    checkedAdd(
      checkedAdd(indexedValidationWork, replayWork, "assessment work"),
      groupedBootstrapWork,
      "assessment work",
    ),
    checkedAdd(outputWork, outputContractWork, "assessment work"),
    "assessment work",
  );
  assertLimit(total, budget.maxAssessmentWork, "assessment work");
}

function unavailable(reason: string): AssessmentMetric {
  return {
    value: null,
    evidenceClass: "unavailable",
    reason,
  };
}

function metric(
  value: number,
  evidenceClass: Exclude<EvidenceClass, "unavailable">,
): AssessmentMetric {
  if (!Number.isFinite(value)) return unavailable("non-finite-metric");
  return { value, evidenceClass };
}

const evidenceRank: Readonly<Record<EvidenceClass, number>> = {
  measured: 0,
  reported: 1,
  modeled: 2,
  unavailable: 3,
};

function weakestEvidenceClass(
  values: readonly EvidenceClass[],
): EvidenceClass {
  return values.reduce(
    (weakest, value) =>
      evidenceRank[value] > evidenceRank[weakest] ? value : weakest,
    "measured" as EvidenceClass,
  );
}

function elapsed(
  start: string,
  end: string,
  label: string,
): number {
  const milliseconds = Date.parse(end) - Date.parse(start);
  if (!Number.isFinite(milliseconds) || milliseconds < 0) {
    throw new Error(`${label} observer timing is invalid`);
  }
  return milliseconds;
}

function executionOperational(
  row: AssessmentExecutionRow,
): ExecutionOperational {
  const first = row.trace.attempts[0];
  const terminal = row.trace.attempts[row.trace.attempts.length - 1];
  const start = first.observerTimings.startedAt;
  const endToEndLatencyMs = elapsed(
    start,
    terminal.observerTimings.completedAt,
    `trace "${row.traceId}"`,
  );
  const meaningful = terminal.observerTimings.firstMeaningfulTokenAt;
  const successfulTtftMeasured =
    row.terminalStatus === "success" && meaningful !== null;
  const ttftMs = successfulTtftMeasured
    ? elapsed(start, meaningful, `trace "${row.traceId}" TTFT`)
    : endToEndLatencyMs;
  const ttftEvidenceClass: EvidenceClass = successfulTtftMeasured
    ? "measured"
    : "modeled";

  let cost = 0;
  const classes: EvidenceClass[] = [];
  for (const attempt of row.trace.attempts) {
    switch (attempt.cost.kind) {
      case "measured":
        cost += attempt.cost.amount;
        classes.push("measured");
        break;
      case "modeled":
        cost += attempt.cost.amount;
        classes.push("modeled");
        break;
      case "provider-reported":
        cost += attempt.cost.amount;
        classes.push("reported");
        break;
      case "unavailable":
        return {
          ttftMs,
          ttftEvidenceClass,
          endToEndLatencyMs,
          costUsd: null,
          costEvidenceClass: "unavailable",
        };
    }
    if (!Number.isFinite(cost)) {
      throw new Error("policy replay cost exceeds the finite numeric range");
    }
  }
  return {
    ttftMs,
    ttftEvidenceClass,
    endToEndLatencyMs,
    costUsd: cost,
    costEvidenceClass: weakestEvidenceClass(classes),
  };
}

function outcome(
  row: AssessmentExecutionRow,
): {
  readonly score: number | null;
  readonly available: boolean;
  readonly evidenceClass: EvidenceClass;
  readonly reason: string | null;
} {
  switch (row.outcome.kind) {
    case "scored":
      return {
        score: row.outcome.score,
        available: true,
        evidenceClass: "reported",
        reason: null,
      };
    case "protocol-failure-zero":
      if (row.terminalStatus === "success") {
        throw new Error(
          "successful execution cannot carry a failure-zero outcome",
        );
      }
      return {
        score: 0,
        available: true,
        evidenceClass: "modeled",
        reason: null,
      };
    case "ambiguous-execution":
      return {
        score: null,
        available: false,
        evidenceClass: "unavailable",
        reason: "ambiguous-execution",
      };
    case "abstained":
      return {
        score: null,
        available: false,
        evidenceClass: "unavailable",
        reason: "evaluator-abstention",
      };
    case "missing-evidence":
      return {
        score: null,
        available: false,
        evidenceClass: "unavailable",
        reason: "missing-evaluator-evidence",
      };
    case "invalid-evidence":
      return {
        score: null,
        available: false,
        evidenceClass: "unavailable",
        reason: "invalid-evaluator-evidence",
      };
  }
}

function executionIdentity(
  caseId: string,
  replicateId: string,
  profileId: string,
): string {
  return canonicalJson([caseId, replicateId, profileId]);
}

function pairIdentity(caseId: string, replicateId: string): string {
  return canonicalJson([caseId, replicateId]);
}

function indexExecutions(
  dataset: AssessmentDataset,
): ReadonlyMap<string, AssessmentExecutionRow> {
  const result = new Map<string, AssessmentExecutionRow>();
  for (const row of dataset.executions) {
    const key = executionIdentity(
      row.caseId,
      row.replicateId,
      row.profileId,
    );
    if (result.has(key)) {
      throw new Error("assessment dataset contains duplicate execution identity");
    }
    result.set(key, row);
  }
  return result;
}

function predicateMatches(
  predicate: PolicyBundle["predicates"][number],
  value: number,
): boolean {
  switch (predicate.operator) {
    case "less-than":
      return value < predicate.threshold;
    case "less-than-or-equal":
      return value <= predicate.threshold;
    case "greater-than":
      return value > predicate.threshold;
    case "greater-than-or-equal":
      return value >= predicate.threshold;
  }
}

function replayDirect(
  row: AssessmentExecutionRow,
  policy: PolicyBundle,
): InternalReplayRow {
  const operational = executionOperational(row);
  const assessed = outcome(row);
  return {
    caseId: row.caseId,
    replicateId: row.replicateId,
    groupId: row.groupId,
    attemptedProfileIds: [row.profileId],
    selectedProfileId: row.profileId,
    status: row.terminalStatus === "success" ? "success" : "failure",
    escalated: false,
    score: assessed.score,
    scoreAvailable: assessed.available,
    scoreEvidenceClass: policy.kind === "cascade" && assessed.available
      ? "modeled"
      : assessed.evidenceClass,
    evidenceReason: assessed.reason,
    trafficWeight: row.trace.workload.declaredTrafficWeight,
    slices: [...row.trace.slices].sort(compareCodeUnits),
    ttftMs: operational.ttftMs,
    endToEndLatencyMs: operational.endToEndLatencyMs,
    costUsd: operational.costUsd,
    ttftEvidenceClass: policy.kind === "cascade"
      ? "modeled"
      : operational.ttftEvidenceClass,
    endToEndEvidenceClass: policy.kind === "cascade"
      ? "modeled"
      : "measured",
    costEvidenceClass:
      policy.kind === "cascade"
      && operational.costEvidenceClass !== "unavailable"
        ? "modeled"
        : operational.costEvidenceClass,
  };
}

function combineFallback(
  primary: AssessmentExecutionRow,
  expert: AssessmentExecutionRow,
): InternalReplayRow {
  const primaryOperational = executionOperational(primary);
  const expertOperational = executionOperational(expert);
  const expertOutcome = outcome(expert);
  const costUsd = primaryOperational.costUsd === null
    || expertOperational.costUsd === null
    ? null
    : primaryOperational.costUsd + expertOperational.costUsd;
  return {
    caseId: primary.caseId,
    replicateId: primary.replicateId,
    groupId: primary.groupId,
    attemptedProfileIds: [primary.profileId, expert.profileId],
    selectedProfileId: expert.profileId,
    status: expert.terminalStatus === "success" ? "success" : "failure",
    escalated: true,
    score: expertOutcome.score,
    scoreAvailable: expertOutcome.available,
    scoreEvidenceClass: expertOutcome.available
      ? "modeled"
      : "unavailable",
    evidenceReason: expertOutcome.reason,
    trafficWeight: primary.trace.workload.declaredTrafficWeight,
    slices: [...primary.trace.slices].sort(compareCodeUnits),
    ttftMs:
      primaryOperational.endToEndLatencyMs + expertOperational.ttftMs,
    endToEndLatencyMs:
      primaryOperational.endToEndLatencyMs
      + expertOperational.endToEndLatencyMs,
    costUsd,
    ttftEvidenceClass: "modeled",
    endToEndEvidenceClass: "modeled",
    costEvidenceClass: costUsd === null
      ? "unavailable"
      : "modeled",
  };
}

function logicalPairs(
  dataset: AssessmentDataset,
): readonly {
  readonly caseId: string;
  readonly replicateId: string;
}[] {
  const pairs = new Map<string, {
    readonly caseId: string;
    readonly replicateId: string;
  }>();
  for (const row of dataset.executions) {
    const key = pairIdentity(row.caseId, row.replicateId);
    if (!pairs.has(key)) {
      pairs.set(key, {
        caseId: row.caseId,
        replicateId: row.replicateId,
      });
    }
  }
  return [...pairs.values()].sort((left, right) =>
    compareCodeUnits(left.caseId, right.caseId)
    || compareCodeUnits(left.replicateId, right.replicateId)
  );
}

function replayPolicy(
  policy: PolicyBundle,
  source: ReplaySource,
): PolicyReplay {
  const rows: InternalReplayRow[] = [];
  const reasons = new Set<string>();
  for (const pair of source.pairs) {
    const primary = source.byIdentity.get(executionIdentity(
      pair.caseId,
      pair.replicateId,
      policy.primaryProfileId,
    ));
    const expert = source.byIdentity.get(executionIdentity(
      pair.caseId,
      pair.replicateId,
      policy.expertProfileId,
    ));
    if (primary === undefined || expert === undefined) {
      reasons.add("missing-required-profile");
      continue;
    }

    if (policy.kind !== "cascade") {
      const selected = policy.kind === "expert-only" ? expert : primary;
      rows.push(replayDirect(selected, policy));
      continue;
    }
    const routeSignal = primary.trace.routeSignal;
    if (routeSignal === null) {
      reasons.add("missing-route-signal");
      continue;
    }
    const predicate = policy.predicates[0];
    if (predicateMatches(predicate, routeSignal.value)) {
      rows.push(replayDirect(expert, policy));
      continue;
    }
    if (primary.terminalStatus === "success") {
      rows.push(replayDirect(primary, policy));
      continue;
    }
    rows.push(combineFallback(primary, expert));
  }
  return {
    rows,
    reasons: [...reasons].sort(compareCodeUnits),
  };
}

function replicateCounts(
  rows: readonly InternalReplayRow[],
): ReadonlyMap<string, number> {
  const counts = new Map<string, number>();
  for (const row of rows) {
    counts.set(row.caseId, (counts.get(row.caseId) ?? 0) + 1);
  }
  return counts;
}

function rowWeights(
  rows: readonly InternalReplayRow[],
): readonly {
  readonly row: InternalReplayRow;
  readonly weight: number;
}[] {
  const counts = replicateCounts(rows);
  return rows.map((row) => ({
    row,
    weight: row.trafficWeight / (counts.get(row.caseId) ?? 1),
  }));
}

function weightedMean(
  values: readonly { readonly value: number; readonly weight: number }[],
): number {
  let numerator = 0;
  let mass = 0;
  for (const entry of values) {
    numerator += entry.value * entry.weight;
    mass += entry.weight;
    if (!Number.isFinite(numerator) || !Number.isFinite(mass)) {
      throw new Error("weighted metric exceeds the finite numeric range");
    }
  }
  return numerator / mass;
}

function operationalMetrics(
  rows: readonly InternalReplayRow[],
  serviceCapacity: AssessmentMetric,
  evidenceCoverage: AssessmentMetric,
): AssessmentMetrics {
  if (rows.length === 0) {
    return {
      meanScore: unavailable("no-replay-rows"),
      failureRate: unavailable("no-replay-rows"),
      ttftMs: unavailable("no-replay-rows"),
      endToEndLatencyMs: unavailable("no-replay-rows"),
      costPerThousandRequestsUsd: unavailable("no-replay-rows"),
      evidenceCoverage,
      serviceCapacity,
    };
  }
  const weighted = rowWeights(rows);
  const allScores = rows.every(({ scoreAvailable }) => scoreAvailable);
  const scoreClass = weakestEvidenceClass(
    rows.map(({ scoreEvidenceClass }) => scoreEvidenceClass),
  );
  const meanScore = allScores
    ? metric(weightedMean(weighted.map(({ row, weight }) => ({
      value: row.score ?? 0,
      weight,
    }))), scoreClass === "measured"
      ? "measured"
      : scoreClass === "reported" ? "reported" : "modeled")
    : unavailable("one or more policy outcomes lack score evidence");
  const ttftClass = weakestEvidenceClass(
    rows.map(({ ttftEvidenceClass }) => ttftEvidenceClass),
  );
  const endToEndClass = weakestEvidenceClass(
    rows.map(({ endToEndEvidenceClass }) => endToEndEvidenceClass),
  );
  const ttftValues: WeightedValue[] = weighted.map(({ row, weight }) => ({
    value: row.ttftMs,
    weight,
    identity: pairIdentity(row.caseId, row.replicateId),
  }));
  const endValues: WeightedValue[] = weighted.map(({ row, weight }) => ({
    value: row.endToEndLatencyMs,
    weight,
    identity: pairIdentity(row.caseId, row.replicateId),
  }));
  const costUnavailable = rows.some(({ costUsd }) => costUsd === null);
  const costClass = weakestEvidenceClass(
    rows.map(({ costEvidenceClass }) => costEvidenceClass),
  );
  return {
    meanScore,
    failureRate: metric(weightedMean(weighted.map(({ row, weight }) => ({
      value: row.status === "failure" ? 1 : 0,
      weight,
    }))), endToEndClass === "modeled" ? "modeled" : "measured"),
    ttftMs: metric(weightedQuantile(ttftValues, 0.95), ttftClass === "reported"
      ? "reported"
      : ttftClass === "modeled" ? "modeled" : "measured"),
    endToEndLatencyMs: metric(
      weightedQuantile(endValues, 0.95),
      endToEndClass === "reported"
        ? "reported"
        : endToEndClass === "modeled" ? "modeled" : "measured",
    ),
    costPerThousandRequestsUsd: costUnavailable
      ? unavailable("one or more attempted costs are unavailable")
      : metric(weightedMean(weighted.map(({ row, weight }) => ({
        value: (row.costUsd ?? 0) * 1_000,
        weight,
      }))), costClass === "measured"
        ? "measured"
        : costClass === "reported" ? "reported" : "modeled"),
    evidenceCoverage,
    serviceCapacity,
  };
}

function gate(
  id: string,
  actual: AssessmentMetric,
  threshold: number,
  operator: ">=" | "<=",
): AssessmentGate {
  const passed = actual.value !== null
    && (operator === ">="
      ? actual.value >= threshold
      : actual.value <= threshold);
  return {
    id,
    operator,
    threshold,
    actual: actual.value,
    evidenceClass: actual.evidenceClass,
    passed,
    ...(actual.reason === undefined ? {} : { reason: actual.reason }),
  };
}

function serviceCapacityFor(
  protocol: ExperimentProtocol,
  manifest: WindowManifest | null,
  policyDigest: string,
  phase: AssessmentPhase,
): {
  readonly metric: AssessmentMetric;
  readonly insufficiency: string | null;
} {
  const requirement = protocol.gates.serviceCapacity;
  if (requirement.kind === "disabled") {
    return {
      metric: unavailable("service-capacity-gate-disabled"),
      insufficiency: null,
    };
  }
  if (phase !== "window") {
    return {
      metric: unavailable(
        "service capacity is evaluated only from a sealed policy window",
      ),
      insufficiency: null,
    };
  }
  if (manifest?.capacityEvidence.kind !== "reported") {
    return {
      metric: unavailable(
        "exact-policy attested window service capacity is unavailable",
      ),
      insufficiency: "required-service-capacity-unavailable",
    };
  }
  if (manifest.frozenPolicyDigest !== policyDigest) {
    return {
      metric: unavailable(
        "window capacity declaration belongs to a different policy",
      ),
      insufficiency: "required-service-capacity-unavailable",
    };
  }
  // A self-digested manifest proves byte integrity, not measurement
  // authenticity. P0 records this input honestly as operator-reported; a P1
  // runtime adapter must supply a locally verified receipt before a measured
  // hard gate can pass.
  return {
    metric: unavailable(
      "window capacity declaration lacks trusted measurement attestation",
    ),
    insufficiency: "required-service-capacity-unavailable",
  };
}

function evidenceReasonSet(
  rows: readonly InternalReplayRow[],
): Set<string> {
  const reasons = new Set<string>();
  for (const row of rows) {
    if (row.evidenceReason !== null) reasons.add(row.evidenceReason);
  }
  return reasons;
}

function candidateAssessment(
  policy: PolicyBundle,
  candidateReplay: PolicyReplay,
  controlReplay: PolicyReplay,
  protocol: ExperimentProtocol,
  manifest: WindowManifest | null,
  phase: AssessmentPhase,
): CandidateAssessment {
  const reasons = new Set(candidateReplay.reasons);
  for (const reason of controlReplay.reasons) reasons.add(reason);
  for (const reason of evidenceReasonSet(candidateReplay.rows)) {
    reasons.add(reason);
  }
  for (const reason of evidenceReasonSet(controlReplay.rows)) {
    reasons.add(reason);
  }

  const capacity = serviceCapacityFor(
    protocol,
    manifest,
    policy.policyDigest,
    phase,
  );
  if (capacity.insufficiency !== null) reasons.add(capacity.insufficiency);

  const eligibleCandidate = new Map(
    candidateReplay.rows
      .filter(({ scoreAvailable }) => scoreAvailable)
      .map((row) => [pairIdentity(row.caseId, row.replicateId), row]),
  );
  const eligibleControl = new Map(
    controlReplay.rows
      .filter(({ scoreAvailable }) => scoreAvailable)
      .map((row) => [pairIdentity(row.caseId, row.replicateId), row]),
  );
  const paired = [...eligibleCandidate.entries()]
    .filter(([key]) => eligibleControl.has(key))
    .map(([, row]) => row);
  const sameReplay = candidateReplay === controlReplay;
  const evidenceRows = sameReplay
    ? candidateReplay.rows
    : [...candidateReplay.rows, ...controlReplay.rows];
  const coveredEvidenceCount = evidenceRows.filter(
    ({ scoreAvailable }) => scoreAvailable,
  ).length;
  const missingEvidenceCount = evidenceRows.filter(
    ({ scoreAvailable }) => !scoreAvailable,
  ).length;
  const evidenceCoverageValue = evidenceRows.length === 0
    ? 0
    : coveredEvidenceCount / evidenceRows.length;
  const evidenceCoverageMetric = evidenceRows.length === 0
    ? unavailable("no-policy-outcome-evidence")
    : metric(evidenceCoverageValue, "measured");
  const metrics = operationalMetrics(
    candidateReplay.rows,
    capacity.metric,
    evidenceCoverageMetric,
  );
  if (
    metrics.evidenceCoverage.value === null
    || metrics.evidenceCoverage.value < protocol.gates.minimumEvidenceCoverage
  ) {
    reasons.add("insufficient-evaluator-coverage");
  }
  if (metrics.costPerThousandRequestsUsd.value === null) {
    reasons.add("required-cost-evidence-unavailable");
  }
  const groupCount = new Set(paired.map(({ groupId }) => groupId)).size;
  if (groupCount < protocol.gates.minimumIndependentGroups) {
    reasons.add("insufficient-independent-groups");
  }
  const criticalSliceGroups = new Map<string, number>();
  for (const slice of protocol.criticalSlices) {
    const count = new Set(
      paired
        .filter(({ slices }) => slices.includes(slice))
        .map(({ groupId }) => groupId),
    ).size;
    criticalSliceGroups.set(slice, count);
    if (count < protocol.gates.minimumCriticalSliceGroups) {
      reasons.add(`insufficient-critical-slice-groups:${slice}`);
    }
  }
  const pairedCases = new Map<string, InternalReplayRow>();
  for (const row of paired) {
    if (!pairedCases.has(row.caseId)) pairedCases.set(row.caseId, row);
  }
  let inference: GroupedWeightedBootstrapCI | null = null;
  if (reasons.size === 0) {
    const replicateDeltas = paired.map((row) => {
      const control = eligibleControl.get(
        pairIdentity(row.caseId, row.replicateId),
      );
      if (
        control === undefined
        || control.score === null
        || row.score === null
      ) {
        throw new Error("eligible paired score unexpectedly missing");
      }
      return {
        caseId: row.caseId,
        replicateId: row.replicateId,
        groupId: row.groupId,
        trafficWeight: row.trafficWeight,
        delta: row.score - control.score,
      };
    });
    const byCase = new Map<string, typeof replicateDeltas>();
    for (const row of replicateDeltas) {
      const existing = byCase.get(row.caseId);
      if (existing === undefined) byCase.set(row.caseId, [row]);
      else existing.push(row);
    }
    const caseEffects = [...byCase.entries()]
      .sort(([left], [right]) => compareCodeUnits(left, right))
      .map(([caseId, replicates]) => ({
        caseId,
        groupId: replicates[0].groupId,
        trafficWeight: replicates[0].trafficWeight,
        effect: median(replicates.map(({ delta }) => delta)),
      }));
    inference = bootstrapGroupedWeightedMeanCI(caseEffects, {
      alpha: protocol.bootstrap.alpha,
      iters: protocol.bootstrap.iterations,
      seed: bootstrapSeedFromString(protocol.bootstrap.seed),
      replicateCount: paired.length,
    });
  }

  const effectiveTrafficMass = inference?.effectiveTrafficMass
    ?? [...pairedCases.values()].reduce(
      (total, row) => {
        const value = total + row.trafficWeight;
        if (!Number.isFinite(value)) {
          throw new Error(
            "coverage traffic mass exceeds the finite numeric range",
          );
        }
        return value;
      },
      0,
    );
  const coverage: AssessmentCoverage = {
    caseCount: pairedCases.size,
    replicateCount: paired.length,
    groupCount,
    effectiveTrafficMass,
    criticalSliceGroups: [...criticalSliceGroups.entries()]
      .sort(([left], [right]) => compareCodeUnits(left, right))
      .map(([sliceId, count]) => ({ sliceId, groupCount: count })),
    failureCount: candidateReplay.rows.filter(
      ({ status }) => status === "failure",
    ).length,
    missingEvidenceCount,
    evidenceCoverage: evidenceCoverageValue,
  };

  const pairedQualityMetric: AssessmentMetric = inference === null
    ? unavailable("coverage failed before statistical inference")
    : metric(inference.interval.lo, "modeled");
  const gates: AssessmentGate[] = [
    gate(
      "paired-quality",
      pairedQualityMetric,
      protocol.gates.nonInferiorityMargin,
      ">=",
    ),
    gate(
      "minimum-mean-score",
      metrics.meanScore,
      protocol.gates.minimumMeanScore,
      ">=",
    ),
    gate(
      "maximum-failure-rate",
      metrics.failureRate,
      protocol.gates.maximumFailureRate,
      "<=",
    ),
    gate(
      "maximum-p95-ttft",
      metrics.ttftMs,
      protocol.gates.maximumP95TtftMs,
      "<=",
    ),
    gate(
      "maximum-p95-end-to-end",
      metrics.endToEndLatencyMs,
      protocol.gates.maximumP95EndToEndMs,
      "<=",
    ),
    gate(
      "maximum-cost-per-thousand",
      metrics.costPerThousandRequestsUsd,
      protocol.gates.maximumCostPerThousandRequestsUsd,
      "<=",
    ),
    gate(
      "minimum-evidence-coverage",
      metrics.evidenceCoverage,
      protocol.gates.minimumEvidenceCoverage,
      ">=",
    ),
    gate(
      "minimum-independent-groups",
      metric(groupCount, "measured"),
      protocol.gates.minimumIndependentGroups,
      ">=",
    ),
    ...[...criticalSliceGroups.entries()]
      .sort(([left], [right]) => compareCodeUnits(left, right))
      .map(([slice, count]) => gate(
        `minimum-critical-slice-groups:${slice}`,
        metric(count, "measured"),
        protocol.gates.minimumCriticalSliceGroups,
        ">=",
      )),
  ];
  if (
    phase === "window"
    && protocol.gates.serviceCapacity.kind !== "disabled"
  ) {
    gates.push(gate(
      "minimum-service-capacity",
      metrics.serviceCapacity,
      protocol.gates.serviceCapacity.minimum,
      ">=",
    ));
  }

  const insufficiencyReasons = [...reasons].sort(compareCodeUnits);
  const passed = insufficiencyReasons.length === 0
    && gates.every(({ passed: gatePassed }) => gatePassed);
  const rejectionReasons = [
    ...insufficiencyReasons,
    ...gates
      .filter(({ passed: gatePassed }) => !gatePassed)
      .map(({ id }) => `failed-gate:${id}`),
  ].sort(compareCodeUnits);
  return deepFreezeContract({
    policy,
    policyDigest: policy.policyDigest,
    status: insufficiencyReasons.length > 0
      ? "INSUFFICIENT_EVIDENCE"
      : passed ? "PASS" : "HOLD",
    replay: candidateReplay.rows.map(({
      scoreAvailable: _scoreAvailable,
      evidenceReason: _evidenceReason,
      ttftEvidenceClass: _ttftEvidenceClass,
      endToEndEvidenceClass: _endToEndEvidenceClass,
      costEvidenceClass: _costEvidenceClass,
      ...row
    }) => row),
    metrics,
    gates,
    coverage,
    inference,
    insufficiencyReasons,
    rejectionReasons,
  });
}

function staleCandidate(
  policy: PolicyBundle,
  staleReasons: readonly string[],
): CandidateAssessment {
  const metrics: AssessmentMetrics = {
    meanScore: unavailable("stale-assessment"),
    failureRate: unavailable("stale-assessment"),
    ttftMs: unavailable("stale-assessment"),
    endToEndLatencyMs: unavailable("stale-assessment"),
    costPerThousandRequestsUsd: unavailable("stale-assessment"),
    evidenceCoverage: unavailable("stale-assessment"),
    serviceCapacity: unavailable("stale-assessment"),
  };
  return deepFreezeContract({
    policy,
    policyDigest: policy.policyDigest,
    status: "STALE",
    replay: [],
    metrics,
    gates: [],
    coverage: {
      caseCount: 0,
      replicateCount: 0,
      groupCount: 0,
      effectiveTrafficMass: 0,
      criticalSliceGroups: [],
      failureCount: 0,
      missingEvidenceCount: 0,
      evidenceCoverage: 0,
    },
    inference: null,
    insufficiencyReasons: [],
    rejectionReasons: [...staleReasons],
  });
}

function finishDecision(
  body: Omit<AssessmentDecision, "decisionDigest">,
): FrozenDecision {
  const decision = parseAssessmentDecisionContract({
    ...body,
    decisionDigest: fingerprintAssessmentDecisionContract(body),
  }) as FrozenDecision;
  authenticAssessmentDecisions.add(decision);
  return decision;
}

function staleReasonsFor(
  protocol: ExperimentProtocol,
  dataset: AssessmentDataset,
  context: AssessmentContext,
  frozenPolicy: PolicyBundle | null,
  manifest: WindowManifest | null,
): string[] {
  const reasons: string[] = [];
  const assessmentCutoff = Date.parse(context.asOf);
  const protocolDigest = fingerprintNormalizedProtocol(protocol);
  if (
    dataset.protocolDigest !== protocolDigest
    || dataset.studyId !== protocol.studyId
  ) {
    reasons.push("protocol-or-study-drift");
  }
  if (
    dataset.assessmentContextDigest !== null
    && dataset.assessmentContextDigest !== context.contextDigest
  ) {
    reasons.push("assessment-context-drift");
  }
  if (dataset.verificationContextIdentities.length > 1) {
    reasons.push("evaluator-verification-context-drift");
  }
  if (Date.parse(context.asOf) < Date.parse(protocol.createdAt)) {
    reasons.push("protocol-not-yet-valid");
  }
  if (Date.parse(context.asOf) >= Date.parse(protocol.expiresAt)) {
    reasons.push("protocol-expired");
  }
  if (
    frozenPolicy !== null
    && Date.parse(frozenPolicy.issuedAt) > assessmentCutoff
  ) {
    reasons.push("policy-not-yet-valid");
  }
  if (manifest !== null) {
    if (
      Date.parse(manifest.eventTimeEndExclusive) > assessmentCutoff
      || Date.parse(manifest.ingestionWatermark) > assessmentCutoff
    ) {
      reasons.push("window-not-yet-sealed-at-assessment-time");
    }
    if (
      frozenPolicy !== null
      && Date.parse(frozenPolicy.issuedAt)
        > Date.parse(manifest.eventTimeStartInclusive)
    ) {
      reasons.push("policy-issued-after-window-start");
    }
  }
  const staleVerificationStatuses = new Set([
    "revoked",
    "stale",
    "future-dated",
    "key-not-yet-valid",
    "key-expired",
  ]);
  const inspectVerification = (
    verification: EvidenceVerificationProvenance | null,
  ): void => {
    if (verification === null || !verification.authentic) return;
    if (
      verification.status === "context-mismatch"
      || verification.assessmentContextDigest !== context.contextDigest
      || verification.assessedAt !== context.asOf
      || verification.operatorTrustPolicySnapshotDigest
        !== context.operatorTrustPolicySnapshotDigest
      || verification.evaluatorRevocationSnapshotDigest
        !== context.evaluatorRevocationSnapshotDigest
    ) {
      reasons.push("evaluator-verification-context-drift");
    }
    if (staleVerificationStatuses.has(verification.status)) {
      reasons.push(`evaluator-evidence-${verification.status}`);
    }
  };
  for (const row of dataset.executions) {
    const terminal = row.trace.attempts[row.trace.attempts.length - 1];
    if (
      Date.parse(terminal.observerTimings.completedAt) > assessmentCutoff
    ) {
      reasons.push("trace-completed-after-assessment-cutoff");
    }
    const profile = protocol.profiles.find(({ id }) => id === row.profileId);
    if (
      profile === undefined
      || fingerprintExecutionProfile(profile)
        !== row.trace.executionProfileDigest
    ) {
      reasons.push("execution-profile-drift");
    }
    if ("verification" in row.outcome) {
      inspectVerification(row.outcome.verification);
      if (
        row.outcome.evidence !== null
        && Date.parse(row.outcome.evidence.producedAt) > assessmentCutoff
      ) {
        reasons.push("evaluator-evidence-produced-after-assessment-cutoff");
      }
    }
  }
  for (const diagnostic of [
    ...dataset.diagnostics.invalidEvidence,
    ...dataset.diagnostics.orphanEvidence,
  ]) {
    inspectVerification(diagnostic.verification);
  }
  for (const conflict of dataset.diagnostics.conflictingEvidence) {
    for (const row of conflict.rows) inspectVerification(row.verification);
  }
  for (const duplicate of dataset.diagnostics.duplicateEvidence) {
    inspectVerification(duplicate.row.verification);
  }
  return [...new Set(reasons)].sort(compareCodeUnits);
}

function assertAssessmentDatasetIntegrity(dataset: AssessmentDataset): void {
  const globalReasons = dataset.admissibility.blockingReasons.filter(
    (reason) => [
      "orphan-evaluator-evidence",
      "duplicate-evaluator-evidence",
      "conflicting-evaluator-evidence",
      "duplicate-traces",
      "conflicting-traces",
    ].includes(reason),
  );
  if (globalReasons.length > 0) {
    throw new Error(
      "assessment dataset failed structural integrity: "
      + globalReasons.join(", "),
    );
  }
}

function assertPhase(
  dataset: AssessmentDataset,
  expected: "dev" | "holdout" | "online",
): void {
  if (
    dataset.executions.some(({ split }) => split !== expected)
    || dataset.pairs.some(({ split }) => split !== expected)
  ) {
    throw new Error(
      `${expected === "dev" ? "development" : expected} assessment accepts `
      + `${expected} split evidence only`,
    );
  }
}

function selectDevelopmentCandidate(
  candidates: readonly CandidateAssessment[],
): CandidateAssessment | null {
  const passing = candidates.filter(({ status }) => status === "PASS");
  passing.sort((left, right) => {
    const leftCost = left.metrics.costPerThousandRequestsUsd.value
      ?? Number.POSITIVE_INFINITY;
    const rightCost = right.metrics.costPerThousandRequestsUsd.value
      ?? Number.POSITIVE_INFINITY;
    return (
      leftCost - rightCost
      || (left.metrics.endToEndLatencyMs.value ?? Number.POSITIVE_INFINITY)
        - (right.metrics.endToEndLatencyMs.value
          ?? Number.POSITIVE_INFINITY)
      || compareCodeUnits(left.policyDigest, right.policyDigest)
    );
  });
  return passing[0] ?? null;
}

function unavailableMetricNames(
  candidates: readonly CandidateAssessment[],
): string[] {
  const names = new Set<string>();
  for (const candidate of candidates) {
    for (const [name, value] of Object.entries(candidate.metrics)) {
      if (value.evidenceClass === "unavailable") names.add(name);
    }
  }
  return [...names].sort(compareCodeUnits);
}

function assessmentWarnings(
  phase: AssessmentPhase,
  protocol: ExperimentProtocol,
  manifest: WindowManifest | null,
  candidates: readonly CandidateAssessment[],
): string[] {
  const warnings = new Set<string>();
  if (
    phase !== "window"
    && protocol.gates.serviceCapacity.kind !== "disabled"
  ) {
    warnings.add("service-capacity-gate-deferred-to-sealed-window");
  }
  if (manifest?.capacityEvidence.kind === "reported") {
    warnings.add("operator-reported-capacity-declaration-ignored");
  }
  if (candidates.some(({ inference }) => inference?.groupCount === 1)) {
    warnings.add("single-independent-group-produces-degenerate-bootstrap");
  }
  return [...warnings].sort(compareCodeUnits);
}

function assess(
  phase: AssessmentPhase,
  protocolInput: ExperimentProtocol,
  dataset: AssessmentDataset,
  contextInput: AssessmentContext,
  budget: WorkBudget,
  frozenPolicy: PolicyBundle | null,
  manifest: WindowManifest | null,
): FrozenDecision {
  if (!isAuthenticAssessmentDataset(dataset)) {
    throw new Error("assessment requires an authentic joined assessment dataset");
  }
  const protocol = normalizeExperimentProtocol(protocolInput);
  const context = parseAssessmentContext(contextInput);
  const protocolDigest = fingerprintNormalizedProtocol(protocol);
  const candidateCount = phase === "development"
    ? protocol.candidateProfileIds.length
      * (protocol.candidatePolicySpace.predicates.length + 1)
    : 1;
  assertAssessmentWorkBudget(
    protocol,
    dataset,
    candidateCount,
    budget,
  );
  assertPhase(
    dataset,
    phase === "development" ? "dev" : phase === "holdout"
      ? "holdout"
      : "online",
  );
  const issueTime = (
    Date.parse(context.asOf) >= Date.parse(protocol.createdAt)
    && Date.parse(context.asOf) < Date.parse(protocol.expiresAt)
  )
    ? context.asOf
    : protocol.createdAt;
  const policySpace = phase === "development"
    ? enumerateProtocolPolicyBundles(
      protocol,
      protocolDigest,
      issueTime,
    )
    : null;
  const controlPolicy = policySpace?.control
    ?? protocolControlPolicyBundle(protocol, protocolDigest, issueTime);
  let policies: readonly PolicyBundle[];
  if (phase === "development") {
    policies = policySpace!.candidates;
  } else {
    if (frozenPolicy === null) {
      throw new Error(`${phase} assessment requires exactly one frozen policy`);
    }
    const policy = parsePolicyBundleValue(frozenPolicy);
    assertPolicyBundleMatchesProtocol(policy, protocol);
    policies = [policy];
  }

  let normalizedManifest: WindowManifest | null = null;
  if (phase === "window") {
    if (manifest === null || frozenPolicy === null) {
      throw new Error("window assessment requires one frozen policy and manifest");
    }
    normalizedManifest = parseWindowManifest(manifest);
    assertWindowManifestMatchesProtocol(
      normalizedManifest,
      protocol,
      policies[0].policyDigest,
    );
    if (normalizedManifest.traceSetDigest !== dataset.traceSetDigest) {
      throw new Error("window manifest trace-set digest conflicts with trace source");
    }
    if (
      normalizedManifest.evaluatorSetDigest !== dataset.evaluatorSetDigest
    ) {
      throw new Error(
        "window manifest evaluator-set digest conflicts with evaluator source",
      );
    }
  }

  const staleReasons = staleReasonsFor(
    protocol,
    dataset,
    context,
    phase === "development" ? null : policies[0],
    normalizedManifest,
  );
  if (staleReasons.length === 0) {
    assertAssessmentDatasetIntegrity(dataset);
  }
  if (normalizedManifest !== null && staleReasons.length === 0) {
    for (const row of dataset.executions) {
      assertTraceBelongsToWindow(row.trace, normalizedManifest);
      if (
        "evidenceAccepted" in row.outcome
        && row.outcome.evidenceAccepted
        && row.outcome.evidence !== null
      ) {
        assertAcceptedEvaluatorEvidenceWithinWindowWatermark(
          row.outcome.evidence,
          normalizedManifest,
        );
      }
    }
  }

  const replaySource: ReplaySource | null = staleReasons.length > 0
    ? null
    : {
      byIdentity: indexExecutions(dataset),
      pairs: logicalPairs(dataset),
    };
  const controlReplay = replaySource === null
    ? null
    : replayPolicy(controlPolicy, replaySource);
  const control = staleReasons.length > 0
    ? staleCandidate(controlPolicy, staleReasons)
    : candidateAssessment(
      controlPolicy,
      controlReplay!,
      controlReplay!,
      protocol,
      normalizedManifest,
      phase,
    );
  const candidates = policies.map((policy) =>
    staleReasons.length > 0
      ? staleCandidate(policy, staleReasons)
      : candidateAssessment(
        policy,
        policy.policyDigest === controlPolicy.policyDigest
          ? controlReplay!
          : replayPolicy(policy, replaySource!),
        controlReplay!,
        protocol,
        normalizedManifest,
        phase,
      )
  );

  let status: AssessmentStatus;
  let selected: CandidateAssessment | null;
  if (staleReasons.length > 0) {
    status = "STALE";
    selected = null;
  } else if (phase === "development") {
    selected = selectDevelopmentCandidate(candidates);
    if (selected !== null) status = "NOMINATED";
    else if (candidates.every(({ status: value }) =>
      value === "INSUFFICIENT_EVIDENCE"
    )) status = "INSUFFICIENT_EVIDENCE";
    else status = "NO_CANDIDATE";
  } else {
    selected = candidates[0];
    status = selected.status === "PASS"
      ? "PASS"
      : selected.status === "HOLD"
        ? "HOLD"
        : selected.status;
  }
  const selectedPolicy = phase === "development"
    ? selected?.policy ?? null
    : policies[0];
  const selectedPolicyDigest = selectedPolicy?.policyDigest ?? null;
  return finishDecision({
    version: "tasc-assessment-decision-v2",
    engineVersion: "tasc-assessment-engine-v2",
    phase,
    status,
    assessmentContextDigest: context.contextDigest,
    protocolDigest,
    datasetDigest: dataset.datasetDigest,
    traceSetDigest: dataset.traceSetDigest,
    evaluatorSetDigest: dataset.evaluatorSetDigest,
    windowManifestDigest: normalizedManifest === null
      ? null
      : fingerprintWindowManifest(normalizedManifest),
    estimator: {
      method: "paired-group-percentile-v1",
      alpha: protocol.bootstrap.alpha,
      iterations: protocol.bootstrap.iterations,
      seed: bootstrapSeedFromString(protocol.bootstrap.seed),
    },
    control,
    candidates,
    selectedPolicy,
    selectedPolicyDigest,
    staleReasons,
    warnings: assessmentWarnings(
      phase,
      protocol,
      normalizedManifest,
      candidates,
    ),
    unavailableMetrics: unavailableMetricNames(candidates),
    attestation: "unattested",
  });
}

export function nominateDevelopment(
  protocol: ExperimentProtocol,
  dataset: DevelopmentAssessmentDataset,
  assessmentContext: AssessmentContext,
  workBudget: WorkBudget,
): FrozenDevelopmentAssessmentDecision {
  return assess(
    "development",
    protocol,
    dataset,
    assessmentContext,
    workBudget,
    null,
    null,
  ) as FrozenDevelopmentAssessmentDecision;
}

export function confirmHoldout(
  protocol: ExperimentProtocol,
  dataset: HoldoutAssessmentDataset,
  nomination: FrozenDevelopmentNomination,
  assessmentContext: AssessmentContext,
  workBudget: WorkBudget,
): FrozenHoldoutAssessmentDecision {
  if (
    !isDevelopmentNomination(nomination)
  ) {
    throw new Error("holdout confirmation requires an authentic nomination");
  }
  return assess(
    "holdout",
    protocol,
    dataset,
    assessmentContext,
    workBudget,
    nomination.selectedPolicy,
    null,
  ) as FrozenHoldoutAssessmentDecision;
}

export function assessPolicyWindow(
  protocol: ExperimentProtocol,
  dataset: OnlineAssessmentDataset,
  frozenPolicy: PolicyBundle,
  windowManifest: WindowManifest,
  assessmentContext: AssessmentContext,
  workBudget: WorkBudget,
): FrozenWindowAssessmentDecision {
  return assess(
    "window",
    protocol,
    dataset,
    assessmentContext,
    workBudget,
    frozenPolicy,
    windowManifest,
  ) as FrozenWindowAssessmentDecision;
}

export function parsePolicyBundle(input: unknown): PolicyBundle {
  return parsePolicyBundleValue(input);
}

export function fingerprintAssessmentDecision(input: unknown): string {
  return fingerprintAssessmentDecisionContract(input);
}

export function parseAssessmentDecision(input: unknown): FrozenDecision {
  return parseAssessmentDecisionContract(input) as FrozenDecision;
}

export function isDevelopmentNomination(
  value: unknown,
): value is FrozenDevelopmentNomination {
  return (
    isAuthenticAssessmentDecision(value)
    && value.phase === "development"
    && value.status === "NOMINATED"
    && value.selectedPolicy !== null
    && value.selectedPolicyDigest !== null
  );
}

/**
 * Restore a persisted nomination without trusting its self-digest alone:
 * strictly parse it, rerun development from authentic source evidence, and
 * require the complete deterministic decision identity to match.
 */
export function revalidateDevelopmentNomination(
  protocol: ExperimentProtocol,
  developmentDataset: DevelopmentAssessmentDataset,
  persistedNomination: unknown,
  assessmentContext: AssessmentContext,
  workBudget: WorkBudget,
): FrozenDevelopmentNomination {
  const persisted = parseAssessmentDecision(persistedNomination);
  if (
    persisted.phase !== "development"
    || persisted.status !== "NOMINATED"
    || persisted.selectedPolicy === null
  ) {
    throw new Error("persisted decision is not a development nomination");
  }
  const recomputed = nominateDevelopment(
    protocol,
    developmentDataset,
    assessmentContext,
    workBudget,
  );
  if (recomputed.decisionDigest !== persisted.decisionDigest) {
    throw new Error(
      "persisted nomination does not match recomputed development evidence",
    );
  }
  if (!isDevelopmentNomination(recomputed)) {
    throw new Error("recomputed development decision is not a nomination");
  }
  return recomputed;
}

export function isAuthenticAssessmentDecision(
  value: unknown,
): value is FrozenDecision {
  return (
    value !== null
    && typeof value === "object"
    && authenticAssessmentDecisions.has(value)
  );
}
