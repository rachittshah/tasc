import type { WorkBudget } from "./work-budget.js";

/**
 * Legacy policy evaluation projects seven fixed Pareto objectives. Capacity occupies its
 * slot even when its gate is disabled, keeping work accounting independent of gate values.
 */
export const LEGACY_OBJECTIVE_DIMENSIONS = 7;

export interface LegacyAssessmentWorkInput {
  candidateCount: number;
  traceRows: number;
  evidenceRows: number;
  bootstrapDraws: number;
  independentGroups: number;
}

export interface LegacyAssessmentWorkEstimate extends LegacyAssessmentWorkInput {
  uniqueObjectiveSignatures: number;
  rowPairWork: number;
  groupedBootstrapWork: number;
  candidateEvaluationWork: number;
  objectiveProjectionWork: number;
  frontierComparisonWork: number;
  assessmentWork: number;
}

function assertNonNegativeSafeInteger(value: number, name: string): void {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error(`${name} must be a safe non-negative integer`);
  }
}

function checkedAdd(left: number, right: number): number {
  if (left > Number.MAX_SAFE_INTEGER - right) {
    throw new Error("legacy assessment work arithmetic overflow");
  }
  return left + right;
}

function checkedMultiply(left: number, right: number): number {
  if (left === 0 || right === 0) return 0;
  if (left > Number.MAX_SAFE_INTEGER / right) {
    throw new Error("legacy assessment work arithmetic overflow");
  }
  return left * right;
}

/**
 * Legacy replay scans its two row streams additively and bootstraps group effects per
 * candidate. It is not an evidence-join Cartesian product.
 */
export function estimateLegacyAssessmentWork(
  input: LegacyAssessmentWorkInput,
  uniqueObjectiveSignatures = 0,
): LegacyAssessmentWorkEstimate {
  assertNonNegativeSafeInteger(input.candidateCount, "candidate count");
  assertNonNegativeSafeInteger(input.traceRows, "trace rows");
  assertNonNegativeSafeInteger(input.evidenceRows, "evidence rows");
  assertNonNegativeSafeInteger(input.bootstrapDraws, "bootstrap draws");
  assertNonNegativeSafeInteger(input.independentGroups, "independent groups");
  assertNonNegativeSafeInteger(uniqueObjectiveSignatures, "unique objective signatures");
  if (uniqueObjectiveSignatures > input.candidateCount) {
    throw new Error("unique objective signatures cannot exceed candidate count");
  }

  const rowPairWork = checkedAdd(input.traceRows, input.evidenceRows);
  const groupedBootstrapWork = checkedMultiply(
    input.bootstrapDraws,
    input.independentGroups,
  );
  const candidateEvaluationWork = checkedMultiply(
    input.candidateCount,
    checkedAdd(rowPairWork, groupedBootstrapWork),
  );
  const objectiveProjectionWork = checkedMultiply(
    input.candidateCount,
    LEGACY_OBJECTIVE_DIMENSIONS,
  );
  const frontierComparisonWork = checkedMultiply(
    checkedMultiply(
      uniqueObjectiveSignatures,
      Math.max(0, uniqueObjectiveSignatures - 1),
    ),
    LEGACY_OBJECTIVE_DIMENSIONS,
  );
  const assessmentWork = checkedAdd(
    checkedAdd(candidateEvaluationWork, objectiveProjectionWork),
    frontierComparisonWork,
  );

  return {
    ...input,
    uniqueObjectiveSignatures,
    rowPairWork,
    groupedBootstrapWork,
    candidateEvaluationWork,
    objectiveProjectionWork,
    frontierComparisonWork,
    assessmentWork,
  };
}

function assertBudgetLimit(value: number, limit: number, name: string): void {
  assertNonNegativeSafeInteger(limit, `${name} budget`);
  if (value > limit) {
    throw new Error(`${name} exceeds caller work budget: ${value} > ${limit}`);
  }
}

export function assertWithinLegacyAssessmentBudget(
  estimate: LegacyAssessmentWorkEstimate,
  budget: WorkBudget,
  phase: "assessment" | "frontier" = "assessment",
): void {
  assertBudgetLimit(estimate.candidateCount, budget.maxCandidates, "candidate count");
  assertBudgetLimit(estimate.traceRows, budget.maxTraceRows, "trace rows");
  assertBudgetLimit(estimate.evidenceRows, budget.maxEvidenceRows, "evidence rows");
  assertBudgetLimit(estimate.bootstrapDraws, budget.maxBootstrapDraws, "bootstrap draws");
  assertBudgetLimit(
    estimate.independentGroups,
    budget.maxIndependentGroups,
    "independent group count",
  );
  assertBudgetLimit(
    estimate.assessmentWork,
    budget.maxAssessmentWork,
    phase === "frontier" ? "frontier assessment work" : "assessment work",
  );
}
