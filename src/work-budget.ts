/** Caller-owned limits for work that expands assessment inputs. */
export interface WorkBudget {
  maxCandidates: number;
  maxTraceRows: number;
  maxEvidenceRows: number;
  maxBootstrapDraws: number;
  maxIndependentGroups: number;
  maxAssessmentWork: number;
}

export interface AssessmentWorkInput {
  candidateCount: number;
  traceRows: number;
  evidenceRows: number;
  bootstrapDraws: number;
  independentGroups: number;
}

export interface AssessmentWorkEstimate extends AssessmentWorkInput {
  assessmentWork: number;
}

function assertNonNegativeSafeInteger(value: number, name: string): void {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error(`${name} must be a safe non-negative integer`);
  }
}

function checkedMultiply(left: number, right: number): number {
  if (left === 0 || right === 0) return 0;
  if (left > Number.MAX_SAFE_INTEGER / right) {
    throw new Error("assessment work arithmetic overflow");
  }
  return left * right;
}

/**
 * Calculate the full Cartesian work before candidate expansion, bootstrap allocation, or
 * evidence materialization. Each input remains visible in the estimate for precise limits.
 */
export function estimateAssessmentWork(input: AssessmentWorkInput): AssessmentWorkEstimate {
  assertNonNegativeSafeInteger(input.candidateCount, "candidate count");
  assertNonNegativeSafeInteger(input.traceRows, "trace rows");
  assertNonNegativeSafeInteger(input.evidenceRows, "evidence rows");
  assertNonNegativeSafeInteger(input.bootstrapDraws, "bootstrap draws");
  assertNonNegativeSafeInteger(input.independentGroups, "independent groups");

  const assessmentWork = [
    input.candidateCount,
    input.traceRows,
    input.evidenceRows,
    input.bootstrapDraws,
    input.independentGroups,
  ].reduce(checkedMultiply, 1);
  return { ...input, assessmentWork };
}

function assertBudgetLimit(value: number, limit: number, name: string): void {
  assertNonNegativeSafeInteger(limit, `${name} budget`);
  if (value > limit) throw new Error(`${name} exceeds caller work budget: ${value} > ${limit}`);
}

/** Reject an estimate before it can allocate or execute work beyond caller-supplied limits. */
export function assertWithinWorkBudget(estimate: AssessmentWorkEstimate, budget: WorkBudget): void {
  assertNonNegativeSafeInteger(estimate.candidateCount, "candidate count");
  assertNonNegativeSafeInteger(estimate.traceRows, "trace rows");
  assertNonNegativeSafeInteger(estimate.evidenceRows, "evidence rows");
  assertNonNegativeSafeInteger(estimate.bootstrapDraws, "bootstrap draws");
  assertNonNegativeSafeInteger(estimate.independentGroups, "independent groups");
  assertNonNegativeSafeInteger(estimate.assessmentWork, "assessment work");
  const recomputedWork = estimateAssessmentWork(estimate).assessmentWork;
  assertBudgetLimit(estimate.candidateCount, budget.maxCandidates, "candidate count");
  assertBudgetLimit(estimate.traceRows, budget.maxTraceRows, "trace rows");
  assertBudgetLimit(estimate.evidenceRows, budget.maxEvidenceRows, "evidence rows");
  assertBudgetLimit(estimate.bootstrapDraws, budget.maxBootstrapDraws, "bootstrap draws");
  assertBudgetLimit(estimate.independentGroups, budget.maxIndependentGroups, "independent groups");
  assertBudgetLimit(recomputedWork, budget.maxAssessmentWork, "assessment work");
}
