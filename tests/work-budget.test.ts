import { describe, expect, it } from "vitest";
import {
  assertWithinWorkBudget,
  estimateAssessmentWork,
  type WorkBudget,
} from "../src/work-budget.js";
import {
  assertWithinLegacyAssessmentBudget,
  estimateLegacyAssessmentWork,
} from "../src/legacy-work-budget.js";

const budget: WorkBudget = {
  maxCandidates: 10,
  maxTraceRows: 100,
  maxEvidenceRows: 100,
  maxBootstrapDraws: 1_000,
  maxIndependentGroups: 20,
  maxAssessmentWork: 1_000_000,
};

describe("assessment work budgeting", () => {
  it("estimates the checked Cartesian assessment workload", () => {
    expect(estimateAssessmentWork({
      candidateCount: 3,
      traceRows: 4,
      evidenceRows: 5,
      bootstrapDraws: 7,
      independentGroups: 2,
    })).toEqual({
      candidateCount: 3,
      traceRows: 4,
      evidenceRows: 5,
      bootstrapDraws: 7,
      independentGroups: 2,
      assessmentWork: 840,
    });
  });

  it("accepts exact caller limits and rejects every exceeded dimension", () => {
    const exact = estimateAssessmentWork({
      candidateCount: 10,
      traceRows: 100,
      evidenceRows: 100,
      bootstrapDraws: 1,
      independentGroups: 1,
    });
    expect(() => assertWithinWorkBudget(exact, { ...budget, maxAssessmentWork: 100_000 })).not.toThrow();
    expect(() => assertWithinWorkBudget(
      estimateAssessmentWork({ candidateCount: 11, traceRows: 1, evidenceRows: 1, bootstrapDraws: 1, independentGroups: 1 }),
      budget,
    )).toThrow(/candidate/i);
    expect(() => assertWithinWorkBudget(
      estimateAssessmentWork({ candidateCount: 1, traceRows: 101, evidenceRows: 1, bootstrapDraws: 1, independentGroups: 1 }),
      budget,
    )).toThrow(/trace/i);
    expect(() => assertWithinWorkBudget(
      estimateAssessmentWork({ candidateCount: 1, traceRows: 1, evidenceRows: 101, bootstrapDraws: 1, independentGroups: 1 }),
      budget,
    )).toThrow(/evidence/i);
    expect(() => assertWithinWorkBudget(
      estimateAssessmentWork({ candidateCount: 1, traceRows: 1, evidenceRows: 1, bootstrapDraws: 1_001, independentGroups: 1 }),
      budget,
    )).toThrow(/bootstrap/i);
    expect(() => assertWithinWorkBudget(
      estimateAssessmentWork({ candidateCount: 1, traceRows: 1, evidenceRows: 1, bootstrapDraws: 1, independentGroups: 21 }),
      budget,
    )).toThrow(/group/i);
  });

  it("fails closed for invalid counts and overflowing products before allocation", () => {
    for (const candidateCount of [-1, Number.NaN, Number.POSITIVE_INFINITY, 1.5]) {
      expect(() => estimateAssessmentWork({
        candidateCount,
        traceRows: 1,
        evidenceRows: 1,
        bootstrapDraws: 1,
        independentGroups: 1,
      })).toThrow(/safe non-negative integer/i);
    }
    expect(() => estimateAssessmentWork({
      candidateCount: Number.MAX_SAFE_INTEGER,
      traceRows: Number.MAX_SAFE_INTEGER,
      evidenceRows: 1,
      bootstrapDraws: 1,
      independentGroups: 1,
    })).toThrow(/overflow/i);
    expect(() => assertWithinWorkBudget(
      estimateAssessmentWork({ candidateCount: 100, traceRows: 100, evidenceRows: 100, bootstrapDraws: 100, independentGroups: 100 }),
      {
        maxCandidates: 100,
        maxTraceRows: 100,
        maxEvidenceRows: 100,
        maxBootstrapDraws: 100,
        maxIndependentGroups: 100,
        maxAssessmentWork: 1_000_000,
      },
    )).toThrow(/assessment work/i);
  });

  it("recomputes total work instead of trusting a forgeable estimate field", () => {
    expect(() => assertWithinWorkBudget({
      candidateCount: 100,
      traceRows: 100,
      evidenceRows: 100,
      bootstrapDraws: 100,
      independentGroups: 100,
      assessmentWork: 0,
    }, {
      maxCandidates: 100,
      maxTraceRows: 100,
      maxEvidenceRows: 100,
      maxBootstrapDraws: 100,
      maxIndependentGroups: 100,
      maxAssessmentWork: 1_000_000,
    })).toThrow(/assessment work/i);
  });
});

describe("legacy grouped assessment work budgeting", () => {
  it("adds row scans and grouped bootstrap work before fixed-objective costs", () => {
    expect(estimateLegacyAssessmentWork({
      candidateCount: 3,
      traceRows: 4,
      evidenceRows: 5,
      bootstrapDraws: 7,
      independentGroups: 2,
    }, 2)).toEqual({
      candidateCount: 3,
      traceRows: 4,
      evidenceRows: 5,
      bootstrapDraws: 7,
      independentGroups: 2,
      uniqueObjectiveSignatures: 2,
      rowPairWork: 9,
      groupedBootstrapWork: 14,
      candidateEvaluationWork: 69,
      objectiveProjectionWork: 21,
      frontierComparisonWork: 14,
      assessmentWork: 104,
    });
  });

  it("accepts exact dimensions and reports a frontier-specific work excess", () => {
    const estimate = estimateLegacyAssessmentWork({
      candidateCount: 2,
      traceRows: 3,
      evidenceRows: 4,
      bootstrapDraws: 5,
      independentGroups: 2,
    }, 2);
    const exact: WorkBudget = {
      maxCandidates: 2,
      maxTraceRows: 3,
      maxEvidenceRows: 4,
      maxBootstrapDraws: 5,
      maxIndependentGroups: 2,
      maxAssessmentWork: estimate.assessmentWork,
    };

    expect(() => assertWithinLegacyAssessmentBudget(estimate, exact, "frontier")).not.toThrow();
    expect(() => assertWithinLegacyAssessmentBudget(estimate, {
      ...exact,
      maxAssessmentWork: estimate.assessmentWork - 1,
    }, "frontier")).toThrow(/frontier assessment work exceeds caller work budget/i);
    expect(() => assertWithinLegacyAssessmentBudget(estimate, {
      ...exact,
      maxIndependentGroups: 1,
    })).toThrow(/independent group count exceeds caller work budget/i);
  });

  it("fails closed for invalid axes and every additive or multiplicative overflow", () => {
    expect(() => estimateLegacyAssessmentWork({
      candidateCount: -1,
      traceRows: 0,
      evidenceRows: 0,
      bootstrapDraws: 0,
      independentGroups: 0,
    })).toThrow(/candidate count.*safe non-negative integer/i);
    expect(() => estimateLegacyAssessmentWork({
      candidateCount: 1,
      traceRows: Number.MAX_SAFE_INTEGER,
      evidenceRows: 1,
      bootstrapDraws: 0,
      independentGroups: 0,
    })).toThrow(/overflow/i);
    expect(() => estimateLegacyAssessmentWork({
      candidateCount: 1,
      traceRows: 0,
      evidenceRows: 0,
      bootstrapDraws: Number.MAX_SAFE_INTEGER,
      independentGroups: 2,
    })).toThrow(/overflow/i);
    expect(() => estimateLegacyAssessmentWork({
      candidateCount: Number.MAX_SAFE_INTEGER,
      traceRows: 0,
      evidenceRows: 0,
      bootstrapDraws: 0,
      independentGroups: 0,
    })).toThrow(/overflow/i);
    expect(() => estimateLegacyAssessmentWork({
      candidateCount: 1,
      traceRows: 0,
      evidenceRows: 0,
      bootstrapDraws: 0,
      independentGroups: 0,
    }, 2)).toThrow(/unique objective signatures cannot exceed candidate count/i);
  });
});
