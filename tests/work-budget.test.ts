import { describe, expect, it } from "vitest";
import {
  assertWithinWorkBudget,
  estimateAssessmentWork,
  type WorkBudget,
} from "../src/work-budget.js";

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
});
