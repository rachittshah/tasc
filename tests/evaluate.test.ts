import { describe, expect, it } from "vitest";
import { bootstrapMeanCI, median } from "../src/statistics.js";
import { sha256, stableJson } from "../src/integrity.js";
import {
  computePolicyMetrics,
  confirmNomination,
  evaluatePolicy,
  nominatePolicy,
  type NominationArtifact,
} from "../src/evaluate.js";
import type { ReplayedRow } from "../src/policy.js";
import { fingerprintPolicy, generateCandidatePolicies } from "../src/policy.js";
import { parseMeasurementSet, type InferenceSpec, type MeasurementSet } from "../src/schema.js";

const ATTESTATION_KEY = "test-only-tasc-attestation-key-32-bytes-minimum";
const WRONG_ATTESTATION_KEY = "wrong-test-only-attestation-key-32-bytes-minimum";

function spec(overrides: Partial<InferenceSpec["constraints"]> = {}): InferenceSpec {
  return {
    version: "tasc-inference-spec-v1",
    id: "evaluate-fixture",
    profiles: [
      { id: "expert", model: "expert", runtime: "remote", hardware: "gpu" },
      { id: "fast", model: "fast", runtime: "remote", hardware: "gpu" },
    ],
    championProfileId: "expert",
    primaryProfileId: "fast",
    candidateSpace: {
      confidenceThresholds: [0.5],
      inputTokenThresholds: [1_000],
      includeFastOnly: true,
    },
    criticalSlices: ["payments", "safety"],
    constraints: {
      taskScoreFloor: 0.7,
      criticalSliceScoreFloor: 0.7,
      maxP95TtftMs: 500,
      maxP95EndToEndLatencyMs: 1_000,
      minP10PerceivedTokensPerSecond: 20,
      minP50TotalTokensPerSecond: 20,
      maxErrorRate: 0.25,
      maxCostPerThousandRequests: 100,
      nonInferiorityMargin: -0.02,
      minimumCostImprovement: 0.1,
      ...overrides,
    },
    bootstrap: { seed: 17, iterations: 200 },
  };
}

function row(overrides: Partial<ReplayedRow> = {}): ReplayedRow {
  return {
    policyId: "candidate",
    caseId: "case-1",
    groupId: "group-1",
    replicateIndex: 0,
    status: "success",
    selectedProfileId: "fast",
    attemptedProfileIds: ["fast"],
    escalated: false,
    taskScore: 0.9,
    ttftMs: 100,
    endToEndLatencyMs: 400,
    outputTokens: 40,
    perceivedTokensPerSecond: 80,
    totalTokensPerSecond: 70,
    costUsd: 0.01,
    trafficWeight: 1,
    slices: ["payments", "safety"],
    critical: true,
    ...overrides,
  };
}

function pairedRows(
  candidateScores: number[][],
  championScores: number[][],
): { candidate: ReplayedRow[]; champion: ReplayedRow[] } {
  const candidate: ReplayedRow[] = [];
  const champion: ReplayedRow[] = [];
  for (let caseIndex = 0; caseIndex < candidateScores.length; caseIndex += 1) {
    for (let replicateIndex = 0; replicateIndex < candidateScores[caseIndex].length; replicateIndex += 1) {
      candidate.push(row({
        caseId: `case-${caseIndex}`,
        groupId: `group-${caseIndex}`,
        replicateIndex,
        taskScore: candidateScores[caseIndex][replicateIndex],
      }));
      champion.push(row({
        policyId: "champion",
        selectedProfileId: "expert",
        attemptedProfileIds: ["expert"],
        caseId: `case-${caseIndex}`,
        groupId: `group-${caseIndex}`,
        replicateIndex,
        taskScore: championScores[caseIndex][replicateIndex],
        costUsd: 0.02,
      }));
    }
  }
  return { candidate, champion };
}

describe("TASC policy metrics", () => {
  it("keeps failures in quality, error, throughput, and latency metrics", () => {
    const metrics = computePolicyMetrics([
      row(),
      row({
        caseId: "case-2",
        groupId: "group-2",
        status: "failure",
        taskScore: 0.8,
        ttftMs: 900,
        endToEndLatencyMs: 900,
        outputTokens: 20,
        perceivedTokensPerSecond: 40,
        totalTokensPerSecond: 35,
        failureCode: "timeout",
      }),
    ], []);

    expect(metrics.meanTaskScore).toBeCloseTo(0.45);
    expect(metrics.successRate).toBeCloseTo(0.5);
    expect(metrics.errorRate).toBeCloseTo(0.5);
    expect(metrics.p95TtftMs).toBe(900);
    expect(metrics.p95EndToEndLatencyMs).toBe(900);
    expect(metrics.p10PerceivedTokensPerSecond).toBe(0);
  });

  it("preserves traffic mix across replicate counts for weighted means and percentiles", () => {
    const rows = [
      row({
        caseId: "heavy",
        groupId: "heavy-group",
        replicateIndex: 0,
        trafficWeight: 3,
        taskScore: 1,
        ttftMs: 100,
        endToEndLatencyMs: 200,
        costUsd: 0.01,
      }),
      ...[0, 1, 2].map((replicateIndex) => row({
        caseId: "light",
        groupId: "light-group",
        replicateIndex,
        trafficWeight: 1,
        taskScore: 0,
        ttftMs: 1_000,
        endToEndLatencyMs: 2_000,
        costUsd: 0.05,
      })),
    ];

    const metrics = computePolicyMetrics(rows, ["payments", "absent"]);

    expect(metrics.meanTaskScore).toBeCloseTo(0.75);
    expect(metrics.costPerRequestUsd).toBeCloseTo(0.02);
    expect(metrics.costPerThousandRequestsUsd).toBeCloseTo(20);
    expect(metrics.p50TtftMs).toBe(100);
    expect(metrics.p95TtftMs).toBe(1_000);
    expect(metrics.p95EndToEndLatencyMs).toBe(2_000);
    expect(metrics.criticalSliceTaskScore.payments).toBeCloseTo(0.75);
    expect(metrics.criticalSliceTaskScore.absent).toBeNull();
  });
});

describe("TASC hard gates", () => {
  it("bounds direct evaluation before allocating an oversized bootstrap", () => {
    const rows = pairedRows([[0.9], [0.9], [0.9]], [[0.9], [0.9], [0.9]]);
    const activeSpec = spec();
    activeSpec.bootstrap.iterations = 10_000_000;

    expect(() => evaluatePolicy(rows.candidate, rows.champion, activeSpec, {
      workBudget: {
        maxCandidates: 1,
        maxTraceRows: Number.MAX_SAFE_INTEGER,
        maxEvidenceRows: Number.MAX_SAFE_INTEGER,
        maxBootstrapDraws: 1,
        maxIndependentGroups: Number.MAX_SAFE_INTEGER,
        maxAssessmentWork: Number.MAX_SAFE_INTEGER,
      },
    })).toThrow(/bootstrap draws exceeds caller work budget/i);
  });

  it("uses case-level median deltas and the preregistered deterministic bootstrap", () => {
    const rows = pairedRows(
      [[0, 1, 1], [0.7], [0.8]],
      [[0.5, 0.5, 0.5], [0.6], [0.9]],
    );
    const result = evaluatePolicy(rows.candidate, rows.champion, spec({
      taskScoreFloor: 0,
      criticalSliceScoreFloor: 0,
      maxP95TtftMs: 10_000,
      maxP95EndToEndLatencyMs: 10_000,
      minP10PerceivedTokensPerSecond: 0,
      minP50TotalTokensPerSecond: 0,
      maxErrorRate: 1,
      maxCostPerThousandRequests: 1_000,
      minimumCostImprovement: 0,
    }));
    const deltas = [0, 1, 2].map((caseIndex) => (
      median(rows.candidate.filter((candidate) => candidate.caseId === `case-${caseIndex}`).map((candidate) => candidate.taskScore))
      - median(rows.champion.filter((champion) => champion.caseId === `case-${caseIndex}`).map((champion) => champion.taskScore))
    ));

    expect(result.pairedQuality.caseCount).toBe(3);
    expect(result.pairedQuality.deltas).toEqual(deltas);
    expect(result.pairedQuality.bootstrap).toEqual(bootstrapMeanCI(deltas, {
      seed: 17,
      iters: 200,
    }));
  });

  it("rejects fewer than three unique paired cases", () => {
    const rows = pairedRows([[0.9], [0.9]], [[0.9], [0.9]]);
    expect(() => evaluatePolicy(rows.candidate, rows.champion, spec())).toThrow(
      /at least 3 unique paired cases/i,
    );
  });

  it("returns an explicit reason for every absolute and paired gate", () => {
    const rows = pairedRows([[0.9], [0.9], [0.9]], [[0.9], [0.9], [0.9]]);
    const result = evaluatePolicy(rows.candidate, rows.champion, spec());

    expect(result.gates.map((gate) => gate.id)).toEqual([
      "paired_quality_non_inferiority",
      "mean_task_score",
      "critical_slice:payments",
      "critical_slice:safety",
      "p95_ttft",
      "p95_end_to_end_latency",
      "p10_perceived_tps",
      "p50_total_tps",
      "error_rate",
      "cost_per_thousand",
      "development_cost_improvement",
    ]);
    expect(result.gates.every((gate) => gate.reason.length > 0)).toBe(true);
    expect(result.gates.find((gate) => gate.id === "paired_quality_non_inferiority")).toMatchObject({
      pass: true,
    });
  });

  it("fails each configured critical slice independently and fails closed when rows are absent", () => {
    const rows = pairedRows([[0.9], [0.9], [0.9]], [[0.9], [0.9], [0.9]]);
    rows.candidate.forEach((candidate, index) => {
      candidate.slices = index === 0 ? ["payments"] : ["routine"];
      if (index === 0) candidate.taskScore = 0.2;
    });
    const result = evaluatePolicy(rows.candidate, rows.champion, spec());

    expect(result.gates.find((gate) => gate.id === "critical_slice:payments")).toMatchObject({
      pass: false,
      actual: 0.2,
    });
    expect(result.gates.find((gate) => gate.id === "critical_slice:safety")).toMatchObject({
      pass: false,
      actual: null,
    });
  });
});

function success(overrides: Record<string, unknown> = {}) {
  return {
    status: "success",
    taskScore: 0.9,
    confidence: 0.7,
    ttftMs: 100,
    endToEndLatencyMs: 500,
    outputTokens: 20,
    perceivedTokensPerSecond: 50,
    totalTokensPerSecond: 50,
    costUsd: 0,
    ...overrides,
  };
}

function failure(overrides: Record<string, unknown> = {}) {
  return {
    status: "failure",
    failureCode: "timeout",
    elapsedMs: 50,
    costUsd: 0,
    ...overrides,
  };
}

function measurements(options: {
  split?: "dev" | "holdout";
  synthetic?: boolean;
  groupPrefix?: string;
  evaluatorVersion?: string;
  fastScore?: number;
  expertScore?: number;
  fastOnlyMustFail?: boolean;
} = {}): MeasurementSet {
  const split = options.split ?? "dev";
  const groupPrefix = options.groupPrefix ?? split;
  const cases = [0, 1, 2].map((caseIndex) => {
    const fast = options.fastOnlyMustFail && caseIndex === 0
      ? failure()
      : success({
        taskScore: options.fastScore ?? 0.85,
        confidence: caseIndex === 1 ? 0.6 : 0.9,
      });
    return {
      id: `${split}-case-${caseIndex}`,
      groupId: `${groupPrefix}-group-${caseIndex}`,
      inputTokens: 100,
      outputTokens: 20,
      repeatedPrefixTokens: 0,
      concurrency: 1,
      mode: "chat",
      critical: false,
      trafficWeight: 1,
      slices: ["routine"],
      observations: [
        {
          profileId: "expert",
          replicates: [success({
            taskScore: options.expertScore ?? 0.95,
            confidence: 1,
            ttftMs: caseIndex === 1 ? 200 : 50,
            endToEndLatencyMs: caseIndex === 1 ? 650 : 500,
            costUsd: caseIndex === 0 ? 0.03 : 0,
          })],
        },
        { profileId: "fast", replicates: [fast] },
      ],
    };
  });
  return parseMeasurementSet({
    version: "tasc-measurements-v1",
    dataset: {
      id: `dataset-${split}`,
      version: "1",
      source: "fixture",
      split,
      synthetic: options.synthetic ?? true,
    },
    evaluator: {
      id: "rubric",
      version: options.evaluatorVersion ?? "1",
      kind: "deterministic",
      validated: true,
    },
    cases,
  });
}

function nominationSpec(): InferenceSpec {
  const value = spec({
    taskScoreFloor: 0.7,
    criticalSliceScoreFloor: 0,
    maxP95TtftMs: 1_000,
    maxP95EndToEndLatencyMs: 2_000,
    minP10PerceivedTokensPerSecond: 0,
    minP50TotalTokensPerSecond: 0,
    maxErrorRate: 0,
    maxCostPerThousandRequests: 100,
    nonInferiorityMargin: -0.2,
    minimumCostImprovement: 0,
  });
  value.criticalSlices = [];
  value.candidateSpace = {
    confidenceThresholds: [0.5, 0.8],
    inputTokenThresholds: [1_000, 2_000],
    includeFastOnly: true,
  };
  return value;
}

function resignNomination(nomination: NominationArtifact): NominationArtifact {
  const { selfDigest: _ignored, attestation: _attestation, ...body } = nomination;
  return { ...nomination, selfDigest: sha256(stableJson(body)) };
}

describe("TASC development nomination", () => {
  it("fails a caller work budget before candidate expansion or bootstrap allocation", () => {
    const activeSpec = nominationSpec();
    activeSpec.candidateSpace = {
      confidenceThresholds: Array.from({ length: 5_000 }, (_value, index) => index),
      inputTokenThresholds: Array.from({ length: 5_000 }, (_value, index) => index),
      includeFastOnly: false,
    };

    expect(() => nominatePolicy(activeSpec, measurements(), {
      workBudget: {
        maxCandidates: 0,
        maxTraceRows: Number.MAX_SAFE_INTEGER,
        maxEvidenceRows: Number.MAX_SAFE_INTEGER,
        maxBootstrapDraws: Number.MAX_SAFE_INTEGER,
        maxIndependentGroups: Number.MAX_SAFE_INTEGER,
        maxAssessmentWork: Number.MAX_SAFE_INTEGER,
      },
    })).toThrow(/candidate count exceeds caller work budget/i);
  });

  it("evaluates every generated policy and retains hard-gate rejections", () => {
    const result = nominatePolicy(nominationSpec(), measurements({ fastOnlyMustFail: true }));

    expect(result.evaluations).toHaveLength(5);
    expect(result.evaluations.filter((evaluation) => !evaluation.evaluation.passed)).not.toHaveLength(0);
    expect(result.evaluations.find((evaluation) => evaluation.policy.kind === "fast-only")?.evaluation.passed).toBe(false);
    expect(result.frontier.every((policyId) => (
      result.evaluations.find((evaluation) => evaluation.policy.id === policyId)?.evaluation.passed
    ))).toBe(true);
  });

  it("keeps non-dominated tradeoffs and nominates by cost, P95 E2E latency, then ID", () => {
    const result = nominatePolicy(nominationSpec(), measurements());
    expect(result.status).toBe("NOMINATED");
    expect(result.frontier.length).toBeGreaterThan(1);

    const orderedFrontier = result.frontier
      .map((id) => result.evaluations.find((entry) => entry.policy.id === id)!)
      .sort((left, right) => (
        left.evaluation.candidateMetrics.costPerRequestUsd
          - right.evaluation.candidateMetrics.costPerRequestUsd
        || left.evaluation.candidateMetrics.p95EndToEndLatencyMs
          - right.evaluation.candidateMetrics.p95EndToEndLatencyMs
        || left.policy.id.localeCompare(right.policy.id)
      ));
    expect(result.nomination?.policy.id).toBe(orderedFrontier[0].policy.id);
  });

  it("returns NO_CANDIDATE and all rejected evaluations when no candidate passes", () => {
    const impossible = nominationSpec();
    impossible.constraints.taskScoreFloor = 1;
    const result = nominatePolicy(impossible, measurements({ fastScore: 0.1, expertScore: 0.2 }));

    expect(result).toMatchObject({ status: "NO_CANDIDATE", nomination: undefined, frontier: [] });
    expect(result.evaluations.every((evaluation) => !evaluation.evaluation.passed)).toBe(true);
  });

  it("binds the nomination to spec, data, evaluator, groups, policy, decisions, and itself", () => {
    const dev = measurements();
    const result = nominatePolicy(nominationSpec(), dev);
    const artifact = result.nomination!;

    expect(artifact).toMatchObject({
      version: "tasc-nomination-v1",
      evaluator: dev.evaluator,
      developmentGroupIds: dev.cases.map((measurementCase) => measurementCase.groupId).sort(),
      developmentSynthetic: true,
    });
    expect(artifact.policyDigest).toBe(fingerprintPolicy(artifact.policy));
    expect(artifact.specDigest).toHaveLength(64);
    expect(artifact.developmentDatasetDigest).toHaveLength(64);
    expect(artifact.decisionDigest).toHaveLength(64);
    expect(artifact.selfDigest).toHaveLength(64);
  });
});

describe("TASC exact holdout confirmation", () => {
  function nominated(devSynthetic = true, attestationKey?: string) {
    const activeSpec = nominationSpec();
    const result = nominatePolicy(
      activeSpec,
      measurements({ synthetic: devSynthetic }),
      { attestationKey },
    );
    return { activeSpec, nomination: result.nomination! };
  }

  it("detects edits using the nomination self-digest", () => {
    const { activeSpec, nomination } = nominated();
    nomination.candidateMetrics.meanTaskScore = 0;
    expect(() => confirmNomination(
      activeSpec,
      measurements({ split: "holdout", groupPrefix: "holdout" }),
      nomination,
    )).toThrow(/self-digest|edited/i);
  });

  it("rejects the wrong split, spec drift, and a re-signed unregistered policy", () => {
    const first = nominated();
    expect(() => confirmNomination(first.activeSpec, measurements(), first.nomination)).toThrow(/holdout split/i);

    const driftedSpec = structuredClone(first.activeSpec);
    driftedSpec.constraints.maxErrorRate = 0.5;
    expect(() => confirmNomination(
      driftedSpec,
      measurements({ split: "holdout", groupPrefix: "holdout" }),
      first.nomination,
    )).toThrow(/spec digest/i);

    const second = nominated();
    second.nomination.policy.confidenceThreshold = 0.65;
    second.nomination.policyDigest = fingerprintPolicy(second.nomination.policy);
    const resigned = resignNomination(second.nomination);
    expect(() => confirmNomination(
      second.activeSpec,
      measurements({ split: "holdout", groupPrefix: "holdout" }),
      resigned,
    )).toThrow(/regenerated candidate|policy drift/i);
  });

  it("rejects evaluator identity drift and development/holdout group leakage", () => {
    const { activeSpec, nomination } = nominated();
    expect(() => confirmNomination(
      activeSpec,
      measurements({ split: "holdout", groupPrefix: "holdout", evaluatorVersion: "2" }),
      nomination,
    )).toThrow(/evaluator drift/i);

    expect(() => confirmNomination(
      activeSpec,
      measurements({ split: "holdout", groupPrefix: "dev" }),
      nomination,
    )).toThrow(/group leakage/i);
  });

  it("evaluates only the frozen nominee and returns DEMO_ONLY for any synthetic evidence", () => {
    const { activeSpec, nomination } = nominated(false);
    const result = confirmNomination(
      activeSpec,
      measurements({ split: "holdout", groupPrefix: "holdout", synthetic: true }),
      nomination,
    );

    expect(result.status).toBe("DEMO_ONLY");
    expect(result.policy.id).toBe(nomination.policy.id);
    expect(result).not.toHaveProperty("evaluations");
    expect(result.evaluation.gates.some((gate) => gate.id === "development_cost_improvement")).toBe(false);
  });

  it("returns READY_FOR_MANUAL_PRODUCTION only when both datasets are real", () => {
    const { activeSpec, nomination } = nominated(false, ATTESTATION_KEY);
    const result = confirmNomination(
      activeSpec,
      measurements({ split: "holdout", groupPrefix: "holdout", synthetic: false }),
      nomination,
      { attestationKey: ATTESTATION_KEY },
    );
    expect(result).toMatchObject({
      status: "READY_FOR_MANUAL_PRODUCTION",
      attestationVerified: true,
    });
  });

  it("returns HOLD instead of reselecting when the frozen nominee fails holdout gates", () => {
    const { activeSpec, nomination } = nominated(false);
    const result = confirmNomination(
      activeSpec,
      measurements({
        split: "holdout",
        groupPrefix: "holdout",
        synthetic: false,
        fastScore: 0.1,
        expertScore: 0.1,
      }),
      nomination,
    );

    expect(result.status).toBe("HOLD");
    expect(result.policy.id).toBe(nomination.policy.id);
    expect(result.evaluation.passed).toBe(false);
  });

  it("prevents a re-signed synthetic flag from elevating a development run", () => {
    const signed = nominated(true, ATTESTATION_KEY);
    signed.nomination.developmentSynthetic = false;
    const edited = resignNomination(signed.nomination);
    const holdout = measurements({ split: "holdout", groupPrefix: "holdout", synthetic: false });

    expect(() => confirmNomination(
      signed.activeSpec,
      holdout,
      edited,
      { attestationKey: ATTESTATION_KEY },
    )).toThrow(/attestation mismatch/i);

    const untrusted = confirmNomination(signed.activeSpec, holdout, edited);
    expect(untrusted).toMatchObject({
      status: "HOLD",
      attestationVerified: false,
    });
    expect(untrusted.statusReason).toMatch(/production readiness requires.*attestation/i);
  });

  it("rejects re-signed removal of development group IDs", () => {
    const signed = nominated(false, ATTESTATION_KEY);
    signed.nomination.developmentGroupIds = [];
    const edited = resignNomination(signed.nomination);

    expect(() => confirmNomination(
      signed.activeSpec,
      measurements({ split: "holdout", groupPrefix: "holdout", synthetic: false }),
      edited,
      { attestationKey: ATTESTATION_KEY },
    )).toThrow(/attestation mismatch/i);
  });

  it("reports an attestation mismatch for an edited signed artifact before its public checksum", () => {
    const signed = nominated(false, ATTESTATION_KEY);
    signed.nomination.developmentGroupIds = [];

    expect(() => confirmNomination(
      signed.activeSpec,
      measurements({ split: "holdout", groupPrefix: "holdout", synthetic: false }),
      signed.nomination,
      { attestationKey: ATTESTATION_KEY },
    )).toThrow(/attestation mismatch/i);
  });

  it("rejects re-signed evaluator metadata", () => {
    const signed = nominated(false, ATTESTATION_KEY);
    signed.nomination.evaluator.version = "rewritten";
    const edited = resignNomination(signed.nomination);

    expect(() => confirmNomination(
      signed.activeSpec,
      measurements({
        split: "holdout",
        groupPrefix: "holdout",
        synthetic: false,
        evaluatorVersion: "rewritten",
      }),
      edited,
      { attestationKey: ATTESTATION_KEY },
    )).toThrow(/attestation mismatch/i);
  });

  it("rejects a re-signed substitution with another valid generated policy", () => {
    const signed = nominated(false, ATTESTATION_KEY);
    const replacement = generateCandidatePolicies(signed.activeSpec)
      .find((policy) => policy.id !== signed.nomination.policy.id)!;
    signed.nomination.policy = replacement;
    signed.nomination.policyDigest = fingerprintPolicy(replacement);
    const edited = resignNomination(signed.nomination);

    expect(() => confirmNomination(
      signed.activeSpec,
      measurements({ split: "holdout", groupPrefix: "holdout", synthetic: false }),
      edited,
      { attestationKey: ATTESTATION_KEY },
    )).toThrow(/attestation mismatch/i);
  });

  it("holds real unattested evidence and requires the original key for readiness", () => {
    const unsigned = nominated(false);
    const holdout = measurements({ split: "holdout", groupPrefix: "holdout", synthetic: false });
    const result = confirmNomination(unsigned.activeSpec, holdout, unsigned.nomination);

    expect(result).toMatchObject({ status: "HOLD", attestationVerified: false });
    expect(result.statusReason).toMatch(/production readiness requires.*attestation/i);
    expect(unsigned.nomination.attestation).toBeUndefined();
  });

  it("fails closed for wrong and short attestation keys", () => {
    const signed = nominated(false, ATTESTATION_KEY);
    const holdout = measurements({ split: "holdout", groupPrefix: "holdout", synthetic: false });

    expect(() => confirmNomination(
      signed.activeSpec,
      holdout,
      signed.nomination,
      { attestationKey: WRONG_ATTESTATION_KEY },
    )).toThrow(/attestation mismatch/i);
    expect(() => nominatePolicy(
      nominationSpec(),
      measurements({ synthetic: false }),
      { attestationKey: "short" },
    )).toThrow(/at least 32.*bytes/i);
    expect(() => confirmNomination(
      signed.activeSpec,
      holdout,
      signed.nomination,
      { attestationKey: "short" },
    )).toThrow(/at least 32.*bytes/i);
  });
});
