import { describe, expect, it } from "vitest";
import { bootstrapMeanCI, median } from "../src/statistics.js";
import { compareCodeUnits } from "../src/determinism.js";
import { sha256, stableJson } from "../src/integrity.js";
import { estimateLegacyAssessmentWork } from "../src/legacy-work-budget.js";
import {
  computePolicyMetrics,
  confirmNomination,
  DEFAULT_ASSESSMENT_WORK_BUDGET,
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
      minimumIndependentGroups: 3,
      minimumCriticalSliceGroups: 1,
      ...overrides,
    },
    bootstrap: { seed: 17, iterations: 200, alpha: 0.05 },
  };
}

function withoutTask4Controls(value: InferenceSpec): InferenceSpec {
  const {
    minimumIndependentGroups: _minimumIndependentGroups,
    minimumCriticalSliceGroups: _minimumCriticalSliceGroups,
    ...constraints
  } = value.constraints;
  const { alpha: _alpha, ...bootstrap } = value.bootstrap;
  return { ...value, constraints, bootstrap };
}

function row(overrides: Partial<ReplayedRow> = {}): ReplayedRow {
  return {
    policyId: "candidate",
    policyKind: "fast-only",
    caseId: "case-1",
    groupId: "group-1",
    replicateIndex: 0,
    status: "success",
    selectedProfileId: "fast",
    attemptedProfileIds: ["fast"],
    escalated: false,
    taskScore: 0.9,
    ttftMs: 100,
    endToEndLatencyMs: 500,
    outputTokens: 40,
    perceivedTokensPerSecond: 80,
    serviceThroughput: { kind: "measured", tokensPerSecond: 70 },
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
        policyKind: "expert-only",
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

function legacyRow(overrides: Partial<ReplayedRow> = {}): ReplayedRow {
  return {
    policyId: "legacy-fast-only",
    caseId: "legacy-case",
    groupId: "legacy-group",
    replicateIndex: 0,
    status: "success",
    selectedProfileId: "fast",
    attemptedProfileIds: ["fast"],
    escalated: false,
    taskScore: 0.9,
    ttftMs: 100,
    endToEndLatencyMs: 500,
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
        serviceThroughput: { kind: "unavailable", reason: "failed execution" },
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
        outputTokens: 1,
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

  it("keeps legacy direct rows source-compatible without trusting numeric capacity", () => {
    const metrics = computePolicyMetrics([legacyRow()], []);
    expect(metrics.p50TotalTokensPerSecond).toBeNull();
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

  it("snapshots direct-evaluation work-budget options without invoking accessors", () => {
    const rows = pairedRows([[0.9], [0.9], [0.9]], [[0.9], [0.9], [0.9]]);
    let budgetReads = 0;
    const workBudget = { ...DEFAULT_ASSESSMENT_WORK_BUDGET };
    Object.defineProperty(workBudget, "maxCandidates", {
      enumerable: true,
      get() {
        budgetReads += 1;
        throw new Error("work-budget getter must not run");
      },
    });

    expect(() => evaluatePolicy(rows.candidate, rows.champion, spec(), {
      workBudget,
    })).toThrow(/evaluation options.*maxCandidates.*accessor|accessor.*maxCandidates/i);
    expect(budgetReads).toBe(0);
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
    const replicateDeltas = rows.candidate.map((candidate) => (
      candidate.taskScore - rows.champion.find((champion) => (
        champion.caseId === candidate.caseId && champion.replicateIndex === candidate.replicateIndex
      ))!.taskScore
    ));
    const caseDeltas = [0, 1, 2].map((caseIndex) => median(
      replicateDeltas.filter((_delta, index) => rows.candidate[index].caseId === `case-${caseIndex}`),
    ));

    expect(result.pairedQuality.caseCount).toBe(3);
    expect(result.pairedQuality.deltas).toEqual(caseDeltas);
    expect(result.pairedQuality.replicateDeltas.map(({ delta }) => delta)).toEqual(replicateDeltas);
    expect(result.pairedQuality.caseEffects.map(({ effect }) => effect)).toEqual(caseDeltas);
    expect(result.pairedQuality.bootstrap).toEqual(bootstrapMeanCI(caseDeltas, {
      alpha: 0.05,
      seed: 17,
      iters: 200,
    }));
  });

  it("pairs replicate indexes before taking each case median", () => {
    const rows = pairedRows(
      [[0, 0, 1], [0.8], [0.8]],
      [[0, 1, 1], [0.8], [0.8]],
    );
    const result = evaluatePolicy(rows.candidate, rows.champion, spec({
      taskScoreFloor: 0,
      criticalSliceScoreFloor: 0,
      minP10PerceivedTokensPerSecond: 0,
      minP50TotalTokensPerSecond: 0,
      minimumCostImprovement: 0,
    }));

    expect(result.pairedQuality.deltas).toEqual([0, 0, 0]);
    expect(result.pairedQuality.replicateDeltas.map(({ delta }) => delta)).toEqual([0, -1, 0, 0, 0]);
    expect(result.pairedQuality.caseEffects).toEqual([
      { caseId: "case-0", groupId: "group-0", effect: 0, trafficWeight: 1 },
      { caseId: "case-1", groupId: "group-1", effect: 0, trafficWeight: 1 },
      { caseId: "case-2", groupId: "group-2", effect: 0, trafficWeight: 1 },
    ]);
    expect(result.pairedQuality.estimate).toBe(0);
  });

  it("rejects missing, duplicate, and lineage-drifted case-replicate pairs", () => {
    const rows = pairedRows([[0.9], [0.9], [0.9]], [[0.9], [0.9], [0.9]]);
    expect(() => evaluatePolicy(rows.candidate.slice(1), rows.champion, spec())).toThrow(
      /missing.*case.*replicate|pair.*missing/i,
    );
    expect(() => evaluatePolicy([...rows.candidate, structuredClone(rows.candidate[0])], rows.champion, spec())).toThrow(
      /duplicate.*case.*replicate/i,
    );
    const drifted = structuredClone(rows.champion);
    drifted[0].groupId = "different-group";
    expect(() => evaluatePolicy(rows.candidate, drifted, spec())).toThrow(
      /lineage|group.*drift|conflicting group/i,
    );
    const weightDrift = structuredClone(rows.champion);
    weightDrift[0].trafficWeight = 2;
    expect(() => evaluatePolicy(rows.candidate, weightDrift, spec())).toThrow(/traffic-weight.*drift/i);
    const sliceDrift = structuredClone(rows.champion);
    sliceDrift[0].slices = ["different-slice"];
    expect(() => evaluatePolicy(rows.candidate, sliceDrift, spec())).toThrow(/slice-set.*drift/i);
    const criticalDrift = structuredClone(rows.champion);
    criticalDrift[0].critical = !criticalDrift[0].critical;
    expect(() => evaluatePolicy(rows.candidate, criticalDrift, spec())).toThrow(/critical.*drift/i);
    const caseLevelDrift = pairedRows([[0.9, 0.9], [0.9], [0.9]], [[0.9, 0.9], [0.9], [0.9]]);
    caseLevelDrift.candidate[1].trafficWeight = 2;
    expect(() => evaluatePolicy(caseLevelDrift.candidate, caseLevelDrift.champion, spec()))
      .toThrow(/candidate case.*traffic-weight.*drift/i);
    const unsafe = structuredClone(rows.candidate);
    unsafe[0].replicateIndex = Number.MAX_SAFE_INTEGER + 1;
    expect(() => evaluatePolicy(unsafe, rows.champion, spec())).toThrow(/replicateIndex.*safe/i);
    const missingScore = structuredClone(rows.candidate) as any[];
    delete missingScore[0].taskScore;
    expect(() => evaluatePolicy(missingScore, rows.champion, spec())).toThrow(/successful.*score|score.*missing/i);
  });

  it("is invariant to candidate/champion row shuffles and slice-set ordering", () => {
    const rows = pairedRows(
      [[0.8, 0.9], [0.7], [0.95]],
      [[0.9, 0.8], [0.75], [0.9]],
    );
    rows.candidate.forEach((candidate) => { candidate.slices = ["safety", "payments"]; });
    const shuffledCandidate = [...rows.candidate].reverse();
    const shuffledChampion = [...rows.champion].reverse();
    shuffledChampion.forEach((champion) => { champion.slices = ["payments", "safety"]; });

    expect(evaluatePolicy(shuffledCandidate, shuffledChampion, spec()))
      .toEqual(evaluatePolicy(rows.candidate, rows.champion, spec()));
  });

  it("counts independent groups and critical-slice group coverage rather than correlated cases", () => {
    const rows = pairedRows(
      [[0.9], [0.9], [0.9], [0.9]],
      [[0.9], [0.9], [0.9], [0.9]],
    );
    for (const candidate of rows.candidate) {
      candidate.groupId = candidate.caseId === "case-3" ? "group-b" : "group-a";
      candidate.slices = candidate.caseId === "case-3" ? ["safety"] : ["payments"];
    }
    for (const champion of rows.champion) {
      champion.groupId = champion.caseId === "case-3" ? "group-b" : "group-a";
      champion.slices = champion.caseId === "case-3" ? ["safety"] : ["payments"];
    }
    const result = evaluatePolicy(rows.candidate, rows.champion, spec({
      minimumIndependentGroups: 3,
      minimumCriticalSliceGroups: 2,
    }));

    expect(result.pairedQuality).toMatchObject({
      caseCount: 4,
      replicateCount: 4,
      groupCount: 2,
      criticalSliceGroupCoverage: { payments: 1, safety: 1 },
    });
    expect(result.gates.find(({ id }) => id === "minimum_independent_groups")).toMatchObject({
      pass: false,
      actual: 2,
      threshold: 3,
    });
    expect(result.gates.find(({ id }) => id === "critical_slice_groups:payments")).toMatchObject({
      pass: false,
      actual: 1,
      threshold: 2,
    });
    expect(result.passed).toBe(false);
  });

  it("fails a required service-throughput gate when every serial cascade row is unavailable", () => {
    const rows = pairedRows([[0.9], [0.9], [0.9]], [[0.9], [0.9], [0.9]]);
    for (const candidate of rows.candidate) {
      candidate.attemptedProfileIds = ["fast", "expert"];
      candidate.escalated = true;
      candidate.serviceThroughput = {
        kind: "unavailable",
        reason: "serial cascade has no measured service-capacity observation",
      };
    }
    const result = evaluatePolicy(rows.candidate, rows.champion, spec());

    expect(result.candidateMetrics.p50TotalTokensPerSecond).toBeNull();
    expect(result.gates.find(({ id }) => id === "p50_total_tps")).toMatchObject({
      pass: false,
      actual: null,
    });
  });

  it("does not let direct callers forge capacity for serial or explicitly cascade rows", () => {
    const serial = pairedRows([[0.9], [0.9], [0.9]], [[0.9], [0.9], [0.9]]);
    for (const candidate of serial.candidate) {
      candidate.attemptedProfileIds = ["fast", "expert"];
      candidate.escalated = true;
      candidate.serviceThroughput = { kind: "measured", tokensPerSecond: 10_000 };
    }
    const serialResult = evaluatePolicy(serial.candidate, serial.champion, spec());
    expect(serialResult.candidateMetrics.p50TotalTokensPerSecond).toBeNull();
    expect(serialResult.gates.find(({ id }) => id === "p50_total_tps"))
      .toMatchObject({ pass: false, actual: null });

    const cascade = pairedRows([[0.9], [0.9], [0.9]], [[0.9], [0.9], [0.9]]);
    for (const candidate of cascade.candidate) {
      candidate.policyKind = "cascade";
      candidate.serviceThroughput = { kind: "measured", tokensPerSecond: 10_000 };
    }
    const cascadeResult = evaluatePolicy(cascade.candidate, cascade.champion, spec());
    expect(cascadeResult.candidateMetrics.p50TotalTokensPerSecond).toBeNull();
  });

  it("preflights bounded direct slice labels before sorting or pairing maps", () => {
    const rows = pairedRows([[0.9], [0.9], [0.9]], [[0.9], [0.9], [0.9]]);
    const activeSpec = spec();
    activeSpec.bootstrap.iterations = 1;
    const exactBudget = {
      maxCandidates: 1,
      maxTraceRows: 3,
      maxEvidenceRows: 3,
      maxBootstrapDraws: 1,
      maxIndependentGroups: 3,
      maxAssessmentWork: 27,
    };
    activeSpec.criticalSlices = Array.from({ length: 65 }, (_unused, index) => `critical-${index}`);
    expect(() => evaluatePolicy(rows.candidate, rows.champion, activeSpec, {
      workBudget: exactBudget,
    })).toThrow(/critical.*slice.*64|64.*critical.*slice/i);

    const boundedSpec = spec();
    boundedSpec.bootstrap.iterations = 1;
    rows.candidate[0].slices = Array.from({ length: 65 }, (_unused, index) => `slice-${index}`);
    expect(() => evaluatePolicy(rows.candidate, rows.champion, boundedSpec, {
      workBudget: exactBudget,
    })).toThrow(/row.*slice.*64|64.*row.*slice/i);
  });

  it("snapshots direct row collection data properties and rejects mutable collection shapes", () => {
    const rows = pairedRows([[0.9], [0.9], [0.9]], [[0.9], [0.9], [0.9]]);
    let getterCalls = 0;
    const accessorRows = [...rows.candidate];
    Object.defineProperty(accessorRows, "0", {
      configurable: true,
      enumerable: true,
      get() {
        getterCalls += 1;
        throw new Error("direct collection getter must not run");
      },
    });
    expect(() => evaluatePolicy(accessorRows, rows.champion, spec())).toThrow(
      /candidate.*collection.*accessor|accessor.*candidate.*collection/i,
    );
    expect(getterCalls).toBe(0);

    let lengthReads = 0;
    let elementReads = 0;
    const changingLength = new Proxy([rows.candidate[0]], {
      get(target, property, receiver) {
        if (property === "length") {
          lengthReads += 1;
          return lengthReads === 1 ? 1 : 20_000;
        }
        if (typeof property === "string" && /^\d+$/.test(property)) {
          elementReads += 1;
          return rows.candidate[0];
        }
        return Reflect.get(target, property, receiver);
      },
    });
    expect(() => evaluatePolicy(changingLength, [rows.champion[0]], spec(), {
      workBudget: {
        maxCandidates: 1,
        maxTraceRows: 1,
        maxEvidenceRows: 1,
        maxBootstrapDraws: 200,
        maxIndependentGroups: 1,
        maxAssessmentWork: 200,
      },
    })).toThrow(/candidate.*proxy|proxy.*candidate/i);
    expect(elementReads).toBe(0);

    const withExtra = [...rows.candidate] as ReplayedRow[] & { metadata?: string };
    withExtra.metadata = "not-row-data";
    expect(() => evaluatePolicy(withExtra, rows.champion, spec())).toThrow(/collection.*extra propert/i);
    const withSymbol = [...rows.candidate];
    Object.defineProperty(withSymbol, Symbol("forged"), { value: true });
    expect(() => evaluatePolicy(withSymbol, rows.champion, spec())).toThrow(/collection.*symbol/i);
    const withHole = [...rows.candidate];
    delete withHole[1];
    expect(() => evaluatePolicy(withHole, rows.champion, spec())).toThrow(/collection.*hole/i);

    let rowGetterCalls = 0;
    const accessorRow = { ...rows.candidate[0] };
    Object.defineProperty(accessorRow, "groupId", {
      enumerable: true,
      get() {
        rowGetterCalls += 1;
        throw new Error("row getter must not run");
      },
    });
    expect(() => evaluatePolicy([accessorRow], [rows.champion[0]], spec())).toThrow(
      /candidate.*row.*groupId.*accessor|accessor.*candidate.*row.*groupId/i,
    );
    expect(rowGetterCalls).toBe(0);
  });

  it("rejects excessive direct groups before copying the remaining rows", () => {
    const candidate = new Array<ReplayedRow>(40_000);
    candidate[0] = row({ caseId: "case-a", groupId: "group-a" });
    candidate[1] = row({ caseId: "case-b", groupId: "group-b" });
    let laterRowReads = 0;
    Object.defineProperty(candidate, "2", {
      enumerable: true,
      get() {
        laterRowReads += 1;
        throw new Error("later direct row getter must not run");
      },
    });

    expect(() => evaluatePolicy(candidate, [
      row({
        policyId: "champion",
        policyKind: "expert-only",
        selectedProfileId: "expert",
        attemptedProfileIds: ["expert"],
        caseId: "case-a",
        groupId: "group-a",
      }),
    ], spec(), {
      workBudget: {
        ...DEFAULT_ASSESSMENT_WORK_BUDGET,
        maxTraceRows: 40_000,
        maxEvidenceRows: 1,
        maxIndependentGroups: 1,
        maxAssessmentWork: Number.MAX_SAFE_INTEGER,
      },
    })).toThrow(/independent group count exceeds caller work budget/i);
    expect(laterRowReads).toBe(0);
  });

  it("snapshots nested direct-row capacity evidence without invoking getters", () => {
    const rows = pairedRows([[0.9]], [[0.9]]);
    let capacityGetterCalls = 0;
    const capacityRow = { ...rows.candidate[0] };
    capacityRow.serviceThroughput = {
      kind: "measured",
      get tokensPerSecond(): never {
        capacityGetterCalls += 1;
        throw new Error("capacity getter must not run");
      },
    };
    expect(() => computePolicyMetrics([capacityRow], [])).toThrow(
      /serviceThroughput.*tokensPerSecond.*accessor|accessor.*serviceThroughput/i,
    );
    expect(capacityGetterCalls).toBe(0);

    const holeRow = { ...rows.candidate[0], attemptedProfileIds: new Array<string>(1) };
    expect(() => computePolicyMetrics([holeRow], [])).toThrow(/attemptedProfileIds.*hole/i);

    const mismatchedAttempt = {
      ...rows.candidate[0],
      attemptedProfileIds: ["other-profile"],
    };
    expect(computePolicyMetrics([mismatchedAttempt], []).p50TotalTokensPerSecond).toBeNull();
  });

  it("rejects object-backed direct-row scalar metrics without invoking proxy traps", () => {
    const rows = pairedRows([[0.9]], [[0.9]]);
    let trapCalls = 0;
    const forgedMetric = new Proxy({}, {
      get() {
        trapCalls += 1;
        throw new Error("direct-row metric proxy trap must not run");
      },
    });
    (rows.candidate[0] as unknown as Record<string, unknown>).ttftMs = forgedMetric;

    expect(() => evaluatePolicy(rows.candidate, rows.champion, spec())).toThrow(
      /candidate.*row.*ttftMs.*number|ttftMs.*finite/i,
    );
    expect(trapCalls).toBe(0);
  });

  it.each([
    [
      "end-to-end latency below TTFT",
      { ttftMs: 100, endToEndLatencyMs: 1 },
      /end-to-end latency.*below TTFT/i,
    ],
    [
      "zero perceived rate for a multi-token success",
      { outputTokens: 10, perceivedTokensPerSecond: 0 },
      /positive perceived tokens per second/i,
    ],
    [
      "a decode duration that cannot fit inside end-to-end latency",
      {
        ttftMs: 0,
        endToEndLatencyMs: 1,
        outputTokens: 10_000,
        perceivedTokensPerSecond: 1_000,
      },
      /end-to-end latency cannot contain.*output tokens/i,
    ],
  ])("rejects a successful direct row with %s", (_label, invalid, expected) => {
    const rows = pairedRows([[0.9], [0.9], [0.9]], [[0.9], [0.9], [0.9]]);
    Object.assign(rows.candidate[0], invalid);

    expect(() => evaluatePolicy(rows.candidate, rows.champion, spec())).toThrow(expected);
  });

  it("retains explicit zero-valued failure semantics at the direct-row boundary", () => {
    const rows = pairedRows([[0.9], [0.9], [0.9]], [[0.9], [0.9], [0.9]]);
    for (const candidate of rows.candidate) {
      Object.assign(candidate, {
        status: "failure",
        taskScore: 0,
        ttftMs: 0,
        endToEndLatencyMs: 0,
        outputTokens: 0,
        perceivedTokensPerSecond: 0,
        serviceThroughput: { kind: "unavailable", reason: "failed execution" },
        failureCode: "timeout",
      });
    }

    expect(evaluatePolicy(rows.candidate, rows.champion, spec()).candidateMetrics)
      .toMatchObject({ meanTaskScore: 0, errorRate: 1 });
  });

  it("rejects whitespace aliases before counting direct-row groups or cases", () => {
    const groupAliases = pairedRows([[0.9], [0.9], [0.9]], [[0.9], [0.9], [0.9]]);
    for (let index = 0; index < groupAliases.candidate.length; index += 1) {
      const groupId = `same-group${" ".repeat(index)}`;
      groupAliases.candidate[index].groupId = groupId;
      groupAliases.champion[index].groupId = groupId;
    }
    expect(() => evaluatePolicy(groupAliases.candidate, groupAliases.champion, spec())).toThrow(
      /groupId.*trim|groupId.*whitespace|canonical.*groupId/i,
    );

    const caseAliases = pairedRows([[0.9], [0.9], [0.9]], [[0.9], [0.9], [0.9]]);
    for (let index = 0; index < caseAliases.candidate.length; index += 1) {
      const caseId = `same-case${" ".repeat(index)}`;
      caseAliases.candidate[index].caseId = caseId;
      caseAliases.champion[index].caseId = caseId;
    }
    expect(() => evaluatePolicy(caseAliases.candidate, caseAliases.champion, spec())).toThrow(
      /caseId.*trim|caseId.*whitespace|canonical.*caseId/i,
    );

    expect(() => computePolicyMetrics([
      row({ attemptedProfileIds: ["fast "] }),
    ], [])).toThrow(/attemptedProfileIds.*trim|attemptedProfileIds.*whitespace/i);
    expect(() => computePolicyMetrics([
      row({ slices: ["payments "] }),
    ], [])).toThrow(/slices.*trim|slices.*whitespace/i);
    expect(() => computePolicyMetrics([
      row({ status: "failure", taskScore: 0, failureCode: " timeout " }),
    ], [])).toThrow(/failureCode.*trim|failureCode.*whitespace/i);
    expect(() => computePolicyMetrics([row()], ["payments "])).toThrow(
      /critical slice list.*trim|critical slice list.*whitespace/i,
    );
  });

  it("rejects mixed direct rows that do not describe one exact policy", () => {
    const rows = pairedRows([[0.9], [0.9], [0.9]], [[0.9], [0.9], [0.9]]);
    rows.candidate[1].policyId = "different-policy";
    expect(() => evaluatePolicy(rows.candidate, rows.champion, spec())).toThrow(
      /candidate rows.*one policyId.*policyKind/i,
    );
  });

  it("fails closed before inference for fewer than the configured independent groups", () => {
    const rows = pairedRows([[0.9], [0.9]], [[0.9], [0.9]]);
    const result = evaluatePolicy(rows.candidate, rows.champion, spec());
    expect(result.pairedQuality).toMatchObject({
      inferenceAvailable: false,
      interval: { lo: null, hi: null },
    });
    expect(result.gates.find(({ id }) => id === "minimum_independent_groups"))
      .toMatchObject({ pass: false, actual: 2, threshold: 3 });
    expect(Number.isFinite(result.pairedQuality.estimate)).toBe(true);
    expect(Number.isFinite(result.pairedQuality.effectiveTrafficMass)).toBe(true);
    expect(() => JSON.parse(JSON.stringify(result))).not.toThrow();
  });

  it("returns an explicit reason for every absolute and paired gate", () => {
    const rows = pairedRows([[0.9], [0.9], [0.9]], [[0.9], [0.9], [0.9]]);
    const result = evaluatePolicy(rows.candidate, rows.champion, spec());

    expect(result.gates.map((gate) => gate.id)).toEqual([
      "paired_quality_non_inferiority",
      "minimum_independent_groups",
      "critical_slice_groups:payments",
      "critical_slice_groups:safety",
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
    rows.champion.forEach((champion, index) => {
      champion.slices = index === 0 ? ["payments"] : ["routine"];
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

function scaledMeasurements(
  caseCount: number,
  fastConfidence?: (caseIndex: number) => number,
): MeasurementSet {
  const value = measurements();
  const templates = value.cases;
  value.cases = Array.from({ length: caseCount }, (_unused, caseIndex) => {
    const measurementCase = structuredClone(templates[caseIndex % templates.length]);
    measurementCase.id = `scaled-case-${caseIndex}`;
    measurementCase.groupId = `scaled-group-${caseIndex}`;
    const fast = measurementCase.observations.find(({ profileId }) => profileId === "fast")!;
    for (const observation of fast.replicates) {
      if (observation.status === "success") {
        observation.confidence = fastConfidence?.(caseIndex) ?? observation.confidence;
      }
    }
    return measurementCase;
  });
  return value;
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
  value.constraints.minimumCriticalSliceGroups = 0;
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
  it("normalizes pre-Task4 raw specs at every direct public assessment boundary", () => {
    const activeSpec = nominationSpec();
    const legacySpec = withoutTask4Controls(activeSpec);
    const rows = pairedRows([[0.9], [0.9], [0.9]], [[0.9], [0.9], [0.9]]);
    const direct = evaluatePolicy(rows.candidate, rows.champion, legacySpec);
    expect(direct.pairedQuality).toMatchObject({ alpha: 0.05, inferenceAvailable: true });
    expect(direct.gates.find(({ id }) => id === "minimum_independent_groups"))
      .toMatchObject({ pass: true, threshold: 3 });

    expect(nominatePolicy(legacySpec, measurements()))
      .toEqual(nominatePolicy(activeSpec, measurements()));
    const nomination = nominatePolicy(activeSpec, measurements()).nomination!;
    expect(confirmNomination(
      legacySpec,
      measurements({ split: "holdout", groupPrefix: "holdout" }),
      nomination,
    ).status).toBe("DEMO_ONLY");
  });

  it("uses one getter-free spec snapshot for candidate budgeting and evaluation", () => {
    const activeSpec = nominationSpec();
    activeSpec.candidateSpace = {
      confidenceThresholds: [0.5],
      inputTokenThresholds: [1_000],
      includeFastOnly: false,
    };
    let getterCalls = 0;
    Object.defineProperty(activeSpec.profiles[0], "model", {
      enumerable: true,
      get() {
        getterCalls += 1;
        activeSpec.candidateSpace.confidenceThresholds.push(0.8);
        return "expert";
      },
    });

    expect(() => nominatePolicy(activeSpec, measurements(), {
      workBudget: {
        ...DEFAULT_ASSESSMENT_WORK_BUDGET,
        maxCandidates: 1,
      },
    })).toThrow(/profile.*accessor|accessor.*profile|own data propert/i);
    expect(getterCalls).toBe(0);
    expect(activeSpec.candidateSpace.confidenceThresholds).toEqual([0.5]);
  });

  it("snapshots nomination attestation options without invoking accessors", () => {
    let keyReads = 0;
    const options: Record<string, unknown> = {};
    Object.defineProperty(options, "attestationKey", {
      enumerable: true,
      get() {
        keyReads += 1;
        throw new Error("nomination attestation-key getter must not run");
      },
    });

    expect(() => nominatePolicy(
      nominationSpec(),
      measurements(),
      options,
    )).toThrow(/nomination options.*attestationKey.*accessor|accessor.*attestationKey/i);
    expect(keyReads).toBe(0);
  });

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

  it("rejects an oversized measurement case lower bound before reading case entries", () => {
    const oversizedCases = new Array<MeasurementSet["cases"][number]>(20_000);
    let caseReads = 0;
    Object.defineProperty(oversizedCases, "0", {
      enumerable: true,
      get() {
        caseReads += 1;
        throw new Error("measurement case getter must not run");
      },
    });
    const dev = { ...measurements(), cases: oversizedCases };

    expect(() => nominatePolicy(nominationSpec(), dev, {
      workBudget: {
        ...DEFAULT_ASSESSMENT_WORK_BUDGET,
        maxTraceRows: 1,
        maxEvidenceRows: 1,
      },
    })).toThrow(/(?:measurement row count|trace rows|evidence rows).*caller work budget/i);
    expect(caseReads).toBe(0);
  });

  it("accepts realistic additive row and grouped-bootstrap work", () => {
    const activeSpec = nominationSpec();
    activeSpec.bootstrap.iterations = 1_000;

    expect(() => nominatePolicy(activeSpec, scaledMeasurements(100))).not.toThrow();
  });

  it("rejects true additive grouped work before bootstrap allocation", () => {
    const activeSpec = nominationSpec();
    activeSpec.bootstrap.iterations = 1_000;
    const dev = scaledMeasurements(100);
    const lastReplicates = dev.cases[99].observations[1].replicates;
    let replicateReads = 0;
    Object.defineProperty(lastReplicates, "0", {
      enumerable: true,
      get() {
        replicateReads += 1;
        throw new Error("replicate getter must not run");
      },
    });

    expect(() => nominatePolicy(activeSpec, dev, {
      workBudget: {
        ...DEFAULT_ASSESSMENT_WORK_BUDGET,
        maxAssessmentWork: 500_000,
      },
    })).toThrow(/assessment work exceeds caller work budget/i);
    expect(replicateReads).toBe(0);
  });

  it("groups 2,000 equal objective signatures before skyline comparison", () => {
    const activeSpec = nominationSpec();
    activeSpec.bootstrap.iterations = 1;
    activeSpec.constraints.minimumIndependentGroups = 1;
    activeSpec.candidateSpace = {
      confidenceThresholds: Array.from(
        { length: 2_000 },
        (_unused, index) => (index + 1) / 2_001,
      ),
      inputTokenThresholds: [1_000],
      includeFastOnly: false,
    };

    const result = nominatePolicy(activeSpec, scaledMeasurements(1, () => 1), {
      workBudget: {
        ...DEFAULT_ASSESSMENT_WORK_BUDGET,
        maxAssessmentWork: 30_000,
      },
    });
    const groupedEstimate = estimateLegacyAssessmentWork({
      candidateCount: 2_000,
      traceRows: 2,
      evidenceRows: 2,
      bootstrapDraws: 1,
      independentGroups: 1,
    }, 1);
    const ungroupedEstimate = estimateLegacyAssessmentWork({
      candidateCount: 2_000,
      traceRows: 2,
      evidenceRows: 2,
      bootstrapDraws: 1,
      independentGroups: 1,
    }, 2_000);

    expect(groupedEstimate.frontierComparisonWork).toBe(0);
    expect(groupedEstimate.assessmentWork).toBeLessThanOrEqual(30_000);
    expect(ungroupedEstimate.assessmentWork).toBeGreaterThan(30_000);
    expect(result.frontier).toHaveLength(2_000);
  });

  it("charges unique objective signatures before quadratic skyline work", () => {
    const activeSpec = nominationSpec();
    activeSpec.bootstrap.iterations = 1;
    activeSpec.constraints.minimumIndependentGroups = 1;
    activeSpec.constraints.taskScoreFloor = 0;
    activeSpec.constraints.nonInferiorityMargin = -1;
    activeSpec.candidateSpace = {
      confidenceThresholds: Array.from(
        { length: 100 },
        (_unused, index) => (index + 1) / 101,
      ),
      inputTokenThresholds: [1_000],
      includeFastOnly: false,
    };

    expect(() => nominatePolicy(
      activeSpec,
      scaledMeasurements(100, (caseIndex) => (caseIndex + 1) / 101),
      {
        workBudget: {
          ...DEFAULT_ASSESSMENT_WORK_BUDGET,
          maxAssessmentWork: 60_000,
        },
      },
    )).toThrow(/frontier.*(?:assessment )?work.*caller work budget/i);
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
        || compareCodeUnits(left.policy.id, right.policy.id)
      ));
    expect(result.nomination?.policy.id).toBe(orderedFrontier[0].policy.id);
  });

  it("lets observed objectives dominate when disabled capacity is null on both cascades", () => {
    const activeSpec = nominationSpec();
    const dev = measurements({ fastOnlyMustFail: true });
    for (const measurementCase of dev.cases) {
      for (const observationSet of measurementCase.observations) {
        for (const observation of observationSet.replicates) {
          if (observation.status === "success") observation.taskScore = 0.95;
          observation.costUsd = observationSet.profileId === "expert" ? 0.03 : 0.005;
        }
      }
    }
    const result = nominatePolicy(activeSpec, dev);
    const passingCascades = result.evaluations.filter(({ policy, evaluation }) => (
      policy.kind === "cascade" && evaluation.passed
    ));
    const dominatedCascadeIds = passingCascades
      .filter(({ policy }) => policy.confidenceThreshold === 0.8)
      .map(({ policy }) => policy.id);

    expect(dominatedCascadeIds.length).toBeGreaterThan(0);
    expect(result.frontier).not.toEqual(expect.arrayContaining(dominatedCascadeIds));
  });

  it("omits disabled capacity when a measured fast-only policy dominates a null-capacity cascade", () => {
    const activeSpec = nominationSpec();
    activeSpec.candidateSpace = {
      confidenceThresholds: [0.8],
      inputTokenThresholds: [1_000],
      includeFastOnly: true,
    };
    const dev = measurements();
    for (const measurementCase of dev.cases) {
      for (const observationSet of measurementCase.observations) {
        for (const observation of observationSet.replicates) {
          if (observation.status === "success") observation.taskScore = 0.95;
          observation.costUsd = observationSet.profileId === "expert" ? 0.03 : 0.005;
        }
      }
    }

    const result = nominatePolicy(activeSpec, dev);
    const fastOnly = result.evaluations.find(({ policy }) => policy.kind === "fast-only")!;
    const cascade = result.evaluations.find(({ policy }) => policy.kind === "cascade")!;
    expect(fastOnly.evaluation.passed).toBe(true);
    expect(cascade.evaluation.passed).toBe(true);
    expect(fastOnly.evaluation.candidateMetrics.p50TotalTokensPerSecond).not.toBeNull();
    expect(cascade.evaluation.candidateMetrics.p50TotalTokensPerSecond).toBeNull();
    expect(result.frontier).toContain(fastOnly.policy.id);
    expect(result.frontier).not.toContain(cascade.policy.id);
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

  it("rejects nomination accessor swaps before attestation or policy verification", () => {
    const signed = nominated(false, ATTESTATION_KEY);
    const alternate = generateCandidatePolicies(signed.activeSpec)
      .find((policy) => policy.id !== signed.nomination.policy.id)!;
    let policyReads = 0;
    let digestReads = 0;
    const forged = { ...signed.nomination };
    Object.defineProperty(forged, "policy", {
      enumerable: true,
      get() {
        policyReads += 1;
        return policyReads <= 2 ? signed.nomination.policy : alternate;
      },
    });
    Object.defineProperty(forged, "policyDigest", {
      enumerable: true,
      get() {
        digestReads += 1;
        return digestReads <= 2
          ? signed.nomination.policyDigest
          : fingerprintPolicy(alternate);
      },
    });

    expect(() => confirmNomination(
      signed.activeSpec,
      measurements({ split: "holdout", groupPrefix: "holdout", synthetic: false }),
      forged,
      { attestationKey: ATTESTATION_KEY },
    )).toThrow(/nomination.*policy.*accessor|accessor.*nomination.*policy/i);
    expect(policyReads).toBe(0);
    expect(digestReads).toBe(0);
  });

  it("snapshots confirmation attestation options without invoking accessors", () => {
    const unsigned = nominated();
    let keyReads = 0;
    const options: Record<string, unknown> = {};
    Object.defineProperty(options, "attestationKey", {
      enumerable: true,
      get() {
        keyReads += 1;
        throw new Error("confirmation attestation-key getter must not run");
      },
    });

    expect(() => confirmNomination(
      unsigned.activeSpec,
      measurements({ split: "holdout", groupPrefix: "holdout" }),
      unsigned.nomination,
      options,
    )).toThrow(/confirmation options.*attestationKey.*accessor|accessor.*attestationKey/i);
    expect(keyReads).toBe(0);
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

  it("round-trips a generated nomination at the 64-critical-slice contract limit", () => {
    const activeSpec = nominationSpec();
    const criticalSlices = Array.from({ length: 64 }, (_unused, index) => `critical-${index}`);
    activeSpec.criticalSlices = criticalSlices;
    activeSpec.constraints.minimumCriticalSliceGroups = 1;
    const dev = measurements();
    const holdout = measurements({ split: "holdout", groupPrefix: "holdout" });
    for (const dataset of [dev, holdout]) {
      for (const measurementCase of dataset.cases) {
        measurementCase.critical = true;
        measurementCase.slices = [...criticalSlices];
      }
    }

    const nomination = nominatePolicy(activeSpec, dev).nomination!;
    expect(nomination.gates).toHaveLength(138);
    const confirmation = confirmNomination(activeSpec, holdout, nomination);
    expect(confirmation.evaluation.gates).toHaveLength(137);
    expect(confirmation.status).toBe("DEMO_ONLY");
  });

  it.each(["__proto__", "constructor", "prototype"])(
    "round-trips the legal %s critical-slice record key",
    (criticalSlice) => {
      const activeSpec = nominationSpec();
      activeSpec.criticalSlices = [criticalSlice];
      activeSpec.constraints.minimumCriticalSliceGroups = 1;
      const dev = measurements();
      const holdout = measurements({ split: "holdout", groupPrefix: "holdout" });
      for (const dataset of [dev, holdout]) {
        for (const measurementCase of dataset.cases) {
          measurementCase.critical = true;
          measurementCase.slices = [criticalSlice];
        }
      }

      const nomination = nominatePolicy(activeSpec, dev).nomination!;
      expect(Object.hasOwn(nomination.candidateMetrics.criticalSliceTaskScore, criticalSlice)).toBe(true);
      expect(confirmNomination(activeSpec, holdout, nomination).status).toBe("DEMO_ONLY");
    },
  );

  it("charges nomination development groups to the caller budget before copying entries", () => {
    const unsigned = nominated();
    unsigned.nomination.developmentGroupIds = Array.from(
      { length: 9 },
      (_unused, index) => `artifact-group-${index}`,
    );
    const resigned = resignNomination(unsigned.nomination);
    let groupReads = 0;
    Object.defineProperty(resigned.developmentGroupIds, "8", {
      enumerable: true,
      get() {
        groupReads += 1;
        return "artifact-group-8";
      },
    });

    expect(() => confirmNomination(
      unsigned.activeSpec,
      measurements({ split: "holdout", groupPrefix: "holdout" }),
      resigned,
      {
        workBudget: {
          ...DEFAULT_ASSESSMENT_WORK_BUDGET,
          maxIndependentGroups: 8,
        },
      },
    )).toThrow(/developmentGroupIds.*exceeds.*8|independent group.*budget/i);
    expect(groupReads).toBe(0);
  });

  it("caps passing real legacy-v1 evidence at HOLD with an explicit migration reason", () => {
    const { activeSpec, nomination } = nominated(false, ATTESTATION_KEY);
    const result = confirmNomination(
      activeSpec,
      measurements({ split: "holdout", groupPrefix: "holdout", synthetic: false }),
      nomination,
      { attestationKey: ATTESTATION_KEY },
    );
    expect(result).toMatchObject({
      status: "HOLD",
      attestationVerified: true,
    });
    expect(result.statusReason).toMatch(/legacy v1.*migrat|migrat.*v2/i);
  });

  it("keeps nomination and decision digests stable when case and profile rows are reordered", () => {
    const activeSpec = nominationSpec();
    const reorderedSpec = structuredClone(activeSpec);
    reorderedSpec.profiles.reverse();
    reorderedSpec.candidateSpace.confidenceThresholds.reverse();
    reorderedSpec.candidateSpace.inputTokenThresholds.reverse();
    const original = measurements();
    const reordered = structuredClone(original);
    reordered.cases.reverse();
    reordered.cases.forEach((measurementCase) => measurementCase.observations.reverse());

    expect(nominatePolicy(reorderedSpec, reordered)).toEqual(nominatePolicy(activeSpec, original));
  });

  it("accepts the pre-default legacy spec digest only for default migration controls", () => {
    const defaults = nominated();
    const legacyDefaultSpec = structuredClone(defaults.activeSpec) as any;
    delete legacyDefaultSpec.constraints.minimumIndependentGroups;
    delete legacyDefaultSpec.constraints.minimumCriticalSliceGroups;
    delete legacyDefaultSpec.bootstrap.alpha;
    defaults.nomination.specDigest = sha256(stableJson(legacyDefaultSpec));
    const migrated = resignNomination(defaults.nomination);
    expect(confirmNomination(
      defaults.activeSpec,
      measurements({ split: "holdout", groupPrefix: "holdout" }),
      migrated,
    ).status).toBe("DEMO_ONLY");

    const nonDefaultSpec = nominationSpec();
    nonDefaultSpec.bootstrap.alpha = 0.1;
    const nonDefaultNomination = nominatePolicy(nonDefaultSpec, measurements()).nomination!;
    const legacyNonDefaultSpec = structuredClone(nonDefaultSpec) as any;
    delete legacyNonDefaultSpec.constraints.minimumIndependentGroups;
    delete legacyNonDefaultSpec.constraints.minimumCriticalSliceGroups;
    delete legacyNonDefaultSpec.bootstrap.alpha;
    nonDefaultNomination.specDigest = sha256(stableJson(legacyNonDefaultSpec));
    expect(() => confirmNomination(
      nonDefaultSpec,
      measurements({ split: "holdout", groupPrefix: "holdout" }),
      resignNomination(nonDefaultNomination),
    )).toThrow(/spec digest mismatch/i);
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
    expect(result.statusReason).toMatch(/legacy v1.*migrat|migrat.*v2/i);
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
