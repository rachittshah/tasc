import { describe, expect, it } from "vitest";
import { parseInferenceSpec, parseMeasurementSet } from "../src/schema.js";
import {
  championPolicy,
  fingerprintPolicy,
  generateCandidatePolicies,
  replayPolicy,
} from "../src/policy.js";

const spec = () => parseInferenceSpec({
  version: "tasc-inference-spec-v1",
  id: "policy-fixture",
  profiles: [
    { id: "expert", model: "expert", runtime: "remote", hardware: "gpu" },
    { id: "fast", model: "fast", runtime: "remote", hardware: "gpu" },
  ],
  championProfileId: "expert",
  primaryProfileId: "fast",
  candidateSpace: { confidenceThresholds: [0.8], inputTokenThresholds: [1_000], includeFastOnly: true },
  criticalSlices: ["critical"],
  constraints: {
    taskScoreFloor: 0.7,
    criticalSliceScoreFloor: 0.7,
    maxP95TtftMs: 5_000,
    maxP95EndToEndLatencyMs: 10_000,
    minP10PerceivedTokensPerSecond: 1,
    minP50TotalTokensPerSecond: 1,
    maxErrorRate: 0.1,
    maxCostPerThousandRequests: 100,
    nonInferiorityMargin: -0.02,
    minimumCostImprovement: 0.1,
  },
  bootstrap: { seed: 2, iterations: 100 },
});

const success = (overrides: Record<string, unknown> = {}) => ({
  status: "success",
  taskScore: 0.9,
  confidence: 0.95,
  ttftMs: 100,
  endToEndLatencyMs: 500,
  outputTokens: 40,
  perceivedTokensPerSecond: 80,
  totalTokensPerSecond: 70,
  costUsd: 0.01,
  ...overrides,
});

const failure = (overrides: Record<string, unknown> = {}) => ({
  status: "failure",
  failureCode: "timeout",
  elapsedMs: 300,
  costUsd: 0.002,
  ...overrides,
});

const measurementCase = (
  id: string,
  fast: Record<string, unknown>,
  expert: Record<string, unknown> = success({ taskScore: 0.99, ttftMs: 200, endToEndLatencyMs: 900, costUsd: 0.05 }),
  overrides: Record<string, unknown> = {},
) => ({
  id,
  groupId: `${id}-group`,
  inputTokens: 100,
  outputTokens: 40,
  repeatedPrefixTokens: 0,
  concurrency: 1,
  mode: "chat",
  critical: false,
  trafficWeight: 1,
  slices: ["routine"],
  observations: [
    { profileId: "expert", replicates: [expert] },
    { profileId: "fast", replicates: [fast] },
  ],
  ...overrides,
});

const measurements = () => parseMeasurementSet({
  version: "tasc-measurements-v1",
  dataset: { id: "dev", version: "1", source: "fixture", split: "dev", synthetic: true },
  evaluator: { id: "deterministic", version: "1", kind: "deterministic", validated: false },
  cases: [
    measurementCase("routine", success({ taskScore: 0.8, costUsd: 0.01 })),
    measurementCase("primary-failure", failure()),
    measurementCase("missing-confidence", success({ confidence: undefined })),
    measurementCase("low-confidence", success({ confidence: 0.7 })),
    measurementCase("long-input", success(), success(), { inputTokens: 1_000 }),
    measurementCase("critical-slice", success(), success(), { slices: ["critical"] }),
    measurementCase("unconfigured-critical", success(), success(), { critical: true }),
    measurementCase("double-failure", failure(), failure({ elapsedMs: 700, costUsd: 0.03 })),
  ],
});

function policy(kind: "fast-only" | "cascade") {
  return generateCandidatePolicies(spec()).find((candidate) => candidate.kind === kind)!;
}

describe("TASC empirical policy replay", () => {
  it("keeps candidate IDs and policy digests stable", () => {
    const first = generateCandidatePolicies(spec());
    const second = generateCandidatePolicies(spec());

    expect(first).toEqual(second);
    expect(first.map((candidate) => candidate.id)).toEqual([...first.map((candidate) => candidate.id)].sort());
    expect(fingerprintPolicy(championPolicy(spec()))).toBe(fingerprintPolicy(championPolicy(spec())));
  });

  it("uses the matching empirical row for expert-only and fast-only policies", () => {
    const data = measurements();
    const expert = replayPolicy(championPolicy(spec()), spec(), data).find((row) => row.caseId === "routine")!;
    const fast = replayPolicy(policy("fast-only"), spec(), data).find((row) => row.caseId === "routine")!;

    expect(expert.selectedProfileId).toBe("expert");
    expect(expert.costUsd).toBe(0.05);
    expect(fast.selectedProfileId).toBe("fast");
    expect(fast.costUsd).toBe(0.01);
  });

  it.each(["primary-failure", "missing-confidence", "low-confidence", "long-input", "critical-slice"]) (
    "escalates a cascade for %s",
    (caseId) => {
      const row = replayPolicy(policy("cascade"), spec(), measurements()).find((candidate) => candidate.caseId === caseId)!;
      expect(row.escalated).toBe(true);
      expect(row.selectedProfileId).toBe("expert");
    },
  );

  it("preserves the fast row when no cascade rule fires", () => {
    const row = replayPolicy(policy("cascade"), spec(), measurements()).find((candidate) => candidate.caseId === "routine")!;
    expect(row).toMatchObject({
      selectedProfileId: "fast",
      escalated: false,
      taskScore: 0.8,
      ttftMs: 100,
      endToEndLatencyMs: 500,
      costUsd: 0.01,
    });
  });

  it("does not escalate an unconfigured critical case", () => {
    const row = replayPolicy(policy("cascade"), spec(), measurements()).find((candidate) => candidate.caseId === "unconfigured-critical")!;
    expect(row).toMatchObject({
      selectedProfileId: "fast",
      escalated: false,
      critical: true,
      slices: ["routine"],
    });
  });

  it("retains both costs and serial latency when an escalation succeeds", () => {
    const row = replayPolicy(policy("cascade"), spec(), measurements()).find((candidate) => candidate.caseId === "primary-failure")!;
    expect(row).toMatchObject({
      status: "success",
      ttftMs: 500,
      endToEndLatencyMs: 1_200,
    });
    expect(row.costUsd).toBeCloseTo(0.052, 12);
  });

  it("keeps an expert failure after escalation as an explicit failed row", () => {
    const row = replayPolicy(policy("cascade"), spec(), measurements()).find((candidate) => candidate.caseId === "double-failure")!;
    expect(row).toMatchObject({
      status: "failure",
      selectedProfileId: "expert",
      escalated: true,
      taskScore: 0,
      costUsd: 0.032,
      ttftMs: 1_000,
      endToEndLatencyMs: 1_000,
      failureCode: "timeout",
    });
  });

  it("generates deterministic duplicate-free candidate policies", () => {
    const duplicateThresholdSpec = spec();
    duplicateThresholdSpec.candidateSpace.confidenceThresholds = [0.8, 0.8];
    duplicateThresholdSpec.candidateSpace.inputTokenThresholds = [1_000, 1_000];
    const candidates = generateCandidatePolicies(duplicateThresholdSpec);
    const ids = candidates.map((candidate) => candidate.id);
    expect(new Set(ids).size).toBe(ids.length);
    expect(candidates).toHaveLength(2);
    expect(candidates.map((candidate) => candidate.kind)).toEqual(["cascade", "fast-only"]);
  });
});
