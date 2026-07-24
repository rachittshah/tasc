import { describe, expect, it } from "vitest";
import {
  assertMeasurementMatrix,
  parseInferenceSpec,
  parseMeasurementSet,
} from "../src/schema.js";

const validSpec = () => ({
  version: "tasc-inference-spec-v1",
  id: "support-routing-v1",
  profiles: [
    { id: "expert", model: "expert-model", runtime: "provider-a", hardware: "remote" },
    { id: "fast", model: "fast-model", runtime: "provider-b", hardware: "remote" },
  ],
  championProfileId: "expert",
  primaryProfileId: "fast",
  candidateSpace: {
    confidenceThresholds: [0.6, 0.8],
    inputTokenThresholds: [1_000, 2_000],
    includeFastOnly: true,
  },
  criticalSlices: ["payments"],
  constraints: {
    taskScoreFloor: 0.7,
    criticalSliceScoreFloor: 0.75,
    maxP95TtftMs: 5_000,
    maxP95EndToEndLatencyMs: 10_000,
    minP10PerceivedTokensPerSecond: 1,
    minP50TotalTokensPerSecond: 1,
    maxErrorRate: 0.05,
    maxCostPerThousandRequests: 100,
    nonInferiorityMargin: -0.02,
    minimumCostImprovement: 0.1,
  },
  bootstrap: { seed: 17, iterations: 1_000 },
});

const success = (taskScore = 0.9, confidence: number | undefined = 0.9) => ({
  status: "success",
  taskScore,
  ...(confidence === undefined ? {} : { confidence }),
  ttftMs: 100,
  endToEndLatencyMs: 500,
  outputTokens: 40,
  perceivedTokensPerSecond: 80,
  totalTokensPerSecond: 70,
  costUsd: 0.01,
  cacheHit: false,
});

const validMeasurements = (split: "dev" | "holdout" = "dev") => ({
  version: "tasc-measurements-v1",
  dataset: {
    id: `support-${split}`,
    version: "1",
    source: "fixture",
    split,
    synthetic: true,
  },
  evaluator: { id: "rubric", version: "1", kind: "deterministic", validated: false },
  cases: [
    {
      id: "case-1",
      groupId: "thread-1",
      inputTokens: 400,
      outputTokens: 40,
      repeatedPrefixTokens: 50,
      concurrency: 1,
      mode: "chat",
      critical: false,
      trafficWeight: 1,
      slices: ["routine"],
      observations: [
        { profileId: "expert", replicates: [success(0.95)] },
        { profileId: "fast", replicates: [success(0.85)] },
      ],
    },
  ],
});

describe("TASC input contracts", () => {
  it("parses a valid spec and complete development measurement matrix", () => {
    const spec = parseInferenceSpec(validSpec());
    const measurements = parseMeasurementSet(validMeasurements(), "dev");

    expect(spec.primaryProfileId).toBe("fast");
    expect(measurements.dataset.split).toBe("dev");
    expect(() => assertMeasurementMatrix(spec, measurements)).not.toThrow();
  });

  it("rejects incomplete profile observations with the case and profile", () => {
    const measurements = validMeasurements();
    measurements.cases[0].observations = measurements.cases[0].observations.filter((row) => row.profileId !== "expert");

    expect(() => assertMeasurementMatrix(parseInferenceSpec(validSpec()), parseMeasurementSet(measurements))).toThrow(
      /case "case-1".*profile "expert"/,
    );
  });

  it("rejects mismatched profile replicate counts with the case and profile", () => {
    const measurements = validMeasurements();
    measurements.cases[0].observations[0].replicates.push(success());

    expect(() => assertMeasurementMatrix(parseInferenceSpec(validSpec()), parseMeasurementSet(measurements))).toThrow(
      /case "case-1".*profile "fast".*replicate/i,
    );
  });

  it.each([
    ["NaN", () => { const value = validMeasurements(); value.cases[0].observations[0].replicates[0].ttftMs = Number.NaN; return value; }],
    ["infinity", () => { const value = validMeasurements(); value.cases[0].observations[0].replicates[0].endToEndLatencyMs = Infinity; return value; }],
    ["negative latency", () => { const value = validMeasurements(); value.cases[0].observations[0].replicates[0].ttftMs = -1; return value; }],
    ["negative cost", () => { const value = validMeasurements(); value.cases[0].observations[0].replicates[0].costUsd = -1; return value; }],
    ["out-of-range score", () => { const value = validMeasurements(); value.cases[0].observations[0].replicates[0].taskScore = 1.1; return value; }],
    ["out-of-range confidence", () => { const value = validMeasurements(); value.cases[0].observations[0].replicates[0].confidence = -0.1; return value; }],
  ])("rejects %s", (_label, invalid) => {
    expect(() => parseMeasurementSet(invalid())).toThrow();
  });

  it("requires every inferential case to have positive traffic mass", () => {
    const measurements = validMeasurements();
    measurements.cases[0].trafficWeight = 0;

    expect(() => parseMeasurementSet(measurements)).toThrow(/trafficWeight|greater than 0/i);
  });

  it("rejects successful timing rows that cannot contain their measured token stream", () => {
    const shorterThanTtft = validMeasurements();
    shorterThanTtft.cases[0].observations[0].replicates[0].endToEndLatencyMs = 50;
    expect(() => parseMeasurementSet(shorterThanTtft)).toThrow(/case "case-1".*expert.*end-to-end.*ttft/i);

    const impossibleDecode = validMeasurements();
    impossibleDecode.cases[0].observations[0].replicates[0].outputTokens = 400;
    impossibleDecode.cases[0].observations[0].replicates[0].perceivedTokensPerSecond = 1;
    expect(() => parseMeasurementSet(impossibleDecode)).toThrow(/case "case-1".*expert.*token.*perceived/i);

    const zeroDecodeRate = validMeasurements();
    zeroDecodeRate.cases[0].observations[0].replicates[0].perceivedTokensPerSecond = 0;
    expect(() => parseMeasurementSet(zeroDecodeRate)).toThrow(/case "case-1".*expert.*perceived/i);
  });

  it("rejects duplicate case and profile IDs", () => {
    const duplicateCases = validMeasurements();
    duplicateCases.cases.push(structuredClone(duplicateCases.cases[0]));
    expect(() => parseMeasurementSet(duplicateCases)).toThrow(/duplicate case id "case-1"/);

    const duplicateProfiles = validSpec();
    duplicateProfiles.profiles[1].id = "expert";
    expect(() => parseInferenceSpec(duplicateProfiles)).toThrow(/duplicate profile id "expert"/);
  });

  it("rejects an unvalidated LLM judge", () => {
    const measurements = validMeasurements();
    measurements.evaluator = { id: "judge", version: "1", kind: "llm-judge", validated: false };

    expect(() => parseMeasurementSet(measurements)).toThrow(/llm-judge.*independently validated/i);
  });

  it("rejects a holdout measurement set when nomination requires development data", () => {
    expect(() => parseMeasurementSet(validMeasurements("holdout"), "dev")).toThrow(/split "holdout".*expected "dev"/);
  });
});
