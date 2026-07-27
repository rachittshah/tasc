import { describe, expect, it } from "vitest";
import {
  assertMeasurementMatrix,
  inferenceSpecSchema,
  measurementSetSchema,
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
    expect(spec.constraints.minimumIndependentGroups).toBe(3);
    expect(spec.constraints.minimumCriticalSliceGroups).toBe(1);
    expect(spec.bootstrap.alpha).toBe(0.05);
    expect(measurements.dataset.split).toBe("dev");
    expect(() => assertMeasurementMatrix(spec, measurements)).not.toThrow();
  });

  it("defaults legacy critical-slice group coverage to zero when no critical slice is configured", () => {
    const withoutCriticalSlices = validSpec();
    withoutCriticalSlices.criticalSlices = [];
    expect(parseInferenceSpec(withoutCriticalSlices).constraints.minimumCriticalSliceGroups).toBe(0);

    const inconsistent = validSpec();
    inconsistent.criticalSlices = [];
    (inconsistent.constraints as any).minimumCriticalSliceGroups = 1;
    expect(() => parseInferenceSpec(inconsistent)).toThrow(/critical.slice.*minimum.*zero/i);
  });

  it("accepts explicit bounded legacy inference controls and rejects unsafe values", () => {
    const explicit = validSpec();
    (explicit.constraints as any).minimumIndependentGroups = 7;
    (explicit.constraints as any).minimumCriticalSliceGroups = 2;
    (explicit.bootstrap as any).alpha = 0.1;
    expect(parseInferenceSpec(explicit)).toMatchObject({
      constraints: {
        minimumIndependentGroups: 7,
        minimumCriticalSliceGroups: 2,
      },
      bootstrap: { alpha: 0.1 },
    });

    const invalidGroups = validSpec();
    (invalidGroups.constraints as any).minimumIndependentGroups = 0;
    expect(() => parseInferenceSpec(invalidGroups)).toThrow(/minimumIndependentGroups|greater than/i);
    const invalidAlpha = validSpec();
    (invalidAlpha.bootstrap as any).alpha = 1;
    expect(() => parseInferenceSpec(invalidAlpha)).toThrow(/alpha|less than/i);
  });

  it("keeps the exported schema parser identical to the hardened migration parser", () => {
    const legacy = validSpec();
    expect(inferenceSpecSchema.parse(legacy)).toEqual(parseInferenceSpec(legacy));

    let getterCalls = 0;
    Object.defineProperty(legacy.profiles[0], "model", {
      enumerable: true,
      get() {
        getterCalls += 1;
        throw new Error("profile getter must not run");
      },
    });
    expect(() => inferenceSpecSchema.parse(legacy)).toThrow(/accessor|own data propert/i);
    expect(getterCalls).toBe(0);
  });

  it("migrates an explicitly undefined critical-slice group minimum like omission", () => {
    const legacy = validSpec();
    Object.defineProperty(legacy.constraints, "minimumCriticalSliceGroups", {
      configurable: true,
      enumerable: true,
      value: undefined,
      writable: true,
    });
    expect(parseInferenceSpec(legacy).constraints.minimumCriticalSliceGroups).toBe(1);
  });

  it("rejects prototype mutation keys instead of materializing inherited safety or lineage fields", () => {
    const spec = validSpec();
    Object.defineProperty(spec.constraints, "__proto__", {
      enumerable: true,
      value: { minimumIndependentGroups: 1 },
    });
    expect(() => parseInferenceSpec(spec)).toThrow(/__proto__|prototype.*key/i);

    const measurements = validMeasurements();
    const firstCase = measurements.cases[0] as Record<string, unknown>;
    delete firstCase.groupId;
    Object.defineProperty(firstCase, "__proto__", {
      enumerable: true,
      value: { groupId: "hidden-group" },
    });
    expect(() => parseMeasurementSet(measurements)).toThrow(/__proto__|prototype.*key/i);
  });

  it("rejects excessive contract nesting with a controlled depth error", () => {
    const spec = validSpec() as Record<string, unknown>;
    const extra: Record<string, unknown> = {};
    let cursor = extra;
    for (let depth = 0; depth < 100; depth += 1) {
      const child: Record<string, unknown> = {};
      cursor.child = child;
      cursor = child;
    }
    spec.extra = extra;
    expect(() => parseInferenceSpec(spec)).toThrow(/nesting depth|snapshot.*depth/i);
  });

  it("rejects repeated object references before a shared DAG can expand", () => {
    const spec = validSpec() as Record<string, unknown>;
    let shared: Record<string, unknown> = { leaf: true };
    for (let depth = 0; depth < 12; depth += 1) {
      shared = { left: shared, right: shared };
    }
    spec.extra = shared;
    expect(() => parseInferenceSpec(spec)).toThrow(/repeated|shared.*reference/i);
  });

  it("rejects inherited or accessor-backed safety controls without invoking getters", () => {
    for (const [label, mutate] of [
      ["minimumIndependentGroups", (value: ReturnType<typeof validSpec>, getter: () => never) => {
        Object.defineProperty(value.constraints, "minimumIndependentGroups", {
          enumerable: true,
          get: getter,
        });
      }],
      ["minimumCriticalSliceGroups", (value: ReturnType<typeof validSpec>, getter: () => never) => {
        Object.defineProperty(value.constraints, "minimumCriticalSliceGroups", {
          enumerable: true,
          get: getter,
        });
      }],
      ["alpha", (value: ReturnType<typeof validSpec>, getter: () => never) => {
        Object.defineProperty(value.bootstrap, "alpha", {
          enumerable: true,
          get: getter,
        });
      }],
      ["constraints", (value: ReturnType<typeof validSpec>, getter: () => never) => {
        Object.defineProperty(value, "constraints", {
          enumerable: true,
          get: getter,
        });
      }],
    ] as const) {
      const value = validSpec();
      let getterCalls = 0;
      mutate(value, () => {
        getterCalls += 1;
        throw new Error(`${label} getter must not run`);
      });
      expect(() => parseInferenceSpec(value)).toThrow(/plain.*data propert|accessor.*not allowed/i);
      expect(getterCalls).toBe(0);
    }

    const inherited = validSpec();
    inherited.constraints = Object.assign(
      Object.create({ minimumIndependentGroups: 1 }),
      inherited.constraints,
    );
    expect(() => parseInferenceSpec(inherited)).toThrow(/plain.*object|inherited|own.*data propert/i);
  });

  it("snapshots measurement rows without invoking lineage accessors", () => {
    const measurements = validMeasurements();
    let getterCalls = 0;
    Object.defineProperty(measurements.cases[0], "groupId", {
      enumerable: true,
      get() {
        getterCalls += 1;
        throw new Error("measurement getter must not run");
      },
    });
    expect(() => parseMeasurementSet(measurements)).toThrow(/groupId.*accessor|accessor.*groupId/i);
    expect(getterCalls).toBe(0);

    const throughSchema = validMeasurements();
    Object.defineProperty(throughSchema.cases[0], "groupId", {
      enumerable: true,
      get() {
        getterCalls += 1;
        throw new Error("measurement schema getter must not run");
      },
    });
    expect(() => measurementSetSchema.parse(throughSchema)).toThrow(/groupId.*accessor|accessor.*groupId/i);
    expect(getterCalls).toBe(0);
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

  it("rejects duplicate or unbounded slice labels", () => {
    const duplicate = validMeasurements();
    duplicate.cases[0].slices = ["routine", "routine"];
    expect(() => parseMeasurementSet(duplicate)).toThrow(/duplicate.*slice/i);

    const oversized = validMeasurements();
    oversized.cases[0].slices = Array.from({ length: 65 }, (_unused, index) => `slice-${index}`);
    expect(() => parseMeasurementSet(oversized)).toThrow(/64|too big|at most/i);
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
