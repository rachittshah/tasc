import { z } from "zod";

export type Split = "dev" | "holdout";

export interface ServingProfile {
  id: string;
  model: string;
  runtime: string;
  hardware: string;
}

export interface InferenceSpec {
  version: "tasc-inference-spec-v1";
  id: string;
  profiles: ServingProfile[];
  championProfileId: string;
  primaryProfileId: string;
  candidateSpace: {
    confidenceThresholds: number[];
    inputTokenThresholds: number[];
    includeFastOnly: boolean;
  };
  criticalSlices: string[];
  constraints: {
    taskScoreFloor: number;
    criticalSliceScoreFloor: number;
    maxP95TtftMs: number;
    maxP95EndToEndLatencyMs: number;
    minP10PerceivedTokensPerSecond: number;
    minP50TotalTokensPerSecond: number;
    maxErrorRate: number;
    maxCostPerThousandRequests: number;
    nonInferiorityMargin: number;
    minimumCostImprovement: number;
  };
  bootstrap: {
    seed: number;
    iterations: number;
  };
}

export interface SuccessfulObservation {
  status: "success";
  taskScore: number;
  confidence?: number;
  ttftMs: number;
  endToEndLatencyMs: number;
  outputTokens: number;
  perceivedTokensPerSecond: number;
  totalTokensPerSecond: number;
  costUsd: number;
  cacheHit?: boolean;
}

export interface FailedObservation {
  status: "failure";
  failureCode: string;
  elapsedMs: number;
  costUsd: number;
}

export type Observation = SuccessfulObservation | FailedObservation;

export interface ProfileObservationSet {
  profileId: string;
  replicates: Observation[];
}

export interface MeasurementCase {
  id: string;
  groupId: string;
  inputTokens: number;
  outputTokens: number;
  repeatedPrefixTokens: number;
  concurrency: number;
  mode: string;
  critical: boolean;
  trafficWeight: number;
  slices: string[];
  observations: ProfileObservationSet[];
}

export interface MeasurementSet {
  version: "tasc-measurements-v1";
  dataset: {
    id: string;
    version: string;
    source: string;
    split: Split;
    synthetic: boolean;
  };
  evaluator: {
    id: string;
    version: string;
    kind: "human" | "deterministic" | "llm-judge";
    validated: boolean;
  };
  cases: MeasurementCase[];
}

const nonEmptyString = z.string().trim().min(1);
const finiteNonNegative = z.number().finite().nonnegative();
const score = z.number().finite().min(0).max(1);
const nonNegativeInteger = z.number().int().finite().nonnegative();

const profileSchema = z.object({
  id: nonEmptyString,
  model: nonEmptyString,
  runtime: nonEmptyString,
  hardware: nonEmptyString,
}).strict();

export const inferenceSpecSchema: z.ZodType<InferenceSpec> = z.object({
  version: z.literal("tasc-inference-spec-v1"),
  id: nonEmptyString,
  profiles: z.array(profileSchema).min(2),
  championProfileId: nonEmptyString,
  primaryProfileId: nonEmptyString,
  candidateSpace: z.object({
    confidenceThresholds: z.array(score).min(1),
    inputTokenThresholds: z.array(nonNegativeInteger).min(1),
    includeFastOnly: z.boolean(),
  }).strict(),
  criticalSlices: z.array(nonEmptyString),
  constraints: z.object({
    taskScoreFloor: score,
    criticalSliceScoreFloor: score,
    maxP95TtftMs: finiteNonNegative,
    maxP95EndToEndLatencyMs: finiteNonNegative,
    minP10PerceivedTokensPerSecond: finiteNonNegative,
    minP50TotalTokensPerSecond: finiteNonNegative,
    maxErrorRate: score,
    maxCostPerThousandRequests: finiteNonNegative,
    nonInferiorityMargin: z.number().finite().min(-1).max(1),
    minimumCostImprovement: score,
  }).strict(),
  bootstrap: z.object({
    seed: z.number().int().finite(),
    iterations: z.number().int().finite().positive(),
  }).strict(),
}).strict();

const successfulObservationSchema = z.object({
  status: z.literal("success"),
  taskScore: score,
  confidence: score.optional(),
  ttftMs: finiteNonNegative,
  endToEndLatencyMs: finiteNonNegative,
  outputTokens: nonNegativeInteger,
  perceivedTokensPerSecond: finiteNonNegative,
  totalTokensPerSecond: finiteNonNegative,
  costUsd: finiteNonNegative,
  cacheHit: z.boolean().optional(),
}).strict();

const failedObservationSchema = z.object({
  status: z.literal("failure"),
  failureCode: nonEmptyString,
  elapsedMs: finiteNonNegative,
  costUsd: finiteNonNegative,
}).strict();

const observationSchema = z.discriminatedUnion("status", [
  successfulObservationSchema,
  failedObservationSchema,
]) as unknown as z.ZodType<Observation>;

export const measurementSetSchema: z.ZodType<MeasurementSet> = z.object({
  version: z.literal("tasc-measurements-v1"),
  dataset: z.object({
    id: nonEmptyString,
    version: nonEmptyString,
    source: nonEmptyString,
    split: z.enum(["dev", "holdout"]),
    synthetic: z.boolean(),
  }).strict(),
  evaluator: z.object({
    id: nonEmptyString,
    version: nonEmptyString,
    kind: z.enum(["human", "deterministic", "llm-judge"]),
    validated: z.boolean(),
  }).strict(),
  cases: z.array(z.object({
    id: nonEmptyString,
    groupId: nonEmptyString,
    inputTokens: nonNegativeInteger,
    outputTokens: nonNegativeInteger,
    repeatedPrefixTokens: nonNegativeInteger,
    concurrency: z.number().int().finite().positive(),
    mode: nonEmptyString,
    critical: z.boolean(),
    trafficWeight: z.number().finite().positive(),
    slices: z.array(nonEmptyString),
    observations: z.array(z.object({
      profileId: nonEmptyString,
      replicates: z.array(observationSchema).min(1),
    }).strict()).min(1),
  }).strict()).min(1),
}).strict();

/** Check profile IDs and the champion/primary references after structural parsing. */
export function assertInferenceSpecSemantics(spec: InferenceSpec): void {
  const profileIds = new Set<string>();
  for (const profile of spec.profiles) {
    if (profileIds.has(profile.id)) throw new Error(`duplicate profile id "${profile.id}"`);
    profileIds.add(profile.id);
  }
  if (!profileIds.has(spec.championProfileId)) {
    throw new Error(`champion profile "${spec.championProfileId}" is not declared`);
  }
  if (!profileIds.has(spec.primaryProfileId)) {
    throw new Error(`primary profile "${spec.primaryProfileId}" is not declared`);
  }
  if (spec.championProfileId === spec.primaryProfileId) {
    throw new Error("champion and primary profiles must be different");
  }
}

/** Check cross-record measurement invariants that cannot be expressed by Zod alone. */
export function assertMeasurementSetSemantics(measurements: MeasurementSet): void {
  if (measurements.evaluator.kind === "llm-judge" && !measurements.evaluator.validated) {
    throw new Error("llm-judge evaluator must be independently validated");
  }

  const caseIds = new Set<string>();
  for (const measurementCase of measurements.cases) {
    if (caseIds.has(measurementCase.id)) throw new Error(`duplicate case id "${measurementCase.id}"`);
    caseIds.add(measurementCase.id);

    const profileIds = new Set<string>();
    for (const observationSet of measurementCase.observations) {
      if (profileIds.has(observationSet.profileId)) {
        throw new Error(`case "${measurementCase.id}" has duplicate profile id "${observationSet.profileId}"`);
      }
      profileIds.add(observationSet.profileId);

      observationSet.replicates.forEach((observation, replicateIndex) => {
        if (observation.status !== "success") return;
        const rowLabel = `case "${measurementCase.id}" profile "${observationSet.profileId}" replicate ${replicateIndex}`;
        if (observation.endToEndLatencyMs < observation.ttftMs) {
          throw new Error(`${rowLabel} end-to-end latency is below TTFT`);
        }
        if (observation.outputTokens <= 1) return;
        if (observation.perceivedTokensPerSecond <= 0) {
          throw new Error(`${rowLabel} requires positive perceived tokens per second for a multi-token success`);
        }

        // Provider counters are often rounded or sampled over slightly different boundaries.
        // Allow 20% of decode time (at least 100 ms), while rejecting physically impossible rows.
        const decodeMs = ((observation.outputTokens - 1) / observation.perceivedTokensPerSecond) * 1_000;
        const toleranceMs = Math.max(100, decodeMs * 0.2);
        if (observation.endToEndLatencyMs + toleranceMs < observation.ttftMs + decodeMs) {
          throw new Error(
            `${rowLabel} end-to-end latency cannot contain ${observation.outputTokens} output tokens at `
            + `${observation.perceivedTokensPerSecond} perceived tokens per second`,
          );
        }
      });
    }
  }
}

export function parseInferenceSpec(input: unknown): InferenceSpec {
  const spec = inferenceSpecSchema.parse(input);
  assertInferenceSpecSemantics(spec);
  return spec;
}

export function parseMeasurementSet(input: unknown, expectedSplit?: Split): MeasurementSet {
  const measurements = measurementSetSchema.parse(input);
  assertMeasurementSetSemantics(measurements);
  if (expectedSplit && measurements.dataset.split !== expectedSplit) {
    throw new Error(`measurement split "${measurements.dataset.split}" does not match expected "${expectedSplit}"`);
  }
  return measurements;
}

/**
 * Ensure each case has a complete, paired empirical matrix for every profile in the spec.
 * This deliberately treats failures as observations: a missing row is never a successful run.
 */
export function assertMeasurementMatrix(spec: InferenceSpec, measurements: MeasurementSet): void {
  const declaredProfiles = new Set(spec.profiles.map((profile) => profile.id));
  for (const measurementCase of measurements.cases) {
    const byProfile = new Map(measurementCase.observations.map((row) => [row.profileId, row]));
    for (const observationSet of measurementCase.observations) {
      if (!declaredProfiles.has(observationSet.profileId)) {
        throw new Error(`case "${measurementCase.id}" has observations for unknown profile "${observationSet.profileId}"`);
      }
    }

    let expectedReplicateCount: number | undefined;
    for (const profile of spec.profiles) {
      const observationSet = byProfile.get(profile.id);
      if (!observationSet) {
        throw new Error(`case "${measurementCase.id}" is missing observations for profile "${profile.id}"`);
      }
      if (expectedReplicateCount === undefined) {
        expectedReplicateCount = observationSet.replicates.length;
      } else if (observationSet.replicates.length !== expectedReplicateCount) {
        throw new Error(
          `case "${measurementCase.id}" profile "${profile.id}" has ${observationSet.replicates.length} replicates; expected ${expectedReplicateCount}`,
        );
      }
    }
  }
}
