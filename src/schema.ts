import { isProxy } from "node:util/types";
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
    /** Added in Task 4; omitted legacy v1 inputs resolve to 3. */
    minimumIndependentGroups?: number;
    /** Added in Task 4; omitted legacy v1 inputs resolve to 0, or 1 when critical slices exist. */
    minimumCriticalSliceGroups?: number;
  };
  bootstrap: {
    seed: number;
    iterations: number;
    /** Added in Task 4; omitted legacy v1 inputs resolve to 0.05. */
    alpha?: number;
  };
}

/** Fully migrated form used internally after a public-boundary normalization. */
export type ResolvedInferenceSpec = Omit<InferenceSpec, "constraints" | "bootstrap"> & {
  constraints: InferenceSpec["constraints"] & {
    minimumIndependentGroups: number;
    minimumCriticalSliceGroups: number;
  };
  bootstrap: InferenceSpec["bootstrap"] & {
    alpha: number;
  };
};

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
const boundedGroupCount = z.number().int().finite().nonnegative().max(100_000);
const boundedSliceArray = z.array(nonEmptyString).max(64);

const profileSchema = z.object({
  id: nonEmptyString,
  model: nonEmptyString,
  runtime: nonEmptyString,
  hardware: nonEmptyString,
}).strict();

const inferenceSpecStructureSchema: z.ZodType<ResolvedInferenceSpec, z.ZodTypeDef, unknown> = z.object({
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
  criticalSlices: boundedSliceArray,
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
    minimumIndependentGroups: boundedGroupCount.positive().default(3),
    minimumCriticalSliceGroups: boundedGroupCount.default(0),
  }).strict(),
  bootstrap: z.object({
    seed: z.number().int().finite().safe(),
    iterations: z.number().int().finite().positive().max(1_000_000),
    alpha: z.number().finite().gt(0).lt(1).default(0.05),
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

const measurementSetStructureSchema: z.ZodType<MeasurementSet> = z.object({
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
    slices: boundedSliceArray,
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
  if (new Set(spec.criticalSlices).size !== spec.criticalSlices.length) {
    throw new Error("duplicate critical slice");
  }
  const minimumCriticalSliceGroups = spec.constraints.minimumCriticalSliceGroups
    ?? (spec.criticalSlices.length === 0 ? 0 : 1);
  if (spec.criticalSlices.length === 0 && minimumCriticalSliceGroups > 0) {
    throw new Error("critical-slice group minimum must be zero when no critical slices are declared");
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
    if (new Set(measurementCase.slices).size !== measurementCase.slices.length) {
      throw new Error(`case "${measurementCase.id}" has a duplicate slice label`);
    }

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

const MAX_SNAPSHOT_DEPTH = 64;
const MAX_SNAPSHOT_NODES = 20_000_000;
const MAX_SNAPSHOT_ARRAY_LENGTH = 100_000;
const MAX_SNAPSHOT_OBJECT_KEYS = 128;

interface SnapshotTraversalState {
  ancestors: WeakSet<object>;
  seen: WeakSet<object>;
  nodes: number;
  arrayLengthLimits: ReadonlyMap<string, number>;
}

/** @internal Descriptor-safe bounded snapshot shared by legacy public contract parsers. */
export function snapshotPlainDataTree(
  input: unknown,
  label: string,
  options: {
    arrayLengthLimits?: ReadonlyMap<string, number>;
  } = {},
): unknown {
  return snapshotPlainDataTreeAt(input, label, {
    ancestors: new WeakSet<object>(),
    seen: new WeakSet<object>(),
    nodes: 0,
    arrayLengthLimits: options.arrayLengthLimits ?? new Map<string, number>(),
  }, 0);
}

function snapshotPlainDataTreeAt(
  input: unknown,
  label: string,
  traversal: SnapshotTraversalState,
  depth: number,
): unknown {
  if (depth > MAX_SNAPSHOT_DEPTH) {
    throw new Error(`${label} snapshot nesting depth exceeds ${MAX_SNAPSHOT_DEPTH}`);
  }
  traversal.nodes += 1;
  if (traversal.nodes > MAX_SNAPSHOT_NODES) {
    throw new Error(`contract snapshot exceeds ${MAX_SNAPSHOT_NODES} values`);
  }
  if (typeof input !== "object" || input === null) return input;
  if (isProxy(input)) throw new Error(`${label} proxy values are not allowed`);
  if (traversal.ancestors.has(input)) throw new Error(`${label} contains a cyclic reference`);
  if (traversal.seen.has(input)) throw new Error(`${label} contains a repeated shared object reference`);
  traversal.seen.add(input);
  traversal.ancestors.add(input);
  try {
    if (Array.isArray(input)) {
      const lengthDescriptor = Object.getOwnPropertyDescriptor(input, "length");
      const length = lengthDescriptor?.value;
      if (!Number.isSafeInteger(length) || length < 0) {
        throw new Error(`${label} length must be a safe non-negative integer data property`);
      }
      const contextualLengthLimit = traversal.arrayLengthLimits.get(label);
      if (contextualLengthLimit !== undefined && length > contextualLengthLimit) {
        throw new Error(`${label} length ${length} exceeds configured maximum ${contextualLengthLimit}`);
      }
      if (length > MAX_SNAPSHOT_ARRAY_LENGTH) {
        throw new Error(`${label} must contain at most ${MAX_SNAPSHOT_ARRAY_LENGTH} entries`);
      }
      if ((label.endsWith(".criticalSlices") || label.endsWith(".slices")) && length > 64) {
        throw new Error(`${label} must contain at most 64 slice labels`);
      }
      const allowedKeys = new Set<string>(["length"]);
      const snapshot: unknown[] = [];
      for (let index = 0; index < length; index += 1) {
        const key = String(index);
        allowedKeys.add(key);
        const descriptor = Object.getOwnPropertyDescriptor(input, key);
        if (descriptor === undefined) throw new Error(`${label} has a hole at index ${index}`);
        if (
          !descriptor.enumerable
          || !Object.prototype.hasOwnProperty.call(descriptor, "value")
        ) {
          throw new Error(
            `${label}[${index}] must be an enumerable own data property; accessors are not allowed`,
          );
        }
        snapshot.push(snapshotPlainDataTreeAt(
          descriptor.value,
          `${label}[${index}]`,
          traversal,
          depth + 1,
        ));
      }
      for (const key of Reflect.ownKeys(input)) {
        if (typeof key !== "string" || !allowedKeys.has(key)) {
          throw new Error(`${label} must contain only indexed own data properties`);
        }
      }
      return snapshot;
    }

    const prototype = Object.getPrototypeOf(input);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new Error(`${label} must be a plain object; inherited properties are not allowed`);
    }
    const keys = Reflect.ownKeys(input);
    if (keys.length > MAX_SNAPSHOT_OBJECT_KEYS) {
      throw new Error(`${label} must contain at most ${MAX_SNAPSHOT_OBJECT_KEYS} own properties`);
    }
    const snapshot: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
    for (const key of keys) {
      if (typeof key !== "string") {
        throw new Error(`${label} must contain only string-keyed own data properties`);
      }
      const descriptor = Object.getOwnPropertyDescriptor(input, key);
      if (
        descriptor === undefined
        || !descriptor.enumerable
        || !Object.prototype.hasOwnProperty.call(descriptor, "value")
      ) {
        throw new Error(`${label}.${key} must be an enumerable own data property; accessors are not allowed`);
      }
      snapshot[key] = snapshotPlainDataTreeAt(
        descriptor.value,
        `${label}.${key}`,
        traversal,
        depth + 1,
      );
    }
    return snapshot;
  } finally {
    traversal.ancestors.delete(input);
  }
}

export interface PreparedInferenceSpec {
  bootstrapIterations: number;
  confidenceThresholdCount: number;
  inputTokenThresholdCount: number;
  includeFastOnly: boolean;
}

interface InferenceSpecInputSnapshot extends PreparedInferenceSpec {
  value: Record<string, unknown>;
  minimumCriticalSliceGroupsWasOmitted: boolean;
}

function snapshotInferenceSpecInput(input: unknown): InferenceSpecInputSnapshot {
  const rootValue = snapshotPlainDataTree(input, "inference spec");
  if (typeof rootValue !== "object" || rootValue === null || Array.isArray(rootValue)) {
    throw new Error("inference spec must be a plain object with enumerable own data properties");
  }
  const root = rootValue as Record<string, unknown>;
  const candidateSpace = root.candidateSpace;
  const constraints = root.constraints;
  const bootstrap = root.bootstrap;
  if (typeof candidateSpace !== "object" || candidateSpace === null || Array.isArray(candidateSpace)) {
    throw new Error("inference spec candidate space must be a plain object");
  }
  if (typeof constraints !== "object" || constraints === null || Array.isArray(constraints)) {
    throw new Error("inference spec constraints must be a plain object");
  }
  if (typeof bootstrap !== "object" || bootstrap === null || Array.isArray(bootstrap)) {
    throw new Error("inference spec bootstrap must be a plain object");
  }
  const candidateSpaceRecord = candidateSpace as Record<string, unknown>;
  const constraintsRecord = constraints as Record<string, unknown>;
  const bootstrapRecord = bootstrap as Record<string, unknown>;
  if (!Number.isSafeInteger(bootstrapRecord.iterations) || (bootstrapRecord.iterations as number) <= 0) {
    throw new Error("inference spec bootstrap iterations must be a positive safe integer");
  }
  if (typeof candidateSpaceRecord.includeFastOnly !== "boolean") {
    throw new Error("inference spec candidate includeFastOnly must be boolean");
  }
  if (
    !Array.isArray(candidateSpaceRecord.confidenceThresholds)
    || !Array.isArray(candidateSpaceRecord.inputTokenThresholds)
  ) {
    throw new Error("inference spec candidate thresholds must be arrays");
  }
  if (!Array.isArray(root.criticalSlices)) throw new Error("critical slices must be an array");
  const normalizedCriticalSlices = new Set<string>();
  for (const slice of root.criticalSlices) {
    if (typeof slice !== "string" || slice.trim().length === 0) {
      throw new Error("critical slices must contain non-empty string labels");
    }
    const normalized = slice.trim();
    if (normalizedCriticalSlices.has(normalized)) throw new Error("critical slices has a duplicate slice label");
    normalizedCriticalSlices.add(normalized);
  }
  const minimumCriticalSliceGroupsWasOmitted = (
    !Object.prototype.hasOwnProperty.call(constraintsRecord, "minimumCriticalSliceGroups")
    || constraintsRecord.minimumCriticalSliceGroups === undefined
  );
  return {
    value: root,
    minimumCriticalSliceGroupsWasOmitted,
    bootstrapIterations: bootstrapRecord.iterations as number,
    confidenceThresholdCount: new Set(candidateSpaceRecord.confidenceThresholds).size,
    inputTokenThresholdCount: new Set(candidateSpaceRecord.inputTokenThresholds).size,
    includeFastOnly: candidateSpaceRecord.includeFastOnly as boolean,
  };
}

const preparedInferenceSpecs = new WeakMap<PreparedInferenceSpec, InferenceSpecInputSnapshot>();

/** Create one immutable-by-ownership snapshot for both work budgeting and parsing. */
export function prepareInferenceSpec(input: unknown): PreparedInferenceSpec {
  const snapshot = snapshotInferenceSpecInput(input);
  const prepared = Object.freeze({
    bootstrapIterations: snapshot.bootstrapIterations,
    confidenceThresholdCount: snapshot.confidenceThresholdCount,
    inputTokenThresholdCount: snapshot.inputTokenThresholdCount,
    includeFastOnly: snapshot.includeFastOnly,
  });
  preparedInferenceSpecs.set(prepared, snapshot);
  return prepared;
}

/**
 * Parse and migrate both untrusted JSON and legacy typed v1 objects. Call this once at
 * every public spec boundary; the returned object has all Task 4 controls explicit.
 */
export function parseInferenceSpec(input: unknown): ResolvedInferenceSpec {
  return parsePreparedInferenceSpec(prepareInferenceSpec(input));
}

export function parsePreparedInferenceSpec(prepared: PreparedInferenceSpec): ResolvedInferenceSpec {
  const snapshot = preparedInferenceSpecs.get(prepared);
  if (snapshot === undefined) throw new Error("inference spec preparation handle is invalid");
  const spec = inferenceSpecStructureSchema.parse(snapshot.value);
  const { minimumCriticalSliceGroupsWasOmitted } = snapshot;
  if (minimumCriticalSliceGroupsWasOmitted && spec.criticalSlices.length > 0) {
    spec.constraints.minimumCriticalSliceGroups = 1;
  }
  assertInferenceSpecSemantics(spec);
  return spec;
}

export const inferenceSpecSchema: z.ZodType<ResolvedInferenceSpec, z.ZodTypeDef, unknown> = z
  .unknown()
  .transform((input, context) => {
    try {
      return parseInferenceSpec(input);
    } catch (error) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        message: error instanceof Error ? error.message : "invalid inference spec",
      });
      return z.NEVER;
    }
  }) as z.ZodType<ResolvedInferenceSpec, z.ZodTypeDef, unknown>;

export function parseMeasurementSet(input: unknown, expectedSplit?: Split): MeasurementSet {
  const measurements = measurementSetStructureSchema.parse(snapshotPlainDataTree(input, "measurement set"));
  assertMeasurementSetSemantics(measurements);
  if (expectedSplit && measurements.dataset.split !== expectedSplit) {
    throw new Error(`measurement split "${measurements.dataset.split}" does not match expected "${expectedSplit}"`);
  }
  return measurements;
}

export const measurementSetSchema: z.ZodType<MeasurementSet, z.ZodTypeDef, unknown> = z
  .unknown()
  .transform((input, context) => {
    try {
      return parseMeasurementSet(input);
    } catch (error) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        message: error instanceof Error ? error.message : "invalid measurement set",
      });
      return z.NEVER;
    }
  }) as z.ZodType<MeasurementSet, z.ZodTypeDef, unknown>;

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
