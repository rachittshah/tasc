import { createHmac, timingSafeEqual } from "node:crypto";
import { isProxy } from "node:util/types";
import { z } from "zod";
import {
  bootstrapGroupedWeightedMeanCI,
  median,
  type BootstrapCI,
  type GroupedCaseEffect,
} from "./statistics.js";
import { canonicalJson, compareCodeUnits } from "./determinism.js";
import { sha256 } from "./integrity.js";
import {
  assertMeasurementMatrix,
  assertSuccessfulTimingSemantics,
  parseMeasurementSet,
  parsePreparedInferenceSpec,
  prepareInferenceSpec,
  snapshotPlainDataTree,
  type InferenceSpec,
  type MeasurementSet,
  type PreparedInferenceSpec,
  type ResolvedInferenceSpec,
} from "./schema.js";
import type { WorkBudget } from "./work-budget.js";
import {
  assertWithinLegacyAssessmentBudget,
  estimateLegacyAssessmentWork,
  type LegacyAssessmentWorkInput,
} from "./legacy-work-budget.js";
import {
  championPolicyForResolvedSpec,
  fingerprintPolicy,
  generateCandidatePoliciesForResolvedSpec,
  replayPolicyForResolvedSpec,
  type InferencePolicy,
  type ReplayedRow,
} from "./policy.js";

export interface PolicyMetrics {
  meanTaskScore: number;
  successRate: number;
  errorRate: number;
  p50TtftMs: number;
  p95TtftMs: number;
  p50EndToEndLatencyMs: number;
  p95EndToEndLatencyMs: number;
  p99EndToEndLatencyMs: number;
  p10PerceivedTokensPerSecond: number;
  p50TotalTokensPerSecond: number | null;
  costPerRequestUsd: number;
  costPerThousandRequestsUsd: number;
  escalationRate: number;
  criticalSliceTaskScore: Record<string, number | null>;
}

export interface GateResult {
  id: string;
  pass: boolean;
  actual: number | null;
  threshold: number;
  comparison: ">=" | "<=";
  reason: string;
}

export interface PairedQualityResult {
  method: "paired-group-percentile-v1";
  alpha: number;
  caseCount: number;
  replicateCount: number;
  groupCount: number;
  effectiveTrafficMass: number;
  deltas: number[];
  replicateDeltas: Array<{
    caseId: string;
    replicateId: string;
    delta: number;
  }>;
  caseEffects: GroupedCaseEffect[];
  criticalSliceGroupCoverage: Record<string, number>;
  estimate: number;
  interval: {
    lo: number | null;
    hi: number | null;
  };
  iterations: number;
  seed: number;
  inferenceAvailable: boolean;
  unavailableReason?: string;
  /** Compatibility projection for existing v1 artifact readers. */
  bootstrap: Omit<BootstrapCI, "lo" | "hi"> & {
    lo: number | null;
    hi: number | null;
  };
}

export interface PolicyEvaluation {
  candidateMetrics: PolicyMetrics;
  championMetrics: PolicyMetrics;
  pairedQuality: PairedQualityResult;
  costImprovement: number | null;
  gates: GateResult[];
  passed: boolean;
}

export interface CandidateEvaluation {
  policy: InferencePolicy;
  evaluation: PolicyEvaluation;
}

export interface EvaluationOptions {
  /** Optional tighter caller limit; omitted callers receive a bounded safe default. */
  workBudget?: WorkBudget;
}

export interface AttestationOptions extends EvaluationOptions {
  attestationKey?: string;
}

const workBudgetLimitSchema = z.number().int().finite().safe().nonnegative();
const workBudgetSchema: z.ZodType<WorkBudget> = z.object({
  maxCandidates: workBudgetLimitSchema,
  maxTraceRows: workBudgetLimitSchema,
  maxEvidenceRows: workBudgetLimitSchema,
  maxBootstrapDraws: workBudgetLimitSchema,
  maxIndependentGroups: workBudgetLimitSchema,
  maxAssessmentWork: workBudgetLimitSchema,
}).strict();

const evaluationOptionsSchema: z.ZodType<EvaluationOptions> = z.object({
  workBudget: workBudgetSchema.optional(),
}).strict();

const attestationOptionsSchema: z.ZodType<AttestationOptions> = z.object({
  workBudget: workBudgetSchema.optional(),
  attestationKey: z.string().optional(),
}).strict();

function parseEvaluationOptions(input: unknown): EvaluationOptions {
  return evaluationOptionsSchema.parse(snapshotPlainDataTree(input, "evaluation options"));
}

function parseAttestationOptions(
  input: unknown,
  label: "nomination options" | "confirmation options",
): AttestationOptions {
  return attestationOptionsSchema.parse(snapshotPlainDataTree(input, label));
}

/** Bounded defaults preserve the synthetic CLI/demo call shape without allowing unbounded work. */
export const DEFAULT_ASSESSMENT_WORK_BUDGET: Readonly<WorkBudget> = Object.freeze({
  maxCandidates: 10_000,
  maxTraceRows: 100_000,
  maxEvidenceRows: 100_000,
  maxBootstrapDraws: 100_000,
  maxIndependentGroups: 100_000,
  maxAssessmentWork: 100_000_000,
});

export interface NominationAttestation {
  algorithm: "hmac-sha256";
  digest: string;
}

export interface NominationArtifact {
  version: "tasc-nomination-v1";
  specDigest: string;
  developmentDatasetDigest: string;
  evaluator: MeasurementSet["evaluator"];
  developmentGroupIds: string[];
  developmentSynthetic: boolean;
  policy: InferencePolicy;
  policyDigest: string;
  candidateMetrics: PolicyMetrics;
  championMetrics: PolicyMetrics;
  gates: GateResult[];
  decisionDigest: string;
  selfDigest: string;
  attestation?: NominationAttestation;
}

const nominationDigestSchema = z.string().regex(/^[a-f0-9]{64}$/);
const nominationTextSchema = z.string()
  .min(1)
  .refine((value) => value === value.trim(), "must not contain surrounding whitespace");
const nominationFiniteNumberSchema = z.number().finite();
const nominationNonNegativeNumberSchema = nominationFiniteNumberSchema.nonnegative();
const nominationCriticalSliceScoresSchema: z.ZodType<Record<string, number | null>> = z.custom(
  (input): input is Record<string, number | null> => (
    typeof input === "object"
    && input !== null
    && !Array.isArray(input)
    && Object.keys(input).every((key) => {
      const value = (input as Record<string, unknown>)[key];
      return (
        key.length > 0
        && key === key.trim()
        && (value === null || (typeof value === "number" && Number.isFinite(value)))
      );
    })
  ),
  "critical-slice scores must be a finite data record",
);

const nominationEvaluatorSchema: z.ZodType<MeasurementSet["evaluator"]> = z.object({
  id: nominationTextSchema,
  version: nominationTextSchema,
  kind: z.enum(["human", "deterministic", "llm-judge"]),
  validated: z.boolean(),
}).strict();

const nominationPolicySchema: z.ZodType<InferencePolicy> = z.object({
  version: z.literal("tasc-policy-v1"),
  id: nominationTextSchema,
  kind: z.enum(["expert-only", "fast-only", "cascade"]),
  primaryProfileId: nominationTextSchema,
  expertProfileId: nominationTextSchema,
  confidenceThreshold: nominationFiniteNumberSchema.min(0).max(1).optional(),
  inputTokenThreshold: z.number().finite().int().nonnegative().optional(),
  criticalSlices: z.array(nominationTextSchema).max(64),
}).strict();

const nominationPolicyMetricsSchema: z.ZodType<PolicyMetrics> = z.object({
  meanTaskScore: nominationFiniteNumberSchema,
  successRate: nominationFiniteNumberSchema,
  errorRate: nominationFiniteNumberSchema,
  p50TtftMs: nominationNonNegativeNumberSchema,
  p95TtftMs: nominationNonNegativeNumberSchema,
  p50EndToEndLatencyMs: nominationNonNegativeNumberSchema,
  p95EndToEndLatencyMs: nominationNonNegativeNumberSchema,
  p99EndToEndLatencyMs: nominationNonNegativeNumberSchema,
  p10PerceivedTokensPerSecond: nominationNonNegativeNumberSchema,
  p50TotalTokensPerSecond: nominationNonNegativeNumberSchema.nullable(),
  costPerRequestUsd: nominationNonNegativeNumberSchema,
  costPerThousandRequestsUsd: nominationNonNegativeNumberSchema,
  escalationRate: nominationFiniteNumberSchema,
  criticalSliceTaskScore: nominationCriticalSliceScoresSchema,
}).strict();

const nominationGateSchema: z.ZodType<GateResult> = z.object({
  id: nominationTextSchema,
  pass: z.boolean(),
  actual: nominationFiniteNumberSchema.nullable(),
  threshold: nominationFiniteNumberSchema,
  comparison: z.enum([">=", "<="]),
  reason: nominationTextSchema,
}).strict();

const nominationAttestationSchema: z.ZodType<NominationAttestation> = z.object({
  algorithm: z.literal("hmac-sha256"),
  digest: nominationDigestSchema,
}).strict();

const nominationArtifactSchema: z.ZodType<NominationArtifact> = z.object({
  version: z.literal("tasc-nomination-v1"),
  specDigest: nominationDigestSchema,
  developmentDatasetDigest: nominationDigestSchema,
  evaluator: nominationEvaluatorSchema,
  developmentGroupIds: z.array(nominationTextSchema).max(100_000),
  developmentSynthetic: z.boolean(),
  policy: nominationPolicySchema,
  policyDigest: nominationDigestSchema,
  candidateMetrics: nominationPolicyMetricsSchema,
  championMetrics: nominationPolicyMetricsSchema,
  gates: z.array(nominationGateSchema).max(256),
  decisionDigest: nominationDigestSchema,
  selfDigest: nominationDigestSchema,
  attestation: nominationAttestationSchema.optional(),
}).strict();

export interface NominationResult {
  status: "NOMINATED" | "NO_CANDIDATE";
  evaluations: CandidateEvaluation[];
  frontier: string[];
  nomination?: NominationArtifact;
}

export type ConfirmationStatus =
  | "DEMO_ONLY"
  | "HOLD"
  /** @deprecated Historical artifact compatibility only; this release never emits it. */
  | "READY_FOR_MANUAL_PRODUCTION";

export interface ConfirmationResult {
  version: "tasc-confirmation-v1";
  status: ConfirmationStatus;
  specDigest: string;
  holdoutDatasetDigest: string;
  nominationDigest: string;
  evaluator: MeasurementSet["evaluator"];
  holdoutGroupIds: string[];
  policy: InferencePolicy;
  policyDigest: string;
  evaluation: PolicyEvaluation;
  attestationVerified: boolean;
  statusReason: string;
  decisionDigest: string;
}

interface WeightedValue {
  value: number;
  weight: number;
}

function checkedAdd(left: number, right: number, name: string): number {
  if (!Number.isSafeInteger(left) || !Number.isSafeInteger(right) || left > Number.MAX_SAFE_INTEGER - right) {
    throw new Error(`${name} exceeds safe integer range`);
  }
  return left + right;
}

function candidatePolicyCount(preflight: PreparedInferenceSpec): number {
  if (
    preflight.confidenceThresholdCount > 0
    && preflight.inputTokenThresholdCount > Number.MAX_SAFE_INTEGER / preflight.confidenceThresholdCount
  ) {
    throw new Error("candidate count exceeds safe integer range");
  }
  return checkedAdd(
    preflight.confidenceThresholdCount * preflight.inputTokenThresholdCount,
    preflight.includeFastOnly ? 1 : 0,
    "candidate count",
  );
}

interface PreparedMeasurementAssessment {
  measurements: MeasurementSet;
  workInput: LegacyAssessmentWorkInput;
}

function assertPlainDescriptorObject(input: unknown, label: string): asserts input is object {
  if (typeof input !== "object" || input === null || Array.isArray(input) || isProxy(input)) {
    throw new Error(`${label} must be a plain non-proxy object`);
  }
  const prototype = Object.getPrototypeOf(input);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new Error(`${label} must be a plain object with own data properties`);
  }
}

function descriptorDataProperty(input: object, key: string, label: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(input, key);
  if (
    descriptor === undefined
    || !descriptor.enumerable
    || !Object.prototype.hasOwnProperty.call(descriptor, "value")
  ) {
    throw new Error(`${label}.${key} must be an enumerable own data property; accessors are not allowed`);
  }
  return descriptor.value;
}

function descriptorArrayLength(input: unknown, label: string): number {
  if (!Array.isArray(input) || isProxy(input)) {
    throw new Error(`${label} must be a non-proxy array`);
  }
  const length = Object.getOwnPropertyDescriptor(input, "length")?.value;
  if (!Number.isSafeInteger(length) || length < 0) {
    throw new Error(`${label} length must be a safe non-negative integer data property`);
  }
  return length;
}

function descriptorArrayEntry(input: unknown[], index: number, label: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(input, String(index));
  if (descriptor === undefined) {
    throw new Error(`${label} has a hole at index ${index}`);
  }
  if (
    !descriptor.enumerable
    || !Object.prototype.hasOwnProperty.call(descriptor, "value")
  ) {
    throw new Error(
      `${label}[${index}] must be an enumerable own data property; accessors are not allowed`,
    );
  }
  return descriptor.value;
}

function assertMeasurementRowBudget(rowCount: number, budget: WorkBudget): void {
  if (rowCount > budget.maxTraceRows) {
    throw new Error(
      `trace rows exceeds caller work budget: ${rowCount} > ${budget.maxTraceRows}`,
    );
  }
  if (rowCount > budget.maxEvidenceRows) {
    throw new Error(
      `evidence rows exceeds caller work budget: ${rowCount} > ${budget.maxEvidenceRows}`,
    );
  }
}

function preflightMeasurementShape(
  input: MeasurementSet,
  candidateCount: number,
  bootstrapDraws: number,
  budget: WorkBudget,
): Omit<LegacyAssessmentWorkInput, "candidateCount" | "bootstrapDraws"> {
  assertPlainDescriptorObject(input, "measurement set");
  const casesInput = descriptorDataProperty(input, "cases", "measurement set");
  const caseCount = descriptorArrayLength(casesInput, "measurement set.cases");
  const cases = casesInput as unknown[];

  // Every structurally valid case contributes at least one observation row.
  assertWithinLegacyAssessmentBudget(estimateLegacyAssessmentWork({
    candidateCount,
    traceRows: caseCount,
    evidenceRows: caseCount,
    bootstrapDraws,
    independentGroups: 0,
  }), budget);

  let rowCount = 0;
  const groups = new Set<string>();
  for (let caseIndex = 0; caseIndex < caseCount; caseIndex += 1) {
    const caseLabel = `measurement set.cases[${caseIndex}]`;
    const measurementCase = descriptorArrayEntry(cases, caseIndex, "measurement set.cases");
    assertPlainDescriptorObject(measurementCase, caseLabel);

    const groupId = descriptorDataProperty(measurementCase, "groupId", caseLabel);
    if (typeof groupId !== "string" || groupId.trim().length === 0) {
      throw new Error(`${caseLabel}.groupId must be a non-empty string`);
    }
    groups.add(groupId.trim());
    if (groups.size > budget.maxIndependentGroups) {
      throw new Error(
        `independent group count exceeds caller work budget: ${groups.size} > ${budget.maxIndependentGroups}`,
      );
    }

    const observationsInput = descriptorDataProperty(measurementCase, "observations", caseLabel);
    const observationCount = descriptorArrayLength(
      observationsInput,
      `${caseLabel}.observations`,
    );
    assertMeasurementRowBudget(
      checkedAdd(rowCount, observationCount, "measurement row count lower bound"),
      budget,
    );
    const observations = observationsInput as unknown[];
    for (let observationIndex = 0; observationIndex < observationCount; observationIndex += 1) {
      const observationLabel = `${caseLabel}.observations[${observationIndex}]`;
      const observationSet = descriptorArrayEntry(
        observations,
        observationIndex,
        `${caseLabel}.observations`,
      );
      assertPlainDescriptorObject(observationSet, observationLabel);
      const replicates = descriptorDataProperty(observationSet, "replicates", observationLabel);
      const replicateCount = descriptorArrayLength(
        replicates,
        `${observationLabel}.replicates`,
      );
      rowCount = checkedAdd(rowCount, replicateCount, "measurement row count");
      assertMeasurementRowBudget(rowCount, budget);
    }
  }
  return {
    traceRows: rowCount,
    evidenceRows: rowCount,
    independentGroups: groups.size,
  };
}

/** Charge descriptor-derived cardinalities before the full owned measurement snapshot. */
function prepareMeasurementAssessment(
  spec: PreparedInferenceSpec,
  measurementInput: MeasurementSet,
  budget: WorkBudget,
): PreparedMeasurementAssessment {
  const candidateCount = candidatePolicyCount(spec);
  const emptyInput: LegacyAssessmentWorkInput = {
    candidateCount,
    traceRows: 0,
    evidenceRows: 0,
    bootstrapDraws: spec.bootstrapIterations,
    independentGroups: 0,
  };
  assertWithinLegacyAssessmentBudget(estimateLegacyAssessmentWork(emptyInput), budget);
  const shape = preflightMeasurementShape(
    measurementInput,
    candidateCount,
    spec.bootstrapIterations,
    budget,
  );
  const workInput = { ...emptyInput, ...shape };
  assertWithinLegacyAssessmentBudget(estimateLegacyAssessmentWork(workInput), budget);
  return {
    measurements: parseMeasurementSet(measurementInput),
    workInput,
  };
}

interface RowCollectionPreflight {
  label: "candidate" | "champion";
  input: readonly ReplayedRow[];
  length: number;
}

function preflightRowCollection(
  input: readonly ReplayedRow[],
  label: RowCollectionPreflight["label"],
): RowCollectionPreflight {
  if (isProxy(input)) throw new Error(`${label} row collection proxy values are not allowed`);
  if (!Array.isArray(input)) throw new Error(`${label} row collection must be an array`);
  const lengthDescriptor = Object.getOwnPropertyDescriptor(input, "length");
  const length = lengthDescriptor?.value;
  if (!Number.isSafeInteger(length) || length < 0) {
    throw new Error(`${label} row collection length must be a safe non-negative integer data property`);
  }
  return { label, input, length };
}

const REQUIRED_REPLAYED_ROW_KEYS = new Set<keyof ReplayedRow>([
  "policyId",
  "caseId",
  "groupId",
  "replicateIndex",
  "status",
  "selectedProfileId",
  "attemptedProfileIds",
  "escalated",
  "taskScore",
  "ttftMs",
  "endToEndLatencyMs",
  "outputTokens",
  "perceivedTokensPerSecond",
  "costUsd",
  "trafficWeight",
  "slices",
  "critical",
]);

const OPTIONAL_REPLAYED_ROW_KEYS = new Set<keyof ReplayedRow>([
  "policyKind",
  "confidence",
  "serviceThroughput",
  "totalTokensPerSecond",
  "cacheHit",
  "failureCode",
]);

function snapshotRowStringArray(
  input: unknown,
  label: string,
  maximumLength: number,
): string[] {
  if (!Array.isArray(input) || isProxy(input)) throw new Error(`${label} must be a non-proxy array`);
  const length = Object.getOwnPropertyDescriptor(input, "length")?.value;
  if (!Number.isSafeInteger(length) || length < 0) {
    throw new Error(`${label} length must be a safe non-negative integer data property`);
  }
  if (length > maximumLength) throw new Error(`${label} exceeds ${maximumLength} entries`);
  const allowedKeys = new Set<string>(["length"]);
  const snapshot: string[] = [];
  for (let index = 0; index < length; index += 1) {
    const key = String(index);
    allowedKeys.add(key);
    const descriptor = Object.getOwnPropertyDescriptor(input, key);
    if (descriptor === undefined) throw new Error(`${label} has a hole at index ${index}`);
    if (
      !descriptor.enumerable
      || !Object.prototype.hasOwnProperty.call(descriptor, "value")
    ) {
      throw new Error(`${label}[${index}] must be an enumerable own data property; accessors are not allowed`);
    }
    if (typeof descriptor.value !== "string" || descriptor.value.length === 0) {
      throw new Error(`${label}[${index}] must be a non-empty string`);
    }
    if (descriptor.value !== descriptor.value.trim()) {
      throw new Error(`${label}[${index}] must be trimmed without surrounding whitespace`);
    }
    snapshot.push(descriptor.value);
  }
  for (const key of Reflect.ownKeys(input)) {
    if (typeof key !== "string" || !allowedKeys.has(key)) {
      throw new Error(`${label} must contain only indexed own data properties`);
    }
  }
  return snapshot;
}

function snapshotServiceThroughput(
  input: ReplayedRow["serviceThroughput"],
  label: string,
): ReplayedRow["serviceThroughput"] {
  if (typeof input !== "object" || input === null || Array.isArray(input) || isProxy(input)) {
    throw new Error(`${label} must be a plain non-proxy object`);
  }
  const prototype = Object.getPrototypeOf(input);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new Error(`${label} must be a plain object with own data properties`);
  }
  const allowedKeys = new Set(["kind", "tokensPerSecond", "reason"]);
  const snapshot: Record<string, unknown> = {};
  for (const key of Reflect.ownKeys(input)) {
    if (typeof key !== "string" || !allowedKeys.has(key)) {
      throw new Error(`${label} has an unexpected property`);
    }
    const descriptor = Object.getOwnPropertyDescriptor(input, key);
    if (
      descriptor === undefined
      || !descriptor.enumerable
      || !Object.prototype.hasOwnProperty.call(descriptor, "value")
    ) {
      throw new Error(`${label}.${key} must be an enumerable own data property; accessors are not allowed`);
    }
    snapshot[key] = descriptor.value;
  }
  if (
    snapshot.kind === "measured"
    && typeof snapshot.tokensPerSecond === "number"
    && Number.isFinite(snapshot.tokensPerSecond)
    && snapshot.tokensPerSecond >= 0
  ) {
    return { kind: "measured", tokensPerSecond: snapshot.tokensPerSecond };
  }
  if (
    snapshot.kind === "unavailable"
    && typeof snapshot.reason === "string"
    && snapshot.reason.length > 0
  ) {
    return { kind: "unavailable", reason: snapshot.reason };
  }
  throw new Error(`${label} is not a valid measured or unavailable capacity observation`);
}

function assertNonEmptyRowString(
  snapshot: Record<string, unknown>,
  key: keyof ReplayedRow,
  label: string,
): void {
  const value = snapshot[key];
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`${label}.${key} must be a non-empty string`);
  }
}

function assertCanonicalRowString(
  snapshot: Record<string, unknown>,
  key: "policyId" | "caseId" | "groupId" | "selectedProfileId" | "failureCode",
  label: string,
): void {
  assertNonEmptyRowString(snapshot, key, label);
  const value = snapshot[key] as string;
  if (value !== value.trim()) {
    throw new Error(`${label}.${key} must be a canonical trimmed string without surrounding whitespace`);
  }
}

function assertFiniteRowNumber(
  snapshot: Record<string, unknown>,
  key: keyof ReplayedRow,
  label: string,
  minimum: number,
  maximum = Number.POSITIVE_INFINITY,
): void {
  const value = snapshot[key];
  if (
    typeof value !== "number"
    || !Number.isFinite(value)
    || value < minimum
    || value > maximum
  ) {
    const range = Number.isFinite(maximum) ? ` in [${minimum}, ${maximum}]` : ` >= ${minimum}`;
    throw new Error(`${label}.${key} must be a finite number${range}`);
  }
}

function assertReplayedRowScalars(snapshot: Record<string, unknown>, label: string): void {
  for (const key of ["policyId", "caseId", "groupId", "selectedProfileId"] as const) {
    assertCanonicalRowString(snapshot, key, label);
  }
  if (snapshot.status !== "success" && snapshot.status !== "failure") {
    throw new Error(`${label}.status must be "success" or "failure"`);
  }
  if (
    snapshot.policyKind !== undefined
    && snapshot.policyKind !== "expert-only"
    && snapshot.policyKind !== "fast-only"
    && snapshot.policyKind !== "cascade"
  ) {
    throw new Error(`${label}.policyKind is invalid`);
  }
  for (const key of ["escalated", "critical"] as const) {
    if (typeof snapshot[key] !== "boolean") throw new Error(`${label}.${key} must be boolean`);
  }
  if (snapshot.cacheHit !== undefined && typeof snapshot.cacheHit !== "boolean") {
    throw new Error(`${label}.cacheHit must be boolean when provided`);
  }
  if (
    typeof snapshot.replicateIndex !== "number"
    || !Number.isSafeInteger(snapshot.replicateIndex)
    || snapshot.replicateIndex < 0
  ) {
    throw new Error(`${label}.replicateIndex must be a safe non-negative integer`);
  }
  if (
    typeof snapshot.outputTokens !== "number"
    || !Number.isSafeInteger(snapshot.outputTokens)
    || snapshot.outputTokens < 0
  ) {
    throw new Error(`${label}.outputTokens must be a safe non-negative integer`);
  }
  assertFiniteRowNumber(snapshot, "taskScore", label, 0, 1);
  if (snapshot.confidence !== undefined) {
    assertFiniteRowNumber(snapshot, "confidence", label, 0, 1);
  }
  for (const key of [
    "ttftMs",
    "endToEndLatencyMs",
    "perceivedTokensPerSecond",
    "costUsd",
  ] as const) {
    assertFiniteRowNumber(snapshot, key, label, 0);
  }
  if (
    typeof snapshot.trafficWeight !== "number"
    || !Number.isFinite(snapshot.trafficWeight)
    || snapshot.trafficWeight <= 0
  ) {
    throw new Error(`${label}.trafficWeight must be finite and positive`);
  }
  if (snapshot.totalTokensPerSecond !== undefined) {
    assertFiniteRowNumber(snapshot, "totalTokensPerSecond", label, 0);
  }
  if (snapshot.failureCode !== undefined) {
    assertCanonicalRowString(snapshot, "failureCode", label);
  }
}

function snapshotReplayedRow(input: ReplayedRow, label: string): ReplayedRow {
  if (typeof input !== "object" || input === null || Array.isArray(input) || isProxy(input)) {
    throw new Error(`${label} must be a plain non-proxy row object`);
  }
  const prototype = Object.getPrototypeOf(input);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new Error(`${label} must be a plain row object with own data properties`);
  }
  const snapshot: Record<string, unknown> = {};
  const observedKeys = new Set<string>();
  for (const key of Reflect.ownKeys(input)) {
    if (
      typeof key !== "string"
      || (
        !REQUIRED_REPLAYED_ROW_KEYS.has(key as keyof ReplayedRow)
        && !OPTIONAL_REPLAYED_ROW_KEYS.has(key as keyof ReplayedRow)
      )
    ) {
      throw new Error(`${label} has an unexpected property`);
    }
    const descriptor = Object.getOwnPropertyDescriptor(input, key);
    if (
      descriptor === undefined
      || !descriptor.enumerable
      || !Object.prototype.hasOwnProperty.call(descriptor, "value")
    ) {
      throw new Error(`${label}.${key} must be an enumerable own data property; accessors are not allowed`);
    }
    observedKeys.add(key);
    snapshot[key] = descriptor.value;
  }
  for (const key of REQUIRED_REPLAYED_ROW_KEYS) {
    if (!observedKeys.has(key)) {
      if (key === "taskScore") {
        throw new Error(`${label} successful row is missing a finite task score in [0, 1]`);
      }
      throw new Error(`${label}.${key} must be an own data property`);
    }
  }
  assertReplayedRowScalars(snapshot, label);
  if (snapshot.status === "success") {
    assertSuccessfulTimingSemantics({
      ttftMs: snapshot.ttftMs as number,
      endToEndLatencyMs: snapshot.endToEndLatencyMs as number,
      outputTokens: snapshot.outputTokens as number,
      perceivedTokensPerSecond: snapshot.perceivedTokensPerSecond as number,
    }, label);
  }
  snapshot.attemptedProfileIds = snapshotRowStringArray(
    snapshot.attemptedProfileIds,
    `${label}.attemptedProfileIds`,
    2,
  );
  snapshot.slices = snapshotRowStringArray(snapshot.slices, `${label}.slices`, 64);
  if (snapshot.serviceThroughput !== undefined) {
    snapshot.serviceThroughput = snapshotServiceThroughput(
      snapshot.serviceThroughput as ReplayedRow["serviceThroughput"],
      `${label}.serviceThroughput`,
    );
  }
  return snapshot as unknown as ReplayedRow;
}

function snapshotReplayedRows(
  rows: readonly ReplayedRow[],
  label: RowCollectionPreflight["label"],
): ReplayedRow[] {
  return rows.map((row, index) => snapshotReplayedRow(row, `${label} row ${index}`));
}

function assertDirectEvaluationCardinalityBudget(
  candidateLength: number,
  championLength: number,
  bootstrapDraws: number,
  budget: WorkBudget,
): void {
  const input: LegacyAssessmentWorkInput = {
    candidateCount: 1,
    traceRows: candidateLength,
    evidenceRows: championLength,
    bootstrapDraws,
    independentGroups: 0,
  };
  assertWithinLegacyAssessmentBudget(estimateLegacyAssessmentWork(input), budget);
}

function snapshotRowCollection(preflight: RowCollectionPreflight): ReplayedRow[] {
  const { input, label, length } = preflight;
  const allowedKeys = new Set<string>(["length"]);
  const snapshot: ReplayedRow[] = [];
  for (let index = 0; index < length; index += 1) {
    const key = String(index);
    allowedKeys.add(key);
    const descriptor = Object.getOwnPropertyDescriptor(input, key);
    if (descriptor === undefined) {
      throw new Error(`${label} row collection has a hole at index ${index}`);
    }
    if (
      !descriptor.enumerable
      || !Object.prototype.hasOwnProperty.call(descriptor, "value")
    ) {
      throw new Error(
        `${label} row collection index ${index} must be an enumerable own data property; accessors are not allowed`,
      );
    }
    snapshot.push(descriptor.value as ReplayedRow);
  }
  for (const key of Reflect.ownKeys(input)) {
    if (typeof key === "symbol") throw new Error(`${label} row collection has a symbol property`);
    if (!allowedKeys.has(key)) throw new Error(`${label} row collection has an extra property "${key}"`);
  }
  if (Object.getOwnPropertyDescriptor(input, "length")?.value !== length) {
    throw new Error(`${label} row collection length changed during snapshot`);
  }
  return snapshot;
}

function preflightDirectEvaluationGroups(
  candidate: RowCollectionPreflight,
  champion: RowCollectionPreflight,
  bootstrapDraws: number,
  budget: WorkBudget,
): LegacyAssessmentWorkInput {
  const input: LegacyAssessmentWorkInput = {
    candidateCount: 1,
    traceRows: candidate.length,
    evidenceRows: champion.length,
    bootstrapDraws,
    independentGroups: 0,
  };
  const groups = new Set<string>();
  for (const collection of [candidate, champion]) {
    for (let index = 0; index < collection.length; index += 1) {
      const rowLabel = `${collection.label} row ${index}`;
      const row = descriptorArrayEntry(
        collection.input as unknown[],
        index,
        `${collection.label} row collection`,
      );
      assertPlainDescriptorObject(row, rowLabel);
      const groupId = descriptorDataProperty(row, "groupId", rowLabel);
      if (
        typeof groupId !== "string"
        || groupId.length === 0
        || groupId !== groupId.trim()
      ) {
        throw new Error(`${rowLabel}.groupId must be a canonical trimmed non-empty string`);
      }
      groups.add(groupId);
      if (groups.size > budget.maxIndependentGroups) {
        throw new Error(
          `independent group count exceeds caller work budget: ${groups.size} > ${budget.maxIndependentGroups}`,
        );
      }
    }
  }
  input.independentGroups = groups.size;
  assertWithinLegacyAssessmentBudget(estimateLegacyAssessmentWork(input), budget);
  return input;
}

function effectiveWeightedRows(rows: readonly ReplayedRow[]): Array<{ row: ReplayedRow; weight: number }> {
  const replicatesByCase = new Map<string, number>();
  const orderedRows = [...rows].sort((left, right) => (
    compareCodeUnits(left.caseId, right.caseId)
    || left.replicateIndex - right.replicateIndex
  ));
  for (const row of orderedRows) {
    replicatesByCase.set(row.caseId, (replicatesByCase.get(row.caseId) ?? 0) + 1);
  }
  return orderedRows.map((row) => ({
    row,
    weight: row.trafficWeight / replicatesByCase.get(row.caseId)!,
  }));
}

function weightedMean(values: readonly WeightedValue[]): number {
  let totalWeight = 0;
  let numerator = 0;
  for (const entry of values) {
    totalWeight += entry.weight;
    numerator += entry.value * entry.weight;
    if (!Number.isFinite(totalWeight) || !Number.isFinite(numerator)) {
      throw new Error("weighted metric accumulation exceeds the finite numeric range");
    }
  }
  if (totalWeight === 0) return 0;
  return numerator / totalWeight;
}

/**
 * Deterministic inverse-CDF weighted quantile. Effective traffic weights, rather than
 * raw replicate counts, determine how much probability mass each recorded outcome owns.
 */
function weightedQuantile(values: readonly WeightedValue[], q: number): number {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((left, right) => left.value - right.value);
  const totalWeight = sorted.reduce((sum, entry) => sum + entry.weight, 0);
  if (totalWeight === 0) return sorted[0].value;
  const target = Math.min(1, Math.max(0, q)) * totalWeight;
  let cumulative = 0;
  for (const entry of sorted) {
    cumulative += entry.weight;
    if (cumulative >= target) return entry.value;
  }
  return sorted[sorted.length - 1].value;
}

function exactPolicyServiceThroughput(row: ReplayedRow): number | undefined {
  const attemptedProfileIds = row.attemptedProfileIds;
  const isKnownSerialPolicy = (
    row.policyKind === "cascade"
    || row.escalated
    || attemptedProfileIds.length !== 1
    || attemptedProfileIds[0] !== row.selectedProfileId
  );
  if (
    isKnownSerialPolicy
    || (row.policyKind !== "fast-only" && row.policyKind !== "expert-only")
    || row.status !== "success"
  ) {
    return undefined;
  }
  const observation = row.serviceThroughput;
  return (
    observation?.kind === "measured"
    && Number.isFinite(observation.tokensPerSecond)
    && observation.tokensPerSecond >= 0
  )
    ? observation.tokensPerSecond
    : undefined;
}

function computePolicyMetricsInternal(
  rows: readonly ReplayedRow[],
  criticalSlices: readonly string[],
): PolicyMetrics {
  const weightedRows = effectiveWeightedRows(rows);
  const values = (select: (row: ReplayedRow) => number): WeightedValue[] => (
    weightedRows.map(({ row, weight }) => ({ value: select(row), weight }))
  );
  const scoreValues = values((row) => row.status === "failure" ? 0 : row.taskScore);
  const costPerRequestUsd = weightedMean(values((row) => row.costUsd));
  const criticalSliceTaskScore: Record<string, number | null> = Object.create(null) as Record<
    string,
    number | null
  >;
  const serviceThroughputValues: WeightedValue[] = [];
  let serviceThroughputUnavailable = false;
  for (const { row, weight } of weightedRows) {
    const tokensPerSecond = exactPolicyServiceThroughput(row);
    if (tokensPerSecond !== undefined) {
      serviceThroughputValues.push({ value: tokensPerSecond, weight });
    } else {
      serviceThroughputUnavailable = true;
    }
  }

  for (const slice of criticalSlices) {
    const sliceRows = weightedRows
      .filter(({ row }) => row.slices.includes(slice))
      .map(({ row, weight }) => ({ value: row.status === "failure" ? 0 : row.taskScore, weight }));
    criticalSliceTaskScore[slice] = sliceRows.length === 0 ? null : weightedMean(sliceRows);
  }

  return {
    meanTaskScore: weightedMean(scoreValues),
    successRate: weightedMean(values((row) => row.status === "success" ? 1 : 0)),
    errorRate: weightedMean(values((row) => row.status === "failure" ? 1 : 0)),
    p50TtftMs: weightedQuantile(values((row) => row.ttftMs), 0.5),
    p95TtftMs: weightedQuantile(values((row) => row.ttftMs), 0.95),
    p50EndToEndLatencyMs: weightedQuantile(values((row) => row.endToEndLatencyMs), 0.5),
    p95EndToEndLatencyMs: weightedQuantile(values((row) => row.endToEndLatencyMs), 0.95),
    p99EndToEndLatencyMs: weightedQuantile(values((row) => row.endToEndLatencyMs), 0.99),
    p10PerceivedTokensPerSecond: weightedQuantile(
      values((row) => row.status === "failure" ? 0 : row.perceivedTokensPerSecond),
      0.1,
    ),
    p50TotalTokensPerSecond: serviceThroughputUnavailable
      ? null
      : weightedQuantile(serviceThroughputValues, 0.5),
    costPerRequestUsd,
    costPerThousandRequestsUsd: costPerRequestUsd * 1_000,
    escalationRate: weightedMean(values((row) => row.escalated ? 1 : 0)),
    criticalSliceTaskScore,
  };
}

export function computePolicyMetrics(rows: ReplayedRow[], criticalSlices: string[]): PolicyMetrics {
  const rowsPreflight = preflightRowCollection(rows, "candidate");
  const rowSnapshot = snapshotReplayedRows(snapshotRowCollection(rowsPreflight), "candidate");
  preflightDirectRowSlices(rowSnapshot, "candidate");
  assertSinglePolicyRows(rowSnapshot, "candidate");
  const criticalSliceSnapshot = snapshotSliceLabels(criticalSlices, "critical slice list");
  return computePolicyMetricsInternal(rowSnapshot, criticalSliceSnapshot);
}

function gate(
  id: string,
  actual: number | null,
  threshold: number,
  comparison: ">=" | "<=",
  absentReason?: string,
): GateResult {
  const pass = actual !== null && (comparison === ">=" ? actual >= threshold : actual <= threshold);
  const reason = actual === null
    ? (absentReason ?? `${id} has no measured value`)
    : `${id}: ${actual} ${pass ? "meets" : "does not meet"} required ${comparison} ${threshold}`;
  return { id, pass, actual, threshold, comparison, reason };
}

function serviceThroughputGate(actual: number | null, threshold: number): GateResult {
  if (actual === null && threshold === 0) {
    return {
      id: "p50_total_tps",
      pass: true,
      actual: null,
      threshold,
      comparison: ">=",
      reason: "p50_total_tps is unavailable and the zero threshold explicitly disables the capacity requirement",
    };
  }
  return gate(
    "p50_total_tps",
    actual,
    threshold,
    ">=",
    "p50_total_tps is unavailable for the exact policy and the required capacity gate fails closed",
  );
}

interface PairedCase {
  caseId: string;
  groupId: string;
  trafficWeight: number;
  slices: string[];
  critical: boolean;
  replicateDeltas: Array<{
    caseId: string;
    replicateId: string;
    delta: number;
  }>;
}

function snapshotSliceLabels(input: unknown, label: string): string[] {
  if (!Array.isArray(input) || isProxy(input)) throw new Error(`${label} must be an array`);
  const lengthDescriptor = Object.getOwnPropertyDescriptor(input, "length");
  const length = lengthDescriptor?.value;
  if (!Number.isSafeInteger(length) || length < 0) {
    throw new Error(`${label} length must be a safe non-negative integer`);
  }
  if (length > 64) throw new Error(`${label} exceeds 64 slice labels`);

  const allowedKeys = new Set<string>(["length"]);
  const slices: string[] = [];
  const seen = new Set<string>();
  for (let index = 0; index < length; index += 1) {
    const key = String(index);
    allowedKeys.add(key);
    const descriptor = Object.getOwnPropertyDescriptor(input, key);
    if (
      descriptor === undefined
      || !descriptor.enumerable
      || !Object.prototype.hasOwnProperty.call(descriptor, "value")
    ) {
      throw new Error(`${label} must be dense and contain only enumerable own data properties`);
    }
    if (typeof descriptor.value !== "string" || descriptor.value.trim().length === 0) {
      throw new Error(`${label} must contain non-empty string labels`);
    }
    if (descriptor.value !== descriptor.value.trim()) {
      throw new Error(`${label} labels must be trimmed without surrounding whitespace`);
    }
    if (seen.has(descriptor.value)) throw new Error(`${label} has duplicate slice labels`);
    seen.add(descriptor.value);
    slices.push(descriptor.value);
  }
  for (const key of Reflect.ownKeys(input)) {
    if (typeof key !== "string" || !allowedKeys.has(key)) {
      throw new Error(`${label} must contain only indexed own data properties`);
    }
  }
  return slices.sort(compareCodeUnits);
}

function normalizedSlices(row: ReplayedRow, label: string): string[] {
  if (typeof row !== "object" || row === null || isProxy(row)) {
    throw new Error(`${label} row must be a non-proxy object`);
  }
  const descriptor = Object.getOwnPropertyDescriptor(row, "slices");
  if (
    descriptor === undefined
    || !Object.prototype.hasOwnProperty.call(descriptor, "value")
  ) {
    throw new Error(`${label} row slices must be an own data property; accessors are not allowed`);
  }
  return snapshotSliceLabels(descriptor.value, `${label} row slices`);
}

function preflightDirectRowSlices(
  rows: readonly ReplayedRow[],
  label: "candidate" | "champion",
): void {
  for (let index = 0; index < rows.length; index += 1) {
    normalizedSlices(rows[index], `${label} index ${index}`);
  }
}

function rowScore(row: ReplayedRow, label: string): number {
  if (row.status === "failure") return 0;
  if (!Number.isFinite(row.taskScore) || row.taskScore < 0 || row.taskScore > 1) {
    throw new Error(`${label} successful row is missing a finite task score in [0, 1]`);
  }
  return row.taskScore;
}

function assertSinglePolicyRows(
  rows: readonly ReplayedRow[],
  label: "candidate" | "champion",
): void {
  let policyId: string | undefined;
  let policyKind: ReplayedRow["policyKind"] | undefined;
  for (let index = 0; index < rows.length; index += 1) {
    const row = rows[index];
    if (typeof row.policyId !== "string" || row.policyId.length === 0) {
      throw new Error(`${label} row ${index} policyId must be a non-empty string`);
    }
    if (
      row.policyKind !== undefined
      && row.policyKind !== "expert-only"
      && row.policyKind !== "fast-only"
      && row.policyKind !== "cascade"
    ) {
      throw new Error(`${label} row ${index} policyKind is invalid`);
    }
    if (index === 0) {
      policyId = row.policyId;
      policyKind = row.policyKind;
    } else if (row.policyId !== policyId || row.policyKind !== policyKind) {
      throw new Error(`${label} rows must share one policyId and policyKind`);
    }
  }
}

function assertRowIdentity(row: ReplayedRow, label: string): void {
  if (typeof row.caseId !== "string" || row.caseId.length === 0) {
    throw new Error(`${label} caseId must be non-empty`);
  }
  if (!Number.isSafeInteger(row.replicateIndex) || row.replicateIndex < 0) {
    throw new Error(`${label} replicateIndex must be a safe non-negative integer`);
  }
  if (typeof row.groupId !== "string" || row.groupId.length === 0) {
    throw new Error(`${label} groupId must be non-empty`);
  }
  if (!Number.isFinite(row.trafficWeight) || row.trafficWeight <= 0) {
    throw new Error(`${label} trafficWeight must be finite and positive`);
  }
  if (typeof row.critical !== "boolean") throw new Error(`${label} critical must be boolean`);
  normalizedSlices(row, label);
  rowScore(row, label);
}

function sameSlices(left: ReplayedRow, right: ReplayedRow, label: string): boolean {
  const leftSlices = normalizedSlices(left, `${label} candidate`);
  const rightSlices = normalizedSlices(right, `${label} champion`);
  return (
    leftSlices.length === rightSlices.length
    && leftSlices.every((slice, index) => slice === rightSlices[index])
  );
}

function assertLineage(left: ReplayedRow, right: ReplayedRow, label: string): void {
  if (left.groupId !== right.groupId) throw new Error(`${label} has group lineage drift`);
  if (left.trafficWeight !== right.trafficWeight) throw new Error(`${label} has traffic-weight lineage drift`);
  if (!sameSlices(left, right, label)) throw new Error(`${label} has slice-set lineage drift`);
  if (left.critical !== right.critical) throw new Error(`${label} has critical lineage drift`);
}

function indexRows(rows: readonly ReplayedRow[], label: string): Map<string, Map<number, ReplayedRow>> {
  const byCase = new Map<string, Map<number, ReplayedRow>>();
  const caseBaseline = new Map<string, ReplayedRow>();
  for (const row of rows) {
    assertRowIdentity(row, label);
    const baseline = caseBaseline.get(row.caseId);
    if (baseline === undefined) caseBaseline.set(row.caseId, row);
    else assertLineage(row, baseline, `${label} case "${row.caseId}"`);
    const byReplicate = byCase.get(row.caseId) ?? new Map<number, ReplayedRow>();
    if (byReplicate.has(row.replicateIndex)) {
      throw new Error(
        `${label} has duplicate (caseId, replicateIndex) pair ("${row.caseId}", ${row.replicateIndex})`,
      );
    }
    byReplicate.set(row.replicateIndex, row);
    byCase.set(row.caseId, byReplicate);
  }
  return byCase;
}

function pairRows(
  candidateRows: readonly ReplayedRow[],
  championRows: readonly ReplayedRow[],
): PairedCase[] {
  const candidateByCase = indexRows(candidateRows, "candidate");
  const championByCase = indexRows(championRows, "champion");
  const caseIds = [...new Set([...candidateByCase.keys(), ...championByCase.keys()])].sort(compareCodeUnits);
  const pairedCases: PairedCase[] = [];
  for (const caseId of caseIds) {
    const candidateReplicates = candidateByCase.get(caseId);
    const championReplicates = championByCase.get(caseId);
    if (candidateReplicates === undefined || championReplicates === undefined) {
      throw new Error(`missing paired case-replicate rows for case "${caseId}"`);
    }
    const replicateIndexes = [...new Set([
      ...candidateReplicates.keys(),
      ...championReplicates.keys(),
    ])].sort((left, right) => left - right);
    const replicateDeltas: PairedCase["replicateDeltas"] = [];
    let baseline: ReplayedRow | undefined;
    for (const replicateIndex of replicateIndexes) {
      const candidate = candidateReplicates.get(replicateIndex);
      const champion = championReplicates.get(replicateIndex);
      if (candidate === undefined || champion === undefined) {
        throw new Error(
          `missing (caseId, replicateIndex) pair ("${caseId}", ${replicateIndex})`,
        );
      }
      assertLineage(candidate, champion, `paired case "${caseId}" replicate ${replicateIndex}`);
      if (baseline === undefined) baseline = candidate;
      else assertLineage(candidate, baseline, `candidate case "${caseId}"`);
      replicateDeltas.push({
        caseId,
        replicateId: `legacy-replicate-${replicateIndex}`,
        delta: rowScore(candidate, "candidate") - rowScore(champion, "champion"),
      });
    }
    const row = baseline!;
    pairedCases.push({
      caseId,
      groupId: row.groupId,
      trafficWeight: row.trafficWeight,
      slices: normalizedSlices(row, `case "${caseId}"`),
      critical: row.critical,
      replicateDeltas,
    });
  }
  return pairedCases;
}

function evaluatePolicyInternal(
  candidateRows: ReplayedRow[],
  championRows: ReplayedRow[],
  spec: ResolvedInferenceSpec,
  requireDevelopmentCostImprovement: boolean,
): PolicyEvaluation {
  const criticalSlices = [...new Set(spec.criticalSlices)].sort(compareCodeUnits);
  const pairedCases = pairRows(candidateRows, championRows);
  if (pairedCases.length === 0) throw new Error("at least one exact paired case is required");
  const replicateDeltas = pairedCases.flatMap((pairedCase) => pairedCase.replicateDeltas);
  const caseEffects: GroupedCaseEffect[] = pairedCases.map((pairedCase) => ({
    caseId: pairedCase.caseId,
    groupId: pairedCase.groupId,
    effect: median(pairedCase.replicateDeltas.map(({ delta }) => delta)),
    trafficWeight: pairedCase.trafficWeight,
  }));
  const deltas = caseEffects.map(({ effect }) => effect);
  const groupCount = new Set(pairedCases.map(({ groupId }) => groupId)).size;
  const criticalSliceGroupCoverage = Object.fromEntries(criticalSlices
    .map((slice): [string, number] => [
      slice,
      new Set(pairedCases.filter((pairedCase) => pairedCase.slices.includes(slice))
        .map(({ groupId }) => groupId)).size,
    ])
    .sort(([left], [right]) => compareCodeUnits(left, right)));
  const coverageFailures = [
    ...(groupCount < spec.constraints.minimumIndependentGroups
      ? [`independent groups ${groupCount} < ${spec.constraints.minimumIndependentGroups}`]
      : []),
    ...criticalSlices
      .filter((slice) => criticalSliceGroupCoverage[slice] < spec.constraints.minimumCriticalSliceGroups)
      .map((slice) => (
        `critical slice "${slice}" groups ${criticalSliceGroupCoverage[slice]}`
        + ` < ${spec.constraints.minimumCriticalSliceGroups}`
      )),
  ];
  const inferenceAvailable = coverageFailures.length === 0;
  const groupedBootstrap = inferenceAvailable
    ? bootstrapGroupedWeightedMeanCI(caseEffects, {
      alpha: spec.bootstrap.alpha,
      seed: spec.bootstrap.seed,
      iters: spec.bootstrap.iterations,
    })
    : undefined;
  let effectiveTrafficMass = 0;
  let weightedEffect = 0;
  for (const effect of caseEffects) {
    effectiveTrafficMass += effect.trafficWeight;
    weightedEffect += effect.effect * effect.trafficWeight;
    if (!Number.isFinite(effectiveTrafficMass) || !Number.isFinite(weightedEffect)) {
      throw new Error("paired-quality traffic accumulation exceeds the finite numeric range");
    }
  }
  const estimate = groupedBootstrap?.estimate ?? weightedEffect / effectiveTrafficMass;
  const bootstrap = {
    mean: estimate,
    lo: groupedBootstrap?.interval.lo ?? null,
    hi: groupedBootstrap?.interval.hi ?? null,
    iters: spec.bootstrap.iterations,
    positive: (groupedBootstrap?.interval.lo ?? Number.NEGATIVE_INFINITY) > 0,
  };
  const pairedQuality: PairedQualityResult = {
    method: "paired-group-percentile-v1",
    alpha: spec.bootstrap.alpha,
    caseCount: pairedCases.length,
    replicateCount: replicateDeltas.length,
    groupCount,
    effectiveTrafficMass,
    deltas,
    replicateDeltas,
    caseEffects,
    criticalSliceGroupCoverage,
    estimate,
    interval: {
      lo: groupedBootstrap?.interval.lo ?? null,
      hi: groupedBootstrap?.interval.hi ?? null,
    },
    iterations: spec.bootstrap.iterations,
    seed: spec.bootstrap.seed,
    inferenceAvailable,
    ...(inferenceAvailable ? {} : { unavailableReason: `Coverage failed before inference: ${coverageFailures.join("; ")}` }),
    bootstrap,
  };
  const candidateMetrics = computePolicyMetricsInternal(candidateRows, criticalSlices);
  const championMetrics = computePolicyMetricsInternal(championRows, criticalSlices);
  const championCost = championMetrics.costPerRequestUsd;
  const costImprovement = championCost === 0
    ? null
    : (championCost - candidateMetrics.costPerRequestUsd) / championCost;

  const gates: GateResult[] = [
    gate(
      "paired_quality_non_inferiority",
      pairedQuality.interval.lo,
      spec.constraints.nonInferiorityMargin,
      ">=",
      pairedQuality.unavailableReason,
    ),
    gate(
      "minimum_independent_groups",
      groupCount,
      spec.constraints.minimumIndependentGroups,
      ">=",
    ),
    ...criticalSlices.map((slice) => gate(
      `critical_slice_groups:${slice}`,
      criticalSliceGroupCoverage[slice],
      spec.constraints.minimumCriticalSliceGroups,
      ">=",
    )),
    gate("mean_task_score", candidateMetrics.meanTaskScore, spec.constraints.taskScoreFloor, ">="),
    ...criticalSlices.map((slice) => gate(
      `critical_slice:${slice}`,
      candidateMetrics.criticalSliceTaskScore[slice],
      spec.constraints.criticalSliceScoreFloor,
      ">=",
      `critical_slice:${slice} has no replayed rows and fails closed`,
    )),
    gate("p95_ttft", candidateMetrics.p95TtftMs, spec.constraints.maxP95TtftMs, "<="),
    gate(
      "p95_end_to_end_latency",
      candidateMetrics.p95EndToEndLatencyMs,
      spec.constraints.maxP95EndToEndLatencyMs,
      "<=",
    ),
    gate(
      "p10_perceived_tps",
      candidateMetrics.p10PerceivedTokensPerSecond,
      spec.constraints.minP10PerceivedTokensPerSecond,
      ">=",
    ),
    serviceThroughputGate(
      candidateMetrics.p50TotalTokensPerSecond,
      spec.constraints.minP50TotalTokensPerSecond,
    ),
    gate("error_rate", candidateMetrics.errorRate, spec.constraints.maxErrorRate, "<="),
    gate(
      "cost_per_thousand",
      candidateMetrics.costPerThousandRequestsUsd,
      spec.constraints.maxCostPerThousandRequests,
      "<=",
    ),
  ];

  if (requireDevelopmentCostImprovement) {
    const developmentCostGate = gate(
      "development_cost_improvement",
      costImprovement,
      spec.constraints.minimumCostImprovement,
      ">=",
      championCost === 0
        ? "development_cost_improvement is undefined because champion cost is zero and fails closed"
        : undefined,
    );
    gates.push(developmentCostGate);
  }

  return {
    candidateMetrics,
    championMetrics,
    pairedQuality,
    costImprovement,
    gates,
    passed: gates.every((result) => result.pass),
  };
}

export function evaluatePolicy(
  candidateRows: ReplayedRow[],
  championRows: ReplayedRow[],
  specInput: InferenceSpec,
  options: EvaluationOptions = {},
): PolicyEvaluation {
  const optionsSnapshot = parseEvaluationOptions(options);
  const budget = optionsSnapshot.workBudget ?? DEFAULT_ASSESSMENT_WORK_BUDGET;
  const candidatePreflight = preflightRowCollection(candidateRows, "candidate");
  const championPreflight = preflightRowCollection(championRows, "champion");
  const specPreflight = prepareInferenceSpec(specInput);
  assertDirectEvaluationCardinalityBudget(
    candidatePreflight.length,
    championPreflight.length,
    specPreflight.bootstrapIterations,
    budget,
  );
  preflightDirectEvaluationGroups(
    candidatePreflight,
    championPreflight,
    specPreflight.bootstrapIterations,
    budget,
  );
  const candidateSnapshot = snapshotReplayedRows(
    snapshotRowCollection(candidatePreflight),
    "candidate",
  );
  const championSnapshot = snapshotReplayedRows(
    snapshotRowCollection(championPreflight),
    "champion",
  );
  preflightDirectRowSlices(candidateSnapshot, "candidate");
  preflightDirectRowSlices(championSnapshot, "champion");
  assertSinglePolicyRows(candidateSnapshot, "candidate");
  assertSinglePolicyRows(championSnapshot, "champion");
  const spec = parsePreparedInferenceSpec(specPreflight);
  return evaluatePolicyInternal(candidateSnapshot, championSnapshot, spec, true);
}

function digest(value: unknown): string {
  return sha256(canonicalJson(value));
}

function normalizedSpecForDigest(spec: ResolvedInferenceSpec): ResolvedInferenceSpec {
  const normalized = structuredClone(spec);
  normalized.profiles.sort((left, right) => compareCodeUnits(left.id, right.id));
  normalized.candidateSpace.confidenceThresholds = [
    ...new Set(normalized.candidateSpace.confidenceThresholds),
  ].sort((left, right) => left - right);
  normalized.candidateSpace.inputTokenThresholds = [
    ...new Set(normalized.candidateSpace.inputTokenThresholds),
  ].sort((left, right) => left - right);
  normalized.criticalSlices = [...new Set(normalized.criticalSlices)].sort(compareCodeUnits);
  return normalized;
}

function specDigest(spec: ResolvedInferenceSpec): string {
  return digest(normalizedSpecForDigest(spec));
}

function legacySpecProjection(spec: ResolvedInferenceSpec): unknown {
  const legacy = structuredClone(spec);
  const legacyConstraints = legacy.constraints as unknown as Record<string, unknown>;
  const legacyBootstrap = legacy.bootstrap as unknown as Record<string, unknown>;
  delete legacyConstraints.minimumIndependentGroups;
  delete legacyConstraints.minimumCriticalSliceGroups;
  delete legacyBootstrap.alpha;
  return legacy;
}

function hasLegacyDefaultInferenceControls(spec: ResolvedInferenceSpec): boolean {
  return (
    spec.bootstrap.alpha === 0.05
    && spec.constraints.minimumIndependentGroups === 3
    && spec.constraints.minimumCriticalSliceGroups === (spec.criticalSlices.length === 0 ? 0 : 1)
  );
}

function normalizedMeasurementsForDigest(measurements: MeasurementSet): MeasurementSet {
  const normalized = structuredClone(measurements);
  normalized.cases = normalized.cases
    .map((measurementCase) => ({
      ...measurementCase,
      slices: [...measurementCase.slices].sort(compareCodeUnits),
      observations: [...measurementCase.observations]
        .sort((left, right) => compareCodeUnits(left.profileId, right.profileId)),
    }))
    .sort((left, right) => compareCodeUnits(left.id, right.id));
  return normalized;
}

function measurementDigest(measurements: MeasurementSet): string {
  return digest(normalizedMeasurementsForDigest(measurements));
}

function dominates(left: PolicyMetrics, right: PolicyMetrics, capacityRequired: boolean): boolean {
  const higherIsBetter: Array<keyof PolicyMetrics> = [
    "meanTaskScore",
    "p10PerceivedTokensPerSecond",
  ];
  if (capacityRequired) {
    higherIsBetter.push("p50TotalTokensPerSecond");
  }
  const lowerIsBetter: Array<keyof PolicyMetrics> = [
    "errorRate",
    "p95TtftMs",
    "p95EndToEndLatencyMs",
    "costPerRequestUsd",
  ];
  const comparable = (value: unknown): value is number => typeof value === "number" && Number.isFinite(value);
  const neverWorse = (
    higherIsBetter.every((key) => (
      comparable(left[key]) && comparable(right[key]) && left[key] >= right[key]
    ))
    && lowerIsBetter.every((key) => (
      comparable(left[key]) && comparable(right[key]) && left[key] <= right[key]
    ))
  );
  const strictlyBetter = (
    higherIsBetter.some((key) => (
      comparable(left[key]) && comparable(right[key]) && left[key] > right[key]
    ))
    || lowerIsBetter.some((key) => (
      comparable(left[key]) && comparable(right[key]) && left[key] < right[key]
    ))
  );
  return neverWorse && strictlyBetter;
}

function objectiveSignature(metrics: PolicyMetrics, capacityRequired: boolean): string {
  return canonicalJson([
    metrics.meanTaskScore,
    metrics.p10PerceivedTokensPerSecond,
    capacityRequired ? metrics.p50TotalTokensPerSecond : null,
    metrics.errorRate,
    metrics.p95TtftMs,
    metrics.p95EndToEndLatencyMs,
    metrics.costPerRequestUsd,
  ]);
}

function boundedParetoFrontier(
  passers: readonly CandidateEvaluation[],
  capacityRequired: boolean,
  workInput: LegacyAssessmentWorkInput,
  budget: WorkBudget,
): CandidateEvaluation[] {
  const bySignature = new Map<string, CandidateEvaluation[]>();
  for (const candidate of passers) {
    const signature = objectiveSignature(
      candidate.evaluation.candidateMetrics,
      capacityRequired,
    );
    const equivalents = bySignature.get(signature);
    if (equivalents === undefined) bySignature.set(signature, [candidate]);
    else equivalents.push(candidate);
  }
  const signatureGroups = [...bySignature.values()].sort((left, right) => (
    compareCodeUnits(left[0].policy.id, right[0].policy.id)
  ));
  assertWithinLegacyAssessmentBudget(
    estimateLegacyAssessmentWork(workInput, signatureGroups.length),
    budget,
    "frontier",
  );

  const nonDominatedGroups = signatureGroups.filter((candidateGroup) => (
    !signatureGroups.some((otherGroup) => (
      otherGroup !== candidateGroup
      && dominates(
        otherGroup[0].evaluation.candidateMetrics,
        candidateGroup[0].evaluation.candidateMetrics,
        capacityRequired,
      )
    ))
  ));
  return nonDominatedGroups.flatMap((group) => group);
}

type NominationArtifactBody = Omit<NominationArtifact, "selfDigest" | "attestation">;

function artifactSelfDigest(artifact: NominationArtifactBody): string {
  return digest(artifact);
}

function validatedAttestationKey(key: string): Buffer {
  const bytes = Buffer.from(key, "utf8");
  if (bytes.byteLength < 32) {
    throw new Error("attestation key must be at least 32 UTF-8 bytes");
  }
  return bytes;
}

function attestationDigest(artifact: Omit<NominationArtifact, "attestation">, key: Buffer): string {
  return createHmac("sha256", key).update(canonicalJson(artifact)).digest("hex");
}

export function nominatePolicy(
  specInput: InferenceSpec,
  dev: MeasurementSet,
  options: AttestationOptions = {},
): NominationResult {
  const optionsSnapshot = parseAttestationOptions(options, "nomination options");
  const workBudget = optionsSnapshot.workBudget ?? DEFAULT_ASSESSMENT_WORK_BUDGET;
  const attestationKeyInput = optionsSnapshot.attestationKey;
  const attestationKey = attestationKeyInput === undefined
    ? undefined
    : validatedAttestationKey(attestationKeyInput);
  const specPreflight = prepareInferenceSpec(specInput);
  const preparedDevelopment = prepareMeasurementAssessment(specPreflight, dev, workBudget);
  const devSnapshot = preparedDevelopment.measurements;
  if (devSnapshot.dataset.split !== "dev") {
    throw new Error(`nomination requires development split "dev"; received "${devSnapshot.dataset.split}"`);
  }
  const spec = parsePreparedInferenceSpec(specPreflight);
  assertMeasurementMatrix(spec, devSnapshot);

  const champion = championPolicyForResolvedSpec(spec);
  const championRows = replayPolicyForResolvedSpec(champion, spec, devSnapshot);
  const evaluations = generateCandidatePoliciesForResolvedSpec(spec).map((policy): CandidateEvaluation => ({
    policy,
    evaluation: evaluatePolicyInternal(
      replayPolicyForResolvedSpec(policy, spec, devSnapshot),
      championRows,
      spec,
      true,
    ),
  }));
  const passers = evaluations.filter(({ evaluation }) => evaluation.passed);
  const frontierEntries = boundedParetoFrontier(
    passers,
    spec.constraints.minP50TotalTokensPerSecond > 0,
    preparedDevelopment.workInput,
    workBudget,
  );
  const orderedFrontier = [...frontierEntries].sort((left, right) => (
    left.evaluation.candidateMetrics.costPerRequestUsd
      - right.evaluation.candidateMetrics.costPerRequestUsd
    || left.evaluation.candidateMetrics.p95EndToEndLatencyMs
      - right.evaluation.candidateMetrics.p95EndToEndLatencyMs
    || compareCodeUnits(left.policy.id, right.policy.id)
  ));
  const frontier = frontierEntries.map(({ policy }) => policy.id).sort(compareCodeUnits);

  if (orderedFrontier.length === 0) {
    return { status: "NO_CANDIDATE", evaluations, frontier, nomination: undefined };
  }

  const selected = orderedFrontier[0];
  const resolvedSpecDigest = specDigest(spec);
  const policyDigest = fingerprintPolicy(selected.policy);
  const decisionDigest = digest({
    evaluations,
    frontier,
    selectedPolicyId: selected.policy.id,
  });
  const artifactBody: NominationArtifactBody = {
    version: "tasc-nomination-v1",
    specDigest: resolvedSpecDigest,
    developmentDatasetDigest: measurementDigest(devSnapshot),
    evaluator: structuredClone(devSnapshot.evaluator),
    developmentGroupIds: [...new Set(devSnapshot.cases.map((measurementCase) => measurementCase.groupId))]
      .sort(compareCodeUnits),
    developmentSynthetic: devSnapshot.dataset.synthetic,
    policy: structuredClone(selected.policy),
    policyDigest,
    candidateMetrics: structuredClone(selected.evaluation.candidateMetrics),
    championMetrics: structuredClone(selected.evaluation.championMetrics),
    gates: structuredClone(selected.evaluation.gates),
    decisionDigest,
  };
  const unsignedArtifact: Omit<NominationArtifact, "attestation"> = {
    ...artifactBody,
    selfDigest: artifactSelfDigest(artifactBody),
  };

  return {
    status: "NOMINATED",
    evaluations,
    frontier,
    nomination: {
      ...unsignedArtifact,
      ...(attestationKey === undefined ? {} : {
        attestation: {
          algorithm: "hmac-sha256",
          digest: attestationDigest(unsignedArtifact, attestationKey),
        } satisfies NominationAttestation,
      }),
    },
  };
}

function assertNominationSelfDigest(nomination: NominationArtifact): void {
  const { selfDigest, attestation: _attestation, ...body } = nomination;
  if (selfDigest !== artifactSelfDigest(body)) {
    throw new Error("nomination self-digest mismatch: artifact was edited after development selection");
  }
}

function parseNominationArtifact(input: unknown, workBudget: WorkBudget): NominationArtifact {
  return nominationArtifactSchema.parse(snapshotPlainDataTree(input, "nomination", {
    arrayLengthLimits: new Map([
      ["nomination.developmentGroupIds", workBudget.maxIndependentGroups],
    ]),
  }));
}

function verifyNominationAttestation(nomination: NominationArtifact, key: Buffer): void {
  const { attestation, ...unsignedArtifact } = nomination;
  const suppliedDigest = attestation?.digest;
  const expectedDigest = attestationDigest(unsignedArtifact, key);
  if (
    attestation?.algorithm !== "hmac-sha256"
    || suppliedDigest === undefined
    || !/^[a-f0-9]{64}$/.test(suppliedDigest)
  ) {
    throw new Error("nomination attestation mismatch");
  }
  const suppliedBytes = Buffer.from(suppliedDigest, "hex");
  const expectedBytes = Buffer.from(expectedDigest, "hex");
  if (!timingSafeEqual(suppliedBytes, expectedBytes)) {
    throw new Error("nomination attestation mismatch");
  }
}

function evaluatorMatches(
  left: MeasurementSet["evaluator"],
  right: MeasurementSet["evaluator"],
): boolean {
  return (
    left.id === right.id
    && left.version === right.version
    && left.kind === right.kind
    && left.validated === right.validated
  );
}

function isRegisteredLegacyCandidate(policy: InferencePolicy, spec: ResolvedInferenceSpec): boolean {
  if (
    policy.version !== "tasc-policy-v1"
    || policy.kind === "expert-only"
    || policy.primaryProfileId !== spec.primaryProfileId
    || policy.expertProfileId !== spec.championProfileId
    || policy.criticalSlices.length !== spec.criticalSlices.length
    || policy.criticalSlices.some((slice, index) => slice !== spec.criticalSlices[index])
  ) {
    return false;
  }
  if (
    policy.kind === "fast-only"
      ? (
        !spec.candidateSpace.includeFastOnly
        || policy.confidenceThreshold !== undefined
        || policy.inputTokenThreshold !== undefined
      )
      : (
        policy.confidenceThreshold === undefined
        || policy.inputTokenThreshold === undefined
        || !spec.candidateSpace.confidenceThresholds.includes(policy.confidenceThreshold)
        || !spec.candidateSpace.inputTokenThresholds.includes(policy.inputTokenThreshold)
      )
  ) {
    return false;
  }
  const { id: _id, ...body } = policy;
  return policy.id === `${policy.kind}-${sha256(canonicalJson(body)).slice(0, 16)}`;
}

export function confirmNomination(
  specInput: InferenceSpec,
  holdout: MeasurementSet,
  nomination: NominationArtifact,
  options: AttestationOptions = {},
): ConfirmationResult {
  const optionsSnapshot = parseAttestationOptions(options, "confirmation options");
  const workBudget = optionsSnapshot.workBudget ?? DEFAULT_ASSESSMENT_WORK_BUDGET;
  const attestationKeyInput = optionsSnapshot.attestationKey;
  const attestationKey = attestationKeyInput === undefined
    ? undefined
    : validatedAttestationKey(attestationKeyInput);
  const specPreflight = prepareInferenceSpec(specInput);
  const preparedHoldout = prepareMeasurementAssessment(specPreflight, holdout, workBudget);
  const holdoutSnapshot = preparedHoldout.measurements;
  const nominationSnapshot = parseNominationArtifact(nomination, workBudget);
  if (holdoutSnapshot.dataset.split !== "holdout") {
    throw new Error(`confirmation requires holdout split "holdout"; received "${holdoutSnapshot.dataset.split}"`);
  }
  if (attestationKey !== undefined) {
    verifyNominationAttestation(nominationSnapshot, attestationKey);
  }
  assertNominationSelfDigest(nominationSnapshot);
  const attestationVerified = attestationKey !== undefined;
  const spec = parsePreparedInferenceSpec(specPreflight);

  const resolvedSpecDigest = specDigest(spec);
  const matchesLegacySpecDigest = (
    hasLegacyDefaultInferenceControls(spec)
    && nominationSnapshot.specDigest === digest(legacySpecProjection(spec))
  );
  if (nominationSnapshot.specDigest !== resolvedSpecDigest && !matchesLegacySpecDigest) {
    throw new Error("spec digest mismatch: nomination was produced from a different inference spec");
  }
  if (nominationSnapshot.policyDigest !== fingerprintPolicy(nominationSnapshot.policy)) {
    throw new Error("policy digest mismatch: nominated policy body was edited");
  }

  const regenerated = generateCandidatePoliciesForResolvedSpec(spec).find((candidate) => (
    candidate.id === nominationSnapshot.policy.id
    && fingerprintPolicy(candidate) === nominationSnapshot.policyDigest
    && canonicalJson(candidate) === canonicalJson(nominationSnapshot.policy)
  )) ?? (
    matchesLegacySpecDigest && isRegisteredLegacyCandidate(nominationSnapshot.policy, spec)
      ? structuredClone(nominationSnapshot.policy)
      : undefined
  );
  if (!regenerated) {
    throw new Error("policy drift: nomination does not exactly match a regenerated candidate");
  }
  if (!evaluatorMatches(nominationSnapshot.evaluator, holdoutSnapshot.evaluator)) {
    throw new Error("evaluator drift: holdout evaluator identity, version, kind, and validation must match development");
  }

  const developmentGroups = new Set(nominationSnapshot.developmentGroupIds);
  const leakedGroups = [...new Set(
    holdoutSnapshot.cases
      .map((measurementCase) => measurementCase.groupId)
      .filter((groupId) => developmentGroups.has(groupId)),
  )].sort(compareCodeUnits);
  if (leakedGroups.length > 0) {
    throw new Error(`development/holdout group leakage: ${leakedGroups.join(", ")}`);
  }
  assertMeasurementMatrix(spec, holdoutSnapshot);

  const championRows = replayPolicyForResolvedSpec(championPolicyForResolvedSpec(spec), spec, holdoutSnapshot);
  const candidateRows = replayPolicyForResolvedSpec(regenerated, spec, holdoutSnapshot);
  const evaluation = evaluatePolicyInternal(candidateRows, championRows, spec, false);
  let status: "DEMO_ONLY" | "HOLD";
  let statusReason: string;
  if (!evaluation.passed) {
    status = "HOLD";
    const failedGateIds = evaluation.gates.filter((gateResult) => !gateResult.pass).map((gateResult) => gateResult.id);
    statusReason = `Holdout hard gates failed: ${failedGateIds.join(", ")}`
      + (
        nominationSnapshot.developmentSynthetic || holdoutSnapshot.dataset.synthetic
          ? ""
          : "; legacy v1 migration to a registered v2 protocol is required for any production recommendation"
      );
  } else if (nominationSnapshot.developmentSynthetic || holdoutSnapshot.dataset.synthetic) {
    status = "DEMO_ONLY";
    statusReason = "Passing gates are demo-only because development or holdout evidence is synthetic";
  } else {
    status = "HOLD";
    statusReason = attestationVerified
      ? "Passing real legacy v1 evidence is capped at HOLD; migrate to a registered v2 protocol for any production recommendation"
      : "Production readiness requires migration from legacy v1 to a registered v2 protocol with verified attestation provenance";
  }
  const confirmationBody = {
    version: "tasc-confirmation-v1" as const,
    status,
    specDigest: resolvedSpecDigest,
    holdoutDatasetDigest: measurementDigest(holdoutSnapshot),
    nominationDigest: nominationSnapshot.selfDigest,
    evaluator: structuredClone(holdoutSnapshot.evaluator),
    holdoutGroupIds: [...new Set(holdoutSnapshot.cases.map((measurementCase) => measurementCase.groupId))]
      .sort(compareCodeUnits),
    policy: structuredClone(regenerated),
    policyDigest: nominationSnapshot.policyDigest,
    evaluation,
    attestationVerified,
    statusReason,
  };
  return {
    ...confirmationBody,
    decisionDigest: digest(confirmationBody),
  };
}
