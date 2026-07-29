import { z } from "zod";
import {
  contractDigestSchema,
  contractSlugSchema,
  deepFreezeContract,
  domainSeparatedDigest,
  type DeepReadonly,
} from "./evidence.js";
import {
  parsePolicyBundleValue,
  type PolicyBundle,
} from "./policy.js";
import type { AssessmentDecision } from "./assessment.js";

const ASSESSMENT_DECISION_DOMAIN = "tasc/assessment-decision/v2";
const MAX_CANDIDATES = 10_000;
export const MAX_ASSESSMENT_DECISION_REPLAY_ROWS = 10_000;
const MAX_GATES = 128;
const MAX_REASON_ENTRIES = 256;
const MAX_CRITICAL_SLICES = 64;
const MAX_ATTEMPTS = 8;
const MAX_SLICES = 64;
const MAX_SNAPSHOT_DEPTH = 20;
export const MAX_ASSESSMENT_DECISION_NODES = 2_000_000;
const MAX_OBJECT_KEYS = 64;
const MAX_PROPERTY_KEY_LENGTH = 1_024;
const MAX_STRING_LENGTH = 4_096;
const MAX_GENERIC_ARRAY_LENGTH = 256;

type SnapshotPath = readonly (string | number)[];

interface SnapshotState {
  nodes: number;
  replayRows: number;
  readonly ancestors: Set<object>;
}

function hasWellFormedUnicode(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const codeUnit = value.charCodeAt(index);
    if (codeUnit < 0xd800 || codeUnit > 0xdfff) continue;
    if (
      codeUnit > 0xdbff
      || index + 1 >= value.length
      || value.charCodeAt(index + 1) < 0xdc00
      || value.charCodeAt(index + 1) > 0xdfff
    ) {
      return false;
    }
    index += 1;
  }
  return true;
}

function arrayLimit(path: SnapshotPath): {
  readonly maximum: number;
  readonly label: string;
} {
  const field = path[path.length - 1];
  switch (field) {
    case "candidates":
      return { maximum: MAX_CANDIDATES, label: "candidate array" };
    case "replay":
      return {
        maximum: MAX_ASSESSMENT_DECISION_REPLAY_ROWS,
        label: "replay-row array",
      };
    case "gates":
      return { maximum: MAX_GATES, label: "gate array" };
    case "criticalSliceGroups":
      return {
        maximum: MAX_CRITICAL_SLICES,
        label: "critical-slice coverage array",
      };
    case "attemptedProfileIds":
      return { maximum: MAX_ATTEMPTS, label: "attempted-profile array" };
    case "slices":
      return { maximum: MAX_SLICES, label: "slice array" };
    case "insufficiencyReasons":
    case "rejectionReasons":
    case "staleReasons":
    case "warnings":
    case "unavailableMetrics":
      return { maximum: MAX_REASON_ENTRIES, label: `${field} array` };
    default:
      return {
        maximum: MAX_GENERIC_ARRAY_LENGTH,
        label: "assessment contract array",
      };
  }
}

function snapshotValue(
  value: unknown,
  path: SnapshotPath,
  depth: number,
  state: SnapshotState,
): unknown {
  state.nodes += 1;
  if (state.nodes > MAX_ASSESSMENT_DECISION_NODES) {
    throw new Error(
      `assessment decision exceeds the ${MAX_ASSESSMENT_DECISION_NODES.toLocaleString(
        "en-US",
      )}-node contract limit`,
    );
  }
  if (depth > MAX_SNAPSHOT_DEPTH) {
    throw new Error("assessment decision exceeds the contract depth limit");
  }
  if (value === null || typeof value === "boolean") return value;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new Error("assessment decision numbers must be finite");
    }
    return value;
  }
  if (typeof value === "string") {
    if (value.length > MAX_STRING_LENGTH) {
      throw new Error("assessment decision string exceeds the length limit");
    }
    if (!hasWellFormedUnicode(value)) {
      throw new Error(
        "assessment decision strings must contain valid Unicode scalar values",
      );
    }
    return value;
  }
  if (typeof value !== "object") {
    throw new Error("assessment decision must contain JSON-compatible data");
  }
  if (state.ancestors.has(value)) {
    throw new Error("assessment decision must be acyclic");
  }

  const isArray = Array.isArray(value);
  const prototype = Reflect.getPrototypeOf(value);
  if (
    (isArray && prototype !== Array.prototype)
    || (!isArray
      && prototype !== Object.prototype
      && prototype !== null)
  ) {
    throw new Error("assessment decision must contain plain data objects");
  }
  let arrayLength: number | null = null;
  if (isArray) {
    const lengthDescriptor = Reflect.getOwnPropertyDescriptor(value, "length");
    const length = lengthDescriptor?.value;
    const limit = arrayLimit(path);
    if (
      typeof length !== "number"
      || !Number.isSafeInteger(length)
      || length < 0
      || length > limit.maximum
    ) {
      const formatted = limit.maximum.toLocaleString("en-US");
      throw new Error(
        `${limit.label} exceeds the explicit ${formatted}-entry limit`,
      );
    }
    arrayLength = length as number;
    if (path[path.length - 1] === "replay") {
      state.replayRows += arrayLength;
      if (
        state.replayRows > MAX_ASSESSMENT_DECISION_REPLAY_ROWS
      ) {
        throw new Error(
          "assessment decision exceeds the explicit "
          + `${MAX_ASSESSMENT_DECISION_REPLAY_ROWS.toLocaleString("en-US")}`
          + "-row total replay limit",
        );
      }
    }
  }
  const ownKeys = Reflect.ownKeys(value);
  if (ownKeys.some((key) => typeof key !== "string")) {
    throw new Error("assessment decision cannot contain symbol properties");
  }
  if (!isArray && ownKeys.length > MAX_OBJECT_KEYS) {
    throw new Error("assessment decision object exceeds the key limit");
  }
  for (const key of ownKeys as string[]) {
    if (
      key.length > MAX_PROPERTY_KEY_LENGTH
      || !hasWellFormedUnicode(key)
    ) {
      throw new Error("assessment decision property key is invalid");
    }
  }

  const descriptors = new Map<string, PropertyDescriptor>();
  for (const key of ownKeys as string[]) {
    const descriptor = Reflect.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined) {
      throw new Error("assessment decision changed during snapshot");
    }
    descriptors.set(key, descriptor);
  }

  state.ancestors.add(value);
  try {
    if (isArray) {
      const length = arrayLength!;
      const allowedKeys = new Set<string>(["length"]);
      const snapshot: unknown[] = new Array(length);
      for (let index = 0; index < length; index += 1) {
        const key = String(index);
        allowedKeys.add(key);
        const descriptor = descriptors.get(key);
        if (
          descriptor === undefined
          || !Object.hasOwn(descriptor, "value")
        ) {
          throw new Error(
            "assessment decision arrays must be dense data arrays",
          );
        }
        snapshot[index] = snapshotValue(
          descriptor.value,
          [...path, index],
          depth + 1,
          state,
        );
      }
      if (
        (ownKeys as string[]).some((key) => !allowedKeys.has(key))
      ) {
        throw new Error(
          "assessment decision arrays cannot contain extra properties",
        );
      }
      return snapshot;
    }

    const snapshot = Object.create(null) as Record<string, unknown>;
    for (const key of ownKeys as string[]) {
      const descriptor = descriptors.get(key);
      if (
        descriptor === undefined
        || !Object.hasOwn(descriptor, "value")
        || descriptor.enumerable !== true
      ) {
        throw new Error(
          "assessment decision objects must contain enumerable data properties",
        );
      }
      snapshot[key] = snapshotValue(
        descriptor.value,
        [...path, key],
        depth + 1,
        state,
      );
    }
    return snapshot;
  } finally {
    state.ancestors.delete(value);
  }
}

function snapshotAssessmentDecision(input: unknown): unknown {
  return snapshotValue(input, [], 0, {
    nodes: 0,
    replayRows: 0,
    ancestors: new Set<object>(),
  });
}

const boundedTextSchema = z.string()
  .min(1)
  .max(512)
  .refine(
    (value) => value === value.trim(),
    "must not contain leading or trailing whitespace",
  );
const finiteNumberSchema = z.number().finite();
const nonNegativeFiniteSchema = finiteNumberSchema.nonnegative();
const safeNonNegativeIntegerSchema = z.number()
  .int()
  .min(0)
  .max(Number.MAX_SAFE_INTEGER);
const safePositiveIntegerSchema = safeNonNegativeIntegerSchema.min(1);
const probabilitySchema = finiteNumberSchema.min(0).max(1);
const evidenceClassSchema = z.enum([
  "measured",
  "reported",
  "modeled",
  "unavailable",
]);

const evidenceClassRank = {
  measured: 0,
  reported: 1,
  modeled: 2,
  unavailable: 3,
} as const;

const policyBundleContractSchema: z.ZodType<
  PolicyBundle,
  z.ZodTypeDef,
  unknown
> = z.unknown()
  .transform((value, context) => {
    try {
      return parsePolicyBundleValue(value);
    } catch (error) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        message: error instanceof Error
          ? error.message
          : "invalid policy bundle",
      });
      return z.NEVER;
    }
  });

const assessmentMetricSchema = z.object({
  value: finiteNumberSchema.nullable(),
  evidenceClass: evidenceClassSchema,
  sourceDigest: contractDigestSchema.optional(),
  reason: boundedTextSchema.optional(),
}).strict().superRefine((metric, context) => {
  if (
    (metric.value === null) !== (metric.evidenceClass === "unavailable")
  ) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      message: "unavailable metrics must have null values and only unavailable metrics may be null",
    });
  }
});

const assessmentMetricsSchema = z.object({
  meanScore: assessmentMetricSchema,
  failureRate: assessmentMetricSchema,
  ttftMs: assessmentMetricSchema,
  endToEndLatencyMs: assessmentMetricSchema,
  costPerThousandRequestsUsd: assessmentMetricSchema,
  evidenceCoverage: assessmentMetricSchema,
  serviceCapacity: assessmentMetricSchema,
}).strict().superRefine((metrics, context) => {
  for (const field of ["meanScore", "failureRate", "evidenceCoverage"] as const) {
    const value = metrics[field].value;
    if (value !== null && (value < 0 || value > 1)) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: [field, "value"],
        message: "must be between zero and one",
      });
    }
  }
  for (
    const field of [
      "ttftMs",
      "endToEndLatencyMs",
      "costPerThousandRequestsUsd",
      "serviceCapacity",
    ] as const
  ) {
    const value = metrics[field].value;
    if (value !== null && value < 0) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: [field, "value"],
        message: "must be non-negative",
      });
    }
  }
});

const assessmentGateSchema = z.object({
  id: boundedTextSchema,
  operator: z.enum([">=", "<="]),
  threshold: finiteNumberSchema,
  actual: finiteNumberSchema.nullable(),
  evidenceClass: evidenceClassSchema,
  passed: z.boolean(),
  reason: boundedTextSchema.optional(),
}).strict().superRefine((gate, context) => {
  if ((gate.actual === null) !== (gate.evidenceClass === "unavailable")) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      message: "gate actual and evidence class are inconsistent",
    });
    return;
  }
  const expected = gate.actual !== null
    && (gate.operator === ">="
      ? gate.actual >= gate.threshold
      : gate.actual <= gate.threshold);
  if (gate.passed !== expected) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      path: ["passed"],
      message: "gate result does not match its operator, threshold, and actual value",
    });
  }
});

const replayRowSchema = z.object({
  caseId: boundedTextSchema,
  replicateId: boundedTextSchema,
  groupId: boundedTextSchema,
  attemptedProfileIds: z.array(contractSlugSchema)
    .min(1)
    .max(MAX_ATTEMPTS),
  selectedProfileId: contractSlugSchema,
  status: z.enum(["success", "failure"]),
  escalated: z.boolean(),
  score: finiteNumberSchema.nullable(),
  scoreEvidenceClass: evidenceClassSchema,
  trafficWeight: nonNegativeFiniteSchema.gt(0),
  slices: z.array(contractSlugSchema).max(MAX_SLICES),
  ttftMs: nonNegativeFiniteSchema,
  endToEndLatencyMs: nonNegativeFiniteSchema,
  costUsd: nonNegativeFiniteSchema.nullable(),
}).strict().superRefine((row, context) => {
  if (
    row.attemptedProfileIds[row.attemptedProfileIds.length - 1]
      !== row.selectedProfileId
  ) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      path: ["selectedProfileId"],
      message: "selected profile must be the terminal attempted profile",
    });
  }
  if (row.escalated !== (row.attemptedProfileIds.length > 1)) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      path: ["escalated"],
      message: "escalation must match attempted-profile cardinality",
    });
  }
  if (new Set(row.attemptedProfileIds).size !== row.attemptedProfileIds.length) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      path: ["attemptedProfileIds"],
      message: "attempted profiles must be unique",
    });
  }
  if (new Set(row.slices).size !== row.slices.length) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      path: ["slices"],
      message: "slices must be unique",
    });
  }
  if (row.ttftMs > row.endToEndLatencyMs) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      path: ["ttftMs"],
      message: "TTFT cannot exceed end-to-end latency",
    });
  }
  if (
    row.status === "failure"
    && row.score !== 0
    && !(row.score === null && row.scoreEvidenceClass === "unavailable")
  ) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      path: ["score"],
      message:
        "known terminal failures must retain score zero; ambiguous failures "
        + "must remain unavailable",
    });
  }
  if (
    row.status === "failure"
    && row.score === 0
    && row.scoreEvidenceClass !== "modeled"
  ) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      path: ["scoreEvidenceClass"],
      message: "known failure-zero scores must be classified as modeled",
    });
  }
  if (
    row.score === null
    && row.scoreEvidenceClass !== "unavailable"
  ) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      path: ["scoreEvidenceClass"],
      message: "missing replay score must have unavailable evidence",
    });
  }
  if (
    row.score !== null
    && row.scoreEvidenceClass === "unavailable"
  ) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      path: ["scoreEvidenceClass"],
      message: "available replay score cannot have unavailable evidence",
    });
  }
});

const inferenceSchema = z.object({
  method: z.literal("paired-group-percentile-v1"),
  alpha: finiteNumberSchema.gt(0).lt(1),
  caseCount: safePositiveIntegerSchema,
  replicateCount: safePositiveIntegerSchema,
  groupCount: safePositiveIntegerSchema,
  effectiveTrafficMass: nonNegativeFiniteSchema.gt(0),
  estimate: finiteNumberSchema,
  interval: z.object({
    lo: finiteNumberSchema,
    hi: finiteNumberSchema,
  }).strict(),
  iterations: safePositiveIntegerSchema.max(1_000_000),
  seed: safeNonNegativeIntegerSchema.max(0xffff_ffff),
  positive: z.boolean(),
}).strict().superRefine((inference, context) => {
  if (
    inference.groupCount > inference.caseCount
    || inference.caseCount > inference.replicateCount
  ) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      message: "inference group, case, and replicate counts are inconsistent",
    });
  }
  if (inference.interval.lo > inference.interval.hi) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      path: ["interval"],
      message: "inference interval lower bound cannot exceed its upper bound",
    });
  }
  if (inference.positive !== (inference.interval.lo > 0)) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      path: ["positive"],
      message: "positive must reflect whether the lower interval bound is positive",
    });
  }
});

const criticalSliceCoverageSchema = z.object({
  sliceId: contractSlugSchema,
  groupCount: safeNonNegativeIntegerSchema,
}).strict();

const assessmentCoverageSchema = z.object({
  caseCount: safeNonNegativeIntegerSchema,
  replicateCount: safeNonNegativeIntegerSchema,
  groupCount: safeNonNegativeIntegerSchema,
  effectiveTrafficMass: nonNegativeFiniteSchema,
  criticalSliceGroups: z.array(criticalSliceCoverageSchema)
    .max(MAX_CRITICAL_SLICES),
  failureCount: safeNonNegativeIntegerSchema,
  missingEvidenceCount: safeNonNegativeIntegerSchema,
  evidenceCoverage: probabilitySchema,
}).strict().superRefine((coverage, context) => {
  if (
    coverage.groupCount > coverage.caseCount
    || coverage.caseCount > coverage.replicateCount
  ) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      message: "coverage group, case, and replicate counts are inconsistent",
    });
  }
  const slices = new Set<string>();
  for (
    let index = 0;
    index < coverage.criticalSliceGroups.length;
    index += 1
  ) {
    const slice = coverage.criticalSliceGroups[index];
    if (slice.groupCount > coverage.groupCount) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["criticalSliceGroups", index, "groupCount"],
        message: "critical-slice groups cannot exceed total groups",
      });
    }
    if (slices.has(slice.sliceId)) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["criticalSliceGroups", index, "sliceId"],
        message: "critical-slice coverage entries must be unique",
      });
    }
    slices.add(slice.sliceId);
  }
});

const candidateAssessmentSchema = z.object({
  policy: policyBundleContractSchema,
  policyDigest: contractDigestSchema,
  status: z.enum([
    "PASS",
    "HOLD",
    "INSUFFICIENT_EVIDENCE",
    "STALE",
  ]),
  replay: z.array(replayRowSchema)
    .max(MAX_ASSESSMENT_DECISION_REPLAY_ROWS),
  metrics: assessmentMetricsSchema,
  gates: z.array(assessmentGateSchema).max(MAX_GATES),
  inference: inferenceSchema.nullable(),
  coverage: assessmentCoverageSchema,
  insufficiencyReasons: z.array(boundedTextSchema)
    .max(MAX_REASON_ENTRIES),
  rejectionReasons: z.array(boundedTextSchema)
    .max(MAX_REASON_ENTRIES),
}).strict().superRefine((candidate, context) => {
  if (candidate.policyDigest !== candidate.policy.policyDigest) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      path: ["policyDigest"],
      message: "candidate policy digest does not match its policy bundle",
    });
  }
  const allReplayScoresAvailable = candidate.replay.every(
    ({ score }) => score !== null,
  );
  const expectedMeanScoreClass = candidate.replay.length === 0
    || !allReplayScoresAvailable
    ? "unavailable"
    : candidate.replay.reduce<z.infer<typeof evidenceClassSchema>>(
      (weakest, row) =>
        evidenceClassRank[row.scoreEvidenceClass]
          > evidenceClassRank[weakest]
          ? row.scoreEvidenceClass
          : weakest,
      "measured",
    );
  if (
    candidate.metrics.meanScore.evidenceClass !== expectedMeanScoreClass
  ) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      path: ["metrics", "meanScore", "evidenceClass"],
      message: "mean-score provenance must match replay score provenance",
    });
  }
  if (candidate.inference !== null) {
    for (
      const field of [
        "caseCount",
        "replicateCount",
        "groupCount",
        "effectiveTrafficMass",
      ] as const
    ) {
      if (candidate.inference[field] !== candidate.coverage[field]) {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["coverage", field],
          message: "coverage must match the reported inference population",
        });
      }
    }
  }
  if (
    candidate.metrics.evidenceCoverage.value !== null
    && candidate.metrics.evidenceCoverage.value
      !== candidate.coverage.evidenceCoverage
  ) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      path: ["coverage", "evidenceCoverage"],
      message: "coverage must match the evidence-coverage metric",
    });
  }
  const failedGates = candidate.gates.filter(({ passed }) => !passed);
  const expectedRejectionReasons = [
    ...candidate.insufficiencyReasons,
    ...failedGates.map(({ id }) => `failed-gate:${id}`),
  ].sort();
  if (
    candidate.status !== "STALE"
    && (
      candidate.rejectionReasons.length !== expectedRejectionReasons.length
      || candidate.rejectionReasons.some(
        (reason, index) => reason !== expectedRejectionReasons[index],
      )
    )
  ) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      path: ["rejectionReasons"],
      message: "candidate rejection reasons do not match insufficiency and failed gates",
    });
  }
  if (
    candidate.status === "PASS"
    && (
      candidate.insufficiencyReasons.length !== 0
      || failedGates.length !== 0
      || candidate.inference === null
    )
  ) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      path: ["status"],
      message: "PASS candidate must have inference, no insufficiency, and no failed gate",
    });
  }
  if (
    candidate.status === "HOLD"
    && (
      candidate.insufficiencyReasons.length !== 0
      || failedGates.length === 0
      || candidate.inference === null
    )
  ) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      path: ["status"],
      message: "HOLD candidate must have inference and at least one failed gate",
    });
  }
  if (
    candidate.status === "INSUFFICIENT_EVIDENCE"
    && (
      candidate.insufficiencyReasons.length === 0
      || candidate.inference !== null
    )
  ) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      path: ["status"],
      message: "INSUFFICIENT_EVIDENCE candidate requires reasons and no inference",
    });
  }
  if (
    candidate.status === "STALE"
    && (
      candidate.replay.length !== 0
      || candidate.gates.length !== 0
      || candidate.inference !== null
      || candidate.insufficiencyReasons.length !== 0
      || candidate.rejectionReasons.length === 0
      || Object.values(candidate.metrics).some(
        ({ evidenceClass }) => evidenceClass !== "unavailable",
      )
    )
  ) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      path: ["status"],
      message: "STALE candidate must contain only unavailable pre-inference results",
    });
  }
});

const estimatorSchema = z.object({
  method: z.literal("paired-group-percentile-v1"),
  alpha: finiteNumberSchema.gt(0).lt(1),
  iterations: safePositiveIntegerSchema.max(1_000_000),
  seed: safeNonNegativeIntegerSchema.max(0xffff_ffff),
}).strict();

const unavailableMetricNameSchema = z.enum([
  "meanScore",
  "failureRate",
  "ttftMs",
  "endToEndLatencyMs",
  "costPerThousandRequestsUsd",
  "evidenceCoverage",
  "serviceCapacity",
]);

const assessmentDecisionBodySchema = z.object({
  version: z.literal("tasc-assessment-decision-v2"),
  engineVersion: z.literal("tasc-assessment-engine-v2"),
  phase: z.enum(["development", "holdout", "window"]),
  status: z.enum([
    "INSUFFICIENT_EVIDENCE",
    "NO_CANDIDATE",
    "NOMINATED",
    "PASS",
    "HOLD",
    "STALE",
  ]),
  assessmentContextDigest: contractDigestSchema,
  protocolDigest: contractDigestSchema,
  datasetDigest: contractDigestSchema,
  traceSetDigest: contractDigestSchema,
  evaluatorSetDigest: contractDigestSchema,
  windowManifestDigest: contractDigestSchema.nullable(),
  estimator: estimatorSchema,
  control: candidateAssessmentSchema,
  candidates: z.array(candidateAssessmentSchema)
    .min(1)
    .max(MAX_CANDIDATES),
  selectedPolicy: policyBundleContractSchema.nullable(),
  selectedPolicyDigest: contractDigestSchema.nullable(),
  staleReasons: z.array(boundedTextSchema).max(MAX_REASON_ENTRIES),
  warnings: z.array(boundedTextSchema).max(MAX_REASON_ENTRIES),
  unavailableMetrics: z.array(unavailableMetricNameSchema)
    .max(MAX_REASON_ENTRIES),
  attestation: z.literal("unattested"),
}).strict();

const assessmentDecisionSchema = assessmentDecisionBodySchema.extend({
  decisionDigest: contractDigestSchema,
}).strict();

type MutableAssessmentDecisionBody = z.infer<
  typeof assessmentDecisionBodySchema
>;
type MutableAssessmentDecision = z.infer<
  typeof assessmentDecisionSchema
>;

type AssessmentDecisionContract = DeepReadonly<AssessmentDecision>;

function sameEstimator(
  estimator: MutableAssessmentDecisionBody["estimator"],
  inference: NonNullable<
    MutableAssessmentDecisionBody["candidates"][number]["inference"]
  >,
): boolean {
  return (
    estimator.method === inference.method
    && estimator.alpha === inference.alpha
    && estimator.iterations === inference.iterations
    && estimator.seed === inference.seed
  );
}

function assertDecisionSemantics(
  decision: MutableAssessmentDecisionBody,
): void {
  const allAssessments = [decision.control, ...decision.candidates];
  for (const [index, candidate] of allAssessments.entries()) {
    if (candidate.policy.protocolDigest !== decision.protocolDigest) {
      throw new Error(
        `${index === 0 ? "control" : "candidate"} policy protocol digest mismatch`,
      );
    }
    if (
      candidate.inference !== null
      && !sameEstimator(decision.estimator, candidate.inference)
    ) {
      throw new Error(
        `${index === 0 ? "control" : "candidate"} inference estimator mismatch`,
      );
    }
  }
  if (decision.control.policy.kind !== "expert-only") {
    throw new Error("assessment control must use an expert-only policy");
  }
  if (
    decision.phase !== "development"
    && decision.candidates.length !== 1
  ) {
    throw new Error(
      `${decision.phase} assessment requires exactly one candidate`,
    );
  }
  const candidateDigests = decision.candidates.map(
    ({ policyDigest }) => policyDigest,
  );
  if (new Set(candidateDigests).size !== candidateDigests.length) {
    throw new Error("assessment candidates must have unique policy digests");
  }
  const sortedCandidateDigests = [...candidateDigests].sort();
  if (candidateDigests.some(
    (digest, index) => digest !== sortedCandidateDigests[index],
  )) {
    throw new Error("assessment candidates must use canonical digest order");
  }
  const derivedUnavailableMetrics = [...new Set(
    decision.candidates.flatMap(({ metrics }) =>
      Object.entries(metrics)
        .filter(([, metric]) => metric.evidenceClass === "unavailable")
        .map(([name]) => name)
    ),
  )].sort();
  if (
    decision.unavailableMetrics.length !== derivedUnavailableMetrics.length
    || decision.unavailableMetrics.some(
      (name, index) => name !== derivedUnavailableMetrics[index],
    )
  ) {
    throw new Error(
      "top-level unavailable metric summary does not match candidates",
    );
  }

  const hasPolicy = decision.selectedPolicy !== null;
  const hasDigest = decision.selectedPolicyDigest !== null;
  if (hasPolicy !== hasDigest) {
    throw new Error(
      "selected policy and selected policy digest must both be present or absent",
    );
  }
  if (
    decision.selectedPolicy !== null
    && (
      decision.selectedPolicy.policyDigest
        !== decision.selectedPolicyDigest
      || decision.selectedPolicy.protocolDigest
        !== decision.protocolDigest
    )
  ) {
    throw new Error("selected policy digest or protocol binding is inconsistent");
  }

  if (decision.phase === "window") {
    if (decision.windowManifestDigest === null) {
      throw new Error("window assessment requires a window manifest digest");
    }
  } else if (decision.windowManifestDigest !== null) {
    throw new Error(
      "window manifest digest is allowed only for window assessments",
    );
  }

  if (decision.phase === "development") {
    if (
      ![
        "NOMINATED",
        "NO_CANDIDATE",
        "INSUFFICIENT_EVIDENCE",
        "STALE",
      ].includes(decision.status)
    ) {
      throw new Error("development decision has an invalid phase status");
    }
    if (decision.status === "NOMINATED") {
      if (
        decision.selectedPolicy === null
        || decision.selectedPolicyDigest === null
      ) {
        throw new Error(
          "development NOMINATED decision requires a selection",
        );
      }
      const selected = decision.candidates.find(
        ({ policyDigest }) =>
          policyDigest === decision.selectedPolicyDigest,
      );
      if (selected === undefined) {
        throw new Error(
          "development nomination must select a reported candidate",
        );
      }
      if (selected.status !== "PASS") {
        throw new Error(
          "development nomination must select a passing candidate",
        );
      }
    } else if (decision.selectedPolicy !== null) {
      throw new Error(
        `${decision.status} development decision cannot contain a selection`,
      );
    }
    if (
      decision.status === "NO_CANDIDATE"
      && (
        decision.candidates.some(({ status }) => status === "PASS")
        || !decision.candidates.some(({ status }) => status === "HOLD")
      )
    ) {
      throw new Error(
        "development candidate status is inconsistent: NO_CANDIDATE "
        + "requires no PASS candidates and at least one HOLD candidate",
      );
    }
    if (
      decision.status === "INSUFFICIENT_EVIDENCE"
      && !decision.candidates.every(
        ({ status }) => status === "INSUFFICIENT_EVIDENCE",
      )
    ) {
      throw new Error(
        "development candidate status is inconsistent: "
        + "INSUFFICIENT_EVIDENCE requires every candidate to be "
        + "INSUFFICIENT_EVIDENCE",
      );
    }
  } else {
    if (
      ![
        "PASS",
        "HOLD",
        "INSUFFICIENT_EVIDENCE",
        "STALE",
      ].includes(decision.status)
    ) {
      throw new Error(`${decision.phase} decision has an invalid phase status`);
    }
    if (
      decision.selectedPolicy === null
      || decision.selectedPolicyDigest === null
    ) {
      throw new Error(
        `${decision.phase} assessment must preserve its frozen policy`,
      );
    }
    const candidate = decision.candidates[0];
    if (candidate.policyDigest !== decision.selectedPolicyDigest) {
      throw new Error(
        `${decision.phase} selected policy must match its sole candidate`,
      );
    }
    if (candidate.status !== decision.status) {
      throw new Error(
        `${decision.phase} top-level and candidate status must agree`,
      );
    }
  }

  if (decision.status === "STALE") {
    if (decision.staleReasons.length === 0) {
      throw new Error("STALE decision requires at least one stale reason");
    }
    for (const assessment of allAssessments) {
      if (
        assessment.status !== "STALE"
        || assessment.rejectionReasons.length
          !== decision.staleReasons.length
        || assessment.rejectionReasons.some(
          (reason, index) => reason !== decision.staleReasons[index],
        )
      ) {
        throw new Error(
          "STALE decision requires matching STALE candidate results",
        );
      }
    }
  } else if (decision.staleReasons.length !== 0) {
    throw new Error("non-STALE decision cannot contain stale reasons");
  } else if (allAssessments.some(({ status }) => status === "STALE")) {
    throw new Error("non-STALE decision cannot contain a STALE candidate");
  }
}

function parseDecisionBodySnapshot(
  input: unknown,
): MutableAssessmentDecisionBody {
  const body = assessmentDecisionBodySchema.parse(input);
  assertDecisionSemantics(body);
  return body;
}

/**
 * Compute the canonical decision identity from a strict body. A caller may
 * pass a complete decision; its supplied self-digest is omitted from the
 * canonical preimage.
 */
export function fingerprintAssessmentDecisionContract(
  input: unknown,
): string {
  const snapshot = snapshotAssessmentDecision(input);
  if (
    snapshot !== null
    && typeof snapshot === "object"
    && !Array.isArray(snapshot)
    && Object.hasOwn(snapshot, "decisionDigest")
  ) {
    const {
      decisionDigest: _decisionDigest,
      ...bodyInput
    } = snapshot as Record<string, unknown>;
    const body = parseDecisionBodySnapshot(bodyInput);
    return domainSeparatedDigest(ASSESSMENT_DECISION_DOMAIN, body);
  }
  const body = parseDecisionBodySnapshot(snapshot);
  return domainSeparatedDigest(ASSESSMENT_DECISION_DOMAIN, body);
}

/**
 * Read once, validate exact v2 shape and phase invariants, verify the
 * domain-separated self-digest, and return an immutable owned decision.
 */
export function parseAssessmentDecisionContract(
  input: unknown,
): AssessmentDecisionContract {
  const snapshot = snapshotAssessmentDecision(input);
  const decision = assessmentDecisionSchema.parse(snapshot);
  const {
    decisionDigest,
    ...body
  } = decision;
  assertDecisionSemantics(body);
  const expected = domainSeparatedDigest(
    ASSESSMENT_DECISION_DOMAIN,
    body,
  );
  if (decisionDigest !== expected) {
    throw new Error("assessment decision digest mismatch");
  }
  return deepFreezeContract(decision) as AssessmentDecisionContract;
}
