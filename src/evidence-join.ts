import { Buffer } from "node:buffer";
import { canonicalJson, compareCodeUnits } from "./determinism.js";
import {
  compareEvidenceIdentities,
  contractSlugSchema,
  deepFreezeContract,
  domainSeparatedDigest,
  fingerprintExecutionProfile,
  fingerprintNormalizedProtocol,
  normalizeExperimentProtocol,
  parseTraceEnvelope,
  verifyTraceDispatchIntent,
  type DeepReadonly,
  type EvaluatorEvidence,
  type ExperimentProtocol,
  type TraceEnvelope,
} from "./evidence.js";
import {
  isAuthenticEvaluatorEvidenceVerification,
  type EvaluatorEvidenceVerification,
  type EvaluatorTrustStatus,
} from "./evaluator-trust.js";
import type { WorkBudget } from "./work-budget.js";

export type OfflineAssessmentSplit = "dev" | "holdout";
export type AssessmentSplit = OfflineAssessmentSplit | "online";

export interface ResolvedGroupSplit {
  readonly algorithm: "tasc-seeded-sha256-group-bucket-v1";
  readonly bucket: number;
  readonly split: OfflineAssessmentSplit;
}

interface ScoredAssessmentOutcome {
  readonly kind: "scored";
  readonly score: number;
  readonly range: {
    readonly minimum: number;
    readonly maximum: number;
  };
  readonly evidenceDigest: string;
  readonly evidence: EvaluatorEvidence;
  readonly verification: EvidenceVerificationProvenance;
  readonly evidenceAccepted: true;
}

interface ProtocolFailureOutcome {
  readonly kind: "protocol-failure-zero";
  readonly score: 0;
  readonly evidence: null;
}

interface AmbiguousExecutionOutcome {
  readonly kind: "ambiguous-execution";
  readonly reasonCode: "dispatch-outcome-ambiguous";
  readonly score: null;
  readonly evidence: null;
}

interface NonScoredAssessmentOutcome {
  readonly kind: "missing-evidence" | "invalid-evidence" | "abstained";
  readonly reasonCode: string;
  readonly evidenceDigest: string | null;
  readonly evidence: EvaluatorEvidence | null;
  readonly verification: EvidenceVerificationProvenance | null;
  readonly evidenceAccepted: boolean;
}

export type AssessmentExecutionOutcome =
  | ScoredAssessmentOutcome
  | ProtocolFailureOutcome
  | AmbiguousExecutionOutcome
  | NonScoredAssessmentOutcome;

export interface AssessmentExecutionRow {
  readonly executionKey: string;
  readonly traceId: string;
  readonly caseId: string;
  readonly replicateId: string;
  readonly groupId: string;
  readonly profileId: string;
  readonly split: AssessmentSplit;
  readonly splitBucket: number | null;
  readonly terminalStatus: "success" | "failure" | "aborted";
  readonly outcome: AssessmentExecutionOutcome;
  readonly trace: TraceEnvelope;
}

export interface AssessmentPair {
  readonly pairKey: string;
  readonly caseId: string;
  readonly replicateId: string;
  readonly groupId: string;
  readonly split: AssessmentSplit;
  readonly declaredTrafficWeight: number;
  readonly slices: readonly string[];
  readonly profileIds: readonly string[];
  readonly executionKeys: readonly string[];
}

export interface EvidenceVerificationProvenance {
  readonly authentic: boolean;
  readonly status: EvaluatorTrustStatus | "inauthentic";
  readonly trusted: boolean;
  readonly reason: string;
  readonly keyId: string | null;
  readonly assessedAt: string | null;
  readonly assessmentContextDigest: string | null;
  readonly operatorTrustPolicySnapshotDigest: string | null;
  readonly evaluatorRevocationSnapshotDigest: string | null;
}

export interface DiagnosticEvidenceRow {
  readonly evidence: EvaluatorEvidence;
  readonly evidenceDigest: string;
  readonly verification: EvidenceVerificationProvenance;
}

export interface EvidenceDiagnostic {
  readonly evidenceDigest: string | null;
  readonly evidence: EvaluatorEvidence | null;
  readonly verification: EvidenceVerificationProvenance;
  readonly traceId: string | null;
  readonly profileId: string | null;
  readonly reason: string;
}

export interface MissingEvidenceDiagnostic {
  readonly executionKey: string;
  readonly traceId: string;
  readonly profileId: string;
  readonly reason: string;
  readonly evidenceDigest?: string;
}

export interface AbstainedEvidenceDiagnostic {
  readonly executionKey: string;
  readonly evidenceDigest: string;
  readonly reasonCode: string;
}

export interface DuplicateEvidenceDiagnostic {
  readonly joinKey: string;
  readonly evidenceDigest: string;
  readonly occurrences: number;
  readonly row: DiagnosticEvidenceRow;
}

export interface ConflictingEvidenceDiagnostic {
  readonly joinKey: string;
  readonly evidenceDigests: readonly string[];
  readonly rows: readonly DiagnosticEvidenceRow[];
  readonly reason: string;
}

export interface DuplicateTraceDiagnostic {
  readonly traceDigest: string;
  readonly traceId: string;
  readonly occurrences: number;
}

export interface ConflictingTraceDiagnostic {
  readonly authoritativeKey: string;
  readonly traceDigests: readonly string[];
  readonly reason: string;
}

export interface MissingProfileDiagnostic {
  readonly caseId: string;
  readonly replicateId: string;
  readonly missingProfileIds: readonly string[];
}

export interface AssessmentDataset {
  readonly version: "tasc-assessment-dataset-v2";
  readonly studyId: string;
  readonly protocolDigest: string;
  readonly assessmentContextDigest: string | null;
  readonly traceSetDigest: string;
  readonly evaluatorSetDigest: string;
  readonly datasetDigest: string;
  readonly splitIdentity: ExperimentProtocol["splitMembership"];
  readonly evaluatorIdentity: ExperimentProtocol["evaluator"];
  readonly requiredProfileIds: readonly string[];
  readonly verificationContextIdentities: readonly string[];
  readonly executions: readonly AssessmentExecutionRow[];
  readonly pairs: readonly AssessmentPair[];
  readonly work: AssessmentJoinWork;
  readonly counts: {
    readonly traceRows: number;
    readonly acceptedTraceRows: number;
    readonly evidenceRows: number;
    readonly matchedRows: number;
    readonly scoredRows: number;
    readonly pairedCaseReplicates: number;
    readonly cases: number;
    readonly caseReplicates: number;
    readonly groups: number;
    readonly observedTrafficMass: number;
    readonly splits: readonly {
      readonly split: AssessmentSplit;
      readonly caseReplicates: number;
      readonly groups: number;
      readonly observedTrafficMass: number;
    }[];
    readonly slices: readonly {
      readonly sliceId: string;
      readonly caseReplicates: number;
      readonly groups: number;
    }[];
  };
  readonly diagnostics: {
    readonly missingEvidence: readonly MissingEvidenceDiagnostic[];
    readonly invalidEvidence: readonly EvidenceDiagnostic[];
    readonly abstainedEvidence: readonly AbstainedEvidenceDiagnostic[];
    readonly orphanEvidence: readonly EvidenceDiagnostic[];
    readonly duplicateEvidence: readonly DuplicateEvidenceDiagnostic[];
    readonly conflictingEvidence: readonly ConflictingEvidenceDiagnostic[];
    readonly duplicateTraces: readonly DuplicateTraceDiagnostic[];
    readonly conflictingTraces: readonly ConflictingTraceDiagnostic[];
    readonly missingProfileExecutions: readonly MissingProfileDiagnostic[];
  };
  readonly admissibility: {
    readonly valid: boolean;
    readonly blockingReasons: readonly string[];
  };
}

type ExecutionForSplit<Split extends AssessmentSplit> = Omit<
  AssessmentExecutionRow,
  "split"
> & {
  readonly split: Split;
};

type PairForSplit<Split extends AssessmentSplit> = Omit<
  AssessmentPair,
  "split"
> & {
  readonly split: Split;
};

type CountsForSplit<Split extends AssessmentSplit> = Omit<
  AssessmentDataset["counts"],
  "splits"
> & {
  readonly splits: readonly (
    Omit<AssessmentDataset["counts"]["splits"][number], "split">
    & { readonly split: Split }
  )[];
};

/** A runtime-authenticated dataset whose complete row population has one phase. */
export type AssessmentDatasetForSplit<Split extends AssessmentSplit> = Omit<
  AssessmentDataset,
  "executions" | "pairs" | "counts"
> & {
  readonly executions: readonly ExecutionForSplit<Split>[];
  readonly pairs: readonly PairForSplit<Split>[];
  readonly counts: CountsForSplit<Split>;
};

export type DevelopmentAssessmentDataset =
  AssessmentDatasetForSplit<"dev">;
export type HoldoutAssessmentDataset =
  AssessmentDatasetForSplit<"holdout">;
export type OnlineAssessmentDataset =
  AssessmentDatasetForSplit<"online">;

export interface AssessmentJoinWork {
  /** Observed input and cardinality dimensions. */
  readonly traceRows: number;
  readonly evidenceRows: number;
  readonly independentGroups: number;
  readonly labelMemberships: number;
  /** Conservative modeled upper bounds used for admission control. */
  readonly hashOperations: number;
  readonly diagnosticRows: number;
  readonly outputRows: number;
  readonly chargedUnits: number;
  /** Observed visits made by the one-pass logical slice aggregation. */
  readonly sliceAggregationVisits: number;
}

interface TraceRecord {
  readonly trace: TraceEnvelope;
  readonly traceDigest: string;
  readonly traceIdentityKey: string;
  readonly traceProfileKey: string;
  readonly logicalProfileKey: string;
  readonly pairKey: string;
  readonly executionKey: string;
  readonly split: AssessmentSplit;
  readonly splitBucket: number | null;
  readonly sortedSlices: readonly string[];
  readonly workloadCanonical: string;
  readonly routeSignalCanonical: string;
}

interface EvidenceRecord {
  readonly evidence: EvaluatorEvidence;
  readonly evidenceDigest: string;
  readonly joinKey: string;
  readonly contextIdentity: string;
  readonly verification: EvidenceVerificationProvenance;
}

interface RejectedEvidenceRecord {
  readonly evidence: EvaluatorEvidence;
  readonly evidenceDigest: string;
  readonly joinKey: string;
  readonly verification: EvidenceVerificationProvenance;
  readonly reason: string;
}

const FAILURE_SCORE = 0 as const;
const authenticAssessmentDatasets = new WeakSet<object>();

function sortStrings(values: readonly string[]): string[] {
  return [...values].sort(compareCodeUnits);
}

function identity(domain: string, value: unknown): string {
  return domainSeparatedDigest(domain, value);
}

function traceIdentityKey(trace: TraceEnvelope): string {
  return identity("tasc/assessment-trace-join-key/v2", {
    protocolDigest: trace.protocolDigest,
    traceId: trace.traceId,
    profileId: trace.profileId,
    terminalOutputId: trace.terminalOutputId,
  });
}

function logicalProfileKey(trace: TraceEnvelope): string {
  return identity("tasc/assessment-logical-profile-key/v2", {
    protocolDigest: trace.protocolDigest,
    caseId: trace.caseId,
    replicateId: trace.replicateId,
    profileId: trace.profileId,
  });
}

function pairKey(trace: TraceEnvelope): string {
  return identity("tasc/assessment-pair-key/v2", {
    protocolDigest: trace.protocolDigest,
    caseId: trace.caseId,
    replicateId: trace.replicateId,
  });
}

function traceProfileKey(
  protocolDigest: string,
  traceId: string,
  profileId: string,
): string {
  return identity("tasc/assessment-trace-profile/v2", {
    protocolDigest,
    traceId,
    profileId,
  });
}

function fingerprintTrace(trace: TraceEnvelope): string {
  return identity("tasc/trace-envelope/v2", trace);
}

function fingerprintVerificationSource(
  input: EvaluatorEvidenceVerification,
): string {
  if (!isAuthenticEvaluatorEvidenceVerification(input)) {
    return identity("tasc/assessment-evaluator-source/v2", {
      kind: "inauthentic-verification-receipt",
    });
  }
  return identity("tasc/assessment-evaluator-source/v2", {
    kind: "authentic-verification-receipt",
    evidenceDigest: input.evidenceDigest,
    status: input.status,
    trusted: input.trusted,
    assessedAt: input.assessedAt,
    assessmentContextDigest: input.assessmentContextDigest,
    operatorTrustPolicySnapshotDigest:
      input.operatorTrustPolicySnapshotDigest,
    evaluatorRevocationSnapshotDigest:
      input.evaluatorRevocationSnapshotDigest,
    keyId: input.keyId,
  });
}

/**
 * Golden preimage:
 * JCS({domain:"tasc/seeded-sha256-group-bucket/v1", value:{
 *   algorithm:"tasc-seeded-sha256-group-bucket-v1", groupId, seed
 * }})
 *
 * The complete SHA-256 value is reduced byte-by-byte with BigInt arithmetic.
 * No rounded IEEE-754 conversion participates in membership.
 */
function resolveNormalizedGroupSplit(
  protocol: ExperimentProtocol,
  groupId: string,
): ResolvedGroupSplit {
  const digest = domainSeparatedDigest(
    "tasc/seeded-sha256-group-bucket/v1",
    {
      algorithm: protocol.splitMembership.algorithm,
      groupId,
      seed: protocol.splitMembership.seed,
    },
  );
  const digestBytes = Buffer.from(digest.slice("sha256:".length), "hex");
  const divisor = BigInt(protocol.splitMembership.bucketCount);
  let remainder = 0n;
  for (const byte of digestBytes) {
    remainder = ((remainder * 256n) + BigInt(byte)) % divisor;
  }
  const bucket = Number(remainder);
  const development = protocol.splitMembership.developmentBuckets.includes(bucket);
  const holdout = protocol.splitMembership.holdoutBuckets.includes(bucket);
  if (development === holdout) {
    throw new Error(`derived split bucket ${bucket} is not in exactly one protocol split`);
  }
  return deepFreezeContract({
    algorithm: protocol.splitMembership.algorithm,
    bucket,
    split: development ? "dev" : "holdout",
  });
}

export function resolveGroupSplit(
  protocol: ExperimentProtocol,
  groupId: string,
): ResolvedGroupSplit {
  return resolveNormalizedGroupSplit(
    normalizeExperimentProtocol(protocol),
    contractSlugSchema.parse(groupId),
  );
}

interface CollectionPreflight<Row> {
  readonly input: readonly Row[];
  readonly label: string;
  readonly length: number;
}

function preflightCollection<Row>(
  value: unknown,
  label: string,
): CollectionPreflight<Row> {
  if (!Array.isArray(value)) throw new Error(`${label} must be an array`);
  const lengthDescriptor = Reflect.getOwnPropertyDescriptor(value, "length");
  if (
    lengthDescriptor === undefined
    || !Object.hasOwn(lengthDescriptor, "value")
  ) {
    throw new Error(`${label} collection length must be a data property`);
  }
  const length = lengthDescriptor.value;
  if (
    typeof length !== "number"
    || !Number.isSafeInteger(length)
    || length < 0
  ) {
    throw new Error(`${label} length must be a safe non-negative integer`);
  }
  return {
    input: value as readonly Row[],
    label,
    length,
  };
}

function snapshotCollection<Row>(
  preflight: CollectionPreflight<Row>,
): readonly Row[] {
  const keys = Reflect.ownKeys(preflight.input);
  const maximumIndexLength = preflight.length === 0
    ? 0
    : String(preflight.length - 1).length;
  for (const key of keys) {
    if (typeof key === "symbol") {
      throw new Error(`${preflight.label} collection cannot contain symbol properties`);
    }
    if (key === "length") continue;
    const index = key.length <= maximumIndexLength ? Number(key) : Number.NaN;
    if (
      !Number.isSafeInteger(index)
      || index < 0
      || index >= preflight.length
      || String(index) !== key
    ) {
      throw new Error(`${preflight.label} collection cannot contain extra properties`);
    }
  }
  if (keys.length !== preflight.length + 1) {
    throw new Error(`${preflight.label} collection cannot contain array holes`);
  }

  const snapshot: Row[] = [];
  for (let index = 0; index < preflight.length; index += 1) {
    const descriptor = Reflect.getOwnPropertyDescriptor(
      preflight.input,
      String(index),
    );
    if (descriptor === undefined) {
      throw new Error(`${preflight.label} collection cannot contain array holes`);
    }
    if (!Object.hasOwn(descriptor, "value")) {
      throw new Error(`${preflight.label} collection element accessors are not allowed`);
    }
    if (!descriptor.enumerable) {
      throw new Error(
        `${preflight.label} collection elements must be enumerable data properties`,
      );
    }
    snapshot.push(descriptor.value as Row);
  }
  return Object.freeze(snapshot);
}

function checkedAdd(left: number, right: number, label: string): number {
  if (
    !Number.isSafeInteger(left)
    || left < 0
    || !Number.isSafeInteger(right)
    || right < 0
    || left > Number.MAX_SAFE_INTEGER - right
  ) {
    throw new Error(`${label} arithmetic overflow`);
  }
  return left + right;
}

function checkedScale(value: number, scale: number, label: string): number {
  if (
    !Number.isSafeInteger(value)
    || value < 0
    || !Number.isSafeInteger(scale)
    || scale < 0
    || (value !== 0 && scale > Number.MAX_SAFE_INTEGER / value)
  ) {
    throw new Error(`${label} arithmetic overflow`);
  }
  return value * scale;
}

function assertJoinLimit(value: number, limit: number, label: string): void {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error(`${label} must be a safe non-negative integer`);
  }
  if (!Number.isSafeInteger(limit) || limit < 0) {
    throw new Error(`${label} budget must be a safe non-negative integer`);
  }
  if (value > limit) {
    throw new Error(`${label} exceeds caller work budget: ${value} > ${limit}`);
  }
}

function estimateJoinWork(
  traceRows: number,
  evidenceRows: number,
  independentGroups: number,
  labelMemberships: number,
  budget: WorkBudget,
): Omit<AssessmentJoinWork, "sliceAggregationVisits"> {
  assertJoinLimit(traceRows, budget.maxTraceRows, "trace rows");
  assertJoinLimit(evidenceRows, budget.maxEvidenceRows, "evidence rows");
  assertJoinLimit(
    independentGroups,
    budget.maxIndependentGroups,
    "independent groups",
  );
  assertJoinLimit(0, budget.maxAssessmentWork, "join work");
  if (!Number.isSafeInteger(labelMemberships) || labelMemberships < 0) {
    throw new Error("label memberships must be a safe non-negative integer");
  }
  const hashOperations = checkedAdd(
    checkedScale(traceRows, 6, "join hash work"),
    checkedScale(evidenceRows, 4, "join hash work"),
    "join hash work",
  );
  const diagnosticRows = checkedAdd(
    checkedScale(traceRows, 2, "join diagnostic work"),
    evidenceRows,
    "join diagnostic work",
  );
  const outputRows = [
    checkedScale(traceRows, 5, "join output work"),
    checkedScale(evidenceRows, 2, "join output work"),
    labelMemberships,
    3,
  ].reduce((total, value) => checkedAdd(total, value, "join output work"), 0);
  const chargedUnits = [
    traceRows,
    evidenceRows,
    independentGroups,
    labelMemberships,
    hashOperations,
    diagnosticRows,
    outputRows,
  ].reduce((total, value) => checkedAdd(total, value, "join work"), 0);
  if (chargedUnits > budget.maxAssessmentWork) {
    throw new Error(
      `join work exceeds caller work budget: ${chargedUnits} > ${budget.maxAssessmentWork}`,
    );
  }
  return {
    traceRows,
    evidenceRows,
    independentGroups,
    labelMemberships,
    hashOperations,
    diagnosticRows,
    outputRows,
    chargedUnits,
  };
}

function distinctGroupCount(
  traces: readonly TraceEnvelope[],
  budget: WorkBudget,
): number {
  const groups = new Set<string>();
  for (const trace of traces) {
    groups.add(trace.groupId);
    if (groups.size > budget.maxIndependentGroups) {
      throw new Error(
        `independent groups exceeds caller work budget: ${groups.size} > ${budget.maxIndependentGroups}`,
      );
    }
  }
  return groups.size;
}

function normalizeTraces(
  protocol: ExperimentProtocol,
  protocolDigest: string,
  inputs: readonly TraceEnvelope[],
  budget: WorkBudget,
  evidenceRows: number,
): {
  readonly traces: TraceEnvelope[];
  readonly work: Omit<AssessmentJoinWork, "sliceAggregationVisits">;
  readonly splitsByGroup: ReadonlyMap<string, ResolvedGroupSplit>;
} {
  const traces = inputs.map((input) => parseTraceEnvelope(input, budget));
  const independentGroups = distinctGroupCount(traces, budget);
  let labelMemberships = 0;
  for (const trace of traces) {
    labelMemberships = checkedAdd(
      labelMemberships,
      trace.slices.length,
      "label membership",
    );
  }
  const work = estimateJoinWork(
    traces.length,
    evidenceRows,
    independentGroups,
    labelMemberships,
    budget,
  );

  const profilesById = new Map(
    protocol.profiles.map((profile) => [
      profile.id,
      {
        profile,
        digest: fingerprintExecutionProfile(profile),
      },
    ]),
  );
  const splitsByGroup = new Map<string, ResolvedGroupSplit>();
  for (const trace of traces) {
    if (trace.studyId !== protocol.studyId) {
      throw new Error(`trace "${trace.traceId}" study identity conflicts with protocol`);
    }
    if (trace.protocolDigest !== protocolDigest) {
      throw new Error(`trace "${trace.traceId}" protocol digest conflicts with protocol`);
    }
    verifyTraceDispatchIntent(trace, protocol);
    const firstAttemptStartedAt = Date.parse(
      trace.attempts[0].observerTimings.startedAt,
    );
    const terminalCompletedAt = Date.parse(
      trace.attempts[trace.attempts.length - 1].observerTimings.completedAt,
    );
    if (
      firstAttemptStartedAt < Date.parse(protocol.createdAt)
      || terminalCompletedAt >= Date.parse(protocol.expiresAt)
    ) {
      throw new Error(
        `trace "${trace.traceId}" falls outside the protocol validity interval`,
      );
    }
    const expectedProfile = profilesById.get(trace.profileId);
    if (expectedProfile === undefined) {
      throw new Error(`trace "${trace.traceId}" references a profile absent from protocol`);
    }
    if (trace.executionProfileDigest !== expectedProfile.digest) {
      throw new Error(`trace "${trace.traceId}" execution profile digest drift`);
    }
    for (const attempt of trace.attempts) {
      if (attempt.cost.kind === "modeled") {
        if (protocol.costAllocation.kind !== "modeled") {
          throw new Error(
            `trace "${trace.traceId}" modeled cost requires a protocol modeled cost allocation`,
          );
        }
        if (
          attempt.cost.modelDigest
            !== protocol.costAllocation.modelDigest
        ) {
          throw new Error(
            `trace "${trace.traceId}" modeled cost model digest conflicts with protocol`,
          );
        }
      }
      if (
        attempt.requestedModel.id !== expectedProfile.profile.model.id
        || attempt.requestedModel.revision
          !== expectedProfile.profile.model.revision
      ) {
        throw new Error(
          `trace "${trace.traceId}" requested model conflicts with protocol profile`,
        );
      }
      if (
        attempt.resolvedModel !== null
        && (
          attempt.resolvedModel.id !== expectedProfile.profile.model.id
          || (
            attempt.resolvedModel.source === "provider-reported"
            && attempt.resolvedModel.revision
              !== expectedProfile.profile.model.revision
          )
        )
      ) {
        throw new Error(
          `trace "${trace.traceId}" resolved model conflicts with protocol profile`,
        );
      }
    }
    const routeSignal = trace.routeSignal;
    if (routeSignal !== null) {
      if (
        routeSignal.definitionId !== protocol.routeSignal.definitionId
        || routeSignal.version !== protocol.routeSignal.version
        || routeSignal.calibrationDigest !== protocol.routeSignal.calibrationDigest
        || routeSignal.value < protocol.routeSignal.minimum
        || routeSignal.value > protocol.routeSignal.maximum
      ) {
        throw new Error(`trace "${trace.traceId}" route-signal drift`);
      }
      if (
        Date.parse(routeSignal.provenance.observedAt)
          > Date.parse(trace.attempts[0].observerTimings.startedAt)
      ) {
        throw new Error(
          `trace "${trace.traceId}" route signal was observed after the first attempt started`,
        );
      }
    }
    if (trace.split !== "online") {
      let resolved = splitsByGroup.get(trace.groupId);
      if (resolved === undefined) {
        resolved = resolveNormalizedGroupSplit(protocol, trace.groupId);
        splitsByGroup.set(trace.groupId, resolved);
      }
      if (trace.split !== resolved.split) {
        throw new Error(
          `trace "${trace.traceId}" declared split disagrees with derived group split`,
        );
      }
    }
  }
  return { traces, work, splitsByGroup };
}

function makeTraceRecord(
  trace: TraceEnvelope,
  splitsByGroup: ReadonlyMap<string, ResolvedGroupSplit>,
): TraceRecord {
  const split = trace.split;
  const resolved = split === "online"
    ? null
    : splitsByGroup.get(trace.groupId);
  if (split !== "online" && resolved === undefined) {
    throw new Error(`derived split is missing for group "${trace.groupId}"`);
  }
  const traceDigest = fingerprintTrace(trace);
  const traceJoinIdentity = traceIdentityKey(trace);
  return {
    trace,
    traceDigest,
    traceIdentityKey: traceJoinIdentity,
    traceProfileKey: traceProfileKey(
      trace.protocolDigest,
      trace.traceId,
      trace.profileId,
    ),
    logicalProfileKey: logicalProfileKey(trace),
    pairKey: pairKey(trace),
    executionKey: identity("tasc/assessment-execution/v2", {
      traceDigest,
      traceIdentityKey: traceJoinIdentity,
    }),
    split,
    splitBucket: resolved?.bucket ?? null,
    sortedSlices: sortStrings(trace.slices),
    workloadCanonical: canonicalJson(trace.workload),
    routeSignalCanonical: canonicalJson(trace.routeSignal),
  };
}

function groupBy<RecordType>(
  values: readonly RecordType[],
  keyOf: (value: RecordType) => string,
): Map<string, RecordType[]> {
  const grouped = new Map<string, RecordType[]>();
  for (const value of values) {
    const key = keyOf(value);
    const group = grouped.get(key);
    if (group === undefined) grouped.set(key, [value]);
    else group.push(value);
  }
  return grouped;
}

function stringArraysEqual(
  left: readonly string[],
  right: readonly string[],
): boolean {
  return (
    left.length === right.length
    && left.every((value, index) => value === right[index])
  );
}

function terminalOutputEqual(
  left: TraceEnvelope["terminalOutputId"],
  right: EvaluatorEvidence["terminalOutputId"],
): boolean {
  return (
    left !== null
    && left.algorithm === right.algorithm
    && left.keyId === right.keyId
    && left.value === right.value
  );
}

function retainUniqueTraceRecords(
  records: readonly TraceRecord[],
  duplicateTraces: DuplicateTraceDiagnostic[],
  conflictingTraces: ConflictingTraceDiagnostic[],
): TraceRecord[] {
  const afterTraceIdentity: TraceRecord[] = [];
  for (const [traceId, group] of groupBy(records, ({ trace }) => trace.traceId)) {
    const digests = sortStrings(group.map(({ traceDigest }) => traceDigest));
    const distinctDigests = [...new Set(digests)];
    if (group.length > 1 && distinctDigests.length === 1) {
      duplicateTraces.push({
        traceDigest: distinctDigests[0],
        traceId,
        occurrences: group.length,
      });
      afterTraceIdentity.push(group[0]);
      continue;
    }
    if (distinctDigests.length > 1) {
      conflictingTraces.push({
        authoritativeKey: identity("tasc/assessment-trace-id/v2", { traceId }),
        traceDigests: distinctDigests,
        reason: "trace-id-lineage-conflict",
      });
      continue;
    }
    afterTraceIdentity.push(group[0]);
  }

  const unique: TraceRecord[] = [];
  for (const [key, group] of groupBy(
    afterTraceIdentity,
    ({ logicalProfileKey: logicalKey }) => logicalKey,
  )) {
    if (group.length > 1) {
      conflictingTraces.push({
        authoritativeKey: key,
        traceDigests: sortStrings(group.map(({ traceDigest }) => traceDigest)),
        reason: "multiple-profile-executions-for-case-replicate",
      });
      continue;
    }
    unique.push(group[0]);
  }
  return unique.sort((left, right) =>
    compareEvidenceIdentities(left.executionKey, right.executionKey)
  );
}

function assertSharedTraceMetadata(
  baselineRecord: TraceRecord,
  record: TraceRecord,
  scope: "paired profile executions" | "case replicates",
): void {
  const baseline = baselineRecord.trace;
  const trace = record.trace;
  if (trace.groupId !== baseline.groupId) {
    throw new Error(`${scope} have conflicting group identity`);
  }
  if (trace.split !== baseline.split) {
    throw new Error(`${scope} have conflicting split`);
  }
  if (
    trace.workload.declaredTrafficWeight
      !== baseline.workload.declaredTrafficWeight
  ) {
    throw new Error(`${scope} have conflicting traffic weight`);
  }
  if (record.workloadCanonical !== baselineRecord.workloadCanonical) {
    throw new Error(`${scope} have conflicting workload identity`);
  }
  if (!stringArraysEqual(record.sortedSlices, baselineRecord.sortedSlices)) {
    throw new Error(`${scope} have conflicting slice identity`);
  }
  if (record.routeSignalCanonical !== baselineRecord.routeSignalCanonical) {
    throw new Error(`${scope} have conflicting route-signal`);
  }
  if (trace.policyDigest !== baseline.policyDigest) {
    throw new Error(`${scope} have conflicting policy digest`);
  }
  if (
    trace.collectionWindowId !== baseline.collectionWindowId
    || trace.collectionWindowMembershipDigest
      !== baseline.collectionWindowMembershipDigest
  ) {
    throw new Error(`${scope} have conflicting window identity`);
  }
}

function validateTraceMetadata(records: readonly TraceRecord[]): void {
  const groupSplits = new Map<string, AssessmentSplit>();
  for (const record of records) {
    const priorSplit = groupSplits.get(record.trace.groupId);
    if (priorSplit !== undefined && priorSplit !== record.split) {
      throw new Error(`cross-split group leakage for "${record.trace.groupId}"`);
    }
    groupSplits.set(record.trace.groupId, record.split);
  }

  for (const recordsForPair of groupBy(records, ({ pairKey: key }) => key).values()) {
    const baseline = recordsForPair[0];
    for (let index = 1; index < recordsForPair.length; index += 1) {
      assertSharedTraceMetadata(
        baseline,
        recordsForPair[index],
        "paired profile executions",
      );
    }
  }

  for (const recordsForCase of groupBy(records, ({ trace }) => trace.caseId).values()) {
    const baseline = recordsForCase[0];
    for (let index = 1; index < recordsForCase.length; index += 1) {
      assertSharedTraceMetadata(
        baseline,
        recordsForCase[index],
        "case replicates",
      );
    }
  }
}

function evidenceJoinKey(evidence: EvaluatorEvidence): string {
  return identity("tasc/assessment-trace-join-key/v2", {
    protocolDigest: evidence.protocolDigest,
    traceId: evidence.traceId,
    profileId: evidence.profileId,
    terminalOutputId: evidence.terminalOutputId,
  });
}

function verificationContextIdentity(
  receipt: EvaluatorEvidenceVerification,
): string {
  return identity("tasc/assessment-verification-context/v2", {
    assessedAt: receipt.assessedAt,
    assessmentContextDigest: receipt.assessmentContextDigest,
    evaluatorRevocationSnapshotDigest:
      receipt.evaluatorRevocationSnapshotDigest,
    operatorTrustPolicySnapshotDigest:
      receipt.operatorTrustPolicySnapshotDigest,
  });
}

function verificationContextCacheKey(
  receipt: EvaluatorEvidenceVerification,
): string {
  return canonicalJson([
    receipt.assessedAt,
    receipt.assessmentContextDigest,
    receipt.evaluatorRevocationSnapshotDigest,
    receipt.operatorTrustPolicySnapshotDigest,
  ]);
}

function authenticVerificationProvenance(
  receipt: EvaluatorEvidenceVerification,
): EvidenceVerificationProvenance {
  return {
    authentic: true,
    status: receipt.status,
    trusted: receipt.trusted,
    reason: receipt.reason,
    keyId: receipt.keyId,
    assessedAt: receipt.assessedAt,
    assessmentContextDigest: receipt.assessmentContextDigest,
    operatorTrustPolicySnapshotDigest:
      receipt.operatorTrustPolicySnapshotDigest,
    evaluatorRevocationSnapshotDigest:
      receipt.evaluatorRevocationSnapshotDigest,
  };
}

function inauthenticVerificationProvenance(): EvidenceVerificationProvenance {
  return {
    authentic: false,
    status: "inauthentic",
    trusted: false,
    reason: "object was not emitted by the local evaluator verifier",
    keyId: null,
    assessedAt: null,
    assessmentContextDigest: null,
    operatorTrustPolicySnapshotDigest: null,
    evaluatorRevocationSnapshotDigest: null,
  };
}

function diagnosticEvidenceRow(record: EvidenceRecord): DiagnosticEvidenceRow {
  return {
    evidence: record.evidence,
    evidenceDigest: record.evidenceDigest,
    verification: record.verification,
  };
}

function diagnosticForEvidence(
  evidence: EvaluatorEvidence | null,
  evidenceDigest: string | null,
  reason: string,
  verification: EvidenceVerificationProvenance,
): EvidenceDiagnostic {
  return {
    evidenceDigest,
    evidence,
    verification,
    traceId: evidence?.traceId ?? null,
    profileId: evidence?.profileId ?? null,
    reason,
  };
}

function verificationSortIdentity(
  verification: EvidenceVerificationProvenance,
): readonly (string | boolean | null)[] {
  return [
    verification.authentic,
    verification.status,
    verification.trusted,
    verification.reason,
    verification.keyId,
    verification.assessedAt,
    verification.assessmentContextDigest,
    verification.operatorTrustPolicySnapshotDigest,
    verification.evaluatorRevocationSnapshotDigest,
  ];
}

function sortByCompactKey<T>(
  values: T[],
  compactKey: (value: T) => string,
): T[] {
  return values
    .map((value) => ({ value, sortKey: compactKey(value) }))
    .sort((left, right) => compareCodeUnits(left.sortKey, right.sortKey))
    .map(({ value }) => value);
}

function rejectedEvidenceSortKey(value: RejectedEvidenceRecord): string {
  return canonicalJson([
    value.joinKey,
    value.evidenceDigest,
    value.reason,
    verificationSortIdentity(value.verification),
  ]);
}

function evidenceDiagnosticSortKey(value: EvidenceDiagnostic): string {
  return canonicalJson([
    value.evidenceDigest,
    value.traceId,
    value.profileId,
    value.reason,
    verificationSortIdentity(value.verification),
  ]);
}

function missingEvidenceSortKey(value: MissingEvidenceDiagnostic): string {
  return canonicalJson([
    value.executionKey,
    value.traceId,
    value.profileId,
    value.reason,
    value.evidenceDigest ?? null,
  ]);
}

function abstainedEvidenceSortKey(value: AbstainedEvidenceDiagnostic): string {
  return canonicalJson([
    value.executionKey,
    value.evidenceDigest,
    value.reasonCode,
  ]);
}

function duplicateEvidenceSortKey(value: DuplicateEvidenceDiagnostic): string {
  return canonicalJson([
    value.joinKey,
    value.evidenceDigest,
    value.occurrences,
    verificationSortIdentity(value.row.verification),
  ]);
}

function conflictingEvidenceSortKey(
  value: ConflictingEvidenceDiagnostic,
): string {
  return canonicalJson([
    value.joinKey,
    value.evidenceDigests,
    value.reason,
    value.rows.map((row) => [
      row.evidenceDigest,
      verificationSortIdentity(row.verification),
    ]),
  ]);
}

function duplicateTraceSortKey(value: DuplicateTraceDiagnostic): string {
  return canonicalJson([
    value.traceDigest,
    value.traceId,
    value.occurrences,
  ]);
}

function conflictingTraceSortKey(value: ConflictingTraceDiagnostic): string {
  return canonicalJson([
    value.authoritativeKey,
    value.traceDigests,
    value.reason,
  ]);
}

function missingProfileSortKey(value: MissingProfileDiagnostic): string {
  return canonicalJson([
    value.caseId,
    value.replicateId,
    value.missingProfileIds,
  ]);
}

function terminalStatus(trace: TraceEnvelope): "success" | "failure" | "aborted" {
  return trace.attempts[trace.attempts.length - 1].status;
}

function hasAmbiguousDispatch(trace: TraceEnvelope): boolean {
  return trace.attempts.some((attempt) =>
    attempt.dispatchState === "sent_unknown"
    || attempt.abortLifecycle === "abort-ambiguous"
  );
}

function terminalCompletion(trace: TraceEnvelope): number {
  return Date.parse(
    trace.attempts[trace.attempts.length - 1].observerTimings.completedAt,
  );
}

function traceLineageMatches(
  trace: TraceEnvelope,
  evidence: EvaluatorEvidence,
): boolean {
  return (
    trace.studyId === evidence.studyId
    && trace.protocolDigest === evidence.protocolDigest
    && trace.traceId === evidence.traceId
    && trace.caseId === evidence.caseId
    && trace.replicateId === evidence.replicateId
    && trace.profileId === evidence.profileId
    && trace.split === evidence.split
    && terminalOutputEqual(trace.terminalOutputId, evidence.terminalOutputId)
  );
}

/**
 * Deterministically join locally verified external evaluator evidence to
 * logical inference executions. This function performs no model or judge call.
 */
export function joinAssessmentEvidence(
  protocolInput: ExperimentProtocol,
  traceInputs: readonly TraceEnvelope[],
  verificationInputs: readonly EvaluatorEvidenceVerification[],
  workBudget: WorkBudget,
): DeepReadonly<AssessmentDataset> {
  const traceCollection = preflightCollection<TraceEnvelope>(
    traceInputs,
    "trace rows",
  );
  const evidenceCollection = preflightCollection<EvaluatorEvidenceVerification>(
    verificationInputs,
    "evidence rows",
  );
  const traceRows = traceCollection.length;
  const evidenceRows = evidenceCollection.length;
  estimateJoinWork(
    traceRows,
    evidenceRows,
    traceRows === 0 ? 0 : 1,
    0,
    workBudget,
  );
  const traceSnapshot = snapshotCollection(traceCollection);
  const verificationSnapshot = snapshotCollection(evidenceCollection);

  const protocol = normalizeExperimentProtocol(protocolInput);
  const protocolDigest = fingerprintNormalizedProtocol(protocol);
  const normalizedTraces = normalizeTraces(
    protocol,
    protocolDigest,
    traceSnapshot,
    workBudget,
    evidenceRows,
  );
  const traces = normalizedTraces.traces;
  const traceSetDigest = identity(
    "tasc/assessment-trace-set/v2",
    sortStrings(traces.map(fingerprintTrace)),
  );
  const evaluatorSetDigest = identity(
    "tasc/assessment-evaluator-set/v2",
    sortStrings(verificationSnapshot.map(fingerprintVerificationSource)),
  );

  const duplicateTraces: DuplicateTraceDiagnostic[] = [];
  const conflictingTraces: ConflictingTraceDiagnostic[] = [];
  const traceRecords = retainUniqueTraceRecords(
    traces.map((trace) =>
      makeTraceRecord(trace, normalizedTraces.splitsByGroup)
    ),
    duplicateTraces,
    conflictingTraces,
  );
  validateTraceMetadata(traceRecords);

  const invalidEvidence: EvidenceDiagnostic[] = [];
  const orphanEvidence: EvidenceDiagnostic[] = [];
  const duplicateEvidence: DuplicateEvidenceDiagnostic[] = [];
  const conflictingEvidence: ConflictingEvidenceDiagnostic[] = [];
  const missingEvidence: MissingEvidenceDiagnostic[] = [];
  const abstainedEvidence: AbstainedEvidenceDiagnostic[] = [];
  const authenticRecords: EvidenceRecord[] = [];
  const rejectedEvidenceRecords: RejectedEvidenceRecord[] = [];
  const authenticContextIdentities: string[] = [];
  const authenticAssessmentContextDigests: string[] = [];
  const verificationContextIdentityCache = new Map<string, string>();
  const rejectEvidence = (
    evidence: EvaluatorEvidence | null,
    evidenceDigest: string | null,
    reason: string,
    verification: EvidenceVerificationProvenance,
  ): void => {
    invalidEvidence.push(diagnosticForEvidence(
      evidence,
      evidenceDigest,
      reason,
      verification,
    ));
    if (evidence !== null && evidenceDigest !== null) {
      rejectedEvidenceRecords.push({
        evidence,
        evidenceDigest,
        joinKey: evidenceJoinKey(evidence),
        verification,
        reason,
      });
    }
  };

  for (const input of verificationSnapshot) {
    if (!isAuthenticEvaluatorEvidenceVerification(input)) {
      rejectEvidence(
        null,
        null,
        "inauthentic-verification-receipt",
        inauthenticVerificationProvenance(),
      );
      continue;
    }
    const verification = authenticVerificationProvenance(input);
    authenticAssessmentContextDigests.push(input.assessmentContextDigest);
    const contextCacheKey = verificationContextCacheKey(input);
    let contextIdentity = verificationContextIdentityCache.get(contextCacheKey);
    if (contextIdentity === undefined) {
      contextIdentity = verificationContextIdentity(input);
      verificationContextIdentityCache.set(contextCacheKey, contextIdentity);
    }
    authenticContextIdentities.push(contextIdentity);
    const evidence = input.evidence;
    const evidenceDigest = input.evidenceDigest;
    if (
      input.keyId !== evidence.keyId
      || input.trusted !== (input.status === "trusted")
    ) {
      rejectEvidence(
        evidence,
        evidenceDigest,
        "verification-receipt-integrity-conflict",
        verification,
      );
      continue;
    }
    if (!input.trusted) {
      rejectEvidence(
        evidence,
        evidenceDigest,
        `verification-${input.status}`,
        verification,
      );
      continue;
    }
    if (!protocol.evaluator.requiredTrustedKeyIds.includes(evidence.keyId)) {
      rejectEvidence(
        evidence,
        evidenceDigest,
        "evaluator-key-not-pinned-by-protocol",
        verification,
      );
      continue;
    }
    if (
      evidence.studyId !== protocol.studyId
      || evidence.protocolDigest !== protocolDigest
      || evidence.evaluator.evaluatorId !== protocol.evaluator.evaluatorId
      || evidence.evaluator.rubricVersion !== protocol.evaluator.rubricVersion
      || evidence.evaluator.calibrationDigest
        !== protocol.evaluator.calibrationDigest
      || evidence.evaluator.producer.kind !== protocol.evaluator.producerKind
      || evidence.evaluator.producer.producerId !== protocol.evaluator.producerId
      || evidence.evaluator.producer.version !== protocol.evaluator.producerVersion
    ) {
      rejectEvidence(
        evidence,
        evidenceDigest,
        "evaluator-or-rubric-or-calibration-or-producer-drift",
        verification,
      );
      continue;
    }
    authenticRecords.push({
      evidence,
      evidenceDigest,
      joinKey: evidenceJoinKey(evidence),
      contextIdentity,
      verification,
    });
  }

  const contextIdentities = sortStrings([
    ...new Set(authenticContextIdentities),
  ]);
  const assessmentContextDigests = sortStrings([
    ...new Set(authenticAssessmentContextDigests),
  ]);
  let identityStableRecords = authenticRecords;
  if (contextIdentities.length > 1) {
    for (const record of authenticRecords) {
      rejectEvidence(
        record.evidence,
        record.evidenceDigest,
        "verification-context-drift",
        record.verification,
      );
    }
    identityStableRecords = [];
  }

  const uniqueEvidence: EvidenceRecord[] = [];
  for (const [digest, records] of groupBy(
    identityStableRecords,
    ({ evidenceDigest }) => evidenceDigest,
  )) {
    if (records.length > 1) {
      duplicateEvidence.push({
        joinKey: records[0].joinKey,
        evidenceDigest: digest,
        occurrences: records.length,
        row: diagnosticEvidenceRow(records[0]),
      });
      uniqueEvidence.push(records[0]);
      continue;
    }
    uniqueEvidence.push(records[0]);
  }

  const nonConflictingEvidence: EvidenceRecord[] = [];
  for (const [key, records] of groupBy(uniqueEvidence, ({ joinKey }) => joinKey)) {
    if (records.length > 1) {
      conflictingEvidence.push({
        joinKey: key,
        evidenceDigests: sortStrings(records.map(({ evidenceDigest }) => evidenceDigest)),
        rows: records
          .map(diagnosticEvidenceRow)
          .sort((left, right) =>
            compareEvidenceIdentities(left.evidenceDigest, right.evidenceDigest)
          ),
        reason: "multiple-distinct-evidence-rows-for-join-key",
      });
      continue;
    }
    nonConflictingEvidence.push(records[0]);
  }

  const tracesByIdentity = new Map(
    traceRecords.map((record) => [record.traceIdentityKey, record]),
  );
  const traceProfileKeys = new Set<string>();
  const failedTraceProfileKeys = new Set<string>();
  for (const record of traceRecords) {
    traceProfileKeys.add(record.traceProfileKey);
    if (terminalStatus(record.trace) !== "success") {
      failedTraceProfileKeys.add(record.traceProfileKey);
    }
  }
  const evidenceByExecution = new Map<string, EvidenceRecord>();
  const invalidOutcomeByExecution = new Map<string, {
    kind: "missing-evidence" | "invalid-evidence" | "abstained";
    reasonCode: string;
    evidence: EvaluatorEvidence;
    evidenceDigest: string;
    verification: EvidenceVerificationProvenance;
  }>();
  const rejectedEvidenceByExecution = new Map<string, RejectedEvidenceRecord>();
  for (const rejected of sortByCompactKey(
    rejectedEvidenceRecords,
    rejectedEvidenceSortKey,
  )) {
    const trace = tracesByIdentity.get(rejected.joinKey);
    if (
      trace !== undefined
      && traceLineageMatches(trace.trace, rejected.evidence)
      && !rejectedEvidenceByExecution.has(trace.executionKey)
    ) {
      rejectedEvidenceByExecution.set(trace.executionKey, rejected);
    }
  }

  for (const record of nonConflictingEvidence.sort((left, right) =>
    compareEvidenceIdentities(left.evidenceDigest, right.evidenceDigest)
  )) {
    const trace = tracesByIdentity.get(record.joinKey);
    if (trace === undefined) {
      const partialKey = traceProfileKey(
        record.evidence.protocolDigest,
        record.evidence.traceId,
        record.evidence.profileId,
      );
      const reason = failedTraceProfileKeys.has(partialKey)
        ? "evidence-for-failed-execution"
        : traceProfileKeys.has(partialKey)
        ? "terminal-output-mismatch"
        : "no-matching-trace";
      orphanEvidence.push(diagnosticForEvidence(
        record.evidence,
        record.evidenceDigest,
        reason,
        record.verification,
      ));
      continue;
    }
    if (!traceLineageMatches(trace.trace, record.evidence)) {
      conflictingEvidence.push({
        joinKey: record.joinKey,
        evidenceDigests: [record.evidenceDigest],
        rows: [diagnosticEvidenceRow(record)],
        reason: "trace-evidence-lineage-conflict",
      });
      continue;
    }
    if (
      Date.parse(record.evidence.producedAt)
        < terminalCompletion(trace.trace)
    ) {
      const reason = "evaluator-evidence-predates-terminal-completion";
      rejectEvidence(
        record.evidence,
        record.evidenceDigest,
        reason,
        record.verification,
      );
      rejectedEvidenceByExecution.set(trace.executionKey, {
        evidence: record.evidence,
        evidenceDigest: record.evidenceDigest,
        joinKey: record.joinKey,
        verification: record.verification,
        reason,
      });
      continue;
    }
    if (record.evidence.outcome.kind === "scored") {
      evidenceByExecution.set(trace.executionKey, record);
      continue;
    }
    const outcomeKind = record.evidence.outcome.kind === "abstained"
      ? "abstained"
      : record.evidence.outcome.kind === "missing"
      ? "missing-evidence"
      : "invalid-evidence";
    invalidOutcomeByExecution.set(trace.executionKey, {
      kind: outcomeKind,
      reasonCode: record.evidence.outcome.reasonCode,
      evidence: record.evidence,
      evidenceDigest: record.evidenceDigest,
      verification: record.verification,
    });
    if (outcomeKind === "abstained") {
      abstainedEvidence.push({
        executionKey: trace.executionKey,
        evidenceDigest: record.evidenceDigest,
        reasonCode: record.evidence.outcome.reasonCode,
      });
    } else if (outcomeKind === "missing-evidence") {
      missingEvidence.push({
        executionKey: trace.executionKey,
        traceId: trace.trace.traceId,
        profileId: trace.trace.profileId,
        reason: `evaluator-declared-${record.evidence.outcome.reasonCode}`,
        evidenceDigest: record.evidenceDigest,
      });
    } else {
      invalidEvidence.push(diagnosticForEvidence(
        record.evidence,
        record.evidenceDigest,
        `evaluator-declared-${record.evidence.outcome.reasonCode}`,
        record.verification,
      ));
    }
  }

  const conflictingJoinKeys = new Set(
    conflictingEvidence.map(({ joinKey }) => joinKey),
  );
  const executions: AssessmentExecutionRow[] = [];
  for (const record of traceRecords) {
    const status = terminalStatus(record.trace);
    let outcome: AssessmentExecutionOutcome;
    if (hasAmbiguousDispatch(record.trace)) {
      outcome = {
        kind: "ambiguous-execution",
        reasonCode: "dispatch-outcome-ambiguous",
        score: null,
        evidence: null,
      };
    } else if (status !== "success") {
      outcome = {
        kind: "protocol-failure-zero",
        score: FAILURE_SCORE,
        evidence: null,
      };
    } else {
      const scored = evidenceByExecution.get(record.executionKey);
      const nonScored = invalidOutcomeByExecution.get(record.executionKey);
      if (scored !== undefined && scored.evidence.outcome.kind === "scored") {
        outcome = {
          kind: "scored",
          score: scored.evidence.outcome.score,
          range: scored.evidence.outcome.range,
          evidenceDigest: scored.evidenceDigest,
          evidence: scored.evidence,
          verification: scored.verification,
          evidenceAccepted: true,
        };
      } else if (nonScored !== undefined) {
        outcome = {
          kind: nonScored.kind,
          reasonCode: nonScored.reasonCode,
          evidenceDigest: nonScored.evidenceDigest,
          evidence: nonScored.evidence,
          verification: nonScored.verification,
          evidenceAccepted: true,
        };
      } else {
        const rejected = rejectedEvidenceByExecution.get(record.executionKey);
        if (rejected !== undefined) {
          outcome = {
            kind: "invalid-evidence",
            reasonCode: rejected.reason,
            evidenceDigest: rejected.evidenceDigest,
            evidence: rejected.evidence,
            verification: rejected.verification,
            evidenceAccepted: false,
          };
        } else if (conflictingJoinKeys.has(record.traceIdentityKey)) {
          outcome = {
            kind: "invalid-evidence",
            reasonCode: "conflicting-evidence",
            evidenceDigest: null,
            evidence: null,
            verification: null,
            evidenceAccepted: false,
          };
        } else {
          outcome = {
            kind: "missing-evidence",
            reasonCode: "successful-execution-without-trusted-evidence",
            evidenceDigest: null,
            evidence: null,
            verification: null,
            evidenceAccepted: false,
          };
          missingEvidence.push({
            executionKey: record.executionKey,
            traceId: record.trace.traceId,
            profileId: record.trace.profileId,
            reason: outcome.reasonCode,
          });
        }
      }
    }
    executions.push({
      executionKey: record.executionKey,
      traceId: record.trace.traceId,
      caseId: record.trace.caseId,
      replicateId: record.trace.replicateId,
      groupId: record.trace.groupId,
      profileId: record.trace.profileId,
      split: record.split,
      splitBucket: record.splitBucket,
      terminalStatus: status,
      outcome,
      trace: record.trace,
    });
  }
  executions.sort((left, right) =>
    compareEvidenceIdentities(left.caseId, right.caseId)
    || compareEvidenceIdentities(left.replicateId, right.replicateId)
    || compareEvidenceIdentities(left.profileId, right.profileId)
    || compareEvidenceIdentities(left.executionKey, right.executionKey)
  );

  const requiredProfileIds = sortStrings([
    protocol.championProfileId,
    ...protocol.candidateProfileIds,
  ]);
  const missingProfileExecutions: MissingProfileDiagnostic[] = [];
  const pairs: AssessmentPair[] = [];
  const pairGroups = [...groupBy(traceRecords, ({ pairKey: key }) => key).values()]
    .sort((left, right) =>
      compareEvidenceIdentities(left[0].pairKey, right[0].pairKey)
    );
  for (const records of pairGroups) {
    const baselineRecord = records[0];
    const baseline = baselineRecord.trace;
    const present = new Set(records.map(({ trace }) => trace.profileId));
    const missing = requiredProfileIds.filter((profileId) => !present.has(profileId));
    if (missing.length > 0) {
      missingProfileExecutions.push({
        caseId: baseline.caseId,
        replicateId: baseline.replicateId,
        missingProfileIds: missing,
      });
      continue;
    }
    pairs.push({
      pairKey: baselineRecord.pairKey,
      caseId: baseline.caseId,
      replicateId: baseline.replicateId,
      groupId: baseline.groupId,
      split: baseline.split,
      declaredTrafficWeight: baseline.workload.declaredTrafficWeight,
      slices: baselineRecord.sortedSlices,
      profileIds: requiredProfileIds,
      executionKeys: sortStrings(records.map(({ executionKey }) => executionKey)),
    });
  }

  const logicalUnits = pairGroups.map((records) => records[0].trace);
  const caseUnits = [...groupBy(logicalUnits, ({ caseId }) => caseId).values()]
    .map((records) => records[0]);
  const trafficMass = caseUnits.reduce(
    (total, trace) => total + trace.workload.declaredTrafficWeight,
    0,
  );
  if (!Number.isFinite(trafficMass)) {
    throw new Error("observed traffic mass exceeds the finite numeric range");
  }
  const groups = new Set(caseUnits.map(({ groupId }) => groupId));
  const splitAccumulators = new Map<AssessmentSplit, {
    caseReplicates: number;
    groups: Set<string>;
    observedTrafficMass: number;
  }>();
  const sliceAccumulators = new Map<string, {
    caseReplicates: number;
    groups: Set<string>;
  }>();
  let sliceAggregationVisits = 0;
  for (const trace of logicalUnits) {
    const split = splitAccumulators.get(trace.split) ?? {
      caseReplicates: 0,
      groups: new Set<string>(),
      observedTrafficMass: 0,
    };
    split.caseReplicates += 1;
    split.groups.add(trace.groupId);
    splitAccumulators.set(trace.split, split);
    for (const sliceId of trace.slices) {
      sliceAggregationVisits = checkedAdd(
        sliceAggregationVisits,
        1,
        "slice aggregation visit",
      );
      const slice = sliceAccumulators.get(sliceId) ?? {
        caseReplicates: 0,
        groups: new Set<string>(),
      };
      slice.caseReplicates += 1;
      slice.groups.add(trace.groupId);
      sliceAccumulators.set(sliceId, slice);
    }
  }
  for (const trace of caseUnits) {
    const split = splitAccumulators.get(trace.split);
    if (split === undefined) throw new Error("case split accumulator is missing");
    split.observedTrafficMass += trace.workload.declaredTrafficWeight;
    if (!Number.isFinite(split.observedTrafficMass)) {
      throw new Error("split traffic mass exceeds the finite numeric range");
    }
  }
  const splits = [...splitAccumulators.entries()]
    .sort(([left], [right]) => compareCodeUnits(left, right))
    .map(([split, accumulator]) => ({
      split,
      caseReplicates: accumulator.caseReplicates,
      groups: accumulator.groups.size,
      observedTrafficMass: accumulator.observedTrafficMass,
    }));
  const slices = [...sliceAccumulators.entries()]
    .sort(([left], [right]) => compareCodeUnits(left, right))
    .map(([sliceId, accumulator]) => ({
      sliceId,
      caseReplicates: accumulator.caseReplicates,
      groups: accumulator.groups.size,
    }));
  const diagnostics = {
    missingEvidence: sortByCompactKey(
      missingEvidence,
      missingEvidenceSortKey,
    ),
    invalidEvidence: sortByCompactKey(
      invalidEvidence,
      evidenceDiagnosticSortKey,
    ),
    abstainedEvidence: sortByCompactKey(
      abstainedEvidence,
      abstainedEvidenceSortKey,
    ),
    orphanEvidence: sortByCompactKey(
      orphanEvidence,
      evidenceDiagnosticSortKey,
    ),
    duplicateEvidence: sortByCompactKey(
      duplicateEvidence,
      duplicateEvidenceSortKey,
    ),
    conflictingEvidence: sortByCompactKey(
      conflictingEvidence,
      conflictingEvidenceSortKey,
    ),
    duplicateTraces: sortByCompactKey(
      duplicateTraces,
      duplicateTraceSortKey,
    ),
    conflictingTraces: sortByCompactKey(
      conflictingTraces,
      conflictingTraceSortKey,
    ),
    missingProfileExecutions: sortByCompactKey(
      missingProfileExecutions,
      missingProfileSortKey,
    ),
  };
  const blockingReasons: string[] = [];
  const blockWhenPresent = (
    values: readonly unknown[],
    reason: string,
  ): void => {
    if (values.length > 0) blockingReasons.push(reason);
  };
  blockWhenPresent(diagnostics.missingEvidence, "missing-evaluator-evidence");
  blockWhenPresent(diagnostics.invalidEvidence, "invalid-evaluator-evidence");
  blockWhenPresent(diagnostics.abstainedEvidence, "abstained-evaluator-evidence");
  blockWhenPresent(diagnostics.orphanEvidence, "orphan-evaluator-evidence");
  blockWhenPresent(diagnostics.duplicateEvidence, "duplicate-evaluator-evidence");
  blockWhenPresent(diagnostics.conflictingEvidence, "conflicting-evaluator-evidence");
  blockWhenPresent(diagnostics.duplicateTraces, "duplicate-traces");
  blockWhenPresent(diagnostics.conflictingTraces, "conflicting-traces");
  blockWhenPresent(
    diagnostics.missingProfileExecutions,
    "missing-profile-executions",
  );

  const datasetBody = {
    version: "tasc-assessment-dataset-v2",
    studyId: protocol.studyId,
    protocolDigest,
    assessmentContextDigest: assessmentContextDigests.length === 1
      ? assessmentContextDigests[0]
      : null,
    traceSetDigest,
    evaluatorSetDigest,
    splitIdentity: protocol.splitMembership,
    evaluatorIdentity: protocol.evaluator,
    requiredProfileIds,
    verificationContextIdentities: contextIdentities,
    executions,
    pairs,
    work: {
      ...normalizedTraces.work,
      sliceAggregationVisits,
    },
    counts: {
      traceRows,
      acceptedTraceRows: traceRecords.length,
      evidenceRows,
      matchedRows: executions.filter(({ outcome }) =>
        "evidenceAccepted" in outcome && outcome.evidenceAccepted
      ).length,
      scoredRows: executions.filter(({ outcome }) =>
        outcome.kind === "scored"
      ).length,
      pairedCaseReplicates: pairs.length,
      cases: caseUnits.length,
      caseReplicates: logicalUnits.length,
      groups: groups.size,
      observedTrafficMass: trafficMass,
      splits,
      slices,
    },
    diagnostics,
    admissibility: {
      valid: blockingReasons.length === 0,
      blockingReasons: sortStrings(blockingReasons),
    },
  } as const;
  const result = deepFreezeContract({
    ...datasetBody,
    datasetDigest: identity("tasc/assessment-dataset/v2", datasetBody),
  });
  authenticAssessmentDatasets.add(result);
  return result;
}

/**
 * Assessment accepts only the exact recursively frozen value emitted by the
 * trusted join in this process. Serialized inputs must be rejoined from raw
 * traces and locally verified evaluator receipts.
 */
export function isAuthenticAssessmentDataset(
  value: unknown,
): value is DeepReadonly<AssessmentDataset> {
  return (
    value !== null
    && typeof value === "object"
    && authenticAssessmentDatasets.has(value)
  );
}

/**
 * Narrow an authentic joined dataset to one assessment phase. The returned
 * object is the original authenticated value; this function never blesses a
 * clone or caller-authored structure.
 */
export function requireAssessmentDatasetSplit<
  Split extends AssessmentSplit,
>(
  value: DeepReadonly<AssessmentDataset>,
  expected: Split,
): DeepReadonly<AssessmentDatasetForSplit<Split>> {
  if (!isAuthenticAssessmentDataset(value)) {
    throw new Error("phase narrowing requires an authentic assessment dataset");
  }
  if (
    value.executions.some(({ split }) => split !== expected)
    || value.pairs.some(({ split }) => split !== expected)
    || value.counts.splits.some(({ split }) => split !== expected)
  ) {
    throw new Error(`assessment dataset contains rows outside ${expected} split`);
  }
  return value as DeepReadonly<AssessmentDatasetForSplit<Split>>;
}
