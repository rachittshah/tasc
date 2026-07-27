import { Buffer } from "node:buffer";
import { canonicalJson, compareCodeUnits } from "./determinism.js";
import {
  compareEvidenceIdentities,
  contractSlugSchema,
  deepFreezeContract,
  domainSeparatedDigest,
  fingerprintExecutionProfile,
  fingerprintNormalizedEvaluatorEvidence,
  fingerprintProtocol,
  normalizeEvaluatorEvidence,
  parseExperimentProtocol,
  parseTraceEnvelope,
  snapshotBoundedContractInput,
  type DeepReadonly,
  type EvaluatorEvidence,
  type ExperimentProtocol,
  type TraceEnvelope,
} from "./evidence.js";
import {
  isAuthenticEvaluatorEvidenceVerification,
  type EvaluatorEvidenceVerification,
} from "./evaluator-trust.js";
import {
  assertWithinWorkBudget,
  estimateAssessmentWork,
  type WorkBudget,
} from "./work-budget.js";

type OfflineSplit = "dev" | "holdout";
type AssessmentSplit = OfflineSplit | "online";

export interface ResolvedGroupSplit {
  readonly algorithm: "tasc-seeded-sha256-group-bucket-v1";
  readonly bucket: number;
  readonly split: OfflineSplit;
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
}

interface ProtocolFailureOutcome {
  readonly kind: "protocol-failure-zero";
  readonly score: 0;
  readonly evidence: null;
}

interface NonScoredAssessmentOutcome {
  readonly kind: "missing-evidence" | "invalid-evidence" | "abstained";
  readonly reasonCode: string;
  readonly evidenceDigest: string | null;
  readonly evidence: EvaluatorEvidence | null;
}

export type AssessmentExecutionOutcome =
  | ScoredAssessmentOutcome
  | ProtocolFailureOutcome
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

export interface EvidenceDiagnostic {
  readonly evidenceDigest: string | null;
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
}

export interface ConflictingEvidenceDiagnostic {
  readonly joinKey: string;
  readonly evidenceDigests: readonly string[];
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
  readonly splitIdentity: ExperimentProtocol["splitMembership"];
  readonly evaluatorIdentity: ExperimentProtocol["evaluator"];
  readonly requiredProfileIds: readonly string[];
  readonly verificationContextIdentities: readonly string[];
  readonly executions: readonly AssessmentExecutionRow[];
  readonly pairs: readonly AssessmentPair[];
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

interface TraceRecord {
  readonly trace: TraceEnvelope;
  readonly traceDigest: string;
  readonly traceIdentityKey: string;
  readonly logicalProfileKey: string;
  readonly executionKey: string;
  readonly split: AssessmentSplit;
  readonly splitBucket: number | null;
}

interface EvidenceRecord {
  readonly evidence: EvaluatorEvidence;
  readonly evidenceDigest: string;
  readonly joinKey: string;
  readonly contextIdentity: string;
}

const FAILURE_SCORE = 0 as const;

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

function fingerprintTrace(trace: TraceEnvelope): string {
  return identity("tasc/trace-envelope/v2", trace);
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
export function resolveGroupSplit(
  protocol: ExperimentProtocol,
  groupId: string,
): ResolvedGroupSplit {
  const normalizedGroupId = contractSlugSchema.parse(groupId);
  if (
    !Number.isSafeInteger(protocol.splitMembership.bucketCount)
    || protocol.splitMembership.bucketCount < 2
    || protocol.splitMembership.bucketCount > 256
  ) {
    throw new Error("split bucket count must be a safe integer from 2 through 256");
  }
  const digest = domainSeparatedDigest(
    "tasc/seeded-sha256-group-bucket/v1",
    {
      algorithm: protocol.splitMembership.algorithm,
      groupId: normalizedGroupId,
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
  const allowedIndexes = new Set(
    Array.from({ length: preflight.length }, (_, index) => String(index)),
  );
  for (const key of keys) {
    if (typeof key === "symbol") {
      throw new Error(`${preflight.label} collection cannot contain symbol properties`);
    }
    if (key !== "length" && !allowedIndexes.has(key)) {
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

function assertJoinBudget(
  traceRows: number,
  evidenceRows: number,
  independentGroups: number,
  budget: WorkBudget,
): void {
  assertWithinWorkBudget(estimateAssessmentWork({
    candidateCount: 1,
    traceRows,
    evidenceRows,
    bootstrapDraws: 0,
    independentGroups,
  }), budget);

  const nonZeroEstimate = estimateAssessmentWork({
    candidateCount: 1,
    traceRows: Math.max(1, traceRows),
    evidenceRows: Math.max(1, evidenceRows),
    bootstrapDraws: 1,
    independentGroups: Math.max(1, independentGroups),
  });
  if (nonZeroEstimate.assessmentWork > budget.maxAssessmentWork) {
    throw new Error(
      `assessment work exceeds caller work budget: ${nonZeroEstimate.assessmentWork} > ${budget.maxAssessmentWork}`,
    );
  }
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
): TraceEnvelope[] {
  const traces = inputs.map((input) => parseTraceEnvelope(input, budget));
  const independentGroups = distinctGroupCount(traces, budget);
  assertJoinBudget(traces.length, evidenceRows, independentGroups, budget);

  const profileDigests = new Map(
    protocol.profiles.map((profile) => [
      profile.id,
      fingerprintExecutionProfile(profile),
    ]),
  );
  for (const trace of traces) {
    if (trace.studyId !== protocol.studyId) {
      throw new Error(`trace "${trace.traceId}" study identity conflicts with protocol`);
    }
    if (trace.protocolDigest !== protocolDigest) {
      throw new Error(`trace "${trace.traceId}" protocol digest conflicts with protocol`);
    }
    const expectedProfileDigest = profileDigests.get(trace.profileId);
    if (expectedProfileDigest === undefined) {
      throw new Error(`trace "${trace.traceId}" references a profile absent from protocol`);
    }
    if (trace.executionProfileDigest !== expectedProfileDigest) {
      throw new Error(`trace "${trace.traceId}" execution profile digest drift`);
    }
    if (
      trace.routeSignal === null
      || trace.routeSignal.definitionId !== protocol.routeSignal.definitionId
      || trace.routeSignal.version !== protocol.routeSignal.version
      || trace.routeSignal.calibrationDigest !== protocol.routeSignal.calibrationDigest
      || trace.routeSignal.value < protocol.routeSignal.minimum
      || trace.routeSignal.value > protocol.routeSignal.maximum
    ) {
      throw new Error(`trace "${trace.traceId}" route-signal drift`);
    }
    if (trace.split !== "online") {
      const resolved = resolveGroupSplit(protocol, trace.groupId);
      if (trace.split !== resolved.split) {
        throw new Error(
          `trace "${trace.traceId}" declared split disagrees with derived group split`,
        );
      }
    }
  }
  return traces;
}

function makeTraceRecord(
  protocol: ExperimentProtocol,
  trace: TraceEnvelope,
): TraceRecord {
  const split = trace.split;
  const resolved = split === "online"
    ? null
    : resolveGroupSplit(protocol, trace.groupId);
  const traceDigest = fingerprintTrace(trace);
  return {
    trace,
    traceDigest,
    traceIdentityKey: traceIdentityKey(trace),
    logicalProfileKey: logicalProfileKey(trace),
    executionKey: identity("tasc/assessment-execution/v2", {
      traceDigest,
      traceIdentityKey: traceIdentityKey(trace),
    }),
    split,
    splitBucket: resolved?.bucket ?? null,
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

function canonicalEqual(left: unknown, right: unknown): boolean {
  return canonicalJson(left) === canonicalJson(right);
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

function validatePairMetadata(records: readonly TraceRecord[]): void {
  const groupSplits = new Map<string, AssessmentSplit>();
  for (const record of records) {
    const priorSplit = groupSplits.get(record.trace.groupId);
    if (priorSplit !== undefined && priorSplit !== record.split) {
      throw new Error(`cross-split group leakage for "${record.trace.groupId}"`);
    }
    groupSplits.set(record.trace.groupId, record.split);
  }

  for (const recordsForPair of groupBy(records, ({ trace }) => pairKey(trace)).values()) {
    const baseline = recordsForPair[0].trace;
    const baselineSlices = sortStrings(baseline.slices);
    for (const { trace } of recordsForPair.slice(1)) {
      if (trace.groupId !== baseline.groupId) {
        throw new Error("paired profile executions have conflicting group identity");
      }
      if (trace.split !== baseline.split) {
        throw new Error("paired profile executions have conflicting split");
      }
      if (
        trace.workload.declaredTrafficWeight
          !== baseline.workload.declaredTrafficWeight
      ) {
        throw new Error("paired profile executions have conflicting traffic weight");
      }
      if (!canonicalEqual(trace.workload, baseline.workload)) {
        throw new Error("paired profile executions have conflicting workload identity");
      }
      if (!canonicalEqual(sortStrings(trace.slices), baselineSlices)) {
        throw new Error("paired profile executions have conflicting slice identity");
      }
      if (!canonicalEqual(trace.routeSignal, baseline.routeSignal)) {
        throw new Error("paired profile executions have conflicting paired route-signal");
      }
      if (trace.policyDigest !== baseline.policyDigest) {
        throw new Error("paired profile executions have conflicting policy digest");
      }
      if (
        trace.collectionWindowId !== baseline.collectionWindowId
        || trace.collectionWindowMembershipDigest
          !== baseline.collectionWindowMembershipDigest
      ) {
        throw new Error("paired profile executions have conflicting window identity");
      }
    }
  }
}

function normalizeInauthenticEvidence(value: unknown): {
  evidence: EvaluatorEvidence | null;
  evidenceDigest: string | null;
} {
  try {
    const snapshot = snapshotBoundedContractInput(value);
    if (
      snapshot === null
      || typeof snapshot !== "object"
      || !Object.hasOwn(snapshot, "evidence")
    ) {
      return { evidence: null, evidenceDigest: null };
    }
    const evidence = normalizeEvaluatorEvidence(
      (snapshot as { evidence: unknown }).evidence,
    );
    return {
      evidence,
      evidenceDigest: fingerprintNormalizedEvaluatorEvidence(evidence),
    };
  } catch {
    return { evidence: null, evidenceDigest: null };
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

function diagnosticForEvidence(
  evidence: EvaluatorEvidence | null,
  evidenceDigest: string | null,
  reason: string,
): EvidenceDiagnostic {
  return {
    evidenceDigest,
    traceId: evidence?.traceId ?? null,
    profileId: evidence?.profileId ?? null,
    reason,
  };
}

function sortDiagnostics<T>(values: T[]): T[] {
  return values.sort((left, right) =>
    compareCodeUnits(canonicalJson(left), canonicalJson(right))
  );
}

function terminalStatus(trace: TraceEnvelope): "success" | "failure" | "aborted" {
  return trace.attempts[trace.attempts.length - 1].status;
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
    && canonicalEqual(trace.terminalOutputId, evidence.terminalOutputId)
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
  assertJoinBudget(
    traceRows,
    evidenceRows,
    traceRows === 0 ? 0 : 1,
    workBudget,
  );
  const traceSnapshot = snapshotCollection(traceCollection);
  const verificationSnapshot = snapshotCollection(evidenceCollection);

  const protocol = parseExperimentProtocol(protocolInput, workBudget);
  const protocolDigest = fingerprintProtocol(protocol);
  const traces = normalizeTraces(
    protocol,
    protocolDigest,
    traceSnapshot,
    workBudget,
    evidenceRows,
  );

  const duplicateTraces: DuplicateTraceDiagnostic[] = [];
  const conflictingTraces: ConflictingTraceDiagnostic[] = [];
  const traceRecords = retainUniqueTraceRecords(
    traces.map((trace) => makeTraceRecord(protocol, trace)),
    duplicateTraces,
    conflictingTraces,
  );
  validatePairMetadata(traceRecords);

  const invalidEvidence: EvidenceDiagnostic[] = [];
  const orphanEvidence: EvidenceDiagnostic[] = [];
  const duplicateEvidence: DuplicateEvidenceDiagnostic[] = [];
  const conflictingEvidence: ConflictingEvidenceDiagnostic[] = [];
  const missingEvidence: MissingEvidenceDiagnostic[] = [];
  const abstainedEvidence: AbstainedEvidenceDiagnostic[] = [];
  const authenticRecords: EvidenceRecord[] = [];

  for (const input of verificationSnapshot) {
    if (!isAuthenticEvaluatorEvidenceVerification(input)) {
      const normalized = normalizeInauthenticEvidence(input);
      invalidEvidence.push(diagnosticForEvidence(
        normalized.evidence,
        normalized.evidenceDigest,
        "inauthentic-verification-receipt",
      ));
      continue;
    }
    const evidence = normalizeEvaluatorEvidence(input.evidence);
    const evidenceDigest = fingerprintNormalizedEvaluatorEvidence(evidence);
    if (
      input.evidenceDigest !== evidenceDigest
      || input.keyId !== evidence.keyId
      || input.trusted !== (input.status === "trusted")
    ) {
      invalidEvidence.push(diagnosticForEvidence(
        evidence,
        evidenceDigest,
        "verification-receipt-integrity-conflict",
      ));
      continue;
    }
    if (!input.trusted) {
      invalidEvidence.push(diagnosticForEvidence(
        evidence,
        evidenceDigest,
        `verification-${input.status}`,
      ));
      continue;
    }
    if (!protocol.evaluator.requiredTrustedKeyIds.includes(evidence.keyId)) {
      invalidEvidence.push(diagnosticForEvidence(
        evidence,
        evidenceDigest,
        "evaluator-key-not-pinned-by-protocol",
      ));
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
      invalidEvidence.push(diagnosticForEvidence(
        evidence,
        evidenceDigest,
        "evaluator-or-rubric-or-calibration-or-producer-drift",
      ));
      continue;
    }
    authenticRecords.push({
      evidence,
      evidenceDigest,
      joinKey: evidenceJoinKey(evidence),
      contextIdentity: verificationContextIdentity(input),
    });
  }

  const contextIdentities = sortStrings([
    ...new Set(authenticRecords.map(({ contextIdentity }) => contextIdentity)),
  ]);
  let identityStableRecords = authenticRecords;
  if (contextIdentities.length > 1) {
    for (const record of authenticRecords) {
      invalidEvidence.push(diagnosticForEvidence(
        record.evidence,
        record.evidenceDigest,
        "verification-context-drift",
      ));
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
        reason: "multiple-distinct-evidence-rows-for-join-key",
      });
      continue;
    }
    nonConflictingEvidence.push(records[0]);
  }

  const tracesByIdentity = new Map(
    traceRecords.map((record) => [record.traceIdentityKey, record]),
  );
  const tracesByTraceAndProfile = groupBy(
    traceRecords,
    ({ trace }) => identity("tasc/assessment-trace-profile/v2", {
      protocolDigest: trace.protocolDigest,
      traceId: trace.traceId,
      profileId: trace.profileId,
    }),
  );
  const evidenceByExecution = new Map<string, EvidenceRecord>();
  const invalidOutcomeByExecution = new Map<string, {
    kind: "missing-evidence" | "invalid-evidence" | "abstained";
    reasonCode: string;
    evidence: EvaluatorEvidence;
    evidenceDigest: string;
  }>();

  for (const record of nonConflictingEvidence.sort((left, right) =>
    compareEvidenceIdentities(left.evidenceDigest, right.evidenceDigest)
  )) {
    const trace = tracesByIdentity.get(record.joinKey);
    if (trace === undefined) {
      const traceProfileKey = identity("tasc/assessment-trace-profile/v2", {
        protocolDigest: record.evidence.protocolDigest,
        traceId: record.evidence.traceId,
        profileId: record.evidence.profileId,
      });
      const partialMatches = tracesByTraceAndProfile.get(traceProfileKey) ?? [];
      const reason = partialMatches.some(
          ({ trace: partial }) => terminalStatus(partial) !== "success",
        )
        ? "evidence-for-failed-execution"
        : partialMatches.length > 0
        ? "terminal-output-mismatch"
        : "no-matching-trace";
      orphanEvidence.push(diagnosticForEvidence(
        record.evidence,
        record.evidenceDigest,
        reason,
      ));
      continue;
    }
    if (!traceLineageMatches(trace.trace, record.evidence)) {
      conflictingEvidence.push({
        joinKey: record.joinKey,
        evidenceDigests: [record.evidenceDigest],
        reason: "trace-evidence-lineage-conflict",
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
      ));
    }
  }

  const executions: AssessmentExecutionRow[] = [];
  for (const record of traceRecords) {
    const status = terminalStatus(record.trace);
    let outcome: AssessmentExecutionOutcome;
    if (status !== "success") {
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
        };
      } else if (nonScored !== undefined) {
        outcome = {
          kind: nonScored.kind,
          reasonCode: nonScored.reasonCode,
          evidenceDigest: nonScored.evidenceDigest,
          evidence: nonScored.evidence,
        };
      } else {
        const hasConflict = conflictingEvidence.some(
          ({ joinKey: key }) => key === record.traceIdentityKey,
        );
        const hasDuplicate = duplicateEvidence.some(
          ({ joinKey: key }) => key === record.traceIdentityKey,
        );
        outcome = {
          kind: hasConflict || hasDuplicate
            ? "invalid-evidence"
            : "missing-evidence",
          reasonCode: hasConflict
            ? "conflicting-evidence"
            : hasDuplicate
            ? "duplicate-evidence"
            : "successful-execution-without-trusted-evidence",
          evidenceDigest: null,
          evidence: null,
        };
        missingEvidence.push({
          executionKey: record.executionKey,
          traceId: record.trace.traceId,
          profileId: record.trace.profileId,
          reason: outcome.reasonCode,
        });
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
    compareEvidenceIdentities(left.executionKey, right.executionKey)
  );

  const requiredProfileIds = sortStrings([
    protocol.championProfileId,
    ...protocol.candidateProfileIds,
  ]);
  const missingProfileExecutions: MissingProfileDiagnostic[] = [];
  const pairs: AssessmentPair[] = [];
  const pairGroups = [...groupBy(traceRecords, ({ trace }) => pairKey(trace)).values()]
    .sort((left, right) =>
      compareEvidenceIdentities(pairKey(left[0].trace), pairKey(right[0].trace))
    );
  for (const records of pairGroups) {
    const baseline = records[0].trace;
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
      pairKey: pairKey(baseline),
      caseId: baseline.caseId,
      replicateId: baseline.replicateId,
      groupId: baseline.groupId,
      split: baseline.split,
      declaredTrafficWeight: baseline.workload.declaredTrafficWeight,
      slices: sortStrings(baseline.slices),
      profileIds: requiredProfileIds,
      executionKeys: sortStrings(records.map(({ executionKey }) => executionKey)),
    });
  }

  const logicalUnits = pairGroups.map((records) => records[0].trace);
  const trafficMass = logicalUnits.reduce(
    (total, trace) => total + trace.workload.declaredTrafficWeight,
    0,
  );
  if (!Number.isFinite(trafficMass)) {
    throw new Error("observed traffic mass exceeds the finite numeric range");
  }
  const cases = new Set(logicalUnits.map(({ caseId }) => caseId));
  const groups = new Set(logicalUnits.map(({ groupId }) => groupId));
  const splits = sortStrings([
    ...new Set(logicalUnits.map(({ split }) => split)),
  ] as string[]).map((splitValue) => {
    const split = splitValue as AssessmentSplit;
    const members = logicalUnits.filter((trace) => trace.split === split);
    const mass = members.reduce(
      (total, trace) => total + trace.workload.declaredTrafficWeight,
      0,
    );
    if (!Number.isFinite(mass)) {
      throw new Error("split traffic mass exceeds the finite numeric range");
    }
    return {
      split,
      caseReplicates: members.length,
      groups: new Set(members.map(({ groupId }) => groupId)).size,
      observedTrafficMass: mass,
    };
  });
  const sliceIds = sortStrings([
    ...new Set(logicalUnits.flatMap(({ slices }) => slices)),
  ]);
  const slices = sliceIds.map((sliceId) => {
    const members = logicalUnits.filter(({ slices: labels }) =>
      labels.includes(sliceId)
    );
    return {
      sliceId,
      caseReplicates: members.length,
      groups: new Set(members.map(({ groupId }) => groupId)).size,
    };
  });
  const diagnostics = {
    missingEvidence: sortDiagnostics(missingEvidence),
    invalidEvidence: sortDiagnostics(invalidEvidence),
    abstainedEvidence: sortDiagnostics(abstainedEvidence),
    orphanEvidence: sortDiagnostics(orphanEvidence),
    duplicateEvidence: sortDiagnostics(duplicateEvidence),
    conflictingEvidence: sortDiagnostics(conflictingEvidence),
    duplicateTraces: sortDiagnostics(duplicateTraces),
    conflictingTraces: sortDiagnostics(conflictingTraces),
    missingProfileExecutions: sortDiagnostics(missingProfileExecutions),
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

  return deepFreezeContract({
    version: "tasc-assessment-dataset-v2",
    studyId: protocol.studyId,
    protocolDigest,
    splitIdentity: protocol.splitMembership,
    evaluatorIdentity: protocol.evaluator,
    requiredProfileIds,
    verificationContextIdentities: contextIdentities,
    executions,
    pairs,
    counts: {
      traceRows,
      acceptedTraceRows: traceRecords.length,
      evidenceRows,
      matchedRows: executions.filter(({ outcome }) => outcome.evidence !== null).length,
      scoredRows: executions.filter(({ outcome }) =>
        outcome.kind === "scored"
      ).length,
      pairedCaseReplicates: pairs.length,
      cases: cases.size,
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
  });
}
