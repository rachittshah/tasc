import { z } from "zod";
import { canonicalJson } from "./determinism.js";
import {
  contractDigestSchema,
  contractSlugSchema,
  contractTimestampSchema,
  deepFreezeContract,
  domainSeparatedDigest,
  fingerprintNormalizedProtocol,
  normalizeEvaluatorEvidence,
  normalizeExperimentProtocol,
  parseTraceEnvelopeValue,
  snapshotBoundedContractInput,
  type DeepReadonly,
  type EvaluatorEvidence,
  type ExperimentProtocol,
  type TraceEnvelope,
} from "./evidence.js";

const WINDOW_MANIFEST_DIGEST_DOMAIN = "tasc/window-manifest/v2";
const WINDOW_MEMBERSHIP_DIGEST_DOMAIN = "tasc/window-membership-rule/v2";
const WINDOW_MEMBERSHIP_BUCKET_DOMAIN =
  "tasc/seeded-sha256-case-replicate-basis-points/v1";
const BASIS_POINT_BUCKET_COUNT = 10_000n;

const safePositiveIntegerSchema = z.number()
  .int()
  .min(1)
  .max(Number.MAX_SAFE_INTEGER);

const finiteNonNegativeSchema = z.number().finite().nonnegative();

const windowMembershipRuleSchema = z.object({
  algorithm: z.literal(
    "tasc-seeded-sha256-case-replicate-basis-points-v1",
  ),
  seed: contractSlugSchema,
  sampleBasisPoints: z.number().int().min(0).max(10_000),
}).strict();

const unavailableCapacityEvidenceSchema = z.object({
  kind: z.literal("unavailable"),
  reasonCode: contractSlugSchema,
}).strict();

const reportedCapacityEvidenceSchema = z.object({
  kind: z.literal("reported"),
  metric: z.literal("aggregate-output-tokens-per-second"),
  value: finiteNonNegativeSchema,
  source: z.literal("operator-reported"),
  declarationDigest: contractDigestSchema,
  frozenPolicyDigest: contractDigestSchema,
  eventTimeStartInclusive: contractTimestampSchema,
  eventTimeEndExclusive: contractTimestampSchema,
}).strict();

const windowCapacityEvidenceSchema = z.discriminatedUnion("kind", [
  unavailableCapacityEvidenceSchema,
  reportedCapacityEvidenceSchema,
]);

const windowManifestBodySchema = z.object({
  version: z.literal("tasc-window-manifest-v2"),
  windowId: contractSlugSchema,
  protocolDigest: contractDigestSchema,
  frozenPolicyDigest: contractDigestSchema,
  eventTimeStartInclusive: contractTimestampSchema,
  eventTimeEndExclusive: contractTimestampSchema,
  ingestionWatermark: contractTimestampSchema,
  closureReason: contractSlugSchema,
  membershipRule: windowMembershipRuleSchema,
  membershipDigest: contractDigestSchema,
  revision: safePositiveIntegerSchema,
  predecessorManifestDigest: contractDigestSchema.nullable(),
  traceSetDigest: contractDigestSchema,
  evaluatorSetDigest: contractDigestSchema,
  capacityEvidence: windowCapacityEvidenceSchema,
}).strict();

const windowManifestSchema = windowManifestBodySchema.extend({
  selfDigest: contractDigestSchema,
}).strict();

const windowManifestRevisionChangesSchema = z.object({
  ingestionWatermark: contractTimestampSchema,
  closureReason: contractSlugSchema,
  traceSetDigest: contractDigestSchema,
  evaluatorSetDigest: contractDigestSchema,
  capacityEvidence: windowCapacityEvidenceSchema,
}).strict();

const membershipBindingSchema = z.object({
  windowId: contractSlugSchema,
  protocolDigest: contractDigestSchema,
  membershipRule: windowMembershipRuleSchema,
}).strict();

const membershipSelectionSchema = z.object({
  membershipRule: windowMembershipRuleSchema,
  caseId: contractSlugSchema,
  replicateId: contractSlugSchema,
}).strict();

type MutableWindowMembershipRule = z.infer<typeof windowMembershipRuleSchema>;
type MutableWindowCapacityEvidence = z.infer<
  typeof windowCapacityEvidenceSchema
>;
type MutableWindowManifestBody = z.infer<typeof windowManifestBodySchema>;
type MutableWindowManifest = z.infer<typeof windowManifestSchema>;
type MutableWindowManifestRevisionChanges = z.infer<
  typeof windowManifestRevisionChangesSchema
>;

export type WindowMembershipRule = DeepReadonly<
  MutableWindowMembershipRule
>;
export type WindowCapacityEvidence = DeepReadonly<
  MutableWindowCapacityEvidence
>;
export type WindowManifestBody = DeepReadonly<MutableWindowManifestBody>;
export type WindowManifest = DeepReadonly<MutableWindowManifest>;
export type WindowManifestRevisionChanges = DeepReadonly<
  MutableWindowManifestRevisionChanges
>;

function digestNormalizedWindowManifest(
  body: MutableWindowManifestBody,
): string {
  return domainSeparatedDigest(WINDOW_MANIFEST_DIGEST_DOMAIN, body);
}

function digestNormalizedMembershipBinding(
  binding: z.infer<typeof membershipBindingSchema>,
): string {
  return domainSeparatedDigest(WINDOW_MEMBERSHIP_DIGEST_DOMAIN, binding);
}

function assertWindowManifestBodySemantics(
  body: MutableWindowManifestBody,
): void {
  const start = Date.parse(body.eventTimeStartInclusive);
  const end = Date.parse(body.eventTimeEndExclusive);
  const watermark = Date.parse(body.ingestionWatermark);
  if (start >= end) {
    throw new Error(
      "window event-time start must be strictly before its exclusive end",
    );
  }
  if (end > watermark) {
    throw new Error(
      "window event-time end must not be after the ingestion watermark",
    );
  }

  if (body.revision === 1 && body.predecessorManifestDigest !== null) {
    throw new Error("window manifest revision 1 predecessor must be null");
  }
  if (body.revision > 1 && body.predecessorManifestDigest === null) {
    throw new Error(
      "window manifest revision greater than 1 requires a predecessor digest",
    );
  }

  const expectedMembershipDigest = digestNormalizedMembershipBinding({
    windowId: body.windowId,
    protocolDigest: body.protocolDigest,
    membershipRule: body.membershipRule,
  });
  if (body.membershipDigest !== expectedMembershipDigest) {
    throw new Error("window membership digest mismatch");
  }

  if (body.capacityEvidence.kind === "reported") {
    if (
      body.capacityEvidence.frozenPolicyDigest !== body.frozenPolicyDigest
    ) {
      throw new Error(
        "reported window capacity is bound to a different frozen policy",
      );
    }
    if (
      body.capacityEvidence.eventTimeStartInclusive
        !== body.eventTimeStartInclusive
      || body.capacityEvidence.eventTimeEndExclusive
        !== body.eventTimeEndExclusive
    ) {
      throw new Error(
        "reported window capacity event bounds must exactly match the manifest",
      );
    }
  }
}

function bodyWithoutSelfDigest(
  manifest: MutableWindowManifest,
): MutableWindowManifestBody {
  const { selfDigest: _selfDigest, ...body } = manifest;
  return body;
}

/**
 * Derive the identity traces must declare for one exact window, protocol, and
 * online sampling rule.
 */
export function deriveWindowMembershipDigest(
  windowId: string,
  protocolDigest: string,
  membershipRule: WindowMembershipRule,
): string {
  const snapshot = snapshotBoundedContractInput({
    windowId,
    protocolDigest,
    membershipRule,
  });
  const binding = membershipBindingSchema.parse(snapshot);
  return digestNormalizedMembershipBinding(binding);
}

function membershipBucketForNormalizedSelection(
  selection: z.infer<typeof membershipSelectionSchema>,
): number {
  const digest = domainSeparatedDigest(
    WINDOW_MEMBERSHIP_BUCKET_DOMAIN,
    {
      algorithm: selection.membershipRule.algorithm,
      caseId: selection.caseId,
      replicateId: selection.replicateId,
      seed: selection.membershipRule.seed,
    },
  );
  const fullDigest = BigInt(`0x${digest.slice("sha256:".length)}`);
  return Number(fullDigest % BASIS_POINT_BUCKET_COUNT);
}

/**
 * Resolve a stable basis-point bucket from the complete SHA-256 integer. No
 * lossy IEEE-754 conversion or truncated digest participates in sampling.
 */
export function deriveWindowMembershipBucket(
  membershipRule: WindowMembershipRule,
  caseId: string,
  replicateId: string,
): number {
  const snapshot = snapshotBoundedContractInput({
    membershipRule,
    caseId,
    replicateId,
  });
  const selection = membershipSelectionSchema.parse(snapshot);
  return membershipBucketForNormalizedSelection(selection);
}

export function isWindowMembershipSelected(
  membershipRule: WindowMembershipRule,
  caseId: string,
  replicateId: string,
): boolean {
  const snapshot = snapshotBoundedContractInput({
    membershipRule,
    caseId,
    replicateId,
  });
  const selection = membershipSelectionSchema.parse(snapshot);
  return (
    membershipBucketForNormalizedSelection(selection)
      < selection.membershipRule.sampleBasisPoints
  );
}

/**
 * Fingerprint the canonical manifest body. A supplied selfDigest is omitted
 * from its own preimage, so callers can recompute and verify persisted values.
 */
export function fingerprintWindowManifest(input: unknown): string {
  const snapshot = snapshotBoundedContractInput(input);
  const manifestResult = windowManifestSchema.safeParse(snapshot);
  const body = manifestResult.success
    ? bodyWithoutSelfDigest(manifestResult.data)
    : windowManifestBodySchema.parse(snapshot);
  assertWindowManifestBodySemantics(body);
  return digestNormalizedWindowManifest(body);
}

export function parseWindowManifest(input: unknown): WindowManifest {
  const snapshot = snapshotBoundedContractInput(input);
  const manifest = windowManifestSchema.parse(snapshot);
  const body = bodyWithoutSelfDigest(manifest);
  assertWindowManifestBodySemantics(body);
  const expectedSelfDigest = digestNormalizedWindowManifest(body);
  if (manifest.selfDigest !== expectedSelfDigest) {
    throw new Error("window manifest self digest mismatch");
  }
  return deepFreezeContract(manifest);
}

function sameMembershipRule(
  left: WindowMembershipRule,
  right: ExperimentProtocol["onlineWindowMembership"],
): boolean {
  return (
    left.algorithm === right.algorithm
    && left.seed === right.seed
    && left.sampleBasisPoints === right.sampleBasisPoints
  );
}

/**
 * Verify the identities that a window assessment receives separately. The
 * protocol is normalized once before its digest and sampling rule are used.
 */
export function assertWindowManifestMatchesProtocol(
  inputManifest: WindowManifest,
  inputProtocol: ExperimentProtocol,
  frozenPolicyDigest: string,
): void {
  const manifest = parseWindowManifest(inputManifest);
  const protocol = normalizeExperimentProtocol(inputProtocol);
  const normalizedPolicyDigest = contractDigestSchema.parse(
    snapshotBoundedContractInput(frozenPolicyDigest),
  );

  if (manifest.protocolDigest !== fingerprintNormalizedProtocol(protocol)) {
    throw new Error("window manifest protocol digest mismatch");
  }
  if (!sameMembershipRule(
    manifest.membershipRule,
    protocol.onlineWindowMembership,
  )) {
    throw new Error(
      "window manifest membership rule does not match the frozen protocol",
    );
  }
  if (manifest.frozenPolicyDigest !== normalizedPolicyDigest) {
    throw new Error("window manifest frozen policy digest mismatch");
  }
}

function snapshotTraceForWindow(input: TraceEnvelope): TraceEnvelope {
  return parseTraceEnvelopeValue(input);
}

function normalizedTraceEventTime(trace: TraceEnvelope): string {
  const firstAttempt = trace.attempts[0];
  if (firstAttempt === undefined) {
    throw new Error("window trace requires at least one attempt");
  }
  return firstAttempt.observerTimings.startedAt;
}

/** The first attempt's observer startedAt is the sole v2 window event time. */
export function traceEventTime(trace: TraceEnvelope): string {
  return normalizedTraceEventTime(snapshotTraceForWindow(trace));
}

/**
 * Recompute every trace/window relationship used by online assessment. Trace
 * declarations are evidence to verify, never authority for membership.
 */
export function assertTraceBelongsToWindow(
  inputTrace: TraceEnvelope,
  inputManifest: WindowManifest,
): void {
  const trace = snapshotTraceForWindow(inputTrace);
  const manifest = parseWindowManifest(inputManifest);
  if (trace.split !== "online") {
    throw new Error("window assessment accepts online traces only");
  }
  if (trace.protocolDigest !== manifest.protocolDigest) {
    throw new Error("trace protocol digest disagrees with window manifest");
  }
  if (trace.policyDigest !== manifest.frozenPolicyDigest) {
    throw new Error("trace policy digest disagrees with window manifest");
  }
  if (trace.collectionWindowId !== manifest.windowId) {
    throw new Error("trace collection window id disagrees with window manifest");
  }
  if (
    trace.collectionWindowMembershipDigest !== manifest.membershipDigest
  ) {
    throw new Error(
      "trace collection membership digest disagrees with window manifest",
    );
  }

  const eventTime = normalizedTraceEventTime(trace);
  const eventMilliseconds = Date.parse(eventTime);
  if (
    eventMilliseconds < Date.parse(manifest.eventTimeStartInclusive)
    || eventMilliseconds >= Date.parse(manifest.eventTimeEndExclusive)
  ) {
    throw new Error(
      "trace event time is outside the manifest's half-open event interval",
    );
  }
  const terminalAttempt = trace.attempts[trace.attempts.length - 1];
  if (
    Date.parse(terminalAttempt.observerTimings.completedAt)
      > Date.parse(manifest.ingestionWatermark)
  ) {
    throw new Error(
      "trace terminal completion is after the ingestion watermark; "
      + "seal a new window manifest revision for late data",
    );
  }

  const selection = membershipSelectionSchema.parse({
    membershipRule: manifest.membershipRule,
    caseId: trace.caseId,
    replicateId: trace.replicateId,
  });
  if (
    membershipBucketForNormalizedSelection(selection)
      >= selection.membershipRule.sampleBasisPoints
  ) {
    throw new Error("trace is excluded by the manifest sampling rule");
  }
}

/**
 * Accepted evaluator evidence is eligible for one sealed revision only when
 * its producer timestamp is at or before that revision's ingestion watermark.
 */
export function assertAcceptedEvaluatorEvidenceWithinWindowWatermark(
  inputEvidence: EvaluatorEvidence,
  inputManifest: WindowManifest,
): void {
  const evidence = normalizeEvaluatorEvidence(inputEvidence);
  const manifest = parseWindowManifest(inputManifest);
  if (
    Date.parse(evidence.producedAt)
      > Date.parse(manifest.ingestionWatermark)
  ) {
    throw new Error(
      "evaluator evidence was produced after the ingestion watermark; "
      + "seal a new window manifest revision for late data",
    );
  }
}

/**
 * Late evidence produces a new linked value. Only revision metadata, source
 * multiset digests, closure metadata, and capacity evidence may change.
 */
export function createWindowManifestRevision(
  inputPrevious: WindowManifest,
  inputChanges: WindowManifestRevisionChanges,
): WindowManifest {
  const previous = parseWindowManifest(inputPrevious);
  const changesSnapshot = snapshotBoundedContractInput(inputChanges);
  const changes = windowManifestRevisionChangesSchema.parse(changesSnapshot);
  if (
    Date.parse(changes.ingestionWatermark)
      < Date.parse(previous.ingestionWatermark)
  ) {
    throw new Error("window revision watermark must be nondecreasing");
  }
  if (
    changes.traceSetDigest === previous.traceSetDigest
    && changes.evaluatorSetDigest === previous.evaluatorSetDigest
    && canonicalJson(changes.capacityEvidence)
      === canonicalJson(previous.capacityEvidence)
  ) {
    throw new Error(
      "window revision source digests or capacity declaration must change "
      + "from the predecessor",
    );
  }
  if (previous.revision === Number.MAX_SAFE_INTEGER) {
    throw new Error("window manifest revision exceeds the safe integer limit");
  }

  const body: MutableWindowManifestBody = {
    version: previous.version,
    windowId: previous.windowId,
    protocolDigest: previous.protocolDigest,
    frozenPolicyDigest: previous.frozenPolicyDigest,
    eventTimeStartInclusive: previous.eventTimeStartInclusive,
    eventTimeEndExclusive: previous.eventTimeEndExclusive,
    ingestionWatermark: changes.ingestionWatermark,
    closureReason: changes.closureReason,
    membershipRule: previous.membershipRule,
    membershipDigest: previous.membershipDigest,
    revision: previous.revision + 1,
    predecessorManifestDigest: previous.selfDigest,
    traceSetDigest: changes.traceSetDigest,
    evaluatorSetDigest: changes.evaluatorSetDigest,
    capacityEvidence: changes.capacityEvidence,
  };
  assertWindowManifestBodySemantics(body);
  return parseWindowManifest({
    ...body,
    selfDigest: digestNormalizedWindowManifest(body),
  });
}
