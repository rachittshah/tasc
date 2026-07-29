import type { KeyObject } from "node:crypto";
import {
  fingerprintProtocol,
  parseExperimentProtocol,
  type ExperimentProtocol,
} from "../../src/evidence.js";
import {
  resolveGroupSplit,
  type AssessmentDatasetForSplit,
} from "../../src/evidence-join.js";
import type { EvaluatorTrustSnapshot } from "../../src/evaluator-trust.js";
import {
  assertPolicyBundleMatchesProtocol,
  type PolicyBundle,
} from "../../src/policy.js";
import {
  assertWindowManifestMatchesProtocol,
  deriveWindowMembershipDigest,
  fingerprintWindowManifest,
  parseWindowManifest,
  type WindowManifest,
} from "../../src/window.js";
import {
  TEST_WORK_BUDGET,
  evaluatorKeyFixture,
  keyedIdentity,
  signDispatchIntent,
  signEvaluatorEvidence,
  unsignedEvaluatorEvidence,
  validAssessmentContextInput,
  validCollectionBinding,
  validProtocolInput,
  validTraceInputForProfile,
} from "./evidence.js";

export type CliV2AssessmentSplit = "dev" | "holdout" | "online";
type CliV2OfflineAssessmentSplit = Exclude<
  CliV2AssessmentSplit,
  "online"
>;

export const CLI_V2_WINDOW_ID = "cli-v2-window-1";
export const CLI_V2_WINDOW_EVENT_START = "2026-07-23T00:00:00.000Z";
export const CLI_V2_WINDOW_EVENT_END = "2026-07-23T00:01:00.000Z";
export const CLI_V2_WINDOW_WATERMARK = "2026-07-23T00:02:00.000Z";
export const CLI_V2_WINDOW_ASSESSMENT_TIME = "2026-07-23T00:03:00.000Z";

type RawProtocolInput = ReturnType<typeof validProtocolInput>;
type BaseRawTraceInput = ReturnType<typeof validTraceInputForProfile>;
type RawTraceInput<
  Split extends CliV2AssessmentSplit = CliV2AssessmentSplit,
> = Omit<
  BaseRawTraceInput,
  | "split"
  | "sourceMode"
  | "collectionBinding"
  | "collectionWindowId"
  | "collectionWindowMembershipDigest"
> & {
  split: Split;
  sourceMode: "imported" | "observed" | "shadow";
  collectionBinding:
    | ReturnType<typeof validCollectionBinding>
    | null;
  collectionWindowId: string | null;
  collectionWindowMembershipDigest: string | null;
};
type RawEvidenceInput = ReturnType<typeof signEvaluatorEvidence>;
type RawAssessmentContextInput = ReturnType<
  typeof validAssessmentContextInput
>;

export interface CliV2AssessmentSplitFixture<
  Split extends CliV2AssessmentSplit = CliV2AssessmentSplit,
> {
  readonly split: Split;
  readonly contextInput: RawAssessmentContextInput;
  readonly traceRows: readonly RawTraceInput<Split>[];
  readonly evidenceRows: readonly RawEvidenceInput[];
}

/**
 * One JSON-compatible fixture set for the complete development-to-holdout CLI
 * workflow. Both splits share the same operator trust snapshot, while the
 * evaluator private key remains local to construction and is never returned.
 */
export interface CliV2AssessmentFixtureSet {
  readonly protocolInput: RawProtocolInput;
  readonly trustSnapshot: EvaluatorTrustSnapshot;
  readonly development: CliV2AssessmentSplitFixture<"dev">;
  readonly holdout: CliV2AssessmentSplitFixture<"holdout">;
}

export interface CliV2OnlineAssessmentFixture {
  readonly protocolInput: RawProtocolInput;
  readonly trustSnapshot: EvaluatorTrustSnapshot;
  readonly online: CliV2AssessmentSplitFixture<"online">;
}

function relaxedProtocolInput(): RawProtocolInput {
  const input = validProtocolInput();
  input.gates = {
    ...input.gates,
    minimumMeanScore: 0.5,
    nonInferiorityMargin: -0.1,
    maximumFailureRate: 0.5,
    maximumP95TtftMs: 10_000,
    maximumP95EndToEndMs: 20_000,
    maximumCostPerThousandRequestsUsd: 100,
    minimumEvidenceCoverage: 1,
    minimumIndependentGroups: 1,
    minimumCriticalSliceGroups: 0,
    serviceCapacity: {
      kind: "disabled",
    },
  };
  input.criticalSlices = [];
  input.bootstrap.iterations = 32;
  input.candidatePolicySpace.maxCandidates = 4;
  input.onlineWindowMembership.sampleBasisPoints = 10_000;
  return input;
}

function groupForSplit(
  protocol: ExperimentProtocol,
  split: CliV2AssessmentSplit,
): string {
  for (let index = 0; index < 10_000; index += 1) {
    const groupId = `cli-v2-${split}-group-${index}`;
    if (resolveGroupSplit(protocol, groupId).split === split) return groupId;
  }
  throw new Error(`unable to create ${split} group fixture`);
}

function signedEvidenceForTrace(
  privateKey: KeyObject,
  trace: RawTraceInput,
  producedAt?: string,
): RawEvidenceInput {
  const unsigned = unsignedEvaluatorEvidence() as Record<string, unknown>;
  unsigned.studyId = trace.studyId;
  unsigned.protocolDigest = trace.protocolDigest;
  unsigned.traceId = trace.traceId;
  unsigned.caseId = trace.caseId;
  unsigned.replicateId = trace.replicateId;
  unsigned.profileId = trace.profileId;
  unsigned.split = trace.split;
  unsigned.terminalOutputId = structuredClone(trace.terminalOutputId);
  unsigned.outcome = {
    kind: "scored",
    score: 0.9,
    range: {
      minimum: 0,
      maximum: 1,
    },
    subscores: [],
  };
  if (producedAt !== undefined) unsigned.producedAt = producedAt;
  return signEvaluatorEvidence(privateKey, unsigned);
}

function splitRows<Split extends CliV2OfflineAssessmentSplit>(
  split: Split,
  protocol: ExperimentProtocol,
  privateKey: KeyObject,
  trustSnapshot: EvaluatorTrustSnapshot,
): CliV2AssessmentSplitFixture<Split> {
  const protocolDigest = fingerprintProtocol(protocol);
  const groupId = groupForSplit(protocol, split);
  const traceRows = (
    ["champion", "candidate"] as const
  ).map((profileId, profileIndex) => {
    const trace = validTraceInputForProfile(
      profileId,
    ) as unknown as RawTraceInput<Split>;
    trace.studyId = protocol.studyId;
    trace.protocolDigest = protocolDigest;
    trace.traceId = `cli-v2-${split}-${profileId}`;
    trace.caseId = `cli-v2-${split}-case`;
    trace.groupId = groupId;
    trace.replicateId = "replicate-0";
    trace.split = split;
    trace.collectionWindowId = null;
    trace.collectionWindowMembershipDigest = null;
    trace.slices = ["routine"];
    trace.routeSignal!.value = 0.9;
    trace.terminalOutputId = keyedIdentity(
      split === "dev"
        ? String(profileIndex + 1)
        : String(profileIndex + 3),
    );
    return signDispatchIntent(trace);
  });
  const evidenceRows = traceRows.map((trace) =>
    signedEvidenceForTrace(privateKey, trace)
  );

  return {
    split,
    contextInput: validAssessmentContextInput(trustSnapshot),
    traceRows,
    evidenceRows,
  };
}

function onlineRows(
  protocol: ExperimentProtocol,
  frozenPolicy: PolicyBundle,
  privateKey: KeyObject,
  trustSnapshot: EvaluatorTrustSnapshot,
): CliV2AssessmentSplitFixture<"online"> {
  const protocolDigest = fingerprintProtocol(protocol);
  const membershipDigest = deriveWindowMembershipDigest(
    CLI_V2_WINDOW_ID,
    protocolDigest,
    protocol.onlineWindowMembership,
  );
  const traceRows = (
    ["champion", "candidate"] as const
  ).map((profileId, profileIndex) => {
    const trace = validTraceInputForProfile(
      profileId,
    ) as unknown as RawTraceInput<"online">;
    trace.studyId = protocol.studyId;
    trace.protocolDigest = protocolDigest;
    trace.traceId = `cli-v2-online-${profileId}`;
    trace.caseId = "cli-v2-online-case";
    trace.groupId = "cli-v2-online-group";
    trace.replicateId = "replicate-0";
    trace.split = "online";
    trace.collectionWindowId = CLI_V2_WINDOW_ID;
    trace.collectionWindowMembershipDigest = membershipDigest;
    trace.sourceMode = "shadow";
    trace.collectionBinding = validCollectionBinding();
    trace.policyDigest = frozenPolicy.policyDigest;
    trace.slices = ["routine"];
    trace.routeSignal!.value = 0.9;
    trace.routeSignal!.provenance.observedAt = CLI_V2_WINDOW_EVENT_START;
    trace.attempts[0].observerTimings = {
      startedAt: CLI_V2_WINDOW_EVENT_START,
      headersAt: "2026-07-23T00:00:00.050Z",
      firstByteAt: "2026-07-23T00:00:00.060Z",
      firstMeaningfulTokenAt: "2026-07-23T00:00:00.075Z",
      completedAt: "2026-07-23T00:00:00.500Z",
    };
    trace.terminalOutputId = keyedIdentity(String(profileIndex + 5));
    return signDispatchIntent(trace);
  });
  const evidenceRows = traceRows.map((trace) =>
    signedEvidenceForTrace(
      privateKey,
      trace,
      "2026-07-23T00:01:00.000Z",
    )
  );
  const contextInput = validAssessmentContextInput(trustSnapshot);
  contextInput.asOf = CLI_V2_WINDOW_ASSESSMENT_TIME;

  return {
    split: "online",
    contextInput,
    traceRows,
    evidenceRows,
  };
}

export function createCliV2AssessmentFixtureSet(): CliV2AssessmentFixtureSet {
  const protocolInput = relaxedProtocolInput();
  const protocol = parseExperimentProtocol(
    protocolInput,
    TEST_WORK_BUDGET,
  );
  const evaluatorKey = evaluatorKeyFixture();

  return {
    protocolInput,
    trustSnapshot: evaluatorKey.trustSnapshot,
    development: splitRows(
      "dev",
      protocol,
      evaluatorKey.privateKey,
      evaluatorKey.trustSnapshot,
    ),
    holdout: splitRows(
      "holdout",
      protocol,
      evaluatorKey.privateKey,
      evaluatorKey.trustSnapshot,
    ),
  };
}

/**
 * Construct online raw inputs only after the caller has frozen a policy.
 * A fresh evaluator key remains private to this call; the returned trust
 * snapshot is the sole authority needed to verify the signed raw rows.
 */
export function createCliV2OnlineAssessmentFixture(
  frozenPolicy: PolicyBundle,
): CliV2OnlineAssessmentFixture {
  const protocolInput = relaxedProtocolInput();
  const protocol = parseExperimentProtocol(
    protocolInput,
    TEST_WORK_BUDGET,
  );
  assertPolicyBundleMatchesProtocol(frozenPolicy, protocol);
  const evaluatorKey = evaluatorKeyFixture();

  return {
    protocolInput,
    trustSnapshot: evaluatorKey.trustSnapshot,
    online: onlineRows(
      protocol,
      frozenPolicy,
      evaluatorKey.privateKey,
      evaluatorKey.trustSnapshot,
    ),
  };
}

/**
 * Seal the exact joined source multisets for the fixture's bounded online
 * interval. The returned manifest is already self-digest verified and checked
 * against both the protocol and chosen frozen policy.
 */
export function createCliV2WindowManifest(
  protocol: ExperimentProtocol,
  frozenPolicy: PolicyBundle,
  dataset: AssessmentDatasetForSplit<"online">,
): WindowManifest {
  assertPolicyBundleMatchesProtocol(frozenPolicy, protocol);
  const protocolDigest = fingerprintProtocol(protocol);
  if (dataset.protocolDigest !== protocolDigest) {
    throw new Error("online fixture dataset does not match protocol");
  }
  const body = {
    version: "tasc-window-manifest-v2" as const,
    windowId: CLI_V2_WINDOW_ID,
    protocolDigest,
    frozenPolicyDigest: frozenPolicy.policyDigest,
    eventTimeStartInclusive: CLI_V2_WINDOW_EVENT_START,
    eventTimeEndExclusive: CLI_V2_WINDOW_EVENT_END,
    ingestionWatermark: CLI_V2_WINDOW_WATERMARK,
    closureReason: "scheduled",
    membershipRule: protocol.onlineWindowMembership,
    membershipDigest: deriveWindowMembershipDigest(
      CLI_V2_WINDOW_ID,
      protocolDigest,
      protocol.onlineWindowMembership,
    ),
    revision: 1,
    predecessorManifestDigest: null,
    traceSetDigest: dataset.traceSetDigest,
    evaluatorSetDigest: dataset.evaluatorSetDigest,
    capacityEvidence: {
      kind: "unavailable" as const,
      reasonCode: "not-collected",
    },
  };
  const manifest = parseWindowManifest({
    ...body,
    selfDigest: fingerprintWindowManifest(body),
  });
  assertWindowManifestMatchesProtocol(
    manifest,
    protocol,
    frozenPolicy.policyDigest,
  );
  return manifest;
}

export function assessmentFixtureForSplit<
  Split extends CliV2OfflineAssessmentSplit,
>(
  fixtures: CliV2AssessmentFixtureSet,
  split: Split,
): CliV2AssessmentSplitFixture<Split> {
  return (
    split === "dev" ? fixtures.development : fixtures.holdout
  ) as CliV2AssessmentSplitFixture<Split>;
}
