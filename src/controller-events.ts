import { z } from "zod";
import { compareCodeUnits } from "./determinism.js";
import {
  contractDigestSchema,
  contractSlugSchema,
  deepFreezeContract,
  domainSeparatedDigest,
  snapshotBoundedContractInput,
  type DeepReadonly,
} from "./evidence.js";

const CONTROLLER_FACT_DIGEST_DOMAIN = "tasc/controller-fact/v1";
const CONTROLLER_EVENT_DIGEST_DOMAIN = "tasc/controller-event/v1";
const CONTROLLER_SNAPSHOT_DIGEST_DOMAIN = "tasc/controller-snapshot/v1";

export const MAX_CONTROLLER_EVENTS = 10_000;
export const MAX_CONTROLLER_ASSESSMENTS = 256;
export const MAX_CONTROLLER_WINDOWS = 64;
export const MAX_CONTROLLER_WINDOW_REVISIONS = 256;

const safeSequenceSchema = z.number()
  .int()
  .min(0)
  .max(MAX_CONTROLLER_EVENTS);

const boundedReasonCodeSchema = contractSlugSchema;

function isLeapYear(year: number): boolean {
  return year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
}

/**
 * Validate the controller's fixed-width UTC timestamp without consulting the
 * wall clock or constructing a Date. Fixed-width values can then be compared
 * by code unit during deterministic replay.
 */
function isExactControllerTimestamp(value: string): boolean {
  const match =
    /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})\.(\d{3})Z$/
      .exec(value);
  if (match === null) return false;
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const hour = Number(match[4]);
  const minute = Number(match[5]);
  const second = Number(match[6]);
  if (
    year < 1
    || month < 1
    || month > 12
    || hour > 23
    || minute > 59
    || second > 59
  ) {
    return false;
  }
  const monthLengths = [
    31,
    isLeapYear(year) ? 29 : 28,
    31,
    30,
    31,
    30,
    31,
    31,
    30,
    31,
    30,
    31,
  ];
  return day >= 1 && day <= monthLengths[month - 1];
}

export const controllerTimestampSchema = z.string()
  .length(24)
  .refine(
    isExactControllerTimestamp,
    "must be an exact real UTC RFC 3339 millisecond timestamp",
  );

export function compareControllerTimestamps(
  left: string,
  right: string,
): number {
  const parsedLeft = controllerTimestampSchema.parse(left);
  const parsedRight = controllerTimestampSchema.parse(right);
  return compareCodeUnits(parsedLeft, parsedRight);
}

export const controllerStateSchema = z.enum([
  "DRAFT",
  "REGISTERED",
  "COLLECTING",
  "DEV_READY",
  "NOMINATED",
  "SHADOW_ASSESSING",
  "HOLDOUT_CONFIRMED",
  "PROMOTION_RECOMMENDED",
  "MONITORING",
  "HOLD",
  "STALE",
  "ROLLBACK_RECOMMENDED",
  "RETIRED",
]);

const selectedPolicyProjectionSchema = z.object({
  policyDigest: contractDigestSchema,
  issuedAt: controllerTimestampSchema,
  expiresAt: controllerTimestampSchema,
}).strict().superRefine((value, context) => {
  if (compareCodeUnits(value.issuedAt, value.expiresAt) >= 0) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      message: "selected policy expiry must be after issue time",
    });
  }
});

const developmentAssessmentStatusSchema = z.enum([
  "NOMINATED",
  "NO_CANDIDATE",
  "INSUFFICIENT_EVIDENCE",
  "STALE",
]);
const holdoutOrWindowAssessmentStatusSchema = z.enum([
  "PASS",
  "HOLD",
  "INSUFFICIENT_EVIDENCE",
  "STALE",
]);

const assessmentProjectionBaseSchema = z.object({
  version: z.literal("tasc-controller-assessment-projection-v1"),
  decisionDigest: contractDigestSchema,
  assessmentContextDigest: contractDigestSchema,
  protocolDigest: contractDigestSchema,
  datasetDigest: contractDigestSchema,
  traceSetDigest: contractDigestSchema,
  evaluatorSetDigest: contractDigestSchema,
  selectedPolicy: selectedPolicyProjectionSchema.nullable(),
  attestation: z.literal("unattested"),
}).strict();

const developmentAssessmentProjectionSchema =
  assessmentProjectionBaseSchema.extend({
    phase: z.literal("development"),
    status: developmentAssessmentStatusSchema,
    windowManifestDigest: z.null(),
  }).strict();

const holdoutAssessmentProjectionSchema =
  assessmentProjectionBaseSchema.extend({
    phase: z.literal("holdout"),
    status: holdoutOrWindowAssessmentStatusSchema,
    windowManifestDigest: z.null(),
    selectedPolicy: selectedPolicyProjectionSchema,
  }).strict();

const windowAssessmentProjectionSchema =
  assessmentProjectionBaseSchema.extend({
    phase: z.literal("window"),
    status: holdoutOrWindowAssessmentStatusSchema,
    windowManifestDigest: contractDigestSchema,
    selectedPolicy: selectedPolicyProjectionSchema,
  }).strict();

export const controllerAssessmentProjectionSchema =
  z.union([
    developmentAssessmentProjectionSchema,
    holdoutAssessmentProjectionSchema,
    windowAssessmentProjectionSchema,
  ]).superRefine((value, context) => {
    if (value.phase !== "development") return;
    const hasPolicy = value.selectedPolicy !== null;
    if ((value.status === "NOMINATED") !== hasPolicy) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        message:
          "development nomination alone requires a selected policy projection",
      });
    }
  });

export const controllerWindowManifestProjectionSchema = z.object({
  version: z.literal("tasc-controller-window-projection-v1"),
  windowId: contractSlugSchema,
  manifestDigest: contractDigestSchema,
  protocolDigest: contractDigestSchema,
  frozenPolicyDigest: contractDigestSchema,
  eventTimeStartInclusive: controllerTimestampSchema,
  eventTimeEndExclusive: controllerTimestampSchema,
  ingestionWatermark: controllerTimestampSchema,
  revision: z.number()
    .int()
    .min(1)
    .max(Number.MAX_SAFE_INTEGER),
  predecessorManifestDigest: contractDigestSchema.nullable(),
  traceSetDigest: contractDigestSchema,
  evaluatorSetDigest: contractDigestSchema,
  capacityEvidenceDigest: contractDigestSchema,
}).strict().superRefine((value, context) => {
  if (
    compareCodeUnits(
      value.eventTimeStartInclusive,
      value.eventTimeEndExclusive,
    ) >= 0
  ) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      message: "window event-time start must be before its exclusive end",
    });
  }
  if (
    compareCodeUnits(value.eventTimeEndExclusive, value.ingestionWatermark) > 0
  ) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      message: "window watermark must be at or after its event-time end",
    });
  }
  if (
    (value.revision === 1) !== (value.predecessorManifestDigest === null)
  ) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      message: "window revision predecessor does not match its revision",
    });
  }
});

const developmentEvidenceProjectionSchema = z.object({
  datasetDigest: contractDigestSchema,
  traceSetDigest: contractDigestSchema,
  evaluatorSetDigest: contractDigestSchema,
}).strict();

const deploymentObservationProjectionSchema = z.object({
  source: z.literal("external-deployment-observation"),
  attestation: z.literal("unattested"),
  observationId: contractSlugSchema,
  environmentId: contractSlugSchema,
  policyDigest: contractDigestSchema,
  observedAt: controllerTimestampSchema,
}).strict();

const factVersion = z.literal("tasc-controller-fact-v1");

const protocolRegisteredFactSchema = z.object({
  version: factVersion,
  kind: z.literal("protocol-registered"),
  protocolCreatedAt: controllerTimestampSchema,
  protocolExpiresAt: controllerTimestampSchema,
}).strict();

const collectionStartedFactSchema = z.object({
  version: factVersion,
  kind: z.literal("collection-started"),
  collectionId: contractSlugSchema,
}).strict();

const developmentEvidenceReadyFactSchema = z.object({
  version: factVersion,
  kind: z.literal("development-evidence-ready"),
  evidence: developmentEvidenceProjectionSchema,
}).strict();

const developmentAssessmentRecordedFactSchema = z.object({
  version: factVersion,
  kind: z.literal("development-assessment-recorded"),
  projection: developmentAssessmentProjectionSchema,
}).strict();

const shadowAssessmentStartedFactSchema = z.object({
  version: factVersion,
  kind: z.literal("shadow-assessment-started"),
  frozenPolicyDigest: contractDigestSchema,
}).strict();

const holdoutAssessmentRecordedFactSchema = z.object({
  version: factVersion,
  kind: z.literal("holdout-assessment-recorded"),
  projection: holdoutAssessmentProjectionSchema,
}).strict();

const windowManifestRecordedFactSchema = z.object({
  version: factVersion,
  kind: z.literal("window-manifest-recorded"),
  projection: controllerWindowManifestProjectionSchema,
}).strict();

const windowAssessmentRecordedFactSchema = z.object({
  version: factVersion,
  kind: z.literal("window-assessment-recorded"),
  windowId: contractSlugSchema,
  projection: windowAssessmentProjectionSchema,
}).strict();

const deploymentObservedFactSchema = z.object({
  version: factVersion,
  kind: z.literal("deployment-observed"),
  observation: deploymentObservationProjectionSchema,
}).strict();

const identityDriftRecordedFactSchema = z.object({
  version: factVersion,
  kind: z.literal("identity-drift-recorded"),
  source: z.literal("operator-projection"),
  attestation: z.literal("unattested"),
  scope: z.enum([
    "evaluator",
    "execution-profile",
    "assessment-context",
    "source",
    "policy",
    "window",
  ]),
  expectedDigest: contractDigestSchema,
  observedDigest: contractDigestSchema,
  reasonCode: boundedReasonCodeSchema,
}).strict();

const protocolExpiryObservedFactSchema = z.object({
  version: factVersion,
  kind: z.literal("protocol-expiry-observed"),
  asOf: controllerTimestampSchema,
}).strict();

const controllerRetiredFactSchema = z.object({
  version: factVersion,
  kind: z.literal("controller-retired"),
  reasonCode: boundedReasonCodeSchema,
}).strict();

export const controllerFactSchema = z.union([
  protocolRegisteredFactSchema,
  collectionStartedFactSchema,
  developmentEvidenceReadyFactSchema,
  developmentAssessmentRecordedFactSchema,
  shadowAssessmentStartedFactSchema,
  holdoutAssessmentRecordedFactSchema,
  windowManifestRecordedFactSchema,
  windowAssessmentRecordedFactSchema,
  deploymentObservedFactSchema,
  identityDriftRecordedFactSchema,
  protocolExpiryObservedFactSchema,
  controllerRetiredFactSchema,
]).superRefine((value, context) => {
  if (
    value.kind === "identity-drift-recorded"
    && value.expectedDigest === value.observedDigest
  ) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      message: "identity drift requires distinct expected and observed digests",
    });
  }
});

const controllerEventBodySchema = z.object({
  version: z.literal("tasc-controller-event-v1"),
  controllerId: contractSlugSchema,
  studyId: contractSlugSchema,
  protocolDigest: contractDigestSchema,
  sequence: safeSequenceSchema.min(1),
  predecessorEventId: contractDigestSchema.nullable(),
  occurredAt: controllerTimestampSchema,
  fact: controllerFactSchema,
  factDigest: contractDigestSchema,
}).strict();

const controllerEventSchema = controllerEventBodySchema.extend({
  eventId: contractDigestSchema,
}).strict();

const controllerWindowLedgerSchema = z.object({
  windowId: contractSlugSchema,
  revisions: z.array(controllerWindowManifestProjectionSchema)
    .min(1)
    .max(MAX_CONTROLLER_WINDOW_REVISIONS),
}).strict();

const controllerSnapshotBodySchema = z.object({
  version: z.literal("tasc-controller-snapshot-v1"),
  controllerId: contractSlugSchema,
  studyId: contractSlugSchema,
  protocolDigest: contractDigestSchema,
  protocolCreatedAt: controllerTimestampSchema,
  protocolExpiresAt: controllerTimestampSchema,
  state: controllerStateSchema,
  sequence: safeSequenceSchema,
  lastEventId: contractDigestSchema.nullable(),
  lastEventAt: controllerTimestampSchema.nullable(),
  collectionId: contractSlugSchema.nullable(),
  developmentEvidence: developmentEvidenceProjectionSchema.nullable(),
  selectedPolicy: selectedPolicyProjectionSchema.nullable(),
  assessments: z.array(controllerAssessmentProjectionSchema)
    .max(MAX_CONTROLLER_ASSESSMENTS),
  windows: z.array(controllerWindowLedgerSchema)
    .max(MAX_CONTROLLER_WINDOWS),
  deploymentObservation: deploymentObservationProjectionSchema.nullable(),
  staleReasons: z.array(boundedReasonCodeSchema).max(64),
  attestation: z.literal("unattested"),
}).strict();

const controllerSnapshotSchema = controllerSnapshotBodySchema.extend({
  snapshotDigest: contractDigestSchema,
}).strict();

type MutableControllerFact = z.infer<typeof controllerFactSchema>;
type MutableControllerEventBody = z.infer<typeof controllerEventBodySchema>;
type MutableControllerEvent = z.infer<typeof controllerEventSchema>;
type MutableControllerSnapshotBody =
  z.infer<typeof controllerSnapshotBodySchema>;
type MutableControllerSnapshot = z.infer<typeof controllerSnapshotSchema>;

export type ControllerState = z.infer<typeof controllerStateSchema>;
export type ControllerAssessmentProjection = DeepReadonly<
  z.infer<typeof controllerAssessmentProjectionSchema>
>;
export type ControllerWindowManifestProjection = DeepReadonly<
  z.infer<typeof controllerWindowManifestProjectionSchema>
>;
export type ControllerFact = DeepReadonly<MutableControllerFact>;
export type ControllerEventBody = DeepReadonly<MutableControllerEventBody>;
export type ControllerEvent = DeepReadonly<MutableControllerEvent>;
export type ControllerSnapshotBody = DeepReadonly<
  MutableControllerSnapshotBody
>;
export type ControllerSnapshot = DeepReadonly<MutableControllerSnapshot>;

function eventBodyWithoutId(
  event: MutableControllerEvent,
): MutableControllerEventBody {
  const { eventId: _eventId, ...body } = event;
  return body;
}

function snapshotBodyWithoutDigest(
  snapshot: MutableControllerSnapshot,
): MutableControllerSnapshotBody {
  const { snapshotDigest: _snapshotDigest, ...body } = snapshot;
  return body;
}

function assertEventBodySemantics(event: MutableControllerEventBody): void {
  if ((event.sequence === 1) !== (event.predecessorEventId === null)) {
    throw new Error(
      "controller event predecessor must be null exactly at sequence 1",
    );
  }
  const expectedFactDigest = domainSeparatedDigest(
    CONTROLLER_FACT_DIGEST_DOMAIN,
    event.fact,
  );
  if (event.factDigest !== expectedFactDigest) {
    throw new Error("controller fact digest does not match canonical fact");
  }
}

function assertSnapshotBodySemantics(
  snapshot: MutableControllerSnapshotBody,
): void {
  if (
    compareCodeUnits(snapshot.protocolCreatedAt, snapshot.protocolExpiresAt)
      >= 0
  ) {
    throw new Error("controller protocol expiry must be after creation");
  }
  const isGenesis = snapshot.sequence === 0;
  const hasLastEventId = snapshot.lastEventId !== null;
  const hasLastEventAt = snapshot.lastEventAt !== null;
  if (hasLastEventId !== hasLastEventAt) {
    throw new Error(
      "controller snapshot last event ID and event time must appear together",
    );
  }
  if (isGenesis !== !hasLastEventId) {
    throw new Error(
      "controller snapshot event identity must be empty exactly at genesis",
    );
  }
  if (
    isGenesis
    && (
      snapshot.state !== "DRAFT"
      || snapshot.collectionId !== null
      || snapshot.developmentEvidence !== null
      || snapshot.selectedPolicy !== null
      || snapshot.assessments.length !== 0
      || snapshot.windows.length !== 0
      || snapshot.deploymentObservation !== null
      || snapshot.staleReasons.length !== 0
    )
  ) {
    throw new Error("controller genesis must contain an empty DRAFT projection");
  }
  if (!isGenesis && snapshot.state === "DRAFT") {
    throw new Error("controller DRAFT state is valid only at genesis");
  }
  if (
    snapshot.lastEventAt !== null
    && compareCodeUnits(snapshot.lastEventAt, snapshot.protocolCreatedAt) < 0
  ) {
    throw new Error("controller snapshot event time predates protocol creation");
  }
  if (
    snapshot.lastEventAt !== null
    && snapshot.state !== "STALE"
    && snapshot.state !== "RETIRED"
    && compareCodeUnits(snapshot.lastEventAt, snapshot.protocolExpiresAt) >= 0
  ) {
    throw new Error(
      "active controller snapshot event time reaches protocol expiry",
    );
  }

  const windowIds = new Set<string>();
  const manifestProjections = new Map<
    string,
    MutableControllerSnapshotBody["windows"][number]["revisions"][number]
  >();
  let totalRevisions = 0;
  let previousWindowId: string | null = null;
  for (const ledger of snapshot.windows) {
    if (windowIds.has(ledger.windowId)) {
      throw new Error("controller snapshot contains duplicate window ledgers");
    }
    if (
      previousWindowId !== null
      && compareCodeUnits(previousWindowId, ledger.windowId) >= 0
    ) {
      throw new Error(
        "controller window ledgers must use deterministic code-unit order",
      );
    }
    windowIds.add(ledger.windowId);
    previousWindowId = ledger.windowId;
    totalRevisions += ledger.revisions.length;
    if (totalRevisions > MAX_CONTROLLER_WINDOW_REVISIONS) {
      throw new Error("controller snapshot exceeds the window revision limit");
    }
    let previousDigest: string | null = null;
    let previousRevision:
      | MutableControllerSnapshotBody["windows"][number]["revisions"][number]
      | null = null;
    for (const [index, revision] of ledger.revisions.entries()) {
      if (
        revision.windowId !== ledger.windowId
        || revision.revision !== index + 1
        || revision.predecessorManifestDigest !== previousDigest
      ) {
        throw new Error(
          "controller snapshot window revision lineage is not contiguous",
        );
      }
      if (
        revision.protocolDigest !== snapshot.protocolDigest
        || snapshot.selectedPolicy === null
        || revision.frozenPolicyDigest
          !== snapshot.selectedPolicy.policyDigest
      ) {
        throw new Error(
          "controller window revision protocol or selected-policy coherence "
          + "failed",
        );
      }
      if (
        compareCodeUnits(
          revision.eventTimeStartInclusive,
          snapshot.protocolCreatedAt,
        ) < 0
        || compareCodeUnits(
          revision.ingestionWatermark,
          snapshot.protocolExpiresAt,
        ) >= 0
      ) {
        throw new Error(
          "controller window revision is outside protocol validity",
        );
      }
      if (
        snapshot.lastEventAt !== null
        && compareCodeUnits(
          revision.ingestionWatermark,
          snapshot.lastEventAt,
        ) > 0
      ) {
        throw new Error(
          "controller window watermark is after the snapshot event time",
        );
      }
      if (manifestProjections.has(revision.manifestDigest)) {
        throw new Error(
          "controller snapshot contains a duplicate window manifest digest",
        );
      }
      manifestProjections.set(revision.manifestDigest, revision);
      if (previousRevision !== null) {
        if (
          revision.eventTimeStartInclusive
            !== previousRevision.eventTimeStartInclusive
          || revision.eventTimeEndExclusive
            !== previousRevision.eventTimeEndExclusive
        ) {
          throw new Error(
            "controller window revision event-time bounds are immutable",
          );
        }
        if (
          compareCodeUnits(
            revision.ingestionWatermark,
            previousRevision.ingestionWatermark,
          ) < 0
        ) {
          throw new Error(
            "controller window revision watermark must be nondecreasing",
          );
        }
        if (
          revision.traceSetDigest === previousRevision.traceSetDigest
          && revision.evaluatorSetDigest
            === previousRevision.evaluatorSetDigest
          && revision.capacityEvidenceDigest
            === previousRevision.capacityEvidenceDigest
        ) {
          throw new Error(
            "controller window revision requires a source or capacity change",
          );
        }
      }
      previousDigest = revision.manifestDigest;
      previousRevision = revision;
    }
  }

  const assessmentDigests = new Set<string>();
  let previousAssessmentPhase = -1;
  let developmentAssessment:
    | MutableControllerSnapshotBody["assessments"][number]
    | null = null;
  let holdoutAssessment:
    | MutableControllerSnapshotBody["assessments"][number]
    | null = null;
  for (const assessment of snapshot.assessments) {
    if (assessmentDigests.has(assessment.decisionDigest)) {
      throw new Error(
        "controller snapshot contains duplicate assessment projections",
      );
    }
    assessmentDigests.add(assessment.decisionDigest);
    if (assessment.protocolDigest !== snapshot.protocolDigest) {
      throw new Error(
        "controller assessment projection protocol digest mismatch",
      );
    }
    const phase = assessment.phase === "development"
      ? 0
      : assessment.phase === "holdout"
      ? 1
      : 2;
    if (phase < previousAssessmentPhase) {
      throw new Error(
        "controller assessment phases must follow development, holdout, "
        + "then window order",
      );
    }
    previousAssessmentPhase = phase;
    if (assessment.phase === "development") {
      if (developmentAssessment !== null) {
        throw new Error(
          "controller snapshot contains multiple development assessments",
        );
      }
      developmentAssessment = assessment;
    } else if (assessment.phase === "holdout") {
      if (
        developmentAssessment === null
        || developmentAssessment.status !== "NOMINATED"
        || holdoutAssessment !== null
      ) {
        throw new Error(
          "controller holdout assessment requires one prior nomination",
        );
      }
      holdoutAssessment = assessment;
    } else {
      if (holdoutAssessment?.status !== "PASS") {
        throw new Error(
          "controller window assessment requires a passing holdout",
        );
      }
      const manifest = manifestProjections.get(
        assessment.windowManifestDigest,
      );
      if (
        manifest === undefined
        || assessment.traceSetDigest !== manifest.traceSetDigest
        || assessment.evaluatorSetDigest !== manifest.evaluatorSetDigest
      ) {
        throw new Error(
          "controller window assessment does not match a sealed source "
          + "projection",
        );
      }
    }
  }

  const samePolicy = (
    left: MutableControllerSnapshotBody["selectedPolicy"],
    right: MutableControllerSnapshotBody["selectedPolicy"],
  ): boolean =>
    left !== null
    && right !== null
    && left.policyDigest === right.policyDigest
    && left.issuedAt === right.issuedAt
    && left.expiresAt === right.expiresAt;

  if (
    snapshot.selectedPolicy !== null
    && (
      compareCodeUnits(
        snapshot.selectedPolicy.issuedAt,
        snapshot.protocolCreatedAt,
      ) < 0
      || compareCodeUnits(
        snapshot.selectedPolicy.expiresAt,
        snapshot.protocolExpiresAt,
      ) !== 0
      || (
        snapshot.lastEventAt !== null
        && compareCodeUnits(
          snapshot.selectedPolicy.issuedAt,
          snapshot.lastEventAt,
        ) > 0
      )
    )
  ) {
    throw new Error(
      "controller selected policy validity disagrees with protocol validity",
    );
  }
  if (
    snapshot.selectedPolicy === null
      ? developmentAssessment?.status === "NOMINATED"
      : (
        developmentAssessment?.status !== "NOMINATED"
        || !samePolicy(
          snapshot.selectedPolicy,
          developmentAssessment.selectedPolicy,
        )
      )
  ) {
    throw new Error(
      "controller selected policy requires its exact development nomination",
    );
  }
  for (const assessment of snapshot.assessments) {
    if (
      assessment.phase !== "development"
      && !samePolicy(snapshot.selectedPolicy, assessment.selectedPolicy)
    ) {
      throw new Error(
        "controller assessment selected policy does not match the snapshot",
      );
    }
  }

  if (
    snapshot.developmentEvidence !== null
    && snapshot.collectionId === null
  ) {
    throw new Error(
      "controller development evidence requires an active collection",
    );
  }
  if (
    snapshot.assessments.length > 0
    && snapshot.developmentEvidence === null
  ) {
    throw new Error(
      "controller assessments require projected development evidence",
    );
  }
  if (
    developmentAssessment !== null
    && snapshot.developmentEvidence !== null
    && (
      developmentAssessment.datasetDigest
        !== snapshot.developmentEvidence.datasetDigest
      || developmentAssessment.traceSetDigest
        !== snapshot.developmentEvidence.traceSetDigest
      || developmentAssessment.evaluatorSetDigest
        !== snapshot.developmentEvidence.evaluatorSetDigest
    )
  ) {
    throw new Error(
      "controller development assessment does not match projected "
      + "development evidence",
    );
  }
  if (snapshot.windows.length > 0 && snapshot.selectedPolicy === null) {
    throw new Error("controller window ledgers require a selected policy");
  }
  const hasPassingWindow = snapshot.assessments.some(
    (assessment) =>
      assessment.phase === "window" && assessment.status === "PASS",
  );
  if (
    snapshot.deploymentObservation !== null
    && (
      snapshot.selectedPolicy === null
      || holdoutAssessment?.status !== "PASS"
      || !hasPassingWindow
      || snapshot.deploymentObservation.policyDigest
        !== snapshot.selectedPolicy.policyDigest
      || compareCodeUnits(
        snapshot.deploymentObservation.observedAt,
        snapshot.protocolCreatedAt,
      ) < 0
      || compareCodeUnits(
        snapshot.deploymentObservation.observedAt,
        snapshot.protocolExpiresAt,
      ) >= 0
      || snapshot.lastEventAt === null
      || compareCodeUnits(
        snapshot.deploymentObservation.observedAt,
        snapshot.lastEventAt,
      ) > 0
      || ![
        "MONITORING",
        "HOLD",
        "ROLLBACK_RECOMMENDED",
        "STALE",
        "RETIRED",
      ].includes(snapshot.state)
    )
  ) {
    throw new Error(
      "controller deployment observation is not coherent with controller "
      + "identity or time",
    );
  }
  if (
    snapshot.staleReasons.length > 0
    && snapshot.state !== "STALE"
    && snapshot.state !== "RETIRED"
  ) {
    throw new Error(
      "controller stale reasons require STALE or RETIRED state",
    );
  }
  if (snapshot.state === "STALE" && snapshot.staleReasons.length === 0) {
    throw new Error("controller STALE state requires a recorded reason");
  }

  const requireCollection = (): void => {
    if (snapshot.collectionId === null) {
      throw new Error(
        `controller ${snapshot.state} state requires collection identity`,
      );
    }
  };
  const requireDevelopmentEvidence = (): void => {
    requireCollection();
    if (snapshot.developmentEvidence === null) {
      throw new Error(
        `controller ${snapshot.state} state requires development evidence`,
      );
    }
  };
  const requireNomination = (): void => {
    requireDevelopmentEvidence();
    if (
      snapshot.selectedPolicy === null
      || developmentAssessment?.status !== "NOMINATED"
    ) {
      throw new Error(
        `controller ${snapshot.state} state requires a selected policy `
        + "nomination",
      );
    }
  };
  const requirePassingHoldout = (): void => {
    requireNomination();
    if (holdoutAssessment?.status !== "PASS") {
      throw new Error(
        `controller ${snapshot.state} state requires a passing holdout`,
      );
    }
  };
  const lastAssessment =
    snapshot.assessments[snapshot.assessments.length - 1] ?? null;
  const windowAssessmentCount = snapshot.assessments.filter(
    (assessment) => assessment.phase === "window",
  ).length;
  const expectedPostHoldoutSequence =
    6 + totalRevisions + windowAssessmentCount;
  const latestWindowAssessmentIs = (
    status: "PASS" | "HOLD",
  ): boolean => {
    if (
      lastAssessment === null
      || lastAssessment.phase !== "window"
      || lastAssessment.status !== status
    ) {
      return false;
    }
    return snapshot.windows.some((ledger) =>
      ledger.revisions[ledger.revisions.length - 1]?.manifestDigest
        === lastAssessment.windowManifestDigest
    );
  };

  switch (snapshot.state) {
    case "DRAFT":
      break;
    case "REGISTERED":
      if (snapshot.sequence !== 1) {
        throw new Error(
          "controller REGISTERED state requires exactly one event",
        );
      }
      if (
        snapshot.collectionId !== null
        || snapshot.developmentEvidence !== null
        || snapshot.selectedPolicy !== null
        || snapshot.assessments.length !== 0
        || snapshot.windows.length !== 0
        || snapshot.deploymentObservation !== null
      ) {
        throw new Error(
          "controller REGISTERED state must precede collection and evidence",
        );
      }
      break;
    case "COLLECTING":
      if (snapshot.sequence !== 2) {
        throw new Error(
          "controller COLLECTING state requires exactly two events",
        );
      }
      requireCollection();
      if (
        snapshot.developmentEvidence !== null
        || snapshot.selectedPolicy !== null
        || snapshot.assessments.length !== 0
        || snapshot.windows.length !== 0
        || snapshot.deploymentObservation !== null
      ) {
        throw new Error(
          "controller COLLECTING state cannot contain later-stage evidence",
        );
      }
      break;
    case "DEV_READY":
      if (snapshot.sequence !== 3) {
        throw new Error(
          "controller DEV_READY state requires exactly three events",
        );
      }
      requireDevelopmentEvidence();
      if (
        snapshot.selectedPolicy !== null
        || snapshot.assessments.length !== 0
        || snapshot.windows.length !== 0
        || snapshot.deploymentObservation !== null
      ) {
        throw new Error(
          "controller DEV_READY state cannot contain assessment results",
        );
      }
      break;
    case "NOMINATED":
      if (snapshot.sequence !== 4) {
        throw new Error(
          "controller NOMINATED state requires exactly four events",
        );
      }
      requireNomination();
      if (
        holdoutAssessment !== null
        || snapshot.windows.length !== 0
        || snapshot.deploymentObservation !== null
      ) {
        throw new Error(
          "controller NOMINATED state precedes shadow and holdout evidence",
        );
      }
      break;
    case "SHADOW_ASSESSING":
      if (snapshot.sequence !== 5 + totalRevisions) {
        throw new Error(
          "controller SHADOW_ASSESSING sequence disagrees with its window "
          + "history",
        );
      }
      requireNomination();
      if (
        holdoutAssessment !== null
        || snapshot.deploymentObservation !== null
      ) {
        throw new Error(
          "controller SHADOW_ASSESSING state precedes holdout results",
        );
      }
      break;
    case "HOLDOUT_CONFIRMED":
      if (snapshot.sequence !== expectedPostHoldoutSequence) {
        throw new Error(
          "controller HOLDOUT_CONFIRMED sequence disagrees with its evidence "
          + "history",
        );
      }
      requirePassingHoldout();
      if (snapshot.deploymentObservation !== null) {
        throw new Error(
          "controller HOLDOUT_CONFIRMED state cannot contain deployment "
          + "observation",
        );
      }
      break;
    case "PROMOTION_RECOMMENDED":
      if (snapshot.sequence !== expectedPostHoldoutSequence) {
        throw new Error(
          "controller PROMOTION_RECOMMENDED sequence disagrees with its "
          + "evidence history",
        );
      }
      requirePassingHoldout();
      if (
        !latestWindowAssessmentIs("PASS")
        || snapshot.deploymentObservation !== null
      ) {
        throw new Error(
          "controller PROMOTION_RECOMMENDED state requires the latest "
          + "passing window and no deployment observation",
        );
      }
      break;
    case "MONITORING":
      if (snapshot.sequence !== expectedPostHoldoutSequence + 1) {
        throw new Error(
          "controller MONITORING sequence disagrees with its observed "
          + "evidence history",
        );
      }
      requirePassingHoldout();
      if (snapshot.deploymentObservation === null) {
        throw new Error(
          "controller MONITORING state requires an external deployment "
          + "observation",
        );
      }
      break;
    case "HOLD":
      requireDevelopmentEvidence();
      if (
        snapshot.sequence !== (
          snapshot.selectedPolicy === null
            ? 3 + snapshot.assessments.length
            : 4
              + snapshot.assessments.length
              + totalRevisions
              + (snapshot.deploymentObservation === null ? 0 : 1)
        )
      ) {
        throw new Error(
          "controller HOLD sequence disagrees with its evidence history",
        );
      }
      if (
        lastAssessment === null
        || lastAssessment.status === "NOMINATED"
        || lastAssessment.status === "PASS"
        || lastAssessment.status === "STALE"
      ) {
        throw new Error(
          "controller HOLD state requires a fail-closed assessment result",
        );
      }
      break;
    case "ROLLBACK_RECOMMENDED":
      if (snapshot.sequence !== expectedPostHoldoutSequence + 1) {
        throw new Error(
          "controller ROLLBACK_RECOMMENDED sequence disagrees with its "
          + "observed evidence history",
        );
      }
      requirePassingHoldout();
      if (
        snapshot.deploymentObservation === null
        || !latestWindowAssessmentIs("HOLD")
      ) {
        throw new Error(
          "controller ROLLBACK_RECOMMENDED state requires an observed "
          + "deployment and latest HOLD window",
        );
      }
      break;
    case "STALE":
    case "RETIRED":
      break;
  }
}

/** Fingerprint one strict, versioned controller fact. */
export function fingerprintControllerFact(input: unknown): string {
  const snapshot = snapshotBoundedContractInput(input);
  const fact = controllerFactSchema.parse(snapshot);
  return domainSeparatedDigest(CONTROLLER_FACT_DIGEST_DOMAIN, fact);
}

/**
 * Fingerprint an ordered event body. A supplied eventId is excluded from its
 * own preimage, while the complete fact remains transitively bound.
 */
export function fingerprintControllerEvent(input: unknown): string {
  const snapshot = snapshotBoundedContractInput(input);
  const parsed = controllerEventSchema.safeParse(snapshot);
  const body = parsed.success
    ? eventBodyWithoutId(parsed.data)
    : controllerEventBodySchema.parse(snapshot);
  assertEventBodySemantics(body);
  return domainSeparatedDigest(CONTROLLER_EVENT_DIGEST_DOMAIN, body);
}

export function parseControllerEvent(input: unknown): ControllerEvent {
  const snapshot = snapshotBoundedContractInput(input);
  const event = controllerEventSchema.parse(snapshot);
  const body = eventBodyWithoutId(event);
  assertEventBodySemantics(body);
  const expectedEventId = domainSeparatedDigest(
    CONTROLLER_EVENT_DIGEST_DOMAIN,
    body,
  );
  if (event.eventId !== expectedEventId) {
    throw new Error("controller event ID does not match canonical event content");
  }
  return deepFreezeContract(event);
}

/**
 * Fingerprint a compact snapshot projection. A self-consistent digest proves
 * integrity only; checkpoint authority is established by controller replay.
 */
export function fingerprintControllerSnapshot(input: unknown): string {
  const snapshot = snapshotBoundedContractInput(input);
  const parsed = controllerSnapshotSchema.safeParse(snapshot);
  const body = parsed.success
    ? snapshotBodyWithoutDigest(parsed.data)
    : controllerSnapshotBodySchema.parse(snapshot);
  assertSnapshotBodySemantics(body);
  return domainSeparatedDigest(CONTROLLER_SNAPSHOT_DIGEST_DOMAIN, body);
}

export function parseControllerSnapshot(input: unknown): ControllerSnapshot {
  const bounded = snapshotBoundedContractInput(input);
  const snapshot = controllerSnapshotSchema.parse(bounded);
  const body = snapshotBodyWithoutDigest(snapshot);
  assertSnapshotBodySemantics(body);
  const expectedDigest = domainSeparatedDigest(
    CONTROLLER_SNAPSHOT_DIGEST_DOMAIN,
    body,
  );
  if (snapshot.snapshotDigest !== expectedDigest) {
    throw new Error(
      "controller snapshot digest does not match canonical snapshot content",
    );
  }
  return deepFreezeContract(snapshot);
}

export function createControllerFact(
  input: ControllerFact,
): ControllerFact {
  const snapshot = snapshotBoundedContractInput(input);
  return deepFreezeContract(controllerFactSchema.parse(snapshot));
}

export function createControllerEvent(
  bodyInput: ControllerEventBody,
): ControllerEvent {
  const snapshot = snapshotBoundedContractInput(bodyInput);
  const body = controllerEventBodySchema.parse(snapshot);
  assertEventBodySemantics(body);
  return parseControllerEvent({
    ...body,
    eventId: domainSeparatedDigest(CONTROLLER_EVENT_DIGEST_DOMAIN, body),
  });
}

export function createControllerSnapshot(
  bodyInput: ControllerSnapshotBody,
): ControllerSnapshot {
  const snapshot = snapshotBoundedContractInput(bodyInput);
  const body = controllerSnapshotBodySchema.parse(snapshot);
  assertSnapshotBodySemantics(body);
  return parseControllerSnapshot({
    ...body,
    snapshotDigest: domainSeparatedDigest(
      CONTROLLER_SNAPSHOT_DIGEST_DOMAIN,
      body,
    ),
  });
}
