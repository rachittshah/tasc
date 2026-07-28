import { isProxy } from "node:util/types";
import { z } from "zod";
import {
  isAuthenticAssessmentDecision,
  type FrozenAssessmentDecision,
} from "./assessment.js";
import { canonicalJson, compareCodeUnits } from "./determinism.js";
import {
  contractDigestSchema,
  contractSlugSchema,
  domainSeparatedDigest,
  fingerprintNormalizedProtocol,
  normalizeExperimentProtocol,
  snapshotBoundedContractInput,
  type ExperimentProtocol,
} from "./evidence.js";
import {
  createControllerEvent,
  createControllerFact,
  createControllerSnapshot,
  fingerprintControllerFact,
  MAX_CONTROLLER_ASSESSMENTS,
  MAX_CONTROLLER_EVENTS,
  parseControllerEvent,
  parseControllerSnapshot,
  compareControllerTimestamps,
  type ControllerAssessmentProjection,
  type ControllerEvent,
  type ControllerFact,
  type ControllerSnapshot,
  type ControllerSnapshotBody,
  type ControllerState,
  type ControllerWindowManifestProjection,
} from "./controller-events.js";
import {
  parseWindowManifest,
  type WindowManifest,
} from "./window.js";

const liveControllerSnapshots = new WeakSet<object>();
const liveControllerEventHistory = new WeakMap<
  object,
  ReadonlyMap<string, string>
>();
const CONTROLLER_WINDOW_CAPACITY_EVIDENCE_DOMAIN =
  "tasc/controller-window-capacity-evidence/v1";

export interface ControllerUpdate {
  readonly event: ControllerEvent;
  readonly snapshot: ControllerSnapshot;
}

export interface ControllerTimeObservation {
  readonly event: ControllerEvent | null;
  readonly snapshot: ControllerSnapshot;
}

export interface ControllerReplaySources {
  readonly assessmentDecisions?: readonly FrozenAssessmentDecision[];
}

export interface CompletePrefixCheckpointVerification {
  readonly kind: "complete-prefix";
  readonly genesis: ControllerSnapshot;
  readonly events: readonly ControllerEvent[];
  readonly assessmentDecisions?: readonly FrozenAssessmentDecision[];
}

export interface PinnedControllerCheckpointAnchor {
  readonly kind: "pinned-anchor";
  readonly controllerId: string;
  readonly protocolDigest: string;
  readonly sequence: number;
  readonly lastEventId: string | null;
  readonly snapshotDigest: string;
}

export type ControllerCheckpointVerification =
  | CompletePrefixCheckpointVerification
  | PinnedControllerCheckpointAnchor;

export interface CollectionStartedInput {
  readonly collectionId: string;
}

export interface DevelopmentEvidenceReadyInput {
  readonly datasetDigest: string;
  readonly traceSetDigest: string;
  readonly evaluatorSetDigest: string;
}

export interface DeploymentObservationInput {
  readonly observationId: string;
  readonly environmentId: string;
  readonly policyDigest: string;
  readonly observedAt: string;
}

export interface IdentityDriftInput {
  readonly scope:
    | "evaluator"
    | "execution-profile"
    | "assessment-context"
    | "source"
    | "policy"
    | "window";
  readonly expectedDigest: string;
  readonly observedDigest: string;
  readonly reasonCode: string;
}

export interface RetireControllerInput {
  readonly reasonCode: string;
}

const pinnedAnchorSchema = z.object({
  kind: z.literal("pinned-anchor"),
  controllerId: contractSlugSchema,
  protocolDigest: contractDigestSchema,
  sequence: z.number().int().min(0).max(MAX_CONTROLLER_EVENTS),
  lastEventId: contractDigestSchema.nullable(),
  snapshotDigest: contractDigestSchema,
}).strict().superRefine((value, context) => {
  if ((value.sequence === 0) !== (value.lastEventId === null)) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      message: "pinned checkpoint event identity disagrees with sequence",
    });
  }
});

function captureStrictDataRecord(
  input: unknown,
  label: string,
  maximumKeys: number,
): ReadonlyMap<string, unknown> {
  if (input === null || typeof input !== "object" || Array.isArray(input)) {
    throw new Error(`${label} requires a plain runtime data object`);
  }
  if (isProxy(input)) {
    throw new Error(`${label} cannot be a proxy`);
  }
  const prototype = Reflect.getPrototypeOf(input);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new Error(`${label} requires a plain runtime data object`);
  }
  const keys = Reflect.ownKeys(input);
  if (keys.length > maximumKeys) {
    throw new Error(`${label} exceeds its finite property limit`);
  }
  if (keys.some((key) => typeof key === "symbol")) {
    throw new Error(`${label} cannot contain symbol properties`);
  }
  const captured = new Map<string, unknown>();
  for (const key of keys as string[]) {
    const descriptor = Reflect.getOwnPropertyDescriptor(input, key);
    if (descriptor === undefined) {
      throw new Error(`${label} changed during descriptor capture`);
    }
    if (!Object.hasOwn(descriptor, "value")) {
      throw new Error(`${label} accessor properties are not allowed`);
    }
    if (!descriptor.enumerable) {
      throw new Error(`${label} cannot contain hidden properties`);
    }
    captured.set(key, descriptor.value);
  }
  return captured;
}

function requireRecordKeys(
  record: ReadonlyMap<string, unknown>,
  label: string,
  allowed: readonly string[],
  required: readonly string[] = [],
): void {
  const allowedKeys = new Set(allowed);
  for (const key of record.keys()) {
    if (!allowedKeys.has(key)) {
      throw new Error(`${label} contains an unexpected ${key} property`);
    }
  }
  for (const key of required) {
    if (!record.has(key)) {
      throw new Error(`${label} requires the ${key} property`);
    }
  }
}

/**
 * Capture a caller-owned array exclusively through own data descriptors.
 * The length descriptor is bounded before index 0 is inspected, so a large
 * array, accessor element, arbitrary iterable, or `length` lookalike cannot
 * bypass admission or execute through ordinary property access.
 */
function captureBoundedRuntimeArray<Item>(
  input: unknown,
  label: string,
  maximumLength: number,
): readonly Item[] {
  if (isProxy(input)) {
    throw new Error(`${label} cannot be a proxy`);
  }
  if (!Array.isArray(input)) {
    throw new Error(`${label} requires a runtime array input`);
  }
  if (Reflect.getPrototypeOf(input) !== Array.prototype) {
    throw new Error(`${label} requires a plain runtime array`);
  }
  const lengthDescriptor = Reflect.getOwnPropertyDescriptor(input, "length");
  if (
    lengthDescriptor === undefined
    || !Object.hasOwn(lengthDescriptor, "value")
  ) {
    throw new Error(`${label} requires a finite data length descriptor`);
  }
  const lengthValue = lengthDescriptor.value;
  if (
    typeof lengthValue !== "number"
    || !Number.isSafeInteger(lengthValue)
    || lengthValue < 0
  ) {
    throw new Error(`${label} requires a finite data length descriptor`);
  }
  const length = lengthValue;
  if (length > maximumLength) {
    throw new Error(`${label} exceeds the finite limit`);
  }

  const ownKeys = Reflect.ownKeys(input);
  if (ownKeys.some((key) => typeof key === "symbol")) {
    throw new Error(`${label} cannot contain symbol properties`);
  }
  if (ownKeys.length !== length + 1) {
    throw new Error(
      `${label} cannot contain holes, hidden entries, or extra properties`,
    );
  }
  const expectedKeys = new Set<string>(["length"]);
  const captured = new Array<Item>(length);
  for (let index = 0; index < length; index += 1) {
    const key = String(index);
    expectedKeys.add(key);
    const descriptor = Reflect.getOwnPropertyDescriptor(input, key);
    if (descriptor === undefined) {
      throw new Error(`${label} cannot contain holes`);
    }
    if (!Object.hasOwn(descriptor, "value")) {
      throw new Error(`${label} accessor properties are not allowed`);
    }
    if (!descriptor.enumerable) {
      throw new Error(`${label} cannot contain hidden entries`);
    }
    captured[index] = descriptor.value as Item;
  }
  for (const key of ownKeys as string[]) {
    if (!expectedKeys.has(key)) {
      throw new Error(`${label} cannot contain extra properties`);
    }
  }
  return Object.freeze(captured);
}

interface CapturedReplaySources {
  readonly assessmentDecisions: readonly FrozenAssessmentDecision[];
}

function captureReplaySources(
  input: unknown,
): CapturedReplaySources {
  const record = captureStrictDataRecord(
    input === undefined ? {} : input,
    "controller replay sources",
    1,
  );
  requireRecordKeys(
    record,
    "controller replay sources",
    ["assessmentDecisions"],
  );
  const decisions = record.has("assessmentDecisions")
    ? captureBoundedRuntimeArray<FrozenAssessmentDecision>(
      record.get("assessmentDecisions"),
      "controller assessment source array",
      MAX_CONTROLLER_ASSESSMENTS,
    )
    : Object.freeze([] as FrozenAssessmentDecision[]);
  return Object.freeze({ assessmentDecisions: decisions });
}

type CapturedCheckpointVerification =
  | {
    readonly kind: "complete-prefix";
    readonly genesis: ControllerSnapshot;
    readonly events: readonly ControllerEvent[];
    readonly assessmentDecisions: readonly FrozenAssessmentDecision[];
  }
  | PinnedControllerCheckpointAnchor;

function captureCheckpointVerification(
  input: unknown,
): CapturedCheckpointVerification {
  const record = captureStrictDataRecord(
    input,
    "controller checkpoint verification",
    6,
  );
  const kind = record.get("kind");
  if (kind === "complete-prefix") {
    requireRecordKeys(
      record,
      "complete-prefix checkpoint verification",
      ["kind", "genesis", "events", "assessmentDecisions"],
      ["kind", "genesis", "events"],
    );
    return Object.freeze({
      kind,
      genesis: record.get("genesis") as ControllerSnapshot,
      events: captureBoundedRuntimeArray<ControllerEvent>(
        record.get("events"),
        "complete-prefix controller event array",
        MAX_CONTROLLER_EVENTS,
      ),
      assessmentDecisions: record.has("assessmentDecisions")
        ? captureBoundedRuntimeArray<FrozenAssessmentDecision>(
          record.get("assessmentDecisions"),
          "complete-prefix assessment source array",
          MAX_CONTROLLER_ASSESSMENTS,
        )
        : Object.freeze([] as FrozenAssessmentDecision[]),
    });
  }
  requireRecordKeys(
    record,
    "pinned checkpoint verification",
    [
      "kind",
      "controllerId",
      "protocolDigest",
      "sequence",
      "lastEventId",
      "snapshotDigest",
    ],
    [
      "kind",
      "controllerId",
      "protocolDigest",
      "sequence",
      "lastEventId",
      "snapshotDigest",
    ],
  );
  const anchor = pinnedAnchorSchema.parse(
    snapshotBoundedContractInput(Object.fromEntries(record)),
  );
  return Object.freeze(anchor);
}

function controllerHistory(
  snapshot: ControllerSnapshot,
): ReadonlyMap<string, string> {
  return liveControllerEventHistory.get(snapshot) ?? new Map();
}

function markLive(
  snapshot: ControllerSnapshot,
  history: ReadonlyMap<string, string> = controllerHistory(snapshot),
): ControllerSnapshot {
  liveControllerSnapshots.add(snapshot);
  liveControllerEventHistory.set(snapshot, new Map(history));
  return snapshot;
}

export function isLiveControllerSnapshot(
  value: unknown,
): value is ControllerSnapshot {
  return (
    value !== null
    && typeof value === "object"
    && liveControllerSnapshots.has(value)
  );
}

function requireLiveSnapshot(input: ControllerSnapshot): ControllerSnapshot {
  if (!isLiveControllerSnapshot(input)) {
    throw new Error(
      "controller mutation requires a live snapshot or verified checkpoint",
    );
  }
  return markLive(parseControllerSnapshot(input), controllerHistory(input));
}

function snapshotBody(
  snapshot: ControllerSnapshot,
): ControllerSnapshotBody {
  const { snapshotDigest: _snapshotDigest, ...body } = snapshot;
  return body;
}

function selectedPolicyProjection(
  decision: FrozenAssessmentDecision,
): ControllerAssessmentProjection["selectedPolicy"] {
  if (decision.selectedPolicy === null) return null;
  if (decision.selectedPolicyDigest !== decision.selectedPolicy.policyDigest) {
    throw new Error(
      "authentic assessment selected-policy identity is inconsistent",
    );
  }
  return {
    policyDigest: decision.selectedPolicy.policyDigest,
    issuedAt: decision.selectedPolicy.issuedAt,
    expiresAt: decision.selectedPolicy.expiresAt,
  };
}

function projectAssessmentDecision(
  decision: FrozenAssessmentDecision,
): ControllerAssessmentProjection {
  if (!isAuthenticAssessmentDecision(decision)) {
    throw new Error(
      "controller assessment admission requires an authentic in-process "
      + "assessment decision",
    );
  }
  const common = {
    version: "tasc-controller-assessment-projection-v1" as const,
    decisionDigest: decision.decisionDigest,
    assessmentContextDigest: decision.assessmentContextDigest,
    protocolDigest: decision.protocolDigest,
    datasetDigest: decision.datasetDigest,
    traceSetDigest: decision.traceSetDigest,
    evaluatorSetDigest: decision.evaluatorSetDigest,
    selectedPolicy: selectedPolicyProjection(decision),
    attestation: "unattested" as const,
  };
  if (decision.phase === "development") {
    if (
      ![
        "NOMINATED",
        "NO_CANDIDATE",
        "INSUFFICIENT_EVIDENCE",
        "STALE",
      ].includes(decision.status)
    ) {
      throw new Error("development assessment has an invalid controller status");
    }
    const fact = createControllerFact({
      version: "tasc-controller-fact-v1",
      kind: "development-assessment-recorded",
      projection: {
        ...common,
        phase: "development",
        status: decision.status,
        windowManifestDigest: null,
      },
    } as ControllerFact);
    if (fact.kind !== "development-assessment-recorded") {
      throw new Error("unreachable development projection parse");
    }
    return fact.projection;
  }
  if (decision.phase === "holdout") {
    const fact = createControllerFact({
      version: "tasc-controller-fact-v1",
      kind: "holdout-assessment-recorded",
      projection: {
        ...common,
        phase: "holdout",
        status: decision.status,
        windowManifestDigest: null,
      },
    } as ControllerFact);
    if (fact.kind !== "holdout-assessment-recorded") {
      throw new Error("unreachable holdout projection parse");
    }
    return fact.projection;
  }
  const fact = createControllerFact({
    version: "tasc-controller-fact-v1",
    kind: "window-assessment-recorded",
    windowId: "projection-validation",
    projection: {
      ...common,
      phase: "window",
      status: decision.status,
      windowManifestDigest: decision.windowManifestDigest,
    },
  } as ControllerFact);
  if (fact.kind !== "window-assessment-recorded") {
    throw new Error("unreachable window projection parse");
  }
  return fact.projection;
}

function projectWindowManifest(
  input: WindowManifest,
): ControllerWindowManifestProjection {
  const manifest = parseWindowManifest(input);
  return {
    version: "tasc-controller-window-projection-v1",
    windowId: manifest.windowId,
    manifestDigest: manifest.selfDigest,
    protocolDigest: manifest.protocolDigest,
    frozenPolicyDigest: manifest.frozenPolicyDigest,
    eventTimeStartInclusive: manifest.eventTimeStartInclusive,
    eventTimeEndExclusive: manifest.eventTimeEndExclusive,
    ingestionWatermark: manifest.ingestionWatermark,
    revision: manifest.revision,
    predecessorManifestDigest: manifest.predecessorManifestDigest,
    traceSetDigest: manifest.traceSetDigest,
    evaluatorSetDigest: manifest.evaluatorSetDigest,
    capacityEvidenceDigest: domainSeparatedDigest(
      CONTROLLER_WINDOW_CAPACITY_EVIDENCE_DOMAIN,
      manifest.capacityEvidence,
    ),
  };
}

function indexAuthenticAssessmentSources(
  sources: ControllerReplaySources = {},
): ReadonlyMap<string, ControllerAssessmentProjection> {
  const capturedSources = captureReplaySources(sources);
  const indexed = new Map<string, ControllerAssessmentProjection>();
  for (const decision of capturedSources.assessmentDecisions) {
    const projection = projectAssessmentDecision(decision);
    const existing = indexed.get(projection.decisionDigest);
    if (
      existing !== undefined
      && canonicalJson(existing) !== canonicalJson(projection)
    ) {
      throw new Error(
        "conflicting authentic assessment sources share one decision digest",
      );
    }
    indexed.set(projection.decisionDigest, projection);
  }
  return indexed;
}

function assertAuthenticProjection(
  projection: ControllerAssessmentProjection,
  sources: ReadonlyMap<string, ControllerAssessmentProjection>,
): void {
  const source = sources.get(projection.decisionDigest);
  if (source === undefined) {
    throw new Error(
      "controller replay requires the authentic source decision for every "
      + "assessment projection",
    );
  }
  if (canonicalJson(source) !== canonicalJson(projection)) {
    throw new Error(
      "controller assessment projection does not match its authentic "
      + "source decision",
    );
  }
}

function requireState(
  current: ControllerState,
  allowed: readonly ControllerState[],
  factKind: ControllerFact["kind"],
): void {
  if (!allowed.includes(current)) {
    throw new Error(
      `${factKind} is invalid from controller state ${current}`,
    );
  }
}

function appendReason(
  reasons: readonly string[],
  reason: string,
): string[] {
  return [...new Set([...reasons, reason])].sort(compareCodeUnits);
}

function sameSelectedPolicy(
  snapshot: ControllerSnapshot,
  projection: ControllerAssessmentProjection,
): boolean {
  return (
    snapshot.selectedPolicy !== null
    && projection.selectedPolicy !== null
    && canonicalJson(snapshot.selectedPolicy)
      === canonicalJson(projection.selectedPolicy)
  );
}

function latestWindowProjection(
  snapshot: ControllerSnapshot,
  windowId: string,
): ControllerWindowManifestProjection | null {
  const ledger = snapshot.windows.find(
    ({ windowId: value }) => value === windowId,
  );
  return ledger?.revisions[ledger.revisions.length - 1] ?? null;
}

function applyWindowProjection(
  snapshot: ControllerSnapshot,
  projection: ControllerWindowManifestProjection,
): ControllerSnapshotBody["windows"] {
  const existing = snapshot.windows.find(
    ({ windowId }) => windowId === projection.windowId,
  );
  if (existing === undefined) {
    if (
      projection.revision !== 1
      || projection.predecessorManifestDigest !== null
    ) {
      throw new Error(
        "new controller window ledger must begin at revision 1",
      );
    }
    return [
      ...snapshot.windows,
      {
        windowId: projection.windowId,
        revisions: [projection],
      },
    ].sort((left, right) =>
      compareCodeUnits(left.windowId, right.windowId)
    );
  }

  const latest = existing.revisions[existing.revisions.length - 1];
  if (projection.revision !== latest.revision + 1) {
    throw new Error(
      "window revision is old or gapped; the next exact revision is required",
    );
  }
  if (projection.predecessorManifestDigest !== latest.manifestDigest) {
    throw new Error(
      "window revision predecessor creates a sibling or fork",
    );
  }
  if (
    projection.eventTimeStartInclusive !== latest.eventTimeStartInclusive
    || projection.eventTimeEndExclusive !== latest.eventTimeEndExclusive
  ) {
    throw new Error("window revision event-time bounds are immutable");
  }
  if (
    compareControllerTimestamps(
      projection.ingestionWatermark,
      latest.ingestionWatermark,
    ) < 0
  ) {
    throw new Error("window revision watermark must be nondecreasing");
  }
  if (
    projection.traceSetDigest === latest.traceSetDigest
    && projection.evaluatorSetDigest === latest.evaluatorSetDigest
    && projection.capacityEvidenceDigest === latest.capacityEvidenceDigest
  ) {
    throw new Error(
      "window revision requires a source or capacity change",
    );
  }
  return snapshot.windows.map((ledger) =>
    ledger.windowId === projection.windowId
      ? {
        windowId: ledger.windowId,
        revisions: [...ledger.revisions, projection],
      }
      : ledger
  );
}

function assertEventEnvelope(
  snapshot: ControllerSnapshot,
  event: ControllerEvent,
): void {
  if (event.controllerId !== snapshot.controllerId) {
    throw new Error("controller event belongs to a different controller");
  }
  if (event.studyId !== snapshot.studyId) {
    throw new Error("controller event belongs to a different study");
  }
  if (event.protocolDigest !== snapshot.protocolDigest) {
    throw new Error("controller event belongs to a different protocol");
  }
  if (event.sequence !== snapshot.sequence + 1) {
    throw new Error(
      "controller event sequence has a gap, branch, or reordering",
    );
  }
  if (event.predecessorEventId !== snapshot.lastEventId) {
    throw new Error(
      "controller event predecessor does not extend the current event chain",
    );
  }
  if (
    snapshot.lastEventAt !== null
    && compareControllerTimestamps(event.occurredAt, snapshot.lastEventAt) < 0
  ) {
    throw new Error("controller event time regresses");
  }
  if (
    compareControllerTimestamps(event.occurredAt, snapshot.protocolCreatedAt)
      < 0
  ) {
    throw new Error("controller event predates protocol creation");
  }
  const expirySafeFacts: readonly ControllerFact["kind"][] = [
    "protocol-expiry-observed",
    "identity-drift-recorded",
    "controller-retired",
  ];
  const isExpirySafeFact = expirySafeFacts.includes(event.fact.kind);
  if (
    !isExpirySafeFact
    && compareControllerTimestamps(
      event.occurredAt,
      snapshot.protocolExpiresAt,
    ) >= 0
  ) {
    throw new Error(
      "controller event is outside the protocol's expiry-exclusive validity",
    );
  }
  if (
    snapshot.selectedPolicy !== null
    && !isExpirySafeFact
    && compareControllerTimestamps(
      event.occurredAt,
      snapshot.selectedPolicy.expiresAt,
    ) >= 0
  ) {
    throw new Error("controller event is outside selected-policy validity");
  }
}

function applyParsedControllerEvent(
  snapshotInput: ControllerSnapshot,
  eventInput: ControllerEvent,
  assessmentSources: ReadonlyMap<string, ControllerAssessmentProjection>,
): ControllerSnapshot {
  const snapshot = parseControllerSnapshot(snapshotInput);
  const event = parseControllerEvent(eventInput);
  assertEventEnvelope(snapshot, event);
  if (snapshot.state === "RETIRED") {
    throw new Error("RETIRED is a terminal controller state");
  }

  let state: ControllerState;
  state = snapshot.state;
  let collectionId = snapshot.collectionId;
  let developmentEvidence = snapshot.developmentEvidence;
  let selectedPolicy = snapshot.selectedPolicy;
  let assessments = [...snapshot.assessments];
  let windows = [...snapshot.windows];
  let deploymentObservation = snapshot.deploymentObservation;
  let staleReasons = [...snapshot.staleReasons];
  const fact = event.fact;

  switch (fact.kind) {
    case "protocol-registered": {
      requireState(state, ["DRAFT"], fact.kind);
      if (
        fact.protocolCreatedAt !== snapshot.protocolCreatedAt
        || fact.protocolExpiresAt !== snapshot.protocolExpiresAt
      ) {
        throw new Error(
          "protocol registration validity disagrees with controller genesis",
        );
      }
      state = "REGISTERED";
      break;
    }
    case "collection-started": {
      requireState(state, ["REGISTERED"], fact.kind);
      collectionId = fact.collectionId;
      state = "COLLECTING";
      break;
    }
    case "development-evidence-ready": {
      requireState(state, ["COLLECTING"], fact.kind);
      developmentEvidence = fact.evidence;
      state = "DEV_READY";
      break;
    }
    case "development-assessment-recorded": {
      requireState(state, ["DEV_READY"], fact.kind);
      assertAuthenticProjection(fact.projection, assessmentSources);
      if (fact.projection.protocolDigest !== snapshot.protocolDigest) {
        throw new Error("development assessment protocol splice");
      }
      if (
        developmentEvidence === null
        || fact.projection.datasetDigest !== developmentEvidence.datasetDigest
        || fact.projection.traceSetDigest
          !== developmentEvidence.traceSetDigest
        || fact.projection.evaluatorSetDigest
          !== developmentEvidence.evaluatorSetDigest
      ) {
        throw new Error(
          "development assessment source projection does not match DEV_READY",
        );
      }
      assessments.push(fact.projection);
      if (fact.projection.status === "NOMINATED") {
        selectedPolicy = fact.projection.selectedPolicy;
        state = "NOMINATED";
      } else if (fact.projection.status === "STALE") {
        staleReasons = appendReason(staleReasons, "assessment-stale");
        state = "STALE";
      } else {
        state = "HOLD";
      }
      break;
    }
    case "shadow-assessment-started": {
      requireState(state, ["NOMINATED"], fact.kind);
      if (
        selectedPolicy === null
        || fact.frozenPolicyDigest !== selectedPolicy.policyDigest
      ) {
        throw new Error("shadow assessment frozen-policy splice");
      }
      state = "SHADOW_ASSESSING";
      break;
    }
    case "holdout-assessment-recorded": {
      requireState(state, ["SHADOW_ASSESSING"], fact.kind);
      assertAuthenticProjection(fact.projection, assessmentSources);
      if (
        fact.projection.protocolDigest !== snapshot.protocolDigest
        || !sameSelectedPolicy(snapshot, fact.projection)
      ) {
        throw new Error("holdout assessment protocol or policy splice");
      }
      assessments.push(fact.projection);
      if (fact.projection.status === "PASS") {
        state = "HOLDOUT_CONFIRMED";
      } else if (fact.projection.status === "STALE") {
        staleReasons = appendReason(staleReasons, "assessment-stale");
        state = "STALE";
      } else {
        state = "HOLD";
      }
      break;
    }
    case "window-manifest-recorded": {
      requireState(state, [
        "SHADOW_ASSESSING",
        "HOLDOUT_CONFIRMED",
        "PROMOTION_RECOMMENDED",
        "MONITORING",
      ], fact.kind);
      if (
        fact.projection.protocolDigest !== snapshot.protocolDigest
        || selectedPolicy === null
        || fact.projection.frozenPolicyDigest
          !== selectedPolicy.policyDigest
      ) {
        throw new Error("window manifest protocol or frozen-policy splice");
      }
      if (
        compareControllerTimestamps(
          fact.projection.ingestionWatermark,
          event.occurredAt,
        ) > 0
      ) {
        throw new Error(
          "window manifest cannot be recorded before its ingestion watermark",
        );
      }
      windows = [...applyWindowProjection(snapshot, fact.projection)];
      if (state === "PROMOTION_RECOMMENDED") {
        state = "HOLDOUT_CONFIRMED";
      }
      break;
    }
    case "window-assessment-recorded": {
      requireState(state, [
        "HOLDOUT_CONFIRMED",
        "MONITORING",
      ], fact.kind);
      assertAuthenticProjection(fact.projection, assessmentSources);
      const latest = latestWindowProjection(snapshot, fact.windowId);
      if (latest === null) {
        throw new Error("window assessment has no sealed manifest ledger");
      }
      if (
        fact.projection.protocolDigest !== snapshot.protocolDigest
        || !sameSelectedPolicy(snapshot, fact.projection)
      ) {
        throw new Error("window assessment protocol or policy splice");
      }
      if (
        fact.projection.windowManifestDigest !== latest.manifestDigest
        || fact.projection.traceSetDigest !== latest.traceSetDigest
        || fact.projection.evaluatorSetDigest !== latest.evaluatorSetDigest
      ) {
        throw new Error(
          "window assessment must use the latest manifest revision and "
          + "its exact source sets",
        );
      }
      assessments.push(fact.projection);
      if (fact.projection.status === "PASS") {
        state = state === "MONITORING"
          ? "MONITORING"
          : "PROMOTION_RECOMMENDED";
      } else if (fact.projection.status === "STALE") {
        staleReasons = appendReason(staleReasons, "assessment-stale");
        state = "STALE";
      } else if (
        state === "MONITORING"
        && fact.projection.status === "HOLD"
      ) {
        state = "ROLLBACK_RECOMMENDED";
      } else {
        state = "HOLD";
      }
      break;
    }
    case "deployment-observed": {
      requireState(state, ["PROMOTION_RECOMMENDED"], fact.kind);
      if (
        selectedPolicy === null
        || fact.observation.policyDigest !== selectedPolicy.policyDigest
      ) {
        throw new Error("deployment observation policy splice");
      }
      if (
        compareControllerTimestamps(
          fact.observation.observedAt,
          event.occurredAt,
        ) > 0
        || (
          snapshot.lastEventAt !== null
          && compareControllerTimestamps(
            fact.observation.observedAt,
            snapshot.lastEventAt,
          ) < 0
        )
      ) {
        throw new Error(
          "external deployment observation time is outside event order",
        );
      }
      deploymentObservation = fact.observation;
      state = "MONITORING";
      break;
    }
    case "identity-drift-recorded": {
      staleReasons = appendReason(staleReasons, fact.reasonCode);
      state = "STALE";
      break;
    }
    case "protocol-expiry-observed": {
      if (fact.asOf !== event.occurredAt) {
        throw new Error(
          "protocol expiry observation must use the explicit event time",
        );
      }
      if (
        compareControllerTimestamps(
          fact.asOf,
          snapshot.protocolExpiresAt,
        ) < 0
      ) {
        throw new Error(
          "protocol expiry is exclusive and has not yet been reached",
        );
      }
      staleReasons = appendReason(staleReasons, "protocol-expired");
      state = "STALE";
      break;
    }
    case "controller-retired": {
      state = "RETIRED";
      break;
    }
  }

  return createControllerSnapshot({
    ...snapshotBody(snapshot),
    state,
    sequence: event.sequence,
    lastEventId: event.eventId,
    lastEventAt: event.occurredAt,
    collectionId,
    developmentEvidence,
    selectedPolicy,
    assessments,
    windows,
    deploymentObservation,
    staleReasons,
  });
}

function appendLiveFact(
  snapshotInput: ControllerSnapshot,
  factInput: ControllerFact,
  occurredAt: string,
  sources: ControllerReplaySources = {},
): ControllerUpdate {
  const snapshot = requireLiveSnapshot(snapshotInput);
  const fact = createControllerFact(factInput);
  const event = createControllerEvent({
    version: "tasc-controller-event-v1",
    controllerId: snapshot.controllerId,
    studyId: snapshot.studyId,
    protocolDigest: snapshot.protocolDigest,
    sequence: snapshot.sequence + 1,
    predecessorEventId: snapshot.lastEventId,
    occurredAt,
    fact,
    factDigest: fingerprintControllerFact(fact),
  });
  const next = applyParsedControllerEvent(
    snapshot,
    event,
    indexAuthenticAssessmentSources(sources),
  );
  const history = new Map(controllerHistory(snapshot));
  history.set(event.eventId, canonicalJson(event));
  return Object.freeze({
    event,
    snapshot: markLive(next, history),
  });
}

export function createController(
  protocolInput: ExperimentProtocol,
  controllerId: string,
): ControllerSnapshot {
  const protocol = normalizeExperimentProtocol(protocolInput);
  return markLive(createControllerSnapshot({
    version: "tasc-controller-snapshot-v1",
    controllerId,
    studyId: protocol.studyId,
    protocolDigest: fingerprintNormalizedProtocol(protocol),
    protocolCreatedAt: protocol.createdAt,
    protocolExpiresAt: protocol.expiresAt,
    state: "DRAFT",
    sequence: 0,
    lastEventId: null,
    lastEventAt: null,
    collectionId: null,
    developmentEvidence: null,
    selectedPolicy: null,
    assessments: [],
    windows: [],
    deploymentObservation: null,
    staleReasons: [],
    attestation: "unattested",
  }));
}

export function registerController(
  snapshot: ControllerSnapshot,
  occurredAt: string,
): ControllerUpdate {
  const live = requireLiveSnapshot(snapshot);
  return appendLiveFact(live, {
    version: "tasc-controller-fact-v1",
    kind: "protocol-registered",
    protocolCreatedAt: live.protocolCreatedAt,
    protocolExpiresAt: live.protocolExpiresAt,
  }, occurredAt);
}

export function startCollection(
  snapshot: ControllerSnapshot,
  input: CollectionStartedInput,
  occurredAt: string,
): ControllerUpdate {
  return appendLiveFact(snapshot, {
    version: "tasc-controller-fact-v1",
    kind: "collection-started",
    collectionId: input.collectionId,
  }, occurredAt);
}

export function markDevelopmentReady(
  snapshot: ControllerSnapshot,
  input: DevelopmentEvidenceReadyInput,
  occurredAt: string,
): ControllerUpdate {
  return appendLiveFact(snapshot, {
    version: "tasc-controller-fact-v1",
    kind: "development-evidence-ready",
    evidence: input,
  }, occurredAt);
}

export function recordDevelopmentAssessment(
  snapshot: ControllerSnapshot,
  decision: FrozenAssessmentDecision,
  occurredAt: string,
): ControllerUpdate {
  const projection = projectAssessmentDecision(decision);
  if (projection.phase !== "development") {
    throw new Error("development controller command requires a development decision");
  }
  return appendLiveFact(snapshot, {
    version: "tasc-controller-fact-v1",
    kind: "development-assessment-recorded",
    projection,
  }, occurredAt, { assessmentDecisions: [decision] });
}

export function startShadowAssessment(
  snapshot: ControllerSnapshot,
  occurredAt: string,
): ControllerUpdate {
  const live = requireLiveSnapshot(snapshot);
  if (live.selectedPolicy === null) {
    throw new Error("shadow assessment requires a frozen selected policy");
  }
  return appendLiveFact(live, {
    version: "tasc-controller-fact-v1",
    kind: "shadow-assessment-started",
    frozenPolicyDigest: live.selectedPolicy.policyDigest,
  }, occurredAt);
}

export function recordHoldoutAssessment(
  snapshot: ControllerSnapshot,
  decision: FrozenAssessmentDecision,
  occurredAt: string,
): ControllerUpdate {
  const projection = projectAssessmentDecision(decision);
  if (projection.phase !== "holdout") {
    throw new Error("holdout controller command requires a holdout decision");
  }
  return appendLiveFact(snapshot, {
    version: "tasc-controller-fact-v1",
    kind: "holdout-assessment-recorded",
    projection,
  }, occurredAt, { assessmentDecisions: [decision] });
}

export function recordWindowManifest(
  snapshot: ControllerSnapshot,
  manifest: WindowManifest,
  occurredAt: string,
): ControllerUpdate {
  return appendLiveFact(snapshot, {
    version: "tasc-controller-fact-v1",
    kind: "window-manifest-recorded",
    projection: projectWindowManifest(manifest),
  }, occurredAt);
}

export function recordWindowAssessment(
  snapshot: ControllerSnapshot,
  decision: FrozenAssessmentDecision,
  occurredAt: string,
): ControllerUpdate {
  const live = requireLiveSnapshot(snapshot);
  const projection = projectAssessmentDecision(decision);
  if (projection.phase !== "window") {
    throw new Error("window controller command requires a window decision");
  }
  const ledger = live.windows.find(({ revisions }) =>
    revisions.some(
      ({ manifestDigest }) =>
        manifestDigest === projection.windowManifestDigest,
    )
  );
  if (ledger === undefined) {
    throw new Error("window decision does not identify a controller window");
  }
  return appendLiveFact(live, {
    version: "tasc-controller-fact-v1",
    kind: "window-assessment-recorded",
    windowId: ledger.windowId,
    projection,
  }, occurredAt, { assessmentDecisions: [decision] });
}

/**
 * Persist an operator-projected, unattested observation of deployment state.
 * This advisory controller has no authority or transport that can deploy,
 * promote, roll back, or otherwise mutate an inference runtime.
 */
export function recordDeploymentObservation(
  snapshot: ControllerSnapshot,
  input: DeploymentObservationInput,
  occurredAt: string,
): ControllerUpdate {
  return appendLiveFact(snapshot, {
    version: "tasc-controller-fact-v1",
    kind: "deployment-observed",
    observation: {
      source: "external-deployment-observation",
      attestation: "unattested",
      ...input,
    },
  }, occurredAt);
}

/**
 * Persist an unattested operator projection of identity drift. The projection
 * can fail the controller closed; it cannot mutate any deployment.
 */
export function recordIdentityDrift(
  snapshot: ControllerSnapshot,
  input: IdentityDriftInput,
  occurredAt: string,
): ControllerUpdate {
  return appendLiveFact(snapshot, {
    version: "tasc-controller-fact-v1",
    kind: "identity-drift-recorded",
    source: "operator-projection",
    attestation: "unattested",
    ...input,
  }, occurredAt);
}

export function observeProtocolTime(
  snapshotInput: ControllerSnapshot,
  asOf: string,
): ControllerTimeObservation {
  const snapshot = requireLiveSnapshot(snapshotInput);
  if (
    compareControllerTimestamps(asOf, snapshot.protocolCreatedAt) < 0
  ) {
    throw new Error("explicit controller time predates protocol creation");
  }
  if (
    compareControllerTimestamps(asOf, snapshot.protocolExpiresAt) < 0
  ) {
    return Object.freeze({ event: null, snapshot: snapshotInput });
  }
  return appendLiveFact(snapshotInput, {
    version: "tasc-controller-fact-v1",
    kind: "protocol-expiry-observed",
    asOf,
  }, asOf);
}

export function retireController(
  snapshot: ControllerSnapshot,
  input: RetireControllerInput,
  occurredAt: string,
): ControllerUpdate {
  return appendLiveFact(snapshot, {
    version: "tasc-controller-fact-v1",
    kind: "controller-retired",
    reasonCode: input.reasonCode,
  }, occurredAt);
}

function replayFromSnapshot(
  initial: ControllerSnapshot,
  eventsInput: readonly ControllerEvent[],
  sources: ControllerReplaySources,
): ControllerSnapshot {
  const events = captureBoundedRuntimeArray<ControllerEvent>(
    eventsInput,
    "controller replay event array",
    MAX_CONTROLLER_EVENTS,
  );
  const assessmentSources = indexAuthenticAssessmentSources(sources);
  const seen = new Map(controllerHistory(initial));
  let snapshot = parseControllerSnapshot(initial);
  for (const input of events) {
    const event = parseControllerEvent(input);
    const canonical = canonicalJson(event);
    const existing = seen.get(event.eventId);
    if (existing !== undefined) {
      if (existing !== canonical) {
        throw new Error("conflicting duplicate controller event ID");
      }
      continue;
    }
    if (
      event.eventId === snapshot.lastEventId
      && event.sequence === snapshot.sequence
    ) {
      seen.set(event.eventId, canonical);
      continue;
    }
    snapshot = applyParsedControllerEvent(
      snapshot,
      event,
      assessmentSources,
    );
    seen.set(event.eventId, canonical);
  }
  return markLive(snapshot, seen);
}

/**
 * Full replay always begins from a structurally empty genesis. Assessment
 * projections must be re-admitted from their live authentic source decisions.
 */
export function replayController(
  genesisInput: ControllerSnapshot,
  events: readonly ControllerEvent[],
  sources: ControllerReplaySources = {},
): ControllerSnapshot {
  if (!isLiveControllerSnapshot(genesisInput)) {
    throw new Error(
      "full controller replay requires a fresh live genesis derived from "
      + "the frozen protocol",
    );
  }
  const genesis = requireLiveSnapshot(genesisInput);
  if (
    genesis.sequence !== 0
    || genesis.state !== "DRAFT"
    || genesis.lastEventId !== null
  ) {
    throw new Error("full controller replay requires an empty DRAFT genesis");
  }
  return replayFromSnapshot(genesis, events, sources);
}

export function verifyControllerCheckpoint(
  checkpointInput: unknown,
  verification: ControllerCheckpointVerification,
): ControllerSnapshot {
  const checkpoint = parseControllerSnapshot(checkpointInput);
  const capturedVerification = captureCheckpointVerification(verification);
  if (capturedVerification.kind === "complete-prefix") {
    const replayed = replayController(
      capturedVerification.genesis,
      capturedVerification.events,
      { assessmentDecisions: capturedVerification.assessmentDecisions },
    );
    if (canonicalJson(replayed) !== canonicalJson(checkpoint)) {
      throw new Error(
        "controller checkpoint does not match the complete verified prefix",
      );
    }
    return markLive(checkpoint, controllerHistory(replayed));
  }

  const anchor = capturedVerification;
  if (
    anchor.controllerId !== checkpoint.controllerId
    || anchor.protocolDigest !== checkpoint.protocolDigest
    || anchor.sequence !== checkpoint.sequence
    || anchor.lastEventId !== checkpoint.lastEventId
    || anchor.snapshotDigest !== checkpoint.snapshotDigest
  ) {
    throw new Error(
      "controller checkpoint does not match the externally pinned anchor",
    );
  }
  return markLive(checkpoint);
}

export function resumeController(
  checkpointInput: unknown,
  verification: ControllerCheckpointVerification,
  suffixEvents: readonly ControllerEvent[],
  sources: ControllerReplaySources = {},
): ControllerSnapshot {
  const checkpoint = verifyControllerCheckpoint(
    checkpointInput,
    verification,
  );
  return replayFromSnapshot(checkpoint, suffixEvents, sources);
}

export type {
  ControllerAssessmentProjection,
  ControllerEvent,
  ControllerFact,
  ControllerSnapshot,
  ControllerState,
  ControllerWindowManifestProjection,
} from "./controller-events.js";
