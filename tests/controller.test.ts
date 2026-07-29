import { describe, expect, it, vi } from "vitest";
import {
  assessPolicyWindow,
  confirmHoldout,
  fingerprintAssessmentDecision,
  isDevelopmentNomination,
  nominateDevelopment,
  type FrozenAssessmentDecision,
  type FrozenDevelopmentNomination,
} from "../src/assessment.js";
import { parseAssessmentContext } from "../src/assessment-context.js";
import {
  createController,
  isLiveControllerSnapshot,
  markDevelopmentReady,
  observeProtocolTime,
  recordDeploymentObservation,
  recordDevelopmentAssessment,
  recordHoldoutAssessment,
  recordIdentityDrift,
  recordWindowAssessment,
  recordWindowManifest,
  registerController,
  replayController,
  resumeController,
  retireController,
  startCollection,
  startShadowAssessment,
  verifyControllerCheckpoint,
  type ControllerSnapshot,
  type ControllerUpdate,
} from "../src/controller.js";
import * as controllerModule from "../src/controller.js";
import {
  fingerprintControllerEvent,
  fingerprintControllerFact,
  fingerprintControllerSnapshot,
  MAX_CONTROLLER_EVENTS,
  parseControllerEvent,
  parseControllerSnapshot,
  type ControllerEvent,
} from "../src/controller-events.js";
import { canonicalJson } from "../src/determinism.js";
import {
  joinAssessmentEvidence,
  requireAssessmentDatasetSplit,
  resolveGroupSplit,
  type AssessmentDatasetForSplit,
} from "../src/evidence-join.js";
import {
  fingerprintProtocol,
  domainSeparatedDigest,
  parseEvaluatorEvidence,
  parseExperimentProtocol,
  parseTraceEnvelope,
  type ExperimentProtocol,
  type TraceEnvelope,
} from "../src/evidence.js";
import {
  parseEvaluatorTrustSnapshot,
  verifyEvaluatorEvidence,
  type EvaluatorEvidenceVerification,
} from "../src/evaluator-trust.js";
import {
  createWindowManifestRevision,
  deriveWindowMembershipDigest,
  fingerprintWindowManifest,
  parseWindowManifest,
  type WindowManifest,
} from "../src/window.js";
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
  type EvaluatorKeyFixture,
} from "./fixtures/evidence.js";

type Split = "dev" | "holdout" | "online";

const CREATED_AT = "2026-07-20T00:00:00.000Z";
const EXPIRES_AT = "2026-08-20T00:00:00.000Z";
const DEV_AS_OF = "2026-07-22T00:00:00.000Z";
const WINDOW_AS_OF = "2026-07-24T00:00:00.000Z";
const DIGEST_Z = `sha256:${"f".repeat(64)}`;

function protocol(
  change?: (input: ReturnType<typeof validProtocolInput>) => void,
): ExperimentProtocol {
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
    serviceCapacity: { kind: "disabled" },
  };
  input.criticalSlices = [];
  input.bootstrap.iterations = 32;
  input.candidatePolicySpace.maxCandidates = 4;
  input.onlineWindowMembership.sampleBasisPoints = 10_000;
  change?.(input);
  return parseExperimentProtocol(input, TEST_WORK_BUDGET);
}

function groupForSplit(
  frozenProtocol: ExperimentProtocol,
  split: "dev" | "holdout",
): string {
  for (let index = 0; index < 10_000; index += 1) {
    const groupId = `controller-${split}-${index}`;
    if (resolveGroupSplit(frozenProtocol, groupId).split === split) {
      return groupId;
    }
  }
  throw new Error(`unable to find a ${split} fixture group`);
}

function verificationFor(
  trace: ReturnType<typeof validTraceInputForProfile>,
  key: EvaluatorKeyFixture,
  context: ReturnType<typeof parseAssessmentContext>,
  score: number | "abstained",
  producedAt: string,
): EvaluatorEvidenceVerification {
  const unsigned = unsignedEvaluatorEvidence();
  unsigned.studyId = trace.studyId;
  unsigned.protocolDigest = trace.protocolDigest;
  unsigned.traceId = trace.traceId;
  unsigned.caseId = trace.caseId;
  unsigned.replicateId = trace.replicateId;
  unsigned.profileId = trace.profileId;
  unsigned.split = trace.split;
  unsigned.terminalOutputId = structuredClone(
    trace.terminalOutputId ?? keyedIdentity("f"),
  );
  unsigned.producedAt = producedAt;
  (unsigned as any).outcome = score === "abstained"
    ? {
      kind: "abstained",
      reasonCode: "controller-fixture-abstained",
    }
    : {
      kind: "scored",
      score,
      range: { minimum: 0, maximum: 1 },
      subscores: [],
    };
  const evidence = parseEvaluatorEvidence(
    signEvaluatorEvidence(key.privateKey, unsigned),
    TEST_WORK_BUDGET,
  );
  return verifyEvaluatorEvidence(
    evidence,
    parseEvaluatorTrustSnapshot(key.trustSnapshot),
    context,
  );
}

interface DatasetFixture<DatasetSplit extends Split> {
  readonly context: ReturnType<typeof parseAssessmentContext>;
  readonly dataset: AssessmentDatasetForSplit<DatasetSplit>;
  readonly traces: readonly TraceEnvelope[];
}

function datasetFixture<DatasetSplit extends Split>(
  frozenProtocol: ExperimentProtocol,
  split: DatasetSplit,
  options: {
    readonly policyDigest?: string;
    readonly windowId?: string;
    readonly windowMembershipDigest?: string;
    readonly candidateScore?: number | "abstained";
    readonly championScore?: number | "abstained";
  } = {},
): DatasetFixture<DatasetSplit> {
  const key = evaluatorKeyFixture();
  const trust = parseEvaluatorTrustSnapshot(key.trustSnapshot);
  const contextInput = validAssessmentContextInput(trust);
  contextInput.asOf = split === "online" ? WINDOW_AS_OF : DEV_AS_OF;
  const context = parseAssessmentContext(contextInput);
  const protocolDigest = fingerprintProtocol(frozenProtocol);
  const groupId = split === "online"
    ? "controller-online-group"
    : groupForSplit(frozenProtocol, split);
  const traces: TraceEnvelope[] = [];
  const verifications: EvaluatorEvidenceVerification[] = [];

  for (const [index, profileId] of (
    ["champion", "candidate"] as const
  ).entries()) {
    const trace = validTraceInputForProfile(profileId) as any;
    trace.studyId = frozenProtocol.studyId;
    trace.protocolDigest = protocolDigest;
    trace.traceId = `controller-${split}-${profileId}`;
    trace.caseId = `controller-${split}-case`;
    trace.groupId = groupId;
    trace.replicateId = "replicate-0";
    trace.split = split;
    trace.policyDigest = options.policyDigest ?? trace.policyDigest;
    trace.slices = ["routine"];
    trace.terminalOutputId = {
      ...keyedIdentity(),
      value: (index + (split === "dev" ? 0 : split === "holdout" ? 2 : 4))
        .toString(16)
        .padStart(64, "0"),
    };
    if (split === "online") {
      trace.collectionWindowId = options.windowId ?? "window-1";
      trace.collectionWindowMembershipDigest =
        options.windowMembershipDigest ?? DIGEST_Z;
      trace.sourceMode = "shadow";
      trace.collectionBinding = validCollectionBinding();
      trace.routeSignal.provenance.observedAt =
        "2026-07-23T00:00:00.000Z";
      trace.attempts[0].observerTimings = {
        startedAt: "2026-07-23T00:00:00.000Z",
        headersAt: "2026-07-23T00:00:00.050Z",
        firstByteAt: "2026-07-23T00:00:00.060Z",
        firstMeaningfulTokenAt: "2026-07-23T00:00:00.075Z",
        completedAt: "2026-07-23T00:00:00.500Z",
      };
    } else {
      trace.collectionWindowId = null;
      trace.collectionWindowMembershipDigest = null;
    }
    signDispatchIntent(trace);
    const parsed = parseTraceEnvelope(trace, TEST_WORK_BUDGET);
    traces.push(parsed);
    verifications.push(verificationFor(
      trace,
      key,
      context,
      profileId === "candidate"
        ? (options.candidateScore ?? 0.9)
        : (options.championScore ?? 0.9),
      split === "online"
        ? "2026-07-23T00:02:00.000Z"
        : "2026-07-21T12:00:00.000Z",
    ));
  }
  const joined = joinAssessmentEvidence(
    frozenProtocol,
    traces,
    verifications,
    TEST_WORK_BUDGET,
  );
  return {
    context,
    traces,
    dataset: requireAssessmentDatasetSplit(
      joined,
      split,
    ) as AssessmentDatasetForSplit<DatasetSplit>,
  };
}

function requireNomination(
  decision: ReturnType<typeof nominateDevelopment>,
): FrozenDevelopmentNomination {
  if (!isDevelopmentNomination(decision)) {
    throw new Error(`fixture expected NOMINATED, received ${decision.status}`);
  }
  return decision;
}

function manifestFor(
  frozenProtocol: ExperimentProtocol,
  policyDigest: string,
  online: DatasetFixture<"online">,
): WindowManifest {
  const body = {
    version: "tasc-window-manifest-v2" as const,
    windowId: "window-1",
    protocolDigest: fingerprintProtocol(frozenProtocol),
    frozenPolicyDigest: policyDigest,
    eventTimeStartInclusive: "2026-07-23T00:00:00.000Z",
    eventTimeEndExclusive: "2026-07-23T00:01:00.000Z",
    ingestionWatermark: "2026-07-23T00:02:00.000Z",
    closureReason: "scheduled",
    membershipRule: frozenProtocol.onlineWindowMembership,
    membershipDigest:
      online.dataset.executions[0].trace.collectionWindowMembershipDigest!,
    revision: 1,
    predecessorManifestDigest: null,
    traceSetDigest: online.dataset.traceSetDigest,
    evaluatorSetDigest: online.dataset.evaluatorSetDigest,
    capacityEvidence: {
      kind: "unavailable" as const,
      reasonCode: "not-collected",
    },
  };
  return parseWindowManifest({
    ...body,
    selfDigest: fingerprintWindowManifest(body),
  });
}

interface AssessmentFlow {
  readonly protocol: ExperimentProtocol;
  readonly development: DatasetFixture<"dev">;
  readonly nomination: FrozenDevelopmentNomination;
  readonly holdout: DatasetFixture<"holdout">;
  readonly confirmation: ReturnType<typeof confirmHoldout>;
  readonly online: DatasetFixture<"online">;
  readonly manifest: WindowManifest;
  readonly windowDecision: ReturnType<typeof assessPolicyWindow>;
}

function assessmentFlow(options: {
  readonly holdoutCandidateScore?: number | "abstained";
  readonly windowCandidateScore?: number | "abstained";
} = {}): AssessmentFlow {
  const frozenProtocol = protocol();
  const development = datasetFixture(frozenProtocol, "dev");
  const nomination = requireNomination(nominateDevelopment(
    frozenProtocol,
    development.dataset,
    development.context,
    TEST_WORK_BUDGET,
  ));
  const holdout = datasetFixture(frozenProtocol, "holdout", {
    candidateScore: options.holdoutCandidateScore,
  });
  const confirmation = confirmHoldout(
    frozenProtocol,
    holdout.dataset,
    nomination,
    holdout.context,
    TEST_WORK_BUDGET,
  );
  const membershipDigest = deriveWindowMembershipDigest(
    "window-1",
    fingerprintProtocol(frozenProtocol),
    frozenProtocol.onlineWindowMembership,
  );
  const online = datasetFixture(frozenProtocol, "online", {
    policyDigest: nomination.selectedPolicyDigest,
    windowId: "window-1",
    windowMembershipDigest: membershipDigest,
    candidateScore: options.windowCandidateScore,
  });
  const manifest = manifestFor(
    frozenProtocol,
    nomination.selectedPolicyDigest,
    online,
  );
  const windowDecision = assessPolicyWindow(
    frozenProtocol,
    online.dataset,
    nomination.selectedPolicy,
    manifest,
    online.context,
    TEST_WORK_BUDGET,
  );
  return {
    protocol: frozenProtocol,
    development,
    nomination,
    holdout,
    confirmation,
    online,
    manifest,
    windowDecision,
  };
}

function appendHappyPath(flow: AssessmentFlow): {
  readonly genesis: ControllerSnapshot;
  readonly events: readonly ControllerEvent[];
  readonly snapshots: readonly ControllerSnapshot[];
  readonly final: ControllerSnapshot;
} {
  const genesis = createController(flow.protocol, "controller-1");
  const updates: ControllerUpdate[] = [];
  const append = (update: ControllerUpdate): ControllerSnapshot => {
    updates.push(update);
    return update.snapshot;
  };
  let snapshot = append(registerController(genesis, CREATED_AT));
  snapshot = append(startCollection(
    snapshot,
    { collectionId: "collection-1" },
    "2026-07-20T00:00:01.000Z",
  ));
  snapshot = append(markDevelopmentReady(
    snapshot,
    {
      datasetDigest: flow.development.dataset.datasetDigest,
      traceSetDigest: flow.development.dataset.traceSetDigest,
      evaluatorSetDigest: flow.development.dataset.evaluatorSetDigest,
    },
    "2026-07-21T23:59:59.000Z",
  ));
  snapshot = append(recordDevelopmentAssessment(
    snapshot,
    flow.nomination,
    DEV_AS_OF,
  ));
  snapshot = append(startShadowAssessment(
    snapshot,
    "2026-07-22T00:00:01.000Z",
  ));
  snapshot = append(recordHoldoutAssessment(
    snapshot,
    flow.confirmation,
    "2026-07-22T00:00:02.000Z",
  ));
  snapshot = append(recordWindowManifest(
    snapshot,
    flow.manifest,
    WINDOW_AS_OF,
  ));
  snapshot = append(recordWindowAssessment(
    snapshot,
    flow.windowDecision,
    "2026-07-24T00:00:01.000Z",
  ));
  snapshot = append(recordDeploymentObservation(
    snapshot,
    {
      observationId: "deployment-observation-1",
      environmentId: "production-us-east",
      policyDigest: flow.nomination.selectedPolicyDigest,
      observedAt: "2026-07-24T00:00:01.500Z",
    },
    "2026-07-24T00:00:02.000Z",
  ));
  return {
    genesis,
    events: updates.map(({ event }) => event),
    snapshots: updates.map(({ snapshot: value }) => value),
    final: snapshot,
  };
}

function allDecisions(
  flow: AssessmentFlow,
): readonly FrozenAssessmentDecision[] {
  return [
    flow.nomination,
    flow.confirmation,
    flow.windowDecision,
  ];
}

function expectRecursivelyFrozen(value: unknown): void {
  if (value === null || typeof value !== "object") return;
  expect(Object.isFrozen(value)).toBe(true);
  for (const child of Object.values(value)) expectRecursivelyFrozen(child);
}

function redigestEvent(input: ControllerEvent, change: (copy: any) => void) {
  const copy = structuredClone(input) as any;
  change(copy);
  copy.factDigest = fingerprintControllerFact(copy.fact);
  copy.eventId = fingerprintControllerEvent(copy);
  return parseControllerEvent(copy);
}

function selfDigestSnapshotWithoutSemanticParsing(
  input: ControllerSnapshot,
  change: (copy: any) => void,
): ControllerSnapshot {
  const copy = structuredClone(input) as any;
  change(copy);
  const { snapshotDigest: _snapshotDigest, ...body } = copy;
  copy.snapshotDigest = domainSeparatedDigest(
    "tasc/controller-snapshot/v1",
    body,
  );
  return copy as ControllerSnapshot;
}

function redigestManifest(
  input: WindowManifest,
  change: (copy: any) => void,
): WindowManifest {
  const copy = structuredClone(input) as any;
  change(copy);
  copy.selfDigest = fingerprintWindowManifest(copy);
  return parseWindowManifest(copy);
}

describe("strict controller events and pure transitions", () => {
  it("creates a deterministic, compact, recursively frozen DRAFT genesis", () => {
    const frozenProtocol = protocol();
    const left = createController(frozenProtocol, "controller-1");
    const right = createController(frozenProtocol, "controller-1");

    expect(left).toEqual(right);
    expect(left).toMatchObject({
      version: "tasc-controller-snapshot-v1",
      controllerId: "controller-1",
      studyId: frozenProtocol.studyId,
      protocolDigest: fingerprintProtocol(frozenProtocol),
      protocolCreatedAt: CREATED_AT,
      protocolExpiresAt: EXPIRES_AT,
      state: "DRAFT",
      sequence: 0,
      lastEventId: null,
      lastEventAt: null,
      selectedPolicy: null,
      assessments: [],
      windows: [],
      deploymentObservation: null,
      attestation: "unattested",
    });
    expect(left.snapshotDigest).toBe(fingerprintControllerSnapshot(left));
    expect(isLiveControllerSnapshot(left)).toBe(true);
    expectRecursivelyFrozen(left);
  });

  it("follows the complete advisory lifecycle without deployment commands", () => {
    const flow = assessmentFlow();
    expect(flow.confirmation.status).toBe("PASS");
    expect(flow.windowDecision.status).toBe("PASS");
    const run = appendHappyPath(flow);

    expect(run.snapshots.map(({ state }) => state)).toEqual([
      "REGISTERED",
      "COLLECTING",
      "DEV_READY",
      "NOMINATED",
      "SHADOW_ASSESSING",
      "HOLDOUT_CONFIRMED",
      "HOLDOUT_CONFIRMED",
      "PROMOTION_RECOMMENDED",
      "MONITORING",
    ]);
    expect(run.final.selectedPolicy).toMatchObject({
      policyDigest: flow.nomination.selectedPolicyDigest,
      issuedAt: flow.nomination.selectedPolicy.issuedAt,
      expiresAt: flow.nomination.selectedPolicy.expiresAt,
    });
    expect(run.final.assessments.map(({ decisionDigest }) => decisionDigest))
      .toEqual([
        flow.nomination.decisionDigest,
        flow.confirmation.decisionDigest,
        flow.windowDecision.decisionDigest,
      ]);
    expect(run.final.windows).toHaveLength(1);
    expect(run.final.windows[0].revisions).toHaveLength(1);
    expect(run.final.deploymentObservation).toMatchObject({
      source: "external-deployment-observation",
      attestation: "unattested",
      policyDigest: flow.nomination.selectedPolicyDigest,
    });
    for (const event of run.events) {
      expect(event.eventId).toBe(fingerprintControllerEvent(event));
      expect(event.factDigest).toBe(fingerprintControllerFact(event.fact));
      expect(canonicalJson(event)).not.toContain('"replay"');
      expect(canonicalJson(event)).not.toContain('"candidates"');
      expect(canonicalJson(event)).not.toContain('"score"');
      expectRecursivelyFrozen(event);
    }
    expect(Object.keys(controllerModule)).not
      .toEqual(expect.arrayContaining([
        "deployPolicy",
        "promotePolicy",
        "rollbackPolicy",
      ]));
  });

  it("captures only bounded runtime event arrays without invoking values", () => {
    const flow = assessmentFlow();
    const run = appendHappyPath(flow);

    let proxyTrapCalls = 0;
    const proxiedEvents = new Proxy([run.events[0]], {
      getPrototypeOf() {
        proxyTrapCalls += 1;
        throw new Error("event array proxy trap must not execute");
      },
      ownKeys() {
        proxyTrapCalls += 1;
        throw new Error("event array proxy trap must not execute");
      },
      get() {
        proxyTrapCalls += 1;
        throw new Error("event array proxy trap must not execute");
      },
    });
    expect(() => replayController(
      createController(flow.protocol, "controller-1"),
      proxiedEvents,
    )).toThrow(/proxy/i);
    expect(proxyTrapCalls).toBe(0);

    let accessorCalls = 0;
    const accessorEvents = [run.events[0]];
    Object.defineProperty(accessorEvents, "0", {
      configurable: true,
      enumerable: true,
      get() {
        accessorCalls += 1;
        return run.events[0];
      },
    });
    expect(() => replayController(
      createController(flow.protocol, "controller-1"),
      accessorEvents,
    )).toThrow(/accessor|data propert/i);
    expect(accessorCalls).toBe(0);

    let oversizedElementReads = 0;
    const oversized = new Array(MAX_CONTROLLER_EVENTS + 1);
    Object.defineProperty(oversized, "0", {
      configurable: true,
      enumerable: true,
      get() {
        oversizedElementReads += 1;
        throw new Error("over-budget event element zero must not be read");
      },
    });
    expect(() => replayController(
      createController(flow.protocol, "controller-1"),
      oversized as ControllerEvent[],
    )).toThrow(/event.*limit|finite limit/i);
    expect(oversizedElementReads).toBe(0);

    let nonArrayReads = 0;
    const iterableLookalike = Object.defineProperties({}, {
      length: {
        enumerable: true,
        get() {
          nonArrayReads += 1;
          return 0;
        },
      },
      [Symbol.iterator]: {
        get() {
          nonArrayReads += 1;
          return function* empty() {};
        },
      },
    });
    expect(() => replayController(
      createController(flow.protocol, "controller-1"),
      iterableLookalike as ControllerEvent[],
    )).toThrow(/runtime array|array input/i);
    expect(nonArrayReads).toBe(0);
  });

  it("captures authentic assessment source arrays without invoking accessors", () => {
    const flow = assessmentFlow();
    const run = appendHappyPath(flow);
    const throughNomination = run.events.slice(0, 4);

    let sourceElementCalls = 0;
    const accessorSources = [flow.nomination];
    Object.defineProperty(accessorSources, "0", {
      configurable: true,
      enumerable: true,
      get() {
        sourceElementCalls += 1;
        return flow.nomination;
      },
    });
    expect(() => replayController(
      createController(flow.protocol, "controller-1"),
      throughNomination,
      { assessmentDecisions: accessorSources },
    )).toThrow(/accessor|data propert/i);
    expect(sourceElementCalls).toBe(0);

    let sourceFieldCalls = 0;
    const accessorSourceObject = Object.create(null);
    Object.defineProperty(accessorSourceObject, "assessmentDecisions", {
      enumerable: true,
      get() {
        sourceFieldCalls += 1;
        return [flow.nomination];
      },
    });
    expect(() => replayController(
      createController(flow.protocol, "controller-1"),
      throughNomination,
      accessorSourceObject,
    )).toThrow(/accessor|data propert/i);
    expect(sourceFieldCalls).toBe(0);

    let sourceProxyTraps = 0;
    const proxiedSources = new Proxy(
      { assessmentDecisions: [flow.nomination] },
      {
        getPrototypeOf() {
          sourceProxyTraps += 1;
          throw new Error("replay source proxy trap must not execute");
        },
        ownKeys() {
          sourceProxyTraps += 1;
          throw new Error("replay source proxy trap must not execute");
        },
      },
    );
    expect(() => replayController(
      createController(flow.protocol, "controller-1"),
      throughNomination,
      proxiedSources,
    )).toThrow(/proxy/i);
    expect(sourceProxyTraps).toBe(0);

    expect(() => replayController(
      createController(flow.protocol, "controller-1"),
      throughNomination,
      {
        assessmentDecisions:
          new Set([flow.nomination]) as unknown as FrozenAssessmentDecision[],
      },
    )).toThrow(/runtime array|array input/i);
  });

  it("replays exact duplicates idempotently and produces byte-identical state", () => {
    const flow = assessmentFlow();
    const run = appendHappyPath(flow);
    expect(() => replayController(
      structuredClone(run.genesis),
      run.events,
      { assessmentDecisions: allDecisions(flow) },
    )).toThrow(/live.*genesis|fresh.*genesis|authority/i);
    const replayed = replayController(
      createController(flow.protocol, "controller-1"),
      [
        run.events[0],
        run.events[0],
        ...run.events.slice(1),
        run.events[3],
      ],
      { assessmentDecisions: allDecisions(flow) },
    );

    expect(canonicalJson(replayed)).toBe(canonicalJson(run.final));
    expect(replayed.sequence).toBe(run.events.length);
    expect(isLiveControllerSnapshot(replayed)).toBe(true);
  });

  it("rejects event gaps, reorderings, branches, and identity splices", () => {
    const flow = assessmentFlow();
    const run = appendHappyPath(flow);
    const other = appendHappyPath(flow);
    const branchA = startCollection(
      run.snapshots[0],
      { collectionId: "branch-a" },
      "2026-07-20T00:00:01.000Z",
    ).event;
    const branchB = startCollection(
      run.snapshots[0],
      { collectionId: "branch-b" },
      "2026-07-20T00:00:01.000Z",
    ).event;

    expect(() => replayController(
      run.genesis,
      [run.events[1], run.events[0]],
    )).toThrow(/sequence|gap|order/i);
    expect(() => replayController(
      run.genesis,
      [run.events[0], run.events[2]],
    )).toThrow(/sequence|gap|predecessor/i);
    expect(() => replayController(
      run.genesis,
      [run.events[0], branchA, branchB],
    )).toThrow(/branch|sequence|predecessor/i);

    const otherGenesis = createController(flow.protocol, "controller-2");
    const otherRegistration = registerController(otherGenesis, CREATED_AT);
    expect(() => replayController(
      run.genesis,
      [otherRegistration.event],
    )).toThrow(/controller/i);

    const protocolSplice = redigestEvent(run.events[0], (event) => {
      event.protocolDigest = DIGEST_Z;
    });
    expect(() => replayController(
      run.genesis,
      [protocolSplice],
    )).toThrow(/protocol/i);

    expect(other.final).toEqual(run.final);
  });

  it("requires live authentic assessments and rejects forged promotion facts", () => {
    const flow = assessmentFlow();
    const run = appendHappyPath(flow);
    const persistedNomination = structuredClone(flow.nomination);

    expect(() => recordDevelopmentAssessment(
      run.snapshots[2],
      persistedNomination,
      DEV_AS_OF,
    )).toThrow(/authentic.*assessment/i);
    expect(() => replayController(
      run.genesis,
      run.events.slice(0, 4),
    )).toThrow(/authentic.*assessment|source decision/i);

    const forgedPass = structuredClone(flow.windowDecision) as any;
    forgedPass.decisionDigest = fingerprintAssessmentDecision(forgedPass);
    expect(() => recordWindowAssessment(
      run.snapshots[6],
      forgedPass,
      "2026-07-24T00:00:01.000Z",
    )).toThrow(/authentic.*assessment/i);

    const forgedEvent = redigestEvent(run.events[7], (event) => {
      event.fact.projection.decisionDigest = DIGEST_Z;
    });
    expect(() => replayController(
      run.genesis,
      [...run.events.slice(0, 7), forgedEvent],
      { assessmentDecisions: allDecisions(flow) },
    )).toThrow(/projection|source decision|assessment/i);

    expect(() => fingerprintControllerFact({
      version: "tasc-controller-fact-v1",
      kind: "promotion-recommended",
      policyDigest: flow.nomination.selectedPolicyDigest,
    })).toThrow(/kind|invalid|union/i);
  });

  it("does not let a self-digested persisted snapshot authorize advancement", () => {
    const flow = assessmentFlow();
    const run = appendHappyPath(flow);
    const persisted = parseControllerSnapshot(
      JSON.parse(JSON.stringify(run.snapshots[0])),
    );

    expect(persisted.attestation).toBe("unattested");
    expect(isLiveControllerSnapshot(persisted)).toBe(false);
    expect(() => startCollection(
      persisted,
      { collectionId: "unauthorized-resume" },
      "2026-07-20T00:00:01.000Z",
    )).toThrow(/verified|live|checkpoint/i);

    let callerReads = 0;
    const hostile = new Proxy(persisted, {
      get() {
        callerReads += 1;
        throw new Error("untrusted snapshot was read before authority check");
      },
    });
    expect(() => registerController(hostile, CREATED_AT))
      .toThrow(/verified|live|checkpoint/i);
    expect(callerReads).toBe(0);
  });

  it("recovers only from a complete prefix or exact externally pinned anchor", () => {
    const flow = assessmentFlow();
    const run = appendHappyPath(flow);
    const prefixEvents = run.events.slice(0, 6);
    const checkpoint = parseControllerSnapshot(
      JSON.parse(JSON.stringify(run.snapshots[5])),
    );
    const completePrefix = {
      kind: "complete-prefix" as const,
      genesis: run.genesis,
      events: prefixEvents,
      assessmentDecisions: [
        flow.nomination,
        flow.confirmation,
      ],
    };

    const verified = verifyControllerCheckpoint(checkpoint, completePrefix);
    expect(isLiveControllerSnapshot(verified)).toBe(true);
    let verificationProxyTraps = 0;
    const proxiedVerification = new Proxy(completePrefix, {
      getPrototypeOf() {
        verificationProxyTraps += 1;
        throw new Error("checkpoint verification proxy trap must not execute");
      },
      ownKeys() {
        verificationProxyTraps += 1;
        throw new Error("checkpoint verification proxy trap must not execute");
      },
    });
    expect(() => verifyControllerCheckpoint(
      checkpoint,
      proxiedVerification,
    )).toThrow(/proxy/i);
    expect(verificationProxyTraps).toBe(0);

    const resumed = resumeController(
      checkpoint,
      completePrefix,
      run.events.slice(6),
      { assessmentDecisions: [flow.windowDecision] },
    );
    expect(canonicalJson(resumed)).toBe(canonicalJson(run.final));
    const resumedAfterDuplicateCheckpointWrite = resumeController(
      checkpoint,
      completePrefix,
      [prefixEvents[prefixEvents.length - 1], ...run.events.slice(6)],
      { assessmentDecisions: [flow.windowDecision] },
    );
    expect(canonicalJson(resumedAfterDuplicateCheckpointWrite))
      .toBe(canonicalJson(run.final));
    const resumedAfterEarlierDuplicate = resumeController(
      checkpoint,
      completePrefix,
      [prefixEvents[0], ...run.events.slice(6)],
      { assessmentDecisions: [flow.windowDecision] },
    );
    expect(canonicalJson(resumedAfterEarlierDuplicate))
      .toBe(canonicalJson(run.final));

    const divergentEarlierDuplicate = structuredClone(prefixEvents[0]) as any;
    divergentEarlierDuplicate.occurredAt =
      "2026-07-20T00:00:00.001Z";
    expect(() => resumeController(
      checkpoint,
      completePrefix,
      [divergentEarlierDuplicate, ...run.events.slice(6)],
      { assessmentDecisions: [flow.windowDecision] },
    )).toThrow(/event ID|duplicate|canonical/i);

    let prefixAccessorCalls = 0;
    const accessorPrefixEvents = [...prefixEvents];
    Object.defineProperty(accessorPrefixEvents, "0", {
      configurable: true,
      enumerable: true,
      get() {
        prefixAccessorCalls += 1;
        return prefixEvents[0];
      },
    });
    expect(() => verifyControllerCheckpoint(checkpoint, {
      ...completePrefix,
      events: accessorPrefixEvents,
    })).toThrow(/accessor|data propert/i);
    expect(prefixAccessorCalls).toBe(0);

    const pinned = verifyControllerCheckpoint(checkpoint, {
      kind: "pinned-anchor",
      controllerId: checkpoint.controllerId,
      protocolDigest: checkpoint.protocolDigest,
      sequence: checkpoint.sequence,
      lastEventId: checkpoint.lastEventId!,
      snapshotDigest: checkpoint.snapshotDigest,
    });
    expect(isLiveControllerSnapshot(pinned)).toBe(true);

    const forged = selfDigestSnapshotWithoutSemanticParsing(
      checkpoint,
      (snapshot) => {
        snapshot.state = "PROMOTION_RECOMMENDED";
      },
    );
    expect(() => verifyControllerCheckpoint(forged, completePrefix))
      .toThrow(/checkpoint|prefix|snapshot|promotion|window/i);
    expect(() => verifyControllerCheckpoint(forged, {
      kind: "pinned-anchor",
      controllerId: checkpoint.controllerId,
      protocolDigest: checkpoint.protocolDigest,
      sequence: checkpoint.sequence,
      lastEventId: checkpoint.lastEventId!,
      snapshotDigest: checkpoint.snapshotDigest,
    })).toThrow(/anchor|digest|checkpoint|promotion|window/i);

    expect(() => verifyControllerCheckpoint(
      run.snapshots[3],
      completePrefix,
    )).toThrow(/checkpoint|prefix|snapshot/i);
    expect(() => resumeController(
      checkpoint,
      completePrefix,
      [run.events[7]],
      { assessmentDecisions: [flow.windowDecision] },
    )).toThrow(/sequence|gap|predecessor/i);
  });

  it("rejects semantically impossible self-digested pinned checkpoints", () => {
    const flow = assessmentFlow();
    const run = appendHappyPath(flow);
    const registered = run.snapshots[0];

    const missingEventTime = selfDigestSnapshotWithoutSemanticParsing(
      registered,
      (snapshot) => {
        snapshot.lastEventAt = null;
      },
    );
    expect(() => parseControllerSnapshot(missingEventTime))
      .toThrow(/event identity|event time|last event/i);

    const impossiblePromotion = selfDigestSnapshotWithoutSemanticParsing(
      registered,
      (snapshot) => {
        snapshot.state = "PROMOTION_RECOMMENDED";
      },
    );
    expect(() => verifyControllerCheckpoint(impossiblePromotion, {
      kind: "pinned-anchor",
      controllerId: impossiblePromotion.controllerId,
      protocolDigest: impossiblePromotion.protocolDigest,
      sequence: impossiblePromotion.sequence,
      lastEventId: impossiblePromotion.lastEventId!,
      snapshotDigest: impossiblePromotion.snapshotDigest,
    })).toThrow(/promotion|selected policy|assessment|window|coherence/i);

    const expiredActiveState = selfDigestSnapshotWithoutSemanticParsing(
      registered,
      (snapshot) => {
        snapshot.lastEventAt = EXPIRES_AT;
      },
    );
    expect(() => verifyControllerCheckpoint(expiredActiveState, {
      kind: "pinned-anchor",
      controllerId: expiredActiveState.controllerId,
      protocolDigest: expiredActiveState.protocolDigest,
      sequence: expiredActiveState.sequence,
      lastEventId: expiredActiveState.lastEventId!,
      snapshotDigest: expiredActiveState.snapshotDigest,
    })).toThrow(/expiry|expired|event time|coherence/i);

    const selectedWithoutNomination = selfDigestSnapshotWithoutSemanticParsing(
      registered,
      (snapshot) => {
        snapshot.selectedPolicy = {
          policyDigest: flow.nomination.selectedPolicy.policyDigest,
          issuedAt: flow.nomination.selectedPolicy.issuedAt,
          expiresAt: flow.nomination.selectedPolicy.expiresAt,
        };
      },
    );
    expect(() => parseControllerSnapshot(selectedWithoutNomination))
      .toThrow(/selected policy|nomination|assessment|coherence/i);
  });

  it("uses explicit time with created-at inclusive and expiry exclusive", () => {
    const frozenProtocol = protocol();
    const genesis = createController(frozenProtocol, "controller-time");
    expect(registerController(genesis, CREATED_AT).snapshot.state)
      .toBe("REGISTERED");
    expect(() => registerController(genesis, EXPIRES_AT))
      .toThrow(/expired|expiry|exclusive/i);
    expect(() => registerController(
      genesis,
      "2026-07-19T23:59:59.999Z",
    )).toThrow(/creation|created|valid/i);

    const before = observeProtocolTime(
      registerController(genesis, CREATED_AT).snapshot,
      "2026-08-19T23:59:59.999Z",
    );
    expect(before.event).toBeNull();
    expect(before.snapshot.state).toBe("REGISTERED");
    const atExpiry = observeProtocolTime(before.snapshot, EXPIRES_AT);
    expect(atExpiry.event?.fact.kind).toBe("protocol-expiry-observed");
    expect(atExpiry.snapshot.state).toBe("STALE");
  });

  it("replays without Date.now, Date construction, network, or model calls", () => {
    const flow = assessmentFlow();
    const run = appendHappyPath(flow);
    const RealDate = globalThis.Date;
    const NoWallClockDate = Object.assign(
      function NoWallClockDate() {
        throw new Error("new Date is forbidden during replay");
      } as unknown as DateConstructor,
      {
        now(): number {
        throw new Error("Date.now is forbidden during replay");
        },
        parse: RealDate.parse.bind(RealDate),
        UTC: RealDate.UTC.bind(RealDate),
      },
    );
    vi.stubGlobal("Date", NoWallClockDate);
    vi.stubGlobal("fetch", () => {
      throw new Error("fetch is forbidden during replay");
    });
    try {
      const replayed = replayController(
        run.genesis,
        run.events,
        { assessmentDecisions: allDecisions(flow) },
      );
      expect(canonicalJson(replayed)).toBe(canonicalJson(run.final));
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("maps failed assessments, drift, and retirement to fail-closed states", () => {
    const insufficientFlow = assessmentFlow({
      holdoutCandidateScore: "abstained",
    });
    expect(insufficientFlow.confirmation.status)
      .toBe("INSUFFICIENT_EVIDENCE");
    const base = appendHappyPath(assessmentFlow());
    const throughShadow = base.snapshots[4];
    const insufficient = recordHoldoutAssessment(
      throughShadow,
      insufficientFlow.confirmation,
      "2026-07-22T00:00:02.000Z",
    );
    expect(insufficient.snapshot.state).toBe("HOLD");

    const evaluatorDrift = recordIdentityDrift(
      base.snapshots[1],
      {
        scope: "evaluator",
        expectedDigest: base.genesis.protocolDigest,
        observedDigest: DIGEST_Z,
        reasonCode: "evaluator-identity-drift",
      },
      "2026-07-20T00:00:02.000Z",
    );
    expect(evaluatorDrift.snapshot.state).toBe("STALE");
    expect(evaluatorDrift.event.fact).toMatchObject({
      kind: "identity-drift-recorded",
      source: "operator-projection",
      attestation: "unattested",
    });

    const profileDrift = recordIdentityDrift(
      base.snapshots[1],
      {
        scope: "execution-profile",
        expectedDigest: base.genesis.protocolDigest,
        observedDigest: DIGEST_Z,
        reasonCode: "profile-identity-drift",
      },
      "2026-07-20T00:00:02.000Z",
    );
    expect(profileDrift.snapshot.state).toBe("STALE");

    const retired = retireController(
      base.final,
      { reasonCode: "experiment-complete" },
      "2026-07-24T00:00:03.000Z",
    );
    expect(retired.snapshot.state).toBe("RETIRED");
    expect(() => recordIdentityDrift(
      retired.snapshot,
      {
        scope: "source",
        expectedDigest: base.genesis.protocolDigest,
        observedDigest: DIGEST_Z,
        reasonCode: "late-drift",
      },
      "2026-07-24T00:00:04.000Z",
    )).toThrow(/retired|terminal/i);
  });
});

describe("sealed window revision lineage and online status mapping", () => {
  it("rejects old, sibling, gapped, and forked revisions", () => {
    const flow = assessmentFlow();
    const run = appendHappyPath(flow);
    const atFirstManifest = run.snapshots[6];
    const revisionA = createWindowManifestRevision(flow.manifest, {
      ingestionWatermark: "2026-07-23T00:03:00.000Z",
      closureReason: "late-evidence-a",
      traceSetDigest: flow.manifest.traceSetDigest,
      evaluatorSetDigest: DIGEST_Z,
      capacityEvidence: flow.manifest.capacityEvidence,
    });
    const revisionB = createWindowManifestRevision(flow.manifest, {
      ingestionWatermark: "2026-07-23T00:04:00.000Z",
      closureReason: "late-evidence-b",
      traceSetDigest: DIGEST_Z,
      evaluatorSetDigest: flow.manifest.evaluatorSetDigest,
      capacityEvidence: flow.manifest.capacityEvidence,
    });
    const afterA = recordWindowManifest(
      atFirstManifest,
      revisionA,
      "2026-07-24T00:00:00.500Z",
    ).snapshot;

    expect(() => recordWindowManifest(
      afterA,
      flow.manifest,
      "2026-07-24T00:00:00.600Z",
    )).toThrow(/revision|old|latest/i);
    expect(() => recordWindowManifest(
      afterA,
      revisionB,
      "2026-07-24T00:00:00.600Z",
    )).toThrow(/revision|predecessor|sibling|fork/i);

    const gappedBody = {
      ...flow.manifest,
      revision: 3,
      predecessorManifestDigest: revisionA.selfDigest,
    };
    const gapped = parseWindowManifest({
      ...gappedBody,
      selfDigest: fingerprintWindowManifest(gappedBody),
    });
    expect(() => recordWindowManifest(
      atFirstManifest,
      gapped,
      "2026-07-24T00:00:00.600Z",
    )).toThrow(/revision|gap|expected/i);
  });

  it("preserves event bounds and nondecreasing source-bearing revisions", () => {
    const flow = assessmentFlow();
    const run = appendHappyPath(flow);
    const atFirstManifest = run.snapshots[6];
    const validRevision = createWindowManifestRevision(flow.manifest, {
      ingestionWatermark: "2026-07-23T00:03:00.000Z",
      closureReason: "late-evidence",
      traceSetDigest: DIGEST_Z,
      evaluatorSetDigest: flow.manifest.evaluatorSetDigest,
      capacityEvidence: flow.manifest.capacityEvidence,
    });

    const changedStart = redigestManifest(validRevision, (manifest) => {
      manifest.eventTimeStartInclusive =
        "2026-07-23T00:00:01.000Z";
    });
    expect(() => recordWindowManifest(
      atFirstManifest,
      changedStart,
      "2026-07-24T00:00:00.500Z",
    )).toThrow(/event-time|event bounds|immutable/i);

    const changedEnd = redigestManifest(validRevision, (manifest) => {
      manifest.eventTimeEndExclusive =
        "2026-07-23T00:01:01.000Z";
    });
    expect(() => recordWindowManifest(
      atFirstManifest,
      changedEnd,
      "2026-07-24T00:00:00.500Z",
    )).toThrow(/event-time|event bounds|immutable/i);

    const regressedWatermark = redigestManifest(
      validRevision,
      (manifest) => {
        manifest.ingestionWatermark =
          "2026-07-23T00:01:00.000Z";
      },
    );
    expect(() => recordWindowManifest(
      atFirstManifest,
      regressedWatermark,
      "2026-07-24T00:00:00.500Z",
    )).toThrow(/watermark.*nondecreasing|watermark.*regress/i);

    const noSourceChange = redigestManifest(
      flow.manifest,
      (manifest) => {
        manifest.revision = 2;
        manifest.predecessorManifestDigest = flow.manifest.selfDigest;
        manifest.closureReason = "metadata-only-change";
      },
    );
    expect(() => recordWindowManifest(
      atFirstManifest,
      noSourceChange,
      "2026-07-24T00:00:00.500Z",
    )).toThrow(/source.*change|capacity.*change|no-op revision/i);

    const capacityOnlyRevision = createWindowManifestRevision(
      flow.manifest,
      {
        ingestionWatermark: flow.manifest.ingestionWatermark,
        closureReason: "capacity-rechecked",
        traceSetDigest: flow.manifest.traceSetDigest,
        evaluatorSetDigest: flow.manifest.evaluatorSetDigest,
        capacityEvidence: {
          kind: "unavailable",
          reasonCode: "capacity-rechecked",
        },
      },
    );
    const withCapacityRevision = recordWindowManifest(
      atFirstManifest,
      capacityOnlyRevision,
      "2026-07-24T00:00:00.500Z",
    );
    expect(withCapacityRevision.snapshot.windows[0].revisions).toHaveLength(2);
  });

  it("invalidates a recommendation on late evidence and assesses latest revision only", () => {
    const flow = assessmentFlow();
    const run = appendHappyPath(flow);
    const newOnline = datasetFixture(flow.protocol, "online", {
      policyDigest: flow.nomination.selectedPolicyDigest,
      windowId: "window-1",
      windowMembershipDigest: flow.manifest.membershipDigest,
      candidateScore: 0.91,
    });
    const revision = createWindowManifestRevision(flow.manifest, {
      ingestionWatermark: "2026-07-23T00:03:00.000Z",
      closureReason: "late-evidence",
      traceSetDigest: newOnline.dataset.traceSetDigest,
      evaluatorSetDigest: newOnline.dataset.evaluatorSetDigest,
      capacityEvidence: flow.manifest.capacityEvidence,
    });
    const latestDecision = assessPolicyWindow(
      flow.protocol,
      newOnline.dataset,
      flow.nomination.selectedPolicy,
      revision,
      newOnline.context,
      TEST_WORK_BUDGET,
    );
    const revised = recordWindowManifest(
      run.snapshots[7],
      revision,
      "2026-07-24T00:00:02.000Z",
    );

    expect(revised.snapshot.state).toBe("HOLDOUT_CONFIRMED");
    expect(() => recordWindowAssessment(
      revised.snapshot,
      flow.windowDecision,
      "2026-07-24T00:00:03.000Z",
    )).toThrow(/latest|revision|manifest/i);
    const reassessed = recordWindowAssessment(
      revised.snapshot,
      latestDecision,
      "2026-07-24T00:00:03.000Z",
    );
    expect(reassessed.snapshot.state).toBe("PROMOTION_RECOMMENDED");
  });

  it("maps a monitored online regression to ROLLBACK_RECOMMENDED", () => {
    const passing = assessmentFlow();
    const run = appendHappyPath(passing);
    const regressedOnline = datasetFixture(passing.protocol, "online", {
      policyDigest: passing.nomination.selectedPolicyDigest,
      windowId: "window-1",
      windowMembershipDigest: passing.manifest.membershipDigest,
      candidateScore: 0.1,
      championScore: 0.95,
    });
    const revision = createWindowManifestRevision(passing.manifest, {
      ingestionWatermark: "2026-07-23T00:03:00.000Z",
      closureReason: "monitoring-regression",
      traceSetDigest: regressedOnline.dataset.traceSetDigest,
      evaluatorSetDigest: regressedOnline.dataset.evaluatorSetDigest,
      capacityEvidence: passing.manifest.capacityEvidence,
    });
    const regression = assessPolicyWindow(
      passing.protocol,
      regressedOnline.dataset,
      passing.nomination.selectedPolicy,
      revision,
      regressedOnline.context,
      TEST_WORK_BUDGET,
    );
    expect(regression.status).toBe("HOLD");

    const withRevision = recordWindowManifest(
      run.final,
      revision,
      "2026-07-24T00:00:03.000Z",
    ).snapshot;
    expect(withRevision.state).toBe("MONITORING");
    const recommendation = recordWindowAssessment(
      withRevision,
      regression,
      "2026-07-24T00:00:04.000Z",
    );
    expect(recommendation.snapshot.state).toBe("ROLLBACK_RECOMMENDED");
    expect(recommendation.event.fact.kind)
      .toBe("window-assessment-recorded");
  });

  it("rejects cross-policy, context, source, and window projection splices", () => {
    const flow = assessmentFlow();
    const run = appendHappyPath(flow);
    const decisionEvent = run.events[7];
    const splices = [
      {
        field: "assessmentContextDigest",
        change: (projection: any) => {
          projection.assessmentContextDigest = DIGEST_Z;
        },
      },
      {
        field: "traceSetDigest",
        change: (projection: any) => {
          projection.traceSetDigest = DIGEST_Z;
        },
      },
      {
        field: "evaluatorSetDigest",
        change: (projection: any) => {
          projection.evaluatorSetDigest = DIGEST_Z;
        },
      },
      {
        field: "selectedPolicy.policyDigest",
        change: (projection: any) => {
          projection.selectedPolicy.policyDigest = DIGEST_Z;
        },
      },
      {
        field: "windowManifestDigest",
        change: (projection: any) => {
          projection.windowManifestDigest = DIGEST_Z;
        },
      },
    ];
    for (const { field, change } of splices) {
      const spliced = redigestEvent(decisionEvent, (event) => {
        change(event.fact.projection);
      });
      expect(() => replayController(
        run.genesis,
        [...run.events.slice(0, 7), spliced],
        { assessmentDecisions: allDecisions(flow) },
      ), field).toThrow(/projection|assessment|policy|window|source/i);
    }
  });
});
