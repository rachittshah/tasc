import { describe, expect, it } from "vitest";
import {
  createControllerSnapshot,
  type ControllerSnapshot,
  type ControllerState,
} from "../src/controller-events.js";
import {
  fingerprintProtocol,
  parseExperimentProtocol,
  type ExperimentProtocol,
} from "../src/evidence.js";
import {
  enumerateProtocolPolicyBundles,
  type PolicyBundle,
} from "../src/policy.js";
import {
  buildShadowRunPlan,
  fingerprintShadowRunPlan,
  isShadowRunPlanMember,
  parseShadowRunPlan,
  SHADOW_RUN_PLAN_AUTHORITY,
  SHADOW_RUN_PLAN_VERSION,
  type BuildShadowRunPlanInput,
  type ShadowRunPlan,
} from "../src/shadow-plan.js";
import {
  TEST_WORK_BUDGET,
  digest,
  validProtocolInput,
} from "./fixtures/evidence.js";

const PLAN_ISSUED_AT = "2026-07-22T00:00:01.000Z";
const WINDOW_START = "2026-07-22T00:01:00.000Z";
const WINDOW_END = "2026-07-22T01:00:00.000Z";
const PLAN_EXPIRES_AT = "2026-07-22T02:00:00.000Z";

function protocolFixture(
  change?: (input: ReturnType<typeof validProtocolInput>) => void,
): ExperimentProtocol {
  const input = validProtocolInput();
  change?.(input);
  return parseExperimentProtocol(input, TEST_WORK_BUDGET);
}

function policySpace(protocol: ExperimentProtocol): {
  readonly selected: PolicyBundle;
  readonly alternative: PolicyBundle;
} {
  const policies = enumerateProtocolPolicyBundles(
    protocol,
    fingerprintProtocol(protocol),
    protocol.createdAt,
  ).candidates;
  if (policies[0] === undefined || policies[1] === undefined) {
    throw new Error("shadow-plan test protocol requires two policies");
  }
  return {
    selected: policies[0],
    alternative: policies[1],
  };
}

function controllerSnapshot(
  protocol: ExperimentProtocol,
  policy: PolicyBundle,
  state: Extract<ControllerState, "NOMINATED" | "SHADOW_ASSESSING"> =
    "SHADOW_ASSESSING",
): ControllerSnapshot {
  const protocolDigest = fingerprintProtocol(protocol);
  const selectedPolicy = {
    policyDigest: policy.policyDigest,
    issuedAt: policy.issuedAt,
    expiresAt: policy.expiresAt,
  };
  const developmentEvidence = {
    datasetDigest: digest("1"),
    traceSetDigest: digest("2"),
    evaluatorSetDigest: digest("3"),
  };
  return createControllerSnapshot({
    version: "tasc-controller-snapshot-v1",
    controllerId: "shadow-controller-1",
    studyId: protocol.studyId,
    protocolDigest,
    protocolCreatedAt: protocol.createdAt,
    protocolExpiresAt: protocol.expiresAt,
    state,
    sequence: state === "SHADOW_ASSESSING" ? 5 : 4,
    lastEventId: digest(state === "SHADOW_ASSESSING" ? "5" : "4"),
    lastEventAt: state === "SHADOW_ASSESSING"
      ? "2026-07-22T00:00:00.000Z"
      : "2026-07-21T23:59:59.000Z",
    collectionId: "shadow-collection-1",
    developmentEvidence,
    selectedPolicy,
    assessments: [
      {
        version: "tasc-controller-assessment-projection-v1",
        phase: "development",
        status: "NOMINATED",
        decisionDigest: digest("6"),
        assessmentContextDigest: digest("7"),
        protocolDigest,
        ...developmentEvidence,
        selectedPolicy,
        windowManifestDigest: null,
        attestation: "unattested",
      },
    ],
    windows: [],
    deploymentObservation: null,
    staleReasons: [],
    attestation: "unattested",
  });
}

function inputFixture(options: {
  readonly protocol?: ExperimentProtocol;
  readonly policy?: PolicyBundle;
  readonly snapshot?: ControllerSnapshot;
} = {}): BuildShadowRunPlanInput {
  const protocol = options.protocol ?? protocolFixture();
  const selected = options.policy ?? policySpace(protocol).selected;
  return {
    controllerSnapshot:
      options.snapshot ?? controllerSnapshot(protocol, selected),
    protocol,
    frozenPolicy: selected,
    window: {
      windowId: "shadow-window-1",
      eventTimeStartInclusive: WINDOW_START,
      eventTimeEndExclusive: WINDOW_END,
    },
    collectionTargets: [
      {
        profileId: "candidate",
        endpointAlias: "approved-vllm",
        endpointBindingDigest: digest("8"),
        route: "chatCompletions",
        authenticationReference: null,
        capabilityReceiptDigests: [digest("b"), digest("a")],
      },
      {
        profileId: "champion",
        endpointAlias: "approved-vllm",
        endpointBindingDigest: digest("9"),
        route: "chatCompletions",
        authenticationReference: null,
        capabilityReceiptDigests: [],
      },
    ],
    workBudget: {
      maxCases: 10,
      maxProfiles: 2,
      maxReplicates: 2,
      maxLogicalExecutions: 40,
      maxAttempts: 80,
      maxNetworkCalls: 82,
      maxDurableRecords: 500,
      maxRequestBytes: 64 * 1024,
      maxResponseBytes: 1024 * 1024,
      maxWallClockMs: 30 * 60 * 1_000,
      maxConcurrency: 2,
    },
    issuedAt: PLAN_ISSUED_AT,
    expiresAt: PLAN_EXPIRES_AT,
  };
}

function clonePlan(plan: ShadowRunPlan): Record<string, any> {
  return structuredClone(plan) as Record<string, any>;
}

function cloneInput(input: BuildShadowRunPlanInput): any {
  return structuredClone(input);
}

describe("shadow run plan", () => {
  it("builds one self-contained, canonical, immutable P0 artifact", () => {
    const plan = buildShadowRunPlan(inputFixture());

    expect(plan.version).toBe(SHADOW_RUN_PLAN_VERSION);
    expect(plan.authority).toBe(SHADOW_RUN_PLAN_AUTHORITY);
    expect(plan.controllerSnapshotDigest)
      .toBe(plan.controllerSnapshot.snapshotDigest);
    expect(plan.protocolDigest).toBe(fingerprintProtocol(plan.protocol));
    expect(plan.frozenPolicyDigest).toBe(plan.frozenPolicy.policyDigest);
    expect(plan.collectionTargets.map(({ profileId }) => profileId))
      .toEqual(["candidate", "champion"]);
    expect(plan.collectionTargets[0].capabilityReceiptDigests)
      .toEqual([digest("a"), digest("b")]);
    expect(plan.planDigest).toBe(fingerprintShadowRunPlan(plan));
    expect(parseShadowRunPlan(plan)).toEqual(plan);
    expect(Object.isFrozen(plan)).toBe(true);
    expect(Object.isFrozen(plan.protocol.profiles)).toBe(true);
    expect(Object.isFrozen(plan.collectionTargets[0])).toBe(true);
  });

  it("rejects a controller outside SHADOW_ASSESSING", () => {
    const protocol = protocolFixture();
    const selected = policySpace(protocol).selected;
    expect(() => buildShadowRunPlan(inputFixture({
      protocol,
      policy: selected,
      snapshot: controllerSnapshot(protocol, selected, "NOMINATED"),
    }))).toThrow(/SHADOW_ASSESSING/);
  });

  it("rejects a different policy than the controller selected", () => {
    const protocol = protocolFixture();
    const { selected, alternative } = policySpace(protocol);
    expect(() => buildShadowRunPlan(inputFixture({
      protocol,
      policy: alternative,
      snapshot: controllerSnapshot(protocol, selected),
    }))).toThrow(/policy.*controller|controller.*policy/i);
  });

  it("rejects a protocol different from the controller snapshot", () => {
    const originalProtocol = protocolFixture();
    const originalPolicy = policySpace(originalProtocol).selected;
    const otherProtocol = protocolFixture((input) => {
      input.studyId = "different-shadow-study";
    });
    const otherPolicy = policySpace(otherProtocol).selected;
    expect(() => buildShadowRunPlan(inputFixture({
      protocol: otherProtocol,
      policy: otherPolicy,
      snapshot: controllerSnapshot(originalProtocol, originalPolicy),
    }))).toThrow(/protocol/i);
  });

  it("rejects event windows and plan validity outside protocol authority", () => {
    const startsBeforeIssue = cloneInput(inputFixture());
    startsBeforeIssue.window.eventTimeStartInclusive =
      "2026-07-21T23:59:59.000Z";
    expect(() => buildShadowRunPlan(startsBeforeIssue))
      .toThrow(/window.*before plan issue/i);

    const expiresAfterPolicy = cloneInput(inputFixture());
    expiresAfterPolicy.expiresAt = "2026-08-20T00:00:00.001Z";
    expect(() => buildShadowRunPlan(expiresAfterPolicy))
      .toThrow(/protocol validity/i);
  });

  it("rejects wall-clock work that cannot fit inside its event window", () => {
    const widerThanWindow = cloneInput(inputFixture());
    widerThanWindow.workBudget.maxWallClockMs =
      Date.parse(WINDOW_END) - Date.parse(WINDOW_START) + 1;
    expect(() => buildShadowRunPlan(widerThanWindow))
      .toThrow(/wall-clock budget exceeds the event window/i);
  });

  it("rejects missing, unknown, and protocol-mismatched endpoint bindings", () => {
    const missing = cloneInput(inputFixture());
    missing.collectionTargets.pop();
    expect(() => buildShadowRunPlan(missing))
      .toThrow(/every protocol execution profile/i);

    const unknown = cloneInput(inputFixture());
    unknown.collectionTargets[0].profileId = "unknown-profile";
    expect(() => buildShadowRunPlan(unknown))
      .toThrow(/unknown profile/i);

    const mismatched = cloneInput(inputFixture());
    mismatched.collectionTargets[0].endpointAlias = "unapproved-endpoint";
    expect(() => buildShadowRunPlan(mismatched))
      .toThrow(/endpoint requirement/i);
  });

  it("rejects a valid-looking artifact when its self digest is stale", () => {
    const plan = buildShadowRunPlan(inputFixture());
    const tampered = clonePlan(plan);
    tampered.workBudget.maxCases += 1;

    expect(() => parseShadowRunPlan(tampered)).toThrow(/plan digest/i);
  });

  it("rejects caller-authored derived window and target identities", () => {
    const plan = buildShadowRunPlan(inputFixture());
    const wrongWindow = clonePlan(plan);
    wrongWindow.window.membershipRule = {
      ...wrongWindow.window.membershipRule,
      seed: "caller-selected-seed",
    };
    expect(() => parseShadowRunPlan(wrongWindow))
      .toThrow(/window membership/i);

    const wrongTarget = clonePlan(plan);
    wrongTarget.collectionTargets[0].runtimeName = "caller-runtime";
    expect(() => parseShadowRunPlan(wrongTarget))
      .toThrow(/canonically derived/i);
  });

  it("makes deterministic membership decisions, including zero effects", () => {
    const plan = buildShadowRunPlan(inputFixture());
    const first = isShadowRunPlanMember(plan, "case-1", "replicate-1");
    expect(isShadowRunPlanMember(plan, "case-1", "replicate-1")).toBe(first);

    const zeroProtocol = protocolFixture((input) => {
      input.onlineWindowMembership.sampleBasisPoints = 0;
    });
    const zeroPolicy = policySpace(zeroProtocol).selected;
    const zeroPlan = buildShadowRunPlan(inputFixture({
      protocol: zeroProtocol,
      policy: zeroPolicy,
      snapshot: controllerSnapshot(zeroProtocol, zeroPolicy),
    }));
    for (let index = 0; index < 32; index += 1) {
      expect(isShadowRunPlanMember(
        zeroPlan,
        `case-${index}`,
        `replicate-${index}`,
      )).toBe(false);
    }
  });
});
