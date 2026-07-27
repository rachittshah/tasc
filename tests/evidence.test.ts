import { describe, expect, it } from "vitest";
import {
  fingerprintExecutionProfile,
  fingerprintProtocol,
  parseEvaluatorEvidence,
  parseExperimentProtocol,
  parseTraceEnvelope,
} from "../src/evidence.js";
import {
  TEST_WORK_BUDGET,
  digest,
  evaluatorKeyFixture,
  mutate,
  validEvaluatorEvidenceInput,
  validExecutionProfile,
  validProtocolInput,
  validTraceInput,
} from "./fixtures/evidence.js";

describe("evidence v2 contracts", () => {
  it("parses and freezes a bounded protocol, logical profile trace, and evaluator record", () => {
    const key = evaluatorKeyFixture();
    const protocol = parseExperimentProtocol(validProtocolInput(), TEST_WORK_BUDGET);
    const trace = parseTraceEnvelope(validTraceInput(), TEST_WORK_BUDGET);
    const evidence = parseEvaluatorEvidence(
      validEvaluatorEvidenceInput(key.privateKey),
      TEST_WORK_BUDGET,
    );

    expect(protocol.version).toBe("tasc-experiment-protocol-v2");
    expect(protocol.splitMembership).toMatchObject({
      algorithm: "tasc-seeded-sha256-group-bucket-v1",
      bucketCount: 10,
      developmentBuckets: [0, 1, 2, 3, 4, 5, 6, 7],
      holdoutBuckets: [8, 9],
    });
    expect(protocol.criticalSlices).toEqual(["payments", "account-recovery"]);
    expect(protocol.evaluator).toMatchObject({
      producerKind: "deterministic",
      producerId: "support-evaluator-service",
      producerVersion: "4.2.0",
    });
    expect(trace).toMatchObject({
      profileId: "champion",
      caseId: "case-1",
      replicateId: "replicate-0",
      attempts: [{ attemptNumber: 1 },],
    });
    expect(evidence).toMatchObject({
      traceId: trace.traceId,
      profileId: trace.profileId,
      terminalOutputId: trace.terminalOutputId,
      evaluator: {
        evaluatorId: "support-correctness",
        rubricVersion: "rubric-4",
      },
    });
    expect(Object.isFrozen(protocol)).toBe(true);
    expect(Object.isFrozen(protocol.profiles[0].runtime)).toBe(true);
    expect(Object.isFrozen(trace.attempts[0].observerTimings)).toBe(true);
    expect(Object.isFrozen(evidence.outcome)).toBe(true);
  });

  it("keeps route-signal provenance separate from evaluator provenance and scores", () => {
    const key = evaluatorKeyFixture();
    const trace = parseTraceEnvelope(validTraceInput(), TEST_WORK_BUDGET);
    const evidence = parseEvaluatorEvidence(
      validEvaluatorEvidenceInput(key.privateKey),
      TEST_WORK_BUDGET,
    );

    expect(trace.routeSignal?.provenance.kind).toBe("route-signal-observation");
    expect(evidence.evaluator.producer.kind).toBe("deterministic");
    expect("outcome" in trace).toBe(false);
    expect("evaluator" in trace).toBe(false);
  });

  it.each([
    ["task score", (trace: any) => { trace.attempts[0].taskScore = 0.99; }],
    ["attempt evaluator", (trace: any) => { trace.attempts[0].evaluator = { id: "judge" }; }],
    ["authorization", (trace: any) => { trace.attempts[0].authorization = "Bearer secret"; }],
    ["headers", (trace: any) => { trace.attempts[0].headers = { authorization: "secret" }; }],
    ["secret", (trace: any) => { trace.attempts[0].secret = "token"; }],
    ["generic metadata smuggling", (trace: any) => { trace.attempts[0].metadata = { taskScore: 1 }; }],
    ["provider smuggling", (trace: any) => { trace.attempts[0].providerReported.headers = {}; }],
  ])("rejects trace %s fields recursively", (_label, change) => {
    expect(() => parseTraceEnvelope(mutate(validTraceInput(), change), TEST_WORK_BUDGET)).toThrow();
  });

  it("requires contiguous ordered attempts with valid observer-time order", () => {
    const retry = validTraceInput();
    const secondAttempt = structuredClone(retry.attempts[0]);
    retry.attempts[0].status = "failure" as "success";
    retry.attempts[0].finishReason = null as unknown as string;
    retry.attempts[0].partialOutput = true;
    retry.attempts[0].failureCategory = "transport-timeout" as unknown as null;
    secondAttempt.attemptId = "attempt-2";
    secondAttempt.attemptNumber = 2;
    secondAttempt.observerTimings.startedAt = "2026-07-21T00:00:01.000Z";
    secondAttempt.observerTimings.headersAt = "2026-07-21T00:00:01.050Z";
    secondAttempt.observerTimings.firstByteAt = "2026-07-21T00:00:01.060Z";
    secondAttempt.observerTimings.firstMeaningfulTokenAt = "2026-07-21T00:00:01.075Z";
    secondAttempt.observerTimings.completedAt = "2026-07-21T00:00:01.500Z";
    retry.attempts.push(secondAttempt);
    expect(parseTraceEnvelope(retry, TEST_WORK_BUDGET).attempts).toHaveLength(2);

    expect(() => parseTraceEnvelope(
      mutate(retry, (value) => { value.attempts[1].attemptNumber = 3; }),
      TEST_WORK_BUDGET,
    )).toThrow(/contiguous|attemptNumber/i);
    expect(() => parseTraceEnvelope(
      mutate(retry, (value) => { value.attempts[1].attemptId = "attempt-1"; }),
      TEST_WORK_BUDGET,
    )).toThrow(/duplicate.*attempt/i);
    expect(() => parseTraceEnvelope(
      mutate(retry, (value) => {
        value.attempts[0].observerTimings.firstByteAt = "2026-07-20T23:59:59.000Z";
      }),
      TEST_WORK_BUDGET,
    )).toThrow(/timing|firstByteAt/i);
    expect(() => parseTraceEnvelope(
      mutate(retry, (value) => {
        value.attempts[1].observerTimings.startedAt = "2026-07-20T23:59:59.000Z";
      }),
      TEST_WORK_BUDGET,
    )).toThrow(/ordered|attempt/i);
  });

  it("rejects inconsistent profile and terminal outcome references", () => {
    expect(() => parseTraceEnvelope(
      mutate(validTraceInput(), (trace) => { trace.observedRoute.selectedProfileId = "candidate"; }),
      TEST_WORK_BUDGET,
    )).toThrow(/selected profile.*top-level profile/i);
    expect(() => parseTraceEnvelope(
      mutate(validTraceInput(), (trace) => { trace.executionProfileDigest = digest("f"); }),
      TEST_WORK_BUDGET,
    )).not.toThrow();
    expect(() => parseTraceEnvelope(
      mutate(validTraceInput(), (trace) => {
        trace.attempts[0].status = "failure" as "success";
      }),
      TEST_WORK_BUDGET,
    )).toThrow(/failureCategory|success|failure/i);

    const online = mutate(validTraceInput(), (trace: any) => {
      trace.split = "online";
      trace.collectionWindowId = "shadow-window-1";
      trace.collectionWindowMembershipDigest = digest("a");
      trace.sourceMode = "shadow";
    });
    expect(() => parseTraceEnvelope(online, TEST_WORK_BUDGET)).not.toThrow();
    expect(() => parseTraceEnvelope(
      mutate(online, (trace) => { trace.collectionWindowMembershipDigest = null; }),
      TEST_WORK_BUDGET,
    )).toThrow(/window.*membership digest/i);
  });

  it("requires keyed or controlled payload identities, distinct observer/provider timing, and classified cost", () => {
    const controlled = validTraceInput();
    controlled.attempts[0].payloads.response = {
      kind: "controlled-reference",
      storeId: "approved-payload-store",
      referenceId: "study-object-42",
      digest: digest("f"),
    } as never;
    expect(() => parseTraceEnvelope(controlled, TEST_WORK_BUDGET)).not.toThrow();

    const plainHash = mutate(validTraceInput(), (trace: any) => {
      trace.attempts[0].payloads.request = { kind: "digest", digest: digest("a") };
    });
    expect(() => parseTraceEnvelope(plainHash, TEST_WORK_BUDGET)).toThrow();

    const rawUrl = mutate(validTraceInput(), (trace: any) => {
      trace.attempts[0].payloads.request = {
        kind: "controlled-reference",
        storeId: "approved-payload-store",
        referenceId: "https://evil.test/prompt",
      };
    });
    expect(() => parseTraceEnvelope(rawUrl, TEST_WORK_BUDGET)).toThrow();

    const modeledWithoutDigest = mutate(validTraceInput(), (trace: any) => {
      delete trace.attempts[0].cost.modelDigest;
    });
    expect(() => parseTraceEnvelope(modeledWithoutDigest, TEST_WORK_BUDGET)).toThrow();

    const tokenWithoutSemantics = mutate(validTraceInput(), (trace: any) => {
      delete trace.attempts[0].tokenUsage.output.semantics;
    });
    expect(() => parseTraceEnvelope(tokenWithoutSemantics, TEST_WORK_BUDGET)).toThrow();
  });

  it("changes profile fingerprints for every execution identity field", () => {
    const base = validExecutionProfile();
    const baseline = fingerprintExecutionProfile(base);
    const mutations: Array<(profile: ReturnType<typeof validExecutionProfile>) => void> = [
      (profile) => { profile.runtime.build = "0.10.3"; },
      (profile) => { profile.backend.name = "rocm"; },
      (profile) => { profile.model.revision = "model-rev-2"; },
      (profile) => { profile.tokenizer.revision = "tokenizer-rev-8"; },
      (profile) => { profile.hardware.accelerator = "h200-sxm"; },
      (profile) => { profile.quantization.format = "int8"; },
      (profile) => { profile.chatTemplateDigest = digest("0"); },
      (profile) => { profile.orchestration.kind = "ray-serve" as "direct"; },
      (profile) => { profile.deploymentConfigurationDigest = digest("0"); },
    ];

    for (const change of mutations) {
      expect(fingerprintExecutionProfile(mutate(base, change))).not.toBe(baseline);
    }
  });

  it("derives domain-separated canonical identities independent of insertion order", () => {
    const protocol = validProtocolInput();
    const reordered = {
      profiles: protocol.profiles,
      version: protocol.version,
      studyId: protocol.studyId,
      protocolVersion: protocol.protocolVersion,
      owner: protocol.owner,
      createdAt: protocol.createdAt,
      expiresAt: protocol.expiresAt,
      splitMembership: protocol.splitMembership,
      onlineWindowMembership: protocol.onlineWindowMembership,
      championProfileId: protocol.championProfileId,
      candidateProfileIds: protocol.candidateProfileIds,
      routeSignal: protocol.routeSignal,
      evaluator: protocol.evaluator,
      candidatePolicySpace: protocol.candidatePolicySpace,
      gates: protocol.gates,
      criticalSlices: protocol.criticalSlices,
      bootstrap: protocol.bootstrap,
      shadowCollection: protocol.shadowCollection,
      costAllocation: protocol.costAllocation,
      endpointRequirements: protocol.endpointRequirements,
      requiredCapabilities: protocol.requiredCapabilities,
    };

    expect(fingerprintProtocol(reordered)).toBe(fingerprintProtocol(protocol));
    expect(fingerprintProtocol(protocol)).toMatch(/^sha256:[a-f0-9]{64}$/);
    expect(fingerprintProtocol(protocol)).not.toBe(fingerprintExecutionProfile(protocol.profiles[0]));
  });

  it("rejects duplicate or inconsistent protocol references and split buckets", () => {
    expect(() => parseExperimentProtocol(
      mutate(validProtocolInput(), (protocol) => {
        protocol.profiles[1].id = "champion";
      }),
      TEST_WORK_BUDGET,
    )).toThrow(/duplicate profile/i);
    expect(() => parseExperimentProtocol(
      mutate(validProtocolInput(), (protocol) => {
        protocol.candidateProfileIds = ["missing"];
      }),
      TEST_WORK_BUDGET,
    )).toThrow(/candidate profile.*missing/i);
    expect(() => parseExperimentProtocol(
      mutate(validProtocolInput(), (protocol) => {
        protocol.splitMembership.holdoutBuckets = [7, 8, 9];
      }),
      TEST_WORK_BUDGET,
    )).toThrow(/bucket.*overlap/i);
    expect(() => parseExperimentProtocol(
      mutate(validProtocolInput(), (protocol) => {
        protocol.splitMembership.holdoutBuckets = [9];
      }),
      TEST_WORK_BUDGET,
    )).toThrow(/bucket.*partition|missing/i);
    expect(() => parseExperimentProtocol(
      mutate(validProtocolInput(), (protocol) => {
        protocol.candidatePolicySpace.predicates[0].routeToProfileId = "missing";
      }),
      TEST_WORK_BUDGET,
    )).toThrow(/predicate.*profile/i);
    expect(() => parseExperimentProtocol(
      mutate(validProtocolInput(), (protocol) => {
        protocol.criticalSlices.push("payments");
      }),
      TEST_WORK_BUDGET,
    )).toThrow(/duplicate critical slice/i);
    expect(() => parseExperimentProtocol(
      mutate(validProtocolInput(), (protocol) => {
        protocol.criticalSlices = [];
      }),
      TEST_WORK_BUDGET,
    )).toThrow(/critical.slice.*minimum|minimum.*critical.slice/i);
    expect(() => parseExperimentProtocol(
      mutate(validProtocolInput(), (protocol) => {
        protocol.criticalSlices = [];
        protocol.gates.minimumCriticalSliceGroups = 0;
      }),
      TEST_WORK_BUDGET,
    )).not.toThrow();
  });

  it.each([
    ["unknown field", () => mutate(validProtocolInput(), (value: any) => { value.typo = true; })],
    ["malformed slug", () => mutate(validProtocolInput(), (value) => { value.studyId = "not a slug"; })],
    ["malformed digest", () => mutate(validProtocolInput(), (value) => { value.routeSignal.calibrationDigest = "abc"; })],
    ["malformed timestamp", () => mutate(validProtocolInput(), (value) => { value.createdAt = "yesterday"; })],
    ["non-finite number", () => mutate(validProtocolInput(), (value) => { value.gates.maximumFailureRate = Number.NaN; })],
    ["invalid expiry order", () => mutate(validProtocolInput(), (value) => { value.expiresAt = value.createdAt; })],
    ["oversized array", () => mutate(validProtocolInput(), (value) => {
      value.requiredCapabilities = Array.from({ length: 129 }, (_, index) => `cap-${index}`);
    })],
    ["oversized string", () => mutate(validProtocolInput(), (value) => { value.owner = "x".repeat(257); })],
  ])("rejects protocol %s", (_label, invalid) => {
    expect(() => parseExperimentProtocol(invalid(), TEST_WORK_BUDGET)).toThrow();
  });

  it("charges protocol, trace, and evaluator parsing to the caller's work budget", () => {
    expect(() => parseExperimentProtocol(validProtocolInput(), {
      ...TEST_WORK_BUDGET,
      maxCandidates: 7,
    })).toThrow(/candidate.*work budget/i);
    expect(() => parseExperimentProtocol(validProtocolInput(), {
      ...TEST_WORK_BUDGET,
      maxBootstrapDraws: 999,
    })).toThrow(/bootstrap.*work budget/i);
    expect(() => parseExperimentProtocol(validProtocolInput(), {
      ...TEST_WORK_BUDGET,
      maxIndependentGroups: 9,
    })).toThrow(/independent group.*work budget/i);
    expect(() => parseExperimentProtocol(validProtocolInput(), {
      ...TEST_WORK_BUDGET,
      maxAssessmentWork: 79_999,
    })).toThrow(/assessment work.*work budget/i);
    expect(() => parseExperimentProtocol(
      mutate(validProtocolInput(), (protocol) => {
        protocol.gates.minimumIndependentGroups = 2;
        protocol.gates.minimumCriticalSliceGroups = 12;
      }),
      { ...TEST_WORK_BUDGET, maxIndependentGroups: 11 },
    )).toThrow(/independent group.*work budget/i);
    expect(() => parseTraceEnvelope(validTraceInput(), {
      ...TEST_WORK_BUDGET,
      maxTraceRows: 0,
    })).toThrow(/trace.*work budget/i);
    const key = evaluatorKeyFixture();
    expect(() => parseEvaluatorEvidence(validEvaluatorEvidenceInput(key.privateKey), {
      ...TEST_WORK_BUDGET,
      maxEvidenceRows: 0,
    })).toThrow(/evidence.*work budget/i);
  });

  it("preflights adversarial input shape before recursive schema parsing", () => {
    const protocol = validProtocolInput() as any;
    protocol.requiredCapabilities = new Array(100_000).fill("streaming");

    expect(() => parseExperimentProtocol(protocol, TEST_WORK_BUDGET))
      .toThrow(/bounded contract input.*array/i);

    class ProtocolObject {
      constructor() {
        Object.assign(this, validProtocolInput());
      }
    }
    expect(() => parseExperimentProtocol(new ProtocolObject(), TEST_WORK_BUDGET))
      .toThrow(/plain JSON object/i);
  });

  it("retains array hole and extra-property rejection during snapshotting", () => {
    const withHole = validProtocolInput();
    withHole.requiredCapabilities = new Array<string>(2);
    withHole.requiredCapabilities[0] = "streaming";
    expect(() => parseExperimentProtocol(withHole, TEST_WORK_BUDGET))
      .toThrow(/arrays cannot contain holes/i);

    const withExtraProperty = validProtocolInput();
    Object.defineProperty(withExtraProperty.requiredCapabilities, "metadata", {
      enumerable: true,
      value: "not-array-data",
    });
    expect(() => parseExperimentProtocol(withExtraProperty, TEST_WORK_BUDGET))
      .toThrow(/arrays cannot contain extra properties/i);
  });

  it("snapshots data properties once and rejects accessors without invoking them", () => {
    let getterCalls = 0;
    const accessor = validProtocolInput() as Record<string, unknown>;
    Object.defineProperty(accessor, "owner", {
      enumerable: true,
      get() {
        getterCalls += 1;
        return "inference-platform";
      },
    });
    expect(() => parseExperimentProtocol(accessor, TEST_WORK_BUDGET))
      .toThrow(/accessor.*not allowed|data propert/i);
    expect(getterCalls).toBe(0);

    let propertyReads = 0;
    const descriptorReads = new Map<PropertyKey, number>();
    const proxy = new Proxy(validProtocolInput(), {
      get() {
        propertyReads += 1;
        throw new Error("caller object was read after snapshot");
      },
      getOwnPropertyDescriptor(target, property) {
        descriptorReads.set(property, (descriptorReads.get(property) ?? 0) + 1);
        return Reflect.getOwnPropertyDescriptor(target, property);
      },
    });
    expect(() => parseExperimentProtocol(proxy, TEST_WORK_BUDGET)).not.toThrow();
    expect(propertyReads).toBe(0);
    expect([...descriptorReads.values()].every((count) => count === 1)).toBe(true);
  });

  it.each<[string, () => object, RegExp]>([
    [
      "wide objects",
      () => Object.fromEntries(
        Array.from({ length: 65 }, (_, index) => [`field-${index}`, index]),
      ),
      /object.*key limit/i,
    ],
    [
      "oversized property names",
      () => ({ ["x".repeat(1_025)]: true }),
      /property key.*length limit/i,
    ],
    [
      "malformed property names",
      () => ({ ["malformed-\ud800"]: true }),
      /property key.*Unicode/i,
    ],
    [
      "symbol properties",
      () => ({ [Symbol("hidden")]: true }),
      /symbol propert/i,
    ],
  ])("rejects %s before requesting any property descriptors", (
    _label,
    makeValue,
    expectedMessage,
  ) => {
    let descriptorReads = 0;
    const proxy = new Proxy(makeValue(), {
      getOwnPropertyDescriptor(target, property) {
        descriptorReads += 1;
        return Reflect.getOwnPropertyDescriptor(target, property);
      },
    });

    expect(() => parseExperimentProtocol(proxy, TEST_WORK_BUDGET))
      .toThrow(expectedMessage);
    expect(descriptorReads).toBe(0);
  });

  it("keeps provider metrics operational and rejects obvious credential markers in trace identity text", () => {
    for (const reservedName of [
      "evaluator-score",
      "judge.reward",
      "quality",
      "reward",
      "task-score",
      "task_score",
    ]) {
      expect(() => parseTraceEnvelope(
        mutate(validTraceInput(), (trace) => {
          trace.attempts[0].providerReported.metrics[0].name = reservedName;
        }),
        TEST_WORK_BUDGET,
      )).toThrow(/reserved.*metric|metric.*reserved/i);
    }

    for (const credentialText of [
      "Bearer abc.def.ghi",
      "api_key=topsecret",
      "authorization: Basic abc123",
      "password=hunter2",
      "sk-1234567890abcdef",
    ]) {
      expect(() => parseTraceEnvelope(
        mutate(validTraceInput(), (trace) => {
          trace.attempts[0].requestedModel.id = credentialText;
        }),
        TEST_WORK_BUDGET,
      )).toThrow(/credential|secret/i);
    }

    expect(() => parseTraceEnvelope(
      mutate(validTraceInput(), (trace) => {
        trace.routeSignal.version = "authorization: Basic abc123";
      }),
      TEST_WORK_BUDGET,
    )).toThrow(/credential|secret/i);
  });
});
