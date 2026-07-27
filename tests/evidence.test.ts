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
});
