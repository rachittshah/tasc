import { generateKeyPairSync } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  collectorAttestationSigningBytes,
  fingerprintExecutionProfile,
  fingerprintProtocol,
  parseEvaluatorEvidence,
  parseEvaluatorEvidenceJson,
  parseExperimentProtocol,
  parseExperimentProtocolJson,
  parseTraceEnvelope,
  parseTraceEnvelopeJson,
  verifyTraceDispatchAuthorization,
  verifyTraceDispatchIntent,
} from "../src/evidence.js";
import type { BoundedJsonLimits } from "../src/bounded-input.js";
import {
  TEST_WORK_BUDGET,
  digest,
  evaluatorKeyFixture,
  mutate,
  signCollectorAttestation,
  signDispatchIntent,
  validCollectionBinding,
  validEvaluatorEvidenceInput,
  validExecutionProfile,
  validProtocolInput,
  validTraceInput,
} from "./fixtures/evidence.js";

const encoder = new TextEncoder();
const RAW_JSON_LIMITS: BoundedJsonLimits = Object.freeze({
  maxBytes: 1_048_576,
  maxDepth: 32,
  maxObjectKeys: 8_192,
  maxArrayItems: 1_024,
  maxTokens: 131_072,
  maxDecodedStringLength: 16_384,
  maxNumericTokenLength: 128,
  maxDiagnosticSnippetLength: 0,
});

describe("evidence v2 contracts", () => {
  it("admits raw bytes through bounded JSON before semantic parsing", () => {
    const key = evaluatorKeyFixture();
    const protocolInput = validProtocolInput();
    const traceInput = validTraceInput();
    const evidenceInput = validEvaluatorEvidenceInput(key.privateKey);

    expect(parseExperimentProtocolJson(
      encoder.encode(JSON.stringify(protocolInput)),
      RAW_JSON_LIMITS,
      TEST_WORK_BUDGET,
    )).toEqual(parseExperimentProtocol(protocolInput, TEST_WORK_BUDGET));
    expect(parseTraceEnvelopeJson(
      encoder.encode(JSON.stringify(traceInput)),
      RAW_JSON_LIMITS,
      TEST_WORK_BUDGET,
    )).toEqual(parseTraceEnvelope(traceInput, TEST_WORK_BUDGET));
    expect(parseEvaluatorEvidenceJson(
      encoder.encode(JSON.stringify(evidenceInput)),
      RAW_JSON_LIMITS,
      TEST_WORK_BUDGET,
    )).toEqual(parseEvaluatorEvidence(
      evidenceInput,
      TEST_WORK_BUDGET,
    ));
  });

  it("rejects duplicate raw keys and byte overages before semantic parsing", () => {
    const protocolSource = JSON.stringify(validProtocolInput());
    const duplicatedVersion = protocolSource.replace(
      '"version":"tasc-experiment-protocol-v2"',
      '"version":"tasc-experiment-protocol-v2",'
        + '"version":"tasc-experiment-protocol-v2"',
    );
    expect(() => parseExperimentProtocolJson(
      encoder.encode(duplicatedVersion),
      RAW_JSON_LIMITS,
      TEST_WORK_BUDGET,
    )).toThrow(/duplicate key/i);

    const traceBytes = encoder.encode(JSON.stringify(validTraceInput()));
    expect(() => parseTraceEnvelopeJson(
      traceBytes,
      {
        ...RAW_JSON_LIMITS,
        maxBytes: traceBytes.byteLength - 1,
      },
      TEST_WORK_BUDGET,
    )).toThrow(/byte limit/i);
  });

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

  it("requires an explicit disabled or measured-window service-capacity gate", () => {
    const disabled = validProtocolInput() as any;
    disabled.gates.serviceCapacity = { kind: "disabled" };
    expect(parseExperimentProtocol(disabled, TEST_WORK_BUDGET).gates.serviceCapacity)
      .toEqual({ kind: "disabled" });

    const required = validProtocolInput() as any;
    required.gates.serviceCapacity = {
      kind: "minimum-measured-window-throughput",
      metric: "aggregate-output-tokens-per-second",
      minimum: 125,
    };
    expect(parseExperimentProtocol(required, TEST_WORK_BUDGET).gates.serviceCapacity)
      .toEqual(required.gates.serviceCapacity);

    const missing = validProtocolInput() as any;
    delete missing.gates.serviceCapacity;
    expect(() => parseExperimentProtocol(missing, TEST_WORK_BUDGET))
      .toThrow(/service.capacity|required/i);

    for (const invalid of [
      {
        kind: "minimum-measured-window-throughput",
        metric: "per-request-decode-tokens-per-second",
        minimum: 125,
      },
      {
        kind: "minimum-measured-window-throughput",
        metric: "aggregate-output-tokens-per-second",
        minimum: -1,
      },
      { kind: "disabled", minimum: 0 },
    ]) {
      const protocol = validProtocolInput() as any;
      protocol.gates.serviceCapacity = invalid;
      expect(() => parseExperimentProtocol(protocol, TEST_WORK_BUDGET)).toThrow();
    }
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
    ["legacy 0-100 score", 50, 0, 100],
    ["score below zero", -0.001, 0, 1],
    ["score above one", 1.001, 0, 1],
    ["signed range", 0.5, -1, 1],
    ["wide range", 0.5, 0, 100],
    ["narrow range", 0.5, 0.2, 0.8],
  ])(
    "rejects a primary evaluator %s",
    (_label, score, minimum, maximum) => {
      const key = evaluatorKeyFixture();
      const evidence = mutate(
        validEvaluatorEvidenceInput(key.privateKey),
        (value: any) => {
          value.outcome.score = score;
          value.outcome.range = { minimum, maximum };
        },
      );

      expect(() => parseEvaluatorEvidence(evidence, TEST_WORK_BUDGET))
        .toThrow(/evaluator.*(?:canonical.*0.*1|within.*range)/i);
    },
  );

  it.each([0, 1])(
    "accepts primary evaluator endpoint score %s with the exact 0-1 range",
    (score) => {
      const key = evaluatorKeyFixture();
      const evidence = mutate(
        validEvaluatorEvidenceInput(key.privateKey),
        (value: any) => {
          value.outcome.score = score;
          value.outcome.range = { minimum: 0, maximum: 1 };
        },
      );

      expect(parseEvaluatorEvidence(evidence, TEST_WORK_BUDGET).outcome)
        .toMatchObject({
          kind: "scored",
          score,
          range: { minimum: 0, maximum: 1 },
        });
    },
  );

  it("keeps optional subscores in their signed declared ranges", () => {
    const key = evaluatorKeyFixture();
    const evidence = mutate(
      validEvaluatorEvidenceInput(key.privateKey),
      (value: any) => {
        value.outcome.subscores = [{
          id: "signed-diagnostic",
          score: -2,
          range: { minimum: -5, maximum: -1 },
        }];
      },
    );

    expect(parseEvaluatorEvidence(evidence, TEST_WORK_BUDGET).outcome)
      .toMatchObject({
        kind: "scored",
        subscores: [{
          id: "signed-diagnostic",
          score: -2,
          range: { minimum: -5, maximum: -1 },
        }],
      });
  });

  it.each(["missing", "invalid", "abstained"] as const)(
    "rejects score and range injection into a %s outcome",
    (kind) => {
      const key = evaluatorKeyFixture();
      const injected = mutate(
        validEvaluatorEvidenceInput(key.privateKey),
        (value: any) => {
          value.outcome = {
            kind,
            reasonCode: "not-scored",
            score: 0.5,
            range: { minimum: 0, maximum: 1 },
          };
        },
      );

      expect(() => parseEvaluatorEvidence(injected, TEST_WORK_BUDGET)).toThrow();
    },
  );

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

  it("requires route observation before dispatch-intent issuance", () => {
    expect(() => parseTraceEnvelope(
      mutate(validTraceInput(), (trace) => {
        trace.dispatchIntent.issuedAt = "2026-07-20T23:59:59.999Z";
      }),
      TEST_WORK_BUDGET,
    )).toThrow(/route signal.*before.*dispatch/i);
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
      trace.collectionBinding = validCollectionBinding();
    });
    expect(() => parseTraceEnvelope(online, TEST_WORK_BUDGET)).not.toThrow();
    expect(() => parseTraceEnvelope(
      mutate(online, (trace) => { trace.collectionWindowMembershipDigest = null; }),
      TEST_WORK_BUDGET,
    )).toThrow(/window.*membership digest/i);
  });

  it("records provider-resolved model IDs without fabricating a revision", () => {
    const idOnly = validTraceInput() as any;
    idOnly.attempts[0].resolvedModel = {
      id: idOnly.attempts[0].requestedModel.id,
      revision: null,
      source: "provider-id-only",
    };

    expect(
      parseTraceEnvelope(idOnly, TEST_WORK_BUDGET)
        .attempts[0].resolvedModel,
    ).toEqual({
      id: "champion-model",
      revision: null,
      source: "provider-id-only",
    });

    const invalidResolvedModels = [
      {
        id: "champion-model",
        revision: null,
        source: "provider-reported",
      },
      {
        id: "champion-model",
        revision: "refs-pr-42",
        source: "provider-id-only",
      },
      {
        id: "champion-model",
        revision: null,
        source: "operator-asserted",
      },
      {
        id: "champion-model",
        revision: null,
        source: "provider-id-only",
        verification: "forged",
      },
    ];
    for (const resolvedModel of invalidResolvedModels) {
      expect(() => parseTraceEnvelope(
        mutate(validTraceInput(), (trace: any) => {
          trace.attempts[0].resolvedModel = resolvedModel;
        }),
        TEST_WORK_BUDGET,
      )).toThrow();
    }
  });

  it("verifies a dispatch intent against the exact protocol authority and validity interval", () => {
    const protocol = validProtocolInput();
    const trace = validTraceInput();
    const verified = verifyTraceDispatchIntent(trace, protocol);

    expect(verified).toEqual(
      parseTraceEnvelope(trace, TEST_WORK_BUDGET),
    );
    expect(verified).not.toBe(trace);
    expect(Object.isFrozen(verified)).toBe(true);

    const wrongAuthority = mutate(trace, (value) => {
      value.dispatchIntent.authorityKeyId = "other-dispatch-authority";
    });
    signDispatchIntent(wrongAuthority);
    expect(() => verifyTraceDispatchIntent(wrongAuthority, protocol))
      .toThrow(/dispatch intent.*authority|authority.*dispatch intent/i);

    const wrongProtocol = mutate(trace, (value) => {
      value.protocolDigest = digest("f");
    });
    signDispatchIntent(wrongProtocol);
    expect(() => verifyTraceDispatchIntent(wrongProtocol, protocol))
      .toThrow(/dispatch intent.*protocol|protocol.*dispatch intent/i);

    const atExpiry = mutate(trace, (value) => {
      value.routeSignal!.provenance.observedAt = protocol.expiresAt;
      for (const field of [
        "startedAt",
        "headersAt",
        "firstByteAt",
        "firstMeaningfulTokenAt",
        "completedAt",
      ] as const) {
        value.attempts[0].observerTimings[field] = protocol.expiresAt;
      }
    });
    signDispatchIntent(atExpiry);
    expect(() => verifyTraceDispatchIntent(atExpiry, protocol))
      .toThrow(/validity interval/i);

    const invalidSignature = mutate(trace, (value) => {
      const signature = value.dispatchIntent.signature;
      value.dispatchIntent.signature =
        `${signature.slice(0, -1)}${signature.endsWith("A") ? "B" : "A"}`;
    });
    expect(() => verifyTraceDispatchIntent(invalidSignature, protocol))
      .toThrow(/invalid dispatch-intent signature/i);
  });

  it("verifies strict dispatch authorization before any outcome exists", () => {
    const protocol = validProtocolInput();
    const {
      attempts: _attempts,
      terminalOutputId: _terminalOutputId,
      collectorVersion: _collectorVersion,
      collectorAttestation: _collectorAttestation,
      ...authorization
    } = validTraceInput();

    const verified = verifyTraceDispatchAuthorization(
      authorization,
      protocol,
    );
    expect(verified).toEqual(authorization);
    expect(verified).not.toBe(authorization);
    expect(Object.isFrozen(verified)).toBe(true);

    const changedOutcomeFreeField = mutate(authorization, (value) => {
      value.policyDigest = digest("f");
    });
    expect(() => verifyTraceDispatchAuthorization(
      changedOutcomeFreeField,
      protocol,
    )).toThrow(/invalid dispatch-intent signature/i);

    expect(() => verifyTraceDispatchAuthorization(
      { ...authorization, attempts: [] },
      protocol,
    )).toThrow(/dispatch authorization is invalid/i);
  });

  it("authenticates every final collector observation independently of dispatch", () => {
    const protocol = validProtocolInput();
    const trace = validTraceInput();
    const originalDispatchSignature = trace.dispatchIntent.signature;
    const signingBytes = collectorAttestationSigningBytes(trace);
    expect(collectorAttestationSigningBytes(
      mutate(trace, (value) => {
        value.collectorAttestation.signature =
          value.collectorAttestation.signature.endsWith("A")
            ? `${value.collectorAttestation.signature.slice(0, -1)}B`
            : `${value.collectorAttestation.signature.slice(0, -1)}A`;
      }),
    )).toEqual(signingBytes);
    expect(collectorAttestationSigningBytes(
      mutate(trace, (value) => {
        value.dispatchIntent.signature =
          value.dispatchIntent.signature.endsWith("A")
            ? `${value.dispatchIntent.signature.slice(0, -1)}B`
            : `${value.dispatchIntent.signature.slice(0, -1)}A`;
      }),
    )).not.toEqual(signingBytes);
    const finalObservationMutations: Array<{
      readonly label: string;
      readonly change: (value: ReturnType<typeof validTraceInput>) => void;
    }> = [
      {
        label: "observer timing",
        change: (value) => {
          value.attempts[0].observerTimings.headersAt =
            "2026-07-21T00:00:00.051Z";
        },
      },
      {
        label: "usage",
        change: (value) => {
          value.attempts[0].tokenUsage.input.value += 1;
        },
      },
      {
        label: "cost",
        change: (value) => {
          value.attempts[0].cost.amount += 0.001;
        },
      },
      {
        label: "status",
        change: (value) => {
          const attempt = value.attempts[0] as unknown as {
            status: "success" | "failure";
            finishReason: string | null;
            failureCategory: string | null;
          };
          attempt.status = "failure";
          attempt.finishReason = null;
          attempt.failureCategory = "provider-error";
          value.terminalOutputId = null as unknown as typeof value.terminalOutputId;
        },
      },
      {
        label: "terminal output identity",
        change: (value) => {
          value.terminalOutputId.value = "2".repeat(64);
        },
      },
      {
        label: "collector version",
        change: (value) => {
          value.collectorVersion = "collector-2.0.1";
        },
      },
    ];

    for (const testCase of finalObservationMutations) {
      const changed = mutate(trace, testCase.change);
      expect(
        changed.dispatchIntent.signature,
        `${testCase.label} must leave pre-dispatch authorization unchanged`,
      ).toBe(originalDispatchSignature);
      expect(
        () => verifyTraceDispatchIntent(changed, protocol),
        testCase.label,
      ).toThrow(/invalid collector-attestation signature/i);
    }

    const alternateCollector = generateKeyPairSync("ed25519");
    const wrongKey = mutate(trace, () => undefined);
    signCollectorAttestation(wrongKey, alternateCollector.privateKey);
    expect(() => verifyTraceDispatchIntent(wrongKey, protocol))
      .toThrow(/invalid collector-attestation signature/i);

    const wrongAuthority = mutate(trace, (value) => {
      value.collectorAttestation.authorityKeyId = "other-collector-authority";
    });
    signCollectorAttestation(wrongAuthority);
    expect(() => verifyTraceDispatchIntent(wrongAuthority, protocol))
      .toThrow(/collector attestation.*authority|authority.*collector attestation/i);

    for (const collectedAt of [
      "2026-07-21T00:00:00.499Z",
      protocol.expiresAt,
    ]) {
      const wrongTime = mutate(trace, (value) => {
        value.collectorAttestation.collectedAt = collectedAt;
      });
      signCollectorAttestation(
        wrongTime,
        undefined,
        { preserveCollectedAt: true },
      );
      expect(() => verifyTraceDispatchIntent(wrongTime, protocol))
        .toThrow(/final-observation interval/i);
    }
  });

  it("binds raw-free shadow collection provenance into dispatch authorization", () => {
    const protocol = validProtocolInput();
    const trace = mutate(validTraceInput(), (value: any) => {
      value.split = "online";
      value.collectionWindowId = "shadow-window-1";
      value.collectionWindowMembershipDigest = digest("a");
      value.sourceMode = "shadow";
      value.collectionBinding = validCollectionBinding();
    });
    signDispatchIntent(trace);
    expect(() => verifyTraceDispatchIntent(trace, protocol)).not.toThrow();

    const changedRoute = mutate(trace, (value: any) => {
      value.collectionBinding!.route = "responses";
    });
    expect(changedRoute.dispatchIntent.signature)
      .toBe(trace.dispatchIntent.signature);
    expect(() => verifyTraceDispatchIntent(changedRoute, protocol))
      .toThrow(/invalid dispatch-intent signature/i);

    const missingBinding = mutate(trace, (value: any) => {
      value.collectionBinding = null;
    });
    signDispatchIntent(missingBinding);
    expect(() => parseTraceEnvelope(missingBinding, TEST_WORK_BUDGET))
      .toThrow(/shadow traces require.*collection binding/i);
    expect(() => verifyTraceDispatchIntent(missingBinding, protocol))
      .toThrow(/dispatch-intent trace is invalid/i);

    const nonShadowBinding = mutate(trace, (value: any) => {
      value.sourceMode = "observed";
    });
    signDispatchIntent(nonShadowBinding);
    expect(() => parseTraceEnvelope(nonShadowBinding, TEST_WORK_BUDGET))
      .toThrow(/non-shadow traces cannot claim.*collection binding/i);
    expect(() => verifyTraceDispatchIntent(nonShadowBinding, protocol))
      .toThrow(/dispatch-intent trace is invalid/i);

    const duplicateReceipts = mutate(trace, (value: any) => {
      value.collectionBinding!.capabilityReceiptDigests = [
        digest("5"),
        digest("5"),
      ];
    });
    expect(() => parseTraceEnvelope(duplicateReceipts, TEST_WORK_BUDGET))
      .toThrow(/duplicate capability receipt digest/i);

    const unsortedReceipts = mutate(trace, (value: any) => {
      value.collectionBinding!.capabilityReceiptDigests = [
        digest("6"),
        digest("5"),
      ];
    });
    expect(() => parseTraceEnvelope(unsortedReceipts, TEST_WORK_BUDGET))
      .toThrow(/sorted canonically/i);
  });

  it("enforces canonical required trace capabilities after dispatch authentication", () => {
    const protocol = validProtocolInput();
    const mutations: Array<{
      readonly mutateTrace: (trace: ReturnType<typeof validTraceInput>) => void;
      readonly expected: RegExp;
    }> = [
      {
        mutateTrace: (trace) => {
          trace.workload.mode = "completion";
        },
        expected: /required chat-completions capability/i,
      },
      {
        mutateTrace: (trace) => {
          const payloads = trace.attempts[0].payloads as unknown as {
            eventStream: unknown | null;
          };
          payloads.eventStream = null;
        },
        expected: /required streaming capability/i,
      },
      {
        mutateTrace: (trace) => {
          const usage = trace.attempts[0].tokenUsage as unknown as {
            total: unknown | null;
          };
          usage.total = null;
        },
        expected: /required final-usage capability/i,
      },
    ];

    for (const testCase of mutations) {
      const trace = mutate(validTraceInput(), testCase.mutateTrace);
      signDispatchIntent(trace);
      expect(() => verifyTraceDispatchIntent(trace, protocol))
        .toThrow(testCase.expected);
    }

    const wrongShadowRoute = mutate(validTraceInput(), (trace: any) => {
      trace.split = "online";
      trace.collectionWindowId = "shadow-window-1";
      trace.collectionWindowMembershipDigest = digest("a");
      trace.sourceMode = "shadow";
      trace.collectionBinding = {
        ...validCollectionBinding(),
        route: "completions",
      };
    });
    signDispatchIntent(wrongShadowRoute);
    expect(() => verifyTraceDispatchIntent(wrongShadowRoute, protocol))
      .toThrow(/required chat-completions capability/i);

    const unknownRequirement = validProtocolInput() as unknown as {
      requiredCapabilities: string[];
    };
    unknownRequirement.requiredCapabilities = ["judge-model"];
    expect(() => verifyTraceDispatchIntent(
      validTraceInput(),
      unknownRequirement,
    )).toThrow(/protocol is invalid/i);
  });

  it("rejects accessor and proxy dispatch inputs without reflecting or reading them", () => {
    const protocol = validProtocolInput();
    const planted = "planted-dispatch-secret";
    let accessorReads = 0;
    const accessorTrace = validTraceInput() as any;
    Object.defineProperty(accessorTrace, "dispatchIntent", {
      enumerable: true,
      configurable: true,
      get() {
        accessorReads += 1;
        throw new Error(planted);
      },
    });

    let accessorError = "";
    try {
      verifyTraceDispatchIntent(accessorTrace, protocol);
    } catch (error) {
      accessorError = String((error as Error).message);
    }
    expect(accessorReads).toBe(0);
    expect(accessorError).toMatch(/dispatch-intent trace is invalid/i);
    expect(accessorError).not.toContain(planted);

    let proxyReads = 0;
    const proxyProtocol = new Proxy(protocol, {
      get() {
        proxyReads += 1;
        throw new Error(planted);
      },
    });
    let proxyError = "";
    try {
      verifyTraceDispatchIntent(validTraceInput(), proxyProtocol);
    } catch (error) {
      proxyError = String((error as Error).message);
    }
    expect(proxyReads).toBe(0);
    expect(proxyError).toMatch(/dispatch-intent protocol is invalid/i);
    expect(proxyError).not.toContain(planted);

    const plantedTrace = validTraceInput();
    plantedTrace.traceId = planted;
    let signatureError = "";
    try {
      verifyTraceDispatchIntent(plantedTrace, protocol);
    } catch (error) {
      signatureError = String((error as Error).message);
    }
    expect(signatureError).toMatch(/invalid dispatch-intent signature/i);
    expect(signatureError).not.toContain(planted);
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

    const traversalLike = mutate(validTraceInput(), (trace: any) => {
      trace.attempts[0].payloads.response = {
        kind: "controlled-reference",
        storeId: "approved-payload-store",
        referenceId: "case..private-output",
      };
    });
    expect(() => parseTraceEnvelope(traversalLike, TEST_WORK_BUDGET))
      .toThrow(/controlled payload reference/i);

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
      dispatchAuthority: protocol.dispatchAuthority,
      collectorAuthority: protocol.collectorAuthority,
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
        protocol.dispatchAuthority.publicKeySpki = "bm90LWEtc3BraQ";
      }),
      TEST_WORK_BUDGET,
    )).toThrow(/dispatch authority.*Ed25519 SPKI/i);
    expect(() => parseExperimentProtocol(
      mutate(validProtocolInput(), (protocol) => {
        protocol.collectorAuthority.publicKeySpki = "bm90LWEtc3BraQ";
      }),
      TEST_WORK_BUDGET,
    )).toThrow(/collector authority.*Ed25519 SPKI/i);
    expect(() => parseExperimentProtocol(
      mutate(validProtocolInput(), (protocol) => {
        protocol.collectorAuthority.keyId =
          protocol.dispatchAuthority.keyId;
      }),
      TEST_WORK_BUDGET,
    )).toThrow(/collector authority.*distinct.*dispatch authority/i);
    expect(() => parseExperimentProtocol(
      mutate(validProtocolInput(), (protocol) => {
        protocol.collectorAuthority.publicKeySpki =
          protocol.dispatchAuthority.publicKeySpki;
      }),
      TEST_WORK_BUDGET,
    )).toThrow(/collector authority.*distinct.*dispatch authority/i);
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
        protocol.candidatePolicySpace.predicates[0].routeToProfileId = "candidate";
      }),
      TEST_WORK_BUDGET,
    )).toThrow(/predicate.*champion|champion.*predicate/i);
    expect(() => parseExperimentProtocol(
      mutate(validProtocolInput(), (protocol) => {
        protocol.candidatePolicySpace.maxCandidates = 1;
      }),
      TEST_WORK_BUDGET,
    )).toThrow(/candidate count.*maxCandidates|maxCandidates.*candidate count/i);
    expect(() => parseExperimentProtocol(
      mutate(validProtocolInput(), (protocol) => {
        const predicate = protocol.candidatePolicySpace.predicates[0];
        protocol.candidatePolicySpace.predicates.push({
          routeToProfileId: predicate.routeToProfileId,
          threshold: predicate.threshold,
          operator: predicate.operator,
          signalDefinitionId: predicate.signalDefinitionId,
        });
      }),
      TEST_WORK_BUDGET,
    )).toThrow(/duplicate.*predicate/i);
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
