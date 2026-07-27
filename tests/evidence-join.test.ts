import { describe, expect, it } from "vitest";
import {
  joinAssessmentEvidence,
  resolveGroupSplit,
} from "../src/evidence-join.js";
import {
  fingerprintProtocol,
  parseEvaluatorEvidence,
  parseExperimentProtocol,
  parseTraceEnvelope,
} from "../src/evidence.js";
import {
  parseEvaluatorTrustSnapshot,
  verifyEvaluatorEvidence,
  type EvaluatorEvidenceVerification,
} from "../src/evaluator-trust.js";
import { parseAssessmentContext } from "../src/assessment-context.js";
import {
  TEST_WORK_BUDGET,
  digest,
  evaluatorKeyFixture,
  keyedIdentity,
  mutate,
  signEvaluatorEvidence,
  unsignedEvaluatorEvidence,
  validAssessmentContextInput,
  validProtocolInput,
  validTraceInputForProfile,
  type EvaluatorKeyFixture,
} from "./fixtures/evidence.js";

type TraceInput = ReturnType<typeof validTraceInputForProfile>;
type ProtocolInput = ReturnType<typeof validProtocolInput>;

function parseProtocol(input: ProtocolInput = validProtocolInput()) {
  return parseExperimentProtocol(input, TEST_WORK_BUDGET);
}

function parseTrace(input: TraceInput) {
  return parseTraceEnvelope(input, TEST_WORK_BUDGET);
}

function verificationFor(
  trace: TraceInput,
  key: EvaluatorKeyFixture,
  change?: (evidence: ReturnType<typeof unsignedEvaluatorEvidence>) => void,
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
  change?.(unsigned);

  const snapshot = parseEvaluatorTrustSnapshot(key.trustSnapshot);
  const context = parseAssessmentContext(validAssessmentContextInput(snapshot));
  const evidence = parseEvaluatorEvidence(
    signEvaluatorEvidence(key.privateKey, unsigned),
    TEST_WORK_BUDGET,
  );
  return verifyEvaluatorEvidence(evidence, snapshot, context);
}

function withProtocolDigest(
  protocolInput: ProtocolInput,
  traces: TraceInput[],
): TraceInput[] {
  const protocol = parseProtocol(protocolInput);
  const protocolDigest = fingerprintProtocol(protocol);
  return traces.map((trace) => mutate(trace, (copy) => {
    copy.studyId = protocol.studyId;
    copy.protocolDigest = protocolDigest;
  }));
}

function failedTerminal(trace: TraceInput): TraceInput {
  return mutate(trace, (copy) => {
    const terminal = copy.attempts[copy.attempts.length - 1];
    terminal.status = "failure" as "success";
    terminal.finishReason = null as unknown as string;
    terminal.failureCategory = "runtime-error" as unknown as null;
    copy.terminalOutputId = null as never;
  });
}

function withFailedFirstAttempt(trace: TraceInput): TraceInput {
  return mutate(trace, (copy) => {
    const terminal = structuredClone(copy.attempts[0]);
    terminal.attemptId = "attempt-2";
    terminal.attemptNumber = 2;
    copy.attempts[0].status = "failure" as "success";
    copy.attempts[0].finishReason = null as unknown as string;
    copy.attempts[0].failureCategory = "transport-timeout" as unknown as null;
    copy.attempts[0].observerTimings.startedAt = "2026-07-20T23:59:58.000Z";
    copy.attempts[0].observerTimings.headersAt = null as never;
    copy.attempts[0].observerTimings.firstByteAt = null as never;
    copy.attempts[0].observerTimings.firstMeaningfulTokenAt = null as never;
    copy.attempts[0].observerTimings.completedAt = "2026-07-20T23:59:59.000Z";
    copy.routeSignal!.provenance.observedAt = "2026-07-20T23:59:58.000Z";
    copy.attempts.push(terminal);
  });
}

function secondReplicatePair(
  change?: (trace: TraceInput) => void,
): [TraceInput, TraceInput] {
  const champion = mutate(validTraceInputForProfile("champion"), (trace) => {
    trace.traceId = "trace-case-1-r1-champion";
    trace.replicateId = "replicate-1";
    trace.terminalOutputId = keyedIdentity("3");
  });
  const candidate = mutate(validTraceInputForProfile("candidate"), (trace) => {
    trace.traceId = "trace-case-1-r1-candidate";
    trace.replicateId = "replicate-1";
    trace.terminalOutputId = keyedIdentity("4");
  });
  change?.(champion);
  change?.(candidate);
  return [champion, candidate];
}

function manyPairedTraces(
  protocol: ReturnType<typeof parseProtocol>,
  caseCount: number,
  slicesForCase: (index: number) => string[],
): TraceInput[] {
  const traces: TraceInput[] = [];
  for (let index = 0; index < caseCount; index += 1) {
    const caseId = `case-${index}`;
    const groupId = `group-${index}`;
    const split = resolveGroupSplit(protocol, groupId).split;
    for (const profileId of ["champion", "candidate"] as const) {
      const trace = validTraceInputForProfile(profileId);
      trace.traceId = `trace-${caseId}-${profileId}`;
      trace.caseId = caseId;
      trace.groupId = groupId;
      trace.split = split as "dev";
      trace.slices = slicesForCase(index);
      trace.terminalOutputId = {
        ...keyedIdentity(),
        value: (index * 2 + (profileId === "candidate" ? 1 : 0))
          .toString(16)
          .padStart(64, "0"),
      };
      traces.push(trace);
    }
  }
  return traces;
}

describe("deterministic assessment evidence join", () => {
  it("publishes exact group-bucket vectors from a domain-separated JCS SHA-256 preimage", () => {
    const protocol = parseProtocol();

    expect(resolveGroupSplit(protocol, "conversation-1")).toEqual({
      algorithm: "tasc-seeded-sha256-group-bucket-v1",
      bucket: 0,
      split: "dev",
    });
    expect(resolveGroupSplit(protocol, "conversation-2")).toEqual({
      algorithm: "tasc-seeded-sha256-group-bucket-v1",
      bucket: 7,
      split: "dev",
    });
    expect(resolveGroupSplit(protocol, "holdout-group")).toEqual({
      algorithm: "tasc-seeded-sha256-group-bucket-v1",
      bucket: 8,
      split: "holdout",
    });

    const binaryProtocol = parseProtocol(mutate(validProtocolInput(), (input) => {
      input.splitMembership.bucketCount = 2;
      input.splitMembership.developmentBuckets = [0];
      input.splitMembership.holdoutBuckets = [1];
    }));
    expect(resolveGroupSplit(binaryProtocol, "conversation-2").bucket).toBe(1);

    const byteProtocol = parseProtocol(mutate(validProtocolInput(), (input) => {
      input.splitMembership.bucketCount = 256;
      input.splitMembership.developmentBuckets = [154];
      input.splitMembership.holdoutBuckets = Array.from(
        { length: 255 },
        (_, bucket) => bucket < 154 ? bucket : bucket + 1,
      );
    }));
    expect(resolveGroupSplit(byteProtocol, "conversation-1")).toMatchObject({
      bucket: 154,
      split: "dev",
    });

    // SHA-256 is cc800a…c0dc8d. Exact modulo is 7; converting the
    // 256-bit digest through Number first rounds it and incorrectly yields 8.
    expect(resolveGroupSplit(protocol, "conversation-2").bucket).toBe(7);
    expect(Number(BigInt(
      "0xcc800acd15546082879ebf7ba666b88d6910420ff75fd16599a8adebe9c0dc8d",
    )) % 10).toBe(8);

    expect(() => resolveGroupSplit(
      mutate(protocol, (input: any) => {
        input.splitMembership.bucketCount = 0;
      }) as never,
      "conversation-1",
    )).toThrow(/bucketCount|bucket count/i);

    expect(() => resolveGroupSplit(
      mutate(protocol, (input: any) => {
        input.routeSignal.maximum = input.routeSignal.minimum;
      }) as never,
      "conversation-1",
    )).toThrow(/route.signal maximum|maximum.*minimum/i);

    let propertyReads = 0;
    const descriptorReads = new Map<PropertyKey, number>();
    const protocolProxy = new Proxy(protocol, {
      get() {
        propertyReads += 1;
        throw new Error("public split resolver re-read caller protocol");
      },
      getOwnPropertyDescriptor(target, property) {
        descriptorReads.set(property, (descriptorReads.get(property) ?? 0) + 1);
        return Reflect.getOwnPropertyDescriptor(target, property);
      },
    });
    expect(resolveGroupSplit(protocolProxy, "conversation-1").bucket).toBe(0);
    expect(propertyReads).toBe(0);
    expect([...descriptorReads.values()].every((count) => count === 1)).toBe(true);
  });

  it("joins trusted scores, pairs required profiles, and is invariant to input order", () => {
    const key = evaluatorKeyFixture();
    const protocol = parseProtocol();
    const rawTraces = [
      validTraceInputForProfile("champion"),
      validTraceInputForProfile("candidate"),
    ];
    const traces = rawTraces.map(parseTrace);
    const evidence = rawTraces.map((trace) => verificationFor(trace, key));

    const joined = joinAssessmentEvidence(
      protocol,
      traces,
      evidence,
      TEST_WORK_BUDGET,
    );
    const reversed = joinAssessmentEvidence(
      protocol,
      [...traces].reverse(),
      [...evidence].reverse(),
      TEST_WORK_BUDGET,
    );

    expect(reversed).toEqual(joined);
    expect(joined).toMatchObject({
      version: "tasc-assessment-dataset-v2",
      studyId: protocol.studyId,
      protocolDigest: expect.stringMatching(/^sha256:[a-f0-9]{64}$/),
      requiredProfileIds: ["candidate", "champion"],
      counts: {
        traceRows: 2,
        evidenceRows: 2,
        matchedRows: 2,
        scoredRows: 2,
        pairedCaseReplicates: 1,
        cases: 1,
        caseReplicates: 1,
        groups: 1,
        observedTrafficMass: 1,
      },
    });
    expect(joined.executions.map(({ profileId, outcome }) => [
      profileId,
      outcome.kind,
    ])).toEqual([
      ["candidate", "scored"],
      ["champion", "scored"],
    ]);
    expect(joined.pairs).toHaveLength(1);
    expect(joined.pairs[0]).toMatchObject({
      caseId: "case-1",
      replicateId: "replicate-0",
      groupId: "conversation-1",
      split: "dev",
      declaredTrafficWeight: 1,
      profileIds: ["candidate", "champion"],
    });
    expect(joined.counts.slices).toEqual([
      { sliceId: "english", caseReplicates: 1, groups: 1 },
      { sliceId: "routine", caseReplicates: 1, groups: 1 },
    ]);
    expect(joined.diagnostics).toEqual({
      abstainedEvidence: [],
      conflictingEvidence: [],
      conflictingTraces: [],
      duplicateEvidence: [],
      duplicateTraces: [],
      invalidEvidence: [],
      missingEvidence: [],
      missingProfileExecutions: [],
      orphanEvidence: [],
    });
    expect(joined.admissibility).toEqual({
      valid: true,
      blockingReasons: [],
    });
    expect(Object.isFrozen(joined)).toBe(true);
    expect(Object.isFrozen(joined.executions)).toBe(true);
    expect(Object.isFrozen(joined.executions[0].trace)).toBe(true);
    expect(joined.executions[0].trace).not.toBe(traces[1]);
  });

  it.each([
    [
      "requested model id",
      (trace: TraceInput) => { trace.attempts[0].requestedModel.id = "attacker-model"; },
      /requested model.*profile|profile.*requested model/i,
    ],
    [
      "requested model revision",
      (trace: TraceInput) => { trace.attempts[0].requestedModel.revision = "attacker-revision"; },
      /requested model.*profile|profile.*requested model/i,
    ],
    [
      "resolved model id",
      (trace: TraceInput) => { trace.attempts[0].resolvedModel!.id = "attacker-model"; },
      /resolved model.*profile|profile.*resolved model/i,
    ],
    [
      "resolved model revision",
      (trace: TraceInput) => { trace.attempts[0].resolvedModel!.revision = "attacker-revision"; },
      /resolved model.*profile|profile.*resolved model/i,
    ],
  ] as const)(
    "rejects trusted successful execution with %s drift despite a retained profile digest",
    (_label, change, expected) => {
      const key = evaluatorKeyFixture();
      const champion = validTraceInputForProfile("champion");
      const candidate = validTraceInputForProfile("candidate");
      change(champion);
      const evidence = [
        verificationFor(champion, key),
        verificationFor(candidate, key),
      ];

      expect(() => joinAssessmentEvidence(
        parseProtocol(),
        [parseTrace(champion), parseTrace(candidate)],
        evidence,
        TEST_WORK_BUDGET,
      )).toThrow(expected);
    },
  );

  it.each([
    [
      "requested model",
      (trace: TraceInput) => {
        trace.attempts[0].requestedModel.revision = "attacker-revision";
      },
      /requested model.*profile|profile.*requested model/i,
    ],
    [
      "resolved model",
      (trace: TraceInput) => {
        trace.attempts[0].resolvedModel!.id = "attacker-model";
      },
      /resolved model.*profile|profile.*resolved model/i,
    ],
  ] as const)(
    "rejects trusted retry history with first-attempt %s drift",
    (_label, change, expected) => {
      const key = evaluatorKeyFixture();
      const champion = withFailedFirstAttempt(
        validTraceInputForProfile("champion"),
      );
      const candidate = validTraceInputForProfile("candidate");
      candidate.routeSignal!.provenance.observedAt
        = champion.routeSignal!.provenance.observedAt;
      change(champion);
      const evidence = [
        verificationFor(champion, key),
        verificationFor(candidate, key),
      ];

      expect(() => joinAssessmentEvidence(
        parseProtocol(),
        [parseTrace(champion), parseTrace(candidate)],
        evidence,
        TEST_WORK_BUDGET,
      )).toThrow(expected);
    },
  );

  it("rejects a post-dispatch route signal even with a complete trusted pair", () => {
    const key = evaluatorKeyFixture();
    const traces = [
      validTraceInputForProfile("champion"),
      validTraceInputForProfile("candidate"),
    ];
    for (const trace of traces) {
      trace.routeSignal!.provenance.observedAt
        = "2026-07-21T00:00:00.001Z";
    }
    const evidence = traces.map((trace) => verificationFor(trace, key));

    expect(() => joinAssessmentEvidence(
      parseProtocol(),
      traces.map(parseTrace),
      evidence,
      TEST_WORK_BUDGET,
    )).toThrow(/route.signal.*(?:first attempt|dispatch|started)/i);
  });

  it("accepts a route signal observed exactly when the first attempt starts", () => {
    const key = evaluatorKeyFixture();
    const traces = [
      validTraceInputForProfile("champion"),
      validTraceInputForProfile("candidate"),
    ];
    for (const trace of traces) {
      trace.routeSignal!.provenance.observedAt
        = trace.attempts[0].observerTimings.startedAt;
    }

    expect(joinAssessmentEvidence(
      parseProtocol(),
      traces.map(parseTrace),
      traces.map((trace) => verificationFor(trace, key)),
      TEST_WORK_BUDGET,
    ).admissibility.valid).toBe(true);
  });

  it("assigns zero only to a terminal failed execution and never fabricates evidence", () => {
    const key = evaluatorKeyFixture();
    const protocol = parseProtocol();
    const successfulChampion = validTraceInputForProfile("champion");
    const failedChampion = failedTerminal(successfulChampion);
    const candidate = validTraceInputForProfile("candidate");
    const evidenceForFailedOutput = verificationFor(successfulChampion, key);

    const joined = joinAssessmentEvidence(
      protocol,
      [parseTrace(failedChampion), parseTrace(candidate)],
      [evidenceForFailedOutput],
      TEST_WORK_BUDGET,
    );

    const failure = joined.executions.find(
      ({ profileId }) => profileId === "champion",
    );
    expect(failure?.outcome).toEqual({
      kind: "protocol-failure-zero",
      score: 0,
      evidence: null,
    });
    expect(joined.diagnostics.orphanEvidence).toEqual([
      expect.objectContaining({
        evidenceDigest: evidenceForFailedOutput.evidenceDigest,
        reason: "evidence-for-failed-execution",
      }),
    ]);
    expect(joined.diagnostics.missingEvidence).toEqual([
      expect.objectContaining({
        profileId: "candidate",
        reason: "successful-execution-without-trusted-evidence",
      }),
    ]);
  });

  it("requires evaluator evidence when an earlier retry fails but the terminal attempt succeeds", () => {
    const trace = validTraceInputForProfile("champion");
    const success = structuredClone(trace.attempts[0]);
    success.attemptId = "attempt-2";
    success.attemptNumber = 2;
    trace.attempts[0].status = "failure" as "success";
    trace.attempts[0].finishReason = null as unknown as string;
    trace.attempts[0].failureCategory = "transport-timeout" as unknown as null;
    trace.attempts[0].observerTimings.startedAt = "2026-07-20T23:59:58.000Z";
    trace.attempts[0].observerTimings.headersAt = null as never;
    trace.attempts[0].observerTimings.firstByteAt = null as never;
    trace.attempts[0].observerTimings.firstMeaningfulTokenAt = null as never;
    trace.attempts[0].observerTimings.completedAt = "2026-07-20T23:59:59.000Z";
    trace.routeSignal!.provenance.observedAt = trace.attempts[0].observerTimings.startedAt;
    trace.attempts.push(success);

    const joined = joinAssessmentEvidence(
      parseProtocol(),
      [parseTrace(trace)],
      [],
      TEST_WORK_BUDGET,
    );

    expect(joined.executions[0]).toMatchObject({
      terminalStatus: "success",
      outcome: {
        kind: "missing-evidence",
        reasonCode: "successful-execution-without-trusted-evidence",
      },
    });
  });

  it("requires trusted authentic receipts, protocol-pinned keys, and exact evaluator identity", () => {
    const key = evaluatorKeyFixture();
    const protocol = parseProtocol();
    const champion = validTraceInputForProfile("champion");
    const candidate = validTraceInputForProfile("candidate");
    const authentic = verificationFor(champion, key);
    const forged = structuredClone(authentic);
    const evaluatorDrift = verificationFor(candidate, key, (evidence) => {
      evidence.evaluator.rubricVersion = "rubric-5";
    });

    const joined = joinAssessmentEvidence(
      protocol,
      [parseTrace(champion), parseTrace(candidate)],
      [forged, evaluatorDrift],
      TEST_WORK_BUDGET,
    );

    expect(joined.diagnostics.invalidEvidence.map(({ reason }) => reason)).toEqual(
      expect.arrayContaining([
        "inauthentic-verification-receipt",
        "evaluator-or-rubric-or-calibration-or-producer-drift",
      ]),
    );
    expect(joined.diagnostics.invalidEvidence).toHaveLength(2);
    expect(joined.counts.matchedRows).toBe(0);

    const unpinnedProtocolInput = mutate(validProtocolInput(), (input) => {
      input.evaluator.requiredTrustedKeyIds = ["evaluator-key-2"];
    });
    const unpinnedProtocol = parseProtocol(unpinnedProtocolInput);
    const [unpinnedChampion, unpinnedCandidate] = withProtocolDigest(
      unpinnedProtocolInput,
      [champion, candidate],
    );
    const unpinned = joinAssessmentEvidence(
      unpinnedProtocol,
      [parseTrace(unpinnedChampion), parseTrace(unpinnedCandidate)],
      [verificationFor(unpinnedChampion, key), verificationFor(unpinnedCandidate, key)],
      TEST_WORK_BUDGET,
    );
    expect(unpinned.diagnostics.invalidEvidence).toHaveLength(2);
    expect(unpinned.diagnostics.invalidEvidence.every(
      ({ reason }) => reason === "evaluator-key-not-pinned-by-protocol",
    )).toBe(true);
  });

  it("fails closed instead of selecting a producer identity by input order", () => {
    const key = evaluatorKeyFixture();
    const protocol = parseProtocol();
    const champion = validTraceInputForProfile("champion");
    const candidate = validTraceInputForProfile("candidate");
    const producerV1 = verificationFor(champion, key);
    const producerV2 = verificationFor(candidate, key, (evidence) => {
      evidence.evaluator.producer.version = "4.2.1";
    });

    const forward = joinAssessmentEvidence(
      protocol,
      [parseTrace(champion), parseTrace(candidate)],
      [producerV1, producerV2],
      TEST_WORK_BUDGET,
    );
    const reverse = joinAssessmentEvidence(
      protocol,
      [parseTrace(candidate), parseTrace(champion)],
      [producerV2, producerV1],
      TEST_WORK_BUDGET,
    );

    expect(reverse).toEqual(forward);
    expect(forward.counts.matchedRows).toBe(1);
    expect(forward.diagnostics.invalidEvidence).toHaveLength(1);
    expect(forward.diagnostics.invalidEvidence.every(
      ({ reason }) =>
        reason === "evaluator-or-rubric-or-calibration-or-producer-drift",
    )).toBe(true);
    expect(forward.admissibility.valid).toBe(false);
  });

  it("retains missing, abstained, invalid-signature, and orphan evidence separately", () => {
    const key = evaluatorKeyFixture();
    const protocol = parseProtocol();
    const champion = validTraceInputForProfile("champion");
    const candidate = validTraceInputForProfile("candidate");
    const abstained = verificationFor(champion, key, (evidence) => {
      evidence.outcome = {
        kind: "abstained",
        reasonCode: "insufficient-context",
      } as never;
    });
    const wrongKey = evaluatorKeyFixture();
    const invalidSignature = verificationFor(candidate, {
      ...key,
      privateKey: wrongKey.privateKey,
    });
    const orphanTrace = mutate(champion, (trace) => {
      trace.traceId = "trace-orphan";
      trace.terminalOutputId = keyedIdentity("9");
    });
    const orphan = verificationFor(orphanTrace, key);

    const joined = joinAssessmentEvidence(
      protocol,
      [parseTrace(champion), parseTrace(candidate)],
      [invalidSignature, orphan, abstained],
      TEST_WORK_BUDGET,
    );

    expect(joined.diagnostics.abstainedEvidence).toEqual([
      expect.objectContaining({
        evidenceDigest: abstained.evidenceDigest,
        reasonCode: "insufficient-context",
      }),
    ]);
    expect(joined.diagnostics.invalidEvidence).toEqual([
      expect.objectContaining({
        evidenceDigest: invalidSignature.evidenceDigest,
        reason: "verification-invalid-signature",
      }),
    ]);
    expect(joined.diagnostics.orphanEvidence).toEqual([
      expect.objectContaining({
        evidenceDigest: orphan.evidenceDigest,
        reason: "no-matching-trace",
      }),
    ]);
    expect(joined.diagnostics.missingEvidence).toEqual([]);
    expect(joined.executions.find(
      ({ profileId }) => profileId === "candidate",
    )?.outcome.kind).toBe("invalid-evidence");
    expect(joined.diagnostics.invalidEvidence[0]).toMatchObject({
      evidence: {
        source: invalidSignature.evidence.source,
        keyId: invalidSignature.evidence.keyId,
        producedAt: invalidSignature.evidence.producedAt,
      },
      verification: {
        status: "invalid-signature",
        trusted: false,
        assessmentContextDigest: invalidSignature.assessmentContextDigest,
      },
    });
    expect(joined.diagnostics.orphanEvidence[0]).toMatchObject({
      evidence: {
        source: orphan.evidence.source,
      },
      verification: {
        status: "trusted",
        trusted: true,
        assessmentContextDigest: orphan.assessmentContextDigest,
      },
    });
    expect(Object.isFrozen(joined.diagnostics.invalidEvidence[0].evidence)).toBe(true);
    expect(Object.isFrozen(
      joined.diagnostics.invalidEvidence[0].verification,
    )).toBe(true);
  });

  it("attaches signed missing and invalid outcomes without treating them as scores", () => {
    const key = evaluatorKeyFixture();
    const protocol = parseProtocol();
    const champion = validTraceInputForProfile("champion");
    const candidate = validTraceInputForProfile("candidate");
    const declaredMissing = verificationFor(champion, key, (evidence) => {
      evidence.outcome = {
        kind: "missing",
        reasonCode: "payload-unavailable",
      } as never;
    });
    const declaredInvalid = verificationFor(candidate, key, (evidence) => {
      evidence.outcome = {
        kind: "invalid",
        reasonCode: "rubric-input-invalid",
      } as never;
    });

    const joined = joinAssessmentEvidence(
      protocol,
      [parseTrace(champion), parseTrace(candidate)],
      [declaredMissing, declaredInvalid],
      TEST_WORK_BUDGET,
    );

    expect(joined.counts).toMatchObject({
      matchedRows: 2,
      scoredRows: 0,
    });
    expect(joined.executions.map(({ outcome }) => outcome.kind).sort()).toEqual([
      "invalid-evidence",
      "missing-evidence",
    ]);
    expect(joined.diagnostics.missingEvidence).toEqual([
      expect.objectContaining({
        evidenceDigest: declaredMissing.evidenceDigest,
        reason: "evaluator-declared-payload-unavailable",
      }),
    ]);
    expect(joined.diagnostics.invalidEvidence).toEqual([
      expect.objectContaining({
        evidenceDigest: declaredInvalid.evidenceDigest,
        reason: "evaluator-declared-rubric-input-invalid",
      }),
    ]);
    expect(joined.admissibility.valid).toBe(false);
  });

  it("reports exact duplicates but rejects every same-key conflict without a winner", () => {
    const key = evaluatorKeyFixture();
    const protocol = parseProtocol();
    const champion = validTraceInputForProfile("champion");
    const candidate = validTraceInputForProfile("candidate");
    const championEvidence = verificationFor(champion, key);
    const candidateEvidence = verificationFor(candidate, key);
    const conflicting = verificationFor(candidate, key, (evidence) => {
      if (evidence.outcome.kind === "scored") evidence.outcome.score = 0.25;
    });
    const input = [
      championEvidence,
      championEvidence,
      candidateEvidence,
      conflicting,
    ];

    const forward = joinAssessmentEvidence(
      protocol,
      [parseTrace(champion), parseTrace(candidate)],
      input,
      TEST_WORK_BUDGET,
    );
    const reverse = joinAssessmentEvidence(
      protocol,
      [parseTrace(candidate), parseTrace(champion)],
      [...input].reverse(),
      TEST_WORK_BUDGET,
    );

    expect(reverse).toEqual(forward);
    expect(forward.diagnostics.duplicateEvidence).toEqual([
      expect.objectContaining({
        evidenceDigest: championEvidence.evidenceDigest,
        occurrences: 2,
      }),
    ]);
    expect(forward.diagnostics.conflictingEvidence).toEqual([
      expect.objectContaining({
        evidenceDigests: [
          candidateEvidence.evidenceDigest,
          conflicting.evidenceDigest,
        ].sort(),
        reason: "multiple-distinct-evidence-rows-for-join-key",
      }),
    ]);
    expect(forward.executions.find(
      ({ profileId }) => profileId === "champion",
    )?.outcome.kind).toBe("scored");
    expect(forward.executions.find(
      ({ profileId }) => profileId === "candidate",
    )?.outcome.kind).toBe("invalid-evidence");
    expect(forward.diagnostics.missingEvidence).toEqual([]);
    expect(forward.diagnostics.conflictingEvidence[0]).toMatchObject({
      rows: expect.arrayContaining([
        expect.objectContaining({
          evidence: candidateEvidence.evidence,
          verification: expect.objectContaining({ status: "trusted" }),
        }),
        expect.objectContaining({
          evidence: conflicting.evidence,
          verification: expect.objectContaining({ status: "trusted" }),
        }),
      ]),
    });
  });

  it("never partial-key attaches terminal-output or redundant-lineage mismatches", () => {
    const key = evaluatorKeyFixture();
    const protocol = parseProtocol();
    const champion = validTraceInputForProfile("champion");
    const candidate = validTraceInputForProfile("candidate");
    const terminalMismatch = verificationFor(
      mutate(champion, (trace) => {
        trace.terminalOutputId = keyedIdentity("8");
      }),
      key,
    );
    const replicateMismatch = verificationFor(candidate, key, (evidence) => {
      evidence.replicateId = "replicate-99";
    });

    const joined = joinAssessmentEvidence(
      protocol,
      [parseTrace(champion), parseTrace(candidate)],
      [terminalMismatch, replicateMismatch],
      TEST_WORK_BUDGET,
    );

    expect(joined.counts.matchedRows).toBe(0);
    expect(joined.diagnostics.orphanEvidence).toEqual([
      expect.objectContaining({
        evidenceDigest: terminalMismatch.evidenceDigest,
        reason: "terminal-output-mismatch",
      }),
    ]);
    expect(joined.diagnostics.conflictingEvidence).toEqual([
      expect.objectContaining({
        evidenceDigests: [replicateMismatch.evidenceDigest],
        reason: "trace-evidence-lineage-conflict",
      }),
    ]);
  });

  it("keeps case-replicate pairing exact and reports every missing profile", () => {
    const protocol = parseProtocol();
    const champion = validTraceInputForProfile("champion");
    const candidate = mutate(validTraceInputForProfile("candidate"), (trace) => {
      trace.replicateId = "replicate-1";
      trace.traceId = "trace-case-1-r1-candidate";
    });

    const joined = joinAssessmentEvidence(
      protocol,
      [parseTrace(champion), parseTrace(candidate)],
      [],
      TEST_WORK_BUDGET,
    );

    expect(joined.pairs).toEqual([]);
    expect(joined.diagnostics.missingProfileExecutions).toEqual([
      {
        caseId: "case-1",
        replicateId: "replicate-0",
        missingProfileIds: ["candidate"],
      },
      {
        caseId: "case-1",
        replicateId: "replicate-1",
        missingProfileIds: ["champion"],
      },
    ]);
  });

  it("counts traffic once per case while retaining every replicate", () => {
    const protocol = parseProtocol();
    const traces = [
      validTraceInputForProfile("champion"),
      validTraceInputForProfile("candidate"),
      ...secondReplicatePair(),
    ].map(parseTrace);

    const joined = joinAssessmentEvidence(
      protocol,
      traces,
      [],
      TEST_WORK_BUDGET,
    );

    expect(joined.counts).toMatchObject({
      cases: 1,
      caseReplicates: 2,
      pairedCaseReplicates: 2,
      observedTrafficMass: 1,
    });
  });

  it.each([
    [
      "group",
      (trace: TraceInput) => { trace.groupId = "group-a"; },
      /case.*group|group.*case/i,
    ],
    [
      "traffic",
      (trace: TraceInput) => { trace.workload.declaredTrafficWeight = 2; },
      /case.*traffic|traffic.*case/i,
    ],
    [
      "workload",
      (trace: TraceInput) => { trace.workload.inputTokenEstimate = 256; },
      /case.*workload|workload.*case/i,
    ],
    [
      "slices",
      (trace: TraceInput) => { trace.slices = ["other-slice"]; },
      /case.*slice|slice.*case/i,
    ],
    [
      "route signal",
      (trace: TraceInput) => { trace.routeSignal!.value = 0.5; },
      /case.*route.signal|route.signal.*case/i,
    ],
    [
      "policy",
      (trace: TraceInput) => { trace.policyDigest = digest("f"); },
      /case.*policy|policy.*case/i,
    ],
  ] as const)("rejects %s drift across replicates of one case", (
    _label,
    change,
    expected,
  ) => {
    const traces = [
      validTraceInputForProfile("champion"),
      validTraceInputForProfile("candidate"),
      ...secondReplicatePair(change),
    ].map(parseTrace);

    expect(() => joinAssessmentEvidence(
      parseProtocol(),
      traces,
      [],
      TEST_WORK_BUDGET,
    )).toThrow(expected);
  });

  it("rejects online window drift across replicates of one case", () => {
    const firstReplicate = [
      validTraceInputForProfile("champion"),
      validTraceInputForProfile("candidate"),
    ];
    const secondReplicate = secondReplicatePair();
    const makeOnline = (trace: TraceInput, windowId: string) => {
      const mutable = trace as any;
      mutable.split = "online";
      mutable.collectionWindowId = windowId;
      mutable.collectionWindowMembershipDigest = digest(
        windowId === "window-1" ? "a" : "b",
      );
      mutable.sourceMode = "shadow";
    };
    firstReplicate.forEach((trace) => makeOnline(trace, "window-1"));
    secondReplicate.forEach((trace) => makeOnline(trace, "window-2"));

    expect(() => joinAssessmentEvidence(
      parseProtocol(),
      [...firstReplicate, ...secondReplicate].map(parseTrace),
      [],
      TEST_WORK_BUDGET,
    )).toThrow(/case.*window|window.*case/i);
  });

  it.each([
    [
      "protocol digest",
      (traces: TraceInput[]) => { traces[0].protocolDigest = digest("f"); },
      /protocol.*digest/i,
    ],
    [
      "profile fingerprint",
      (traces: TraceInput[]) => { traces[0].executionProfileDigest = digest("f"); },
      /execution profile.*digest|profile.*drift/i,
    ],
    [
      "declared split",
      (traces: TraceInput[]) => {
        traces[0].groupId = "holdout-group";
        traces[0].split = "dev";
      },
      /declared split.*derived|split.*disagree/i,
    ],
    [
      "route definition",
      (traces: TraceInput[]) => { traces[0].routeSignal!.version = "3"; },
      /route.signal.*drift/i,
    ],
    [
      "route value",
      (traces: TraceInput[]) => { traces[0].routeSignal!.value = 0.5; },
      /paired.*route.signal|route.signal.*pair/i,
    ],
    [
      "group identity",
      (traces: TraceInput[]) => { traces[0].groupId = "group-a"; },
      /paired.*group|group.*pair/i,
    ],
    [
      "traffic weight",
      (traces: TraceInput[]) => {
        traces[0].workload.declaredTrafficWeight = 2;
      },
      /paired.*traffic|traffic.*pair/i,
    ],
    [
      "slice identity",
      (traces: TraceInput[]) => { traces[0].slices = ["other-slice"]; },
      /paired.*slice|slice.*pair/i,
    ],
  ] as const)("fails closed on %s drift", (_label, change, message) => {
    const traces = [
      validTraceInputForProfile("champion"),
      validTraceInputForProfile("candidate"),
    ];
    change(traces);
    expect(() => joinAssessmentEvidence(
      parseProtocol(),
      traces.map(parseTrace),
      [],
      TEST_WORK_BUDGET,
    )).toThrow(message);
  });

  it("rejects trace-id reuse, duplicate profile executions, and cross-split group leakage", () => {
    const protocol = parseProtocol();
    const champion = validTraceInputForProfile("champion");
    const candidate = validTraceInputForProfile("candidate");

    const reusedTraceId = joinAssessmentEvidence(
      protocol,
      [
        parseTrace(champion),
        parseTrace(mutate(candidate, (trace) => {
          trace.traceId = champion.traceId;
        })),
      ],
      [],
      TEST_WORK_BUDGET,
    );
    expect(reusedTraceId.executions).toEqual([]);
    expect(reusedTraceId.diagnostics.conflictingTraces).toEqual([
      expect.objectContaining({
        reason: "trace-id-lineage-conflict",
        traceDigests: expect.arrayContaining([
          expect.stringMatching(/^sha256:/),
          expect.stringMatching(/^sha256:/),
        ]),
      }),
    ]);

    const duplicateProfile = joinAssessmentEvidence(
      protocol,
      [
        parseTrace(champion),
        parseTrace(mutate(champion, (trace) => {
          trace.traceId = "trace-duplicate-profile";
        })),
      ],
      [],
      TEST_WORK_BUDGET,
    );
    expect(duplicateProfile.executions).toEqual([]);
    expect(duplicateProfile.diagnostics.conflictingTraces).toEqual([
      expect.objectContaining({
        reason: "multiple-profile-executions-for-case-replicate",
      }),
    ]);

    const onlineCandidate = mutate(candidate, (trace: any) => {
      trace.split = "online";
      trace.collectionWindowId = "window-1";
      trace.collectionWindowMembershipDigest = digest("a");
      trace.sourceMode = "shadow";
    });
    expect(() => joinAssessmentEvidence(
      protocol,
      [parseTrace(champion), parseTrace(onlineCandidate)],
      [],
      TEST_WORK_BUDGET,
    )).toThrow(/cross.split.*group|group.*split/i);
  });

  it("retains one canonical exact duplicate trace and records all occurrences", () => {
    const protocol = parseProtocol();
    const champion = parseTrace(validTraceInputForProfile("champion"));
    const candidate = parseTrace(validTraceInputForProfile("candidate"));

    const joined = joinAssessmentEvidence(
      protocol,
      [champion, candidate, champion],
      [],
      TEST_WORK_BUDGET,
    );

    expect(joined.counts).toMatchObject({
      traceRows: 3,
      acceptedTraceRows: 2,
    });
    expect(joined.executions.map(({ profileId }) => profileId).sort()).toEqual([
      "candidate",
      "champion",
    ]);
    expect(joined.diagnostics.duplicateTraces).toEqual([
      expect.objectContaining({
        traceId: champion.traceId,
        occurrences: 2,
      }),
    ]);
    expect(joined.diagnostics.missingProfileExecutions).toEqual([]);
    expect(joined.admissibility).toMatchObject({
      valid: false,
      blockingReasons: expect.arrayContaining(["duplicate-traces"]),
    });
  });

  it("preflights row and full work budgets before reading collection elements", () => {
    const protocol = parseProtocol();
    let elementReads = 0;
    const traces = new Proxy(
      [parseTrace(validTraceInputForProfile("champion"))],
      {
        get(target, property, receiver) {
          if (property !== "length") elementReads += 1;
          return Reflect.get(target, property, receiver);
        },
      },
    );

    expect(() => joinAssessmentEvidence(
      protocol,
      traces,
      [],
      { ...TEST_WORK_BUDGET, maxTraceRows: 0 },
    )).toThrow(/trace rows?.*work budget/i);
    expect(elementReads).toBe(0);

    expect(() => joinAssessmentEvidence(
      protocol,
      [parseTrace(validTraceInputForProfile("champion"))],
      [],
      { ...TEST_WORK_BUDGET, maxAssessmentWork: 0 },
    )).toThrow(/(?:assessment|join) work.*work budget/i);

    expect(() => joinAssessmentEvidence(
      protocol,
      [parseTrace(validTraceInputForProfile("champion"))],
      [],
      { ...TEST_WORK_BUDGET, maxIndependentGroups: 0 },
    )).toThrow(/independent group.*work budget/i);
  });

  it("charges cumulative label memberships before allocating slice output", () => {
    const protocol = parseProtocol();
    const withoutLabels = manyPairedTraces(protocol, 1, () => []);
    const withLabels = manyPairedTraces(
      protocol,
      1,
      () => Array.from({ length: 64 }, (_, index) => `slice-${index}`),
    );
    const tightBudget = {
      ...TEST_WORK_BUDGET,
      maxAssessmentWork: 50,
    };

    expect(() => joinAssessmentEvidence(
      protocol,
      withoutLabels.map(parseTrace),
      [],
      tightBudget,
    )).not.toThrow();
    expect(() => joinAssessmentEvidence(
      protocol,
      withLabels.map(parseTrace),
      [],
      tightBudget,
    )).toThrow(/join work.*work budget|label membership.*work budget/i);
  });

  it("admits a 320-pair linear join and reports one-pass disjoint-slice visits", () => {
    const protocol = parseProtocol();
    const traces = manyPairedTraces(
      protocol,
      320,
      (index) => [`slice-${index}`],
    ).map(parseTrace);
    const budget = {
      ...TEST_WORK_BUDGET,
      maxTraceRows: 1_000,
      maxEvidenceRows: 1_000,
      maxIndependentGroups: 500,
      maxAssessmentWork: 30_000,
    };

    const joined = joinAssessmentEvidence(protocol, traces, [], budget);

    expect(joined.counts).toMatchObject({
      traceRows: 640,
      cases: 320,
      caseReplicates: 320,
      pairedCaseReplicates: 320,
    });
    expect(joined.counts.slices).toHaveLength(320);
    expect(joined.work).toMatchObject({
      labelMemberships: 640,
      sliceAggregationVisits: 320,
    });
    expect(joined.work.chargedUnits).toBeLessThanOrEqual(30_000);
  });

  it("snapshots collection data properties once and never invokes element accessors", () => {
    const protocol = parseProtocol();
    let getterCalls = 0;
    const traces = [parseTrace(validTraceInputForProfile("champion"))];
    Object.defineProperty(traces, "0", {
      enumerable: true,
      configurable: true,
      get() {
        getterCalls += 1;
        throw new Error("collection accessor must not run");
      },
    });

    expect(() => joinAssessmentEvidence(
      protocol,
      traces,
      [],
      TEST_WORK_BUDGET,
    )).toThrow(/collection.*accessor|accessor.*collection/i);
    expect(getterCalls).toBe(0);

    const withExtra = [parseTrace(validTraceInputForProfile("champion"))];
    Object.defineProperty(withExtra, "metadata", {
      enumerable: true,
      value: "not-row-data",
    });
    expect(() => joinAssessmentEvidence(
      protocol,
      withExtra,
      [],
      TEST_WORK_BUDGET,
    )).toThrow(/collection.*extra propert|extra propert.*collection/i);
  });
});
