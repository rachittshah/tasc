import { describe, expect, it } from "vitest";
import {
  fingerprintExperimentBudget,
  fingerprintExperimentHistory,
  fingerprintExperimentProposalDecision,
  parseExperimentBudget,
  parseExperimentHistory,
  parseExperimentProposalDecision,
  proposeExperiment,
  type ExperimentBudgetInput,
  type ExperimentHistoryInput,
  type ExperimentProposalDecision,
} from "../src/experiments.js";
import {
  domainSeparatedDigest,
  fingerprintProtocol,
  parseExperimentProtocol,
} from "../src/evidence.js";
import {
  enumerateProtocolPolicyBundles,
  type PolicyBundle,
} from "../src/policy.js";
import {
  TEST_WORK_BUDGET,
  validProtocolInput,
} from "./fixtures/evidence.js";

const digest = (label: string): string =>
  domainSeparatedDigest("tasc/test/experiment-proposal", label);

const DEFAULT_BUDGET: ExperimentBudgetInput = {
  version: "tasc-experiment-budget-v1",
  maxLogicalExecutions: 100,
  maxAttempts: 200,
  maxCostUsd: 25,
  maxWallClockMs: 60_000,
  payloadPolicy: "keyed-identities-only",
};

const EMPTY_HISTORY: ExperimentHistoryInput = {
  version: "tasc-experiment-history-v1",
  registeredExperiments: [],
  findings: [],
};

function policyFixtures(): {
  readonly control: PolicyBundle;
  readonly candidate: PolicyBundle;
  readonly otherCandidate: PolicyBundle;
} {
  const protocol = parseExperimentProtocol(
    validProtocolInput(),
    TEST_WORK_BUDGET,
  );
  const policies = enumerateProtocolPolicyBundles(
    protocol,
    fingerprintProtocol(protocol),
    protocol.createdAt,
  );
  return {
    control: policies.control,
    candidate: policies.candidates[0],
    otherCandidate: policies.candidates[1],
  };
}

function metric(
  value: number | null,
  evidenceClass:
    | "measured"
    | "reported"
    | "modeled"
    | "unavailable",
): Record<string, unknown> {
  return value === null
    ? { value, evidenceClass, reason: "fixture-unavailable" }
    : { value, evidenceClass };
}

function passingCandidate(policy: PolicyBundle): Record<string, any> {
  return {
    policy,
    policyDigest: policy.policyDigest,
    status: "PASS",
    replay: [
      {
        caseId: "case-1",
        replicateId: "replicate-1",
        groupId: "group-1",
        attemptedProfileIds: [policy.primaryProfileId],
        selectedProfileId: policy.primaryProfileId,
        status: "success",
        escalated: false,
        score: 0.9,
        scoreEvidenceClass: "reported",
        trafficWeight: 1,
        slices: ["routine"],
        ttftMs: 10,
        endToEndLatencyMs: 20,
        costUsd: 0.01,
      },
    ],
    metrics: {
      meanScore: metric(0.9, "reported"),
      failureRate: metric(0, "measured"),
      ttftMs: metric(10, "measured"),
      endToEndLatencyMs: metric(20, "measured"),
      costPerThousandRequestsUsd: metric(10, "reported"),
      evidenceCoverage: metric(1, "measured"),
      serviceCapacity: metric(null, "unavailable"),
    },
    gates: [
      {
        id: "minimum-mean-score",
        operator: ">=",
        threshold: 0.8,
        actual: 0.9,
        evidenceClass: "reported",
        passed: true,
      },
    ],
    inference: {
      method: "paired-group-percentile-v1",
      alpha: 0.05,
      caseCount: 1,
      replicateCount: 1,
      groupCount: 1,
      effectiveTrafficMass: 1,
      estimate: 0.1,
      interval: { lo: 0.1, hi: 0.1 },
      iterations: 1_000,
      seed: 42,
      positive: true,
    },
    coverage: {
      caseCount: 1,
      replicateCount: 1,
      groupCount: 1,
      effectiveTrafficMass: 1,
      criticalSliceGroups: [{ sliceId: "payments", groupCount: 1 }],
      failureCount: 0,
      missingEvidenceCount: 0,
      evidenceCoverage: 1,
    },
    insufficiencyReasons: [],
    rejectionReasons: [],
  };
}

function developmentAssessmentBody(): Record<string, any> {
  const { control, candidate } = policyFixtures();
  return {
    version: "tasc-assessment-decision-v2",
    engineVersion: "tasc-assessment-engine-v2",
    phase: "development",
    status: "NOMINATED",
    assessmentContextDigest: digest("context"),
    protocolDigest: candidate.protocolDigest,
    datasetDigest: digest("dataset"),
    traceSetDigest: digest("traces"),
    evaluatorSetDigest: digest("evaluators"),
    windowManifestDigest: null,
    estimator: {
      method: "paired-group-percentile-v1",
      alpha: 0.05,
      iterations: 1_000,
      seed: 42,
    },
    control: passingCandidate(control),
    candidates: [passingCandidate(candidate)],
    selectedPolicy: candidate,
    selectedPolicyDigest: candidate.policyDigest,
    staleReasons: [],
    warnings: [],
    unavailableMetrics: ["serviceCapacity"],
    attestation: "unattested",
  };
}

function sealAssessment(
  body: Record<string, unknown>,
): Record<string, unknown> {
  return {
    ...body,
    decisionDigest: domainSeparatedDigest(
      "tasc/assessment-decision/v2",
      body,
    ),
  };
}

function developmentAssessment(
  mutate?: (body: Record<string, any>) => void,
): Record<string, unknown> {
  const body = structuredClone(developmentAssessmentBody());
  mutate?.(body);
  return sealAssessment(body);
}

function makeInsufficient(
  body: Record<string, any>,
  reasons: readonly string[],
): void {
  body.status = "INSUFFICIENT_EVIDENCE";
  body.selectedPolicy = null;
  body.selectedPolicyDigest = null;
  const candidate = body.candidates[0];
  candidate.status = "INSUFFICIENT_EVIDENCE";
  candidate.inference = null;
  candidate.insufficiencyReasons = [...reasons].sort();
  candidate.rejectionReasons = [...reasons].sort();
}

function failedGate(
  id: string,
): Record<string, unknown> {
  const quality = id === "paired-quality"
    || id === "minimum-mean-score"
    || id.startsWith("paired-critical-slice-quality:");
  return quality
    ? {
      id,
      operator: ">=",
      threshold: 0.8,
      actual: 0.7,
      evidenceClass: "modeled",
      passed: false,
    }
    : {
      id,
      operator: "<=",
      threshold: 10,
      actual: 20,
      evidenceClass: "measured",
      passed: false,
    };
}

function makeNoCandidate(
  body: Record<string, any>,
  gateIds: readonly string[],
): void {
  body.status = "NO_CANDIDATE";
  body.selectedPolicy = null;
  body.selectedPolicyDigest = null;
  const candidate = body.candidates[0];
  candidate.status = "HOLD";
  candidate.gates.push(...gateIds.map(failedGate));
  candidate.rejectionReasons = gateIds
    .map((id) => `failed-gate:${id}`)
    .sort();
}

function changePhase(
  body: Record<string, any>,
  phase: "holdout" | "window",
  status: "PASS" | "HOLD" = "PASS",
): void {
  body.phase = phase;
  body.status = status;
  body.windowManifestDigest = phase === "window"
    ? digest("window")
    : null;
  body.candidates[0].status = status;
  if (status === "HOLD") {
    body.candidates[0].gates.push(failedGate("unrecognized-gate"));
    body.candidates[0].rejectionReasons = [
      "failed-gate:unrecognized-gate",
    ];
  }
}

function makeStale(
  body: Record<string, any>,
  reasons: readonly string[],
): void {
  body.status = "STALE";
  body.selectedPolicy = null;
  body.selectedPolicyDigest = null;
  body.staleReasons = reasons;
  for (const candidate of [body.control, ...body.candidates]) {
    candidate.status = "STALE";
    candidate.replay = [];
    candidate.metrics = {
      meanScore: metric(null, "unavailable"),
      failureRate: metric(null, "unavailable"),
      ttftMs: metric(null, "unavailable"),
      endToEndLatencyMs: metric(null, "unavailable"),
      costPerThousandRequestsUsd: metric(null, "unavailable"),
      evidenceCoverage: metric(null, "unavailable"),
      serviceCapacity: metric(null, "unavailable"),
    };
    candidate.gates = [];
    candidate.inference = null;
    candidate.coverage = {
      caseCount: 0,
      replicateCount: 0,
      groupCount: 0,
      effectiveTrafficMass: 0,
      criticalSliceGroups: [],
      failureCount: 0,
      missingEvidenceCount: 0,
      evidenceCoverage: 0,
    };
    candidate.insufficiencyReasons = [];
    candidate.rejectionReasons = reasons;
  }
  body.unavailableMetrics = [
    "costPerThousandRequestsUsd",
    "endToEndLatencyMs",
    "evidenceCoverage",
    "failureRate",
    "meanScore",
    "serviceCapacity",
    "ttftMs",
  ];
}

function makeEvaluatorStale(body: Record<string, any>): void {
  makeStale(body, [
    "evaluator-evidence-stale",
    "evaluator-verification-context-drift",
  ]);
}

function expectProposed(
  decision: ExperimentProposalDecision,
  diagnosis: string,
): Extract<ExperimentProposalDecision, { readonly status: "PROPOSED" }> {
  expect(decision.status).toBe("PROPOSED");
  if (decision.status !== "PROPOSED") {
    throw new Error(`expected proposal, received ${decision.holdReason}`);
  }
  expect(decision.diagnosis).toBe(diagnosis);
  return decision;
}

function resignProposal(
  decision: Extract<
    ExperimentProposalDecision,
    { readonly status: "PROPOSED" }
  >,
  mutate: (body: Record<string, any>) => void,
): Record<string, unknown> {
  const body = structuredClone(decision) as Record<string, any>;
  delete body.decisionDigest;
  mutate(body);
  body.experimentIntentDigest = domainSeparatedDigest(
    "tasc/experiment-intent/v2",
    {
      version: "tasc-experiment-intent-v2",
      parentAssessmentDigest: body.parentAssessmentDigest,
      parentProtocolDigest: body.parentProtocolDigest,
      budgetDigest: body.budget.budgetDigest,
      diagnosis: body.diagnosis,
      hypothesis: body.hypothesis,
      changedVariable: body.changedVariable,
      frozenControls: body.frozenControls,
      evidenceRequirements: body.evidenceRequirements,
      stopCondition: body.stopCondition,
      expectedDecision: body.expectedDecision,
    },
  );
  body.decisionDigest = domainSeparatedDigest(
    "tasc/experiment-proposal-decision/v2",
    body,
  );
  return body;
}

describe("experiment proposal contracts", () => {
  it("normalizes, fingerprints, and recursively freezes a bounded budget", () => {
    const parsed = parseExperimentBudget(DEFAULT_BUDGET);

    expect(parsed.budgetDigest).toBe(
      fingerprintExperimentBudget(DEFAULT_BUDGET),
    );
    expect(Object.isFrozen(parsed)).toBe(true);
    expect(parseExperimentBudget(parsed)).toEqual(parsed);
  });

  it("rejects unsafe budgets while preserving zero as a valid hard ceiling", () => {
    expect(parseExperimentBudget({
      ...DEFAULT_BUDGET,
      maxLogicalExecutions: 0,
      maxAttempts: 0,
      maxCostUsd: 0,
      maxWallClockMs: 0,
    }).maxLogicalExecutions).toBe(0);

    for (const mutation of [
      { maxLogicalExecutions: 1_000_001 },
      { maxAttempts: 8_000_001 },
      { maxLogicalExecutions: 4, maxAttempts: 3 },
      { maxCostUsd: Number.POSITIVE_INFINITY },
      { maxCostUsd: -1 },
      { maxWallClockMs: 2_592_000_001 },
      { payloadPolicy: "raw-payloads" },
      { unexpected: true },
    ]) {
      expect(() => parseExperimentBudget({
        ...DEFAULT_BUDGET,
        ...mutation,
      })).toThrow();
    }
  });

  it("normalizes history order and binds its optional self-digest", () => {
    const input: ExperimentHistoryInput = {
      version: "tasc-experiment-history-v1",
      registeredExperiments: [
        {
          parentProtocolDigest: digest("parent-b"),
          experimentIntentDigest: digest("intent-b"),
          registeredProtocolDigest: digest("registered-b"),
          outcomeAssessmentDigest: null,
        },
        {
          parentProtocolDigest: digest("parent-a"),
          experimentIntentDigest: digest("intent-a"),
          registeredProtocolDigest: digest("registered-a"),
          outcomeAssessmentDigest: digest("outcome-a"),
        },
      ],
      findings: [
        {
          kind: "required-capability-mismatch",
          protocolDigest: digest("protocol-b"),
          profileId: "profile-b",
          capabilityId: "streaming",
          capabilityEvidenceDigest: digest("finding-b"),
        },
        {
          kind: "required-capability-mismatch",
          protocolDigest: digest("protocol-a"),
          profileId: "profile-a",
          capabilityId: "cancellation",
          capabilityEvidenceDigest: digest("finding-a"),
        },
      ],
    };
    const forward = parseExperimentHistory(input);
    const reversed = parseExperimentHistory({
      ...input,
      registeredExperiments: [...input.registeredExperiments].reverse(),
      findings: [...input.findings].reverse(),
    });

    expect(reversed).toEqual(forward);
    expect(forward.historyDigest).toBe(
      fingerprintExperimentHistory(input),
    );
    expect(Object.isFrozen(forward.findings)).toBe(true);
    expect(Object.isFrozen(forward.findings[0])).toBe(true);
    expect(parseExperimentHistory(forward)).toEqual(forward);
  });

  it("rejects duplicate, oversized, or self-digest-mismatched history", () => {
    const registration = {
      parentProtocolDigest: digest("parent"),
      experimentIntentDigest: digest("intent"),
      registeredProtocolDigest: digest("registered"),
      outcomeAssessmentDigest: null,
    };
    const finding = {
      kind: "required-capability-mismatch" as const,
      protocolDigest: digest("protocol"),
      profileId: "candidate",
      capabilityId: "streaming",
      capabilityEvidenceDigest: digest("finding"),
    };

    expect(() => parseExperimentHistory({
      ...EMPTY_HISTORY,
      registeredExperiments: [registration, registration],
    })).toThrow(/duplicate/i);
    expect(() => parseExperimentHistory({
      ...EMPTY_HISTORY,
      findings: [finding, finding],
    })).toThrow(/duplicate/i);
    expect(() => parseExperimentHistory({
      ...EMPTY_HISTORY,
      registeredExperiments: Array.from({ length: 257 }, (_, index) => ({
        ...registration,
        experimentIntentDigest: digest(`intent-${index}`),
        registeredProtocolDigest: digest(`protocol-${index}`),
      })),
    })).toThrow(/limit|256|length/i);
    expect(() => parseExperimentHistory({
      ...EMPTY_HISTORY,
      historyDigest: digest("wrong"),
    })).toThrow(/digest/i);
  });

  it("strictly verifies and freezes persisted proposal decisions", () => {
    const proposal = expectProposed(
      proposeExperiment(
        developmentAssessment(),
        EMPTY_HISTORY,
        DEFAULT_BUDGET,
      ),
      "sealed-shadow-replication",
    );
    const parsed = parseExperimentProposalDecision(
      structuredClone(proposal),
    );

    expect(parsed).toEqual(proposal);
    expect(parsed.status).toBe("PROPOSED");
    if (parsed.status !== "PROPOSED") {
      throw new Error("expected parsed proposal");
    }
    expect(parsed.decisionDigest).toBe(
      fingerprintExperimentProposalDecision(parsed),
    );
    expect(Object.isFrozen(parsed)).toBe(true);
    expect(Object.isFrozen(parsed.budget)).toBe(true);
    expect(Object.isFrozen(parsed.evidenceRequirements)).toBe(true);

    expect(() => parseExperimentProposalDecision({
      ...structuredClone(proposal),
      diagnosis: "cost-regression",
    })).toThrow(/digest|semantic/i);
    expect(() => parseExperimentProposalDecision({
      ...structuredClone(proposal),
      unexpected: true,
    })).toThrow();
  });

  it("rejects re-signed proposal content outside the deterministic table", () => {
    const proposal = expectProposed(
      proposeExperiment(
        developmentAssessment(),
        EMPTY_HISTORY,
        DEFAULT_BUDGET,
      ),
      "sealed-shadow-replication",
    );

    expect(() => parseExperimentProposalDecision(
      resignProposal(proposal, (body) => {
        body.evidenceRequirements = [
          { kind: "exact-policy-capacity-evidence" },
        ];
      }),
    )).toThrow(/semantic|evidence requirement/i);
    expect(() => parseExperimentProposalDecision(
      resignProposal(proposal, (body) => {
        body.changedVariable.targetId = "unrelated-target";
      }),
    )).toThrow(/semantic|changed.?variable|target|literal/i);
  });

  it("binds every non-capability diagnosis to a semantic role target", () => {
    const cases: readonly {
      readonly diagnosis: string;
      readonly kind: string;
      readonly targetId: string;
      readonly mutate: (body: Record<string, any>) => void;
    }[] = [
      {
        diagnosis: "quality-regression",
        kind: "routing-policy",
        targetId: "selected-policy",
        mutate: (body) => {
          makeNoCandidate(body, ["minimum-mean-score"]);
        },
      },
      {
        diagnosis: "critical-slice-regression",
        kind: "routing-policy",
        targetId: "selected-policy",
        mutate: (body) => {
          makeNoCandidate(body, [
            "paired-critical-slice-quality:payments",
          ]);
        },
      },
      {
        diagnosis: "ttft-regression",
        kind: "execution-profile",
        targetId: "selected-profile",
        mutate: (body) => {
          makeNoCandidate(body, ["maximum-p95-ttft"]);
        },
      },
      {
        diagnosis: "tail-latency-regression",
        kind: "execution-profile",
        targetId: "selected-profile",
        mutate: (body) => {
          makeNoCandidate(body, ["maximum-p95-end-to-end"]);
        },
      },
      {
        diagnosis: "error-regression",
        kind: "execution-profile",
        targetId: "selected-profile",
        mutate: (body) => {
          makeNoCandidate(body, ["maximum-failure-rate"]);
        },
      },
      {
        diagnosis: "cost-regression",
        kind: "execution-profile",
        targetId: "selected-profile",
        mutate: (body) => {
          makeNoCandidate(body, ["maximum-cost-per-thousand"]);
        },
      },
      {
        diagnosis: "unavailable-capacity",
        kind: "capacity-observation",
        targetId: "nominated-window",
        mutate: (body) => {
          body.phase = "window";
          body.status = "INSUFFICIENT_EVIDENCE";
          body.windowManifestDigest = digest("capacity-window");
          const candidate = body.candidates[0];
          candidate.status = "INSUFFICIENT_EVIDENCE";
          candidate.inference = null;
          candidate.insufficiencyReasons = [
            "required-service-capacity-unavailable",
          ];
          candidate.rejectionReasons = [
            "required-service-capacity-unavailable",
          ];
        },
      },
    ];

    for (const testCase of cases) {
      const proposal = expectProposed(
        proposeExperiment(
          developmentAssessment(testCase.mutate),
          EMPTY_HISTORY,
          DEFAULT_BUDGET,
        ),
        testCase.diagnosis,
      );
      expect(proposal.changedVariable).toEqual({
        kind: testCase.kind,
        targetId: testCase.targetId,
      });
      expect(() => parseExperimentProposalDecision(
        resignProposal(proposal, (body) => {
          body.changedVariable.targetId = "unrelated-subject";
        }),
      )).toThrow(/semantic|changed variable|target/i);
    }
  });

  it("keeps intent identity history-independent while binding history in the final decision", () => {
    const initial = expectProposed(
      proposeExperiment(
        developmentAssessment(),
        EMPTY_HISTORY,
        DEFAULT_BUDGET,
      ),
      "sealed-shadow-replication",
    );
    const withUnrelatedHistory = expectProposed(
      proposeExperiment(
        developmentAssessment(),
        {
          ...EMPTY_HISTORY,
          registeredExperiments: [
            {
              parentProtocolDigest: digest("unrelated-parent"),
              experimentIntentDigest: digest("unrelated-intent"),
              registeredProtocolDigest: digest("unrelated-protocol"),
              outcomeAssessmentDigest: null,
            },
          ],
        },
        DEFAULT_BUDGET,
      ),
      "sealed-shadow-replication",
    );

    expect(withUnrelatedHistory.experimentIntentDigest).toBe(
      initial.experimentIntentDigest,
    );
    expect(withUnrelatedHistory.historyDigest).not.toBe(
      initial.historyDigest,
    );
    expect(withUnrelatedHistory.decisionDigest).not.toBe(
      initial.decisionDigest,
    );
  });
});

describe("deterministic next-experiment decision table", () => {
  it("uses the specified stable diagnosis priority", () => {
    const cases: Array<{
      readonly expected: string;
      readonly mutate: (body: Record<string, any>) => void;
    }> = [
      {
        expected: "insufficient-evidence",
        mutate: (body) => {
          makeInsufficient(body, [
            "required-service-capacity-unavailable",
            "insufficient-independent-groups",
          ]);
        },
      },
      {
        expected: "evaluator-drift",
        mutate: makeEvaluatorStale,
      },
      {
        expected: "quality-regression",
        mutate: (body) => {
          makeNoCandidate(body, [
            "maximum-cost-per-thousand",
            "minimum-mean-score",
            "maximum-p95-ttft",
          ]);
        },
      },
      {
        expected: "critical-slice-regression",
        mutate: (body) => {
          makeNoCandidate(body, [
            "maximum-p95-ttft",
            "paired-critical-slice-quality:payments",
          ]);
        },
      },
      {
        expected: "ttft-regression",
        mutate: (body) => {
          makeNoCandidate(body, [
            "maximum-p95-end-to-end",
            "maximum-p95-ttft",
          ]);
        },
      },
      {
        expected: "tail-latency-regression",
        mutate: (body) => {
          makeNoCandidate(body, [
            "maximum-failure-rate",
            "maximum-p95-end-to-end",
          ]);
        },
      },
      {
        expected: "error-regression",
        mutate: (body) => {
          makeNoCandidate(body, [
            "maximum-cost-per-thousand",
            "maximum-failure-rate",
          ]);
        },
      },
      {
        expected: "cost-regression",
        mutate: (body) => {
          makeNoCandidate(body, ["maximum-cost-per-thousand"]);
        },
      },
      {
        expected: "unavailable-capacity",
        mutate: (body) => {
          body.phase = "window";
          body.status = "INSUFFICIENT_EVIDENCE";
          body.windowManifestDigest = digest("capacity-window");
          const candidate = body.candidates[0];
          candidate.status = "INSUFFICIENT_EVIDENCE";
          candidate.inference = null;
          candidate.insufficiencyReasons = [
            "required-service-capacity-unavailable",
          ];
          candidate.rejectionReasons = [
            "required-service-capacity-unavailable",
          ];
        },
      },
    ];

    for (const { expected, mutate } of cases) {
      expectProposed(
        proposeExperiment(
          developmentAssessment(mutate),
          EMPTY_HISTORY,
          DEFAULT_BUDGET,
        ),
        expected,
      );
    }
  });

  it("treats critical-slice coverage as insufficiency, never quality tuning", () => {
    const coverage = expectProposed(
      proposeExperiment(
        developmentAssessment((body) => {
          makeInsufficient(
            body,
            ["insufficient-critical-slice-groups:payments"],
          );
        }),
        EMPTY_HISTORY,
        DEFAULT_BUDGET,
      ),
      "insufficient-evidence",
    );
    const malformedQualitySignal = proposeExperiment(
      developmentAssessment((body) => {
        makeNoCandidate(body, [
          "minimum-critical-slice-groups:payments",
        ]);
      }),
      EMPTY_HISTORY,
      DEFAULT_BUDGET,
    );

    expect(coverage.changedVariable.kind).toBe("evidence-collection");
    expect(malformedQualitySignal).toMatchObject({
      status: "HOLD",
      holdReason: "no-actionable-diagnosis",
    });
  });

  it("requires a sealed policy window before proposing capacity observation", () => {
    const decision = proposeExperiment(
      developmentAssessment((body) => {
        makeInsufficient(
          body,
          ["required-service-capacity-unavailable"],
        );
      }),
      EMPTY_HISTORY,
      DEFAULT_BUDGET,
    );

    expect(decision).toMatchObject({
      status: "HOLD",
      holdReason: "no-actionable-diagnosis",
    });
  });

  it("accepts capability mismatch only from an exact evidence-backed finding", () => {
    const assessment = developmentAssessment();
    const base = developmentAssessmentBody();
    const candidateProfileId = base.selectedPolicy.primaryProfileId;
    const exactFinding = {
      kind: "required-capability-mismatch" as const,
      protocolDigest: base.protocolDigest,
      profileId: candidateProfileId,
      capabilityId: "stream-cancellation",
      capabilityEvidenceDigest: digest("capability-evidence"),
    };
    const history: ExperimentHistoryInput = {
      ...EMPTY_HISTORY,
      findings: [
        {
          ...exactFinding,
          protocolDigest: digest("other-protocol"),
        },
        {
          ...exactFinding,
          profileId: "other-profile",
        },
        exactFinding,
      ],
    };
    const proposal = expectProposed(
      proposeExperiment(assessment, history, DEFAULT_BUDGET),
      "capability-mismatch",
    );

    expect(proposal.changedVariable).toEqual({
      kind: "required-capability",
      targetId: exactFinding.capabilityId,
      profileId: exactFinding.profileId,
    });
    expect(proposal.evidenceRequirements).toContainEqual({
      kind: "runtime-capability-evidence",
      protocolDigest: exactFinding.protocolDigest,
      profileId: exactFinding.profileId,
      capabilityId: exactFinding.capabilityId,
      evidenceDigest: exactFinding.capabilityEvidenceDigest,
    });
    expect(Object.keys(proposal.changedVariable)).toEqual([
      "kind",
      "targetId",
      "profileId",
    ]);
    if (proposal.changedVariable.kind !== "required-capability") {
      throw new Error("expected a profile-bound capability variable");
    }
    expect(proposal.evidenceRequirements[0]).toMatchObject({
      protocolDigest: proposal.parentProtocolDigest,
      profileId: proposal.changedVariable.profileId,
      capabilityId: proposal.changedVariable.targetId,
    });

    expect(() => parseExperimentProposalDecision(
      resignProposal(proposal, (body) => {
        body.evidenceRequirements[0].protocolDigest =
          digest("forged-protocol");
      }),
    )).toThrow(/protocol|parent|lineage|semantic/i);
    expect(() => parseExperimentProposalDecision(
      resignProposal(proposal, (body) => {
        body.evidenceRequirements[0].profileId = "forged-profile";
      }),
    )).toThrow(/profile|lineage|semantic/i);
    expect(() => parseExperimentProposalDecision(
      resignProposal(proposal, (body) => {
        body.changedVariable.profileId = "forged-profile";
      }),
    )).toThrow(/profile|lineage|semantic/i);

    const noExactFinding = proposeExperiment(assessment, {
      ...EMPTY_HISTORY,
      findings: history.findings.slice(0, 2),
    }, DEFAULT_BUDGET);
    expectProposed(noExactFinding, "sealed-shadow-replication");
  });

  it("normalizes history before selecting a capability finding", () => {
    const body = developmentAssessmentBody();
    const common = {
      kind: "required-capability-mismatch" as const,
      protocolDigest: body.protocolDigest,
      profileId: body.selectedPolicy.primaryProfileId,
      capabilityId: "streaming",
    };
    const findings = [
      {
        ...common,
        capabilityEvidenceDigest: digest("evidence-b"),
      },
      {
        ...common,
        capabilityEvidenceDigest: digest("evidence-a"),
      },
    ];
    const first = proposeExperiment(
      developmentAssessment(),
      { ...EMPTY_HISTORY, findings },
      DEFAULT_BUDGET,
    );
    const second = proposeExperiment(
      developmentAssessment(),
      { ...EMPTY_HISTORY, findings: [...findings].reverse() },
      DEFAULT_BUDGET,
    );

    expect(second).toEqual(first);
  });

  it("proposes disjoint sealed-shadow replication after a nomination", () => {
    const proposal = expectProposed(
      proposeExperiment(
        developmentAssessment(),
        EMPTY_HISTORY,
        DEFAULT_BUDGET,
      ),
      "sealed-shadow-replication",
    );

    expect(proposal.changedVariable).toEqual({
      kind: "evidence-window",
      targetId: "sealed-shadow-window",
    });
    expect(proposal.expectedDecision).toEqual({
      ifSupported: "REASSESS_WITH_REGISTERED_PROTOCOL",
      otherwise: "HOLD",
    });
    expect(proposal.authority).toBe("operator-registration-required");
    expect(proposal.attestation).toBe("unattested");
  });

  it("diagnoses only the selected policy when a nomination retains rejected candidates", () => {
    const proposal = expectProposed(
      proposeExperiment(
        developmentAssessment((body) => {
          const { otherCandidate } = policyFixtures();
          const unrelated = passingCandidate(otherCandidate);
          unrelated.status = "INSUFFICIENT_EVIDENCE";
          unrelated.inference = null;
          unrelated.insufficiencyReasons = [
            "insufficient-independent-groups",
          ];
          unrelated.rejectionReasons = [
            "insufficient-independent-groups",
          ];
          body.candidates.push(unrelated);
          body.candidates.sort((
            left: Record<string, any>,
            right: Record<string, any>,
          ) => left.policyDigest < right.policyDigest ? -1 : 1);
        }),
        EMPTY_HISTORY,
        DEFAULT_BUDGET,
      ),
      "sealed-shadow-replication",
    );

    expect(proposal.changedVariable.targetId).toBe(
      "sealed-shadow-window",
    );
  });

  it("always forbids proposal generation from holdout", () => {
    const decision = proposeExperiment(
      developmentAssessment((body) => {
        changePhase(body, "holdout", "HOLD");
      }),
      EMPTY_HISTORY,
      DEFAULT_BUDGET,
    );

    expect(decision).toMatchObject({
      status: "HOLD",
      holdReason: "holdout-tuning-forbidden",
      relatedProtocolDigest: null,
      authority: "operator-registration-required",
      attestation: "unattested",
    });
  });

  it("does not propose another experiment for an already passing window", () => {
    const decision = proposeExperiment(
      developmentAssessment((body) => {
        changePhase(body, "window", "PASS");
      }),
      EMPTY_HISTORY,
      DEFAULT_BUDGET,
    );

    expect(decision).toMatchObject({
      status: "HOLD",
      holdReason: "assessment-already-passing",
    });
  });

  it("holds on structural or mixed staleness without inspecting failed-policy diagnoses", () => {
    for (const reasons of [
      ["protocol-expired"],
      [
        "evaluator-evidence-stale",
        "execution-profile-drift",
      ],
    ]) {
      const decision = proposeExperiment(
        developmentAssessment((body) => {
          makeStale(body, reasons);
        }),
        EMPTY_HISTORY,
        DEFAULT_BUDGET,
      );
      expect(decision).toMatchObject({
        status: "HOLD",
        holdReason: "structural-staleness",
      });
    }
  });

  it("returns HOLD when a valid budget cannot fund one paired observation", () => {
    for (const budget of [
      { ...DEFAULT_BUDGET, maxLogicalExecutions: 1 },
      {
        ...DEFAULT_BUDGET,
        maxLogicalExecutions: 1,
        maxAttempts: 1,
      },
      { ...DEFAULT_BUDGET, maxWallClockMs: 0 },
    ]) {
      expect(proposeExperiment(
        developmentAssessment(),
        EMPTY_HISTORY,
        budget,
      )).toMatchObject({
        status: "HOLD",
        holdReason: "insufficient-proposal-budget",
      });
    }
  });

  it("rejects an intent already registered as a protocol", () => {
    const proposal = expectProposed(
      proposeExperiment(
        developmentAssessment(),
        EMPTY_HISTORY,
        DEFAULT_BUDGET,
      ),
      "sealed-shadow-replication",
    );
    const registeredProtocolDigest = digest("registered-protocol");
    const duplicate = proposeExperiment(
      developmentAssessment(),
      {
        ...EMPTY_HISTORY,
        registeredExperiments: [
          {
            parentProtocolDigest: proposal.parentProtocolDigest,
            experimentIntentDigest: proposal.experimentIntentDigest,
            registeredProtocolDigest,
            outcomeAssessmentDigest: null,
          },
        ],
      },
      DEFAULT_BUDGET,
    );

    expect(duplicate).toMatchObject({
      status: "HOLD",
      holdReason: "duplicate-registered-experiment",
      relatedProtocolDigest: registeredProtocolDigest,
    });
  });

  it("emits one bounded variable without judge, payload, or deployment authority", () => {
    const proposal = expectProposed(
      proposeExperiment(
        developmentAssessment((body) => {
          makeNoCandidate(body, ["maximum-p95-ttft"]);
        }),
        EMPTY_HISTORY,
        DEFAULT_BUDGET,
      ),
      "ttft-regression",
    );
    const serialized = JSON.stringify(proposal);
    const keys: string[] = [];
    const visit = (value: unknown): void => {
      if (value === null || typeof value !== "object") return;
      if (Array.isArray(value)) {
        value.forEach(visit);
        return;
      }
      for (const [key, child] of Object.entries(value)) {
        keys.push(key);
        visit(child);
      }
    };
    visit(proposal);

    expect(Object.keys(proposal.changedVariable)).toEqual([
      "kind",
      "targetId",
    ]);
    expect(proposal.evidenceRequirements.length).toBeGreaterThan(0);
    expect(proposal.evidenceRequirements.length).toBeLessThanOrEqual(8);
    expect(proposal.stopCondition).toEqual({
      kind: "first-budget-limit",
      budgetDigest: proposal.budget.budgetDigest,
    });
    expect(keys).not.toContain("score");
    expect(keys).not.toContain("prompt");
    expect(keys).not.toContain("output");
    expect(keys).not.toContain("endpoint");
    expect(keys).not.toContain("deploymentAction");
    expect(serialized.toLowerCase()).not.toContain("judge");
    expect(serialized.toLowerCase()).not.toContain("raw payload");
    expect(serialized.toLowerCase()).not.toContain("deploy this");
    expect(serialized.toLowerCase()).not.toContain("will improve");
  });

  it("rejects a tampered assessment even when it is not WeakSet-authentic", () => {
    const persisted = developmentAssessment();
    expect(() => proposeExperiment(
      {
        ...persisted,
        protocolDigest: digest("tampered"),
      },
      EMPTY_HISTORY,
      DEFAULT_BUDGET,
    )).toThrow(/digest/i);

    expect(() => proposeExperiment(
      persisted,
      { ...EMPTY_HISTORY, unexpected: true },
      DEFAULT_BUDGET,
    )).toThrow();
  });
});
