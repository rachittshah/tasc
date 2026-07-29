import { describe, expect, it } from "vitest";
import {
  fingerprintAssessmentDecisionContract,
  MAX_ASSESSMENT_DECISION_REPLAY_ROWS,
  parseAssessmentDecisionContract,
} from "../src/assessment-contract.js";
import { domainSeparatedDigest, fingerprintProtocol, parseExperimentProtocol } from "../src/evidence.js";
import { enumerateProtocolPolicyBundles, type PolicyBundle } from "../src/policy.js";
import { TEST_WORK_BUDGET, validProtocolInput } from "./fixtures/evidence.js";

const digest = (value: string): string => `sha256:${value.repeat(64)}`;

function policyFixtures(): {
  readonly control: PolicyBundle;
  readonly candidate: PolicyBundle;
} {
  const protocol = parseExperimentProtocol(
    validProtocolInput(),
    TEST_WORK_BUDGET,
  );
  const space = enumerateProtocolPolicyBundles(
    protocol,
    fingerprintProtocol(protocol),
    protocol.createdAt,
  );
  return {
    control: space.control,
    candidate: space.candidates[0],
  };
}

function metric(
  value: number | null,
  evidenceClass: "measured" | "reported" | "modeled" | "unavailable",
): Record<string, unknown> {
  return value === null
    ? { value, evidenceClass, reason: "fixture-unavailable" }
    : { value, evidenceClass };
}

function candidateAssessment(
  policy: PolicyBundle,
): Record<string, unknown> {
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

function developmentBody(): Record<string, any> {
  const { control, candidate } = policyFixtures();
  return {
    version: "tasc-assessment-decision-v2",
    engineVersion: "tasc-assessment-engine-v2",
    phase: "development",
    status: "NOMINATED",
    assessmentContextDigest: digest("a"),
    protocolDigest: candidate.protocolDigest,
    datasetDigest: digest("b"),
    traceSetDigest: digest("c"),
    evaluatorSetDigest: digest("d"),
    windowManifestDigest: null,
    estimator: {
      method: "paired-group-percentile-v1",
      alpha: 0.05,
      iterations: 1_000,
      seed: 42,
    },
    control: candidateAssessment(control),
    candidates: [candidateAssessment(candidate)],
    selectedPolicy: candidate,
    selectedPolicyDigest: candidate.policyDigest,
    staleReasons: [],
    warnings: [],
    unavailableMetrics: ["serviceCapacity"],
    attestation: "unattested",
  };
}

function seal(body: Record<string, unknown>): Record<string, unknown> {
  return {
    ...body,
    decisionDigest: domainSeparatedDigest(
      "tasc/assessment-decision/v2",
      body,
    ),
  };
}

function resign(
  mutate: (body: Record<string, any>) => void,
): Record<string, unknown> {
  const body = structuredClone(developmentBody());
  mutate(body);
  return seal(body);
}

describe("strict assessment-decision contract", () => {
  it("parses a phase-consistent decision, verifies its digest, and freezes it", () => {
    const body = developmentBody();
    const parsed = parseAssessmentDecisionContract(seal(body));

    expect(parsed.selectedPolicyDigest).toBe(
      body.selectedPolicy.policyDigest,
    );
    expect(parsed.decisionDigest).toBe(
      fingerprintAssessmentDecisionContract(body),
    );
    expect(Object.isFrozen(parsed)).toBe(true);
    expect(Object.isFrozen(parsed.candidates[0].coverage)).toBe(true);
    expect(Object.isFrozen(parsed.candidates[0].replay[0].slices)).toBe(true);
  });

  it("rejects unknown and missing fields at every decision layer", () => {
    const mutations: Array<(body: Record<string, any>) => void> = [
      (body) => {
        body.unexpected = true;
      },
      (body) => {
        delete body.estimator;
      },
      (body) => {
        body.estimator.unexpected = true;
      },
      (body) => {
        body.candidates[0].unexpected = true;
      },
      (body) => {
        body.candidates[0].metrics.meanScore.unexpected = true;
      },
      (body) => {
        body.candidates[0].gates[0].unexpected = true;
      },
      (body) => {
        body.candidates[0].replay[0].unexpected = true;
      },
      (body) => {
        body.candidates[0].inference.unexpected = true;
      },
      (body) => {
        body.candidates[0].coverage.unexpected = true;
      },
    ];

    for (const mutate of mutations) {
      expect(() => parseAssessmentDecisionContract(resign(mutate))).toThrow();
    }
  });

  it("rejects a self-consistent outer digest when a nested policy digest drifts", () => {
    expect(() => parseAssessmentDecisionContract(resign((body) => {
      body.candidates[0].policyDigest = digest("e");
    }))).toThrow(/policy digest/i);
  });

  it("requires development selection if and only if the outcome is NOMINATED", () => {
    expect(() => parseAssessmentDecisionContract(resign((body) => {
      body.selectedPolicy = null;
      body.selectedPolicyDigest = null;
    }))).toThrow(/NOMINATED/i);

    for (const status of [
      "NO_CANDIDATE",
      "INSUFFICIENT_EVIDENCE",
      "STALE",
    ]) {
      expect(() => parseAssessmentDecisionContract(resign((body) => {
        body.status = status;
        if (status === "STALE") body.staleReasons = ["protocol-expired"];
      }))).toThrow(/selection/i);
    }
  });

  it("requires the development nomination to select a passing candidate", () => {
    expect(() => parseAssessmentDecisionContract(resign((body) => {
      const candidate = body.candidates[0];
      candidate.status = "HOLD";
      candidate.gates[0].threshold = 0.95;
      candidate.gates[0].passed = false;
      candidate.rejectionReasons = ["failed-gate:minimum-mean-score"];
    }))).toThrow(/passing candidate/i);

    expect(() => parseAssessmentDecisionContract(resign((body) => {
      body.selectedPolicy = body.control.policy;
      body.selectedPolicyDigest = body.control.policyDigest;
    }))).toThrow(/candidate/i);
  });

  it("requires development aggregate status to exactly reflect candidate statuses", () => {
    const clearSelection = (body: Record<string, any>): void => {
      body.selectedPolicy = null;
      body.selectedPolicyDigest = null;
    };
    const makeHold = (candidate: Record<string, any>): void => {
      candidate.status = "HOLD";
      candidate.gates[0].threshold = 0.95;
      candidate.gates[0].passed = false;
      candidate.rejectionReasons = ["failed-gate:minimum-mean-score"];
    };
    const makeInsufficient = (candidate: Record<string, any>): void => {
      candidate.status = "INSUFFICIENT_EVIDENCE";
      candidate.inference = null;
      candidate.insufficiencyReasons = ["missing-route-signal"];
      candidate.rejectionReasons = ["missing-route-signal"];
    };

    for (const status of ["NO_CANDIDATE", "INSUFFICIENT_EVIDENCE"]) {
      expect(() => parseAssessmentDecisionContract(resign((body) => {
        body.status = status;
        clearSelection(body);
      }))).toThrow(/development.*candidate status|candidate status.*development/i);
    }

    expect(() => parseAssessmentDecisionContract(resign((body) => {
      body.status = "NO_CANDIDATE";
      clearSelection(body);
      makeInsufficient(body.candidates[0]);
    }))).toThrow(/NO_CANDIDATE.*HOLD|HOLD.*NO_CANDIDATE/i);

    expect(() => parseAssessmentDecisionContract(resign((body) => {
      body.status = "INSUFFICIENT_EVIDENCE";
      clearSelection(body);
      makeHold(body.candidates[0]);
    }))).toThrow(/INSUFFICIENT_EVIDENCE.*candidate|candidate.*INSUFFICIENT_EVIDENCE/i);

    expect(parseAssessmentDecisionContract(resign((body) => {
      body.status = "NO_CANDIDATE";
      clearSelection(body);
      makeHold(body.candidates[0]);
    })).status).toBe("NO_CANDIDATE");

    expect(parseAssessmentDecisionContract(resign((body) => {
      body.status = "INSUFFICIENT_EVIDENCE";
      clearSelection(body);
      makeInsufficient(body.candidates[0]);
    })).status).toBe("INSUFFICIENT_EVIDENCE");
  });

  it("requires terminal failure replay rows to retain score zero", () => {
    expect(() => parseAssessmentDecisionContract(resign((body) => {
      body.candidates[0].replay[0].status = "failure";
      body.candidates[0].replay[0].score = 0.25;
    }))).toThrow(/failure.*score zero|score zero.*failure/i);

    expect(() => parseAssessmentDecisionContract(resign((body) => {
      body.candidates[0].replay[0].status = "failure";
      body.candidates[0].replay[0].score = 0;
      body.candidates[0].replay[0].scoreEvidenceClass = "reported";
    }))).toThrow(/failure-zero.*modeled|modeled.*failure-zero/i);
  });

  it("binds mean-score provenance to the weakest replay score evidence", () => {
    expect(() => parseAssessmentDecisionContract(resign((body) => {
      body.candidates[0].replay[0].scoreEvidenceClass = "modeled";
    }))).toThrow(/mean-score provenance.*replay/i);
  });

  it("requires holdout and window phases to preserve exactly one frozen policy", () => {
    const holdout = resign((body) => {
      body.phase = "holdout";
      body.status = "PASS";
    });
    expect(parseAssessmentDecisionContract(holdout).phase).toBe("holdout");

    expect(() => parseAssessmentDecisionContract(resign((body) => {
      body.phase = "holdout";
      body.status = "PASS";
      body.candidates.push(structuredClone(body.candidates[0]));
    }))).toThrow(/exactly one candidate/i);

    expect(() => parseAssessmentDecisionContract(resign((body) => {
      body.phase = "holdout";
      body.status = "PASS";
      body.selectedPolicy = null;
      body.selectedPolicyDigest = null;
    }))).toThrow(/frozen policy/i);

    expect(() => parseAssessmentDecisionContract(resign((body) => {
      body.phase = "holdout";
      body.status = "HOLD";
    }))).toThrow(/candidate status/i);

    const window = parseAssessmentDecisionContract(resign((body) => {
      body.phase = "window";
      body.status = "PASS";
      body.windowManifestDigest = digest("f");
    }));
    expect(window.windowManifestDigest).toBe(digest("f"));
  });

  it("requires a window manifest digest only for window decisions", () => {
    expect(() => parseAssessmentDecisionContract(resign((body) => {
      body.phase = "window";
      body.status = "PASS";
    }))).toThrow(/window manifest digest/i);

    expect(() => parseAssessmentDecisionContract(resign((body) => {
      body.windowManifestDigest = digest("f");
    }))).toThrow(/window manifest digest/i);
  });

  it("requires estimator and inference parameters to agree exactly", () => {
    expect(() => parseAssessmentDecisionContract(resign((body) => {
      body.estimator.seed += 1;
    }))).toThrow(/estimator/i);
  });

  it("rejects internally impossible metrics, gates, inference, and coverage", () => {
    const mutations: Array<(body: Record<string, any>) => void> = [
      (body) => {
        body.candidates[0].metrics.meanScore.value = null;
      },
      (body) => {
        body.candidates[0].gates[0].passed = false;
      },
      (body) => {
        body.candidates[0].inference.interval = { lo: 0.2, hi: 0.1 };
      },
      (body) => {
        body.candidates[0].inference.positive = false;
      },
      (body) => {
        body.candidates[0].coverage.replicateCount = 0;
      },
      (body) => {
        body.candidates[0].coverage.criticalSliceGroups.push({
          sliceId: "payments",
          groupCount: 1,
        });
      },
    ];

    for (const mutate of mutations) {
      expect(() => parseAssessmentDecisionContract(resign(mutate))).toThrow();
    }
  });

  it("rejects candidate statuses and rejection lists that contradict gates or coverage", () => {
    expect(() => parseAssessmentDecisionContract(resign((body) => {
      const candidate = body.candidates[0];
      candidate.gates[0].threshold = 0.95;
      candidate.gates[0].passed = false;
      candidate.rejectionReasons = ["failed-gate:minimum-mean-score"];
    }))).toThrow(/PASS.*gate|status/i);

    expect(() => parseAssessmentDecisionContract(resign((body) => {
      const candidate = body.candidates[0];
      candidate.status = "INSUFFICIENT_EVIDENCE";
      candidate.insufficiencyReasons = ["missing-route-signal"];
      candidate.rejectionReasons = ["missing-route-signal"];
    }))).toThrow(/inference.*insufficient|insufficient.*inference/i);

    expect(() => parseAssessmentDecisionContract(resign((body) => {
      body.candidates[0].rejectionReasons = ["invented-reason"];
    }))).toThrow(/rejection/i);
  });

  it("requires top-level stale and unavailable summaries to match candidate content", () => {
    expect(() => parseAssessmentDecisionContract(resign((body) => {
      body.unavailableMetrics = [];
    }))).toThrow(/unavailable metric/i);

    expect(() => parseAssessmentDecisionContract(resign((body) => {
      body.status = "STALE";
      body.staleReasons = ["protocol-expired"];
      body.selectedPolicy = null;
      body.selectedPolicyDigest = null;
    }))).toThrow(/STALE candidate|candidate.*STALE/i);
  });

  it("checks the supplied decision digest after strict parsing", () => {
    const decision = seal(developmentBody());
    decision.decisionDigest = digest("0");
    expect(() => parseAssessmentDecisionContract(decision)).toThrow(
      /decision digest mismatch/i,
    );
  });

  it("rejects more than 10,000 candidates before reading candidate elements", () => {
    const decision = seal(developmentBody()) as Record<string, any>;
    const candidates = new Array(10_001);
    Object.defineProperty(candidates, "0", {
      enumerable: true,
      get(): never {
        throw new Error("candidate element getter was read");
      },
    });
    decision.candidates = candidates;

    expect(() => parseAssessmentDecisionContract(decision)).toThrow(
      /candidate.*10,000/i,
    );
  });

  it("rejects aggregate replay output beyond the fixed contract bound", () => {
    const decision = seal(developmentBody()) as Record<string, any>;
    const row = decision.control.replay[0];
    const firstCount =
      Math.floor(MAX_ASSESSMENT_DECISION_REPLAY_ROWS / 2) + 1;
    decision.control.replay = new Array(firstCount).fill(row);
    const overflowing = new Array(
      MAX_ASSESSMENT_DECISION_REPLAY_ROWS - firstCount + 1,
    );
    Object.defineProperty(overflowing, "0", {
      enumerable: true,
      get(): never {
        throw new Error("overflowing replay row getter was read");
      },
    });
    decision.candidates[0].replay = overflowing;

    expect(() => parseAssessmentDecisionContract(decision)).toThrow(
      /total replay limit/i,
    );
  });
});
