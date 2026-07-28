import { describe, expect, it } from "vitest";
import {
  assessPolicyWindow,
  confirmHoldout,
  isDevelopmentNomination,
  nominateDevelopment,
  parseAssessmentDecision,
  parsePolicyBundle,
  revalidateDevelopmentNomination,
  type FrozenDevelopmentNomination,
} from "../src/assessment.js";
import { parseAssessmentContext } from "../src/assessment-context.js";
import {
  assertPolicyBundleMatchesProtocol,
  enumerateProtocolPolicyBundles,
  fingerprintPolicyBundle,
} from "../src/policy.js";
import {
  fingerprintExecutionProfile,
  fingerprintProtocol,
  parseEvaluatorEvidence,
  parseExperimentProtocol,
  parseTraceEnvelope,
  type ExperimentProtocol,
  type TraceEnvelope,
} from "../src/evidence.js";
import {
  joinAssessmentEvidence,
  requireAssessmentDatasetSplit,
  resolveGroupSplit,
  type AssessmentDataset,
  type AssessmentDatasetForSplit,
} from "../src/evidence-join.js";
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
  validExecutionProfile,
  validProtocolInput,
  validTraceInputForProfile,
  type EvaluatorKeyFixture,
} from "./fixtures/evidence.js";

type Split = "dev" | "holdout" | "online";
type ProfileId = "champion" | "candidate";
type MutableProtocol = any;

const DISABLED_CAPACITY = {
  kind: "disabled" as const,
};

function protocolInput(
  change?: (value: MutableProtocol) => void,
): MutableProtocol {
  const value = validProtocolInput() as MutableProtocol;
  value.gates = {
    ...value.gates,
    minimumMeanScore: 0.5,
    nonInferiorityMargin: -0.1,
    maximumFailureRate: 0.5,
    maximumP95TtftMs: 10_000,
    maximumP95EndToEndMs: 20_000,
    maximumCostPerThousandRequestsUsd: 100,
    minimumEvidenceCoverage: 1,
    minimumIndependentGroups: 1,
    minimumCriticalSliceGroups: 0,
    serviceCapacity: DISABLED_CAPACITY,
  };
  value.criticalSlices = [];
  value.bootstrap.iterations = 32;
  value.candidatePolicySpace.maxCandidates = 4;
  value.onlineWindowMembership.sampleBasisPoints = 10_000;
  change?.(value);
  return value;
}

function protocol(
  change?: (value: MutableProtocol) => void,
): ExperimentProtocol {
  return parseExperimentProtocol(protocolInput(change), TEST_WORK_BUDGET);
}

function groupForSplit(
  value: ExperimentProtocol,
  split: Exclude<Split, "online">,
  suffix = "",
): string {
  for (let index = 0; index < 10_000; index += 1) {
    const groupId = `assessment-${split}-${suffix || "base"}-${index}`;
    if (resolveGroupSplit(value, groupId).split === split) return groupId;
  }
  throw new Error(`unable to find ${split} group fixture`);
}

function verificationFor(
  trace: ReturnType<typeof validTraceInputForProfile>,
  key: EvaluatorKeyFixture,
  context: ReturnType<typeof parseAssessmentContext>,
  score: number | "abstained",
  producedAt?: string,
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
  if (producedAt !== undefined) unsigned.producedAt = producedAt;
  (unsigned as any).outcome = score === "abstained"
    ? {
      kind: "abstained",
      reasonCode: "evaluator-could-not-determine",
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

interface DatasetOptions {
  split?: Split;
  caseCount?: number;
  routeSignal?: number | null;
  candidateScore?: number | "abstained";
  championScore?: number | "abstained";
  candidateFailure?: boolean;
  championFailure?: boolean;
  candidateAmbiguous?: boolean;
  championAmbiguous?: boolean;
  slices?: readonly string[];
  candidateCost?: number;
  championCost?: number;
  policyDigest?: string;
  windowId?: string;
  windowMembershipDigest?: string;
  trafficWeights?: readonly number[];
  groupIds?: readonly string[];
  candidateFailures?: readonly boolean[];
  candidateCosts?: readonly number[];
  candidateDurationsMs?: readonly number[];
  replicateCounts?: readonly number[];
  candidateCostUnavailable?: boolean;
  candidateMissingTtft?: boolean;
  evaluatorProducedAt?: string;
  contextAsOf?: string;
  traceStartedAt?: string;
}

function assessmentFixture<DatasetSplit extends Split = "dev">(
  frozenProtocol: ExperimentProtocol,
  options: Omit<DatasetOptions, "split"> & {
    split?: DatasetSplit;
  } = {},
): {
  context: ReturnType<typeof parseAssessmentContext>;
  dataset: AssessmentDatasetForSplit<DatasetSplit>;
  traces: readonly TraceEnvelope[];
} {
  const key = evaluatorKeyFixture();
  const trust = parseEvaluatorTrustSnapshot(key.trustSnapshot);
  const split = options.split ?? "dev";
  const contextInput = validAssessmentContextInput(trust);
  if (split === "online") {
    contextInput.asOf = "2026-07-24T00:00:00.000Z";
  }
  if (options.contextAsOf !== undefined) {
    contextInput.asOf = options.contextAsOf;
  }
  const context = parseAssessmentContext(contextInput);
  const traceInputs: ReturnType<typeof validTraceInputForProfile>[] = [];
  const verifications: EvaluatorEvidenceVerification[] = [];
  const protocolDigest = fingerprintProtocol(frozenProtocol);
  const caseCount = options.caseCount ?? 1;
  let terminalIdentity = 0;

  for (let index = 0; index < caseCount; index += 1) {
    const caseId = `assessment-case-${index}`;
    const groupId = options.groupIds?.[index] ?? (
      split === "online"
        ? `assessment-online-${index}`
        : groupForSplit(frozenProtocol, split, String(index))
    );
    const replicateCount = options.replicateCounts?.[index] ?? 1;
    for (
      let replicateIndex = 0;
      replicateIndex < replicateCount;
      replicateIndex += 1
    ) {
      for (const profileId of ["champion", "candidate"] as const) {
      const trace = validTraceInputForProfile(profileId) as any;
      trace.studyId = frozenProtocol.studyId;
      trace.protocolDigest = protocolDigest;
      trace.traceId =
        `trace-${caseId}-replicate-${replicateIndex}-${profileId}`;
      trace.caseId = caseId;
      trace.groupId = groupId;
      trace.replicateId = `replicate-${replicateIndex}`;
      trace.split = split;
      trace.workload.declaredTrafficWeight =
        options.trafficWeights?.[index] ?? 1;
      trace.slices = [...(options.slices ?? ["routine"])];
      trace.routeSignal = options.routeSignal === null
        ? null
        : {
          ...trace.routeSignal!,
          value: options.routeSignal ?? 0.9,
        };
      trace.policyDigest = options.policyDigest ?? trace.policyDigest;
      trace.terminalOutputId = {
        ...keyedIdentity(),
        value: terminalIdentity
          .toString(16)
          .padStart(64, "0"),
      };
      terminalIdentity += 1;
      if (split === "online") {
        trace.collectionWindowId = options.windowId ?? "window-1";
        trace.collectionWindowMembershipDigest =
          options.windowMembershipDigest ?? `sha256:${"d".repeat(64)}`;
        trace.sourceMode = "shadow";
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
      if (options.traceStartedAt !== undefined) {
        const start = Date.parse(options.traceStartedAt);
        trace.routeSignal.provenance.observedAt = new Date(start).toISOString();
        trace.attempts[0].observerTimings = {
          startedAt: new Date(start).toISOString(),
          headersAt: new Date(start + 50).toISOString(),
          firstByteAt: new Date(start + 60).toISOString(),
          firstMeaningfulTokenAt: new Date(start + 75).toISOString(),
          completedAt: new Date(start + 500).toISOString(),
        };
      }
      const cost = profileId === "candidate"
        ? (options.candidateCosts?.[index] ?? options.candidateCost)
        : options.championCost;
      if (cost !== undefined) trace.attempts[0].cost.amount = cost;
      if (profileId === "candidate" && options.candidateCostUnavailable) {
        trace.attempts[0].cost = {
          kind: "unavailable",
        };
      }
      if (profileId === "candidate" && options.candidateMissingTtft) {
        trace.attempts[0].observerTimings.firstMeaningfulTokenAt = null;
      }
      const shouldFail = profileId === "candidate"
        ? (
          options.candidateFailures?.[index]
          ?? options.candidateFailure
          ?? options.candidateAmbiguous
        )
        : (options.championFailure ?? options.championAmbiguous);
      const duration = profileId === "candidate"
        ? options.candidateDurationsMs?.[index]
        : undefined;
      if (duration !== undefined) {
        trace.attempts[0].observerTimings.completedAt = new Date(
          Date.parse(trace.attempts[0].observerTimings.startedAt) + duration,
        ).toISOString();
      }
      if (shouldFail) {
        const terminal = trace.attempts[trace.attempts.length - 1];
        terminal.status = "failure" as "success";
        terminal.finishReason = null as unknown as string;
        terminal.failureCategory = "runtime-error" as unknown as null;
        terminal.resolvedModel = null;
        terminal.partialOutput = false;
        trace.terminalOutputId = null;
      }
      const ambiguous = profileId === "candidate"
        ? options.candidateAmbiguous
        : options.championAmbiguous;
      if (ambiguous) {
        trace.attempts[trace.attempts.length - 1].dispatchState =
          "sent_unknown";
      }
      signDispatchIntent(trace);
      traceInputs.push(trace);
      if (!shouldFail) {
        verifications.push(verificationFor(
          trace,
          key,
          context,
          profileId === "candidate"
            ? (options.candidateScore ?? 0.9)
            : (options.championScore ?? 0.9),
          options.evaluatorProducedAt
            ?? (split === "online"
              ? "2026-07-23T00:02:00.000Z"
              : undefined),
        ));
      }
      }
    }
  }

  const traces = traceInputs.map((trace) =>
    parseTraceEnvelope(trace, TEST_WORK_BUDGET)
  );
  const dataset = joinAssessmentEvidence(
    frozenProtocol,
    traces,
    verifications,
    TEST_WORK_BUDGET,
  );
  return {
    context,
    traces,
    dataset: requireAssessmentDatasetSplit(
      dataset,
      split as DatasetSplit,
    ) as AssessmentDatasetForSplit<DatasetSplit>,
  };
}

function expectRecursivelyFrozen(value: unknown): void {
  if (value === null || typeof value !== "object") return;
  expect(Object.isFrozen(value)).toBe(true);
  for (const child of Object.values(value)) expectRecursivelyFrozen(child);
}

function requireNomination(
  decision: ReturnType<typeof nominateDevelopment>,
): FrozenDevelopmentNomination {
  if (!isDevelopmentNomination(decision)) {
    throw new Error(`expected development nomination, received ${decision.status}`);
  }
  return decision;
}

describe("evidence-v2 assessment phase boundaries", () => {
  it("has phase-safe arities and development alone enumerates the bounded declarative space", () => {
    expect(nominateDevelopment.length).toBe(4);
    expect(confirmHoldout.length).toBe(5);
    expect(assessPolicyWindow.length).toBe(6);

    const frozenProtocol = protocol();
    const { context, dataset } = assessmentFixture(frozenProtocol);
    const decision = nominateDevelopment(
      frozenProtocol,
      dataset,
      context,
      TEST_WORK_BUDGET,
    );

    expect(decision.status).toBe("NOMINATED");
    expect(decision.phase).toBe("development");
    expect(decision.control.policy.kind).toBe("expert-only");
    expect(decision.candidates.map(({ policy }) => policy.kind).sort()).toEqual([
      "cascade",
      "fast-only",
    ]);
    expect(decision.candidates).toHaveLength(2);
    expect(decision.estimator).toEqual({
      method: "paired-group-percentile-v1",
      alpha: frozenProtocol.bootstrap.alpha,
      iterations: frozenProtocol.bootstrap.iterations,
      seed: expect.any(Number),
    });
    expect(decision.candidates.every(({ coverage }) => (
      coverage.caseCount === 1
      && coverage.replicateCount === 1
      && coverage.groupCount === 1
      && coverage.missingEvidenceCount === 0
      && coverage.evidenceCoverage === 1
    ))).toBe(true);
    expect(decision.selectedPolicy).not.toBeNull();
    expect(decision.selectedPolicyDigest).toBe(
      fingerprintPolicyBundle(decision.selectedPolicy!),
    );
    expect(decision.candidates.every(({ policy }) =>
      policy.kind !== "cascade"
      || (
        policy.predicates.length === 1
        && policy.predicates[0].routeToProfileId === frozenProtocol.championProfileId
      )
    )).toBe(true);
  });

  it("rejects counterfeit joined data and assessment-context drift", () => {
    const frozenProtocol = protocol();
    const { context, dataset } = assessmentFixture(frozenProtocol);

    expect(() => nominateDevelopment(
      frozenProtocol,
      structuredClone(dataset),
      context,
      TEST_WORK_BUDGET,
    )).toThrow(/authentic.*assessment dataset/i);

    const {
      contextDigest: _contextDigest,
      ...contextWithoutDigest
    } = context;
    const driftedContext = parseAssessmentContext({
      ...contextWithoutDigest,
      asOf: "2026-07-23T00:00:00.000Z",
    });
    expect(nominateDevelopment(
      frozenProtocol,
      dataset,
      driftedContext,
      TEST_WORK_BUDGET,
    ).status).toBe("STALE");
  });

  it("keeps a missing route signal as cascade-specific insufficiency", () => {
    const frozenProtocol = protocol();
    const { context, dataset } = assessmentFixture(frozenProtocol, {
      routeSignal: null,
    });
    const decision = nominateDevelopment(
      frozenProtocol,
      dataset,
      context,
      TEST_WORK_BUDGET,
    );

    expect(decision.status).toBe("NOMINATED");
    expect(decision.candidates.find(({ policy }) => policy.kind === "fast-only"))
      .toMatchObject({ status: "PASS" });
    expect(decision.candidates.find(({ policy }) => policy.kind === "cascade"))
      .toMatchObject({
        status: "INSUFFICIENT_EVIDENCE",
        insufficiencyReasons: expect.arrayContaining(["missing-route-signal"]),
      });
  });

  it("replays primary failure as a conservative serial champion fallback", () => {
    const frozenProtocol = protocol();
    const { context, dataset } = assessmentFixture(frozenProtocol, {
      routeSignal: 0.9,
      candidateFailure: true,
      candidateCost: 0.01,
      championCost: 0.02,
    });
    const decision = nominateDevelopment(
      frozenProtocol,
      dataset,
      context,
      TEST_WORK_BUDGET,
    );
    const cascade = decision.candidates.find(
      ({ policy }) => policy.kind === "cascade",
    )!;

    expect(cascade.replay).toEqual([
      expect.objectContaining({
        attemptedProfileIds: ["candidate", "champion"],
        selectedProfileId: "champion",
        status: "success",
        escalated: true,
      }),
    ]);
    expect(cascade.metrics.failureRate.value).toBe(0);
    expect(cascade.metrics.costPerThousandRequestsUsd.value).toBeCloseTo(30);
    expect(cascade.metrics.endToEndLatencyMs.evidenceClass).toBe("modeled");
  });

  it("fails coverage before bootstrap for abstention and missing critical-slice groups", () => {
    const frozenProtocol = protocol((value) => {
      value.criticalSlices = ["payments"];
      value.gates.minimumCriticalSliceGroups = 1;
    });
    const { context, dataset } = assessmentFixture(frozenProtocol, {
      candidateScore: "abstained",
      slices: ["routine"],
    });
    const decision = nominateDevelopment(
      frozenProtocol,
      dataset,
      context,
      TEST_WORK_BUDGET,
    );

    expect(decision.status).toBe("INSUFFICIENT_EVIDENCE");
    expect(decision.candidates.every(({ inference }) => inference === null))
      .toBe(true);
    expect(decision.candidates.flatMap(({ insufficiencyReasons }) =>
      insufficiencyReasons
    )).toEqual(expect.arrayContaining([
      "evaluator-abstention",
      "insufficient-critical-slice-groups:payments",
    ]));
  });

  it("uses paired quality and distinguishes hard-gate rejection from insufficiency", () => {
    const frozenProtocol = protocol((value) => {
      value.gates.nonInferiorityMargin = -0.01;
      value.gates.minimumMeanScore = 0.8;
    });
    const { context, dataset } = assessmentFixture(frozenProtocol, {
      candidateScore: 0.5,
      championScore: 0.95,
    });
    const decision = nominateDevelopment(
      frozenProtocol,
      dataset,
      context,
      TEST_WORK_BUDGET,
    );

    expect(decision.status).toBe("NO_CANDIDATE");
    expect(decision.candidates.every(({ status }) => status === "HOLD"))
      .toBe(true);
    expect(decision.candidates.every(({ inference }) =>
      inference?.method === "paired-group-percentile-v1"
    )).toBe(true);
    expect(decision.candidates.some(({ gates }) =>
      gates.some(({ id, passed }) => id === "paired-quality" && !passed)
    )).toBe(true);
  });

  it("defers an enabled capacity gate until an exact sealed policy window", () => {
    const frozenProtocol = protocol((value) => {
      value.gates.serviceCapacity = {
        kind: "minimum-measured-window-throughput",
        metric: "aggregate-output-tokens-per-second",
        minimum: 100,
      };
    });
    const { context, dataset } = assessmentFixture(frozenProtocol);
    const decision = nominateDevelopment(
      frozenProtocol,
      dataset,
      context,
      TEST_WORK_BUDGET,
    );

    expect(decision.status).toBe("NOMINATED");
    expect(decision.candidates.every(({ metrics }) =>
      metrics.serviceCapacity.evidenceClass === "unavailable"
    )).toBe(true);
    expect(decision.candidates.every(({ insufficiencyReasons }) =>
      !insufficiencyReasons.includes("required-service-capacity-unavailable")
    )).toBe(true);
    expect(decision.warnings).toContain(
      "service-capacity-gate-deferred-to-sealed-window",
    );
  });

  it("gates paired candidate-control evidence coverage before inference", () => {
    const frozenProtocol = protocol();
    const { context, dataset } = assessmentFixture(frozenProtocol, {
      candidateScore: 0.9,
      championScore: "abstained",
    });
    const decision = nominateDevelopment(
      frozenProtocol,
      dataset,
      context,
      TEST_WORK_BUDGET,
    );

    expect(decision.status).toBe("INSUFFICIENT_EVIDENCE");
    expect(decision.candidates.every(({ coverage, inference, metrics }) => (
      coverage.evidenceCoverage === 0.5
      && coverage.missingEvidenceCount === 1
      && metrics.evidenceCoverage.value === 0.5
      && inference === null
    ))).toBe(true);
  });

  it("treats paired terminal failures as known score-zero outcomes, not missing evidence", () => {
    const frozenProtocol = protocol();
    const { context, dataset } = assessmentFixture(frozenProtocol, {
      candidateFailure: true,
      championFailure: true,
    });
    const decision = nominateDevelopment(
      frozenProtocol,
      dataset,
      context,
      TEST_WORK_BUDGET,
    );

    expect(decision.status).toBe("NO_CANDIDATE");
    expect(decision.candidates.every(({ status, coverage, inference, metrics }) => (
      status === "HOLD"
      && coverage.evidenceCoverage === 1
      && coverage.missingEvidenceCount === 0
      && inference?.estimate === 0
      && metrics.failureRate.value === 1
      && metrics.meanScore.evidenceClass === "modeled"
    ))).toBe(true);
  });

  it("treats sent-unknown execution outcomes as unavailable before inference", () => {
    const frozenProtocol = protocol();
    const { context, dataset } = assessmentFixture(frozenProtocol, {
      championAmbiguous: true,
    });
    expect(dataset.executions.find(
      ({ profileId }) => profileId === "champion",
    )?.outcome.kind).toBe("ambiguous-execution");

    const decision = nominateDevelopment(
      frozenProtocol,
      dataset,
      context,
      TEST_WORK_BUDGET,
    );

    expect(decision.status).toBe("INSUFFICIENT_EVIDENCE");
    expect(decision.candidates.every(({ coverage, inference }) =>
      coverage.missingEvidenceCount === 1
      && coverage.evidenceCoverage === 0.5
      && inference === null
    )).toBe(true);
    expect(decision.control.metrics.meanScore.evidenceClass).toBe(
      "unavailable",
    );
    expect(decision.candidates.flatMap(
      ({ insufficiencyReasons }) => insufficiencyReasons,
    )).toContain("ambiguous-execution");
  });

  it("treats unavailable required cost as insufficiency and missing TTFT as modeled", () => {
    const frozenProtocol = protocol();
    const missingCost = assessmentFixture(frozenProtocol, {
      candidateCostUnavailable: true,
    });
    const costDecision = nominateDevelopment(
      frozenProtocol,
      missingCost.dataset,
      missingCost.context,
      TEST_WORK_BUDGET,
    );
    const fastWithMissingCost = costDecision.candidates.find(
      ({ policy }) => policy.kind === "fast-only",
    )!;
    expect(fastWithMissingCost.status).toBe("INSUFFICIENT_EVIDENCE");
    expect(fastWithMissingCost.insufficiencyReasons).toContain(
      "required-cost-evidence-unavailable",
    );

    const missingTtft = assessmentFixture(frozenProtocol, {
      candidateMissingTtft: true,
    });
    const ttftDecision = nominateDevelopment(
      frozenProtocol,
      missingTtft.dataset,
      missingTtft.context,
      TEST_WORK_BUDGET,
    );
    expect(ttftDecision.candidates.find(
      ({ policy }) => policy.kind === "fast-only",
    )!.metrics.ttftMs.evidenceClass).toBe("modeled");
  });

  it("gives stale identity and expiry precedence over coverage and candidate outcomes", () => {
    const frozenProtocol = protocol((value) => {
      value.expiresAt = "2026-07-21T23:59:59.999Z";
    });
    const { context, dataset } = assessmentFixture(frozenProtocol, {
      candidateScore: "abstained",
    });
    const decision = nominateDevelopment(
      frozenProtocol,
      dataset,
      context,
      TEST_WORK_BUDGET,
    );

    expect(decision.status).toBe("STALE");
    expect(decision.staleReasons).toContain("protocol-expired");
    expect(decision.selectedPolicy).toBeNull();
  });

  it("classifies authentic stale evaluator receipts and pre-protocol assessment as STALE", () => {
    const frozenProtocol = protocol();
    const staleEvidence = assessmentFixture(frozenProtocol, {
      evaluatorProducedAt: "2026-07-01T00:00:00.000Z",
    });
    const staleDecision = nominateDevelopment(
      frozenProtocol,
      staleEvidence.dataset,
      staleEvidence.context,
      TEST_WORK_BUDGET,
    );
    expect(staleDecision.status).toBe("STALE");
    expect(staleDecision.staleReasons).toContain("evaluator-evidence-stale");

    const normal = assessmentFixture(frozenProtocol);
    const {
      contextDigest: _contextDigest,
      ...contextBody
    } = normal.context;
    const beforeProtocol = parseAssessmentContext({
      ...contextBody,
      asOf: "2026-07-19T23:59:59.999Z",
    });
    const beforeDecision = nominateDevelopment(
      frozenProtocol,
      normal.dataset,
      beforeProtocol,
      TEST_WORK_BUDGET,
    );
    expect(beforeDecision.status).toBe("STALE");
    expect(beforeDecision.staleReasons).toContain("protocol-not-yet-valid");
    expect(() => enumerateProtocolPolicyBundles(
      frozenProtocol,
      fingerprintProtocol(frozenProtocol),
      beforeProtocol.asOf,
    )).toThrow(/issue time.*validity interval/i);
  });

  it("freezes assessment time across traces, evaluator production, and policies", () => {
    const frozenProtocol = protocol();
    const futureFailures = assessmentFixture(frozenProtocol, {
      candidateFailure: true,
      championFailure: true,
      traceStartedAt: "2026-07-23T00:00:00.000Z",
    });
    const futureTraceDecision = nominateDevelopment(
      frozenProtocol,
      futureFailures.dataset,
      futureFailures.context,
      TEST_WORK_BUDGET,
    );
    expect(futureTraceDecision.status).toBe("STALE");
    expect(futureTraceDecision.staleReasons).toContain(
      "trace-completed-after-assessment-cutoff",
    );

    const futureEvidence = assessmentFixture(frozenProtocol, {
      evaluatorProducedAt: "2026-07-22T00:00:15.000Z",
    });
    const futureEvidenceDecision = nominateDevelopment(
      frozenProtocol,
      futureEvidence.dataset,
      futureEvidence.context,
      TEST_WORK_BUDGET,
    );
    expect(futureEvidenceDecision.status).toBe("STALE");
    expect(futureEvidenceDecision.staleReasons).toContain(
      "evaluator-evidence-produced-after-assessment-cutoff",
    );

    const development = assessmentFixture(frozenProtocol);
    const nomination = requireNomination(nominateDevelopment(
      frozenProtocol,
      development.dataset,
      development.context,
      TEST_WORK_BUDGET,
    ));
    const holdout = assessmentFixture(frozenProtocol, {
      split: "holdout",
      contextAsOf: "2026-07-21T13:00:00.000Z",
    });
    const prematureConfirmation = confirmHoldout(
      frozenProtocol,
      holdout.dataset,
      nomination,
      holdout.context,
      TEST_WORK_BUDGET,
    );
    expect(prematureConfirmation.status).toBe("STALE");
    expect(prematureConfirmation.staleReasons).toContain(
      "policy-not-yet-valid",
    );
  });

  it("binds every source/context/policy digest and recursively freezes decisions", () => {
    const frozenProtocol = protocol();
    const { context, dataset } = assessmentFixture(frozenProtocol);
    const decision = nominateDevelopment(
      frozenProtocol,
      dataset,
      context,
      TEST_WORK_BUDGET,
    );

    expect(decision).toMatchObject({
      assessmentContextDigest: context.contextDigest,
      protocolDigest: dataset.protocolDigest,
      datasetDigest: dataset.datasetDigest,
      traceSetDigest: dataset.traceSetDigest,
      evaluatorSetDigest: dataset.evaluatorSetDigest,
      selectedPolicyDigest: expect.stringMatching(/^sha256:/),
      decisionDigest: expect.stringMatching(/^sha256:/),
    });
    expect(decision.candidates.every(({ policyDigest, metrics, gates }) =>
      policyDigest === fingerprintPolicyBundle(
        decision.candidates.find((candidate) =>
          candidate.policyDigest === policyDigest
        )!.policy,
      )
      && Object.values(metrics).every(({ evidenceClass }) =>
        ["measured", "reported", "modeled", "unavailable"].includes(
          evidenceClass,
        )
      )
      && gates.every(({ evidenceClass }) =>
        ["measured", "reported", "modeled", "unavailable"].includes(
          evidenceClass,
        )
      )
    )).toBe(true);
    expectRecursivelyFrozen(decision);
  });

  it("holds out exactly one authentic nomination and preserves a rejected frozen policy", () => {
    const frozenProtocol = protocol();
    const development = assessmentFixture(frozenProtocol, {
      candidateScore: 0.95,
      championScore: 0.9,
    });
    const nomination = requireNomination(nominateDevelopment(
      frozenProtocol,
      development.dataset,
      development.context,
      TEST_WORK_BUDGET,
    ));

    const holdout = assessmentFixture(frozenProtocol, {
      split: "holdout",
      candidateScore: 0.1,
      championScore: 0.95,
    });
    const confirmation = confirmHoldout(
      frozenProtocol,
      holdout.dataset,
      nomination,
      holdout.context,
      TEST_WORK_BUDGET,
    );

    expect(confirmation.phase).toBe("holdout");
    expect(confirmation.status).toBe("HOLD");
    expect(confirmation.candidates).toHaveLength(1);
    expect(confirmation.selectedPolicy).toEqual(nomination.selectedPolicy);
    expect(confirmation.selectedPolicyDigest).toBe(
      nomination.selectedPolicyDigest,
    );
  });

  it("rejects split reuse and a forged nomination", () => {
    const frozenProtocol = protocol();
    const development = assessmentFixture(frozenProtocol);
    const nomination = requireNomination(nominateDevelopment(
      frozenProtocol,
      development.dataset,
      development.context,
      TEST_WORK_BUDGET,
    ));

    expect(() => confirmHoldout(
      frozenProtocol,
      development.dataset as never,
      nomination,
      development.context,
      TEST_WORK_BUDGET,
    )).toThrow(/holdout.*only|split/i);
    expect(() => confirmHoldout(
      frozenProtocol,
      assessmentFixture(frozenProtocol, { split: "holdout" }).dataset,
      structuredClone(nomination) as FrozenDevelopmentNomination,
      development.context,
      TEST_WORK_BUDGET,
    )).toThrow(/authentic.*nomination/i);
  });

  it("strictly parses persisted decisions and revalidates nominations from source evidence", () => {
    const frozenProtocol = protocol();
    const development = assessmentFixture(frozenProtocol);
    const nomination = requireNomination(nominateDevelopment(
      frozenProtocol,
      development.dataset,
      development.context,
      TEST_WORK_BUDGET,
    ));
    const persisted = JSON.parse(JSON.stringify(nomination));
    const parsed = parseAssessmentDecision(persisted);

    expect(parsed).toEqual(nomination);
    expect(isDevelopmentNomination(parsed)).toBe(false);
    const revalidated = revalidateDevelopmentNomination(
      frozenProtocol,
      development.dataset,
      persisted,
      development.context,
      TEST_WORK_BUDGET,
    );
    expect(revalidated.decisionDigest).toBe(nomination.decisionDigest);
    expect(isDevelopmentNomination(revalidated)).toBe(true);

    const otherDevelopment = assessmentFixture(frozenProtocol, {
      candidateScore: 0.8,
    });
    expect(() => revalidateDevelopmentNomination(
      frozenProtocol,
      development.dataset,
      nominateDevelopment(
        frozenProtocol,
        otherDevelopment.dataset,
        otherDevelopment.context,
        TEST_WORK_BUDGET,
      ),
      development.context,
      TEST_WORK_BUDGET,
    )).toThrow(/does not match recomputed/i);
  });

  it("parses a frozen policy only when its self-digest is exact", () => {
    const frozenProtocol = protocol();
    const { context, dataset } = assessmentFixture(frozenProtocol);
    const nomination = nominateDevelopment(
      frozenProtocol,
      dataset,
      context,
      TEST_WORK_BUDGET,
    );
    const policy = nomination.selectedPolicy!;

    expect(parsePolicyBundle(policy)).toEqual(policy);
    expect(() => parsePolicyBundle({
      ...policy,
      policyDigest: `sha256:${"0".repeat(64)}`,
    })).toThrow(/policy digest/i);

    const cascade = nomination.candidates.find(
      ({ policy: candidate }) => candidate.kind === "cascade",
    )!.policy;
    const forgedBody = {
      ...cascade,
      predicates: [{
        ...cascade.predicates[0],
        threshold: cascade.predicates[0].threshold + 0.01,
      }],
    };
    const forged = parsePolicyBundle({
      ...forgedBody,
      policyDigest: fingerprintPolicyBundle(forgedBody),
    });
    expect(() => assertPolicyBundleMatchesProtocol(
      forged,
      frozenProtocol,
    )).toThrow(/predicate.*protocol|protocol.*predicate/i);
  });

  it("rejects wrong phases and preflights caller work before assessment expansion", () => {
    const frozenProtocol = protocol();
    const development = assessmentFixture(frozenProtocol);
    const holdout = assessmentFixture(frozenProtocol, { split: "holdout" });

    expect(() => nominateDevelopment(
      frozenProtocol,
      holdout.dataset as never,
      holdout.context,
      TEST_WORK_BUDGET,
    )).toThrow(/development.*dev split|dev split.*only/i);
    expect(() => nominateDevelopment(
      frozenProtocol,
      development.dataset,
      development.context,
      { ...TEST_WORK_BUDGET, maxCandidates: 1 },
    )).toThrow(/candidate count.*work budget/i);
    expect(() => nominateDevelopment(
      frozenProtocol,
      development.dataset,
      development.context,
      { ...TEST_WORK_BUDGET, maxAssessmentWork: 100 },
    )).toThrow(/assessment work.*work budget/i);
    expect(() => nominateDevelopment(
      frozenProtocol,
      development.dataset,
      development.context,
      { ...TEST_WORK_BUDGET, maxAssessmentWork: 0 },
    )).toThrow(/assessment work.*work budget/i);
  });

  it("rejects globally ambiguous joined evidence before replay", () => {
    const frozenProtocol = protocol();
    const development = assessmentFixture(frozenProtocol);
    const ambiguous = joinAssessmentEvidence(
      frozenProtocol,
      [...development.traces, development.traces[0]],
      [],
      TEST_WORK_BUDGET,
    );
    expect(ambiguous.admissibility.blockingReasons).toContain(
      "duplicate-traces",
    );
    expect(() => nominateDevelopment(
      frozenProtocol,
      requireAssessmentDatasetSplit(ambiguous, "dev"),
      development.context,
      TEST_WORK_BUDGET,
    )).toThrow(/structural integrity.*duplicate-traces/i);
  });

  it("classifies authentic cross-protocol evidence as stale and rejects forged bundle lineage", () => {
    const original = protocol();
    const { context, dataset } = assessmentFixture(original);
    const changed = protocol((value) => {
      value.owner = "different-operator";
    });
    const stale = nominateDevelopment(
      changed,
      dataset,
      context,
      TEST_WORK_BUDGET,
    );
    expect(stale.status).toBe("STALE");
    expect(stale.staleReasons).toContain("protocol-or-study-drift");

    expect(() => enumerateProtocolPolicyBundles(
      original,
      `sha256:${"f".repeat(64)}`,
      context.asOf,
    )).toThrow(/protocol digest/i);
  });

  it("weights operational metrics by case traffic rather than row count", () => {
    const frozenProtocol = protocol((value) => {
      value.gates.maximumFailureRate = 1;
      value.gates.minimumMeanScore = 0;
    });
    const { context, dataset } = assessmentFixture(frozenProtocol, {
      caseCount: 2,
      trafficWeights: [9, 1],
      candidateFailures: [true, false],
      candidateCosts: [0.01, 0.001],
      candidateDurationsMs: [1_000, 100],
    });
    const decision = nominateDevelopment(
      frozenProtocol,
      requireAssessmentDatasetSplit(dataset, "dev"),
      context,
      TEST_WORK_BUDGET,
    );
    const fast = decision.candidates.find(
      ({ policy }) => policy.kind === "fast-only",
    )!;

    expect(fast.metrics.failureRate.value).toBeCloseTo(0.9);
    expect(fast.metrics.costPerThousandRequestsUsd.value).toBeCloseTo(9.1);
    expect(fast.metrics.endToEndLatencyMs.value).toBe(1_000);
  });

  it("keeps case traffic mass invariant when a case has more replicates", () => {
    const frozenProtocol = protocol((value) => {
      value.gates.maximumFailureRate = 1;
      value.gates.minimumMeanScore = 0;
    });
    const options = {
      caseCount: 2,
      trafficWeights: [9, 1],
      candidateFailures: [true, false],
      candidateCosts: [0.01, 0.001],
      candidateDurationsMs: [1_000, 100],
    } as const;
    const once = assessmentFixture(frozenProtocol, {
      ...options,
      replicateCounts: [1, 1],
    });
    const repeated = assessmentFixture(frozenProtocol, {
      ...options,
      replicateCounts: [3, 1],
    });
    const onceFast = nominateDevelopment(
      frozenProtocol,
      once.dataset,
      once.context,
      TEST_WORK_BUDGET,
    ).candidates.find(({ policy }) => policy.kind === "fast-only")!;
    const repeatedFast = nominateDevelopment(
      frozenProtocol,
      repeated.dataset,
      repeated.context,
      TEST_WORK_BUDGET,
    ).candidates.find(({ policy }) => policy.kind === "fast-only")!;

    expect(onceFast.replay).toHaveLength(2);
    expect(repeatedFast.replay).toHaveLength(4);
    expect(repeatedFast.metrics).toEqual(onceFast.metrics);
    expect(repeatedFast.inference?.estimate).toBe(onceFast.inference?.estimate);
  });

  it("reports the exact bootstrap traffic mass for fractional weights across groups", () => {
    const frozenProtocol = protocol((value) => {
      value.gates.minimumIndependentGroups = 3;
    });
    const groupIds = ["z", "m", "a"].map((suffix) =>
      groupForSplit(frozenProtocol, "dev", `fractional-${suffix}`)
    );
    const { context, dataset } = assessmentFixture(frozenProtocol, {
      caseCount: 3,
      trafficWeights: [0.1, 0.2, 0.3],
      groupIds,
    });

    const fast = nominateDevelopment(
      frozenProtocol,
      dataset,
      context,
      TEST_WORK_BUDGET,
    ).candidates.find(({ policy }) => policy.kind === "fast-only")!;

    expect(fast.inference).not.toBeNull();
    expect(fast.coverage.effectiveTrafficMass).toBe(
      fast.inference!.effectiveTrafficMass,
    );
    expect(fast.coverage.effectiveTrafficMass).toBe(0.6);
  });

  it("does not let one unrelated candidate's abstention poison valid policies", () => {
    const frozenProtocol = protocol((value) => {
      value.profiles.push(validExecutionProfile("candidate-b"));
      value.candidateProfileIds.push("candidate-b");
      value.candidatePolicySpace.maxCandidates = 4;
    });
    const key = evaluatorKeyFixture();
    const trust = parseEvaluatorTrustSnapshot(key.trustSnapshot);
    const context = parseAssessmentContext(validAssessmentContextInput(trust));
    const protocolDigest = fingerprintProtocol(frozenProtocol);
    const groupId = groupForSplit(frozenProtocol, "dev", "candidate-isolation");
    const rawTraces: any[] = [];
    const receipts: EvaluatorEvidenceVerification[] = [];
    for (const [index, profileId] of [
      "champion",
      "candidate",
      "candidate-b",
    ].entries()) {
      const trace = validTraceInputForProfile(
        profileId === "champion" ? "champion" : "candidate",
      ) as any;
      const profile = frozenProtocol.profiles.find(
        ({ id }) => id === profileId,
      )!;
      trace.studyId = frozenProtocol.studyId;
      trace.protocolDigest = protocolDigest;
      trace.traceId = `trace-candidate-isolation-${profileId}`;
      trace.caseId = "candidate-isolation";
      trace.groupId = groupId;
      trace.profileId = profileId;
      trace.executionProfileDigest = fingerprintExecutionProfile(profile);
      trace.observedRoute.selectedProfileId = profileId;
      trace.attempts[0].requestedModel = { ...profile.model };
      trace.attempts[0].resolvedModel = {
        ...profile.model,
        source: "provider-reported",
      };
      trace.terminalOutputId = {
        ...keyedIdentity(),
        value: index.toString(16).padStart(64, "0"),
      };
      signDispatchIntent(trace);
      rawTraces.push(trace);
      receipts.push(verificationFor(
        trace,
        key,
        context,
        profileId === "candidate-b" ? "abstained" : 0.9,
      ));
    }
    const dataset = joinAssessmentEvidence(
      frozenProtocol,
      rawTraces.map((trace) =>
        parseTraceEnvelope(trace, TEST_WORK_BUDGET)
      ),
      receipts,
      TEST_WORK_BUDGET,
    );
    const decision = nominateDevelopment(
      frozenProtocol,
      requireAssessmentDatasetSplit(dataset, "dev"),
      context,
      TEST_WORK_BUDGET,
    );

    expect(decision.status).toBe("NOMINATED");
    expect(decision.candidates.filter(
      ({ policy }) => policy.primaryProfileId === "candidate",
    ).every(({ status }) => status === "PASS")).toBe(true);
    expect(decision.candidates.filter(
      ({ policy }) => policy.primaryProfileId === "candidate-b",
    ).every(({ status }) => status === "INSUFFICIENT_EVIDENCE")).toBe(true);
  });
});

// Window integration is exercised here as well as in window.test.ts so that the
// assessment boundary, rather than only manifest parsing, owns exact-policy replay.
describe("sealed online policy assessment", () => {
  const membershipRule = {
    algorithm:
      "tasc-seeded-sha256-case-replicate-basis-points-v1" as const,
    seed: "support-routing-shadow-2",
    sampleBasisPoints: 10_000,
  };

  function baseManifest(
    protocolDigest: string,
    frozenPolicyDigest: string,
    dataset: AssessmentDataset,
    capacityEvidence: Record<string, unknown> = {
      kind: "unavailable",
      reasonCode: "not-collected",
    },
  ): WindowManifest {
    const content = {
      version: "tasc-window-manifest-v2" as const,
      windowId: "window-1",
      protocolDigest,
      frozenPolicyDigest,
      eventTimeStartInclusive: "2026-07-23T00:00:00.000Z",
      eventTimeEndExclusive: "2026-07-23T00:01:00.000Z",
      ingestionWatermark: "2026-07-23T00:02:00.000Z",
      closureReason: "scheduled",
      membershipRule,
      membershipDigest: dataset.executions[0].trace
        .collectionWindowMembershipDigest!,
      revision: 1,
      predecessorManifestDigest: null,
      traceSetDigest: dataset.traceSetDigest,
      evaluatorSetDigest: dataset.evaluatorSetDigest,
      capacityEvidence,
    };
    return parseWindowManifest({
      ...content,
      selfDigest: fingerprintWindowManifest(content),
    });
  }

  it("replays exactly one frozen policy and retains it on HOLD", () => {
    const frozenProtocol = protocol();
    const development = assessmentFixture(frozenProtocol);
    const nomination = nominateDevelopment(
      frozenProtocol,
      development.dataset,
      development.context,
      TEST_WORK_BUDGET,
    );
    const policy = nomination.selectedPolicy!;
    const membershipDigest = deriveWindowMembershipDigest(
      "window-1",
      fingerprintProtocol(frozenProtocol),
      membershipRule,
    );
    const online = assessmentFixture(frozenProtocol, {
      split: "online",
      policyDigest: policy.policyDigest,
      windowId: "window-1",
      windowMembershipDigest: membershipDigest,
      candidateScore: 0.1,
      championScore: 0.95,
    });
    const manifest = baseManifest(
      fingerprintProtocol(frozenProtocol),
      policy.policyDigest,
      online.dataset,
    );
    const decision = assessPolicyWindow(
      frozenProtocol,
      online.dataset,
      policy,
      manifest,
      online.context,
      TEST_WORK_BUDGET,
    );

    expect(decision.phase).toBe("window");
    expect(decision.status).toBe("HOLD");
    expect(decision.candidates).toHaveLength(1);
    expect(decision.selectedPolicy).toEqual(policy);
  });

  it("does not assess an online window before its sealed watermark exists", () => {
    const frozenProtocol = protocol();
    const development = assessmentFixture(frozenProtocol);
    const policy = requireNomination(nominateDevelopment(
      frozenProtocol,
      development.dataset,
      development.context,
      TEST_WORK_BUDGET,
    )).selectedPolicy;
    const membershipDigest = deriveWindowMembershipDigest(
      "window-1",
      fingerprintProtocol(frozenProtocol),
      membershipRule,
    );
    const online = assessmentFixture(frozenProtocol, {
      split: "online",
      policyDigest: policy.policyDigest,
      windowId: "window-1",
      windowMembershipDigest: membershipDigest,
      candidateFailure: true,
      championFailure: true,
      contextAsOf: "2026-07-23T00:01:30.000Z",
    });
    const manifest = baseManifest(
      fingerprintProtocol(frozenProtocol),
      policy.policyDigest,
      online.dataset,
    );

    const decision = assessPolicyWindow(
      frozenProtocol,
      online.dataset,
      policy,
      manifest,
      online.context,
      TEST_WORK_BUDGET,
    );

    expect(decision.status).toBe("STALE");
    expect(decision.staleReasons).toContain(
      "window-not-yet-sealed-at-assessment-time",
    );
  });

  it("fails closed on manifest source drift and creates immutable linked revisions", () => {
    const frozenProtocol = protocol();
    const development = assessmentFixture(frozenProtocol);
    const nomination = nominateDevelopment(
      frozenProtocol,
      development.dataset,
      development.context,
      TEST_WORK_BUDGET,
    );
    const policy = nomination.selectedPolicy!;
    const membershipDigest = deriveWindowMembershipDigest(
      "window-1",
      fingerprintProtocol(frozenProtocol),
      membershipRule,
    );
    const online = assessmentFixture(frozenProtocol, {
      split: "online",
      policyDigest: policy.policyDigest,
      windowId: "window-1",
      windowMembershipDigest: membershipDigest,
    });
    const manifest = baseManifest(
      fingerprintProtocol(frozenProtocol),
      policy.policyDigest,
      online.dataset,
    );
    const revision = createWindowManifestRevision(manifest, {
      ingestionWatermark: "2026-07-23T00:03:00.000Z",
      closureReason: "late-evidence",
      traceSetDigest: `sha256:${"e".repeat(64)}`,
      evaluatorSetDigest: online.dataset.evaluatorSetDigest,
      capacityEvidence: manifest.capacityEvidence,
    });

    expect(revision.revision).toBe(2);
    expect(revision.predecessorManifestDigest).toBe(manifest.selfDigest);
    expect(Object.isFrozen(revision)).toBe(true);
    expect(manifest.revision).toBe(1);

    const drifted = parseWindowManifest({
      ...manifest,
      traceSetDigest: `sha256:${"f".repeat(64)}`,
      selfDigest: fingerprintWindowManifest({
        ...manifest,
        traceSetDigest: `sha256:${"f".repeat(64)}`,
      }),
    });
    expect(() => assessPolicyWindow(
      frozenProtocol,
      online.dataset,
      policy,
      drifted,
      online.context,
      TEST_WORK_BUDGET,
    )).toThrow(/trace-set digest|trace source/i);
  });

  it("does not trust a self-digested caller capacity declaration as measurement", () => {
    const frozenProtocol = protocol((value) => {
      value.gates.serviceCapacity = {
        kind: "minimum-measured-window-throughput",
        metric: "aggregate-output-tokens-per-second",
        minimum: 100,
      };
    });
    const protocolDigest = fingerprintProtocol(frozenProtocol);
    const policy = enumerateProtocolPolicyBundles(
      frozenProtocol,
      protocolDigest,
      "2026-07-22T00:00:00.000Z",
    ).candidates.find(({ kind }) => kind === "fast-only")!;
    const membershipDigest = deriveWindowMembershipDigest(
      "window-1",
      protocolDigest,
      membershipRule,
    );
    const online = assessmentFixture(frozenProtocol, {
      split: "online",
      policyDigest: policy.policyDigest,
      windowId: "window-1",
      windowMembershipDigest: membershipDigest,
    });
    const manifest = baseManifest(
      protocolDigest,
      policy.policyDigest,
      online.dataset,
      {
        kind: "reported",
        metric: "aggregate-output-tokens-per-second",
        value: 150,
        source: "operator-reported",
        declarationDigest: `sha256:${"a".repeat(64)}`,
        frozenPolicyDigest: policy.policyDigest,
        eventTimeStartInclusive: "2026-07-23T00:00:00.000Z",
        eventTimeEndExclusive: "2026-07-23T00:01:00.000Z",
      },
    );
    const decision = assessPolicyWindow(
      frozenProtocol,
      online.dataset,
      policy,
      manifest,
      online.context,
      TEST_WORK_BUDGET,
    );

    expect(decision.status).toBe("INSUFFICIENT_EVIDENCE");
    expect(decision.candidates[0].metrics.serviceCapacity).toMatchObject({
      value: null,
      evidenceClass: "unavailable",
    });
    expect(decision.candidates[0].gates).toContainEqual(
      expect.objectContaining({
        id: "minimum-service-capacity",
        passed: false,
      }),
    );
    expect(decision.candidates[0].insufficiencyReasons).toContain(
      "required-service-capacity-unavailable",
    );
  });
});
