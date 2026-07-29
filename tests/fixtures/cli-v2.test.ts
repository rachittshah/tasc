import { describe, expect, it } from "vitest";
import {
  assessPolicyWindow,
  confirmHoldout,
  isDevelopmentNomination,
  nominateDevelopment,
} from "../../src/assessment.js";
import { parseAssessmentContext } from "../../src/assessment-context.js";
import {
  parseEvaluatorEvidence,
  parseExperimentProtocol,
  parseTraceEnvelope,
} from "../../src/evidence.js";
import {
  joinAssessmentEvidence,
  requireAssessmentDatasetSplit,
} from "../../src/evidence-join.js";
import {
  parseEvaluatorTrustSnapshot,
  verifyEvaluatorEvidence,
} from "../../src/evaluator-trust.js";
import { TEST_WORK_BUDGET } from "./evidence.js";
import {
  assessmentFixtureForSplit,
  createCliV2AssessmentFixtureSet,
  createCliV2OnlineAssessmentFixture,
  createCliV2WindowManifest,
  type CliV2AssessmentSplit,
  type CliV2AssessmentSplitFixture,
} from "./cli-v2.js";

function rawFileRoundTrip<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

function rawNdjsonRoundTrip<T>(rows: readonly T[]): T[] {
  const contents = rows.map((row) => JSON.stringify(row)).join("\n") + "\n";
  return contents.trimEnd().split("\n").map((line) =>
    JSON.parse(line) as T
  );
}

function joinedSplit<Split extends CliV2AssessmentSplit>(
  fixture:
    | ReturnType<typeof createCliV2AssessmentFixtureSet>
    | ReturnType<typeof createCliV2OnlineAssessmentFixture>,
  splitFixture: CliV2AssessmentSplitFixture<Split>,
) {
  const protocol = parseExperimentProtocol(
    rawFileRoundTrip(fixture.protocolInput),
    TEST_WORK_BUDGET,
  );
  const trust = parseEvaluatorTrustSnapshot(
    rawFileRoundTrip(fixture.trustSnapshot),
  );
  const context = parseAssessmentContext(
    rawFileRoundTrip(splitFixture.contextInput),
  );
  const traces = rawNdjsonRoundTrip(splitFixture.traceRows).map((trace) =>
    parseTraceEnvelope(trace, TEST_WORK_BUDGET)
  );
  const verifications = rawNdjsonRoundTrip(
    splitFixture.evidenceRows,
  ).map((row) =>
    verifyEvaluatorEvidence(
      parseEvaluatorEvidence(row, TEST_WORK_BUDGET),
      trust,
      context,
    )
  );
  expect(verifications.every(({ trusted }) => trusted)).toBe(true);

  return {
    protocol,
    context,
    dataset: requireAssessmentDatasetSplit(
      joinAssessmentEvidence(
        protocol,
        traces,
        verifications,
        TEST_WORK_BUDGET,
      ),
      splitFixture.split,
    ),
  };
}

describe("Task 9 raw assessment file fixtures", () => {
  it("nominates on development and confirms the selected policy on holdout", () => {
    const fixtures = createCliV2AssessmentFixtureSet();
    expect("privateKey" in fixtures).toBe(false);

    const development = joinedSplit(
      fixtures,
      assessmentFixtureForSplit(fixtures, "dev"),
    );
    const nomination = nominateDevelopment(
      development.protocol,
      development.dataset,
      development.context,
      TEST_WORK_BUDGET,
    );
    expect(nomination.status).toBe("NOMINATED");
    expect(isDevelopmentNomination(nomination)).toBe(true);
    if (!isDevelopmentNomination(nomination)) {
      throw new Error("expected fixture to produce a development nomination");
    }

    const holdout = joinedSplit(
      fixtures,
      assessmentFixtureForSplit(fixtures, "holdout"),
    );
    const confirmation = confirmHoldout(
      holdout.protocol,
      holdout.dataset,
      nomination,
      holdout.context,
      TEST_WORK_BUDGET,
    );

    expect(confirmation).toMatchObject({
      phase: "holdout",
      status: "PASS",
      selectedPolicyDigest: nomination.selectedPolicyDigest,
    });

    const onlineFixtures = createCliV2OnlineAssessmentFixture(
      nomination.selectedPolicy,
    );
    expect(onlineFixtures.protocolInput.onlineWindowMembership)
      .toMatchObject({ sampleBasisPoints: 10_000 });
    expect("privateKey" in onlineFixtures).toBe(false);
    const online = joinedSplit(
      onlineFixtures,
      onlineFixtures.online,
    );
    const manifest = createCliV2WindowManifest(
      online.protocol,
      nomination.selectedPolicy,
      online.dataset,
    );
    const decision = assessPolicyWindow(
      online.protocol,
      online.dataset,
      nomination.selectedPolicy,
      manifest,
      online.context,
      TEST_WORK_BUDGET,
    );

    expect(manifest).toMatchObject({
      frozenPolicyDigest: nomination.selectedPolicyDigest,
      traceSetDigest: online.dataset.traceSetDigest,
      evaluatorSetDigest: online.dataset.evaluatorSetDigest,
    });
    expect(decision).toMatchObject({
      phase: "window",
      status: "PASS",
      selectedPolicyDigest: nomination.selectedPolicyDigest,
      traceSetDigest: online.dataset.traceSetDigest,
      evaluatorSetDigest: online.dataset.evaluatorSetDigest,
    });
  });
});
