import { describe, expect, it, vi } from "vitest";

const operations = vi.hoisted(() => ({
  canonicalValues: vi.fn(),
  contractSnapshots: vi.fn(),
  evidenceFingerprints: vi.fn(),
}));

vi.mock("../src/determinism.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/determinism.js")>();
  return {
    ...actual,
    canonicalJson(value: unknown) {
      operations.canonicalValues(value);
      return actual.canonicalJson(value);
    },
  };
});

vi.mock("../src/evidence.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/evidence.js")>();
  return {
    ...actual,
    fingerprintNormalizedEvaluatorEvidence(
      evidence: Parameters<
        typeof actual.fingerprintNormalizedEvaluatorEvidence
      >[0],
    ) {
      operations.evidenceFingerprints(evidence);
      return actual.fingerprintNormalizedEvaluatorEvidence(evidence);
    },
    snapshotBoundedContractInput(input: unknown) {
      operations.contractSnapshots(input);
      return actual.snapshotBoundedContractInput(input);
    },
  };
});

import { parseAssessmentContext } from "../src/assessment-context.js";
import { joinAssessmentEvidence } from "../src/evidence-join.js";
import {
  parseEvaluatorEvidence,
  parseExperimentProtocol,
  parseTraceEnvelope,
} from "../src/evidence.js";
import {
  parseEvaluatorTrustSnapshot,
  verifyEvaluatorEvidence,
} from "../src/evaluator-trust.js";
import {
  TEST_WORK_BUDGET,
  evaluatorKeyFixture,
  mutate,
  signEvaluatorEvidence,
  unsignedEvaluatorEvidence,
  validAssessmentContextInput,
  validEvaluatorEvidenceInput,
  validProtocolInput,
  validTraceInput,
} from "./fixtures/evidence.js";

function embedsFullEvaluatorEvidence(value: unknown): boolean {
  if (value === null || typeof value !== "object") return false;
  if (!Object.hasOwn(value, "evidence")) return false;
  const evidence = (value as { evidence?: unknown }).evidence;
  return (
    evidence !== null
    && typeof evidence === "object"
    && (evidence as { version?: unknown }).version
      === "tasc-evaluator-evidence-v2"
  );
}

describe("assessment join operation bounds", () => {
  it("reuses authentic receipt digests and never serializes embedded evidence to sort diagnostics", () => {
    const trustedKey = evaluatorKeyFixture();
    const wrongKey = evaluatorKeyFixture();
    const trustSnapshot = parseEvaluatorTrustSnapshot(
      trustedKey.trustSnapshot,
    );
    const context = parseAssessmentContext(
      validAssessmentContextInput(trustSnapshot),
    );
    const unsigned = unsignedEvaluatorEvidence();
    unsigned.outcome.subscores = Array.from({ length: 64 }, (_, index) => ({
      id: `diagnostic-${index}`,
      score: index - 32,
      range: { minimum: -32, maximum: 31 },
    }));
    const evidence = parseEvaluatorEvidence(
      signEvaluatorEvidence(wrongKey.privateKey, unsigned),
      TEST_WORK_BUDGET,
    );
    const receipt = verifyEvaluatorEvidence(
      evidence,
      trustSnapshot,
      context,
    );
    expect(receipt.status).toBe("invalid-signature");

    operations.canonicalValues.mockClear();
    operations.evidenceFingerprints.mockClear();
    const joined = joinAssessmentEvidence(
      parseExperimentProtocol(validProtocolInput(), TEST_WORK_BUDGET),
      [parseTraceEnvelope(validTraceInput(), TEST_WORK_BUDGET)],
      [receipt],
      TEST_WORK_BUDGET,
    );

    expect(joined.diagnostics.invalidEvidence).toHaveLength(1);
    expect(joined.executions[0].outcome).toMatchObject({
      kind: "invalid-evidence",
      evidenceDigest: receipt.evidenceDigest,
      evidence: receipt.evidence,
      evidenceAccepted: false,
    });
    expect(
      operations.canonicalValues.mock.calls
        .map(([value]) => value)
        .filter(embedsFullEvaluatorEvidence),
    ).toEqual([]);
    expect(operations.evidenceFingerprints).not.toHaveBeenCalled();
  });

  it("treats a forged receipt as an opaque constant-work row", () => {
    const protocol = parseExperimentProtocol(
      validProtocolInput(),
      TEST_WORK_BUDGET,
    );
    const filler = Array.from(
      { length: 100 },
      () => Array<number>(256).fill(0),
    );
    let forgedPropertyOperations = 0;
    const forged = new Proxy({ filler }, {
      get(target, property, receiver) {
        forgedPropertyOperations += 1;
        return Reflect.get(target, property, receiver);
      },
      getOwnPropertyDescriptor(target, property) {
        forgedPropertyOperations += 1;
        return Reflect.getOwnPropertyDescriptor(target, property);
      },
      ownKeys(target) {
        forgedPropertyOperations += 1;
        return Reflect.ownKeys(target);
      },
    });
    operations.contractSnapshots.mockClear();
    operations.evidenceFingerprints.mockClear();

    const joined = joinAssessmentEvidence(
      protocol,
      [],
      [forged as never],
      {
        ...TEST_WORK_BUDGET,
        maxTraceRows: 0,
        maxEvidenceRows: 1,
        maxIndependentGroups: 0,
        maxAssessmentWork: 11,
      },
    );

    expect(joined.work).toMatchObject({
      evidenceRows: 1,
      traceRows: 0,
      chargedUnits: 11,
    });
    expect(joined.diagnostics.invalidEvidence).toEqual([{
      evidence: null,
      evidenceDigest: null,
      traceId: null,
      profileId: null,
      reason: "inauthentic-verification-receipt",
      verification: {
        authentic: false,
        status: "inauthentic",
        trusted: false,
        reason: "object was not emitted by the local evaluator verifier",
        keyId: null,
        assessedAt: null,
        assessmentContextDigest: null,
        operatorTrustPolicySnapshotDigest: null,
        evaluatorRevocationSnapshotDigest: null,
      },
    }]);
    expect(forgedPropertyOperations).toBe(0);
    expect(operations.contractSnapshots).not.toHaveBeenCalled();
    expect(operations.evidenceFingerprints).not.toHaveBeenCalled();
  });

  it("keeps a successful trace missing when its only receipt is forged", () => {
    const forged = new Proxy({}, {
      get() {
        throw new Error("forged receipt property was read");
      },
      getOwnPropertyDescriptor() {
        throw new Error("forged receipt descriptor was read");
      },
      ownKeys() {
        throw new Error("forged receipt keys were read");
      },
    });

    const joined = joinAssessmentEvidence(
      parseExperimentProtocol(validProtocolInput(), TEST_WORK_BUDGET),
      [parseTraceEnvelope(validTraceInput(), TEST_WORK_BUDGET)],
      [forged as never],
      TEST_WORK_BUDGET,
    );

    expect(joined.executions[0].outcome).toMatchObject({
      kind: "missing-evidence",
      evidence: null,
      evidenceDigest: null,
      evidenceAccepted: false,
    });
    expect(joined.diagnostics.invalidEvidence).toHaveLength(1);
    expect(joined.diagnostics.missingEvidence).toHaveLength(1);
  });

  it("orders same-digest diagnostics by compact status and context identities", () => {
    const key = evaluatorKeyFixture();
    const evidence = parseEvaluatorEvidence(
      validEvaluatorEvidenceInput(key.privateKey),
      TEST_WORK_BUDGET,
    );
    const trustedSnapshot = parseEvaluatorTrustSnapshot(key.trustSnapshot);
    const trustedContext = parseAssessmentContext(
      validAssessmentContextInput(trustedSnapshot),
    );
    const trusted = verifyEvaluatorEvidence(
      evidence,
      trustedSnapshot,
      trustedContext,
    );
    const revokedSnapshot = parseEvaluatorTrustSnapshot(
      mutate(key.trustSnapshot, (snapshot) => {
        snapshot.revocations.push({
          keyId: "evaluator-key-1",
          revokedAt: "2026-07-22T00:00:00.000Z",
          reasonCode: "operator-revocation",
        });
      }),
    );
    const revokedContext = parseAssessmentContext(
      validAssessmentContextInput(revokedSnapshot),
    );
    const revoked = verifyEvaluatorEvidence(
      evidence,
      revokedSnapshot,
      revokedContext,
    );
    expect([trusted.status, revoked.status]).toEqual(["trusted", "revoked"]);

    const protocol = parseExperimentProtocol(
      validProtocolInput(),
      TEST_WORK_BUDGET,
    );
    const trace = parseTraceEnvelope(validTraceInput(), TEST_WORK_BUDGET);
    const forward = joinAssessmentEvidence(
      protocol,
      [trace],
      [trusted, revoked],
      TEST_WORK_BUDGET,
    );
    const reverse = joinAssessmentEvidence(
      protocol,
      [trace],
      [revoked, trusted],
      TEST_WORK_BUDGET,
    );

    expect(reverse).toEqual(forward);
    expect(forward.diagnostics.invalidEvidence.map((row) => [
      row.evidenceDigest,
      row.reason,
      row.verification.status,
      row.verification.assessmentContextDigest,
    ])).toEqual([
      [
        trusted.evidenceDigest,
        "verification-context-drift",
        "trusted",
        trusted.assessmentContextDigest,
      ],
      [
        revoked.evidenceDigest,
        "verification-revoked",
        "revoked",
        revoked.assessmentContextDigest,
      ],
    ]);
  });
});
