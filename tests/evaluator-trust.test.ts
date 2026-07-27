import { sign } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import { canonicalJsonBytes } from "../src/determinism.js";
import {
  fingerprintEvaluatorRevocations,
  fingerprintEvaluatorTrustPolicy,
  parseEvaluatorTrustSnapshot,
  verifyEvaluatorEvidence,
} from "../src/evaluator-trust.js";
import { parseAssessmentContext } from "../src/assessment-context.js";
import {
  parseEvaluatorEvidence,
  parseExperimentProtocol,
} from "../src/evidence.js";
import {
  TEST_WORK_BUDGET,
  digest,
  evaluatorKeyFixture,
  mutate,
  signEvaluatorEvidence,
  unsignedEvaluatorEvidence,
  validAssessmentContextInput,
  validEvaluatorEvidenceInput,
  validProtocolInput,
} from "./fixtures/evidence.js";

describe("external evaluator evidence trust", () => {
  it("derives trusted Ed25519 evidence from explicit context and operator key material", () => {
    const key = evaluatorKeyFixture();
    const snapshot = parseEvaluatorTrustSnapshot(key.trustSnapshot);
    const context = parseAssessmentContext(validAssessmentContextInput(snapshot));
    const evidence = parseEvaluatorEvidence(
      validEvaluatorEvidenceInput(key.privateKey),
      TEST_WORK_BUDGET,
    );
    const clock = vi.spyOn(Date, "now").mockImplementation(() => {
      throw new Error("wall clock access is forbidden");
    });

    try {
      expect(verifyEvaluatorEvidence(evidence, snapshot, context)).toMatchObject({
        status: "trusted",
        trusted: true,
        evidence,
        evidenceDigest: expect.stringMatching(/^sha256:[a-f0-9]{64}$/),
        assessedAt: context.asOf,
        assessmentContextDigest: context.contextDigest,
        operatorTrustPolicySnapshotDigest: context.operatorTrustPolicySnapshotDigest,
        evaluatorRevocationSnapshotDigest: context.evaluatorRevocationSnapshotDigest,
      });
    } finally {
      clock.mockRestore();
    }
  });

  it("rejects cryptographically valid legacy 0-100 primary scores before trust", () => {
    const key = evaluatorKeyFixture();
    const snapshot = parseEvaluatorTrustSnapshot(key.trustSnapshot);
    const context = parseAssessmentContext(validAssessmentContextInput(snapshot));
    const unsigned = unsignedEvaluatorEvidence();
    unsigned.outcome.score = 50;
    unsigned.outcome.range = { minimum: 0, maximum: 100 };
    const signed = {
      ...unsigned,
      signature: sign(
        null,
        canonicalJsonBytes({
          domain: "tasc/evaluator-evidence-signature/v2",
          evidence: unsigned,
        }),
        key.privateKey,
      ).toString("base64url"),
    };

    let disposition = "rejected-at-contract";
    let parsingError = "";
    try {
      const parsed = parseEvaluatorEvidence(signed, TEST_WORK_BUDGET);
      disposition = verifyEvaluatorEvidence(parsed, snapshot, context).status;
    } catch (error) {
      parsingError = error instanceof Error ? error.message : String(error);
    }

    expect(disposition).toBe("rejected-at-contract");
    expect(parsingError).toMatch(/evaluator.*canonical.*0.*1/i);
  });

  it("signs every mutable identity, lineage, scored outcome, source, and production-time leaf", () => {
    const key = evaluatorKeyFixture();
    const snapshot = parseEvaluatorTrustSnapshot(key.trustSnapshot);
    const context = parseAssessmentContext(validAssessmentContextInput(snapshot));
    const signed = validEvaluatorEvidenceInput(key.privateKey);
    const mutations: Array<(evidence: any) => void> = [
      (evidence) => { evidence.studyId = "other-study"; },
      (evidence) => { evidence.protocolDigest = digest("f"); },
      (evidence) => { evidence.traceId = "other-trace"; },
      (evidence) => { evidence.caseId = "case-2"; },
      (evidence) => { evidence.replicateId = "replicate-1"; },
      (evidence) => { evidence.profileId = "candidate"; },
      (evidence) => { evidence.split = "holdout"; },
      (evidence) => { evidence.terminalOutputId.keyId = "other-payload-key"; },
      (evidence) => { evidence.terminalOutputId.value = "2".repeat(64); },
      (evidence) => { evidence.evaluator.evaluatorId = "other-evaluator"; },
      (evidence) => { evidence.evaluator.rubricVersion = "rubric-5"; },
      (evidence) => { evidence.evaluator.calibrationDigest = digest("b"); },
      (evidence) => { evidence.evaluator.producer.producerId = "other-producer"; },
      (evidence) => { evidence.evaluator.producer.kind = "human"; },
      (evidence) => { evidence.evaluator.producer.version = "4.2.1"; },
      (evidence) => { evidence.outcome.score = 0.91; },
      (evidence) => { evidence.outcome.subscores[0].id = "factuality"; },
      (evidence) => { evidence.outcome.subscores[0].score = 0.94; },
      (evidence) => { evidence.outcome.subscores[0].range.minimum = -1; },
      (evidence) => { evidence.outcome.subscores[0].range.maximum = 2; },
      (evidence) => { evidence.source.digest = digest("f"); },
      (evidence) => {
        evidence.source = {
          kind: "controlled-reference",
          storeId: "evaluator-store",
          referenceId: "evidence-2",
          digest: digest("e"),
        };
      },
      (evidence) => {
        evidence.outcome = {
          kind: "abstained",
          reasonCode: "insufficient-context",
        };
      },
      (evidence) => { evidence.producedAt = "2026-07-21T12:00:00.001Z"; },
      (evidence) => { evidence.keyId = "evaluator-key-2"; },
    ];

    for (const change of mutations) {
      const tampered = parseEvaluatorEvidence(mutate(signed, change), TEST_WORK_BUDGET);
      expect(verifyEvaluatorEvidence(tampered, snapshot, context).status)
        .toBe("invalid-signature");
    }
  });

  it("signs non-scored outcome reasons and every controlled-source leaf", () => {
    const key = evaluatorKeyFixture();
    const snapshot = parseEvaluatorTrustSnapshot(key.trustSnapshot);
    const context = parseAssessmentContext(validAssessmentContextInput(snapshot));

    for (const kind of ["missing", "invalid", "abstained"] as const) {
      const signed = signEvaluatorEvidence(key.privateKey, {
        ...unsignedEvaluatorEvidence(),
        outcome: { kind, reasonCode: "original-reason" },
      });
      const original = parseEvaluatorEvidence(signed, TEST_WORK_BUDGET);
      expect(verifyEvaluatorEvidence(original, snapshot, context).status).toBe("trusted");
      const tampered = parseEvaluatorEvidence(
        mutate(signed, (evidence: any) => {
          evidence.outcome.reasonCode = "changed-reason";
        }),
        TEST_WORK_BUDGET,
      );
      expect(verifyEvaluatorEvidence(tampered, snapshot, context).status)
        .toBe("invalid-signature");
    }

    const controlled = signEvaluatorEvidence(key.privateKey, {
      ...unsignedEvaluatorEvidence(),
      source: {
        kind: "controlled-reference",
        storeId: "evaluator-store",
        referenceId: "evidence-1",
        digest: digest("e"),
      },
    });
    const originalControlled = parseEvaluatorEvidence(controlled, TEST_WORK_BUDGET);
    expect(verifyEvaluatorEvidence(originalControlled, snapshot, context).status)
      .toBe("trusted");
    for (const change of [
      (evidence: any) => { evidence.source.storeId = "other-store"; },
      (evidence: any) => { evidence.source.referenceId = "evidence-2"; },
      (evidence: any) => { evidence.source.digest = digest("f"); },
      (evidence: any) => { delete evidence.source.digest; },
    ]) {
      const tampered = parseEvaluatorEvidence(mutate(controlled, change), TEST_WORK_BUDGET);
      expect(verifyEvaluatorEvidence(tampered, snapshot, context).status)
        .toBe("invalid-signature");
    }
  });

  it("returns explicit unknown, revoked, stale, future, malformed, wrong-key, and unauthorized states", () => {
    const key = evaluatorKeyFixture();
    const baseSnapshot = parseEvaluatorTrustSnapshot(key.trustSnapshot);
    const evidence = parseEvaluatorEvidence(
      validEvaluatorEvidenceInput(key.privateKey),
      TEST_WORK_BUDGET,
    );
    const verifyWith = (
      snapshotInput: typeof key.trustSnapshot,
      evidenceInput: typeof evidence = evidence,
      asOf = "2026-07-22T00:00:00.000Z",
    ) => {
      const snapshot = parseEvaluatorTrustSnapshot(snapshotInput);
      const context = parseAssessmentContext({
        ...validAssessmentContextInput(snapshot),
        asOf,
      });
      return verifyEvaluatorEvidence(evidenceInput, snapshot, context);
    };

    const unknownEvidence = parseEvaluatorEvidence(
      signEvaluatorEvidence(key.privateKey, {
        ...unsignedEvaluatorEvidence(),
        keyId: "unknown-key",
      }),
      TEST_WORK_BUDGET,
    );
    expect(verifyWith(key.trustSnapshot, unknownEvidence).status).toBe("unknown-key");

    const revokedSnapshot = mutate(key.trustSnapshot, (snapshot) => {
      snapshot.revocations.push({
        keyId: "evaluator-key-1",
        revokedAt: "2026-07-22T00:00:00.000Z",
        reasonCode: "operator-revocation",
      });
    });
    expect(verifyWith(revokedSnapshot, evidence).status).toBe("revoked");

    expect(verifyWith(
      key.trustSnapshot,
      evidence,
      "2026-07-28T12:00:00.001Z",
    ).status).toBe("stale");
    expect(verifyWith(
      key.trustSnapshot,
      evidence,
      "2026-07-21T11:59:29.999Z",
    ).status).toBe("future-dated");

    const malformed = parseEvaluatorEvidence(
      { ...validEvaluatorEvidenceInput(key.privateKey), signature: "A".repeat(85) },
      TEST_WORK_BUDGET,
    );
    expect(verifyWith(key.trustSnapshot, malformed).status).toBe("malformed-signature");

    const otherKey = evaluatorKeyFixture();
    const wrongKey = parseEvaluatorEvidence(
      validEvaluatorEvidenceInput(otherKey.privateKey),
      TEST_WORK_BUDGET,
    );
    expect(verifyWith(key.trustSnapshot, wrongKey).status).toBe("invalid-signature");

    const unauthorizedUnsigned = {
      ...unsignedEvaluatorEvidence(),
      evaluator: {
        ...unsignedEvaluatorEvidence().evaluator,
        rubricVersion: "rubric-6",
      },
    };
    const unauthorized = parseEvaluatorEvidence(
      signEvaluatorEvidence(key.privateKey, unauthorizedUnsigned),
      TEST_WORK_BUDGET,
    );
    expect(verifyWith(key.trustSnapshot, unauthorized).status).toBe("unauthorized-evidence");
    expect(baseSnapshot.keys[0].purpose).toBe("evaluator-evidence");
  });

  it("checks a known-key signature before interpreting signed freshness or evaluator metadata", () => {
    const key = evaluatorKeyFixture();
    const snapshotInput = mutate(key.trustSnapshot, (snapshot) => {
      snapshot.revocations.push({
        keyId: "evaluator-key-1",
        revokedAt: "2026-07-22T00:00:00.000Z",
        reasonCode: "operator-revocation",
      });
    });
    const snapshot = parseEvaluatorTrustSnapshot(snapshotInput);
    const context = parseAssessmentContext(validAssessmentContextInput(snapshot));
    const signed = validEvaluatorEvidenceInput(key.privateKey);

    for (const change of [
      (evidence: any) => { evidence.producedAt = "2026-08-30T00:00:00.000Z"; },
      (evidence: any) => { evidence.evaluator.rubricVersion = "rubric-6"; },
      (evidence: any) => { evidence.outcome.score = 0.91; },
    ]) {
      const evidence = parseEvaluatorEvidence(mutate(signed, change), TEST_WORK_BUDGET);
      expect(verifyEvaluatorEvidence(evidence, snapshot, context).status)
        .toBe("invalid-signature");
    }
  });

  it("normalizes verifier inputs once and only returns immutable local evidence", () => {
    const key = evaluatorKeyFixture();
    const rawEvidence = validEvaluatorEvidenceInput(key.privateKey);
    const rawContext = validAssessmentContextInput(key.trustSnapshot);
    let propertyReads = 0;
    const noGet = <T extends object>(value: T): T => new Proxy(value, {
      get() {
        propertyReads += 1;
        throw new Error("verifier re-read a caller object");
      },
    });

    const verified = verifyEvaluatorEvidence(
      noGet(rawEvidence) as never,
      noGet(key.trustSnapshot) as never,
      noGet(rawContext) as never,
    );
    expect(verified.status).toBe("trusted");
    expect(verified.evidence).not.toBe(rawEvidence);
    expect(Object.isFrozen(verified.evidence)).toBe(true);
    expect(propertyReads).toBe(0);
  });

  it("rejects duplicate key material and non-canonical Ed25519 SPKI encodings", () => {
    const key = evaluatorKeyFixture();
    const duplicate = mutate(key.trustSnapshot, (snapshot) => {
      snapshot.keys[1].publicKeySpki = snapshot.keys[0].publicKeySpki;
    });
    expect(() => parseEvaluatorTrustSnapshot(duplicate))
      .toThrow(/duplicate.*public key|public key.*duplicate/i);

    const nonCanonical = mutate(key.trustSnapshot, (snapshot) => {
      const canonical = Buffer.from(snapshot.keys[0].publicKeySpki, "base64url");
      snapshot.keys[0].publicKeySpki = Buffer.concat([
        canonical,
        Buffer.from([0]),
      ]).toString("base64url");
    });
    expect(() => parseEvaluatorTrustSnapshot(nonCanonical))
      .toThrow(/canonical.*Ed25519|Ed25519.*canonical/i);
  });

  it("uses one rubric identity contract across protocols, evidence, and trust authorization", () => {
    const key = evaluatorKeyFixture();
    const rubricVersion = "Rubric v4 / strict";
    const trust = mutate(key.trustSnapshot, (snapshot) => {
      snapshot.keys[0].authorizedRubricVersions = [rubricVersion];
    });
    const evidence = signEvaluatorEvidence(key.privateKey, {
      ...unsignedEvaluatorEvidence(),
      evaluator: {
        ...unsignedEvaluatorEvidence().evaluator,
        rubricVersion,
      },
    });
    const protocol = mutate(validProtocolInput(), (value) => {
      value.evaluator.rubricVersion = rubricVersion;
    });

    const parsedTrust = parseEvaluatorTrustSnapshot(trust);
    const parsedEvidence = parseEvaluatorEvidence(evidence, TEST_WORK_BUDGET);
    const context = parseAssessmentContext(validAssessmentContextInput(parsedTrust));
    expect(verifyEvaluatorEvidence(parsedEvidence, parsedTrust, context).status)
      .toBe("trusted");
    expect(() => parseExperimentProtocol(protocol, TEST_WORK_BUDGET)).not.toThrow();
  });

  it("honors exact freshness, skew, revocation, and key-validity boundaries", () => {
    const key = evaluatorKeyFixture();
    const evidence = parseEvaluatorEvidence(
      validEvaluatorEvidenceInput(key.privateKey),
      TEST_WORK_BUDGET,
    );
    const verifyAt = (asOf: string, snapshotInput = key.trustSnapshot) => {
      const snapshot = parseEvaluatorTrustSnapshot(snapshotInput);
      return verifyEvaluatorEvidence(
        evidence,
        snapshot,
        parseAssessmentContext({ ...validAssessmentContextInput(snapshot), asOf }),
      );
    };

    expect(verifyAt("2026-07-28T12:00:00.000Z").status).toBe("trusted");
    expect(verifyAt("2026-07-21T11:59:30.000Z").status).toBe("trusted");

    const revokedAfter = mutate(key.trustSnapshot, (snapshot) => {
      snapshot.revocations.push({
        keyId: "evaluator-key-1",
        revokedAt: "2026-07-22T00:00:00.001Z",
        reasonCode: "operator-revocation",
      });
    });
    expect(verifyAt("2026-07-22T00:00:00.000Z", revokedAfter).status).toBe("trusted");

    const notYetValid = mutate(key.trustSnapshot, (snapshot) => {
      snapshot.keys[0].validFrom = "2026-07-21T12:00:00.001Z";
    });
    expect(verifyAt("2026-07-22T00:00:00.000Z", notYetValid).status).toBe("key-not-yet-valid");

    const expired = mutate(key.trustSnapshot, (snapshot) => {
      snapshot.keys[0].validUntil = "2026-07-21T11:59:59.999Z";
    });
    expect(verifyAt("2026-07-22T00:00:00.000Z", expired).status).toBe("key-expired");
  });

  it("binds the exact trust and revocation snapshots to assessment context", () => {
    const key = evaluatorKeyFixture();
    const snapshot = parseEvaluatorTrustSnapshot(key.trustSnapshot);
    const context = parseAssessmentContext(validAssessmentContextInput(snapshot));
    const evidence = parseEvaluatorEvidence(
      validEvaluatorEvidenceInput(key.privateKey),
      TEST_WORK_BUDGET,
    );
    const changedPolicy = parseEvaluatorTrustSnapshot(mutate(key.trustSnapshot, (value) => {
      value.freshness.maximumFutureSkewMs += 1;
    }));
    const changedRevocations = parseEvaluatorTrustSnapshot(mutate(key.trustSnapshot, (value) => {
      value.revocations.push({
        keyId: "evaluator-key-2",
        revokedAt: "2026-08-01T00:00:00.000Z",
        reasonCode: "scheduled-revocation",
      });
    }));

    expect(fingerprintEvaluatorTrustPolicy(changedPolicy))
      .not.toBe(context.operatorTrustPolicySnapshotDigest);
    expect(fingerprintEvaluatorRevocations(changedRevocations))
      .not.toBe(context.evaluatorRevocationSnapshotDigest);
    expect(verifyEvaluatorEvidence(evidence, changedPolicy, context).status)
      .toBe("context-mismatch");
    expect(verifyEvaluatorEvidence(evidence, changedRevocations, context).status)
      .toBe("context-mismatch");
  });

  it("keeps evaluator outcome invalid distinct from cryptographic invalidity", () => {
    const key = evaluatorKeyFixture();
    const snapshot = parseEvaluatorTrustSnapshot(key.trustSnapshot);
    const context = parseAssessmentContext(validAssessmentContextInput(snapshot));
    const unsigned = {
      ...unsignedEvaluatorEvidence(),
      outcome: {
        kind: "invalid" as const,
        reasonCode: "malformed-evaluator-input",
      },
    };
    const evidence = parseEvaluatorEvidence(
      signEvaluatorEvidence(key.privateKey, unsigned),
      TEST_WORK_BUDGET,
    );
    const verified = verifyEvaluatorEvidence(evidence, snapshot, context);

    expect(verified.status).toBe("trusted");
    expect(verified.evidence.outcome.kind).toBe("invalid");
  });

  it("rejects empty key validity intervals", () => {
    const key = evaluatorKeyFixture();
    const invalid = mutate(key.trustSnapshot, (snapshot) => {
      snapshot.keys[0].validUntil = snapshot.keys[0].validFrom;
    });

    expect(() => parseEvaluatorTrustSnapshot(invalid)).toThrow(/validity.*after|validity.*start/i);
  });

  it.each([
    ["producer trust claim", (evidence: any) => { evidence.trusted = true; }],
    ["unknown evaluator field", (evidence: any) => { evidence.evaluator.trust = "trusted"; }],
    ["plain evidence URL", (evidence: any) => {
      evidence.source = { kind: "controlled-reference", storeId: "store", referenceId: "https://evil.test/evidence" };
    }],
    ["non-finite score", (evidence: any) => { evidence.outcome.score = Number.NaN; }],
    ["duplicate subscore", (evidence: any) => { evidence.outcome.subscores.push(evidence.outcome.subscores[0]); }],
    ["padded signature", (evidence: any) => { evidence.signature += "=="; }],
  ])("rejects %s at parse time", (_label, change) => {
    const key = evaluatorKeyFixture();
    expect(() => parseEvaluatorEvidence(
      mutate(validEvaluatorEvidenceInput(key.privateKey), change),
      TEST_WORK_BUDGET,
    )).toThrow();
  });

  it("requires all four explicit evidence outcomes", () => {
    const key = evaluatorKeyFixture();
    for (const outcome of [
      { kind: "missing" as const, reasonCode: "evaluator-timeout" },
      { kind: "invalid" as const, reasonCode: "malformed-evaluator-input" },
      { kind: "abstained" as const, reasonCode: "insufficient-context" },
    ]) {
      expect(() => parseEvaluatorEvidence(
        signEvaluatorEvidence(key.privateKey, {
          ...unsignedEvaluatorEvidence(),
          outcome,
        }),
        TEST_WORK_BUDGET,
      )).not.toThrow();
    }
  });
});
