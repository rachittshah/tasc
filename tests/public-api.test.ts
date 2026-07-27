import { describe, expect, it } from "vitest";
import * as tasc from "../src/index.js";

describe("standalone public API", () => {
  it("exports the complete policy-lab surface from one package entry point", () => {
    expect(tasc).toMatchObject({
      parseInferenceSpec: expect.any(Function),
      parseMeasurementSet: expect.any(Function),
      generateCandidatePolicies: expect.any(Function),
      replayPolicy: expect.any(Function),
      nominatePolicy: expect.any(Function),
      confirmNomination: expect.any(Function),
      buildDevelopmentReport: expect.any(Function),
      buildConfirmationReport: expect.any(Function),
      proposeNextExperiment: expect.any(Function),
      parseExperimentProtocol: expect.any(Function),
      parseTraceEnvelope: expect.any(Function),
      parseEvaluatorEvidence: expect.any(Function),
      verifyEvaluatorEvidence: expect.any(Function),
      parseAssessmentContext: expect.any(Function),
      fingerprintExecutionProfile: expect.any(Function),
      fingerprintProtocol: expect.any(Function),
    });
  });

  it("keeps deterministic identities independent of object insertion order", () => {
    expect(tasc.stableJson({ beta: 2, alpha: { delta: 4, gamma: 3 } }))
      .toBe(tasc.stableJson({ alpha: { gamma: 3, delta: 4 }, beta: 2 }));
    expect(tasc.sha256("tasc")).toHaveLength(64);
  });

  it("does not expose contract implementation helpers from the package entry point", () => {
    expect(tasc).not.toHaveProperty("deepFreezeContract");
    expect(tasc).not.toHaveProperty("domainSeparatedDigest");
    expect(tasc).not.toHaveProperty("contractSlugSchema");
    expect(tasc).not.toHaveProperty("contractTimestampSchema");
    expect(tasc).not.toHaveProperty("snapshotBoundedContractInput");
    expect(tasc).not.toHaveProperty("normalizeEvaluatorEvidence");
  });
});
