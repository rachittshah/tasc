import { describe, expect, it, vi } from "vitest";
import {
  fingerprintAssessmentContext,
  parseAssessmentContext,
} from "../src/assessment-context.js";
import {
  evaluatorKeyFixture,
  mutate,
  validAssessmentContextInput,
} from "./fixtures/evidence.js";

describe("assessment context v2", () => {
  it("derives and verifies its domain-separated JCS digest", () => {
    const key = evaluatorKeyFixture();
    const input = validAssessmentContextInput(key.trustSnapshot);
    const parsed = parseAssessmentContext(input);

    expect(parsed).toEqual({
      ...input,
      contextDigest: expect.stringMatching(/^sha256:[a-f0-9]{64}$/),
    });
    expect(parsed.contextDigest).toBe(fingerprintAssessmentContext(input));
    expect(parseAssessmentContext({ ...input, contextDigest: parsed.contextDigest })).toEqual(parsed);
    expect(Object.isFrozen(parsed)).toBe(true);
  });

  it("rejects a supplied digest that does not match canonical content", () => {
    const key = evaluatorKeyFixture();
    expect(() => parseAssessmentContext({
      ...validAssessmentContextInput(key.trustSnapshot),
      contextDigest: `sha256:${"0".repeat(64)}`,
    })).toThrow(/context digest.*match/i);
  });

  it("is insertion-order independent and never reads the wall clock", () => {
    const key = evaluatorKeyFixture();
    const input = validAssessmentContextInput(key.trustSnapshot);
    const reordered = {
      evaluatorRevocationSnapshotDigest: input.evaluatorRevocationSnapshotDigest,
      operatorTrustPolicySnapshotDigest: input.operatorTrustPolicySnapshotDigest,
      asOf: input.asOf,
      version: input.version,
    };
    const clock = vi.spyOn(Date, "now").mockImplementation(() => {
      throw new Error("wall clock access is forbidden");
    });
    try {
      expect(parseAssessmentContext(reordered).contextDigest)
        .toBe(parseAssessmentContext(input).contextDigest);
    } finally {
      clock.mockRestore();
    }
  });

  it.each([
    ["unknown field", (context: any) => { context.trusted = true; }],
    ["invalid asOf", (context: any) => { context.asOf = "now"; }],
    ["invalid trust digest", (context: any) => { context.operatorTrustPolicySnapshotDigest = "sha256:no"; }],
    ["invalid revocation digest", (context: any) => { context.evaluatorRevocationSnapshotDigest = "0".repeat(64); }],
  ])("rejects %s", (_label, change) => {
    const key = evaluatorKeyFixture();
    expect(() => parseAssessmentContext(
      mutate(validAssessmentContextInput(key.trustSnapshot), change),
    )).toThrow();
  });

  it("rejects explicit non-I-JSON optional values instead of normalizing them away", () => {
    const key = evaluatorKeyFixture();
    expect(() => parseAssessmentContext({
      ...validAssessmentContextInput(key.trustSnapshot),
      contextDigest: undefined,
    })).toThrow(/I-JSON|JSON-compatible/i);
  });
});
