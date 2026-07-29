import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  fingerprintProtocol,
  parseEvaluatorEvidence,
  parseExperimentProtocol,
  parseTraceEnvelope,
} from "../src/evidence.js";
import {
  assertAcceptedEvaluatorEvidenceWithinWindowWatermark,
  assertTraceBelongsToWindow,
  assertWindowManifestMatchesProtocol,
  createWindowManifestRevision,
  deriveWindowMembershipBucket,
  deriveWindowMembershipDigest,
  fingerprintWindowManifest,
  isWindowMembershipSelected,
  parseWindowManifest,
  traceEventTime,
} from "../src/window.js";
import {
  TEST_WORK_BUDGET,
  evaluatorKeyFixture,
  signEvaluatorEvidence,
  unsignedEvaluatorEvidence,
  validCollectionBinding,
  validProtocolInput,
  validTraceInput,
} from "./fixtures/evidence.js";

const digestFor = (value: string): string =>
  `sha256:${createHash("sha256").update(value).digest("hex")}`;

const defaultRule = Object.freeze({
  algorithm: "tasc-seeded-sha256-case-replicate-basis-points-v1" as const,
  seed: "window-sample-seed",
  sampleBasisPoints: 10_000,
});

function unsignedManifest(overrides: Record<string, unknown> = {}) {
  const base = {
    version: "tasc-window-manifest-v2" as const,
    windowId: "shadow-window-2026-07-21-00",
    protocolDigest: digestFor("protocol"),
    frozenPolicyDigest: digestFor("frozen-policy"),
    eventTimeStartInclusive: "2026-07-21T00:00:00.000Z",
    eventTimeEndExclusive: "2026-07-21T01:00:00.000Z",
    ingestionWatermark: "2026-07-21T01:05:00.000Z",
    closureReason: "scheduled-end",
    membershipRule: defaultRule,
    revision: 1,
    predecessorManifestDigest: null,
    traceSetDigest: digestFor("trace-set-1"),
    evaluatorSetDigest: digestFor("evaluator-set-1"),
    capacityEvidence: {
      kind: "unavailable" as const,
      reasonCode: "not-collected",
    },
  };
  const body = { ...base, ...overrides };
  return {
    ...body,
    membershipDigest: Object.hasOwn(overrides, "membershipDigest")
      ? overrides.membershipDigest
      : deriveWindowMembershipDigest(
        body.windowId as string,
        body.protocolDigest as string,
        body.membershipRule as typeof defaultRule,
      ),
  };
}

function manifestInput(overrides: Record<string, unknown> = {}) {
  const body = unsignedManifest(overrides);
  return {
    ...body,
    selfDigest: fingerprintWindowManifest(body),
  };
}

function reportedCapacity(overrides: Record<string, unknown> = {}) {
  return {
    kind: "reported" as const,
    metric: "aggregate-output-tokens-per-second" as const,
    value: 412.5,
    source: "operator-reported" as const,
    declarationDigest: digestFor("capacity-declaration"),
    frozenPolicyDigest: digestFor("frozen-policy"),
    eventTimeStartInclusive: "2026-07-21T00:00:00.000Z",
    eventTimeEndExclusive: "2026-07-21T01:00:00.000Z",
    ...overrides,
  };
}

function protocolBoundManifest(overrides: Record<string, unknown> = {}) {
  const protocolInput = validProtocolInput();
  const protocolDigest = fingerprintProtocol(protocolInput);
  return manifestInput({
    protocolDigest,
    membershipRule: protocolInput.onlineWindowMembership,
    ...overrides,
  });
}

function onlineTrace(
  manifest = parseWindowManifest(protocolBoundManifest()),
  overrides: Record<string, unknown> = {},
) {
  const input = structuredClone(validTraceInput()) as Record<string, any>;
  input.protocolDigest = manifest.protocolDigest;
  input.policyDigest = manifest.frozenPolicyDigest;
  input.caseId = "case-0";
  input.split = "online";
  input.collectionWindowId = manifest.windowId;
  input.collectionWindowMembershipDigest = manifest.membershipDigest;
  input.sourceMode = "shadow";
  input.collectionBinding = validCollectionBinding();
  input.attempts[0].observerTimings.startedAt =
    manifest.eventTimeStartInclusive;
  input.attempts[0].observerTimings.headersAt =
    "2026-07-21T00:00:00.050Z";
  input.attempts[0].observerTimings.firstByteAt =
    "2026-07-21T00:00:00.060Z";
  input.attempts[0].observerTimings.firstMeaningfulTokenAt =
    "2026-07-21T00:00:00.075Z";
  input.attempts[0].observerTimings.completedAt =
    "2026-07-21T00:00:00.500Z";
  Object.assign(input, overrides);
  return parseTraceEnvelope(input, TEST_WORK_BUDGET);
}

describe("tasc-window-manifest-v2", () => {
  it("parses the complete strict contract, verifies its self digest, and recursively freezes it", () => {
    const input = manifestInput({
      capacityEvidence: reportedCapacity(),
    });
    const manifest = parseWindowManifest(input);

    expect(manifest).toEqual(input);
    expect(manifest.selfDigest).toBe(fingerprintWindowManifest(manifest));
    expect(Object.isFrozen(manifest)).toBe(true);
    expect(Object.isFrozen(manifest.membershipRule)).toBe(true);
    expect(Object.isFrozen(manifest.capacityEvidence)).toBe(true);
    expect(() => {
      (manifest.membershipRule as any).sampleBasisPoints = 1;
    }).toThrow(TypeError);
    expect(() => {
      (manifest.capacityEvidence as any).value = 1;
    }).toThrow(TypeError);
  });

  it("uses a domain-separated canonical fingerprint that ignores object insertion order", () => {
    const body = unsignedManifest();
    const reversed = Object.fromEntries(Object.entries(body).reverse());

    expect(fingerprintWindowManifest(reversed))
      .toBe(fingerprintWindowManifest(body));
    expect(fingerprintWindowManifest(body)).toMatch(/^sha256:[a-f0-9]{64}$/);
    expect(fingerprintWindowManifest(body))
      .not.toBe(digestFor(JSON.stringify(body)));
  });

  it("rejects unknown fields, a forged self digest, and a membership identity mismatch", () => {
    expect(() => parseWindowManifest({
      ...manifestInput(),
      unexpected: true,
    })).toThrow(/unrecognized|unknown/i);
    expect(() => parseWindowManifest({
      ...manifestInput(),
      selfDigest: digestFor("forged"),
    })).toThrow(/self digest.*mismatch/i);
    expect(() => parseWindowManifest(manifestInput({
      membershipDigest: digestFor("wrong-rule-identity"),
    }))).toThrow(/membership digest.*mismatch/i);
    const original = manifestInput();
    expect(() => parseWindowManifest({
      ...original,
      traceSetDigest: digestFor("different-trace-multiset"),
    })).toThrow(/self digest.*mismatch/i);
  });

  it("enforces non-empty half-open event bounds closed behind the ingestion watermark", () => {
    expect(() => parseWindowManifest(manifestInput({
      eventTimeEndExclusive: "2026-07-21T00:00:00.000Z",
    }))).toThrow(/start.*before.*end/i);
    expect(() => parseWindowManifest(manifestInput({
      eventTimeEndExclusive: "2026-07-20T23:59:59.999Z",
    }))).toThrow(/start.*before.*end/i);
    expect(() => parseWindowManifest(manifestInput({
      ingestionWatermark: "2026-07-21T00:59:59.999Z",
    }))).toThrow(/end.*watermark/i);

    expect(parseWindowManifest(manifestInput({
      ingestionWatermark: "2026-07-21T01:00:00.000Z",
    })).ingestionWatermark).toBe("2026-07-21T01:00:00.000Z");
  });

  it("enforces revision-one/null-predecessor and later-revision/predecessor semantics", () => {
    expect(() => parseWindowManifest(manifestInput({
      predecessorManifestDigest: digestFor("impossible-predecessor"),
    }))).toThrow(/revision 1.*predecessor.*null/i);
    expect(() => parseWindowManifest(manifestInput({
      revision: 2,
      predecessorManifestDigest: null,
    }))).toThrow(/revision.*greater than 1.*predecessor/i);

    expect(parseWindowManifest(manifestInput({
      revision: 2,
      predecessorManifestDigest: digestFor("revision-1"),
    })).revision).toBe(2);
  });

  it("accepts only the protocol's exact bounded online sampling rule", () => {
    expect(() => parseWindowManifest(manifestInput({
      membershipRule: {
        ...defaultRule,
        algorithm: "invented-sampling",
      },
    }))).toThrow(/algorithm|invalid literal/i);
    expect(() => parseWindowManifest(manifestInput({
      membershipRule: {
        ...defaultRule,
        sampleBasisPoints: 10_001,
      },
    }))).toThrow(/sampleBasisPoints|less than or equal/i);
    expect(() => parseWindowManifest(manifestInput({
      membershipRule: {
        ...defaultRule,
        extra: true,
      },
    }))).toThrow(/unrecognized|unknown/i);
  });

  it("derives the online bucket from the full SHA-256 integer modulo 10,000", () => {
    const rule = {
      algorithm: "tasc-seeded-sha256-case-replicate-basis-points-v1" as const,
      seed: "support-routing-shadow-2",
      sampleBasisPoints: 8_969,
    };

    // Golden domain-separated JCS value includes algorithm, seed, case, and
    // replicate. Its SHA-256 is:
    // SHA-256:
    // 9d65698377545936aabeb42efe95375f31feb19f005732ffb54458867baf8da1
    const expectedBucket = Number(BigInt(
      "0x9d65698377545936aabeb42efe95375f31feb19f005732ffb54458867baf8da1",
    ) % 10_000n);
    expect(expectedBucket).toBe(5_841);
    expect(deriveWindowMembershipBucket(
      rule,
      "case-1",
      "replicate-0",
    )).toBe(expectedBucket);

    // Converting the full digest to an IEEE-754 number before reducing it loses
    // precision and produces the wrong bucket; the implementation never does so.
    expect(Number(BigInt(
      "0x9d65698377545936aabeb42efe95375f31feb19f005732ffb54458867baf8da1",
    )) % 10_000).toBe(5_120);
    expect(isWindowMembershipSelected(rule, "case-1", "replicate-0"))
      .toBe(true);
    expect(isWindowMembershipSelected(
      { ...rule, sampleBasisPoints: 5_841 },
      "case-1",
      "replicate-0",
    )).toBe(false);
    expect(isWindowMembershipSelected(
      { ...rule, sampleBasisPoints: 0 },
      "case-1",
      "replicate-0",
    )).toBe(false);
  });

  it("domain-binds the membership identity to the window, protocol, and exact rule", () => {
    const first = deriveWindowMembershipDigest(
      "window-one",
      digestFor("protocol-one"),
      defaultRule,
    );
    expect(first).not.toBe(deriveWindowMembershipDigest(
      "window-two",
      digestFor("protocol-one"),
      defaultRule,
    ));
    expect(first).not.toBe(deriveWindowMembershipDigest(
      "window-one",
      digestFor("protocol-two"),
      defaultRule,
    ));
    expect(first).not.toBe(deriveWindowMembershipDigest(
      "window-one",
      digestFor("protocol-one"),
      { ...defaultRule, sampleBasisPoints: 9_999 },
    ));
  });

  it("binds a manifest to the exact normalized protocol, sampling rule, and frozen policy", () => {
    const protocol = parseExperimentProtocol(
      validProtocolInput(),
      TEST_WORK_BUDGET,
    );
    const manifest = parseWindowManifest(protocolBoundManifest());

    expect(() => assertWindowManifestMatchesProtocol(
      manifest,
      protocol,
      manifest.frozenPolicyDigest,
    )).not.toThrow();
    expect(() => assertWindowManifestMatchesProtocol(
      manifest,
      protocol,
      digestFor("different-policy"),
    )).toThrow(/frozen policy digest/i);
    expect(() => assertWindowManifestMatchesProtocol(
      parseWindowManifest(protocolBoundManifest({
        membershipRule: {
          ...protocol.onlineWindowMembership,
          sampleBasisPoints:
            protocol.onlineWindowMembership.sampleBasisPoints + 1,
        },
      })),
      protocol,
      digestFor("frozen-policy"),
    )).toThrow(/membership rule.*protocol/i);
    expect(() => assertWindowManifestMatchesProtocol(
      parseWindowManifest(protocolBoundManifest({
        protocolDigest: digestFor("other-protocol"),
      })),
      protocol,
      digestFor("frozen-policy"),
    )).toThrow(/protocol digest/i);
  });

  it("labels caller capacity as operator-reported, never measured", () => {
    expect(parseWindowManifest(manifestInput()).capacityEvidence).toEqual({
      kind: "unavailable",
      reasonCode: "not-collected",
    });
    expect(parseWindowManifest(manifestInput({
      capacityEvidence: reportedCapacity(),
    })).capacityEvidence).toMatchObject({
      kind: "reported",
      metric: "aggregate-output-tokens-per-second",
      value: 412.5,
      source: "operator-reported",
    });

    for (const capacityEvidence of [
      reportedCapacity({ metric: "request-rate" }),
      reportedCapacity({ source: "provider-reported" }),
      reportedCapacity({ value: -1 }),
      reportedCapacity({ declarationDigest: "not-a-digest" }),
    ]) {
      expect(() => parseWindowManifest(manifestInput({
        capacityEvidence,
      }))).toThrow();
    }
  });

  it("rejects reported capacity not bound to the exact policy and event-time interval", () => {
    expect(() => parseWindowManifest(manifestInput({
      capacityEvidence: reportedCapacity({
        frozenPolicyDigest: digestFor("other-policy"),
      }),
    }))).toThrow(/capacity.*policy/i);
    expect(() => parseWindowManifest(manifestInput({
      capacityEvidence: reportedCapacity({
        eventTimeStartInclusive: "2026-07-21T00:00:00.001Z",
      }),
    }))).toThrow(/capacity.*event.*bounds/i);
    expect(() => parseWindowManifest(manifestInput({
      capacityEvidence: reportedCapacity({
        eventTimeEndExclusive: "2026-07-21T00:59:59.999Z",
      }),
    }))).toThrow(/capacity.*event.*bounds/i);
  });

  it("defines trace event time as the first attempt's observer startedAt", () => {
    const manifest = parseWindowManifest(protocolBoundManifest());
    const input = structuredClone(validTraceInput()) as Record<string, any>;
    input.protocolDigest = manifest.protocolDigest;
    input.policyDigest = manifest.frozenPolicyDigest;
    input.caseId = "case-0";
    input.split = "online";
    input.collectionWindowId = manifest.windowId;
    input.collectionWindowMembershipDigest = manifest.membershipDigest;
    input.sourceMode = "shadow";
    input.collectionBinding = validCollectionBinding();
    input.attempts[0].status = "failure";
    input.attempts[0].finishReason = null;
    input.attempts[0].failureCategory = "transient";
    input.attempts.push({
      ...structuredClone(input.attempts[0]),
      attemptId: "attempt-2",
      attemptNumber: 2,
      status: "success",
      finishReason: "stop",
      failureCategory: null,
      observerTimings: {
        startedAt: "2026-07-21T00:00:02.000Z",
        headersAt: "2026-07-21T00:00:02.050Z",
        firstByteAt: "2026-07-21T00:00:02.060Z",
        firstMeaningfulTokenAt: "2026-07-21T00:00:02.075Z",
        completedAt: "2026-07-21T00:00:02.500Z",
      },
    });
    const trace = parseTraceEnvelope(input, TEST_WORK_BUDGET);

    expect(traceEventTime(trace)).toBe("2026-07-21T00:00:00.000Z");
    expect(() => assertTraceBelongsToWindow(trace, manifest)).not.toThrow();
  });

  it("applies full trace semantics at every public window boundary", () => {
    const manifest = parseWindowManifest(protocolBoundManifest());
    const impossible = structuredClone(onlineTrace(manifest)) as Record<
      string,
      any
    >;
    impossible.attempts[0].observerTimings.headersAt =
      "2026-07-20T23:59:59.999Z";

    expect(() => traceEventTime(impossible as never)).toThrow(
      /timing.*precedes/i,
    );
    expect(() => assertTraceBelongsToWindow(
      impossible as never,
      manifest,
    )).toThrow(/timing.*precedes/i);
  });

  it("recomputes half-open event-time and sampling membership for online traces", () => {
    const manifest = parseWindowManifest(protocolBoundManifest());
    expect(() => assertTraceBelongsToWindow(
      onlineTrace(manifest),
      manifest,
    )).not.toThrow();

    const justInside = onlineTrace(manifest);
    const justInsideInput = structuredClone(justInside) as Record<string, any>;
    justInsideInput.attempts[0].observerTimings.startedAt =
      "2026-07-21T00:59:59.999Z";
    justInsideInput.attempts[0].observerTimings.headersAt =
      "2026-07-21T00:59:59.999Z";
    justInsideInput.attempts[0].observerTimings.firstByteAt =
      "2026-07-21T00:59:59.999Z";
    justInsideInput.attempts[0].observerTimings.firstMeaningfulTokenAt =
      "2026-07-21T00:59:59.999Z";
    justInsideInput.attempts[0].observerTimings.completedAt =
      "2026-07-21T00:59:59.999Z";
    expect(() => assertTraceBelongsToWindow(
      parseTraceEnvelope(justInsideInput, TEST_WORK_BUDGET),
      manifest,
    )).not.toThrow();

    const atExclusiveEnd = structuredClone(justInsideInput) as Record<string, any>;
    for (const timing of Object.keys(
      atExclusiveEnd.attempts[0].observerTimings,
    )) {
      atExclusiveEnd.attempts[0].observerTimings[timing] =
        manifest.eventTimeEndExclusive;
    }
    expect(() => assertTraceBelongsToWindow(
      parseTraceEnvelope(atExclusiveEnd, TEST_WORK_BUDGET),
      manifest,
    )).toThrow(/event time.*outside/i);

    const noSamples = parseWindowManifest(protocolBoundManifest({
      membershipRule: {
        ...manifest.membershipRule,
        sampleBasisPoints: 0,
      },
    }));
    const unsampled = onlineTrace(noSamples);
    expect(() => assertTraceBelongsToWindow(unsampled, noSamples))
      .toThrow(/sampling rule/i);
  });

  it("seals only traces whose terminal completion is at or before the watermark", () => {
    const manifest = parseWindowManifest(protocolBoundManifest());
    const atWatermark = structuredClone(onlineTrace(manifest)) as Record<
      string,
      any
    >;
    atWatermark.attempts[0].observerTimings.completedAt =
      manifest.ingestionWatermark;
    expect(() => assertTraceBelongsToWindow(
      parseTraceEnvelope(atWatermark, TEST_WORK_BUDGET),
      manifest,
    )).not.toThrow();

    const afterWatermark = structuredClone(atWatermark) as Record<string, any>;
    afterWatermark.attempts[0].observerTimings.completedAt =
      "2026-07-21T01:05:00.001Z";
    expect(() => assertTraceBelongsToWindow(
      parseTraceEnvelope(afterWatermark, TEST_WORK_BUDGET),
      manifest,
    )).toThrow(/terminal completion.*watermark.*revision/i);
  });

  it("seals only accepted evaluator evidence produced at or before the watermark", () => {
    const manifest = parseWindowManifest(protocolBoundManifest());
    const key = evaluatorKeyFixture();
    const evidenceAt = (producedAt: string) => {
      const unsigned = unsignedEvaluatorEvidence();
      unsigned.protocolDigest = manifest.protocolDigest;
      (unsigned as any).split = "online";
      unsigned.producedAt = producedAt;
      return parseEvaluatorEvidence(
        signEvaluatorEvidence(key.privateKey, unsigned),
        TEST_WORK_BUDGET,
      );
    };

    expect(() => assertAcceptedEvaluatorEvidenceWithinWindowWatermark(
      evidenceAt(manifest.ingestionWatermark),
      manifest,
    )).not.toThrow();
    expect(() => assertAcceptedEvaluatorEvidenceWithinWindowWatermark(
      evidenceAt("2026-07-21T01:05:00.001Z"),
      manifest,
    )).toThrow(/evaluator evidence.*watermark.*revision/i);
  });

  it("rejects trace-declared split, protocol, policy, window, and membership identity drift", () => {
    const manifest = parseWindowManifest(protocolBoundManifest());
    const valid = onlineTrace(manifest);
    const cases: Array<[string, Record<string, unknown>, RegExp]> = [
      ["protocol", { protocolDigest: digestFor("wrong-protocol") }, /protocol digest/i],
      ["policy", { policyDigest: digestFor("wrong-policy") }, /policy digest/i],
      ["window", { collectionWindowId: "wrong-window" }, /window id/i],
      [
        "membership",
        { collectionWindowMembershipDigest: digestFor("wrong-membership") },
        /membership digest/i,
      ],
    ];
    for (const [_label, overrides, expected] of cases) {
      const input = { ...structuredClone(valid), ...overrides };
      expect(() => assertTraceBelongsToWindow(
        parseTraceEnvelope(input, TEST_WORK_BUDGET),
        manifest,
      )).toThrow(expected);
    }

    expect(() => assertTraceBelongsToWindow(
      parseTraceEnvelope(validTraceInput(), TEST_WORK_BUDGET),
      manifest,
    )).toThrow(/online/i);
  });

  it("creates a linked immutable late-evidence revision without mutating its predecessor", () => {
    const previous = parseWindowManifest(manifestInput());
    const previousSnapshot = structuredClone(previous);
    const next = createWindowManifestRevision(previous, {
      ingestionWatermark: "2026-07-21T02:00:00.000Z",
      closureReason: "late-evaluator-evidence",
      traceSetDigest: previous.traceSetDigest,
      evaluatorSetDigest: digestFor("evaluator-set-2"),
      capacityEvidence: reportedCapacity(),
    });

    expect(previous).toEqual(previousSnapshot);
    expect(next).toMatchObject({
      version: "tasc-window-manifest-v2",
      windowId: previous.windowId,
      protocolDigest: previous.protocolDigest,
      frozenPolicyDigest: previous.frozenPolicyDigest,
      eventTimeStartInclusive: previous.eventTimeStartInclusive,
      eventTimeEndExclusive: previous.eventTimeEndExclusive,
      membershipRule: previous.membershipRule,
      membershipDigest: previous.membershipDigest,
      revision: 2,
      predecessorManifestDigest: previous.selfDigest,
      ingestionWatermark: "2026-07-21T02:00:00.000Z",
      evaluatorSetDigest: digestFor("evaluator-set-2"),
    });
    expect(next.selfDigest).toBe(fingerprintWindowManifest(next));
    expect(next.selfDigest).not.toBe(previous.selfDigest);
    expect(Object.isFrozen(next)).toBe(true);
    expect(Object.isFrozen(next.capacityEvidence)).toBe(true);
  });

  it("requires explicit fresh source digests and a nondecreasing revision watermark", () => {
    const previous = parseWindowManifest(manifestInput());
    expect(() => createWindowManifestRevision(previous, {
      ingestionWatermark: "2026-07-21T01:04:59.999Z",
      closureReason: "late-evidence",
      traceSetDigest: digestFor("trace-set-2"),
      evaluatorSetDigest: previous.evaluatorSetDigest,
      capacityEvidence: previous.capacityEvidence,
    })).toThrow(/watermark.*nondecreasing/i);
    expect(() => createWindowManifestRevision(previous, {
      ingestionWatermark: previous.ingestionWatermark,
      closureReason: "late-evidence",
      traceSetDigest: previous.traceSetDigest,
      evaluatorSetDigest: previous.evaluatorSetDigest,
      capacityEvidence: previous.capacityEvidence,
    })).toThrow(/source digests.*change/i);
    expect(() => createWindowManifestRevision(previous, {
      ingestionWatermark: previous.ingestionWatermark,
      closureReason: "late-evidence",
      traceSetDigest: digestFor("trace-set-2"),
      capacityEvidence: previous.capacityEvidence,
    } as any)).toThrow(/evaluatorSetDigest/i);
  });

  it("allows a linked capacity-only revision without inventing source drift", () => {
    const previous = parseWindowManifest(manifestInput());
    const next = createWindowManifestRevision(previous, {
      ingestionWatermark: previous.ingestionWatermark,
      closureReason: "capacity-declaration-added",
      traceSetDigest: previous.traceSetDigest,
      evaluatorSetDigest: previous.evaluatorSetDigest,
      capacityEvidence: reportedCapacity(),
    });

    expect(next.revision).toBe(2);
    expect(next.predecessorManifestDigest).toBe(previous.selfDigest);
    expect(next.traceSetDigest).toBe(previous.traceSetDigest);
    expect(next.evaluatorSetDigest).toBe(previous.evaluatorSetDigest);
    expect(next.capacityEvidence.kind).toBe("reported");
  });

  it("does not permit revision changes to invariant window identity fields", () => {
    const previous = parseWindowManifest(manifestInput());
    for (const illegal of [
      { windowId: "different-window" },
      { protocolDigest: digestFor("other-protocol") },
      { frozenPolicyDigest: digestFor("other-policy") },
      { eventTimeEndExclusive: "2026-07-21T02:00:00.000Z" },
      { membershipRule: { ...defaultRule, sampleBasisPoints: 1 } },
      { revision: 99 },
      { predecessorManifestDigest: digestFor("invented") },
    ]) {
      expect(() => createWindowManifestRevision(previous, {
        ingestionWatermark: previous.ingestionWatermark,
        closureReason: "late-evidence",
        traceSetDigest: digestFor("trace-set-2"),
        evaluatorSetDigest: previous.evaluatorSetDigest,
        capacityEvidence: previous.capacityEvidence,
        ...illegal,
      } as any)).toThrow(/unrecognized|invariant|unknown/i);
    }
  });

  it("snapshots bounded plain caller data without invoking accessors", () => {
    const input = manifestInput();
    let reads = 0;
    Object.defineProperty(input, "closureReason", {
      enumerable: true,
      get() {
        reads += 1;
        return "scheduled-end";
      },
    });

    expect(() => parseWindowManifest(input)).toThrow(/accessor/i);
    expect(reads).toBe(0);
    expect(() => parseWindowManifest(manifestInput({
      closureReason: "x".repeat(1_025),
    }))).toThrow(/bounded.*length|too big|at most/i);
    expect(() => parseWindowManifest(Object.assign(
      Object.create({ inherited: true }),
      manifestInput(),
    ))).toThrow(/plain JSON|plain.*object/i);
  });

  it("reads every caller-owned top-level data descriptor exactly once", () => {
    const target = manifestInput();
    let propertyReads = 0;
    const descriptorReads = new Map<PropertyKey, number>();
    const input = new Proxy(target, {
      get() {
        propertyReads += 1;
        throw new Error("caller data property was re-read");
      },
      getOwnPropertyDescriptor(value, property) {
        descriptorReads.set(
          property,
          (descriptorReads.get(property) ?? 0) + 1,
        );
        return Reflect.getOwnPropertyDescriptor(value, property);
      },
    });

    expect(parseWindowManifest(input)).toEqual(target);
    expect(propertyReads).toBe(0);
    expect([...descriptorReads.values()].every((count) => count === 1))
      .toBe(true);
  });
});
