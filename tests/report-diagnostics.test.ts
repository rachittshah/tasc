import { readFile, mkdtemp, readdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, join } from "node:path";
import { describe, expect, it } from "vitest";
import { verifyArtifactPacket } from "../src/artifacts.js";
import { nominatePolicy } from "../src/evaluate.js";
import {
  proposeNextExperiment,
  writeDevelopmentArtifacts,
} from "../src/report.js";
import {
  parseInferenceSpec,
  parseMeasurementSet,
} from "../src/schema.js";

type GateComparison = ">=" | "<=";

function failedGate(
  id: string,
  actual: number | null,
  threshold: number,
  comparison: GateComparison,
) {
  return {
    id,
    pass: false,
    actual,
    threshold,
    comparison,
    reason: `${id} fixture failure`,
  };
}

function rejectedResult(
  gates: readonly ReturnType<typeof failedGate>[],
) {
  return {
    status: "NO_CANDIDATE",
    evaluations: [{
      policy: { id: "candidate-a", kind: "fast-only" },
      evaluation: { gates },
    }],
    frontier: [],
  } as never;
}

function experimentContext(
  cases: readonly {
    readonly repeatedPrefixTokens: number;
    readonly inputTokens: number;
  }[] = [],
) {
  return {
    spec: {
      candidateSpace: {
        inputTokenThresholds: [100],
      },
    },
    measurements: { cases },
  } as never;
}

describe("legacy next-experiment diagnostics", () => {
  it("requires complete parsed experiment context", () => {
    const result = rejectedResult([]);
    expect(() => proposeNextExperiment(result, null as never))
      .toThrow(/parsed spec and measurements context/);
    expect(() => proposeNextExperiment(result, {} as never))
      .toThrow(/parsed spec and measurements context/);
  });

  it("rejects an internally inconsistent nominated result", () => {
    expect(() => proposeNextExperiment({
      status: "NOMINATED",
      nomination: null,
      evaluations: [],
      frontier: [],
    } as never, experimentContext())).toThrow(
      /missing its nomination artifact/,
    );
  });

  it("publishes a nominated diagnostic packet through the direct API", async () => {
    const spec = parseInferenceSpec(JSON.parse(await readFile(
      new URL("../examples/synthetic/spec.json", import.meta.url),
      "utf8",
    )));
    const measurements = parseMeasurementSet(JSON.parse(await readFile(
      new URL("../examples/synthetic/dev.json", import.meta.url),
      "utf8",
    )), "dev");
    const result = nominatePolicy(spec, measurements);
    expect(result.status).toBe("NOMINATED");
    expect(result.nomination).not.toBeNull();
    const proposal = proposeNextExperiment(result, { spec, measurements });
    expect(proposal.trigger).toMatch(/passed every development gate/i);

    const root = await mkdtemp(join(tmpdir(), "tasc-report-diagnostics-"));
    const output = join(root, "packet");
    await writeDevelopmentArtifacts(output, result, {
      synthetic: true,
      spec,
      measurements,
    });
    expect(await readdir(output)).toEqual(expect.arrayContaining([
      "development-report.json",
      "next-experiment.json",
      "nomination.json",
      "report.md",
    ]));
    await expect(verifyArtifactPacket(dirname(output), basename(output)))
      .resolves.toMatchObject({ path: output });
  });

  it.each([
    {
      name: "repeated prefixes and long inputs",
      cases: [{ repeatedPrefixTokens: 32, inputTokens: 128 }],
      technique: /prefix caching.*chunked prefill/i,
    },
    {
      name: "repeated prefixes only",
      cases: [{ repeatedPrefixTokens: 32, inputTokens: 64 }],
      technique: /prefix caching and cache-aware routing/i,
    },
    {
      name: "long inputs only",
      cases: [{ repeatedPrefixTokens: 0, inputTokens: 128 }],
      technique: /chunked prefill at preregistered input-length bands/i,
    },
    {
      name: "neither observed condition",
      cases: [{ repeatedPrefixTokens: 0, inputTokens: 64 }],
      technique: /instrument prefill, queue, and runtime phases/i,
    },
  ])(
    "selects evidence-supported TTFT diagnostics for $name",
    ({ cases, technique }) => {
      const proposal = proposeNextExperiment(
        rejectedResult([
          failedGate("p95_ttft", 1_200, 1_000, "<="),
          failedGate("error_rate", 0.011, 0.01, "<="),
        ]),
        experimentContext(cases),
      );
      expect(proposal.trigger).toContain("p95_ttft");
      expect(proposal.technique).toMatch(technique);
      expect(proposal.requiredMeasurements).not.toHaveLength(0);
    },
  );

  it.each([
    {
      id: "p10_perceived_tps",
      actual: 9,
      threshold: 10,
      comparison: ">=" as const,
      technique: /speculative decoding/i,
    },
    {
      id: "p50_total_tps",
      actual: 90,
      threshold: 100,
      comparison: ">=" as const,
      technique: /continuous-batch sizes/i,
    },
    {
      id: "cost_per_thousand",
      actual: 11,
      threshold: 10,
      comparison: "<=" as const,
      technique: /quantization as a new measured profile/i,
    },
    {
      id: "p95_end_to_end_latency",
      actual: 1_100,
      threshold: 1_000,
      comparison: "<=" as const,
      technique: /queues and benchmark autoscaling/i,
    },
    {
      id: "unclassified_guardrail",
      actual: null,
      threshold: 1,
      comparison: ">=" as const,
      technique: /disjoint shadow traces/i,
    },
  ])(
    "maps a dominant $id failure to a bounded measurement proposal",
    ({ id, actual, threshold, comparison, technique }) => {
      const proposal = proposeNextExperiment(
        rejectedResult([failedGate(id, actual, threshold, comparison)]),
        experimentContext(),
      );
      expect(proposal.trigger).toContain(id);
      expect(proposal.technique).toMatch(technique);
      expect(proposal.unchangedGuardrails).toEqual([
        `${id} ${comparison} ${threshold}`,
      ]);
    },
  );

  it("requests a complete matrix when no candidate evaluation exists", () => {
    const proposal = proposeNextExperiment({
      status: "NO_CANDIDATE",
      evaluations: [],
      frontier: [],
    } as never, experimentContext());
    expect(proposal.trigger).toMatch(/no candidate evaluation/i);
    expect(proposal.technique).toMatch(/disjoint shadow traces/i);
  });
});
