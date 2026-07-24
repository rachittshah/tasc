import { mkdir, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import {
  type CandidateEvaluation,
  type ConfirmationResult,
  type GateResult,
  type NominationResult,
  type PolicyMetrics,
} from "./evaluate.js";
import { fingerprintPolicy } from "./policy.js";
import type { InferenceSpec, MeasurementSet } from "./schema.js";

export interface NextExperiment {
  version: "tasc-next-experiment-v1";
  trigger: string;
  hypothesis: string;
  technique: string;
  requiredMeasurements: string[];
  unchangedGuardrails: string[];
}

export interface ReportEvidenceOptions {
  synthetic: boolean;
}

export interface ExperimentContext {
  spec: InferenceSpec;
  measurements: MeasurementSet;
}

export interface DevelopmentReportOptions extends ReportEvidenceOptions, ExperimentContext {}

function fixed(value: number | null, digits = 3): string {
  return value === null ? "N/A" : value.toFixed(digits);
}

function percent(value: number | null): string {
  return value === null ? "N/A" : `${(value * 100).toFixed(1)}%`;
}

function metricsRow(label: string, metrics: PolicyMetrics): string {
  return [
    label,
    fixed(metrics.meanTaskScore),
    percent(metrics.errorRate),
    fixed(metrics.p95TtftMs, 0),
    fixed(metrics.p95EndToEndLatencyMs, 0),
    fixed(metrics.p10PerceivedTokensPerSecond, 1),
    fixed(metrics.p50TotalTokensPerSecond, 1),
    `$${fixed(metrics.costPerThousandRequestsUsd, 2)}`,
    percent(metrics.escalationRate),
  ].join(" | ");
}

function metricsTable(champion: PolicyMetrics, candidates: CandidateEvaluation[]): string {
  const rows = [
    "| Policy | Mean score | Error | P95 TTFT ms | P95 E2E ms | P10 perceived TPS | P50 total TPS | Cost / 1k | Escalation |",
    "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    `| ${metricsRow("Champion (expert-only)", champion)} |`,
    ...candidates.map(({ policy, evaluation }) => (
      `| ${metricsRow(`Candidate \`${policy.id}\` (${policy.kind})`, evaluation.candidateMetrics)} |`
    )),
  ];
  return rows.join("\n");
}

function gatesBlock(label: string, gates: GateResult[]): string {
  const failed = gates.filter((gate) => !gate.pass);
  if (failed.length === 0) return `- ${label}: None`;
  return failed.map((gate) => `- ${label} — \`${gate.id}\`: ${gate.reason}`).join("\n");
}

function policyFingerprints(evaluations: CandidateEvaluation[]): string {
  return evaluations
    .map(({ policy }) => `- \`${policy.id}\`: \`${fingerprintPolicy(policy)}\``)
    .join("\n");
}

function guardrailSummary(result: NominationResult): string[] {
  const gates = result.evaluations[0]?.evaluation.gates ?? [];
  return gates.map((gate) => `${gate.id} ${gate.comparison} ${gate.threshold}`);
}

function assertEvidenceProvenance(options: unknown): asserts options is ReportEvidenceOptions {
  if (
    typeof options !== "object"
    || options === null
    || typeof (options as { synthetic?: unknown }).synthetic !== "boolean"
  ) {
    throw new Error('report provenance requires an explicit boolean "synthetic" option');
  }
}

function assertExperimentContext(options: unknown): asserts options is ExperimentContext {
  if (typeof options !== "object" || options === null) {
    throw new Error("development diagnostics require parsed spec and measurements context");
  }
  const context = options as Partial<ExperimentContext>;
  if (!context.spec || !context.measurements) {
    throw new Error("development diagnostics require parsed spec and measurements context");
  }
}

function assertDevelopmentContext(options: unknown): asserts options is DevelopmentReportOptions {
  assertEvidenceProvenance(options);
  assertExperimentContext(options);
}

function normalizedBreach(gate: GateResult): number {
  if (gate.pass) return 0;
  if (gate.actual === null) return Number.POSITIVE_INFINITY;
  const distance = gate.comparison === ">="
    ? Math.max(0, gate.threshold - gate.actual)
    : Math.max(0, gate.actual - gate.threshold);
  const scale = Math.max(Math.abs(gate.threshold), Math.abs(gate.actual), 1e-12);
  return distance / scale;
}

function failedGates(candidate: CandidateEvaluation): GateResult[] {
  return candidate.evaluation.gates.filter((gate) => !gate.pass);
}

function mostPromisingRejectedCandidate(result: NominationResult): CandidateEvaluation | undefined {
  return [...result.evaluations].sort((left, right) => {
    const leftFailures = failedGates(left);
    const rightFailures = failedGates(right);
    const countDifference = leftFailures.length - rightFailures.length;
    if (countDifference !== 0) return countDifference;
    const leftBreach = leftFailures.reduce((sum, gate) => sum + normalizedBreach(gate), 0);
    const rightBreach = rightFailures.reduce((sum, gate) => sum + normalizedBreach(gate), 0);
    return leftBreach - rightBreach || left.policy.id.localeCompare(right.policy.id);
  })[0];
}

function dominantFailedGate(candidate: CandidateEvaluation): GateResult | undefined {
  return [...failedGates(candidate)].sort((left, right) => (
    normalizedBreach(right) - normalizedBreach(left)
    || left.id.localeCompare(right.id)
  ))[0];
}

function ttftExperiment(context: ExperimentContext): Pick<
  NextExperiment,
  "hypothesis" | "technique" | "requiredMeasurements"
> {
  const hasRepeatedPrefixes = context.measurements.cases.some((measurementCase) => (
    measurementCase.repeatedPrefixTokens > 0
  ));
  const crossesPreregisteredInputThreshold = context.measurements.cases.some((measurementCase) => (
    context.spec.candidateSpace.inputTokenThresholds.some((threshold) => (
      measurementCase.inputTokens >= threshold
    ))
  ));
  if (hasRepeatedPrefixes && crossesPreregisteredInputThreshold) {
    return {
      hypothesis: "Measure whether prefix caching for observed repeated prefixes or chunked prefill for inputs crossing a preregistered threshold reduces P95 TTFT.",
      technique: "Benchmark prefix caching/cache-aware routing and chunked prefill as separate measured variants.",
      requiredMeasurements: [
        "P50/P95 TTFT split by repeated-prefix tokens and preregistered input threshold",
        "Cache-hit rate and first-attempt failure rate",
        "Quality, end-to-end latency, throughput, and cost for every variant",
      ],
    };
  }
  if (hasRepeatedPrefixes) {
    return {
      hypothesis: "Measure whether prefix caching for the observed repeated-prefix workload reduces P95 TTFT.",
      technique: "Benchmark prefix caching and cache-aware routing.",
      requiredMeasurements: [
        "P50/P95 TTFT split by repeated-prefix tokens",
        "Cache-hit rate and first-attempt failure rate",
        "Quality, end-to-end latency, throughput, and cost",
      ],
    };
  }
  if (crossesPreregisteredInputThreshold) {
    return {
      hypothesis: "Measure whether chunked prefill for inputs crossing a preregistered threshold reduces P95 TTFT.",
      technique: "Benchmark chunked prefill at preregistered input-length bands.",
      requiredMeasurements: [
        "P50/P95 TTFT split by preregistered input threshold",
        "Prefill duration and first-attempt failure rate",
        "Quality, end-to-end latency, throughput, and cost",
      ],
    };
  }
  return {
    hypothesis: "Measure where TTFT is spent before selecting a serving optimization technique.",
    technique: "Instrument prefill, queue, and runtime phases and benchmark an alternative serving profile.",
    requiredMeasurements: [
      "P50/P95 TTFT decomposed into queue, prefill, and runtime phases",
      "Input-length and concurrency bands",
      "Quality, end-to-end latency, throughput, failures, and cost",
    ],
  };
}

function experimentForGate(gateId: string | undefined, context: ExperimentContext): Pick<
  NextExperiment,
  "hypothesis" | "technique" | "requiredMeasurements"
> {
  if (gateId?.startsWith("critical_slice:") || gateId === "mean_task_score" || gateId === "paired_quality_non_inferiority") {
    return {
      hypothesis: "Measure whether confidence calibration and slice-aware routing recover quality without erasing the cascade's measured cost advantage.",
      technique: "Calibrate routing thresholds and evaluate slice-aware escalation.",
      requiredMeasurements: [
        "Paired task scores and confidence calibration by slice",
        "Escalation rate and cost per 1,000 requests",
        "Bootstrap non-inferiority interval on disjoint groups",
      ],
    };
  }
  if (gateId === "p95_ttft") {
    return ttftExperiment(context);
  }
  if (gateId === "p10_perceived_tps") {
    return {
      hypothesis: "Measure whether speculative decoding improves low-concurrency perceived token rate while preserving task quality.",
      technique: "Benchmark speculative decoding at preregistered draft/verification settings.",
      requiredMeasurements: [
        "P10 perceived TPS by concurrency",
        "Acceptance rate and end-to-end latency",
        "Paired quality, failures, and cost",
      ],
    };
  }
  if (gateId === "p50_total_tps") {
    return {
      hypothesis: "Measure whether continuous batching and explicit concurrency targets improve total service throughput without breaching latency gates.",
      technique: "Benchmark continuous-batch sizes and concurrency targets.",
      requiredMeasurements: [
        "P50 total TPS by concurrency and batch size",
        "P95/P99 end-to-end latency and queue time",
        "Error rate, task quality, and cost",
      ],
    };
  }
  if (gateId === "cost_per_thousand" || gateId === "development_cost_improvement") {
    return {
      hypothesis: "Measure whether a quantized serving profile lowers cost while remaining inside the unchanged quality and reliability gates.",
      technique: "Benchmark quantization as a new measured profile; do not infer gains from model size alone.",
      requiredMeasurements: [
        "Paired task scores by critical slice",
        "Latency, perceived TPS, total TPS, and error rate",
        "Measured cost per request and per 1,000 requests",
      ],
    };
  }
  if (gateId === "p95_end_to_end_latency" || gateId === "error_rate") {
    return {
      hypothesis: "Measure whether queue, cold-start, autoscaling, and routing changes reduce tail latency or failures under the same arrival pattern.",
      technique: "Instrument queues and benchmark autoscaling/routing reliability under varied concurrency.",
      requiredMeasurements: [
        "Queue time, cold-start rate, and provider failure codes",
        "P95/P99 end-to-end latency by concurrency",
        "Error rate, task quality, throughput, and cost",
      ],
    };
  }
  return {
    hypothesis: "Measure whether the nominated policy reproduces its development behavior on additional shadow traces before any manual production decision.",
    technique: "Collect disjoint shadow traces and run a preregistered replication.",
    requiredMeasurements: [
      "Paired quality and confidence by workload slice",
      "TTFT, end-to-end latency, perceived TPS, and total TPS distributions",
      "Failures, escalation rate, and measured cost",
    ],
  };
}

export function proposeNextExperiment(
  result: NominationResult,
  context: ExperimentContext,
): NextExperiment {
  assertExperimentContext(context);
  if (result.status === "NOMINATED") {
    if (!result.nomination) {
      throw new Error("NOMINATED result is missing its nomination artifact");
    }
    return {
      version: "tasc-next-experiment-v1",
      trigger: `Selected candidate ${result.nomination.policy.id} passed every development gate; independent replication is still required.`,
      hypothesis: "Measure whether the nominated policy reproduces its development behavior on disjoint shadow traces before any manual production decision.",
      technique: "Collect disjoint shadow traces and run a preregistered replication.",
      requiredMeasurements: [
        "Paired quality and confidence by workload slice",
        "TTFT, end-to-end latency, perceived TPS, and total TPS distributions",
        "Failures, escalation rate, and measured cost",
      ],
      unchangedGuardrails: guardrailSummary(result),
    };
  }

  const candidate = mostPromisingRejectedCandidate(result);
  const failedGate = candidate && dominantFailedGate(candidate);
  const trigger = candidate && failedGate
    ? `${candidate.policy.id} was the most promising rejected candidate; dominant failed gate ${failedGate.id}: ${failedGate.reason}`
    : "No candidate evaluation was available; collect a complete measured development matrix.";
  const proposal = experimentForGate(failedGate?.id, context);
  return {
    version: "tasc-next-experiment-v1",
    trigger,
    ...proposal,
    unchangedGuardrails: guardrailSummary(result),
  };
}

export function buildDevelopmentReport(
  result: NominationResult,
  options: ReportEvidenceOptions,
): string {
  assertEvidenceProvenance(options);
  const selectedId = result.nomination?.policy.id;
  const champion = result.evaluations[0]?.evaluation.championMetrics;
  const synthetic = options.synthetic;
  const evidenceLabel = synthetic
    ? "## SYNTHETIC / DEMO ONLY"
    : "## Evidence classification";
  const evidenceText = synthetic
    ? "This fictional evidence cannot establish production readiness."
    : result.nomination
      ? "Development evidence is marked non-synthetic; holdout confirmation and manual review are still required."
      : "No nomination was created; evidence classification is not embedded in a nomination artifact.";
  const candidateTable = champion
    ? metricsTable(champion, result.evaluations)
    : "_No candidate evaluations were produced._";
  const failedGates = result.evaluations.length === 0
    ? "- No candidate evaluations were produced."
    : result.evaluations.map(({ policy, evaluation }) => gatesBlock(`\`${policy.id}\``, evaluation.gates)).join("\n");
  const fingerprints = result.evaluations.length === 0
    ? "- None"
    : policyFingerprints(result.evaluations);
  const frontier = result.frontier.length === 0
    ? "None"
    : result.frontier.map((id) => `\`${id}\``).join(", ");
  const statusReason = result.status === "NOMINATED"
    ? "The selected policy passed every development gate and won the deterministic frontier ordering."
    : "No candidate passed every preregistered development gate.";

  return [
    "# TASC Development Decision",
    "",
    evidenceLabel,
    "",
    evidenceText,
    "",
    `**Status:** ${result.status}`,
    "",
    `**Status reason:** ${statusReason}`,
    "",
    `**Selected candidate:** ${selectedId ? `\`${selectedId}\`` : "None"}`,
    "",
    `**Pareto frontier:** ${frontier}`,
    "",
    "## Champion vs candidates",
    "",
    candidateTable,
    "",
    "## Explicit failed gates",
    "",
    failedGates,
    "",
    "## Fingerprints",
    "",
    ...(result.nomination ? [
      `- Spec: \`${result.nomination.specDigest}\``,
      `- Development dataset: \`${result.nomination.developmentDatasetDigest}\``,
      `- Selected policy: \`${result.nomination.policyDigest}\``,
      `- Decision: \`${result.nomination.decisionDigest}\``,
      `- Nomination: \`${result.nomination.selfDigest}\``,
    ] : []),
    fingerprints,
    "",
    "## Manual boundary",
    "",
    "This report is decision support only. TASC does not mutate serving configuration; any rollout requires separate manual review.",
    "",
  ].join("\n");
}

export function buildConfirmationReport(
  result: ConfirmationResult,
  options: ReportEvidenceOptions,
): string {
  assertEvidenceProvenance(options);
  const synthetic = options.synthetic;
  return [
    "# TASC Holdout Confirmation",
    "",
    synthetic ? "## SYNTHETIC / DEMO ONLY" : "## Evidence classification",
    "",
    synthetic
      ? "This fictional evidence is a demonstration and cannot establish production readiness."
      : "See the status and status reason below for the evidence boundary.",
    "",
    `**Status:** ${result.status}`,
    "",
    `**Status reason:** ${result.statusReason}`,
    "",
    `**Exact frozen nominee:** \`${result.policy.id}\` (${result.policy.kind})`,
    "",
    "## Champion vs confirmed candidate",
    "",
    metricsTable(result.evaluation.championMetrics, [{
      policy: result.policy,
      evaluation: result.evaluation,
    }]),
    "",
    "## Explicit failed gates",
    "",
    gatesBlock(`\`${result.policy.id}\``, result.evaluation.gates),
    "",
    "## Fingerprints",
    "",
    `- Spec: \`${result.specDigest}\``,
    `- Holdout dataset: \`${result.holdoutDatasetDigest}\``,
    `- Nomination: \`${result.nominationDigest}\``,
    `- Policy: \`${result.policyDigest}\``,
    `- Decision: \`${result.decisionDigest}\``,
    "",
    "## Manual boundary",
    "",
    "Confirmation does not mutate a serving endpoint. Even READY_FOR_MANUAL_PRODUCTION requires separate manual review and rollout.",
    "",
  ].join("\n");
}

async function writeJson(path: string, value: unknown): Promise<void> {
  await writeFile(path, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

async function createFreshOutputDirectory(outDirectory: string): Promise<void> {
  await mkdir(dirname(outDirectory), { recursive: true });
  try {
    await mkdir(outDirectory);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "EEXIST") {
      throw new Error(`output directory "${outDirectory}" already exists; use a fresh --out path`);
    }
    throw error;
  }
}

export async function writeDevelopmentArtifacts(
  outDirectory: string,
  result: NominationResult,
  options: DevelopmentReportOptions,
): Promise<void> {
  assertDevelopmentContext(options);
  await createFreshOutputDirectory(outDirectory);
  await writeJson(join(outDirectory, "development-report.json"), result);
  await writeJson(join(outDirectory, "next-experiment.json"), proposeNextExperiment(result, options));
  await writeFile(join(outDirectory, "report.md"), buildDevelopmentReport(result, options), "utf8");
  if (result.nomination) {
    await writeJson(join(outDirectory, "nomination.json"), result.nomination);
  }
}

export async function writeConfirmationArtifacts(
  outDirectory: string,
  result: ConfirmationResult,
  options: ReportEvidenceOptions,
): Promise<void> {
  assertEvidenceProvenance(options);
  await createFreshOutputDirectory(outDirectory);
  await writeJson(join(outDirectory, "confirmation.json"), result);
  await writeFile(join(outDirectory, "report.md"), buildConfirmationReport(result, options), "utf8");
}
