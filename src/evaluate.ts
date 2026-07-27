import { createHmac, timingSafeEqual } from "node:crypto";
import { bootstrapMeanCI, median, type BootstrapCI } from "./statistics.js";
import { canonicalJson, compareCodeUnits } from "./determinism.js";
import { sha256 } from "./integrity.js";
import { assertMeasurementMatrix, type InferenceSpec, type MeasurementSet } from "./schema.js";
import {
  championPolicy,
  fingerprintPolicy,
  generateCandidatePolicies,
  replayPolicy,
  type InferencePolicy,
  type ReplayedRow,
} from "./policy.js";

export interface PolicyMetrics {
  meanTaskScore: number;
  successRate: number;
  errorRate: number;
  p50TtftMs: number;
  p95TtftMs: number;
  p50EndToEndLatencyMs: number;
  p95EndToEndLatencyMs: number;
  p99EndToEndLatencyMs: number;
  p10PerceivedTokensPerSecond: number;
  p50TotalTokensPerSecond: number;
  costPerRequestUsd: number;
  costPerThousandRequestsUsd: number;
  escalationRate: number;
  criticalSliceTaskScore: Record<string, number | null>;
}

export interface GateResult {
  id: string;
  pass: boolean;
  actual: number | null;
  threshold: number;
  comparison: ">=" | "<=";
  reason: string;
}

export interface PairedQualityResult {
  caseCount: number;
  deltas: number[];
  bootstrap: BootstrapCI;
}

export interface PolicyEvaluation {
  candidateMetrics: PolicyMetrics;
  championMetrics: PolicyMetrics;
  pairedQuality: PairedQualityResult;
  costImprovement: number | null;
  gates: GateResult[];
  passed: boolean;
}

export interface CandidateEvaluation {
  policy: InferencePolicy;
  evaluation: PolicyEvaluation;
}

export interface AttestationOptions {
  attestationKey?: string;
}

export interface NominationAttestation {
  algorithm: "hmac-sha256";
  digest: string;
}

export interface NominationArtifact {
  version: "tasc-nomination-v1";
  specDigest: string;
  developmentDatasetDigest: string;
  evaluator: MeasurementSet["evaluator"];
  developmentGroupIds: string[];
  developmentSynthetic: boolean;
  policy: InferencePolicy;
  policyDigest: string;
  candidateMetrics: PolicyMetrics;
  championMetrics: PolicyMetrics;
  gates: GateResult[];
  decisionDigest: string;
  selfDigest: string;
  attestation?: NominationAttestation;
}

export interface NominationResult {
  status: "NOMINATED" | "NO_CANDIDATE";
  evaluations: CandidateEvaluation[];
  frontier: string[];
  nomination?: NominationArtifact;
}

export interface ConfirmationResult {
  version: "tasc-confirmation-v1";
  status: "DEMO_ONLY" | "READY_FOR_MANUAL_PRODUCTION" | "HOLD";
  specDigest: string;
  holdoutDatasetDigest: string;
  nominationDigest: string;
  evaluator: MeasurementSet["evaluator"];
  holdoutGroupIds: string[];
  policy: InferencePolicy;
  policyDigest: string;
  evaluation: PolicyEvaluation;
  attestationVerified: boolean;
  statusReason: string;
  decisionDigest: string;
}

interface WeightedValue {
  value: number;
  weight: number;
}

function effectiveWeightedRows(rows: readonly ReplayedRow[]): Array<{ row: ReplayedRow; weight: number }> {
  const replicatesByCase = new Map<string, number>();
  for (const row of rows) {
    replicatesByCase.set(row.caseId, (replicatesByCase.get(row.caseId) ?? 0) + 1);
  }
  return rows.map((row) => ({
    row,
    weight: row.trafficWeight / replicatesByCase.get(row.caseId)!,
  }));
}

function weightedMean(values: readonly WeightedValue[]): number {
  const totalWeight = values.reduce((sum, entry) => sum + entry.weight, 0);
  if (totalWeight === 0) return 0;
  return values.reduce((sum, entry) => sum + entry.value * entry.weight, 0) / totalWeight;
}

/**
 * Deterministic inverse-CDF weighted quantile. Effective traffic weights, rather than
 * raw replicate counts, determine how much probability mass each recorded outcome owns.
 */
function weightedQuantile(values: readonly WeightedValue[], q: number): number {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((left, right) => left.value - right.value);
  const totalWeight = sorted.reduce((sum, entry) => sum + entry.weight, 0);
  if (totalWeight === 0) return sorted[0].value;
  const target = Math.min(1, Math.max(0, q)) * totalWeight;
  let cumulative = 0;
  for (const entry of sorted) {
    cumulative += entry.weight;
    if (cumulative >= target) return entry.value;
  }
  return sorted[sorted.length - 1].value;
}

export function computePolicyMetrics(rows: ReplayedRow[], criticalSlices: string[]): PolicyMetrics {
  const weightedRows = effectiveWeightedRows(rows);
  const values = (select: (row: ReplayedRow) => number): WeightedValue[] => (
    weightedRows.map(({ row, weight }) => ({ value: select(row), weight }))
  );
  const scoreValues = values((row) => row.status === "failure" ? 0 : row.taskScore);
  const costPerRequestUsd = weightedMean(values((row) => row.costUsd));
  const criticalSliceTaskScore: Record<string, number | null> = {};

  for (const slice of criticalSlices) {
    const sliceRows = weightedRows
      .filter(({ row }) => row.slices.includes(slice))
      .map(({ row, weight }) => ({ value: row.status === "failure" ? 0 : row.taskScore, weight }));
    criticalSliceTaskScore[slice] = sliceRows.length === 0 ? null : weightedMean(sliceRows);
  }

  return {
    meanTaskScore: weightedMean(scoreValues),
    successRate: weightedMean(values((row) => row.status === "success" ? 1 : 0)),
    errorRate: weightedMean(values((row) => row.status === "failure" ? 1 : 0)),
    p50TtftMs: weightedQuantile(values((row) => row.ttftMs), 0.5),
    p95TtftMs: weightedQuantile(values((row) => row.ttftMs), 0.95),
    p50EndToEndLatencyMs: weightedQuantile(values((row) => row.endToEndLatencyMs), 0.5),
    p95EndToEndLatencyMs: weightedQuantile(values((row) => row.endToEndLatencyMs), 0.95),
    p99EndToEndLatencyMs: weightedQuantile(values((row) => row.endToEndLatencyMs), 0.99),
    p10PerceivedTokensPerSecond: weightedQuantile(
      values((row) => row.status === "failure" ? 0 : row.perceivedTokensPerSecond),
      0.1,
    ),
    p50TotalTokensPerSecond: weightedQuantile(
      values((row) => row.status === "failure" ? 0 : row.totalTokensPerSecond),
      0.5,
    ),
    costPerRequestUsd,
    costPerThousandRequestsUsd: costPerRequestUsd * 1_000,
    escalationRate: weightedMean(values((row) => row.escalated ? 1 : 0)),
    criticalSliceTaskScore,
  };
}

function gate(
  id: string,
  actual: number | null,
  threshold: number,
  comparison: ">=" | "<=",
  absentReason?: string,
): GateResult {
  const pass = actual !== null && (comparison === ">=" ? actual >= threshold : actual <= threshold);
  const reason = actual === null
    ? (absentReason ?? `${id} has no measured value`)
    : `${id}: ${actual} ${pass ? "meets" : "does not meet"} required ${comparison} ${threshold}`;
  return { id, pass, actual, threshold, comparison, reason };
}

function caseScores(rows: readonly ReplayedRow[]): Map<string, number[]> {
  const byCase = new Map<string, number[]>();
  for (const row of rows) {
    const scores = byCase.get(row.caseId) ?? [];
    scores.push(row.status === "failure" ? 0 : row.taskScore);
    byCase.set(row.caseId, scores);
  }
  return byCase;
}

function evaluatePolicyInternal(
  candidateRows: ReplayedRow[],
  championRows: ReplayedRow[],
  spec: InferenceSpec,
  requireDevelopmentCostImprovement: boolean,
): PolicyEvaluation {
  const candidateByCase = caseScores(candidateRows);
  const championByCase = caseScores(championRows);
  const pairedCaseIds = [...candidateByCase.keys()]
    .filter((caseId) => championByCase.has(caseId))
    .sort(compareCodeUnits);
  if (pairedCaseIds.length < 3) {
    throw new Error(`at least 3 unique paired cases are required; received ${pairedCaseIds.length}`);
  }

  const deltas = pairedCaseIds.map((caseId) => (
    median(candidateByCase.get(caseId)!) - median(championByCase.get(caseId)!)
  ));
  const bootstrap = bootstrapMeanCI(deltas, {
    seed: spec.bootstrap.seed,
    iters: spec.bootstrap.iterations,
  });
  const candidateMetrics = computePolicyMetrics(candidateRows, spec.criticalSlices);
  const championMetrics = computePolicyMetrics(championRows, spec.criticalSlices);
  const championCost = championMetrics.costPerRequestUsd;
  const costImprovement = championCost === 0
    ? null
    : (championCost - candidateMetrics.costPerRequestUsd) / championCost;

  const gates: GateResult[] = [
    gate(
      "paired_quality_non_inferiority",
      bootstrap.lo,
      spec.constraints.nonInferiorityMargin,
      ">=",
    ),
    gate("mean_task_score", candidateMetrics.meanTaskScore, spec.constraints.taskScoreFloor, ">="),
    ...spec.criticalSlices.map((slice) => gate(
      `critical_slice:${slice}`,
      candidateMetrics.criticalSliceTaskScore[slice],
      spec.constraints.criticalSliceScoreFloor,
      ">=",
      `critical_slice:${slice} has no replayed rows and fails closed`,
    )),
    gate("p95_ttft", candidateMetrics.p95TtftMs, spec.constraints.maxP95TtftMs, "<="),
    gate(
      "p95_end_to_end_latency",
      candidateMetrics.p95EndToEndLatencyMs,
      spec.constraints.maxP95EndToEndLatencyMs,
      "<=",
    ),
    gate(
      "p10_perceived_tps",
      candidateMetrics.p10PerceivedTokensPerSecond,
      spec.constraints.minP10PerceivedTokensPerSecond,
      ">=",
    ),
    gate(
      "p50_total_tps",
      candidateMetrics.p50TotalTokensPerSecond,
      spec.constraints.minP50TotalTokensPerSecond,
      ">=",
    ),
    gate("error_rate", candidateMetrics.errorRate, spec.constraints.maxErrorRate, "<="),
    gate(
      "cost_per_thousand",
      candidateMetrics.costPerThousandRequestsUsd,
      spec.constraints.maxCostPerThousandRequests,
      "<=",
    ),
  ];

  if (requireDevelopmentCostImprovement) {
    const developmentCostGate = gate(
      "development_cost_improvement",
      costImprovement,
      spec.constraints.minimumCostImprovement,
      ">=",
      championCost === 0
        ? "development_cost_improvement is undefined because champion cost is zero and fails closed"
        : undefined,
    );
    gates.push(developmentCostGate);
  }

  return {
    candidateMetrics,
    championMetrics,
    pairedQuality: { caseCount: pairedCaseIds.length, deltas, bootstrap },
    costImprovement,
    gates,
    passed: gates.every((result) => result.pass),
  };
}

export function evaluatePolicy(
  candidateRows: ReplayedRow[],
  championRows: ReplayedRow[],
  spec: InferenceSpec,
): PolicyEvaluation {
  return evaluatePolicyInternal(candidateRows, championRows, spec, true);
}

function digest(value: unknown): string {
  return sha256(canonicalJson(value));
}

function dominates(left: PolicyMetrics, right: PolicyMetrics): boolean {
  const higherIsBetter: Array<keyof PolicyMetrics> = [
    "meanTaskScore",
    "p10PerceivedTokensPerSecond",
    "p50TotalTokensPerSecond",
  ];
  const lowerIsBetter: Array<keyof PolicyMetrics> = [
    "errorRate",
    "p95TtftMs",
    "p95EndToEndLatencyMs",
    "costPerRequestUsd",
  ];
  const neverWorse = (
    higherIsBetter.every((key) => (left[key] as number) >= (right[key] as number))
    && lowerIsBetter.every((key) => (left[key] as number) <= (right[key] as number))
  );
  const strictlyBetter = (
    higherIsBetter.some((key) => (left[key] as number) > (right[key] as number))
    || lowerIsBetter.some((key) => (left[key] as number) < (right[key] as number))
  );
  return neverWorse && strictlyBetter;
}

type NominationArtifactBody = Omit<NominationArtifact, "selfDigest" | "attestation">;

function artifactSelfDigest(artifact: NominationArtifactBody): string {
  return digest(artifact);
}

function validatedAttestationKey(key: string): Buffer {
  const bytes = Buffer.from(key, "utf8");
  if (bytes.byteLength < 32) {
    throw new Error("attestation key must be at least 32 UTF-8 bytes");
  }
  return bytes;
}

function attestationDigest(artifact: Omit<NominationArtifact, "attestation">, key: Buffer): string {
  return createHmac("sha256", key).update(canonicalJson(artifact)).digest("hex");
}

export function nominatePolicy(
  spec: InferenceSpec,
  dev: MeasurementSet,
  options: AttestationOptions = {},
): NominationResult {
  const attestationKey = options.attestationKey === undefined
    ? undefined
    : validatedAttestationKey(options.attestationKey);
  if (dev.dataset.split !== "dev") {
    throw new Error(`nomination requires development split "dev"; received "${dev.dataset.split}"`);
  }
  assertMeasurementMatrix(spec, dev);

  const champion = championPolicy(spec);
  const championRows = replayPolicy(champion, spec, dev);
  const evaluations = generateCandidatePolicies(spec).map((policy): CandidateEvaluation => ({
    policy,
    evaluation: evaluatePolicy(replayPolicy(policy, spec, dev), championRows, spec),
  }));
  const passers = evaluations.filter(({ evaluation }) => evaluation.passed);
  const frontierEntries = passers.filter((candidate) => (
    !passers.some((other) => (
      other.policy.id !== candidate.policy.id
      && dominates(other.evaluation.candidateMetrics, candidate.evaluation.candidateMetrics)
    ))
  ));
  const orderedFrontier = [...frontierEntries].sort((left, right) => (
    left.evaluation.candidateMetrics.costPerRequestUsd
      - right.evaluation.candidateMetrics.costPerRequestUsd
    || left.evaluation.candidateMetrics.p95EndToEndLatencyMs
      - right.evaluation.candidateMetrics.p95EndToEndLatencyMs
    || compareCodeUnits(left.policy.id, right.policy.id)
  ));
  const frontier = frontierEntries.map(({ policy }) => policy.id).sort(compareCodeUnits);

  if (orderedFrontier.length === 0) {
    return { status: "NO_CANDIDATE", evaluations, frontier, nomination: undefined };
  }

  const selected = orderedFrontier[0];
  const specDigest = digest(spec);
  const policyDigest = fingerprintPolicy(selected.policy);
  const decisionDigest = digest({
    evaluations,
    frontier,
    selectedPolicyId: selected.policy.id,
  });
  const artifactBody: NominationArtifactBody = {
    version: "tasc-nomination-v1",
    specDigest,
    developmentDatasetDigest: digest(dev),
    evaluator: structuredClone(dev.evaluator),
    developmentGroupIds: [...new Set(dev.cases.map((measurementCase) => measurementCase.groupId))]
      .sort(compareCodeUnits),
    developmentSynthetic: dev.dataset.synthetic,
    policy: structuredClone(selected.policy),
    policyDigest,
    candidateMetrics: structuredClone(selected.evaluation.candidateMetrics),
    championMetrics: structuredClone(selected.evaluation.championMetrics),
    gates: structuredClone(selected.evaluation.gates),
    decisionDigest,
  };
  const unsignedArtifact: Omit<NominationArtifact, "attestation"> = {
    ...artifactBody,
    selfDigest: artifactSelfDigest(artifactBody),
  };

  return {
    status: "NOMINATED",
    evaluations,
    frontier,
    nomination: {
      ...unsignedArtifact,
      ...(attestationKey === undefined ? {} : {
        attestation: {
          algorithm: "hmac-sha256",
          digest: attestationDigest(unsignedArtifact, attestationKey),
        } satisfies NominationAttestation,
      }),
    },
  };
}

function assertNominationSelfDigest(nomination: NominationArtifact): void {
  const { selfDigest, attestation: _attestation, ...body } = nomination;
  if (selfDigest !== artifactSelfDigest(body)) {
    throw new Error("nomination self-digest mismatch: artifact was edited after development selection");
  }
}

function verifyNominationAttestation(nomination: NominationArtifact, key: Buffer): void {
  const { attestation, ...unsignedArtifact } = nomination;
  const suppliedDigest = attestation?.digest;
  const expectedDigest = attestationDigest(unsignedArtifact, key);
  if (
    attestation?.algorithm !== "hmac-sha256"
    || suppliedDigest === undefined
    || !/^[a-f0-9]{64}$/.test(suppliedDigest)
  ) {
    throw new Error("nomination attestation mismatch");
  }
  const suppliedBytes = Buffer.from(suppliedDigest, "hex");
  const expectedBytes = Buffer.from(expectedDigest, "hex");
  if (!timingSafeEqual(suppliedBytes, expectedBytes)) {
    throw new Error("nomination attestation mismatch");
  }
}

function evaluatorMatches(
  left: MeasurementSet["evaluator"],
  right: MeasurementSet["evaluator"],
): boolean {
  return (
    left.id === right.id
    && left.version === right.version
    && left.kind === right.kind
    && left.validated === right.validated
  );
}

export function confirmNomination(
  spec: InferenceSpec,
  holdout: MeasurementSet,
  nomination: NominationArtifact,
  options: AttestationOptions = {},
): ConfirmationResult {
  const attestationKey = options.attestationKey === undefined
    ? undefined
    : validatedAttestationKey(options.attestationKey);
  if (holdout.dataset.split !== "holdout") {
    throw new Error(`confirmation requires holdout split "holdout"; received "${holdout.dataset.split}"`);
  }
  if (attestationKey !== undefined) {
    verifyNominationAttestation(nomination, attestationKey);
  }
  assertNominationSelfDigest(nomination);
  const attestationVerified = attestationKey !== undefined;

  const specDigest = digest(spec);
  if (nomination.specDigest !== specDigest) {
    throw new Error("spec digest mismatch: nomination was produced from a different inference spec");
  }
  if (nomination.policyDigest !== fingerprintPolicy(nomination.policy)) {
    throw new Error("policy digest mismatch: nominated policy body was edited");
  }

  const regenerated = generateCandidatePolicies(spec).find((candidate) => (
    candidate.id === nomination.policy.id
    && fingerprintPolicy(candidate) === nomination.policyDigest
    && canonicalJson(candidate) === canonicalJson(nomination.policy)
  ));
  if (!regenerated) {
    throw new Error("policy drift: nomination does not exactly match a regenerated candidate");
  }
  if (!evaluatorMatches(nomination.evaluator, holdout.evaluator)) {
    throw new Error("evaluator drift: holdout evaluator identity, version, kind, and validation must match development");
  }

  const developmentGroups = new Set(nomination.developmentGroupIds);
  const leakedGroups = [...new Set(
    holdout.cases
      .map((measurementCase) => measurementCase.groupId)
      .filter((groupId) => developmentGroups.has(groupId)),
  )].sort(compareCodeUnits);
  if (leakedGroups.length > 0) {
    throw new Error(`development/holdout group leakage: ${leakedGroups.join(", ")}`);
  }
  assertMeasurementMatrix(spec, holdout);

  const championRows = replayPolicy(championPolicy(spec), spec, holdout);
  const candidateRows = replayPolicy(regenerated, spec, holdout);
  const evaluation = evaluatePolicyInternal(candidateRows, championRows, spec, false);
  let status: ConfirmationResult["status"];
  let statusReason: string;
  if (!evaluation.passed) {
    status = "HOLD";
    const failedGateIds = evaluation.gates.filter((gateResult) => !gateResult.pass).map((gateResult) => gateResult.id);
    statusReason = `Holdout hard gates failed: ${failedGateIds.join(", ")}`;
  } else if (nomination.developmentSynthetic || holdout.dataset.synthetic) {
    status = "DEMO_ONLY";
    statusReason = "Passing gates are demo-only because development or holdout evidence is synthetic";
  } else if (attestationVerified) {
    status = "READY_FOR_MANUAL_PRODUCTION";
    statusReason = "Passing real evidence has a verified nomination attestation; manual production review is required";
  } else {
    status = "HOLD";
    statusReason = "Production readiness requires a verified nomination attestation";
  }
  const confirmationBody = {
    version: "tasc-confirmation-v1" as const,
    status,
    specDigest,
    holdoutDatasetDigest: digest(holdout),
    nominationDigest: nomination.selfDigest,
    evaluator: structuredClone(holdout.evaluator),
    holdoutGroupIds: [...new Set(holdout.cases.map((measurementCase) => measurementCase.groupId))]
      .sort(compareCodeUnits),
    policy: structuredClone(regenerated),
    policyDigest: nomination.policyDigest,
    evaluation,
    attestationVerified,
    statusReason,
  };
  return {
    ...confirmationBody,
    decisionDigest: digest(confirmationBody),
  };
}
