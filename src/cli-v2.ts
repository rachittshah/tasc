import { createReadStream } from "node:fs";
import { basename, dirname, resolve } from "node:path";
import {
  assessPolicyWindow,
  confirmHoldout,
  nominateDevelopment,
  parseAssessmentDecision,
  parsePolicyBundle,
  revalidateDevelopmentNomination,
  type FrozenAssessmentDecision,
  type FrozenDevelopmentNomination,
} from "./assessment.js";
import {
  parseAssessmentContext,
  type AssessmentContext,
} from "./assessment-context.js";
import {
  NO_DEPLOYMENT_AUTHORITY,
  writeArtifactPacket,
  type ArtifactWriteResult,
} from "./artifacts.js";
import {
  BoundedInputError,
  readBoundedJson,
  readBoundedNdjson,
  type BoundedInputErrorCode,
  type BoundedJsonLimits,
  type BoundedNdjsonLimits,
} from "./bounded-input.js";
import type {
  AssessDevelopmentCommand,
  AssessHoldoutCommand,
  AssessWindowCommand,
  EvidenceValidateCommand,
  ExperimentNextCommand,
  ProtocolValidateCommand,
  TracesValidateCommand,
} from "./cli-args.js";
import { canonicalJson } from "./determinism.js";
import {
  fingerprintProtocol,
  parseEvaluatorEvidence,
  parseExperimentProtocol,
  parseTraceEnvelope,
  type EvaluatorEvidence,
  type ExperimentProtocol,
  type TraceEnvelope,
} from "./evidence.js";
import {
  joinAssessmentEvidence,
  requireAssessmentDatasetSplit,
} from "./evidence-join.js";
import {
  fingerprintEvaluatorRevocations,
  fingerprintEvaluatorTrustPolicy,
  parseEvaluatorTrustSnapshot,
  verifyEvaluatorEvidence,
  type EvaluatorEvidenceVerification,
  type EvaluatorTrustSnapshot,
} from "./evaluator-trust.js";
import {
  parseExperimentBudget,
  parseExperimentHistory,
  proposeExperiment,
} from "./experiments.js";
import { parseWindowManifest } from "./window.js";
import type { WorkBudget } from "./work-budget.js";

export type CliInputLabel =
  | "assessment"
  | "budget"
  | "context"
  | "development-context"
  | "development-evidence"
  | "development-traces"
  | "evidence"
  | "history"
  | "nomination"
  | "policy"
  | "protocol"
  | "traces"
  | "trust"
  | "window"
  | "work-budget";

export type CliInputFailureDetail =
  | BoundedInputErrorCode
  | "context-mismatch"
  | "contract-invalid"
  | "trust-rejected";

/** A fixed-field input failure safe to render without provider/source text. */
export class CliInputError extends Error {
  readonly input: CliInputLabel;
  readonly detail: CliInputFailureDetail;
  readonly line: number | undefined;

  constructor(
    input: CliInputLabel,
    detail: CliInputFailureDetail,
    line?: number,
  ) {
    super("Input validation failed.");
    this.name = "CliInputError";
    this.input = input;
    this.detail = detail;
    this.line =
      Number.isSafeInteger(line) && (line ?? 0) >= 1 ? line : undefined;
  }
}

/** An atomic publication/freshness failure with no path-bearing details. */
export class CliOutputError extends Error {
  constructor() {
    super("Artifact publication failed.");
    this.name = "CliOutputError";
  }
}

export type CliV2Command =
  | ProtocolValidateCommand
  | TracesValidateCommand
  | EvidenceValidateCommand
  | AssessDevelopmentCommand
  | AssessHoldoutCommand
  | AssessWindowCommand
  | ExperimentNextCommand;

export interface CliV2Result {
  readonly version: "tasc-cli-result-v1";
  readonly command: string;
  readonly status: string;
  readonly authority: typeof NO_DEPLOYMENT_AUTHORITY;
  readonly [key: string]: unknown;
}

export interface HoldoutNominationLineage {
  readonly version: "tasc-holdout-nomination-lineage-v1";
  readonly relationship: "holdout-confirms-development-nomination";
  readonly nominationDecisionDigest: string;
  readonly developmentAssessmentContextDigest: string;
  readonly developmentDatasetDigest: string;
  readonly developmentTraceSetDigest: string;
  readonly developmentEvaluatorSetDigest: string;
  readonly protocolDigest: string;
  readonly selectedPolicyDigest: string;
  readonly attestation: "unattested";
  readonly authority: typeof NO_DEPLOYMENT_AUTHORITY;
}

const MAX_CLI_ROWS = 100_000;

const WORK_BUDGET_JSON_LIMITS: BoundedJsonLimits = Object.freeze({
  maxBytes: 16 * 1024,
  maxDepth: 4,
  maxObjectKeys: 16,
  maxArrayItems: 0,
  maxTokens: 128,
  maxDecodedStringLength: 128,
  maxNumericTokenLength: 32,
  maxDiagnosticSnippetLength: 0,
});

const CONTRACT_JSON_LIMITS: BoundedJsonLimits = Object.freeze({
  maxBytes: 16 * 1024 * 1024,
  maxDepth: 64,
  maxObjectKeys: 131_072,
  maxArrayItems: 100_000,
  maxTokens: 2_000_000,
  maxDecodedStringLength: 1_048_576,
  maxNumericTokenLength: 128,
  maxDiagnosticSnippetLength: 0,
});

function rowLimits(maxItems: number): BoundedNdjsonLimits {
  return Object.freeze({
    maxBytes: 128 * 1024 * 1024,
    maxDepth: 64,
    maxObjectKeys: 65_536,
    maxArrayItems: 65_536,
    maxTokens: 1_000_000,
    maxDecodedStringLength: 1_048_576,
    maxNumericTokenLength: 128,
    maxDiagnosticSnippetLength: 0,
    maxLineBytes: 8 * 1024 * 1024,
    maxItems: Math.min(maxItems, MAX_CLI_ROWS),
  });
}

async function readJsonInput(
  path: string,
  input: CliInputLabel,
  limits: BoundedJsonLimits = CONTRACT_JSON_LIMITS,
): Promise<unknown> {
  try {
    return await readBoundedJson(createReadStream(path), limits);
  } catch (error) {
    if (error instanceof BoundedInputError) {
      throw new CliInputError(input, error.code, error.line);
    }
    throw new CliInputError(input, "contract-invalid");
  }
}

async function readNdjsonInput(
  path: string,
  input: CliInputLabel,
  limits: BoundedNdjsonLimits,
): Promise<readonly unknown[]> {
  try {
    return await readBoundedNdjson(createReadStream(path), limits);
  } catch (error) {
    if (error instanceof BoundedInputError) {
      throw new CliInputError(input, error.code, error.line);
    }
    throw new CliInputError(input, "contract-invalid");
  }
}

function parseInput<T>(
  input: CliInputLabel,
  parse: () => T,
  line?: number,
): T {
  try {
    return parse();
  } catch {
    throw new CliInputError(input, "contract-invalid", line);
  }
}

const WORK_BUDGET_FIELDS = [
  "maxCandidates",
  "maxTraceRows",
  "maxEvidenceRows",
  "maxBootstrapDraws",
  "maxIndependentGroups",
  "maxAssessmentWork",
] as const satisfies readonly (keyof WorkBudget)[];

function parseWorkBudget(input: unknown): Readonly<WorkBudget> {
  if (input === null || typeof input !== "object") {
    throw new Error("work budget must be an object");
  }
  const prototype = Reflect.getPrototypeOf(input);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new Error("work budget must be a plain object");
  }
  const keys = Reflect.ownKeys(input);
  if (
    keys.length !== WORK_BUDGET_FIELDS.length
    || keys.some((key) =>
      typeof key !== "string"
      || !WORK_BUDGET_FIELDS.includes(key as keyof WorkBudget)
    )
  ) {
    throw new Error("work budget must have the exact v2 fields");
  }
  const values: number[] = [];
  for (const field of WORK_BUDGET_FIELDS) {
    const descriptor = Reflect.getOwnPropertyDescriptor(input, field);
    if (
      descriptor === undefined
      || !descriptor.enumerable
      || !Object.hasOwn(descriptor, "value")
      || !Number.isSafeInteger(descriptor.value)
      || descriptor.value < 0
    ) {
      throw new Error("work budget fields must be safe non-negative integers");
    }
    values.push(descriptor.value as number);
  }
  return Object.freeze({
    maxCandidates: values[0]!,
    maxTraceRows: values[1]!,
    maxEvidenceRows: values[2]!,
    maxBootstrapDraws: values[3]!,
    maxIndependentGroups: values[4]!,
    maxAssessmentWork: values[5]!,
  });
}

async function loadWorkBudget(path: string): Promise<Readonly<WorkBudget>> {
  const input = await readJsonInput(
    path,
    "work-budget",
    WORK_BUDGET_JSON_LIMITS,
  );
  return parseInput("work-budget", () => parseWorkBudget(input));
}

async function loadProtocol(
  path: string,
  budget: WorkBudget,
): Promise<ExperimentProtocol> {
  const input = await readJsonInput(path, "protocol");
  return parseInput(
    "protocol",
    () => parseExperimentProtocol(input, budget),
  );
}

async function loadTraces(
  path: string,
  label: "traces" | "development-traces",
  budget: WorkBudget,
): Promise<readonly TraceEnvelope[]> {
  const inputs = await readNdjsonInput(
    path,
    label,
    rowLimits(budget.maxTraceRows),
  );
  return Object.freeze(inputs.map((input, index) =>
    parseInput(
      label,
      () => parseTraceEnvelope(input, budget),
      index + 1,
    )
  ));
}

async function loadEvidence(
  path: string,
  label: "evidence" | "development-evidence",
  budget: WorkBudget,
): Promise<readonly EvaluatorEvidence[]> {
  const inputs = await readNdjsonInput(
    path,
    label,
    rowLimits(budget.maxEvidenceRows),
  );
  return Object.freeze(inputs.map((input, index) =>
    parseInput(
      label,
      () => parseEvaluatorEvidence(input, budget),
      index + 1,
    )
  ));
}

interface TrustContext {
  readonly trust: EvaluatorTrustSnapshot;
  readonly context: AssessmentContext;
}

async function loadTrustContext(
  trustPath: string,
  contextPath: string,
  contextLabel: "context" | "development-context",
): Promise<TrustContext> {
  const trustInput = await readJsonInput(trustPath, "trust");
  const trust = parseInput(
    "trust",
    () => parseEvaluatorTrustSnapshot(trustInput),
  );
  const contextInput = await readJsonInput(contextPath, contextLabel);
  const context = parseInput(
    contextLabel,
    () => parseAssessmentContext(contextInput),
  );
  if (
    fingerprintEvaluatorTrustPolicy(trust)
      !== context.operatorTrustPolicySnapshotDigest
    || fingerprintEvaluatorRevocations(trust)
      !== context.evaluatorRevocationSnapshotDigest
  ) {
    throw new CliInputError(contextLabel, "context-mismatch");
  }
  return Object.freeze({ trust, context });
}

function verifyEvidenceRows(
  evidence: readonly EvaluatorEvidence[],
  trustContext: TrustContext,
): readonly EvaluatorEvidenceVerification[] {
  return Object.freeze(evidence.map((row) =>
    verifyEvaluatorEvidence(
      row,
      trustContext.trust,
      trustContext.context,
    )
  ));
}

async function loadJoinedDataset(
  protocol: ExperimentProtocol,
  tracePath: string,
  evidencePath: string,
  labels: {
    readonly traces: "traces" | "development-traces";
    readonly evidence: "evidence" | "development-evidence";
  },
  trustContext: TrustContext,
  budget: WorkBudget,
): Promise<ReturnType<typeof joinAssessmentEvidence>> {
  const traces = await loadTraces(tracePath, labels.traces, budget);
  const evidence = await loadEvidence(
    evidencePath,
    labels.evidence,
    budget,
  );
  const receipts = verifyEvidenceRows(evidence, trustContext);
  return parseInput(
    "assessment",
    () => joinAssessmentEvidence(protocol, traces, receipts, budget),
  );
}

function artifactSummary(write: ArtifactWriteResult): Readonly<{
  manifestDigest: string;
  packetDigest: string;
  durability: "full" | "degraded";
  limitations: readonly string[];
}> {
  return Object.freeze({
    manifestDigest: write.manifest.manifestDigest,
    packetDigest: write.manifest.packetDigest,
    durability: write.durability.level,
    limitations: write.durability.limitations,
  });
}

async function publishPacket(
  outputPath: string,
  input: Parameters<typeof writeArtifactPacket>[2],
): Promise<ArtifactWriteResult> {
  const absolute = resolve(outputPath);
  try {
    return await writeArtifactPacket(
      dirname(absolute),
      basename(absolute),
      input,
    );
  } catch {
    throw new CliOutputError();
  }
}

async function publishAssessment(
  command: "assess development" | "assess holdout" | "assess window",
  kind:
    | "development-assessment"
    | "holdout-assessment"
    | "window-assessment",
  outputPath: string,
  decision: FrozenAssessmentDecision,
  nominationLineage: HoldoutNominationLineage | null = null,
): Promise<CliV2Result> {
  const files: Parameters<typeof writeArtifactPacket>[2]["files"][number][] = [
    {
      name: "assessment.json",
      bytes: `${canonicalJson(decision)}\n`,
      mediaType: "application/json",
      schemaVersion: decision.version,
    },
  ];
  if (decision.selectedPolicy !== null) {
    files.push({
      name: "policy.json",
      bytes: `${canonicalJson(decision.selectedPolicy)}\n`,
      mediaType: "application/json",
      schemaVersion: decision.selectedPolicy.version,
    });
  }
  if (nominationLineage !== null) {
    files.push({
      name: "nomination-lineage.json",
      bytes: `${canonicalJson(nominationLineage)}\n`,
      mediaType: "application/json",
      schemaVersion: nominationLineage.version,
    });
  }
  const write = await publishPacket(outputPath, {
    descriptor: {
      version: "tasc-artifact-packet-v1",
      kind,
      assessmentDecisionDigest: decision.decisionDigest,
      assessmentContextDigest: decision.assessmentContextDigest,
      attestation: "unattested",
    },
    files,
  });
  return Object.freeze({
    version: "tasc-cli-result-v1",
    command,
    status: decision.status,
    decisionDigest: decision.decisionDigest,
    protocolDigest: decision.protocolDigest,
    assessmentContextDigest: decision.assessmentContextDigest,
    selectedPolicyDigest: decision.selectedPolicyDigest,
    ...(nominationLineage === null
      ? {}
      : { nominationDecisionDigest: nominationLineage.nominationDecisionDigest }),
    artifact: artifactSummary(write),
    attestation: "unattested",
    authority: NO_DEPLOYMENT_AUTHORITY,
  });
}

function holdoutNominationLineage(
  nomination: FrozenDevelopmentNomination,
): HoldoutNominationLineage {
  return Object.freeze({
    version: "tasc-holdout-nomination-lineage-v1",
    relationship: "holdout-confirms-development-nomination",
    nominationDecisionDigest: nomination.decisionDigest,
    developmentAssessmentContextDigest:
      nomination.assessmentContextDigest,
    developmentDatasetDigest: nomination.datasetDigest,
    developmentTraceSetDigest: nomination.traceSetDigest,
    developmentEvaluatorSetDigest: nomination.evaluatorSetDigest,
    protocolDigest: nomination.protocolDigest,
    selectedPolicyDigest: nomination.selectedPolicyDigest,
    attestation: "unattested",
    authority: NO_DEPLOYMENT_AUTHORITY,
  });
}

async function validateProtocolCommand(
  command: ProtocolValidateCommand,
): Promise<CliV2Result> {
  const budget = await loadWorkBudget(command.workBudget);
  const protocol = await loadProtocol(command.protocol, budget);
  return Object.freeze({
    version: "tasc-cli-result-v1",
    command: "protocol validate",
    status: "VALID",
    protocolDigest: fingerprintProtocol(protocol),
    authority: NO_DEPLOYMENT_AUTHORITY,
  });
}

async function validateTracesCommand(
  command: TracesValidateCommand,
): Promise<CliV2Result> {
  const budget = await loadWorkBudget(command.workBudget);
  const traces = await loadTraces(command.traces, "traces", budget);
  return Object.freeze({
    version: "tasc-cli-result-v1",
    command: "traces validate",
    status: "VALID",
    count: traces.length,
    scope: "contract-only-no-protocol-admission",
    authority: NO_DEPLOYMENT_AUTHORITY,
  });
}

async function validateEvidenceCommand(
  command: EvidenceValidateCommand,
): Promise<CliV2Result> {
  const budget = await loadWorkBudget(command.workBudget);
  const trustContext = await loadTrustContext(
    command.trust,
    command.context,
    "context",
  );
  const evidence = await loadEvidence(
    command.evidence,
    "evidence",
    budget,
  );
  const receipts = verifyEvidenceRows(evidence, trustContext);
  const rejectedLine = receipts.findIndex(({ trusted }) => !trusted);
  if (rejectedLine >= 0) {
    throw new CliInputError(
      "evidence",
      "trust-rejected",
      rejectedLine + 1,
    );
  }
  return Object.freeze({
    version: "tasc-cli-result-v1",
    command: "evidence validate",
    status: "VALID",
    count: evidence.length,
    trustedCount: receipts.length,
    scope: "signature-and-local-trust-only",
    authority: NO_DEPLOYMENT_AUTHORITY,
  });
}

async function assessDevelopmentCommand(
  command: AssessDevelopmentCommand,
): Promise<CliV2Result> {
  const budget = await loadWorkBudget(command.workBudget);
  const protocol = await loadProtocol(command.protocol, budget);
  const trustContext = await loadTrustContext(
    command.trust,
    command.context,
    "context",
  );
  const joinedDataset = await loadJoinedDataset(
    protocol,
    command.traces,
    command.evidence,
    { traces: "traces", evidence: "evidence" },
    trustContext,
    budget,
  );
  const dataset = parseInput(
    "assessment",
    () => requireAssessmentDatasetSplit(joinedDataset, "dev"),
  );
  const decision = parseInput(
    "assessment",
    () => nominateDevelopment(
      protocol,
      dataset,
      trustContext.context,
      budget,
    ),
  );
  return publishAssessment(
    "assess development",
    "development-assessment",
    command.out,
    decision,
  );
}

async function assessHoldoutCommand(
  command: AssessHoldoutCommand,
): Promise<CliV2Result> {
  const budget = await loadWorkBudget(command.workBudget);
  const protocol = await loadProtocol(command.protocol, budget);
  const developmentTrustContext = await loadTrustContext(
    command.developmentTrust,
    command.developmentContext,
    "development-context",
  );
  const joinedDevelopmentDataset = await loadJoinedDataset(
    protocol,
    command.developmentTraces,
    command.developmentEvidence,
    {
      traces: "development-traces",
      evidence: "development-evidence",
    },
    developmentTrustContext,
    budget,
  );
  const developmentDataset = parseInput(
    "assessment",
    () => requireAssessmentDatasetSplit(joinedDevelopmentDataset, "dev"),
  );
  const persistedNomination = await readJsonInput(
    command.nomination,
    "nomination",
  );
  const nomination = parseInput(
    "nomination",
    () => revalidateDevelopmentNomination(
      protocol,
      developmentDataset,
      persistedNomination,
      developmentTrustContext.context,
      budget,
    ),
  );

  const holdoutTrustContext = await loadTrustContext(
    command.trust,
    command.context,
    "context",
  );
  const joinedHoldoutDataset = await loadJoinedDataset(
    protocol,
    command.traces,
    command.evidence,
    { traces: "traces", evidence: "evidence" },
    holdoutTrustContext,
    budget,
  );
  const holdoutDataset = parseInput(
    "assessment",
    () => requireAssessmentDatasetSplit(
      joinedHoldoutDataset,
      "holdout",
    ),
  );
  const decision = parseInput(
    "assessment",
    () => confirmHoldout(
      protocol,
      holdoutDataset,
      nomination,
      holdoutTrustContext.context,
      budget,
    ),
  );
  return publishAssessment(
    "assess holdout",
    "holdout-assessment",
    command.out,
    decision,
    holdoutNominationLineage(nomination),
  );
}

async function assessWindowCommand(
  command: AssessWindowCommand,
): Promise<CliV2Result> {
  const budget = await loadWorkBudget(command.workBudget);
  const protocol = await loadProtocol(command.protocol, budget);
  const trustContext = await loadTrustContext(
    command.trust,
    command.context,
    "context",
  );
  const joinedDataset = await loadJoinedDataset(
    protocol,
    command.traces,
    command.evidence,
    { traces: "traces", evidence: "evidence" },
    trustContext,
    budget,
  );
  const dataset = parseInput(
    "assessment",
    () => requireAssessmentDatasetSplit(joinedDataset, "online"),
  );
  const policyInput = await readJsonInput(command.policy, "policy");
  const policy = parseInput(
    "policy",
    () => parsePolicyBundle(policyInput),
  );
  const windowInput = await readJsonInput(command.window, "window");
  const manifest = parseInput(
    "window",
    () => parseWindowManifest(windowInput),
  );
  const decision = parseInput(
    "assessment",
    () => assessPolicyWindow(
      protocol,
      dataset,
      policy,
      manifest,
      trustContext.context,
      budget,
    ),
  );
  return publishAssessment(
    "assess window",
    "window-assessment",
    command.out,
    decision,
  );
}

async function experimentNextCommand(
  command: ExperimentNextCommand,
): Promise<CliV2Result> {
  const assessmentInput = await readJsonInput(
    command.assessment,
    "assessment",
  );
  const assessment = parseInput(
    "assessment",
    () => parseAssessmentDecision(assessmentInput),
  );
  const historyInput = await readJsonInput(command.history, "history");
  const history = parseInput(
    "history",
    () => parseExperimentHistory(historyInput),
  );
  const budgetInput = await readJsonInput(command.budget, "budget");
  const budget = parseInput(
    "budget",
    () => parseExperimentBudget(budgetInput),
  );
  const proposal = parseInput(
    "assessment",
    () => proposeExperiment(assessment, history, budget),
  );
  const write = await publishPacket(command.out, {
    descriptor: {
      version: "tasc-artifact-packet-v1",
      kind: "experiment-proposal",
      assessmentDecisionDigest: proposal.parentAssessmentDigest,
      assessmentContextDigest: assessment.assessmentContextDigest,
      attestation: "unattested",
    },
    files: [
      {
        name: "experiment-proposal.json",
        bytes: `${canonicalJson(proposal)}\n`,
        mediaType: "application/json",
        schemaVersion: proposal.version,
      },
    ],
  });
  return Object.freeze({
    version: "tasc-cli-result-v1",
    command: "experiment next",
    status: proposal.status,
    decisionDigest: proposal.decisionDigest,
    parentAssessmentDigest: proposal.parentAssessmentDigest,
    parentProtocolDigest: proposal.parentProtocolDigest,
    artifact: artifactSummary(write),
    attestation: "unattested",
    authority: NO_DEPLOYMENT_AUTHORITY,
  });
}

/** Execute one already-parsed v2 command without ambient process authority. */
export async function executeCliV2(
  command: CliV2Command,
): Promise<CliV2Result> {
  switch (command.kind) {
    case "protocol-validate":
      return validateProtocolCommand(command);
    case "traces-validate":
      return validateTracesCommand(command);
    case "evidence-validate":
      return validateEvidenceCommand(command);
    case "assess-development":
      return assessDevelopmentCommand(command);
    case "assess-holdout":
      return assessHoldoutCommand(command);
    case "assess-window":
      return assessWindowCommand(command);
    case "experiment-next":
      return experimentNextCommand(command);
  }
}
