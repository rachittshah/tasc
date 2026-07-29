import { Buffer } from "node:buffer";
import {
  createPrivateKey,
  createPublicKey,
  createSecretKey,
  sign as signBytes,
  type KeyObject,
} from "node:crypto";
import { createReadStream } from "node:fs";
import { lstat, realpath } from "node:fs/promises";
import {
  basename,
  dirname,
  isAbsolute,
  join,
  normalize,
  parse as parsePath,
  resolve,
  sep,
} from "node:path";
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
  RuntimeProbeCommand,
  ShadowRunCommand,
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
import {
  createStudyPayloadIdentity,
} from "./references.js";
import {
  RuntimeInvocationInputError,
  type RuntimeInvocationInput,
  type RuntimeInvocationRoute,
} from "./runtime/invoke.js";
import {
  authorizeCollectorRequest,
  fingerprintCollectorEndpointBinding,
  parseCollectorTrustPolicy,
  type CollectorTrustPolicy,
} from "./runtime/network-policy.js";
import { parseEndpointDescriptor } from "./runtime/orchestration.js";
import {
  probeRuntimeCapability,
  RuntimeProbeInputError,
} from "./runtime/probe.js";
import {
  getRuntimeProfile,
  parseRuntimeInstanceIdentity,
} from "./runtime/profiles.js";
import {
  runShadowCollection,
  type CollectorAttestationSigner,
  type DispatchIntentSigner,
  type ShadowCaseInput,
  type ShadowProfileTarget,
  type ShadowRunInput,
} from "./runtime/shadow.js";
import {
  parseShadowRunPlan,
  type ShadowRunPlan,
  type ShadowRunPlanCollectionTarget,
} from "./shadow-plan.js";
import type {
  RuntimeSecretHeaderFactory,
  RuntimeSecretHeaderName,
  RuntimeHttpLimits,
  RuntimeWireDispatchState,
} from "./runtime/http.js";
import type {
  EndpointDescriptor,
  RuntimeInstanceIdentity,
} from "./runtime/types.js";
import type { PersistedErrorCategory } from "./redaction.js";
import { parseWindowManifest } from "./window.js";
import type { WorkBudget } from "./work-budget.js";

export type CliInputLabel =
  | "assessment"
  | "budget"
  | "context"
  | "development-context"
  | "development-evidence"
  | "development-traces"
  | "endpoint"
  | "evidence"
  | "history"
  | "identity"
  | "nomination"
  | "policy"
  | "plan"
  | "profiles"
  | "protocol"
  | "runtime"
  | "shadow"
  | "cases"
  | "traces"
  | "trust"
  | "window"
  | "work-budget";

export type CliInputFailureDetail =
  | BoundedInputErrorCode
  | "context-mismatch"
  | "contract-invalid"
  | "runtime-rejected"
  | "secret-invalid"
  | "secret-unavailable"
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

export type CliRuntimeOperation = "runtime-probe" | "shadow-run";

/** A provider-safe runtime failure with no source, endpoint, or secret text. */
export class CliRuntimeError extends Error {
  readonly operation: CliRuntimeOperation;
  readonly detail: PersistedErrorCategory | "runtime-rejected";
  readonly dispatchState: RuntimeWireDispatchState | "not-applicable";

  constructor(
    operation: CliRuntimeOperation,
    detail: PersistedErrorCategory | "runtime-rejected",
    dispatchState: RuntimeWireDispatchState | "not-applicable",
  ) {
    super("Runtime operation failed.");
    this.name = "CliRuntimeError";
    this.operation = operation;
    this.detail = detail;
    this.dispatchState = dispatchState;
  }
}

export type CliV2Command =
  | ProtocolValidateCommand
  | TracesValidateCommand
  | EvidenceValidateCommand
  | AssessDevelopmentCommand
  | AssessHoldoutCommand
  | AssessWindowCommand
  | ExperimentNextCommand
  | RuntimeProbeCommand
  | ShadowRunCommand;

export interface CliV2ExecutionContext {
  /**
   * Resolve only an already-validated environment-variable name. The returned
   * value is used ephemerally and must never be persisted or reflected.
   */
  readonly readSecretEnvironmentVariable?: (
    name: string,
  ) => string | undefined;
  /** Caller-owned cancellation for effectful runtime operations. */
  readonly signal?: AbortSignal;
}

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

const CLI_ENDPOINT_VERSION = "tasc-cli-runtime-endpoint-v1" as const;
const CLI_SHADOW_PROFILES_VERSION =
  "tasc-cli-shadow-profiles-v2" as const;
const CLI_SHADOW_IDENTITY_VERSION =
  "tasc-cli-shadow-identity-v2" as const;
const CONTRACT_SLUG_PATTERN =
  /^[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?$/;
const AUTH_ENVIRONMENT_PATTERN =
  /^TASC_RUNTIME_AUTH_[A-Z][A-Z0-9_]{0,63}$/;
const HMAC_ENVIRONMENT_PATTERN =
  /^TASC_SHADOW_HMAC_[A-Z][A-Z0-9_]{0,63}$/;
const SIGNING_ENVIRONMENT_PATTERN =
  /^TASC_SHADOW_SIGNING_[A-Z][A-Z0-9_]{0,63}$/;
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/;
const MAX_AUTH_HEADER_BYTES = 8 * 1024;

interface CliAuthenticationConfig {
  readonly reference: string;
  readonly header: RuntimeSecretHeaderName;
  readonly environmentVariable: string;
}

interface CliEndpointConfig {
  readonly schemaVersion: typeof CLI_ENDPOINT_VERSION;
  readonly endpointAlias: string;
  readonly endpointDescriptor?: EndpointDescriptor;
  readonly authentication?: CliAuthenticationConfig;
}

interface CliShadowTargetConfig {
  readonly profileId: string;
  readonly endpoint: CliEndpointConfig;
  readonly instance: RuntimeInstanceIdentity;
  readonly route: RuntimeInvocationRoute;
  readonly httpLimits?: Readonly<Partial<RuntimeHttpLimits>>;
}

interface CliShadowProfilesConfig {
  readonly schemaVersion: typeof CLI_SHADOW_PROFILES_VERSION;
  readonly targets: readonly CliShadowTargetConfig[];
}

interface CliShadowIdentityConfig {
  readonly schemaVersion: typeof CLI_SHADOW_IDENTITY_VERSION;
  readonly studyId: string;
  readonly keyId: string;
  readonly hmacKeyEnvironmentVariable: string;
  readonly dispatchPrivateKeyEnvironmentVariable: string;
  readonly collectorPrivateKeyEnvironmentVariable: string;
}

interface RuntimeAuthenticationFields {
  readonly authenticationReference?: string;
  readonly secretHeaderFactory?: RuntimeSecretHeaderFactory;
}

function strictCliRecord(
  input: unknown,
  allowedKeys: ReadonlySet<string>,
): Readonly<Record<string, unknown>> {
  if (
    input === null
    || typeof input !== "object"
    || Array.isArray(input)
    || (
      Reflect.getPrototypeOf(input) !== Object.prototype
      && Reflect.getPrototypeOf(input) !== null
    )
  ) {
    throw new Error("CLI contract must be a plain object");
  }
  const result: Record<string, unknown> = Object.create(null);
  for (const key of Reflect.ownKeys(input)) {
    if (typeof key !== "string" || !allowedKeys.has(key)) {
      throw new Error("CLI contract contains an unknown field");
    }
    const descriptor = Reflect.getOwnPropertyDescriptor(input, key);
    if (
      descriptor === undefined
      || !descriptor.enumerable
      || !Object.hasOwn(descriptor, "value")
    ) {
      throw new Error("CLI contract requires enumerable data fields");
    }
    result[key] = descriptor.value;
  }
  return Object.freeze(result);
}

function strictCliArray(
  input: unknown,
  maximum: number,
): readonly unknown[] {
  if (
    !Array.isArray(input)
    || Reflect.getPrototypeOf(input) !== Array.prototype
    || input.length > maximum
  ) {
    throw new Error("CLI contract array is invalid");
  }
  const allowedKeys = new Set(["length"]);
  const values: unknown[] = [];
  for (let index = 0; index < input.length; index += 1) {
    const key = String(index);
    allowedKeys.add(key);
    const descriptor = Reflect.getOwnPropertyDescriptor(input, key);
    if (
      descriptor === undefined
      || !descriptor.enumerable
      || !Object.hasOwn(descriptor, "value")
    ) {
      throw new Error("CLI contract array must be dense");
    }
    values.push(descriptor.value);
  }
  if (
    Reflect.ownKeys(input).some(
      (key) => typeof key !== "string" || !allowedKeys.has(key),
    )
  ) {
    throw new Error("CLI contract array contains an unknown field");
  }
  return Object.freeze(values);
}

function exactFields(
  record: Readonly<Record<string, unknown>>,
  fields: readonly string[],
): void {
  if (
    Reflect.ownKeys(record).length !== fields.length
    || fields.some((field) => !Object.hasOwn(record, field))
  ) {
    throw new Error("CLI contract is missing a required field");
  }
}

function contractSlug(value: unknown): string {
  if (typeof value !== "string" || !CONTRACT_SLUG_PATTERN.test(value)) {
    throw new Error("CLI contract identifier is invalid");
  }
  return value;
}

function safePositiveInteger(
  value: unknown,
  maximum = Number.MAX_SAFE_INTEGER,
): number {
  if (
    typeof value !== "number"
    || !Number.isSafeInteger(value)
    || value < 1
    || value > maximum
  ) {
    throw new Error("CLI contract integer is invalid");
  }
  return value;
}

function parseAuthenticationConfig(
  input: unknown,
): CliAuthenticationConfig {
  const record = strictCliRecord(
    input,
    new Set(["reference", "header", "environmentVariable"]),
  );
  exactFields(record, ["reference", "header", "environmentVariable"]);
  if (
    record.header !== "authorization"
    && record.header !== "x-api-key"
  ) {
    throw new Error("CLI authentication header is invalid");
  }
  if (
    typeof record.environmentVariable !== "string"
    || !AUTH_ENVIRONMENT_PATTERN.test(record.environmentVariable)
  ) {
    throw new Error("CLI authentication environment name is invalid");
  }
  return Object.freeze({
    reference: contractSlug(record.reference),
    header: record.header,
    environmentVariable: record.environmentVariable,
  });
}

function parseCliEndpoint(input: unknown): CliEndpointConfig {
  const record = strictCliRecord(
    input,
    new Set([
      "schemaVersion",
      "endpointAlias",
      "endpointDescriptor",
      "authentication",
    ]),
  );
  if (
    record.schemaVersion !== CLI_ENDPOINT_VERSION
    || !Object.hasOwn(record, "endpointAlias")
  ) {
    throw new Error("CLI endpoint contract is invalid");
  }
  const endpointDescriptor = record.endpointDescriptor === undefined
    ? undefined
    : parseEndpointDescriptor(record.endpointDescriptor);
  const authentication = record.authentication === undefined
    ? undefined
    : parseAuthenticationConfig(record.authentication);
  const descriptorReference =
    endpointDescriptor?.orchestration.authenticationReference;
  if (
    descriptorReference !== undefined
    && descriptorReference !== authentication?.reference
  ) {
    throw new Error("CLI endpoint authentication binding is invalid");
  }
  return Object.freeze({
    schemaVersion: CLI_ENDPOINT_VERSION,
    endpointAlias: contractSlug(record.endpointAlias),
    ...(endpointDescriptor === undefined ? {} : { endpointDescriptor }),
    ...(authentication === undefined ? {} : { authentication }),
  });
}

const CLI_HTTP_LIMIT_FIELDS = Object.freeze([
  "maxRequestBytes",
  "maxResponseHeaderBytes",
  "maxResponseHeaders",
  "maxResponseBytes",
  "maxResponseChunks",
  "maxSecretHeaderBytes",
  "connectTimeoutMs",
  "headersTimeoutMs",
  "bodyTimeoutMs",
  "deadlineMs",
] as const satisfies readonly (keyof RuntimeHttpLimits)[]);

function parseCliHttpLimits(
  input: unknown,
): Readonly<Partial<RuntimeHttpLimits>> {
  const record = strictCliRecord(
    input,
    new Set(CLI_HTTP_LIMIT_FIELDS),
  );
  if (Reflect.ownKeys(record).length < 1) {
    throw new Error("CLI HTTP limits cannot be empty");
  }
  const result: Partial<Record<keyof RuntimeHttpLimits, number>> = {};
  for (const [key, value] of Object.entries(record)) {
    result[key as keyof RuntimeHttpLimits] = safePositiveInteger(value);
  }
  return Object.freeze(result);
}

function parseShadowTarget(input: unknown): CliShadowTargetConfig {
  const record = strictCliRecord(
    input,
    new Set([
      "profileId",
      "endpoint",
      "instance",
      "route",
      "httpLimits",
    ]),
  );
  for (const required of ["profileId", "endpoint", "instance", "route"]) {
    if (!Object.hasOwn(record, required)) {
      throw new Error("CLI shadow target is missing a required field");
    }
  }
  if (
    record.route !== "chatCompletions"
    && record.route !== "completions"
    && record.route !== "responses"
    && record.route !== "nativeChat"
    && record.route !== "nativeGenerate"
  ) {
    throw new Error("CLI shadow target route is invalid");
  }
  return Object.freeze({
    profileId: contractSlug(record.profileId),
    endpoint: parseCliEndpoint(record.endpoint),
    instance: parseRuntimeInstanceIdentity(record.instance),
    route: record.route,
    ...(record.httpLimits === undefined
      ? {}
      : { httpLimits: parseCliHttpLimits(record.httpLimits) }),
  });
}

function parseShadowProfiles(input: unknown): CliShadowProfilesConfig {
  const record = strictCliRecord(
    input,
    new Set([
      "schemaVersion",
      "targets",
    ]),
  );
  exactFields(record, [
    "schemaVersion",
    "targets",
  ]);
  if (record.schemaVersion !== CLI_SHADOW_PROFILES_VERSION) {
    throw new Error("CLI shadow profiles version is invalid");
  }
  const targets = strictCliArray(record.targets, 16)
    .map(parseShadowTarget);
  if (targets.length < 2) {
    throw new Error("CLI shadow profiles require at least two targets");
  }
  if (new Set(targets.map(({ profileId }) => profileId)).size !== targets.length) {
    throw new Error("CLI shadow target ids must be unique");
  }
  return Object.freeze({
    schemaVersion: CLI_SHADOW_PROFILES_VERSION,
    targets: Object.freeze(targets),
  });
}

function parseShadowIdentity(input: unknown): CliShadowIdentityConfig {
  const record = strictCliRecord(
    input,
    new Set([
      "schemaVersion",
      "studyId",
      "keyId",
      "hmacKeyEnvironmentVariable",
      "dispatchPrivateKeyEnvironmentVariable",
      "collectorPrivateKeyEnvironmentVariable",
    ]),
  );
  exactFields(record, [
    "schemaVersion",
    "studyId",
    "keyId",
    "hmacKeyEnvironmentVariable",
    "dispatchPrivateKeyEnvironmentVariable",
    "collectorPrivateKeyEnvironmentVariable",
  ]);
  if (
    record.schemaVersion !== CLI_SHADOW_IDENTITY_VERSION
    || typeof record.hmacKeyEnvironmentVariable !== "string"
    || !HMAC_ENVIRONMENT_PATTERN.test(
      record.hmacKeyEnvironmentVariable,
    )
    || typeof record.dispatchPrivateKeyEnvironmentVariable !== "string"
    || !SIGNING_ENVIRONMENT_PATTERN.test(
      record.dispatchPrivateKeyEnvironmentVariable,
    )
    || typeof record.collectorPrivateKeyEnvironmentVariable !== "string"
    || !SIGNING_ENVIRONMENT_PATTERN.test(
      record.collectorPrivateKeyEnvironmentVariable,
    )
    || record.collectorPrivateKeyEnvironmentVariable
      === record.dispatchPrivateKeyEnvironmentVariable
  ) {
    throw new Error("CLI shadow identity contract is invalid");
  }
  return Object.freeze({
    schemaVersion: CLI_SHADOW_IDENTITY_VERSION,
    studyId: contractSlug(record.studyId),
    keyId: contractSlug(record.keyId),
    hmacKeyEnvironmentVariable: record.hmacKeyEnvironmentVariable,
    dispatchPrivateKeyEnvironmentVariable:
      record.dispatchPrivateKeyEnvironmentVariable,
    collectorPrivateKeyEnvironmentVariable:
      record.collectorPrivateKeyEnvironmentVariable,
  });
}

function readSecret(
  context: CliV2ExecutionContext,
  environmentVariable: string,
  input: "endpoint" | "identity" | "profiles",
): string {
  let value: string | undefined;
  try {
    value = context.readSecretEnvironmentVariable?.(
      environmentVariable,
    );
  } catch {
    throw new CliInputError(input, "secret-unavailable");
  }
  if (typeof value !== "string") {
    throw new CliInputError(input, "secret-unavailable");
  }
  return value;
}

function runtimeAuthenticationFields(
  endpoint: CliEndpointConfig,
  context: CliV2ExecutionContext,
  input: "endpoint" | "profiles",
): RuntimeAuthenticationFields {
  if (endpoint.authentication === undefined) return Object.freeze({});
  const secret = readSecret(
    context,
    endpoint.authentication.environmentVariable,
    input,
  );
  if (
    secret.length < 1
    || secret.length > MAX_AUTH_HEADER_BYTES
    || Buffer.byteLength(secret, "utf8") > MAX_AUTH_HEADER_BYTES
    || !/^[\x20-\x7e]+$/.test(secret)
  ) {
    throw new CliInputError(input, "secret-invalid");
  }
  const headers = Object.freeze([
    Object.freeze([
      endpoint.authentication.header,
      secret,
    ] as const),
  ]);
  return Object.freeze({
    authenticationReference: endpoint.authentication.reference,
    secretHeaderFactory: (reference: string) => {
      if (reference !== endpoint.authentication?.reference) {
        throw new Error("Runtime authentication reference was rejected.");
      }
      return headers;
    },
  });
}

function canonicalSecretBytes(
  source: string,
  maximumBytes: number,
  input: "identity",
): Buffer {
  const maximumEncodedLength = Math.ceil(maximumBytes * 4 / 3) + 2;
  if (
    source.length < 1
    || source.length > maximumEncodedLength
    || !BASE64URL_PATTERN.test(source)
    || source.includes("=")
  ) {
    throw new CliInputError(input, "secret-invalid");
  }
  let bytes: Buffer;
  try {
    bytes = Buffer.from(source, "base64url");
  } catch {
    throw new CliInputError(input, "secret-invalid");
  }
  if (
    bytes.byteLength < 1
    || bytes.byteLength > maximumBytes
    || bytes.toString("base64url") !== source
  ) {
    bytes.fill(0);
    throw new CliInputError(input, "secret-invalid");
  }
  return bytes;
}

function loadShadowSigningKey(
  context: CliV2ExecutionContext,
  environmentVariable: string,
): {
  readonly privateKey: KeyObject;
  readonly publicKeySpki: string;
} {
  const signingSource = readSecret(context, environmentVariable, "identity");
  const signingBytes = canonicalSecretBytes(signingSource, 512, "identity");
  let privateKey: KeyObject;
  try {
    privateKey = createPrivateKey({
      key: signingBytes,
      format: "der",
      type: "pkcs8",
    });
    const exported = privateKey.export({
      format: "der",
      type: "pkcs8",
    });
    try {
      if (
        privateKey.type !== "private"
        || privateKey.asymmetricKeyType !== "ed25519"
        || !exported.equals(signingBytes)
      ) {
        throw new Error("invalid key");
      }
    } finally {
      exported.fill(0);
    }
  } catch {
    throw new CliInputError("identity", "secret-invalid");
  } finally {
    signingBytes.fill(0);
  }
  try {
    return Object.freeze({
      privateKey,
      publicKeySpki: createPublicKey(privateKey)
        .export({ format: "der", type: "spki" })
        .toString("base64url"),
    });
  } catch {
    throw new CliInputError("identity", "secret-invalid");
  }
}

function synchronousSigner(
  keyId: string,
  privateKey: KeyObject,
): DispatchIntentSigner & CollectorAttestationSigner {
  return Object.freeze({
    keyId,
    algorithm: "ed25519",
    sign: (bytes: Uint8Array) =>
      signBytes(null, bytes, privateKey).toString("base64url"),
  });
}

function shadowAuthorities(
  identity: CliShadowIdentityConfig,
  plan: ShadowRunPlan,
  context: CliV2ExecutionContext,
): {
  readonly identity: RuntimeInvocationInput["identity"];
  readonly dispatchIntentSigner: DispatchIntentSigner;
  readonly collectorAttestationSigner: CollectorAttestationSigner;
} {
  const protocol = plan.protocol;
  if (identity.studyId !== protocol.studyId) {
    throw new CliInputError("identity", "contract-invalid");
  }
  const hmacSource = readSecret(
    context,
    identity.hmacKeyEnvironmentVariable,
    "identity",
  );
  const hmacBytes = canonicalSecretBytes(hmacSource, 32, "identity");
  if (hmacBytes.byteLength !== 32) {
    hmacBytes.fill(0);
    throw new CliInputError("identity", "secret-invalid");
  }
  let hmacKey: KeyObject;
  try {
    hmacKey = createSecretKey(hmacBytes);
  } catch {
    throw new CliInputError("identity", "secret-invalid");
  } finally {
    hmacBytes.fill(0);
  }
  try {
    createStudyPayloadIdentity(
      protocol.studyId,
      identity.keyId,
      hmacKey,
      new Uint8Array(0),
    );
  } catch {
    throw new CliInputError("identity", "secret-invalid");
  }

  const dispatch = loadShadowSigningKey(
    context,
    identity.dispatchPrivateKeyEnvironmentVariable,
  );
  const collector = loadShadowSigningKey(
    context,
    identity.collectorPrivateKeyEnvironmentVariable,
  );
  if (
    dispatch.publicKeySpki === collector.publicKeySpki
    || dispatch.publicKeySpki
      !== protocol.dispatchAuthority.publicKeySpki
    || collector.publicKeySpki
      !== protocol.collectorAuthority.publicKeySpki
  ) {
    throw new CliInputError("identity", "contract-invalid");
  }
  return Object.freeze({
    identity: Object.freeze({
      studyId: protocol.studyId,
      keyId: identity.keyId,
      key: hmacKey,
    }),
    dispatchIntentSigner: synchronousSigner(
      protocol.dispatchAuthority.keyId,
      dispatch.privateKey,
    ),
    collectorAttestationSigner: synchronousSigner(
      protocol.collectorAuthority.keyId,
      collector.privateKey,
    ),
  });
}

function runtimeRequestPath(
  descriptor: EndpointDescriptor | undefined,
  routePath: string,
): string {
  const basePath = descriptor?.basePath ?? "/";
  if (basePath === "/") return routePath;
  if (routePath === "/") return basePath;
  return `${basePath}${routePath}`;
}

function assertEndpointBinding(
  policy: CollectorTrustPolicy,
  endpoint: CliEndpointConfig,
  instance: RuntimeInstanceIdentity,
): void {
  const digest = fingerprintCollectorEndpointBinding(
    policy,
    endpoint.endpointAlias,
    endpoint.endpointDescriptor,
  );
  if (digest !== instance.endpointDescriptorDigest) {
    throw new Error("runtime endpoint binding does not match");
  }
}

function validateShadowTarget(
  target: CliShadowTargetConfig,
  policy: CollectorTrustPolicy,
  protocol: ExperimentProtocol,
  planTarget: ShadowRunPlanCollectionTarget,
): void {
  if (
    target.profileId !== planTarget.profileId
    || target.endpoint.endpointAlias !== planTarget.endpointAlias
    || target.instance.endpointDescriptorDigest
      !== planTarget.endpointBindingDigest
    || target.instance.runtime.profileId !== planTarget.runtimeName
    || target.route !== planTarget.route
    || (target.endpoint.authentication?.reference ?? null)
      !== planTarget.authenticationReference
  ) {
    throw new Error("runtime target conflicts with the shadow run plan");
  }
  assertEndpointBinding(policy, target.endpoint, target.instance);
  const profile = getRuntimeProfile(target.instance.runtime.profileId);
  if (target.instance.runtime.build !== profile.runtime.build) {
    throw new Error("runtime build does not match the registry");
  }
  const executionProfile = protocol.profiles.find(
    ({ id }) => id === target.profileId,
  );
  if (
    executionProfile === undefined
    || executionProfile.runtime.name !== target.instance.runtime.profileId
    || executionProfile.runtime.build !== target.instance.runtime.build
    || executionProfile.backend.name !== target.instance.backend.name
    || executionProfile.backend.build !== target.instance.backend.build
    || executionProfile.model.id !== target.instance.model.id
    || executionProfile.model.revision !== target.instance.model.revision
    || executionProfile.deploymentConfigurationDigest
      !== target.instance.configurationDigest
  ) {
    throw new Error("runtime target conflicts with the protocol profile");
  }
  const endpointRequirement = protocol.endpointRequirements.find(
    (requirement) =>
      requirement.runtimeName === executionProfile.runtime.name
      && requirement.endpointAlias === target.endpoint.endpointAlias,
  );
  const trustedEndpoint = policy.endpoints.find(
    ({ alias }) => alias === target.endpoint.endpointAlias,
  );
  if (endpointRequirement === undefined || trustedEndpoint === undefined) {
    throw new Error("runtime target is outside protocol endpoint requirements");
  }
  const trustedOrigin = new URL(trustedEndpoint.origin);
  const loopbackHttp = trustedOrigin.protocol === "http:"
    && (
      trustedOrigin.hostname === "127.0.0.1"
      || trustedOrigin.hostname === "[::1]"
    );
  if (
    endpointRequirement.transport !== planTarget.transport
    || (
      endpointRequirement.transport === "https"
      && trustedOrigin.protocol !== "https:"
    )
    || (
      endpointRequirement.transport === "loopback-http"
      && !loopbackHttp
    )
  ) {
    throw new Error("runtime target transport conflicts with the protocol");
  }
  const route = profile.endpoints.inference[target.route];
  if (route === undefined) {
    throw new Error("runtime target route is unsupported");
  }
  const expectation = profile.capabilities[route.capability];
  if (expectation.state !== "supported") {
    throw new Error("runtime target capability admission is invalid");
  }
  if (
    protocol.shadowCollection.attemptTimeoutMs
      > policy.maximumRequestDurationMs
  ) {
    throw new Error("runtime target deadline exceeds collector trust");
  }
  authorizeCollectorRequest(policy, {
    endpointAlias: target.endpoint.endpointAlias,
    runtime: target.instance.runtime,
    method: route.method,
    path: runtimeRequestPath(
      target.endpoint.endpointDescriptor,
      route.path,
    ),
    ...(target.endpoint.authentication === undefined
      ? {}
      : {
        authenticationReference:
          target.endpoint.authentication.reference,
      }),
  });
}

function runtimeTarget(
  target: CliShadowTargetConfig,
  policy: CollectorTrustPolicy,
  authentication: RuntimeAuthenticationFields,
): ShadowProfileTarget {
  return Object.freeze({
    profileId: target.profileId,
    runtime: Object.freeze({
      policy,
      endpointAlias: target.endpoint.endpointAlias,
      ...(target.endpoint.endpointDescriptor === undefined
        ? {}
        : {
          endpointDescriptor: target.endpoint.endpointDescriptor,
      }),
      instance: target.instance,
      route: target.route,
      ...(target.httpLimits === undefined
        ? {}
        : { httpLimits: target.httpLimits }),
      ...authentication,
    }),
  });
}

async function assertExistingOutputRoot(path: string): Promise<void> {
  const root = resolve(path);
  if (
    !isAbsolute(root)
    || normalize(root) !== root
    || root === parsePath(root).root
  ) {
    throw new CliOutputError();
  }
  const parsed = parsePath(root);
  const suffix = root.slice(parsed.root.length);
  const components = suffix.length === 0 ? [] : suffix.split(sep);
  let current = parsed.root;
  try {
    for (const component of components) {
      current = join(current, component);
      const stats = await lstat(current);
      if (stats.isSymbolicLink() || !stats.isDirectory()) {
        throw new Error("invalid output root");
      }
    }
    if (normalize(await realpath(root)) !== root) {
      throw new Error("invalid output root");
    }
  } catch {
    throw new CliOutputError();
  }
}

async function runtimeProbeCommand(
  command: RuntimeProbeCommand,
  context: CliV2ExecutionContext,
): Promise<CliV2Result> {
  const [endpointInput, runtimeInput, trustInput] = await Promise.all([
    readJsonInput(command.endpoint, "endpoint"),
    readJsonInput(command.runtime, "runtime"),
    readJsonInput(command.trust, "trust"),
  ]);
  const endpoint = parseInput(
    "endpoint",
    () => parseCliEndpoint(endpointInput),
  );
  const instance = parseInput(
    "runtime",
    () => parseRuntimeInstanceIdentity(runtimeInput),
  );
  const policy = parseInput(
    "trust",
    () => parseCollectorTrustPolicy(trustInput),
  );
  try {
    assertEndpointBinding(policy, endpoint, instance);
  } catch {
    throw new CliInputError("runtime", "runtime-rejected");
  }
  const authentication = runtimeAuthenticationFields(
    endpoint,
    context,
    "endpoint",
  );
  let result;
  try {
    result = await probeRuntimeCapability({
      policy,
      endpointAlias: endpoint.endpointAlias,
      ...(endpoint.endpointDescriptor === undefined
        ? {}
        : { endpointDescriptor: endpoint.endpointDescriptor }),
      instance,
      capability: command.capability,
      observationEffect: command.observationEffect,
      totalDeadlineMs: command.deadlineMs,
      ...(context.signal === undefined ? {} : { signal: context.signal }),
      ...authentication,
    });
  } catch (error) {
    if (error instanceof RuntimeProbeInputError) {
      throw new CliInputError("runtime", "runtime-rejected");
    }
    throw new CliRuntimeError(
      "runtime-probe",
      "runtime-rejected",
      "not-applicable",
    );
  }
  if (result.observation.error !== null) {
    throw new CliRuntimeError(
      "runtime-probe",
      result.observation.error.category,
      result.observation.dispatchState,
    );
  }
  return Object.freeze({
    version: "tasc-cli-result-v1",
    command: "runtime probe",
    status: result.evidence.state.toUpperCase(),
    evidence: result.evidence,
    observation: result.observation,
    authorizationIssued: result.authorization !== null,
    scope: "observation-only-no-persisted-capability-authority",
    authority: NO_DEPLOYMENT_AUTHORITY,
  });
}

async function shadowRunCommand(
  command: ShadowRunCommand,
  context: CliV2ExecutionContext,
): Promise<CliV2Result> {
  const planInput = await readJsonInput(command.plan, "plan");
  const plan = parseInput(
    "plan",
    () => parseShadowRunPlan(planInput),
  );
  if (plan.planDigest !== command.expectedPlanDigest) {
    throw new CliInputError("plan", "context-mismatch");
  }
  const [
    profilesInput,
    trustInput,
    identityInput,
  ] = await Promise.all([
    readJsonInput(command.profiles, "profiles"),
    readJsonInput(command.trust, "trust"),
    readJsonInput(command.identity, "identity"),
  ]);
  const profiles = parseInput(
    "profiles",
    () => parseShadowProfiles(profilesInput),
  );
  const policy = parseInput(
    "trust",
    () => parseCollectorTrustPolicy(trustInput),
  );
  const identityConfig = parseInput(
    "identity",
    () => parseShadowIdentity(identityInput),
  );
  const casesInput = await readNdjsonInput(
    command.cases,
    "cases",
    rowLimits(Math.min(plan.workBudget.maxCases, 10_000)),
  );
  const cases = Object.freeze(
    [...casesInput],
  ) as unknown as readonly ShadowCaseInput[];

  const configByProfile = new Map(
    profiles.targets.map((target) => [target.profileId, target]),
  );
  if (
    configByProfile.size !== plan.collectionTargets.length
    || plan.collectionTargets.some(
      ({ profileId }) => !configByProfile.has(profileId),
    )
  ) {
    throw new CliInputError("profiles", "runtime-rejected");
  }
  const orderedTargets: CliShadowTargetConfig[] = [];
  const authentications: RuntimeAuthenticationFields[] = [];
  try {
    for (const planTarget of plan.collectionTargets) {
      const target = configByProfile.get(planTarget.profileId);
      if (target === undefined) {
        throw new Error("shadow target set is incomplete");
      }
      validateShadowTarget(target, policy, plan.protocol, planTarget);
      orderedTargets.push(target);
      authentications.push(runtimeAuthenticationFields(
        target.endpoint,
        context,
        "profiles",
      ));
    }
  } catch (error) {
    if (error instanceof CliInputError) throw error;
    throw new CliInputError("profiles", "runtime-rejected");
  }
  const authorities = shadowAuthorities(identityConfig, plan, context);
  const runtimeTargets = orderedTargets.map((target, index) =>
    runtimeTarget(target, policy, authentications[index]!)
  );
  const runInput: ShadowRunInput = {
    plan,
    expectedPlanDigest: command.expectedPlanDigest,
    rootDirectory: resolve(command.out),
    cases,
    profiles: Object.freeze(runtimeTargets),
    identity: authorities.identity,
    dispatchIntentSigner: authorities.dispatchIntentSigner,
    collectorAttestationSigner: authorities.collectorAttestationSigner,
    ...(context.signal === undefined ? {} : { signal: context.signal }),
  };
  await assertExistingOutputRoot(command.out);

  let result;
  try {
    result = await runShadowCollection(runInput);
  } catch (error) {
    if (error instanceof RuntimeInvocationInputError) {
      throw new CliRuntimeError(
        "shadow-run",
        error.persistedError.category,
        error.dispatchState,
      );
    }
    throw new CliOutputError();
  }
  return Object.freeze({
    version: "tasc-cli-result-v1",
    command: "shadow run",
    status: result.status.toUpperCase(),
    summary: Object.freeze({
      logicalExecutions: result.logicalExecutions,
      tracesAccepted: result.traces.length,
      pending: result.pendingTraceIds.length,
      attemptsRecorded: result.attemptsRecorded,
      networkCalls: result.networkCalls,
      durableRecordsWritten: result.durableRecordsWritten,
      resumed: result.resumed,
      deduplicated: result.deduplicated,
      sentUnknown: result.sentUnknown,
      membershipExcludedReplicates:
        result.membershipExcludedReplicates,
    }),
    scope: "trace-collection-only-no-evaluation-or-deployment",
    authority: NO_DEPLOYMENT_AUTHORITY,
  });
}

/** Execute one already-parsed v2 command with explicit ephemeral authority. */
export async function executeCliV2(
  command: CliV2Command,
  context: CliV2ExecutionContext = Object.freeze({}),
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
    case "runtime-probe":
      return runtimeProbeCommand(command, context);
    case "shadow-run":
      return shadowRunCommand(command, context);
  }
}
