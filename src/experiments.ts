import { z } from "zod";
import {
  type CandidateAssessment,
  parseAssessmentDecision,
} from "./assessment.js";
import {
  canonicalJson,
  compareCodeUnits,
} from "./determinism.js";
import {
  contractDigestSchema,
  contractSlugSchema,
  deepFreezeContract,
  domainSeparatedDigest,
  snapshotBoundedContractInput,
  type DeepReadonly,
} from "./evidence.js";

const BUDGET_DOMAIN = "tasc/experiment-budget/v1";
const HISTORY_DOMAIN = "tasc/experiment-history/v1";
const INTENT_DOMAIN = "tasc/experiment-intent/v2";
const DECISION_DOMAIN = "tasc/experiment-proposal-decision/v2";

export const MAX_EXPERIMENT_LOGICAL_EXECUTIONS = 1_000_000;
export const MAX_EXPERIMENT_ATTEMPTS = 8_000_000;
export const MAX_EXPERIMENT_WALL_CLOCK_MS = 2_592_000_000;
export const MAX_REGISTERED_EXPERIMENTS = 256;
export const MAX_CAPABILITY_FINDINGS = 128;

const safeNonNegativeIntegerSchema = z.number()
  .int()
  .min(0)
  .max(Number.MAX_SAFE_INTEGER);
const boundedTextSchema = z.string()
  .min(1)
  .max(512)
  .refine(
    (value) => value === value.trim(),
    "must not contain leading or trailing whitespace",
  );

const budgetBodySchema = z.object({
  version: z.literal("tasc-experiment-budget-v1"),
  maxLogicalExecutions: safeNonNegativeIntegerSchema
    .max(MAX_EXPERIMENT_LOGICAL_EXECUTIONS),
  maxAttempts: safeNonNegativeIntegerSchema.max(MAX_EXPERIMENT_ATTEMPTS),
  maxCostUsd: z.number().finite().nonnegative(),
  maxWallClockMs: safeNonNegativeIntegerSchema
    .max(MAX_EXPERIMENT_WALL_CLOCK_MS),
  payloadPolicy: z.literal("keyed-identities-only"),
}).strict();

const budgetInputSchema = budgetBodySchema.extend({
  budgetDigest: contractDigestSchema.optional(),
}).strict();

type MutableExperimentBudgetBody = z.infer<typeof budgetBodySchema>;

export interface ExperimentBudgetInput {
  readonly version: "tasc-experiment-budget-v1";
  readonly maxLogicalExecutions: number;
  readonly maxAttempts: number;
  readonly maxCostUsd: number;
  readonly maxWallClockMs: number;
  readonly payloadPolicy: "keyed-identities-only";
  readonly budgetDigest?: string;
}

export type ExperimentBudget = DeepReadonly<
  MutableExperimentBudgetBody & {
    budgetDigest: string;
  }
>;

function budgetBody(input: unknown): MutableExperimentBudgetBody {
  const snapshot = snapshotBoundedContractInput(input);
  const parsed = budgetInputSchema.parse(snapshot);
  if (parsed.maxAttempts < parsed.maxLogicalExecutions) {
    throw new Error(
      "experiment attempt ceiling must cover every logical execution",
    );
  }
  const {
    budgetDigest: _budgetDigest,
    ...body
  } = parsed;
  return body;
}

export function fingerprintExperimentBudget(input: unknown): string {
  return domainSeparatedDigest(BUDGET_DOMAIN, budgetBody(input));
}

export function parseExperimentBudget(
  input: unknown,
): ExperimentBudget {
  const snapshot = snapshotBoundedContractInput(input);
  const parsed = budgetInputSchema.parse(snapshot);
  if (parsed.maxAttempts < parsed.maxLogicalExecutions) {
    throw new Error(
      "experiment attempt ceiling must cover every logical execution",
    );
  }
  const {
    budgetDigest: suppliedDigest,
    ...body
  } = parsed;
  const budgetDigest = domainSeparatedDigest(BUDGET_DOMAIN, body);
  if (
    suppliedDigest !== undefined
    && suppliedDigest !== budgetDigest
  ) {
    throw new Error(
      "experiment budget digest does not match canonical budget content",
    );
  }
  return deepFreezeContract({
    ...body,
    budgetDigest,
  });
}

const registeredExperimentSchema = z.object({
  parentProtocolDigest: contractDigestSchema,
  experimentIntentDigest: contractDigestSchema,
  registeredProtocolDigest: contractDigestSchema,
  outcomeAssessmentDigest: contractDigestSchema.nullable(),
}).strict();

const capabilityFindingSchema = z.object({
  kind: z.literal("required-capability-mismatch"),
  protocolDigest: contractDigestSchema,
  profileId: contractSlugSchema,
  capabilityId: contractSlugSchema,
  capabilityEvidenceDigest: contractDigestSchema,
}).strict();

const historyBodySchema = z.object({
  version: z.literal("tasc-experiment-history-v1"),
  registeredExperiments: z.array(registeredExperimentSchema)
    .max(MAX_REGISTERED_EXPERIMENTS),
  findings: z.array(capabilityFindingSchema)
    .max(MAX_CAPABILITY_FINDINGS),
}).strict();

const historyInputSchema = historyBodySchema.extend({
  historyDigest: contractDigestSchema.optional(),
}).strict();

type MutableRegisteredExperiment = z.infer<
  typeof registeredExperimentSchema
>;
type MutableCapabilityFinding = z.infer<
  typeof capabilityFindingSchema
>;
type MutableExperimentHistoryBody = z.infer<
  typeof historyBodySchema
>;

export type RegisteredExperiment = DeepReadonly<
  MutableRegisteredExperiment
>;
export type RequiredCapabilityMismatchFinding = DeepReadonly<
  MutableCapabilityFinding
>;

export interface ExperimentHistoryInput {
  readonly version: "tasc-experiment-history-v1";
  readonly registeredExperiments: readonly RegisteredExperiment[];
  readonly findings: readonly RequiredCapabilityMismatchFinding[];
  readonly historyDigest?: string;
}

export type ExperimentHistory = DeepReadonly<
  MutableExperimentHistoryBody & {
    historyDigest: string;
  }
>;

function compareCanonical(left: unknown, right: unknown): number {
  return compareCodeUnits(canonicalJson(left), canonicalJson(right));
}

function assertNoDuplicateHistoryIdentities(
  history: MutableExperimentHistoryBody,
): void {
  const intentDigests = new Set<string>();
  const protocolDigests = new Set<string>();
  for (const registration of history.registeredExperiments) {
    if (intentDigests.has(registration.experimentIntentDigest)) {
      throw new Error(
        "experiment history contains a duplicate experiment intent",
      );
    }
    if (protocolDigests.has(registration.registeredProtocolDigest)) {
      throw new Error(
        "experiment history contains a duplicate registered protocol",
      );
    }
    intentDigests.add(registration.experimentIntentDigest);
    protocolDigests.add(registration.registeredProtocolDigest);
  }
  const findings = new Set<string>();
  for (const finding of history.findings) {
    const identity = canonicalJson(finding);
    if (findings.has(identity)) {
      throw new Error(
        "experiment history contains a duplicate capability finding",
      );
    }
    findings.add(identity);
  }
}

function normalizedHistoryBody(
  input: unknown,
): MutableExperimentHistoryBody {
  const snapshot = snapshotBoundedContractInput(input);
  const parsed = historyInputSchema.parse(snapshot);
  const normalized: MutableExperimentHistoryBody = {
    version: parsed.version,
    registeredExperiments: [...parsed.registeredExperiments]
      .sort(compareCanonical),
    findings: [...parsed.findings].sort(compareCanonical),
  };
  assertNoDuplicateHistoryIdentities(normalized);
  return normalized;
}

export function fingerprintExperimentHistory(input: unknown): string {
  return domainSeparatedDigest(
    HISTORY_DOMAIN,
    normalizedHistoryBody(input),
  );
}

export function parseExperimentHistory(
  input: unknown,
): ExperimentHistory {
  const snapshot = snapshotBoundedContractInput(input);
  const parsed = historyInputSchema.parse(snapshot);
  const normalized: MutableExperimentHistoryBody = {
    version: parsed.version,
    registeredExperiments: [...parsed.registeredExperiments]
      .sort(compareCanonical),
    findings: [...parsed.findings].sort(compareCanonical),
  };
  assertNoDuplicateHistoryIdentities(normalized);
  const historyDigest = domainSeparatedDigest(HISTORY_DOMAIN, normalized);
  if (
    parsed.historyDigest !== undefined
    && parsed.historyDigest !== historyDigest
  ) {
    throw new Error(
      "experiment history digest does not match normalized history content",
    );
  }
  return deepFreezeContract({
    ...normalized,
    historyDigest,
  });
}

export type ExperimentDiagnosis =
  | "insufficient-evidence"
  | "evaluator-drift"
  | "quality-regression"
  | "critical-slice-regression"
  | "ttft-regression"
  | "tail-latency-regression"
  | "error-regression"
  | "cost-regression"
  | "unavailable-capacity"
  | "capability-mismatch"
  | "sealed-shadow-replication";

export type ExperimentChangedVariable =
  | {
    readonly kind: "evidence-collection";
    readonly targetId: "assessment-evidence";
  }
  | {
    readonly kind: "evaluator-calibration";
    readonly targetId: "external-evaluator";
  }
  | {
    readonly kind: "routing-policy";
    readonly targetId: "selected-policy";
  }
  | {
    readonly kind: "execution-profile";
    readonly targetId: "selected-profile";
  }
  | {
    readonly kind: "capacity-observation";
    readonly targetId: "nominated-window";
  }
  | {
    readonly kind: "required-capability";
    readonly targetId: string;
    readonly profileId: string;
  }
  | {
    readonly kind: "evidence-window";
    readonly targetId: "sealed-shadow-window";
  };

export type ExperimentChangedVariableKind =
  ExperimentChangedVariable["kind"];

export type ExperimentFrozenControl =
  | "evaluator-calibration"
  | "execution-profiles"
  | "holdout-membership"
  | "payload-policy"
  | "policy-gates"
  | "production-state"
  | "routing-policy"
  | "sampling-membership";

export type ExperimentEvidenceRequirement =
  | {
    readonly kind:
      | "paired-evaluator-evidence"
      | "independent-group-coverage"
      | "critical-slice-coverage"
      | "observer-timing-evidence"
      | "observer-failure-evidence"
      | "attempt-cost-evidence"
      | "exact-policy-capacity-evidence"
      | "sealed-shadow-window-evidence"
      | "evaluator-calibration-evidence";
  }
  | {
    readonly kind: "runtime-capability-evidence";
    readonly protocolDigest: string;
    readonly profileId: string;
    readonly capabilityId: string;
    readonly evidenceDigest: string;
  };

export interface ExperimentStopCondition {
  readonly kind: "first-budget-limit";
  readonly budgetDigest: string;
}

export interface ExperimentExpectedDecision {
  readonly ifSupported: "REASSESS_WITH_REGISTERED_PROTOCOL";
  readonly otherwise: "HOLD";
}

export type ExperimentHoldReason =
  | "holdout-tuning-forbidden"
  | "assessment-already-passing"
  | "structural-staleness"
  | "insufficient-proposal-budget"
  | "duplicate-registered-experiment"
  | "no-actionable-diagnosis";

export interface ProposedExperimentDecision {
  readonly version: "tasc-experiment-proposal-decision-v2";
  readonly status: "PROPOSED";
  readonly parentAssessmentDigest: string;
  readonly parentProtocolDigest: string;
  readonly historyDigest: string;
  readonly budget: ExperimentBudget;
  readonly diagnosis: ExperimentDiagnosis;
  readonly hypothesis: string;
  readonly changedVariable: ExperimentChangedVariable;
  readonly frozenControls: readonly ExperimentFrozenControl[];
  readonly evidenceRequirements: readonly ExperimentEvidenceRequirement[];
  readonly stopCondition: ExperimentStopCondition;
  readonly expectedDecision: ExperimentExpectedDecision;
  readonly authority: "operator-registration-required";
  readonly attestation: "unattested";
  readonly experimentIntentDigest: string;
  readonly decisionDigest: string;
}

export interface HeldExperimentDecision {
  readonly version: "tasc-experiment-proposal-decision-v2";
  readonly status: "HOLD";
  readonly parentAssessmentDigest: string;
  readonly parentProtocolDigest: string;
  readonly historyDigest: string;
  readonly budget: ExperimentBudget;
  readonly holdReason: ExperimentHoldReason;
  readonly relatedProtocolDigest: string | null;
  readonly authority: "operator-registration-required";
  readonly attestation: "unattested";
  readonly decisionDigest: string;
}

export type ExperimentProposalDecision = DeepReadonly<
  ProposedExperimentDecision | HeldExperimentDecision
>;

const diagnosisSchema = z.enum([
  "insufficient-evidence",
  "evaluator-drift",
  "quality-regression",
  "critical-slice-regression",
  "ttft-regression",
  "tail-latency-regression",
  "error-regression",
  "cost-regression",
  "unavailable-capacity",
  "capability-mismatch",
  "sealed-shadow-replication",
]);

const changedVariableSchema = z.discriminatedUnion("kind", [
  z.object({
    kind: z.literal("evidence-collection"),
    targetId: z.literal("assessment-evidence"),
  }).strict(),
  z.object({
    kind: z.literal("evaluator-calibration"),
    targetId: z.literal("external-evaluator"),
  }).strict(),
  z.object({
    kind: z.literal("routing-policy"),
    targetId: z.literal("selected-policy"),
  }).strict(),
  z.object({
    kind: z.literal("execution-profile"),
    targetId: z.literal("selected-profile"),
  }).strict(),
  z.object({
    kind: z.literal("capacity-observation"),
    targetId: z.literal("nominated-window"),
  }).strict(),
  z.object({
    kind: z.literal("required-capability"),
    targetId: contractSlugSchema,
    profileId: contractSlugSchema,
  }).strict(),
  z.object({
    kind: z.literal("evidence-window"),
    targetId: z.literal("sealed-shadow-window"),
  }).strict(),
]);

const frozenControlSchema = z.enum([
  "evaluator-calibration",
  "execution-profiles",
  "holdout-membership",
  "payload-policy",
  "policy-gates",
  "production-state",
  "routing-policy",
  "sampling-membership",
]);

const simpleEvidenceRequirementSchema = z.object({
  kind: z.enum([
    "paired-evaluator-evidence",
    "independent-group-coverage",
    "critical-slice-coverage",
    "observer-timing-evidence",
    "observer-failure-evidence",
    "attempt-cost-evidence",
    "exact-policy-capacity-evidence",
    "sealed-shadow-window-evidence",
    "evaluator-calibration-evidence",
  ]),
}).strict();

const capabilityEvidenceRequirementSchema = z.object({
  kind: z.literal("runtime-capability-evidence"),
  protocolDigest: contractDigestSchema,
  profileId: contractSlugSchema,
  capabilityId: contractSlugSchema,
  evidenceDigest: contractDigestSchema,
}).strict();

const evidenceRequirementSchema = z.discriminatedUnion("kind", [
  simpleEvidenceRequirementSchema,
  capabilityEvidenceRequirementSchema,
]);

const parsedBudgetSchema: z.ZodType<
  ExperimentBudget,
  z.ZodTypeDef,
  unknown
> = z.unknown().transform((value, context) => {
  try {
    return parseExperimentBudget(value);
  } catch (error) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      message: error instanceof Error
        ? error.message
        : "invalid experiment budget",
    });
    return z.NEVER;
  }
});

const proposalBodySchema = z.object({
  version: z.literal("tasc-experiment-proposal-decision-v2"),
  status: z.literal("PROPOSED"),
  parentAssessmentDigest: contractDigestSchema,
  parentProtocolDigest: contractDigestSchema,
  historyDigest: contractDigestSchema,
  budget: parsedBudgetSchema,
  diagnosis: diagnosisSchema,
  hypothesis: boundedTextSchema,
  changedVariable: changedVariableSchema,
  frozenControls: z.array(frozenControlSchema).min(1).max(8),
  evidenceRequirements: z.array(evidenceRequirementSchema)
    .min(1)
    .max(8),
  stopCondition: z.object({
    kind: z.literal("first-budget-limit"),
    budgetDigest: contractDigestSchema,
  }).strict(),
  expectedDecision: z.object({
    ifSupported: z.literal("REASSESS_WITH_REGISTERED_PROTOCOL"),
    otherwise: z.literal("HOLD"),
  }).strict(),
  authority: z.literal("operator-registration-required"),
  attestation: z.literal("unattested"),
  experimentIntentDigest: contractDigestSchema,
}).strict();

const holdReasonSchema = z.enum([
  "holdout-tuning-forbidden",
  "assessment-already-passing",
  "structural-staleness",
  "insufficient-proposal-budget",
  "duplicate-registered-experiment",
  "no-actionable-diagnosis",
]);

const holdBodySchema = z.object({
  version: z.literal("tasc-experiment-proposal-decision-v2"),
  status: z.literal("HOLD"),
  parentAssessmentDigest: contractDigestSchema,
  parentProtocolDigest: contractDigestSchema,
  historyDigest: contractDigestSchema,
  budget: parsedBudgetSchema,
  holdReason: holdReasonSchema,
  relatedProtocolDigest: contractDigestSchema.nullable(),
  authority: z.literal("operator-registration-required"),
  attestation: z.literal("unattested"),
}).strict();

const decisionBodySchema = z.discriminatedUnion("status", [
  proposalBodySchema,
  holdBodySchema,
]);

const proposalDecisionSchema = proposalBodySchema.extend({
  decisionDigest: contractDigestSchema,
}).strict();

const holdDecisionSchema = holdBodySchema.extend({
  decisionDigest: contractDigestSchema,
}).strict();

const decisionSchema = z.discriminatedUnion("status", [
  proposalDecisionSchema,
  holdDecisionSchema,
]);

type MutableProposalBody = z.infer<typeof proposalBodySchema>;
type MutableHoldBody = z.infer<typeof holdBodySchema>;
type MutableDecisionBody = z.infer<typeof decisionBodySchema>;
type ExperimentIntentSource = Pick<
  MutableProposalBody,
  | "parentAssessmentDigest"
  | "parentProtocolDigest"
  | "budget"
  | "diagnosis"
  | "hypothesis"
  | "changedVariable"
  | "frozenControls"
  | "evidenceRequirements"
  | "stopCondition"
  | "expectedDecision"
>;

function sortedUnique<T>(values: readonly T[]): T[] {
  const sorted = [...values].sort(compareCanonical);
  for (let index = 1; index < sorted.length; index += 1) {
    if (canonicalJson(sorted[index - 1]) === canonicalJson(sorted[index])) {
      throw new Error("experiment proposal arrays must contain unique entries");
    }
  }
  return sorted;
}

function assertCanonicalArray(
  values: readonly unknown[],
  label: string,
): void {
  const sorted = sortedUnique(values);
  if (
    values.some(
      (value, index) =>
        canonicalJson(value) !== canonicalJson(sorted[index]),
    )
  ) {
    throw new Error(
      `${label} must use locale-independent canonical ordering`,
    );
  }
}

function experimentIntentBody(proposal: ExperimentIntentSource): {
  readonly version: "tasc-experiment-intent-v2";
  readonly parentAssessmentDigest: string;
  readonly parentProtocolDigest: string;
  readonly budgetDigest: string;
  readonly diagnosis: ExperimentDiagnosis;
  readonly hypothesis: string;
  readonly changedVariable: ExperimentChangedVariable;
  readonly frozenControls: readonly ExperimentFrozenControl[];
  readonly evidenceRequirements:
    readonly ExperimentEvidenceRequirement[];
  readonly stopCondition: ExperimentStopCondition;
  readonly expectedDecision: ExperimentExpectedDecision;
} {
  return {
    version: "tasc-experiment-intent-v2",
    parentAssessmentDigest: proposal.parentAssessmentDigest,
    parentProtocolDigest: proposal.parentProtocolDigest,
    budgetDigest: proposal.budget.budgetDigest,
    diagnosis: proposal.diagnosis,
    hypothesis: proposal.hypothesis,
    changedVariable: proposal.changedVariable,
    frozenControls: proposal.frozenControls,
    evidenceRequirements: proposal.evidenceRequirements,
    stopCondition: proposal.stopCondition,
    expectedDecision: proposal.expectedDecision,
  };
}

function fingerprintIntent(proposal: MutableProposalBody): string {
  return domainSeparatedDigest(
    INTENT_DOMAIN,
    experimentIntentBody(proposal),
  );
}

const HYPOTHESES: Readonly<Record<ExperimentDiagnosis, string>> = {
  "insufficient-evidence":
    "A registered collection with complete paired evidence can determine whether the frozen policy is assessable.",
  "evaluator-drift":
    "A separately registered calibration study can determine whether external evaluator evidence is current and consistent.",
  "quality-regression":
    "A registered routing-policy variant can determine whether the preregistered paired quality gates are satisfied.",
  "critical-slice-regression":
    "A registered routing-policy variant can determine whether the explicit critical-slice quality gate is satisfied.",
  "ttft-regression":
    "A registered execution-profile variant can determine whether the preregistered time-to-first-token gate is satisfied.",
  "tail-latency-regression":
    "A registered execution-profile variant can determine whether the preregistered end-to-end tail-latency gate is satisfied.",
  "error-regression":
    "A registered execution-profile variant can determine whether the preregistered failure-rate gate is satisfied.",
  "cost-regression":
    "A registered execution-profile variant can determine whether the preregistered cost gate is satisfied.",
  "unavailable-capacity":
    "An exact-policy capacity observation can determine whether the preregistered service-capacity gate is satisfied.",
  "capability-mismatch":
    "A registered profile varying one required capability can determine whether the evidenced capability mismatch is resolved.",
  "sealed-shadow-replication":
    "A disjoint sealed-shadow window can determine whether the nominated policy reproduces its development result.",
};

const COMMON_CONTROLS: readonly ExperimentFrozenControl[] = [
  "holdout-membership",
  "payload-policy",
  "policy-gates",
  "production-state",
];

interface DiagnosisMatch {
  readonly diagnosis: ExperimentDiagnosis;
  readonly capabilityFinding?: RequiredCapabilityMismatchFinding;
}

function controlsFor(
  diagnosis: ExperimentDiagnosis,
): ExperimentFrozenControl[] {
  const controls = new Set<ExperimentFrozenControl>(COMMON_CONTROLS);
  if (diagnosis !== "evaluator-drift") {
    controls.add("evaluator-calibration");
  }
  if (
    diagnosis !== "ttft-regression"
    && diagnosis !== "tail-latency-regression"
    && diagnosis !== "error-regression"
    && diagnosis !== "cost-regression"
    && diagnosis !== "capability-mismatch"
  ) {
    controls.add("execution-profiles");
  }
  if (
    diagnosis !== "quality-regression"
    && diagnosis !== "critical-slice-regression"
  ) {
    controls.add("routing-policy");
  }
  if (diagnosis !== "sealed-shadow-replication") {
    controls.add("sampling-membership");
  }
  return [...controls].sort(compareCodeUnits);
}

function simpleRequirement(
  kind: Extract<
    ExperimentEvidenceRequirement,
    { readonly kind: string }
  >["kind"],
): ExperimentEvidenceRequirement {
  if (kind === "runtime-capability-evidence") {
    throw new Error(
      "runtime capability evidence requires explicit lineage",
    );
  }
  return { kind };
}

function requirementsFor(
  match: DiagnosisMatch,
): ExperimentEvidenceRequirement[] {
  let requirements: ExperimentEvidenceRequirement[];
  switch (match.diagnosis) {
    case "insufficient-evidence":
      requirements = [
        simpleRequirement("paired-evaluator-evidence"),
        simpleRequirement("independent-group-coverage"),
        simpleRequirement("observer-failure-evidence"),
      ];
      break;
    case "evaluator-drift":
      requirements = [
        simpleRequirement("evaluator-calibration-evidence"),
      ];
      break;
    case "quality-regression":
      requirements = [
        simpleRequirement("paired-evaluator-evidence"),
        simpleRequirement("independent-group-coverage"),
      ];
      break;
    case "critical-slice-regression":
      requirements = [
        simpleRequirement("paired-evaluator-evidence"),
        simpleRequirement("critical-slice-coverage"),
      ];
      break;
    case "ttft-regression":
    case "tail-latency-regression":
      requirements = [
        simpleRequirement("observer-timing-evidence"),
        simpleRequirement("paired-evaluator-evidence"),
        simpleRequirement("observer-failure-evidence"),
      ];
      break;
    case "error-regression":
      requirements = [
        simpleRequirement("observer-failure-evidence"),
        simpleRequirement("paired-evaluator-evidence"),
      ];
      break;
    case "cost-regression":
      requirements = [
        simpleRequirement("attempt-cost-evidence"),
        simpleRequirement("paired-evaluator-evidence"),
      ];
      break;
    case "unavailable-capacity":
      requirements = [
        simpleRequirement("exact-policy-capacity-evidence"),
      ];
      break;
    case "capability-mismatch": {
      const finding = match.capabilityFinding;
      if (finding === undefined) {
        throw new Error(
          "capability mismatch requires exact evidence lineage",
        );
      }
      requirements = [{
        kind: "runtime-capability-evidence",
        protocolDigest: finding.protocolDigest,
        profileId: finding.profileId,
        capabilityId: finding.capabilityId,
        evidenceDigest: finding.capabilityEvidenceDigest,
      }];
      break;
    }
    case "sealed-shadow-replication":
      requirements = [
        simpleRequirement("sealed-shadow-window-evidence"),
        simpleRequirement("paired-evaluator-evidence"),
        simpleRequirement("independent-group-coverage"),
      ];
      break;
  }
  return sortedUnique(requirements);
}

function changedVariableFor(
  match: DiagnosisMatch,
): ExperimentChangedVariable {
  switch (match.diagnosis) {
    case "insufficient-evidence":
      return {
        kind: "evidence-collection",
        targetId: "assessment-evidence",
      };
    case "evaluator-drift":
      return {
        kind: "evaluator-calibration",
        targetId: "external-evaluator",
      };
    case "quality-regression":
    case "critical-slice-regression":
      return {
        kind: "routing-policy",
        targetId: "selected-policy",
      };
    case "ttft-regression":
    case "tail-latency-regression":
    case "error-regression":
    case "cost-regression":
      return {
        kind: "execution-profile",
        targetId: "selected-profile",
      };
    case "unavailable-capacity":
      return {
        kind: "capacity-observation",
        targetId: "nominated-window",
      };
    case "capability-mismatch": {
      const finding = match.capabilityFinding;
      if (finding === undefined) {
        throw new Error(
          "capability mismatch requires exact evidence lineage",
        );
      }
      return {
        kind: "required-capability",
        targetId: finding.capabilityId,
        profileId: finding.profileId,
      };
    }
    case "sealed-shadow-replication":
      return {
        kind: "evidence-window",
        targetId: "sealed-shadow-window",
      };
  }
}

function assertProposalSemantics(proposal: MutableProposalBody): void {
  assertCanonicalArray(proposal.frozenControls, "frozen controls");
  assertCanonicalArray(
    proposal.evidenceRequirements,
    "evidence requirements",
  );
  if (
    proposal.stopCondition.budgetDigest
      !== proposal.budget.budgetDigest
  ) {
    throw new Error(
      "experiment stop condition must bind the exact proposal budget",
    );
  }
  if (proposal.hypothesis !== HYPOTHESES[proposal.diagnosis]) {
    throw new Error(
      "experiment proposal semantic mismatch: hypothesis does not match "
      + "the deterministic diagnosis",
    );
  }
  const capabilityRequirements = proposal.evidenceRequirements.filter(
    (requirement) =>
      requirement.kind === "runtime-capability-evidence",
  );
  if (
    proposal.diagnosis === "capability-mismatch"
      ? (
        capabilityRequirements.length !== 1
        || capabilityRequirements[0].kind
          !== "runtime-capability-evidence"
        || capabilityRequirements[0].protocolDigest
          !== proposal.parentProtocolDigest
        || proposal.changedVariable.kind
          !== "required-capability"
        || capabilityRequirements[0].capabilityId
          !== proposal.changedVariable.targetId
        || capabilityRequirements[0].profileId
          !== proposal.changedVariable.profileId
      )
      : capabilityRequirements.length !== 0
  ) {
    throw new Error(
      "capability diagnosis must retain exactly one parent-protocol, "
      + "profile-bound evidence finding",
    );
  }
  const semanticMatch: DiagnosisMatch = {
    diagnosis: proposal.diagnosis,
    ...(proposal.diagnosis === "capability-mismatch"
      && capabilityRequirements[0]?.kind
        === "runtime-capability-evidence"
      ? {
        capabilityFinding: {
          kind: "required-capability-mismatch",
          protocolDigest: capabilityRequirements[0].protocolDigest,
          profileId: capabilityRequirements[0].profileId,
          capabilityId: capabilityRequirements[0].capabilityId,
          capabilityEvidenceDigest:
            capabilityRequirements[0].evidenceDigest,
        },
      }
      : {}),
  };
  if (
    canonicalJson(proposal.changedVariable)
      !== canonicalJson(changedVariableFor(semanticMatch))
  ) {
    throw new Error(
      "experiment proposal semantic mismatch: changed variable does "
      + "not match the deterministic diagnosis and evidence lineage",
    );
  }
  const expectedControls = controlsFor(proposal.diagnosis);
  if (
    canonicalJson(proposal.frozenControls)
      !== canonicalJson(expectedControls)
  ) {
    throw new Error(
      "experiment proposal semantic mismatch: frozen controls do not "
      + "match the deterministic diagnosis",
    );
  }
  const expectedRequirements = requirementsFor(semanticMatch);
  if (
    canonicalJson(proposal.evidenceRequirements)
      !== canonicalJson(expectedRequirements)
  ) {
    throw new Error(
      "experiment proposal semantic mismatch: evidence requirements do "
      + "not match the deterministic diagnosis",
    );
  }
  if (proposal.experimentIntentDigest !== fingerprintIntent(proposal)) {
    throw new Error(
      "experiment intent digest does not match canonical intent content",
    );
  }
}

function assertHoldSemantics(hold: MutableHoldBody): void {
  const duplicate = hold.holdReason
    === "duplicate-registered-experiment";
  if (duplicate !== (hold.relatedProtocolDigest !== null)) {
    throw new Error(
      "only a duplicate experiment HOLD may name a related protocol",
    );
  }
}

function decisionBody(
  input: unknown,
): MutableDecisionBody {
  const snapshot = snapshotBoundedContractInput(input);
  const object = z.record(z.unknown()).parse(snapshot);
  const {
    decisionDigest: _decisionDigest,
    ...bodyInput
  } = object;
  const body = decisionBodySchema.parse(bodyInput);
  if (body.status === "PROPOSED") {
    assertProposalSemantics(body);
  } else {
    assertHoldSemantics(body);
  }
  return body;
}

export function fingerprintExperimentProposalDecision(
  input: unknown,
): string {
  return domainSeparatedDigest(DECISION_DOMAIN, decisionBody(input));
}

export function parseExperimentProposalDecision(
  input: unknown,
): ExperimentProposalDecision {
  const snapshot = snapshotBoundedContractInput(input);
  const decision = decisionSchema.parse(snapshot);
  const {
    decisionDigest,
    ...body
  } = decision;
  if (body.status === "PROPOSED") {
    assertProposalSemantics(body);
  } else {
    assertHoldSemantics(body);
  }
  const expected = domainSeparatedDigest(DECISION_DOMAIN, body);
  if (decisionDigest !== expected) {
    throw new Error(
      "experiment proposal decision digest does not match canonical content",
    );
  }
  return deepFreezeContract(decision) as ExperimentProposalDecision;
}

function finishDecision(
  body: MutableDecisionBody,
): ExperimentProposalDecision {
  return parseExperimentProposalDecision({
    ...body,
    decisionDigest: domainSeparatedDigest(DECISION_DOMAIN, body),
  });
}

function holdDecision(
  parentAssessmentDigest: string,
  parentProtocolDigest: string,
  history: ExperimentHistory,
  budget: ExperimentBudget,
  holdReason: ExperimentHoldReason,
  relatedProtocolDigest: string | null = null,
): ExperimentProposalDecision {
  return finishDecision({
    version: "tasc-experiment-proposal-decision-v2",
    status: "HOLD",
    parentAssessmentDigest,
    parentProtocolDigest,
    historyDigest: history.historyDigest,
    budget,
    holdReason,
    relatedProtocolDigest,
    authority: "operator-registration-required",
    attestation: "unattested",
  });
}

function candidatesWithFailedGate(
  candidates: readonly CandidateAssessment[],
  predicate: (gateId: string) => boolean,
): CandidateAssessment | null {
  for (const candidate of candidates) {
    if (
      candidate.gates.some(
        ({ id, passed, actual }) =>
          !passed
          && actual !== null
          && predicate(id),
      )
    ) {
      return candidate;
    }
  }
  return null;
}

const EVALUATOR_STALE_REASONS = new Set([
  "evaluator-verification-context-drift",
  "evaluator-evidence-revoked",
  "evaluator-evidence-stale",
  "evaluator-evidence-future-dated",
  "evaluator-evidence-key-not-yet-valid",
  "evaluator-evidence-key-expired",
  "evaluator-evidence-produced-after-assessment-cutoff",
]);

function isEvaluatorOnlyStale(
  assessment: ReturnType<typeof parseAssessmentDecision>,
): boolean {
  return assessment.status === "STALE"
    && assessment.staleReasons.length > 0
    && assessment.staleReasons.every(
      (reason) => EVALUATOR_STALE_REASONS.has(reason),
    );
}

function candidateProfileIds(
  candidate: CandidateAssessment,
): string[] {
  return [
    candidate.policy.primaryProfileId,
    candidate.policy.expertProfileId,
    ...(candidate.policy.fallbackProfileId === null
      ? []
      : [candidate.policy.fallbackProfileId]),
  ];
}

function capabilityFindingFor(
  protocolDigest: string,
  candidates: readonly CandidateAssessment[],
  findings: readonly RequiredCapabilityMismatchFinding[],
): RequiredCapabilityMismatchFinding | null {
  const profiles = new Set(
    candidates.flatMap(candidateProfileIds),
  );
  return findings.find(
    (finding) =>
      finding.protocolDigest === protocolDigest
      && profiles.has(finding.profileId),
  ) ?? null;
}

function actionableDiagnosis(
  assessment: ReturnType<typeof parseAssessmentDecision>,
  history: ExperimentHistory,
): DiagnosisMatch | null {
  const candidates = assessment.selectedPolicyDigest === null
    ? assessment.candidates
    : assessment.candidates.filter(
      ({ policyDigest }) =>
        policyDigest === assessment.selectedPolicyDigest,
    );
  if (
    assessment.selectedPolicyDigest !== null
    && candidates.length !== 1
  ) {
    throw new Error(
      "selected assessment policy must identify exactly one candidate",
    );
  }
  const nonCapacityInsufficiency = candidates.find(
    ({ insufficiencyReasons }) =>
      insufficiencyReasons.some(
        (reason) =>
          reason !== "required-service-capacity-unavailable",
      ),
  );
  if (nonCapacityInsufficiency !== undefined) {
    return {
      diagnosis: "insufficient-evidence",
    };
  }
  if (
    isEvaluatorOnlyStale(assessment)
  ) {
    return {
      diagnosis: "evaluator-drift",
    };
  }
  const quality = candidatesWithFailedGate(
    candidates,
    (id) => id === "paired-quality"
      || id === "minimum-mean-score",
  );
  if (quality !== null) {
    return {
      diagnosis: "quality-regression",
    };
  }
  const critical = candidatesWithFailedGate(
    candidates,
    (id) => {
      const prefix = "paired-critical-slice-quality:";
      if (!id.startsWith(prefix)) return false;
      const candidateSlice = id.slice(prefix.length);
      return contractSlugSchema.safeParse(candidateSlice).success;
    },
  );
  if (critical !== null) {
    return {
      diagnosis: "critical-slice-regression",
    };
  }
  const gateDiagnoses: readonly {
    readonly id: string;
    readonly diagnosis: ExperimentDiagnosis;
  }[] = [
    { id: "maximum-p95-ttft", diagnosis: "ttft-regression" },
    {
      id: "maximum-p95-end-to-end",
      diagnosis: "tail-latency-regression",
    },
    { id: "maximum-failure-rate", diagnosis: "error-regression" },
    {
      id: "maximum-cost-per-thousand",
      diagnosis: "cost-regression",
    },
  ];
  for (const { id, diagnosis } of gateDiagnoses) {
    const candidate = candidatesWithFailedGate(
      candidates,
      (gateId) => gateId === id,
    );
    if (candidate !== null) {
      return {
        diagnosis,
      };
    }
  }
  const capacity = assessment.phase === "window"
    ? candidates.find(
      ({ insufficiencyReasons, gates }) =>
        insufficiencyReasons.includes(
          "required-service-capacity-unavailable",
        )
        || gates.some(
          ({ id, passed, actual }) =>
            id === "minimum-service-capacity"
            && !passed
            && actual === null,
        ),
    )
    : undefined;
  if (capacity !== undefined) {
    return {
      diagnosis: "unavailable-capacity",
    };
  }
  const finding = capabilityFindingFor(
    assessment.protocolDigest,
    candidates,
    history.findings,
  );
  if (finding !== null) {
    return {
      diagnosis: "capability-mismatch",
      capabilityFinding: finding,
    };
  }
  if (
    assessment.phase === "development"
    && assessment.status === "NOMINATED"
  ) {
    return {
      diagnosis: "sealed-shadow-replication",
    };
  }
  return null;
}

function proposalBody(
  parentAssessmentDigest: string,
  parentProtocolDigest: string,
  history: ExperimentHistory,
  budget: ExperimentBudget,
  match: DiagnosisMatch,
): MutableProposalBody {
  const base = {
    version: "tasc-experiment-proposal-decision-v2" as const,
    status: "PROPOSED" as const,
    parentAssessmentDigest,
    parentProtocolDigest,
    historyDigest: history.historyDigest,
    budget,
    diagnosis: match.diagnosis,
    hypothesis: HYPOTHESES[match.diagnosis],
    changedVariable: changedVariableFor(match),
    frozenControls: controlsFor(match.diagnosis),
    evidenceRequirements: requirementsFor(match),
    stopCondition: {
      kind: "first-budget-limit" as const,
      budgetDigest: budget.budgetDigest,
    },
    expectedDecision: {
      ifSupported: "REASSESS_WITH_REGISTERED_PROTOCOL" as const,
      otherwise: "HOLD" as const,
    },
    authority: "operator-registration-required" as const,
    attestation: "unattested" as const,
  };
  return proposalBodySchema.parse({
    ...base,
    experimentIntentDigest: domainSeparatedDigest(
      INTENT_DOMAIN,
      experimentIntentBody(base),
    ),
  });
}

/**
 * Inspect one strict persisted assessment and emit one bounded, unattested
 * experiment intent. This function is pure: it performs no model call,
 * endpoint discovery, payload inspection, protocol registration, or
 * deployment action.
 */
export function proposeExperiment(
  assessmentInput: unknown,
  historyInput: unknown,
  budgetInput: unknown,
): ExperimentProposalDecision {
  const assessment = parseAssessmentDecision(assessmentInput);
  const history = parseExperimentHistory(historyInput);
  const budget = parseExperimentBudget(budgetInput);
  const parentAssessmentDigest = assessment.decisionDigest;
  const parentProtocolDigest = assessment.protocolDigest;

  if (assessment.phase === "holdout") {
    return holdDecision(
      parentAssessmentDigest,
      parentProtocolDigest,
      history,
      budget,
      "holdout-tuning-forbidden",
    );
  }
  if (
    assessment.phase === "window"
    && assessment.status === "PASS"
  ) {
    return holdDecision(
      parentAssessmentDigest,
      parentProtocolDigest,
      history,
      budget,
      "assessment-already-passing",
    );
  }
  if (
    assessment.status === "STALE"
    && !isEvaluatorOnlyStale(assessment)
  ) {
    return holdDecision(
      parentAssessmentDigest,
      parentProtocolDigest,
      history,
      budget,
      "structural-staleness",
    );
  }
  if (
    budget.maxLogicalExecutions < 2
    || budget.maxAttempts < 2
    || budget.maxWallClockMs === 0
  ) {
    return holdDecision(
      parentAssessmentDigest,
      parentProtocolDigest,
      history,
      budget,
      "insufficient-proposal-budget",
    );
  }

  const match = actionableDiagnosis(assessment, history);
  if (match === null) {
    return holdDecision(
      parentAssessmentDigest,
      parentProtocolDigest,
      history,
      budget,
      "no-actionable-diagnosis",
    );
  }
  const proposal = proposalBody(
    parentAssessmentDigest,
    parentProtocolDigest,
    history,
    budget,
    match,
  );
  const duplicate = history.registeredExperiments.find(
    ({ experimentIntentDigest }) =>
      experimentIntentDigest === proposal.experimentIntentDigest,
  );
  if (duplicate !== undefined) {
    return holdDecision(
      parentAssessmentDigest,
      parentProtocolDigest,
      history,
      budget,
      "duplicate-registered-experiment",
      duplicate.registeredProtocolDigest,
    );
  }
  return finishDecision(proposal);
}
