import { z } from "zod";
import { compareCodeUnits } from "./determinism.js";
import {
  parseControllerSnapshot,
  type ControllerSnapshot,
} from "./controller-events.js";
import {
  contractDigestSchema,
  contractSlugSchema,
  contractTimestampSchema,
  deepFreezeContract,
  domainSeparatedDigest,
  fingerprintExecutionProfile,
  fingerprintNormalizedProtocol,
  normalizeExperimentProtocol,
  snapshotBoundedContractInput,
  type DeepReadonly,
  type ExperimentProtocol,
} from "./evidence.js";
import {
  assertPolicyBundleMatchesProtocol,
  parsePolicyBundleValue,
  type PolicyBundle,
} from "./policy.js";
import {
  deriveWindowMembershipDigest,
  isWindowMembershipSelected,
} from "./window.js";

export const SHADOW_RUN_PLAN_VERSION = "tasc-shadow-run-plan-v1" as const;
export const SHADOW_RUN_PLAN_AUTHORITY =
  "out-of-band-controller-only-no-deployment-authority" as const;

const SHADOW_RUN_PLAN_DIGEST_DOMAIN = "tasc/shadow-run-plan/v1";
const MAX_COLLECTION_TARGETS = 16;
const MAX_CAPABILITY_RECEIPTS = 16;

const safePositiveIntegerSchema = z.number()
  .int()
  .min(1)
  .max(Number.MAX_SAFE_INTEGER);

const routeSchema = z.enum([
  "chatCompletions",
  "completions",
  "responses",
  "nativeChat",
  "nativeGenerate",
]);

const workBudgetSchema = z.object({
  maxCases: safePositiveIntegerSchema,
  maxProfiles: safePositiveIntegerSchema,
  maxReplicates: safePositiveIntegerSchema,
  maxLogicalExecutions: safePositiveIntegerSchema,
  maxAttempts: safePositiveIntegerSchema,
  maxNetworkCalls: safePositiveIntegerSchema,
  maxDurableRecords: safePositiveIntegerSchema,
  maxRequestBytes: safePositiveIntegerSchema,
  maxResponseBytes: safePositiveIntegerSchema,
  maxWallClockMs: safePositiveIntegerSchema,
  maxConcurrency: safePositiveIntegerSchema,
}).strict();

const collectionTargetInputSchema = z.object({
  profileId: contractSlugSchema,
  endpointAlias: contractSlugSchema,
  endpointBindingDigest: contractDigestSchema,
  route: routeSchema,
  authenticationReference: contractSlugSchema.nullable(),
  capabilityReceiptDigests:
    z.array(contractDigestSchema).max(MAX_CAPABILITY_RECEIPTS),
}).strict();

const collectionTargetSchema = collectionTargetInputSchema.extend({
  executionProfileDigest: contractDigestSchema,
  runtimeName: contractSlugSchema,
  transport: z.enum(["https", "loopback-http"]),
}).strict();

const windowInputSchema = z.object({
  windowId: contractSlugSchema,
  eventTimeStartInclusive: contractTimestampSchema,
  eventTimeEndExclusive: contractTimestampSchema,
}).strict();

const membershipRuleSchema = z.object({
  algorithm: z.literal(
    "tasc-seeded-sha256-case-replicate-basis-points-v1",
  ),
  seed: contractSlugSchema,
  sampleBasisPoints: z.number().int().min(0).max(10_000),
}).strict();

const windowSchema = windowInputSchema.extend({
  membershipRule: membershipRuleSchema,
  membershipDigest: contractDigestSchema,
}).strict();

const buildInputSchema = z.object({
  controllerSnapshot: z.unknown(),
  protocol: z.unknown(),
  frozenPolicy: z.unknown(),
  window: windowInputSchema,
  collectionTargets:
    z.array(collectionTargetInputSchema).min(1).max(MAX_COLLECTION_TARGETS),
  workBudget: workBudgetSchema,
  issuedAt: contractTimestampSchema,
  expiresAt: contractTimestampSchema,
}).strict();

const planBodySchema = z.object({
  version: z.literal(SHADOW_RUN_PLAN_VERSION),
  authority: z.literal(SHADOW_RUN_PLAN_AUTHORITY),
  controllerSnapshot: z.unknown(),
  controllerSnapshotDigest: contractDigestSchema,
  protocol: z.unknown(),
  protocolDigest: contractDigestSchema,
  frozenPolicy: z.unknown(),
  frozenPolicyDigest: contractDigestSchema,
  window: windowSchema,
  collectionTargets:
    z.array(collectionTargetSchema).min(1).max(MAX_COLLECTION_TARGETS),
  workBudget: workBudgetSchema,
  issuedAt: contractTimestampSchema,
  expiresAt: contractTimestampSchema,
}).strict();

const planSchema = planBodySchema.extend({
  planDigest: contractDigestSchema,
}).strict();

export type ShadowRunPlanRoute = z.infer<typeof routeSchema>;
export type ShadowRunPlanWorkBudget =
  DeepReadonly<z.infer<typeof workBudgetSchema>>;
export type ShadowRunPlanCollectionTargetInput =
  DeepReadonly<z.infer<typeof collectionTargetInputSchema>>;
export type ShadowRunPlanCollectionTarget =
  DeepReadonly<z.infer<typeof collectionTargetSchema>>;
export type ShadowRunPlanWindowInput =
  DeepReadonly<z.infer<typeof windowInputSchema>>;
export type ShadowRunPlanWindow =
  DeepReadonly<z.infer<typeof windowSchema>>;

export interface BuildShadowRunPlanInput {
  readonly controllerSnapshot: ControllerSnapshot;
  readonly protocol: ExperimentProtocol;
  readonly frozenPolicy: PolicyBundle;
  readonly window: ShadowRunPlanWindowInput;
  readonly collectionTargets:
    readonly ShadowRunPlanCollectionTargetInput[];
  readonly workBudget: ShadowRunPlanWorkBudget;
  readonly issuedAt: string;
  readonly expiresAt: string;
}

export interface ShadowRunPlanBody {
  readonly version: typeof SHADOW_RUN_PLAN_VERSION;
  readonly authority: typeof SHADOW_RUN_PLAN_AUTHORITY;
  readonly controllerSnapshot: ControllerSnapshot;
  readonly controllerSnapshotDigest: string;
  readonly protocol: ExperimentProtocol;
  readonly protocolDigest: string;
  readonly frozenPolicy: PolicyBundle;
  readonly frozenPolicyDigest: string;
  readonly window: ShadowRunPlanWindow;
  readonly collectionTargets: readonly ShadowRunPlanCollectionTarget[];
  readonly workBudget: ShadowRunPlanWorkBudget;
  readonly issuedAt: string;
  readonly expiresAt: string;
}

export type ShadowRunPlan = DeepReadonly<
  ShadowRunPlanBody & { readonly planDigest: string }
>;

function assertBefore(
  left: string,
  right: string,
  message: string,
): void {
  if (compareCodeUnits(left, right) >= 0) {
    throw new Error(message);
  }
}

function assertAtOrAfter(
  value: string,
  floor: string,
  message: string,
): void {
  if (compareCodeUnits(value, floor) < 0) {
    throw new Error(message);
  }
}

function assertAtOrBefore(
  value: string,
  ceiling: string,
  message: string,
): void {
  if (compareCodeUnits(value, ceiling) > 0) {
    throw new Error(message);
  }
}

function assertUniqueSortedDigests(
  values: readonly string[],
  profileId: string,
): readonly string[] {
  const sorted = [...values].sort(compareCodeUnits);
  if (new Set(sorted).size !== sorted.length) {
    throw new Error(
      `collection target "${profileId}" has duplicate capability receipts`,
    );
  }
  return Object.freeze(sorted);
}

function normalizeCollectionTargets(
  inputTargets: readonly z.infer<typeof collectionTargetInputSchema>[],
  protocol: ExperimentProtocol,
): readonly ShadowRunPlanCollectionTarget[] {
  const profiles = new Map(
    protocol.profiles.map((profile) => [profile.id, profile]),
  );
  const seenProfiles = new Set<string>();
  const targets = inputTargets.map((targetInput) => {
    const target = collectionTargetInputSchema.parse(targetInput);
    if (seenProfiles.has(target.profileId)) {
      throw new Error(
        `duplicate collection target for profile "${target.profileId}"`,
      );
    }
    seenProfiles.add(target.profileId);
    const profile = profiles.get(target.profileId);
    if (profile === undefined) {
      throw new Error(
        `collection target references unknown profile "${target.profileId}"`,
      );
    }
    const endpoint = protocol.endpointRequirements.find(
      (requirement) => requirement.endpointAlias === target.endpointAlias,
    );
    if (
      endpoint === undefined
      || endpoint.runtimeName !== profile.runtime.name
    ) {
      throw new Error(
        `collection target "${target.profileId}" does not match a protocol `
        + "endpoint requirement",
      );
    }
    return {
      ...target,
      capabilityReceiptDigests: assertUniqueSortedDigests(
        target.capabilityReceiptDigests,
        target.profileId,
      ),
      executionProfileDigest: fingerprintExecutionProfile(profile),
      runtimeName: profile.runtime.name,
      transport: endpoint.transport,
    };
  });

  if (
    seenProfiles.size !== profiles.size
    || [...profiles.keys()].some((profileId) => !seenProfiles.has(profileId))
  ) {
    throw new Error(
      "collection targets must bind every protocol execution profile exactly once",
    );
  }
  targets.sort((left, right) =>
    compareCodeUnits(left.profileId, right.profileId)
  );
  return deepFreezeContract(targets);
}

function assertWorkBudgetSemantics(
  workBudget: ShadowRunPlanWorkBudget,
  targetCount: number,
  protocol: ExperimentProtocol,
  planDurationMs: number,
  windowDurationMs: number,
): void {
  if (workBudget.maxProfiles < targetCount) {
    throw new Error("shadow plan work budget cannot admit its profile targets");
  }
  if (
    workBudget.maxLogicalExecutions
      > protocol.shadowCollection.maximumLogicalExecutions
  ) {
    throw new Error(
      "shadow plan logical-execution budget exceeds the protocol ceiling",
    );
  }
  if (
    workBudget.maxConcurrency > protocol.shadowCollection.maximumConcurrency
  ) {
    throw new Error(
      "shadow plan concurrency budget exceeds the protocol ceiling",
    );
  }
  if (workBudget.maxWallClockMs > planDurationMs) {
    throw new Error(
      "shadow plan wall-clock budget exceeds the plan validity interval",
    );
  }
  if (workBudget.maxWallClockMs > windowDurationMs) {
    throw new Error(
      "shadow plan wall-clock budget exceeds the event window",
    );
  }
}

function normalizePlanBody(input: unknown): ShadowRunPlanBody {
  const raw = planBodySchema.parse(snapshotBoundedContractInput(input));
  const controllerSnapshot = parseControllerSnapshot(raw.controllerSnapshot);
  const protocol = normalizeExperimentProtocol(raw.protocol);
  const frozenPolicy = parsePolicyBundleValue(raw.frozenPolicy);
  assertPolicyBundleMatchesProtocol(frozenPolicy, protocol);

  const protocolDigest = fingerprintNormalizedProtocol(protocol);
  if (
    controllerSnapshot.state !== "SHADOW_ASSESSING"
    || controllerSnapshot.selectedPolicy === null
  ) {
    throw new Error(
      "shadow run plan requires a SHADOW_ASSESSING controller snapshot",
    );
  }
  if (
    controllerSnapshot.studyId !== protocol.studyId
    || controllerSnapshot.protocolDigest !== protocolDigest
    || controllerSnapshot.protocolCreatedAt !== protocol.createdAt
    || controllerSnapshot.protocolExpiresAt !== protocol.expiresAt
  ) {
    throw new Error(
      "shadow run plan controller snapshot does not match its protocol",
    );
  }
  if (
    controllerSnapshot.selectedPolicy.policyDigest
      !== frozenPolicy.policyDigest
    || controllerSnapshot.selectedPolicy.issuedAt !== frozenPolicy.issuedAt
    || controllerSnapshot.selectedPolicy.expiresAt !== frozenPolicy.expiresAt
  ) {
    throw new Error(
      "shadow run plan policy does not match the controller selection",
    );
  }
  if (
    raw.controllerSnapshotDigest !== controllerSnapshot.snapshotDigest
    || raw.protocolDigest !== protocolDigest
    || raw.frozenPolicyDigest !== frozenPolicy.policyDigest
  ) {
    throw new Error("shadow run plan contains a mismatched derived digest");
  }

  const expectedMembershipDigest = deriveWindowMembershipDigest(
    raw.window.windowId,
    protocolDigest,
    protocol.onlineWindowMembership,
  );
  if (
    raw.window.membershipDigest !== expectedMembershipDigest
    || raw.window.membershipRule.algorithm
      !== protocol.onlineWindowMembership.algorithm
    || raw.window.membershipRule.seed !== protocol.onlineWindowMembership.seed
    || raw.window.membershipRule.sampleBasisPoints
      !== protocol.onlineWindowMembership.sampleBasisPoints
  ) {
    throw new Error(
      "shadow run plan window membership does not match its protocol",
    );
  }

  assertBefore(
    raw.issuedAt,
    raw.expiresAt,
    "shadow run plan expiry must be after issue time",
  );
  assertAtOrAfter(
    raw.issuedAt,
    controllerSnapshot.lastEventAt
      ?? controllerSnapshot.protocolCreatedAt,
    "shadow run plan cannot predate its controller snapshot",
  );
  assertAtOrAfter(
    raw.issuedAt,
    frozenPolicy.issuedAt,
    "shadow run plan cannot predate its frozen policy",
  );
  assertAtOrBefore(
    raw.expiresAt,
    protocol.expiresAt,
    "shadow run plan expiry exceeds protocol validity",
  );
  assertAtOrBefore(
    raw.expiresAt,
    frozenPolicy.expiresAt,
    "shadow run plan expiry exceeds frozen policy validity",
  );
  assertBefore(
    raw.window.eventTimeStartInclusive,
    raw.window.eventTimeEndExclusive,
    "shadow run plan event-time start must precede its exclusive end",
  );
  assertAtOrAfter(
    raw.window.eventTimeStartInclusive,
    raw.issuedAt,
    "shadow run plan event window cannot begin before plan issue",
  );
  assertAtOrBefore(
    raw.window.eventTimeEndExclusive,
    raw.expiresAt,
    "shadow run plan event window exceeds plan validity",
  );

  const normalizedTargets = normalizeCollectionTargets(
    raw.collectionTargets.map((target) => ({
      profileId: target.profileId,
      endpointAlias: target.endpointAlias,
      endpointBindingDigest: target.endpointBindingDigest,
      route: target.route,
      authenticationReference: target.authenticationReference,
      capabilityReceiptDigests: target.capabilityReceiptDigests,
    })),
    protocol,
  );
  for (const [index, target] of raw.collectionTargets.entries()) {
    const normalized = normalizedTargets[index];
    if (
      normalized === undefined
      || target.profileId !== normalized.profileId
      || target.executionProfileDigest !== normalized.executionProfileDigest
      || target.runtimeName !== normalized.runtimeName
      || target.endpointAlias !== normalized.endpointAlias
      || target.transport !== normalized.transport
      || target.endpointBindingDigest !== normalized.endpointBindingDigest
      || target.route !== normalized.route
      || target.authenticationReference
        !== normalized.authenticationReference
      || target.capabilityReceiptDigests.length
        !== normalized.capabilityReceiptDigests.length
      || target.capabilityReceiptDigests.some(
        (digest, digestIndex) =>
          digest !== normalized.capabilityReceiptDigests[digestIndex],
      )
    ) {
      throw new Error(
        "shadow run plan collection targets are not canonically derived",
      );
    }
  }

  const issuedAtMs = Date.parse(raw.issuedAt);
  const expiresAtMs = Date.parse(raw.expiresAt);
  assertWorkBudgetSemantics(
    raw.workBudget,
    normalizedTargets.length,
    protocol,
    expiresAtMs - issuedAtMs,
    Date.parse(raw.window.eventTimeEndExclusive)
      - Date.parse(raw.window.eventTimeStartInclusive),
  );

  return deepFreezeContract({
    version: SHADOW_RUN_PLAN_VERSION,
    authority: SHADOW_RUN_PLAN_AUTHORITY,
    controllerSnapshot,
    controllerSnapshotDigest: controllerSnapshot.snapshotDigest,
    protocol,
    protocolDigest,
    frozenPolicy,
    frozenPolicyDigest: frozenPolicy.policyDigest,
    window: {
      windowId: raw.window.windowId,
      eventTimeStartInclusive: raw.window.eventTimeStartInclusive,
      eventTimeEndExclusive: raw.window.eventTimeEndExclusive,
      membershipRule: protocol.onlineWindowMembership,
      membershipDigest: expectedMembershipDigest,
    },
    collectionTargets: normalizedTargets,
    workBudget: raw.workBudget,
    issuedAt: raw.issuedAt,
    expiresAt: raw.expiresAt,
  });
}

function bodyWithoutDigest(input: unknown): ShadowRunPlanBody {
  const bounded = snapshotBoundedContractInput(input);
  const parsedPlan = planSchema.safeParse(bounded);
  if (parsedPlan.success) {
    const { planDigest: _planDigest, ...body } = parsedPlan.data;
    return normalizePlanBody(body);
  }
  return normalizePlanBody(bounded);
}

/** Fingerprint the complete self-contained P0 authorization artifact. */
export function fingerprintShadowRunPlan(input: unknown): string {
  return domainSeparatedDigest(
    SHADOW_RUN_PLAN_DIGEST_DOMAIN,
    bodyWithoutDigest(input),
  );
}

/** Build a self-contained P0 plan without accepting caller-supplied identities. */
export function buildShadowRunPlan(
  input: BuildShadowRunPlanInput,
): ShadowRunPlan {
  const raw = buildInputSchema.parse(snapshotBoundedContractInput(input));
  const controllerSnapshot = parseControllerSnapshot(raw.controllerSnapshot);
  const protocol = normalizeExperimentProtocol(raw.protocol);
  const frozenPolicy = parsePolicyBundleValue(raw.frozenPolicy);
  assertPolicyBundleMatchesProtocol(frozenPolicy, protocol);
  const protocolDigest = fingerprintNormalizedProtocol(protocol);
  const collectionTargets = normalizeCollectionTargets(
    raw.collectionTargets,
    protocol,
  );
  const body = normalizePlanBody({
    version: SHADOW_RUN_PLAN_VERSION,
    authority: SHADOW_RUN_PLAN_AUTHORITY,
    controllerSnapshot,
    controllerSnapshotDigest: controllerSnapshot.snapshotDigest,
    protocol,
    protocolDigest,
    frozenPolicy,
    frozenPolicyDigest: frozenPolicy.policyDigest,
    window: {
      ...raw.window,
      membershipRule: protocol.onlineWindowMembership,
      membershipDigest: deriveWindowMembershipDigest(
        raw.window.windowId,
        protocolDigest,
        protocol.onlineWindowMembership,
      ),
    },
    collectionTargets,
    workBudget: raw.workBudget,
    issuedAt: raw.issuedAt,
    expiresAt: raw.expiresAt,
  });
  return parseShadowRunPlan({
    ...body,
    planDigest: domainSeparatedDigest(SHADOW_RUN_PLAN_DIGEST_DOMAIN, body),
  });
}

/** Parse, re-derive, and recursively freeze one persisted shadow run plan. */
export function parseShadowRunPlan(input: unknown): ShadowRunPlan {
  const raw = planSchema.parse(snapshotBoundedContractInput(input));
  const { planDigest, ...rawBody } = raw;
  const body = normalizePlanBody(rawBody);
  const expectedDigest = domainSeparatedDigest(
    SHADOW_RUN_PLAN_DIGEST_DOMAIN,
    body,
  );
  if (planDigest !== expectedDigest) {
    throw new Error("shadow run plan digest does not match canonical content");
  }
  return deepFreezeContract({
    ...body,
    planDigest: expectedDigest,
  });
}

/**
 * Make the protocol's deterministic zero-effect online membership decision
 * from the P0 plan. A zero-basis-point plan always returns false.
 */
export function isShadowRunPlanMember(
  planInput: ShadowRunPlan,
  caseId: string,
  replicateId: string,
): boolean {
  const plan = parseShadowRunPlan(planInput);
  return isWindowMembershipSelected(
    plan.window.membershipRule,
    caseId,
    replicateId,
  );
}
