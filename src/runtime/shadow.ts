import { Buffer } from "node:buffer";
import {
  createHmac,
  randomBytes,
  timingSafeEqual,
  type KeyObject,
} from "node:crypto";
import { isAbsolute, parse as parsePath, resolve as resolvePath } from "node:path";
import { isProxy } from "node:util/types";
import { z } from "zod";
import {
  readArtifactPacketIfPresent,
  writeArtifactPacketOrVerifyIdentical,
  type ArtifactReadResult,
  type ArtifactWriteOrVerifyResult,
} from "../artifacts.js";
import {
  parseBoundedJson,
  type BoundedJsonLimits,
} from "../bounded-input.js";
import {
  canonicalJsonBytes,
  compareCodeUnits,
} from "../determinism.js";
import {
  contractDigestSchema,
  contractSlugSchema,
  contractTimestampSchema,
  collectorAttestationSigningBytes,
  domainSeparatedDigest,
  dispatchIntentSigningBytes,
  fingerprintExecutionProfile,
  fingerprintNormalizedProtocol,
  normalizeExperimentProtocol,
  parseTraceEnvelopeValue,
  verifyTraceDispatchAuthorization,
  verifyTraceDispatchIntent,
  type ExperimentProtocol,
  type TraceDispatchAuthorization,
  type TraceEnvelope,
} from "../evidence.js";
import {
  isShadowRunPlanMember,
  parseShadowRunPlan,
  type ShadowRunPlan,
  type ShadowRunPlanCollectionTarget,
} from "../shadow-plan.js";
import {
  createStudyPayloadIdentity,
  type KeyedPayloadIdentity,
} from "../references.js";
import {
  sanitizeErrorForPersistence,
  type PersistedError,
  type PersistedErrorCategory,
} from "../redaction.js";
import {
  describeRuntimeInvocation,
  dispatchPreparedRuntimeInvocation,
  prepareRuntimeInvocation,
  RuntimeInvocationInputError,
  type PreparedRuntimeInvocation,
  type RuntimeGenerationRequest,
  type RuntimeInvocationDescription,
  type RuntimeInvocationInput,
  type RuntimeInvocationOutcome,
  type RuntimeInvocationPersistence,
} from "./invoke.js";
import {
  DEFAULT_RUNTIME_HTTP_LIMITS,
  type RuntimeHttpLimits,
} from "./http.js";
import {
  authorizeCollectorRequest,
  fingerprintCollectorEndpointBinding,
} from "./network-policy.js";
import { parseEndpointDescriptor } from "./orchestration.js";
import { verifyRuntimeCapabilityAuthorization } from "./probe.js";
import {
  getRuntimeProfile,
  parseRuntimeInstanceIdentity,
} from "./profiles.js";

export const SHADOW_RUNNER_VERSION = "tasc-shadow-runner-v1" as const;
export const SHADOW_RUN_RESULT_VERSION =
  "tasc-shadow-run-result-v1" as const;

const INTENT_RECORD_VERSION = "tasc-shadow-intent-record-v1" as const;
const ADMISSION_RECORD_VERSION = "tasc-shadow-run-admission-v1" as const;
const LEASE_RECORD_VERSION = "tasc-shadow-send-lease-v1" as const;
const OUTCOME_RECORD_VERSION = "tasc-shadow-outcome-record-v1" as const;
const ACCEPTED_RECORD_VERSION = "tasc-shadow-accepted-record-v1" as const;
const COMPLETE_RECORD_VERSION = "tasc-shadow-complete-record-v1" as const;
const AUTHENTICATED_RECORD_VERSION =
  "tasc-shadow-authenticated-record-v1" as const;
const RECORD_AUTHENTICATION_VERSION =
  "tasc-shadow-record-authentication-v1" as const;
const RECORD_AUTHENTICATION_PREFIX =
  "TASC_SHADOW_RECORD_HMAC_V1\u0000";
const RECORD_FILENAME = "record.json";
const RECORD_MEDIA_TYPE = "application/json";
const MAX_CASES = 10_000;
const MAX_PROFILES = 16;
const MAX_REPLICATES = 10_000;
const MAX_TOTAL_LOGICAL_EXECUTIONS = 1_000_000;
const MAX_ROOT_LENGTH = 4_096;
const MAX_CLOCK_MS = 8_640_000_000_000_000;
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/;
const DIGEST_PATTERN = /^sha256:[a-f0-9]{64}$/;
const MANIFEST_DIGEST_PATTERN = /^[a-f0-9]{64}$/;
const CONTRACT_SLUG_PATTERN =
  /^[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?$/;

const RECORD_JSON_LIMITS: Readonly<BoundedJsonLimits> = Object.freeze({
  maxBytes: 1024 * 1024,
  maxDepth: 32,
  maxObjectKeys: 16_384,
  maxArrayItems: 16_384,
  maxTokens: 131_072,
  maxDecodedStringLength: 512 * 1024,
  maxNumericTokenLength: 128,
  maxDiagnosticSnippetLength: 0,
});

type ShadowGenerationRequest = Omit<RuntimeGenerationRequest, "model">;
type ShadowRuntimeTarget = Omit<
  RuntimeInvocationInput,
  "generation" | "identity" | "totalDeadlineMs" | "signal"
>;

export interface ShadowCaseInput {
  readonly caseId: string;
  readonly groupId: string;
  readonly replicates: number;
  /**
   * Ephemeral inference input. It is admitted and HMACed by the runtime
   * invocation boundary, but is never included in a durable shadow record.
   */
  readonly generation: ShadowGenerationRequest;
  readonly workload: {
    readonly mode: string;
    readonly declaredTrafficWeight: number;
    readonly inputTokenEstimate: number | null;
  };
  readonly slices: readonly string[];
  readonly routeSignal?: {
    readonly value: number;
    readonly sourceId: string;
    readonly observedAt: string;
  } | null;
}

export interface ShadowProfileTarget {
  /** Execution-profile id from the experiment protocol. */
  readonly profileId: string;
  /** Runtime authority and route, excluding per-case payload and deadlines. */
  readonly runtime: ShadowRuntimeTarget;
}

/**
 * P0-plan-owned admission ceiling. Every worst-case retry and durable phase is
 * accounted for before signing, filesystem access, or network dispatch.
 */
export interface ShadowWorkBudget {
  readonly maxCases: number;
  readonly maxProfiles: number;
  readonly maxReplicates: number;
  readonly maxLogicalExecutions: number;
  readonly maxAttempts: number;
  readonly maxNetworkCalls: number;
  readonly maxDurableRecords: number;
  readonly maxRequestBytes: number;
  readonly maxResponseBytes: number;
  readonly maxWallClockMs: number;
  readonly maxConcurrency: number;
}

export interface DispatchIntentSigner {
  readonly keyId: string;
  readonly algorithm: "ed25519";
  sign(bytes: Uint8Array): string;
}

export interface CollectorAttestationSigner {
  readonly keyId: string;
  readonly algorithm: "ed25519";
  sign(bytes: Uint8Array): string;
}

/** @internal Fault-injection surface for direct source tests only. */
export type ShadowCrashPoint =
  | "after-intent"
  | "after-lease"
  | "after-dispatch"
  | "after-outcome"
  | "after-accepted"
  | "after-complete";

/** @internal Fault-injection surface for direct source tests only. */
export interface ShadowCheckpointContext {
  readonly traceId: string;
  readonly attemptNumber: number | null;
}

/** @internal Fault-injection surface for direct source tests only. */
export interface ShadowRunnerHooks {
  /** Wall-clock injection for deterministic crash/recovery tests. */
  readonly now?: () => Date;
  readonly prepareInvocation?: (
    input: RuntimeInvocationInput,
  ) => PreparedRuntimeInvocation;
  readonly dispatchInvocation?: (
    prepared: PreparedRuntimeInvocation,
  ) => Promise<RuntimeInvocationOutcome>;
  readonly readPacket?: typeof readArtifactPacketIfPresent;
  readonly writePacket?: typeof writeArtifactPacketOrVerifyIdentical;
  readonly checkpoint?: (
    point: ShadowCrashPoint,
    context: ShadowCheckpointContext,
  ) => void | Promise<void>;
}

export interface ShadowRunInput {
  readonly plan: ShadowRunPlan;
  /**
   * Operator-pinned P0 authority. The plan's self digest proves integrity only;
   * this independently supplied value proves that P1 received the approved plan.
   */
  readonly expectedPlanDigest: string;
  readonly rootDirectory: string;
  readonly cases: readonly ShadowCaseInput[];
  readonly profiles: readonly ShadowProfileTarget[];
  readonly identity: RuntimeInvocationInput["identity"];
  readonly dispatchIntentSigner: DispatchIntentSigner;
  readonly collectorAttestationSigner: CollectorAttestationSigner;
  readonly signal?: AbortSignal;
}

export interface ShadowRunResult {
  readonly version: typeof SHADOW_RUN_RESULT_VERSION;
  readonly status: "complete" | "partial" | "cancelled";
  readonly logicalExecutions: number;
  readonly membershipExcludedReplicates: number;
  readonly traces: readonly TraceEnvelope[];
  readonly pendingTraceIds: readonly string[];
  /** Trace ids in the exact order in which P1 dispatch was entered. */
  readonly dispatchOrder: readonly string[];
  readonly attemptsRecorded: number;
  readonly networkCalls: number;
  readonly durableRecordsWritten: number;
  readonly resumed: number;
  readonly deduplicated: number;
  readonly sentUnknown: number;
}

type TraceAttempt = TraceEnvelope["attempts"][number];
type TraceBase = TraceDispatchAuthorization;

interface IntentRecord {
  readonly version: typeof INTENT_RECORD_VERSION;
  readonly traceId: string;
  readonly requestIdentity: KeyedPayloadIdentity;
  readonly trace: TraceBase;
}

interface RunAdmissionRecord {
  readonly version: typeof ADMISSION_RECORD_VERSION;
  readonly runId: string;
  readonly startedAt: string;
  readonly deadlineAt: string;
  readonly protocolExpiresAt: string;
  readonly workBudgetDigest: string;
  readonly maximumAttemptWorkMs: number;
  readonly maximumResponseBytes: number;
}

interface LeaseRecord {
  readonly version: typeof LEASE_RECORD_VERSION;
  readonly traceId: string;
  readonly attemptId: string;
  readonly attemptNumber: number;
  readonly claimId: string;
  readonly issuedAt: string;
  readonly expiresAt: string;
  readonly preparedDeadlineMs: number;
  readonly httpLimitsDigest: string;
  readonly responseByteLimit: number;
  readonly prepared: PreparedRuntimeInvocation;
}

interface PersistedLease {
  readonly record: LeaseRecord;
  /** True only for the process whose private claim won immutable publication. */
  readonly acquired: boolean;
}

interface OutcomeRecord {
  readonly version: typeof OUTCOME_RECORD_VERSION;
  readonly traceId: string;
  readonly attempt: TraceAttempt;
  readonly terminalOutputId: KeyedPayloadIdentity | null;
}

interface AcceptedRecord {
  readonly version: typeof ACCEPTED_RECORD_VERSION;
  readonly trace: TraceEnvelope;
}

interface CompleteRecord {
  readonly version: typeof COMPLETE_RECORD_VERSION;
  readonly traceId: string;
  readonly traceDigest: string;
  readonly acceptedPacketDigest: string;
}

interface NormalizedCase {
  readonly caseId: string;
  readonly groupId: string;
  readonly replicates: number;
  readonly generation: ShadowGenerationRequest;
  readonly workload: ShadowCaseInput["workload"];
  readonly slices: readonly string[];
  readonly routeSignal: {
    readonly value: number;
    readonly sourceId: string;
    readonly observedAt: string;
  } | null;
}

interface NormalizedProfileTarget {
  readonly profileId: string;
  readonly runtime: ShadowRuntimeTarget;
  readonly httpLimits: RuntimeHttpLimits;
  readonly httpLimitsDigest: string;
  readonly responseByteLimit: number;
  readonly planTarget: ShadowRunPlanCollectionTarget;
}

interface PreflightInvocationMetadata {
  readonly schemaVersion: "tasc-shadow-invocation-description-v1";
  readonly endpointBindingDigest: string;
  readonly profile: PreparedRuntimeInvocation["profile"];
  readonly route: PreparedRuntimeInvocation["route"];
  readonly requestedModel: PreparedRuntimeInvocation["requestedModel"];
  readonly requestIdentity: KeyedPayloadIdentity;
  readonly requestByteCount: number;
  readonly httpLimitsDigest: string;
  readonly responseByteLimit: number;
}

interface JobSeed {
  readonly index: number;
  readonly caseInput: NormalizedCase;
  readonly profileTarget: NormalizedProfileTarget;
  readonly profile: ExperimentProtocol["profiles"][number];
  readonly replicateIndex: number;
  readonly replicateId: string;
}

interface PreparedJob extends JobSeed {
  readonly laneKey: string;
  readonly traceId: string;
  readonly decisionId: string;
  readonly preflight: PreflightInvocationMetadata;
}

interface NormalizedRun {
  readonly plan: ShadowRunPlan;
  readonly protocol: ExperimentProtocol;
  readonly protocolDigest: string;
  readonly rootDirectory: string;
  readonly collectionWindowId: string;
  readonly collectionWindowMembershipDigest: string;
  readonly policyDigest: string;
  readonly identity: RuntimeInvocationInput["identity"];
  readonly signer: DispatchIntentSigner;
  readonly collectorSigner: CollectorAttestationSigner;
  readonly workBudget: ShadowWorkBudget;
  readonly jobs: readonly PreparedJob[];
  readonly runId: string;
  readonly runStartedAtMs: number;
  readonly runDeadlineAtMs: number;
  readonly maximumAttemptWorkMs: number;
  readonly maximumResponseBytes: number;
  readonly membershipExcludedReplicates: number;
  readonly signal: AbortSignal;
  readonly cancellation: RunCancellation;
  readonly hooks: Required<
    Pick<
      ShadowRunnerHooks,
      "prepareInvocation" | "dispatchInvocation" | "readPacket"
      | "writePacket"
    >
  > & Pick<ShadowRunnerHooks, "checkpoint">;
  readonly clock: MonotonicWallClock;
}

interface JobResult {
  readonly trace: TraceEnvelope | null;
  readonly pending: boolean;
  readonly resumed: boolean;
  readonly deduplicated: boolean;
  readonly attemptsRecorded: number;
  readonly sentUnknown: number;
}

interface MutableCounters {
  networkCalls: number;
  durableRecordsWritten: number;
}

type DispatchStart =
  | {
    readonly kind: "not-started";
    readonly observedAtMs: number;
    readonly aborted: boolean;
  }
  | {
    readonly kind: "started";
    readonly outcome: Promise<RuntimeInvocationOutcome> | null;
    readonly failure: unknown;
    readonly failedSynchronously: boolean;
  };

interface DispatchTurn {
  readonly begin: () => DispatchStart;
  readonly resolve: (start: DispatchStart) => void;
  readonly reject: (error: unknown) => void;
}

/**
 * Starts each logical execution's first P1 call in declared job order.
 *
 * Jobs may perform durable P0 work concurrently and P1 promises may overlap,
 * but the synchronous call boundary itself cannot overtake the protocol's
 * counterbalanced order. Jobs that finish without P1 contact explicitly
 * relinquish their turn so resumptions and pending lanes cannot deadlock it.
 */
class StableDispatchOrder {
  readonly #turns = new Map<number, DispatchTurn | null>();
  #nextIndex = 0;

  start(
    jobIndex: number,
    begin: () => DispatchStart,
  ): Promise<DispatchStart> {
    if (jobIndex < this.#nextIndex || this.#turns.has(jobIndex)) {
      throw new Error("shadow dispatch order was entered more than once");
    }
    return new Promise<DispatchStart>((resolve, reject) => {
      this.#turns.set(jobIndex, { begin, resolve, reject });
      this.#pump();
    });
  }

  skip(jobIndex: number): void {
    if (jobIndex < this.#nextIndex || this.#turns.has(jobIndex)) return;
    this.#turns.set(jobIndex, null);
    this.#pump();
  }

  #pump(): void {
    while (this.#turns.has(this.#nextIndex)) {
      const turn = this.#turns.get(this.#nextIndex);
      this.#turns.delete(this.#nextIndex);
      this.#nextIndex += 1;
      if (turn === null || turn === undefined) continue;
      try {
        turn.resolve(turn.begin());
      } catch (error) {
        turn.reject(error);
      }
    }
  }
}

const keyedIdentitySchema = z.object({
  algorithm: z.literal("hmac-sha256"),
  keyId: contractSlugSchema,
  value: z.string().length(64).regex(/^[a-f0-9]{64}$/),
}).strict();

const requestedModelSchema = z.object({
  id: z.string().min(1).max(256),
  revision: z.string().min(1).max(256),
}).strict();

const preparedSchema = z.object({
  schemaVersion: z.literal("tasc-prepared-runtime-invocation-v1"),
  endpointBindingDigest: contractDigestSchema,
  profile: z.object({
    id: z.enum([
      "llama.cpp",
      "lm-studio",
      "mlx-lm",
      "ollama",
      "sglang",
      "tensorrt-llm",
      "tgi",
      "vllm",
    ]),
    build: z.string().min(1).max(256),
  }).strict(),
  route: z.enum([
    "chatCompletions",
    "completions",
    "responses",
    "nativeChat",
    "nativeGenerate",
  ]),
  requestedModel: requestedModelSchema,
  requestIdentity: keyedIdentitySchema,
  requestByteCount: z.number().int().nonnegative().max(1024 * 1024),
}).strict();

const invocationDescriptionSchema = preparedSchema.extend({
  schemaVersion: z.literal("tasc-runtime-invocation-description-v1"),
}).strict();

const leaseRecordSchema = z.object({
  version: z.literal(LEASE_RECORD_VERSION),
  traceId: contractSlugSchema,
  attemptId: contractSlugSchema,
  attemptNumber: z.number().int().min(1).max(8),
  claimId: z.string().length(64).regex(/^[a-f0-9]{64}$/),
  issuedAt: contractTimestampSchema,
  expiresAt: contractTimestampSchema,
  preparedDeadlineMs: z.number().int().positive().max(300_000),
  httpLimitsDigest: contractDigestSchema,
  responseByteLimit: z.number().int().positive().max(16_777_216),
  prepared: preparedSchema,
}).strict();

const runAdmissionRecordSchema = z.object({
  version: z.literal(ADMISSION_RECORD_VERSION),
  runId: contractSlugSchema,
  startedAt: contractTimestampSchema,
  deadlineAt: contractTimestampSchema,
  protocolExpiresAt: contractTimestampSchema,
  workBudgetDigest: contractDigestSchema,
  maximumAttemptWorkMs: z.number().int().positive(),
  maximumResponseBytes: z.number().int().positive(),
}).strict();

const completeRecordSchema = z.object({
  version: z.literal(COMPLETE_RECORD_VERSION),
  traceId: contractSlugSchema,
  traceDigest: contractDigestSchema,
  acceptedPacketDigest: z.string().regex(MANIFEST_DIGEST_PATTERN),
}).strict();

const persistedErrorSchema = z.object({
  version: z.literal("tasc-persisted-error-v1"),
  category: z.enum([
    "authentication",
    "authorization",
    "timeout",
    "rate-limit",
    "transport",
    "invalid-response",
    "cancelled",
    "internal",
    "unknown",
  ]),
  message: z.string().min(1).max(128),
  status: z.number().int().min(100).max(599).nullable(),
  runtime: z.string().min(1).max(128).nullable(),
  requestId: z.string().min(1).max(128).nullable(),
}).strict();

const providerUsageSchema = z.object({
  inputTokens: z.number().int().nonnegative().nullable(),
  outputTokens: z.number().int().nonnegative().nullable(),
  totalTokens: z.number().int().nonnegative().nullable(),
}).strict();

const providerTimingSchema = z.object({
  totalDurationNs: z.number().int().nonnegative()
    .max(86_400_000_000_000).optional(),
  loadDurationNs: z.number().int().nonnegative()
    .max(86_400_000_000_000).optional(),
  promptEvaluationDurationNs: z.number().int().nonnegative()
    .max(86_400_000_000_000).optional(),
  evaluationDurationNs: z.number().int().nonnegative()
    .max(86_400_000_000_000).optional(),
}).strict();

const wireTimingSchema = z.object({
  startedAt: contractTimestampSchema,
  headersMs: z.number().finite().nonnegative().max(300_000).optional(),
  firstByteMs: z.number().finite().nonnegative().max(300_000).optional(),
  completedMs: z.number().finite().nonnegative().max(300_000),
}).strict();

const streamTimingSchema = z.object({
  startedAtMs: z.number().finite().nonnegative().max(Number.MAX_SAFE_INTEGER),
  firstByteAtMs:
    z.number().finite().nonnegative().max(Number.MAX_SAFE_INTEGER).nullable(),
  firstMeaningfulAtMs:
    z.number().finite().nonnegative().max(Number.MAX_SAFE_INTEGER).nullable(),
  completedAtMs:
    z.number().finite().nonnegative().max(Number.MAX_SAFE_INTEGER),
  timeToFirstByteMs:
    z.number().finite().nonnegative().max(300_000).nullable(),
  timeToFirstMeaningfulMs:
    z.number().finite().nonnegative().max(300_000).nullable(),
  durationMs: z.number().finite().nonnegative().max(300_000),
}).strict();

const runtimePersistenceSchema = z.object({
  schemaVersion: z.literal("tasc-runtime-invocation-persistence-v1"),
  status: z.enum(["completed", "incomplete", "failed"]),
  endpointBindingDigest: contractDigestSchema,
  profile: preparedSchema.shape.profile,
  route: preparedSchema.shape.route,
  requestedModel: requestedModelSchema,
  resolvedModel: z.object({
    id: z.string().min(1).max(512),
    revision: z.string().min(1).max(512).nullable(),
    verification: z.literal("provider-reported"),
  }).strict().nullable(),
  requestIdentity: keyedIdentitySchema,
  responseIdentity: keyedIdentitySchema.nullable(),
  eventStreamIdentity: keyedIdentitySchema.nullable(),
  terminalOutputIdentity: keyedIdentitySchema.nullable(),
  finishReason: z.string().min(1).max(128).nullable(),
  providerUsage: providerUsageSchema.nullable(),
  providerTiming: providerTimingSchema,
  finalUsage: z.enum(["present", "missing"]),
  partialOutput: z.boolean(),
  dispatchState: z.enum(["not_sent", "sent_unknown", "completed"]),
  abortLifecycle: z.enum([
    "not-aborted",
    "caller-cancelled-before-dispatch",
    "caller-cancelled-after-dispatch-ambiguous",
    "deadline-exceeded",
  ]),
  wireTiming: wireTimingSchema.nullable(),
  streamTiming: streamTimingSchema.nullable(),
  error: persistedErrorSchema.nullable(),
}).strict();

const ABORT_SIGNAL_GETTER =
  Reflect.getOwnPropertyDescriptor(AbortSignal.prototype, "aborted")?.get;

function deepFreeze<T>(value: T): T {
  if (value === null || typeof value !== "object" || Object.isFrozen(value)) {
    return value;
  }
  for (const descriptor of Object.values(
    Object.getOwnPropertyDescriptors(value),
  )) {
    if (Object.hasOwn(descriptor, "value")) {
      deepFreeze(descriptor.value);
    }
  }
  return Object.freeze(value);
}

function strictRecord(
  input: unknown,
  label: string,
  allowedKeys: ReadonlySet<string>,
): Record<string, unknown> {
  if (
    input === null
    || typeof input !== "object"
    || isProxy(input)
    || (
      Reflect.getPrototypeOf(input) !== Object.prototype
      && Reflect.getPrototypeOf(input) !== null
    )
  ) {
    throw new Error(`${label} must be a plain non-proxy object`);
  }
  const result: Record<string, unknown> = Object.create(null);
  for (const key of Reflect.ownKeys(input)) {
    if (typeof key !== "string" || !allowedKeys.has(key)) {
      throw new Error(`${label} contains an unknown field`);
    }
    const descriptor = Reflect.getOwnPropertyDescriptor(input, key);
    if (
      descriptor === undefined
      || !descriptor.enumerable
      || !Object.hasOwn(descriptor, "value")
    ) {
      throw new Error(`${label} requires enumerable data fields`);
    }
    result[key] = descriptor.value;
  }
  return result;
}

function strictArray(
  input: unknown,
  label: string,
  maximum: number,
): readonly unknown[] {
  if (
    input === null
    || typeof input !== "object"
    || isProxy(input)
    || !Array.isArray(input)
    || Reflect.getPrototypeOf(input) !== Array.prototype
  ) {
    throw new Error(`${label} must be a plain non-proxy array`);
  }
  const length = Reflect.getOwnPropertyDescriptor(input, "length")?.value;
  if (
    typeof length !== "number"
    || !Number.isSafeInteger(length)
    || length < 0
    || length > maximum
  ) {
    throw new Error(`${label} exceeds its item limit`);
  }
  const result: unknown[] = [];
  for (let index = 0; index < length; index += 1) {
    const descriptor = Reflect.getOwnPropertyDescriptor(input, String(index));
    if (
      descriptor === undefined
      || !descriptor.enumerable
      || !Object.hasOwn(descriptor, "value")
    ) {
      throw new Error(`${label} must be dense and contain data elements`);
    }
    result.push(descriptor.value);
  }
  const allowedKeys = new Set(["length"]);
  for (let index = 0; index < length; index += 1) {
    allowedKeys.add(String(index));
  }
  for (const key of Reflect.ownKeys(input)) {
    if (typeof key !== "string" || !allowedKeys.has(key)) {
      throw new Error(`${label} contains an unknown field`);
    }
  }
  return Object.freeze(result);
}

function snapshotJsonData(
  input: unknown,
  label: string,
  state = { nodes: 0 },
  depth = 0,
): unknown {
  if (
    input === null
    || typeof input === "string"
    || typeof input === "boolean"
    || typeof input === "number"
  ) {
    if (typeof input === "number" && !Number.isFinite(input)) {
      throw new Error(`${label} contains a non-finite number`);
    }
    return input;
  }
  if (
    typeof input !== "object"
    || isProxy(input)
    || depth > 24
    || state.nodes >= 16_384
  ) {
    throw new Error(`${label} is not bounded plain data`);
  }
  state.nodes += 1;
  if (Array.isArray(input)) {
    const values = strictArray(input, label, 16_384);
    return Object.freeze(
      values.map((value) =>
        snapshotJsonData(value, label, state, depth + 1)
      ),
    );
  }
  const prototype = Reflect.getPrototypeOf(input);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new Error(`${label} is not plain data`);
  }
  const result: Record<string, unknown> = Object.create(null);
  const keys = Reflect.ownKeys(input);
  if (keys.length > 1_024) {
    throw new Error(`${label} exceeds its field limit`);
  }
  for (const key of keys) {
    if (typeof key !== "string") {
      throw new Error(`${label} contains a symbol field`);
    }
    const descriptor = Reflect.getOwnPropertyDescriptor(input, key);
    if (
      descriptor === undefined
      || !descriptor.enumerable
      || !Object.hasOwn(descriptor, "value")
    ) {
      throw new Error(`${label} contains an accessor or hidden field`);
    }
    result[key] = snapshotJsonData(
      descriptor.value,
      label,
      state,
      depth + 1,
    );
  }
  return Object.freeze(result);
}

function safePositiveInteger(
  value: unknown,
  label: string,
  maximum = Number.MAX_SAFE_INTEGER,
): number {
  if (
    typeof value !== "number"
    || !Number.isSafeInteger(value)
    || value < 1
    || value > maximum
  ) {
    throw new Error(`${label} must be a bounded positive integer`);
  }
  return value;
}

function safeNonNegativeInteger(
  value: unknown,
  label: string,
  maximum = Number.MAX_SAFE_INTEGER,
): number {
  if (
    typeof value !== "number"
    || !Number.isSafeInteger(value)
    || value < 0
    || value > maximum
  ) {
    throw new Error(`${label} must be a bounded non-negative integer`);
  }
  return value;
}

function checkedMultiply(left: number, right: number, label: string): number {
  const product = left * right;
  if (!Number.isSafeInteger(product) || product < 0) {
    throw new Error(`${label} exceeds the safe work range`);
  }
  return product;
}

function checkedAdd(left: number, right: number, label: string): number {
  const sum = left + right;
  if (!Number.isSafeInteger(sum) || sum < 0) {
    throw new Error(`${label} exceeds the safe work range`);
  }
  return sum;
}

function requireSlug(value: unknown, label: string): string {
  if (
    typeof value !== "string"
    || value.length < 1
    || value.length > 128
    || !CONTRACT_SLUG_PATTERN.test(value)
  ) {
    throw new Error(`${label} must be a lowercase contract slug`);
  }
  return value;
}

function requireDigest(value: unknown, label: string): string {
  if (typeof value !== "string" || !DIGEST_PATTERN.test(value)) {
    throw new Error(`${label} must be a canonical sha256 digest`);
  }
  return value;
}

function requireTimestamp(value: unknown, label: string): string {
  const parsed = contractTimestampSchema.safeParse(value);
  if (!parsed.success) throw new Error(`${label} must be an exact UTC timestamp`);
  return parsed.data;
}

function requireFinite(
  value: unknown,
  label: string,
  minimum = Number.NEGATIVE_INFINITY,
  maximum = Number.POSITIVE_INFINITY,
): number {
  if (
    typeof value !== "number"
    || !Number.isFinite(value)
    || value < minimum
    || value > maximum
  ) {
    throw new Error(`${label} must be a bounded finite number`);
  }
  return value;
}

function normalizeRoot(value: unknown): string {
  if (
    typeof value !== "string"
    || value.length < 1
    || value.length > MAX_ROOT_LENGTH
    || value.trim() !== value
    || value.includes("\u0000")
    || !isAbsolute(value)
  ) {
    throw new Error("shadow root must be a bounded absolute path");
  }
  const normalized = resolvePath(value);
  if (normalized === parsePath(normalized).root) {
    throw new Error("shadow root cannot be a filesystem root");
  }
  return normalized;
}

function snapshotGeneration(input: unknown): ShadowGenerationRequest {
  const record = strictRecord(
    input,
    "shadow generation",
    new Set([
      "stream",
      "n",
      "messages",
      "prompt",
      "maxTokens",
      "temperature",
      "topP",
      "seed",
      "stop",
    ]),
  );
  const result: Record<string, unknown> = Object.create(null);
  for (const key of [
    "stream",
    "n",
    "prompt",
    "maxTokens",
    "temperature",
    "topP",
    "seed",
  ]) {
    if (Object.hasOwn(record, key)) result[key] = record[key];
  }
  if (Object.hasOwn(record, "messages")) {
    result.messages = strictArray(record.messages, "shadow messages", 64)
      .map((message, index) => {
        const item = strictRecord(
          message,
          `shadow message ${index}`,
          new Set(["role", "content"]),
        );
        if (!Object.hasOwn(item, "role") || !Object.hasOwn(item, "content")) {
          throw new Error("shadow message is missing a required field");
        }
        return Object.freeze({
          role: item.role,
          content: item.content,
        });
      });
  }
  if (Object.hasOwn(record, "stop")) {
    result.stop = Array.isArray(record.stop)
      ? strictArray(record.stop, "shadow stop", 8).slice()
      : record.stop;
  }
  return deepFreeze(result) as unknown as ShadowGenerationRequest;
}

function normalizeCase(input: unknown, index: number): NormalizedCase {
  const record = strictRecord(
    input,
    `shadow case ${index}`,
    new Set([
      "caseId",
      "groupId",
      "replicates",
      "generation",
      "workload",
      "slices",
      "routeSignal",
    ]),
  );
  for (const required of [
    "caseId",
    "groupId",
    "replicates",
    "generation",
    "workload",
    "slices",
  ]) {
    if (!Object.hasOwn(record, required)) {
      throw new Error(`shadow case ${index} is missing a required field`);
    }
  }
  const workload = strictRecord(
    record.workload,
    `shadow case ${index} workload`,
    new Set(["mode", "declaredTrafficWeight", "inputTokenEstimate"]),
  );
  if (
    !Object.hasOwn(workload, "mode")
    || !Object.hasOwn(workload, "declaredTrafficWeight")
    || !Object.hasOwn(workload, "inputTokenEstimate")
  ) {
    throw new Error("shadow workload is missing a required field");
  }
  const slices = strictArray(record.slices, "shadow slices", 64)
    .map((slice) => requireSlug(slice, "shadow slice"));
  if (new Set(slices).size !== slices.length) {
    throw new Error("shadow slices must be unique");
  }
  let routeSignal: NormalizedCase["routeSignal"] = null;
  if (record.routeSignal !== undefined && record.routeSignal !== null) {
    const signal = strictRecord(
      record.routeSignal,
      `shadow case ${index} route signal`,
      new Set(["value", "sourceId", "observedAt"]),
    );
    if (
      !Object.hasOwn(signal, "value")
      || !Object.hasOwn(signal, "sourceId")
      || !Object.hasOwn(signal, "observedAt")
    ) {
      throw new Error("shadow route signal is missing a required field");
    }
    routeSignal = Object.freeze({
      value: requireFinite(signal.value, "route signal value"),
      sourceId: requireSlug(signal.sourceId, "route signal source id"),
      observedAt: requireTimestamp(
        signal.observedAt,
        "route signal observation",
      ),
    });
  }
  return deepFreeze({
    caseId: requireSlug(record.caseId, "shadow case id"),
    groupId: requireSlug(record.groupId, "shadow group id"),
    replicates: safePositiveInteger(
      record.replicates,
      "shadow replicate count",
      MAX_REPLICATES,
    ),
    generation: snapshotGeneration(record.generation),
    workload: {
      mode: requireSlug(workload.mode, "shadow workload mode"),
      declaredTrafficWeight: requireFinite(
        workload.declaredTrafficWeight,
        "shadow traffic weight",
        Number.MIN_VALUE,
      ),
      inputTokenEstimate: workload.inputTokenEstimate === null
        ? null
        : safeNonNegativeInteger(
          workload.inputTokenEstimate,
          "shadow input token estimate",
        ),
    },
    slices,
    routeSignal,
  });
}

const RUNTIME_TARGET_KEYS = new Set([
  "policy",
  "endpointAlias",
  "endpointDescriptor",
  "instance",
  "capabilityAuthorizations",
  "route",
  "authenticationReference",
  "secretHeaderFactory",
  "httpLimits",
]);

const HTTP_LIMIT_KEYS = new Set(
  Object.keys(DEFAULT_RUNTIME_HTTP_LIMITS),
);

function normalizeHttpLimits(input: unknown): RuntimeHttpLimits {
  const values: Record<string, number> = {
    ...DEFAULT_RUNTIME_HTTP_LIMITS,
  };
  if (input !== undefined) {
    const record = strictRecord(
      input,
      "shadow runtime HTTP limits",
      HTTP_LIMIT_KEYS,
    );
    for (const [key, value] of Object.entries(record)) {
      values[key] = safePositiveInteger(
        value,
        `shadow runtime HTTP limit ${key}`,
      );
    }
  }
  return Object.freeze(values) as unknown as RuntimeHttpLimits;
}

function runtimeRequestPath(
  descriptor: ReturnType<typeof parseEndpointDescriptor> | undefined,
  routePath: string,
): string {
  const basePath = descriptor?.basePath ?? "/";
  if (basePath === "/") return routePath;
  if (routePath === "/") return basePath;
  return `${basePath}${routePath}`;
}

function normalizeTarget(
  input: unknown,
  index: number,
  minimumAuthorityRemainingMs: number,
  planTarget: ShadowRunPlanCollectionTarget,
  protocol: ExperimentProtocol,
): NormalizedProfileTarget {
  const record = strictRecord(
    input,
    `shadow profile target ${index}`,
    new Set(["profileId", "runtime"]),
  );
  if (!Object.hasOwn(record, "profileId") || !Object.hasOwn(record, "runtime")) {
    throw new Error(`shadow profile target ${index} is missing a required field`);
  }
  const runtime = strictRecord(
    record.runtime,
    `shadow profile target ${index} runtime`,
    RUNTIME_TARGET_KEYS,
  );
  for (const required of ["policy", "endpointAlias", "instance", "route"]) {
    if (!Object.hasOwn(runtime, required)) {
      throw new Error("shadow runtime target is missing a required field");
    }
  }
  if (
    runtime.policy === null
    || typeof runtime.policy !== "object"
    || isProxy(runtime.policy)
    || !Object.isFrozen(runtime.policy)
  ) {
    throw new Error(
      "shadow collector policy must be an immutable authentic authority",
    );
  }
  const httpLimits = normalizeHttpLimits(runtime.httpLimits);
  const endpointDescriptor = runtime.endpointDescriptor === undefined
    ? undefined
    : parseEndpointDescriptor(runtime.endpointDescriptor);
  const instance = parseRuntimeInstanceIdentity(runtime.instance);
  const profileId = requireSlug(record.profileId, "shadow profile id");
  let endpointBindingDigest: string;
  try {
    endpointBindingDigest = fingerprintCollectorEndpointBinding(
      runtime.policy as Parameters<
        typeof fingerprintCollectorEndpointBinding
      >[0],
      runtime.endpointAlias as string,
      endpointDescriptor,
    );
  } catch {
    throw new Error(
      "shadow collector policy must be an authentic endpoint authority",
    );
  }
  if (instance.endpointDescriptorDigest !== endpointBindingDigest) {
    throw new Error("shadow runtime instance conflicts with endpoint authority");
  }
  const runtimeProfile = getRuntimeProfile(instance.runtime.profileId);
  const runtimeRoute = runtime.route as RuntimeInvocationInput["route"];
  const routeDefinition = runtimeProfile.endpoints.inference[runtimeRoute];
  const executionProfile = protocol.profiles.find(
    ({ id }) => id === profileId,
  );
  if (
    profileId !== planTarget.profileId
    || runtime.endpointAlias !== planTarget.endpointAlias
    || endpointBindingDigest !== planTarget.endpointBindingDigest
    || runtimeRoute !== planTarget.route
    || (runtime.authenticationReference ?? null)
      !== planTarget.authenticationReference
    || instance.runtime.profileId !== planTarget.runtimeName
    || instance.runtime.build !== runtimeProfile.runtime.build
    || executionProfile === undefined
    || executionProfile.runtime.name !== instance.runtime.profileId
    || executionProfile.runtime.build !== instance.runtime.build
    || executionProfile.backend.name !== instance.backend.name
    || executionProfile.backend.build !== instance.backend.build
    || executionProfile.model.id !== instance.model.id
    || executionProfile.model.revision !== instance.model.revision
    || executionProfile.deploymentConfigurationDigest
      !== instance.configurationDigest
    || routeDefinition === undefined
    || runtimeProfile.capabilities[routeDefinition.capability].state
      !== "supported"
  ) {
    throw new Error("shadow runtime target conflicts with its P0 plan");
  }
  const endpointRequirement = protocol.endpointRequirements.find(
    (requirement) =>
      requirement.runtimeName === executionProfile.runtime.name
      && requirement.endpointAlias === runtime.endpointAlias,
  );
  const policy = runtime.policy as RuntimeInvocationInput["policy"];
  const trustedEndpoint = policy.endpoints.find(
    ({ alias }) => alias === runtime.endpointAlias,
  );
  if (
    endpointRequirement === undefined
    || trustedEndpoint === undefined
    || endpointRequirement.transport !== planTarget.transport
  ) {
    throw new Error("shadow runtime target conflicts with protocol authority");
  }
  const trustedOrigin = new URL(trustedEndpoint.origin);
  const loopbackHttp = trustedOrigin.protocol === "http:"
    && (
      trustedOrigin.hostname === "127.0.0.1"
      || trustedOrigin.hostname === "[::1]"
    );
  if (
    (
      endpointRequirement.transport === "https"
      && trustedOrigin.protocol !== "https:"
    )
    || (
      endpointRequirement.transport === "loopback-http"
      && !loopbackHttp
    )
  ) {
    throw new Error("shadow runtime target transport conflicts with protocol");
  }
  try {
    authorizeCollectorRequest(policy, {
      endpointAlias: runtime.endpointAlias,
      runtime: instance.runtime,
      method: routeDefinition.method,
      path: runtimeRequestPath(endpointDescriptor, routeDefinition.path),
      ...(runtime.authenticationReference === undefined
        ? {}
        : {
          authenticationReference: runtime.authenticationReference,
        }),
    });
  } catch {
    throw new Error("shadow runtime target conflicts with collector authority");
  }
  const normalizedRuntime: Record<string, unknown> = {
    policy: runtime.policy,
    endpointAlias: runtime.endpointAlias,
    instance,
    route: runtime.route,
    httpLimits,
  };
  if (endpointDescriptor !== undefined) {
    normalizedRuntime.endpointDescriptor = endpointDescriptor;
  }
  if (runtime.capabilityAuthorizations !== undefined) {
    const authorizations = strictArray(
      runtime.capabilityAuthorizations,
      "runtime capability authorizations",
      16,
    );
    const route = runtimeProfile.endpoints.inference[runtimeRoute];
    if (route === undefined) {
      throw new Error("shadow runtime route is not declared by its profile");
    }
    for (const authorization of authorizations) {
      if (
        authorization === null
        || typeof authorization !== "object"
        || isProxy(authorization)
        || !Object.isFrozen(authorization)
        || !verifyRuntimeCapabilityAuthorization(
          authorization as Parameters<
            typeof verifyRuntimeCapabilityAuthorization
          >[0],
          {
            instance,
            capability: route.capability,
            route: runtime.route as RuntimeInvocationInput["route"],
            minimumRemainingMs: minimumAuthorityRemainingMs,
          },
        )
      ) {
        throw new Error(
          "runtime capability authorization must be an immutable authority",
        );
      }
    }
    normalizedRuntime.capabilityAuthorizations =
      Object.freeze([...authorizations]);
  }
  if (runtime.authenticationReference !== undefined) {
    normalizedRuntime.authenticationReference =
      runtime.authenticationReference;
  }
  if (runtime.secretHeaderFactory !== undefined) {
    if (
      typeof runtime.secretHeaderFactory !== "function"
      || isProxy(runtime.secretHeaderFactory)
    ) {
      throw new Error("runtime secret header factory must be a function");
    }
    normalizedRuntime.secretHeaderFactory = runtime.secretHeaderFactory;
  }
  const httpLimitsDigest = domainSeparatedDigest(
    "tasc/shadow-http-limits/v1",
    httpLimits,
  );
  return Object.freeze({
    profileId,
    runtime: Object.freeze(normalizedRuntime) as unknown as ShadowRuntimeTarget,
    httpLimits,
    httpLimitsDigest,
    responseByteLimit: httpLimits.maxResponseBytes,
    planTarget,
  });
}

function normalizeBudget(input: unknown): ShadowWorkBudget {
  const record = strictRecord(
    input,
    "shadow work budget",
    new Set([
      "maxCases",
      "maxProfiles",
      "maxReplicates",
      "maxLogicalExecutions",
      "maxAttempts",
      "maxNetworkCalls",
      "maxDurableRecords",
      "maxRequestBytes",
      "maxResponseBytes",
      "maxWallClockMs",
      "maxConcurrency",
    ]),
  );
  const result: Record<string, number> = Object.create(null);
  for (const field of [
    "maxCases",
    "maxProfiles",
    "maxReplicates",
    "maxLogicalExecutions",
    "maxAttempts",
    "maxNetworkCalls",
    "maxDurableRecords",
    "maxRequestBytes",
    "maxResponseBytes",
    "maxWallClockMs",
    "maxConcurrency",
  ]) {
    if (!Object.hasOwn(record, field)) {
      throw new Error(`shadow work budget is missing ${field}`);
    }
    result[field] = safePositiveInteger(
      record[field],
      `shadow work budget ${field}`,
    );
  }
  return Object.freeze(result) as unknown as ShadowWorkBudget;
}

function normalizeIdentity(
  input: unknown,
  studyId: string,
): RuntimeInvocationInput["identity"] {
  const record = strictRecord(
    input,
    "shadow payload identity authority",
    new Set(["studyId", "keyId", "key"]),
  );
  if (
    record.studyId !== studyId
    || !Object.hasOwn(record, "key")
  ) {
    throw new Error("shadow payload identity authority conflicts with study");
  }
  return Object.freeze({
    studyId,
    keyId: requireSlug(record.keyId, "shadow payload key id"),
    key: record.key as KeyObject,
  });
}

function normalizeSigner(
  input: unknown,
  protocol: ExperimentProtocol,
): DispatchIntentSigner {
  const record = strictRecord(
    input,
    "dispatch intent signer",
    new Set(["keyId", "algorithm", "sign"]),
  );
  if (
    record.keyId !== protocol.dispatchAuthority.keyId
    || record.algorithm !== "ed25519"
    || typeof record.sign !== "function"
    || isProxy(record.sign)
  ) {
    throw new Error("dispatch intent signer conflicts with protocol authority");
  }
  return Object.freeze({
    keyId: record.keyId,
    algorithm: "ed25519",
    sign: record.sign as DispatchIntentSigner["sign"],
  });
}

function normalizeCollectorSigner(
  input: unknown,
  protocol: ExperimentProtocol,
): CollectorAttestationSigner {
  const record = strictRecord(
    input,
    "collector attestation signer",
    new Set(["keyId", "algorithm", "sign"]),
  );
  if (
    record.keyId !== protocol.collectorAuthority.keyId
    || record.algorithm !== "ed25519"
    || typeof record.sign !== "function"
    || isProxy(record.sign)
  ) {
    throw new Error(
      "collector attestation signer conflicts with protocol authority",
    );
  }
  return Object.freeze({
    keyId: record.keyId,
    algorithm: "ed25519",
    sign: record.sign as CollectorAttestationSigner["sign"],
  });
}

function normalizeHooks(input: unknown): {
  readonly hooks: NormalizedRun["hooks"];
  readonly now?: () => Date;
} {
  if (input === undefined) {
    return {
      hooks: Object.freeze({
        prepareInvocation: prepareRuntimeInvocation,
        dispatchInvocation: dispatchPreparedRuntimeInvocation,
        readPacket: readArtifactPacketIfPresent,
        writePacket: writeArtifactPacketOrVerifyIdentical,
      }),
    };
  }
  const record = strictRecord(
    input,
    "shadow runner hooks",
    new Set([
      "now",
      "prepareInvocation",
      "dispatchInvocation",
      "readPacket",
      "writePacket",
      "checkpoint",
    ]),
  );
  for (const [name, value] of Object.entries(record)) {
    if (typeof value !== "function" || isProxy(value)) {
      throw new Error(`shadow hook ${name} must be a non-proxy function`);
    }
  }
  return {
    hooks: Object.freeze({
      prepareInvocation:
        (record.prepareInvocation as ShadowRunnerHooks["prepareInvocation"])
        ?? prepareRuntimeInvocation,
      dispatchInvocation:
        (record.dispatchInvocation as ShadowRunnerHooks["dispatchInvocation"])
        ?? dispatchPreparedRuntimeInvocation,
      readPacket:
        (record.readPacket as ShadowRunnerHooks["readPacket"])
        ?? readArtifactPacketIfPresent,
      writePacket:
        (record.writePacket as ShadowRunnerHooks["writePacket"])
        ?? writeArtifactPacketOrVerifyIdentical,
      ...(record.checkpoint === undefined
        ? {}
        : {
          checkpoint: record.checkpoint as NonNullable<
            ShadowRunnerHooks["checkpoint"]
          >,
        }),
    }),
    ...(record.now === undefined
      ? {}
      : { now: record.now as NonNullable<ShadowRunnerHooks["now"]> }),
  };
}

class MonotonicWallClock {
  readonly #now: () => Date;
  #last = Number.NEGATIVE_INFINITY;

  constructor(now: (() => Date) | undefined) {
    this.#now = now ?? (() => new Date());
  }

  milliseconds(): number {
    let value: Date;
    try {
      value = this.#now();
    } catch {
      throw new Error("shadow clock failed");
    }
    let milliseconds: number;
    try {
      milliseconds = Date.prototype.getTime.call(value);
    } catch {
      throw new Error("shadow clock must return a Date");
    }
    if (
      !Number.isFinite(milliseconds)
      || milliseconds < -MAX_CLOCK_MS
      || milliseconds > MAX_CLOCK_MS
      || milliseconds < this.#last
    ) {
      throw new Error("shadow clock must be finite and monotonic");
    }
    this.#last = milliseconds;
    return milliseconds;
  }

}

type RunCancellationKind = "caller" | "deadline" | "fatal";

class RunCancellation {
  readonly #controller = new AbortController();
  readonly #callerSignal: AbortSignal | undefined;
  readonly #callerAbort: (() => void) | undefined;
  #remainingMs: number;
  #lastTimerStartNs = process.hrtime.bigint();
  #timer: ReturnType<typeof setTimeout> | undefined;
  #kind: RunCancellationKind | null = null;

  constructor(
    callerSignal: AbortSignal | undefined,
    durationMs: number,
  ) {
    this.#callerSignal = callerSignal;
    this.#remainingMs = durationMs;
    this.#callerAbort = callerSignal === undefined
      ? undefined
      : () => this.abort("caller");
    if (callerSignal !== undefined) {
      if (signalAborted(callerSignal)) {
        this.abort("caller");
      } else {
        callerSignal.addEventListener("abort", this.#callerAbort!, {
          once: true,
        });
      }
    }
    if (!this.#controller.signal.aborted) this.#armDeadline();
  }

  get signal(): AbortSignal {
    return this.#controller.signal;
  }

  get kind(): RunCancellationKind | null {
    return this.#kind;
  }

  abort(kind: RunCancellationKind): void {
    if (this.#controller.signal.aborted) return;
    this.#kind = kind;
    this.#controller.abort(kind);
    if (this.#timer !== undefined) clearTimeout(this.#timer);
    this.#timer = undefined;
  }

  dispose(): void {
    if (this.#timer !== undefined) clearTimeout(this.#timer);
    this.#timer = undefined;
    if (
      this.#callerSignal !== undefined
      && this.#callerAbort !== undefined
    ) {
      this.#callerSignal.removeEventListener("abort", this.#callerAbort);
    }
  }

  #armDeadline(): void {
    if (this.#remainingMs <= 0) {
      this.abort("deadline");
      return;
    }
    const delay = Math.min(this.#remainingMs, 2_147_483_647);
    this.#lastTimerStartNs = process.hrtime.bigint();
    this.#timer = setTimeout(() => {
      const elapsedNs = process.hrtime.bigint() - this.#lastTimerStartNs;
      this.#remainingMs -= Number(elapsedNs / 1_000_000n);
      if (this.#remainingMs <= 0) {
        this.abort("deadline");
      } else {
        this.#armDeadline();
      }
    }, delay);
  }
}

function signalAborted(signal: AbortSignal | undefined): boolean {
  if (signal === undefined) return false;
  try {
    return ABORT_SIGNAL_GETTER?.call(signal) === true;
  } catch {
    throw new Error("shadow abort signal is invalid");
  }
}

function derivedHex(
  identity: RuntimeInvocationInput["identity"],
  domain: string,
  value: unknown,
): string {
  return createStudyPayloadIdentity(
    identity.studyId,
    identity.keyId,
    identity.key,
    canonicalJsonBytes({ domain, value }),
  ).value;
}

function derivedId(
  prefix: string,
  identity: RuntimeInvocationInput["identity"],
  domain: string,
  value: unknown,
): string {
  return `${prefix}-${derivedHex(identity, domain, value)}`;
}

function profileOrder(
  protocol: ExperimentProtocol,
  planDigest: string,
  caseInput: NormalizedCase,
  replicateIndex: number,
): readonly string[] {
  const base = [
    protocol.championProfileId,
    ...protocol.candidateProfileIds,
  ];
  const blockStart =
    replicateIndex - (replicateIndex % base.length);
  const rankedReplicates = base.map((_profileId, offset) => {
    const index = blockStart + offset;
    return {
      index,
      digest: domainSeparatedDigest(
        "tasc/shadow-counterbalance/v2",
        {
          planDigest,
          caseId: caseInput.caseId,
          groupId: caseInput.groupId,
          replicateIndex: index,
        },
      ),
    };
  }).sort(
    (left, right) =>
      compareCodeUnits(left.digest, right.digest)
      || left.index - right.index,
  );
  const offset = rankedReplicates.findIndex(
    ({ index }) => index === replicateIndex,
  );
  if (offset < 0) {
    throw new Error("shadow counterbalance assignment failed");
  }
  return Object.freeze([
    ...base.slice(offset),
    ...base.slice(0, offset),
  ]);
}

function invocationForJob(
  job: JobSeed | PreparedJob,
  identity: RuntimeInvocationInput["identity"],
  timeoutMs: number,
  signal: AbortSignal | undefined,
): RuntimeInvocationInput {
  const admitted = job.profileTarget.httpLimits;
  const httpLimits: RuntimeHttpLimits = Object.freeze({
    ...admitted,
    connectTimeoutMs: Math.min(admitted.connectTimeoutMs, timeoutMs),
    headersTimeoutMs: Math.min(admitted.headersTimeoutMs, timeoutMs),
    bodyTimeoutMs: Math.min(admitted.bodyTimeoutMs, timeoutMs),
    deadlineMs: Math.min(admitted.deadlineMs, timeoutMs),
  });
  return {
    ...job.profileTarget.runtime,
    generation: {
      ...job.caseInput.generation,
      model: job.profile.model,
    },
    identity,
    totalDeadlineMs: timeoutMs,
    httpLimits,
    ...(signal === undefined ? {} : { signal }),
  };
}

function invocationMetadataForJob(
  invocationInput: PreparedRuntimeInvocation | RuntimeInvocationDescription,
  job: JobSeed | PreparedJob,
): PreflightInvocationMetadata {
  const invocation = z.union([
    preparedSchema,
    invocationDescriptionSchema,
  ]).parse(
    snapshotJsonData(invocationInput, "runtime invocation metadata"),
  );
  if (
    invocation.profile.id !== job.profile.runtime.name
    || invocation.profile.build !== job.profile.runtime.build
    || invocation.requestedModel.id !== job.profile.model.id
    || invocation.requestedModel.revision !== job.profile.model.revision
  ) {
    throw new Error("runtime invocation conflicts with execution profile");
  }
  return deepFreeze({
    schemaVersion: "tasc-shadow-invocation-description-v1",
    endpointBindingDigest: invocation.endpointBindingDigest,
    profile: invocation.profile,
    route: invocation.route,
    requestedModel: invocation.requestedModel,
    requestIdentity: invocation.requestIdentity,
    requestByteCount: invocation.requestByteCount,
    httpLimitsDigest: job.profileTarget.httpLimitsDigest,
    responseByteLimit: job.profileTarget.responseByteLimit,
  });
}

function assertLivePreparedMatches(
  prepared: PreparedRuntimeInvocation,
  job: PreparedJob,
): PreparedRuntimeInvocation {
  const metadata = invocationMetadataForJob(prepared, job);
  if (!sameCanonical(metadata, job.preflight)) {
    throw new Error("prepared invocation changed after shadow preflight");
  }
  return prepared;
}

function traceBaseFor(
  run: Pick<
    NormalizedRun,
    "plan" | "protocol" | "protocolDigest" | "collectionWindowId"
    | "collectionWindowMembershipDigest" | "policyDigest"
  >,
  job: PreparedJob,
  issuedAt: string,
  signature: string,
): TraceBase {
  const routeSignal = job.caseInput.routeSignal === null
    ? null
    : {
      definitionId: run.protocol.routeSignal.definitionId,
      version: run.protocol.routeSignal.version,
      calibrationDigest: run.protocol.routeSignal.calibrationDigest,
      value: job.caseInput.routeSignal.value,
      provenance: {
        kind: "route-signal-observation" as const,
        sourceId: job.caseInput.routeSignal.sourceId,
        observedAt: job.caseInput.routeSignal.observedAt,
      },
    };
  return deepFreeze({
    version: "tasc-trace-envelope-v2" as const,
    studyId: run.protocol.studyId,
    protocolDigest: run.protocolDigest,
    traceId: job.traceId,
    caseId: job.caseInput.caseId,
    groupId: job.caseInput.groupId,
    replicateId: job.replicateId,
    split: "online" as const,
    collectionWindowId: run.collectionWindowId,
    collectionWindowMembershipDigest:
      run.collectionWindowMembershipDigest,
    sourceMode: "shadow" as const,
    collectionBinding: {
      shadowPlanDigest: run.plan.planDigest,
      endpointAlias: job.profileTarget.planTarget.endpointAlias,
      endpointBindingDigest:
        job.profileTarget.planTarget.endpointBindingDigest,
      route: job.profileTarget.planTarget.route,
      authenticationReference:
        job.profileTarget.planTarget.authenticationReference,
      capabilityReceiptDigests:
        job.profileTarget.planTarget.capabilityReceiptDigests,
    },
    profileId: job.profile.id,
    executionProfileDigest: fingerprintExecutionProfile(job.profile),
    policyDigest: run.policyDigest,
    observedRoute: {
      selectedProfileId: job.profile.id,
      decisionId: job.decisionId,
    },
    workload: job.caseInput.workload,
    slices: job.caseInput.slices,
    routeSignal,
    dispatchIntent: {
      version: "tasc-dispatch-intent-v1" as const,
      issuedAt,
      authorityKeyId: run.protocol.dispatchAuthority.keyId,
      signatureAlgorithm: "ed25519" as const,
      signature,
    },
  });
}

function provisionalAttempt(
  job: PreparedJob,
  timestamp: string,
): TraceAttempt {
  return deepFreeze({
    attemptId: `attempt-${job.traceId.slice("trace-".length)}`,
    attemptNumber: 1,
    dispatchState: "not_sent" as const,
    observerTimings: {
      startedAt: timestamp,
      headersAt: null,
      firstByteAt: null,
      firstMeaningfulTokenAt: null,
      completedAt: timestamp,
    },
    status: "failure" as const,
    finishReason: null,
    partialOutput: false,
    abortLifecycle: "not-aborted" as const,
    failureCategory: "internal",
    requestedModel: job.preflight.requestedModel,
    resolvedModel: null,
    tokenUsage: {
      input: null,
      output: null,
      total: null,
    },
    providerReported: {
      timings: [],
      metrics: [],
    },
    cost: { kind: "unavailable" as const },
    payloads: {
      request: job.preflight.requestIdentity,
      response: null,
      eventStream: null,
    },
  }) as TraceAttempt;
}

function assertWithin(value: number, ceiling: number, label: string): void {
  if (value > ceiling) {
    throw new Error(`${label} exceeds the caller work budget`);
  }
}

function buildJobSeeds(input: {
  readonly plan: ShadowRunPlan;
  readonly protocol: ExperimentProtocol;
  readonly protocolDigest: string;
  readonly collectionWindowId: string;
  readonly collectionWindowMembershipDigest: string;
  readonly policyDigest: string;
  readonly cases: readonly NormalizedCase[];
  readonly targets: readonly NormalizedProfileTarget[];
}): {
  readonly jobs: readonly JobSeed[];
  readonly membershipExcludedReplicates: number;
} {
  const profiles = new Map(
    input.protocol.profiles.map((profile) => [profile.id, profile]),
  );
  const targets = new Map(
    input.targets.map((target) => [target.profileId, target]),
  );
  const jobs: JobSeed[] = [];
  let membershipExcludedReplicates = 0;
  for (const caseInput of input.cases) {
    for (
      let replicateIndex = 0;
      replicateIndex < caseInput.replicates;
      replicateIndex += 1
    ) {
      const replicateId = `replicate-${
        domainSeparatedDigest(
          "tasc/shadow-replicate-id/v2",
          {
            planDigest: input.plan.planDigest,
            caseId: caseInput.caseId,
            groupId: caseInput.groupId,
            replicateIndex,
          },
        ).slice("sha256:".length)
      }`;
      if (
        !isShadowRunPlanMember(
          input.plan,
          caseInput.caseId,
          replicateId,
        )
      ) {
        membershipExcludedReplicates += 1;
        continue;
      }
      for (
        const profileId of profileOrder(
          input.protocol,
          input.plan.planDigest,
          caseInput,
          replicateIndex,
        )
      ) {
        const profile = profiles.get(profileId);
        const profileTarget = targets.get(profileId);
        if (profile === undefined || profileTarget === undefined) {
          throw new Error("shadow profile target set is incomplete");
        }
        jobs.push(Object.freeze({
          index: jobs.length,
          caseInput,
          profileTarget,
          profile,
          replicateIndex,
          replicateId,
        }));
      }
    }
  }
  return Object.freeze({
    jobs: Object.freeze(jobs),
    membershipExcludedReplicates,
  });
}

function normalizeSignal(input: unknown): AbortSignal | undefined {
  if (input === undefined) return undefined;
  try {
    ABORT_SIGNAL_GETTER?.call(input);
  } catch {
    throw new Error("shadow abort signal is invalid");
  }
  if (ABORT_SIGNAL_GETTER === undefined) {
    throw new Error("shadow abort signal support is unavailable");
  }
  return input as AbortSignal;
}

function assertRequiredCapabilitiesAreAdmitted(
  protocol: ExperimentProtocol,
  cases: readonly NormalizedCase[],
  planTargets: readonly ShadowRunPlanCollectionTarget[],
): void {
  for (const capability of protocol.requiredCapabilities) {
    if (capability === "chat-completions") {
      if (
        planTargets.some((target) => target.route !== "chatCompletions")
        || cases.some((caseInput) =>
          caseInput.workload.mode !== "chat"
          || !Object.hasOwn(caseInput.generation, "messages")
          || !Array.isArray(caseInput.generation.messages)
          || caseInput.generation.messages.length === 0
          || Object.hasOwn(caseInput.generation, "prompt")
        )
      ) {
        throw new Error(
          "P0 plan does not admit the required chat-completions capability",
        );
      }
      continue;
    }

    if (capability === "streaming") {
      if (
        planTargets.some(
          (target) =>
            getRuntimeProfile(target.runtimeName).capabilities.streaming.state
              !== "supported",
        )
        || cases.some((caseInput) => caseInput.generation.stream !== true)
      ) {
        throw new Error(
          "P0 plan does not admit the required streaming capability",
        );
      }
      continue;
    }

    if (
      planTargets.some(
        (target) =>
          getRuntimeProfile(target.runtimeName).capabilities.finalUsage.state
            !== "supported",
      )
    ) {
      throw new Error(
        "P0 plan does not admit the required final-usage capability",
      );
    }
  }
}

function normalizeRunInput(
  input: ShadowRunInput & { readonly hooks?: ShadowRunnerHooks },
  allowTestingHooks: boolean,
): NormalizedRun {
  const allowedKeys = new Set([
    "plan",
    "expectedPlanDigest",
    "rootDirectory",
    "cases",
    "profiles",
    "identity",
    "dispatchIntentSigner",
    "collectorAttestationSigner",
    "signal",
  ]);
  if (allowTestingHooks) allowedKeys.add("hooks");
  const top = strictRecord(
    input,
    "shadow run input",
    allowedKeys,
  );
  for (const required of [
    "plan",
    "expectedPlanDigest",
    "rootDirectory",
    "cases",
    "profiles",
    "identity",
    "dispatchIntentSigner",
    "collectorAttestationSigner",
  ]) {
    if (!Object.hasOwn(top, required)) {
      throw new Error(`shadow run input is missing ${required}`);
    }
  }

  if (
    typeof top.expectedPlanDigest !== "string"
    || !/^sha256:[0-9a-f]{64}$/u.test(top.expectedPlanDigest)
  ) {
    throw new Error("shadow run expected plan digest is invalid");
  }
  const plan = parseShadowRunPlan(top.plan);
  if (plan.planDigest !== top.expectedPlanDigest) {
    throw new Error("shadow run does not match the expected plan digest");
  }
  const protocol = plan.protocol;
  const protocolDigest = plan.protocolDigest;
  const rootDirectory = normalizeRoot(top.rootDirectory);
  const collectionWindowId = plan.window.windowId;
  const collectionWindowMembershipDigest = plan.window.membershipDigest;
  const policyDigest = plan.frozenPolicyDigest;
  const workBudget = normalizeBudget(plan.workBudget);
  const identity = normalizeIdentity(top.identity, protocol.studyId);
  const signer = normalizeSigner(top.dispatchIntentSigner, protocol);
  const collectorSigner = normalizeCollectorSigner(
    top.collectorAttestationSigner,
    protocol,
  );
  const signal = normalizeSignal(top.signal);
  const hookInput = normalizeHooks(
    allowTestingHooks ? top.hooks : undefined,
  );
  const clock = new MonotonicWallClock(hookInput.now);

  const caseValues = strictArray(top.cases, "shadow cases", MAX_CASES);
  const profileValues = strictArray(
    top.profiles,
    "shadow profile targets",
    MAX_PROFILES,
  );
  if (caseValues.length < 1 || profileValues.length < 2) {
    throw new Error("shadow collection requires cases and at least two profiles");
  }
  const cases = caseValues.map(normalizeCase);
  assertRequiredCapabilitiesAreAdmitted(
    protocol,
    cases,
    plan.collectionTargets,
  );
  const planTargets = new Map(
    plan.collectionTargets.map((target) => [target.profileId, target]),
  );
  const targets = profileValues.map((target, index) =>
    {
      const targetRecord = strictRecord(
        target,
        `shadow profile target ${index}`,
        new Set(["profileId", "runtime"]),
      );
      const profileId = requireSlug(
        targetRecord.profileId,
        "shadow profile id",
      );
      const planTarget = planTargets.get(profileId);
      if (planTarget === undefined) {
        throw new Error("shadow profile target is absent from its P0 plan");
      }
      return normalizeTarget(
        target,
        index,
        protocol.shadowCollection.attemptTimeoutMs,
        planTarget,
        protocol,
      );
    }
  );
  const caseIds = new Set(cases.map(({ caseId }) => caseId));
  if (caseIds.size !== cases.length) {
    throw new Error("shadow case ids must be unique");
  }
  const targetIds = new Set(targets.map(({ profileId }) => profileId));
  if (targetIds.size !== targets.length) {
    throw new Error("shadow profile target ids must be unique");
  }
  const protocolProfileIds = new Set(
    protocol.profiles.map(({ id }) => id),
  );
  if (
    targetIds.size !== protocolProfileIds.size
    || [...targetIds].some((id) => !protocolProfileIds.has(id))
  ) {
    throw new Error("shadow profile targets must exactly cover the protocol");
  }
  for (const caseInput of cases) {
    if (
      caseInput.routeSignal !== null
      && (
        caseInput.routeSignal.value < protocol.routeSignal.minimum
        || caseInput.routeSignal.value > protocol.routeSignal.maximum
      )
    ) {
      throw new Error("shadow route signal is outside the protocol range");
    }
  }

  let totalReplicates = 0;
  for (const caseInput of cases) {
    totalReplicates = checkedAdd(
      totalReplicates,
      caseInput.replicates,
      "shadow replicate work",
    );
  }
  // Reject the declared upper bound before membership expansion. Membership
  // can reduce the exact job set, but must never be usable to make an
  // otherwise unbounded case × replicate × profile input cheap only after
  // allocating and hashing every candidate job.
  assertWithin(cases.length, workBudget.maxCases, "shadow case count");
  assertWithin(targets.length, workBudget.maxProfiles, "shadow profile count");
  assertWithin(
    totalReplicates,
    workBudget.maxReplicates,
    "shadow replicate count",
  );
  const declaredLogicalExecutions = checkedMultiply(
    totalReplicates,
    targets.length,
    "shadow declared logical execution work",
  );
  assertWithin(
    declaredLogicalExecutions,
    protocol.shadowCollection.maximumLogicalExecutions,
    "shadow logical execution count",
  );
  assertWithin(
    declaredLogicalExecutions,
    workBudget.maxLogicalExecutions,
    "shadow logical execution count",
  );
  if (declaredLogicalExecutions > MAX_TOTAL_LOGICAL_EXECUTIONS) {
    throw new Error("shadow logical execution count exceeds the hard limit");
  }
  const seedResult = buildJobSeeds({
    plan,
    protocol,
    protocolDigest,
    collectionWindowId,
    collectionWindowMembershipDigest,
    policyDigest,
    cases,
    targets,
  });
  const logicalExecutions = seedResult.jobs.length;
  const admittedReplicates = targets.length === 0
    ? 0
    : logicalExecutions / targets.length;
  const maximumAttempts = checkedMultiply(
    logicalExecutions,
    protocol.shadowCollection.maximumAttempts,
    "shadow attempt work",
  );
  const maximumDurableRecords = checkedAdd(
    1,
    checkedAdd(
      checkedMultiply(
        logicalExecutions,
        3,
        "shadow fixed durable record work",
      ),
      checkedMultiply(
        maximumAttempts,
        2,
        "shadow attempt durable record work",
      ),
      "shadow durable record work",
    ),
    "shadow durable record work",
  );
  const maximumAttemptWorkMs = checkedMultiply(
    maximumAttempts,
    protocol.shadowCollection.attemptTimeoutMs,
    "shadow elapsed attempt work",
  );
  let maximumResponseBytes = 0;
  for (const target of targets) {
    maximumResponseBytes = checkedAdd(
      maximumResponseBytes,
      checkedMultiply(
        checkedMultiply(
          admittedReplicates,
          protocol.shadowCollection.maximumAttempts,
          "shadow response work",
        ),
        target.responseByteLimit,
        "shadow response byte work",
      ),
      "shadow response byte work",
    );
  }
  assertWithin(cases.length, workBudget.maxCases, "shadow case count");
  assertWithin(targets.length, workBudget.maxProfiles, "shadow profile count");
  assertWithin(
    totalReplicates,
    workBudget.maxReplicates,
    "shadow replicate count",
  );
  assertWithin(
    logicalExecutions,
    protocol.shadowCollection.maximumLogicalExecutions,
    "shadow logical execution count",
  );
  assertWithin(
    logicalExecutions,
    workBudget.maxLogicalExecutions,
    "shadow logical execution count",
  );
  assertWithin(maximumAttempts, workBudget.maxAttempts, "shadow attempt count");
  assertWithin(
    maximumAttempts,
    workBudget.maxNetworkCalls,
    "shadow network call count",
  );
  assertWithin(
    maximumDurableRecords,
    workBudget.maxDurableRecords,
    "shadow durable record count",
  );
  assertWithin(
    maximumResponseBytes,
    workBudget.maxResponseBytes,
    "shadow response bytes",
  );
  assertWithin(
    maximumAttemptWorkMs,
    workBudget.maxWallClockMs,
    "shadow elapsed attempt work",
  );
  if (logicalExecutions > MAX_TOTAL_LOGICAL_EXECUTIONS) {
    throw new Error("shadow logical execution count exceeds the hard limit");
  }

  const startedAtMs = clock.milliseconds();
  const protocolExpiresAtMs = Date.parse(protocol.expiresAt);
  const planExpiresAtMs = Date.parse(plan.expiresAt);
  const windowStartsAtMs = Date.parse(
    plan.window.eventTimeStartInclusive,
  );
  const windowEndsAtMs = Date.parse(plan.window.eventTimeEndExclusive);
  const authorityEndsAtMs = Math.min(
    protocolExpiresAtMs,
    planExpiresAtMs,
    windowEndsAtMs,
  );
  const runDeadlineAtMs = Math.min(
    authorityEndsAtMs,
    startedAtMs + workBudget.maxWallClockMs,
  );
  if (
    startedAtMs < Date.parse(protocol.createdAt)
    || startedAtMs < Date.parse(plan.issuedAt)
    || startedAtMs < windowStartsAtMs
    || startedAtMs >= authorityEndsAtMs
  ) {
    throw new Error("shadow collection is outside P0 plan validity");
  }
  assertWithin(
    workBudget.maxWallClockMs,
    authorityEndsAtMs - startedAtMs,
    "shadow admitted wall-clock",
  );
  for (const caseInput of cases) {
    if (
      caseInput.routeSignal !== null
      && Date.parse(caseInput.routeSignal.observedAt) > startedAtMs
    ) {
      throw new Error("shadow route signal cannot be observed in the future");
    }
  }

  const jobInputs = seedResult.jobs;
  const jobs: PreparedJob[] = [];
  let aggregateRequestBytes = 0;
  for (const jobInput of jobInputs) {
    const preflight = invocationMetadataForJob(
      describeRuntimeInvocation(
        invocationForJob(
          jobInput,
          identity,
          protocol.shadowCollection.attemptTimeoutMs,
          signal,
        ),
      ),
      jobInput,
    );
    aggregateRequestBytes = checkedAdd(
      aggregateRequestBytes,
      checkedMultiply(
        preflight.requestByteCount,
        protocol.shadowCollection.maximumAttempts,
        "shadow request byte work",
      ),
      "shadow request byte work",
    );
    const traceBinding = {
      studyId: protocol.studyId,
      protocolDigest,
      collectionWindowId,
      collectionWindowMembershipDigest,
      policyDigest,
      caseId: jobInput.caseInput.caseId,
      groupId: jobInput.caseInput.groupId,
      replicateId: jobInput.replicateId,
      profileId: jobInput.profile.id,
      requestIdentity: preflight.requestIdentity,
      endpointBindingDigest: preflight.endpointBindingDigest,
      authenticationReference:
        jobInput.profileTarget.planTarget.authenticationReference,
    };
    const job: PreparedJob = Object.freeze({
      ...jobInput,
      laneKey:
        `${jobInput.profile.id}\u0000${preflight.endpointBindingDigest}`,
      traceId: derivedId(
        "trace",
        identity,
        "tasc/shadow-trace-id/v2",
        traceBinding,
      ),
      decisionId: derivedId(
        "route",
        identity,
        "tasc/shadow-route-decision-id/v2",
        traceBinding,
      ),
      preflight,
    });
    const issuedAt = new Date(startedAtMs).toISOString();
    dispatchIntentSigningBytes(
      traceBaseFor({
        plan,
        protocol,
        protocolDigest,
        collectionWindowId,
        collectionWindowMembershipDigest,
        policyDigest,
      }, job, issuedAt, "AA"),
    );
    jobs.push(job);
  }
  assertWithin(
    aggregateRequestBytes,
    workBudget.maxRequestBytes,
    "shadow request bytes",
  );

  const runBinding = {
    planDigest: plan.planDigest,
    protocolDigest,
    collectionWindowId,
    collectionWindowMembershipDigest,
    policyDigest,
    workBudget,
    jobs: jobs.map((job) => ({
      traceId: job.traceId,
      laneKey: job.laneKey,
      requestIdentity: job.preflight.requestIdentity,
      endpointBindingDigest: job.preflight.endpointBindingDigest,
      authenticationReference:
        job.profileTarget.planTarget.authenticationReference,
      requestByteCount: job.preflight.requestByteCount,
      responseByteLimit: job.preflight.responseByteLimit,
      httpLimitsDigest: job.preflight.httpLimitsDigest,
    })),
  };
  const runId = derivedId(
    "run",
    identity,
    "tasc/shadow-run-id/v1",
    runBinding,
  );

  const cancellation = new RunCancellation(
    signal,
    Math.max(0, runDeadlineAtMs - clock.milliseconds()),
  );
  return Object.freeze({
    plan,
    protocol,
    protocolDigest,
    rootDirectory,
    collectionWindowId,
    collectionWindowMembershipDigest,
    policyDigest,
    identity,
    signer,
    collectorSigner,
    workBudget,
    jobs: Object.freeze(jobs),
    runId,
    runStartedAtMs: startedAtMs,
    runDeadlineAtMs,
    maximumAttemptWorkMs,
    maximumResponseBytes,
    membershipExcludedReplicates:
      seedResult.membershipExcludedReplicates,
    signal: cancellation.signal,
    cancellation,
    hooks: hookInput.hooks,
    clock,
  });
}

type ShadowRecordKind =
  | "admission"
  | "intent"
  | "lease"
  | "outcome"
  | "accepted"
  | "complete";

interface ReadRecord {
  readonly packet: ArtifactReadResult;
  readonly value: unknown;
}

interface PersistedRecord {
  readonly packet: ArtifactReadResult | ArtifactWriteOrVerifyResult;
  readonly value: unknown;
  readonly disposition: "written" | "existing";
}

function targetFor(
  job: PreparedJob,
  kind: Exclude<ShadowRecordKind, "admission">,
  attemptNumber?: number,
): string {
  const traceHex = job.traceId.slice("trace-".length);
  return attemptNumber === undefined
    ? `shadow-${traceHex}-${kind}`
    : `shadow-${traceHex}-a${attemptNumber}-${kind}`;
}

function admissionTarget(run: NormalizedRun): string {
  return `shadow-${run.runId.slice("run-".length)}-admission`;
}

function recordSchemaVersion(kind: ShadowRecordKind): string {
  switch (kind) {
    case "admission":
      return ADMISSION_RECORD_VERSION;
    case "intent":
      return INTENT_RECORD_VERSION;
    case "lease":
      return LEASE_RECORD_VERSION;
    case "outcome":
      return OUTCOME_RECORD_VERSION;
    case "accepted":
      return ACCEPTED_RECORD_VERSION;
    case "complete":
      return COMPLETE_RECORD_VERSION;
  }
}

function recordDescriptorKind(kind: ShadowRecordKind): string {
  return `tasc-shadow-${kind}-record-v1`;
}

function requiresRecordAuthentication(kind: ShadowRecordKind): boolean {
  return kind !== "accepted";
}

interface ShadowRecordAuthentication {
  readonly version: typeof RECORD_AUTHENTICATION_VERSION;
  readonly algorithm: "hmac-sha256";
  readonly keyId: string;
  readonly value: string;
}

function recordAuthentication(
  run: NormalizedRun,
  targetName: string,
  kind: ShadowRecordKind,
  record: unknown,
): ShadowRecordAuthentication {
  const authentication = {
    version: RECORD_AUTHENTICATION_VERSION,
    algorithm: "hmac-sha256" as const,
    keyId: run.identity.keyId,
  };
  const value = createHmac("sha256", run.identity.key)
    .update(RECORD_AUTHENTICATION_PREFIX, "utf8")
    .update(canonicalJsonBytes({
      studyId: run.protocol.studyId,
      protocolDigest: run.protocolDigest,
      shadowPlanDigest: run.plan.planDigest,
      runId: run.runId,
      targetName,
      recordKind: kind,
      schemaVersion: recordSchemaVersion(kind),
      authentication,
      record,
    }))
    .digest("hex");
  return Object.freeze({
    ...authentication,
    value,
  });
}

function authenticatedRecord(
  run: NormalizedRun,
  targetName: string,
  kind: ShadowRecordKind,
  record: unknown,
): Readonly<Record<string, unknown>> {
  return deepFreeze({
    version: AUTHENTICATED_RECORD_VERSION,
    record,
    authentication: recordAuthentication(run, targetName, kind, record),
  });
}

function verifyAuthenticatedRecord(
  run: NormalizedRun,
  targetName: string,
  kind: ShadowRecordKind,
  input: unknown,
): unknown {
  const envelope = strictRecord(
    input,
    "shadow authenticated record",
    new Set(["version", "record", "authentication"]),
  );
  if (
    envelope.version !== AUTHENTICATED_RECORD_VERSION
    || !Object.hasOwn(envelope, "record")
    || !Object.hasOwn(envelope, "authentication")
  ) {
    throw new Error("shadow resume record authentication is invalid");
  }
  const authentication = strictRecord(
    envelope.authentication,
    "shadow record authentication",
    new Set(["version", "algorithm", "keyId", "value"]),
  );
  const expected = recordAuthentication(
    run,
    targetName,
    kind,
    envelope.record,
  );
  const value = authentication.value;
  if (
    authentication.version !== RECORD_AUTHENTICATION_VERSION
    || authentication.algorithm !== "hmac-sha256"
    || authentication.keyId !== run.identity.keyId
    || typeof value !== "string"
    || !/^[a-f0-9]{64}$/u.test(value)
    || !timingSafeEqual(
      Buffer.from(value, "hex"),
      Buffer.from(expected.value, "hex"),
    )
  ) {
    throw new Error("shadow resume record authentication is invalid");
  }
  return envelope.record;
}

async function readRecord(
  run: NormalizedRun,
  targetName: string,
  kind: ShadowRecordKind,
): Promise<ReadRecord | null> {
  const packet = await run.hooks.readPacket(run.rootDirectory, targetName);
  if (packet === null) return null;
  if (
    packet.manifest.descriptor.kind !== recordDescriptorKind(kind)
    || packet.manifest.descriptor.assessmentDecisionDigest !== null
    || packet.manifest.descriptor.assessmentContextDigest !== null
    || packet.manifest.descriptor.attestation !== "unattested"
    || packet.files.length !== 1
  ) {
    throw new Error("shadow artifact packet has an unexpected descriptor");
  }
  const payload = packet.files[0];
  if (
    payload === undefined
    || payload.name !== RECORD_FILENAME
    || payload.mediaType !== RECORD_MEDIA_TYPE
    || payload.schemaVersion !== recordSchemaVersion(kind)
  ) {
    throw new Error("shadow artifact packet has an unexpected payload");
  }
  const parsed = parseBoundedJson(payload.copyBytes(), RECORD_JSON_LIMITS);
  const value = requiresRecordAuthentication(kind)
    ? verifyAuthenticatedRecord(run, targetName, kind, parsed)
    : parsed;
  return Object.freeze({ packet, value });
}

async function persistRecord(
  run: NormalizedRun,
  counters: MutableCounters,
  targetName: string,
  kind: ShadowRecordKind,
  value: unknown,
): Promise<PersistedRecord> {
  const durableValue = requiresRecordAuthentication(kind)
    ? authenticatedRecord(run, targetName, kind, value)
    : value;
  try {
    const packet = await run.hooks.writePacket(
      run.rootDirectory,
      targetName,
      {
        descriptor: {
          version: "tasc-artifact-packet-v1",
          kind: recordDescriptorKind(kind),
          assessmentDecisionDigest: null,
          assessmentContextDigest: null,
          attestation: "unattested",
        },
        files: [{
          name: RECORD_FILENAME,
          bytes: canonicalJsonBytes(durableValue),
          mediaType: RECORD_MEDIA_TYPE,
          schemaVersion: recordSchemaVersion(kind),
        }],
      },
    );
    if (packet.disposition === "written") counters.durableRecordsWritten += 1;
    const winner = await readRecord(run, targetName, kind);
    if (winner === null) {
      throw new Error("shadow artifact publication was not observable");
    }
    return Object.freeze({
      packet: winner.packet,
      value: winner.value,
      disposition: packet.disposition === "written" ? "written" : "existing",
    });
  } catch (error) {
    // Immutable publication races are resolved by the packet already at the
    // target. It remains authoritative even when its bytes differ (notably a
    // durable sent_unknown beating a late provider response).
    const winner = await readRecord(run, targetName, kind);
    if (winner === null) throw error;
    return Object.freeze({
      packet: winner.packet,
      value: winner.value,
      disposition: "existing",
    });
  }
}

function validateRunAdmission(
  run: NormalizedRun,
  input: unknown,
): RunAdmissionRecord {
  const record = runAdmissionRecordSchema.parse(input);
  const startedAtMs = Date.parse(record.startedAt);
  const deadlineAtMs = Date.parse(record.deadlineAt);
  const protocolExpiresAtMs = Date.parse(run.protocol.expiresAt);
  const expectedDeadlineAtMs = Math.min(
    protocolExpiresAtMs,
    Date.parse(run.plan.expiresAt),
    Date.parse(run.plan.window.eventTimeEndExclusive),
    startedAtMs + run.workBudget.maxWallClockMs,
  );
  const workBudgetDigest = domainSeparatedDigest(
    "tasc/shadow-work-budget/v1",
    run.workBudget,
  );
  if (
    record.runId !== run.runId
    || record.protocolExpiresAt !== run.protocol.expiresAt
    || record.workBudgetDigest !== workBudgetDigest
    || record.maximumAttemptWorkMs !== run.maximumAttemptWorkMs
    || record.maximumResponseBytes !== run.maximumResponseBytes
    || startedAtMs < Date.parse(run.protocol.createdAt)
    || startedAtMs < Date.parse(run.plan.issuedAt)
    || startedAtMs
      < Date.parse(run.plan.window.eventTimeStartInclusive)
    || startedAtMs >= protocolExpiresAtMs
    || deadlineAtMs !== expectedDeadlineAtMs
    || run.maximumAttemptWorkMs > deadlineAtMs - startedAtMs
  ) {
    throw new Error("shadow run admission conflicts with preflight");
  }
  return deepFreeze(record);
}

async function establishRunAdmission(
  run: NormalizedRun,
  counters: MutableCounters,
): Promise<NormalizedRun> {
  const intended: RunAdmissionRecord = {
    version: ADMISSION_RECORD_VERSION,
    runId: run.runId,
    startedAt: new Date(run.runStartedAtMs).toISOString(),
    deadlineAt: new Date(run.runDeadlineAtMs).toISOString(),
    protocolExpiresAt: run.protocol.expiresAt,
    workBudgetDigest: domainSeparatedDigest(
      "tasc/shadow-work-budget/v1",
      run.workBudget,
    ),
    maximumAttemptWorkMs: run.maximumAttemptWorkMs,
    maximumResponseBytes: run.maximumResponseBytes,
  };
  const persisted = await persistRecord(
    run,
    counters,
    admissionTarget(run),
    "admission",
    intended,
  );
  const winner = validateRunAdmission(run, persisted.value);
  return Object.freeze({
    ...run,
    runStartedAtMs: Date.parse(winner.startedAt),
    runDeadlineAtMs: Date.parse(winner.deadlineAt),
  });
}

function sameCanonical(left: unknown, right: unknown): boolean {
  return Buffer.compare(
    canonicalJsonBytes(left),
    canonicalJsonBytes(right),
  ) === 0;
}

const TRACE_BASE_KEYS = new Set([
  "version",
  "studyId",
  "protocolDigest",
  "traceId",
  "caseId",
  "groupId",
  "replicateId",
  "split",
  "collectionWindowId",
  "collectionWindowMembershipDigest",
  "sourceMode",
  "collectionBinding",
  "profileId",
  "executionProfileDigest",
  "policyDigest",
  "observedRoute",
  "workload",
  "slices",
  "routeSignal",
  "dispatchIntent",
]);

function extractTraceBase(trace: TraceEnvelope): TraceBase {
  return deepFreeze({
    version: trace.version,
    studyId: trace.studyId,
    protocolDigest: trace.protocolDigest,
    traceId: trace.traceId,
    caseId: trace.caseId,
    groupId: trace.groupId,
    replicateId: trace.replicateId,
    split: trace.split,
    collectionWindowId: trace.collectionWindowId,
    collectionWindowMembershipDigest:
      trace.collectionWindowMembershipDigest,
    sourceMode: trace.sourceMode,
    collectionBinding: trace.collectionBinding,
    profileId: trace.profileId,
    executionProfileDigest: trace.executionProfileDigest,
    policyDigest: trace.policyDigest,
    observedRoute: trace.observedRoute,
    workload: trace.workload,
    slices: trace.slices,
    routeSignal: trace.routeSignal,
    dispatchIntent: trace.dispatchIntent,
  });
}

function validateTraceForJob(
  run: NormalizedRun,
  job: PreparedJob,
  traceInput: unknown,
): TraceEnvelope {
  const trace = verifyTraceDispatchIntent(traceInput, run.protocol);
  if (trace.traceId !== job.traceId) {
    throw new Error("shadow trace conflicts with deterministic identity");
  }
  const expected = traceBaseFor(
    run,
    job,
    trace.dispatchIntent.issuedAt,
    trace.dispatchIntent.signature,
  );
  if (!sameCanonical(extractTraceBase(trace), expected)) {
    throw new Error("shadow trace conflicts with run input");
  }
  return trace;
}

function validateAuthorizationForJob(
  run: NormalizedRun,
  job: PreparedJob,
  authorizationInput: unknown,
): TraceBase {
  const authorization = verifyTraceDispatchAuthorization(
    authorizationInput,
    run.protocol,
  );
  if (authorization.traceId !== job.traceId) {
    throw new Error("shadow trace conflicts with deterministic identity");
  }
  const expected = traceBaseFor(
    run,
    job,
    authorization.dispatchIntent.issuedAt,
    authorization.dispatchIntent.signature,
  );
  if (!sameCanonical(authorization, expected)) {
    throw new Error("shadow trace conflicts with run input");
  }
  return authorization;
}

function validateUnattestedTraceForJob(
  run: NormalizedRun,
  job: PreparedJob,
  traceInput: Record<string, unknown>,
): TraceEnvelope {
  const placeholderCollectedAt = new Date(
    Date.parse(run.protocol.expiresAt) - 1,
  ).toISOString();
  const trace = parseTraceEnvelopeValue({
    ...traceInput,
    collectorAttestation: {
      version: "tasc-collector-attestation-v1",
      collectedAt: placeholderCollectedAt,
      authorityKeyId: run.protocol.collectorAuthority.keyId,
      signatureAlgorithm: "ed25519",
      signature: "AA",
    },
  });
  validateAuthorizationForJob(run, job, extractTraceBase(trace));
  return trace;
}

function assertTraceAttemptLineage(
  run: NormalizedRun,
  job: PreparedJob,
  trace: TraceEnvelope,
): void {
  for (const [index, attempt] of trace.attempts.entries()) {
    const attemptNumber = index + 1;
    if (
      attempt.attemptId !== expectedAttemptId(run, job, attemptNumber)
      || attempt.attemptNumber !== attemptNumber
      || !sameCanonical(
        attempt.payloads.request,
        job.preflight.requestIdentity,
      )
      || attempt.requestedModel.id !== job.profile.model.id
      || attempt.requestedModel.revision !== job.profile.model.revision
    ) {
      throw new Error("shadow trace contains an invalid attempt lineage");
    }
    for (const identity of [
      attempt.payloads.response,
      attempt.payloads.eventStream,
    ]) {
      if (
        identity !== null
        && (
          !("algorithm" in identity)
          || identity.algorithm !== "hmac-sha256"
          || identity.keyId !== run.identity.keyId
        )
      ) {
        throw new Error("shadow trace violates keyed-only payload custody");
      }
    }
    if (
      index < trace.attempts.length - 1
      && (
        attempt.dispatchState !== "not_sent"
        || attempt.status !== "failure"
        || attempt.abortLifecycle !== "not-aborted"
        || (
          attempt.failureCategory !== "transport"
          && attempt.failureCategory !== "timeout"
        )
      )
    ) {
      throw new Error("shadow trace retries an attempt that was not provably unsent");
    }
  }
  if (
    trace.terminalOutputId !== null
    && trace.terminalOutputId.keyId !== run.identity.keyId
  ) {
    throw new Error("shadow trace terminal output uses the wrong payload key");
  }
}

function validateIntentRecord(
  run: NormalizedRun,
  job: PreparedJob,
  input: unknown,
): IntentRecord {
  const record = strictRecord(
    input,
    "shadow intent record",
    new Set(["version", "traceId", "requestIdentity", "trace"]),
  );
  if (
    record.version !== INTENT_RECORD_VERSION
    || record.traceId !== job.traceId
  ) {
    throw new Error("shadow intent record has an invalid identity");
  }
  const requestIdentity = keyedIdentitySchema.parse(record.requestIdentity);
  if (
    !sameCanonical(
      requestIdentity,
      job.preflight.requestIdentity,
    )
  ) {
    throw new Error("shadow intent request identity conflicts with preflight");
  }
  strictRecord(record.trace, "shadow trace base", TRACE_BASE_KEYS);
  const verified = validateAuthorizationForJob(run, job, record.trace);
  return deepFreeze({
    version: INTENT_RECORD_VERSION,
    traceId: job.traceId,
    requestIdentity,
    trace: verified,
  });
}

function normalizeSignature(
  input: unknown,
  authority = "dispatch intent signer",
): string {
  if (
    typeof input !== "string"
    || input.length < 1
    || input.length > 512
    || !BASE64URL_PATTERN.test(input)
  ) {
    throw new Error(`${authority} returned an invalid signature`);
  }
  const bytes = Buffer.from(input, "base64url");
  if (bytes.toString("base64url") !== input) {
    throw new Error(`${authority} returned a noncanonical signature`);
  }
  return input;
}

async function loadOrCreateIntent(
  run: NormalizedRun,
  job: PreparedJob,
  counters: MutableCounters,
): Promise<IntentRecord> {
  const target = targetFor(job, "intent");
  const existing = await readRecord(run, target, "intent");
  if (existing !== null) {
    return validateIntentRecord(run, job, existing.value);
  }
  const issuedAtMs = run.clock.milliseconds();
  if (
    signalAborted(run.signal)
    ||
    issuedAtMs < Date.parse(run.protocol.createdAt)
    || issuedAtMs >= run.runDeadlineAtMs
  ) {
    throw new ProtocolExpiredBeforeIntent();
  }
  const issuedAt = new Date(issuedAtMs).toISOString();
  const unsigned = traceBaseFor(run, job, issuedAt, "AA");
  let signed: unknown;
  try {
    signed = run.signer.sign(dispatchIntentSigningBytes(unsigned));
  } catch {
    throw new Error("dispatch intent signing failed");
  }
  const signature = normalizeSignature(signed);
  const intended: IntentRecord = {
    version: INTENT_RECORD_VERSION,
    traceId: job.traceId,
    requestIdentity: job.preflight.requestIdentity,
    trace: traceBaseFor(run, job, issuedAt, signature),
  };
  // Authenticate before any durable lease or P1 contact.
  validateIntentRecord(run, job, intended);
  const persisted = await persistRecord(
    run,
    counters,
    target,
    "intent",
    intended,
  );
  const winner = validateIntentRecord(run, job, persisted.value);
  if (persisted.disposition === "written") {
    await checkpoint(run, "after-intent", job, null);
  }
  return winner;
}

function parseAcceptedRecord(
  run: NormalizedRun,
  job: PreparedJob,
  input: unknown,
): AcceptedRecord {
  const record = strictRecord(
    input,
    "shadow accepted record",
    new Set(["version", "trace"]),
  );
  if (record.version !== ACCEPTED_RECORD_VERSION) {
    throw new Error("shadow accepted record has an invalid version");
  }
  // Resume invariants that determine whether this runner could ever have
  // authored the record are checked on a strict semantic snapshot before
  // signature verification. This keeps operational diagnostics specific
  // without weakening authentication: every otherwise-admissible record
  // still passes both authority signatures below.
  const semanticTrace = parseTraceEnvelopeValue(record.trace);
  if (semanticTrace.collectorVersion !== SHADOW_RUNNER_VERSION) {
    throw new Error("shadow accepted trace has an incompatible collector version");
  }
  if (
    semanticTrace.attempts.length
      > run.protocol.shadowCollection.maximumAttempts
  ) {
    throw new Error("shadow accepted trace exceeds protocol maximum attempts");
  }
  const trace = validateTraceForJob(run, job, semanticTrace);
  assertTraceAttemptLineage(run, job, trace);
  return deepFreeze({
    version: ACCEPTED_RECORD_VERSION,
    trace,
  });
}

function parseCompleteRecord(
  job: PreparedJob,
  input: unknown,
): CompleteRecord {
  const record = completeRecordSchema.parse(input);
  if (record.traceId !== job.traceId) {
    throw new Error("shadow completion record conflicts with trace");
  }
  return deepFreeze(record);
}

async function checkpoint(
  run: NormalizedRun,
  point: ShadowCrashPoint,
  job: PreparedJob,
  attemptNumber: number | null,
): Promise<void> {
  await run.hooks.checkpoint?.(
    point,
    Object.freeze({ traceId: job.traceId, attemptNumber }),
  );
}

class ProtocolExpiredBeforeIntent extends Error {}

function expectedAttemptId(
  run: NormalizedRun,
  job: PreparedJob,
  attemptNumber: number,
): string {
  return derivedId(
    "attempt",
    run.identity,
    "tasc/shadow-attempt-id/v1",
    {
      traceId: job.traceId,
      attemptNumber,
    },
  );
}

function validateLeaseRecord(
  run: NormalizedRun,
  job: PreparedJob,
  attemptNumber: number,
  input: unknown,
): LeaseRecord {
  const lease = leaseRecordSchema.parse(input);
  const expectedId = expectedAttemptId(run, job, attemptNumber);
  const issuedAtMs = Date.parse(lease.issuedAt);
  const expiresAtMs = Date.parse(lease.expiresAt);
  const prepared = invocationMetadataForJob(lease.prepared, job);
  if (
    lease.traceId !== job.traceId
    || lease.attemptId !== expectedId
    || lease.attemptNumber !== attemptNumber
    || expiresAtMs <= issuedAtMs
    || expiresAtMs - issuedAtMs > lease.preparedDeadlineMs
    || lease.preparedDeadlineMs
      > run.protocol.shadowCollection.attemptTimeoutMs
    || expiresAtMs > run.runDeadlineAtMs
    || lease.httpLimitsDigest !== job.preflight.httpLimitsDigest
    || lease.responseByteLimit !== job.preflight.responseByteLimit
    || issuedAtMs < Date.parse(run.protocol.createdAt)
    || issuedAtMs >= run.runDeadlineAtMs
    || !sameCanonical(
      prepared.requestIdentity,
      job.preflight.requestIdentity,
    )
    || prepared.requestByteCount !== job.preflight.requestByteCount
  ) {
    throw new Error("shadow send lease conflicts with deterministic work");
  }
  return deepFreeze({
    version: LEASE_RECORD_VERSION,
    traceId: job.traceId,
    attemptId: expectedId,
    attemptNumber,
    claimId: lease.claimId,
    issuedAt: lease.issuedAt,
    expiresAt: lease.expiresAt,
    preparedDeadlineMs: lease.preparedDeadlineMs,
    httpLimitsDigest: lease.httpLimitsDigest,
    responseByteLimit: lease.responseByteLimit,
    prepared: lease.prepared,
  });
}

async function persistLease(
  run: NormalizedRun,
  job: PreparedJob,
  counters: MutableCounters,
  attemptNumber: number,
  prepared: PreparedRuntimeInvocation,
  minimumStartedAtMs: number,
  preparedDeadlineMs: number,
  expiresAtMs: number,
): Promise<PersistedLease | null> {
  const clockMs = run.clock.milliseconds();
  const issuedAtMs = Math.max(clockMs, minimumStartedAtMs);
  if (issuedAtMs >= expiresAtMs) return null;
  const preparedSnapshot = preparedSchema.parse(
    snapshotJsonData(prepared, "prepared runtime invocation"),
  );
  const intended: LeaseRecord = {
    version: LEASE_RECORD_VERSION,
    traceId: job.traceId,
    attemptId: expectedAttemptId(run, job, attemptNumber),
    attemptNumber,
    claimId: randomBytes(32).toString("hex"),
    issuedAt: new Date(issuedAtMs).toISOString(),
    expiresAt: new Date(expiresAtMs).toISOString(),
    preparedDeadlineMs,
    httpLimitsDigest: job.preflight.httpLimitsDigest,
    responseByteLimit: job.preflight.responseByteLimit,
    prepared: preparedSnapshot,
  };
  const persisted = await persistRecord(
    run,
    counters,
    targetFor(job, "lease", attemptNumber),
    "lease",
    intended,
  );
  const winner = validateLeaseRecord(run, job, attemptNumber, persisted.value);
  const acquired = winner.claimId === intended.claimId;
  if (acquired) {
    await checkpoint(run, "after-lease", job, attemptNumber);
  }
  return Object.freeze({
    record: winner,
    acquired,
  });
}

function validateOutcomeRecord(
  run: NormalizedRun,
  job: PreparedJob,
  intent: IntentRecord,
  priorAttempts: readonly TraceAttempt[],
  input: unknown,
): OutcomeRecord {
  const record = strictRecord(
    input,
    "shadow outcome record",
    new Set(["version", "traceId", "attempt", "terminalOutputId"]),
  );
  if (
    record.version !== OUTCOME_RECORD_VERSION
    || record.traceId !== job.traceId
  ) {
    throw new Error("shadow outcome record has an invalid identity");
  }
  const terminalOutputId = record.terminalOutputId === null
    ? null
    : keyedIdentitySchema.parse(record.terminalOutputId);
  const candidate = validateUnattestedTraceForJob(run, job, {
    ...intent.trace,
    attempts: [...priorAttempts, record.attempt],
    terminalOutputId,
    collectorVersion: SHADOW_RUNNER_VERSION,
  });
  assertTraceAttemptLineage(run, job, candidate);
  const attempt = candidate.attempts[candidate.attempts.length - 1];
  const attemptNumber = priorAttempts.length + 1;
  if (
    attempt === undefined
    || attempt.attemptNumber !== attemptNumber
    || attempt.attemptId !== expectedAttemptId(run, job, attemptNumber)
    || !sameCanonical(
      attempt.payloads.request,
      job.preflight.requestIdentity,
    )
    || attempt.requestedModel.id !== job.profile.model.id
    || attempt.requestedModel.revision !== job.profile.model.revision
  ) {
    throw new Error("shadow outcome conflicts with deterministic attempt");
  }
  return deepFreeze({
    version: OUTCOME_RECORD_VERSION,
    traceId: job.traceId,
    attempt,
    terminalOutputId,
  });
}

async function persistOutcome(
  run: NormalizedRun,
  job: PreparedJob,
  counters: MutableCounters,
  intent: IntentRecord,
  priorAttempts: readonly TraceAttempt[],
  intended: OutcomeRecord,
): Promise<OutcomeRecord> {
  const attemptNumber = priorAttempts.length + 1;
  const validatedIntended = validateOutcomeRecord(
    run,
    job,
    intent,
    priorAttempts,
    intended,
  );
  const persisted = await persistRecord(
    run,
    counters,
    targetFor(job, "outcome", attemptNumber),
    "outcome",
    validatedIntended,
  );
  const winner = validateOutcomeRecord(
    run,
    job,
    intent,
    priorAttempts,
    persisted.value,
  );
  if (persisted.disposition === "written") {
    await checkpoint(run, "after-outcome", job, attemptNumber);
  }
  return winner;
}

function lastCompletionMs(attempts: readonly TraceAttempt[]): number {
  const last = attempts[attempts.length - 1];
  return last === undefined
    ? Number.NEGATIVE_INFINITY
    : Date.parse(last.observerTimings.completedAt);
}

function tokenUsageValue(
  value: number | null,
  semantics: "provider-input-tokens" | "provider-output-tokens"
    | "provider-total-tokens",
): TraceAttempt["tokenUsage"]["input"] {
  if (value === null) return null;
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error("runtime outcome contains invalid provider token usage");
  }
  return Object.freeze({
    value,
    source: "provider-reported" as const,
    semantics,
  });
}

function providerTimings(
  timing: RuntimeInvocationPersistence["providerTiming"],
): TraceAttempt["providerReported"]["timings"] {
  const fields = [
    ["totalDurationNs", "total-duration"],
    ["loadDurationNs", "load-duration"],
    ["promptEvaluationDurationNs", "prompt-evaluation-duration"],
    ["evaluationDurationNs", "evaluation-duration"],
  ] as const;
  const result: Array<{
    name: string;
    valueMs: number;
    source: "provider-reported";
  }> = [];
  for (const [field, name] of fields) {
    const value = timing[field];
    if (value === undefined) continue;
    if (
      typeof value !== "number"
      || !Number.isFinite(value)
      || value < 0
    ) {
      throw new Error("runtime outcome contains invalid provider timing");
    }
    result.push(Object.freeze({
      name,
      valueMs: value / 1_000_000,
      source: "provider-reported",
    }));
  }
  return Object.freeze(result);
}

function observerTimingsFromPersistence(
  clock: MonotonicWallClock,
  lease: LeaseRecord,
  persistence: RuntimeInvocationPersistence,
): TraceAttempt["observerTimings"] {
  const attemptStartedAtMs = Date.parse(lease.issuedAt);
  const wire = persistence.wireTiming;
  if (wire === null) {
    return Object.freeze({
      startedAt: lease.issuedAt,
      headersAt: null,
      firstByteAt: null,
      firstMeaningfulTokenAt: null,
      completedAt: new Date(
        Math.max(attemptStartedAtMs, clock.milliseconds()),
      ).toISOString(),
    });
  }
  const wireStartedAtMs = Date.parse(wire.startedAt);
  if (
    wireStartedAtMs < attemptStartedAtMs
    || wireStartedAtMs >= Date.parse(lease.expiresAt)
  ) {
    throw new Error("runtime wire timing starts outside the send lease");
  }
  const headersAtMs = wire.headersMs === undefined
    ? null
    : wireStartedAtMs + wire.headersMs;
  const firstByteAtMs =
    wire.firstByteMs === undefined
      ? null
      : wireStartedAtMs + wire.firstByteMs;
  if (
    firstByteAtMs !== null
    && headersAtMs !== null
    && firstByteAtMs < headersAtMs
  ) {
    throw new Error("runtime first-byte timing precedes headers");
  }
  const meaningfulOffset =
    persistence.streamTiming?.timeToFirstMeaningfulMs ?? null;
  const firstMeaningfulAtMs = meaningfulOffset === null
    ? null
    : wireStartedAtMs + meaningfulOffset;
  if (
    firstMeaningfulAtMs !== null
    && (
      firstByteAtMs === null
      || firstMeaningfulAtMs < firstByteAtMs
    )
  ) {
    throw new Error("runtime meaningful-token timing precedes first byte");
  }
  const wireCompletedAtMs = wireStartedAtMs + wire.completedMs;
  if (
    (headersAtMs ?? wireStartedAtMs) > wireCompletedAtMs
    || (firstByteAtMs ?? wireStartedAtMs) > wireCompletedAtMs
    || (firstMeaningfulAtMs ?? wireStartedAtMs) > wireCompletedAtMs
  ) {
    throw new Error("runtime observation timing follows wire completion");
  }
  const completedAtMs = Math.max(wireCompletedAtMs, clock.milliseconds());
  return Object.freeze({
    startedAt: lease.issuedAt,
    headersAt: headersAtMs === null
      ? null
      : new Date(headersAtMs).toISOString(),
    firstByteAt: firstByteAtMs === null
      ? null
      : new Date(firstByteAtMs).toISOString(),
    firstMeaningfulTokenAt: firstMeaningfulAtMs === null
      ? null
      : new Date(firstMeaningfulAtMs).toISOString(),
    completedAt: new Date(completedAtMs).toISOString(),
  });
}

function normalizeRuntimePersistence(
  run: NormalizedRun,
  outcome: RuntimeInvocationOutcome,
): RuntimeInvocationPersistence {
  const record = strictRecord(
    outcome,
    "runtime invocation outcome",
    new Set(["schemaVersion", "status", "output", "persistence"]),
  );
  for (const required of [
    "schemaVersion",
    "status",
    "output",
    "persistence",
  ]) {
    if (!Object.hasOwn(record, required)) {
      throw new Error("runtime invocation outcome is missing a field");
    }
  }
  if (
    record.schemaVersion !== "tasc-runtime-invocation-v1"
    || (
      record.output !== null
      && (
        typeof record.output !== "object"
        || isProxy(record.output)
      )
    )
  ) {
    throw new Error("runtime invocation outcome is invalid");
  }
  const parsed = runtimePersistenceSchema.parse(
    snapshotJsonData(
      record.persistence,
      "runtime invocation persistence",
    ),
  );
  if (record.status !== parsed.status) {
    throw new Error("runtime outcome status conflicts with persistence");
  }
  for (const identity of [
    parsed.requestIdentity,
    parsed.responseIdentity,
    parsed.eventStreamIdentity,
    parsed.terminalOutputIdentity,
  ]) {
    if (identity !== null && identity.keyId !== run.identity.keyId) {
      throw new Error("runtime outcome uses the wrong payload key identity");
    }
  }
  return deepFreeze(parsed) as RuntimeInvocationPersistence;
}

function validatePersistenceBinding(
  persistence: RuntimeInvocationPersistence,
  lease: LeaseRecord,
  job: PreparedJob,
): void {
  const dispatchEvidenceIsConsistent =
    persistence.dispatchState !== "not_sent"
    || (
      persistence.status === "failed"
      && persistence.resolvedModel === null
      && persistence.responseIdentity === null
      && persistence.eventStreamIdentity === null
      && persistence.terminalOutputIdentity === null
      && persistence.finishReason === null
      && persistence.providerUsage === null
      && persistence.finalUsage === "missing"
      && !persistence.partialOutput
      && persistence.wireTiming === null
      && persistence.streamTiming === null
      && persistence.error !== null
    );
  if (
    persistence === null
    || typeof persistence !== "object"
    || isProxy(persistence)
    || persistence.schemaVersion
      !== "tasc-runtime-invocation-persistence-v1"
    || !new Set(["completed", "incomplete", "failed"]).has(
      persistence.status,
    )
    || !new Set(["not_sent", "sent_unknown", "completed"]).has(
      persistence.dispatchState,
    )
    || persistence.endpointBindingDigest
      !== lease.prepared.endpointBindingDigest
    || persistence.profile.id !== lease.prepared.profile.id
    || persistence.profile.build !== lease.prepared.profile.build
    || persistence.route !== lease.prepared.route
    || !sameCanonical(
      persistence.requestedModel,
      lease.prepared.requestedModel,
    )
    || !sameCanonical(
      persistence.requestIdentity,
      lease.prepared.requestIdentity,
    )
    || persistence.requestedModel.id !== job.profile.model.id
    || persistence.requestedModel.revision !== job.profile.model.revision
    || !dispatchEvidenceIsConsistent
  ) {
    throw new Error("runtime outcome conflicts with the send lease");
  }
}

function resolvedModelFromPersistence(
  persistence: RuntimeInvocationPersistence,
): TraceAttempt["resolvedModel"] {
  const resolved = persistence.resolvedModel;
  if (resolved === null) return null;
  if (
    typeof resolved.id !== "string"
    || resolved.id.length < 1
    || resolved.id.length > 256
  ) {
    throw new Error("runtime outcome contains invalid resolved model");
  }
  if (resolved.revision === null) {
    return Object.freeze({
      id: resolved.id,
      revision: null,
      source: "provider-id-only" as const,
    });
  }
  if (
    typeof resolved.revision !== "string"
    || resolved.revision.length < 1
    || resolved.revision.length > 256
  ) {
    throw new Error("runtime outcome contains invalid model revision");
  }
  return Object.freeze({
    id: resolved.id,
    revision: resolved.revision,
    source: "provider-reported" as const,
  });
}

function abortLifecycleFromPersistence(
  persistence: RuntimeInvocationPersistence,
): TraceAttempt["abortLifecycle"] {
  switch (persistence.abortLifecycle) {
    case "not-aborted":
      return "not-aborted";
    case "caller-cancelled-before-dispatch":
      return "abort-confirmed";
    case "caller-cancelled-after-dispatch-ambiguous":
      return "abort-ambiguous";
    case "deadline-exceeded":
      return persistence.dispatchState === "not_sent"
        ? "abort-confirmed"
        : "abort-ambiguous";
  }
}

function safeFailureCategory(
  error: PersistedError | null,
  fallback: string,
): string {
  const value = error?.category ?? fallback;
  return requireSlug(value, "runtime failure category");
}

function outcomeFromRuntime(
  run: NormalizedRun,
  job: PreparedJob,
  lease: LeaseRecord,
  outcome: RuntimeInvocationOutcome,
): OutcomeRecord {
  // The normalizer intentionally validates only the persistence descriptor;
  // ephemeral `output` text is type-checked at the envelope boundary but
  // never traversed, copied, or persisted.
  const persistence = normalizeRuntimePersistence(run, outcome);
  validatePersistenceBinding(persistence, lease, job);
  const observerTimings = observerTimingsFromPersistence(
    run.clock,
    lease,
    persistence,
  );
  const completedAtMs = Date.parse(observerTimings.completedAt);
  const completionExpired =
    completedAtMs >= run.runDeadlineAtMs
    || completedAtMs >= Date.parse(lease.expiresAt);
  const resolvedModel = resolvedModelFromPersistence(persistence);
  const abortLifecycle = completionExpired
    ? "abort-ambiguous"
    : abortLifecycleFromPersistence(persistence);
  const finishReason =
    persistence.finishReason !== null
      && typeof persistence.finishReason === "string"
      && CONTRACT_SLUG_PATTERN.test(persistence.finishReason)
      && persistence.finishReason.length <= 128
      ? persistence.finishReason
      : null;
  const terminalOutputId = persistence.terminalOutputIdentity === null
    ? null
    : keyedIdentitySchema.parse(persistence.terminalOutputIdentity);
  const success =
    persistence.status === "completed"
    && persistence.dispatchState === "completed"
    && abortLifecycle === "not-aborted"
    && !persistence.partialOutput
    && finishReason !== null
    && resolvedModel !== null
    && terminalOutputId !== null
    && !completionExpired;
  const aborted = abortLifecycle !== "not-aborted";
  const status: TraceAttempt["status"] = success
    ? "success"
    : aborted ? "aborted" : "failure";
  const failureCategory = success
    ? null
    : completionExpired
      ? "timeout"
    : persistence.status === "incomplete"
      ? "incomplete-response"
      : aborted
        ? safeFailureCategory(persistence.error, "cancelled")
      : persistence.dispatchState === "sent_unknown"
        ? "unknown"
        : safeFailureCategory(
          persistence.error,
          persistence.status === "failed"
            ? "internal"
            : "invalid-response",
        );
  const usage = persistence.providerUsage;
  const attempt: TraceAttempt = {
    attemptId: lease.attemptId,
    attemptNumber: lease.attemptNumber,
    dispatchState: persistence.dispatchState,
    observerTimings,
    status,
    finishReason: success ? finishReason : null,
    partialOutput: persistence.partialOutput,
    abortLifecycle,
    failureCategory,
    requestedModel: persistence.requestedModel,
    resolvedModel,
    tokenUsage: {
      input: tokenUsageValue(
        usage?.inputTokens ?? null,
        "provider-input-tokens",
      ),
      output: tokenUsageValue(
        usage?.outputTokens ?? null,
        "provider-output-tokens",
      ),
      total: tokenUsageValue(
        usage?.totalTokens ?? null,
        "provider-total-tokens",
      ),
    },
    providerReported: {
      timings: providerTimings(persistence.providerTiming),
      metrics: [],
    },
    cost: { kind: "unavailable" },
    payloads: {
      request: persistence.requestIdentity,
      response: persistence.responseIdentity,
      eventStream: persistence.eventStreamIdentity,
    },
  };
  return deepFreeze({
    version: OUTCOME_RECORD_VERSION,
    traceId: job.traceId,
    attempt,
    terminalOutputId: success ? terminalOutputId : null,
  });
}

function syntheticError(category: PersistedErrorCategory): PersistedError {
  return sanitizeErrorForPersistence({ category });
}

function syntheticOutcome(input: {
  readonly run: NormalizedRun;
  readonly job: PreparedJob;
  readonly attemptNumber: number;
  readonly startedAt: string;
  readonly completedAtMs: number;
  readonly dispatchState: "not_sent" | "sent_unknown";
  readonly error: PersistedError;
  readonly aborted?: boolean;
}): OutcomeRecord {
  const startedAtMs = Date.parse(input.startedAt);
  const completedAt = new Date(
    Math.max(startedAtMs, input.completedAtMs),
  ).toISOString();
  const aborted = input.aborted === true;
  return deepFreeze({
    version: OUTCOME_RECORD_VERSION,
    traceId: input.job.traceId,
    attempt: {
      attemptId: expectedAttemptId(
        input.run,
        input.job,
        input.attemptNumber,
      ),
      attemptNumber: input.attemptNumber,
      dispatchState: input.dispatchState,
      observerTimings: {
        startedAt: input.startedAt,
        headersAt: null,
        firstByteAt: null,
        firstMeaningfulTokenAt: null,
        completedAt,
      },
      status: aborted ? "aborted" : "failure",
      finishReason: null,
      partialOutput: false,
      abortLifecycle: aborted
        ? input.dispatchState === "not_sent"
          ? "abort-confirmed"
          : "abort-ambiguous"
        : "not-aborted",
      failureCategory: input.error.category,
      requestedModel: input.job.preflight.requestedModel,
      resolvedModel: null,
      tokenUsage: {
        input: null,
        output: null,
        total: null,
      },
      providerReported: {
        timings: [],
        metrics: [],
      },
      cost: { kind: "unavailable" },
      payloads: {
        request: input.job.preflight.requestIdentity,
        response: null,
        eventStream: null,
      },
    },
    terminalOutputId: null,
  }) as OutcomeRecord;
}

function outcomeIsTerminal(
  run: NormalizedRun,
  outcome: OutcomeRecord,
  maximumAttempts: number,
): boolean {
  const retrySafeCategory =
    outcome.attempt.failureCategory === "transport"
    || outcome.attempt.failureCategory === "timeout";
  const retryable =
    outcome.attempt.dispatchState === "not_sent"
    && outcome.attempt.status === "failure"
    && outcome.attempt.abortLifecycle === "not-aborted"
    && retrySafeCategory
    && outcome.attempt.attemptNumber < maximumAttempts
    && !signalAborted(run.signal)
    && run.clock.milliseconds() < run.runDeadlineAtMs;
  return !retryable;
}

function attestCollectedTrace(
  run: NormalizedRun,
  job: PreparedJob,
  traceBody: Omit<TraceEnvelope, "collectorAttestation">,
): TraceEnvelope {
  const terminal = traceBody.attempts[traceBody.attempts.length - 1];
  if (terminal === undefined) {
    throw new Error("shadow collector cannot attest an empty trace");
  }
  const collectedAtMs = Math.max(
    run.clock.milliseconds(),
    Date.parse(terminal.observerTimings.completedAt),
  );
  if (collectedAtMs >= Date.parse(run.protocol.expiresAt)) {
    throw new Error("shadow collection completed outside protocol validity");
  }
  const unsigned = {
    ...traceBody,
    collectorAttestation: {
      version: "tasc-collector-attestation-v1" as const,
      collectedAt: new Date(collectedAtMs).toISOString(),
      authorityKeyId: run.protocol.collectorAuthority.keyId,
      signatureAlgorithm: "ed25519" as const,
      signature: "AA",
    },
  };
  let signed: unknown;
  try {
    signed = run.collectorSigner.sign(
      collectorAttestationSigningBytes(unsigned),
    );
  } catch {
    throw new Error("collector attestation signing failed");
  }
  const signature = normalizeSignature(
    signed,
    "collector attestation signer",
  );
  return validateTraceForJob(run, job, {
    ...unsigned,
    collectorAttestation: {
      ...unsigned.collectorAttestation,
      signature,
    },
  });
}

async function persistAcceptedAndComplete(
  run: NormalizedRun,
  job: PreparedJob,
  counters: MutableCounters,
  intent: IntentRecord,
  attempts: readonly TraceAttempt[],
  terminalOutputId: KeyedPayloadIdentity | null,
): Promise<TraceEnvelope> {
  const trace = attestCollectedTrace(run, job, {
    ...intent.trace,
    attempts,
    terminalOutputId,
    collectorVersion: SHADOW_RUNNER_VERSION,
  });
  assertTraceAttemptLineage(run, job, trace);
  const acceptedTarget = targetFor(job, "accepted");
  const accepted = await persistRecord(
    run,
    counters,
    acceptedTarget,
    "accepted",
    {
      version: ACCEPTED_RECORD_VERSION,
      trace,
    } satisfies AcceptedRecord,
  );
  const acceptedRecord = parseAcceptedRecord(run, job, accepted.value);
  if (accepted.disposition === "written") {
    await checkpoint(run, "after-accepted", job, null);
  }
  await ensureComplete(
    run,
    job,
    counters,
    acceptedRecord.trace,
    accepted.packet.manifest.packetDigest,
  );
  return acceptedRecord.trace;
}

async function ensureComplete(
  run: NormalizedRun,
  job: PreparedJob,
  counters: MutableCounters,
  trace: TraceEnvelope,
  acceptedPacketDigest: string,
): Promise<void> {
  const completeTarget = targetFor(job, "complete");
  const traceDigest = domainSeparatedDigest(
    "tasc/shadow-accepted-trace/v1",
    trace,
  );
  const existing = await readRecord(run, completeTarget, "complete");
  if (existing !== null) {
    const record = parseCompleteRecord(job, existing.value);
    if (
      record.traceDigest !== traceDigest
      || record.acceptedPacketDigest !== acceptedPacketDigest
    ) {
      throw new Error("shadow completion marker conflicts with accepted trace");
    }
    return;
  }
  const intended: CompleteRecord = {
    version: COMPLETE_RECORD_VERSION,
    traceId: job.traceId,
    traceDigest,
    acceptedPacketDigest,
  };
  const persisted = await persistRecord(
    run,
    counters,
    completeTarget,
    "complete",
    intended,
  );
  const winner = parseCompleteRecord(job, persisted.value);
  if (
    winner.traceDigest !== traceDigest
    || winner.acceptedPacketDigest !== acceptedPacketDigest
  ) {
    throw new Error("shadow completion marker conflicts with accepted trace");
  }
  if (persisted.disposition === "written") {
    await checkpoint(run, "after-complete", job, null);
  }
}

async function loadAccepted(
  run: NormalizedRun,
  job: PreparedJob,
): Promise<{
  readonly trace: TraceEnvelope;
  readonly packetDigest: string;
} | null> {
  const read = await readRecord(
    run,
    targetFor(job, "accepted"),
    "accepted",
  );
  if (read === null) return null;
  const accepted = parseAcceptedRecord(run, job, read.value);
  return Object.freeze({
    trace: accepted.trace,
    packetDigest: read.packet.manifest.packetDigest,
  });
}

function notSentOutcomeForPrepareFailure(input: {
  readonly run: NormalizedRun;
  readonly job: PreparedJob;
  readonly attemptNumber: number;
  readonly startedAtMs: number;
  readonly error: unknown;
}): OutcomeRecord {
  const aborted = signalAborted(input.run.signal);
  const persistedError =
    input.error instanceof RuntimeInvocationInputError
      ? input.error.persistedError
      : syntheticError(aborted ? "cancelled" : "internal");
  return syntheticOutcome({
    run: input.run,
    job: input.job,
    attemptNumber: input.attemptNumber,
    startedAt: new Date(input.startedAtMs).toISOString(),
    completedAtMs: Math.max(
      input.startedAtMs,
      input.run.clock.milliseconds(),
    ),
    dispatchState: "not_sent",
    error: persistedError,
    aborted,
  });
}

function beginDispatch(input: {
  readonly run: NormalizedRun;
  readonly job: PreparedJob;
  readonly lease: LeaseRecord;
  readonly prepared: PreparedRuntimeInvocation;
  readonly counters: MutableCounters;
  readonly dispatchOrder: string[];
}): DispatchStart {
  const observedAtMs = input.run.clock.milliseconds();
  const aborted = signalAborted(input.run.signal);
  if (aborted || observedAtMs >= Date.parse(input.lease.expiresAt)) {
    return Object.freeze({
      kind: "not-started",
      observedAtMs,
      aborted,
    });
  }
  if (input.counters.networkCalls >= input.run.workBudget.maxNetworkCalls) {
    throw new Error("shadow network call budget was exhausted");
  }
  input.counters.networkCalls += 1;
  input.dispatchOrder.push(input.job.traceId);
  try {
    return Object.freeze({
      kind: "started",
      outcome: input.run.hooks.dispatchInvocation(input.prepared),
      failure: undefined,
      failedSynchronously: false,
    });
  } catch (error) {
    return Object.freeze({
      kind: "started",
      outcome: null,
      failure: error,
      failedSynchronously: true,
    });
  }
}

type DispatchSettlement =
  | {
    readonly kind: "outcome";
    readonly outcome: RuntimeInvocationOutcome;
  }
  | {
    readonly kind: "failure";
    readonly error: unknown;
  }
  | {
    readonly kind: "aborted";
  }
  | {
    readonly kind: "timed-out";
  };

async function awaitDispatchSettlement(
  run: NormalizedRun,
  lease: LeaseRecord,
  start: Extract<DispatchStart, { readonly kind: "started" }>,
): Promise<DispatchSettlement> {
  if (start.failedSynchronously) {
    return Object.freeze({ kind: "failure", error: start.failure });
  }
  if (signalAborted(run.signal)) {
    return Object.freeze({ kind: "aborted" });
  }
  const remainingMs =
    Date.parse(lease.expiresAt) - run.clock.milliseconds();
  if (remainingMs <= 0) {
    return Object.freeze({ kind: "timed-out" });
  }
  let abortListener: (() => void) | undefined;
  const aborted = new Promise<DispatchSettlement>((resolve) => {
    abortListener = () => resolve(Object.freeze({ kind: "aborted" }));
    run.signal.addEventListener("abort", abortListener, { once: true });
  });
  let timeout: ReturnType<typeof setTimeout> | undefined;
  const timedOut = new Promise<DispatchSettlement>((resolve) => {
    timeout = setTimeout(
      () => resolve(Object.freeze({ kind: "timed-out" })),
      remainingMs,
    );
  });
  const settled = Promise.resolve(start.outcome!).then<
    DispatchSettlement,
    DispatchSettlement
  >(
    (outcome) => Object.freeze({ kind: "outcome", outcome }),
    (error: unknown) => Object.freeze({ kind: "failure", error }),
  );
  try {
    return await Promise.race([settled, aborted, timedOut]);
  } finally {
    if (timeout !== undefined) clearTimeout(timeout);
    if (abortListener !== undefined) {
      run.signal.removeEventListener("abort", abortListener);
    }
  }
}

async function processJob(
  run: NormalizedRun,
  job: PreparedJob,
  counters: MutableCounters,
  dispatchOrder: string[],
  stableDispatchOrder: StableDispatchOrder,
): Promise<JobResult> {
  const accepted = await loadAccepted(run, job);
  if (accepted !== null) {
    await ensureComplete(
      run,
      job,
      counters,
      accepted.trace,
      accepted.packetDigest,
    );
    return Object.freeze({
      trace: accepted.trace,
      pending: false,
      resumed: true,
      deduplicated: true,
      attemptsRecorded: accepted.trace.attempts.length,
      sentUnknown: accepted.trace.attempts.filter(
        ({ dispatchState }) => dispatchState === "sent_unknown",
      ).length,
    });
  }
  const orphanComplete = await readRecord(
    run,
    targetFor(job, "complete"),
    "complete",
  );
  if (orphanComplete !== null) {
    throw new Error("shadow completion marker has no accepted trace");
  }
  if (signalAborted(run.signal)) {
    return Object.freeze({
      trace: null,
      pending: true,
      resumed: false,
      deduplicated: false,
      attemptsRecorded: 0,
      sentUnknown: 0,
    });
  }

  let resumed = false;
  const existingIntent = await readRecord(
    run,
    targetFor(job, "intent"),
    "intent",
  );
  if (existingIntent !== null) resumed = true;
  let intent: IntentRecord;
  try {
    intent = existingIntent === null
      ? await loadOrCreateIntent(run, job, counters)
      : validateIntentRecord(run, job, existingIntent.value);
  } catch (error) {
    if (error instanceof ProtocolExpiredBeforeIntent) {
      return Object.freeze({
        trace: null,
        pending: true,
        resumed,
        deduplicated: false,
        attemptsRecorded: 0,
        sentUnknown: 0,
      });
    }
    throw error;
  }
  const attempts: TraceAttempt[] = [];
  let terminalOutputId: KeyedPayloadIdentity | null = null;
  let enteredStableDispatchOrder = false;
  const maximumAttempts = run.protocol.shadowCollection.maximumAttempts;
  for (
    let attemptNumber = 1;
    attemptNumber <= maximumAttempts;
    attemptNumber += 1
  ) {
    const outcomeTarget = targetFor(job, "outcome", attemptNumber);
    const existingOutcome = await readRecord(
      run,
      outcomeTarget,
      "outcome",
    );
    let outcome: OutcomeRecord | null = null;
    if (existingOutcome !== null) {
      resumed = true;
      outcome = validateOutcomeRecord(
        run,
        job,
        intent,
        attempts,
        existingOutcome.value,
      );
    } else {
      const leaseTarget = targetFor(job, "lease", attemptNumber);
      const existingLease = await readRecord(
        run,
        leaseTarget,
        "lease",
      );
      let lease: LeaseRecord | null = null;
      if (existingLease !== null) {
        resumed = true;
        lease = validateLeaseRecord(
          run,
          job,
          attemptNumber,
          existingLease.value,
        );
        const nowMs = run.clock.milliseconds();
        if (nowMs < Date.parse(lease.expiresAt)) {
          return Object.freeze({
            trace: null,
            pending: true,
            resumed,
            deduplicated: false,
            attemptsRecorded: attempts.length,
            sentUnknown: attempts.filter(
              ({ dispatchState }) => dispatchState === "sent_unknown",
            ).length,
          });
        }
        outcome = await persistOutcome(
          run,
          job,
          counters,
          intent,
          attempts,
          syntheticOutcome({
            run,
            job,
            attemptNumber,
            startedAt: lease.issuedAt,
            completedAtMs: nowMs,
            dispatchState: "sent_unknown",
            error: syntheticError("unknown"),
          }),
        );
      } else {
        const minimumStartedAtMs = lastCompletionMs(attempts);
        const clockMs = run.clock.milliseconds();
        const startedAtMs = Math.max(clockMs, minimumStartedAtMs);
        const expired = startedAtMs >= run.runDeadlineAtMs;
        const aborted = signalAborted(run.signal);
        if (expired || aborted) {
          outcome = await persistOutcome(
            run,
            job,
            counters,
            intent,
            attempts,
            syntheticOutcome({
              run,
              job,
              attemptNumber,
              startedAt: new Date(startedAtMs).toISOString(),
              completedAtMs: startedAtMs,
              dispatchState: "not_sent",
              error: syntheticError(aborted ? "cancelled" : "timeout"),
              aborted,
            }),
          );
        } else {
          const dispatchExpiresAtMs = Math.min(
            run.runDeadlineAtMs,
            startedAtMs + run.protocol.shadowCollection.attemptTimeoutMs,
          );
          const preparedDeadlineMs = dispatchExpiresAtMs - startedAtMs;
          let prepared: PreparedRuntimeInvocation | null = null;
          try {
            prepared = assertLivePreparedMatches(
              run.hooks.prepareInvocation(
                invocationForJob(
                  job,
                  run.identity,
                  preparedDeadlineMs,
                  run.signal,
                ),
              ),
              job,
            );
          } catch (error) {
            outcome = await persistOutcome(
              run,
              job,
              counters,
              intent,
              attempts,
              notSentOutcomeForPrepareFailure({
                run,
                job,
                attemptNumber,
                startedAtMs,
                error,
              }),
            );
          }
          if (prepared !== null) {
            const persistedLease = await persistLease(
              run,
              job,
              counters,
              attemptNumber,
              prepared,
              startedAtMs,
              preparedDeadlineMs,
              dispatchExpiresAtMs,
            );
            if (persistedLease === null) {
              outcome = await persistOutcome(
                run,
                job,
                counters,
                intent,
                attempts,
                syntheticOutcome({
                  run,
                  job,
                  attemptNumber,
                  startedAt: new Date(startedAtMs).toISOString(),
                  completedAtMs: run.clock.milliseconds(),
                  dispatchState: "not_sent",
                  error: syntheticError("timeout"),
                }),
              );
            } else {
              lease = persistedLease.record;
              if (!persistedLease.acquired) {
                resumed = true;
                const nowMs = run.clock.milliseconds();
                if (nowMs < Date.parse(lease.expiresAt)) {
                  return Object.freeze({
                    trace: null,
                    pending: true,
                    resumed,
                    deduplicated: false,
                    attemptsRecorded: attempts.length,
                    sentUnknown: attempts.filter(
                      ({ dispatchState }) => dispatchState === "sent_unknown",
                    ).length,
                  });
                }
                outcome = await persistOutcome(
                  run,
                  job,
                  counters,
                  intent,
                  attempts,
                  syntheticOutcome({
                    run,
                    job,
                    attemptNumber,
                    startedAt: lease.issuedAt,
                    completedAtMs: nowMs,
                    dispatchState: "sent_unknown",
                    error: syntheticError("unknown"),
                  }),
                );
              } else {
                const begin = (): DispatchStart => beginDispatch({
                  run,
                  job,
                  lease: persistedLease.record,
                  prepared,
                  counters,
                  dispatchOrder,
                });
                const dispatchStart = enteredStableDispatchOrder
                  ? begin()
                  : await stableDispatchOrder.start(job.index, begin);
                enteredStableDispatchOrder = true;
                if (dispatchStart.kind === "not-started") {
                  outcome = await persistOutcome(
                    run,
                    job,
                    counters,
                    intent,
                    attempts,
                    syntheticOutcome({
                      run,
                      job,
                      attemptNumber,
                      startedAt: lease.issuedAt,
                      completedAtMs: dispatchStart.observedAtMs,
                      dispatchState: "not_sent",
                      error: syntheticError(
                        dispatchStart.aborted ? "cancelled" : "timeout",
                      ),
                      aborted: dispatchStart.aborted,
                    }),
                  );
                } else {
                  const settlement = await awaitDispatchSettlement(
                    run,
                    lease,
                    dispatchStart,
                  );
                  if (
                    settlement.kind === "outcome"
                    && !signalAborted(run.signal)
                  ) {
                    await checkpoint(
                      run,
                      "after-dispatch",
                      job,
                      attemptNumber,
                    );
                    try {
                      outcome = outcomeFromRuntime(
                        run,
                        job,
                        lease,
                        settlement.outcome,
                      );
                    } catch {
                      outcome = syntheticOutcome({
                        run,
                        job,
                        attemptNumber,
                        startedAt: lease.issuedAt,
                        completedAtMs: run.clock.milliseconds(),
                        dispatchState: "sent_unknown",
                        error: syntheticError("unknown"),
                      });
                    }
                  } else if (
                    settlement.kind === "aborted"
                    || settlement.kind === "timed-out"
                    || signalAborted(run.signal)
                  ) {
                    outcome = syntheticOutcome({
                      run,
                      job,
                      attemptNumber,
                      startedAt: lease.issuedAt,
                      completedAtMs: run.clock.milliseconds(),
                      dispatchState: "sent_unknown",
                      error: syntheticError(
                        settlement.kind === "timed-out"
                          || run.cancellation.kind === "deadline"
                          ? "timeout"
                          : "cancelled",
                      ),
                      aborted: true,
                    });
                  } else if (settlement.kind === "failure") {
                    const inputError =
                      settlement.error instanceof RuntimeInvocationInputError
                        ? settlement.error
                        : null;
                    const provablyNotSent = inputError !== null;
                    outcome = syntheticOutcome({
                      run,
                      job,
                      attemptNumber,
                      startedAt: lease.issuedAt,
                      completedAtMs: run.clock.milliseconds(),
                      dispatchState: provablyNotSent
                        ? "not_sent"
                        : "sent_unknown",
                      error: provablyNotSent
                        ? inputError.persistedError
                        : syntheticError("unknown"),
                      aborted: signalAborted(run.signal),
                    });
                  } else {
                    throw new Error(
                      "shadow dispatch settlement was inconsistent",
                    );
                  }
                  outcome = await persistOutcome(
                    run,
                    job,
                    counters,
                    intent,
                    attempts,
                    outcome,
                  );
                }
              }
            }
          }
        }
      }
    }
    if (outcome === null) {
      throw new Error("shadow attempt state machine produced no outcome");
    }
    attempts.push(outcome.attempt);
    terminalOutputId = outcome.terminalOutputId;
    if (!outcomeIsTerminal(run, outcome, maximumAttempts)) continue;
    const trace = await persistAcceptedAndComplete(
      run,
      job,
      counters,
      intent,
      attempts,
      terminalOutputId,
    );
    const sentUnknown = attempts.filter(
      ({ dispatchState }) => dispatchState === "sent_unknown",
    ).length;
    return Object.freeze({
      trace,
      pending: false,
      resumed,
      deduplicated: false,
      attemptsRecorded: attempts.length,
      sentUnknown,
    });
  }
  throw new Error("shadow attempt state machine exhausted unexpectedly");
}

async function runScheduledJobs(
  run: NormalizedRun,
  counters: MutableCounters,
  dispatchOrder: string[],
): Promise<readonly JobResult[]> {
  const results: Array<JobResult | undefined> =
    new Array<JobResult | undefined>(run.jobs.length);
  const pendingJobs = [...run.jobs];
  const activeLanes = new Set<string>();
  const stableDispatchOrder = new StableDispatchOrder();
  const maximum = run.workBudget.maxConcurrency;
  let unfinished = run.jobs.length;
  let active = 0;
  let fatal: unknown;
  let fatalSet = false;

  return new Promise((resolve, reject) => {
    const abandonPending = (): void => {
      for (const pending of pendingJobs.splice(0)) {
        stableDispatchOrder.skip(pending.index);
      }
    };

    const markPendingJobs = (): void => {
      for (const pending of pendingJobs.splice(0)) {
        results[pending.index] = Object.freeze({
          trace: null,
          pending: true,
          resumed: false,
          deduplicated: false,
          attemptsRecorded: 0,
          sentUnknown: 0,
        });
        unfinished -= 1;
        stableDispatchOrder.skip(pending.index);
      }
    };

    const settleIfDone = (): boolean => {
      if (active !== 0) return false;
      if (fatalSet) {
        reject(fatal);
        return true;
      }
      if (unfinished === 0) {
        resolve(Object.freeze(results as JobResult[]));
        return true;
      }
      return false;
    };

    const pump = (): void => {
      if (settleIfDone() || fatalSet) return;
      if (signalAborted(run.signal)) {
        markPendingJobs();
        settleIfDone();
        return;
      }
      while (active < maximum && pendingJobs.length > 0) {
        const readyIndex = pendingJobs.findIndex(
          ({ laneKey }) => !activeLanes.has(laneKey),
        );
        if (readyIndex < 0) break;
        const [job] = pendingJobs.splice(readyIndex, 1);
        if (job === undefined) {
          fatal = new Error("shadow scheduler lost declared work");
          fatalSet = true;
          run.cancellation.abort("fatal");
          abandonPending();
          break;
        }
        activeLanes.add(job.laneKey);
        active += 1;
        void processJob(
          run,
          job,
          counters,
          dispatchOrder,
          stableDispatchOrder,
        ).then(
          (result) => {
            results[job.index] = result;
            unfinished -= 1;
            if (result.pending) {
              for (
                let index = pendingJobs.length - 1;
                index >= 0;
                index -= 1
              ) {
                const blocked = pendingJobs[index];
                if (blocked?.laneKey !== job.laneKey) continue;
                pendingJobs.splice(index, 1);
                results[blocked.index] = Object.freeze({
                  trace: null,
                  pending: true,
                  resumed: false,
                  deduplicated: false,
                  attemptsRecorded: 0,
                  sentUnknown: 0,
                });
                unfinished -= 1;
                stableDispatchOrder.skip(blocked.index);
              }
            }
          },
          (error: unknown) => {
            if (!fatalSet) {
              fatal = error;
              fatalSet = true;
              run.cancellation.abort("fatal");
              abandonPending();
            }
          },
        ).finally(() => {
          stableDispatchOrder.skip(job.index);
          activeLanes.delete(job.laneKey);
          active -= 1;
          pump();
        });
      }
      settleIfDone();
    };
    pump();
  });
}

/**
 * Execute a protocol-bounded shadow collection.
 *
 * This subordinate P1 runner consumes a frozen P0 ShadowRunPlan. Its effect
 * boundary is exactly `dispatchPreparedRuntimeInvocation`; it returns signed
 * trace evidence only and has no evaluator, judge, score, rollout, policy,
 * or deployment authority.
 */
async function executeShadowCollection(
  input: ShadowRunInput & { readonly hooks?: ShadowRunnerHooks },
  allowTestingHooks: boolean,
): Promise<ShadowRunResult> {
  // This complete admission pass deliberately occurs before signer, fs, or
  // network hooks are invoked.
  const preflight = normalizeRunInput(input, allowTestingHooks);
  try {
    if (preflight.jobs.length === 0) {
      return deepFreeze({
        version: SHADOW_RUN_RESULT_VERSION,
        status: signalAborted(preflight.signal)
          ? "cancelled"
          : "complete",
        logicalExecutions: 0,
        membershipExcludedReplicates:
          preflight.membershipExcludedReplicates,
        traces: [],
        pendingTraceIds: [],
        dispatchOrder: [],
        attemptsRecorded: 0,
        networkCalls: 0,
        durableRecordsWritten: 0,
        resumed: 0,
        deduplicated: 0,
        sentUnknown: 0,
      });
    }
    const counters: MutableCounters = {
      networkCalls: 0,
      durableRecordsWritten: 0,
    };
    const run = signalAborted(preflight.signal)
      ? preflight
      : await establishRunAdmission(preflight, counters);
    const dispatchOrder: string[] = [];
    const results = await runScheduledJobs(run, counters, dispatchOrder);
    const traces = results
      .map(({ trace }) => trace)
      .filter((trace): trace is TraceEnvelope => trace !== null);
    const pendingTraceIds = run.jobs
      .filter((_job, index) => results[index]?.pending === true)
      .map(({ traceId }) => traceId);
    const attemptsRecorded = results.reduce(
      (total, result) => total + result.attemptsRecorded,
      0,
    );
    const resumed = results.filter(({ resumed: value }) => value).length;
    const deduplicated = results.filter(
      ({ deduplicated: value }) => value,
    ).length;
    const sentUnknown = results.reduce(
      (total, result) => total + result.sentUnknown,
      0,
    );
    if (
      counters.networkCalls > run.workBudget.maxNetworkCalls
      || counters.durableRecordsWritten > run.workBudget.maxDurableRecords
      || attemptsRecorded > run.workBudget.maxAttempts
    ) {
      throw new Error("shadow work exceeded its admitted budget");
    }
    return deepFreeze({
      version: SHADOW_RUN_RESULT_VERSION,
      status: signalAborted(run.signal)
        ? "cancelled"
        : pendingTraceIds.length === 0 ? "complete" : "partial",
      logicalExecutions: run.jobs.length,
      membershipExcludedReplicates:
        run.membershipExcludedReplicates,
      traces,
      pendingTraceIds,
      dispatchOrder,
      attemptsRecorded,
      networkCalls: counters.networkCalls,
      durableRecordsWritten: counters.durableRecordsWritten,
      resumed,
      deduplicated,
      sentUnknown,
    });
  } finally {
    preflight.cancellation.dispose();
  }
}

export async function runShadowCollection(
  input: ShadowRunInput,
): Promise<ShadowRunResult> {
  return executeShadowCollection(input, false);
}

/**
 * @internal Direct source-test entry point. Not exported from the package.
 */
export async function runShadowCollectionForTesting(
  input: ShadowRunInput & { readonly hooks?: ShadowRunnerHooks },
): Promise<ShadowRunResult> {
  return executeShadowCollection(input, true);
}
