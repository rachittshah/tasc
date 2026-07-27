import {
  generateKeyPairSync,
  sign,
  type KeyObject,
} from "node:crypto";
import type { WorkBudget } from "../../src/work-budget.js";
import {
  evaluatorEvidenceSigningBytes,
  fingerprintExecutionProfile,
  fingerprintProtocol,
  fingerprintEvaluatorRevocations,
  fingerprintEvaluatorTrustPolicy,
  type EvaluatorTrustSnapshot,
} from "../../src/index.js";

export const TEST_WORK_BUDGET: Readonly<WorkBudget> = Object.freeze({
  maxCandidates: 32,
  maxTraceRows: 64,
  maxEvidenceRows: 64,
  maxBootstrapDraws: 2_000,
  maxIndependentGroups: 64,
  maxAssessmentWork: 1_000_000_000,
});

export const digest = (digit: string): string => `sha256:${digit.repeat(64)}`;
export const keyedIdentity = (digit = "a") => ({
  algorithm: "hmac-sha256" as const,
  keyId: "study-payload-key",
  value: digit.repeat(64),
});

export const validExecutionProfile = (id = "champion") => ({
  id,
  runtime: {
    name: "vllm",
    build: "0.10.2",
  },
  backend: {
    name: "cuda",
    build: "12.8",
  },
  model: {
    id: `${id}-model`,
    revision: "refs-pr-42",
  },
  tokenizer: {
    id: `${id}-tokenizer`,
    revision: "tokenizer-rev-7",
  },
  hardware: {
    architecture: "x86-64",
    accelerator: "h100-sxm",
    acceleratorCount: 1,
  },
  quantization: {
    format: "fp8",
    configurationDigest: digest(id === "champion" ? "1" : "2"),
  },
  chatTemplateDigest: digest(id === "champion" ? "3" : "4"),
  orchestration: {
    kind: "direct" as const,
    configurationDigest: digest(id === "champion" ? "5" : "6"),
  },
  deploymentConfigurationDigest: digest(id === "champion" ? "7" : "8"),
});

export const validProtocolInput = () => {
  const champion = validExecutionProfile("champion");
  const candidate = validExecutionProfile("candidate");
  return {
    version: "tasc-experiment-protocol-v2" as const,
    studyId: "support-routing-study",
    protocolVersion: "protocol-2",
    owner: "inference-platform",
    createdAt: "2026-07-20T00:00:00.000Z",
    expiresAt: "2026-08-20T00:00:00.000Z",
    splitMembership: {
      algorithm: "tasc-seeded-sha256-group-bucket-v1" as const,
      seed: "support-routing-split-2",
      bucketCount: 10,
      developmentBuckets: [0, 1, 2, 3, 4, 5, 6, 7],
      holdoutBuckets: [8, 9],
    },
    onlineWindowMembership: {
      algorithm: "tasc-seeded-sha256-case-replicate-basis-points-v1" as const,
      seed: "support-routing-shadow-2",
      sampleBasisPoints: 1_000,
    },
    profiles: [champion, candidate],
    championProfileId: "champion",
    candidateProfileIds: ["candidate"],
    routeSignal: {
      definitionId: "router-confidence",
      version: "2",
      minimum: 0,
      maximum: 1,
      direction: "higher-is-more-confident" as const,
      calibrationDigest: digest("9"),
    },
    evaluator: {
      evaluatorId: "support-correctness",
      rubricVersion: "rubric-4",
      calibrationDigest: digest("a"),
      producerKind: "deterministic" as const,
      requiredTrustedKeyIds: ["evaluator-key-1"],
    },
    candidatePolicySpace: {
      version: "tasc-declarative-policy-space-v1" as const,
      maxCandidates: 8,
      predicates: [
        {
          signalDefinitionId: "router-confidence",
          operator: "less-than" as const,
          threshold: 0.7,
          routeToProfileId: "champion",
        },
      ],
    },
    gates: {
      minimumMeanScore: 0.8,
      nonInferiorityMargin: -0.02,
      maximumFailureRate: 0.02,
      maximumP95TtftMs: 2_000,
      maximumP95EndToEndMs: 15_000,
      maximumCostPerThousandRequestsUsd: 25,
      minimumEvidenceCoverage: 0.98,
      minimumIndependentGroups: 10,
      minimumCriticalSliceGroups: 3,
    },
    criticalSlices: ["payments", "account-recovery"],
    bootstrap: {
      algorithm: "paired-group-percentile-v1" as const,
      seed: "bootstrap-support-2",
      iterations: 1_000,
      alpha: 0.05,
    },
    shadowCollection: {
      maximumLogicalExecutions: 1_000,
      maximumConcurrency: 8,
      attemptTimeoutMs: 60_000,
      maximumAttempts: 2,
      payloadPolicy: "keyed-identities-only" as const,
    },
    costAllocation: {
      kind: "modeled" as const,
      modelDigest: digest("b"),
      currency: "USD" as const,
    },
    endpointRequirements: [
      {
        runtimeName: "vllm",
        endpointAlias: "approved-vllm",
        transport: "https" as const,
      },
    ],
    requiredCapabilities: ["chat-completions", "streaming", "final-usage"],
  };
};

export const validTraceInput = () => {
  const protocol = validProtocolInput();
  return {
    version: "tasc-trace-envelope-v2" as const,
    studyId: protocol.studyId,
    protocolDigest: fingerprintProtocol(protocol),
    traceId: "trace-case-1-r0-champion",
    caseId: "case-1",
    groupId: "conversation-1",
    replicateId: "replicate-0",
    split: "dev" as const,
    collectionWindowId: null,
    collectionWindowMembershipDigest: null,
    sourceMode: "imported" as const,
    profileId: "champion",
    executionProfileDigest: fingerprintExecutionProfile(protocol.profiles[0]),
    policyDigest: digest("c"),
    observedRoute: {
      selectedProfileId: "champion",
      decisionId: "route-decision-1",
    },
    workload: {
      mode: "chat",
      declaredTrafficWeight: 1,
      inputTokenEstimate: 128,
    },
    slices: ["routine", "english"],
    routeSignal: {
      definitionId: protocol.routeSignal.definitionId,
      version: protocol.routeSignal.version,
      calibrationDigest: protocol.routeSignal.calibrationDigest,
      value: 0.91,
      provenance: {
        kind: "route-signal-observation" as const,
        sourceId: "serving-router",
        observedAt: "2026-07-21T00:00:00.000Z",
      },
    },
    attempts: [
      {
        attemptId: "attempt-1",
        attemptNumber: 1,
        dispatchState: "completed" as const,
        observerTimings: {
          startedAt: "2026-07-21T00:00:00.000Z",
          headersAt: "2026-07-21T00:00:00.050Z",
          firstByteAt: "2026-07-21T00:00:00.060Z",
          firstMeaningfulTokenAt: "2026-07-21T00:00:00.075Z",
          completedAt: "2026-07-21T00:00:00.500Z",
        },
        status: "success" as const,
        finishReason: "stop",
        partialOutput: false,
        abortLifecycle: "not-aborted" as const,
        failureCategory: null,
        requestedModel: {
          id: "champion-model",
          revision: "refs-pr-42",
        },
        resolvedModel: {
          id: "champion-model",
          revision: "refs-pr-42",
          source: "provider-reported" as const,
        },
        tokenUsage: {
          input: {
            value: 128,
            source: "provider-reported" as const,
            semantics: "runtime-input-token-count",
            tokenizerDigest: digest("d"),
          },
          output: {
            value: 32,
            source: "provider-reported" as const,
            semantics: "runtime-output-token-count",
            tokenizerDigest: digest("d"),
          },
          total: {
            value: 160,
            source: "provider-reported" as const,
            semantics: "runtime-total-token-count",
            tokenizerDigest: digest("d"),
          },
        },
        providerReported: {
          timings: [
            {
              name: "queue-time",
              valueMs: 4,
              source: "provider-reported" as const,
            },
          ],
          metrics: [
            {
              name: "cached-input-tokens",
              value: 0,
              unit: "tokens",
              source: "provider-reported" as const,
            },
          ],
        },
        cost: {
          kind: "modeled" as const,
          amount: 0.004,
          currency: "USD" as const,
          modelDigest: digest("b"),
        },
        payloads: {
          request: keyedIdentity("e"),
          response: keyedIdentity("f"),
          eventStream: keyedIdentity("0"),
        },
      },
    ],
    terminalOutputId: keyedIdentity("1"),
    collectorVersion: "collector-2.0.0",
  };
};

export interface EvaluatorKeyFixture {
  privateKey: KeyObject;
  publicKey: KeyObject;
  trustSnapshot: EvaluatorTrustSnapshot;
}

export const evaluatorKeyFixture = (): EvaluatorKeyFixture => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const alternate = generateKeyPairSync("ed25519");
  const key = (keyId: string, keyObject: KeyObject) => ({
    keyId,
    purpose: "evaluator-evidence" as const,
    algorithm: "ed25519" as const,
    publicKeySpki: keyObject.export({ type: "spki", format: "der" }).toString("base64url"),
    evaluatorId: "support-correctness",
    producerId: "support-evaluator-service",
    authorizedRubricVersions: ["rubric-4", "rubric-5"],
    authorizedCalibrationDigests: [digest("a"), digest("b")],
    validFrom: "2026-07-01T00:00:00.000Z",
    validUntil: "2026-09-01T00:00:00.000Z",
  });
  return {
    privateKey,
    publicKey,
    trustSnapshot: {
      version: "tasc-evaluator-trust-snapshot-v1",
      freshness: {
        maximumEvidenceAgeMs: 7 * 24 * 60 * 60 * 1_000,
        maximumFutureSkewMs: 30_000,
      },
      keys: [
        key("evaluator-key-1", publicKey),
        key("evaluator-key-2", alternate.publicKey),
      ],
      revocations: [],
    },
  };
};

export const validAssessmentContextInput = (trustSnapshot: EvaluatorTrustSnapshot) => ({
  version: "tasc-assessment-context-v2" as const,
  asOf: "2026-07-22T00:00:00.000Z",
  operatorTrustPolicySnapshotDigest: fingerprintEvaluatorTrustPolicy(trustSnapshot),
  evaluatorRevocationSnapshotDigest: fingerprintEvaluatorRevocations(trustSnapshot),
});

export const unsignedEvaluatorEvidence = () => {
  const protocol = validProtocolInput();
  const trace = validTraceInput();
  return {
    version: "tasc-evaluator-evidence-v2" as const,
    studyId: protocol.studyId,
    protocolDigest: trace.protocolDigest,
    traceId: trace.traceId,
    caseId: trace.caseId,
    replicateId: trace.replicateId,
    profileId: trace.profileId,
    split: trace.split,
    terminalOutputId: trace.terminalOutputId,
    evaluator: {
      evaluatorId: protocol.evaluator.evaluatorId,
      rubricVersion: protocol.evaluator.rubricVersion,
      calibrationDigest: protocol.evaluator.calibrationDigest,
      producer: {
        kind: "deterministic" as const,
        producerId: "support-evaluator-service",
        version: "4.2.0",
      },
    },
    outcome: {
      kind: "scored" as const,
      score: 0.92,
      range: {
        minimum: 0,
        maximum: 1,
      },
      subscores: [
        {
          id: "correctness",
          score: 0.95,
          range: {
            minimum: 0,
            maximum: 1,
          },
        },
      ],
    },
    source: {
      kind: "digest" as const,
      digest: digest("e"),
    },
    producedAt: "2026-07-21T12:00:00.000Z",
    keyId: "evaluator-key-1",
    signatureAlgorithm: "ed25519" as const,
  };
};

export const signEvaluatorEvidence = (
  privateKey: KeyObject,
  unsigned: Record<string, unknown> = unsignedEvaluatorEvidence(),
) => ({
  ...unsigned,
  signature: sign(null, evaluatorEvidenceSigningBytes(unsigned), privateKey).toString("base64url"),
});

export const validEvaluatorEvidenceInput = (privateKey: KeyObject) =>
  signEvaluatorEvidence(privateKey);

type Mutable<T> =
  T extends readonly (infer Item)[] ? Mutable<Item>[]
    : T extends object ? { -readonly [Key in keyof T]: Mutable<T[Key]> }
      : T;

export function mutate<T>(value: T, change: (copy: Mutable<T>) => void): Mutable<T> {
  const copy = structuredClone(value) as Mutable<T>;
  change(copy);
  return copy;
}
