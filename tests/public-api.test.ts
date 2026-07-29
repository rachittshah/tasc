import { describe, expect, it } from "vitest";
import * as tasc from "../src/index.js";
import * as runtime from "../src/runtime/index.js";
import type {
  ArtifactReadPayload,
  ArtifactReadResult,
  ArtifactWriteOrVerifyResult,
  AuthorizedControlledReference,
  BoundedInputErrorCode,
  BoundedJsonLimits,
  BoundedNdjsonLimits,
  ByteChunkSource,
  ControlledReference,
  ControlledReferenceRegistry,
  ControlledReferenceStore,
  ControllerEventBody,
  ControllerSnapshotBody,
  KeyedPayloadIdentity,
  PersistedError,
  PersistedErrorCategory,
} from "../src/index.js";
import type {
  BoundedNdjsonStreamLimits,
  BoundedRuntimeHttpResult,
  BoundedSseLimits,
  CollectorAttestationSigner,
  CollectorTrustPolicy,
  DispatchIntentSigner,
  PinnedCollectorRequest,
  PreparedRuntimeInvocation,
  PrometheusParseResult,
  RuntimeCapabilityAuthorization,
  RuntimeCapabilityProbeInput,
  RuntimeCapabilityProbeResult,
  RuntimeContentTypeParameter,
  RuntimeHttpLimits,
  RuntimeInvocationInput,
  RuntimeInvocationOutcome,
  RuntimeProbeMetric,
  RuntimeProbeMetricsObservation,
  RuntimeWireDispatchState,
  RuntimeWireErrorCode,
  ShadowCaseInput,
  ShadowProfileTarget,
  ShadowRunInput,
  ShadowRunResult,
  ShadowWorkBudget,
} from "../src/runtime/index.js";

type TaskEightPublicTypes = [
  AuthorizedControlledReference,
  BoundedInputErrorCode,
  BoundedJsonLimits,
  BoundedNdjsonLimits,
  ByteChunkSource,
  ControlledReference,
  ControlledReferenceRegistry,
  ControlledReferenceStore,
  KeyedPayloadIdentity,
  PersistedError,
  PersistedErrorCategory,
];

const taskEightPublicTypeCount: TaskEightPublicTypes["length"] = 11;

type ControllerPublicTypes = [
  ControllerEventBody,
  ControllerSnapshotBody,
];

const controllerPublicTypeCount: ControllerPublicTypes["length"] = 2;

type ArtifactResumePublicTypes = [
  ArtifactReadPayload,
  ArtifactReadResult,
  ArtifactWriteOrVerifyResult,
];

const artifactResumePublicTypeCount:
  ArtifactResumePublicTypes["length"] = 3;

type RuntimeTransportPublicTypes = [
  CollectorTrustPolicy,
  PinnedCollectorRequest,
  RuntimeHttpLimits,
  RuntimeWireDispatchState,
  RuntimeWireErrorCode,
  BoundedRuntimeHttpResult<unknown>,
  BoundedSseLimits,
  BoundedNdjsonStreamLimits,
  PrometheusParseResult,
  RuntimeContentTypeParameter,
];

const runtimeTransportPublicTypeCount:
  RuntimeTransportPublicTypes["length"] = 10;

type RuntimeCallPublicTypes = [
  PreparedRuntimeInvocation,
  RuntimeCapabilityAuthorization,
  RuntimeCapabilityProbeInput,
  RuntimeCapabilityProbeResult,
  RuntimeProbeMetric,
  RuntimeProbeMetricsObservation,
  RuntimeInvocationInput,
  RuntimeInvocationOutcome,
];

const runtimeCallPublicTypeCount: RuntimeCallPublicTypes["length"] = 8;

type ShadowRunnerPublicTypes = [
  CollectorAttestationSigner,
  DispatchIntentSigner,
  ShadowCaseInput,
  ShadowProfileTarget,
  ShadowRunInput,
  ShadowRunResult,
  ShadowWorkBudget,
];

const shadowRunnerPublicTypeCount:
  ShadowRunnerPublicTypes["length"] = 7;

describe("standalone public API", () => {
  it("exports the complete policy-lab surface from one package entry point", () => {
    expect(tasc).toMatchObject({
      parseInferenceSpec: expect.any(Function),
      parseMeasurementSet: expect.any(Function),
      generateCandidatePolicies: expect.any(Function),
      replayPolicy: expect.any(Function),
      nominatePolicy: expect.any(Function),
      confirmNomination: expect.any(Function),
      buildDevelopmentReport: expect.any(Function),
      buildConfirmationReport: expect.any(Function),
      proposeNextExperiment: expect.any(Function),
      parseExperimentProtocol: expect.any(Function),
      parseExperimentProtocolJson: expect.any(Function),
      parseTraceEnvelope: expect.any(Function),
      parseTraceEnvelopeJson: expect.any(Function),
      verifyTraceDispatchIntent: expect.any(Function),
      parseEvaluatorEvidence: expect.any(Function),
      parseEvaluatorEvidenceJson: expect.any(Function),
      verifyEvaluatorEvidence: expect.any(Function),
      parseAssessmentContext: expect.any(Function),
      fingerprintExecutionProfile: expect.any(Function),
      fingerprintProtocol: expect.any(Function),
      joinAssessmentEvidence: expect.any(Function),
      resolveGroupSplit: expect.any(Function),
      writeArtifactPacket: expect.any(Function),
      verifyArtifactPacket: expect.any(Function),
      readArtifactPacketIfPresent: expect.any(Function),
      writeArtifactPacketOrVerifyIdentical: expect.any(Function),
      createController: expect.any(Function),
      registerController: expect.any(Function),
      replayController: expect.any(Function),
      resumeController: expect.any(Function),
      proposeExperiment: expect.any(Function),
      parseExperimentBudget: expect.any(Function),
      parseExperimentHistory: expect.any(Function),
      parseExperimentProposalDecision: expect.any(Function),
      BoundedInputError: expect.any(Function),
      MAX_BOUNDED_INPUT_CHUNKS: expect.any(Number),
      parseBoundedJson: expect.any(Function),
      parseBoundedNdjson: expect.any(Function),
      readBoundedJson: expect.any(Function),
      readBoundedNdjson: expect.any(Function),
      PERSISTED_ERROR_VERSION: "tasc-persisted-error-v1",
      sanitizeErrorForPersistence: expect.any(Function),
      CONTROLLED_REFERENCE_REGISTRY_VERSION:
        "tasc-controlled-reference-registry-v1",
      MAX_CONTROLLED_REFERENCE_STORES: expect.any(Number),
      MAX_PAYLOAD_IDENTITY_BYTES: expect.any(Number),
      parseControlledReference: expect.any(Function),
      createControlledReferenceRegistry: expect.any(Function),
      authorizeControlledReference: expect.any(Function),
      resolveAuthorizedControlledReferenceRoot: expect.any(Function),
      createStudyPayloadIdentity: expect.any(Function),
      fingerprintRuntimeInvocationHttpLimits: expect.any(Function),
      normalizeRuntimeInvocationHttpLimits: expect.any(Function),
      SHADOW_RUN_PLAN_VERSION: "tasc-shadow-run-plan-v1",
      buildShadowRunPlan: expect.any(Function),
      parseShadowRunPlan: expect.any(Function),
      verifyTraceDispatchAuthorization: expect.any(Function),
    });
    expect(runtime).toMatchObject({
      RUNTIME_REGISTRY_VERSION: "tasc-runtime-registry-v1",
      listRuntimeProfiles: expect.any(Function),
      probeRuntimeCapability: expect.any(Function),
      describeRuntimeInvocation: expect.any(Function),
      fingerprintRuntimeInvocationHttpLimits: expect.any(Function),
      normalizeRuntimeInvocationHttpLimits: expect.any(Function),
      invokeRuntime: expect.any(Function),
      runShadowCollection: expect.any(Function),
    });
    for (const effectfulExport of [
      "parseCollectorTrustPolicy",
      "probeRuntimeCapability",
      "invokeRuntime",
      "runShadowCollection",
    ]) {
      expect(tasc).not.toHaveProperty(effectfulExport);
    }
    expect(runtime).not.toHaveProperty("runShadowCollectionForTesting");
    expect(runtime).not.toHaveProperty("verifyRuntimeCapabilityAuthorization");
    expect(runtime).not.toHaveProperty("consumePinnedCollectorRequest");
    expect(taskEightPublicTypeCount).toBe(11);
    expect(controllerPublicTypeCount).toBe(2);
    expect(artifactResumePublicTypeCount).toBe(3);
    expect(runtimeTransportPublicTypeCount).toBe(10);
    expect(runtimeCallPublicTypeCount).toBe(8);
    expect(shadowRunnerPublicTypeCount).toBe(7);
  });

  it("keeps deterministic identities independent of object insertion order", () => {
    expect(tasc.stableJson({ beta: 2, alpha: { delta: 4, gamma: 3 } }))
      .toBe(tasc.stableJson({ alpha: { gamma: 3, delta: 4 }, beta: 2 }));
    expect(tasc.sha256("tasc")).toHaveLength(64);
  });

  it("does not expose contract implementation helpers from the package entry point", () => {
    expect(tasc).not.toHaveProperty("deepFreezeContract");
    expect(tasc).not.toHaveProperty("domainSeparatedDigest");
    expect(tasc).not.toHaveProperty("contractSlugSchema");
    expect(tasc).not.toHaveProperty("contractTimestampSchema");
    expect(tasc).not.toHaveProperty("snapshotBoundedContractInput");
    expect(tasc).not.toHaveProperty("normalizeEvaluatorEvidence");
    expect(tasc).not.toHaveProperty("bootstrapGroupedWeightedMeanCI");
    expect(tasc).not.toHaveProperty("computePolicyMetrics");
    expect(tasc).not.toHaveProperty("ERROR_MESSAGES");
    expect(tasc).not.toHaveProperty("Scanner");
    expect(tasc).not.toHaveProperty("scanValue");
    expect(tasc).not.toHaveProperty("registryAuthorities");
    expect(tasc).not.toHaveProperty("referenceAuthorities");
    expect(tasc).not.toHaveProperty("SECRET_KEY_PROBE");
    expect(tasc).not.toHaveProperty("CONSTANT_SAFE_MESSAGES");
    expect(tasc).not.toHaveProperty("snapshotAllowlistedMetadata");
    expect(tasc).not.toHaveProperty("deploy");
    expect(tasc).not.toHaveProperty("promoteDeployment");
    expect(tasc).not.toHaveProperty("rollbackDeployment");
    expect(tasc).not.toHaveProperty("consumePinnedCollectorRequest");
    expect(tasc).not.toHaveProperty(
      "verifyRuntimeCapabilityAuthorization",
    );
  });
});
