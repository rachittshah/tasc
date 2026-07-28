import { describe, expect, it } from "vitest";
import * as tasc from "../src/index.js";
import type {
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
  CollectorTrustPolicy,
  BoundedRuntimeHttpResult,
  BoundedSseLimits,
  BoundedNdjsonStreamLimits,
  PrometheusParseResult,
  KeyedPayloadIdentity,
  PinnedCollectorRequest,
  PersistedError,
  PersistedErrorCategory,
  RuntimeHttpLimits,
  RuntimeWireDispatchState,
  RuntimeWireErrorCode,
} from "../src/index.js";

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
];

const runtimeTransportPublicTypeCount:
  RuntimeTransportPublicTypes["length"] = 9;

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
      COLLECTOR_TRUST_POLICY_VERSION: "tasc-collector-trust-policy-v1",
      parseCollectorTrustPolicy: expect.any(Function),
      fingerprintCollectorTrustPolicy: expect.any(Function),
      narrowCollectorTrustPolicy: expect.any(Function),
      authorizeCollectorRequest: expect.any(Function),
      pinAuthorizedCollectorRequest: expect.any(Function),
      withBoundedHttpResponse: expect.any(Function),
      RuntimeWireError: expect.any(Function),
      RuntimeCodecError: expect.any(Function),
      parseBoundedSse: expect.any(Function),
      parseBoundedJsonSse: expect.any(Function),
      parseBoundedNdjsonStream: expect.any(Function),
      parsePrometheusText: expect.any(Function),
    });
    expect(taskEightPublicTypeCount).toBe(11);
    expect(controllerPublicTypeCount).toBe(2);
    expect(runtimeTransportPublicTypeCount).toBe(9);
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
  });
});
