export const RUNTIME_CAPABILITIES = [
  "chatCompletions",
  "completions",
  "responses",
  "nativeChat",
  "nativeGenerate",
  "streaming",
  "finalUsage",
  "logprobs",
  "structuredOutput",
  "tools",
  "cancellation",
  "modelDiscovery",
  "liveness",
  "readiness",
  "prometheusMetrics",
  "jsonMetrics",
] as const;

export type RuntimeCapability = typeof RUNTIME_CAPABILITIES[number];
export type CapabilityState =
  | "supported"
  | "conditional"
  | "unsupported"
  | "unknown";

export type RuntimeProfileId =
  | "llama.cpp"
  | "lm-studio"
  | "mlx-lm"
  | "ollama"
  | "sglang"
  | "tensorrt-llm"
  | "tgi"
  | "vllm";

export type RuntimeSupportTier =
  | "production-candidate"
  | "legacy"
  | "approved-internal"
  | "experimental-local-only";

export type RuntimeLocality = "remote-or-local" | "local-only";

export interface RuntimeBuildIdentity {
  readonly profileId: RuntimeProfileId;
  readonly build: string;
}

export type EvidenceDimensionStatus =
  | "established"
  | "conditional"
  | "not-established";

export interface StaticBackendEvidence {
  readonly status: EvidenceDimensionStatus;
  readonly name?: string;
  readonly build?: string;
}

export interface StaticModelEvidence {
  readonly status: EvidenceDimensionStatus;
  readonly id?: string;
  readonly revision?: string;
}

export interface StaticConfigurationEvidence {
  readonly status: EvidenceDimensionStatus;
  readonly digest?: string;
  readonly requirements?: readonly string[];
}

export interface DocumentedCapabilityExpectation {
  readonly schemaVersion: "tasc-documented-capability-v1";
  readonly source: "documentation";
  readonly capability: RuntimeCapability;
  readonly state: CapabilityState;
  readonly runtime: RuntimeBuildIdentity;
  readonly backend: StaticBackendEvidence;
  readonly model: StaticModelEvidence;
  readonly configuration: StaticConfigurationEvidence;
  readonly documentationUrl: string;
  readonly note: string;
}

export interface RuntimeCapabilityProbeEvidence {
  readonly schemaVersion: "tasc-runtime-capability-probe-v1";
  readonly source: "live-probe";
  readonly capability: RuntimeCapability;
  readonly state: CapabilityState;
  readonly probedAt: string;
  /**
   * The instance fields below are the configured scope of the observation,
   * not an assertion that every identity dimension was provider-reported.
   * This record makes the evidence basis explicit and keeps unobserved values
   * null instead of laundering caller configuration into live proof.
   */
  readonly identityVerification: RuntimeCapabilityIdentityVerification;
  readonly endpointDescriptorDigest: string;
  readonly runtime: RuntimeBuildIdentity;
  readonly backend: {
    readonly name: string;
    readonly build: string;
  };
  readonly model: {
    readonly id: string;
    readonly revision: string;
  };
  readonly configurationDigest: string;
}

export type RuntimeIdentityVerificationBasis =
  | "operator-policy"
  | "provider-reported"
  | "unverified";

export interface RuntimeCapabilityIdentityVerification {
  readonly endpointBinding: "operator-policy";
  readonly runtimeBuild: {
    readonly basis: "operator-policy" | "provider-reported";
    readonly observed: string | null;
  };
  readonly backend: {
    readonly basis: "unverified" | "provider-reported";
    readonly observed: {
      readonly name: string;
      readonly build: string;
    } | null;
  };
  readonly modelId: {
    readonly basis: "unverified" | "provider-reported";
    readonly observed: string | null;
  };
  readonly modelRevision: {
    readonly basis: "unverified" | "provider-reported";
    readonly observed: string | null;
  };
  readonly configurationDigest: {
    readonly basis: "unverified" | "provider-reported";
    readonly observed: string | null;
  };
}

export interface UnestablishedCapabilityExpectation {
  readonly schemaVersion: "tasc-unestablished-capability-v1";
  readonly source: "unestablished";
  readonly capability: RuntimeCapability;
  readonly state: "unknown";
  readonly runtime: RuntimeBuildIdentity;
  readonly backend: {
    readonly status: "not-established";
  };
  readonly model: {
    readonly status: "not-established";
  };
  readonly configuration: {
    readonly status: "not-established";
  };
  readonly note: string;
}

export interface RuntimeInstanceIdentity {
  readonly endpointDescriptorDigest: string;
  readonly runtime: RuntimeBuildIdentity;
  readonly backend: {
    readonly name: string;
    readonly build: string;
  };
  readonly model: {
    readonly id: string;
    readonly revision: string;
  };
  readonly configurationDigest: string;
}

export type RuntimeCapabilityEvidence =
  | DocumentedCapabilityExpectation
  | UnestablishedCapabilityExpectation
  | RuntimeCapabilityProbeEvidence;

export type RuntimeCapabilityExpectations = Readonly<
  Record<RuntimeCapability, DocumentedCapabilityExpectation>
>;

export type RuntimeCapabilityEvidenceMap = Readonly<
  Record<RuntimeCapability, RuntimeCapabilityEvidence>
>;

export type RuntimeResponseFraming = "json" | "sse" | "ndjson";

export type RuntimeInferenceWireProtocol =
  | "openai-chat-completions"
  | "openai-completions"
  | "openai-responses"
  | "ollama-native-chat"
  | "ollama-native-generate"
  | "tgi-native-generate"
  | "lm-studio-native-chat";

export interface RuntimeInferenceRoute {
  readonly method: "POST";
  readonly path: string;
  readonly wireProtocol: RuntimeInferenceWireProtocol;
  readonly requestFraming: "json";
  readonly responseFraming: readonly RuntimeResponseFraming[];
  readonly capability:
    | "chatCompletions"
    | "completions"
    | "responses"
    | "nativeChat"
    | "nativeGenerate";
  readonly observationEffect: "inference-canary";
}

export interface RuntimeModelRoute {
  readonly method: "GET";
  readonly path: string;
  readonly wireProtocol:
    | "openai-model-list"
    | "ollama-model-list"
    | "lm-studio-model-list"
    | "runtime-model-info";
  readonly capability: "modelDiscovery";
  readonly observationEffect: "non-mutating";
}

export interface RuntimeHealthRoute {
  readonly method: "GET";
  readonly path: string;
  readonly semantics: "liveness" | "readiness";
  readonly capability: "liveness" | "readiness";
  readonly observationEffect: "non-mutating" | "inference-canary";
}

export interface RuntimeVersionRoute {
  readonly method: "GET";
  readonly path: string;
  readonly wireProtocol: "runtime-version";
  readonly observationEffect: "non-mutating";
}

export interface RuntimeMetricsRoute {
  readonly method: "GET";
  readonly path: string;
  readonly format: "prometheus" | "json";
  readonly capability: "prometheusMetrics" | "jsonMetrics";
  readonly availability: CapabilityState;
  readonly observationEffect: "non-mutating" | "consumptive";
}

export interface RuntimeWireEndpoints {
  readonly inference: {
    readonly chatCompletions?: RuntimeInferenceRoute;
    readonly completions?: RuntimeInferenceRoute;
    readonly responses?: RuntimeInferenceRoute;
    readonly nativeChat?: RuntimeInferenceRoute;
    readonly nativeGenerate?: RuntimeInferenceRoute;
  };
  readonly models: {
    readonly list?: RuntimeModelRoute;
    readonly info?: RuntimeModelRoute;
  };
  readonly health: {
    readonly liveness?: RuntimeHealthRoute;
    readonly readiness?: RuntimeHealthRoute;
  };
  readonly version?: RuntimeVersionRoute;
  readonly metrics: readonly RuntimeMetricsRoute[];
}

export interface RuntimeDocumentationSource {
  readonly title: string;
  readonly url: string;
  readonly kind: "official-documentation" | "official-release";
}

export interface RuntimeWireProfile {
  readonly schemaVersion: "tasc-runtime-wire-profile-v1";
  readonly id: RuntimeProfileId;
  readonly displayName: string;
  readonly runtime: {
    readonly name: RuntimeProfileId;
    readonly build: string;
  };
  readonly supportTier: RuntimeSupportTier;
  readonly locality: RuntimeLocality;
  readonly preferredDialect:
    | "openai"
    | "ollama-native"
    | "lm-studio-native-v1";
  readonly endpoints: RuntimeWireEndpoints;
  readonly capabilities: RuntimeCapabilityExpectations;
  readonly documentation: readonly RuntimeDocumentationSource[];
}

export interface ResolvedRuntimeProfile {
  readonly profile: RuntimeWireProfile;
  readonly instance: RuntimeInstanceIdentity;
  readonly expectationBasis:
    | "build-pinned-documentation"
    | "unestablished-build";
  readonly capabilities: RuntimeCapabilityEvidenceMap;
}

export type OrchestrationKind = "ray-serve" | "skypilot" | "skyserve";

export interface EndpointDescriptor {
  readonly schemaVersion: "tasc-endpoint-descriptor-v1";
  readonly origin: string;
  readonly basePath: string;
  readonly runtime: RuntimeBuildIdentity;
  readonly orchestration:
    | {
      readonly kind: "ray-serve";
      readonly build: string;
      readonly configurationDigest: string;
      readonly locator: {
        readonly applicationName: string;
        readonly deploymentName: string;
      };
      readonly authenticationReference?: string;
    }
    | {
      readonly kind: "skypilot" | "skyserve";
      readonly build: string;
      readonly configurationDigest: string;
      readonly locator: {
        readonly serviceName: string;
      };
      readonly authenticationReference?: string;
    };
  readonly authority: {
    readonly deployment: "none";
    readonly network: "unverified";
  };
}

export interface RayServeEndpointDescriptorInput {
  readonly origin: string;
  readonly routePrefix: string;
  readonly runtimeProfileId: RuntimeProfileId;
  readonly runtimeBuild: string;
  readonly rayBuild: string;
  readonly configurationDigest: string;
  readonly applicationName: string;
  readonly deploymentName: string;
  readonly authenticationReference?: string;
}

export interface SkyPilotEndpointDescriptorInput {
  readonly origin: string;
  readonly routePrefix: string;
  readonly runtimeProfileId: RuntimeProfileId;
  readonly runtimeBuild: string;
  readonly skyPilotBuild: string;
  readonly configurationDigest: string;
  readonly mode: "skypilot" | "skyserve";
  readonly serviceName: string;
  readonly authenticationReference?: string;
}
