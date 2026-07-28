import { isProxy } from "node:util/types";
import {
  domainSeparatedDigest,
} from "../evidence.js";
import {
  RUNTIME_CAPABILITIES,
  type CapabilityState,
  type DocumentedCapabilityExpectation,
  type EvidenceDimensionStatus,
  type ResolvedRuntimeProfile,
  type RuntimeCapability,
  type RuntimeCapabilityEvidenceMap,
  type RuntimeCapabilityExpectations,
  type RuntimeCapabilityProbeEvidence,
  type RuntimeDocumentationSource,
  type RuntimeHealthRoute,
  type RuntimeInferenceRoute,
  type RuntimeInferenceWireProtocol,
  type RuntimeInstanceIdentity,
  type RuntimeMetricsRoute,
  type RuntimeModelRoute,
  type RuntimeProfileId,
  type RuntimeResponseFraming,
  type RuntimeVersionRoute,
  type RuntimeWireProfile,
} from "./types.js";

export const RUNTIME_REGISTRY_VERSION = "tasc-runtime-registry-v1" as const;

const DIGEST_PATTERN = /^sha256:[a-f0-9]{64}$/;
const TIMESTAMP_PATTERN =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const MAX_IDENTITY_LENGTH = 512;
const PROFILE_FINGERPRINT_DOMAIN = "tasc/runtime-wire-profile/v1";

export const RUNTIME_PROFILE_IDS = Object.freeze([
  "llama.cpp",
  "lm-studio",
  "mlx-lm",
  "ollama",
  "sglang",
  "tensorrt-llm",
  "tgi",
  "vllm",
] as const satisfies readonly RuntimeProfileId[]);

interface CapabilitySeed {
  readonly state: CapabilityState;
  readonly note: string;
  readonly backend?: EvidenceDimensionStatus;
  readonly model?: EvidenceDimensionStatus;
  readonly configuration?: EvidenceDimensionStatus;
  readonly requirements?: readonly string[];
  readonly documentationUrl?: string;
}

function deepFreezeRuntimeValue<T>(value: T): T {
  if (value === null || typeof value !== "object" || Object.isFrozen(value)) {
    return value;
  }
  for (const descriptor of Object.values(
    Object.getOwnPropertyDescriptors(value),
  )) {
    if (Object.hasOwn(descriptor, "value")) {
      deepFreezeRuntimeValue(descriptor.value);
    }
  }
  return Object.freeze(value);
}

function documentation(
  ...sources: readonly RuntimeDocumentationSource[]
): readonly RuntimeDocumentationSource[] {
  return sources;
}

function inferenceRoute(
  path: string,
  wireProtocol: RuntimeInferenceWireProtocol,
  capability: RuntimeInferenceRoute["capability"],
  responseFraming: readonly RuntimeResponseFraming[] = ["json", "sse"],
): RuntimeInferenceRoute {
  return {
    method: "POST",
    path,
    wireProtocol,
    requestFraming: "json",
    responseFraming,
    capability,
    observationEffect: "inference-canary",
  };
}

function modelRoute(
  path: string,
  wireProtocol: RuntimeModelRoute["wireProtocol"],
): RuntimeModelRoute {
  return {
    method: "GET",
    path,
    wireProtocol,
    capability: "modelDiscovery",
    observationEffect: "non-mutating",
  };
}

function healthRoute(
  path: string,
  semantics: RuntimeHealthRoute["semantics"],
  observationEffect: RuntimeHealthRoute["observationEffect"] = "non-mutating",
): RuntimeHealthRoute {
  return {
    method: "GET",
    path,
    semantics,
    capability: semantics,
    observationEffect,
  };
}

function versionRoute(path: string): RuntimeVersionRoute {
  return {
    method: "GET",
    path,
    wireProtocol: "runtime-version",
    observationEffect: "non-mutating",
  };
}

function metricsRoute(
  path: string,
  format: RuntimeMetricsRoute["format"],
  availability: CapabilityState,
  observationEffect: RuntimeMetricsRoute["observationEffect"],
): RuntimeMetricsRoute {
  return {
    method: "GET",
    path,
    format,
    capability: format === "prometheus"
      ? "prometheusMetrics"
      : "jsonMetrics",
    availability,
    observationEffect,
  };
}

function createCapabilityExpectations(
  profileId: RuntimeProfileId,
  build: string,
  defaultDocumentationUrl: string,
  seeds: Partial<Record<RuntimeCapability, CapabilitySeed>>,
): RuntimeCapabilityExpectations {
  const entries = RUNTIME_CAPABILITIES.map((capability) => {
    const seed = seeds[capability] ?? {
      state: "unknown",
      note: "This build fixture does not establish this capability.",
    };
    const expectation: DocumentedCapabilityExpectation = {
      schemaVersion: "tasc-documented-capability-v1",
      source: "documentation",
      capability,
      state: seed.state,
      runtime: { profileId, build },
      backend: { status: seed.backend ?? "not-established" },
      model: { status: seed.model ?? "not-established" },
      configuration: {
        status: seed.configuration ?? "not-established",
        ...(seed.requirements === undefined
          ? {}
          : { requirements: [...seed.requirements] }),
      },
      documentationUrl: seed.documentationUrl ?? defaultDocumentationUrl,
      note: seed.note,
    };
    return [capability, expectation] as const;
  });
  return Object.fromEntries(entries) as RuntimeCapabilityExpectations;
}

function defineProfile(
  profile: Omit<RuntimeWireProfile, "schemaVersion" | "capabilities"> & {
    readonly capabilitySeeds: Partial<
      Record<RuntimeCapability, CapabilitySeed>
    >;
  },
): RuntimeWireProfile {
  const { capabilitySeeds, ...body } = profile;
  const result: RuntimeWireProfile = {
    schemaVersion: "tasc-runtime-wire-profile-v1",
    ...body,
    capabilities: createCapabilityExpectations(
      body.id,
      body.runtime.build,
      body.documentation[0]?.url
        ?? "https://github.com/rachittshah/tasc",
      capabilitySeeds,
    ),
  };
  return deepFreezeRuntimeValue(result);
}

const VLLM_DOCUMENTATION =
  "https://docs.vllm.ai/en/v0.26.0/serving/openai_compatible_server/";
const SGLANG_DOCUMENTATION =
  "https://github.com/sgl-project/sglang/blob/v0.5.16/python/sglang/srt/entrypoints/http_server.py";
const TRT_DOCUMENTATION =
  "https://github.com/NVIDIA/TensorRT-LLM/blob/v1.2.1/docs/source/commands/trtllm-serve/index.rst";
const LLAMA_DOCUMENTATION =
  "https://github.com/ggml-org/llama.cpp/blob/b10156/tools/server/README.md";
const OLLAMA_DOCUMENTATION =
  "https://github.com/ollama/ollama/blob/v0.32.5/docs/api.md";
const TGI_DOCUMENTATION =
  "https://huggingface.co/docs/text-generation-inference/en/reference/api_reference";
const LM_STUDIO_DOCUMENTATION = "https://lmstudio.ai/docs/developer/rest";
const MLX_DOCUMENTATION =
  "https://github.com/ml-explore/mlx-lm/blob/v0.31.3/mlx_lm/SERVER.md";

const profiles = [
  defineProfile({
    id: "llama.cpp",
    displayName: "llama.cpp server",
    runtime: { name: "llama.cpp", build: "b10156" },
    supportTier: "production-candidate",
    locality: "remote-or-local",
    preferredDialect: "openai",
    endpoints: {
      inference: {
        chatCompletions: inferenceRoute(
          "/v1/chat/completions",
          "openai-chat-completions",
          "chatCompletions",
        ),
        completions: inferenceRoute(
          "/v1/completions",
          "openai-completions",
          "completions",
        ),
        responses: inferenceRoute(
          "/v1/responses",
          "openai-responses",
          "responses",
        ),
      },
      models: {
        list: modelRoute("/v1/models", "openai-model-list"),
        info: modelRoute("/props", "runtime-model-info"),
      },
      health: {
        liveness: healthRoute("/health", "liveness"),
      },
      version: versionRoute("/props"),
      metrics: [
        metricsRoute("/metrics", "prometheus", "conditional", "non-mutating"),
      ],
    },
    documentation: documentation(
      {
        title: "llama.cpp server README at build b10156",
        url: LLAMA_DOCUMENTATION,
        kind: "official-documentation",
      },
      {
        title: "llama.cpp build b10156 release",
        url: "https://github.com/ggml-org/llama.cpp/releases/tag/b10156",
        kind: "official-release",
      },
    ),
    capabilitySeeds: {
      chatCompletions: {
        state: "conditional",
        model: "conditional",
        configuration: "conditional",
        note: "Requires a compatible chat template.",
      },
      completions: {
        state: "supported",
        note: "The pinned server documents the OpenAI completions route.",
      },
      responses: {
        state: "conditional",
        model: "conditional",
        note: "The pinned server documents the Responses route through its chat stack.",
      },
      streaming: {
        state: "supported",
        note: "The documented inference routes support streaming.",
      },
      finalUsage: {
        state: "conditional",
        configuration: "conditional",
        note: "Usage fields are documented but must be verified for the selected route.",
      },
      logprobs: {
        state: "conditional",
        model: "conditional",
        note: "Log probabilities depend on the selected route and model.",
      },
      structuredOutput: {
        state: "conditional",
        model: "conditional",
        configuration: "conditional",
        note: "Schema constraints depend on grammar and model configuration.",
      },
      tools: {
        state: "conditional",
        model: "conditional",
        configuration: "conditional",
        requirements: ["--jinja and a compatible tool-call template"],
        note: "Tool calling requires Jinja plus compatible model templates.",
      },
      modelDiscovery: {
        state: "supported",
        note: "The pinned server documents /v1/models and /props.",
      },
      liveness: {
        state: "supported",
        note: "The pinned server documents /health.",
      },
      readiness: {
        state: "unknown",
        note: "/health reports load state, but this fixture does not claim a distinct readiness contract.",
      },
      prometheusMetrics: {
        state: "conditional",
        configuration: "conditional",
        requirements: ["server started with --metrics"],
        note: "Prometheus metrics require the --metrics flag.",
      },
      jsonMetrics: {
        state: "unsupported",
        note: "The pinned server documents Prometheus rather than JSON metrics.",
      },
    },
  }),
  defineProfile({
    id: "lm-studio",
    displayName: "LM Studio",
    runtime: { name: "lm-studio", build: "0.4.1" },
    supportTier: "approved-internal",
    locality: "local-only",
    preferredDialect: "openai",
    endpoints: {
      inference: {
        chatCompletions: inferenceRoute(
          "/v1/chat/completions",
          "openai-chat-completions",
          "chatCompletions",
        ),
        responses: inferenceRoute(
          "/v1/responses",
          "openai-responses",
          "responses",
        ),
        nativeChat: inferenceRoute(
          "/api/v1/chat",
          "lm-studio-native-chat",
          "nativeChat",
        ),
      },
      models: {
        list: modelRoute("/v1/models", "openai-model-list"),
      },
      health: {},
      metrics: [],
    },
    documentation: documentation(
      {
        title: "LM Studio 0.4 REST API",
        url: LM_STUDIO_DOCUMENTATION,
        kind: "official-documentation",
      },
      {
        title: "LM Studio OpenAI Responses API",
        url: "https://lmstudio.ai/docs/developer/openai-compat/responses",
        kind: "official-documentation",
      },
    ),
    capabilitySeeds: {
      chatCompletions: {
        state: "conditional",
        model: "conditional",
        note: "OpenAI-shaped chat requires a loaded compatible model.",
      },
      responses: {
        state: "conditional",
        model: "conditional",
        configuration: "conditional",
        note: "Responses behavior depends on model and enabled integrations.",
      },
      nativeChat: {
        state: "conditional",
        model: "conditional",
        note: "The native v1 chat route requires a loaded compatible model.",
      },
      streaming: {
        state: "supported",
        note: "The native and compatible chat routes document streaming.",
      },
      finalUsage: {
        state: "supported",
        note: "The native v1 response documents token and timing statistics.",
      },
      structuredOutput: {
        state: "conditional",
        model: "conditional",
        note: "Structured output depends on the loaded model.",
      },
      tools: {
        state: "conditional",
        model: "conditional",
        configuration: "conditional",
        note: "Tool behavior depends on model templates and server settings.",
      },
      modelDiscovery: {
        state: "supported",
        note: "The native v1 model-list route is documented.",
      },
      liveness: {
        state: "unknown",
        note: "The pinned public API documentation does not establish a passive health path.",
      },
      readiness: {
        state: "unknown",
        note: "Model listing is not treated as a documented readiness contract.",
      },
      prometheusMetrics: {
        state: "unknown",
        note: "No runtime Prometheus path is established by this fixture.",
      },
      jsonMetrics: {
        state: "unknown",
        note: "Per-request native stats are not a service metrics endpoint.",
      },
    },
  }),
  defineProfile({
    id: "mlx-lm",
    displayName: "MLX-LM server",
    runtime: { name: "mlx-lm", build: "0.31.3" },
    supportTier: "experimental-local-only",
    locality: "local-only",
    preferredDialect: "openai",
    endpoints: {
      inference: {
        chatCompletions: inferenceRoute(
          "/v1/chat/completions",
          "openai-chat-completions",
          "chatCompletions",
        ),
        completions: inferenceRoute(
          "/v1/completions",
          "openai-completions",
          "completions",
        ),
      },
      models: {
        list: modelRoute("/v1/models", "openai-model-list"),
      },
      health: {
        liveness: healthRoute("/health", "liveness"),
      },
      metrics: [],
    },
    documentation: documentation(
      {
        title: "MLX-LM v0.31.3 HTTP server",
        url: MLX_DOCUMENTATION,
        kind: "official-documentation",
      },
      {
        title: "MLX-LM v0.31.3 release",
        url: "https://github.com/ml-explore/mlx-lm/releases/tag/v0.31.3",
        kind: "official-release",
      },
    ),
    capabilitySeeds: {
      chatCompletions: {
        state: "conditional",
        model: "conditional",
        note: "The experimental local server requires a compatible chat template.",
      },
      completions: {
        state: "conditional",
        model: "conditional",
        note: "Completion behavior depends on the selected model.",
      },
      streaming: {
        state: "supported",
        note: "The pinned server implements streaming responses.",
      },
      finalUsage: {
        state: "conditional",
        note: "Final usage must be verified for the selected route.",
      },
      logprobs: {
        state: "conditional",
        model: "conditional",
        note: "Log probabilities depend on route and model support.",
      },
      structuredOutput: {
        state: "conditional",
        model: "conditional",
        note: "Structured behavior is model dependent.",
      },
      tools: {
        state: "conditional",
        model: "conditional",
        note: "Tool parsing is model and template dependent.",
      },
      modelDiscovery: {
        state: "supported",
        note: "The pinned source implements /v1/models.",
      },
      liveness: {
        state: "supported",
        note: "The pinned source implements /health.",
      },
      readiness: {
        state: "unknown",
        note: "No separate readiness guarantee is established.",
      },
      prometheusMetrics: {
        state: "unsupported",
        note: "The pinned local server exposes no Prometheus route.",
      },
      jsonMetrics: {
        state: "unsupported",
        note: "The pinned local server exposes no service metrics route.",
      },
    },
  }),
  defineProfile({
    id: "ollama",
    displayName: "Ollama",
    runtime: { name: "ollama", build: "0.32.5" },
    supportTier: "production-candidate",
    locality: "local-only",
    preferredDialect: "ollama-native",
    endpoints: {
      inference: {
        chatCompletions: inferenceRoute(
          "/v1/chat/completions",
          "openai-chat-completions",
          "chatCompletions",
        ),
        completions: inferenceRoute(
          "/v1/completions",
          "openai-completions",
          "completions",
        ),
        responses: inferenceRoute(
          "/v1/responses",
          "openai-responses",
          "responses",
        ),
        nativeChat: inferenceRoute(
          "/api/chat",
          "ollama-native-chat",
          "nativeChat",
          ["json", "ndjson"],
        ),
        nativeGenerate: inferenceRoute(
          "/api/generate",
          "ollama-native-generate",
          "nativeGenerate",
          ["json", "ndjson"],
        ),
      },
      models: {
        list: modelRoute("/api/tags", "ollama-model-list"),
      },
      health: {
        liveness: healthRoute("/api/version", "liveness"),
      },
      version: versionRoute("/api/version"),
      metrics: [],
    },
    documentation: documentation(
      {
        title: "Ollama v0.32.5 API source",
        url: OLLAMA_DOCUMENTATION,
        kind: "official-documentation",
      },
      {
        title: "Ollama OpenAI compatibility",
        url: "https://docs.ollama.com/api/openai-compatibility",
        kind: "official-documentation",
      },
      {
        title: "Ollama v0.32.5 release",
        url: "https://github.com/ollama/ollama/releases/tag/v0.32.5",
        kind: "official-release",
      },
    ),
    capabilitySeeds: {
      chatCompletions: {
        state: "conditional",
        model: "conditional",
        note: "OpenAI chat behavior depends on the installed model.",
      },
      completions: {
        state: "conditional",
        model: "conditional",
        note: "OpenAI completions behavior depends on the installed model.",
      },
      responses: {
        state: "conditional",
        model: "conditional",
        note: "The non-stateful Responses route depends on the installed model.",
      },
      nativeChat: {
        state: "supported",
        note: "The native chat API is documented for this build.",
      },
      nativeGenerate: {
        state: "supported",
        note: "The native generate API is documented for this build.",
      },
      streaming: {
        state: "supported",
        note: "Native APIs stream NDJSON by default.",
      },
      finalUsage: {
        state: "supported",
        note: "Native terminal frames document durations and token counts.",
      },
      logprobs: {
        state: "conditional",
        model: "conditional",
        note: "Log probabilities depend on model support.",
      },
      structuredOutput: {
        state: "conditional",
        model: "conditional",
        note: "JSON schema behavior depends on model support.",
      },
      tools: {
        state: "conditional",
        model: "conditional",
        note: "Tool calling depends on model support.",
      },
      modelDiscovery: {
        state: "supported",
        note: "The native /api/tags model-list route is documented.",
      },
      liveness: {
        state: "conditional",
        note: "/api/version is a passive transport check, not a model readiness claim.",
      },
      readiness: {
        state: "unknown",
        note: "No passive model-readiness route is established by this fixture.",
      },
      prometheusMetrics: {
        state: "unsupported",
        note: "No Prometheus endpoint is documented.",
      },
      jsonMetrics: {
        state: "unsupported",
        note: "Per-request durations are not a service metrics endpoint.",
      },
    },
  }),
  defineProfile({
    id: "sglang",
    displayName: "SGLang",
    runtime: { name: "sglang", build: "0.5.16" },
    supportTier: "production-candidate",
    locality: "remote-or-local",
    preferredDialect: "openai",
    endpoints: {
      inference: {
        chatCompletions: inferenceRoute(
          "/v1/chat/completions",
          "openai-chat-completions",
          "chatCompletions",
        ),
        completions: inferenceRoute(
          "/v1/completions",
          "openai-completions",
          "completions",
        ),
        responses: inferenceRoute(
          "/v1/responses",
          "openai-responses",
          "responses",
        ),
      },
      models: {
        list: modelRoute("/v1/models", "openai-model-list"),
        info: modelRoute("/model_info", "runtime-model-info"),
      },
      health: {
        liveness: healthRoute("/health", "liveness"),
        readiness: healthRoute(
          "/health_generate",
          "readiness",
          "inference-canary",
        ),
      },
      version: versionRoute("/server_info"),
      metrics: [
        metricsRoute("/metrics", "prometheus", "conditional", "non-mutating"),
      ],
    },
    documentation: documentation(
      {
        title: "SGLang OpenAI APIs",
        url: SGLANG_DOCUMENTATION,
        kind: "official-documentation",
      },
      {
        title: "SGLang observability",
        url: "https://docs.sglang.ai/advanced_features/observability.html",
        kind: "official-documentation",
      },
      {
        title: "SGLang v0.5.16 release",
        url: "https://github.com/sgl-project/sglang/releases/tag/v0.5.16",
        kind: "official-release",
      },
    ),
    capabilitySeeds: {
      chatCompletions: {
        state: "conditional",
        model: "conditional",
        note: "Chat requires a compatible model and template.",
      },
      completions: {
        state: "supported",
        note: "The pinned server documents completions.",
      },
      responses: {
        state: "conditional",
        model: "conditional",
        configuration: "conditional",
        note: "The Responses app must initialize successfully for the selected model.",
      },
      streaming: {
        state: "supported",
        note: "The documented OpenAI endpoints support streaming.",
      },
      finalUsage: {
        state: "conditional",
        configuration: "conditional",
        note: "Terminal usage must be verified for the configured server.",
      },
      logprobs: {
        state: "conditional",
        model: "conditional",
        note: "Log probabilities depend on model/backend support.",
      },
      structuredOutput: {
        state: "conditional",
        model: "conditional",
        configuration: "conditional",
        note: "Structured output depends on backend and launch configuration.",
      },
      tools: {
        state: "conditional",
        model: "conditional",
        configuration: "conditional",
        note: "Tool parsing depends on model and parser configuration.",
      },
      modelDiscovery: {
        state: "supported",
        note: "The pinned server documents model-list and model-info routes.",
      },
      liveness: {
        state: "supported",
        note: "The pinned server documents /health.",
      },
      readiness: {
        state: "conditional",
        model: "conditional",
        note: "/health_generate is an inference canary, not a passive health read.",
      },
      prometheusMetrics: {
        state: "conditional",
        configuration: "conditional",
        requirements: ["server started with --enable-metrics"],
        note: "Prometheus metrics require --enable-metrics.",
      },
      jsonMetrics: {
        state: "unsupported",
        note: "The pinned profile uses Prometheus metrics.",
      },
    },
  }),
  defineProfile({
    id: "tensorrt-llm",
    displayName: "TensorRT-LLM",
    runtime: { name: "tensorrt-llm", build: "1.2.1" },
    supportTier: "production-candidate",
    locality: "remote-or-local",
    preferredDialect: "openai",
    endpoints: {
      inference: {
        chatCompletions: inferenceRoute(
          "/v1/chat/completions",
          "openai-chat-completions",
          "chatCompletions",
        ),
        completions: inferenceRoute(
          "/v1/completions",
          "openai-completions",
          "completions",
        ),
        responses: inferenceRoute(
          "/v1/responses",
          "openai-responses",
          "responses",
        ),
      },
      models: {
        list: modelRoute("/v1/models", "openai-model-list"),
      },
      health: {
        liveness: healthRoute("/health", "liveness"),
        readiness: healthRoute(
          "/health_generate",
          "readiness",
          "inference-canary",
        ),
      },
      version: versionRoute("/version"),
      metrics: [
        metricsRoute("/metrics", "json", "conditional", "consumptive"),
        metricsRoute(
          "/prometheus/metrics",
          "prometheus",
          "conditional",
          "non-mutating",
        ),
      ],
    },
    documentation: documentation(
      {
        title: "TensorRT-LLM trtllm-serve",
        url: TRT_DOCUMENTATION,
        kind: "official-documentation",
      },
      {
        title: "TensorRT-LLM v1.2.1 release",
        url: "https://github.com/NVIDIA/TensorRT-LLM/releases/tag/v1.2.1",
        kind: "official-release",
      },
    ),
    capabilitySeeds: {
      chatCompletions: {
        state: "conditional",
        model: "conditional",
        note: "Chat requires a compatible text model and template.",
      },
      completions: {
        state: "supported",
        note: "The pinned server documents the completions route.",
      },
      responses: {
        state: "conditional",
        model: "conditional",
        note: "The pinned server exposes Responses for compatible text models.",
      },
      streaming: {
        state: "supported",
        note: "The pinned server documents streaming inference.",
      },
      finalUsage: {
        state: "conditional",
        configuration: "conditional",
        note: "Final usage must be probed for the exact server configuration.",
      },
      logprobs: {
        state: "conditional",
        backend: "conditional",
        model: "conditional",
        note: "Log probabilities vary by backend and model.",
      },
      structuredOutput: {
        state: "conditional",
        backend: "conditional",
        model: "conditional",
        note: "Structured output varies by backend and model.",
      },
      tools: {
        state: "conditional",
        model: "conditional",
        configuration: "conditional",
        note: "Tool use varies by model and parser configuration.",
      },
      modelDiscovery: {
        state: "supported",
        note: "The pinned server documents /v1/models.",
      },
      liveness: {
        state: "supported",
        note: "The pinned server documents /health.",
      },
      readiness: {
        state: "conditional",
        model: "conditional",
        note: "/health_generate is an inference canary.",
      },
      jsonMetrics: {
        state: "conditional",
        backend: "conditional",
        configuration: "conditional",
        requirements: [
          "iteration statistics enabled for the selected backend",
          "a prior request may be required",
        ],
        note: "Reading /metrics removes queued iteration records.",
      },
      prometheusMetrics: {
        state: "conditional",
        configuration: "conditional",
        requirements: ["prototype return_perf_metrics=true"],
        note: "Prometheus metrics require the prototype performance-metrics option.",
      },
    },
  }),
  defineProfile({
    id: "tgi",
    displayName: "Text Generation Inference",
    runtime: { name: "tgi", build: "3.3.7" },
    supportTier: "legacy",
    locality: "remote-or-local",
    preferredDialect: "openai",
    endpoints: {
      inference: {
        chatCompletions: inferenceRoute(
          "/v1/chat/completions",
          "openai-chat-completions",
          "chatCompletions",
        ),
        nativeGenerate: inferenceRoute(
          "/generate",
          "tgi-native-generate",
          "nativeGenerate",
          ["json"],
        ),
      },
      models: {
        list: modelRoute("/v1/models", "openai-model-list"),
        info: modelRoute("/info", "runtime-model-info"),
      },
      health: {
        liveness: healthRoute("/health", "liveness"),
      },
      version: versionRoute("/info"),
      metrics: [
        metricsRoute("/metrics", "prometheus", "supported", "non-mutating"),
      ],
    },
    documentation: documentation(
      {
        title: "TGI HTTP API",
        url: TGI_DOCUMENTATION,
        kind: "official-documentation",
      },
      {
        title: "TGI metrics",
        url: "https://huggingface.co/docs/text-generation-inference/en/reference/metrics",
        kind: "official-documentation",
      },
      {
        title: "TGI v3.3.7 release",
        url: "https://github.com/huggingface/text-generation-inference/releases/tag/v3.3.7",
        kind: "official-release",
      },
    ),
    capabilitySeeds: {
      chatCompletions: {
        state: "conditional",
        model: "conditional",
        note: "The Messages API requires a compatible LLM chat template.",
      },
      nativeGenerate: {
        state: "supported",
        note: "The legacy native generate route is documented.",
      },
      streaming: {
        state: "supported",
        note: "The Messages and native generation APIs support streaming.",
      },
      finalUsage: {
        state: "supported",
        note: "The Messages API documents terminal usage.",
      },
      logprobs: {
        state: "conditional",
        model: "conditional",
        note: "Token details depend on the model and route.",
      },
      structuredOutput: {
        state: "conditional",
        model: "conditional",
        configuration: "conditional",
        note: "Guidance support varies by model and configuration.",
      },
      tools: {
        state: "conditional",
        model: "conditional",
        note: "Tool support requires a compatible chat template.",
      },
      responses: {
        state: "unsupported",
        note: "The archived 3.3.7 server does not document the Responses API.",
      },
      modelDiscovery: {
        state: "supported",
        note: "The pinned source exposes /v1/models and /info.",
      },
      liveness: {
        state: "supported",
        note: "The pinned source exposes /health.",
      },
      readiness: {
        state: "unknown",
        note: "No distinct passive readiness route is established.",
      },
      prometheusMetrics: {
        state: "supported",
        note: "The pinned server documents /metrics.",
      },
      jsonMetrics: {
        state: "unsupported",
        note: "The pinned profile uses Prometheus metrics.",
      },
    },
  }),
  defineProfile({
    id: "vllm",
    displayName: "vLLM",
    runtime: { name: "vllm", build: "0.26.0" },
    supportTier: "production-candidate",
    locality: "remote-or-local",
    preferredDialect: "openai",
    endpoints: {
      inference: {
        chatCompletions: inferenceRoute(
          "/v1/chat/completions",
          "openai-chat-completions",
          "chatCompletions",
        ),
        completions: inferenceRoute(
          "/v1/completions",
          "openai-completions",
          "completions",
        ),
        responses: inferenceRoute(
          "/v1/responses",
          "openai-responses",
          "responses",
        ),
      },
      models: {
        list: modelRoute("/v1/models", "openai-model-list"),
      },
      health: {
        liveness: healthRoute("/health", "liveness"),
      },
      version: versionRoute("/version"),
      metrics: [
        metricsRoute("/metrics", "prometheus", "supported", "non-mutating"),
      ],
    },
    documentation: documentation(
      {
        title: "vLLM OpenAI-compatible server",
        url: VLLM_DOCUMENTATION,
        kind: "official-documentation",
      },
      {
        title: "vLLM v0.26.0 release",
        url: "https://github.com/vllm-project/vllm/releases/tag/v0.26.0",
        kind: "official-release",
      },
    ),
    capabilitySeeds: {
      chatCompletions: {
        state: "conditional",
        model: "conditional",
        note: "Chat requires a compatible chat template.",
      },
      completions: {
        state: "supported",
        note: "The pinned server documents /v1/completions.",
      },
      responses: {
        state: "conditional",
        model: "conditional",
        note: "Responses is documented for compatible text models.",
      },
      streaming: {
        state: "supported",
        note: "The documented inference routes support streaming.",
      },
      finalUsage: {
        state: "conditional",
        configuration: "conditional",
        note: "Terminal usage must be probed for the selected route and configuration.",
      },
      logprobs: {
        state: "conditional",
        model: "conditional",
        configuration: "conditional",
        note: "Log probability limits and support depend on model and configuration.",
      },
      structuredOutput: {
        state: "conditional",
        model: "conditional",
        configuration: "conditional",
        note: "Structured output backend and model behavior must be pinned.",
      },
      tools: {
        state: "conditional",
        model: "conditional",
        configuration: "conditional",
        note: "Tool parsing requires model-specific configuration.",
      },
      cancellation: {
        state: "unknown",
        note: "A live abort probe is required for the exact instance.",
      },
      modelDiscovery: {
        state: "supported",
        note: "The pinned server documents /v1/models.",
      },
      liveness: {
        state: "supported",
        note: "The pinned server documents /health.",
      },
      readiness: {
        state: "unknown",
        note: "No separate passive readiness contract is established.",
      },
      prometheusMetrics: {
        state: "supported",
        note: "The pinned server documents /metrics.",
      },
      jsonMetrics: {
        state: "unsupported",
        note: "The pinned profile uses Prometheus metrics.",
      },
    },
  }),
] as const;

const frozenProfiles = deepFreezeRuntimeValue(
  [...profiles].sort((left, right) => {
    if (left.id < right.id) return -1;
    if (left.id > right.id) return 1;
    return 0;
  }),
);

const profileById = new Map<RuntimeProfileId, RuntimeWireProfile>(
  frozenProfiles.map((profile) => [profile.id, profile]),
);
const authenticProfiles = new WeakSet<object>(frozenProfiles);

export function listRuntimeProfiles(): readonly RuntimeWireProfile[] {
  return frozenProfiles;
}

export function getRuntimeProfile(profileId: string): RuntimeWireProfile {
  const profile = profileById.get(profileId as RuntimeProfileId);
  if (profile === undefined) {
    throw new Error("unknown runtime profile");
  }
  return profile;
}

export function fingerprintRuntimeWireProfile(
  profile: RuntimeWireProfile,
): string {
  if (
    profile === null
    || typeof profile !== "object"
    || !authenticProfiles.has(profile)
  ) {
    throw new Error("an authentic registered runtime wire profile is required");
  }
  return domainSeparatedDigest(PROFILE_FINGERPRINT_DOMAIN, profile);
}

function snapshotRecord(
  input: unknown,
  label: string,
  allowedKeys: ReadonlySet<string>,
): Record<string, unknown> {
  if (input === null || typeof input !== "object") {
    throw new Error(`${label} must be a plain object`);
  }
  if (isProxy(input)) {
    throw new Error(`${label} cannot be a proxy`);
  }
  const prototype = Reflect.getPrototypeOf(input);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new Error(`${label} must be a plain object`);
  }
  const ownKeys = Reflect.ownKeys(input);
  if (ownKeys.length > allowedKeys.size) {
    throw new Error(`${label} contains an unknown field`);
  }
  const snapshot: Record<string, unknown> = Object.create(null);
  for (const key of ownKeys) {
    if (typeof key !== "string") {
      throw new Error(`${label} cannot contain symbol fields`);
    }
    if (!allowedKeys.has(key)) {
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
    snapshot[key] = descriptor.value;
  }
  return snapshot;
}

function requiredBoundedString(
  value: unknown,
  label: string,
  maximum = MAX_IDENTITY_LENGTH,
): string {
  if (
    typeof value !== "string"
    || value.length < 1
    || value.length > maximum
    || value.trim() !== value
  ) {
    throw new Error(`${label} must be a bounded non-empty string`);
  }
  return value;
}

function requiredDigest(value: unknown, label: string): string {
  if (typeof value !== "string" || !DIGEST_PATTERN.test(value)) {
    throw new Error(`${label} must be a canonical sha256: digest`);
  }
  return value;
}

function parseRuntimeBuildIdentity(input: unknown): {
  readonly profileId: RuntimeProfileId;
  readonly build: string;
} {
  const snapshot = snapshotRecord(
    input,
    "runtime build identity",
    new Set(["profileId", "build"]),
  );
  const profileId = requiredBoundedString(snapshot.profileId, "runtime profile id");
  const profile = getRuntimeProfile(profileId);
  return deepFreezeRuntimeValue({
    profileId: profile.id,
    build: requiredBoundedString(snapshot.build, "runtime build"),
  });
}

function parseBackendIdentity(input: unknown): {
  readonly name: string;
  readonly build: string;
} {
  const snapshot = snapshotRecord(
    input,
    "runtime backend identity",
    new Set(["name", "build"]),
  );
  return deepFreezeRuntimeValue({
    name: requiredBoundedString(snapshot.name, "backend name"),
    build: requiredBoundedString(snapshot.build, "backend build"),
  });
}

function parseModelIdentity(input: unknown): {
  readonly id: string;
  readonly revision: string;
} {
  const snapshot = snapshotRecord(
    input,
    "runtime model identity",
    new Set(["id", "revision"]),
  );
  return deepFreezeRuntimeValue({
    id: requiredBoundedString(snapshot.id, "model id"),
    revision: requiredBoundedString(snapshot.revision, "model revision"),
  });
}

const INSTANCE_KEYS = new Set([
  "endpointDescriptorDigest",
  "runtime",
  "backend",
  "model",
  "configurationDigest",
]);

export function parseRuntimeInstanceIdentity(
  input: unknown,
): RuntimeInstanceIdentity {
  const snapshot = snapshotRecord(input, "runtime instance", INSTANCE_KEYS);
  return deepFreezeRuntimeValue({
    endpointDescriptorDigest: requiredDigest(
      snapshot.endpointDescriptorDigest,
      "endpoint descriptor digest",
    ),
    runtime: parseRuntimeBuildIdentity(snapshot.runtime),
    backend: parseBackendIdentity(snapshot.backend),
    model: parseModelIdentity(snapshot.model),
    configurationDigest: requiredDigest(
      snapshot.configurationDigest,
      "runtime configuration digest",
    ),
  });
}

const PROBE_KEYS = new Set([
  "schemaVersion",
  "source",
  "capability",
  "state",
  "probedAt",
  ...INSTANCE_KEYS,
]);

export function parseRuntimeCapabilityProbeEvidence(
  input: unknown,
): RuntimeCapabilityProbeEvidence {
  const snapshot = snapshotRecord(
    input,
    "runtime capability probe evidence",
    PROBE_KEYS,
  );
  if (snapshot.schemaVersion !== "tasc-runtime-capability-probe-v1") {
    throw new Error(
      'runtime capability probe schemaVersion must be "tasc-runtime-capability-probe-v1"',
    );
  }
  if (snapshot.source !== "live-probe") {
    throw new Error('runtime capability probe source must be "live-probe"');
  }
  if (
    typeof snapshot.capability !== "string"
    || !RUNTIME_CAPABILITIES.includes(
      snapshot.capability as RuntimeCapability,
    )
  ) {
    throw new Error("runtime capability probe has an unknown capability");
  }
  if (
    snapshot.state !== "supported"
    && snapshot.state !== "conditional"
    && snapshot.state !== "unsupported"
    && snapshot.state !== "unknown"
  ) {
    throw new Error("runtime capability probe has an invalid state");
  }
  const probedAt = requiredBoundedString(snapshot.probedAt, "probe timestamp");
  const milliseconds = Date.parse(probedAt);
  if (
    !TIMESTAMP_PATTERN.test(probedAt)
    || !Number.isFinite(milliseconds)
    || new Date(milliseconds).toISOString() !== probedAt
  ) {
    throw new Error("probe timestamp must be exact UTC RFC 3339 milliseconds");
  }
  const instance = parseRuntimeInstanceIdentity({
    endpointDescriptorDigest: snapshot.endpointDescriptorDigest,
    runtime: snapshot.runtime,
    backend: snapshot.backend,
    model: snapshot.model,
    configurationDigest: snapshot.configurationDigest,
  });
  return deepFreezeRuntimeValue({
    schemaVersion: "tasc-runtime-capability-probe-v1",
    source: "live-probe",
    capability: snapshot.capability as RuntimeCapability,
    state: snapshot.state,
    probedAt,
    ...instance,
  });
}

function sameRuntimeInstance(
  left: RuntimeInstanceIdentity,
  right: RuntimeInstanceIdentity,
): boolean {
  return left.endpointDescriptorDigest === right.endpointDescriptorDigest
    && left.runtime.profileId === right.runtime.profileId
    && left.runtime.build === right.runtime.build
    && left.backend.name === right.backend.name
    && left.backend.build === right.backend.build
    && left.model.id === right.model.id
    && left.model.revision === right.model.revision
    && left.configurationDigest === right.configurationDigest;
}

function snapshotProbeArray(
  inputs: readonly unknown[],
): readonly unknown[] {
  if (isProxy(inputs)) {
    throw new Error("runtime probe evidence array cannot be a proxy");
  }
  if (!Array.isArray(inputs)) {
    throw new Error("runtime probe evidence must be an array");
  }
  if (Reflect.getPrototypeOf(inputs) !== Array.prototype) {
    throw new Error("runtime probe evidence must be a plain array");
  }
  const descriptors = Object.getOwnPropertyDescriptors(inputs);
  const length = Reflect.getOwnPropertyDescriptor(inputs, "length")?.value;
  if (
    typeof length !== "number"
    || !Number.isSafeInteger(length)
    || length < 0
    || length > RUNTIME_CAPABILITIES.length
  ) {
    throw new Error("runtime probe evidence exceeds the capability limit");
  }
  const allowed = new Set(["length"]);
  const snapshot: unknown[] = [];
  for (let index = 0; index < length; index += 1) {
    const key = String(index);
    allowed.add(key);
    const descriptor = descriptors[key];
    if (
      descriptor === undefined
      || !descriptor.enumerable
      || !Object.hasOwn(descriptor, "value")
    ) {
      throw new Error("runtime probe evidence array must be dense data");
    }
    snapshot.push(descriptor.value);
  }
  if (Reflect.ownKeys(descriptors).some((key) =>
    typeof key !== "string" || !allowed.has(key)
  )) {
    throw new Error("runtime probe evidence array contains an extra field");
  }
  return snapshot;
}

function createUnestablishedCapabilities(
  runtime: RuntimeInstanceIdentity["runtime"],
): RuntimeCapabilityEvidenceMap {
  return deepFreezeRuntimeValue(Object.fromEntries(
    RUNTIME_CAPABILITIES.map((capability) => [
      capability,
      {
        schemaVersion: "tasc-unestablished-capability-v1",
        source: "unestablished",
        capability,
        state: "unknown",
        runtime,
        backend: { status: "not-established" },
        model: { status: "not-established" },
        configuration: { status: "not-established" },
        note:
          "This runtime build does not match the build-pinned documentation fixture; an exact-instance probe is required.",
      },
    ]),
  )) as RuntimeCapabilityEvidenceMap;
}

export function resolveRuntimeCapabilities(
  instanceInput: RuntimeInstanceIdentity,
  probeInputs: readonly unknown[],
): ResolvedRuntimeProfile {
  const instance = parseRuntimeInstanceIdentity(instanceInput);
  const profile = getRuntimeProfile(instance.runtime.profileId);
  const buildMatches = instance.runtime.build === profile.runtime.build;
  const baseCapabilities = buildMatches
    ? profile.capabilities
    : createUnestablishedCapabilities(instance.runtime);
  const capabilities: Record<
    RuntimeCapability,
    RuntimeCapabilityEvidenceMap[RuntimeCapability]
  > = { ...baseCapabilities };
  const seen = new Set<RuntimeCapability>();
  for (const input of snapshotProbeArray(probeInputs)) {
    const probe = parseRuntimeCapabilityProbeEvidence(input);
    if (probe.runtime.profileId !== profile.id) {
      throw new Error("runtime capability probe does not match runtime profile");
    }
    if (!sameRuntimeInstance(instance, probe)) {
      throw new Error("runtime capability probe does not match runtime instance");
    }
    if (seen.has(probe.capability)) {
      throw new Error("duplicate probe evidence for runtime capability");
    }
    seen.add(probe.capability);
    capabilities[probe.capability] = probe;
  }

  return deepFreezeRuntimeValue({
    profile,
    instance,
    expectationBasis: buildMatches
      ? "build-pinned-documentation"
      : "unestablished-build",
    capabilities,
  });
}
