# Runtime and orchestration support

TASC is a trace-aware control plane, not a generic model SDK. P0 owns protocols,
evaluator evidence, offline and sealed-window assessment, policy replay, and
controller state. P1 performs bounded inference observations only when an
operator explicitly authorizes an exact endpoint, runtime build, route, effect,
deadline, and secret reference.

This document describes the collector included in the current source tree. It
does not claim that two servers with OpenAI-shaped endpoints behave identically,
or that a documented capability works for every model, backend, quantization,
chat template, or launch configuration.

## Reading the matrix

Each registered runtime has a build-pinned profile. Static documentation records
one of four states:

- `supported`: the pinned upstream build documents the capability;
- `conditional`: model, backend, template, or launch configuration matters;
- `unsupported`: the pinned build does not expose that contract;
- `unknown`: TASC has no adequate basis for a claim.

That state is only an expectation. A live probe is separate evidence scoped to
the configured endpoint, runtime build, backend, model revision, and
configuration digest. Operator configuration is never relabeled as
provider-reported identity.

| Runtime profile | Pinned profile | Tier / locality | Implemented inference wire contracts | Observation routes |
| --- | --- | --- | --- | --- |
| vLLM | `0.26.0` | production candidate; remote or local | OpenAI Chat Completions, Completions, and Responses; JSON/SSE | `/v1/models`, `/health`, `/version`, Prometheus `/metrics` |
| SGLang | `0.5.16` | production candidate; remote or local | OpenAI Chat Completions, Completions, and Responses; JSON/SSE | `/v1/models`, `/model_info`; conservative inference-canary `/health` because launch configuration can make it generative/billable; inference-canary `/health_generate`; `/server_info`; optional Prometheus `/metrics` |
| TensorRT-LLM | `1.2.1` | production candidate; remote or local | OpenAI Chat Completions, Completions, and Responses; JSON/SSE | `/v1/models`, passive `/health`, inference-canary `/health_generate`, `/version`, consumptive JSON `/metrics`, optional Prometheus `/prometheus/metrics` |
| llama.cpp | build `b10156` | production candidate; remote or local | OpenAI Chat Completions, Completions, and Responses; JSON/SSE | `/v1/models`, `/props`, `/health`, optional Prometheus `/metrics` |
| Ollama | `0.32.5` | production candidate; local only | OpenAI-compatible Chat, Completions, and Responses plus native Chat/Generate; JSON, SSE, and native NDJSON | `/api/tags`, `/api/version`; no service-metrics route claimed |
| Text Generation Inference | `3.3.7` | legacy; remote or local | OpenAI-compatible Chat and native `/generate`; JSON/SSE | `/v1/models`, `/info`, `/health`, Prometheus `/metrics` |
| LM Studio | `0.4.1` | approved internal; local only | OpenAI-compatible Chat and Responses plus native `/api/v1/chat`; JSON/SSE | `/v1/models`; no passive health or service-metrics route claimed |
| MLX-LM | `0.31.3` | experimental, local only | OpenAI-compatible Chat and Completions; JSON/SSE | `/v1/models`, `/health`; no service-metrics route claimed |

The source of truth for route and capability details is
[`src/runtime/profiles.ts`](../src/runtime/profiles.ts). Upstream references:

- [vLLM OpenAI-compatible server](https://docs.vllm.ai/en/v0.26.0/serving/openai_compatible_server/)
- [SGLang server entrypoint at v0.5.16](https://github.com/sgl-project/sglang/blob/v0.5.16/python/sglang/srt/entrypoints/http_server.py)
  and [observability](https://docs.sglang.ai/advanced_features/observability.html)
- [TensorRT-LLM server routes at v1.2.1](https://github.com/NVIDIA/TensorRT-LLM/blob/v1.2.1/tensorrt_llm/serve/openai_server.py)
  and [`trtllm-serve` documentation](https://github.com/NVIDIA/TensorRT-LLM/blob/v1.2.1/docs/source/commands/trtllm-serve/trtllm-serve.rst)
- [llama.cpp server at build b10156](https://github.com/ggml-org/llama.cpp/blob/b10156/tools/server/README.md)
- [Ollama routes at v0.32.5](https://github.com/ollama/ollama/blob/v0.32.5/server/routes.go),
  [native API](https://github.com/ollama/ollama/blob/v0.32.5/docs/api.md),
  [tagged OpenAI compatibility](https://github.com/ollama/ollama/blob/v0.32.5/docs/api/openai-compatibility.mdx),
  and the [readable current guide](https://docs.ollama.com/api/openai-compatibility)
- [Text Generation Inference routes at v3.3.7](https://github.com/huggingface/text-generation-inference/blob/v3.3.7/router/src/server.rs),
  plus the readable [HTTP API](https://huggingface.co/docs/text-generation-inference/en/reference/api_reference)
  and [metrics](https://huggingface.co/docs/text-generation-inference/en/reference/metrics)
- [LM Studio REST API](https://lmstudio.ai/docs/developer/rest)
  [Responses compatibility](https://lmstudio.ai/docs/developer/openai-compat/responses),
  and the [0.4.1 API changelog](https://lmstudio.ai/docs/developer/api-changelog)
- [MLX-LM server source at v0.31.3](https://github.com/ml-explore/mlx-lm/blob/v0.31.3/mlx_lm/server.py)
  and [server guide](https://github.com/ml-explore/mlx-lm/blob/v0.31.3/mlx_lm/SERVER.md)

## What a live call records

The collector prepares an invocation before opening a socket. Preparation
validates the exact runtime route, endpoint binding, generation bounds, trust
policy, payload identity key, work deadline, and optional authorization
reference. Prepared invocation authority is process-local and one-shot; copying
or serializing its visible metadata does not preserve permission to send.

The durable result intentionally excludes prompt and output text. It retains:

- request and response HMAC identities;
- endpoint-binding and execution-profile identities;
- requested model identity and selected runtime route;
- dispatch state: `not_sent`, `sent_unknown`, or `completed`;
- bounded wire timing and provider-reported timing;
- provider-reported token usage, with unavailable fields left `null`;
- normalized completion/incompletion status; and
- an allowlisted error category and status, never a reflected response body.

`RuntimeInvocationPersistence` does not claim request/response byte or frame
counts. The internal durable `tasc-shadow-send-lease-v1` records the prepared
request byte count and authorized response-byte limit for shadow work
accounting; neither value is an observed response byte/frame count or a field
of the accepted `TraceEnvelope`.

Accepted shadow traces additionally retain the P0 run-plan digest, endpoint
alias/binding, route, capability-receipt digests, and a distinct collector
attestation over the complete final observation.

Missing terminal usage, truncated frames, cancellation after dispatch, protocol
violations, and ambiguous transport failures are not promoted to successful
traces.

## Probes and effects

TASC separates passive observations from calls that can consume capacity:

| Effect | Examples | Required operator treatment |
| --- | --- | --- |
| `non-mutating` | liveness, model list, passive Prometheus scrape | Exact route must still be authorized. |
| `consumptive` | TensorRT iteration-stat reads that may drain queued data | Caller must opt into the consumptive effect. |
| `inference-canary` | readiness generation and one-token inference probes | This is a real, potentially billable model call and requires explicit effect authorization. |

An inference canary is a standalone probe effect. The shadow v1 command does
not launch canaries while admitting a collection run; it accepts only routes
whose pinned profile capability is already `supported`. This keeps probe calls
from escaping the P0 plan's aggregate request, concurrency, persistence, and
wall-clock ceilings.

Probes do not mutate deployment state. TASC never starts a server, loads a
model, changes autoscaling, edits a route, or deploys a policy.

## Manual one-call smoke

`npm run live:smoke` has two deliberately separate modes:

- with no `TASC_LIVE_SMOKE_*` variables, it starts the deterministic local
  fixture used by CI and makes six bounded literal-loopback contacts across
  vLLM, Ollama NDJSON, and TGI contracts;
- an operator can opt into a real endpoint outside CI by supplying the complete
  contract below. Partial, misspelled, or unknown `TASC_LIVE_SMOKE_*`
  configuration fails closed before contact.

Real mode requires:

| Variable | Contract |
| --- | --- |
| `TASC_LIVE_SMOKE_ENDPOINT` | Exact canonical origin. Public HTTPS is the default and must not include a path, query, fragment, credentials, or trailing slash. |
| `TASC_LIVE_SMOKE_RUNTIME` | Registered profile ID such as `vllm`; it must match the endpoint contract. |
| `TASC_LIVE_SMOKE_RUNTIME_BUILD` | Exact pinned registry build, not `latest`. |
| `TASC_LIVE_SMOKE_ROUTE` | One of the registered invocation routes whose pinned capability state is already `supported`; conditional routes are rejected rather than auto-probed. |
| `TASC_LIVE_SMOKE_MODEL_ID` / `TASC_LIVE_SMOKE_MODEL_REVISION` | Exact model identity and immutable revision. |
| `TASC_LIVE_SMOKE_BACKEND_NAME` / `TASC_LIVE_SMOKE_BACKEND_BUILD` | Exact backend identity. |
| `TASC_LIVE_SMOKE_CONFIGURATION_DIGEST` | Canonical lowercase `sha256:` digest of the deployment configuration. |

Optional authentication is reference-only:

```text
TASC_LIVE_SMOKE_AUTH_ENV=TASC_RUNTIME_AUTH_VLLM
TASC_LIVE_SMOKE_AUTH_HEADER=authorization
```

Supply both variables or neither. The named `TASC_RUNTIME_AUTH_*` variable must
already be injected by the operator's secret manager and contains the complete
header value (for example, including a bearer scheme when the endpoint
requires it). Its value is read only at dispatch and is never copied to
configuration or output. `x-api-key` is the other accepted header.

Literal local HTTP requires both an exact `http://127.0.0.1:<port>` or
`http://[::1]:<port>` origin and `TASC_LIVE_SMOKE_ALLOW_LOOPBACK=1`. The flag is
rejected for a public endpoint. Private, link-local, metadata, and noncanonical
targets remain blocked by collector policy and connection-time address
pinning.

Operator mode makes exactly one direct inference request. It performs no
probe, canary, model discovery, retry, deployment, or service mutation.
The request is fixed at eight output tokens and is bounded by a 10-second total
deadline, 3-second connect timeout, 5-second header/body timeouts, 64 KiB
request limit, 1 MiB response limit, 16 KiB/64-header limit, 4,096 response
chunks, and 8 KiB secret-header limit. It emits one JSON record containing only
the exact instance identity and `RuntimeInvocationPersistence`; raw prompt,
output, endpoint origin, auth reference, environment-variable name, and secret
value are excluded and checked before printing. An incomplete or failed
invocation still prints only that sanitized metadata and exits nonzero.
The `instance` block remains operator-configured scope; only fields explicitly
marked `provider-reported` in the persistence record are live identity
verification.

Real mode rejects `CI` and `GITHUB_ACTIONS`. Repository tests exercise the
pure configuration boundary and deterministic loopback fixture only; they do
not claim that an external endpoint was run.

## Ray Serve and SkyPilot / SkyServe

Ray and SkyPilot are orchestration layers, not alternate wire protocols in
TASC. An orchestration descriptor adds provenance to an underlying registered
runtime:

- Ray Serve: Ray build, application, deployment, route prefix, and
  configuration digest;
- plain SkyPilot: SkyPilot build, cluster name, route prefix, mode, and
  configuration digest;
- SkyServe: SkyPilot build, service name, route prefix, mode, and configuration
  digest.

The locator schema is mode-specific. `kind: "skypilot"` requires
`locator.clusterName`; `kind: "skyserve"` requires `locator.serviceName`.
The pre-release draft shape that put `serviceName` under plain `skypilot` is
rejected rather than reinterpreted, because silently changing a locator would
change trace provenance and the endpoint-descriptor fingerprint.

The underlying vLLM, SGLang, TensorRT-LLM, llama.cpp, or other registered
runtime still owns request and response parsing. TASC does not import the Ray or
SkyPilot SDK, inspect a cluster, execute a job, or create/update a service.

References:

- [Ray Serve 2.56.1 application/deployment configuration](https://github.com/ray-project/ray/blob/ray-2.56.1/doc/source/serve/production-guide/config.md)
  and [release](https://github.com/ray-project/ray/releases/tag/ray-2.56.1)
- [SkyPilot 0.13.1rc1 CLI identifiers](https://github.com/skypilot-org/skypilot/blob/v0.13.1rc1/sky/client/cli/command.py),
  [SkyServe service semantics](https://github.com/skypilot-org/skypilot/blob/v0.13.1rc1/docs/source/serving/sky-serve.rst),
  and [release](https://github.com/skypilot-org/skypilot/releases/tag/v0.13.1rc1)

## Network and authentication policy

Every request is derived from an operator-owned `CollectorTrustPolicy`.
Authorization covers the exact endpoint alias, origin, runtime build, method,
path prefix, duration ceiling, and optional secret reference.

Remote origins require HTTPS and public addresses. DNS is checked at connection
time, the accepted address is pinned into the actual connection while TLS
continues to verify the original hostname, redirects are disabled, and private,
loopback, link-local, CGNAT, ULA, unspecified, and cloud-metadata destinations
are rejected. Local servers require an exact literal-loopback origin and an
explicit local-mode opt-in.

Authentication values come from an injected secret-header factory or an
environment reference selected by policy. Values must not appear in protocol,
profile, case, endpoint, or artifact JSON. TASC stores only the approved
reference name.

## Shadow collection

Shadow collection is paired R&D execution, not live traffic routing. P1
consumes one self-contained P0 run plan plus ephemeral cases, exact runtime
target bindings, collector trust, environment-backed secret/signing
references, and an approved durable storage root. It rejects loose policy,
protocol, window-membership, and work-budget identities. Within that authority,
P1 calls the selected profiles in stable counterbalanced order.

Before signing, filesystem access, or network contact, the runner accounts for
worst-case cases, profiles, replicates, attempts, network calls, request bytes,
durable records, concurrency, and deadlines. Its durable lifecycle is:

```text
intent → send lease → outcome → accepted trace → complete marker
```

On resume, accepted traces are deduplicated. A lease that might have crossed the
network boundary but has no outcome becomes `sent_unknown`; it is retained and
is never retried. Only an outcome that proves `not_sent` can use a remaining,
pre-budgeted attempt. This favors honest missing coverage over duplicate model
calls.

## Other local inference workflows evaluated

The following are useful ecosystems but are not registered runtime profiles in
this release:

| Workflow | Why teams use it | TASC position |
| --- | --- | --- |
| [LocalAI](https://localai.io/basics/getting_started/) | Broad OpenAI-compatible local gateway across backends | Candidate for a build-pinned profile after contract tests; do not assume its backend behavior from the OpenAI shape. |
| [llama-cpp-python server](https://llama-cpp-python.readthedocs.io/en/latest/server/) | Python packaging around llama.cpp with an OpenAI-compatible server | Use the native llama.cpp profile only when its pinned wire contract actually matches; otherwise add a separate profile. |
| [MLC LLM REST server](https://llm.mlc.ai/docs/deploy/rest.html) | Compiled multi-platform deployment, including edge devices | Roadmap candidate requiring streaming, usage, cancellation, and identity fixtures. |
| [Jan API server](https://jan.ai/docs/api-server) | Desktop/local OpenAI-compatible workflow | Roadmap candidate for explicitly approved local use. |
| [BentoML](https://docs.bentoml.com/en/latest/) | Packaging and serving arbitrary inference applications | Treat as orchestration around a registered, contract-tested inference route rather than a generic adapter. |
| [Transformers Serve](https://huggingface.co/docs/transformers/serve-cli/serving) | Lightweight OpenAI-compatible local/self-hosted server in Transformers | High-priority candidate now that TGI is legacy; pin a Transformers release and test its own Responses/streaming lifecycle rather than inheriting TGI behavior. |
| [Xinference](https://inference.readthedocs.io/en/stable/getting_started/using_xinference.html) | Local or distributed multi-backend server with OpenAI-compatible APIs | Candidate requiring a distinct profile because backend selection and authentication materially affect identity and wire behavior. |
| [NVIDIA Triton OpenAI frontend](https://docs.nvidia.com/deeplearning/triton-inference-server/user-guide/docs/client_guide/openai_readme.html) | Production serving frontend over vLLM or TensorRT-LLM backends | Candidate orchestration/wire profile; do not treat direct `trtllm-serve` coverage as Triton coverage. |
| [NVIDIA NIM for LLMs](https://docs.nvidia.com/nim/large-language-models/latest/reference/api-reference.html) | Locally deployable container with a vLLM-backed OpenAI API plus NIM-specific health, metadata, version, and metrics routes | Candidate requiring an exact NIM image, model profile, and backend identity; direct vLLM coverage does not cover the NIM proxy contract. |
| [NVIDIA Dynamo](https://docs.nvidia.com/dynamo/latest/getting-started/local-installation) | Local-to-Kubernetes inference frontend, router, and workers over vLLM, SGLang, or TensorRT-LLM | Candidate orchestration/wire profile that must bind the Dynamo build, frontend/parser/router configuration, and underlying engine instead of inheriting the engine profile. |
| [llamafile](https://github.com/Mozilla-Ocho/llamafile/releases) | Portable single-file local runtime with an OpenAI-compatible server | Local roadmap candidate with its own bundled llama.cpp revision and server contract. |
| [DeepSpeed-MII](https://deepspeed-mii.readthedocs.io/en/latest/rest.html) | Persistent local or multi-node gRPC serving with an optional REST gateway | Roadmap candidate requiring a released MII build and separate gRPC, REST, streaming, health, and deployment-identity contract tests. |

The admission rule is intentionally strict: a popular library does not get a
generic adapter merely because it accepts OpenAI-looking JSON. A new profile
needs a pinned upstream build, official route evidence, success and failure
fixtures, JSON/SSE/NDJSON limits as applicable, timeout/cancellation tests,
identity semantics, and a documented support tier.

## Adding or upgrading a profile

1. Pin one released runtime build and link primary upstream documentation.
2. Describe every capability as supported, conditional, unsupported, or
   unknown. Record model/backend/configuration dependencies explicitly.
3. Add exact route and framing metadata; do not share a codec when terminal or
   usage semantics differ.
4. Add local contract-server fixtures for JSON, streaming, truncation,
   malformed framing, oversized bodies, timeout, cancellation, missing usage,
   and provider failures.
5. Verify probe evidence never upgrades unobserved identity fields.
6. Run the live contract against an operator-provided endpoint outside CI and
   record the runtime/model/configuration identity and bounded result.
7. Review SSRF policy, authentication references, secret redaction, and
   persisted fields before changing the support tier.

## Explicit non-goals

- no synchronous choice on a production request path;
- no model-server deployment or autoscaling control;
- no runtime SDK/plugin loading or arbitrary discovery hooks;
- no shell commands supplied by protocols or endpoints;
- no claim that an OpenAI-compatible shape means equivalent semantics;
- no raw prompt/output persistence in shadow records; and
- no evaluator or LLM-as-judge implementation hidden inside the collector.
