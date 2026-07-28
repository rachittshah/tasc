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
| SGLang | `0.5.16` | production candidate; remote or local | OpenAI Chat Completions, Completions, and Responses; JSON/SSE | `/v1/models`, `/model_info`, `/health`, consumptive `/health_generate`, `/server_info`, optional Prometheus `/metrics` |
| TensorRT-LLM | `1.2.1` | production candidate; remote or local | OpenAI Chat Completions, Completions, and Responses; JSON/SSE | `/v1/models`, `/health`, consumptive `/health_generate`, `/version`, JSON `/metrics`, Prometheus `/prometheus/metrics` |
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
- [TensorRT-LLM `trtllm-serve` at v1.2.1](https://github.com/NVIDIA/TensorRT-LLM/blob/v1.2.1/docs/source/commands/trtllm-serve/index.rst)
- [llama.cpp server at build b10156](https://github.com/ggml-org/llama.cpp/blob/b10156/tools/server/README.md)
- [Ollama API at v0.32.5](https://github.com/ollama/ollama/blob/v0.32.5/docs/api.md)
  and [OpenAI compatibility](https://docs.ollama.com/api/openai-compatibility)
- [Text Generation Inference HTTP API](https://huggingface.co/docs/text-generation-inference/en/reference/api_reference)
  and [metrics](https://huggingface.co/docs/text-generation-inference/en/reference/metrics)
- [LM Studio REST API](https://lmstudio.ai/docs/developer/rest)
  and [Responses compatibility](https://lmstudio.ai/docs/developer/openai-compat/responses)
- [MLX-LM server at v0.31.3](https://github.com/ml-explore/mlx-lm/blob/v0.31.3/mlx_lm/SERVER.md)

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
- request/response byte and frame counts;
- dispatch state: `not_sent`, `sent_unknown`, or `completed`;
- bounded wire timing and provider-reported timing;
- provider-reported token usage, with unavailable fields left `null`;
- provider request ID when safely available;
- normalized completion/incompletion status; and
- an allowlisted error category and status, never a reflected response body.

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

Probes do not mutate deployment state. TASC never starts a server, loads a
model, changes autoscaling, edits a route, or deploys a policy.

## Ray Serve and SkyPilot / SkyServe

Ray and SkyPilot are orchestration layers, not alternate wire protocols in
TASC. An orchestration descriptor adds provenance to an underlying registered
runtime:

- Ray Serve: Ray build, application, deployment, route prefix, and
  configuration digest;
- SkyPilot or SkyServe: SkyPilot build, service name, route prefix, mode, and
  configuration digest.

The underlying vLLM, SGLang, TensorRT-LLM, llama.cpp, or other registered
runtime still owns request and response parsing. TASC does not import the Ray or
SkyPilot SDK, inspect a cluster, execute a job, or create/update a service.

References:

- [Ray Serve LLM](https://docs.ray.io/en/latest/serve/llm/index.html)
- [SkyServe](https://docs.skypilot.ai/en/latest/serving/sky-serve.html)

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

Shadow collection is paired R&D execution, not live traffic routing. P0 supplies
the protocol, case membership, profiles, route-time signal, budget, signing
authority, and storage root. P1 calls the selected profiles in stable
counterbalanced order.

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

