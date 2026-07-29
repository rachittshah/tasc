# TASC

[![CI](https://github.com/rachittshah/tasc/actions/workflows/ci.yml/badge.svg)](https://github.com/rachittshah/tasc/actions/workflows/ci.yml)
[![CodeQL](https://github.com/rachittshah/tasc/actions/workflows/codeql.yml/badge.svg)](https://github.com/rachittshah/tasc/actions/workflows/codeql.yml)
[![Release](https://github.com/rachittshah/tasc/actions/workflows/release.yml/badge.svg)](https://github.com/rachittshah/tasc/actions/workflows/release.yml)

**Trace-Aware Serving Controller**

TASC is an out-of-band controller for inference evaluation and routing R&D. It
joins paired request traces with independently produced evaluator evidence,
selects a policy on development data, freezes it, and replays only that policy
on a holdout or sealed shadow-online window.

The boundary is deliberate:

- **P0 is authoritative:** protocols, split/window membership, trust snapshots,
  evidence joins, grouped inference, policy decisions, controller state,
  experiment proposals, and immutable review artifacts.
- **P1 is effectful but subordinate:** bounded probes and inference calls
  against an exact operator-approved endpoint, plus resumable paired shadow
  collection. P1 returns trace evidence to P0; it never chooses a policy.

TASC is **not an LLM-as-a-judge package**. It has no judge prompt, judge client,
reward model, or hidden scoring call. Scores arrive as separately signed
`EvaluatorEvidence` from a human, deterministic evaluator, or externally
operated model evaluator under an explicit trust policy. TASC is also **not a
deployment controller**: v2 CLI results and artifact manifests carry
`evidence-only-no-deployment-authority`; the P0 shadow plan carries its own
equally explicit out-of-band, no-deployment authority.

## What is implemented

```text
                         P0: out of band
protocol + trust + traces + signed evaluator evidence
                         |
                         v
       bounded parse → verify → deterministic join
                         |
              development policy search
                         |
                 freeze exact policy
                  /                 \
        holdout confirmation     sealed window replay
                  \                 /
                 gates + diagnosis
                         |
          bounded next-experiment proposal
                         |
       immutable raw-free review artifact packets

                         P1: effects
P0 shadow-run plan + trust + secrets by reference
                         |
              probe / invoke / paired shadow
                         |
       signed TraceEnvelope records returned to P0
```

The v2 path provides:

- strict `ExperimentProtocol`, `TraceEnvelope`, `EvaluatorEvidence`,
  `AssessmentContext`, `PolicyBundle`, and `WindowManifest` contracts;
- separate Ed25519 dispatch-intent, collector-observation, and
  evaluator-evidence verification;
- seeded group-disjoint development/holdout membership and deterministic
  sealed-window sampling;
- fast-only, expert-only, and single-predicate cascade replay;
- grouped paired bootstrap inference, traffic-weighted operational metrics,
  hard quality/slice/failure/latency/cost/capacity gates, and fail-closed
  missing evidence;
- development nomination, exact-policy holdout confirmation, and sealed online
  assessment with no window retuning;
- bounded next-experiment intents that require operator registration;
- a replayable controller event log with pinned checkpoints;
- bounded JSON/NDJSON, HTTP, SSE, native NDJSON, work, and artifact limits;
- SSRF-resistant endpoint policy, DNS/IP pinning, disabled redirects, exact
  route/effect authorization, and environment-only secret values;
- immutable manifest-last artifact packets and crash-safe shadow records; and
- a maintained legacy v1 adapter for the original synthetic workflow.

See the [design](docs/design.md), [operating guide](docs/operating-guide.md),
[runtime matrix](docs/runtime-support.md), [threat model](docs/threat-model.md),
[v2 migration guide](docs/migration-v2.md), [security policy](SECURITY.md), and
[contribution guide](CONTRIBUTING.md).

## Quick start: production-shaped v2 replay

Requirement: Node.js 22 or newer.

```bash
git clone https://github.com/rachittshah/tasc.git
cd tasc
npm ci
npm run demo:control-plane
```

The committed fixture has separate paired trace NDJSON and signed external
evaluator-evidence NDJSON. The demo uses only public package APIs. It verifies
dispatch and collector authorities plus evaluator trust, nominates a cascade
on development,
replays that frozen policy on a sealed online window, holds because trusted
exact-policy capacity is unavailable, emits the next bounded experiment and a
raw-free recommendation, then rereads and verifies every manifest and payload
digest.

Expected key lines:

```text
network calls: 0
model calls: 0
development: NOMINATED
sealed window: INSUFFICIENT_EVIDENCE
service capacity: UNAVAILABLE (...)
next experiment: PROPOSED (unavailable-capacity)
authority: evidence-only-no-deployment-authority
artifact verification: 4/4 manifests and payload digests verified
```

Run the same development and window phases through the v2 CLI:

```bash
TASC_RUN_ROOT=$(realpath "$(mktemp -d)")

npm run tasc -- assess development \
  --protocol examples/control-plane/protocol.json \
  --traces examples/control-plane/development-traces.ndjson \
  --evidence examples/control-plane/development-evidence.ndjson \
  --context examples/control-plane/development-context.json \
  --trust examples/control-plane/trust-snapshot.json \
  --work-budget examples/control-plane/work-budget.json \
  --out "$TASC_RUN_ROOT/development"

npm run tasc -- assess window \
  --protocol examples/control-plane/protocol.json \
  --traces examples/control-plane/online-traces.ndjson \
  --evidence examples/control-plane/online-evidence.ndjson \
  --context examples/control-plane/online-context.json \
  --policy "$TASC_RUN_ROOT/development/policy.json" \
  --window examples/control-plane/window-manifest.json \
  --trust examples/control-plane/trust-snapshot.json \
  --work-budget examples/control-plane/work-budget.json \
  --out "$TASC_RUN_ROOT/window"

npm run tasc -- experiment next \
  --assessment "$TASC_RUN_ROOT/window/assessment.json" \
  --history examples/control-plane/experiment-history.json \
  --budget examples/control-plane/experiment-budget.json \
  --out "$TASC_RUN_ROOT/next-experiment"
```

Every assessment output is an immutable packet. The final target must not
already exist. A successful command may still report `HOLD`,
`INSUFFICIENT_EVIDENCE`, or `STALE`; those are completed fail-closed decisions,
not process failures.

## Live inference and shadow collection

TASC can make live inference calls, but only in P1 and only under an explicit
operator contract. Application code can keep that boundary visible by importing
controller contracts from `@rachittshah/tasc` and effectful adapters from
`@rachittshah/tasc/runtime`. The registered runtime profiles are:

| Runtime | Pinned support profile | Wire paths |
| --- | --- | --- |
| vLLM | `0.26.0` | OpenAI Chat, Completions, Responses; JSON/SSE |
| SGLang | `0.5.16` | OpenAI Chat, Completions, Responses; JSON/SSE |
| TensorRT-LLM | `1.2.1` | OpenAI Chat, Completions, Responses; JSON/SSE |
| llama.cpp | build `b10156` | OpenAI Chat, Completions, Responses; JSON/SSE |
| Ollama | `0.32.5` | OpenAI-compatible plus native Chat/Generate; JSON/SSE/NDJSON |
| Text Generation Inference | `3.3.7` | OpenAI Chat plus native Generate; JSON/SSE |
| LM Studio | `0.4.1` | OpenAI Chat/Responses plus native Chat; JSON/SSE |
| MLX-LM | `0.31.3` | OpenAI Chat and Completions; JSON/SSE |

Support is build-pinned and capability-specific, not a promise that every
model/backend/configuration combination works. Live probe evidence records the
exact runtime, backend, model, endpoint, and deployment configuration.

Ray Serve and SkyPilot/SkyServe are supported as orchestration provenance
around an underlying registered inference runtime. TASC does not import their
SDKs, inspect clusters, launch jobs, or mutate services. Plain SkyPilot binds a
cluster name; SkyServe binds a service name; the two locator shapes are not
interchangeable. The
[runtime support matrix](docs/runtime-support.md) records exact routes,
capability tiers, upstream sources, and additional local workflows considered:
LocalAI, llama-cpp-python, MLC LLM, Jan, BentoML, Transformers Serve,
Xinference, NVIDIA Triton, NVIDIA NIM, NVIDIA Dynamo, llamafile, and
DeepSpeed-MII.

A bounded probe is explicit about the effect:

```bash
npm run tasc -- runtime probe \
  --endpoint operator/endpoint.json \
  --runtime operator/runtime-instance.json \
  --trust operator/collector-trust.json \
  --capability liveness \
  --effect non-mutating \
  --deadline-ms 5000
```

`inference-canary` is a real, potentially billable model call.
`consumptive` covers observations that can drain or consume runtime state.
Neither effect deploys or reconfigures anything.

For an operator-run, one-call compatibility smoke outside CI, provide every
exact identity field and choose a route whose pinned capability is
`supported`:

```bash
TASC_LIVE_SMOKE_ENDPOINT=https://inference.example.com \
TASC_LIVE_SMOKE_RUNTIME=vllm \
TASC_LIVE_SMOKE_RUNTIME_BUILD=0.26.0 \
TASC_LIVE_SMOKE_ROUTE=completions \
TASC_LIVE_SMOKE_MODEL_ID=model-id \
TASC_LIVE_SMOKE_MODEL_REVISION=immutable-revision \
TASC_LIVE_SMOKE_BACKEND_NAME=cuda \
TASC_LIVE_SMOKE_BACKEND_BUILD=13.0 \
TASC_LIVE_SMOKE_CONFIGURATION_DIGEST=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
npm run live:smoke
```

Replace the example endpoint and identities. This mode performs exactly one
direct inference call—no probe, canary, discovery, or deployment action—and
prints only raw-free invocation metadata. It rejects CI and GitHub Actions.
With no `TASC_LIVE_SMOKE_*` variables, the same command runs the deterministic
six-contact literal-loopback fixture used by CI; no external endpoint is part
of the repository verification. Optional auth and local-loopback instructions
are in the [runtime support guide](docs/runtime-support.md#manual-one-call-smoke).

Paired collection is resumable:

```bash
npm run tasc -- shadow run \
  --plan operator/shadow-run-plan.json \
  --plan-digest "$TASC_APPROVED_SHADOW_PLAN_DIGEST" \
  --cases operator/cases.ndjson \
  --profiles operator/shadow-profiles.json \
  --trust operator/collector-trust.json \
  --identity operator/shadow-identity.json \
  --out /var/lib/tasc/study-window
```

P0 creates the self-contained `tasc-shadow-run-plan-v1` only from a controller
snapshot already in `SHADOW_ASSESSING`, the exact frozen policy and protocol,
window bounds, endpoint/profile bindings, and the aggregate work budget.
The required `--plan-digest` must come from independent operator custody or an
out-of-band approval channel. Never read it from the plan being executed: the
plan's self-digest proves integrity, while the separately pinned value proves
that P1 received the plan P0 approved. P1 compares that authority first, then
parses and re-derives the artifact; it does not accept caller-authored policy
or membership digests. Replicates outside the plan's deterministic membership
rule are counted and excluded before filesystem or network effects.

The runner preflights the complete worst-case admitted work before signing,
filesystem, or network effects. Durable progress is monotonic:

```text
intent → send lease → outcome → accepted trace → complete marker
```

Resume deduplicates accepted traces. A crash after a possible send is persisted
as `sent_unknown` and never retried; only an outcome that proves `not_sent` can
consume another pre-budgeted attempt. Raw prompts and outputs stay in memory;
durable records contain only keyed identities and allowlisted operational
metadata. Every resume-authoritative journal packet is authenticated with a
distinct-domain per-study HMAC before it can win an immutable publication
race; the accepted trace is independently dispatch- and collector-signed.
Create the output root as a protected `0700` directory and reuse the same HMAC
key on resume.

Endpoint JSON binds an alias, optional orchestration descriptor, and optional
auth reference. P0 pins that reference into the collection target and signed
trace provenance; it is a non-secret identifier, never the credential itself.
Secret values come only from `TASC_RUNTIME_AUTH_*`. Shadow identity JSON names
one `TASC_SHADOW_HMAC_*` key plus distinct
`TASC_SHADOW_SIGNING_*` dispatch and collector private keys; it never contains
their values. Every shadow target must exactly match the P0 plan, protocol
endpoint requirement, and execution profile. Per-target HTTP limits may lower
defaults; they cannot widen the plan budget. Conditional routes are not
auto-probed inside a shadow run: use the explicit runtime-probe command to
observe them, or select a build-pinned route with established support. Full
schemas and runbooks are in the
[operating guide](docs/operating-guide.md).

## Offline and online policy grading

TASC grades inference policies, not evaluator models:

1. The protocol freezes profile identities, route-signal definition,
   evaluator/rubric/calibration identity, policy space, gates, splits, window
   sampling, endpoint requirements, and work limits.
2. A dispatch signature proves that the route signal, workload, profile, and
   policy binding existed before inference.
3. A distinct collector signature attests the complete raw-free outcome and,
   for shadow traces, its P0 plan and endpoint provenance.
4. External evaluator evidence binds one terminal output identity and is
   verified against operator-controlled keys, validity, revocations, freshness,
   rubric, calibration, and producer authorization.
5. Development is the only phase allowed to enumerate policy candidates.
6. Holdout and online assessment accept exactly one frozen policy.
7. A sealed window binds event-time bounds, watermark, sampling membership,
   trace/evaluator set digests, revision lineage, and capacity evidence.
8. Missing, stale, ambiguous, untrusted, or unattested evidence remains
   visible and fails the relevant gate.

The controller can record collection, development readiness, nomination,
holdout/window decisions, manifest revisions, drift, and retirement. The
experiment proposer diagnoses a decision and emits one bounded hypothesis with
frozen controls, evidence requirements, stop conditions, and
`operator-registration-required`. It does not autonomously change the protocol,
call an evaluator, run an experiment, or deploy a route.

## Real MLX result, with honest limits

The repository includes a measured Apple M4 Pro snapshot from July 2026:

| MLX 4-bit model | ARC-Challenge `acc_norm` | Short decode | Batch-8 decode |
| --- | ---: | ---: | ---: |
| LFM2.5-350M | 31.48% | 650.0 tok/s | 1,447.6 tok/s aggregate |
| LFM2.5-1.2B-Instruct | 39.42% | 303.4 tok/s | 678.3 tok/s aggregate |

On that machine and workload, the smaller model decoded `2.14×` faster while
the larger model gained `7.94` percentage points of normalized ARC accuracy.
This is a real controlled speed/quality frontier, not proof that a cascade is
safe. The benchmark has aggregate task accuracy and kernel throughput, not
paired per-request route signals, evaluator scores, failure/cost evidence,
user-perceived latency, or exact-policy service capacity. TASC never combines
those aggregates into fictional traces.

See the [result and caveats](benchmarks/results/2026-07-26-m4-pro/) and the
[hash-locked rerun workflow](benchmarks/mlx/README.md).

## Status and authority

| Status | Meaning |
| --- | --- |
| `NOMINATED` | One policy passed development and was frozen. |
| `NO_CANDIDATE` | No development policy passed all gates. |
| `PASS` | The one frozen policy passed a holdout/window assessment. |
| `HOLD` | The frozen policy failed one or more measured gates. |
| `INSUFFICIENT_EVIDENCE` | A required input or evidence class was unavailable. |
| `STALE` | Protocol, profile, evaluator, context, policy, or window lineage drifted. |
| `DEMO_ONLY` | Legacy v1 synthetic holdout passed. |

`PASS` means “the frozen policy passed this bounded evidence contract.” It does
not mean “deploy.” Digests provide deterministic identity and corruption
detection; signatures provide authenticity only for their stated boundary.
Neither proves that a benchmark is representative, an evaluator is valid, or a
deployment is safe.

## Legacy v1 quick start

The original v1 measurement-matrix adapter remains available:

```bash
npm run demo
```

Or run its two phases directly:

```bash
TASC_LEGACY_ROOT=$(realpath "$(mktemp -d)")

npm run tasc -- nominate \
  --spec examples/synthetic/spec.json \
  --measurements examples/synthetic/dev.json \
  --out "$TASC_LEGACY_ROOT/development"

npm run tasc -- confirm \
  --spec examples/synthetic/spec.json \
  --measurements examples/synthetic/holdout.json \
  --nomination "$TASC_LEGACY_ROOT/development/nomination.json" \
  --out "$TASC_LEGACY_ROOT/holdout"
```

Legacy real-data confirmation stays capped at `HOLD`, including when its
optional environment-only HMAC continuity check succeeds. New integrations
should use v2; see the [migration guide](docs/migration-v2.md).

## Development

```bash
npm run typecheck
npm test
npm run coverage
npm run build
npm run demo:control-plane
npm run package:smoke
python3 -m unittest benchmarks/mlx/test_run_benchmarks.py
```

No new runtime profile or effect should merge without pinned primary upstream
documentation, bounded success/failure/framing fixtures, cancellation and
identity tests, and security review. See [CONTRIBUTING.md](CONTRIBUTING.md).

Built by [Rachitt Shah](https://github.com/rachittshah). Released under the
[MIT License](LICENSE).
