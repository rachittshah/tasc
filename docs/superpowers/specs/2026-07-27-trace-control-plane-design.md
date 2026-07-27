# TASC Trace Control Plane — Design Specification

- Date: 2026-07-27
- Status: Approved for implementation
- Priority: P0 out-of-band controller; P1 active inference collection
- Product boundary: inference evaluation and routing-policy control, not LLM-as-judge

## 1. Decision

TASC becomes an out-of-band, trace-aware control plane for inference
experiments. It observes or launches paired inference work, joins immutable
trace evidence with scores produced by external evaluators, assesses frozen
routing policies, and proposes the next falsifiable experiment.

TASC does **not** implement an evaluator model, author judge prompts, reinterpret
log probabilities as quality, or sit on the production request path. A serving
system may consume a policy bundle that TASC recommends, but applying that
bundle remains a separate, explicit authority.

The first production-shaped release has two priorities:

1. **P0 — control plane:** versioned evidence contracts, deterministic offline
   and shadow-online assessment, protocol lineage, trustworthy statistics,
   resumable state, review packets, and bounded experiment proposals.
2. **P1 — inference collection:** optional live calls to local and hosted
   inference runtimes, with runtime-specific capability evidence and complete
   observer-side traces.

This ordering keeps the decision engine useful for traces collected by any
system and prevents network clients from becoming the product's center.

## 2. Goals

TASC must:

- preserve inference attempts, failures, retries, timing, usage, and provenance
  as immutable evidence;
- keep route-time signals distinct from evaluator scores;
- ingest evaluator evidence created elsewhere and bind it to a named rubric,
  version, calibration, producer, and source digest;
- compare champion and candidate policies using paired replicates and the true
  independent sampling unit;
- grade policies on offline datasets and sealed windows of live shadow traces;
- distinguish measured, observer-derived, provider-reported, modeled, and
  unavailable metrics;
- fail closed when protocol lineage, evidence coverage, or evaluator provenance
  is missing or stale;
- emit deterministic diagnoses and a bounded next-experiment manifest;
- call supported inference endpoints without requiring vendor SDKs;
- resume interrupted collection without duplicating accepted observations;
- produce atomic, self-describing evidence packets for human and machine review;
- remain safe to run with untrusted model output and partially trusted provider
  responses;
- remain useful with no credentials through deterministic fixtures and local
  contract-test servers.

## 3. Non-goals

The implementation will not:

- provide an LLM judge framework or a generic prompt-evaluation package;
- train, fine-tune, calibrate, or silently replace an evaluator;
- choose a model synchronously for a production user request;
- mutate Ray, SkyPilot, Kubernetes, cloud, or model-server deployments;
- promote or roll back a production policy;
- claim capacity from per-request token rates;
- infer cost when no explicit versioned allocation model exists;
- store raw prompts, outputs, authorization headers, or secrets by default;
- promise identical behavior merely because two runtimes expose an
  OpenAI-shaped endpoint.

## 4. System shape

```text
                       ┌────────────────────────────┐
serving export ───────>│                            │
shadow collector ─────>│ immutable TraceEnvelope   │──┐
                       │ stream                     │  │
                       └────────────────────────────┘  │
                                                       │
                       ┌────────────────────────────┐  │
human/deterministic ──>│ immutable EvaluatorEvidence│──┤
external judge ───────>│ stream                     │  │
                       └────────────────────────────┘  │
                                                       v
┌──────────────────────┐                    ┌───────────────────────┐
│ frozen Experiment    │───────────────────>│ deterministic join +  │
│ Protocol             │                    │ assessment engine     │
└──────────────────────┘                    └───────────┬───────────┘
                                                       │
                            ┌──────────────────────────┼────────────┐
                            v                          v            v
                    AssessmentArtifact       ExperimentProposal  PolicyBundle
                    + review packet          for approval        recommendation
```

The deterministic core remains network-free. The optional collector depends on
the core contracts, never the other way around.

## 5. Trust boundaries

1. **Serving system:** owns the user response, provider selection, timeouts,
   retries, and fallback. TASC cannot affect availability.
2. **Collector:** is authoritative only for observer-side timestamps, transport
   events, request configuration, and bytes it actually observes.
3. **Runtime:** may report model identity, token counts, timings, and metrics.
   These remain labeled `provider_reported`; they never overwrite observer
   evidence.
4. **External evaluator:** owns quality scores. TASC validates their shape and
   lineage but does not assert that a rubric is correct.
5. **Control plane:** performs immutable joins and deterministic decisions. It
   cannot rewrite source evidence.
6. **Experiment proposer:** can suggest one bounded experiment. It cannot change
   frozen gates, holdout membership, evaluator evidence, or production state.
7. **Deployment authority:** a human or existing release system applies or
   rejects recommendations.
8. **Payload store:** raw prompts and responses remain outside TASC by default.
   Evidence contains digests and controlled references unless an operator
   explicitly enables payload capture.

## 6. Versioned contracts

Every contract uses strict runtime validation, explicit finite bounds, canonical
serialization, and a content digest. Unknown fields are rejected so typos cannot
silently weaken an experiment.

### 6.1 `ExperimentProtocol`

`tasc-experiment-protocol-v2` freezes:

- study ID, protocol version, owner, creation time, and expiry;
- deterministic development, holdout, and online-window membership rules;
- champion and candidate execution profiles;
- model, tokenizer, runtime, backend, hardware, quantization, chat-template,
  orchestration, and deployment-configuration identities;
- route-signal definition, version, range, direction, and calibration digest;
- external evaluator ID, rubric version, calibration digest, producer kind, and
  validation state;
- candidate policy space and exact declarative predicates;
- quality, reliability, latency, cost, and coverage gates;
- independent-group and critical-slice minimums;
- bootstrap seed, method, and bounded iteration count;
- shadow sampling budget, concurrency, timeout, retry, and payload policy;
- an explicit cost-allocation model or `unavailable`;
- the allowed endpoint hosts and runtime capabilities required by the study.

The protocol digest is derived from canonical content. It is never supplied as a
trusted input.

### 6.2 `TraceEnvelope`

`tasc-trace-envelope-v2` records one case replicate:

- study, protocol, trace, case, group, replicate, split, and collection-window
  IDs;
- source mode: `imported`, `observed`, or `shadow`;
- policy digest and route actually observed;
- workload and declared traffic weight;
- slice labels;
- route-signal value plus definition and calibration identities;
- ordered attempt events for each execution profile;
- observer timestamps for start, headers, first byte, first meaningful token,
  and completion;
- status, finish reason, partial-output state, abort lifecycle, and normalized
  failure category;
- requested and resolved model identities;
- token usage with source and semantics;
- provider-reported timings and metrics in a separate namespace;
- request, response, and event-stream digests or controlled payload references;
- collector version and execution-profile digest.

`TraceEnvelope` contains no evaluator score. Authorization headers, secret
values, and raw environment variables are forbidden.

### 6.3 `EvaluatorEvidence`

`tasc-evaluator-evidence-v2` records:

- study, protocol, trace, case, replicate, profile, and split identities;
- evaluator, rubric, calibration, and producer identities;
- score, score range, and optional structured subscores;
- evidence source digest or controlled reference;
- production time, validation state, and optional signature;
- explicit `missing`, `invalid`, and `abstained` outcomes.

Changing the evaluator, rubric, or calibration makes prior evidence stale for a
new study. TASC never converts output log probabilities into this contract.

### 6.4 `AssessmentDataset`

The join is deterministic on
`(protocolDigest, caseId, replicateId, profileId)`. It:

- rejects duplicates and identity conflicts;
- retains failed attempts and missing evaluator evidence;
- rejects cross-split group leakage;
- reports unmatched traces and evidence rather than dropping them;
- preserves source digests;
- separates measured, reported, modeled, and unavailable fields.

### 6.5 `PolicyBundle`

A recommendation contains only declarative routing predicates, named execution
profiles, fallback behavior, compatibility version, protocol and policy
digests, issue and expiry times, and optional signer metadata. It contains no
arbitrary code and TASC does not install it.

### 6.6 `AssessmentArtifact`

Each result records:

- engine and schema versions;
- protocol, trace-set, evaluator-set, policy, and source digests;
- estimator identifier and parameters;
- case, replicate, independent-group, slice, failure, and missing-evidence
  coverage;
- every gate's operator, threshold, actual value, evidence class, and result;
- all candidate decisions, not only the selected policy;
- warnings, stale conditions, and unavailable metrics;
- attestation state and a completion manifest.

## 7. Deterministic controller

The P0 controller is a state machine backed by append-only evidence and atomic
checkpoints:

```text
DRAFT
  -> REGISTERED
  -> COLLECTING
  -> DEV_READY
  -> NOMINATED
  -> SHADOW_ASSESSING
  -> HOLDOUT_CONFIRMED
  -> PROMOTION_RECOMMENDED
  -> MONITORING

any assessable state -> HOLD
identity drift       -> STALE
online regression    -> ROLLBACK_RECOMMENDED
final lifecycle      -> RETIRED
```

State transitions are pure functions of a frozen protocol and source evidence.
Replaying the same content must produce byte-identical decision JSON apart from
explicitly excluded wall-clock envelope metadata.

“Online grading” means repeatedly assessing immutable, sealed windows of live
or shadow traces. A window has an event-time range, ingestion watermark, source
digests, and closure reason. Late evidence creates a new revision; it never
mutates an already attested artifact.

## 8. Statistical method

Decision-affecting order uses a locale-independent UTF-16 code-unit comparator.
`localeCompare` is forbidden in canonicalization, sampling order, tie-breaking,
and artifact order.

Quality comparison follows the evidence hierarchy:

1. pair champion and candidate outcomes by case and replicate;
2. calculate the paired score delta for each replicate;
3. summarize replicates within a case using the preregistered estimator;
4. preserve case traffic weights;
5. aggregate related cases within `groupId`;
6. cluster-bootstrap independent groups with replacement;
7. recalculate the traffic-weighted estimand inside every draw;
8. compare the preregistered confidence bound with the non-inferiority margin.

The artifact reports method, estimate, interval, iterations, seed, case count,
replicate count, group count, and effective traffic mass. Coverage gates are
evaluated before inference. Production recommendations require protocol-defined
minimum independent groups and per-critical-slice group coverage; a legacy v1
dataset cannot produce a production recommendation.

Operational metrics retain traffic weights. Retries and failures remain
outcomes. A serial fallback may conservatively sum observed attempt cost and
latency, but TASC will not assign it aggregate service throughput. Capacity
gates require measured window-level server evidence from the exact deployed
policy; otherwise the gate is `UNAVAILABLE` and fails closed when required.

## 9. Agentic experiment loop

Agentic behavior is an inspect-propose-approve-measure loop, not a chat agent:

1. inspect failed gates, uncertainty, drift, missing evidence, runtime
   capabilities, and prior experiments;
2. choose one diagnosis using stable priority rules;
3. emit one falsifiable `ExperimentProposal` with hypothesis, changed variable,
   frozen controls, evidence requirements, budget, stop condition, and expected
   decision;
4. reject proposals that duplicate prior protocol digests or exceed configured
   privacy, cost, or workload bounds;
5. wait for an operator to register the proposal as a new protocol;
6. collect, join, assess, and record the result;
7. recommend another experiment, a bounded canary outside TASC, or `HOLD`.

The proposer may recommend an evaluator-calibration study when disagreement or
staleness is observed. It cannot generate replacement scores or tune on the
policy holdout.

## 10. P1 live inference collection

The collector uses Node's native `fetch`, streaming readers, and `AbortSignal`.
Vendor SDKs are avoided because they commonly hide raw frames, first-byte
timing, nonstandard fields, and mid-stream failures.

Shared wire codecs cover:

- OpenAI-style Chat Completions JSON and SSE;
- OpenAI-style Responses event streams where the runtime genuinely supports
  them;
- Ollama native NDJSON;
- Prometheus exposition for non-destructive server metrics.

Each runtime has a separate profile rather than one misleading generic adapter:

- vLLM;
- SGLang;
- TensorRT-LLM;
- llama.cpp;
- Ollama;
- Text Generation Inference as legacy compatibility;
- LM Studio for approved internal use;
- MLX-LM as experimental/local-only.

A capability has state `supported`, `conditional`, `unsupported`, or `unknown`,
plus probe time, evidence source, runtime build, model revision, backend, and
configuration digest. Startup probes independently cover transport liveness,
model readiness, model discovery, streaming framing, final usage, log
probabilities, structured output, cancellation, and metrics.

Ray Serve and SkyPilot/SkyServe are orchestration descriptors or optional
endpoint-discovery plugins. The underlying runtime profile still owns the wire
contract. P1 will not import Ray, Kubernetes, or SkyPilot SDKs into the
TypeScript core and will not create or mutate deployments.

The shadow runner:

- counterbalances champion/candidate invocation order;
- uses stable replicate IDs and idempotency keys;
- enforces bounded concurrency, per-attempt deadlines, total work budgets, and
  response/event-size limits;
- records every retry as evidence;
- aborts outstanding requests on cancellation;
- checkpoints accepted envelopes atomically;
- resumes without duplicating completed `(case, replicate, profile)` keys;
- never logs authentication material;
- sanitizes provider errors before persistence.

## 11. Security and failure handling

- Configured endpoint hosts are explicit. Cloud metadata and link-local
  addresses are denied unless an operator opts in with a dedicated unsafe flag.
- Authentication is supplied through environment-variable references or an
  injected header factory. Secret values never enter parsed config or artifacts.
- Raw payload capture defaults to `digest-only`; controlled references and
  encrypted external stores are opt-in.
- JSON, SSE, NDJSON, metrics, and output files have strict byte, depth, item, and
  duration limits.
- Work estimates are calculated before candidate expansion, bootstrap, or live
  calls. Inputs exceeding the budget fail before partial execution.
- Artifact output uses a same-parent private staging directory, exclusive files,
  restrictive permissions, flushed content, a manifest written last, and atomic
  rename.
- Import paths and benchmark-derived filenames use strict slugs and verified
  containment.
- Partial runtime success never becomes a successful trace; final usage absence,
  transport truncation, and cancellation ambiguity remain explicit.
- Deployment mutation, shell hooks, arbitrary plugins, and dynamic code loading
  are excluded from this release.

## 12. CLI and library surface

The intended CLI:

```text
tasc protocol validate <protocol.json>
tasc traces validate <traces.ndjson>
tasc evidence validate <evaluator-evidence.ndjson>
tasc assess offline --protocol ... --traces ... --evidence ... --out ...
tasc assess window  --protocol ... --traces ... --evidence ... --out ...
tasc experiment next --assessment ... --history ... --out ...
tasc runtime probe --endpoint ... --runtime ...
tasc shadow run --protocol ... --cases ... --out ...
tasc --help
tasc --version
```

Commands return structured JSON on stdout, diagnostics on stderr, and documented
exit codes. The public library exposes intentional entry points instead of
wildcard-exporting internal statistics and filesystem helpers.

The existing v1 nomination/confirmation flow remains readable for migration and
synthetic demos, but it is explicitly legacy and cannot emit a v2 production
recommendation.

## 13. Repository and release quality

The repository will include:

- test-first unit, property, adversarial, integration, and package-smoke tests;
- local HTTP/SSE/NDJSON contract servers for deterministic runtime tests;
- a sanitized end-to-end fixture showing trace/evaluator separation;
- a manual live-call smoke command that never records credentials or raw private
  payloads;
- Node 22 and 24 checks on Linux and macOS;
- Python benchmark parser tests in CI;
- typecheck, coverage, build, clean-tarball install/import/CLI, dependency audit,
  and security analysis;
- a regenerated cross-platform npm lockfile with integrity metadata;
- `prepack` build behavior so a pristine package contains its runtime;
- release notes, migration guide, architecture, threat model, runtime support
  matrix, operating guide, and contribution instructions;
- an opt-in release workflow that publishes only an immutable, verified tag.

Commits are divided by coherent behavior so each can be reviewed and reverted
without relying on empty or cosmetic history.

## 14. Implementation slices

1. Repository isolation and approved design record.
2. Detailed TDD implementation plan.
3. Evidence contract v2 and canonical identity.
4. Correct paired, weighted, group-clustered assessment.
5. Deterministic out-of-band controller and sealed online windows.
6. External evaluator ingestion and complete review artifacts.
7. Agentic next-experiment protocol.
8. Runtime registry and capability evidence.
9. Resilient live shadow collector.
10. vLLM, SGLang, TensorRT-LLM, llama.cpp, Ollama, TGI, LM Studio, and
    MLX-LM profiles.
11. Ray Serve and SkyPilot endpoint descriptors.
12. CLI, compatibility, and packaging.
13. CI, security, release, and documentation.
14. Real live smoke, multi-angle review, and PR.

## 15. Acceptance criteria

The release is acceptable only when:

- evaluator scores are absent from trace attempts and accepted only through
  `EvaluatorEvidence`;
- route signals and evaluator scores have different types and provenance;
- repeated execution across supported locales produces identical decisions and
  canonical artifacts;
- correlated case duplication cannot narrow uncertainty as if it created new
  independent groups;
- traffic-weighted regressions cannot be hidden by many low-weight cases;
- an inferred cascade throughput value cannot pass a gate;
- protocol, profile, route-signal, evaluator, split, and window drift fails
  closed;
- offline and sealed shadow-window assessments use the same deterministic core;
- no assessment path can mutate a serving deployment;
- every supported runtime profile has capability, success, timeout,
  truncation, cancellation, and malformed-stream tests appropriate to its
  contract;
- Ray and SkyPilot remain orchestration metadata rather than fake inference
  adapters;
- an interrupted shadow run resumes without duplicate accepted traces;
- artifacts are either complete and manifested or absent after injected write
  failures;
- package installation from a clean tarball supports import, `--help`, and a
  documented CLI smoke;
- all mandatory Linux, macOS, Node, Python, package, audit, and security checks
  are green;
- one real endpoint call is recorded as a sanitized trace without secret
  leakage;
- Codex specialty reviews and Claude Code review have no unresolved critical or
  important findings;
- the pull request documents the trust boundary, verification evidence,
  limitations, and follow-up work.

