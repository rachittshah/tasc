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

### 1.1 Final P0/P1 authority closure

The implemented release sharpens that boundary:

- P0 emits one content-addressed `tasc-shadow-run-plan-v1` only from a
  `SHADOW_ASSESSING` controller snapshot. The plan embeds the exact protocol,
  frozen policy, deterministic window membership, endpoint/profile bindings,
  validity, and aggregate work budget.
- P1 consumes that plan and excludes nonmembers before effects. It cannot
  replace policy/window digests or silently run a conditional-capability
  canary.
- The protocol carries distinct Ed25519 dispatch and collector authorities.
  Dispatch authenticates the pre-call routing intent; collector attestation
  authenticates the complete raw-free final observation and collection
  provenance.
- The plan digest is integrity, not origin attestation. Operator custody and a
  pinned expected digest remain the authority for the P0 artifact.

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
4. **External evaluator:** owns quality scores. TASC verifies producer
   signatures and lineage against an operator-controlled trust store but does
   not assert that a rubric is correct.
5. **Control plane:** performs immutable joins and deterministic decisions. It
   cannot rewrite source evidence.
6. **Experiment proposer:** can suggest one bounded experiment. It cannot change
   frozen gates, holdout membership, evaluator evidence, or production state.
7. **Deployment authority:** a human or existing release system applies or
   rejects recommendations.
8. **Payload store:** raw prompts and responses remain outside TASC by default.
   Evidence contains per-study keyed identities and allowlisted controlled
   references unless an operator explicitly enables encrypted payload capture.
9. **Collector trust policy:** local operator configuration, not an imported
   experiment protocol, is authoritative for endpoints, evaluator keys, payload
   stores, and secret references. A protocol may only narrow that authority.

## 6. Versioned contracts

Every contract uses strict runtime validation, explicit finite bounds,
versioned RFC 8785 JSON Canonicalization Scheme (JCS) bytes, and a content
digest. Unknown fields and non-I-JSON values are rejected so typos or ambiguous
serialization cannot silently weaken an experiment. Cross-language official JCS
vectors define number, Unicode, escaping, and key-order behavior.

### 6.1 `ExperimentProtocol`

`tasc-experiment-protocol-v2` freezes:

- study ID, protocol version, owner, creation time, and expiry;
- deterministic development/holdout membership using a named, seeded
  group-bucket algorithm and online-window membership rules;
- champion and candidate execution profiles;
- model, tokenizer, runtime, backend, hardware, quantization, chat-template,
  orchestration, and deployment-configuration identities;
- route-signal definition, version, range, direction, and calibration digest;
- external evaluator ID, rubric version, calibration digest, producer kind, and
  required trusted key IDs;
- candidate policy space and exact declarative predicates;
- quality, reliability, latency, cost, and coverage gates;
- independent-group and critical-slice minimums;
- bootstrap seed, method, and bounded iteration count;
- shadow sampling budget, concurrency, timeout, retry, and payload policy;
- an explicit cost-allocation model or `unavailable`;
- endpoint requirements that may narrow, but never widen, the local
  `CollectorTrustPolicy`;
- runtime capabilities required by the study.

The protocol digest is derived from canonical content. It is never supplied as a
trusted input. A protocol must be registered through the local trust policy
before it can authorize live work.

### 6.2 `TraceEnvelope`

`tasc-trace-envelope-v2` records one logical execution of one profile for one
case replicate. A paired study therefore produces one envelope per profile for
the same `(caseId, replicateId)`:

- study, protocol, trace, case, group, replicate, split, and collection-window
  IDs;
- source mode: `imported`, `observed`, or `shadow`;
- profile ID, execution-profile digest, policy digest, and route actually
  observed;
- workload and declared traffic weight;
- slice labels;
- route-signal value plus definition and calibration identities;
- ordered transport attempts for this logical profile execution;
- observer timestamps for start, headers, first byte, first meaningful token,
  and completion;
- status, finish reason, partial-output state, abort lifecycle, and normalized
  failure category;
- requested and resolved model identities;
- token usage with source and semantics;
- provider-reported timings and metrics in a separate namespace;
- keyed request, response, and event-stream identities or controlled payload
  references;
- keyed terminal-output ID used by any evaluator evidence;
- collector version.

`TraceEnvelope` contains no evaluator score. Authorization headers, secret
values, raw environment variables, and plain hashes of private payloads are
forbidden. Attempt dispatch state is explicit:
`not_sent | sent_unknown | completed`; a timeout never proves the provider did
not execute a request.

### 6.3 `EvaluatorEvidence`

`tasc-evaluator-evidence-v2` records:

- study, protocol, trace, case, replicate, profile, and split identities;
- evaluator, rubric, calibration, and producer identities;
- score, score range, and optional structured subscores;
- the exact keyed terminal-output ID being scored;
- evidence source digest or allowlisted controlled reference;
- production time, key ID, approved signature algorithm, and signature over
  canonical bytes covering every identity, lineage, score, and source field;
- explicit `missing`, `invalid`, and `abstained` outcomes.

Changing the evaluator, rubric, or calibration makes prior evidence stale for a
new study. Trust state is derived by verification against a local key store,
revocation data, and freshness/clock-skew policy; it is not accepted from the
evidence producer. Production recommendations fail closed for unsigned,
untrusted, revoked, or stale evidence. TASC never converts output log
probabilities into this contract.

### 6.4 `AssessmentDataset`

The evidence join is authoritative on
`(protocolDigest, traceId, profileId, terminalOutputId)`. After that
identity and signature check, policy pairing is authoritative on
`(protocolDigest, caseId, replicateId)` across the required profile IDs. It:

- rejects duplicates and identity conflicts;
- retains failed attempts and missing evaluator evidence;
- recomputes development/holdout membership from the frozen group-bucket rule,
  rejects a trace-declared split that disagrees, and rejects cross-split group
  leakage;
- reports unmatched traces and evidence rather than dropping them;
- preserves source digests;
- separates measured, reported, modeled, and unavailable fields.

A failed terminal execution needs no fabricated evaluator score and contributes
the protocol's preregistered failure score, which is zero in v2. A successful
execution without valid evaluator evidence fails coverage before statistical
inference.

### 6.5 `WindowManifest`

`tasc-window-manifest-v2` seals one offline or shadow-online assessment window:

- protocol and frozen-policy digests;
- event-time start and end;
- ingestion watermark and closure reason;
- deterministic membership rule and membership digest;
- revision and optional predecessor-manifest digest;
- trace-set and evaluator-set digests.

Late evidence creates a new manifest revision linked to its predecessor. An
existing manifest and assessment are never edited in place. Window assessment
recomputes event-time and sampling membership from the manifest and rejects any
declared window ID or membership digest that disagrees.

### 6.6 `PolicyBundle`

A recommendation contains only declarative routing predicates, named execution
profiles, fallback behavior, compatibility version, protocol and policy
digests, issue and expiry times, and optional signer metadata. It contains no
arbitrary code and TASC does not install it.

### 6.7 `AssessmentDecision` and `AssessmentPacket`

A pure `AssessmentDecision` records:

- engine and schema versions;
- protocol, trace-set, evaluator-set, policy, and source digests;
- estimator identifier and parameters;
- case, replicate, independent-group, slice, failure, and missing-evidence
  coverage;
- every gate's operator, threshold, actual value, evidence class, and result;
- all candidate decisions, not only the selected policy;
- warnings, stale conditions, and unavailable metrics;
- attestation state.

The artifact writer wraps that decision in an `AssessmentPacket` whose
completion manifest records exact file bytes, sizes, hashes, schema versions,
and durability level. Pure assessment code never manufactures filesystem
completion evidence.

### 6.8 `AssessmentContext`

Every deterministic decision receives
`tasc-assessment-context-v2` explicitly. It contains:

- `asOf`, used for protocol, evaluator, policy, and evidence freshness;
- the operator trust-policy snapshot digest;
- the evaluator-key revocation snapshot digest;
- its JCS content digest.

Assessment code never reads the wall clock or live trust configuration. The
context digest is bound into every decision and packet.

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

The persisted controller log uses versioned `ControllerEvent` records with
stable event IDs. A `ControllerSnapshot` binds the last applied event, state,
protocol, frozen policy, evidence sets, window manifests, and assessment
digests. Replay is append-only and idempotent, and invalid transitions fail
closed.

State transitions are pure functions of a frozen protocol, versioned events,
and source evidence. Replaying the same content must produce byte-identical
decision JSON apart from explicitly excluded wall-clock envelope metadata.

“Online grading” means repeatedly assessing immutable, sealed windows of live
or shadow traces. A window has an event-time range, ingestion watermark, source
digests, and closure reason. Late evidence creates a new revision; it never
mutates an already attested artifact.

## 8. Statistical method

Decision-affecting order uses a locale-independent UTF-16 code-unit comparator.
`localeCompare` is forbidden in canonicalization, sampling order, tie-breaking,
and artifact order.

Assessment has three structurally separate entry points:

- development nomination may enumerate candidates;
- holdout confirmation requires a nomination and evaluates only its frozen
  policy;
- window assessment requires a frozen policy and a `WindowManifest`.

Holdout and window APIs cannot accept a candidate space. Quality comparison
then follows this exact evidence hierarchy:

1. pair champion and candidate outcomes by `(caseId, replicateId)`;
2. calculate the paired score delta for each replicate;
3. use score zero for a failed terminal execution and fail coverage for a
   successful execution without trusted evaluator evidence;
4. summarize replicate deltas within a case with their median;
5. preserve each case's preregistered traffic weight;
6. calculate each group effect as the traffic-weighted mean of its case effects;
7. calculate the point estimate as the traffic-weighted mean across all case
   effects;
8. resample independent groups uniformly with replacement, retaining the
   original case traffic weights inside every sampled group;
9. recalculate the traffic-weighted estimate inside every draw;
10. use the preregistered two-sided percentile interval and alpha;
11. compare the lower bound with the non-inferiority margin.

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

The collector uses a fetch-compatible Undici transport with a controlled
connection dispatcher, streaming readers, and `AbortSignal`. Vendor SDKs are
avoided because they commonly hide raw frames, first-byte timing, nonstandard
fields, and mid-stream failures.

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
plus evidence source and its exact runtime/model/backend/configuration scope.
Live probes cover registered health, discovery, metrics, and explicit
non-streaming route-canary observations. Streaming framing, terminal usage,
log probabilities, structured output, and cancellation are established only by
the corresponding bounded invocation contract tests or separately scoped live
evidence; a route canary does not prove those dimensions.

Ray Serve and SkyPilot/SkyServe are declarative orchestration descriptors. The
underlying runtime profile still owns the wire contract. P1 will not load
plugins, execute discovery code, import Ray, Kubernetes, or SkyPilot SDKs into
the TypeScript core, or create or mutate deployments.

The shadow runner:

- counterbalances champion/candidate invocation order;
- uses stable replicate and attempt IDs;
- enforces bounded concurrency, per-attempt deadlines, total work budgets, and
  response/event-size limits;
- records durable dispatch intent before sending and preserves
  `not_sent | sent_unknown | completed`;
- binds the P0-selected non-secret authentication reference into the plan and
  signed trace, and HMAC-authenticates resume-authoritative journal records;
- retries only an explicitly retry-safe runtime outcome; ambiguous requests are
  retained and fail coverage rather than being assumed deduplicated;
- aborts outstanding requests on cancellation;
- checkpoints accepted envelopes atomically;
- resumes without duplicating accepted `(case, replicate, profile)` envelopes;
- never logs authentication material;
- sanitizes provider errors before persistence.

## 11. Security and failure handling

- An operator-controlled `CollectorTrustPolicy` allows exact origins, schemes,
  ports, runtime paths, evaluator keys, payload-store roots, and secret
  references. Imported protocols can only narrow it.
- Remote endpoints default to HTTPS and public addresses. Redirects are disabled
  or every hop is fully revalidated. DNS results, IPv4/IPv6 forms, loopback,
  private, link-local, CGNAT, ULA, unspecified, and metadata ranges are checked
  at connection time. A controlled lookup/dispatcher pins a validated address
  for the actual connection while preserving TLS hostname verification, and
  every new connection is revalidated. Local inference requires an exact
  loopback-origin opt-in.
- Authentication is supplied through environment-variable references or an
  injected header factory. Secret values never enter parsed config or artifacts.
- Raw payload identity defaults to a per-study HMAC whose key is never
  serialized. Controlled references are limited to configured store schemes and
  roots; inline, `file:`, and arbitrary URL references are forbidden.
- Bounded, fatal-UTF-8 parsing occurs before materialization. JSON, SSE, NDJSON,
  metrics, headers, and output files have strict byte, depth, key, token,
  string, line, event, item, and duration limits. Duplicate JSON keys and
  compressed responses are rejected.
- Work estimates are calculated before candidate expansion, bootstrap, or live
  calls. Inputs exceeding the budget fail before partial execution.
- Artifact output rejects symlinks and existing targets, verifies realpath
  containment, uses a same-parent `0700` staging directory and exclusive `0600`
  files, fsyncs content, writes a manifest of exact byte sizes/hashes last,
  fsyncs the directory, atomically renames, and fsyncs the parent. Platforms
  lacking a guarantee report degraded durability.
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
tasc assess development --protocol ... --traces ... --evidence ... --context ... --out ...
tasc assess holdout --protocol ... --traces ... --evidence ... --context ... --nomination ... --out ...
tasc assess window --protocol ... --traces ... --evidence ... --context ... --policy ... --window ... --out ...
tasc experiment next --assessment ... --history ... --out ...
tasc runtime probe --endpoint ... --runtime ...
tasc shadow run --plan ... --plan-digest <operator-pinned-sha256> --cases ... --profiles ... --trust ... --identity ... --out ...
tasc --help
tasc --version
```

`--plan-digest` is an independently custodied P0 approval value. P1 must not
derive or copy it from the plan it is being asked to execute.

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
- a deliberate public package manifest with scoped public access; publishing is
  not attempted until the repository's protected trusted-publisher environment
  is configured;
- release notes, migration guide, architecture, threat model, runtime support
  matrix, operating guide, and contribution instructions;
- a public-package release workflow using protected OIDC trusted publishing:
  build and test one tarball, record its SHA-512, and publish that exact tarball
  only from the verified tagged commit.

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
- one explicitly authorized real endpoint call is recorded manually as a
  sanitized trace without secret leakage; CI never calls an arbitrary live
  endpoint;
- Codex specialty reviews and Claude Code review have no unresolved critical or
  important findings;
- the pull request documents the trust boundary, verification evidence,
  limitations, and follow-up work.
