# TASC architecture

- Status: implemented
- Architecture: out-of-band trace-control plane with bounded inference effects
- Authority: evidence and recommendation only; no deployment authority

## Design objective

TASC answers a narrow inference R&D question:

> Given paired outcomes from exact inference profiles and independently
> verified evaluator evidence, which preregistered routing policy can be frozen
> on development and survive a disjoint holdout or sealed online window?

It does not answer this with a blended benchmark score or another judge-model
wrapper. The system preserves the lineage between dispatch intent, inference
outcome, external evaluator evidence, policy replay, assessment context, and
the final review artifact.

## P0 and P1

The architecture separates decision authority from effects.

### P0: out-of-band authority

P0 owns:

- protocol, profile, evaluator, route-signal, gate, split, and sampling
  definitions;
- dispatch/evaluator signature verification and local trust snapshots;
- deterministic evidence joins and diagnostics;
- development policy enumeration and selection;
- exact-policy holdout and sealed-window assessment;
- controller state and checkpoint replay;
- self-contained shadow-run plans issued only from `SHADOW_ASSESSING`;
- bounded next-experiment proposals; and
- immutable raw-free artifact publication.

P0 does not open model connections, score outputs, register protocols,
configure endpoints, or deploy routes.

### P1: bounded inference effects

P1 owns:

- exact runtime capability probes;
- bounded JSON/SSE/NDJSON inference requests;
- observer timing, usage, provider-ID, failure, and payload-identity capture;
- stable paired/counterbalanced shadow execution; and
- crash-safe durable collection state.

P1 cannot select or grade a policy. For paired collection it consumes one
self-contained P0 plan binding the controller snapshot, protocol, frozen
policy, window membership, endpoint/profile targets, validity, and aggregate
work budget. Runtime secrets remain separate references. P1 returns traces.

```text
controller snapshot + protocol + frozen policy
          |
          v
  P0 emits content-addressed plan +
          |                       |
          | exact bounded effect  v
          +--------------------> P1 inference
                                  |
                                  | signed raw-free traces
                                  v
external evaluator evidence --> P0 join/assessment
                                  |
                                  v
                          review artifacts only
```

This keeps live calls subordinate to evaluation. No serving request waits on a
TASC decision.

## Core contracts

### Experiment protocol

`ExperimentProtocol` freezes:

- study/version/owner and validity interval;
- distinct Ed25519 dispatch and collector authorities;
- seeded group development/holdout partition;
- seeded basis-point online membership;
- complete execution-profile identities;
- champion and candidate roles;
- route-signal definition and calibration digest;
- evaluator, rubric, calibration, producer, and required trusted keys;
- finite declarative routing predicates;
- independent gates and critical slices;
- grouped-bootstrap configuration;
- shadow execution ceilings and payload policy;
- cost evidence semantics;
- endpoint requirements; and
- required runtime capabilities.

An execution profile binds runtime/backend builds, model/tokenizer revisions,
hardware, quantization, chat template, orchestration, and deployment
configuration. A friendly endpoint alias cannot relabel that identity.

### Trace envelope

`TraceEnvelope` is a request-level inference observation. It records keyed
identities rather than payload bytes, plus:

- study/protocol/case/group/replicate/split/window lineage;
- the P0 shadow-plan, endpoint-binding, route, nullable non-secret
  authentication reference, and capability-receipt lineage for shadow
  observations;
- exact profile and policy digests;
- route-time signal and provenance;
- workload shape and traffic weight;
- a pre-dispatch signed intent;
- ordered attempts with `not_sent`, `sent_unknown`, or `completed`;
- observer timings, status, abort lifecycle, model identity, usage, cost, and
  allowlisted provider metrics; and
- the keyed terminal-output identity; and
- a separate collector signature over the complete raw-free final observation.

The dispatch signature covers every routing and workload field that can affect
replay before an inference call starts. Attempts and outputs are excluded from
that pre-dispatch preimage because they do not yet exist. The collector
signature covers those final attempts, timing, usage, cost, output identity,
collector version, dispatch signature, and collection provenance. Dispatch and
collector keys must be distinct.

### Evaluator evidence and trust

`EvaluatorEvidence` is produced outside TASC. It binds one terminal output
identity to an evaluator outcome and contains evaluator/rubric/calibration/
producer identity, production time, key ID, and Ed25519 signature.

An `AssessmentContext` binds an explicit `asOf` time to fingerprints of the
operator trust policy and revocation view. Verification checks:

- canonical signature and public key;
- key purpose and producer/evaluator authorization;
- rubric and calibration authorization;
- key validity and revocation;
- freshness and future skew; and
- exact context/trust fingerprints.

Verification creates an in-process authentic receipt. The join rejects
lookalike caller-authored receipts, unpinned keys, lineage drift, duplicates,
conflicts, or orphan evidence.

TASC has no judge prompt or evaluator client. An external model evaluator is
just one producer kind; its operation and calibration remain outside this
repository.

### Joined assessment dataset

`joinAssessmentEvidence`:

1. preflights row cardinality and work;
2. verifies each trace against the protocol, dispatch authority, and final
   collector attestation;
3. recomputes development/holdout membership;
4. verifies trace/profile/route/evaluator lineage;
5. joins trusted evidence to successful terminal outputs;
6. preserves failures, ambiguous sends, missing scores, abstentions,
   duplicates, conflicts, and missing profiles as explicit states;
7. computes split, group, slice, case, replicate, traffic, trace-set, evaluator-
   set, and dataset identities; and
8. returns a recursively frozen, process-authenticated dataset.

Serialized joined datasets are not trusted on reload. Sources must be parsed,
verified, and joined again.

## Assessment flow

### Development

Development is the only search phase. TASC enumerates one fast-only policy per
candidate profile and one cascade per preregistered predicate. The expert-only
champion remains the control.

Replay uses measured paired executions:

- fast-only selects the candidate outcome;
- expert-only selects the champion;
- a cascade selects the expert when its one route predicate fires;
- a primary terminal failure escalates;
- serial fallback retains both attempts' measured cost and latency; and
- unavailable or ambiguous outcomes stay unavailable.

Each candidate receives independent gates for mean score, paired grouped
non-inferiority, critical-slice group coverage, failure rate, P95 TTFT, P95
end-to-end latency, cost, evidence coverage, and independent group count.
Service capacity is deferred to a sealed exact-policy window. No weighted
aggregate can offset a failed gate.

Passing candidates are ranked by measured cost, then end-to-end latency, then a
locale-independent policy digest. The result is either `NOMINATED`,
`NO_CANDIDATE`, `INSUFFICIENT_EVIDENCE`, or `STALE`.

### Holdout

Holdout accepts one authentic development nomination. It revalidates the
persisted nomination by rerunning development from source evidence, verifies
group partitioning and context lineage, and assesses only the frozen policy.
There is no API that enumerates or retunes on holdout.

### Sealed online window

A `WindowManifest` binds:

- exact frozen policy and protocol;
- half-open event-time bounds and ingestion watermark;
- deterministic membership rule and digest;
- revision and predecessor;
- trace/evaluator-set digests; and
- exact-policy capacity evidence.

Assessment recomputes membership for every trace, validates event and
completion times, verifies accepted evidence is within the watermark, and
replays exactly one frozen policy. Late evidence creates a linked manifest
revision; it never mutates a sealed revision.

Operator-reported capacity is not promoted to measured capacity merely because
the manifest self-digest is valid. Until a trusted exact-policy measurement
receipt exists, a required capacity gate remains unavailable and the window
returns `INSUFFICIENT_EVIDENCE`.

## Statistical model

Quality inference is paired by case and replicate, summarized within case, and
bootstrapped over independent groups with the protocol's fixed seed,
iterations, and alpha. Original traffic weights are retained. Replicates or
correlated cases do not become independent samples.

Operational metrics use declared traffic weights and preserve their evidence
class: measured, provider-reported, modeled, or unavailable. A missing value is
not zero. Failed terminal executions are visible protocol outcomes rather than
dropped rows.

The estimator is deterministic for the same canonical protocol, verified
sources, and assessment context. It does not claim that the supplied traffic
weights or groups are representative; that is an operator review obligation.

## Controller and bounded experiment loop

The event-sourced controller records facts such as registration, collection,
development readiness, development/holdout/window decisions, window manifests,
identity drift, deployment observations, and retirement. Events and snapshots
are content-addressed, replayed in order, bounded in count, and verified
against pinned checkpoints.

`proposeExperiment` converts an assessment into one bounded intent. It can
diagnose insufficient evidence, evaluator drift, quality or slice regression,
latency, failure, cost, unavailable capacity, capability mismatch, or the need
for sealed-shadow replication. The proposal freezes controls, states required
evidence, carries a first-budget-limit stop condition, and sets
`operator-registration-required`.

This is the agentic loop:

```text
assessment → diagnosis → bounded hypothesis → operator registration
     ^                                           |
     |              new signed evidence          |
     +-------------------------------------------+
```

The proposer does not edit the protocol, choose infrastructure, call an
evaluator, execute the experiment, accept evidence, or deploy a result.

## Runtime collection

Runtime profiles contain build-pinned route and capability declarations. The
implementation has explicit codecs for OpenAI-shaped and native runtime
contracts; shared JSON shape does not imply shared terminal, usage, streaming,
or error semantics.

Before contact, P1 validates:

- the P0 plan, controller state, frozen policy, online membership, validity,
  and aggregate work admission;
- runtime capability and exact route;
- endpoint alias/origin and orchestration descriptor, including mode-specific
  Ray application/deployment, SkyPilot cluster, or SkyServe service identity;
- instance/profile identity;
- effect (`non-mutating`, `inference-canary`, or `consumptive`);
- request/generation/media bounds;
- the P0-pinned authentication reference as non-secret provenance (never the
  credential value);
- authorization TTL and whole-operation deadline; and
- caller-owned aggregate work limits.

Automatic conditional-capability canaries are not part of a shadow run. They
would be separate potentially billable effects with their own admission and
receipt. The v1 shadow plan therefore admits only build-pinned routes whose
capability is already `supported`; conditional observation remains available
through the explicit runtime-probe operation.

Prepared invocation authority is private, one-shot, and expiring. Visible
metadata cannot be copied into a new authorized request. Network policy pins
the accepted IP into the actual connection, retains TLS hostname validation,
rejects disallowed address classes, and disables redirects. See
[runtime support](runtime-support.md) and the [threat model](threat-model.md).

## Shadow crash semantics

The shadow collector derives replicate identities and applies the plan's
deterministic online membership before profile fan-out. Excluded replicates are
reported with zero effects. It then accounts for the complete admitted
Cartesian work before signing, filesystem, or network effects: cases,
profiles, replicates, logical
executions, attempts, calls, request/response bytes, durable records,
concurrency, and wall clock.

Its immutable lifecycle is:

```text
intent → send lease → outcome → accepted trace → complete marker
```

- intent exists before contact;
- a send lease marks the ambiguity boundary;
- an outcome records what P1 can prove;
- acceptance records the verified trace;
- completion closes the logical execution.

On resume:

- an accepted trace is deduplicated;
- outcome without acceptance is deterministically rebuilt;
- an expired lease without outcome becomes `sent_unknown`;
- `sent_unknown` is never retried; and
- only proven `not_sent` may consume another already-budgeted attempt.

This favors honest missing coverage over duplicate inference calls. Durable
records never contain prompt/output bytes, authorization values, HMAC keys, or
dispatch private keys.

## Artifact custody

Artifact packets are immutable directories published under an existing trusted
root. Payloads are snapshotted, bounded, written with restrictive modes,
flushed where supported, hashed, and followed by a manifest written last.
Publication is atomic within the cooperative namespace. Resume may verify an
identical packet but never overwrite a different one.

Verification checks the exact allowlist, file modes, sizes, payload digests,
packet digest, manifest self-digest, target binding, final metadata custody, and
an optional pinned manifest digest. Readers receive copy-returning closures over
the final verified bytes.

Every manifest embeds `evidence-only-no-deployment-authority`. Hash integrity is
not attestation. Pure Node's path API also cannot eliminate every hostile
same-UID namespace replacement race; the manifest declares that residual
limitation.

## Work and input bounds

Every expansion point has caller-owned ceilings:

- byte/depth/key/item/token/string/number limits for JSON and NDJSON;
- trace/evidence/candidate/bootstrap/group/total assessment work;
- experiment history and logical/attempt/cost/wall-clock budgets;
- protocol and controller collection cardinality;
- HTTP request/header/body/chunk/frame/deadline limits;
- shadow request/response/record/network/concurrency/wall-clock budgets; and
- artifact member/count/total-byte limits.

Admission happens before expensive allocation or effects. Numeric arithmetic is
checked for finite safe bounds. Error persistence uses allowlisted categories
and never reflects provider or input bodies.

## Source map

| Area | Implementation |
| --- | --- |
| Contracts and signatures | `src/evidence.ts`, `src/assessment-context.ts`, `src/evaluator-trust.ts` |
| Join and split discipline | `src/evidence-join.ts`, `src/window.ts` |
| Policy replay and assessment | `src/policy.ts`, `src/assessment.ts`, `src/statistics.ts` |
| Controller and experiments | `src/controller*.ts`, `src/experiments.ts` |
| Artifact custody | `src/artifacts.ts` |
| Bounded input and redaction | `src/bounded-input.ts`, `src/redaction.ts`, `src/references.ts` |
| Runtime effects | `src/runtime/` |
| CLI | `src/cli.ts`, `src/cli-v2.ts`, `src/cli-args.ts` |
| Legacy adapter | `src/schema.ts`, `src/evaluate.ts`, `src/report.ts` |

## Legacy compatibility

Legacy v1 measurement-matrix confirmation remains capped at `HOLD` for real
evidence. Migrate new studies to v2 for signed trace/evaluator lineage,
sealed-window assessment, and the P0/P1 runtime boundary.

## Non-goals

- synchronous production routing;
- a generic model/evaluator SDK;
- an LLM-as-judge or reward-model package;
- autonomous prompt, evaluator, gate, or holdout tuning;
- cluster, model-server, autoscaling, or deployment mutation;
- inference from unpaired aggregate benchmark tables;
- raw payload or credential persistence; and
- treating a digest, signature, `PASS`, or human recommendation as deployment
  authority.
