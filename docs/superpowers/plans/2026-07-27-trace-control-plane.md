# TASC Trace Control Plane Implementation Plan

> **For Codex:** REQUIRED SUB-SKILL: Use
> `superpowers:subagent-driven-development` to execute this plan task by task.
> Every production-code change follows `superpowers:test-driven-development`;
> every task receives spec-compliance and code-quality review before the next
> task starts.

**Goal:** Ship TASC as a production-shaped, out-of-band inference trace
controller with externally supplied evaluator evidence, deterministic
offline/shadow policy assessment, runtime-specific live collection, and a green,
publishable repository.

**Architecture:** Keep the deterministic core network-free. Add strict evidence
v2 contracts and a deterministic join, repair the existing statistical and
provenance defects, build a resumable controller over immutable windows, then
add an optional raw-HTTP collector whose runtime profiles describe real
capability differences. Ray and SkyPilot remain endpoint/orchestration
descriptors. All deployment changes remain outside TASC.

**Tech stack:** TypeScript 5.x, Node.js 22/24, a fetch-compatible Undici
transport with controlled DNS dispatch, Zod 3, Vitest 4, Node filesystem/crypto
primitives, Python `unittest` for the optional MLX runner, GitHub Actions.

**Design source:** `docs/superpowers/specs/2026-07-27-trace-control-plane-design.md`

## Global constraints

- TASC MUST NOT implement a judge model, judge prompt package, or evaluator
  score generator.
- `TraceEnvelope` MUST NOT contain evaluator scores. `EvaluatorEvidence` is the
  only external quality-score input.
- The route-time signal and evaluator score MUST have separate types,
  identities, calibration provenance, and lifecycle.
- P0 is the out-of-band controller. Network model calls are optional P1 and
  MUST NOT infect the deterministic core.
- Tasks 1–9 form a complete, green P0 commit boundary before Task 10 starts P1.
  P1 is layered onto the same requested draft PR without leaving P0 dependent on
  runtime code.
- “Online” means deterministic assessment of sealed live/shadow windows. TASC
  MUST NOT make a synchronous production routing decision.
- TASC MUST NOT create, mutate, promote, roll back, or delete Ray, SkyPilot,
  Kubernetes, cloud, or inference deployments.
- Ray and SkyPilot describe orchestration around an underlying runtime; they
  are not inference wire protocols.
- Runtime behavior MUST be capability-probed by runtime/build/backend/model
  identity. “OpenAI compatible” is not sufficient evidence.
- Observer values, provider-reported values, modeled values, and unavailable
  values MUST remain distinguishable.
- Per-request decode rate MUST NOT be represented as aggregate service
  throughput. A cascade has no capacity result without measured window-level
  evidence.
- Decision-affecting ordering MUST use the locale-independent comparator.
  `localeCompare` is forbidden in canonicalization, sampling, candidate
  ordering, tie-breaking, proposals, and artifact ordering.
- Every input collection, response stream, bootstrap, candidate expansion,
  output file, and live run MUST be bounded.
- A caller-supplied `WorkBudget` MUST be threaded through parsing, joining,
  candidate generation, bootstrap, artifacts, CLI reads, and collection; a
  standalone estimator is not enforcement.
- Secrets MUST be referenced, never serialized. Persisted errors MUST be
  sanitized. Private payload identity uses a nonserialized per-study HMAC;
  plain payload hashes are forbidden.
- Imported protocols can only narrow the local operator-controlled trust policy.
  They cannot authorize endpoints, evaluator keys, stores, or secrets.
- Existing synthetic nomination/confirmation remains runnable and
  `DEMO_ONLY`; legacy v1 evidence cannot make a new production recommendation.
- No production function is written before its covering test has been observed
  failing for the intended reason.
- Each task ends in a meaningful commit after targeted verification. No empty
  commits.

---

### Task 1: Locale-independent determinism and bounded work

**Files:**

- Create: `src/determinism.ts`
- Create: `src/work-budget.ts`
- Create: `tests/determinism.test.ts`
- Create: `tests/work-budget.test.ts`
- Modify: `src/integrity.ts`
- Modify: `src/policy.ts`
- Modify: `src/evaluate.ts`
- Modify: `src/report.ts`
- Modify: `src/index.ts`

**Step 1: Write failing determinism tests**

Test an exported `compareCodeUnits(left, right)` against ASCII, accented,
numeric-looking, prefix, and surrogate-pair IDs. Specify versioned RFC 8785 JCS
canonical bytes using official cross-language vectors for numbers, Unicode,
escaping, key order, and rejected non-I-JSON values. Test canonical JSON,
candidate ordering, tie-breaking, and serialized artifact bytes/digests in child
Node processes under `LANG` and `LC_ALL` values `C`, `en_US.UTF-8`, and
`sv_SE.UTF-8`. Assert the subprocess-resolved Swedish collation differs so the
regression test proves it exercises the original failure mode.

**Step 2: Verify RED**

Run:

```bash
npx vitest run tests/determinism.test.ts
```

Expected: FAIL because the comparator does not exist and decision paths still
use `localeCompare`.

**Step 3: Implement locale-independent ordering**

Implement a plain UTF-16 code-unit comparator and replace every
decision-affecting `localeCompare`. Implement JCS as the canonical identity
algorithm and keep `stableJson` only as a compatibility alias with documented
version semantics.

**Step 4: Write failing work-budget tests**

Specify `estimateAssessmentWork()` and `assertWithinWorkBudget()` behavior for
candidate count, trace/evidence rows, bootstrap draws, independent groups, and
their checked product. Test integer overflow, negative/NaN inputs, exact limits,
and an oversized Cartesian workload that fails before allocation.

**Step 5: Verify RED, implement, and verify GREEN**

Run:

```bash
npx vitest run tests/work-budget.test.ts
npx vitest run tests/determinism.test.ts tests/work-budget.test.ts tests/evaluate.test.ts tests/policy.test.ts
```

**Step 6: Commit**

```bash
git add src tests
git commit -m "fix(core): make decisions portable and bounded"
```

---

### Task 2: Evidence v2 contracts and canonical identities

**Files:**

- Create: `src/evidence.ts`
- Create: `src/evaluator-trust.ts`
- Create: `src/assessment-context.ts`
- Create: `tests/evidence.test.ts`
- Create: `tests/evaluator-trust.test.ts`
- Create: `tests/assessment-context.test.ts`
- Create: `tests/fixtures/evidence.ts`
- Modify: `src/index.ts`

**Step 1: Write failing contract tests**

Specify strict parsers for:

- `tasc-experiment-protocol-v2`;
- `tasc-trace-envelope-v2`;
- `tasc-evaluator-evidence-v2`;
- `tasc-assessment-context-v2`.

Use wished-for public APIs:

```ts
parseExperimentProtocol(input)
parseTraceEnvelope(input)
parseEvaluatorEvidence(input)
verifyEvaluatorEvidence(evidence, trustSnapshot, assessmentContext)
parseAssessmentContext(input)
fingerprintExecutionProfile(profile)
fingerprintProtocol(protocol)
```

Tests must prove:

- trace attempts cannot accept `taskScore`, evaluator, or secret/header fields;
- one trace envelope represents one logical execution of one profile for one
  `(caseId, replicateId)` and contains ordered retry attempts;
- evaluator evidence binds protocol, trace, case, replicate, profile, rubric,
  calibration, keyed terminal-output ID, and evidence digest/reference;
- Ed25519 verification covers canonical bytes for every identity, lineage,
  outcome, score, source, and production-time field;
- trusted, unknown, revoked, stale, future-dated, malformed, and wrong-key
  signatures produce explicit derived trust results; trust is never an input
  claim;
- route-signal provenance is distinct from evaluator provenance;
- protocol split membership names and configures the exact seeded group-bucket
  algorithm;
- assessment context supplies `asOf`, operator trust-policy snapshot digest,
  evaluator-revocation snapshot digest, and its JCS digest; no deterministic
  path may read the wall clock;
- profile fingerprints change with runtime build, backend, model/tokenizer
  revision, hardware, quantization, template digest, or orchestration;
- unknown fields, duplicate profiles, malformed slugs/digests/timestamps,
  non-finite numbers, oversized arrays/strings, invalid timing order, and
  inconsistent profile references fail;
- canonical digests do not depend on object-key insertion order.

Build shared valid protocol/trace/evaluator factories with narrow mutation
helpers in `tests/fixtures/evidence.ts`; later tasks reuse them rather than
copying large strict contracts.

**Step 2: Verify RED**

```bash
npx vitest run tests/evidence.test.ts
```

**Step 3: Implement the smallest strict contracts**

Use bounded Zod schemas plus semantic checks and the caller's `WorkBudget`.
Represent token usage as
`{ value, source, semantics, tokenizerDigest? }`. Keep observer timings and
provider timings in different fields. Represent cost as measured/modeled/
provider-reported/unavailable with a model digest where applicable. Payload
identity is a per-study HMAC/key ID or an allowlisted controlled reference.
`TraceEnvelope` has a top-level profile ID and no score. Keep assessment,
window, and policy-bundle output schemas in the tasks that own their behavior.

**Step 4: Verify GREEN and public declarations**

```bash
npx vitest run tests/evidence.test.ts tests/evaluator-trust.test.ts tests/assessment-context.test.ts tests/public-api.test.ts
npm run typecheck
```

**Step 5: Commit**

```bash
git add src/evidence.ts src/evaluator-trust.ts src/assessment-context.ts src/index.ts tests
git commit -m "feat(evidence): add immutable trace and evaluator contracts"
```

---

### Task 3: Deterministic evidence join and coverage diagnostics

**Files:**

- Create: `src/evidence-join.ts`
- Create: `tests/evidence-join.test.ts`
- Modify: `src/evidence.ts`
- Modify: `src/index.ts`

**Step 1: Write failing join tests**

Specify:

```ts
joinAssessmentEvidence(protocol, traces, verifiedEvaluatorEvidence, workBudget)
```

Join evaluator evidence to a logical profile execution on
`(protocolDigest, traceId, profileId, terminalOutputId)`, then pair required
profiles for policy replay on `(protocolDigest, caseId, replicateId)`. Retain
failures and report:

- matched rows;
- missing, invalid, or abstained evaluator evidence;
- orphan evaluator rows;
- duplicate and conflicting rows;
- case/replicate/group/slice counts;
- observed traffic mass;
- split and protocol identity.

Test shuffled input determinism, cross-split group leakage, duplicate evidence,
profile drift, route-signal drift, evaluator/rubric/calibration drift, missing
profile executions, mismatched replicate IDs, terminal-output mismatches,
untrusted signatures, and evidence for failed attempts. A failed terminal
execution receives the protocol's score zero without fabricated evidence; a
successful execution without trusted evidence fails coverage.
Evidence signed by a locally trusted key still fails when its `keyId` is not
pinned by the protocol's `evaluator.requiredTrustedKeyIds`; Task 2 verification
has no protocol argument, so this pinning belongs at the Task 3 join boundary.

Recompute development/holdout membership with the protocol's seeded
group-bucket algorithm. Reject trace-declared splits that disagree and prove all
members of one group resolve to one split.

**Step 2: Verify RED**

```bash
npx vitest run tests/evidence-join.test.ts
```

**Step 3: Implement strict immutable joining**

Return frozen/copy-safe structures and sorted diagnostics. Never silently drop
an unmatched row. Reject identity conflicts; represent legitimate missing or
abstained scores explicitly. Enforce the caller's budget before maps or paired
matrices are allocated.

**Step 4: Verify GREEN**

```bash
npx vitest run tests/evidence-join.test.ts tests/evidence.test.ts
npm run typecheck
```

**Step 5: Commit**

```bash
git add src/evidence.ts src/evidence-join.ts src/index.ts tests
git commit -m "feat(evidence): join traces and evaluator scores deterministically"
```

---

### Task 4: Repair paired inference and legacy safety claims

**Files:**

- Modify: `src/statistics.ts`
- Modify: `src/policy.ts`
- Modify: `src/evaluate.ts`
- Modify: `src/schema.ts`
- Modify: `src/report.ts`
- Modify: `tests/statistics.test.ts`
- Modify: `tests/evaluate.test.ts`
- Modify: `tests/policy.test.ts`
- Modify: `tests/schema.test.ts`
- Modify: `tests/cli.test.ts`

**Step 1: Write failing adversarial tests**

Add tests proving:

- legacy replicate-index deltas are paired before case summarization;
- many correlated cases in one group do not count as independent samples;
- duplicated correlated cases cannot narrow the interval;
- low-weight wins cannot hide one high-traffic regression;
- fewer than the configured independent-group minimum fails closed;
- critical-slice group coverage is reported and enforced;
- a serial cascade has `serviceThroughput: unavailable`, not the final
  profile's per-request token rate;
- legacy real v1 evidence cannot emit `READY_FOR_MANUAL_PRODUCTION`;
- locale variants reproduce the same nomination and digest.

**Step 2: Verify RED**

```bash
npx vitest run tests/statistics.test.ts tests/evaluate.test.ts tests/policy.test.ts
```

**Step 3: Implement the preregistered estimator**

For the legacy adapter only, map each replicate index to a stable internal ID.
Pair by `(caseId, replicateId)`, calculate each delta, take the median delta
within each case, calculate each group effect as the traffic-weighted mean of
its case effects, and calculate the point estimate as the traffic-weighted mean
across all cases. For every bootstrap draw, sample independent groups uniformly
with replacement and recalculate the estimate using original case traffic
weights. Use the configured two-sided percentile interval and alpha. Missing
successful scores fail coverage before inference; terminal failures score zero.
Report method, alpha, case/replicate/group counts, effective traffic mass,
deltas, estimate, interval, iterations, and seed.

Remove cascade capacity inference. Keep request-level perceived decode rate only
where measured. Make required unavailable capacity gates fail closed.

Cap all v1 non-synthetic confirmations at `HOLD` with a migration reason; keep
synthetic `DEMO_ONLY`.

**Step 4: Verify GREEN**

```bash
npx vitest run tests/statistics.test.ts tests/evaluate.test.ts tests/policy.test.ts tests/schema.test.ts tests/cli.test.ts
npm run typecheck
```

**Step 5: Commit**

```bash
git add src tests
git commit -m "fix(assessment): use grouped paired inference"
```

---

### Task 5: Evidence v2 policy replay and assessment engine

**Files:**

- Create: `src/assessment.ts`
- Create: `src/window.ts`
- Create: `tests/assessment.test.ts`
- Create: `tests/window.test.ts`
- Modify: `src/evidence.ts`
- Modify: `src/evidence-join.ts`
- Modify: `src/policy.ts`
- Modify: `src/statistics.ts`
- Modify: `src/index.ts`

**Step 1: Write failing end-to-end assessment tests**

Specify phase-safe entry points:

```ts
nominateDevelopment(protocol, joinedDataset, assessmentContext, workBudget)
confirmHoldout(protocol, joinedDataset, nomination, assessmentContext, workBudget)
assessPolicyWindow(protocol, joinedDataset, frozenPolicy, windowManifest, assessmentContext, workBudget)
```

`confirmHoldout` and `assessPolicyWindow` cannot accept or enumerate a candidate
space. Define the pure `AssessmentDecision` and `PolicyBundle` schemas here,
where their behavior exists. The filesystem `AssessmentPacket` belongs to Task
6.

Test expert-only, fast-only, and cascade replay; primary failure escalation;
missing route signals; critical slices; paired quality; traffic-weighted
latency/error/cost; evaluator abstention; protocol expiry; profile/evaluator
staleness; missing capacity evidence; coverage failure; deterministic candidate
selection; and preservation of rejected candidates.

Define `tasc-window-manifest-v2` with event-time bounds, ingestion watermark,
membership rule/digest, closure reason, revision, predecessor digest,
trace/evaluator-set digests, protocol digest, and frozen-policy digest. Test
late-evidence revisions and digest mismatches. Recompute event-time and sampling
membership; reject trace-declared window IDs or membership digests that disagree.

The result must use statuses:

```text
INSUFFICIENT_EVIDENCE | NO_CANDIDATE | NOMINATED | PASS | HOLD | STALE
```

No status changes production.

**Step 2: Verify RED**

```bash
npx vitest run tests/assessment.test.ts tests/window.test.ts
```

**Step 3: Implement replay and hard gates**

Use only joined evidence. Keep attempted-profile latency/cost conservative.
Label every metric's evidence class. A weighted score cannot compensate for a
failed hard gate. Select only on development; assess one frozen policy on
holdout or online windows. Bind the assessment context digest to every decision
and use its `asOf` for all expiry/freshness checks.

**Step 4: Verify GREEN**

```bash
npx vitest run tests/assessment.test.ts tests/window.test.ts tests/evidence-join.test.ts tests/evaluate.test.ts
npm run typecheck
```

**Step 5: Commit**

```bash
git add src tests
git commit -m "feat(assessment): evaluate frozen policies from trace evidence"
```

---

### Task 6: Resumable controller and sealed online windows

**Files:**

- Create: `src/controller.ts`
- Create: `src/controller-events.ts`
- Create: `src/artifacts.ts`
- Create: `tests/controller.test.ts`
- Create: `tests/artifacts.test.ts`
- Modify: `src/evidence.ts`
- Modify: `src/index.ts`

**Step 1: Write failing state-machine tests**

Specify pure transitions for:

```text
DRAFT -> REGISTERED -> COLLECTING -> DEV_READY -> NOMINATED
      -> SHADOW_ASSESSING -> HOLDOUT_CONFIRMED
      -> PROMOTION_RECOMMENDED -> MONITORING
```

Define versioned `ControllerEvent` and `ControllerSnapshot` schemas. Test
append/replay semantics, stable event IDs, duplicate-event idempotence,
event-order rejection, snapshot recovery, and explicit mappings from assessment
outcomes to states. Also test `HOLD`, `STALE`, `ROLLBACK_RECOMMENDED`, and
terminal `RETIRED`; invalid transitions; protocol expiry; evaluator/profile
drift; sealed window manifests; late-evidence revisions; and byte-identical
decisions from the same valid event log.

**Step 2: Write failing artifact fault tests**

Inject crashes before and after each file, manifest, and rename operation. Prove
the final output is either absent or complete. Verify lstat/realpath containment,
symlink rejection for every path component, existing-target rejection,
same-parent `0700` staging, `0600` `wx` files, exact-byte hashes and sizes,
manifest allowlist and manifest-last semantics, file/manifest/directory fsync,
parent fsync after rename, cleanup, and an explicit degraded-durability result on
platforms that cannot promise the operation.

Define `AssessmentPacket` here as the pure `AssessmentDecision` plus packet
metadata and completion manifest. The writer, not assessment code, creates
filesystem completion evidence.

**Step 3: Verify RED**

```bash
npx vitest run tests/controller.test.ts tests/artifacts.test.ts
```

**Step 4: Implement controller and atomic packets**

First implement and commit the artifact writer behind dependency-injected
filesystem primitives so crash behavior is testable without test-only
production APIs. Migrate every legacy writer; do not leave a weaker parallel
path. Then implement and commit the pure event reducer, append/replay logic, and
snapshot validation.

**Step 5: Verify GREEN**

```bash
npx vitest run tests/controller.test.ts tests/artifacts.test.ts
npm run typecheck
```

**Step 6: Commit in independently revertible parts**

```bash
git add src/artifacts.ts src/report.ts tests/artifacts.test.ts
git commit -m "feat(artifacts): write durable evidence packets"

git add src/controller.ts src/controller-events.ts src/evidence.ts src/index.ts tests/controller.test.ts
git commit -m "feat(controller): add sealed shadow assessment windows"
```

---

### Task 7: Agentic next-experiment protocol

**Files:**

- Create: `src/experiments.ts`
- Create: `tests/experiments.test.ts`
- Modify: `src/report.ts`
- Modify: `src/index.ts`

**Step 1: Write failing proposal tests**

Specify:

```ts
proposeExperiment(assessment, history, budget)
```

Test stable diagnosis priority for insufficient evidence, evaluator drift,
quality regression, critical-slice regression, TTFT, tail latency, errors,
cost, unavailable capacity, and capability mismatch. Every proposal must contain
one hypothesis, one changed variable, frozen controls, evidence requirements,
budget, stop condition, expected decision, and parent assessment digest.

Test duplicate-protocol rejection, holdout-tuning rejection, over-budget
rejection, and stable ordering. Confirm that no proposal contains evaluator
scores, judge prompts, deployment actions, or claimed unmeasured gains.

**Step 2: Verify RED**

```bash
npx vitest run tests/experiments.test.ts
```

**Step 3: Implement deterministic proposal generation**

Use explicit decision tables, not an LLM. Preserve the existing v1 proposal API
as a compatibility wrapper whose output is marked legacy.

**Step 4: Verify GREEN**

```bash
npx vitest run tests/experiments.test.ts tests/evaluate.test.ts
npm run typecheck
```

**Step 5: Commit**

```bash
git add src tests
git commit -m "feat(agent): propose bounded inference experiments"
```

---

### Task 8: Security primitives for untrusted evidence

**Files:**

- Create: `src/bounded-input.ts`
- Create: `src/redaction.ts`
- Create: `src/references.ts`
- Create: `tests/bounded-input.test.ts`
- Create: `tests/redaction.test.ts`
- Create: `tests/references.test.ts`
- Modify: `src/evidence.ts`
- Modify: `src/index.ts`

**Step 1: Write failing bounded-input tests**

Specify a byte-limited, fatal-UTF-8 JSON/NDJSON reader that enforces depth,
object-key, token, string, line, item, and diagnostic-snippet limits before
unbounded materialization. Test duplicate JSON keys, malformed UTF-8, huge
numbers/strings, deep nesting, many short keys, oversized lines, blank NDJSON,
and exact limits.

**Step 2: Write failing redaction/reference tests**

Persisted errors contain only allowlisted status/category/runtime/request-ID
fields and bounded constant-safe messages. Test secrets in headers, URLs,
query/userinfo, response bodies, nested causes, and provider JSON. Define one
opaque controlled-reference scheme whose store ID/root comes from local trust
configuration; reject `file:`, `data:`, HTTP(S), inline content, traversal,
encoded traversal, and unknown stores.

**Step 3: Verify RED**

```bash
npx vitest run tests/bounded-input.test.ts tests/redaction.test.ts tests/references.test.ts
```

**Step 4: Implement and thread the primitives**

Raw private payload identity uses a per-study HMAC key supplied by reference and
never serialized. All CLI and evidence imports use the bounded reader and
allowlisted diagnostics.

**Step 5: Verify GREEN**

```bash
npx vitest run tests/bounded-input.test.ts tests/redaction.test.ts tests/references.test.ts tests/evidence.test.ts
npm run typecheck
```

**Step 6: Commit**

```bash
git add src tests
git commit -m "feat(security): bound and redact untrusted evidence"
```

---

### Task 9: Production CLI for protocols, evidence, assessment, and help

**Files:**

- Create: `src/cli-args.ts`
- Create: `tests/cli-v2.test.ts`
- Modify: `src/cli.ts`
- Modify: `tests/cli.test.ts`
- Modify: `package.json`

**Step 1: Write failing CLI tests**

Cover:

```text
tasc protocol validate
tasc traces validate
tasc evidence validate
tasc assess development
tasc assess holdout
tasc assess window
tasc experiment next
tasc --help
tasc --version
```

Assert structured JSON stdout, diagnostics-only stderr, documented exit codes,
duplicate/unknown flag rejection, bounded parsing before `JSON.parse`, NDJSON
line diagnostics, explicit `WorkBudget`, local evaluator trust policy, fresh
output enforcement, and legacy `nominate`/`confirm` compatibility. Holdout
requires a nomination; window requires a frozen policy and `WindowManifest`.
Every v2 assessment requires an explicit `--context`; the CLI never substitutes
the wall clock.
Do not add runtime probe/shadow stubs here; Task 13 adds those commands when the
implementations exist.

**Step 2: Verify RED**

```bash
npx vitest run tests/cli-v2.test.ts
```

**Step 3: Refactor parsing away from import side effects**

Export a testable `runCli(argv, environment, io)` and keep the executable entry
thin. Route every command through the shared runtime schemas and atomic artifact
writer.

**Step 4: Verify GREEN**

```bash
npx vitest run tests/cli-v2.test.ts tests/cli.test.ts
npm run typecheck
npm run build
```

**Step 5: Commit**

```bash
git add src tests package.json
git commit -m "feat(cli): expose the trace control plane workflow"
```

---

### Task 10: Runtime registry and capability evidence

**Files:**

- Create: `src/runtime/types.ts`
- Create: `src/runtime/profiles.ts`
- Create: `src/runtime/orchestration.ts`
- Create: `tests/runtime-profiles.test.ts`
- Modify: `src/index.ts`

**Step 1: Write failing registry tests**

Specify runtime profiles for:

- vLLM;
- SGLang;
- TensorRT-LLM;
- llama.cpp;
- Ollama;
- Text Generation Inference;
- LM Studio;
- MLX-LM.

Test profile-specific inference/model/health/metrics paths and static capability
expectations without claiming support that requires a probe. A capability is
`supported | conditional | unsupported | unknown` with runtime/build/backend/
model/config evidence. Table fixtures name the exact runtime build whose
documented behavior they model; anything not established by that fixture or a
live probe remains `unknown` or `conditional`.

Specify locally supplied, declarative Ray Serve and SkyPilot descriptors that
wrap an underlying runtime and produce an `EndpointDescriptor`. Test that they
cannot load code, discover or invoke deployment mutation, or masquerade as
runtime profiles.

**Step 2: Verify RED**

```bash
npx vitest run tests/runtime-profiles.test.ts
```

**Step 3: Implement the declarative registry**

Use no vendor, Ray, SkyPilot, Kubernetes, or cloud SDK dependency. Keep
version-specific differences explicit and let probe evidence override only the
probed capability instance, never the static profile definition.

**Step 4: Verify GREEN**

```bash
npx vitest run tests/runtime-profiles.test.ts
npm run typecheck
```

**Step 5: Commit**

```bash
git add src/runtime src/index.ts tests/runtime-profiles.test.ts
git commit -m "feat(runtime): model real inference server capabilities"
```

---

### Task 11: Bounded HTTP, SSE, and NDJSON wire codecs

**Files:**

- Create: `src/runtime/http.ts`
- Create: `src/runtime/network-policy.ts`
- Create: `src/runtime/sse.ts`
- Create: `src/runtime/ndjson.ts`
- Create: `src/runtime/metrics.ts`
- Create: `tests/runtime-codecs.test.ts`
- Create: `tests/network-policy.test.ts`
- Modify: `package.json`
- Modify: `package-lock.json`

**Step 1: Write failing codec tests**

Use real `127.0.0.1` ephemeral HTTP servers, not mocked `fetch`. Give every test
a bounded deadline and await server/socket shutdown. Test:

- split UTF-8 code points and SSE fields across arbitrary chunks;
- comments, event names, IDs, multiline data, blank-line dispatch, and `[DONE]`;
- typed Responses events;
- Ollama NDJSON framing;
- Prometheus samples needed by supported profiles;
- non-2xx responses;
- mid-stream error events and socket truncation;
- missing final usage;
- invalid JSON and invalid UTF-8 handling;
- header, event, line, response, and total-byte limits;
- first-byte versus first-meaningful-output timing;
- timeout and caller cancellation with `AbortSignal`;
- authorization and provider errors redacted from persisted diagnostics.

Also define and test a local `CollectorTrustPolicy` with exact origins, schemes,
ports, path prefixes, secret references, evaluator key IDs, store roots, and
explicit local mode. A protocol may only narrow it. Cover redirect denial,
userinfo, queries/fragments, Unicode/trailing-dot hosts, non-default ports,
decimal/integer/hex IP forms, IPv4-mapped IPv6, unspecified, loopback, RFC1918,
CGNAT, ULA, link-local/metadata addresses, mixed DNS answers, and revalidation.
Remote targets require HTTPS/public addresses; local mode requires an exact
literal loopback origin. A controlled lookup/dispatcher pins one validated DNS
result for the actual connection while preserving TLS SNI/hostname, and every
new connection is revalidated.

**Step 2: Verify RED**

```bash
npx vitest run tests/network-policy.test.ts tests/runtime-codecs.test.ts
```

**Step 3: Implement bounded streaming primitives**

Use the fetch-compatible controlled Undici transport only through
`CollectorTrustPolicy`, `TextDecoder` fatal streaming mode, the shared bounded
parser, and explicit limits. Send
`Accept-Encoding: identity`, disable redirects, and return keyed event
identities plus normalized events. Never buffer an unbounded stream or include a
raw provider frame in an error.

**Step 4: Verify GREEN**

```bash
npx vitest run tests/network-policy.test.ts tests/runtime-codecs.test.ts
npm run typecheck
```

**Step 5: Commit**

```bash
git add src/runtime tests/runtime-codecs.test.ts tests/network-policy.test.ts package.json package-lock.json
git commit -m "feat(runtime): parse bounded inference streams"
```

---

### Task 12: Runtime-specific probes and live invocation

**Files:**

- Create: `src/runtime/probe.ts`
- Create: `src/runtime/invoke.ts`
- Create: `tests/runtime-invoke.test.ts`
- Modify: `src/runtime/profiles.ts`
- Modify: `src/runtime/metrics.ts`

**Step 1: Write failing contract-server tests**

Create table-driven `127.0.0.1` servers that emulate named, build-pinned
documented differences for vLLM, SGLang, TensorRT-LLM, llama.cpp, Ollama, TGI,
LM Studio, and MLX-LM. Give each test a bounded deadline and await teardown.
Cover model discovery, liveness, readiness canary, chat invocation, streaming
usage, logprobs, cancellation semantics, malformed responses, metrics location
and format, and unsupported features.

Explicitly test:

- TensorRT-LLM's consumptive JSON `/metrics` versus optional Prometheus path;
- Ollama native durations/usage and lack of local auth assumption;
- llama.cpp timing extensions without treating them as portable;
- MLX-LM's experimental/non-production classification;
- conditional tool, structured-output, logprob, and Responses support.

**Step 2: Verify RED**

```bash
npx vitest run tests/runtime-invoke.test.ts
```

**Step 3: Implement probe and invoke**

Share codecs, not capability claims. Record requested/resolved model IDs,
observer timing, provider usage, finish reason, build/version evidence, abort
lifecycle, stream digest, and sanitized error. Authentication is injected by
environment reference or header factory and never returned. Every request goes
through the shared network policy at connection time; there is no unsafe invoke
export.

**Step 4: Verify GREEN**

```bash
npx vitest run tests/runtime-invoke.test.ts tests/runtime-codecs.test.ts tests/runtime-profiles.test.ts
npm run typecheck
```

**Step 5: Commit**

```bash
git add src/runtime tests
git commit -m "feat(runtime): probe and call inference endpoints"
```

---

### Task 13: Resumable paired shadow runner

**Files:**

- Create: `src/runtime/shadow.ts`
- Create: `tests/shadow-runner.test.ts`
- Modify: `src/artifacts.ts`
- Modify: `src/evidence.ts`
- Modify: `src/cli-args.ts`
- Modify: `src/cli.ts`

**Step 1: Write failing runner tests**

Test stable champion/candidate order counterbalancing, replicate and attempt
IDs, bounded concurrency, per-attempt and whole-run deadlines, failure
retention, response-size limits, cancellation, checkpointing, restart/resume,
duplicate prevention, partial checkpoint recovery, SIGINT-style abort, and exact
work-budget preflight.

Inject crashes before durable dispatch intent, after intent/before send, after
send, before envelope checkpoint, and after checkpoint. Preserve
`not_sent | sent_unknown | completed`. Retry only documented retry-safe outcomes
with bounded count/backoff/`Retry-After`; never retry auth, validation, or
ambiguous `sent_unknown` outcomes. Drain readers and release concurrency slots
on every deadline and cancellation path.

Test `tasc runtime probe` and `tasc shadow run` CLI behavior with the local
contract server. Assert operator trust-policy enforcement, default denial of
cloud metadata/link-local targets, secret redaction, keyed payload identities,
and no deployment mutation.

**Step 2: Verify RED**

```bash
npx vitest run tests/shadow-runner.test.ts
```

**Step 3: Implement the runner**

Accept case request bodies from controlled input, but store only configured
digests/references. Checkpoint each accepted trace atomically and rebuild resume
state from validated envelopes.

**Step 4: Verify GREEN**

```bash
npx vitest run tests/shadow-runner.test.ts tests/cli-v2.test.ts tests/runtime-invoke.test.ts
npm run typecheck
```

**Step 5: Commit**

```bash
git add src tests
git commit -m "feat(shadow): collect resumable paired inference traces"
```

---

### Task 14: Packaging, Python hardening, and repository automation

**Files:**

- Create: `scripts/package-smoke.mjs`
- Create: `scripts/live-smoke.ts`
- Create: `.github/workflows/codeql.yml`
- Create: `.github/workflows/release.yml`
- Modify: `.github/workflows/ci.yml`
- Modify: `package.json`
- Modify: `package-lock.json`
- Modify: `benchmarks/mlx/run_benchmarks.py`
- Modify: `benchmarks/mlx/test_run_benchmarks.py`
- Modify: `benchmarks/mlx/requirements.txt`
- Create: `benchmarks/mlx/requirements.lock`
- Create or modify: `vitest.config.ts`

**Step 1: Add failing package verification**

During development, make the package smoke script copy the current tracked
working tree into a temporary source while excluding `.git`, `node_modules`,
`dist`, coverage, artifacts, and ignored scratch; then run `npm ci` and
`npm pack` so `prepack` must create `dist`. Install that exact tarball into a
separate temporary consumer, import by package name, and run `tasc --help` and
`tasc --version`. First record the current clean-source failure showing why
prepack is required; never test from an already-built worktree. Post-commit CI
also performs the same smoke from `git archive HEAD` to prove only committed
sources are required.

**Step 2: Add failing Python safety tests**

Test import and parser/safety behavior with no optional MLX/Hugging Face package
installed, lazy live-run imports, strict model/scenario slugs, full revision
identity, resolved output containment, duplicate targets, exclusive writes,
subprocess timeout, bounded captured output, reduced environment, and cleanup
after failure.

Run:

```bash
python3 -m unittest benchmarks/mlx/test_run_benchmarks.py
```

**Step 3: Implement package and Python fixes**

Set the package deliberately publishable with scoped public access, add
`prepack`, a deliberate export map, executable/package metadata, a
cross-platform integrity-bearing npm lockfile, package smoke, and bounded MLX
subprocess handling. Add a hash-pinned Python lock for reproducible macOS
benchmark environments while keeping Linux parser tests dependency-free and
GPU/model execution optional.

Add a matching `@vitest/coverage-v8` provider, `npm run coverage`, explicit
source include/exclude rules, and initially measured, justified thresholds.

**Step 4: Expand CI**

Create separate named checks for:

- Linux Node 22 and 24;
- macOS Node 22 and 24;
- typecheck/build/package smoke;
- Vitest coverage with justified thresholds;
- Python 3.12 parser/safety tests without MLX hardware;
- dependency audit;
- CodeQL;
- release dry run.

Pin every GitHub Action by full commit SHA with a version comment and use
least-privilege job permissions. Add dependency review, npm/Python auditing, and
secret scanning. The release workflow uses a protected environment plus OIDC
trusted publishing: it builds and tests one tarball, records its SHA-512, and
publishes that exact tarball only for the verified tagged commit. Pull requests
perform a credential-free dry run; do not publish during this task.

**Step 5: Verify**

```bash
npm ci
npm run typecheck
npm test
npm run coverage
npm run build
npm run package:smoke
npm audit --audit-level=high
python3 -m unittest benchmarks/mlx/test_run_benchmarks.py
```

**Step 6: Commit in coherent parts**

```bash
git add package.json package-lock.json scripts/package-smoke.mjs vitest.config.ts
git commit -m "build(package): verify pristine consumer installs"

git add benchmarks/mlx
git commit -m "fix(mlx): harden benchmark execution and outputs"

git add .github scripts/live-smoke.ts
git commit -m "ci: validate every supported release surface"
```

---

### Task 15: End-to-end example, operating documentation, and migration

**Files:**

- Create: `examples/control-plane/protocol.json`
- Create: `examples/control-plane/traces.ndjson`
- Create: `examples/control-plane/evaluator-evidence.ndjson`
- Create: `examples/control-plane/window.json`
- Create: `scripts/control-plane-demo.ts`
- Create: `docs/runtime-support.md`
- Create: `docs/threat-model.md`
- Create: `docs/migration-v2.md`
- Create: `CONTRIBUTING.md`
- Create: `CHANGELOG.md` if absent, otherwise modify it
- Modify: `README.md`
- Modify: `docs/design.md`
- Modify: `docs/operating-guide.md`
- Modify: `package.json`
- Modify: `tests/public-api.test.ts`

**Step 1: Write the end-to-end executable example**

The fixture must contain sanitized paired traces and separate deterministic
evaluator evidence. The demo validates, joins, assesses development, seals a
shadow window, emits a next experiment and policy recommendation, and verifies
all artifact digests. It must not contain a judge prompt or raw private payload.

**Step 2: Add a golden smoke test before implementation**

Assert the expected statuses, selected policy digest, group/slice coverage,
unavailable capacity result, and manifest. Observe the test fail until the
script and fixtures exist.

**Step 3: Document the finished product**

README must lead with the trace-control-plane premise, explain P0/P1, show the
actual controller flow, retain the real MLX R&D result with honest limits, and
include CI/release badges.

`docs/runtime-support.md` records current vLLM, Ray Serve, SkyPilot, TensorRT-LLM,
SGLang, llama.cpp, Ollama, TGI, LM Studio, and MLX-LM support and limitations
with official source links.

The threat model covers payloads, secrets, SSRF, malicious output, evaluator
poisoning, protocol drift, artifact custody, deployment separation, denial of
service, and supply chain. The migration guide explains why v1 real readiness
now fails closed.

**Step 4: Verify docs and demos**

```bash
npm run demo
npm run demo:control-plane
npx vitest run tests/public-api.test.ts tests/cli-v2.test.ts
npm run check
git diff --check
```

**Step 5: Commit in coherent parts**

```bash
git add examples scripts/control-plane-demo.ts tests package.json
git commit -m "feat(demo): ship a trace-aware control plane study"

git add README.md docs CONTRIBUTING.md CHANGELOG.md
git commit -m "docs: document the production R&D workflow"
```

---

### Task 16: Live verification, specialty review, and PR readiness

**Files:**

- Modify only files required by verified review findings.

**Step 1: Run the complete local gate from a clean install**

```bash
npm ci
npm run check
npm run coverage
npm run package:smoke
npm run demo
npm run demo:control-plane
npm audit --audit-level=high
python3 -m unittest benchmarks/mlx/test_run_benchmarks.py
git diff --check
git status --short
```

Record exact test/pass counts and package-smoke results.

**Step 2: Make one real inference call**

Use `scripts/live-smoke.ts` only against an explicitly configured
`TASC_LIVE_SMOKE_ENDPOINT` plus `TASC_LIVE_SMOKE_RUNTIME` and an optional named
secret reference, or an already-running exact loopback endpoint. Never print a
key, use an arbitrary URL, run this in CI, download model/runtime code
implicitly, or commit raw output. Validate the sanitized trace against
`TraceEnvelope`, inspect it for secret leakage, record only non-sensitive
verification metadata, then remove private run data.

The deterministic local contract-server smoke remains mandatory. If no
authorized real endpoint exists, do not fabricate compatibility evidence or
weaken network policy: leave this acceptance item incomplete and report the
external-state blocker.

**Step 3: Run multi-angle Codex review**

Review the full branch for:

- architecture and product-boundary compliance;
- statistical validity and performance;
- security and threat model;
- resilience and partial-failure behavior;
- test gaps and package/release integrity.

Fix all critical and important findings with failing regression tests, rerun
targeted verification, commit, and re-review.

**Step 4: Run Claude Code review**

Use installed Claude Code in read-only review mode against
`origin/main...HEAD`, the design spec, and this plan. Ask specifically for
incorrect judge-model scope, inference/statistics defects, unsafe network/file
behavior, missing runtime capability distinctions, test blind spots, and
release blockers.

Fix every actionable critical/important finding using TDD, commit, and rerun the
review until clear.

**Step 5: Rebase/conflict and final verification**

Fetch `origin/main`, inspect open PRs and shared-file conflicts, rebase only if
needed without force-pushing, then rerun the complete gate.

**Step 6: Push and open the PR**

Create a comprehensive conventional-commit PR that includes design, trust
boundary, runtime matrix, screenshots or artifact excerpts where useful, exact
verification counts, live-call evidence classification, limitations, and
follow-up work. Preserve the worktree for CI fixes.

**Step 7: Drive checks green**

Inspect every GitHub check and log. Fix repository-caused failures, add
regression coverage, push meaningful commits, and repeat until all required and
informational checks that can run for the repository are green.
