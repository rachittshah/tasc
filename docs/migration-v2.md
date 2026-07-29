# Migrating from legacy v1 to the v2 control plane

Legacy v1 remains available so existing `nominate` and `confirm` artifacts can
be read and reproduced. It is deliberately unable to turn real measurements
into a new production recommendation: real v1 confirmation fails closed at
`HOLD`, even when its HMAC continuity check succeeds.

V2 is not a renamed judge wrapper. It separates inference traces from external
evaluator evidence, binds both to an operator-owned protocol and trust context,
and assesses routing policies offline or over a sealed shadow window.

## Why v1 fails closed

V1 was a useful proof of concept but its contract cannot establish several
facts required for production-shaped R&D:

- task score and inference outcome share one measurement row instead of
  independently authenticated evidence;
- evaluator validation is metadata rather than a signed, revocable trust
  relationship;
- dispatch intent and raw-payload identity are not bound into a trace;
- live/shadow window membership and ingestion watermark are absent;
- protocol, trust, revocation, and assessment-time snapshots are not one
  explicit context;
- controller recovery is not an append-only, replayable state transition; and
- legacy attestation authenticates nomination continuity only.

Silently reinterpreting old rows would manufacture provenance that never
existed. TASC therefore preserves v1 results as migration evidence and requires
a fresh v2 study for a v2 decision.

## Contract mapping

| Legacy v1 | V2 replacement | Important difference |
| --- | --- | --- |
| `tasc-inference-spec-v1` | `tasc-experiment-protocol-v2` | Profiles, candidate policies, gates, evaluator requirements, split rules, work limits, and distinct dispatch/collector authorities are normalized and fingerprinted. |
| `tasc-measurements-v1` case/observation | `tasc-trace-envelope-v2` | Inference lifecycle, attempts, route signal, timing, usage, pre-dispatch authorization, final collector attestation, collection provenance, and keyed request/response identities are explicit; no score is embedded. |
| inline evaluator metadata and task score | `tasc-evaluator-evidence-v2` | Score is independently signed, time-bound, revocable, and joined to the trace by explicit identities. |
| optional `TASC_ATTESTATION_KEY` nomination HMAC | protocol dispatch/collector authorities plus evaluator trust snapshot | Separate authorities cover pre-call dispatch, final operational observation, and evaluator evidence. Public digests remain non-secret identities. |
| implicit invocation context | `tasc-assessment-context-v2` | Assessment time, trust-policy digest, revocation digest, and controller lineage are frozen. |
| development/holdout file label | protocol split membership and joined dataset | Group disjointness and completeness are checked at the join/assessment boundary. |
| no online-window contract | `tasc-window-manifest-v2` | Event range, watermark, source, membership, policy, and protocol are sealed before window assessment. |
| report directory | immutable artifact packet | Exact bytes, sizes, hashes, packet lineage, custody, durability, and `NO_DEPLOYMENT_AUTHORITY` are explicit. |
| `next-experiment.json` heuristic | versioned experiment proposal | Proposal binds the parent decision/protocol, frozen controls, evidence requirements, budget, and stop condition. |

## Status mapping

There is no one-to-one upgrade of a v1 status. Re-run the study under v2.

| V1 status | Migration interpretation | Possible v2 outcomes after re-evaluation |
| --- | --- | --- |
| `NOMINATED` | A legacy development candidate passed legacy gates. | `NOMINATED`, `NO_CANDIDATE`, `INSUFFICIENT_EVIDENCE`, or `STALE` |
| `NO_CANDIDATE` | No legacy development candidate passed. | Any development status after protocol/evidence changes are explicitly declared |
| `DEMO_ONLY` | Synthetic legacy holdout passed. | A synthetic v2 fixture remains demonstration evidence and has no deployment authority |
| `HOLD` | Legacy holdout failed or real v1 was safety-capped. | `PASS`, `HOLD`, `INSUFFICIENT_EVIDENCE`, or `STALE` only after a fresh v2 holdout/window assessment |

`PASS` is evidence for manual review. It does not deploy, promote, route, or
authorize production.

## Migration procedure

### 1. Preserve the v1 packet

Keep the original spec, development measurements, nomination, holdout
measurements, confirmation, reports, and the exact TASC version used. Do not
edit v1 artifacts into v2-looking JSON. Treat them as historical experiment
evidence.

### 2. Register a v2 protocol

Declare:

- exact champion and candidate execution profiles;
- model, tokenizer, runtime, backend, hardware, quantization, chat-template,
  and configuration identities;
- permitted routing policies and route-time signals;
- group/split and critical-slice rules;
- absolute quality, reliability, latency, capacity, and cost gates;
- paired inference parameters;
- evaluator identity, trusted key IDs, evidence window, and score contract;
- bootstrap parameters; and
- explicit work budgets.

Changing one of these after seeing holdout results is a new protocol, not a
migration correction.

### 3. Prepare P0 collection authority for fresh traces

When migration requires new inference calls, first advance the replayed
controller to `SHADOW_ASSESSING` and build one self-contained
`tasc-shadow-run-plan-v1` from its exact snapshot, selected policy, protocol,
window, endpoint/profile bindings, and aggregate work budget. Pin the expected
plan digest at the operator job boundary. Pin each nullable non-secret
authentication reference in the corresponding P0 collection target; changing
that reference creates new collection authority and trace lineage. Fingerprint
each target's complete normalized/defaulted inference HTTP limits as well;
changing a timeout or byte ceiling requires a new plan and distinct trace
lineage.

Prepare the matching v2 shadow target configuration and collector trust policy.
Keep the per-study payload HMAC, dispatch private key, collector-attestation
private key, and provider credential in separate environment references; the
dispatch and collector Ed25519 authorities must be distinct. P1 accepts the plan
and those exact runtime bindings—it does not accept loose policy, membership,
protocol, or work-budget overrides. The same per-study HMAC key must remain
available for crash resume because it also authenticates the local shadow
journal; an old unauthenticated journal is intentionally not accepted.

Historical traces do not acquire this authority retroactively. If the original
call lacks authentic dispatch or collector provenance, collect it again under a
new plan.

### 4. Reconstruct inference traces without inventing fields

A v1 observation can be exported as a v2 trace only when the original raw
record establishes every required field. Preserve failure attempts. Leave
provider usage, request IDs, route signals, cost, capacity, or timing
unavailable when they were not observed.

Do not:

- copy task score into routing confidence;
- derive TTFT from aggregate prefill throughput;
- infer a successful terminal frame from HTTP 200 alone;
- join aggregate benchmark accuracy to unrelated request traces;
- fabricate model/tokenizer revisions or configuration digests; or
- create dispatch signatures for historical calls that were never authorized
  under the v2 protocol; or
- create collector attestations for operational outcomes that were not observed
  by the registered collector.

If historical dispatch provenance is insufficient, collect fresh paired traces.
The resumable shadow runner is designed for that job.

### 5. Produce evaluator evidence separately

Use a frozen deterministic evaluator or externally validated human/model
evaluator. Emit one signed evidence contract for the trace/output identity with
the declared task, score, evaluator version, production time, and trusted key.

TASC verifies and joins evidence; it does not call a judge model or generate
replacement grades. Missing or untrusted evidence remains missing.

### 6. Freeze trust and assessment context

Create an operator snapshot containing trusted evaluator keys, validity
windows, allowed tasks/evaluators, and revocations. Bind its digests and the
assessment time into the v2 assessment context. Review clock skew and
revocations before every assessment.

### 7. Validate before assessing

The CLI requires an explicit work budget:

```bash
tasc protocol validate protocol.json --work-budget work-budget.json

tasc traces validate traces.ndjson --work-budget work-budget.json

tasc evidence validate evaluator-evidence.ndjson \
  --trust evaluator-trust.json \
  --context assessment-context.json \
  --work-budget work-budget.json
```

Contract-only trace validation does not prove protocol admission. The
assessment join performs protocol, split, lineage, completeness, and evaluator
trust checks.

### 8. Re-run development selection

```bash
tasc assess development \
  --protocol protocol.json \
  --traces development-traces.ndjson \
  --evidence development-evidence.ndjson \
  --context development-context.json \
  --trust evaluator-trust.json \
  --work-budget work-budget.json \
  --out artifacts/development-v2
```

The output directory must not exist. Preserve the complete immutable packet,
including rejected candidates and limitations.

### 9. Confirm the exact nomination

Use group-disjoint, previously sealed holdout data. V2 confirmation revalidates
the persisted development nomination against the development dataset and
context before evaluating the holdout.

```bash
tasc assess holdout \
  --protocol protocol.json \
  --traces holdout-traces.ndjson \
  --evidence holdout-evidence.ndjson \
  --context holdout-context.json \
  --trust evaluator-trust.json \
  --nomination artifacts/development-v2/assessment.json \
  --development-traces development-traces.ndjson \
  --development-evidence development-evidence.ndjson \
  --development-context development-context.json \
  --development-trust evaluator-trust.json \
  --work-budget work-budget.json \
  --out artifacts/holdout-v2
```

Do not search holdout for a replacement policy. A failed or stale nomination is
a result, not permission to retune.

### 10. Use sealed windows for shadow-online grading

Live collection and online assessment are separate. Collect raw-free inference
traces under a protocol and work budget, obtain external evaluator evidence,
then seal membership and watermark in a window manifest. Assess that immutable
window with:

```bash
tasc assess window \
  --protocol protocol.json \
  --traces online-traces.ndjson \
  --evidence online-evidence.ndjson \
  --context online-context.json \
  --trust evaluator-trust.json \
  --policy frozen-policy.json \
  --window window.json \
  --work-budget work-budget.json \
  --out artifacts/window-v2
```

TASC is not in the synchronous production request path. A shadow `PASS` does
not promote the policy.

## Operational cutover checklist

- [ ] Original v1 artifacts are immutable and retained.
- [ ] V2 protocol was declared before holdout/window evidence was inspected.
- [ ] Every execution profile and runtime configuration is pinned.
- [ ] Fresh collection uses a pinned P0 plan, exact target and HTTP-limit
      bindings, and distinct dispatch/collector authorities.
- [ ] Historical fields were migrated only when supported by raw evidence.
- [ ] Fresh paired traces were collected where v1 provenance was insufficient.
- [ ] Failures and `sent_unknown` attempts remain visible.
- [ ] Evaluator evidence is separate, calibrated externally, signed, current,
      trusted, and unrevoked.
- [ ] Development and holdout groups are disjoint.
- [ ] Window membership and watermark are sealed for online assessment.
- [ ] Work budgets and provider quotas cap maximum cost.
- [ ] Artifact durability and manifest verification are acceptable.
- [ ] Reviewers understand that every packet has `NO_DEPLOYMENT_AUTHORITY`.

## Correcting pre-release orchestration descriptors

An unreleased v2 development draft used `locator.serviceName` for both plain
SkyPilot and SkyServe descriptors. That shape did not match SkyPilot's own
identity model: a plain `sky launch` target is identified by a cluster name,
while `sky serve up` creates a named SkyServe service.

Do not rename the field inside an already fingerprinted descriptor. Recreate
the operator-owned descriptor from authoritative deployment metadata:

- `kind: "skypilot"` requires `locator.clusterName`;
- `kind: "skyserve"` requires `locator.serviceName`; and
- Ray Serve continues to require both `locator.applicationName` and
  `locator.deploymentName`.

The parser rejects the ambiguous draft
`{ "kind": "skypilot", "locator": { "serviceName": "..." } }` rather than
silently interpreting that value as a cluster. Recompute the endpoint
descriptor fingerprint and every operator-controlled binding that legitimately
depends on it, then collect fresh evidence under the corrected identity. Never
rewrite an accepted trace or signed historical record.

## Compatibility policy

Legacy commands remain for reproduction:

```text
tasc nominate ...
tasc confirm ...
```

They will not acquire v2 production semantics. New protocol, evidence, runtime,
shadow, controller, and assessment work belongs in versioned v2 contracts. A
future breaking contract will use a new explicit version rather than silently
changing v1 or v2 interpretation.
