# TASC operating guide

This guide covers the implemented v2 assessment, live probe, and resumable
shadow workflows. TASC is an out-of-band evidence controller. It may call an
approved inference endpoint to collect traces, but it never runs an evaluator,
routes a production request synchronously, changes serving configuration, or
deploys a policy.

Every result is evidence-only and carries
`evidence-only-no-deployment-authority`.

## Install and verify

Use Node.js 22 or newer:

```bash
npm ci
npm run typecheck
npm test
npm run build
```

For a zero-network production-shaped replay:

```bash
npm run demo:control-plane
```

The committed fixture contains public keys and precomputed synthetic
signatures, not private keys. It uses separate trace and evaluator-evidence
NDJSON. The demo verifies trust, assesses development and a sealed window,
publishes four immutable packets, and rereads every payload digest.

## Before a study

Assign explicit owners for:

- protocol and gate approval;
- route-signal definition and calibration;
- evaluator/rubric/calibration validation;
- trusted evaluator and dispatch keys;
- group split and holdout custody;
- endpoint/trust policy and secret references;
- model/runtime/backend/configuration identity;
- work and spend limits;
- shadow window sealing;
- artifact storage and review; and
- the separate deployment decision.

Do not let the same mutable file stand in for both an operator trust decision
and producer evidence. Record all review inputs by digest.

### Preregister the protocol

Freeze the v2 protocol before collection. In particular, review:

- champion and candidate profile identities;
- finite routing predicate space;
- route-signal definition/version/range/direction/calibration;
- evaluator identity, rubric, calibration, producer, and required key IDs;
- seeded group development/holdout partition;
- seeded online sample and intended traffic fraction;
- absolute quality, slice, reliability, tail-latency, cost, evidence, group,
  and capacity gates;
- bootstrap seed, iterations, and alpha;
- shadow logical/concurrency/attempt/time ceilings;
- endpoint requirements and transport;
- required runtime capabilities; and
- protocol creation/expiry times.

Validate it with a caller-owned assessment budget:

```bash
tasc protocol validate protocol.json --work-budget assessment-budget.json
```

Protocol validation is structural and semantic. It does not prove that an
endpoint exists, a model is loaded, an evaluator is good, or traffic is
representative.

### Establish trust and assessment time

An evaluator trust snapshot contains canonical Ed25519 public keys, purpose,
evaluator/producer authorization, allowed rubric and calibration identities,
key validity, freshness limits, and revocations.

An assessment context contains:

- an explicit `asOf` timestamp;
- the fingerprint of the operator trust-policy portion; and
- the fingerprint of the revocation view.

Recreate the context when keys, revocations, freshness policy, or assessment
time changes. Never substitute process wall clock silently. Validate evidence
before joining:

```bash
tasc evidence validate evaluator-evidence.ndjson \
  --trust evaluator-trust.json \
  --context assessment-context.json \
  --work-budget assessment-budget.json
```

This verifies signatures and local trust only. Protocol pinning, trace lineage,
and terminal-output matching happen at the join/assessment boundary.

## Offline assessment

### Inputs

Keep these as distinct review objects:

- protocol JSON;
- pre-dispatch-authorized and final-collector-attested trace NDJSON;
- evaluator-signed evidence NDJSON;
- evaluator trust snapshot;
- assessment context; and
- assessment work budget.

Trace payloads should be represented by study-scoped HMAC identities. A
successful trace must bind evaluator evidence to its exact terminal output
identity. Failed or aborted executions do not receive fabricated scores.
Ambiguous sends remain ambiguous.

Split related cases by `groupId`. TASC recomputes group membership from the
protocol and rejects a trace-declared development/holdout split that disagrees.
Do not reveal or use holdout evidence while choosing candidates.

### Development nomination

```bash
RUN_ROOT=$(realpath "$(mktemp -d)")

tasc assess development \
  --protocol protocol.json \
  --traces development-traces.ndjson \
  --evidence development-evidence.ndjson \
  --context development-context.json \
  --trust evaluator-trust.json \
  --work-budget assessment-budget.json \
  --out "$RUN_ROOT/development"
```

The final `--out` target must not exist; its parent must exist. The packet
contains `assessment.json`, and contains `policy.json` only when a policy was
selected. Preserve the manifest digest alongside the review record.

Artifact roots and every existing path component must be canonical directories,
not symlinks. On macOS, `tmpdir()` may report `/var/...` even though `/var`
resolves through `/private/var`; use `realpath` and pass the canonical
`/private/var/...` path, or use a canonical private directory under `$HOME`.

Review:

- status and stale/insufficiency reasons;
- control and every candidate, including rejected policies;
- independent group and critical-slice group coverage;
- missing, invalid, abstained, orphan, duplicate, and conflicting evidence;
- paired bootstrap method/interval/effective traffic mass;
- evidence class on every metric;
- failed and ambiguous attempts;
- route-signal/profile/evaluator identity;
- selected policy and policy digest; and
- deferred service-capacity warning.

`NOMINATED` freezes a candidate. It is not permission to deploy or to expose the
holdout.

### Holdout confirmation

Holdout revalidates a persisted nomination by rerunning development from source
evidence, then assesses one policy:

```bash
tasc assess holdout \
  --protocol protocol.json \
  --traces holdout-traces.ndjson \
  --evidence holdout-evidence.ndjson \
  --context holdout-context.json \
  --nomination "$RUN_ROOT/development/assessment.json" \
  --development-traces development-traces.ndjson \
  --development-evidence development-evidence.ndjson \
  --development-context development-context.json \
  --development-trust evaluator-trust.json \
  --trust evaluator-trust.json \
  --work-budget assessment-budget.json \
  --out "$RUN_ROOT/holdout"
```

Use the development `assessment.json`, not just `policy.json`, as the
nomination. The output includes nomination-lineage metadata. `PASS` means only
that the exact frozen policy passed this bounded holdout evidence contract.
Never search a second holdout candidate after a failure.

## Sealed shadow-online assessment

### Collect and seal

Define the window ID, event-time start/end, ingestion watermark, deterministic
sampling rule, and frozen policy before collecting. After collection:

1. stop admitting events for the revision;
2. wait until the declared ingestion watermark;
3. compute exact trace- and evaluator-set digests;
4. record the membership digest;
5. record capacity as trusted measured evidence, or explicitly unavailable;
6. set revision/predecessor and closure reason; and
7. compute and persist the manifest self-digest.

Late evidence belongs in a new linked revision. Do not rewrite revision 1.

Assess the sealed window:

```bash
tasc assess window \
  --protocol protocol.json \
  --traces online-traces.ndjson \
  --evidence online-evidence.ndjson \
  --context online-context.json \
  --policy "$RUN_ROOT/development/policy.json" \
  --window window-manifest.json \
  --trust evaluator-trust.json \
  --work-budget assessment-budget.json \
  --out "$RUN_ROOT/window"
```

TASC recomputes trace membership, event-time eligibility, watermark
eligibility, source-set digests, policy identity, and evaluator trust. It does
not enumerate candidates.

An operator-reported throughput number is retained as reported, not promoted
to measured capacity. A required capacity gate remains unavailable until the
assessment can consume a locally verified exact-policy measurement receipt.

### Propose the next experiment

```bash
tasc experiment next \
  --assessment "$RUN_ROOT/window/assessment.json" \
  --history experiment-history.json \
  --budget experiment-budget.json \
  --out "$RUN_ROOT/next-experiment"
```

The proposal is pure and bounded. Review its diagnosis, one changed variable,
frozen controls, evidence requirements, stop condition, prior-history checks,
and budget. `operator-registration-required` means an operator must create and
approve a new protocol before any collection. Never execute a proposal merely
because it was emitted.

## Runtime probe operation

`runtime probe` can perform passive, consumptive, or inference-canary
observations:

```bash
tasc runtime probe \
  --endpoint endpoint.json \
  --runtime runtime-instance.json \
  --trust collector-trust.json \
  --capability liveness \
  --effect non-mutating \
  --deadline-ms 5000
```

An endpoint wrapper has this exact top-level shape:

```json
{
  "schemaVersion": "tasc-cli-runtime-endpoint-v1",
  "endpointAlias": "approved-vllm",
  "authentication": {
    "reference": "runtime-bearer",
    "header": "authorization",
    "environmentVariable": "TASC_RUNTIME_AUTH_VLLM"
  }
}
```

`endpointDescriptor` and `authentication` are optional. When present,
`endpointDescriptor` must be a valid public orchestration descriptor and its
authentication reference must match. Authentication header is exactly
`authorization` or `x-api-key`; the environment name must begin
`TASC_RUNTIME_AUTH_`. The environment contains the header value. JSON and argv
never do.

Orchestration locators are mode-specific: Ray Serve requires
`applicationName` and `deploymentName`, plain SkyPilot requires `clusterName`,
and SkyServe requires `serviceName`. The parser rejects a plain-SkyPilot
descriptor carrying `serviceName`; regenerate it from authoritative cluster
metadata instead of renaming a field in signed or fingerprinted evidence.

`runtime-instance.json` is exact:

```json
{
  "endpointDescriptorDigest": "sha256:<64 lowercase hex>",
  "runtime": { "profileId": "vllm", "build": "0.26.0" },
  "backend": { "name": "cuda", "build": "13.0" },
  "model": { "id": "model-id", "revision": "immutable-revision" },
  "configurationDigest": "sha256:<64 lowercase hex>"
}
```

The collector trust policy must allow the exact endpoint alias, origin, runtime
build, HTTP method, path prefix, duration, local/remote mode, and authentication
reference. Remote origins require HTTPS and public addresses. Local HTTP is
limited to literal `127.0.0.1` or `[::1]` under explicit local mode. Redirects
are disabled.

Treat effects differently:

| Effect | Meaning |
| --- | --- |
| `non-mutating` | Passive liveness, model list, version, or metrics read. |
| `inference-canary` | Real potentially billable generation in an explicit standalone probe; never hidden inside shadow collection. |
| `consumptive` | Observation documented to consume/drain server state. |

All three are no-deployment operations.

## Resumable shadow collection

### P0 shadow-run plan

P1 accepts one `tasc-shadow-run-plan-v1`; it does not accept loose policy,
window-membership, protocol, or work-budget identities. Construct the plan in
P0 with `buildShadowRunPlan`. The builder requires:

- a self-consistent controller snapshot in `SHADOW_ASSESSING`;
- the exact normalized protocol and the controller-selected `PolicyBundle`;
- an inclusive event-time start and exclusive end;
- one endpoint/profile/route/auth-reference target binding for every protocol
  profile;
- the aggregate shadow work budget; and
- issue/expiry times consistent with controller, protocol, and frozen-policy
  authority.

The event window begins no earlier than plan issue and ends no later than plan
expiry. At P1 admission, the run deadline is the earliest of protocol expiry,
plan expiry, event-window end, and the admitted wall-clock ceiling; the
wall-clock budget must fit both the plan-validity and event-window durations.

The persisted plan contains the full snapshot, protocol, and frozen policy plus
their re-derived digests; the protocol membership rule and window membership
digest; sorted target bindings; the budget; validity; the authority string
`out-of-band-controller-only-no-deployment-authority`; and its canonical
`planDigest`. `parseShadowRunPlan` recomputes every redundant identity and
recursively freezes the result.

P0 must obtain each `endpointBindingDigest` from the exact approved collector
trust policy and endpoint descriptor. It must never copy a digest from an
untrusted target file. Store the completed plan under the same immutable
operator custody as the controller checkpoint. P1 binds `planDigest` into both
the dispatch signature and the final collector signature. Each target also
pins `authenticationReference` as a nullable non-secret identifier. Changing
the credential/tenant reference requires a new P0 plan; rotating the secret
behind one stable reference does not.

The v1 plan is content-addressed, not independently signed, and its embedded
controller snapshot explicitly remains `unattested`. Its digest detects drift;
it does not authenticate origin. Pin the expected plan digest in the
operator-controlled job/configuration boundary and never accept a plan from a
model server, evaluator, or payload source.

### Cases

`cases.ndjson` is sensitive ephemeral input. Each line has exact fields:

```json
{
  "caseId": "case-one",
  "groupId": "conversation-one",
  "replicates": 1,
  "generation": {
    "stream": false,
    "n": 1,
    "messages": [{ "role": "user", "content": "<sensitive input>" }],
    "maxTokens": 32,
    "temperature": 0
  },
  "workload": {
    "mode": "chat",
    "declaredTrafficWeight": 1,
    "inputTokenEstimate": 128
  },
  "slices": ["english"],
  "routeSignal": {
    "value": 0.82,
    "sourceId": "router-observer",
    "observedAt": "2026-07-28T00:00:00.000Z"
  }
}
```

`generation` accepts the bounded runtime generation fields `stream`, `n`,
`messages` or `prompt`, `maxTokens`, `temperature`, `topP`, `seed`, and `stop`.
It must not contain a model; each target's frozen profile supplies it.
`routeSignal` may be null only when the protocol/replay semantics permit
missing signal. Protect this input file separately; prompt bytes are HMACed and
used for inference but are not copied to durable shadow records.

### Target profiles

The following shows the exact shape of one target entry. It is a fragment, not
a complete valid `shadow-profiles.json`; the real `targets` array must contain
at least two distinct protocol targets:

```json
{
  "schemaVersion": "tasc-cli-shadow-profiles-v2",
  "targets": [
    {
      "profileId": "candidate-profile",
      "endpoint": {
        "schemaVersion": "tasc-cli-runtime-endpoint-v1",
        "endpointAlias": "approved-candidate"
      },
      "instance": {
        "endpointDescriptorDigest": "sha256:<64 lowercase hex>",
        "runtime": { "profileId": "vllm", "build": "0.26.0" },
        "backend": { "name": "cuda", "build": "13.0" },
        "model": { "id": "model-id", "revision": "immutable-revision" },
        "configurationDigest": "sha256:<64 lowercase hex>"
      },
      "route": "chatCompletions",
      "httpLimits": { "maxResponseBytes": 1048576 }
    }
  ]
}
```

At least two targets are required. Routes are `chatCompletions`,
`completions`, `responses`, `nativeChat`, or `nativeGenerate`, subject to the
registered runtime profile.

Optional `httpLimits` may contain one or more exact
`RuntimeHttpLimits` names:

`maxRequestBytes`, `maxResponseHeaderBytes`, `maxResponseHeaders`,
`maxResponseBytes`, `maxResponseChunks`, `maxSecretHeaderBytes`,
`connectTimeoutMs`, `headersTimeoutMs`, `bodyTimeoutMs`, and `deadlineMs`.

Every target must exactly match both the P0 plan and its embedded protocol:
profile digest, endpoint requirement, alias, transport, endpoint binding,
runtime/backend/model/configuration identity, route, and nullable
authentication reference. That reference is P0-pinned non-secret provenance:
it names an authorized secret lookup but never contains or grants the secret
value. Shadow v1 accepts only a build-pinned route whose registered capability
state is `supported`.
The full execution-profile digest remains P0-planned metadata. P1 separately
checks the instance fields it can honestly assert—runtime, backend, model, and
deployment-configuration digest. Tokenizer, hardware, quantization, chat
template, and orchestration fields are not mislabeled as live-observed proof;
stronger per-dimension attestation is future work.
Conditional routes are rejected before filesystem or network effects. Observe
one explicitly with `tasc runtime probe --effect inference-canary`, or issue a
plan for a statically established route; a standalone probe does not silently
grant a later shadow run authority.

### Identity and secrets

`shadow-identity.json` contains only references:

```json
{
  "schemaVersion": "tasc-cli-shadow-identity-v2",
  "studyId": "study-one",
  "keyId": "shadow-payload-key",
  "hmacKeyEnvironmentVariable": "TASC_SHADOW_HMAC_STUDY",
  "dispatchPrivateKeyEnvironmentVariable": "TASC_SHADOW_SIGNING_DISPATCH",
  "collectorPrivateKeyEnvironmentVariable": "TASC_SHADOW_SIGNING_COLLECTOR"
}
```

- `TASC_SHADOW_HMAC_*` must contain exactly 32 bytes as unpadded canonical
  base64url.
- Each `TASC_SHADOW_SIGNING_*` value must contain canonical Ed25519 PKCS8 DER
  as unpadded base64url. The public keys must match the plan protocol's
  respective dispatch and collector authorities. The two key IDs and SPKIs
  must be distinct.
- Runtime auth references are P0-pinned into the target and resulting
  `collectionBinding`; auth values remain only in `TASC_RUNTIME_AUTH_*`.

Load these from a secret manager into the process environment. Never write
their values to JSON, argv, logs, fixtures, artifacts, crash reports, or shell
history. Rotate by registering new key IDs/protocols rather than editing old
evidence.

### Plan work budget and execution

The P0 plan embeds a shadow budget with every field:

```json
{
  "maxCases": 100,
  "maxProfiles": 4,
  "maxReplicates": 3,
  "maxLogicalExecutions": 1200,
  "maxAttempts": 1200,
  "maxNetworkCalls": 1200,
  "maxDurableRecords": 6000,
  "maxRequestBytes": 104857600,
  "maxResponseBytes": 536870912,
  "maxWallClockMs": 3600000,
  "maxConcurrency": 8
}
```

Set the ceilings from an independently calculated worst case. The plan builder
refuses ceilings wider than the protocol or plan validity, and P1 admits the
actual selected membership against every field before effects.

Create the output root itself as a private, absolute, existing directory:

```bash
install -d -m 700 /var/lib/tasc/study-window

tasc shadow run \
  --plan shadow-run-plan.json \
  --plan-digest "$TASC_APPROVED_SHADOW_PLAN_DIGEST" \
  --cases cases.ndjson \
  --profiles shadow-profiles.json \
  --trust collector-trust.json \
  --identity shadow-identity.json \
  --out /var/lib/tasc/study-window
```

Unlike assessment packet output, shadow `--out` is the existing durable root.
Obtain `--plan-digest` from operator custody or the out-of-band P0 approval
channel; never copy the value out of the plan at execution time. The independent
pin is the substitution boundary, while the plan's own digest is only its
self-integrity check.
The complete zero-contact preflight verifies the plan, keys, target bindings,
membership, exact request descriptions, and aggregate work before any
filesystem write or model call.

On crash, rerun the identical command with identical frozen inputs and secret
identities. Resume verifies immutable packets, rebuilds outcome-without-
acceptance, deduplicates accepted traces, and converts an expired lease without
outcome to `sent_unknown`. Never delete a lease to force a retry. Only
`not_sent` is retryable. Before any journal record can influence resume, its
canonical body, plan/run identity, record kind, and exact target are verified
with a distinct-domain per-study HMAC using the identity key. Intent additionally
contains the dispatch signature; accepted traces carry both dispatch and
collector signatures. Only an authenticated immutable race winner is
authoritative.

Keep the output root on a supported local filesystem with cooperative,
same-UID custody and mode `0700`. Journal authentication prevents forged
outcomes from being promoted into signed evidence; it cannot prevent a process
that can delete or indefinitely squat in the namespace from causing denial of
service.

## Review and decision runbook

For any `PASS`, `HOLD`, or `INSUFFICIENT_EVIDENCE` packet:

1. pin and verify the artifact manifest digest;
2. rerun source parsing, signature verification, join, and assessment in a
   clean environment;
3. compare protocol, context, dataset, trace-set, evaluator-set, window, policy,
   decision, packet, and manifest identities;
4. inspect every unavailable evidence class and failed gate;
5. confirm independent group and critical-slice coverage;
6. confirm no holdout/window tuning;
7. inspect failed, partial, cancelled, and ambiguous attempts;
8. verify endpoint/profile/evaluator identity and key/revocation snapshots;
9. verify cost semantics and exact-policy capacity provenance;
10. review durability and namespace limitations;
11. record reviewer names and the separate deployment-system change; and
12. require a human-controlled rollback/canary plan outside TASC.

Do not automate deployment from status text. TASC intentionally exposes no
deployment token or mutation adapter.

## Common failure modes

| Symptom | Action |
| --- | --- |
| `INPUT_INVALID` | Treat the named file as untrusted; repair at the producer and rerun. |
| `STALE` | Freeze a new context/protocol/profile/window revision; never rewrite old evidence. |
| untrusted evidence | Check key, revocation, validity, freshness, rubric, calibration, and producer authorization. |
| missing evaluator coverage | Restore the external evaluator pipeline; do not invoke a hidden fallback judge. |
| `sent_unknown` | Retain it as ambiguous and include it in coverage/failure review; do not resend. |
| capacity unavailable | Collect a trusted exact-policy sealed-window capacity receipt. |
| capability conditional | Run an explicit standalone inference-canary probe for observation, or use a route with build-pinned supported capability; shadow does not auto-probe. |
| artifact target exists | Verify identical content or choose a new target; never overwrite. |
| output durability degraded | Preserve the declared limitation and move review artifacts to an appropriate filesystem. |

## Legacy v1

`nominate` and `confirm` remain for compatibility with
`tasc-inference-spec-v1` and measurement matrices. Real legacy confirmation is
always capped at `HOLD`; its optional `TASC_ATTESTATION_KEY` authenticates
continuity only. New studies should use v2. See [migration-v2.md](migration-v2.md).

For security controls and residual risk, use
[threat-model.md](threat-model.md), [SECURITY.md](../SECURITY.md), and
[runtime-support.md](runtime-support.md).
