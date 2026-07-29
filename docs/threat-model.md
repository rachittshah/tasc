# Threat model

This threat model covers TASC's v2 trace-control-plane library, CLI, live
runtime probes/invocations, resumable shadow collector, evaluator-evidence
verification, controller replay, and artifact publication. It does not cover
the security of a model server, evaluator service, secret manager, CI runner,
payload store, or deployment system except at the boundary where TASC consumes
their data.

TASC is out of band. It may recommend a policy for manual review, but it has no
authority or adapter to change production traffic.

## Security objectives

1. A protocol, trace, provider response, or CLI argument cannot cause an
   unapproved network request, file read/write, process execution, or deployment
   mutation.
2. Raw prompts, outputs, credentials, signing keys, and payload-identity keys do
   not enter durable controller or assessment artifacts.
3. A partial, ambiguous, stale, untrusted, or incomplete observation cannot be
   silently promoted to successful evidence. V2 cannot infer whether authentic
   operator-supplied evidence is synthetic or representative.
4. Development selection, holdout confirmation, and sealed online-window
   assessment preserve their declared data and evaluator lineage.
5. Work is finite before expansion or dispatch, and every parser, transport,
   subprocess, and artifact operation is bounded.
6. Crash recovery is monotonic: resume does not duplicate accepted traces or
   retry a call whose send state is ambiguous.
7. Public digests provide deterministic identity and corruption detection;
   signatures and operator trust policy provide authenticity where claimed.
8. No status grants deployment authority.
9. P1 shadow effects require one P0 plan and accepted operational facts require
   a collector key distinct from the pre-dispatch key.

## Assets

| Asset | Required protection |
| --- | --- |
| Prompts, outputs, user identifiers | Confidentiality; stable keyed identity without durable raw bytes |
| Provider credentials | Confidentiality; policy-scoped use; never reflected or serialized |
| HMAC identity and Ed25519 signing keys | Confidentiality and correct authority binding |
| Protocol, split, policy, evaluator, and window lineage | Integrity and deterministic replay |
| Holdout membership | Confidentiality before use; integrity and group disjointness |
| Runtime/model/backend/configuration identity | Integrity; explicit distinction between configured and provider-reported values |
| Trace/evaluator evidence | Integrity, authenticity where signed, completeness, bounded ingestion |
| Artifact packets and controller journal | Integrity, custody, monotonic recovery, no overwrite |
| Operator review | Accurate status and limitations; no implied rollout authority |
| Host and network | No SSRF, arbitrary process execution, path traversal, or unbounded resource use |

## Trust boundaries

```text
untrusted files / argv / provider bytes / DNS
                    |
                    v
        bounded parser + semantic admission
                    |
          operator trust policy + keys
                    |
        P0 controller / assessment authority
                    |
          explicit, bounded P1 dispatch
                    |
       immutable raw-free artifact packets
                    |
          independent human review
                    |
        deployment system (out of scope)
```

Inputs are untrusted even when they came from this repository previously.
Parsed JavaScript objects may contain proxies, accessors, symbols, inherited
properties, cycles, duplicate keys, non-finite values, or mutable aliases.
Filesystem paths may be symlinks or may change while an operation is running.
Endpoints and DNS answers may be attacker controlled. Provider bodies and
headers may contain secrets, control characters, malformed Unicode, infinite
streams, or misleading success fields.

## Actors and assumptions

- An operator controls the local process, trust policy, output root, trusted
  evaluator keys, runtime endpoints, secret references, and assessment time.
- A study author may be less trusted than the operator and may supply malicious
  protocols, cases, traces, evidence, or endpoint descriptors.
- A runtime/provider or network peer may be buggy or malicious.
- An evaluator producer may be compromised, stale, unauthorized, or poisoned.
- Another local process may race artifact paths or replace filesystem entries.
- A contributor or dependency may attempt a supply-chain compromise.
- A fully compromised operator account, kernel, Node/Python runtime, secret
  manager, or deployment system is outside TASC's defensive boundary.

## Threats and controls

### SSRF, DNS rebinding, and endpoint confusion

Threats:

- endpoint URLs target cloud metadata, loopback, private networks, link-local
  interfaces, CGNAT, IPv6 ULA, unspecified addresses, or alternate encodings;
- DNS resolves publicly during validation and privately during connection;
- redirects cross the approved boundary;
- an orchestration descriptor changes the origin or runtime identity;
- a path or base path escapes its approved route.

Controls:

- `CollectorTrustPolicy` authorizes an exact alias, origin, runtime build,
  method, path prefix, duration ceiling, and optional authentication reference;
- the P0 plan and signed trace `collectionBinding` pin that non-secret
  reference, while the corresponding credential remains process-local;
- the same plan/binding pins the complete normalized/defaulted inference HTTP
  limits, so a looser P1 timeout or byte ceiling cannot reuse an accepted
  journal or trace identity;
- remote endpoints require HTTPS and public literal/DNS results;
- local endpoints require an exact literal-loopback origin plus explicit local
  mode;
- IPv4, IPv6, mapped, private, link-local, CGNAT, ULA, unspecified, and metadata
  ranges are classified before connection;
- the accepted DNS address is pinned into the actual Undici connection while
  TLS verifies the original hostname;
- redirects are disabled;
- route paths are canonical, bounded, absolute paths with no query, fragment,
  encoding ambiguity, or traversal segment;
- endpoint-descriptor fingerprints bind orchestration and runtime provenance;
  and
- prepared request authority is process-local, expiring, one-shot, and cannot
  survive cloning or JSON serialization.

Residual risk: an approved public service can itself proxy to sensitive
resources. That service is inside the operator's allowed boundary and must be
reviewed separately.

### Credential and payload disclosure

Threats:

- secrets appear in argv, JSON, logs, errors, artifacts, crash dumps, or test
  fixtures;
- raw prompts/outputs enter trace or controller state;
- provider errors reflect request data or authorization headers;
- public hashes enable offline guessing of low-entropy prompts.

Controls:

- protocols and endpoint descriptors contain secret reference names, never
  values;
- header values are supplied just in time by an injected factory or an
  environment lookup selected by the operator;
- raw bodies are ephemeral and durable records contain per-study HMAC
  identities, not public payload hashes;
- persistence types are explicit allowlists rather than serialized transport
  objects;
- provider errors are reduced to category, safe status, and allowlisted request
  ID;
- CLI diagnostics use fixed messages and never include source paths, argv
  values, provider text, or secret values;
- tests assert that secrets and raw payloads do not appear in persisted JSON;
  and
- artifact and log guidance treats real evidence as sensitive even after raw
  payload removal.

Residual risk: raw prompts and outputs necessarily exist in process memory
during a live call. Operators should use isolated workers, avoid core dumps and
debug logging, and scope memory/host access accordingly.

### Malicious or unbounded provider output

Threats:

- infinite/chunk-amplified streams, decompression bombs, oversized headers or
  bodies, slowloris behavior, malformed UTF-8/JSON/SSE/NDJSON, duplicate JSON
  keys, non-finite numbers, misleading terminal frames, or consumer stalls;
- a partial stream is mistaken for a successful completion;
- provider timing/usage is treated as locally measured truth.

Controls:

- compressed responses are rejected;
- headers, content type, body bytes, chunks, frames, lines, events, JSON depth,
  keys, tokens, strings, and numeric tokens have finite limits;
- UTF-8 is fatal and JSON rejects duplicate keys and non-finite values;
- connect, header, inter-chunk idle, and whole-operation deadlines are separate
  and monotonic;
- body idle timing excludes bounded consumer work;
- abort paths drain/destroy readers and release slots;
- route-specific codecs require their actual terminal protocol;
- missing usage, truncation, malformed terminal events, and cancellation after
  send stay incomplete or ambiguous;
- local wire timing and provider-reported timing/usage remain distinct; and
- output text never becomes evaluator evidence automatically.

### Ambiguous sends, crashes, and duplicate calls

Threats:

- the process crashes after opening a socket but before persisting the result;
- a retry duplicates a billable or stateful inference;
- two collectors accept the same logical execution;
- resume loses failures or changes counterbalancing order.
- P1 changes its local HMAC key to manipulate online-window membership.

Controls:

- a self-contained P0 plan binds controller state, frozen policy, public
  membership rule, endpoint targets, validity, and every work ceiling;
- shadow work and every retry are budgeted before contact;
- stable public plan-derived replicate IDs make membership reproducible and
  independent of P1 secrets, while keyed trace/request identities protect
  payload linkage;
- profile order is deterministic and counterbalanced;
- an immutable intent is written before a send lease;
- the lease is durable before network dispatch;
- outcome, accepted trace, and completion marker are separate immutable packets;
- an expired lease with no outcome becomes `sent_unknown` and is never retried;
- only a result proving `not_sent` can consume a pre-budgeted retry;
- every local journal record except the already collector-signed accepted trace
  has a distinct-domain per-study HMAC over study, protocol, plan, run, target,
  kind, schema, authentication metadata, and canonical record body;
- a random MAC-covered lease claim identifies the process whose immutable claim
  won, including when another actor exact-copied its staged bytes;
- identical concurrent publication deduplicates; a different
  correctly-authenticated winner remains authoritative for conservative
  `sent_unknown` races, while unauthenticated content fails closed;
- resume verifies packet manifests and journal authentication before it uses
  state or invokes the collector signer, then reconstructs state monotonically;
- accepted traces are returned once per logical execution; and
- a distinct collector signature covers all attempts, terminal identity,
  collector version, dispatch signature, and plan/endpoint provenance.

Residual risk: a provider can execute a request without returning a provider
request ID or supporting idempotency. TASC reports `sent_unknown`; an operator
must reconcile provider-side logs instead of assuming success or failure.

### Evaluator poisoning and “judge” confusion

Threats:

- policy quality is inferred from model output, log probability, or routing
  confidence;
- an unauthorized/stale evaluator signs scores;
- an evaluator changes between development and holdout;
- a compromised judge systematically favors one profile or slice;
- assessment code silently calls an LLM to fill missing grades.

Controls:

- evaluator evidence is a separate signed contract joined to traces by explicit
  identities;
- allowed keys, algorithms, validity windows, revocations, evaluator identity,
  and production-time skew come from an operator snapshot;
- assessment context fingerprints trust and revocation snapshots;
- evaluator, protocol, dataset, trace, and policy lineage are bound into
  decisions;
- routing signal is recorded separately and cannot substitute for task score;
- missing/untrusted evidence fails coverage;
- offline and sealed online assessment use the same deterministic core; and
- TASC contains no judge-model client, prompt, score generator, or fallback
  grader.

Residual risk: a correctly signed evaluator can still be bad. Calibration,
human-label agreement, slice bias, prompt/model provenance, and adjudication
remain external evidence that reviewers must inspect.

### Selection leakage, protocol drift, and false readiness

Threats:

- holdout data influences candidate selection;
- related groups cross development/holdout boundaries;
- gates, bootstrap seed, evaluator, or policy change after nomination;
- synthetic or incomplete evidence receives a production-looking status;
- an operator treats a recommendation as deployment authority.

Controls:

- protocols are normalized and fingerprinted before evaluation;
- candidate space, hard gates, work budget, evaluator requirements, bootstrap
  parameters, and split rules are versioned;
- development chooses at most one policy; holdout revalidates and tests that
  exact nomination;
- `groupId` disjointness prevents obvious family leakage;
- sealed window manifests bind event range, watermark, membership, source, and
  policy;
- controller events and checkpoints replay deterministically;
- decisions include lineage digests and explicit limitations;
- legacy synthetic evidence is capped at `DEMO_ONLY`, while v2 relies on
  operator trust and custody to keep synthetic fixtures out of real studies;
- every artifact-packet manifest declares `NO_DEPLOYMENT_AUTHORITY`; and
- there is no deployment adapter in the repository.

### Artifact tampering and filesystem races

Threats:

- path traversal, symlink escape, output overwrite, stale-file mixing,
  same-name races, partial writes, manifest substitution, or crash-torn
  publication;
- an attacker swaps a trusted directory between validation and write;
- public digests are mistaken for authenticity.

Controls:

- roots must be absolute, normalized, existing, non-symlink directories whose
  component identities are rechecked;
- targets are one safe, non-hidden segment contained under the trusted root;
- publication uses same-parent private staging directories, exclusive private
  files, bounded sizes, fsync, manifest-last construction, atomic rename, and
  parent-directory fsync;
- existing targets are never overwritten;
- reads verify file type, custody, exact bytes, hashes, manifest digest, and
  packet digest;
- immutable `write-or-verify-identical` supports crash recovery without mutable
  checkpoints;
- resume-authoritative journal bodies are HMAC-authenticated independently of
  their public packet hashes;
- platforms that cannot prove full durability report a degraded level; and
- signatures/HMACs are used for authenticity claims; public SHA-256 digests are
  only identity and corruption checks.

Residual risk: some network filesystems do not honor local atomicity and fsync
semantics. A hostile same-UID actor can still delete records, squat on target
names, or cause denial of service, and a process that can read the service's
environment may also obtain its keys. Use a protected cooperative `0700` root
on a supported local filesystem, or an external transactional object-store
adapter with equivalent, independently reviewed guarantees.

### Denial of service and cost amplification

Threats:

- huge integers or Cartesian products expand before validation;
- one-byte chunks, deep JSON, excessive traces/evidence, bootstrap work, retries,
  concurrency, or model tokens exhaust resources or spend money;
- a child process or its descendant survives an MLX timeout;
- cleanup deletes an attacker-swapped path.

Controls:

- bounded readers limit bytes, chunks, lines, items, depth, keys, tokens,
  decoded strings, and numeric tokens;
- safe-integer work estimates run before candidate expansion, bootstrap,
  signing, filesystem access, or network contact;
- live collection caps cases, profiles, replicates, logical executions,
  attempts, calls, request bytes, records, concurrency, and deadlines;
- provider response and diagnostic output remain bounded;
- MLX configuration has whole-suite process, token-position, and timeout
  ceilings;
- MLX subprocesses use no shell, reduced environment, private process groups,
  output/deadline caps, and descendant termination before leader reaping;
- MLX output is exclusively reserved and failure cleanup only traverses the
  exact opened directory identity; and
- CI exercises parser/security tests without downloading models.

Residual risk: a budget can still authorize expensive work. Budget approval and
provider-side quotas belong to the operator.

### Supply-chain compromise

Threats:

- mutable GitHub Actions, dependency confusion, transitive package changes,
  leaked publish token, or model/runtime code execution during CI.

Controls:

- npm installs use the committed lock and `npm ci`;
- the publishable tarball is built from committed source, installed into a
  clean consumer, imported by package name, and exercised through CLI smoke;
- release automation verifies and publishes the exact tested tarball;
- trusted npm publishing uses OIDC rather than a long-lived registry token;
- GitHub Actions are pinned to full commit SHAs with least-privilege
  permissions;
- dependency review, audit, CodeQL, secret scanning, coverage, Node 22/24, and
  Linux/macOS checks are separate gates;
- MLX runtime and build dependencies use exact hash locks; and
- CI does not install MLX, download models, load arbitrary runtime plugins, or
  contact operator endpoints.

Residual risk: a pinned dependency or action can itself be compromised. Review
updates, minimize dependencies, protect environments, and require branch
protection outside this repository.

## STRIDE summary

| Category | Representative risk | Primary controls |
| --- | --- | --- |
| Spoofing | fake evaluator/runtime/collector identity or substituted plan | distinct operator key roles, signatures, endpoint binding, pinned plan digest/operator custody, explicit identity-verification basis |
| Tampering | edited traces, controller state, or artifact packet | canonical digests, signatures, immutable packets, custody verification |
| Repudiation | uncertain whether a live call was sent | intent/lease/outcome journal and explicit `sent_unknown` |
| Information disclosure | prompt, output, token, path, provider body | HMAC identities, ephemeral secret factories, allowlisted persistence/diagnostics |
| Denial of service | unbounded parse/work/stream/retry | preflight budgets, parser/transport/deadline/concurrency limits |
| Elevation of privilege | endpoint config causes SSRF or deployment | exact trust policy, DNS pinning, process-local authority, no deployment adapter |

## Operator checklist

Before a real study:

1. Keep raw payloads and secrets outside the repository and generated artifact
   root.
2. Review the exact collector trust policy, including origin, runtime build,
   routes, effects, secret references, evaluator keys, and store roots.
3. Pin runtime, backend, model/tokenizer revision, quantization, chat template,
   launch configuration, and orchestration descriptor.
4. Set provider quotas and a TASC work budget that reflects acceptable maximum
   spend.
5. Issue and pin the P0 shadow plan only after the controller reaches
   `SHADOW_ASSESSING`; keep dispatch and collector keys distinct.
6. Validate evaluator calibration and revocation state independently.
7. Seal group-disjoint development/holdout or online-window membership.
8. Run passive probes before inference-canary probes and review identity fields
   that remain unverified.
9. Store artifacts on a filesystem with understood atomicity/fsync behavior.
10. Treat `sent_unknown`, missing usage, partial traces, degraded durability, and
   missing evidence as blockers requiring reconciliation.
11. Review the final packet manually; do not wire TASC status directly to a
    deploy or routing system.

## Reporting

Follow [`SECURITY.md`](../SECURITY.md). Do not include real prompts, model
outputs, credentials, signing keys, private endpoint names, or customer traces
in a public issue or pull request.
