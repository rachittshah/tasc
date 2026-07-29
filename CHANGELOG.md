# Changelog

All notable changes to TASC are documented here.

The project follows semantic versioning once a stable public API is declared.

## Unreleased

### Added

- The v2 trace-control-plane contracts: experiment protocol, execution profile,
  dispatch-signed trace envelope, evaluator-signed evidence, assessment
  context, policy bundle, sealed window manifest, controller events, and
  bounded experiment proposals.
- Operator-controlled Ed25519 evaluator trust, revocation, validity, freshness,
  rubric, calibration, and producer verification.
- Deterministic evidence joining with seeded group splits, online membership,
  complete diagnostics, profile/route/evaluator lineage checks, and explicit
  failed, ambiguous, missing, abstained, duplicate, conflicting, and orphan
  evidence states.
- Development policy nomination, exact-policy holdout confirmation, and sealed
  shadow-online assessment with grouped paired bootstrap inference,
  traffic-weighted operational metrics, critical-slice group coverage, and
  fail-closed exact-policy capacity.
- A content-addressed controller journal with bounded replay, checkpoint
  verification, window revisions, drift recording, and retirement.
- Pure bounded next-experiment intents with frozen controls, evidence
  requirements, prior-history checks, stop conditions, and mandatory operator
  registration.
- Immutable, restrictive-mode, manifest-last artifact packets with atomic
  publication, identical-content resume, final custody revalidation, pinned
  manifest verification, and copy-returning bounded reads.
- Bounded JSON and NDJSON ingestion with duplicate-key, Unicode, depth,
  cardinality, lexical-work, number, byte, line, and chunk limits.
- Build-pinned runtime profiles and real inference wire integrations for vLLM,
  SGLang, TensorRT-LLM, llama.cpp, Ollama, Text Generation Inference, LM
  Studio, and MLX-LM, including OpenAI-compatible and supported native
  JSON/SSE/NDJSON contracts.
- Runtime capability probes and inference invocation with exact route/effect
  authorization, whole-operation deadlines, one-shot prepared authority,
  cancellation, bounded framing, truthful usage/model identity, and raw-free
  outcomes.
- Ray Serve plus mode-specific SkyPilot cluster and SkyServe service
  orchestration descriptors that bind provenance without importing cluster
  SDKs or mutating services.
- SSRF-resistant collector policy with exact endpoint/runtime/path/auth
  binding, public-address and literal-loopback modes, DNS/IP pinning into the
  actual connection, TLS hostname preservation, and disabled redirects.
- A preflighted paired shadow runner with stable counterbalancing, bounded
  concurrency, immutable `intent → lease → outcome → accepted → complete`
  records, distinct-domain HMAC-authenticated resume state, private lease
  claims, crash resume, accepted-trace deduplication, and fail-closed
  `sent_unknown` handling.
- A self-contained P0 shadow-run plan that binds controller state, the frozen
  policy, deterministic window membership, endpoint/profile provenance,
  validity, and the complete P1 work budget before any collection effect.
- Separate dispatch and collector Ed25519 authorities: the first authorizes
  routing before contact, while the second attests the complete raw-free final
  observation, including attempts, timing, usage, cost, output identity, and
  endpoint/plan provenance.
- V2 CLI commands for protocol/trace/evidence validation, development,
  holdout, and window assessment, experiment proposals, runtime probes, and
  resumable shadow collection. Secrets are referenced by JSON and read only
  from allowlisted environment variables.
- A signed synthetic control-plane fixture and deterministic golden demo that
  verifies trust, assesses development and a sealed window, proposes the next
  experiment, publishes raw-free recommendations, and rereads every artifact
  manifest and payload digest under a zero-network test.
- A reproducible Apple Silicon MLX benchmark runner with immutable model
  revisions, hash-locked runtime and build dependencies, isolated process
  groups, strict bounded configuration/result parsing, sanitized environment
  provenance, restrictive output custody, and tested failure cleanup.
- A real 2026-07-26 M4 Pro snapshot for two official 2026 sub-7B LiquidAI
  models, covering three throughput workloads and the full ARC-Challenge test
  task.
- Cross-platform Node 22/24 CI, coverage floors, package-consumer smoke tests,
  Python safety tests, audit/dependency/secret checks, CodeQL, and a
  trusted-publishing release workflow with pull-request dry runs.
- A P0-only root export plus a deliberate `@rachittshah/tasc/runtime` P1
  subpath, CLI binary metadata, constrained tarball contents, clean prepack
  builds, and exact packed-artifact/type-consumer verification.
- Production architecture, operations, runtime support, migration, threat
  model, security, and contribution documentation.

### Changed

- Reframed TASC as a P0 out-of-band trace-aware controller with subordinate P1
  bounded inference effects. TASC can collect live inference traces but still
  has no synchronous production-routing or deployment authority.
- Made external evaluator evidence a separately signed input. TASC does not
  provide a judge prompt, judge client, reward model, or evaluator fallback.
- Replaced candidate-level independent-case assumptions with paired
  replicate/case effects and independent-group resampling.
- Made development the only candidate-enumeration phase. Holdout and sealed
  windows replay exactly one frozen v2 policy.
- Made metric evidence classes explicit (`measured`, `reported`, `modeled`, or
  `unavailable`) and deferred exact-policy service-capacity decisions to a
  sealed online window.
- Retained legacy v1 `nominate`/`confirm` for migration while capping real
  legacy confirmation at `HOLD`.
- Bound TensorRT-LLM, MLX-LM, Ollama, and TGI capability claims to exact tagged
  server source files while retaining readable upstream guides as secondary
  evidence.

### Fixed

- Prevented correlated cases and duplicated replicates from narrowing the
  quality interval as though they were independent samples.
- Prevented serial cascade capacity from being inferred from one component
  profile's request-level token rate.
- Prevented missing or unattested capacity from being misdiagnosed as a
  quality regression in next-experiment selection.
- Prevented endpoint configuration from relabeling runtime, backend, model, or
  deployment identity in collected traces.
- Prevented P1 authentication-reference changes from colliding with or
  deduplicating a different P0-approved credential/tenant lineage.
- Prevented P1 timeout and byte-limit changes from reusing a P0 plan, accepted
  journal, or trace identity by binding normalized limits into the target and
  signed collection provenance.
- Prevented forged local admission, lease, outcome, intent, or completion
  journal packets from being promoted into collector-signed trace evidence.
- Made signed control-plane fixture regeneration byte-for-byte stable with
  explicitly public, domain-separated fixture-only key derivation.
- Rejected declared case/replicate/profile products before deterministic job
  expansion, closing a pre-admission CPU and memory amplification path.
- Classified SGLang `/health` conservatively as an inference canary because
  launch configuration can make that endpoint perform one-token generation.
- Marked MLX-LM v0.31.3 structured output unsupported because its pinned server
  has no `response_format` or grammar request contract.
- Rejected the pre-release plain-SkyPilot `{serviceName}` locator shape;
  `skypilot` now requires `clusterName`, while `skyserve` requires
  `serviceName`, so endpoint fingerprints cannot silently change meaning.
- Prevented ambiguous post-send failures from being retried after a crash.
- Prevented loose caller-authored policy/window digests and automatic
  conditional-capability canaries from escaping P0 shadow authority.
- Prevented unsigned operational outcomes or endpoint provenance from entering
  accepted shadow evidence.
- Prevented copied/serialized prepared-invocation metadata from retaining
  network authority.
- Prevented unbounded response framing, reflected provider errors, duplicate
  JSON keys, non-finite numbers, unsafe artifact reuse, and incomplete
  manifest reads from crossing persisted trust boundaries.

### Security

- Durable controller, shadow, assessment, and recommendation records exclude
  prompts, outputs, credentials, HMAC keys, and private signing keys.
- Every v2 CLI result and artifact-packet manifest carries
  `evidence-only-no-deployment-authority`; the underlying decisions remain
  evidence contracts with no deployment adapter or implied rollout authority.
- Authentication, payload-identity, dispatch-signing, and collector-signing
  secret values are environment-only; CLI JSON and argv carry allowlisted
  reference names.
- Runtime and artifact operations fail closed on disallowed network targets,
  symlinked/noncanonical custody roots, path drift, deadline exhaustion,
  framing ambiguity, and manifest or payload digest drift.

## 0.1.0 — 2026-07-24

Initial standalone legacy v1 release.

### Added

- Strict, versioned inference-spec and measurement contracts.
- Complete paired profile-matrix validation, including failed observations.
- Deterministic expert-only, fast-only, and cascade policy replay.
- Traffic-weighted quality, latency, throughput, reliability, and cost metrics.
- Paired bootstrap quality non-inferiority.
- Independent hard gates and deterministic Pareto selection.
- Content fingerprints and optional HMAC nomination attestation.
- Group-disjoint exact-policy holdout confirmation.
- Reviewer-facing JSON and Markdown evidence artifacts.
- Failure-driven next-experiment diagnostics.
- `nominate` and `confirm` CLI commands.
- Fictional end-to-end development and holdout example.
- Standalone package exports, build, tests, documentation, and security model.

### Safety

- Synthetic evidence is permanently capped at `DEMO_ONLY`.
- The v1 CLI has no model-provider caller or serving mutation path.
- Real evidence without verified attestation returns `HOLD`.
