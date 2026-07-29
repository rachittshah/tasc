# Security policy

## Supported versions

TASC is pre-1.0. Security fixes target the latest release and the current
`main` branch. Contract compatibility is explicit and versioned; a security fix
may reject data that an older parser accepted.

## Reporting a vulnerability

Use GitHub private vulnerability reporting for this repository or contact the
repository owner directly. Do not open a public issue containing an exploit,
credential, signing key, private endpoint, customer trace, prompt, model output,
or proprietary benchmark.

Include:

- the affected release and commit;
- the boundary involved: input, evaluator trust, network, runtime codec, shadow
  recovery, artifact custody, CLI, subprocess, package, or CI/release;
- a minimal synthetic reproduction;
- expected and observed behavior;
- whether a network call, duplicate inference, file write, secret disclosure,
  or incorrect assessment may have occurred; and
- any provider request ID or artifact digest that can be shared safely.

See the full [`docs/threat-model.md`](docs/threat-model.md) for assets,
assumptions, controls, residual risks, and the operator checklist.

## Sensitive data

Real studies can involve prompts, outputs, user identifiers, evaluator labels,
provider errors, timing, model/runtime identity, endpoint metadata, and cost.
TASC's v2 durable trace path is raw-free, but raw prompt and output bytes still
exist briefly in process memory during a live inference call.

- Keep raw payloads and private evidence outside the repository.
- Use isolated workers and access-controlled storage.
- Disable core dumps and verbose transport/provider logging for sensitive runs.
- Review artifacts before sharing; keyed identities and operational metadata
  can still be sensitive.
- Retain failures and ambiguous sends. Omitting them biases assessment.
- Never import an aggregate quality/throughput table as fabricated per-request
  paired evidence.

The repository ignores common private-output directories as a guardrail. Ignore
rules are not data-loss prevention.

## Secrets and signing keys

Secret values must come from a secret manager, environment reference, or an
injected ephemeral factory selected by operator policy. They must never appear
in protocol, trace, endpoint, case, work-budget, artifact, or CLI argument JSON.

This includes:

- provider authorization values;
- per-study HMAC payload-identity and resume-journal keys;
- Ed25519 dispatch private keys;
- Ed25519 collector-attestation private keys;
- evaluator private keys; and
- the legacy `TASC_ATTESTATION_KEY`.

Never place a secret in source control, shell history, fixtures, generated
artifacts, logs, issues, pull requests, or diagnostic output. Use separate keys
per authority and study, rotate them through the external secret manager, and
review evaluator revocations before assessment.

The legacy HMAC authenticates nomination continuity only. V2 dispatch,
collector-attestation, and evaluator signatures authenticate their respective
exact canonical contracts only. Neither proves that a benchmark is honest, an
evaluator is calibrated, a holdout remained sealed, or a rollout is safe.

## Live endpoint policy

Live probes, invocations, and shadow collection perform real HTTP requests and
can consume capacity or incur cost. Every call must be admitted by an
operator-owned `CollectorTrustPolicy`.

- Remote endpoints require an approved HTTPS origin and public connection-time
  address.
- Local inference requires an exact literal-loopback origin and explicit local
  mode.
- Cloud metadata, private, link-local, CGNAT, ULA, unspecified, unapproved
  loopback, redirects, and path escapes are rejected.
- Inference-canary and consumptive probes require the matching explicit effect.
- Shadow inference requires the profiles configuration to match the P0-pinned
  normalized HTTP-limit digest before signer, filesystem, journal, or network
  effects.
- Set provider quotas as well as TASC work/deadline/concurrency budgets.
- Treat `sent_unknown` as unresolved; do not retry it or assume no charge.

TASC does not discover, create, update, scale, or delete a Ray, SkyPilot,
TensorRT, vLLM, or other deployment.

## Artifact custody

Write real artifacts to a trusted, access-controlled root on a filesystem whose
atomic rename and fsync behavior you understand. TASC refuses existing targets,
symlinks, custody drift, unauthenticated resume packets, and manifest mismatch.
An authenticated immutable winner can conservatively supersede a competing
outcome (for example, `sent_unknown` beating a late response). Create shadow
roots with mode `0700`, retain the same per-study HMAC key for resume, and
review any reported degraded durability before accepting a packet.

Public SHA-256 digests are deterministic identities and corruption checks.
Anyone who can edit an artifact can recompute them. Do not treat a public digest
as authenticity.

## Supply chain

- Install Node dependencies with the committed lock and `npm ci`.
- Install MLX benchmark dependencies with both documented hash locks.
- Do not run model downloads or optional MLX/runtime code in ordinary CI.
- GitHub Actions are pinned to full commit SHAs and use least privilege.
- npm release publishing uses a protected environment and OIDC trusted
  publishing; no long-lived npm token belongs in repository settings.
- Review dependency, action, model, runtime, and lock updates independently.

## Production boundary

TASC is an out-of-band evidence controller. It has no deployment adapter and no
synchronous production-routing function. Every v2 CLI result and
artifact-packet manifest explicitly carries `NO_DEPLOYMENT_AUTHORITY`; legacy
real v1 remains capped at `HOLD`. Other contracts carry only the authority
defined by their type and never gain deployment authority from a status value.

`NOMINATED` or `PASS` means the declared evidence passed the declared
assessment phase. A human must independently review evidence truth,
representativeness, evaluator calibration, capacity, security, rollback,
observability, and change-management approval before any serving change.
