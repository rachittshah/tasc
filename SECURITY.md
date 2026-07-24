# Security policy

## Supported versions

TASC is an early proof of concept. Security fixes target the latest commit on
`main` and the current `0.1.x` line.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting for this repository, or contact
the repository owner directly. Do not open a public issue containing an
exploit, secret, customer trace, prompt, model output, or proprietary benchmark.

Include:

- the affected commit;
- a minimal reproduction using synthetic data;
- the expected and observed trust-boundary behavior; and
- whether any nomination, confirmation, or secret material may have leaked.

## Sensitive measurements

Real measurement sets may contain prompts, outputs, user identifiers, provider
errors, timing traces, and cost data. TASC does not upload them, but its CLI
reads and writes local files supplied by the operator.

- Keep real measurements outside the repository.
- Use access-controlled storage for evidence and generated artifacts.
- Review reports before sharing; they preserve profile, dataset, evaluator, and
  slice metadata.
- Do not replace failed observations with missing rows. Omissions undermine the
  safety gates.

The repository ignores `measurements/private/`, `artifacts/`, `runs/`, and
`.tasc/` as guardrails, but ignore rules are not a data-loss-prevention system.

## Attestation key

`TASC_ATTESTATION_KEY` must contain at least 32 UTF-8 bytes and should come from
a secret manager. It is intentionally accepted only through the environment:
there is no CLI flag.

Never place the key in:

- source control;
- shell history;
- fixture or measurement JSON;
- generated artifacts;
- logs; or
- issue and pull-request content.

The HMAC authenticates continuity between a development nomination and holdout
confirmation. It does **not** prove that measurements are honest, an evaluator
is calibrated, a holdout remained sealed, or a rollout is safe.

## Production boundary

TASC has no deployment adapter and never mutates a serving configuration.
`READY_FOR_MANUAL_PRODUCTION` is a review status, not authorization to deploy.
A human must independently review evidence, capacity, security, rollback, and
observability before any serving change.
