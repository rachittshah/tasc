# Contributing to TASC

TASC is small by design. Contributions should preserve deterministic decisions,
explicit trust boundaries, and a narrow separation between measurement,
recommendation, and production mutation.

## Local setup

```bash
git clone git@github.com:rachittshah/tasc.git
cd tasc
npm ci
npm run typecheck
npm test
npm run build
npm run demo
```

Use Node.js 22 or newer. Do not commit changes to `package-lock.json` unless
`package.json` or dependency resolution intentionally changed.

## Change workflow

1. Create a focused branch from `main`.
2. Add or update tests with every behavior change.
3. Run the full validation set.
4. Use a conventional commit such as `feat(policy): ...` or `fix(schema): ...`.
5. Explain any metric, gate, artifact-schema, or trust-boundary change in the
   pull request.

Before requesting review:

```bash
npm run typecheck
npm test
npm run build
npm run demo
npm pack --dry-run
```

## Design rules

- Never select a policy on holdout data.
- Never infer an unmeasured serving outcome.
- Never let one good metric compensate for a failed hard gate.
- Keep decisions deterministic for identical inputs and bootstrap settings.
- Record failures, elapsed time, and incurred cost rather than dropping them.
- Keep synthetic and real evidence visibly distinct.
- Do not add an automatic production-deployment path.

## Fixtures and sensitive data

Only explicitly fictional **TASC input fixtures** belong in Git. Never commit
real customer prompts, model outputs, private traces, credentials, provider
tokens, attestation keys, device identifiers, or proprietary benchmark data.
Use `examples/synthetic/` as the pattern for reviewable decision-engine tests.

If a change needs realistic private measurements, reproduce the behavior with a
minimal synthetic fixture and keep the source evidence in approved
access-controlled storage.

Sanitized measurements of public models on public benchmark tasks may be
committed under `benchmarks/results/` when they include:

- immutable model revisions and public task/evaluator versions;
- exact runtime, quantization, hardware-class, and workload metadata;
- raw numeric logs and reproducible summary derivation;
- no prompts, generated text, usernames, serial numbers, UUIDs, cache paths,
  tokens, or other host/customer identifiers; and
- a clear boundary between a benchmark snapshot and TASC-ready paired evidence.

Review the model, dataset, and evaluator licenses before publishing results.

## Versioned contracts

Input and artifact versions are part of the public contract. A breaking schema
change requires:

- a new version literal;
- migration or explicit rejection behavior;
- compatibility tests; and
- operating-guide and changelog updates.
