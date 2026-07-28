# Contributing to TASC

TASC is a trace-aware inference control plane. Contributions must preserve the
architectural boundary:

- P0 is the out-of-band protocol, evidence, policy-assessment, and controller
  layer.
- P1 performs explicitly authorized, bounded inference observations.
- Evaluator evidence is external input. Do not add an LLM-as-judge client,
  hidden grading fallback, or score-generation wrapper.
- No code path may deploy a model, mutate a serving endpoint, or synchronously
  route a production request.

## Set up

Use Node.js 22 or 24 and the npm version declared in `package.json`:

```bash
npm ci
npm run typecheck
npm test
```

The MLX parser/security suite has no MLX or Hugging Face import-time dependency:

```bash
python3 -m unittest benchmarks/mlx/test_run_benchmarks.py
```

Actual MLX benchmarks require Apple Silicon and the two hash-locked installation
steps documented in [`benchmarks/mlx/README.md`](benchmarks/mlx/README.md).

## Before changing behavior

1. Identify the contract and trust boundary affected.
2. Add or update a focused failing test.
3. Keep the implementation narrow and deterministic.
4. Run the focused test, then the proportional repository gates.
5. Update versioned fixtures and operator documentation when behavior changes.

Do not weaken a bound merely to make a fixture pass. Explain and test any new
byte, item, work, concurrency, or deadline ceiling.

## Required local gates

For TypeScript changes:

```bash
npm run typecheck
npm test
npm run coverage
npm run build
node scripts/package-smoke.mjs --git-archive
npm audit --audit-level=high
```

`--git-archive` requires the relevant source to be committed. Before that
commit, run `npm run package:smoke` against the bounded copied workspace.

For documentation-only changes:

```bash
git diff --check
npm run typecheck
```

For MLX changes:

```bash
python3 -m py_compile \
  benchmarks/mlx/run_benchmarks.py \
  benchmarks/mlx/test_run_benchmarks.py
python3 -m unittest benchmarks/mlx/test_run_benchmarks.py
git diff --check -- benchmarks/mlx
```

Never run model downloads or GPU benchmarks in ordinary CI.

## Contract rules

- All external data receives strict runtime validation; TypeScript types are not
  an input boundary.
- Reject proxies, accessors, inherited fields, symbols, duplicate JSON keys,
  non-finite values, unsafe integers, unbounded strings, and unknown fields
  where the contract is exact.
- Estimate worst-case work before expansion, signing, filesystem access, or
  network contact.
- Keep locale, wall clock, randomness, filesystem order, and concurrency out of
  deterministic identities unless they are explicit versioned inputs.
- Preserve measured, reported, modeled, and unavailable evidence classes.
- Never turn missing data or a partial transport success into measured success.
- Public SHA-256 digests are identities, not authentication.
- Persist only allowlisted, raw-free data.

## Runtime profiles

A new runtime profile or build upgrade needs:

- one pinned upstream release/build and primary-source documentation;
- exact request route, response framing, terminal, usage, and error semantics;
- separate `supported`, `conditional`, `unsupported`, and `unknown` capability
  evidence;
- success, malformed, oversized, timeout, cancellation, truncation, and missing
  terminal/usage contract fixtures;
- SSRF, redirect, DNS-pinning, authentication-reference, and redaction review;
- honest provider-reported versus operator-configured identity fields; and
- updates to [`docs/runtime-support.md`](docs/runtime-support.md).

OpenAI-compatible JSON is not sufficient evidence that an existing codec or
profile is semantically correct.

Ray Serve, SkyPilot, BentoML, and similar systems are orchestration provenance
unless a contribution adds and tests a distinct wire contract. Do not import
their SDKs into the core simply for endpoint discovery.

## Security-sensitive changes

Read [`docs/threat-model.md`](docs/threat-model.md) before changing:

- network authorization or DNS resolution;
- authentication and secret handling;
- bounded parsers or streaming codecs;
- dispatch, retry, cancellation, or crash recovery;
- evaluator trust and signatures;
- artifact roots, staging, fsync, rename, or resume;
- subprocess execution; or
- release workflows and package contents.

Tests should prove both the allowed behavior and zero contact/zero write on
preflight rejection. Error tests must assert that source values, paths, provider
text, and secrets are absent.

Report vulnerabilities privately as described in [`SECURITY.md`](SECURITY.md).

## Fixtures and examples

Committed examples must be synthetic or sanitized, contain no credential or
private endpoint, and state which fields are measured versus fictional. Do not
commit raw prompts or outputs merely to exercise identity logic. Prefer a local
contract server for live HTTP tests.

Golden vectors must include the exact preimage/domain and digest. A test that
asserts an unrelated hard-coded hash and bucket is worse than no golden vector.

## Pull requests

Use a conventional title such as:

```text
feat(runtime): add bounded MLC streaming profile
fix(shadow): retain ambiguous dispatch after restart
docs: explain evaluator evidence custody
```

Describe:

- the operator-facing outcome;
- contracts and security boundaries changed;
- tests and exact pass counts;
- runtime/model calls made, if any;
- compatibility or migration impact; and
- residual risks or unavailable verification.

Keep generated artifacts, real measurements, credentials, private endpoints,
model downloads, and local worktrees out of commits.
