# TASC — Trace-Aware Serving Controller

- Date: 2026-07-24
- Status: Implemented proof of concept
- Scope: Private standalone repository. The synthetic path needs no credentials, while legacy v1 can authenticate real-data artifact continuity with an optional environment-only attestation key.

## Outcome

TASC is an eval-gated inference policy lab. It turns measured per-request outcomes from two serving profiles into a reproducible recommendation for an application-level inference cascade.

The proof of concept must answer one useful question:

> Can a fast serving profile handle routine requests while an expert profile handles difficult requests, reducing cost without violating task quality, latency, throughput, or reliability constraints?

TASC does not claim to optimize CUDA kernels, GPU layouts, or model servers without hardware measurements. It replays measured observations, evaluates policies on a development split, nominates exactly one policy, and confirms only that frozen policy on a sealed holdout split.

A gate-passing synthetic run produces `DEMO_ONLY`; any failed holdout gate produces `HOLD`. Real legacy v1 confirmation always produces `HOLD`, even when the development nomination's HMAC attestation verifies. Users should plan to migrate to the v2 controller assessment when Task 5 lands; this release does not include that production-recommendation command. Every status remains decision support, and TASC never edits production configuration.

## Why this project

Three concepts were considered:

1. A GPU recipe tuner for quantization, batching, and parallelism.
2. An inference observability recorder.
3. An application-level cascade optimizer with evaluation gates.

The cascade optimizer is the strongest proof of concept because it is useful without pretending that local synthetic runs predict GPU performance. It combines self-improving evaluation discipline with inference engineering's core quality, latency, throughput, reliability, and cost trade-offs. The other two concepts become future adapters and experiment generators.

## Boundaries

TASC will:

- consume observations produced by a benchmark or production trace export;
- require complete outcome matrices, including timeouts and provider failures;
- distinguish perceived token rate from total service throughput;
- compare P50/P90/P95/P99-style distributions rather than averages alone;
- keep development selection and holdout confirmation as separate commands;
- content-fingerprint specs, datasets, policies, and decisions for deterministic identity and consistency checks;
- retain rejected candidates and failed gate reasons;
- suggest the next measured inference experiment;
- run with no credentials using clearly labeled synthetic fixtures;
- optionally HMAC-attest a real-data nomination with an out-of-band environment secret.

TASC will not:

- call a model provider;
- invent performance improvements;
- tune a live endpoint;
- apply a production configuration;
- expose copyrighted source material or private benchmark or customer data;
- treat synthetic data as production evidence.

## Architecture

```text
spec.json + dev measurements
          |
          v
 validate complete empirical matrix
          |
          v
 deterministic candidate generation
          |
          v
 replay fast / expert observations
          |
          v
 metrics + hard gates + Pareto frontier
          |
          v
 one content-fingerprinted, optionally HMAC-attested nomination
          |
          | separate command
          v
 holdout measurements + nomination
          |
          v
 exact-policy confirmation
          |
          v
 DEMO_ONLY | HOLD
```

The implementation lives in `src/`:

- `schema.ts`: versioned Zod contracts and semantic validation;
- `policy.ts`: deterministic policy generation, fingerprinting, and empirical replay;
- `evaluate.ts`: metrics, paired quality uncertainty, gates, Pareto selection, and holdout confirmation;
- `report.ts`: diagnostics and human/machine-readable artifacts.

`src/cli.ts` is a small CLI adapter. It performs file I/O but delegates all decisions to pure library functions.

## Versioned input contracts

### Inference spec

The spec declares:

- a champion profile and a faster primary profile;
- model/runtime/hardware metadata for transparent provenance;
- a deterministic candidate space of confidence and input-length thresholds;
- critical slices that always escalate;
- absolute service-level constraints;
- a paired quality non-inferiority margin;
- a minimum cost improvement required on development data;
- a fixed bootstrap seed and iteration count.

Candidate policies use the fast profile first. They escalate to the expert profile when any configured rule fires:

- the primary attempt fails;
- confidence is missing or below the candidate threshold;
- input length is at or above the candidate threshold;
- the case belongs to a critical slice.

The champion is expert-only. An optional fast-only candidate provides a useful lower-quality boundary point.

### Measurements

Development and holdout are separate `tasc-measurements-v1` files. Each contains:

- dataset ID, version, source, split, and a `synthetic` flag;
- evaluator ID, version, kind, and validation state;
- cases with stable `id` and cross-split `groupId`;
- workload shape: input/output tokens, repeated-prefix tokens, concurrency, mode, and criticality;
- strictly positive traffic weight and slice labels;
- one or more observations for every declared serving profile.

A successful observation records:

- bounded task score and optional confidence;
- TTFT and end-to-end latency;
- output token count;
- perceived tokens per second;
- total service tokens per second;
- request cost;
- optional cache-hit state.

A failed observation remains a row. It records an explicit failure status, cost, and elapsed latency. Failed rows contribute task score zero and count toward error rate. Omitting them is invalid.

All numeric inputs must be finite and non-negative except traffic weight, which must be strictly positive so zero-mass cases cannot influence paired inference or its minimum sample count. Replicate counts must match across profiles within a case so replay remains paired.

Successful timing rows must also be internally coherent: end-to-end latency cannot precede TTFT, multi-token responses require positive perceived TPS, and token count/rate must fit within end-to-end latency. A bounded tolerance accommodates rounded or slightly different provider measurement windows without admitting physically impossible rows.

An LLM judge may supply task scores only when the measurement metadata marks that judge as independently validated. Human and deterministic evaluators remain allowed. TASC trusts this metadata; evaluator calibration happens outside the tool and must be reviewed separately.

## Empirical policy replay

TASC never predicts a profile outcome. It chooses among recorded observations:

- expert-only uses the expert observation;
- fast-only uses the fast observation;
- a cascade uses fast unless an escalation rule fires;
- an escalated success uses expert quality and output metrics;
- escalated cost is `fast cost + expert cost`;
- escalated TTFT is `fast elapsed time + expert TTFT`;
- escalated end-to-end latency is `fast elapsed time + expert elapsed time`;
- if expert also fails, the composite row is a failure and retains both costs and elapsed times.

This is intentionally conservative: a serial fallback cannot hide the time and money spent on the first attempt.

## Metrics and gates

Each policy reports:

- traffic-weighted mean task score;
- success and error rate;
- P50 and P95 TTFT;
- P50, P95, and P99 end-to-end latency;
- P10 perceived TPS;
- P50 total TPS;
- cost per request and cost per 1,000 requests;
- escalation rate;
- critical-slice task score.

Legacy v1 cannot derive exact-policy service capacity for a serial cascade from
either component profile's token rate. Accordingly,
`PolicyMetrics.p50TotalTokensPerSecond` is nullable, and the deprecated
`ReplayedRow.totalTokensPerSecond` input is optional source compatibility only;
it is never treated as cascade capacity. Existing library consumers must handle
the explicit unavailable case. TASC does not fabricate a numeric projection.

Development and holdout apply the same preregistered hard gates:

- paired quality bootstrap lower bound is not below the configured non-inferiority margin;
- mean task score meets the absolute floor;
- every configured critical slice meets its floor;
- P95 TTFT and P95 end-to-end latency stay under their ceilings;
- P10 perceived TPS and P50 total TPS stay above their floors;
- error rate stays under its ceiling;
- cost per 1,000 stays under its ceiling.

Development additionally requires the configured cost improvement relative to the champion.

No weighted score can compensate for a failed hard gate. Passing candidates are reduced to a Pareto frontier across quality, error rate, latency, throughput, and cost. TASC nominates the lowest-cost frontier member, with lower P95 end-to-end latency and then stable policy ID as deterministic tie-breakers.

At least three paired cases are required for an inferential quality decision. Smaller datasets remain invalid rather than producing false confidence.

## Split discipline, artifact consistency, and optional attestation

Candidate enumeration and selection use development data only.

The nomination binds:

- parsed spec digest;
- development dataset digest;
- evaluator identity and version;
- development group IDs;
- development synthetic provenance;
- exact policy body and policy digest;
- champion and candidate metrics, gates, and decision digest;
- a public self-digest and, when configured, an `hmac-sha256` attestation.

Holdout confirmation:

1. validates the holdout file and its `split`;
2. verifies the HMAC first when an attestation key is supplied;
3. always revalidates the nomination's self-digest;
4. checks the current spec digest;
5. regenerates the allowed candidate space and finds the exact nominated policy;
6. rejects any holdout `groupId` seen in development;
7. requires the evaluator identity and version used for nomination;
8. evaluates only the champion and nominated policy;
9. writes a confirmation packet.

There is no direct “pick the best holdout candidate” API.

The public self-digest is a reproducibility and corruption check, not authentication: anyone can coherently edit and re-digest public data. Authenticity for a real-data nomination requires an out-of-band `TASC_ATTESTATION_KEY` of at least 32 UTF-8 bytes, supplied to both commands through the environment and never written to a CLI flag, artifact, or log. Successful verification authenticates nomination continuity but does not change the legacy v1 safety boundary: real confirmation remains `HOLD`. Users should plan to migrate to the v2 controller assessment when Task 5 lands; this release does not include that production-recommendation command.

Neither the public hashes nor the HMAC prove benchmark provenance, evaluator quality, honest synthetic labeling, or operational sealing of the holdout. These remain manual review and data-custody responsibilities.

## Diagnostics and self-improvement

Rejected policies are first-class results. TASC converts the dominant failed gate or bottleneck into a next-experiment proposal:

- high TTFT with repeated prefixes → benchmark prefix caching and cache-aware routing;
- high TTFT on long inputs → benchmark chunked prefill; consider disaggregation only at sustained scale;
- low perceived TPS at low concurrency → benchmark speculative decoding;
- cost pressure on high-precision profiles → benchmark quantization behind the same quality gates;
- low total TPS at high concurrency → benchmark continuous-batch and concurrency targets;
- high end-to-end latency or errors → inspect queues, cold starts, autoscaling, routing, and provider failures.

Every proposal is phrased as a hypothesis with measurement requirements. No unmeasured gain is reported as fact.

## CLI and artifacts

Development nomination:

```bash
npm run tasc -- nominate \
  --spec examples/synthetic/spec.json \
  --measurements examples/synthetic/dev.json \
  --out /tmp/tasc-dev
```

Holdout confirmation:

```bash
npm run tasc -- confirm \
  --spec examples/synthetic/spec.json \
  --measurements examples/synthetic/holdout.json \
  --nomination /tmp/tasc-dev/nomination.json \
  --out /tmp/tasc-holdout
```

`nominate` always writes `development-report.json`, `next-experiment.json`, and `report.md`; it writes `nomination.json` only when the status is `NOMINATED`. `confirm` writes `confirmation.json` and `report.md`. Reports prominently label synthetic evidence.

Each `--out` path must be a fresh, nonexistent directory. TASC refuses to reuse an output directory, never deletes an old artifact set, and never overwrites it.

For real-data attestation, `TASC_ATTESTATION_KEY` is read only from the environment. The same trusted value must be present for nomination and confirmation. The synthetic example intentionally runs without it.

## Error handling

Input and integrity failures are fatal and produce a non-zero exit:

- invalid versions or unknown profiles;
- duplicate IDs;
- incomplete matrices;
- mismatched replicate counts;
- non-finite or out-of-range numbers;
- unvalidated LLM judges;
- direct holdout use in nomination;
- non-holdout use in confirmation;
- self-inconsistent nomination edits;
- coherently re-digested nomination edits when keyed attestation verification is enabled;
- cross-split group leakage;
- evaluator drift.

Ordinary candidate gate failures are not runtime errors. They are retained in the report and lead to `NO_CANDIDATE` or `HOLD`.

## Verification strategy

Tests cover:

- schema and complete-matrix validation;
- conservative replay for every escalation rule and double failure;
- deterministic candidate and artifact fingerprints;
- explicit failure accounting and percentile metrics;
- hard-gate and Pareto selection behavior;
- holdout isolation and leakage rejection;
- public self-digest inconsistency rejection and keyed attestation rejection;
- `DEMO_ONLY` versus the legacy v1 real-data `HOLD` boundary;
- CLI artifact creation on the bundled synthetic example.

Final verification includes targeted Vitest suites, TypeScript typecheck, the full test suite, both CLI commands, and `git diff --check`.
