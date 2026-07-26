# TASC

**Trace-Aware Serving Controller**

> Use cheaper inference where it works. Verify that the guardrails still hold.

TASC helps you decide whether routine AI requests can use a faster, cheaper
model setup while difficult requests go to a stronger one. It compares both
setups on the same measured requests, selects a routing rule on development
data, and verifies that unchanged rule on a separate test set.

The TASC decision engine produces a reviewable report. It does not call models,
estimate unmeasured performance, change serving configuration, or deploy
anything. The separate [`benchmarks/mlx/`](benchmarks/mlx/) workflow can collect
local Apple Silicon measurements; it does not turn an aggregate benchmark into
a serving recommendation.

## Value proposition

Always using the strongest setup can be unnecessarily expensive. Always using
the fastest setup can hurt quality or reliability. A **cascade** tries the fast
setup first and escalates selected requests to the expert setup.

```text
request → fast setup → routine → return fast result
                     ↘ difficult or failed → expert setup → return expert result
```

The hard part is showing that the routing rule saves money without hiding a
quality regression, failed request, or slow tail. TASC is that evidence layer:

```text
measure both setups → choose on development data → freeze the rule
→ verify on untouched test data → write a decision report
```

TASC is the bridge between a benchmark table and a serving change. It answers
the harder question: **given paired request-level evidence, which exact routing
rule reduces cost while every quality, slice, latency, throughput, and
reliability requirement still passes?**

It is useful to inference engineers, applied-ML teams, and reviewers who already
have traces from two model/runtime/hardware profiles and need a reproducible
go/no-go packet. It is intentionally not a learned router, load generator, or
deployment controller.

## Real MLX numbers: M4 Pro, July 2026

The repository now includes a reproducible local snapshot from a 20-GPU-core
Apple M4 Pro with 48 GB unified memory. Both models are official, same-family
4-bit MLX conversions released in calendar 2026 and are well below seven
billion parameters:

| Measured model | 2026 release | Parameters | ARC-Challenge `acc_norm` | Short decode | Batch-8 decode |
| --- | --- | ---: | ---: | ---: | ---: |
| [LFM2.5-350M MLX 4-bit](https://huggingface.co/LiquidAI/LFM2.5-350M-MLX-4bit) | Mar 31 | 350M | 31.48% | 650.0 tok/s | 1,447.6 tok/s |
| [LFM2.5-1.2B-Instruct MLX 4-bit](https://huggingface.co/LiquidAI/LFM2.5-1.2B-Instruct-MLX-4bit) | Jan 5 | 1.2B | 39.42% | 303.4 tok/s | 678.3 tok/s |

Quality is the full 1,172-example ARC-Challenge test set, zero-shot, with
length-normalized multiple-choice scoring. Throughput is the median of ten
timed `mlx_lm.benchmark` trials after warmup. “Short” is 128 prompt tokens and
256 generated tokens at batch 1; batch 8 is aggregate throughput for 512 prompt
and 128 generated tokens per sequence.

On this machine the 350M profile decoded **2.14× faster**, while the 1.2B
profile gained **7.94 percentage points** of normalized ARC accuracy. That is a
real speed/quality frontier, not yet proof that a cascade is safe. A TASC
decision additionally needs paired per-request task scores, TTFT, route-time
confidence, failures, cost, and group-disjoint development/holdout evidence.

See the [full result, caveats, and raw evidence](benchmarks/results/2026-07-26-m4-pro/)
and the [rerun instructions](benchmarks/mlx/README.md). Exact model revisions,
MLX versions, every trial, P10/P95 ranges, and peak memory are committed. The
models use the
[LFM Open License 1.0](https://docs.liquid.ai/lfm/help/model-license), so review
its commercial terms separately from TASC's MIT license.

## Example: lower cost with an explicit latency trade-off

The bundled fictional demo measures a fast setup and an expert setup on the
same eight holdout requests. On development data, TASC selects this rule:

- start with the fast setup;
- escalate when the fast setup's supplied routing confidence is below `0.8`;
- escalate when the input reaches `8,000` tokens;
- escalate requests tagged with the configured critical slice; and
- escalate if the fast attempt fails.

It then checks that exact rule—without tuning it again—on the holdout:

| Confirmed holdout metric | Expert only | Selected cascade |
| --- | ---: | ---: |
| Cost per 1,000 requests | $40.00 | $27.25 |
| Mean task score (0–1; higher is better) | 0.9650 | 0.9525 |
| Critical-slice score (0–1; higher is better) | 0.99 | 0.99 |
| Median time to first token | 325 ms | 260 ms |
| P95 end-to-end latency (95% finish within) | 7.35 s | 11.45 s |
| Error rate | 0% | 0% |
| Requests escalated | — | 50% |

The cascade costs **31.9% less** and starts streaming sooner at the median, but
its tail requests take longer because escalation runs both setups. TASC exposes
that trade-off instead of averaging it away. The rule passes only because its
11.45-second P95 remains below the example's predeclared 12-second ceiling.

Because these measurements are fictional, the result is permanently labeled
`DEMO_ONLY`. The P95 is a traffic-weighted estimate from only eight fictional
cases, not an SLA claim or a production recommendation. TASC consumes the
routing confidence recorded in the measurements; it does not calculate or
calibrate that confidence.

## Try it in five minutes

Requirement: Node.js 22 or newer.

```bash
git clone https://github.com/rachittshah/tasc.git
cd tasc
npm ci
npm run demo
```

Expected result:

```text
NOMINATED — artifacts: .../development
DEMO_ONLY — artifacts: .../holdout
Synthetic artifacts: ...
```

`NOMINATED` means one rule passed the development checks. `DEMO_ONLY` means the
same rule passed holdout, but the evidence was synthetic. The generated
`report.md` files show the winning rule, key measured trade-offs, and failed
alternatives; the JSON artifacts retain the complete metrics and gates.

<details>
<summary>Run the two CLI steps directly</summary>

```bash
TASC_RUN_ROOT=$(mktemp -d)

npm run tasc -- nominate \
  --spec examples/synthetic/spec.json \
  --measurements examples/synthetic/dev.json \
  --out "$TASC_RUN_ROOT/development"

npm run tasc -- confirm \
  --spec examples/synthetic/spec.json \
  --measurements examples/synthetic/holdout.json \
  --nomination "$TASC_RUN_ROOT/development/nomination.json" \
  --out "$TASC_RUN_ROOT/holdout"
```

Both output directories must be new. TASC refuses to write into an existing
directory, preventing stale artifacts from being mixed into a new decision.

</details>

## How TASC makes a decision

1. **Measure both setups.** Run the fast and expert setups on the same requests,
   including timeouts, out-of-memory errors, and provider failures. A setup, or
   **profile**, is a specific model, runtime, and hardware combination.
2. **Declare the rules up front.** Define the routing thresholds and hard
   requirements for quality, important request groups, latency, streaming
   speed, service throughput, error rate, and cost.
3. **Select once.** TASC replays the allowed routing rules on development data.
   A cheaper rule cannot compensate for a failed requirement.
4. **Verify once.** TASC freezes the selected rule and evaluates only that rule
   on the untouched holdout. It cannot search the holdout for a better answer.

Escalation uses conservative accounting: if the fast attempt runs before the
expert attempt, both attempts' measured latency and cost count. TASC never
invents a direct-to-expert outcome that was not measured.

## What TASC does—and does not—prove

| TASC does | TASC does not |
| --- | --- |
| Compare two setups using paired measurements | Run benchmarks or call a model provider |
| Apply independent pass/fail requirements | Blend failures into one flattering score |
| Keep failed attempts and rejected rules visible | Predict performance for an unmeasured GPU |
| Separate rule selection from final verification | Tune a rule on holdout data |
| Fingerprint artifacts for reproducibility | Prove that the source measurements are truthful |
| Produce evidence for human review | Change or deploy a production endpoint |

The optional MLX runner measures local models, but it stays outside this
decision contract. TASC will not silently combine aggregate throughput and
aggregate accuracy into fictional per-request evidence.

For real evidence, TASC can add a secret-key signature to detect nomination
tampering between development and holdout. That signature protects continuity;
it does not replace dataset custody, evaluator validation, or operational
review.

## Advantages over an ad-hoc benchmark

- **Paired counterfactuals.** Both profiles are measured on the same requests,
  so the decision is not built from unrelated averages.
- **Cascade accounting.** When a request escalates, both attempts' latency and
  cost remain visible instead of charging only the successful expert call.
- **Hard guardrails.** Savings cannot compensate for a failed quality, critical
  slice, tail-latency, throughput, reliability, or cost requirement.
- **Selection discipline.** Development data chooses one rule; group-disjoint
  holdout data can only verify that frozen rule.
- **Reviewable failure.** Rejected policies, failed gates, uncertainty,
  fingerprints, and provenance survive in machine- and human-readable
  artifacts.
- **Deployment separation.** A passing result remains a manual engineering
  decision, which keeps evidence generation separate from production mutation.

## Use TASC on your own measurements

1. Copy the [example spec](examples/synthetic/spec.json) and define the two
   profiles, allowed routing thresholds, and non-negotiable requirements.
2. Measure both profiles on the same representative requests and replicates.
3. Split related requests into development and holdout using `groupId`.
4. Export measured quality, latency, throughput, cost, and failures using the
   [example datasets](examples/synthetic/).
5. Run `nominate` on development, preserve its artifacts, then run `confirm`
   once on sealed holdout data.

Set `synthetic: false` only when the measurements and provenance are real. Real
confirmation also requires the same environment-only secret for both commands:

```bash
export TASC_ATTESTATION_KEY="<at least 32 UTF-8 bytes from your secret manager>"
```

See the [operating guide](docs/operating-guide.md) for the measurement contract
and the [design document](docs/design.md) for replay, statistics, selection, and
attestation details.

## How TASC helps R&D

TASC turns inference optimization into a falsifiable loop:

1. Benchmark a fast and an expert profile on the same workload.
2. Preregister the routing policies and constraints worth testing.
3. Nominate only policies that pass every development gate.
4. Inspect the Pareto frontier and the exact bottleneck for rejected policies.
5. Run the suggested next experiment—such as quantization, prefix caching,
   chunked prefill, speculative decoding, batching, or reliability
   instrumentation—while keeping the evaluator and gates fixed.
6. Replicate the frozen winner on group-disjoint holdout traces.

This helps teams learn *why* an optimization is or is not deployable. A smaller
model may win decode throughput but lose a critical slice; batching may raise
total TPS while hurting per-user streaming; escalation may recover quality but
break P95 latency. TASC preserves those trade-offs instead of collapsing them
into one leaderboard score.

## Result statuses

| Status | Plain-language meaning |
| --- | --- |
| `NOMINATED` | One rule passed every development requirement and was selected. |
| `NO_CANDIDATE` | No development rule passed every requirement. |
| `DEMO_ONLY` | The frozen rule passed holdout, but some evidence was synthetic. |
| `HOLD` | Holdout failed, or real evidence could not be authenticated. |
| `READY_FOR_MANUAL_PRODUCTION` | Authenticated real evidence passed; a human must still review and roll it out. |

No status changes production.

## Small glossary

| Term | Meaning |
| --- | --- |
| Inference | Running a trained model to answer a request. |
| Profile | One measured model + runtime + hardware setup. |
| Cascade | Try the fast profile, then use the expert profile for selected requests. |
| Gate | A hard pass/fail requirement; savings cannot offset a failure. |
| Holdout | A separate test set that is not used to choose the routing rule. |
| Time to first token | How long a user waits before streamed output begins. |
| P95 latency | 95% of requests finish at or below this time; 5% take longer. |
| Perceived TPS | Token streaming speed seen by one user. |
| Total TPS | Token throughput across the whole serving setup. |

## Development

```bash
npm run typecheck
npm test
npm run build
npm run demo
npm pack --dry-run
python3 -m unittest benchmarks/mlx/test_run_benchmarks.py
```

The public library surface is exported from `src/index.ts`; the CLI adapter is
in `src/cli.ts`. Core contracts, replay, evaluation, reporting, examples, and
tests live in `src/`, `examples/`, and `tests/`.

## Author

Built by [Rachitt Shah](https://github.com/rachittshah).

Released under the [MIT License](LICENSE).
