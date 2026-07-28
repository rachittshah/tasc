# TASC operating guide

TASC (Trace-Aware Serving Controller) is an offline decision tool for one
inference-engineering question:

> Can a measured fast serving profile handle routine requests while a measured
> expert profile handles difficult requests, lowering cost without violating
> quality, tail-latency, throughput, or reliability constraints?

It combines deterministic inference-policy replay with development/holdout eval
discipline. It does not call a model provider, predict unmeasured GPU
performance, change an endpoint, or deploy anything.

## Try the synthetic example

The bundled data is fictional and always remains demo-only:

```bash
TASC_RUN_ROOT=$(mktemp -d)

npm run tasc -- nominate \
  --spec examples/synthetic/spec.json \
  --measurements examples/synthetic/dev.json \
  --out "$TASC_RUN_ROOT/dev"

npm run tasc -- confirm \
  --spec examples/synthetic/spec.json \
  --measurements examples/synthetic/holdout.json \
  --nomination "$TASC_RUN_ROOT/dev/nomination.json" \
  --out "$TASC_RUN_ROOT/holdout"
```

Both `--out` paths must be new, nonexistent directories. TASC refuses to reuse
one so stale nominations and confirmations cannot be mixed, and it never
deletes or overwrites an existing artifact directory.

The example nominates a fast-to-expert cascade on development data and
confirms that exact policy on holdout as `DEMO_ONLY`. Its numbers demonstrate
the workflow, not expected performance for any real model or GPU.

## The two-command contract

`nominate` is the only selection step:

1. Parse a versioned spec and development measurement set.
2. Require a complete, paired observation matrix.
3. Generate candidates from preregistered thresholds.
4. Replay every candidate and the expert-only champion.
5. Apply independent hard gates.
6. Build a Pareto frontier and nominate one deterministic winner.

`confirm` is confirmation, not another search:

1. Parse a holdout measurement set.
2. Validate the saved nomination and current spec.
3. Reject evaluator drift and any development/holdout `groupId` overlap.
4. Regenerate and locate the exact nominated policy.
5. Evaluate only that frozen nominee and the champion.

There is no holdout API that picks a better alternative. If the nominee fails,
the result is `HOLD`.

## Inputs

### Inference spec

`tasc-inference-spec-v1` declares:

- the expert champion and fast primary serving profiles;
- model, runtime, and hardware provenance for each profile;
- confidence and input-token thresholds used to enumerate candidates;
- slice labels that always escalate;
- absolute quality, critical-slice, P95 TTFT, P95 end-to-end latency, P10
  perceived TPS, P50 total TPS, error-rate, and cost ceilings/floors;
- a paired quality non-inferiority margin;
- the minimum development cost improvement over the champion;
- a deterministic bootstrap seed and iteration count.

TASC evaluates the Cartesian product of the declared confidence and input-token
thresholds. The optional fast-only candidate supplies a useful low-cost
boundary. Candidate generation and tie-breaking are deterministic.

### Measurement sets

Development and holdout use separate `tasc-measurements-v1` files. Each file
contains dataset provenance, evaluator identity, and cases. A case records:

- stable `id` and cross-split `groupId`;
- input/output shape, repeated-prefix tokens, concurrency, and mode;
- strictly positive traffic weight and slice labels;
- one or more observations for every declared serving profile.

Split related examples by `groupId`, not just case ID. No holdout group may
appear in the development nomination.

Every profile must have the same replicate count within a case. A successful
observation records task score, optional routing confidence, TTFT, end-to-end
latency, output tokens, perceived TPS, total service TPS, measured request
cost, and optional cache-hit state.

Successful timing rows must be physically coherent: end-to-end latency cannot
precede TTFT, multi-token output needs a positive perceived TPS, and the token
count/rate must fit inside end-to-end latency. Validation permits a bounded
rounding/sampling tolerance, but rejects impossible trace exports.

A timeout, provider error, OOM, or other failed attempt is still an observation.
Record it with `status: "failure"`, a failure code, elapsed time, and cost.
Failures receive task score and throughput zero, retain latency and cost, and
count toward error rate. Omitting failed attempts biases every downstream gate
and is rejected as an incomplete matrix.

The case-level `critical` boolean is trace metadata. Escalation and
critical-slice quality gates are driven by case `slices` matching the spec's
`criticalSlices`.

## Replay semantics

TASC selects from recorded observations; it never estimates how a profile would
have behaved.

- Expert-only selects the expert observation.
- Fast-only selects the fast observation.
- A cascade escalates when the fast attempt fails, confidence is missing or
  below threshold, input length reaches the threshold, or a critical slice
  matches.
- An escalated success uses expert quality and output metrics.
- Escalated cost is fast cost plus expert cost.
- Escalated TTFT is fast elapsed time plus expert TTFT.
- Escalated end-to-end latency is both attempts' elapsed time.
- If the expert attempt also fails, the composite row remains a failure.

This is deliberately conservative serial-fallback accounting. Even a routing
rule knowable before execution retains the recorded fast-attempt cost and
latency; TASC does not model an unmeasured direct-to-expert shortcut.

## Metrics, gates, and selection

Operational metrics are traffic-weighted while each case's traffic mass is
divided across its replicates. TASC reports:

- mean task score, success rate, and error rate;
- P50/P95 TTFT and P50/P95/P99 end-to-end latency;
- P10 perceived tokens per second;
- P50 total service tokens per second;
- cost per request and per 1,000 requests;
- escalation rate and configured critical-slice quality.

Quality non-inferiority uses the median score per case for the candidate and
champion, then bootstraps the paired case deltas with the preregistered seed.
At least three paired cases are required. Larger, representative datasets are
strongly preferred; three is an implementation floor, not a claim of adequate
statistical power.

Every gate is independent. Better cost cannot compensate for a quality failure,
and better average latency cannot compensate for a P95 breach. Development also
requires the configured cost improvement over the champion. Passing candidates
enter a Pareto frontier across quality, reliability, latency, throughput, and
cost. The lowest-cost member wins, followed by lower P95 end-to-end latency and
stable policy ID as tie-breakers.

## Outputs and statuses

`nominate` always writes:

- `development-report.json` — all candidate metrics, gates, and frontier;
- `next-experiment.json` — one measured follow-up hypothesis;
- `report.md` — reviewer-oriented decision report.

It writes `nomination.json` only when a candidate is nominated.

`confirm` writes:

- `confirmation.json` — the exact-policy holdout result;
- `report.md` — reviewer-oriented confirmation report.

Statuses mean:

| Status | Meaning |
| --- | --- |
| `NOMINATED` | A development candidate passed all gates and won deterministic selection. |
| `NO_CANDIDATE` | No development candidate passed every gate; no nomination exists. |
| `DEMO_ONLY` | Holdout gates passed, but development or holdout evidence is synthetic. |
| `HOLD` | Holdout gates failed, or legacy v1 processed real evidence. |

Legacy v1 confirmation always returns `HOLD` for real evidence, even when the
nomination HMAC verifies. Plan to migrate to the v2 controller workflow when
its controller and CLI milestones ship; this release does not include that
production-recommendation command. No status causes a serving change.

## Collecting local MLX measurements

The optional [`benchmarks/mlx/`](../benchmarks/mlx/) workflow is a reference
collector for Apple Silicon. It pins current-year sub-7B model revisions and
records:

- random-token prefill and decode throughput from `mlx_lm.benchmark`;
- peak MLX allocator memory for each workload;
- a full standardized quality task through `mlx_lm.evaluate`; and
- sanitized hardware, OS, runtime, power-source, and thermal-warning metadata.

The committed [2026-07-26 M4 Pro snapshot](../benchmarks/results/2026-07-26-m4-pro/)
is deliberately not shaped like `tasc-measurements-v1`. Runtime throughput and
aggregate ARC-Challenge accuracy were measured in separate programs. Joining
them would create per-request relationships, latency, confidence, and cost that
were never observed.

Use the snapshot to screen model/runtime candidates and design the paired
experiment. To collect TASC-ready MLX evidence:

1. Freeze public task cases, evaluator code, model commits, quantization,
   generation settings, MLX versions, and group-disjoint split assignments.
2. Run both profiles on every same case and replicate. Randomize execution order
   so drift and thermal state are not confounded with one profile.
3. Synchronize pending Metal work before stopping each clock. Measure request
   start, first streamed output token, and final output token directly; do not
   derive TTFT from aggregate prefill TPS.
4. Retain failures and their elapsed time. Keep batch aggregate throughput
   separate from single-request perceived TPS.
5. Score each case with a frozen deterministic or validated evaluator.
6. Supply a genuine route-time confidence. For multiple choice this can be a
   calibrated normalized option likelihood, fitted on development data and then
   frozen. It cannot be copied from the final task score.
7. Measure energy and define reviewable hardware-amortization assumptions if
   local request cost is a selection objective. Zero expert cost makes relative
   cost improvement undefined by design.
8. Preserve raw records and the sanitized environment beside the exported
   TASC inputs.

MLX uses the Metal GPU for model kernels, but tokenization and host orchestration
still use the CPU and unified memory. Describe results as “MLX/Metal on Apple
Silicon,” not as a GPU-only end-to-end measurement.

## Replacing the fixtures with real measurements

1. Define the task and latency/cost budget before benchmarking.
2. Freeze the profile identities, candidate thresholds, critical slices, gates,
   evaluator version, bootstrap settings, and split assignment.
3. Create group-disjoint development and holdout cases representative of the
   production traffic mix, including difficult slices and failures.
4. Run both profiles on the same cases and paired replicates under comparable
   arrival patterns, concurrency, cache state, and network boundaries. Do not
   combine unrelated fast and expert traces as if they were paired.
5. Export measured—not inferred—latency, throughput, cost, and failure rows.
   Shadow or controlled dual execution is usually needed to obtain both
   counterfactual outcomes.
6. Set `synthetic: false` only when the evidence and provenance are real.
7. Run `nominate` once on development, preserve the artifact, then run
   `confirm` once on the sealed holdout.

Measure end-to-end latency as users experience it as well as runtime metrics.
Keep perceived TPS distinct from total service TPS: the first is user-facing
decode speed, while the second is system throughput.

## Evaluator calibration

Task scores must be bounded from 0 to 1 and mean the same thing across profiles
and splits. Prefer deterministic checks or blinded human labels where possible.

Before using an LLM judge:

1. Build a representative, human-labeled calibration set.
2. Measure agreement and slice-specific false-positive/false-negative behavior.
3. Freeze the prompt/model/rubric as a versioned evaluator.
4. Use the same evaluator identity, version, kind, and validation state on both
   splits.
5. Keep routing confidence separate from evaluator score.

TASC trusts the supplied `evaluator.validated` metadata; it does not run judge
calibration itself. The validation evidence belongs beside the TASC artifacts
in a real review packet.

## Attestation and trust boundary

Public hashes such as `selfDigest` are deterministic content and corruption
checks. Anyone who edits an artifact can recompute a public hash, so hashes are
not authenticity.

For authenticated legacy v1 review, load the same secret into the environment
for both commands:

```bash
export TASC_ATTESTATION_KEY="<at least 32 UTF-8 bytes from your secret manager>"
```

There is intentionally no CLI key flag. Never place the key in shell history,
source control, an artifact, or a log. The nomination stores only its
`hmac-sha256` digest. Confirmation with the trusted key rejects coherently
edited nominations. Passing real evidence always returns `HOLD` in legacy v1;
the verification does not make a production recommendation. The v2 controller
workflow will provide that decision path when its controller and CLI milestones
ship; it is not a command in this release.

The HMAC authenticates nomination continuity, not truth. It does not prove that
the raw benchmark is honest, the evaluator is good, `synthetic` is labeled
correctly, or the holdout was operationally sealed. A production reviewer
should rerun confirmation with trusted inputs and the secret rather than trust
a copied JSON status. Dataset custody, evaluator validation, access control,
and audit logging remain external responsibilities.

## The self-improvement loop

Rejected candidates and failed gates stay visible. `next-experiment.json`
turns the dominant observed shortfall into a falsifiable follow-up:

- repeated-prefix TTFT → benchmark prefix caching/cache-aware routing;
- long-input TTFT → benchmark chunked prefill;
- low perceived TPS → benchmark speculative decoding;
- low total TPS → benchmark batching/concurrency settings;
- cost pressure → add a measured quantized profile behind unchanged gates;
- tail latency or failures → instrument queues, cold starts, autoscaling, and
  routing.

When a candidate wins, the next step is disjoint shadow-trace replication, not
automatic rollout. These are hypotheses with required measurements; they are
never reported as achieved gains.

## Verify the implementation

```bash
npx vitest run \
  tests/schema.test.ts \
  tests/policy.test.ts \
  tests/evaluate.test.ts \
  tests/cli.test.ts

npm run typecheck
```

The implementation and design rationale live in
the [`src/`](../src/) library and
[`docs/design.md`](design.md).
