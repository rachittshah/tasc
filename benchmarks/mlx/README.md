# MLX benchmark workflow

This directory makes the repository's local Apple Silicon snapshot
reproducible. It measures two things:

1. MLX prefill throughput, decode throughput, and peak allocator memory with
   Apple's `mlx_lm.benchmark`.
2. Full-task ARC-Challenge quality with `mlx_lm.evaluate` and
   `lm-evaluation-harness`.

These are real local measurements, but they are not a TASC nomination or
confirmation. The throughput benchmark has no task score, and the aggregate
quality eval has no per-request TTFT, route-time confidence, failure, or cost
record. Combining those aggregates into a `tasc-measurements-v1` file would
invent a paired trace that was never observed.

## Why these models

The pinned pair is:

- [`LiquidAI/LFM2.5-350M-MLX-4bit`](https://huggingface.co/LiquidAI/LFM2.5-350M-MLX-4bit),
  released March 31, 2026; and
- [`LiquidAI/LFM2.5-1.2B-Instruct-MLX-4bit`](https://huggingface.co/LiquidAI/LFM2.5-1.2B-Instruct-MLX-4bit),
  released January 5, 2026.

Both are calendar-2026 models, comfortably below seven billion parameters,
official LiquidAI MLX conversions, and use the same 4-bit affine/group-64
format. That controls family, converter, and precision better than comparing
unrelated community quantizations. Both use the
[LFM Open License 1.0](https://docs.liquid.ai/lfm/help/model-license), which is
not Apache or MIT; review its commercial-use terms before deployment.
The model-selection cutoff for this snapshot is **2026-07-26**; models released
after that date are outside its year-to-date claim.

Exact revisions, release sources, and workloads are frozen in
[`benchmark_config.json`](benchmark_config.json).

## Environment

Requirements:

- Apple Silicon with Metal support;
- macOS 14 or newer;
- Python 3.12; and
- [`uv`](https://docs.astral.sh/uv/) or another environment manager.

Create an isolated environment:

```bash
uv venv --python 3.12 .venv-mlx
uv pip install --python .venv-mlx/bin/python \
  --require-hashes \
  -r benchmarks/mlx/build-requirements.lock
uv pip install --python .venv-mlx/bin/python \
  --require-hashes \
  --no-build-isolation \
  -r benchmarks/mlx/requirements.lock
```

`requirements.txt` is the small direct-constraint input used to regenerate the
fully resolved, hash-pinned `requirements.lock`. The lock is the reproducible
runtime install surface. Three transitive packages are available only as source
distributions, so their PEP 517 bootstrap is separately closed by
`build-requirements.lock`; `--no-build-isolation` is required so an installer
cannot fetch an unpinned build backend. Do not compare a new result with the
committed snapshot as though the runtime were controlled if MLX, `mlx-lm`, the
task implementation, tokenizer stack, transitive dependencies, build
bootstrap, or model revision changed.

Regenerate both locks deliberately:

```bash
MACOSX_DEPLOYMENT_TARGET=14.0 uv pip compile \
  benchmarks/mlx/build-requirements.txt \
  --python-version 3.12 \
  --python-platform aarch64-apple-darwin \
  --generate-hashes \
  --output-file benchmarks/mlx/build-requirements.lock

MACOSX_DEPLOYMENT_TARGET=14.0 uv pip compile \
  benchmarks/mlx/requirements.txt \
  --python-version 3.12 \
  --python-platform aarch64-apple-darwin \
  --generate-hashes \
  --output-file benchmarks/mlx/requirements.lock
```

Review every version change and rerun the parser/safety tests before committing
regenerated locks.

## Run the benchmark suite

```bash
.venv-mlx/bin/python benchmarks/mlx/run_benchmarks.py \
  --benchmark-command .venv-mlx/bin/mlx_lm.benchmark \
  --evaluate-command .venv-mlx/bin/mlx_lm.evaluate \
  --download-timeout-seconds 3600 \
  --benchmark-timeout-seconds 3600 \
  --evaluate-timeout-seconds 21600 \
  --output /tmp/tasc-mlx-$(date +%Y%m%d-%H%M%S)
```

The runner:

- downloads each model at its immutable revision;
- starts a fresh `mlx_lm.benchmark` process for every model/workload pair;
- retains the built-in warmup and ten timed trials;
- writes raw logs;
- calculates median, P10, and P95 using R-7 linear interpolation;
- runs the full configured quality task for each pinned model; and
- records only sanitized machine, OS, device, package, power-source, and
  thermal-warning metadata.

The runner treats its config, child processes, and result files as trust
boundaries. It requires full 40-hex model revisions and safe unique keys,
rejects oversized or duplicate-key JSON, caps the total trial matrix, launches
downloads and MLX commands without a shell under hard time and output limits,
and passes only an allowlisted environment (never inherited tokens) to child
processes. The output directory is claimed exclusively, files are created with
mode `0600` under a `0700` directory, result reads are bounded and symlink-safe,
and a failed run clears partial contents only through the exact directory
descriptor it created. It intentionally retains that empty root reservation:
macOS has no atomic “remove this pathname only if it still names this inode,”
so path removal would risk deleting a concurrent replacement. A pre-existing
or replacement output is never traversed or overwritten; inspect and remove an
empty failed-run reservation explicitly before reusing its name.

The three workloads are:

| Workload | Prompt | Generation | Batch | Interpretation |
| --- | ---: | ---: | ---: | --- |
| `short-interactive` | 128 | 256 | 1 | Single-sequence prefill and decode |
| `long-prefill` | 4,096 | 128 | 1 | Long-prompt prefill and subsequent decode |
| `static-batch-8` | 512 | 128 | 8 | Aggregate static-batch throughput |

The pinned `mlx_lm.benchmark` 0.31.1 implementation seeds MLX random generation
with `0`, uses random token IDs, disables EOS stopping, and forces the requested
lengths. Its `prompt_tps` and `generation_tps` isolate runtime kernels; they are
not end-to-end request latency. At batch 8,
`generation_tps` is aggregate batch throughput, not per-user streaming speed.
`peak_memory` is peak MLX allocator memory for that process and workload, not
the model file size. P10/P95 over ten trials describe repeatability within this
microbenchmark only; they are too coarse to support a production tail-latency
claim.

Run the parser tests without a GPU:

```bash
python3 -m unittest benchmarks/mlx/test_run_benchmarks.py
```

## Run the full quality eval separately

The suite runner already executes the quality eval. To run only that step by
hand, download the same immutable snapshots:

```bash
hf download LiquidAI/LFM2.5-350M-MLX-4bit \
  --revision 8188cd2d54e7a49544853ec017ae21c17f752fc5 \
  --local-dir /tmp/lfm2.5-350m-mlx

hf download LiquidAI/LFM2.5-1.2B-Instruct-MLX-4bit \
  --revision c30e30c5efac705771e1f37df38a32115718dd5d \
  --local-dir /tmp/lfm2.5-1.2b-mlx
```

Then run all 1,172 ARC-Challenge test examples:

```bash
.venv-mlx/bin/mlx_lm.evaluate \
  --model /tmp/lfm2.5-350m-mlx \
  --tasks arc_challenge \
  --batch-size 8 \
  --num-shots 0 \
  --seed 20260726 \
  --apply-chat-template \
  --output-dir /tmp/lfm2.5-350m-arc

.venv-mlx/bin/mlx_lm.evaluate \
  --model /tmp/lfm2.5-1.2b-mlx \
  --tasks arc_challenge \
  --batch-size 8 \
  --num-shots 0 \
  --seed 20260726 \
  --apply-chat-template \
  --output-dir /tmp/lfm2.5-1.2b-arc
```

Do not publish a result produced with `--limit` as a full-task score.

## From this snapshot to TASC-ready evidence

A TASC decision requires one complete paired row for both profiles on every
request and replicate. A production-grade MLX collector should:

1. use the same group-disjoint development and holdout task cases for both
   profiles;
2. synchronize Metal and measure request start, first streamed token, and final
   token directly;
3. retain model failures and elapsed time;
4. calculate a deterministic per-case task score;
5. calculate and calibrate an actual route-time confidence, such as normalized
   option likelihood on development data;
6. keep single-user decode speed separate from aggregate service throughput;
7. use an honest local cost model based on measured energy plus hardware
   amortization, or omit the cost claim outside TASC rather than write zero;
8. randomize profile order, control cache/concurrency/power conditions, and use
   enough replicates for tail percentiles; and
9. freeze the evaluator and spec before nomination, then attest and confirm
   once on sealed holdout data.

Missing confidence deliberately causes a cascade to escalate. Zero expert cost
deliberately makes cost improvement undefined. Those fail-closed behaviors
prevent an incomplete local benchmark from turning into a flattering serving
recommendation.

The committed run and its raw evidence are in
[`benchmarks/results/2026-07-26-m4-pro/`](../results/2026-07-26-m4-pro/).
