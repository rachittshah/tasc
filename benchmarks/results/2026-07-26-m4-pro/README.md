# M4 Pro MLX snapshot — 2026-07-26

This is a measured local snapshot, not vendor-reported performance and not a
TASC production-readiness result.

## Result

Quality used the full 1,172-example ARC-Challenge test task, zero-shot with the
model chat template. The headline metric is length-normalized multiple-choice
accuracy:

| Model | Parameters | ARC-Challenge `acc_norm` | Standard error |
| --- | ---: | ---: | ---: |
| LFM2.5-350M MLX 4-bit | 350M | 31.48% | 1.36 pp |
| LFM2.5-1.2B-Instruct MLX 4-bit | 1.2B | 39.42% | 1.43 pp |

Throughput values below are medians across ten timed trials after one built-in
warmup. Brackets show `[P10, P95]`. Peak memory is the maximum reported by MLX
for that fresh process. These ten-trial quantiles describe microbenchmark
repeatability, not a production latency distribution or SLA.

| Workload | Model | Prefill tok/s | Decode tok/s | Peak GB |
| --- | --- | ---: | ---: | ---: |
| 128 prompt / 256 generation / batch 1 | 350M | 6,820 `[6,770, 6,884]` | 650.0 `[646.2, 651.4]` | 0.376 |
| 128 prompt / 256 generation / batch 1 | 1.2B | 2,560 `[2,535, 2,629]` | 303.4 `[302.6, 305.0]` | 0.800 |
| 4,096 prompt / 128 generation / batch 1 | 350M | 8,614 `[8,586, 8,660]` | 400.3 `[392.9, 410.0]` | 2.302 |
| 4,096 prompt / 128 generation / batch 1 | 1.2B | 3,072 `[3,069, 3,075]` | 253.4 `[252.2, 255.6]` | 1.645 |
| 512 prompt / 128 generation / batch 8 | 350M | 9,247 `[9,197, 9,282]` | 1,447.6 `[1,444.3, 1,462.0]` aggregate | 2.209 |
| 512 prompt / 128 generation / batch 8 | 1.2B | 3,176 `[3,173, 3,183]` | 678.3 `[676.8, 679.3]` aggregate | 1.704 |

On this machine, the 350M model delivered:

- **2.14×** the single-sequence short-prompt decode throughput;
- **2.80×** the long-prompt prefill throughput; and
- **2.13×** the batch-8 aggregate decode throughput.

The 1.2B model gained **7.94 percentage points** of normalized ARC-Challenge
accuracy. That is the concrete inference R&D trade-off: the smaller profile is
materially faster, while the larger profile is materially more accurate.
Whether a cascade captures both benefits depends on paired request traces,
route-time confidence, failures, latency, and cost—the evidence TASC is built
to evaluate.

The 350M model's higher 4K-prompt peak memory is not a typo. Peak allocator
memory includes workload- and architecture-dependent cache behavior; parameter
count alone does not determine long-context memory.

## Controlled environment

- MacBook Pro `Mac16,7`
- Apple M4 Pro: 14 CPU cores, 20 GPU cores
- 48 GB unified memory
- macOS 26.5.2 (`25F84`)
- AC power; no recorded thermal or performance warning
- Python 3.12.12
- MLX 0.31.1 and mlx-lm 0.31.1
- lm-eval 0.4.12, Transformers 5.14.1, Datasets 5.0.0

Both models are official LiquidAI 4-bit affine/group-64 MLX conversions released
in 2026 and pinned by immutable Hugging Face commit:

- `LiquidAI/LFM2.5-350M-MLX-4bit@8188cd2d54e7a49544853ec017ae21c17f752fc5`
- `LiquidAI/LFM2.5-1.2B-Instruct-MLX-4bit@c30e30c5efac705771e1f37df38a32115718dd5d`

## Evidence

- [`throughput.json`](throughput.json) — environment, every trial, and derived
  quantiles
- [`quality.json`](quality.json) — task settings and full-task metrics
- [`raw/`](raw/) — original mlx-lm timing logs and evaluator JSON
- [`benchmark_config.json`](../../mlx/benchmark_config.json) — pinned model and
  workload definitions
- [`run_benchmarks.py`](../../mlx/run_benchmarks.py) — the runner that produced
  both artifacts

`mlx_lm.benchmark` operates on fixed-length random token IDs, disables EOS, and
measures model runtime rather than tokenizer or request-serving overhead.
ARC-Challenge measures multiple-choice knowledge/reasoning, not general product
quality. The 350M release is optimized primarily for tool use, extraction, and
structured output, so ARC is a controlled common task rather than its ideal
deployment workload. Treat these numbers as one reproducible
machine/model/runtime snapshot, not a universal ranking or SLA.
