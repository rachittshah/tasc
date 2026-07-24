/** Deterministic PRNG used to make bootstrap decisions reproducible. */
export function mulberry32(seed: number): () => number {
  let state = seed >>> 0;
  return function random(): number {
    state |= 0;
    state = (state + 0x6d2b79f5) | 0;
    let value = Math.imul(state ^ (state >>> 15), 1 | state);
    value = (value + Math.imul(value ^ (value >>> 7), 61 | value)) ^ value;
    return ((value ^ (value >>> 14)) >>> 0) / 4294967296;
  };
}

export function mean(values: readonly number[]): number {
  if (values.length === 0) return Number.NaN;
  return values.reduce((sum, value) => sum + value, 0) / values.length;
}

export function median(values: readonly number[]): number {
  if (values.length === 0) return Number.NaN;
  const sorted = [...values].sort((left, right) => left - right);
  const middle = Math.floor(sorted.length / 2);
  return sorted.length % 2 === 1
    ? sorted[middle]
    : (sorted[middle - 1] + sorted[middle]) / 2;
}

export function quantile(values: readonly number[], probability: number): number {
  if (values.length === 0) return Number.NaN;
  if (values.length === 1) return values[0];
  const sorted = [...values].sort((left, right) => left - right);
  const boundedProbability = Math.min(1, Math.max(0, probability));
  const position = (sorted.length - 1) * boundedProbability;
  const lower = Math.floor(position);
  const upper = Math.ceil(position);
  if (lower === upper) return sorted[lower];
  return sorted[lower] + (sorted[upper] - sorted[lower]) * (position - lower);
}

export interface BootstrapCI {
  mean: number;
  lo: number;
  hi: number;
  iters: number;
  positive: boolean;
}

/** Percentile bootstrap confidence interval over a paired-delta mean. */
export function bootstrapMeanCI(
  values: readonly number[],
  options: { iters?: number; alpha?: number; seed?: number } = {},
): BootstrapCI {
  const iters = options.iters ?? 10_000;
  const alpha = options.alpha ?? 0.05;
  const seed = options.seed ?? 0x9e3779b9;
  if (!Number.isSafeInteger(iters) || iters < 1) {
    throw new Error("bootstrap iterations must be a positive integer");
  }
  if (!Number.isFinite(alpha) || alpha <= 0 || alpha >= 1) {
    throw new Error("bootstrap alpha must be between 0 and 1");
  }
  if (values.length === 0) {
    return {
      mean: Number.NaN,
      lo: Number.NaN,
      hi: Number.NaN,
      iters,
      positive: false,
    };
  }

  const random = mulberry32(seed);
  const means = new Array<number>(iters);
  for (let bootstrapIndex = 0; bootstrapIndex < iters; bootstrapIndex += 1) {
    let sum = 0;
    for (let sampleIndex = 0; sampleIndex < values.length; sampleIndex += 1) {
      sum += values[Math.floor(random() * values.length)];
    }
    means[bootstrapIndex] = sum / values.length;
  }
  const lo = quantile(means, alpha / 2);
  const hi = quantile(means, 1 - alpha / 2);
  return {
    mean: mean(values),
    lo,
    hi,
    iters,
    positive: lo > 0,
  };
}
