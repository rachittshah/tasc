import { createHash } from "node:crypto";
import { canonicalJsonBytes } from "./determinism.js";
import { compareCodeUnits } from "./determinism.js";

const UINT32_MODULUS = 0x1_0000_0000n;

/**
 * Portable mapping from a preregistered string seed to the uint32 consumed by
 * the deterministic PRNG. The complete SHA-256 integer participates.
 */
export function bootstrapSeedFromString(seed: string): number {
  if (
    typeof seed !== "string"
    || !/^[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?$/.test(seed)
    || seed.length > 128
  ) {
    throw new Error("bootstrap seed must be a lowercase contract slug");
  }
  const bytes = canonicalJsonBytes({
    domain: "tasc/paired-group-bootstrap-seed/v1",
    value: seed,
  });
  const digest = createHash("sha256").update(bytes).digest("hex");
  return Number(BigInt(`0x${digest}`) % UINT32_MODULUS);
}

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

function quantileFromSorted(
  sorted: readonly number[],
  probability: number,
): number {
  if (sorted.length === 0) return Number.NaN;
  if (sorted.length === 1) return sorted[0];
  const boundedProbability = Math.min(1, Math.max(0, probability));
  const position = (sorted.length - 1) * boundedProbability;
  const lower = Math.floor(position);
  const upper = Math.ceil(position);
  if (lower === upper) return sorted[lower];
  return sorted[lower] + (sorted[upper] - sorted[lower]) * (position - lower);
}

export function quantile(values: readonly number[], probability: number): number {
  return quantileFromSorted(
    [...values].sort((left, right) => left - right),
    probability,
  );
}

export interface WeightedValue {
  value: number;
  weight: number;
  identity: string;
}

/**
 * Traffic-weighted inverse empirical CDF. Stable identity ordering resolves
 * equal-value rows before finite summation.
 */
export function weightedQuantile(
  values: readonly WeightedValue[],
  probability: number,
): number {
  if (values.length === 0) return Number.NaN;
  if (!Number.isFinite(probability) || probability < 0 || probability > 1) {
    throw new Error("weighted quantile probability must be between zero and one");
  }
  const sorted = [...values].sort((left, right) => (
    left.value - right.value
    || compareCodeUnits(left.identity, right.identity)
  ));
  let mass = 0;
  for (const entry of sorted) {
    if (!Number.isFinite(entry.value)) {
      throw new Error("weighted quantile values must be finite");
    }
    if (!Number.isFinite(entry.weight) || entry.weight <= 0) {
      throw new Error("weighted quantile weights must be finite and positive");
    }
    mass = checkedFiniteAdd(mass, entry.weight, "weighted quantile mass");
  }
  const target = probability * mass;
  let cumulative = 0;
  for (const entry of sorted) {
    cumulative = checkedFiniteAdd(
      cumulative,
      entry.weight,
      "weighted quantile cumulative mass",
    );
    if (cumulative >= target) return entry.value;
  }
  return sorted[sorted.length - 1].value;
}

export interface BootstrapCI {
  mean: number;
  lo: number;
  hi: number;
  iters: number;
  positive: boolean;
}

export interface GroupedCaseEffect {
  caseId: string;
  groupId: string;
  effect: number;
  trafficWeight: number;
}

export interface GroupedWeightedBootstrapCI {
  method: "paired-group-percentile-v1";
  alpha: number;
  caseCount: number;
  replicateCount: number;
  groupCount: number;
  effectiveTrafficMass: number;
  estimate: number;
  interval: {
    lo: number;
    hi: number;
  };
  iterations: number;
  seed: number;
  positive: boolean;
}

interface GroupAccumulator {
  groupId: string;
  numerator: number;
  mass: number;
}

function checkedFiniteAdd(left: number, right: number, name: string): number {
  const result = left + right;
  if (!Number.isFinite(result)) throw new Error(`${name} exceeds the finite numeric range`);
  return result;
}

/**
 * Percentile bootstrap over independent groups. Each draw samples sorted group IDs
 * uniformly with replacement and retains case traffic mass inside the sampled group.
 */
export function bootstrapGroupedWeightedMeanCI(
  caseEffects: readonly GroupedCaseEffect[],
  options: {
    iters?: number;
    alpha?: number;
    seed?: number;
    replicateCount?: number;
  } = {},
): GroupedWeightedBootstrapCI {
  const iters = options.iters ?? 10_000;
  const alpha = options.alpha ?? 0.05;
  const seed = options.seed ?? 0x9e3779b9;
  if (!Number.isSafeInteger(iters) || iters < 1 || iters > 1_000_000) {
    throw new Error("bootstrap iterations must be a bounded positive integer");
  }
  if (!Number.isFinite(alpha) || alpha <= 0 || alpha >= 1) {
    throw new Error("bootstrap alpha must be between 0 and 1");
  }
  if (!Number.isSafeInteger(seed)) throw new Error("bootstrap seed must be a safe integer");
  if (caseEffects.length === 0) throw new Error("grouped bootstrap requires at least one case effect");
  if (caseEffects.length > 100_000) {
    throw new Error("grouped bootstrap case effects exceed the bounded maximum");
  }
  const replicateCount = options.replicateCount ?? caseEffects.length;
  if (
    !Number.isSafeInteger(replicateCount)
    || replicateCount < caseEffects.length
    || replicateCount > 1_000_000
  ) {
    throw new Error(
      "grouped bootstrap replicate count must be a bounded integer "
      + "at least as large as case count",
    );
  }

  const caseIds = new Set<string>();
  for (const entry of caseEffects) {
    if (entry.caseId.length === 0 || entry.groupId.length === 0) {
      throw new Error("grouped bootstrap case and group IDs must be non-empty");
    }
    if (caseIds.has(entry.caseId)) throw new Error(`duplicate grouped-bootstrap case ID "${entry.caseId}"`);
    caseIds.add(entry.caseId);
    if (!Number.isFinite(entry.effect)) throw new Error(`case "${entry.caseId}" effect must be finite`);
    if (!Number.isFinite(entry.trafficWeight) || entry.trafficWeight <= 0) {
      throw new Error(`case "${entry.caseId}" traffic weight must be finite and positive`);
    }
  }

  const byGroup = new Map<string, GroupAccumulator>();
  let totalNumerator = 0;
  let effectiveTrafficMass = 0;
  for (const entry of [...caseEffects].sort((left, right) => (
    compareCodeUnits(left.groupId, right.groupId)
    || compareCodeUnits(left.caseId, right.caseId)
  ))) {
    const weightedEffect = entry.effect * entry.trafficWeight;
    if (!Number.isFinite(weightedEffect)) {
      throw new Error(`case "${entry.caseId}" weighted effect exceeds the finite numeric range`);
    }
    totalNumerator = checkedFiniteAdd(totalNumerator, weightedEffect, "weighted effect");
    effectiveTrafficMass = checkedFiniteAdd(effectiveTrafficMass, entry.trafficWeight, "traffic mass");
    const group = byGroup.get(entry.groupId) ?? {
      groupId: entry.groupId,
      numerator: 0,
      mass: 0,
    };
    group.numerator = checkedFiniteAdd(group.numerator, weightedEffect, `group "${entry.groupId}" numerator`);
    group.mass = checkedFiniteAdd(group.mass, entry.trafficWeight, `group "${entry.groupId}" traffic mass`);
    byGroup.set(entry.groupId, group);
  }
  const groups = [...byGroup.values()].sort((left, right) => compareCodeUnits(left.groupId, right.groupId));
  if (groups.length > 100_000 || iters > Math.floor(100_000_000 / groups.length)) {
    throw new Error("grouped bootstrap iterations times independent groups exceed the bounded work maximum");
  }

  const random = mulberry32(seed);
  const estimates = new Array<number>(iters);
  for (let bootstrapIndex = 0; bootstrapIndex < iters; bootstrapIndex += 1) {
    let numerator = 0;
    let mass = 0;
    for (let sampleIndex = 0; sampleIndex < groups.length; sampleIndex += 1) {
      const sampled = groups[Math.floor(random() * groups.length)];
      numerator = checkedFiniteAdd(numerator, sampled.numerator, "bootstrap numerator");
      mass = checkedFiniteAdd(mass, sampled.mass, "bootstrap traffic mass");
    }
    estimates[bootstrapIndex] = numerator / mass;
  }
  estimates.sort((left, right) => left - right);
  const lo = quantileFromSorted(estimates, alpha / 2);
  const hi = quantileFromSorted(estimates, 1 - alpha / 2);
  return {
    method: "paired-group-percentile-v1",
    alpha,
    caseCount: caseEffects.length,
    replicateCount,
    groupCount: groups.length,
    effectiveTrafficMass,
    estimate: totalNumerator / effectiveTrafficMass,
    interval: { lo, hi },
    iterations: iters,
    seed,
    positive: lo > 0,
  };
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
