import { describe, expect, it } from "vitest";
import {
  bootstrapMeanCI,
  median,
  quantile,
} from "../src/statistics.js";

describe("deterministic statistical primitives", () => {
  it("computes median and interpolated quantiles without mutating inputs", () => {
    const values = [4, 1, 3, 2];
    expect(median(values)).toBe(2.5);
    expect(quantile(values, 0.25)).toBe(1.75);
    expect(values).toEqual([4, 1, 3, 2]);
  });

  it("reproduces a paired bootstrap interval from the same seed", () => {
    const first = bootstrapMeanCI([0.03, 0.02, 0.01, -0.01], {
      iters: 2_000,
      seed: 42,
    });
    const second = bootstrapMeanCI([0.03, 0.02, 0.01, -0.01], {
      iters: 2_000,
      seed: 42,
    });
    expect(first).toEqual(second);
    expect(first.mean).toBeCloseTo(0.0125);
  });

  it("fails closed on invalid bootstrap controls", () => {
    expect(() => bootstrapMeanCI([1], { iters: 0 })).toThrow(/positive integer/i);
    expect(() => bootstrapMeanCI([1], { alpha: 1 })).toThrow(/between 0 and 1/i);
  });
});
