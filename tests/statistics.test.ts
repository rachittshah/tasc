import { describe, expect, it } from "vitest";
import * as statistics from "../src/statistics.js";
import {
  bootstrapMeanCI,
  median,
  mulberry32,
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

  it("resamples independent groups while retaining original case traffic weights", () => {
    const groupedBootstrap = (statistics as any).bootstrapGroupedWeightedMeanCI;
    const result = groupedBootstrap([
      { caseId: "high-traffic-regression", groupId: "group-a", effect: -0.2, trafficWeight: 90 },
      ...Array.from({ length: 9 }, (_unused, index) => ({
        caseId: `small-win-${index}`,
        groupId: `group-${String.fromCharCode("b".charCodeAt(0) + index)}`,
        effect: 1,
        trafficWeight: 1,
      })),
    ], { alpha: 0.1, iters: 1_000, seed: 42 });

    expect(result).toMatchObject({
      method: "paired-group-percentile-v1",
      alpha: 0.1,
      caseCount: 10,
      groupCount: 10,
      effectiveTrafficMass: 99,
      iterations: 1_000,
      seed: 42,
    });
    expect(result.estimate).toBeCloseTo(-9 / 99);
    expect(result.interval.lo).toBeLessThan(0);
  });

  it("uses exact numerator and mass multiplicity for unequal-mass group draws", () => {
    const groupedBootstrap = (statistics as any).bootstrapGroupedWeightedMeanCI;
    const iters = 20;
    const seed = 91;
    const result = groupedBootstrap([
      { caseId: "a", groupId: "a", effect: -1, trafficWeight: 9 },
      { caseId: "b", groupId: "b", effect: 1, trafficWeight: 1 },
    ], { alpha: 0.2, iters, seed });
    const random = mulberry32(seed);
    const exactDraws = Array.from({ length: iters }, () => {
      let numerator = 0;
      let mass = 0;
      for (let draw = 0; draw < 2; draw += 1) {
        if (Math.floor(random() * 2) === 0) {
          numerator -= 9;
          mass += 9;
        } else {
          numerator += 1;
          mass += 1;
        }
      }
      return numerator / mass;
    });
    expect(result.interval).toEqual({
      lo: quantile(exactDraws, 0.1),
      hi: quantile(exactDraws, 0.9),
    });
  });

  it("does not narrow grouped uncertainty when correlated cases are duplicated within groups", () => {
    const groupedBootstrap = (statistics as any).bootstrapGroupedWeightedMeanCI;
    const original = groupedBootstrap([
      { caseId: "a", groupId: "group-a", effect: -0.2, trafficWeight: 1 },
      { caseId: "b", groupId: "group-b", effect: 0.2, trafficWeight: 1 },
      { caseId: "c", groupId: "group-c", effect: 0, trafficWeight: 1 },
    ], { iters: 2_000, seed: 7 });
    const duplicated = groupedBootstrap([
      { caseId: "a-1", groupId: "group-a", effect: -0.2, trafficWeight: 0.5 },
      { caseId: "a-2", groupId: "group-a", effect: -0.2, trafficWeight: 0.5 },
      { caseId: "b-1", groupId: "group-b", effect: 0.2, trafficWeight: 0.5 },
      { caseId: "b-2", groupId: "group-b", effect: 0.2, trafficWeight: 0.5 },
      { caseId: "c-1", groupId: "group-c", effect: 0, trafficWeight: 0.5 },
      { caseId: "c-2", groupId: "group-c", effect: 0, trafficWeight: 0.5 },
    ], { iters: 2_000, seed: 7 });

    expect(duplicated.groupCount).toBe(original.groupCount);
    expect(duplicated.interval).toEqual(original.interval);
  });

  it("rejects non-finite accumulated traffic mass before bootstrap allocation", () => {
    const groupedBootstrap = (statistics as any).bootstrapGroupedWeightedMeanCI;
    expect(() => groupedBootstrap([
      { caseId: "a", groupId: "a", effect: 0, trafficWeight: Number.MAX_VALUE },
      { caseId: "b", groupId: "b", effect: 0, trafficWeight: Number.MAX_VALUE },
    ], { iters: 1_000, seed: 1 })).toThrow(/traffic mass.*finite numeric range/i);
  });
});
