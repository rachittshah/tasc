import { describe, expect, it } from "vitest";
import {
  DEFAULT_RUNTIME_HTTP_LIMITS,
  fingerprintRuntimeInvocationHttpLimits,
  normalizeRuntimeInvocationHttpLimits,
  type RuntimeHttpLimits,
} from "../src/runtime-http-limits.js";

const MAXIMUMS: Readonly<RuntimeHttpLimits> = Object.freeze({
  maxRequestBytes: 1_048_576,
  maxResponseHeaderBytes: 16_384,
  maxResponseHeaders: 256,
  maxResponseBytes: 8_388_608,
  maxResponseChunks: 16_384,
  maxSecretHeaderBytes: 16_384,
  connectTimeoutMs: 30_000,
  headersTimeoutMs: 60_000,
  bodyTimeoutMs: 60_000,
  deadlineMs: 300_000,
});

describe("runtime invocation HTTP-limit identity", () => {
  it("normalizes omitted and partial input to one complete immutable contract", () => {
    const omitted = normalizeRuntimeInvocationHttpLimits();
    const empty = normalizeRuntimeInvocationHttpLimits({});
    const partial = normalizeRuntimeInvocationHttpLimits({
      maxResponseBytes: 4_096,
    });

    expect(omitted).toEqual(DEFAULT_RUNTIME_HTTP_LIMITS);
    expect(empty).toEqual(DEFAULT_RUNTIME_HTTP_LIMITS);
    expect(partial).toEqual({
      ...DEFAULT_RUNTIME_HTTP_LIMITS,
      maxResponseBytes: 4_096,
    });
    expect(Object.isFrozen(omitted)).toBe(true);
    expect(Object.isFrozen(partial)).toBe(true);
    expect(fingerprintRuntimeInvocationHttpLimits())
      .toBe(fingerprintRuntimeInvocationHttpLimits({}));
    expect(fingerprintRuntimeInvocationHttpLimits(partial))
      .not.toBe(fingerprintRuntimeInvocationHttpLimits());
  });

  it("accepts every exact inference-invocation ceiling", () => {
    expect(normalizeRuntimeInvocationHttpLimits(MAXIMUMS))
      .toEqual(MAXIMUMS);
  });

  it.each(
    Object.entries(MAXIMUMS) as [
      keyof RuntimeHttpLimits,
      number,
    ][],
  )("rejects %s above its exact ceiling", (key, maximum) => {
    expect(() => normalizeRuntimeInvocationHttpLimits({
      [key]: maximum + 1,
    })).toThrow();
  });

  it("rejects zero, fractional, and unknown limit fields", () => {
    expect(() => normalizeRuntimeInvocationHttpLimits({
      deadlineMs: 0,
    })).toThrow();
    expect(() => normalizeRuntimeInvocationHttpLimits({
      deadlineMs: 1.5,
    })).toThrow();
    expect(() => normalizeRuntimeInvocationHttpLimits({
      deadlineMs: 1_000,
      retryCount: 2,
    })).toThrow();
  });
});
