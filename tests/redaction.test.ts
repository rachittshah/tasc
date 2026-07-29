import { describe, expect, it } from "vitest";
import {
  PERSISTED_ERROR_VERSION,
  sanitizeErrorForPersistence,
} from "../src/redaction.js";

describe("persisted error redaction", () => {
  it("keeps only bounded allowlisted metadata and a category-owned message", () => {
    const secret = "sk-live-THIS-MUST-NEVER-PERSIST";
    const sanitized = sanitizeErrorForPersistence({
      category: "rate-limit",
      status: 429,
      runtime: "vllm",
      requestId: "req_01ABC.xyz-9",
      message: `provider said ${secret}`,
      stack: `Error: ${secret}`,
      headers: { authorization: `Bearer ${secret}` },
      url: `https://user:${secret}@runtime.invalid/infer?token=${secret}`,
      body: { prompt: secret },
      provider: { error: { detail: secret } },
      cause: { message: secret },
    });

    expect(sanitized).toEqual({
      version: PERSISTED_ERROR_VERSION,
      category: "rate-limit",
      message: "Inference runtime rate limit was reached.",
      status: 429,
      runtime: "vllm",
      requestId: "req_01ABC.xyz-9",
    });
    expect(Object.keys(sanitized)).toEqual([
      "version",
      "category",
      "message",
      "status",
      "runtime",
      "requestId",
    ]);
    expect(JSON.stringify(sanitized)).not.toContain(secret);
    expect(Object.isFrozen(sanitized)).toBe(true);
  });

  it.each([
    ["authentication", "Inference runtime authentication failed."],
    ["authorization", "Inference runtime authorization failed."],
    ["timeout", "Inference request timed out."],
    ["rate-limit", "Inference runtime rate limit was reached."],
    ["transport", "Inference transport failed."],
    ["invalid-response", "Inference runtime returned an invalid response."],
    ["cancelled", "Inference request was cancelled."],
    ["internal", "Inference runtime failed."],
    ["unknown", "Inference request failed."],
  ] as const)("uses a constant message for %s failures", (category, message) => {
    expect(sanitizeErrorForPersistence({ category }).message).toBe(message);
  });

  it("does not inspect sensitive accessors", () => {
    let sensitiveReads = 0;
    const input: Record<string, unknown> = {
      category: "transport",
      status: 503,
      runtime: "sglang",
      requestId: "request-7",
    };
    for (const name of [
      "message",
      "stack",
      "cause",
      "headers",
      "url",
      "body",
      "provider",
    ]) {
      Object.defineProperty(input, name, {
        enumerable: true,
        get() {
          sensitiveReads += 1;
          throw new Error("sensitive accessor must not execute");
        },
      });
    }

    expect(sanitizeErrorForPersistence(input)).toMatchObject({
      category: "transport",
      status: 503,
      runtime: "sglang",
      requestId: "request-7",
    });
    expect(sensitiveReads).toBe(0);
  });

  it("degrades an accessor in allowlisted metadata without invoking it", () => {
    let reads = 0;
    const input = Object.create(null) as Record<string, unknown>;
    Object.defineProperty(input, "category", {
      enumerable: true,
      get() {
        reads += 1;
        return "authentication";
      },
    });
    input.status = 401;

    expect(sanitizeErrorForPersistence(input)).toEqual({
      version: PERSISTED_ERROR_VERSION,
      category: "unknown",
      message: "Inference request failed.",
      status: null,
      runtime: null,
      requestId: null,
    });
    expect(reads).toBe(0);
  });

  it("degrades native errors without reading message, stack, or cause", () => {
    const secret = "provider-secret-native-error";
    const error = new Error(secret, { cause: new Error(secret) });
    Object.defineProperty(error, "category", {
      get() {
        throw new Error(secret);
      },
    });

    const sanitized = sanitizeErrorForPersistence(error);
    expect(sanitized).toEqual({
      version: PERSISTED_ERROR_VERSION,
      category: "unknown",
      message: "Inference request failed.",
      status: null,
      runtime: null,
      requestId: null,
    });
    expect(JSON.stringify(sanitized)).not.toContain(secret);
  });

  it("detects proxies before triggering any caller trap", () => {
    let trapCalls = 0;
    const proxy = new Proxy(
      { category: "timeout" },
      {
        get() {
          trapCalls += 1;
          throw new Error("get trap");
        },
        getOwnPropertyDescriptor() {
          trapCalls += 1;
          throw new Error("descriptor trap");
        },
        getPrototypeOf() {
          trapCalls += 1;
          throw new Error("prototype trap");
        },
        ownKeys() {
          trapCalls += 1;
          throw new Error("keys trap");
        },
      },
    );

    expect(sanitizeErrorForPersistence(proxy).category).toBe("unknown");
    expect(trapCalls).toBe(0);
  });

  it("rejects unbounded, malformed, and credential-like allowlisted values", () => {
    const sanitized = sanitizeErrorForPersistence({
      category: "provider-injected-category",
      status: 99,
      runtime: "sk-live-secret000000",
      requestId: "Bearer token000000",
    });

    expect(sanitized).toEqual({
      version: PERSISTED_ERROR_VERSION,
      category: "unknown",
      message: "Inference request failed.",
      status: null,
      runtime: null,
      requestId: null,
    });

    expect(sanitizeErrorForPersistence({
      category: "timeout",
      status: 600,
      runtime: "a".repeat(129),
      requestId: "r".repeat(129),
    })).toMatchObject({
      category: "timeout",
      status: null,
      runtime: null,
      requestId: null,
    });
  });

  it("is deterministic and never copies arbitrary input fields", () => {
    const left = sanitizeErrorForPersistence({
      category: "invalid-response",
      status: 502,
      runtime: "tensorrt-llm",
      requestId: "req-2",
      arbitrary: "left",
    });
    const right = sanitizeErrorForPersistence({
      arbitrary: "right",
      requestId: "req-2",
      runtime: "tensorrt-llm",
      status: 502,
      category: "invalid-response",
    });

    expect(left).toEqual(right);
    expect(left).not.toHaveProperty("arbitrary");
  });
});
