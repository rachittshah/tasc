import { Buffer } from "node:buffer";
import { createSecretKey } from "node:crypto";
import { describe, expect, it } from "vitest";
import type { BoundedJsonLimits } from "../src/bounded-input.js";
import {
  DEFAULT_SSE_LIMITS,
  MAX_SSE_TOTAL_BYTES,
  RuntimeCodecError,
  parseBoundedJsonSse,
  parseBoundedSse,
  type BoundedSseOptions,
} from "../src/runtime/sse.js";
import {
  DEFAULT_NDJSON_STREAM_LIMITS,
  MAX_NDJSON_TOTAL_BYTES,
  parseBoundedNdjsonStream,
} from "../src/runtime/ndjson.js";
import {
  DEFAULT_PROMETHEUS_LIMITS,
  parsePrometheusText,
} from "../src/runtime/metrics.js";

const key = createSecretKey(Buffer.alloc(32, 0x2a));

const jsonLimits: BoundedJsonLimits = {
  maxBytes: 256 * 1024,
  maxDepth: 16,
  maxObjectKeys: 256,
  maxArrayItems: 256,
  maxTokens: 4_096,
  maxDecodedStringLength: 256 * 1024,
  maxNumericTokenLength: 64,
  maxDiagnosticSnippetLength: 0,
};

const baseOptions: BoundedSseOptions = {
  limits: DEFAULT_SSE_LIMITS,
  identity: {
    studyId: "runtime-codec-study",
    keyId: "runtime-codec-key",
    key,
  },
  startedAtMs: 100,
  clock: () => 100,
};

async function* chunks(
  values: readonly Uint8Array[],
): AsyncIterable<Uint8Array> {
  for (const value of values) yield value;
}

function byteChunks(value: string): readonly Uint8Array[] {
  return [...Buffer.from(value, "utf8")].map(
    (byte) => Uint8Array.of(byte),
  );
}

describe("bounded SSE codecs", () => {
  it("parses WHATWG fields, comments, multiline data, CR/LF forms, and split UTF-8", async () => {
    const body = [
      ":keep-alive\r\n",
      "event: response.output_text.delta\r",
      "id: event-7\n",
      "retry: 1250\n",
      "data: {\"delta\":\"hé\"\n",
      "data: }\r\n",
      "\r\n",
      "data: [DONE]\n\n",
    ].join("");

    const parsed = await parseBoundedSse(
      chunks(byteChunks(body)),
      baseOptions,
    );

    expect(parsed.events).toHaveLength(2);
    expect(parsed.events[0]).toMatchObject({
      kind: "event",
      event: "response.output_text.delta",
      id: "event-7",
      retryMs: 1250,
      comments: ["keep-alive"],
      data: "{\"delta\":\"hé\"\n}",
    });
    expect(parsed.events[0]?.rawFrameIdentity).toMatchObject({
      algorithm: "hmac-sha256",
      keyId: "runtime-codec-key",
    });
    expect(parsed.events[1]).toMatchObject({
      kind: "done",
      data: "[DONE]",
      id: "event-7",
    });
    expect(parsed.summary).toMatchObject({
      terminal: "done-sentinel",
      trailingIncompleteEvent: false,
      totalBytes: Buffer.byteLength(body),
      totalChunks: Buffer.byteLength(body),
    });
    expect(Object.isFrozen(parsed)).toBe(true);
    expect(Object.isFrozen(parsed.events)).toBe(true);
    expect(Object.isFrozen(parsed.events[0])).toBe(true);
  });

  it("makes raw-frame identities independent of transport chunking", async () => {
    const body = "data: {\"value\":\"same\"}\r\n\r\n";
    const whole = await parseBoundedSse(
      chunks([Buffer.from(body)]),
      baseOptions,
    );
    const split = await parseBoundedSse(
      chunks(byteChunks(body)),
      baseOptions,
    );

    expect(split.events[0]?.rawFrameIdentity)
      .toEqual(whole.events[0]?.rawFrameIdentity);

    const lf = await parseBoundedSse(
      chunks([Buffer.from("data: {\"value\":\"same\"}\n\n")]),
      baseOptions,
    );
    expect(lf.events[0]?.rawFrameIdentity)
      .not.toEqual(whole.events[0]?.rawFrameIdentity);
  });

  it("accepts and ignores one leading SSE BOM", async () => {
    const parsed = await parseBoundedSse(chunks([
      Buffer.concat([
        Buffer.from([0xef, 0xbb, 0xbf]),
        Buffer.from("data: payload\n\n"),
      ]),
    ]), baseOptions);

    expect(parsed.events).toHaveLength(1);
    expect(parsed.events[0]?.data).toBe("payload");
  });

  it("keeps first byte distinct from first meaningful chat output", async () => {
    let now = 100;
    const nextTime = (): number => {
      now += 10;
      return now;
    };
    const frames = [
      ": keepalive\n\n",
      "data: {\"choices\":[{\"delta\":{\"role\":\"assistant\"}}]}\n\n",
      "data: {\"choices\":[{\"delta\":{\"content\":\"hello\"}}]}\n\n",
      "data: {\"choices\":[],\"usage\":{\"completion_tokens\":1}}\n\n",
      "data: [DONE]\n\n",
    ].map((value) => Buffer.from(value));

    const parsed = await parseBoundedJsonSse(chunks(frames), {
      ...baseOptions,
      clock: nextTime,
      jsonLimits,
      protocol: "openai-chat-completions",
    });

    expect(parsed.summary).toMatchObject({
      terminal: "done-sentinel",
      finalUsage: "present",
      timing: {
        startedAtMs: 100,
        firstByteAtMs: 110,
        firstMeaningfulAtMs: 130,
        timeToFirstByteMs: 10,
        timeToFirstMeaningfulMs: 30,
        completedAtMs: 160,
        durationMs: 60,
      },
    });
    expect(parsed.events.map(({ meaningfulOutput }) => meaningfulOutput))
      .toEqual([false, true, false, false]);
  });

  it("recognizes typed Responses completion and provider error events explicitly", async () => {
    const completed = await parseBoundedJsonSse(chunks([
      Buffer.from(
        "event: response.output_text.delta\n"
        + "data: {\"type\":\"response.output_text.delta\",\"delta\":\"ok\"}\n\n"
        + "event: response.completed\n"
        + "data: {\"type\":\"response.completed\",\"response\":{\"usage\":{\"output_tokens\":1}}}\n\n",
      ),
    ]), {
      ...baseOptions,
      jsonLimits,
      protocol: "openai-responses",
    });
    expect(completed.summary).toMatchObject({
      terminal: "response.completed",
      finalUsage: "present",
    });
    expect(completed.events.map(({ type }) => type)).toEqual([
      "response.output_text.delta",
      "response.completed",
    ]);

    const errored = await parseBoundedJsonSse(chunks([
      Buffer.from(
        "event: response.output_text.delta\n"
        + "data: {\"type\":\"response.output_text.delta\",\"delta\":\"partial\"}\n\n"
        + "event: error\n"
        + "data: {\"type\":\"error\",\"error\":{\"message\":\"provider secret\"}}\n\n",
      ),
    ]), {
      ...baseOptions,
      jsonLimits,
      protocol: "openai-responses",
    });
    expect(errored.summary.terminal).toBe("provider-error");
    expect(errored.events.at(-1)?.providerError).toBe(true);
    expect(JSON.stringify(errored.summary)).not.toContain("provider secret");

    await expect(parseBoundedJsonSse(chunks([
      Buffer.from(
        "data: {\"type\":\"response.completed\",\"response\":{\"usage\":{}}}\n\n"
        + "data: {\"type\":\"response.output_text.delta\",\"delta\":\"late\"}\n\n",
      ),
    ]), {
      ...baseOptions,
      jsonLimits,
      protocol: "openai-responses",
    })).rejects.toMatchObject({ code: "terminal-order" });

    await expect(parseBoundedJsonSse(chunks([
      Buffer.from(
        "event: error\n"
        + "data: {\"type\":\"error\",\"error\":{}}\n\n"
        + "data: {\"type\":\"response.output_text.delta\",\"delta\":\"late\"}\n\n",
      ),
    ]), {
      ...baseOptions,
      jsonLimits,
      protocol: "openai-responses",
    })).rejects.toMatchObject({ code: "terminal-order" });
  });

  it("reports truncation and missing final usage without promoting partial output", async () => {
    const parsed = await parseBoundedJsonSse(chunks([
      Buffer.from("data: {\"choices\":[{\"delta\":{\"content\":\"partial\"}}]}\n\n"),
    ]), {
      ...baseOptions,
      jsonLimits,
      protocol: "openai-chat-completions",
    });

    expect(parsed.summary).toMatchObject({
      terminal: "truncated",
      finalUsage: "missing",
    });
  });

  it("derives final usage only from the protocol-valid terminal event", async () => {
    const chat = await parseBoundedJsonSse(chunks([
      Buffer.from(
        "data: {\"choices\":[],\"usage\":{\"completion_tokens\":1}}\n\n"
        + "data: {\"choices\":[{\"delta\":{\"content\":\"later\"}}]}\n\n"
        + "data: [DONE]\n\n",
      ),
    ]), {
      ...baseOptions,
      jsonLimits,
      protocol: "openai-chat-completions",
    });
    expect(chat.summary).toMatchObject({
      terminal: "done-sentinel",
      finalUsage: "missing",
    });

    const responses = await parseBoundedJsonSse(chunks([
      Buffer.from(
        "data: {\"type\":\"response.output_text.done\",\"usage\":{\"output_tokens\":1}}\n\n"
        + "data: {\"type\":\"response.completed\",\"response\":{}}\n\n",
      ),
    ]), {
      ...baseOptions,
      jsonLimits,
      protocol: "openai-responses",
    });
    expect(responses.summary).toMatchObject({
      terminal: "response.completed",
      finalUsage: "missing",
    });
  });

  it("rejects duplicate JSON keys, invalid UTF-8, post-terminal data, and limits", async () => {
    await expect(parseBoundedJsonSse(chunks([
      Buffer.from("data: {\"x\":1,\"x\":2}\n\n"),
    ]), {
      ...baseOptions,
      jsonLimits,
      protocol: "generic-json-sse",
    })).rejects.toMatchObject({ code: "invalid-json" });

    await expect(parseBoundedSse(chunks([
      Uint8Array.of(0x64, 0x61, 0x74, 0x61, 0x3a, 0x20, 0xc3, 0x28),
    ]), baseOptions)).rejects.toMatchObject({ code: "invalid-utf8" });

    await expect(parseBoundedSse(chunks([
      Buffer.from("data: [DONE]\n\ndata: after\n\n"),
    ]), baseOptions)).rejects.toMatchObject({ code: "terminal-order" });

    await expect(parseBoundedSse(chunks([
      Buffer.from("data: [DONE]\n\ndata: unterminated"),
    ]), baseOptions)).rejects.toMatchObject({ code: "terminal-order" });

    for (const terminalFrame of [
      "data: {\"type\":\"response.completed\",\"response\":{}}\n\n",
      "event: error\ndata: {\"type\":\"error\",\"error\":{}}\n\n",
    ]) {
      await expect(parseBoundedJsonSse(chunks([
        Buffer.from(
          terminalFrame
          + "data: {\"type\":\"response.output_text.delta\",\"delta\":\"unterminated\"}",
        ),
      ]), {
        ...baseOptions,
        jsonLimits,
        protocol: "openai-responses",
      })).rejects.toMatchObject({ code: "terminal-order" });
    }

    await expect(parseBoundedSse(chunks([
      Buffer.from("data: too-large\n\n"),
    ]), {
      ...baseOptions,
      limits: {
        ...DEFAULT_SSE_LIMITS,
        maxTotalBytes: 64,
        maxEventBytes: 8,
        maxLineBytes: 8,
        maxFieldBytes: 8,
      },
    })).rejects.toBeInstanceOf(RuntimeCodecError);
  });

  it("rejects accessor iterators and absolute-limit options before iteration", async () => {
    let accessorReads = 0;
    const accessorSource = {};
    Object.defineProperty(accessorSource, Symbol.asyncIterator, {
      enumerable: false,
      get() {
        accessorReads += 1;
        throw new Error("must not execute");
      },
    });
    await expect(parseBoundedSse(
      accessorSource as AsyncIterable<Uint8Array>,
      baseOptions,
    )).rejects.toMatchObject({ code: "invalid-source" });
    expect(accessorReads).toBe(0);

    let iterations = 0;
    async function* untrusted(): AsyncIterable<Uint8Array> {
      iterations += 1;
      yield Buffer.from("data: never\n\n");
    }
    await expect(parseBoundedSse(untrusted(), {
      ...baseOptions,
      limits: {
        ...DEFAULT_SSE_LIMITS,
        maxTotalBytes: MAX_SSE_TOTAL_BYTES + 1,
      },
    })).rejects.toMatchObject({ code: "invalid-options" });
    expect(iterations).toBe(0);
  });
});

describe("bounded NDJSON codecs", () => {
  it("parses Ollama frames across every byte boundary with terminal usage", async () => {
    const body = [
      "{\"message\":{\"content\":\"hé\"},\"done\":false}",
      "{\"message\":{\"content\":\"llo\"},\"done\":false}",
      "{\"done\":true,\"prompt_eval_count\":2,\"eval_count\":1}",
      "",
    ].join("\n");
    let now = 100;
    const parsed = await parseBoundedNdjsonStream(
      chunks(byteChunks(body)),
      {
        limits: DEFAULT_NDJSON_STREAM_LIMITS,
        identity: baseOptions.identity,
        protocol: "ollama",
        startedAtMs: 100,
        clock: () => {
          now += 1;
          return now;
        },
      },
    );

    expect(parsed.items).toHaveLength(3);
    expect(parsed.items.map(({ done }) => done)).toEqual([
      false,
      false,
      true,
    ]);
    expect(parsed.summary).toMatchObject({
      terminal: "done",
      finalUsage: "present",
      totalBytes: Buffer.byteLength(body),
      totalChunks: Buffer.byteLength(body),
      totalLines: 3,
    });
    expect(parsed.summary.timing.firstByteAtMs).toBe(101);
    expect(parsed.summary.timing.firstMeaningfulAtMs).toBeGreaterThan(101);
    expect(parsed.items[0]?.rawLineIdentity).toMatchObject({
      algorithm: "hmac-sha256",
      keyId: "runtime-codec-key",
    });
  });

  it("makes line identity independent of chunks while preserving exact line bytes", async () => {
    const line = "{\"response\":\"same\",\"done\":false}\r\n";
    const whole = await parseBoundedNdjsonStream(chunks([
      Buffer.from(line),
    ]), {
      limits: DEFAULT_NDJSON_STREAM_LIMITS,
      identity: baseOptions.identity,
      protocol: "ollama",
      startedAtMs: 100,
      clock: () => 100,
    });
    const split = await parseBoundedNdjsonStream(
      chunks(byteChunks(line)),
      {
        limits: DEFAULT_NDJSON_STREAM_LIMITS,
        identity: baseOptions.identity,
        protocol: "ollama",
        startedAtMs: 100,
        clock: () => 100,
      },
    );
    expect(split.items[0]?.rawLineIdentity)
      .toEqual(whole.items[0]?.rawLineIdentity);

    const lf = await parseBoundedNdjsonStream(chunks([
      Buffer.from("{\"response\":\"same\",\"done\":false}\n"),
    ]), {
      limits: DEFAULT_NDJSON_STREAM_LIMITS,
      identity: baseOptions.identity,
      protocol: "ollama",
      startedAtMs: 100,
      clock: () => 100,
    });
    expect(lf.items[0]?.rawLineIdentity)
      .not.toEqual(whole.items[0]?.rawLineIdentity);
  });

  it("reports Ollama truncation, missing usage, and provider errors", async () => {
    const partial = await parseBoundedNdjsonStream(chunks([
      Buffer.from("{\"response\":\"partial\",\"done\":false}\n"),
    ]), {
      limits: DEFAULT_NDJSON_STREAM_LIMITS,
      identity: baseOptions.identity,
      protocol: "ollama",
      startedAtMs: 100,
      clock: () => 100,
    });
    expect(partial.summary).toMatchObject({
      terminal: "truncated",
      finalUsage: "missing",
    });

    const errored = await parseBoundedNdjsonStream(chunks([
      Buffer.from("{\"error\":\"provider secret\"}\n"),
    ]), {
      limits: DEFAULT_NDJSON_STREAM_LIMITS,
      identity: baseOptions.identity,
      protocol: "ollama",
      startedAtMs: 100,
      clock: () => 100,
    });
    expect(errored.summary.terminal).toBe("provider-error");
    expect(JSON.stringify(errored.summary)).not.toContain("provider secret");

    const intermediateUsage = await parseBoundedNdjsonStream(chunks([
      Buffer.from(
        "{\"response\":\"x\",\"done\":false,\"eval_count\":1}\n"
        + "{\"done\":true}\n",
      ),
    ]), {
      limits: DEFAULT_NDJSON_STREAM_LIMITS,
      identity: baseOptions.identity,
      protocol: "ollama",
      startedAtMs: 100,
      clock: () => 100,
    });
    expect(intermediateUsage.summary.finalUsage).toBe("missing");

    for (const partialTerminalUsage of [
      "{\"done\":true,\"prompt_eval_count\":1}\n",
      "{\"done\":true,\"eval_count\":1}\n",
    ]) {
      const partialUsage = await parseBoundedNdjsonStream(chunks([
        Buffer.from(partialTerminalUsage),
      ]), {
        limits: DEFAULT_NDJSON_STREAM_LIMITS,
        identity: baseOptions.identity,
        protocol: "ollama",
        startedAtMs: 100,
        clock: () => 100,
      });
      expect(partialUsage.summary).toMatchObject({
        terminal: "done",
        finalUsage: "missing",
      });
    }
  });

  it("rejects duplicate keys, blank records, data after terminal, UTF-8, and limits", async () => {
    const options = {
      limits: DEFAULT_NDJSON_STREAM_LIMITS,
      identity: baseOptions.identity,
      protocol: "ollama" as const,
      startedAtMs: 100,
      clock: () => 100,
    };
    await expect(parseBoundedNdjsonStream(chunks([
      Buffer.from("{\"done\":false,\"done\":true}\n"),
    ]), options)).rejects.toMatchObject({ code: "invalid-json" });
    await expect(parseBoundedNdjsonStream(chunks([
      Buffer.from("{\"done\":false}\n\n{\"done\":true}\n"),
    ]), options)).rejects.toMatchObject({ code: "blank-line" });
    await expect(parseBoundedNdjsonStream(chunks([
      Buffer.from("{\"done\":true}\n{\"done\":false}\n"),
    ]), options)).rejects.toMatchObject({ code: "terminal-order" });
    await expect(parseBoundedNdjsonStream(chunks([
      Uint8Array.of(0x7b, 0x22, 0x78, 0x22, 0x3a, 0x22, 0xc3, 0x28),
    ]), options)).rejects.toMatchObject({ code: "invalid-utf8" });
    await expect(parseBoundedNdjsonStream(chunks([
      Buffer.from("{\"response\":\"too large\"}\n"),
    ]), {
      ...options,
      limits: {
        ...DEFAULT_NDJSON_STREAM_LIMITS,
        maxBytes: 64,
        maxLineBytes: 8,
      },
    })).rejects.toMatchObject({ code: "line-byte-limit" });
  });

  it("rejects absolute-limit options before executing the source", async () => {
    let iterations = 0;
    async function* untrusted(): AsyncIterable<Uint8Array> {
      iterations += 1;
      yield Buffer.from("{\"done\":true}\n");
    }
    await expect(parseBoundedNdjsonStream(untrusted(), {
      limits: {
        ...DEFAULT_NDJSON_STREAM_LIMITS,
        maxBytes: MAX_NDJSON_TOTAL_BYTES + 1,
      },
      identity: baseOptions.identity,
      protocol: "ollama",
      startedAtMs: 100,
      clock: () => 100,
    })).rejects.toMatchObject({ code: "invalid-options" });
    expect(iterations).toBe(0);
  });
});

describe("bounded Prometheus text codec", () => {
  const metricsOptions = {
    limits: DEFAULT_PROMETHEUS_LIMITS,
    selectedMetricNames: [
      "vllm:num_requests_running",
      "tgi_request_duration_seconds_sum",
    ],
    identity: baseOptions.identity,
  };

  it("retains bounded selected samples with labels, escapes, values, and timestamps", () => {
    const text = [
      "# HELP vllm:num_requests_running Requests currently running.",
      "# TYPE vllm:num_requests_running gauge",
      "vllm:num_requests_running{model=\"a\\\"b\",worker=\"line\\n2\"} 2 1720000000000",
      "unselected_metric{pool=\"main\"} 99",
      "tgi_request_duration_seconds_sum -1.25e+2",
      "",
    ].join("\n");

    const parsed = parsePrometheusText(Buffer.from(text), metricsOptions);

    expect(parsed.samples).toEqual([
      {
        metric: "vllm:num_requests_running",
        labels: [
          { name: "model", value: "a\"b" },
          { name: "worker", value: "line\n2" },
        ],
        value: 2,
        timestampMs: "1720000000000",
        rawSampleIdentity: expect.objectContaining({
          algorithm: "hmac-sha256",
          keyId: "runtime-codec-key",
        }),
      },
      {
        metric: "tgi_request_duration_seconds_sum",
        labels: [],
        value: -125,
        timestampMs: null,
        rawSampleIdentity: expect.objectContaining({
          algorithm: "hmac-sha256",
          keyId: "runtime-codec-key",
        }),
      },
    ]);
    expect(parsed.summary).toEqual({
      totalBytes: Buffer.byteLength(text),
      totalLines: 5,
      totalSamples: 3,
      selectedSamples: 2,
      ignoredSamples: 1,
      commentLines: 2,
    });
    expect(Object.isFrozen(parsed.samples[0]?.labels)).toBe(true);
  });

  it("keys exact sample framing and distinguishes LF from CRLF", () => {
    const lf = parsePrometheusText(
      Buffer.from("vllm:num_requests_running 1\n"),
      metricsOptions,
    );
    const crlf = parsePrometheusText(
      Buffer.from("vllm:num_requests_running 1\r\n"),
      metricsOptions,
    );
    expect(lf.samples[0]?.rawSampleIdentity)
      .not.toEqual(crlf.samples[0]?.rawSampleIdentity);
  });

  it("preserves canonical signed-int64 timestamps without precision loss", () => {
    const parsed = parsePrometheusText(Buffer.from(
      "vllm:num_requests_running 1 +009223372036854775807\n"
      + "tgi_request_duration_seconds_sum 1 -9223372036854775808\n",
    ), metricsOptions);
    expect(parsed.samples.map(({ timestampMs }) => timestampMs)).toEqual([
      "9223372036854775807",
      "-9223372036854775808",
    ]);

    for (const timestamp of [
      "9223372036854775808",
      "-9223372036854775809",
    ]) {
      expect(() => parsePrometheusText(Buffer.from(
        `vllm:num_requests_running 1 ${timestamp}\n`,
      ), metricsOptions)).toThrow(expect.objectContaining({
        code: "unsupported-syntax",
      }));
    }
  });

  it("rejects duplicate samples and duplicate labels independent of label order", () => {
    expect(() => parsePrometheusText(Buffer.from(
      "vllm:num_requests_running{a=\"1\",b=\"2\"} 1\n"
      + "vllm:num_requests_running{b=\"2\",a=\"1\"} 2\n",
    ), metricsOptions)).toThrow(expect.objectContaining({
      code: "duplicate-sample",
    }));

    expect(() => parsePrometheusText(Buffer.from(
      "vllm:num_requests_running{a=\"1\",a=\"2\"} 1\n",
    ), metricsOptions)).toThrow(expect.objectContaining({
      code: "duplicate-sample",
    }));
  });

  it.each([
    "vllm:num_requests_running NaN\n",
    "vllm:num_requests_running +Inf\n",
    "vllm:num_requests_running -Infinity\n",
    "vllm:num_requests_running 1e9999\n",
  ])("rejects non-finite sample %j", (text) => {
    expect(() => parsePrometheusText(
      Buffer.from(text),
      metricsOptions,
    )).toThrow(expect.objectContaining({ code: "nonfinite-value" }));
  });

  it.each([
    "vllm:num_requests_running{a=\"bad\\t\"} 1\n",
    "vllm:num_requests_running 1.0 1.5\n",
    "vllm:num_requests_running 1 # {trace_id=\"x\"}\n",
    "# UNIT vllm:num_requests_running requests\n",
    "# EOF\n",
  ])("strictly rejects unsupported Prometheus/OpenMetrics syntax %j", (text) => {
    expect(() => parsePrometheusText(
      Buffer.from(text),
      metricsOptions,
    )).toThrow(expect.objectContaining({ code: "unsupported-syntax" }));
  });

  it("rejects invalid UTF-8, BOMs, and byte/sample/label limits", () => {
    expect(() => parsePrometheusText(
      Uint8Array.of(0xc3, 0x28),
      metricsOptions,
    )).toThrow(expect.objectContaining({ code: "invalid-utf8" }));
    expect(() => parsePrometheusText(
      Buffer.concat([
        Buffer.from([0xef, 0xbb, 0xbf]),
        Buffer.from("vllm:num_requests_running 1\n"),
      ]),
      metricsOptions,
    )).toThrow(expect.objectContaining({ code: "utf8-bom" }));
    expect(() => parsePrometheusText(
      Buffer.from("vllm:num_requests_running 1\n"),
      {
        ...metricsOptions,
        limits: { ...DEFAULT_PROMETHEUS_LIMITS, maxBytes: 8 },
      },
    )).toThrow(expect.objectContaining({ code: "invalid-options" }));
    expect(() => parsePrometheusText(Buffer.from(
      "vllm:num_requests_running 1\n"
      + "tgi_request_duration_seconds_sum 1\n",
    ), {
      ...metricsOptions,
      limits: {
        ...DEFAULT_PROMETHEUS_LIMITS,
        maxSamples: 1,
        maxSelectedSamples: 1,
      },
    })).toThrow(expect.objectContaining({ code: "sample-limit" }));
    expect(() => parsePrometheusText(Buffer.from(
      "vllm:num_requests_running{a=\"1\"} 1\n",
    ), {
      ...metricsOptions,
      limits: {
        ...DEFAULT_PROMETHEUS_LIMITS,
        maxLabelsPerSample: 0,
      },
    })).toThrow(expect.objectContaining({ code: "label-limit" }));
  });

  it("rejects hidden selected metric entries without invoking accessors", () => {
    const hidden: string[] = [];
    Object.defineProperty(hidden, "0", {
      value: "vllm:num_requests_running",
      enumerable: false,
    });
    Object.defineProperty(hidden, "length", { value: 1 });

    expect(() => parsePrometheusText(
      Buffer.from("vllm:num_requests_running 1\n"),
      { ...metricsOptions, selectedMetricNames: hidden },
    )).toThrow(expect.objectContaining({ code: "invalid-options" }));
  });

  it("applies configured metric-name bounds to HELP and TYPE metadata", () => {
    const boundedNames = {
      ...metricsOptions,
      selectedMetricNames: ["okay"],
      limits: {
        ...DEFAULT_PROMETHEUS_LIMITS,
        maxMetricNameLength: 4,
      },
    };
    expect(() => parsePrometheusText(
      Buffer.from("# HELP too_long documentation\nokay 1\n"),
      boundedNames,
    )).toThrow(expect.objectContaining({ code: "unsupported-syntax" }));
    expect(() => parsePrometheusText(
      Buffer.from("# TYPE too_long gauge\nokay 1\n"),
      boundedNames,
    )).toThrow(expect.objectContaining({ code: "unsupported-syntax" }));
  });
});
