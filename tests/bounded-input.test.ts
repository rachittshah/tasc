import { Readable } from "node:stream";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  BoundedInputError,
  MAX_BOUNDED_INPUT_CHUNKS,
  parseBoundedJson,
  parseBoundedNdjson,
  readBoundedJson,
  readBoundedNdjson,
  type BoundedJsonLimits,
  type BoundedNdjsonLimits,
} from "../src/bounded-input.js";

const encoder = new TextEncoder();

const jsonLimits: BoundedJsonLimits = Object.freeze({
  maxBytes: 1_024,
  maxDepth: 8,
  maxObjectKeys: 16,
  maxArrayItems: 16,
  maxTokens: 64,
  maxDecodedStringLength: 64,
  maxNumericTokenLength: 32,
  maxDiagnosticSnippetLength: 24,
});

afterEach(() => {
  vi.restoreAllMocks();
});

const ndjsonLimits: BoundedNdjsonLimits = Object.freeze({
  ...jsonLimits,
  maxLineBytes: 512,
  maxItems: 8,
});

function bytes(value: string): Uint8Array {
  return encoder.encode(value);
}

function errorFrom(action: () => unknown): BoundedInputError {
  try {
    action();
  } catch (error) {
    expect(error).toBeInstanceOf(BoundedInputError);
    return error as BoundedInputError;
  }
  throw new Error("expected action to throw");
}

describe("parseBoundedJson", () => {
  it("parses valid JSON without mutating frozen caller limits", () => {
    const input = bytes('{"ok":true,"nested":[null,"value",12.5]}');

    expect(parseBoundedJson(input, jsonLimits)).toEqual({
      ok: true,
      nested: [null, "value", 12.5],
    });
    expect(Object.isFrozen(jsonLimits)).toBe(true);
  });

  it("recursively freezes parsed object and array values", () => {
    const result = parseBoundedJson(
      bytes('{"object":{"value":1},"array":[{"value":2}]}'),
      jsonLimits,
    ) as {
      object: { value: number };
      array: Array<{ value: number }>;
    };

    expect(Object.isFrozen(result)).toBe(true);
    expect(Object.isFrozen(result.object)).toBe(true);
    expect(Object.isFrozen(result.array)).toBe(true);
    expect(Object.isFrozen(result.array[0])).toBe(true);
  });

  it("accepts exact byte limits and rejects one byte less before UTF-8 decoding", () => {
    const input = bytes('"ok"');
    const decode = vi.spyOn(TextDecoder.prototype, "decode");

    expect(parseBoundedJson(input, { ...jsonLimits, maxBytes: input.byteLength })).toBe("ok");
    const callsAfterExactLimit = decode.mock.calls.length;
    expect(errorFrom(() => parseBoundedJson(input, {
      ...jsonLimits,
      maxBytes: input.byteLength - 1,
    })).code).toBe("byte-limit");
    expect(decode).toHaveBeenCalledTimes(callsAfterExactLimit);
  });

  it("uses exact container-depth limits", () => {
    const input = bytes("[[]]");

    expect(parseBoundedJson(input, { ...jsonLimits, maxDepth: 2 })).toEqual([[]]);
    expect(errorFrom(() => parseBoundedJson(input, {
      ...jsonLimits,
      maxDepth: 1,
    })).code).toBe("depth-limit");
  });

  it("uses an exact document-wide object-key limit", () => {
    const input = bytes('{"a":1,"nested":{"b":2}}');

    expect(parseBoundedJson(input, { ...jsonLimits, maxObjectKeys: 3 })).toEqual({
      a: 1,
      nested: { b: 2 },
    });
    expect(errorFrom(() => parseBoundedJson(input, {
      ...jsonLimits,
      maxObjectKeys: 2,
    })).code).toBe("object-key-limit");
  });

  it("uses an exact per-array item limit independently for nested arrays", () => {
    const input = bytes("[[0,1],[2,3]]");

    expect(parseBoundedJson(input, { ...jsonLimits, maxArrayItems: 2 }))
      .toEqual([[0, 1], [2, 3]]);
    expect(errorFrom(() => parseBoundedJson(input, {
      ...jsonLimits,
      maxArrayItems: 1,
    })).code).toBe("array-item-limit");
  });

  it("uses an exact lexical-token limit including punctuation", () => {
    const input = bytes('{"a":1,"b":2}');

    expect(parseBoundedJson(input, { ...jsonLimits, maxTokens: 9 })).toEqual({
      a: 1,
      b: 2,
    });
    expect(errorFrom(() => parseBoundedJson(input, {
      ...jsonLimits,
      maxTokens: 8,
    })).code).toBe("token-limit");
  });

  it("limits decoded string UTF-16 length for raw and escaped strings", () => {
    expect(parseBoundedJson(bytes('"💡"'), {
      ...jsonLimits,
      maxDecodedStringLength: 2,
    })).toBe("💡");
    expect(parseBoundedJson(bytes('"\\ud83d\\udca1"'), {
      ...jsonLimits,
      maxDecodedStringLength: 2,
    })).toBe("💡");

    expect(errorFrom(() => parseBoundedJson(bytes('"💡"'), {
      ...jsonLimits,
      maxDecodedStringLength: 1,
    })).code).toBe("decoded-string-limit");
    expect(errorFrom(() => parseBoundedJson(bytes('"\\ud83d\\udca1"'), {
      ...jsonLimits,
      maxDecodedStringLength: 1,
    })).code).toBe("decoded-string-limit");
  });

  it("uses exact numeric-token limits and rejects non-finite JSON numbers", () => {
    const input = bytes("-12.3e+4");

    expect(parseBoundedJson(input, {
      ...jsonLimits,
      maxNumericTokenLength: 8,
    })).toBe(-123_000);
    expect(errorFrom(() => parseBoundedJson(input, {
      ...jsonLimits,
      maxNumericTokenLength: 7,
    })).code).toBe("numeric-token-limit");
    expect(errorFrom(() => parseBoundedJson(bytes("1e400"), jsonLimits)).code)
      .toBe("number-range");
  });

  it("rejects duplicate keys after JSON escape decoding in every object scope", () => {
    expect(errorFrom(() => parseBoundedJson(
      bytes('{"a":1,"\\u0061":2}'),
      jsonLimits,
    )).code).toBe("duplicate-key");
    expect(errorFrom(() => parseBoundedJson(
      bytes('{"outer":{"x":1,"x":2}}'),
      jsonLimits,
    )).code).toBe("duplicate-key");

    expect(parseBoundedJson(bytes('{"left":{"x":1},"right":{"x":2}}'), jsonLimits))
      .toEqual({ left: { x: 1 }, right: { x: 2 } });
  });

  it("rejects malformed UTF-8 before JSON parsing", () => {
    const input = Uint8Array.from([0x22, 0xc3, 0x28, 0x22]);
    const parse = vi.spyOn(JSON, "parse");

    expect(errorFrom(() => parseBoundedJson(input, jsonLimits)).code).toBe("invalid-utf8");
    expect(parse).not.toHaveBeenCalled();
  });

  it("explicitly rejects an initial UTF-8 BOM before JSON.parse", () => {
    const input = Uint8Array.from([0xef, 0xbb, 0xbf, ...bytes("null")]);
    const parse = vi.spyOn(JSON, "parse");

    expect(errorFrom(() => parseBoundedJson(input, jsonLimits)).code).toBe("utf8-bom");
    expect(parse).not.toHaveBeenCalled();
  });

  it("rejects oversized strings, numbers, depth, keys, and tokens before JSON.parse", () => {
    const parse = vi.spyOn(JSON, "parse");
    const overLimitInputs: ReadonlyArray<readonly [string, BoundedJsonLimits, string]> = [
      ['"' + "s".repeat(65) + '"', jsonLimits, "decoded-string-limit"],
      ["1".repeat(33), jsonLimits, "numeric-token-limit"],
      ["[[[]]]", { ...jsonLimits, maxDepth: 2 }, "depth-limit"],
      ['{"a":0,"b":0,"c":0}', { ...jsonLimits, maxObjectKeys: 2 }, "object-key-limit"],
      ["[0,0,0]", { ...jsonLimits, maxTokens: 6 }, "token-limit"],
    ];

    for (const [input, limits, code] of overLimitInputs) {
      expect(errorFrom(() => parseBoundedJson(bytes(input), limits)).code).toBe(code);
    }
    expect(parse).not.toHaveBeenCalled();
  });

  it("rejects invalid grammar and trailing garbage rather than accepting a prefix", () => {
    for (const input of [
      "",
      '{"a":1,}',
      "[1,]",
      "01",
      "true false",
      '"unterminated',
      '"bad\nstring"',
    ]) {
      expect(errorFrom(() => parseBoundedJson(bytes(input), jsonLimits)).code)
        .toBe("invalid-json");
    }
  });

  it("rejects lone Unicode surrogates while accepting scalar-value pairs", () => {
    expect(parseBoundedJson(
      bytes('["\\ud83d\\ude00","💡"]'),
      jsonLimits,
    )).toEqual(["😀", "💡"]);

    for (const input of [
      '"\\ud800"',
      '"\\udfff"',
      '{"\\ud800":1}',
      '["ok","\\ud83dX"]',
    ]) {
      expect(errorFrom(() => parseBoundedJson(bytes(input), jsonLimits)).code)
        .toBe("invalid-unicode");
    }
  });

  it("emits bounded constant-safe diagnostics without reflecting source secrets", () => {
    const secret = "sk-live-do-not-echo";
    const error = errorFrom(() => parseBoundedJson(
      bytes(`{"authorization":"${secret}",}`),
      { ...jsonLimits, maxDiagnosticSnippetLength: 7 },
    ));

    expect(error.diagnosticSnippet.length).toBeLessThanOrEqual(7);
    expect(`${error.message} ${error.diagnosticSnippet}`).not.toContain(secret);
    expect(`${error.message} ${error.diagnosticSnippet}`).not.toContain("authorization");
  });

  it("rejects unsafe or incomplete limits before decoding or parsing", () => {
    const decode = vi.spyOn(TextDecoder.prototype, "decode");
    const parse = vi.spyOn(JSON, "parse");

    for (const maxBytes of [-1, 1.5, Number.NaN, Number.POSITIVE_INFINITY]) {
      expect(() => parseBoundedJson(bytes("null"), {
        ...jsonLimits,
        maxBytes,
      })).toThrow(/maxBytes.*safe non-negative integer/i);
    }
    expect(() => parseBoundedJson(bytes("null"), {
      ...jsonLimits,
      maxTokens: undefined as unknown as number,
    })).toThrow(/maxTokens.*safe non-negative integer/i);
    expect(decode).not.toHaveBeenCalled();
    expect(parse).not.toHaveBeenCalled();
  });

  it("requires an exact plain data-property limit record without invoking accessors", () => {
    const accessor = vi.fn(() => 1_024);
    const withAccessor = { ...jsonLimits } as Record<string, unknown>;
    Object.defineProperty(withAccessor, "maxBytes", {
      enumerable: true,
      get: accessor,
    });
    const withHidden = { ...jsonLimits };
    Object.defineProperty(withHidden, "hidden", { value: "secret", enumerable: false });
    const withSymbol = {
      ...jsonLimits,
      [Symbol("secret")]: 1,
    };

    expect(() => parseBoundedJson(bytes("null"), {
      ...jsonLimits,
      unknown: 1,
    } as BoundedJsonLimits)).toThrow(/exact limit record/i);
    expect(() => parseBoundedJson(bytes("null"), withHidden as BoundedJsonLimits))
      .toThrow(/exact limit record/i);
    expect(() => parseBoundedJson(bytes("null"), withSymbol as BoundedJsonLimits))
      .toThrow(/exact limit record/i);
    expect(() => parseBoundedJson(bytes("null"), withAccessor as unknown as BoundedJsonLimits))
      .toThrow(/data propert/i);
    expect(accessor).not.toHaveBeenCalled();
  });

  it("rejects proxied limits and byte views without triggering their traps", () => {
    const limitTrap = vi.fn(() => {
      throw new Error("limit trap must not run");
    });
    const inputTrap = vi.fn(() => {
      throw new Error("input trap must not run");
    });
    const proxiedLimits = new Proxy(jsonLimits, {
      get: limitTrap,
      ownKeys: limitTrap,
    });
    const proxiedInput = new Proxy(bytes("null"), {
      get: inputTrap,
    });

    expect(() => parseBoundedJson(bytes("null"), proxiedLimits))
      .toThrow(/plain, non-proxied limit record/i);
    expect(limitTrap).not.toHaveBeenCalled();
    expect(() => parseBoundedJson(proxiedInput, jsonLimits))
      .toThrow(/genuine Uint8Array/i);
    expect(inputTrap).not.toHaveBeenCalled();
  });

  it("uses intrinsic byte-view metadata before rejecting an oversized hostile subclass", () => {
    const trap = vi.fn(() => {
      throw new Error("hostile byte-view hook must not run");
    });
    class HostileBytes extends Uint8Array {
      override get byteLength(): number {
        return trap();
      }

      override [Symbol.iterator](): ArrayIterator<number> {
        return trap();
      }
    }
    const input = new HostileBytes(bytes("null"));
    const decode = vi.spyOn(TextDecoder.prototype, "decode");

    expect(errorFrom(() => parseBoundedJson(input, {
      ...jsonLimits,
      maxBytes: 3,
    })).code).toBe("byte-limit");
    expect(trap).not.toHaveBeenCalled();
    expect(decode).not.toHaveBeenCalled();
  });

  it("rejects SharedArrayBuffer-backed views before decoding", () => {
    const shared = new SharedArrayBuffer(4);
    const input = new Uint8Array(shared);
    input.set(bytes("null"));
    const decode = vi.spyOn(TextDecoder.prototype, "decode");

    expect(() => parseBoundedJson(input, jsonLimits))
      .toThrow(/non-shared memory/i);
    expect(decode).not.toHaveBeenCalled();
  });
});

describe("parseBoundedNdjson", () => {
  it("parses LF and CRLF records, allows one final newline, and freezes the result", () => {
    const input = bytes('{"id":1}\r\n{"id":2}\n');
    const result = parseBoundedNdjson(input, {
      ...ndjsonLimits,
      maxBytes: input.byteLength,
      maxLineBytes: bytes('{"id":1}').byteLength,
      maxItems: 2,
    });

    expect(result).toEqual([{ id: 1 }, { id: 2 }]);
    expect(Object.isFrozen(result)).toBe(true);
    expect(Object.isFrozen(result[0])).toBe(true);
    expect(Object.isFrozen(result[1])).toBe(true);
  });

  it("accepts empty input but rejects blank or whitespace-only records", () => {
    expect(parseBoundedNdjson(new Uint8Array(), ndjsonLimits)).toEqual([]);

    for (const input of ["\n", " \n", '{"id":1}\n\n', '{"id":1}\n \n']) {
      expect(errorFrom(() => parseBoundedNdjson(bytes(input), ndjsonLimits)).code)
        .toBe("blank-line");
    }
  });

  it("enforces the exact total byte limit before decoding", () => {
    const input = bytes('{"id":1}\n');
    const decode = vi.spyOn(TextDecoder.prototype, "decode");

    expect(parseBoundedNdjson(input, {
      ...ndjsonLimits,
      maxBytes: input.byteLength,
    })).toEqual([{ id: 1 }]);
    const callsAfterExactLimit = decode.mock.calls.length;
    expect(errorFrom(() => parseBoundedNdjson(input, {
      ...ndjsonLimits,
      maxBytes: input.byteLength - 1,
    })).code).toBe("byte-limit");
    expect(decode).toHaveBeenCalledTimes(callsAfterExactLimit);
  });

  it("enforces an exact raw line-byte limit before decoding the line", () => {
    const input = bytes('{"id":1}');
    const decode = vi.spyOn(TextDecoder.prototype, "decode");

    expect(parseBoundedNdjson(input, {
      ...ndjsonLimits,
      maxLineBytes: input.byteLength,
    })).toEqual([{ id: 1 }]);
    const callsAfterExactLimit = decode.mock.calls.length;
    const error = errorFrom(() => parseBoundedNdjson(input, {
      ...ndjsonLimits,
      maxLineBytes: input.byteLength - 1,
    }));
    expect(error).toMatchObject({ code: "line-byte-limit", line: 1 });
    expect(decode).toHaveBeenCalledTimes(callsAfterExactLimit);
  });

  it("counts a bare carriage return at EOF as data, not CRLF framing", () => {
    const error = errorFrom(() => parseBoundedNdjson(
      bytes("0\r"),
      { ...ndjsonLimits, maxLineBytes: 1 },
    ));
    expect(error).toMatchObject({ code: "line-byte-limit", line: 1 });
  });

  it("enforces an exact item limit before parsing an additional record", () => {
    const input = bytes("0\n1");
    const parse = vi.spyOn(JSON, "parse");

    expect(parseBoundedNdjson(input, {
      ...ndjsonLimits,
      maxItems: 2,
    })).toEqual([0, 1]);
    parse.mockClear();

    const error = errorFrom(() => parseBoundedNdjson(input, {
      ...ndjsonLimits,
      maxItems: 1,
    }));
    expect(error).toMatchObject({ code: "item-limit", line: 2 });
    expect(parse).toHaveBeenCalledTimes(1);
  });

  it("uses fatal UTF-8 and reports a safe line number", () => {
    const first = bytes('{"id":1}\n');
    const input = new Uint8Array(first.byteLength + 4);
    input.set(first);
    input.set([0x22, 0xc3, 0x28, 0x22], first.byteLength);

    const error = errorFrom(() => parseBoundedNdjson(input, ndjsonLimits));
    expect(error).toMatchObject({ code: "invalid-utf8", line: 2 });
  });

  it("rejects per-record duplicate keys, limits, and trailing garbage", () => {
    expect(errorFrom(() => parseBoundedNdjson(
      bytes('{"a":1,"a":2}\n'),
      ndjsonLimits,
    )).code).toBe("duplicate-key");
    expect(errorFrom(() => parseBoundedNdjson(
      bytes('"toolong"\n'),
      { ...ndjsonLimits, maxDecodedStringLength: 3 },
    )).code).toBe("decoded-string-limit");

    const trailing = errorFrom(() => parseBoundedNdjson(
      bytes('{"id":1}\n{"id":2} trailing'),
      ndjsonLimits,
    ));
    expect(trailing).toMatchObject({ code: "invalid-json", line: 2 });
  });
});

describe("async bounded readers", () => {
  it("reads JSON across chunks, including a split multibyte UTF-8 scalar", async () => {
    const input = bytes('{"text":"💡"}');
    const scalarStart = input.indexOf(0xf0);

    async function* chunks(): AsyncGenerator<Uint8Array> {
      yield input.subarray(0, scalarStart + 1);
      yield input.subarray(scalarStart + 1, scalarStart + 3);
      yield input.subarray(scalarStart + 3);
    }

    await expect(readBoundedJson(chunks(), jsonLimits))
      .resolves.toEqual({ text: "💡" });
  });

  it("reads NDJSON across arbitrary record and UTF-8 chunk boundaries", async () => {
    const input = bytes('{"text":"💡"}\n{"text":"ok"}\n');
    const chunks = [
      input.subarray(0, 4),
      input.subarray(4, 12),
      input.subarray(12, 17),
      input.subarray(17),
    ];

    await expect(readBoundedNdjson(chunks, ndjsonLimits)).resolves.toEqual([
      { text: "💡" },
      { text: "ok" },
    ]);
  });

  it("accepts Node Readable byte streams", async () => {
    const source = Readable.from([Buffer.from("nu"), Buffer.from("ll")]);

    await expect(readBoundedJson(source, jsonLimits)).resolves.toBeNull();
  });

  it("checks cumulative bytes before copying an over-budget chunk", async () => {
    const set = vi.spyOn(Uint8Array.prototype, "set");

    async function* chunks(): AsyncGenerator<Uint8Array> {
      yield bytes("nu");
      yield bytes("ll");
    }

    const error = await readBoundedJson(chunks(), {
      ...jsonLimits,
      maxBytes: 3,
    }).then(
      () => undefined,
      (cause: unknown) => cause,
    );
    expect(error).toMatchObject({ code: "byte-limit" });
    expect(set).toHaveBeenCalledTimes(1);
  });

  it("rejects an oversized first chunk before copying it", async () => {
    const set = vi.spyOn(Uint8Array.prototype, "set");

    const error = await readBoundedJson([bytes("null")], {
      ...jsonLimits,
      maxBytes: 3,
    }).then(
      () => undefined,
      (cause: unknown) => cause,
    );
    expect(error).toMatchObject({ code: "byte-limit" });
    expect(set).not.toHaveBeenCalled();
  });

  it("rejects proxied chunks without triggering traps or copying", async () => {
    const trap = vi.fn(() => {
      throw new Error("chunk trap must not run");
    });
    const set = vi.spyOn(Uint8Array.prototype, "set");
    const chunk = new Proxy(bytes("null"), { get: trap });

    const error = await readBoundedJson(
      [chunk],
      jsonLimits,
    ).then(
      () => undefined,
      (cause: unknown) => cause,
    );
    expect(error).toMatchObject({ code: "invalid-chunk" });
    expect(trap).not.toHaveBeenCalled();
    expect(set).not.toHaveBeenCalled();
  });

  it("rejects a proxied chunk source before reading iterator metadata", async () => {
    const trap = vi.fn(() => {
      throw new Error("source trap must not run");
    });
    const source = new Proxy([bytes("null")], {
      get: trap,
    });

    await expect(readBoundedJson(source, jsonLimits))
      .rejects.toMatchObject({ code: "input-stream" });
    expect(trap).not.toHaveBeenCalled();
  });

  it("brand-checks proxied chunks from a native async iterator before copying", async () => {
    const trap = vi.fn(() => {
      throw new Error("async chunk trap must not run");
    });
    const set = vi.spyOn(Uint8Array.prototype, "set");
    const chunk = new Proxy(bytes("null"), { get: trap });
    const source: AsyncIterable<Uint8Array> = {
      [Symbol.asyncIterator]() {
        let emitted = false;
        return {
          async next() {
            if (emitted) return { done: true, value: undefined };
            emitted = true;
            return { done: false, value: chunk };
          },
        };
      },
    };

    await expect(readBoundedJson(source, jsonLimits))
      .rejects.toMatchObject({ code: "invalid-chunk" });
    expect(trap).not.toHaveBeenCalled();
    expect(set).not.toHaveBeenCalled();
  });

  it("rejects SharedArrayBuffer-backed chunks before copying", async () => {
    const shared = new SharedArrayBuffer(4);
    const chunk = new Uint8Array(shared);
    chunk.set(bytes("null"));
    const set = vi.spyOn(Uint8Array.prototype, "set");
    set.mockClear();

    await expect(readBoundedJson([chunk], jsonLimits))
      .rejects.toMatchObject({ code: "invalid-chunk" });
    expect(set).not.toHaveBeenCalled();
  });

  it("rejects empty chunks so zero-byte streams cannot consume unbounded work", async () => {
    await expect(readBoundedJson([new Uint8Array(), bytes("null")], jsonLimits))
      .rejects.toMatchObject({ code: "invalid-chunk" });
  });

  it("caps hostile one-byte chunk work independently of the byte budget", async () => {
    function* chunks(): Generator<Uint8Array> {
      for (let index = 0; index <= MAX_BOUNDED_INPUT_CHUNKS; index += 1) {
        yield Uint8Array.of(0x20);
      }
    }

    await expect(readBoundedJson(chunks(), {
      ...jsonLimits,
      maxBytes: MAX_BOUNDED_INPUT_CHUNKS + 1,
    })).rejects.toMatchObject({ code: "chunk-limit" });
  });

  it("scales chunk work for a large byte budget without rejecting common small chunks", async () => {
    function* chunks(): Generator<Uint8Array> {
      for (let index = 0; index <= MAX_BOUNDED_INPUT_CHUNKS; index += 1) {
        yield Uint8Array.of(0x20);
      }
      yield bytes("null");
    }

    await expect(readBoundedJson(chunks(), {
      ...jsonLimits,
      maxBytes: 128 * 1024 * 1024,
    })).resolves.toBeNull();
  });

  it("keeps UTF-8 fatal when an invalid sequence is split across chunks", async () => {
    const chunks = [
      Uint8Array.from([0x22, 0xc3]),
      Uint8Array.from([0x28, 0x22]),
    ];

    await expect(readBoundedJson(chunks, jsonLimits))
      .rejects.toMatchObject({ code: "invalid-utf8" });
  });

  it("snapshots mutable limits before awaiting the first stream chunk", async () => {
    const mutableLimits = { ...jsonLimits };
    let release: (() => void) | undefined;
    const ready = new Promise<void>((resolve) => {
      release = resolve;
    });
    async function* chunks(): AsyncGenerator<Uint8Array> {
      await ready;
      yield bytes("null");
    }

    const pending = readBoundedJson(chunks(), mutableLimits);
    mutableLimits.maxBytes = 0;
    release?.();

    await expect(pending).resolves.toBeNull();
  });

  it("sanitizes source-iterator failures", async () => {
    const secret = "stream-secret-must-not-echo";
    async function* chunks(): AsyncGenerator<Uint8Array> {
      throw new Error(secret);
    }

    const error = await readBoundedJson(chunks(), jsonLimits).then(
      () => undefined,
      (cause: unknown) => cause,
    );
    expect(error).toMatchObject({ code: "input-stream" });
    expect(String(error)).not.toContain(secret);
  });

  it("does not trust caller-thrown lookalike bounded-input errors", async () => {
    const secret = "Bearer planted-bounded-input-secret";
    const planted = new BoundedInputError("byte-limit", 24);
    planted.message = secret;
    async function* chunks(): AsyncGenerator<Uint8Array> {
      throw planted;
    }

    const error = await readBoundedJson(chunks(), jsonLimits).then(
      () => undefined,
      (cause: unknown) => cause,
    );
    expect(error).toBeInstanceOf(BoundedInputError);
    expect(error).not.toBe(planted);
    expect(error).toMatchObject({ code: "input-stream" });
    expect(String(error)).not.toContain(secret);
  });
});
