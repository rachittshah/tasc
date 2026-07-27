import { execFileSync } from "node:child_process";
import { describe, expect, it } from "vitest";
import {
  CANONICAL_JSON_VERSION,
  canonicalJson,
  canonicalJsonBytes,
  compareCodeUnits,
} from "../src/determinism.js";

describe("portable deterministic primitives", () => {
  it("orders identifiers by UTF-16 code units without locale collation", () => {
    const identifiers = ["z", "ä", "a10", "a2", "a", "a\u0000", "😀", "😃"];

    expect([...identifiers].sort(compareCodeUnits)).toEqual([
      "a",
      "a\u0000",
      "a10",
      "a2",
      "z",
      "ä",
      "😀",
      "😃",
    ]);
    expect(compareCodeUnits("a", "a")).toBe(0);
    expect(compareCodeUnits("a", "a\u0000")).toBeLessThan(0);
    expect(compareCodeUnits("😀", "😃")).toBeLessThan(0);
  });

  it("implements versioned RFC 8785 JCS vectors", () => {
    expect(CANONICAL_JSON_VERSION).toBe("rfc8785-jcs-v1");
    expect(canonicalJson({
      numbers: [333333333.33333329, 1e30, 4.50, 2e-3, 0.000000000000000000000000001],
      string: "€$\u000f\nA'B\"\\\"/",
    })).toBe('{"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\\u000f\\nA\'B\\"\\\\\\"/"}');
    expect(canonicalJson({ "\ufb33": "Hebrew", "\u0080": "Control", "\r": "CR", "1": "One", "€": "Euro", "ö": "Latin", "😀": "Smiley" }))
      .toBe('{"\\r":"CR","1":"One","":"Control","ö":"Latin","€":"Euro","😀":"Smiley","דּ":"Hebrew"}');
    expect(canonicalJsonBytes({ b: 2, a: 1 }).toString("utf8")).toBe('{"a":1,"b":2}');
    expect(() => canonicalJson({ nan: Number.NaN })).toThrow(/I-JSON|finite/i);
    expect(() => canonicalJson({ infinity: Number.POSITIVE_INFINITY })).toThrow(/I-JSON|finite/i);
    expect(() => canonicalJson({ missing: undefined })).toThrow(/I-JSON|JSON-compatible/i);
    expect(() => canonicalJson({ [Symbol("non-json")]: 1 })).toThrow(/JSON-compatible/i);
    expect(() => canonicalJson([, 1])).toThrow(/arrays without holes/i);
    expect(() => canonicalJson({ surrogate: "\ud800" })).toThrow(/Unicode|surrogate/i);
  });

  it("keeps canonical artifact bytes and decisions invariant across process locales", () => {
    const moduleUrl = new URL("../src/determinism.ts", import.meta.url).href;
    const evaluateUrl = new URL("../src/evaluate.ts", import.meta.url).href;
    const schemaUrl = new URL("../src/schema.ts", import.meta.url).href;
    const specPath = new URL("../examples/synthetic/spec.json", import.meta.url).pathname;
    const developmentPath = new URL("../examples/synthetic/dev.json", import.meta.url).pathname;
    const script = `
      import { createHash } from "node:crypto";
      import { readFileSync } from "node:fs";
      import { canonicalJson, compareCodeUnits } from ${JSON.stringify(moduleUrl)};
      import { nominatePolicy } from ${JSON.stringify(evaluateUrl)};
      import { parseInferenceSpec, parseMeasurementSet } from ${JSON.stringify(schemaUrl)};
      const ids = ["z", "ä", "a10", "a2", "😀", "😃"];
      const ordered = [...ids].sort(compareCodeUnits);
      const spec = parseInferenceSpec(JSON.parse(readFileSync(${JSON.stringify(specPath)}, "utf8")));
      const development = parseMeasurementSet(JSON.parse(readFileSync(${JSON.stringify(developmentPath)}, "utf8")), "dev");
      const result = nominatePolicy(spec, development);
      if (result.status !== "NOMINATED" || !result.nomination) throw new Error("expected synthetic nomination");
      const artifact = canonicalJson(result.nomination);
      process.stdout.write(JSON.stringify({
        legacy: "z".localeCompare("ä"),
        ordered,
        status: result.status,
        decisionDigest: result.nomination.decisionDigest,
        selfDigest: result.nomination.selfDigest,
        artifact,
        digest: createHash("sha256").update(artifact).digest("hex"),
      }));
    `;
    const run = (locale: string) => JSON.parse(execFileSync(process.execPath, [
      "--import",
      "tsx",
      "--input-type=module",
      "--eval",
      script,
    ], {
      encoding: "utf8",
      env: { ...process.env, LANG: locale, LC_ALL: locale },
    })) as {
      legacy: number;
      ordered: string[];
      status: string;
      decisionDigest: string;
      selfDigest: string;
      artifact: string;
      digest: string;
    };

    const c = run("C");
    const english = run("en_US.UTF-8");
    const swedish = run("sv_SE.UTF-8");

    expect(swedish.legacy).toBeLessThan(0);
    expect(c.legacy).not.toBe(swedish.legacy);
    expect(english.legacy).not.toBe(swedish.legacy);
    expect([c, english, swedish].map(({ legacy: _legacy, ...result }) => result)).toEqual([
      expect.objectContaining({
        ordered: ["a10", "a2", "z", "ä", "😀", "😃"],
        status: "NOMINATED",
        decisionDigest: expect.stringMatching(/^[a-f0-9]{64}$/),
        selfDigest: expect.stringMatching(/^[a-f0-9]{64}$/),
      }),
      expect.objectContaining({
        ordered: ["a10", "a2", "z", "ä", "😀", "😃"],
        status: "NOMINATED",
        decisionDigest: expect.stringMatching(/^[a-f0-9]{64}$/),
        selfDigest: expect.stringMatching(/^[a-f0-9]{64}$/),
      }),
      expect.objectContaining({
        ordered: ["a10", "a2", "z", "ä", "😀", "😃"],
        status: "NOMINATED",
        decisionDigest: expect.stringMatching(/^[a-f0-9]{64}$/),
        selfDigest: expect.stringMatching(/^[a-f0-9]{64}$/),
      }),
    ]);
    expect(c.artifact).toBe(english.artifact);
    expect(c.artifact).toBe(swedish.artifact);
    expect(c.digest).toBe(english.digest);
    expect(c.digest).toBe(swedish.digest);
    expect(c.decisionDigest).toBe(english.decisionDigest);
    expect(c.decisionDigest).toBe(swedish.decisionDigest);
    expect(c.selfDigest).toBe(english.selfDigest);
    expect(c.selfDigest).toBe(swedish.selfDigest);
  });
});
