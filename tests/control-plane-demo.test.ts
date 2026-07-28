import { readFileSync, rmSync } from "node:fs";
import { resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { describe, expect, it } from "vitest";

const repositoryRoot = resolve(import.meta.dirname, "..");
const demoPath = resolve(repositoryRoot, "scripts/control-plane-demo.ts");
const fixtureRoot = resolve(repositoryRoot, "examples/control-plane");
const networkBlocker = [
  'import net from "node:net";',
  'import http from "node:http";',
  'import https from "node:https";',
  'import http2 from "node:http2";',
  'const deny=()=>{throw new Error("NETWORK_FORBIDDEN_BY_TEST")};',
  "net.connect=deny;",
  "net.createConnection=deny;",
  "net.Socket.prototype.connect=deny;",
  "http.request=deny;",
  "http.get=deny;",
  "https.request=deny;",
  "https.get=deny;",
  "http2.connect=deny;",
  'Object.defineProperty(globalThis,"fetch",',
  "{value:deny,writable:false,configurable:false});",
].join("");
const blockerUrl = `data:text/javascript,${
  encodeURIComponent(networkBlocker)
}`;

const GOLDEN_SUMMARY = [
  "TASC CONTROL PLANE DEMO",
  "mode: OFFLINE_FIXTURE_REPLAY",
  "network calls: 0",
  "model calls: 0",
  "dispatch intents: 16/16 verified",
  "evaluator evidence: 16/16 trusted",
  "development: NOMINATED",
  "selected policy kind: cascade",
  "selected policy digest: "
    + "sha256:36bad55a2b455ef9a08f85e0d940afa566403e3b5568d33d3c093cfdbaf9848f",
  "development coverage: groups=4 account-recovery-groups=2 evidence=1.00",
  "sealed window: INSUFFICIENT_EVIDENCE",
  "window coverage: groups=4 account-recovery-groups=2 evidence=1.00",
  "service capacity: UNAVAILABLE "
    + "(exact-policy attested window service capacity is unavailable)",
  "next experiment: PROPOSED (unavailable-capacity)",
  "recommendation: HOLD_FOR_TRUSTED_CAPACITY_EVIDENCE",
  "authority: evidence-only-no-deployment-authority",
  "artifact packets: "
    + "development-assessment="
    + "7a98d50eb80a1e2ffff450c618aa1755e0aa31204afd825e6fd5c09b4a77a44f,"
    + "next-experiment="
    + "2ff1086ab1bafe9b684bb3458ed75c48f38b26cd37afe183cfbf7981d32036a4,"
    + "policy-recommendation="
    + "c09b4c14800b2c9ccba29511b3d8df001266602458789a4c1c27e630896998d7,"
    + "sealed-window-assessment="
    + "0fbe75410621f29ed20eba4d76a72b534326633ac58fedc6b1d74d6f462255b3",
  "artifact verification: 4/4 manifests and payload digests verified",
  "artifact root: <TEMP>",
  "",
].join("\n");

interface DemoRun {
  readonly normalized: string;
  readonly output: string;
  readonly artifactRoot: string;
}

function runDemo(): DemoRun {
  const result = spawnSync(
    process.execPath,
    ["--import", blockerUrl, "--import", "tsx", demoPath],
    {
      cwd: repositoryRoot,
      encoding: "utf8",
      timeout: 60_000,
      env: {
        ...process.env,
        HTTP_PROXY: "http://127.0.0.1:1",
        HTTPS_PROXY: "http://127.0.0.1:1",
        NO_PROXY: "",
      },
    },
  );
  expect(result.error).toBeUndefined();
  expect(result.status).toBe(0);
  expect(result.stderr).toBe("");
  const match = /^artifact root: (.+)$/mu.exec(result.stdout);
  expect(match).not.toBeNull();
  const artifactRoot = match![1];
  return {
    output: result.stdout,
    normalized: result.stdout.replace(
      /^artifact root: .+$/mu,
      "artifact root: <TEMP>",
    ),
    artifactRoot,
  };
}

describe("production control-plane demo", () => {
  it("replays signed fixtures deterministically without network or model calls", () => {
    const runs: DemoRun[] = [];
    try {
      runs.push(runDemo());
      expect(runs[0].normalized).toBe(GOLDEN_SUMMARY);

      for (const run of runs) {
        expect(run.output).not.toMatch(
          /\b(?:prompt|raw output|private key|api key|secret)\b/iu,
        );
        for (const target of [
          "development-assessment",
          "sealed-window-assessment",
          "next-experiment",
          "policy-recommendation",
        ]) {
          const manifest = JSON.parse(readFileSync(
            resolve(run.artifactRoot, target, "manifest.json"),
            "utf8",
          )) as {
            completion: { authority: string };
            manifestDigest: string;
            packetDigest: string;
          };
          expect(manifest.completion.authority)
            .toBe("evidence-only-no-deployment-authority");
          expect(manifest.manifestDigest).toMatch(/^[a-f0-9]{64}$/u);
          expect(manifest.packetDigest).toMatch(/^[a-f0-9]{64}$/u);
        }
      }

      const fixtureText = [
        "protocol.json",
        "trust-snapshot.json",
        "development-traces.ndjson",
        "development-evidence.ndjson",
        "online-traces.ndjson",
        "online-evidence.ndjson",
      ].map((name) => readFileSync(resolve(fixtureRoot, name), "utf8"))
        .join("\n");
      expect(fixtureText).not.toMatch(
        /\b(?:privateKey|private_key|apiKey|api_key|secret|prompt)\b/iu,
      );
      expect(readFileSync(demoPath, "utf8")).not.toMatch(
        /\b(?:fetch|request|connect|invokeRuntime|probeRuntime)\s*\(/u,
      );
    } finally {
      for (const { artifactRoot } of runs) {
        rmSync(artifactRoot, { recursive: true, force: true });
      }
    }
  }, 90_000);
});
