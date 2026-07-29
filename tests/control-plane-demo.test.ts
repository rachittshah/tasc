import { createSecretKey } from "node:crypto";
import {
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { describe, expect, it } from "vitest";
import {
  parseShadowRunPlan,
} from "../src/index.js";
import {
  authorizeCollectorRequest,
  fingerprintCollectorEndpointBinding,
  fingerprintRuntimeWireProfile,
  getRuntimeProfile,
  parseCollectorTrustPolicy,
  parseRuntimeInstanceIdentity,
  type ShadowCaseInput,
} from "../src/runtime/index.js";
import {
  runShadowCollectionForTesting,
  type ShadowRunnerHooks,
} from "../src/runtime/shadow.js";

const repositoryRoot = resolve(import.meta.dirname, "..");
const demoPath = resolve(repositoryRoot, "scripts/control-plane-demo.ts");
const fixtureRoot = resolve(repositoryRoot, "examples/control-plane");
const EXPECTED_SHADOW_PLAN_DIGEST =
  "sha256:59e05741d187dda366db4028363890be9fb8b1828bf75d8f72837b4e84cd16ea";
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
  "controller snapshot: SHADOW_ASSESSING verified",
  "P1 static admission: "
    + "2/2 registry-pinned completions targets authorized",
  "P0 -> P1 lineage: 8/8 online traces bound to 2/2 plan targets",
  "dispatch intents: 16/16 verified",
  "evaluator evidence: 16/16 trusted",
  "development: NOMINATED",
  "selected policy kind: cascade",
  "selected policy digest: "
    + "sha256:fe8efa318a040c2f35f0f2f630e34c3897f04753ae4f7998c48a400119fa19f1",
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
    + "8d0fb525dbb25e0463bac7c09fae85cb0ab678942d4e180f5f0afff86dadebf4,"
    + "next-experiment="
    + "6ad1ef0cc210dbf058361b5f48f90a3c8f5f94598bf5e120676414589dec4ae6,"
    + "policy-recommendation="
    + "724211323bb623bd7113ad9e794f0d6dda2f82f918abf668ed99ab416d701a9b,"
    + "sealed-window-assessment="
    + "590a3c1dee9e4095909057b2dbd148ea5a0caa8cded47c25d948b9df59340bf6",
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
        "controller-snapshot.json",
        "shadow-run-plan.json",
        "shadow-profiles.json",
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
      const collectorTrustText = readFileSync(
        resolve(fixtureRoot, "collector-trust.json"),
        "utf8",
      );
      expect(collectorTrustText).not.toMatch(
        /\b(?:privateKey|private_key|apiKey|api_key|credential|bearer|token)\b/iu,
      );
      const collectorTrust = JSON.parse(collectorTrustText) as {
        secretReferences: readonly string[];
        endpoints: readonly {
          routes: readonly {
            authenticationReferences: readonly string[];
          }[];
        }[];
      };
      expect(collectorTrust.secretReferences).toEqual([]);
      expect(collectorTrust.endpoints.flatMap(
        ({ routes }) => routes.flatMap(
          ({ authenticationReferences }) => authenticationReferences,
        ),
      )).toEqual([]);
      expect(readFileSync(demoPath, "utf8")).not.toMatch(
        /\b(?:fetch|request|connect|invokeRuntime|probeRuntime)\s*\(/u,
      );

      const controllerSnapshot = JSON.parse(readFileSync(
        resolve(fixtureRoot, "controller-snapshot.json"),
        "utf8",
      )) as { snapshotDigest: string; state: string };
      const plan = JSON.parse(readFileSync(
        resolve(fixtureRoot, "shadow-run-plan.json"),
        "utf8",
      )) as {
        planDigest: string;
        controllerSnapshot: unknown;
        controllerSnapshotDigest: string;
        collectionTargets: readonly {
          profileId: string;
          authenticationReference: string | null;
        }[];
      };
      const onlineTraces = readFileSync(
        resolve(fixtureRoot, "online-traces.ndjson"),
        "utf8",
      ).trim().split("\n").map((line) => JSON.parse(line) as {
        profileId: string;
        collectionBinding: {
          shadowPlanDigest: string;
          authenticationReference: string | null;
        } | null;
      });
      expect(controllerSnapshot.state).toBe("SHADOW_ASSESSING");
      expect(plan.controllerSnapshot).toEqual(controllerSnapshot);
      expect(plan.controllerSnapshotDigest)
        .toBe(controllerSnapshot.snapshotDigest);
      expect(new Set(plan.collectionTargets.map(({ profileId }) => profileId)))
        .toEqual(new Set(onlineTraces.map(({ profileId }) => profileId)));
      expect(plan.collectionTargets.every(
        ({ authenticationReference }) => authenticationReference === null,
      )).toBe(true);
      expect(onlineTraces.every(
        ({ collectionBinding }) =>
          collectionBinding?.shadowPlanDigest === plan.planDigest
          && collectionBinding.authenticationReference === null,
      )).toBe(true);
    } finally {
      for (const { artifactRoot } of runs) {
        rmSync(artifactRoot, { recursive: true, force: true });
      }
    }
  }, 90_000);

  it("admits every committed plan target against exact shipped P1 metadata", () => {
    const plan = parseShadowRunPlan(JSON.parse(readFileSync(
      resolve(fixtureRoot, "shadow-run-plan.json"),
      "utf8",
    )));
    const collectorTrust = parseCollectorTrustPolicy(JSON.parse(readFileSync(
      resolve(fixtureRoot, "collector-trust.json"),
      "utf8",
    )));
    const profiles = JSON.parse(readFileSync(
      resolve(fixtureRoot, "shadow-profiles.json"),
      "utf8",
    )) as {
      schemaVersion: string;
      targets: readonly {
        profileId: string;
        endpoint: {
          schemaVersion: string;
          endpointAlias: string;
        };
        instance: unknown;
        route: string;
      }[];
    };

    expect(profiles.schemaVersion).toBe("tasc-cli-shadow-profiles-v2");
    expect(plan.protocol.requiredCapabilities).toEqual([]);
    expect(plan.collectionTargets.every(
      ({ capabilityReceiptDigests }) =>
        capabilityReceiptDigests.length === 0,
    )).toBe(true);

    const admitted = plan.collectionTargets.map((planTarget) => {
      const target = profiles.targets.find(
        ({ profileId }) => profileId === planTarget.profileId,
      );
      expect(target).toBeDefined();
      expect(target!.endpoint.schemaVersion)
        .toBe("tasc-cli-runtime-endpoint-v1");
      expect(target!.endpoint.endpointAlias).toBe(planTarget.endpointAlias);
      expect(target!.route).toBe("completions");
      expect(planTarget.route).toBe("completions");
      expect(planTarget.authenticationReference).toBeNull();

      const instance = parseRuntimeInstanceIdentity(target!.instance);
      const registry = getRuntimeProfile(instance.runtime.profileId);
      const executionProfile = plan.protocol.profiles.find(
        ({ id }) => id === planTarget.profileId,
      );
      expect(executionProfile).toBeDefined();
      expect(instance.runtime.build).toBe(registry.runtime.build);
      expect(executionProfile!.runtime).toEqual({
        name: registry.id,
        build: registry.runtime.build,
      });
      expect(instance.backend).toEqual(executionProfile!.backend);
      expect(instance.model).toEqual(executionProfile!.model);
      expect(instance.configurationDigest)
        .toBe(executionProfile!.deploymentConfigurationDigest);
      expect(instance.endpointDescriptorDigest)
        .toBe(planTarget.endpointBindingDigest);
      expect(fingerprintCollectorEndpointBinding(
        collectorTrust,
        target!.endpoint.endpointAlias,
      )).toBe(planTarget.endpointBindingDigest);
      expect(registry.capabilities.completions.state).toBe("supported");
      const route = registry.endpoints.inference.completions;
      expect(route).toMatchObject({
        method: "POST",
        path: "/v1/completions",
        capability: "completions",
      });
      expect(fingerprintRuntimeWireProfile(registry))
        .toMatch(/^sha256:[a-f0-9]{64}$/u);
      expect(authorizeCollectorRequest(collectorTrust, {
        endpointAlias: target!.endpoint.endpointAlias,
        runtime: instance.runtime,
        method: route!.method,
        path: route!.path,
      }).authority.kind).toBe("collector-trust-policy");
      return {
        profileId: planTarget.profileId,
        runtime: instance.runtime,
        route: target!.route,
      };
    });

    expect(admitted).toEqual([
      {
        profileId: "candidate-tensorrt-skypilot",
        runtime: { profileId: "tensorrt-llm", build: "1.2.1" },
        route: "completions",
      },
      {
        profileId: "champion-vllm-ray",
        runtime: { profileId: "vllm", build: "0.26.0" },
        route: "completions",
      },
    ]);
    const windowDurationMs =
      Date.parse(plan.window.eventTimeEndExclusive)
      - Date.parse(plan.window.eventTimeStartInclusive);
    const worstCaseAttemptTimeMs =
      plan.workBudget.maxAttempts
      * plan.protocol.shadowCollection.attemptTimeoutMs;
    expect(plan.workBudget.maxWallClockMs).toBeGreaterThanOrEqual(
      worstCaseAttemptTimeMs,
    );
    expect(plan.workBudget.maxWallClockMs)
      .toBeLessThanOrEqual(windowDurationMs);
  });

  it("admits the sealed historical plan through the runner core using the test-only clock/effect seam", async () => {
    const plan = parseShadowRunPlan(JSON.parse(readFileSync(
      resolve(fixtureRoot, "shadow-run-plan.json"),
      "utf8",
    )));
    expect(plan.planDigest).toBe(EXPECTED_SHADOW_PLAN_DIGEST);

    const collectorTrust = parseCollectorTrustPolicy(JSON.parse(readFileSync(
      resolve(fixtureRoot, "collector-trust.json"),
      "utf8",
    )));
    const profileInput = JSON.parse(readFileSync(
      resolve(fixtureRoot, "shadow-profiles.json"),
      "utf8",
    )) as {
      targets: readonly {
        profileId: string;
        endpoint: { endpointAlias: string };
        instance: unknown;
        route: "completions";
        httpLimits: {
          deadlineMs: number;
          maxRequestBytes: number;
          maxResponseBytes: number;
        };
      }[];
    };
    const traces = readFileSync(
      resolve(fixtureRoot, "online-traces.ndjson"),
      "utf8",
    ).trim().split("\n").map((line) => JSON.parse(line) as {
      caseId: string;
      groupId: string;
      workload: ShadowCaseInput["workload"];
      slices: readonly string[];
      routeSignal: {
        value: number;
        provenance: {
          sourceId: string;
          observedAt: string;
        };
      } | null;
    });
    const casesById = new Map<string, ShadowCaseInput>();
    for (const trace of traces) {
      if (casesById.has(trace.caseId)) continue;
      expect(trace.routeSignal).not.toBeNull();
      casesById.set(trace.caseId, Object.freeze({
        caseId: trace.caseId,
        groupId: trace.groupId,
        replicates: 1,
        generation: Object.freeze({
          stream: false,
          n: 1,
          prompt: `test-only-${trace.caseId}`,
          maxTokens: 1,
          temperature: 0,
        }),
        workload: trace.workload,
        slices: trace.slices,
        routeSignal: Object.freeze({
          value: trace.routeSignal!.value,
          sourceId: trace.routeSignal!.provenance.sourceId,
          observedAt: plan.window.eventTimeStartInclusive,
        }),
      }));
    }

    const effectViolation = (): never => {
      throw new Error("historical P1 admission test crossed an effect boundary");
    };
    const hooks: ShadowRunnerHooks = Object.freeze({
      now: () => new Date(plan.window.eventTimeStartInclusive),
      prepareInvocation: effectViolation,
      dispatchInvocation: async () => effectViolation(),
      readPacket: async () => effectViolation(),
      writePacket: async () => effectViolation(),
      checkpoint: effectViolation,
    });
    const signal = new AbortController();
    signal.abort();
    const temporaryRoot = mkdtempSync(join(tmpdir(), "tasc-p1-admission-"));
    const outputRoot = resolve(temporaryRoot, "never-created");
    try {
      expect(existsSync(outputRoot)).toBe(false);
      const result = await runShadowCollectionForTesting({
        plan,
        expectedPlanDigest: EXPECTED_SHADOW_PLAN_DIGEST,
        rootDirectory: outputRoot,
        cases: Object.freeze([...casesById.values()]),
        profiles: Object.freeze(profileInput.targets.map((target) =>
          Object.freeze({
            profileId: target.profileId,
            runtime: Object.freeze({
              policy: collectorTrust,
              endpointAlias: target.endpoint.endpointAlias,
              instance: parseRuntimeInstanceIdentity(target.instance),
              route: target.route,
              httpLimits: target.httpLimits,
            }),
          })
        )),
        identity: Object.freeze({
          studyId: plan.protocol.studyId,
          keyId: "test-only-payload-key",
          key: createSecretKey(Buffer.alloc(32, 0x53)),
        }),
        dispatchIntentSigner: Object.freeze({
          keyId: plan.protocol.dispatchAuthority.keyId,
          algorithm: "ed25519",
          sign: effectViolation,
        }),
        collectorAttestationSigner: Object.freeze({
          keyId: plan.protocol.collectorAuthority.keyId,
          algorithm: "ed25519",
          sign: effectViolation,
        }),
        signal: signal.signal,
        hooks,
      });
      expect(result).toMatchObject({
        status: "cancelled",
        logicalExecutions: 8,
        attemptsRecorded: 0,
        networkCalls: 0,
        durableRecordsWritten: 0,
      });
      expect(result.pendingTraceIds).toHaveLength(8);
      expect(existsSync(outputRoot)).toBe(false);
    } finally {
      rmSync(temporaryRoot, { recursive: true, force: true });
    }
  });
});
