import { Buffer } from "node:buffer";
import {
  createSecretKey,
  generateKeyPairSync,
  sign,
  type KeyObject,
} from "node:crypto";
import {
  mkdtemp,
  readFile,
  readdir,
  rm,
  stat,
} from "node:fs/promises";
import { createServer } from "node:http";
import type { Socket } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  readArtifactPacketIfPresent,
  writeArtifactPacketOrVerifyIdentical,
  type ArtifactReadResult,
} from "../src/artifacts.js";
import { canonicalJsonBytes } from "../src/determinism.js";
import {
  createControllerSnapshot,
  type ControllerSnapshot,
} from "../src/controller-events.js";
import {
  normalizeExperimentProtocol,
  fingerprintProtocol,
  type ExperimentProtocol,
} from "../src/evidence.js";
import {
  enumerateProtocolPolicyBundles,
  type PolicyBundle,
} from "../src/policy.js";
import {
  createStudyPayloadIdentity,
} from "../src/references.js";
import {
  fingerprintRuntimeInvocationHttpLimits,
} from "../src/runtime-http-limits.js";
import {
  describeRuntimeInvocation,
  RuntimeInvocationInputError,
  type PreparedRuntimeInvocation,
  type RuntimeInvocationInput,
  type RuntimeInvocationOutcome,
  type RuntimeInvocationPersistence,
} from "../src/runtime/invoke.js";
import {
  fingerprintCollectorEndpointBinding,
  parseCollectorTrustPolicy,
} from "../src/runtime/network-policy.js";
import {
  runShadowCollection as runShadowCollectionProduction,
  runShadowCollectionForTesting as runShadowCollection,
  type ShadowCaseInput,
  type ShadowProfileTarget,
  type ShadowRunInput,
  type ShadowRunnerHooks,
  type ShadowWorkBudget,
} from "../src/runtime/shadow.js";
import {
  buildShadowRunPlan,
  type ShadowRunPlan,
} from "../src/shadow-plan.js";
import { validProtocolInput } from "./fixtures/evidence.js";

const DIGEST = (digit: string): string => `sha256:${digit.repeat(64)}`;
const roots = new Set<string>();

afterEach(async () => {
  await Promise.all([...roots].map(async (root) => {
    roots.delete(root);
    await rm(root, { recursive: true, force: true });
  }));
});

async function temporaryRoot(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "tasc-shadow-test-"));
  roots.add(root);
  return root;
}

interface TestClock {
  readonly now: () => Date;
  advance(milliseconds: number): void;
}

function testClock(): TestClock {
  let milliseconds = Date.parse("2026-07-25T12:00:00.000Z");
  return {
    now: () => new Date(milliseconds),
    advance: (amount) => {
      milliseconds += amount;
    },
  };
}

interface ProtocolFixture {
  readonly protocol: ExperimentProtocol;
  readonly signer: ShadowRunInput["dispatchIntentSigner"];
  readonly collectorSigner:
    ShadowRunInput["collectorAttestationSigner"];
}

function protocolFixture(input: {
  readonly maximumAttempts?: number;
  readonly maximumConcurrency?: number;
  readonly attemptTimeoutMs?: number;
  readonly expiresAt?: string;
  readonly runtimeBuild?: string;
  readonly requiredCapabilities?: ExperimentProtocol["requiredCapabilities"];
} = {}): ProtocolFixture {
  const keys = generateKeyPairSync("ed25519");
  const collectorKeys = generateKeyPairSync("ed25519");
  const protocolInput = validProtocolInput();
  protocolInput.dispatchAuthority.publicKeySpki = keys.publicKey
    .export({ type: "spki", format: "der" })
    .toString("base64url");
  protocolInput.collectorAuthority.publicKeySpki = collectorKeys.publicKey
    .export({ type: "spki", format: "der" })
    .toString("base64url");
  protocolInput.onlineWindowMembership.sampleBasisPoints = 10_000;
  protocolInput.shadowCollection.maximumLogicalExecutions = 100;
  protocolInput.shadowCollection.maximumAttempts =
    input.maximumAttempts ?? 2;
  protocolInput.shadowCollection.maximumConcurrency =
    input.maximumConcurrency ?? 1;
  protocolInput.shadowCollection.attemptTimeoutMs =
    input.attemptTimeoutMs ?? 100;
  (
    protocolInput.endpointRequirements[0] as {
      transport: "https" | "loopback-http";
    }
  ).transport = "loopback-http";
  if (input.expiresAt !== undefined) {
    protocolInput.expiresAt = input.expiresAt;
  }
  for (const profile of protocolInput.profiles) {
    profile.runtime.build = input.runtimeBuild ?? "0.26.0";
  }
  if (input.requiredCapabilities !== undefined) {
    protocolInput.requiredCapabilities = [...input.requiredCapabilities];
  } else {
    protocolInput.requiredCapabilities = [];
  }
  return {
    protocol: normalizeExperimentProtocol(protocolInput),
    signer: {
      keyId: protocolInput.dispatchAuthority.keyId,
      algorithm: "ed25519",
      sign: (bytes) => sign(null, bytes, keys.privateKey).toString("base64url"),
    },
    collectorSigner: {
      keyId: protocolInput.collectorAuthority.keyId,
      algorithm: "ed25519",
      sign: (bytes) =>
        sign(null, bytes, collectorKeys.privateKey).toString("base64url"),
    },
  };
}

function selectedPolicy(protocol: ExperimentProtocol): PolicyBundle {
  const policy = enumerateProtocolPolicyBundles(
    protocol,
    fingerprintProtocol(protocol),
    protocol.createdAt,
  ).candidates[0];
  if (policy === undefined) {
    throw new Error("shadow test protocol has no candidate policy");
  }
  return policy;
}

function shadowControllerSnapshot(
  protocol: ExperimentProtocol,
  policy: PolicyBundle,
  issuedAt: string,
): ControllerSnapshot {
  const protocolDigest = fingerprintProtocol(protocol);
  const selected = {
    policyDigest: policy.policyDigest,
    issuedAt: policy.issuedAt,
    expiresAt: policy.expiresAt,
  };
  return createControllerSnapshot({
    version: "tasc-controller-snapshot-v1",
    controllerId: "shadow-controller-1",
    studyId: protocol.studyId,
    protocolDigest,
    protocolCreatedAt: protocol.createdAt,
    protocolExpiresAt: protocol.expiresAt,
    state: "SHADOW_ASSESSING",
    sequence: 5,
    lastEventId: DIGEST("5"),
    lastEventAt: new Date(Date.parse(issuedAt) - 1_000).toISOString(),
    collectionId: "shadow-collection-1",
    developmentEvidence: {
      datasetDigest: DIGEST("1"),
      traceSetDigest: DIGEST("2"),
      evaluatorSetDigest: DIGEST("3"),
    },
    selectedPolicy: selected,
    assessments: [{
      version: "tasc-controller-assessment-projection-v1",
      phase: "development",
      status: "NOMINATED",
      decisionDigest: DIGEST("6"),
      assessmentContextDigest: DIGEST("7"),
      protocolDigest,
      datasetDigest: DIGEST("1"),
      traceSetDigest: DIGEST("2"),
      evaluatorSetDigest: DIGEST("3"),
      selectedPolicy: selected,
      windowManifestDigest: null,
      attestation: "unattested",
    }],
    windows: [],
    deploymentObservation: null,
    staleReasons: [],
    attestation: "unattested",
  });
}

function shadowPlan(input: {
  readonly fixture: ProtocolFixture;
  readonly profiles: readonly ShadowProfileTarget[];
  readonly budget: ShadowWorkBudget;
  readonly clock: TestClock;
  readonly windowId?: string;
}): ShadowRunPlan {
  const nowMs = input.clock.now().getTime();
  const issuedAt = new Date(nowMs - 60_000).toISOString();
  const protocolExpiryMs = Date.parse(input.fixture.protocol.expiresAt);
  const desiredExpiryMs = nowMs + input.budget.maxWallClockMs + 60_000;
  const expiresAtMs = Math.min(protocolExpiryMs, desiredExpiryMs);
  const policy = selectedPolicy(input.fixture.protocol);
  return buildShadowRunPlan({
    controllerSnapshot: shadowControllerSnapshot(
      input.fixture.protocol,
      policy,
      issuedAt,
    ),
    protocol: input.fixture.protocol,
    frozenPolicy: policy,
    window: {
      windowId: input.windowId ?? "window-one",
      eventTimeStartInclusive: input.clock.now().toISOString(),
      eventTimeEndExclusive: new Date(expiresAtMs).toISOString(),
    },
    collectionTargets: input.profiles.map((profile) => {
      const runtime = profile.runtime as unknown as RuntimeInvocationInput;
      return {
        profileId: profile.profileId,
        endpointAlias: runtime.endpointAlias,
        endpointBindingDigest:
          runtime.instance.endpointDescriptorDigest,
        route: runtime.route,
        authenticationReference:
          runtime.authenticationReference ?? null,
        httpLimitsDigest:
          fingerprintRuntimeInvocationHttpLimits(runtime.httpLimits),
        capabilityReceiptDigests: [],
      };
    }),
    workBudget: {
      ...input.budget,
      maxLogicalExecutions: Math.min(
        input.budget.maxLogicalExecutions,
        input.fixture.protocol.shadowCollection.maximumLogicalExecutions,
      ),
      maxConcurrency: Math.min(
        input.budget.maxConcurrency,
        input.fixture.protocol.shadowCollection.maximumConcurrency,
      ),
    },
    issuedAt,
    expiresAt: new Date(expiresAtMs).toISOString(),
  });
}

function caseInput(input: {
  readonly caseId?: string;
  readonly replicates?: number;
  readonly prompt?: string;
} = {}): ShadowCaseInput {
  const caseId = input.caseId ?? "case-one";
  return {
    caseId,
    groupId: `group-${caseId}`,
    replicates: input.replicates ?? 1,
    generation: {
      stream: false,
      n: 1,
      prompt: input.prompt ?? "private-prompt-must-never-persist",
      maxTokens: 32,
      temperature: 0,
      seed: 7,
    },
    workload: {
      mode: "completion",
      declaredTrafficWeight: 1,
      inputTokenEstimate: 8,
    },
    slices: ["english"],
    routeSignal: {
      value: 0.75,
      sourceId: "router-observer",
      observedAt: "2026-07-25T11:59:59.000Z",
    },
  };
}

function targets(
  protocol: ExperimentProtocol,
  origin?: string,
  route: "chatCompletions" | "completions" = "completions",
): readonly ShadowProfileTarget[] {
  return protocol.profiles.map((profile, index) => {
    const endpointAlias = "approved-vllm";
    const policy = parseCollectorTrustPolicy({
      schemaVersion: "tasc-collector-trust-policy-v1",
      localMode: "literal-loopback-only",
      maximumRequestDurationMs: 300_000,
      endpoints: [{
        alias: endpointAlias,
        origin: origin ?? `http://127.0.0.1:${9_000 + index}`,
        runtime: {
          profileId: profile.runtime.name,
          build: profile.runtime.build,
        },
        routes: [{
          method: "POST",
          pathPrefix: route === "chatCompletions"
            ? "/v1/chat/completions"
            : "/v1/completions",
          authenticationReferences: [],
        }],
      }],
      secretReferences: [],
      evaluatorKeyIds: [],
      storeRoots: [],
    });
    return {
      profileId: profile.id,
      runtime: {
        policy,
        endpointAlias,
        instance: {
          endpointDescriptorDigest: fingerprintCollectorEndpointBinding(
            policy,
            endpointAlias,
          ),
          runtime: {
            profileId: profile.runtime.name,
            build: profile.runtime.build,
          },
          backend: {
            name: profile.backend.name,
            build: profile.backend.build,
          },
          model: profile.model,
          configurationDigest: profile.deploymentConfigurationDigest,
        },
        route,
      },
    } as unknown as ShadowProfileTarget;
  });
}

const GENEROUS_BUDGET: Readonly<ShadowWorkBudget> = Object.freeze({
  maxCases: 100,
  maxProfiles: 16,
  maxReplicates: 1_000,
  maxLogicalExecutions: 10_000,
  maxAttempts: 100_000,
  maxNetworkCalls: 100_000,
  maxDurableRecords: 300_000,
  maxRequestBytes: 1024 * 1024 * 1024,
  maxResponseBytes: 1024 * 1024 * 1024,
  maxWallClockMs: 1_000_000_000,
  maxConcurrency: 100,
});

function fakePrepare(input: RuntimeInvocationInput): PreparedRuntimeInvocation {
  const description = describeRuntimeInvocation(input);
  return Object.freeze({
    schemaVersion: "tasc-prepared-runtime-invocation-v1",
    endpointBindingDigest: description.endpointBindingDigest,
    profile: description.profile,
    route: description.route,
    requestedModel: description.requestedModel,
    requestIdentity: description.requestIdentity,
    requestByteCount: description.requestByteCount,
  });
}

function persistence(
  prepared: PreparedRuntimeInvocation,
  override: Partial<RuntimeInvocationPersistence> = {},
): RuntimeInvocationPersistence {
  const terminalOutputIdentity = createStudyPayloadIdentity(
    "support-routing-study",
    "shadow-key",
    createSecretKey(Buffer.alloc(32, 0x53)),
    Buffer.from(`output-${prepared.requestedModel.id}`),
  );
  return {
    schemaVersion: "tasc-runtime-invocation-persistence-v1",
    status: "completed",
    endpointBindingDigest: prepared.endpointBindingDigest,
    profile: prepared.profile,
    route: prepared.route,
    requestedModel: prepared.requestedModel,
    resolvedModel: {
      id: prepared.requestedModel.id,
      revision: null,
      verification: "provider-reported",
    },
    requestIdentity: prepared.requestIdentity,
    responseIdentity: terminalOutputIdentity,
    eventStreamIdentity: terminalOutputIdentity,
    terminalOutputIdentity,
    finishReason: "stop",
    providerUsage: {
      inputTokens: 8,
      outputTokens: 4,
      totalTokens: 12,
    },
    providerTiming: {
      totalDurationNs: 10_000_000,
    },
    finalUsage: "present",
    partialOutput: false,
    dispatchState: "completed",
    abortLifecycle: "not-aborted",
    wireTiming: {
      startedAt: "2026-07-25T12:00:00.000Z",
      headersMs: 2,
      firstByteMs: 3,
      completedMs: 10,
    },
    streamTiming: {
      startedAtMs: 0,
      firstByteAtMs: 3,
      firstMeaningfulAtMs: 4,
      completedAtMs: 10,
      timeToFirstByteMs: 3,
      timeToFirstMeaningfulMs: 4,
      durationMs: 10,
    },
    error: null,
    ...override,
  };
}

function runtimeOutcome(
  prepared: PreparedRuntimeInvocation,
  override: Partial<RuntimeInvocationPersistence> = {},
): RuntimeInvocationOutcome {
  const durable = persistence(prepared, override);
  return {
    schemaVersion: "tasc-runtime-invocation-v1",
    status: durable.status,
    output: {
      text: "private-provider-output-must-never-persist",
      metadata: {
        choiceCount: 1,
        logprobsObserved: false,
      },
    },
    persistence: durable,
  };
}

async function makeInput(input: {
  readonly root?: string;
  readonly fixture?: ProtocolFixture;
  readonly cases?: readonly ShadowCaseInput[];
  readonly clock?: TestClock;
  readonly dispatch?: (
    prepared: PreparedRuntimeInvocation,
  ) => Promise<RuntimeInvocationOutcome>;
  readonly checkpoint?: ShadowRunnerHooks["checkpoint"];
  readonly signal?: AbortSignal;
  readonly workBudget?: ShadowWorkBudget;
  readonly profiles?: readonly ShadowProfileTarget[];
  readonly collectionWindowId?: string;
  readonly plan?: ShadowRunPlan;
  readonly expectedPlanDigest?: string;
  readonly identityKey?: KeyObject;
  readonly prepare?: (
    input: RuntimeInvocationInput,
  ) => PreparedRuntimeInvocation;
} = {}): Promise<{
  readonly input: ShadowRunInput & { readonly hooks?: ShadowRunnerHooks };
  readonly root: string;
  readonly fixture: ProtocolFixture;
  readonly clock: TestClock;
}> {
  const root = input.root ?? await temporaryRoot();
  const fixture = input.fixture ?? protocolFixture();
  const clock = input.clock ?? testClock();
  const profileTargets = input.profiles ?? targets(fixture.protocol);
  const budget = input.workBudget ?? GENEROUS_BUDGET;
  const plan = input.plan ?? shadowPlan({
    fixture,
    profiles: profileTargets,
    budget,
    clock,
    ...(input.collectionWindowId === undefined
      ? {}
      : { windowId: input.collectionWindowId }),
  });
  const hooks: ShadowRunnerHooks = {
    now: clock.now,
    prepareInvocation: input.prepare ?? fakePrepare,
    dispatchInvocation: input.dispatch
      ?? (async (prepared) =>
        runtimeOutcome(prepared, {
          wireTiming: {
            startedAt: clock.now().toISOString(),
            headersMs: 2,
            firstByteMs: 3,
            completedMs: 10,
          },
        })),
    ...(input.checkpoint === undefined
      ? {}
      : { checkpoint: input.checkpoint }),
  };
  return {
    root,
    fixture,
    clock,
    input: {
      plan,
      expectedPlanDigest: input.expectedPlanDigest ?? plan.planDigest,
      rootDirectory: root,
      cases: input.cases ?? [caseInput()],
      profiles: profileTargets,
      identity: {
        studyId: fixture.protocol.studyId,
        keyId: "shadow-key",
        key: input.identityKey
          ?? createSecretKey(Buffer.alloc(32, 0x53)),
      },
      dispatchIntentSigner: fixture.signer,
      collectorAttestationSigner: fixture.collectorSigner,
      ...(input.signal === undefined ? {} : { signal: input.signal }),
      hooks,
    },
  };
}

async function allFileText(root: string): Promise<string> {
  const chunks: string[] = [];
  const visit = async (path: string): Promise<void> => {
    for (const name of await readdir(path)) {
      const child = join(path, name);
      if ((await stat(child)).isDirectory()) {
        await visit(child);
      } else {
        chunks.push(await readFile(child, "utf8"));
      }
    }
  };
  await visit(root);
  return chunks.join("\n");
}

function acceptedPacketReader(
  transform: (trace: Record<string, unknown>) => Record<string, unknown>,
): NonNullable<ShadowRunnerHooks["readPacket"]> {
  return async (rootDirectory, targetName): Promise<ArtifactReadResult | null> => {
    const packet = await readArtifactPacketIfPresent(
      rootDirectory,
      targetName,
    );
    if (packet === null || !targetName.endsWith("-accepted")) return packet;
    const payload = packet.files[0]!;
    const record = JSON.parse(
      Buffer.from(payload.copyBytes()).toString("utf8"),
    ) as {
      version: string;
      trace: Record<string, unknown>;
    };
    const bytes = canonicalJsonBytes({
      ...record,
      trace: transform(record.trace),
    });
    return Object.freeze({
      ...packet,
      files: Object.freeze([Object.freeze({
        ...payload,
        copyBytes: () => Uint8Array.from(bytes),
      })]),
    });
  };
}

describe("shadow runner", () => {
  it("rejects a substituted self-consistent P0 plan before any P1 effect", async () => {
    const fixture = protocolFixture();
    const clock = testClock();
    const profileTargets = targets(fixture.protocol);
    const approvedPlan = shadowPlan({
      fixture,
      profiles: profileTargets,
      budget: GENEROUS_BUDGET,
      clock,
      windowId: "approved-window",
    });
    const substitutedPlan = shadowPlan({
      fixture,
      profiles: profileTargets,
      budget: GENEROUS_BUDGET,
      clock,
      windowId: "substituted-window",
    });
    expect(substitutedPlan.planDigest).not.toBe(approvedPlan.planDigest);

    const sign = vi.fn(fixture.signer.sign);
    const collectorSign = vi.fn(fixture.collectorSigner.sign);
    const prepare = vi.fn(fakePrepare);
    const dispatch = vi.fn(async (prepared: PreparedRuntimeInvocation) =>
      runtimeOutcome(prepared)
    );
    const readPacket = vi.fn(async () => null);
    const writePacket = vi.fn(async () => {
      throw new Error("must not write");
    });
    const made = await makeInput({
      fixture: {
        protocol: fixture.protocol,
        signer: { ...fixture.signer, sign },
        collectorSigner: { ...fixture.collectorSigner, sign: collectorSign },
      },
      clock,
      profiles: profileTargets,
      plan: substitutedPlan,
      expectedPlanDigest: approvedPlan.planDigest,
      prepare,
      dispatch,
    });

    await expect(runShadowCollection({
      ...made.input,
      hooks: {
        ...made.input.hooks,
        readPacket:
          readPacket as NonNullable<ShadowRunnerHooks["readPacket"]>,
        writePacket: writePacket as unknown as NonNullable<
          ShadowRunnerHooks["writePacket"]
        >,
      },
    })).rejects.toThrow(/expected plan digest/);
    expect(prepare).not.toHaveBeenCalled();
    expect(sign).not.toHaveBeenCalled();
    expect(collectorSign).not.toHaveBeenCalled();
    expect(readPacket).not.toHaveBeenCalled();
    expect(writePacket).not.toHaveBeenCalled();
    expect(dispatch).not.toHaveBeenCalled();
    await expect(readdir(made.root)).resolves.toEqual([]);
  });

  it.each([
    {
      name: "missing",
      mutate: (input: Record<string, unknown>) => {
        delete input.expectedPlanDigest;
      },
    },
    {
      name: "noncanonical",
      mutate: (input: Record<string, unknown>) => {
        input.expectedPlanDigest = "SHA256:" + "A".repeat(64);
      },
    },
  ])("rejects a $name expected P0 digest before effects", async ({ mutate }) => {
    const dispatch = vi.fn(async (prepared: PreparedRuntimeInvocation) =>
      runtimeOutcome(prepared)
    );
    const made = await makeInput({ dispatch });
    const candidate = { ...made.input } as Record<string, unknown>;
    mutate(candidate);
    await expect(runShadowCollection(
      candidate as unknown as ShadowRunInput & {
        readonly hooks: ShadowRunnerHooks;
      },
    )).rejects.toThrow(/expectedPlanDigest|expected plan digest/);
    expect(dispatch).not.toHaveBeenCalled();
    await expect(readdir(made.root)).resolves.toEqual([]);
  });

  it("keeps fault-injection hooks outside the production boundary", async () => {
    const dispatch = vi.fn(async (prepared: PreparedRuntimeInvocation) =>
      runtimeOutcome(prepared)
    );
    const made = await makeInput({ dispatch });
    await expect(runShadowCollectionProduction(
      made.input as ShadowRunInput,
    )).rejects.toThrow(/unknown field/);
    expect(dispatch).not.toHaveBeenCalled();
  });

  it("returns deterministic zero-effect cancellation before admission", async () => {
    const controller = new AbortController();
    controller.abort();
    const dispatch = vi.fn(async (prepared: PreparedRuntimeInvocation) =>
      runtimeOutcome(prepared)
    );
    const readPacket = vi.fn(async () => null);
    const writePacket = vi.fn(async () => {
      throw new Error("must not write");
    });
    const made = await makeInput({
      signal: controller.signal,
      dispatch,
    });
    const result = await runShadowCollection({
      ...made.input,
      hooks: {
        ...made.input.hooks,
        readPacket:
          readPacket as NonNullable<ShadowRunnerHooks["readPacket"]>,
        writePacket: writePacket as unknown as NonNullable<
          ShadowRunnerHooks["writePacket"]
        >,
      },
    });
    expect(result).toMatchObject({
      status: "cancelled",
      logicalExecutions: 2,
      networkCalls: 0,
      durableRecordsWritten: 0,
    });
    expect(result.pendingTraceIds).toHaveLength(2);
    expect(readPacket).not.toHaveBeenCalled();
    expect(writePacket).not.toHaveBeenCalled();
    expect(dispatch).not.toHaveBeenCalled();
  });

  it("rejects a required chat capability before effects when P0 admitted completions", async () => {
    const fixture = protocolFixture({
      requiredCapabilities: ["chat-completions"],
    });
    const prepare = vi.fn(fakePrepare);
    const dispatch = vi.fn(async (prepared: PreparedRuntimeInvocation) =>
      runtimeOutcome(prepared)
    );
    const readPacket = vi.fn(async () => null);
    const writePacket = vi.fn(async () => {
      throw new Error("must not write");
    });
    const made = await makeInput({ fixture, prepare, dispatch });
    await expect(runShadowCollection({
      ...made.input,
      hooks: {
        ...made.input.hooks,
        readPacket:
          readPacket as NonNullable<ShadowRunnerHooks["readPacket"]>,
        writePacket: writePacket as unknown as NonNullable<
          ShadowRunnerHooks["writePacket"]
        >,
      },
    })).rejects.toThrow(/required chat-completions capability/);
    expect(prepare).not.toHaveBeenCalled();
    expect(readPacket).not.toHaveBeenCalled();
    expect(writePacket).not.toHaveBeenCalled();
    expect(dispatch).not.toHaveBeenCalled();
  });

  it("rejects asynchronous dispatch-intent signers", async () => {
    const made = await makeInput();
    const asyncSigner = {
      ...made.fixture.signer,
      sign: async (bytes: Uint8Array) => made.fixture.signer.sign(bytes),
    } as unknown as ShadowRunInput["dispatchIntentSigner"];
    await expect(runShadowCollection({
      ...made.input,
      dispatchIntentSigner: asyncSigner,
    })).rejects.toThrow(/invalid signature/);
  });

  it("rejects over-budget work before signer, filesystem, or network contact", async () => {
    const fixture = protocolFixture();
    const clock = testClock();
    const signSpy = vi.fn(fixture.signer.sign);
    const prepareSpy = vi.fn(fakePrepare);
    const dispatchSpy = vi.fn(async (prepared: PreparedRuntimeInvocation) =>
      runtimeOutcome(prepared)
    );
    const readSpy = vi.fn(async () => null);
    const writeSpy = vi.fn(async () => {
      throw new Error("must not write");
    });
    const made = await makeInput({
      fixture: {
        protocol: fixture.protocol,
        collectorSigner: fixture.collectorSigner,
        signer: {
          ...fixture.signer,
          sign: signSpy,
        },
      },
      clock,
      cases: [caseInput({ replicates: 2 })],
      workBudget: {
        ...GENEROUS_BUDGET,
        maxLogicalExecutions: 1,
      },
    });
    const rejectedInput: ShadowRunInput & {
      readonly hooks: ShadowRunnerHooks;
    } = {
      ...made.input,
      hooks: {
        now: clock.now,
        prepareInvocation: prepareSpy,
        dispatchInvocation: dispatchSpy,
        readPacket: readSpy as NonNullable<ShadowRunnerHooks["readPacket"]>,
        writePacket: writeSpy as unknown as NonNullable<
          ShadowRunnerHooks["writePacket"]
        >,
      },
    };
    await expect(runShadowCollection(rejectedInput)).rejects.toThrow(
      /work budget/,
    );
    expect(prepareSpy).not.toHaveBeenCalled();
    expect(signSpy).not.toHaveBeenCalled();
    expect(readSpy).not.toHaveBeenCalled();
    expect(writeSpy).not.toHaveBeenCalled();
    expect(dispatchSpy).not.toHaveBeenCalled();
  });

  it("rejects maximum-size replicate expansion before materializing jobs", async () => {
    const fixture = protocolFixture();
    const prepare = vi.fn(fakePrepare);
    const dispatch = vi.fn(async (prepared: PreparedRuntimeInvocation) =>
      runtimeOutcome(prepared)
    );
    const made = await makeInput({
      fixture,
      cases: [caseInput({ replicates: 10_000 })],
      workBudget: {
        ...GENEROUS_BUDGET,
        maxReplicates: 1,
        maxLogicalExecutions: 2,
      },
      prepare,
      dispatch,
    });
    const startedAt = Date.now();
    await expect(runShadowCollection(made.input)).rejects.toThrow(
      /replicate count.*work budget/,
    );
    expect(Date.now() - startedAt).toBeLessThan(1_000);
    expect(prepare).not.toHaveBeenCalled();
    expect(dispatch).not.toHaveBeenCalled();
    await expect(readdir(made.root)).resolves.toEqual([]);
  });

  it.each([
    {
      name: "runtime build",
      mutate: (instance: RuntimeInvocationInput["instance"]) => ({
        ...instance,
        runtime: { ...instance.runtime, build: "0.26.0-drifted" },
      }),
    },
    {
      name: "backend name",
      mutate: (instance: RuntimeInvocationInput["instance"]) => ({
        ...instance,
        backend: { ...instance.backend, name: "drifted-backend" },
      }),
    },
    {
      name: "backend build",
      mutate: (instance: RuntimeInvocationInput["instance"]) => ({
        ...instance,
        backend: { ...instance.backend, build: "9.9.9" },
      }),
    },
    {
      name: "model revision",
      mutate: (instance: RuntimeInvocationInput["instance"]) => ({
        ...instance,
        model: { ...instance.model, revision: "drifted-revision" },
      }),
    },
    {
      name: "deployment configuration",
      mutate: (instance: RuntimeInvocationInput["instance"]) => ({
        ...instance,
        configurationDigest: DIGEST("9"),
      }),
    },
  ])(
    "rejects direct-library $name drift before signer, storage, or P1 contact",
    async ({ mutate }) => {
      const fixture = protocolFixture();
      const prepare = vi.fn(fakePrepare);
      const dispatch = vi.fn(async (prepared: PreparedRuntimeInvocation) =>
        runtimeOutcome(prepared)
      );
      const signSpy = vi.fn(fixture.signer.sign);
      const collectorSignSpy = vi.fn(fixture.collectorSigner.sign);
      const baseline = targets(fixture.protocol);
      const made = await makeInput({
        fixture: {
          protocol: fixture.protocol,
          signer: { ...fixture.signer, sign: signSpy },
          collectorSigner: {
            ...fixture.collectorSigner,
            sign: collectorSignSpy,
          },
        },
        profiles: baseline,
        prepare,
        dispatch,
      });
      const profiles = baseline.map((target, index) => {
        if (index !== 0) return target;
        const runtime =
          target.runtime as unknown as RuntimeInvocationInput;
        return {
          ...target,
          runtime: {
            ...runtime,
            instance: mutate(runtime.instance),
          },
        } as unknown as ShadowProfileTarget;
      });
      await expect(runShadowCollection({
        ...made.input,
        profiles,
      })).rejects.toThrow(/runtime target conflicts/);
      expect(prepare).not.toHaveBeenCalled();
      expect(dispatch).not.toHaveBeenCalled();
      expect(signSpy).not.toHaveBeenCalled();
      expect(collectorSignSpy).not.toHaveBeenCalled();
      await expect(readdir(made.root)).resolves.toEqual([]);
    },
  );

  it("binds the P0 authentication reference before any P1 effect", async () => {
    const fixture = protocolFixture();
    const withAuthentication = (reference: "tenant-a" | "tenant-b") =>
      targets(fixture.protocol).map((target) => {
        const runtime =
          target.runtime as unknown as RuntimeInvocationInput;
        const policy = parseCollectorTrustPolicy({
          ...runtime.policy,
          endpoints: runtime.policy.endpoints.map((endpoint) => ({
            ...endpoint,
            routes: endpoint.routes.map((route) => ({
              ...route,
              authenticationReferences: ["tenant-a", "tenant-b"],
            })),
          })),
          secretReferences: ["tenant-a", "tenant-b"],
        });
        return {
          ...target,
          runtime: {
            ...runtime,
            policy,
            authenticationReference: reference,
            instance: {
              ...runtime.instance,
              endpointDescriptorDigest:
                fingerprintCollectorEndpointBinding(
                  policy,
                  runtime.endpointAlias,
                  runtime.endpointDescriptor,
                ),
            },
          },
        } as unknown as ShadowProfileTarget;
      });
    const prepare = vi.fn(fakePrepare);
    const dispatch = vi.fn(async (prepared: PreparedRuntimeInvocation) =>
      runtimeOutcome(prepared)
    );
    const approvedProfiles = withAuthentication("tenant-a");
    const made = await makeInput({
      fixture,
      profiles: approvedProfiles,
      prepare,
      dispatch,
    });
    expect(made.input.plan.collectionTargets.every(
      ({ authenticationReference }) =>
        authenticationReference === "tenant-a",
    )).toBe(true);

    await expect(runShadowCollection({
      ...made.input,
      profiles: withAuthentication("tenant-b"),
    })).rejects.toThrow(/runtime target conflicts with its P0 plan/);
    expect(prepare).not.toHaveBeenCalled();
    expect(dispatch).not.toHaveBeenCalled();
    await expect(readdir(made.root)).resolves.toEqual([]);
  });

  it("rejects P1 HTTP-limit substitution before signer, storage, or P1 contact", async () => {
    const fixture = protocolFixture();
    const withResponseLimit = (maxResponseBytes: number) =>
      targets(fixture.protocol).map((target) => ({
        ...target,
        runtime: {
          ...target.runtime,
          httpLimits: { maxResponseBytes },
        },
      })) as unknown as readonly ShadowProfileTarget[];
    const approvedProfiles = withResponseLimit(4_096);
    const signSpy = vi.fn(fixture.signer.sign);
    const collectorSignSpy = vi.fn(fixture.collectorSigner.sign);
    const prepare = vi.fn(fakePrepare);
    const dispatch = vi.fn(async (prepared: PreparedRuntimeInvocation) =>
      runtimeOutcome(prepared)
    );
    const made = await makeInput({
      fixture: {
        protocol: fixture.protocol,
        signer: { ...fixture.signer, sign: signSpy },
        collectorSigner: {
          ...fixture.collectorSigner,
          sign: collectorSignSpy,
        },
      },
      profiles: approvedProfiles,
      prepare,
      dispatch,
    });
    const approvedDigest =
      fingerprintRuntimeInvocationHttpLimits({
        maxResponseBytes: 4_096,
      });
    expect(made.input.plan.collectionTargets.every(
      ({ httpLimitsDigest }) => httpLimitsDigest === approvedDigest,
    )).toBe(true);
    const accepted = await runShadowCollection(made.input);
    expect(accepted.status).toBe("complete");
    expect(accepted.traces).toHaveLength(2);
    const acceptedRootEntries = await readdir(made.root);
    expect(acceptedRootEntries.length).toBeGreaterThan(0);

    prepare.mockClear();
    dispatch.mockClear();
    signSpy.mockClear();
    collectorSignSpy.mockClear();
    const readPacket = vi.fn(async () => null);
    const writePacket = vi.fn(async () => {
      throw new Error("must not write");
    });

    await expect(runShadowCollection({
      ...made.input,
      profiles: withResponseLimit(2_048),
      hooks: {
        ...made.input.hooks,
        readPacket:
          readPacket as NonNullable<ShadowRunnerHooks["readPacket"]>,
        writePacket: writePacket as unknown as NonNullable<
          ShadowRunnerHooks["writePacket"]
        >,
      },
    })).rejects.toThrow(/P0 HTTP limits/);
    expect(prepare).not.toHaveBeenCalled();
    expect(dispatch).not.toHaveBeenCalled();
    expect(signSpy).not.toHaveBeenCalled();
    expect(collectorSignSpy).not.toHaveBeenCalled();
    expect(readPacket).not.toHaveBeenCalled();
    expect(writePacket).not.toHaveBeenCalled();
    await expect(readdir(made.root)).resolves.toEqual(acceptedRootEntries);

    const alteredProfiles = withResponseLimit(2_048);
    const altered = await makeInput({
      fixture: {
        protocol: fixture.protocol,
        signer: fixture.signer,
        collectorSigner: fixture.collectorSigner,
      },
      clock: made.clock,
      profiles: alteredProfiles,
      prepare: fakePrepare,
      dispatch: async (prepared) => runtimeOutcome(prepared),
    });
    const alteredAccepted = await runShadowCollection(altered.input);
    const alteredDigest =
      fingerprintRuntimeInvocationHttpLimits({
        maxResponseBytes: 2_048,
      });
    expect(altered.input.plan.planDigest)
      .not.toBe(made.input.plan.planDigest);
    expect(alteredAccepted.traces.map(({ traceId }) => traceId))
      .not.toEqual(accepted.traces.map(({ traceId }) => traceId));
    expect(accepted.traces.every(
      ({ collectionBinding }) =>
        collectionBinding?.httpLimitsDigest === approvedDigest,
    )).toBe(true);
    expect(alteredAccepted.traces.every(
      ({ collectionBinding }) =>
        collectionBinding?.httpLimitsDigest === alteredDigest,
    )).toBe(true);
  });

  it.each([
    {
      name: "transport",
      profiles: (protocol: ExperimentProtocol) =>
        targets(protocol, "https://runtime.example.test"),
    },
    {
      name: "collector route",
      profiles: (protocol: ExperimentProtocol) =>
        targets(protocol).map((target) => {
          const runtime =
            target.runtime as unknown as RuntimeInvocationInput;
          const policy = parseCollectorTrustPolicy({
            ...runtime.policy,
            endpoints: runtime.policy.endpoints.map((endpoint) => ({
              ...endpoint,
              routes: endpoint.routes.map((route) => ({
                ...route,
                pathPrefix: "/wrong",
              })),
            })),
          });
          return {
            ...target,
            runtime: {
              ...runtime,
              policy,
              instance: {
                ...runtime.instance,
                endpointDescriptorDigest:
                  fingerprintCollectorEndpointBinding(
                    policy,
                    runtime.endpointAlias,
                    runtime.endpointDescriptor,
                  ),
              },
            },
          } as unknown as ShadowProfileTarget;
        }),
    },
  ])(
    "rejects direct-library $name drift before P1 contact",
    async ({ profiles: buildProfiles }) => {
      const fixture = protocolFixture();
      const prepare = vi.fn(fakePrepare);
      const dispatch = vi.fn(async (prepared: PreparedRuntimeInvocation) =>
        runtimeOutcome(prepared)
      );
      const profileTargets = buildProfiles(fixture.protocol);
      const made = await makeInput({
        fixture,
        profiles: profileTargets,
        prepare,
        dispatch,
      });
      await expect(runShadowCollection(made.input)).rejects.toThrow(
        /runtime target.*(?:protocol|collector) authority|transport conflicts/,
      );
      expect(prepare).not.toHaveBeenCalled();
      expect(dispatch).not.toHaveBeenCalled();
      await expect(readdir(made.root)).resolves.toEqual([]);
    },
  );

  it.each([
    {
      name: "aggregate response bytes",
      budget: {
        ...GENEROUS_BUDGET,
        maxResponseBytes: 1,
      },
    },
    {
      name: "aggregate elapsed attempt work",
      budget: {
        ...GENEROUS_BUDGET,
        maxWallClockMs: 399,
      },
    },
  ])(
    "rejects $name before preparation, signer, filesystem, or P1 contact",
    async ({ budget }) => {
      const fixture = protocolFixture();
      const clock = testClock();
      const prepareSpy = vi.fn(fakePrepare);
      const signSpy = vi.fn(fixture.signer.sign);
      const readSpy = vi.fn(async () => null);
      const writeSpy = vi.fn(async () => {
        throw new Error("must not write");
      });
      const dispatchSpy = vi.fn(async (prepared: PreparedRuntimeInvocation) =>
        runtimeOutcome(prepared)
      );
      const made = await makeInput({
        fixture: {
          protocol: fixture.protocol,
          collectorSigner: fixture.collectorSigner,
          signer: {
            ...fixture.signer,
            sign: signSpy,
          },
        },
        clock,
        workBudget: budget,
      });
      await expect(runShadowCollection({
        ...made.input,
        hooks: {
          now: clock.now,
          prepareInvocation: prepareSpy,
          dispatchInvocation: dispatchSpy,
          readPacket:
            readSpy as NonNullable<ShadowRunnerHooks["readPacket"]>,
          writePacket: writeSpy as unknown as NonNullable<
            ShadowRunnerHooks["writePacket"]
          >,
        },
      })).rejects.toThrow(/work budget/);
      expect(prepareSpy).not.toHaveBeenCalled();
      expect(signSpy).not.toHaveBeenCalled();
      expect(readSpy).not.toHaveBeenCalled();
      expect(writeSpy).not.toHaveBeenCalled();
      expect(dispatchSpy).not.toHaveBeenCalled();
    },
  );

  it("uses deterministic HMAC identities and counterbalanced dispatch order", async () => {
    const fixture = protocolFixture({ maximumConcurrency: 2 });
    const first = await makeInput({
      fixture,
      cases: [caseInput({ replicates: 2 })],
    });
    const second = await makeInput({
      fixture,
      cases: [caseInput({ replicates: 2 })],
    });
    const differentPayloadKey = await makeInput({
      fixture,
      cases: [caseInput({ replicates: 2 })],
      identityKey: createSecretKey(Buffer.alloc(32, 0x54)),
    });
    const firstResult = await runShadowCollection(first.input);
    const secondResult = await runShadowCollection(second.input);
    const differentKeyResult = await runShadowCollection(
      differentPayloadKey.input,
    );
    expect(firstResult.dispatchOrder).toEqual(secondResult.dispatchOrder);
    expect(firstResult.traces.map(({ profileId }) => profileId))
      .toEqual(secondResult.traces.map(({ profileId }) => profileId));
    const profiles = firstResult.traces.map(({ profileId }) => profileId);
    const profileByTrace = new Map(
      firstResult.traces.map(({ traceId, profileId }) => [traceId, profileId]),
    );
    expect(firstResult.dispatchOrder.map(
      (traceId) => profileByTrace.get(traceId),
    )).toEqual(profiles);
    const differentProfileByTrace = new Map(
      differentKeyResult.traces.map(
        ({ traceId, profileId }) => [traceId, profileId],
      ),
    );
    expect(differentKeyResult.dispatchOrder.map(
      (traceId) => differentProfileByTrace.get(traceId),
    )).toEqual(profiles);
    expect(differentKeyResult.traces.map(({ profileId }) => profileId))
      .toEqual(profiles);
    expect(differentKeyResult.traces.map(({ replicateId }) => replicateId))
      .toEqual(firstResult.traces.map(({ replicateId }) => replicateId));
    expect(differentKeyResult.traces.map(({ traceId }) => traceId))
      .not.toEqual(firstResult.traces.map(({ traceId }) => traceId));
    expect(profiles.slice(0, 2).sort()).toEqual(["candidate", "champion"]);
    expect(profiles.slice(2, 4)).toEqual(
      profiles.slice(0, 2).reverse(),
    );
    expect(firstResult.traces.every(
      ({ traceId }) => /^trace-[a-f0-9]{64}$/.test(traceId),
    )).toBe(true);
    const defaultLimitsDigest =
      fingerprintRuntimeInvocationHttpLimits();
    expect(firstResult.traces.every(
      ({ collectionBinding }) =>
        collectionBinding?.httpLimitsDigest === defaultLimitsDigest,
    )).toBe(true);
  });

  it("never consults locale collation for counterbalanced P1 ordering", async () => {
    const localeCompare = vi.spyOn(
      String.prototype,
      "localeCompare",
    ).mockImplementation(() => {
      throw new Error("locale collation must not affect P1 ordering");
    });
    try {
      const made = await makeInput({
        fixture: protocolFixture({ maximumConcurrency: 2 }),
        cases: [caseInput({ replicates: 2 })],
      });
      await expect(runShadowCollection(made.input)).resolves.toMatchObject({
        status: "complete",
        logicalExecutions: 4,
      });
    } finally {
      localeCompare.mockRestore();
    }
  });

  it("rejects accepted traces from a different collector version", async () => {
    const made = await makeInput();
    await expect(runShadowCollection(made.input)).resolves.toMatchObject({
      status: "complete",
    });
    const resumed = await makeInput({
      root: made.root,
      fixture: made.fixture,
      clock: made.clock,
    });
    await expect(runShadowCollection({
      ...resumed.input,
      hooks: {
        ...resumed.input.hooks,
        readPacket: acceptedPacketReader((trace) => ({
          ...trace,
          collectorVersion: "tasc-shadow-runner-v999",
        })),
      },
    })).rejects.toThrow(/collector version/);
  });

  it("rejects accepted traces exceeding the protocol attempt ceiling", async () => {
    const fixture = protocolFixture({ maximumAttempts: 1 });
    const made = await makeInput({ fixture });
    const initial = await runShadowCollection(made.input);
    expect(initial.status).toBe("complete");
    const resumed = await makeInput({
      root: made.root,
      fixture,
      clock: made.clock,
    });
    await expect(runShadowCollection({
      ...resumed.input,
      hooks: {
        ...resumed.input.hooks,
        readPacket: acceptedPacketReader((trace) => {
          const attempts = trace.attempts as Array<Record<string, unknown>>;
          const first = attempts[0]!;
          const traceId = trace.traceId as string;
          const secondAttemptId = `attempt-${
            createStudyPayloadIdentity(
              fixture.protocol.studyId,
              resumed.input.identity.keyId,
              resumed.input.identity.key,
              canonicalJsonBytes({
                domain: "tasc/shadow-attempt-id/v1",
                value: { traceId, attemptNumber: 2 },
              }),
            ).value
          }`;
          return {
            ...trace,
            attempts: [
              {
                ...first,
                dispatchState: "not_sent",
                status: "failure",
                finishReason: null,
                partialOutput: false,
                abortLifecycle: "not-aborted",
                failureCategory: "transport",
                resolvedModel: null,
                tokenUsage: {
                  input: null,
                  output: null,
                  total: null,
                },
                providerReported: {
                  timings: [],
                  metrics: [],
                },
                cost: { kind: "unavailable" },
                payloads: {
                  ...(first.payloads as Record<string, unknown>),
                  response: null,
                  eventStream: null,
                },
                observerTimings: {
                  startedAt: (
                    first.observerTimings as Record<string, unknown>
                  ).startedAt,
                  headersAt: null,
                  firstByteAt: null,
                  firstMeaningfulTokenAt: null,
                  completedAt: (
                    first.observerTimings as Record<string, unknown>
                  ).startedAt,
                },
              },
              {
                ...first,
                attemptId: secondAttemptId,
                attemptNumber: 2,
              },
            ],
          };
        }),
      },
    })).rejects.toThrow(/maximum attempts/);
  });

  it("still authenticates accepted outcomes after semantic resume checks", async () => {
    const made = await makeInput();
    await expect(runShadowCollection(made.input)).resolves.toMatchObject({
      status: "complete",
    });
    const resumed = await makeInput({
      root: made.root,
      fixture: made.fixture,
      clock: made.clock,
    });
    await expect(runShadowCollection({
      ...resumed.input,
      hooks: {
        ...resumed.input.hooks,
        readPacket: acceptedPacketReader((trace) => {
          const attempts = trace.attempts as Array<Record<string, unknown>>;
          const first = attempts[0]!;
          const tokenUsage = first.tokenUsage as Record<string, unknown>;
          const input = tokenUsage.input as Record<string, unknown>;
          return {
            ...trace,
            attempts: [{
              ...first,
              tokenUsage: {
                ...tokenUsage,
                input: {
                  ...input,
                  value: (input.value as number) + 1,
                },
              },
            }],
          };
        }),
      },
    })).rejects.toThrow(/collector-attestation signature/);
  });

  it("binds replicate and trace identities to the collection window", async () => {
    const fixture = protocolFixture();
    const first = await makeInput({
      fixture,
      collectionWindowId: "window-one",
    });
    const second = await makeInput({
      fixture,
      collectionWindowId: "window-two",
    });
    const firstResult = await runShadowCollection(first.input);
    const secondResult = await runShadowCollection(second.input);
    expect(new Set(firstResult.traces.map(({ replicateId }) => replicateId)))
      .not.toEqual(
        new Set(secondResult.traces.map(({ replicateId }) => replicateId)),
      );
    expect(new Set(firstResult.traces.map(({ traceId }) => traceId)))
      .not.toEqual(
        new Set(secondResult.traces.map(({ traceId }) => traceId)),
      );
  });

  it("uses immutable dispatch snapshots after caller targets are mutated", async () => {
    const fixture = protocolFixture();
    const profileTargets = targets(fixture.protocol).map((target) => ({
      ...target,
      runtime: {
        ...target.runtime,
        instance: {
          ...target.runtime.instance,
          runtime: { ...target.runtime.instance.runtime },
          backend: { ...target.runtime.instance.backend },
          model: { ...target.runtime.instance.model },
        },
        httpLimits: {
          maxRequestBytes: 1_048_576,
          maxResponseHeaderBytes: 16_384,
          maxResponseHeaders: 64,
          maxResponseBytes: 4_096,
          maxResponseChunks: 4_096,
          maxSecretHeaderBytes: 8_192,
          connectTimeoutMs: 5_000,
          headersTimeoutMs: 10_000,
          bodyTimeoutMs: 10_000,
          deadlineMs: 30_000,
        },
      },
    })) as unknown as ShadowProfileTarget[];
    const observed: RuntimeInvocationInput[] = [];
    const prepare = vi.fn((input: RuntimeInvocationInput) => {
      observed.push(input);
      return fakePrepare(input);
    });
    let mutated = false;
    const signer: ShadowRunInput["dispatchIntentSigner"] = {
      ...fixture.signer,
      sign: (bytes) => {
        if (!mutated) {
          mutated = true;
          const first = profileTargets[0] as unknown as {
            runtime: {
              endpointAlias: string;
              instance: {
                runtime: { build: string };
                configurationDigest: string;
              };
              httpLimits: { maxResponseBytes: number };
            };
          };
          first.runtime.endpointAlias = "mutated-endpoint";
          first.runtime.instance.runtime.build = "mutated-build";
          first.runtime.instance.configurationDigest = DIGEST("9");
          first.runtime.httpLimits.maxResponseBytes = 1;
        }
        return fixture.signer.sign(bytes);
      },
    };
    const made = await makeInput({
      fixture: {
        protocol: fixture.protocol,
        signer,
        collectorSigner: fixture.collectorSigner,
      },
      profiles: profileTargets,
      prepare,
    });
    const result = await runShadowCollection(made.input);
    expect(result.status).toBe("complete");
    expect(observed).toHaveLength(2);
    expect(observed.every(
      ({ endpointAlias }) => endpointAlias !== "mutated-endpoint",
    )).toBe(true);
    expect(observed.every(
      ({ instance }) => instance.runtime.build !== "mutated-build",
    )).toBe(true);
    expect(observed.every(
      ({ httpLimits }) => httpLimits?.maxResponseBytes === 4_096,
    )).toBe(true);
  });

  it("bounds global concurrency while serializing replicates in each profile lane", async () => {
    const fixture = protocolFixture({ maximumConcurrency: 2 });
    let active = 0;
    let maximumActive = 0;
    const activeRequests = new Set<string>();
    const activeLanes = new Set<string>();
    const dispatch = vi.fn(async (prepared: PreparedRuntimeInvocation) => {
      active += 1;
      maximumActive = Math.max(maximumActive, active);
      const request = prepared.requestIdentity.value;
      const lane =
        `${prepared.profile.id}\u0000${prepared.endpointBindingDigest}`;
      expect(activeRequests.has(request)).toBe(false);
      expect(activeLanes.has(lane)).toBe(false);
      activeRequests.add(request);
      activeLanes.add(lane);
      await new Promise((resolve) => setTimeout(resolve, 5));
      activeRequests.delete(request);
      activeLanes.delete(lane);
      active -= 1;
      return runtimeOutcome(prepared);
    });
    const made = await makeInput({
      fixture,
      cases: [
        caseInput({ caseId: "case-one", replicates: 2, prompt: "one" }),
        caseInput({ caseId: "case-two", replicates: 2, prompt: "two" }),
      ],
      dispatch,
    });
    const result = await runShadowCollection(made.input);
    expect(result.status).toBe("complete");
    expect(maximumActive).toBe(2);
    expect(dispatch).toHaveBeenCalledTimes(8);
  });

  it("actively bounds hung P1 dispatches as sent_unknown", async () => {
    const fixture = protocolFixture({
      maximumAttempts: 1,
      maximumConcurrency: 2,
      attemptTimeoutMs: 50,
    });
    const dispatch = vi.fn(
      async (_prepared: PreparedRuntimeInvocation) =>
        new Promise<RuntimeInvocationOutcome>(() => {}),
    );
    const made = await makeInput({ fixture, dispatch });
    const startedAt = Date.now();
    const result = await runShadowCollection(made.input);

    expect(Date.now() - startedAt).toBeLessThan(1_000);
    expect(result.status).toBe("complete");
    expect(result.networkCalls).toBe(2);
    expect(result.sentUnknown).toBe(2);
    expect(result.traces).toHaveLength(2);
    expect(result.traces.every(({ attempts }) =>
      attempts.length === 1
      && attempts[0]?.status === "aborted"
      && attempts[0]?.dispatchState === "sent_unknown"
      && attempts[0]?.abortLifecycle === "abort-ambiguous"
      && attempts[0]?.failureCategory === "timeout"
    )).toBe(true);
    expect(dispatch).toHaveBeenCalledTimes(2);
  });

  it("starts no P1 work after the global deadline", async () => {
    const fixture = protocolFixture({
      maximumAttempts: 1,
      maximumConcurrency: 1,
      attemptTimeoutMs: 50,
    });
    const dispatch = vi.fn(
      async (_prepared: PreparedRuntimeInvocation) =>
        new Promise<RuntimeInvocationOutcome>(() => {}),
    );
    const made = await makeInput({
      fixture,
      dispatch,
      workBudget: {
        ...GENEROUS_BUDGET,
        maxWallClockMs: 100,
      },
    });
    const startedAt = Date.now();
    const result = await runShadowCollection(made.input);
    expect(Date.now() - startedAt).toBeLessThan(1_000);
    expect(result.status).toBe("cancelled");
    expect(result.networkCalls).toBeLessThanOrEqual(1);
    expect(dispatch).toHaveBeenCalledTimes(result.networkCalls);
    if (result.networkCalls === 0) {
      expect(result.pendingTraceIds).toHaveLength(2);
      expect(result.sentUnknown).toBe(0);
      expect(result.traces).toHaveLength(0);
    } else {
      expect(result.pendingTraceIds).toHaveLength(1);
      expect(result.sentUnknown).toBe(1);
      expect(result.traces[0]?.attempts[0]).toMatchObject({
        status: "aborted",
        dispatchState: "sent_unknown",
        abortLifecycle: "abort-ambiguous",
        failureCategory: "timeout",
      });
    }
  });

  it("aborts active P1 work when another lane fails fatally", async () => {
    const fixture = protocolFixture({
      maximumAttempts: 1,
      maximumConcurrency: 2,
      attemptTimeoutMs: 1_000,
    });
    let calls = 0;
    const dispatch = vi.fn(async (prepared: PreparedRuntimeInvocation) => {
      calls += 1;
      if (calls === 1) {
        return new Promise<RuntimeInvocationOutcome>(() => {});
      }
      return runtimeOutcome(prepared);
    });
    const made = await makeInput({
      fixture,
      dispatch,
      checkpoint: (point) => {
        if (point === "after-dispatch") {
          throw new Error("fatal-checkpoint");
        }
      },
    });
    await expect(runShadowCollection(made.input)).rejects.toThrow(
      "fatal-checkpoint",
    );
    expect(dispatch).toHaveBeenCalledTimes(2);
  });

  it("dispatches every declared lane in its counterbalanced job order", async () => {
    const fixture = protocolFixture({ maximumConcurrency: 1 });
    const made = await makeInput({
      fixture,
      cases: [caseInput({ replicates: 4 })],
    });
    const result = await runShadowCollection(made.input);
    const profileByTrace = new Map(
      result.traces.map(({ traceId, profileId }) => [traceId, profileId]),
    );
    const dispatchedProfiles = result.dispatchOrder.map(
      (traceId) => profileByTrace.get(traceId),
    );
    expect(dispatchedProfiles).toHaveLength(8);
    expect(dispatchedProfiles).toEqual(
      result.traces.map(({ profileId }) => profileId),
    );
    expect(dispatchedProfiles.filter((profile) => profile === "champion"))
      .toHaveLength(4);
    expect(dispatchedProfiles.filter((profile) => profile === "candidate"))
      .toHaveLength(4);
  });

  it("dispatches the exact one-shot prepared authority that acquired the lease", async () => {
    const made = await makeInput();
    const minted = new WeakSet<object>();
    const prepare = vi.fn((input: RuntimeInvocationInput) => {
      const prepared = fakePrepare(input);
      minted.add(prepared);
      return prepared;
    });
    const dispatch = vi.fn(async (prepared: PreparedRuntimeInvocation) => {
      expect(minted.has(prepared)).toBe(true);
      return runtimeOutcome(prepared);
    });
    const input: ShadowRunInput & {
      readonly hooks: ShadowRunnerHooks;
    } = {
      ...made.input,
      hooks: {
        now: made.clock.now,
        prepareInvocation: prepare,
        dispatchInvocation: dispatch,
      },
    };
    const result = await runShadowCollection(input);
    expect(result.status).toBe("complete");
    expect(dispatch).toHaveBeenCalledTimes(2);
  });

  it("retries only provable not_sent outcomes and respects the exact attempt cap", async () => {
    const fixture = protocolFixture({ maximumAttempts: 2 });
    const counts = new Map<string, number>();
    const dispatch = vi.fn(async (prepared: PreparedRuntimeInvocation) => {
      const model = prepared.requestedModel.id;
      const count = (counts.get(model) ?? 0) + 1;
      counts.set(model, count);
      return count === 1
        ? runtimeOutcome(prepared, {
          status: "failed",
          resolvedModel: null,
          responseIdentity: null,
          eventStreamIdentity: null,
          terminalOutputIdentity: null,
          finishReason: null,
          providerUsage: null,
          providerTiming: {},
          finalUsage: "missing",
          partialOutput: false,
          dispatchState: "not_sent",
          wireTiming: null,
          streamTiming: null,
          error: {
            version: "tasc-persisted-error-v1",
            category: "transport",
            message: "Inference transport failed.",
            status: null,
            runtime: null,
            requestId: null,
          },
        })
        : runtimeOutcome(prepared);
    });
    const made = await makeInput({ fixture, dispatch });
    const result = await runShadowCollection(made.input);
    expect(result.networkCalls).toBe(4);
    expect(result.traces.every(({ attempts }) => attempts.length === 2))
      .toBe(true);
    expect(result.traces.every(
      ({ attempts }) => attempts[0]?.dispatchState === "not_sent",
    )).toBe(true);
    expect(result.traces.every(
      ({ attempts }) => attempts[1]?.status === "success",
    )).toBe(true);
  });

  it.each([
    "authentication",
    "authorization",
    "rate-limit",
    "invalid-response",
    "internal",
  ] as const)(
    "does not retry a provably not_sent %s failure",
    async (category) => {
      const fixture = protocolFixture({ maximumAttempts: 2 });
      const dispatch = vi.fn(async (prepared: PreparedRuntimeInvocation) =>
        runtimeOutcome(prepared, {
          status: "failed",
          resolvedModel: null,
          responseIdentity: null,
          eventStreamIdentity: null,
          terminalOutputIdentity: null,
          finishReason: null,
          providerUsage: null,
          providerTiming: {},
          finalUsage: "missing",
          partialOutput: false,
          dispatchState: "not_sent",
          wireTiming: null,
          streamTiming: null,
          error: {
            version: "tasc-persisted-error-v1",
            category,
            message: "Inference request failed.",
            status: null,
            runtime: null,
            requestId: null,
          },
        })
      );
      const made = await makeInput({ fixture, dispatch });
      const result = await runShadowCollection(made.input);
      expect(dispatch).toHaveBeenCalledTimes(2);
      expect(result.traces.every(
        ({ attempts }) =>
          attempts.length === 1
          && attempts[0]?.dispatchState === "not_sent"
          && attempts[0]?.failureCategory === category,
      )).toBe(true);
    },
  );

  it("records a post-preflight prepare rejection as provably not_sent", async () => {
    const fixture = protocolFixture({ maximumAttempts: 2 });
    const made = await makeInput({ fixture });
    let calls = 0;
    const prepare = vi.fn((input: RuntimeInvocationInput) => {
      calls += 1;
      // Exact admission is description-only; reject the first live attempt,
      // then let its retry and the other profile proceed.
      if (calls === 1) {
        throw new RuntimeInvocationInputError(
          "PREPARED_INVOCATION_EXPIRED",
        );
      }
      return fakePrepare(input);
    });
    const dispatch = vi.fn(async (prepared: PreparedRuntimeInvocation) =>
      runtimeOutcome(prepared)
    );
    const input: ShadowRunInput & {
      readonly hooks: ShadowRunnerHooks;
    } = {
      ...made.input,
      hooks: {
        now: made.clock.now,
        prepareInvocation: prepare,
        dispatchInvocation: dispatch,
      },
    };
    const result = await runShadowCollection(input);
    expect(result.status).toBe("complete");
    expect(result.traces.some(
      ({ attempts }) =>
        attempts.length === 2
        && attempts[0]?.dispatchState === "not_sent"
        && attempts[0]?.failureCategory === "timeout",
    )).toBe(true);
    expect(dispatch).toHaveBeenCalledTimes(2);
  });

  it("treats authorization prepare codes as terminal even when not_sent", async () => {
    const fixture = protocolFixture({ maximumAttempts: 2 });
    let calls = 0;
    const prepare = vi.fn((input: RuntimeInvocationInput) => {
      calls += 1;
      if (calls === 1) {
        throw new RuntimeInvocationInputError(
          "PREPARED_INVOCATION_REJECTED",
        );
      }
      return fakePrepare(input);
    });
    const dispatch = vi.fn(async (prepared: PreparedRuntimeInvocation) =>
      runtimeOutcome(prepared)
    );
    const made = await makeInput({ fixture, prepare, dispatch });
    const result = await runShadowCollection(made.input);
    expect(result.traces.some(
      ({ attempts }) =>
        attempts.length === 1
        && attempts[0]?.dispatchState === "not_sent"
        && attempts[0]?.failureCategory === "authorization",
    )).toBe(true);
    expect(dispatch).toHaveBeenCalledTimes(1);
  });

  it("does not retry an ambiguous thrown dispatch", async () => {
    const fixture = protocolFixture({ maximumAttempts: 2 });
    const dispatch = vi.fn(async () => {
      throw new Error("provider detail must not persist");
    });
    const made = await makeInput({ fixture, dispatch });
    const result = await runShadowCollection(made.input);
    expect(dispatch).toHaveBeenCalledTimes(2);
    expect(result.sentUnknown).toBe(2);
    expect(result.traces.every(
      ({ attempts }) =>
        attempts.length === 1
        && attempts[0]?.dispatchState === "sent_unknown",
    )).toBe(true);
    expect(await allFileText(made.root)).not.toContain("provider detail");
  });

  it.each([
    "extra-raw-field",
    "accessor",
    "proxy",
    "wrong-payload-key",
  ] as const)(
    "normalizes a malicious %s runtime outcome before immutable write",
    async (variant) => {
      let getterCalls = 0;
      let dispatchCalls = 0;
      const dispatch = vi.fn(async (prepared: PreparedRuntimeInvocation) => {
        dispatchCalls += 1;
        if (dispatchCalls !== 1) return runtimeOutcome(prepared);
        const durable = persistence(prepared);
        let hostilePersistence: unknown;
        switch (variant) {
          case "extra-raw-field":
            hostilePersistence = {
              ...durable,
              rawResponse: "raw-secret-must-never-persist",
            };
            break;
          case "accessor": {
            const accessor: Record<string, unknown> = {};
            for (const [key, value] of Object.entries(durable)) {
              if (key === "error") continue;
              Object.defineProperty(accessor, key, {
                value,
                enumerable: true,
                configurable: false,
                writable: false,
              });
            }
            Object.defineProperty(accessor, "error", {
              enumerable: true,
              configurable: false,
              get: () => {
                getterCalls += 1;
                throw new Error("raw-accessor-secret");
              },
            });
            hostilePersistence = accessor;
            break;
          }
          case "proxy":
            hostilePersistence = new Proxy(durable, {
              get: () => {
                throw new Error("raw-proxy-secret");
              },
            });
            break;
          case "wrong-payload-key":
            hostilePersistence = {
              ...durable,
              responseIdentity: {
                ...durable.responseIdentity!,
                keyId: "foreign-payload-key",
              },
            };
            break;
        }
        return {
          schemaVersion: "tasc-runtime-invocation-v1",
          status: durable.status,
          output: {
            text: "raw-output-secret",
            metadata: {
              choiceCount: 1,
              logprobsObserved: false,
            },
          },
          persistence: hostilePersistence,
        } as unknown as RuntimeInvocationOutcome;
      });
      const made = await makeInput({ dispatch });
      const result = await runShadowCollection(made.input);
      expect(result.status).toBe("complete");
      expect(result.sentUnknown).toBe(1);
      expect(getterCalls).toBe(0);

      const resumeDispatch = vi.fn(
        async (prepared: PreparedRuntimeInvocation) =>
          runtimeOutcome(prepared),
      );
      const resumed = await makeInput({
        root: made.root,
        fixture: made.fixture,
        clock: made.clock,
        dispatch: resumeDispatch,
      });
      const resumedResult = await runShadowCollection(resumed.input);
      expect(resumedResult.status).toBe("complete");
      expect(resumeDispatch).not.toHaveBeenCalled();
      const durableText = await allFileText(made.root);
      expect(durableText).not.toContain("raw-secret");
      expect(durableText).not.toContain("raw-output-secret");
      expect(durableText).not.toContain("foreign-payload-key");
    },
  );

  it("resumes an expired lease as sent_unknown without redispatch", async () => {
    const fixture = protocolFixture({
      maximumConcurrency: 1,
      attemptTimeoutMs: 100,
    });
    const clock = testClock();
    let crashed = false;
    const first = await makeInput({
      fixture,
      clock,
      checkpoint: (point) => {
        if (!crashed && point === "after-lease") {
          crashed = true;
          throw new Error("simulated crash");
        }
      },
    });
    await expect(runShadowCollection(first.input)).rejects.toThrow(
      "simulated crash",
    );

    const dispatch = vi.fn(async (prepared: PreparedRuntimeInvocation) =>
      runtimeOutcome(prepared)
    );
    const immediate = await makeInput({
      root: first.root,
      fixture,
      clock,
      dispatch,
    });
    const pending = await runShadowCollection(immediate.input);
    expect(pending.status).toBe("partial");
    expect(pending.pendingTraceIds).toHaveLength(1);

    clock.advance(101);
    const recoveredInput = await makeInput({
      root: first.root,
      fixture,
      clock,
      dispatch,
      plan: first.input.plan,
    });
    const callsBeforeRecovery = dispatch.mock.calls.length;
    const recovered = await runShadowCollection(recoveredInput.input);
    expect(recovered.status).toBe("complete");
    expect(recovered.sentUnknown).toBe(1);
    expect(dispatch.mock.calls.length).toBe(callsBeforeRecovery);
  });

  it.each([
    {
      boundary: "whole-run deadline",
      expiresAt: undefined,
      maxWallClockMs: 2_000,
    },
    {
      boundary: "protocol expiry",
      expiresAt: "2026-07-25T12:00:02.000Z",
      maxWallClockMs: 2_000,
    },
  ])(
    "clamps live P1 deadlines and rejects completion at the $boundary",
    async ({ expiresAt, maxWallClockMs }) => {
      const fixture = protocolFixture({
        maximumAttempts: 1,
        maximumConcurrency: 1,
        attemptTimeoutMs: 1_000,
        ...(expiresAt === undefined ? {} : { expiresAt }),
      });
      const clock = testClock();
      const preparedInputs: RuntimeInvocationInput[] = [];
      const prepare = vi.fn((input: RuntimeInvocationInput) => {
        preparedInputs.push(input);
        return fakePrepare(input);
      });
      let calls = 0;
      const dispatch = vi.fn(async (prepared: PreparedRuntimeInvocation) => {
        calls += 1;
        if (calls === 1) {
          clock.advance(1_200);
          return runtimeOutcome(prepared);
        }
        return runtimeOutcome(prepared, {
          wireTiming: {
            startedAt: clock.now().toISOString(),
            headersMs: 2,
            firstByteMs: 3,
            completedMs: 800,
          },
        });
      });
      const made = await makeInput({
        fixture,
        clock,
        prepare,
        dispatch,
        workBudget: {
          ...GENEROUS_BUDGET,
          maxWallClockMs,
        },
      });
      const execution = runShadowCollection(made.input);
      if (expiresAt !== undefined) {
        await expect(execution).rejects.toThrow(
          /completed outside protocol validity/,
        );
        expect(preparedInputs.map(({ totalDeadlineMs }) => totalDeadlineMs))
          .toEqual([1_000, 800]);
        expect(preparedInputs.map(
          ({ httpLimits }) => httpLimits?.deadlineMs,
        )).toEqual([1_000, 800]);
        return;
      }
      const result = await execution;
      expect(result.status).toBe("complete");
      expect(preparedInputs.map(({ totalDeadlineMs }) => totalDeadlineMs))
        .toEqual([1_000, 800]);
      expect(preparedInputs.map(
        ({ httpLimits }) => httpLimits?.deadlineMs,
      )).toEqual([1_000, 800]);
      expect(new Set(preparedInputs.map(
        ({ httpLimits }) => httpLimits?.maxResponseBytes,
      ))).toEqual(new Set([8_388_608]));
      expect(result.traces.every(
        ({ attempts, terminalOutputId }) =>
          attempts.length === 1
          && attempts[0]?.status !== "success"
          && attempts[0]?.failureCategory === "timeout"
          && terminalOutputId === null,
      )).toBe(true);
      expect(await allFileText(made.root)).toContain(
        "2026-07-25T12:00:02.000Z",
      );
    },
  );

  it("anchors wire offsets to wire start while lease issuance starts the attempt", async () => {
    const clock = testClock();
    const dispatch = vi.fn(async (prepared: PreparedRuntimeInvocation) =>
      runtimeOutcome(prepared, {
        wireTiming: {
          startedAt: "2026-07-25T12:00:00.005Z",
          headersMs: 2,
          firstByteMs: 3,
          completedMs: 10,
        },
      })
    );
    const made = await makeInput({ clock, dispatch });
    const result = await runShadowCollection(made.input);
    for (const trace of result.traces) {
      expect(trace.attempts[0]?.observerTimings).toEqual({
        startedAt: "2026-07-25T12:00:00.000Z",
        headersAt: "2026-07-25T12:00:00.007Z",
        firstByteAt: "2026-07-25T12:00:00.008Z",
        firstMeaningfulTokenAt: "2026-07-25T12:00:00.009Z",
        completedAt: "2026-07-25T12:00:00.015Z",
      });
    }
  });

  it("keeps durable sent_unknown dominant over a late provider result", async () => {
    const fixture = protocolFixture({
      maximumConcurrency: 1,
      attemptTimeoutMs: 100,
    });
    const clock = testClock();
    let releaseLate!: (outcome: RuntimeInvocationOutcome) => void;
    let announceDispatch!: () => void;
    const dispatched = new Promise<void>((resolve) => {
      announceDispatch = resolve;
    });
    const late = new Promise<RuntimeInvocationOutcome>((resolve) => {
      releaseLate = resolve;
    });
    let latePrepared: PreparedRuntimeInvocation | null = null;
    const firstDispatch = vi.fn(async (prepared: PreparedRuntimeInvocation) => {
      if (latePrepared === null) {
        latePrepared = prepared;
        announceDispatch();
        return late;
      }
      return runtimeOutcome(prepared, {
        wireTiming: {
          startedAt: clock.now().toISOString(),
          headersMs: 2,
          firstByteMs: 3,
          completedMs: 10,
        },
      });
    });
    const first = await makeInput({
      fixture,
      clock,
      dispatch: firstDispatch,
    });
    const originalRun = runShadowCollection(first.input);
    await dispatched;

    clock.advance(101);
    const recovery = await makeInput({
      root: first.root,
      fixture,
      clock,
      plan: first.input.plan,
    });
    const recovered = await runShadowCollection(recovery.input);
    expect(recovered.sentUnknown).toBe(1);

    releaseLate(runtimeOutcome(latePrepared!));
    const original = await originalRun;
    expect(original.sentUnknown).toBe(1);
    const finalInput = await makeInput({
      root: first.root,
      fixture,
      clock,
      plan: first.input.plan,
    });
    const final = await runShadowCollection(finalInput.input);
    expect(final.sentUnknown).toBe(1);
    expect(final.deduplicated).toBe(2);
  });

  it("rejects a forged resume outcome before collector attestation", async () => {
    const fixture = protocolFixture({
      maximumAttempts: 1,
      maximumConcurrency: 1,
    });
    const clock = testClock();
    const collectorSign = vi.fn(fixture.collectorSigner.sign);
    let crashedTraceId: string | null = null;
    const victim = await makeInput({
      fixture: {
        protocol: fixture.protocol,
        signer: fixture.signer,
        collectorSigner: {
          ...fixture.collectorSigner,
          sign: collectorSign,
        },
      },
      clock,
      checkpoint: (point, context) => {
        if (point === "after-lease" && crashedTraceId === null) {
          crashedTraceId = context.traceId;
          throw new Error("crash-after-lease");
        }
      },
    });
    await expect(runShadowCollection(victim.input)).rejects.toThrow(
      "crash-after-lease",
    );
    expect(crashedTraceId).not.toBeNull();
    expect(collectorSign).not.toHaveBeenCalled();

    const donor = await makeInput({
      fixture,
      clock,
      plan: victim.input.plan,
    });
    await expect(runShadowCollection(donor.input)).resolves.toMatchObject({
      status: "complete",
    });
    const outcomeTarget =
      `shadow-${crashedTraceId!.slice("trace-".length)}-a1-outcome`;
    const donorPacket = await readArtifactPacketIfPresent(
      donor.root,
      outcomeTarget,
    );
    expect(donorPacket).not.toBeNull();
    const payload = donorPacket!.files[0]!;
    const envelope = JSON.parse(
      Buffer.from(payload.copyBytes()).toString("utf8"),
    ) as {
      version: string;
      record: {
        version: string;
        traceId: string;
        attempt: Record<string, unknown>;
        terminalOutputId: Record<string, unknown> | null;
      };
      authentication: {
        algorithm: string;
        keyId: string;
        value: string;
      };
    };
    const attemptPayloads =
      envelope.record.attempt.payloads as Record<string, unknown>;
    const forgedIdentity = {
      algorithm: "hmac-sha256",
      keyId: victim.input.identity.keyId,
      value: "f".repeat(64),
    };
    const forgedEnvelope = {
      ...envelope,
      record: {
        ...envelope.record,
        attempt: {
          ...envelope.record.attempt,
          payloads: {
            ...attemptPayloads,
            response: forgedIdentity,
            eventStream: forgedIdentity,
          },
        },
        terminalOutputId: forgedIdentity,
      },
      authentication: {
        ...envelope.authentication,
        value: "0".repeat(64),
      },
    };
    await writeArtifactPacketOrVerifyIdentical(
      victim.root,
      outcomeTarget,
      {
        descriptor: donorPacket!.manifest.descriptor,
        files: [{
          name: payload.name,
          bytes: canonicalJsonBytes(forgedEnvelope),
          mediaType: payload.mediaType,
          schemaVersion: payload.schemaVersion,
        }],
      },
    );

    const resumeDispatch = vi.fn(
      async (prepared: PreparedRuntimeInvocation) => runtimeOutcome(prepared),
    );
    const resumed = await makeInput({
      root: victim.root,
      fixture: {
        protocol: fixture.protocol,
        signer: fixture.signer,
        collectorSigner: {
          ...fixture.collectorSigner,
          sign: collectorSign,
        },
      },
      clock,
      plan: victim.input.plan,
      dispatch: resumeDispatch,
    });
    await expect(runShadowCollection(resumed.input)).rejects.toThrow(
      /resume record authentication/,
    );
    expect(resumeDispatch).not.toHaveBeenCalled();
    expect(collectorSign).not.toHaveBeenCalled();
  });

  it.each([
    "after-intent",
    "after-outcome",
    "after-accepted",
    "after-complete",
  ] as const)(
    "resumes crash cutpoint %s without duplicating P1 dispatch",
    async (cutpoint) => {
      const fixture = protocolFixture({ maximumConcurrency: 1 });
      const clock = testClock();
      let crashed = false;
      let crashedModel: string | null = null;
      const calls = new Map<string, number>();
      const dispatch = vi.fn(async (prepared: PreparedRuntimeInvocation) => {
        const model = prepared.requestedModel.id;
        calls.set(model, (calls.get(model) ?? 0) + 1);
        return runtimeOutcome(prepared);
      });
      const first = await makeInput({
        fixture,
        clock,
        dispatch,
        checkpoint: (point, context) => {
          if (!crashed && point === cutpoint) {
            crashed = true;
            crashedModel = context.traceId;
            throw new Error(`crash-${cutpoint}`);
          }
        },
      });
      await expect(runShadowCollection(first.input)).rejects.toThrow(
        `crash-${cutpoint}`,
      );
      const callsAfterCrash = new Map(calls);
      const resumedInput = await makeInput({
        root: first.root,
        fixture,
        clock,
        dispatch,
      });
      const resumed = await runShadowCollection(resumedInput.input);
      expect(resumed.status).toBe("complete");
      expect(resumed.traces.some(({ traceId }) => traceId === crashedModel))
        .toBe(true);
      const duplicated = [...callsAfterCrash].some(
        ([model, count]) => (calls.get(model) ?? 0) > count + 1,
      );
      expect(duplicated).toBe(false);
    },
  );

  it("recovers a crash after P1 dispatch without dispatching that trace again", async () => {
    const fixture = protocolFixture({
      maximumConcurrency: 1,
      attemptTimeoutMs: 100,
    });
    const clock = testClock();
    const calls = new Map<string, number>();
    let crashed = false;
    let crashedModel: string | null = null;
    const dispatch = vi.fn(async (prepared: PreparedRuntimeInvocation) => {
      const model = prepared.requestedModel.id;
      calls.set(model, (calls.get(model) ?? 0) + 1);
      return runtimeOutcome(prepared);
    });
    const first = await makeInput({
      fixture,
      clock,
      dispatch,
      checkpoint: (point) => {
        if (!crashed && point === "after-dispatch") {
          crashed = true;
          crashedModel = [...calls.keys()][0] ?? null;
          throw new Error("crash-after-dispatch");
        }
      },
    });
    await expect(runShadowCollection(first.input)).rejects.toThrow(
      "crash-after-dispatch",
    );
    expect(crashedModel).not.toBeNull();
    expect(calls.get(crashedModel!)).toBe(1);

    const immediate = await makeInput({
      root: first.root,
      fixture,
      clock,
      dispatch,
    });
    const partial = await runShadowCollection(immediate.input);
    expect(partial.status).toBe("partial");
    expect(calls.get(crashedModel!)).toBe(1);

    clock.advance(101);
    const resumed = await makeInput({
      root: first.root,
      fixture,
      clock,
      dispatch,
      plan: first.input.plan,
    });
    const recovered = await runShadowCollection(resumed.input);
    expect(recovered.status).toBe("complete");
    expect(recovered.sentUnknown).toBe(1);
    expect(calls.get(crashedModel!)).toBe(1);
  });

  it("allows two fresh runners to acquire each P1 send lease exactly once", async () => {
    const fixture = protocolFixture({ maximumConcurrency: 2 });
    const root = await temporaryRoot();
    const clock = testClock();
    let release!: () => void;
    let announceTwo!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const twoDispatched = new Promise<void>((resolve) => {
      announceTwo = resolve;
    });
    const calls = new Map<string, number>();
    const dispatch = vi.fn(async (prepared: PreparedRuntimeInvocation) => {
      const model = prepared.requestedModel.id;
      calls.set(model, (calls.get(model) ?? 0) + 1);
      if ([...calls.values()].reduce((sum, value) => sum + value, 0) >= 2) {
        announceTwo();
      }
      await gate;
      return runtimeOutcome(prepared);
    });
    const first = await makeInput({ root, fixture, clock, dispatch });
    const second = await makeInput({ root, fixture, clock, dispatch });
    const firstRun = runShadowCollection(first.input);
    const secondRun = runShadowCollection(second.input);
    await Promise.race([
      twoDispatched,
      new Promise<never>((_resolve, reject) => {
        setTimeout(
          () => reject(new Error("concurrent runners did not dispatch")),
          2_000,
        );
      }),
    ]);
    release();
    await Promise.all([firstRun, secondRun]);
    expect(dispatch).toHaveBeenCalledTimes(2);
    expect([...calls.values()]).toEqual([1, 1]);

    const resumeDispatch = vi.fn(
      async (prepared: PreparedRuntimeInvocation) => runtimeOutcome(prepared),
    );
    const finalInput = await makeInput({
      root,
      fixture,
      clock,
      dispatch: resumeDispatch,
    });
    const final = await runShadowCollection(finalInput.input);
    expect(final.status).toBe("complete");
    expect(final.deduplicated).toBe(2);
    expect(resumeDispatch).not.toHaveBeenCalled();
  });

  it("preserves incomplete, provider-id-only, partial, and token provenance truth", async () => {
    const dispatch = vi.fn(async (prepared: PreparedRuntimeInvocation) =>
      runtimeOutcome(prepared, {
        status: "incomplete",
        resolvedModel: {
          id: prepared.requestedModel.id,
          revision: null,
          verification: "provider-reported",
        },
        terminalOutputIdentity: null,
        finishReason: null,
        providerUsage: {
          inputTokens: 8,
          outputTokens: null,
          totalTokens: 8,
        },
        finalUsage: "missing",
        partialOutput: true,
        dispatchState: "completed",
        error: {
          version: "tasc-persisted-error-v1",
          category: "invalid-response",
          message: "Inference runtime returned an invalid response.",
          status: null,
          runtime: null,
          requestId: null,
        },
      })
    );
    const made = await makeInput({ dispatch });
    const result = await runShadowCollection(made.input);
    for (const trace of result.traces) {
      const attempt = trace.attempts[0]!;
      expect(attempt.status).toBe("failure");
      expect(attempt.failureCategory).toBe("incomplete-response");
      expect(attempt.partialOutput).toBe(true);
      expect(attempt.resolvedModel).toEqual({
        id: attempt.requestedModel.id,
        revision: null,
        source: "provider-id-only",
      });
      expect(attempt.tokenUsage.input).toMatchObject({
        value: 8,
        source: "provider-reported",
      });
      expect(attempt.tokenUsage.output).toBeNull();
      expect(trace.terminalOutputId).toBeNull();
    }
  });

  it("uses authentic prepare and dispatch authorities for live local inference", async () => {
    let contacts = 0;
    const sockets = new Set<Socket>();
    const server = createServer((request, response) => {
      contacts += 1;
      const chunks: Buffer[] = [];
      request.on("data", (chunk) => chunks.push(Buffer.from(chunk)));
      request.on("end", () => {
        const body = JSON.parse(Buffer.concat(chunks).toString("utf8")) as {
          model: string;
        };
        response.statusCode = 200;
        response.setHeader("content-type", "application/json");
        response.end(JSON.stringify({
          model: body.model,
          choices: [{
            index: 0,
            text: "live-local-output",
            finish_reason: "stop",
          }],
          usage: {
            prompt_tokens: 8,
            completion_tokens: 1,
            total_tokens: 9,
          },
        }));
      });
    });
    server.on("connection", (socket) => {
      sockets.add(socket);
      socket.once("close", () => sockets.delete(socket));
    });
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", () => {
        server.off("error", reject);
        resolve();
      });
    });
    try {
      const address = server.address();
      if (address === null || typeof address === "string") {
        throw new Error("shadow integration server has no address");
      }
      const fixture = protocolFixture({
        maximumAttempts: 1,
        maximumConcurrency: 2,
        attemptTimeoutMs: 2_000,
        runtimeBuild: "0.26.0",
        requiredCapabilities: [],
      });
      const realCase = caseInput();
      const liveClock: TestClock = {
        now: () => new Date(),
        advance: () => {},
      };
      const made = await makeInput({
        fixture,
        clock: liveClock,
        cases: [{
          ...realCase,
          generation: {
            stream: false,
            n: 1,
            prompt: "private-live-local-prompt",
            maxTokens: 32,
            temperature: 0,
            seed: 7,
          },
        }],
        profiles: targets(
          fixture.protocol,
          `http://127.0.0.1:${address.port}`,
          "completions",
        ),
      });
      const { hooks: _fakeHooks, ...realInput } = made.input;
      const result = await runShadowCollectionProduction(realInput);
      expect(result.status).toBe("complete");
      expect(result.networkCalls).toBe(2);
      expect(contacts).toBe(2);
      expect(result.traces.every(
        ({ attempts, terminalOutputId }) =>
          attempts[0]?.status === "success"
          && terminalOutputId !== null,
      )).toBe(true);
      expect(await allFileText(made.root)).not.toContain(
        "live-local-output",
      );
    } finally {
      const closed = new Promise<void>((resolve) => {
        server.close(() => resolve());
      });
      for (const socket of sockets) socket.destroy();
      server.closeAllConnections();
      await closed;
    }
  });

  it("records abort truth and leaves durable packets free of prompt and output text", async () => {
    const controller = new AbortController();
    let calls = 0;
    const dispatch = vi.fn(async (prepared: PreparedRuntimeInvocation) => {
      calls += 1;
      if (calls === 1) controller.abort();
      return runtimeOutcome(prepared, {
        status: "failed",
        resolvedModel: null,
        responseIdentity: null,
        eventStreamIdentity: null,
        terminalOutputIdentity: null,
        finishReason: null,
        providerUsage: null,
        providerTiming: {},
        finalUsage: "missing",
        partialOutput: false,
        dispatchState: "sent_unknown",
        abortLifecycle: "caller-cancelled-after-dispatch-ambiguous",
        wireTiming: null,
        streamTiming: null,
        error: {
          version: "tasc-persisted-error-v1",
          category: "cancelled",
          message: "Inference request was cancelled.",
          status: null,
          runtime: null,
          requestId: null,
        },
      });
    });
    const made = await makeInput({
      dispatch,
      signal: controller.signal,
      cases: [caseInput({ prompt: "ultra-private-prompt" })],
    });
    const result = await runShadowCollection(made.input);
    expect(result.status).toBe("cancelled");
    const attempt = result.traces[0]?.attempts[0];
    expect(attempt).toMatchObject({
      status: "aborted",
      abortLifecycle: "abort-ambiguous",
      dispatchState: "sent_unknown",
      failureCategory: "cancelled",
    });
    const persisted = await allFileText(made.root);
    expect(persisted).not.toContain("ultra-private-prompt");
    expect(persisted).not.toContain("private-provider-output");
  });
});
