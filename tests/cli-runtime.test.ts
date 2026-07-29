import { Buffer } from "node:buffer";
import { generateKeyPairSync } from "node:crypto";
import {
  createServer,
  type IncomingMessage,
  type ServerResponse,
} from "node:http";
import type { Socket } from "node:net";
import {
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { runCli, type CliIo } from "../src/cli.js";
import { createControllerSnapshot } from "../src/controller-events.js";
import {
  fingerprintProtocol,
  parseExperimentProtocol,
  type ExperimentProtocol,
} from "../src/evidence.js";
import {
  enumerateProtocolPolicyBundles,
  type PolicyBundle,
} from "../src/policy.js";
import {
  fingerprintCollectorEndpointBinding,
  parseCollectorTrustPolicy,
} from "../src/runtime/network-policy.js";
import { getRuntimeProfile } from "../src/runtime/profiles.js";
import { buildShadowRunPlan } from "../src/shadow-plan.js";
import {
  TEST_WORK_BUDGET,
  validProtocolInput,
} from "./fixtures/evidence.js";

const DIGEST = (digit: string): string => `sha256:${digit.repeat(64)}`;
const roots = new Set<string>();

interface CapturedIo extends CliIo {
  output(): { readonly stdout: string; readonly stderr: string };
}

interface ContractServer {
  readonly origin: string;
  readonly contacts: () => number;
  readonly authorizations: () => readonly (string | undefined)[];
  close(): Promise<void>;
}

const servers = new Set<ContractServer>();

afterEach(async () => {
  await Promise.all([...servers].map((server) => server.close()));
  await Promise.all([...roots].map(async (root) => {
    roots.delete(root);
    await rm(root, { recursive: true, force: true });
  }));
});

function captureIo(): CapturedIo {
  let stdout = "";
  let stderr = "";
  return {
    stdout: { write: (value) => { stdout += value; } },
    stderr: { write: (value) => { stderr += value; } },
    output: () => ({ stdout, stderr }),
  };
}

async function temporaryRoot(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "tasc-cli-runtime-"));
  roots.add(root);
  return root;
}

async function jsonFile(
  root: string,
  name: string,
  value: unknown,
): Promise<string> {
  const path = join(root, name);
  await writeFile(path, `${JSON.stringify(value)}\n`, "utf8");
  return path;
}

async function ndjsonFile(
  root: string,
  name: string,
  values: readonly unknown[],
): Promise<string> {
  const path = join(root, name);
  await writeFile(
    path,
    `${values.map((value) => JSON.stringify(value)).join("\n")}\n`,
    "utf8",
  );
  return path;
}

function jsonLine(source: string): Record<string, any> {
  expect(source.endsWith("\n")).toBe(true);
  expect(source.trim().split("\n")).toHaveLength(1);
  return JSON.parse(source) as Record<string, any>;
}

async function readBody(request: IncomingMessage): Promise<Buffer> {
  const chunks: Buffer[] = [];
  for await (const chunk of request) chunks.push(Buffer.from(chunk));
  return Buffer.concat(chunks);
}

async function startContractServer(): Promise<ContractServer> {
  let contacts = 0;
  const authorizations: Array<string | undefined> = [];
  const sockets = new Set<Socket>();
  const server = createServer((request, response) => {
    contacts += 1;
    authorizations.push(request.headers.authorization);
    void readBody(request).then((body) => {
      if (request.url !== "/v1/completions" || request.method !== "POST") {
        response.statusCode = 404;
        response.end();
        return;
      }
      const requestJson = JSON.parse(body.toString("utf8")) as {
        readonly model: string;
      };
      response.statusCode = 200;
      response.setHeader("content-type", "application/json");
      response.end(JSON.stringify({
        model: requestJson.model,
        choices: [{
          index: 0,
          text: "private-provider-output",
          finish_reason: "stop",
        }],
        usage: {
          prompt_tokens: 2,
          completion_tokens: 1,
          total_tokens: 3,
        },
      }));
    }).catch(() => response.destroy());
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
  const address = server.address();
  if (address === null || typeof address === "string") {
    throw new Error("contract server did not bind");
  }
  const result: ContractServer = {
    origin: `http://127.0.0.1:${address.port}`,
    contacts: () => contacts,
    authorizations: () => Object.freeze([...authorizations]),
    close: async () => {
      if (!servers.delete(result)) return;
      const closed = new Promise<void>((resolve) => {
        server.close(() => resolve());
      });
      for (const socket of sockets) socket.destroy();
      server.closeAllConnections();
      await closed;
    },
  };
  servers.add(result);
  return result;
}

function trustInput(
  server: ContractServer,
  endpoints: readonly {
    readonly alias: string;
    readonly authenticationReference?: string;
  }[],
): Record<string, unknown> {
  const profile = getRuntimeProfile("vllm");
  const references = endpoints.flatMap(({ authenticationReference }) =>
    authenticationReference === undefined ? [] : [authenticationReference]
  );
  return {
    schemaVersion: "tasc-collector-trust-policy-v1",
    localMode: "literal-loopback-only",
    maximumRequestDurationMs: 2_000,
    endpoints: endpoints.map(({ alias, authenticationReference }) => ({
      alias,
      origin: server.origin,
      runtime: {
        profileId: profile.id,
        build: profile.runtime.build,
      },
      routes: [{
        method: "POST",
        pathPrefix: "/v1/completions",
        authenticationReferences:
          authenticationReference === undefined
            ? []
            : [authenticationReference],
      }],
    })),
    secretReferences: references,
    evaluatorKeyIds: [],
    storeRoots: [],
  };
}

function instanceFor(
  trust: ReturnType<typeof parseCollectorTrustPolicy>,
  alias: string,
  modelId: string,
) {
  const profile = getRuntimeProfile("vllm");
  return {
    endpointDescriptorDigest: fingerprintCollectorEndpointBinding(
      trust,
      alias,
    ),
    runtime: {
      profileId: profile.id,
      build: profile.runtime.build,
    },
    backend: {
      name: "contract-backend",
      build: "1.0.0",
    },
    model: {
      id: modelId,
      revision: "revision-one",
    },
    configurationDigest: DIGEST(alias === "champion-endpoint" ? "1" : "2"),
  };
}

function shadowControllerSnapshot(
  protocol: ExperimentProtocol,
  policy: PolicyBundle,
  lastEventAt: string,
) {
  const protocolDigest = fingerprintProtocol(protocol);
  const selectedPolicy = {
    policyDigest: policy.policyDigest,
    issuedAt: policy.issuedAt,
    expiresAt: policy.expiresAt,
  };
  const developmentEvidence = {
    datasetDigest: DIGEST("a"),
    traceSetDigest: DIGEST("b"),
    evaluatorSetDigest: DIGEST("c"),
  };
  return createControllerSnapshot({
    version: "tasc-controller-snapshot-v1",
    controllerId: "cli-shadow-controller",
    studyId: protocol.studyId,
    protocolDigest,
    protocolCreatedAt: protocol.createdAt,
    protocolExpiresAt: protocol.expiresAt,
    state: "SHADOW_ASSESSING",
    sequence: 5,
    lastEventId: DIGEST("d"),
    lastEventAt,
    collectionId: "cli-shadow-collection",
    developmentEvidence,
    selectedPolicy,
    assessments: [{
      version: "tasc-controller-assessment-projection-v1",
      phase: "development",
      status: "NOMINATED",
      decisionDigest: DIGEST("e"),
      assessmentContextDigest: DIGEST("f"),
      protocolDigest,
      ...developmentEvidence,
      selectedPolicy,
      windowManifestDigest: null,
      attestation: "unattested",
    }],
    windows: [],
    deploymentObservation: null,
    staleReasons: [],
    attestation: "unattested",
  });
}

async function allFileText(root: string): Promise<string> {
  const chunks: string[] = [];
  const visit = async (path: string): Promise<void> => {
    for (const name of await readdir(path, { withFileTypes: true })) {
      const child = join(path, name.name);
      if (name.isDirectory()) await visit(child);
      else if (name.isFile()) chunks.push(await readFile(child, "utf8"));
    }
  };
  await visit(root);
  return chunks.join("\n");
}

describe("runtime and shadow CLI execution", () => {
  it("rejects metadata/link-local trust before runtime contact", async () => {
    const root = await temporaryRoot();
    const profile = getRuntimeProfile("vllm");
    const metadataOrigin = "http://169.254.169.254";
    const endpoint = await jsonFile(root, "endpoint.json", {
      schemaVersion: "tasc-cli-runtime-endpoint-v1",
      endpointAlias: "metadata-endpoint",
    });
    const runtime = await jsonFile(root, "runtime.json", {
      endpointDescriptorDigest: DIGEST("a"),
      runtime: {
        profileId: profile.id,
        build: profile.runtime.build,
      },
      backend: { name: "unknown", build: "unknown" },
      model: { id: "model", revision: "revision" },
      configurationDigest: DIGEST("b"),
    });
    const trust = await jsonFile(root, "trust.json", {
      schemaVersion: "tasc-collector-trust-policy-v1",
      localMode: "disabled",
      maximumRequestDurationMs: 1_000,
      endpoints: [{
        alias: "metadata-endpoint",
        origin: metadataOrigin,
        runtime: {
          profileId: profile.id,
          build: profile.runtime.build,
        },
        routes: [{
          method: "GET",
          pathPrefix: "/health",
          authenticationReferences: [],
        }],
      }],
      secretReferences: [],
      evaluatorKeyIds: [],
      storeRoots: [],
    });
    const io = captureIo();

    await expect(runCli([
      "runtime",
      "probe",
      "--endpoint",
      endpoint,
      "--runtime",
      runtime,
      "--trust",
      trust,
      "--capability",
      "liveness",
      "--effect",
      "non-mutating",
      "--deadline-ms",
      "500",
    ], {}, io)).resolves.toBe(3);
    expect(jsonLine(io.output().stderr)).toMatchObject({
      code: "INPUT_INVALID",
      input: "trust",
      detail: "contract-invalid",
    });
    expect(io.output().stderr).not.toContain(metadataOrigin);
  });

  it("performs an explicitly effect-marked live probe without reflecting auth", async () => {
    const root = await temporaryRoot();
    const server = await startContractServer();
    const auth = "Bearer planted-runtime-secret";
    const trustValue = trustInput(server, [{
      alias: "probe-endpoint",
      authenticationReference: "runtime-auth",
    }]);
    const trust = parseCollectorTrustPolicy(trustValue);
    const endpoint = await jsonFile(root, "endpoint.json", {
      schemaVersion: "tasc-cli-runtime-endpoint-v1",
      endpointAlias: "probe-endpoint",
      authentication: {
        reference: "runtime-auth",
        header: "authorization",
        environmentVariable: "TASC_RUNTIME_AUTH_PROBE",
      },
    });
    const runtime = await jsonFile(
      root,
      "runtime.json",
      instanceFor(trust, "probe-endpoint", "probe-model"),
    );
    const trustPath = await jsonFile(root, "trust.json", trustValue);
    const io = captureIo();

    await expect(runCli([
      "runtime",
      "probe",
      "--endpoint",
      endpoint,
      "--runtime",
      runtime,
      "--trust",
      trustPath,
      "--capability",
      "completions",
      "--effect",
      "inference-canary",
      "--deadline-ms",
      "1500",
    ], { TASC_RUNTIME_AUTH_PROBE: auth }, io)).resolves.toBe(0);

    expect(server.contacts()).toBe(1);
    expect(server.authorizations()).toEqual([auth]);
    expect(io.output().stderr).toBe("");
    expect(jsonLine(io.output().stdout)).toMatchObject({
      command: "runtime probe",
      status: "SUPPORTED",
      authorizationIssued: true,
      scope: "observation-only-no-persisted-capability-authority",
      authority: "evidence-only-no-deployment-authority",
      observation: {
        effect: "inference-canary",
        dispatchState: "completed",
      },
    });
    expect(io.output().stdout).not.toContain(auth);
    expect(io.output().stdout).not.toContain("private-provider-output");

    const endpointWithInlineSecret = await jsonFile(
      root,
      "endpoint-with-inline-secret.json",
      {
        schemaVersion: "tasc-cli-runtime-endpoint-v1",
        endpointAlias: "probe-endpoint",
        authorization: auth,
      },
    );
    const inlineSecretIo = captureIo();
    await expect(runCli([
      "runtime",
      "probe",
      "--endpoint",
      endpointWithInlineSecret,
      "--runtime",
      runtime,
      "--trust",
      trustPath,
      "--capability",
      "completions",
      "--effect",
      "inference-canary",
      "--deadline-ms",
      "1500",
    ], {}, inlineSecretIo)).resolves.toBe(3);
    expect(server.contacts()).toBe(1);
    expect(inlineSecretIo.output().stderr).not.toContain(auth);

    const missingSecretIo = captureIo();
    await expect(runCli([
      "runtime",
      "probe",
      "--endpoint",
      endpoint,
      "--runtime",
      runtime,
      "--trust",
      trustPath,
      "--capability",
      "completions",
      "--effect",
      "inference-canary",
      "--deadline-ms",
      "1500",
    ], {}, missingSecretIo)).resolves.toBe(3);
    expect(server.contacts()).toBe(1);
    expect(jsonLine(missingSecretIo.output().stderr)).toMatchObject({
      code: "INPUT_INVALID",
      input: "endpoint",
      detail: "secret-unavailable",
    });
    expect(missingSecretIo.output().stderr).not.toContain(root);
    expect(missingSecretIo.output().stderr).not.toContain(auth);

    await server.close();
    const networkFailureIo = captureIo();
    await expect(runCli([
      "runtime",
      "probe",
      "--endpoint",
      endpoint,
      "--runtime",
      runtime,
      "--trust",
      trustPath,
      "--capability",
      "completions",
      "--effect",
      "inference-canary",
      "--deadline-ms",
      "1500",
    ], { TASC_RUNTIME_AUTH_PROBE: auth }, networkFailureIo)).resolves.toBe(1);
    expect(jsonLine(networkFailureIo.output().stderr)).toMatchObject({
      code: "RUNTIME_FAILURE",
      operation: "runtime-probe",
      detail: "transport",
    });
    expect(networkFailureIo.output().stderr).not.toContain(auth);
    expect(networkFailureIo.output().stderr).not.toContain(server.origin);
  });

  it("consumes a P0 plan, collects, and resumes without duplicate calls", async () => {
    const root = await temporaryRoot();
    const server = await startContractServer();
    const output = join(root, "shadow-output");
    const rejectedOutput = join(root, "rejected-output");
    await Promise.all([
      mkdir(output, { mode: 0o700 }),
      mkdir(rejectedOutput, { mode: 0o700 }),
    ]);
    const runtimeProfile = getRuntimeProfile("vllm");
    const aliases = ["champion-endpoint", "candidate-endpoint"] as const;
    const trustValue = trustInput(
      server,
      aliases.map((alias) => ({ alias })),
    );
    const trust = parseCollectorTrustPolicy(trustValue);
    const dispatchKeys = generateKeyPairSync("ed25519");
    const collectorKeys = generateKeyPairSync("ed25519");
    const now = Date.now();
    const protocolInput = validProtocolInput();
    protocolInput.createdAt = new Date(now - 120_000).toISOString();
    protocolInput.expiresAt = new Date(now + 60 * 60_000).toISOString();
    protocolInput.dispatchAuthority.publicKeySpki = dispatchKeys.publicKey
      .export({ format: "der", type: "spki" })
      .toString("base64url");
    protocolInput.collectorAuthority.publicKeySpki = collectorKeys.publicKey
      .export({ format: "der", type: "spki" })
      .toString("base64url");
    protocolInput.onlineWindowMembership.sampleBasisPoints = 10_000;
    protocolInput.requiredCapabilities = [];
    protocolInput.shadowCollection = {
      maximumLogicalExecutions: 10,
      maximumConcurrency: 2,
      attemptTimeoutMs: 1_500,
      maximumAttempts: 1,
      payloadPolicy: "keyed-identities-only",
    };
    protocolInput.profiles.forEach((executionProfile, index) => {
      executionProfile.runtime = {
        name: "vllm",
        build: runtimeProfile.runtime.build,
      };
      executionProfile.model = {
        id: index === 0 ? "champion-model" : "candidate-model",
        revision: "revision-one",
      };
    });
    (protocolInput as unknown as {
      endpointRequirements: Array<{
        runtimeName: string;
        endpointAlias: string;
        transport: "https" | "loopback-http";
      }>;
    }).endpointRequirements = aliases.map((alias) => ({
      runtimeName: "vllm",
      endpointAlias: alias,
      transport: "loopback-http",
    }));
    const protocol = parseExperimentProtocol(
      protocolInput,
      TEST_WORK_BUDGET,
    );
    const instances = aliases.map((alias, index) => ({
      ...instanceFor(
        trust,
        alias,
        index === 0 ? "champion-model" : "candidate-model",
      ),
      backend: protocol.profiles[index].backend,
      configurationDigest:
        protocol.profiles[index].deploymentConfigurationDigest,
    }));
    const trustPath = await jsonFile(root, "trust.json", trustValue);
    const profileTargets = protocol.profiles.map((profile, index) => ({
      profileId: profile.id,
      endpoint: {
        schemaVersion: "tasc-cli-runtime-endpoint-v1",
        endpointAlias: aliases[index],
      },
      instance: instances[index],
      route: "completions",
      httpLimits: {
        maxResponseBytes: 1024 * 1024,
      },
    }));
    const profilesPath = await jsonFile(root, "profiles.json", {
      schemaVersion: "tasc-cli-shadow-profiles-v2",
      targets: profileTargets,
    });

    const protocolDigest = fingerprintProtocol(protocol);
    const selectedPolicy = enumerateProtocolPolicyBundles(
      protocol,
      protocolDigest,
      protocol.createdAt,
    ).candidates[0]!;
    const planIssuedAt = new Date(now - 60_000).toISOString();
    const planWorkBudget = {
      maxCases: 1,
      maxProfiles: 2,
      maxReplicates: 1,
      maxLogicalExecutions: 2,
      maxAttempts: 2,
      maxNetworkCalls: 2,
      maxDurableRecords: 20,
      maxRequestBytes: 1024 * 1024,
      maxResponseBytes: 2 * 1024 * 1024,
      maxWallClockMs: 60_000,
      maxConcurrency: 2,
    };
    const planInput = {
      controllerSnapshot: shadowControllerSnapshot(
        protocol,
        selectedPolicy,
        new Date(now - 61_000).toISOString(),
      ),
      protocol,
      frozenPolicy: selectedPolicy,
      window: {
        windowId: "window-one",
        eventTimeStartInclusive: planIssuedAt,
        eventTimeEndExclusive:
          new Date(now + 20 * 60_000).toISOString(),
      },
      collectionTargets: protocol.profiles.map((profile, index) => ({
        profileId: profile.id,
        endpointAlias: aliases[index],
        endpointBindingDigest:
          instances[index].endpointDescriptorDigest,
        route: "completions" as const,
        authenticationReference: null,
        capabilityReceiptDigests: [],
      })),
      workBudget: planWorkBudget,
      issuedAt: planIssuedAt,
      expiresAt: new Date(now + 30 * 60_000).toISOString(),
    } as const;
    const plan = buildShadowRunPlan(planInput);
    const planPath = await jsonFile(root, "shadow-plan.json", plan);
    const conditionalPlan = buildShadowRunPlan({
      ...planInput,
      collectionTargets: planInput.collectionTargets.map((target) => ({
        ...target,
        route: "chatCompletions" as const,
      })),
    });
    const conditionalPlanPath = await jsonFile(
      root,
      "conditional-shadow-plan.json",
      conditionalPlan,
    );

    const hmacSecret = Buffer.alloc(32, 0x53).toString("base64url");
    const dispatchSigningSecret = dispatchKeys.privateKey
      .export({ format: "der", type: "pkcs8" })
      .toString("base64url");
    const collectorSigningSecret = collectorKeys.privateKey
      .export({ format: "der", type: "pkcs8" })
      .toString("base64url");
    const identityPath = await jsonFile(root, "identity.json", {
      schemaVersion: "tasc-cli-shadow-identity-v2",
      studyId: protocol.studyId,
      keyId: "shadow-payload-key",
      hmacKeyEnvironmentVariable: "TASC_SHADOW_HMAC_TEST",
      dispatchPrivateKeyEnvironmentVariable:
        "TASC_SHADOW_SIGNING_DISPATCH_TEST",
      collectorPrivateKeyEnvironmentVariable:
        "TASC_SHADOW_SIGNING_COLLECTOR_TEST",
    });
    const reusedIdentityPath = await jsonFile(
      root,
      "reused-identity.json",
      {
        schemaVersion: "tasc-cli-shadow-identity-v2",
        studyId: protocol.studyId,
        keyId: "shadow-payload-key",
        hmacKeyEnvironmentVariable: "TASC_SHADOW_HMAC_TEST",
        dispatchPrivateKeyEnvironmentVariable:
          "TASC_SHADOW_SIGNING_DISPATCH_TEST",
        collectorPrivateKeyEnvironmentVariable:
          "TASC_SHADOW_SIGNING_REUSED_TEST",
      },
    );
    const privatePrompt = "private-prompt-must-never-persist";
    const casesPath = await ndjsonFile(root, "cases.ndjson", [{
      caseId: "case-one",
      groupId: "group-one",
      replicates: 1,
      generation: {
        stream: false,
        n: 1,
        prompt: privatePrompt,
        maxTokens: 4,
        temperature: 0,
      },
      workload: {
        mode: "completion",
        declaredTrafficWeight: 1,
        inputTokenEstimate: 2,
      },
      slices: ["english"],
      routeSignal: {
        value: 0.75,
        sourceId: "router-observer",
        observedAt: new Date(Date.now() - 30_000).toISOString(),
      },
    }]);
    const oldProfilesPath = await jsonFile(
      root,
      "profiles-v1.json",
      {
        schemaVersion: "tasc-cli-shadow-profiles-v1",
        collectionWindowId: "window-one",
        collectionWindowMembershipDigest: plan.window.membershipDigest,
        policyDigest: plan.frozenPolicyDigest,
        targets: profileTargets,
      },
    );
    const wrongBindingProfilesPath = await jsonFile(
      root,
      "wrong-binding-profiles.json",
      {
        schemaVersion: "tasc-cli-shadow-profiles-v2",
        targets: profileTargets.map((target, index) =>
          index === 0
            ? {
              ...target,
              endpoint: {
                ...target.endpoint,
                endpointAlias: aliases[1],
              },
            }
            : target
        ),
      },
    );
    const conditionalProfilesPath = await jsonFile(
      root,
      "conditional-profiles.json",
      {
        schemaVersion: "tasc-cli-shadow-profiles-v2",
        targets: profileTargets.map((target) => ({
          ...target,
          route: "chatCompletions",
        })),
      },
    );
    const capabilityProbeProfilesPath = await jsonFile(
      root,
      "capability-probe-profiles.json",
      {
        schemaVersion: "tasc-cli-shadow-profiles-v2",
        targets: profileTargets.map((target, index) =>
          index === 0
            ? {
              ...target,
              capabilityProbe: {
                observationEffect: "inference-canary",
                totalDeadlineMs: 1_500,
                authorizationTtlMs: 1_500,
              },
            }
            : target
        ),
      },
    );
    const environment = {
      TASC_SHADOW_HMAC_TEST: hmacSecret,
      TASC_SHADOW_SIGNING_DISPATCH_TEST: dispatchSigningSecret,
      TASC_SHADOW_SIGNING_COLLECTOR_TEST: collectorSigningSecret,
      TASC_SHADOW_SIGNING_REUSED_TEST: dispatchSigningSecret,
    };
    const command = (
      out: string,
      options: {
        readonly plan?: string;
        readonly expectedPlanDigest?: string;
        readonly profiles?: string;
        readonly identity?: string;
      } = {},
    ) => [
      "shadow",
      "run",
      "--plan",
      options.plan ?? planPath,
      "--plan-digest",
      options.expectedPlanDigest ?? plan.planDigest,
      "--cases",
      casesPath,
      "--profiles",
      options.profiles ?? profilesPath,
      "--trust",
      trustPath,
      "--identity",
      options.identity ?? identityPath,
      "--out",
      out,
    ];

    for (const rejection of [
      {
        options: {
          expectedPlanDigest:
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          profiles: join(root, "must-not-read-profiles.json"),
          identity: join(root, "must-not-read-identity.json"),
        },
        input: "plan",
        detail: "context-mismatch",
      },
      {
        options: { profiles: oldProfilesPath },
        input: "profiles",
        detail: "contract-invalid",
      },
      {
        options: {
          plan: conditionalPlanPath,
          expectedPlanDigest: conditionalPlan.planDigest,
          profiles: conditionalProfilesPath,
        },
        input: "profiles",
        detail: "runtime-rejected",
      },
      {
        options: { profiles: capabilityProbeProfilesPath },
        input: "profiles",
        detail: "contract-invalid",
      },
      {
        options: { profiles: wrongBindingProfilesPath },
        input: "profiles",
        detail: "runtime-rejected",
      },
      {
        options: { identity: reusedIdentityPath },
        input: "identity",
        detail: "contract-invalid",
      },
    ] as const) {
      const rejectedIo = captureIo();
      await expect(runCli(
        command(rejectedOutput, rejection.options),
        environment,
        rejectedIo,
      )).resolves.toBe(3);
      expect(server.contacts()).toBe(0);
      expect(jsonLine(rejectedIo.output().stderr)).toMatchObject({
        code: "INPUT_INVALID",
        input: rejection.input,
        detail: rejection.detail,
      });
      for (const sensitive of [
        root,
        server.origin,
        hmacSecret,
        dispatchSigningSecret,
        collectorSigningSecret,
      ]) {
        expect(rejectedIo.output().stderr).not.toContain(sensitive);
      }
      expect(await readdir(rejectedOutput)).toEqual([]);
    }

    const cancelledIo = captureIo();
    const cancelled = new AbortController();
    cancelled.abort();
    await expect(runCli(
      command(rejectedOutput),
      environment,
      cancelledIo,
      cancelled.signal,
    )).resolves.toBe(0);
    expect(server.contacts()).toBe(0);
    expect(jsonLine(cancelledIo.output().stdout)).toMatchObject({
      command: "shadow run",
      status: "CANCELLED",
      summary: {
        pending: 2,
        networkCalls: 0,
        membershipExcludedReplicates: 0,
      },
    });

    const firstIo = captureIo();
    const firstCode = await runCli(
      command(output),
      environment,
      firstIo,
    );
    expect(firstCode, firstIo.output().stderr).toBe(0);
    expect(server.contacts()).toBe(2);
    expect(firstIo.output().stderr).toBe("");
    expect(jsonLine(firstIo.output().stdout)).toMatchObject({
      command: "shadow run",
      status: "COMPLETE",
      scope: "trace-collection-only-no-evaluation-or-deployment",
      authority: "evidence-only-no-deployment-authority",
      summary: {
        logicalExecutions: 2,
        tracesAccepted: 2,
        pending: 0,
        networkCalls: 2,
        membershipExcludedReplicates: 0,
      },
    });

    const secondIo = captureIo();
    const secondCode = await runCli(
      command(output),
      environment,
      secondIo,
    );
    expect(secondCode, secondIo.output().stderr).toBe(0);
    expect(server.contacts()).toBe(2);
    expect(jsonLine(secondIo.output().stdout)).toMatchObject({
      command: "shadow run",
      status: "COMPLETE",
      authority: "evidence-only-no-deployment-authority",
      summary: {
        tracesAccepted: 2,
        networkCalls: 0,
        deduplicated: 2,
      },
    });

    const persisted = await allFileText(output);
    for (const secret of [
      privatePrompt,
      "private-provider-output",
      hmacSecret,
      dispatchSigningSecret,
      collectorSigningSecret,
    ]) {
      expect(firstIo.output().stdout).not.toContain(secret);
      expect(secondIo.output().stdout).not.toContain(secret);
      expect(persisted).not.toContain(secret);
    }
  }, 30_000);
});
