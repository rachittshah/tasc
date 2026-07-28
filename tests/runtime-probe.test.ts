import { Buffer } from "node:buffer";
import {
  createServer,
  type IncomingMessage,
  type ServerResponse,
} from "node:http";
import type { Socket } from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import {
  probeRuntimeCapability,
  RuntimeProbeInputError,
  verifyRuntimeCapabilityAuthorization,
  type RuntimeCapabilityProbeInput,
} from "../src/runtime/probe.js";
import {
  fingerprintCollectorEndpointBinding,
  parseCollectorTrustPolicy,
  type CollectorTrustPolicy,
} from "../src/runtime/network-policy.js";
import { getRuntimeProfile } from "../src/runtime/profiles.js";
import type {
  RuntimeInstanceIdentity,
  RuntimeProfileId,
} from "../src/runtime/types.js";

const TEST_TIMEOUT_MS = 5_000;
const MODEL = Object.freeze({ id: "test-model", revision: "rev-1" });
const DIGEST_A = `sha256:${"a".repeat(64)}`;
const DIGEST_B = `sha256:${"b".repeat(64)}`;

type Handler = (
  request: IncomingMessage,
  response: ServerResponse,
) => void | Promise<void>;

interface TestServer {
  readonly origin: string;
  readonly contacts: () => number;
  readonly requests: () => readonly {
    readonly method: string | undefined;
    readonly path: string | undefined;
    readonly accept: string | undefined;
    readonly body: Uint8Array;
  }[];
  close(): Promise<void>;
}

const activeServers = new Set<TestServer>();

function deadline<T>(
  promise: Promise<T>,
  milliseconds = 2_000,
): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(
      () => reject(new Error("probe test exceeded its deadline")),
      milliseconds,
    );
  });
  return Promise.race([promise, timeout]).finally(() => {
    if (timer !== undefined) clearTimeout(timer);
  });
}

async function readRequest(request: IncomingMessage): Promise<Buffer> {
  const chunks: Buffer[] = [];
  for await (const chunk of request) chunks.push(Buffer.from(chunk));
  return Buffer.concat(chunks);
}

async function startServer(handler: Handler): Promise<TestServer> {
  let contacts = 0;
  const requests: Array<{
    method: string | undefined;
    path: string | undefined;
    accept: string | undefined;
    body: Uint8Array;
  }> = [];
  const sockets = new Set<Socket>();
  const server = createServer((request, response) => {
    contacts += 1;
    void readRequest(request).then(async (body) => {
      requests.push({
        method: request.method,
        path: request.url,
        accept: request.headers.accept,
        body,
      });
      await handler(request, response);
    }).catch(() => response.destroy());
  });
  server.on("connection", (socket) => {
    sockets.add(socket);
    socket.once("close", () => sockets.delete(socket));
  });
  await deadline(new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.off("error", reject);
      resolve();
    });
  }));
  const address = server.address();
  if (address === null || typeof address === "string") {
    throw new Error("test server has no TCP address");
  }
  const result: TestServer = {
    origin: `http://127.0.0.1:${address.port}`,
    contacts: () => contacts,
    requests: () => requests,
    close: async () => {
      if (!activeServers.delete(result)) return;
      const closed = new Promise<void>((resolve) => {
        server.close(() => resolve());
      });
      for (const socket of sockets) socket.destroy();
      server.closeAllConnections();
      await deadline(closed, 1_000);
    },
  };
  activeServers.add(result);
  return result;
}

afterEach(async () => {
  await Promise.all([...activeServers].map((server) => server.close()));
});

function jsonResponse(
  response: ServerResponse,
  value: unknown,
  statusCode = 200,
  contentType = "application/json",
): void {
  response.statusCode = statusCode;
  response.setHeader("content-type", contentType);
  response.end(JSON.stringify(value));
}

function fixture(input: {
  readonly server: TestServer;
  readonly profileId: RuntimeProfileId;
  readonly capability:
    | "modelDiscovery"
    | "chatCompletions"
    | "nativeChat";
  readonly observationEffect: "non-mutating" | "inference-canary";
  readonly authorizationTtlMs?: number;
}): {
  readonly policy: CollectorTrustPolicy;
  readonly instance: RuntimeInstanceIdentity;
  readonly probe: RuntimeCapabilityProbeInput;
} {
  const profile = getRuntimeProfile(input.profileId);
  const route = input.capability === "modelDiscovery"
    ? profile.endpoints.models.list
    : profile.endpoints.inference[input.capability];
  if (route === undefined) throw new Error("fixture route is missing");
  const endpointAlias = `probe-${input.profileId.replace(".", "-")}`;
  const policy = parseCollectorTrustPolicy({
    schemaVersion: "tasc-collector-trust-policy-v1",
    localMode: "literal-loopback-only",
    maximumRequestDurationMs: 2_000,
    endpoints: [{
      alias: endpointAlias,
      origin: input.server.origin,
      runtime: {
        profileId: profile.id,
        build: profile.runtime.build,
      },
      routes: [{
        method: route.method,
        pathPrefix: route.path,
        authenticationReferences: [],
      }],
    }],
    secretReferences: [],
    evaluatorKeyIds: [],
    storeRoots: [],
  });
  const instance: RuntimeInstanceIdentity = {
    endpointDescriptorDigest: fingerprintCollectorEndpointBinding(
      policy,
      endpointAlias,
    ),
    runtime: {
      profileId: profile.id,
      build: profile.runtime.build,
    },
    backend: { name: "contract-backend", build: "1.0.0" },
    model: MODEL,
    configurationDigest: DIGEST_A,
  };
  return {
    policy,
    instance,
    probe: {
      policy,
      endpointAlias,
      instance,
      capability: input.capability,
      observationEffect: input.observationEffect,
      totalDeadlineMs: 1_500,
      ...(input.authorizationTtlMs === undefined
        ? {}
        : { authorizationTtlMs: input.authorizationTtlMs }),
    },
  };
}

describe("runtime capability probes", () => {
  it("passively discovers the exact pinned vLLM model with no authority side effect", async () => {
    const server = await startServer((_request, response) => {
      jsonResponse(response, {
        object: "list",
        data: [{
          id: MODEL.id,
          object: "model",
          created: 1_700_000_000,
          owned_by: "fixture",
        }],
      });
    });
    const { probe, instance } = fixture({
      server,
      profileId: "vllm",
      capability: "modelDiscovery",
      observationEffect: "non-mutating",
    });

    const result = await deadline(probeRuntimeCapability(probe));

    expect(server.contacts()).toBe(1);
    expect(server.requests()).toMatchObject([{
      method: "GET",
      path: "/v1/models",
      accept: "application/json",
    }]);
    expect(result).toMatchObject({
      schemaVersion: "tasc-runtime-probe-v1",
      evidence: {
        source: "live-probe",
        capability: "modelDiscovery",
        state: "supported",
        endpointDescriptorDigest: instance.endpointDescriptorDigest,
        model: MODEL,
        identityVerification: {
          endpointBinding: "operator-policy",
          runtimeBuild: {
            basis: "operator-policy",
            observed: null,
          },
          backend: {
            basis: "unverified",
            observed: null,
          },
          modelId: {
            basis: "provider-reported",
            observed: MODEL.id,
          },
          modelRevision: {
            basis: "unverified",
            observed: null,
          },
          configurationDigest: {
            basis: "unverified",
            observed: null,
          },
        },
      },
      authorization: null,
      observation: {
        effect: "non-mutating",
        statusCode: 200,
        error: null,
      },
    });
    expect(JSON.stringify(result)).not.toContain("owned_by");
    expect(Object.isFrozen(result)).toBe(true);
    expect(Object.isFrozen(result.evidence)).toBe(true);
  });

  it("uses one library-owned Ollama canary and mints only exact live authority", async () => {
    const server = await startServer((_request, response) => {
      jsonResponse(response, {
        model: MODEL.id,
        message: { role: "assistant", content: "ok" },
        done: true,
        done_reason: "stop",
        prompt_eval_count: 2,
        eval_count: 1,
      });
    });
    const { probe, instance } = fixture({
      server,
      profileId: "ollama",
      capability: "nativeChat",
      observationEffect: "inference-canary",
      authorizationTtlMs: 50,
    });

    const result = await deadline(probeRuntimeCapability(probe));

    expect(server.contacts()).toBe(1);
    expect(server.requests()[0]).toMatchObject({
      method: "POST",
      path: "/api/chat",
      accept: "application/json",
    });
    expect(JSON.parse(
      Buffer.from(server.requests()[0]!.body).toString("utf8"),
    )).toEqual({
      model: MODEL.id,
      messages: [{ role: "user", content: "ping" }],
      stream: false,
      options: { num_predict: 1, temperature: 0 },
    });
    expect(result.evidence.state).toBe("supported");
    expect(result.authorization).not.toBeNull();
    const expectation = {
      instance,
      capability: "nativeChat" as const,
      route: "nativeChat" as const,
      minimumRemainingMs: 0,
    };
    expect(verifyRuntimeCapabilityAuthorization(
      result.authorization!,
      expectation,
    )).toBe(true);
    expect(verifyRuntimeCapabilityAuthorization(
      structuredClone(result.authorization!),
      expectation,
    )).toBe(false);
    expect(verifyRuntimeCapabilityAuthorization(
      {
        ...result.authorization!,
      },
      expectation,
    )).toBe(false);
    expect(verifyRuntimeCapabilityAuthorization(
      result.authorization!,
      {
        ...expectation,
        instance: {
          ...instance,
          configurationDigest: DIGEST_B,
        },
      },
    )).toBe(false);
    expect(verifyRuntimeCapabilityAuthorization(
      result.authorization!,
      {
        ...expectation,
        minimumRemainingMs: 1_500,
      },
    )).toBe(false);
  });

  it("expires canary authority against a monotonic bounded TTL", async () => {
    const server = await startServer((_request, response) => {
      jsonResponse(response, {
        model: MODEL.id,
        choices: [{
          index: 0,
          message: { role: "assistant", content: "o" },
          finish_reason: "length",
        }],
      });
    });
    const { probe, instance } = fixture({
      server,
      profileId: "vllm",
      capability: "chatCompletions",
      observationEffect: "inference-canary",
      authorizationTtlMs: 1,
    });
    const result = await deadline(probeRuntimeCapability(probe));
    expect(result.authorization).not.toBeNull();
    await new Promise((resolve) => setTimeout(resolve, 8));
    expect(verifyRuntimeCapabilityAuthorization(
      result.authorization!,
      {
        instance,
        capability: "chatCompletions",
        route: "chatCompletions",
        minimumRemainingMs: 0,
      },
    )).toBe(false);
  });

  it("rejects hostile DTOs and endpoint drift before any network contact", async () => {
    const server = await startServer((_request, response) => {
      jsonResponse(response, {});
    });
    const { probe, instance } = fixture({
      server,
      profileId: "vllm",
      capability: "modelDiscovery",
      observationEffect: "non-mutating",
    });
    await expect(probeRuntimeCapability({
      ...probe,
      instance: {
        ...instance,
        endpointDescriptorDigest: DIGEST_B,
      },
    })).rejects.toMatchObject({
      code: "ENDPOINT_BINDING_MISMATCH",
    });

    let getterCalls = 0;
    const hostile = { ...probe } as Record<string, unknown>;
    Object.defineProperty(hostile, "url", {
      enumerable: true,
      get: () => {
        getterCalls += 1;
        return "http://metadata.invalid";
      },
    });
    await expect(probeRuntimeCapability(
      hostile as unknown as RuntimeCapabilityProbeInput,
    )).rejects.toBeInstanceOf(RuntimeProbeInputError);
    await expect(probeRuntimeCapability({
      ...probe,
      authorizationTtlMs: 2_001,
    })).rejects.toBeInstanceOf(RuntimeProbeInputError);

    const invalidSignal = new Proxy(new AbortController().signal, {});
    await expect(probeRuntimeCapability({
      ...probe,
      signal: invalidSignal,
    })).rejects.toBeInstanceOf(RuntimeProbeInputError);
    expect(getterCalls).toBe(0);
    expect(server.contacts()).toBe(0);
  });

  it("classifies a pre-aborted probe as not sent without fabricating response evidence", async () => {
    const server = await startServer((_request, response) => {
      jsonResponse(response, {});
    });
    const fixtureValue = fixture({
      server,
      profileId: "vllm",
      capability: "modelDiscovery",
      observationEffect: "non-mutating",
    });
    const controller = new AbortController();
    controller.abort();

    const result = await probeRuntimeCapability({
      ...fixtureValue.probe,
      signal: controller.signal,
    });

    expect(server.contacts()).toBe(0);
    expect(result).toMatchObject({
      evidence: {
        state: "unknown",
        identityVerification: {
          modelId: { basis: "unverified", observed: null },
          modelRevision: { basis: "unverified", observed: null },
        },
      },
      observation: {
        dispatchState: "not_sent",
        statusCode: null,
        wireTiming: null,
        error: { category: "cancelled" },
      },
    });
  });

  it("fails closed on malformed framing and distinguishes an exact 404", async () => {
    const wrongType = await startServer((_request, response) => {
      jsonResponse(response, {
        object: "list",
        data: [{ id: MODEL.id }],
      }, 200, "text/plain");
    });
    const wrongFixture = fixture({
      server: wrongType,
      profileId: "vllm",
      capability: "modelDiscovery",
      observationEffect: "non-mutating",
    });
    const unknown = await deadline(
      probeRuntimeCapability(wrongFixture.probe),
    );
    expect(unknown).toMatchObject({
      evidence: { state: "unknown" },
      authorization: null,
      observation: {
        error: expect.any(Object),
      },
    });

    const missing = await startServer((_request, response) => {
      jsonResponse(response, { error: "private provider detail" }, 404);
    });
    const missingFixture = fixture({
      server: missing,
      profileId: "vllm",
      capability: "modelDiscovery",
      observationEffect: "non-mutating",
    });
    const unsupported = await deadline(
      probeRuntimeCapability(missingFixture.probe),
    );
    expect(unsupported).toMatchObject({
      evidence: { state: "unsupported" },
      authorization: null,
      observation: {
        statusCode: 404,
      },
    });
    expect(JSON.stringify(unsupported)).not.toContain("private provider");
  });
}, TEST_TIMEOUT_MS);
