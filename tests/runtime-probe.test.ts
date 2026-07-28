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
  type RuntimeProbeCapability,
  type RuntimeProbeObservationEffect,
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
  readonly capability: RuntimeProbeCapability;
  readonly observationEffect: RuntimeProbeObservationEffect;
  readonly authorizationTtlMs?: number;
  readonly selectedMetricNames?: readonly string[];
}): {
  readonly policy: CollectorTrustPolicy;
  readonly instance: RuntimeInstanceIdentity;
  readonly probe: RuntimeCapabilityProbeInput;
} {
  const profile = getRuntimeProfile(input.profileId);
  const route = input.capability === "modelDiscovery"
    ? profile.endpoints.models.list
    : input.capability === "liveness"
        || input.capability === "readiness"
      ? profile.endpoints.health[input.capability]
      : input.capability === "prometheusMetrics"
          || input.capability === "jsonMetrics"
        ? profile.endpoints.metrics.find(
          ({ capability }) => capability === input.capability,
        )
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
      ...(input.selectedMetricNames === undefined
        ? {}
        : { selectedMetricNames: input.selectedMetricNames }),
    },
  };
}

describe("runtime capability probes", () => {
  it.each([
    ["vllm", "/health", "empty"],
    ["tensorrt-llm", "/health", "empty"],
    ["tgi", "/health", "empty"],
    ["llama.cpp", "/health", "status"],
    ["mlx-lm", "/health", "status"],
    ["ollama", "/api/version", "version"],
  ] as const)(
    "observes the exact passive %s liveness contract",
    async (profileId, path, responseKind) => {
      const profile = getRuntimeProfile(profileId);
      const server = await startServer((_request, response) => {
        if (responseKind === "empty") {
          response.statusCode = 200;
          response.end();
        } else if (responseKind === "version") {
          jsonResponse(response, { version: profile.runtime.build });
        } else {
          jsonResponse(response, { status: "ok" });
        }
      });
      const { probe } = fixture({
        server,
        profileId,
        capability: "liveness",
        observationEffect: "non-mutating",
      });

      const result = await deadline(probeRuntimeCapability(probe));

      expect(server.contacts()).toBe(1);
      expect(server.requests()).toMatchObject([{
        method: "GET",
        path,
        accept: "application/json",
      }]);
      expect(result).toMatchObject({
        evidence: {
          capability: "liveness",
          state: "supported",
        },
        authorization: null,
        observation: {
          effect: "non-mutating",
          dispatchState: "completed",
          statusCode: 200,
          error: null,
          metrics: null,
        },
      });
    },
  );

  it("rejects ambiguous SGLang liveness before contact without authentic launch configuration", async () => {
    const server = await startServer((_request, response) => {
      response.statusCode = 200;
      response.end();
    });
    const { probe } = fixture({
      server,
      profileId: "sglang",
      capability: "liveness",
      observationEffect: "non-mutating",
    });

    await expect(probeRuntimeCapability(probe)).rejects.toMatchObject({
      code: "UNSUPPORTED_PROBE",
    });
    expect(server.contacts()).toBe(0);
  });

  it.each([
    [
      "vllm",
      "/metrics",
      "vllm:e2e_request_latency_seconds_sum",
      "vllm:e2e_request_latency_seconds",
    ],
    ["sglang", "/metrics", "sglang:num_running_reqs", null],
    [
      "tensorrt-llm",
      "/prometheus/metrics",
      "trtllm_e2e_request_latency_seconds_sum",
      "trtllm_e2e_request_latency_seconds",
    ],
    [
      "tgi",
      "/metrics",
      "tgi_request_duration_sum",
      "tgi_request_duration",
    ],
    ["llama.cpp", "/metrics", "llamacpp:requests_processing", null],
  ] as const)(
    "parses only allowlisted classic Prometheus numbers from %s",
    async (profileId, path, metricName, histogramFamily) => {
      const server = await startServer((_request, response) => {
        response.statusCode = 200;
        response.setHeader(
          "content-type",
          "text/plain; version=0.0.4; charset=utf-8",
        );
        response.end(histogramFamily === null
          ? `# HELP ${metricName} Current operational value.\n`
            + `# TYPE ${metricName} gauge\n`
            + `${metricName}{model="must-not-persist"} 2\n`
            + "unselected_provider_metric 99\n"
          : `# HELP ${histogramFamily} Request latency.\n`
            + `# TYPE ${histogramFamily} histogram\n`
            + `${histogramFamily}_bucket{le="1",model="must-not-persist"} 1\n`
            + `${histogramFamily}_sum{model="must-not-persist"} 2\n`
            + `${histogramFamily}_count{model="must-not-persist"} 1\n`
            + "unselected_provider_metric 99\n");
      });
      const { probe } = fixture({
        server,
        profileId,
        capability: "prometheusMetrics",
        observationEffect: "non-mutating",
        selectedMetricNames: [metricName],
      });

      const result = await deadline(probeRuntimeCapability(probe));

      expect(server.contacts()).toBe(1);
      expect(server.requests()).toMatchObject([{
        method: "GET",
        path,
        accept: "text/plain; version=0.0.4",
      }]);
      expect(result).toMatchObject({
        evidence: {
          capability: "prometheusMetrics",
          state: "supported",
        },
        authorization: null,
        observation: {
          effect: "non-mutating",
          error: null,
          metrics: {
            format: "prometheus",
            method: "GET",
            path,
            effect: "non-mutating",
            selectedMetricNames: [metricName],
            metrics: [{
              name: metricName,
              value: 2,
              timestampMs: null,
            }],
            totalSamples: histogramFamily === null ? 2 : 4,
            ignoredSamples: histogramFamily === null ? 1 : 3,
          },
        },
      });
      expect(JSON.stringify(result)).not.toContain("must-not-persist");
      expect(JSON.stringify(result)).not.toContain(
        "unselected_provider_metric",
      );
    },
  );

  it.each([
    ["sglang", "/health_generate", ""],
    [
      "tensorrt-llm",
      "/health_generate",
      "Generation health check OK",
    ],
  ] as const)(
    "runs exactly one explicit %s readiness canary without minting inference authority",
    async (profileId, path, responseBody) => {
      const server = await startServer((_request, response) => {
        response.statusCode = 200;
        response.end(responseBody);
      });
      const { probe } = fixture({
        server,
        profileId,
        capability: "readiness",
        observationEffect: "inference-canary",
      });

      const result = await deadline(probeRuntimeCapability(probe));

      expect(server.contacts()).toBe(1);
      expect(server.requests()).toMatchObject([{
        method: "GET",
        path,
        accept: "application/json",
      }]);
      expect(server.requests()[0]?.body.byteLength).toBe(0);
      expect(result).toMatchObject({
        evidence: {
          capability: "readiness",
          state: "supported",
        },
        authorization: null,
        observation: {
          effect: "inference-canary",
          dispatchState: "completed",
          statusCode: 200,
          error: null,
          metrics: null,
        },
      });
    },
  );

  it("rejects a non-exact TensorRT generation-health body after one canary", async () => {
    const server = await startServer((_request, response) => {
      response.statusCode = 200;
      response.end("Generation health check OK\n");
    });
    const { probe } = fixture({
      server,
      profileId: "tensorrt-llm",
      capability: "readiness",
      observationEffect: "inference-canary",
    });

    const result = await deadline(probeRuntimeCapability(probe));

    expect(server.contacts()).toBe(1);
    expect(result).toMatchObject({
      evidence: {
        capability: "readiness",
        state: "unknown",
      },
      authorization: null,
      observation: {
        effect: "inference-canary",
        dispatchState: "completed",
        metrics: null,
      },
    });
  });

  it("retains only selected bounded numbers from consumptive TensorRT JSON metrics", async () => {
    const server = await startServer((_request, response) => {
      jsonResponse(response, [{
        gpuMemUsage: 76_665_782_272,
        iter: 154,
        iterLatencyMS: 7.00688362121582,
        kvCacheStats: {
          cacheHitRate: 0.00128,
          freeNumBlocks: 101_253,
          unrecognizedPrivateCounter: 7,
        },
        numActiveRequests: 1,
        privateBackendMessage: "must-not-persist",
      }]);
    });
    const { probe } = fixture({
      server,
      profileId: "tensorrt-llm",
      capability: "jsonMetrics",
      observationEffect: "consumptive",
      selectedMetricNames: [
        "iterLatencyMS",
        "kvCacheStats.cacheHitRate",
      ],
    });

    const result = await deadline(probeRuntimeCapability(probe));

    expect(server.contacts()).toBe(1);
    expect(server.requests()).toMatchObject([{
      method: "GET",
      path: "/metrics",
      accept: "application/json",
    }]);
    expect(result).toMatchObject({
      evidence: {
        capability: "jsonMetrics",
        state: "supported",
      },
      authorization: null,
      observation: {
        effect: "consumptive",
        dispatchState: "completed",
        error: null,
        metrics: {
          format: "json",
          method: "GET",
          path: "/metrics",
          effect: "consumptive",
          selectedMetricNames: [
            "iterLatencyMS",
            "kvCacheStats.cacheHitRate",
          ],
          metrics: [
            {
              name: "iterLatencyMS",
              value: 7.00688362121582,
              timestampMs: null,
            },
            {
              name: "kvCacheStats.cacheHitRate",
              value: 0.00128,
              timestampMs: null,
            },
          ],
          totalSamples: 6,
          ignoredSamples: 4,
        },
      },
    });
    expect(JSON.stringify(result)).not.toContain("must-not-persist");
    expect(JSON.stringify(result)).not.toContain(
      "unrecognizedPrivateCounter",
    );
  });

  it("rejects wrong effects and arbitrary metric namespaces before contact", async () => {
    const server = await startServer((_request, response) => {
      jsonResponse(response, []);
    });
    const readiness = fixture({
      server,
      profileId: "tensorrt-llm",
      capability: "readiness",
      observationEffect: "inference-canary",
    });
    await expect(probeRuntimeCapability({
      ...readiness.probe,
      observationEffect: "non-mutating",
    })).rejects.toMatchObject({ code: "UNSUPPORTED_PROBE" });

    const metrics = fixture({
      server,
      profileId: "tensorrt-llm",
      capability: "jsonMetrics",
      observationEffect: "consumptive",
    });
    await expect(probeRuntimeCapability({
      ...metrics.probe,
      observationEffect: "non-mutating",
    })).rejects.toMatchObject({ code: "UNSUPPORTED_PROBE" });
    await expect(probeRuntimeCapability({
      ...metrics.probe,
      selectedMetricNames: ["judge_score"],
    })).rejects.toBeInstanceOf(RuntimeProbeInputError);
    expect(server.contacts()).toBe(0);
  });

  it("classifies missing classic version and malformed JSON metrics as unknown after one call each", async () => {
    const prometheusServer = await startServer((_request, response) => {
      response.statusCode = 200;
      response.setHeader("content-type", "text/plain");
      response.end("vllm:num_requests_running 1\n");
    });
    const prometheus = fixture({
      server: prometheusServer,
      profileId: "vllm",
      capability: "prometheusMetrics",
      observationEffect: "non-mutating",
    });
    const wrongPrometheus = await deadline(
      probeRuntimeCapability(prometheus.probe),
    );
    expect(wrongPrometheus).toMatchObject({
      evidence: { state: "unknown" },
      authorization: null,
      observation: {
        dispatchState: "completed",
        statusCode: 200,
        metrics: null,
      },
    });
    expect(prometheusServer.contacts()).toBe(1);

    const jsonServer = await startServer((_request, response) => {
      jsonResponse(response, [{ iterLatencyMS: "provider-secret" }]);
    });
    const jsonMetrics = fixture({
      server: jsonServer,
      profileId: "tensorrt-llm",
      capability: "jsonMetrics",
      observationEffect: "consumptive",
    });
    const malformedJson = await deadline(
      probeRuntimeCapability(jsonMetrics.probe),
    );
    expect(malformedJson).toMatchObject({
      evidence: { state: "unknown" },
      authorization: null,
      observation: {
        dispatchState: "completed",
        statusCode: 200,
        metrics: null,
      },
    });
    expect(JSON.stringify(malformedJson)).not.toContain("provider-secret");
    expect(jsonServer.contacts()).toBe(1);
  });

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
