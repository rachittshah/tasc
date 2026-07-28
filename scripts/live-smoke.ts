import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { createSecretKey } from "node:crypto";
import {
  createServer,
  type IncomingMessage,
  type ServerResponse,
} from "node:http";
import type { Socket } from "node:net";
import {
  fingerprintCollectorEndpointBinding,
  getRuntimeProfile,
  invokeRuntime,
  parseCollectorTrustPolicy,
  probeRuntimeCapability,
  type CollectorRouteTrust,
  type CollectorTrustPolicy,
  type RuntimeGenerationRequest,
  type RuntimeInstanceIdentity,
  type RuntimeInvocationRoute,
  type RuntimeProfileId,
} from "../src/index.js";

const OVERALL_DEADLINE_MS = 10_000;
const OPERATION_DEADLINE_MS = 2_000;
const MAX_REQUEST_BYTES = 64 * 1024;
const MODEL = Object.freeze({
  id: "live-smoke-model",
  revision: "fixture-revision-1",
});
const CONFIGURATION_DIGEST = `sha256:${"7".repeat(64)}`;
const PAYLOAD_KEY = createSecretKey(Buffer.alloc(32, 0x73));

interface ObservedRequest {
  readonly method: string;
  readonly path: string;
  readonly body: Buffer;
}

interface FixtureServer {
  readonly origin: string;
  readonly requests: readonly ObservedRequest[];
  readonly failures: readonly Error[];
  close(): Promise<void>;
}

interface RuntimeFixture {
  readonly policy: CollectorTrustPolicy;
  readonly endpointAlias: string;
  readonly instance: RuntimeInstanceIdentity;
}

function withDeadline<T>(
  operation: Promise<T>,
  milliseconds: number,
  label: string,
): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  const deadline = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(
      () => reject(new Error(`${label} exceeded its bounded deadline`)),
      milliseconds,
    );
    timer.unref();
  });
  return Promise.race([operation, deadline]).finally(() => {
    if (timer !== undefined) clearTimeout(timer);
  });
}

async function readBoundedRequest(request: IncomingMessage): Promise<Buffer> {
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of request) {
    const bytes = Buffer.from(chunk);
    total += bytes.byteLength;
    if (total > MAX_REQUEST_BYTES) {
      throw new Error("fixture request exceeded its byte limit");
    }
    chunks.push(bytes);
  }
  return Buffer.concat(chunks, total);
}

function respondJson(response: ServerResponse, value: unknown): void {
  response.statusCode = 200;
  response.setHeader("content-type", "application/json");
  response.end(JSON.stringify(value));
}

function parseFixtureJson(body: Buffer): Record<string, unknown> {
  const value: unknown = JSON.parse(body.toString("utf8"));
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("fixture received a non-object JSON request");
  }
  return value as Record<string, unknown>;
}

async function startFixtureServer(): Promise<FixtureServer> {
  const requests: ObservedRequest[] = [];
  const failures: Error[] = [];
  const sockets = new Set<Socket>();
  let expectedHost = "";

  const handleRequest = async (
    request: IncomingMessage,
    response: ServerResponse,
  ): Promise<void> => {
    if (
      request.socket.remoteAddress !== "127.0.0.1"
      || request.headers.host !== expectedHost
    ) {
      throw new Error("fixture rejected a non-loopback contact");
    }
    const method = request.method ?? "";
    const path = request.url ?? "";
    const body = await readBoundedRequest(request);
    requests.push(Object.freeze({ method, path, body }));

    if (method === "GET" && path === "/health") {
      response.statusCode = 200;
      response.end();
      return;
    }
    if (method === "GET" && path === "/api/version") {
      respondJson(response, { version: getRuntimeProfile("ollama").runtime.build });
      return;
    }
    if (method === "POST" && path === "/v1/completions") {
      const requestBody = parseFixtureJson(body);
      assert.equal(requestBody.model, MODEL.id);
      assert.equal(requestBody.stream, false);
      respondJson(response, {
        model: MODEL.id,
        choices: [{
          index: 0,
          text: "vllm-live",
          finish_reason: "stop",
        }],
        usage: {
          prompt_tokens: 2,
          completion_tokens: 1,
          total_tokens: 3,
        },
      });
      return;
    }
    if (method === "POST" && path === "/api/generate") {
      const requestBody = parseFixtureJson(body);
      assert.equal(requestBody.model, MODEL.id);
      assert.equal(requestBody.stream, true);
      response.statusCode = 200;
      response.setHeader(
        "content-type",
        "application/x-ndjson; charset=utf-8",
      );
      response.write(
        `${JSON.stringify({
          model: MODEL.id,
          response: "ollama-",
          done: false,
        })}\n`,
      );
      response.end(
        `${JSON.stringify({
          model: MODEL.id,
          response: "live",
          done: true,
          done_reason: "stop",
          prompt_eval_count: 2,
          eval_count: 1,
          total_duration: 1_000,
          eval_duration: 500,
        })}\n`,
      );
      return;
    }
    if (method === "POST" && path === "/generate") {
      const requestBody = parseFixtureJson(body);
      assert.equal(requestBody.inputs, "fixture prompt");
      respondJson(response, {
        generated_text: "tgi-live",
        details: {
          finish_reason: "length",
          generated_tokens: 1,
        },
      });
      return;
    }
    response.statusCode = 404;
    response.end();
    throw new Error(`fixture rejected unexpected route ${method} ${path}`);
  };

  const server = createServer((request, response) => {
    void handleRequest(request, response).catch((error: unknown) => {
      failures.push(
        error instanceof Error
          ? error
          : new Error("fixture handler failed unexpectedly"),
      );
      if (!response.headersSent) response.statusCode = 500;
      if (!response.writableEnded) response.end();
    });
  });
  server.on("connection", (socket) => {
    sockets.add(socket);
    socket.once("close", () => sockets.delete(socket));
  });

  await withDeadline(
    new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", () => {
        server.off("error", reject);
        resolve();
      });
    }),
    OPERATION_DEADLINE_MS,
    "fixture startup",
  );
  const address = server.address();
  if (address === null || typeof address === "string") {
    throw new Error("fixture did not expose a TCP address");
  }
  expectedHost = `127.0.0.1:${address.port}`;
  const origin = `http://${expectedHost}`;
  assert.match(origin, /^http:\/\/127\.0\.0\.1:\d+$/u);

  let closed = false;
  return Object.freeze({
    origin,
    requests,
    failures,
    close: async (): Promise<void> => {
      if (closed) return;
      closed = true;
      const completion = new Promise<void>((resolve) => {
        server.close(() => resolve());
      });
      server.closeAllConnections();
      for (const socket of sockets) socket.destroy();
      await withDeadline(completion, OPERATION_DEADLINE_MS, "fixture shutdown");
    },
  });
}

function runtimeFixture(
  origin: string,
  profileId: RuntimeProfileId,
  inferenceRoute: RuntimeInvocationRoute,
): RuntimeFixture {
  const profile = getRuntimeProfile(profileId);
  const health = profile.endpoints.health.liveness;
  const inference = profile.endpoints.inference[inferenceRoute];
  if (health === undefined || inference === undefined) {
    throw new Error("live smoke route is absent from the runtime registry");
  }
  const endpointAlias = `live-smoke-${profileId.replace(".", "-")}`;
  const routes: readonly CollectorRouteTrust[] = Object.freeze([
    Object.freeze({
      method: health.method,
      pathPrefix: health.path,
      authenticationReferences: Object.freeze([]),
    }),
    Object.freeze({
      method: inference.method,
      pathPrefix: inference.path,
      authenticationReferences: Object.freeze([]),
    }),
  ]);
  const policy = parseCollectorTrustPolicy({
    schemaVersion: "tasc-collector-trust-policy-v1",
    localMode: "literal-loopback-only",
    maximumRequestDurationMs: OPERATION_DEADLINE_MS,
    endpoints: [{
      alias: endpointAlias,
      origin,
      runtime: {
        profileId: profile.id,
        build: profile.runtime.build,
      },
      routes,
    }],
    secretReferences: [],
    evaluatorKeyIds: [],
    storeRoots: [],
  });
  return Object.freeze({
    policy,
    endpointAlias,
    instance: Object.freeze({
      endpointDescriptorDigest: fingerprintCollectorEndpointBinding(
        policy,
        endpointAlias,
      ),
      runtime: Object.freeze({
        profileId: profile.id,
        build: profile.runtime.build,
      }),
      backend: Object.freeze({
        name: "live-smoke-fixture",
        build: "1.0.0",
      }),
      model: MODEL,
      configurationDigest: CONFIGURATION_DIGEST,
    }),
  });
}

function generation(
  route: RuntimeInvocationRoute,
  stream: boolean,
): RuntimeGenerationRequest {
  return Object.freeze({
    model: MODEL,
    stream,
    n: 1,
    prompt: "fixture prompt",
    maxTokens: 8,
    temperature: 0,
    seed: 20260728,
  });
}

async function exerciseRuntime(
  fixture: RuntimeFixture,
  route: RuntimeInvocationRoute,
  stream: boolean,
  signal: AbortSignal,
): Promise<Awaited<ReturnType<typeof invokeRuntime>>> {
  const probe = await probeRuntimeCapability({
    policy: fixture.policy,
    endpointAlias: fixture.endpointAlias,
    instance: fixture.instance,
    capability: "liveness",
    observationEffect: "non-mutating",
    totalDeadlineMs: OPERATION_DEADLINE_MS,
    signal,
  });
  assert.equal(probe.evidence.state, "supported");
  assert.equal(probe.observation.dispatchState, "completed");
  assert.equal(probe.observation.error, null);
  assert.equal(probe.authorization, null);

  return invokeRuntime({
    policy: fixture.policy,
    endpointAlias: fixture.endpointAlias,
    instance: fixture.instance,
    route,
    generation: generation(route, stream),
    identity: {
      studyId: "live-smoke-study",
      keyId: "live-smoke-payload-key",
      key: PAYLOAD_KEY,
    },
    totalDeadlineMs: OPERATION_DEADLINE_MS,
    signal,
  });
}

async function main(): Promise<void> {
  const abortController = new AbortController();
  const timer = setTimeout(
    () => abortController.abort(new Error("live smoke deadline exceeded")),
    OVERALL_DEADLINE_MS,
  );
  timer.unref();
  let server: FixtureServer | undefined;
  try {
    server = await startFixtureServer();

    const vllm = await exerciseRuntime(
      runtimeFixture(server.origin, "vllm", "completions"),
      "completions",
      false,
      abortController.signal,
    );
    assert.equal(vllm.status, "completed");
    assert.equal(vllm.output?.text, "vllm-live");

    const ollama = await exerciseRuntime(
      runtimeFixture(server.origin, "ollama", "nativeGenerate"),
      "nativeGenerate",
      true,
      abortController.signal,
    );
    assert.equal(ollama.status, "completed");
    assert.equal(ollama.output?.text, "ollama-live");
    assert.equal(ollama.persistence.eventStreamIdentity?.algorithm, "hmac-sha256");

    const tgi = await exerciseRuntime(
      runtimeFixture(server.origin, "tgi", "nativeGenerate"),
      "nativeGenerate",
      false,
      abortController.signal,
    );
    assert.equal(tgi.status, "incomplete");
    assert.equal(tgi.output?.text, "tgi-live");
    assert.equal(tgi.persistence.resolvedModel, null);

    assert.deepEqual(
      server.requests.map(({ method, path }) => ({ method, path })),
      [
        { method: "GET", path: "/health" },
        { method: "POST", path: "/v1/completions" },
        { method: "GET", path: "/api/version" },
        { method: "POST", path: "/api/generate" },
        { method: "GET", path: "/health" },
        { method: "POST", path: "/generate" },
      ],
    );
    assert.deepEqual(server.failures, []);
    for (const outcome of [vllm, ollama, tgi]) {
      const persisted = JSON.stringify(outcome.persistence);
      assert.equal(persisted.includes("fixture prompt"), false);
      assert.equal(persisted.includes(outcome.output?.text ?? ""), false);
    }

    process.stdout.write(
      "live runtime smoke passed (vLLM, Ollama NDJSON, TGI; 6 loopback contacts)\n",
    );
  } finally {
    clearTimeout(timer);
    abortController.abort();
    if (server !== undefined) await server.close();
  }
}

main().catch((error: unknown) => {
  const message = error instanceof Error
    ? error.message
    : "live runtime smoke failed unexpectedly";
  process.stderr.write(`live runtime smoke failed: ${message}\n`);
  process.exitCode = 1;
});
