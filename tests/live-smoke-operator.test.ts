import { Buffer } from "node:buffer";
import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import {
  createServer,
  type IncomingHttpHeaders,
  type IncomingMessage,
  type ServerResponse,
} from "node:http";
import type { Socket } from "node:net";
import { resolve } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

const repositoryRoot = resolve(import.meta.dirname, "..");
const liveSmokePath = resolve(repositoryRoot, "scripts/live-smoke.ts");
const MODEL_ID = "live-smoke-subprocess-model";
const MODEL_REVISION = "fixture-revision-1";
const CONFIGURATION_DIGEST = `sha256:${"b".repeat(64)}`;
const MAX_CAPTURE_BYTES = 2 * 1024 * 1024;
const PROCESS_TIMEOUT_MS = 15_000;
const TEST_TIMEOUT_MS = PROCESS_TIMEOUT_MS + 5_000;

interface ObservedInferenceRequest {
  readonly method: string;
  readonly path: string;
  readonly remoteAddress: string | undefined;
  readonly authorizationMatches: boolean;
  readonly body: Buffer;
}

interface ContractServer {
  readonly origin: string;
  readonly requests: readonly ObservedInferenceRequest[];
  close(): Promise<void>;
}

interface ProcessResult {
  readonly status: number | null;
  readonly signal: NodeJS.Signals | null;
  readonly stdout: string;
  readonly stderr: string;
  readonly timedOut: boolean;
  readonly captureExceeded: boolean;
}

type Responder = (
  request: IncomingMessage,
  response: ServerResponse,
) => void;

const activeServers = new Set<ContractServer>();

async function readBoundedBody(request: IncomingMessage): Promise<Buffer> {
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of request) {
    const bytes = Buffer.from(chunk);
    total += bytes.byteLength;
    if (total > 64 * 1024) {
      throw new Error("operator smoke test request exceeded its bound");
    }
    chunks.push(bytes);
  }
  return Buffer.concat(chunks, total);
}

async function startContractServer(
  expectedSecret: string,
  responder: Responder,
): Promise<ContractServer> {
  const requests: ObservedInferenceRequest[] = [];
  const sockets = new Set<Socket>();
  const server = createServer((request, response) => {
    void readBoundedBody(request).then((body) => {
      const headers: IncomingHttpHeaders = request.headers;
      requests.push(Object.freeze({
        method: request.method ?? "",
        path: request.url ?? "",
        remoteAddress: request.socket.remoteAddress,
        authorizationMatches:
          headers.authorization === expectedSecret,
        body,
      }));
      responder(request, response);
    }).catch(() => response.destroy());
  });
  server.on("connection", (socket) => {
    sockets.add(socket);
    socket.once("close", () => sockets.delete(socket));
  });
  await new Promise<void>((resolveListen, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.off("error", reject);
      resolveListen();
    });
  });
  const address = server.address();
  if (address === null || typeof address === "string") {
    throw new Error("operator smoke test server address is unavailable");
  }
  let closed = false;
  const contract: ContractServer = Object.freeze({
    origin: `http://127.0.0.1:${address.port}`,
    requests,
    close: async (): Promise<void> => {
      if (closed) return;
      closed = true;
      const completion = new Promise<void>((resolveClose) => {
        server.close(() => resolveClose());
      });
      server.closeAllConnections();
      for (const socket of sockets) socket.destroy();
      await completion;
      activeServers.delete(contract);
    },
  });
  activeServers.add(contract);
  return contract;
}

function isolatedChildEnvironment(
  origin: string,
  secret: string,
): NodeJS.ProcessEnv {
  const environment: NodeJS.ProcessEnv = {};
  for (const [key, value] of Object.entries(process.env)) {
    if (
      key === "CI"
      || key === "GITHUB_ACTIONS"
      || key.startsWith("TASC_LIVE_SMOKE_")
      || key === "TASC_RUNTIME_AUTH_LIVE_SMOKE_TEST"
    ) {
      continue;
    }
    environment[key] = value;
  }
  return {
    ...environment,
    TASC_LIVE_SMOKE_ENDPOINT: origin,
    TASC_LIVE_SMOKE_RUNTIME: "ollama",
    TASC_LIVE_SMOKE_RUNTIME_BUILD: "0.32.5",
    TASC_LIVE_SMOKE_ROUTE: "nativeGenerate",
    TASC_LIVE_SMOKE_MODEL_ID: MODEL_ID,
    TASC_LIVE_SMOKE_MODEL_REVISION: MODEL_REVISION,
    TASC_LIVE_SMOKE_BACKEND_NAME: "fixture-cpu",
    TASC_LIVE_SMOKE_BACKEND_BUILD: "1.0.0",
    TASC_LIVE_SMOKE_CONFIGURATION_DIGEST: CONFIGURATION_DIGEST,
    TASC_LIVE_SMOKE_ALLOW_LOOPBACK: "1",
    TASC_LIVE_SMOKE_AUTH_ENV: "TASC_RUNTIME_AUTH_LIVE_SMOKE_TEST",
    TASC_LIVE_SMOKE_AUTH_HEADER: "authorization",
    TASC_RUNTIME_AUTH_LIVE_SMOKE_TEST: secret,
  };
}

async function runOperatorProcess(
  origin: string,
  secret: string,
): Promise<ProcessResult> {
  const child = spawn(
    process.execPath,
    ["--import", "tsx", liveSmokePath],
    {
      cwd: repositoryRoot,
      env: isolatedChildEnvironment(origin, secret),
      stdio: ["ignore", "pipe", "pipe"],
    },
  );
  let stdout: Buffer = Buffer.alloc(0);
  let stderr: Buffer = Buffer.alloc(0);
  let timedOut = false;
  let captureExceeded = false;
  const append = (current: Buffer, chunk: Buffer): Buffer => {
    const nextLength = current.byteLength + chunk.byteLength;
    if (nextLength > MAX_CAPTURE_BYTES) {
      captureExceeded = true;
      child.kill("SIGKILL");
      return current;
    }
    return Buffer.concat([current, chunk], nextLength);
  };
  child.stdout.on("data", (chunk: Buffer) => {
    stdout = append(stdout, chunk);
  });
  child.stderr.on("data", (chunk: Buffer) => {
    stderr = append(stderr, chunk);
  });
  const timer = setTimeout(() => {
    timedOut = true;
    child.kill("SIGKILL");
  }, PROCESS_TIMEOUT_MS);
  const result = await new Promise<{
    readonly status: number | null;
    readonly signal: NodeJS.Signals | null;
  }>((resolveClose, reject) => {
    child.once("error", reject);
    child.once("close", (status, signal) => {
      resolveClose({ status, signal });
    });
  }).finally(() => clearTimeout(timer));
  return Object.freeze({
    ...result,
    stdout: stdout.toString("utf8"),
    stderr: stderr.toString("utf8"),
    timedOut,
    captureExceeded,
  });
}

function parseRequestBody(
  request: ObservedInferenceRequest,
): Readonly<Record<string, unknown>> {
  const value: unknown = JSON.parse(request.body.toString("utf8"));
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("operator smoke test request is not a JSON object");
  }
  return value as Readonly<Record<string, unknown>>;
}

function assertFixedRequest(
  request: ObservedInferenceRequest,
): string {
  expect(request.method).toBe("POST");
  expect(request.path).toBe("/api/generate");
  expect(request.remoteAddress).toBe("127.0.0.1");
  expect(request.authorizationMatches).toBe(true);
  const body = parseRequestBody(request);
  expect(Reflect.ownKeys(body).sort()).toEqual([
    "model",
    "options",
    "prompt",
    "stream",
  ]);
  expect(body.model).toBe(MODEL_ID);
  expect(body.stream).toBe(false);
  expect(body.options).toEqual({
    num_predict: 8,
    temperature: 0,
  });
  expect(typeof body.prompt).toBe("string");
  const prompt = body.prompt as string;
  expect(prompt.startsWith("TASC operator live smoke ")).toBe(true);
  expect(
    /^TASC operator live smoke [a-f0-9]{32}\. Reply with a short acknowledgement\.$/u
      .test(prompt),
  ).toBe(true);
  return prompt;
}

function assertRawFreeOutput(
  result: ProcessResult,
  values: readonly string[],
): void {
  for (const value of values) {
    expect(result.stdout.includes(value)).toBe(false);
    expect(result.stderr.includes(value)).toBe(false);
  }
}

afterEach(async () => {
  await Promise.all([...activeServers].map((server) => server.close()));
});

describe("operator-real live smoke subprocess", () => {
  it("performs exactly one bounded Ollama inference and emits raw-free metadata", async () => {
    const secret = `Bearer ${randomBytes(24).toString("base64url")}`;
    const providerOutput =
      `provider-output-${randomBytes(24).toString("hex")}`;
    const server = await startContractServer(
      secret,
      (_request, response) => {
        response.statusCode = 200;
        response.setHeader("content-type", "application/json");
        response.end(JSON.stringify({
          model: MODEL_ID,
          response: providerOutput,
          done: true,
          done_reason: "stop",
          prompt_eval_count: 6,
          eval_count: 1,
          total_duration: 1_000,
          load_duration: 100,
          prompt_eval_duration: 500,
          eval_duration: 400,
        }));
      },
    );
    try {
      const result = await runOperatorProcess(server.origin, secret);

      expect(result.timedOut).toBe(false);
      expect(result.captureExceeded).toBe(false);
      expect(result.status).toBe(0);
      expect(result.signal).toBeNull();
      expect(result.stderr).toBe("");
      expect(server.requests).toHaveLength(1);
      const prompt = assertFixedRequest(server.requests[0]!);
      assertRawFreeOutput(result, [
        prompt,
        providerOutput,
        secret,
        server.origin,
        "TASC_RUNTIME_AUTH_LIVE_SMOKE_TEST",
        "operator-live-smoke-auth",
      ]);
      const output: unknown = JSON.parse(result.stdout);
      expect(output).toMatchObject({
        schemaVersion: "tasc-operator-live-smoke-result-v1",
        mode: "operator-real",
        authority: "observation-only-no-deployment-authority",
        instance: {
          runtime: { profileId: "ollama", build: "0.32.5" },
          model: { id: MODEL_ID, revision: MODEL_REVISION },
          configurationDigest: CONFIGURATION_DIGEST,
        },
        invocation: {
          status: "completed",
          dispatchState: "completed",
          route: "nativeGenerate",
          finalUsage: "present",
          partialOutput: false,
          providerUsage: {
            inputTokens: 6,
            outputTokens: 1,
            totalTokens: 7,
          },
          error: null,
        },
      });
    } finally {
      await server.close();
    }
  }, TEST_TIMEOUT_MS);

  it("fails closed on a malformed provider response without reflecting it", async () => {
    const secret = `Bearer ${randomBytes(24).toString("base64url")}`;
    const malformedProviderBody =
      `{"raw":"provider-body-${randomBytes(24).toString("hex")}"`;
    const server = await startContractServer(
      secret,
      (_request, response) => {
        response.statusCode = 200;
        response.setHeader("content-type", "application/json");
        response.end(malformedProviderBody);
      },
    );
    try {
      const result = await runOperatorProcess(server.origin, secret);

      expect(result.timedOut).toBe(false);
      expect(result.captureExceeded).toBe(false);
      expect(result.status).toBe(1);
      expect(result.signal).toBeNull();
      expect(result.stderr).toBe("live runtime smoke failed.\n");
      expect(server.requests).toHaveLength(1);
      const prompt = assertFixedRequest(server.requests[0]!);
      assertRawFreeOutput(result, [
        prompt,
        malformedProviderBody,
        secret,
        server.origin,
        "TASC_RUNTIME_AUTH_LIVE_SMOKE_TEST",
        "operator-live-smoke-auth",
      ]);
      const output: unknown = JSON.parse(result.stdout);
      expect(output).toMatchObject({
        schemaVersion: "tasc-operator-live-smoke-result-v1",
        mode: "operator-real",
        invocation: {
          status: "failed",
          dispatchState: "completed",
          partialOutput: false,
          error: {
            category: "invalid-response",
          },
        },
      });
    } finally {
      await server.close();
    }
  }, TEST_TIMEOUT_MS);
});
