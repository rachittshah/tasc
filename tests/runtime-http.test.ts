import { Buffer } from "node:buffer";
import { gzipSync } from "node:zlib";
import {
  createServer,
  type IncomingMessage,
  type ServerResponse,
} from "node:http";
import type { Socket } from "node:net";
import { describe, expect, it } from "vitest";
import {
  authorizeCollectorRequest,
  parseCollectorTrustPolicy,
  pinAuthorizedCollectorRequest,
  type PinnedCollectorRequest,
} from "../src/runtime/network-policy.js";
import {
  RuntimeWireError,
  withBoundedHttpResponse,
  type BoundedRuntimeHttpResponse,
  type RuntimeHttpLimits,
  type RuntimeHttpRequest,
} from "../src/runtime/http.js";
import type { RuntimeBuildIdentity } from "../src/runtime/types.js";

const ENDPOINT_ALIAS = "loopback-vllm";
const RUNTIME = Object.freeze({
  profileId: "vllm" as const,
  build: "0.26.0",
});
const REQUEST_PATH = "/runtime";
const TEST_TIMEOUT_MS = 4_000;

type TestHandler = (
  request: IncomingMessage,
  response: ServerResponse,
) => void | Promise<void>;

interface LoopbackServer {
  readonly origin: string;
  readonly contacts: () => number;
  readonly close: () => Promise<void>;
}

function withDeadline<T>(
  operation: Promise<T>,
  milliseconds = 1_500,
): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(
      () => reject(new Error("test operation exceeded its deadline")),
      milliseconds,
    );
  });
  return Promise.race([operation, timeout]).finally(() => {
    if (timer !== undefined) {
      clearTimeout(timer);
    }
  });
}

async function startLoopbackServer(
  handler: TestHandler,
): Promise<LoopbackServer> {
  let contacts = 0;
  const sockets = new Set<Socket>();
  const server = createServer((request, response) => {
    contacts += 1;
    void Promise.resolve(handler(request, response)).catch(() => {
      response.destroy();
    });
  });
  server.on("connection", (socket) => {
    sockets.add(socket);
    socket.once("close", () => sockets.delete(socket));
  });

  await withDeadline(new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.off("error", reject);
      resolve();
    });
  }));

  const address = server.address();
  if (address === null || typeof address === "string") {
    throw new Error("loopback server did not expose a TCP address");
  }

  return {
    origin: `http://127.0.0.1:${address.port}`,
    contacts: () => contacts,
    close: async () => {
      const socketClosures = [...sockets].map(
        (socket) => new Promise<void>((resolve) => {
          socket.once("close", () => resolve());
        }),
      );
      const closed = new Promise<void>((resolve, reject) => {
        server.close((error) => {
          if (error === undefined) {
            resolve();
          } else {
            reject(error);
          }
        });
      });
      for (const socket of sockets) {
        socket.destroy();
      }
      server.closeAllConnections();
      await withDeadline(
        Promise.all([closed, ...socketClosures]).then(() => undefined),
        1_000,
      );
      expect(sockets.size).toBe(0);
    },
  };
}

async function withLoopbackServer<T>(
  handler: TestHandler,
  run: (server: LoopbackServer) => Promise<T>,
): Promise<T> {
  const server = await startLoopbackServer(handler);
  try {
    return await withDeadline(run(server));
  } finally {
    await server.close();
  }
}

async function mintPin(input: {
  readonly origin: string;
  readonly endpointAlias?: string;
  readonly runtime?: RuntimeBuildIdentity;
  readonly authenticationReference?: string;
  readonly totalDeadlineMs?: number;
  readonly signal?: AbortSignal;
}): Promise<PinnedCollectorRequest> {
  const endpointAlias = input.endpointAlias ?? ENDPOINT_ALIAS;
  const runtime = input.runtime ?? RUNTIME;
  const authenticationReferences =
    input.authenticationReference === undefined
      ? []
      : [input.authenticationReference];
  const policy = parseCollectorTrustPolicy({
    schemaVersion: "tasc-collector-trust-policy-v1",
    localMode: "literal-loopback-only",
    maximumRequestDurationMs: 2_000,
    endpoints: [{
      alias: endpointAlias,
      origin: input.origin,
      runtime,
      routes: [{
        method: "POST",
        pathPrefix: REQUEST_PATH,
        authenticationReferences,
      }],
    }],
    secretReferences: authenticationReferences,
    evaluatorKeyIds: [],
    storeRoots: [],
  });
  const authorization = authorizeCollectorRequest(policy, {
    endpointAlias,
    runtime,
    method: "POST",
    path: REQUEST_PATH,
    ...(input.authenticationReference === undefined
      ? {}
      : { authenticationReference: input.authenticationReference }),
  });
  return pinAuthorizedCollectorRequest(authorization, {
    totalDeadlineMs: input.totalDeadlineMs ?? 1_000,
    ...(input.signal === undefined ? {} : { signal: input.signal }),
  });
}

async function readBody(
  response: BoundedRuntimeHttpResponse,
): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of response.body) {
    chunks.push(Buffer.from(chunk));
  }
  return Buffer.concat(chunks).toString("utf8");
}

async function captureWireError(
  operation: Promise<unknown>,
): Promise<RuntimeWireError> {
  try {
    await operation;
  } catch (error) {
    expect(error).toBeInstanceOf(RuntimeWireError);
    return error as RuntimeWireError;
  }
  throw new Error("expected a RuntimeWireError");
}

describe("bounded runtime HTTP lifecycle", () => {
  it("pins the actual connection, injects only approved secrets, and records observer timing", async () => {
    await withLoopbackServer(async (request, response) => {
      expect(request.method).toBe("POST");
      expect(request.url).toBe(REQUEST_PATH);
      expect(request.headers.authorization).toBe("Bearer test-runtime-key");
      expect(request.headers.accept).toBe("application/json");
      expect(request.headers["accept-encoding"]).toBe("identity");
      expect(request.headers["x-not-authorized"]).toBeUndefined();
      response.statusCode = 200;
      response.setHeader("content-type", "application/json; charset=utf-8");
      response.flushHeaders();
      await new Promise((resolve) => setTimeout(resolve, 20));
      response.end("ok");
    }, async (server) => {
      const pin = await mintPin({
        origin: server.origin,
        authenticationReference: "runtime-test",
      });
      let bodyAccessorReads = 0;
      const requestBody = Buffer.from("{}");
      Object.defineProperty(requestBody, "buffer", {
        configurable: true,
        get() {
          bodyAccessorReads += 1;
          throw new Error("typed-array own getter must not run");
        },
      });
      const result = await withBoundedHttpResponse(
        pin,
        {
          accept: "application/json",
          body: requestBody,
          secretHeaderFactory: (reference, signal) => {
            expect(reference).toBe("runtime-test");
            expect(signal.aborted).toBe(false);
            return [["authorization", "Bearer test-runtime-key"]];
          },
        },
        readBody,
      );

      expect(result).toMatchObject({
        value: "ok",
        statusCode: 200,
        responseBytes: 2,
        target: {
          endpointAlias: ENDPOINT_ALIAS,
          runtime: RUNTIME,
        },
      });
      expect(result.responseChunks).toBeGreaterThanOrEqual(1);
      expect(bodyAccessorReads).toBe(0);
      expect(result.timing.headersMs).toBeGreaterThanOrEqual(0);
      expect(result.timing.firstByteMs).toBeGreaterThanOrEqual(
        result.timing.headersMs ?? 0,
      );
      expect(result.timing.completedMs).toBeGreaterThanOrEqual(
        result.timing.firstByteMs ?? 0,
      );
      expect(server.contacts()).toBe(1);
    });
  }, TEST_TIMEOUT_MS);

  it("classifies an unknown pre-connect failure as a non-dispatched transport failure", async () => {
    const server = await startLoopbackServer((_request, response) => {
      response.end("closed server must not be contacted");
    });
    const origin = server.origin;
    await server.close();

    const error = await withDeadline(captureWireError(
      withBoundedHttpResponse(
        await mintPin({ origin }),
        {},
        readBody,
      ),
    ));
    expect(error).toMatchObject({
      code: "CONNECT_FAILED",
      dispatchState: "not_sent",
      persistedError: {
        category: "transport",
        status: null,
        runtime: "vllm",
      },
    });
    expect(server.contacts()).toBe(0);
  }, TEST_TIMEOUT_MS);

  it("denies redirects without contacting their destination or reading provider details", async () => {
    await withLoopbackServer((_request, response) => {
      response.end("redirect destination must not be contacted");
    }, async (destination) => {
      await withLoopbackServer((_request, response) => {
        response.statusCode = 302;
        response.setHeader(
          "location",
          `${destination.origin}/provider-secret-location`,
        );
        response.end("provider-secret-redirect-body");
      }, async (redirector) => {
        const error = await captureWireError(
          withBoundedHttpResponse(
            await mintPin({ origin: redirector.origin }),
            {},
            readBody,
          ),
        );
        expect(error).toMatchObject({
          code: "REDIRECT_DENIED",
          dispatchState: "completed",
          statusCode: 302,
        });
        expect(error.persistedError).toMatchObject({
          category: "invalid-response",
          runtime: "vllm",
        });
        expect(JSON.stringify(error)).not.toContain("provider-secret");
        expect(destination.contacts()).toBe(0);
        expect(redirector.contacts()).toBe(1);
      });
    });
  }, TEST_TIMEOUT_MS);

  it("rejects compressed responses before invoking the consumer", async () => {
    await withLoopbackServer((_request, response) => {
      response.statusCode = 200;
      response.setHeader("content-encoding", "gzip");
      response.end(gzipSync("provider-secret-compressed"));
    }, async (server) => {
      let consumerCalls = 0;
      const error = await captureWireError(
        withBoundedHttpResponse(
          await mintPin({ origin: server.origin }),
          {},
          async (response) => {
            consumerCalls += 1;
            return readBody(response);
          },
        ),
      );
      expect(error.code).toBe("COMPRESSED_RESPONSE");
      expect(error.dispatchState).toBe("sent_unknown");
      expect(consumerCalls).toBe(0);
      expect(JSON.stringify(error)).not.toContain("provider-secret");
    });
  }, TEST_TIMEOUT_MS);

  it("redacts non-success provider headers, bodies, and authentication failures", async () => {
    const providerSecret = "provider-secret-must-not-persist";
    await withLoopbackServer((_request, response) => {
      response.statusCode = 503;
      response.setHeader("x-provider-detail", providerSecret);
      response.end(providerSecret);
    }, async (server) => {
      const providerError = await captureWireError(
        withBoundedHttpResponse(
          await mintPin({ origin: server.origin }),
          {},
          readBody,
        ),
      );
      expect(providerError).toMatchObject({
        code: "PROVIDER_ERROR",
        dispatchState: "completed",
        statusCode: 503,
        persistedError: {
          category: "invalid-response",
          status: 503,
          runtime: "vllm",
        },
      });
      expect(`${providerError}\n${providerError.stack ?? ""}`).not.toContain(
        providerSecret,
      );
      expect(JSON.stringify(providerError)).not.toContain(providerSecret);
    });

    await withLoopbackServer((_request, response) => {
      response.end("must not be contacted");
    }, async (server) => {
      const credentialSecret = "credential-secret-must-not-persist";
      const error = await captureWireError(
        withBoundedHttpResponse(
          await mintPin({
            origin: server.origin,
            authenticationReference: "runtime-test",
          }),
          {
            secretHeaderFactory: () => {
              throw new Error(credentialSecret);
            },
          },
          readBody,
        ),
      );
      expect(error).toMatchObject({
        code: "AUTHENTICATION_UNAVAILABLE",
        dispatchState: "not_sent",
        persistedError: {
          category: "authentication",
          runtime: "vllm",
        },
      });
      expect(`${error}\n${error.stack ?? ""}`).not.toContain(credentialSecret);
      expect(JSON.stringify(error)).not.toContain(credentialSecret);
      expect(server.contacts()).toBe(0);
    });
  }, TEST_TIMEOUT_MS);

  it("does not trust a consumer-forged RuntimeWireError instance", async () => {
    const secret = "consumer-forged-provider-secret";
    await withLoopbackServer((_request, response) => {
      response.end("complete-body");
    }, async (server) => {
      const forged = new RuntimeWireError({
        code: "PROVIDER_ERROR",
        diagnostic: secret,
        dispatchState: "completed",
        timing: {
          startedAt: "1970-01-01T00:00:00.000Z",
          completedMs: 0,
        },
        persistedError: {
          version: "tasc-persisted-error-v1",
          category: "unknown",
          message: secret,
          status: null,
          runtime: null,
          requestId: null,
        },
      });
      expect(forged).toBeInstanceOf(RuntimeWireError);

      const error = await captureWireError(
        withBoundedHttpResponse(
          await mintPin({ origin: server.origin }),
          {},
          async (response) => {
            await readBody(response);
            throw forged;
          },
        ),
      );
      expect(error).not.toBe(forged);
      expect(error).toMatchObject({
        code: "RESPONSE_REJECTED",
        dispatchState: "completed",
        persistedError: {
          category: "invalid-response",
          runtime: "vllm",
        },
      });
      expect(`${error}\n${error.stack ?? ""}`).not.toContain(secret);
      expect(JSON.stringify(error)).not.toContain(secret);
    });
  }, TEST_TIMEOUT_MS);

  it("does not replay a genuine RuntimeWireError across request lifecycles", async () => {
    const requestAError = await withLoopbackServer((_request, response) => {
      response.statusCode = 503;
      response.end("request-a-provider-error");
    }, async (server) =>
      captureWireError(
        withBoundedHttpResponse(
          await mintPin({
            origin: server.origin,
            endpointAlias: "request-a-vllm",
          }),
          {},
          readBody,
        ),
      )
    );
    expect(requestAError).toMatchObject({
      code: "PROVIDER_ERROR",
      target: {
        endpointAlias: "request-a-vllm",
        runtime: RUNTIME,
      },
    });

    const requestBRuntime = Object.freeze({
      profileId: "sglang" as const,
      build: "0.5.16",
    });
    await withLoopbackServer((_request, response) => {
      response.end("request-b-complete");
    }, async (server) => {
      const error = await captureWireError(
        withBoundedHttpResponse(
          await mintPin({
            origin: server.origin,
            endpointAlias: "request-b-sglang",
            runtime: requestBRuntime,
          }),
          {},
          async (response) => {
            await readBody(response);
            throw requestAError;
          },
        ),
      );

      expect(error).not.toBe(requestAError);
      expect(error).toMatchObject({
        code: "RESPONSE_REJECTED",
        dispatchState: "completed",
        target: {
          endpointAlias: "request-b-sglang",
          runtime: requestBRuntime,
        },
        persistedError: {
          category: "invalid-response",
          runtime: "sglang",
        },
      });
      expect(error.timing).not.toBe(requestAError.timing);
    });
  }, TEST_TIMEOUT_MS);

  it("classifies socket truncation and an undrained consumer as ambiguous", async () => {
    await withLoopbackServer((_request, response) => {
      response.writeHead(200, {
        "content-length": "64",
        "content-type": "application/json",
      });
      response.write("short");
      setTimeout(() => response.socket?.destroy(), 10);
    }, async (server) => {
      const error = await captureWireError(
        withBoundedHttpResponse(
          await mintPin({ origin: server.origin }),
          {},
          readBody,
        ),
      );
      expect(error).toMatchObject({
        code: "RESPONSE_TRUNCATED",
        dispatchState: "sent_unknown",
      });
    });

    await withLoopbackServer((_request, response) => {
      response.end("complete-body");
    }, async (server) => {
      const error = await captureWireError(
        withBoundedHttpResponse(
          await mintPin({ origin: server.origin }),
          {},
          async (response) => {
            for await (const chunk of response.body) {
              return Buffer.from(chunk).toString("utf8");
            }
            return "";
          },
        ),
      );
      expect(error).toMatchObject({
        code: "RESPONSE_NOT_CONSUMED",
        dispatchState: "sent_unknown",
      });
    });
  }, TEST_TIMEOUT_MS);

  it("enforces request, response, chunk, and header bounds", async () => {
    await withLoopbackServer((_request, response) => {
      response.end("must not be contacted");
    }, async (server) => {
      const pin = await mintPin({ origin: server.origin });
      const requestError = await captureWireError(
        withBoundedHttpResponse(
          pin,
          {
            body: Buffer.from("too-large"),
            limits: { maxRequestBytes: 2 },
          },
          readBody,
        ),
      );
      expect(requestError).toMatchObject({
        code: "INVALID_REQUEST",
        dispatchState: "not_sent",
      });
      const replayError = await captureWireError(
        withBoundedHttpResponse(pin, {}, readBody),
      );
      expect(replayError).toMatchObject({
        code: "AUTHORIZATION_REJECTED",
        dispatchState: "not_sent",
      });

      for (const limits of [
        { maxResponseHeaderBytes: 16_385 },
        { maxResponseBytes: 16_777_217 },
        { maxResponseChunks: 16_385 },
        { connectTimeoutMs: 30_001 },
        { headersTimeoutMs: 60_001 },
        { bodyTimeoutMs: 60_001 },
      ] satisfies readonly Partial<RuntimeHttpLimits>[]) {
        const ceilingError = await captureWireError(
          withBoundedHttpResponse(
            await mintPin({ origin: server.origin }),
            { limits },
            readBody,
          ),
        );
        expect(ceilingError).toMatchObject({
          code: "INVALID_REQUEST",
          dispatchState: "not_sent",
        });
      }
      expect(server.contacts()).toBe(0);
    });

    await withLoopbackServer(async (_request, response) => {
      response.write("abc");
      await new Promise((resolve) => setTimeout(resolve, 10));
      response.end("def");
    }, async (server) => {
      const error = await captureWireError(
        withBoundedHttpResponse(
          await mintPin({ origin: server.origin }),
          { limits: { maxResponseBytes: 4 } },
          readBody,
        ),
      );
      expect(error.code).toBe("RESPONSE_TOO_LARGE");
    });

    await withLoopbackServer(async (_request, response) => {
      response.flushHeaders();
      response.write("a");
      await new Promise((resolve) => setTimeout(resolve, 15));
      response.end("b");
    }, async (server) => {
      const error = await captureWireError(
        withBoundedHttpResponse(
          await mintPin({ origin: server.origin }),
          { limits: { maxResponseChunks: 1 } },
          readBody,
        ),
      );
      expect(error.code).toBe("RESPONSE_CHUNK_LIMIT");
    });

    await withLoopbackServer((_request, response) => {
      response.setHeader("x-oversized", "x".repeat(2_048));
      response.end("ok");
    }, async (server) => {
      const error = await captureWireError(
        withBoundedHttpResponse(
          await mintPin({ origin: server.origin }),
          { limits: { maxResponseHeaderBytes: 256 } },
          readBody,
        ),
      );
      expect(error.code).toBe("INVALID_RESPONSE_HEADERS");
    });
  }, TEST_TIMEOUT_MS);

  it("distinguishes header/body timeout, carried total deadline, and caller cancellation", async () => {
    await withLoopbackServer(() => {
      // Deliberately never send headers.
    }, async (server) => {
      const error = await captureWireError(
        withBoundedHttpResponse(
          await mintPin({ origin: server.origin }),
          {
            limits: {
              headersTimeoutMs: 25,
              deadlineMs: 500,
            },
          },
          readBody,
        ),
      );
      expect(error).toMatchObject({
        code: "HEADERS_TIMEOUT",
        dispatchState: "sent_unknown",
      });
    });

    await withLoopbackServer((_request, response) => {
      response.flushHeaders();
      response.write("first");
      // Deliberately never finish the body.
    }, async (server) => {
      const error = await captureWireError(
        withBoundedHttpResponse(
          await mintPin({ origin: server.origin }),
          {
            limits: {
              bodyTimeoutMs: 25,
              deadlineMs: 500,
            },
          },
          readBody,
        ),
      );
      expect(error).toMatchObject({
        code: "BODY_TIMEOUT",
        dispatchState: "sent_unknown",
      });
    });

    await withLoopbackServer((_request, response) => {
      response.end("must not be contacted");
    }, async (server) => {
      const error = await captureWireError(
        withBoundedHttpResponse(
          await mintPin({
            origin: server.origin,
            authenticationReference: "runtime-test",
            totalDeadlineMs: 40,
          }),
          {
            secretHeaderFactory: async () =>
              new Promise<never>(() => undefined),
          },
          readBody,
        ),
      );
      expect(error).toMatchObject({
        code: "DEADLINE_EXCEEDED",
        dispatchState: "not_sent",
      });
      expect(server.contacts()).toBe(0);
    });

    let markReceived: (() => void) | undefined;
    const received = new Promise<void>((resolve) => {
      markReceived = resolve;
    });
    await withLoopbackServer(() => {
      markReceived?.();
      // Deliberately never send a response.
    }, async (server) => {
      const controller = new AbortController();
      const operation = withBoundedHttpResponse(
        await mintPin({ origin: server.origin }),
        { signal: controller.signal },
        readBody,
      );
      await withDeadline(received, 500);
      controller.abort();
      const error = await captureWireError(operation);
      expect(error).toMatchObject({
        code: "CALLER_CANCELLED",
        dispatchState: "sent_unknown",
      });
    });
  }, TEST_TIMEOUT_MS);

  it("rejects forged pins and hostile request/header snapshots without contact or accessor execution", async () => {
    await withLoopbackServer((_request, response) => {
      response.end("must not be contacted");
    }, async (server) => {
      const forged = {
        schemaVersion: "tasc-pinned-collector-request-v1",
        authority: {
          kind: "collector-trust-policy",
          policyDigest: `sha256:${"a".repeat(64)}`,
          authorizationDigest: `sha256:${"b".repeat(64)}`,
        },
      } as unknown as PinnedCollectorRequest;
      const forgedError = await captureWireError(
        withBoundedHttpResponse(forged, {}, readBody),
      );
      expect(forgedError).toMatchObject({
        code: "AUTHORIZATION_REJECTED",
        dispatchState: "not_sent",
      });

      let requestReads = 0;
      const hostileRequest = new Proxy(
        {},
        {
          get() {
            requestReads += 1;
            throw new Error("request accessor must not run");
          },
        },
      ) as RuntimeHttpRequest;
      const hostileError = await captureWireError(
        withBoundedHttpResponse(
          await mintPin({ origin: server.origin }),
          hostileRequest,
          readBody,
        ),
      );
      expect(hostileError.code).toBe("INVALID_REQUEST");
      expect(requestReads).toBe(0);

      let limitReads = 0;
      const hostileLimits = {};
      Object.defineProperty(hostileLimits, "maxResponseBytes", {
        enumerable: true,
        get() {
          limitReads += 1;
          throw new Error("limit accessor must not run");
        },
      });
      const limitError = await captureWireError(
        withBoundedHttpResponse(
          await mintPin({ origin: server.origin }),
          { limits: hostileLimits },
          readBody,
        ),
      );
      expect(limitError.code).toBe("INVALID_REQUEST");
      expect(limitReads).toBe(0);

      let signalReads = 0;
      const hostileSignal = new AbortController().signal;
      Object.defineProperty(hostileSignal, "addEventListener", {
        enumerable: true,
        get() {
          signalReads += 1;
          throw new Error("signal override must not run");
        },
      });
      const signalError = await captureWireError(
        withBoundedHttpResponse(
          await mintPin({ origin: server.origin }),
          { signal: hostileSignal },
          readBody,
        ),
      );
      expect(signalError.code).toBe("INVALID_REQUEST");
      expect(signalReads).toBe(0);

      const forgedSignal = Object.create(
        AbortSignal.prototype,
      ) as AbortSignal;
      const forgedSignalError = await captureWireError(
        withBoundedHttpResponse(
          await mintPin({ origin: server.origin }),
          { signal: forgedSignal },
          readBody,
        ),
      );
      expect(forgedSignalError).toMatchObject({
        code: "INVALID_REQUEST",
        dispatchState: "not_sent",
      });

      let headerReads = 0;
      const headers: unknown[] = [["authorization", "safe-placeholder"]];
      Object.defineProperty(headers, "0", {
        enumerable: true,
        get() {
          headerReads += 1;
          throw new Error("secret accessor must not run");
        },
      });
      const secretError = await captureWireError(
        withBoundedHttpResponse(
          await mintPin({
            origin: server.origin,
            authenticationReference: "runtime-test",
          }),
          {
            secretHeaderFactory: () => headers as never,
          },
          readBody,
        ),
      );
      expect(secretError.code).toBe("AUTHENTICATION_REJECTED");
      expect(headerReads).toBe(0);

      const sharedBodyError = await captureWireError(
        withBoundedHttpResponse(
          await mintPin({ origin: server.origin }),
          { body: new Uint8Array(new SharedArrayBuffer(8)) },
          readBody,
        ),
      );
      expect(sharedBodyError.code).toBe("INVALID_REQUEST");
      expect(server.contacts()).toBe(0);
    });
  }, TEST_TIMEOUT_MS);
});
