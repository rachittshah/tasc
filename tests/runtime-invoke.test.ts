import { Buffer } from "node:buffer";
import { createSecretKey } from "node:crypto";
import {
  createServer,
  type IncomingMessage,
  type ServerResponse,
} from "node:http";
import type { Socket } from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import { createStudyPayloadIdentity } from "../src/references.js";
import {
  invokeRuntime,
  RuntimeInvocationInputError,
  type RuntimeGenerationRequest,
  type RuntimeInvocationInput,
  type RuntimeInvocationRoute,
} from "../src/runtime/invoke.js";
import {
  fingerprintCollectorEndpointBinding,
  parseCollectorTrustPolicy,
  type CollectorTrustPolicy,
} from "../src/runtime/network-policy.js";
import {
  probeRuntimeCapability,
  type RuntimeCapabilityAuthorization,
} from "../src/runtime/probe.js";
import { getRuntimeProfile } from "../src/runtime/profiles.js";
import type {
  EndpointDescriptor,
  RuntimeInstanceIdentity,
  RuntimeProfileId,
} from "../src/runtime/types.js";

const TEST_TIMEOUT_MS = 5_000;
const MODEL = Object.freeze({
  id: "test-model",
  revision: "rev-1",
});
const IDENTITY = Object.freeze({
  studyId: "invoke-study",
  keyId: "invoke-payload-key",
  key: createSecretKey(Buffer.alloc(32, 0x51)),
});
const DIGEST = `sha256:${"a".repeat(64)}`;
const DIGEST_B = `sha256:${"b".repeat(64)}`;

type Handler = (
  request: IncomingMessage,
  response: ServerResponse,
) => void | Promise<void>;

interface TestServer {
  readonly origin: string;
  readonly contacts: () => number;
  readonly requests: () => readonly {
    readonly accept: string | undefined;
    readonly body: Uint8Array;
    readonly path: string | undefined;
  }[];
  close(): Promise<void>;
}

const activeServers = new Set<TestServer>();

function deadline<T>(promise: Promise<T>, milliseconds = 2_000): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(
      () => reject(new Error("invoke test exceeded its deadline")),
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
  const requests: {
    accept: string | undefined;
    body: Uint8Array;
    path: string | undefined;
  }[] = [];
  const sockets = new Set<Socket>();
  const server = createServer((request, response) => {
    contacts += 1;
    void readRequest(request).then((body) => {
      requests.push({
        accept: request.headers.accept,
        body,
        path: request.url,
      });
      return handler(request, response);
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

function generation(
  route: RuntimeInvocationRoute,
  stream: boolean,
): RuntimeGenerationRequest {
  const chat = route === "chatCompletions" || route === "nativeChat";
  return {
    model: MODEL,
    stream,
    n: 1,
    ...(chat
      ? {
        messages: [{
          role: "user" as const,
          content: "private prompt must not persist",
        }],
      }
      : { prompt: "private prompt must not persist" }),
    maxTokens: 32,
    temperature: 0,
    seed: 7,
  };
}

function fixture(input: {
  readonly server: TestServer;
  readonly profileId: RuntimeProfileId;
  readonly route: RuntimeInvocationRoute;
  readonly stream: boolean;
}): {
  readonly policy: CollectorTrustPolicy;
  readonly instance: RuntimeInstanceIdentity;
  readonly invocation: RuntimeInvocationInput;
} {
  const profile = getRuntimeProfile(input.profileId);
  const route = profile.endpoints.inference[input.route];
  if (route === undefined) throw new Error("test route is not declared");
  const policy = parseCollectorTrustPolicy({
    schemaVersion: "tasc-collector-trust-policy-v1",
    localMode: "literal-loopback-only",
    maximumRequestDurationMs: 2_000,
    endpoints: [{
      alias: `local-${input.profileId.replace(".", "-")}`,
      origin: input.server.origin,
      runtime: {
        profileId: profile.id,
        build: profile.runtime.build,
      },
      routes: [{
        method: "POST",
        pathPrefix: route.path,
        authenticationReferences: [],
      }],
    }],
    secretReferences: [],
    evaluatorKeyIds: [],
    storeRoots: [],
  });
  const endpointAlias = policy.endpoints[0]!.alias;
  const instance: RuntimeInstanceIdentity = {
    endpointDescriptorDigest: fingerprintCollectorEndpointBinding(
      policy,
      endpointAlias,
    ),
    runtime: {
      profileId: profile.id,
      build: profile.runtime.build,
    },
    backend: {
      name: "contract-backend",
      build: "1.0.0",
    },
    model: MODEL,
    configurationDigest: DIGEST,
  };
  return {
    policy,
    instance,
    invocation: {
      policy,
      endpointAlias,
      instance,
      route: input.route,
      generation: generation(input.route, input.stream),
      identity: IDENTITY,
      totalDeadlineMs: 1_500,
    },
  };
}

function jsonResponse(
  response: ServerResponse,
  value: unknown,
  contentType = "application/json",
): void {
  response.statusCode = 200;
  response.setHeader("content-type", contentType);
  response.end(JSON.stringify(value));
}

describe("runtime invocation foundation", () => {
  it("sends one canonical vLLM completion request and returns raw-free immutable JSON normalization", async () => {
    const server = await startServer((_request, response) => {
      jsonResponse(response, {
        id: "completion-1",
        object: "text_completion",
        model: MODEL.id,
        choices: [{
          index: 0,
          text: "hello",
          finish_reason: "stop",
          logprobs: null,
        }],
        usage: {
          prompt_tokens: 2,
          completion_tokens: 1,
          total_tokens: 3,
        },
      });
    });
    const { invocation } = fixture({
      server,
      profileId: "vllm",
      route: "completions",
      stream: false,
    });

    const outcome = await deadline(invokeRuntime(invocation));

    expect(server.contacts()).toBe(1);
    expect(server.requests()).toHaveLength(1);
    expect(server.requests()[0]).toMatchObject({
      accept: "application/json",
      path: "/v1/completions",
    });
    const sent = server.requests()[0]!.body;
    expect(JSON.parse(Buffer.from(sent).toString("utf8"))).toEqual({
      max_tokens: 32,
      model: MODEL.id,
      n: 1,
      prompt: "private prompt must not persist",
      seed: 7,
      stream: false,
      temperature: 0,
    });
    expect(outcome).toMatchObject({
      status: "completed",
      output: {
        text: "hello",
        metadata: {
          choiceCount: 1,
          logprobsObserved: false,
        },
      },
      persistence: {
        dispatchState: "completed",
        finalUsage: "present",
        finishReason: "stop",
        providerUsage: {
          inputTokens: 2,
          outputTokens: 1,
          totalTokens: 3,
        },
      },
    });
    expect(outcome.persistence.requestIdentity).toEqual(
      createStudyPayloadIdentity(
        IDENTITY.studyId,
        IDENTITY.keyId,
        IDENTITY.key,
        sent,
      ),
    );
    expect(outcome.persistence.terminalOutputIdentity).toEqual(
      createStudyPayloadIdentity(
        IDENTITY.studyId,
        IDENTITY.keyId,
        IDENTITY.key,
        Buffer.from("hello", "utf8"),
      ),
    );
    const persisted = JSON.stringify(outcome.persistence);
    expect(persisted).not.toContain("private prompt");
    expect(persisted).not.toContain("hello");
    expect(Object.isFrozen(outcome)).toBe(true);
    expect(Object.isFrozen(outcome.persistence)).toBe(true);
    expect(Object.isFrozen(outcome.output)).toBe(true);
  });

  it("parses vLLM SSE without changing identity across HTTP chunk boundaries", async () => {
    const frames = [
      "data: {\"model\":\"test-model\",\"choices\":[{\"index\":0,\"text\":\"hel\",\"finish_reason\":null}]}\n\n",
      "data: {\"model\":\"test-model\",\"choices\":[{\"index\":0,\"text\":\"lo\",\"finish_reason\":\"stop\"}]}\n\n",
      "data: {\"model\":\"test-model\",\"choices\":[],\"usage\":{\"prompt_tokens\":2,\"completion_tokens\":1,\"total_tokens\":3}}\n\n",
      "data: [DONE]\n\n",
    ];
    const raw = Buffer.from(frames.join(""));
    const server = await startServer((_request, response) => {
      response.statusCode = 200;
      response.setHeader("content-type", "text/event-stream");
      for (const frame of frames) response.write(frame);
      response.end();
    });
    const { invocation } = fixture({
      server,
      profileId: "vllm",
      route: "completions",
      stream: true,
    });

    const outcome = await deadline(invokeRuntime(invocation));

    expect(server.contacts()).toBe(1);
    expect(server.requests()[0]?.accept).toBe("text/event-stream");
    expect(outcome).toMatchObject({
      status: "completed",
      output: { text: "hello" },
      persistence: {
        finalUsage: "present",
        finishReason: "stop",
      },
    });
    expect(outcome.persistence.responseIdentity).toEqual(
      createStudyPayloadIdentity(
        IDENTITY.studyId,
        IDENTITY.keyId,
        IDENTITY.key,
        raw,
      ),
    );
    expect(outcome.persistence.eventStreamIdentity)
      .toEqual(outcome.persistence.responseIdentity);
  });

  it("parses exact Ollama native-chat NDJSON with terminal usage and nanosecond timing", async () => {
    const server = await startServer((_request, response) => {
      response.statusCode = 200;
      response.setHeader("content-type", "application/x-ndjson");
      response.write(
        "{\"model\":\"test-model\",\"message\":{\"content\":\"ol\"},\"done\":false}\n",
      );
      response.end(
        "{\"model\":\"test-model\",\"message\":{\"content\":\"lama\"},"
        + "\"done\":true,\"done_reason\":\"stop\","
        + "\"prompt_eval_count\":2,\"eval_count\":2,"
        + "\"total_duration\":1000,\"eval_duration\":500}\n",
      );
    });
    const { invocation } = fixture({
      server,
      profileId: "ollama",
      route: "nativeChat",
      stream: true,
    });

    const outcome = await deadline(invokeRuntime(invocation));

    expect(server.contacts()).toBe(1);
    expect(server.requests()[0]?.accept).toBe("application/x-ndjson");
    expect(outcome).toMatchObject({
      status: "completed",
      output: { text: "ollama" },
      persistence: {
        finishReason: "stop",
        providerUsage: {
          inputTokens: 2,
          outputTokens: 2,
          totalTokens: 4,
        },
        providerTiming: {
          totalDurationNs: 1000,
          evaluationDurationNs: 500,
        },
      },
    });
  });

  it("requires exact opaque probe authority for conditional routes without confused-deputy I/O", async () => {
    let responseIndex = 0;
    const server = await startServer((_request, response) => {
      responseIndex += 1;
      jsonResponse(response, {
        model: MODEL.id,
        choices: [{
          index: 0,
          message: {
            role: "assistant",
            content: responseIndex === 1 ? "probe" : "invoked",
          },
          finish_reason: "stop",
        }],
        usage: {
          prompt_tokens: 1,
          completion_tokens: 1,
          total_tokens: 2,
        },
      });
    });
    const conditional = fixture({
      server,
      profileId: "ollama",
      route: "chatCompletions",
      stream: false,
    });
    const authorizedInvocation: RuntimeInvocationInput = {
      ...conditional.invocation,
      totalDeadlineMs: 500,
    };
    const probe = await deadline(probeRuntimeCapability({
      policy: conditional.policy,
      endpointAlias: authorizedInvocation.endpointAlias,
      instance: conditional.instance,
      capability: "chatCompletions",
      observationEffect: "inference-canary",
      totalDeadlineMs: 1_500,
      authorizationTtlMs: 2_000,
    }));
    expect(probe.authorization).not.toBeNull();
    const authorization = probe.authorization!;
    expect(server.contacts()).toBe(1);

    const outcome = await deadline(invokeRuntime({
      ...authorizedInvocation,
      capabilityAuthorizations: [authorization],
    }));

    expect(outcome).toMatchObject({
      status: "completed",
      output: { text: "invoked" },
      persistence: {
        resolvedModel: { id: MODEL.id },
        terminalOutputIdentity: expect.any(Object),
      },
    });
    expect(server.contacts()).toBe(2);
    expect(server.requests().map((request) => request.path)).toEqual([
      "/v1/chat/completions",
      "/v1/chat/completions",
    ]);

    const rejectWithoutContact = async (
      invocation: RuntimeInvocationInput,
      code: string,
    ): Promise<void> => {
      await expect(invokeRuntime(invocation)).rejects.toMatchObject({
        code,
        persistedError: { category: "authorization" },
      });
      expect(server.contacts()).toBe(2);
    };
    await rejectWithoutContact(
      authorizedInvocation,
      "CONDITIONAL_CAPABILITY_REQUIRES_AUTHORIZATION",
    );
    await rejectWithoutContact({
      ...authorizedInvocation,
      capabilityAuthorizations: [{ ...authorization }],
    }, "CAPABILITY_AUTHORIZATION_REJECTED");
    await rejectWithoutContact({
      ...authorizedInvocation,
      capabilityAuthorizations: [
        JSON.parse(
          JSON.stringify(authorization),
        ) as RuntimeCapabilityAuthorization,
      ],
    }, "CAPABILITY_AUTHORIZATION_REJECTED");
    await rejectWithoutContact({
      ...authorizedInvocation,
      capabilityAuthorizations: [structuredClone(authorization)],
    }, "CAPABILITY_AUTHORIZATION_REJECTED");
    await rejectWithoutContact({
      ...authorizedInvocation,
      route: "completions",
      generation: generation("completions", false),
      capabilityAuthorizations: [authorization],
    }, "CAPABILITY_AUTHORIZATION_REJECTED");
    await rejectWithoutContact({
      ...authorizedInvocation,
      instance: {
        ...conditional.instance,
        configurationDigest: DIGEST_B,
      },
      capabilityAuthorizations: [authorization],
    }, "CAPABILITY_AUTHORIZATION_REJECTED");
    await rejectWithoutContact({
      ...authorizedInvocation,
      capabilityAuthorizations: [authorization, authorization],
    }, "CAPABILITY_AUTHORIZATION_REJECTED");
    await rejectWithoutContact({
      ...authorizedInvocation,
      route: "nativeChat",
      generation: generation("nativeChat", false),
      capabilityAuthorizations: [authorization],
    }, "CAPABILITY_AUTHORIZATION_REJECTED");
  });

  it("rejects conditional authority that cannot cover the invocation deadline", async () => {
    const server = await startServer((_request, response) => {
      jsonResponse(response, {
        model: MODEL.id,
        choices: [{
          index: 0,
          message: { role: "assistant", content: "probe" },
          finish_reason: "stop",
        }],
      });
    });
    const conditional = fixture({
      server,
      profileId: "ollama",
      route: "chatCompletions",
      stream: false,
    });
    const probe = await deadline(probeRuntimeCapability({
      policy: conditional.policy,
      endpointAlias: conditional.invocation.endpointAlias,
      instance: conditional.instance,
      capability: "chatCompletions",
      observationEffect: "inference-canary",
      totalDeadlineMs: 1_500,
      authorizationTtlMs: 250,
    }));
    expect(probe.authorization).not.toBeNull();
    expect(server.contacts()).toBe(1);

    const invocation = {
      ...conditional.invocation,
      capabilityAuthorizations: [probe.authorization!],
    };
    await expect(invokeRuntime(invocation)).rejects.toMatchObject({
      code: "CAPABILITY_AUTHORIZATION_REJECTED",
      persistedError: { category: "authorization" },
    });
    expect(server.contacts()).toBe(1);

    await new Promise((resolve) => setTimeout(resolve, 275));
    await expect(invokeRuntime(invocation)).rejects.toMatchObject({
      code: "CAPABILITY_AUTHORIZATION_REJECTED",
      persistedError: { category: "authorization" },
    });
    expect(server.contacts()).toBe(1);
  });

  it("rejects invalid DTOs and endpoint bindings before any contact", async () => {
    const server = await startServer((_request, response) => {
      jsonResponse(response, {});
    });
    const valid = fixture({
      server,
      profileId: "vllm",
      route: "completions",
      stream: false,
    });
    const badBinding = {
      ...valid.invocation,
      instance: {
        ...valid.instance,
        endpointDescriptorDigest: `sha256:${"b".repeat(64)}`,
      },
    };
    await expect(invokeRuntime(badBinding)).rejects.toMatchObject({
      code: "ENDPOINT_BINDING_MISMATCH",
    });

    await expect(invokeRuntime({
      ...valid.invocation,
      route: "nativeChat",
      generation: generation("nativeChat", false),
    })).rejects.toMatchObject({ code: "UNSUPPORTED_ROUTE" });

    const unknown = {
      ...valid.invocation,
      generation: {
        ...valid.invocation.generation,
        url: "http://metadata.invalid",
      },
    };
    await expect(invokeRuntime(unknown as RuntimeInvocationInput))
      .rejects.toBeInstanceOf(RuntimeInvocationInputError);

    await expect(invokeRuntime({
      ...valid.invocation,
      httpLimits: { deadlineMs: 300_001 },
    })).rejects.toMatchObject({ code: "INVALID_INPUT" });

    const controller = new AbortController();
    controller.abort();
    const cancelled = await invokeRuntime({
      ...valid.invocation,
      signal: controller.signal,
    });
    expect(cancelled).toMatchObject({
      status: "failed",
      output: null,
      persistence: {
        dispatchState: "not_sent",
        abortLifecycle: "caller-cancelled-before-dispatch",
        terminalOutputIdentity: null,
        error: { category: "cancelled" },
      },
    });
    expect(server.contacts()).toBe(0);
  });

  it("snapshots a descriptor once and rejects hostile descriptor accessors without invoking them", async () => {
    const server = await startServer((_request, response) => {
      jsonResponse(response, {
        model: MODEL.id,
        choices: [{
          index: 0,
          text: "bound",
          finish_reason: "stop",
        }],
        usage: {
          prompt_tokens: 1,
          completion_tokens: 1,
          total_tokens: 2,
        },
      });
    });
    const profile = getRuntimeProfile("vllm");
    const mutableDescriptor = {
      schemaVersion: "tasc-endpoint-descriptor-v1" as const,
      origin: server.origin,
      basePath: "/serve",
      runtime: {
        profileId: "vllm" as const,
        build: profile.runtime.build,
      },
      orchestration: {
        kind: "ray-serve" as const,
        build: "2.56.1",
        configurationDigest: DIGEST,
        locator: {
          applicationName: "application",
          deploymentName: "deployment",
        },
      },
      authority: {
        deployment: "none" as const,
        network: "unverified" as const,
      },
    };
    const policy = parseCollectorTrustPolicy({
      schemaVersion: "tasc-collector-trust-policy-v1",
      localMode: "literal-loopback-only",
      maximumRequestDurationMs: 2_000,
      endpoints: [{
        alias: "local-ray-vllm",
        origin: server.origin,
        runtime: {
          profileId: profile.id,
          build: profile.runtime.build,
        },
        routes: [{
          method: "POST",
          pathPrefix: "/serve/v1/completions",
          authenticationReferences: [],
        }],
      }],
      secretReferences: [],
      evaluatorKeyIds: [],
      storeRoots: [],
    });
    const endpointAlias = policy.endpoints[0]!.alias;
    const instance: RuntimeInstanceIdentity = {
      endpointDescriptorDigest: fingerprintCollectorEndpointBinding(
        policy,
        endpointAlias,
        mutableDescriptor,
      ),
      runtime: {
        profileId: profile.id,
        build: profile.runtime.build,
      },
      backend: {
        name: "contract-backend",
        build: "1.0.0",
      },
      model: MODEL,
      configurationDigest: DIGEST,
    };
    const invocation: RuntimeInvocationInput = {
      policy,
      endpointAlias,
      endpointDescriptor: mutableDescriptor as EndpointDescriptor,
      instance,
      route: "completions",
      generation: generation("completions", false),
      identity: IDENTITY,
      totalDeadlineMs: 1_500,
    };

    let getterReads = 0;
    const hostileDescriptor = {
      ...mutableDescriptor,
      runtime: { ...mutableDescriptor.runtime },
      orchestration: {
        ...mutableDescriptor.orchestration,
        locator: { ...mutableDescriptor.orchestration.locator },
      },
      authority: { ...mutableDescriptor.authority },
    };
    Object.defineProperty(hostileDescriptor, "basePath", {
      enumerable: true,
      get: () => {
        getterReads += 1;
        return "/serve";
      },
    });
    await expect(invokeRuntime({
      ...invocation,
      endpointDescriptor: hostileDescriptor as EndpointDescriptor,
    })).rejects.toMatchObject({ code: "INVALID_INPUT" });
    expect(getterReads).toBe(0);
    expect(server.contacts()).toBe(0);

    const pending = invokeRuntime(invocation);
    mutableDescriptor.basePath = "/mutated";
    mutableDescriptor.origin = "http://127.0.0.1:1";
    mutableDescriptor.runtime.build = "mutated";
    mutableDescriptor.orchestration.locator.deploymentName = "mutated";
    const outcome = await deadline(pending);

    expect(outcome.status).toBe("completed");
    expect(server.contacts()).toBe(1);
    expect(server.requests()[0]?.path).toBe("/serve/v1/completions");
  });

  it("rejects the non-contract application/ndjson alias", async () => {
    const server = await startServer((_request, response) => {
      response.statusCode = 200;
      response.setHeader("content-type", "application/ndjson");
      response.end(
        "{\"model\":\"test-model\",\"message\":{\"content\":\"nope\"},"
        + "\"done\":true,\"done_reason\":\"stop\","
        + "\"prompt_eval_count\":1,\"eval_count\":1}\n",
      );
    });
    const { invocation } = fixture({
      server,
      profileId: "ollama",
      route: "nativeChat",
      stream: true,
    });

    const outcome = await deadline(invokeRuntime(invocation));

    expect(outcome).toMatchObject({
      status: "failed",
      output: null,
      persistence: {
        dispatchState: "completed",
        terminalOutputIdentity: null,
        error: { category: "invalid-response" },
      },
    });
  });

  it("requires authentic usage and resolved-model evidence before completion", async () => {
    const nullableUsageServer = await startServer((_request, response) => {
      jsonResponse(response, {
        model: MODEL.id,
        choices: [{
          index: 0,
          text: "observed",
          finish_reason: "provider-secret-sk-must-not-persist",
        }],
        usage: null,
      });
    });
    const nullableUsage = fixture({
      server: nullableUsageServer,
      profileId: "vllm",
      route: "completions",
      stream: false,
    });

    const incomplete = await deadline(invokeRuntime(nullableUsage.invocation));

    expect(incomplete).toMatchObject({
      status: "incomplete",
      output: { text: "observed" },
      persistence: {
        finishReason: "other",
        finalUsage: "missing",
        terminalOutputIdentity: null,
      },
    });
    expect(JSON.stringify(incomplete.persistence))
      .not.toContain("provider-secret");

    const conflictingUsageServer = await startServer((_request, response) => {
      jsonResponse(response, {
        model: MODEL.id,
        choices: [{
          index: 0,
          text: "must-not-normalize",
          finish_reason: "stop",
        }],
        usage: {
          prompt_tokens: 1,
          input_tokens: 2,
          completion_tokens: 1,
          total_tokens: 2,
        },
      });
    });
    const conflictingUsage = fixture({
      server: conflictingUsageServer,
      profileId: "vllm",
      route: "completions",
      stream: false,
    });

    const failed = await deadline(invokeRuntime(conflictingUsage.invocation));

    expect(failed).toMatchObject({
      status: "failed",
      output: null,
      persistence: {
        terminalOutputIdentity: null,
        error: { category: "invalid-response" },
      },
    });

    const unresolvedModelServer = await startServer((_request, response) => {
      jsonResponse(response, {
        choices: [{
          index: 0,
          text: "unresolved",
          finish_reason: "stop",
        }],
        usage: {
          prompt_tokens: 1,
          completion_tokens: 1,
          total_tokens: 2,
        },
      });
    });
    const unresolvedModel = fixture({
      server: unresolvedModelServer,
      profileId: "vllm",
      route: "completions",
      stream: false,
    });

    const unresolved = await deadline(invokeRuntime(
      unresolvedModel.invocation,
    ));

    expect(unresolved).toMatchObject({
      status: "incomplete",
      output: { text: "unresolved" },
      persistence: {
        resolvedModel: null,
        finalUsage: "present",
        terminalOutputIdentity: null,
      },
    });

    const overflowServer = await startServer((_request, response) => {
      jsonResponse(response, {
        model: MODEL.id,
        message: { content: "must-not-normalize" },
        done: true,
        done_reason: "stop",
        prompt_eval_count: Number.MAX_SAFE_INTEGER,
        eval_count: 1,
      });
    });
    const overflow = fixture({
      server: overflowServer,
      profileId: "ollama",
      route: "nativeChat",
      stream: false,
    });

    await expect(deadline(invokeRuntime(overflow.invocation)))
      .resolves.toMatchObject({
        status: "failed",
        output: null,
        persistence: {
          terminalOutputIdentity: null,
          error: { category: "invalid-response" },
        },
      });
  });

  it("retains observed text but not provider payload when a stream terminates with an error", async () => {
    const server = await startServer((_request, response) => {
      response.statusCode = 200;
      response.setHeader("content-type", "text/event-stream");
      response.write(
        "data: {\"model\":\"test-model\",\"choices\":["
        + "{\"index\":0,\"text\":\"partial\",\"finish_reason\":null}]}\n\n",
      );
      response.end(
        "event: error\n"
        + "data: {\"error\":{\"message\":\"provider payload secret\"}}\n\n",
      );
    });
    const { invocation } = fixture({
      server,
      profileId: "vllm",
      route: "completions",
      stream: true,
    });

    const outcome = await deadline(invokeRuntime(invocation));

    expect(outcome).toMatchObject({
      status: "failed",
      output: { text: "partial" },
      persistence: {
        partialOutput: true,
        terminalOutputIdentity: null,
        error: { category: "invalid-response" },
      },
    });
    expect(JSON.stringify(outcome.persistence))
      .not.toContain("provider payload secret");
  });

  it("rejects usage smuggling, post-finish mutation, and malformed native-chat output", async () => {
    const usage = {
      prompt_tokens: 1,
      completion_tokens: 1,
      total_tokens: 2,
    };
    const invalidSseStreams = [
      [
        `data: ${
          JSON.stringify({
            model: MODEL.id,
            choices: [{
              index: 0,
              text: "usage-on-choice",
              finish_reason: "stop",
            }],
            usage,
          })
        }\n\n`,
        "data: [DONE]\n\n",
      ],
      [
        `data: ${
          JSON.stringify({
            model: MODEL.id,
            choices: [{
              index: 0,
              text: "finished",
              finish_reason: "stop",
            }],
          })
        }\n\n`,
        `data: ${
          JSON.stringify({
            model: MODEL.id,
            choices: [{
              index: 0,
              text: "post-finish-mutation",
              finish_reason: null,
            }],
          })
        }\n\n`,
        `data: ${
          JSON.stringify({ model: MODEL.id, choices: [], usage })
        }\n\n`,
        "data: [DONE]\n\n",
      ],
      [
        `data: ${
          JSON.stringify({
            model: MODEL.id,
            choices: [{
              index: 0,
              text: "finished",
              finish_reason: "stop",
            }],
          })
        }\n\n`,
        `data: ${
          JSON.stringify({ model: MODEL.id, choices: [], usage })
        }\n\n`,
        `data: ${
          JSON.stringify({ model: MODEL.id, choices: [], usage })
        }\n\n`,
        "data: [DONE]\n\n",
      ],
    ];

    for (const frames of invalidSseStreams) {
      const server = await startServer((_request, response) => {
        response.statusCode = 200;
        response.setHeader("content-type", "text/event-stream");
        response.end(frames.join(""));
      });
      const { invocation } = fixture({
        server,
        profileId: "vllm",
        route: "completions",
        stream: true,
      });

      const outcome = await deadline(invokeRuntime(invocation));

      expect(outcome).toMatchObject({
        status: "failed",
        output: null,
        persistence: {
          terminalOutputIdentity: null,
          error: { category: "invalid-response" },
        },
      });
    }

    const malformedNativeServer = await startServer((_request, response) => {
      response.statusCode = 200;
      response.setHeader("content-type", "application/x-ndjson");
      response.write(
        "{\"model\":\"test-model\",\"message\":{\"content\":7},"
        + "\"done\":false}\n",
      );
      response.end(
        "{\"model\":\"test-model\",\"message\":{\"content\":\"accepted\"},"
        + "\"done\":true,\"done_reason\":\"stop\","
        + "\"prompt_eval_count\":1,\"eval_count\":1}\n",
      );
    });
    const malformedNative = fixture({
      server: malformedNativeServer,
      profileId: "ollama",
      route: "nativeChat",
      stream: true,
    });

    await expect(deadline(invokeRuntime(malformedNative.invocation)))
      .resolves.toMatchObject({
        status: "failed",
        output: null,
        persistence: {
          terminalOutputIdentity: null,
          error: { category: "invalid-response" },
        },
      });
  });

  it("fails closed on content-type mismatch and marks missing SSE terminal as incomplete", async () => {
    const wrongTypeServer = await startServer((_request, response) => {
      jsonResponse(response, {
        model: MODEL.id,
        choices: [{
          index: 0,
          text: "must-not-accept",
          finish_reason: "stop",
        }],
        usage: {
          prompt_tokens: 1,
          completion_tokens: 1,
          total_tokens: 2,
        },
      }, "text/plain");
    });
    const wrongType = fixture({
      server: wrongTypeServer,
      profileId: "vllm",
      route: "completions",
      stream: false,
    });
    const failed = await deadline(invokeRuntime(wrongType.invocation));
    expect(failed).toMatchObject({
      status: "failed",
      output: null,
      persistence: {
        dispatchState: "completed",
        terminalOutputIdentity: null,
        error: { category: "invalid-response" },
      },
    });

    const truncatedServer = await startServer((_request, response) => {
      response.statusCode = 200;
      response.setHeader("content-type", "text/event-stream");
      response.end(
        "data: {\"model\":\"test-model\",\"choices\":["
        + "{\"index\":0,\"text\":\"partial\",\"finish_reason\":\"stop\"}]}\n\n",
      );
    });
    const truncated = fixture({
      server: truncatedServer,
      profileId: "vllm",
      route: "completions",
      stream: true,
    });
    const incomplete = await deadline(invokeRuntime(truncated.invocation));
    expect(incomplete).toMatchObject({
      status: "incomplete",
      output: { text: "partial" },
      persistence: {
        partialOutput: true,
        finalUsage: "missing",
        terminalOutputIdentity: null,
        error: { category: "invalid-response" },
      },
    });
  });

  it("preserves sent-unknown transport semantics when a partial stream is cut off", async () => {
    const server = await startServer((_request, response) => {
      const partial =
        "data: {\"model\":\"test-model\",\"choices\":["
        + "{\"index\":0,\"text\":\"observed\",\"finish_reason\":null}]}\n\n";
      response.statusCode = 200;
      response.setHeader("content-type", "text/event-stream");
      response.setHeader(
        "content-length",
        Buffer.byteLength(partial, "utf8") + 32,
      );
      response.end(partial);
    });
    const { invocation } = fixture({
      server,
      profileId: "vllm",
      route: "completions",
      stream: true,
    });

    const outcome = await deadline(invokeRuntime(invocation));

    expect(outcome).toMatchObject({
      status: "failed",
      persistence: {
        dispatchState: "sent_unknown",
        terminalOutputIdentity: null,
        error: { category: "transport" },
      },
    });
  });
}, TEST_TIMEOUT_MS);
