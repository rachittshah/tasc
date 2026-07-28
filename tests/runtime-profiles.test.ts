import { describe, expect, it } from "vitest";
import {
  RUNTIME_CAPABILITIES,
  RUNTIME_PROFILE_IDS,
  createRayServeEndpointDescriptor,
  createSkyPilotEndpointDescriptor,
  fingerprintEndpointDescriptor,
  fingerprintRuntimeWireProfile,
  getRuntimeProfile,
  listRuntimeProfiles,
  parseEndpointDescriptor,
  parseRuntimeCapabilityProbeEvidence,
  resolveRuntimeCapabilities,
  type RuntimeInstanceIdentity,
  type RuntimeCapabilityProbeEvidence,
} from "../src/index.js";

const DIGEST = `sha256:${"a".repeat(64)}`;
const UNVERIFIED_IDENTITY = Object.freeze({
  endpointBinding: "operator-policy" as const,
  runtimeBuild: {
    basis: "operator-policy" as const,
    observed: null,
  },
  backend: {
    basis: "unverified" as const,
    observed: null,
  },
  modelId: {
    basis: "unverified" as const,
    observed: null,
  },
  modelRevision: {
    basis: "unverified" as const,
    observed: null,
  },
  configurationDigest: {
    basis: "unverified" as const,
    observed: null,
  },
});

describe("build-pinned runtime registry", () => {
  it("models the documented endpoint shapes for each runtime snapshot", () => {
    const fixtures = [
      {
        id: "vllm",
        build: "0.26.0",
        chat: "/v1/chat/completions",
        models: "/v1/models",
        liveness: "/health",
        metrics: ["/metrics"],
      },
      {
        id: "sglang",
        build: "0.5.16",
        chat: "/v1/chat/completions",
        models: "/v1/models",
        liveness: "/health",
        metrics: ["/metrics"],
      },
      {
        id: "tensorrt-llm",
        build: "1.2.1",
        chat: "/v1/chat/completions",
        models: "/v1/models",
        liveness: "/health",
        metrics: ["/metrics", "/prometheus/metrics"],
      },
      {
        id: "llama.cpp",
        build: "b10156",
        chat: "/v1/chat/completions",
        models: "/v1/models",
        liveness: "/health",
        metrics: ["/metrics"],
      },
      {
        id: "ollama",
        build: "0.32.5",
        chat: "/v1/chat/completions",
        models: "/api/tags",
        liveness: "/api/version",
        metrics: [],
      },
      {
        id: "tgi",
        build: "3.3.7",
        chat: "/v1/chat/completions",
        models: "/v1/models",
        liveness: "/health",
        metrics: ["/metrics"],
      },
      {
        id: "lm-studio",
        build: "0.4.1",
        chat: "/v1/chat/completions",
        models: "/v1/models",
        liveness: undefined,
        metrics: [],
      },
      {
        id: "mlx-lm",
        build: "0.31.3",
        chat: "/v1/chat/completions",
        models: "/v1/models",
        liveness: "/health",
        metrics: [],
      },
    ] as const;

    for (const fixture of fixtures) {
      const profile = getRuntimeProfile(fixture.id);
      expect(profile.runtime.build).toBe(fixture.build);
      expect(profile.endpoints.inference.chatCompletions?.path).toBe(
        fixture.chat,
      );
      expect(profile.endpoints.models.list?.path).toBe(fixture.models);
      expect(profile.endpoints.health.liveness?.path).toBe(fixture.liveness);
      expect(profile.endpoints.metrics.map(({ path }) => path)).toEqual(
        fixture.metrics,
      );
      expect(profile.documentation.every(({ url }) => url.startsWith("https://")))
        .toBe(true);
    }
  });

  it("keeps native and nonportable wire behavior explicit", () => {
    const ollama = getRuntimeProfile("ollama");
    expect(ollama.endpoints.inference.nativeChat).toMatchObject({
      path: "/api/chat",
      responseFraming: ["json", "ndjson"],
      wireProtocol: "ollama-native-chat",
    });
    expect(ollama.endpoints.inference.nativeGenerate).toMatchObject({
      path: "/api/generate",
      responseFraming: ["json", "ndjson"],
      wireProtocol: "ollama-native-generate",
    });

    const tensorRt = getRuntimeProfile("tensorrt-llm");
    expect(tensorRt.endpoints.inference.responses?.path).toBe("/v1/responses");
    expect(tensorRt.endpoints.health.readiness?.path).toBe("/health_generate");
    expect(tensorRt.endpoints.version?.path).toBe("/version");
    expect(tensorRt.endpoints.metrics).toEqual([
      expect.objectContaining({
        path: "/metrics",
        format: "json",
        observationEffect: "consumptive",
      }),
      expect.objectContaining({
        path: "/prometheus/metrics",
        format: "prometheus",
        observationEffect: "non-mutating",
      }),
    ]);

    expect(getRuntimeProfile("llama.cpp").endpoints.metrics[0]).toMatchObject({
      path: "/metrics",
      availability: "conditional",
    });

    const sglang = getRuntimeProfile("sglang");
    expect(sglang.endpoints.models.info?.path).toBe("/model_info");
    expect(sglang.endpoints.version?.path).toBe("/server_info");
  });

  it("represents every static capability with scoped evidence, not a generic compatibility claim", () => {
    for (const profile of listRuntimeProfiles()) {
      expect(Object.keys(profile.capabilities).sort()).toEqual(
        [...RUNTIME_CAPABILITIES].sort(),
      );
      for (const capability of RUNTIME_CAPABILITIES) {
        const evidence = profile.capabilities[capability];
        expect(evidence.source).toBe("documentation");
        expect(evidence.capability).toBe(capability);
        expect(evidence.runtime).toEqual({
          profileId: profile.id,
          build: profile.runtime.build,
        });
        expect(evidence.backend.status).toMatch(
          /^(established|conditional|not-established)$/,
        );
        expect(evidence.model.status).toMatch(
          /^(established|conditional|not-established)$/,
        );
        expect(evidence.configuration.status).toMatch(
          /^(established|conditional|not-established)$/,
        );
      }
    }

    expect(getRuntimeProfile("vllm").capabilities.tools.state).toBe(
      "conditional",
    );
    expect(
      getRuntimeProfile("tensorrt-llm").capabilities.responses.state,
    ).not.toBe("unsupported");
    expect(
      getRuntimeProfile("llama.cpp").capabilities.prometheusMetrics.state,
    ).toBe("conditional");
    expect(getRuntimeProfile("lm-studio").capabilities.liveness.state).toBe(
      "unknown",
    );
    expect(getRuntimeProfile("mlx-lm")).toMatchObject({
      supportTier: "experimental-local-only",
      locality: "local-only",
    });
    expect(getRuntimeProfile("tgi")).toMatchObject({
      supportTier: "legacy",
    });
    expect(getRuntimeProfile("lm-studio").supportTier).toBe(
      "approved-internal",
    );
    expect(getRuntimeProfile("vllm").supportTier).toBe(
      "production-candidate",
    );
  });

  it("pins default capability claims to the exact documented build", () => {
    expect(
      getRuntimeProfile("vllm").capabilities.chatCompletions.documentationUrl,
    ).toContain("/en/v0.26.0/");
    expect(
      getRuntimeProfile("sglang").capabilities.chatCompletions.documentationUrl,
    ).toContain("/blob/v0.5.16/");
    expect(
      getRuntimeProfile("tensorrt-llm").capabilities.chatCompletions
        .documentationUrl,
    ).toContain("/blob/v1.2.1/");
    expect(
      getRuntimeProfile("ollama").capabilities.chatCompletions.documentationUrl,
    ).toContain("/blob/v0.32.5/");
  });

  it("returns a deterministic, frozen registry without orchestration impostors", () => {
    expect(RUNTIME_PROFILE_IDS).toEqual([
      "llama.cpp",
      "lm-studio",
      "mlx-lm",
      "ollama",
      "sglang",
      "tensorrt-llm",
      "tgi",
      "vllm",
    ]);
    expect(listRuntimeProfiles().map(({ id }) => id)).toEqual(
      RUNTIME_PROFILE_IDS,
    );
    expect(RUNTIME_PROFILE_IDS).not.toContain("ray-serve");
    expect(RUNTIME_PROFILE_IDS).not.toContain("skypilot");
    expect(Object.isFrozen(listRuntimeProfiles())).toBe(true);
    expect(Object.isFrozen(getRuntimeProfile("vllm"))).toBe(true);
    expect(Object.isFrozen(getRuntimeProfile("vllm").capabilities)).toBe(true);
    expect(() => getRuntimeProfile("openai-compatible")).toThrow(
      "unknown runtime profile",
    );
  });

  it("overrides only a probed capability on an identity-matched instance", () => {
    const instance: RuntimeInstanceIdentity = {
      endpointDescriptorDigest: `sha256:${"b".repeat(64)}`,
      runtime: {
        profileId: "vllm",
        build: "0.26.0",
      },
      backend: {
        name: "cuda",
        build: "13.0",
      },
      model: {
        id: "example/model",
        revision: "0123456789abcdef",
      },
      configurationDigest: DIGEST,
    };
    const probe: RuntimeCapabilityProbeEvidence = {
      schemaVersion: "tasc-runtime-capability-probe-v1",
      source: "live-probe",
      capability: "cancellation",
      state: "supported",
      probedAt: "2026-07-28T12:00:00.000Z",
      identityVerification: UNVERIFIED_IDENTITY,
      ...instance,
    };

    const staticProfile = getRuntimeProfile("vllm");
    expect(staticProfile.capabilities.cancellation.state).toBe("unknown");

    const resolved = resolveRuntimeCapabilities(instance, [probe]);
    expect(resolved.capabilities.cancellation).toEqual(probe);
    expect(resolved.capabilities.streaming).toBe(
      staticProfile.capabilities.streaming,
    );
    expect(resolved.profile).toBe(staticProfile);
    expect(Object.isFrozen(resolved)).toBe(true);

    expect(getRuntimeProfile("vllm").capabilities.cancellation.state).toBe(
      "unknown",
    );
    expect(
      resolveRuntimeCapabilities(instance, []).capabilities.cancellation.state,
    ).toBe("unknown");
  });

  it("rejects ambiguous or identity-mismatched probe overrides", () => {
    const instance: RuntimeInstanceIdentity = {
      endpointDescriptorDigest: `sha256:${"b".repeat(64)}`,
      runtime: {
        profileId: "vllm",
        build: "0.26.0",
      },
      backend: {
        name: "cuda",
        build: "13.0",
      },
      model: {
        id: "example/model",
        revision: "0123456789abcdef",
      },
      configurationDigest: DIGEST,
    };
    const probe: RuntimeCapabilityProbeEvidence = {
      schemaVersion: "tasc-runtime-capability-probe-v1",
      source: "live-probe",
      capability: "cancellation",
      state: "supported",
      probedAt: "2026-07-28T12:00:00.000Z",
      identityVerification: UNVERIFIED_IDENTITY,
      ...instance,
    };

    expect(() =>
      resolveRuntimeCapabilities(instance, [
        {
          ...probe,
          runtime: { ...probe.runtime, build: "different-build" },
        },
      ])
    ).toThrow("does not match runtime instance");
    expect(() =>
      resolveRuntimeCapabilities(instance, [{
        ...probe,
        endpointDescriptorDigest: `sha256:${"c".repeat(64)}`,
      }])
    ).toThrow("does not match runtime instance");
    expect(() => resolveRuntimeCapabilities(instance, [probe, probe])).toThrow(
      "duplicate probe evidence",
    );
  });

  it("starts an unestablished runtime build unknown and accepts only exact-instance probes", () => {
    const descriptor = createRayServeEndpointDescriptor({
      origin: "https://newer-vllm.internal.example",
      routePrefix: "/",
      runtimeProfileId: "vllm",
      runtimeBuild: "0.26.1-local",
      rayBuild: "2.56.1",
      configurationDigest: `sha256:${"f".repeat(64)}`,
      applicationName: "newer-vllm",
      deploymentName: "VLLMDeployment",
      authenticationReference: "ray-shadow-token",
    });
    const endpointDescriptorDigest = fingerprintEndpointDescriptor(descriptor);
    expect(parseEndpointDescriptor(descriptor).runtime).toEqual({
      profileId: "vllm",
      build: "0.26.1-local",
    });
    const instance: RuntimeInstanceIdentity = {
      endpointDescriptorDigest,
      runtime: descriptor.runtime,
      backend: {
        name: "cuda",
        build: "13.0",
      },
      model: {
        id: "example/model",
        revision: "fedcba9876543210",
      },
      configurationDigest: `sha256:${"e".repeat(64)}`,
    };
    const unprobed = resolveRuntimeCapabilities(instance, []);
    expect(unprobed.expectationBasis).toBe("unestablished-build");
    for (const capability of RUNTIME_CAPABILITIES) {
      expect(unprobed.capabilities[capability]).toMatchObject({
        source: "unestablished",
        state: "unknown",
        runtime: instance.runtime,
      });
    }

    const probe: RuntimeCapabilityProbeEvidence = {
      schemaVersion: "tasc-runtime-capability-probe-v1",
      source: "live-probe",
      capability: "liveness",
      state: "supported",
      probedAt: "2026-07-28T12:00:00.000Z",
      identityVerification: UNVERIFIED_IDENTITY,
      ...instance,
    };
    const probed = resolveRuntimeCapabilities(instance, [probe]);
    expect(probed.capabilities.liveness).toEqual(probe);
    expect(probed.capabilities.chatCompletions.state).toBe("unknown");
    expect(getRuntimeProfile("vllm").capabilities.liveness.source).toBe(
      "documentation",
    );
  });

  it("fingerprints the complete immutable wire profile", () => {
    const profile = getRuntimeProfile("vllm");
    expect(fingerprintRuntimeWireProfile(profile)).toMatch(
      /^sha256:[a-f0-9]{64}$/,
    );
    expect(fingerprintRuntimeWireProfile(profile)).toBe(
      fingerprintRuntimeWireProfile(getRuntimeProfile("vllm")),
    );
    expect(fingerprintRuntimeWireProfile(profile)).not.toBe(
      fingerprintRuntimeWireProfile(getRuntimeProfile("sglang")),
    );
  });

  it("strictly snapshots bounded probe evidence without executing proxies or accessors", () => {
    const valid = {
      schemaVersion: "tasc-runtime-capability-probe-v1",
      source: "live-probe",
      capability: "cancellation",
      state: "supported",
      probedAt: "2026-07-28T12:00:00.000Z",
      identityVerification: UNVERIFIED_IDENTITY,
      endpointDescriptorDigest: `sha256:${"b".repeat(64)}`,
      runtime: { profileId: "vllm", build: "0.26.0" },
      backend: { name: "cuda", build: "13.0" },
      model: { id: "example/model", revision: "0123456789abcdef" },
      configurationDigest: DIGEST,
    };
    expect(parseRuntimeCapabilityProbeEvidence(valid)).toEqual(valid);
    expect(Object.isFrozen(parseRuntimeCapabilityProbeEvidence(valid))).toBe(
      true,
    );

    let touched = false;
    const proxied = new Proxy(valid, {
      getPrototypeOf() {
        touched = true;
        throw new Error("must not execute");
      },
    });
    expect(() => parseRuntimeCapabilityProbeEvidence(proxied)).toThrow(/proxy/i);
    expect(touched).toBe(false);
  });
});

describe("declarative orchestration descriptors", () => {
  it("wraps an existing Ray Serve endpoint without changing the runtime wire contract", () => {
    const descriptor = createRayServeEndpointDescriptor({
      origin: "https://serve.internal.example",
      routePrefix: "/language",
      runtimeProfileId: "vllm",
      runtimeBuild: "0.26.0",
      rayBuild: "2.56.1",
      configurationDigest: DIGEST,
      applicationName: "language",
      deploymentName: "VLLMDeployment",
      authenticationReference: "ray-shadow-token",
    });

    expect(descriptor).toEqual({
      schemaVersion: "tasc-endpoint-descriptor-v1",
      origin: "https://serve.internal.example",
      basePath: "/language",
      runtime: {
        profileId: "vllm",
        build: "0.26.0",
      },
      orchestration: {
        kind: "ray-serve",
        build: "2.56.1",
        configurationDigest: DIGEST,
        locator: {
          applicationName: "language",
          deploymentName: "VLLMDeployment",
        },
        authenticationReference: "ray-shadow-token",
      },
      authority: {
        deployment: "none",
        network: "unverified",
      },
    });
    expect(Object.isFrozen(descriptor)).toBe(true);
    expect(Object.isFrozen(descriptor.orchestration.locator)).toBe(true);
    expect(getRuntimeProfile(descriptor.runtime.profileId).endpoints.inference)
      .toBe(getRuntimeProfile("vllm").endpoints.inference);
    expect(fingerprintEndpointDescriptor(descriptor)).toMatch(
      /^sha256:[a-f0-9]{64}$/,
    );
    expect(parseEndpointDescriptor(descriptor)).toEqual(descriptor);
  });

  it("models SkyPilot and SkyServe as supplied endpoint metadata", () => {
    const skyPilot = createSkyPilotEndpointDescriptor({
      origin: "https://sky.internal.example",
      routePrefix: "/",
      runtimeProfileId: "tgi",
      runtimeBuild: "3.3.7",
      skyPilotBuild: "0.13.1rc1",
      configurationDigest: DIGEST,
      mode: "skypilot",
      serviceName: "legacy-tgi",
      authenticationReference: "sky-shadow-token",
    });
    const skyServe = createSkyPilotEndpointDescriptor({
      origin: "https://skyserve.internal.example",
      routePrefix: "/models",
      runtimeProfileId: "sglang",
      runtimeBuild: "0.5.16",
      skyPilotBuild: "0.13.1rc1",
      configurationDigest: DIGEST,
      mode: "skyserve",
      serviceName: "sglang-shadow",
      authenticationReference: "skyserve-shadow-token",
    });

    expect(skyPilot.orchestration).toMatchObject({
      kind: "skypilot",
      locator: { serviceName: "legacy-tgi" },
    });
    expect(skyServe.orchestration).toMatchObject({
      kind: "skyserve",
      locator: { serviceName: "sglang-shadow" },
    });
    expect(skyServe.runtime).toEqual({
      profileId: "sglang",
      build: "0.5.16",
    });
  });

  it("rejects executable hooks, deployment actions, and fake runtime profiles", () => {
    let called = false;
    const deploy = () => {
      called = true;
    };
    expect(() =>
      createRayServeEndpointDescriptor({
        origin: "https://serve.internal.example",
        routePrefix: "/",
        runtimeProfileId: "vllm",
        runtimeBuild: "0.26.0",
        rayBuild: "2.56.1",
        configurationDigest: DIGEST,
        applicationName: "language",
        deploymentName: "VLLMDeployment",
        authenticationReference: "ray-shadow-token",
        deploy,
      } as never)
    ).toThrow();
    expect(called).toBe(false);

    expect(() =>
      createSkyPilotEndpointDescriptor({
        origin: "https://sky.internal.example",
        routePrefix: "/",
        runtimeProfileId: "ray-serve",
        runtimeBuild: "2.56.1",
        skyPilotBuild: "0.13.1rc1",
        configurationDigest: DIGEST,
        mode: "skyserve",
        serviceName: "bad-wrapper",
        authenticationReference: "skyserve-shadow-token",
      } as never)
    ).toThrow("unknown runtime profile");
    expect(() =>
      createSkyPilotEndpointDescriptor({
        origin: "https://sky.internal.example/path?token=secret",
        routePrefix: "/",
        runtimeProfileId: "vllm",
        runtimeBuild: "0.26.0",
        skyPilotBuild: "0.13.1rc1",
        configurationDigest: DIGEST,
        mode: "skyserve",
        serviceName: "bad-origin",
        authenticationReference: "skyserve-shadow-token",
      })
    ).toThrow("canonical HTTP(S) origin");
    expect(() =>
      createSkyPilotEndpointDescriptor({
        origin: "https://sky.internal.example",
        routePrefix: "/.",
        runtimeProfileId: "vllm",
        runtimeBuild: "0.26.0",
        skyPilotBuild: "0.13.1rc1",
        configurationDigest: DIGEST,
        mode: "skyserve",
        serviceName: "bad-route",
        authenticationReference: "skyserve-shadow-token",
      })
    ).toThrow("canonical absolute path");

    for (const forbidden of [
      "run",
      "setup",
      "yaml",
      "importPath",
      "runtimeEnv",
      "callback",
    ]) {
      expect(() =>
        createSkyPilotEndpointDescriptor({
          origin: "https://sky.internal.example",
          routePrefix: "/",
          runtimeProfileId: "vllm",
          runtimeBuild: "0.26.0",
          skyPilotBuild: "0.13.1rc1",
          configurationDigest: DIGEST,
          mode: "skyserve",
          serviceName: "strict-wrapper",
          authenticationReference: "skyserve-shadow-token",
          [forbidden]: "forbidden",
        } as never)
      ).toThrow(/unknown field/i);
    }
  });
});
