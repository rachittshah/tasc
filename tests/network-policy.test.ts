import { describe, expect, it, vi } from "vitest";
import {
  assertCollectorEvaluatorKeyAuthorized,
  assertCollectorStoreRootAuthorized,
  authorizeCollectorRequest,
  consumePinnedCollectorRequest,
  fingerprintCollectorEndpointBinding,
  fingerprintCollectorTrustPolicy,
  narrowCollectorTrustPolicy,
  parseCollectorTrustPolicy,
  pinAuthorizedCollectorRequest,
  type CollectorDnsLookup,
  type CollectorTrustPolicy,
} from "../src/runtime/network-policy.js";
import {
  createRayServeEndpointDescriptor,
} from "../src/runtime/orchestration.js";

const remotePolicyInput = () => ({
  schemaVersion: "tasc-collector-trust-policy-v1" as const,
  localMode: "disabled" as const,
  maximumRequestDurationMs: 60_000,
  endpoints: [
    {
      alias: "approved-vllm",
      origin: "https://inference.example.com:8443",
      runtime: {
        profileId: "vllm" as const,
        build: "0.26.0",
      },
      routes: [
        {
          method: "GET" as const,
          pathPrefix: "/health",
          authenticationReferences: [] as string[],
        },
        {
          method: "POST" as const,
          pathPrefix: "/v1",
          authenticationReferences: ["runtime-prod"],
        },
        {
          method: "POST" as const,
          pathPrefix: "/v1/admin",
          authenticationReferences: ["runtime-admin"],
        },
      ],
    },
  ],
  secretReferences: ["runtime-admin", "runtime-prod"],
  evaluatorKeyIds: ["eval-primary"],
  storeRoots: ["/srv/tasc/payloads"],
});

const publicDns: CollectorDnsLookup = async () => [
  { address: "93.184.216.34", family: 4 },
  { address: "2606:4700:4700::1111", family: 6 },
];

const localPolicyInput = (
  origin = "http://127.0.0.1:8000",
) => ({
  schemaVersion: "tasc-collector-trust-policy-v1" as const,
  localMode: "literal-loopback-only" as const,
  maximumRequestDurationMs: 5_000,
  endpoints: [{
    alias: "local-vllm",
    origin,
    runtime: {
      profileId: "vllm" as const,
      build: "0.26.0",
    },
    routes: [{
      method: "POST" as const,
      pathPrefix: "/v1",
      authenticationReferences: [] as string[],
    }],
  }],
  secretReferences: [] as string[],
  evaluatorKeyIds: [] as string[],
  storeRoots: [] as string[],
});

function parsedRemotePolicy(): CollectorTrustPolicy {
  return parseCollectorTrustPolicy(remotePolicyInput());
}

const remoteRequest = (
  overrides: Partial<{
    endpointAlias: string;
    runtime: { profileId: "vllm"; build: string };
    method: "GET" | "POST";
    path: string;
    authenticationReference: string;
  }> = {},
) => ({
  endpointAlias: "approved-vllm",
  runtime: { profileId: "vllm" as const, build: "0.26.0" },
  method: "POST" as const,
  path: "/v1/chat/completions",
  authenticationReference: "runtime-prod",
  ...overrides,
});

describe("collector trust policy", () => {
  it("parses, canonicalizes, freezes, and fingerprints exact authority", () => {
    const input = remotePolicyInput();
    input.evaluatorKeyIds = ["eval-primary", "eval-backup"];
    const reversed = {
      ...input,
      evaluatorKeyIds: [...input.evaluatorKeyIds].reverse(),
      endpoints: [{
        ...input.endpoints[0],
        routes: [...input.endpoints[0]!.routes].reverse(),
      }],
    };

    const policy = parseCollectorTrustPolicy(input);
    expect(policy).toEqual(parseCollectorTrustPolicy(reversed));
    expect(Object.isFrozen(policy)).toBe(true);
    expect(Object.isFrozen(policy.endpoints)).toBe(true);
    expect(Object.isFrozen(policy.endpoints[0]?.routes)).toBe(true);
    expect(
      fingerprintCollectorTrustPolicy(input),
    ).toBe(fingerprintCollectorTrustPolicy(reversed));
    expect(fingerprintCollectorTrustPolicy(input)).toMatch(
      /^sha256:[a-f0-9]{64}$/,
    );
  });

  it("binds instance identity to exact live authority and validated orchestration", () => {
    const policy = parseCollectorTrustPolicy(remotePolicyInput());
    const direct = fingerprintCollectorEndpointBinding(
      policy,
      "approved-vllm",
    );
    expect(direct).toMatch(/^sha256:[a-f0-9]{64}$/);

    const unrelated = remotePolicyInput();
    unrelated.evaluatorKeyIds = ["different-evaluator"];
    unrelated.storeRoots = ["/srv/tasc/other-payloads"];
    expect(
      fingerprintCollectorEndpointBinding(
        parseCollectorTrustPolicy(unrelated),
        "approved-vllm",
      ),
    ).toBe(direct);

    const changedRoute = remotePolicyInput();
    changedRoute.endpoints[0]!.routes[1]!.pathPrefix =
      "/v1/chat/completions";
    expect(
      fingerprintCollectorEndpointBinding(
        parseCollectorTrustPolicy(changedRoute),
        "approved-vllm",
      ),
    ).not.toBe(direct);

    const changedAlias = remotePolicyInput();
    changedAlias.endpoints[0]!.alias = "renamed-vllm";
    expect(
      fingerprintCollectorEndpointBinding(
        parseCollectorTrustPolicy(changedAlias),
        "renamed-vllm",
      ),
    ).not.toBe(direct);

    const descriptorInput = remotePolicyInput();
    descriptorInput.endpoints[0]!.routes =
      descriptorInput.endpoints[0]!.routes.slice(0, 2);
    const descriptorPolicy = parseCollectorTrustPolicy(descriptorInput);
    const descriptor = createRayServeEndpointDescriptor({
      origin: "https://inference.example.com:8443",
      routePrefix: "/",
      runtimeProfileId: "vllm",
      runtimeBuild: "0.26.0",
      rayBuild: "2.48.0",
      configurationDigest: `sha256:${"a".repeat(64)}`,
      applicationName: "tasc",
      deploymentName: "vllm",
    });
    const orchestrated = fingerprintCollectorEndpointBinding(
      descriptorPolicy,
      "approved-vllm",
      descriptor,
    );
    expect(orchestrated).not.toBe(
      fingerprintCollectorEndpointBinding(
        descriptorPolicy,
        "approved-vllm",
      ),
    );

    expect(() =>
      fingerprintCollectorEndpointBinding(
        descriptorPolicy,
        "approved-vllm",
        { ...descriptor, origin: "https://other.example.com:8443" },
      )
    ).toThrow(/does not match/);
    expect(() =>
      fingerprintCollectorEndpointBinding(
        descriptorPolicy,
        "approved-vllm",
        { ...descriptor, basePath: "/serve" },
      )
    ).toThrow(/route prefix/);
    expect(() =>
      fingerprintCollectorEndpointBinding(
        { ...descriptorPolicy },
        "approved-vllm",
      )
    ).toThrow(/authentic/);
  });

  it("rejects proxies, accessors, symbols, hidden fields, holes, and duplicates without invoking them", () => {
    let invoked = 0;
    const accessor = remotePolicyInput() as Record<string, unknown>;
    Object.defineProperty(accessor, "localMode", {
      enumerable: true,
      get: () => {
        invoked += 1;
        return "disabled";
      },
    });
    expect(() => parseCollectorTrustPolicy(accessor)).toThrow(/data fields/);
    expect(invoked).toBe(0);

    const proxied = new Proxy(remotePolicyInput(), {
      get: () => {
        invoked += 1;
        throw new Error("must not run");
      },
    });
    expect(() => parseCollectorTrustPolicy(proxied)).toThrow(/proxy/);
    expect(invoked).toBe(0);

    const withSymbol = remotePolicyInput() as Record<PropertyKey, unknown>;
    withSymbol[Symbol("hidden")] = true;
    expect(() => parseCollectorTrustPolicy(withSymbol)).toThrow(/symbol/);

    const hidden = remotePolicyInput();
    Object.defineProperty(hidden.endpoints[0]!.routes[0], "extra", {
      enumerable: false,
      value: true,
    });
    expect(() => parseCollectorTrustPolicy(hidden)).toThrow(
      /unknown|non-enumerable/,
    );

    const hole = remotePolicyInput();
    delete hole.endpoints[0]!.routes[1];
    expect(() => parseCollectorTrustPolicy(hole)).toThrow(/holes/);

    const duplicate = remotePolicyInput();
    duplicate.evaluatorKeyIds.push("eval-primary");
    expect(() => parseCollectorTrustPolicy(duplicate)).toThrow(/duplicate/);
  });

  it("requires canonical origins, paths, identifiers, and store roots", () => {
    for (const origin of [
      "https://user@example.com",
      "https://example.com/",
      "https://example.com?x=1",
      "https://example.com#fragment",
      "https://EXAMPLE.com",
      "https://example.com.",
      "https://bücher.example",
      "https://example.com:443",
      "https://2130706433",
      "https://0x7f000001",
      "https://0177.0.0.1",
    ]) {
      const input = remotePolicyInput();
      input.endpoints[0]!.origin = origin;
      expect(
        () => parseCollectorTrustPolicy(input),
        origin,
      ).toThrow();
    }

    for (const pathPrefix of [
      "v1",
      "/v1/",
      "/v1//chat",
      "/v1/../admin",
      "/v1/%2e%2e/admin",
      "/v1/chat?x=1",
    ]) {
      const input = remotePolicyInput();
      input.endpoints[0]!.routes[0]!.pathPrefix = pathPrefix;
      expect(
        () => parseCollectorTrustPolicy(input),
        pathPrefix,
      ).toThrow();
    }

    const relativeRoot = remotePolicyInput();
    relativeRoot.storeRoots = ["relative/store"];
    expect(() => parseCollectorTrustPolicy(relativeRoot)).toThrow(/root/);

    const filesystemRoot = remotePolicyInput();
    filesystemRoot.storeRoots = ["/"];
    expect(() => parseCollectorTrustPolicy(filesystemRoot)).toThrow(/root/);

    const unregisteredSecret = remotePolicyInput();
    unregisteredSecret.secretReferences = ["runtime-prod"];
    expect(() => parseCollectorTrustPolicy(unregisteredSecret)).toThrow(
      /secret allowlist/,
    );

    for (const build of ["0.26.0 secret", "0.26.0..local"]) {
      const unsafeBuild = remotePolicyInput();
      unsafeBuild.endpoints[0]!.runtime.build = build;
      expect(() => parseCollectorTrustPolicy(unsafeBuild)).toThrow(
        /constant-safe runtime identifier/,
      );
    }
  });

  it("authorizes an exact origin and segment-aware most-specific route", () => {
    const policy = parsedRemotePolicy();
    expect(() =>
      authorizeCollectorRequest(policy, remoteRequest())
    ).not.toThrow();

    for (const request of [
      remoteRequest({ path: "/v10/chat/completions" }),
      remoteRequest({ method: "GET" }),
      remoteRequest({
        path: "/v1/admin/jobs",
        authenticationReference: "runtime-prod",
      }),
      remoteRequest({ path: "/v1/chat?debug=1" }),
      remoteRequest({ path: "/v1/chat#debug" }),
      remoteRequest({ path: "//user@inference.example.com/v1/chat" }),
      remoteRequest({ endpointAlias: "other-vllm" }),
      remoteRequest({ runtime: { profileId: "vllm", build: "0.27.0" } }),
    ]) {
      expect(
        () => authorizeCollectorRequest(policy, request),
        request.path,
      ).toThrow(/not authorized|canonical/);
    }

    expect(() => authorizeCollectorRequest(policy, remoteRequest({
      path: "/v1/admin/jobs",
      authenticationReference: "runtime-admin",
    }))).not.toThrow();
    const health = remoteRequest({
      method: "GET",
      path: "/health",
    }) as Record<string, unknown>;
    delete health.authenticationReference;
    expect(() => authorizeCollectorRequest(policy, health)).not.toThrow();

    const structuralCopy = JSON.parse(
      JSON.stringify(policy),
    ) as CollectorTrustPolicy;
    expect(() =>
      authorizeCollectorRequest(structuralCopy, remoteRequest())
    ).toThrow(/authentic/);
  });

  it("enforces exact evaluator keys, store roots, and narrowing subsets", () => {
    const parent = parsedRemotePolicy();
    expect(() =>
      assertCollectorEvaluatorKeyAuthorized(parent, "eval-primary")
    ).not.toThrow();
    expect(() =>
      assertCollectorEvaluatorKeyAuthorized(parent, "eval-other")
    ).toThrow(/not authorized/);
    expect(() =>
      assertCollectorStoreRootAuthorized(parent, "/srv/tasc/payloads")
    ).not.toThrow();
    expect(() =>
      assertCollectorStoreRootAuthorized(parent, "/srv/tasc/payloads/child")
    ).toThrow(/not authorized/);

    const narrowed = remotePolicyInput();
    narrowed.endpoints[0]!.routes = [{
      method: "POST",
      pathPrefix: "/v1/chat",
      authenticationReferences: ["runtime-prod"],
    }];
    expect(() => narrowCollectorTrustPolicy(parent, narrowed)).not.toThrow();

    const broaderPath = remotePolicyInput();
    broaderPath.endpoints[0]!.routes[1]!.pathPrefix = "/";
    expect(() => narrowCollectorTrustPolicy(parent, broaderPath)).toThrow(
      /widen/,
    );

    const crossedCredentialBoundary = remotePolicyInput();
    crossedCredentialBoundary.endpoints[0]!.routes = [{
      method: "POST",
      pathPrefix: "/v1/admin/jobs",
      authenticationReferences: ["runtime-prod"],
    }];
    expect(
      () => narrowCollectorTrustPolicy(parent, crossedCredentialBoundary),
    ).toThrow(/widen/);

    const runtimeDrift = remotePolicyInput();
    runtimeDrift.endpoints[0]!.runtime.build = "0.27.0";
    expect(() => narrowCollectorTrustPolicy(parent, runtimeDrift)).toThrow(
      /endpoint identity/,
    );

    const aliasDrift = remotePolicyInput();
    aliasDrift.endpoints[0]!.alias = "renamed-vllm";
    expect(() => narrowCollectorTrustPolicy(parent, aliasDrift)).toThrow(
      /endpoint identity/,
    );

    const longerDeadline = remotePolicyInput();
    longerDeadline.maximumRequestDurationMs = 60_001;
    expect(() => narrowCollectorTrustPolicy(parent, longerDeadline)).toThrow(
      /duration/,
    );
  });

  it("pins an authorized request and consumes connection authority once", async () => {
    const authorization = authorizeCollectorRequest(
      parsedRemotePolicy(),
      remoteRequest(),
    );
    const pin = await pinAuthorizedCollectorRequest(authorization, {
      totalDeadlineMs: 5_000,
      lookup: publicDns,
    });
    const target = consumePinnedCollectorRequest(pin);

    expect(target).toMatchObject({
      schemaVersion: "tasc-pinned-http-request-v1",
      authority: {
        kind: "collector-trust-policy",
        policyDigest: expect.stringMatching(/^sha256:[a-f0-9]{64}$/),
        authorizationDigest: expect.stringMatching(/^sha256:[a-f0-9]{64}$/),
      },
      method: "POST",
      endpointAlias: "approved-vllm",
      runtime: { profileId: "vllm", build: "0.26.0" },
      url: "https://inference.example.com:8443/v1/chat/completions",
      origin: "https://inference.example.com:8443",
      path: "/v1/chat/completions",
      hostname: "inference.example.com",
      servername: "inference.example.com",
      port: 8443,
      address: "93.184.216.34",
      family: 4,
      authenticationReference: "runtime-prod",
      remainingDeadlineMs: expect.any(Number),
    });
    expect(Object.isFrozen(target)).toBe(true);
    expect(() => consumePinnedCollectorRequest(pin)).toThrow(
      /authentic unconsumed/,
    );
    expect(() =>
      consumePinnedCollectorRequest({
        schemaVersion: "tasc-pinned-collector-request-v1",
      } as never)
    ).toThrow(/authentic unconsumed/);

    const copiedAuthorization = JSON.parse(
      JSON.stringify(authorization),
    );
    await expect(
      pinAuthorizedCollectorRequest(copiedAuthorization, {
        totalDeadlineMs: 1_000,
        lookup: publicDns,
      }),
    ).rejects.toThrow(/authentic/);
  });
});

describe("collector network classification", () => {
  it("allows only explicitly configured exact literal loopback HTTP origins in local mode", async () => {
    for (const origin of [
      "http://127.0.0.1:8000",
      "http://[::1]:8000",
    ]) {
      const policy = parseCollectorTrustPolicy(localPolicyInput(origin));
      const authorization = authorizeCollectorRequest(policy, {
        endpointAlias: "local-vllm",
        runtime: { profileId: "vllm", build: "0.26.0" },
        method: "POST",
        path: "/v1/chat/completions",
      });
      const lookup = vi.fn<CollectorDnsLookup>();
      const pin = await pinAuthorizedCollectorRequest(authorization, {
        totalDeadlineMs: 1_000,
        lookup,
      });
      const target = consumePinnedCollectorRequest(pin);
      expect(target.address).toBe(
        origin.includes("[::1]") ? "::1" : "127.0.0.1",
      );
      expect(target.servername).toBeUndefined();
      expect(lookup).not.toHaveBeenCalled();
    }

    const disabled = localPolicyInput();
    disabled.localMode = "disabled" as never;
    expect(() => parseCollectorTrustPolicy(disabled)).toThrow(
      /literal loopback mode/,
    );

    for (const origin of [
      "http://localhost:8000",
      "http://127.0.0.2:8000",
      "http://0.0.0.0:8000",
      "http://192.168.1.1:8000",
      "http://[::ffff:7f00:1]:8000",
      "https://127.0.0.1:8000",
    ]) {
      expect(
        () => parseCollectorTrustPolicy(localPolicyInput(origin)),
        origin,
      ).toThrow();
    }
  });

  it("rejects non-public literal IPv4 and IPv6 address classes", () => {
    const forbiddenOrigins = [
      "https://0.0.0.0:8443",
      "https://10.0.0.1:8443",
      "https://100.64.0.1:8443",
      "https://127.0.0.1:8443",
      "https://169.254.169.254:8443",
      "https://172.16.0.1:8443",
      "https://192.168.0.1:8443",
      "https://198.18.0.1:8443",
      "https://224.0.0.1:8443",
      "https://255.255.255.255:8443",
      "https://[::]:8443",
      "https://[::1]:8443",
      "https://[::ffff:7f00:1]:8443",
      "https://[64:ff9b::7f00:1]:8443",
      "https://[2001:db8::1]:8443",
      "https://[2002:7f00:1::]:8443",
      "https://[fc00::1]:8443",
      "https://[fe80::1]:8443",
      "https://[ff00::1]:8443",
    ];
    for (const origin of forbiddenOrigins) {
      const input = remotePolicyInput();
      input.endpoints[0]!.origin = origin;
      expect(
        () => parseCollectorTrustPolicy(input),
        origin,
      ).toThrow(/public|HTTPS|loopback/);
    }

    for (const origin of [
      "https://93.184.216.34:8443",
      "https://[2606:4700:4700::1111]:8443",
    ]) {
      const input = remotePolicyInput();
      input.endpoints[0]!.origin = origin;
      expect(() => parseCollectorTrustPolicy(input), origin).not.toThrow();
    }
  });

  it("requires remote HTTPS/public DNS and rejects every mixed answer", async () => {
    const authorization = authorizeCollectorRequest(
      parsedRemotePolicy(),
      remoteRequest({ path: "/v1/chat" }),
    );
    const mixed: CollectorDnsLookup = async () => [
      { address: "93.184.216.34", family: 4 },
      { address: "169.254.169.254", family: 4 },
    ];
    await expect(
      pinAuthorizedCollectorRequest(authorization, {
        totalDeadlineMs: 5_000,
        lookup: mixed,
      }),
    ).rejects.toThrow(/public/);
  });

  it("rejects each non-public DNS class, family mismatch, and oversized or hostile answer sets", async () => {
    const authorization = authorizeCollectorRequest(
      parsedRemotePolicy(),
      remoteRequest({ path: "/v1/chat" }),
    );
    for (const [address, family] of [
      ["0.0.0.0", 4],
      ["10.0.0.1", 4],
      ["100.127.255.255", 4],
      ["127.0.0.1", 4],
      ["169.254.169.254", 4],
      ["172.31.255.255", 4],
      ["192.168.1.1", 4],
      ["::", 6],
      ["::1", 6],
      ["::ffff:127.0.0.1", 6],
      ["fc00::1", 6],
      ["fe80::1", 6],
      ["ff02::1", 6],
      ["2001:db8::1", 6],
      ["93.184.216.34", 6],
    ] as const) {
      await expect(
        pinAuthorizedCollectorRequest(authorization, {
          totalDeadlineMs: 1_000,
          lookup: async () => [{ address, family }],
        }),
        address,
      ).rejects.toThrow(/public/);
    }

    await expect(
      pinAuthorizedCollectorRequest(authorization, {
        totalDeadlineMs: 1_000,
        lookup: async () =>
          Array.from({ length: 33 }, () => ({
            address: "93.184.216.34",
            family: 4 as const,
          })),
      }),
    ).rejects.toThrow(/limit/);

    let invoked = 0;
    const answer = {} as Record<string, unknown>;
    Object.defineProperty(answer, "address", {
      enumerable: true,
      get: () => {
        invoked += 1;
        return "93.184.216.34";
      },
    });
    Object.defineProperty(answer, "family", {
      enumerable: true,
      value: 4,
    });
    await expect(
      pinAuthorizedCollectorRequest(authorization, {
        totalDeadlineMs: 1_000,
        lookup: async () => [answer as never],
      }),
    ).rejects.toThrow(/data fields/);
    expect(invoked).toBe(0);
  });

  it("revalidates DNS on every pin and fails a rebinding answer", async () => {
    const authorization = authorizeCollectorRequest(
      parsedRemotePolicy(),
      remoteRequest({ path: "/v1/chat" }),
    );
    const lookup = vi.fn<CollectorDnsLookup>()
      .mockResolvedValueOnce([{ address: "93.184.216.34", family: 4 }])
      .mockResolvedValueOnce([{ address: "127.0.0.1", family: 4 }]);

    const first = await pinAuthorizedCollectorRequest(authorization, {
      totalDeadlineMs: 5_000,
      lookup,
    });
    expect(consumePinnedCollectorRequest(first).address).toBe("93.184.216.34");
    await expect(
      pinAuthorizedCollectorRequest(authorization, {
        totalDeadlineMs: 5_000,
        lookup,
      }),
    ).rejects.toThrow(/public/);
    expect(lookup).toHaveBeenCalledTimes(2);
  });

  it("bounds DNS and carries one monotonic total deadline through the pin", async () => {
    const authorization = authorizeCollectorRequest(
      parsedRemotePolicy(),
      remoteRequest({ path: "/v1/chat" }),
    );
    const delayed: CollectorDnsLookup = async () => {
      await new Promise((resolve) => setTimeout(resolve, 20));
      return [{ address: "93.184.216.34", family: 4 }];
    };
    const pin = await pinAuthorizedCollectorRequest(authorization, {
      totalDeadlineMs: 200,
      lookup: delayed,
    });
    const target = consumePinnedCollectorRequest(pin);
    expect(target.remainingDeadlineMs).toBeGreaterThan(0);
    expect(target.remainingDeadlineMs).toBeLessThan(200);

    await expect(
      pinAuthorizedCollectorRequest(authorization, {
        totalDeadlineMs: 60_001,
        lookup: publicDns,
      }),
    ).rejects.toThrow(/policy bounds/);

    const never: CollectorDnsLookup = async () =>
      await new Promise<never>(() => undefined);
    await expect(
      pinAuthorizedCollectorRequest(authorization, {
        totalDeadlineMs: 5,
        lookup: never,
      }),
    ).rejects.toThrow(/deadline expired/);

    const localPolicy = parseCollectorTrustPolicy(localPolicyInput());
    const localAuthorization = authorizeCollectorRequest(localPolicy, {
      endpointAlias: "local-vllm",
      runtime: { profileId: "vllm", build: "0.26.0" },
      method: "POST",
      path: "/v1/chat/completions",
    });
    const expiringPin = await pinAuthorizedCollectorRequest(
      localAuthorization,
      { totalDeadlineMs: 5 },
    );
    await new Promise((resolve) => setTimeout(resolve, 12));
    expect(() => consumePinnedCollectorRequest(expiringPin)).toThrow(
      /deadline expired/,
    );
    expect(() => consumePinnedCollectorRequest(expiringPin)).toThrow(
      /authentic unconsumed/,
    );
  });

  it("cancels DNS without contacting it when already aborted and removes in-flight work", async () => {
    const authorization = authorizeCollectorRequest(
      parsedRemotePolicy(),
      remoteRequest({ path: "/v1/chat" }),
    );
    const alreadyAborted = new AbortController();
    alreadyAborted.abort();
    const lookup = vi.fn<CollectorDnsLookup>();
    await expect(
      pinAuthorizedCollectorRequest(authorization, {
        totalDeadlineMs: 1_000,
        signal: alreadyAborted.signal,
        lookup,
      }),
    ).rejects.toThrow(/cancelled/);
    expect(lookup).not.toHaveBeenCalled();

    const controller = new AbortController();
    const pending = pinAuthorizedCollectorRequest(authorization, {
      totalDeadlineMs: 1_000,
      signal: controller.signal,
      lookup: async () => await new Promise<never>(() => undefined),
    });
    controller.abort();
    await expect(pending).rejects.toThrow(/cancelled/);

    const forged = Object.create(AbortSignal.prototype) as AbortSignal;
    await expect(
      pinAuthorizedCollectorRequest(authorization, {
        totalDeadlineMs: 1_000,
        signal: forged,
        lookup: publicDns,
      }),
    ).rejects.toThrow(
      "collector cancellation signal must be an AbortSignal",
    );

    let invoked = 0;
    const tampered = new AbortController().signal;
    Object.defineProperty(tampered, "aborted", {
      configurable: true,
      get: () => {
        invoked += 1;
        return false;
      },
    });
    await expect(
      pinAuthorizedCollectorRequest(authorization, {
        totalDeadlineMs: 1_000,
        signal: tampered,
        lookup: publicDns,
      }),
    ).rejects.toThrow(/AbortSignal/);
    expect(invoked).toBe(0);
  });
});
