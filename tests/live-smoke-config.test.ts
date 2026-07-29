import { describe, expect, it } from "vitest";
import {
  LiveSmokeConfigurationError,
  OPERATOR_LIVE_SMOKE_DEADLINE_MS,
  parseLiveSmokeEnvironment,
  type LiveSmokeEnvironment,
} from "../scripts/live-smoke-config.js";

const DIGEST = `sha256:${"a".repeat(64)}`;

function validEnvironment(
  overrides: LiveSmokeEnvironment = {},
): LiveSmokeEnvironment {
  return {
    TASC_LIVE_SMOKE_ENDPOINT: "https://inference.example.com",
    TASC_LIVE_SMOKE_RUNTIME: "vllm",
    TASC_LIVE_SMOKE_RUNTIME_BUILD: "0.26.0",
    TASC_LIVE_SMOKE_ROUTE: "completions",
    TASC_LIVE_SMOKE_MODEL_ID: "model-id",
    TASC_LIVE_SMOKE_MODEL_REVISION: "immutable-revision",
    TASC_LIVE_SMOKE_BACKEND_NAME: "cuda",
    TASC_LIVE_SMOKE_BACKEND_BUILD: "13.0",
    TASC_LIVE_SMOKE_CONFIGURATION_DIGEST: DIGEST,
    ...overrides,
  };
}

function expectFixedConfigurationError(operation: () => unknown): void {
  let caught: unknown;
  try {
    operation();
  } catch (error) {
    caught = error;
  }
  expect(caught).toBeInstanceOf(LiveSmokeConfigurationError);
  expect((caught as Error).message).toBe(
    "Operator live smoke configuration is invalid.",
  );
}

describe("operator live-smoke configuration", () => {
  it("keeps the deterministic loopback fixture as the no-configuration path", () => {
    const configuration = parseLiveSmokeEnvironment({
      CI: "true",
      TASC_RUNTIME_AUTH_UNUSED: "not-a-live-smoke-trigger",
    });

    expect(configuration).toEqual({ mode: "loopback" });
    expect(Object.isFrozen(configuration)).toBe(true);
  });

  it("builds a bounded public-HTTPS contract for a statically supported route", () => {
    const configuration = parseLiveSmokeEnvironment(validEnvironment());

    expect(configuration.mode).toBe("operator-real");
    if (configuration.mode !== "operator-real") return;
    expect(configuration.policy.localMode).toBe("disabled");
    expect(configuration.policy.maximumRequestDurationMs).toBe(
      OPERATOR_LIVE_SMOKE_DEADLINE_MS,
    );
    expect(configuration.route).toBe("completions");
    expect(configuration.instance).toMatchObject({
      runtime: { profileId: "vllm", build: "0.26.0" },
      backend: { name: "cuda", build: "13.0" },
      model: { id: "model-id", revision: "immutable-revision" },
      configurationDigest: DIGEST,
    });
    expect(configuration.authentication).toBeUndefined();
    expect(Object.isFrozen(configuration)).toBe(true);
  });

  it("allows exact literal loopback only with the explicit opt-in", () => {
    expectFixedConfigurationError(() =>
      parseLiveSmokeEnvironment(validEnvironment({
        TASC_LIVE_SMOKE_ENDPOINT: "http://127.0.0.1:8000",
      }))
    );

    const configuration = parseLiveSmokeEnvironment(validEnvironment({
      TASC_LIVE_SMOKE_ENDPOINT: "http://127.0.0.1:8000",
      TASC_LIVE_SMOKE_ALLOW_LOOPBACK: "1",
    }));
    expect(configuration.mode).toBe("operator-real");
    if (configuration.mode !== "operator-real") return;
    expect(configuration.policy.localMode).toBe("literal-loopback-only");
  });

  it("requires exact identity fields and a supported route without auto-canary", () => {
    expectFixedConfigurationError(() =>
      parseLiveSmokeEnvironment(validEnvironment({
        TASC_LIVE_SMOKE_RUNTIME_BUILD: "latest",
      }))
    );
    expectFixedConfigurationError(() =>
      parseLiveSmokeEnvironment(validEnvironment({
        TASC_LIVE_SMOKE_ROUTE: "chatCompletions",
      }))
    );
    expectFixedConfigurationError(() =>
      parseLiveSmokeEnvironment(validEnvironment({
        TASC_LIVE_SMOKE_MODEL_REVISION: "",
      }))
    );
    expectFixedConfigurationError(() =>
      parseLiveSmokeEnvironment(validEnvironment({
        TASC_LIVE_SMOKE_CONFIGURATION_DIGEST: "sha256:wrong",
      }))
    );
  });

  it("rejects real-endpoint mode in CI before contact", () => {
    expectFixedConfigurationError(() =>
      parseLiveSmokeEnvironment(validEnvironment({ CI: "true" }))
    );
    expectFixedConfigurationError(() =>
      parseLiveSmokeEnvironment(validEnvironment({
        GITHUB_ACTIONS: "true",
      }))
    );
  });

  it("carries only an optional auth environment reference, never its value", () => {
    const secret = "uniquely-sensitive-live-smoke-token";
    const configuration = parseLiveSmokeEnvironment(validEnvironment({
      TASC_LIVE_SMOKE_AUTH_ENV: "TASC_RUNTIME_AUTH_VLLM",
      TASC_LIVE_SMOKE_AUTH_HEADER: "authorization",
      TASC_RUNTIME_AUTH_VLLM: secret,
    }));

    expect(configuration.mode).toBe("operator-real");
    if (configuration.mode !== "operator-real") return;
    expect(configuration.authentication).toEqual({
      environmentVariable: "TASC_RUNTIME_AUTH_VLLM",
      header: "authorization",
      reference: "operator-live-smoke-auth",
    });
    expect(JSON.stringify(configuration)).not.toContain(secret);
  });

  it("uses a non-reflective error for partial, unknown, or malformed input", () => {
    const planted = "https://do-not-reflect.invalid/private-token";
    expectFixedConfigurationError(() =>
      parseLiveSmokeEnvironment({
        TASC_LIVE_SMOKE_ENDPOINT: planted,
      })
    );
    expectFixedConfigurationError(() =>
      parseLiveSmokeEnvironment(validEnvironment({
        TASC_LIVE_SMOKE_DIRECT_API_KEY: planted,
      }))
    );
    expectFixedConfigurationError(() =>
      parseLiveSmokeEnvironment(validEnvironment({
        TASC_LIVE_SMOKE_AUTH_ENV: "TASC_RUNTIME_AUTH_VLLM",
      }))
    );
  });
});
