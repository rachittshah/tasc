import {
  fingerprintCollectorEndpointBinding,
  getRuntimeProfile,
  parseCollectorTrustPolicy,
  parseRuntimeInstanceIdentity,
  type CollectorTrustPolicy,
  type RuntimeInstanceIdentity,
  type RuntimeInvocationPersistence,
  type RuntimeInvocationRoute,
  type RuntimeSecretHeaderName,
} from "../src/runtime/index.js";

export const OPERATOR_LIVE_SMOKE_DEADLINE_MS = 10_000;
export const OPERATOR_LIVE_SMOKE_MAX_REQUEST_BYTES = 64 * 1024;
export const OPERATOR_LIVE_SMOKE_MAX_RESPONSE_BYTES = 1024 * 1024;
export const OPERATOR_LIVE_SMOKE_MAX_TOKENS = 8;
export const OPERATOR_LIVE_SMOKE_ENDPOINT_ALIAS =
  "operator-live-smoke" as const;
export const OPERATOR_LIVE_SMOKE_AUTH_REFERENCE =
  "operator-live-smoke-auth" as const;

const LIVE_SMOKE_PREFIX = "TASC_LIVE_SMOKE_";
const DIGEST_PATTERN = /^sha256:[a-f0-9]{64}$/;
const MODEL_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._+:/-]{0,511}$/;
const AUTH_ENVIRONMENT_PATTERN =
  /^TASC_RUNTIME_AUTH_[A-Z][A-Z0-9_]{0,63}$/;
const ALLOWED_LIVE_SMOKE_ENVIRONMENT_KEYS = new Set([
  "TASC_LIVE_SMOKE_ENDPOINT",
  "TASC_LIVE_SMOKE_RUNTIME",
  "TASC_LIVE_SMOKE_RUNTIME_BUILD",
  "TASC_LIVE_SMOKE_ROUTE",
  "TASC_LIVE_SMOKE_MODEL_ID",
  "TASC_LIVE_SMOKE_MODEL_REVISION",
  "TASC_LIVE_SMOKE_BACKEND_NAME",
  "TASC_LIVE_SMOKE_BACKEND_BUILD",
  "TASC_LIVE_SMOKE_CONFIGURATION_DIGEST",
  "TASC_LIVE_SMOKE_ALLOW_LOOPBACK",
  "TASC_LIVE_SMOKE_AUTH_ENV",
  "TASC_LIVE_SMOKE_AUTH_HEADER",
]);

export type LiveSmokeEnvironment = Readonly<
  Record<string, string | undefined>
>;

export interface LoopbackLiveSmokeConfiguration {
  readonly mode: "loopback";
}

export interface OperatorLiveSmokeAuthentication {
  readonly environmentVariable: string;
  readonly header: RuntimeSecretHeaderName;
  readonly reference: typeof OPERATOR_LIVE_SMOKE_AUTH_REFERENCE;
}

export interface OperatorLiveSmokeConfiguration {
  readonly mode: "operator-real";
  readonly endpointAlias: typeof OPERATOR_LIVE_SMOKE_ENDPOINT_ALIAS;
  readonly policy: CollectorTrustPolicy;
  readonly instance: RuntimeInstanceIdentity;
  readonly route: RuntimeInvocationRoute;
  readonly authentication?: OperatorLiveSmokeAuthentication;
}

export type LiveSmokeConfiguration =
  | LoopbackLiveSmokeConfiguration
  | OperatorLiveSmokeConfiguration;

export interface OperatorLiveSmokeResult {
  readonly schemaVersion: "tasc-operator-live-smoke-result-v1";
  readonly mode: "operator-real";
  readonly authority: "observation-only-no-deployment-authority";
  readonly instance: RuntimeInstanceIdentity;
  readonly invocation: RuntimeInvocationPersistence;
}

export class LiveSmokeConfigurationError extends Error {
  constructor() {
    super("Operator live smoke configuration is invalid.");
    this.name = "LiveSmokeConfigurationError";
    Object.freeze(this);
  }
}

function configurationFail(): never {
  throw new LiveSmokeConfigurationError();
}

function requiredEnvironmentValue(
  environment: LiveSmokeEnvironment,
  key: string,
  maximum = 512,
): string {
  const value = environment[key];
  if (
    typeof value !== "string"
    || value.length < 1
    || value.length > maximum
    || value.trim() !== value
    || /[\u0000-\u001f\u007f]/u.test(value)
  ) {
    configurationFail();
  }
  return value;
}

function ciEnvironmentIsActive(environment: LiveSmokeEnvironment): boolean {
  const active = (value: string | undefined): boolean =>
    value !== undefined
    && value !== ""
    && value.toLowerCase() !== "false"
    && value !== "0";
  return active(environment.CI) || active(environment.GITHUB_ACTIONS);
}

function parseRoute(value: string): RuntimeInvocationRoute {
  if (
    value !== "chatCompletions"
    && value !== "completions"
    && value !== "responses"
    && value !== "nativeChat"
    && value !== "nativeGenerate"
  ) {
    configurationFail();
  }
  return value;
}

function parseAuthentication(
  environment: LiveSmokeEnvironment,
): OperatorLiveSmokeAuthentication | undefined {
  const environmentVariable = environment.TASC_LIVE_SMOKE_AUTH_ENV;
  const header = environment.TASC_LIVE_SMOKE_AUTH_HEADER;
  if (environmentVariable === undefined && header === undefined) {
    return undefined;
  }
  if (
    typeof environmentVariable !== "string"
    || !AUTH_ENVIRONMENT_PATTERN.test(environmentVariable)
    || (header !== "authorization" && header !== "x-api-key")
  ) {
    configurationFail();
  }
  return Object.freeze({
    environmentVariable,
    header,
    reference: OPERATOR_LIVE_SMOKE_AUTH_REFERENCE,
  });
}

function assertEndpointMode(
  endpoint: string,
  allowLoopback: boolean,
): void {
  let parsed: URL;
  try {
    parsed = new URL(endpoint);
  } catch {
    configurationFail();
  }
  const literalLoopback =
    parsed.protocol === "http:"
    && (parsed.hostname === "127.0.0.1" || parsed.hostname === "[::1]");
  if (allowLoopback !== literalLoopback) configurationFail();
}

function parseOperatorConfiguration(
  environment: LiveSmokeEnvironment,
): OperatorLiveSmokeConfiguration {
  if (ciEnvironmentIsActive(environment)) configurationFail();
  for (const key of Object.keys(environment)) {
    if (
      key.startsWith(LIVE_SMOKE_PREFIX)
      && !ALLOWED_LIVE_SMOKE_ENVIRONMENT_KEYS.has(key)
    ) {
      configurationFail();
    }
  }

  const endpoint = requiredEnvironmentValue(
    environment,
    "TASC_LIVE_SMOKE_ENDPOINT",
    2_048,
  );
  const runtimeValue = requiredEnvironmentValue(
    environment,
    "TASC_LIVE_SMOKE_RUNTIME",
    64,
  );
  const profile = getRuntimeProfile(runtimeValue);
  const runtimeBuild = requiredEnvironmentValue(
    environment,
    "TASC_LIVE_SMOKE_RUNTIME_BUILD",
    256,
  );
  if (runtimeBuild !== profile.runtime.build) configurationFail();

  const route = parseRoute(
    requiredEnvironmentValue(
      environment,
      "TASC_LIVE_SMOKE_ROUTE",
      32,
    ),
  );
  const routeDefinition = profile.endpoints.inference[route];
  if (
    routeDefinition === undefined
    || profile.capabilities[routeDefinition.capability].state !== "supported"
  ) {
    configurationFail();
  }

  const modelId = requiredEnvironmentValue(
    environment,
    "TASC_LIVE_SMOKE_MODEL_ID",
  );
  const modelRevision = requiredEnvironmentValue(
    environment,
    "TASC_LIVE_SMOKE_MODEL_REVISION",
  );
  if (
    !MODEL_ID_PATTERN.test(modelId)
    || !MODEL_ID_PATTERN.test(modelRevision)
  ) {
    configurationFail();
  }
  const backendName = requiredEnvironmentValue(
    environment,
    "TASC_LIVE_SMOKE_BACKEND_NAME",
  );
  const backendBuild = requiredEnvironmentValue(
    environment,
    "TASC_LIVE_SMOKE_BACKEND_BUILD",
  );
  const configurationDigest = requiredEnvironmentValue(
    environment,
    "TASC_LIVE_SMOKE_CONFIGURATION_DIGEST",
    71,
  );
  if (!DIGEST_PATTERN.test(configurationDigest)) configurationFail();

  const allowLoopbackValue =
    environment.TASC_LIVE_SMOKE_ALLOW_LOOPBACK;
  if (
    allowLoopbackValue !== undefined
    && allowLoopbackValue !== "1"
  ) {
    configurationFail();
  }
  const allowLoopback = allowLoopbackValue === "1";
  assertEndpointMode(endpoint, allowLoopback);
  const authentication = parseAuthentication(environment);
  const authenticationReferences = authentication === undefined
    ? Object.freeze([]) as readonly string[]
    : Object.freeze([authentication.reference]);
  const policy = parseCollectorTrustPolicy({
    schemaVersion: "tasc-collector-trust-policy-v1",
    localMode: allowLoopback ? "literal-loopback-only" : "disabled",
    maximumRequestDurationMs: OPERATOR_LIVE_SMOKE_DEADLINE_MS,
    endpoints: [{
      alias: OPERATOR_LIVE_SMOKE_ENDPOINT_ALIAS,
      origin: endpoint,
      runtime: {
        profileId: profile.id,
        build: runtimeBuild,
      },
      routes: [{
        method: routeDefinition.method,
        pathPrefix: routeDefinition.path,
        authenticationReferences,
      }],
    }],
    secretReferences: authenticationReferences,
    evaluatorKeyIds: [],
    storeRoots: [],
  });
  const instance = parseRuntimeInstanceIdentity({
    endpointDescriptorDigest: fingerprintCollectorEndpointBinding(
      policy,
      OPERATOR_LIVE_SMOKE_ENDPOINT_ALIAS,
    ),
    runtime: {
      profileId: profile.id,
      build: runtimeBuild,
    },
    backend: {
      name: backendName,
      build: backendBuild,
    },
    model: {
      id: modelId,
      revision: modelRevision,
    },
    configurationDigest,
  });

  return Object.freeze({
    mode: "operator-real",
    endpointAlias: OPERATOR_LIVE_SMOKE_ENDPOINT_ALIAS,
    policy,
    instance,
    route,
    ...(authentication === undefined ? {} : { authentication }),
  });
}

export function parseLiveSmokeEnvironment(
  environment: LiveSmokeEnvironment,
): LiveSmokeConfiguration {
  try {
    const configured = Object.keys(environment).some(
      (key) =>
        key.startsWith(LIVE_SMOKE_PREFIX)
        && environment[key] !== undefined,
    );
    if (!configured) return Object.freeze({ mode: "loopback" });
    return parseOperatorConfiguration(environment);
  } catch {
    configurationFail();
  }
}

export function buildOperatorLiveSmokeResult(
  configuration: OperatorLiveSmokeConfiguration,
  persistence: RuntimeInvocationPersistence,
): OperatorLiveSmokeResult {
  return Object.freeze({
    schemaVersion: "tasc-operator-live-smoke-result-v1",
    mode: "operator-real",
    authority: "observation-only-no-deployment-authority",
    instance: configuration.instance,
    invocation: persistence,
  });
}
