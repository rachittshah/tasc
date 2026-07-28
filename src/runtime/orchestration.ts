import { isProxy } from "node:util/types";
import { domainSeparatedDigest } from "../evidence.js";
import { getRuntimeProfile } from "./profiles.js";
import type {
  EndpointDescriptor,
  RayServeEndpointDescriptorInput,
  SkyPilotEndpointDescriptorInput,
} from "./types.js";

const DIGEST_PATTERN = /^sha256:[a-f0-9]{64}$/;
const OPAQUE_REFERENCE_PATTERN =
  /^[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?$/;
const LOCATOR_PATTERN = /^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,126}[A-Za-z0-9])?$/;
const ROUTE_PREFIX_PATTERN = /^(?:\/|(?:\/[A-Za-z0-9._~-]+)+)$/;
const MAX_ORIGIN_LENGTH = 2_048;
const MAX_BUILD_LENGTH = 256;
const ENDPOINT_FINGERPRINT_DOMAIN = "tasc/endpoint-descriptor/v1";

const RAY_INPUT_KEYS = new Set([
  "origin",
  "routePrefix",
  "runtimeProfileId",
  "runtimeBuild",
  "rayBuild",
  "configurationDigest",
  "applicationName",
  "deploymentName",
  "authenticationReference",
]);
const SKY_INPUT_KEYS = new Set([
  "origin",
  "routePrefix",
  "runtimeProfileId",
  "runtimeBuild",
  "skyPilotBuild",
  "configurationDigest",
  "mode",
  "serviceName",
  "authenticationReference",
]);
const ENDPOINT_KEYS = new Set([
  "schemaVersion",
  "origin",
  "basePath",
  "runtime",
  "orchestration",
  "authority",
]);

function deepFreezeDescriptor<T>(value: T): T {
  if (value === null || typeof value !== "object" || Object.isFrozen(value)) {
    return value;
  }
  for (const descriptor of Object.values(
    Object.getOwnPropertyDescriptors(value),
  )) {
    if (Object.hasOwn(descriptor, "value")) {
      deepFreezeDescriptor(descriptor.value);
    }
  }
  return Object.freeze(value);
}

function snapshotRecord(
  input: unknown,
  label: string,
  allowedKeys: ReadonlySet<string>,
): Record<string, unknown> {
  if (input === null || typeof input !== "object") {
    throw new Error(`${label} must be a plain object`);
  }
  if (isProxy(input)) {
    throw new Error(`${label} cannot be a proxy`);
  }
  const prototype = Reflect.getPrototypeOf(input);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new Error(`${label} must be a plain object`);
  }
  const ownKeys = Reflect.ownKeys(input);
  if (ownKeys.length > allowedKeys.size) {
    throw new Error(`${label} contains an unknown field`);
  }
  const result: Record<string, unknown> = Object.create(null);
  for (const key of ownKeys) {
    if (typeof key !== "string") {
      throw new Error(`${label} cannot contain symbol fields`);
    }
    if (!allowedKeys.has(key)) {
      throw new Error(`${label} contains an unknown field`);
    }
    const descriptor = Reflect.getOwnPropertyDescriptor(input, key);
    if (
      descriptor === undefined
      || !descriptor.enumerable
      || !Object.hasOwn(descriptor, "value")
    ) {
      throw new Error(`${label} requires enumerable data fields`);
    }
    result[key] = descriptor.value;
  }
  return result;
}

function boundedString(
  value: unknown,
  label: string,
  maximum: number,
): string {
  if (
    typeof value !== "string"
    || value.length < 1
    || value.length > maximum
    || value.trim() !== value
  ) {
    throw new Error(`${label} must be a bounded non-empty string`);
  }
  return value;
}

function parseDigest(value: unknown): string {
  if (typeof value !== "string" || !DIGEST_PATTERN.test(value)) {
    throw new Error("configuration digest must be a canonical sha256: digest");
  }
  return value;
}

function parseLocator(value: unknown, label: string): string {
  const locator = boundedString(value, label, 128);
  if (!LOCATOR_PATTERN.test(locator)) {
    throw new Error(`${label} must be an opaque service identifier`);
  }
  return locator;
}

function parseAuthenticationReference(value: unknown): string | undefined {
  if (value === undefined) return undefined;
  const reference = boundedString(value, "authentication reference", 128);
  if (!OPAQUE_REFERENCE_PATTERN.test(reference)) {
    throw new Error(
      "authentication reference must be a lowercase opaque identifier",
    );
  }
  return reference;
}

function parseCanonicalOrigin(value: unknown): string {
  const origin = boundedString(value, "endpoint origin", MAX_ORIGIN_LENGTH);
  let parsed: URL;
  try {
    parsed = new URL(origin);
  } catch {
    throw new Error("endpoint must use a canonical HTTP(S) origin");
  }
  if (
    (parsed.protocol !== "http:" && parsed.protocol !== "https:")
    || parsed.username !== ""
    || parsed.password !== ""
    || parsed.pathname !== "/"
    || parsed.search !== ""
    || parsed.hash !== ""
    || parsed.origin !== origin
  ) {
    throw new Error("endpoint must use a canonical HTTP(S) origin");
  }
  return origin;
}

function parseRoutePrefix(value: unknown): string {
  const routePrefix = boundedString(value, "route prefix", 1_024);
  if (
    !ROUTE_PREFIX_PATTERN.test(routePrefix)
    || routePrefix.includes("%")
    || routePrefix.split("/").some((segment) =>
      segment === "." || segment === ".."
    )
  ) {
    throw new Error("route prefix must be a bounded canonical absolute path");
  }
  return routePrefix;
}

function descriptorAuthority(input: unknown): EndpointDescriptor["authority"] {
  const snapshot = snapshotRecord(
    input,
    "endpoint authority",
    new Set(["deployment", "network"]),
  );
  if (snapshot.deployment !== "none" || snapshot.network !== "unverified") {
    throw new Error("endpoint descriptor cannot claim deployment or network authority");
  }
  return { deployment: "none", network: "unverified" };
}

function descriptorRuntime(input: unknown): EndpointDescriptor["runtime"] {
  const snapshot = snapshotRecord(
    input,
    "endpoint runtime",
    new Set(["profileId", "build"]),
  );
  const profileId = boundedString(
    snapshot.profileId,
    "runtime profile id",
    128,
  );
  const profile = getRuntimeProfile(profileId);
  const build = boundedString(snapshot.build, "runtime build", MAX_BUILD_LENGTH);
  return { profileId: profile.id, build };
}

function descriptorOrchestration(
  input: unknown,
): EndpointDescriptor["orchestration"] {
  const base = snapshotRecord(
    input,
    "endpoint orchestration",
    new Set([
      "kind",
      "build",
      "configurationDigest",
      "locator",
      "authenticationReference",
    ]),
  );
  if (
    base.kind !== "ray-serve"
    && base.kind !== "skypilot"
    && base.kind !== "skyserve"
  ) {
    throw new Error("endpoint orchestration has an unknown kind");
  }
  const build = boundedString(
    base.build,
    "orchestration build",
    MAX_BUILD_LENGTH,
  );
  const configurationDigest = parseDigest(base.configurationDigest);
  const authenticationReference = parseAuthenticationReference(
    base.authenticationReference,
  );
  if (base.kind === "ray-serve") {
    const locator = snapshotRecord(
      base.locator,
      "Ray Serve locator",
      new Set(["applicationName", "deploymentName"]),
    );
    return {
      kind: "ray-serve",
      build,
      configurationDigest,
      locator: {
        applicationName: parseLocator(
          locator.applicationName,
          "Ray Serve application name",
        ),
        deploymentName: parseLocator(
          locator.deploymentName,
          "Ray Serve deployment name",
        ),
      },
      ...(authenticationReference === undefined
        ? {}
        : { authenticationReference }),
    };
  }
  const locator = snapshotRecord(
    base.locator,
    "SkyPilot locator",
    new Set(["serviceName"]),
  );
  return {
    kind: base.kind,
    build,
    configurationDigest,
    locator: {
      serviceName: parseLocator(locator.serviceName, "SkyPilot service name"),
    },
    ...(authenticationReference === undefined
      ? {}
      : { authenticationReference }),
  };
}

export function parseEndpointDescriptor(input: unknown): EndpointDescriptor {
  const snapshot = snapshotRecord(
    input,
    "endpoint descriptor",
    ENDPOINT_KEYS,
  );
  if (snapshot.schemaVersion !== "tasc-endpoint-descriptor-v1") {
    throw new Error(
      'endpoint descriptor schemaVersion must be "tasc-endpoint-descriptor-v1"',
    );
  }
  return deepFreezeDescriptor({
    schemaVersion: "tasc-endpoint-descriptor-v1",
    origin: parseCanonicalOrigin(snapshot.origin),
    basePath: parseRoutePrefix(snapshot.basePath),
    runtime: descriptorRuntime(snapshot.runtime),
    orchestration: descriptorOrchestration(snapshot.orchestration),
    authority: descriptorAuthority(snapshot.authority),
  });
}

export function fingerprintEndpointDescriptor(input: unknown): string {
  return domainSeparatedDigest(
    ENDPOINT_FINGERPRINT_DOMAIN,
    parseEndpointDescriptor(input),
  );
}

export function createRayServeEndpointDescriptor(
  input: RayServeEndpointDescriptorInput | unknown,
): EndpointDescriptor {
  const snapshot = snapshotRecord(input, "Ray Serve endpoint", RAY_INPUT_KEYS);
  const profileId = boundedString(
    snapshot.runtimeProfileId,
    "runtime profile id",
    128,
  );
  const profile = getRuntimeProfile(profileId);
  return parseEndpointDescriptor({
    schemaVersion: "tasc-endpoint-descriptor-v1",
    origin: parseCanonicalOrigin(snapshot.origin),
    basePath: parseRoutePrefix(snapshot.routePrefix),
    runtime: {
      profileId: profile.id,
      build: boundedString(
        snapshot.runtimeBuild,
        "runtime build",
        MAX_BUILD_LENGTH,
      ),
    },
    orchestration: {
      kind: "ray-serve",
      build: boundedString(snapshot.rayBuild, "Ray build", MAX_BUILD_LENGTH),
      configurationDigest: parseDigest(snapshot.configurationDigest),
      locator: {
        applicationName: parseLocator(
          snapshot.applicationName,
          "Ray Serve application name",
        ),
        deploymentName: parseLocator(
          snapshot.deploymentName,
          "Ray Serve deployment name",
        ),
      },
      ...(parseAuthenticationReference(snapshot.authenticationReference)
          === undefined
        ? {}
        : {
          authenticationReference: parseAuthenticationReference(
            snapshot.authenticationReference,
          ),
        }),
    },
    authority: {
      deployment: "none",
      network: "unverified",
    },
  });
}

export function createSkyPilotEndpointDescriptor(
  input: SkyPilotEndpointDescriptorInput | unknown,
): EndpointDescriptor {
  const snapshot = snapshotRecord(
    input,
    "SkyPilot endpoint",
    SKY_INPUT_KEYS,
  );
  if (snapshot.mode !== "skypilot" && snapshot.mode !== "skyserve") {
    throw new Error("SkyPilot endpoint has an unknown mode");
  }
  const profileId = boundedString(
    snapshot.runtimeProfileId,
    "runtime profile id",
    128,
  );
  const profile = getRuntimeProfile(profileId);
  return parseEndpointDescriptor({
    schemaVersion: "tasc-endpoint-descriptor-v1",
    origin: parseCanonicalOrigin(snapshot.origin),
    basePath: parseRoutePrefix(snapshot.routePrefix),
    runtime: {
      profileId: profile.id,
      build: boundedString(
        snapshot.runtimeBuild,
        "runtime build",
        MAX_BUILD_LENGTH,
      ),
    },
    orchestration: {
      kind: snapshot.mode,
      build: boundedString(
        snapshot.skyPilotBuild,
        "SkyPilot build",
        MAX_BUILD_LENGTH,
      ),
      configurationDigest: parseDigest(snapshot.configurationDigest),
      locator: {
        serviceName: parseLocator(
          snapshot.serviceName,
          "SkyPilot service name",
        ),
      },
      ...(parseAuthenticationReference(snapshot.authenticationReference)
          === undefined
        ? {}
        : {
          authenticationReference: parseAuthenticationReference(
            snapshot.authenticationReference,
          ),
        }),
    },
    authority: {
      deployment: "none",
      network: "unverified",
    },
  });
}
