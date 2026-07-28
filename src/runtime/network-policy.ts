import { lookup as nodeLookup } from "node:dns/promises";
import { isIP } from "node:net";
import {
  isAbsolute,
  parse as parsePath,
  resolve as resolvePath,
} from "node:path";
import { isProxy } from "node:util/types";
import { domainSeparatedDigest } from "../evidence.js";
import { RUNTIME_PROFILE_IDS } from "./profiles.js";
import type { RuntimeBuildIdentity, RuntimeProfileId } from "./types.js";

export const COLLECTOR_TRUST_POLICY_VERSION =
  "tasc-collector-trust-policy-v1" as const;

const POLICY_FINGERPRINT_DOMAIN = "tasc/collector-trust-policy/v1";
const AUTHORIZATION_FINGERPRINT_DOMAIN =
  "tasc/collector-request-authorization/v1";
const MAX_ENDPOINTS = 64;
const MAX_ROUTES_PER_ENDPOINT = 128;
const MAX_ALLOWLIST_ITEMS = 256;
const MAX_DNS_ANSWERS = 32;
const MAX_ORIGIN_LENGTH = 2_048;
const MAX_PATH_LENGTH = 2_048;
const MAX_ROOT_LENGTH = 4_096;
const MAX_BUILD_LENGTH = 256;
const MAX_REQUEST_DURATION_MS = 300_000;
const OPAQUE_ID_PATTERN =
  /^[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?$/;
const RUNTIME_BUILD_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._+-]{0,255}$/;
const ROUTE_PATH_PATTERN = /^(?:\/|(?:\/[A-Za-z0-9._~-]+)+)$/;
const REQUEST_PATH_PATTERN =
  /^(?:\/|(?:\/[A-Za-z0-9._~-]+)+(?:\/)?)$/;
const CONTROL_CHARACTER_PATTERN = /[\u0000-\u001f\u007f]/;

export type CollectorRequestMethod = "GET" | "POST";
export type CollectorLocalMode = "disabled" | "literal-loopback-only";

export interface CollectorRouteTrust {
  readonly method: CollectorRequestMethod;
  readonly pathPrefix: string;
  readonly authenticationReferences: readonly string[];
}

export interface CollectorEndpointTrust {
  readonly alias: string;
  readonly origin: string;
  readonly runtime: RuntimeBuildIdentity;
  readonly routes: readonly CollectorRouteTrust[];
}

export interface CollectorTrustPolicy {
  readonly schemaVersion: typeof COLLECTOR_TRUST_POLICY_VERSION;
  readonly localMode: CollectorLocalMode;
  readonly maximumRequestDurationMs: number;
  readonly endpoints: readonly CollectorEndpointTrust[];
  readonly secretReferences: readonly string[];
  readonly evaluatorKeyIds: readonly string[];
  readonly storeRoots: readonly string[];
}

export interface CollectorRequestAuthorizationInput {
  readonly endpointAlias: string;
  readonly runtime: RuntimeBuildIdentity;
  readonly method: CollectorRequestMethod;
  readonly path: string;
  readonly authenticationReference?: string;
}

export interface AuthorizedCollectorRequest {
  readonly schemaVersion: "tasc-authorized-collector-request-v1";
  readonly authority: {
    readonly kind: "collector-trust-policy";
    readonly policyDigest: string;
    readonly authorizationDigest: string;
  };
}

export interface CollectorDnsAddress {
  readonly address: string;
  readonly family: 4 | 6;
}

export type CollectorDnsLookup = (
  hostname: string,
) => Promise<readonly CollectorDnsAddress[]>;

export interface CollectorPinOptions {
  readonly totalDeadlineMs: number;
  readonly signal?: AbortSignal;
  readonly lookup?: CollectorDnsLookup;
}

export interface PinnedCollectorRequest {
  readonly schemaVersion: "tasc-pinned-collector-request-v1";
  readonly authority: {
    readonly kind: "collector-trust-policy";
    readonly policyDigest: string;
    readonly authorizationDigest: string;
  };
}

export interface PinnedHttpRequestTarget {
  readonly schemaVersion: "tasc-pinned-http-request-v1";
  readonly authority: {
    readonly kind: "collector-trust-policy";
    readonly policyDigest: string;
    readonly authorizationDigest: string;
  };
  readonly endpointAlias: string;
  readonly runtime: RuntimeBuildIdentity;
  readonly url: string;
  readonly origin: string;
  readonly path: string;
  readonly method: CollectorRequestMethod;
  readonly hostname: string;
  readonly servername?: string;
  readonly port: number;
  readonly address: string;
  readonly family: 4 | 6;
  readonly authenticationReference?: string;
  readonly remainingDeadlineMs: number;
}

interface OriginInspection {
  readonly kind: "literal-loopback" | "remote-dns" | "remote-literal";
  readonly urlHostname: string;
  readonly lookupHostname: string;
  readonly port: number;
  readonly literalAddress?: string;
  readonly literalFamily?: 4 | 6;
}

interface EndpointAuthority {
  readonly endpoint: CollectorEndpointTrust;
  readonly origin: OriginInspection;
}

interface PolicyAuthority {
  readonly digest: string;
  readonly endpoints: ReadonlyMap<string, EndpointAuthority>;
}

interface RequestAuthority {
  readonly policyDigest: string;
  readonly authorizationDigest: string;
  readonly endpointAlias: string;
  readonly runtime: RuntimeBuildIdentity;
  readonly url: string;
  readonly origin: string;
  readonly path: string;
  readonly method: CollectorRequestMethod;
  readonly hostname: string;
  readonly lookupHostname: string;
  readonly port: number;
  readonly networkKind: OriginInspection["kind"];
  readonly literalAddress?: string;
  readonly literalFamily?: 4 | 6;
  readonly authenticationReference?: string;
  readonly maximumRequestDurationMs: number;
}

const policyAuthorities = new WeakMap<object, PolicyAuthority>();
const requestAuthorities = new WeakMap<object, RequestAuthority>();
const pinAuthorities = new WeakMap<object, {
  readonly target: Omit<PinnedHttpRequestTarget, "remainingDeadlineMs">;
  readonly expiresAtNs: bigint;
}>();

const ABORTED_GETTER =
  Reflect.getOwnPropertyDescriptor(AbortSignal.prototype, "aborted")?.get;
const ADD_EVENT_LISTENER = Reflect.getOwnPropertyDescriptor(
  EventTarget.prototype,
  "addEventListener",
)?.value as ((...args: unknown[]) => unknown) | undefined;
const REMOVE_EVENT_LISTENER = Reflect.getOwnPropertyDescriptor(
  EventTarget.prototype,
  "removeEventListener",
)?.value as ((...args: unknown[]) => unknown) | undefined;

function deepFreeze<T>(value: T): T {
  if (value === null || typeof value !== "object" || Object.isFrozen(value)) {
    return value;
  }
  for (const descriptor of Object.values(
    Object.getOwnPropertyDescriptors(value),
  )) {
    if (Object.hasOwn(descriptor, "value")) {
      deepFreeze(descriptor.value);
    }
  }
  return Object.freeze(value);
}

function snapshotStrictRecord(
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

  const snapshot: Record<string, unknown> = Object.create(null);
  for (const key of Reflect.ownKeys(input)) {
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
    snapshot[key] = descriptor.value;
  }
  return snapshot;
}

function snapshotStrictArray(
  input: unknown,
  label: string,
  maximum: number,
): readonly unknown[] {
  if (
    input === null
    || typeof input !== "object"
    || isProxy(input)
    || !Array.isArray(input)
    || Reflect.getPrototypeOf(input) !== Array.prototype
  ) {
    throw new Error(`${label} must be a plain non-proxy array`);
  }
  const lengthDescriptor = Reflect.getOwnPropertyDescriptor(input, "length");
  const length = lengthDescriptor?.value;
  if (
    typeof length !== "number"
    || !Number.isSafeInteger(length)
    || length < 0
    || length > maximum
  ) {
    throw new Error(`${label} exceeds its item limit`);
  }

  const allowedKeys = new Set(["length"]);
  const snapshot = new Array<unknown>(length);
  for (let index = 0; index < length; index += 1) {
    const key = String(index);
    allowedKeys.add(key);
    const descriptor = Reflect.getOwnPropertyDescriptor(input, key);
    if (descriptor === undefined) {
      throw new Error(`${label} cannot contain holes`);
    }
    if (!descriptor.enumerable || !Object.hasOwn(descriptor, "value")) {
      throw new Error(`${label} requires enumerable data items`);
    }
    snapshot[index] = descriptor.value;
  }
  for (const key of Reflect.ownKeys(input)) {
    if (typeof key !== "string") {
      throw new Error(`${label} cannot contain symbol fields`);
    }
    if (!allowedKeys.has(key)) {
      throw new Error(`${label} cannot contain extra fields`);
    }
  }
  return snapshot;
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
    || CONTROL_CHARACTER_PATTERN.test(value)
  ) {
    throw new Error(`${label} must be a bounded non-empty string`);
  }
  return value;
}

function parseOpaqueId(value: unknown, label: string): string {
  const id = boundedString(value, label, 128);
  if (!OPAQUE_ID_PATTERN.test(id) || id.includes("..")) {
    throw new Error(`${label} must be a lowercase opaque identifier`);
  }
  return id;
}

function parseRuntimeIdentity(
  input: unknown,
  label: string,
): RuntimeBuildIdentity {
  const snapshot = snapshotStrictRecord(
    input,
    label,
    new Set(["profileId", "build"]),
  );
  if (
    typeof snapshot.profileId !== "string"
    || !RUNTIME_PROFILE_IDS.includes(
      snapshot.profileId as RuntimeProfileId,
    )
  ) {
    throw new Error(`${label} must identify a registered runtime profile`);
  }
  const build = boundedString(
    snapshot.build,
    `${label} build`,
    MAX_BUILD_LENGTH,
  );
  if (!RUNTIME_BUILD_PATTERN.test(build) || build.includes("..")) {
    throw new Error(`${label} build must be a constant-safe runtime identifier`);
  }
  return {
    profileId: snapshot.profileId as RuntimeProfileId,
    build,
  };
}

function parseCanonicalRoutePath(value: unknown): string {
  const path = boundedString(value, "route path prefix", MAX_PATH_LENGTH);
  if (
    !ROUTE_PATH_PATTERN.test(path)
    || path.includes("%")
    || path.split("/").some((segment) =>
      segment === "." || segment === ".."
    )
  ) {
    throw new Error("route path prefix must be a canonical absolute path");
  }
  return path;
}

function parseCanonicalRequestPath(value: unknown): string {
  const path = boundedString(value, "request path", MAX_PATH_LENGTH);
  if (
    !REQUEST_PATH_PATTERN.test(path)
    || path.includes("%")
    || path.includes("?")
    || path.includes("#")
    || path.split("/").some((segment) =>
      segment === "." || segment === ".."
    )
  ) {
    throw new Error("request path must be a canonical absolute path");
  }
  return path;
}

function parseMethod(value: unknown): CollectorRequestMethod {
  if (value !== "GET" && value !== "POST") {
    throw new Error("collector request method is not authorized");
  }
  return value;
}

function parseCanonicalRoot(value: unknown): string {
  const root = boundedString(value, "store root", MAX_ROOT_LENGTH);
  if (!isAbsolute(root)) {
    throw new Error("store root must be a canonical absolute local path");
  }
  const normalized = resolvePath(root);
  if (
    normalized !== root
    || normalized === parsePath(normalized).root
  ) {
    throw new Error("store root must be a canonical non-filesystem root");
  }
  return root;
}

function parseUniqueStrings(
  input: unknown,
  label: string,
  parser: (value: unknown) => string,
): readonly string[] {
  const values = snapshotStrictArray(input, label, MAX_ALLOWLIST_ITEMS)
    .map(parser)
    .sort();
  for (let index = 1; index < values.length; index += 1) {
    if (values[index] === values[index - 1]) {
      throw new Error(`${label} cannot contain duplicate entries`);
    }
  }
  return values;
}

function compareStrings(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function parseCanonicalIpv4(address: string): readonly number[] | undefined {
  const parts = address.split(".");
  if (parts.length !== 4) return undefined;
  const octets = parts.map((part) => {
    if (!/^(?:0|[1-9][0-9]{0,2})$/.test(part)) return -1;
    const value = Number(part);
    return value <= 255 ? value : -1;
  });
  return octets.every((octet) => octet >= 0) ? octets : undefined;
}

function isPublicIpv4(address: string): boolean {
  const octets = parseCanonicalIpv4(address);
  if (octets === undefined) return false;
  const [a = -1, b = -1, c = -1] = octets;
  if (
    a === 0
    || a === 10
    || a === 127
    || a >= 224
    || (a === 100 && b >= 64 && b <= 127)
    || (a === 169 && b === 254)
    || (a === 172 && b >= 16 && b <= 31)
    || (a === 192 && b === 0 && c === 0)
    || (a === 192 && b === 0 && c === 2)
    || (a === 192 && b === 88 && c === 99)
    || (a === 192 && b === 168)
    || (a === 198 && (b === 18 || b === 19))
    || (a === 198 && b === 51 && c === 100)
    || (a === 203 && b === 0 && c === 113)
  ) {
    return false;
  }
  return true;
}

function ipv6Words(address: string): readonly number[] | undefined {
  if (address.includes("%")) return undefined;
  const halves = address.toLowerCase().split("::");
  if (halves.length > 2) return undefined;

  const parseHalf = (half: string): number[] | undefined => {
    if (half === "") return [];
    const result: number[] = [];
    const parts = half.split(":");
    for (let index = 0; index < parts.length; index += 1) {
      const part = parts[index] ?? "";
      if (part.includes(".")) {
        if (index !== parts.length - 1) return undefined;
        const ipv4 = parseCanonicalIpv4(part);
        if (ipv4 === undefined) return undefined;
        result.push(
          ((ipv4[0] ?? 0) << 8) | (ipv4[1] ?? 0),
          ((ipv4[2] ?? 0) << 8) | (ipv4[3] ?? 0),
        );
      } else {
        if (!/^[a-f0-9]{1,4}$/.test(part)) return undefined;
        result.push(Number.parseInt(part, 16));
      }
    }
    return result;
  };

  const left = parseHalf(halves[0] ?? "");
  const right = parseHalf(halves[1] ?? "");
  if (left === undefined || right === undefined) return undefined;
  if (halves.length === 1) return left.length === 8 ? left : undefined;
  const missing = 8 - left.length - right.length;
  if (missing < 1) return undefined;
  return [...left, ...new Array<number>(missing).fill(0), ...right];
}

function isPublicIpv6(address: string): boolean {
  const words = ipv6Words(address);
  if (words === undefined || words.length !== 8) return false;
  const first = words[0] ?? 0;
  const second = words[1] ?? 0;
  if ((first & 0xe000) !== 0x2000) return false;
  if (first === 0x2001 && second <= 0x01ff) return false;
  if (first === 0x2001 && second === 0x0db8) return false;
  if (first === 0x2002) return false;
  if ((first & 0xfff0) === 0x3ff0) return false;
  return true;
}

function isPublicAddress(address: string, family: 4 | 6): boolean {
  return family === 4
    ? isIP(address) === 4 && isPublicIpv4(address)
    : isIP(address) === 6 && isPublicIpv6(address);
}

function stripIpv6Brackets(hostname: string): string {
  return hostname.startsWith("[") && hostname.endsWith("]")
    ? hostname.slice(1, -1)
    : hostname;
}

function isCanonicalDnsHostname(hostname: string): boolean {
  if (
    hostname.length < 1
    || hostname.length > 253
    || hostname.endsWith(".")
    || hostname !== hostname.toLowerCase()
    || !hostname.includes(".")
  ) {
    return false;
  }
  const labels = hostname.split(".");
  return labels.every((label) =>
    label.length >= 1
    && label.length <= 63
    && /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label)
  ) && !/^[0-9]+$/.test(labels.at(-1) ?? "");
}

function inspectCanonicalOrigin(
  value: unknown,
  localMode: CollectorLocalMode,
): OriginInspection {
  const origin = boundedString(value, "collector endpoint origin", MAX_ORIGIN_LENGTH);
  let parsed: URL;
  try {
    parsed = new URL(origin);
  } catch {
    throw new Error("collector endpoint origin must be canonical");
  }
  if (
    parsed.username !== ""
    || parsed.password !== ""
    || parsed.search !== ""
    || parsed.hash !== ""
    || parsed.pathname !== "/"
    || parsed.origin !== origin
    || parsed.href !== `${origin}/`
    || parsed.hostname.includes("%")
  ) {
    throw new Error("collector endpoint origin must be canonical");
  }

  const lookupHostname = stripIpv6Brackets(parsed.hostname);
  const family = isIP(lookupHostname);
  const port = parsed.port === ""
    ? parsed.protocol === "https:" ? 443 : 80
    : Number(parsed.port);
  if (!Number.isSafeInteger(port) || port < 1 || port > 65_535) {
    throw new Error("collector endpoint origin has an invalid port");
  }
  const exactLoopback =
    lookupHostname === "127.0.0.1" || lookupHostname === "::1";

  if (
    parsed.protocol === "http:"
    && exactLoopback
    && localMode === "literal-loopback-only"
  ) {
    return {
      kind: "literal-loopback",
      urlHostname: parsed.hostname,
      lookupHostname,
      port,
      literalAddress: lookupHostname,
      literalFamily: lookupHostname === "127.0.0.1" ? 4 : 6,
    };
  }
  if (parsed.protocol !== "https:" || exactLoopback) {
    throw new Error(
      "collector endpoints require remote HTTPS or explicit literal loopback mode",
    );
  }
  if (family === 4 || family === 6) {
    if (!isPublicAddress(lookupHostname, family)) {
      throw new Error("remote collector endpoint must use a public address");
    }
    return {
      kind: "remote-literal",
      urlHostname: parsed.hostname,
      lookupHostname,
      port,
      literalAddress: lookupHostname,
      literalFamily: family,
    };
  }
  if (!isCanonicalDnsHostname(lookupHostname)) {
    throw new Error("remote collector endpoint hostname must be canonical");
  }
  return {
    kind: "remote-dns",
    urlHostname: parsed.hostname,
    lookupHostname,
    port,
  };
}

const ROUTE_KEYS = new Set([
  "method",
  "pathPrefix",
  "authenticationReferences",
]);

function parseRoute(
  input: unknown,
  allowedSecrets: ReadonlySet<string>,
): CollectorRouteTrust {
  const snapshot = snapshotStrictRecord(
    input,
    "collector route",
    ROUTE_KEYS,
  );
  const authenticationReferences = parseUniqueStrings(
    snapshot.authenticationReferences,
    "route authentication references",
    (value) => parseOpaqueId(value, "authentication reference"),
  );
  if (
    authenticationReferences.some((reference) =>
      !allowedSecrets.has(reference)
    )
  ) {
    throw new Error(
      "route authentication reference is outside the secret allowlist",
    );
  }
  return {
    method: parseMethod(snapshot.method),
    pathPrefix: parseCanonicalRoutePath(snapshot.pathPrefix),
    authenticationReferences,
  };
}

const ENDPOINT_KEYS = new Set([
  "alias",
  "origin",
  "runtime",
  "routes",
]);

function parseEndpoint(
  input: unknown,
  localMode: CollectorLocalMode,
  allowedSecrets: ReadonlySet<string>,
): {
  readonly endpoint: CollectorEndpointTrust;
  readonly origin: OriginInspection;
} {
  const snapshot = snapshotStrictRecord(
    input,
    "collector endpoint",
    ENDPOINT_KEYS,
  );
  const origin = inspectCanonicalOrigin(snapshot.origin, localMode);
  const routes = snapshotStrictArray(
    snapshot.routes,
    "collector endpoint routes",
    MAX_ROUTES_PER_ENDPOINT,
  ).map((route) => parseRoute(route, allowedSecrets));
  if (routes.length < 1) {
    throw new Error("collector endpoint requires at least one route");
  }
  routes.sort((left, right) =>
    compareStrings(left.method, right.method)
    || compareStrings(left.pathPrefix, right.pathPrefix)
  );
  for (let index = 1; index < routes.length; index += 1) {
    const previous = routes[index - 1];
    const current = routes[index];
    if (
      previous?.method === current?.method
      && previous.pathPrefix === current.pathPrefix
    ) {
      throw new Error("collector endpoint cannot contain duplicate routes");
    }
  }
  return {
    endpoint: {
      alias: parseOpaqueId(snapshot.alias, "endpoint alias"),
      origin: boundedString(
        snapshot.origin,
        "collector endpoint origin",
        MAX_ORIGIN_LENGTH,
      ),
      runtime: parseRuntimeIdentity(
        snapshot.runtime,
        "collector endpoint runtime",
      ),
      routes,
    },
    origin,
  };
}

const POLICY_KEYS = new Set([
  "schemaVersion",
  "localMode",
  "maximumRequestDurationMs",
  "endpoints",
  "secretReferences",
  "evaluatorKeyIds",
  "storeRoots",
]);

export function parseCollectorTrustPolicy(
  input: unknown,
): CollectorTrustPolicy {
  const snapshot = snapshotStrictRecord(
    input,
    "collector trust policy",
    POLICY_KEYS,
  );
  if (snapshot.schemaVersion !== COLLECTOR_TRUST_POLICY_VERSION) {
    throw new Error("collector trust policy has an unsupported version");
  }
  if (
    snapshot.localMode !== "disabled"
    && snapshot.localMode !== "literal-loopback-only"
  ) {
    throw new Error("collector trust policy has an invalid local mode");
  }
  const localMode = snapshot.localMode;
  if (
    typeof snapshot.maximumRequestDurationMs !== "number"
    || !Number.isSafeInteger(snapshot.maximumRequestDurationMs)
    || snapshot.maximumRequestDurationMs < 1
    || snapshot.maximumRequestDurationMs > MAX_REQUEST_DURATION_MS
  ) {
    throw new Error("collector maximum request duration is out of bounds");
  }
  const maximumRequestDurationMs = snapshot.maximumRequestDurationMs;
  const secretReferences = parseUniqueStrings(
    snapshot.secretReferences,
    "collector secret references",
    (value) => parseOpaqueId(value, "secret reference"),
  );
  const evaluatorKeyIds = parseUniqueStrings(
    snapshot.evaluatorKeyIds,
    "collector evaluator key ids",
    (value) => parseOpaqueId(value, "evaluator key id"),
  );
  const storeRoots = parseUniqueStrings(
    snapshot.storeRoots,
    "collector store roots",
    parseCanonicalRoot,
  );
  const parsedEndpoints = snapshotStrictArray(
    snapshot.endpoints,
    "collector endpoints",
    MAX_ENDPOINTS,
  ).map((endpoint) =>
    parseEndpoint(endpoint, localMode, new Set(secretReferences))
  );
  if (parsedEndpoints.length < 1) {
    throw new Error("collector trust policy requires at least one endpoint");
  }
  parsedEndpoints.sort((left, right) =>
    compareStrings(left.endpoint.alias, right.endpoint.alias)
  );

  const endpointAuthorities = new Map<string, EndpointAuthority>();
  for (const parsed of parsedEndpoints) {
    if (endpointAuthorities.has(parsed.endpoint.alias)) {
      throw new Error("collector endpoint aliases must be unique");
    }
    endpointAuthorities.set(parsed.endpoint.alias, {
      endpoint: parsed.endpoint,
      origin: parsed.origin,
    });
  }

  const policy = deepFreeze<CollectorTrustPolicy>({
    schemaVersion: COLLECTOR_TRUST_POLICY_VERSION,
    localMode,
    maximumRequestDurationMs,
    endpoints: parsedEndpoints.map(({ endpoint }) => endpoint),
    secretReferences,
    evaluatorKeyIds,
    storeRoots,
  });
  policyAuthorities.set(policy, {
    digest: domainSeparatedDigest(POLICY_FINGERPRINT_DOMAIN, policy),
    endpoints: endpointAuthorities,
  });
  return policy;
}

function authenticPolicyAuthority(
  policy: CollectorTrustPolicy,
): PolicyAuthority {
  const authority =
    policy !== null && typeof policy === "object"
      ? policyAuthorities.get(policy)
      : undefined;
  if (authority === undefined) {
    throw new Error("an authentic collector trust policy is required");
  }
  return authority;
}

export function fingerprintCollectorTrustPolicy(input: unknown): string {
  const policy = parseCollectorTrustPolicy(input);
  return authenticPolicyAuthority(policy).digest;
}

function pathIsWithin(path: string, prefix: string): boolean {
  return prefix === "/"
    || path === prefix
    || path.startsWith(`${prefix}/`);
}

function mostSpecificRoute(
  routes: readonly CollectorRouteTrust[],
  method: CollectorRequestMethod,
  path: string,
): CollectorRouteTrust | undefined {
  let selected: CollectorRouteTrust | undefined;
  for (const route of routes) {
    if (
      route.method === method
      && pathIsWithin(path, route.pathPrefix)
      && (
        selected === undefined
        || route.pathPrefix.length > selected.pathPrefix.length
      )
    ) {
      selected = route;
    }
  }
  return selected;
}

function sameRuntime(
  left: RuntimeBuildIdentity,
  right: RuntimeBuildIdentity,
): boolean {
  return left.profileId === right.profileId && left.build === right.build;
}

const AUTHORIZATION_KEYS = new Set([
  "endpointAlias",
  "runtime",
  "method",
  "path",
  "authenticationReference",
]);

export function authorizeCollectorRequest(
  policy: CollectorTrustPolicy,
  input: unknown,
): AuthorizedCollectorRequest {
  const policyAuthority = authenticPolicyAuthority(policy);
  const snapshot = snapshotStrictRecord(
    input,
    "collector request authorization",
    AUTHORIZATION_KEYS,
  );
  const endpointAlias = parseOpaqueId(
    snapshot.endpointAlias,
    "endpoint alias",
  );
  const runtime = parseRuntimeIdentity(
    snapshot.runtime,
    "collector request runtime",
  );
  const method = parseMethod(snapshot.method);
  const path = parseCanonicalRequestPath(snapshot.path);
  const endpoint = policyAuthority.endpoints.get(endpointAlias);
  if (
    endpoint === undefined
    || !sameRuntime(runtime, endpoint.endpoint.runtime)
  ) {
    throw new Error("collector request is not authorized");
  }
  const route = mostSpecificRoute(endpoint.endpoint.routes, method, path);
  if (route === undefined) {
    throw new Error("collector request is not authorized");
  }

  const authenticationReference = Object.hasOwn(
    snapshot,
    "authenticationReference",
  )
    ? parseOpaqueId(
      snapshot.authenticationReference,
      "authentication reference",
    )
    : undefined;
  if (
    route.authenticationReferences.length === 0
      ? authenticationReference !== undefined
      : authenticationReference === undefined
        || !route.authenticationReferences.includes(authenticationReference)
  ) {
    throw new Error("collector request is not authorized");
  }

  const url = `${endpoint.endpoint.origin}${path}`;
  const authorizationBody = {
    policyDigest: policyAuthority.digest,
    endpointAlias,
    runtime,
    origin: endpoint.endpoint.origin,
    method,
    path,
    authenticationReference: authenticationReference ?? null,
  };
  const authorizationDigest = domainSeparatedDigest(
    AUTHORIZATION_FINGERPRINT_DOMAIN,
    authorizationBody,
  );
  const publicAuthority = deepFreeze({
    kind: "collector-trust-policy" as const,
    policyDigest: policyAuthority.digest,
    authorizationDigest,
  });
  const authorization = deepFreeze<AuthorizedCollectorRequest>({
    schemaVersion: "tasc-authorized-collector-request-v1",
    authority: publicAuthority,
  });
  requestAuthorities.set(authorization, {
    policyDigest: policyAuthority.digest,
    authorizationDigest,
    endpointAlias,
    runtime,
    url,
    origin: endpoint.endpoint.origin,
    path,
    method,
    hostname: endpoint.origin.urlHostname,
    lookupHostname: endpoint.origin.lookupHostname,
    port: endpoint.origin.port,
    networkKind: endpoint.origin.kind,
    ...(endpoint.origin.literalAddress === undefined
      ? {}
      : { literalAddress: endpoint.origin.literalAddress }),
    ...(endpoint.origin.literalFamily === undefined
      ? {}
      : { literalFamily: endpoint.origin.literalFamily }),
    ...(authenticationReference === undefined
      ? {}
      : { authenticationReference }),
    maximumRequestDurationMs: policy.maximumRequestDurationMs,
  });
  return authorization;
}

function allowlistIsSubset(
  candidate: readonly string[],
  parent: readonly string[],
): boolean {
  const parentValues = new Set(parent);
  return candidate.every((value) => parentValues.has(value));
}

export function narrowCollectorTrustPolicy(
  parent: CollectorTrustPolicy,
  candidateInput: unknown,
): CollectorTrustPolicy {
  authenticPolicyAuthority(parent);
  const candidate = parseCollectorTrustPolicy(candidateInput);
  if (
    parent.localMode === "disabled"
    && candidate.localMode !== "disabled"
  ) {
    throw new Error("collector trust policy narrowing cannot widen local mode");
  }
  if (
    candidate.maximumRequestDurationMs > parent.maximumRequestDurationMs
  ) {
    throw new Error(
      "collector trust policy narrowing cannot widen request duration",
    );
  }
  if (
    !allowlistIsSubset(candidate.secretReferences, parent.secretReferences)
    || !allowlistIsSubset(candidate.evaluatorKeyIds, parent.evaluatorKeyIds)
    || !allowlistIsSubset(candidate.storeRoots, parent.storeRoots)
  ) {
    throw new Error("collector trust policy narrowing cannot widen allowlists");
  }

  const parentEndpoints = new Map(
    parent.endpoints.map((endpoint) => [endpoint.alias, endpoint]),
  );
  for (const endpoint of candidate.endpoints) {
    const parentEndpoint = parentEndpoints.get(endpoint.alias);
    if (
      parentEndpoint === undefined
      || endpoint.origin !== parentEndpoint.origin
      || !sameRuntime(endpoint.runtime, parentEndpoint.runtime)
    ) {
      throw new Error(
        "collector trust policy narrowing cannot widen endpoint identity",
      );
    }
    for (const route of endpoint.routes) {
      const parentRoute = mostSpecificRoute(
        parentEndpoint.routes,
        route.method,
        route.pathPrefix,
      );
      const authenticationNarrows =
        parentRoute !== undefined
        && (
          parentRoute.authenticationReferences.length === 0
            ? route.authenticationReferences.length === 0
            : route.authenticationReferences.length > 0
              && allowlistIsSubset(
                route.authenticationReferences,
                parentRoute.authenticationReferences,
              )
        );
      if (!authenticationNarrows) {
        throw new Error(
          "collector trust policy narrowing cannot widen route authority",
        );
      }
    }
  }
  return candidate;
}

export function assertCollectorEvaluatorKeyAuthorized(
  policy: CollectorTrustPolicy,
  keyId: unknown,
): void {
  authenticPolicyAuthority(policy);
  const parsed = parseOpaqueId(keyId, "evaluator key id");
  if (!policy.evaluatorKeyIds.includes(parsed)) {
    throw new Error("collector evaluator key is not authorized");
  }
}

export function assertCollectorStoreRootAuthorized(
  policy: CollectorTrustPolicy,
  root: unknown,
): void {
  authenticPolicyAuthority(policy);
  const parsed = parseCanonicalRoot(root);
  if (!policy.storeRoots.includes(parsed)) {
    throw new Error("collector store root is not authorized");
  }
}

const defaultCollectorDnsLookup: CollectorDnsLookup = async (hostname) => {
  const answers = await nodeLookup(hostname, {
    all: true,
    verbatim: true,
  });
  return answers.map(({ address, family }) => ({
    address,
    family: family as 4 | 6,
  }));
};

function parseDnsAnswers(input: unknown): readonly CollectorDnsAddress[] {
  const snapshots = snapshotStrictArray(
    input,
    "collector DNS answers",
    MAX_DNS_ANSWERS,
  );
  if (snapshots.length < 1) {
    throw new Error("collector DNS resolution returned no public addresses");
  }
  return snapshots.map((inputAnswer) => {
    const answer = snapshotStrictRecord(
      inputAnswer,
      "collector DNS answer",
      new Set(["address", "family"]),
    );
    if (
      typeof answer.address !== "string"
      || (answer.family !== 4 && answer.family !== 6)
      || !isPublicAddress(answer.address, answer.family)
    ) {
      throw new Error(
        "collector DNS resolution must contain only public addresses",
      );
    }
    return {
      address: answer.address,
      family: answer.family,
    };
  });
}

function remainingDeadlineMs(expiresAtNs: bigint): number {
  const remainingNs = expiresAtNs - process.hrtime.bigint();
  if (remainingNs <= 0n) return 0;
  return Math.floor(Number(remainingNs) / 1_000_000);
}

function inspectAbortSignal(value: unknown): AbortSignal | undefined {
  if (value === undefined) return undefined;
  const invalidSignal = () =>
    new Error("collector cancellation signal must be an AbortSignal");
  if (
    value === null
    || typeof value !== "object"
    || isProxy(value)
    || Reflect.getPrototypeOf(value) !== AbortSignal.prototype
    || ABORTED_GETTER === undefined
    || ADD_EVENT_LISTENER === undefined
    || REMOVE_EVENT_LISTENER === undefined
    || Reflect.ownKeys(value).some((key) => typeof key === "string")
  ) {
    throw invalidSignal();
  }
  try {
    if (typeof Reflect.apply(ABORTED_GETTER, value, []) !== "boolean") {
      throw invalidSignal();
    }
  } catch {
    throw invalidSignal();
  }
  return value as AbortSignal;
}

function signalIsAborted(signal: AbortSignal): boolean {
  return Reflect.apply(ABORTED_GETTER!, signal, []) as boolean;
}

function addAbortListener(
  signal: AbortSignal,
  listener: () => void,
): void {
  Reflect.apply(ADD_EVENT_LISTENER!, signal, [
    "abort",
    listener,
    { once: true },
  ]);
}

function removeAbortListener(
  signal: AbortSignal,
  listener: () => void,
): void {
  Reflect.apply(REMOVE_EVENT_LISTENER!, signal, ["abort", listener]);
}

async function boundedDnsLookup(
  hostname: string,
  lookup: CollectorDnsLookup,
  expiresAtNs: bigint,
  signal: AbortSignal | undefined,
): Promise<readonly CollectorDnsAddress[]> {
  let timeout: ReturnType<typeof setTimeout> | undefined;
  let abortListener: (() => void) | undefined;
  try {
    if (signal !== undefined && signalIsAborted(signal)) {
      throw new Error("collector request was cancelled");
    }
    const remainingMs = remainingDeadlineMs(expiresAtNs);
    if (remainingMs < 1) {
      throw new Error("collector request deadline expired");
    }
    const timeoutPromise = new Promise<never>((_resolve, reject) => {
      timeout = setTimeout(() => {
        reject(new Error("collector request deadline expired"));
      }, remainingMs);
    });
    const cancellationPromise = signal === undefined
      ? new Promise<never>(() => undefined)
      : new Promise<never>((_resolve, reject) => {
        abortListener = () => {
          reject(new Error("collector request was cancelled"));
        };
        addAbortListener(signal, abortListener);
        if (signalIsAborted(signal)) abortListener();
      });
    const answers = await Promise.race([
      Promise.resolve().then(() => lookup(hostname)),
      timeoutPromise,
      cancellationPromise,
    ]);
    return parseDnsAnswers(answers);
  } catch (error) {
    if (
      error instanceof Error
      && (
        error.message === "collector request deadline expired"
        || error.message === "collector request was cancelled"
        || error.message.startsWith("collector DNS resolution must")
        || error.message.startsWith("collector DNS resolution returned")
        || error.message.startsWith("collector DNS answers")
        || error.message.startsWith("collector DNS answer")
      )
    ) {
      throw error;
    }
    throw new Error("collector DNS resolution failed");
  } finally {
    if (timeout !== undefined) clearTimeout(timeout);
    if (signal !== undefined && abortListener !== undefined) {
      removeAbortListener(signal, abortListener);
    }
  }
}

const PIN_OPTION_KEYS = new Set([
  "totalDeadlineMs",
  "signal",
  "lookup",
]);

export async function pinAuthorizedCollectorRequest(
  authorization: AuthorizedCollectorRequest,
  optionsInput: CollectorPinOptions,
): Promise<PinnedCollectorRequest> {
  const startedAtNs = process.hrtime.bigint();
  const authority =
    authorization !== null && typeof authorization === "object"
      ? requestAuthorities.get(authorization)
      : undefined;
  if (authority === undefined) {
    throw new Error("an authentic authorized collector request is required");
  }
  const options = snapshotStrictRecord(
    optionsInput,
    "collector pin options",
    PIN_OPTION_KEYS,
  );
  if (
    typeof options.totalDeadlineMs !== "number"
    || !Number.isSafeInteger(options.totalDeadlineMs)
    || options.totalDeadlineMs < 1
    || options.totalDeadlineMs > authority.maximumRequestDurationMs
  ) {
    throw new Error("collector request deadline is out of policy bounds");
  }
  const signal = inspectAbortSignal(options.signal);
  const lookupValue = options.lookup === undefined
    ? defaultCollectorDnsLookup
    : options.lookup;
  if (typeof lookupValue !== "function" || isProxy(lookupValue)) {
    throw new Error("collector DNS lookup must be a trusted function");
  }
  const lookup = lookupValue as CollectorDnsLookup;
  if (signal !== undefined && signalIsAborted(signal)) {
    throw new Error("collector request was cancelled");
  }
  const expiresAtNs =
    startedAtNs + BigInt(options.totalDeadlineMs) * 1_000_000n;

  let selected: CollectorDnsAddress;
  if (authority.networkKind === "remote-dns") {
    const answers = await boundedDnsLookup(
      authority.lookupHostname,
      lookup,
      expiresAtNs,
      signal,
    );
    selected = answers[0]!;
  } else {
    selected = {
      address: authority.literalAddress!,
      family: authority.literalFamily!,
    };
  }
  if (remainingDeadlineMs(expiresAtNs) < 1) {
    throw new Error("collector request deadline expired");
  }
  const deadlineBoundAuthorizationDigest = domainSeparatedDigest(
    "tasc/collector-request-deadline-authorization/v1",
    {
      authorizationDigest: authority.authorizationDigest,
      totalDeadlineMs: options.totalDeadlineMs,
    },
  );
  const publicAuthority = deepFreeze({
    kind: "collector-trust-policy" as const,
    policyDigest: authority.policyDigest,
    authorizationDigest: deadlineBoundAuthorizationDigest,
  });
  const target = deepFreeze<Omit<
    PinnedHttpRequestTarget,
    "remainingDeadlineMs"
  >>({
    schemaVersion: "tasc-pinned-http-request-v1",
    authority: publicAuthority,
    endpointAlias: authority.endpointAlias,
    runtime: authority.runtime,
    url: authority.url,
    origin: authority.origin,
    path: authority.path,
    method: authority.method,
    hostname: authority.hostname,
    ...(authority.networkKind === "remote-dns"
      ? { servername: authority.lookupHostname }
      : {}),
    port: authority.port,
    address: selected.address,
    family: selected.family,
    ...(authority.authenticationReference === undefined
      ? {}
      : { authenticationReference: authority.authenticationReference }),
  });
  const pin = deepFreeze<PinnedCollectorRequest>({
    schemaVersion: "tasc-pinned-collector-request-v1",
    authority: publicAuthority,
  });
  pinAuthorities.set(pin, { target, expiresAtNs });
  return pin;
}

/**
 * One-shot handoff to the HTTP transport. Structural copies, JSON round trips,
 * caller-fabricated pins, and already-consumed pins fail before network I/O.
 */
export function consumePinnedCollectorRequest(
  pin: PinnedCollectorRequest,
): PinnedHttpRequestTarget {
  const authority =
    pin !== null && typeof pin === "object"
      ? pinAuthorities.get(pin)
      : undefined;
  if (authority === undefined) {
    throw new Error(
      "an authentic unconsumed pinned collector request is required",
    );
  }
  pinAuthorities.delete(pin);
  const remainingMs = remainingDeadlineMs(authority.expiresAtNs);
  if (remainingMs < 1) {
    throw new Error("pinned collector request deadline expired");
  }
  return deepFreeze({
    ...authority.target,
    remainingDeadlineMs: remainingMs,
  });
}
