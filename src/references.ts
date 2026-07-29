import { Buffer } from "node:buffer";
import { createHmac, createSecretKey, type KeyObject } from "node:crypto";
import {
  isAbsolute,
  parse as parsePath,
  resolve as resolvePath,
} from "node:path";
import {
  isKeyObject,
  isProxy,
  isSharedArrayBuffer,
  isUint8Array,
} from "node:util/types";

export const CONTROLLED_REFERENCE_REGISTRY_VERSION =
  "tasc-controlled-reference-registry-v1" as const;
export const MAX_CONTROLLED_REFERENCE_STORES = 64;
export const MAX_PAYLOAD_IDENTITY_BYTES = 16 * 1024 * 1024;

const MAX_LOCAL_ROOT_LENGTH = 4_096;
const MAX_ID_LENGTH = 128;
const CONTRACT_ID_PATTERN =
  /^[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?$/;
const CONTRACT_DIGEST_PATTERN = /^sha256:[a-f0-9]{64}$/;
const URL_OR_INLINE_PATTERN = /^(?:data|file|https?|inline):/i;
const HMAC_DOMAIN = "tasc/payload-identity/v1\u0000";

export interface ControlledReference {
  readonly kind: "controlled-reference";
  readonly storeId: string;
  readonly referenceId: string;
  readonly digest?: string;
}

export interface ControlledReferenceStore {
  readonly storeId: string;
  readonly root: string;
}

export interface ControlledReferenceRegistry {
  readonly version: typeof CONTROLLED_REFERENCE_REGISTRY_VERSION;
  readonly storeIds: readonly string[];
}

export interface AuthorizedControlledReference {
  readonly reference: ControlledReference;
  toJSON(): ControlledReference;
}

export interface KeyedPayloadIdentity {
  readonly algorithm: "hmac-sha256";
  readonly keyId: string;
  readonly value: string;
}

const registryAuthorities =
  new WeakMap<object, ReadonlyMap<string, string>>();
const referenceAuthorities = new WeakMap<object, string>();

const SECRET_KEY_PROBE = createSecretKey(Buffer.alloc(32));
const SECRET_KEY_PROTOTYPE = Reflect.getPrototypeOf(SECRET_KEY_PROBE);
const KEY_OBJECT_PROTOTYPE = SECRET_KEY_PROTOTYPE === null
  ? null
  : Reflect.getPrototypeOf(SECRET_KEY_PROTOTYPE);
const KEY_OBJECT_TYPE_GETTER = KEY_OBJECT_PROTOTYPE === null
  ? undefined
  : Reflect.getOwnPropertyDescriptor(KEY_OBJECT_PROTOTYPE, "type")?.get;
const SECRET_KEY_SIZE_GETTER = SECRET_KEY_PROTOTYPE === null
  ? undefined
  : Reflect.getOwnPropertyDescriptor(
    SECRET_KEY_PROTOTYPE,
    "symmetricKeySize",
  )?.get;

const TYPED_ARRAY_PROTOTYPE = Reflect.getPrototypeOf(Uint8Array.prototype);
const TYPED_ARRAY_BUFFER_GETTER = TYPED_ARRAY_PROTOTYPE === null
  ? undefined
  : Reflect.getOwnPropertyDescriptor(TYPED_ARRAY_PROTOTYPE, "buffer")?.get;
const TYPED_ARRAY_BYTE_OFFSET_GETTER = TYPED_ARRAY_PROTOTYPE === null
  ? undefined
  : Reflect.getOwnPropertyDescriptor(
    TYPED_ARRAY_PROTOTYPE,
    "byteOffset",
  )?.get;
const TYPED_ARRAY_BYTE_LENGTH_GETTER = TYPED_ARRAY_PROTOTYPE === null
  ? undefined
  : Reflect.getOwnPropertyDescriptor(
    TYPED_ARRAY_PROTOTYPE,
    "byteLength",
  )?.get;

function assertContractId(
  value: unknown,
  label: "storeId" | "referenceId" | "studyId" | "keyId",
): asserts value is string {
  if (
    typeof value !== "string"
    || value.length < 1
    || value.length > MAX_ID_LENGTH
    || !CONTRACT_ID_PATTERN.test(value)
    || value.includes("..")
    || URL_OR_INLINE_PATTERN.test(value)
  ) {
    throw new Error(
      `${label} must be a bounded lowercase opaque identifier without paths or traversal`,
    );
  }
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
  const keys = Reflect.ownKeys(input);
  if (keys.length > allowedKeys.size) {
    throw new Error(`${label} contains an unknown field or exceeds its field limit`);
  }

  const snapshot: Record<string, unknown> = Object.create(null);
  for (const key of keys) {
    if (typeof key !== "string") {
      throw new Error(`${label} cannot contain symbol fields`);
    }
    if (!allowedKeys.has(key)) {
      throw new Error(`${label} contains an unknown field`);
    }
    const descriptor = Reflect.getOwnPropertyDescriptor(input, key);
    if (descriptor === undefined) {
      throw new Error(`${label} changed during validation`);
    }
    if (!descriptor.enumerable) {
      throw new Error(`${label} cannot contain non-enumerable fields`);
    }
    if (!Object.hasOwn(descriptor, "value")) {
      throw new Error(`${label} cannot contain accessor fields`);
    }
    snapshot[key] = descriptor.value;
  }
  return snapshot;
}

const REFERENCE_KEYS = new Set([
  "kind",
  "storeId",
  "referenceId",
  "digest",
]);

/** Parse the exact controlled-reference shape accepted by evidence contracts. */
export function parseControlledReference(input: unknown): ControlledReference {
  const snapshot = snapshotStrictRecord(
    input,
    "controlled reference",
    REFERENCE_KEYS,
  );
  if (snapshot.kind !== "controlled-reference") {
    throw new Error('controlled reference kind must be "controlled-reference"');
  }
  assertContractId(snapshot.storeId, "storeId");
  assertContractId(snapshot.referenceId, "referenceId");
  if (
    Object.hasOwn(snapshot, "digest")
    && (
      typeof snapshot.digest !== "string"
      || !CONTRACT_DIGEST_PATTERN.test(snapshot.digest)
    )
  ) {
    throw new Error("controlled reference digest must be a canonical sha256: digest");
  }

  const reference: {
    kind: "controlled-reference";
    storeId: string;
    referenceId: string;
    digest?: string;
  } = {
    kind: "controlled-reference",
    storeId: snapshot.storeId,
    referenceId: snapshot.referenceId,
  };
  if (typeof snapshot.digest === "string") reference.digest = snapshot.digest;
  return Object.freeze(reference);
}

const STORE_KEYS = new Set(["storeId", "root"]);

function normalizeTrustedRoot(value: unknown): string {
  if (
    typeof value !== "string"
    || value.length < 1
    || value.length > MAX_LOCAL_ROOT_LENGTH
    || value.trim() !== value
    || value.includes("\u0000")
    || URL_OR_INLINE_PATTERN.test(value)
    || !isAbsolute(value)
  ) {
    throw new Error("controlled-reference store root must be a bounded absolute local path");
  }
  const normalized = resolvePath(value);
  if (
    !isAbsolute(normalized)
    || normalized === parsePath(normalized).root
  ) {
    throw new Error("controlled-reference store root cannot be a filesystem root");
  }
  return normalized;
}

function snapshotStoreArray(input: unknown): readonly unknown[] {
  if (input === null || typeof input !== "object" || isProxy(input)) {
    throw new Error("controlled-reference stores must be a non-proxy array");
  }
  if (!Array.isArray(input) || Reflect.getPrototypeOf(input) !== Array.prototype) {
    throw new Error("controlled-reference stores must be a plain array");
  }

  const lengthDescriptor = Reflect.getOwnPropertyDescriptor(input, "length");
  const length = lengthDescriptor?.value;
  if (
    typeof length !== "number"
    || !Number.isSafeInteger(length)
    || length < 1
    || length > MAX_CONTROLLED_REFERENCE_STORES
  ) {
    throw new Error(
      `controlled-reference store limit is 1-${MAX_CONTROLLED_REFERENCE_STORES}`,
    );
  }

  const allowedKeys = new Set<string>(["length"]);
  const snapshot = new Array<unknown>(length);
  for (let index = 0; index < length; index += 1) {
    const key = String(index);
    allowedKeys.add(key);
    const descriptor = Reflect.getOwnPropertyDescriptor(input, key);
    if (descriptor === undefined) {
      throw new Error("controlled-reference store array cannot contain holes");
    }
    if (!Object.hasOwn(descriptor, "value")) {
      throw new Error("controlled-reference store array cannot contain accessors");
    }
    snapshot[index] = descriptor.value;
  }
  for (const key of Reflect.ownKeys(input)) {
    if (typeof key !== "string") {
      throw new Error("controlled-reference store array cannot contain symbols");
    }
    if (!allowedKeys.has(key)) {
      throw new Error("controlled-reference store array cannot contain extra fields");
    }
  }
  return snapshot;
}

/**
 * Register lexical store roots supplied by trusted local configuration. No
 * filesystem access occurs here; store implementations must separately apply
 * descriptor-safe realpath containment when opening a referenced payload.
 */
export function createControlledReferenceRegistry(
  stores: unknown,
): ControlledReferenceRegistry {
  const storeInputs = snapshotStoreArray(stores);
  const roots = new Map<string, string>();
  const rootOwners = new Map<string, string>();

  for (const storeInput of storeInputs) {
    const snapshot = snapshotStrictRecord(
      storeInput,
      "controlled-reference store",
      STORE_KEYS,
    );
    assertContractId(snapshot.storeId, "storeId");
    const root = normalizeTrustedRoot(snapshot.root);
    if (roots.has(snapshot.storeId)) {
      throw new Error("duplicate store id");
    }
    const existingOwner = rootOwners.get(root);
    if (existingOwner !== undefined) {
      throw new Error("duplicate trusted root");
    }
    roots.set(snapshot.storeId, root);
    rootOwners.set(root, snapshot.storeId);
  }

  const storeIds = Object.freeze([...roots.keys()].sort());
  const registry = Object.freeze({
    version: CONTROLLED_REFERENCE_REGISTRY_VERSION,
    storeIds,
  });
  registryAuthorities.set(registry, roots);
  return registry;
}

/**
 * Resolve only a locally registered store. The trusted root remains entirely
 * out of the returned object's structural surface and can only be recovered
 * through the authentic-authority resolver below.
 */
export function authorizeControlledReference(
  registry: ControlledReferenceRegistry,
  input: unknown,
): AuthorizedControlledReference {
  const roots = registry !== null && typeof registry === "object"
    ? registryAuthorities.get(registry)
    : undefined;
  if (roots === undefined) {
    throw new Error("an authentic local controlled-reference registry is required");
  }

  const reference = parseControlledReference(input);
  const trustedRoot = roots.get(reference.storeId);
  if (trustedRoot === undefined) {
    throw new Error("unknown controlled-reference store");
  }

  const authorization = {} as {
    reference: ControlledReference;
    toJSON(): ControlledReference;
  };
  Object.defineProperties(authorization, {
    reference: {
      value: reference,
      enumerable: true,
      writable: false,
      configurable: false,
    },
    toJSON: {
      value: (): ControlledReference => reference,
      enumerable: false,
      writable: false,
      configurable: false,
    },
  });
  const frozen = Object.freeze(authorization);
  referenceAuthorities.set(frozen, trustedRoot);
  return frozen;
}

/**
 * Recover a trusted root only from an authority minted in this process.
 * Structural copies, JSON round trips, and lookalike frozen objects fail closed.
 */
export function resolveAuthorizedControlledReferenceRoot(
  authorization: AuthorizedControlledReference,
): string {
  const trustedRoot =
    authorization !== null && typeof authorization === "object"
      ? referenceAuthorities.get(authorization)
      : undefined;
  if (trustedRoot === undefined) {
    throw new Error(
      "an authentic authorized controlled reference is required",
    );
  }
  return trustedRoot;
}

interface InspectedPayload {
  readonly view: Uint8Array;
  readonly byteLength: number;
}

function inspectPayload(payload: unknown): InspectedPayload | undefined {
  if (
    payload === null
    || typeof payload !== "object"
    || isProxy(payload)
    || !isUint8Array(payload)
    || TYPED_ARRAY_BUFFER_GETTER === undefined
    || TYPED_ARRAY_BYTE_OFFSET_GETTER === undefined
    || TYPED_ARRAY_BYTE_LENGTH_GETTER === undefined
  ) {
    return undefined;
  }
  try {
    const buffer = Reflect.apply(
      TYPED_ARRAY_BUFFER_GETTER,
      payload,
      [],
    ) as ArrayBufferLike;
    if (isSharedArrayBuffer(buffer)) return undefined;
    const byteOffset = Reflect.apply(
      TYPED_ARRAY_BYTE_OFFSET_GETTER,
      payload,
      [],
    ) as number;
    const byteLength = Reflect.apply(
      TYPED_ARRAY_BYTE_LENGTH_GETTER,
      payload,
      [],
    ) as number;
    return Object.freeze({
      view: new Uint8Array(buffer, byteOffset, byteLength),
      byteLength,
    });
  } catch {
    return undefined;
  }
}

function inspectSecretKeySize(key: unknown): number | undefined {
  if (
    key === null
    || typeof key !== "object"
    || isProxy(key)
    || !isKeyObject(key)
    || KEY_OBJECT_TYPE_GETTER === undefined
    || SECRET_KEY_SIZE_GETTER === undefined
    || Reflect.getPrototypeOf(key) !== SECRET_KEY_PROTOTYPE
    || Reflect.getOwnPropertyDescriptor(key, "type") !== undefined
    || Reflect.getOwnPropertyDescriptor(key, "symmetricKeySize") !== undefined
  ) {
    return undefined;
  }
  try {
    const type = Reflect.apply(KEY_OBJECT_TYPE_GETTER, key, []) as unknown;
    if (type !== "secret") return undefined;
    const size = Reflect.apply(SECRET_KEY_SIZE_GETTER, key, []) as unknown;
    return typeof size === "number" ? size : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Derive an opaque private-payload identity. The secret key must remain in a
 * runtime KeyObject and the bounded payload snapshot is zeroed after hashing.
 * Neither value is represented in the returned wire contract.
 */
export function createStudyPayloadIdentity(
  studyId: string,
  keyId: string,
  key: KeyObject,
  payload: Uint8Array,
): KeyedPayloadIdentity {
  assertContractId(studyId, "studyId");
  assertContractId(keyId, "keyId");

  const keySize = inspectSecretKeySize(key);
  if (keySize === undefined) {
    throw new Error("payload HMAC key must be a secret runtime KeyObject");
  }
  if (keySize < 32) {
    throw new Error("payload HMAC KeyObject must contain at least 32 bytes");
  }
  const inspectedPayload = inspectPayload(payload);
  if (inspectedPayload === undefined) {
    throw new Error("payload identity input must be a Uint8Array");
  }
  if (inspectedPayload.byteLength > MAX_PAYLOAD_IDENTITY_BYTES) {
    throw new Error(
      `payload byte limit is ${MAX_PAYLOAD_IDENTITY_BYTES}`,
    );
  }

  let snapshot: Buffer;
  try {
    snapshot = Buffer.from(inspectedPayload.view);
  } catch {
    throw new Error("payload identity input could not be snapshotted");
  }
  try {
    const value = createHmac("sha256", key)
      .update(HMAC_DOMAIN, "utf8")
      .update(studyId, "utf8")
      .update("\u0000", "utf8")
      .update(keyId, "utf8")
      .update("\u0000", "utf8")
      .update(snapshot)
      .digest("hex");
    return Object.freeze({
      algorithm: "hmac-sha256",
      keyId,
      value,
    });
  } finally {
    snapshot.fill(0);
  }
}
