import { Buffer } from "node:buffer";
import { createSecretKey } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  CONTROLLED_REFERENCE_REGISTRY_VERSION,
  MAX_CONTROLLED_REFERENCE_STORES,
  MAX_PAYLOAD_IDENTITY_BYTES,
  authorizeControlledReference,
  createControlledReferenceRegistry,
  createStudyPayloadIdentity,
  parseControlledReference,
  resolveAuthorizedControlledReferenceRoot,
} from "../src/references.js";

const TRUSTED_ROOT = "/srv/tasc/private-payloads";

describe("controlled payload references", () => {
  it("strictly parses and freezes the existing controlled-reference wire shape", () => {
    const reference = parseControlledReference({
      kind: "controlled-reference",
      storeId: "encrypted-payloads",
      referenceId: "case-42.output-1",
      digest: `sha256:${"a".repeat(64)}`,
    });

    expect(reference).toEqual({
      kind: "controlled-reference",
      storeId: "encrypted-payloads",
      referenceId: "case-42.output-1",
      digest: `sha256:${"a".repeat(64)}`,
    });
    expect(Object.isFrozen(reference)).toBe(true);
  });

  it("rejects unknown, hidden, symbolic, and accessor-backed fields", () => {
    expect(() => parseControlledReference({
      kind: "controlled-reference",
      storeId: "encrypted-payloads",
      referenceId: "case-42",
      inline: "private output",
    })).toThrow(/unknown field/i);

    const hidden = {
      kind: "controlled-reference",
      storeId: "encrypted-payloads",
      referenceId: "case-42",
    };
    Object.defineProperty(hidden, "path", {
      enumerable: false,
      value: "/etc/passwd",
    });
    expect(() => parseControlledReference(hidden)).toThrow(/unknown|non-enumerable/i);

    const symbolic = {
      kind: "controlled-reference",
      storeId: "encrypted-payloads",
      referenceId: "case-42",
      [Symbol("secret")]: "private output",
    };
    expect(() => parseControlledReference(symbolic)).toThrow(/symbol/i);

    let reads = 0;
    const accessor = {
      kind: "controlled-reference",
      storeId: "encrypted-payloads",
      get referenceId() {
        reads += 1;
        return "case-42";
      },
    };
    expect(() => parseControlledReference(accessor)).toThrow(/accessor/i);
    expect(reads).toBe(0);
  });

  it("never reflects attacker-controlled field names in diagnostics", () => {
    const secretField = "Authorization_planted_secret_field_should_not_log";
    let message = "";
    try {
      parseControlledReference({
        kind: "controlled-reference",
        storeId: "encrypted-payloads",
        referenceId: "case-42",
        [secretField]: "private output",
      });
    } catch (error) {
      message = error instanceof Error ? error.message : String(error);
    }

    expect(message).toMatch(/unknown field/i);
    expect(message).not.toContain(secretField);
    expect(message.length).toBeLessThan(128);
  });

  it("rejects proxies without invoking caller traps", () => {
    let traps = 0;
    const input = new Proxy(
      {
        kind: "controlled-reference",
        storeId: "encrypted-payloads",
        referenceId: "case-42",
      },
      {
        ownKeys() {
          traps += 1;
          throw new Error("ownKeys");
        },
        getOwnPropertyDescriptor() {
          traps += 1;
          throw new Error("descriptor");
        },
      },
    );

    expect(() => parseControlledReference(input)).toThrow(/proxy/i);
    expect(traps).toBe(0);
  });

  it.each([
    "file:///srv/private/output",
    "data:text/plain,private",
    "http://runtime.invalid/output",
    "https://runtime.invalid/output",
    "inline:private-output",
    "../private-output",
    "..\\private-output",
    "nested/private-output",
    "nested\\private-output",
    "%2e%2e%2fprivate-output",
    "%252e%252e%252fprivate-output",
    "case..private-output",
  ])("rejects path, URL, inline, or traversal reference ID %s", (referenceId) => {
    expect(() => parseControlledReference({
      kind: "controlled-reference",
      storeId: "encrypted-payloads",
      referenceId,
    })).toThrow(/referenceId|reference id/i);
  });

  it("creates an authentic deterministic registry with normalized local roots", () => {
    const registry = createControlledReferenceRegistry([
      { storeId: "z-store", root: "/srv/tasc/z-store/" },
      {
        storeId: "encrypted-payloads",
        root: "/srv/tasc/./private-payloads/../private-payloads",
      },
    ]);

    expect(registry).toEqual({
      version: CONTROLLED_REFERENCE_REGISTRY_VERSION,
      storeIds: ["encrypted-payloads", "z-store"],
    });
    expect(Object.isFrozen(registry)).toBe(true);
    expect(Object.isFrozen(registry.storeIds)).toBe(true);

    const authorized = authorizeControlledReference(registry, {
      kind: "controlled-reference",
      storeId: "encrypted-payloads",
      referenceId: "case-42.output-1",
    });
    expect(resolveAuthorizedControlledReferenceRoot(authorized))
      .toBe(TRUSTED_ROOT);
  });

  it("rejects duplicate stores, aliases, unknown stores, and forged registries", () => {
    expect(() => createControlledReferenceRegistry([
      { storeId: "payloads", root: "/srv/tasc/one" },
      { storeId: "payloads", root: "/srv/tasc/two" },
    ])).toThrow(/duplicate store id/i);

    expect(() => createControlledReferenceRegistry([
      { storeId: "payloads-a", root: "/srv/tasc/shared" },
      { storeId: "payloads-b", root: "/srv/tasc/./shared" },
    ])).toThrow(/duplicate trusted root/i);
    expect(() => createControlledReferenceRegistry([
      { storeId: "payloads-a", root: "/srv/tasc/shared" },
      { storeId: "payloads-b", root: "/srv/tasc/shared/" },
    ])).toThrow(/duplicate trusted root/i);

    const registry = createControlledReferenceRegistry([
      { storeId: "payloads", root: TRUSTED_ROOT },
    ]);
    expect(() => authorizeControlledReference(registry, {
      kind: "controlled-reference",
      storeId: "other",
      referenceId: "case-42",
    })).toThrow(/unknown controlled-reference store/i);

    expect(() => authorizeControlledReference(
      {
        version: CONTROLLED_REFERENCE_REGISTRY_VERSION,
        storeIds: ["payloads"],
      } as any,
      {
        kind: "controlled-reference",
        storeId: "payloads",
        referenceId: "case-42",
      },
    )).toThrow(/authentic.*registry/i);

    const roundTripped = JSON.parse(JSON.stringify(registry));
    expect(() => authorizeControlledReference(roundTripped, {
      kind: "controlled-reference",
      storeId: "payloads",
      referenceId: "case-42",
    })).toThrow(/authentic.*registry/i);
  });

  it("keeps the trusted root out of structural and serialized surfaces", () => {
    const registry = createControlledReferenceRegistry([
      { storeId: "payloads", root: TRUSTED_ROOT },
    ]);
    const authorized = authorizeControlledReference(registry, {
      kind: "controlled-reference",
      storeId: "payloads",
      referenceId: "case-42",
    });

    expect(authorized.reference).toEqual({
      kind: "controlled-reference",
      storeId: "payloads",
      referenceId: "case-42",
    });
    expect({ ...authorized }).toEqual({ reference: authorized.reference });
    expect(JSON.parse(JSON.stringify(authorized))).toEqual(authorized.reference);
    expect(JSON.stringify(authorized)).not.toContain(TRUSTED_ROOT);
    expect(Object.isFrozen(authorized)).toBe(true);
    expect(resolveAuthorizedControlledReferenceRoot(authorized))
      .toBe(TRUSTED_ROOT);
  });

  it("rejects structural authorization forgeries and round trips", () => {
    const registry = createControlledReferenceRegistry([
      { storeId: "payloads", root: TRUSTED_ROOT },
    ]);
    const authorized = authorizeControlledReference(registry, {
      kind: "controlled-reference",
      storeId: "payloads",
      referenceId: "case-42",
    });
    const fake = Object.freeze({
      reference: authorized.reference,
      trustedRoot: "/etc",
      toJSON: (): typeof authorized.reference => authorized.reference,
    });

    expect(() => resolveAuthorizedControlledReferenceRoot(fake))
      .toThrow(/authentic authorized controlled reference/i);
    expect(() => resolveAuthorizedControlledReferenceRoot(
      JSON.parse(JSON.stringify(authorized)),
    )).toThrow(/authentic authorized controlled reference/i);
  });

  it.each([
    "relative/payloads",
    ".",
    "/",
    "file:///srv/tasc/payloads",
    "https://store.invalid/payloads",
    "/srv/tasc\u0000/payloads",
  ])("rejects untrusted or non-local store root %s", (root) => {
    expect(() => createControlledReferenceRegistry([
      { storeId: "payloads", root },
    ])).toThrow(/root/i);
  });

  it("bounds store count before reading element zero and rejects config accessors", () => {
    const oversized = new Array(MAX_CONTROLLED_REFERENCE_STORES + 1);
    Object.defineProperty(oversized, "0", {
      get() {
        throw new Error("must not read over-budget element zero");
      },
    });
    expect(() => createControlledReferenceRegistry(oversized))
      .toThrow(/store limit/i);

    const stores = [{
      storeId: "payloads",
      get root() {
        throw new Error("must not invoke root accessor");
      },
    }];
    expect(() => createControlledReferenceRegistry(stores)).toThrow(/accessor/i);
  });

  it("rejects a proxied registry config without invoking its traps", () => {
    let traps = 0;
    const stores = new Proxy([], {
      getOwnPropertyDescriptor() {
        traps += 1;
        throw new Error("descriptor");
      },
      get() {
        traps += 1;
        throw new Error("get");
      },
    });

    expect(() => createControlledReferenceRegistry(stores)).toThrow(/proxy/i);
    expect(traps).toBe(0);
  });
});

describe("per-study payload identities", () => {
  it("uses a secret KeyObject and a domain-separated HMAC-SHA256 identity", () => {
    const keyBytes = Buffer.alloc(32, 7);
    const key = createSecretKey(keyBytes);
    const payload = Buffer.from("private prompt");

    const identity = createStudyPayloadIdentity(
      "study-alpha",
      "study-alpha-payload-key",
      key,
      payload,
    );

    expect(identity).toEqual({
      algorithm: "hmac-sha256",
      keyId: "study-alpha-payload-key",
      value: "a0e28d1857ead84d491a26e63d14fcecb34a08ccdcaf36aa27b382c729231614",
    });
    expect(Object.keys(identity)).toEqual(["algorithm", "keyId", "value"]);
    expect(Object.isFrozen(identity)).toBe(true);
    expect(JSON.stringify(identity)).not.toContain("private prompt");
    expect(JSON.stringify(identity)).not.toContain(keyBytes.toString("hex"));
  });

  it("is deterministic within a study and unlinkable when the study changes", () => {
    const key = createSecretKey(Buffer.alloc(32, 3));
    const payload = Buffer.from("same private payload");

    const first = createStudyPayloadIdentity("study-a", "payload-key", key, payload);
    const repeated = createStudyPayloadIdentity("study-a", "payload-key", key, payload);
    const otherStudy = createStudyPayloadIdentity("study-b", "payload-key", key, payload);
    const otherPayload = createStudyPayloadIdentity(
      "study-a",
      "payload-key",
      key,
      Buffer.from("different private payload"),
    );

    expect(repeated).toEqual(first);
    expect(otherStudy.value).not.toBe(first.value);
    expect(otherPayload.value).not.toBe(first.value);
  });

  it("accepts the exact payload limit and rejects one byte more", () => {
    const key = createSecretKey(Buffer.alloc(32, 5));
    expect(createStudyPayloadIdentity(
      "study-a",
      "payload-key",
      key,
      new Uint8Array(MAX_PAYLOAD_IDENTITY_BYTES),
    ).value).toMatch(/^[a-f0-9]{64}$/);

    expect(() => createStudyPayloadIdentity(
      "study-a",
      "payload-key",
      key,
      new Uint8Array(MAX_PAYLOAD_IDENTITY_BYTES + 1),
    )).toThrow(/payload.*byte limit/i);
  });

  it("requires a strong secret KeyObject and bounded canonical identities", () => {
    const strongKey = createSecretKey(Buffer.alloc(32, 1));
    const weakKey = createSecretKey(Buffer.alloc(16, 1));

    expect(() => createStudyPayloadIdentity(
      "study-a",
      "payload-key",
      Buffer.alloc(32) as any,
      Buffer.from("payload"),
    )).toThrow(/KeyObject/i);
    expect(() => createStudyPayloadIdentity(
      "study-a",
      "payload-key",
      weakKey,
      Buffer.from("payload"),
    )).toThrow(/secret runtime KeyObject|at least 32 bytes/i);
    expect(() => createStudyPayloadIdentity(
      "../study",
      "payload-key",
      strongKey,
      Buffer.from("payload"),
    )).toThrow(/studyId/i);
    expect(() => createStudyPayloadIdentity(
      "study-a",
      "https://keys.invalid/key",
      strongKey,
      Buffer.from("payload"),
    )).toThrow(/keyId/i);
    expect(() => createStudyPayloadIdentity(
      "study-a",
      "payload-key",
      strongKey,
      "payload" as any,
    )).toThrow(/Uint8Array/i);
  });

  it("rejects shared memory so concurrent writers cannot race the identity snapshot", () => {
    const key = createSecretKey(Buffer.alloc(32, 1));
    const shared = new Uint8Array(new SharedArrayBuffer(16));

    expect(() => createStudyPayloadIdentity(
      "study-a",
      "payload-key",
      key,
      shared,
    )).toThrow(/Uint8Array/i);
  });

  it("uses intrinsic key metadata instead of spoofable own properties", () => {
    const weakKey = createSecretKey(Buffer.alloc(1, 9));
    Object.defineProperty(weakKey, "symmetricKeySize", {
      value: 32,
      enumerable: true,
    });
    expect(() => createStudyPayloadIdentity(
      "study-a",
      "payload-key",
      weakKey,
      Buffer.from("payload"),
    )).toThrow(/secret runtime KeyObject|at least 32 bytes/i);

    let getterReads = 0;
    const strongKey = createSecretKey(Buffer.alloc(32, 9));
    Object.defineProperties(strongKey, {
      type: {
        get() {
          getterReads += 1;
          throw new Error("must not invoke own type getter");
        },
      },
      symmetricKeySize: {
        get() {
          getterReads += 1;
          throw new Error("must not invoke own key-size getter");
        },
      },
    });
    expect(() => createStudyPayloadIdentity(
      "study-a",
      "payload-key",
      strongKey,
      Buffer.from("payload"),
    )).toThrow(/secret runtime KeyObject/i);
    expect(getterReads).toBe(0);
  });

  it("uses intrinsic byte-view metadata before enforcing the payload cap", () => {
    let getterReads = 0;
    class SpoofedLargeBytes extends Uint8Array {
      override get buffer(): ArrayBuffer {
        getterReads += 1;
        return new ArrayBuffer(1);
      }

      override get byteLength(): number {
        getterReads += 1;
        return 1;
      }

      override get length(): number {
        getterReads += 1;
        return 1;
      }
    }
    const oversized = new SpoofedLargeBytes(
      MAX_PAYLOAD_IDENTITY_BYTES + 1,
    );
    expect(() => createStudyPayloadIdentity(
      "study-a",
      "payload-key",
      createSecretKey(Buffer.alloc(32, 4)),
      oversized,
    )).toThrow(/payload.*byte limit/i);
    expect(getterReads).toBe(0);
  });

  it("detects shared backing memory through intrinsic byte-view metadata", () => {
    let getterReads = 0;
    class SpoofedSharedBytes extends Uint8Array {
      override get buffer(): ArrayBuffer {
        getterReads += 1;
        return new ArrayBuffer(16);
      }

      override get byteLength(): number {
        getterReads += 1;
        return 16;
      }
    }
    const shared = new SpoofedSharedBytes(
      new SharedArrayBuffer(16) as unknown as ArrayBuffer,
    );
    expect(() => createStudyPayloadIdentity(
      "study-a",
      "payload-key",
      createSecretKey(Buffer.alloc(32, 4)),
      shared,
    )).toThrow(/Uint8Array/i);
    expect(getterReads).toBe(0);
  });
});
