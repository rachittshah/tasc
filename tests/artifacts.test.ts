import { createHash } from "node:crypto";
import {
  chmod,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rename,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, join, resolve } from "node:path";
import { describe, expect, it, vi } from "vitest";
import {
  ARTIFACT_MANIFEST_FILENAME,
  MAX_ARTIFACT_FILE_BYTES,
  MAX_ARTIFACT_FILES,
  MAX_ARTIFACT_TOTAL_BYTES,
  NO_DEPLOYMENT_AUTHORITY,
  PURE_NODE_NAMESPACE_LIMITATION,
  nodeArtifactFilesystem,
  verifyArtifactPacket,
  writeArtifactPacket,
  type ArtifactFileHandle,
  type ArtifactFilesystem,
  type ArtifactPacketInput,
} from "../src/artifacts.js";
import { canonicalJson } from "../src/determinism.js";

const mode = (value: Awaited<ReturnType<typeof lstat>>): number => (
  Number(value.mode) & 0o777
);

function digest(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function packet(
  files: ArtifactPacketInput["files"] = [
    {
      name: "b.json",
      bytes: '{"b":2}\n',
      mediaType: "application/json",
      schemaVersion: "fixture-b-v1",
    },
    {
      name: "a.txt",
      bytes: Buffer.from("alpha\n"),
      mediaType: "text/plain",
      schemaVersion: "fixture-a-v1",
    },
  ],
): ArtifactPacketInput {
  return {
    descriptor: {
      version: "tasc-artifact-packet-v1",
      kind: "assessment-review",
      assessmentDecisionDigest: null,
      assessmentContextDigest: null,
      attestation: "unattested",
    },
    files,
  };
}

async function freshRoot(): Promise<string> {
  return mkdtemp(join(tmpdir(), "tasc-artifacts-"));
}

async function pathExists(path: string): Promise<boolean> {
  try {
    await lstat(path);
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return false;
    throw error;
  }
}

interface Fault {
  readonly ordinal: number;
  readonly when: "before" | "after";
}

function instrumentedFilesystem(
  operations: string[],
  fault?: Fault,
): ArtifactFilesystem {
  let ordinal = 0;
  const around = async <T>(
    name: string,
    operation: () => Promise<T>,
  ): Promise<T> => {
    const current = ordinal;
    ordinal += 1;
    operations.push(name);
    if (fault?.ordinal === current && fault.when === "before") {
      throw new Error(`injected crash before ${name}`);
    }
    const result = await operation();
    if (fault?.ordinal === current && fault.when === "after") {
      throw new Error(`injected crash after ${name}`);
    }
    return result;
  };

  return {
    ...nodeArtifactFilesystem,
    async open(path, flags, fileMode) {
      const handle = await nodeArtifactFilesystem.open(path, flags, fileMode);
      const directory = flags === "r";
      const directoryKind = basename(path).includes(".tasc-stage-")
        ? "stage"
        : "parent";
      const handleName = basename(path);
      const wrapped: ArtifactFileHandle = {
        writeFile: (bytes) => around(
          `write:${handleName}`,
          () => handle.writeFile(bytes),
        ),
        chmod: (requestedMode) => handle.chmod(requestedMode),
        read: (buffer, offset, length, position) => (
          handle.read(buffer, offset, length, position)
        ),
        stat: () => handle.stat(),
        sync: () => around(
          directory
            ? `sync-directory:${directoryKind}`
            : `sync-file:${handleName}`,
          () => handle.sync(),
        ),
        close: () => handle.close(),
      };
      return wrapped;
    },
    rename(from, to) {
      return around("rename", () => nodeArtifactFilesystem.rename(from, to));
    },
  };
}

describe("atomic artifact packets", () => {
  it("publishes deterministic exact bytes, hashes, modes, and a manifest last", async () => {
    const root = await freshRoot();
    const result = await writeArtifactPacket(root, "packet", packet());
    const target = join(root, "packet");

    expect(result.path).toBe(target);
    expect(result.durability).toEqual({
      level: "full",
      limitations: [],
    });
    expect(await readdir(root)).toEqual(["packet"]);
    expect((await readdir(target)).sort()).toEqual([
      "a.txt",
      "b.json",
      ARTIFACT_MANIFEST_FILENAME,
    ].sort());
    expect(mode(await lstat(target))).toBe(0o700);
    for (const filename of await readdir(target)) {
      expect(mode(await lstat(join(target, filename)))).toBe(0o600);
    }

    const aBytes = await readFile(join(target, "a.txt"));
    const bBytes = await readFile(join(target, "b.json"));
    expect(aBytes).toEqual(Buffer.from("alpha\n"));
    expect(bBytes).toEqual(Buffer.from('{"b":2}\n'));
    expect(result.manifest.files).toEqual([
      {
        name: "a.txt",
        byteLength: aBytes.byteLength,
        sha256: digest(aBytes),
        mediaType: "text/plain",
        schemaVersion: "fixture-a-v1",
      },
      {
        name: "b.json",
        byteLength: bBytes.byteLength,
        sha256: digest(bBytes),
        mediaType: "application/json",
        schemaVersion: "fixture-b-v1",
      },
    ]);
    expect(result.manifest.completion).toEqual({
      state: "complete",
      manifestWrittenLast: true,
      authority: NO_DEPLOYMENT_AUTHORITY,
    });
    expect(result.manifest.namespaceSafety).toEqual({
      level: "best-effort",
      limitation: PURE_NODE_NAMESPACE_LIMITATION,
    });

    const manifestBytes = await readFile(
      join(target, ARTIFACT_MANIFEST_FILENAME),
    );
    expect(manifestBytes.toString("utf8")).toBe(
      `${canonicalJson(result.manifest)}\n`,
    );
    expect(await verifyArtifactPacket(root, "packet")).toEqual(result);
  });

  it("snapshots bytes and rejects active or oversized input before mutation", async () => {
    const root = await freshRoot();
    const source = Buffer.from("before\n");
    let stagingCalls = 0;
    const mutateAfterSnapshot: ArtifactFilesystem = {
      ...nodeArtifactFilesystem,
      async mkdtemp(prefix) {
        stagingCalls += 1;
        source.fill(0x78);
        return nodeArtifactFilesystem.mkdtemp(prefix);
      },
    };
    await writeArtifactPacket(
      root,
      "snapshotted",
      packet([{
        name: "source.txt",
        bytes: source,
        mediaType: "text/plain",
        schemaVersion: "fixture-v1",
      }]),
      { filesystem: mutateAfterSnapshot },
    );
    expect(await readFile(join(root, "snapshotted", "source.txt"), "utf8"))
      .toBe("before\n");

    const active = packet();
    Object.defineProperty(active.descriptor, "kind", {
      enumerable: true,
      get() {
        return "assessment-review";
      },
    });
    await expect(writeArtifactPacket(
      root,
      "active",
      active,
      { filesystem: mutateAfterSnapshot },
    )).rejects.toThrow(/data properties|accessor/i);

    await expect(writeArtifactPacket(
      root,
      "too-many",
      packet(Array.from({ length: MAX_ARTIFACT_FILES + 1 }, (_, index) => ({
        name: `file-${index}.txt`,
        bytes: "x",
        mediaType: "text/plain",
        schemaVersion: "fixture-v1",
      }))),
      { filesystem: mutateAfterSnapshot },
    )).rejects.toThrow(/file count|files/i);

    const oversized = new Uint8Array(MAX_ARTIFACT_FILE_BYTES + 1);
    const bufferFrom = vi.spyOn(Buffer, "from");
    try {
      await expect(writeArtifactPacket(
        root,
        "oversized",
        packet([{
          name: "oversized.bin",
          bytes: oversized,
          mediaType: "application/octet-stream",
          schemaVersion: "fixture-v1",
        }]),
        { filesystem: mutateAfterSnapshot },
      )).rejects.toThrow(/byte limit/i);
      expect(
        bufferFrom.mock.calls.some(([value]) => value === oversized),
      ).toBe(false);
    } finally {
      bufferFrom.mockRestore();
    }
    expect(stagingCalls).toBe(1);
    expect(await readdir(root)).toEqual(["snapshotted"]);
  });

  it("rejects traversal, symlinked roots and intermediates, and every existing target kind", async () => {
    const base = await freshRoot();
    const root = join(base, "root");
    await mkdir(root, { mode: 0o700 });

    for (const target of [
      ".",
      "..",
      "nested/packet",
      "nested\\packet",
      ".hidden",
      "white space",
      ARTIFACT_MANIFEST_FILENAME,
    ]) {
      await expect(writeArtifactPacket(root, target, packet()))
        .rejects.toThrow(/safe target|segment|reserved/i);
    }

    const linkedRoot = join(base, "linked-root");
    await symlink(root, linkedRoot, "dir");
    await expect(writeArtifactPacket(linkedRoot, "packet", packet()))
      .rejects.toThrow(/symlink/i);

    const realIntermediate = join(base, "real-intermediate");
    await mkdir(join(realIntermediate, "nested"), {
      recursive: true,
      mode: 0o700,
    });
    const linkedIntermediate = join(base, "linked-intermediate");
    await symlink(realIntermediate, linkedIntermediate, "dir");
    await expect(writeArtifactPacket(
      join(linkedIntermediate, "nested"),
      "packet",
      packet(),
    )).rejects.toThrow(/symlink/i);

    await writeFile(join(root, "existing-file"), "keep");
    await mkdir(join(root, "existing-directory"));
    await symlink("missing", join(root, "dangling-target"));
    await symlink(join(root, "existing-directory"), join(root, "linked-target"));
    for (const target of [
      "existing-file",
      "existing-directory",
      "dangling-target",
      "linked-target",
    ]) {
      await expect(writeArtifactPacket(root, target, packet()))
        .rejects.toThrow(/already exists/i);
    }
    expect(await readFile(join(root, "existing-file"), "utf8")).toBe("keep");
  });

  it("rejects a staging symlink without following or deleting its destination", async () => {
    const base = await freshRoot();
    const root = join(base, "root");
    const outside = join(base, "outside");
    await mkdir(root, { mode: 0o700 });
    await mkdir(outside, { mode: 0o700 });
    await writeFile(join(outside, "keep.txt"), "keep");
    let stagingLink = "";
    const maliciousFilesystem: ArtifactFilesystem = {
      ...nodeArtifactFilesystem,
      async mkdtemp(prefix) {
        stagingLink = `${prefix}malicious`;
        await symlink(outside, stagingLink, "dir");
        return stagingLink;
      },
    };

    await expect(writeArtifactPacket(
      root,
      "packet",
      packet(),
      { filesystem: maliciousFilesystem },
    )).rejects.toThrow(/staging.*symlink|symlink.*staging/i);
    expect(await readFile(join(outside, "keep.txt"), "utf8")).toBe("keep");
    expect(await pathExists(join(root, "packet"))).toBe(false);
    expect(await pathExists(stagingLink)).toBe(true);
    await rm(stagingLink);
  });

  it("detects staged source drift and rogue files before publication", async () => {
    for (const attack of ["bytes", "rogue"] as const) {
      const root = await freshRoot();
      let attacked = false;
      const maliciousFilesystem: ArtifactFilesystem = {
        ...nodeArtifactFilesystem,
        async readdir(path) {
          if (!attacked && basename(path).includes(".tasc-stage-")) {
            attacked = true;
            if (attack === "bytes") {
              await writeFile(join(path, "a.txt"), "edited\n");
            } else {
              await writeFile(join(path, "rogue.txt"), "rogue\n", {
                mode: 0o600,
              });
            }
          }
          return nodeArtifactFilesystem.readdir(path);
        },
      };
      await expect(writeArtifactPacket(
        root,
        "packet",
        packet(),
        { filesystem: maliciousFilesystem },
      )).rejects.toThrow(
        attack === "bytes" ? /hash|size|drift/i : /allowlist|rogue|unexpected/i,
      );
      expect(await pathExists(join(root, "packet"))).toBe(false);
      expect(await readdir(root)).toEqual([]);
    }
  });

  it("detects a target created by a cooperative rival and never overwrites it", async () => {
    const root = await freshRoot();
    const target = join(root, "packet");
    let absentChecks = 0;
    const racingFilesystem: ArtifactFilesystem = {
      ...nodeArtifactFilesystem,
      async lstat(path) {
        if (path === target) {
          absentChecks += 1;
          if (absentChecks === 2) {
            await mkdir(target, { mode: 0o700 });
            await writeFile(join(target, "rival.txt"), "rival\n");
          }
        }
        return nodeArtifactFilesystem.lstat(path);
      },
    };

    await expect(writeArtifactPacket(
      root,
      "packet",
      packet(),
      { filesystem: racingFilesystem },
    )).rejects.toThrow(/already exists/i);
    expect(await readFile(join(target, "rival.txt"), "utf8")).toBe("rival\n");
    expect((await readdir(root)).filter((name) => name.includes(".tasc-stage-")))
      .toEqual([]);
  });

  it("leaves the final path absent or completely verifiable at every injected write, sync, and rename crash", async () => {
    const baselineRoot = await freshRoot();
    const baselineOperations: string[] = [];
    await writeArtifactPacket(
      baselineRoot,
      "packet",
      packet(),
      { filesystem: instrumentedFilesystem(baselineOperations) },
    );
    expect(baselineOperations).toEqual([
      "sync-directory:parent",
      "write:a.txt",
      "sync-file:a.txt",
      "write:b.json",
      "sync-file:b.json",
      "sync-directory:stage",
      `write:${ARTIFACT_MANIFEST_FILENAME}`,
      `sync-file:${ARTIFACT_MANIFEST_FILENAME}`,
      "sync-directory:stage",
      "rename",
      "sync-directory:parent",
    ]);

    for (let ordinal = 0; ordinal < baselineOperations.length; ordinal += 1) {
      for (const when of ["before", "after"] as const) {
        const root = await freshRoot();
        const observed: string[] = [];
        await expect(writeArtifactPacket(
          root,
          "packet",
          packet(),
          {
            filesystem: instrumentedFilesystem(observed, { ordinal, when }),
          },
        )).rejects.toThrow(/injected crash/);
        if (await pathExists(join(root, "packet"))) {
          await expect(verifyArtifactPacket(root, "packet")).resolves
            .toMatchObject({ path: join(root, "packet") });
        } else {
          expect(
            (await readdir(root)).filter((name) => name.includes(".tasc-stage-")),
          ).toEqual([]);
        }
      }
    }
  }, 30_000);

  it("records only explicit unsupported durability primitives as degraded", async () => {
    const root = await freshRoot();
    const unsupportedFilesystem: ArtifactFilesystem = {
      ...nodeArtifactFilesystem,
      async open(path, flags, fileMode) {
        const handle = await nodeArtifactFilesystem.open(path, flags, fileMode);
        return {
          writeFile: (bytes) => handle.writeFile(bytes),
          chmod: (requestedMode) => handle.chmod(requestedMode),
          read: (buffer, offset, length, position) => (
            handle.read(buffer, offset, length, position)
          ),
          stat: () => handle.stat(),
          async sync() {
            const error = new Error("operation is not supported") as NodeJS.ErrnoException;
            error.code = "ENOTSUP";
            throw error;
          },
          close: () => handle.close(),
        };
      },
    };
    const result = await writeArtifactPacket(
      root,
      "packet",
      packet(),
      { filesystem: unsupportedFilesystem },
    );
    expect(result.durability).toEqual({
      level: "degraded",
      limitations: [
        "directory-fsync-unsupported",
        "file-fsync-unsupported",
        "parent-directory-fsync-unsupported",
      ],
    });
    expect((await verifyArtifactPacket(root, "packet")).durability)
      .toEqual(result.durability);

    const failureRoot = await freshRoot();
    let fileSyncs = 0;
    const failingFilesystem: ArtifactFilesystem = {
      ...nodeArtifactFilesystem,
      async open(path, flags, fileMode) {
        const handle = await nodeArtifactFilesystem.open(path, flags, fileMode);
        return {
          writeFile: (bytes) => handle.writeFile(bytes),
          chmod: (requestedMode) => handle.chmod(requestedMode),
          read: (buffer, offset, length, position) => (
            handle.read(buffer, offset, length, position)
          ),
          stat: () => handle.stat(),
          async sync() {
            if (flags !== "r" && fileSyncs++ === 0) {
              const error = new Error("simulated I/O failure") as NodeJS.ErrnoException;
              error.code = "EIO";
              throw error;
            }
            return handle.sync();
          },
          close: () => handle.close(),
        };
      },
    };
    await expect(writeArtifactPacket(
      failureRoot,
      "packet",
      packet(),
      { filesystem: failingFilesystem },
    )).rejects.toMatchObject({ code: "EIO" });
    expect(await pathExists(join(failureRoot, "packet"))).toBe(false);
    expect(await readdir(failureRoot)).toEqual([]);
  });

  it("allows only one cooperative writer to publish an existing target", async () => {
    const root = await freshRoot();
    const results = await Promise.allSettled([
      writeArtifactPacket(root, "packet", packet()),
      writeArtifactPacket(root, "packet", packet()),
    ]);
    expect(results.filter((result) => result.status === "fulfilled")).toHaveLength(1);
    expect(results.filter((result) => result.status === "rejected")).toHaveLength(1);
    await expect(verifyArtifactPacket(root, "packet")).resolves
      .toMatchObject({ path: join(root, "packet") });
    expect(
      (await readdir(root)).filter((name) => name.includes(".tasc-stage-")),
    ).toEqual([]);
  });

  it("closes the staging directory descriptor before rename", async () => {
    const root = await freshRoot();
    let stagingDirectoryOpen = false;
    const strictRenameFilesystem: ArtifactFilesystem = {
      ...nodeArtifactFilesystem,
      async open(path, flags, fileMode) {
        const handle = await nodeArtifactFilesystem.open(path, flags, fileMode);
        if (flags !== "r" || !basename(path).includes(".tasc-stage-")) {
          return handle;
        }
        stagingDirectoryOpen = true;
        return {
          writeFile: (bytes) => handle.writeFile(bytes),
          chmod: (requestedMode) => handle.chmod(requestedMode),
          read: (buffer, offset, length, position) => (
            handle.read(buffer, offset, length, position)
          ),
          stat: () => handle.stat(),
          sync: () => handle.sync(),
          async close() {
            await handle.close();
            stagingDirectoryOpen = false;
          },
        };
      },
      async rename(from, to) {
        if (stagingDirectoryOpen) {
          const error = new Error(
            "open directory cannot be renamed",
          ) as NodeJS.ErrnoException;
          error.code = "EBUSY";
          throw error;
        }
        await nodeArtifactFilesystem.rename(from, to);
      },
    };

    await expect(writeArtifactPacket(
      root,
      "packet",
      packet(),
      { filesystem: strictRenameFilesystem },
    )).resolves.toMatchObject({ path: join(root, "packet") });
  });

  it("sets payload modes on exclusive descriptors, not replaceable paths", async () => {
    const root = await freshRoot();
    const descriptorModeFilesystem: ArtifactFilesystem = {
      ...nodeArtifactFilesystem,
      async chmod(path, requestedMode) {
        if (!basename(path).includes(".tasc-stage-")) {
          throw new Error("path-level payload chmod is forbidden");
        }
        await nodeArtifactFilesystem.chmod(path, requestedMode);
      },
    };

    await expect(writeArtifactPacket(
      root,
      "packet",
      packet(),
      { filesystem: descriptorModeFilesystem },
    )).resolves.toMatchObject({ path: join(root, "packet") });
  });
});

describe("packet verification", () => {
  async function writtenPacket(): Promise<{
    readonly root: string;
    readonly target: string;
  }> {
    const root = await freshRoot();
    await writeArtifactPacket(root, "packet", packet());
    return { root, target: join(root, "packet") };
  }

  it("rejects payload drift, invalid modes, rogue files, and non-canonical manifests", async () => {
    {
      const { root, target } = await writtenPacket();
      await writeFile(join(target, "a.txt"), "tampered\n");
      await expect(verifyArtifactPacket(root, "packet"))
        .rejects.toThrow(/hash|size/i);
    }
    {
      const { root, target } = await writtenPacket();
      await chmod(join(target, "a.txt"), 0o644);
      await expect(verifyArtifactPacket(root, "packet"))
        .rejects.toThrow(/0600|mode/i);
    }
    {
      const { root, target } = await writtenPacket();
      await writeFile(join(target, "rogue.txt"), "rogue\n", { mode: 0o600 });
      await expect(verifyArtifactPacket(root, "packet"))
        .rejects.toThrow(/allowlist|unexpected|rogue/i);
    }
    {
      const { root, target } = await writtenPacket();
      const manifestPath = join(target, ARTIFACT_MANIFEST_FILENAME);
      const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
      await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, {
        mode: 0o600,
      });
      await expect(verifyArtifactPacket(root, "packet"))
        .rejects.toThrow(/canonical/i);
    }
  });

  it("rejects symlink substitution and target directory mode drift", async () => {
    {
      const { root, target } = await writtenPacket();
      const payloadPath = join(target, "a.txt");
      await rm(payloadPath);
      await symlink(join(target, "b.json"), payloadPath);
      await expect(verifyArtifactPacket(root, "packet"))
        .rejects.toThrow(/symlink|regular file/i);
    }
    {
      const { root, target } = await writtenPacket();
      await chmod(target, 0o755);
      await expect(verifyArtifactPacket(root, "packet"))
        .rejects.toThrow(/0700|mode/i);
    }
  });

  it("rejects aggregate manifest bytes before reading any payload", async () => {
    const root = await freshRoot();
    const targetName = "oversized-packet";
    const target = join(root, targetName);
    await mkdir(target, { mode: 0o700 });
    const descriptor = packet().descriptor;
    const files = Array.from({ length: 5 }, (_unused, index) => ({
      name: `payload-${index}.bin`,
      byteLength: 52 * 1024 * 1024,
      sha256: "0".repeat(64),
      mediaType: "application/octet-stream",
      schemaVersion: "fixture-v1",
    }));
    expect(files.reduce((sum, file) => sum + file.byteLength, 0))
      .toBeGreaterThan(MAX_ARTIFACT_TOTAL_BYTES);
    const body = {
      version: "tasc-artifact-manifest-v1" as const,
      canonicalization: "rfc8785-jcs-v1" as const,
      targetName,
      descriptor,
      files,
      packetDigest: digest(Buffer.from(canonicalJson({
        version: "tasc-artifact-packet-digest-v1",
        targetName,
        descriptor,
        files,
      }), "utf8")),
      durability: {
        level: "full" as const,
        limitations: [],
      },
      completion: {
        state: "complete" as const,
        manifestWrittenLast: true as const,
        authority: NO_DEPLOYMENT_AUTHORITY,
      },
      namespaceSafety: {
        level: "best-effort" as const,
        limitation: PURE_NODE_NAMESPACE_LIMITATION,
      },
    };
    const manifest = {
      ...body,
      manifestDigest: digest(Buffer.from(canonicalJson({
        domain: "tasc/artifact-manifest/v1",
        body,
      }), "utf8")),
    };
    await writeFile(
      join(target, ARTIFACT_MANIFEST_FILENAME),
      `${canonicalJson(manifest)}\n`,
      { mode: 0o600 },
    );

    await expect(verifyArtifactPacket(root, targetName))
      .rejects.toThrow(/total limit/i);
  });

  it("binds all manifest metadata and supports an externally pinned digest", async () => {
    const root = await freshRoot();
    const result = await writeArtifactPacket(root, "packet", packet());
    const manifestDigest = result.manifest.manifestDigest;
    expect(manifestDigest).toMatch(/^[a-f0-9]{64}$/);
    await expect(verifyArtifactPacket(root, "packet", {
      expectedManifestDigest: manifestDigest,
    })).resolves.toMatchObject({ path: join(root, "packet") });
    await expect(verifyArtifactPacket(root, "packet", {
      expectedManifestDigest: "0".repeat(64),
    })).rejects.toThrow(/pinned manifest digest mismatch/i);

    const manifestPath = join(root, "packet", ARTIFACT_MANIFEST_FILENAME);
    const edited = JSON.parse(await readFile(manifestPath, "utf8"));
    edited.durability = {
      level: "degraded",
      limitations: ["file-fsync-unsupported"],
    };
    await writeFile(manifestPath, `${canonicalJson(edited)}\n`, { mode: 0o600 });
    await expect(verifyArtifactPacket(root, "packet"))
      .rejects.toThrow(/manifest digest mismatch/i);
  });

  it("uses bounded descriptor reads instead of path-level readFile after lstat", async () => {
    const { root } = await writtenPacket();
    const boundedFilesystem: ArtifactFilesystem = {
      ...nodeArtifactFilesystem,
      async readFile() {
        throw new Error("unbounded path-level readFile is forbidden");
      },
    };

    await expect(verifyArtifactPacket(
      root,
      "packet",
      { filesystem: boundedFilesystem },
    )).resolves.toMatchObject({ path: join(root, "packet") });
  });
});
