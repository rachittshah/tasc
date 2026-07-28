import { createHash } from "node:crypto";
import type { Stats } from "node:fs";
import {
  chmod,
  lstat,
  mkdtemp,
  open,
  readFile,
  readdir,
  realpath,
  rename,
  rm,
} from "node:fs/promises";
import {
  basename,
  dirname,
  isAbsolute,
  join,
  normalize,
  parse,
  relative,
  resolve,
  sep,
} from "node:path";
import { TextDecoder } from "node:util";
import { z } from "zod";
import { canonicalJson, compareCodeUnits } from "./determinism.js";
import type { AssessmentDecision } from "./assessment.js";

export const ARTIFACT_MANIFEST_FILENAME = "manifest.json" as const;
export const MAX_ARTIFACT_FILES = 64;
export const MAX_ARTIFACT_FILE_BYTES = 64 * 1024 * 1024;
export const MAX_ARTIFACT_TOTAL_BYTES = 256 * 1024 * 1024;
const MAX_MANIFEST_BYTES = 1024 * 1024;

/**
 * Packet publication is evidence custody only. This value is deliberately
 * embedded in every manifest so a packet can never be mistaken for a rollout
 * command or deployment capability.
 */
export const NO_DEPLOYMENT_AUTHORITY =
  "evidence-only-no-deployment-authority" as const;

/**
 * Pure Node exposes path-based filesystem calls, not descriptor-relative
 * openat2/renameat2 operations. Repeated lstat/realpath/inode checks protect
 * cooperative namespaces and detect observed drift, but cannot make hostile
 * same-UID namespace replacement races impossible.
 */
export const PURE_NODE_NAMESPACE_LIMITATION =
  "Pure Node path operations cannot make hostile same-UID namespace swaps "
  + "race-proof without native descriptor-relative and no-replace primitives.";

export type ArtifactDurabilityLimitation =
  | "directory-fsync-unsupported"
  | "file-fsync-unsupported"
  | "parent-directory-fsync-unsupported";

export interface ArtifactDurability {
  readonly level: "full" | "degraded";
  readonly limitations: readonly ArtifactDurabilityLimitation[];
}

export interface ArtifactPacketDescriptor {
  readonly version: "tasc-artifact-packet-v1";
  readonly kind: string;
  readonly assessmentDecisionDigest: string | null;
  readonly assessmentContextDigest: string | null;
  readonly attestation: "unattested";
}

export interface ArtifactPayload {
  readonly name: string;
  readonly bytes: string | Uint8Array;
  readonly mediaType: string;
  readonly schemaVersion: string;
}

export interface ArtifactPacketInput {
  readonly descriptor: ArtifactPacketDescriptor;
  readonly files: readonly ArtifactPayload[];
}

export interface ArtifactManifestFile {
  readonly name: string;
  readonly byteLength: number;
  readonly sha256: string;
  readonly mediaType: string;
  readonly schemaVersion: string;
}

export interface ArtifactManifest {
  readonly version: "tasc-artifact-manifest-v1";
  readonly canonicalization: "rfc8785-jcs-v1";
  readonly targetName: string;
  readonly descriptor: ArtifactPacketDescriptor;
  readonly files: readonly ArtifactManifestFile[];
  readonly packetDigest: string;
  readonly durability: ArtifactDurability;
  readonly completion: {
    readonly state: "complete";
    readonly manifestWrittenLast: true;
    readonly authority: typeof NO_DEPLOYMENT_AUTHORITY;
  };
  readonly namespaceSafety: {
    readonly level: "best-effort";
    readonly limitation: typeof PURE_NODE_NAMESPACE_LIMITATION;
  };
  readonly manifestDigest: string;
}

/**
 * A review-layer packet is a pure decision plus identity metadata and the
 * writer-observed completion manifest. It remains explicitly unattested and
 * carries no deployment authority.
 */
export interface AssessmentPacket {
  readonly version: "tasc-assessment-packet-v1";
  readonly decision: AssessmentDecision;
  readonly metadata: {
    readonly decisionDigest: string;
    readonly assessmentContextDigest: string;
    readonly protocolDigest: string;
    readonly datasetDigest: string;
    readonly traceSetDigest: string;
    readonly evaluatorSetDigest: string;
    readonly windowManifestDigest: string | null;
    readonly attestation: "unattested";
  };
  readonly completionManifest: ArtifactManifest;
}

export interface ArtifactWriteResult {
  readonly path: string;
  readonly manifest: ArtifactManifest;
  readonly durability: ArtifactDurability;
}

export interface ArtifactReadPayload {
  readonly name: string;
  readonly copyBytes: () => Uint8Array;
  readonly mediaType: string;
  readonly schemaVersion: string;
}

export interface ArtifactReadResult extends ArtifactWriteResult {
  readonly files: readonly ArtifactReadPayload[];
}

export interface ArtifactWriteOrVerifyResult extends ArtifactWriteResult {
  readonly disposition: "written" | "verified-identical";
}

export interface ArtifactFileHandle {
  writeFile(bytes: Uint8Array): Promise<void>;
  chmod(mode: number): Promise<void>;
  read(
    buffer: Uint8Array,
    offset: number,
    length: number,
    position: number,
  ): Promise<{ readonly bytesRead: number }>;
  stat(): Promise<Stats>;
  sync(): Promise<void>;
  close(): Promise<void>;
}

export interface ArtifactFilesystem {
  lstat(path: string): Promise<Stats>;
  realpath(path: string): Promise<string>;
  readdir(path: string): Promise<string[]>;
  readFile(path: string): Promise<Buffer>;
  mkdtemp(prefix: string): Promise<string>;
  chmod(path: string, mode: number): Promise<void>;
  open(path: string, flags: "r" | "wx", mode?: number): Promise<ArtifactFileHandle>;
  rename(from: string, to: string): Promise<void>;
  rm(
    path: string,
    options: { readonly recursive: boolean; readonly force: boolean },
  ): Promise<void>;
}

export const nodeArtifactFilesystem: ArtifactFilesystem = Object.freeze({
  lstat,
  realpath,
  readdir: (path: string) => readdir(path),
  readFile: (path: string) => readFile(path),
  mkdtemp,
  chmod,
  open: async (path: string, flags: "r" | "wx", mode?: number) => (
    open(path, flags, mode)
  ),
  rename,
  rm,
});

export interface ArtifactWriterOptions {
  readonly filesystem?: ArtifactFilesystem;
}

export interface ArtifactVerificationOptions extends ArtifactWriterOptions {
  readonly expectedManifestDigest?: string;
}

interface SnapshottedPayload {
  readonly name: string;
  readonly bytes: Buffer;
  readonly mediaType: string;
  readonly schemaVersion: string;
}

interface SnapshottedPacket {
  readonly descriptor: ArtifactPacketDescriptor;
  readonly files: readonly SnapshottedPayload[];
}

interface PathIdentity {
  readonly path: string;
  readonly dev: number;
  readonly ino: number;
}

interface ArtifactMemberCustody extends PathIdentity {
  readonly size: number;
  readonly mode: number;
  readonly ctimeMs: number;
  readonly mtimeMs: number;
}

interface VerifiedPayloadSet {
  readonly custody: readonly ArtifactMemberCustody[];
}

interface FinalVerifiedPacket {
  readonly manifest: ArtifactManifest;
  readonly payloads: readonly ArtifactReadPayload[];
}

interface TrustedRoot {
  readonly path: string;
  readonly realPath: string;
  readonly identities: readonly PathIdentity[];
}

type SyncStatus = "unknown" | "supported" | "unsupported";

interface SyncCapability {
  status: SyncStatus;
}

class ArtifactTargetExistsError extends Error {
  readonly code = "TASC_ARTIFACT_TARGET_EXISTS";

  constructor(path: string) {
    super(`output directory "${path}" already exists; use a fresh --out path`);
    this.name = "ArtifactTargetExistsError";
  }
}

const safeSegmentPattern = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const kindPattern = /^[a-z0-9][a-z0-9._-]{0,127}$/;
const mediaTypePattern =
  /^[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]{0,63}\/[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]{0,63}$/;
const schemaVersionPattern = /^[A-Za-z0-9][A-Za-z0-9._:+/-]{0,127}$/;
const sha256Pattern = /^[a-f0-9]{64}$/;
const contractDigestPattern = /^sha256:[a-f0-9]{64}$/;

const descriptorSchema = z.object({
  version: z.literal("tasc-artifact-packet-v1"),
  kind: z.string().regex(kindPattern),
  assessmentDecisionDigest: z.string().regex(contractDigestPattern).nullable(),
  assessmentContextDigest: z.string().regex(contractDigestPattern).nullable(),
  attestation: z.literal("unattested"),
}).strict();

const manifestFileSchema = z.object({
  name: z.string().regex(safeSegmentPattern),
  byteLength: z.number().int().nonnegative().max(MAX_ARTIFACT_FILE_BYTES),
  sha256: z.string().regex(sha256Pattern),
  mediaType: z.string().regex(mediaTypePattern),
  schemaVersion: z.string().regex(schemaVersionPattern),
}).strict();

const durabilityLimitationSchema = z.enum([
  "directory-fsync-unsupported",
  "file-fsync-unsupported",
  "parent-directory-fsync-unsupported",
]);

const manifestSchema = z.object({
  version: z.literal("tasc-artifact-manifest-v1"),
  canonicalization: z.literal("rfc8785-jcs-v1"),
  targetName: z.string().regex(safeSegmentPattern),
  descriptor: descriptorSchema,
  files: z.array(manifestFileSchema).min(1).max(MAX_ARTIFACT_FILES),
  packetDigest: z.string().regex(sha256Pattern),
  durability: z.object({
    level: z.enum(["full", "degraded"]),
    limitations: z.array(durabilityLimitationSchema).max(3),
  }).strict(),
  completion: z.object({
    state: z.literal("complete"),
    manifestWrittenLast: z.literal(true),
    authority: z.literal(NO_DEPLOYMENT_AUTHORITY),
  }).strict(),
  namespaceSafety: z.object({
    level: z.literal("best-effort"),
    limitation: z.literal(PURE_NODE_NAMESPACE_LIMITATION),
  }).strict(),
  manifestDigest: z.string().regex(sha256Pattern),
}).strict();

function errorCode(error: unknown): string | undefined {
  return (error as NodeJS.ErrnoException | undefined)?.code;
}

function isMissing(error: unknown): boolean {
  return errorCode(error) === "ENOENT";
}

function assertPlainDataObject(
  value: unknown,
  label: string,
  keys: readonly string[],
): asserts value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`${label} must be a plain data object`);
  }
  const prototype = Reflect.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new Error(`${label} must be a plain data object`);
  }
  const ownKeys = Reflect.ownKeys(value);
  if (ownKeys.some((key) => typeof key !== "string")) {
    throw new Error(`${label} cannot contain symbol properties`);
  }
  const actual = [...ownKeys as string[]].sort(compareCodeUnits);
  const expected = [...keys].sort(compareCodeUnits);
  if (
    actual.length !== expected.length
    || actual.some((key, index) => key !== expected[index])
  ) {
    throw new Error(`${label} must contain exactly: ${expected.join(", ")}`);
  }
  for (const key of expected) {
    const descriptor = Reflect.getOwnPropertyDescriptor(value, key);
    if (
      descriptor === undefined
      || !Object.hasOwn(descriptor, "value")
    ) {
      throw new Error(`${label} fields must be data properties, not accessors`);
    }
  }
}

function dataProperty(
  value: Record<string, unknown>,
  key: string,
): unknown {
  return Reflect.getOwnPropertyDescriptor(value, key)!.value;
}

function snapshotPacket(input: unknown): SnapshottedPacket {
  assertPlainDataObject(input, "artifact packet", ["descriptor", "files"]);
  const descriptorInput = dataProperty(input, "descriptor");
  assertPlainDataObject(descriptorInput, "artifact packet descriptor", [
    "version",
    "kind",
    "assessmentDecisionDigest",
    "assessmentContextDigest",
    "attestation",
  ]);
  const descriptorSnapshot = {
    version: dataProperty(descriptorInput, "version"),
    kind: dataProperty(descriptorInput, "kind"),
    assessmentDecisionDigest: dataProperty(
      descriptorInput,
      "assessmentDecisionDigest",
    ),
    assessmentContextDigest: dataProperty(
      descriptorInput,
      "assessmentContextDigest",
    ),
    attestation: dataProperty(descriptorInput, "attestation"),
  };
  const descriptor = descriptorSchema.parse(
    descriptorSnapshot,
  ) as ArtifactPacketDescriptor;

  const filesInput = dataProperty(input, "files");
  if (!Array.isArray(filesInput)) {
    throw new Error("artifact packet files must be a dense data array");
  }
  const lengthDescriptor = Reflect.getOwnPropertyDescriptor(
    filesInput,
    "length",
  );
  const length = lengthDescriptor?.value;
  if (
    typeof length !== "number"
    || !Number.isSafeInteger(length)
    || length < 1
    || length > MAX_ARTIFACT_FILES
  ) {
    throw new Error(
      `artifact packet file count must be between 1 and ${MAX_ARTIFACT_FILES}`,
    );
  }
  const allowedArrayKeys = new Set<string>([
    "length",
    ...Array.from({ length }, (_, index) => String(index)),
  ]);
  for (const key of Reflect.ownKeys(filesInput)) {
    if (typeof key !== "string" || !allowedArrayKeys.has(key)) {
      throw new Error("artifact packet files must be a dense data array");
    }
  }

  const names = new Set<string>();
  const files: SnapshottedPayload[] = [];
  let totalBytes = 0;
  for (let index = 0; index < length; index += 1) {
    const elementDescriptor = Reflect.getOwnPropertyDescriptor(
      filesInput,
      String(index),
    );
    if (
      elementDescriptor === undefined
      || !Object.hasOwn(elementDescriptor, "value")
    ) {
      throw new Error("artifact packet files must be dense data properties");
    }
    const fileInput = elementDescriptor.value;
    assertPlainDataObject(fileInput, `artifact file ${index}`, [
      "name",
      "bytes",
      "mediaType",
      "schemaVersion",
    ]);
    const name = dataProperty(fileInput, "name");
    const mediaType = dataProperty(fileInput, "mediaType");
    const schemaVersion = dataProperty(fileInput, "schemaVersion");
    const sourceBytes = dataProperty(fileInput, "bytes");
    if (
      typeof name !== "string"
      || !safeSegmentPattern.test(name)
      || name === ARTIFACT_MANIFEST_FILENAME
      || name === "."
      || name === ".."
    ) {
      throw new Error(`artifact file ${index} has an unsafe or reserved name`);
    }
    if (names.has(name)) {
      throw new Error(`artifact packet contains duplicate file "${name}"`);
    }
    if (
      typeof mediaType !== "string"
      || !mediaTypePattern.test(mediaType)
    ) {
      throw new Error(`artifact file "${name}" has an invalid media type`);
    }
    if (
      typeof schemaVersion !== "string"
      || !schemaVersionPattern.test(schemaVersion)
    ) {
      throw new Error(`artifact file "${name}" has an invalid schema version`);
    }
    let sourceByteLength: number;
    if (typeof sourceBytes === "string") {
      sourceByteLength = Buffer.byteLength(sourceBytes, "utf8");
    } else if (sourceBytes instanceof Uint8Array) {
      sourceByteLength = sourceBytes.byteLength;
    } else {
      throw new Error(`artifact file "${name}" bytes must be UTF-8 or bytes`);
    }
    if (
      !Number.isSafeInteger(sourceByteLength)
      || sourceByteLength < 0
      || sourceByteLength > MAX_ARTIFACT_FILE_BYTES
    ) {
      throw new Error(
        `artifact file "${name}" exceeds the ${MAX_ARTIFACT_FILE_BYTES}-byte limit`,
      );
    }
    const projectedTotalBytes = totalBytes + sourceByteLength;
    if (
      !Number.isSafeInteger(projectedTotalBytes)
      || projectedTotalBytes > MAX_ARTIFACT_TOTAL_BYTES
    ) {
      throw new Error(
        `artifact packet exceeds the ${MAX_ARTIFACT_TOTAL_BYTES}-byte total limit`,
      );
    }
    const bytes = typeof sourceBytes === "string"
      ? Buffer.from(sourceBytes, "utf8")
      : Buffer.from(sourceBytes);
    if (bytes.byteLength !== sourceByteLength) {
      throw new Error(`artifact file "${name}" changed while being snapshotted`);
    }
    totalBytes = projectedTotalBytes;
    names.add(name);
    files.push({ name, bytes, mediaType, schemaVersion });
  }
  files.sort((left, right) => compareCodeUnits(left.name, right.name));
  return Object.freeze({
    descriptor: Object.freeze({ ...descriptor }),
    files: Object.freeze(files.map((file) => Object.freeze(file))),
  });
}

function assertSafeTargetName(targetName: string): void {
  if (
    !safeSegmentPattern.test(targetName)
    || targetName === "."
    || targetName === ".."
    || targetName.startsWith(".")
    || targetName === ARTIFACT_MANIFEST_FILENAME
    || basename(targetName) !== targetName
    || targetName.includes("/")
    || targetName.includes("\\")
  ) {
    throw new Error(
      "artifact target must be one safe, non-hidden path segment",
    );
  }
}

function identity(path: string, stats: Stats): PathIdentity {
  return { path, dev: stats.dev, ino: stats.ino };
}

function sameIdentity(left: PathIdentity, stats: Stats): boolean {
  return left.dev === stats.dev && left.ino === stats.ino;
}

function rootComponents(rootPath: string): string[] {
  const parsed = parse(rootPath);
  const suffix = rootPath.slice(parsed.root.length);
  const parts = suffix.length === 0 ? [] : suffix.split(sep);
  const paths = [parsed.root];
  let current = parsed.root;
  for (const part of parts) {
    current = join(current, part);
    paths.push(current);
  }
  return paths;
}

async function inspectTrustedRoot(
  rootPath: string,
  filesystem: ArtifactFilesystem,
): Promise<TrustedRoot> {
  if (
    !isAbsolute(rootPath)
    || normalize(rootPath) !== rootPath
    || resolve(rootPath) !== rootPath
  ) {
    throw new Error(
      "artifact root must be an absolute, normalized existing directory",
    );
  }
  const identities: PathIdentity[] = [];
  for (const component of rootComponents(rootPath)) {
    const stats = await filesystem.lstat(component);
    if (stats.isSymbolicLink()) {
      throw new Error(
        `artifact root path component "${component}" is a symlink`,
      );
    }
    if (!stats.isDirectory()) {
      throw new Error(
        `artifact root path component "${component}" is not a directory`,
      );
    }
    identities.push(identity(component, stats));
  }
  const resolved = normalize(await filesystem.realpath(rootPath));
  if (resolved !== rootPath) {
    throw new Error("artifact root realpath differs from its trusted path");
  }
  return Object.freeze({
    path: rootPath,
    realPath: resolved,
    identities: Object.freeze(identities),
  });
}

async function recheckTrustedRoot(
  root: TrustedRoot,
  filesystem: ArtifactFilesystem,
): Promise<void> {
  for (const expected of root.identities) {
    const stats = await filesystem.lstat(expected.path);
    if (
      stats.isSymbolicLink()
      || !stats.isDirectory()
      || !sameIdentity(expected, stats)
    ) {
      throw new Error(
        `artifact root identity drifted at "${expected.path}"`,
      );
    }
  }
  if (normalize(await filesystem.realpath(root.path)) !== root.realPath) {
    throw new Error("artifact root realpath drifted during publication");
  }
}

function assertContained(
  parent: string,
  child: string,
  expectedSegment?: string,
): void {
  const relation = relative(parent, child);
  if (
    relation.length === 0
    || relation.startsWith(`..${sep}`)
    || relation === ".."
    || isAbsolute(relation)
    || (expectedSegment !== undefined && relation !== expectedSegment)
  ) {
    throw new Error("artifact path escaped its trusted root");
  }
}

async function assertPathAbsent(
  path: string,
  filesystem: ArtifactFilesystem,
): Promise<void> {
  try {
    await filesystem.lstat(path);
  } catch (error) {
    if (isMissing(error)) return;
    throw error;
  }
  throw new ArtifactTargetExistsError(path);
}

function fileMode(stats: Stats): number {
  return stats.mode & 0o777;
}

function memberCustody(path: string, stats: Stats): ArtifactMemberCustody {
  return Object.freeze({
    path,
    dev: stats.dev,
    ino: stats.ino,
    size: stats.size,
    mode: fileMode(stats),
    ctimeMs: stats.ctimeMs,
    mtimeMs: stats.mtimeMs,
  });
}

function sameCustody(
  expected: ArtifactMemberCustody,
  stats: Stats,
): boolean {
  return (
    sameIdentity(expected, stats)
    && expected.size === stats.size
    && expected.mode === fileMode(stats)
    && expected.ctimeMs === stats.ctimeMs
    && expected.mtimeMs === stats.mtimeMs
  );
}

function assertRegularFileCustody(
  expected: ArtifactMemberCustody,
  stats: Stats,
  label: string,
): void {
  if (
    stats.isSymbolicLink()
    || !stats.isFile()
    || !sameCustody(expected, stats)
  ) {
    throw new Error(`${label} custody drifted`);
  }
}

function assertDirectoryCustody(
  expected: ArtifactMemberCustody,
  stats: Stats,
  label: string,
): void {
  if (
    stats.isSymbolicLink()
    || !stats.isDirectory()
    || !sameCustody(expected, stats)
  ) {
    throw new Error(`${label} custody drifted`);
  }
}

function sha256(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function packetDigest(
  targetName: string,
  descriptor: ArtifactPacketDescriptor,
  files: readonly ArtifactManifestFile[],
): string {
  return sha256(Buffer.from(canonicalJson({
    version: "tasc-artifact-packet-digest-v1",
    targetName,
    descriptor,
    files,
  }), "utf8"));
}

function fingerprintManifestBody(
  body: Omit<ArtifactManifest, "manifestDigest">,
): string {
  return sha256(Buffer.from(canonicalJson({
    domain: "tasc/artifact-manifest/v1",
    body,
  }), "utf8"));
}

function isUnsupportedSync(error: unknown): boolean {
  return new Set(["EINVAL", "ENOSYS", "ENOTSUP", "EOPNOTSUPP"]).has(
    errorCode(error) ?? "",
  );
}

function isUnsupportedDirectoryOpen(error: unknown): boolean {
  return new Set(["EISDIR", "ENOSYS", "ENOTSUP", "EOPNOTSUPP"]).has(
    errorCode(error) ?? "",
  );
}

function addLimitation(
  limitations: Set<ArtifactDurabilityLimitation>,
  limitation: ArtifactDurabilityLimitation,
): void {
  limitations.add(limitation);
}

async function syncHandle(
  handle: ArtifactFileHandle,
  capability: SyncCapability,
  limitation: ArtifactDurabilityLimitation,
  limitations: Set<ArtifactDurabilityLimitation>,
): Promise<void> {
  try {
    await handle.sync();
    if (capability.status === "unknown") capability.status = "supported";
  } catch (error) {
    if (!isUnsupportedSync(error)) throw error;
    if (capability.status === "supported") {
      throw new Error(
        `filesystem ${limitation} capability changed after packet sealing began`,
        { cause: error },
      );
    }
    capability.status = "unsupported";
    addLimitation(limitations, limitation);
  }
}

async function openDirectoryHandle(
  path: string,
  filesystem: ArtifactFilesystem,
  capability: SyncCapability,
  limitation: ArtifactDurabilityLimitation,
  limitations: Set<ArtifactDurabilityLimitation>,
): Promise<ArtifactFileHandle | null> {
  try {
    return await filesystem.open(path, "r");
  } catch (error) {
    if (!isUnsupportedDirectoryOpen(error)) throw error;
    capability.status = "unsupported";
    addLimitation(limitations, limitation);
    return null;
  }
}

async function closeHandle(
  handle: ArtifactFileHandle | null,
): Promise<void> {
  if (handle !== null) await handle.close();
}

async function writeExclusiveFile(
  path: string,
  bytes: Uint8Array,
  filesystem: ArtifactFilesystem,
  capability: SyncCapability,
  limitations: Set<ArtifactDurabilityLimitation>,
): Promise<void> {
  const handle = await filesystem.open(path, "wx", 0o600);
  let operationError: unknown;
  try {
    await handle.chmod(0o600);
    await handle.writeFile(bytes);
    await syncHandle(
      handle,
      capability,
      "file-fsync-unsupported",
      limitations,
    );
  } catch (error) {
    operationError = error;
    throw error;
  } finally {
    try {
      await handle.close();
    } catch (closeError) {
      if (operationError === undefined) throw closeError;
    }
  }
}

function expectedManifestFiles(
  files: readonly SnapshottedPayload[],
): ArtifactManifestFile[] {
  return files.map((file) => ({
    name: file.name,
    byteLength: file.bytes.byteLength,
    sha256: sha256(file.bytes),
    mediaType: file.mediaType,
    schemaVersion: file.schemaVersion,
  }));
}

function sortedNames(names: readonly string[]): string[] {
  return [...names].sort(compareCodeUnits);
}

function sameStrings(
  left: readonly string[],
  right: readonly string[],
): boolean {
  return (
    left.length === right.length
    && left.every((value, index) => value === right[index])
  );
}

async function readBoundedFile(
  path: string,
  maximum: number,
  filesystem: ArtifactFilesystem,
): Promise<Buffer> {
  const before = await filesystem.lstat(path);
  if (
    before.isSymbolicLink()
    || !before.isFile()
    || before.size > maximum
  ) {
    throw new Error(`artifact file "${path}" is not a bounded regular file`);
  }
  const handle = await filesystem.open(path, "r");
  let operationError: unknown;
  try {
    const opened = await handle.stat();
    if (
      !opened.isFile()
      || !sameIdentity(identity(path, before), opened)
      || opened.size < 0
      || opened.size > maximum
    ) {
      throw new Error(`artifact file "${path}" drifted before bounded read`);
    }
    const capacity = opened.size + 1;
    const bounded = Buffer.alloc(capacity);
    let total = 0;
    while (total < capacity) {
      const { bytesRead } = await handle.read(
        bounded,
        total,
        capacity - total,
        total,
      );
      if (bytesRead === 0) break;
      if (
        !Number.isSafeInteger(bytesRead)
        || bytesRead < 0
        || bytesRead > capacity - total
      ) {
        throw new Error("filesystem returned an invalid bounded read length");
      }
      total += bytesRead;
    }
    if (total > maximum) {
      throw new Error(`artifact file "${path}" exceeds its byte limit`);
    }
    const [openedAfter, pathAfter] = await Promise.all([
      handle.stat(),
      filesystem.lstat(path),
    ]);
    const expectedIdentity = identity(path, before);
    if (
      pathAfter.isSymbolicLink()
      || !pathAfter.isFile()
      || !openedAfter.isFile()
      || !sameIdentity(expectedIdentity, openedAfter)
      || !sameIdentity(expectedIdentity, pathAfter)
      || openedAfter.size !== total
      || pathAfter.size !== total
    ) {
      throw new Error(`artifact file "${path}" drifted while being read`);
    }
    return Buffer.from(bounded.subarray(0, total));
  } catch (error) {
    operationError = error;
    throw error;
  } finally {
    try {
      await handle.close();
    } catch (closeError) {
      if (operationError === undefined) throw closeError;
    }
  }
}

async function verifyPayloadSet(
  directory: string,
  files: readonly ArtifactManifestFile[],
  filesystem: ArtifactFilesystem,
  includeManifest: boolean,
): Promise<VerifiedPayloadSet> {
  const expectedNames = sortedNames([
    ...files.map((file) => file.name),
    ...(includeManifest ? [ARTIFACT_MANIFEST_FILENAME] : []),
  ]);
  const actualNames = sortedNames(await filesystem.readdir(directory));
  if (!sameStrings(actualNames, expectedNames)) {
    throw new Error(
      "artifact directory violates its exact allowlist; "
      + `expected [${expectedNames.join(", ")}], got [${actualNames.join(", ")}]`,
    );
  }
  const custody: ArtifactMemberCustody[] = [];
  for (const file of files) {
    const path = join(directory, file.name);
    const stats = await filesystem.lstat(path);
    if (stats.isSymbolicLink() || !stats.isFile()) {
      throw new Error(`artifact payload "${file.name}" is not a regular file`);
    }
    if (fileMode(stats) !== 0o600) {
      throw new Error(`artifact payload "${file.name}" must have mode 0600`);
    }
    if (stats.size !== file.byteLength) {
      throw new Error(`artifact payload "${file.name}" size drifted`);
    }
    const beforeCustody = memberCustody(path, stats);
    const bytes = await readBoundedFile(
      path,
      MAX_ARTIFACT_FILE_BYTES,
      filesystem,
    );
    if (bytes.byteLength !== file.byteLength || sha256(bytes) !== file.sha256) {
      throw new Error(`artifact payload "${file.name}" hash or size drifted`);
    }
    const statsAfter = await filesystem.lstat(path);
    assertRegularFileCustody(
      beforeCustody,
      statsAfter,
      `artifact payload "${file.name}"`,
    );
    custody.push(memberCustody(path, statsAfter));
  }
  const finalNames = sortedNames(await filesystem.readdir(directory));
  if (!sameStrings(finalNames, expectedNames)) {
    throw new Error(
      "artifact directory violates its exact allowlist; "
      + `expected [${expectedNames.join(", ")}], got [${finalNames.join(", ")}]`,
    );
  }
  return Object.freeze({
    custody: Object.freeze(custody),
  });
}

function durabilityFrom(
  limitations: Set<ArtifactDurabilityLimitation>,
): ArtifactDurability {
  const values = [...limitations].sort(compareCodeUnits);
  return Object.freeze({
    level: values.length === 0 ? "full" : "degraded",
    limitations: Object.freeze(values),
  });
}

function createManifest(
  targetName: string,
  packet: SnapshottedPacket,
  files: readonly ArtifactManifestFile[],
  durability: ArtifactDurability,
): ArtifactManifest {
  const body: Omit<ArtifactManifest, "manifestDigest"> = {
    version: "tasc-artifact-manifest-v1",
    canonicalization: "rfc8785-jcs-v1",
    targetName,
    descriptor: packet.descriptor,
    files,
    packetDigest: packetDigest(targetName, packet.descriptor, files),
    durability,
    completion: {
      state: "complete",
      manifestWrittenLast: true,
      authority: NO_DEPLOYMENT_AUTHORITY,
    },
    namespaceSafety: {
      level: "best-effort",
      limitation: PURE_NODE_NAMESPACE_LIMITATION,
    },
  };
  return deepFreeze({
    ...body,
    manifestDigest: fingerprintManifestBody(body),
  }) as ArtifactManifest;
}

function deepFreeze<T>(value: T): T {
  if (typeof value !== "object" || value === null || Object.isFrozen(value)) {
    return value;
  }
  Object.freeze(value);
  for (const child of Object.values(value as Record<string, unknown>)) {
    deepFreeze(child);
  }
  return value;
}

function parseManifestBytes(bytes: Buffer): ArtifactManifest {
  if (bytes.byteLength > MAX_MANIFEST_BYTES) {
    throw new Error("artifact manifest exceeds its byte limit");
  }
  let source: string;
  try {
    source = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch (error) {
    throw new Error("artifact manifest is not valid UTF-8", { cause: error });
  }
  let input: unknown;
  try {
    input = JSON.parse(source);
  } catch (error) {
    throw new Error("artifact manifest is not valid JSON", { cause: error });
  }
  const manifest = manifestSchema.parse(input) as ArtifactManifest;
  let totalBytes = 0;
  for (const file of manifest.files) {
    totalBytes += file.byteLength;
    if (
      !Number.isSafeInteger(totalBytes)
      || totalBytes > MAX_ARTIFACT_TOTAL_BYTES
    ) {
      throw new Error(
        `artifact manifest exceeds the ${MAX_ARTIFACT_TOTAL_BYTES}-byte total limit`,
      );
    }
  }
  if (source !== `${canonicalJson(manifest)}\n`) {
    throw new Error(
      "artifact manifest must use exact canonical JSON with one trailing newline",
    );
  }
  const names = manifest.files.map((file) => file.name);
  if (!sameStrings(names, sortedNames(names)) || new Set(names).size !== names.length) {
    throw new Error("artifact manifest file allowlist must be unique and sorted");
  }
  const limitations = manifest.durability.limitations;
  if (
    !sameStrings(limitations, sortedNames(limitations))
    || new Set(limitations).size !== limitations.length
    || (manifest.durability.level === "full") !== (limitations.length === 0)
  ) {
    throw new Error("artifact manifest durability declaration is inconsistent");
  }
  if (
    manifest.packetDigest
    !== packetDigest(
      manifest.targetName,
      manifest.descriptor,
      manifest.files,
    )
  ) {
    throw new Error("artifact manifest packet digest mismatch");
  }
  const {
    manifestDigest: recordedManifestDigest,
    ...manifestBody
  } = manifest;
  if (
    recordedManifestDigest
    !== fingerprintManifestBody(manifestBody)
  ) {
    throw new Error("artifact manifest digest mismatch");
  }
  return deepFreeze(manifest);
}

/**
 * Re-read and hash every member after the initial pass, then perform one final
 * metadata barrier. Returned payload factories close over only these final
 * verified bytes. The documented Pure Node namespace limitation still applies
 * after the final filesystem operation.
 */
async function verifyFinalPacketCustody(
  root: TrustedRoot,
  targetName: string,
  directory: string,
  targetRealPath: string,
  requireFinalSegment: boolean,
  directoryCustody: ArtifactMemberCustody,
  initialManifest: ArtifactManifest,
  initialManifestBytes: Buffer,
  initialManifestCustody: ArtifactMemberCustody,
  initialPayloadCustody: readonly ArtifactMemberCustody[],
  filesystem: ArtifactFilesystem,
  capturePayloads: boolean,
): Promise<FinalVerifiedPacket> {
  const files = initialManifest.files;
  if (initialPayloadCustody.length !== files.length) {
    throw new Error("artifact payload custody set is incomplete");
  }
  const expectedNames = sortedNames([
    ...files.map((file) => file.name),
    ARTIFACT_MANIFEST_FILENAME,
  ]);
  const actualNames = sortedNames(await filesystem.readdir(directory));
  if (!sameStrings(actualNames, expectedNames)) {
    throw new Error(
      "artifact directory violates its exact allowlist; "
      + `expected [${expectedNames.join(", ")}], got [${actualNames.join(", ")}]`,
    );
  }

  const manifestBefore = await filesystem.lstat(initialManifestCustody.path);
  assertRegularFileCustody(
    initialManifestCustody,
    manifestBefore,
    "artifact manifest",
  );
  const finalManifestBytes = await readBoundedFile(
    initialManifestCustody.path,
    MAX_MANIFEST_BYTES,
    filesystem,
  );
  const manifestBeforeCustody = memberCustody(
    initialManifestCustody.path,
    manifestBefore,
  );
  const manifestAfter = await filesystem.lstat(initialManifestCustody.path);
  assertRegularFileCustody(
    manifestBeforeCustody,
    manifestAfter,
    "artifact manifest",
  );
  if (!finalManifestBytes.equals(initialManifestBytes)) {
    throw new Error("artifact manifest content drifted");
  }
  const finalManifest = parseManifestBytes(finalManifestBytes);
  const finalManifestCustody = memberCustody(
    initialManifestCustody.path,
    manifestAfter,
  );

  const payloads: ArtifactReadPayload[] = [];
  const finalPayloadCustody: ArtifactMemberCustody[] = [];
  let totalBytes = 0;
  for (let index = 0; index < files.length; index += 1) {
    const file = files[index]!;
    const expected = initialPayloadCustody[index]!;
    const expectedPath = join(directory, file.name);
    if (expected.path !== expectedPath) {
      throw new Error("artifact payload custody order is inconsistent");
    }
    const before = await filesystem.lstat(expected.path);
    assertRegularFileCustody(
      expected,
      before,
      `artifact payload "${basename(expected.path)}"`,
    );
    const finalBytes = await readBoundedFile(
      expected.path,
      MAX_ARTIFACT_FILE_BYTES,
      filesystem,
    );
    totalBytes += finalBytes.byteLength;
    if (
      !Number.isSafeInteger(totalBytes)
      || totalBytes > MAX_ARTIFACT_TOTAL_BYTES
    ) {
      throw new Error(
        `artifact packet exceeds the ${MAX_ARTIFACT_TOTAL_BYTES}-byte total limit`,
      );
    }
    if (
      finalBytes.byteLength !== file.byteLength
      || sha256(finalBytes) !== file.sha256
    ) {
      throw new Error(`artifact payload "${file.name}" content drifted`);
    }
    const beforeCustody = memberCustody(expected.path, before);
    const after = await filesystem.lstat(expected.path);
    assertRegularFileCustody(
      beforeCustody,
      after,
      `artifact payload "${file.name}"`,
    );
    finalPayloadCustody.push(memberCustody(expected.path, after));
    if (capturePayloads) {
      const verifiedBytes = Uint8Array.from(finalBytes);
      const copyBytes = (): Uint8Array => Uint8Array.from(verifiedBytes);
      payloads.push(Object.freeze({
        name: file.name,
        copyBytes,
        mediaType: file.mediaType,
        schemaVersion: file.schemaVersion,
      }));
    }
  }

  const finalNames = sortedNames(await filesystem.readdir(directory));
  if (!sameStrings(finalNames, expectedNames)) {
    throw new Error(
      "artifact directory violates its exact allowlist; "
      + `expected [${expectedNames.join(", ")}], got [${finalNames.join(", ")}]`,
    );
  }
  assertRegularFileCustody(
    finalManifestCustody,
    await filesystem.lstat(finalManifestCustody.path),
    "artifact manifest",
  );
  for (const expected of finalPayloadCustody) {
    assertRegularFileCustody(
      expected,
      await filesystem.lstat(expected.path),
      `artifact payload "${basename(expected.path)}"`,
    );
  }
  assertDirectoryCustody(
    directoryCustody,
    await filesystem.lstat(directory),
    "artifact target directory",
  );

  const finalRealPath = normalize(await filesystem.realpath(directory));
  if (finalRealPath !== targetRealPath) {
    throw new Error("artifact target realpath drifted during verification");
  }
  assertContained(
    root.realPath,
    finalRealPath,
    requireFinalSegment ? targetName : undefined,
  );
  assertDirectoryCustody(
    directoryCustody,
    await filesystem.lstat(directory),
    "artifact target directory",
  );
  await recheckTrustedRoot(root, filesystem);
  return Object.freeze({
    manifest: finalManifest,
    payloads: Object.freeze(payloads),
  });
}

async function verifyPacketDirectory(
  root: TrustedRoot,
  targetName: string,
  directory: string,
  filesystem: ArtifactFilesystem,
  requireFinalSegment = true,
  expectedManifestDigest?: string,
  capturePayloads = false,
): Promise<ArtifactReadResult> {
  const directoryStats = await filesystem.lstat(directory);
  if (directoryStats.isSymbolicLink() || !directoryStats.isDirectory()) {
    throw new Error("artifact target must be a regular directory, not a symlink");
  }
  if (fileMode(directoryStats) !== 0o700) {
    throw new Error("artifact target directory must have mode 0700");
  }
  const directoryCustody = memberCustody(directory, directoryStats);
  const targetRealPath = normalize(await filesystem.realpath(directory));
  assertContained(
    root.realPath,
    targetRealPath,
    requireFinalSegment ? targetName : undefined,
  );

  const manifestPath = join(directory, ARTIFACT_MANIFEST_FILENAME);
  const manifestStats = await filesystem.lstat(manifestPath);
  if (manifestStats.isSymbolicLink() || !manifestStats.isFile()) {
    throw new Error("artifact manifest must be a regular file");
  }
  if (fileMode(manifestStats) !== 0o600) {
    throw new Error("artifact manifest must have mode 0600");
  }
  const manifestCustodyBefore = memberCustody(manifestPath, manifestStats);
  const manifestBytes = await readBoundedFile(
    manifestPath,
    MAX_MANIFEST_BYTES,
    filesystem,
  );
  const manifestStatsAfter = await filesystem.lstat(manifestPath);
  assertRegularFileCustody(
    manifestCustodyBefore,
    manifestStatsAfter,
    "artifact manifest",
  );
  const manifestCustody = memberCustody(manifestPath, manifestStatsAfter);
  const manifest = parseManifestBytes(manifestBytes);
  if (manifest.targetName !== targetName) {
    throw new Error("artifact manifest is bound to a different target name");
  }
  if (
    expectedManifestDigest !== undefined
    && manifest.manifestDigest !== expectedManifestDigest
  ) {
    throw new Error("pinned manifest digest mismatch");
  }
  const verifiedPayloads = await verifyPayloadSet(
    directory,
    manifest.files,
    filesystem,
    true,
  );
  const finalPacket = await verifyFinalPacketCustody(
    root,
    targetName,
    directory,
    targetRealPath,
    requireFinalSegment,
    directoryCustody,
    manifest,
    manifestBytes,
    manifestCustody,
    verifiedPayloads.custody,
    filesystem,
    capturePayloads,
  );
  return Object.freeze({
    path: directory,
    manifest: finalPacket.manifest,
    durability: finalPacket.manifest.durability,
    files: finalPacket.payloads,
  });
}

function writeResultFrom(read: ArtifactReadResult): ArtifactWriteResult {
  return Object.freeze({
    path: read.path,
    manifest: read.manifest,
    durability: read.durability,
  });
}

async function safeCleanupStaging(
  stagingPath: string | null,
  stagingIdentity: PathIdentity | null,
  root: TrustedRoot,
  filesystem: ArtifactFilesystem,
): Promise<void> {
  if (stagingPath === null || stagingIdentity === null) return;
  let stats: Stats;
  try {
    stats = await filesystem.lstat(stagingPath);
  } catch (error) {
    if (isMissing(error)) return;
    throw error;
  }
  if (
    stats.isSymbolicLink()
    || !stats.isDirectory()
    || !sameIdentity(stagingIdentity, stats)
  ) {
    return;
  }
  const stagingRealPath = normalize(await filesystem.realpath(stagingPath));
  assertContained(root.realPath, stagingRealPath);
  await filesystem.rm(stagingPath, { recursive: true, force: true });
}

/**
 * Atomically publish one immutable packet under an existing trusted root.
 *
 * The caller supplies one target segment, never a path. The final directory is
 * absent until a fully verified staging directory is renamed into place.
 */
export async function writeArtifactPacket(
  rootDirectory: string,
  targetName: string,
  input: ArtifactPacketInput,
  options: ArtifactWriterOptions = {},
): Promise<ArtifactWriteResult> {
  return writeSnapshottedArtifactPacket(
    rootDirectory,
    targetName,
    snapshotPacket(input),
    options,
  );
}

async function writeSnapshottedArtifactPacket(
  rootDirectory: string,
  targetName: string,
  packet: SnapshottedPacket,
  options: ArtifactWriterOptions,
): Promise<ArtifactWriteResult> {
  const rootPath = String(rootDirectory);
  const targetSnapshot = String(targetName);
  assertSafeTargetName(targetSnapshot);
  const filesystem = options.filesystem ?? nodeArtifactFilesystem;
  const root = await inspectTrustedRoot(rootPath, filesystem);
  const targetPath = join(root.path, targetSnapshot);
  assertContained(root.path, targetPath, targetSnapshot);
  await assertPathAbsent(targetPath, filesystem);

  const limitations = new Set<ArtifactDurabilityLimitation>();
  const parentCapability: SyncCapability = { status: "unknown" };
  const directoryCapability: SyncCapability = { status: "unknown" };
  const fileCapability: SyncCapability = { status: "unknown" };
  let parentHandle: ArtifactFileHandle | null = null;
  let stagingHandle: ArtifactFileHandle | null = null;
  let stagingPath: string | null = null;
  let stagingIdentity: PathIdentity | null = null;
  let published = false;
  let operationError: unknown;

  try {
    parentHandle = await openDirectoryHandle(
      root.path,
      filesystem,
      parentCapability,
      "parent-directory-fsync-unsupported",
      limitations,
    );
    if (parentHandle !== null) {
      await syncHandle(
        parentHandle,
        parentCapability,
        "parent-directory-fsync-unsupported",
        limitations,
      );
    }

    const stagingPrefix = join(
      root.path,
      `.${targetSnapshot}.tasc-stage-`,
    );
    stagingPath = await filesystem.mkdtemp(stagingPrefix);
    if (
      !isAbsolute(stagingPath)
      || normalize(stagingPath) !== stagingPath
      || dirname(stagingPath) !== root.path
      || !basename(stagingPath).startsWith(
        `.${targetSnapshot}.tasc-stage-`,
      )
    ) {
      throw new Error("filesystem returned an unsafe staging path");
    }
    const initialStagingStats = await filesystem.lstat(stagingPath);
    if (
      initialStagingStats.isSymbolicLink()
      || !initialStagingStats.isDirectory()
    ) {
      throw new Error("artifact staging path is a symlink or not a directory");
    }
    const stagingRealPath = normalize(await filesystem.realpath(stagingPath));
    assertContained(root.realPath, stagingRealPath);
    stagingIdentity = identity(stagingPath, initialStagingStats);
    await filesystem.chmod(stagingPath, 0o700);
    const securedStagingStats = await filesystem.lstat(stagingPath);
    if (
      !sameIdentity(stagingIdentity, securedStagingStats)
      || securedStagingStats.isSymbolicLink()
      || !securedStagingStats.isDirectory()
      || fileMode(securedStagingStats) !== 0o700
    ) {
      throw new Error("artifact staging identity or 0700 mode drifted");
    }

    const files = expectedManifestFiles(packet.files);
    for (const file of packet.files) {
      await writeExclusiveFile(
        join(stagingPath, file.name),
        file.bytes,
        filesystem,
        fileCapability,
        limitations,
      );
    }
    await verifyPayloadSet(stagingPath, files, filesystem, false);

    stagingHandle = await openDirectoryHandle(
      stagingPath,
      filesystem,
      directoryCapability,
      "directory-fsync-unsupported",
      limitations,
    );
    if (stagingHandle !== null) {
      await syncHandle(
        stagingHandle,
        directoryCapability,
        "directory-fsync-unsupported",
        limitations,
      );
    }

    const durability = durabilityFrom(limitations);
    const manifest = createManifest(
      targetSnapshot,
      packet,
      files,
      durability,
    );
    const manifestBytes = Buffer.from(`${canonicalJson(manifest)}\n`, "utf8");
    if (manifestBytes.byteLength > MAX_MANIFEST_BYTES) {
      throw new Error("artifact manifest exceeds its byte limit");
    }
    await writeExclusiveFile(
      join(stagingPath, ARTIFACT_MANIFEST_FILENAME),
      manifestBytes,
      filesystem,
      fileCapability,
      limitations,
    );
    if (
      limitations.size !== durability.limitations.length
      || [...limitations].some(
        (limitation) => !durability.limitations.includes(limitation),
      )
    ) {
      throw new Error(
        "filesystem durability capability changed after manifest sealing",
      );
    }
    await verifyPacketDirectory(
      root,
      targetSnapshot,
      stagingPath,
      filesystem,
      false,
    );
    if (stagingHandle !== null) {
      await syncHandle(
        stagingHandle,
        directoryCapability,
        "directory-fsync-unsupported",
        limitations,
      );
    }
    const syncedStagingHandle = stagingHandle;
    stagingHandle = null;
    await closeHandle(syncedStagingHandle);

    await recheckTrustedRoot(root, filesystem);
    const stagingBeforeRename = await filesystem.lstat(stagingPath);
    if (
      stagingBeforeRename.isSymbolicLink()
      || !stagingBeforeRename.isDirectory()
      || !sameIdentity(stagingIdentity, stagingBeforeRename)
    ) {
      throw new Error("artifact staging identity drifted before publication");
    }
    await assertPathAbsent(targetPath, filesystem);
    await filesystem.rename(stagingPath, targetPath);
    published = true;
    const targetStats = await filesystem.lstat(targetPath);
    if (
      targetStats.isSymbolicLink()
      || !targetStats.isDirectory()
      || !sameIdentity(stagingIdentity, targetStats)
    ) {
      throw new Error("artifact target identity drifted during publication");
    }
    const result = await verifyPacketDirectory(
      root,
      targetSnapshot,
      targetPath,
      filesystem,
    );
    if (parentHandle !== null) {
      await syncHandle(
        parentHandle,
        parentCapability,
        "parent-directory-fsync-unsupported",
        limitations,
      );
    }
    return writeResultFrom(result);
  } catch (error) {
    operationError = error;
    const failures: unknown[] = [error];
    const openStagingHandle = stagingHandle;
    stagingHandle = null;
    try {
      await closeHandle(openStagingHandle);
    } catch (closeError) {
      failures.push(closeError);
    }
    if (!published) {
      try {
        await safeCleanupStaging(
          stagingPath,
          stagingIdentity,
          root,
          filesystem,
        );
      } catch (cleanupError) {
        failures.push(cleanupError);
      }
    }
    if (failures.length > 1) {
      throw new AggregateError(
        failures,
        "artifact publication or staging cleanup failed",
      );
    }
    throw error;
  } finally {
    try {
      await closeHandle(stagingHandle);
      await closeHandle(parentHandle);
    } catch (closeError) {
      if (operationError === undefined) throw closeError;
    }
  }
}

/**
 * Verify packet self-consistency and filesystem custody. This is deliberately
 * integrity-only: because the manifest is unattested, a coherently rewritten
 * packet is not authenticated and cannot authorize a controller transition.
 */
export async function verifyArtifactPacket(
  rootDirectory: string,
  targetName: string,
  options: ArtifactVerificationOptions = {},
): Promise<ArtifactWriteResult> {
  const rootPath = String(rootDirectory);
  const targetSnapshot = String(targetName);
  assertSafeTargetName(targetSnapshot);
  const expectedManifestDigest = options.expectedManifestDigest;
  if (
    expectedManifestDigest !== undefined
    && !sha256Pattern.test(expectedManifestDigest)
  ) {
    throw new Error(
      "expected manifest digest must be a lowercase SHA-256 digest",
    );
  }
  const filesystem = options.filesystem ?? nodeArtifactFilesystem;
  const root = await inspectTrustedRoot(rootPath, filesystem);
  const targetPath = join(root.path, targetSnapshot);
  assertContained(root.path, targetPath, targetSnapshot);
  return writeResultFrom(await verifyPacketDirectory(
    root,
    targetSnapshot,
    targetPath,
    filesystem,
    true,
    expectedManifestDigest,
  ));
}

/**
 * Read a complete packet if it exists. Absence is recognized only for the
 * final target segment; an incomplete target, missing payload, symlink, or
 * custody drift is an error. Each payload exposes only a copy-returning data
 * method backed by closure-private bytes from the bounded descriptor read that
 * verified its manifest hash.
 */
export async function readArtifactPacketIfPresent(
  rootDirectory: string,
  targetName: string,
  options: ArtifactVerificationOptions = {},
): Promise<ArtifactReadResult | null> {
  const rootPath = String(rootDirectory);
  const targetSnapshot = String(targetName);
  assertSafeTargetName(targetSnapshot);
  const expectedManifestDigest = options.expectedManifestDigest;
  if (
    expectedManifestDigest !== undefined
    && !sha256Pattern.test(expectedManifestDigest)
  ) {
    throw new Error(
      "expected manifest digest must be a lowercase SHA-256 digest",
    );
  }
  const filesystem = options.filesystem ?? nodeArtifactFilesystem;
  const root = await inspectTrustedRoot(rootPath, filesystem);
  const targetPath = join(root.path, targetSnapshot);
  assertContained(root.path, targetPath, targetSnapshot);

  for (let check = 0; check < 2; check += 1) {
    try {
      await filesystem.lstat(targetPath);
    } catch (error) {
      if (!isMissing(error)) throw error;
      await recheckTrustedRoot(root, filesystem);
      continue;
    }
    return verifyPacketDirectory(
      root,
      targetSnapshot,
      targetPath,
      filesystem,
      true,
      expectedManifestDigest,
      true,
    );
  }
  return null;
}

const IMMUTABLE_PACKET_CONFLICT =
  "artifact target conflicts with the expected immutable packet";

function isTargetPublicationCollision(error: unknown): boolean {
  return (
    error instanceof ArtifactTargetExistsError
    || new Set(["EEXIST", "ENOTEMPTY"]).has(errorCode(error) ?? "")
  );
}

function matchingPacketResult(
  result: ArtifactWriteResult,
  expectedPacketDigest: string,
  disposition: ArtifactWriteOrVerifyResult["disposition"],
): ArtifactWriteOrVerifyResult {
  if (result.manifest.packetDigest !== expectedPacketDigest) {
    throw new Error(IMMUTABLE_PACKET_CONFLICT);
  }
  return Object.freeze({
    path: result.path,
    manifest: result.manifest,
    durability: result.durability,
    disposition,
  });
}

/**
 * Publish an immutable packet, or verify that a concurrently/previously
 * published packet has the exact same canonical identity. Valid but different
 * bytes always produce the same conflict error and are never overwritten.
 */
export async function writeArtifactPacketOrVerifyIdentical(
  rootDirectory: string,
  targetName: string,
  input: ArtifactPacketInput,
  options: ArtifactWriterOptions = {},
): Promise<ArtifactWriteOrVerifyResult> {
  const rootPath = String(rootDirectory);
  const targetSnapshot = String(targetName);
  assertSafeTargetName(targetSnapshot);
  const packet = snapshotPacket(input);
  const expectedPacketDigest = packetDigest(
    targetSnapshot,
    packet.descriptor,
    expectedManifestFiles(packet.files),
  );
  const filesystem = options.filesystem ?? nodeArtifactFilesystem;
  const existing = await readArtifactPacketIfPresent(
    rootPath,
    targetSnapshot,
    { filesystem },
  );
  if (existing !== null) {
    return matchingPacketResult(
      existing,
      expectedPacketDigest,
      "verified-identical",
    );
  }

  try {
    const written = await writeSnapshottedArtifactPacket(
      rootPath,
      targetSnapshot,
      packet,
      { filesystem },
    );
    return matchingPacketResult(written, expectedPacketDigest, "written");
  } catch (error) {
    if (!isTargetPublicationCollision(error)) throw error;
    const winner = await readArtifactPacketIfPresent(
      rootPath,
      targetSnapshot,
      { filesystem },
    );
    if (winner === null) throw error;
    return matchingPacketResult(
      winner,
      expectedPacketDigest,
      "verified-identical",
    );
  }
}
