#!/usr/bin/env node

import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmod,
  lstat,
  mkdir,
  readFile,
  readdir,
  rename,
  writeFile,
} from "node:fs/promises";
import {
  basename,
  dirname,
  isAbsolute,
  join,
  resolve,
} from "node:path";
import process from "node:process";

const PACKAGE_NAME = "@rachittshah/tasc";
const EXPECTED_REPOSITORY = "rachittshah/tasc";
const OUTPUT_DIRECTORY_NAME = "release-candidate";
const TARBALL_NAME = "package.tgz";
const CHECKSUM_NAME = "SHA512SUMS";
const PACK_RESULT_NAME = "pack-result.json";
const PROVENANCE_NAME = "provenance.json";
const OUTPUT_NAMES = Object.freeze([
  CHECKSUM_NAME,
  PACK_RESULT_NAME,
  PROVENANCE_NAME,
  TARBALL_NAME,
]);
const REQUIRED_PACKAGE_FILES = Object.freeze([
  "CHANGELOG.md",
  "LICENSE",
  "README.md",
  "SECURITY.md",
  "dist/cli.d.ts",
  "dist/cli.js",
  "dist/index.d.ts",
  "dist/index.js",
  "dist/runtime/index.d.ts",
  "dist/runtime/index.js",
  "package.json",
]);
const ALLOWED_PACKAGE_ROOTS = new Set([
  "CHANGELOG.md",
  "LICENSE",
  "README.md",
  "SECURITY.md",
  "dist",
  "package.json",
]);
const SEMVER_PATTERN =
  /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/u;
const COMMIT_PATTERN = /^[a-f0-9]{40}$/u;
const MAX_TARBALL_BYTES = 32 * 1024 * 1024;
const MAX_PACKAGE_FILES = 20_000;
const MAX_COMMAND_OUTPUT_BYTES = 16 * 1024 * 1024;
const COMMAND_TIMEOUT_MS = 2 * 60 * 1_000;
const npmExecutable = process.platform === "win32" ? "npm.cmd" : "npm";
const repositoryRoot = resolve(import.meta.dirname, "..");
const outputDirectory = join(repositoryRoot, OUTPUT_DIRECTORY_NAME);
const tarballPath = join(outputDirectory, TARBALL_NAME);

function fail(message) {
  throw new Error(message);
}

function terminate(child) {
  if (child.pid === undefined) return;
  try {
    if (process.platform === "win32") {
      child.kill("SIGKILL");
    } else {
      process.kill(-child.pid, "SIGKILL");
    }
  } catch {
    try {
      child.kill("SIGKILL");
    } catch {
      // The process may already have exited.
    }
  }
}

async function runCommand(
  command,
  args,
  {
    cwd = repositoryRoot,
    environment = process.env,
    timeoutMs = COMMAND_TIMEOUT_MS,
    outputLimit = MAX_COMMAND_OUTPUT_BYTES,
  } = {},
) {
  return new Promise((resolvePromise, rejectPromise) => {
    const stdout = [];
    const stderr = [];
    let outputBytes = 0;
    let failure = null;
    const child = spawn(command, args, {
      cwd,
      env: environment,
      detached: process.platform !== "win32",
      shell: false,
      stdio: ["ignore", "pipe", "pipe"],
      windowsHide: true,
    });
    const rejectOnce = (error) => {
      failure ??= error;
      terminate(child);
    };
    const capture = (collection) => (chunk) => {
      if (!Buffer.isBuffer(chunk)) {
        rejectOnce(new Error("subprocess returned non-byte output"));
        return;
      }
      outputBytes += chunk.byteLength;
      if (outputBytes > outputLimit) {
        rejectOnce(new Error("subprocess exceeded its output limit"));
        return;
      }
      collection.push(chunk);
    };
    child.stdout.on("data", capture(stdout));
    child.stderr.on("data", capture(stderr));
    const timer = setTimeout(() => {
      rejectOnce(new Error("subprocess exceeded its deadline"));
    }, timeoutMs);
    timer.unref();
    child.once("error", (error) => {
      failure ??= error;
    });
    child.once("close", (code, signal) => {
      clearTimeout(timer);
      if (failure !== null) {
        rejectPromise(failure);
        return;
      }
      if (code !== 0) {
        const detail = Buffer.concat([...stdout, ...stderr])
          .toString("utf8")
          .slice(-4_000);
        rejectPromise(new Error(
          `subprocess failed with code ${String(code)}`
          + `${signal === null ? "" : ` and signal ${signal}`}`
          + `${detail.length === 0 ? "" : `:\n${detail}`}`,
        ));
        return;
      }
      resolvePromise(Object.freeze({
        stdout: Buffer.concat(stdout),
        stderr: Buffer.concat(stderr),
      }));
    });
  });
}

function parseJson(bytes, label) {
  try {
    return JSON.parse(bytes.toString("utf8"));
  } catch {
    fail(`${label} is not valid JSON`);
  }
}

function isPlainRecord(value) {
  return value !== null
    && typeof value === "object"
    && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype;
}

function hasExactKeys(value, expected) {
  return isPlainRecord(value)
    && JSON.stringify(sorted(Object.keys(value)))
      === JSON.stringify(sorted(expected));
}

function hasExpectedPublicSurface(metadata, version) {
  return isPlainRecord(metadata)
    && metadata.name === PACKAGE_NAME
    && metadata.version === version
    && metadata.private !== true
    && metadata.main === "./dist/index.js"
    && metadata.types === "./dist/index.d.ts"
    && metadata.sideEffects === false
    && metadata.publishConfig?.access === "public"
    && metadata.repository?.url
      === "git+https://github.com/rachittshah/tasc.git"
    && hasExactKeys(metadata.bin, ["tasc"])
    && metadata.bin.tasc === "./dist/cli.js"
    && hasExactKeys(metadata.exports, [".", "./runtime"])
    && hasExactKeys(metadata.exports["."], ["default", "import", "types"])
    && metadata.exports["."].types === "./dist/index.d.ts"
    && metadata.exports["."].import === "./dist/index.js"
    && metadata.exports["."].default === "./dist/index.js"
    && hasExactKeys(
      metadata.exports["./runtime"],
      ["default", "import", "types"],
    )
    && metadata.exports["./runtime"].types === "./dist/runtime/index.d.ts"
    && metadata.exports["./runtime"].import === "./dist/runtime/index.js"
    && metadata.exports["./runtime"].default === "./dist/runtime/index.js";
}

function safePackagePath(path) {
  if (
    typeof path !== "string"
    || path.length === 0
    || path.length > 4_096
    || path.includes("\\")
    || path.includes("\0")
    || isAbsolute(path)
  ) {
    return false;
  }
  return path.split("/").every(
    (segment) => segment.length > 0 && segment !== "." && segment !== "..",
  );
}

function sorted(values) {
  return [...values].sort((left, right) => (
    left < right ? -1 : left > right ? 1 : 0
  ));
}

async function packageMetadata() {
  const metadata = parseJson(
    await readFile(join(repositoryRoot, "package.json")),
    "package metadata",
  );
  if (
    typeof metadata?.version !== "string"
    || !SEMVER_PATTERN.test(metadata.version)
    || !hasExpectedPublicSurface(metadata, metadata.version)
  ) {
    fail("package metadata is not the expected public release surface");
  }
  return metadata;
}

function releaseTag() {
  const ref = process.env.GITHUB_REF;
  const refName = process.env.GITHUB_REF_NAME;
  const refType = process.env.GITHUB_REF_TYPE;
  if (typeof ref === "string" && ref.startsWith("refs/tags/")) {
    return ref.slice("refs/tags/".length);
  }
  if (refType === "tag" && typeof refName === "string") return refName;
  return null;
}

function validateReleaseContext(version) {
  const tag = releaseTag();
  if (tag === null) return;
  if (tag !== `v${version}` || !SEMVER_PATTERN.test(tag.slice(1))) {
    fail("release tag must exactly match v<package.version>");
  }
  if (
    process.env.GITHUB_REPOSITORY !== undefined
    && process.env.GITHUB_REPOSITORY !== EXPECTED_REPOSITORY
  ) {
    fail("release tags are accepted only from the canonical repository");
  }
}

function parsePackResult(stdout, version) {
  const parsed = parseJson(stdout, "npm pack output");
  if (!Array.isArray(parsed) || parsed.length !== 1) {
    fail("npm pack did not report exactly one tarball");
  }
  const result = parsed[0];
  if (
    !isPlainRecord(result)
    || result.name !== PACKAGE_NAME
    || result.version !== version
    || result.id !== `${PACKAGE_NAME}@${version}`
    || typeof result.filename !== "string"
    || basename(result.filename) !== result.filename
    || !result.filename.endsWith(".tgz")
    || typeof result.integrity !== "string"
    || !result.integrity.startsWith("sha512-")
    || !Array.isArray(result.files)
    || result.files.length < 1
    || result.files.length > MAX_PACKAGE_FILES
  ) {
    fail("npm pack returned invalid release metadata");
  }
  return result;
}

function validatePackFiles(packResult) {
  const paths = [];
  for (const file of packResult.files) {
    if (
      !isPlainRecord(file)
      || !safePackagePath(file.path)
      || typeof file.size !== "number"
      || !Number.isSafeInteger(file.size)
      || file.size < 0
      || typeof file.mode !== "number"
      || !Number.isSafeInteger(file.mode)
      || file.mode < 0
      || file.mode > 0o777
    ) {
      fail("npm pack reported an invalid package file");
    }
    paths.push(file.path);
  }
  const unique = new Set(paths);
  if (unique.size !== paths.length) {
    fail("npm pack reported duplicate package paths");
  }
  for (const required of REQUIRED_PACKAGE_FILES) {
    if (!unique.has(required)) {
      fail(`release tarball is missing ${required}`);
    }
  }
  for (const path of unique) {
    const root = path.split("/")[0];
    if (!ALLOWED_PACKAGE_ROOTS.has(root)) {
      fail(`release tarball contains unexpected path ${path}`);
    }
    if (root === "dist" && !/\.(?:d\.ts|js|js\.map)$/u.test(path)) {
      fail(`release tarball contains unexpected dist path ${path}`);
    }
  }
  return paths;
}

async function exactCommit() {
  const fromEnvironment = process.env.GITHUB_SHA;
  if (
    typeof fromEnvironment === "string"
    && COMMIT_PATTERN.test(fromEnvironment)
  ) {
    return fromEnvironment;
  }
  const result = await runCommand("git", ["rev-parse", "HEAD"]);
  const commit = result.stdout.toString("utf8").trim();
  if (!COMMIT_PATTERN.test(commit)) fail("git returned an invalid commit");
  return commit;
}

async function assertPristineRepository() {
  const status = await runCommand(
    "git",
    ["status", "--porcelain=v1", "--untracked-files=all"],
  );
  if (status.stdout.byteLength !== 0) {
    fail("release candidates must be built from a pristine checkout");
  }
}

async function createProvenance(version, digest, integrity) {
  const commit = await exactCommit();
  const repository = process.env.GITHUB_REPOSITORY ?? EXPECTED_REPOSITORY;
  const serverUrl = process.env.GITHUB_SERVER_URL ?? "https://github.com";
  const runId = process.env.GITHUB_RUN_ID ?? "local";
  const runAttempt = process.env.GITHUB_RUN_ATTEMPT ?? "1";
  const npmVersion = (
    await runCommand(npmExecutable, ["--version"])
  ).stdout.toString("utf8").trim();
  return {
    _type: "https://in-toto.io/Statement/v1",
    subject: [{
      name: TARBALL_NAME,
      digest: { sha512: digest },
    }],
    predicateType: "https://slsa.dev/provenance/v1",
    predicate: {
      buildDefinition: {
        buildType:
          "https://github.com/rachittshah/tasc/.github/workflows/release.yml@v1",
        externalParameters: {
          eventName: process.env.GITHUB_EVENT_NAME ?? "local",
          ref: process.env.GITHUB_REF ?? "local",
          package: {
            name: PACKAGE_NAME,
            version,
            integrity,
          },
        },
        internalParameters: {
          node: process.version,
          npm: npmVersion,
        },
        resolvedDependencies: [{
          uri: `git+https://github.com/${repository}.git`,
          digest: { gitCommit: commit },
        }],
      },
      runDetails: {
        builder: {
          id: `${serverUrl}/${repository}/actions/runs/${runId}`,
        },
        metadata: {
          invocationId: `${runId}/${runAttempt}`,
        },
      },
    },
  };
}

async function assertRegularFile(path, maximumBytes) {
  const stats = await lstat(path);
  if (
    !stats.isFile()
    || !Number.isSafeInteger(stats.size)
    || stats.size < 1
    || stats.size > maximumBytes
  ) {
    fail(`${basename(path)} is not a bounded regular file`);
  }
  return stats;
}

async function validateTarball(packResult, version) {
  const stats = await assertRegularFile(tarballPath, MAX_TARBALL_BYTES);
  const bytes = await readFile(tarballPath);
  if (bytes.byteLength !== stats.size) {
    fail("release tarball changed while being read");
  }
  const digest = createHash("sha512").update(bytes).digest("hex");
  const integrity =
    `sha512-${createHash("sha512").update(bytes).digest("base64")}`;
  if (packResult.integrity !== integrity) {
    fail("npm integrity does not match the exact release tarball");
  }

  const packagePaths = validatePackFiles(packResult);
  const listing = await runCommand("tar", ["-tzf", tarballPath]);
  const archivePaths = listing.stdout
    .toString("utf8")
    .split(/\r?\n/u)
    .filter((path) => path.length > 0 && !path.endsWith("/"));
  if (
    archivePaths.some(
      (path) => !path.startsWith("package/")
        || !safePackagePath(path.slice("package/".length)),
    )
    || JSON.stringify(sorted(archivePaths))
      !== JSON.stringify(sorted(
        packagePaths.map((path) => `package/${path}`),
      ))
  ) {
    fail("tar archive entries do not match npm pack metadata");
  }
  const verboseListing = await runCommand("tar", ["-tvzf", tarballPath]);
  if (
    verboseListing.stdout
      .toString("utf8")
      .split(/\r?\n/u)
      .filter((line) => line.length > 0)
      .some((line) => line[0] !== "-" && line[0] !== "d")
  ) {
    fail("release tarball cannot contain links or special files");
  }

  const packedMetadata = parseJson(
    (
      await runCommand(
        "tar",
        ["-xOzf", tarballPath, "package/package.json"],
      )
    ).stdout,
    "packed package metadata",
  );
  if (
    !hasExpectedPublicSurface(packedMetadata, version)
  ) {
    fail("packed package public surface is invalid");
  }
  return Object.freeze({ digest, integrity });
}

async function buildReleaseCandidate() {
  const metadata = await packageMetadata();
  validateReleaseContext(metadata.version);
  await assertPristineRepository();
  await mkdir(outputDirectory, { mode: 0o700 });

  const environment = {
    ...process.env,
    npm_config_audit: "false",
    npm_config_fund: "false",
    npm_config_provenance: "false",
    npm_config_update_notifier: "false",
  };
  const packed = await runCommand(
    npmExecutable,
    ["pack", "--json", "--pack-destination", outputDirectory],
    { environment },
  );
  const packResult = parsePackResult(packed.stdout, metadata.version);
  const npmTarballPath = resolve(outputDirectory, packResult.filename);
  if (dirname(npmTarballPath) !== outputDirectory) {
    fail("npm pack returned a tarball outside the release directory");
  }
  await rename(npmTarballPath, tarballPath);
  await chmod(tarballPath, 0o600);

  const verified = await validateTarball(packResult, metadata.version);
  const provenance = await createProvenance(
    metadata.version,
    verified.digest,
    verified.integrity,
  );
  await Promise.all([
    writeFile(
      join(outputDirectory, CHECKSUM_NAME),
      `${verified.digest}  ${TARBALL_NAME}\n`,
      { encoding: "utf8", flag: "wx", mode: 0o600 },
    ),
    writeFile(
      join(outputDirectory, PACK_RESULT_NAME),
      `${JSON.stringify({
        ...packResult,
        artifactFilename: TARBALL_NAME,
      }, null, 2)}\n`,
      { encoding: "utf8", flag: "wx", mode: 0o600 },
    ),
    writeFile(
      join(outputDirectory, PROVENANCE_NAME),
      `${JSON.stringify(provenance, null, 2)}\n`,
      { encoding: "utf8", flag: "wx", mode: 0o600 },
    ),
  ]);
  await verifyReleaseCandidate();
}

async function verifyReleaseCandidate() {
  const metadata = await packageMetadata();
  validateReleaseContext(metadata.version);
  const entries = await readdir(outputDirectory);
  if (
    JSON.stringify(sorted(entries)) !== JSON.stringify(sorted(OUTPUT_NAMES))
  ) {
    fail("release directory contains unexpected files");
  }
  await Promise.all(
    OUTPUT_NAMES.map((name) => assertRegularFile(
      join(outputDirectory, name),
      name === TARBALL_NAME ? MAX_TARBALL_BYTES : 2 * 1024 * 1024,
    )),
  );

  const storedPackResult = parseJson(
    await readFile(join(outputDirectory, PACK_RESULT_NAME)),
    "stored npm pack result",
  );
  if (
    !isPlainRecord(storedPackResult)
    || storedPackResult.artifactFilename !== TARBALL_NAME
  ) {
    fail("stored npm pack result is invalid");
  }
  const packResult = parsePackResult(
    Buffer.from(JSON.stringify([storedPackResult])),
    metadata.version,
  );
  const verified = await validateTarball(packResult, metadata.version);

  const checksum = (
    await readFile(join(outputDirectory, CHECKSUM_NAME), "utf8")
  );
  if (checksum !== `${verified.digest}  ${TARBALL_NAME}\n`) {
    fail("SHA512SUMS does not match the exact release tarball");
  }
  const provenance = parseJson(
    await readFile(join(outputDirectory, PROVENANCE_NAME)),
    "release provenance",
  );
  const commit = await exactCommit();
  if (
    !isPlainRecord(provenance)
    || provenance._type !== "https://in-toto.io/Statement/v1"
    || provenance.predicateType !== "https://slsa.dev/provenance/v1"
    || !Array.isArray(provenance.subject)
    || provenance.subject.length !== 1
    || provenance.subject[0]?.name !== TARBALL_NAME
    || provenance.subject[0]?.digest?.sha512 !== verified.digest
    || provenance.predicate?.buildDefinition?.externalParameters?.package
      ?.name !== PACKAGE_NAME
    || provenance.predicate?.buildDefinition?.externalParameters?.package
      ?.version !== metadata.version
    || provenance.predicate?.buildDefinition?.externalParameters?.package
      ?.integrity !== verified.integrity
    || provenance.predicate?.buildDefinition?.resolvedDependencies?.[0]
      ?.digest?.gitCommit !== commit
  ) {
    fail("release provenance does not bind this package, commit, and tarball");
  }
  process.stdout.write(
    `release candidate verified (${PACKAGE_NAME}@${metadata.version}, `
    + `sha512:${verified.digest})\n`,
  );
}

async function main() {
  const [command, ...extra] = process.argv.slice(2);
  if (
    extra.length !== 0
    || (command !== "build" && command !== "verify")
  ) {
    fail("usage: node scripts/release-artifact.mjs <build|verify>");
  }
  if (command === "build") {
    await buildReleaseCandidate();
  } else {
    await verifyReleaseCandidate();
  }
}

main().catch((error) => {
  const message = error instanceof Error
    ? error.message
    : "release artifact command failed unexpectedly";
  process.stderr.write(`release artifact failed: ${message}\n`);
  process.exitCode = 1;
});
