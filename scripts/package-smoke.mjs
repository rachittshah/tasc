#!/usr/bin/env node

import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import {
  access,
  copyFile,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  writeFile,
} from "node:fs/promises";
import { constants as fsConstants } from "node:fs";
import { tmpdir } from "node:os";
import {
  basename,
  dirname,
  isAbsolute,
  join,
  relative,
  resolve,
  sep,
} from "node:path";
import process from "node:process";

const PACKAGE_NAME = "@rachittshah/tasc";
const SOURCE_EXCLUSIONS = new Set([
  ".git",
  "node_modules",
  "dist",
  "coverage",
  "artifacts",
  "scratch",
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
const COMMAND_OUTPUT_LIMIT = 4 * 1024 * 1024;
const GIT_OUTPUT_LIMIT = 16 * 1024 * 1024;
const SOURCE_FILE_LIMIT = 20_000;
const SOURCE_FILE_BYTE_LIMIT = 128 * 1024 * 1024;
const SOURCE_TOTAL_BYTE_LIMIT = 1024 * 1024 * 1024;
const TARBALL_BYTE_LIMIT = 32 * 1024 * 1024;
const INSTALL_TIMEOUT_MS = 4 * 60 * 1_000;
const PACK_TIMEOUT_MS = 2 * 60 * 1_000;
const COMMAND_TIMEOUT_MS = 30 * 1_000;
const npmExecutable = process.platform === "win32" ? "npm.cmd" : "npm";
const binExecutable = process.platform === "win32" ? "tasc.cmd" : "tasc";

function fail(message) {
  throw new Error(message);
}

function parseArguments(argv) {
  if (argv.length === 0) return Object.freeze({ gitArchive: false });
  if (argv.length === 1 && argv[0] === "--git-archive") {
    return Object.freeze({ gitArchive: true });
  }
  fail("usage: node scripts/package-smoke.mjs [--git-archive]");
}

function safeEnvironment(configDirectory, cacheDirectory) {
  const path = process.env.PATH;
  if (typeof path !== "string" || path.length === 0) {
    fail("package smoke requires PATH");
  }
  const environment = {
    PATH: path,
    CI: "true",
    NO_COLOR: "1",
    FORCE_COLOR: "0",
    npm_config_audit: "false",
    npm_config_cache: cacheDirectory,
    npm_config_fund: "false",
    npm_config_loglevel: "error",
    npm_config_provenance: "false",
    npm_config_update_notifier: "false",
    npm_config_userconfig: join(configDirectory, ".npmrc"),
  };
  for (const name of [
    "COMSPEC",
    "LANG",
    "LC_ALL",
    "PATHEXT",
    "SystemRoot",
    "TEMP",
    "TMP",
    "TMPDIR",
  ]) {
    const value = process.env[name];
    if (typeof value === "string" && value.length > 0) {
      environment[name] = value;
    }
  }
  return Object.freeze(environment);
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

function diagnosticOutput(stdout, stderr) {
  const source = Buffer.concat([...stdout, ...stderr])
    .toString("utf8")
    .replaceAll(/\u001b\[[0-9;]*m/g, "");
  const maximum = 4_000;
  return source.length <= maximum ? source : source.slice(-maximum);
}

async function runCommand(
  command,
  args,
  {
    cwd,
    environment,
    timeoutMs = COMMAND_TIMEOUT_MS,
    outputLimit = COMMAND_OUTPUT_LIMIT,
  },
) {
  return new Promise((resolvePromise, rejectPromise) => {
    const stdout = [];
    const stderr = [];
    let outputBytes = 0;
    let failure = null;
    let settled = false;
    const child = spawn(command, args, {
      cwd,
      env: environment,
      detached: process.platform !== "win32",
      shell: false,
      stdio: ["ignore", "pipe", "pipe"],
      windowsHide: true,
    });

    const rejectOnce = (error) => {
      if (failure === null) failure = error;
      terminate(child);
    };
    const capture = (collection) => (chunk) => {
      if (!Buffer.isBuffer(chunk)) {
        rejectOnce(new Error("subprocess returned non-byte output"));
        return;
      }
      outputBytes += chunk.byteLength;
      if (outputBytes > outputLimit) {
        rejectOnce(new Error("subprocess exceeded its bounded output limit"));
        return;
      }
      collection.push(chunk);
    };
    child.stdout.on("data", capture(stdout));
    child.stderr.on("data", capture(stderr));
    const timer = setTimeout(() => {
      rejectOnce(new Error("subprocess exceeded its bounded deadline"));
    }, timeoutMs);
    timer.unref();

    child.once("error", (error) => {
      failure ??= error;
    });
    child.once("close", (code, signal) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (failure !== null) {
        rejectPromise(failure);
        return;
      }
      if (code !== 0) {
        const detail = diagnosticOutput(stdout, stderr);
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

function safeRepositoryPath(root, gitPath) {
  if (
    gitPath.length === 0
    || gitPath.includes("\\")
    || gitPath.includes("\0")
    || isAbsolute(gitPath)
  ) {
    fail("git returned an unsafe source path");
  }
  const segments = gitPath.split("/");
  if (
    segments.some(
      (segment) => segment.length === 0 || segment === "." || segment === "..",
    )
  ) {
    fail("git returned an unsafe source path");
  }
  const absolute = resolve(root, ...segments);
  const relation = relative(root, absolute);
  if (
    relation.length === 0
    || relation === ".."
    || relation.startsWith(`..${sep}`)
    || isAbsolute(relation)
  ) {
    fail("git source path escaped the repository");
  }
  return absolute;
}

function excludedSourcePath(gitPath) {
  return SOURCE_EXCLUSIONS.has(gitPath.split("/")[0]);
}

async function copyWorkspaceSource(
  repositoryRoot,
  sourceDirectory,
  environment,
) {
  const listed = await runCommand(
    "git",
    ["ls-files", "-z", "--cached", "--others", "--exclude-standard"],
    {
      cwd: repositoryRoot,
      environment,
      outputLimit: GIT_OUTPUT_LIMIT,
    },
  );
  const paths = listed.stdout.toString("utf8").split("\0");
  for (const gitPath of paths) {
    if (gitPath.length === 0 || excludedSourcePath(gitPath)) continue;
    const sourcePath = safeRepositoryPath(repositoryRoot, gitPath);
    let stats;
    try {
      stats = await lstat(sourcePath);
    } catch (error) {
      if (error?.code === "ENOENT") continue;
      throw error;
    }
    if (stats.isSymbolicLink()) {
      fail("package smoke refuses repository symlinks");
    }
    if (!stats.isFile()) {
      fail("package smoke source entries must be regular files");
    }
    const destinationPath = safeRepositoryPath(sourceDirectory, gitPath);
    await mkdir(dirname(destinationPath), { recursive: true });
    await copyFile(sourcePath, destinationPath, fsConstants.COPYFILE_EXCL);
  }
}

async function copyGitArchiveSource(
  repositoryRoot,
  sourceDirectory,
  temporaryRoot,
  environment,
) {
  const archivePath = join(temporaryRoot, "source.tar");
  await runCommand(
    "git",
    ["archive", "--format=tar", "--output", archivePath, "HEAD"],
    { cwd: repositoryRoot, environment },
  );
  await runCommand(
    "tar",
    ["-xf", archivePath, "-C", sourceDirectory],
    { cwd: repositoryRoot, environment },
  );
  await rm(archivePath, { force: true });
  for (const name of SOURCE_EXCLUSIONS) {
    await rm(join(sourceDirectory, name), { recursive: true, force: true });
  }
}

async function pathExists(path) {
  try {
    await access(path);
    return true;
  } catch (error) {
    if (error?.code === "ENOENT") return false;
    throw error;
  }
}

async function assertPristineSource(sourceDirectory) {
  for (const name of SOURCE_EXCLUSIONS) {
    if (await pathExists(join(sourceDirectory, name))) {
      fail(`pristine source unexpectedly contains excluded root "${name}"`);
    }
  }
  for (const name of ["package.json", "package-lock.json"]) {
    if (!await pathExists(join(sourceDirectory, name))) {
      fail(`pristine source is missing ${name}`);
    }
  }

  const pending = [sourceDirectory];
  let totalFiles = 0;
  let totalBytes = 0;
  while (pending.length > 0) {
    const directory = pending.pop();
    const entries = await readdir(directory, { withFileTypes: true });
    entries.sort((left, right) => (
      left.name < right.name ? -1 : left.name > right.name ? 1 : 0
    ));
    for (const entry of entries) {
      const path = join(directory, entry.name);
      const stats = await lstat(path);
      if (stats.isSymbolicLink()) {
        fail("pristine package source must not contain symlinks");
      }
      if (stats.isDirectory()) {
        pending.push(path);
        continue;
      }
      if (
        !stats.isFile()
        || !Number.isSafeInteger(stats.size)
        || stats.size < 0
        || stats.size > SOURCE_FILE_BYTE_LIMIT
      ) {
        fail("pristine package source contains an invalid or oversized file");
      }
      totalFiles += 1;
      totalBytes += stats.size;
      if (
        totalFiles > SOURCE_FILE_LIMIT
        || !Number.isSafeInteger(totalBytes)
        || totalBytes > SOURCE_TOTAL_BYTE_LIMIT
      ) {
        fail("pristine package source exceeds its bounded size");
      }
    }
  }
}

function parseJson(bytes, label) {
  try {
    return JSON.parse(bytes.toString("utf8"));
  } catch {
    fail(`${label} is not valid JSON`);
  }
}

function parsePackResult(stdout) {
  const parsed = parseJson(stdout, "npm pack output");
  if (!Array.isArray(parsed) || parsed.length !== 1) {
    fail("npm pack did not report exactly one tarball");
  }
  const result = parsed[0];
  if (result === null || typeof result !== "object" || Array.isArray(result)) {
    fail("npm pack returned an invalid result");
  }
  if (
    typeof result.filename !== "string"
    || basename(result.filename) !== result.filename
    || !Array.isArray(result.files)
  ) {
    fail("npm pack returned unsafe tarball metadata");
  }
  return result;
}

function sorted(values) {
  return [...values].sort((left, right) => (
    left < right ? -1 : left > right ? 1 : 0
  ));
}

function safeTarPath(path) {
  if (
    typeof path !== "string"
    || path.length === 0
    || path.includes("\\")
    || path.includes("\0")
    || isAbsolute(path)
  ) {
    return false;
  }
  const segments = path.split("/");
  return segments.every(
    (segment) => segment.length > 0 && segment !== "." && segment !== "..",
  );
}

async function validateTarball(packResult, tarballPath, environment, cwd) {
  const stats = await lstat(tarballPath);
  if (
    !stats.isFile()
    || !Number.isSafeInteger(stats.size)
    || stats.size < 1
    || stats.size > TARBALL_BYTE_LIMIT
  ) {
    fail("npm pack produced an invalid or oversized tarball");
  }
  const tarball = await readFile(tarballPath);
  if (tarball.byteLength !== stats.size) {
    fail("tarball size drifted while being validated");
  }
  const integrity = `sha512-${
    createHash("sha512").update(tarball).digest("base64")
  }`;
  if (packResult.integrity !== integrity) {
    fail("npm pack integrity does not match the exact tarball");
  }

  const filePaths = [];
  for (const file of packResult.files) {
    if (
      file === null
      || typeof file !== "object"
      || Array.isArray(file)
      || !safeTarPath(file.path)
    ) {
      fail("npm pack reported an unsafe package path");
    }
    filePaths.push(file.path);
  }
  const uniquePaths = new Set(filePaths);
  if (uniquePaths.size !== filePaths.length) {
    fail("npm pack reported duplicate package paths");
  }
  for (const required of REQUIRED_PACKAGE_FILES) {
    if (!uniquePaths.has(required)) {
      fail(`packed tarball is missing ${required}`);
    }
  }
  for (const path of uniquePaths) {
    const root = path.split("/")[0];
    if (!ALLOWED_PACKAGE_ROOTS.has(root)) {
      fail(`packed tarball contains unexpected path ${path}`);
    }
    if (
      root === "dist"
      && !/\.(?:d\.ts|js|js\.map)$/.test(path)
    ) {
      fail(`packed dist contains unexpected path ${path}`);
    }
  }

  const listing = await runCommand(
    "tar",
    ["-tzf", tarballPath],
    { cwd, environment },
  );
  const archivePaths = listing.stdout
    .toString("utf8")
    .split(/\r?\n/u)
    .filter((path) => path.length > 0 && !path.endsWith("/"));
  const expectedArchivePaths = filePaths.map((path) => `package/${path}`);
  if (
    JSON.stringify(sorted(archivePaths))
    !== JSON.stringify(sorted(expectedArchivePaths))
  ) {
    fail("tar archive entries do not match npm pack metadata");
  }
}

async function validateInstalledPackage(
  consumerDirectory,
  version,
  environment,
  typescriptCliPath,
  nodeTypeRootsPath,
) {
  const installedRoot = join(
    consumerDirectory,
    "node_modules",
    "@rachittshah",
    "tasc",
  );
  const installedMetadata = parseJson(
    await readFile(join(installedRoot, "package.json")),
    "installed package metadata",
  );
  if (
    installedMetadata.name !== PACKAGE_NAME
    || installedMetadata.version !== version
    || installedMetadata.private === true
    || installedMetadata.publishConfig?.access !== "public"
    || installedMetadata.bin?.tasc !== "./dist/cli.js"
    || installedMetadata.exports?.["."]?.import !== "./dist/index.js"
    || installedMetadata.exports?.["."]?.types !== "./dist/index.d.ts"
    || installedMetadata.exports?.["./runtime"]?.import
      !== "./dist/runtime/index.js"
    || installedMetadata.exports?.["./runtime"]?.types
      !== "./dist/runtime/index.d.ts"
  ) {
    fail("installed package metadata is not the deliberate public surface");
  }

  const importCheck = [
    `const value = await import(${JSON.stringify(PACKAGE_NAME)});`,
    `const runtime = await import(${
      JSON.stringify(`${PACKAGE_NAME}/runtime`)
    });`,
    "if (typeof value.parseInferenceSpec !== 'function') {",
    "  throw new Error('root export is unavailable');",
    "}",
    "for (const name of ['buildShadowRunPlan', 'parseShadowRunPlan', 'verifyTraceDispatchAuthorization']) {",
    "  if (typeof value[name] !== 'function') {",
    "    throw new Error(`root control-plane export ${name} is unavailable`);",
    "  }",
    "}",
    "for (const name of ['invokeRuntime', 'runShadowCollection']) {",
    "  if (typeof runtime[name] !== 'function') {",
    "    throw new Error(`runtime effect export ${name} is unavailable`);",
    "  }",
    "}",
    "if ('invokeRuntime' in value || 'runShadowCollection' in value) {",
    "  throw new Error('runtime effects leaked through the root export');",
    "}",
    "process.stdout.write('import-ok\\n');",
  ].join("\n");
  const imported = await runCommand(
    process.execPath,
    ["--input-type=module", "--eval", importCheck],
    { cwd: consumerDirectory, environment },
  );
  if (imported.stdout.toString("utf8") !== "import-ok\n") {
    fail("consumer import returned unexpected output");
  }

  const typeConsumerPath = join(consumerDirectory, "consumer.ts");
  await writeFile(
    typeConsumerPath,
    [
      `import {`,
      `  buildShadowRunPlan,`,
      `  parseShadowRunPlan,`,
      `  verifyTraceDispatchAuthorization,`,
      `  type BuildShadowRunPlanInput,`,
      `  type ShadowRunPlan,`,
      `} from ${JSON.stringify(PACKAGE_NAME)};`,
      `import {`,
      `  runShadowCollection,`,
      `  type CollectorAttestationSigner,`,
      `  type DispatchIntentSigner,`,
      `  type ShadowRunInput,`,
      `  type ShadowRunResult,`,
      `} from ${JSON.stringify(`${PACKAGE_NAME}/runtime`)};`,
      `void buildShadowRunPlan;`,
      `void parseShadowRunPlan;`,
      `void verifyTraceDispatchAuthorization;`,
      `void runShadowCollection;`,
      `type InstalledSurface = [`,
      `  BuildShadowRunPlanInput,`,
      `  ShadowRunPlan,`,
      `  CollectorAttestationSigner,`,
      `  DispatchIntentSigner,`,
      `  ShadowRunInput,`,
      `  ShadowRunResult,`,
      `];`,
      `const installedSurfaceCount: InstalledSurface["length"] = 6;`,
      `void installedSurfaceCount;`,
      ``,
    ].join("\n"),
    { encoding: "utf8", flag: "wx", mode: 0o600 },
  );
  await runCommand(
    process.execPath,
    [
      typescriptCliPath,
      "--noEmit",
      "--strict",
      "--target",
      "ES2022",
      "--module",
      "NodeNext",
      "--moduleResolution",
      "NodeNext",
      "--types",
      "node",
      "--typeRoots",
      nodeTypeRootsPath,
      typeConsumerPath,
    ],
    { cwd: consumerDirectory, environment },
  );

  const executable = join(
    consumerDirectory,
    "node_modules",
    ".bin",
    binExecutable,
  );
  const help = await runCommand(
    executable,
    ["--help"],
    { cwd: consumerDirectory, environment },
  );
  const helpText = help.stdout.toString("utf8");
  if (
    !helpText.startsWith("Usage:\n")
    || !helpText.includes("  tasc --help\n")
    || help.stderr.byteLength !== 0
  ) {
    fail("installed tasc --help output is invalid");
  }
  const reportedVersion = await runCommand(
    executable,
    ["--version"],
    { cwd: consumerDirectory, environment },
  );
  if (
    reportedVersion.stdout.toString("utf8") !== `${version}\n`
    || reportedVersion.stderr.byteLength !== 0
  ) {
    fail("installed tasc --version output is invalid");
  }
}

async function main() {
  const options = parseArguments(process.argv.slice(2));
  const temporaryRoot = await mkdtemp(join(tmpdir(), "tasc-package-smoke-"));
  const sourceDirectory = join(temporaryRoot, "source");
  const packDirectory = join(temporaryRoot, "packed");
  const consumerDirectory = join(temporaryRoot, "consumer");
  const configDirectory = join(temporaryRoot, "config");
  const cacheDirectory = join(temporaryRoot, "npm-cache");
  try {
    await Promise.all([
      mkdir(sourceDirectory),
      mkdir(packDirectory),
      mkdir(consumerDirectory),
      mkdir(configDirectory),
      mkdir(cacheDirectory),
    ]);
    await writeFile(join(configDirectory, ".npmrc"), "", {
      encoding: "utf8",
      flag: "wx",
      mode: 0o600,
    });
    const environment = safeEnvironment(configDirectory, cacheDirectory);
    const rootResult = await runCommand(
      "git",
      ["rev-parse", "--show-toplevel"],
      {
        cwd: process.cwd(),
        environment,
      },
    );
    const repositoryRoot = rootResult.stdout.toString("utf8").trim();
    if (
      repositoryRoot.length === 0
      || !isAbsolute(repositoryRoot)
      || resolve(repositoryRoot) !== repositoryRoot
    ) {
      fail("git returned an unsafe repository root");
    }

    if (options.gitArchive) {
      await copyGitArchiveSource(
        repositoryRoot,
        sourceDirectory,
        temporaryRoot,
        environment,
      );
    } else {
      await copyWorkspaceSource(
        repositoryRoot,
        sourceDirectory,
        environment,
      );
    }
    await assertPristineSource(sourceDirectory);

    await runCommand(
      npmExecutable,
      ["ci", "--no-audit", "--no-fund"],
      {
        cwd: sourceDirectory,
        environment,
        timeoutMs: INSTALL_TIMEOUT_MS,
      },
    );
    if (await pathExists(join(sourceDirectory, "dist"))) {
      fail("npm ci unexpectedly built dist before prepack");
    }

    const packed = await runCommand(
      npmExecutable,
      ["pack", "--json", "--pack-destination", packDirectory],
      {
        cwd: sourceDirectory,
        environment,
        timeoutMs: PACK_TIMEOUT_MS,
      },
    );
    const packResult = parsePackResult(packed.stdout);
    const tarballPath = resolve(packDirectory, packResult.filename);
    if (dirname(tarballPath) !== packDirectory) {
      fail("npm pack returned a tarball outside the pack directory");
    }
    if (!await pathExists(join(sourceDirectory, "dist"))) {
      fail("prepack did not build dist from pristine source");
    }
    await validateTarball(
      packResult,
      tarballPath,
      environment,
      sourceDirectory,
    );

    const sourceMetadata = parseJson(
      await readFile(join(sourceDirectory, "package.json")),
      "source package metadata",
    );
    if (
      sourceMetadata.name !== PACKAGE_NAME
      || typeof sourceMetadata.version !== "string"
      || sourceMetadata.version.length === 0
    ) {
      fail("source package identity is invalid");
    }
    await writeFile(
      join(consumerDirectory, "package.json"),
      `${JSON.stringify({
        name: "tasc-package-smoke-consumer",
        version: "1.0.0",
        private: true,
        type: "module",
      }, null, 2)}\n`,
      { encoding: "utf8", flag: "wx", mode: 0o600 },
    );
    await runCommand(
      npmExecutable,
      [
        "install",
        "--ignore-scripts",
        "--no-audit",
        "--no-fund",
        "--package-lock=false",
        "--save-exact",
        tarballPath,
      ],
      {
        cwd: consumerDirectory,
        environment,
        timeoutMs: INSTALL_TIMEOUT_MS,
      },
    );
    await validateInstalledPackage(
      consumerDirectory,
      sourceMetadata.version,
      environment,
      join(sourceDirectory, "node_modules", "typescript", "bin", "tsc"),
      join(sourceDirectory, "node_modules", "@types"),
    );

    process.stdout.write(
      `package smoke passed (${options.gitArchive ? "git archive" : "workspace"}, `
      + `${packResult.filename}, ${packResult.files.length} files)\n`,
    );
  } finally {
    await rm(temporaryRoot, { recursive: true, force: true });
  }
}

main().catch((error) => {
  const message = error instanceof Error
    ? error.message
    : "package smoke failed unexpectedly";
  process.stderr.write(`package smoke failed: ${message}\n`);
  process.exitCode = 1;
});
