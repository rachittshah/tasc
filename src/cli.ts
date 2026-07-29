#!/usr/bin/env node
import { createReadStream, realpathSync } from "node:fs";
import { createRequire } from "node:module";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  BoundedInputError,
  readBoundedJson,
  type BoundedJsonLimits,
} from "./bounded-input.js";
import {
  CLI_USAGE,
  CliArgumentError,
  parseCliArguments,
  type LegacyConfirmCommand,
  type LegacyNominateCommand,
  type ParsedCliCommand,
} from "./cli-args.js";
import {
  CliInputError,
  CliOutputError,
  CliRuntimeError,
  executeCliV2,
  type CliV2ExecutionContext,
} from "./cli-v2.js";
import { canonicalJson } from "./determinism.js";
import {
  confirmNomination,
  nominatePolicy,
  type AttestationOptions,
  type NominationArtifact,
} from "./evaluate.js";
import {
  writeConfirmationArtifacts,
  writeDevelopmentArtifacts,
} from "./report.js";
import {
  assertMeasurementMatrix,
  parseInferenceSpec,
  parseMeasurementSet,
  type Split,
} from "./schema.js";

const packageMetadata = createRequire(import.meta.url)("../package.json") as {
  readonly version: string;
};
const CLI_VERSION = packageMetadata.version;

type LegacyJsonInputLabel = "spec" | "measurement" | "nomination";

class LegacyJsonInputError extends Error {
  readonly input: LegacyJsonInputLabel;
  readonly detail: string;

  constructor(input: LegacyJsonInputLabel, detail: string) {
    super("Legacy JSON input validation failed.");
    this.name = "LegacyJsonInputError";
    this.input = input;
    this.detail = detail;
  }
}

class LegacyOutputError extends Error {
  constructor() {
    super("Legacy artifact publication failed.");
    this.name = "LegacyOutputError";
  }
}

const LEGACY_JSON_LIMITS: BoundedJsonLimits = Object.freeze({
  maxBytes: 4 * 1024 * 1024,
  maxDepth: 32,
  maxObjectKeys: 65_536,
  maxArrayItems: 65_536,
  maxTokens: 1_000_000,
  maxDecodedStringLength: 65_536,
  maxNumericTokenLength: 128,
  maxDiagnosticSnippetLength: 0,
});

async function readJson(
  path: string,
  label: LegacyJsonInputLabel,
): Promise<unknown> {
  try {
    return await readBoundedJson(
      createReadStream(path),
      LEGACY_JSON_LIMITS,
    );
  } catch (error) {
    const code = error instanceof BoundedInputError
      ? error.code
      : "input-failure";
    throw new LegacyJsonInputError(label, code);
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function assertString(value: unknown, field: string): asserts value is string {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`invalid nomination: "${field}" must be a non-empty string`);
  }
}

function assertStringArray(value: unknown, field: string): asserts value is string[] {
  if (!Array.isArray(value) || value.some((entry) => typeof entry !== "string")) {
    throw new Error(`invalid nomination: "${field}" must be an array of strings`);
  }
}

function parseNomination(input: unknown): NominationArtifact {
  if (!isRecord(input)) throw new Error("invalid nomination: expected a JSON object");
  if (input.version !== "tasc-nomination-v1") {
    throw new Error('invalid nomination: "version" must be "tasc-nomination-v1"');
  }
  for (const field of [
    "specDigest",
    "developmentDatasetDigest",
    "policyDigest",
    "decisionDigest",
    "selfDigest",
  ]) {
    assertString(input[field], field);
  }
  if (typeof input.developmentSynthetic !== "boolean") {
    throw new Error('invalid nomination: "developmentSynthetic" must be a boolean');
  }
  assertStringArray(input.developmentGroupIds, "developmentGroupIds");
  if (!isRecord(input.evaluator)) throw new Error('invalid nomination: "evaluator" must be an object');
  assertString(input.evaluator.id, "evaluator.id");
  assertString(input.evaluator.version, "evaluator.version");
  if (!["human", "deterministic", "llm-judge"].includes(String(input.evaluator.kind))) {
    throw new Error('invalid nomination: "evaluator.kind" is unsupported');
  }
  if (typeof input.evaluator.validated !== "boolean") {
    throw new Error('invalid nomination: "evaluator.validated" must be a boolean');
  }
  if (!isRecord(input.policy)) throw new Error('invalid nomination: "policy" must be an object');
  if (input.policy.version !== "tasc-policy-v1") {
    throw new Error('invalid nomination: "policy.version" must be "tasc-policy-v1"');
  }
  assertString(input.policy.id, "policy.id");
  assertString(input.policy.primaryProfileId, "policy.primaryProfileId");
  assertString(input.policy.expertProfileId, "policy.expertProfileId");
  assertStringArray(input.policy.criticalSlices, "policy.criticalSlices");
  if (!["expert-only", "fast-only", "cascade"].includes(String(input.policy.kind))) {
    throw new Error('invalid nomination: "policy.kind" is unsupported');
  }
  if (
    input.policy.kind === "cascade"
    && (
      typeof input.policy.confidenceThreshold !== "number"
      || typeof input.policy.inputTokenThreshold !== "number"
    )
  ) {
    throw new Error("invalid nomination: cascade policy thresholds must be numbers");
  }
  if (!isRecord(input.candidateMetrics) || !isRecord(input.championMetrics)) {
    throw new Error("invalid nomination: candidateMetrics and championMetrics must be objects");
  }
  if (!Array.isArray(input.gates)) throw new Error('invalid nomination: "gates" must be an array');
  if (input.attestation !== undefined && !isRecord(input.attestation)) {
    throw new Error('invalid nomination: "attestation" must be an object when present');
  }
  return input as unknown as NominationArtifact;
}

function attestationOptions(
  environment: Readonly<NodeJS.ProcessEnv>,
): AttestationOptions {
  const attestationKey = environment.TASC_ATTESTATION_KEY;
  return attestationKey === undefined ? {} : { attestationKey };
}

type LegacyCommand = LegacyNominateCommand | LegacyConfirmCommand;

async function parsedInputs(args: LegacyCommand, split: Split) {
  const [specInput, measurementsInput] = await Promise.all([
    readJson(args.spec, "spec"),
    readJson(args.measurements, "measurement"),
  ]);
  const spec = parseInferenceSpec(specInput);
  const measurements = parseMeasurementSet(measurementsInput, split);
  assertMeasurementMatrix(spec, measurements);
  return { spec, measurements };
}

export interface CliIo {
  readonly stdout: { write(value: string): unknown };
  readonly stderr: { write(value: string): unknown };
}

export type CliExitCode = 0 | 1 | 2 | 3 | 4;

async function executeLegacy(
  command: LegacyCommand,
  environment: Readonly<NodeJS.ProcessEnv>,
  io: CliIo,
): Promise<void> {
  if (command.kind === "legacy-nominate") {
    const { spec, measurements } = await parsedInputs(command, "dev");
    const result = nominatePolicy(
      spec,
      measurements,
      attestationOptions(environment),
    );
    try {
      await writeDevelopmentArtifacts(command.out, result, {
        synthetic: measurements.dataset.synthetic,
        spec,
        measurements,
      });
    } catch {
      throw new LegacyOutputError();
    }
    io.stdout.write(`${result.status} — artifacts written\n`);
    return;
  }

  const [{ spec, measurements }, nominationInput] = await Promise.all([
    parsedInputs(command, "holdout"),
    readJson(command.nomination, "nomination"),
  ]);
  const nomination = parseNomination(nominationInput);
  const result = confirmNomination(
    spec,
    measurements,
    nomination,
    attestationOptions(environment),
  );
  try {
    await writeConfirmationArtifacts(command.out, result, {
      synthetic:
        measurements.dataset.synthetic || nomination.developmentSynthetic,
    });
  } catch {
    throw new LegacyOutputError();
  }
  io.stdout.write(`${result.status} — artifacts written\n`);
}

function writeJsonLine(
  destination: { write(value: string): unknown },
  value: unknown,
): void {
  destination.write(`${canonicalJson(value)}\n`);
}

function writeUsageDiagnostic(io: CliIo): void {
  writeJsonLine(io.stderr, {
    version: "tasc-cli-diagnostic-v1",
    code: "USAGE",
    message: "Invalid command usage.",
  });
}

function isLegacyCommand(
  command: ParsedCliCommand | undefined,
): command is LegacyCommand {
  return command?.kind === "legacy-nominate"
    || command?.kind === "legacy-confirm";
}

function legacyFailure(
  error: unknown,
): Readonly<{
  exitCode: CliExitCode;
  code: string;
  message: string;
  input?: LegacyJsonInputLabel;
  detail?: string;
}> {
  if (error instanceof LegacyJsonInputError) {
    return Object.freeze({
      exitCode: 3,
      code: "INPUT_INVALID",
      message: `Invalid ${error.input} JSON (${error.detail}).`,
      input: error.input,
      detail: error.detail,
    });
  }
  if (error instanceof LegacyOutputError) {
    return Object.freeze({
      exitCode: 4,
      code: "OUTPUT_FAILURE",
      message: "Artifact publication failed; a fresh output directory is required.",
    });
  }

  const internalMessage = error instanceof Error ? error.message : "";
  if (internalMessage.includes("attestation mismatch")) {
    return Object.freeze({
      exitCode: 3,
      code: "NOMINATION_INVALID",
      message: "Nomination attestation mismatch.",
    });
  }
  if (
    internalMessage.includes("self-digest")
    || internalMessage.includes("artifact was edited")
  ) {
    return Object.freeze({
      exitCode: 3,
      code: "NOMINATION_INVALID",
      message: "Nomination self-digest mismatch; artifact may have been edited.",
    });
  }
  if (internalMessage.startsWith("invalid nomination")) {
    return Object.freeze({
      exitCode: 3,
      code: "NOMINATION_INVALID",
      message: "Invalid nomination artifact.",
    });
  }
  return Object.freeze({
    exitCode: 3,
    code: "LEGACY_INPUT_INVALID",
    message: "Legacy evaluation input was rejected.",
  });
}

/**
 * Execute one CLI invocation without importing ambient process state.
 *
 * V2 runtime commands receive only a named, descriptor-safe secret lookup;
 * pure argument and file parsers never import ambient process state.
 */
export async function runCli(
  argv: readonly string[],
  environment: Readonly<NodeJS.ProcessEnv>,
  io: CliIo,
  signal?: AbortSignal,
): Promise<CliExitCode> {
  let command: ParsedCliCommand;
  try {
    command = parseCliArguments(argv);
  } catch (error) {
    if (error instanceof CliArgumentError) {
      writeUsageDiagnostic(io);
      return 2;
    }
    writeJsonLine(io.stderr, {
      version: "tasc-cli-diagnostic-v1",
      code: "INTERNAL",
      message: "The command failed unexpectedly.",
    });
    return 1;
  }

  try {
    if (command.kind === "help") {
      io.stdout.write(`${CLI_USAGE}\n`);
      return 0;
    }
    if (command.kind === "version") {
      io.stdout.write(`${CLI_VERSION}\n`);
      return 0;
    }
    if (isLegacyCommand(command)) {
      await executeLegacy(command, environment, io);
      return 0;
    }

    const executionContext: CliV2ExecutionContext = Object.freeze({
      readSecretEnvironmentVariable: (name: string) => {
        try {
          const descriptor = Reflect.getOwnPropertyDescriptor(
            environment,
            name,
          );
          return descriptor !== undefined
              && Object.hasOwn(descriptor, "value")
              && typeof descriptor.value === "string"
            ? descriptor.value
            : undefined;
        } catch {
          return undefined;
        }
      },
      ...(signal === undefined ? {} : { signal }),
    });
    const result = await executeCliV2(command, executionContext);
    writeJsonLine(io.stdout, result);
    return 0;
  } catch (error) {
    if (error instanceof CliInputError) {
      writeJsonLine(io.stderr, {
        version: "tasc-cli-diagnostic-v1",
        code: "INPUT_INVALID",
        message: "Input validation failed.",
        input: error.input,
        detail: error.detail,
        ...(error.line === undefined ? {} : { line: error.line }),
      });
      return 3;
    }
    if (error instanceof CliOutputError) {
      writeJsonLine(io.stderr, {
        version: "tasc-cli-diagnostic-v1",
        code: "OUTPUT_FAILURE",
        message: "Artifact publication failed.",
      });
      return 4;
    }
    if (error instanceof CliRuntimeError) {
      writeJsonLine(io.stderr, {
        version: "tasc-cli-diagnostic-v1",
        code: "RUNTIME_FAILURE",
        message: "Runtime operation failed.",
        operation: error.operation,
        detail: error.detail,
        dispatchState: error.dispatchState,
      });
      return 1;
    }
    if (isLegacyCommand(command)) {
      const failure = legacyFailure(error);
      writeJsonLine(io.stderr, {
        version: "tasc-cli-diagnostic-v1",
        code: failure.code,
        message: failure.message,
        ...(failure.input === undefined ? {} : { input: failure.input }),
        ...(failure.detail === undefined ? {} : { detail: failure.detail }),
      });
      return failure.exitCode;
    }
    writeJsonLine(io.stderr, {
      version: "tasc-cli-diagnostic-v1",
      code: "INTERNAL",
      message: "The command failed unexpectedly.",
    });
    return 1;
  }
}

function isDirectExecution(argvEntry: string | undefined): boolean {
  if (argvEntry === undefined) return false;
  const modulePath = fileURLToPath(import.meta.url);
  try {
    return realpathSync(argvEntry) === realpathSync(modulePath);
  } catch {
    return resolve(argvEntry) === resolve(modulePath);
  }
}

if (isDirectExecution(process.argv[1])) {
  const directArguments = process.argv.slice(2);
  const effectfulRuntimeCommand =
    directArguments[0] === "runtime" || directArguments[0] === "shadow";
  const controller = effectfulRuntimeCommand
    ? new AbortController()
    : undefined;
  const abort = (): void => controller?.abort();
  if (controller !== undefined) {
    process.once("SIGINT", abort);
    process.once("SIGTERM", abort);
  }
  runCli(
    directArguments,
    process.env,
    { stdout: process.stdout, stderr: process.stderr },
    controller?.signal,
  ).then(
    (code) => {
      process.exitCode = code;
    },
    () => {
      process.exitCode = 1;
    },
  ).finally(() => {
    if (controller !== undefined) {
      process.off("SIGINT", abort);
      process.off("SIGTERM", abort);
    }
  });
}
