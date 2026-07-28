#!/usr/bin/env node
import { createReadStream } from "node:fs";
import {
  BoundedInputError,
  readBoundedJson,
  type BoundedJsonLimits,
} from "./bounded-input.js";
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

type Command = "nominate" | "confirm";

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

interface Arguments {
  command: Command;
  spec: string;
  measurements: string;
  out: string;
  nomination?: string;
}

function usage(): string {
  return [
    "Usage:",
    "  tasc nominate --spec <path> --measurements <path> --out <directory>",
    "  tasc confirm --spec <path> --measurements <path> --nomination <path> --out <directory>",
  ].join("\n");
}

function parseArguments(argv: string[]): Arguments {
  const command = argv[0];
  if (command !== "nominate" && command !== "confirm") {
    throw new Error(`expected command "nominate" or "confirm"\n${usage()}`);
  }
  const allowed = new Set([
    "--spec",
    "--measurements",
    "--out",
    ...(command === "confirm" ? ["--nomination"] : []),
  ]);
  const values = new Map<string, string>();
  for (let index = 1; index < argv.length; index += 2) {
    const flag = argv[index];
    const value = argv[index + 1];
    if (!flag?.startsWith("--") || !allowed.has(flag)) {
      throw new Error(`unknown argument "${flag ?? ""}"\n${usage()}`);
    }
    if (!value || value.startsWith("--")) {
      throw new Error(`argument "${flag}" requires a value\n${usage()}`);
    }
    if (values.has(flag)) {
      throw new Error(`argument "${flag}" was provided more than once`);
    }
    values.set(flag, value);
  }
  const required = [
    "--spec",
    "--measurements",
    "--out",
    ...(command === "confirm" ? ["--nomination"] : []),
  ];
  for (const flag of required) {
    if (!values.has(flag)) throw new Error(`missing required argument "${flag}"\n${usage()}`);
  }
  return {
    command,
    spec: values.get("--spec")!,
    measurements: values.get("--measurements")!,
    out: values.get("--out")!,
    ...(command === "confirm" ? { nomination: values.get("--nomination")! } : {}),
  };
}

async function readJson(path: string, label: string): Promise<unknown> {
  try {
    return await readBoundedJson(
      createReadStream(path),
      LEGACY_JSON_LIMITS,
    );
  } catch (error) {
    const code = error instanceof BoundedInputError
      ? error.code
      : "input-failure";
    throw new Error(`invalid ${label} JSON (${code})`);
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

function attestationOptions(): AttestationOptions {
  const attestationKey = process.env.TASC_ATTESTATION_KEY;
  return attestationKey === undefined ? {} : { attestationKey };
}

async function parsedInputs(args: Arguments, split: Split) {
  const [specInput, measurementsInput] = await Promise.all([
    readJson(args.spec, "spec"),
    readJson(args.measurements, "measurement"),
  ]);
  const spec = parseInferenceSpec(specInput);
  const measurements = parseMeasurementSet(measurementsInput, split);
  assertMeasurementMatrix(spec, measurements);
  return { spec, measurements };
}

async function main(): Promise<void> {
  const args = parseArguments(process.argv.slice(2));
  if (args.command === "nominate") {
    const { spec, measurements } = await parsedInputs(args, "dev");
    const result = nominatePolicy(spec, measurements, attestationOptions());
    await writeDevelopmentArtifacts(args.out, result, {
      synthetic: measurements.dataset.synthetic,
      spec,
      measurements,
    });
    process.stdout.write(`${result.status} — artifacts: ${args.out}\n`);
    return;
  }

  const [{ spec, measurements }, nominationInput] = await Promise.all([
    parsedInputs(args, "holdout"),
    readJson(args.nomination!, "nomination"),
  ]);
  const nomination = parseNomination(nominationInput);
  const result = confirmNomination(spec, measurements, nomination, attestationOptions());
  await writeConfirmationArtifacts(args.out, result, {
    synthetic: measurements.dataset.synthetic || nomination.developmentSynthetic,
  });
  process.stdout.write(`${result.status} — artifacts: ${args.out}\n`);
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`TASC error: ${message}\n`);
  process.exitCode = 1;
});
