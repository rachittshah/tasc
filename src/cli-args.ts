export type CliArgumentErrorCode =
  | "missing-command"
  | "unknown-command"
  | "missing-action"
  | "unknown-action"
  | "missing-positional"
  | "unexpected-argument"
  | "unknown-option"
  | "duplicate-option"
  | "missing-option-value"
  | "missing-required-option";

const CLI_ARGUMENT_ERROR_MESSAGES: Readonly<Record<CliArgumentErrorCode, string>> =
  Object.freeze({
    "missing-command": "a command is required",
    "unknown-command": "the command is not supported",
    "missing-action": "a command action is required",
    "unknown-action": "the command action is not supported",
    "missing-positional": "a required path argument is missing",
    "unexpected-argument": "an unexpected argument was provided",
    "unknown-option": "an unsupported option was provided",
    "duplicate-option": "an option was provided more than once",
    "missing-option-value": "an option requires a non-empty value",
    "missing-required-option": "a required option is missing",
  });

/**
 * A constant-safe CLI grammar error.
 *
 * The message never incorporates argv content. Callers may append {@link CLI_USAGE}
 * without risking disclosure of a path, token, or other argument value.
 */
export class CliArgumentError extends Error {
  readonly code: CliArgumentErrorCode;

  constructor(code: CliArgumentErrorCode) {
    super(CLI_ARGUMENT_ERROR_MESSAGES[code]);
    this.name = "CliArgumentError";
    this.code = code;
  }
}

export interface ProtocolValidateCommand {
  readonly kind: "protocol-validate";
  readonly protocol: string;
  readonly workBudget: string;
}

export interface TracesValidateCommand {
  readonly kind: "traces-validate";
  readonly traces: string;
  readonly workBudget: string;
}

export interface EvidenceValidateCommand {
  readonly kind: "evidence-validate";
  readonly evidence: string;
  readonly trust: string;
  readonly context: string;
  readonly workBudget: string;
}

export interface AssessDevelopmentCommand {
  readonly kind: "assess-development";
  readonly protocol: string;
  readonly traces: string;
  readonly evidence: string;
  readonly context: string;
  readonly trust: string;
  readonly workBudget: string;
  readonly out: string;
}

export interface AssessHoldoutCommand {
  readonly kind: "assess-holdout";
  readonly protocol: string;
  readonly traces: string;
  readonly evidence: string;
  readonly context: string;
  readonly nomination: string;
  readonly developmentTraces: string;
  readonly developmentEvidence: string;
  readonly developmentContext: string;
  readonly developmentTrust: string;
  readonly trust: string;
  readonly workBudget: string;
  readonly out: string;
}

export interface AssessWindowCommand {
  readonly kind: "assess-window";
  readonly protocol: string;
  readonly traces: string;
  readonly evidence: string;
  readonly context: string;
  readonly policy: string;
  readonly window: string;
  readonly trust: string;
  readonly workBudget: string;
  readonly out: string;
}

export interface ExperimentNextCommand {
  readonly kind: "experiment-next";
  readonly assessment: string;
  readonly history: string;
  readonly budget: string;
  readonly out: string;
}

export interface LegacyNominateCommand {
  readonly kind: "legacy-nominate";
  readonly spec: string;
  readonly measurements: string;
  readonly out: string;
}

export interface LegacyConfirmCommand {
  readonly kind: "legacy-confirm";
  readonly spec: string;
  readonly measurements: string;
  readonly nomination: string;
  readonly out: string;
}

export interface HelpCommand {
  readonly kind: "help";
}

export interface VersionCommand {
  readonly kind: "version";
}

export type ParsedCliCommand =
  | ProtocolValidateCommand
  | TracesValidateCommand
  | EvidenceValidateCommand
  | AssessDevelopmentCommand
  | AssessHoldoutCommand
  | AssessWindowCommand
  | ExperimentNextCommand
  | LegacyNominateCommand
  | LegacyConfirmCommand
  | HelpCommand
  | VersionCommand;

export type CliExecutableCommandKind = Exclude<
  ParsedCliCommand["kind"],
  "help" | "version"
>;

export interface CliCommandMetadata {
  readonly kind: CliExecutableCommandKind;
  readonly usage: string;
  readonly requiredOptions: readonly string[];
}

function commandMetadata(
  kind: CliExecutableCommandKind,
  usage: string,
  requiredOptions: readonly string[] = [],
): CliCommandMetadata {
  return Object.freeze({
    kind,
    usage,
    requiredOptions: Object.freeze([...requiredOptions]),
  });
}

const DEVELOPMENT_OPTIONS = Object.freeze([
  "--protocol",
  "--traces",
  "--evidence",
  "--context",
  "--trust",
  "--work-budget",
  "--out",
]);

const HOLDOUT_OPTIONS = Object.freeze([
  "--protocol",
  "--traces",
  "--evidence",
  "--context",
  "--nomination",
  "--development-traces",
  "--development-evidence",
  "--development-context",
  "--development-trust",
  "--trust",
  "--work-budget",
  "--out",
]);

const WINDOW_OPTIONS = Object.freeze([
  "--protocol",
  "--traces",
  "--evidence",
  "--context",
  "--policy",
  "--window",
  "--trust",
  "--work-budget",
  "--out",
]);

const EXPERIMENT_OPTIONS = Object.freeze([
  "--assessment",
  "--history",
  "--budget",
  "--out",
]);

const PROTOCOL_VALIDATION_OPTIONS = Object.freeze([
  "--work-budget",
]);

const TRACE_VALIDATION_OPTIONS = Object.freeze([
  "--work-budget",
]);

const EVIDENCE_VALIDATION_OPTIONS = Object.freeze([
  "--trust",
  "--context",
  "--work-budget",
]);

const LEGACY_NOMINATE_OPTIONS = Object.freeze([
  "--spec",
  "--measurements",
  "--out",
]);

const LEGACY_CONFIRM_OPTIONS = Object.freeze([
  "--spec",
  "--measurements",
  "--nomination",
  "--out",
]);

export const CLI_COMMANDS: readonly CliCommandMetadata[] = Object.freeze([
  commandMetadata(
    "protocol-validate",
    "tasc protocol validate <protocol.json> --work-budget <path>",
    PROTOCOL_VALIDATION_OPTIONS,
  ),
  commandMetadata(
    "traces-validate",
    "tasc traces validate <traces.ndjson> --work-budget <path>",
    TRACE_VALIDATION_OPTIONS,
  ),
  commandMetadata(
    "evidence-validate",
    "tasc evidence validate <evaluator-evidence.ndjson> --trust <path> --context <path> --work-budget <path>",
    EVIDENCE_VALIDATION_OPTIONS,
  ),
  commandMetadata(
    "assess-development",
    "tasc assess development --protocol <path> --traces <path> --evidence <path> --context <path> --trust <path> --work-budget <path> --out <directory>",
    DEVELOPMENT_OPTIONS,
  ),
  commandMetadata(
    "assess-holdout",
    "tasc assess holdout --protocol <path> --traces <path> --evidence <path> --context <path> --nomination <path> --development-traces <path> --development-evidence <path> --development-context <path> --development-trust <path> --trust <path> --work-budget <path> --out <directory>",
    HOLDOUT_OPTIONS,
  ),
  commandMetadata(
    "assess-window",
    "tasc assess window --protocol <path> --traces <path> --evidence <path> --context <path> --policy <path> --window <path> --trust <path> --work-budget <path> --out <directory>",
    WINDOW_OPTIONS,
  ),
  commandMetadata(
    "experiment-next",
    "tasc experiment next --assessment <path> --history <path> --budget <path> --out <directory>",
    EXPERIMENT_OPTIONS,
  ),
  commandMetadata(
    "legacy-nominate",
    "tasc nominate --spec <path> --measurements <path> --out <directory>",
    LEGACY_NOMINATE_OPTIONS,
  ),
  commandMetadata(
    "legacy-confirm",
    "tasc confirm --spec <path> --measurements <path> --nomination <path> --out <directory>",
    LEGACY_CONFIRM_OPTIONS,
  ),
]);

export const CLI_USAGE = [
  "Usage:",
  ...CLI_COMMANDS.map(({ usage }) => `  ${usage}`),
  "  tasc --help",
  "  tasc --version",
  "",
  "Exit codes:",
  "  0 completed decision or validation (including HOLD/STALE)",
  "  1 unexpected internal failure",
  "  2 invalid command usage",
  "  3 unreadable, malformed, untrusted, or context-mismatched input",
  "  4 output freshness, custody, or publication failure",
].join("\n");

type ParsedOptions = ReadonlyMap<string, string>;

function fail(code: CliArgumentErrorCode): never {
  throw new CliArgumentError(code);
}

function isOptionToken(value: string): boolean {
  return value.startsWith("-");
}

function parseOptions(
  argv: readonly string[],
  startIndex: number,
  requiredOptions: readonly string[],
): ParsedOptions {
  const allowed = new Set(requiredOptions);
  const values = new Map<string, string>();

  for (let index = startIndex; index < argv.length;) {
    const option = argv[index];
    if (option === undefined) fail("unexpected-argument");
    if (!isOptionToken(option)) fail("unexpected-argument");
    if (!option.startsWith("--") || option.includes("=") || !allowed.has(option)) {
      fail("unknown-option");
    }
    if (values.has(option)) fail("duplicate-option");

    const value = argv[index + 1];
    if (value === undefined || value.length === 0 || isOptionToken(value)) {
      fail("missing-option-value");
    }
    values.set(option, value);
    index += 2;
  }

  for (const option of requiredOptions) {
    if (!values.has(option)) fail("missing-required-option");
  }
  return values;
}

function requiredOption(options: ParsedOptions, option: string): string {
  const value = options.get(option);
  if (value === undefined) {
    // This is unreachable after parseOptions checks the command's fixed schema.
    throw new Error("CLI option parser invariant violated");
  }
  return value;
}

function parseValidationCommand(
  argv: readonly string[],
  group: "protocol" | "traces" | "evidence",
): ProtocolValidateCommand | TracesValidateCommand | EvidenceValidateCommand {
  const action = argv[1];
  if (action === undefined) fail("missing-action");
  if (action !== "validate") fail("unknown-action");

  const path = argv[2];
  if (path === undefined || path.length === 0) fail("missing-positional");
  if (isOptionToken(path)) fail("unknown-option");

  switch (group) {
    case "protocol": {
      const options = parseOptions(argv, 3, PROTOCOL_VALIDATION_OPTIONS);
      return Object.freeze({
        kind: "protocol-validate",
        protocol: path,
        workBudget: requiredOption(options, "--work-budget"),
      });
    }
    case "traces": {
      const options = parseOptions(argv, 3, TRACE_VALIDATION_OPTIONS);
      return Object.freeze({
        kind: "traces-validate",
        traces: path,
        workBudget: requiredOption(options, "--work-budget"),
      });
    }
    case "evidence": {
      const options = parseOptions(argv, 3, EVIDENCE_VALIDATION_OPTIONS);
      return Object.freeze({
        kind: "evidence-validate",
        evidence: path,
        trust: requiredOption(options, "--trust"),
        context: requiredOption(options, "--context"),
        workBudget: requiredOption(options, "--work-budget"),
      });
    }
  }
}

function parseAssessCommand(argv: readonly string[]): ParsedCliCommand {
  const action = argv[1];
  if (action === undefined) fail("missing-action");

  if (action === "development") {
    const options = parseOptions(argv, 2, DEVELOPMENT_OPTIONS);
    return Object.freeze({
      kind: "assess-development",
      protocol: requiredOption(options, "--protocol"),
      traces: requiredOption(options, "--traces"),
      evidence: requiredOption(options, "--evidence"),
      context: requiredOption(options, "--context"),
      trust: requiredOption(options, "--trust"),
      workBudget: requiredOption(options, "--work-budget"),
      out: requiredOption(options, "--out"),
    });
  }

  if (action === "holdout") {
    const options = parseOptions(argv, 2, HOLDOUT_OPTIONS);
    return Object.freeze({
      kind: "assess-holdout",
      protocol: requiredOption(options, "--protocol"),
      traces: requiredOption(options, "--traces"),
      evidence: requiredOption(options, "--evidence"),
      context: requiredOption(options, "--context"),
      nomination: requiredOption(options, "--nomination"),
      developmentTraces: requiredOption(options, "--development-traces"),
      developmentEvidence: requiredOption(options, "--development-evidence"),
      developmentContext: requiredOption(options, "--development-context"),
      developmentTrust: requiredOption(options, "--development-trust"),
      trust: requiredOption(options, "--trust"),
      workBudget: requiredOption(options, "--work-budget"),
      out: requiredOption(options, "--out"),
    });
  }

  if (action === "window") {
    const options = parseOptions(argv, 2, WINDOW_OPTIONS);
    return Object.freeze({
      kind: "assess-window",
      protocol: requiredOption(options, "--protocol"),
      traces: requiredOption(options, "--traces"),
      evidence: requiredOption(options, "--evidence"),
      context: requiredOption(options, "--context"),
      policy: requiredOption(options, "--policy"),
      window: requiredOption(options, "--window"),
      trust: requiredOption(options, "--trust"),
      workBudget: requiredOption(options, "--work-budget"),
      out: requiredOption(options, "--out"),
    });
  }

  return fail("unknown-action");
}

function parseExperimentCommand(argv: readonly string[]): ExperimentNextCommand {
  const action = argv[1];
  if (action === undefined) fail("missing-action");
  if (action !== "next") fail("unknown-action");
  const options = parseOptions(argv, 2, EXPERIMENT_OPTIONS);
  return Object.freeze({
    kind: "experiment-next",
    assessment: requiredOption(options, "--assessment"),
    history: requiredOption(options, "--history"),
    budget: requiredOption(options, "--budget"),
    out: requiredOption(options, "--out"),
  });
}

function parseLegacyNominateCommand(
  argv: readonly string[],
): LegacyNominateCommand {
  const options = parseOptions(argv, 1, LEGACY_NOMINATE_OPTIONS);
  return Object.freeze({
    kind: "legacy-nominate",
    spec: requiredOption(options, "--spec"),
    measurements: requiredOption(options, "--measurements"),
    out: requiredOption(options, "--out"),
  });
}

function parseLegacyConfirmCommand(
  argv: readonly string[],
): LegacyConfirmCommand {
  const options = parseOptions(argv, 1, LEGACY_CONFIRM_OPTIONS);
  return Object.freeze({
    kind: "legacy-confirm",
    spec: requiredOption(options, "--spec"),
    measurements: requiredOption(options, "--measurements"),
    nomination: requiredOption(options, "--nomination"),
    out: requiredOption(options, "--out"),
  });
}

/**
 * Parse the complete public CLI grammar without reading the filesystem,
 * environment, clock, or network.
 */
export function parseCliArguments(argv: readonly string[]): ParsedCliCommand {
  const command = argv[0];
  if (command === undefined) fail("missing-command");

  if (command === "--help") {
    if (argv.length !== 1) fail("unexpected-argument");
    return Object.freeze({ kind: "help" });
  }
  if (command === "--version") {
    if (argv.length !== 1) fail("unexpected-argument");
    return Object.freeze({ kind: "version" });
  }

  switch (command) {
    case "protocol":
    case "traces":
    case "evidence":
      return parseValidationCommand(argv, command);
    case "assess":
      return parseAssessCommand(argv);
    case "experiment":
      return parseExperimentCommand(argv);
    case "nominate":
      return parseLegacyNominateCommand(argv);
    case "confirm":
      return parseLegacyConfirmCommand(argv);
    default:
      return fail("unknown-command");
  }
}
