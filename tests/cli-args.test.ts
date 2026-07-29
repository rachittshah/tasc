import { describe, expect, it } from "vitest";
import {
  CLI_COMMANDS,
  CLI_USAGE,
  CliArgumentError,
  parseCliArguments,
} from "../src/cli-args.js";

describe("parseCliArguments", () => {
  it.each([
    {
      argv: [
        "protocol",
        "validate",
        "protocol.json",
        "--work-budget",
        "work-budget.json",
      ],
      expected: {
        kind: "protocol-validate",
        protocol: "protocol.json",
        workBudget: "work-budget.json",
      },
    },
    {
      argv: [
        "traces",
        "validate",
        "traces.ndjson",
        "--work-budget",
        "work-budget.json",
      ],
      expected: {
        kind: "traces-validate",
        traces: "traces.ndjson",
        workBudget: "work-budget.json",
      },
    },
    {
      argv: [
        "evidence",
        "validate",
        "evidence.ndjson",
        "--trust",
        "trust.json",
        "--context",
        "context.json",
        "--work-budget",
        "work-budget.json",
      ],
      expected: {
        kind: "evidence-validate",
        evidence: "evidence.ndjson",
        trust: "trust.json",
        context: "context.json",
        workBudget: "work-budget.json",
      },
    },
    {
      argv: [
        "assess",
        "development",
        "--protocol",
        "protocol.json",
        "--traces",
        "traces.ndjson",
        "--evidence",
        "evidence.ndjson",
        "--context",
        "context.json",
        "--trust",
        "trust.json",
        "--work-budget",
        "work-budget.json",
        "--out",
        "assessment",
      ],
      expected: {
        kind: "assess-development",
        protocol: "protocol.json",
        traces: "traces.ndjson",
        evidence: "evidence.ndjson",
        context: "context.json",
        trust: "trust.json",
        workBudget: "work-budget.json",
        out: "assessment",
      },
    },
    {
      argv: [
        "assess",
        "holdout",
        "--protocol",
        "protocol.json",
        "--traces",
        "holdout-traces.ndjson",
        "--evidence",
        "holdout-evidence.ndjson",
        "--context",
        "holdout-context.json",
        "--nomination",
        "nomination.json",
        "--development-traces",
        "development-traces.ndjson",
        "--development-evidence",
        "development-evidence.ndjson",
        "--development-context",
        "development-context.json",
        "--development-trust",
        "development-trust.json",
        "--trust",
        "trust.json",
        "--work-budget",
        "work-budget.json",
        "--out",
        "assessment",
      ],
      expected: {
        kind: "assess-holdout",
        protocol: "protocol.json",
        traces: "holdout-traces.ndjson",
        evidence: "holdout-evidence.ndjson",
        context: "holdout-context.json",
        nomination: "nomination.json",
        developmentTraces: "development-traces.ndjson",
        developmentEvidence: "development-evidence.ndjson",
        developmentContext: "development-context.json",
        developmentTrust: "development-trust.json",
        trust: "trust.json",
        workBudget: "work-budget.json",
        out: "assessment",
      },
    },
    {
      argv: [
        "assess",
        "window",
        "--protocol",
        "protocol.json",
        "--traces",
        "window-traces.ndjson",
        "--evidence",
        "window-evidence.ndjson",
        "--context",
        "window-context.json",
        "--policy",
        "policy.json",
        "--window",
        "window.json",
        "--trust",
        "trust.json",
        "--work-budget",
        "work-budget.json",
        "--out",
        "assessment",
      ],
      expected: {
        kind: "assess-window",
        protocol: "protocol.json",
        traces: "window-traces.ndjson",
        evidence: "window-evidence.ndjson",
        context: "window-context.json",
        policy: "policy.json",
        window: "window.json",
        trust: "trust.json",
        workBudget: "work-budget.json",
        out: "assessment",
      },
    },
    {
      argv: [
        "experiment",
        "next",
        "--history",
        "history.json",
        "--out",
        "experiment",
        "--assessment",
        "assessment.json",
        "--budget",
        "budget.json",
      ],
      expected: {
        kind: "experiment-next",
        assessment: "assessment.json",
        history: "history.json",
        budget: "budget.json",
        out: "experiment",
      },
    },
    {
      argv: [
        "runtime",
        "probe",
        "--runtime",
        "runtime.json",
        "--endpoint",
        "endpoint.json",
        "--trust",
        "trust.json",
        "--capability",
        "completions",
        "--effect",
        "inference-canary",
        "--deadline-ms",
        "1500",
      ],
      expected: {
        kind: "runtime-probe",
        endpoint: "endpoint.json",
        runtime: "runtime.json",
        trust: "trust.json",
        capability: "completions",
        observationEffect: "inference-canary",
        deadlineMs: 1500,
      },
    },
    {
      argv: [
        "shadow",
        "run",
        "--plan",
        "shadow-plan.json",
        "--plan-digest",
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "--cases",
        "cases.ndjson",
        "--profiles",
        "profiles.json",
        "--trust",
        "trust.json",
        "--identity",
        "identity.json",
        "--out",
        "shadow-records",
      ],
      expected: {
        kind: "shadow-run",
        plan: "shadow-plan.json",
        expectedPlanDigest:
          "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        cases: "cases.ndjson",
        profiles: "profiles.json",
        trust: "trust.json",
        identity: "identity.json",
        out: "shadow-records",
      },
    },
    {
      argv: [
        "nominate",
        "--spec",
        "spec.json",
        "--measurements",
        "measurements.json",
        "--out",
        "nomination",
      ],
      expected: {
        kind: "legacy-nominate",
        spec: "spec.json",
        measurements: "measurements.json",
        out: "nomination",
      },
    },
    {
      argv: [
        "confirm",
        "--spec",
        "spec.json",
        "--measurements",
        "measurements.json",
        "--nomination",
        "nomination.json",
        "--out",
        "confirmation",
      ],
      expected: {
        kind: "legacy-confirm",
        spec: "spec.json",
        measurements: "measurements.json",
        nomination: "nomination.json",
        out: "confirmation",
      },
    },
    {
      argv: ["--help"],
      expected: { kind: "help" },
    },
    {
      argv: ["--version"],
      expected: { kind: "version" },
    },
  ])("parses and freezes $expected.kind", ({ argv, expected }) => {
    const before = [...argv];
    const parsed = parseCliArguments(argv);

    expect(parsed).toEqual(expected);
    expect(Object.isFrozen(parsed)).toBe(true);
    expect(argv).toEqual(before);
  });

  it.each([
    {
      argv: [],
      code: "missing-command",
    },
    {
      argv: ["serve"],
      code: "unknown-command",
    },
    {
      argv: ["protocol", "inspect", "protocol.json"],
      code: "unknown-action",
    },
    {
      argv: ["protocol", "validate"],
      code: "missing-positional",
    },
    {
      argv: ["protocol", "validate", "one.json", "two.json"],
      code: "unexpected-argument",
    },
    {
      argv: ["protocol", "validate", "--protocol=secret.json"],
      code: "unknown-option",
    },
    {
      argv: ["assess", "development", "-p", "secret.json"],
      code: "unknown-option",
    },
    {
      argv: ["assess", "development", "--protocol=secret.json"],
      code: "unknown-option",
    },
    {
      argv: [
        "assess",
        "development",
        "--protocol",
        "one.json",
        "--protocol",
        "two.json",
      ],
      code: "duplicate-option",
    },
    {
      argv: ["assess", "development", "--protocol"],
      code: "missing-option-value",
    },
    {
      argv: ["assess", "development", "--protocol", "--traces"],
      code: "missing-option-value",
    },
    {
      argv: ["assess", "development", "--protocol", "protocol.json"],
      code: "missing-required-option",
    },
    {
      argv: ["assess", "development", "unexpected-secret-path"],
      code: "unexpected-argument",
    },
    {
      argv: ["assess", "development", "--runtime", "vllm"],
      code: "unknown-option",
    },
    {
      argv: ["runtime", "inspect"],
      code: "unknown-action",
    },
    {
      argv: ["shadow", "run"],
      code: "missing-required-option",
    },
    {
      argv: [
        "shadow",
        "run",
        "--plan",
        "shadow-plan.json",
        "--plan-digest",
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "--cases",
        "cases.ndjson",
        "--profiles",
        "profiles.json",
        "--trust",
        "trust.json",
        "--identity",
        "identity.json",
        "--out",
        "shadow-records",
        "--protocol",
        "protocol.json",
      ],
      code: "unknown-option",
    },
    {
      argv: [
        "shadow",
        "run",
        "--plan",
        "shadow-plan.json",
        "--plan-digest",
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "--cases",
        "cases.ndjson",
        "--profiles",
        "profiles.json",
        "--trust",
        "trust.json",
        "--identity",
        "identity.json",
        "--out",
        "shadow-records",
        "--work-budget",
        "work-budget.json",
      ],
      code: "unknown-option",
    },
    {
      argv: [
        "shadow",
        "run",
        "--plan",
        "shadow-plan.json",
        "--plan-digest",
        "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "--cases",
        "cases.ndjson",
        "--profiles",
        "profiles.json",
        "--trust",
        "trust.json",
        "--identity",
        "identity.json",
        "--out",
        "shadow-records",
      ],
      code: "invalid-option-value",
    },
    {
      argv: [
        "runtime",
        "probe",
        "--endpoint",
        "endpoint.json",
        "--runtime",
        "runtime.json",
        "--trust",
        "trust.json",
        "--capability",
        "planted-secret-capability",
        "--effect",
        "non-mutating",
        "--deadline-ms",
        "1000",
      ],
      code: "invalid-option-value",
    },
    {
      argv: [
        "runtime",
        "probe",
        "--endpoint",
        "endpoint.json",
        "--runtime",
        "runtime.json",
        "--trust",
        "trust.json",
        "--capability",
        "liveness",
        "--effect",
        "non-mutating",
        "--deadline-ms",
        "0001",
      ],
      code: "invalid-option-value",
    },
    {
      argv: ["--help", "unexpected"],
      code: "unexpected-argument",
    },
    {
      argv: ["nominate", "--nomination", "secret.json"],
      code: "unknown-option",
    },
  ] as const)("rejects invalid grammar with $code", ({ argv, code }) => {
    try {
      parseCliArguments(argv);
      throw new Error("expected parseCliArguments to reject");
    } catch (error) {
      expect(error).toBeInstanceOf(CliArgumentError);
      expect((error as CliArgumentError).code).toBe(code);
      expect((error as Error).message).not.toContain("secret");
    }
  });

  it("requires holdout revalidation inputs as well as the nomination", () => {
    const common = [
      "assess",
      "holdout",
      "--protocol",
      "protocol.json",
      "--traces",
      "traces.ndjson",
      "--evidence",
      "evidence.ndjson",
      "--context",
      "context.json",
      "--nomination",
      "nomination.json",
      "--trust",
      "trust.json",
      "--work-budget",
      "work-budget.json",
      "--out",
      "assessment",
    ];

    const developmentOptions = [
      ["--development-traces", "development-traces.ndjson"],
      ["--development-evidence", "development-evidence.ndjson"],
      ["--development-context", "development-context.json"],
      ["--development-trust", "development-trust.json"],
    ] as const;

    for (const [omittedFlag] of developmentOptions) {
      const present = developmentOptions
        .filter(([flag]) => flag !== omittedFlag)
        .flat();
      expect(() => parseCliArguments([...common, ...present]))
        .toThrowError(expect.objectContaining({
          code: "missing-required-option",
        }));
    }
  });

  it("never reflects arbitrary argv values in errors", () => {
    const planted = "TOP_SECRET_PATH_DO_NOT_LOG";
    const invalidInputs = [
      [planted],
      ["protocol", planted, "protocol.json"],
      ["protocol", "validate", "protocol.json", planted],
      ["assess", "development", planted],
      ["assess", "development", `--${planted}`, "value"],
    ];

    for (const argv of invalidInputs) {
      expect(() => parseCliArguments(argv)).toThrowError(
        expect.not.objectContaining({ message: expect.stringContaining(planted) }),
      );
    }
  });
});

describe("CLI command metadata", () => {
  it("publishes fixed, deeply frozen usage metadata without a package version", () => {
    expect(CLI_COMMANDS.map(({ kind }) => kind)).toEqual([
      "protocol-validate",
      "traces-validate",
      "evidence-validate",
      "assess-development",
      "assess-holdout",
      "assess-window",
      "experiment-next",
      "runtime-probe",
      "shadow-run",
      "legacy-nominate",
      "legacy-confirm",
    ]);
    expect(CLI_USAGE).toContain("tasc assess holdout");
    expect(CLI_USAGE).toContain("tasc runtime probe");
    expect(CLI_USAGE).toContain("tasc shadow run");
    expect(CLI_USAGE).toContain("tasc shadow run --plan <path>");
    const shadow = CLI_COMMANDS.find(({ kind }) => kind === "shadow-run");
    expect(shadow?.requiredOptions).toEqual([
      "--plan",
      "--plan-digest",
      "--cases",
      "--profiles",
      "--trust",
      "--identity",
      "--out",
    ]);
    expect(shadow?.usage).not.toContain("--protocol");
    expect(shadow?.usage).not.toContain("--work-budget");
    expect(CLI_USAGE).toContain("--development-context");
    expect(CLI_USAGE).toContain("--development-trust");
    expect(CLI_USAGE).toContain("tasc --help");
    expect(CLI_USAGE).toContain("tasc --version");
    expect(CLI_USAGE).toContain("0 completed decision or validation");
    expect(CLI_USAGE).toContain("4 output freshness, custody, or publication failure");
    expect(CLI_USAGE).not.toMatch(/\b\d+\.\d+\.\d+\b/);
    expect(Object.isFrozen(CLI_COMMANDS)).toBe(true);
    expect(CLI_COMMANDS.every((command) => Object.isFrozen(command))).toBe(true);
    expect(CLI_COMMANDS.every((command) => Object.isFrozen(command.requiredOptions))).toBe(true);
  });
});
