import {
  mkdtemp,
  readFile,
  readdir,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, resolve } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { parsePolicyBundle } from "../src/assessment.js";
import { parseAssessmentContext } from "../src/assessment-context.js";
import { verifyArtifactPacket } from "../src/artifacts.js";
import { runCli } from "../src/cli.js";
import {
  parseEvaluatorEvidence,
  parseExperimentProtocol,
  parseTraceEnvelope,
} from "../src/evidence.js";
import {
  joinAssessmentEvidence,
  requireAssessmentDatasetSplit,
} from "../src/evidence-join.js";
import {
  parseEvaluatorTrustSnapshot,
  verifyEvaluatorEvidence,
} from "../src/evaluator-trust.js";
import {
  TEST_WORK_BUDGET,
  evaluatorKeyFixture,
  validAssessmentContextInput,
  validEvaluatorEvidenceInput,
  validProtocolInput,
  validTraceInput,
} from "./fixtures/evidence.js";
import {
  createCliV2AssessmentFixtureSet,
  createCliV2OnlineAssessmentFixture,
  createCliV2WindowManifest,
} from "./fixtures/cli-v2.js";

interface CapturedIo {
  readonly stdout: { write(value: string): void };
  readonly stderr: { write(value: string): void };
  readonly output: () => { stdout: string; stderr: string };
}

const roots: string[] = [];

afterEach(async () => {
  await Promise.all(
    roots.splice(0).map((root) =>
      rm(root, { recursive: true, force: true })
    ),
  );
});

function captureIo(): CapturedIo {
  let stdout = "";
  let stderr = "";
  return {
    stdout: {
      write(value: string): void {
        stdout += value;
      },
    },
    stderr: {
      write(value: string): void {
        stderr += value;
      },
    },
    output: () => ({ stdout, stderr }),
  };
}

async function fixtureRoot(): Promise<string> {
  const root = await mkdtemp(resolve(tmpdir(), "tasc-cli-v2-"));
  roots.push(root);
  return root;
}

async function jsonFile(
  root: string,
  name: string,
  value: unknown,
): Promise<string> {
  const path = resolve(root, name);
  await writeFile(path, `${JSON.stringify(value)}\n`, "utf8");
  return path;
}

async function ndjsonFile(
  root: string,
  name: string,
  values: readonly unknown[],
): Promise<string> {
  const path = resolve(root, name);
  await writeFile(
    path,
    values.map((value) => JSON.stringify(value)).join("\n") + "\n",
    "utf8",
  );
  return path;
}

function parsedLine(value: string): Record<string, unknown> {
  expect(value.endsWith("\n")).toBe(true);
  expect(value.trim().split("\n")).toHaveLength(1);
  return JSON.parse(value) as Record<string, unknown>;
}

async function parsedFile(path: string): Promise<Record<string, any>> {
  return JSON.parse(await readFile(path, "utf8")) as Record<string, any>;
}

describe("production trace-control-plane CLI", () => {
  it("exposes import-safe help and version commands", async () => {
    const helpIo = captureIo();
    await expect(runCli(["--help"], {}, helpIo)).resolves.toBe(0);
    expect(helpIo.output().stderr).toBe("");
    expect(helpIo.output().stdout).toContain("tasc assess development");
    expect(helpIo.output().stdout).toContain("tasc experiment next");
    expect(helpIo.output().stdout).toContain("tasc runtime probe");
    expect(helpIo.output().stdout).toContain("tasc shadow run");

    const versionIo = captureIo();
    await expect(runCli(["--version"], {}, versionIo)).resolves.toBe(0);
    expect(versionIo.output()).toEqual({
      stdout: "0.1.0\n",
      stderr: "",
    });
  });

  it("rejects malformed runtime commands without reflecting input", async () => {
    const secret = "planted-unknown-command-secret";
    const io = captureIo();
    await expect(runCli(["runtime", "probe", `--${secret}`], {}, io))
      .resolves.toBe(2);

    const diagnostic = parsedLine(io.output().stderr);
    expect(diagnostic).toMatchObject({
      version: "tasc-cli-diagnostic-v1",
      code: "USAGE",
      message: "Invalid command usage.",
    });
    expect(io.output().stderr).not.toContain(secret);
    expect(io.output().stdout).toBe("");
  });

  it("validates a protocol and emits one bounded structured result", async () => {
    const root = await fixtureRoot();
    const protocol = await jsonFile(
      root,
      "protocol.json",
      validProtocolInput(),
    );
    const workBudget = await jsonFile(
      root,
      "work-budget.json",
      TEST_WORK_BUDGET,
    );
    const io = captureIo();

    await expect(runCli([
      "protocol",
      "validate",
      protocol,
      "--work-budget",
      workBudget,
    ], {}, io)).resolves.toBe(0);

    expect(io.output().stderr).toBe("");
    expect(parsedLine(io.output().stdout)).toMatchObject({
      version: "tasc-cli-result-v1",
      command: "protocol validate",
      status: "VALID",
      authority: "evidence-only-no-deployment-authority",
    });
  });

  it("validates trace NDJSON as contract-only evidence", async () => {
    const root = await fixtureRoot();
    const traces = await ndjsonFile(
      root,
      "traces.ndjson",
      [validTraceInput()],
    );
    const workBudget = await jsonFile(
      root,
      "work-budget.json",
      TEST_WORK_BUDGET,
    );
    const io = captureIo();

    await expect(runCli([
      "traces",
      "validate",
      traces,
      "--work-budget",
      workBudget,
    ], {}, io)).resolves.toBe(0);

    expect(io.output().stderr).toBe("");
    expect(parsedLine(io.output().stdout)).toMatchObject({
      version: "tasc-cli-result-v1",
      command: "traces validate",
      status: "VALID",
      count: 1,
      scope: "contract-only-no-protocol-admission",
      authority: "evidence-only-no-deployment-authority",
    });
  });

  it("validates evaluator evidence against explicit local trust and context", async () => {
    const root = await fixtureRoot();
    const key = evaluatorKeyFixture();
    const evidence = await ndjsonFile(
      root,
      "evidence.ndjson",
      [validEvaluatorEvidenceInput(key.privateKey)],
    );
    const trust = await jsonFile(root, "trust.json", key.trustSnapshot);
    const context = await jsonFile(
      root,
      "context.json",
      validAssessmentContextInput(key.trustSnapshot),
    );
    const workBudget = await jsonFile(
      root,
      "work-budget.json",
      TEST_WORK_BUDGET,
    );
    const io = captureIo();

    await expect(runCli([
      "evidence",
      "validate",
      evidence,
      "--trust",
      trust,
      "--context",
      context,
      "--work-budget",
      workBudget,
    ], {}, io)).resolves.toBe(0);

    expect(io.output().stderr).toBe("");
    expect(parsedLine(io.output().stdout)).toMatchObject({
      version: "tasc-cli-result-v1",
      command: "evidence validate",
      status: "VALID",
      count: 1,
      trustedCount: 1,
      scope: "signature-and-local-trust-only",
      authority: "evidence-only-no-deployment-authority",
    });
  });

  it("reports bounded line-aware input failures without paths or secrets", async () => {
    const root = await fixtureRoot();
    const secret = "planted-cli-v2-source-secret";
    const traces = resolve(root, "private-secret-traces.ndjson");
    await writeFile(
      traces,
      `${JSON.stringify({ secret })}\n\n`,
      "utf8",
    );
    const workBudget = await jsonFile(
      root,
      "work-budget.json",
      TEST_WORK_BUDGET,
    );
    const io = captureIo();

    await expect(runCli([
      "traces",
      "validate",
      traces,
      "--work-budget",
      workBudget,
    ], {}, io)).resolves.toBe(3);

    const diagnostic = parsedLine(io.output().stderr);
    expect(diagnostic).toMatchObject({
      version: "tasc-cli-diagnostic-v1",
      code: "INPUT_INVALID",
      message: "Input validation failed.",
      input: "traces",
      detail: "blank-line",
      line: 2,
    });
    expect(io.output().stderr).not.toContain(secret);
    expect(io.output().stderr).not.toContain(root);
    expect(io.output().stdout).toBe("");
  });

  it("publishes a fresh unattested development assessment packet", async () => {
    const root = await fixtureRoot();
    const fixtures = createCliV2AssessmentFixtureSet();
    const protocol = await jsonFile(
      root,
      "protocol.json",
      fixtures.protocolInput,
    );
    const traces = await ndjsonFile(
      root,
      "development-traces.ndjson",
      fixtures.development.traceRows,
    );
    const evidence = await ndjsonFile(
      root,
      "development-evidence.ndjson",
      fixtures.development.evidenceRows,
    );
    const trust = await jsonFile(
      root,
      "trust.json",
      fixtures.trustSnapshot,
    );
    const context = await jsonFile(
      root,
      "development-context.json",
      fixtures.development.contextInput,
    );
    const workBudget = await jsonFile(
      root,
      "work-budget.json",
      TEST_WORK_BUDGET,
    );
    const out = resolve(root, "development-assessment");
    const io = captureIo();

    await expect(runCli([
      "assess",
      "development",
      "--protocol",
      protocol,
      "--traces",
      traces,
      "--evidence",
      evidence,
      "--context",
      context,
      "--trust",
      trust,
      "--work-budget",
      workBudget,
      "--out",
      out,
    ], {
      TASC_ATTESTATION_KEY: "legacy-key-must-be-ignored",
    }, io)).resolves.toBe(0);

    expect(io.output().stderr).toBe("");
    const result = parsedLine(io.output().stdout);
    expect(result).toMatchObject({
      version: "tasc-cli-result-v1",
      command: "assess development",
      status: "NOMINATED",
      attestation: "unattested",
      authority: "evidence-only-no-deployment-authority",
      artifact: {
        durability: expect.stringMatching(/^(?:full|degraded)$/),
        manifestDigest: expect.stringMatching(/^[a-f0-9]{64}$/),
        packetDigest: expect.stringMatching(/^[a-f0-9]{64}$/),
      },
    });
    expect(io.output().stdout).not.toContain("legacy-key-must-be-ignored");

    await expect(verifyArtifactPacket(dirname(out), basename(out)))
      .resolves.toMatchObject({ path: out });
    expect((await readdir(out)).sort()).toEqual([
      "assessment.json",
      "manifest.json",
      "policy.json",
    ]);
    expect(await parsedFile(resolve(out, "assessment.json")))
      .toMatchObject({
        phase: "development",
        status: "NOMINATED",
        attestation: "unattested",
      });

    const repeatedIo = captureIo();
    await expect(runCli([
      "assess",
      "development",
      "--protocol",
      protocol,
      "--traces",
      traces,
      "--evidence",
      evidence,
      "--context",
      context,
      "--trust",
      trust,
      "--work-budget",
      workBudget,
      "--out",
      out,
    ], {}, repeatedIo)).resolves.toBe(4);
    expect(parsedLine(repeatedIo.output().stderr)).toMatchObject({
      code: "OUTPUT_FAILURE",
      message: "Artifact publication failed.",
    });
    expect(repeatedIo.output().stdout).toBe("");
  }, 30_000);

  it("replays development sources before confirming a persisted holdout nomination", async () => {
    const root = await fixtureRoot();
    const fixtures = createCliV2AssessmentFixtureSet();
    const protocol = await jsonFile(
      root,
      "protocol.json",
      fixtures.protocolInput,
    );
    const developmentTrust = await jsonFile(
      root,
      "development-trust.json",
      fixtures.trustSnapshot,
    );
    const holdoutTrustSnapshot = {
      ...structuredClone(fixtures.trustSnapshot),
      freshness: {
        ...structuredClone(fixtures.trustSnapshot.freshness),
        maximumFutureSkewMs:
          fixtures.trustSnapshot.freshness.maximumFutureSkewMs + 1,
      },
    };
    const trust = await jsonFile(
      root,
      "holdout-trust.json",
      holdoutTrustSnapshot,
    );
    const workBudget = await jsonFile(
      root,
      "work-budget.json",
      TEST_WORK_BUDGET,
    );
    const developmentContext = await jsonFile(
      root,
      "development-context.json",
      fixtures.development.contextInput,
    );
    const developmentTraces = await ndjsonFile(
      root,
      "development-traces.ndjson",
      fixtures.development.traceRows,
    );
    const developmentEvidence = await ndjsonFile(
      root,
      "development-evidence.ndjson",
      fixtures.development.evidenceRows,
    );
    const developmentOut = resolve(root, "development");
    const developmentIo = captureIo();
    expect(await runCli([
      "assess",
      "development",
      "--protocol",
      protocol,
      "--traces",
      developmentTraces,
      "--evidence",
      developmentEvidence,
      "--context",
      developmentContext,
      "--trust",
      developmentTrust,
      "--work-budget",
      workBudget,
      "--out",
      developmentOut,
    ], {}, developmentIo)).toBe(0);

    const holdoutContext = await jsonFile(
      root,
      "holdout-context.json",
      validAssessmentContextInput(holdoutTrustSnapshot),
    );
    const holdoutTraces = await ndjsonFile(
      root,
      "holdout-traces.ndjson",
      fixtures.holdout.traceRows,
    );
    const holdoutEvidence = await ndjsonFile(
      root,
      "holdout-evidence.ndjson",
      fixtures.holdout.evidenceRows,
    );
    const nomination = resolve(developmentOut, "assessment.json");
    const holdoutOut = resolve(root, "holdout");
    const holdoutIo = captureIo();

    expect(await runCli([
      "assess",
      "holdout",
      "--protocol",
      protocol,
      "--traces",
      holdoutTraces,
      "--evidence",
      holdoutEvidence,
      "--context",
      holdoutContext,
      "--nomination",
      nomination,
      "--development-traces",
      developmentTraces,
      "--development-evidence",
      developmentEvidence,
      "--development-context",
      developmentContext,
      "--development-trust",
      developmentTrust,
      "--trust",
      trust,
      "--work-budget",
      workBudget,
      "--out",
      holdoutOut,
    ], {}, holdoutIo)).toBe(0);

    expect(parsedLine(holdoutIo.output().stdout)).toMatchObject({
      command: "assess holdout",
      status: "PASS",
      nominationDecisionDigest:
        (await parsedFile(nomination)).decisionDigest,
      selectedPolicyDigest:
        (await parsedFile(nomination)).selectedPolicyDigest,
    });
    expect(await parsedFile(resolve(holdoutOut, "assessment.json")))
      .toMatchObject({ phase: "holdout", status: "PASS" });
    const lineage = await parsedFile(
      resolve(holdoutOut, "nomination-lineage.json"),
    );
    expect(lineage).toMatchObject({
      version: "tasc-holdout-nomination-lineage-v1",
      relationship: "holdout-confirms-development-nomination",
      nominationDecisionDigest:
        (await parsedFile(nomination)).decisionDigest,
      developmentAssessmentContextDigest:
        (await parsedFile(nomination)).assessmentContextDigest,
      developmentDatasetDigest:
        (await parsedFile(nomination)).datasetDigest,
      developmentTraceSetDigest:
        (await parsedFile(nomination)).traceSetDigest,
      developmentEvaluatorSetDigest:
        (await parsedFile(nomination)).evaluatorSetDigest,
      authority: "evidence-only-no-deployment-authority",
    });
    const verifiedHoldout = await verifyArtifactPacket(
      dirname(holdoutOut),
      basename(holdoutOut),
    );
    expect(verifiedHoldout.manifest.files.map(({ name }) => name))
      .toContain("nomination-lineage.json");

    const tampered = await parsedFile(nomination);
    tampered.selectedPolicy.issueTime = "2026-07-25T00:00:00.000Z";
    const tamperedPath = await jsonFile(root, "tampered.json", tampered);
    const tamperedIo = captureIo();
    expect(await runCli([
      "assess",
      "holdout",
      "--protocol",
      protocol,
      "--traces",
      holdoutTraces,
      "--evidence",
      holdoutEvidence,
      "--context",
      holdoutContext,
      "--nomination",
      tamperedPath,
      "--development-traces",
      developmentTraces,
      "--development-evidence",
      developmentEvidence,
      "--development-context",
      developmentContext,
      "--development-trust",
      developmentTrust,
      "--trust",
      trust,
      "--work-budget",
      workBudget,
      "--out",
      resolve(root, "tampered-out"),
    ], {}, tamperedIo)).toBe(3);
    expect(parsedLine(tamperedIo.output().stderr)).toMatchObject({
      code: "INPUT_INVALID",
      input: "nomination",
      detail: "contract-invalid",
    });
  }, 30_000);

  it("writes proposed and held next-experiment packets as completed decisions", async () => {
    const root = await fixtureRoot();
    const fixtures = createCliV2AssessmentFixtureSet();
    const protocol = await jsonFile(
      root,
      "protocol.json",
      fixtures.protocolInput,
    );
    const traces = await ndjsonFile(
      root,
      "development-traces.ndjson",
      fixtures.development.traceRows,
    );
    const evidence = await ndjsonFile(
      root,
      "development-evidence.ndjson",
      fixtures.development.evidenceRows,
    );
    const trust = await jsonFile(
      root,
      "trust.json",
      fixtures.trustSnapshot,
    );
    const context = await jsonFile(
      root,
      "context.json",
      fixtures.development.contextInput,
    );
    const workBudget = await jsonFile(
      root,
      "work-budget.json",
      TEST_WORK_BUDGET,
    );
    const assessmentOut = resolve(root, "assessment");
    expect(await runCli([
      "assess",
      "development",
      "--protocol",
      protocol,
      "--traces",
      traces,
      "--evidence",
      evidence,
      "--context",
      context,
      "--trust",
      trust,
      "--work-budget",
      workBudget,
      "--out",
      assessmentOut,
    ], {}, captureIo())).toBe(0);

    const history = await jsonFile(root, "history.json", {
      version: "tasc-experiment-history-v1",
      registeredExperiments: [],
      findings: [],
    });
    const proposedBudget = await jsonFile(root, "proposal-budget.json", {
      version: "tasc-experiment-budget-v1",
      maxLogicalExecutions: 64,
      maxAttempts: 128,
      maxCostUsd: 10,
      maxWallClockMs: 60_000,
      payloadPolicy: "keyed-identities-only",
    });
    const proposedOut = resolve(root, "proposal");
    const proposedIo = captureIo();
    expect(await runCli([
      "experiment",
      "next",
      "--assessment",
      resolve(assessmentOut, "assessment.json"),
      "--history",
      history,
      "--budget",
      proposedBudget,
      "--out",
      proposedOut,
    ], {}, proposedIo)).toBe(0);
    expect(parsedLine(proposedIo.output().stdout)).toMatchObject({
      command: "experiment next",
      status: "PROPOSED",
      authority: "evidence-only-no-deployment-authority",
    });
    expect((await readdir(proposedOut)).sort()).toEqual([
      "experiment-proposal.json",
      "manifest.json",
    ]);

    const heldBudget = await jsonFile(root, "hold-budget.json", {
      version: "tasc-experiment-budget-v1",
      maxLogicalExecutions: 1,
      maxAttempts: 1,
      maxCostUsd: 0,
      maxWallClockMs: 0,
      payloadPolicy: "keyed-identities-only",
    });
    const heldIo = captureIo();
    expect(await runCli([
      "experiment",
      "next",
      "--assessment",
      resolve(assessmentOut, "assessment.json"),
      "--history",
      history,
      "--budget",
      heldBudget,
      "--out",
      resolve(root, "held"),
    ], {}, heldIo)).toBe(0);
    expect(parsedLine(heldIo.output().stdout)).toMatchObject({
      command: "experiment next",
      status: "HOLD",
    });
  }, 30_000);

  it("assesses one frozen policy against an exact sealed online window", async () => {
    const root = await fixtureRoot();
    const developmentFixtures = createCliV2AssessmentFixtureSet();
    const developmentProtocol = await jsonFile(
      root,
      "development-protocol.json",
      developmentFixtures.protocolInput,
    );
    const developmentTraces = await ndjsonFile(
      root,
      "development-traces.ndjson",
      developmentFixtures.development.traceRows,
    );
    const developmentEvidence = await ndjsonFile(
      root,
      "development-evidence.ndjson",
      developmentFixtures.development.evidenceRows,
    );
    const developmentTrust = await jsonFile(
      root,
      "development-trust.json",
      developmentFixtures.trustSnapshot,
    );
    const developmentContext = await jsonFile(
      root,
      "development-context.json",
      developmentFixtures.development.contextInput,
    );
    const workBudget = await jsonFile(
      root,
      "work-budget.json",
      TEST_WORK_BUDGET,
    );
    const developmentOut = resolve(root, "development");
    expect(await runCli([
      "assess",
      "development",
      "--protocol",
      developmentProtocol,
      "--traces",
      developmentTraces,
      "--evidence",
      developmentEvidence,
      "--context",
      developmentContext,
      "--trust",
      developmentTrust,
      "--work-budget",
      workBudget,
      "--out",
      developmentOut,
    ], {}, captureIo())).toBe(0);
    const policy = parsePolicyBundle(
      await parsedFile(resolve(developmentOut, "policy.json")),
    );

    const onlineFixtures = createCliV2OnlineAssessmentFixture(policy);
    const protocolValue = parseExperimentProtocol(
      onlineFixtures.protocolInput,
      TEST_WORK_BUDGET,
    );
    const trustValue = parseEvaluatorTrustSnapshot(
      onlineFixtures.trustSnapshot,
    );
    const contextValue = parseAssessmentContext(
      onlineFixtures.online.contextInput,
    );
    const traceValues = onlineFixtures.online.traceRows.map((row) =>
      parseTraceEnvelope(row, TEST_WORK_BUDGET)
    );
    const evidenceValues = onlineFixtures.online.evidenceRows.map((row) =>
      verifyEvaluatorEvidence(
        parseEvaluatorEvidence(row, TEST_WORK_BUDGET),
        trustValue,
        contextValue,
      )
    );
    const onlineDataset = requireAssessmentDatasetSplit(
      joinAssessmentEvidence(
        protocolValue,
        traceValues,
        evidenceValues,
        TEST_WORK_BUDGET,
      ),
      "online",
    );
    const manifest = createCliV2WindowManifest(
      protocolValue,
      policy,
      onlineDataset,
    );

    const protocol = await jsonFile(
      root,
      "online-protocol.json",
      onlineFixtures.protocolInput,
    );
    const traces = await ndjsonFile(
      root,
      "online-traces.ndjson",
      onlineFixtures.online.traceRows,
    );
    const evidence = await ndjsonFile(
      root,
      "online-evidence.ndjson",
      onlineFixtures.online.evidenceRows,
    );
    const trust = await jsonFile(
      root,
      "online-trust.json",
      onlineFixtures.trustSnapshot,
    );
    const context = await jsonFile(
      root,
      "online-context.json",
      onlineFixtures.online.contextInput,
    );
    const policyPath = await jsonFile(root, "policy.json", policy);
    const windowPath = await jsonFile(root, "window.json", manifest);
    const out = resolve(root, "window-assessment");
    const io = captureIo();

    expect(await runCli([
      "assess",
      "window",
      "--protocol",
      protocol,
      "--traces",
      traces,
      "--evidence",
      evidence,
      "--context",
      context,
      "--policy",
      policyPath,
      "--window",
      windowPath,
      "--trust",
      trust,
      "--work-budget",
      workBudget,
      "--out",
      out,
    ], {}, io)).toBe(0);

    expect(parsedLine(io.output().stdout)).toMatchObject({
      command: "assess window",
      status: "PASS",
      selectedPolicyDigest: policy.policyDigest,
    });
    expect(await parsedFile(resolve(out, "assessment.json")))
      .toMatchObject({
        phase: "window",
        status: "PASS",
        windowManifestDigest: expect.stringMatching(/^sha256:/),
      });
  }, 30_000);

  it("rejects malformed work budgets before reading assessment sources", async () => {
    const root = await fixtureRoot();
    const sourceSecret = "source-must-not-be-read";
    const invalidSource = resolve(root, sourceSecret);
    const workBudget = await jsonFile(root, "invalid-budget.json", {
      ...TEST_WORK_BUDGET,
      maxTraceRows: 1.5,
    });
    const io = captureIo();

    expect(await runCli([
      "traces",
      "validate",
      invalidSource,
      "--work-budget",
      workBudget,
    ], {}, io)).toBe(3);
    expect(parsedLine(io.output().stderr)).toMatchObject({
      code: "INPUT_INVALID",
      input: "work-budget",
      detail: "contract-invalid",
    });
    expect(io.output().stderr).not.toContain(sourceSecret);
  });
});
