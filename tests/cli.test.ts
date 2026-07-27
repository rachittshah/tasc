import { createHash } from "node:crypto";
import { mkdtemp, readFile, readdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { sha256, stableJson } from "../src/integrity.js";
import {
  buildConfirmationReport,
  buildDevelopmentReport,
  proposeNextExperiment,
  writeConfirmationArtifacts,
  writeDevelopmentArtifacts,
} from "../src/report.js";
import { parseInferenceSpec, parseMeasurementSet } from "../src/schema.js";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const CLI = resolve(REPO_ROOT, "src/cli.ts");
const SPEC = resolve(REPO_ROOT, "examples/synthetic/spec.json");
const DEV = resolve(REPO_ROOT, "examples/synthetic/dev.json");
const HOLDOUT = resolve(REPO_ROOT, "examples/synthetic/holdout.json");

function runCli(args: string[], env: Partial<NodeJS.ProcessEnv> = {}) {
  const childEnv = { ...process.env, ...env };
  delete childEnv.TASC_ATTESTATION_KEY;
  if (env.TASC_ATTESTATION_KEY !== undefined) {
    childEnv.TASC_ATTESTATION_KEY = env.TASC_ATTESTATION_KEY;
  }
  return spawnSync(process.execPath, [
    "--import",
    "tsx",
    CLI,
    ...args,
  ], {
    cwd: REPO_ROOT,
    encoding: "utf8",
    env: childEnv,
  });
}

async function json(path: string): Promise<Record<string, any>> {
  return JSON.parse(await readFile(path, "utf8"));
}

async function digest(path: string): Promise<string> {
  return createHash("sha256").update(await readFile(path)).digest("hex");
}

describe("TASC CLI synthetic end-to-end example", () => {
  it("keeps packaged safety docs aligned with the legacy-v1 HOLD boundary", async () => {
    for (const path of [
      resolve(REPO_ROOT, "README.md"),
      resolve(REPO_ROOT, "docs/operating-guide.md"),
      resolve(REPO_ROOT, "docs/design.md"),
    ]) {
      const source = await readFile(path, "utf8");
      expect(source).not.toMatch(
        /(?:produces?|returns?|status[^\n]*meaning)[^\n]{0,120}`READY_FOR_MANUAL_PRODUCTION`|`READY_FOR_MANUAL_PRODUCTION`[^\n]{0,160}(?:authenticated|real .*passed)/i,
      );
      expect(source).toMatch(/legacy v1[\s\S]{0,240}HOLD|HOLD[\s\S]{0,240}migrat[\s\S]{0,120}v2/i);
    }
  });

  it("nominates and confirms the exact cascade with deterministic, reviewer-ready artifacts", async () => {
    const root = await mkdtemp(resolve(tmpdir(), "tasc-cli-"));
    const devOne = resolve(root, "dev-one");
    const devTwo = resolve(root, "dev-two");
    const holdoutOne = resolve(root, "holdout-one");
    const holdoutTwo = resolve(root, "holdout-two");

    const firstNomination = runCli([
      "nominate", "--spec", SPEC, "--measurements", DEV, "--out", devOne,
    ]);
    expect(firstNomination.status, firstNomination.stderr).toBe(0);
    expect(firstNomination.stdout).toContain("NOMINATED");
    expect(firstNomination.stdout).toContain(devOne);
    expect(await readdir(devOne)).toEqual([
      "development-report.json",
      "next-experiment.json",
      "nomination.json",
      "report.md",
    ]);

    const secondNomination = runCli([
      "nominate", "--spec", SPEC, "--measurements", DEV, "--out", devTwo,
    ]);
    expect(secondNomination.status, secondNomination.stderr).toBe(0);
    for (const filename of ["development-report.json", "next-experiment.json", "nomination.json"]) {
      expect(await digest(resolve(devOne, filename))).toBe(await digest(resolve(devTwo, filename)));
    }
    expect(await readFile(resolve(devOne, "report.md"), "utf8"))
      .toBe(await readFile(resolve(devTwo, "report.md"), "utf8"));

    const nomination = await json(resolve(devOne, "nomination.json"));
    expect(nomination.policy.kind).toBe("cascade");
    const development = await json(resolve(devOne, "development-report.json"));
    expect(development.status).toBe("NOMINATED");
    expect(development.frontier).toContain(nomination.policy.id);
    expect(development.evaluations.some((entry: any) => (
      entry.policy.kind === "fast-only"
      && entry.evaluation.gates.some((gate: any) => !gate.pass)
    ))).toBe(true);

    const report = await readFile(resolve(devOne, "report.md"), "utf8");
    expect(report).toContain("SYNTHETIC / DEMO ONLY");
    expect(report).toMatch(/champion/i);
    expect(report).toMatch(/candidate/i);
    expect(report).toMatch(/frontier/i);
    expect(report).toMatch(/failed gates/i);
    expect(report).toMatch(/status reason/i);
    expect(report).toContain(nomination.policyDigest);
    expect(report).toMatch(/manual review/i);
    expect(report).toMatch(/does not mutate|no mutation/i);

    const nextExperiment = await json(resolve(devOne, "next-experiment.json"));
    expect(nextExperiment).toMatchObject({
      trigger: expect.any(String),
      hypothesis: expect.any(String),
      technique: expect.any(String),
      requiredMeasurements: expect.any(Array),
      unchangedGuardrails: expect.any(Array),
    });
    expect(nextExperiment.requiredMeasurements.length).toBeGreaterThan(0);
    expect(nextExperiment.unchangedGuardrails.length).toBeGreaterThan(0);
    expect(nextExperiment.trigger).toContain(nomination.policy.id);
    expect(nextExperiment.trigger).toMatch(/passed every.*gate/i);
    expect(nextExperiment.technique).toMatch(/shadow.*replication/i);

    const firstConfirmation = runCli([
      "confirm",
      "--spec", SPEC,
      "--measurements", HOLDOUT,
      "--nomination", resolve(devOne, "nomination.json"),
      "--out", holdoutOne,
    ]);
    expect(firstConfirmation.status, firstConfirmation.stderr).toBe(0);
    expect(firstConfirmation.stdout).toContain("DEMO_ONLY");
    expect(firstConfirmation.stdout).toContain(holdoutOne);
    expect(await readdir(holdoutOne)).toEqual(["confirmation.json", "report.md"]);

    const secondConfirmation = runCli([
      "confirm",
      "--spec", SPEC,
      "--measurements", HOLDOUT,
      "--nomination", resolve(devOne, "nomination.json"),
      "--out", holdoutTwo,
    ]);
    expect(secondConfirmation.status, secondConfirmation.stderr).toBe(0);
    expect(await digest(resolve(holdoutOne, "confirmation.json")))
      .toBe(await digest(resolve(holdoutTwo, "confirmation.json")));
    expect(await readFile(resolve(holdoutOne, "report.md"), "utf8"))
      .toBe(await readFile(resolve(holdoutTwo, "report.md"), "utf8"));

    const confirmationBefore = await digest(resolve(holdoutOne, "confirmation.json"));
    const reusedConfirmation = runCli([
      "confirm",
      "--spec", SPEC,
      "--measurements", HOLDOUT,
      "--nomination", resolve(devOne, "nomination.json"),
      "--out", holdoutOne,
    ]);
    expect(reusedConfirmation.status).not.toBe(0);
    expect(reusedConfirmation.stderr).toMatch(/output directory.*already exists.*fresh/i);
    expect(await digest(resolve(holdoutOne, "confirmation.json"))).toBe(confirmationBefore);

    const confirmation = await json(resolve(holdoutOne, "confirmation.json"));
    expect(confirmation).toMatchObject({
      status: "DEMO_ONLY",
      policy: { id: nomination.policy.id, kind: "cascade" },
      policyDigest: nomination.policyDigest,
    });
    expect(confirmation.statusReason).toMatch(/synthetic/i);
    const confirmationReport = await readFile(resolve(holdoutOne, "report.md"), "utf8");
    expect(confirmationReport).toContain("SYNTHETIC / DEMO ONLY");
    expect(confirmationReport).toContain("DEMO_ONLY");
    expect(confirmationReport).toContain(confirmation.statusReason);
    expect(confirmationReport).toContain(confirmation.policyDigest);
    expect(confirmationReport).toMatch(/manual review/i);
    expect(confirmationReport).toMatch(/does not mutate|no mutation/i);

    expect(buildDevelopmentReport(development as any, { synthetic: true }))
      .toContain("SYNTHETIC / DEMO ONLY");
    expect(buildConfirmationReport(confirmation as any, { synthetic: true }))
      .toContain("SYNTHETIC / DEMO ONLY");
    expect(() => (buildDevelopmentReport as any)(development)).toThrow(/provenance.*synthetic/i);
    expect(() => (buildConfirmationReport as any)(confirmation)).toThrow(/provenance.*synthetic/i);
    await expect((writeDevelopmentArtifacts as any)(
      resolve(root, "missing-dev-provenance"),
      development,
    )).rejects.toThrow(/provenance.*synthetic/i);
    await expect((writeConfirmationArtifacts as any)(
      resolve(root, "missing-confirmation-provenance"),
      confirmation,
    )).rejects.toThrow(/provenance.*synthetic/i);
  }, 30_000);

  it("produces the same nomination and digest under distinct locale environments", async () => {
    const root = await mkdtemp(resolve(tmpdir(), "tasc-locale-"));
    const firstOut = resolve(root, "first");
    const secondOut = resolve(root, "second");
    const first = runCli([
      "nominate", "--spec", SPEC, "--measurements", DEV, "--out", firstOut,
    ], { LANG: "de_DE.UTF-8", LC_ALL: "de_DE.UTF-8" });
    const second = runCli([
      "nominate", "--spec", SPEC, "--measurements", DEV, "--out", secondOut,
    ], { LANG: "sv_SE.UTF-8", LC_ALL: "sv_SE.UTF-8" });

    expect(first.status, first.stderr).toBe(0);
    expect(second.status, second.stderr).toBe(0);
    expect(await json(resolve(firstOut, "nomination.json")))
      .toEqual(await json(resolve(secondOut, "nomination.json")));
    expect(await digest(resolve(firstOut, "nomination.json")))
      .toBe(await digest(resolve(secondOut, "nomination.json")));
  }, 30_000);

  it("reports passing real legacy confirmation as HOLD with a v2 migration reason", async () => {
    const root = await mkdtemp(resolve(tmpdir(), "tasc-legacy-real-"));
    const devPath = resolve(root, "dev.json");
    const holdoutPath = resolve(root, "holdout.json");
    const devOut = resolve(root, "dev-out");
    const holdoutOut = resolve(root, "holdout-out");
    const dev = await json(DEV);
    const holdout = await json(HOLDOUT);
    dev.dataset.synthetic = false;
    holdout.dataset.synthetic = false;
    await writeFile(devPath, `${JSON.stringify(dev, null, 2)}\n`);
    await writeFile(holdoutPath, `${JSON.stringify(holdout, null, 2)}\n`);
    const key = "task4-real-legacy-attestation-key-at-least-32-bytes";

    const nominated = runCli([
      "nominate", "--spec", SPEC, "--measurements", devPath, "--out", devOut,
    ], { TASC_ATTESTATION_KEY: key });
    expect(nominated.status, nominated.stderr).toBe(0);
    const confirmed = runCli([
      "confirm",
      "--spec", SPEC,
      "--measurements", holdoutPath,
      "--nomination", resolve(devOut, "nomination.json"),
      "--out", holdoutOut,
    ], { TASC_ATTESTATION_KEY: key });

    expect(confirmed.status, confirmed.stderr).toBe(0);
    expect(confirmed.stdout).toContain("HOLD");
    const confirmation = await json(resolve(holdoutOut, "confirmation.json"));
    expect(confirmation.status).toBe("HOLD");
    expect(confirmation.statusReason).toMatch(/legacy v1.*migrat|migrat.*v2/i);
    expect(await readFile(resolve(holdoutOut, "report.md"), "utf8")).toMatch(/legacy v1.*migrat|migrat.*v2/i);
  }, 30_000);

  it("writes diagnostic artifacts and exits normally when no candidate passes", async () => {
    const root = await mkdtemp(resolve(tmpdir(), "tasc-no-candidate-"));
    const impossibleSpecPath = resolve(root, "spec.json");
    const out = resolve(root, "out");
    const impossibleSpec = await json(SPEC);
    impossibleSpec.constraints.taskScoreFloor = 1;
    await writeFile(impossibleSpecPath, `${JSON.stringify(impossibleSpec, null, 2)}\n`);

    const reusedOut = resolve(root, "reused");
    const first = runCli([
      "nominate", "--spec", SPEC, "--measurements", DEV, "--out", reusedOut,
    ]);
    expect(first.status, first.stderr).toBe(0);
    const originalNominationDigest = await digest(resolve(reusedOut, "nomination.json"));
    const staleAttempt = runCli([
      "nominate", "--spec", impossibleSpecPath, "--measurements", DEV, "--out", reusedOut,
    ]);
    expect(staleAttempt.status).not.toBe(0);
    expect(staleAttempt.stderr).toMatch(/output directory.*already exists.*fresh/i);
    expect(staleAttempt.stdout).not.toContain("NO_CANDIDATE");
    expect(await digest(resolve(reusedOut, "nomination.json"))).toBe(originalNominationDigest);

    const run = runCli([
      "nominate", "--spec", impossibleSpecPath, "--measurements", DEV, "--out", out,
    ]);

    expect(run.status, run.stderr).toBe(0);
    expect(run.stdout).toContain("NO_CANDIDATE");
    expect(await readdir(out)).toEqual([
      "development-report.json",
      "next-experiment.json",
      "report.md",
    ]);
    expect((await json(resolve(out, "development-report.json"))).status).toBe("NO_CANDIDATE");
    const report = await readFile(resolve(out, "report.md"), "utf8");
    expect(report).toContain("SYNTHETIC / DEMO ONLY");
    expect(report).toMatch(/failed gates/i);

    const development = await json(resolve(out, "development-report.json"));
    const nextExperiment = await json(resolve(out, "next-experiment.json"));
    expect(nextExperiment.trigger).toContain("cascade-47a5ff94080a050b");
    expect(nextExperiment.trigger).toContain("mean_task_score");
    expect(nextExperiment.trigger).toMatch(/does not meet required/);
    expect(nextExperiment.technique).toMatch(/routing/i);

    const spec = parseInferenceSpec(impossibleSpec);
    const measurements = parseMeasurementSet(await json(DEV), "dev");
    expect(proposeNextExperiment(development as any, { spec, measurements }))
      .toEqual(nextExperiment);
  });

  it("links a dominant TTFT failure only to techniques supported by measured workload evidence", async () => {
    const root = await mkdtemp(resolve(tmpdir(), "tasc-ttft-"));
    const specPath = resolve(root, "spec.json");
    const out = resolve(root, "out");
    const ttftSpec = await json(SPEC);
    ttftSpec.constraints.maxP95TtftMs = 1000;
    await writeFile(specPath, `${JSON.stringify(ttftSpec, null, 2)}\n`);

    const run = runCli([
      "nominate", "--spec", specPath, "--measurements", DEV, "--out", out,
    ]);

    expect(run.status, run.stderr).toBe(0);
    expect(run.stdout).toContain("NO_CANDIDATE");
    const proposal = await json(resolve(out, "next-experiment.json"));
    expect(proposal.trigger).toContain("cascade-47a5ff94080a050b");
    expect(proposal.trigger).toContain("p95_ttft");
    expect(proposal.trigger).toMatch(/does not meet required/);
    expect(proposal.technique).toMatch(/prefix cach/i);
    expect(proposal.technique).toMatch(/chunked prefill/i);
  });

  it("keeps synthetic HOLD provenance explicit and requires it at report-builder runtime", async () => {
    const root = await mkdtemp(resolve(tmpdir(), "tasc-hold-"));
    const devOut = resolve(root, "dev");
    const holdoutPath = resolve(root, "holdout.json");
    const holdoutOut = resolve(root, "holdout-out");
    const nominated = runCli([
      "nominate", "--spec", SPEC, "--measurements", DEV, "--out", devOut,
    ]);
    expect(nominated.status, nominated.stderr).toBe(0);

    const failingHoldout = await json(HOLDOUT);
    const critical = failingHoldout.cases.find((entry: any) => entry.critical);
    critical.observations
      .find((entry: any) => entry.profileId === "expert")
      .replicates[0].taskScore = 0.2;
    await writeFile(holdoutPath, `${JSON.stringify(failingHoldout, null, 2)}\n`);

    const confirmed = runCli([
      "confirm",
      "--spec", SPEC,
      "--measurements", holdoutPath,
      "--nomination", resolve(devOut, "nomination.json"),
      "--out", holdoutOut,
    ]);
    expect(confirmed.status, confirmed.stderr).toBe(0);
    expect(confirmed.stdout).toContain("HOLD");
    const confirmation = await json(resolve(holdoutOut, "confirmation.json"));
    expect(confirmation.status).toBe("HOLD");
    const report = await readFile(resolve(holdoutOut, "report.md"), "utf8");
    expect(report).toContain("SYNTHETIC / DEMO ONLY");
    expect(buildConfirmationReport(confirmation as any, { synthetic: true }))
      .toContain("SYNTHETIC / DEMO ONLY");
    expect(() => (buildConfirmationReport as any)(confirmation)).toThrow(/provenance.*synthetic/i);
  });

  it("uses only the environment attestation key and rejects coherently edited signed nominations", async () => {
    const root = await mkdtemp(resolve(tmpdir(), "tasc-keyed-"));
    const devOut = resolve(root, "dev");
    const editedPath = resolve(root, "edited.json");
    const key = "task3-test-attestation-key-at-least-32-bytes";
    const nominated = runCli([
      "nominate", "--spec", SPEC, "--measurements", DEV, "--out", devOut,
    ], { TASC_ATTESTATION_KEY: key });
    expect(nominated.status, nominated.stderr).toBe(0);

    const confirmedOut = resolve(root, "confirmed");
    const confirmed = runCli([
      "confirm",
      "--spec", SPEC,
      "--measurements", HOLDOUT,
      "--nomination", resolve(devOut, "nomination.json"),
      "--out", confirmedOut,
    ], { TASC_ATTESTATION_KEY: key });
    expect(confirmed.status, confirmed.stderr).toBe(0);
    expect(confirmed.stdout).toContain("DEMO_ONLY");

    for (const directory of [devOut, confirmedOut]) {
      for (const filename of await readdir(directory)) {
        expect(await readFile(resolve(directory, filename), "utf8")).not.toContain(key);
      }
    }

    const nomination = await json(resolve(devOut, "nomination.json"));
    nomination.developmentGroupIds = [];
    const {
      selfDigest: _selfDigest,
      attestation: _attestation,
      ...publicBody
    } = nomination;
    nomination.selfDigest = sha256(stableJson(publicBody));
    await writeFile(editedPath, `${JSON.stringify(nomination, null, 2)}\n`);

    const tampered = runCli([
      "confirm",
      "--spec", SPEC,
      "--measurements", HOLDOUT,
      "--nomination", editedPath,
      "--out", resolve(root, "holdout"),
    ], { TASC_ATTESTATION_KEY: key });
    expect(tampered.status).not.toBe(0);
    expect(tampered.stderr).toMatch(/attestation mismatch/i);
    expect(tampered.stderr).not.toContain(key);
  }, 30_000);

  it("returns clear non-zero errors for invalid arguments and malformed or edited nominations", async () => {
    const root = await mkdtemp(resolve(tmpdir(), "tasc-cli-errors-"));
    const devOut = resolve(root, "dev");
    expect(runCli(["nominate", "--spec", SPEC]).status).not.toBe(0);
    expect(runCli([
      "nominate", "--spec", SPEC, "--measurements", DEV, "--out", devOut, "--attestation-key", "secret",
    ]).status).not.toBe(0);

    const nominated = runCli([
      "nominate", "--spec", SPEC, "--measurements", DEV, "--out", devOut,
    ]);
    expect(nominated.status, nominated.stderr).toBe(0);

    const malformedPath = resolve(root, "malformed.json");
    await writeFile(malformedPath, "{}\n");
    const malformed = runCli([
      "confirm",
      "--spec", SPEC,
      "--measurements", HOLDOUT,
      "--nomination", malformedPath,
      "--out", resolve(root, "malformed-out"),
    ]);
    expect(malformed.status).not.toBe(0);
    expect(malformed.stderr).toMatch(/invalid nomination/i);
    expect(malformed.stderr).not.toMatch(/TypeError/);

    const editedPath = resolve(root, "edited.json");
    const edited = await json(resolve(devOut, "nomination.json"));
    edited.policy.confidenceThreshold = 0.123;
    await writeFile(editedPath, `${JSON.stringify(edited, null, 2)}\n`);
    const tampered = runCli([
      "confirm",
      "--spec", SPEC,
      "--measurements", HOLDOUT,
      "--nomination", editedPath,
      "--out", resolve(root, "edited-out"),
    ]);
    expect(tampered.status).not.toBe(0);
    expect(tampered.stderr).toMatch(/self-digest|edited/i);
  }, 30_000);
});
