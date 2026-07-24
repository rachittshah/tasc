import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { spawnSync } from "node:child_process";

const repositoryRoot = resolve(import.meta.dirname, "..");
const artifactRoot = await mkdtemp(resolve(tmpdir(), "tasc-demo-"));
const developmentOutput = resolve(artifactRoot, "development");
const holdoutOutput = resolve(artifactRoot, "holdout");
const cli = resolve(repositoryRoot, "src/cli.ts");
const spec = resolve(repositoryRoot, "examples/synthetic/spec.json");
const development = resolve(repositoryRoot, "examples/synthetic/dev.json");
const holdout = resolve(repositoryRoot, "examples/synthetic/holdout.json");

function run(arguments_: string[]): void {
  const result = spawnSync(process.execPath, ["--import", "tsx", cli, ...arguments_], {
    cwd: repositoryRoot,
    encoding: "utf8",
    env: Object.fromEntries(
      Object.entries(process.env).filter(([key]) => key !== "TASC_ATTESTATION_KEY"),
    ),
  });
  process.stdout.write(result.stdout);
  process.stderr.write(result.stderr);
  if (result.status !== 0) {
    throw new Error(`TASC demo command failed with status ${result.status ?? "unknown"}`);
  }
}

run([
  "nominate",
  "--spec",
  spec,
  "--measurements",
  development,
  "--out",
  developmentOutput,
]);
run([
  "confirm",
  "--spec",
  spec,
  "--measurements",
  holdout,
  "--nomination",
  resolve(developmentOutput, "nomination.json"),
  "--out",
  holdoutOutput,
]);

process.stdout.write(`Synthetic artifacts: ${artifactRoot}\n`);
