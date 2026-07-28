import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { mkdtemp, realpath } from "node:fs/promises";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import {
  NO_DEPLOYMENT_AUTHORITY,
  assessPolicyWindow,
  canonicalJson,
  isDevelopmentNomination,
  joinAssessmentEvidence,
  nominateDevelopment,
  parseAssessmentContext,
  parseEvaluatorEvidence,
  parseEvaluatorTrustSnapshot,
  parseExperimentProtocol,
  parseTraceEnvelope,
  parseWindowManifest,
  proposeExperiment,
  readArtifactPacketIfPresent,
  readBoundedJson,
  readBoundedNdjson,
  requireAssessmentDatasetSplit,
  verifyArtifactPacket,
  verifyEvaluatorEvidence,
  verifyTraceDispatchIntent,
  writeArtifactPacket,
  type ArtifactPacketInput,
  type AssessmentContext,
  type EvaluatorEvidenceVerification,
  type EvaluatorTrustSnapshot,
  type ExperimentProtocol,
  type TraceEnvelope,
  type WorkBudget,
} from "../src/index.js";

const repositoryRoot = resolve(import.meta.dirname, "..");
const fixtureRoot = resolve(repositoryRoot, "examples/control-plane");
const JSON_LIMITS = Object.freeze({
  maxBytes: 512 * 1024,
  maxDepth: 32,
  maxObjectKeys: 8_192,
  maxArrayItems: 1_024,
  maxTokens: 100_000,
  maxDecodedStringLength: 16_384,
  maxNumericTokenLength: 64,
  maxDiagnosticSnippetLength: 0,
});
const NDJSON_LIMITS = Object.freeze({
  ...JSON_LIMITS,
  maxBytes: 2 * 1024 * 1024,
  maxLineBytes: 256 * 1024,
  maxItems: 64,
});
const WORK_BUDGET_FIELDS = [
  "maxAssessmentWork",
  "maxBootstrapDraws",
  "maxCandidates",
  "maxEvidenceRows",
  "maxIndependentGroups",
  "maxTraceRows",
] as const satisfies readonly (keyof WorkBudget)[];

function parseWorkBudget(input: unknown): WorkBudget {
  if (
    input === null
    || typeof input !== "object"
    || Array.isArray(input)
  ) {
    throw new Error("assessment work budget must be an object");
  }
  const record = input as Record<string, unknown>;
  const keys = Object.keys(record).sort();
  if (
    keys.length !== WORK_BUDGET_FIELDS.length
    || keys.some((key, index) => key !== WORK_BUDGET_FIELDS[index])
  ) {
    throw new Error("assessment work budget has unexpected fields");
  }
  const budget: Record<string, number> = {};
  for (const field of WORK_BUDGET_FIELDS) {
    const value = record[field];
    if (!Number.isSafeInteger(value) || (value as number) < 0) {
      throw new Error(`assessment work budget ${field} is invalid`);
    }
    budget[field] = value as number;
  }
  return Object.freeze(budget) as unknown as WorkBudget;
}

async function readFixtureJson(name: string): Promise<unknown> {
  return readBoundedJson(
    createReadStream(resolve(fixtureRoot, name)),
    JSON_LIMITS,
  );
}

async function readFixtureNdjson(name: string): Promise<readonly unknown[]> {
  return readBoundedNdjson(
    createReadStream(resolve(fixtureRoot, name)),
    NDJSON_LIMITS,
  );
}

async function loadTraceSet(
  name: string,
  protocol: ExperimentProtocol,
  workBudget: WorkBudget,
): Promise<readonly TraceEnvelope[]> {
  const rows = await readFixtureNdjson(name);
  return Object.freeze(rows.map((row) => {
    const parsed = parseTraceEnvelope(row, workBudget);
    return verifyTraceDispatchIntent(parsed, protocol);
  }));
}

async function loadEvidenceReceipts(
  name: string,
  trustSnapshot: EvaluatorTrustSnapshot,
  context: AssessmentContext,
  workBudget: WorkBudget,
): Promise<readonly EvaluatorEvidenceVerification[]> {
  const rows = await readFixtureNdjson(name);
  const receipts = rows.map((row) => verifyEvaluatorEvidence(
    parseEvaluatorEvidence(row, workBudget),
    trustSnapshot,
    context,
  ));
  const rejected = receipts.filter(({ trusted }) => !trusted);
  if (rejected.length > 0) {
    throw new Error(
      `${name} contains ${rejected.length} untrusted evaluator records`,
    );
  }
  return Object.freeze(receipts);
}

function artifactPayload(
  name: string,
  schemaVersion: string,
  value: unknown,
) {
  return Object.freeze({
    name,
    bytes: `${canonicalJson(value)}\n`,
    mediaType: "application/json",
    schemaVersion,
  });
}

function artifactPacket(
  kind: string,
  assessmentDecisionDigest: string | null,
  assessmentContextDigest: string | null,
  files: ArtifactPacketInput["files"],
): ArtifactPacketInput {
  return Object.freeze({
    descriptor: Object.freeze({
      version: "tasc-artifact-packet-v1" as const,
      kind,
      assessmentDecisionDigest,
      assessmentContextDigest,
      attestation: "unattested" as const,
    }),
    files: Object.freeze(files),
  });
}

const [
  protocolInput,
  trustInput,
  developmentContextInput,
  onlineContextInput,
  workBudgetInput,
  historyInput,
  experimentBudgetInput,
  windowManifestInput,
] = await Promise.all([
  readFixtureJson("protocol.json"),
  readFixtureJson("trust-snapshot.json"),
  readFixtureJson("development-context.json"),
  readFixtureJson("online-context.json"),
  readFixtureJson("work-budget.json"),
  readFixtureJson("experiment-history.json"),
  readFixtureJson("experiment-budget.json"),
  readFixtureJson("window-manifest.json"),
]);

const workBudget = parseWorkBudget(workBudgetInput);
const protocol = parseExperimentProtocol(protocolInput, workBudget);
const trustSnapshot = parseEvaluatorTrustSnapshot(trustInput);
const developmentContext = parseAssessmentContext(developmentContextInput);
const onlineContext = parseAssessmentContext(onlineContextInput);
const windowManifest = parseWindowManifest(windowManifestInput);

const [
  developmentTraces,
  developmentReceipts,
  onlineTraces,
  onlineReceipts,
] = await Promise.all([
  loadTraceSet("development-traces.ndjson", protocol, workBudget),
  loadEvidenceReceipts(
    "development-evidence.ndjson",
    trustSnapshot,
    developmentContext,
    workBudget,
  ),
  loadTraceSet("online-traces.ndjson", protocol, workBudget),
  loadEvidenceReceipts(
    "online-evidence.ndjson",
    trustSnapshot,
    onlineContext,
    workBudget,
  ),
]);

const developmentDataset = requireAssessmentDatasetSplit(
  joinAssessmentEvidence(
    protocol,
    developmentTraces,
    developmentReceipts,
    workBudget,
  ),
  "dev",
);
const developmentDecision = nominateDevelopment(
  protocol,
  developmentDataset,
  developmentContext,
  workBudget,
);
if (!isDevelopmentNomination(developmentDecision)) {
  throw new Error(
    `synthetic development fixture did not nominate: `
    + developmentDecision.status,
  );
}

const onlineDataset = requireAssessmentDatasetSplit(
  joinAssessmentEvidence(
    protocol,
    onlineTraces,
    onlineReceipts,
    workBudget,
  ),
  "online",
);
const windowDecision = assessPolicyWindow(
  protocol,
  onlineDataset,
  developmentDecision.selectedPolicy,
  windowManifest,
  onlineContext,
  workBudget,
);
const experimentDecision = proposeExperiment(
  windowDecision,
  historyInput,
  experimentBudgetInput,
);

const selectedDevelopment = developmentDecision.candidates.find(
  ({ policyDigest }) =>
    policyDigest === developmentDecision.selectedPolicyDigest,
);
if (selectedDevelopment === undefined) {
  throw new Error("selected development policy assessment is missing");
}
const windowCandidate = windowDecision.candidates[0];
if (windowCandidate === undefined) {
  throw new Error("sealed window policy assessment is missing");
}
if (
  windowCandidate.metrics.serviceCapacity.value !== null
  || windowCandidate.metrics.serviceCapacity.evidenceClass !== "unavailable"
) {
  throw new Error("synthetic window must preserve unavailable capacity");
}

const recommendation = Object.freeze({
  version: "tasc-policy-recommendation-v1",
  recommendation: "HOLD_FOR_TRUSTED_CAPACITY_EVIDENCE",
  frozenPolicy: developmentDecision.selectedPolicy,
  developmentDecisionDigest: developmentDecision.decisionDigest,
  windowDecisionDigest: windowDecision.decisionDigest,
  windowManifestDigest: windowManifest.selfDigest,
  nextExperimentDecisionDigest: experimentDecision.decisionDigest,
  capacityEvidence: {
    value: null,
    evidenceClass: windowCandidate.metrics.serviceCapacity.evidenceClass,
    reason: windowCandidate.metrics.serviceCapacity.reason,
  },
  attestation: "unattested",
  authority: NO_DEPLOYMENT_AUTHORITY,
});

const canonicalTemporaryRoot = await realpath(tmpdir());
const artifactRoot = await mkdtemp(
  resolve(canonicalTemporaryRoot, "tasc-control-plane-demo-"),
);
const packets = [
  {
    target: "development-assessment",
    input: artifactPacket(
      "development-assessment",
      developmentDecision.decisionDigest,
      developmentContext.contextDigest,
      [
        artifactPayload(
          "assessment.json",
          "tasc-assessment-decision-v2",
          developmentDecision,
        ),
        artifactPayload(
          "policy.json",
          "tasc-policy-bundle-v2",
          developmentDecision.selectedPolicy,
        ),
      ],
    ),
  },
  {
    target: "sealed-window-assessment",
    input: artifactPacket(
      "sealed-window-assessment",
      windowDecision.decisionDigest,
      onlineContext.contextDigest,
      [
        artifactPayload(
          "assessment.json",
          "tasc-assessment-decision-v2",
          windowDecision,
        ),
        artifactPayload(
          "window-manifest.json",
          "tasc-window-manifest-v2",
          windowManifest,
        ),
      ],
    ),
  },
  {
    target: "next-experiment",
    input: artifactPacket(
      "next-experiment",
      windowDecision.decisionDigest,
      onlineContext.contextDigest,
      [
        artifactPayload(
          "proposal.json",
          "tasc-experiment-proposal-decision-v2",
          experimentDecision,
        ),
      ],
    ),
  },
  {
    target: "policy-recommendation",
    input: artifactPacket(
      "policy-recommendation",
      windowDecision.decisionDigest,
      onlineContext.contextDigest,
      [
        artifactPayload(
          "recommendation.json",
          "tasc-policy-recommendation-v1",
          recommendation,
        ),
      ],
    ),
  },
] as const;

const written = await Promise.all(packets.map(async ({ target, input }) => ({
  target,
  result: await writeArtifactPacket(artifactRoot, target, input),
})));

for (const { target, result } of written) {
  const verified = await verifyArtifactPacket(artifactRoot, target, {
    expectedManifestDigest: result.manifest.manifestDigest,
  });
  if (
    verified.manifest.manifestDigest !== result.manifest.manifestDigest
    || verified.manifest.packetDigest !== result.manifest.packetDigest
    || verified.manifest.completion.authority !== NO_DEPLOYMENT_AUTHORITY
  ) {
    throw new Error(`artifact manifest verification drifted for ${target}`);
  }
  const read = await readArtifactPacketIfPresent(artifactRoot, target, {
    expectedManifestDigest: result.manifest.manifestDigest,
  });
  if (read === null) {
    throw new Error(`verified artifact disappeared for ${target}`);
  }
  for (const payload of read.files) {
    const manifestFile = read.manifest.files.find(
      ({ name }) => name === payload.name,
    );
    const digest = createHash("sha256")
      .update(payload.copyBytes())
      .digest("hex");
    if (manifestFile === undefined || manifestFile.sha256 !== digest) {
      throw new Error(`artifact payload digest mismatch for ${target}`);
    }
  }
}

const developmentCriticalCoverage =
  selectedDevelopment.coverage.criticalSliceGroups.find(
    ({ sliceId }) => sliceId === "account-recovery",
  )?.groupCount ?? 0;
const onlineCriticalCoverage =
  windowCandidate.coverage.criticalSliceGroups.find(
    ({ sliceId }) => sliceId === "account-recovery",
  )?.groupCount ?? 0;
const packetDigests = written
  .map(({ target, result }) => `${target}=${result.manifest.packetDigest}`)
  .sort()
  .join(",");

process.stdout.write(
  "TASC CONTROL PLANE DEMO\n"
  + "mode: OFFLINE_FIXTURE_REPLAY\n"
  + "network calls: 0\n"
  + "model calls: 0\n"
  + `dispatch intents: ${
    developmentTraces.length + onlineTraces.length
  }/${developmentTraces.length + onlineTraces.length} verified\n`
  + `evaluator evidence: ${
    developmentReceipts.length + onlineReceipts.length
  }/${developmentReceipts.length + onlineReceipts.length} trusted\n`
  + `development: ${developmentDecision.status}\n`
  + `selected policy kind: ${developmentDecision.selectedPolicy.kind}\n`
  + `selected policy digest: ${developmentDecision.selectedPolicyDigest}\n`
  + `development coverage: groups=${
    selectedDevelopment.coverage.groupCount
  } account-recovery-groups=${developmentCriticalCoverage} evidence=${
    selectedDevelopment.coverage.evidenceCoverage.toFixed(2)
  }\n`
  + `sealed window: ${windowDecision.status}\n`
  + `window coverage: groups=${
    windowCandidate.coverage.groupCount
  } account-recovery-groups=${onlineCriticalCoverage} evidence=${
    windowCandidate.coverage.evidenceCoverage.toFixed(2)
  }\n`
  + "service capacity: UNAVAILABLE "
  + `(${windowCandidate.metrics.serviceCapacity.reason})\n`
  + `next experiment: ${experimentDecision.status} `
  + `(${experimentDecision.status === "PROPOSED"
    ? experimentDecision.diagnosis
    : experimentDecision.holdReason})\n`
  + `recommendation: ${recommendation.recommendation}\n`
  + `authority: ${NO_DEPLOYMENT_AUTHORITY}\n`
  + `artifact packets: ${packetDigests}\n`
  + `artifact verification: ${written.length}/${written.length} `
  + "manifests and payload digests verified\n"
  + `artifact root: ${artifactRoot}\n`,
);
