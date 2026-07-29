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
  parseControllerSnapshot,
  parseEvaluatorEvidence,
  parseEvaluatorTrustSnapshot,
  parseExperimentProtocol,
  parseShadowRunPlan,
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
import {
  authorizeCollectorRequest,
  fingerprintCollectorEndpointBinding,
  fingerprintRuntimeWireProfile,
  getRuntimeProfile,
  parseCollectorTrustPolicy,
  parseRuntimeInstanceIdentity,
  type RuntimeInstanceIdentity,
} from "../src/runtime/index.js";

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

interface AdmissionEndpoint {
  readonly schemaVersion: "tasc-cli-runtime-endpoint-v1";
  readonly endpointAlias: string;
}

interface AdmissionTarget {
  readonly profileId: string;
  readonly endpoint: AdmissionEndpoint;
  readonly instance: RuntimeInstanceIdentity;
  readonly route: "completions";
  readonly httpLimits: {
    readonly deadlineMs: number;
    readonly maxRequestBytes: number;
    readonly maxResponseBytes: number;
  };
}

function strictRecord(
  input: unknown,
  label: string,
): Record<string, unknown> {
  if (
    input === null
    || typeof input !== "object"
    || Array.isArray(input)
    || Object.getPrototypeOf(input) !== Object.prototype
  ) {
    throw new Error(`${label} must be a plain object`);
  }
  return input as Record<string, unknown>;
}

function exactKeys(
  record: Record<string, unknown>,
  keys: readonly string[],
  label: string,
): void {
  const actual = Object.keys(record).sort();
  const expected = [...keys].sort();
  if (
    actual.length !== expected.length
    || actual.some((key, index) => key !== expected[index])
  ) {
    throw new Error(`${label} has unexpected fields`);
  }
}

function parseAdmissionTargets(input: unknown): readonly AdmissionTarget[] {
  const root = strictRecord(input, "shadow profiles");
  exactKeys(root, ["schemaVersion", "targets"], "shadow profiles");
  if (
    root.schemaVersion !== "tasc-cli-shadow-profiles-v2"
    || !Array.isArray(root.targets)
    || root.targets.length < 2
    || root.targets.length > 16
  ) {
    throw new Error("shadow profiles fixture is invalid");
  }
  const targets = root.targets.map((inputTarget) => {
    const target = strictRecord(inputTarget, "shadow target");
    exactKeys(
      target,
      ["endpoint", "httpLimits", "instance", "profileId", "route"],
      "shadow target",
    );
    const endpoint = strictRecord(target.endpoint, "shadow endpoint");
    exactKeys(
      endpoint,
      ["endpointAlias", "schemaVersion"],
      "shadow endpoint",
    );
    if (
      typeof target.profileId !== "string"
      || target.route !== "completions"
      || endpoint.schemaVersion !== "tasc-cli-runtime-endpoint-v1"
      || typeof endpoint.endpointAlias !== "string"
    ) {
      throw new Error("shadow target identity is invalid");
    }
    const limits = strictRecord(target.httpLimits, "shadow HTTP limits");
    exactKeys(
      limits,
      ["deadlineMs", "maxRequestBytes", "maxResponseBytes"],
      "shadow HTTP limits",
    );
    if (
      limits.deadlineMs !== 10_000
      || limits.maxRequestBytes !== 1_048_576
      || limits.maxResponseBytes !== 8_388_608
    ) {
      throw new Error("shadow target limits drifted from the P0 budget");
    }
    return Object.freeze({
      profileId: target.profileId,
      endpoint: Object.freeze({
        schemaVersion: endpoint.schemaVersion,
        endpointAlias: endpoint.endpointAlias,
      }),
      instance: parseRuntimeInstanceIdentity(target.instance),
      route: target.route,
      httpLimits: Object.freeze({
        deadlineMs: limits.deadlineMs,
        maxRequestBytes: limits.maxRequestBytes,
        maxResponseBytes: limits.maxResponseBytes,
      }),
    });
  });
  if (
    new Set(targets.map(({ profileId }) => profileId)).size
      !== targets.length
  ) {
    throw new Error("shadow profiles contain duplicate targets");
  }
  return Object.freeze(targets);
}

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
  controllerSnapshotInput,
  shadowRunPlanInput,
  collectorTrustInput,
  shadowProfilesInput,
] = await Promise.all([
  readFixtureJson("protocol.json"),
  readFixtureJson("trust-snapshot.json"),
  readFixtureJson("development-context.json"),
  readFixtureJson("online-context.json"),
  readFixtureJson("work-budget.json"),
  readFixtureJson("experiment-history.json"),
  readFixtureJson("experiment-budget.json"),
  readFixtureJson("window-manifest.json"),
  readFixtureJson("controller-snapshot.json"),
  readFixtureJson("shadow-run-plan.json"),
  readFixtureJson("collector-trust.json"),
  readFixtureJson("shadow-profiles.json"),
]);

const workBudget = parseWorkBudget(workBudgetInput);
const protocol = parseExperimentProtocol(protocolInput, workBudget);
const trustSnapshot = parseEvaluatorTrustSnapshot(trustInput);
const developmentContext = parseAssessmentContext(developmentContextInput);
const onlineContext = parseAssessmentContext(onlineContextInput);
const windowManifest = parseWindowManifest(windowManifestInput);
const controllerSnapshot = parseControllerSnapshot(
  controllerSnapshotInput,
);
const shadowRunPlan = parseShadowRunPlan(shadowRunPlanInput);
const collectorTrust = parseCollectorTrustPolicy(collectorTrustInput);
const admissionTargets = parseAdmissionTargets(shadowProfilesInput);
if (
  canonicalJson(shadowRunPlan.controllerSnapshot)
    !== canonicalJson(controllerSnapshot)
  || controllerSnapshot.state !== "SHADOW_ASSESSING"
  || shadowRunPlan.controllerSnapshotDigest
    !== controllerSnapshot.snapshotDigest
  || shadowRunPlan.protocolDigest !== windowManifest.protocolDigest
  || canonicalJson(shadowRunPlan.protocol) !== canonicalJson(protocol)
  || shadowRunPlan.window.windowId !== windowManifest.windowId
  || shadowRunPlan.window.membershipDigest
    !== windowManifest.membershipDigest
  || shadowRunPlan.window.eventTimeStartInclusive
    !== windowManifest.eventTimeStartInclusive
  || shadowRunPlan.window.eventTimeEndExclusive
    !== windowManifest.eventTimeEndExclusive
) {
  throw new Error(
    "P0 shadow plan does not match its committed controller/protocol/window",
  );
}

const admissionTargetByProfile = new Map(
  admissionTargets.map((target) => [target.profileId, target]),
);
let admittedTargetCount = 0;
for (const planTarget of shadowRunPlan.collectionTargets) {
  const target = admissionTargetByProfile.get(planTarget.profileId);
  const executionProfile = protocol.profiles.find(
    ({ id }) => id === planTarget.profileId,
  );
  if (
    target === undefined
    || executionProfile === undefined
    || target.route !== "completions"
    || planTarget.route !== "completions"
    || target.endpoint.endpointAlias !== planTarget.endpointAlias
    || target.instance.endpointDescriptorDigest
      !== planTarget.endpointBindingDigest
    || planTarget.authenticationReference !== null
    || target.instance.runtime.profileId !== planTarget.runtimeName
    || target.instance.runtime.build !== executionProfile.runtime.build
    || target.instance.backend.name !== executionProfile.backend.name
    || target.instance.backend.build !== executionProfile.backend.build
    || target.instance.model.id !== executionProfile.model.id
    || target.instance.model.revision !== executionProfile.model.revision
    || target.instance.configurationDigest
      !== executionProfile.deploymentConfigurationDigest
  ) {
    throw new Error(
      "P1 runtime metadata does not match its exact plan/protocol target",
    );
  }
  const registry = getRuntimeProfile(target.instance.runtime.profileId);
  const route = registry.endpoints.inference.completions;
  const trustedEndpoint = collectorTrust.endpoints.find(
    ({ alias }) => alias === target.endpoint.endpointAlias,
  );
  if (
    target.instance.runtime.build !== registry.runtime.build
    || executionProfile.runtime.name !== registry.id
    || route === undefined
    || route.method !== "POST"
    || route.capability !== "completions"
    || registry.capabilities.completions.state !== "supported"
    || trustedEndpoint?.runtime.profileId !== registry.id
    || trustedEndpoint.runtime.build !== registry.runtime.build
    || new URL(trustedEndpoint.origin).protocol !== "https:"
    || fingerprintCollectorEndpointBinding(
      collectorTrust,
      target.endpoint.endpointAlias,
    ) !== planTarget.endpointBindingDigest
    || !/^sha256:[a-f0-9]{64}$/u.test(
      fingerprintRuntimeWireProfile(registry),
    )
  ) {
    throw new Error(
      "P1 runtime target is not admitted by its pinned public metadata",
    );
  }
  authorizeCollectorRequest(collectorTrust, {
    endpointAlias: target.endpoint.endpointAlias,
    runtime: target.instance.runtime,
    method: route.method,
    path: route.path,
  });
  admittedTargetCount += 1;
}
if (
  admissionTargetByProfile.size !== shadowRunPlan.collectionTargets.length
  || admittedTargetCount !== shadowRunPlan.collectionTargets.length
  || protocol.requiredCapabilities.length !== 0
  || shadowRunPlan.collectionTargets.some(
    ({ capabilityReceiptDigests }) =>
      capabilityReceiptDigests.length !== 0,
  )
) {
  throw new Error(
    "P0 work/capability budget is not honestly executable by P1 admission",
  );
}

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

const planTargets = new Map(
  shadowRunPlan.collectionTargets.map((target) => [
    target.profileId,
    target,
  ]),
);
const observedPlanTargets = new Set<string>();
for (const trace of onlineTraces) {
  const target = planTargets.get(trace.profileId);
  const binding = trace.collectionBinding;
  if (
    target === undefined
    || binding === null
    || binding.shadowPlanDigest !== shadowRunPlan.planDigest
    || binding.endpointAlias !== target.endpointAlias
    || binding.endpointBindingDigest !== target.endpointBindingDigest
    || binding.route !== target.route
    || binding.authenticationReference !== target.authenticationReference
    || canonicalJson(binding.capabilityReceiptDigests)
      !== canonicalJson(target.capabilityReceiptDigests)
    || trace.policyDigest !== shadowRunPlan.frozenPolicyDigest
    || trace.collectionWindowId !== shadowRunPlan.window.windowId
    || trace.collectionWindowMembershipDigest
      !== shadowRunPlan.window.membershipDigest
  ) {
    throw new Error(
      "online trace is not bound to its exact P0 shadow-plan target",
    );
  }
  observedPlanTargets.add(trace.profileId);
}
if (
  onlineTraces.length > shadowRunPlan.workBudget.maxLogicalExecutions
  || observedPlanTargets.size !== planTargets.size
  || [...planTargets.keys()].some(
    (profileId) => !observedPlanTargets.has(profileId),
  )
) {
  throw new Error(
    "online trace set does not cover the bounded P0 target set",
  );
}

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
const controllerDevelopment = controllerSnapshot.assessments.find(
  ({ phase }) => phase === "development",
);
if (
  controllerSnapshot.developmentEvidence === null
  || controllerSnapshot.selectedPolicy === null
  || controllerDevelopment === undefined
  || controllerSnapshot.developmentEvidence.datasetDigest
    !== developmentDataset.datasetDigest
  || controllerSnapshot.developmentEvidence.traceSetDigest
    !== developmentDataset.traceSetDigest
  || controllerSnapshot.developmentEvidence.evaluatorSetDigest
    !== developmentDataset.evaluatorSetDigest
  || controllerDevelopment.decisionDigest
    !== developmentDecision.decisionDigest
  || controllerDevelopment.assessmentContextDigest
    !== developmentContext.contextDigest
  || canonicalJson(shadowRunPlan.frozenPolicy)
    !== canonicalJson(developmentDecision.selectedPolicy)
) {
  throw new Error(
    "P0 controller snapshot does not match development nomination evidence",
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
  + "controller snapshot: SHADOW_ASSESSING verified\n"
  + `P1 static admission: ${admittedTargetCount}/${
    shadowRunPlan.collectionTargets.length
  } registry-pinned completions targets authorized\n`
  + `P0 -> P1 lineage: ${onlineTraces.length}/${onlineTraces.length} `
  + `online traces bound to ${observedPlanTargets.size}/${
    planTargets.size
  } plan targets\n`
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
