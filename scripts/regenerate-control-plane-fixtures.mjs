import {
  createHash,
  createPrivateKey,
  createPublicKey,
  createSecretKey,
  sign,
} from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import {
  assessPolicyWindow,
  buildShadowRunPlan,
  canonicalJson,
  collectorAttestationSigningBytes,
  createControllerSnapshot,
  createStudyPayloadIdentity,
  dispatchIntentSigningBytes,
  evaluatorEvidenceSigningBytes,
  fingerprintEvaluatorRevocations,
  fingerprintEvaluatorTrustPolicy,
  fingerprintExecutionProfile,
  fingerprintRuntimeInvocationHttpLimits,
  fingerprintProtocol,
  fingerprintWindowManifest,
  isDevelopmentNomination,
  joinAssessmentEvidence,
  nominateDevelopment,
  parseAssessmentContext,
  parseEvaluatorEvidence,
  parseEvaluatorTrustSnapshot,
  parseExperimentProtocol,
  parseTraceEnvelope,
  parseWindowManifest,
  requireAssessmentDatasetSplit,
  verifyEvaluatorEvidence,
  verifyTraceDispatchIntent,
} from "../src/index.js";
import { domainSeparatedDigest } from "../src/evidence.js";

const fixtureRoot = resolve(
  import.meta.dirname,
  "../examples/control-plane",
);

const DEVELOPMENT_CONTEXT_AS_OF = "2026-07-22T00:00:00.000Z";
const ONLINE_CONTEXT_AS_OF = "2026-07-24T00:00:00.000Z";
const WINDOW_START = "2026-07-23T00:00:00.000Z";
const WINDOW_END = "2026-07-23T00:01:30.000Z";
const WINDOW_WATERMARK = "2026-07-23T00:02:00.000Z";
const PLAN_ISSUED_AT = "2026-07-22T00:00:02.000Z";
const PAYLOAD_KEY_ID = "synthetic-study-payload-key";
const PUBLIC_FIXTURE_KEY_DOMAIN =
  "tasc/public-control-plane-fixture-key/v1";
const ED25519_PKCS8_SEED_PREFIX = Buffer.from(
  "302e020100300506032b657004220420",
  "hex",
);

/**
 * These deterministic keys are deliberately public test fixtures. They offer
 * reproducible signatures and identities only; they confer no production
 * authority and must never be reused for a real study.
 */
function publicFixtureSeed(label) {
  return createHash("sha256")
    .update(PUBLIC_FIXTURE_KEY_DOMAIN, "utf8")
    .update("\0", "utf8")
    .update(label, "utf8")
    .digest();
}

function publicFixtureEd25519KeyPair(label) {
  const privateKey = createPrivateKey({
    key: Buffer.concat([
      ED25519_PKCS8_SEED_PREFIX,
      publicFixtureSeed(label),
    ]),
    format: "der",
    type: "pkcs8",
  });
  return Object.freeze({
    privateKey,
    publicKey: createPublicKey(privateKey),
  });
}

async function readJson(name) {
  return JSON.parse(await readFile(resolve(fixtureRoot, name), "utf8"));
}

async function readRows(name) {
  return (await readFile(resolve(fixtureRoot, name), "utf8"))
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line));
}

async function writeJson(name, value) {
  await writeFile(
    resolve(fixtureRoot, name),
    `${JSON.stringify(value, null, 2)}\n`,
    "utf8",
  );
}

async function writeRows(name, values) {
  await writeFile(
    resolve(fixtureRoot, name),
    `${values.map((value) => canonicalJson(value)).join("\n")}\n`,
    "utf8",
  );
}

function clone(value) {
  return structuredClone(value);
}

function publicKeySpki(keyPair) {
  return keyPair.publicKey
    .export({ type: "spki", format: "der" })
    .toString("base64url");
}

function payloadIdentity(payloadKey, studyId, label) {
  return createStudyPayloadIdentity(
    studyId,
    PAYLOAD_KEY_ID,
    payloadKey,
    Buffer.from(label, "utf8"),
  );
}

function resignTrace({
  input,
  protocol,
  protocolDigest,
  policyDigest,
  payloadKey,
  dispatchPrivateKey,
  collectorPrivateKey,
  plan,
  workBudget,
}) {
  const trace = clone(input);
  const profile = protocol.profiles.find(
    ({ id }) => id === trace.profileId,
  );
  if (profile === undefined) {
    throw new Error(`unknown fixture profile ${trace.profileId}`);
  }

  trace.protocolDigest = protocolDigest;
  trace.executionProfileDigest = fingerprintExecutionProfile(profile);
  trace.policyDigest = policyDigest;
  trace.dispatchIntent.authorityKeyId =
    protocol.dispatchAuthority.keyId;
  trace.dispatchIntent.signatureAlgorithm =
    protocol.dispatchAuthority.algorithm;
  trace.collectorAttestation.authorityKeyId =
    protocol.collectorAuthority.keyId;
  trace.collectorAttestation.signatureAlgorithm =
    protocol.collectorAuthority.algorithm;

  for (const attempt of trace.attempts) {
    attempt.payloads.request = payloadIdentity(
      payloadKey,
      protocol.studyId,
      `${trace.traceId}/${attempt.attemptId}/request`,
    );
    attempt.payloads.response = payloadIdentity(
      payloadKey,
      protocol.studyId,
      `${trace.traceId}/${attempt.attemptId}/response`,
    );
    attempt.payloads.eventStream = payloadIdentity(
      payloadKey,
      protocol.studyId,
      `${trace.traceId}/${attempt.attemptId}/event-stream`,
    );
  }
  trace.terminalOutputId = payloadIdentity(
    payloadKey,
    protocol.studyId,
    `${trace.traceId}/terminal-output`,
  );

  if (plan === null) {
    trace.collectionWindowId = null;
    trace.collectionWindowMembershipDigest = null;
    trace.collectionBinding = null;
  } else {
    const target = plan.collectionTargets.find(
      ({ profileId }) => profileId === trace.profileId,
    );
    if (target === undefined) {
      throw new Error(`plan is missing fixture profile ${trace.profileId}`);
    }
    trace.collectionWindowId = plan.window.windowId;
    trace.collectionWindowMembershipDigest =
      plan.window.membershipDigest;
    trace.collectionBinding = {
      shadowPlanDigest: plan.planDigest,
      endpointAlias: target.endpointAlias,
      endpointBindingDigest: target.endpointBindingDigest,
      route: target.route,
      authenticationReference: target.authenticationReference,
      httpLimitsDigest: target.httpLimitsDigest,
      capabilityReceiptDigests: target.capabilityReceiptDigests,
    };
  }

  trace.dispatchIntent.signature = sign(
    null,
    dispatchIntentSigningBytes(trace),
    dispatchPrivateKey,
  ).toString("base64url");
  trace.collectorAttestation.signature = sign(
    null,
    collectorAttestationSigningBytes(trace),
    collectorPrivateKey,
  ).toString("base64url");
  return verifyTraceDispatchIntent(
    parseTraceEnvelope(trace, workBudget),
    protocol,
  );
}

function resignEvidence({
  input,
  traceById,
  protocolDigest,
  evaluatorKeyId,
  evaluatorPrivateKey,
  workBudget,
}) {
  const evidence = clone(input);
  const trace = traceById.get(evidence.traceId);
  if (trace === undefined) {
    throw new Error(`evidence has no trace ${evidence.traceId}`);
  }
  evidence.protocolDigest = protocolDigest;
  evidence.terminalOutputId = trace.terminalOutputId;
  evidence.keyId = evaluatorKeyId;
  evidence.source = {
    kind: "digest",
    digest: domainSeparatedDigest(
      "tasc/synthetic-evaluator-source/v1",
      {
        traceId: evidence.traceId,
        terminalOutputId: evidence.terminalOutputId,
        outcome: evidence.outcome,
      },
    ),
  };
  evidence.signature = sign(
    null,
    evaluatorEvidenceSigningBytes(evidence),
    evaluatorPrivateKey,
  ).toString("base64url");
  return parseEvaluatorEvidence(evidence, workBudget);
}

function verifyEvidenceSet(evidence, trust, context) {
  return Object.freeze(evidence.map((row) => {
    const verification = verifyEvaluatorEvidence(row, trust, context);
    if (!verification.trusted) {
      throw new Error(
        `fresh fixture evidence ${row.traceId} is not trusted`,
      );
    }
    return verification;
  }));
}

const [
  protocolInput,
  trustInput,
  developmentTraceInput,
  onlineTraceInput,
  developmentEvidenceInput,
  onlineEvidenceInput,
  oldPlan,
  shadowProfiles,
  workBudget,
] = await Promise.all([
  readJson("protocol.json"),
  readJson("trust-snapshot.json"),
  readRows("development-traces.ndjson"),
  readRows("online-traces.ndjson"),
  readRows("development-evidence.ndjson"),
  readRows("online-evidence.ndjson"),
  readJson("shadow-run-plan.json"),
  readJson("shadow-profiles.json"),
  readJson("work-budget.json"),
]);

// Public, deterministic fixture material is process-local and never serialized.
const dispatchKeys = publicFixtureEd25519KeyPair("dispatch-ed25519");
const collectorKeys = publicFixtureEd25519KeyPair("collector-ed25519");
const evaluatorKeys = publicFixtureEd25519KeyPair("evaluator-ed25519");
const payloadKey = createSecretKey(publicFixtureSeed("payload-hmac-sha256"));

protocolInput.dispatchAuthority.publicKeySpki =
  publicKeySpki(dispatchKeys);
protocolInput.collectorAuthority.publicKeySpki =
  publicKeySpki(collectorKeys);
const protocol = parseExperimentProtocol(protocolInput, workBudget);
const protocolDigest = fingerprintProtocol(protocol);

trustInput.keys[0].publicKeySpki = publicKeySpki(evaluatorKeys);
const trust = parseEvaluatorTrustSnapshot(trustInput);
const trustPolicyDigest = fingerprintEvaluatorTrustPolicy(trust);
const revocationDigest = fingerprintEvaluatorRevocations(trust);
const developmentContext = parseAssessmentContext({
  version: "tasc-assessment-context-v2",
  asOf: DEVELOPMENT_CONTEXT_AS_OF,
  operatorTrustPolicySnapshotDigest: trustPolicyDigest,
  evaluatorRevocationSnapshotDigest: revocationDigest,
});
const onlineContext = parseAssessmentContext({
  version: "tasc-assessment-context-v2",
  asOf: ONLINE_CONTEXT_AS_OF,
  operatorTrustPolicySnapshotDigest: trustPolicyDigest,
  evaluatorRevocationSnapshotDigest: revocationDigest,
});

const observedDevelopmentPolicyDigest = domainSeparatedDigest(
  "tasc/synthetic-observed-policy/v1",
  { protocolDigest },
);
const developmentTraces = developmentTraceInput.map((trace) =>
  resignTrace({
    input: trace,
    protocol,
    protocolDigest,
    policyDigest: observedDevelopmentPolicyDigest,
    payloadKey,
    dispatchPrivateKey: dispatchKeys.privateKey,
    collectorPrivateKey: collectorKeys.privateKey,
    plan: null,
    workBudget,
  })
);
const developmentTraceById = new Map(
  developmentTraces.map((trace) => [trace.traceId, trace]),
);
const developmentEvidence = developmentEvidenceInput.map((evidence) =>
  resignEvidence({
    input: evidence,
    traceById: developmentTraceById,
    protocolDigest,
    evaluatorKeyId: trust.keys[0].keyId,
    evaluatorPrivateKey: evaluatorKeys.privateKey,
    workBudget,
  })
);
const developmentReceipts = verifyEvidenceSet(
  developmentEvidence,
  trust,
  developmentContext,
);
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
  throw new Error("fresh development fixture did not nominate a policy");
}

const selectedPolicy = developmentDecision.selectedPolicy;
const selectedPolicyIdentity = {
  policyDigest: selectedPolicy.policyDigest,
  issuedAt: selectedPolicy.issuedAt,
  expiresAt: selectedPolicy.expiresAt,
};
const controllerSnapshot = createControllerSnapshot({
  version: "tasc-controller-snapshot-v1",
  controllerId: "synthetic-shadow-controller-1",
  studyId: protocol.studyId,
  protocolDigest,
  protocolCreatedAt: protocol.createdAt,
  protocolExpiresAt: protocol.expiresAt,
  state: "SHADOW_ASSESSING",
  sequence: 5,
  lastEventId: domainSeparatedDigest(
    "tasc/synthetic-controller-event/v1",
    { protocolDigest, sequence: 5 },
  ),
  lastEventAt: "2026-07-22T00:00:01.000Z",
  collectionId: "synthetic-shadow-collection-1",
  developmentEvidence: {
    datasetDigest: developmentDataset.datasetDigest,
    traceSetDigest: developmentDataset.traceSetDigest,
    evaluatorSetDigest: developmentDataset.evaluatorSetDigest,
  },
  selectedPolicy: selectedPolicyIdentity,
  assessments: [{
    version: "tasc-controller-assessment-projection-v1",
    phase: "development",
    status: "NOMINATED",
    decisionDigest: developmentDecision.decisionDigest,
    assessmentContextDigest: developmentContext.contextDigest,
    protocolDigest,
    datasetDigest: developmentDataset.datasetDigest,
    traceSetDigest: developmentDataset.traceSetDigest,
    evaluatorSetDigest: developmentDataset.evaluatorSetDigest,
    selectedPolicy: selectedPolicyIdentity,
    windowManifestDigest: null,
    attestation: "unattested",
  }],
  windows: [],
  deploymentObservation: null,
  staleReasons: [],
  attestation: "unattested",
});

const plan = buildShadowRunPlan({
  controllerSnapshot,
  protocol,
  frozenPolicy: selectedPolicy,
  window: {
    windowId: oldPlan.window.windowId,
    eventTimeStartInclusive: WINDOW_START,
    eventTimeEndExclusive: WINDOW_END,
  },
  collectionTargets: oldPlan.collectionTargets.map((target) => {
    const runtimeTarget = shadowProfiles.targets.find(
      ({ profileId }) => profileId === target.profileId,
    );
    if (runtimeTarget === undefined) {
      throw new Error(`profiles are missing fixture target ${target.profileId}`);
    }
    return {
      profileId: target.profileId,
      endpointAlias: target.endpointAlias,
      endpointBindingDigest: target.endpointBindingDigest,
      route: target.route,
      authenticationReference: target.authenticationReference ?? null,
      httpLimitsDigest:
        fingerprintRuntimeInvocationHttpLimits(runtimeTarget.httpLimits),
      capabilityReceiptDigests: target.capabilityReceiptDigests,
    };
  }),
  workBudget: {
    maxCases: 4,
    maxProfiles: 2,
    maxReplicates: 4,
    maxLogicalExecutions: 8,
    maxAttempts: 8,
    maxNetworkCalls: 8,
    maxDurableRecords: 64,
    maxRequestBytes: 1_048_576,
    maxResponseBytes: 67_108_864,
    maxWallClockMs: 80_000,
    maxConcurrency: 2,
  },
  issuedAt: PLAN_ISSUED_AT,
  expiresAt: WINDOW_END,
});

const onlineTraces = onlineTraceInput.map((trace) =>
  resignTrace({
    input: trace,
    protocol,
    protocolDigest,
    policyDigest: selectedPolicy.policyDigest,
    payloadKey,
    dispatchPrivateKey: dispatchKeys.privateKey,
    collectorPrivateKey: collectorKeys.privateKey,
    plan,
    workBudget,
  })
);
const onlineTraceById = new Map(
  onlineTraces.map((trace) => [trace.traceId, trace]),
);
const onlineEvidence = onlineEvidenceInput.map((evidence) =>
  resignEvidence({
    input: evidence,
    traceById: onlineTraceById,
    protocolDigest,
    evaluatorKeyId: trust.keys[0].keyId,
    evaluatorPrivateKey: evaluatorKeys.privateKey,
    workBudget,
  })
);
const onlineReceipts = verifyEvidenceSet(
  onlineEvidence,
  trust,
  onlineContext,
);
const onlineDataset = requireAssessmentDatasetSplit(
  joinAssessmentEvidence(
    protocol,
    onlineTraces,
    onlineReceipts,
    workBudget,
  ),
  "online",
);
const manifestBody = {
  version: "tasc-window-manifest-v2",
  windowId: plan.window.windowId,
  protocolDigest,
  frozenPolicyDigest: selectedPolicy.policyDigest,
  eventTimeStartInclusive: WINDOW_START,
  eventTimeEndExclusive: WINDOW_END,
  ingestionWatermark: WINDOW_WATERMARK,
  closureReason: "scheduled",
  membershipRule: protocol.onlineWindowMembership,
  membershipDigest: plan.window.membershipDigest,
  revision: 1,
  predecessorManifestDigest: null,
  traceSetDigest: onlineDataset.traceSetDigest,
  evaluatorSetDigest: onlineDataset.evaluatorSetDigest,
  capacityEvidence: {
    kind: "unavailable",
    reasonCode: "trusted-receipt-not-collected",
  },
};
const windowManifest = parseWindowManifest({
  ...manifestBody,
  selfDigest: fingerprintWindowManifest(manifestBody),
});
assessPolicyWindow(
  protocol,
  onlineDataset,
  selectedPolicy,
  windowManifest,
  onlineContext,
  workBudget,
);

for (const target of shadowProfiles.targets) {
  target.httpLimits.maxResponseBytes = 8_388_608;
}

await Promise.all([
  writeJson("protocol.json", protocol),
  writeJson("trust-snapshot.json", trust),
  writeJson("development-context.json", developmentContext),
  writeJson("online-context.json", onlineContext),
  writeRows("development-traces.ndjson", developmentTraces),
  writeRows("development-evidence.ndjson", developmentEvidence),
  writeRows("online-traces.ndjson", onlineTraces),
  writeRows("online-evidence.ndjson", onlineEvidence),
  writeJson("controller-snapshot.json", controllerSnapshot),
  writeJson("shadow-run-plan.json", plan),
  writeJson("shadow-profiles.json", shadowProfiles),
  writeJson("window-manifest.json", windowManifest),
]);

// Deliberately print, rather than rewrite, the independently reviewed test
// pin. Treat approving a new plan digest as a separate custody action.
process.stdout.write(
  `${JSON.stringify({
    protocolDigest,
    selectedPolicyDigest: selectedPolicy.policyDigest,
    controllerSnapshotDigest: controllerSnapshot.snapshotDigest,
    shadowPlanDigest: plan.planDigest,
    windowManifestDigest: windowManifest.selfDigest,
  }, null, 2)}\n`,
);
