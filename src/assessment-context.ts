import { z } from "zod";
import {
  contractDigestSchema,
  contractTimestampSchema,
  deepFreezeContract,
  domainSeparatedDigest,
  snapshotBoundedContractInput,
  type DeepReadonly,
} from "./evidence.js";

const assessmentContextInputSchema = z.object({
  version: z.literal("tasc-assessment-context-v2"),
  asOf: contractTimestampSchema,
  operatorTrustPolicySnapshotDigest: contractDigestSchema,
  evaluatorRevocationSnapshotDigest: contractDigestSchema,
  contextDigest: contractDigestSchema.optional(),
}).strict();

type MutableAssessmentContextInput = z.infer<typeof assessmentContextInputSchema>;
type MutableAssessmentContext = Omit<MutableAssessmentContextInput, "contextDigest"> & {
  contextDigest: string;
};

export type AssessmentContextInput = DeepReadonly<
  Omit<MutableAssessmentContextInput, "contextDigest">
  & { contextDigest?: string }
>;
export type AssessmentContext = DeepReadonly<MutableAssessmentContext>;

function withoutContextDigest(
  context: MutableAssessmentContextInput,
): Omit<MutableAssessmentContextInput, "contextDigest"> {
  const { contextDigest: _contextDigest, ...content } = context;
  return content;
}

/**
 * Fingerprint only the context content. A supplied self-digest is deliberately
 * excluded and is always recomputed by `parseAssessmentContext`.
 */
export function fingerprintAssessmentContext(input: unknown): string {
  const snapshot = snapshotBoundedContractInput(input);
  const parsed = assessmentContextInputSchema.parse(snapshot);
  return domainSeparatedDigest(
    "tasc/assessment-context/v2",
    withoutContextDigest(parsed),
  );
}

export function parseAssessmentContext(input: unknown): AssessmentContext {
  const snapshot = snapshotBoundedContractInput(input);
  const parsed = assessmentContextInputSchema.parse(snapshot);
  const derivedDigest = domainSeparatedDigest(
    "tasc/assessment-context/v2",
    withoutContextDigest(parsed),
  );
  if (parsed.contextDigest !== undefined && parsed.contextDigest !== derivedDigest) {
    throw new Error("assessment context digest does not match canonical context content");
  }
  return deepFreezeContract({
    ...withoutContextDigest(parsed),
    contextDigest: derivedDigest,
  });
}
