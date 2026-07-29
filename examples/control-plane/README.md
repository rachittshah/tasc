# Signed synthetic control-plane fixture

This directory is a deterministic, synthetic example of the TASC v2 evidence
boundary. It contains no prompt, model output, customer identifier,
credential, HMAC key, or private signing key.

The files deliberately keep inference traces and evaluation evidence separate:

- `protocol.json` freezes profiles, routing predicates, group/window
  membership, hard gates, distinct dispatch/collector authorities, evaluator
  identity, endpoint requirements, and shadow limits.
- `development-traces.ndjson` and `online-traces.ndjson` contain paired,
  pre-dispatch-authorized and final-collector-attested `TraceEnvelope` records.
  Online shadow rows also bind raw-free shadow-plan, endpoint, route, and
  capability-receipt provenance. Payloads are represented only by HMAC
  identities.
- `controller-snapshot.json` is the self-digested `SHADOW_ASSESSING` P0
  controller projection derived from the development nomination.
- `shadow-run-plan.json` is the self-contained, self-digested P0
  authorization artifact. It freezes that controller snapshot, the selected
  policy, online window, exact endpoint targets, capability receipts, and
  effect budgets. Every online trace binds its exact plan and target.
- `collector-trust.json` and `shadow-profiles.json` are sanitized, feedable P1
  admission metadata. They bind the plan to the shipped registry's vLLM
  `0.26.0` and TensorRT-LLM `1.2.1` builds, their statically supported
  `/v1/completions` routes, HTTPS-only synthetic `.invalid` origins, and exact
  endpoint-binding digests. Their P0-pinned `authenticationReference` is
  explicitly `null` because this credential-free replay has no secret lookup
  provenance. The plan and each signed online trace also pin the exact
  normalized/defaulted HTTP-limit digest. No request is made to either origin.
- `development-evidence.ndjson` and `online-evidence.ndjson` contain separately
  signed `EvaluatorEvidence` records from the frozen deterministic evaluator.
- `trust-snapshot.json`, the two assessment contexts, and
  `work-budget.json` make verification time, keys, revocations, and bounded
  work explicit.
- `window-manifest.json` seals one online shadow window and records capacity as
  unavailable because the fixture has no trusted exact-policy capacity
  receipt.
- the experiment history and budget authorize only a bounded next-experiment
  proposal.

Distinct Ed25519 dispatch, collector, and evaluator keys—and the
payload-identity key—are deterministically derived from public,
domain-separated fixture labels. This makes regeneration byte-for-byte
reproducible. The derived private material is never serialized, but it is
intentionally public and provides no real authority or secrecy; never reuse
these fixture keys for a real study.

The committed plan authorized effects only inside its sealed historical
90-second window and is now replay-only. Its aggregate budgets were admitted
through the runner core with a test-only historical clock/effect-denial seam;
that test does not create current or public live authority. A live collection
must build a fresh bounded plan and supply its digest from operator custody or
another out-of-band P0 approval channel—never by trusting the digest field in
the plan being executed.

Maintainers can regenerate the complete signed packet with:

```bash
node --import tsx scripts/regenerate-control-plane-fixtures.mjs
```

The script derives fixture-only keys in memory, writes only public/signed
artifacts, and prints the stable plan digest. It intentionally does not update
the independent test pin; reviewing and pinning that value is a separate
custody action.

Run the full replay:

```bash
npm run demo:control-plane
```

The demo uses TASC's public APIs to boundedly parse every file, verify dispatch,
collector, and evaluator signatures, verify the controller-to-shadow-plan-to-
trace P0→P1 lineage, prove both P1 targets are statically admitted by their
exact public registry builds/routes and collector policy, join paired evidence,
nominate a development policy, assess the frozen policy on the sealed window,
publish immutable raw-free artifacts, and verify every manifest and payload
digest. The plan declares no capability claim that requires a live receipt;
final trace evidence remains independently verified. The replay performs zero
network or model calls and every artifact carries
`evidence-only-no-deployment-authority`.
