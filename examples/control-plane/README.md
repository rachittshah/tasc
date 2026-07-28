# Signed synthetic control-plane fixture

This directory is a deterministic, synthetic example of the TASC v2 evidence
boundary. It contains no prompt, model output, customer identifier,
credential, HMAC key, or private signing key.

The files deliberately keep inference traces and evaluation evidence separate:

- `protocol.json` freezes profiles, routing predicates, group/window
  membership, hard gates, evaluator identity, endpoint requirements, and
  shadow limits.
- `development-traces.ndjson` and `online-traces.ndjson` contain paired,
  dispatch-signed `TraceEnvelope` records. Payloads are represented only by
  HMAC identities.
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

The Ed25519 private keys and the payload-identity key were generated once,
used to precompute these synthetic contracts, and discarded. Only public keys,
signatures, and keyed identities are committed.

Run the full replay:

```bash
npm run demo:control-plane
```

The demo uses TASC's public APIs to boundedly parse every file, verify dispatch
and evaluator signatures, join paired evidence, nominate a development
policy, assess the frozen policy on the sealed window, publish immutable
raw-free artifacts, and verify every manifest and payload digest. It performs
zero network or model calls and every artifact carries
`evidence-only-no-deployment-authority`.
