# Changelog

All notable changes to TASC are documented here.

The project follows semantic versioning once a stable public API is declared.

## 0.1.0 — 2026-07-24

Initial standalone proof of concept.

### Added

- Strict, versioned inference-spec and measurement contracts.
- Complete paired profile-matrix validation, including failed observations.
- Deterministic expert-only, fast-only, and cascade policy replay.
- Traffic-weighted quality, latency, throughput, reliability, and cost metrics.
- Paired bootstrap quality non-inferiority.
- Independent hard gates and deterministic Pareto selection.
- Content fingerprints and optional HMAC nomination attestation.
- Group-disjoint exact-policy holdout confirmation.
- Reviewer-facing JSON and Markdown evidence artifacts.
- Failure-driven next-experiment diagnostics.
- `nominate` and `confirm` CLI commands.
- Fictional end-to-end development and holdout example.
- Standalone package exports, build, tests, documentation, and security model.

### Safety

- Synthetic evidence is permanently capped at `DEMO_ONLY`.
- TASC never calls a model provider or mutates a serving configuration.
- Real evidence without verified attestation returns `HOLD`.
