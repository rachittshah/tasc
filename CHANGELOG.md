# Changelog

All notable changes to TASC are documented here.

The project follows semantic versioning once a stable public API is declared.

## Unreleased

### Added

- A reproducible Apple Silicon MLX benchmark runner with immutable model
  revisions, isolated processes, raw logs, sanitized environment provenance,
  and tested P10/median/P95 parsing.
- A real 2026-07-26 M4 Pro snapshot for two official 2026 sub-7B LiquidAI
  models, covering three throughput workloads and the full ARC-Challenge test
  task.
- Explicit documentation of TASC's value proposition, adoption workflow,
  advantages over ad-hoc benchmark tables, and inference R&D loop.
- Guidance for turning an aggregate MLX snapshot into complete paired,
  per-request TASC evidence without inventing confidence, latency, or cost.

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
