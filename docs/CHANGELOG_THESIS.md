# Thesis Changelog

## 2026-02-12 - Post-upgrade benchmark snapshot

- Branch: `codex/enterprise-grade-upgrade`
- Commit: `unreleased-local`
- Command: `python -m benchmark.runner --scenarios benchmark/scenarios/scenarios.yaml --baseline all --runs 5 --compare --seed 1 --out results/run.json --summary results/summary.json`
- Artifacts:
  - `results/baseline_post_upgrade/summary.json`
  - `results/baseline_post_upgrade/summary_comparison.json`
  - `results/baseline_post_upgrade/report/`

### Key deltas (B0 -> B3)
- ASR: `0.5417 -> 0.0000` (reduction `0.5417`)
- Leakage: `0.1200 -> 0.0000` (reduction `0.1200`)
- Task success: `0.4800 -> 0.9800` (improvement `0.5000`)
- Approval rate: not recorded in current summary schema
- p95 latency: benchmark-dependent (see `summary_comparison.json` for exact run)

### Schema/versioning notes
- Summary schema version: `1.1.0`
- Metadata now includes commit/platform/seed/config hash/policy hash.
