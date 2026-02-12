# Thesis Changelog

## 2026-02-12 - Post-upgrade benchmark snapshot

- Branch: `codex/qw-final-integration`
- Commit: `1eba0ca`
- Command: `python -m benchmark.runner --scenarios benchmark/scenarios/scenarios.yaml --baseline all --runs 5 --compare --out results/run.json --summary results/summary.json`
- Artifacts:
  - `results/baseline_post_upgrade/summary.json`
  - `results/baseline_post_upgrade/summary_comparison.json`
  - `results/baseline_post_upgrade/report/`

### Key deltas (B0 -> B3)
- ASR: `0.5417 -> 0.0000` (reduction `0.5417`)
- Leakage: `0.1200 -> 0.0000` (reduction `0.1200`)
- Task success: `0.4800 -> 0.9800` (improvement `0.5000`)
- Approval rate: not recorded in current summary schema
- p95 latency: `0.08ms -> 8.78ms`
