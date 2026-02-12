# Submission Checklist

Date: 2026-02-12
Repository: `llm-agent-security-benchmark`

## 1) Code and branch state
- [x] PR merged to `main`: https://github.com/giselleevita/llm-agent-security-benchmark/pull/1
- [x] Local branch is `main`
- [x] Working tree clean

## 2) Security controls implemented
- [x] PEP/PDP enforcement path active (`gateway/pep.py`, `gateway/pdp_client.py`)
- [x] Unknown tool denial + allowlist controls
- [x] URL authority hardening and SSRF-related policy checks (`policies/rego/agent_policy.rego`)
- [x] `requires_approval` halting semantics
- [x] Audit trail includes `correlation_id`

## 3) Verification and tests
- [x] Core tests pass locally (`pytest -q`)
- [x] Targeted policy/audit tests pass (`tests/test_http_path_policy.py`, `tests/test_audit_correlation.py`)
- [x] Benchmark rerun completed for B0-B3 (runs=5)
- [x] CI security gate passed on merged PR

## 4) Artifacts and reproducibility
- [x] Immutable post-upgrade snapshot stored in `results/baseline_post_upgrade/`
- [x] Includes `summary.json`, `summary_comparison.json`, and report plots/tables
- [x] Changelog entry present: `docs/CHANGELOG_THESIS.md`

## 5) Thesis and hiring assets
- [x] Enterprise security review: `docs/enterprise_security_review.md`
- [x] Hireability/demo assets: `docs/hireability_assets.md`
- [x] Recruiter-facing “Why this matters” and architecture Mermaid in `README.md`

## 6) Final pre-submission commands
```bash
pytest -q
python -m benchmark.runner --scenarios benchmark/scenarios/scenarios.yaml --baseline all --runs 5 --compare --out results/run.json --summary results/summary.json
python scripts/report_results.py --results-dir results --scenarios benchmark/scenarios/scenarios.yaml --make-plots --out-dir results/baseline_post_upgrade/report
```

## Notes
- Local branch cleanup for old `codex/*` branches may be restricted by environment policy; this does not affect submitted `main`.
