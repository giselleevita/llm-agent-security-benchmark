# Hireability Assets

## 60-second demo script

```bash
# 0-10s: setup
python3 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'

# 10-20s: run weak baseline
python -m benchmark.runner \
  --scenarios benchmark/scenarios/scenarios.yaml \
  --baseline B2 --runs 1 \
  --out results/demo_b2_run.json \
  --summary results/demo_b2_summary.json

# 20-35s: show machine-readable metrics
cat results/demo_b2_summary.json

# 35-50s: run report generation
python scripts/report_results.py \
  --results-dir results \
  --scenarios benchmark/scenarios/scenarios.yaml \
  --out-dir results/report \
  --make-plots

# 50-60s: show security gate config
cat ci/thresholds.yaml
```

Talk track:
- \"The model never executes tools directly; PEP enforces policy decisions.\"
- \"Policy decisions are explicit and auditable (`allow`, `deny`, `requires_approval`).\"
- \"Benchmark scenarios and CI thresholds make security regressions measurable and blockable.\"

## CV bullets (impact-focused)

- Built a policy-enforced tool gateway (PEP/PDP with OPA Rego) that externalizes LLM tool authorization decisions.
- Implemented scenario-driven prompt-injection benchmark harness across B0-B3 with machine-readable security metrics.
- Added CI security gate with threshold checks (`ASR`, leakage, false-positive, p95 latency) to fail insecure builds.
- Designed taint/canary-aware controls and approval semantics to constrain high-risk tool actions.
- Delivered reproducible artifacts (JSON summaries, markdown reports, plots) for thesis-grade security evaluation.
