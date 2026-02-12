# Reproducibility

## Environment
- Python 3.11+
- Docker + Docker Compose
- OPA container (`openpolicyagent/opa`)

## One-command reproduction

### 1) Start OPA:
```bash
docker compose up -d
```

### 2) Run benchmark:
```bash
mkdir -p results
python -m benchmark.runner \
  --scenarios benchmark/scenarios/scenarios.yaml \
  --baseline B3 \
  --runs 5 \
  --seed 1 \
  --out results/run.json \
  --summary results/summary.json
```

## Determinism

- Benchmark uses a deterministic planner (MockModelPlanner) by default.
- Tools are deterministic mocks (no internet, no external systems).
- Scenario order is deterministic (`id` sort) with explicit `--seed`.
- CI stability is ensured by eliminating stochastic model behavior.

## Outputs

- `results/run.json`: per-run traces
- `results/summary.json`: aggregated metrics + metadata (`schema_version`, `meta`)
- `benchmark/result_schema.json`: machine-readable schema contract

## CI

GitHub Actions runs the benchmark and fails if thresholds in `ci/thresholds.yaml` are violated.
