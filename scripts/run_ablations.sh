#!/usr/bin/env bash
set -euo pipefail

SCENARIOS="${1:-benchmark/scenarios/scenarios.yaml}"
RUNS="${2:-5}"

mkdir -p results
docker compose up -d

BASE="B3"
ABLATIONS=("none" "no_approvals" "no_taint_approvals" "no_path" "no_canary" "no_ticket_size")

for A in "${ABLATIONS[@]}"; do
  NAME="B3_${A}"
  echo "=== Running $NAME ==="
  mkdir -p "results/$NAME"
  python -m benchmark.runner \
    --scenarios "$SCENARIOS" \
    --baseline "$BASE" \
    --ablation "$A" \
    --runs "$RUNS" \
    --out "results/$NAME/run.json" \
    --summary "results/$NAME/summary.json"
done

echo "Done. Results in results/B3_*"
