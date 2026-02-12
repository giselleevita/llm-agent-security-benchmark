#!/usr/bin/env bash
set -euo pipefail

SCENARIOS="${1:-benchmark/scenarios/scenarios.yaml}"
RUNS="${2:-5}"

mkdir -p results

docker compose up -d

for B in B0 B1 B2 B3; do
  echo "=== Running $B ==="
  mkdir -p "results/$B"
  python -m benchmark.runner \
    --scenarios "$SCENARIOS" \
    --baseline "$B" \
    --runs "$RUNS" \
    --out "results/$B/run.json" \
    --summary "results/$B/summary.json"
done

echo "Done. Results in results/{B0,B1,B2,B3}/"
