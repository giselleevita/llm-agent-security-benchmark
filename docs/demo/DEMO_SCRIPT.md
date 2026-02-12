# Demo Script (Public)

## Goal
Show end-to-end policy-enforced benchmarking with a single deterministic command.

## Commands
```bash
make setup
make demo
```

## What to show in UI/browser
1. Open `results/latest/report/index.html`.
2. Show baseline comparison table (B0-B3).
3. Highlight B3 row (ASR/leakage near zero, high task success).
4. Scroll to threat breakdown table.
5. Show chart images (ASR, leakage, false positive, latency, task success).
6. Show `results/summary.json` and point to `schema_version` + `meta` fields.

## Optional evidence commands
```bash
cat results/summary.json
cat results/summary_comparison.json
```

## Expected outcome
Reviewer can run `make setup && make demo`, open one report file, and verify controls + metrics without manual OPA setup.
