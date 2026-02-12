# Result Schema

`summary.json` follows `benchmark/result_schema.json`.

## Compatibility
- Existing metric keys are unchanged.
- `schema_version` and `meta` were added additively.

## Required top-level fields
- `schema_version`
- `asr`
- `leakage_rate`
- `task_success_rate`
- `false_positive_rate`
- `latency_ms_p95`
- `counts`
- `meta`

## `meta` fields
- `git_commit`
- `timestamp_utc`
- `python_version`
- `platform`
- `seed`
- `scenario_hash`
- `config_hash`
- `policy_hash`

## Validation
- Runtime validation in `benchmark/schema.py`.
- Unit coverage in `tests/test_summary_schema.py`.
