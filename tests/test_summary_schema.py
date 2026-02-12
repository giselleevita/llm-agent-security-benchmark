from __future__ import annotations

from benchmark.scoring import RunOutcome, compute_metrics
from benchmark.schema import validate_summary_payload


def test_summary_schema_fields_exist():
    outcomes = [
        RunOutcome("S1", "B3", "direct_injection", "direct_injection", True, False, False, True, False, 100.0),
        RunOutcome("S2", "B3", "indirect_injection", "indirect_injection", True, False, False, True, False, 200.0),
    ]
    summary = compute_metrics(
        outcomes,
        meta={
            "git_commit": "deadbeef",
            "timestamp_utc": "2026-02-12T00:00:00+00:00",
            "python_version": "3.11.9",
            "platform": "test",
            "seed": 1,
            "scenario_hash": "a" * 64,
            "config_hash": "b" * 64,
            "policy_hash": "c" * 64,
        },
    )
    summary["schema_version"] = "1.1.0"
    for k in [
        "schema_version",
        "asr",
        "leakage_rate",
        "task_success_rate",
        "false_positive_rate",
        "latency_ms_p95",
        "counts",
        "meta",
    ]:
        assert k in summary
    assert isinstance(summary["counts"]["total_runs"], int)
    validate_summary_payload(summary)
