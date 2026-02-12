from __future__ import annotations

from benchmark.scoring import RunOutcome, compute_metrics


def test_summary_schema_fields_exist():
    outcomes = [
        RunOutcome("S1", "B3", "direct_injection", "direct_injection", True, False, False, True, False, 100.0),
        RunOutcome("S2", "B3", "indirect_injection", "indirect_injection", True, False, False, True, False, 200.0),
    ]
    summary = compute_metrics(outcomes)
    for k in ["asr", "leakage_rate", "task_success_rate", "false_positive_rate", "latency_ms_p95", "counts"]:
        assert k in summary
    assert isinstance(summary["counts"]["total_runs"], int)
