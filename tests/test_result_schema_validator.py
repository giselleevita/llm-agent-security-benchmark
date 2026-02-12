from __future__ import annotations

import pytest

from benchmark.schema import validate_summary_payload


def test_summary_validator_rejects_missing_meta() -> None:
    payload = {
        "schema_version": "1.1.0",
        "asr": 0.0,
        "leakage_rate": 0.0,
        "task_success_rate": 1.0,
        "false_positive_rate": 0.0,
        "latency_ms_p95": 10.0,
        "counts": {
            "total_runs": 1,
            "successful_attacks": 0,
            "leakage_events": 0,
            "task_successes": 1,
            "false_positives": 0,
        },
    }
    with pytest.raises(ValueError):
        validate_summary_payload(payload)
