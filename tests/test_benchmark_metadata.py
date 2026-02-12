from __future__ import annotations

from benchmark.runner import build_summary_meta


def test_build_summary_meta_has_required_fields() -> None:
    meta = build_summary_meta(
        seed=1,
        scenario_doc={"scenarios": [{"id": "S1"}]},
        defaults={"canaries": ["C1"]},
        ablation={},
    )
    for key in [
        "git_commit",
        "timestamp_utc",
        "python_version",
        "platform",
        "seed",
        "scenario_hash",
        "config_hash",
        "policy_hash",
    ]:
        assert key in meta
