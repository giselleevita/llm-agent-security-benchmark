from __future__ import annotations

BASELINES = ("B0", "B1", "B2", "B3")


def validate_baseline(name: str) -> str:
    if name not in BASELINES:
        raise ValueError(f"Unknown baseline: {name}")
    return name
