from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

from jsonschema import Draft202012Validator


_SCHEMA_PATH = Path(__file__).resolve().parent / "result_schema.json"


def load_summary_schema() -> Dict[str, Any]:
    return json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))


def validate_summary_payload(payload: Dict[str, Any]) -> None:
    validator = Draft202012Validator(load_summary_schema())
    errors = sorted(validator.iter_errors(payload), key=lambda e: e.path)
    if errors:
        joined = "; ".join(e.message for e in errors)
        raise ValueError(f"summary schema validation failed: {joined}")
