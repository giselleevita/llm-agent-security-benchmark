from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Dict


class AuditLogger:
    """
    Writes structured JSONL audit events.
    Intended for both benchmarking and interactive /run usage.
    """

    def __init__(self, path: str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def emit(self, event: Dict[str, Any]) -> None:
        event = dict(event)
        event.setdefault("ts", time.time())
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(event, ensure_ascii=False) + "\n")
