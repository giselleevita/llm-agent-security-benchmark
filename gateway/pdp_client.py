from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict
import httpx


@dataclass
class PDPDecision:
    allow: bool
    requires_approval: bool
    reason: str


class PDPClient:
    def __init__(self, opa_url: str):
        self.opa_url = opa_url.rstrip("/")

    def decide(self, input_doc: Dict[str, Any]) -> PDPDecision:
        url = f"{self.opa_url}/v1/data/agent/policy/result"
        with httpx.Client(timeout=5.0) as client:
            r = client.post(url, json={"input": input_doc})
            r.raise_for_status()
            data = r.json()

        result = (data or {}).get("result") or {}
        return PDPDecision(
            allow=bool(result.get("allow", False)),
            requires_approval=bool(result.get("requires_approval", False)),
            reason=str(result.get("reason", "no_reason")),
        )
