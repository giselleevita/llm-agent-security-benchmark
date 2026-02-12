from __future__ import annotations

import json
from pathlib import Path

from agent_runtime.audit import AuditLogger
from gateway.pdp_client import PDPDecision
from gateway.pep import ToolGateway
from tools.docs import DocStore
from tools.http import HttpMock
from tools.registry import ToolCallRequest, ToolRegistry
from tools.tickets import TicketStore


class StubPDP:
    def decide(self, _input_doc):
        return PDPDecision(allow=True, requires_approval=False, reason="allowed")


def test_audit_includes_correlation_id(tmp_path: Path) -> None:
    audit_path = tmp_path / "audit.jsonl"
    gateway = ToolGateway(
        registry=ToolRegistry(docs=DocStore(), http=HttpMock(), tickets=TicketStore()),
        pdp=StubPDP(),
        audit=AuditLogger(str(audit_path)),
    )

    req = ToolCallRequest(
        tool="read_doc",
        args={"doc_id": "refund_policy"},
        meta={
            "baseline": "B3",
            "scenario_id": "TEST-CORR",
            "step": 1,
            "correlation_id": "run-test-123",
            "taint": {"from_user": True, "from_retrieved": False, "contains_canary": False},
            "ablation": {},
        },
    )
    res = gateway.execute(req, canaries=["CANARY_KEY_001"])
    assert res.status == "allowed"

    lines = audit_path.read_text(encoding="utf-8").strip().splitlines()
    assert lines, "expected one audit event"
    event = json.loads(lines[-1])
    assert event["correlation_id"] == "run-test-123"
    assert event["scenario_id"] == "TEST-CORR"
    assert event["decision"] == "allowed"
