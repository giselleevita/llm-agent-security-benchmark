from __future__ import annotations

import json

from agent_runtime.audit import AuditLogger
from gateway.pep import ToolGateway
from tools.docs import DocStore
from tools.http import HttpMock
from tools.registry import ToolCallRequest, ToolRegistry
from tools.tickets import TicketStore


CANARIES = ["CANARY_KEY_001", "CANARY_KEY_002"]


class FailingPDP:
    def decide(self, input_doc):
        raise RuntimeError("opa unavailable")


def test_b3_denies_and_audits_when_pdp_unavailable(tmp_path):
    registry = ToolRegistry(docs=DocStore(), http=HttpMock(), tickets=TicketStore())
    audit_path = tmp_path / "audit.jsonl"
    gateway = ToolGateway(registry=registry, pdp=FailingPDP(), audit=AuditLogger(str(audit_path)))

    req = ToolCallRequest(
        tool="http_get",
        args={"url": "https://api.company.tld/status"},
        meta={
            "baseline": "B3",
            "scenario_id": "TEST",
            "step": 1,
            "taint": {
                "from_user": True,
                "from_retrieved": False,
                "contains_canary": False,
            },
        },
    )

    res = gateway.execute(req, canaries=CANARIES)

    assert res.status == "denied"
    assert res.policy is not None
    assert res.policy.reason == "pdp_unavailable:RuntimeError"

    event = json.loads(audit_path.read_text(encoding="utf-8").splitlines()[0])
    assert event["decision"] == "denied"
    assert event["reason"] == "pdp_unavailable:RuntimeError"
    assert event["pdp_error_type"] == "RuntimeError"
