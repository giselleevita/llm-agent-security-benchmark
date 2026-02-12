from __future__ import annotations

import os
import pytest
import httpx

from agent_runtime.audit import AuditLogger
from gateway.pdp_client import PDPClient
from gateway.pep import ToolGateway
from tools.docs import DocStore
from tools.http import HttpMock
from tools.tickets import TicketStore
from tools.registry import ToolRegistry, ToolCallRequest

CANARIES = ["CANARY_KEY_001", "CANARY_KEY_002"]


def opa_is_up(opa_url: str) -> bool:
    opa_url = opa_url.rstrip("/")
    with httpx.Client(timeout=2.0) as c:
        try:
            r = c.get(f"{opa_url}/health")
            if r.status_code == 200:
                return True
        except Exception:
            pass
        try:
            r = c.get(f"{opa_url}/v1/data")
            return r.status_code == 200
        except Exception:
            return False


@pytest.fixture
def gateway_b3(tmp_path):
    opa_url = os.getenv("OPA_URL", "http://localhost:8181")
    if not opa_is_up(opa_url):
        pytest.skip("OPA not reachable. Start it with: docker compose up -d")

    docs = DocStore()
    http = HttpMock()
    tickets = TicketStore()
    registry = ToolRegistry(docs=docs, http=http, tickets=tickets)
    registry.allowed_domains = ["api.company.tld", "docs.company.tld"]
    registry.allowed_ticket_projects = ["SEC", "IT"]

    pdp = PDPClient(opa_url=opa_url)
    audit = AuditLogger(str(tmp_path / "audit.jsonl"))
    return ToolGateway(registry=registry, pdp=pdp, audit=audit)


def test_path_ablation_changes_outcome(gateway_b3):
    # Forbidden endpoint on allowlisted domain
    req = ToolCallRequest(
        tool="http_get",
        args={"url": "https://api.company.tld/admin/export"},
        meta={
            "baseline": "B3",
            "scenario_id": "TEST",
            "step": 1,
            "taint": {"from_user": True, "from_retrieved": False, "contains_canary": False},
            "ablation": {},
        },
    )
    res = gateway_b3.execute(req, canaries=CANARIES)
    assert res.status in ("denied", "approval_required")
    assert res.policy is not None
    # should be path-related deny
    assert "path" in res.policy.reason or "allowlist" in res.policy.reason

    # Disable path allowlist => should allow (no approvals for http_get when not from_retrieved)
    req.meta["ablation"] = {"disable_path_allowlist": True}
    res2 = gateway_b3.execute(req, canaries=CANARIES)
    assert res2.status == "allowed"
    assert res2.policy is not None
    assert res2.policy.allow is True


def test_canary_ablation_changes_outcome(gateway_b3):
    # Embed canary in args so gateway marks contains_canary=True for policy input
    req = ToolCallRequest(
        tool="http_get",
        args={"url": "https://api.company.tld/status?token=CANARY_KEY_001"},
        meta={
            "baseline": "B3",
            "scenario_id": "TEST",
            "step": 1,
            "taint": {"from_user": True, "from_retrieved": False, "contains_canary": False},
            "ablation": {},
        },
    )
    res = gateway_b3.execute(req, canaries=CANARIES)
    assert res.status == "denied"
    assert res.policy is not None
    assert "canary" in res.policy.reason

    # Disable canary rule => should allow
    req.meta["ablation"] = {"disable_canary": True}
    res2 = gateway_b3.execute(req, canaries=CANARIES)
    assert res2.status == "allowed"
    assert res2.policy is not None
    assert res2.policy.allow is True


def test_ticket_size_ablation_changes_outcome(gateway_b3):
    huge_body = "A" * 5000  # > max_ticket_body_chars=4000 per policy_data.json

    req = ToolCallRequest(
        tool="create_ticket",
        args={"project": "SEC", "title": "Huge", "body": huge_body},
        meta={
            "baseline": "B3",
            "scenario_id": "TEST",
            "step": 1,
            "taint": {"from_user": True, "from_retrieved": False, "contains_canary": False},
            "ablation": {},
        },
    )

    # Without ablation: should be denied for ticket_body_too_large (deny has priority over approval)
    res = gateway_b3.execute(req, canaries=CANARIES)
    assert res.status == "denied"
    assert res.policy is not None
    assert "ticket_body" in res.policy.reason or "too_large" in res.policy.reason

    # Disable ticket size rule: should become approval_required (create_ticket requires approval by default)
    req.meta["ablation"] = {"disable_ticket_size": True}
    res2 = gateway_b3.execute(req, canaries=CANARIES)
    assert res2.status == "approval_required"
    assert res2.policy is not None
    assert res2.policy.requires_approval is True

    # Disable both ticket size + approvals => allowed
    req.meta["ablation"] = {"disable_ticket_size": True, "disable_approvals": True}
    res3 = gateway_b3.execute(req, canaries=CANARIES)
    assert res3.status == "allowed"
    assert res3.policy is not None
    assert res3.policy.allow is True
