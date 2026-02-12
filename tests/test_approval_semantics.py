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


def test_create_ticket_requires_approval_by_default(gateway_b3):
    req = ToolCallRequest(
        tool="create_ticket",
        args={"project": "SEC", "title": "Test", "body": "Hello"},
        meta={
            "baseline": "B3",
            "scenario_id": "TEST",
            "step": 1,
            "taint": {"from_user": True, "from_retrieved": False, "contains_canary": False},
            "ablation": {},
        },
    )
    res = gateway_b3.execute(req, canaries=CANARIES)
    assert res.status == "approval_required"
    assert res.policy is not None
    assert res.policy.requires_approval is True


def test_disable_approvals_allows_create_ticket(gateway_b3):
    req = ToolCallRequest(
        tool="create_ticket",
        args={"project": "SEC", "title": "Test", "body": "Hello"},
        meta={
            "baseline": "B3",
            "scenario_id": "TEST",
            "step": 1,
            "taint": {"from_user": True, "from_retrieved": False, "contains_canary": False},
            "ablation": {"disable_approvals": True},
        },
    )
    res = gateway_b3.execute(req, canaries=CANARIES)
    assert res.status == "allowed"
    assert res.policy is not None
    assert res.policy.allow is True


def test_from_retrieved_http_get_requires_approval(gateway_b3):
    # This is the key "indirect injection" control: from_retrieved + network risk => approval_required in B3
    req = ToolCallRequest(
        tool="http_get",
        args={"url": "https://api.company.tld/status"},
        meta={
            "baseline": "B3",
            "scenario_id": "TEST",
            "step": 1,
            "taint": {"from_user": False, "from_retrieved": True, "contains_canary": False},
            "ablation": {},
        },
    )
    res = gateway_b3.execute(req, canaries=CANARIES)
    assert res.status == "approval_required"
    assert res.policy is not None
    assert res.policy.requires_approval is True


def test_disable_taint_approvals_allows_from_retrieved_http_get(gateway_b3):
    req = ToolCallRequest(
        tool="http_get",
        args={"url": "https://api.company.tld/status"},
        meta={
            "baseline": "B3",
            "scenario_id": "TEST",
            "step": 1,
            "taint": {"from_user": False, "from_retrieved": True, "contains_canary": False},
            "ablation": {"disable_taint_approvals": True},
        },
    )
    res = gateway_b3.execute(req, canaries=CANARIES)
    assert res.status == "allowed"
    assert res.policy is not None
    assert res.policy.allow is True
