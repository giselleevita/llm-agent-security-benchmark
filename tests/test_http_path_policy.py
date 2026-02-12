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
        # /health is common; fallback to /v1/data
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

    # Align with policy_data.json defaults
    registry.allowed_domains = ["api.company.tld", "docs.company.tld"]
    registry.allowed_ticket_projects = ["SEC", "IT"]

    pdp = PDPClient(opa_url=opa_url)
    audit = AuditLogger(str(tmp_path / "audit.jsonl"))
    return ToolGateway(registry=registry, pdp=pdp, audit=audit)


def _req_http(url: str, taint: dict | None = None, ablation: dict | None = None) -> ToolCallRequest:
    return ToolCallRequest(
        tool="http_get",
        args={"url": url},
        meta={
            "baseline": "B3",
            "scenario_id": "TEST",
            "step": 1,
            "taint": (taint or {"from_user": True, "from_retrieved": False, "contains_canary": False}),
            "ablation": (ablation or {}),
        },
    )


def test_allowed_path_status(gateway_b3):
    req = _req_http("https://api.company.tld/status")
    res = gateway_b3.execute(req, canaries=CANARIES)
    assert res.status == "allowed"
    assert res.policy is not None
    assert res.policy.allow is True


def test_allowed_path_status_with_query(gateway_b3):
    # Query should not break path allowlist if policy uses parsed_path without query
    req = _req_http("https://api.company.tld/status?x=1")
    res = gateway_b3.execute(req, canaries=CANARIES)
    # Tool may return 404 in mock (because mapping is exact), but policy should still allow
    assert res.status == "allowed"
    assert res.policy is not None
    assert res.policy.allow is True


def test_denied_forbidden_path_admin_export(gateway_b3):
    req = _req_http("https://api.company.tld/admin/export")
    res = gateway_b3.execute(req, canaries=CANARIES)
    assert res.status in ("denied", "approval_required")
    assert res.policy is not None
    # With upgraded policy, path allowlist should deny (not approval) for forbidden path
    assert "path" in res.policy.reason or "allowlist" in res.policy.reason


def test_denied_traversal_path(gateway_b3):
    # If your policy uses exact path matching, this should be denied
    req = _req_http("https://docs.company.tld/../internal/secrets")
    res = gateway_b3.execute(req, canaries=CANARIES)
    assert res.status in ("denied", "approval_required")
    assert res.policy is not None
    assert "path" in res.policy.reason or "allowlist" in res.policy.reason


def test_denied_disallowed_domain(gateway_b3):
    req = _req_http("https://evil.tld/payload")
    res = gateway_b3.execute(req, canaries=CANARIES)
    assert res.status in ("denied", "approval_required")
    assert res.policy is not None
    assert "domain" in res.policy.reason or "allowlist" in res.policy.reason


def test_denied_ip_literal(gateway_b3):
    req = _req_http("http://127.0.0.1/status")
    res = gateway_b3.execute(req, canaries=CANARIES)
    assert res.status in ("denied", "approval_required")
    assert res.policy is not None
    assert "ip" in res.policy.reason or "literal" in res.policy.reason or "private" in res.policy.reason


def test_denied_userinfo_authority_bypass(gateway_b3):
    # Attempt to smuggle an attacker host via URL userinfo/authority confusion.
    req = _req_http("https://api.company.tld:443@evil.tld/status")
    res = gateway_b3.execute(req, canaries=CANARIES)
    assert res.status in ("denied", "approval_required")
    assert res.policy is not None
    assert "authority" in res.policy.reason or "domain" in res.policy.reason


def test_denied_ipv6_literal(gateway_b3):
    req = _req_http("http://[::1]/status")
    res = gateway_b3.execute(req, canaries=CANARIES)
    assert res.status in ("denied", "approval_required")
    assert res.policy is not None
    assert "ipv6" in res.policy.reason or "ip" in res.policy.reason
