from __future__ import annotations

import uuid
from fastapi import FastAPI
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel
from typing import Any, Dict

from agent_runtime.config import settings
from agent_runtime.audit import AuditLogger
from agent_runtime.metrics import metrics
from agent_runtime.policy_meta import load_policy_meta
from gateway.pdp_client import PDPClient
from gateway.pep import ToolGateway
from tools.registry import ToolRegistry
from tools.docs import DocStore
from tools.http import HttpMock
from tools.http_real import HttpReal, HttpRealConfig
from tools.tickets import TicketStore
from agent_runtime.orchestrator import AgentOrchestrator

app = FastAPI(title="Secure Agent Runtime")

audit = AuditLogger(settings.audit_log_path)
docs = DocStore()
if settings.http_adapter.lower() == "real":
    http_adapter = HttpReal(
        HttpRealConfig(
            allowed_domains=["api.company.tld", "docs.company.tld"],
            timeout_ms=settings.http_timeout_ms,
            allow_redirects=settings.http_allow_redirects,
            max_redirects=settings.http_max_redirects,
        )
    )
else:
    http_adapter = HttpMock()
tickets = TicketStore()
registry = ToolRegistry(docs=docs, http=http_adapter, tickets=tickets)
pdp = PDPClient(opa_url=settings.opa_url)
gateway = ToolGateway(registry=registry, pdp=pdp, audit=audit)
policy_meta = load_policy_meta()

DEFAULT_CANARIES = ["CANARY_KEY_001", "CANARY_KEY_002"]


class RunRequest(BaseModel):
    task: str
    baseline: str | None = None
    scenario_id: str | None = None


@app.get("/health")
def health() -> Dict[str, str]:
    return {"status": "ok"}


@app.post("/run")
def run(req: RunRequest) -> Dict[str, Any]:
    baseline = req.baseline or settings.default_baseline
    orch = AgentOrchestrator(gateway=gateway, canaries=DEFAULT_CANARIES)
    request_id = f"req-{uuid.uuid4().hex[:12]}"
    result = orch.run(task=req.task, baseline=baseline, scenario=None, request_id=request_id)
    metrics.inc("tool_gateway_decisions_total", "run_requests")
    return {
        "final_output": result.final_output,
        "tool_trace": result.tool_trace,
        "latency_ms": result.latency_ms,
        "request_id": result.request_id,
        "correlation_id": result.correlation_id,
        "policy_version": policy_meta["policy_version"],
    }


@app.get(settings.metrics_path, response_class=PlainTextResponse)
def metrics_export() -> str:
    if not settings.metrics_enabled:
        return ""
    return metrics.render_prometheus()
