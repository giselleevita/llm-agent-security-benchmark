from __future__ import annotations

from fastapi import FastAPI
from pydantic import BaseModel
from typing import Any, Dict, List

from agent_runtime.config import settings
from agent_runtime.audit import AuditLogger
from gateway.pdp_client import PDPClient
from gateway.pep import ToolGateway
from tools.registry import ToolRegistry
from tools.docs import DocStore
from tools.http import HttpMock
from tools.tickets import TicketStore
from agent_runtime.orchestrator import AgentOrchestrator

app = FastAPI(title="Secure Agent Runtime")

audit = AuditLogger(settings.audit_log_path)
docs = DocStore()
httpmock = HttpMock()
tickets = TicketStore()
registry = ToolRegistry(docs=docs, http=httpmock, tickets=tickets)
pdp = PDPClient(opa_url=settings.opa_url)
gateway = ToolGateway(registry=registry, pdp=pdp, audit=audit)

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
    result = orch.run(task=req.task, baseline=baseline, scenario=None)
    return {
        "final_output": result.final_output,
        "tool_trace": result.tool_trace,
        "latency_ms": result.latency_ms,
        "correlation_id": result.correlation_id,
    }
