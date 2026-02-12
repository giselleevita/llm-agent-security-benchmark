from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

from agent_runtime.context import detect_canary
from gateway.pdp_client import PDPClient
from tools.registry import ToolRegistry, ToolCallRequest, ToolCallResult, PolicyInfo
from agent_runtime.audit import AuditLogger


def _tool_risk(tool: str) -> str:
    if tool == "http_get":
        return "network"
    if tool == "create_ticket":
        return "action"
    if tool in ("search_docs", "read_doc", "db_query_readonly"):
        return "read"
    return "unknown"


class ToolGateway:
    """
    Policy Enforcement Point (PEP).
    Enforces baseline behavior B0..B3 and logs audit events.
    """

    def __init__(self, registry: ToolRegistry, pdp: PDPClient, audit: AuditLogger):
        self.registry = registry
        self.pdp = pdp
        self.audit = audit

    def execute(self, req: ToolCallRequest, canaries: List[str]) -> ToolCallResult:
        t0 = time.perf_counter()

        baseline = (req.meta or {}).get("baseline") or "B3"
        scenario_id = (req.meta or {}).get("scenario_id")
        taint = ((req.meta or {}).get("taint") or {})
        from_user = bool(taint.get("from_user", False))
        from_retrieved = bool(taint.get("from_retrieved", False))

        tool = req.tool
        tool_def = self.registry.get(tool)
        if tool_def is None:
            res = ToolCallResult.denied(tool, "tool_not_registered")
            self._audit(req, res, t0)
            return res

        try:
            parsed_args = tool_def.args_model(**(req.args or {}))
        except Exception as e:
            res = ToolCallResult.denied(tool, f"schema_validation_failed: {type(e).__name__}")
            self._audit(req, res, t0)
            return res

        contains_canary = bool(taint.get("contains_canary", False)) or detect_canary(
            parsed_args.model_dump(), canaries
        )

        if baseline in ("B0", "B1"):
            result = tool_def.execute(parsed_args)
            res = ToolCallResult.allowed(
                tool, result, PolicyInfo(allow=True, reason="baseline_permissive")
            )
            self._audit(req, res, t0, extra={"contains_canary": contains_canary})
            return res

        if baseline == "B2":
            if contains_canary:
                res = ToolCallResult.denied(tool, "canary_detected")
                self._audit(req, res, t0, extra={"contains_canary": contains_canary})
                return res

            if tool == "http_get":
                url = str(parsed_args.url)
                host = url.split("://")[-1].split("/")[0].split(":")[0]
                allowed = self.registry.allowed_domains
                if host not in allowed and not any(host.endswith("." + d) for d in allowed):
                    res = ToolCallResult.denied(tool, "domain_not_allowlisted")
                    self._audit(req, res, t0)
                    return res

            if tool == "create_ticket":
                if parsed_args.project not in self.registry.allowed_ticket_projects:
                    res = ToolCallResult.denied(tool, "ticket_project_not_allowed")
                    self._audit(req, res, t0)
                    return res

            result = tool_def.execute(parsed_args)
            res = ToolCallResult.allowed(
                tool, result, PolicyInfo(allow=True, reason="simple_checks_passed")
            )
            self._audit(req, res, t0, extra={"contains_canary": contains_canary})
            return res

        if baseline == "B3":
            ablation = (req.meta or {}).get("ablation") or {}
            pdp_input = {
                "scenario_id": scenario_id,
                "baseline": baseline,
                "tool": tool,
                "args": parsed_args.model_dump(),
                "taint": {
                    "from_user": from_user,
                    "from_retrieved": from_retrieved,
                    "contains_canary": contains_canary,
                },
                "risk": {
                    "tool_risk": _tool_risk(tool),
                    "high_risk_action": _tool_risk(tool) in ("network", "action"),
                },
                "env": {
                    "allowed_domains": self.registry.allowed_domains,
                    "allowed_ticket_projects": self.registry.allowed_ticket_projects,
                },
                "ablation": ablation,
            }

            decision = self.pdp.decide(pdp_input)

            if decision.allow:
                result = tool_def.execute(parsed_args)
                res = ToolCallResult.allowed(
                    tool, result, PolicyInfo(allow=True, reason=decision.reason)
                )
                self._audit(req, res, t0, extra={"contains_canary": contains_canary, "pdp_input": pdp_input})
                return res

            if decision.requires_approval:
                res = ToolCallResult.approval_required(
                    tool,
                    parsed_args.model_dump(),
                    PolicyInfo(allow=False, requires_approval=True, reason=decision.reason),
                )
                self._audit(req, res, t0, extra={"contains_canary": contains_canary, "pdp_input": pdp_input})
                return res

            res = ToolCallResult.denied(tool, decision.reason)
            self._audit(req, res, t0, extra={"contains_canary": contains_canary, "pdp_input": pdp_input})
            return res

        res = ToolCallResult.denied(tool, f"unknown_baseline:{baseline}")
        self._audit(req, res, t0)
        return res

    def _audit(
        self,
        req: ToolCallRequest,
        res: ToolCallResult,
        t0: float,
        extra: Optional[Dict[str, Any]] = None,
    ) -> None:
        t1 = time.perf_counter()
        event = {
            "scenario_id": (req.meta or {}).get("scenario_id"),
            "baseline": (req.meta or {}).get("baseline"),
            "step": (req.meta or {}).get("step"),
            "tool": req.tool,
            "args": req.args,
            "decision": res.status,
            "reason": res.policy.reason if res.policy else None,
            "requires_approval": bool(res.policy.requires_approval) if res.policy else False,
            "latency_ms": (t1 - t0) * 1000.0,
        }
        if extra:
            event.update(extra)
        self.audit.emit(event)
