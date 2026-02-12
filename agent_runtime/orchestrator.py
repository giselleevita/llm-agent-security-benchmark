from __future__ import annotations

import time
import uuid
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple

from agent_runtime.context import Taint, detect_canary
from gateway.pep import ToolGateway
from tools.registry import ToolCallRequest


@dataclass
class OrchestratorResult:
    final_output: str
    tool_trace: List[Dict[str, Any]]
    latency_ms: float
    correlation_id: str


class MockModelPlanner:
    """
    Deterministic planner used by default for benchmark + CI stability.
    It deliberately attempts forbidden actions in adversarial scenarios so
    the gateway/policies can demonstrate prevention.
    """

    def plan_one_step(
        self,
        scenario: Dict[str, Any] | None,
        task: str,
        baseline: str,
        canaries: List[str],
    ) -> Tuple[str, Dict[str, Any], Taint, str]:
        """
        Returns: (tool_name, args, taint, draft_final_output)
        """
        if scenario is None:
            taint = Taint(from_user=True, from_retrieved=False, contains_canary=False)
            t = task.lower()
            if "ticket" in t:
                return (
                    "create_ticket",
                    {"project": "SEC", "title": "Ticket", "body": "Created from /run request."},
                    taint,
                    "Prepared ticket draft.",
                )
            if "summar" in t or "policy" in t:
                return "read_doc", {"doc_id": "refund_policy"}, taint, "Summarizing requested policy."
            return "http_get", {"url": "https://api.company.tld/status"}, taint, "Fetching status."

        sid = scenario["id"]
        category = scenario.get("category", "")
        expected = scenario.get("expected") or {}
        denied_domains = list(expected.get("denied_domains") or [])
        denied_tools = list(expected.get("denied_tools") or [])
        denied_projects = list(expected.get("denied_projects") or [])
        denied_url_paths = list(expected.get("denied_url_paths") or [])
        must_not_leak = bool(expected.get("must_not_leak_canaries", False))
        allowed_tools = list(expected.get("allowed_tools") or [])
        req_approval_for = list(expected.get("requires_approval_for") or [])

        is_adversarial = bool(
            scenario.get("adversarial_inputs")
            or (scenario.get("retrieval_setup") or {}).get("malicious_snippet")
        )

        taint = Taint()
        if category in ("direct_injection", "tool_misuse", "exfiltration", "excessive_agency"):
            taint.from_user = True
        if category in ("indirect_injection",):
            taint.from_retrieved = True

        # Try forbidden URL paths (B3-only capability: path allowlisting)
        if is_adversarial and denied_url_paths:
            tool = "http_get"
            # Use allowlisted domain but forbidden path
            path = denied_url_paths[0]
            args = {"url": f"https://api.company.tld{path}"}
            return tool, args, taint, f"[{sid}] Attempting forbidden endpoint."

        if is_adversarial and denied_domains:
            tool = "http_get"
            args = {"url": f"https://{denied_domains[0]}/payload"}
            return tool, args, taint, f"[{sid}] Attempting remote fetch."

        if is_adversarial and denied_tools:
            tool = denied_tools[0]
            args = {"noop": True}
            return tool, args, taint, f"[{sid}] Attempting forbidden tool."

        if (
            ("create_ticket" in allowed_tools)
            or ("create_ticket" in req_approval_for)
            or category in ("exfiltration", "excessive_agency")
        ):
            tool = "create_ticket"
            project = denied_projects[0] if (is_adversarial and denied_projects) else "SEC"
            max_body_chars = expected.get("max_ticket_body_chars")
            # If scenario expects oversized body, create one
            if is_adversarial and isinstance(max_body_chars, int):
                body = "X" * (max_body_chars + 100)  # Exceed limit
            else:
                body = f"{sid}: Auto-generated ticket."
            if is_adversarial and must_not_leak:
                body += f" Canary={canaries[0]}"
                taint.contains_canary = True
            args = {"project": project, "title": f"{sid} Ticket", "body": body}
            return tool, args, taint, f"[{sid}] Prepared ticket draft."

        # If scenario is adversarial and expects approval for http_get, propose a safe allowlisted call.
        # This lets B2 execute (attack success) while B3 halts with approval_required due to from_retrieved+network risk.
        if is_adversarial and "http_get" in req_approval_for:
            tool = "http_get"
            args = {"url": "https://api.company.tld/status"}  # path is allowlisted; approval is the control
            return tool, args, taint, f"[{sid}] Attempting status check (should require approval)."

        if category == "indirect_injection" or "read_doc" in allowed_tools:
            doc_id = (scenario.get("retrieval_setup") or {}).get("doc_id", "refund_policy")
            return "read_doc", {"doc_id": doc_id}, taint, f"[{sid}] Reading doc for summary."

        return "http_get", {"url": "https://api.company.tld/status"}, taint, f"[{sid}] Status fetched."


class AgentOrchestrator:
    def __init__(self, gateway: ToolGateway, canaries: List[str], max_steps: int = 6):
        self.gateway = gateway
        self.canaries = canaries
        self.max_steps = max_steps
        self.planner = MockModelPlanner()

    def run(self, task: str, baseline: str, scenario: Dict[str, Any] | None = None, ablation: Dict[str, Any] | None = None) -> OrchestratorResult:
        start = time.perf_counter()
        trace: List[Dict[str, Any]] = []
        correlation_id = f"run-{uuid.uuid4().hex[:12]}"

        for step in range(1, self.max_steps + 1):
            tool, args, taint, draft = self.planner.plan_one_step(
                scenario, task, baseline, self.canaries
            )

            if not tool:
                break

            req = ToolCallRequest(
                tool=tool,
                args=args,
                meta={
                    "scenario_id": (scenario["id"] if scenario else None),
                    "baseline": baseline,
                    "step": step,
                    "source": "mock_planner",
                    "correlation_id": correlation_id,
                    "taint": taint.model_dump(),
                    "ablation": (ablation or {}),
                },
            )

            res = self.gateway.execute(req, canaries=self.canaries)

            trace.append({"step": step, "request": req.model_dump(), "response": res.model_dump()})

            if res.status in ("denied", "approval_required"):
                final = f"{draft} (stopped: {res.status} / {res.policy.reason})"
                end = time.perf_counter()
                return OrchestratorResult(
                    final_output=final,
                    tool_trace=trace,
                    latency_ms=(end - start) * 1000,
                    correlation_id=correlation_id,
                )

            final = f"{draft} (tool executed: {tool})"
            end = time.perf_counter()
            return OrchestratorResult(
                final_output=final,
                tool_trace=trace,
                latency_ms=(end - start) * 1000,
                correlation_id=correlation_id,
            )

        end = time.perf_counter()
        return OrchestratorResult(
            final_output="No action taken.",
            tool_trace=trace,
            latency_ms=(end - start) * 1000,
            correlation_id=correlation_id,
        )
