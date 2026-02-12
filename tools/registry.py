from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

from pydantic import BaseModel, Field


class ToolCallRequest(BaseModel):
    tool: str
    args: Dict[str, Any] = Field(default_factory=dict)
    meta: Dict[str, Any] = Field(default_factory=dict)


class PolicyInfo(BaseModel):
    allow: bool
    requires_approval: bool = False
    reason: str = "no_reason"


class ToolCallResult(BaseModel):
    status: str
    tool: str
    result: Any | None = None
    error: Dict[str, Any] | None = None
    policy: PolicyInfo | None = None

    @staticmethod
    def allowed(tool: str, result: Any, policy: PolicyInfo) -> "ToolCallResult":
        return ToolCallResult(status="allowed", tool=tool, result=result, policy=policy)

    @staticmethod
    def denied(tool: str, reason: str) -> "ToolCallResult":
        return ToolCallResult(
            status="denied",
            tool=tool,
            error={"code": "POLICY_DENY", "message": reason},
            policy=PolicyInfo(allow=False, requires_approval=False, reason=reason),
        )

    @staticmethod
    def approval_required(tool: str, proposed_action: Dict[str, Any], policy: PolicyInfo) -> "ToolCallResult":
        return ToolCallResult(
            status="approval_required",
            tool=tool,
            result={"proposed_action": proposed_action},
            policy=policy,
        )


class SearchDocsArgs(BaseModel):
    query: str


class ReadDocArgs(BaseModel):
    doc_id: str


class HttpGetArgs(BaseModel):
    url: str
    follow_redirects: bool = False


class CreateTicketArgs(BaseModel):
    project: str
    title: str
    body: str


class DbQueryReadonlyArgs(BaseModel):
    sql: str


@dataclass
class ToolDef:
    name: str
    args_model: type[BaseModel]
    execute: Callable[[BaseModel], Dict[str, Any]]


class ToolRegistry:
    def __init__(self, docs, http, tickets):
        self.docs = docs
        self.http = http
        self.tickets = tickets

        self._allowed_domains: List[str] = ["api.company.tld", "docs.company.tld"]
        self.allowed_ticket_projects: List[str] = ["SEC", "IT"]
        self._sync_http_allowed_domains()

        self._tools: Dict[str, ToolDef] = {
            "search_docs": ToolDef("search_docs", SearchDocsArgs, self._exec_search_docs),
            "read_doc": ToolDef("read_doc", ReadDocArgs, self._exec_read_doc),
            "http_get": ToolDef("http_get", HttpGetArgs, self._exec_http_get),
            "create_ticket": ToolDef("create_ticket", CreateTicketArgs, self._exec_create_ticket),
            "db_query_readonly": ToolDef("db_query_readonly", DbQueryReadonlyArgs, self._exec_db_query_readonly),
        }

    def get(self, name: str) -> Optional[ToolDef]:
        return self._tools.get(name)

    @property
    def allowed_domains(self) -> List[str]:
        return self._allowed_domains

    @allowed_domains.setter
    def allowed_domains(self, value: List[str]) -> None:
        self._allowed_domains = list(value)
        self._sync_http_allowed_domains()

    def _sync_http_allowed_domains(self) -> None:
        if hasattr(self.http, "allowed_domains"):
            setattr(self.http, "allowed_domains", list(self._allowed_domains))

    def _exec_search_docs(self, args: SearchDocsArgs) -> Dict[str, Any]:
        return self.docs.search(args.query)

    def _exec_read_doc(self, args: ReadDocArgs) -> Dict[str, Any]:
        return self.docs.read(args.doc_id)

    def _exec_http_get(self, args: HttpGetArgs) -> Dict[str, Any]:
        return self.http.get(args.url)

    def _exec_create_ticket(self, args: CreateTicketArgs) -> Dict[str, Any]:
        return self.tickets.create(args.project, args.title, args.body)

    def _exec_db_query_readonly(self, args: DbQueryReadonlyArgs) -> Dict[str, Any]:
        sql_upper = args.sql.upper()
        if any(k in sql_upper for k in ["DROP", "DELETE", "UPDATE", "INSERT"]):
            return {"error": "write_query_denied"}
        return {"rows": [{"count": self.tickets.count()}]}
