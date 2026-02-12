from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ApprovalResult:
    approved: bool
    reason: str


def require_external_approval() -> ApprovalResult:
    return ApprovalResult(approved=False, reason="external_approval_required")
