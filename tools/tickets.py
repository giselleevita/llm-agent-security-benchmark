from __future__ import annotations

import json
from typing import Dict, Any, List


class TicketStore:
    """
    Deterministic in-memory ticket store.
    """

    def __init__(self):
        self._tickets: List[Dict[str, Any]] = []

    def create(self, project: str, title: str, body: str) -> Dict[str, Any]:
        payload = {"project": project, "title": title, "body": body}
        tid = f"TICKET-{abs(hash(json.dumps(payload, sort_keys=True))) % 100000}"
        ticket = {"ticket_id": tid, **payload}
        self._tickets.append(ticket)
        return {"ticket_id": tid}

    def count(self) -> int:
        return len(self._tickets)

    def all(self) -> List[Dict[str, Any]]:
        return list(self._tickets)
