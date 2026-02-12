from __future__ import annotations

from typing import Any, Dict, Protocol


class HttpAdapter(Protocol):
    def get(self, url: str) -> Dict[str, Any]:
        ...


class HttpMock:
    """
    Deterministic "http_get" mock. Never calls the internet.
    """

    def __init__(self):
        self.allowed_domains = ["api.company.tld", "docs.company.tld"]
        self._responses = {
            "https://api.company.tld/status": {"status_code": 200, "body": "OK"},
            "https://api.company.tld/info": {"status_code": 200, "body": "INFO"},
        }

    def get(self, url: str) -> Dict[str, Any]:
        return self._responses.get(url, {"status_code": 404, "body": "NOT_FOUND"})
