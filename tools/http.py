from __future__ import annotations

from typing import Dict, Any


class HttpMock:
    """
    Deterministic "http_get" mock. Never calls the internet.
    """

    def __init__(self):
        self._responses = {
            "https://api.company.tld/status": {"status_code": 200, "body": "OK"},
            "https://api.company.tld/info": {"status_code": 200, "body": "INFO"},
        }

    def get(self, url: str) -> Dict[str, Any]:
        return self._responses.get(url, {"status_code": 404, "body": "NOT_FOUND"})
