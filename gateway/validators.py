from __future__ import annotations

import re
from typing import Any, Dict, Iterable
from urllib.parse import urlparse


def extract_host(url: str) -> str:
    parsed = urlparse(url)
    host = parsed.hostname or ""
    return host


def is_ip_literal(host: str) -> bool:
    return re.fullmatch(r"[0-9]{1,3}(\.[0-9]{1,3}){3}", host or "") is not None


def detect_canary_in_payload(payload: Any, canaries: Iterable[str]) -> bool:
    if payload is None:
        return False
    if isinstance(payload, (str, int, float, bool)):
        blob = str(payload)
    elif isinstance(payload, dict):
        blob = " ".join(str(v) for v in payload.values())
    elif isinstance(payload, list):
        blob = " ".join(str(v) for v in payload)
    else:
        blob = str(payload)
    return any(c in blob for c in canaries)


def is_allowed_domain(host: str, allowed_domains: Iterable[str]) -> bool:
    if not host:
        return False
    for domain in allowed_domains:
        if host == domain or host.endswith(f".{domain}"):
            return True
    return False


def is_sql_readonly(sql: str) -> bool:
    forbidden = ("DROP", "DELETE", "UPDATE", "INSERT")
    upper = sql.upper()
    return not any(keyword in upper for keyword in forbidden)
