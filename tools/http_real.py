from __future__ import annotations

import ipaddress
import posixpath
import socket
from dataclasses import dataclass
from typing import Any, Dict, Iterable, Set
from urllib.parse import SplitResult, unquote, urlsplit, urlunsplit

import httpx


class HttpSecurityError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


@dataclass
class HttpRealConfig:
    allowed_domains: list[str]
    timeout_ms: int = 5000
    allow_redirects: bool = False
    max_redirects: int = 0


class HttpReal:
    """Hardened adapter used only when HTTP_ADAPTER=real."""

    def __init__(self, config: HttpRealConfig):
        self.config = config

    @property
    def allowed_domains(self) -> list[str]:
        return self.config.allowed_domains

    @allowed_domains.setter
    def allowed_domains(self, value: Iterable[str]) -> None:
        self.config.allowed_domains = list(value)

    def get(self, url: str) -> Dict[str, Any]:
        current_url = self._normalize_url(url)
        visited = 0

        while True:
            host = current_url.hostname or ""
            self._enforce_host_policy(host)
            before = self._resolve_public_ips(host)
            timeout = max(self.config.timeout_ms / 1000.0, 0.1)
            with httpx.Client(timeout=timeout, follow_redirects=False, trust_env=False) as client:
                response = client.get(urlunsplit(current_url))

            after = self._resolve_public_ips(host)
            if before != after:
                raise HttpSecurityError("DENY_DNS_REBINDING_SUSPECTED", "resolved IP set changed")

            if 300 <= response.status_code < 400:
                if not self.config.allow_redirects:
                    raise HttpSecurityError("DENY_UNSAFE_REDIRECT", "redirects are disabled")
                visited += 1
                if visited > self.config.max_redirects:
                    raise HttpSecurityError("DENY_TOO_MANY_REDIRECTS", "max redirects exceeded")
                location = response.headers.get("location")
                if not location:
                    raise HttpSecurityError("DENY_UNSAFE_REDIRECT", "redirect without location")
                current_url = self._normalize_url(location)
                continue

            return {
                "status_code": int(response.status_code),
                "body": response.text[:8192],
                "headers": dict(response.headers),
            }

    def _normalize_url(self, raw_url: str) -> SplitResult:
        parsed = urlsplit(raw_url)
        if parsed.scheme.lower() not in ("http", "https"):
            raise HttpSecurityError("DENY_SCHEME_NOT_ALLOWED", "only http/https are allowed")
        if parsed.username or parsed.password:
            raise HttpSecurityError("DENY_INVALID_URL_AUTHORITY", "userinfo in URL is not allowed")
        if not parsed.hostname:
            raise HttpSecurityError("DENY_INVALID_URL", "host is required")

        raw_host = parsed.hostname
        if any(ord(ch) > 127 for ch in raw_host):
            raise HttpSecurityError("DENY_NON_ASCII_HOST", "non-ascii host is not allowed")
        if "xn--" in raw_host.lower():
            raise HttpSecurityError("DENY_PUNYCODE_HOST", "punycode host is not allowed")
        host_ascii = raw_host.encode("idna").decode("ascii").lower()

        path = parsed.path or "/"
        decoded = unquote(path)
        normalized = posixpath.normpath(decoded)
        if ".." in decoded.split("/"):
            raise HttpSecurityError("DENY_PATH_TRAVERSAL", "path traversal not allowed")
        if "%2e%2e" in path.lower() or "%2f" in path.lower():
            raise HttpSecurityError("DENY_PATH_TRAVERSAL", "encoded traversal not allowed")
        if not normalized.startswith("/"):
            normalized = "/" + normalized

        netloc = host_ascii
        if parsed.port:
            netloc = f"{host_ascii}:{parsed.port}"

        return SplitResult(
            scheme=parsed.scheme.lower(),
            netloc=netloc,
            path=normalized,
            query=parsed.query,
            fragment="",
        )

    def _enforce_host_policy(self, host: str) -> None:
        try:
            addr = ipaddress.ip_address(host)
            if self._is_private_or_reserved(addr):
                raise HttpSecurityError("DENY_PRIVATE_IP", f"blocked non-public address {host}")
            raise HttpSecurityError("DENY_IP_LITERAL", "ip literals are not allowed")
        except ValueError:
            pass

        if host in {"metadata.google.internal", "metadata", "localhost"}:
            raise HttpSecurityError("DENY_METADATA_ENDPOINT", "metadata/local endpoints are blocked")

        allowed = self.config.allowed_domains
        if host not in allowed and not any(host.endswith("." + d) for d in allowed):
            raise HttpSecurityError("DENY_DOMAIN_NOT_ALLOWLISTED", "host is not allowlisted")

    def _resolve_public_ips(self, host: str) -> Set[str]:
        try:
            records = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        except socket.gaierror as exc:
            raise HttpSecurityError("DENY_DNS_RESOLUTION_FAILED", str(exc)) from exc

        ips: Set[str] = set()
        for rec in records:
            ip = rec[4][0]
            addr = ipaddress.ip_address(ip)
            if self._is_private_or_reserved(addr):
                raise HttpSecurityError("DENY_PRIVATE_IP", f"blocked non-public address {ip}")
            if str(addr) == "169.254.169.254":
                raise HttpSecurityError("DENY_METADATA_ENDPOINT", "metadata IP blocked")
            ips.add(ip)
        return ips

    @staticmethod
    def _is_private_or_reserved(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
        return (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_reserved
            or addr.is_unspecified
            or addr.is_multicast
        )
