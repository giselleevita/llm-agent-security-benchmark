from __future__ import annotations

import socket
from typing import Any

import pytest

from tools.http_real import HttpReal, HttpRealConfig, HttpSecurityError


class _Resp:
    def __init__(self, status_code: int, text: str = "OK", headers: dict[str, str] | None = None):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}


class _Client:
    def __init__(self, response: _Resp):
        self._response = response

    def __enter__(self):
        return self

    def __exit__(self, *_args: Any):
        return None

    def get(self, _url: str) -> _Resp:
        return self._response


@pytest.fixture
def real_adapter() -> HttpReal:
    return HttpReal(
        HttpRealConfig(
            allowed_domains=["api.company.tld", "docs.company.tld"],
            timeout_ms=1000,
            allow_redirects=False,
            max_redirects=0,
        )
    )


def _mock_public_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))],
    )


def test_blocks_userinfo(real_adapter: HttpReal):
    with pytest.raises(HttpSecurityError) as exc:
        real_adapter.get("https://api.company.tld:443@evil.tld/status")
    assert exc.value.code == "DENY_INVALID_URL_AUTHORITY"


def test_blocks_unicode_and_punycode_hosts(real_adapter: HttpReal):
    with pytest.raises(HttpSecurityError) as exc1:
        real_adapter.get("https://xn--oogle-qmc.com/status")
    assert exc1.value.code == "DENY_PUNYCODE_HOST"

    with pytest.raises(HttpSecurityError) as exc2:
        real_adapter.get("https://gοοgle.com/status")
    assert exc2.value.code == "DENY_NON_ASCII_HOST"


def test_blocks_private_and_metadata_hosts(real_adapter: HttpReal):
    with pytest.raises(HttpSecurityError) as exc1:
        real_adapter.get("http://127.0.0.1/status")
    assert exc1.value.code in {"DENY_DOMAIN_NOT_ALLOWLISTED", "DENY_PRIVATE_IP"}

    with pytest.raises(HttpSecurityError) as exc2:
        real_adapter.get("http://metadata.google.internal/latest")
    assert exc2.value.code == "DENY_METADATA_ENDPOINT"


def test_blocks_path_traversal(real_adapter: HttpReal):
    with pytest.raises(HttpSecurityError) as exc:
        real_adapter.get("https://api.company.tld/%2e%2e/admin")
    assert exc.value.code == "DENY_PATH_TRAVERSAL"


def test_blocks_suffix_bypass_domain(real_adapter: HttpReal):
    with pytest.raises(HttpSecurityError) as exc:
        real_adapter.get("https://api.company.tld.evil.tld/status")
    assert exc.value.code == "DENY_DOMAIN_NOT_ALLOWLISTED"


def test_blocks_redirect_when_disabled(monkeypatch: pytest.MonkeyPatch, real_adapter: HttpReal):
    _mock_public_dns(monkeypatch)
    monkeypatch.setattr(
        "httpx.Client",
        lambda **_kwargs: _Client(_Resp(302, "", {"location": "https://evil.tld/steal"})),
    )
    with pytest.raises(HttpSecurityError) as exc:
        real_adapter.get("https://api.company.tld/status")
    assert exc.value.code == "DENY_UNSAFE_REDIRECT"


def test_ignores_proxy_env(monkeypatch: pytest.MonkeyPatch, real_adapter: HttpReal):
    _mock_public_dns(monkeypatch)
    seen: dict[str, Any] = {}

    def _factory(**kwargs: Any):
        seen.update(kwargs)
        return _Client(_Resp(200, "OK"))

    monkeypatch.setattr("httpx.Client", _factory)
    out = real_adapter.get("https://api.company.tld/status")
    assert out["status_code"] == 200
    assert seen.get("trust_env") is False
