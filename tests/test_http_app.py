"""Testy adaptera HTTP (FastAPI) przez TestClient: pytest -q  (wymaga httpx)."""
import base64
import json
import urllib.parse
from pathlib import Path

import numpy as np
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi.testclient import TestClient
from starlette.requests import Request

from fpscanner.biometrics.preprocessing import Minutia
from fpscanner.client.api_client import ApiClientError, FingerprintClient
from fpscanner.security.device_auth import (
    NetworkTrust,
    fingerprint_from_header,
    fingerprint_pem,
    resolve_client,
)
from fpscanner.security.template_vault import KeyProviderUnavailable
from fpscanner.server.http_app import MAX_BODY_BYTES, context_from_request, create_app
from fpscanner.server.server_config import build_service
from fpscanner.server.template_repository import RepositoryUnavailable
from fpscanner.tools.provision_dev import provision

PROXY = ("127.0.0.1", 50000)          # adres, z którego łączy się nginx (zaufany)
CLIENT_IP = "198.51.100.7"


def tpl(seed, n=40):
    rng = np.random.default_rng(seed)
    return [Minutia(int(rng.integers(20, 300)), int(rng.integers(20, 380)),
                    float(rng.uniform(0, 6.28)), int(rng.integers(0, 2))) for _ in range(n)]


def b64d(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


class Transport:
    """Transport dla FingerprintClient: wywołuje aplikację tak, jak zrobiłby to nginx."""

    def __init__(self, tc, headers=None):
        self.tc, self.extra, self.last = tc, headers or {}, None

    def post(self, path, body, headers):
        r = self.tc.post(path, content=json.dumps(body),
                         headers={"content-type": "application/json", **self.extra, **headers})
        self.last = r
        try:
            return r.status_code, r.json()
        except ValueError:
            return r.status_code, {}


class World:
    def __init__(self, tmp, env_overrides=None):
        self.out = provision(tmp, ["reader-01"], admin_ids=("admin-01",), behind_proxy=True, local_kek=True)
        self.svc, self.trust = build_service({**self.out["env"], **(env_overrides or {})})
        self.app = create_app(self.svc, self.trust)
        self.pub = Ed25519PublicKey.from_public_bytes(b64d(self.out["server_public_key"]))

    def proxy_headers(self, dev, ip=CLIENT_IP, xff=None, verify="SUCCESS"):
        pem = Path(self.out["clients"][dev]["cert"]).read_text()
        return {"x-forwarded-for": xff or ip, "x-client-cert": urllib.parse.quote(pem, safe=""),
                "x-client-cert-verify": verify}

    def client(self, dev="reader-01", *, peer=PROXY, headers=None, **kw):
        tc = TestClient(self.app, client=peer)
        tr = Transport(tc, headers if headers is not None else self.proxy_headers(dev))
        c = FingerprintClient(tr, device_id=dev, server_verify_key=self.pub,
                              device_secret=b64d(self.out["clients"][dev]["secret"]),
                              totp_secret=b64d(self.out["clients"][dev]["totp_secret"]), **kw)
        return c, tr, tc


@pytest.fixture
def world(tmp_path):
    return World(tmp_path)


def api_error(status, code, fn):
    with pytest.raises(ApiClientError) as e:
        fn()
    assert (e.value.status, e.value.code) == (status, code), (e.value.status, e.value.code)


# --------------------------------------------------------------------------- #
def test_full_flow_through_trusted_proxy(world):
    c, _, _ = world.client()
    c.connect()
    assert c.enroll("alice", tpl(1)) == {"status": "enrolled"}
    assert c.verify("alice", tpl(1)) is True
    assert c.verify("alice", tpl(77)) is False
    api_error(403, "forbidden", lambda: c.erase("alice"))            # czytnik nie kasuje
    admin, _, _ = world.client("admin-01")
    admin.connect()
    assert admin.erase("alice") == {"status": "erased"}
    assert c.verify("alice", tpl(1)) is False
    c.close()


def test_headers_from_untrusted_peer_are_ignored(world):
    # ten sam komplet nagłówków, ale połączenie nie pochodzi z zaufanego proxy
    c, _, _ = world.client(peer=("203.0.113.9", 4444))
    api_error(401, "auth_failed", c.connect)


def test_failed_certificate_verification_header_blocks_access(world):
    c, _, _ = world.client(headers=world.proxy_headers("reader-01", verify="FAILED"))
    api_error(401, "auth_failed", c.connect)


def test_foreign_certificate_in_header_is_rejected(world):
    # admin-01 ma swój sekret, ale proxy przekazało certyfikat reader-01
    c, _, _ = world.client("admin-01", headers=world.proxy_headers("reader-01"))
    api_error(401, "auth_failed", c.connect)


def test_x_forwarded_for_only_rightmost_untrusted_hop_counts(world):
    c, tr, _ = world.client(headers=world.proxy_headers("reader-01", xff=f"6.6.6.6, {CLIENT_IP}"))
    c.connect()                                                       # sfałszowany lewy wpis nie ma znaczenia
    tr.extra = world.proxy_headers("reader-01", xff=f"1.1.1.1, {CLIENT_IP}")
    assert c.verify("nobody", tpl(1)) is False                        # ten sam klient: token pasuje
    tr.extra = world.proxy_headers("reader-01", xff="198.51.100.99")
    api_error(401, "token_binding", lambda: c.verify("nobody", tpl(1)))


def test_stolen_token_from_other_address_is_rejected(world):
    c, tr, _ = world.client()
    c.connect()
    tr.extra = world.proxy_headers("reader-01", ip="203.0.113.77")
    api_error(401, "token_binding", lambda: c.verify("alice", tpl(1)))


def test_lockout_sets_retry_after_header():
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        w = World(tmp, {"FP_MAX_FAILURES_DEVICE": "2"})
        c, tr, _ = w.client()
        c.connect()
        c.enroll("alice", tpl(1))
        assert c.verify("alice", tpl(50)) is False and c.verify("alice", tpl(51)) is False
        api_error(429, "too_many_attempts", lambda: c.verify("alice", tpl(1)))
        assert 1 <= int(tr.last.headers["retry-after"]) <= 300


def test_body_limits_and_malformed_json(world):
    tc = TestClient(world.app, client=PROXY)
    r = tc.post("/v1/verify", content=b"x" * (MAX_BODY_BYTES + 1))
    assert (r.status_code, r.json()) == (413, {"error": "payload_too_large"})
    chunked = (b"x" * 1024 for _ in range(100))                       # bez Content-Length
    r = tc.post("/v1/verify", content=chunked)
    assert (r.status_code, r.json()) == (413, {"error": "payload_too_large"})
    r = tc.post("/v1/handshake", content=b"{nie json")
    assert (r.status_code, r.json()) == (400, {"error": "invalid_message"})
    r = tc.post("/v1/handshake", content=b"\xff\xfe")
    assert (r.status_code, r.json()) == (400, {"error": "invalid_message"})
    r = tc.post("/v1/handshake", content=b"[" * 5000 + b"]" * 5000)
    assert r.status_code == 400                                        # zbyt głębokie zagnieżdżenie
    r = tc.post("/v1/verify", content=b"{}")                           # bez tokenu
    assert (r.status_code, r.json()) == (401, {"error": "invalid_token"})


def test_unknown_paths_methods_and_no_openapi(world):
    tc = TestClient(world.app, client=PROXY)
    assert tc.get("/v1/verify").status_code == 405
    assert tc.get("/v1/verify").json() == {"error": "method_not_allowed"}
    assert tc.post("/nope").json() == {"error": "not_found"}
    for path in ("/docs", "/redoc", "/openapi.json"):
        assert tc.get(path).status_code == 404
    assert tc.get("/healthz").json() == {"status": "ok"}


def test_responses_are_not_cacheable(world):
    c, tr, _ = world.client()
    c.connect()
    assert tr.last.headers["cache-control"] == "no-store"
    assert tr.last.headers["x-content-type-options"] == "nosniff"


def test_unexpected_errors_do_not_leak_details(world, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("tajny szczegół wewnętrzny")
    monkeypatch.setattr(world.svc, "handshake", boom)
    tc = TestClient(world.app, client=PROXY, raise_server_exceptions=False)
    r = tc.post("/v1/handshake", content=b"{}")
    assert (r.status_code, r.json()) == (500, {"error": "internal_error"})
    assert "tajny" not in r.text


@pytest.mark.parametrize("exc", [KeyProviderUnavailable("vault: tajny szczegół"),
                                 RepositoryUnavailable("baza: tajny szczegół")])
def test_dependency_outage_is_503_not_500(world, monkeypatch, exc):
    def down(*a, **k):
        raise exc
    monkeypatch.setattr(world.svc, "handshake", down)
    tc = TestClient(world.app, client=PROXY, raise_server_exceptions=False)
    r = tc.post("/v1/handshake", content=b"{}")
    assert (r.status_code, r.json()) == (503, {"error": "unavailable"})
    assert r.headers["retry-after"] == "5" and "tajny" not in r.text


# --------------------------------------------------------------------------- #
# Budowanie kontekstu i nagłówek z certyfikatem
# --------------------------------------------------------------------------- #
def _request(peer, headers=None, tls=None):
    scope = {"type": "http", "method": "POST", "path": "/v1/verify", "query_string": b"",
             "headers": [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()],
             "client": (peer, 1234), "extensions": {"tls": tls} if tls else {}}
    return Request(scope)


def test_asgi_tls_extension_used_only_for_untrusted_peer(world):
    pem = Path(world.out["clients"]["reader-01"]["cert"]).read_text()
    expect = world.out["pki"]["devices"]["reader-01"]["fingerprint"]
    trust = NetworkTrust(trusted_proxies=("127.0.0.1",))
    direct = context_from_request(_request("203.0.113.9", tls={"client_cert_chain": [pem]}), trust)
    assert direct.cert_fingerprint == expect and direct.client_ip == "203.0.113.9"
    # połączenie od proxy: jego własny certyfikat TLS nie jest certyfikatem urządzenia
    via_proxy = context_from_request(_request("127.0.0.1", tls={"client_cert_chain": [pem]}), trust)
    assert via_proxy.cert_fingerprint is None


def test_bearer_token_parsing():
    trust = NetworkTrust()
    ok = lambda h: context_from_request(_request("203.0.113.9", {"Authorization": h}), trust).bearer_token
    assert ok("Bearer abc.def") == "abc.def" and ok("bearer  xyz ") == "xyz"
    assert ok("Basic dXNlcjpwdw==") is None and ok("Bearer") is None and ok("") is None


def test_certificate_header_accepts_pem_or_fingerprint(world):
    pem = Path(world.out["clients"]["reader-01"]["cert"]).read_text()
    fp = world.out["pki"]["devices"]["reader-01"]["fingerprint"]
    assert fingerprint_pem(pem) == fp
    assert fingerprint_from_header(urllib.parse.quote(pem, safe="")) == fp
    assert fingerprint_from_header(fp.upper().replace("SHA256:", "sha256:")) == fp
    for bad in ("", "nic", "-----BEGIN CERTIFICATE-----\nZm9v\n-----END CERTIFICATE-----",
                "%2D%2D%2D" * 10, "A" * 20_000):
        with pytest.raises(ValueError):
            fingerprint_from_header(bad)
    trust = NetworkTrust(trusted_proxies=("10.0.0.0/8",), cert_header="x-client-cert",
                         verify_header="x-client-cert-verify")
    h = {"x-client-cert": urllib.parse.quote(pem, safe=""), "x-client-cert-verify": "SUCCESS",
         "x-forwarded-for": "198.51.100.7"}
    assert resolve_client("10.0.0.5", h, trust) == ("198.51.100.7", fp)
    assert resolve_client("10.0.0.5", {**h, "x-client-cert": "śmieci"}, trust)[1] is None
    assert resolve_client("203.0.113.9", h, trust) == ("203.0.113.9", None)


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
