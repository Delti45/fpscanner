"""
Test integracyjny: prawdziwy nginx (TLS 1.3 + mTLS) -> uvicorn (http_app) -> klient.
Pomijany, gdy w systemie nie ma nginx (apt install nginx / nginx-light).
Uruchomienie: pytest -q tests/test_proxy_integration.py
"""
import base64
import http.client
import os
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

import fpscanner
from fpscanner.client.api_client import ApiClientError, FingerprintClient, HttpsTransport
from fpscanner.security import tls_config as tc
from fpscanner.tools.provision_dev import provision

NGINX = shutil.which("nginx") or ("/usr/sbin/nginx" if os.path.exists("/usr/sbin/nginx") else None)
pytestmark = pytest.mark.skipif(NGINX is None, reason="brak nginx w systemie")


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_for(check, what, timeout=15.0):
    end = time.time() + timeout
    while time.time() < end:
        try:
            if check():
                return
        except OSError:
            pass
        time.sleep(0.1)
    raise AssertionError(f"nie doczekano się: {what}")


def b64d(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def tpl(seed, n=40):
    import numpy as np

    from fpscanner.biometrics.preprocessing import Minutia
    rng = np.random.default_rng(seed)
    return [Minutia(int(rng.integers(20, 300)), int(rng.integers(20, 380)),
                    float(rng.uniform(0, 6.28)), int(rng.integers(0, 2))) for _ in range(n)]


@pytest.fixture(scope="module")
def stack():
    proxy_port, app_port = free_port(), free_port()
    procs = []
    with tempfile.TemporaryDirectory() as tmp:
        out = provision(tmp, ["reader-01"], admin_ids=("admin-01",), behind_proxy=True,
                        proxy_port=proxy_port, app_port=app_port, local_kek=True)
        src_dir = str(Path(fpscanner.__file__).resolve().parent.parent)
        env = {**os.environ, **out["env"], "PYTHONPATH": src_dir + os.pathsep + os.environ.get("PYTHONPATH", "")}
        app_log = open(Path(tmp) / "app.log", "wb")
        procs.append(subprocess.Popen([sys.executable, "-m", "fpscanner.server.http_app"], env=env,
                                      stdout=app_log, stderr=subprocess.STDOUT))
        wait_for(lambda: urllib.request.urlopen(f"http://127.0.0.1:{app_port}/healthz", timeout=1).status == 200,
                 "uvicorn")
        procs.append(subprocess.Popen([NGINX, "-c", out["nginx_conf"], "-p", out["nginx_run_dir"],
                                       "-g", "daemon off;"], stdout=subprocess.DEVNULL,
                                      stderr=subprocess.DEVNULL))
        wait_for(lambda: socket.create_connection(("127.0.0.1", proxy_port), timeout=1).close() or True,
                 "nginx")
        try:
            yield {"out": out, "url": f"https://127.0.0.1:{proxy_port}", "port": proxy_port,
                   "pub": Ed25519PublicKey.from_public_bytes(b64d(out["server_public_key"]))}
        finally:
            for p in reversed(procs):
                p.terminate()
            for p in procs:
                try:
                    p.wait(5)
                except subprocess.TimeoutExpired:
                    p.kill()
            app_log.close()


# Klient łączy się z 127.0.0.2, a nginx widzi go pod tym adresem: inny niż adres proxy (127.0.0.1).
# Bez tego test nie wykryłby, że uvicorn z domyślnym `proxy_headers` podmienia adres połączenia.
CLIENT_SRC = ("127.0.0.2", 0)


def make_client(stack, dev, *, cert_of=None, extra_headers=None):
    """Klient z certyfikatem `cert_of` (domyślnie własnym); `extra_headers` dopisuje próbę fałszerstwa."""
    info, own = stack["out"]["clients"][cert_of or dev], stack["out"]["clients"][dev]
    ctx = tc.client_ssl_context(info["ca"], info["cert"], info["key"])
    transport = HttpsTransport(stack["url"], ctx, source_address=CLIENT_SRC)
    if extra_headers:
        inner = transport

        class Spoofing:
            def post(self, path, body, headers):
                return inner.post(path, body, {**headers, **extra_headers})
        transport = Spoofing()
    return FingerprintClient(transport, device_id=dev, server_verify_key=stack["pub"],
                             device_secret=b64d(own["secret"]))


def test_full_flow_over_tls13_with_mtls(stack):
    c = make_client(stack, "reader-01")
    c.connect()
    assert c.enroll("alice", tpl(1)) == {"status": "enrolled"}
    assert c.verify("alice", tpl(1)) is True
    assert c.verify("alice", tpl(77)) is False
    with pytest.raises(ApiClientError) as e:
        c.erase("alice")
    assert (e.value.status, e.value.code) == (403, "forbidden")
    admin = make_client(stack, "admin-01")
    admin.connect()
    assert admin.erase("alice") == {"status": "erased"}
    c.close()


def test_proxy_overwrites_certificate_header_sent_by_client(stack):
    """Atakujący z certyfikatem czytnika i skradzionym sekretem admina podstawia certyfikat admina w nagłówku."""
    admin_pem = Path(stack["out"]["clients"]["admin-01"]["cert"]).read_text()
    forged = {"X-Client-Cert": urllib.parse.quote(admin_pem, safe=""),
              "X-Client-Cert-Verify": "SUCCESS", "X-Forwarded-For": "6.6.6.6"}
    c = make_client(stack, "admin-01", cert_of="reader-01", extra_headers=forged)
    # certyfikat z TLS to reader-01, więc po nadpisaniu nagłówka nie pasuje do admin-01
    with pytest.raises(ApiClientError) as e:
        c.connect()
    assert (e.value.status, e.value.code) == (401, "auth_failed")


def raw_post(stack, ctx, path="/v1/handshake", method="POST", body=b"{}"):
    conn = http.client.HTTPSConnection("127.0.0.1", stack["port"], context=ctx, timeout=8,
                                       source_address=CLIENT_SRC)
    try:
        conn.request(method, path, body=body, headers={"Content-Type": "application/json"})
        r = conn.getresponse()
        return r.status, r.read(200)
    finally:
        conn.close()


def test_connection_without_client_certificate_never_reaches_app(stack):
    ctx = tc.client_ssl_context(stack["out"]["pki"]["ca"])
    try:
        status, body = raw_post(stack, ctx)
    except (ssl.SSLError, OSError, http.client.HTTPException):
        return                                           # odrzucone na poziomie TLS
    assert status == 400 and b'"error"' not in body       # strona błędu nginx, nie odpowiedź aplikacji


def test_certificate_from_foreign_ca_is_rejected(stack):
    with tempfile.TemporaryDirectory() as tmp:
        other = tc.generate_dev_pki(tmp, ["intruder"])
        d = other["devices"]["intruder"]
        ctx = tc.client_ssl_context(stack["out"]["pki"]["ca"], d["cert"], d["key"])
        try:
            status, body = raw_post(stack, ctx)
        except (ssl.SSLError, OSError, http.client.HTTPException):
            return
        assert status != 200 and b'"error"' not in body


def test_tls12_client_is_rejected(stack):
    info = stack["out"]["clients"]["reader-01"]
    ctx = tc.client_ssl_context(info["ca"], info["cert"], info["key"])
    ctx.minimum_version = ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    with pytest.raises((ssl.SSLError, OSError)):
        raw_post(stack, ctx)


def test_proxy_exposes_only_post_v1(stack):
    info = stack["out"]["clients"]["reader-01"]
    ctx = tc.client_ssl_context(info["ca"], info["cert"], info["key"])
    assert raw_post(stack, ctx, "/v1/verify", "GET", b"")[0] == 403          # limit_except POST
    assert raw_post(stack, ctx, "/healthz", "GET", b"")[0] == 404            # nie wystawiamy na zewnątrz
    assert raw_post(stack, ctx, "/docs", "GET", b"")[0] == 404
    assert raw_post(stack, ctx, "/v1/verify", "POST", b"x" * 200_000)[0] == 413   # limit rozmiaru w nginx
