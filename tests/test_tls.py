"""Testy mTLS na prawdziwych połączeniach TLS. Uruchomienie: pytest -q"""
import os
import socket
import ssl
import stat
import tempfile
import threading
from pathlib import Path

import fpscanner.security.tls_config as tc
from fpscanner.security.device_auth import fingerprint_from_asgi_tls, fingerprint_pem, normalize_fingerprint


class OneShotServer:
    """Przyjmuje jedno połączenie TLS i zapisuje, jak się skończyło."""

    def __init__(self, ctx):
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(1)
        self.sock.settimeout(8)
        self.port = self.sock.getsockname()[1]
        self.result = None
        self._t = threading.Thread(target=self._serve, args=(ctx,), daemon=True)
        self._t.start()

    def _serve(self, ctx):
        try:
            conn, _ = self.sock.accept()
        except OSError as e:
            self.result = ("no-connection", str(e))
            return
        try:
            t = ctx.wrap_socket(conn, server_side=True)          # tu odbywa się handshake
            der = t.getpeercert(binary_form=True)
            self.result = ("ok", t.version(), der)
            t.recv(16)                      # najpierw odczyt, inaczej zamknięcie daje reset TCP
            t.sendall(b"pong")
            t.close()
        except (ssl.SSLError, OSError) as e:
            self.result = ("fail", type(e).__name__, str(e))
            conn.close()
        finally:
            self.sock.close()

    def wait(self):
        self._t.join(10)
        return self.result


def client_attempt(port, ctx, hostname="localhost"):
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=8) as s:
            with ctx.wrap_socket(s, server_hostname=hostname) as t:
                t.sendall(b"ping")
                data = t.recv(16)       # w TLS 1.3 odrzucenie certyfikatu klienta widać dopiero tutaj
                if not data:
                    return ("fail", "closed", "")
                return ("ok", t.version(), data)
    except (ssl.SSLError, OSError) as e:
        return ("fail", type(e).__name__, str(e))


def make_pki(tmp):
    return tc.generate_dev_pki(tmp, ["reader-01", "reader-02"], extra_ca_names=("intruder",))


def test_valid_client_cert_connects_over_tls13_and_fingerprint_matches():
    with tempfile.TemporaryDirectory() as tmp:
        pki = make_pki(tmp)
        srv = OneShotServer(tc.server_ssl_context(pki["server_cert"], pki["server_key"], pki["ca"]))
        dev = pki["devices"]["reader-01"]
        res = client_attempt(srv.port, tc.client_ssl_context(pki["ca"], dev["cert"], dev["key"]))
        seen = srv.wait()
        assert res == ("ok", "TLSv1.3", b"pong"), res
        assert seen[0] == "ok" and seen[1] == "TLSv1.3"
        from fpscanner.security.device_auth import fingerprint_der
        assert fingerprint_der(seen[2]) == dev["fingerprint"]          # to z tego odcisku korzysta serwer
        assert dev["fingerprint"] != pki["devices"]["reader-02"]["fingerprint"]


def test_client_without_certificate_is_rejected():
    with tempfile.TemporaryDirectory() as tmp:
        pki = make_pki(tmp)
        srv = OneShotServer(tc.server_ssl_context(pki["server_cert"], pki["server_key"], pki["ca"]))
        res = client_attempt(srv.port, tc.client_ssl_context(pki["ca"]))
        seen = srv.wait()
        assert res[0] == "fail", res
        assert seen[0] == "fail", seen


def test_certificate_from_foreign_ca_is_rejected():
    with tempfile.TemporaryDirectory() as tmp:
        pki = make_pki(tmp)
        intruder = pki["other_intruder"]
        srv = OneShotServer(tc.server_ssl_context(pki["server_cert"], pki["server_key"], pki["ca"]))
        res = client_attempt(srv.port, tc.client_ssl_context(pki["ca"], intruder["cert"], intruder["key"]))
        seen = srv.wait()
        assert res[0] == "fail" and seen[0] == "fail", (res, seen)


def test_tls12_client_is_rejected():
    with tempfile.TemporaryDirectory() as tmp:
        pki = make_pki(tmp)
        dev = pki["devices"]["reader-01"]
        srv = OneShotServer(tc.server_ssl_context(pki["server_cert"], pki["server_key"], pki["ca"]))
        ctx = tc.client_ssl_context(pki["ca"], dev["cert"], dev["key"])
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        res = client_attempt(srv.port, ctx)
        seen = srv.wait()
        assert res[0] == "fail" and seen[0] == "fail", (res, seen)


def test_client_rejects_server_with_untrusted_ca_or_wrong_hostname():
    with tempfile.TemporaryDirectory() as tmp:
        pki = make_pki(tmp)
        dev = pki["devices"]["reader-01"]
        srv = OneShotServer(tc.server_ssl_context(pki["server_cert"], pki["server_key"], pki["ca"]))
        res = client_attempt(srv.port, tc.client_ssl_context(pki["other_intruder"]["ca"], dev["cert"], dev["key"]))
        srv.wait()
        assert res[0] == "fail", res                                    # serwer spoza zaufanego CA
    with tempfile.TemporaryDirectory() as tmp:
        pki = make_pki(tmp)
        dev = pki["devices"]["reader-01"]
        srv = OneShotServer(tc.server_ssl_context(pki["server_cert"], pki["server_key"], pki["ca"]))
        res = client_attempt(srv.port, tc.client_ssl_context(pki["ca"], dev["cert"], dev["key"]),
                             hostname="evil.example")
        srv.wait()
        assert res[0] == "fail", res                                    # niezgodna nazwa hosta


def test_optional_client_cert_mode_allows_connection_without_certificate():
    with tempfile.TemporaryDirectory() as tmp:
        pki = make_pki(tmp)
        srv = OneShotServer(tc.server_ssl_context(pki["server_cert"], pki["server_key"], pki["ca"],
                                                  require_client_cert=False))
        res = client_attempt(srv.port, tc.client_ssl_context(pki["ca"]))
        seen = srv.wait()
        assert res[0] == "ok" and seen[0] == "ok" and not seen[2]       # połączono, ale bez certyfikatu


def test_asgi_tls_extension_and_fingerprint_helpers():
    with tempfile.TemporaryDirectory() as tmp:
        pki = make_pki(tmp)
        dev = pki["devices"]["reader-01"]
        pem = Path(dev["cert"]).read_text()
        assert fingerprint_pem(pem) == dev["fingerprint"]
        assert fingerprint_from_asgi_tls({"client_cert_chain": [pem]}) == dev["fingerprint"]
        assert fingerprint_from_asgi_tls({"client_cert_chain": []}) is None
        assert fingerprint_from_asgi_tls({"client_cert_chain": ["to nie jest PEM"]}) is None
        assert fingerprint_from_asgi_tls(None) is None
        raw = dev["fingerprint"].split(":")[1]
        spaced = ":".join(raw[i:i + 2] for i in range(0, len(raw), 2)).upper()
        assert normalize_fingerprint(spaced) == dev["fingerprint"]      # format z dwukropkami


def test_private_keys_are_not_world_readable():
    if os.name != "posix":
        return
    with tempfile.TemporaryDirectory() as tmp:
        pki = make_pki(tmp)
        for path in (pki["ca_key"], pki["server_key"], pki["devices"]["reader-01"]["key"]):
            assert stat.S_IMODE(os.stat(path).st_mode) == 0o600, path


if __name__ == "__main__":
    import sys
    import time
    tests = [(n, f) for n, f in sorted(globals().items()) if n.startswith("test_")]
    failed = 0
    for name, fn in tests:
        t0 = time.time()
        try:
            fn()
            print(f"PASS {name} ({time.time() - t0:.2f}s)")
        except Exception as e:                                # noqa: BLE001
            failed += 1
            print(f"FAIL {name}: {type(e).__name__}: {e}")
    print(f"\n{len(tests) - failed}/{len(tests)} testów OK")
    sys.exit(1 if failed else 0)
