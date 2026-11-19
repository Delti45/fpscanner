"""
Testy kroku 3: repozytoria (test kontraktowy), adapter Vault Transit (na lokalnym, udawanym
serwerze Transit z prawdziwym AES-GCM/HKDF), rotacja KEK-a po stronie Vaulta i budowanie
konfiguracji. PostgreSQL jest testowany tylko, gdy ustawiono
FP_TEST_PG_DSN (np. postgresql://fp:haslo@127.0.0.1:5432/fp); bez tego test jest pomijany.
"""
import base64
import contextlib
import json
import os
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from fpscanner.security.template_vault import (
    KeyProviderUnavailable,
    VaultError,
    decrypt_template,
    encrypt_template,
    record_kek_id,
)
from fpscanner.security.vault_transit import VaultTransitKeyProvider
from fpscanner.server.server_config import (
    ConfigError,
    build_key_provider,
    build_repository,
)
from fpscanner.server.template_repository import (
    InMemoryTemplateRepository,
    PostgresTemplateRepository,
)


@contextlib.contextmanager
def raises(exc):
    try:
        yield
    except exc:
        return
    except Exception as e:                                       # noqa: BLE001
        raise AssertionError(f"oczekiwano {exc.__name__}, jest {type(e).__name__}: {e}")
    raise AssertionError(f"oczekiwano {exc.__name__}, nie było wyjątku")


# --------------------------------------------------------------------------- #
# Udawany Vault Transit
# --------------------------------------------------------------------------- #
class FakeTransit:
    """Minimalny Transit: klucz derived aes256-gcm96, wersje, encrypt/decrypt/odczyt klucza."""

    def __init__(self, token="t0ken", derived=True):
        self.token, self.derived = token, derived
        self.versions = [os.urandom(32)]
        self.fail_status = None                    # np. 503: symulacja awarii
        self.calls = 0
        fake = self

        class H(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def _send(self, status, obj):
                raw = json.dumps(obj).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def _handle(self):
                fake.calls += 1
                n = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(n)) if n else {}
                if self.headers.get("X-Vault-Token") != fake.token:
                    return self._send(403, {"errors": ["permission denied"]})
                if fake.fail_status:
                    return self._send(fake.fail_status, {"errors": ["x"]})
                parts = self.path.split("/")                     # /v1/transit/<op>/<key>
                op = parts[3]
                if op == "keys":
                    return self._send(200, {"data": {
                        "type": "aes256-gcm96", "derived": fake.derived,
                        "latest_version": len(fake.versions),
                        "supports_encryption": True, "supports_decryption": True}})
                ctx = base64.b64decode(body.get("context", ""))
                if op == "encrypt":
                    ver = len(fake.versions)
                    nonce = os.urandom(12)
                    ct = AESGCM(fake._key(ver, ctx)).encrypt(
                        nonce, base64.b64decode(body["plaintext"]), None)
                    out = f"vault:v{ver}:" + base64.b64encode(nonce + ct).decode()
                    return self._send(200, {"data": {"ciphertext": out}})
                if op == "decrypt":
                    try:
                        _, v, b = body["ciphertext"].split(":", 2)
                        raw = base64.b64decode(b)
                        pt = AESGCM(fake._key(int(v[1:]), ctx)).decrypt(raw[:12], raw[12:], None)
                    except (InvalidTag, ValueError, IndexError):
                        return self._send(400, {"errors": ["cipher: message authentication failed"]})
                    return self._send(200, {"data": {"plaintext": base64.b64encode(pt).decode()}})
                self._send(404, {"errors": []})

            do_GET = do_POST = _handle

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.addr = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def _key(self, ver, ctx):
        return HKDF(hashes.SHA256(), 32, None, ctx).derive(self.versions[ver - 1])

    def rotate(self):
        self.versions.append(os.urandom(32))

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()


@contextlib.contextmanager
def transit(**kw):
    t = FakeTransit(**kw)
    try:
        yield t
    finally:
        t.stop()


def provider_for(t, **kw):
    kw.setdefault("key_info_ttl_s", 0.0)
    return VaultTransitKeyProvider(t.addr, "fp-kek", token=t.token, allow_insecure_http=True,
                                   retries=0, **kw)


# --------------------------------------------------------------------------- #
# Test kontraktowy repozytoriów
# --------------------------------------------------------------------------- #
def _contract(repo):
    assert repo.get("a") is None
    assert repo.add("a", b"r1") is True
    assert repo.add("a", b"r2") is False                       # nic nie zmienia
    assert repo.get("a") == b"r1"
    assert repo.add("b", b"\x00\xff" * 50) is True and repo.get("b") == b"\x00\xff" * 50
    assert repo.delete("a") is True and repo.delete("a") is False
    assert repo.get("a") is None and repo.get("b") is not None
    assert repo.add("a", b"nowy") is True                      # po usunięciu można dodać ponownie


def test_repository_contract_memory():
    _contract(InMemoryTemplateRepository())


def test_repository_contract_postgres():
    dsn = os.environ.get("FP_TEST_PG_DSN")
    if not dsn:
        print("  (pominięto: brak FP_TEST_PG_DSN)")
        return
    repo = PostgresTemplateRepository(dsn)
    try:
        for subject in ("a", "b"):
            repo.delete(subject)
        _contract(repo)
        for subject in ("a", "b"):
            repo.delete(subject)
    finally:
        repo.close()


# --------------------------------------------------------------------------- #
# Vault Transit
# --------------------------------------------------------------------------- #
def test_vault_roundtrip_and_binding():
    with transit() as t:
        p = provider_for(t)
        rec = encrypt_template(p, "alice", b"szablon")
        assert record_kek_id(rec) == "fp-kek:v1" == p.current_kek_id()
        assert decrypt_template(p, "alice", rec) == b"szablon"
        with raises(VaultError):
            decrypt_template(p, "bob", rec)                     # AAD/kontekst wiąże rekord z osobą
        with raises(VaultError):
            decrypt_template(p, "alice", rec[:-1] + bytes([rec[-1] ^ 1]))


def test_vault_rejects_bad_key_and_http_and_token():
    with transit(derived=False) as t:
        with raises(ValueError):
            provider_for(t)                                     # bez derived=true context byłby ignorowany
    with transit() as t:
        with raises(ValueError):
            VaultTransitKeyProvider(t.addr, "fp-kek", token="x")           # http bez jawnej zgody
        with raises(ValueError):
            VaultTransitKeyProvider(t.addr, "fp-kek", allow_insecure_http=True)   # brak tokenu
        with raises(KeyProviderUnavailable):
            VaultTransitKeyProvider(t.addr, "fp-kek", token="zly", allow_insecure_http=True, retries=0)


def test_vault_outage_is_unavailable_not_vaulterror():
    with transit() as t:
        p = provider_for(t)
        rec = encrypt_template(p, "alice", b"x")
        t.fail_status = 503
        with raises(KeyProviderUnavailable):
            decrypt_template(p, "alice", rec)                   # awaria != „rekord uszkodzony”
        with raises(KeyProviderUnavailable):
            encrypt_template(p, "alice", b"x")
        t.fail_status = None
        assert decrypt_template(p, "alice", rec) == b"x"        # odzyskuje się po awarii
    p.close()                                                   # zamknij trwałe połączenie
    with raises(KeyProviderUnavailable):
        decrypt_template(p, "alice", rec)                       # serwer wyłączony


def test_vault_token_file_reloaded_on_403():
    with transit() as t, tempfile.TemporaryDirectory() as d:
        f = os.path.join(d, "token")
        with open(f, "w") as fh:
            fh.write(t.token)
        p = VaultTransitKeyProvider(t.addr, "fp-kek", token_file=f, allow_insecure_http=True,
                                    retries=0, key_info_ttl_s=0.0)
        t.token = "nowy"                                        # Vault Agent odnowił token
        with open(f, "w") as fh:
            fh.write("nowy")
        assert decrypt_template(p, "a", encrypt_template(p, "a", b"x")) == b"x"


def test_vault_header_must_match_ciphertext():
    with transit() as t:
        p = provider_for(t)
        rec = encrypt_template(p, "alice", b"x")
        forged = rec.replace(b"fp-kek:v1", b"fp-kek:v9")        # ten sam rozmiar nagłówka
        with raises(VaultError):
            decrypt_template(p, "alice", forged)


# --------------------------------------------------------------------------- #
# Rotacja KEK-a (po stronie Vaulta: `vault write -f transit/keys/fp-kek/rotate`)
# --------------------------------------------------------------------------- #
def test_vault_rotation_keeps_old_records_readable():
    with transit() as t:
        p = provider_for(t)
        old = encrypt_template(p, "alice", b"przed-rotacja")
        assert record_kek_id(old) == "fp-kek:v1"
        t.rotate()
        assert p.current_kek_id() == "fp-kek:v2"
        assert decrypt_template(p, "alice", old) == b"przed-rotacja"     # stary rekord nadal czytelny
        new = encrypt_template(p, "alice", b"po-rotacji")
        assert record_kek_id(new) == "fp-kek:v2"                         # nowe rekordy: nowa wersja
        assert decrypt_template(p, "alice", new) == b"po-rotacji"


# --------------------------------------------------------------------------- #
# Konfiguracja
# --------------------------------------------------------------------------- #
def test_config_builders():
    with raises(ConfigError):
        build_key_provider({"FP_KEY_PROVIDER": "vault"})                  # brak FP_VAULT_ADDR
    with raises(ConfigError):
        build_key_provider({"FP_KEY_PROVIDER": "nieznany"})
    with raises(ConfigError):
        build_key_provider({})                                            # domyślnie vault: brak FP_VAULT_ADDR
    assert isinstance(build_repository({}), InMemoryTemplateRepository)
    with transit() as t:
        env = {"FP_KEY_PROVIDER": "vault", "FP_VAULT_ADDR": t.addr, "FP_VAULT_TOKEN": t.token,
               "FP_VAULT_ALLOW_HTTP": "1"}
        assert build_key_provider(env).current_kek_id() == "fp-kek:v1"
        env["FP_VAULT_TOKEN"] = "zly"
        with raises(ConfigError):
            build_key_provider(env)
