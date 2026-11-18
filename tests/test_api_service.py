"""
Testy tokenów JWT, uwierzytelniania urządzeń i logiki endpointów (bez frameworka HTTP),
w tym scenariusze ataków. Uruchomienie: pytest -q
"""
import base64
import contextlib
import copy
import os
import struct
import tempfile
from dataclasses import dataclass

import jwt
import numpy as np
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

import fpscanner.server.wire_protocol as wp
from fpscanner.biometrics.preprocessing import Minutia, template_to_bytes
from fpscanner.client.api_client import ApiClientError, FingerprintClient
from fpscanner.security.crypto_session import ClientHandshake, _b64e, seal
from fpscanner.security.device_auth import (
    DeviceAuthError,
    DevicePolicy,
    InMemoryDeviceRegistry,
    NetworkTrust,
    authenticate_device,
    check_device_binding,
    device_proof,
    normalize_fingerprint,
    resolve_client,
)
from fpscanner.security.replay_guard import ReplayError
from fpscanner.security.session_tokens import (
    TokenBindingError,
    TokenExpired,
    TokenInvalid,
    TokenService,
)
from fpscanner.security.template_vault import LocalKeyProvider, VaultError, decrypt_template
from fpscanner.security.totp import totp
from fpscanner.server.api_service import ApiError, ApiService, AttemptLimiter, RequestContext, ServiceSettings
from fpscanner.server.server_config import ConfigError, build_service
from fpscanner.server.template_repository import InMemoryTemplateRepository

T0 = 1_800_000_000_000                 # ms
T0S = T0 // 1000
FP_A, FP_B, FP_C = ("sha256:" + c * 64 for c in ("aa", "bb", "cc"))
IP = "203.0.113.10"


@contextlib.contextmanager
def raises(exc):
    try:
        yield
    except exc:
        return
    except Exception as e:                                       # noqa: BLE001
        raise AssertionError(f"oczekiwano {exc.__name__}, jest {type(e).__name__}: {e}")
    raise AssertionError(f"oczekiwano {exc.__name__}, nie było wyjątku")


@contextlib.contextmanager
def api_error(status, code=None):
    try:
        yield
    except ApiClientError as e:
        assert e.status == status and (code is None or e.code == code), (e.status, e.code)
        return
    raise AssertionError(f"oczekiwano błędu API {status}")


# ============================= TOKENY JWT ==================================== #
def tokens(**kw):
    key = os.urandom(32)
    return TokenService(key, **kw), key


def test_token_roundtrip_and_claims():
    svc, _ = tokens()
    t = svc.issue(session_id=b"S" * 16, device_id="reader-A", client_ip=IP, now=T0S)
    c = svc.verify(t, client_ip=IP, now=T0S + 10)
    assert c.session_id == b"S" * 16 and c.device_id == "reader-A" and c.client_ip == IP
    assert c.expires_at == T0S + 900
    assert svc.issue(session_id=b"S" * 16, device_id="x", client_ip=IP, now=T0S) != t   # unikalny jti


def test_token_expiry_and_not_before():
    svc, _ = tokens(ttl_s=60)
    t = svc.issue(session_id=b"S" * 16, device_id="d", client_ip=IP, now=T0S)
    svc.verify(t, client_ip=IP, now=T0S + 59)
    with raises(TokenExpired):
        svc.verify(t, client_ip=IP, now=T0S + 60)
    future = svc.issue(session_id=b"S" * 16, device_id="d", client_ip=IP, now=T0S + 100)
    with raises(TokenInvalid):
        svc.verify(future, client_ip=IP, now=T0S)                # wydany „w przyszłości"
    svc.verify(future, client_ip=IP, now=T0S + 96)               # w granicach tolerancji zegara


def test_token_signature_and_payload_tampering():
    svc, ring = tokens()
    t = svc.issue(session_id=b"S" * 16, device_id="d", client_ip=IP, now=T0S)
    h, p, s = t.split(".")
    flipped = p[:-2] + ("A" if p[-2] != "A" else "B") + p[-1]
    for bad in (f"{h}.{flipped}.{s}", f"{h}.{p}.{s[:-2]}AA", "a.b.c", "", "nie-jwt"):
        with raises(TokenInvalid):
            svc.verify(bad, client_ip=IP, now=T0S)
    other, _ = tokens()                                          # inny klucz
    with raises(TokenInvalid):
        other.verify(t, client_ip=IP, now=T0S)


def _payload(**over):
    p = {"iss": "fp-server", "aud": "fp-api", "sub": "d", "sid": "AAAA", "jti": "j",
         "iat": T0S, "nbf": T0S, "exp": T0S + 900, "ip": IP}
    p.update(over)
    return {k: v for k, v in p.items() if v is not None}


def test_token_alg_none_and_alg_confusion_rejected():
    svc, key = tokens()
    none_tok = jwt.encode(_payload(), None, algorithm="none")
    hs512 = jwt.encode(_payload(), key, algorithm="HS512")
    for bad in (none_tok, hs512):
        with raises(TokenInvalid):
            svc.verify(bad, client_ip=IP, now=T0S)
    jwt.decode(jwt.encode(_payload(), key, algorithm="HS256"), key,
               algorithms=["HS256"], audience="fp-api", issuer="fp-server",
               options={"verify_iat": False, "verify_exp": False, "verify_nbf": False})   # kontrola poprawności testu (bez zegara systemowego)
    svc.verify(jwt.encode(_payload(), key, algorithm="HS256"), client_ip=IP, now=T0S)


def test_token_bad_claims():
    svc, key = tokens()
    for missing in ("sid", "exp", "iat", "nbf", "jti", "sub", "aud", "iss"):
        tok = jwt.encode(_payload(**{missing: None}), key, algorithm="HS256")
        with raises(TokenInvalid):
            svc.verify(tok, client_ip=IP, now=T0S)
    for over in ({"iss": "ktoś-inny"}, {"aud": "inne-api"}, {"exp": "jutro"}, {"sid": "***"}):
        tok = jwt.encode(_payload(**over), key, algorithm="HS256")
        with raises(TokenInvalid):
            svc.verify(tok, client_ip=IP, now=T0S)


def test_token_ip_binding():
    svc, _ = tokens()
    t = svc.issue(session_id=b"S" * 16, device_id="d", client_ip=IP, now=T0S)
    with raises(TokenBindingError):
        svc.verify(t, client_ip="198.51.100.9", now=T0S)
    with raises(TokenBindingError):
        svc.verify(t, client_ip=None, now=T0S)
    with raises(TokenBindingError):
        svc.verify(t, client_ip="nie-ip", now=T0S)
    mapped = svc.issue(session_id=b"S" * 16, device_id="d", client_ip="::ffff:203.0.113.10", now=T0S)
    svc.verify(mapped, client_ip=IP, now=T0S)                    # IPv4-mapped IPv6 == IPv4
    with raises(ValueError):
        svc.issue(session_id=b"S" * 16, device_id="d", client_ip=None, now=T0S)


def test_token_without_binding_rejected_when_binding_required():
    key = os.urandom(32)
    unbound = TokenService(key, bind_ip=False).issue(session_id=b"S" * 16, device_id="d", now=T0S)
    TokenService(key, bind_ip=False).verify(unbound, now=T0S)
    with raises(TokenInvalid):
        TokenService(key, bind_ip=True).verify(unbound, client_ip=IP, now=T0S)


def test_token_key_validation():
    with raises(ValueError):
        TokenService(b"krotki")                                  # klucz HMAC musi mieć >= 32 B
    with raises(ValueError):
        TokenService("tekst-zamiast-bajtow" * 3)


# ============================= URZĄDZENIA ==================================== #
def test_fingerprint_normalization():
    h = "ab" * 32
    assert normalize_fingerprint(h) == "sha256:" + h
    assert normalize_fingerprint("SHA256=" + h.upper()) == "sha256:" + h
    assert normalize_fingerprint("sha1:" + "cd" * 20) == "sha1:" + "cd" * 20
    assert normalize_fingerprint(":".join(["ab"] * 32)) == "sha256:" + h
    for bad in ("", "xyz", "ab" * 31, "sha256:" + "ab" * 20, "sha1:" + "ab" * 32):
        with raises(ValueError):
            normalize_fingerprint(bad)


def test_device_proof_binds_every_field():
    s = os.urandom(32)
    base = dict(device_id="d", client_pub=b"P" * 32, client_random=b"R" * 32, timestamp_ms=T0)
    p = device_proof(s, **base)
    assert p == device_proof(s, **base) and len(p) == 32
    for k, v in (("device_id", "e"), ("client_pub", b"Q" * 32), ("client_random", b"S" * 32),
                 ("timestamp_ms", T0 + 1)):
        assert device_proof(s, **{**base, k: v}) != p
    assert device_proof(os.urandom(32), **base) != p


def test_policy_and_device_binding_checks():
    with raises(ValueError):
        DevicePolicy(require_mtls=False, require_proof=False)
    reg = InMemoryDeviceRegistry()
    rec = reg.register("a", secret=os.urandom(32), cert_fingerprint=FP_A)
    both = DevicePolicy(True, True)
    check_device_binding(rec, both, FP_A)
    for fp in (None, FP_B):
        with raises(DeviceAuthError):
            check_device_binding(rec, both, fp)
    with raises(DeviceAuthError):
        check_device_binding(None, both, FP_A)
    reg.revoke("a")
    with raises(DeviceAuthError):
        check_device_binding(reg.get("a"), both, FP_A)
    reg.register("b", secret=os.urandom(32))                      # bez certyfikatu w rejestrze
    with raises(DeviceAuthError):
        check_device_binding(reg.get("b"), DevicePolicy(False, True), FP_A)   # a certyfikat przedstawiono
    check_device_binding(reg.get("b"), DevicePolicy(False, True), None)
    with raises(ValueError):
        reg.register("c", secret=b"za-krotki")


def test_authenticate_device_proof_required_and_verified():
    reg = InMemoryDeviceRegistry()
    secret = os.urandom(32)
    rec = reg.register("a", secret=secret, cert_fingerprint=FP_A)
    kw = dict(cert_fingerprint=FP_A, device_id="a", client_pub=b"P" * 32, client_random=b"R" * 32,
              timestamp_ms=T0)
    good = device_proof(secret, device_id="a", client_pub=b"P" * 32, client_random=b"R" * 32, timestamp_ms=T0)
    authenticate_device(rec, DevicePolicy(True, True), proof=good, **kw)
    for bad in (None, b"x" * 32, device_proof(os.urandom(32), device_id="a", client_pub=b"P" * 32,
                                              client_random=b"R" * 32, timestamp_ms=T0)):
        with raises(DeviceAuthError):
            authenticate_device(rec, DevicePolicy(True, True), proof=bad, **kw)
    authenticate_device(rec, DevicePolicy(True, False), proof=None, **kw)       # tylko mTLS


def test_resolve_client_trusts_headers_only_from_proxies():
    trust = NetworkTrust(trusted_proxies=("10.0.0.0/8", "127.0.0.1"), verify_header="x-client-cert-verify")
    h = {"x-client-cert-fingerprint": "AB" * 32, "x-client-cert-verify": "SUCCESS",
         "x-forwarded-for": "198.51.100.7, 10.1.1.1"}
    assert resolve_client("10.0.0.5", h, trust) == ("198.51.100.7", "sha256:" + "ab" * 32)
    assert resolve_client("203.0.113.50", h, trust) == ("203.0.113.50", None)    # podszywanie się pod proxy
    forged = {**h, "x-forwarded-for": "6.6.6.6, 198.51.100.7, 10.1.1.1"}
    assert resolve_client("10.0.0.5", forged, trust)[0] == "198.51.100.7"        # fałszywy hop po lewej ignorowany
    assert resolve_client("10.0.0.5", {**h, "x-client-cert-verify": "FAILED"}, trust)[1] is None
    assert resolve_client("10.0.0.5", {**h, "x-client-cert-fingerprint": "to nie odcisk"}, trust)[1] is None
    assert resolve_client("10.0.0.5", {}, trust) == ("10.0.0.5", None)
    assert resolve_client("1.2.3.4", h, NetworkTrust()) == ("1.2.3.4", None)     # brak skonfigurowanych proxy


# ============================= PROTOKÓŁ ====================================== #
def test_wire_payload_roundtrip_and_validation():
    data = wp.pack_subject_payload("user.1@x", b"\x01\x02")
    assert wp.unpack_subject_payload(data) == ("user.1@x", b"\x01\x02")
    for bad in ("", "a b", "ż", "x" * 129, "a/b"):
        with raises(wp.ProtocolError):
            wp.pack_subject_payload(bad)
    for raw in (b"", b"\x00", b"\x00\x00ab", b"\x00\x05ab", struct.pack(">H", 2) + b"\xff\xfe"):
        with raises(wp.ProtocolError):
            wp.unpack_subject_payload(raw)
    assert wp.unpack_json(wp.pack_json({"b": 1, "a": True})) == {"a": True, "b": 1}
    for raw in (b"[]", b"nie json", b"\xff"):
        with raises(wp.ProtocolError):
            wp.unpack_json(raw)


# ============================= ŚWIAT TESTOWY ================================= #
def tpl(seed, n=40):
    rng = np.random.default_rng(seed)
    return [Minutia(int(rng.integers(20, 300)), int(rng.integers(20, 380)),
                    float(rng.uniform(0, 2 * np.pi)), int(rng.integers(0, 2))) for _ in range(n)]


@dataclass
class Dev:
    fp: str
    secret: bytes
    totp_secret: bytes | None = None


class World:
    pass


def make_world(*, policy=None, bind_ip=True, totp=False, **settings_kw):
    """`totp=True`: urządzenia mają sekret TOTP, a domyślna polityka wymaga kodu w handshake'u."""
    w = World()
    w.now = [T0]
    w.clock = lambda: w.now[0]
    w.registry = InMemoryDeviceRegistry()
    w.dev = {}
    for name, fp, perms in (("reader-A", FP_A, {"enroll", "verify"}), ("reader-B", FP_B, {"enroll", "verify"}),
                            ("admin-1", FP_C, {"enroll", "verify", "erase"})):
        secret, totp_secret = os.urandom(32), (os.urandom(32) if totp else None)
        w.registry.register(name, secret=secret, cert_fingerprint=fp, permissions=perms,
                            totp_secret=totp_secret)
        w.dev[name] = Dev(fp, secret, totp_secret)
    w.identity = Ed25519PrivateKey.generate()
    w.provider = LocalKeyProvider.generate()
    w.repo = InMemoryTemplateRepository()
    w.tokens = TokenService(os.urandom(32), bind_ip=bind_ip)
    settings_kw.setdefault("match_threshold", 0.2)       # test: próg wyraźnie ponad szumem losowych szablonów
    w.svc = ApiService(tokens=w.tokens, devices=w.registry, policy=policy or DevicePolicy(True, True, totp),
                       identity_key=w.identity, vault_provider=w.provider, repo=w.repo,
                       settings=ServiceSettings(**settings_kw), clock=w.clock)
    return w


class InProcess:
    """Transport wywołujący serwis w procesie; zapisuje wysłane żądania (przechwycenie)."""

    def __init__(self, svc, ip=IP, cert=None):
        self.svc, self.ip, self.cert, self.log = svc, ip, cert, []

    def post(self, path, body, headers):
        auth = headers.get("Authorization", "")
        ctx = RequestContext(self.ip, self.cert, auth[7:] if auth.startswith("Bearer ") else None)
        self.log.append((path, copy.deepcopy(body), dict(headers)))
        try:
            if path == "/v1/session/close":
                return 200, self.svc.close_session(ctx)
            handler = {"/v1/handshake": self.svc.handshake, "/v1/enroll": self.svc.enroll,
                       "/v1/verify": self.svc.verify, "/v1/erase": self.svc.erase}[path]
            return 200, handler(body, ctx)
        except ApiError as e:
            return e.status, {"error": e.code}


def new_client(w, device="reader-A", *, ip=IP, cert="auto", secret="auto", transport_cls=InProcess,
               totp="auto", sleep=None):
    info = w.dev.get(device)
    tr = transport_cls(w.svc, ip, (info.fp if info else FP_A) if cert == "auto" else cert)
    key = (info.secret if info else os.urandom(32)) if secret == "auto" else secret
    totp_key = (info.totp_secret if info else None) if totp == "auto" else totp
    c = FingerprintClient(tr, device_id=device, server_verify_key=w.identity.public_key(),
                          device_secret=key, totp_secret=totp_key, clock=w.clock, sleep=sleep)
    return c, tr


def connected(w, device="reader-A", **kw):
    c, tr = new_client(w, device, **kw)
    c.connect()
    return c, tr


def enrolled_world(**kw):
    w = make_world(**kw)
    c, tr = connected(w)
    c.enroll("alice", tpl(1))
    return w, c, tr


def post_sealed(tr, c, path, payload, purpose, *, bearer=None):
    msg = seal(c._keys, payload, purpose, now=c._clock())
    return tr.post(path, msg.to_dict(), {"Authorization": f"Bearer {bearer or c._token}"}), msg


def verify_payload(subject, seed):
    return wp.pack_subject_payload(subject, template_to_bytes(tpl(seed)))


# ============================= PRZEBIEG PODSTAWOWY =========================== #
def test_full_flow_enroll_verify_erase_close():
    w = make_world()
    c, _ = connected(w)
    assert c.enroll("alice", tpl(1)) == {"status": "enrolled"}
    assert c.verify("alice", tpl(1)) is True
    assert c.verify("alice", tpl(99)) is False                    # inny palec
    assert c.verify("nieznany", tpl(1)) is False                  # brak enumeracji: ta sama odpowiedź
    admin, _ = connected(w, "admin-1")
    assert admin.erase("alice") == {"status": "erased"}
    assert c.verify("alice", tpl(1)) is False
    c.close()
    with raises(RuntimeError):
        c.verify("alice", tpl(1))


def test_score_hidden_by_default_and_optional():
    w = make_world()
    c, _ = connected(w)
    c.enroll("alice", tpl(1))
    assert "score" not in c._call("/v1/verify", wp.PURPOSE_VERIFY, verify_payload("alice", 1))
    w2 = make_world(return_score=True)
    c2, _ = connected(w2)
    c2.enroll("alice", tpl(1))
    assert c2._call("/v1/verify", wp.PURPOSE_VERIFY, verify_payload("alice", 1))["score"] > 0.9


def test_template_is_encrypted_at_rest_and_bound_to_subject():
    w, _, _ = enrolled_world()
    record = w.repo.get("alice")
    raw = template_to_bytes(tpl(1))
    assert raw not in record and record[:3] == b"FPT"
    assert decrypt_template(w.provider, "alice", record) == raw
    with raises(VaultError):
        decrypt_template(LocalKeyProvider.generate(), "alice", record)         # bez klucza głównego
    with raises(VaultError):
        decrypt_template(w.provider, "mallory", record)                        # rekord innej osoby


def test_duplicate_enrollment_and_invalid_templates_rejected():
    w, c, _ = enrolled_world()
    with api_error(409, "already_enrolled"):
        c.enroll("alice", tpl(2))
    assert c.verify("alice", tpl(1)) is True                      # oryginał nietknięty
    good = template_to_bytes(tpl(3))
    kind_bad = bytearray(good)
    kind_bad[3 + 6] = 2                                           # typ minutii spoza {0,1}
    cases = {"za mało minutiae": template_to_bytes(tpl(3, n=5)), "śmieci na końcu": good + b"x",
             "zły typ": bytes(kind_bad), "ucięty": good[:-3], "pusty": b""}
    for name, raw in cases.items():
        with api_error(400, "invalid_payload"):
            c.enroll(f"user-{abs(hash(name)) % 10**6}", raw)
    (st, _), _ = post_sealed(*_tr(c), "/v1/enroll", struct.pack(">H", 3) + b"a b" + good, "enroll")
    assert st == 400                                              # niedozwolone znaki w subject_id


def _tr(c):
    return c._t, c


# ============================= UPRAWNIENIA =================================== #
def test_permissions_enforced():
    w, c, _ = enrolled_world()
    with api_error(403, "forbidden"):
        c.erase("alice")                                          # zwykły czytnik nie kasuje
    assert w.repo.get("alice") is not None
    w.registry.register("verify-only", secret=os.urandom(32), cert_fingerprint="sha256:" + "dd" * 32,
                        permissions={"verify"})
    w.dev["verify-only"] = Dev("sha256:" + "dd" * 32, w.registry.get("verify-only").secret)
    v, _ = connected(w, "verify-only")
    with api_error(403, "forbidden"):
        v.enroll("bob", tpl(5))
    assert v.verify("alice", tpl(1)) is True


# ============================= ATAKI NA HANDSHAKE ============================ #
def test_handshake_rejects_unknown_device_wrong_proof_and_certificate():
    w = make_world()
    for kw in ({"device": "ghost"},                               # niezarejestrowane
               {"secret": os.urandom(32)},                        # zły sekret
               {"secret": None},                                  # brak dowodu
               {"cert": FP_B},                                    # certyfikat innego urządzenia
               {"cert": None}):                                   # brak certyfikatu
        c, _ = new_client(w, kw.pop("device", "reader-A"), **kw)
        with api_error(401, "auth_failed"):
            c.connect()


def test_handshake_replay_and_stale_rejected():
    w = make_world()
    c, tr = new_client(w)
    c.connect()
    path, body, headers = tr.log[0]
    assert tr.post(path, body, headers) == (409, {"error": "replay_detected"})
    w.now[0] += 61_000
    assert tr.post(path, body, headers) == (401, {"error": "stale_message"})


def test_handshake_with_forged_hello_fails_authentication():
    w = make_world()
    c, tr = new_client(w)
    c.connect()
    path, body, headers = tr.log[0]
    forged = copy.deepcopy(body)
    forged["hello"]["client_pub"] = base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip("=")
    forged["hello"]["client_random"] = base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip("=")
    assert tr.post(path, forged, headers)[0] == 401               # dowód nie pasuje do nowych danych
    for junk in ({}, {"hello": 5}, {"hello": {}, "ts": "x"}, {**body, "ts": True}):
        assert tr.post(path, junk, headers)[0] == 400


def test_alternative_policies():
    w = make_world(policy=DevicePolicy(require_mtls=False, require_proof=True))
    c, _ = connected(w, cert=None)                                # sam dowód HMAC, bez mTLS
    c.enroll("alice", tpl(1))
    bad, _ = new_client(w, cert=FP_B)
    with api_error(401):
        bad.connect()                                             # przedstawiony, ale cudzy certyfikat
    w2 = make_world(policy=DevicePolicy(require_mtls=True, require_proof=False))
    c2, _ = connected(w2, secret=None)                            # sam mTLS
    c2.enroll("alice", tpl(1))
    no_ip = make_world(bind_ip=False)
    c3, _ = connected(no_ip, ip=None)                             # bez wiązania z adresem
    assert c3.enroll("alice", tpl(1)) == {"status": "enrolled"}
    w4 = make_world()
    bad_ip, _ = new_client(w4, ip="nie-ip")
    with api_error(400, "client_address_unknown"):
        bad_ip.connect()


# ============================= ATAKI NA TOKEN ================================ #
def test_missing_garbage_and_foreign_tokens_rejected():
    w, c, tr = enrolled_world()
    msg = seal(c._keys, verify_payload("alice", 1), "verify", now=w.now[0]).to_dict()
    assert tr.post("/v1/verify", msg, {})[0] == 401                                  # bez tokenu
    assert tr.post("/v1/verify", msg, {"Authorization": "Bearer abc"})[0] == 401     # śmieci
    alien = TokenService(os.urandom(32)).issue(session_id=c._keys.session_id,
                                                       device_id="reader-A", client_ip=IP, now=T0S)
    assert tr.post("/v1/verify", msg, {"Authorization": f"Bearer {alien}"})[0] == 401   # obcy klucz
    assert tr.post("/v1/verify", msg, {"Authorization": f"Bearer {c._token}"})[0] == 200


def test_expired_token_and_session_rejected():
    w, c, tr = enrolled_world()
    w.now[0] += 899_000
    assert c.verify("alice", tpl(1)) is True                      # tuż przed wygaśnięciem
    w.now[0] += 2_000
    with api_error(401, "token_expired"):
        c.verify("alice", tpl(1))
    c.connect()                                                   # nowa sesja działa
    assert c.verify("alice", tpl(1)) is True


def test_token_stolen_to_other_address_or_device_rejected():
    w, c, tr = enrolled_world()
    (st, _), msg = post_sealed(tr, c, "/v1/verify", verify_payload("alice", 1), "verify")
    assert st == 200
    attacker_ip = InProcess(w.svc, "198.51.100.9", FP_A)          # ten sam certyfikat, inny adres
    assert attacker_ip.post("/v1/verify", msg.to_dict(), {"Authorization": f"Bearer {c._token}"})[0] == 401
    fresh = seal(c._keys, verify_payload("alice", 1), "verify", now=w.now[0]).to_dict()
    other_dev = InProcess(w.svc, IP, FP_B)                        # ten sam adres, certyfikat urządzenia B
    st, body = other_dev.post("/v1/verify", fresh, {"Authorization": f"Bearer {c._token}"})
    assert (st, body["error"]) == (401, "device_mismatch")
    no_cert = InProcess(w.svc, IP, None)
    assert no_cert.post("/v1/verify", fresh, {"Authorization": f"Bearer {c._token}"})[0] == 401


def test_session_closed_revoked_device_and_foreign_session_message():
    w, c, tr = enrolled_world()
    token = c._token
    other, _ = connected(w, "reader-B")
    foreign = seal(other._keys, verify_payload("alice", 1), "verify", now=w.now[0]).to_dict()
    assert tr.post("/v1/verify", foreign, {"Authorization": f"Bearer {token}"})[0] == 400   # wiadomość z innej sesji
    w.registry.revoke("reader-A")
    with api_error(401, "device_mismatch"):
        c.verify("alice", tpl(1))                                 # unieważnienie działa natychmiast
    w2, c2, tr2 = enrolled_world()
    token2, keys2 = c2._token, c2._keys
    c2.close()
    msg = seal(keys2, verify_payload("alice", 1), "verify", now=w2.now[0]).to_dict()
    assert tr2.post("/v1/verify", msg, {"Authorization": f"Bearer {token2}"})[0] == 401     # sesja zamknięta
    assert tr2.post("/v1/session/close", None, {"Authorization": "Bearer zly"})[0] == 401


# ============================= ATAKI REPLAY / MANIPULACJE ==================== #
def test_replayed_request_rejected():
    w, c, tr = enrolled_world()
    assert c.verify("alice", tpl(1)) is True
    path, body, headers = tr.log[-1]
    assert tr.post(path, body, headers) == (409, {"error": "replay_detected"})      # ten sam pakiet
    w.now[0] += 61_000
    assert tr.post(path, body, headers) == (401, {"error": "stale_message"})        # po oknie czasowym


def test_request_not_burned_when_intercepted_and_redirected():
    w, c, tr = enrolled_world()
    (st, _), msg = post_sealed(tr, c, "/v1/enroll", verify_payload("bob", 7), "verify")   # cel „verify" na /enroll
    assert st == 400
    st, _ = tr.post("/v1/verify", msg.to_dict(), {"Authorization": f"Bearer {c._token}"})
    assert st == 200                                              # oryginał dochodzi, bo nonce nie został spalony


def test_future_timestamp_and_tampered_messages_rejected():
    w, c, tr = enrolled_world()
    bearer = {"Authorization": f"Bearer {c._token}"}
    future = seal(c._keys, verify_payload("alice", 1), "verify", now=w.now[0] + 10_000)
    assert tr.post("/v1/verify", future.to_dict(), bearer)[0] == 401
    msg = seal(c._keys, verify_payload("alice", 1), "verify", now=w.now[0]).to_dict()
    ct = bytearray(base64.urlsafe_b64decode(msg["ct"] + "=" * (-len(msg["ct"]) % 4)))
    ct[5] ^= 1
    mutations = {"szyfrogram": {**msg, "ct": base64.urlsafe_b64encode(bytes(ct)).decode().rstrip("=")},
                 "znacznik czasu": {**msg, "ts": msg["ts"] + 1}, "cel": {**msg, "purpose": "enroll"}}
    for name, bad in mutations.items():
        assert tr.post("/v1/verify", bad, bearer)[0] == 400, name
    assert tr.post("/v1/verify", msg, bearer)[0] == 200           # oryginał nadal przechodzi
    for junk in ([], None, 5, "x", {"v": 1}):
        assert tr.post("/v1/verify", junk, bearer)[0] == 400


def test_client_rejects_tampered_and_replayed_responses():
    class Tamper(InProcess):
        def post(self, path, body, headers):
            st, resp = super().post(path, body, headers)
            if st == 200 and "ct" in resp:
                ct = bytearray(base64.urlsafe_b64decode(resp["ct"] + "=" * (-len(resp["ct"]) % 4)))
                ct[0] ^= 1
                resp = {**resp, "ct": base64.urlsafe_b64encode(bytes(ct)).decode().rstrip("=")}
            return st, resp

    class ReplayResp(InProcess):
        cached = None

        def post(self, path, body, headers):
            st, resp = super().post(path, body, headers)
            if st == 200 and "ct" in resp:
                if self.cached is None:
                    self.cached = resp
                return st, self.cached
            return st, resp

    w, _, _ = enrolled_world()
    t, _ = connected(w, transport_cls=Tamper)
    with raises(Exception):                                       # CryptoError z odbioru odpowiedzi
        t.verify("alice", tpl(1))
    r, _ = connected(w, transport_cls=ReplayResp)
    assert r.verify("alice", tpl(1)) is True
    with raises(ReplayError):
        r.verify("alice", tpl(1))                                 # stara odpowiedź podstawiona drugi raz


# ============================= LIMITY PRÓB ================================== #
def test_device_lockout_after_failures_and_window_expiry():
    w, c, _ = enrolled_world(max_failures_per_device=5)
    for seed in range(100, 105):
        assert c.verify("alice", tpl(seed)) is False
    with api_error(429, "too_many_attempts"):
        c.verify("alice", tpl(1))                                 # nawet poprawny odcisk czeka
    w.now[0] += 301_000
    assert c.verify("alice", tpl(1)) is True                      # po oknie blokady znów działa


def test_success_does_not_reset_device_counter():
    w, c, _ = enrolled_world(max_failures_per_device=5)
    for seed in range(100, 104):
        assert c.verify("alice", tpl(seed)) is False
    assert c.verify("alice", tpl(1)) is True                      # własny, poprawny odcisk nie czyści limitu
    assert c.verify("alice", tpl(104)) is False                   # piąta porażka w oknie
    with api_error(429):
        c.verify("alice", tpl(1))


def test_device_limit_spans_subjects():
    w = make_world(max_failures_per_device=3)
    d, _ = connected(w)
    for i in range(3):
        assert d.verify(f"user-{i}", tpl(i)) is False             # „spray" po różnych osobach
    with api_error(429):
        d.verify("user-99", tpl(1))


def test_attempt_limiter_window():
    lim = AttemptLimiter(2, 10)
    assert lim.blocked("k", T0) is None
    lim.failure("k", T0)
    lim.failure("k", T0 + 1000)
    assert lim.blocked("k", T0 + 2000) == 8
    assert lim.blocked("k", T0 + 10_000) == 1
    assert lim.blocked("k", T0 + 11_000) is None
    lim.failure("x", T0)
    lim.success("x")
    assert lim.blocked("x", T0) is None


# ============================= KONFIGURACJA / ŚRODOWISKO DEV ================= #
def test_provisioned_environment_builds_working_service():
    from fpscanner.tools.provision_dev import provision
    with tempfile.TemporaryDirectory() as tmp:
        out = provision(tmp, ["reader-01"], admin_ids=("admin-01",), local_kek=True)
        svc, trust = build_service(out["env"])
        pub = Ed25519PublicKey.from_public_bytes(
            base64.urlsafe_b64decode(out["server_public_key"] + "=" * (-len(out["server_public_key"]) % 4)))
        cl = out["clients"]["reader-01"]
        secret = base64.urlsafe_b64decode(cl["secret"] + "=" * (-len(cl["secret"]) % 4))
        fp = out["pki"]["devices"]["reader-01"]["fingerprint"]
        totp_secret = base64.urlsafe_b64decode(cl["totp_secret"] + "=" * (-len(cl["totp_secret"]) % 4))
        c = FingerprintClient(InProcess(svc, IP, fp), device_id="reader-01", server_verify_key=pub,
                              device_secret=secret, totp_secret=totp_secret)
        c.connect()
        assert c.enroll("alice", tpl(1)) == {"status": "enrolled"}
        assert c.verify("alice", tpl(1)) is True
        wrong = FingerprintClient(InProcess(svc, IP, out["pki"]["devices"]["admin-01"]["fingerprint"]),
                                  device_id="reader-01", server_verify_key=pub, device_secret=secret,
                                  totp_secret=totp_secret)
        with api_error(401):
            wrong.connect()                                       # cudzy certyfikat z tego samego CA
        assert trust.cert_header == "x-client-cert-fingerprint"


def test_config_errors_are_reported_clearly():
    from fpscanner.tools.provision_dev import provision
    with tempfile.TemporaryDirectory() as tmp:
        env = provision(tmp, ["r"], local_kek=True)["env"]
        for broken in ({k: v for k, v in env.items() if k != "FP_JWT_KEY"},
                       {**env, "FP_JWT_KEY": base64.urlsafe_b64encode(b"krotki").decode()},
                       {**env, "FP_DEVICES_FILE": "/nie/ma/takiego/pliku"},
                       {**env, "FP_ACTIVE_KEK": "nieznany"}):
            with raises(ConfigError):
                build_service(broken)


# ============================= TOTP (RFC 6238) =============================== #
def raw_handshake(w, device="reader-A", *, ts=T0, totp_at=None, code="auto"):
    """Handshake zbudowany ręcznie: niezależnie ustawiany znacznik `ts` i chwila liczenia kodu."""
    info = w.dev[device]
    hs = ClientHandshake(device.encode())
    body = {"hello": hs.hello.to_dict(), "ts": ts,
            "proof": _b64e(device_proof(info.secret, device_id=device, client_pub=hs.hello.client_pub,
                                        client_random=hs.hello.client_random, timestamp_ms=ts))}
    if code == "auto":
        code = totp(info.totp_secret, T0S if totp_at is None else totp_at)
    if code is not None:
        body["totp"] = code
    return InProcess(w.svc, IP, info.fp).post("/v1/handshake", body, {})


def test_totp_handshake_succeeds_and_sends_code():
    w = make_world(totp=True)
    c, tr = connected(w)
    path, body, _ = tr.log[0]
    assert path == "/v1/handshake" and body["totp"] == totp(w.dev["reader-A"].totp_secret, T0S)
    assert c.enroll("alice", tpl(1)) == {"status": "enrolled"}


def test_totp_required_but_missing_or_wrong_is_rejected():
    w = make_world(totp=True)
    c, _ = new_client(w, totp=None)
    with api_error(401, "auth_failed"):
        c.connect()                                                  # brak czynnika TOTP
    c, _ = new_client(w, totp=os.urandom(32))
    with api_error(401, "auth_failed"):
        c.connect()                                                  # kod z cudzego sekretu
    assert raw_handshake(w, code=None)[0] == 401
    for bad in ("12345", "1234567", "abcdef", "١٢٣٤٥٦", " 12345", ""):
        assert raw_handshake(w, code=bad)[0] == 401, bad            # zły format: nigdy nie przechodzi
    status, resp = raw_handshake(w, code=123456)                     # liczba zamiast tekstu
    assert (status, resp["error"]) == (400, "invalid_message")


def test_totp_other_devices_code_is_rejected():
    w = make_world(totp=True)
    foreign = totp(w.dev["reader-B"].totp_secret, T0S)
    assert raw_handshake(w, "reader-A", code=foreign)[0] == 401      # kod innego urządzenia


def test_totp_replayed_handshake_is_reported_as_replay_not_auth_failure():
    w = make_world(totp=True)
    c, tr = connected(w)
    _, captured, _ = tr.log[0]
    status, resp = tr.post("/v1/handshake", captured, {})            # dokładny powtórzony handshake
    assert (status, resp["error"]) == (409, "replay_detected")       # nonce wykrywa replay (nie 401)


def test_totp_code_is_single_use_even_with_fresh_nonce_and_proof():
    w = make_world(totp=True)
    assert raw_handshake(w)[0] == 200                                # pierwszy handshake w kroku
    status, resp = raw_handshake(w)                                  # nowy nonce, ważny dowód, ten sam krok
    assert (status, resp["error"]) == (409, "replay_detected")
    w.now[0] += 30_000                                               # następny krok TOTP
    assert raw_handshake(w, ts=w.now[0], totp_at=w.now[0] / 1000)[0] == 200
    assert raw_handshake(w, ts=w.now[0], totp_at=w.now[0] / 1000)[0] == 409
    # kod ze starszego kroku po przyjęciu nowszego też jest odrzucony (kroki tylko rosną)
    assert raw_handshake(w, ts=w.now[0], totp_at=T0S)[0] == 409


def test_totp_steps_are_tracked_per_device():
    w = make_world(totp=True)
    assert raw_handshake(w, "reader-A")[0] == 200
    assert raw_handshake(w, "reader-B")[0] == 200                    # inny krok licznika nie dotyczy B
    assert raw_handshake(w, "reader-A")[0] == 409


def test_totp_checks_device_clock_against_server_clock():
    # `ts` ustawiony poprawnie, rozjeżdża się wyłącznie zegar liczący kod (serwer: T0, krok c)
    for offset_s, expected in ((-25, 200), (-45, 401), (+25, 200), (+45, 200), (+65, 401)):
        w = make_world(totp=True)
        status, _ = raw_handshake(w, totp_at=T0S + offset_s)
        assert status == expected, (offset_s, status)
    # zegar urządzenia spóźnia się o 45 s, więc zarówno `ts`, jak i kod pochodzą z tej samej, złej
    # chwili. Znacznik mieści się w oknie 60 s, ale serwer liczy kod z WŁASNEGO zegara, nie z `ts`
    w = make_world(totp=True)
    assert raw_handshake(w, ts=T0 - 45_000, totp_at=T0S - 45)[0] == 401
    # bez TOTP ten sam rozjazd przechodzi: to TOTP jest tu kontrolą synchronizacji
    w = make_world(totp=False)
    assert raw_handshake(w, ts=T0 - 45_000, code=None)[0] == 200


def test_totp_client_waits_for_next_step_instead_of_failing():
    w = make_world(totp=True)
    waits = []

    def fake_sleep(seconds):
        waits.append(seconds)
        w.now[0] += int(seconds * 1000)

    c, tr = new_client(w, sleep=fake_sleep)
    c.connect()
    assert waits == []                                               # pierwszy handshake: bez czekania
    c.connect()                                                      # ten sam krok -> czeka do następnego
    assert waits == [30.0]
    codes = [body["totp"] for path, body, _ in tr.log if path == "/v1/handshake"]
    sec = w.dev["reader-A"].totp_secret
    assert codes == [totp(sec, T0S), totp(sec, T0S + 30)] and codes[0] != codes[1]
    assert c.enroll("alice", tpl(1)) == {"status": "enrolled"}       # sesja po drugim handshake działa


def test_totp_presented_is_verified_even_when_not_required():
    w = make_world(totp=True, policy=DevicePolicy(True, True, False))
    assert raw_handshake(w, code=None)[0] == 200                     # niewymagany i niepodany: OK
    w2 = make_world(totp=True, policy=DevicePolicy(True, True, False))
    bad = totp(w2.dev["reader-A"].totp_secret, T0S + 600)            # kod z odległego kroku
    assert raw_handshake(w2, code=bad)[0] == 401                     # podany => musi być poprawny


def test_totp_presented_for_device_without_secret_is_rejected():
    w = make_world(totp=False)                                       # urządzenia bez sekretu TOTP
    assert raw_handshake(w, code="123456")[0] == 401


def test_policy_and_registry_validation_for_totp():
    DevicePolicy(require_mtls=False, require_proof=False, require_totp=True)     # sam TOTP wystarczy
    with raises(ValueError):
        DevicePolicy(False, False, False)
    reg = InMemoryDeviceRegistry()
    secret = os.urandom(32)
    with raises(ValueError):
        reg.register("a", secret=secret, totp_secret=b"za-krotki")
    with raises(ValueError):
        reg.register("b", secret=secret, totp_secret=secret)         # ten sam sekret = jeden czynnik
    assert reg.register("c", secret=secret, totp_secret=os.urandom(32)).totp_secret is not None


def test_authenticate_device_returns_totp_step_and_requires_code():
    reg = InMemoryDeviceRegistry()
    secret, tsec = os.urandom(32), os.urandom(32)
    rec = reg.register("a", secret=secret, cert_fingerprint=FP_A, totp_secret=tsec)
    pub, rnd, ts = os.urandom(32), os.urandom(32), T0
    proof = device_proof(secret, device_id="a", client_pub=pub, client_random=rnd, timestamp_ms=ts)
    kw = {"proof": proof, "cert_fingerprint": FP_A, "device_id": "a", "client_pub": pub,
          "client_random": rnd, "timestamp_ms": ts}
    pol = DevicePolicy(True, True, True)
    good = totp(tsec, T0S)
    assert authenticate_device(rec, pol, totp_code=good, now_s=T0S, **kw) == T0S // 30
    for bad_kw in ({}, {"totp_code": "000000" if good != "000000" else "000001", "now_s": T0S},
                   {"totp_code": good}, {"totp_code": good, "now_s": T0S + 3600}):
        with raises(DeviceAuthError):
            authenticate_device(rec, pol, **bad_kw, **kw)
    assert authenticate_device(rec, DevicePolicy(True, True, False), **kw) is None


def test_server_config_rejects_devices_without_totp_secret_when_required():
    import json

    from fpscanner.tools.provision_dev import provision
    with tempfile.TemporaryDirectory() as tmp:
        out = provision(tmp, ["r"], local_kek=True)
        env = out["env"]
        assert env["FP_REQUIRE_TOTP"] == "1"
        path = env["FP_DEVICES_FILE"]
        data = json.loads(open(path, encoding="utf-8").read())
        for d in data["devices"]:
            d.pop("totp_secret")
        open(path, "w", encoding="utf-8").write(json.dumps(data))
        with raises(ConfigError):
            build_service(env)                                       # TOTP wymagany, a sekretu brak
        build_service({**env, "FP_REQUIRE_TOTP": "0"})               # po wyłączeniu wymagania: OK


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
