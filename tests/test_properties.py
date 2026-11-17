"""
Testy własności (Hypothesis) dla kryptografii i anti-replay: parser szablonu i rekord Vault nie
rzucają niespodziewanych wyjątków na dowolnych danych, a każda zmiana bitu w rekordzie,
wiadomości sesyjnej lub tokenie jest wykrywana. Okno czasowe i nonce mają dokładne granice.
Uruchomienie: pytest -q tests/test_properties.py
"""
import math
import os
import string

import pytest
from hypothesis import assume, given
from hypothesis import strategies as st

from fpscanner.biometrics.preprocessing import Minutia, template_from_bytes, template_to_bytes
from fpscanner.security.crypto_session import (
    CryptoError,
    MalformedMessage,
    SealedMessage,
    SessionKeys,
    open_message,
    seal,
)
from fpscanner.security.device_auth import (
    device_proof,
)
from fpscanner.security.replay_guard import NonceReused, ReplayError, ReplayGuard, StaleTimestamp
from fpscanner.security.session_tokens import TokenError, TokenService
from fpscanner.security.template_vault import (
    LocalKeyProvider,
    VaultError,
    decrypt_template,
    encrypt_template,
    rewrap,
)

TWO_PI = 2 * math.pi

# --- strategie ------------------------------------------------------------- #
minutiae = st.builds(Minutia, x=st.integers(0, 65535), y=st.integers(0, 65535),
                     theta=st.floats(0, TWO_PI, exclude_max=True), kind=st.integers(0, 1))
small_minutiae = st.builds(Minutia, x=st.integers(0, 300), y=st.integers(0, 400),
                           theta=st.floats(0, TWO_PI, exclude_max=True), kind=st.integers(0, 1))
json_leaf = (st.none() | st.booleans() | st.integers(-2**53, 2**53)
             | st.floats(allow_nan=False, allow_infinity=False) | st.text(max_size=20))
json_value = st.recursive(json_leaf, lambda c: st.lists(c, max_size=3)
                          | st.dictionaries(st.text(max_size=8), c, max_size=3), max_leaves=10)
json_dict = st.dictionaries(st.text(max_size=8), json_value, max_size=5)
subject_ids = st.from_regex(r"[A-Za-z0-9._@:-]{1,128}", fullmatch=True)
purposes = st.from_regex(r"[a-z0-9_.-]{1,32}", fullmatch=True)


def angle_distance(a, b):
    d = abs(a - b) % TWO_PI
    return min(d, TWO_PI - d)


# --- szablon .tpl ---------------------------------------------------------- #
@given(st.lists(minutiae, max_size=100))
def test_template_roundtrip_preserves_geometry(ms):
    raw = template_to_bytes(ms)
    assert len(raw) == 3 + 7 * len(ms)
    back = template_from_bytes(raw)
    assert len(back) == len(ms)
    for a, b in zip(ms, back, strict=True):
        assert (a.x, a.y, a.kind) == (b.x, b.y, b.kind)
        assert angle_distance(a.theta, b.theta) <= TWO_PI / 65536     # kwantyzacja kąta do u16


@given(st.lists(minutiae, max_size=50))
def test_serialization_is_idempotent(ms):
    raw = template_to_bytes(ms)
    assert template_to_bytes(template_from_bytes(raw)) == raw


@given(st.binary(max_size=300))
def test_template_parser_raises_only_valueerror(data):
    try:
        template_from_bytes(data)
    except ValueError:
        pass


# --- vault ----------------------------------------------------------------- #
@given(st.binary(max_size=2000), st.text(min_size=1, max_size=40))
def test_vault_roundtrip_and_subject_binding(template, subject):
    p = LocalKeyProvider.generate()
    rec = encrypt_template(p, subject, template)
    assert decrypt_template(p, subject, rec) == template
    with pytest.raises(VaultError):
        decrypt_template(p, subject + "x", rec)                        # inna osoba


@given(st.binary(min_size=1, max_size=300), st.data())
def test_any_single_bit_flip_in_vault_record_is_detected(template, data):
    p = LocalKeyProvider.generate()
    rec = bytearray(encrypt_template(p, "alice", template))
    i = data.draw(st.integers(0, len(rec) - 1))
    rec[i] ^= 1 << data.draw(st.integers(0, 7))
    with pytest.raises(VaultError):
        decrypt_template(p, "alice", bytes(rec))


@given(st.binary(max_size=400))
def test_vault_parsers_raise_only_vaulterror(garbage):
    p = LocalKeyProvider.generate()
    for fn in (decrypt_template, rewrap):
        try:
            fn(p, "alice", garbage)
        except VaultError:
            pass


@given(st.binary(max_size=500))
def test_rewrap_keeps_plaintext_and_moves_to_new_kek(template):
    p = LocalKeyProvider.generate("kek-1")
    rec = encrypt_template(p, "alice", template)
    p.add_key("kek-2", os.urandom(32), make_current=True)
    new = rewrap(p, "alice", rec)
    p.remove_key("kek-1")                                             # stary klucz już niepotrzebny
    assert decrypt_template(p, "alice", new) == template


# --- protokół aplikacyjny -------------------------------------------------- #








# --- warstwa kryptograficzna ----------------------------------------------- #
def make_keys():
    sid = os.urandom(16)
    k_c2s, k_s2c = os.urandom(32), os.urandom(32)
    far = 2**62
    return (SessionKeys(sid, b"dev", k_c2s, k_s2c, far), SessionKeys(sid, b"dev", k_s2c, k_c2s, far))


@given(st.binary(max_size=3000), purposes)
def test_seal_open_roundtrip_and_serialization_forms(plaintext, purpose):
    client, server = make_keys()
    msg = seal(client, plaintext, purpose, now=1_000)
    assert SealedMessage.from_bytes(msg.to_bytes()) == msg
    assert SealedMessage.from_dict(msg.to_dict()) == msg
    assert open_message(server, msg, ReplayGuard(), expected_purpose=purpose, now=1_000) == plaintext


@given(st.binary(max_size=400))
def test_sealed_from_bytes_raises_only_malformed(data):
    try:
        SealedMessage.from_bytes(data)
    except MalformedMessage:
        pass


@given(json_dict)
def test_sealed_from_dict_raises_only_cryptoerror(d):
    try:
        SealedMessage.from_dict(d)
    except CryptoError:
        pass


@given(st.binary(min_size=1, max_size=200), st.data())
def test_any_bit_flip_in_sealed_message_is_rejected(plaintext, data):
    client, server = make_keys()
    raw = bytearray(seal(client, plaintext, "verify", now=1_000).to_bytes())
    i = data.draw(st.integers(0, len(raw) - 1))
    raw[i] ^= 1 << data.draw(st.integers(0, 7))
    try:
        msg = SealedMessage.from_bytes(bytes(raw))
        open_message(server, msg, ReplayGuard(), expected_purpose="verify", now=1_000)
    except (CryptoError, ReplayError):          # odrzucenie przez kryptografię albo okno czasowe
        return
    raise AssertionError("zmodyfikowana wiadomość została przyjęta")


# --- tokeny ---------------------------------------------------------------- #
def token_service():
    return TokenService(os.urandom(32), ttl_s=900, bind_ip=False)


@given(st.text(max_size=3000))
def test_token_verify_raises_only_tokenerror_on_garbage(text):
    try:
        token_service().verify(text, now=1_800_000_000)
    except TokenError:
        pass


@given(st.binary(min_size=1, max_size=32), st.text(min_size=1, max_size=40),
       st.integers(1_000_000_000, 2_000_000_000))
def test_token_roundtrip(session_id, device_id, now):
    svc = token_service()
    c = svc.verify(svc.issue(session_id=session_id, device_id=device_id, now=now), now=now)
    assert (c.session_id, c.device_id, c.expires_at) == (session_id, device_id, now + 900)


@given(st.data())
def test_any_character_change_in_token_is_rejected(data):
    svc = token_service()
    token = svc.issue(session_id=b"\x01" * 16, device_id="reader-01", now=1_800_000_000)
    i = data.draw(st.integers(0, len(token) - 1))
    repl = data.draw(st.sampled_from(string.ascii_letters + string.digits + "-_"))
    assume(repl != token[i])
    bad = token[:i] + repl + token[i + 1:]
    try:
        c = svc.verify(bad, now=1_800_000_000)
    except TokenError:
        return
    # wyjątek: zmiana nieistotnych bitów ostatniego znaku base64 daje ten sam token po dekodowaniu
    assert i >= len(token) - 2 and c.device_id == "reader-01"


@given(st.integers(1_000_000_000, 2_000_000_000), st.integers(-100, 2000))
def test_token_lifetime_boundaries(issued, delta):
    svc = token_service()
    token = svc.issue(session_id=b"s" * 16, device_id="d", now=issued)
    now = issued + delta
    try:
        svc.verify(token, now=now)
        accepted = True
    except TokenError:
        accepted = False
    assert accepted == (-svc.leeway_s <= delta < svc.ttl_s)


# --- odciski i adresy ------------------------------------------------------ #










@given(st.binary(min_size=32, max_size=64), st.text(min_size=1, max_size=20), st.binary(max_size=40),
       st.binary(max_size=40), st.integers(0, 2**63))
def test_device_proof_binds_every_field(secret, dev, pub, rnd, ts):
    base = dict(device_id=dev, client_pub=pub, client_random=rnd, timestamp_ms=ts)
    p = device_proof(secret, **base)
    assert p == device_proof(secret, **base) and len(p) == 32
    assert p != device_proof(secret, **{**base, "device_id": dev + "x"})
    assert p != device_proof(secret, **{**base, "client_pub": pub + b"x"})
    assert p != device_proof(secret, **{**base, "client_random": rnd + b"x"})
    assert p != device_proof(secret, **{**base, "timestamp_ms": ts + 1})
    assert p != device_proof(secret + b"x", **base)


# --- limiter prób: porównanie z modelem referencyjnym ---------------------- #




# --- replay guard ---------------------------------------------------------- #
@given(st.binary(min_size=16, max_size=16), st.binary(min_size=12, max_size=12))
def test_nonce_can_be_claimed_exactly_once(session_id, nonce):
    g = ReplayGuard()
    g.claim_nonce(session_id, nonce, now=1_000)
    with pytest.raises(NonceReused):
        g.claim_nonce(session_id, nonce, now=2_000)


@given(st.integers(-120_000, 120_000))
def test_timestamp_window_is_exact(age):
    g = ReplayGuard(max_age_ms=60_000, max_future_ms=5_000)
    now = 10_000_000
    try:
        g.check_timestamp(now - age, now)
        accepted = True
    except StaleTimestamp:
        accepted = False
    assert accepted == (-5_000 <= age <= 60_000)


# --- matching -------------------------------------------------------------- #




