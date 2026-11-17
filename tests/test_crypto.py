"""Testy warstwy kryptograficznej. Uruchomienie: pytest -q"""
import contextlib
import json
import threading

import numpy as np
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import fpscanner.security.crypto_session as cs
import fpscanner.security.template_vault as tv
from fpscanner.biometrics.matching import match
from fpscanner.biometrics.preprocessing import Minutia, template_from_bytes, template_to_bytes
from fpscanner.security.crypto_session import (
    ClientHandshake,
    DecryptionError,
    HandshakeError,
    MalformedMessage,
    SealedMessage,
    SessionExhausted,
    SessionExpired,
    SessionKeys,
    SessionStore,
    open_message,
    seal,
    server_accept,
)
from fpscanner.security.replay_guard import (
    GuardFull,
    InMemoryNonceStore,
    NonceReused,
    ReplayGuard,
    StaleTimestamp,
)

T0 = 1_800_000_000_000        # stały „teraz" w ms, żeby testy były deterministyczne


@contextlib.contextmanager
def raises(exc):
    try:
        yield
    except exc:
        return
    except Exception as e:                               # inny wyjątek = błąd testu
        raise AssertionError(f"oczekiwano {exc.__name__}, jest {type(e).__name__}: {e}")
    raise AssertionError(f"oczekiwano {exc.__name__}, nie było wyjątku")


def make_session(device=b"reader-01", now=T0, ttl=900_000):
    identity = Ed25519PrivateKey.generate()
    client = ClientHandshake(device)
    sh, server_keys = server_accept(client.hello, identity, ttl_ms=ttl, now=now)
    client_keys = client.finish(sh, identity.public_key(), now=now)
    return identity, client, sh, client_keys, server_keys


def template(n=40, seed=0):
    rng = np.random.default_rng(seed)
    return [Minutia(int(rng.integers(20, 300)), int(rng.integers(20, 380)),
                    float(rng.uniform(0, 2 * np.pi)), int(rng.integers(0, 2))) for _ in range(n)]


# ----------------------------- HKDF ---------------------------------------- #
def test_hkdf_rfc5869_test_case_1():
    okm = cs.hkdf_sha256(bytes([0x0b] * 22), salt=bytes(range(0x00, 0x0d)),
                         info=bytes(range(0xf0, 0xfa)), length=42)
    assert okm.hex() == ("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56"
                         "ecc4c5bf34007208d5b887185865")


# ----------------------------- handshake ----------------------------------- #
def test_handshake_yields_matching_directional_keys():
    _, _, _, ck, sk = make_session()
    assert ck.send_key == sk.recv_key and ck.recv_key == sk.send_key
    assert ck.send_key != ck.recv_key                    # osobny klucz na kierunek
    assert len(ck.send_key) == 32 and ck.session_id == sk.session_id


def test_each_session_has_fresh_keys():
    a = make_session()[3]
    b = make_session()[3]
    assert a.send_key != b.send_key and a.session_id != b.session_id


def test_wrong_pinned_server_key_is_rejected():
    client = ClientHandshake(b"dev")
    sh, _ = server_accept(client.hello, Ed25519PrivateKey.generate(), now=T0)
    with raises(HandshakeError):
        client.finish(sh, Ed25519PrivateKey.generate().public_key(), now=T0)


def test_active_mitm_swapping_ephemeral_key_is_rejected():
    identity = Ed25519PrivateKey.generate()
    client = ClientHandshake(b"dev")
    sh, _ = server_accept(client.hello, identity, now=T0)
    evil_hs = ClientHandshake(b"x")                      # atakujący ma własny klucz X25519
    forged = cs.ServerHello(evil_hs.hello.client_pub, sh.server_random, sh.session_id,
                            sh.expires_at_ms, sh.signature)
    with raises(HandshakeError):
        client.finish(forged, identity.public_key(), now=T0)


def test_tampering_with_any_server_hello_field_is_rejected():
    identity = Ed25519PrivateKey.generate()
    client = ClientHandshake(b"dev")
    sh, _ = server_accept(client.hello, identity, now=T0)
    flip = lambda b: bytes([b[0] ^ 1]) + b[1:]
    variants = [
        cs.ServerHello(sh.server_pub, flip(sh.server_random), sh.session_id, sh.expires_at_ms, sh.signature),
        cs.ServerHello(sh.server_pub, sh.server_random, flip(sh.session_id), sh.expires_at_ms, sh.signature),
        cs.ServerHello(sh.server_pub, sh.server_random, sh.session_id, sh.expires_at_ms + 1, sh.signature),
    ]
    for v in variants:
        with raises(HandshakeError):
            client.finish(v, identity.public_key(), now=T0)


def test_expired_session_offer_is_rejected_by_client():
    identity = Ed25519PrivateKey.generate()
    client = ClientHandshake(b"dev")
    sh, _ = server_accept(client.hello, identity, ttl_ms=1000, now=T0)
    with raises(HandshakeError):
        client.finish(sh, identity.public_key(), now=T0 + 5000)


def test_hello_serialization_and_validation():
    _, client, sh, _, _ = make_session()
    assert cs.ClientHello.from_dict(json.loads(json.dumps(client.hello.to_dict()))) == client.hello
    assert cs.ServerHello.from_dict(json.loads(json.dumps(sh.to_dict()))) == sh
    with raises(MalformedMessage):
        cs.ClientHello.from_dict({"client_pub": "AAAA"})
    with raises(MalformedMessage):
        ClientHandshake(b"")                             # pusty device_id


# ----------------------------- szyfrowanie --------------------------------- #
def test_roundtrip_both_directions():
    _, _, _, ck, sk = make_session()
    g = ReplayGuard()
    m = seal(ck, b"szablon", "verify", now=T0)
    assert open_message(sk, m, g, now=T0) == b"szablon"
    r = seal(sk, b"odpowiedz", "result", now=T0)
    assert open_message(ck, r, ReplayGuard(), now=T0) == b"odpowiedz"


def test_ciphertext_hides_plaintext_and_nonces_are_unique():
    _, _, _, ck, _ = make_session()
    pt = b"A" * 200
    msgs = [seal(ck, pt, "verify", now=T0) for _ in range(2000)]
    assert len({m.nonce for m in msgs}) == 2000
    assert msgs[0].ciphertext != msgs[1].ciphertext and pt not in msgs[0].ciphertext
    assert len(msgs[0].ciphertext) == len(pt) + 16       # tag GCM 128 bit


def test_wire_roundtrip_bytes_and_json():
    _, _, _, ck, sk = make_session()
    m = seal(ck, b"dane", "enroll", now=T0)
    assert SealedMessage.from_bytes(m.to_bytes()) == m
    assert SealedMessage.from_dict(json.loads(json.dumps(m.to_dict()))) == m
    assert open_message(sk, SealedMessage.from_bytes(m.to_bytes()), ReplayGuard(), now=T0) == b"dane"


def test_any_modification_is_detected():
    _, _, _, ck, sk = make_session()
    m = seal(ck, b"tajny szablon", "verify", now=T0)
    from dataclasses import replace
    flip = lambda b, i=0: b[:i] + bytes([b[i] ^ 1]) + b[i + 1:]
    cases = {
        "szyfrogram": (replace(m, ciphertext=flip(m.ciphertext, 3)), DecryptionError),
        "tag": (replace(m, ciphertext=flip(m.ciphertext, len(m.ciphertext) - 1)), DecryptionError),
        "nonce": (replace(m, nonce=flip(m.nonce)), DecryptionError),
        "znacznik czasu": (replace(m, timestamp_ms=m.timestamp_ms + 1), DecryptionError),
        "cel": (replace(m, purpose="enroll"), DecryptionError),
        "id sesji": (replace(m, session_id=flip(m.session_id)), MalformedMessage),
        "wersja": (replace(m, version=2), MalformedMessage),
    }
    for name, (bad, exc) in cases.items():
        with raises(exc):
            open_message(sk, bad, ReplayGuard(), now=T0)


def test_expected_purpose_is_enforced():
    _, _, _, ck, sk = make_session()
    m = seal(ck, b"x", "enroll", now=T0)
    with raises(MalformedMessage):
        open_message(sk, m, ReplayGuard(), expected_purpose="verify", now=T0)


def test_message_from_another_session_is_rejected():
    _, _, _, ck1, _ = make_session()
    _, _, _, _, sk2 = make_session()
    with raises(MalformedMessage):
        open_message(sk2, seal(ck1, b"x", "verify", now=T0), ReplayGuard(), now=T0)
    # nawet z podstawionym session_id klucz jest inny -> tag się nie zgadza
    forged = SessionKeys(ck1.session_id, b"d", sk2.send_key, sk2.recv_key, T0 + 10**6)
    with raises(DecryptionError):
        open_message(forged, seal(ck1, b"x", "verify", now=T0), ReplayGuard(), now=T0)


def test_session_expiry_for_seal_and_open():
    _, _, _, ck, sk = make_session(ttl=10_000)
    m = seal(ck, b"x", "verify", now=T0)
    with raises(SessionExpired):
        seal(ck, b"x", "verify", now=T0 + 10_000)
    with raises(SessionExpired):
        open_message(sk, m, ReplayGuard(), now=T0 + 10_000)


def test_message_limit_per_session():
    _, _, _, ck, _ = make_session()
    ck._sent = cs.MAX_MESSAGES
    with raises(SessionExhausted):
        seal(ck, b"x", "verify", now=T0)


def test_malformed_wire_inputs():
    for bad in (b"", b"\x01" * 10, b"\x01" * 5000):
        with raises(MalformedMessage):
            SealedMessage.from_bytes(bad)
    for bad in ({}, {"v": 1}, {"v": 1, "sid": "!!!", "ts": 1, "purpose": "x", "nonce": "", "ct": ""},
                {"v": 1, "sid": "AAAA", "ts": -1, "purpose": "verify", "nonce": "", "ct": ""},
                {"v": 1, "sid": "AAAA", "ts": 1, "purpose": "BAD PURPOSE", "nonce": "", "ct": ""}):
        with raises(MalformedMessage):
            SealedMessage.from_dict(bad)
    _, _, _, ck, _ = make_session()
    with raises(ValueError):
        seal(ck, b"x", "Verify Now", now=T0)             # niedozwolony cel
    with raises(ValueError):
        seal(ck, b"x" * (cs.MAX_PLAINTEXT + 1), "verify", now=T0)


# ----------------------------- replay -------------------------------------- #
def test_replayed_message_is_rejected():
    _, _, _, ck, sk = make_session()
    g = ReplayGuard()
    m = seal(ck, b"x", "verify", now=T0)
    open_message(sk, m, g, now=T0)
    with raises(NonceReused):
        open_message(sk, m, g, now=T0 + 1000)
    with raises(NonceReused):                            # także po zdekodowaniu z bajtów
        open_message(sk, SealedMessage.from_bytes(m.to_bytes()), g, now=T0 + 2000)


def test_invalid_message_does_not_burn_the_nonce():
    _, _, _, ck, sk = make_session()
    g = ReplayGuard()
    m = seal(ck, b"x", "verify", now=T0)
    from dataclasses import replace
    with raises(DecryptionError):
        open_message(sk, replace(m, ciphertext=m.ciphertext[:-1] + b"\x00"), g, now=T0)
    assert open_message(sk, m, g, now=T0) == b"x"        # oryginał nadal przechodzi


def test_timestamp_window():
    _, _, _, ck, sk = make_session()
    m = seal(ck, b"x", "verify", now=T0)
    open_message(sk, m, ReplayGuard(), now=T0 + 60_000)                 # dokładnie na granicy
    with raises(StaleTimestamp):
        open_message(sk, m, ReplayGuard(), now=T0 + 60_001)             # za stara
    with raises(StaleTimestamp):
        open_message(sk, m, ReplayGuard(), now=T0 - 5_001)              # z przyszłości
    open_message(sk, m, ReplayGuard(), now=T0 - 5_000)                  # tolerancja zegara


def test_old_message_stays_rejected_after_nonce_expiry():
    _, _, _, ck, sk = make_session()
    g = ReplayGuard()
    m = seal(ck, b"x", "verify", now=T0)
    open_message(sk, m, g, now=T0)
    # wpis nonce'a wygasa po 5 min, ale wtedy blokuje już okno czasowe (60 s)
    with raises(StaleTimestamp):
        open_message(sk, m, g, now=T0 + 301_000)


def test_concurrent_replay_exactly_one_wins():
    _, _, _, ck, sk = make_session()
    g = ReplayGuard()
    m = seal(ck, b"x", "verify", now=T0)
    results, barrier = [], threading.Barrier(24)

    def worker():
        barrier.wait()
        try:
            open_message(sk, m, g, now=T0)
            results.append("ok")
        except NonceReused:
            results.append("replay")

    threads = [threading.Thread(target=worker) for _ in range(24)]
    [t.start() for t in threads]; [t.join() for t in threads]
    assert results.count("ok") == 1 and results.count("replay") == 23


def test_guard_configuration_and_fail_closed():
    with raises(ValueError):
        ReplayGuard(max_age_ms=60_000, max_future_ms=5_000, nonce_ttl_ms=30_000)
    g = ReplayGuard(InMemoryNonceStore(max_entries=2))
    g.claim_nonce(b"s", b"1", now=T0); g.claim_nonce(b"s", b"2", now=T0)
    with raises(GuardFull):
        g.claim_nonce(b"s", b"3", now=T0)
    g.claim_nonce(b"s", b"3", now=T0 + 400_000)          # stare wpisy wygasły i zrobiły miejsce


def test_session_store_expiry():
    _, _, _, _, sk = make_session(ttl=1000)
    store = SessionStore()
    store.add(sk)
    assert store.get(sk.session_id, now=T0 + 500) is sk
    assert store.get(sk.session_id, now=T0 + 1000) is None
    assert store.get(b"\x00" * 16, now=T0) is None


# ----------------------------- vault --------------------------------------- #
def test_vault_roundtrip_and_randomization():
    p = tv.LocalKeyProvider.generate()
    t = template_to_bytes(template())
    r1, r2 = tv.encrypt_template(p, "user-1", t), tv.encrypt_template(p, "user-1", t)
    assert r1 != r2 and t not in r1                      # losowy DEK i nonce
    assert tv.decrypt_template(p, "user-1", r1) == t


def test_vault_binds_record_to_subject():
    p = tv.LocalKeyProvider.generate()
    r = tv.encrypt_template(p, "alice", b"szablon alice")
    with raises(tv.VaultError):
        tv.decrypt_template(p, "bob", r)                 # podmiana właściciela


def test_vault_detects_tampering_everywhere():
    p = tv.LocalKeyProvider.generate()
    r = tv.encrypt_template(p, "u", b"szablon")
    for i in range(len(r)):                              # zmiana KAŻDEGO bajtu rekordu
        bad = r[:i] + bytes([r[i] ^ 1]) + r[i + 1:]
        with raises(tv.VaultError):
            tv.decrypt_template(p, "u", bad)
    for junk in (b"", b"FPT", b"XXXX" * 20, r[:10], r + b"x"):
        with raises(tv.VaultError):
            tv.decrypt_template(p, "u", junk)


def test_key_rotation_via_rewrap():
    p = tv.LocalKeyProvider.generate("kek-1")
    t = b"szablon-do-rotacji"
    old = tv.encrypt_template(p, "u", t)
    p.add_key("kek-2", tv.AESGCM.generate_key(256), make_current=True)
    new = tv.rewrap(p, "u", old)
    assert new != old and new.split(b"kek-")[1][0:1] == b"2"
    p.remove_key("kek-1")                                # stary klucz wycofany
    assert tv.decrypt_template(p, "u", new) == t
    with raises(tv.VaultError):
        tv.decrypt_template(p, "u", old)                 # rekord sprzed rotacji już nie do odczytu
    with raises(tv.VaultError):
        tv.rewrap(p, "other", new)                       # rewrap też respektuje właściciela


def test_provider_validation():
    with raises(ValueError):
        tv.LocalKeyProvider({"k": b"short"}, "k")
    with raises(ValueError):
        tv.LocalKeyProvider.generate("a").remove_key("a")


# ----------------------------- end-to-end ---------------------------------- #
def test_end_to_end_template_through_channel_and_vault_then_match():
    original = template(55, seed=7)
    _, _, _, ck, sk = make_session()
    wire = seal(ck, template_to_bytes(original), "verify", now=T0).to_bytes()      # klient
    received = open_message(sk, SealedMessage.from_bytes(wire), ReplayGuard(),
                            expected_purpose="verify", now=T0)                      # serwer
    probe = template_from_bytes(received)
    provider = tv.LocalKeyProvider.generate()
    stored = tv.encrypt_template(provider, "user-42", template_to_bytes(original))  # baza
    enrolled = template_from_bytes(tv.decrypt_template(provider, "user-42", stored))
    res = match(enrolled, probe)
    assert res.n_matched >= 50 and res.score > 0.7      # kwantyzacja kąta (.tpl) nie psuje dopasowania


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
