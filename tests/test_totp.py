"""
Testy TOTP (RFC 6238) i HOTP (RFC 4226): wektory testowe z RFC, okno tolerancji, walidacja
formatu kodu i jednorazowość. Testy zachowania w handshake'u są w test_api_service.py.
"""
import threading

import pytest

from fpscanner.security.totp import (
    TotpConfig,
    TotpReplayTracker,
    hotp,
    totp,
    totp_for_counter,
    verify_totp,
)

# Sekrety z dodatku B RFC 6238 (ASCII; długość równa długości skrótu: 20, 32 i 64 bajty)
S1 = b"12345678901234567890"
S256 = b"12345678901234567890123456789012"
S512 = b"1234567890123456789012345678901234567890123456789012345678901234"


def test_hotp_rfc4226_appendix_d_vectors():
    expected = ["755224", "287082", "359152", "969429", "338314",
                "254676", "287922", "162583", "399871", "520489"]
    assert [hotp(S1, i, algorithm="sha1") for i in range(10)] == expected


@pytest.mark.parametrize("t, sha1, sha256, sha512", [
    (59, "94287082", "46119246", "90693936"),
    (1111111109, "07081804", "68084774", "25091201"),
    (1111111111, "14050471", "67062674", "99943326"),
    (1234567890, "89005924", "91819424", "93441116"),
    (2000000000, "69279037", "90698825", "38618901"),
    (20000000000, "65353130", "77737706", "47863826"),
])
def test_totp_rfc6238_appendix_b_vectors(t, sha1, sha256, sha512):
    assert totp(S1, t, TotpConfig(digits=8, algorithm="sha1")) == sha1
    assert totp(S256, t, TotpConfig(digits=8, algorithm="sha256")) == sha256
    assert totp(S512, t, TotpConfig(digits=8, algorithm="sha512")) == sha512


def test_code_is_stable_within_a_step_and_changes_at_the_boundary():
    cfg = TotpConfig()
    assert totp(S256, 1_800_000_000, cfg) == totp(S256, 1_800_000_029, cfg)
    assert totp(S256, 1_800_000_029, cfg) != totp(S256, 1_800_000_030, cfg)
    assert cfg.counter(1_800_000_000) == 60_000_000 and cfg.counter(1_800_000_029) == 60_000_000
    assert cfg.seconds_to_next_step(1_800_000_000) == 30 and cfg.seconds_to_next_step(1_800_000_029) == 1


def test_verify_window_edges():
    cfg = TotpConfig(window=1)
    now = 1_800_000_010
    c = cfg.counter(now)
    for step, ok in ((c - 2, False), (c - 1, True), (c, True), (c + 1, True), (c + 2, False)):
        assert verify_totp(S256, totp_for_counter(S256, step, cfg), now, cfg) == (step if ok else None)
    strict = TotpConfig(window=0)
    assert verify_totp(S256, totp_for_counter(S256, c, strict), now, strict) == c
    assert verify_totp(S256, totp_for_counter(S256, c - 1, strict), now, strict) is None


def test_verify_rejects_wrong_secret_and_malformed_codes():
    now = 1_800_000_000
    good = totp(S256, now)
    assert verify_totp(S256, good, now) is not None
    assert verify_totp(b"x" * 32, good, now) is None                         # inny sekret
    for bad in (None, 123456, b"123456", "", "12345", "1234567", "12345a", " 12345", "١٢٣٤٥٦", "12 345"):
        assert verify_totp(S256, bad, now) is None, bad


def test_verify_near_epoch_skips_negative_counters():
    cfg = TotpConfig(window=1)
    assert verify_totp(S256, totp_for_counter(S256, 0, cfg), 5, cfg) == 0


def test_secret_length_counter_range_and_config_validation():
    with pytest.raises(ValueError):
        hotp(b"krotki", 0)                                                   # < 128 bitów (RFC 4226 R6)
    with pytest.raises(ValueError):
        hotp(S1, -1)
    with pytest.raises(ValueError):
        hotp(S1, 1 << 64)
    for kw in ({"step_s": 0}, {"digits": 5}, {"digits": 9}, {"algorithm": "md5"}, {"window": -1},
               {"window": 6}):
        with pytest.raises(ValueError):
            TotpConfig(**kw)


def test_replay_tracker_accepts_only_newer_steps_per_device():
    t = TotpReplayTracker()
    assert t.consume("a", 100) is True
    assert t.consume("a", 100) is False                   # ten sam krok
    assert t.consume("a", 99) is False                    # starszy krok
    assert t.consume("a", 101) is True
    assert t.consume("b", 100) is True                    # urządzenia są niezależne
    assert t.consume("a", 100) is False


def test_replay_tracker_is_atomic_under_concurrency():
    t = TotpReplayTracker()
    wins, start = [], threading.Barrier(16)

    def worker():
        start.wait()
        wins.append(t.consume("dev", 7))

    threads = [threading.Thread(target=worker) for _ in range(16)]
    for th in threads:
        th.start()
    for th in threads:
        th.join()
    assert wins.count(True) == 1                           # dokładnie jeden z 16 równoległych wygrywa
