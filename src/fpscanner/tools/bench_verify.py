#!/usr/bin/env python3
"""
Benchmark ścieżki `verify` w procesie (bez sieci): ile weryfikacji 1:1 na sekundę
i jakie opóźnienia przy N równoległych wątkach. Pomaga zdecydować, czy dopasowanie
trzeba przenieść do puli procesów.

    python -m fpscanner.tools.bench_verify --threads 1 2 4 8 --seconds 5

Mierzy całość: kontrola tokenu i urządzenia, odszyfrowanie szablonu z "bazy"
(AES-GCM + koperta KEK), dopasowanie (`match`) i zaszyfrowanie odpowiedzi.
Szablony są syntetyczne (domyślnie 50 minutiae, tyle co z typowego obrazu FVC),
więc to oszacowanie kosztu CPU, a nie jakości dopasowania.
"""
from __future__ import annotations

import argparse
import base64
import os
import statistics
import tempfile
import threading
import time

from fpscanner.client.api_client import FingerprintClient
from fpscanner.server import wire_protocol as wp
from fpscanner.server.api_service import ApiError, RequestContext
from fpscanner.server.server_config import build_service
from fpscanner.tools.provision_dev import provision
from fpscanner.tools.smoke_test import synthetic_template

CLIENT_IP = "198.51.100.7"


class InProcessTransport:
    """Wywołuje serwis bezpośrednio, tak jak zrobiłby to adapter HTTP."""

    def __init__(self, svc, fingerprint):
        self.svc, self.fp = svc, fingerprint

    def post(self, path, body, headers):
        auth = headers.get("Authorization", "")
        ctx = RequestContext(CLIENT_IP, self.fp, auth[7:] if auth.startswith("Bearer ") else None)
        routes = {wp.PATH_HANDSHAKE: self.svc.handshake, wp.PATH_ENROLL: self.svc.enroll,
                  wp.PATH_VERIFY: self.svc.verify, wp.PATH_ERASE: self.svc.erase}
        try:
            if path == wp.PATH_CLOSE:
                return 200, self.svc.close_session(ctx)
            return 200, routes[path](body, ctx)
        except ApiError as e:
            return e.status, {"error": e.code}


def percentile(values: list[float], q: float) -> float:
    s = sorted(values)
    return s[min(len(s) - 1, int(q * len(s)))]


def run_load(clients: list[FingerprintClient], subjects: list[str], templates, seconds: float):
    latencies: list[float] = []
    lock = threading.Lock()
    stop = time.perf_counter() + seconds

    def worker(client: FingerprintClient, offset: int):
        local, i = [], offset
        while time.perf_counter() < stop:
            k = i % len(subjects)
            t0 = time.perf_counter()
            client.verify(subjects[k], templates[k])
            local.append(time.perf_counter() - t0)
            i += 1
        with lock:
            latencies.extend(local)

    t0 = time.perf_counter()
    threads = [threading.Thread(target=worker, args=(c, n * 7)) for n, c in enumerate(clients)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return latencies, time.perf_counter() - t0


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--threads", type=int, nargs="+", default=[1, 2, 4, 8])
    ap.add_argument("--seconds", type=float, default=5.0, help="czas pomiaru dla każdej liczby wątków")
    ap.add_argument("--subjects", type=int, default=50, help="liczba zarejestrowanych osób")
    ap.add_argument("--minutiae", type=int, default=50)
    a = ap.parse_args()

    with tempfile.TemporaryDirectory() as tmp:
        out = provision(tmp, ["reader-01"], local_kek=True)
        # FP_REQUIRE_TOTP=0: benchmark mierzy verify, a wielu klientów jednego urządzenia musiałoby
        # czekać po 30 s na kolejny krok TOTP (jeden handshake na krok)
        env = {**out["env"], "FP_MAX_FAILURES_DEVICE": "1000000", "FP_REQUIRE_TOTP": "0"}
        svc, _ = build_service(env)
        info = out["clients"]["reader-01"]
        fp = out["pki"]["devices"]["reader-01"]["fingerprint"]
        pub = _pubkey(out["server_public_key"])
        secret = base64.urlsafe_b64decode(info["secret"] + "=" * (-len(info["secret"]) % 4))

        def new_client():
            c = FingerprintClient(InProcessTransport(svc, fp), device_id="reader-01",
                                  server_verify_key=pub, device_secret=secret)
            c.connect()
            return c

        subjects = [f"subj-{i}" for i in range(a.subjects)]
        templates = [synthetic_template(i, a.minutiae) for i in range(a.subjects)]
        admin = new_client()
        for s, t in zip(subjects, templates, strict=True):
            admin.enroll(s, t)

        from fpscanner.biometrics.matching import match
        t0 = time.perf_counter()
        for i in range(200):
            match(templates[i % len(templates)], templates[(i + 1) % len(templates)])
        per_match = (time.perf_counter() - t0) / 200
        print(f"CPU: {os.cpu_count()} rdzeni | osób: {a.subjects} | minutiae: {a.minutiae}")
        print(f"samo match(): {per_match * 1000:.2f} ms ({1 / per_match:.0f}/s na jednym wątku)\n")
        print(f"{'wątki':>6} | {'verify/s':>9} | {'p50 ms':>7} | {'p95 ms':>7} | {'p99 ms':>7}")
        for n in a.threads:
            clients = [new_client() for _ in range(n)]
            lat, wall = run_load(clients, subjects, templates, a.seconds)
            print(f"{n:>6} | {len(lat) / wall:>9.1f} | {statistics.median(lat) * 1000:>7.2f} | "
                  f"{percentile(lat, .95) * 1000:>7.2f} | {percentile(lat, .99) * 1000:>7.2f}")


def _pubkey(b64: str):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    return Ed25519PublicKey.from_public_bytes(base64.urlsafe_b64decode(b64 + "=" * (-len(b64) % 4)))


if __name__ == "__main__":
    main()
