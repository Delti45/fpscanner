#!/usr/bin/env python3
"""
Test dymny działającego wdrożenia (np. docker compose): handshake, rejestracja,
weryfikacja (swoja i cudza), zamknięcie sesji. Kod wyjścia 0 = wszystko działa.

    python -m fpscanner.tools.smoke_test --url https://localhost:8443 \\
        --client dev/clients/reader-01.json [--admin dev/clients/admin-01.json]

`--client` to plik wygenerowany przez provision_dev (sekret, certyfikat, klucz,
CA, klucz publiczny serwera). Z `--admin` osoba testowa jest po teście usuwana;
bez niego zostaje w bazie pod identyfikatorem `smoke-<losowy>`.
"""
from __future__ import annotations

import argparse
import base64
import json
import secrets
import sys
import time
from pathlib import Path

import numpy as np
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from fpscanner.biometrics.preprocessing import Minutia
from fpscanner.client.api_client import ApiClientError, FingerprintClient, HttpsTransport
from fpscanner.security.tls_config import client_ssl_context


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def synthetic_template(seed: int, n: int = 40) -> list[Minutia]:
    rng = np.random.default_rng(seed)
    return [Minutia(int(rng.integers(20, 300)), int(rng.integers(20, 380)),
                    float(rng.uniform(0, 2 * np.pi)), int(rng.integers(0, 2))) for _ in range(n)]


def make_client(url: str, client_file: Path) -> FingerprintClient:
    info = json.loads(client_file.read_text(encoding="utf-8"))
    ctx = client_ssl_context(info["ca"], info["cert"], info["key"])
    return FingerprintClient(
        HttpsTransport(url, ctx), device_id=info["device_id"],
        server_verify_key=Ed25519PublicKey.from_public_bytes(_b64d(info["server_public_key"])),
        device_secret=_b64d(info["secret"]),
        totp_secret=_b64d(info["totp_secret"]) if info.get("totp_secret") else None)


def run(url: str, client_file: Path, admin_file: Path | None = None,
        wait_s: float = 0.0) -> list[tuple[str, bool]]:
    subject = "smoke-" + secrets.token_hex(4)
    own, other = synthetic_template(1), synthetic_template(2)
    results: list[tuple[str, bool]] = []

    def check(name: str, ok: bool) -> None:
        results.append((name, bool(ok)))

    client = make_client(url, client_file)
    deadline = time.monotonic() + wait_s              # usługi w compose startują równolegle
    while True:
        try:
            client.connect()
            break
        except OSError:
            if time.monotonic() > deadline:
                raise
            time.sleep(0.5)
    check("handshake i sesja", True)
    check("rejestracja", client.enroll(subject, own) == {"status": "enrolled"})
    check("weryfikacja własnego odcisku", client.verify(subject, own) is True)
    check("odrzucenie cudzego odcisku", client.verify(subject, other) is False)
    try:
        client.enroll(subject, own)
        check("ponowna rejestracja odrzucona (409)", False)
    except ApiClientError as e:
        check("ponowna rejestracja odrzucona (409)", (e.status, e.code) == (409, "already_enrolled"))
    if admin_file:
        admin = make_client(url, admin_file)
        admin.connect()
        check("usunięcie osoby testowej", admin.erase(subject) == {"status": "erased"})
        admin.close()
    client.close()
    check("zamknięcie sesji", True)
    return results


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url", required=True, help="np. https://localhost:8443")
    ap.add_argument("--client", required=True, type=Path, help="plik clients/<id>.json")
    ap.add_argument("--admin", type=Path, help="plik admina (do usunięcia osoby testowej)")
    ap.add_argument("--wait", type=float, default=0.0, metavar="S",
                    help="ile sekund czekać na start serwera (domyślnie 0)")
    a = ap.parse_args()
    try:
        results = run(a.url, a.client, a.admin, a.wait)
    except (ApiClientError, OSError) as e:
        print(f"BŁĄD: {type(e).__name__}: {e}", file=sys.stderr)
        raise SystemExit(1) from None
    for name, ok in results:
        print(f"{'OK  ' if ok else 'FAIL'} {name}")
    raise SystemExit(0 if all(ok for _, ok in results) else 1)


if __name__ == "__main__":
    main()
