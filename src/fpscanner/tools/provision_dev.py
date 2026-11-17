#!/usr/bin/env python3
"""
Generator deweloperskiego środowiska: PKI (CA, serwer, urządzenia), klucze
serwera, rejestr urządzeń i plik zmiennych środowiskowych dla `build_service`.

WYŁĄCZNIE do ROZWOJU I TESTÓW. Wszystkie wygenerowane sekrety (klucze prywatne,
klucz JWT, sekrety urządzeń) leżą na dysku jako zwykłe pliki z
uprawnieniami 0600, a katalog wynikowy trzeba dodać do .gitignore.

Użycie:
    python -m fpscanner.tools.provision_dev --out dev --readers reader-01 reader-02 --admins admin-01
    set -a; source dev/server.env; set +a        # Linux/macOS (Windows: patrz README)
    # klient: dev/clients/reader-01.json (sekret, klucz publiczny serwera, ścieżki do certyfikatów)

W kodzie (np. testy):
    out = provision(tmpdir, ["reader-01"], admin_ids=("admin-01",), local_kek=True)
    svc, trust = build_service(out["env"])        # local_kek=True: KEK-i w zmiennych (bez Vaulta)
"""
from __future__ import annotations

import argparse
import base64
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import fpscanner.security.tls_config as tc
from fpscanner.tools.nginx_conf import CERT_HEADER, VERIFY_HEADER
from fpscanner.tools.nginx_conf import render as render_nginx

READER_PERMISSIONS = ["enroll", "verify"]
ADMIN_PERMISSIONS = ["enroll", "verify", "erase"]


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _write_secret(path: Path, text: str) -> str:
    path.write_text(text, encoding="utf-8")
    if os.name == "posix":
        os.chmod(path, 0o600)
    return str(path)


def provision(directory: str | Path, device_ids: list[str], *, admin_ids=(),
              bind_ip: bool = True, local_kek: bool = False,
              trusted_proxies: tuple = (), behind_proxy: bool = False,
              proxy_port: int = 8443, app_port: int = 8000, proxy_host: str = "127.0.0.1",
              upstream_host: str = "127.0.0.1", server_names: tuple = ("localhost",),
              nginx_error_log: str | None = None) -> dict:
    """
    Tworzy środowisko w `directory` i zwraca słownik:
      env                 zmienne dla build_service (same napisy),
      server_public_key   klucz Ed25519 serwera do zapinowania w kliencie (base64url),
      clients             {id: {secret, cert, key, ca}} dane urządzeń,
      pki                 wynik tls_config.generate_dev_pki,
      env_file, devices_file   ścieżki zapisanych plików.
    `local_kek=True` dodaje KEK-i w zmiennych i FP_KEY_PROVIDER=local (testy, benchmarki);
    domyślnie klucze główne zostają w Vault Transit (FP_KEY_PROVIDER=vault ustawia Compose).
    `behind_proxy=True` konfiguruje aplikację do pracy za nginx (zaufany adres
    127.0.0.1, nagłówki z certyfikatem) i zapisuje gotowy `nginx.conf`
    (słucha na <proxy_host>:<proxy_port>, aplikacja na <upstream_host>:<app_port>).
    `server_names`: nazwy DNS w certyfikacie serwera (klient sprawdza hostname),
    np. ("localhost", "proxy") dla klienta w sieci docker-compose.
    """
    d = Path(directory).resolve()
    d.mkdir(parents=True, exist_ok=True)
    admin_ids = tuple(admin_ids)
    all_ids = list(device_ids) + [a for a in admin_ids if a not in device_ids]

    pki = tc.generate_dev_pki(d / "pki", all_ids, server_names=tuple(server_names))

    signing = Ed25519PrivateKey.generate()
    seed = signing.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                 serialization.NoEncryption())
    public = signing.public_key().public_bytes(serialization.Encoding.Raw,
                                               serialization.PublicFormat.Raw)

    devices, clients = [], {}
    for dev in all_ids:
        secret = os.urandom(32)
        perms = ADMIN_PERMISSIONS if dev in admin_ids else READER_PERMISSIONS
        info = pki["devices"][dev]
        devices.append({"device_id": dev, "secret": _b64(secret), "permissions": perms,
                        "cert_fingerprint": info["fingerprint"]})
        clients[dev] = {"secret": _b64(secret), "cert": info["cert"], "key": info["key"],
                        "ca": pki["ca"]}

    devices_file = _write_secret(d / "devices.json", json.dumps({"devices": devices}, indent=1))
    env = {
        "FP_JWT_KEY": _b64(os.urandom(32)),
        "FP_SERVER_SIGNING_KEY": _b64(seed),
        "FP_DEVICES_FILE": devices_file,
        "FP_REQUIRE_MTLS": "1",
        "FP_REQUIRE_PROOF": "1",
        "FP_BIND_IP": "1" if bind_ip else "0",
    }
    if behind_proxy:
        trusted_proxies = tuple(dict.fromkeys((*trusted_proxies, "127.0.0.1", "::1")))
        env["FP_CERT_HEADER"] = CERT_HEADER.lower()
        env["FP_CERT_VERIFY_HEADER"] = VERIFY_HEADER.lower()
        env["FP_PORT"] = str(app_port)
    if trusted_proxies:
        env["FP_TRUSTED_PROXIES"] = ",".join(trusted_proxies)
    if local_kek:
        env.update({"FP_KEY_PROVIDER": "local", "FP_KEK_KEK1": _b64(os.urandom(32)),
                    "FP_ACTIVE_KEK": "kek1"})
    env_file = _write_secret(d / "server.env", "".join(f"{k}={v}\n" for k, v in env.items()))

    (d / "clients").mkdir(exist_ok=True)
    for dev, info in clients.items():
        _write_secret(d / "clients" / f"{dev}.json", json.dumps(
            {"device_id": dev, **info, "server_public_key": _b64(public)}, indent=1))

    result = {"env": env, "server_public_key": _b64(public), "clients": clients, "pki": pki,
              "env_file": env_file, "devices_file": devices_file}
    if behind_proxy:
        run = d / "run"
        for leaf in ("client_body", "proxy", "fastcgi", "uwsgi", "scgi"):
            (run / "tmp" / leaf).mkdir(parents=True, exist_ok=True)
        conf = render_nginx(server_cert=pki["server_cert"], server_key=pki["server_key"],
                            client_ca=pki["ca"], listen=f"{proxy_host}:{proxy_port}",
                            upstream=f"{upstream_host}:{app_port}", run_dir=str(run),
                            error_log=nginx_error_log)
        (d / "nginx.conf").write_text(conf, encoding="utf-8")
        result.update(nginx_conf=str(d / "nginx.conf"), nginx_run_dir=str(run),
                      proxy_url=f"https://localhost:{proxy_port}")
    return result


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", type=Path, default=Path("dev"), help="katalog wynikowy")
    ap.add_argument("--readers", nargs="+", default=["reader-01"], metavar="ID")
    ap.add_argument("--admins", nargs="*", default=[], metavar="ID",
                    help="urządzenia z prawem kasowania (erase)")
    ap.add_argument("--no-bind-ip", action="store_true", help="nie wiąż tokenów z adresem IP")
    ap.add_argument("--local-kek", action="store_true",
                    help="KEK-i w zmiennych zamiast Vaulta (tylko lokalne próby bez Dockera)")
    ap.add_argument("--trusted-proxy", action="append", default=[], metavar="CIDR")
    ap.add_argument("--behind-proxy", action="store_true",
                    help="skonfiguruj pracę za nginx i zapisz dev/nginx.conf")
    ap.add_argument("--proxy-port", type=int, default=8443)
    ap.add_argument("--app-port", type=int, default=8000)
    ap.add_argument("--proxy-host", default="127.0.0.1", help="adres nasłuchu nginx (w kontenerze 0.0.0.0)")
    ap.add_argument("--upstream-host", default="127.0.0.1", help="adres aplikacji widziany przez nginx")
    ap.add_argument("--nginx-error-log", default=None, help="np. /dev/stderr (w kontenerze)")
    ap.add_argument("--server-name", action="append", default=None, metavar="DNS",
                    help="nazwa DNS w certyfikacie serwera (można powtarzać; domyślnie localhost)")
    a = ap.parse_args()
    out = provision(a.out, a.readers, admin_ids=a.admins, bind_ip=not a.no_bind_ip,
                    local_kek=a.local_kek, trusted_proxies=tuple(a.trusted_proxy),
                    behind_proxy=a.behind_proxy, proxy_port=a.proxy_port, app_port=a.app_port,
                    proxy_host=a.proxy_host, upstream_host=a.upstream_host,
                    server_names=tuple(a.server_name or ["localhost"]),
                    nginx_error_log=a.nginx_error_log)
    print(f"Środowisko zapisane w {a.out}/")
    print(f"  zmienne serwera : {out['env_file']}")
    print(f"  rejestr urządzeń: {out['devices_file']}")
    print(f"  klucz publiczny serwera (zapinowany w kliencie): {out['server_public_key']}")
    for dev in out["clients"]:
        print(f"  klient {dev}: {Path(a.out) / 'clients' / (dev + '.json')}")
    if a.behind_proxy:
        print(f"\nUruchomienie (trzy terminale):\n"
              f"  1. set -a; . {out['env_file']}; set +a; python -m fpscanner.server.http_app\n"
              f"  2. nginx -c {out['nginx_conf']} -p {out['nginx_run_dir']}\n"
              f"  3. klient: HttpsTransport('{out['proxy_url']}', ...) z certyfikatem z clients/*.json")
    print("Pamiętaj: dodaj katalog wynikowy do .gitignore (zawiera klucze prywatne).")


if __name__ == "__main__":
    main()
