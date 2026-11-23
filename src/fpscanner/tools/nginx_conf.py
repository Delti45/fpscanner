#!/usr/bin/env python3
"""
Generator konfiguracji nginx: reverse proxy z TLS 1.3 i wymaganym certyfikatem
klienta (mTLS) przed aplikacją FastAPI.

Co robi proxy (i dlaczego aplikacja na tym polega):
  * TLS tylko 1.3, `ssl_verify_client on` – bez ważnego certyfikatu z naszego CA
    połączenie nie dochodzi do aplikacji,
  * NADPISUJE nagłówki X-Forwarded-For, X-Client-Cert i X-Client-Cert-Verify
    (`proxy_set_header`), więc wartości podane przez klienta nie docierają dalej,
  * przekazuje cały certyfikat klienta (`$ssl_client_escaped_cert`); aplikacja
    liczy z niego SHA-256 (wbudowany `$ssl_client_fingerprint` to SHA-1),
  * wystawia tylko POST na /v1/, resztę (w tym /healthz) zwraca jako 404,
  * limity: rozmiar ciała, czasy, liczba żądań na adres,
  * w logach dostępowych (produkcja) nie ma nagłówków ani treści żądań.

Aplikacja musi mieć FP_TRUSTED_PROXIES=<adres, z którego łączy się nginx>,
FP_CERT_HEADER=x-client-cert i FP_CERT_VERIFY_HEADER=x-client-cert-verify
(provision_dev --behind-proxy ustawia to sam).

    python -m fpscanner.tools.nginx_conf --prod > deploy/nginx.conf
"""
from __future__ import annotations

import argparse

CERT_HEADER = "X-Client-Cert"
VERIFY_HEADER = "X-Client-Cert-Verify"

_FRAGMENT = """\
{log_format}limit_req_zone $binary_remote_addr zone=fp_api:10m rate={rate};
limit_req_status 429;

server {{
    listen {listen} ssl;
    server_name {server_name};
    server_tokens off;
{access_log}
    ssl_certificate         {server_cert};
    ssl_certificate_key     {server_key};
    ssl_protocols           TLSv1.3;
    ssl_session_tickets     off;

    # mTLS: certyfikat klienta musi pochodzić z naszego CA
    ssl_client_certificate  {client_ca};
    ssl_verify_client       on;
    ssl_verify_depth        1;

    client_max_body_size    64k;
    client_header_timeout   10s;
    client_body_timeout     10s;
    keepalive_timeout       30s;

    location /v1/ {{
        limit_except POST {{ deny all; }}
        limit_req zone=fp_api burst={burst} nodelay;

        proxy_pass              http://{upstream};
        proxy_http_version      1.1;
        proxy_set_header        Connection "";
        proxy_set_header        Host $host;
        # NADPISUJEMY (nie dopisujemy): nginx jest brzegiem sieci
        proxy_set_header        X-Forwarded-For $remote_addr;
        proxy_set_header        {cert_header} $ssl_client_escaped_cert;
        proxy_set_header        {verify_header} $ssl_client_verify;
        proxy_connect_timeout   3s;
        proxy_send_timeout      15s;
        proxy_read_timeout      15s;
    }}

    location / {{ return 404; }}
}}
"""

_PROD_HEADER = """\
# Wygenerowano przez fpscanner.tools.nginx_conf (nie edytuj ręcznie, zmień generator).
# Fragment kontekstu `http`: zapisz jako /etc/nginx/conf.d/fp.conf (dołączany z nginx.conf).
"""

_PROD_LOG_FORMAT = (
    "log_format fp '$remote_addr [$time_local] \"$request_method $uri\" "
    "$status $body_bytes_sent $request_time';\n")


def render(*, server_cert: str, server_key: str, client_ca: str, listen: str = "443",
           server_name: str = "localhost", upstream: str = "127.0.0.1:8000",
           run_dir: str | None = None, error_log: str | None = None,
           rate: str = "30r/s", burst: int = 60) -> str:
    """
    `run_dir=None`: fragment produkcyjny do /etc/nginx/conf.d/ (logi dostępowe bez
    nagłówków i treści żądań).
    `run_dir=<katalog>`: kompletny plik deweloperski uruchamiany bez roota
    (`nginx -c <plik> -p <katalog>`): pid, log błędów i katalogi tymczasowe w
    `run_dir`, bez logu dostępowego. `error_log` zmienia miejsce logu błędów
    (w kontenerze: /dev/stderr, żeby trafiał do `docker logs`).
    """
    fields = dict(listen=listen, server_name=server_name, server_cert=server_cert,
                  server_key=server_key, client_ca=client_ca, upstream=upstream,
                  cert_header=CERT_HEADER, verify_header=VERIFY_HEADER, rate=rate,
                  burst=burst)
    if run_dir is None:
        body = _FRAGMENT.format(log_format=_PROD_LOG_FORMAT,
                                access_log="    access_log /var/log/nginx/fp_access.log fp;\n",
                                **fields)
        return _PROD_HEADER + body
    body = _FRAGMENT.format(log_format="", access_log="    access_log off;\n", **fields)
    indented = "".join(("    " + line if line.strip() else line) for line in body.splitlines(True))
    temp = "".join(f"    {d}_temp_path {run_dir}/tmp/{d};\n"
                   for d in ("client_body", "proxy", "fastcgi", "uwsgi", "scgi"))
    return (f"worker_processes 1;\npid {run_dir}/nginx.pid;\n"
            f"error_log {error_log or run_dir + '/nginx-error.log'} warn;\n"
            f"events {{ worker_connections 256; }}\n\nhttp {{\n{temp}\n{indented}}}\n")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--prod", action="store_true", help="konfiguracja produkcyjna (ścieżki /etc/fp/...)")
    ap.add_argument("--server-cert", default="/etc/fp/tls/server.pem")
    ap.add_argument("--server-key", default="/etc/fp/tls/server.key")
    ap.add_argument("--client-ca", default="/etc/fp/tls/client-ca.pem")
    ap.add_argument("--listen", default="443")
    ap.add_argument("--server-name", default="fp.example.com")
    ap.add_argument("--upstream", default="127.0.0.1:8000")
    a = ap.parse_args()
    if not a.prod:
        ap.error("do konfiguracji deweloperskiej użyj: provision_dev --behind-proxy")
    print(render(server_cert=a.server_cert, server_key=a.server_key, client_ca=a.client_ca,
                 listen=a.listen, server_name=a.server_name, upstream=a.upstream), end="")


if __name__ == "__main__":
    main()
