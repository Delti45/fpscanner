#!/usr/bin/env python3
"""
Adapter HTTP (FastAPI) nad `ApiService`.

Adapter jest cienki: czyta i ogranicza ciało żądania, buduje `RequestContext`
(adres klienta, odcisk certyfikatu, token) i mapuje `ApiError` na odpowiedź
JSON `{"error": "<kod>"}`. Całą logikę bezpieczeństwa wykonuje `ApiService`.

Wdrożenie (patrz deploy/nginx.conf):

    klient --TLS 1.3 + mTLS--> nginx --HTTP, 127.0.0.1--> uvicorn (ta aplikacja)

TLS 1.3, weryfikację certyfikatu klienta i limity robi reverse proxy; do
aplikacji przekazuje adres klienta (X-Forwarded-For) oraz certyfikat klienta
(X-Client-Cert). Aplikacja uwzględnia te nagłówki tylko od adresów z
FP_TRUSTED_PROXIES (patrz device_auth.resolve_client).

UWAGA – uvicorn musi działać z `proxy_headers=False` (`--no-proxy-headers`).
Domyślnie uvicorn podmienia adres połączenia na wartość z X-Forwarded-For,
przez co aplikacja widziałaby „klienta” zamiast proxy i (słusznie) ignorowała
by nagłówek z certyfikatem. `python -m fpscanner.server.http_app` ustawia to sam.

Uruchomienie:
    export $(grep -v '^#' dev/server.env | xargs)     # zmienne FP_*
    python -m fpscanner.server.http_app               # 127.0.0.1:8000
    # albo: uvicorn --factory --no-proxy-headers fpscanner.server.http_app:create_app_from_env

Ścieżki: POST /v1/handshake | /v1/enroll | /v1/verify | /v1/erase | /v1/session/close
oraz GET /healthz (tylko dla orkiestratora; proxy go nie wystawia na zewnątrz).
Dokumentacja OpenAPI jest wyłączona.
"""
from __future__ import annotations

import json
import logging
import os

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool
from starlette.exceptions import HTTPException as StarletteHTTPException

from fpscanner.security.device_auth import NetworkTrust, fingerprint_from_asgi_tls, resolve_client
from fpscanner.security.template_vault import KeyProviderUnavailable
from fpscanner.server import wire_protocol as wp
from fpscanner.server.api_service import ApiError, ApiService, RequestContext
from fpscanner.server.template_repository import RepositoryUnavailable

log = logging.getLogger("fp.http")

MAX_BODY_BYTES = 64 * 1024          # największy sensowny szablon (1000 minutiae) to ok. 20 KB w JSON-ie
_NO_STORE = {"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"}


def _json(status: int, content, *, retry_after: int | None = None) -> JSONResponse:
    headers = dict(_NO_STORE)
    if retry_after is not None:
        headers["Retry-After"] = str(retry_after)
    return JSONResponse(content, status_code=status, headers=headers)


def _error_response(e: ApiError) -> JSONResponse:
    return _json(e.status, {"error": e.code}, retry_after=e.retry_after)


def context_from_request(request: Request, trust: NetworkTrust) -> RequestContext:
    """
    Adres klienta i odcisk certyfikatu: z nagłówków zaufanego proxy albo – gdy
    połączenie przyszło wprost od klienta – z rozszerzenia ASGI `tls` serwera
    (Hypercorn/Daphne; uvicorn go nie udostępnia). Nagłówki od niezaufanych
    adresów są ignorowane.
    """
    peer = request.client.host if request.client else None
    client_ip, fingerprint = resolve_client(peer, request.headers, trust)
    if fingerprint is None and peer is not None and not trust.is_trusted(peer):
        fingerprint = fingerprint_from_asgi_tls(request.scope.get("extensions", {}).get("tls"))
    auth = request.headers.get("authorization", "")
    scheme, _, token = auth.partition(" ")
    bearer = token.strip() if scheme.lower() == "bearer" and token.strip() else None
    return RequestContext(client_ip, fingerprint, bearer)


async def _read_body(request: Request) -> bytes:
    """Ciało z twardym limitem rozmiaru (także gdy brak/zły Content-Length)."""
    declared = request.headers.get("content-length", "")
    if declared.isdigit() and int(declared) > MAX_BODY_BYTES:
        raise ApiError(413, "payload_too_large")
    chunks, size = [], 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > MAX_BODY_BYTES:
            raise ApiError(413, "payload_too_large")
        chunks.append(chunk)
    return b"".join(chunks)


def _parse_json(raw: bytes):
    if not raw:
        return None
    try:
        return json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, RecursionError):
        raise ApiError(400, "invalid_message") from None


def create_app(service: ApiService, trust: NetworkTrust | None = None) -> FastAPI:
    trust = trust or NetworkTrust()
    app = FastAPI(title="fp-api", docs_url=None, redoc_url=None, openapi_url=None)

    def post(path: str, method: str, *, with_body: bool = True):
        async def endpoint(request: Request):
            try:
                raw = await _read_body(request)
                ctx = context_from_request(request, trust)
                handler = getattr(service, method)             # po nazwie: łatwe podmienianie w testach
                args = (_parse_json(raw), ctx) if with_body else (ctx,)
                result = await run_in_threadpool(handler, *args)    # dopasowanie to praca dla CPU
                return _json(200, result)
            except ApiError as e:
                return _error_response(e)
            except (KeyProviderUnavailable, RepositoryUnavailable) as e:
                # awaria zależności (Vault/baza), nie błąd klienta ani uszkodzony rekord
                log.error("zależność niedostępna w %s: %s", path, e)
                return _json(503, {"error": "unavailable"}, retry_after=5)
            except Exception:                                  # noqa: BLE001 – nic nie ujawniamy klientowi
                log.exception("nieobsłużony błąd w %s", path)
                return _json(500, {"error": "internal_error"})
        endpoint.__name__ = method
        app.post(path)(endpoint)

    post(wp.PATH_HANDSHAKE, "handshake")
    post(wp.PATH_ENROLL, "enroll")
    post(wp.PATH_VERIFY, "verify")
    post(wp.PATH_ERASE, "erase")
    post(wp.PATH_CLOSE, "close_session", with_body=False)

    @app.get("/healthz")
    async def healthz():
        return _json(200, {"status": "ok"})

    @app.exception_handler(StarletteHTTPException)
    async def http_errors(_request: Request, exc: StarletteHTTPException):
        codes = {404: "not_found", 405: "method_not_allowed"}
        return _json(exc.status_code, {"error": codes.get(exc.status_code, "error")})

    return app


def create_app_from_env() -> FastAPI:
    """Fabryka dla uvicorna: serwis budowany ze zmiennych FP_* (patrz server_config)."""
    from fpscanner.server.server_config import build_service

    logging.basicConfig(level=os.environ.get("FP_LOG_LEVEL", "INFO"),
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    service, trust = build_service()
    return create_app(service, trust)


def main() -> None:
    import uvicorn

    host = os.environ.get("FP_HOST", "127.0.0.1")        # domyślnie tylko loopback: dostęp przez proxy
    port = int(os.environ.get("FP_PORT", "8000"))
    uvicorn.run(create_app_from_env(), host=host, port=port, proxy_headers=False,
                server_header=False, date_header=False, access_log=False)


if __name__ == "__main__":
    main()
