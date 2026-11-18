#!/usr/bin/env python3
"""
Klient API czytnika linii papilarnych.

`FingerprintClient` realizuje stronę klienta protokołu: handshake (X25519 +
dowód posiadania sekretu urządzenia), szyfrowanie żądań kluczem sesyjnym
(AES-256-GCM, losowy nonce, znacznik czasu), odbiór i weryfikację odpowiedzi
(tag GCM, okno czasowe, własny ReplayGuard: podstawiona stara odpowiedź jest
odrzucana). Klucz publiczny serwera (Ed25519) musi być ZAPINOWANY po stronie
klienta, a nie pobierany tą samą drogą co handshake.

Transport to dowolny obiekt z metodą
    post(path: str, body: dict | None, headers: dict) -> (status: int, json: dict)
W testach jest to wywołanie serwisu w procesie, a w produkcji `HttpsTransport`
(TLS 1.3 + mTLS, patrz tls_config.client_ssl_context).

Przykład:
    ctx = tls_config.client_ssl_context("ca.pem", "device.pem", "device.key")
    client = FingerprintClient(HttpsTransport("https://localhost:8443", ctx),
                               device_id="reader-01", server_verify_key=pub,
                               device_secret=secret, totp_secret=totp_secret)
    client.connect()
    client.enroll("alice", minutiae)
    ok = client.verify("alice", minutiae_probe)
    client.close()
"""
from __future__ import annotations

import http.client
import json
import ssl
import time
import urllib.parse

import fpscanner.server.wire_protocol as wp
from fpscanner.biometrics.preprocessing import Minutia, template_to_bytes
from fpscanner.security.crypto_session import (
    ClientHandshake,
    SealedMessage,
    ServerHello,
    SessionKeys,
    _b64e,
    open_message,
    seal,
)
from fpscanner.security.device_auth import device_proof
from fpscanner.security.replay_guard import ReplayGuard, now_ms
from fpscanner.security.totp import DEFAULT as DEFAULT_TOTP
from fpscanner.security.totp import TotpConfig, totp


class ApiClientError(Exception):
    """Serwer odrzucił żądanie: status HTTP + ogólny kod błędu."""

    def __init__(self, status: int, code: str):
        super().__init__(f"{status} {code}")
        self.status, self.code = status, code


def _raise_for(status: int, resp) -> None:
    code = resp.get("error", "unknown") if isinstance(resp, dict) else "unknown"
    raise ApiClientError(status, str(code))


class FingerprintClient:
    def __init__(self, transport, *, device_id: str, server_verify_key,
                 device_secret: bytes | None = None, totp_secret: bytes | None = None,
                 totp_config: TotpConfig = DEFAULT_TOTP, clock=None, sleep=None):
        self._t = transport
        self._device_id = device_id
        self._verify_key = server_verify_key
        self._secret = device_secret
        self._totp_secret, self._totp_cfg = totp_secret, totp_config
        self._last_totp_step: int | None = None
        self._sleep = sleep or time.sleep
        self._clock = clock or now_ms
        self._keys: SessionKeys | None = None
        self._token: str | None = None
        self._guard = ReplayGuard()

    # ------------------------------- sesja ---------------------------------- #
    def connect(self) -> None:
        """Handshake: nowe klucze sesyjne i token. Wcześniejsza sesja jest porzucana."""
        hs = ClientHandshake(self._device_id.encode("utf-8"))
        ts = self._clock()
        step = None
        if self._totp_secret is not None:
            step = self._totp_cfg.counter(ts / 1000)
            if self._last_totp_step is not None and step <= self._last_totp_step:
                # serwer przyjmuje kod z danego kroku tylko raz (RFC 6238, §5.2): czekamy na następny
                self._sleep(self._totp_cfg.seconds_to_next_step(ts / 1000))
                ts = self._clock()
                step = self._totp_cfg.counter(ts / 1000)
        body: dict = {"hello": hs.hello.to_dict(), "ts": ts}
        if self._totp_secret is not None:
            body["totp"] = totp(self._totp_secret, ts / 1000, self._totp_cfg)
            self._last_totp_step = step
        if self._secret is not None:
            body["proof"] = _b64e(device_proof(
                self._secret, device_id=self._device_id, client_pub=hs.hello.client_pub,
                client_random=hs.hello.client_random, timestamp_ms=ts))
        status, resp = self._t.post(wp.PATH_HANDSHAKE, body, {})
        if status != 200:
            _raise_for(status, resp)
        keys = hs.finish(ServerHello.from_dict(resp["server_hello"]), self._verify_key,
                         now=self._clock())
        self._keys, self._token, self._guard = keys, resp["token"], ReplayGuard()

    def close(self) -> None:
        """Zamyka sesję na serwerze; lokalne klucze są kasowane zawsze."""
        if self._keys is None:
            return
        try:
            self._t.post(wp.PATH_CLOSE, None, {"Authorization": f"Bearer {self._token}"})
        finally:
            self._keys, self._token = None, None

    # ------------------------------ wywołania -------------------------------- #
    def _call(self, path: str, purpose: str, payload: bytes) -> dict:
        if self._keys is None or self._token is None:
            raise RuntimeError("brak sesji: najpierw wywołaj connect()")
        msg = seal(self._keys, payload, purpose, now=self._clock())
        status, resp = self._t.post(path, msg.to_dict(), {"Authorization": f"Bearer {self._token}"})
        if status != 200:
            _raise_for(status, resp)
        reply = open_message(self._keys, SealedMessage.from_dict(resp), self._guard,
                             expected_purpose=wp.response_purpose(purpose), now=self._clock())
        return wp.unpack_json(reply)

    @staticmethod
    def _as_bytes(template) -> bytes:
        return bytes(template) if isinstance(template, (bytes, bytearray)) else template_to_bytes(
            list(template))

    def enroll(self, subject_id: str, template: list[Minutia] | bytes) -> dict:
        payload = wp.pack_subject_payload(subject_id, self._as_bytes(template))
        return self._call(wp.PATH_ENROLL, wp.PURPOSE_ENROLL, payload)

    def verify(self, subject_id: str, template: list[Minutia] | bytes) -> bool:
        payload = wp.pack_subject_payload(subject_id, self._as_bytes(template))
        return bool(self._call(wp.PATH_VERIFY, wp.PURPOSE_VERIFY, payload).get("match"))

    def erase(self, subject_id: str) -> dict:
        return self._call(wp.PATH_ERASE, wp.PURPOSE_ERASE, wp.pack_subject_payload(subject_id))


class HttpsTransport:
    """Transport HTTPS (JSON) na bibliotece standardowej; `ssl_context` z tls_config."""

    def __init__(self, base_url: str, ssl_context: ssl.SSLContext, *, timeout: float = 10.0,
                 source_address: tuple[str, int] | None = None):
        u = urllib.parse.urlsplit(base_url)
        if u.scheme != "https" or not u.hostname:
            raise ValueError("base_url musi mieć postać https://host[:port]")
        self._host, self._port = u.hostname, u.port or 443
        self._ctx, self._timeout, self._source = ssl_context, timeout, source_address

    def post(self, path: str, body, headers: dict) -> tuple[int, dict]:
        data = json.dumps(body).encode("utf-8")
        hdrs = {"Content-Type": "application/json", "Accept": "application/json", **headers}
        conn = http.client.HTTPSConnection(self._host, self._port, context=self._ctx,
                                           timeout=self._timeout, source_address=self._source)
        try:
            conn.request("POST", path, body=data, headers=hdrs)
            r = conn.getresponse()
            raw = r.read(1_000_000)
            try:
                return r.status, json.loads(raw.decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                return r.status, {"error": "bad_response"}
        finally:
            conn.close()
