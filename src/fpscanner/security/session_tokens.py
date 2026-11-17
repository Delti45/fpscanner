#!/usr/bin/env python3
"""
Krótko żyjące tokeny sesji (JWT, HS256) powiązane z urządzeniem i adresem IP.

Token jest wydawany po udanym handshake'u i wysyłany w nagłówku
`Authorization: Bearer ...`. Zawiera: iss, aud, sub (device_id), sid (session_id,
base64url), jti (unikalny), iat/nbf/exp oraz `ip` (adres klienta, gdy włączono
wiązanie). Domyślny czas życia to 15 minut (jak sesja kryptograficzna).

Zasady weryfikacji (każde naruszenie => TokenInvalid):
  * algorytm wyłącznie HS256 (odrzucamy `none`, HS512 i podmianę algorytmu),
  * jeden klucz HMAC (>= 32 B); token żyje 15 minut, więc wymiana klucza to restart serwera
    (wszystkie sesje i tak wygasają wraz z kluczem sesyjnym),
  * obowiązkowe pola oraz zgodne `iss` i `aud`, liczbowe exp/iat/nbf,
  * czas sprawdzamy sami (wstrzykiwany `now`, tolerancja zegara `leeway_s`),
    dzięki czemu testy są deterministyczne,
  * wiązanie z IP: adres z żądania musi równać się adresowi z tokenu
    (IPv4-mapped IPv6 traktujemy jak IPv4).
Token NIE zastępuje kryptografii sesji: wiadomości i tak są szyfrowane kluczem
sesyjnym, a token tylko identyfikuje sesję i urządzenie.
"""
from __future__ import annotations

import base64
import binascii
import hmac
import secrets
import time
from dataclasses import dataclass

import jwt

from fpscanner.security.device_auth import normalize_ip

ALGORITHM = "HS256"
MIN_KEY_LEN = 32
_REQUIRED = ["iss", "aud", "sub", "sid", "jti", "iat", "nbf", "exp"]
MAX_TOKEN_LEN = 4096


class TokenError(Exception):
    """Bazowy wyjątek tokenów."""


class TokenInvalid(TokenError):
    """Token niepoprawny: podpis, struktura, claims lub czas wydania."""


class TokenExpired(TokenInvalid):
    """Token wygasł."""


class TokenBindingError(TokenError):
    """Token użyty z innego adresu IP niż ten, dla którego go wydano."""


def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _b64d_strict(s: str) -> bytes:
    if not isinstance(s, str):
        raise ValueError("oczekiwano tekstu")
    return base64.b64decode(s + "=" * (-len(s) % 4), altchars=b"-_", validate=True)


# --------------------------------------------------------------------------- #
# Tokeny
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class TokenClaims:
    session_id: bytes
    device_id: str
    client_ip: str | None
    expires_at: int            # sekundy UNIX
    jti: str = ""
    issued_at: int = 0


def _is_int(v) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


class TokenService:
    def __init__(self, key: bytes, *, ttl_s: int = 900, bind_ip: bool = True,
                 leeway_s: int = 5, issuer: str = "fp-server", audience: str = "fp-api"):
        if not isinstance(key, (bytes, bytearray)) or len(key) < MIN_KEY_LEN:
            raise ValueError(f"klucz tokenów musi mieć co najmniej {MIN_KEY_LEN} bajtów")
        if ttl_s <= 0 or leeway_s < 0:
            raise ValueError("ttl_s musi być dodatnie, leeway_s nieujemne")
        self._key, self.ttl_s, self.bind_ip = bytes(key), ttl_s, bind_ip
        self.leeway_s, self.issuer, self.audience = leeway_s, issuer, audience

    def issue(self, *, session_id: bytes, device_id: str, client_ip: str | None = None,
              now: int | None = None) -> str:
        now = int(time.time()) if now is None else now
        payload = {"iss": self.issuer, "aud": self.audience, "sub": device_id,
                   "sid": _b64e(session_id), "jti": secrets.token_urlsafe(16),
                   "iat": now, "nbf": now, "exp": now + self.ttl_s}
        if self.bind_ip:
            ip = normalize_ip(client_ip)
            if ip is None:
                raise ValueError("wiązanie z adresem IP wymaga poprawnego client_ip")
            payload["ip"] = ip
        return jwt.encode(payload, self._key, algorithm=ALGORITHM)

    def verify(self, token: str, *, client_ip: str | None = None,
               now: int | None = None) -> TokenClaims:
        now = int(time.time()) if now is None else now
        if not isinstance(token, str) or not token or len(token) > MAX_TOKEN_LEN:
            raise TokenInvalid("brak lub niepoprawny token")
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError:
            raise TokenInvalid("niepoprawny nagłówek tokenu") from None
        if header.get("alg") != ALGORITHM:
            raise TokenInvalid("niedozwolony algorytm")
        try:
            p = jwt.decode(token, self._key, algorithms=[ALGORITHM], audience=self.audience,
                           issuer=self.issuer,
                           options={"require": _REQUIRED, "verify_exp": False,
                                    "verify_nbf": False, "verify_iat": False})
        except jwt.PyJWTError:
            raise TokenInvalid("token nie przeszedł weryfikacji") from None

        if not all(_is_int(p[c]) for c in ("exp", "iat", "nbf")):
            raise TokenInvalid("pola czasu muszą być liczbami całkowitymi")
        if not isinstance(p["sub"], str) or not p["sub"] or not isinstance(p["jti"], str):
            raise TokenInvalid("niepoprawne pola sub/jti")
        try:
            session_id = _b64d_strict(p["sid"])
        except (ValueError, binascii.Error):
            raise TokenInvalid("niepoprawny identyfikator sesji") from None
        if not session_id:
            raise TokenInvalid("pusty identyfikator sesji")

        if now >= p["exp"]:
            raise TokenExpired("token wygasł")
        if p["nbf"] > now + self.leeway_s or p["iat"] > now + self.leeway_s:
            raise TokenInvalid("token wydany w przyszłości")

        bound_ip = None
        if self.bind_ip:
            claim_ip = normalize_ip(p.get("ip"))
            if claim_ip is None:
                raise TokenInvalid("token bez wiązania z adresem IP")
            presented = normalize_ip(client_ip)
            if presented is None or not hmac.compare_digest(presented, claim_ip):
                raise TokenBindingError("adres klienta różni się od adresu z tokenu")
            bound_ip = claim_ip
        return TokenClaims(session_id, p["sub"], bound_ip, p["exp"], p["jti"], p["iat"])
