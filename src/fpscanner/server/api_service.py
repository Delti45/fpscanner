#!/usr/bin/env python3
"""
Logika endpointów API (bez frameworka HTTP).

Serwis przyjmuje już sparsowane JSON-y i kontekst żądania (`RequestContext`:
adres klienta, odcisk certyfikatu i token z nagłówka), a zwraca słowniki
JSON-serializowalne albo rzuca `ApiError(status, code)`. Cienki adapter HTTP
(FastAPI / Flask / zwykły serwer) tylko mapuje to na odpowiedzi; dzięki temu całość
da się testować bez sieci (patrz tests/test_api_service.py).

Endpointy:
  handshake      POST /v1/handshake      uzgodnienie kluczy + token sesji
  enroll         POST /v1/enroll         rejestracja szablonu      (uprawnienie "enroll")
  verify         POST /v1/verify         weryfikacja 1:1           (uprawnienie "verify")
  erase          POST /v1/erase          usunięcie szablonu (RODO) (uprawnienie "erase")
  close_session  POST /v1/session/close  zamknięcie sesji

Kolejność kontroli w endpointach z tokenem (od najtańszej, bez efektów ubocznych):
  token (podpis, czas, IP) -> sesja -> urządzenie/certyfikat/unieważnienie ->
  uprawnienie -> wiadomość (sesja, ważność, okno czasowe, tag GCM, cel) ->
  atomowe zajęcie nonce'a -> logika. Nonce jest zajmowany dopiero po udanym
  uwierzytelnieniu wiadomości (patrz replay_guard).

Zasady bezpieczeństwa:
  * odpowiedzi na verify nie ujawniają, czy osoba istnieje (ten sam wynik i
    ten sam koszt obliczeń dla nieznanego `subject_id`),
  * domyślnie nie zwracamy wyniku dopasowania (`return_score=False`): wynik
    ułatwia atak typu „hill climbing” na szablon,
  * limit nieudanych weryfikacji per urządzenie (okno przesuwane; udana weryfikacja nie zeruje
    licznika). Świadomie nie ma blokady per osoba (byłaby DoS-em na konkretną osobę) ani limitu
    handshake'ów per IP (to robi nginx: `limit_req` oraz mTLS przed aplikacją),
  * błędy nie ujawniają szczegółów kryptograficznych (kody są ogólne),
  * w logach nie ma sekretów ani szablonów; identyfikatory osób są skracane do skrótu.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import math
import struct
import threading
from collections import deque
from dataclasses import dataclass

import fpscanner.server.wire_protocol as wp
from fpscanner.biometrics.matching import MatchConfig, match
from fpscanner.biometrics.preprocessing import Minutia, template_from_bytes
from fpscanner.security.crypto_session import (
    ClientHello,
    CryptoError,
    HandshakeError,
    SealedMessage,
    SessionExhausted,
    SessionExpired,
    SessionKeys,
    SessionStore,
    _b64d,
    open_message,
    seal,
    server_accept,
)
from fpscanner.security.device_auth import (
    DeviceAuthError,
    DevicePolicy,
    authenticate_device,
    check_device_binding,
    normalize_ip,
)
from fpscanner.security.replay_guard import (
    GuardFull,
    NonceReused,
    ReplayError,
    ReplayGuard,
    StaleTimestamp,
    now_ms,
)
from fpscanner.security.session_tokens import TokenBindingError, TokenExpired, TokenInvalid, TokenService
from fpscanner.security.template_vault import VaultError, decrypt_template, encrypt_template

log = logging.getLogger("fp.api")

SESSION_GRACE_S = 60           # sesja żyje dłużej niż token: token zawsze wygasa pierwszy
TEMPLATE_VERSION = 1
TEMPLATE_HEADER = 3            # wersja:u8 + N:u16
TEMPLATE_ENTRY = 7             # x:u16 y:u16 kąt:u16 typ:u8


# --------------------------------------------------------------------------- #
# Typy
# --------------------------------------------------------------------------- #
class ApiError(Exception):
    """Błąd do zwrócenia klientowi: status HTTP + ogólny kod (bez szczegółów)."""

    def __init__(self, status: int, code: str, *, retry_after: int | None = None):
        super().__init__(f"{status} {code}")
        self.status, self.code, self.retry_after = status, code, retry_after


@dataclass(frozen=True)
class RequestContext:
    client_ip: str | None            # po resolve_client (adres klienta, nie proxy)
    cert_fingerprint: str | None     # 'sha256:<hex>' z zaufanego źródła (TLS/proxy)
    bearer_token: str | None         # token z nagłówka Authorization


@dataclass(frozen=True)
class ServiceSettings:
    match_threshold: float = 0.25            # dobrać z krzywej DET (fpscanner.tools.evaluate_fvc)
    return_score: bool = False
    max_failures_per_device: int = 50        # jedyny limit prób: nieudane weryfikacje na urządzenie
    lockout_window_s: int = 300
    min_minutiae: int = 12                   # mniej => szablon za słaby do rejestracji/weryfikacji
    max_minutiae: int = 1000

    def __post_init__(self):
        if not 0.0 < self.match_threshold <= 1.0:
            raise ValueError("match_threshold musi leżeć w (0, 1]")
        if min(self.max_failures_per_device, self.lockout_window_s) < 1:
            raise ValueError("limit prób i okno blokady muszą być >= 1")
        if not 1 <= self.min_minutiae <= self.max_minutiae:
            raise ValueError("niepoprawne limity liczby minutiae")


# --------------------------------------------------------------------------- #
# Limiter prób
# --------------------------------------------------------------------------- #
class AttemptLimiter:
    """
    Okno przesuwane: klucz jest zablokowany, gdy w ostatnich `window_s` sekundach
    było co najmniej `max_failures` porażek. `blocked` zwraca liczbę sekund do
    odblokowania (>= 1) albo None. Czas podajemy z zewnątrz (ms).
    """

    def __init__(self, max_failures: int, window_s: int, *, max_keys: int = 100_000):
        self._max, self._window_ms, self._max_keys = max_failures, window_s * 1000, max_keys
        self._failures: dict[str, deque] = {}
        self._lock = threading.Lock()

    def _prune(self, q: deque, now: int) -> None:
        while q and now - q[0] > self._window_ms:
            q.popleft()

    def blocked(self, key: str, now_ms_: int) -> int | None:
        with self._lock:
            q = self._failures.get(key)
            if q is None:
                return None
            self._prune(q, now_ms_)
            if not q:
                del self._failures[key]
                return None
            if len(q) < self._max:
                return None
            remaining_ms = q[0] + self._window_ms - now_ms_
            return max(1, math.ceil(remaining_ms / 1000))

    def failure(self, key: str, now_ms_: int) -> None:
        with self._lock:
            q = self._failures.get(key)
            if q is None:
                if len(self._failures) >= self._max_keys:
                    self._gc(now_ms_)
                q = self._failures[key] = deque(maxlen=self._max)
            self._prune(q, now_ms_)
            q.append(now_ms_)

    def success(self, key: str) -> None:
        with self._lock:
            self._failures.pop(key, None)

    def _gc(self, now: int) -> None:
        for k in [k for k, q in self._failures.items() if not q or now - q[-1] > self._window_ms]:
            del self._failures[k]
        while len(self._failures) >= self._max_keys:          # nadal pełno: usuń najstarszy klucz
            del self._failures[next(iter(self._failures))]


# --------------------------------------------------------------------------- #
# Serwis
# --------------------------------------------------------------------------- #
def _short(subject_id: str) -> str:
    return hashlib.sha256(subject_id.encode()).hexdigest()[:10]


# Stały, syntetyczny szablon: dla nieznanego subject_id liczymy to samo dopasowanie,
# żeby czas odpowiedzi nie zdradzał, czy osoba istnieje.
_DUMMY = [Minutia((i * 37) % 300, (i * 53) % 400, (i * 0.7) % 6.28, i % 2) for i in range(40)]


class ApiService:
    def __init__(self, *, tokens: TokenService, devices, policy: DevicePolicy, identity_key,
                 vault_provider, repo, settings: ServiceSettings | None = None, clock=None,
                 sessions: SessionStore | None = None, guard: ReplayGuard | None = None,
                 match_config: MatchConfig | None = None):
        self.tokens, self.devices, self.policy = tokens, devices, policy
        self.repo, self.settings = repo, settings or ServiceSettings()
        self.clock = clock or now_ms                               # zwraca milisekundy
        self.sessions = sessions or SessionStore()
        self.guard = guard or ReplayGuard()
        self.match_config = match_config or MatchConfig()
        self._identity, self._provider = identity_key, vault_provider
        s = self.settings
        self._device_lim = AttemptLimiter(s.max_failures_per_device, s.lockout_window_s)

    # ------------------------------ pomocnicze ------------------------------ #
    @staticmethod
    def _replay_error(e: ReplayError) -> ApiError:
        if isinstance(e, NonceReused):
            return ApiError(409, "replay_detected")
        if isinstance(e, StaleTimestamp):
            return ApiError(401, "stale_message")
        if isinstance(e, GuardFull):
            return ApiError(503, "unavailable")
        return ApiError(400, "invalid_message")

    @staticmethod
    def _crypto_error(e: CryptoError) -> ApiError:
        if isinstance(e, SessionExpired):
            return ApiError(401, "session_expired")
        if isinstance(e, SessionExhausted):
            return ApiError(401, "session_exhausted")
        return ApiError(400, "invalid_message")                    # ten sam kod dla każdej przyczyny

    def _authenticate(self, ctx: RequestContext, permission: str | None):
        """Token -> sesja -> urządzenie -> uprawnienie. Zwraca (claims, keys, rekord)."""
        now = self.clock()
        if not ctx.bearer_token:
            raise ApiError(401, "invalid_token")
        try:
            claims = self.tokens.verify(ctx.bearer_token, client_ip=ctx.client_ip, now=now // 1000)
        except TokenExpired:
            raise ApiError(401, "token_expired") from None
        except TokenBindingError:
            raise ApiError(401, "token_binding") from None
        except TokenInvalid:
            raise ApiError(401, "invalid_token") from None
        keys = self.sessions.get(claims.session_id, now)
        if keys is None or not hmac.compare_digest(keys.device_id, claims.device_id.encode("utf-8")):
            raise ApiError(401, "session_closed")
        record = self.devices.get(claims.device_id)
        try:
            check_device_binding(record, self.policy, ctx.cert_fingerprint)
        except DeviceAuthError:
            raise ApiError(401, "device_mismatch") from None
        if permission is not None and not record.allows(permission):
            raise ApiError(403, "forbidden")
        return claims, keys, record

    def _open(self, keys: SessionKeys, body, purpose: str) -> bytes:
        if not isinstance(body, dict):
            raise ApiError(400, "invalid_message")
        try:
            msg = SealedMessage.from_dict(body)
            return open_message(keys, msg, self.guard, expected_purpose=purpose, now=self.clock())
        except ReplayError as e:
            raise self._replay_error(e) from None
        except CryptoError as e:
            raise self._crypto_error(e) from None

    def _reply(self, keys: SessionKeys, purpose: str, obj: dict) -> dict:
        try:
            return seal(keys, wp.pack_json(obj), wp.response_purpose(purpose),
                        now=self.clock()).to_dict()
        except CryptoError as e:
            raise self._crypto_error(e) from None

    def _read_subject(self, plaintext: bytes) -> tuple[str, bytes]:
        try:
            return wp.unpack_subject_payload(plaintext)
        except wp.ProtocolError:
            raise ApiError(400, "invalid_payload") from None

    def _check_template(self, raw: bytes) -> bytes:
        """Ścisła walidacja szablonu .tpl (wersja, długość, typy, liczba minutiae)."""
        s = self.settings
        bad = ApiError(400, "invalid_payload")
        if len(raw) < TEMPLATE_HEADER:
            raise bad
        ver, n = struct.unpack_from(">BH", raw, 0)
        if (ver != TEMPLATE_VERSION or not s.min_minutiae <= n <= s.max_minutiae
                or len(raw) != TEMPLATE_HEADER + TEMPLATE_ENTRY * n):
            raise bad
        if not set(raw[TEMPLATE_HEADER + 6::TEMPLATE_ENTRY]) <= {0, 1}:
            raise bad
        return raw

    # ------------------------------- handshake ------------------------------- #
    @staticmethod
    def _parse_handshake(body):
        if not isinstance(body, dict):
            raise ApiError(400, "invalid_message")
        ts, h, proof = body.get("ts"), body.get("hello"), body.get("proof")
        if not isinstance(ts, int) or isinstance(ts, bool) or ts < 0 or not isinstance(h, dict):
            raise ApiError(400, "invalid_message")
        try:
            hello = ClientHello.from_dict(h)
            raw_proof = None if proof is None else _b64d(proof)
            device_id = hello.device_id.decode("utf-8")
        except (CryptoError, UnicodeDecodeError, ValueError):
            raise ApiError(400, "invalid_message") from None
        return hello, device_id, ts, raw_proof

    def handshake(self, body, ctx: RequestContext) -> dict:
        now = self.clock()
        hello, device_id, ts, proof = self._parse_handshake(body)
        ip = normalize_ip(ctx.client_ip)
        if ip is None and self.tokens.bind_ip:
            raise ApiError(400, "client_address_unknown")
        ip_key = ip or "-"
        try:
            self.guard.check_timestamp(ts, now)
        except ReplayError as e:
            raise self._replay_error(e) from None
        try:
            authenticate_device(self.devices.get(device_id), self.policy, proof=proof,
                                cert_fingerprint=ctx.cert_fingerprint, device_id=device_id,
                                client_pub=hello.client_pub, client_random=hello.client_random,
                                timestamp_ms=ts)
        except DeviceAuthError:
            log.warning("handshake odrzucony: urządzenie=%r ip=%s", device_id[:64], ip_key)
            raise ApiError(401, "auth_failed") from None
        try:                                           # jednorazowość handshake'u (po uwierzytelnieniu)
            self.guard.claim_nonce(b"hs:" + hello.device_id, hello.client_random, now)
        except ReplayError as e:
            raise self._replay_error(e) from None
        try:
            hello_out, keys = server_accept(
                hello, self._identity, now=now,
                ttl_ms=(self.tokens.ttl_s + SESSION_GRACE_S) * 1000)
        except HandshakeError:
            raise ApiError(400, "invalid_message") from None
        self.sessions.add(keys)
        token = self.tokens.issue(session_id=keys.session_id, device_id=device_id,
                                  client_ip=ip, now=now // 1000)
        log.info("sesja otwarta: urządzenie=%r ip=%s", device_id, ip_key)
        return {"server_hello": hello_out.to_dict(), "token": token}

    # -------------------------------- endpointy ------------------------------ #
    def enroll(self, body, ctx: RequestContext) -> dict:
        claims, keys, _ = self._authenticate(ctx, "enroll")
        subject, raw = self._read_subject(self._open(keys, body, wp.PURPOSE_ENROLL))
        self._check_template(raw)
        if self.repo.get(subject) is not None:
            raise ApiError(409, "already_enrolled")
        record = encrypt_template(self._provider, subject, raw)
        if not self.repo.add(subject, record):                      # wyścig: ktoś był szybszy
            raise ApiError(409, "already_enrolled")
        log.info("rejestracja: osoba=%s urządzenie=%r", _short(subject), claims.device_id)
        return self._reply(keys, wp.PURPOSE_ENROLL, {"status": "enrolled"})

    def verify(self, body, ctx: RequestContext) -> dict:
        claims, keys, _ = self._authenticate(ctx, "verify")
        subject, raw = self._read_subject(self._open(keys, body, wp.PURPOSE_VERIFY))
        probe = template_from_bytes(self._check_template(raw))
        now = self.clock()
        retry = self._device_lim.blocked(claims.device_id, now)
        if retry is not None:
            log.warning("blokada prób: urządzenie=%r", claims.device_id)
            raise ApiError(429, "too_many_attempts", retry_after=retry)

        stored = self.repo.get(subject)
        score = 0.0
        if stored is None:
            match(probe, _DUMMY, self.match_config)                 # wyrównanie kosztu (brak enumeracji)
        else:
            try:
                enrolled = template_from_bytes(decrypt_template(self._provider, subject, stored))
            except VaultError:
                log.error("nie można odszyfrować rekordu osoby %s", _short(subject))
                raise ApiError(500, "internal_error") from None
            score = match(enrolled, probe, self.match_config).score
        ok = stored is not None and score >= self.settings.match_threshold

        if not ok:                       # sukces NIE zeruje licznika: inaczej własny, poprawny odcisk
            self._device_lim.failure(claims.device_id, now)     # atakującego resetowałby limit
        log.info("weryfikacja: osoba=%s urządzenie=%r wynik=%s", _short(subject), claims.device_id,
                 "OK" if ok else "ODRZUCONO")
        reply = {"match": ok}
        if self.settings.return_score:
            reply["score"] = round(score, 5)
        return self._reply(keys, wp.PURPOSE_VERIFY, reply)

    def erase(self, body, ctx: RequestContext) -> dict:
        claims, keys, _ = self._authenticate(ctx, "erase")
        subject, _ = self._read_subject(self._open(keys, body, wp.PURPOSE_ERASE))
        existed = self.repo.delete(subject)
        log.info("usunięcie: osoba=%s istniała=%s urządzenie=%r", _short(subject), existed,
                 claims.device_id)
        return self._reply(keys, wp.PURPOSE_ERASE, {"status": "erased"})

    def close_session(self, ctx: RequestContext) -> dict:
        claims, keys, _ = self._authenticate(ctx, None)
        self.sessions.remove(keys.session_id)
        log.info("sesja zamknięta: urządzenie=%r", claims.device_id)
        return {"status": "closed"}


