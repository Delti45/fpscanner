#!/usr/bin/env python3
"""
Szyfrowanie szablonu biometrycznego w transmisji: klucz sesyjny (HKDF) +
AES-256-GCM z uwierzytelnianiem nagłówka (AAD).

Warstwa ta działa NA GÓRZE TLS 1.3, jako dodatkowa ochrona (np. gdy TLS
kończy się na pośredniczącym proxy). Nie zastępuje TLS ani mTLS.

Protokół (v1)
-------------
1. Uzgodnienie klucza (handshake), jednorazowo na sesję:
     klient  -> ClientHello(efemeryczny X25519, client_random, device_id)
     serwer  -> ServerHello(efemeryczny X25519, server_random, session_id,
                            wygaśnięcie, podpis Ed25519 transkryptu)
   Klient weryfikuje podpis kluczem serwera, który ma ZAPINOWANY (nie pobiera
   go z tej samej drogi co handshake; inaczej aktywny MITM podmieniłby klucze).
2. Z sekretu X25519 przez HKDF-SHA256 powstają DWA niezależne klucze
   AES-256: klient->serwer i serwer->klient. Sól = client_random||server_random,
   info = etykieta kierunku + skrót transkryptu (zmiana dowolnego pola
   handshake'u daje inne klucze). Osobne klucze na kierunek wykluczają
   kolizję nonce'ów między kierunkami.
3. Wiadomość (SealedMessage): nagłówek jawny, ale uwierzytelniony jako AAD:
       wersja | session_id | timestamp_ms | cel (np. "enroll", "verify")
   + nonce 96 bit z CSPRNG + szyfrogram z tagiem GCM.
   Zmiana któregokolwiek pola nagłówka (np. podmiana celu "verify" na
   "enroll" albo przesunięcie znacznika czasu) psuje tag.
4. Odbiór (open_message): sesja -> ważność -> okno czasowe -> deszyfrowanie
   z weryfikacją tagu -> atomowe zajęcie nonce'a w ReplayGuard.

Zasady bezpieczeństwa
---------------------
* Nonce GCM jest losowy (96 bit). Kolizja przy tym samym kluczu zniszczyłaby
  poufność i integralność, więc klucz jest per sesja, a liczba wiadomości na
  sesję ograniczona (MAX_MESSAGES). Przy limicie 2^20 prawdopodobieństwo
  kolizji to ok. 2^-57.
* Błędy deszyfrowania nie ujawniają przyczyny (jeden komunikat), żeby nie
  dawać wyroczni atakującemu.
* Python nie gwarantuje wyzerowania kluczy w pamięci; to ograniczenie języka.
* Moduł nie wydaje tokenów sesji (JWT) ani nie uwierzytelnia użytkownika;
  `session_id` jest identyfikatorem kryptograficznym, nie poświadczeniem.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
import struct
import threading
from dataclasses import dataclass, field

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from fpscanner.security.replay_guard import ReplayGuard, now_ms

PROTOCOL_VERSION = 1
KEY_LEN = 32                    # AES-256
NONCE_LEN = 12                  # 96 bit
TAG_LEN = 16
SESSION_ID_LEN = 16
RANDOM_LEN = 32
MAX_DEVICE_ID = 64
MAX_PLAINTEXT = 64 * 1024       # szablon ma kilkaset bajtów; limit chroni pamięć
MAX_MESSAGES = 1 << 20          # na sesję i kierunek
DEFAULT_SESSION_TTL_MS = 15 * 60 * 1000
_PURPOSE_RE = re.compile(r"^[a-z0-9_.-]{1,32}$")


# --------------------------------------------------------------------------- #
# Wyjątki
# --------------------------------------------------------------------------- #
class CryptoError(Exception):
    """Bazowy wyjątek warstwy kryptograficznej."""


class HandshakeError(CryptoError):
    pass


class MalformedMessage(CryptoError):
    pass


class DecryptionError(CryptoError):
    """Tag GCM nie pasuje. Celowo bez szczegółów."""


class SessionExpired(CryptoError):
    pass


class SessionExhausted(CryptoError):
    """Przekroczono limit wiadomości na sesję; trzeba zestawić nową."""


# --------------------------------------------------------------------------- #
# Narzędzia
# --------------------------------------------------------------------------- #
def hkdf_sha256(ikm: bytes, *, salt: bytes, info: bytes, length: int = KEY_LEN) -> bytes:
    """HKDF (RFC 5869) z SHA-256."""
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(ikm)


def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _b64d(s: str) -> bytes:
    if not isinstance(s, str):
        raise MalformedMessage("oczekiwano tekstu base64url")
    try:
        return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    except Exception as e:                                   # noqa: BLE001
        raise MalformedMessage("niepoprawne base64url") from e


def _lp(*fields: bytes) -> bytes:
    """Konkatenacja z prefiksem długości: brak niejednoznaczności granic pól."""
    return b"".join(struct.pack(">H", len(f)) + f for f in fields)


def _pub_bytes(key: X25519PublicKey) -> bytes:
    return key.public_bytes(Encoding.Raw, PublicFormat.Raw)


def _transcript(client_pub, server_pub, client_random, server_random,
                session_id, device_id, expires_at_ms) -> bytes:
    return b"fp-handshake/v1" + _lp(client_pub, server_pub, client_random, server_random,
                                    session_id, device_id, struct.pack(">Q", expires_at_ms))


def _derive_keys(shared: bytes, client_random: bytes, server_random: bytes,
                 transcript: bytes) -> tuple[bytes, bytes]:
    salt = client_random + server_random
    th = hashlib.sha256(transcript).digest()
    c2s = hkdf_sha256(shared, salt=salt, info=b"fp/v1 key c2s" + th)
    s2c = hkdf_sha256(shared, salt=salt, info=b"fp/v1 key s2c" + th)
    return c2s, s2c


def _need(name: str, value: bytes, length: int) -> bytes:
    if not isinstance(value, (bytes, bytearray)) or len(value) != length:
        raise MalformedMessage(f"pole {name}: oczekiwano {length} bajtów")
    return bytes(value)


# --------------------------------------------------------------------------- #
# Handshake
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class ClientHello:
    client_pub: bytes
    client_random: bytes
    device_id: bytes

    def to_dict(self) -> dict:
        return {"client_pub": _b64e(self.client_pub), "client_random": _b64e(self.client_random),
                "device_id": _b64e(self.device_id)}

    @classmethod
    def from_dict(cls, d: dict) -> ClientHello:
        try:
            return cls(_need("client_pub", _b64d(d["client_pub"]), 32),
                       _need("client_random", _b64d(d["client_random"]), RANDOM_LEN),
                       _check_device(_b64d(d["device_id"])))
        except KeyError as e:
            raise MalformedMessage(f"brak pola {e}") from e


@dataclass(frozen=True)
class ServerHello:
    server_pub: bytes
    server_random: bytes
    session_id: bytes
    expires_at_ms: int
    signature: bytes

    def to_dict(self) -> dict:
        return {"server_pub": _b64e(self.server_pub), "server_random": _b64e(self.server_random),
                "session_id": _b64e(self.session_id), "expires_at_ms": self.expires_at_ms,
                "signature": _b64e(self.signature)}

    @classmethod
    def from_dict(cls, d: dict) -> ServerHello:
        try:
            exp = d["expires_at_ms"]
            if not isinstance(exp, int) or isinstance(exp, bool) or exp < 0:
                raise MalformedMessage("niepoprawne expires_at_ms")
            return cls(_need("server_pub", _b64d(d["server_pub"]), 32),
                       _need("server_random", _b64d(d["server_random"]), RANDOM_LEN),
                       _need("session_id", _b64d(d["session_id"]), SESSION_ID_LEN),
                       exp, _need("signature", _b64d(d["signature"]), 64))
        except KeyError as e:
            raise MalformedMessage(f"brak pola {e}") from e


def _check_device(device_id: bytes) -> bytes:
    if not 1 <= len(device_id) <= MAX_DEVICE_ID:
        raise MalformedMessage(f"device_id musi mieć 1–{MAX_DEVICE_ID} bajtów")
    return device_id


@dataclass
class SessionKeys:
    """Klucze jednej strony sesji. `send_key` szyfruje, `recv_key` deszyfruje."""
    session_id: bytes
    device_id: bytes
    send_key: bytes = field(repr=False)
    recv_key: bytes = field(repr=False)
    expires_at_ms: int = 0
    _sent: int = field(default=0, repr=False, compare=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False, compare=False)


class ClientHandshake:
    """Strona klienta. `hello` wysyłamy na serwer, `finish` kończy uzgadnianie."""

    def __init__(self, device_id: bytes):
        self._device_id = _check_device(device_id)
        self._priv = X25519PrivateKey.generate()
        self._random = os.urandom(RANDOM_LEN)
        self.hello = ClientHello(_pub_bytes(self._priv.public_key()), self._random, device_id)

    def finish(self, sh: ServerHello, pinned_server_key: Ed25519PublicKey, *,
               now: int | None = None) -> SessionKeys:
        now = now_ms() if now is None else now
        transcript = _transcript(self.hello.client_pub, sh.server_pub, self.hello.client_random,
                                 sh.server_random, sh.session_id, self._device_id, sh.expires_at_ms)
        try:
            pinned_server_key.verify(sh.signature, transcript)
        except InvalidSignature as e:
            raise HandshakeError("podpis serwera nie zgadza się z zapinowanym kluczem") from e
        if sh.expires_at_ms <= now:
            raise HandshakeError("sesja zaproponowana przez serwer już wygasła")
        try:
            shared = self._priv.exchange(X25519PublicKey.from_public_bytes(sh.server_pub))
        except ValueError as e:
            raise HandshakeError("niepoprawny klucz publiczny serwera") from e
        c2s, s2c = _derive_keys(shared, self.hello.client_random, sh.server_random, transcript)
        return SessionKeys(sh.session_id, self._device_id, c2s, s2c, sh.expires_at_ms)


def server_accept(hello: ClientHello, identity_key: Ed25519PrivateKey, *,
                  ttl_ms: int = DEFAULT_SESSION_TTL_MS,
                  now: int | None = None) -> tuple[ServerHello, SessionKeys]:
    """Strona serwera: zwraca odpowiedź dla klienta i klucze sesji serwera."""
    now = now_ms() if now is None else now
    _check_device(hello.device_id)
    priv = X25519PrivateKey.generate()
    server_pub = _pub_bytes(priv.public_key())
    server_random = os.urandom(RANDOM_LEN)
    session_id = os.urandom(SESSION_ID_LEN)
    expires = now + ttl_ms
    transcript = _transcript(hello.client_pub, server_pub, hello.client_random, server_random,
                             session_id, hello.device_id, expires)
    try:
        shared = priv.exchange(X25519PublicKey.from_public_bytes(hello.client_pub))
    except ValueError as e:
        raise HandshakeError("niepoprawny klucz publiczny klienta") from e
    c2s, s2c = _derive_keys(shared, hello.client_random, server_random, transcript)
    sh = ServerHello(server_pub, server_random, session_id, expires,
                     identity_key.sign(transcript))
    return sh, SessionKeys(session_id, hello.device_id, s2c, c2s, expires)


class SessionStore:
    """Prosty magazyn sesji serwera (w pamięci, z usuwaniem wygasłych)."""

    def __init__(self):
        self._sessions: dict[bytes, SessionKeys] = {}
        self._lock = threading.Lock()

    def add(self, keys: SessionKeys) -> None:
        with self._lock:
            self._sessions[keys.session_id] = keys

    def get(self, session_id: bytes, now: int | None = None) -> SessionKeys | None:
        now = now_ms() if now is None else now
        with self._lock:
            for sid in [s for s, k in self._sessions.items() if k.expires_at_ms <= now]:
                del self._sessions[sid]
            return self._sessions.get(session_id)

    def remove(self, session_id: bytes) -> None:
        with self._lock:
            self._sessions.pop(session_id, None)


# --------------------------------------------------------------------------- #
# Wiadomości
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class SealedMessage:
    session_id: bytes
    timestamp_ms: int
    purpose: str
    nonce: bytes
    ciphertext: bytes              # szyfrogram || tag GCM (16 B)
    version: int = PROTOCOL_VERSION

    def header(self) -> bytes:
        """Jawny nagłówek; jest jednocześnie AAD dla GCM."""
        p = self.purpose.encode("ascii")
        return struct.pack(">B16sQB", self.version, self.session_id, self.timestamp_ms, len(p)) + p

    def to_bytes(self) -> bytes:
        return self.header() + self.nonce + self.ciphertext

    @classmethod
    def from_bytes(cls, data: bytes) -> SealedMessage:
        fixed = struct.calcsize(">B16sQB")
        if len(data) < fixed + 1 + NONCE_LEN + TAG_LEN or len(data) > MAX_PLAINTEXT + 256:
            raise MalformedMessage("niepoprawna długość wiadomości")
        ver, sid, ts, plen = struct.unpack_from(">B16sQB", data)
        end = fixed + plen
        if plen == 0 or len(data) < end + NONCE_LEN + TAG_LEN:
            raise MalformedMessage("niepoprawny nagłówek")
        try:
            purpose = data[fixed:end].decode("ascii")
        except UnicodeDecodeError as e:
            raise MalformedMessage("niepoprawny cel wiadomości") from e
        if not _PURPOSE_RE.match(purpose):
            raise MalformedMessage("niepoprawny cel wiadomości")
        return cls(sid, ts, purpose, data[end:end + NONCE_LEN], data[end + NONCE_LEN:], ver)

    def to_dict(self) -> dict:
        return {"v": self.version, "sid": _b64e(self.session_id), "ts": self.timestamp_ms,
                "purpose": self.purpose, "nonce": _b64e(self.nonce), "ct": _b64e(self.ciphertext)}

    @classmethod
    def from_dict(cls, d: dict) -> SealedMessage:
        try:
            ts, ver, purpose = d["ts"], d["v"], d["purpose"]
            if (not isinstance(ts, int) or isinstance(ts, bool) or ts < 0
                    or not isinstance(ver, int) or not isinstance(purpose, str)
                    or not _PURPOSE_RE.match(purpose)):
                raise MalformedMessage("niepoprawne pola nagłówka")
            ct = _b64d(d["ct"])
            if len(ct) < TAG_LEN or len(ct) > MAX_PLAINTEXT + TAG_LEN:
                raise MalformedMessage("niepoprawna długość szyfrogramu")
            return cls(_need("sid", _b64d(d["sid"]), SESSION_ID_LEN), ts, purpose,
                       _need("nonce", _b64d(d["nonce"]), NONCE_LEN), ct, ver)
        except KeyError as e:
            raise MalformedMessage(f"brak pola {e}") from e


def seal(keys: SessionKeys, plaintext: bytes, purpose: str, *,
         now: int | None = None) -> SealedMessage:
    """Szyfruje `plaintext` (np. template_to_bytes(...)) kluczem wysyłającym."""
    now = now_ms() if now is None else now
    if not _PURPOSE_RE.match(purpose):
        raise ValueError("purpose: 1–32 znaków [a-z0-9_.-]")
    if len(plaintext) > MAX_PLAINTEXT:
        raise ValueError("zbyt duża wiadomość")
    if now >= keys.expires_at_ms:
        raise SessionExpired("sesja wygasła")
    with keys._lock:
        if keys._sent >= MAX_MESSAGES:
            raise SessionExhausted("limit wiadomości na sesję; zestaw nową sesję")
        keys._sent += 1
    nonce = os.urandom(NONCE_LEN)
    msg = SealedMessage(keys.session_id, now, purpose, nonce, b"")
    ct = AESGCM(keys.send_key).encrypt(nonce, plaintext, msg.header())
    return SealedMessage(keys.session_id, now, purpose, nonce, ct)


def open_message(keys: SessionKeys, msg: SealedMessage, guard: ReplayGuard, *,
                 expected_purpose: str | None = None, now: int | None = None) -> bytes:
    """
    Odbiór wiadomości. Kolejność kontroli (od najtańszej):
    wersja/sesja -> ważność sesji -> okno czasowe -> tag GCM -> nonce jednorazowy.
    Rzuca CryptoError albo replay_guard.ReplayError.
    """
    now = now_ms() if now is None else now
    if msg.version != PROTOCOL_VERSION:
        raise MalformedMessage("nieobsługiwana wersja protokołu")
    if not hmac.compare_digest(msg.session_id, keys.session_id):
        raise MalformedMessage("wiadomość z innej sesji")
    if now >= keys.expires_at_ms:
        raise SessionExpired("sesja wygasła")
    guard.check_timestamp(msg.timestamp_ms, now)
    try:
        plaintext = AESGCM(keys.recv_key).decrypt(msg.nonce, msg.ciphertext, msg.header())
    except InvalidTag:
        raise DecryptionError("uwierzytelnienie wiadomości nie powiodło się") from None
    if expected_purpose is not None and msg.purpose != expected_purpose:
        raise MalformedMessage("nieoczekiwany cel wiadomości")
    guard.claim_nonce(msg.session_id, msg.nonce, now)
    return plaintext
