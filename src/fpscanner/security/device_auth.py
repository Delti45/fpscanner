#!/usr/bin/env python3
"""
Uwierzytelnianie urządzeń (czytników): rejestr, odciski certyfikatów, dowód
posiadania sekretu oraz bezpieczne ustalanie adresu i certyfikatu klienta
za reverse proxy.

Trzy niezależne czynniki (konfigurowane przez `DevicePolicy`):
  * mTLS  – certyfikat klienta zweryfikowany przez TLS/proxy; serwer porównuje
            jego odcisk SHA-256 z odciskiem zapisanym w rejestrze urządzeń;
  * dowód – HMAC-SHA256 po sekrecie urządzenia, liczony z pól handshake'u
            (device_id, klucz efemeryczny, losowość klienta, znacznik czasu).
            Podmiana któregokolwiek pola unieważnia dowód, a jednorazowość
            zapewnia nonce (client_random) zajmowany w ReplayGuard;
  * TOTP  – jednorazowy kod zależny od czasu (RFC 6238) z OSOBNEGO sekretu urządzenia;
            weryfikowany względem zegara serwera, więc sprawdza też synchronizację czasu.
            Tutaj kod tylko się weryfikuje (bezstanowo); jednorazowość egzekwuje
            `totp.TotpReplayTracker` w serwisie, po zajęciu nonce'a handshake'u.
Polityka musi wymagać przynajmniej jednego czynnika. Czynnik, który został przedstawiony,
jest zawsze weryfikowany, nawet gdy polityka go nie wymaga.

Zaufanie do nagłówków: odcisk certyfikatu i adres klienta przekazane przez
proxy (np. `X-Client-Cert-Fingerprint`, `X-Forwarded-For`) są uwzględniane
WYŁĄCZNIE, gdy połączenie przyszło z adresu zaufanego proxy
(`NetworkTrust.trusted_proxies`). Proxy musi nadpisywać te nagłówki (nie
dopisywać) i usuwać wartości podane przez klienta; inaczej klient mógłby
podszyć się pod dowolne urządzenie.

Moduł zależy od biblioteki standardowej; `cryptography` jest użyta tylko do sprawdzenia,
że certyfikat z nagłówka proxy jest poprawnym X.509.
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import re
import ssl
import struct
import threading
import urllib.parse
from collections.abc import Mapping
from dataclasses import dataclass, field, replace

from fpscanner.security import totp as _totp

PERMISSIONS = frozenset({"enroll", "verify", "erase"})
DEFAULT_PERMISSIONS = frozenset({"enroll", "verify"})     # kasowanie tylko jawnie nadane
MIN_SECRET_LEN = 32

_FP_HEX_LEN = {"sha256": 64, "sha1": 40}
_FP_PREFIX = re.compile(r"^(sha256|sha1)[:=](.*)$")
_HEX = re.compile(r"^[0-9a-f]+$")
_STORED_FP = re.compile(r"^[a-z0-9]+:[0-9a-f]+$")
_PROOF_LABEL = b"fp-device-proof/v1"


class DeviceAuthError(Exception):
    """Uwierzytelnienie urządzenia nie powiodło się (bez wskazywania przyczyny)."""


# --------------------------------------------------------------------------- #
# Odciski certyfikatów i adresy
# --------------------------------------------------------------------------- #
def fingerprint_der(der: bytes) -> str:
    """Odcisk SHA-256 certyfikatu w DER: 'sha256:<64 znaki hex>'."""
    return "sha256:" + hashlib.sha256(der).hexdigest()


def fingerprint_pem(pem: str | bytes) -> str:
    """Odcisk certyfikatu podanego jako PEM. ValueError, gdy to nie jest PEM."""
    if isinstance(pem, bytes):
        pem = pem.decode("ascii", errors="strict")
    return fingerprint_der(ssl.PEM_cert_to_DER_cert(pem))


def normalize_fingerprint(value: str) -> str:
    """
    Sprowadza odcisk do postaci 'algorytm:hex' (małe litery). Akceptuje
    'ab12..', 'AB:12:..', 'SHA256=ab12..', 'sha256:ab12..', 'sha1:..'.
    Bez prefiksu zakładany jest SHA-256. ValueError przy złym formacie/długości.
    """
    if not isinstance(value, str):
        raise ValueError("odcisk musi być tekstem")
    s = value.strip().lower()
    algo = None
    m = _FP_PREFIX.match(s)
    if m:
        algo, s = m.group(1), m.group(2)
    s = s.replace(":", "").replace(" ", "")
    if not s or not _HEX.match(s):
        raise ValueError("odcisk certyfikatu musi być zapisem szesnastkowym")
    algo = algo or "sha256"
    if len(s) != _FP_HEX_LEN[algo]:
        raise ValueError(f"odcisk {algo} musi mieć {_FP_HEX_LEN[algo]} znaków hex")
    return f"{algo}:{s}"


def fingerprint_from_asgi_tls(tls_ext: Mapping | None) -> str | None:
    """
    Odcisk certyfikatu klienta z rozszerzenia ASGI `tls` (scope["extensions"]["tls"]),
    gdy serwer ASGI sam terminuje TLS. None, gdy brak lub niepoprawny certyfikat.
    """
    try:
        chain = tls_ext.get("client_cert_chain") if tls_ext else None
        if not chain:
            return None
        return fingerprint_pem(chain[0])
    except (ValueError, TypeError, AttributeError, UnicodeError):
        return None


def fingerprint_from_header(raw: str) -> str:
    """
    Odcisk z wartości nagłówka ustawionego przez proxy. Dwie postaci:
      * gotowy odcisk ('sha256:ab12..', 'AB:12:..'),
      * cały certyfikat PEM zakodowany procentowo (nginx: $ssl_client_escaped_cert);
        SHA-256 liczymy wtedy sami. nginx nie ma wbudowanego SHA-256 certyfikatu
        (jego $ssl_client_fingerprint to SHA-1), a ta droga nie wymaga skryptów.
    ValueError przy każdym błędzie.
    """
    if not isinstance(raw, str) or len(raw) > 16_384:
        raise ValueError("niepoprawny nagłówek z certyfikatem")
    value = raw.strip()
    decoded = urllib.parse.unquote(value)
    if decoded.lstrip().startswith("-----BEGIN CERTIFICATE-----"):
        pem = decoded.strip()
        from cryptography import x509  # tylko tu: sprawdzamy, że to prawdziwy certyfikat
        try:
            x509.load_pem_x509_certificate(pem.encode("ascii"))
        except (ValueError, UnicodeEncodeError):
            raise ValueError("nagłówek nie zawiera poprawnego certyfikatu") from None
        return fingerprint_pem(pem)
    return normalize_fingerprint(value)


def normalize_ip(value) -> str | None:
    """Poprawny adres IP w postaci kanonicznej (IPv4-mapped IPv6 -> IPv4) albo None."""
    if not isinstance(value, str):
        return None
    try:
        ip = ipaddress.ip_address(value.strip().split("%")[0])
    except ValueError:
        return None
    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return str(ip)


def _canon_stored(fp: str) -> str:
    """Postać porównywalna: małe litery, bez spacji; wymagany format 'algorytm:hex'."""
    s = fp.strip().lower()
    if not _STORED_FP.match(s):
        raise ValueError("odcisk musi mieć postać 'algorytm:hex'")
    return s


def _eq(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


# --------------------------------------------------------------------------- #
# Dowód posiadania sekretu
# --------------------------------------------------------------------------- #
def _lp(*fields: bytes) -> bytes:
    return b"".join(struct.pack(">H", len(f)) + f for f in fields)


def device_proof(secret: bytes, *, device_id: str, client_pub: bytes, client_random: bytes,
                 timestamp_ms: int) -> bytes:
    """HMAC-SHA256 (32 B) wiążący sekret urządzenia ze wszystkimi polami handshake'u."""
    msg = _PROOF_LABEL + _lp(device_id.encode("utf-8"), client_pub, client_random,
                             struct.pack(">Q", timestamp_ms))
    return hmac.new(secret, msg, hashlib.sha256).digest()


# --------------------------------------------------------------------------- #
# Polityka i rejestr
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class DevicePolicy:
    require_mtls: bool = True
    require_proof: bool = True
    require_totp: bool = False         # biblioteka: wyłączone; serwer (FP_REQUIRE_TOTP) włącza domyślnie

    def __post_init__(self):
        if not (self.require_mtls or self.require_proof or self.require_totp):
            raise ValueError("polityka musi wymagać mTLS, dowodu posiadania sekretu lub TOTP")


@dataclass(frozen=True)
class DeviceRecord:
    device_id: str
    secret: bytes = field(repr=False)
    cert_fingerprint: str | None = None
    permissions: frozenset = DEFAULT_PERMISSIONS
    revoked: bool = False
    totp_secret: bytes | None = field(default=None, repr=False)

    def allows(self, permission: str) -> bool:
        return permission in self.permissions


class InMemoryDeviceRegistry:
    """
    Rejestr urządzeń w pamięci (bezpieczny wątkowo). `revoke` działa natychmiast:
    kolejne żądania z tokenem tego urządzenia są odrzucane.
    Na produkcji sekrety urządzeń należy trzymać w Vault/HSM, nie w bazie aplikacji.
    """

    def __init__(self):
        self._devices: dict[str, DeviceRecord] = {}
        self._lock = threading.Lock()

    def register(self, device_id: str, *, secret: bytes, cert_fingerprint: str | None = None,
                 permissions=None, totp_secret: bytes | None = None) -> DeviceRecord:
        if not isinstance(device_id, str) or not 1 <= len(device_id.encode("utf-8")) <= 64:
            raise ValueError("device_id musi mieć 1–64 bajtów")
        if not isinstance(secret, (bytes, bytearray)) or len(secret) < MIN_SECRET_LEN:
            raise ValueError(f"sekret urządzenia musi mieć co najmniej {MIN_SECRET_LEN} bajtów")
        perms = frozenset(DEFAULT_PERMISSIONS if permissions is None else permissions)
        if not perms <= PERMISSIONS:
            raise ValueError(f"nieznane uprawnienia: {sorted(perms - PERMISSIONS)}")
        if totp_secret is not None:
            if not isinstance(totp_secret, (bytes, bytearray)) or len(totp_secret) < _totp.MIN_SECRET_LEN:
                raise ValueError(f"sekret TOTP musi mieć co najmniej {_totp.MIN_SECRET_LEN} bajtów")
            if bytes(totp_secret) == bytes(secret):
                raise ValueError("sekret TOTP musi różnić się od sekretu dowodu (dwa niezależne czynniki)")
        fp = _canon_stored(cert_fingerprint) if cert_fingerprint else None
        rec = DeviceRecord(device_id, bytes(secret), fp, perms,
                           totp_secret=None if totp_secret is None else bytes(totp_secret))
        with self._lock:
            if device_id in self._devices:
                raise ValueError(f"urządzenie {device_id!r} jest już zarejestrowane")
            self._devices[device_id] = rec
        return rec

    def get(self, device_id: str) -> DeviceRecord | None:
        with self._lock:
            return self._devices.get(device_id)

    def revoke(self, device_id: str) -> None:
        with self._lock:
            rec = self._devices.get(device_id)
            if rec is not None:
                self._devices[device_id] = replace(rec, revoked=True)

    def __len__(self) -> int:
        with self._lock:
            return len(self._devices)


def check_device_binding(record: DeviceRecord | None, policy: DevicePolicy,
                         presented_fingerprint: str | None) -> None:
    """
    Sprawdza rekord i certyfikat. Wykonywane przy handshake'u ORAZ przy każdym
    żądaniu z tokenem (unieważnienie urządzenia działa natychmiast).
    Certyfikat, który został przedstawiony, musi zawsze pasować do rejestru –
    także wtedy, gdy polityka go nie wymaga.
    """
    if record is None or record.revoked:
        raise DeviceAuthError("uwierzytelnienie urządzenia nie powiodło się")
    presented = None
    if presented_fingerprint:
        try:
            presented = _canon_stored(presented_fingerprint)
        except ValueError:
            raise DeviceAuthError("uwierzytelnienie urządzenia nie powiodło się") from None
    if policy.require_mtls and presented is None:
        raise DeviceAuthError("uwierzytelnienie urządzenia nie powiodło się")
    if presented is not None:
        if record.cert_fingerprint is None or not _eq(presented, record.cert_fingerprint):
            raise DeviceAuthError("uwierzytelnienie urządzenia nie powiodło się")


def authenticate_device(record: DeviceRecord | None, policy: DevicePolicy, *,
                        proof: bytes | None, cert_fingerprint: str | None, device_id: str,
                        client_pub: bytes, client_random: bytes, timestamp_ms: int,
                        totp_code: str | None = None, now_s: int | None = None,
                        totp_config: _totp.TotpConfig = _totp.DEFAULT) -> int | None:
    """
    Pełne uwierzytelnienie w handshake'u: certyfikat + (wymagany) dowód HMAC + (wymagany) TOTP.
    Zwraca numer kroku TOTP, z którego pochodzi przyjęty kod (albo None, gdy kodu nie podano);
    wywołujący musi go zużyć w `TotpReplayTracker`, żeby kod był jednorazowy.
    `now_s` to czas SERWERA w sekundach (nie znacznik z wiadomości klienta): tylko wtedy kod
    sprawdza synchronizację zegara urządzenia.
    """
    secret = record.secret if record is not None else b"\x00" * MIN_SECRET_LEN
    expected = device_proof(secret, device_id=device_id, client_pub=client_pub,
                            client_random=client_random, timestamp_ms=timestamp_ms)
    check_device_binding(record, policy, cert_fingerprint)
    if proof is None:
        if policy.require_proof:
            raise DeviceAuthError("uwierzytelnienie urządzenia nie powiodło się")
    elif not hmac.compare_digest(expected, proof):        # dowód podany: zawsze weryfikowany
        raise DeviceAuthError("uwierzytelnienie urządzenia nie powiodło się")

    if totp_code is None:
        if policy.require_totp:
            raise DeviceAuthError("uwierzytelnienie urządzenia nie powiodło się")
        return None
    if now_s is None or record is None or record.totp_secret is None:
        raise DeviceAuthError("uwierzytelnienie urządzenia nie powiodło się")
    counter = _totp.verify_totp(record.totp_secret, totp_code, now_s, totp_config)   # podany: zawsze
    if counter is None:
        raise DeviceAuthError("uwierzytelnienie urządzenia nie powiodło się")
    return counter


# --------------------------------------------------------------------------- #
# Zaufane proxy: adres klienta i certyfikat z nagłówków
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class NetworkTrust:
    trusted_proxies: tuple = ()                    # adresy lub sieci CIDR, np. ("10.0.0.0/8",)
    cert_header: str = "x-client-cert-fingerprint"
    verify_header: str | None = None               # np. "x-client-cert-verify" (nginx $ssl_client_verify)
    verify_value: str = "SUCCESS"
    forwarded_header: str = "x-forwarded-for"

    def __post_init__(self):
        nets = tuple(ipaddress.ip_network(p, strict=False) for p in self.trusted_proxies)
        object.__setattr__(self, "_nets", nets)

    def is_trusted(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in net for net in self._nets)


def resolve_client(peer_ip: str | None, headers: Mapping[str, str],
                   trust: NetworkTrust) -> tuple[str | None, str | None]:
    """
    Zwraca (adres_klienta, odcisk_certyfikatu). Nagłówki są brane pod uwagę tylko
    od zaufanego proxy. X-Forwarded-For czytamy od prawej: pomijamy kolejne
    zaufane hopy, pierwszy niezaufany adres to klient (wpisy po lewej mógł
    sfałszować klient i są ignorowane). Nieczytelny wpis => adres nieznany (None).
    Nagłówek z certyfikatem może zawierać gotowy odcisk albo cały certyfikat
    PEM (patrz `fingerprint_from_header`).
    """
    peer = normalize_ip(peer_ip)
    if peer is None or not trust.is_trusted(peer):
        return peer, None
    hdr = {str(k).lower(): v for k, v in headers.items()}
    client: str | None = peer
    xff = hdr.get(trust.forwarded_header.lower())
    if xff:
        hops = [h.strip() for h in xff.split(",") if h.strip()]
        for hop in reversed(hops):
            ip = normalize_ip(hop)
            if ip is None:
                client = None
                break
            client = ip
            if not trust.is_trusted(ip):
                break
    fingerprint = None
    verified = True
    if trust.verify_header:
        verified = hdr.get(trust.verify_header.lower()) == trust.verify_value
    raw = hdr.get(trust.cert_header.lower())
    if verified and raw:
        try:
            fingerprint = fingerprint_from_header(raw)
        except ValueError:
            fingerprint = None
    return client, fingerprint
