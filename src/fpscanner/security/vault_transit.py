#!/usr/bin/env python3
"""
Adapter `KeyProvider` do HashiCorp Vault (silnik Transit): KEK nigdy nie opuszcza Vaulta.

Mapowanie na protokół `KeyProvider` z `template_vault`:
  * wrap(dek, aad)         -> POST transit/encrypt/<klucz>  (plaintext = DEK, context = AAD)
  * unwrap(kek_id, w, aad) -> POST transit/decrypt/<klucz>
  * current_kek_id()       -> GET  transit/keys/<klucz>     (latest_version, z krótkim cache)

Identyfikator KEK-a w rekordzie to `<klucz>:v<wersja>` (np. `fp-kek:v3`), a „opakowany DEK”
to pełny szyfrogram Transit (`vault:v3:...`). Dzięki temu rotacja wygląda tak samo jak dla
`LocalKeyProvider`: po `vault write -f transit/keys/fp-kek/rotate` bieżący id zmienia się na `:v4`,
a skrypt rotacji dopakowuje rekordy, które mają starszy id.

AAD trafia do Transit jako `context`. Działa to jako wiązanie kryptograficzne WYŁĄCZNIE dla
kluczy z `derived=true`; dla kluczy zwykłych Vault po cichu ignoruje `context`. Dlatego
konstruktor odczytuje opis klucza i odmawia pracy z kluczem niespełniającym wymagań:

    vault write transit/keys/fp-kek type=aes256-gcm96 derived=true

Awarie infrastruktury (sieć, 5xx, brak uprawnień, brak klucza) kończą się
`KeyProviderUnavailable`; błędy danych (zły szyfrogram/kontekst) to `ValueError`, które
`decrypt_template` zamienia na `VaultError`. Tokeny, DEK-i i szyfrogramy nie trafiają do komunikatów.

Uwierzytelnianie: token statyczny albo plik z tokenem (np. sink Vault Agent z AppRole; plik jest
czytany ponownie po odpowiedzi 403, więc odnowiony token zadziała bez restartu). Minimalna polityka:

    path "transit/encrypt/fp-kek" { capabilities = ["update"] }
    path "transit/decrypt/fp-kek" { capabilities = ["update"] }
    path "transit/keys/fp-kek"    { capabilities = ["read"] }
"""
from __future__ import annotations

import base64
import http.client
import json
import logging
import re
import ssl
import threading
import time
from urllib.parse import quote, urlsplit

from fpscanner.security.template_vault import KEY_LEN, KeyProviderUnavailable

log = logging.getLogger("fp.vault")

_CT_VERSION = re.compile(rb"^vault:v(\d+):")


class VaultTransitKeyProvider:
    def __init__(self, addr: str, key_name: str = "fp-kek", *,
                 token: str | None = None, token_file: str | None = None,
                 mount: str = "transit", namespace: str | None = None,
                 ca_cert: str | None = None, timeout_s: float = 5.0, retries: int = 2,
                 allow_insecure_http: bool = False, key_info_ttl_s: float = 30.0,
                 check_key: bool = True, clock=time.monotonic):
        if (token is None) == (token_file is None):
            raise ValueError("podaj dokładnie jedno z: token, token_file")
        u = urlsplit(addr)
        if u.scheme not in ("http", "https") or not u.hostname:
            raise ValueError("adres Vaulta musi być w postaci http(s)://host[:port]")
        if u.scheme == "http" and not allow_insecure_http:
            raise ValueError("Vault przez zwykłe HTTP jest dozwolony tylko jawnie "
                             "(allow_insecure_http=True, wyłącznie środowisko deweloperskie)")
        if not re.fullmatch(r"[A-Za-z0-9._-]+", key_name) or not re.fullmatch(r"[A-Za-z0-9._/-]+", mount):
            raise ValueError("niepoprawna nazwa klucza lub ścieżka silnika Transit")
        self._scheme, self._host, self._port = u.scheme, u.hostname, u.port
        self._key, self._mount = key_name, mount.strip("/")
        self._token = token
        self._token_file = token_file
        self._namespace = namespace
        self._timeout, self._retries = timeout_s, max(0, retries)
        self._ssl = ssl.create_default_context(cafile=ca_cert) if u.scheme == "https" else None
        self._tls = threading.local()                # jedno trwałe połączenie na wątek
        self._ttl, self._clock = key_info_ttl_s, clock
        self._cached: tuple[float, int] | None = None
        self._lock = threading.Lock()
        if token_file is not None:
            self._token = self._read_token_file()
        if check_key:
            self.check_key()

    # ------------------------------------------------------------------ #
    # KeyProvider
    # ------------------------------------------------------------------ #
    def current_kek_id(self) -> str:
        return f"{self._key}:v{self._latest_version()}"

    def wrap(self, dek: bytes, aad: bytes) -> tuple[str, bytes]:
        data = self._call("POST", f"encrypt/{self._key}", {
            "plaintext": base64.b64encode(dek).decode("ascii"),
            "context": base64.b64encode(aad).decode("ascii")})
        try:
            ct = str(data["ciphertext"]).encode("ascii")
            version = int(_CT_VERSION.match(ct).group(1))
        except (KeyError, AttributeError, ValueError):
            raise KeyProviderUnavailable("Vault zwrócił nieoczekiwaną odpowiedź na encrypt") from None
        return f"{self._key}:v{version}", ct

    def unwrap(self, kek_id: str, wrapped: bytes, aad: bytes) -> bytes:
        m = _CT_VERSION.match(wrapped)
        if m is None or kek_id != f"{self._key}:v{int(m.group(1))}":
            raise KeyError(kek_id)                    # nagłówek rekordu nie zgadza się z szyfrogramem/kluczem
        data = self._call("POST", f"decrypt/{self._key}", {
            "ciphertext": wrapped.decode("ascii"),    # UnicodeDecodeError jest ValueError
            "context": base64.b64encode(aad).decode("ascii")}, data_errors=True)
        try:
            dek = base64.b64decode(data["plaintext"], validate=True)
        except (KeyError, ValueError):
            raise KeyProviderUnavailable("Vault zwrócił nieoczekiwaną odpowiedź na decrypt") from None
        if len(dek) != KEY_LEN:
            raise ValueError("DEK ma niepoprawną długość")
        return dek

    # ------------------------------------------------------------------ #
    # Weryfikacja klucza
    # ------------------------------------------------------------------ #
    def check_key(self) -> None:
        """Fail-closed: klucz musi istnieć, być AES-256-GCM i mieć derived=true."""
        info = self._call("GET", f"keys/{self._key}")
        problems = []
        if info.get("type") != "aes256-gcm96":
            problems.append(f"typ {info.get('type')!r} zamiast 'aes256-gcm96'")
        if info.get("derived") is not True:
            problems.append("brak derived=true (Vault ignorowałby `context`, czyli AAD)")
        if not (info.get("supports_encryption") and info.get("supports_decryption")):
            problems.append("klucz nie obsługuje szyfrowania/deszyfrowania")
        if problems:
            raise ValueError(f"klucz Transit {self._key!r} jest nieodpowiedni: " + "; ".join(problems))
        self._remember(int(info["latest_version"]))

    def _latest_version(self) -> int:
        with self._lock:
            if self._cached and self._clock() - self._cached[0] < self._ttl:
                return self._cached[1]
        info = self._call("GET", f"keys/{self._key}")
        try:
            return self._remember(int(info["latest_version"]))
        except (KeyError, ValueError):
            raise KeyProviderUnavailable("Vault zwrócił nieoczekiwany opis klucza") from None

    def _remember(self, version: int) -> int:
        with self._lock:
            self._cached = (self._clock(), version)
        return version

    # ------------------------------------------------------------------ #
    # HTTP
    # ------------------------------------------------------------------ #
    def _read_token_file(self) -> str:
        try:
            with open(self._token_file, encoding="ascii") as f:
                token = f.read().strip()
        except (OSError, UnicodeDecodeError):
            raise KeyProviderUnavailable("nie można odczytać pliku z tokenem Vaulta") from None
        if not token:
            raise KeyProviderUnavailable("plik z tokenem Vaulta jest pusty")
        return token

    def _connection(self) -> http.client.HTTPConnection:
        conn = getattr(self._tls, "conn", None)
        if conn is None:
            if self._scheme == "https":
                conn = http.client.HTTPSConnection(self._host, self._port, timeout=self._timeout,
                                                   context=self._ssl)
            else:
                conn = http.client.HTTPConnection(self._host, self._port, timeout=self._timeout)
            self._tls.conn = conn
        return conn

    def _drop_connection(self) -> None:
        conn = getattr(self._tls, "conn", None)
        self._tls.conn = None
        if conn is not None:
            conn.close()

    def _call(self, method: str, path: str, body: dict | None = None, *,
              data_errors: bool = False) -> dict:
        """
        Zwraca pole `data` odpowiedzi. 400 -> ValueError (tylko gdy `data_errors`, czyli dla
        decrypt: zły szyfrogram/kontekst); pozostałe niepowodzenia -> KeyProviderUnavailable.
        """
        url = f"/v1/{self._mount}/{quote(path, safe='/')}"
        payload = None if body is None else json.dumps(body).encode()
        refreshed = False
        last = "brak odpowiedzi"
        attempt = -1
        while attempt < self._retries:
            attempt += 1
            headers = {"X-Vault-Token": self._token, "Accept": "application/json"}
            if payload is not None:
                headers["Content-Type"] = "application/json"
            if self._namespace:
                headers["X-Vault-Namespace"] = self._namespace
            try:
                conn = self._connection()
                conn.request(method, url, body=payload, headers=headers)
                resp = conn.getresponse()
                raw = resp.read()
                status = resp.status
            except (OSError, http.client.HTTPException) as e:        # sieć, TLS, timeout
                self._drop_connection()
                last = type(e).__name__
                time.sleep(0.05 * (2 ** attempt))
                continue
            if status == 200:
                try:
                    return json.loads(raw)["data"]
                except (ValueError, KeyError, TypeError):
                    raise KeyProviderUnavailable("Vault zwrócił niepoprawny JSON") from None
            if status == 400 and data_errors:
                raise ValueError("Vault odrzucił szyfrogram lub kontekst")
            if status == 403 and self._token_file and not refreshed:
                refreshed = True                                     # token mógł zostać odnowiony
                self._token = self._read_token_file()
                attempt -= 1                                         # odświeżenie nie zużywa próby
                continue
            if status in (429, 500, 502, 503, 504):
                self._drop_connection()
                last = f"HTTP {status}"
                time.sleep(0.05 * (2 ** attempt))
                continue
            log.error("Vault %s %s -> HTTP %s", method, path, status)
            raise KeyProviderUnavailable(f"Vault odpowiedział HTTP {status} "
                                         "(uprawnienia, brak klucza albo błąd konfiguracji)")
        log.error("Vault %s %s niedostępny: %s", method, path, last)
        raise KeyProviderUnavailable(f"Vault niedostępny ({last})")

    def close(self) -> None:
        self._drop_connection()
