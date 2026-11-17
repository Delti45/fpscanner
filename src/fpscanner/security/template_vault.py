#!/usr/bin/env python3
"""
Szyfrowanie szablonów biometrycznych w spoczynku (w bazie danych).

Schemat „envelope encryption":
  * każdy rekord dostaje własny, losowy klucz danych DEK (AES-256),
  * szablon jest szyfrowany DEK-iem (AES-256-GCM, losowy nonce 96 bit),
  * DEK jest „opakowany" (zaszyfrowany) kluczem głównym KEK, który nigdy nie
    opuszcza dostawcy kluczy (HSM / HashiCorp Vault Transit). W bazie leży
    tylko: identyfikator KEK-a, opakowany DEK, nonce i szyfrogram.

Dlaczego tak:
  * rotacja KEK-a = ponowne opakowanie samych DEK-ów (`rewrap`), bez
    deszyfrowania szablonów ani dotykania szyfrogramu;
  * AAD wiąże rekord z osobą (`subject_id`): przeniesienie zaszyfrowanego
    szablonu jednej osoby do rekordu innej kończy się błędem tagu;
  * „prawo do usunięcia" (RODO) można spełnić też przez usunięcie
    opakowanego DEK-a (crypto-shredding), ale to nie zastępuje usunięcia
    rekordu z kopii zapasowych zgodnie z polityką retencji.

Dostawcę kluczy opisuje protokół `KeyProvider`. `LocalKeyProvider` służy do
rozwoju i testów (klucze w pamięci/zmiennych środowiskowych). Na produkcji
służy `VaultTransitKeyProvider` (fpscanner.security.vault_transit): `wrap`/`unwrap`
mapują się na encrypt/decrypt w Transit, a KEK nie opuszcza Vaulta.

Format rekordu (big-endian):
    "FPT" | wersja:u8 | len_kek_id:u8 | kek_id | len_wrapped:u16 | wrapped_dek
          | nonce:12 B | szyfrogram+tag
"""
from __future__ import annotations

import base64
import os
import struct
from typing import Protocol

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"FPT"
RECORD_VERSION = 1
KEY_LEN = 32
NONCE_LEN = 12
_DATA_CONTEXT = b"fp-template/v1"


class VaultError(Exception):
    """Błąd odczytu/zapisu zaszyfrowanego rekordu (bez szczegółów kryptograficznych)."""


class KeyProviderUnavailable(Exception):
    """
    Dostawca kluczy (np. Vault) jest nieosiągalny albo odmawia dostępu z powodu konfiguracji.
    To awaria infrastruktury, nie błąd danych: wywołujący ma zwrócić 503 i NIE traktować jej
    jak uszkodzonego rekordu (`VaultError`) ani jak nieudanej próby weryfikacji.
    """


class KeyProvider(Protocol):
    def current_kek_id(self) -> str:
        """Identyfikator klucza używanego do nowych opakowań."""

    def wrap(self, dek: bytes, aad: bytes) -> tuple[str, bytes]:
        """Zwraca (kek_id, opakowany DEK)."""

    def unwrap(self, kek_id: str, wrapped: bytes, aad: bytes) -> bytes:
        """Zwraca DEK; rzuca wyjątek przy złym kluczu lub zmanipulowanych danych."""


class LocalKeyProvider:
    """
    Dostawca kluczy do ROZWOJU i testów: KEK-i trzymane w pamięci procesu.
    Opakowanie to AES-256-GCM z losowym nonce (nonce||szyfrogram).
    """

    def __init__(self, keys: dict[str, bytes], current: str):
        for kid, k in keys.items():
            if len(k) != KEY_LEN:
                raise ValueError(f"KEK {kid!r} musi mieć {KEY_LEN} bajtów")
        if current not in keys:
            raise ValueError("`current` musi wskazywać istniejący KEK")
        self._keys = dict(keys)
        self._current = current

    @classmethod
    def generate(cls, kek_id: str = "kek-1") -> LocalKeyProvider:
        return cls({kek_id: AESGCM.generate_key(256)}, kek_id)

    @classmethod
    def from_env(cls, current: str, prefix: str = "FP_KEK_") -> LocalKeyProvider:
        """Wczytuje klucze ze zmiennych FP_KEK_<id> (base64url, 32 bajty)."""
        keys = {}
        for name, value in os.environ.items():
            if name.startswith(prefix):
                raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
                keys[name[len(prefix):].lower()] = raw
        return cls(keys, current)

    def add_key(self, kek_id: str, key: bytes, make_current: bool = False) -> None:
        if len(key) != KEY_LEN:
            raise ValueError(f"KEK musi mieć {KEY_LEN} bajtów")
        self._keys[kek_id] = key
        if make_current:
            self._current = kek_id

    def remove_key(self, kek_id: str) -> None:
        if kek_id == self._current:
            raise ValueError("nie można usunąć bieżącego KEK-a")
        self._keys.pop(kek_id, None)

    def current_kek_id(self) -> str:
        return self._current

    def wrap(self, dek: bytes, aad: bytes) -> tuple[str, bytes]:
        nonce = os.urandom(NONCE_LEN)
        return self._current, nonce + AESGCM(self._keys[self._current]).encrypt(nonce, dek, aad)

    def unwrap(self, kek_id: str, wrapped: bytes, aad: bytes) -> bytes:
        if kek_id not in self._keys:
            raise KeyError(kek_id)
        return AESGCM(self._keys[kek_id]).decrypt(wrapped[:NONCE_LEN], wrapped[NONCE_LEN:], aad)


# --------------------------------------------------------------------------- #
# Rekordy
# --------------------------------------------------------------------------- #
def _lp(b: bytes) -> bytes:
    return struct.pack(">H", len(b)) + b


def _aad(subject_id: str) -> bytes:
    """Kontekst wiążący szyfrogram z osobą."""
    return _DATA_CONTEXT + _lp(subject_id.encode("utf-8"))


def _wrap_aad(subject_id: str) -> bytes:
    return _aad(subject_id) + b"/dek"


def _pack(kek_id: str, wrapped: bytes, nonce: bytes, ct: bytes) -> bytes:
    kid = kek_id.encode("ascii")
    return (MAGIC + struct.pack(">BB", RECORD_VERSION, len(kid)) + kid
            + struct.pack(">H", len(wrapped)) + wrapped + nonce + ct)


def _unpack(record: bytes) -> tuple[str, bytes, bytes, bytes]:
    try:
        if record[:3] != MAGIC:
            raise VaultError("to nie jest rekord szablonu")
        ver, klen = struct.unpack_from(">BB", record, 3)
        if ver != RECORD_VERSION:
            raise VaultError("nieobsługiwana wersja rekordu")
        pos = 5
        kek_id = record[pos:pos + klen].decode("ascii")
        pos += klen
        (wlen,) = struct.unpack_from(">H", record, pos)
        pos += 2
        wrapped = record[pos:pos + wlen]
        pos += wlen
        nonce, ct = record[pos:pos + NONCE_LEN], record[pos + NONCE_LEN:]
        if len(wrapped) != wlen or len(nonce) != NONCE_LEN or len(ct) < 16:
            raise VaultError("rekord jest uszkodzony")
        return kek_id, wrapped, nonce, ct
    except (struct.error, UnicodeDecodeError) as e:
        raise VaultError("rekord jest uszkodzony") from e


def record_kek_id(record: bytes) -> str:
    """Identyfikator KEK-a zapisany w nagłówku rekordu (bez odpakowywania czegokolwiek)."""
    return _unpack(record)[0]


def encrypt_template(provider: KeyProvider, subject_id: str, template: bytes) -> bytes:
    """Szyfruje szablon (np. template_to_bytes(...)) do postaci rekordu bazy."""
    dek = AESGCM.generate_key(256)
    nonce = os.urandom(NONCE_LEN)
    ct = AESGCM(dek).encrypt(nonce, template, _aad(subject_id))
    kek_id, wrapped = provider.wrap(dek, _wrap_aad(subject_id))
    return _pack(kek_id, wrapped, nonce, ct)


def decrypt_template(provider: KeyProvider, subject_id: str, record: bytes) -> bytes:
    """Odszyfrowuje rekord. Każdy błąd uwierzytelnienia kończy się VaultError."""
    kek_id, wrapped, nonce, ct = _unpack(record)
    try:
        dek = provider.unwrap(kek_id, wrapped, _wrap_aad(subject_id))
        return AESGCM(dek).decrypt(nonce, ct, _aad(subject_id))
    except (InvalidTag, KeyError, ValueError):
        raise VaultError("nie można odszyfrować rekordu") from None


def rewrap(provider: KeyProvider, subject_id: str, record: bytes) -> bytes:
    """
    Rotacja KEK-a: odpakowuje DEK starym kluczem i opakowuje bieżącym.
    Szyfrogram i nonce pozostają bez zmian; szablon nie jest deszyfrowany.
    """
    kek_id, wrapped, nonce, ct = _unpack(record)
    try:
        dek = provider.unwrap(kek_id, wrapped, _wrap_aad(subject_id))
    except (InvalidTag, KeyError, ValueError):
        raise VaultError("nie można odpakować klucza rekordu") from None
    new_id, new_wrapped = provider.wrap(dek, _wrap_aad(subject_id))
    return _pack(new_id, new_wrapped, nonce, ct)
