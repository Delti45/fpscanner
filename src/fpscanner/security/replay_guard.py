#!/usr/bin/env python3
"""
Ochrona przed atakami replay: okno czasowe + jednorazowe nonce'y.

Moduł nie zależy od kryptografii ani od reszty projektu. Realizuje dwa
mechanizmy z opisu projektu:
  * znacznik czasu – wiadomości starsze niż `max_age_ms` (domyślnie 60 s)
    są odrzucane; wiadomości „z przyszłości" ponad `max_future_ms` (tolerancja
    na rozjazd zegarów, domyślnie 5 s) również;
  * nonce jednorazowy – para (sesja, nonce) może zostać „zajęta" tylko raz
    w oknie `nonce_ttl_ms` (domyślnie 5 min, czyli wyraźnie dłużej niż okno
    czasowe, więc przechwycona wiadomość nie może zostać użyta po wygaśnięciu
    wpisu).

Kolejność wywołań po stronie serwera (patrz crypto_session.open_message):
  1. check_timestamp  – tanie sprawdzenie, przed deszyfrowaniem,
  2. deszyfrowanie i weryfikacja tagu GCM,
  3. claim_nonce      – dopiero PO udanej weryfikacji, atomowo.
Zajmowanie nonce'a po uwierzytelnieniu nie pozwala atakującemu zapełnić
magazynu losowymi wpisami, a atomowość chroni przed wyścigiem dwóch
identycznych żądań wysłanych równolegle.

Magazyn nonce'ów jest wymienny (`NonceStore`). Dołączona wersja w pamięci wystarcza dla
jednego procesu i tak jest wdrażany prototyp. Przy wielu procesach potrzebny byłby wspólny
magazyn z atomowym `claim` (np. tabela PostgreSQL z kluczem unikalnym).
"""
from __future__ import annotations

import threading
import time
from collections import OrderedDict
from typing import Protocol


# --------------------------------------------------------------------------- #
# Wyjątki
# --------------------------------------------------------------------------- #
class ReplayError(Exception):
    """Bazowy wyjątek: wiadomość odrzucona przez ochronę przed replay."""


class StaleTimestamp(ReplayError):
    """Znacznik czasu poza dozwolonym oknem (za stary lub z przyszłości)."""


class NonceReused(ReplayError):
    """Ten nonce został już użyty w obrębie okna."""


class GuardFull(ReplayError):
    """Magazyn nonce'ów jest pełny (odmowa zamiast pomijania kontroli)."""


# --------------------------------------------------------------------------- #
# Magazyny nonce'ów
# --------------------------------------------------------------------------- #
class NonceStore(Protocol):
    def claim(self, key: bytes, ttl_ms: int, now_ms: int) -> bool:
        """Atomowo zapisuje `key`. True = zapis pierwszy, False = już istniał."""


class InMemoryNonceStore:
    """
    Magazyn w pamięci procesu, bezpieczny wątkowo. Wpisy mają ten sam TTL, więc
    kolejność wstawiania = kolejność wygasania i czyszczenie to zdejmowanie
    elementów z początku `OrderedDict` (O(1) amortyzowane).
    """

    def __init__(self, max_entries: int = 1_000_000):
        self._data: OrderedDict[bytes, int] = OrderedDict()
        self._lock = threading.Lock()
        self._max = max_entries

    def claim(self, key: bytes, ttl_ms: int, now_ms: int) -> bool:
        with self._lock:
            while self._data:
                oldest = next(iter(self._data))
                if self._data[oldest] > now_ms:
                    break
                del self._data[oldest]
            if key in self._data:
                return False
            if len(self._data) >= self._max:
                raise GuardFull("magazyn nonce'ów jest pełny")
            self._data[key] = now_ms + ttl_ms
            return True

    def __len__(self) -> int:
        with self._lock:
            return len(self._data)


# --------------------------------------------------------------------------- #
# Straż
# --------------------------------------------------------------------------- #
def now_ms() -> int:
    return time.time_ns() // 1_000_000


class ReplayGuard:
    def __init__(self, store: NonceStore | None = None, *,
                 max_age_ms: int = 60_000,
                 max_future_ms: int = 5_000,
                 nonce_ttl_ms: int = 300_000):
        if nonce_ttl_ms < max_age_ms + max_future_ms:
            raise ValueError("nonce_ttl_ms musi pokrywać całe okno czasowe, "
                             "inaczej stara wiadomość mogłaby wrócić po wygaśnięciu wpisu")
        # `is not None`, nie `or`: pusty magazyn ma len()==0 i byłby uznany za fałsz
        self.store = store if store is not None else InMemoryNonceStore()
        self.max_age_ms = max_age_ms
        self.max_future_ms = max_future_ms
        self.nonce_ttl_ms = nonce_ttl_ms

    def check_timestamp(self, timestamp_ms: int, now: int | None = None) -> None:
        """Rzuca StaleTimestamp, gdy znacznik jest poza oknem."""
        now = now_ms() if now is None else now
        age = now - timestamp_ms
        if age > self.max_age_ms:
            raise StaleTimestamp(f"wiadomość za stara o {age} ms (limit {self.max_age_ms} ms)")
        if -age > self.max_future_ms:
            raise StaleTimestamp(f"znacznik czasu z przyszłości o {-age} ms "
                                 f"(limit {self.max_future_ms} ms)")

    def claim_nonce(self, session_id: bytes, nonce: bytes, now: int | None = None) -> None:
        """Zajmuje nonce; rzuca NonceReused, jeśli był już użyty."""
        now = now_ms() if now is None else now
        if not self.store.claim(session_id + nonce, self.nonce_ttl_ms, now):
            raise NonceReused("ponowne użycie nonce'a (podejrzenie ataku replay)")
