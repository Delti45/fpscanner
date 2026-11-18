#!/usr/bin/env python3
"""
TOTP (RFC 6238) oparty na HOTP (RFC 4226): jednorazowe kody zależne od czasu.

Rola w projekcie: drugi, niezależny od dowodu HMAC czynnik uwierzytelnienia urządzenia
w handshake'u i jednocześnie kontrola synchronizacji czasu. Urządzenie liczy kod z własnego
zegara, serwer ze swojego: gdy zegary rozjadą się o więcej niż okno tolerancji, handshake
jest odrzucany. Kod, który wyciekłby, jest bezużyteczny po kilkudziesięciu sekundach
i może zostać użyty tylko raz (RFC 6238, §5.2).

Moduł zależy wyłącznie od biblioteki standardowej.

  * `hotp`/`totp`        generowanie kodu (testy z wektorami z RFC 4226 App. D i RFC 6238 App. B),
  * `verify_totp`        weryfikacja w oknie ±`window` kroków, w stałym czasie względem liczby
                         kandydatów; zwraca numer kroku, z którego pochodzi kod,
  * `TotpReplayTracker`  jednorazowość: przyjmuje tylko kroki nowsze niż ostatnio przyjęty
                         dla danego urządzenia (stan w pamięci procesu, jak sesje i nonce'y).

Domyślne parametry: HMAC-SHA256 (RFC 6238 dopuszcza SHA-1/256/512), 6 cyfr, krok 30 s,
okno ±1 krok. Kod ma 10^6 możliwych wartości, ale zgadywanie wymaga wcześniej przejścia
mTLS i dowodu HMAC, więc 6 cyfr wystarcza; wartość można zwiększyć do 8.
"""
from __future__ import annotations

import hmac
import struct
import threading
from dataclasses import dataclass

MIN_SECRET_LEN = 16            # RFC 4226, R6: co najmniej 128 bitów (zalecane 160)
ALGORITHMS = ("sha1", "sha256", "sha512")


@dataclass(frozen=True)
class TotpConfig:
    step_s: int = 30           # X z RFC 6238
    digits: int = 6
    algorithm: str = "sha256"
    window: int = 1            # akceptowane kroki: [c - window, c + window]
    t0: int = 0                # początek epoki liczenia kroków (sekundy UNIX)

    def __post_init__(self):
        if self.step_s < 1:
            raise ValueError("step_s musi być >= 1")
        if not 6 <= self.digits <= 8:
            raise ValueError("digits musi leżeć w przedziale 6-8")
        if self.algorithm not in ALGORITHMS:
            raise ValueError(f"algorithm musi być jednym z {ALGORITHMS}")
        if not 0 <= self.window <= 5:
            raise ValueError("window musi leżeć w przedziale 0-5")

    def counter(self, at_s: int | float) -> int:
        """Numer kroku czasu T = floor((t - T0) / X)."""
        return int((at_s - self.t0) // self.step_s)

    def seconds_to_next_step(self, at_s: int | float) -> float:
        """Ile sekund zostało do początku następnego kroku."""
        return (self.counter(at_s) + 1) * self.step_s + self.t0 - at_s


DEFAULT = TotpConfig()


def hotp(secret: bytes, counter: int, *, digits: int = 6, algorithm: str = "sha1") -> str:
    """HOTP (RFC 4226, §5.3): dynamiczne obcięcie HMAC licznika do `digits` cyfr."""
    if not isinstance(secret, (bytes, bytearray)) or len(secret) < MIN_SECRET_LEN:
        raise ValueError(f"sekret TOTP musi mieć co najmniej {MIN_SECRET_LEN} bajtów")
    if not 0 <= counter < 1 << 64:
        raise ValueError("licznik poza zakresem 64 bitów")
    digest = hmac.new(bytes(secret), struct.pack(">Q", counter), algorithm).digest()
    offset = digest[-1] & 0x0F
    binary = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(binary % 10 ** digits).zfill(digits)


def totp(secret: bytes, at_s: int | float, cfg: TotpConfig = DEFAULT) -> str:
    """Kod TOTP dla chwili `at_s` (sekundy UNIX)."""
    return hotp(secret, cfg.counter(at_s), digits=cfg.digits, algorithm=cfg.algorithm)


def totp_for_counter(secret: bytes, counter: int, cfg: TotpConfig = DEFAULT) -> str:
    return hotp(secret, counter, digits=cfg.digits, algorithm=cfg.algorithm)


def verify_totp(secret: bytes, code, at_s: int | float, cfg: TotpConfig = DEFAULT) -> int | None:
    """
    Sprawdza kod w oknie [c - window, c + window] względem czasu serwera `at_s`.
    Zwraca numer kroku, z którego kod pochodzi, albo None. Porównuje ze wszystkimi
    kandydatami (bez wcześniejszego wyjścia), żeby czas nie zdradzał, który krok pasował.
    Kod musi składać się z dokładnie `digits` cyfr ASCII; wszystko inne to None.
    """
    if not isinstance(code, str) or len(code) != cfg.digits or not (code.isascii() and code.isdigit()):
        return None
    center = cfg.counter(at_s)
    matched: int | None = None
    for candidate in range(center - cfg.window, center + cfg.window + 1):
        if candidate < 0:
            continue
        if hmac.compare_digest(totp_for_counter(secret, candidate, cfg), code):
            matched = candidate
    return matched


class TotpReplayTracker:
    """
    Jednorazowość kodów (RFC 6238, §5.2): dla każdego urządzenia pamięta najwyższy przyjęty
    krok i odrzuca kod z kroku nie nowszego. Dzięki temu przechwycony kod nie zadziała
    ponownie, także w obrębie okna tolerancji.

    Konsekwencja: jedno urządzenie może wykonać najwyżej jeden handshake na krok (domyślnie
    30 s). Klient to uwzględnia (patrz FingerprintClient.connect). Stan jest lokalny dla
    procesu, tak jak sesje i nonce'y. Wpisy powstają tylko dla uwierzytelnionych urządzeń,
    więc pamięć jest ograniczona liczbą zarejestrowanych urządzeń.
    """

    def __init__(self):
        self._last: dict[str, int] = {}
        self._lock = threading.Lock()

    def consume(self, device_id: str, counter: int) -> bool:
        """Atomowo: True i zapamiętanie, gdy krok jest nowszy niż ostatnio przyjęty."""
        with self._lock:
            if counter <= self._last.get(device_id, -1):
                return False
            self._last[device_id] = counter
            return True
