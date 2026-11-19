#!/usr/bin/env python3
"""
Format rekordu minutii ISO/IEC 19794-2:2005 (z poprawką Cor.1:2009): eksport i import.

Zakres: rekord z minutiami bez bloków rozszerzonych (liczba linii, rdzenie/delty, jakość stref).
Obsługuje wiele widoków palców. Format ANSI/INCITS 378-2004 ma ten sam znacznik i wersję, ale
inną długość rekordu i inny zakres kąta; jest wykrywany i odrzucany z czytelnym komunikatem.

Układ (wszystkie liczby big-endian):

  nagłówek rekordu, 24 B
    "FMR\\0" (4) | " 20\\0" (4) | długość całego rekordu (4) |
    certyfikacja czytnika (4 bity) + identyfikator typu czytnika (12 bitów) (2) |
    szerokość obrazu (2) | wysokość (2) | rozdzielczość X (2) | rozdzielczość Y (2), piksele/cm |
    liczba widoków palców (1) | zarezerwowany, zero (1)
  widok palca
    nagłówek 4 B: pozycja palca 0-10 (1) | numer widoku (4 bity) + typ odbitki (4 bity) (1) |
                  jakość widoku 0-100 (1) | liczba minutii (1)
    minutie po 6 B: typ (2 bity) + X (14 bitów) (2) | zero (2 bity) + Y (14 bitów) (2) |
                    kąt (1) | jakość minutii, 0 = nie podano (1)
    długość bloków rozszerzonych (2); tu zawsze 0

Współrzędne: piksele, początek w lewym górnym rogu, X rośnie w prawo, Y w dół, środek piksela.
Kąt: 0 = w prawo, rośnie przeciwnie do ruchu wskazówek zegara (tak jak widać obraz), jednostka
360/256 stopnia. Typ: 1 = zakończenie linii, 2 = rozwidlenie, 0 = inny.

Konwencja kąta w ISO a w tym projekcie (`preprocessing.Minutia.theta`):
  * zakończenie: oba kąty wskazują od końca linii w głąb linii; kąt się nie zmienia,
  * rozwidlenie: ISO wskazuje od punktu rozwidlenia w głąb doliny między gałęziami (średni
    kierunek dwóch gałęzi), a projekt wzdłuż pnia, czyli w stronę przeciwną. Przy konwersji
    kąt rozwidlenia obracamy o 180°. Pominięcie tego dałoby kąty przesunięte o pół obrotu, a
    matcher (tolerancja 12°) odrzuciłby wszystkie takie pary.

Źródła specyfikacji (norma jest płatna i nie była dostępna w całości): streszczenie formatu
https://templates.machinezoo.com/iso-19794-2-2005 (CC BY 4.0) oraz niezależne opisy konwencji
współrzędnych i kąta w publikacjach NIST i w literaturze patentowej. Układ pól i konwencje należy
zweryfikować względem normy albo certyfikowanego narzędzia, zanim rekord posłuży do wymiany
z systemami trzecimi.

Parser traktuje wejście jako niezaufane: sprawdza długości przed każdym odczytem, wymaga zgodności
długości rekordu z rozmiarem danych, odrzuca niezerowe bity zarezerwowane, niedozwolone wartości
pól i bloki rozszerzone, które by się nie zmieściły. Błędy to zawsze `IsoFormatError`.
"""
from __future__ import annotations

import math
import struct
from dataclasses import dataclass

from fpscanner.biometrics.preprocessing import BIFURCATION, ENDING, Minutia

MAGIC = b"FMR\x00"
VERSION = b" 20\x00"
HEADER_LEN = 24
VIEW_HEADER_LEN = 4
MINUTIA_LEN = 6
EXT_LEN_FIELD = 2

MAX_MINUTIAE = 255                       # pole liczby minutii ma 1 bajt
MAX_COORD = (1 << 14) - 1                # 14 bitów na współrzędną
MAX_VIEWS = 11 * 16                      # 11 pozycji palca x 16 numerów widoku (unikalne pary)
MAX_RECORD_BYTES = (HEADER_LEN + MAX_VIEWS * (VIEW_HEADER_LEN + MAX_MINUTIAE * MINUTIA_LEN + EXT_LEN_FIELD))
MIN_RESOLUTION_PX_CM = 99                # 250 dpi; wymagane od rekordów, które tworzymy

TYPE_OTHER, TYPE_ENDING, TYPE_BIFURCATION = 0, 1, 2
VALID_IMPRESSION_TYPES = frozenset({0, 1, 2, 3, 8})
ANGLE_UNITS = 256
_TWO_PI = 2 * math.pi


class IsoFormatError(ValueError):
    """Rekord niezgodny z ISO/IEC 19794-2:2005 albo spoza obsługiwanego zakresu."""


@dataclass(frozen=True)
class IsoMinutia:
    """Minutia w jednostkach formatu (bez konwersji konwencji projektu)."""
    x: int
    y: int
    angle: int                 # 0..255, jednostka 360/256 stopnia
    kind: int                  # 0 inny, 1 zakończenie, 2 rozwidlenie
    quality: int = 0           # 0 = nie podano, 1..100


@dataclass(frozen=True)
class IsoFingerView:
    minutiae: tuple[IsoMinutia, ...]
    finger_position: int = 0   # 0 nieznany, 1-5 prawa ręka kciuk..mały, 6-10 lewa ręka kciuk..mały
    view_number: int = 0       # 0..15
    impression_type: int = 0   # 0 nacisk na czytniku, 1 rolowany, 2/3 nieżywe, 8 przesuwany
    quality: int = 100         # 0..100; norma nie ma wartości „nieznana", zalecane 100


@dataclass(frozen=True)
class IsoRecord:
    width: int
    height: int
    resolution_x: int          # piksele na cm
    resolution_y: int
    views: tuple[IsoFingerView, ...]
    compliance: int = 0        # 4 bity (najstarszy: czytnik certyfikowany)
    capture_device_id: int = 0  # 12 bitów


# --------------------------------------------------------------------------- #
# Kodowanie rekordu
# --------------------------------------------------------------------------- #
def _check_int(name: str, value, lo: int, hi: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or not lo <= value <= hi:
        raise IsoFormatError(f"{name} poza zakresem {lo}-{hi}: {value!r}")


def encode_record(rec: IsoRecord) -> bytes:
    """Serializuje rekord; waliduje każde pole, więc wynik zawsze przechodzi `decode_record`."""
    _check_int("szerokość", rec.width, 1, 0xFFFF)
    _check_int("wysokość", rec.height, 1, 0xFFFF)
    _check_int("rozdzielczość X", rec.resolution_x, MIN_RESOLUTION_PX_CM, 0xFFFF)
    _check_int("rozdzielczość Y", rec.resolution_y, MIN_RESOLUTION_PX_CM, 0xFFFF)
    _check_int("certyfikacja czytnika", rec.compliance, 0, 0xF)
    _check_int("identyfikator czytnika", rec.capture_device_id, 0, 0xFFF)
    if len(rec.views) > MAX_VIEWS:
        raise IsoFormatError(f"zbyt wiele widoków: {len(rec.views)} > {MAX_VIEWS}")
    seen: set[tuple[int, int]] = set()
    body = bytearray()
    for v in rec.views:
        _check_int("pozycja palca", v.finger_position, 0, 10)
        _check_int("numer widoku", v.view_number, 0, 15)
        _check_int("jakość widoku", v.quality, 0, 100)
        if v.impression_type not in VALID_IMPRESSION_TYPES:
            raise IsoFormatError(f"niedozwolony typ odbitki: {v.impression_type!r}")
        if len(v.minutiae) > MAX_MINUTIAE:
            raise IsoFormatError(f"zbyt wiele minutii: {len(v.minutiae)} > {MAX_MINUTIAE}")
        key = (v.finger_position, v.view_number)
        if key in seen:
            raise IsoFormatError(f"powtórzona para (pozycja palca, numer widoku): {key}")
        seen.add(key)
        body += struct.pack(">BBBB", v.finger_position, (v.view_number << 4) | v.impression_type,
                            v.quality, len(v.minutiae))
        for m in v.minutiae:
            _check_int("X minutii", m.x, 0, MAX_COORD)
            _check_int("Y minutii", m.y, 0, MAX_COORD)
            _check_int("kąt minutii", m.angle, 0, ANGLE_UNITS - 1)
            _check_int("jakość minutii", m.quality, 0, 100)
            if m.kind not in (TYPE_OTHER, TYPE_ENDING, TYPE_BIFURCATION):
                raise IsoFormatError(f"niedozwolony typ minutii: {m.kind!r}")
            body += struct.pack(">HHBB", (m.kind << 14) | m.x, m.y, m.angle, m.quality)
        body += struct.pack(">H", 0)                      # brak bloków rozszerzonych
    total = HEADER_LEN + len(body)
    head = struct.pack(">4s4sIHHHHHBB", MAGIC, VERSION, total, (rec.compliance << 12) | rec.capture_device_id,
                       rec.width, rec.height, rec.resolution_x, rec.resolution_y, len(rec.views), 0)
    return head + bytes(body)


# --------------------------------------------------------------------------- #
# Dekodowanie rekordu (dane niezaufane)
# --------------------------------------------------------------------------- #
def decode_record(data: bytes) -> IsoRecord:
    """Parsuje rekord ISO/IEC 19794-2:2005. `IsoFormatError` dla każdej niezgodności."""
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise IsoFormatError("oczekiwano bajtów")
    data = bytes(data)
    if len(data) > MAX_RECORD_BYTES:
        raise IsoFormatError(f"rekord dłuższy niż dopuszczalne {MAX_RECORD_BYTES} B")
    if len(data) < HEADER_LEN:
        raise IsoFormatError("rekord krótszy niż nagłówek (24 B)")
    if data[:4] != MAGIC:
        raise IsoFormatError("zły znacznik formatu (oczekiwano 'FMR\\0')")
    if data[4:8] != VERSION:
        raise IsoFormatError("nieobsługiwana wersja (oczekiwano ' 20\\0')")
    # ANSI/INCITS 378-2004 ma ten sam znacznik i wersję, ale 2-bajtową długość >= 26 w tym miejscu
    if struct.unpack_from(">H", data, 8)[0] >= 26:
        raise IsoFormatError("to rekord ANSI/INCITS 378-2004, nie ISO/IEC 19794-2:2005")
    (total, devword, width, height, res_x, res_y, view_count, reserved) = struct.unpack_from(
        ">IHHHHHBB", data, 8)
    if total != len(data):
        raise IsoFormatError(
            f"długość rekordu w nagłówku ({total}) różni się od rozmiaru danych ({len(data)})")
    if reserved != 0:
        raise IsoFormatError("niezerowy bajt zarezerwowany nagłówka")
    pos = HEADER_LEN
    views: list[IsoFingerView] = []
    seen: set[tuple[int, int]] = set()
    for _ in range(view_count):
        if len(data) - pos < VIEW_HEADER_LEN:
            raise IsoFormatError("rekord ucięty w nagłówku widoku")
        position, vi, quality, count = struct.unpack_from(">BBBB", data, pos)
        pos += VIEW_HEADER_LEN
        view_number, impression = vi >> 4, vi & 0xF
        if position > 10:
            raise IsoFormatError(f"niedozwolona pozycja palca: {position}")
        if impression not in VALID_IMPRESSION_TYPES:
            raise IsoFormatError(f"niedozwolony typ odbitki: {impression}")
        if quality > 100:
            raise IsoFormatError(f"jakość widoku poza zakresem: {quality}")
        if (position, view_number) in seen:
            raise IsoFormatError(f"powtórzona para (pozycja palca, numer widoku): {(position, view_number)}")
        seen.add((position, view_number))
        need = count * MINUTIA_LEN + EXT_LEN_FIELD
        if len(data) - pos < need:
            raise IsoFormatError("rekord ucięty w minutiach widoku")
        minutiae = []
        for _i in range(count):
            w1, w2, angle, mq = struct.unpack_from(">HHBB", data, pos)
            pos += MINUTIA_LEN
            kind = w1 >> 14
            if kind == 3:
                raise IsoFormatError("niedozwolony typ minutii (11)")
            if w2 >> 14:
                raise IsoFormatError("niezerowe bity zarezerwowane przy współrzędnej Y")
            if mq > 100:
                raise IsoFormatError(f"jakość minutii poza zakresem: {mq}")
            minutiae.append(IsoMinutia(w1 & MAX_COORD, w2 & MAX_COORD, angle, kind, mq))
        (ext,) = struct.unpack_from(">H", data, pos)
        pos += EXT_LEN_FIELD
        if ext != 0:
            raise IsoFormatError("bloki rozszerzone (liczba linii, rdzenie/delty, jakość stref) "
                                 "nie są obsługiwane")
        views.append(IsoFingerView(tuple(minutiae), position, view_number, impression, quality))
    if pos != len(data):
        raise IsoFormatError(f"{len(data) - pos} B nadmiarowych danych po ostatnim widoku")
    return IsoRecord(width, height, res_x, res_y, tuple(views),
                     compliance=devword >> 12, capture_device_id=devword & 0xFFF)


# --------------------------------------------------------------------------- #
# Konwersja z/do minutii projektu
# --------------------------------------------------------------------------- #
def dpi_to_px_per_cm(dpi: float) -> int:
    return round(dpi / 2.54)


def px_per_cm_to_dpi(px_per_cm: int) -> float:
    return px_per_cm * 2.54


def _angle_to_iso(theta: float, kind: int) -> int:
    """Radiany (konwencja projektu) -> jednostki ISO; rozwidlenie obracamy o 180°."""
    if kind == BIFURCATION:
        theta += math.pi
    return int(math.floor(theta / _TWO_PI * ANGLE_UNITS + 0.5)) % ANGLE_UNITS


def _angle_from_iso(angle: int, kind: int) -> float:
    if kind == BIFURCATION:
        angle -= ANGLE_UNITS // 2
    return (angle % ANGLE_UNITS) * _TWO_PI / ANGLE_UNITS


def minutiae_to_iso(minutiae: list[Minutia], *, width: int, height: int, dpi: float = 500,
                    finger_position: int = 0, view_number: int = 0, impression_type: int = 0,
                    quality: int = 100, compliance: int = 0, capture_device_id: int = 0) -> bytes:
    """
    Minutie projektu -> rekord ISO/IEC 19794-2:2005 z jednym widokiem. Współrzędne muszą mieścić się
    w obrazie `width` x `height`; więcej niż 255 minutii to błąd (nie przycinamy po cichu).
    Jakość minutii zapisujemy jako 0 („nie podano"): spójność orientacji z ekstrakcji nie jest
    jakością w rozumieniu normy.
    """
    px_cm = dpi_to_px_per_cm(dpi)
    out: list[IsoMinutia] = []
    for m in minutiae:
        if m.kind not in (ENDING, BIFURCATION):
            raise IsoFormatError(f"nieznany typ minutii projektu: {m.kind!r}")
        if not (0 <= m.x < width and 0 <= m.y < height):
            raise IsoFormatError(f"minutia ({m.x}, {m.y}) poza obrazem {width}x{height}")
        iso_kind = TYPE_ENDING if m.kind == ENDING else TYPE_BIFURCATION
        out.append(IsoMinutia(int(m.x), int(m.y), _angle_to_iso(m.theta, m.kind), iso_kind))
    view = IsoFingerView(tuple(out), finger_position, view_number, impression_type, quality)
    return encode_record(IsoRecord(width, height, px_cm, px_cm, (view,), compliance, capture_device_id))


def minutiae_from_iso(data: bytes, *, view: int = 0, other: str = "ending") -> list[Minutia]:
    """
    Rekord ISO/IEC 19794-2:2005 -> minutie projektu (widok o indeksie `view`). Projekt zna tylko
    zakończenia i rozwidlenia; minutie typu „inny" obsługuje `other`: "ending" (domyślnie;
    matcher domyślnie nie porównuje typów), "skip" (pomiń) albo "error".
    """
    if other not in ("ending", "skip", "error"):
        raise ValueError("other musi być 'ending', 'skip' albo 'error'")
    rec = decode_record(data)
    if not 0 <= view < len(rec.views):
        raise IsoFormatError(f"rekord ma {len(rec.views)} widoków, żądano {view}")
    result: list[Minutia] = []
    for m in rec.views[view].minutiae:
        if m.kind == TYPE_OTHER:
            if other == "skip":
                continue
            if other == "error":
                raise IsoFormatError("minutia typu 'inny' nie ma odpowiednika w projekcie")
            kind = ENDING
        else:
            kind = ENDING if m.kind == TYPE_ENDING else BIFURCATION
        result.append(Minutia(m.x, m.y, _angle_from_iso(m.angle, kind), kind))
    return result
