"""
Testy formatu ISO/IEC 19794-2:2005: rekord wzorcowy złożony ręcznie, odwracalność, konwencje
kąta i typu, odrzucanie błędnych rekordów oraz odporność parsera na dowolne bajty.
Porównanie z niezależnym ekstraktorem (NBIS) jest w test_iso19794_xcheck.py.
"""
import math
import struct

import numpy as np
import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from fpscanner.biometrics import iso19794 as iso
from fpscanner.biometrics.matching import match
from fpscanner.biometrics.preprocessing import BIFURCATION, ENDING, Minutia

# Rekord wzorcowy: pola wypisane ręcznie wg układu z dokumentacji formatu, bez użycia kodera.
GOLDEN = bytes.fromhex(
    "464D5200"      # "FMR\0"
    "20323000"      # " 20\0"
    "0000002A"      # długość rekordu: 24 + 4 + 2*6 + 2 = 42
    "0000"          # certyfikacja i identyfikator czytnika
    "012C" "0190"   # obraz 300 x 400 px
    "00C5" "00C5"   # 197 px/cm (500 dpi)
    "01" "00"       # jeden widok palca, bajt zarezerwowany
    "02" "00" "5A" "02"   # prawy wskazujący, widok 0 / odbitka 0, jakość 90, dwie minutie
    "4064" "00C8" "40" "00"   # zakończenie (typ 01) X=100 Y=200, kąt 64 (w górę), jakość: brak
    "8096" "00FA" "C0" "00"   # rozwidlenie (typ 10) X=150 Y=250, kąt 192 (w dół)
    "0000"          # brak bloków rozszerzonych
)
GOLDEN_RECORD = iso.IsoRecord(
    300, 400, 197, 197,
    (iso.IsoFingerView((iso.IsoMinutia(100, 200, 64, 1), iso.IsoMinutia(150, 250, 192, 2)),
                       finger_position=2, quality=90),))


def test_golden_record_encodes_and_decodes_exactly():
    assert len(GOLDEN) == 42
    assert iso.encode_record(GOLDEN_RECORD) == GOLDEN
    assert iso.decode_record(GOLDEN) == GOLDEN_RECORD


def test_project_minutiae_map_to_expected_iso_bytes():
    # Konwencja projektu: theta w radianach, 0 = w prawo, rośnie przeciwnie do ruchu wskazówek
    # (tak jak widać obraz, Y w dół); zakończenie: w głąb linii; rozwidlenie: wzdłuż pnia.
    ending = Minutia(100, 200, math.pi / 2, ENDING)           # linia w górę od końca
    bifurcation = Minutia(150, 250, math.pi / 2, BIFURCATION)  # pień w górę, gałęzie rozchodzą się w dół
    data = iso.minutiae_to_iso([ending, bifurcation], width=300, height=400, dpi=500, finger_position=2,
                               quality=90)
    assert data == GOLDEN                                      # ISO: zakończenie 64; rozwidlenie 64+128
    back = iso.minutiae_from_iso(data)
    assert [(m.x, m.y, m.kind) for m in back] == [(100, 200, ENDING), (150, 250, BIFURCATION)]
    assert all(math.isclose(m.theta, math.pi / 2, abs_tol=1e-9) for m in back)


def _random_minutiae(seed, n=45, w=388, h=374):
    rng = np.random.default_rng(seed)
    return [Minutia(int(rng.integers(10, w - 10)), int(rng.integers(10, h - 10)),
                    float(rng.uniform(0, 2 * math.pi)), int(rng.integers(0, 2))) for _ in range(n)]


@pytest.mark.parametrize("seed", [1, 2, 3])
def test_roundtrip_error_is_bounded_and_matching_is_unchanged(seed):
    a = _random_minutiae(seed)
    b = iso.minutiae_from_iso(iso.minutiae_to_iso(a, width=388, height=374))
    assert [(m.x, m.y, m.kind) for m in a] == [(m.x, m.y, m.kind) for m in b]
    err = max(abs((x.theta - y.theta + math.pi) % (2 * math.pi) - math.pi) for x, y in zip(a, b, strict=True))
    assert err <= math.pi / 256 + 1e-9                       # połowa kwantu 360/256 stopnia
    assert match(a, a).score == pytest.approx(1.0) and match(a, b).score == pytest.approx(1.0)
    assert match(a, _random_minutiae(seed + 100)).score < 0.1  # inny „palec" nadal się nie dopasowuje


def test_missing_bifurcation_flip_would_break_matching():
    # Dowód, że zamiana kąta rozwidleń o 180° ma znaczenie: bez niej genuine spada z 1,0 do ~0,2
    a = _random_minutiae(7)
    b = iso.minutiae_from_iso(iso.minutiae_to_iso(a, width=388, height=374))
    wrong = [Minutia(m.x, m.y, (m.theta + math.pi) % (2 * math.pi) if m.kind == BIFURCATION else m.theta,
                     m.kind) for m in b]
    assert match(a, wrong).score < 0.5 < match(a, b).score


def test_other_type_policy():
    rec = iso.IsoRecord(300, 400, 197, 197, (iso.IsoFingerView((
        iso.IsoMinutia(10, 10, 0, iso.TYPE_OTHER), iso.IsoMinutia(20, 20, 64, iso.TYPE_ENDING)),),))
    data = iso.encode_record(rec)
    assert [m.kind for m in iso.minutiae_from_iso(data)] == [ENDING, ENDING]            # domyślnie: zakończenie
    assert len(iso.minutiae_from_iso(data, other="skip")) == 1
    with pytest.raises(iso.IsoFormatError):
        iso.minutiae_from_iso(data, other="error")
    with pytest.raises(ValueError):
        iso.minutiae_from_iso(data, other="nieznane")


def test_view_selection_and_multiple_views():
    v0 = iso.IsoFingerView((iso.IsoMinutia(1, 2, 3, 1),), finger_position=2, view_number=0)
    v1 = iso.IsoFingerView((iso.IsoMinutia(4, 5, 6, 2), iso.IsoMinutia(7, 8, 9, 1)), finger_position=2,
                           view_number=1, impression_type=8, quality=40)
    data = iso.encode_record(iso.IsoRecord(300, 400, 197, 197, (v0, v1), compliance=8, capture_device_id=0xABC))
    rec = iso.decode_record(data)
    assert rec.views == (v0, v1) and rec.compliance == 8 and rec.capture_device_id == 0xABC
    assert len(iso.minutiae_from_iso(data, view=1)) == 2
    with pytest.raises(iso.IsoFormatError):
        iso.minutiae_from_iso(data, view=2)


def test_dpi_conversion():
    assert iso.dpi_to_px_per_cm(500) == 197 and iso.dpi_to_px_per_cm(250) == 98
    assert iso.px_per_cm_to_dpi(197) == pytest.approx(500.38, abs=0.01)


# --------------------------------------------------------------------------- #
# Walidacja przy kodowaniu
# --------------------------------------------------------------------------- #
def _enc(**over):
    base = {"width": 300, "height": 400, "dpi": 500}
    base.update(over)
    return lambda minutiae: iso.minutiae_to_iso(minutiae, **base)


def test_encoder_rejects_out_of_range_input():
    ok = Minutia(10, 10, 0.0, ENDING)
    assert iso.minutiae_to_iso([ok], width=300, height=400)
    for bad in (Minutia(300, 10, 0.0, ENDING), Minutia(10, 400, 0.0, ENDING), Minutia(-1, 10, 0.0, ENDING),
                Minutia(10, 10, 0.0, 7)):
        with pytest.raises(iso.IsoFormatError):
            iso.minutiae_to_iso([bad], width=300, height=400)
    with pytest.raises(iso.IsoFormatError):
        iso.minutiae_to_iso([ok] * 256, width=300, height=400)             # 255 to maksimum
    assert iso.minutiae_to_iso([ok] * 255, width=300, height=400)
    for kw in ({"width": 0}, {"height": 70000}, {"dpi": 100}, {"finger_position": 11}, {"quality": 101},
               {"impression_type": 4}, {"view_number": 16}, {"compliance": 16}, {"capture_device_id": 4096}):
        with pytest.raises(iso.IsoFormatError):
            _enc(**kw)([ok])
    big = iso.minutiae_to_iso([Minutia(16383, 9, 0.0, ENDING)], width=16384, height=100)
    assert iso.decode_record(big).views[0].minutiae[0].x == 16383
    with pytest.raises(iso.IsoFormatError):
        iso.minutiae_to_iso([Minutia(16384, 9, 0.0, ENDING)], width=17000, height=100)   # 14 bitów


def test_encoder_rejects_duplicate_views():
    v = iso.IsoFingerView((), finger_position=1, view_number=0)
    with pytest.raises(iso.IsoFormatError):
        iso.encode_record(iso.IsoRecord(300, 400, 197, 197, (v, v)))


# --------------------------------------------------------------------------- #
# Odrzucanie błędnych rekordów
# --------------------------------------------------------------------------- #
def _patch(data: bytes, offset: int, new: bytes) -> bytes:
    return data[:offset] + new + data[offset + len(new):]


def _with_total_fixed(data: bytes) -> bytes:
    return _patch(data, 8, struct.pack(">I", len(data)))


BAD_RECORDS = {
    "pusty": b"",
    "krótszy niż nagłówek": GOLDEN[:23],
    "zły znacznik": _patch(GOLDEN, 0, b"FMX\x00"),
    "zła wersja": _patch(GOLDEN, 4, b" 30\x00"),
    "ANSI 378-2004 (2-bajtowa długość)": _patch(GOLDEN, 8, struct.pack(">H", 0x32)),
    "długość większa niż dane": _patch(GOLDEN, 8, struct.pack(">I", 43)),
    "długość mniejsza niż dane": _patch(GOLDEN, 8, struct.pack(">I", 41)),
    "ucięty o 1 B": GOLDEN[:-1],
    "ucięty w minutiach": _with_total_fixed(GOLDEN[:-5]),
    "nadmiar na końcu": _with_total_fixed(GOLDEN + b"\x00"),
    "niezerowy bajt zarezerwowany": _patch(GOLDEN, 23, b"\x01"),
    "pozycja palca 11": _patch(GOLDEN, 24, b"\x0b"),
    "typ odbitki 4": _patch(GOLDEN, 25, b"\x04"),
    "jakość widoku 101": _patch(GOLDEN, 26, b"\x65"),
    "liczba minutii większa niż dane": _patch(GOLDEN, 27, b"\x03"),
    "liczba widoków większa niż dane": _patch(GOLDEN, 22, b"\x02"),
    "typ minutii 11": _patch(GOLDEN, 28, b"\xc0\x64"),
    "bity zarezerwowane przy Y": _patch(GOLDEN, 30, b"\x40\xc8"),
    "jakość minutii 101": _patch(GOLDEN, 33, b"\x65"),
    "bloki rozszerzone": _patch(GOLDEN, 40, b"\x00\x04"),
    "powtórzony widok": _with_total_fixed(_patch(GOLDEN, 22, b"\x02") + GOLDEN[24:40] + b"\x00\x00"),
    "zbyt duży rekord": b"FMR\x00 20\x00" + b"\x00" * (iso.MAX_RECORD_BYTES + 1),
}


@pytest.mark.parametrize("name", sorted(BAD_RECORDS))
def test_decoder_rejects_malformed_records(name):
    with pytest.raises(iso.IsoFormatError):
        iso.decode_record(BAD_RECORDS[name])


def test_decoder_rejects_wrong_types():
    for bad in (None, "FMR", 42, [1, 2]):
        with pytest.raises(iso.IsoFormatError):
            iso.decode_record(bad)
    assert iso.decode_record(bytearray(GOLDEN)) == GOLDEN_RECORD
    assert iso.decode_record(memoryview(GOLDEN)) == GOLDEN_RECORD


def test_ansi_378_message_is_specific():
    with pytest.raises(iso.IsoFormatError, match="ANSI"):
        iso.decode_record(BAD_RECORDS["ANSI 378-2004 (2-bajtowa długość)"])


# --------------------------------------------------------------------------- #
# Właściwości: parser na dowolnych bajtach
# --------------------------------------------------------------------------- #
@settings(max_examples=300, deadline=None)
@given(st.binary(max_size=200))
def test_decoder_only_raises_isoformaterror_on_random_bytes(data):
    try:
        iso.decode_record(data)
    except iso.IsoFormatError:
        pass


@settings(max_examples=400, deadline=None)
@given(st.lists(st.tuples(st.integers(0, 41), st.integers(0, 255)), min_size=1, max_size=6))
def test_mutated_records_are_rejected_or_canonical(edits):
    data = bytearray(GOLDEN)
    for pos, value in edits:
        data[pos] = value
    try:
        rec = iso.decode_record(bytes(data))
    except iso.IsoFormatError:
        return
    # przyjęty rekord ma jedyną reprezentację: kodowanie po dekodowaniu daje te same bajty
    assert rec.width >= 1 and rec.height >= 1
    if min(rec.resolution_x, rec.resolution_y) >= iso.MIN_RESOLUTION_PX_CM:
        assert iso.encode_record(rec) == bytes(data)


@settings(max_examples=200, deadline=None)
@given(st.lists(st.tuples(st.integers(0, 16383), st.integers(0, 16383), st.integers(0, 255),
                          st.integers(0, 2), st.integers(0, 100)), max_size=40),
       st.integers(0, 10), st.integers(0, 15), st.sampled_from([0, 1, 2, 3, 8]), st.integers(0, 100))
def test_encode_decode_roundtrip_property(rows, position, view_number, impression, quality):
    view = iso.IsoFingerView(tuple(iso.IsoMinutia(*r[:3], r[3], r[4]) for r in rows), position, view_number,
                             impression, quality)
    rec = iso.IsoRecord(16384, 16384, 197, 197, (view,))
    data = iso.encode_record(rec)
    assert len(data) == 24 + 4 + 6 * len(rows) + 2
    assert iso.decode_record(data) == rec
