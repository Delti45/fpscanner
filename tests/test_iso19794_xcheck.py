"""
Porównanie konwencji kąta i typu z niezależnym ekstraktorem NBIS (pakiet `nbis-python`, kąty w
konwencji ISO 19794-2). Test pomijany, gdy pakiet nie jest zainstalowany: `pip install -e ".[xcheck]"`
(koło tylko dla Linuksa x86_64).

Obrazy są syntetyczne i mają geometrię, którą da się opisać bez żadnego kodu:
  * linia biegnąca od lewej krawędzi i urwana w x = 200: zakończenie, ISO wskazuje w głąb linii, czyli
    w lewo = 180°;
  * linia biegnąca od lewej, która w x = 300 rozdwaja się w gałęzie rozchodzące się w prawo:
    rozwidlenie, ISO wskazuje do doliny między gałęziami, czyli w prawo = 0°. Projekt mierzy kierunek
    wzdłuż pnia (w lewo = 180°), więc bez obrotu o 180° kąty rozwidleń byłyby przeciwne.
"""
import math

import cv2
import numpy as np
import pytest

from fpscanner.biometrics.iso19794 import _angle_to_iso
from fpscanner.biometrics.preprocessing import BIFURCATION, ENDING, Config, process_image

nbis = pytest.importorskip("nbis")


def _angle_diff_deg(a: float, b: float) -> float:
    return abs((a - b + 180.0) % 360.0 - 180.0)


def _nbis_minutiae(img: np.ndarray):
    ok, png = cv2.imencode(".png", img)
    assert ok
    ex = nbis.new_nbis_extractor(nbis.NbisExtractorSettings(
        min_quality=0.0, get_center=False, check_fingerprint=False, compute_nfiq2=False, ppi=500.0))
    return ex.extract_minutiae(png.tobytes()).list()


def _ending_image() -> np.ndarray:
    size, period, thick = 520, 16, 5
    img = np.full((size, size), 255, np.uint8)
    for y in range(24, size - 8, period):
        cv2.line(img, (0, y), (200 if y == 168 else size, y), 0, thick)       # linia y=168 urwana w x=200
    return cv2.GaussianBlur(img, (3, 3), 0.8)


def _bifurcation_image() -> np.ndarray:
    size, period, thick, spread, bx = 600, 24, 6, 10, 300
    img = np.full((size, size), 255, np.uint8)
    by = 24 + period * 17
    for y in range(24, size - 8, period):
        if y != by:
            cv2.line(img, (0, y), (size, y), 0, thick)
            continue
        cv2.line(img, (0, y), (bx, y), 0, thick)                              # pień
        for s in (-1, 1):                                                      # dwie gałęzie w prawo
            cv2.line(img, (bx, y), (bx + 60, y + s * spread), 0, thick)
            cv2.line(img, (bx + 60, y + s * spread), (size, y + s * spread), 0, thick)
    return cv2.GaussianBlur(img, (3, 3), 0.8)


def _nearest(items, x, y, limit):
    near = [m for m in items if math.hypot(m.x - x, m.y - y) <= limit]
    assert near, f"brak minutii w promieniu {limit} px od ({x}, {y})"
    return min(near, key=lambda m: math.hypot(m.x - x, m.y - y))


def test_ending_angle_agrees_with_nbis():
    img = _ending_image()
    theirs = _nearest([m for m in _nbis_minutiae(img) if m.kind.name == "RIDGE_ENDING"], 200, 168, 15)
    # Ekstraktor projektu zgłasza też drobne odgałęzienia (spurs) przy brzegach linii, ok. 6 px nad i pod
    # osią; prawdziwe zakończenie leży na osi linii (y = 168), więc wybieramy po odległości od osi.
    candidates = [m for m in process_image(img, Config()).minutiae
                  if m.kind == ENDING and math.hypot(m.x - 200, m.y - 168) <= 15]
    assert candidates
    mine = min(candidates, key=lambda m: abs(m.y - 168))
    assert abs(mine.y - 168) <= 2
    mine_iso = _angle_to_iso(mine.theta, mine.kind) * 360 / 256
    assert theirs.angle == pytest.approx(180.0, abs=2)           # geometria: w głąb linii (w lewo)
    assert _angle_diff_deg(mine_iso, theirs.angle) <= 10


def test_bifurcation_angle_agrees_with_nbis_only_after_the_180_degree_flip():
    img = _bifurcation_image()
    by = 24 + 24 * 17
    theirs = _nearest([m for m in _nbis_minutiae(img) if m.kind.name == "BIFURCATION"], 310, by, 30)
    mine = _nearest([m for m in process_image(img, Config()).minutiae if m.kind == BIFURCATION],
                    310, by, 30)
    assert theirs.angle == pytest.approx(0.0, abs=2) or theirs.angle == pytest.approx(360.0, abs=2)
    mine_iso = _angle_to_iso(mine.theta, mine.kind) * 360 / 256
    assert _angle_diff_deg(mine_iso, theirs.angle) <= 10          # z obrotem: zgodne z NBIS
    assert _angle_diff_deg(math.degrees(mine.theta), theirs.angle) >= 150   # bez obrotu: przeciwne
