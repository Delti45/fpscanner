#!/usr/bin/env python3
"""
Dopasowanie szablonów minutiae (matching 1:1).

Moduł jest niezależny od obrazów: przyjmuje listy `Minutia` z
`fingerprint_preprocessing` (albo bajty szablonu .tpl) i zwraca wynik
podobieństwa w [0, 1].

Algorytm:
  1. Oba szablony przesuwamy do środka ciężkości (układy współrzędnych
     względem własnych centroidów, oś y skierowana w górę).
  2. Głosowanie Hougha po parach (minutia A, minutia B tego samego typu):
     każda para zakłada pewien obrót dθ i przesunięcie t. Głosy trafiają do
     koszyków (dθ, tx, ty); najliczniejsze koszyki to kandydaci na wyrównanie.
  3. Dla każdego kandydata: parowanie 1:1 (zachłannie wg odległości, z
     tolerancją położenia i kąta), doprecyzowanie transformacji metodą
     najmniejszych kwadratów (Kabsch 2D) i ponowne parowanie. Zwycięża
     wyrównanie z największą liczbą par (remis: mniejsza średnia odległość).
  4. Wynik zależy od `score_mode`:
       "total"   (domyślny): n² / (N_A · N_B), N_* = liczba wszystkich minutiae;
       "overlap": n² / (N_A_ov · N_B_ov), N_*_ov = minutie we wspólnym obszarze
                  (otoczki wypukłe) – uwzględnia częściowe nakładanie, ale na
                  danych testowych był mniej odporny na artefakty.
     W obu trybach mianowniki mają dolne ograniczenie `min_overlap_count`.

Użycie:
    from fpscanner.biometrics.matching import match, match_bytes
    res = match(minutiae_a, minutiae_b)
    if res.score >= 0.25: ...
"""
from __future__ import annotations

from dataclasses import dataclass, field

import cv2
import numpy as np

from fpscanner.biometrics.preprocessing import Minutia, template_from_bytes

TWO_PI = 2 * np.pi


# --------------------------------------------------------------------------- #
# Konfiguracja i wynik
# --------------------------------------------------------------------------- #
@dataclass
class MatchConfig:
    # Tolerancje parowania (px / stopnie); ok. 1,5 okresu linii dla 500 DPI
    dist_tol: float = 15.0          # na FVC DB1_A: 15 px najlepsze pod względem FNMR@FMR
    angle_tol_deg: float = 12.0
    match_types: bool = False       # True: zakończenie tylko z zakończeniem; False dało niższy EER na Db1_a
    # Głosowanie Hougha
    hough_angle_bin_deg: float = 16.0
    hough_trans_bin: float = 20.0
    n_candidates: int = 8           # ile najlepszych koszyków sprawdzamy (więcej nie poprawia wyniku)
    refine_iters: int = 2           # iteracje doprecyzowania transformacji
    # Wynik
    score_mode: str = "total"       # "total" albo "overlap" (patrz docstring modułu)
    overlap_margin: float = 12.0    # tolerancja obszaru wspólnego (tryb "overlap", px)
    min_overlap_count: int = 10     # dolne ograniczenie mianowników


@dataclass
class MatchResult:
    score: float                    # [0, 1]
    n_matched: int
    n_overlap_a: int
    n_overlap_b: int
    rotation_deg: float = 0.0       # obrót A względem B (przeciwnie do ruchu wskazówek)
    translation: tuple[float, float] = (0.0, 0.0)
    pairs: list[tuple[int, int]] = field(default_factory=list)  # indeksy (A, B)


_EMPTY = MatchResult(0.0, 0, 0, 0)


# --------------------------------------------------------------------------- #
# Narzędzia geometryczne
# --------------------------------------------------------------------------- #
def _wrap(a: np.ndarray | float) -> np.ndarray | float:
    """Zawija kąt do [-π, π)."""
    return (a + np.pi) % TWO_PI - np.pi


def _rot(phi: float) -> np.ndarray:
    c, s = np.cos(phi), np.sin(phi)
    return np.array([[c, -s], [s, c]])


def _to_array(ms: list[Minutia]) -> np.ndarray:
    """(N, 4): x, y_w_górę, theta, typ. Kąty w Minutia są już w układzie y-w-górę."""
    return np.array([[m.x, -m.y, m.theta, m.kind] for m in ms], dtype=np.float64)


def _assign(a_pos: np.ndarray, a_th: np.ndarray, a_kind: np.ndarray,
            b_pos: np.ndarray, b_th: np.ndarray, b_kind: np.ndarray,
            cfg: MatchConfig) -> list[tuple[int, int]]:
    """Parowanie 1:1: najbliższe dopuszczalne pary mają pierwszeństwo."""
    d = np.linalg.norm(a_pos[:, None, :] - b_pos[None, :, :], axis=2)
    dth = np.abs(_wrap(a_th[:, None] - b_th[None, :]))
    ok = (d <= cfg.dist_tol) & (dth <= np.deg2rad(cfg.angle_tol_deg))
    if cfg.match_types:
        ok &= a_kind[:, None] == b_kind[None, :]
    ii, jj = np.nonzero(ok)
    order = np.argsort(d[ii, jj], kind="stable")
    used_a = np.zeros(len(a_pos), bool)
    used_b = np.zeros(len(b_pos), bool)
    pairs = []
    for k in order:
        i, j = int(ii[k]), int(jj[k])
        if used_a[i] or used_b[j]:
            continue
        used_a[i] = used_b[j] = True
        pairs.append((i, j))
    return pairs


def _fit_rigid(pa: np.ndarray, pb: np.ndarray) -> tuple[float, np.ndarray]:
    """Obrót + przesunięcie (min. kwadraty) przeprowadzające pa na pb."""
    ca, cb = pa.mean(axis=0), pb.mean(axis=0)
    a, b = pa - ca, pb - cb
    phi = float(np.arctan2((a[:, 0] * b[:, 1] - a[:, 1] * b[:, 0]).sum(),
                           (a * b).sum()))
    return phi, cb - _rot(phi) @ ca


def _inside_hull(points: np.ndarray, hull_src: np.ndarray, margin: float) -> np.ndarray:
    """Które z `points` leżą w otoczce wypukłej `hull_src` (z tolerancją)."""
    if len(hull_src) < 3:
        return np.ones(len(points), bool)
    hull = cv2.convexHull(hull_src.astype(np.float32))
    if len(hull) < 3:
        return np.ones(len(points), bool)
    return np.array([cv2.pointPolygonTest(hull, (float(x), float(y)), True) >= -margin
                     for x, y in points])


# --------------------------------------------------------------------------- #
# Dopasowanie
# --------------------------------------------------------------------------- #
def _align(pa, tha, ka, pb, thb, kb, phi, t, cfg):
    """Doprecyzowuje wyrównanie (phi, t) i zwraca (phi, t, pary, średni błąd)."""
    for _ in range(cfg.refine_iters):
        pairs = _assign(pa @ _rot(phi).T + t, tha + phi, ka, pb, thb, kb, cfg)
        if len(pairs) < 2:
            break
        i, j = zip(*pairs)
        phi, t = _fit_rigid(pa[list(i)], pb[list(j)])

    pa_t = pa @ _rot(phi).T + t
    pairs = _assign(pa_t, tha + phi, ka, pb, thb, kb, cfg)
    if pairs:
        i, j = zip(*pairs)
        resid = float(np.linalg.norm(pa_t[list(i)] - pb[list(j)], axis=1).mean())
    else:
        resid = float("inf")
    return phi, t, pairs, resid


def _finalize(pa, pb, phi, t, pairs, cfg) -> MatchResult:
    """Liczy wynik dla wybranego wyrównania."""
    n = len(pairs)
    rot_deg, trans = float(np.rad2deg(phi)), (float(t[0]), float(t[1]))
    if n == 0:
        return MatchResult(0.0, 0, 0, 0, rot_deg, trans)
    if cfg.score_mode == "overlap":
        pa_t = pa @ _rot(phi).T + t
        n_a = max(int(_inside_hull(pa_t, pb, cfg.overlap_margin).sum()), n)
        n_b = max(int(_inside_hull(pb, pa_t, cfg.overlap_margin).sum()), n)
    elif cfg.score_mode == "total":
        n_a, n_b = len(pa), len(pb)
    else:
        raise ValueError(f"Nieznany score_mode: {cfg.score_mode!r}")
    floor = cfg.min_overlap_count
    score = min(1.0, n * n / (max(n_a, floor) * max(n_b, floor)))
    return MatchResult(score, n, n_a, n_b, rot_deg, trans, pairs)


def match(a: list[Minutia], b: list[Minutia],
          cfg: MatchConfig | None = None) -> MatchResult:
    """Porównuje dwa szablony. Wynik 1.0 = identyczne, ~0 = niezwiązane."""
    cfg = cfg or MatchConfig()
    if len(a) < 2 or len(b) < 2:
        return _EMPTY

    A, B = _to_array(a), _to_array(b)
    ca, cb = A[:, :2].mean(axis=0), B[:, :2].mean(axis=0)
    pa, pb = A[:, :2] - ca, B[:, :2] - cb
    tha, thb, ka, kb = A[:, 2], B[:, 2], A[:, 3], B[:, 3]

    # --- głosowanie Hougha po parach minutiae ---
    allowed = (ka[:, None] == kb[None, :]) if cfg.match_types \
        else np.ones((len(A), len(B)), bool)
    I, J = np.nonzero(allowed)
    if len(I) == 0:
        return _EMPTY
    dth = _wrap(thb[J] - tha[I])
    c, s = np.cos(dth), np.sin(dth)
    tx = pb[J, 0] - (c * pa[I, 0] - s * pa[I, 1])
    ty = pb[J, 1] - (s * pa[I, 0] + c * pa[I, 1])

    abin = np.floor((dth + np.pi) / np.deg2rad(cfg.hough_angle_bin_deg)).astype(np.int64)
    xbin = np.floor(tx / cfg.hough_trans_bin).astype(np.int64) + 5000
    ybin = np.floor(ty / cfg.hough_trans_bin).astype(np.int64) + 5000
    keys = (abin * 10007 + xbin) * 10007 + ybin
    uniq, inverse, counts = np.unique(keys, return_inverse=True, return_counts=True)

    best = None                       # (n_par, -błąd, phi, t, pary)
    for u in np.argsort(counts)[::-1][:cfg.n_candidates]:
        sel = inverse == u
        phi = float(np.arctan2(np.sin(dth[sel]).sum(), np.cos(dth[sel]).sum()))
        t = np.array([tx[sel].mean(), ty[sel].mean()])
        phi, t, pairs, resid = _align(pa, tha, ka, pb, thb, kb, phi, t, cfg)
        key = (len(pairs), -resid)
        if best is None or key > best[0]:
            best = (key, phi, t, pairs)
    if best is None:
        return _EMPTY
    _, phi, t, pairs = best
    return _finalize(pa, pb, phi, t, pairs, cfg)


def match_bytes(tpl_a: bytes, tpl_b: bytes,
                cfg: MatchConfig | None = None) -> MatchResult:
    """Porównuje dwa szablony w formacie .tpl (np. po odszyfrowaniu na serwerze)."""
    return match(template_from_bytes(tpl_a), template_from_bytes(tpl_b), cfg)
