#!/usr/bin/env python3
"""
Preprocessing obrazów linii papilarnych (FVC2002 / FVC2004) i ekstrakcja minutiae.

Potok:
    obraz 8-bit grayscale
      -> segmentacja (maska odcisku, wariancja lokalna)
      -> normalizacja (Hong, Wan, Jain 1998)
      -> pole orientacji (metoda gradientowa)
      -> wzmocnienie filtrami Gabora
      -> binaryzacja -> szkieletyzacja (thinning)
      -> Crossing Number (zakończenia i rozwidlenia)
      -> post-processing (brzegi, spury, bliskie pary)
      -> filtr jakości (spójność orientacji, gęstość minutiae)
      -> wektor cech (szablon) -> serializacja do bajtów (pod AES-256-GCM)

Zależności: numpy, opencv-python (opcjonalnie scikit-image jako szybszy szkielet).

Użycie:
    python -m fpscanner.biometrics.preprocessing ścieżka/do/DB1_B --out wyniki --debug
    python -m fpscanner.biometrics.preprocessing 101_1.tif --debug
"""
from __future__ import annotations

import argparse
import json
import struct
from dataclasses import asdict, dataclass, field
from pathlib import Path

import cv2
import numpy as np

ENDING, BIFURCATION = 0, 1
KIND_NAMES = {ENDING: "ending", BIFURCATION: "bifurcation"}

# Sąsiedzi 8-spójni w kolejności cyklicznej (N, NE, E, SE, S, SW, W, NW) jako (dy, dx)
_RING = [(-1, 0), (-1, 1), (0, 1), (1, 1), (1, 0), (1, -1), (0, -1), (-1, -1)]


# --------------------------------------------------------------------------- #
# Konfiguracja
# --------------------------------------------------------------------------- #
@dataclass
class Config:
    # Normalizacja
    target_mean: float = 100.0
    target_var: float = 100.0

    # Segmentacja
    seg_block: int = 16            # okno liczenia lokalnego odchylenia std
    seg_min_std: float = 6.0       # dolny próg std (chroni przed pustymi obrazami)

    # Orientacja
    orient_sigma: float = 7.0      # wygładzanie tensora gradientów

    # Gabor – okres listew ~9 px odpowiada ok. 500 DPI; dla baz o innej
    # rozdzielczości skoryguj ridge_period (FVC ma różne DPI w różnych DB)
    ridge_period: float = 8.0
    gabor_sigma: float = 3.5
    gabor_size: int = 25
    n_orient: int = 16

    # Post-processing minutiae
    border_margin: int = 12        # odrzuć minutiae bliżej niż N px od brzegu maski
    min_dist: float = 6.0          # pary bliżej niż N px uznajemy za artefakt
    trace_len: int = 12            # ile pikseli szkieletu śledzić do wyznaczenia kąta
    min_branch_len: int = 6        # krótsze gałęzie = spur / szum

    # Filtr jakości
    min_coherence: float = 0.2    # minimalna spójność orientacji w punkcie (0..1)
    density_radius: float = 15.0   # promień szukania sąsiadów (px)
    density_max: int = 2           # więcej sąsiadów w promieniu => zaszumiony fragment


# --------------------------------------------------------------------------- #
# Struktury wyników
# --------------------------------------------------------------------------- #
@dataclass
class Minutia:
    x: int
    y: int
    theta: float   # radiany, [0, 2π), układ y w górę
    kind: int      # ENDING / BIFURCATION
    quality: float = 1.0   # spójność orientacji w punkcie (0..1); nie trafia do .tpl


@dataclass
class PipelineResult:
    mask: np.ndarray
    normalized: np.ndarray
    orientation: np.ndarray
    coherence: np.ndarray
    enhanced: np.ndarray
    binary: np.ndarray
    skeleton: np.ndarray
    minutiae: list[Minutia] = field(default_factory=list)
    stats: dict = field(default_factory=dict)
    rejected: list = field(default_factory=list)   # [(Minutia, powód), ...]


# --------------------------------------------------------------------------- #
# 1. Wczytanie
# --------------------------------------------------------------------------- #
def load_image(path: str | Path) -> np.ndarray:
    """Wczytuje obraz jako 8-bit grayscale (FVC to zwykle .tif/.bmp)."""
    img = cv2.imread(str(path), cv2.IMREAD_GRAYSCALE)
    if img is None:
        raise FileNotFoundError(f"Nie udało się wczytać obrazu: {path}")
    return img


# --------------------------------------------------------------------------- #
# 2. Segmentacja
# --------------------------------------------------------------------------- #
def segment(img: np.ndarray, cfg: Config) -> np.ndarray:
    """Maska obszaru z liniami papilarnymi (uint8 0/1) – lokalne odchylenie std."""
    f = img.astype(np.float32)
    k = (cfg.seg_block, cfg.seg_block)
    mean = cv2.blur(f, k)
    var = np.maximum(cv2.blur(f * f, k) - mean * mean, 0)
    std = np.sqrt(var)

    std8 = cv2.normalize(std, None, 0, 255, cv2.NORM_MINMAX).astype(np.uint8)
    otsu, _ = cv2.threshold(std8, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
    # Otsu liczony na znormalizowanej mapie -> przelicz próg na jednostki std
    thr = max(cfg.seg_min_std, otsu / 255.0 * float(std.max()) * 0.6)
    mask = (std > thr).astype(np.uint8)

    # Domknięcie / otwarcie, największa składowa, wypełnienie dziur
    ker = cv2.getStructuringElement(cv2.MORPH_ELLIPSE, (15, 15))
    mask = cv2.morphologyEx(mask, cv2.MORPH_CLOSE, ker)
    mask = cv2.morphologyEx(mask, cv2.MORPH_OPEN, ker)

    n, labels, stats, _ = cv2.connectedComponentsWithStats(mask, connectivity=8)
    if n <= 1:
        return np.zeros_like(mask)
    largest = 1 + int(np.argmax(stats[1:, cv2.CC_STAT_AREA]))
    mask = (labels == largest).astype(np.uint8)
    contours, _ = cv2.findContours(mask, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
    filled = np.zeros_like(mask)
    cv2.drawContours(filled, contours, -1, 1, thickness=cv2.FILLED)
    return filled


# --------------------------------------------------------------------------- #
# 3. Normalizacja
# --------------------------------------------------------------------------- #
def normalize(img: np.ndarray, mask: np.ndarray, cfg: Config) -> np.ndarray:
    """Normalizacja do zadanej średniej i wariancji; statystyki tylko z maski."""
    f = img.astype(np.float32)
    region = f[mask > 0] if mask.any() else f.ravel()
    m, v = float(region.mean()), float(region.var()) + 1e-6
    dev = np.sqrt(cfg.target_var * (f - m) ** 2 / v)
    out = np.where(f > m, cfg.target_mean + dev, cfg.target_mean - dev)
    return out.astype(np.float32)


# --------------------------------------------------------------------------- #
# 4. Pole orientacji
# --------------------------------------------------------------------------- #
def orientation_field(img: np.ndarray, cfg: Config) -> tuple[np.ndarray, np.ndarray]:
    """
    Zwraca (alpha, coherence).
    alpha     – orientacja NORMALNEJ do linii papilarnych (rad, [-π/2, π/2]);
                orientacja samej linii = alpha + π/2.
    coherence – spójność orientacji w [0, 1]: 1 = wszystkie gradienty w okolicy
                wskazują ten sam kierunek (wyraźne, równoległe linie),
                0 = kierunki chaotyczne (rozmazanie, szum, brak linii).
    """
    g = cv2.GaussianBlur(img, (0, 0), 1.0)
    gx = cv2.Sobel(g, cv2.CV_32F, 1, 0, ksize=3)
    gy = cv2.Sobel(g, cv2.CV_32F, 0, 1, ksize=3)
    gxx = cv2.GaussianBlur(gx * gx, (0, 0), cfg.orient_sigma)
    gyy = cv2.GaussianBlur(gy * gy, (0, 0), cfg.orient_sigma)
    gxy = cv2.GaussianBlur(gx * gy, (0, 0), cfg.orient_sigma)
    alpha = 0.5 * np.arctan2(2 * gxy, gxx - gyy)
    coh = np.sqrt((gxx - gyy) ** 2 + 4 * gxy ** 2) / (gxx + gyy + 1e-6)
    return alpha, np.clip(coh, 0.0, 1.0).astype(np.float32)


# --------------------------------------------------------------------------- #
# 5. Wzmocnienie Gaborem
# --------------------------------------------------------------------------- #
def gabor_enhance(img: np.ndarray, alpha: np.ndarray, mask: np.ndarray,
                  cfg: Config) -> np.ndarray:
    """Filtr Gabora dobierany per piksel wg lokalnej orientacji."""
    inv = -(img - img.mean())          # linie w FVC są ciemne -> odwracamy
    n = cfg.n_orient
    bank = []
    for k in range(n):
        ker = cv2.getGaborKernel((cfg.gabor_size, cfg.gabor_size), cfg.gabor_sigma,
                                 k * np.pi / n, cfg.ridge_period, 1.0, 0,
                                 ktype=cv2.CV_32F)
        ker -= ker.mean()              # brak składowej stałej
        bank.append(cv2.filter2D(inv, cv2.CV_32F, ker))
    idx = np.round(np.mod(alpha, np.pi) / (np.pi / n)).astype(np.int32) % n
    out = np.take_along_axis(np.stack(bank), idx[None], axis=0)[0]
    return out * mask


# --------------------------------------------------------------------------- #
# 6. Binaryzacja i szkieletyzacja
# --------------------------------------------------------------------------- #
def binarize(enhanced: np.ndarray, mask: np.ndarray) -> np.ndarray:
    b = ((enhanced > 0) & (mask > 0)).astype(np.uint8)
    return cv2.medianBlur(b * 255, 3).astype(np.uint8) // 255


def _zhang_suen(binary: np.ndarray) -> np.ndarray:
    """Wektorowa implementacja Zhang-Suen (fallback bez opencv-contrib/skimage)."""
    img = (binary > 0).astype(np.uint8)
    changed = True
    while changed:
        changed = False
        for step in (0, 1):
            p = np.pad(img, 1)
            n = [p[:-2, 1:-1], p[:-2, 2:], p[1:-1, 2:], p[2:, 2:],
                 p[2:, 1:-1], p[2:, :-2], p[1:-1, :-2], p[:-2, :-2]]
            B = sum(x.astype(np.int16) for x in n)
            A = sum(((n[i] == 0) & (n[(i + 1) % 8] == 1)).astype(np.int16)
                    for i in range(8))
            if step == 0:
                c = (n[0] * n[2] * n[4] == 0) & (n[2] * n[4] * n[6] == 0)
            else:
                c = (n[0] * n[2] * n[6] == 0) & (n[0] * n[4] * n[6] == 0)
            rm = (img == 1) & (B >= 2) & (B <= 6) & (A == 1) & c
            if rm.any():
                img[rm] = 0
                changed = True
    return img


def thin(binary: np.ndarray) -> np.ndarray:
    """Szkielet 1-px: opencv-contrib -> scikit-image -> własny Zhang-Suen."""
    b = (binary > 0).astype(np.uint8)
    ximgproc_thinning = getattr(getattr(cv2, "ximgproc", None), "thinning", None)
    if ximgproc_thinning is not None:      # w OpenCV 5 moduł ximgproc bywa pusty
        return (ximgproc_thinning(b * 255) > 0).astype(np.uint8)
    try:
        from skimage.morphology import skeletonize
        return skeletonize(b > 0).astype(np.uint8)
    except ImportError:
        return _zhang_suen(b)


# --------------------------------------------------------------------------- #
# 7. Crossing Number
# --------------------------------------------------------------------------- #
def crossing_number(skel: np.ndarray) -> np.ndarray:
    """CN = 0.5 * Σ|P_i - P_{i+1}| po 8 sąsiadach. CN=1: zakończenie, CN=3: rozwidlenie."""
    h, w = skel.shape
    s = np.pad(skel.astype(np.int8), 1)
    nb = [s[1 + dy:1 + dy + h, 1 + dx:1 + dx + w] for dy, dx in _RING]
    return sum(np.abs(nb[i] - nb[(i + 1) % 8]) for i in range(8)) // 2


def _free_neighbors(skel: np.ndarray, pt: tuple[int, int], visited: set):
    """Piksele szkieletu sąsiadujące z `pt`, których jeszcze nie odwiedzono."""
    h, w = skel.shape
    out = []
    for dy, dx in _RING:
        yy, xx = pt[0] + dy, pt[1] + dx
        if 0 <= yy < h and 0 <= xx < w and skel[yy, xx] and (yy, xx) not in visited:
            out.append((yy, xx))
    return out


def _branches(skel: np.ndarray, y: int, x: int, cfg: Config):
    """
    Dla piksela szkieletu zwraca listę gałęzi: (wektor_dy_dx, długość).
    Sąsiedzi tworzący ciągły łuk pierścienia to jedna gałąź. Podczas śledzenia
    gałęzi blokowane są tylko piksele INNYCH gałęzi – własne piksele łuku
    pozostają przejezdne (inaczej schodkowy szkielet urywa śledzenie po 1 px).
    """
    h, w = skel.shape
    ring = []
    for dy, dx in _RING:
        yy, xx = y + dy, x + dx
        ring.append(bool(0 <= yy < h and 0 <= xx < w and skel[yy, xx]))

    starts = [i for i in range(8) if ring[i] and not ring[i - 1]]   # początki łuków
    runs = []
    for i in starts:
        run, j = [], i
        while ring[j % 8] and len(run) < 8:
            dy, dx = _RING[j % 8]
            run.append((y + dy, x + dx))
            j += 1
        runs.append(run)

    out = []
    for r, run in enumerate(runs):
        others = {p for k, rr in enumerate(runs) if k != r for p in rr}
        visited = {(y, x)} | others
        cur, length = run[0], 1
        visited.add(cur)
        while length < cfg.trace_len:
            cands = _free_neighbors(skel, cur, visited)
            if not cands:
                break
            if len(cands) == 1:
                nxt = cands[0]
            else:
                # Wybierz piksel, za którym szkielet biegnie dalej (omiń ślepe
                # piksele narożne schodków), a pozostałych kandydatów zablokuj.
                cs = set(cands)
                nxt = max(cands, key=lambda c: len(
                    [q for q in _free_neighbors(skel, c, visited) if q not in cs]))
                visited.update(cs - {nxt})
            visited.add(nxt)
            cur, length = nxt, length + 1
        out.append(((cur[0] - y, cur[1] - x), length))
    return out


def _angle(dy: float, dx: float) -> float:
    """Kąt w układzie y-w-górę, [0, 2π)."""
    return float(np.arctan2(-dy, dx) % (2 * np.pi))


def _cluster_representatives(cand: np.ndarray) -> list[tuple[int, int]]:
    """
    Thinning często daje przy jednym rozwidleniu 2-3 sąsiednie piksele z CN=3.
    Łączymy je w spójne składowe i zwracamy po jednym pikselu (najbliżej środka).
    """
    n, labels = cv2.connectedComponents(cand.astype(np.uint8), connectivity=8)
    reps = []
    for lab in range(1, n):
        ys, xs = np.nonzero(labels == lab)
        cy, cx = ys.mean(), xs.mean()
        i = int(np.argmin((ys - cy) ** 2 + (xs - cx) ** 2))
        reps.append((int(ys[i]), int(xs[i])))
    return reps


def extract_minutiae(skel: np.ndarray, mask: np.ndarray, cfg: Config,
                     stats: dict | None = None,
                     coherence: np.ndarray | None = None,
                     rejected: list | None = None) -> list[Minutia]:
    """
    Kąt: dla zakończenia – kierunek wzdłuż linii od końca w głąb linii;
    dla rozwidlenia – kierunek wzdłuż pnia (gałęzi leżącej naprzeciw dwóch pozostałych).
    `stats` (opcjonalny słownik) dostaje liczniki odrzuceń – pomocne przy strojeniu.
    Gdy podano `coherence`, stosowany jest filtr jakości (patrz quality_filter);
    odrzucone minutie trafiają do listy `rejected` wraz z powodem.
    """
    cn = crossing_number(skel)
    sk = skel.astype(bool)
    safe = cv2.erode(mask, cv2.getStructuringElement(
        cv2.MORPH_ELLIPSE, (2 * cfg.border_margin + 1,) * 2))

    all_end = _cluster_representatives(sk & (cn == 1) & (mask > 0))
    all_bif = _cluster_representatives(sk & (cn == 3) & (mask > 0))
    cands = [(p, ENDING) for p in all_end] + [(p, BIFURCATION) for p in all_bif]
    n_cands = len(cands)
    cands = [(p, k) for p, k in cands if safe[p] > 0]
    n_border = n_cands - len(cands)

    found: list[Minutia] = []
    n_branch = 0
    for (y, x), kind in cands:
        br = _branches(skel, y, x, cfg)
        if kind == ENDING:
            if len(br) != 1 or br[0][1] < cfg.min_branch_len:
                n_branch += 1
                continue                                   # spur / szum
            (dy, dx), _ = br[0]
            found.append(Minutia(x, y, _angle(dy, dx), ENDING))
        else:
            if len(br) != 3 or min(l for _, l in br) < cfg.min_branch_len:
                n_branch += 1
                continue
            v = np.array([[d[0], d[1]] for d, _ in br], dtype=np.float32)
            v /= (np.linalg.norm(v, axis=1, keepdims=True) + 1e-9)
            ang = np.arccos(np.clip(v @ v.T, -1, 1))
            stem = int(np.argmax(ang.sum(axis=1)))         # najbardziej "z boku"
            found.append(Minutia(x, y, _angle(*br[stem][0]), BIFURCATION))

    after_close = _remove_close(found, cfg.min_dist)
    if coherence is not None:
        rej: list = [] if rejected is None else rejected
        n_before = len(rej)
        final = quality_filter(after_close, coherence, cfg, rej)
        new = rej[n_before:]
    else:
        final, new = after_close, []
    if stats is not None:
        stats.update(candidates=n_cands, rejected_border=n_border,
                     rejected_branch=n_branch,
                     rejected_close=len(found) - len(after_close),
                     rejected_coherence=sum(r == "coherence" for _, r in new),
                     rejected_density=sum(r == "density" for _, r in new),
                     kept=len(final))
    return final


def quality_filter(ms: list[Minutia], coherence: np.ndarray, cfg: Config,
                   rejected: list | None = None) -> list[Minutia]:
    """
    Filtr jakości minutiae:
      1) spójność orientacji w punkcie < min_coherence  -> fragment rozmazany;
      2) zbyt wiele innych minutiae w promieniu density_radius -> zaszumiony
         fragment (prawdziwe minutiae nie występują tak gęsto).
    Gęstość liczona jest względem WSZYSTKICH wejściowych minutiae, więc usuwane
    jest całe skupisko, a nie tylko jego część.
    """
    if not ms:
        return ms
    for m in ms:
        m.quality = float(coherence[m.y, m.x])

    p = np.array([[m.x, m.y] for m in ms], dtype=np.float32)
    d = np.linalg.norm(p[:, None] - p[None], axis=2)
    neighbors = (d <= cfg.density_radius).sum(axis=1) - 1     # bez siebie

    kept = []
    for m, n in zip(ms, neighbors):
        if m.quality < cfg.min_coherence:
            reason = "coherence"
        elif n > cfg.density_max:
            reason = "density"
        else:
            kept.append(m)
            continue
        if rejected is not None:
            rejected.append((m, reason))
    return kept


def _remove_close(ms: list[Minutia], min_dist: float) -> list[Minutia]:
    """Usuwa obie minutiae z pary leżącej bliżej niż min_dist (mostki, przerwy)."""
    if len(ms) < 2:
        return ms
    p = np.array([[m.x, m.y] for m in ms], dtype=np.float32)
    d = np.linalg.norm(p[:, None] - p[None], axis=2)
    np.fill_diagonal(d, np.inf)
    keep = d.min(axis=1) >= min_dist
    return [m for m, k in zip(ms, keep) if k]


# --------------------------------------------------------------------------- #
# Cały potok
# --------------------------------------------------------------------------- #
def process_image(img: np.ndarray, cfg: Config | None = None) -> PipelineResult:
    cfg = cfg or Config()
    mask = segment(img, cfg)
    norm = normalize(img, mask, cfg)
    alpha, coh = orientation_field(norm, cfg)
    enh = gabor_enhance(norm, alpha, mask, cfg)
    binary = binarize(enh, mask)
    skel = thin(binary) * mask
    stats: dict = {}
    rejected: list = []
    minutiae = extract_minutiae(skel, mask, cfg, stats, coh, rejected)
    return PipelineResult(mask=mask, normalized=norm, orientation=alpha,
                          coherence=coh, enhanced=enh, binary=binary,
                          skeleton=skel, minutiae=minutiae, stats=stats,
                          rejected=rejected)


# --------------------------------------------------------------------------- #
# Wektor cech / serializacja (wejście dla modułu kryptograficznego)
# --------------------------------------------------------------------------- #
def to_feature_vector(minutiae: list[Minutia]) -> np.ndarray:
    """Macierz (N, 4): x, y, theta, typ."""
    return np.array([[m.x, m.y, m.theta, m.kind] for m in minutiae],
                    dtype=np.float32).reshape(-1, 4)


def template_to_bytes(minutiae: list[Minutia]) -> bytes:
    """
    Deterministyczna, zwarta serializacja szablonu – to jest plaintext
    podawany do AES-256-GCM. Format (big-endian):
        wersja:u8 | N:u16 | N * (x:u16, y:u16, kąt:u16 [0..65535 ~ 0..2π], typ:u8)
    """
    buf = bytearray(struct.pack(">BH", 1, len(minutiae)))
    for m in minutiae:
        a = int(round(m.theta / (2 * np.pi) * 65536)) % 65536
        buf += struct.pack(">HHHB", m.x, m.y, a, m.kind)
    return bytes(buf)


def template_from_bytes(data: bytes) -> list[Minutia]:
    """Odwrotność `template_to_bytes`. ValueError dla każdych niepoprawnych danych
    (za krótkie, obcięte, bajty na końcu, nieznana wersja)."""
    if len(data) < 3:
        raise ValueError("Szablon jest za krótki")
    ver, n = struct.unpack_from(">BH", data, 0)
    if ver != 1:
        raise ValueError(f"Nieobsługiwana wersja szablonu: {ver}")
    if len(data) != 3 + 7 * n:
        raise ValueError("Długość szablonu nie zgadza się z liczbą minutiae")
    out, off = [], 3
    for _ in range(n):
        x, y, a, k = struct.unpack_from(">HHHB", data, off)
        off += 7
        out.append(Minutia(x, y, a / 65536 * 2 * np.pi, k))
    return out


# --------------------------------------------------------------------------- #
# Wizualizacja / CLI
# --------------------------------------------------------------------------- #
def debug_image(img: np.ndarray, res: PipelineResult) -> np.ndarray:
    def to_bgr(a):
        return cv2.cvtColor(a, cv2.COLOR_GRAY2BGR)

    norm8 = cv2.normalize(res.normalized, None, 0, 255, cv2.NORM_MINMAX).astype(np.uint8)
    enh8 = cv2.normalize(res.enhanced, None, 0, 255, cv2.NORM_MINMAX).astype(np.uint8)
    overlay = to_bgr(img.copy())
    overlay[res.skeleton > 0] = (0, 200, 0)
    for m in res.minutiae:
        color = (0, 0, 255) if m.kind == ENDING else (255, 0, 0)
        cv2.circle(overlay, (m.x, m.y), 4, color, 1)
        tip = (int(m.x + 10 * np.cos(m.theta)), int(m.y - 10 * np.sin(m.theta)))
        cv2.line(overlay, (m.x, m.y), tip, color, 1)
    # odrzucone: żółty krzyżyk = zła spójność, fioletowy = zbyt gęsto
    for m, reason in res.rejected:
        color = (0, 220, 255) if reason == "coherence" else (200, 0, 200)
        cv2.drawMarker(overlay, (m.x, m.y), color, cv2.MARKER_TILTED_CROSS, 7, 1)
    coh8 = (np.clip(res.coherence, 0, 1) * 255).astype(np.uint8)
    coh_map = cv2.applyColorMap(coh8, cv2.COLORMAP_JET)
    coh_map[res.mask == 0] = 0
    panels = [to_bgr(img), to_bgr(norm8), to_bgr(res.mask * 255),
              coh_map, to_bgr(enh8), overlay]
    return np.hstack(panels)


def _collect(path: Path) -> list[Path]:
    if path.is_file():
        return [path]
    exts = {".tif", ".tiff", ".bmp", ".png", ".jpg"}
    return sorted(p for p in path.rglob("*") if p.suffix.lower() in exts)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("input", type=Path, help="plik obrazu lub katalog (np. DB1_B)")
    ap.add_argument("--out", type=Path, default=Path("output"))
    ap.add_argument("--debug", action="store_true", help="zapisz obrazy poglądowe")
    ap.add_argument("--period", type=float, default=Config.ridge_period,
                    help="okres linii papilarnych w px (dla innego DPI)")
    ap.add_argument("--margin", type=int, default=Config.border_margin,
                    help="margines od brzegu maski (px), w którym odrzucamy minutiae")
    ap.add_argument("--min-dist", type=float, default=Config.min_dist,
                    help="minimalna odległość między minutiami (px)")
    ap.add_argument("--min-branch", type=int, default=Config.min_branch_len,
                    help="minimalna długość gałęzi szkieletu (px)")
    ap.add_argument("--min-coherence", type=float, default=Config.min_coherence,
                    help="minimalna spójność orientacji (0 = wyłącz ten filtr)")
    ap.add_argument("--density-max", type=int, default=Config.density_max,
                    help="maks. liczba sąsiadów w promieniu (duża liczba = wyłącz)")
    ap.add_argument("--density-radius", type=float, default=Config.density_radius,
                    help="promień filtra gęstości (px)")
    ap.add_argument("--iso", action="store_true",
                    help="zapisz też rekord ISO/IEC 19794-2:2005 (<nazwa>.fmr) z wymiarami obrazu")
    ap.add_argument("--dpi", type=float, default=500, help="rozdzielczość obrazu zapisywana w rekordzie ISO")
    ap.add_argument("--finger-position", type=int, default=0,
                    help="pozycja palca w rekordzie ISO (0 nieznany, 1-5 prawa, 6-10 lewa ręka)")
    args = ap.parse_args()

    cfg = Config(ridge_period=args.period, border_margin=args.margin,
                 min_dist=args.min_dist, min_branch_len=args.min_branch,
                 min_coherence=args.min_coherence, density_max=args.density_max,
                 density_radius=args.density_radius)
    args.out.mkdir(parents=True, exist_ok=True)
    files = _collect(args.input)
    if not files:
        raise SystemExit("Nie znaleziono obrazów.")

    for f in files:
        img = load_image(f)
        res = process_image(img, cfg)
        stem = f.stem
        (args.out / f"{stem}.json").write_text(json.dumps(
            {"file": f.name, "shape": list(img.shape),
             "minutiae": [{**asdict(m), "kind": KIND_NAMES[m.kind]}
                          for m in res.minutiae]}, indent=1))
        (args.out / f"{stem}.tpl").write_bytes(template_to_bytes(res.minutiae))
        if args.iso:
            from fpscanner.biometrics.iso19794 import minutiae_to_iso  # lokalnie: unikamy cyklu importów
            (args.out / f"{stem}.fmr").write_bytes(minutiae_to_iso(
                res.minutiae, width=img.shape[1], height=img.shape[0], dpi=args.dpi,
                finger_position=args.finger_position))
        if args.debug:
            cv2.imwrite(str(args.out / f"{stem}_debug.png"), debug_image(img, res))
        print(f"{f.name}: {len(res.minutiae)} minutiae  {res.stats}")


if __name__ == "__main__":
    main()
