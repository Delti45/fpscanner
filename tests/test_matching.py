"""Testy matchingu na syntetycznych szablonach (bez obrazów): pytest -q"""
import numpy as np
import pytest

from fpscanner.biometrics.matching import MatchConfig, match, match_bytes
from fpscanner.biometrics.preprocessing import Minutia, template_to_bytes
from fpscanner.tools.evaluate_fvc import equal_error_rate, fnmr_at_fmr

TWO_PI = 2 * np.pi


def random_template(rng, n=40, w=300, h=400) -> list[Minutia]:
    """Losowe minutie w elipsie (odcisk ~300x400 px)."""
    out = []
    while len(out) < n:
        x, y = rng.uniform(0, w), rng.uniform(0, h)
        if ((x - w / 2) / (w / 2)) ** 2 + ((y - h / 2) / (h / 2)) ** 2 < 1:
            out.append(Minutia(int(x), int(y), rng.uniform(0, TWO_PI),
                               int(rng.integers(0, 2))))
    return out


def distort(rng, ms, rot_deg=0.0, shift=(0, 0), pos_noise=2.5, ang_noise_deg=8.0,
            drop=0.2, spurious=0.15, w=300, h=400) -> list[Minutia]:
    """Druga odbitka tego samego palca: obrót, przesunięcie, szum, braki, fałszywe minutie."""
    phi = np.deg2rad(rot_deg)
    c, s = np.cos(phi), np.sin(phi)
    cx, cy = w / 2, h / 2
    out = []
    for m in ms:
        if rng.random() < drop:
            continue
        x, y = m.x - cx, -(m.y - cy)                       # y w górę
        xr, yr = c * x - s * y, s * x + c * y
        nx = xr + cx + shift[0] + rng.normal(0, pos_noise)
        ny = -(yr) + cy + shift[1] + rng.normal(0, pos_noise)   # z powrotem y w dół
        th = (m.theta + phi + np.deg2rad(rng.normal(0, ang_noise_deg))) % TWO_PI
        out.append(Minutia(int(round(nx)), int(round(ny)), th, m.kind))
    out += random_template(rng, int(len(ms) * spurious))
    return out


def test_identical_templates_score_one():
    rng = np.random.default_rng(0)
    t = random_template(rng)
    res = match(t, t)
    assert res.score > 0.95 and res.n_matched == len(t)


def test_rotated_shifted_copy_is_recovered():
    rng = np.random.default_rng(1)
    t = random_template(rng)
    moved = distort(rng, t, rot_deg=25, shift=(30, -20), pos_noise=0, ang_noise_deg=0,
                    drop=0, spurious=0)
    res = match(t, moved)
    assert res.score > 0.9
    assert abs(res.rotation_deg - 25) < 3       # sprawdza zgodność konwencji kątów/osi


def test_unrelated_templates_score_low():
    rng = np.random.default_rng(2)
    scores = [match(random_template(rng), random_template(rng)).score for _ in range(30)]
    assert np.mean(scores) < 0.12 and max(scores) < 0.35


def test_genuine_vs_impostor_separation():
    rng = np.random.default_rng(3)
    gen, imp = [], []
    for _ in range(60):
        base = random_template(rng)
        other = random_template(rng)
        probe = distort(rng, base, rot_deg=rng.uniform(-30, 30),
                        shift=(rng.uniform(-25, 25), rng.uniform(-25, 25)))
        gen.append(match(base, probe).score)
        imp.append(match(base, other).score)
    eer, _ = equal_error_rate(np.array(gen), np.array(imp))
    assert eer < 0.05
    assert np.median(gen) > 3 * np.median(imp)


def test_type_matching_switch():
    rng = np.random.default_rng(4)
    t = random_template(rng)
    flipped = [Minutia(m.x, m.y, m.theta, 1 - m.kind) for m in t]
    assert match(t, flipped, MatchConfig(match_types=True)).score < 0.2
    assert match(t, flipped, MatchConfig(match_types=False)).score > 0.9


def test_degenerate_inputs():
    rng = np.random.default_rng(5)
    t = random_template(rng)
    assert match([], t).score == 0.0
    assert match(t[:1], t).score == 0.0


def test_match_bytes_roundtrip():
    rng = np.random.default_rng(6)
    t = random_template(rng)
    res = match_bytes(template_to_bytes(t), template_to_bytes(t))
    assert res.score > 0.9      # kwantyzacja kąta w .tpl nie psuje dopasowania


def test_error_rate_helpers():
    gen = np.array([0.8, 0.7, 0.9, 0.6])
    imp = np.array([0.1, 0.2, 0.15, 0.3])
    eer, _ = equal_error_rate(gen, imp)
    assert eer == 0.0                            # rozdzielone idealnie
    assert fnmr_at_fmr(gen, imp, 0.0) == 0.0
    eer2, thr = equal_error_rate(imp, gen)       # odwrócone role -> EER = 1
    assert eer2 == pytest.approx(1.0)
