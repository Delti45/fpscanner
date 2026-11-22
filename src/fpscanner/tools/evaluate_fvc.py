#!/usr/bin/env python3
"""
Ocena jakości systemu (FMR / FNMR / EER) na bazach FVC2002 / FVC2004.

Protokół (jak w FVC, przy założeniu symetrycznego matchingu):
  * genuine  – wszystkie pary różnych odbitek tego samego palca (i < j),
               np. 8 odbitek -> 28 par na palec;
  * impostor – pierwsza odbitka palca A z pierwszą odbitką palca B, dla
               wszystkich par palców (A < B).
Nazwy plików muszą mieć postać <palec>_<odbitka>.<rozszerzenie> (np. 101_1.tif).

Szablony są liczone raz i zapisywane w cache (osobno dla każdej konfiguracji
preprocessingu), więc zmiana parametrów MATCHINGU nie wymaga ponownego
liczenia obrazów.

Przykłady:
    python -m fpscanner.tools.evaluate_fvc FVC2002/Db1_b --out wyniki --jobs 4
    python -m fpscanner.tools.evaluate_fvc FVC2002/Db1_b --min-coherence 0.2
    python -m fpscanner.tools.evaluate_fvc FVC2002/Db1_b --sweep min_coherence 0 0.2 0.3 0.4
    python -m fpscanner.tools.evaluate_fvc FVC2002/Db1_b --sweep dist_tol 8 10 12 15
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import itertools
import json
import re
import time
from concurrent.futures import ProcessPoolExecutor
from dataclasses import asdict, fields
from pathlib import Path

import numpy as np

from fpscanner.biometrics.matching import MatchConfig, match
from fpscanner.biometrics.preprocessing import Config, Minutia, load_image, process_image

FNAME = re.compile(r"^(\d+)_(\d+)\.\w+$")
IMG_EXT = {".tif", ".tiff", ".bmp", ".png", ".jpg"}


# --------------------------------------------------------------------------- #
# Metryki błędów
# --------------------------------------------------------------------------- #
def error_rates(genuine: np.ndarray, impostor: np.ndarray):
    """
    Zwraca (progi, FMR, FNMR); wynik >= próg = akceptacja.
    FMR(t)  = odsetek impostorów z wynikiem >= t  (fałszywa akceptacja),
    FNMR(t) = odsetek genuine z wynikiem <  t     (fałszywe odrzucenie).
    """
    g, i = np.sort(genuine), np.sort(impostor)
    thr = np.unique(np.concatenate([g, i]))
    thr = np.append(thr, thr[-1] + 1e-9)               # próg powyżej maksimum: FMR = 0
    fmr = 1.0 - np.searchsorted(i, thr, side="left") / len(i)
    fnmr = np.searchsorted(g, thr, side="left") / len(g)
    return thr, fmr, fnmr


def equal_error_rate(genuine: np.ndarray, impostor: np.ndarray) -> tuple[float, float]:
    """EER (interpolowany liniowo) i próg, przy którym występuje."""
    thr, fmr, fnmr = error_rates(genuine, impostor)
    idx = int(np.argmax(fmr <= fnmr))                  # pierwszy próg po przecięciu
    if idx == 0:
        return float(0.5 * (fmr[0] + fnmr[0])), float(thr[0])
    d0 = fmr[idx - 1] - fnmr[idx - 1]
    d1 = fmr[idx] - fnmr[idx]
    w = d0 / (d0 - d1) if d0 != d1 else 1.0
    eer = fmr[idx - 1] + w * (fmr[idx] - fmr[idx - 1])
    return float(eer), float(thr[idx - 1] + w * (thr[idx] - thr[idx - 1]))


def fnmr_at_fmr(genuine: np.ndarray, impostor: np.ndarray, target_fmr: float) -> float:
    """Najmniejszy FNMR, przy którym FMR <= target_fmr."""
    _, fmr, fnmr = error_rates(genuine, impostor)
    return float(fnmr[fmr <= target_fmr].min())


# --------------------------------------------------------------------------- #
# Zbiór danych i szablony
# --------------------------------------------------------------------------- #
def scan_dataset(root: Path) -> dict[int, dict[int, Path]]:
    """{palec: {odbitka: ścieżka}} dla plików o nazwach <palec>_<odbitka>.<ext>."""
    data: dict[int, dict[int, Path]] = {}
    for p in sorted(root.rglob("*")):
        m = FNAME.match(p.name)
        if m and p.suffix.lower() in IMG_EXT:
            data.setdefault(int(m.group(1)), {})[int(m.group(2))] = p
    return data


def genuine_pairs(data) -> list[tuple[tuple[int, int], tuple[int, int]]]:
    return [((f, a), (f, b)) for f, imps in data.items()
            for a, b in itertools.combinations(sorted(imps), 2)]


def impostor_pairs(data) -> list[tuple[tuple[int, int], tuple[int, int]]]:
    first = {f: (f, min(imps)) for f, imps in data.items()}
    return [(first[a], first[b]) for a, b in itertools.combinations(sorted(first), 2)]


def _extract_one(job):
    path, cfg_dict = job
    res = process_image(load_image(path), Config(**cfg_dict))
    return [(m.x, m.y, m.theta, m.kind, m.quality) for m in res.minutiae]


def cfg_hash(cfg: Config) -> str:
    return hashlib.md5(json.dumps(asdict(cfg), sort_keys=True).encode()).hexdigest()[:10]


def load_templates(data, cfg: Config, cache_dir: Path, jobs: int
                   ) -> dict[tuple[int, int], list[Minutia]]:
    """Szablony wszystkich obrazów; z cache, a brakujące liczone równolegle."""
    folder = cache_dir / cfg_hash(cfg)
    folder.mkdir(parents=True, exist_ok=True)
    templates, todo = {}, []
    for f, imps in data.items():
        for i, path in imps.items():
            cache = folder / f"{f}_{i}.json"
            if cache.exists():
                raw = json.loads(cache.read_text())
                templates[(f, i)] = [Minutia(*r) for r in raw]
            else:
                todo.append(((f, i), path, cache))
    if todo:
        print(f"  liczenie minutiae: {len(todo)} obrazów (cache: {folder})")
        work = [(str(p), asdict(cfg)) for _, p, _ in todo]
        if jobs > 1:
            with ProcessPoolExecutor(max_workers=jobs) as ex:
                results = list(ex.map(_extract_one, work, chunksize=4))
        else:
            results = [_extract_one(w) for w in work]
        for (key, _, cache), raw in zip(todo, results):
            cache.write_text(json.dumps(raw))
            templates[key] = [Minutia(int(x), int(y), th, k, q) for x, y, th, k, q in raw]
    # elementy z cache mają typ int/float z JSON – ujednolić
    return {k: [Minutia(int(m.x), int(m.y), float(m.theta), int(m.kind), float(m.quality))
                for m in v] for k, v in templates.items()}


def score_pairs(templates, pairs, mcfg: MatchConfig, label: str):
    scores, rows, t0 = [], [], time.time()
    for n, (a, b) in enumerate(pairs, 1):
        res = match(templates[a], templates[b], mcfg)
        scores.append(res.score)
        rows.append((label, a[0], a[1], b[0], b[1], round(res.score, 5), res.n_matched,
                     round(res.rotation_deg, 1), round(res.translation[0], 1),
                     round(res.translation[1], 1), len(templates[a]), len(templates[b])))
        if n % 1000 == 0:
            print(f"  {label}: {n}/{len(pairs)} ({time.time() - t0:.0f}s)")
    return np.array(scores), rows


# --------------------------------------------------------------------------- #
# Eksperyment
# --------------------------------------------------------------------------- #
def run_experiment(data, cfg: Config, mcfg: MatchConfig, args) -> dict:
    templates = load_templates(data, cfg, args.cache, args.jobs)
    counts = np.array([len(v) for v in templates.values()])
    gen, rows_g = score_pairs(templates, genuine_pairs(data), mcfg, "genuine")
    imp, rows_i = score_pairs(templates, impostor_pairs(data), mcfg, "impostor")
    eer, eer_thr = equal_error_rate(gen, imp)
    report = {
        "preprocessing": asdict(cfg), "matching": asdict(mcfg),
        "n_images": len(templates), "n_genuine": len(gen), "n_impostor": len(imp),
        "minutiae_mean": float(counts.mean()), "minutiae_min": int(counts.min()),
        "EER": eer, "EER_threshold": eer_thr,
        "FNMR@FMR=1%": fnmr_at_fmr(gen, imp, 0.01),
        "FNMR@FMR=0.1%": fnmr_at_fmr(gen, imp, 0.001),
        "genuine_median": float(np.median(gen)), "impostor_median": float(np.median(imp)),
    }
    return {"report": report, "rows": rows_g + rows_i, "gen": gen, "imp": imp}


def save_outputs(out: Path, result: dict, tag: str = "") -> None:
    out.mkdir(parents=True, exist_ok=True)
    suffix = f"_{tag}" if tag else ""
    with open(out / f"scores{suffix}.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["type", "finger_a", "impr_a", "finger_b", "impr_b", "score", "n_matched",
                    "rotation_deg", "tx", "ty", "n_minutiae_a", "n_minutiae_b"])
        w.writerows(result["rows"])
    (out / f"report{suffix}.json").write_text(json.dumps(result["report"], indent=1))
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        thr, fmr, fnmr = error_rates(result["gen"], result["imp"])
        fig, ax = plt.subplots(1, 2, figsize=(11, 4))
        ax[0].hist(result["imp"], bins=40, alpha=.6, label="impostor", density=True)
        ax[0].hist(result["gen"], bins=40, alpha=.6, label="genuine", density=True)
        ax[0].set(xlabel="wynik dopasowania", title="Rozkłady wyników")
        ax[0].legend()
        ax[1].loglog(np.maximum(fmr, 1e-5), np.maximum(fnmr, 1e-5))
        ax[1].set(xlabel="FMR", ylabel="FNMR", title="Krzywa DET")
        ax[1].grid(True, which="both", alpha=.3)
        fig.tight_layout()
        fig.savefig(out / f"plots{suffix}.png", dpi=120)
        plt.close(fig)
    except ImportError:
        pass


# --------------------------------------------------------------------------- #
# CLI: parametry obu konfiguracji generowane z dataclass
# --------------------------------------------------------------------------- #
_TYPES = {"int": int, "float": float, "str": str,
          "bool": lambda s: s.lower() in ("1", "true", "yes", "tak")}


def _add_args(ap: argparse.ArgumentParser, cls, group_name: str) -> None:
    group = ap.add_argument_group(group_name)
    for f in fields(cls):
        group.add_argument("--" + f.name.replace("_", "-"), dest=f.name,
                           type=_TYPES[f.type], default=None,
                           help=f"(domyślnie {f.default})")


def _build(cls, args):
    return cls(**{f.name: getattr(args, f.name) for f in fields(cls)
                  if getattr(args, f.name, None) is not None})


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("dataset", type=Path, help="katalog bazy FVC (np. FVC2002/Db1_b)")
    ap.add_argument("--out", type=Path, default=Path("eval_output"))
    ap.add_argument("--cache", type=Path, default=Path("cache_minutiae"))
    ap.add_argument("--jobs", type=int, default=1, help="procesy do liczenia minutiae")
    ap.add_argument("--sweep", nargs="+", metavar=("PARAM", "WARTOŚĆ"),
                    help="przeleć parametr po wartościach, np. --sweep min_coherence 0 0.2 0.3")
    _add_args(ap, Config, "Parametry preprocessingu")
    _add_args(ap, MatchConfig, "Parametry matchingu")
    args = ap.parse_args()
    args.cache = args.cache / hashlib.md5(str(args.dataset.resolve()).encode()).hexdigest()[:8]
    
    data = scan_dataset(args.dataset)
    if not data:
        raise SystemExit(f"Brak plików <palec>_<odbitka>.<ext> w {args.dataset}")
    print(f"Palców: {len(data)}, obrazów: {sum(len(v) for v in data.values())}, "
          f"genuine: {len(genuine_pairs(data))}, impostor: {len(impostor_pairs(data))}")

    base_cfg, base_mcfg = _build(Config, args), _build(MatchConfig, args)

    if not args.sweep:
        result = run_experiment(data, base_cfg, base_mcfg, args)
        save_outputs(args.out, result)
        r = result["report"]
        print(f"\nEER = {r['EER']:.2%} (próg {r['EER_threshold']:.3f})   "
              f"FNMR@FMR=1%: {r['FNMR@FMR=1%']:.2%}   "
              f"FNMR@FMR=0.1%: {r['FNMR@FMR=0.1%']:.2%}")
        print(f"minutiae/obraz: średnio {r['minutiae_mean']:.1f}, min {r['minutiae_min']}")
        return

    name = args.sweep[0].replace("-", "_")
    owner = Config if name in {f.name for f in fields(Config)} else MatchConfig
    if name not in {f.name for f in fields(owner)}:
        raise SystemExit(f"Nieznany parametr: {name}")
    caster = _TYPES[next(f.type for f in fields(owner) if f.name == name)]
    print(f"\n{'wartość':>10} | {'EER':>7} | {'FNMR@1%':>8} | {'minutiae/obraz':>14}")
    for raw in args.sweep[1:]:
        value = caster(raw)
        cfg = Config(**{**asdict(base_cfg), **({name: value} if owner is Config else {})})
        mcfg = MatchConfig(**{**asdict(base_mcfg), **({name: value} if owner is MatchConfig else {})})
        result = run_experiment(data, cfg, mcfg, args)
        save_outputs(args.out, result, tag=f"{name}={value}")
        r = result["report"]
        print(f"{value:>10} | {r['EER']:>7.2%} | {r['FNMR@FMR=1%']:>8.2%} | {r['minutiae_mean']:>14.1f}")


if __name__ == "__main__":
    main()
