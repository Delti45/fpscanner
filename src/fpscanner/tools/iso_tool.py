#!/usr/bin/env python3
"""
fp-iso: konwersja szablonów między formatem projektu (.tpl) a ISO/IEC 19794-2:2005 oraz podgląd rekordu.

  fp-iso export odcisk.tpl odcisk.fmr --width 388 --height 374 [--dpi 500] [--finger-position 2]
  fp-iso import odcisk.fmr odcisk.tpl [--view 0] [--other ending|skip|error]
  fp-iso info   odcisk.fmr

Szablon .tpl nie przechowuje wymiarów obrazu, więc `export` wymaga ich jawnie (przy ekstrakcji
z obrazu wygodniej użyć `fp-extract --iso`, które zna rozmiar obrazu). Kod wyjścia: 0 sukces,
1 błąd danych (niepoprawny rekord, plik, parametry).
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from fpscanner.biometrics import iso19794 as iso
from fpscanner.biometrics.preprocessing import template_from_bytes, template_to_bytes


def _read_record(path: Path) -> bytes:
    size = path.stat().st_size
    if size > iso.MAX_RECORD_BYTES:                       # nie wczytujemy dowolnie dużych plików
        raise iso.IsoFormatError(f"plik większy niż dopuszczalny rekord ({iso.MAX_RECORD_BYTES} B)")
    return path.read_bytes()


def cmd_export(a: argparse.Namespace) -> int:
    minutiae = template_from_bytes(a.template.read_bytes())
    data = iso.minutiae_to_iso(minutiae, width=a.width, height=a.height, dpi=a.dpi,
                               finger_position=a.finger_position, view_number=a.view_number,
                               quality=a.quality)
    a.output.write_bytes(data)
    print(f"{a.output}: {len(minutiae)} minutii, {len(data)} B")
    return 0


def cmd_import(a: argparse.Namespace) -> int:
    minutiae = iso.minutiae_from_iso(_read_record(a.record), view=a.view, other=a.other)
    a.output.write_bytes(template_to_bytes(minutiae))
    print(f"{a.output}: {len(minutiae)} minutii")
    return 0


def cmd_info(a: argparse.Namespace) -> int:
    data = _read_record(a.record)
    rec = iso.decode_record(data)
    views = []
    for v in rec.views:
        kinds = [m.kind for m in v.minutiae]
        views.append({"finger_position": v.finger_position, "view_number": v.view_number,
                      "impression_type": v.impression_type, "quality": v.quality,
                      "minutiae": len(kinds), "endings": kinds.count(iso.TYPE_ENDING),
                      "bifurcations": kinds.count(iso.TYPE_BIFURCATION),
                      "other": kinds.count(iso.TYPE_OTHER)})
    print(json.dumps({
        "format": "ISO/IEC 19794-2:2005", "bytes": len(data), "width": rec.width, "height": rec.height,
        "resolution_px_per_cm": [rec.resolution_x, rec.resolution_y],
        "dpi": [round(iso.px_per_cm_to_dpi(rec.resolution_x)), round(iso.px_per_cm_to_dpi(rec.resolution_y))],
        "compliance": rec.compliance, "capture_device_id": rec.capture_device_id, "views": views},
        indent=1))
    return 0


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="fp-iso", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    ex = sub.add_parser("export", help=".tpl -> rekord ISO/IEC 19794-2:2005")
    ex.add_argument("template", type=Path)
    ex.add_argument("output", type=Path)
    ex.add_argument("--width", type=int, required=True, help="szerokość obrazu w px")
    ex.add_argument("--height", type=int, required=True, help="wysokość obrazu w px")
    ex.add_argument("--dpi", type=float, default=500)
    ex.add_argument("--finger-position", type=int, default=0, help="0 nieznany, 1-5 prawa, 6-10 lewa ręka")
    ex.add_argument("--view-number", type=int, default=0)
    ex.add_argument("--quality", type=int, default=100, help="jakość widoku 0-100 (norma: domyślnie 100)")
    ex.set_defaults(func=cmd_export)

    im = sub.add_parser("import", help="rekord ISO/IEC 19794-2:2005 -> .tpl")
    im.add_argument("record", type=Path)
    im.add_argument("output", type=Path)
    im.add_argument("--view", type=int, default=0, help="indeks widoku palca w rekordzie")
    im.add_argument("--other", choices=("ending", "skip", "error"), default="ending",
                    help="co zrobić z minutiami typu 'inny' (domyślnie: zakończenie)")
    im.set_defaults(func=cmd_import)

    inf = sub.add_parser("info", help="podsumowanie rekordu (JSON)")
    inf.add_argument("record", type=Path)
    inf.set_defaults(func=cmd_info)
    return ap


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (iso.IsoFormatError, ValueError, OSError) as e:
        print(f"błąd: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
