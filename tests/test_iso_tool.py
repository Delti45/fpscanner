"""Testy narzędzi: fp-iso (export / import / info) oraz fp-extract --iso."""
import json
import math
import sys

import cv2
import numpy as np
import pytest

from fpscanner.biometrics import iso19794 as iso
from fpscanner.biometrics import preprocessing
from fpscanner.biometrics.preprocessing import (
    BIFURCATION,
    ENDING,
    Minutia,
    template_from_bytes,
    template_to_bytes,
)
from fpscanner.tools.iso_tool import main


def _minutiae():
    return [Minutia(100, 200, math.pi / 2, ENDING), Minutia(150, 250, 3.0, BIFURCATION),
            Minutia(20, 30, 0.5, ENDING)]


def test_export_import_roundtrip_through_files(tmp_path, capsys):
    tpl, fmr, back = tmp_path / "a.tpl", tmp_path / "a.fmr", tmp_path / "b.tpl"
    tpl.write_bytes(template_to_bytes(_minutiae()))
    assert main(["export", str(tpl), str(fmr), "--width", "300", "--height", "400",
                 "--finger-position", "2"]) == 0
    rec = iso.decode_record(fmr.read_bytes())
    assert (rec.width, rec.height, rec.resolution_x) == (300, 400, 197)
    assert rec.views[0].finger_position == 2 and len(rec.views[0].minutiae) == 3
    assert main(["import", str(fmr), str(back)]) == 0
    got = template_from_bytes(back.read_bytes())
    assert [(m.x, m.y, m.kind) for m in got] == [(m.x, m.y, m.kind) for m in _minutiae()]


def test_info_prints_json_summary(tmp_path, capsys):
    fmr = tmp_path / "a.fmr"
    fmr.write_bytes(iso.minutiae_to_iso(_minutiae(), width=300, height=400, finger_position=7))
    assert main(["info", str(fmr)]) == 0
    info = json.loads(capsys.readouterr().out)
    assert info["format"] == "ISO/IEC 19794-2:2005" and info["bytes"] == 24 + 4 + 18 + 2
    assert info["dpi"] == [500, 500] and info["views"][0]["finger_position"] == 7
    assert (info["views"][0]["endings"], info["views"][0]["bifurcations"]) == (2, 1)


@pytest.mark.parametrize("content", [b"", b"nie jest rekordem", b"FMR\x00 20\x00" + b"\x00" * 30])
def test_bad_record_gives_exit_code_1_and_message(tmp_path, capsys, content):
    bad = tmp_path / "bad.fmr"
    bad.write_bytes(content)
    assert main(["info", str(bad)]) == 1
    assert main(["import", str(bad), str(tmp_path / "x.tpl")]) == 1
    assert "błąd" in capsys.readouterr().err
    assert not (tmp_path / "x.tpl").exists()


def test_export_rejects_minutiae_outside_declared_image(tmp_path, capsys):
    tpl = tmp_path / "a.tpl"
    tpl.write_bytes(template_to_bytes(_minutiae()))
    assert main(["export", str(tpl), str(tmp_path / "o.fmr"), "--width", "120", "--height", "400"]) == 1
    assert "poza obrazem" in capsys.readouterr().err
    assert main(["export", str(tmp_path / "brak.tpl"), str(tmp_path / "o.fmr"), "--width", "9",
                 "--height", "9"]) == 1


def test_oversized_file_is_not_read(tmp_path, capsys):
    big = tmp_path / "big.fmr"
    big.write_bytes(b"\x00" * (iso.MAX_RECORD_BYTES + 1))
    assert main(["info", str(big)]) == 1
    assert "większy" in capsys.readouterr().err


def test_fp_extract_writes_iso_record_with_image_dimensions(tmp_path, monkeypatch):
    img = np.full((300, 340), 255, np.uint8)
    for y in range(24, 292, 16):
        cv2.line(img, (0, y), (150 if y == 168 else 340, y), 0, 5)        # jedna urwana linia
    src = tmp_path / "scan.png"
    cv2.imwrite(str(src), cv2.GaussianBlur(img, (3, 3), 0.8))
    out = tmp_path / "out"
    monkeypatch.setattr(sys, "argv", ["fp-extract", str(src), "--out", str(out), "--iso",
                                      "--dpi", "508", "--finger-position", "2"])
    preprocessing.main()
    rec = iso.decode_record((out / "scan.fmr").read_bytes())
    assert (rec.width, rec.height, rec.resolution_x) == (340, 300, 200)    # 508 dpi = 200 px/cm
    assert rec.views[0].finger_position == 2
    assert len(rec.views[0].minutiae) == len(template_from_bytes((out / "scan.tpl").read_bytes()))


def test_fp_extract_without_iso_flag_writes_no_record(tmp_path, monkeypatch):
    img = np.full((120, 120), 255, np.uint8)
    for y in range(10, 110, 12):
        cv2.line(img, (0, y), (119, y), 0, 4)
    cv2.imwrite(str(tmp_path / "s.png"), img)
    monkeypatch.setattr(sys, "argv", ["fp-extract", str(tmp_path / "s.png"), "--out", str(tmp_path / "o")])
    preprocessing.main()
    assert (tmp_path / "o" / "s.tpl").exists() and not (tmp_path / "o" / "s.fmr").exists()
