"""P20b kalem 2 — ASAR açıcı yazamadığında sessiz 0 dönmüyor.

Önce (f28c96a): `extract_asar` çıktı dizini yoksa, yol bir dosyaysa ya da dizin
yazılamazsa hata vermeden `skipped: {write_failed: N}`, `files_written: 0`
dönüyordu (gerçek Electron Fiddle `app.asar` 104 dosya → 0, write_failed 3;
`extractthis.asar` 5 → 0, write_failed 4). Ürün çağıranı (`_extract_asar`)
dizini kurduğu için ürün akışında yalnız "yazılamaz dizin" yolu kalıyordu;
orada da aşama hatası nedensizdi ("ASAR extract basarisiz: <yol>"). Çıktı yolu
bir dosyaysa `_extract_asar`'ın `mkdir`'i try dışında olduğundan statik aşama
istisnayla düşüyordu.

Sonra: dizin yok / dizin değil → `NotADirectoryError`; rapor P-S1 durumunu taşır
(`calisti` / `kismi` / `hata` + `status_reason`); yazılamayan arşivde neden
aşama hatasına gider.
"""

from __future__ import annotations

import json
import os
import stat
import struct
from pathlib import Path
from typing import Any

import pytest

from karadul.analyzers.electron import ElectronAnalyzer, extract_asar
from karadul.config import Config
from karadul.core.target import Language, TargetInfo, TargetType
from karadul.core.workspace import Workspace

BIG = 1 << 40
_ROOT = os.geteuid() == 0 if hasattr(os, "geteuid") else False


def _asar(tree: dict[str, Any], extra: dict[str, Any] | None = None) -> bytes:
    body = bytearray()

    def node(t: dict[str, Any]) -> dict[str, Any]:
        files: dict[str, Any] = {}
        for name, v in t.items():
            if isinstance(v, dict):
                files[name] = node(v)
            else:
                files[name] = {"size": len(v), "offset": str(len(body))}
                body.extend(v)
        return {"files": files}

    header = node(tree)
    if extra:
        header["files"].update(extra)
    js = json.dumps(header).encode()
    payload = struct.pack("<I", len(js)) + js + b"\x00" * ((-len(js)) % 4)
    pickle = struct.pack("<I", len(payload)) + payload
    return struct.pack("<II", 4, len(pickle)) + pickle + bytes(body)


_TREE = {"package.json": b'{"main": "main.js"}', "lib": {"main.js": b"function main(){return 1}\n" * 20}}


@pytest.fixture
def asar(tmp_path: Path) -> Path:
    p = tmp_path / "app.asar"
    p.write_bytes(_asar(_TREE))
    return p


def test_missing_output_dir_is_an_error_not_silent_zero(tmp_path, asar):
    out = tmp_path / "yok" / "out"
    with pytest.raises(NotADirectoryError, match="ASAR çıktı dizini yok"):
        extract_asar(asar, out, max_total_bytes=BIG)
    assert not out.exists()


def test_output_path_that_is_a_file_is_an_error(tmp_path, asar):
    out = tmp_path / "dosya"
    out.write_text("x")
    with pytest.raises(NotADirectoryError):
        extract_asar(asar, out, max_total_bytes=BIG)
    assert out.read_text() == "x"


@pytest.mark.skipif(_ROOT, reason="root izin denetimini atlar")
def test_unwritable_dir_reports_hata_with_reason(tmp_path, asar):
    out = tmp_path / "ro"
    out.mkdir()
    os.chmod(out, stat.S_IRUSR | stat.S_IXUSR)
    try:
        rep = extract_asar(asar, out, max_total_bytes=BIG)
    finally:
        os.chmod(out, stat.S_IRWXU)
    assert rep["files_written"] == 0
    assert rep["files_in_header"] == 2
    assert rep["status"] == "hata"
    assert "hiçbir dosya yazılamadı" in rep["status_reason"]
    assert "yazılan dosya 0 / 2" in rep["status_reason"]
    assert "write_failed" in rep["status_reason"]


def test_partial_extraction_is_kismi(tmp_path):
    p = tmp_path / "app.asar"
    p.write_bytes(_asar(_TREE, extra={"evil": {"link": "../../etc/passwd"}}))
    out = tmp_path / "out"
    out.mkdir()
    rep = extract_asar(p, out, max_total_bytes=BIG)
    assert rep["files_written"] == 2
    assert rep["status"] == "kismi"
    assert "symlink: 1" in rep["status_reason"]
    assert not (out / "evil").exists()


def test_clean_extraction_is_calisti(tmp_path, asar):
    out = tmp_path / "out"
    out.mkdir()
    rep = extract_asar(asar, out, max_total_bytes=BIG)
    assert rep["files_written"] == 2
    assert rep["status"] == "calisti" and rep["status_reason"] is None


def _target(asar: Path) -> TargetInfo:
    return TargetInfo(path=asar, name="app", target_type=TargetType.ELECTRON_APP,
                      language=Language.JAVASCRIPT, file_size=asar.stat().st_size, file_hash="x")


@pytest.mark.skipif(_ROOT, reason="root izin denetimini atlar")
def test_analyze_static_unwritable_extract_dir_has_reason(tmp_path, asar):
    ws = Workspace(tmp_path / "ws", "e")
    ws.create()
    dest = ws.get_stage_dir("raw") / "asar_extracted"
    dest.mkdir(parents=True)
    os.chmod(dest, stat.S_IRUSR | stat.S_IXUSR)
    try:
        res = ElectronAnalyzer(Config()).analyze_static(_target(asar), ws)
    finally:
        os.chmod(dest, stat.S_IRWXU)
    assert res.success is False
    assert res.stats["asar_extract"]["status"] == "hata"
    assert "hiçbir dosya yazılamadı" in res.errors[0]


def test_analyze_static_extract_path_is_file_does_not_crash(tmp_path, asar):
    ws = Workspace(tmp_path / "ws", "e")
    ws.create()
    dest = ws.get_stage_dir("raw") / "asar_extracted"
    dest.write_text("x")
    res = ElectronAnalyzer(Config()).analyze_static(_target(asar), ws)
    assert res.success is False
    assert res.errors and "ASAR extract basarisiz" in res.errors[0] and "(" in res.errors[0]
