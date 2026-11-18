"""P19 / BICIM-06 (ASAR kısmı): ASAR Python'da açılır; ağ ve alt süreç yok.

Eskiden `npx --yes @electron/asar extract` sürümü sabitlenmemiş bir paketi
ağdan indirip ÇALIŞTIRIYORDU. Yeni açıcı düşman girdiye karşı: yol geçişi,
simgesel bağ, toplam boyut ve dosya sayısı bütçesi, harf duyarsız ad çakışması,
sınır dışı ofset, `.asar.unpacked`.
"""

from __future__ import annotations

import json
import os
import socket
import struct
import subprocess
from pathlib import Path
from typing import Any

import pytest

from karadul.analyzers import electron as el
from karadul.analyzers.electron import AsarFormatError, ElectronAnalyzer, extract_asar
from karadul.config import Config
from karadul.core import subprocess_runner
from karadul.core.target import Language, TargetInfo, TargetType
from karadul.core.workspace import Workspace

BIG = 1 << 40


def _pickle_header(header: dict[str, Any]) -> bytes:
    js = json.dumps(header).encode()
    pad = (-len(js)) % 4
    payload = struct.pack("<I", len(js)) + js + b"\x00" * pad
    pickle = struct.pack("<I", len(payload)) + payload
    return struct.pack("<II", 4, len(pickle)) + pickle


def build_asar(tree: dict[str, Any], extra: dict[str, Any] | None = None) -> bytes:
    """tree: ad -> bytes (dosya) | dict (dizin). extra: başlığa elle eklenecek girdiler."""
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
    return _pickle_header(header) + bytes(body)


def _write(tmp: Path, data: bytes, name: str = "app.asar") -> Path:
    p = tmp / name
    p.write_bytes(data)
    return p


def _files_under(root: Path) -> dict[str, bytes]:
    return {
        str(p.relative_to(root)): p.read_bytes()
        for p in sorted(root.rglob("*")) if p.is_file() and not p.is_symlink()
    }


def test_roundtrip_nested(tmp_path):
    asar = _write(tmp_path, build_asar({
        "package.json": b'{"main": "main.js"}',
        "main.js": b"console.log(1);\n",
        "lib": {"a.js": b"A" * 10, "deep": {"b.txt": b"bee"}},
        "empty.txt": b"",
    }))
    out = tmp_path / "out"
    out.mkdir()
    rep = extract_asar(asar, out, max_total_bytes=BIG)
    assert _files_under(out) == {
        "package.json": b'{"main": "main.js"}',
        "main.js": b"console.log(1);\n",
        "lib/a.js": b"A" * 10,
        "lib/deep/b.txt": b"bee",
        "empty.txt": b"",
    }
    assert rep["files_written"] == 5 and rep["dirs_created"] == 2
    assert rep["skipped"] == {} and rep["truncated"] is False


@pytest.mark.parametrize("bad", ["..", "../escape.txt", "/etc/escape.txt", "a/b.txt",
                                 "a\\b.txt", ".", "", "x\x00y"])
def test_traversal_names_rejected(tmp_path, bad):
    asar = _write(tmp_path, build_asar(
        {"ok.txt": b"ok"},
        extra={bad: {"size": 2, "offset": "0"}},
    ))
    out = tmp_path / "out"
    out.mkdir()
    rep = extract_asar(asar, out, max_total_bytes=BIG)
    assert rep["skipped"] == {"bad_name": 1}
    assert _files_under(out) == {"ok.txt": b"ok"}
    assert not (tmp_path / "escape.txt").exists()


def test_traversal_directory_name_rejected(tmp_path):
    asar = _write(tmp_path, build_asar(
        {"ok.txt": b"ok"},
        extra={"..": {"files": {"pwn.txt": {"size": 2, "offset": "0"}}}},
    ))
    out = tmp_path / "sub" / "out"
    out.mkdir(parents=True)
    rep = extract_asar(asar, out, max_total_bytes=BIG)
    assert rep["skipped"] == {"bad_name": 1}
    assert not (tmp_path / "sub" / "pwn.txt").exists()


def test_link_entries_not_created(tmp_path):
    asar = _write(tmp_path, build_asar(
        {"ok.txt": b"ok"}, extra={"evil": {"link": "../../../../etc/passwd"}},
    ))
    out = tmp_path / "out"
    out.mkdir()
    rep = extract_asar(asar, out, max_total_bytes=BIG)
    assert rep["skipped"] == {"symlink": 1}
    assert not (out / "evil").exists() and not (out / "evil").is_symlink()


def test_existing_symlink_in_output_not_followed(tmp_path):
    victim = tmp_path / "victim.txt"
    victim.write_text("orijinal")
    asar = _write(tmp_path, build_asar({"evil.txt": b"EZILDI"}))
    out = tmp_path / "out"
    out.mkdir()
    (out / "evil.txt").symlink_to(victim)
    rep = extract_asar(asar, out, max_total_bytes=BIG)
    assert victim.read_text() == "orijinal"
    assert rep["files_written"] == 0


def test_total_size_budget(tmp_path):
    asar = _write(tmp_path, build_asar({f"f{i:02d}.bin": b"x" * 100 for i in range(50)}))
    out = tmp_path / "out"
    out.mkdir()
    rep = extract_asar(asar, out, max_total_bytes=1000)
    assert rep["truncated"] is True and "boyut" in rep["truncate_reason"]
    assert rep["files_written"] == 10
    assert sum(len(v) for v in _files_under(out).values()) <= 1000


def test_file_count_budget(tmp_path):
    asar = _write(tmp_path, build_asar({f"f{i:02d}": b"x" for i in range(30)}))
    out = tmp_path / "out"
    out.mkdir()
    rep = extract_asar(asar, out, max_total_bytes=BIG, max_files=7)
    assert rep["truncated"] is True and "sayı" in rep["truncate_reason"]
    assert len(_files_under(out)) == 7


def test_out_of_bounds_offset_and_size(tmp_path):
    asar = _write(tmp_path, build_asar(
        {"ok.txt": b"ok"},
        extra={"far.bin": {"size": 10, "offset": "999999"},
               "huge.bin": {"size": 1 << 40, "offset": "0"},
               "neg.bin": {"size": 1, "offset": "-1"},
               "badoff.bin": {"size": 1, "offset": "abc"},
               "badsize.bin": {"size": "1", "offset": "0"}},
    ))
    out = tmp_path / "out"
    out.mkdir()
    rep = extract_asar(asar, out, max_total_bytes=BIG)
    assert rep["skipped"] == {"out_of_bounds": 3, "bad_offset": 1, "bad_size": 1}
    assert _files_under(out) == {"ok.txt": b"ok"}


def test_casefold_collision_keeps_both(tmp_path):
    asar = _write(tmp_path, build_asar({"Main.js": b"upper", "main.js": b"lower"}))
    out = tmp_path / "out"
    out.mkdir()
    rep = extract_asar(asar, out, max_total_bytes=BIG)
    got = sorted(_files_under(out).values())
    assert got == [b"lower", b"upper"]
    assert len(rep["renamed"]) == 1


def test_unpacked_entries(tmp_path):
    asar = _write(tmp_path, build_asar(
        {"ok.txt": b"ok"},
        extra={"native": {"files": {
            "addon.node": {"size": 4, "unpacked": True},
            "link.node": {"size": 6, "unpacked": True},
            "gone.node": {"size": 1, "unpacked": True},
        }}},
    ))
    unpacked = tmp_path / "app.asar.unpacked" / "native"
    unpacked.mkdir(parents=True)
    (unpacked / "addon.node").write_bytes(b"\x7fELF")
    secret = tmp_path / "secret.txt"
    secret.write_text("gizli!")
    (unpacked / "link.node").symlink_to(secret)
    out = tmp_path / "out"
    out.mkdir()
    rep = extract_asar(asar, out, max_total_bytes=BIG)
    assert (out / "native" / "addon.node").read_bytes() == b"\x7fELF"
    assert not (out / "native" / "link.node").exists()
    assert rep["unpacked_files"] == 1
    assert rep["skipped"] == {"unpacked_not_regular": 1, "unpacked_missing": 1}


@pytest.mark.parametrize("data", [
    b"",
    b"PK\x03\x04" + b"\x00" * 60,
    struct.pack("<4I", 4, 0x7FFFFFFF, 0x7FFFFFF0, 0x7FFFFF00),
    struct.pack("<4I", 4, 12, 8, 4) + b"null",
    struct.pack("<4I", 4, 16, 12, 8) + b'{"a":1}\x00',
])
def test_bad_header_raises(tmp_path, data):
    asar = _write(tmp_path, data)
    out = tmp_path / "out"
    out.mkdir()
    with pytest.raises(AsarFormatError):
        extract_asar(asar, out, max_total_bytes=BIG)


# ------------------------------------------------- analizör: ağ / alt süreç yok


@pytest.fixture
def no_subprocess(monkeypatch):
    calls: list[Any] = []

    def boom(*a, **k):
        calls.append(a)
        raise AssertionError(f"alt süreç/ağ çağrısı: {a!r}")

    monkeypatch.setattr(subprocess, "run", boom)
    monkeypatch.setattr(subprocess, "Popen", boom)
    monkeypatch.setattr(subprocess_runner.SubprocessRunner, "run_command", boom)
    monkeypatch.setattr(socket.socket, "connect", boom)
    return calls


def test_analyze_static_offline(tmp_path, no_subprocess):
    js = b"function main(){ return 42; }\n" * 200
    asar = _write(tmp_path, build_asar({"package.json": b'{"main": "main.js"}', "main.js": js}))
    ws = Workspace(tmp_path / "ws", "e")
    ws.create()
    ti = TargetInfo(path=asar, name="app", target_type=TargetType.ELECTRON_APP,
                    language=Language.JAVASCRIPT, file_size=asar.stat().st_size, file_hash="x")
    res = ElectronAnalyzer(Config()).analyze_static(ti, ws)
    assert no_subprocess == []
    assert res.success is True, res.errors
    assert res.stats["asar_extract"]["files_written"] == 2
    extracted = ws.get_stage_dir("raw") / "asar_extracted"
    assert (extracted / "main.js").read_bytes() == js


def test_analyze_static_bad_asar_reports_reason(tmp_path, no_subprocess):
    asar = _write(tmp_path, b"\x04\x00\x00\x00" + b"\x00" * 60)
    ws = Workspace(tmp_path / "ws", "e")
    ws.create()
    ti = TargetInfo(path=asar, name="app", target_type=TargetType.ELECTRON_APP,
                    language=Language.JAVASCRIPT, file_size=asar.stat().st_size, file_hash="x")
    res = ElectronAnalyzer(Config()).analyze_static(ti, ws)
    assert no_subprocess == []
    assert res.success is False
    assert "ASAR extract basarisiz" in res.errors[0] and "(" in res.errors[0]


def test_electron_module_has_no_npx():
    src = Path(el.__file__).read_text(encoding="utf-8")
    assert '"--yes"' not in src and "@electron/asar\"" not in src


def test_package_json_main_outside_extract_dir_ignored(tmp_path):
    ext = tmp_path / "ext"
    ext.mkdir()
    outside = tmp_path / "outside.js"
    outside.write_text("var secret = 1;\n" * 100)
    (ext / "package.json").write_text(json.dumps({"main": "../outside.js"}))
    inner = ext / "index.js"
    inner.write_text("var x = 1;\n" * 100)
    an = ElectronAnalyzer(Config())
    assert an._find_main_js(ext, [inner]) == inner
    (ext / "package.json").write_text(json.dumps({"main": str(outside)}))
    assert an._find_main_js(ext, [inner]) == inner


_REAL = Path.home() / "karadul_olcum/dogrulama_native/electron/extractthis/extractthis.asar"


@pytest.mark.skipif(not _REAL.is_file(), reason="gerçek doğrulama örneği yok (K-8)")
def test_real_extractthis_asar(tmp_path):
    out = tmp_path / "out"
    out.mkdir()
    rep = extract_asar(_REAL, out, max_total_bytes=BIG)
    files = _files_under(out)
    assert files["dir1/file1.txt"] == b"file one."
    assert files["file0.txt"] == b"file0 content"
    assert files["emptyfile.txt"] == b""
    assert files["dir2/file3.txt"] == b"123"
    assert files["dir2/file2.png"].startswith(b"\x89PNG")
    assert rep["files_written"] == 5 and rep["skipped"] == {}
