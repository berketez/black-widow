"""P08 / IMZA-07: imza veritabanı ad başına kitaplık LİSTESİ tutar.

- İçe aktarılan simgeleri tanım diye yazan kaynaklar (PyPI tekerlekleri) dışlanır.
- Ubuntu kaynağından yalnız libc6 paketinin kayıtları alınır (kitaplık "glibc").
- Bir ad platformla süzüldükten sonra birden çok kitaplık ailesinde kalıyorsa
  eşleme tek kitaplık uydurmaz (``library == ""``, adaylar ``libraries``'de).
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

lmdb = pytest.importorskip("lmdb")

from karadul.analyzers.signature_db import (  # noqa: E402
    SignatureDB,
    _lib_family,
    _resolve_attribution,
)
from karadul.config import Config  # noqa: E402

DEPO = Path(__file__).resolve().parent.parent


def _load_builder():
    spec = importlib.util.spec_from_file_location(
        "build_sig_lmdb_p08", str(DEPO / "scripts" / "build_sig_lmdb.py"))
    mod = importlib.util.module_from_spec(spec)
    sys.modules["build_sig_lmdb_p08"] = mod
    spec.loader.exec_module(mod)
    return mod


def _dump(path: Path, sigs: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    pad = {f"p08_pad_{i}": {"lib": "padlib", "purpose": "", "category": "pad"} for i in range(3)}
    path.write_text(json.dumps({"meta": {"generator": "test"}, "signatures": {**sigs, **pad}}),
                    encoding="utf-8")


@pytest.fixture(scope="module")
def built(tmp_path_factory):
    root = tmp_path_factory.mktemp("proj")
    _dump(root / "sigs" / "pypi_native_symbols.json", {
        "__printf_chk": {"lib": "opencv_python_headless", "purpose": "", "category": "pypi_native"},
        "fgetfilecon": {"lib": "psycopg2_binary", "purpose": "", "category": "pypi_native"},
    })
    _dump(root / "sigs" / "ubuntu_elf_signatures.json", {
        "__printf_chk": {"lib": "c", "purpose": "", "category": "linux_glibc"},
        "is_selinux_enabled": {"lib": "gio-2.0", "purpose": "", "category": "linux_gtk"},
    })
    _dump(root / "sigs" / "linux_signatures.json", {
        "printf": {"lib": "glibc", "purpose": "formatted print", "category": "posix_stdio"},
    })
    _dump(root / "sigs" / "sdk_tbd_symbols.json", {
        "printf": {"lib": "libSystem.B", "purpose": "", "category": "macos_sdk"},
        "p08_dup": {"lib": "libAAA", "purpose": "", "category": "macos_sdk"},
    })
    _dump(root / "sigs" / "homebrew_deep.json", {
        "p08_dup": {"lib": "libBBB", "purpose": "", "category": "homebrew"},
        "p08_hdr": {"lib": "_stdio.h", "purpose": "", "category": "_stdio.h"},
    })
    _dump(root / "sigs" / "tuned_weights.json", {})
    out = root / "out" / "signatures.lmdb"
    mod = _load_builder()
    summary = mod.build(project_root=root, output=out, rebuild=True, map_size=32 * 1024 * 1024)
    cfg = Config()
    cfg.project_root = root / "bos"
    cfg.perf.use_lmdb_sigdb = True
    cfg.perf.sig_lmdb_path = out
    return {"root": root, "out": out, "summary": summary, "cfg": cfg, "mod": mod}


def test_imported_symbol_sources_excluded(built):
    from karadul.analyzers.sigdb_lmdb import LMDBSignatureDB

    db = LMDBSignatureDB(built["out"], readonly=True)
    try:
        pc = db.lookup_symbol("__printf_chk")
        assert pc is not None
        assert [p[0] for p in pc["providers"]] == ["glibc"]
        assert db.lookup_symbol("fgetfilecon") is None  # yalnız PyPI'da vardı
        assert db.lookup_symbol("is_selinux_enabled") is None  # ubuntu, glibc dışı
        assert db.lookup_symbol("p08_hdr") is None  # başlık dosyası kitaplık değil
        assert db.lookup_symbol("weights") is None  # ağırlık tablosu imza değil
    finally:
        db.close()
    excl = {e["source"] for e in built["summary"]["excluded_sources"]}
    assert "sigs/pypi_native_symbols.json" in excl
    assert "sigs/tuned_weights.json" in excl
    kunye = json.loads((built["out"] / "kunye.json").read_text("utf-8"))
    assert kunye["schema_version"] == 2
    assert kunye["build_id"] == built["summary"]["build_id"]


def test_name_keeps_all_providers(built):
    from karadul.analyzers.sigdb_lmdb import LMDBSignatureDB

    db = LMDBSignatureDB(built["out"], readonly=True)
    try:
        pr = db.lookup_symbol("printf")
        assert sorted(p[0] for p in pr["providers"]) == ["glibc", "libSystem.B"]
        dup = db.lookup_symbol("p08_dup")
        assert sorted(dup["libs"]) == ["libAAA", "libBBB"]
        assert dup["lib"] == ""
    finally:
        db.close()


def test_match_uses_platform_filtered_single_library(built):
    sdb = SignatureDB(built["cfg"], target_platform="elf")
    m = sdb._match_by_symbol("__printf_chk", target_platform="elf")
    assert m is not None and m.library == "glibc"
    m = sdb._match_by_symbol("printf", target_platform="elf")
    # yerleşik sözlükte de printf var; kitaplık glibc ailesinden olmalı
    assert m is not None and _lib_family(m.library) == "c"
    assert sdb._match_by_symbol("fgetfilecon", target_platform="elf") is None


def test_ambiguous_name_gets_no_single_library(built):
    sdb = SignatureDB(built["cfg"], target_platform="macho")
    m = sdb._match_by_symbol("p08_dup", target_platform="macho")
    assert m is not None
    assert m.library == ""
    assert sorted(m.libraries) == ["libAAA", "libBBB"]
    # macOS'a özgü sağlayıcılar ELF hedefinde sayılmaz
    assert SignatureDB(built["cfg"], target_platform="elf")._match_by_symbol(
        "p08_dup", target_platform="elf") is None


def test_resolve_attribution_filters_platform_before_counting():
    info = {"providers": [["glibc", "posix", ["elf"], 0], ["libSystem.B", "macos_sdk", ["macho"], 1],
                          ["msvcrt", "win_crt", ["pe"], 2]]}
    assert _resolve_attribution(info, "elf")[0] == "glibc"
    assert _resolve_attribution(info, "macho")[0] == "libSystem.B"
    assert _resolve_attribution(info, "pe")[0] == "msvcrt"
    amb = _resolve_attribution(info, None)
    assert amb[0] == "" and len(amb[2]) == 3
    same_family = {"providers": [["libc", "x", ["elf"], 0], ["glibc", "y", ["elf"], 1]]}
    assert _resolve_attribution(same_family, "elf")[0] == "libc"


def test_builder_refuses_to_overwrite_schema1_db(tmp_path, built):
    old = tmp_path / "eski.lmdb"
    old.mkdir()
    (old / "data.mdb").write_bytes(b"\0" * 16)
    (old / "version.txt").write_text("deadbeef\nsymbols=1\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="üstüne yazılmıyor"):
        built["mod"].build(project_root=built["root"], output=old, rebuild=True,
                           map_size=32 * 1024 * 1024)
    assert (old / "data.mdb").read_bytes() == b"\0" * 16
