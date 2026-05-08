"""Tests -- PDBAdapter (v1.14 Dalga 1).

PDB binary'leri Mac uzerinde uretilemez (Microsoft formati); test verisi
hardcoded ``llvm-pdbutil dump`` ciktisi ornegidir. Subprocess cagrilari
``monkeypatch`` ile mock'lanir; gercek binary varligini gerektiren tek
test ``@pytest.mark.skipif`` ile korumali.

Coverage:
    1. is_available() binary YOK -> False
    2. is_available() binary VAR (env override) -> True
    3. get_version() binary YOK -> None
    4. get_version() binary VAR -> stdout string
    5. extract_symbols() binary YOK -> RuntimeError
    6. extract_types() binary YOK -> RuntimeError
    7. extract_all() PDB YOK -> RuntimeError
    8. parse_dump(): bos string -> ([], [])
    9. parse_dump(): tek S_GPROC32 -> 1 PDBSymbol (function, addr, size, type)
    10. parse_dump(): S_GDATA32 / S_LDATA32 / S_GTHREAD32 -> dogru kind'lar
    11. parse_dump(): S_PUB32 -> public kind
    12. parse_dump(): LF_STRUCTURE + LF_FIELDLIST -> PDBType + members
    13. parse_dump(): LF_PROCEDURE + LF_CLASS karisik -> 2 type
    14. _resolve_binary explicit arg + dosya yok -> None
    15. extract_all() mocked subprocess (rc=0) -> PDBResult dolu
    16. extract_all() mocked subprocess (rc!=0) -> raw_stdout/return_code raporlanir
    17. extract_all() mocked timeout -> rc=-1
    18. Real binary smoke -- skipif binary yoksa
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import pytest

from karadul.analyzers.pdb_parser import (
    PDBAdapter,
    PDBResult,
    PDBSymbol,
    PDBType,
)


# ---------------------------------------------------------------------------
# Sample llvm-pdbutil dump ciktisi (yapay; format gercek)
# ---------------------------------------------------------------------------


SAMPLE_PROC = """\
Symbols
============================================================
  Mod 0000 | `C:\\proj\\foo.obj`:
        4 | S_GPROC32 [size = 44] `MyFunction`
            parent = 0, addr = 0001:00010, code size = 64
            debug start = 4, debug end = 60
            flags = none
            type = 0x1003 (int (int))
       52 | S_END
"""


SAMPLE_DATA_MIX = """\
Global Symbols
============================================================
        0 | S_GDATA32 [size = 28] `g_counter`
            type = 0x0074 (int), addr = 0002:00100
       28 | S_LDATA32 [size = 28] `s_local_buf`
            type = 0x0075 (char[16]), addr = 0002:00120
       56 | S_GTHREAD32 [size = 28] `tls_value`
            type = 0x0074 (int), addr = 0003:00000
"""


SAMPLE_PUB = """\
Public Symbols
============================================================
        4 | S_PUB32 [size = 24] `?foo@@YAHH@Z`
            flags = function, addr = 0001:00010
"""


# Struct + LF_FIELDLIST (gercek llvm-pdbutil format)
SAMPLE_STRUCT_TYPE = """\
Types (TPI Stream)
============================================================
  0x1004 | LF_STRUCTURE [size = 64] `Foo`
          unique name: `.?AUFoo@@`
          vtable: <no type>, base list: <no type>, field list: 0x1005
          options: forward ref | has unique name, sizeof 24
  0x1005 | LF_FIELDLIST [size = 28]
          - LF_MEMBER [name = `m_x`, Type = 0x0074 (int), offset = 0]
          - LF_MEMBER [name = `m_y`, Type = 0x0074 (int), offset = 4]
          - LF_MEMBER [name = `m_buf`, Type = 0x0075 (char[16]), offset = 8]
"""


SAMPLE_PROC_AND_CLASS = """\
Types (TPI Stream)
============================================================
  0x1003 | LF_PROCEDURE [size = 16]
          return type = 0x0074 (int), # args = 1, param list = 0x1002
          calling conv = near c, options = None
  0x1010 | LF_CLASS [size = 80] `Bar`
          unique name: `.?AVBar@@`
          options: has unique name, sizeof 16
"""


# ---------------------------------------------------------------------------
# Yardimci: binary "yok" sayan fixture mantigi
# ---------------------------------------------------------------------------


def _hide_binary(monkeypatch: pytest.MonkeyPatch) -> None:
    """Tum cozumleme yollarini kapat -- binary 'yok' gibi davran."""
    monkeypatch.delenv("KARADUL_LLVM_PDBUTIL", raising=False)
    monkeypatch.setattr("shutil.which", lambda _name: None)
    # Brew lokasyonlarini override et
    monkeypatch.setattr(
        "karadul.analyzers.pdb_parser._BREW_LOCATIONS",
        (Path("/nonexistent/llvm-pdbutil"),),
    )


# ---------------------------------------------------------------------------
# 1) is_available() -- binary yokken False
# ---------------------------------------------------------------------------


def test_is_available_binary_missing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    _hide_binary(monkeypatch)
    pdb = tmp_path / "foo.pdb"
    pdb.write_bytes(b"")
    adapter = PDBAdapter(pdb_path=pdb)
    assert adapter.is_available() is False


# ---------------------------------------------------------------------------
# 2) is_available() binary VAR (env var)
# ---------------------------------------------------------------------------


def test_is_available_via_env_var(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    fake = tmp_path / "llvm-pdbutil"
    fake.write_text("#!/bin/sh\n")
    fake.chmod(0o755)
    monkeypatch.setenv("KARADUL_LLVM_PDBUTIL", str(fake))
    pdb = tmp_path / "foo.pdb"
    pdb.write_bytes(b"")
    adapter = PDBAdapter(pdb_path=pdb)
    assert adapter.is_available() is True
    assert adapter._binary_path == str(fake)


# ---------------------------------------------------------------------------
# 3) get_version() binary YOK -> None
# ---------------------------------------------------------------------------


def test_get_version_returns_none_when_unavailable(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    _hide_binary(monkeypatch)
    adapter = PDBAdapter(pdb_path=tmp_path / "foo.pdb")
    assert adapter.get_version() is None


# ---------------------------------------------------------------------------
# 4) get_version() binary VAR -> stdout string
# ---------------------------------------------------------------------------


def test_get_version_uses_subprocess(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    fake = tmp_path / "llvm-pdbutil"
    fake.write_text("")
    fake.chmod(0o755)

    def _fake_run(cmd: list[str], **_kw: Any) -> subprocess.CompletedProcess[str]:
        assert cmd[0] == str(fake)
        assert cmd[1] == "--version"
        return subprocess.CompletedProcess(
            cmd, 0, stdout="LLVM version 22.1.3\n", stderr="",
        )

    monkeypatch.setattr(subprocess, "run", _fake_run)
    adapter = PDBAdapter(
        pdb_path=tmp_path / "foo.pdb", llvm_pdbutil_path=fake,
    )
    version = adapter.get_version()
    assert version is not None
    assert "22.1.3" in version


# ---------------------------------------------------------------------------
# 5) extract_symbols() binary YOK -> RuntimeError
# ---------------------------------------------------------------------------


def test_extract_symbols_raises_when_unavailable(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    _hide_binary(monkeypatch)
    adapter = PDBAdapter(pdb_path=tmp_path / "foo.pdb")
    with pytest.raises(RuntimeError, match="llvm-pdbutil not available"):
        adapter.extract_symbols()


# ---------------------------------------------------------------------------
# 6) extract_types() binary YOK -> RuntimeError
# ---------------------------------------------------------------------------


def test_extract_types_raises_when_unavailable(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    _hide_binary(monkeypatch)
    adapter = PDBAdapter(pdb_path=tmp_path / "foo.pdb")
    with pytest.raises(RuntimeError, match="llvm-pdbutil not available"):
        adapter.extract_types()


# ---------------------------------------------------------------------------
# 7) extract_all() PDB dosyasi YOK -> RuntimeError
# ---------------------------------------------------------------------------


def test_extract_all_missing_pdb_file(tmp_path: Path) -> None:
    fake = tmp_path / "llvm-pdbutil"
    fake.write_text("")
    fake.chmod(0o755)
    adapter = PDBAdapter(
        pdb_path=tmp_path / "absent.pdb", llvm_pdbutil_path=fake,
    )
    with pytest.raises(RuntimeError, match="PDB dosyasi yok"):
        adapter.extract_all()


# ---------------------------------------------------------------------------
# 8) parse_dump(): bos string -> ([], [])
# ---------------------------------------------------------------------------


def test_parse_dump_empty(tmp_path: Path) -> None:
    adapter = PDBAdapter.__new__(PDBAdapter)  # init bypass
    adapter._binary_path = None
    adapter.pdb_path = tmp_path / "foo.pdb"
    syms, types = adapter.parse_dump("")
    assert syms == []
    assert types == []


# ---------------------------------------------------------------------------
# 9) parse_dump(): S_GPROC32 -> function symbol
# ---------------------------------------------------------------------------


def test_parse_dump_gproc32(tmp_path: Path) -> None:
    adapter = PDBAdapter.__new__(PDBAdapter)
    adapter._binary_path = None
    adapter.pdb_path = tmp_path / "foo.pdb"
    syms, types = adapter.parse_dump(SAMPLE_PROC)
    assert types == []
    assert len(syms) == 1
    s = syms[0]
    assert s.name == "MyFunction"
    assert s.kind == "function"
    assert s.section == 1
    assert s.address == 0x10
    assert s.size == 64
    assert s.type_index == 0x1003


# ---------------------------------------------------------------------------
# 10) parse_dump(): GDATA32 / LDATA32 / GTHREAD32 -> dogru kind
# ---------------------------------------------------------------------------


def test_parse_dump_data_mix(tmp_path: Path) -> None:
    adapter = PDBAdapter.__new__(PDBAdapter)
    adapter._binary_path = None
    adapter.pdb_path = tmp_path / "foo.pdb"
    syms, types = adapter.parse_dump(SAMPLE_DATA_MIX)
    assert types == []
    assert len(syms) == 3
    by_name = {s.name: s for s in syms}
    assert by_name["g_counter"].kind == "global"
    assert by_name["s_local_buf"].kind == "static"
    assert by_name["tls_value"].kind == "thread"
    # adresler dogru parse edilmis mi
    assert by_name["g_counter"].section == 2
    assert by_name["g_counter"].address == 0x100


# ---------------------------------------------------------------------------
# 11) parse_dump(): S_PUB32 -> public kind
# ---------------------------------------------------------------------------


def test_parse_dump_pub32(tmp_path: Path) -> None:
    adapter = PDBAdapter.__new__(PDBAdapter)
    adapter._binary_path = None
    adapter.pdb_path = tmp_path / "foo.pdb"
    syms, _types = adapter.parse_dump(SAMPLE_PUB)
    assert len(syms) == 1
    assert syms[0].kind == "public"
    assert syms[0].name == "?foo@@YAHH@Z"  # mangled
    assert syms[0].section == 1
    assert syms[0].address == 0x10


# ---------------------------------------------------------------------------
# 12) parse_dump(): LF_STRUCTURE + LF_FIELDLIST -> PDBType + members
# ---------------------------------------------------------------------------


def test_parse_dump_struct_with_members(tmp_path: Path) -> None:
    adapter = PDBAdapter.__new__(PDBAdapter)
    adapter._binary_path = None
    adapter.pdb_path = tmp_path / "foo.pdb"
    _syms, types = adapter.parse_dump(SAMPLE_STRUCT_TYPE)
    # LF_STRUCTURE 'Foo' + LF_FIELDLIST 0x1005 -- 2 tip
    assert len(types) == 2
    foo = next(t for t in types if t.kind == "Struct")
    assert foo.name == "Foo"
    assert foo.type_id == 0x1004
    assert foo.size == 24
    # field listesi (LF_MEMBER) -- LF_FIELDLIST tipinde 3 member toplandi
    fl = next(t for t in types if t.kind == "FieldList")
    assert len(fl.fields) == 3
    names = [f["name"] for f in fl.fields]
    assert names == ["m_x", "m_y", "m_buf"]
    offsets = [f["offset"] for f in fl.fields]
    assert offsets == [0, 4, 8]
    # type_id'ler dogru
    assert fl.fields[0]["type_id"] == 0x0074


# ---------------------------------------------------------------------------
# 13) parse_dump(): LF_PROCEDURE + LF_CLASS -> 2 type, dogru kind'lar
# ---------------------------------------------------------------------------


def test_parse_dump_procedure_and_class(tmp_path: Path) -> None:
    adapter = PDBAdapter.__new__(PDBAdapter)
    adapter._binary_path = None
    adapter.pdb_path = tmp_path / "foo.pdb"
    _syms, types = adapter.parse_dump(SAMPLE_PROC_AND_CLASS)
    assert len(types) == 2
    by_id = {t.type_id: t for t in types}
    assert 0x1003 in by_id
    assert 0x1010 in by_id
    assert by_id[0x1003].kind == "Procedure"
    assert by_id[0x1010].kind == "Class"
    assert by_id[0x1010].name == "Bar"
    assert by_id[0x1010].size == 16


# ---------------------------------------------------------------------------
# 14) _resolve_binary explicit arg + dosya yok -> None
# ---------------------------------------------------------------------------


def test_resolve_binary_arg_missing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    """Explicit yol verildi ama dosya yok -> binary cozumlemeden None."""
    monkeypatch.delenv("KARADUL_LLVM_PDBUTIL", raising=False)
    monkeypatch.setattr("shutil.which", lambda _n: "/some/where/llvm-pdbutil")
    pdb = tmp_path / "foo.pdb"
    pdb.write_bytes(b"")
    adapter = PDBAdapter(
        pdb_path=pdb,
        llvm_pdbutil_path=tmp_path / "nope.bin",
    )
    # PATH'a duşmedi cunku explicit verilince fallback yok
    assert adapter.is_available() is False


# ---------------------------------------------------------------------------
# 15) extract_all() mocked subprocess (rc=0) -> PDBResult dolu
# ---------------------------------------------------------------------------


def test_extract_all_mocked_success(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    fake = tmp_path / "llvm-pdbutil"
    fake.write_text("")
    fake.chmod(0o755)
    pdb = tmp_path / "foo.pdb"
    pdb.write_bytes(b"\x00\x01\x02")  # var olmasi yeterli

    adapter = PDBAdapter(pdb_path=pdb, llvm_pdbutil_path=fake)

    combined = SAMPLE_PROC + "\n" + SAMPLE_STRUCT_TYPE

    def _fake_run(cmd: list[str]) -> subprocess.CompletedProcess[str]:
        assert "dump" in cmd
        return subprocess.CompletedProcess(
            cmd, 0, stdout=combined, stderr="",
        )

    monkeypatch.setattr(adapter, "_run_subprocess", _fake_run)
    result = adapter.extract_all()
    assert isinstance(result, PDBResult)
    assert result.return_code == 0
    assert len(result.symbols) == 1
    assert result.symbols[0].name == "MyFunction"
    assert len(result.types) == 2
    assert result.duration_ms >= 0.0
    assert result.pdb_path == pdb


# ---------------------------------------------------------------------------
# 16) extract_all() mocked subprocess (rc!=0)
# ---------------------------------------------------------------------------


def test_extract_all_mocked_nonzero(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    fake = tmp_path / "llvm-pdbutil"
    fake.write_text("")
    fake.chmod(0o755)
    pdb = tmp_path / "foo.pdb"
    pdb.write_bytes(b"")

    adapter = PDBAdapter(pdb_path=pdb, llvm_pdbutil_path=fake)
    monkeypatch.setattr(
        adapter,
        "_run_subprocess",
        lambda _c: subprocess.CompletedProcess(
            _c, 1, stdout="", stderr="error: invalid PDB",
        ),
    )
    result = adapter.extract_all()
    assert result.return_code == 1
    assert result.symbols == []
    assert result.types == []


# ---------------------------------------------------------------------------
# 17) extract_all() mocked timeout -> rc=-1
# ---------------------------------------------------------------------------


def test_extract_all_mocked_timeout(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    fake = tmp_path / "llvm-pdbutil"
    fake.write_text("")
    fake.chmod(0o755)
    pdb = tmp_path / "foo.pdb"
    pdb.write_bytes(b"")

    adapter = PDBAdapter(pdb_path=pdb, llvm_pdbutil_path=fake, timeout=1)

    def _raise_timeout(_cmd: list[str]) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired(cmd=_cmd, timeout=1)

    monkeypatch.setattr(adapter, "_run_subprocess", _raise_timeout)
    result = adapter.extract_all()
    assert result.return_code == -1


# ---------------------------------------------------------------------------
# Dataclass smoke
# ---------------------------------------------------------------------------


def test_pdb_symbol_defaults() -> None:
    s = PDBSymbol(name="x")
    assert s.name == "x"
    assert s.address is None
    assert s.size is None
    assert s.section is None
    assert s.kind == "unknown"
    assert s.type_index is None


def test_pdb_type_defaults() -> None:
    t = PDBType(type_id=0x1000, kind="Struct")
    assert t.type_id == 0x1000
    assert t.kind == "Struct"
    assert t.name is None
    assert t.size is None
    assert t.fields == []
    assert t.raw == ""


def test_pdb_result_defaults() -> None:
    r = PDBResult()
    assert r.symbols == []
    assert r.types == []
    assert r.pdb_path is None
    assert r.pdb_version is None
    assert r.return_code == 0


# ---------------------------------------------------------------------------
# 18) Real binary smoke (skipif binary yoksa)
# ---------------------------------------------------------------------------


def _real_pdbutil_available() -> bool:
    """Pytest discovery sirasinda gercek binary kontrolu."""
    import os as _os
    import shutil as _sh

    env = _os.environ.get("KARADUL_LLVM_PDBUTIL")
    if env and Path(env).exists():
        return True
    candidates = (
        Path("/opt/homebrew/opt/llvm/bin/llvm-pdbutil"),
        Path("/usr/local/opt/llvm/bin/llvm-pdbutil"),
        Path("/home/linuxbrew/.linuxbrew/opt/llvm/bin/llvm-pdbutil"),
    )
    for c in candidates:
        if c.exists():
            return True
    return _sh.which("llvm-pdbutil") is not None


@pytest.mark.skipif(
    not _real_pdbutil_available(),
    reason="llvm-pdbutil kurulu degil. Kurulum: brew install llvm "
    "(Mac) veya apt install llvm (Linux).",
)
def test_real_pdbutil_version_smoke(tmp_path: Path) -> None:
    """Gercek binary --version cagrisi (PDB dosyasi gerekmez)."""
    adapter = PDBAdapter(pdb_path=tmp_path / "dummy.pdb")
    version = adapter.get_version()
    assert version is None or isinstance(version, str)
    assert adapter.is_available() is True
