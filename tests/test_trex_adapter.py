"""Tests -- TRex adapter (v1.13 Dalga 3).

Mac uzerinde Rust toolchain kurulu degil, dolayisiyla TRex binary'si yok.
Tum testler hermetik; subprocess cagrilari ``monkeypatch`` ile mock'lanir.

Coverage:
    1. is_available() binary YOK -> False
    2. get_version() binary YOK -> None
    3. analyze() binary YOK -> RuntimeError("trex binary not available")
    4. parse_output(): hardcoded README ornegi -> 1 struct, 2 field
    5. parse_output(): bos string -> []
    6. parse_output(): birden fazla struct -> hepsi parse edilir
    7. parse_output(): variable annotation comment -> function alani dolu
    8. _resolve_binary: explicit arg + dosya yok -> None + warning
    9. analyze() mocked subprocess (RC=0) -> structs parse edilir
    10. analyze() mocked subprocess (RC!=0) -> raw_stderr + structs bos
    11. analyze() mocked timeout -> rc=-1 + raw_stderr aciklamasi
    12. analyze() lifted dosyasi YOK -> RuntimeError
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import pytest

from karadul.analyzers.trex_adapter import (
    TRexAdapter,
    TRexResult,
    TRexStruct,
)


# ---------------------------------------------------------------------------
# Sample data -- vendor/trex/README.md ornegi
# ---------------------------------------------------------------------------


SAMPLE_README_OUTPUT = """\
// n@getlast@00100000 : t1*
// nxt@getlast@00100000 : t1*

struct t1 {
  int32_t field_0;
  t1* field_8;
};
"""

SAMPLE_MULTI_STRUCT = """\
// head@list_init@00400000 : node*

struct node {
  int64_t field_0;
  node* field_8;
};

struct list_header {
  node* field_0;
  int32_t field_8;
  int32_t field_12;
};
"""


# ---------------------------------------------------------------------------
# 1) is_available() -- binary yokken False
# ---------------------------------------------------------------------------


def test_is_available_binary_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    """Mac'te Rust kurulu degil + env unset -> is_available False."""
    monkeypatch.delenv("KARADUL_TREX_PATH", raising=False)
    # PATH'tan trex'i de gizle
    monkeypatch.setattr("shutil.which", lambda _name: None)
    # Vendor binary path'ini override et (yok say)
    monkeypatch.setattr(
        "karadul.analyzers.trex_adapter._VENDOR_TREX_BIN",
        Path("/nonexistent/trex"),
    )
    adapter = TRexAdapter()
    assert adapter.is_available() is False


# ---------------------------------------------------------------------------
# 2) get_version() -- binary yokken None
# ---------------------------------------------------------------------------


def test_get_version_returns_none_when_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("KARADUL_TREX_PATH", raising=False)
    monkeypatch.setattr("shutil.which", lambda _name: None)
    monkeypatch.setattr(
        "karadul.analyzers.trex_adapter._VENDOR_TREX_BIN",
        Path("/nonexistent/trex"),
    )
    adapter = TRexAdapter()
    assert adapter.get_version() is None


def test_get_version_uses_subprocess(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    """Binary varsa --version cagrisinin stdout'u return edilir."""
    fake_bin = tmp_path / "trex"
    fake_bin.write_text("#!/bin/sh\n")
    fake_bin.chmod(0o755)

    def _fake_run(cmd: list[str], **_kw: Any) -> subprocess.CompletedProcess[str]:
        assert cmd[0] == str(fake_bin)
        assert cmd[1] == "--version"
        return subprocess.CompletedProcess(cmd, 0, stdout="trex 0.1.0\n", stderr="")

    monkeypatch.setattr(subprocess, "run", _fake_run)
    adapter = TRexAdapter(binary_path=fake_bin)
    assert adapter.get_version() == "trex 0.1.0"


# ---------------------------------------------------------------------------
# 3) analyze() -- binary yokken RuntimeError
# ---------------------------------------------------------------------------


def test_analyze_raises_when_binary_missing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    monkeypatch.delenv("KARADUL_TREX_PATH", raising=False)
    monkeypatch.setattr("shutil.which", lambda _name: None)
    monkeypatch.setattr(
        "karadul.analyzers.trex_adapter._VENDOR_TREX_BIN",
        Path("/nonexistent/trex"),
    )
    adapter = TRexAdapter()
    with pytest.raises(RuntimeError, match="trex binary not available"):
        adapter.analyze(tmp_path / "foo.lifted")


# ---------------------------------------------------------------------------
# 4-7) parse_output()
# ---------------------------------------------------------------------------


def test_parse_output_readme_example() -> None:
    """README ornegi -> 1 struct, 2 field, function='getlast'."""
    adapter = TRexAdapter.__new__(TRexAdapter)  # init bypass
    adapter._binary_path = None  # type: ignore[attr-defined]
    structs = adapter.parse_output(SAMPLE_README_OUTPUT)
    assert len(structs) == 1
    s = structs[0]
    assert s.name == "t1"
    assert s.function == "getlast"
    assert len(s.fields) == 2
    # field_0
    assert s.fields[0]["name"] == "field_0"
    assert s.fields[0]["type"] == "int32_t"
    assert s.fields[0]["offset"] == "0x0"
    # field_8 -> tip "t1*" (whitespace yok)
    assert s.fields[1]["name"] == "field_8"
    assert s.fields[1]["type"].replace(" ", "") == "t1*"
    assert s.fields[1]["offset"] == "0x8"


def test_parse_output_empty_string() -> None:
    adapter = TRexAdapter.__new__(TRexAdapter)
    adapter._binary_path = None  # type: ignore[attr-defined]
    assert adapter.parse_output("") == []


def test_parse_output_multiple_structs() -> None:
    adapter = TRexAdapter.__new__(TRexAdapter)
    adapter._binary_path = None  # type: ignore[attr-defined]
    structs = adapter.parse_output(SAMPLE_MULTI_STRUCT)
    assert len(structs) == 2
    names = [s.name for s in structs]
    assert names == ["node", "list_header"]
    # list_header 3 field
    list_header = structs[1]
    assert len(list_header.fields) == 3
    # field offset'ler sirayla 0,8,12 olmali (field_<N> konvansiyonu)
    offsets = [f["offset"] for f in list_header.fields]
    assert offsets == ["0x0", "0x8", "0xc"]


def test_parse_output_no_var_comment() -> None:
    """var@func@addr yorumu yoksa function = None."""
    no_comment = "struct foo {\n  int32_t field_0;\n};"
    adapter = TRexAdapter.__new__(TRexAdapter)
    adapter._binary_path = None  # type: ignore[attr-defined]
    structs = adapter.parse_output(no_comment)
    assert len(structs) == 1
    assert structs[0].function is None


# ---------------------------------------------------------------------------
# 8) _resolve_binary explicit arg + dosya yok
# ---------------------------------------------------------------------------


def test_resolve_binary_arg_missing_returns_none(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    """Explicit binary_path verildi ama dosya yok -> None (PATH'a duşmez)."""
    monkeypatch.delenv("KARADUL_TREX_PATH", raising=False)
    monkeypatch.setattr("shutil.which", lambda _name: "/some/where/trex")
    adapter = TRexAdapter(binary_path=tmp_path / "does_not_exist")
    assert adapter.is_available() is False


def test_resolve_binary_env_var(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    """KARADUL_TREX_PATH env var'i dosyayi gosterirse oradan alinir."""
    fake = tmp_path / "trex_envbin"
    fake.write_text("#!/bin/sh\n")
    fake.chmod(0o755)
    monkeypatch.setenv("KARADUL_TREX_PATH", str(fake))
    adapter = TRexAdapter()
    assert adapter.is_available() is True
    assert adapter._binary_path == str(fake)  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# 9-11) analyze() ile mocked subprocess
# ---------------------------------------------------------------------------


def test_analyze_mocked_success(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    """Mocked rc=0 + valid stdout -> structs parse edilir."""
    fake = tmp_path / "trex"
    fake.write_text("")
    fake.chmod(0o755)
    lifted = tmp_path / "foo.lifted"
    lifted.write_text("dummy")

    adapter = TRexAdapter(binary_path=fake)

    def _fake_run(_cmd: list[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            _cmd, 0, stdout=SAMPLE_README_OUTPUT, stderr="",
        )

    monkeypatch.setattr(adapter, "_run_subprocess", _fake_run)
    result = adapter.analyze(lifted)
    assert isinstance(result, TRexResult)
    assert result.return_code == 0
    assert len(result.structs) == 1
    assert result.structs[0].name == "t1"
    assert result.duration_ms >= 0.0


def test_analyze_mocked_nonzero_exit(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    """rc != 0 -> structs bos, raw_stderr dolu."""
    fake = tmp_path / "trex"
    fake.write_text("")
    fake.chmod(0o755)
    lifted = tmp_path / "foo.lifted"
    lifted.write_text("dummy")

    adapter = TRexAdapter(binary_path=fake)
    monkeypatch.setattr(
        adapter,
        "_run_subprocess",
        lambda _c: subprocess.CompletedProcess(
            _c, 2, stdout="", stderr="parse error: foo",
        ),
    )
    result = adapter.analyze(lifted)
    assert result.return_code == 2
    assert result.structs == []
    assert "parse error" in result.raw_stderr


def test_analyze_mocked_timeout(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    """Timeout -> rc=-1 + 'timeout' raw_stderr'da."""
    fake = tmp_path / "trex"
    fake.write_text("")
    fake.chmod(0o755)
    lifted = tmp_path / "foo.lifted"
    lifted.write_text("dummy")

    adapter = TRexAdapter(binary_path=fake, timeout=1)

    def _raise_timeout(_cmd: list[str]) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired(cmd=_cmd, timeout=1)

    monkeypatch.setattr(adapter, "_run_subprocess", _raise_timeout)
    result = adapter.analyze(lifted)
    assert result.return_code == -1
    assert "timeout" in result.raw_stderr.lower()


# ---------------------------------------------------------------------------
# 12) analyze() lifted yoksa RuntimeError
# ---------------------------------------------------------------------------


def test_analyze_missing_lifted_file(tmp_path: Path) -> None:
    """Binary VAR ama .lifted dosyasi yok -> RuntimeError."""
    fake = tmp_path / "trex"
    fake.write_text("")
    fake.chmod(0o755)
    adapter = TRexAdapter(binary_path=fake)
    with pytest.raises(RuntimeError, match=r"\.lifted"):
        adapter.analyze(tmp_path / "absent.lifted")


# ---------------------------------------------------------------------------
# Dataclass smoke
# ---------------------------------------------------------------------------


def test_trex_struct_dataclass_defaults() -> None:
    s = TRexStruct(name="foo")
    assert s.name == "foo"
    assert s.fields == []
    assert s.function is None
    assert s.raw_output == ""


def test_trex_result_dataclass_defaults() -> None:
    r = TRexResult()
    assert r.structs == []
    assert r.raw_stdout == ""
    assert r.raw_stderr == ""
    assert r.return_code == 0
    assert r.duration_ms == 0.0


# ---------------------------------------------------------------------------
# Gercek binary varsa: skip-if pattern
# ---------------------------------------------------------------------------


def _real_trex_available() -> bool:
    """Pytest discovery sirasinda gercek binary kontrolu."""
    import shutil as _sh

    if "KARADUL_TREX_PATH" in __import__("os").environ:
        env = __import__("os").environ["KARADUL_TREX_PATH"]
        return Path(env).exists()
    vendor = (
        Path(__file__).resolve().parents[1]
        / "vendor" / "trex" / "trex" / "target" / "release" / "trex"
    )
    if vendor.exists():
        return True
    return _sh.which("trex") is not None


@pytest.mark.skipif(
    not _real_trex_available(),
    reason="TRex binary kurulu degil (Rust toolchain yok). "
    "Kurulum: vendor/trex/BUILD_INSTRUCTIONS.md",
)
def test_real_trex_version_smoke() -> None:
    adapter = TRexAdapter()
    version = adapter.get_version()
    assert version is None or isinstance(version, str)
