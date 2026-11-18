"""P19 / BICIM-08: yerel PE, dizgi yüzünden .NET sayılmıyor.

Eskiden ilk 1 MB'ta `mscoree.dll` / `mscorlib` / `System.Runtime` dizgisi
yetiyordu: MSVC CRT'li yerel ikililer (CorExitProcess için mscoree.dll arar) ve
CLR'yi kendisi yükleyen yükleyiciler DOTNET_ASSEMBLY olup Ghidra'dan geçmiyor,
.NET analizörü de "0 fonksiyon, başarılı" diyordu. Karar artık PE başlığından:
DataDirectory[14] + geçerli CLI başlığı + BSJB metadata imzası.
"""

from __future__ import annotations

import struct
import zipfile
from pathlib import Path

import pytest

from karadul.analyzers.dotnet_binary import DotNetBinaryAnalyzer
from karadul.config import Config
from karadul.core.target import Language, TargetDetector, TargetInfo, TargetType
from karadul.core.workspace import Workspace
from tests.test_dotnet_binary import _build_minimal_pe


def _kulvar_native_pe() -> bytes:
    """Kulvar gösterimi: 436 baytlık yerel PE + `mscoree.dll\\0CLRCreateInstance`."""
    pe = bytearray(436)
    pe[0:2] = b"MZ"
    struct.pack_into("<I", pe, 0x3C, 0x40)
    pe[0x40:0x44] = b"PE\x00\x00"
    struct.pack_into("<HH", pe, 0x44, 0x14C, 0)
    struct.pack_into("<H", pe, 0x54, 0xE0)
    struct.pack_into("<H", pe, 0x58, 0x10B)
    struct.pack_into("<I", pe, 0x58 + 92, 16)
    tail = b"mscoree.dll\x00CLRCreateInstance\x00"
    pe[436 - len(tail):] = tail
    return bytes(pe)


def _write(tmp_path: Path, name: str, data: bytes) -> Path:
    p = tmp_path / name
    p.write_bytes(data)
    return p


def test_kulvar_native_loader_is_pe(tmp_path):
    p = _write(tmp_path, "loader.exe", _kulvar_native_pe())
    assert TargetDetector._is_dotnet(p) is False
    ti = TargetDetector().detect(p)
    assert ti.target_type == TargetType.PE_BINARY
    assert ti.metadata.get("clr_host_strings") is True


def test_native_pe_with_clr_strings_is_pe(tmp_path):
    data = _build_minimal_pe(has_cli=False, include_mscoree=True)
    data += b"\x00mscorlib\x00System.Runtime\x00_CorExeMain\x00"
    p = _write(tmp_path, "crt.exe", data)
    ti = TargetDetector().detect(p)
    assert ti.target_type == TargetType.PE_BINARY


def test_real_cli_header_is_dotnet(tmp_path):
    p = _write(tmp_path, "App.dll", _build_minimal_pe(has_cli=True, include_mscoree=False))
    ti = TargetDetector().detect(p)
    assert ti.target_type == TargetType.DOTNET_ASSEMBLY
    assert ti.metadata.get("dotnet_evidence") == "cli_header+bsjb"


def test_clr_dir_without_bsjb_is_not_dotnet(tmp_path):
    data = bytearray(_build_minimal_pe(has_cli=True))
    i = data.find(b"BSJB")
    assert i > 0
    data[i:i + 4] = b"XXXX"
    p = _write(tmp_path, "fake.dll", bytes(data))
    ev = TargetDetector._pe_clr_evidence(p)
    assert ev["clr_dir"] and ev["cli_header"] and not ev["bsjb"]
    ti = TargetDetector().detect(p)
    assert ti.target_type == TargetType.PE_BINARY
    assert ti.metadata.get("clr_dir_without_valid_metadata") is True


@pytest.mark.parametrize("data", [
    b"MZ",
    b"MZ" + b"\x00" * 58 + struct.pack("<I", 0xFFFFFFF0),
    b"MZ" + b"\x00" * 58 + struct.pack("<I", 0x40) + b"PE\x00\x00" + b"\xff" * 300,
    b"MZ" + b"\x00" * 58 + struct.pack("<I", 0x3C),
])
def test_garbage_pe_headers_do_not_crash(tmp_path, data):
    p = _write(tmp_path, "g.exe", data)
    assert TargetDetector._is_dotnet(p) is False


def test_analyzer_rejects_native_pe(tmp_path):
    p = _write(tmp_path, "loader.exe", _kulvar_native_pe())
    an = DotNetBinaryAnalyzer(Config())
    assert DotNetBinaryAnalyzer.can_handle(TargetInfo(
        path=p, name="loader", target_type=TargetType.PE_BINARY,
        language=Language.UNKNOWN, file_size=p.stat().st_size, file_hash="x",
    )) is False
    ws = Workspace(tmp_path / "ws", "l")
    ws.create()
    ti = TargetInfo(path=p, name="loader", target_type=TargetType.DOTNET_ASSEMBLY,
                    language=Language.CSHARP, file_size=p.stat().st_size, file_hash="x")
    st = an.analyze_static(ti, ws)
    assert st.success is False
    assert st.stats["has_cli_header"] is False
    assert any("CLI" in e for e in st.errors)
    rec = an.reconstruct(ti, ws)
    assert rec is not None and rec.success is False
    proj = ws.get_stage_dir("reconstructed") / "dotnet_project"
    assert not list(proj.glob("*.csproj"))


_GHIDRA_WINHELLO = (Path.home() / "Library/BlackWidowBuild/ghidra_12.1.2_PUBLIC/docs/"
                    "GhidraClass/ExerciseFiles/WinhelloCPP/WinHelloCPP.exe")
_NUPKG = (Path.home() / "karadul_olcum/dogrulama_native/dotnet/newtonsoft.json.13.0.3/"
          "newtonsoft.json.13.0.3.nupkg")


@pytest.mark.skipif(not _GHIDRA_WINHELLO.is_file(), reason="Ghidra örnek dosyası yok")
def test_real_msvc_native_exe_is_pe():
    """Gerçek MSVC C++ ikilisi (`file`: native); eskiden DOTNET_ASSEMBLY'ydi."""
    assert TargetDetector._is_dotnet(_GHIDRA_WINHELLO) is False


@pytest.mark.skipif(not _NUPKG.is_file(), reason="K-8 doğrulama örneği yok")
def test_real_dotnet_dll_is_dotnet(tmp_path):
    with zipfile.ZipFile(_NUPKG) as zf:
        data = zf.read("lib/net45/Newtonsoft.Json.dll")
    p = _write(tmp_path, "Newtonsoft.Json.dll", data)
    assert TargetDetector().detect(p).target_type == TargetType.DOTNET_ASSEMBLY
