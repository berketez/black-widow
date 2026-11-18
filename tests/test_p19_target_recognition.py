"""P19 / BICIM-10 (tanıma): tek .pyc, cx_Freeze, FAT64, evrensel dilimlerde
PyInstaller/Go/Bun, wheel / IPA / nupkg (container_classifier bağlandı).

Eskiden hepsi `unknown` (ya da `universal_binary` / yerel ELF) oluyordu.
Tanınan ama analiz hattı olmayan kapsayıcılar UNKNOWN kalır; ne oldukları ve
içlerindeki çalıştırılabilirler metadata'ya yazılır. Sentetik dosyalar
zararsızdır; hiçbir örnek çalıştırılmaz.
"""

from __future__ import annotations

import json
import py_compile
import struct
import sys
import zipfile
from pathlib import Path

import pytest

from karadul.core.target import TargetDetector, TargetType

MEI = b"MEI\x0c\x0b\x0a\x0b\x0e"
MACHO_THIN = b"\xcf\xfa\xed\xfe" + struct.pack("<iiIIII", 0x0100000C, 0, 2, 0, 0, 0)


def _pyc(tmp_path: Path, name: str = "m") -> Path:
    src = tmp_path / f"{name}_src.py"
    src.write_text("def f(x):\n    return x * 2\n")
    out = tmp_path / f"{name}.pyc"
    py_compile.compile(str(src), cfile=str(out), doraise=True)
    return out


def _fat(slices: list[bytes], *, fat64: bool = False) -> bytes:
    align = 0x4000
    n = len(slices)
    hdr = struct.pack(">II", 0xCAFEBABF if fat64 else 0xCAFEBABE, n)
    body = bytearray()
    offs = []
    off = align
    for s in slices:
        offs.append(off)
        off += ((len(s) + align - 1) // align) * align
    for (o, s) in zip(offs, slices):
        if fat64:
            hdr += struct.pack(">iiQQII", 0x0100000C, 0, o, len(s), 14, 0)
        else:
            hdr += struct.pack(">iiIII", 0x0100000C, 0, o, len(s), 14)
    data = bytearray(hdr + b"\x00" * (align - len(hdr)))
    for (o, s) in zip(offs, slices):
        data += b"\x00" * (o - len(data))
        data += s
    return bytes(data)


def _detect(p: Path):
    return TargetDetector().detect(p)


# ------------------------------------------------------------------ .pyc


def test_single_pyc_is_python_packed(tmp_path):
    p = _pyc(tmp_path)
    ti = _detect(p)
    assert ti.target_type == TargetType.PYTHON_PACKED
    assert ti.metadata["format"] == "pyc" and ti.metadata["packer"] == "pyc"
    assert ti.metadata["python_version"] == f"{sys.version_info[0]}.{sys.version_info[1]}"


def test_pyc_magic_without_crlf_not_pyc(tmp_path):
    data = bytearray(_pyc(tmp_path).read_bytes())
    data[2:4] = b"\x00\x00"
    p = tmp_path / "bad.pyc"
    p.write_bytes(bytes(data))
    assert _detect(p).target_type != TargetType.PYTHON_PACKED


def test_single_pyc_python_pipeline(tmp_path):
    """Tanınan .pyc python hattında gerçekten işlenir (eskiden JS hatası)."""
    from karadul.analyzers.python_binary import PythonBinaryAnalyzer
    from karadul.config import Config
    from karadul.core.workspace import Workspace

    p = _pyc(tmp_path)
    ti = _detect(p)
    ws = Workspace(tmp_path / "ws", "m")
    ws.create()
    an = PythonBinaryAnalyzer(Config())
    st = an.analyze_static(ti, ws)
    assert st.stats["packer"] == "pyc"
    rec = an.reconstruct(ti, ws)
    assert rec is not None and rec.success is True
    assert rec.stats["extracted_count"] == 1
    manifest = json.loads((ws.get_stage_dir("reconstructed") / "python_project"
                           / "manifest.json").read_text())
    assert manifest["decompile"]["total_pyc"] == 1


# ------------------------------------------------------------------ fat / FAT64


def test_fat64_is_universal(tmp_path):
    p = tmp_path / "fat64"
    p.write_bytes(_fat([MACHO_THIN + b"\x00" * 4000], fat64=True))
    ti = _detect(p)
    assert ti.target_type == TargetType.UNIVERSAL_BINARY
    assert len(ti.metadata["slices"]) == 1


def test_universal_pyinstaller_cookie_deep_in_tail(tmp_path):
    """Çerez dilim sonundan 300 KB önce (imzalı gerçek yt-dlp_macos düzeni)."""
    s2 = bytearray(MACHO_THIN + b"\x00" * (3 * 1024 * 1024))
    pos = len(s2) - 300 * 1024
    s2[pos:pos + len(MEI)] = MEI
    p = tmp_path / "pyi_universal"
    p.write_bytes(_fat([MACHO_THIN + b"\x00" * 4000, bytes(s2)]))
    ti = _detect(p)
    assert ti.target_type == TargetType.PYTHON_PACKED
    assert ti.metadata["packer"] == "pyinstaller"
    assert ti.metadata["native_format"] == "macho_universal"


def test_thin_macho_pyinstaller_cookie_beyond_256k(tmp_path):
    data = bytearray(MACHO_THIN + b"\x00" * (4 * 1024 * 1024))
    pos = len(data) - 300 * 1024
    data[pos:pos + len(MEI)] = MEI
    p = tmp_path / "pyi_thin"
    p.write_bytes(bytes(data))
    assert _detect(p).target_type == TargetType.PYTHON_PACKED


@pytest.mark.parametrize("marker,key", [(b"__gopclntab", "go_slice"), (b"__BUN\x00", "bun_slice")])
def test_universal_go_bun_slices_flagged(tmp_path, marker, key):
    s2 = MACHO_THIN + b"\x00" * 64 + marker + b"\x00" * 4000
    p = tmp_path / "u"
    p.write_bytes(_fat([MACHO_THIN + b"\x00" * 4000, s2]))
    ti = _detect(p)
    assert ti.target_type == TargetType.UNIVERSAL_BINARY
    assert ti.metadata.get(key) is True


def test_plain_universal_has_no_flags(tmp_path):
    p = tmp_path / "u"
    p.write_bytes(_fat([MACHO_THIN + b"\x00" * 4000, MACHO_THIN + b"\x00" * 4000]))
    ti = _detect(p)
    assert ti.target_type == TargetType.UNIVERSAL_BINARY
    assert not any(ti.metadata.get(k) for k in ("go_slice", "bun_slice", "packer"))


def test_fat_header_with_bogus_slices(tmp_path):
    hdr = struct.pack(">II", 0xCAFEBABE, 2) + struct.pack(">iiIII", 7, 3, 0xFFFFFF00, 0x1000, 12)
    p = tmp_path / "bogus"
    p.write_bytes(hdr + struct.pack(">iiIII", 7, 3, 64, 0, 12) + b"\x00" * 100)
    assert TargetDetector._fat_slices(p) == []


# ------------------------------------------------------------------ kapsayıcılar


def _zip(p: Path, files: dict[str, bytes]) -> Path:
    with zipfile.ZipFile(p, "w") as zf:
        for n, d in files.items():
            zf.writestr(n, d)
    return p


def test_wheel_recognized(tmp_path):
    p = _zip(tmp_path / "pkg-1.0-py3-none-any.whl", {
        "pkg/__init__.py": b"x = 1\n",
        "pkg/_speed.cpython-312-darwin.so": b"\xcf\xfa\xed\xfe",
        "pkg-1.0.dist-info/WHEEL": b"Wheel-Version: 1.0\n",
        "pkg-1.0.dist-info/METADATA": b"Name: pkg\n",
        "pkg-1.0.dist-info/RECORD": b"",
    })
    ti = _detect(p)
    assert ti.target_type == TargetType.UNKNOWN
    assert ti.metadata["container"] == "python_wheel"
    assert ti.metadata["container_package_id"] == "pkg"
    assert ti.metadata["container_version"] == "1.0"
    assert ti.metadata["container_executables"] == ["pkg/_speed.cpython-312-darwin.so"]


def test_wheel_needs_two_independent_files(tmp_path):
    p = _zip(tmp_path / "x.whl", {"pkg-1.0.dist-info/WHEEL": b"", "pkg/__init__.py": b""})
    assert "container" not in _detect(p).metadata


def test_nupkg_recognized(tmp_path):
    p = _zip(tmp_path / "Acme.Lib.1.0.0.nupkg", {
        "Acme.Lib.nuspec": b"<package/>",
        "[Content_Types].xml": b"<Types/>",
        "_rels/.rels": b"<Relationships/>",
        "lib/net6.0/Acme.Lib.dll": b"MZ",
    })
    m = _detect(p).metadata
    assert m["container"] == "nuget_package"
    assert m["container_package_id"] == "Acme.Lib"
    assert m["container_executables"] == ["lib/net6.0/Acme.Lib.dll"]


def test_ipa_recognized(tmp_path):
    p = _zip(tmp_path / "app.ipa", {
        "Payload/Demo.app/Info.plist": b"<?xml version='1.0'?><plist><dict/></plist>",
        "Payload/Demo.app/Demo": MACHO_THIN + b"\x00" * 100,
    })
    m = _detect(p).metadata
    assert m["container"] == "ipa"
    assert "unsupported_reason" in m


def test_plain_zip_not_container(tmp_path):
    p = _zip(tmp_path / "veri.zip", {"a.txt": b"x", "b/c.json": b"{}"})
    ti = _detect(p)
    assert ti.target_type == TargetType.UNKNOWN and "container" not in ti.metadata


# ------------------------------------------------------------------ cx_Freeze


def _cx_dist(tmp_path: Path, members: dict[str, bytes]) -> Path:
    d = tmp_path / "dist"
    (d / "lib").mkdir(parents=True)
    exe = d / "app"
    exe.write_bytes(b"\x7fELF\x02\x01\x01" + b"\x00" * 2000)
    _zip(d / "lib" / "library.zip", members)
    return exe


def test_cx_freeze_distribution_recognized(tmp_path):
    exe = _cx_dist(tmp_path, {"__startup__.pyc": b"x", "BUILD_CONSTANTS.pyc": b"x",
                              "app__main__.pyc": b"x"})
    ti = _detect(exe)
    assert ti.target_type == TargetType.PYTHON_PACKED
    assert ti.metadata["packer"] == "cx_freeze"
    assert ti.metadata["native_format"] == "elf"


def test_lib_zip_without_cx_freeze_modules_stays_native(tmp_path):
    exe = _cx_dist(tmp_path, {"json/__init__.pyc": b"x", "os.pyc": b"x"})
    assert _detect(exe).target_type == TargetType.ELF_BINARY


def test_ooxml_docx_is_not_nupkg(tmp_path):
    """[Content_Types].xml + _rels/ tek başına NuGet değil (docx/xlsx aynı OPC)."""
    p = _zip(tmp_path / "rapor.docx", {
        "[Content_Types].xml": b"<Types/>",
        "_rels/.rels": b"<Relationships/>",
        "word/document.xml": b"<w:document/>",
    })
    assert "container" not in _detect(p).metadata


# ------------------------------------------------------------------ gerçek örnekler (K-8)

_K8 = Path.home() / "karadul_olcum/dogrulama_native"


@pytest.mark.skipif(not (_K8 / "pyinstaller/yt-dlp_macos/yt-dlp_macos").is_file(),
                    reason="K-8 doğrulama örneği yok")
def test_real_universal_pyinstaller():
    ti = _detect(_K8 / "pyinstaller/yt-dlp_macos/yt-dlp_macos")
    assert ti.target_type == TargetType.PYTHON_PACKED


@pytest.mark.skipif(not (_K8 / "wheel").is_dir(), reason="K-8 doğrulama örneği yok")
def test_real_wheel_and_nupkg():
    whl = next((_K8 / "wheel").rglob("*.whl"))
    assert _detect(whl).metadata["container"] == "python_wheel"
    for nupkg in (_K8 / "dotnet").rglob("*.nupkg"):
        m = _detect(nupkg).metadata
        assert m["container"] == "nuget_package"
        assert m["container_executables_total"] > 0
