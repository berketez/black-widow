"""P03 / IMZA-06 -- capa tarayicisi gercekten calisiyor ve her kosulda durum donduruyor.

Eski kusur: Python API yolu ``backend="auto"`` geciyordu; capa 9.4 bunu
``ValueError: unexpected backend: auto`` ile reddediyordu (194/194 girdide).
Eski testler ``_scan_via_api``'yi taklit ettigi icin kirik gorunmuyordu (RAPOR
T13). Bu dosyadaki tumlesik testler GERCEK capa'yi cagirir (capa / kurallar /
ornek yoksa skipif).

Durum sozlesmesi: ``status`` in {calisti, arac_yok, hata, desteklenmiyor},
``status_reason`` (calisti disinda dolu), ``backend`` (``api:<arka uc>`` ya da
``cli:<yol>``).
"""

from __future__ import annotations

import json
import os
import stat
import struct
import sys
from pathlib import Path

import pytest

from karadul.analyzers import capa_scanner as cs
from karadul.analyzers.capa_scanner import (
    STATUS_ERROR,
    STATUS_NO_TOOL,
    STATUS_RAN,
    STATUS_UNSUPPORTED,
    CAPAScanner,
)

try:
    import capa.loader  # noqa: F401
    HAS_CAPA = True
except ImportError:  # pragma: no cover
    HAS_CAPA = False

RULES = cs.DEFAULT_RULES_PATH
HAS_RULES = RULES.is_dir() and any(RULES.rglob("*.yml"))
W32 = Path(sys.prefix) / "lib" / f"python{sys.version_info.major}.{sys.version_info.minor}" \
    / "site-packages" / "pip" / "_vendor" / "distlib" / "w32.exe"
_DEB_LS = sorted((Path.home() / "karadul_olcum" / "n1_debian13" / "coreutils" / "ls")
                 .glob("ws/workspaces/*/*/raw/ls"))

needs_capa = pytest.mark.skipif(not (HAS_CAPA and HAS_RULES), reason="capa ya da kurallar yok")


# ---------------------------------------------------------------------------
# Sentetik basliklar
# ---------------------------------------------------------------------------

def _pe(machine: int, clr: bool = False) -> bytes:
    opt = bytearray(224)
    struct.pack_into("<H", opt, 0, 0x10B)
    if clr:
        struct.pack_into("<II", opt, 96 + 14 * 8, 0x2008, 0x48)
    return (b"MZ" + b"\x00" * 0x3A + struct.pack("<I", 0x40) + b"PE\x00\x00"
            + struct.pack("<HHIIIHH", machine, 0, 0, 0, 0, 224, 0x0102) + bytes(opt))


def _elf(machine: int) -> bytes:
    hdr = bytearray(64)
    hdr[0:6] = b"\x7fELF\x02\x01"
    struct.pack_into("<H", hdr, 0x12, machine)
    return bytes(hdr)


def _macho() -> bytes:
    return struct.pack("<IiiIIIII", 0xFEEDFACF, 0x0100000C, 0, 2, 0, 0, 0, 0)


@pytest.fixture
def rules_dir(tmp_path):
    d = tmp_path / "rules"
    d.mkdir()
    for i in range(12):
        (d / f"r{i}.yml").write_text("rule: {}\n")
    return d


# ---------------------------------------------------------------------------
# Baslik denetimi: kapsam disi girdide capa calistirilmaz, durum acik
# ---------------------------------------------------------------------------

class TestUnsupported:
    @pytest.mark.parametrize("data,fmt,needle", [
        (_macho(), "macho", "Mach-O"),
        (_elf(183), "elf", "e_machine=183"),
        (_pe(0xAA64), "pe", "Machine=0xaa64"),
    ])
    def test_scan_reports_unsupported(self, tmp_path, rules_dir, monkeypatch, data, fmt, needle):
        s = CAPAScanner(rules_path=rules_dir)
        monkeypatch.setattr(s, "is_available", lambda: True)

        def _boom(_p):  # capa'ya hic gidilmemeli
            raise AssertionError("kapsam disi girdide capa calistirildi")

        monkeypatch.setattr(s, "_scan_via_api", _boom)
        monkeypatch.setattr(s, "_scan_via_cli", _boom)
        f = tmp_path / "in.bin"
        f.write_bytes(data)
        r = s.scan(f)
        assert r.status == STATUS_UNSUPPORTED
        assert r.success is False
        assert r.format_ == fmt
        assert needle in r.status_reason
        assert r.to_dict()["status"] == STATUS_UNSUPPORTED

    def test_x86_and_dotnet_pass_header_check(self, tmp_path):
        for data in (_pe(0x14C), _pe(0x8664), _pe(0xAA64, clr=True), _elf(62), _elf(3)):
            f = tmp_path / "x.bin"
            f.write_bytes(data)
            ok, _, why = cs._header_support(f)
            assert ok, why

    def test_unknown_format(self, tmp_path):
        f = tmp_path / "raw.bin"
        f.write_bytes(b"\x00" * 64)
        ok, fmt, why = cs._header_support(f)
        assert not ok and fmt == "" and why


# ---------------------------------------------------------------------------
# Arac yok / hata
# ---------------------------------------------------------------------------

class TestNoTool:
    def test_rules_missing(self, tmp_path):
        s = CAPAScanner(rules_path=tmp_path / "yok")
        f = tmp_path / "a.exe"
        f.write_bytes(_pe(0x14C))
        r = s.scan(f)
        assert r.status == STATUS_NO_TOOL
        assert "kural dizini yok" in r.status_reason

    def test_capa_not_installed(self, tmp_path, rules_dir, monkeypatch):
        monkeypatch.setattr(cs, "resolve_tool", lambda name, **kw: None)
        monkeypatch.setitem(sys.modules, "capa", None)  # import capa.* -> ImportError
        monkeypatch.setitem(sys.modules, "capa.rules", None)
        monkeypatch.setitem(sys.modules, "capa.loader", None)
        s = CAPAScanner(rules_path=rules_dir)
        f = tmp_path / "a.exe"
        f.write_bytes(_pe(0x14C))
        r = s.scan(f)
        assert r.status == STATUS_NO_TOOL
        assert "capa kurulu degil" in r.status_reason

    def test_missing_binary_is_error(self, tmp_path, rules_dir, monkeypatch):
        s = CAPAScanner(rules_path=rules_dir)
        monkeypatch.setattr(s, "is_available", lambda: True)
        r = s.scan(tmp_path / "yok.exe")
        assert r.status == STATUS_ERROR and r.status_reason


# ---------------------------------------------------------------------------
# CLI yolu: capa 9.x'te -o yok; JSON stdout'tan dosyaya
# ---------------------------------------------------------------------------

_FAKE_JSON = {
    "meta": {"analysis": {"format": "pe", "arch": "i386", "os": "windows"}},
    "rules": {
        "create process on Windows": {
            "meta": {"name": "create process on Windows", "namespace": "host-interaction/process/create"},
            "matches": [[{"type": "absolute", "value": 4198400}, {}]],
        },
    },
}


def _fake_cli(tmp_path: Path, exit_code: int = 0) -> Path:
    script = tmp_path / "capa"
    script.write_text(
        f"#!{sys.executable}\n"
        "import sys, json\n"
        "if '-o' in sys.argv or '--output' in sys.argv:\n"
        "    sys.stderr.write('capa: error: unrecognized arguments: -o')\n"
        "    sys.exit(2)\n"
        f"if {exit_code}:\n"
        "    sys.stderr.write('unsupported')\n"
        f"    sys.exit({exit_code})\n"
        f"print({json.dumps(_FAKE_JSON)!r})\n",
        encoding="utf-8",
    )
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    return script


class TestCli:
    def test_cli_json_from_stdout(self, tmp_path, rules_dir):
        s = CAPAScanner(rules_path=rules_dir)
        s._capa_available = True
        s._cli_path = str(_fake_cli(tmp_path))
        f = tmp_path / "a.exe"
        f.write_bytes(_pe(0x14C))
        r = s.scan(f)
        assert r.status == STATUS_RAN, r.status_reason
        assert r.success and r.total_rules_matched == 1
        assert r.backend.startswith("cli:")
        assert "0x401000" in r.function_capabilities

    def test_cli_unsupported_exit(self, tmp_path, rules_dir):
        s = CAPAScanner(rules_path=rules_dir)
        s._capa_available = True
        s._cli_path = str(_fake_cli(tmp_path, exit_code=17))  # E_INVALID_FILE_ARCH
        f = tmp_path / "a.exe"
        f.write_bytes(_pe(0x14C))
        r = s.scan(f)
        assert r.status == STATUS_UNSUPPORTED


# ---------------------------------------------------------------------------
# GERCEK capa Python API (taklit yok)
# ---------------------------------------------------------------------------

@needs_capa
@pytest.mark.skipif(not W32.is_file(), reason="pip distlib w32.exe yok")
def test_real_api_on_x86_pe():
    s = CAPAScanner()
    assert s.is_available(), s.unavailable_reason
    s._cli_path = None  # Python API yolunu zorla
    r = s.scan(W32)
    assert r.status == STATUS_RAN, r.status_reason
    assert r.success is True
    assert r.backend == "api:vivisect"
    assert r.total_rules_matched > 0
    assert r.format_ == "pe"
    names = {c.name for caps in r.function_capabilities.values() for c in caps}
    names |= {c.name for c in r.file_capabilities}
    # distlib baslaticisi python surecini baslatir
    assert "create process on Windows" in names


@needs_capa
@pytest.mark.skipif(not _DEB_LS, reason="Debian AArch64 ls yok")
def test_real_api_rejects_aarch64_elf():
    """vivisect AArch64 kodunu cozemez: API yolu kendi de reddetmeli (0 yetenekli 'temiz' yok)."""
    s = CAPAScanner()
    assert s.is_available()
    r = s._scan_via_api(_DEB_LS[0])
    assert r.status == STATUS_UNSUPPORTED
    assert "aarch64" in r.status_reason


@needs_capa
def test_real_api_rejects_macho():
    s = CAPAScanner()
    assert s.is_available()
    r = s._scan_via_api(Path("/bin/ls"))
    assert r.status == STATUS_UNSUPPORTED
