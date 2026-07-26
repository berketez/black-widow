"""pyc_decompiler.py testleri.

Strateji: harici arac (pycdc) GEREKMEDEN test edilir. Gercek .pyc'ler calisan
Python'un ``compile()`` + ``marshal.dumps`` ile uretilir; pycdc dallari
``monkeypatch`` ile resolve_tool/safe_run sahtelenerek test edilir.

Mutation-korumali (CLAUDE.md test-kalitesi dersi): header offset, magic tail,
surum normalize ve pycdc "anlamli cikti" filtreleri hedefli asserlarla korunur.
"""

from __future__ import annotations

import marshal
import struct
import subprocess
import sys
from pathlib import Path

import pytest

from karadul.analyzers import pyc_decompiler as pd
from karadul.analyzers.pyc_decompiler import (
    _PYC_MAGIC_TO_VERSION,
    _PYC_HEADER_SIZE_37,
    _VERSION_TO_MAGIC,
    DecompileResult,
    decompile_pyc,
    has_valid_pyc_header,
    magic_bytes_for_version,
    repair_pyc_header,
    version_from_pyc_bytes,
)

RUNNING = f"{sys.version_info.major}.{sys.version_info.minor}"


# ---------------------------------------------------------------------------
# Yardimcilar
# ---------------------------------------------------------------------------

def _marshal_body(src: str = "def f(a, b):\n    return a + b\n") -> bytes:
    """Calisan Python surumu icin header'SIZ marshal govdesi (stripped .pyc gibi)."""
    code = compile(src, "m.py", "exec")
    return marshal.dumps(code)


def _real_pyc(src: str = "def f(a, b):\n    return a + b\n") -> bytes:
    """Calisan Python surumu icin gecerli header'li tam .pyc."""
    import importlib.util
    return importlib.util.MAGIC_NUMBER + struct.pack("<I", 0) * 3 + _marshal_body(src)


# ---------------------------------------------------------------------------
# Magic tablolari & tutarlilik
# ---------------------------------------------------------------------------

class TestMagicTables:
    def test_version_to_magic_tutarli(self):
        """_VERSION_TO_MAGIC her kanonik magic, _PYC_MAGIC_TO_VERSION'da ayni surume map."""
        assert _VERSION_TO_MAGIC, "tablo bos olamaz"
        for ver, magic in _VERSION_TO_MAGIC.items():
            assert _PYC_MAGIC_TO_VERSION.get(magic) == ver, (
                f"TUTARSIZ: {ver} -> {magic} ama tabloda {_PYC_MAGIC_TO_VERSION.get(magic)}"
            )

    def test_tum_ana_surumler_kapsanir(self):
        for ver in ("3.7", "3.8", "3.9", "3.10", "3.11", "3.12", "3.13"):
            assert ver in _VERSION_TO_MAGIC


class TestMagicBytesForVersion:
    def test_bilinen_surum(self):
        mb = magic_bytes_for_version("3.11")
        assert mb is not None and len(mb) == 4
        # magic int + \r\n
        assert mb[2:4] == b"\r\n"
        assert struct.unpack("<H", mb[0:2])[0] == _VERSION_TO_MAGIC["3.11"]

    def test_patch_surumu_normalize(self):
        # "3.11.4" -> "3.11" ile ayni magic uretmeli (mutant: parts[:2] koruma)
        assert magic_bytes_for_version("3.11.4") == magic_bytes_for_version("3.11")

    def test_bilinmeyen_ve_bos(self):
        assert magic_bytes_for_version("2.7") is None
        assert magic_bytes_for_version("") is None
        assert magic_bytes_for_version("garbage") is None


# ---------------------------------------------------------------------------
# has_valid_pyc_header
# ---------------------------------------------------------------------------

class TestHasValidHeader:
    def test_gecerli_header(self):
        assert has_valid_pyc_header(_real_pyc()) is True

    def test_stripped_body_gecersiz(self):
        # marshal govdesi tip kodu ('c'/0xe3) ile baslar -> gecerli magic degil
        assert has_valid_pyc_header(_marshal_body()) is False

    def test_cok_kisa(self):
        assert has_valid_pyc_header(b"\x00\x00") is False
        assert has_valid_pyc_header(b"") is False

    def test_yanlis_tail(self):
        # dogru magic int ama tail \r\n degil (mutant: _MAGIC_TAIL koruma)
        bad = struct.pack("<H", _VERSION_TO_MAGIC["3.11"]) + b"XY" + b"\x00" * 12
        assert has_valid_pyc_header(bad) is False

    def test_bilinmeyen_magic_int(self):
        # tail dogru ama magic int tabloda yok
        bad = struct.pack("<H", 9999) + b"\r\n" + b"\x00" * 12
        assert has_valid_pyc_header(bad) is False


# ---------------------------------------------------------------------------
# repair_pyc_header
# ---------------------------------------------------------------------------

class TestRepairHeader:
    def test_stripped_onarilir(self):
        body = _marshal_body()
        repaired = repair_pyc_header(body, RUNNING)
        assert repaired is not None
        assert has_valid_pyc_header(repaired)
        # header 16 byte, govde AYNEN korunur (mutant: offset/govde koruma)
        assert len(repaired) == len(body) + _PYC_HEADER_SIZE_37
        assert repaired[_PYC_HEADER_SIZE_37:] == body

    def test_round_trip_marshal(self):
        # Onarilan .pyc'nin govdesi calisan Python'da marshal.loads edilebilmeli
        body = _marshal_body("x = 1 + 2\n")
        repaired = repair_pyc_header(body, RUNNING)
        code = marshal.loads(repaired[_PYC_HEADER_SIZE_37:])
        assert code is not None

    def test_idempotent_gecerli_header(self):
        real = _real_pyc()
        assert repair_pyc_header(real, RUNNING) == real

    def test_surum_yoksa_none(self):
        assert repair_pyc_header(_marshal_body(), None) is None
        assert repair_pyc_header(_marshal_body(), "2.7") is None

    def test_dogru_magic_yazilir(self):
        body = _marshal_body()
        repaired = repair_pyc_header(body, "3.10")
        magic_int = struct.unpack("<H", repaired[0:2])[0]
        assert _PYC_MAGIC_TO_VERSION[magic_int] == "3.10"


class TestVersionFromBytes:
    def test_gecerli(self):
        v = version_from_pyc_bytes(_real_pyc())
        assert v == RUNNING

    def test_stripped_none(self):
        assert version_from_pyc_bytes(_marshal_body()) is None


# ---------------------------------------------------------------------------
# decompile_pyc -- disassembly fallback (harici arac YOK)
# ---------------------------------------------------------------------------

class TestDecompileDisasmFallback:
    def test_pycdc_yoksa_disasm(self, tmp_path, monkeypatch):
        # Hicbir harici arac yok -> stdlib dis fallback (ayni surum)
        monkeypatch.setattr(pd, "resolve_tool", lambda name, **k: None)
        body = _marshal_body("def g():\n    return 42\n")
        pyc = tmp_path / "g.pyc"
        pyc.write_bytes(repair_pyc_header(body, RUNNING))

        res = decompile_pyc(pyc, tmp_path / "out", py_version=RUNNING)
        assert isinstance(res, DecompileResult)
        assert res.is_disassembly is True
        assert res.success is False           # disasm kaynak DEGIL -- durust
        assert res.method == "disasm"
        assert res.output_path is not None and res.output_path.exists()
        assert res.output_path.suffix == ".txt"
        assert "RETURN" in res.output_path.read_text().upper()

    def test_surum_uyusmazsa_disasm_yok(self, tmp_path, monkeypatch):
        # pycdas yok + calisan surumden FARKLI surum -> marshal.loads guvenilmez -> none
        monkeypatch.setattr(pd, "resolve_tool", lambda name, **k: None)
        body = _marshal_body()
        # Farkli bir surum etiketiyle ( or. running 3.12 ise 3.8) header yaz
        other = "3.8" if RUNNING != "3.8" else "3.9"
        pyc = tmp_path / "x.pyc"
        pyc.write_bytes(repair_pyc_header(body, other))
        res = decompile_pyc(pyc, tmp_path / "out", py_version=other)
        assert res.success is False
        assert res.method == "none"


# ---------------------------------------------------------------------------
# decompile_pyc -- pycdc dallari (monkeypatch)
# ---------------------------------------------------------------------------

def _fake_completed(stdout: str, returncode: int = 0, stderr: str = "") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=["pycdc"], returncode=returncode, stdout=stdout, stderr=stderr)


class TestDecompilePycdc:
    def test_pycdc_basari(self, tmp_path, monkeypatch):
        monkeypatch.setattr(pd, "resolve_tool", lambda name, **k: "/fake/pycdc" if name == "pycdc" else None)
        real_source = "def f(a, b):\n    return a + b\n"
        monkeypatch.setattr(pd, "safe_run", lambda *a, **k: _fake_completed(real_source))

        pyc = tmp_path / "f.pyc"
        pyc.write_bytes(repair_pyc_header(_marshal_body(), RUNNING))
        res = decompile_pyc(pyc, tmp_path / "out", py_version=RUNNING)

        assert res.success is True
        assert res.method == "pycdc"
        assert res.is_disassembly is False
        assert res.output_path.suffix == ".py"
        assert "return a + b" in res.output_path.read_text()

    def test_pycdc_bos_cikti_reddedilir(self, tmp_path, monkeypatch):
        # rc=0 ama SADECE yorum satirlari -> anlamli kaynak degil -> fallback'e gec
        # (mutant: 'meaningful' filtresi koruma)
        calls = {"n": 0}

        def fake_resolve(name, **k):
            return "/fake/pycdc" if name == "pycdc" else None

        def fake_run(cmd, *a, **k):
            calls["n"] += 1
            return _fake_completed("# Source generated by Decompyle++\n# but empty\n")

        monkeypatch.setattr(pd, "resolve_tool", fake_resolve)
        monkeypatch.setattr(pd, "safe_run", fake_run)

        pyc = tmp_path / "e.pyc"
        pyc.write_bytes(repair_pyc_header(_marshal_body(), RUNNING))
        res = decompile_pyc(pyc, tmp_path / "out", py_version=RUNNING)

        assert calls["n"] >= 1                 # pycdc denendi
        assert res.method != "pycdc"           # ama yorum-only reddedildi
        assert res.is_disassembly is True      # disasm'a dustu (ayni surum)

    def test_pycdc_returncode_hata_fallback(self, tmp_path, monkeypatch):
        monkeypatch.setattr(pd, "resolve_tool",
                            lambda name, **k: "/fake/pycdc" if name == "pycdc" else None)
        monkeypatch.setattr(pd, "safe_run",
                            lambda *a, **k: _fake_completed("", returncode=1, stderr="Unsupported opcode"))
        pyc = tmp_path / "h.pyc"
        pyc.write_bytes(repair_pyc_header(_marshal_body(), RUNNING))
        res = decompile_pyc(pyc, tmp_path / "out", py_version=RUNNING)
        assert res.method != "pycdc"

    def test_pycdc_timeout_fallback(self, tmp_path, monkeypatch):
        def raise_timeout(*a, **k):
            raise subprocess.TimeoutExpired(cmd="pycdc", timeout=1.0)
        monkeypatch.setattr(pd, "resolve_tool",
                            lambda name, **k: "/fake/pycdc" if name == "pycdc" else None)
        monkeypatch.setattr(pd, "safe_run", raise_timeout)
        pyc = tmp_path / "t.pyc"
        pyc.write_bytes(repair_pyc_header(_marshal_body(), RUNNING))
        # timeout -> pycdc None doner -> disasm fallback (ayni surum), patlamaz
        res = decompile_pyc(pyc, tmp_path / "out", py_version=RUNNING)
        assert res.method in ("disasm", "none")
