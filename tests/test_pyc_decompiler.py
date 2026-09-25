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
    _PYCDC_INCOMPLETE_MARKER,
    _VERSION_TO_MAGIC,
    DecompileResult,
    decompile_pyc,
    has_valid_pyc_header,
    magic_bytes_for_version,
    repair_pyc_header,
    version_from_pyc_bytes,
)

RUNNING = f"{sys.version_info.major}.{sys.version_info.minor}"
# Çalışan sürümden FARKLI bir sürüm: stdlib dis bu .pyc için kullanılamaz.
OTHER = "3.8" if RUNNING != "3.8" else "3.9"

# setup_pycdc.sh çıktısı (git-ignored). Yoksa gerçek-ikili testleri atlanır.
_VENDOR_PYCDC = Path(__file__).resolve().parents[1] / "vendor" / "pycdc"
_HAS_VENDOR_PYCDC = (_VENDOR_PYCDC / "pycdc").is_file() and (_VENDOR_PYCDC / "pycdas").is_file()


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


# ---------------------------------------------------------------------------
# pycdc çıktı doğrulaması -- 2026-09-25 regresyonu: pycdc desteklemediği opcode'da
# da rc=0 döner; eksik/geçersiz çıktı "decompiled" sayılıyordu (gerçek 3.12
# PyInstaller binary'si: 7/7 iddia, 0/7 derlenebilir + eksiksiz).
# ---------------------------------------------------------------------------

def _pycdc_only(monkeypatch, stdout, returncode: int = 0, stderr: str = "") -> None:
    """Yalnız pycdc 'kurulu' (pycdas yok); safe_run sabit pycdc sonucu döner."""
    monkeypatch.setattr(pd, "resolve_tool",
                        lambda name, **k: "/fake/pycdc" if name == "pycdc" else None)
    monkeypatch.setattr(pd, "safe_run",
                        lambda *a, **k: _fake_completed(stdout, returncode=returncode, stderr=stderr))


class TestPycdcCiktiDogrulama:
    """Her sinyal TEK BAŞINA kısmi saydırmalı -> her kontrol ayrı mutation'la korunur."""

    @pytest.mark.parametrize("stdout,rc,stderr,beklenen", [
        # yalnız işaret (rc=0, stderr boş, derlenebilir) -- pycdc 3.12 struct.pyc deseni
        ("x = 1\n" + _PYCDC_INCOMPLETE_MARKER + "\n", 0, "", "Decompyle incomplete"),
        # yalnız stderr: derlenebilir ama anlamca YANLIŞ (pycdc 3.11: return döngü içine kaydı)
        ("def t(vs):\n    for v in vs:\n        return v\n", 0,
         "Warning: block stack is not empty!\n", "pycdc stderr"),
        # yalnız compile: modül düzeyi return -- ast.parse GEÇER, compile() geçmez
        ("if __name__ == '__main__':\n    print(1)\n    return None\n", 0, "", "SyntaxError"),
        # yalnız rc: sinyalle çöküş; çıktı derlenebilir ama yarıda kesik
        ("def greet(n):\n    return n\n", -11, "", "SIGSEGV"),
    ], ids=["isaret", "stderr", "compile", "rc"])
    def test_tek_sinyal_kismi_sayilir(self, tmp_path, monkeypatch, stdout, rc, stderr, beklenen):
        _pycdc_only(monkeypatch, stdout, rc, stderr)
        pyc = tmp_path / "m.pyc"
        pyc.write_bytes(repair_pyc_header(_marshal_body(), RUNNING))
        res = decompile_pyc(pyc, tmp_path / "out", py_version=RUNNING)

        assert res.success is False                    # BUG: eskiden True
        assert res.method != "pycdc"
        assert not (tmp_path / "out" / "m.py").exists()  # sahte "kaynak" yazılmadı
        assert res.partial_path is not None and res.partial_path.name == "m.partial.py"
        assert beklenen in res.partial_reason
        text = res.partial_path.read_text(encoding="utf-8")
        assert text.startswith("# KARADUL: pycdc çıktısı DOĞRULANAMADI")
        assert stdout in text                          # pycdc çıktısı kaybolmadı
        assert res.is_disassembly is True              # zincir disasm'a devam etti

    def test_syntaxerror_satiri_partial_dosyasina_denk(self, tmp_path, monkeypatch):
        """Nedendeki satır numarası uyarı başlığı eklenmiş .partial.py'ye göredir."""
        import re
        _pycdc_only(monkeypatch, "if __name__ == '__main__':\n    print(1)\n    return None\n")
        pyc = tmp_path / "m.pyc"
        pyc.write_bytes(repair_pyc_header(_marshal_body(), RUNNING))
        res = decompile_pyc(pyc, tmp_path / "out", py_version=RUNNING)
        m = re.search(r"\.partial\.py satır (\d+)", res.partial_reason)
        assert m, res.partial_reason
        lines = res.partial_path.read_text(encoding="utf-8").splitlines()
        assert lines[int(m.group(1)) - 1].strip() == "return None"

    def test_disasm_yoksa_kismi_cikti_yine_teslim(self, tmp_path, monkeypatch):
        """Farklı sürüm + pycdas yok -> disasm yok; kısmi pycdc çıktısı tek sonuç olur."""
        _pycdc_only(monkeypatch, "x = 1\n" + _PYCDC_INCOMPLETE_MARKER + "\n")
        pyc = tmp_path / "m.pyc"
        pyc.write_bytes(repair_pyc_header(_marshal_body(), OTHER))
        res = decompile_pyc(pyc, tmp_path / "out", py_version=OTHER)
        assert res.success is False
        assert res.is_disassembly is False
        assert res.method == "pycdc_partial"
        assert res.output_path == res.partial_path and res.partial_path.exists()


class TestPycdcCiktiKodlama:
    def test_gecersiz_utf8_cikti_kaybolmaz(self, tmp_path, monkeypatch):
        """pycdc yalnız vekil karakteri ham bayt basar (ölçülen: '\\udcff' -> ed b3 bf).

        Regresyon: text=True ile UnicodeDecodeError -> pycdc çıktısının TAMAMI atılıyordu.
        Sahte safe_run gerçek subprocess gibi davranır: metin istenirse çözerken patlar.
        """
        raw = "A = 'dünya'\nB = '".encode("utf-8") + b"\xed\xb3\xbf" + b"'\n"

        def fake_run(cmd, **k):
            if k.get("text", True):
                raw.decode("utf-8")  # subprocess(text=True) davranışı: UnicodeDecodeError
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout=raw, stderr=b"")

        monkeypatch.setattr(pd, "resolve_tool",
                            lambda name, **k: "/fake/pycdc" if name == "pycdc" else None)
        monkeypatch.setattr(pd, "safe_run", fake_run)
        pyc = tmp_path / "enc.pyc"
        pyc.write_bytes(repair_pyc_header(_marshal_body(), RUNNING))
        res = decompile_pyc(pyc, tmp_path / "out", py_version=RUNNING)

        assert res.partial_path is not None           # çıktı korunur...
        assert "geçersiz UTF-8" in res.partial_reason  # ...ama sabit bozulduğu için kısmi
        text = res.partial_path.read_text(encoding="utf-8")
        assert "A = 'dünya'" in text and "\ufffd" in text


class TestPycdasAracYolu:
    def test_pycdas_extra_paths_ile_bulunur(self, tmp_path, monkeypatch):
        """pycdas yalnız extra_paths'te (vendor/pycdc) -> farklı sürümlü .pyc disasm olmalı.

        Regresyon: _disassemble resolve_tool("pycdas")'ı extra_paths'siz çağırıyordu;
        vendor'daki pycdas hiç bulunmuyordu (ölçülen: 3.9 korpusunda 2/7, 3.11 ve 3.13'te
        1/7 dosya "none"a düştü).
        """
        vendor = str(tmp_path / "vendor")

        def fake_resolve(name, extra_paths=None):
            if name == "pycdas" and extra_paths and vendor in extra_paths:
                return "/fake/pycdas"
            return None

        monkeypatch.setattr(pd, "resolve_tool", fake_resolve)
        monkeypatch.setattr(pd, "safe_run", lambda cmd, **k: _fake_completed(
            "m.pyc (Python 3.8)\n[Code]\n    File Name: m.py\n"))
        pyc = tmp_path / "m.pyc"
        pyc.write_bytes(repair_pyc_header(_marshal_body(), OTHER))
        res = decompile_pyc(pyc, tmp_path / "out", py_version=OTHER, extra_paths=[vendor])
        assert res.method == "disasm"
        assert res.is_disassembly is True
        assert "[Code]" in res.output_path.read_text()

    def test_pycdas_bad_magic_disasm_sayilmaz(self, tmp_path, monkeypatch):
        """pycdas tanımadığı magic'te de rc=0 döner ('<NULL>'); disassembly sayılmamalı."""
        monkeypatch.setattr(pd, "resolve_tool",
                            lambda name, **k: "/fake/pycdas" if name == "pycdas" else None)
        monkeypatch.setattr(pd, "safe_run", lambda cmd, **k: _fake_completed(
            "m (Python -1.-1)\n<NULL>", stderr="Bad MAGIC!\n"))
        pyc = tmp_path / "m.pyc"
        pyc.write_bytes(repair_pyc_header(_marshal_body(), OTHER))
        res = decompile_pyc(pyc, tmp_path / "out", py_version=OTHER)
        assert res.is_disassembly is False
        assert res.method == "none"


@pytest.mark.skipif(not _HAS_VENDOR_PYCDC, reason="vendor/pycdc yok (scripts/setup_pycdc.sh)")
class TestGercekPycdc:
    """Gerçek pycdc/pycdas ikilileriyle DEĞİŞMEZ: "decompiled" denen her çıktı derlenir ve
    'Decompyle incomplete' taşımaz. pycdc yeteneğinden bağımsızdır (pycdc gelişse de geçer);
    pycdc b428976 ile 3.11/3.12/3.13'te closure ve 3.12+'da star-import eksik çıkar -> eski
    kod bu testte düşer."""

    KORPUS = {
        "add": "def f(a, b):\n    return a + b\n",
        "closure": "def outer(x):\n    def inner(y):\n        return x + y\n    return inner\n",
        "star": "from os.path import *\n",
        "tryexc": ("def g(a, b):\n    try:\n        return a / b\n"
                   "    except ZeroDivisionError:\n        return None\n"),
        "main": "import sys\nif __name__ == '__main__':\n    print(sys.argv)\n",
    }

    def test_decompiled_denen_her_cikti_gecerli(self, tmp_path):
        import warnings
        for ad, src in self.KORPUS.items():
            pyc = tmp_path / f"{ad}.pyc"
            pyc.write_bytes(_real_pyc(src))
            res = decompile_pyc(pyc, tmp_path / "out", py_version=RUNNING,
                                extra_paths=[str(_VENDOR_PYCDC)])
            if res.success:
                text = res.output_path.read_text(encoding="utf-8")
                assert _PYCDC_INCOMPLETE_MARKER not in text, ad
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore")
                    compile(text, ad, "exec", dont_inherit=True)  # SyntaxError -> FAIL
            else:
                assert res.partial_path is not None or res.is_disassembly, ad
            if res.is_disassembly:
                # "[Code]" yalnız pycdas'ta var (stdlib dis basmaz) -> vendor pycdas kullanıldı
                assert "[Code]" in res.output_path.read_text(encoding="utf-8"), ad

    def test_vekil_karakterli_sabit_ciktiyi_dusurmez(self, tmp_path):
        pyc = tmp_path / "enc.pyc"
        pyc.write_bytes(_real_pyc("A = 'dünya'\nB = '\\udcff'\n"))
        res = decompile_pyc(pyc, tmp_path / "out", py_version=RUNNING,
                            extra_paths=[str(_VENDOR_PYCDC)])
        kaynak = res.output_path if res.success else res.partial_path
        assert kaynak is not None, "pycdc çıktısı kayboldu (UnicodeDecodeError regresyonu)"
        assert "dünya" in kaynak.read_text(encoding="utf-8")
