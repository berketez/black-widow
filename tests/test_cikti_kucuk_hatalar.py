"""Çıktıdaki beş küçük hata (2026-11-11).

Rapor sayaçları (docs/arge/2026-11-11_rapor_sayaclari/sonuc.md) ve temiz harita
(docs/arge/2026-11-11_temiz_harita/sonuc.md) onarımlarında görülüp dokunulmayan, kullanıcıya
yanlış ya da eksik bilgi gösteren çıktılar. Hiçbiri ad davranışını değiştirmez.

1. Markdown raporu ithal sayısı bilinmiyorken "0" yazıyordu (JSON raporu "N/A" yazıyor).
2. ``lief_analysis.json`` kitaplık listesi ELF'te hep boştu: lief 0.17 ELF ve PE kitaplıklarını düz
   metin verir, kod yalnız Mach-O nesnelerinin ``.name`` alanını okuyordu.
3. ``symbols.json`` stripped ELF'te 0 simgeydi: ``nm -g`` dinamik simge tablosunu okumaz (``-D``
   yok) ve PATH'teki nm (conda cctools) ELF'i hiç okumaz. nm simge vermezse ELF'in dinamik simge
   tablosu lief ile okunur; kayıtlar ``nm -gD`` ile aynı (adres, harf, sürüm eksiz ad).
4. CLI "Imports" satırı ikililerde hiç çıkmıyordu: ``stats["imports"]`` yalnız JS çözümleyicisinde
   üretilir; ikililerin sayısı ``imports_found``. Değer yoksa satır yazılmaz.
"""

from __future__ import annotations

import sys
import types
from pathlib import Path

import pytest

import tests.test_macho as _tm
from karadul.analyzers import macho as _macho
from karadul.analyzers.macho import MachOAnalyzer
from karadul.core.result import PipelineResult, StageResult
from karadul.core.target import TargetType
from karadul.core.workspace import Workspace
from karadul.reporting.markdown_report import MarkdownReporter


def _workspace(tmp_path: Path) -> Workspace:
    ws = Workspace(base_dir=tmp_path / "workspaces", target_name="ikili")
    ws.create()
    return ws


def _result(ws: Workspace, stages: dict[str, dict]) -> PipelineResult:
    result = PipelineResult(target_name="ikili", target_hash="0" * 64, workspace_path=ws.path)
    for name, stats in stages.items():
        result.add_stage_result(StageResult(
            stage_name=name, success=True, duration_seconds=1.0, stats=stats,
        ))
    return result


# ---------------------------------------------------------------------------
# 1. Markdown raporu: ithal sayısı
# ---------------------------------------------------------------------------


def _markdown_imports_line(tmp_path: Path, static_stats: dict) -> str:
    """``reports/report.md`` yazılır ve ithal satırı geri okunur."""
    ws = _workspace(tmp_path)
    path = MarkdownReporter().generate(_result(ws, {"static": static_stats}), ws)
    lines = [ln for ln in path.read_text(encoding="utf-8").splitlines() if "Imports found" in ln]
    assert len(lines) == 1
    return lines[0]


class TestMarkdownImports:
    def test_sayi_varsa_yazilir(self, tmp_path) -> None:
        line = _markdown_imports_line(tmp_path, {"ghidra_function_count": 250, "imports_found": 63})
        assert line == "- **Imports found:** 63"

    def test_gercek_sifir_korunur(self, tmp_path) -> None:
        """İthal listesi okundu ve boşsa sayı gerçekten 0'dır."""
        line = _markdown_imports_line(tmp_path, {"imports_found": 0})
        assert line == "- **Imports found:** 0"

    def test_bilinmiyorsa_sifir_degil(self, tmp_path) -> None:
        line = _markdown_imports_line(tmp_path, {"ghidra_function_count": 250})
        assert line == "- **Imports found:** N/A"


# ---------------------------------------------------------------------------
# 2. lief kitaplık listesi: ELF/PE düz metin, Mach-O nesne
# ---------------------------------------------------------------------------

_ELF_STRIPPED = (
    Path(__file__).parent / "benchmark" / "fixtures" / "linux_elf_stripped" / "sample_elf_stripped"
)


def _fake_lief(monkeypatch, binary) -> None:
    fake = types.ModuleType("lief")
    fake.parse = lambda _p: binary  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "lief", fake)


class _Dylib:
    def __init__(self, name: str) -> None:
        self.name = name


def _lief_binary(libraries: list) -> object:
    return types.SimpleNamespace(
        format="ELF", segments=[], sections=[], libraries=libraries, imported_functions=[],
    )


class TestLiefLibraries:
    def test_elf_duz_metin_okunur(self, monkeypatch, tmp_path, config) -> None:
        _fake_lief(monkeypatch, _lief_binary(["libc.so.6", "ld-linux-aarch64.so.1"]))
        result = MachOAnalyzer(config)._run_lief(tmp_path / "ikili")
        assert result["libraries"] == ["libc.so.6", "ld-linux-aarch64.so.1"]

    def test_macho_nesne_adi_okunur(self, monkeypatch, tmp_path, config) -> None:
        _fake_lief(monkeypatch, _lief_binary([_Dylib("/usr/lib/libSystem.B.dylib")]))
        result = MachOAnalyzer(config)._run_lief(tmp_path / "ikili")
        assert result["libraries"] == ["/usr/lib/libSystem.B.dylib"]

    def test_gercek_lief_elf(self, config) -> None:
        """Depodaki stripped ELF örneği gerçek lief ile: DT_NEEDED girdisi listede."""
        pytest.importorskip("lief")
        result = MachOAnalyzer(config)._run_lief(_ELF_STRIPPED)
        assert result is not None
        assert result["libraries"] == ["libc.so.6"]


# ---------------------------------------------------------------------------
# 3. Stripped ELF simgeleri: dinamik simge tablosu
# ---------------------------------------------------------------------------

_W, _A, _X = _macho._SHF_WRITE, _macho._SHF_ALLOC, _macho._SHF_EXECINSTR
_GLOBAL, _WEAK, _UNIQUE = _macho._STB_GLOBAL, _macho._STB_WEAK, _macho._STB_GNU_UNIQUE
_NOTYPE, _OBJECT, _FUNC, _IFUNC = 0, _macho._STT_OBJECT, 2, _macho._STT_GNU_IFUNC
_PROGBITS, _NOBITS = 1, _macho._SHT_NOBITS


@pytest.mark.parametrize(
    "binding, sym_type, shndx, sec_type, sec_flags, letter",
    [
        (_WEAK, _NOTYPE, 0, None, None, "w"),         # zayıf tanımsız
        (_WEAK, _OBJECT, 0, None, None, "v"),         # zayıf tanımsız nesne
        (_WEAK, _FUNC, 12, _PROGBITS, _A | _X, "W"),  # zayıf tanımlı
        (_WEAK, _OBJECT, 20, _PROGBITS, _A | _W, "V"),
        (_GLOBAL, _FUNC, 0, None, None, "U"),
        (_GLOBAL, _OBJECT, 0xFFF2, None, None, "C"),
        (_UNIQUE, _OBJECT, 20, _PROGBITS, _A | _W, "u"),
        (_GLOBAL, _IFUNC, 12, _PROGBITS, _A | _X, "i"),
        (_GLOBAL, _NOTYPE, 0xFFF1, None, None, "A"),
        (_GLOBAL, _FUNC, 12, None, None, "?"),        # bölüm bilinmiyor
        (_GLOBAL, _FUNC, 12, _PROGBITS, _A | _X, "T"),
        (_GLOBAL, _OBJECT, 25, _NOBITS, _A | _W, "B"),
        (_GLOBAL, _OBJECT, 20, _PROGBITS, _A | _W, "D"),
        (_GLOBAL, _OBJECT, 15, _PROGBITS, _A, "R"),
        (_GLOBAL, _NOTYPE, 30, _PROGBITS, 0, "N"),
    ],
)
def test_elf_nm_harfi(binding, sym_type, shndx, sec_type, sec_flags, letter) -> None:
    assert _macho._elf_nm_letter(binding, sym_type, shndx, sec_type, sec_flags) == letter


def _sym(name, binding, sym_type, shndx, value=0, section=None):
    return types.SimpleNamespace(
        name=name, binding=binding, type=sym_type, shndx=shndx, value=value, section=section,
    )


def _elf(symbols, identity_class=2):
    return types.SimpleNamespace(
        header=types.SimpleNamespace(identity_class=identity_class), dynamic_symbols=symbols,
    )


_TEXT = types.SimpleNamespace(type=_PROGBITS, flags=_A | _X)


class TestRunElfDynsym:
    def test_gercek_lief_nm_gD_ile_ayni(self, config) -> None:
        """Depodaki stripped ELF: ``/usr/bin/nm -gD`` çıktısıyla aynı kayıtlar (sürüm eki atılmış)."""
        pytest.importorskip("lief")
        result = MachOAnalyzer(config)._run_elf_dynsym(_ELF_STRIPPED)
        got = sorted((s["address"], s["type"], s["name"]) for s in result["symbols"])
        assert got == sorted([
            (None, "w", "_ITM_deregisterTMCloneTable"),
            (None, "w", "_ITM_registerTMCloneTable"),
            (None, "w", "__gmon_start__"),
            (None, "U", "__libc_start_main"),
            (None, "U", "abort"),
            (None, "U", "strlen"),
        ])
        assert result["total"] == 6
        assert result["source"] == "elf_dynamic_symbols"

    def test_yalniz_dis_simgeler(self, monkeypatch, tmp_path, config) -> None:
        """nm -g gibi: yerel, bölüm ve adsız girişler atlanır; tanımlı simgenin adresi yazılır."""
        _fake_lief(monkeypatch, _elf([
            _sym("", 0, _NOTYPE, 0),
            _sym("", 0, _macho._STT_SECTION, 12, 0x3c98, _TEXT),
            _sym("yerel_fn", 0, _FUNC, 12, 0x4000, _TEXT),
            _sym("main", _GLOBAL, _FUNC, 12, 0x4100, _TEXT),
            _sym("printf", _GLOBAL, _FUNC, 0),
        ]))
        result = MachOAnalyzer(config)._run_elf_dynsym(tmp_path / "ikili")
        assert result["symbols"] == [
            {"address": "0000000000004100", "type": "T", "name": "main"},
            {"address": None, "type": "U", "name": "printf"},
        ]

    def test_elf32_adres_genisligi(self, monkeypatch, tmp_path, config) -> None:
        _fake_lief(monkeypatch, _elf([_sym("main", _GLOBAL, _FUNC, 12, 0x8100, _TEXT)], 1))
        result = MachOAnalyzer(config)._run_elf_dynsym(tmp_path / "ikili")
        assert result["symbols"][0]["address"] == "00008100"

    def test_okunamazsa_none(self, monkeypatch, tmp_path, config) -> None:
        _fake_lief(monkeypatch, types.SimpleNamespace())  # dynamic_symbols yok
        assert MachOAnalyzer(config)._run_elf_dynsym(tmp_path / "ikili") is None


_NM_ONE = {
    "binary": "x", "total": 1, "symbols": [{"address": "0x100", "type": "T", "name": "_main"}],
}
_DYNSYM = {
    "binary": "x", "total": 2, "source": "elf_dynamic_symbols",
    "symbols": [
        {"address": None, "type": "U", "name": "memcpy"},
        {"address": None, "type": "w", "name": "__gmon_start__"},
    ],
}


def _static_symbols(monkeypatch, tmp_path, sample_macho_file, config, target_type, nm_result):
    """analyze_static: nm ve dinamik tablo sahte; symbols.json ve symbol_count geri okunur."""
    _tm.TestAnalyzeStatic()._patch_pipeline(monkeypatch, ghidra_result=None)
    monkeypatch.setattr(MachOAnalyzer, "_run_nm", lambda self, p: nm_result, raising=True)
    calls: list[Path] = []

    def _dynsym(self, p):
        calls.append(p)
        return _DYNSYM

    monkeypatch.setattr(MachOAnalyzer, "_run_elf_dynsym", _dynsym, raising=True)
    ws = _tm._make_workspace(tmp_path)
    target = _tm._make_target(sample_macho_file, target_type)
    result = MachOAnalyzer(config).analyze_static(target, ws)
    return ws.load_json("static", "symbols"), result.stats.get("symbol_count"), calls


class TestStaticSymbols:
    @pytest.mark.parametrize("nm_result", [
        {"binary": "x", "total": 0, "symbols": []},  # nm -g: stripped ELF'te simge yok
        None,                                         # nm başarısız (ELF'i okuyamıyor)
    ])
    def test_elf_nm_bos_dinamik_tablo_okunur(
        self, monkeypatch, tmp_path, sample_macho_file, config, nm_result,
    ) -> None:
        data, count, calls = _static_symbols(
            monkeypatch, tmp_path, sample_macho_file, config, TargetType.ELF_BINARY, nm_result,
        )
        assert data == _DYNSYM
        assert count == 2
        assert len(calls) == 1

    def test_elf_nm_simge_verdiyse_nm_kalir(
        self, monkeypatch, tmp_path, sample_macho_file, config,
    ) -> None:
        data, count, calls = _static_symbols(
            monkeypatch, tmp_path, sample_macho_file, config, TargetType.ELF_BINARY, _NM_ONE,
        )
        assert data == _NM_ONE
        assert count == 1
        assert calls == []

    def test_macho_dinamik_tablo_okunmaz(
        self, monkeypatch, tmp_path, sample_macho_file, config,
    ) -> None:
        empty = {"binary": "x", "total": 0, "symbols": []}
        data, count, calls = _static_symbols(
            monkeypatch, tmp_path, sample_macho_file, config, TargetType.MACHO_BINARY, empty,
        )
        assert data == empty
        assert count == 0
        assert calls == []


# ---------------------------------------------------------------------------
# 4. CLI "Imports" satırı
# ---------------------------------------------------------------------------


def _imports_lines(lines: list[str]) -> list[str]:
    return [ln for ln in lines if "Imports" in ln]


class TestCliImports:
    def test_canli_panel_ikili_ithal_sayisi(self) -> None:
        import karadul.hacker_cli as h

        stats = {"ghidra_function_count": 250, "imports_found": 63}
        lines = _imports_lines(h._format_stage_stats("static", stats))
        assert len(lines) == 1
        assert "Imports: [medium_purple1]63[/]" in lines[0]

    def test_canli_panel_js_ithal_sayisi_korunur(self) -> None:
        import karadul.hacker_cli as h

        lines = _imports_lines(h._format_stage_stats("static", {"functions": 10, "imports": 12}))
        assert len(lines) == 1
        assert "Imports: [medium_purple1]12[/]" in lines[0]

    def test_canli_panel_deger_yoksa_satir_yok(self) -> None:
        import karadul.hacker_cli as h

        assert _imports_lines(h._format_stage_stats("static", {"ghidra_function_count": 250})) == []

    @staticmethod
    def _stage_log(monkeypatch, stats: dict) -> str:
        import io

        from rich.console import Console

        import karadul.hacker_cli as h

        buf = io.StringIO()
        monkeypatch.setattr(h, "console", Console(file=buf, theme=h.KARADUL_THEME, width=200))
        h._show_stage_result("static", StageResult(
            stage_name="static", success=True, duration_seconds=1.0, stats=stats,
        ), "12:00:00")
        return buf.getvalue()

    def test_asama_gunlugu_ikili_ithal_sayisi(self, monkeypatch) -> None:
        out = self._stage_log(monkeypatch, {"ghidra_function_count": 250, "imports_found": 63})
        assert "|-- Imports: 63" in out

    def test_asama_gunlugu_deger_yoksa_satir_yok(self, monkeypatch) -> None:
        out = self._stage_log(monkeypatch, {"ghidra_function_count": 250})
        assert "Imports" not in out
