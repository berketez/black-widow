"""Ghidra entegrasyonu ve MachO analyzer testleri.

Test kategorileri:
1. GhidraHeadless -- is_available(), get_version(), analyze()
2. GhidraProject -- create/cleanup
3. MachOAnalyzer -- otool, strings, nm ciktilari
4. RustBinaryAnalyzer -- demangle, crate extraction
5. Gercek binary testleri (conditional -- dosya/arac yoksa skip)
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from karadul.config import Config
from karadul.core.subprocess_runner import SubprocessRunner
from karadul.core.target import TargetDetector, TargetType, Language
from karadul.core.workspace import Workspace
from karadul.ghidra.headless import GhidraHeadless
from karadul.ghidra.project import GhidraProject

# Analyzer import'lari -- register_analyzer side effect icin
from karadul.analyzers.macho import MachOAnalyzer
from karadul.analyzers.rust_binary import RustBinaryAnalyzer
from karadul.analyzers import get_analyzer


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

SAMPLE_MACHO = Path(__file__).parent / "fixtures" / "sample_macho"
CODEX_CLI = Path(
    "/opt/homebrew/Caskroom/codex/0.118.0/codex-aarch64-apple-darwin"
)


@pytest.fixture
def config() -> Config:
    """Test icin varsayilan Config."""
    return Config()


@pytest.fixture
def ghidra(config: Config) -> GhidraHeadless:
    """GhidraHeadless instance."""
    return GhidraHeadless(config)


@pytest.fixture
def workspace(tmp_path: Path) -> Workspace:
    """Gecici workspace."""
    ws = Workspace(base_dir=tmp_path / "workspaces", target_name="test_binary")
    ws.create()
    return ws


# ---------------------------------------------------------------------------
# Test 1: GhidraHeadless.is_available()
# ---------------------------------------------------------------------------

class TestGhidraHeadless:
    """GhidraHeadless unit testleri."""

    def test_is_available(self, ghidra: GhidraHeadless) -> None:
        """Ghidra analyzeHeadless mevcut olmali (config path'i dogrulanmis)."""
        result = ghidra.is_available()
        # Config'deki path gercekten var mi?
        if ghidra.analyze_headless.exists():
            assert result is True
        else:
            assert result is False

    def test_get_version(self, ghidra: GhidraHeadless) -> None:
        """Ghidra versiyonu path'ten cikartilabilmeli."""
        version = ghidra.get_version()
        if ghidra.is_available():
            # Path-based version: "12.0" gibi bir sey donmeli
            assert version is not None
            assert "." in version
        # Ghidra yoksa None donmesi normal

    def test_get_default_scripts(self, ghidra: GhidraHeadless) -> None:
        """Varsayilan scriptler mevcut olmali."""
        scripts = ghidra.get_default_scripts()
        # Scriptleri yeni yazdik, mevcut olmali
        assert len(scripts) > 0
        script_names = [s.name for s in scripts]
        assert "function_lister.py" in script_names
        assert "export_results.py" in script_names

    def test_default_scripts_order(self, ghidra: GhidraHeadless) -> None:
        """Script sirasi dogru olmali (export_results en sonda)."""
        scripts = ghidra.get_default_scripts()
        if scripts:
            assert scripts[-1].name == "export_results.py"


# ---------------------------------------------------------------------------
# Test 1b: GDT (Data Type Archive) destegi
# ---------------------------------------------------------------------------

class TestGhidraGDT:
    """Ghidra GDT (Data Type Archive) entegrasyonu testleri."""

    def test_config_gdt_default_empty(self, config: Config) -> None:
        """ghidra_data_type_archives varsayilan olarak bos liste olmali."""
        assert config.binary_reconstruction.ghidra_data_type_archives == []

    def test_config_gdt_set(self) -> None:
        """ghidra_data_type_archives listeye deger atanabilmeli."""
        config = Config()
        config.binary_reconstruction.ghidra_data_type_archives = [
            "generic_clib.gdt",
            "mac_osx.gdt",
        ]
        assert len(config.binary_reconstruction.ghidra_data_type_archives) == 2
        assert "generic_clib.gdt" in config.binary_reconstruction.ghidra_data_type_archives

    def test_config_gdt_from_dict(self) -> None:
        """YAML'dan yuklenen config GDT path'lerini icerebilmeli."""
        data = {
            "binary_reconstruction": {
                "ghidra_data_type_archives": [
                    "generic_clib.gdt",
                    "/custom/path/types.gdt",
                ],
            },
        }
        config = Config._from_dict(data)
        assert len(config.binary_reconstruction.ghidra_data_type_archives) == 2
        assert config.binary_reconstruction.ghidra_data_type_archives[0] == "generic_clib.gdt"
        assert config.binary_reconstruction.ghidra_data_type_archives[1] == "/custom/path/types.gdt"

    def test_resolve_gdt_path_absolute(self, tmp_path: Path) -> None:
        """Tam yol verilirse dogrudan dondurmeli."""
        gdt_file = tmp_path / "test.gdt"
        gdt_file.write_text("dummy", encoding="utf-8")
        result = GhidraHeadless._resolve_gdt_path(tmp_path, str(gdt_file))
        assert result == gdt_file

    def test_resolve_gdt_path_absolute_missing(self, tmp_path: Path) -> None:
        """Var olmayan tam yol icin None dondurmeli."""
        result = GhidraHeadless._resolve_gdt_path(
            tmp_path, "/nonexistent/path/types.gdt",
        )
        assert result is None

    def test_resolve_gdt_path_short_name_in_typeinfo(self, tmp_path: Path) -> None:
        """Kisa isim verilirse Ghidra typeinfo dizininde aranmali."""
        # Ghidra typeinfo dizin yapisini simule et
        typeinfo_dir = tmp_path / "Ghidra" / "Features" / "Base" / "data" / "typeinfo"
        typeinfo_dir.mkdir(parents=True)
        gdt_file = typeinfo_dir / "generic_clib.gdt"
        gdt_file.write_text("dummy", encoding="utf-8")

        result = GhidraHeadless._resolve_gdt_path(tmp_path, "generic_clib.gdt")
        assert result == gdt_file

    def test_resolve_gdt_path_auto_extension(self, tmp_path: Path) -> None:
        """Uzantisiz isim verilirse .gdt uzantisi otomatik eklenmeli."""
        typeinfo_dir = tmp_path / "Ghidra" / "Features" / "Base" / "data" / "typeinfo"
        typeinfo_dir.mkdir(parents=True)
        gdt_file = typeinfo_dir / "generic_clib.gdt"
        gdt_file.write_text("dummy", encoding="utf-8")

        result = GhidraHeadless._resolve_gdt_path(tmp_path, "generic_clib")
        assert result == gdt_file

    def test_resolve_gdt_path_subdirectory(self, tmp_path: Path) -> None:
        """Alt dizindeki GDT dosyasi recursive aranmali."""
        typeinfo_dir = tmp_path / "Ghidra" / "Features" / "Base" / "data" / "typeinfo"
        sub_dir = typeinfo_dir / "win"
        sub_dir.mkdir(parents=True)
        gdt_file = sub_dir / "windows_vs12_64.gdt"
        gdt_file.write_text("dummy", encoding="utf-8")

        result = GhidraHeadless._resolve_gdt_path(tmp_path, "windows_vs12_64.gdt")
        assert result == gdt_file

    def test_resolve_gdt_path_not_found(self, tmp_path: Path) -> None:
        """Bulunamayan GDT icin None dondurmeli."""
        typeinfo_dir = tmp_path / "Ghidra" / "Features" / "Base" / "data" / "typeinfo"
        typeinfo_dir.mkdir(parents=True)

        result = GhidraHeadless._resolve_gdt_path(tmp_path, "nonexistent.gdt")
        assert result is None

    def test_resolve_gdt_path_no_typeinfo_dir(self, tmp_path: Path) -> None:
        """typeinfo dizini yoksa None dondurmeli."""
        result = GhidraHeadless._resolve_gdt_path(tmp_path, "generic_clib.gdt")
        assert result is None

    def test_cli_gdt_params_added(self, config: Config) -> None:
        """CLI modunda GDT path'leri cmd'ye eklenmeli."""
        config.binary_reconstruction.ghidra_data_type_archives = [
            "generic_clib.gdt",
        ]
        ghidra = GhidraHeadless(config)

        # CLI komut satirini dogrudan olusturamayiz cunku
        # _analyze_cli process calistiriyor. Ama _resolve_gdt_path
        # cagrisinin dogru calistigini dolayil olarak test edebiliriz.
        ghidra_install = ghidra.analyze_headless.parent.parent
        resolved = GhidraHeadless._resolve_gdt_path(
            ghidra_install, "generic_clib.gdt",
        )
        # Ghidra kurulu ise dosya bulunur, degilse None doner
        if ghidra_install.exists():
            # Ghidra var, typeinfo dizininde aranmali
            typeinfo = ghidra_install / "Ghidra" / "Features" / "Base" / "data" / "typeinfo"
            if typeinfo.exists():
                assert resolved is not None
        # Her durumda hata vermemeli


# ---------------------------------------------------------------------------
# Test 2: GhidraProject create/cleanup
# ---------------------------------------------------------------------------

class TestGhidraProject:
    """GhidraProject unit testleri."""

    def test_create(self, workspace: Workspace, config: Config) -> None:
        """Proje dizini olusturulabilmeli."""
        proj = GhidraProject(workspace, config)
        proj_dir = proj.create()
        assert proj_dir.exists()
        assert proj_dir.is_dir()

    def test_output_dir(self, workspace: Workspace, config: Config) -> None:
        """Output dizini olusturulabilmeli."""
        proj = GhidraProject(workspace, config)
        proj.create()
        output = proj.get_output_dir()
        assert output.exists()
        assert output.is_dir()

    def test_decompiled_dir(self, workspace: Workspace, config: Config) -> None:
        """Decompiled dizini olusturulabilmeli."""
        proj = GhidraProject(workspace, config)
        proj.create()
        decompiled = proj.get_decompiled_dir()
        assert decompiled.exists()
        assert "decompiled" in str(decompiled)

    def test_cleanup(self, workspace: Workspace, config: Config) -> None:
        """Proje dizini temizlenebilmeli."""
        proj = GhidraProject(workspace, config)
        proj.create()
        assert proj.project_dir.exists()

        proj.cleanup()
        assert not proj.project_dir.exists()

    def test_cleanup_idempotent(self, workspace: Workspace, config: Config) -> None:
        """Cleanup iki kez cagrildiginda hata vermemeli."""
        proj = GhidraProject(workspace, config)
        proj.create()
        proj.cleanup()
        # Ikinci cleanup hata vermemeli
        proj.cleanup()


# ---------------------------------------------------------------------------
# Test 3: MachOAnalyzer -- sample_macho uzerinde
# ---------------------------------------------------------------------------

class TestMachOAnalyzer:
    """MachOAnalyzer testleri (sample_macho fixture ile)."""

    @pytest.fixture
    def analyzer(self, config: Config) -> MachOAnalyzer:
        return MachOAnalyzer(config)

    @pytest.fixture
    def target_info(self) -> None:
        """sample_macho icin TargetInfo."""
        if not SAMPLE_MACHO.exists():
            pytest.skip("sample_macho fixture bulunamadi")
        detector = TargetDetector()
        return detector.detect(SAMPLE_MACHO)

    def test_target_detection(self, target_info) -> None:
        """sample_macho MACHO_BINARY olarak tespit edilmeli."""
        assert target_info.target_type == TargetType.MACHO_BINARY
        assert target_info.file_size > 0

    def test_otool_libs(self, analyzer: MachOAnalyzer) -> None:
        """otool -L ciktisi dynamic library'leri listeler."""
        if not SAMPLE_MACHO.exists():
            pytest.skip("sample_macho fixture bulunamadi")
        result = analyzer._run_otool_libs(SAMPLE_MACHO)
        assert result is not None
        assert "libraries" in result
        assert result["total"] > 0
        # libSystem en azindan olmali
        lib_paths = [lib["path"] for lib in result["libraries"]]
        assert any("libSystem" in p for p in lib_paths)

    def test_otool_load_commands(self, analyzer: MachOAnalyzer) -> None:
        """otool -l ciktisi bos olmamali."""
        if not SAMPLE_MACHO.exists():
            pytest.skip("sample_macho fixture bulunamadi")
        result = analyzer._run_otool_load_commands(SAMPLE_MACHO)
        assert result
        assert "LC_SEGMENT_64" in result

    def test_strings_extraction(self, analyzer: MachOAnalyzer) -> None:
        """strings komutu bilinen string'leri bulmali."""
        if not SAMPLE_MACHO.exists():
            pytest.skip("sample_macho fixture bulunamadi")
        result = analyzer.runner.run_strings(SAMPLE_MACHO)
        assert len(result) > 0
        # C kaynak kodundaki string'ler bulunmali
        combined = "\n".join(result)
        assert "BlackWidow" in combined

    def test_nm_symbols(self, analyzer: MachOAnalyzer) -> None:
        """nm global symbol'leri bulmali."""
        if not SAMPLE_MACHO.exists():
            pytest.skip("sample_macho fixture bulunamadi")
        result = analyzer._run_nm(SAMPLE_MACHO)
        assert result is not None
        assert result["total"] > 0
        sym_names = [s["name"] for s in result["symbols"]]
        assert any("main" in n for n in sym_names)

    def test_analyzer_registry(self) -> None:
        """MachOAnalyzer MACHO_BINARY icin kayitli olmali."""
        cls = get_analyzer(TargetType.MACHO_BINARY)
        assert cls is MachOAnalyzer

    def test_universal_binary_registry(self) -> None:
        """MachOAnalyzer UNIVERSAL_BINARY icin de kayitli olmali."""
        cls = get_analyzer(TargetType.UNIVERSAL_BINARY)
        assert cls is MachOAnalyzer

    def test_analyze_static_full(
        self,
        analyzer: MachOAnalyzer,
        target_info,
        workspace: Workspace,
    ) -> None:
        """Tam statik analiz testi (Ghidra haric)."""
        if not SAMPLE_MACHO.exists():
            pytest.skip("sample_macho fixture bulunamadi")

        result = analyzer.analyze_static(target_info, workspace)

        assert result.success or len(result.artifacts) > 0
        assert result.duration_seconds > 0
        assert "dylib_count" in result.stats or "string_count" in result.stats


# ---------------------------------------------------------------------------
# Test 4: RustBinaryAnalyzer -- demangling testleri
# ---------------------------------------------------------------------------

class TestRustBinaryAnalyzer:
    """RustBinaryAnalyzer unit testleri."""

    @pytest.fixture
    def analyzer(self, config: Config) -> RustBinaryAnalyzer:
        return RustBinaryAnalyzer(config)

    def test_demangle_itanium_simple(self, analyzer: RustBinaryAnalyzer) -> None:
        """Basit Itanium ABI demangling."""
        result = analyzer._demangle_rust("_ZN4core3fmt5write17h...")
        assert "core" in result
        assert "fmt" in result

    def test_demangle_itanium_full(self, analyzer: RustBinaryAnalyzer) -> None:
        """core::fmt::write seklinde demangle olmali."""
        result = analyzer._demangle_rust("_ZN4core3fmt5writeE")
        assert result == "core::fmt::write"

    def test_demangle_std(self, analyzer: RustBinaryAnalyzer) -> None:
        """std::io::Read demangling."""
        result = analyzer._demangle_rust("_ZN3std2io4ReadE")
        assert result == "std::io::Read"

    def test_demangle_non_rust(self, analyzer: RustBinaryAnalyzer) -> None:
        """Rust olmayan symbol degismemeli."""
        result = analyzer._demangle_rust("_main")
        assert result == "_main"

    def test_demangle_empty(self, analyzer: RustBinaryAnalyzer) -> None:
        """Bos string degismemeli."""
        result = analyzer._demangle_rust("")
        assert result == ""

    def test_extract_crates(self, analyzer: RustBinaryAnalyzer) -> None:
        """Crate isimleri dogru cikartilmali."""
        symbols = [
            {"name": "_ZN4core3fmt5writeE", "address": "0x1000", "type": "T"},
            {"name": "_ZN3std2io4ReadE", "address": "0x2000", "type": "T"},
            {"name": "_ZN4core5panic8panic_fmtE", "address": "0x3000", "type": "T"},
            {"name": "_main", "address": "0x4000", "type": "T"},
        ]
        result = analyzer._extract_crates(symbols)
        crate_names = [c["name"] for c in result["crates"]]
        assert "core" in crate_names
        assert "std" in crate_names

    def test_detect_panic_handlers(self, analyzer: RustBinaryAnalyzer) -> None:
        """Panic handler pattern'leri bulunmali."""
        symbols = [
            {"name": "rust_begin_unwind", "address": "0x1000", "type": "T"},
            {"name": "_main", "address": "0x2000", "type": "T"},
            {"name": "core::panicking::panic_fmt", "address": "0x3000", "type": "T"},
        ]
        result = analyzer._detect_panic_handlers(symbols)
        assert len(result) == 2
        patterns = [r["pattern"] for r in result]
        assert "rust_begin_unwind" in patterns

    def test_find_rust_strings(self, analyzer: RustBinaryAnalyzer) -> None:
        """Rust string pattern'leri bulunmali."""
        strings = [
            "called `Result::unwrap()` on an `Err` value",
            "thread 'main' panicked at",
            "Hello world",
            "/Users/user/.cargo/registry/src/something",
            "regular string",
        ]
        result = analyzer._find_rust_strings(strings)
        assert result["total"] >= 3
        categories = result["category_stats"]
        assert "unwrap_pattern" in categories or "panic_message" in categories


# ---------------------------------------------------------------------------
# Test 5: Gercek binary testleri (conditional)
# ---------------------------------------------------------------------------

class TestRealBinary:
    """Gercek binary dosyalari ile integration testleri.

    Bu testler yalnizca ilgili dosya/arac mevcutsa calisir.
    """

    @pytest.mark.skipif(
        not SAMPLE_MACHO.exists(),
        reason="sample_macho fixture bulunamadi",
    )
    def test_sample_macho_detection(self) -> None:
        """sample_macho MACHO_BINARY olarak tespit edilmeli."""
        detector = TargetDetector()
        info = detector.detect(SAMPLE_MACHO)
        assert info.target_type == TargetType.MACHO_BINARY
        assert info.file_size > 0
        assert info.file_hash  # hash bos olmamali

    @pytest.mark.skipif(
        not SAMPLE_MACHO.exists(),
        reason="sample_macho fixture bulunamadi",
    )
    def test_sample_macho_strings(self, config: Config) -> None:
        """sample_macho'dan strings cikartilabilmeli."""
        runner = SubprocessRunner(config)
        result = runner.run_strings(SAMPLE_MACHO)
        assert len(result) > 0
        combined = "\n".join(result)
        assert "BlackWidow" in combined
        assert "ARM64" in combined

    @pytest.mark.skipif(
        not CODEX_CLI.exists(),
        reason="Codex CLI bulunamadi",
    )
    def test_codex_cli_detection(self) -> None:
        """Codex CLI MACHO_BINARY olarak tespit edilmeli."""
        detector = TargetDetector()
        info = detector.detect(CODEX_CLI)
        assert info.target_type == TargetType.MACHO_BINARY
        # Dil tespiti 1MB okuyor, Rust signature'lari daha ileride olabilir
        assert info.language in (Language.RUST, Language.UNKNOWN)
        assert info.file_size > 50_000_000  # 50MB+

    @pytest.mark.skipif(
        not CODEX_CLI.exists(),
        reason="Codex CLI bulunamadi",
    )
    def test_codex_cli_strings(self, config: Config) -> None:
        """Codex CLI'dan Rust string'leri cikartilabilmeli (timeout=120s)."""
        runner = SubprocessRunner(config)
        result = runner.run_strings(CODEX_CLI, min_length=8)
        assert len(result) > 100  # Buyuk binary, cok string olmali

    @pytest.mark.skipif(
        not GhidraHeadless(Config()).is_available(),
        reason="Ghidra mevcut degil",
    )
    @pytest.mark.skipif(
        not SAMPLE_MACHO.exists(),
        reason="sample_macho fixture bulunamadi",
    )
    def test_ghidra_full_analysis(self, config: Config, tmp_path: Path) -> None:
        """Ghidra tam analiz sample_macho uzerinde calisabilmeli."""
        ghidra = GhidraHeadless(config)

        result = ghidra.analyze(
            binary_path=SAMPLE_MACHO,
            project_dir=tmp_path / "ghidra_proj",
            project_name="test_sample",
            output_dir=tmp_path / "output",
            timeout=120,
        )

        assert result["success"] is True, (
            "Ghidra basarisiz: %s" % result.get("ghidra_log", "")[:500]
        )
        assert "functions" in result["scripts_output"]
        func_data = result["scripts_output"]["functions"]
        assert func_data["total"] > 0

        # Bilinen fonksiyonlar bulunmali
        func_names = [f["name"] for f in func_data["functions"]]
        # gcc compiled binary'lerde _main ya da entry
        assert any(
            "main" in n.lower() or "add" in n.lower() or "entry" in n.lower()
            for n in func_names
        ), "Bilinen fonksiyon bulunamadi. Bulunanlar: %s" % func_names[:20]

        # Decompilation ciktisi olmali
        if "decompiled" in result["scripts_output"]:
            decomp = result["scripts_output"]["decompiled"]
            assert decomp["success"] > 0, "Hic decompile edilen fonksiyon yok"

        # Output dosyalari olusturulmus olmali
        output_dir = tmp_path / "output"
        assert (output_dir / "functions.json").exists()
        assert (output_dir / "call_graph.json").exists()
