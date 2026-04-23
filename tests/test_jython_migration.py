"""v1.11.0 Jython Sunset Faz 1: Migration syntax + import testleri.

Bu test suite PyGhidra 3.0 Python 3 migrasyonunun temel dogrulamasini yapar:
- Migrate edilmis script py3 syntax'ina uygun (py_compile)
- Legacy backup mevcut ve py3 syntax'ina da uygun (Jython 2.7 icin yazilan
  ortak altkume; bu yuzden Python 3'te de compile edilebilir olmasi sart)
- Feature flag config.perf.use_legacy_jython_scripts mevcut ve False default
- headless.get_default_scripts() flag'e gore dogru branch'i seciyor
- JSON output schema (modul-level top-level anahtarlar) beklenen yapida
"""

from __future__ import annotations

import json
import py_compile
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "karadul" / "ghidra" / "scripts"
LEGACY_DIR = SCRIPTS_DIR / "legacy"


class TestMigrationSyntax:
    """Migrate edilmis ve legacy scriptler Python 3 syntax'ina uygun olmali."""

    def test_migrated_function_lister_py3_compile(self) -> None:
        """Yeni function_lister.py py_compile OK (Python 3 syntax)."""
        script = SCRIPTS_DIR / "function_lister.py"
        assert script.exists(), f"Migrate edilmis script bulunamadi: {script}"
        # py_compile.compile hata atarsa test fail.
        py_compile.compile(str(script), doraise=True)

    def test_legacy_function_lister_py3_compile(self) -> None:
        """Legacy backup py3'te de compile olmali (Jython Py2/3 ortak altkume)."""
        legacy = LEGACY_DIR / "function_lister.py"
        assert legacy.exists(), f"Legacy backup bulunamadi: {legacy}"
        py_compile.compile(str(legacy), doraise=True)

    def test_migrated_script_uses_future_annotations(self) -> None:
        """Migrate edilmis script 'from __future__ import annotations' icermeli."""
        script = SCRIPTS_DIR / "function_lister.py"
        content = script.read_text(encoding="utf-8")
        assert "from __future__ import annotations" in content

    def test_migrated_script_header_updated(self) -> None:
        """Migrate edilmis scriptin header'i PyGhidra 3.0'a guncel olmali."""
        script = SCRIPTS_DIR / "function_lister.py"
        content = script.read_text(encoding="utf-8")
        assert "PyGhidra 3.0" in content
        # Eski Jython 2.7 kisitlamasi kaldirilmis olmali
        assert "Python 3 syntax'i KULLANILMAMALIDIR" not in content

    def test_migrated_script_uses_utf8_open(self) -> None:
        """Migrate edilmis script UTF-8 encoding ile dosya acmali."""
        script = SCRIPTS_DIR / "function_lister.py"
        content = script.read_text(encoding="utf-8")
        assert 'encoding="utf-8"' in content
        assert "ensure_ascii=False" in content

    def test_migrated_script_defensive_jpype_wraps(self) -> None:
        """JPype boundary'de str()/int() defansifleri olmali."""
        script = SCRIPTS_DIR / "function_lister.py"
        content = script.read_text(encoding="utf-8")
        # En azindan su wrapper'lar kullanilmali
        assert "str(func.getName())" in content
        assert "int(func.getBody().getNumAddresses())" in content


class TestFeatureFlag:
    """config.perf.use_legacy_jython_scripts feature flag testleri."""

    def test_perf_config_has_flag(self) -> None:
        """PerfConfig use_legacy_jython_scripts alanina sahip olmali."""
        from karadul.config import PerfConfig
        perf = PerfConfig()
        assert hasattr(perf, "use_legacy_jython_scripts")
        # Default False olmali (yeni script'ler aktif)
        assert perf.use_legacy_jython_scripts is False

    def test_config_default_uses_migrated_script(self) -> None:
        """Default config -> get_default_scripts function_lister'i ana
        scripts_dir'den yukluyor olmali (legacy'den DEGIL)."""
        from karadul.config import Config
        from karadul.ghidra.headless import GhidraHeadless

        cfg = Config()
        assert cfg.perf.use_legacy_jython_scripts is False

        ghidra = GhidraHeadless(cfg)
        scripts = ghidra.get_default_scripts()
        fl_paths = [s for s in scripts if s.name == "function_lister.py"]
        assert len(fl_paths) == 1
        # legacy/ klasoru path'te olmamali
        assert "legacy" not in fl_paths[0].parts

    def test_legacy_flag_selects_legacy_script(self) -> None:
        """Flag True -> function_lister.py legacy/ altindan yuklenmeli."""
        from karadul.config import Config
        from karadul.ghidra.headless import GhidraHeadless

        cfg = Config()
        cfg.perf.use_legacy_jython_scripts = True
        ghidra = GhidraHeadless(cfg)
        scripts = ghidra.get_default_scripts()
        fl_paths = [s for s in scripts if s.name == "function_lister.py"]
        assert len(fl_paths) == 1
        assert "legacy" in fl_paths[0].parts

    def test_non_migrated_scripts_unaffected_by_flag(self) -> None:
        """v1.11.0 Dalga 6B sonrası tüm default scriptler migrate edildi.

        Flag True iken HEPSİ legacy/'den yüklenmeli; migrate edilmemiş
        script kalmadığı için non_migrated set'i boş. Ileride yeni bir
        script eklenirse (migrate edilmemiş) burada tekrar doldurulur.
        """
        from karadul.config import Config
        from karadul.ghidra.headless import GhidraHeadless

        cfg = Config()
        cfg.perf.use_legacy_jython_scripts = True
        ghidra = GhidraHeadless(cfg)
        scripts = ghidra.get_default_scripts()

        # Faz 1 Dalga 2: function_lister
        # Faz 1.2 Dalga 3: string_extractor + type_recovery
        # Faz 1.3 Dalga 4: call_graph + cfg_extraction + xref_analysis
        # Faz 1.4 Dalga 6B: decompile_all + export_results +
        #                    function_id_extractor + pcode_analysis
        non_migrated: set[str] = set()
        for script in scripts:
            if script.name in non_migrated:
                assert "legacy" not in script.parts, (
                    f"{script.name} legacy'den yuklenmemeli (henuz migrate edilmedi)"
                )

    def test_dalga3_migrated_scripts_load_from_legacy_when_flag_on(self) -> None:
        """Faz 1.2 Dalga 3: Flag True -> string_extractor/type_recovery legacy'den."""
        from karadul.config import Config
        from karadul.ghidra.headless import GhidraHeadless

        cfg = Config()
        cfg.perf.use_legacy_jython_scripts = True
        ghidra = GhidraHeadless(cfg)
        scripts = ghidra.get_default_scripts()

        migrated_in_dalga3 = {"string_extractor.py", "type_recovery.py"}
        for script in scripts:
            if script.name in migrated_in_dalga3:
                assert "legacy" in script.parts, (
                    f"{script.name} flag=True iken legacy/'den yuklenmeli"
                )

    def test_dalga3_migrated_scripts_use_new_when_flag_off(self) -> None:
        """Faz 1.2 Dalga 3: Default flag=False -> yeni PyGhidra 3.0 versiyonlari."""
        from karadul.config import Config
        from karadul.ghidra.headless import GhidraHeadless

        cfg = Config()
        assert cfg.perf.use_legacy_jython_scripts is False
        ghidra = GhidraHeadless(cfg)
        scripts = ghidra.get_default_scripts()

        migrated_in_dalga3 = {"string_extractor.py", "type_recovery.py"}
        for script in scripts:
            if script.name in migrated_in_dalga3:
                assert "legacy" not in script.parts, (
                    f"{script.name} flag=False iken yeni versiyonu yuklenmeli"
                )

    def test_dalga4_migrated_scripts_load_from_legacy_when_flag_on(self) -> None:
        """Faz 1.3 Dalga 4: Flag True -> call_graph/cfg_extraction/xref_analysis legacy'den."""
        from karadul.config import Config
        from karadul.ghidra.headless import GhidraHeadless

        cfg = Config()
        cfg.perf.use_legacy_jython_scripts = True
        ghidra = GhidraHeadless(cfg)
        scripts = ghidra.get_default_scripts()

        migrated_in_dalga4 = {
            "call_graph.py",
            "cfg_extraction.py",
            "xref_analysis.py",
        }
        for script in scripts:
            if script.name in migrated_in_dalga4:
                assert "legacy" in script.parts, (
                    f"{script.name} flag=True iken legacy/'den yuklenmeli"
                )

    def test_dalga4_migrated_scripts_use_new_when_flag_off(self) -> None:
        """Faz 1.3 Dalga 4: Default flag=False -> yeni PyGhidra 3.0 versiyonlari."""
        from karadul.config import Config
        from karadul.ghidra.headless import GhidraHeadless

        cfg = Config()
        assert cfg.perf.use_legacy_jython_scripts is False
        ghidra = GhidraHeadless(cfg)
        scripts = ghidra.get_default_scripts()

        migrated_in_dalga4 = {
            "call_graph.py",
            "cfg_extraction.py",
            "xref_analysis.py",
        }
        for script in scripts:
            if script.name in migrated_in_dalga4:
                assert "legacy" not in script.parts, (
                    f"{script.name} flag=False iken yeni versiyonu yuklenmeli"
                )

    def test_dalga4_migrated_scripts_py3_compile(self) -> None:
        """Faz 1.3 Dalga 4: 3 script py_compile OK (Python 3 syntax)."""
        import py_compile

        for name in ("call_graph.py", "cfg_extraction.py", "xref_analysis.py"):
            script = SCRIPTS_DIR / name
            assert script.exists(), f"Migrate edilmis script bulunamadi: {script}"
            py_compile.compile(str(script), doraise=True)

    def test_dalga6_migrated_scripts_load_from_legacy_when_flag_on(self) -> None:
        """Faz 1.4 Dalga 6B: flag=True -> 4 yeni migrate legacy'den."""
        from karadul.config import Config
        from karadul.ghidra.headless import GhidraHeadless

        cfg = Config()
        cfg.perf.use_legacy_jython_scripts = True
        ghidra = GhidraHeadless(cfg)
        scripts = ghidra.get_default_scripts()

        migrated_in_dalga6 = {
            "decompile_all.py",
            "export_results.py",
            "function_id_extractor.py",
            "pcode_analysis.py",
        }
        for script in scripts:
            if script.name in migrated_in_dalga6:
                assert "legacy" in script.parts, (
                    f"{script.name} flag=True iken legacy/'den yuklenmeli"
                )

    def test_dalga6_migrated_scripts_use_new_when_flag_off(self) -> None:
        """Faz 1.4 Dalga 6B: default flag=False -> yeni PyGhidra 3.0."""
        from karadul.config import Config
        from karadul.ghidra.headless import GhidraHeadless

        cfg = Config()
        assert cfg.perf.use_legacy_jython_scripts is False
        ghidra = GhidraHeadless(cfg)
        scripts = ghidra.get_default_scripts()

        migrated_in_dalga6 = {
            "decompile_all.py",
            "export_results.py",
            "function_id_extractor.py",
            "pcode_analysis.py",
        }
        for script in scripts:
            if script.name in migrated_in_dalga6:
                assert "legacy" not in script.parts, (
                    f"{script.name} flag=False iken yeni versiyonu yuklenmeli"
                )

    def test_dalga6_migrated_scripts_py3_compile(self) -> None:
        """Faz 1.4 Dalga 6B: 4 yeni migrate py_compile OK (Python 3)."""
        import py_compile

        for name in (
            "decompile_all.py",
            "export_results.py",
            "function_id_extractor.py",
            "pcode_analysis.py",
        ):
            script = SCRIPTS_DIR / name
            assert script.exists(), f"Migrate edilmis script bulunamadi: {script}"
            py_compile.compile(str(script), doraise=True)


class TestScriptOrderPreserved:
    """test_ghidra.py SCRIPT_ORDER assertion'lari bozulmamis olmali."""

    def test_function_lister_first(self) -> None:
        from karadul.config import Config
        from karadul.ghidra.headless import GhidraHeadless

        cfg = Config()
        ghidra = GhidraHeadless(cfg)
        scripts = ghidra.get_default_scripts()
        if scripts:
            assert scripts[0].name == "function_lister.py"

    def test_export_results_last(self) -> None:
        from karadul.config import Config
        from karadul.ghidra.headless import GhidraHeadless

        cfg = Config()
        ghidra = GhidraHeadless(cfg)
        scripts = ghidra.get_default_scripts()
        if scripts:
            assert scripts[-1].name == "export_results.py"


class TestBackupPreservation:
    """Rollback icin legacy backup KESINLIKLE silinmemeli."""

    def test_legacy_dir_exists(self) -> None:
        assert LEGACY_DIR.exists(), "scripts/legacy/ dizini yok"
        assert LEGACY_DIR.is_dir()

    def test_legacy_function_lister_exists(self) -> None:
        legacy = LEGACY_DIR / "function_lister.py"
        assert legacy.exists(), "legacy/function_lister.py silinmis (rollback imkansiz)"

    def test_legacy_content_matches_original_semantics(self) -> None:
        """Legacy script Jython 2.7 header'ini hala tasiyor olmali (dokunulmadi)."""
        legacy = LEGACY_DIR / "function_lister.py"
        content = legacy.read_text(encoding="utf-8")
        # Eski header'in izi olmali
        assert "Jython 2.7" in content
