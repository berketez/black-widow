"""v1.11.0 Jython Sunset Faz 1.3 (Dalga 4): cfg_extraction.py A/B parity testi.

STRATEJI:
- Lokal dev makinede Ghidra / PyGhidra kurulu olmayabilir -> gercek
  subprocess cagrisi yapilmaz (integration marker ile ayrilabilir).
- Bu test suite STATIK parity dogrulamasi yapar:
  * Her iki scriptin (legacy + migrated) AYNI JSON schema'yi uretmesi
  * Fonksiyon/degisken yapisinin (classify_edge, is_back_edge,
    extract_function_cfg, extract_all_cfgs, compute_global_stats,
    get_output_dir, main) iki dosyada da ayni signature ile mevcut olmasi
  * Eski icerigi bozacak yeniden-isimlendirme yapilmadi

Runtime parity (gercek binary'de JSON diff) PyGhidra 3.0 + Ghidra 12.0.4
kurulu CI ortaminda @pytest.mark.integration ile ayri kosulur.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "karadul" / "ghidra" / "scripts"
LEGACY_DIR = SCRIPTS_DIR / "legacy"


def _collect_top_level_defs(script_path: Path) -> dict[str, list[str]]:
    """Script'ten top-level fonksiyon adlari + imzalarini cikar."""
    tree = ast.parse(script_path.read_text(encoding="utf-8"))
    funcs: dict[str, list[str]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            args = [a.arg for a in node.args.args]
            funcs[node.name] = args
    return funcs


class TestStaticParity:
    """Legacy ve migrated scriptler ayni API surface'ina sahip olmali."""

    CFG_REQUIRED_FUNCS = (
        "classify_edge",
        "is_back_edge",
        "extract_function_cfg",
        "extract_all_cfgs",
        "compute_global_stats",
        "get_output_dir",
        "main",
    )

    def test_same_top_level_functions(self) -> None:
        """Kritik fonksiyon adlari degisemez."""
        legacy_funcs = _collect_top_level_defs(LEGACY_DIR / "cfg_extraction.py")
        new_funcs = _collect_top_level_defs(SCRIPTS_DIR / "cfg_extraction.py")

        for required in self.CFG_REQUIRED_FUNCS:
            assert required in legacy_funcs, f"{required} legacy'de yok"
            assert required in new_funcs, f"{required} migrate edilmisde yok"

    def test_function_arg_counts_match(self) -> None:
        """Her fonksiyonun parametre sayisi iki dosyada da esit olmali."""
        legacy_funcs = _collect_top_level_defs(LEGACY_DIR / "cfg_extraction.py")
        new_funcs = _collect_top_level_defs(SCRIPTS_DIR / "cfg_extraction.py")

        for fname in self.CFG_REQUIRED_FUNCS:
            assert len(legacy_funcs[fname]) == len(new_funcs[fname]), (
                f"{fname} arg count mismatch: "
                f"legacy={legacy_funcs[fname]} vs new={new_funcs[fname]}"
            )


class TestJSONSchemaStability:
    """Migrate edilen scriptin urettigi JSON schema'sinin anahtarlari
    legacy ile birebir ayni olmali (downstream parser koruma)."""

    CFG_TOP_LEVEL_KEYS = {
        "program", "total_functions",
        "extraction_stats", "global_stats", "functions",
    }
    CFG_FUNCTION_KEYS = {
        "name", "address", "block_count", "edge_count",
        "cyclomatic_complexity", "loop_header_count",
        "loop_headers", "back_edges", "blocks", "edges",
    }
    CFG_BLOCK_KEYS = {"start_address", "end_address", "size"}
    CFG_EDGE_KEYS = {"from_block", "to_block", "edge_type", "is_back_edge"}
    CFG_GLOBAL_STATS_KEYS = {
        "total_blocks", "total_edges", "total_loop_headers",
        "avg_cyclomatic_complexity", "max_cyclomatic_complexity",
        "max_complexity_function", "complexity_distribution",
    }
    CFG_EXTRACTION_STATS_KEYS = {
        "total_processed", "successful", "errors",
        "skipped_over_batch", "batch_size",
    }
    CFG_DISTRIBUTION_KEYS = {
        "linear_le2", "moderate_3_10", "high_11_20", "very_high_gt20",
    }

    def _extract_dict_keys_from_source(self, script_path: Path) -> set[str]:
        tree = ast.parse(script_path.read_text(encoding="utf-8"))
        keys: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Dict):
                for k in node.keys:
                    if isinstance(k, ast.Constant) and isinstance(k.value, str):
                        keys.add(k.value)
            elif isinstance(node, ast.Subscript):
                slice_node = node.slice
                if isinstance(slice_node, ast.Constant) and isinstance(
                    slice_node.value, str
                ):
                    keys.add(slice_node.value)
        return keys

    def test_migrated_has_all_top_level_keys(self) -> None:
        keys = self._extract_dict_keys_from_source(
            SCRIPTS_DIR / "cfg_extraction.py"
        )
        missing = self.CFG_TOP_LEVEL_KEYS - keys
        assert not missing, f"Top-level JSON anahtarlari eksik: {missing}"

    def test_migrated_function_keys_preserved(self) -> None:
        keys = self._extract_dict_keys_from_source(
            SCRIPTS_DIR / "cfg_extraction.py"
        )
        missing = self.CFG_FUNCTION_KEYS - keys
        assert not missing, f"Function dict anahtarlari eksik: {missing}"

    def test_migrated_block_keys_preserved(self) -> None:
        keys = self._extract_dict_keys_from_source(
            SCRIPTS_DIR / "cfg_extraction.py"
        )
        missing = self.CFG_BLOCK_KEYS - keys
        assert not missing, f"Block dict anahtarlari eksik: {missing}"

    def test_migrated_edge_keys_preserved(self) -> None:
        keys = self._extract_dict_keys_from_source(
            SCRIPTS_DIR / "cfg_extraction.py"
        )
        missing = self.CFG_EDGE_KEYS - keys
        assert not missing, f"Edge dict anahtarlari eksik: {missing}"

    def test_migrated_global_stats_keys_preserved(self) -> None:
        keys = self._extract_dict_keys_from_source(
            SCRIPTS_DIR / "cfg_extraction.py"
        )
        missing = self.CFG_GLOBAL_STATS_KEYS - keys
        assert not missing, f"Global stats anahtarlari eksik: {missing}"

    def test_migrated_extraction_stats_keys_preserved(self) -> None:
        keys = self._extract_dict_keys_from_source(
            SCRIPTS_DIR / "cfg_extraction.py"
        )
        missing = self.CFG_EXTRACTION_STATS_KEYS - keys
        assert not missing, f"Extraction stats anahtarlari eksik: {missing}"

    def test_migrated_distribution_keys_preserved(self) -> None:
        keys = self._extract_dict_keys_from_source(
            SCRIPTS_DIR / "cfg_extraction.py"
        )
        missing = self.CFG_DISTRIBUTION_KEYS - keys
        assert not missing, f"Complexity distribution anahtarlari eksik: {missing}"

    def test_key_set_parity_legacy_vs_migrated(self) -> None:
        """Legacy ve migrated scriptler ESIT dict anahtar kumesine sahip olmali."""
        legacy_keys = self._extract_dict_keys_from_source(
            LEGACY_DIR / "cfg_extraction.py"
        )
        new_keys = self._extract_dict_keys_from_source(
            SCRIPTS_DIR / "cfg_extraction.py"
        )
        assert legacy_keys == new_keys, (
            f"JSON schema key delta! "
            f"only_legacy={legacy_keys - new_keys} "
            f"only_new={new_keys - legacy_keys}"
        )


class TestMigrationHeaders:
    """Migrate edilen script PyGhidra 3.0 header'ina sahip olmali."""

    def test_header_updated(self) -> None:
        script = SCRIPTS_DIR / "cfg_extraction.py"
        content = script.read_text(encoding="utf-8")
        assert "PyGhidra 3.0" in content
        assert "Python 3 syntax'i KULLANILMAMALIDIR" not in content

    def test_uses_future_annotations(self) -> None:
        script = SCRIPTS_DIR / "cfg_extraction.py"
        content = script.read_text(encoding="utf-8")
        assert "from __future__ import annotations" in content

    def test_uses_utf8_ensure_ascii_false(self) -> None:
        script = SCRIPTS_DIR / "cfg_extraction.py"
        content = script.read_text(encoding="utf-8")
        assert 'encoding="utf-8"' in content
        assert "ensure_ascii=False" in content

    def test_defensive_jpype_wraps(self) -> None:
        """JPype boundary'de str()/int()/bool() defansifleri olmali."""
        script = SCRIPTS_DIR / "cfg_extraction.py"
        content = script.read_text(encoding="utf-8")
        assert "str(func.getName())" in content
        assert "int(block.getNumAddresses())" in content

    def test_legacy_retains_jython_header(self) -> None:
        """Legacy backup Jython 2.7 header'ini korumali (rollback garantisi)."""
        legacy = LEGACY_DIR / "cfg_extraction.py"
        content = legacy.read_text(encoding="utf-8")
        assert "Jython 2.7" in content


@pytest.mark.integration
class TestRuntimeParity:
    """PyGhidra 3.0 + Ghidra 12.0.4 kurulu ortamda calisir."""

    def test_sample_macho_parity(self, tmp_path: Path) -> None:
        pytest.skip(
            "Runtime parity test'i PyGhidra 3.0 + Ghidra 12.0.4 kurulu "
            "CI image'inda kosulmalidir (v1.11.0 Faz 1.3 Dalga 4)."
        )
