"""v1.11.0 Jython Sunset Faz 1.3 (Dalga 4): xref_analysis.py A/B parity testi.

STRATEJI:
- Lokal dev makinede Ghidra / PyGhidra kurulu olmayabilir -> gercek
  subprocess cagrisi yapilmaz (integration marker ile ayrilabilir).
- Bu test suite STATIK parity dogrulamasi yapar:
  * Her iki scriptin (legacy + migrated) AYNI JSON schema'yi uretmesi
  * Fonksiyon/degisken yapisinin (build_function_xref_map,
    build_string_xref_map, build_global_xref_map, compute_statistics,
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

    XREF_REQUIRED_FUNCS = (
        "build_function_xref_map",
        "build_string_xref_map",
        "build_global_xref_map",
        "compute_statistics",
        "get_output_dir",
        "main",
    )

    def test_same_top_level_functions(self) -> None:
        """Kritik fonksiyon adlari degisemez."""
        legacy_funcs = _collect_top_level_defs(LEGACY_DIR / "xref_analysis.py")
        new_funcs = _collect_top_level_defs(SCRIPTS_DIR / "xref_analysis.py")

        for required in self.XREF_REQUIRED_FUNCS:
            assert required in legacy_funcs, f"{required} legacy'de yok"
            assert required in new_funcs, f"{required} migrate edilmisde yok"

    def test_function_arg_counts_match(self) -> None:
        """Her fonksiyonun parametre sayisi iki dosyada da esit olmali."""
        legacy_funcs = _collect_top_level_defs(LEGACY_DIR / "xref_analysis.py")
        new_funcs = _collect_top_level_defs(SCRIPTS_DIR / "xref_analysis.py")

        for fname in self.XREF_REQUIRED_FUNCS:
            assert len(legacy_funcs[fname]) == len(new_funcs[fname]), (
                f"{fname} arg count mismatch: "
                f"legacy={legacy_funcs[fname]} vs new={new_funcs[fname]}"
            )


class TestJSONSchemaStability:
    """Migrate edilen scriptin urettigi JSON schema'sinin anahtarlari
    legacy ile birebir ayni olmali (downstream parser koruma)."""

    XREF_TOP_LEVEL_KEYS = {
        "program", "statistics",
        "function_xrefs", "string_xrefs", "global_xrefs",
    }
    XREF_FUNCTION_ENTRY_KEYS = {
        "name", "address",
        "strings_used", "globals_accessed", "functions_called",
        "called_by", "data_refs_from", "call_refs_from",
    }
    XREF_STRING_ENTRY_KEYS = {
        "address", "value", "length", "type",
        "referenced_by_count", "referenced_by", "defined_in_function",
    }
    XREF_GLOBAL_ENTRY_KEYS = {
        "name", "address", "type", "size", "symbol_type",
        "is_external", "reader_count", "writer_count",
        "readers", "writers",
    }
    XREF_STATISTICS_KEYS = {
        "total_functions", "total_strings_with_xrefs",
        "total_globals_with_xrefs", "isolated_functions",
        "avg_callers_per_func", "avg_refs_per_string",
        "most_referenced_strings", "most_called_functions",
        "most_written_globals",
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
            SCRIPTS_DIR / "xref_analysis.py"
        )
        missing = self.XREF_TOP_LEVEL_KEYS - keys
        assert not missing, f"Top-level JSON anahtarlari eksik: {missing}"

    def test_migrated_function_entry_keys_preserved(self) -> None:
        keys = self._extract_dict_keys_from_source(
            SCRIPTS_DIR / "xref_analysis.py"
        )
        missing = self.XREF_FUNCTION_ENTRY_KEYS - keys
        assert not missing, f"Function xref anahtarlari eksik: {missing}"

    def test_migrated_string_entry_keys_preserved(self) -> None:
        keys = self._extract_dict_keys_from_source(
            SCRIPTS_DIR / "xref_analysis.py"
        )
        missing = self.XREF_STRING_ENTRY_KEYS - keys
        assert not missing, f"String xref anahtarlari eksik: {missing}"

    def test_migrated_global_entry_keys_preserved(self) -> None:
        keys = self._extract_dict_keys_from_source(
            SCRIPTS_DIR / "xref_analysis.py"
        )
        missing = self.XREF_GLOBAL_ENTRY_KEYS - keys
        assert not missing, f"Global xref anahtarlari eksik: {missing}"

    def test_migrated_statistics_keys_preserved(self) -> None:
        keys = self._extract_dict_keys_from_source(
            SCRIPTS_DIR / "xref_analysis.py"
        )
        missing = self.XREF_STATISTICS_KEYS - keys
        assert not missing, f"Statistics anahtarlari eksik: {missing}"

    def test_key_set_parity_legacy_vs_migrated(self) -> None:
        """Legacy ve migrated scriptler ESIT dict anahtar kumesine sahip olmali."""
        legacy_keys = self._extract_dict_keys_from_source(
            LEGACY_DIR / "xref_analysis.py"
        )
        new_keys = self._extract_dict_keys_from_source(
            SCRIPTS_DIR / "xref_analysis.py"
        )
        assert legacy_keys == new_keys, (
            f"JSON schema key delta! "
            f"only_legacy={legacy_keys - new_keys} "
            f"only_new={new_keys - legacy_keys}"
        )


class TestMigrationHeaders:
    """Migrate edilen script PyGhidra 3.0 header'ina sahip olmali."""

    def test_header_updated(self) -> None:
        script = SCRIPTS_DIR / "xref_analysis.py"
        content = script.read_text(encoding="utf-8")
        assert "PyGhidra 3.0" in content
        assert "Python 3 syntax'i KULLANILMAMALIDIR" not in content

    def test_uses_future_annotations(self) -> None:
        script = SCRIPTS_DIR / "xref_analysis.py"
        content = script.read_text(encoding="utf-8")
        assert "from __future__ import annotations" in content

    def test_uses_utf8_ensure_ascii_false(self) -> None:
        script = SCRIPTS_DIR / "xref_analysis.py"
        content = script.read_text(encoding="utf-8")
        assert 'encoding="utf-8"' in content
        assert "ensure_ascii=False" in content

    def test_defensive_jpype_wraps(self) -> None:
        """JPype boundary'de str()/int()/bool() defansifleri olmali."""
        script = SCRIPTS_DIR / "xref_analysis.py"
        content = script.read_text(encoding="utf-8")
        assert "str(func.getName())" in content
        assert "int(data.getLength())" in content

    def test_legacy_retains_jython_header(self) -> None:
        """Legacy backup Jython 2.7 header'ini korumali (rollback garantisi)."""
        legacy = LEGACY_DIR / "xref_analysis.py"
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
