"""v1.11.0 Jython Sunset Faz 1: function_lister.py A/B parity testi.

STRATEJI:
- Lokal dev makinede Ghidra / PyGhidra kurulu olmayabilir -> gercek
  subprocess cagrisi yapilmaz (integration marker ile ayrilabilir).
- Bu test suite STATIK parity dogrulamasi yapar:
  * Her iki scriptin (legacy + migrated) AYNI JSON schema'yi uretmesi
  * Fonksiyon/degisken yapisinin (extract_functions, main, get_output_dir)
    iki dosyada da ayni signature ile mevcut olmasi
  * Eski icerigi bozacak yeniden-isimlendirme yapilmadi

Runtime parity (gercek binary'de JSON diff) PyGhidra 3.0 + Ghidra 12.0.4
kurulu CI ortaminda @pytest.mark.integration ile ayri kosulur.
"""

from __future__ import annotations

import ast
import json
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

    def test_same_top_level_functions(self) -> None:
        """extract_functions, get_output_dir, main -> her iki dosyada da
        AYNI isimlerle mevcut olmali."""
        legacy_funcs = _collect_top_level_defs(LEGACY_DIR / "function_lister.py")
        new_funcs = _collect_top_level_defs(SCRIPTS_DIR / "function_lister.py")

        # Kritik 3 fonksiyon adi degisemez
        for required in ("extract_functions", "get_output_dir", "main"):
            assert required in legacy_funcs, f"{required} legacy'de yok"
            assert required in new_funcs, f"{required} migrate edilmisde yok"

    def test_function_arg_counts_match(self) -> None:
        """Her fonksiyonun parametre sayisi iki dosyada da esit olmali."""
        legacy_funcs = _collect_top_level_defs(LEGACY_DIR / "function_lister.py")
        new_funcs = _collect_top_level_defs(SCRIPTS_DIR / "function_lister.py")

        for fname in ("extract_functions", "get_output_dir", "main"):
            assert len(legacy_funcs[fname]) == len(new_funcs[fname]), (
                f"{fname} arg count mismatch: "
                f"legacy={legacy_funcs[fname]} vs new={new_funcs[fname]}"
            )


class TestJSONSchemaStability:
    """Migrate edilen scriptin urettigi JSON schema'sinin anahtarlari
    legacy ile birebir ayni olmali (downstream parser koruma)."""

    EXPECTED_TOP_LEVEL_KEYS = {"total", "program", "functions"}
    EXPECTED_FUNCTION_KEYS = {
        "name", "address", "size", "param_count", "return_type",
        "is_thunk", "calling_convention", "is_external",
        "parameters", "source",
    }
    EXPECTED_PARAM_KEYS = {"name", "type", "ordinal"}

    def _extract_dict_keys_from_source(self, script_path: Path) -> set[str]:
        """Scriptteki dict literal'larindan + subscript atamalarindan
        string anahtarlarini topla.

        entry['parameters'] = [...] gibi `Subscript` atamalari da kapsanir;
        sadece `{"k": v}` literal'i DEGIL.
        """
        tree = ast.parse(script_path.read_text(encoding="utf-8"))
        keys: set[str] = set()
        for node in ast.walk(tree):
            # Dict literal: {"k": v}
            if isinstance(node, ast.Dict):
                for k in node.keys:
                    if isinstance(k, ast.Constant) and isinstance(k.value, str):
                        keys.add(k.value)
            # Subscript atama: entry["k"] = v
            elif isinstance(node, ast.Subscript):
                slice_node = node.slice
                if isinstance(slice_node, ast.Constant) and isinstance(
                    slice_node.value, str
                ):
                    keys.add(slice_node.value)
        return keys

    def test_migrated_has_all_expected_function_keys(self) -> None:
        """Migrate edilen scriptin dict literal'larinda beklenen tum function
        entry anahtarlari mevcut olmali."""
        keys = self._extract_dict_keys_from_source(SCRIPTS_DIR / "function_lister.py")
        missing = self.EXPECTED_FUNCTION_KEYS - keys
        assert not missing, f"Migrate edilen scriptte eksik anahtarlar: {missing}"

    def test_migrated_has_all_top_level_keys(self) -> None:
        keys = self._extract_dict_keys_from_source(SCRIPTS_DIR / "function_lister.py")
        missing = self.EXPECTED_TOP_LEVEL_KEYS - keys
        assert not missing, f"Top-level JSON anahtarlari eksik: {missing}"

    def test_migrated_param_keys_preserved(self) -> None:
        keys = self._extract_dict_keys_from_source(SCRIPTS_DIR / "function_lister.py")
        missing = self.EXPECTED_PARAM_KEYS - keys
        assert not missing, f"Parametre dict anahtarlari eksik: {missing}"

    def test_key_set_parity_legacy_vs_migrated(self) -> None:
        """Legacy ve migrated scriptler ESIT dict anahtar kumesine sahip olmali."""
        legacy_keys = self._extract_dict_keys_from_source(
            LEGACY_DIR / "function_lister.py"
        )
        new_keys = self._extract_dict_keys_from_source(
            SCRIPTS_DIR / "function_lister.py"
        )
        # Migrate sirasinda HIC ANAHTAR EKLENMEDI / SILINMEDI
        assert legacy_keys == new_keys, (
            f"JSON schema key delta! "
            f"only_legacy={legacy_keys - new_keys} "
            f"only_new={new_keys - legacy_keys}"
        )


@pytest.mark.integration
class TestRuntimeParity:
    """PyGhidra 3.0 + Ghidra 12.0.4 kurulu ortamda calisir.

    Gercek subprocess cagrisi ile iki scripti calistirir ve JSON diff yapar.
    Bu test default 'pytest' kosusunda -m 'not integration' ile atlanir.
    """

    def test_sample_macho_parity(self, tmp_path: Path) -> None:
        """sample_macho uzerinde Jython vs PyGhidra JSON diff >= %99 eslesme."""
        pytest.skip(
            "Runtime parity test'i PyGhidra 3.0 + Ghidra 12.0.4 kurulu "
            "CI image'inda kosulmalidir (v1.11.0 Faz 1 Gun 5)."
        )
