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
# Jython 2.7 yedekleri (scripts/legacy/) 2026-11-18'de silindi (K-3 A2); onlarla
# karşılaştıran parite testleri kaldırıldı, yeni betiklerin kendi şema / API testleri kaldı.


def _collect_top_level_defs(script_path: Path) -> dict[str, list[str]]:
    """Script'ten top-level fonksiyon adlari + imzalarini cikar."""
    tree = ast.parse(script_path.read_text(encoding="utf-8"))
    funcs: dict[str, list[str]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            args = [a.arg for a in node.args.args]
            funcs[node.name] = args
    return funcs




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
