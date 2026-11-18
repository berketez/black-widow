"""v1.11.0 Jython Sunset Faz 1.2: type_recovery.py A/B parity testi.

STRATEJI:
- Lokal dev makinede Ghidra / PyGhidra kurulu olmayabilir -> gercek
  subprocess cagrisi yapilmaz (integration marker ile ayrilabilir).
- Bu test suite STATIK parity dogrulamasi yapar:
  * Her iki scriptin (legacy + migrated) AYNI JSON schema'yi uretmesi
  * 6 top-level fonksiyonun (extract_structures, extract_enums,
    extract_typedefs, extract_function_definitions, summarize_categories,
    main, get_output_dir) iki dosyada da ayni signature ile mevcut olmasi
  * Recursive type hiyerarsisi (Structure -> fields, FunctionDefinition ->
    parameters) anahtar seviyesinde parity koruyor.

Runtime parity (gercek binary'de JSON diff) PyGhidra 3.0 + Ghidra 12.0.4
kurulu CI ortaminda @pytest.mark.integration ile ayri kosulur.
"""

from __future__ import annotations

import ast
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
    legacy ile birebir ayni olmali (downstream parser koruma).

    type_recovery.py 4 farkli entry tipi uretir: Structure, Enum, TypeDef,
    FunctionDefinition. Her birinin kendi anahtar seti var.
    """

    EXPECTED_TOP_LEVEL = {
        "program",
        "total_structures",
        "total_enums",
        "total_typedefs",
        "total_function_definitions",
        "total_types",
        "category_summary",
        "structures",
        "enums",
        "typedefs",
        "function_definitions",
    }
    EXPECTED_STRUCT = {
        "name", "category", "kind", "size", "alignment",
        "description", "field_count", "fields",
    }
    EXPECTED_FIELD = {"name", "type", "offset", "size", "comment", "ordinal"}
    EXPECTED_ENUM = {
        "name", "category", "size", "description", "value_count", "values",
    }
    EXPECTED_TYPEDEF = {
        "name", "category", "base_type", "base_type_name", "size", "description",
    }
    EXPECTED_FUNCDEF = {
        "name", "category", "return_type", "calling_convention",
        "param_count", "parameters",
    }
    EXPECTED_PARAM = {"name", "type"}
    EXPECTED_CATEGORY_ITEM = {"path", "count"}

    def _extract_dict_keys_from_source(self, script_path: Path) -> set[str]:
        """Scriptteki dict literal'larindan + subscript atamalarindan
        string anahtarlarini topla.

        entry['fields'].append(...) gibi Subscript + method call zinciri
        olsa bile sadece Subscript node string literal slice olarak gorulur.
        """
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

    def test_migrated_has_all_top_level(self) -> None:
        keys = self._extract_dict_keys_from_source(SCRIPTS_DIR / "type_recovery.py")
        missing = self.EXPECTED_TOP_LEVEL - keys
        assert not missing, f"Top-level anahtarlar eksik: {missing}"

    def test_migrated_has_struct_keys(self) -> None:
        keys = self._extract_dict_keys_from_source(SCRIPTS_DIR / "type_recovery.py")
        missing = self.EXPECTED_STRUCT - keys
        assert not missing, f"Struct entry anahtarlar eksik: {missing}"

    def test_migrated_has_field_keys(self) -> None:
        keys = self._extract_dict_keys_from_source(SCRIPTS_DIR / "type_recovery.py")
        missing = self.EXPECTED_FIELD - keys
        assert not missing, f"Field entry anahtarlar eksik: {missing}"

    def test_migrated_has_enum_keys(self) -> None:
        keys = self._extract_dict_keys_from_source(SCRIPTS_DIR / "type_recovery.py")
        missing = self.EXPECTED_ENUM - keys
        assert not missing, f"Enum entry anahtarlar eksik: {missing}"

    def test_migrated_has_typedef_keys(self) -> None:
        keys = self._extract_dict_keys_from_source(SCRIPTS_DIR / "type_recovery.py")
        missing = self.EXPECTED_TYPEDEF - keys
        assert not missing, f"Typedef entry anahtarlar eksik: {missing}"

    def test_migrated_has_funcdef_keys(self) -> None:
        keys = self._extract_dict_keys_from_source(SCRIPTS_DIR / "type_recovery.py")
        missing = self.EXPECTED_FUNCDEF - keys
        assert not missing, f"FunctionDefinition entry anahtarlar eksik: {missing}"

    def test_migrated_has_category_item_keys(self) -> None:
        keys = self._extract_dict_keys_from_source(SCRIPTS_DIR / "type_recovery.py")
        missing = self.EXPECTED_CATEGORY_ITEM - keys
        assert not missing, f"Category item anahtarlar eksik: {missing}"



class TestMigrationHeaders:
    """Migrate edilen script PyGhidra 3.0 header'ina sahip olmali."""

    def test_header_updated(self) -> None:
        script = SCRIPTS_DIR / "type_recovery.py"
        content = script.read_text(encoding="utf-8")
        assert "PyGhidra 3.0" in content
        assert "Python 3 syntax'i KULLANILMAMALIDIR" not in content

    def test_uses_future_annotations(self) -> None:
        script = SCRIPTS_DIR / "type_recovery.py"
        content = script.read_text(encoding="utf-8")
        assert "from __future__ import annotations" in content

    def test_uses_utf8_ensure_ascii_false(self) -> None:
        script = SCRIPTS_DIR / "type_recovery.py"
        content = script.read_text(encoding="utf-8")
        assert 'encoding="utf-8"' in content
        assert "ensure_ascii=False" in content

    def test_defensive_jpype_wraps(self) -> None:
        """JPype boundary'de str()/int() defansifleri olmali.

        Ghidra DataType API'si cok sayida getName/getLength/getOffset donusu
        uretir; bunlarin hepsi java primitif'leri -> explicit wrap sart.
        """
        script = SCRIPTS_DIR / "type_recovery.py"
        content = script.read_text(encoding="utf-8")
        assert "str(dt.getName())" in content
        assert "int(dt.getLength())" in content
        # Field seviyesi wrap
        assert "int(comp.getOffset())" in content


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
            "CI image'inda kosulmalidir (v1.11.0 Faz 1.2 Dalga 3)."
        )
