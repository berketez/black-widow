"""v1.11.0 Jython Sunset Faz 1.4 (Dalga 6B): pcode_analysis.py A/B parity.

Runtime parity (gercek binary + Ghidra 12.0.4) @pytest.mark.integration ile ayri.
"""

from __future__ import annotations

import ast
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "karadul" / "ghidra" / "scripts"
# Jython 2.7 yedekleri (scripts/legacy/) 2026-11-18'de silindi (K-3 A2); onlarla
# karşılaştıran parite testleri kaldırıldı, yeni betiklerin kendi şema / API testleri kaldı.


def _collect_top_level_defs(script_path: Path) -> dict[str, list[str]]:
    tree = ast.parse(script_path.read_text(encoding="utf-8"))
    funcs: dict[str, list[str]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            args = [a.arg for a in node.args.args]
            funcs[node.name] = args
    return funcs


def _extract_dict_keys(script_path: Path) -> set[str]:
    tree = ast.parse(script_path.read_text(encoding="utf-8"))
    keys: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Dict):
            for k in node.keys:
                if isinstance(k, ast.Constant) and isinstance(k.value, str):
                    keys.add(k.value)
        elif isinstance(node, ast.Subscript):
            if isinstance(node.slice, ast.Constant) and isinstance(
                node.slice.value, str
            ):
                keys.add(node.slice.value)
    return keys




class TestJSONSchemaStability:
    EXPECTED_TOP_LEVEL_KEYS = {
        "program",
        "duration_seconds",
        "functions",
        "stats",
    }
    EXPECTED_VARNODE_KEYS = {
        "space",
        "offset",
        "size",
        "is_constant",
        "is_register",
        "is_unique",
        "is_address",
    }
    EXPECTED_PCODE_OP_KEYS = {
        "seq_num",
        "mnemonic",
        "inputs",
        "output",
    }
    EXPECTED_HIGH_VARIABLE_KEYS = {
        "name",
        "storage_offset",
        "is_parameter",
    }
    EXPECTED_STATS_KEYS = {
        "op_count",
        "avg_ops_per_function",
        "mnemonic_distribution",
    }

    def test_migrated_top_level_keys(self) -> None:
        keys = _extract_dict_keys(SCRIPTS_DIR / "pcode_analysis.py")
        missing = self.EXPECTED_TOP_LEVEL_KEYS - keys
        assert not missing, f"Top-level anahtar eksik: {missing}"

    def test_migrated_varnode_keys(self) -> None:
        keys = _extract_dict_keys(SCRIPTS_DIR / "pcode_analysis.py")
        missing = self.EXPECTED_VARNODE_KEYS - keys
        assert not missing, f"Varnode anahtar eksik: {missing}"

    def test_migrated_pcode_op_keys(self) -> None:
        keys = _extract_dict_keys(SCRIPTS_DIR / "pcode_analysis.py")
        missing = self.EXPECTED_PCODE_OP_KEYS - keys
        assert not missing, f"PCode op anahtar eksik: {missing}"

    def test_migrated_high_variable_keys(self) -> None:
        keys = _extract_dict_keys(SCRIPTS_DIR / "pcode_analysis.py")
        missing = self.EXPECTED_HIGH_VARIABLE_KEYS - keys
        assert not missing, f"HighVariable anahtar eksik: {missing}"

    def test_migrated_stats_keys(self) -> None:
        keys = _extract_dict_keys(SCRIPTS_DIR / "pcode_analysis.py")
        missing = self.EXPECTED_STATS_KEYS - keys
        assert not missing, f"Stats anahtar eksik: {missing}"



class TestMigrationHeaders:
    def test_header_updated(self) -> None:
        script = SCRIPTS_DIR / "pcode_analysis.py"
        content = script.read_text(encoding="utf-8")
        assert "PyGhidra 3.0" in content

    def test_uses_future_annotations(self) -> None:
        script = SCRIPTS_DIR / "pcode_analysis.py"
        content = script.read_text(encoding="utf-8")
        assert "from __future__ import annotations" in content

    def test_py3_compile(self) -> None:
        import py_compile

        script = SCRIPTS_DIR / "pcode_analysis.py"
        py_compile.compile(str(script), doraise=True)
