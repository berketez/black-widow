"""v1.11.0 Jython Sunset Faz 1.4 (Dalga 6B): function_id_extractor.py A/B parity.

Runtime parity (gercek binary + Ghidra 12.0.4) @pytest.mark.integration ile ayri.
"""

from __future__ import annotations

import ast
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "karadul" / "ghidra" / "scripts"
LEGACY_DIR = SCRIPTS_DIR / "legacy"


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


class TestStaticParity:
    REQUIRED_FUNCS = (
        "get_output_dir",
        "extract_function_id_matches",
    )

    def test_same_top_level_functions(self) -> None:
        legacy_funcs = _collect_top_level_defs(
            LEGACY_DIR / "function_id_extractor.py"
        )
        new_funcs = _collect_top_level_defs(
            SCRIPTS_DIR / "function_id_extractor.py"
        )
        for required in self.REQUIRED_FUNCS:
            assert required in legacy_funcs, f"{required} legacy'de yok"
            assert required in new_funcs, f"{required} migrate'de yok"

    def test_function_arg_counts_match(self) -> None:
        legacy_funcs = _collect_top_level_defs(
            LEGACY_DIR / "function_id_extractor.py"
        )
        new_funcs = _collect_top_level_defs(
            SCRIPTS_DIR / "function_id_extractor.py"
        )
        for fname in self.REQUIRED_FUNCS:
            assert len(legacy_funcs[fname]) == len(new_funcs[fname]), (
                f"{fname} arg count mismatch: "
                f"legacy={legacy_funcs[fname]} vs new={new_funcs[fname]}"
            )


class TestJSONSchemaStability:
    EXPECTED_TOP_LEVEL_KEYS = {
        "program",
        "total_functions",
        "total_matches",
        "total_unnamed",
        "matches",
    }
    EXPECTED_MATCH_KEYS = {
        "address",
        "name",
        "size",
        "param_count",
        "source",
        "library",
    }

    def test_migrated_has_top_level_keys(self) -> None:
        keys = _extract_dict_keys(SCRIPTS_DIR / "function_id_extractor.py")
        missing = self.EXPECTED_TOP_LEVEL_KEYS - keys
        assert not missing, f"Top-level anahtar eksik: {missing}"

    def test_migrated_match_keys_preserved(self) -> None:
        keys = _extract_dict_keys(SCRIPTS_DIR / "function_id_extractor.py")
        missing = self.EXPECTED_MATCH_KEYS - keys
        assert not missing, f"Match dict anahtar eksik: {missing}"

    def test_key_set_parity_legacy_vs_migrated(self) -> None:
        legacy_keys = _extract_dict_keys(
            LEGACY_DIR / "function_id_extractor.py"
        )
        new_keys = _extract_dict_keys(
            SCRIPTS_DIR / "function_id_extractor.py"
        )
        assert legacy_keys == new_keys, (
            f"JSON schema delta! "
            f"only_legacy={legacy_keys - new_keys} "
            f"only_new={new_keys - legacy_keys}"
        )


class TestMigrationHeaders:
    def test_header_updated(self) -> None:
        script = SCRIPTS_DIR / "function_id_extractor.py"
        content = script.read_text(encoding="utf-8")
        assert "PyGhidra 3.0" in content

    def test_uses_future_annotations(self) -> None:
        script = SCRIPTS_DIR / "function_id_extractor.py"
        content = script.read_text(encoding="utf-8")
        assert "from __future__ import annotations" in content

    def test_py3_compile(self) -> None:
        import py_compile

        script = SCRIPTS_DIR / "function_id_extractor.py"
        py_compile.compile(str(script), doraise=True)
