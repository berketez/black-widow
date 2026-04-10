"""Tests for v1.8.0 Stream A fixes: Bug 1 (duplicate code) + Bug 2 (duplicate param names).

Bug 1: _apply_names_to_code was using textual find to locate function definitions,
       hitting forward declarations, call sites, or comments instead. Each rename
       shifted offsets, corrupting subsequent renames. Now uses pre-computed spans
       and bottom-to-top processing.

Bug 2: _resolve_conflicts started used_names empty, ignoring existing non-auto
       parameter names. Two different auto-params could resolve to the same name
       (e.g., both become "M_matrix"). Now pre-seeds used_names from existing params.
"""

from __future__ import annotations

import textwrap
from collections import defaultdict
from dataclasses import dataclass
from unittest.mock import MagicMock

import pytest

from karadul.reconstruction.engineering.semantic_namer import (
    SemanticName,
    SemanticParameterNamer,
    _is_auto_or_generic_name,
    _replace_whole_word,
)
from karadul.config import Config


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_sn(
    orig: str,
    semantic: str,
    func: str,
    confidence: float = 0.85,
    source: str = "algorithm_template",
) -> SemanticName:
    """Shorthand for creating a SemanticName."""
    return SemanticName(
        original_name=orig,
        semantic_name=semantic,
        function_name=func,
        confidence=confidence,
        source=source,
        reason="test",
        domain="generic",
    )


def _make_namer() -> SemanticParameterNamer:
    """Create a minimal SemanticParameterNamer instance for unit testing."""
    cfg = Config()
    namer = SemanticParameterNamer.__new__(SemanticParameterNamer)
    # Minimum attribute set required by methods under test
    namer._functions = {}
    namer._func_codes = {}
    namer._call_graph = {}
    namer._reverse_graph = {}
    namer._func_domains = {}
    namer._BASE_CONFIDENCE = {
        "signature_based": 0.92,
        "algorithm_template": 0.85,
        "call_graph_propagation": 0.75,
        "struct_context": 0.70,
        "type_heuristic": 0.60,
        "call_context": 0.65,
    }
    namer._STRATEGY_PRIORITY = {
        "signature_based": 60,
        "algorithm_template": 50,
        "call_graph_propagation": 40,
        "struct_context": 30,
        "call_context": 25,
        "type_heuristic": 20,
    }
    return namer


# ===========================================================================
# Bug 1 Tests: _find_all_function_spans + _apply_names_to_code
# ===========================================================================


class TestFindAllFunctionSpans:
    """Tests for the new _find_all_function_spans static method."""

    def test_single_function(self):
        code = textwrap.dedent("""\
            void my_func(int param_1) {
                int x = param_1 + 1;
                return;
            }
        """)
        spans = SemanticParameterNamer._find_all_function_spans(code)
        assert "my_func" in spans
        def_start, body_open, body_close = spans["my_func"]
        assert code[body_open] == "{"
        assert code[body_close - 1] == "}"
        assert "my_func" in code[def_start:body_open]

    def test_multiple_functions(self):
        code = textwrap.dedent("""\
            int func_a(int param_1) {
                return param_1;
            }

            double func_b(double param_1, double param_2) {
                return param_1 + param_2;
            }
        """)
        spans = SemanticParameterNamer._find_all_function_spans(code)
        assert "func_a" in spans
        assert "func_b" in spans
        # func_a should start before func_b
        assert spans["func_a"][0] < spans["func_b"][0]

    def test_nested_braces(self):
        code = textwrap.dedent("""\
            void complex_func(int param_1) {
                if (param_1 > 0) {
                    for (int i = 0; i < param_1; i++) {
                        do_something();
                    }
                }
            }
        """)
        spans = SemanticParameterNamer._find_all_function_spans(code)
        assert "complex_func" in spans
        _, _, body_close = spans["complex_func"]
        # body_close should point past the final }
        # The function body should contain the entire nested block
        _, body_open, body_close = spans["complex_func"]
        body = code[body_open:body_close]
        assert body.count("{") == body.count("}")

    def test_no_functions(self):
        code = "int x = 5;\n"
        spans = SemanticParameterNamer._find_all_function_spans(code)
        assert spans == {}


class TestApplyNamesToCodeBug1:
    """Bug 1: single function multi-param, multi-function same file, cross-ref."""

    def test_single_function_multi_param(self):
        """Single function with multiple params renamed correctly."""
        code = textwrap.dedent("""\
            void solve(int param_1, double *param_2, double *param_3) {
                param_2[0] = param_1 * 2.0;
                param_3[0] = param_2[0] + 1.0;
            }
        """)
        names = [
            _make_sn("param_1", "n_dof", "solve"),
            _make_sn("param_2", "K_global", "solve"),
            _make_sn("param_3", "F_vector", "solve"),
        ]
        namer = _make_namer()
        result = namer._apply_names_to_code(code, names)

        # All three params should be renamed
        assert "n_dof" in result
        assert "K_global" in result
        assert "F_vector" in result
        # Original auto-names should be gone from executable code
        # (they may appear in /* was: */ comments)
        assert "was: param_1" in result
        assert "was: param_2" in result
        assert "was: param_3" in result
        # No duplicate function body
        assert result.count("void solve") == 1

    def test_multi_function_same_file(self):
        """Multiple functions in same file, each gets correct renames."""
        code = textwrap.dedent("""\
            void func_a(int param_1, double *param_2) {
                param_2[0] = param_1;
            }

            void func_b(int param_1, double *param_2) {
                param_2[0] = param_1 * 3;
            }
        """)
        names = [
            _make_sn("param_1", "rows", "func_a"),
            _make_sn("param_2", "matrix", "func_a"),
            _make_sn("param_1", "cols", "func_b"),
            _make_sn("param_2", "vector", "func_b"),
        ]
        namer = _make_namer()
        result = namer._apply_names_to_code(code, names)

        # func_a should have rows/matrix, func_b should have cols/vector
        # Split by function to check isolation
        fa_start = result.find("void func_a")
        fb_start = result.find("void func_b")
        assert fa_start != -1 and fb_start != -1
        fa_section = result[fa_start:fb_start]
        fb_section = result[fb_start:]

        assert "rows" in fa_section
        assert "matrix" in fa_section
        assert "cols" not in fa_section  # belongs to func_b only
        assert "vector" not in fa_section

        assert "cols" in fb_section
        assert "vector" in fb_section
        assert "rows" not in fb_section  # belongs to func_a only
        assert "matrix" not in fb_section

    def test_cross_reference_no_corruption(self):
        """Function A calls function B -- renaming B's params must NOT touch A's call site."""
        code = textwrap.dedent("""\
            void callee(int param_1, double *param_2) {
                param_2[0] = param_1 * 2.0;
            }

            void caller(int param_1) {
                double buf[10];
                callee(param_1, buf);
            }
        """)
        # Only rename callee's params, not caller's
        names = [
            _make_sn("param_1", "n_elements", "callee"),
            _make_sn("param_2", "output_buf", "callee"),
        ]
        namer = _make_namer()
        result = namer._apply_names_to_code(code, names)

        # callee should be renamed
        callee_start = result.find("void callee")
        caller_start = result.find("void caller")
        callee_section = result[callee_start:caller_start]
        caller_section = result[caller_start:]

        assert "n_elements" in callee_section
        assert "output_buf" in callee_section

        # caller's param_1 should NOT be renamed to n_elements
        # (it's a different function's param)
        assert "n_elements" not in caller_section
        # caller should still have its original param_1
        assert "param_1" in caller_section

    def test_no_duplicate_code_output(self):
        """Ensure no duplicate function body appears in output (the original bug)."""
        code = textwrap.dedent("""\
            void my_func(int param_1, double *param_2) {
                double x = param_2[param_1];
                if (x > 0) {
                    return;
                }
            }
        """)
        names = [
            _make_sn("param_1", "index", "my_func"),
            _make_sn("param_2", "data_array", "my_func"),
        ]
        namer = _make_namer()
        result = namer._apply_names_to_code(code, names)

        # Only one function definition should exist
        assert result.count("void my_func") == 1
        # Only one opening brace at function level
        # Count "double x =" to ensure body not duplicated
        assert result.count("double x =") == 1

    def test_names_for_nonexistent_function_skipped(self):
        """Names targeting a function not in code should be silently skipped."""
        code = textwrap.dedent("""\
            void existing_func(int param_1) {
                return;
            }
        """)
        names = [
            _make_sn("param_1", "count", "nonexistent_func"),
        ]
        namer = _make_namer()
        result = namer._apply_names_to_code(code, names)
        # Code should be unchanged
        assert result == code

    def test_bottom_to_top_preserves_offsets(self):
        """Renaming a later function should not shift earlier function's offsets."""
        code = textwrap.dedent("""\
            int first(int param_1) {
                return param_1 + 1;
            }

            int second(int param_1) {
                return param_1 + 2;
            }

            int third(int param_1) {
                return param_1 + 3;
            }
        """)
        names = [
            _make_sn("param_1", "alpha", "first"),
            _make_sn("param_1", "beta", "second"),
            _make_sn("param_1", "gamma", "third"),
        ]
        namer = _make_namer()
        result = namer._apply_names_to_code(code, names)

        # Each function should have its own renamed param
        first_start = result.find("int first")
        second_start = result.find("int second")
        third_start = result.find("int third")

        assert "alpha" in result[first_start:second_start]
        assert "beta" in result[second_start:third_start]
        assert "gamma" in result[third_start:]

        # No param_1 should remain in executable code (only in /* was: */ comments)
        # Remove comments to check
        import re
        no_comments = re.sub(r"/\*.*?\*/", "", result)
        assert "param_1" not in no_comments


# ===========================================================================
# Bug 2 Tests: _resolve_conflicts pre-seed
# ===========================================================================


class TestResolveConflictsBug2:
    """Bug 2: existing param collision, triple auto-param same name, no collision."""

    def test_existing_param_collision(self):
        """If a function already has 'matrix_ptr', auto-param should get _2 suffix."""
        namer = _make_namer()
        # Simulate function with existing non-auto param 'matrix_ptr'
        namer._functions = {
            "solve_system": {
                "params": [
                    {"name": "matrix_ptr", "type": "double *", "position": 0},
                    {"name": "param_2", "type": "int", "position": 1},
                ],
            },
        }

        candidates = [
            _make_sn("param_2", "matrix_ptr", "solve_system", confidence=0.85),
        ]

        result = namer._resolve_conflicts(candidates)
        assert len(result) == 1
        # Should NOT be "matrix_ptr" -- collision with existing param
        assert result[0].semantic_name == "matrix_ptr_2"

    def test_triple_auto_param_same_name(self):
        """Three different auto-params all resolving to same semantic name."""
        namer = _make_namer()
        namer._functions = {
            "compute": {
                "params": [
                    {"name": "param_1", "type": "double *", "position": 0},
                    {"name": "param_2", "type": "double *", "position": 1},
                    {"name": "param_3", "type": "double *", "position": 2},
                ],
            },
        }

        candidates = [
            _make_sn("param_1", "M_matrix", "compute", confidence=0.85),
            _make_sn("param_2", "M_matrix", "compute", confidence=0.80),
            _make_sn("param_3", "M_matrix", "compute", confidence=0.75),
        ]

        result = namer._resolve_conflicts(candidates)
        assert len(result) == 3
        names = {r.semantic_name for r in result}
        # All three must be distinct
        assert len(names) == 3
        assert "M_matrix" in names
        assert "M_matrix_2" in names
        assert "M_matrix_3" in names

    def test_no_collision_scenario(self):
        """When names are all distinct, no suffix should be added."""
        namer = _make_namer()
        namer._functions = {
            "assemble": {
                "params": [
                    {"name": "param_1", "type": "int", "position": 0},
                    {"name": "param_2", "type": "double *", "position": 1},
                    {"name": "param_3", "type": "double *", "position": 2},
                ],
            },
        }

        candidates = [
            _make_sn("param_1", "n_dof", "assemble", confidence=0.85),
            _make_sn("param_2", "K_global", "assemble", confidence=0.80),
            _make_sn("param_3", "F_vector", "assemble", confidence=0.75),
        ]

        result = namer._resolve_conflicts(candidates)
        assert len(result) == 3
        names = {r.semantic_name for r in result}
        assert names == {"n_dof", "K_global", "F_vector"}

    def test_existing_non_auto_plus_auto_collision(self):
        """Mixed scenario: function has 'n_rows' already, auto-param wants 'n_rows'."""
        namer = _make_namer()
        namer._functions = {
            "fill_matrix": {
                "params": [
                    {"name": "n_rows", "type": "int", "position": 0},
                    {"name": "param_2", "type": "int", "position": 1},
                    {"name": "param_3", "type": "double *", "position": 2},
                ],
            },
        }

        candidates = [
            _make_sn("param_2", "n_rows", "fill_matrix", confidence=0.85),
            _make_sn("param_3", "data_ptr", "fill_matrix", confidence=0.80),
        ]

        result = namer._resolve_conflicts(candidates)
        assert len(result) == 2
        name_map = {r.original_name: r.semantic_name for r in result}
        # param_2 should get suffix because n_rows exists
        assert name_map["param_2"] == "n_rows_2"
        # param_3 has no collision
        assert name_map["param_3"] == "data_ptr"

    def test_pre_seed_ignores_auto_names(self):
        """Auto/generic names in existing params should NOT be pre-seeded."""
        namer = _make_namer()
        namer._functions = {
            "process": {
                "params": [
                    {"name": "param_1", "type": "int", "position": 0},
                    {"name": "param_2", "type": "double *", "position": 1},
                ],
            },
        }

        candidates = [
            _make_sn("param_1", "count", "process", confidence=0.85),
            _make_sn("param_2", "buffer", "process", confidence=0.80),
        ]

        result = namer._resolve_conflicts(candidates)
        assert len(result) == 2
        names = {r.semantic_name for r in result}
        # No suffix needed -- param_1 and param_2 are auto names, not pre-seeded
        assert names == {"count", "buffer"}


# ===========================================================================
# Integration: Bug 1 + Bug 2 combined
# ===========================================================================


class TestIntegrationBug1Bug2:
    """Combined scenarios ensuring both fixes work together."""

    def test_full_rename_pipeline_two_functions(self):
        """Two functions with conflicting param names, cross-refs, full pipeline."""
        code = textwrap.dedent("""\
            void assemble(int param_1, double *param_2, double *param_3) {
                for (int i = 0; i < param_1; i++) {
                    param_3[i] = param_2[i] * 2.0;
                }
                solve(param_1, param_3);
            }

            void solve(int param_1, double *param_2) {
                for (int i = 0; i < param_1; i++) {
                    param_2[i] = param_2[i] / 3.0;
                }
            }
        """)
        names = [
            _make_sn("param_1", "n_dof", "assemble"),
            _make_sn("param_2", "K_global", "assemble"),
            _make_sn("param_3", "F_vector", "assemble"),
            _make_sn("param_1", "n_eq", "solve"),
            _make_sn("param_2", "x_solution", "solve"),
        ]

        namer = _make_namer()
        result = namer._apply_names_to_code(code, names)

        # assemble should have its own names
        asm_start = result.find("void assemble")
        sol_start = result.find("void solve")
        asm_section = result[asm_start:sol_start]
        sol_section = result[sol_start:]

        assert "n_dof" in asm_section
        assert "K_global" in asm_section
        assert "F_vector" in asm_section

        assert "n_eq" in sol_section
        assert "x_solution" in sol_section

        # assemble's call to solve() should NOT be renamed
        # The call "solve(param_1, param_3)" is inside assemble body,
        # but param_1 in assemble IS being renamed to n_dof
        assert "solve(n_dof" in asm_section or "solve( n_dof" in asm_section or "solve(n_dof," in result

        # No duplicate function bodies
        assert result.count("void assemble") == 1
        assert result.count("void solve") == 1

    def test_empty_names_no_change(self):
        """Empty names list should return code unchanged."""
        code = "void foo(int x) { return; }\n"
        namer = _make_namer()
        result = namer._apply_names_to_code(code, [])
        assert result == code
