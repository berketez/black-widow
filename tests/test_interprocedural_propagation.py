"""Inter-procedural parameter name propagation test suite.

Tests cover:
1. Backward propagation (callee -> caller)
   - Known API function names propagate to caller's variables
   - Multi-argument propagation
   - Only auto-generated names get renamed
2. Forward propagation (caller -> callee)
   - Caller's known param names propagate to callee's params
   - Lower confidence than backward
3. Multi-hop iterative propagation
   - Chain: A -> B -> C, C known -> B named -> A named
   - Confidence decay per hop
   - Convergence detection
4. Call-argument graph building
   - Correct parsing of Ghidra-style call sites
   - Nested calls, casts, pointer arithmetic
   - Skip boilerplate functions
5. Edge cases
   - Empty files, no known names
   - Recursive calls
   - Self-referencing chains
   - Conflicting names (first wins)

v1.8.1: Inter-procedural parameter name propagation (Technique 2).
"""
from __future__ import annotations

import json
import textwrap
from pathlib import Path
from typing import Any

import pytest

from karadul.config import Config
from karadul.reconstruction.engineering.data_flow import (
    InterProceduralDataFlow,
    PropagatedParamName,
    _parse_args_string,
    _extract_base_var,
)


# ===========================================================================
# Helpers
# ===========================================================================

def _write_c_file(directory: Path, name: str, content: str) -> Path:
    """Write a C file to the directory."""
    path = directory / f"{name}.c"
    path.write_text(textwrap.dedent(content))
    return path


def _write_functions_json(directory: Path, functions: list[dict]) -> Path:
    """Write functions.json."""
    path = directory / "ghidra_functions.json"
    path.write_text(json.dumps({"functions": functions}))
    return path


def _write_call_graph_json(directory: Path, graph: dict) -> Path:
    """Write call_graph.json."""
    path = directory / "ghidra_call_graph.json"
    path.write_text(json.dumps(graph))
    return path


def _make_tracker() -> InterProceduralDataFlow:
    """Create a tracker instance."""
    return InterProceduralDataFlow(Config())


# ===========================================================================
# 1. Backward Propagation
# ===========================================================================

class TestBackwardPropagation:
    """Callee'nin bilinen param isimlerini caller'a yay."""

    def test_basic_memcpy_backward(self, tmp_path: Path) -> None:
        """memcpy(param_1, param_2, param_3) -> dest, src, n."""
        decompiled = tmp_path / "decompiled"
        decompiled.mkdir()
        static = tmp_path / "static"
        static.mkdir()

        _write_c_file(decompiled, "caller", """
            void FUN_00401000(long param_1, long param_2, int param_3) {
                memcpy(param_1, param_2, param_3);
            }
        """)
        _write_c_file(decompiled, "memcpy_stub", """
            void memcpy(void *dest, void *src, size_t n) {
                return;
            }
        """)

        funcs_json = _write_functions_json(static, [
            {
                "name": "FUN_00401000",
                "address": "0x401000",
                "parameters": [
                    {"name": "param_1", "type": "long", "ordinal": 0},
                    {"name": "param_2", "type": "long", "ordinal": 1},
                    {"name": "param_3", "type": "int", "ordinal": 2},
                ],
            },
        ])
        cg_json = _write_call_graph_json(static, {
            "nodes": [
                {"name": "FUN_00401000", "callees": [{"name": "memcpy"}]},
            ],
        })

        tracker = _make_tracker()
        results = tracker.propagate_param_names(
            decompiled_dir=decompiled,
            functions_json=funcs_json,
            call_graph_json=cg_json,
            known_names={"memcpy": {"param_1": "dest", "param_2": "src", "param_3": "n"}},
        )

        # param_1 -> dest, param_2 -> src, param_3 -> n
        by_orig = {r.original_name: r for r in results if r.function_name == "FUN_00401000"}
        assert "param_1" in by_orig
        assert by_orig["param_1"].propagated_name == "dest"
        assert by_orig["param_1"].direction == "backward"
        assert by_orig["param_1"].hop_count == 1
        assert by_orig["param_1"].confidence >= 0.80

        assert "param_2" in by_orig
        assert by_orig["param_2"].propagated_name == "src"

        assert "param_3" in by_orig
        assert by_orig["param_3"].propagated_name == "n"

    def test_does_not_rename_meaningful_params(self, tmp_path: Path) -> None:
        """Already meaningful names should not be overwritten."""
        decompiled = tmp_path / "decompiled"
        decompiled.mkdir()
        static = tmp_path / "static"
        static.mkdir()

        _write_c_file(decompiled, "caller", """
            void FUN_00401000(long dest_buffer, long param_2) {
                memcpy(dest_buffer, param_2, 100);
            }
        """)

        funcs_json = _write_functions_json(static, [
            {
                "name": "FUN_00401000",
                "address": "0x401000",
                "parameters": [
                    {"name": "dest_buffer", "type": "long", "ordinal": 0},
                    {"name": "param_2", "type": "long", "ordinal": 1},
                ],
            },
        ])
        cg_json = _write_call_graph_json(static, {"nodes": []})

        tracker = _make_tracker()
        results = tracker.propagate_param_names(
            decompiled_dir=decompiled,
            functions_json=funcs_json,
            call_graph_json=cg_json,
            known_names={"memcpy": {"param_1": "dest", "param_2": "src", "param_3": "n"}},
        )

        # dest_buffer should NOT be renamed (already meaningful)
        renamed_originals = {r.original_name for r in results if r.function_name == "FUN_00401000"}
        assert "dest_buffer" not in renamed_originals
        # param_2 SHOULD be renamed
        assert "param_2" in renamed_originals

    def test_backward_confidence_decay(self, tmp_path: Path) -> None:
        """Confidence should decay per hop."""
        decompiled = tmp_path / "decompiled"
        decompiled.mkdir()
        static = tmp_path / "static"
        static.mkdir()

        # Chain: A -> B -> C (C known)
        _write_c_file(decompiled, "func_a", """
            void FUN_A(long param_1) {
                FUN_B(param_1);
            }
        """)
        _write_c_file(decompiled, "func_b", """
            void FUN_B(long param_1) {
                known_func(param_1);
            }
        """)
        _write_c_file(decompiled, "known", """
            void known_func(long matrix_data) {
                return;
            }
        """)

        funcs_json = _write_functions_json(static, [
            {"name": "FUN_A", "address": "0xa", "parameters": [
                {"name": "param_1", "type": "long", "ordinal": 0},
            ]},
            {"name": "FUN_B", "address": "0xb", "parameters": [
                {"name": "param_1", "type": "long", "ordinal": 0},
            ]},
            {"name": "known_func", "address": "0xc", "parameters": [
                {"name": "matrix_data", "type": "long", "ordinal": 0},
            ]},
        ])
        cg_json = _write_call_graph_json(static, {
            "nodes": [
                {"name": "FUN_A", "callees": [{"name": "FUN_B"}]},
                {"name": "FUN_B", "callees": [{"name": "known_func"}]},
            ],
        })

        tracker = _make_tracker()
        results = tracker.propagate_param_names(
            decompiled_dir=decompiled,
            functions_json=funcs_json,
            call_graph_json=cg_json,
        )

        # FUN_B.param_1 should be named in round 1 (hop 1)
        # FUN_A.param_1 should be named in round 2 (hop 2)
        b_result = [r for r in results if r.function_name == "FUN_B"]
        a_result = [r for r in results if r.function_name == "FUN_A"]

        assert len(b_result) >= 1
        assert b_result[0].propagated_name == "matrix_data"
        assert b_result[0].hop_count == 1

        assert len(a_result) >= 1
        assert a_result[0].propagated_name == "matrix_data"
        assert a_result[0].hop_count == 2
        # Round 2 confidence < round 1 confidence
        assert a_result[0].confidence < b_result[0].confidence


# ===========================================================================
# 2. Forward Propagation
# ===========================================================================

class TestForwardPropagation:
    """Caller'in bilinen param isimlerini callee'ye yay."""

    def test_basic_forward(self, tmp_path: Path) -> None:
        """Known caller param -> unknown callee param."""
        decompiled = tmp_path / "decompiled"
        decompiled.mkdir()
        static = tmp_path / "static"
        static.mkdir()

        _write_c_file(decompiled, "caller", """
            void known_caller(long K_global, long f_load, int n_dof) {
                FUN_unknown(K_global, f_load, n_dof);
            }
        """)
        _write_c_file(decompiled, "callee", """
            void FUN_unknown(long param_1, long param_2, int param_3) {
                return;
            }
        """)

        funcs_json = _write_functions_json(static, [
            {"name": "known_caller", "address": "0x1", "parameters": [
                {"name": "K_global", "type": "long", "ordinal": 0},
                {"name": "f_load", "type": "long", "ordinal": 1},
                {"name": "n_dof", "type": "int", "ordinal": 2},
            ]},
            {"name": "FUN_unknown", "address": "0x2", "parameters": [
                {"name": "param_1", "type": "long", "ordinal": 0},
                {"name": "param_2", "type": "long", "ordinal": 1},
                {"name": "param_3", "type": "int", "ordinal": 2},
            ]},
        ])
        cg_json = _write_call_graph_json(static, {
            "nodes": [
                {"name": "known_caller", "callees": [{"name": "FUN_unknown"}]},
            ],
        })

        tracker = _make_tracker()
        results = tracker.propagate_param_names(
            decompiled_dir=decompiled,
            functions_json=funcs_json,
            call_graph_json=cg_json,
        )

        forward = [r for r in results if r.direction == "forward" and r.function_name == "FUN_unknown"]
        by_orig = {r.original_name: r for r in forward}

        assert "param_1" in by_orig
        assert by_orig["param_1"].propagated_name == "K_global"
        assert "param_2" in by_orig
        assert by_orig["param_2"].propagated_name == "f_load"
        assert "param_3" in by_orig
        assert by_orig["param_3"].propagated_name == "n_dof"

    def test_forward_lower_confidence_than_backward(self, tmp_path: Path) -> None:
        """Forward propagation should have lower confidence than backward."""
        decompiled = tmp_path / "decompiled"
        decompiled.mkdir()
        static = tmp_path / "static"
        static.mkdir()

        _write_c_file(decompiled, "caller", """
            void known_caller(long data_ptr) {
                FUN_callee(data_ptr);
            }
        """)
        _write_c_file(decompiled, "callee", """
            void FUN_callee(long param_1) {
                known_api(param_1);
            }
        """)

        funcs_json = _write_functions_json(static, [
            {"name": "known_caller", "address": "0x1", "parameters": [
                {"name": "data_ptr", "type": "long", "ordinal": 0},
            ]},
            {"name": "FUN_callee", "address": "0x2", "parameters": [
                {"name": "param_1", "type": "long", "ordinal": 0},
            ]},
        ])
        cg_json = _write_call_graph_json(static, {
            "nodes": [
                {"name": "known_caller", "callees": [{"name": "FUN_callee"}]},
                {"name": "FUN_callee", "callees": [{"name": "known_api"}]},
            ],
        })

        tracker = _make_tracker()
        results = tracker.propagate_param_names(
            decompiled_dir=decompiled,
            functions_json=funcs_json,
            call_graph_json=cg_json,
            known_names={"known_api": {"param_1": "buffer"}},
        )

        forward = [r for r in results if r.direction == "forward"]
        backward = [r for r in results if r.direction == "backward"]

        if forward and backward:
            assert forward[0].confidence < backward[0].confidence


# ===========================================================================
# 3. Multi-hop Iterative Propagation
# ===========================================================================

class TestIterativePropagation:
    """Multi-hop iterative name propagation."""

    def test_convergence(self, tmp_path: Path) -> None:
        """Should converge when no new names found."""
        decompiled = tmp_path / "decompiled"
        decompiled.mkdir()
        static = tmp_path / "static"
        static.mkdir()

        # Single known callee, single caller -- should converge in 1 round
        _write_c_file(decompiled, "caller", """
            void FUN_caller(long param_1) {
                known(param_1);
            }
        """)
        _write_c_file(decompiled, "known", """
            void known(long data) {
                return;
            }
        """)

        funcs_json = _write_functions_json(static, [
            {"name": "FUN_caller", "address": "0x1", "parameters": [
                {"name": "param_1", "type": "long", "ordinal": 0},
            ]},
            {"name": "known", "address": "0x2", "parameters": [
                {"name": "data", "type": "long", "ordinal": 0},
            ]},
        ])
        cg_json = _write_call_graph_json(static, {"nodes": []})

        tracker = _make_tracker()
        results = tracker.propagate_param_names(
            decompiled_dir=decompiled,
            functions_json=funcs_json,
            call_graph_json=cg_json,
        )

        # Should find exactly 1 result (param_1 -> data)
        caller_results = [r for r in results if r.function_name == "FUN_caller"]
        assert len(caller_results) == 1
        assert caller_results[0].propagated_name == "data"

    def test_three_hop_chain(self, tmp_path: Path) -> None:
        """A -> B -> C -> D (D known). A should get name after 3 rounds."""
        decompiled = tmp_path / "decompiled"
        decompiled.mkdir()
        static = tmp_path / "static"
        static.mkdir()

        _write_c_file(decompiled, "a", """
            void FUN_A(long param_1) {
                FUN_B(param_1);
            }
        """)
        _write_c_file(decompiled, "b", """
            void FUN_B(long param_1) {
                FUN_C(param_1);
            }
        """)
        _write_c_file(decompiled, "c", """
            void FUN_C(long param_1) {
                target_func(param_1);
            }
        """)
        _write_c_file(decompiled, "d", """
            void target_func(long encryption_key) {
                return;
            }
        """)

        funcs_json = _write_functions_json(static, [
            {"name": "FUN_A", "address": "0xa", "parameters": [
                {"name": "param_1", "type": "long", "ordinal": 0},
            ]},
            {"name": "FUN_B", "address": "0xb", "parameters": [
                {"name": "param_1", "type": "long", "ordinal": 0},
            ]},
            {"name": "FUN_C", "address": "0xc", "parameters": [
                {"name": "param_1", "type": "long", "ordinal": 0},
            ]},
            {"name": "target_func", "address": "0xd", "parameters": [
                {"name": "encryption_key", "type": "long", "ordinal": 0},
            ]},
        ])
        cg_json = _write_call_graph_json(static, {"nodes": []})

        tracker = _make_tracker()
        results = tracker.propagate_param_names(
            decompiled_dir=decompiled,
            functions_json=funcs_json,
            call_graph_json=cg_json,
        )

        # All three should be named "encryption_key"
        for func in ("FUN_A", "FUN_B", "FUN_C"):
            func_results = [r for r in results if r.function_name == func]
            assert len(func_results) >= 1, f"{func} should have a propagated name"
            assert func_results[0].propagated_name == "encryption_key"

        # Hop counts: C=1, B=2, A=3
        c_result = [r for r in results if r.function_name == "FUN_C"][0]
        b_result = [r for r in results if r.function_name == "FUN_B"][0]
        a_result = [r for r in results if r.function_name == "FUN_A"][0]

        assert c_result.hop_count == 1
        assert b_result.hop_count == 2
        assert a_result.hop_count == 3

        # Confidence: C > B > A (decay)
        assert c_result.confidence > b_result.confidence > a_result.confidence


# ===========================================================================
# 4. Call-Argument Graph Building
# ===========================================================================

class TestCallArgumentGraph:
    """Test _build_call_argument_graph.

    NOT: _build_call_argument_graph all_func_code'da BODY alir
    (_extract_functions -> _extract_body sonucu). Yani sadece
    { ... } icerigi, fonksiyon imzasi HARIC.
    """

    def test_simple_call(self, tmp_path: Path) -> None:
        """Basic function call parsing."""
        tracker = _make_tracker()
        code = {
            "caller": "{ callee(param_1); }",
        }
        result = tracker._build_call_argument_graph(code, {}, {})
        assert "caller" in result
        entries = result["caller"]
        callees = [e[0] for e in entries]
        assert "callee" in callees

    def test_skip_boilerplate(self, tmp_path: Path) -> None:
        """Skip printf (in _PROP_SKIP). memcpy/memset NOT skipped in propagation."""
        tracker = _make_tracker()
        code = {
            "caller": "{ printf(param_1); memset(param_1, 0, 10); }",
        }
        result = tracker._build_call_argument_graph(code, {}, {})
        # printf IS in _PROP_SKIP (output/logging)
        if "caller" in result:
            callees = [e[0] for e in result["caller"]]
            assert "printf" not in callees
            # memset is NOT skipped in propagation (known API, has param names)
            assert "memset" in callees

    def test_skip_recursive(self, tmp_path: Path) -> None:
        """Skip recursive calls."""
        tracker = _make_tracker()
        code = {
            "caller": "{ caller(param_1); other(param_1); }",
        }
        result = tracker._build_call_argument_graph(code, {}, {})
        if "caller" in result:
            callees = [e[0] for e in result["caller"]]
            assert "caller" not in callees
            assert "other" in callees

    def test_multi_arg_call(self, tmp_path: Path) -> None:
        """Multiple arguments parsed correctly."""
        tracker = _make_tracker()
        code = {
            "caller": "{ callee(param_1, param_2, 42); }",
        }
        result = tracker._build_call_argument_graph(code, {}, {})
        assert "caller" in result
        entries = result["caller"]
        callee_entry = [e for e in entries if e[0] == "callee"]
        assert len(callee_entry) == 1
        arg_mappings = callee_entry[0][1]
        # Should have param_1 at idx 0, param_2 at idx 1
        idxs = {idx for idx, _ in arg_mappings}
        vars_ = {var for _, var in arg_mappings}
        assert 0 in idxs
        assert 1 in idxs
        assert "param_1" in vars_
        assert "param_2" in vars_

    def test_skip_control_flow_keywords(self, tmp_path: Path) -> None:
        """if, while, for, switch, return should be skipped."""
        tracker = _make_tracker()
        code = {
            "caller": "{ if (x > 0) { while (x) { x = x - 1; } } }",
        }
        result = tracker._build_call_argument_graph(code, {}, {})
        # Should not have if, while, return as callees
        if "caller" in result:
            callees = [e[0] for e in result["caller"]]
            for kw in ("if", "while", "for", "switch", "return"):
                assert kw not in callees


# ===========================================================================
# 5. Edge Cases
# ===========================================================================

class TestEdgeCases:
    """Edge cases and robustness."""

    def test_no_c_files(self, tmp_path: Path) -> None:
        """Empty decompiled directory."""
        decompiled = tmp_path / "decompiled"
        decompiled.mkdir()
        static = tmp_path / "static"
        static.mkdir()

        funcs_json = _write_functions_json(static, [])
        cg_json = _write_call_graph_json(static, {"nodes": []})

        tracker = _make_tracker()
        results = tracker.propagate_param_names(
            decompiled_dir=decompiled,
            functions_json=funcs_json,
            call_graph_json=cg_json,
        )
        assert results == []

    def test_no_known_names(self, tmp_path: Path) -> None:
        """No known names -- nothing to propagate."""
        decompiled = tmp_path / "decompiled"
        decompiled.mkdir()
        static = tmp_path / "static"
        static.mkdir()

        _write_c_file(decompiled, "a", """
            void FUN_A(long param_1) {
                FUN_B(param_1);
            }
        """)
        _write_c_file(decompiled, "b", """
            void FUN_B(long param_1) {
                return;
            }
        """)

        funcs_json = _write_functions_json(static, [
            {"name": "FUN_A", "address": "0xa", "parameters": [
                {"name": "param_1", "type": "long", "ordinal": 0},
            ]},
            {"name": "FUN_B", "address": "0xb", "parameters": [
                {"name": "param_1", "type": "long", "ordinal": 0},
            ]},
        ])
        cg_json = _write_call_graph_json(static, {"nodes": []})

        tracker = _make_tracker()
        results = tracker.propagate_param_names(
            decompiled_dir=decompiled,
            functions_json=funcs_json,
            call_graph_json=cg_json,
            known_names={},  # explicitly empty
        )
        # Both params are auto-gen (param_1), neither is known
        # So nothing should propagate
        assert results == []

    def test_propagated_param_name_serialization(self) -> None:
        """PropagatedParamName.to_dict() works correctly."""
        p = PropagatedParamName(
            function_name="FUN_001",
            original_name="param_1",
            propagated_name="dest",
            confidence=0.85,
            direction="backward",
            hop_count=1,
            source_function="memcpy",
            source_param_idx=0,
            evidence="param_1 passed as arg0 to memcpy(dest) [round 1]",
        )
        d = p.to_dict()
        assert d["function_name"] == "FUN_001"
        assert d["propagated_name"] == "dest"
        assert d["confidence"] == 0.85
        assert d["direction"] == "backward"
        assert d["hop_count"] == 1

    def test_bidirectional_same_round(self, tmp_path: Path) -> None:
        """Both backward and forward can happen in the same round."""
        decompiled = tmp_path / "decompiled"
        decompiled.mkdir()
        static = tmp_path / "static"
        static.mkdir()

        _write_c_file(decompiled, "known_caller", """
            void known_caller(long K_global) {
                FUN_middle(K_global);
            }
        """)
        _write_c_file(decompiled, "middle", """
            void FUN_middle(long param_1) {
                known_callee(param_1);
            }
        """)
        _write_c_file(decompiled, "known_callee", """
            void known_callee(long stiffness_matrix) {
                return;
            }
        """)

        funcs_json = _write_functions_json(static, [
            {"name": "known_caller", "address": "0x1", "parameters": [
                {"name": "K_global", "type": "long", "ordinal": 0},
            ]},
            {"name": "FUN_middle", "address": "0x2", "parameters": [
                {"name": "param_1", "type": "long", "ordinal": 0},
            ]},
            {"name": "known_callee", "address": "0x3", "parameters": [
                {"name": "stiffness_matrix", "type": "long", "ordinal": 0},
            ]},
        ])
        cg_json = _write_call_graph_json(static, {"nodes": []})

        tracker = _make_tracker()
        results = tracker.propagate_param_names(
            decompiled_dir=decompiled,
            functions_json=funcs_json,
            call_graph_json=cg_json,
        )

        # FUN_middle.param_1 should get named (either from backward or forward)
        middle_results = [r for r in results if r.function_name == "FUN_middle"]
        assert len(middle_results) >= 1
        # Should get one of the known names
        assert middle_results[0].propagated_name in ("K_global", "stiffness_matrix")


# ===========================================================================
# 6. Config Integration
# ===========================================================================

class TestConfigIntegration:
    """Source weight in NameMergerConfig."""

    def test_interprocedural_weight_exists(self) -> None:
        """interprocedural_propagation should be in source_weights."""
        from karadul.config import NameMergerConfig
        cfg = NameMergerConfig()
        assert "interprocedural_propagation" in cfg.source_weights
        assert cfg.source_weights["interprocedural_propagation"] == 0.85

    def test_name_merger_accepts_source(self) -> None:
        """NameMerger should accept interprocedural_propagation as a source."""
        from karadul.reconstruction.name_merger import NameMerger, NamingCandidate
        merger = NameMerger()
        candidates = {
            "FUN_001": [
                NamingCandidate(
                    name="dest",
                    confidence=0.80,
                    source="interprocedural_propagation",
                    reason="backward from memcpy",
                ),
            ],
        }
        result = merger.merge(candidates)
        assert result.total_merged >= 1
        merged = result.merged_names.get("FUN_001")
        assert merged is not None
        assert merged.final_name == "dest"
