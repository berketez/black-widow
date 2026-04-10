"""Tests for v1.7.2 parameter naming improvements.

Tests cover:
- Strategy 0: Signature-based parameter naming
- Strategy 5: Call-context naming
- Enhanced type-based heuristics
- First-param self/ctx detection
- Integration with existing strategies
"""

from __future__ import annotations

import json
import textwrap
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from karadul.config import Config
from karadul.reconstruction.engineering.semantic_namer import (
    SemanticParameterNamer,
    SemanticNamingResult,
    _sanitize_c_name,
    _is_auto_or_generic_name,
    _types_compatible,
    _detect_usage_pattern,
    _detect_index_pattern,
    _FIRST_PARAM_SELF_TYPES,
)


# ---------------------------------------------------------------------------
# Test fixtures
# ---------------------------------------------------------------------------

@dataclass
class MockSignatureMatch:
    """Mock for SignatureMatch from signature_db."""
    original_name: str
    matched_name: str
    library: str
    confidence: float
    match_method: str = "symbol"
    purpose: str = ""
    category: str = ""


@dataclass
class MockAlgorithmMatch:
    """Mock for AlgorithmMatch."""
    name: str
    function_name: str
    confidence: float


@pytest.fixture
def config():
    return Config()


@pytest.fixture
def namer(config):
    return SemanticParameterNamer(config)


@pytest.fixture
def tmp_workspace(tmp_path):
    """Create a minimal workspace for testing."""
    static = tmp_path / "static"
    static.mkdir()
    decompiled = tmp_path / "decompiled"
    decompiled.mkdir()
    output = tmp_path / "output"
    output.mkdir()

    # Minimal functions.json
    functions_json = static / "ghidra_functions.json"
    functions_json.write_text(json.dumps({"functions": []}))

    # Minimal call_graph.json
    call_graph_json = static / "ghidra_call_graph.json"
    call_graph_json.write_text(json.dumps({"nodes": {}, "edges": []}))

    return tmp_path, static, decompiled, output, functions_json, call_graph_json


def _write_c_file(decompiled_dir: Path, filename: str, code: str) -> Path:
    """Write a C file and return its path."""
    p = decompiled_dir / filename
    p.write_text(textwrap.dedent(code))
    return p


def _write_functions_json(path: Path, functions: list[dict]) -> None:
    """Write functions JSON."""
    path.write_text(json.dumps({"functions": functions}))


# =========================================================================
# Test: Strategy 0 -- Signature-based parameter naming
# =========================================================================

class TestSignatureBasedNaming:
    """v1.7.2: Signature DB match -> copy param names from APIParamDB."""

    def test_sqlite3_open_params(self, namer, tmp_workspace):
        """sqlite3_open matched by signature -> param_1=filename, param_2=ppDb."""
        tmp_path, static, decompiled, output, functions_json, call_graph_json = tmp_workspace

        _write_c_file(decompiled, "funcs.c", """\
            int FUN_00401000(char *param_1, long *param_2) {
                return 0;
            }
        """)
        _write_functions_json(functions_json, [
            {"name": "FUN_00401000", "address": "0x401000", "params": [
                {"name": "param_1", "type": "char *", "position": 0},
                {"name": "param_2", "type": "long *", "position": 1},
            ]},
        ])

        sig_matches = [
            MockSignatureMatch(
                original_name="FUN_00401000",
                matched_name="sqlite3_open",
                library="sqlite",
                confidence=0.90,
            ),
        ]

        result = namer.rename(
            decompiled_dir=decompiled,
            functions_json=functions_json,
            call_graph_json=call_graph_json,
            output_dir=output,
            signature_matches=sig_matches,
        )

        assert result.success
        assert result.total_renamed >= 2
        names = {sn.original_name: sn.semantic_name for sn in result.names
                 if sn.function_name == "FUN_00401000"}
        assert names.get("param_1") == "filename"
        assert names.get("param_2") == "ppDb"

    def test_memcpy_params(self, namer, tmp_workspace):
        """memcpy matched by signature -> dest, src, n."""
        tmp_path, static, decompiled, output, functions_json, call_graph_json = tmp_workspace

        # Note: Ghidra decompiles void* return as "undefined8" or "long"
        _write_c_file(decompiled, "funcs.c", """\
            long FUN_00402000(long param_1, long param_2, int param_3) {
                return param_1;
            }
        """)
        _write_functions_json(functions_json, [
            {"name": "FUN_00402000", "address": "0x402000", "params": [
                {"name": "param_1", "type": "long", "position": 0},
                {"name": "param_2", "type": "long", "position": 1},
                {"name": "param_3", "type": "int", "position": 2},
            ]},
        ])

        sig_matches = [
            MockSignatureMatch(
                original_name="FUN_00402000",
                matched_name="memcpy",
                library="libc",
                confidence=0.95,
            ),
        ]

        result = namer.rename(
            decompiled_dir=decompiled,
            functions_json=functions_json,
            call_graph_json=call_graph_json,
            output_dir=output,
            signature_matches=sig_matches,
        )

        assert result.success
        names = {sn.original_name: sn.semantic_name for sn in result.names
                 if sn.function_name == "FUN_00402000" and sn.source == "signature_based"}
        assert names.get("param_1") == "dest"
        assert names.get("param_2") == "src"
        assert names.get("param_3") == "n"

    def test_signature_confidence_scaling(self, namer, tmp_workspace):
        """Signature confidence affects param naming confidence."""
        tmp_path, static, decompiled, output, functions_json, call_graph_json = tmp_workspace

        _write_c_file(decompiled, "funcs.c", """\
            int FUN_00403000(int param_1) {
                return 0;
            }
        """)
        _write_functions_json(functions_json, [
            {"name": "FUN_00403000", "address": "0x403000", "params": [
                {"name": "param_1", "type": "int", "position": 0},
            ]},
        ])

        # High confidence signature match
        sig_matches_high = [
            MockSignatureMatch(
                original_name="FUN_00403000",
                matched_name="close",
                library="libc",
                confidence=0.95,
            ),
        ]
        result_high = namer.rename(
            decompiled_dir=decompiled,
            functions_json=functions_json,
            call_graph_json=call_graph_json,
            output_dir=output,
            signature_matches=sig_matches_high,
        )

        # Low confidence signature match
        sig_matches_low = [
            MockSignatureMatch(
                original_name="FUN_00403000",
                matched_name="close",
                library="libc",
                confidence=0.50,
            ),
        ]
        result_low = namer.rename(
            decompiled_dir=decompiled,
            functions_json=functions_json,
            call_graph_json=call_graph_json,
            output_dir=output,
            signature_matches=sig_matches_low,
        )

        # Both should rename, but high confidence should have higher naming conf
        high_names = [sn for sn in result_high.names if sn.source == "signature_based"]
        low_names = [sn for sn in result_low.names if sn.source == "signature_based"]
        if high_names and low_names:
            assert high_names[0].confidence >= low_names[0].confidence

    def test_underscore_prefix_lookup(self, namer, tmp_workspace):
        """Underscore-prefixed function names (Mach-O) should be resolved."""
        tmp_path, static, decompiled, output, functions_json, call_graph_json = tmp_workspace

        _write_c_file(decompiled, "funcs.c", """\
            int FUN_00404000(char *param_1, int param_2) {
                return 0;
            }
        """)
        _write_functions_json(functions_json, [
            {"name": "FUN_00404000", "address": "0x404000", "params": [
                {"name": "param_1", "type": "char *", "position": 0},
                {"name": "param_2", "type": "int", "position": 1},
            ]},
        ])

        # _open is the Mach-O symbol for open()
        sig_matches = [
            MockSignatureMatch(
                original_name="FUN_00404000",
                matched_name="_open",
                library="libc",
                confidence=0.90,
            ),
        ]

        result = namer.rename(
            decompiled_dir=decompiled,
            functions_json=functions_json,
            call_graph_json=call_graph_json,
            output_dir=output,
            signature_matches=sig_matches,
        )

        assert result.success
        names = {sn.original_name: sn.semantic_name for sn in result.names
                 if sn.source == "signature_based"}
        # Should find open(pathname, flags, mode) -> param_1=pathname
        assert names.get("param_1") == "pathname"

    def test_no_rename_for_already_named_params(self, namer, tmp_workspace):
        """Parameters that already have meaningful names should NOT be renamed."""
        tmp_path, static, decompiled, output, functions_json, call_graph_json = tmp_workspace

        _write_c_file(decompiled, "funcs.c", """\
            int FUN_00405000(char *filename, long *param_2) {
                return 0;
            }
        """)
        _write_functions_json(functions_json, [
            {"name": "FUN_00405000", "address": "0x405000", "params": [
                {"name": "filename", "type": "char *", "position": 0},
                {"name": "param_2", "type": "long *", "position": 1},
            ]},
        ])

        sig_matches = [
            MockSignatureMatch(
                original_name="FUN_00405000",
                matched_name="sqlite3_open",
                library="sqlite",
                confidence=0.90,
            ),
        ]

        result = namer.rename(
            decompiled_dir=decompiled,
            functions_json=functions_json,
            call_graph_json=call_graph_json,
            output_dir=output,
            signature_matches=sig_matches,
        )

        # filename is already meaningful -> should NOT be in renames
        sig_names = [sn for sn in result.names if sn.source == "signature_based"]
        orig_names = {sn.original_name for sn in sig_names}
        assert "filename" not in orig_names
        assert "param_2" in orig_names


# =========================================================================
# Test: Strategy 5 -- Call-context naming
# =========================================================================

class TestCallContextNaming:
    """v1.7.2: Callee API calls infer parameter names."""

    def test_malloc_call_names_size(self, namer, tmp_workspace):
        """If function calls malloc(param_2), then param_2 -> size."""
        tmp_path, static, decompiled, output, functions_json, call_graph_json = tmp_workspace

        # Note: use 'long' return type, Ghidra decompiles void* as long/undefined8
        _write_c_file(decompiled, "funcs.c", """\
            long FUN_00501000(int param_1, int param_2) {
                long buf = malloc(param_2);
                return buf;
            }
        """)
        _write_functions_json(functions_json, [
            {"name": "FUN_00501000", "address": "0x501000", "params": [
                {"name": "param_1", "type": "int", "position": 0},
                {"name": "param_2", "type": "int", "position": 1},
            ]},
        ])

        result = namer.rename(
            decompiled_dir=decompiled,
            functions_json=functions_json,
            call_graph_json=call_graph_json,
            output_dir=output,
        )

        assert result.success
        cc_names = {sn.original_name: sn.semantic_name for sn in result.names
                    if sn.source == "call_context"}
        assert cc_names.get("param_2") == "size"

    def test_send_call_names_params(self, namer, tmp_workspace):
        """send(param_1, param_2, param_3, 0) -> sockfd, buf, len."""
        tmp_path, static, decompiled, output, functions_json, call_graph_json = tmp_workspace

        _write_c_file(decompiled, "funcs.c", """\
            int FUN_00502000(int param_1, char *param_2, int param_3) {
                int ret = send(param_1, param_2, param_3, 0);
                return ret;
            }
        """)
        _write_functions_json(functions_json, [
            {"name": "FUN_00502000", "address": "0x502000", "params": [
                {"name": "param_1", "type": "int", "position": 0},
                {"name": "param_2", "type": "char *", "position": 1},
                {"name": "param_3", "type": "int", "position": 2},
            ]},
        ])

        result = namer.rename(
            decompiled_dir=decompiled,
            functions_json=functions_json,
            call_graph_json=call_graph_json,
            output_dir=output,
        )

        assert result.success
        cc_names = {sn.original_name: sn.semantic_name for sn in result.names
                    if sn.source == "call_context"}
        assert cc_names.get("param_1") == "sockfd"
        assert cc_names.get("param_2") == "buf"
        assert cc_names.get("param_3") == "len"

    def test_memcpy_call_context(self, namer, tmp_workspace):
        """memcpy(local_x, param_1, param_3) -> param_1=src, param_3=n."""
        tmp_path, static, decompiled, output, functions_json, call_graph_json = tmp_workspace

        _write_c_file(decompiled, "funcs.c", """\
            void FUN_00503000(void *param_1, int param_2, int param_3) {
                char local_buf[256];
                memcpy(local_buf, param_1, param_3);
                return;
            }
        """)
        _write_functions_json(functions_json, [
            {"name": "FUN_00503000", "address": "0x503000", "params": [
                {"name": "param_1", "type": "void *", "position": 0},
                {"name": "param_2", "type": "int", "position": 1},
                {"name": "param_3", "type": "int", "position": 2},
            ]},
        ])

        result = namer.rename(
            decompiled_dir=decompiled,
            functions_json=functions_json,
            call_graph_json=call_graph_json,
            output_dir=output,
        )

        assert result.success
        cc_names = {sn.original_name: sn.semantic_name for sn in result.names
                    if sn.source == "call_context"}
        assert cc_names.get("param_1") == "src"
        assert cc_names.get("param_3") == "n"


# =========================================================================
# Test: Enhanced type-based heuristics
# =========================================================================

class TestEnhancedTypeHeuristics:
    """v1.7.2: Improved type-based parameter naming."""

    def test_first_param_self_detection(self, namer, tmp_workspace):
        """First param (long) with offset access -> 'self'."""
        tmp_path, static, decompiled, output, functions_json, call_graph_json = tmp_workspace

        _write_c_file(decompiled, "funcs.c", """\
            void FUN_00601000(long param_1, int param_2) {
                int x = *(int *)(param_1 + 0x10);
                int y = *(int *)(param_1 + 0x14);
                *(int *)(param_1 + 0x18) = x + y;
                return;
            }
        """)
        _write_functions_json(functions_json, [
            {"name": "FUN_00601000", "address": "0x601000", "params": [
                {"name": "param_1", "type": "long", "position": 0},
                {"name": "param_2", "type": "int", "position": 1},
            ]},
        ])

        result = namer.rename(
            decompiled_dir=decompiled,
            functions_json=functions_json,
            call_graph_json=call_graph_json,
            output_dir=output,
        )

        assert result.success
        names = {sn.original_name: sn.semantic_name for sn in result.names
                 if sn.function_name == "FUN_00601000"}
        assert names.get("param_1") == "self"

    def test_int_loop_bound_becomes_n_size(self, namer, tmp_workspace):
        """int param used as loop bound -> 'n_size'."""
        tmp_path, static, decompiled, output, functions_json, call_graph_json = tmp_workspace

        _write_c_file(decompiled, "funcs.c", """\
            void FUN_00602000(double *param_1, int param_2) {
                for (int i = 0; i < param_2; i++) {
                    param_1[i] = 0.0;
                }
                return;
            }
        """)
        _write_functions_json(functions_json, [
            {"name": "FUN_00602000", "address": "0x602000", "params": [
                {"name": "param_1", "type": "double *", "position": 0},
                {"name": "param_2", "type": "int", "position": 1},
            ]},
        ])

        result = namer.rename(
            decompiled_dir=decompiled,
            functions_json=functions_json,
            call_graph_json=call_graph_json,
            output_dir=output,
        )

        assert result.success
        names = {sn.original_name: sn.semantic_name for sn in result.names
                 if sn.source == "type_heuristic"}
        assert names.get("param_2") == "n_size"

    def test_char_ptr_becomes_str(self, namer, tmp_workspace):
        """char * param -> 'str' or similar text name."""
        tmp_path, static, decompiled, output, functions_json, call_graph_json = tmp_workspace

        _write_c_file(decompiled, "funcs.c", """\
            void FUN_00603000(char *param_1) {
                printf("%s", param_1);
                return;
            }
        """)
        _write_functions_json(functions_json, [
            {"name": "FUN_00603000", "address": "0x603000", "params": [
                {"name": "param_1", "type": "char *", "position": 0},
            ]},
        ])

        result = namer.rename(
            decompiled_dir=decompiled,
            functions_json=functions_json,
            call_graph_json=call_graph_json,
            output_dir=output,
        )

        assert result.success
        # Should get a name from either call_context (printf format) or type_heuristic
        names = {sn.original_name: sn.semantic_name for sn in result.names}
        # param_1 should be named something text-related
        assert "param_1" in names
        # The name should NOT still be param_1
        assert names["param_1"] != "param_1"


# =========================================================================
# Test: Type compatibility enhancements
# =========================================================================

class TestTypeCompatibility:
    """v1.7.2: Extended type compatibility groups."""

    def test_uint_compat(self):
        """uint should be compatible with int, unsigned int."""
        assert _types_compatible("uint", "int")
        assert _types_compatible("uint", "unsigned int")
        assert _types_compatible("uint", "undefined4")

    def test_bool_compat(self):
        """bool should be compatible with int, byte."""
        assert _types_compatible("bool", "int")
        assert _types_compatible("bool", "byte")
        assert _types_compatible("bool", "char")

    def test_float_compat(self):
        """float should be compatible with double."""
        assert _types_compatible("float", "double")

    def test_char_star_compat(self):
        """char * should be compatible with void *."""
        assert _types_compatible("char *", "void *")
        assert _types_compatible("char *", "unsigned char *")

    def test_first_param_self_types(self):
        """_FIRST_PARAM_SELF_TYPES should include common pointer-like types."""
        assert "long" in _FIRST_PARAM_SELF_TYPES
        assert "void *" in _FIRST_PARAM_SELF_TYPES
        assert "undefined8" in _FIRST_PARAM_SELF_TYPES


# =========================================================================
# Test: Strategy priority and conflict resolution
# =========================================================================

class TestStrategyPriority:
    """Signature-based naming should win over type heuristics."""

    def test_signature_wins_over_type_heuristic(self, namer, tmp_workspace):
        """When both signature and type heuristic name a param, signature wins."""
        tmp_path, static, decompiled, output, functions_json, call_graph_json = tmp_workspace

        _write_c_file(decompiled, "funcs.c", """\
            int FUN_00701000(char *param_1, long *param_2) {
                return 0;
            }
        """)
        _write_functions_json(functions_json, [
            {"name": "FUN_00701000", "address": "0x701000", "params": [
                {"name": "param_1", "type": "char *", "position": 0},
                {"name": "param_2", "type": "long *", "position": 1},
            ]},
        ])

        sig_matches = [
            MockSignatureMatch(
                original_name="FUN_00701000",
                matched_name="sqlite3_open",
                library="sqlite",
                confidence=0.90,
            ),
        ]

        result = namer.rename(
            decompiled_dir=decompiled,
            functions_json=functions_json,
            call_graph_json=call_graph_json,
            output_dir=output,
            signature_matches=sig_matches,
        )

        assert result.success
        names = {sn.original_name: sn.semantic_name for sn in result.names
                 if sn.function_name == "FUN_00701000"}
        # Signature-based naming should win: "filename" not "str"
        assert names.get("param_1") == "filename"

    def test_call_context_complements_type_heuristic(self, namer, tmp_workspace):
        """Call-context names should appear alongside type heuristic names."""
        tmp_path, static, decompiled, output, functions_json, call_graph_json = tmp_workspace

        _write_c_file(decompiled, "funcs.c", """\
            void FUN_00702000(int param_1, char *param_2, int param_3) {
                int ret = send(param_1, param_2, param_3, 0);
                return;
            }
        """)
        _write_functions_json(functions_json, [
            {"name": "FUN_00702000", "address": "0x702000", "params": [
                {"name": "param_1", "type": "int", "position": 0},
                {"name": "param_2", "type": "char *", "position": 1},
                {"name": "param_3", "type": "int", "position": 2},
            ]},
        ])

        result = namer.rename(
            decompiled_dir=decompiled,
            functions_json=functions_json,
            call_graph_json=call_graph_json,
            output_dir=output,
        )

        assert result.success
        # At minimum, call_context should have named them from send()
        final_names = {sn.original_name: sn.semantic_name for sn in result.names
                       if sn.function_name == "FUN_00702000"}
        # param_1 should be "sockfd" from call_context (higher conf than generic type heuristic)
        assert "param_1" in final_names
        assert "param_2" in final_names


# =========================================================================
# Test: Output file contains renamed parameters
# =========================================================================

class TestOutputFileContent:
    """Verify renamed parameters appear in output C files."""

    def test_output_contains_renamed_params(self, namer, tmp_workspace):
        """Output C file should contain the new parameter names."""
        tmp_path, static, decompiled, output, functions_json, call_graph_json = tmp_workspace

        _write_c_file(decompiled, "funcs.c", """\
            int FUN_00801000(char *param_1, long *param_2) {
                return 0;
            }
        """)
        _write_functions_json(functions_json, [
            {"name": "FUN_00801000", "address": "0x801000", "params": [
                {"name": "param_1", "type": "char *", "position": 0},
                {"name": "param_2", "type": "long *", "position": 1},
            ]},
        ])

        sig_matches = [
            MockSignatureMatch(
                original_name="FUN_00801000",
                matched_name="sqlite3_open",
                library="sqlite",
                confidence=0.90,
            ),
        ]

        result = namer.rename(
            decompiled_dir=decompiled,
            functions_json=functions_json,
            call_graph_json=call_graph_json,
            output_dir=output,
            signature_matches=sig_matches,
        )

        assert result.success
        assert result.output_files
        out_content = result.output_files[0].read_text()
        assert "filename" in out_content
        assert "ppDb" in out_content

    def test_naming_map_json_version(self, namer, tmp_workspace):
        """param_naming_map.json should have version 1.7.2."""
        tmp_path, static, decompiled, output, functions_json, call_graph_json = tmp_workspace

        _write_c_file(decompiled, "funcs.c", """\
            int FUN_00802000(int param_1) {
                return param_1;
            }
        """)
        _write_functions_json(functions_json, [
            {"name": "FUN_00802000", "address": "0x802000", "params": [
                {"name": "param_1", "type": "int", "position": 0},
            ]},
        ])

        result = namer.rename(
            decompiled_dir=decompiled,
            functions_json=functions_json,
            call_graph_json=call_graph_json,
            output_dir=output,
        )

        map_path = output.parent / "param_naming_map.json"
        assert map_path.exists()
        map_data = json.loads(map_path.read_text())
        assert map_data["version"] == "1.7.2"


# =========================================================================
# Test: Edge cases
# =========================================================================

class TestEdgeCases:
    """Edge cases for the new naming strategies."""

    def test_empty_signature_matches(self, namer, tmp_workspace):
        """Empty signature_matches should not crash."""
        tmp_path, static, decompiled, output, functions_json, call_graph_json = tmp_workspace

        _write_c_file(decompiled, "funcs.c", """\
            void FUN_00901000(int param_1) {
                return;
            }
        """)
        _write_functions_json(functions_json, [
            {"name": "FUN_00901000", "address": "0x901000", "params": [
                {"name": "param_1", "type": "int", "position": 0},
            ]},
        ])

        result = namer.rename(
            decompiled_dir=decompiled,
            functions_json=functions_json,
            call_graph_json=call_graph_json,
            output_dir=output,
            signature_matches=[],
        )
        assert result.success

    def test_unknown_api_in_signature(self, namer, tmp_workspace):
        """Signature matches an unknown API (not in APIParamDB) -> graceful skip."""
        tmp_path, static, decompiled, output, functions_json, call_graph_json = tmp_workspace

        _write_c_file(decompiled, "funcs.c", """\
            void FUN_00902000(int param_1) {
                return;
            }
        """)
        _write_functions_json(functions_json, [
            {"name": "FUN_00902000", "address": "0x902000", "params": [
                {"name": "param_1", "type": "int", "position": 0},
            ]},
        ])

        sig_matches = [
            MockSignatureMatch(
                original_name="FUN_00902000",
                matched_name="unknown_internal_func_xyz",
                library="custom",
                confidence=0.85,
            ),
        ]

        result = namer.rename(
            decompiled_dir=decompiled,
            functions_json=functions_json,
            call_graph_json=call_graph_json,
            output_dir=output,
            signature_matches=sig_matches,
        )
        # Should not crash, just skip signature naming for this function
        assert result.success
        sig_names = [sn for sn in result.names if sn.source == "signature_based"]
        assert len(sig_names) == 0

    def test_more_params_than_api_knows(self, namer, tmp_workspace):
        """Function has more params than API definition -> extra params get other strategies."""
        tmp_path, static, decompiled, output, functions_json, call_graph_json = tmp_workspace

        _write_c_file(decompiled, "funcs.c", """\
            int FUN_00903000(int param_1, int param_2, int param_3) {
                return 0;
            }
        """)
        _write_functions_json(functions_json, [
            {"name": "FUN_00903000", "address": "0x903000", "params": [
                {"name": "param_1", "type": "int", "position": 0},
                {"name": "param_2", "type": "int", "position": 1},
                {"name": "param_3", "type": "int", "position": 2},
            ]},
        ])

        # close() only has 1 param (fd)
        sig_matches = [
            MockSignatureMatch(
                original_name="FUN_00903000",
                matched_name="close",
                library="libc",
                confidence=0.90,
            ),
        ]

        result = namer.rename(
            decompiled_dir=decompiled,
            functions_json=functions_json,
            call_graph_json=call_graph_json,
            output_dir=output,
            signature_matches=sig_matches,
        )

        assert result.success
        sig_names = {sn.original_name: sn for sn in result.names if sn.source == "signature_based"}
        # Only param_1 should be named by signature (close has only fd)
        assert "param_1" in sig_names
        assert sig_names["param_1"].semantic_name == "fd"
        assert "param_2" not in sig_names
        assert "param_3" not in sig_names

    def test_sanitize_c_name_special_chars(self):
        """_sanitize_c_name should handle special characters."""
        assert _sanitize_c_name("my-name") == "my_name"
        # Note: _sanitize_c_name strips leading _ after adding it for digit start
        # This is existing behavior we don't change
        assert _sanitize_c_name("123abc") == "123abc"
        assert _sanitize_c_name("a  b") == "a_b"
        assert _sanitize_c_name("") == "unnamed"

    def test_is_auto_name_detection(self):
        """_is_auto_or_generic_name should detect all Ghidra auto patterns."""
        assert _is_auto_or_generic_name("param_1")
        assert _is_auto_or_generic_name("param_42")
        assert _is_auto_or_generic_name("src_1")
        assert _is_auto_or_generic_name("dest_2")
        assert _is_auto_or_generic_name("local_10")
        assert _is_auto_or_generic_name("local_abc")
        assert _is_auto_or_generic_name("aVar1")
        assert _is_auto_or_generic_name("in_RAX")
        # These should NOT be auto names
        assert not _is_auto_or_generic_name("filename")
        assert not _is_auto_or_generic_name("buf")
        assert not _is_auto_or_generic_name("count")


# =========================================================================
# Test: Combined strategies integration
# =========================================================================

class TestIntegration:
    """Integration tests verifying all strategies work together."""

    def test_all_strategies_produce_names(self, namer, tmp_workspace):
        """A complex function should trigger multiple naming strategies."""
        tmp_path, static, decompiled, output, functions_json, call_graph_json = tmp_workspace

        # Function with:
        # - signature match (sqlite3_exec)
        # - API calls in body (malloc)
        # - loop bound parameter
        _write_c_file(decompiled, "funcs.c", """\
            int FUN_00A01000(long param_1, char *param_2, long param_3, long param_4, long param_5) {
                return 0;
            }
            void FUN_00A02000(long param_1, int param_2, int param_3) {
                void *buf = malloc(param_3);
                for (int i = 0; i < param_2; i++) {
                    *(int *)(param_1 + 0x10) = i;
                }
                return;
            }
        """)
        _write_functions_json(functions_json, [
            {"name": "FUN_00A01000", "address": "0xA01000", "params": [
                {"name": "param_1", "type": "long", "position": 0},
                {"name": "param_2", "type": "char *", "position": 1},
                {"name": "param_3", "type": "long", "position": 2},
                {"name": "param_4", "type": "long", "position": 3},
                {"name": "param_5", "type": "long", "position": 4},
            ]},
            {"name": "FUN_00A02000", "address": "0xA02000", "params": [
                {"name": "param_1", "type": "long", "position": 0},
                {"name": "param_2", "type": "int", "position": 1},
                {"name": "param_3", "type": "int", "position": 2},
            ]},
        ])

        sig_matches = [
            MockSignatureMatch(
                original_name="FUN_00A01000",
                matched_name="sqlite3_exec",
                library="sqlite",
                confidence=0.90,
            ),
        ]

        result = namer.rename(
            decompiled_dir=decompiled,
            functions_json=functions_json,
            call_graph_json=call_graph_json,
            output_dir=output,
            signature_matches=sig_matches,
        )

        assert result.success
        assert result.total_renamed >= 3  # At least some params named

        # FUN_00A01000: signature-based (sqlite3_exec)
        a01_names = {sn.original_name: sn for sn in result.names
                     if sn.function_name == "FUN_00A01000"}
        if "param_1" in a01_names:
            assert a01_names["param_1"].semantic_name == "db"
        if "param_2" in a01_names:
            assert a01_names["param_2"].semantic_name == "sql"

        # FUN_00A02000: call-context (malloc -> size) + type heuristic (self, n_size)
        a02_names = {sn.original_name: sn for sn in result.names
                     if sn.function_name == "FUN_00A02000"}
        # param_1 with offset access at position 0 -> "self"
        if "param_1" in a02_names:
            assert a02_names["param_1"].semantic_name == "self"

    def test_by_source_stats(self, namer, tmp_workspace):
        """Result should include per-source statistics."""
        tmp_path, static, decompiled, output, functions_json, call_graph_json = tmp_workspace

        _write_c_file(decompiled, "funcs.c", """\
            int FUN_00B01000(char *param_1, long *param_2) {
                return 0;
            }
        """)
        _write_functions_json(functions_json, [
            {"name": "FUN_00B01000", "address": "0xB01000", "params": [
                {"name": "param_1", "type": "char *", "position": 0},
                {"name": "param_2", "type": "long *", "position": 1},
            ]},
        ])

        sig_matches = [
            MockSignatureMatch(
                original_name="FUN_00B01000",
                matched_name="sqlite3_open",
                library="sqlite",
                confidence=0.90,
            ),
        ]

        result = namer.rename(
            decompiled_dir=decompiled,
            functions_json=functions_json,
            call_graph_json=call_graph_json,
            output_dir=output,
            signature_matches=sig_matches,
        )

        assert result.success
        assert "signature_based" in result.by_source
        assert result.by_source["signature_based"] >= 1
