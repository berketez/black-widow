"""Tests for DWARF debug info extractor -- ground truth name extraction.

Tests cover:
- DwarfVariable dataclass: field access, is_param flag
- DwarfFunction dataclass: params list, locals list, address, defaults
- DwarfExtractor.has_debug_info(): debug binary (True), non-debug (False), nonexistent
- DwarfExtractor.extract_functions(): empty result, graceful errors, timeout
- DwarfExtractor.to_ground_truth(): output format validation
- DwarfExtractor.to_signature_json(): Karadul sig DB format compatibility
- Edge cases: missing binary, missing dwarfdump, timeout, empty output
- Parsing: _parse_lines with real dwarfdump output samples, nested DIEs, lexical blocks
- Helper functions: _strip_quotes, _parse_hex, _parse_int, _extract_type_name
"""

from __future__ import annotations

import subprocess
import textwrap
from pathlib import Path
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

from karadul.analyzers.dwarf_extractor import (
    DwarfExtractor,
    DwarfFunction,
    DwarfVariable,
    _ChildParseState,
    _extract_type_name,
    _FuncParseState,
    _parse_hex,
    _parse_int,
    _strip_quotes,
)


# ======================================================================
# Sample dwarfdump output fragments
# ======================================================================

# Minimal dwarfdump output with one function, one param, one local
SAMPLE_DWARFDUMP_SIMPLE = textwrap.dedent("""\
    /tmp/test: file format Mach-O 64-bit x86-64

    .debug_info contents:
    0x0000000b: DW_TAG_compile_unit
                  DW_AT_name	("/tmp/test.c")

    0x0000002d:   DW_TAG_subprogram
                    DW_AT_name	("calculate")
                    DW_AT_low_pc	(0x0000000100003f60)
                    DW_AT_type	(0x000000f0 "int")
                    DW_AT_decl_file	("/tmp/test.c")
                    DW_AT_decl_line	(10)

    0x00000045:     DW_TAG_formal_parameter
                      DW_AT_name	("count")
                      DW_AT_type	(0x000000f0 "int")

    0x00000055:     DW_TAG_variable
                      DW_AT_name	("result")
                      DW_AT_type	(0x000000f4 "long")

                    NULL
""")

# dwarfdump output with multiple functions
SAMPLE_DWARFDUMP_MULTI = textwrap.dedent("""\
    /tmp/multi: file format Mach-O 64-bit x86-64

    .debug_info contents:

    0x0000002d:   DW_TAG_subprogram
                    DW_AT_name	("init_buffer")
                    DW_AT_low_pc	(0x0000000100001000)
                    DW_AT_type	(0x000000f4 "void")
                    DW_AT_decl_file	("/src/buffer.c")
                    DW_AT_decl_line	(5)

    0x00000045:     DW_TAG_formal_parameter
                      DW_AT_name	("buf")
                      DW_AT_type	(0x00000100 "char *")

    0x00000055:     DW_TAG_formal_parameter
                      DW_AT_name	("size")
                      DW_AT_type	(0x000000f0 "int")

                    NULL

    0x0000006d:   DW_TAG_subprogram
                    DW_AT_name	("process_data")
                    DW_AT_low_pc	(0x0000000100002000)
                    DW_AT_type	(0x000000f0 "int")
                    DW_AT_decl_file	("/src/process.c")
                    DW_AT_decl_line	(42)

    0x00000085:     DW_TAG_formal_parameter
                      DW_AT_name	("data")
                      DW_AT_type	(0x00000110 "void *")

    0x00000095:     DW_TAG_formal_parameter
                      DW_AT_name	("length")
                      DW_AT_type	(0x000000f0 "int")

    0x000000a5:     DW_TAG_variable
                      DW_AT_name	("status")
                      DW_AT_type	(0x000000f0 "int")

    0x000000b5:     DW_TAG_variable
                      DW_AT_name	("offset")
                      DW_AT_type	(0x000000f8 "size_t")

                    NULL
""")

# dwarfdump output with lexical block (nested scope)
SAMPLE_DWARFDUMP_LEXICAL_BLOCK = textwrap.dedent("""\
    0x0000002d:   DW_TAG_subprogram
                    DW_AT_name	("outer_func")
                    DW_AT_low_pc	(0x0000000100003000)
                    DW_AT_type	(0x000000f0 "int")
                    DW_AT_decl_file	("/src/scope.c")
                    DW_AT_decl_line	(1)

    0x00000045:     DW_TAG_formal_parameter
                      DW_AT_name	("input")
                      DW_AT_type	(0x000000f0 "int")

    0x00000055:     DW_TAG_variable
                      DW_AT_name	("total")
                      DW_AT_type	(0x000000f0 "int")

    0x00000065:     DW_TAG_lexical_block
                      DW_AT_low_pc	(0x0000000100003100)
                      DW_AT_high_pc	(0x0000000100003200)

    0x00000075:       DW_TAG_variable
                        DW_AT_name	("temp")
                        DW_AT_type	(0x000000f0 "int")

                      NULL

                    NULL
""")

# dwarfdump output with no DW_TAG_ lines (no debug info)
SAMPLE_DWARFDUMP_NO_DEBUG = textwrap.dedent("""\
    /tmp/stripped: file format Mach-O 64-bit x86-64

    .debug_info contents:
""")

# Unnamed subprogram (compiler-generated, should be skipped)
SAMPLE_DWARFDUMP_UNNAMED = textwrap.dedent("""\
    0x0000002d:   DW_TAG_subprogram
                    DW_AT_low_pc	(0x0000000100005000)

    0x00000045:     DW_TAG_formal_parameter
                      DW_AT_name	("x")
                      DW_AT_type	(0x000000f0 "int")

                    NULL

    0x0000006d:   DW_TAG_subprogram
                    DW_AT_name	("real_func")
                    DW_AT_low_pc	(0x0000000100006000)
                    DW_AT_type	(0x000000f0 "int")

                    NULL
""")

# Nameless child variable (should be skipped)
SAMPLE_DWARFDUMP_NAMELESS_CHILD = textwrap.dedent("""\
    0x0000002d:   DW_TAG_subprogram
                    DW_AT_name	("func_with_anon_param")
                    DW_AT_low_pc	(0x0000000100007000)

    0x00000045:     DW_TAG_formal_parameter
                      DW_AT_type	(0x000000f0 "int")

    0x00000055:     DW_TAG_formal_parameter
                      DW_AT_name	("named_param")
                      DW_AT_type	(0x000000f0 "int")

                    NULL
""")


# ======================================================================
# DwarfVariable dataclass tests
# ======================================================================

class TestDwarfVariable:
    """DwarfVariable dataclass field access and is_param flag."""

    def test_basic_construction(self):
        v = DwarfVariable(name="count", type_name="int", is_param=True)
        assert v.name == "count"
        assert v.type_name == "int"
        assert v.is_param is True

    def test_local_variable(self):
        v = DwarfVariable(name="result", type_name="long", is_param=False)
        assert v.name == "result"
        assert v.is_param is False

    def test_pointer_type(self):
        v = DwarfVariable(name="buffer", type_name="char *", is_param=True)
        assert v.type_name == "char *"

    def test_struct_type(self):
        v = DwarfVariable(name="st", type_name="struct stat", is_param=False)
        assert v.type_name == "struct stat"

    def test_equality(self):
        """Dataclass equality -- same fields means equal."""
        v1 = DwarfVariable(name="x", type_name="int", is_param=True)
        v2 = DwarfVariable(name="x", type_name="int", is_param=True)
        assert v1 == v2

    def test_inequality_different_is_param(self):
        v1 = DwarfVariable(name="x", type_name="int", is_param=True)
        v2 = DwarfVariable(name="x", type_name="int", is_param=False)
        assert v1 != v2


# ======================================================================
# DwarfFunction dataclass tests
# ======================================================================

class TestDwarfFunction:
    """DwarfFunction dataclass field access, params, locals, defaults."""

    def test_basic_construction(self):
        f = DwarfFunction(name="calculate", address=0x100003f60)
        assert f.name == "calculate"
        assert f.address == 0x100003f60
        assert f.params == []
        assert f.locals == []
        assert f.return_type == ""
        assert f.source_file == ""
        assert f.line_number == 0

    def test_with_params_and_locals(self):
        p1 = DwarfVariable(name="count", type_name="int", is_param=True)
        p2 = DwarfVariable(name="buffer", type_name="char *", is_param=True)
        loc = DwarfVariable(name="result", type_name="long", is_param=False)
        f = DwarfFunction(
            name="process",
            address=0x1000,
            params=[p1, p2],
            locals=[loc],
            return_type="int",
            source_file="/src/main.c",
            line_number=42,
        )
        assert len(f.params) == 2
        assert f.params[0].name == "count"
        assert f.params[1].name == "buffer"
        assert len(f.locals) == 1
        assert f.locals[0].name == "result"
        assert f.return_type == "int"
        assert f.source_file == "/src/main.c"
        assert f.line_number == 42

    def test_default_lists_are_independent(self):
        """Each instance must have its own list, not shared default."""
        f1 = DwarfFunction(name="a", address=0)
        f2 = DwarfFunction(name="b", address=0)
        f1.params.append(DwarfVariable("x", "int", True))
        assert len(f2.params) == 0

    def test_address_zero(self):
        f = DwarfFunction(name="start", address=0)
        assert f.address == 0


# ======================================================================
# _FuncParseState tests
# ======================================================================

class TestFuncParseState:
    """Internal parse state -> DwarfFunction conversion."""

    def test_to_dwarf_function_with_name(self):
        state = _FuncParseState()
        state.name = "test_func"
        state.address = 0x1000
        state.return_type = "int"
        state.source_file = "/tmp/test.c"
        state.line_number = 10
        func = state.to_dwarf_function()
        assert func is not None
        assert func.name == "test_func"
        assert func.address == 0x1000

    def test_to_dwarf_function_no_name_returns_none(self):
        """Unnamed subprograms (compiler-generated) must return None."""
        state = _FuncParseState()
        state.address = 0x5000
        assert state.to_dwarf_function() is None

    def test_to_dwarf_function_copies_params(self):
        """Returned DwarfFunction must have copies of param/local lists."""
        state = _FuncParseState()
        state.name = "f"
        p = DwarfVariable("x", "int", True)
        state.params.append(p)
        func = state.to_dwarf_function()
        assert func is not None
        # Mutation of state should not affect the returned function
        state.params.append(DwarfVariable("y", "int", True))
        assert len(func.params) == 1


# ======================================================================
# _ChildParseState tests
# ======================================================================

class TestChildParseState:
    """Internal child parse state."""

    def test_param_state(self):
        state = _ChildParseState(is_param=True)
        assert state.is_param is True
        assert state.name == ""
        assert state.type_name == ""

    def test_local_state(self):
        state = _ChildParseState(is_param=False)
        assert state.is_param is False


# ======================================================================
# Helper function tests
# ======================================================================

class TestStripQuotes:
    def test_quoted_string(self):
        assert _strip_quotes('"calculate"') == "calculate"

    def test_quoted_path(self):
        assert _strip_quotes('"/tmp/test.c"') == "/tmp/test.c"

    def test_no_quotes(self):
        assert _strip_quotes("plain_value") == "plain_value"

    def test_single_quotes_not_stripped(self):
        assert _strip_quotes("'single'") == "'single'"

    def test_whitespace_around_quotes(self):
        assert _strip_quotes('  "padded"  ') == "padded"

    def test_empty_quoted_string(self):
        assert _strip_quotes('""') == ""

    def test_empty_string(self):
        assert _strip_quotes("") == ""


class TestParseHex:
    def test_simple_hex(self):
        assert _parse_hex("0x0000000100003f60") == 0x100003f60

    def test_hex_with_suffix(self):
        """dwarfdump sometimes appends '(relocated)' after hex."""
        assert _parse_hex("0x100 (relocated)") == 0x100

    def test_zero(self):
        assert _parse_hex("0x0") == 0

    def test_no_hex(self):
        assert _parse_hex("not_a_hex") == 0

    def test_whitespace(self):
        assert _parse_hex("  0xDEAD  ") == 0xDEAD

    def test_large_address(self):
        assert _parse_hex("0xFFFFFFFFFFFFFFFF") == 0xFFFFFFFFFFFFFFFF


class TestParseInt:
    def test_simple_int(self):
        assert _parse_int("42") == 42

    def test_zero(self):
        assert _parse_int("0") == 0

    def test_invalid_returns_zero(self):
        assert _parse_int("not_a_number") == 0

    def test_whitespace(self):
        assert _parse_int("  10  ") == 10

    def test_negative(self):
        assert _parse_int("-5") == -5

    def test_empty_returns_zero(self):
        assert _parse_int("") == 0


class TestExtractTypeName:
    def test_standard_type(self):
        assert _extract_type_name('0x000000f0 "int"') == "int"

    def test_pointer_type(self):
        assert _extract_type_name('0x00000100 "char *"') == "char *"

    def test_struct_type(self):
        assert _extract_type_name('0x000000fe "Point"') == "Point"

    def test_no_quotes_returns_stripped(self):
        assert _extract_type_name("0x000000f0") == "0x000000f0"

    def test_complex_type(self):
        assert _extract_type_name('0x00000200 "const char *"') == "const char *"

    def test_empty_quoted(self):
        assert _extract_type_name('0x00000100 ""') == ""


# ======================================================================
# DwarfExtractor construction and _resolve_dwarf_target
# ======================================================================

class TestDwarfExtractorInit:
    """DwarfExtractor initialization and target resolution."""

    def test_nonexistent_binary(self, tmp_path):
        """Nonexistent binary -> _dwarf_target is None."""
        ext = DwarfExtractor(tmp_path / "does_not_exist")
        assert ext._dwarf_target is None

    def test_existing_binary_no_dsym(self, tmp_path):
        """Existing binary without .dSYM -> target is the binary itself."""
        binary = tmp_path / "test_bin"
        binary.write_bytes(b"\x00" * 64)
        ext = DwarfExtractor(binary)
        assert ext._dwarf_target == binary

    def test_dsym_bundle_preferred(self, tmp_path):
        """If .dSYM dir exists, it takes precedence over binary."""
        binary = tmp_path / "test_bin"
        binary.write_bytes(b"\x00" * 64)
        dsym = tmp_path / "test_bin.dSYM"
        dsym.mkdir()
        ext = DwarfExtractor(binary)
        assert ext._dwarf_target == dsym

    def test_dsym_file_not_dir_ignored(self, tmp_path):
        """If .dSYM exists but is a file (not directory), use binary."""
        binary = tmp_path / "test_bin"
        binary.write_bytes(b"\x00" * 64)
        dsym = tmp_path / "test_bin.dSYM"
        dsym.write_text("not a real dSYM")  # file, not dir
        ext = DwarfExtractor(binary)
        assert ext._dwarf_target == binary

    def test_timeout_default(self, tmp_path):
        binary = tmp_path / "test_bin"
        binary.write_bytes(b"\x00")
        ext = DwarfExtractor(binary)
        assert ext.timeout == 30

    def test_timeout_custom(self, tmp_path):
        binary = tmp_path / "test_bin"
        binary.write_bytes(b"\x00")
        ext = DwarfExtractor(binary, timeout=120)
        assert ext.timeout == 120

    def test_path_converted_to_pathlib(self, tmp_path):
        """String path should be converted to Path."""
        binary = tmp_path / "test_bin"
        binary.write_bytes(b"\x00")
        ext = DwarfExtractor(str(binary))
        assert isinstance(ext.binary_path, Path)


# ======================================================================
# DwarfExtractor.has_debug_info() tests
# ======================================================================

class TestHasDebugInfo:
    """DwarfExtractor.has_debug_info() with mocked subprocess."""

    def test_has_debug_true(self, tmp_path):
        """Binary with DW_TAG_ lines -> True."""
        binary = tmp_path / "debug_bin"
        binary.write_bytes(b"\x00" * 64)

        with patch("karadul.analyzers.dwarf_extractor.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout=SAMPLE_DWARFDUMP_SIMPLE,
            )
            ext = DwarfExtractor(binary)
            assert ext.has_debug_info() is True

    def test_has_debug_false_no_tags(self, tmp_path):
        """Binary with no DW_TAG_ in output -> False."""
        binary = tmp_path / "stripped_bin"
        binary.write_bytes(b"\x00" * 64)

        with patch("karadul.analyzers.dwarf_extractor.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout=SAMPLE_DWARFDUMP_NO_DEBUG,
            )
            ext = DwarfExtractor(binary)
            assert ext.has_debug_info() is False

    def test_has_debug_false_nonexistent(self, tmp_path):
        """Nonexistent binary -> False (target is None)."""
        ext = DwarfExtractor(tmp_path / "ghost")
        assert ext.has_debug_info() is False

    def test_has_debug_false_dwarfdump_not_found(self, tmp_path):
        """dwarfdump not installed -> False."""
        binary = tmp_path / "bin"
        binary.write_bytes(b"\x00" * 64)

        with patch("karadul.analyzers.dwarf_extractor.subprocess.run") as mock_run:
            mock_run.side_effect = FileNotFoundError("dwarfdump not found")
            ext = DwarfExtractor(binary)
            assert ext.has_debug_info() is False

    def test_has_debug_false_timeout(self, tmp_path):
        """dwarfdump timeout -> False."""
        binary = tmp_path / "huge_bin"
        binary.write_bytes(b"\x00" * 64)

        with patch("karadul.analyzers.dwarf_extractor.subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.TimeoutExpired(cmd="dwarfdump", timeout=10)
            ext = DwarfExtractor(binary)
            assert ext.has_debug_info() is False

    def test_has_debug_false_nonzero_return(self, tmp_path):
        """dwarfdump returns nonzero -> False."""
        binary = tmp_path / "bad_bin"
        binary.write_bytes(b"\x00" * 64)

        with patch("karadul.analyzers.dwarf_extractor.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="")
            ext = DwarfExtractor(binary)
            assert ext.has_debug_info() is False


# ======================================================================
# DwarfExtractor._parse_lines() tests -- core parser
# ======================================================================

class TestParseLines:
    """Direct testing of the incremental DWARF parser with sample outputs."""

    def _parse(self, text: str) -> list[DwarfFunction]:
        """Helper: create a dummy extractor and parse lines from text."""
        # We bypass __init__ to avoid needing a real binary path
        ext = object.__new__(DwarfExtractor)
        ext.binary_path = Path("/dummy")
        ext.timeout = 30
        ext._dwarf_target = Path("/dummy")
        return list(ext._parse_lines(iter(text.splitlines())))

    def test_simple_function(self):
        funcs = self._parse(SAMPLE_DWARFDUMP_SIMPLE)
        assert len(funcs) == 1
        f = funcs[0]
        assert f.name == "calculate"
        assert f.address == 0x100003f60
        assert f.return_type == "int"
        assert f.source_file == "/tmp/test.c"
        assert f.line_number == 10
        assert len(f.params) == 1
        assert f.params[0].name == "count"
        assert f.params[0].type_name == "int"
        assert f.params[0].is_param is True
        assert len(f.locals) == 1
        assert f.locals[0].name == "result"
        assert f.locals[0].type_name == "long"
        assert f.locals[0].is_param is False

    def test_multiple_functions(self):
        funcs = self._parse(SAMPLE_DWARFDUMP_MULTI)
        assert len(funcs) == 2

        # First function: init_buffer
        f0 = funcs[0]
        assert f0.name == "init_buffer"
        assert f0.address == 0x100001000
        assert f0.return_type == "void"
        assert f0.source_file == "/src/buffer.c"
        assert f0.line_number == 5
        assert len(f0.params) == 2
        assert f0.params[0].name == "buf"
        assert f0.params[0].type_name == "char *"
        assert f0.params[1].name == "size"
        assert len(f0.locals) == 0

        # Second function: process_data
        f1 = funcs[1]
        assert f1.name == "process_data"
        assert f1.address == 0x100002000
        assert len(f1.params) == 2
        assert f1.params[0].name == "data"
        assert f1.params[1].name == "length"
        assert len(f1.locals) == 2
        assert f1.locals[0].name == "status"
        assert f1.locals[1].name == "offset"
        assert f1.locals[1].type_name == "size_t"

    def test_lexical_block_attributes_not_applied_to_function(self):
        """DW_AT_low_pc inside DW_TAG_lexical_block must NOT overwrite function address.

        Variables inside lexical blocks ARE collected as locals -- they are
        still local variables of the enclosing function. The parser only
        ignores the block's own attributes (DW_AT_low_pc, DW_AT_high_pc)
        to protect the function's address.
        """
        funcs = self._parse(SAMPLE_DWARFDUMP_LEXICAL_BLOCK)
        assert len(funcs) == 1
        f = funcs[0]
        assert f.name == "outer_func"
        # Address should be the function's, not the lexical block's
        assert f.address == 0x100003000
        assert len(f.params) == 1
        assert f.params[0].name == "input"
        # 2 locals: "total" at function scope + "temp" inside lexical block
        assert len(f.locals) == 2
        assert f.locals[0].name == "total"
        assert f.locals[1].name == "temp"

    def test_unnamed_subprogram_skipped(self):
        """Subprogram without DW_AT_name is skipped."""
        funcs = self._parse(SAMPLE_DWARFDUMP_UNNAMED)
        assert len(funcs) == 1
        assert funcs[0].name == "real_func"
        assert funcs[0].address == 0x100006000

    def test_nameless_child_skipped(self):
        """Parameter/variable without DW_AT_name is skipped."""
        funcs = self._parse(SAMPLE_DWARFDUMP_NAMELESS_CHILD)
        assert len(funcs) == 1
        f = funcs[0]
        # Only the named parameter should be present
        assert len(f.params) == 1
        assert f.params[0].name == "named_param"

    def test_empty_input(self):
        """Empty input -> no functions."""
        funcs = self._parse("")
        assert funcs == []

    def test_header_only_no_functions(self):
        """Only header lines, no actual DIEs."""
        text = textwrap.dedent("""\
            /tmp/test: file format Mach-O 64-bit x86-64

            .debug_info contents:
        """)
        funcs = self._parse(text)
        assert funcs == []

    def test_function_without_type_info(self):
        """Function with name and address but no type/file/line."""
        text = textwrap.dedent("""\
            0x0000002d:   DW_TAG_subprogram
                            DW_AT_name	("bare_func")
                            DW_AT_low_pc	(0x0000000100009000)

                          NULL
        """)
        funcs = self._parse(text)
        assert len(funcs) == 1
        assert funcs[0].name == "bare_func"
        assert funcs[0].return_type == ""
        assert funcs[0].source_file == ""
        assert funcs[0].line_number == 0

    def test_consecutive_subprograms_without_null(self):
        """Back-to-back subprogram tags without NULL in between."""
        text = textwrap.dedent("""\
            0x0000002d:   DW_TAG_subprogram
                            DW_AT_name	("func_a")
                            DW_AT_low_pc	(0x0000000100001000)

            0x0000004d:   DW_TAG_subprogram
                            DW_AT_name	("func_b")
                            DW_AT_low_pc	(0x0000000100002000)

                          NULL
        """)
        funcs = self._parse(text)
        assert len(funcs) == 2
        assert funcs[0].name == "func_a"
        assert funcs[1].name == "func_b"

    def test_child_type_unknown_when_missing(self):
        """Parameter without DW_AT_type gets '<unknown>' type."""
        text = textwrap.dedent("""\
            0x0000002d:   DW_TAG_subprogram
                            DW_AT_name	("func_missing_type")
                            DW_AT_low_pc	(0x0000000100001000)

            0x00000045:     DW_TAG_formal_parameter
                              DW_AT_name	("mystery_param")

                            NULL
        """)
        funcs = self._parse(text)
        assert len(funcs) == 1
        assert funcs[0].params[0].type_name == "<unknown>"

    def test_many_params_order_preserved(self):
        """Parameter order must match dwarfdump output order."""
        lines = ['0x0000002d:   DW_TAG_subprogram']
        lines.append('                DW_AT_name\t("many_params")')
        lines.append('                DW_AT_low_pc\t(0x0000000100001000)')
        lines.append('')
        param_names = ["alpha", "beta", "gamma", "delta", "epsilon"]
        for i, name in enumerate(param_names):
            offset = 0x45 + i * 0x10
            lines.append(f'0x{offset:08x}:     DW_TAG_formal_parameter')
            lines.append(f'                      DW_AT_name\t("{name}")')
            lines.append(f'                      DW_AT_type\t(0x000000f0 "int")')
            lines.append('')
        lines.append('                    NULL')
        text = "\n".join(lines)
        funcs = self._parse(text)
        assert len(funcs) == 1
        assert [p.name for p in funcs[0].params] == param_names


# ======================================================================
# DwarfExtractor.extract_functions() tests
# ======================================================================

class TestExtractFunctions:
    """extract_functions() with mocked subprocess."""

    def _make_extractor(self, tmp_path: Path) -> DwarfExtractor:
        binary = tmp_path / "test_bin"
        binary.write_bytes(b"\x00" * 64)
        return DwarfExtractor(binary)

    def test_extract_empty_for_none_target(self, tmp_path):
        """Nonexistent binary -> empty list."""
        ext = DwarfExtractor(tmp_path / "no_such_binary")
        assert ext.extract_functions() == []

    def test_extract_dwarfdump_not_found(self, tmp_path):
        """FileNotFoundError from subprocess -> empty list."""
        ext = self._make_extractor(tmp_path)
        with patch("karadul.analyzers.dwarf_extractor.subprocess.Popen") as mock_popen:
            mock_popen.side_effect = FileNotFoundError("dwarfdump not found")
            result = ext.extract_functions()
            assert result == []

    def test_extract_timeout_returns_partial(self, tmp_path):
        """TimeoutExpired -> return whatever was parsed so far."""
        ext = self._make_extractor(tmp_path)
        with patch("karadul.analyzers.dwarf_extractor.subprocess.Popen") as mock_popen:
            mock_popen.side_effect = subprocess.TimeoutExpired(
                cmd="dwarfdump", timeout=30
            )
            result = ext.extract_functions()
            assert isinstance(result, list)

    def test_extract_normal_output(self, tmp_path):
        """Successful dwarfdump -> parsed functions."""
        ext = self._make_extractor(tmp_path)

        mock_proc = MagicMock()
        mock_proc.stdout = iter(SAMPLE_DWARFDUMP_SIMPLE.splitlines(keepends=True))
        mock_proc.stderr = MagicMock()
        mock_proc.wait.return_value = 0
        # v1.10.0 HIGH-5 fix: Popen artik `with` context manager; mock'un
        # __enter__ kendisini dondurmeli (gercek Popen.__enter__ self doner).
        mock_proc.__enter__.return_value = mock_proc
        mock_proc.__exit__.return_value = False

        with patch("karadul.analyzers.dwarf_extractor.subprocess.Popen", return_value=mock_proc):
            result = ext.extract_functions()
            assert len(result) == 1
            assert result[0].name == "calculate"


# ======================================================================
# DwarfExtractor.to_ground_truth() tests
# ======================================================================

class TestToGroundTruth:
    """to_ground_truth() output format validation."""

    def _make_extractor_with_mock(self, tmp_path: Path, dwarfdump_output: str):
        binary = tmp_path / "gt_bin"
        binary.write_bytes(b"\x00" * 64)
        ext = DwarfExtractor(binary)

        mock_proc = MagicMock()
        mock_proc.stdout = iter(dwarfdump_output.splitlines(keepends=True))
        mock_proc.stderr = MagicMock()
        mock_proc.wait.return_value = 0
        # v1.10.0 HIGH-5 fix: Popen artik `with` context manager; mock'un
        # __enter__ kendisini dondurmeli (gercek Popen.__enter__ self doner).
        mock_proc.__enter__.return_value = mock_proc
        mock_proc.__exit__.return_value = False
        return ext, mock_proc

    def test_ground_truth_format(self, tmp_path):
        ext, mock_proc = self._make_extractor_with_mock(tmp_path, SAMPLE_DWARFDUMP_SIMPLE)

        with patch("karadul.analyzers.dwarf_extractor.subprocess.Popen", return_value=mock_proc):
            gt = ext.to_ground_truth()

        assert "calculate" in gt
        entry = gt["calculate"]
        # Address should be hex string
        assert entry["address"].startswith("0x")
        # Params dict with integer keys
        assert 0 in entry["params"]
        assert entry["params"][0] == "count"
        # Locals dict with name keys
        assert "result" in entry["locals"]
        assert entry["locals"]["result"]["type"] == "long"
        # Return type
        assert entry["return_type"] == "int"
        # Source file
        assert entry["source_file"] == "/tmp/test.c"
        # Line number
        assert entry["line_number"] == 10

    def test_ground_truth_multiple_funcs(self, tmp_path):
        ext, mock_proc = self._make_extractor_with_mock(tmp_path, SAMPLE_DWARFDUMP_MULTI)

        with patch("karadul.analyzers.dwarf_extractor.subprocess.Popen", return_value=mock_proc):
            gt = ext.to_ground_truth()

        assert len(gt) == 2
        assert "init_buffer" in gt
        assert "process_data" in gt
        # init_buffer has 2 params, 0 locals
        assert len(gt["init_buffer"]["params"]) == 2
        assert len(gt["init_buffer"]["locals"]) == 0
        # process_data has 2 params, 2 locals
        assert len(gt["process_data"]["params"]) == 2
        assert len(gt["process_data"]["locals"]) == 2

    def test_ground_truth_empty_on_no_debug(self, tmp_path):
        ext = DwarfExtractor(tmp_path / "no_exist")
        gt = ext.to_ground_truth()
        assert gt == {}

    def test_ground_truth_address_zero(self, tmp_path):
        """Function with address=0 should render as '0x0'."""
        text = textwrap.dedent("""\
            0x0000002d:   DW_TAG_subprogram
                            DW_AT_name	("zero_addr_func")

                          NULL
        """)
        ext, mock_proc = self._make_extractor_with_mock(tmp_path, text)
        with patch("karadul.analyzers.dwarf_extractor.subprocess.Popen", return_value=mock_proc):
            gt = ext.to_ground_truth()
        assert gt["zero_addr_func"]["address"] == "0x0"


# ======================================================================
# DwarfExtractor.to_signature_json() tests
# ======================================================================

class TestToSignatureJson:
    """to_signature_json() Karadul sig DB format validation."""

    def _make_extractor_with_mock(self, tmp_path: Path, dwarfdump_output: str, name: str = "test_lib"):
        binary = tmp_path / name
        binary.write_bytes(b"\x00" * 64)
        ext = DwarfExtractor(binary)

        mock_proc = MagicMock()
        mock_proc.stdout = iter(dwarfdump_output.splitlines(keepends=True))
        mock_proc.stderr = MagicMock()
        mock_proc.wait.return_value = 0
        # v1.10.0 HIGH-5 fix: Popen artik `with` context manager; mock'un
        # __enter__ kendisini dondurmeli (gercek Popen.__enter__ self doner).
        mock_proc.__enter__.return_value = mock_proc
        mock_proc.__exit__.return_value = False
        return ext, mock_proc

    def test_signature_json_top_level_keys(self, tmp_path):
        ext, mock_proc = self._make_extractor_with_mock(tmp_path, SAMPLE_DWARFDUMP_SIMPLE)

        with patch("karadul.analyzers.dwarf_extractor.subprocess.Popen", return_value=mock_proc):
            sig = ext.to_signature_json(lib_name="mylib")

        assert sig["library"] == "mylib"
        assert sig["source"] == "dwarf"
        assert sig["binary"] == str(ext.binary_path)
        assert sig["function_count"] == 1
        assert "functions" in sig

    def test_signature_json_function_format(self, tmp_path):
        ext, mock_proc = self._make_extractor_with_mock(tmp_path, SAMPLE_DWARFDUMP_SIMPLE)

        with patch("karadul.analyzers.dwarf_extractor.subprocess.Popen", return_value=mock_proc):
            sig = ext.to_signature_json()

        func = sig["functions"]["calculate"]
        assert func["address"].startswith("0x")
        assert func["return_type"] == "int"
        assert func["source_file"] == "/tmp/test.c"
        assert func["line_number"] == 10
        # params must be list of dicts
        assert isinstance(func["params"], list)
        assert len(func["params"]) == 1
        assert func["params"][0] == {"name": "count", "type": "int"}
        # locals must be list of dicts
        assert isinstance(func["locals"], list)
        assert len(func["locals"]) == 1
        assert func["locals"][0] == {"name": "result", "type": "long"}

    def test_signature_json_default_lib_name(self, tmp_path):
        """When lib_name not provided, should use binary stem."""
        ext, mock_proc = self._make_extractor_with_mock(
            tmp_path, SAMPLE_DWARFDUMP_SIMPLE, name="libcrypto"
        )
        with patch("karadul.analyzers.dwarf_extractor.subprocess.Popen", return_value=mock_proc):
            sig = ext.to_signature_json()
        assert sig["library"] == "libcrypto"

    def test_signature_json_multi_function(self, tmp_path):
        ext, mock_proc = self._make_extractor_with_mock(tmp_path, SAMPLE_DWARFDUMP_MULTI)

        with patch("karadul.analyzers.dwarf_extractor.subprocess.Popen", return_value=mock_proc):
            sig = ext.to_signature_json(lib_name="buffer_lib")

        assert sig["function_count"] == 2
        assert "init_buffer" in sig["functions"]
        assert "process_data" in sig["functions"]
        # init_buffer: 2 params, 0 locals
        assert len(sig["functions"]["init_buffer"]["params"]) == 2
        assert len(sig["functions"]["init_buffer"]["locals"]) == 0
        # process_data: 2 params, 2 locals
        pd = sig["functions"]["process_data"]
        assert pd["params"][0]["name"] == "data"
        assert pd["params"][1]["name"] == "length"
        assert pd["locals"][0]["name"] == "status"
        assert pd["locals"][1]["name"] == "offset"
        assert pd["locals"][1]["type"] == "size_t"

    def test_signature_json_empty_for_nonexistent(self, tmp_path):
        ext = DwarfExtractor(tmp_path / "nope")
        sig = ext.to_signature_json(lib_name="ghost")
        assert sig["function_count"] == 0
        assert sig["functions"] == {}
        assert sig["library"] == "ghost"
        assert sig["source"] == "dwarf"


# ======================================================================
# Edge cases
# ======================================================================

class TestEdgeCases:
    """Edge cases: missing binary, dwarfdump unavailable, timeout, etc."""

    def test_binary_path_as_string(self, tmp_path):
        """String path should work, not just Path objects."""
        binary = tmp_path / "str_path_bin"
        binary.write_bytes(b"\x00" * 64)
        ext = DwarfExtractor(str(binary))
        assert ext.binary_path == binary

    def test_extract_functions_on_nonexistent_binary(self, tmp_path):
        ext = DwarfExtractor(tmp_path / "vanished")
        assert ext.extract_functions() == []

    def test_to_ground_truth_on_nonexistent_binary(self, tmp_path):
        ext = DwarfExtractor(tmp_path / "vanished")
        assert ext.to_ground_truth() == {}

    def test_to_signature_json_on_nonexistent_binary(self, tmp_path):
        ext = DwarfExtractor(tmp_path / "vanished")
        sig = ext.to_signature_json()
        assert sig["function_count"] == 0

    def test_dwarfdump_empty_stdout(self, tmp_path):
        """dwarfdump returns empty stdout (success but no output)."""
        binary = tmp_path / "empty_out"
        binary.write_bytes(b"\x00" * 64)
        ext = DwarfExtractor(binary)

        mock_proc = MagicMock()
        mock_proc.stdout = iter([])
        mock_proc.stderr = MagicMock()
        mock_proc.wait.return_value = 0
        # v1.10.0 HIGH-5 fix: Popen artik `with` context manager; mock'un
        # __enter__ kendisini dondurmeli (gercek Popen.__enter__ self doner).
        mock_proc.__enter__.return_value = mock_proc
        mock_proc.__exit__.return_value = False

        with patch("karadul.analyzers.dwarf_extractor.subprocess.Popen", return_value=mock_proc):
            result = ext.extract_functions()
        assert result == []

    def test_dwarfdump_garbage_output(self, tmp_path):
        """dwarfdump produces non-standard garbage output."""
        binary = tmp_path / "garbage"
        binary.write_bytes(b"\x00" * 64)
        ext = DwarfExtractor(binary)

        garbage_lines = [
            "random nonsense line\n",
            "more garbage: {[()]}\n",
            "ERROR: something went wrong\n",
            "\n",
            "  \t  \n",
        ]
        mock_proc = MagicMock()
        mock_proc.stdout = iter(garbage_lines)
        mock_proc.stderr = MagicMock()
        mock_proc.wait.return_value = 0
        # v1.10.0 HIGH-5 fix: Popen artik `with` context manager; mock'un
        # __enter__ kendisini dondurmeli (gercek Popen.__enter__ self doner).
        mock_proc.__enter__.return_value = mock_proc
        mock_proc.__exit__.return_value = False

        with patch("karadul.analyzers.dwarf_extractor.subprocess.Popen", return_value=mock_proc):
            result = ext.extract_functions()
        assert result == []

    def test_very_large_address(self, tmp_path):
        """Verify 64-bit addresses are handled correctly."""
        text = textwrap.dedent("""\
            0x0000002d:   DW_TAG_subprogram
                            DW_AT_name	("high_addr")
                            DW_AT_low_pc	(0xFFFFFFFF00000000)

                          NULL
        """)
        ext = object.__new__(DwarfExtractor)
        ext.binary_path = Path("/dummy")
        ext.timeout = 30
        ext._dwarf_target = Path("/dummy")
        funcs = list(ext._parse_lines(iter(text.splitlines())))
        assert len(funcs) == 1
        assert funcs[0].address == 0xFFFFFFFF00000000

    def test_parse_lines_with_only_null(self):
        """Only NULL lines -- no crash, no functions."""
        text = "    NULL\n    NULL\n    NULL\n"
        ext = object.__new__(DwarfExtractor)
        ext.binary_path = Path("/dummy")
        ext.timeout = 30
        ext._dwarf_target = Path("/dummy")
        funcs = list(ext._parse_lines(iter(text.splitlines())))
        assert funcs == []

    def test_parse_lines_with_only_blank(self):
        """Only blank lines."""
        text = "\n\n   \n\n"
        ext = object.__new__(DwarfExtractor)
        ext.binary_path = Path("/dummy")
        ext.timeout = 30
        ext._dwarf_target = Path("/dummy")
        funcs = list(ext._parse_lines(iter(text.splitlines())))
        assert funcs == []


# ======================================================================
# DwarfExtractor._apply_func_attr / _apply_child_attr / _commit_child
# ======================================================================

class TestApplyMethods:
    """Static methods that apply parsed attributes to state objects."""

    def test_apply_func_attr_name(self):
        state = _FuncParseState()
        DwarfExtractor._apply_func_attr(state, "DW_AT_name", '"my_func"')
        assert state.name == "my_func"

    def test_apply_func_attr_low_pc(self):
        state = _FuncParseState()
        DwarfExtractor._apply_func_attr(state, "DW_AT_low_pc", "0x100")
        assert state.address == 0x100

    def test_apply_func_attr_type(self):
        state = _FuncParseState()
        DwarfExtractor._apply_func_attr(state, "DW_AT_type", '0x000000f0 "int"')
        assert state.return_type == "int"

    def test_apply_func_attr_decl_file(self):
        state = _FuncParseState()
        DwarfExtractor._apply_func_attr(state, "DW_AT_decl_file", '"/src/main.c"')
        assert state.source_file == "/src/main.c"

    def test_apply_func_attr_decl_line(self):
        state = _FuncParseState()
        DwarfExtractor._apply_func_attr(state, "DW_AT_decl_line", "42")
        assert state.line_number == 42

    def test_apply_func_attr_unknown_ignored(self):
        """Unknown attributes should not crash."""
        state = _FuncParseState()
        DwarfExtractor._apply_func_attr(state, "DW_AT_some_unknown", "value")
        # No change
        assert state.name == ""

    def test_apply_child_attr_name(self):
        state = _ChildParseState(is_param=True)
        DwarfExtractor._apply_child_attr(state, "DW_AT_name", '"count"')
        assert state.name == "count"

    def test_apply_child_attr_type(self):
        state = _ChildParseState(is_param=False)
        DwarfExtractor._apply_child_attr(state, "DW_AT_type", '0x000000f0 "int"')
        assert state.type_name == "int"

    def test_commit_child_param(self):
        func_state = _FuncParseState()
        func_state.name = "f"
        child = _ChildParseState(is_param=True)
        child.name = "x"
        child.type_name = "int"
        DwarfExtractor._commit_child(func_state, child)
        assert len(func_state.params) == 1
        assert func_state.params[0].name == "x"
        assert func_state.params[0].is_param is True

    def test_commit_child_local(self):
        func_state = _FuncParseState()
        func_state.name = "f"
        child = _ChildParseState(is_param=False)
        child.name = "result"
        child.type_name = "long"
        DwarfExtractor._commit_child(func_state, child)
        assert len(func_state.locals) == 1
        assert func_state.locals[0].name == "result"
        assert func_state.locals[0].is_param is False

    def test_commit_child_unnamed_skipped(self):
        """Unnamed child (compiler-generated) is silently skipped."""
        func_state = _FuncParseState()
        func_state.name = "f"
        child = _ChildParseState(is_param=True)
        child.name = ""  # unnamed
        child.type_name = "int"
        DwarfExtractor._commit_child(func_state, child)
        assert len(func_state.params) == 0

    def test_commit_child_missing_type_gets_unknown(self):
        """Child without type_name should get '<unknown>'."""
        func_state = _FuncParseState()
        func_state.name = "f"
        child = _ChildParseState(is_param=True)
        child.name = "param_no_type"
        # type_name stays ""
        DwarfExtractor._commit_child(func_state, child)
        assert len(func_state.params) == 1
        assert func_state.params[0].type_name == "<unknown>"


# ======================================================================
# Regex pattern tests
# ======================================================================

class TestRegexPatterns:
    """Test the module-level regex patterns used for parsing."""

    def test_re_tag_matches_subprogram(self):
        from karadul.analyzers.dwarf_extractor import _RE_TAG
        m = _RE_TAG.match("0x0000002d:   DW_TAG_subprogram")
        assert m is not None
        assert m.group(1) == "DW_TAG_subprogram"

    def test_re_tag_matches_formal_parameter(self):
        from karadul.analyzers.dwarf_extractor import _RE_TAG
        m = _RE_TAG.match("0x00000045:     DW_TAG_formal_parameter")
        assert m is not None
        assert m.group(1) == "DW_TAG_formal_parameter"

    def test_re_tag_no_match_attribute(self):
        from karadul.analyzers.dwarf_extractor import _RE_TAG
        m = _RE_TAG.match("                DW_AT_name\t(\"foo\")")
        assert m is None

    def test_re_attr_matches_name(self):
        from karadul.analyzers.dwarf_extractor import _RE_ATTR
        m = _RE_ATTR.match('                    DW_AT_name\t("calculate")')
        assert m is not None
        assert m.group(1) == "DW_AT_name"
        assert m.group(2) == '"calculate"'

    def test_re_attr_matches_low_pc(self):
        from karadul.analyzers.dwarf_extractor import _RE_ATTR
        m = _RE_ATTR.match("                    DW_AT_low_pc\t(0x0000000100003f60)")
        assert m is not None
        assert m.group(1) == "DW_AT_low_pc"
        assert m.group(2) == "0x0000000100003f60"

    def test_re_null_matches(self):
        from karadul.analyzers.dwarf_extractor import _RE_NULL
        assert _RE_NULL.match("                    NULL")
        assert _RE_NULL.match("    NULL")
        assert _RE_NULL.match("  NULL  ")

    def test_re_null_no_match_text(self):
        from karadul.analyzers.dwarf_extractor import _RE_NULL
        assert not _RE_NULL.match("NULL_PTR")
        assert not _RE_NULL.match("0x00: DW_TAG_subprogram")

    def test_re_indent_captures(self):
        from karadul.analyzers.dwarf_extractor import _RE_INDENT
        m = _RE_INDENT.match("0x0000002d:   DW_TAG_subprogram")
        assert m is not None
        assert m.group(1) == "0x0000002d:"
        indent_len = len(m.group(2))
        assert indent_len > 0
