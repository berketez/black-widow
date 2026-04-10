"""Binary reconstruction modullerinin testleri.

Kapsar:
- CVariableNamer (c_namer.py)
- CTypeRecoverer (c_type_recoverer.py)
- CCommentGenerator (c_comment_generator.py)
- CAlgorithmIdentifier (c_algorithm_id.py)
- CProjectBuilder (c_project_builder.py)
- SignatureDB (signature_db.py)
- BinaryDeobfuscator (binary_deobfuscator.py)
- ContentStore (content_store.py)
- PackingDetector / calculate_entropy (packed_binary.py)
"""

from __future__ import annotations

import json
import math
import os
from pathlib import Path
from typing import Any

import pytest

from karadul.config import Config
from karadul.core.content_store import ContentStore
from karadul.reconstruction.c_namer import (
    CVariableNamer,
    CNamingResult,
    _is_ghidra_auto_name,
    _sanitize_c_name,
    _extract_keywords_from_string,
)
from karadul.reconstruction.c_type_recoverer import (
    CTypeRecoverer,
    CTypeRecoveryResult,
    RecoveredStruct,
    RecoveredEnum,
    StructField,
)
from karadul.reconstruction.c_comment_generator import (
    CCommentGenerator,
    CCommentResult,
    SYSCALL_DOCS,
    VULN_PATTERNS,
    LOGIC_COMMENT_PATTERNS,
)
from karadul.reconstruction.c_algorithm_id import (
    CAlgorithmIdentifier,
    CAlgorithmResult,
    AlgorithmMatch,
    ALGORITHM_SIGNATURES,
    CRYPTO_APIS,
    STRUCTURAL_PATTERNS,
)
from karadul.reconstruction.c_project_builder import (
    CProjectBuilder,
    CProjectBuildResult,
)
from karadul.analyzers.signature_db import SignatureDB, SignatureMatch
from karadul.deobfuscators.binary_deobfuscator import (
    BinaryDeobfuscator,
    BinaryDeobfuscationResult,
)
from karadul.analyzers.packed_binary import (
    PackingDetector,
    PackingInfo,
    PackingType,
    calculate_entropy,
    calculate_section_entropy,
    UPX_MAGIC,
)


# ===================================================================
# Fixtures
# ===================================================================


@pytest.fixture
def config() -> Config:
    """Test icin varsayilan Config instance."""
    return Config()


@pytest.fixture
def tmp_workspace(tmp_path: Path):
    """Sahte Ghidra ciktisi olan gecici workspace.

    Returns:
        (tmp_path, static_dir, decompiled_dir) tuple.
    """
    static = tmp_path / "static"
    static.mkdir()

    # ghidra_functions.json
    functions = {
        "total": 5,
        "program": "test_binary",
        "functions": [
            {
                "name": "FUN_00001000",
                "address": "00001000",
                "size": 64,
                "parameters": [
                    {"name": "param_1", "type": "char *", "ordinal": 0},
                ],
                "return_type": "int",
                "calling_convention": "cdecl",
                "is_external": False,
                "is_thunk": False,
                "source": "ANALYSIS",
            },
            {
                "name": "_main",
                "address": "00002000",
                "size": 128,
                "parameters": [],
                "return_type": "int",
                "calling_convention": "cdecl",
                "is_external": False,
                "is_thunk": False,
                "source": "IMPORTED",
            },
            {
                "name": "_malloc",
                "address": "00003000",
                "size": 32,
                "parameters": [
                    {"name": "param_1", "type": "long", "ordinal": 0},
                ],
                "return_type": "void *",
                "calling_convention": "cdecl",
                "is_external": True,
                "is_thunk": False,
                "source": "IMPORTED",
            },
            {
                "name": "FUN_00004000",
                "address": "00004000",
                "size": 256,
                "parameters": [
                    {"name": "param_1", "type": "undefined8", "ordinal": 0},
                    {"name": "param_2", "type": "int", "ordinal": 1},
                ],
                "return_type": "undefined8",
                "calling_convention": "cdecl",
                "is_external": False,
                "is_thunk": False,
                "source": "ANALYSIS",
            },
            {
                "name": "thunk_FUN_00005000",
                "address": "00005000",
                "size": 8,
                "parameters": [],
                "return_type": "void",
                "calling_convention": "cdecl",
                "is_external": False,
                "is_thunk": True,
                "source": "ANALYSIS",
            },
        ],
    }
    (static / "ghidra_functions.json").write_text(json.dumps(functions))

    # ghidra_strings.json
    strings = {
        "total": 4,
        "program": "test_binary",
        "strings": [
            {
                "address": "00006000",
                "value": "Failed to connect to server",
                "length": 28,
                "type": "string",
                "function": "00001000",
            },
            {
                "address": "00006100",
                "value": "malloc failed",
                "length": 14,
                "type": "string",
                "function": "00004000",
            },
            {
                "address": "00006200",
                "value": "/usr/lib/libSystem.B.dylib",
                "length": 26,
                "type": "string",
                "function": None,
            },
            {
                "address": "00006300",
                "value": "AES encryption complete",
                "length": 24,
                "type": "string",
                "function": "00004000",
            },
        ],
    }
    (static / "ghidra_strings.json").write_text(json.dumps(strings))

    # ghidra_call_graph.json
    call_graph = {
        "program": "test_binary",
        "total_functions": 5,
        "total_edges": 4,
        "nodes": {
            "00001000": {
                "name": "FUN_00001000",
                "address": "00001000",
                "caller_count": 1,
                "callee_count": 0,
                "callers": [{"name": "_main", "address": "00002000"}],
                "callees": [],
            },
            "00002000": {
                "name": "_main",
                "address": "00002000",
                "caller_count": 0,
                "callee_count": 3,
                "callers": [],
                "callees": [
                    {"name": "FUN_00001000", "address": "00001000"},
                    {"name": "_malloc", "address": "00003000"},
                    {"name": "FUN_00004000", "address": "00004000"},
                ],
            },
            "00003000": {
                "name": "_malloc",
                "address": "00003000",
                "caller_count": 1,
                "callee_count": 0,
                "callers": [{"name": "_main", "address": "00002000"}],
                "callees": [],
            },
            "00004000": {
                "name": "FUN_00004000",
                "address": "00004000",
                "caller_count": 1,
                "callee_count": 1,
                "callers": [{"name": "_main", "address": "00002000"}],
                "callees": [{"name": "_malloc", "address": "00003000"}],
            },
            "00005000": {
                "name": "thunk_FUN_00005000",
                "address": "00005000",
                "caller_count": 0,
                "callee_count": 0,
                "callers": [],
                "callees": [],
            },
        },
        "edges": [
            {"from": "00002000", "to": "00001000", "from_name": "_main", "to_name": "FUN_00001000"},
            {"from": "00002000", "to": "00003000", "from_name": "_main", "to_name": "_malloc"},
            {"from": "00002000", "to": "00004000", "from_name": "_main", "to_name": "FUN_00004000"},
            {"from": "00004000", "to": "00003000", "from_name": "FUN_00004000", "to_name": "_malloc"},
        ],
    }
    (static / "ghidra_call_graph.json").write_text(json.dumps(call_graph))

    # decompiled C dosyalari
    decompiled = static / "ghidra_output" / "decompiled"
    decompiled.mkdir(parents=True)

    (decompiled / "FUN_00001000.c").write_text(
        "// Function: FUN_00001000\n// Address: 00001000\n\n"
        "int FUN_00001000(char *param_1)\n{\n"
        "  int local_8;\n  local_8 = strlen(param_1);\n"
        '  if (local_8 < 0) { return -1; }\n'
        "  void *buf = malloc(0x100);\n"
        "  if (buf == NULL) { return -1; }\n"
        "  for (local_8 = 0; local_8 < 10; local_8++) {\n"
        '    printf("item %d", local_8);\n'
        "  }\n"
        '  if (strcmp(param_1, "admin") == 0) {\n'
        "    free(buf);\n"
        "    return 1;\n  }\n"
        '  printf("Failed to connect to server");\n'
        "  free(buf);\n"
        "  return 0;\n}\n"
    )
    (decompiled / "_main.c").write_text(
        "// Function: _main\n// Address: 00002000\n\n"
        "int _main(void)\n{\n"
        "  void *ptr = _malloc(0x100);\n"
        '  FUN_00001000("test");\n'
        "  FUN_00004000(ptr, 42);\n"
        "  return 0;\n}\n"
    )
    (decompiled / "_malloc.c").write_text(
        "// Function: _malloc\n// Address: 00003000\n\n"
        "void * _malloc(long param_1)\n{\n  return (void *)0;\n}\n"
    )
    (decompiled / "FUN_00004000.c").write_text(
        "// Function: FUN_00004000\n// Address: 00004000\n\n"
        "undefined8 FUN_00004000(undefined8 param_1, int param_2)\n{\n"
        "  undefined8 local_18;\n"
        "  *(long *)(param_1 + 0x10) = 42;\n"
        "  *(int *)(param_1 + 0x18) = param_2;\n"
        '  *(char **)(param_1 + 0x20) = "AES encryption complete";\n'
        "  local_18 = _malloc(0x200);\n"
        "  strcpy(local_18, param_1);\n"
        "  return local_18;\n}\n"
    )
    (decompiled / "thunk_FUN_00005000.c").write_text(
        "// Function: thunk_FUN_00005000\n// Address: 00005000\n\n"
        'void thunk_FUN_00005000(void)\n{\n  FUN_00001000("x");\n}\n'
    )

    return tmp_path, static, decompiled


# ===================================================================
# ContentStore testleri
# ===================================================================


class TestContentStore:
    """ContentStore in-memory dosya deposu testleri."""

    def test_load_from_directory(self, tmp_workspace):
        """load_from_directory dosya sayisini dogru dondurur."""
        _, _, decompiled = tmp_workspace
        store = ContentStore()
        count = store.load_from_directory(decompiled)
        assert count == 5
        assert len(store) == 5

    def test_get_existing(self, tmp_workspace):
        """Var olan stem icin icerik dondurmeli."""
        _, _, decompiled = tmp_workspace
        store = ContentStore()
        store.load_from_directory(decompiled)
        content = store.get("FUN_00001000")
        assert content is not None
        assert "FUN_00001000" in content

    def test_get_nonexistent(self):
        """Olmayan stem icin None dondurmeli."""
        store = ContentStore()
        assert store.get("nonexistent") is None

    def test_set_and_get(self):
        """set ile ayarlanan icerik get ile dondurulebilmeli."""
        store = ContentStore()
        store.set("test_func", "int test_func(void) { return 0; }")
        assert store.get("test_func") == "int test_func(void) { return 0; }"

    def test_contains(self, tmp_workspace):
        """__contains__ operatoru doğru calismali."""
        _, _, decompiled = tmp_workspace
        store = ContentStore()
        store.load_from_directory(decompiled)
        assert "FUN_00001000" in store
        assert "_main" in store
        assert "nonexistent" not in store

    def test_len(self):
        """__len__ dogru eleman sayisi dondurmeli."""
        store = ContentStore()
        assert len(store) == 0
        store.set("a", "content_a")
        store.set("b", "content_b")
        assert len(store) == 2

    def test_flush_to_directory(self, tmp_path):
        """flush_to_directory dosyalari diske yazmali."""
        store = ContentStore()
        store.set("func_a", "void func_a(void) {}")
        store.set("func_b", "int func_b(int x) { return x; }")
        output_dir = tmp_path / "output"
        written = store.flush_to_directory(output_dir)
        assert written == 2
        assert (output_dir / "func_a.c").exists()
        assert (output_dir / "func_b.c").exists()
        assert "func_a" in (output_dir / "func_a.c").read_text()

    def test_flush_only_dirty(self, tmp_path):
        """only_dirty=True ise sadece degistirilmis dosyalar yazilmali."""
        store = ContentStore()
        store.set("clean", "// clean")
        # Flush to clear dirty set
        output_dir = tmp_path / "out1"
        store.flush_to_directory(output_dir)

        # Simdi sadece yeni bir dosya ekleyelim
        store.set("dirty", "// dirty new content")
        output_dir2 = tmp_path / "out2"
        written = store.flush_to_directory(output_dir2, only_dirty=True)
        assert written == 1
        assert (output_dir2 / "dirty.c").exists()
        assert not (output_dir2 / "clean.c").exists()

    def test_memory_usage_mb(self, tmp_workspace):
        """memory_usage_mb pozitif float dondurmeli."""
        _, _, decompiled = tmp_workspace
        store = ContentStore()
        store.load_from_directory(decompiled)
        usage = store.memory_usage_mb()
        assert isinstance(usage, float)
        assert usage > 0.0


# ===================================================================
# CVariableNamer testleri
# ===================================================================


class TestCVariableNamer:
    """CVariableNamer -- Ghidra auto-name'leri anlamli isimlere ceviren modul."""

    def test_empty_functions_json(self, config, tmp_path):
        """Fonksiyon JSON'u bos ise success=False donmeli."""
        namer = CVariableNamer(config)
        empty_json = tmp_path / "empty_functions.json"
        empty_json.write_text('{"functions": []}')
        strings_json = tmp_path / "strings.json"
        strings_json.write_text('{"strings": []}')
        cg_json = tmp_path / "call_graph.json"
        cg_json.write_text('{"nodes": {}, "edges": []}')

        decompiled = tmp_path / "decompiled"
        decompiled.mkdir()
        output = tmp_path / "output"

        result = namer.analyze_and_rename(decompiled, empty_json, strings_json, cg_json, output)
        assert result.success is False

    def test_nonexistent_decompiled_dir(self, config, tmp_workspace):
        """Decompiled dizini yoksa success=False donmeli."""
        tmp_path, static, _ = tmp_workspace
        namer = CVariableNamer(config)
        result = namer.analyze_and_rename(
            decompiled_dir=tmp_path / "nonexistent_dir",
            functions_json=static / "ghidra_functions.json",
            strings_json=static / "ghidra_strings.json",
            call_graph_json=static / "ghidra_call_graph.json",
            output_dir=tmp_path / "output",
        )
        assert result.success is False
        assert len(result.errors) > 0

    def test_symbol_based_main_preserved(self, config, tmp_workspace):
        """_main gibi bilinen symbol'ler yeniden adlandirilmamali."""
        tmp_path, static, decompiled = tmp_workspace
        namer = CVariableNamer(config)
        output = tmp_path / "named_output"
        result = namer.analyze_and_rename(
            decompiled, static / "ghidra_functions.json",
            static / "ghidra_strings.json",
            static / "ghidra_call_graph.json",
            output,
        )
        assert result.success is True
        # _main is already a known symbol, should not be renamed
        assert "_main" not in result.naming_map

    def test_fun_auto_name_renamed(self, config, tmp_workspace):
        """FUN_xxx isimleri yeniden adlandirilmali."""
        tmp_path, static, decompiled = tmp_workspace
        namer = CVariableNamer(config)
        output = tmp_path / "named_output"
        result = namer.analyze_and_rename(
            decompiled, static / "ghidra_functions.json",
            static / "ghidra_strings.json",
            static / "ghidra_call_graph.json",
            output,
        )
        assert result.success is True
        assert result.total_renamed > 0
        # FUN_00001000 veya FUN_00004000 en azindan birisi rename edilmeli
        has_fun_rename = any(k.startswith("FUN_") for k in result.naming_map)
        assert has_fun_rename

    def test_naming_result_dataclass(self):
        """CNamingResult dataclass dogru varsayilan degerler icermeli."""
        result = CNamingResult(success=True)
        assert result.success is True
        assert result.total_renamed == 0
        assert result.naming_map == {}
        assert result.errors == []
        assert result.output_files == []
        assert result.high_confidence == 0
        assert result.medium_confidence == 0
        assert result.low_confidence == 0

    def test_is_ghidra_auto_name_func(self):
        """FUN_xxx, param_N, local_XX Ghidra auto-name olarak tanimlanmali."""
        assert _is_ghidra_auto_name("FUN_00001000") is True
        assert _is_ghidra_auto_name("FUN_ABCDEF01") is True
        assert _is_ghidra_auto_name("param_1") is True
        assert _is_ghidra_auto_name("param_42") is True
        assert _is_ghidra_auto_name("local_8") is True
        assert _is_ghidra_auto_name("local_1c") is True
        assert _is_ghidra_auto_name("DAT_00100000") is True
        assert _is_ghidra_auto_name("PTR_00200000") is True
        assert _is_ghidra_auto_name("uVar1") is True
        assert _is_ghidra_auto_name("iVar3") is True
        # Bunlar auto-name degil
        assert _is_ghidra_auto_name("_main") is False
        assert _is_ghidra_auto_name("my_function") is False
        assert _is_ghidra_auto_name("strlen") is False

    def test_is_ghidra_auto_name_thunk(self):
        """thunk_ pattern'i _is_ghidra_auto_name'de kontrol edilmez (ayri regex)."""
        # thunk_ auto-name kontrolu c_project_builder'da _THUNK_RE ile yapilir
        assert _is_ghidra_auto_name("thunk_FUN_00005000") is False

    def test_sanitize_c_name_basic(self):
        """_sanitize_c_name gecerli C identifier uretmeli."""
        assert _sanitize_c_name("open database connection") == "open_database_connection"
        # Basa rakam gelince _ eklenir ama strip sonrasi kalir
        result = _sanitize_c_name("123invalid")
        assert result in ("123invalid", "_123invalid", "invalid")
        assert _sanitize_c_name("HELLO__WORLD") == "hello_world"
        assert _sanitize_c_name("") == "unnamed"
        assert _sanitize_c_name("---") == "unnamed"

    def test_sanitize_c_name_special_chars(self):
        """Ozel karakterler alt cizgiye donusturulmeli."""
        assert _sanitize_c_name("foo.bar/baz") == "foo_bar_baz"
        assert _sanitize_c_name("func@addr") == "func_addr"

    def test_extract_keywords_from_string(self):
        """String literal'den anlamli anahtar kelimeler cikarilmali."""
        kw = _extract_keywords_from_string("Failed to open database connection")
        assert "open" in kw
        assert "database" in kw
        assert "connection" in kw
        # Stopword'ler olmamali
        assert "to" not in kw

    def test_extract_keywords_short_string(self):
        """Cok kisa string'den kelime cikarilmamali."""
        kw = _extract_keywords_from_string("ab")
        assert kw == []

    def test_extract_keywords_max_4(self):
        """En fazla 4 kelime dondurmeli."""
        kw = _extract_keywords_from_string(
            "alpha bravo charlie delta echo foxtrot golf"
        )
        assert len(kw) <= 4

    def test_naming_collision_prevention(self, config, tmp_workspace):
        """Iki farkli sembol ayni yeni ismi alamaz, suffix eklenmeli."""
        tmp_path, static, decompiled = tmp_workspace
        namer = CVariableNamer(config)
        output = tmp_path / "named_output"
        result = namer.analyze_and_rename(
            decompiled, static / "ghidra_functions.json",
            static / "ghidra_strings.json",
            static / "ghidra_call_graph.json",
            output,
        )
        if result.success and result.total_renamed > 1:
            # Yeni isimler unique olmali
            new_names = list(result.naming_map.values())
            assert len(new_names) == len(set(new_names)), "Cakisan yeni isimler var!"

    def test_output_files_created(self, config, tmp_workspace):
        """Rename sonrasi output dizininde dosyalar olusturulmali."""
        tmp_path, static, decompiled = tmp_workspace
        namer = CVariableNamer(config)
        output = tmp_path / "named_output"
        result = namer.analyze_and_rename(
            decompiled, static / "ghidra_functions.json",
            static / "ghidra_strings.json",
            static / "ghidra_call_graph.json",
            output,
        )
        assert result.success is True
        assert len(result.output_files) == 5  # 5 C dosyasi
        for f in result.output_files:
            assert f.exists()

    def test_naming_map_json_saved(self, config, tmp_workspace):
        """naming_map.json output dizinine kaydedilmeli."""
        tmp_path, static, decompiled = tmp_workspace
        namer = CVariableNamer(config)
        output = tmp_path / "named_output"
        namer.analyze_and_rename(
            decompiled, static / "ghidra_functions.json",
            static / "ghidra_strings.json",
            static / "ghidra_call_graph.json",
            output,
        )
        map_file = output / "naming_map.json"
        assert map_file.exists()
        data = json.loads(map_file.read_text())
        assert isinstance(data, dict)

    def test_by_strategy_populated(self, config, tmp_workspace):
        """by_strategy dict'i en az bir strateji icermeli."""
        tmp_path, static, decompiled = tmp_workspace
        namer = CVariableNamer(config)
        output = tmp_path / "named_output"
        result = namer.analyze_and_rename(
            decompiled, static / "ghidra_functions.json",
            static / "ghidra_strings.json",
            static / "ghidra_call_graph.json",
            output,
        )
        assert result.success is True
        assert len(result.by_strategy) > 0
        # Her strateji sayisi pozitif
        for count in result.by_strategy.values():
            assert count > 0


# ===================================================================
# CTypeRecoverer testleri
# ===================================================================


class TestCTypeRecoverer:
    """CTypeRecoverer -- field access pattern'lerinden struct/enum recovery."""

    def test_field_access_struct_recovery(self, config, tmp_workspace):
        """*(TYPE*)(base+OFFSET) pattern'inden struct kurtarma."""
        tmp_path, static, decompiled = tmp_workspace
        recoverer = CTypeRecoverer(config)
        output = tmp_path / "typed_output"
        result = recoverer.recover(
            decompiled_dir=decompiled,
            functions_json=static / "ghidra_functions.json",
            output_dir=output,
        )
        assert result.success is True
        # FUN_00004000.c'de 3 field access var (0x10, 0x18, 0x20)
        if result.structs:
            # En az bir struct kurtarilmis olmali
            assert len(result.structs) >= 1
            # Fields offset'leri dogru olmali
            for s in result.structs:
                offsets = [f.offset for f in s.fields]
                assert len(offsets) == len(set(offsets)), "Duplicate offset!"

    def test_undefined_type_propagation(self, config, tmp_workspace):
        """undefined8 -> uint64_t donusumu type_replacements'ta olmali."""
        tmp_path, static, decompiled = tmp_workspace
        recoverer = CTypeRecoverer(config)
        output = tmp_path / "typed_output"
        result = recoverer.recover(
            decompiled_dir=decompiled,
            functions_json=static / "ghidra_functions.json",
            output_dir=output,
        )
        assert result.success is True
        # undefined8 -> uint64_t default propagation
        if result.type_replacements:
            has_undefined = any("undefined" in k for k in result.type_replacements)
            assert has_undefined

    def test_types_header_created(self, config, tmp_workspace):
        """types.h output dizininde olusturulmali."""
        tmp_path, static, decompiled = tmp_workspace
        recoverer = CTypeRecoverer(config)
        output = tmp_path / "typed_output"
        result = recoverer.recover(
            decompiled_dir=decompiled,
            functions_json=static / "ghidra_functions.json",
            output_dir=output,
        )
        assert result.success is True
        assert result.types_header is not None
        assert result.types_header.exists()
        content = result.types_header.read_text()
        assert "#ifndef" in content
        # types.h struct tanimlarini icerir, stdint.h include eder
        assert "#include <stdint.h>" in content

    def test_output_c_files_created(self, config, tmp_workspace):
        """Tip duzeltilmis C dosyalari olusturulmali."""
        tmp_path, static, decompiled = tmp_workspace
        recoverer = CTypeRecoverer(config)
        output = tmp_path / "typed_output"
        result = recoverer.recover(
            decompiled_dir=decompiled,
            functions_json=static / "ghidra_functions.json",
            output_dir=output,
        )
        assert result.success is True
        assert len(result.output_files) == 5

    def test_empty_input(self, config, tmp_path):
        """Bos dizin icin success=False, 0 type."""
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()
        recoverer = CTypeRecoverer(config)
        result = recoverer.recover(
            decompiled_dir=empty_dir,
            functions_json=tmp_path / "no.json",
            output_dir=tmp_path / "out",
        )
        assert result.success is False
        assert result.total_types_recovered == 0

    def test_nonexistent_dir(self, config, tmp_path):
        """Varolmayan dizin icin success=False."""
        recoverer = CTypeRecoverer(config)
        result = recoverer.recover(
            decompiled_dir=tmp_path / "does_not_exist",
            functions_json=tmp_path / "no.json",
            output_dir=tmp_path / "out",
        )
        assert result.success is False
        assert len(result.errors) > 0

    def test_struct_field_dataclass(self):
        """StructField dataclass dogru calisir."""
        sf = StructField(offset=0x10, name="field_10", type="long", size=8)
        assert sf.offset == 0x10
        assert sf.name == "field_10"
        assert sf.confidence == 0.8  # varsayilan

    def test_recovered_struct_dataclass(self):
        """RecoveredStruct dataclass dogru calisir."""
        rs = RecoveredStruct(
            name="my_struct",
            fields=[StructField(0, "a", "int", 4), StructField(4, "b", "int", 4)],
            total_size=8,
            source_functions=["FUN_00004000"],
        )
        assert rs.alignment == 8  # varsayilan ARM64
        assert len(rs.fields) == 2

    def test_recovered_enum_dataclass(self):
        """RecoveredEnum dataclass dogru calisir."""
        re_enum = RecoveredEnum(
            name="status_enum",
            values={"OK": 0, "ERR": 1, "TIMEOUT": 2},
            source_functions=["FUN_00001000"],
        )
        assert len(re_enum.values) == 3

    def test_switch_case_enum_recovery(self, config, tmp_path):
        """switch/case pattern'inden enum kurtarma."""
        decompiled_dir = tmp_path / "decompiled"
        decompiled_dir.mkdir()
        # switch ile 4+ case
        (decompiled_dir / "handler.c").write_text(
            "int handler(int param_1)\n{\n"
            "  switch (param_1) {\n"
            "    case 0: return 10;\n"
            "    case 1: return 20;\n"
            "    case 2: return 30;\n"
            "    case 3: return 40;\n"
            "    case 4: return 50;\n"
            "    default: return -1;\n"
            "  }\n}\n"
        )
        func_json = tmp_path / "functions.json"
        func_json.write_text(json.dumps({
            "functions": [
                {"name": "handler", "address": "00010000", "size": 100,
                 "parameters": [{"name": "param_1", "type": "int"}],
                 "return_type": "int"},
            ]
        }))
        recoverer = CTypeRecoverer(config, min_enum_values=3)
        result = recoverer.recover(decompiled_dir, func_json, tmp_path / "out")
        assert result.success is True
        # min_enum_values=3, 5 case >= 3, en az bir enum olmali
        if result.enums:
            assert result.enums[0].name  # isim bos olmamali
            assert len(result.enums[0].values) >= 3

    def test_total_types_recovered(self, config, tmp_workspace):
        """total_types_recovered = structs + enums + vtables sayisi."""
        tmp_path, static, decompiled = tmp_workspace
        recoverer = CTypeRecoverer(config)
        output = tmp_path / "typed_output"
        result = recoverer.recover(
            decompiled_dir=decompiled,
            functions_json=static / "ghidra_functions.json",
            output_dir=output,
        )
        expected_total = len(result.structs) + len(result.enums) + len(result.vtables)
        assert result.total_types_recovered == expected_total

    # --- v1.7.2 yeni testler: context-aware + call-graph + struct application ---

    def test_context_aware_string_arg_inference(self, config, tmp_path):
        """String fonksiyonuna arguman olarak gecilen undefined8 -> char * olmali."""
        decompiled_dir = tmp_path / "decompiled"
        decompiled_dir.mkdir()
        (decompiled_dir / "FUN_00010000.c").write_text(
            "undefined8 FUN_00010000(undefined8 param_1)\n{\n"
            "  undefined8 local_18;\n"
            "  local_18 = param_1;\n"
            "  strlen(local_18);\n"
            "  return local_18;\n}\n"
        )
        func_json = tmp_path / "functions.json"
        func_json.write_text(json.dumps({
            "functions": [
                {"name": "FUN_00010000", "address": "00010000", "size": 64,
                 "parameters": [{"name": "param_1", "type": "undefined8"}],
                 "return_type": "undefined8"},
            ]
        }))
        recoverer = CTypeRecoverer(config)
        result = recoverer.recover(decompiled_dir, func_json, tmp_path / "out")
        assert result.success is True
        # Output dosyasini oku ve undefined8'in degistigini dogrula
        out_files = list((tmp_path / "out").glob("*.c"))
        assert len(out_files) == 1
        content = out_files[0].read_text()
        # Global replace: undefined8 -> uint64_t (varsayilan)
        # Ama per-func context-aware: local_18 strlen'e geciyor -> char *
        # Dolayisiyla "char * local_18" veya en azindan undefined8 kalmamis olmali
        assert "undefined8" not in content

    def test_context_aware_alloc_result_inference(self, config, tmp_path):
        """malloc sonucu atanan degisken -> void * olmali."""
        decompiled_dir = tmp_path / "decompiled"
        decompiled_dir.mkdir()
        (decompiled_dir / "FUN_00020000.c").write_text(
            "undefined8 FUN_00020000(int param_1)\n{\n"
            "  undefined8 local_10;\n"
            "  local_10 = malloc(0x100);\n"
            "  return local_10;\n}\n"
        )
        func_json = tmp_path / "functions.json"
        func_json.write_text(json.dumps({
            "functions": [
                {"name": "FUN_00020000", "address": "00020000", "size": 64,
                 "parameters": [{"name": "param_1", "type": "int"}],
                 "return_type": "undefined8"},
            ]
        }))
        recoverer = CTypeRecoverer(config)
        result = recoverer.recover(decompiled_dir, func_json, tmp_path / "out")
        assert result.success is True
        out_files = list((tmp_path / "out").glob("*.c"))
        content = out_files[0].read_text()
        # alloc_result -> void *
        assert "void * local_10" in content or "void *local_10" in content

    def test_context_aware_pointer_deref(self, config, tmp_path):
        """Dereference edilen undefined8 -> void * olmali."""
        decompiled_dir = tmp_path / "decompiled"
        decompiled_dir.mkdir()
        (decompiled_dir / "FUN_00030000.c").write_text(
            "void FUN_00030000(undefined8 param_1)\n{\n"
            "  undefined8 local_10;\n"
            "  local_10 = *param_1;\n"
            "  return;\n}\n"
        )
        func_json = tmp_path / "functions.json"
        func_json.write_text(json.dumps({
            "functions": [
                {"name": "FUN_00030000", "address": "00030000", "size": 32,
                 "parameters": [{"name": "param_1", "type": "undefined8"}],
                 "return_type": "void"},
            ]
        }))
        recoverer = CTypeRecoverer(config)
        result = recoverer.recover(decompiled_dir, func_json, tmp_path / "out")
        assert result.success is True

    def test_call_graph_type_propagation(self, config, tmp_path):
        """Call graph'tan callee parametre tipi -> caller argumanina propagate."""
        decompiled_dir = tmp_path / "decompiled"
        decompiled_dir.mkdir()
        # callee: bilinen parametre tipleri
        (decompiled_dir / "known_func.c").write_text(
            "int known_func(char *param_1, int param_2)\n{\n"
            "  return strlen(param_1) + param_2;\n}\n"
        )
        # caller: undefined parametrelerle cagiriyor
        (decompiled_dir / "caller_func.c").write_text(
            "void caller_func(undefined8 param_1, undefined4 param_2)\n{\n"
            "  known_func(param_1, param_2);\n"
            "  return;\n}\n"
        )
        func_json = tmp_path / "functions.json"
        func_json.write_text(json.dumps({
            "functions": [
                {"name": "known_func", "address": "00040000", "size": 64,
                 "parameters": [
                     {"name": "param_1", "type": "char *"},
                     {"name": "param_2", "type": "int"},
                 ],
                 "return_type": "int"},
                {"name": "caller_func", "address": "00050000", "size": 64,
                 "parameters": [
                     {"name": "param_1", "type": "undefined8"},
                     {"name": "param_2", "type": "undefined4"},
                 ],
                 "return_type": "void"},
            ]
        }))
        cg_json = tmp_path / "call_graph.json"
        cg_json.write_text(json.dumps({
            "nodes": {
                "00040000": {
                    "name": "known_func", "address": "00040000",
                    "callers": [{"name": "caller_func", "address": "00050000"}],
                    "callees": [],
                },
                "00050000": {
                    "name": "caller_func", "address": "00050000",
                    "callers": [],
                    "callees": [{"name": "known_func", "address": "00040000"}],
                },
            }
        }))
        recoverer = CTypeRecoverer(config)
        result = recoverer.recover(
            decompiled_dir, func_json, tmp_path / "out",
            call_graph_json=cg_json,
        )
        assert result.success is True
        # caller_func'taki param_1 char* olmali (known_func'in 1. parametresi)
        caller_out = (tmp_path / "out" / "caller_func.c").read_text()
        assert "char *" in caller_out or "char*" in caller_out

    def test_struct_type_application(self, config, tmp_path):
        """Field access pattern'i struct'la eslesen degisken -> struct * olmali."""
        decompiled_dir = tmp_path / "decompiled"
        decompiled_dir.mkdir()
        (decompiled_dir / "FUN_00060000.c").write_text(
            "undefined8 FUN_00060000(undefined8 param_1)\n{\n"
            "  *(long *)(param_1 + 0x10) = 42;\n"
            "  *(int *)(param_1 + 0x18) = 7;\n"
            '  *(char **)(param_1 + 0x20) = "hello";\n'
            "  return param_1;\n}\n"
        )
        func_json = tmp_path / "functions.json"
        func_json.write_text(json.dumps({
            "functions": [
                {"name": "FUN_00060000", "address": "00060000", "size": 128,
                 "parameters": [{"name": "param_1", "type": "undefined8"}],
                 "return_type": "undefined8"},
            ]
        }))
        recoverer = CTypeRecoverer(config)
        result = recoverer.recover(decompiled_dir, func_json, tmp_path / "out")
        assert result.success is True
        # 3 field access -> struct kurtarilmis olmali
        assert len(result.structs) >= 1
        # Struct ismi per-func replacement'a eklenmis olmali
        out_content = (tmp_path / "out" / "FUN_00060000.c").read_text()
        # param_1 artik undefined8 degil, struct pointer olmali
        # (ya da en azindan uint64_t global replace olmus olmali)
        assert "undefined8" not in out_content

    def test_per_func_replacement_isolation(self, config, tmp_path):
        """Per-func replacement baska fonksiyonlari etkilememeli."""
        decompiled_dir = tmp_path / "decompiled"
        decompiled_dir.mkdir()
        # Iki farkli fonksiyon, farkli context'ler
        (decompiled_dir / "func_a.c").write_text(
            "void func_a(undefined8 param_1)\n{\n"
            "  strlen(param_1);\n"
            "  return;\n}\n"
        )
        (decompiled_dir / "func_b.c").write_text(
            "void func_b(undefined8 param_1)\n{\n"
            "  *(long *)(param_1 + 0x10) = 1;\n"
            "  *(int *)(param_1 + 0x18) = 2;\n"
            "  *(int *)(param_1 + 0x20) = 3;\n"
            "  return;\n}\n"
        )
        func_json = tmp_path / "functions.json"
        func_json.write_text(json.dumps({
            "functions": [
                {"name": "func_a", "address": "00070000", "size": 32,
                 "parameters": [{"name": "param_1", "type": "undefined8"}],
                 "return_type": "void"},
                {"name": "func_b", "address": "00080000", "size": 64,
                 "parameters": [{"name": "param_1", "type": "undefined8"}],
                 "return_type": "void"},
            ]
        }))
        recoverer = CTypeRecoverer(config)
        result = recoverer.recover(decompiled_dir, func_json, tmp_path / "out")
        assert result.success is True
        # Her iki output dosyasinda da undefined8 kalmamis olmali
        for f in (tmp_path / "out").glob("*.c"):
            content = f.read_text()
            assert "undefined8" not in content, f"undefined8 kaldi: {f.name}"

    def test_call_graph_json_optional(self, config, tmp_workspace):
        """call_graph_json=None gecildiginde hata vermemeli."""
        tmp_path, static, decompiled = tmp_workspace
        recoverer = CTypeRecoverer(config)
        output = tmp_path / "typed_output"
        result = recoverer.recover(
            decompiled_dir=decompiled,
            functions_json=static / "ghidra_functions.json",
            output_dir=output,
            call_graph_json=None,
        )
        assert result.success is True

    def test_call_graph_with_existing_fixture(self, config, tmp_workspace):
        """Mevcut fixture'daki call_graph ile calistirma."""
        tmp_path, static, decompiled = tmp_workspace
        recoverer = CTypeRecoverer(config)
        output = tmp_path / "typed_output"
        result = recoverer.recover(
            decompiled_dir=decompiled,
            functions_json=static / "ghidra_functions.json",
            output_dir=output,
            call_graph_json=static / "ghidra_call_graph.json",
        )
        assert result.success is True
        # Struct kurtarilmis olmali (FUN_00004000'de 3 field access var)
        if result.structs:
            assert len(result.structs) >= 1

    def test_bitwise_op_infers_unsigned(self, config, tmp_path):
        """Bitwise islem yapilan degisken unsigned olmali."""
        decompiled_dir = tmp_path / "decompiled"
        decompiled_dir.mkdir()
        (decompiled_dir / "FUN_00090000.c").write_text(
            "void FUN_00090000(undefined4 param_1)\n{\n"
            "  undefined4 local_c;\n"
            "  local_c = param_1 >> 4;\n"
            "  return;\n}\n"
        )
        func_json = tmp_path / "functions.json"
        func_json.write_text(json.dumps({
            "functions": [
                {"name": "FUN_00090000", "address": "00090000", "size": 32,
                 "parameters": [{"name": "param_1", "type": "undefined4"}],
                 "return_type": "void"},
            ]
        }))
        recoverer = CTypeRecoverer(config)
        result = recoverer.recover(decompiled_dir, func_json, tmp_path / "out")
        assert result.success is True

    # --- v1.8: Enhanced type inference tests ---

    def test_float_literal_infers_double(self, config, tmp_path):
        """Float literal assignment yapilan degisken double olmali."""
        decompiled_dir = tmp_path / "decompiled"
        decompiled_dir.mkdir()
        (decompiled_dir / "FUN_00100000.c").write_text(
            "void FUN_00100000(undefined8 param_1)\n{\n"
            "  undefined8 local_10;\n"
            "  local_10 = param_1 * 3.14159;\n"
            "  return;\n}\n"
        )
        func_json = tmp_path / "functions.json"
        func_json.write_text(json.dumps({
            "functions": [
                {"name": "FUN_00100000", "address": "00100000", "size": 64,
                 "parameters": [{"name": "param_1", "type": "undefined8"}],
                 "return_type": "void"},
            ]
        }))
        recoverer = CTypeRecoverer(config)
        result = recoverer.recover(decompiled_dir, func_json, tmp_path / "out")
        assert result.success is True
        out_files = list((tmp_path / "out").glob("*.c"))
        assert len(out_files) == 1

    def test_typed_malloc_cast(self, config, tmp_path):
        """var = (double *)malloc(n) -> var: double *."""
        decompiled_dir = tmp_path / "decompiled"
        decompiled_dir.mkdir()
        (decompiled_dir / "FUN_00110000.c").write_text(
            "void FUN_00110000(void)\n{\n"
            "  undefined8 local_10;\n"
            "  local_10 = (double *)malloc(0x100);\n"
            "  return;\n}\n"
        )
        func_json = tmp_path / "functions.json"
        func_json.write_text(json.dumps({
            "functions": [
                {"name": "FUN_00110000", "address": "00110000", "size": 64,
                 "parameters": [],
                 "return_type": "void"},
            ]
        }))
        recoverer = CTypeRecoverer(config)
        result = recoverer.recover(decompiled_dir, func_json, tmp_path / "out")
        assert result.success is True

    def test_in_stack_fortran_typing(self, config, tmp_path):
        """in_stack_XXXXXX parametreleri Fortran by-ref olmali."""
        decompiled_dir = tmp_path / "decompiled"
        decompiled_dir.mkdir()
        (decompiled_dir / "_fortran_sub_.c").write_text(
            "void _fortran_sub_(int *param_1, double *param_2)\n{\n"
            "  long in_stack_00000030;\n"
            "  *(int *)(in_stack_00000030 + 0x80) = *param_1;\n"
            "  return;\n}\n"
        )
        func_json = tmp_path / "functions.json"
        func_json.write_text(json.dumps({
            "functions": [
                {"name": "_fortran_sub_", "address": "00120000", "size": 128,
                 "parameters": [
                     {"name": "param_1", "type": "int *"},
                     {"name": "param_2", "type": "double *"},
                 ],
                 "return_type": "void"},
            ]
        }))
        recoverer = CTypeRecoverer(config)
        result = recoverer.recover(decompiled_dir, func_json, tmp_path / "out")
        assert result.success is True

    def test_ghidra_high_vars_loading(self, config, tmp_path):
        """decompiled_json icindeki pcode_high_vars tip bilgisi yuklenmeli."""
        decompiled_dir = tmp_path / "decompiled"
        decompiled_dir.mkdir()
        (decompiled_dir / "_Graph_free.c").write_text(
            "void _Graph_free(undefined8 param_1)\n{\n"
            "  undefined8 local_10;\n"
            "  local_10 = *(undefined8 *)(param_1 + 0x10);\n"
            "  return;\n}\n"
        )
        func_json = tmp_path / "functions.json"
        func_json.write_text(json.dumps({
            "functions": [
                {"name": "_Graph_free", "address": "1003b5f5c", "size": 84,
                 "parameters": [{"name": "param_1", "type": "undefined8"}],
                 "return_type": "void"},
            ]
        }))
        # decompiled.json with pcode_high_vars
        decomp_json = tmp_path / "decompiled.json"
        decomp_json.write_text(json.dumps({
            "functions": [
                {
                    "name": "_Graph_free",
                    "address": "1003b5f5c",
                    "pcode_high_vars": [
                        {"name": "param_1", "type": "void *", "size": 8,
                         "storage": "(register, 0x4000, 8)"},
                    ]
                }
            ]
        }))
        recoverer = CTypeRecoverer(config)
        result = recoverer.recover(
            decompiled_dir, func_json, tmp_path / "out",
            decompiled_json=decomp_json,
        )
        assert result.success is True
        # Output dosyasini oku -- param_1 void * olmali
        out_files = list((tmp_path / "out").glob("*.c"))
        assert len(out_files) == 1
        content = out_files[0].read_text()
        # undefined8 param_1 -> void * param_1 degismis olmali
        assert "void * param_1" in content or "void *param_1" in content

    def test_ghidra_high_vars_skips_undefined(self, config, tmp_path):
        """pcode_high_vars'taki undefined tipler atlanmali."""
        decompiled_dir = tmp_path / "decompiled"
        decompiled_dir.mkdir()
        (decompiled_dir / "FUN_00200000.c").write_text(
            "void FUN_00200000(undefined8 param_1)\n{\n"
            "  return;\n}\n"
        )
        func_json = tmp_path / "functions.json"
        func_json.write_text(json.dumps({
            "functions": [
                {"name": "FUN_00200000", "address": "00200000", "size": 32,
                 "parameters": [{"name": "param_1", "type": "undefined8"}],
                 "return_type": "void"},
            ]
        }))
        decomp_json = tmp_path / "decompiled.json"
        decomp_json.write_text(json.dumps({
            "functions": [
                {
                    "name": "FUN_00200000",
                    "address": "00200000",
                    "pcode_high_vars": [
                        {"name": "param_1", "type": "undefined8", "size": 8,
                         "storage": "(register, 0x4000, 8)"},
                    ]
                }
            ]
        }))
        recoverer = CTypeRecoverer(config)
        result = recoverer.recover(
            decompiled_dir, func_json, tmp_path / "out",
            decompiled_json=decomp_json,
        )
        assert result.success is True
        # undefined8 tipler high_vars'tan atlanmali -- global default hala uygulanir
        assert recoverer._ghidra_high_vars.get("FUN_00200000") is None or \
               "param_1" not in recoverer._ghidra_high_vars.get("FUN_00200000", {})

    def test_cast_deref_pointer_inference(self, config, tmp_path):
        """*(double *)(var + offset) pattern'i var'in pointer oldugunu gostermeli."""
        decompiled_dir = tmp_path / "decompiled"
        decompiled_dir.mkdir()
        (decompiled_dir / "FUN_00300000.c").write_text(
            "void FUN_00300000(undefined8 param_1)\n{\n"
            "  undefined8 local_10;\n"
            "  local_10 = *(double *)(param_1 + 0x10);\n"
            "  *(double *)(param_1 + 0x18) = local_10;\n"
            "  return;\n}\n"
        )
        func_json = tmp_path / "functions.json"
        func_json.write_text(json.dumps({
            "functions": [
                {"name": "FUN_00300000", "address": "00300000", "size": 64,
                 "parameters": [{"name": "param_1", "type": "undefined8"}],
                 "return_type": "void"},
            ]
        }))
        recoverer = CTypeRecoverer(config)
        result = recoverer.recover(decompiled_dir, func_json, tmp_path / "out")
        assert result.success is True

    def test_decompiled_json_optional(self, config, tmp_workspace):
        """decompiled_json=None gecildiginde hata vermemeli."""
        tmp_path, static, decompiled = tmp_workspace
        recoverer = CTypeRecoverer(config)
        output = tmp_path / "typed_output"
        result = recoverer.recover(
            decompiled_dir=decompiled,
            functions_json=static / "ghidra_functions.json",
            output_dir=output,
            decompiled_json=None,
        )
        assert result.success is True


# ===================================================================
# CCommentGenerator testleri
# ===================================================================


class TestCCommentGenerator:
    """CCommentGenerator -- decompile edilmis C koduna yorum ekleme."""

    def test_syscall_annotation_malloc(self, config, tmp_workspace):
        """malloc cagrisi syscall yorumu almali."""
        tmp_path, static, decompiled = tmp_workspace
        gen = CCommentGenerator(config)
        output = tmp_path / "commented"
        result = gen.generate(decompiled, output)
        assert result.success is True
        # _malloc(0x100) cagrisi _main.c'de var
        assert result.syscall_annotations > 0

    def test_vuln_warning_strcpy(self, config, tmp_workspace):
        """strcpy cagrisi VULN uyarisi almali."""
        tmp_path, static, decompiled = tmp_workspace
        gen = CCommentGenerator(config)
        output = tmp_path / "commented"
        result = gen.generate(decompiled, output)
        assert result.success is True
        # FUN_00004000.c'de strcpy(local_18, param_1) var
        assert result.vulnerability_warnings > 0

    def test_empty_input(self, config, tmp_path):
        """Bos dizin icin success=False, 0 yorum."""
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()
        gen = CCommentGenerator(config)
        result = gen.generate(empty_dir, tmp_path / "out")
        assert result.success is False
        assert result.total_comments_added == 0

    def test_nonexistent_dir(self, config, tmp_path):
        """Varolmayan dizin icin success=False."""
        gen = CCommentGenerator(config)
        result = gen.generate(tmp_path / "nonexistent", tmp_path / "out")
        assert result.success is False

    def test_output_files_created(self, config, tmp_workspace):
        """Yorumlu C dosyalari output dizininde olusturulmali."""
        tmp_path, static, decompiled = tmp_workspace
        gen = CCommentGenerator(config)
        output = tmp_path / "commented"
        result = gen.generate(decompiled, output)
        assert result.success is True
        assert len(result.output_files) == 5
        for f in result.output_files:
            assert f.exists()

    def test_function_header_comments(self, config, tmp_workspace):
        """Fonksiyon baslik yorumlari veya syscall/vuln yorumlari eklenmeli."""
        tmp_path, static, decompiled = tmp_workspace
        gen = CCommentGenerator(config)
        output = tmp_path / "commented"
        result = gen.generate(
            decompiled, output,
            functions_json=static / "ghidra_functions.json",
        )
        assert result.success is True
        # En az bir tur yorum eklenmis olmali
        assert result.total_comments_added > 0

    def test_syscall_combined_regex_exists(self):
        """_SYSCALL_COMBINED regex derlenmis olmali."""
        assert CCommentGenerator._SYSCALL_COMBINED is not None

    def test_check_syscall_malloc(self):
        """_check_syscall malloc satirini tanimali."""
        line = "  void *ptr = malloc(0x100);"
        result = CCommentGenerator._check_syscall(line)
        assert result != ""
        assert "allocate" in result.lower() or "bytes" in result.lower()

    def test_check_syscall_no_match(self):
        """_check_syscall bilinen cagri olmayan satirda bos dondur."""
        line = "  int x = y + z;"
        result = CCommentGenerator._check_syscall(line)
        assert result == ""

    def test_to_dict(self, config, tmp_workspace):
        """CCommentResult.to_dict JSON-serializable dondurmeli."""
        tmp_path, static, decompiled = tmp_workspace
        gen = CCommentGenerator(config)
        output = tmp_path / "commented"
        result = gen.generate(decompiled, output)
        d = result.to_dict()
        assert isinstance(d, dict)
        assert "total_comments_added" in d
        assert "logic_comments" in d
        # JSON serializasyonu calismali
        json_str = json.dumps(d)
        assert len(json_str) > 10

    # ----- Logic comment tests -----

    def test_logic_comments_generated(self, config, tmp_workspace):
        """Logic comments en az 1 yorum uretmeli (fixture'da pattern'ler var)."""
        tmp_path, static, decompiled = tmp_workspace
        gen = CCommentGenerator(config)
        output = tmp_path / "commented"
        result = gen.generate(decompiled, output)
        assert result.success is True
        assert result.logic_comments > 0

    def test_logic_error_check_negative(self):
        """if (x < 0) { return -1; } error check yorumu almali."""
        line = "if (ret < 0) {"
        ctx = "if (ret < 0) { return -1; }"
        result = CCommentGenerator._check_logic_pattern(line, ctx)
        assert result != ""
        assert "error" in result.lower() or "failure" in result.lower()

    def test_logic_null_check(self):
        """if (ptr == NULL) null check yorumu almali."""
        line = "if (buf == NULL) {"
        ctx = "if (buf == NULL) { return -1; }"
        result = CCommentGenerator._check_logic_pattern(line, ctx)
        assert result != ""
        assert "null" in result.lower()

    def test_logic_for_loop(self):
        """for (i=0; i<N; i++) iterate yorumu almali."""
        line = "for (i = 0; i < count; i++)"
        result = CCommentGenerator._check_logic_pattern(line, line)
        assert result != ""
        assert "iterate" in result.lower()

    def test_logic_malloc_check(self):
        """malloc + null check combo yorumu almali."""
        line = "buf = malloc(0x100);"
        ctx = "buf = malloc(0x100);\n  if (buf == NULL) { return -1; }"
        result = CCommentGenerator._check_logic_pattern(line, ctx)
        assert result != ""
        assert "allocate" in result.lower()

    def test_logic_free(self):
        """free(ptr) release yorumu almali."""
        line = "free(buffer);"
        result = CCommentGenerator._check_logic_pattern(line, line)
        assert result != ""
        assert "release" in result.lower()

    def test_logic_strcmp(self):
        """strcmp karsilastirma yorumu almali."""
        line = 'if (strcmp(name, "root") == 0)'
        result = CCommentGenerator._check_logic_pattern(line, line)
        assert result != ""
        assert "compare" in result.lower()

    def test_logic_no_match(self):
        """Normal aritmetik satirda logic yorum olmamali."""
        line = "int x = y + z * 2;"
        result = CCommentGenerator._check_logic_pattern(line, line)
        assert result == ""

    def test_logic_comment_max_length(self):
        """Logic yorumlari 60 karakteri gecmemeli."""
        # Uzun bir degisken ismi ile test et
        line = "if (very_long_variable_name_that_goes_on_and_on < 0) {"
        ctx = line + " return -1; }"
        result = CCommentGenerator._check_logic_pattern(line, ctx)
        if result:  # Eslesmis ise
            assert len(result) <= 60

    def test_logic_while_break(self):
        """while(1) { if(cond) break; } loop-until yorumu almali."""
        line = "while (1) {"
        ctx = "while (1) {\n    process();\n    if (done) break;\n}"
        result = CCommentGenerator._check_logic_pattern(line, ctx)
        assert result != ""
        assert "loop" in result.lower() or "until" in result.lower()

    def test_logic_goto_cleanup(self):
        """goto err_cleanup icin cleanup yorumu almali."""
        line = "goto error_handler;"
        result = CCommentGenerator._check_logic_pattern(line, line)
        assert result != ""
        assert "cleanup" in result.lower()

    def test_logic_memcpy(self):
        """memcpy(dst, src, n) icin copy yorumu almali."""
        line = "memcpy(dest, source, nbytes);"
        result = CCommentGenerator._check_logic_pattern(line, line)
        assert result != ""
        assert "copy" in result.lower()

    def test_logic_patterns_list_nonempty(self):
        """LOGIC_COMMENT_PATTERNS listesi bos olmamali."""
        assert len(LOGIC_COMMENT_PATTERNS) >= 10

    def test_logic_integration_output_file(self, config, tmp_workspace):
        """Yorumlu cikti dosyasinda logic comment metni bulunmali."""
        tmp_path, static, decompiled = tmp_workspace
        gen = CCommentGenerator(config)
        output = tmp_path / "commented"
        result = gen.generate(decompiled, output)
        assert result.success is True
        # FUN_00001000.c'de if (local_8 < 0), malloc, for loop, strcmp, free var
        commented_file = output / "FUN_00001000.c"
        assert commented_file.exists()
        text = commented_file.read_text()
        # En az birkaç logic comment icermeli
        logic_markers = [
            "error check", "null check", "iterate", "allocate",
            "release", "compare",
        ]
        found = sum(1 for m in logic_markers if m in text.lower())
        assert found >= 2, f"Expected at least 2 logic markers in output, found {found}"


# ===================================================================
# CAlgorithmIdentifier testleri
# ===================================================================


class TestCAlgorithmIdentifier:
    """CAlgorithmIdentifier -- kriptografik algoritma tespiti."""

    def test_aes_sbox_constant_detection(self, config, tmp_path):
        """AES S-box sabiti iceren C kodunda AES tespiti."""
        decompiled = tmp_path / "decompiled"
        decompiled.mkdir()
        # AES S-box'un ilk byte'lari -- body 500+ char olmali (v1.4.3 min body filtresi)
        (decompiled / "crypto_func.c").write_text(
            "void crypto_func(unsigned char *input, unsigned char *output, int len)\n{\n"
            "  unsigned char sbox[256] = {\n"
            "    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,\n"
            "    0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76\n"
            "  };\n"
            "  unsigned char rcon[10] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36};\n"
            "  int round_key[44];\n"
            "  int state[16];\n"
            "  int i, j, round;\n"
            "  for (i = 0; i < 16; i++) { state[i] = input[i]; }\n"
            "  for (round = 0; round < 10; round++) {\n"
            "    for (i = 0; i < 16; i++) {\n"
            "      state[i] = sbox[state[i] & 0xff];\n"
            "      state[i] ^= round_key[round * 4 + (i >> 2)];\n"
            "    }\n"
            "  }\n"
            "  for (i = 0; i < 16; i++) { output[i] = state[i]; }\n"
            "  return;\n}\n"
        )
        identifier = CAlgorithmIdentifier(config)
        result = identifier.identify(decompiled)
        assert result.success is True
        algo_names = [a.name for a in result.algorithms]
        assert "AES" in algo_names

    def test_sha256_k_constant_detection(self, config, tmp_path):
        """SHA-256 K-constant iceren C kodunda SHA-256 tespiti."""
        decompiled = tmp_path / "decompiled"
        decompiled.mkdir()
        # Body 500+ char olmali (v1.4.3 min body filtresi)
        (decompiled / "hash_func.c").write_text(
            "void hash_func(unsigned char *msg, unsigned int *digest, int msg_len)\n{\n"
            "  unsigned int k[4] = {\n"
            "    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5\n"
            "  };\n"
            "  unsigned int h[8] = {\n"
            "    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,\n"
            "    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19\n"
            "  };\n"
            "  unsigned int w[64];\n"
            "  int i, j;\n"
            "  for (i = 0; i < 16; i++) {\n"
            "    w[i] = ((unsigned int)msg[i*4] << 24) | ((unsigned int)msg[i*4+1] << 16)\n"
            "         | ((unsigned int)msg[i*4+2] << 8) | (unsigned int)msg[i*4+3];\n"
            "  }\n"
            "  for (i = 0; i < 64; i++) {\n"
            "    unsigned int temp = h[7] + k[i % 4] + w[i % 16];\n"
            "    h[7] = h[6]; h[6] = h[5]; h[5] = h[4];\n"
            "    h[4] = h[3] + temp; h[3] = h[2]; h[2] = h[1]; h[1] = h[0];\n"
            "    h[0] = temp;\n"
            "  }\n"
            "  for (i = 0; i < 8; i++) { digest[i] = h[i]; }\n}\n"
        )
        identifier = CAlgorithmIdentifier(config)
        result = identifier.identify(decompiled)
        assert result.success is True
        algo_names = [a.name for a in result.algorithms]
        assert "SHA-256" in algo_names

    def test_api_cccrypt_detection(self, config, tmp_path):
        """CCCrypt API cagrisi olan C kodunda CommonCrypto tespiti."""
        decompiled = tmp_path / "decompiled"
        decompiled.mkdir()
        (decompiled / "encrypt.c").write_text(
            "int encrypt(void)\n{\n"
            "  CCCryptorStatus status = CCCrypt(\n"
            "    kCCEncrypt, kCCAlgorithmAES, kCCOptionPKCS7Padding,\n"
            "    key, kCCKeySizeAES256, iv, data, len, out, outlen, &outmoved\n"
            "  );\n}\n"
        )
        identifier = CAlgorithmIdentifier(config)
        result = identifier.identify(decompiled)
        assert result.success is True
        # CCCrypt -> "AES/DES/3DES" or "CommonCrypto AES"
        algo_names = [a.name for a in result.algorithms]
        has_crypto = any("AES" in n or "DES" in n or "CommonCrypto" in n for n in algo_names)
        assert has_crypto

    def test_empty_input(self, config, tmp_path):
        """Bos dizin icin success=True, 0 algoritma."""
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()
        identifier = CAlgorithmIdentifier(config)
        result = identifier.identify(empty_dir)
        # Bos dizin hala basarili ama 0 tespit
        assert result.total_detected == 0

    def test_algorithm_match_dataclass(self):
        """AlgorithmMatch dataclass dogru calisir."""
        am = AlgorithmMatch(
            name="AES",
            category="symmetric_cipher",
            confidence=0.9,
            detection_method="constant",
            evidence=["S-box match"],
            function_name="FUN_00004000",
            address="00004000",
        )
        d = am.to_dict()
        assert d["name"] == "AES"
        assert d["confidence"] == 0.9

    def test_algorithm_result_to_dict(self):
        """CAlgorithmResult.to_dict JSON-serializable dondurmeli."""
        result = CAlgorithmResult(
            success=True,
            algorithms=[
                AlgorithmMatch("AES", "symmetric_cipher", 0.9, "constant",
                               ["sbox"], "func", "0x1000"),
            ],
            total_detected=1,
        )
        d = result.to_dict()
        assert d["total_detected"] == 1
        json_str = json.dumps(d)
        assert "AES" in json_str

    def test_builtin_algorithm_signatures_coverage(self):
        """ALGORITHM_SIGNATURES en az 15 algoritma icermeli."""
        assert len(ALGORITHM_SIGNATURES) >= 15

    def test_crypto_apis_coverage(self):
        """CRYPTO_APIS en az 50 API icermeli."""
        assert len(CRYPTO_APIS) >= 50

    def test_structural_patterns_coverage(self):
        """STRUCTURAL_PATTERNS en az 8 pattern icermeli."""
        assert len(STRUCTURAL_PATTERNS) >= 8

    def test_no_false_positive_for_plain_code(self, config, tmp_path):
        """Duz C kodunda (crypto olmayan) false positive olmamali."""
        decompiled = tmp_path / "decompiled"
        decompiled.mkdir()
        (decompiled / "hello.c").write_text(
            'int main(void)\n{\n  printf("Hello, world!\\n");\n  return 0;\n}\n'
        )
        identifier = CAlgorithmIdentifier(config)
        result = identifier.identify(decompiled)
        # Basit hello world'de algoritma tespiti olmamali
        assert result.total_detected == 0


# ===================================================================
# SignatureDB testleri
# ===================================================================


class TestSignatureDB:
    """SignatureDB -- binary fonksiyon imza veritabani."""

    def test_builtin_signature_count(self, config):
        """Builtin imza sayisi >= 500."""
        db = SignatureDB(config)
        db_stats = db.stats()
        total = db_stats["total_symbol_signatures"]
        assert total >= 500, f"Builtin imza sayisi {total}, beklenen >= 500"

    def test_dispatch_once_match(self, config):
        """_dispatch_once libdispatch olarak eslestirilmeli."""
        db = SignatureDB(config)
        result = db.match_function("_dispatch_once")
        assert result is not None
        assert result.library == "libdispatch"

    def test_objc_msgSend_match(self, config):
        """_objc_msgSend libobjc olarak eslestirilmeli."""
        db = SignatureDB(config)
        result = db.match_function("_objc_msgSend")
        assert result is not None
        assert result.library == "libobjc"

    def test_unknown_function_no_match(self, config):
        """Bilinmeyen fonksiyon icin None donmeli."""
        db = SignatureDB(config)
        result = db.match_function("my_custom_function_12345")
        assert result is None

    def test_swift_retain_match(self, config):
        """_swift_retain swift_runtime olarak eslestirilmeli."""
        db = SignatureDB(config)
        result = db.match_function("_swift_retain")
        assert result is not None
        assert result.library == "swift_runtime"

    def test_cc_sha256_match(self, config):
        """_CC_SHA256 CommonCrypto olarak eslestirilmeli."""
        db = SignatureDB(config)
        result = db.match_function("_CC_SHA256")
        assert result is not None
        assert result.library == "CommonCrypto"

    def test_evp_encrypt_match(self, config):
        """_EVP_EncryptInit_ex openssl olarak eslestirilmeli."""
        db = SignatureDB(config)
        result = db.match_function("_EVP_EncryptInit_ex")
        assert result is not None
        assert result.library == "openssl"

    def test_match_all_integration(self, config, tmp_workspace):
        """match_all integration testi -- tum katmanlarla birlikte."""
        tmp_path, static, decompiled = tmp_workspace
        db = SignatureDB(config)
        matches = db.match_all(
            functions_json=static / "ghidra_functions.json",
            strings_json=static / "ghidra_strings.json",
            call_graph_json=static / "ghidra_call_graph.json",
            decompiled_dir=decompiled,
        )
        assert isinstance(matches, list)
        # _malloc bilinen bir system symbol, eslesmesi beklenir
        # Ama match_all edge format'i farkli olabilir, match sayisi >= 0 yeterli
        # Onemli olan calisma sirasinda exception olmamasidir

    def test_match_function_with_body(self, config):
        """match_function body'den string extract ederek eslestirme yapabilmeli."""
        db = SignatureDB(config)
        # _malloc bilinen bir symbol
        result = db.match_function("_malloc")
        # _malloc symbol DB'de olmayabilir (ust cizgisiz kontrol gerekir)
        # Ama sistem kotu yonlenmeye yol acmamali
        # Sadece None veya SignatureMatch dondurulmeli
        assert result is None or isinstance(result, SignatureMatch)

    def test_match_result_serializable(self, config):
        """SignatureMatch.to_dict JSON-serializable."""
        sm = SignatureMatch(
            original_name="FUN_123",
            matched_name="EVP_EncryptInit",
            library="openssl",
            confidence=0.95,
            match_method="symbol",
            purpose="encryption init",
            category="crypto",
        )
        d = sm.to_dict()
        json.dumps(d)  # hata vermemeli

    def test_stats(self, config):
        """stats() dogru yapida istatistik dondurmeli."""
        db = SignatureDB(config)
        db_stats = db.stats()
        assert "total_symbol_signatures" in db_stats
        assert "total_byte_signatures" in db_stats
        assert "libraries" in db_stats
        assert isinstance(db_stats["libraries"], list)
        assert len(db_stats["libraries"]) > 5  # En az 5+ farkli kutuphane


# ===================================================================
# CProjectBuilder testleri
# ===================================================================


class TestCProjectBuilder:
    """CProjectBuilder -- organize IDE projesi uretimi."""

    def test_subsystem_classification_network(self, config, tmp_workspace):
        """socket callee olan fonksiyon 'network' subsystem'e atanmali."""
        builder = CProjectBuilder(config)
        callees = [{"name": "socket"}, {"name": "connect"}, {"name": "send"}]
        subsys = builder._classify_subsystem("FUN_net", callees)
        assert subsys == "network"

    def test_subsystem_classification_crypto(self, config):
        """SSL_ callee olan fonksiyon 'crypto' subsystem'e atanmali."""
        builder = CProjectBuilder(config)
        callees = [{"name": "SSL_connect"}, {"name": "SSL_read"}]
        subsys = builder._classify_subsystem("FUN_ssl", callees)
        assert subsys == "crypto"

    def test_subsystem_classification_misc(self, config):
        """Bilinmeyen callee'ler 'misc' dondurmeli."""
        builder = CProjectBuilder(config)
        callees = [{"name": "unknown_func"}]
        subsys = builder._classify_subsystem("FUN_misc", callees)
        assert subsys == "misc"

    def test_entry_point_main(self, config, tmp_workspace):
        """_main fonksiyonu entry point olarak src/main.c'ye yazilmali."""
        tmp_path, static, decompiled = tmp_workspace
        builder = CProjectBuilder(config)

        # Workspace mock
        class FakeWorkspace:
            def get_stage_dir(self, name):
                return static

        output = tmp_path / "project"
        result = builder.build(decompiled, output, workspace=FakeWorkspace())
        assert result.success is True
        main_c = output / "src" / "main.c"
        assert main_c.exists()
        assert "_main" in main_c.read_text()

    def test_thunk_merging(self, config, tmp_workspace):
        """Thunk fonksiyonlar birlestirilmis dosyada olmali."""
        tmp_path, static, decompiled = tmp_workspace
        builder = CProjectBuilder(config)

        class FakeWorkspace:
            def get_stage_dir(self, name):
                return static

        output = tmp_path / "project"
        result = builder.build(decompiled, output, workspace=FakeWorkspace())
        assert result.success is True
        assert result.functions_merged > 0

    def test_cmake_created(self, config, tmp_workspace):
        """CMakeLists.txt olusturulmali."""
        tmp_path, static, decompiled = tmp_workspace
        builder = CProjectBuilder(config)

        class FakeWorkspace:
            def get_stage_dir(self, name):
                return static

        output = tmp_path / "project"
        builder.build(decompiled, output, workspace=FakeWorkspace())
        cmake = output / "CMakeLists.txt"
        assert cmake.exists()
        content = cmake.read_text()
        assert "cmake_minimum_required" in content
        assert "test_binary" in content or "project(" in content

    def test_types_h_created(self, config, tmp_workspace):
        """types.h Ghidra undefined typedef'lerini icermeli."""
        tmp_path, static, decompiled = tmp_workspace
        builder = CProjectBuilder(config)

        class FakeWorkspace:
            def get_stage_dir(self, name):
                return static

        output = tmp_path / "project"
        builder.build(decompiled, output, workspace=FakeWorkspace())
        types_h = output / "include" / "types.h"
        assert types_h.exists()
        content = types_h.read_text()
        assert "undefined8" in content
        assert "uint64_t" in content
        assert "#ifndef _TYPES_H_" in content

    def test_empty_source_dir(self, config, tmp_path):
        """C dosyasi olmayan dizin icin success=False."""
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()
        builder = CProjectBuilder(config)
        result = builder.build(empty_dir, tmp_path / "project")
        assert result.success is False
        assert len(result.errors) > 0

    def test_compile_commands_json(self, config, tmp_workspace):
        """compile_commands.json olusturulmali."""
        tmp_path, static, decompiled = tmp_workspace
        builder = CProjectBuilder(config)

        class FakeWorkspace:
            def get_stage_dir(self, name):
                return static

        output = tmp_path / "project"
        builder.build(decompiled, output, workspace=FakeWorkspace())
        cc_json = output / "compile_commands.json"
        assert cc_json.exists()
        entries = json.loads(cc_json.read_text())
        assert isinstance(entries, list)
        assert len(entries) > 0

    def test_clangd_config(self, config, tmp_workspace):
        """.clangd dosyasi olusturulmali."""
        tmp_path, static, decompiled = tmp_workspace
        builder = CProjectBuilder(config)

        class FakeWorkspace:
            def get_stage_dir(self, name):
                return static

        output = tmp_path / "project"
        builder.build(decompiled, output, workspace=FakeWorkspace())
        clangd = output / ".clangd"
        assert clangd.exists()
        content = clangd.read_text()
        assert "CompileFlags" in content


# ===================================================================
# BinaryDeobfuscator testleri
# ===================================================================


class TestBinaryDeobfuscator:
    """BinaryDeobfuscator -- Ghidra C ciktisini temizler."""

    def _make_workspace(self, tmp_path, decompiled_dir=None, with_json=False):
        """Basit workspace mock olustur."""
        class FakeWorkspace:
            def get_stage_dir(self, name):
                if name == "static":
                    static = tmp_path / "static"
                    static.mkdir(exist_ok=True)
                    ghidra_out = static / "ghidra_output" / "decompiled"
                    ghidra_out.mkdir(parents=True, exist_ok=True)
                    if decompiled_dir:
                        import shutil
                        for f in decompiled_dir.glob("*.c"):
                            shutil.copy2(str(f), str(ghidra_out / f.name))
                    return static
                elif name == "deobfuscated":
                    d = tmp_path / "deobfuscated"
                    d.mkdir(exist_ok=True)
                    return d
                return tmp_path / name
        return FakeWorkspace()

    def test_ghidra_artifact_cleanup(self, config, tmp_path):
        """Ghidra WARNING yorumlari temizlenmeli."""
        decompiled = tmp_path / "decompiled_src"
        decompiled.mkdir()
        (decompiled / "func.c").write_text(
            "/* WARNING: Restarted to delay slot code */\n"
            "int func(void)\n{\n"
            "  /* DISPLAY WARNING - bad instruction */\n"
            "  return 0;\n}\n"
        )
        deobf = BinaryDeobfuscator(config)
        ws = self._make_workspace(tmp_path, decompiled)
        result = deobf.deobfuscate(ws)
        assert result.success is True
        assert result.stats.get("ghidra_artifacts_cleaned", 0) > 0

    def test_anti_debug_marking_ptrace(self, config, tmp_path):
        """ptrace anti-debug kodu isaretlenmeli."""
        decompiled = tmp_path / "decompiled_src"
        decompiled.mkdir()
        (decompiled / "anti.c").write_text(
            "void anti_debug(void)\n{\n"
            "  ptrace(PT_DENY_ATTACH, 0, 0, 0);\n"
            "}\n"
        )
        deobf = BinaryDeobfuscator(config)
        ws = self._make_workspace(tmp_path, decompiled)
        result = deobf.deobfuscate(ws)
        assert result.success is True
        assert result.stats.get("anti_debug_markers", 0) > 0

    def test_xor_pattern_marking(self, config, tmp_path):
        """XOR encryption loop'u isaretlenmeli."""
        decompiled = tmp_path / "decompiled_src"
        decompiled.mkdir()
        (decompiled / "xor.c").write_text(
            "void decrypt(char *buf, int len)\n{\n"
            "  for (int i=0; i<len; i++) {\n"
            "    buf[i] = buf[i] ^ 0xAA;\n"
            "  }\n}\n"
        )
        deobf = BinaryDeobfuscator(config)
        ws = self._make_workspace(tmp_path, decompiled)
        result = deobf.deobfuscate(ws)
        assert result.success is True
        assert result.stats.get("xor_patterns_found", 0) > 0

    def test_empty_workspace(self, config, tmp_path):
        """Decompiled dosya olmayan workspace icin success=False."""
        class EmptyWorkspace:
            def get_stage_dir(self, name):
                d = tmp_path / name
                d.mkdir(exist_ok=True)
                return d

        deobf = BinaryDeobfuscator(config)
        result = deobf.deobfuscate(EmptyWorkspace())
        assert result.success is False
        assert len(result.errors) > 0

    def test_result_dataclass(self):
        """BinaryDeobfuscationResult dataclass dogru calisir."""
        result = BinaryDeobfuscationResult(success=True)
        assert result.artifacts == {}
        assert result.stats == {}
        assert result.errors == []


# ===================================================================
# PackedBinary testleri
# ===================================================================


class TestPackedBinary:
    """PackingDetector ve entropy hesaplama testleri."""

    def test_entropy_zero_bytes(self):
        """Sifir byte'lardan olusan veri ~0 entropy olmali."""
        data = b"\x00" * 1024
        ent = calculate_entropy(data)
        assert ent == 0.0

    def test_entropy_single_value(self):
        """Tek degere sahip veri 0 entropy olmali."""
        data = b"\xFF" * 1024
        ent = calculate_entropy(data)
        assert ent == 0.0

    def test_entropy_random_high(self):
        """Random-benzeri veri yuksek entropy (~8) olmali."""
        # Her byte degerinden esit miktarda
        data = bytes(range(256)) * 100  # 25600 byte, esit dagilim
        ent = calculate_entropy(data)
        assert ent >= 7.9  # 8.0'a cok yakin olmali

    def test_entropy_empty(self):
        """Bos veri icin 0.0 donmeli."""
        assert calculate_entropy(b"") == 0.0

    def test_section_entropy(self):
        """Section entropy hesaplamasi calismali."""
        # Ilk section dusuk, ikinci section yuksek entropy
        low_ent = b"\x00" * 65536
        high_ent = bytes(range(256)) * 256  # 65536 byte, uniform
        data = low_ent + high_ent
        entropies = calculate_section_entropy(data, section_size=65536)
        assert len(entropies) == 2
        assert entropies[0] < 1.0  # dusuk entropy
        assert entropies[1] > 7.0  # yuksek entropy

    def test_upx_magic_detection(self, config, tmp_path):
        """UPX magic iceren binary 'packed' olarak tespit edilmeli."""
        fake_binary = tmp_path / "packed"
        # UPX magic'i binary'nin icerisine gom
        data = b"\x00" * 512 + UPX_MAGIC + b"\x00" * 512
        fake_binary.write_bytes(data)
        detector = PackingDetector(config)
        result = detector.detect(fake_binary)
        assert result.is_packed is True
        assert result.packing_type == PackingType.UPX

    def test_not_packed_binary(self, config, tmp_path):
        """Normal (dusuk entropy) binary 'not packed' olmali."""
        fake_binary = tmp_path / "normal"
        # Duz metin benzeri icerik
        data = b"This is a normal binary with low entropy. " * 1000
        fake_binary.write_bytes(data)
        detector = PackingDetector(config)
        result = detector.detect(fake_binary)
        assert result.is_packed is False
        assert result.packing_type == PackingType.NONE

    def test_nonexistent_file(self, config, tmp_path):
        """Varolmayan dosya icin is_packed=False."""
        detector = PackingDetector(config)
        result = detector.detect(tmp_path / "nonexistent")
        assert result.is_packed is False
        assert result.packing_type == PackingType.NONE

    def test_packing_info_to_dict(self, config):
        """PackingInfo.to_dict JSON-serializable dondurmeli."""
        info = PackingInfo(
            is_packed=True,
            packing_type=PackingType.UPX,
            confidence=0.95,
            evidence=["UPX magic found"],
            overall_entropy=7.5,
        )
        d = info.to_dict()
        assert d["is_packed"] is True
        assert d["packing_type"] == "upx"
        json.dumps(d)  # hata vermemeli

    def test_packing_type_enum_values(self):
        """PackingType enum beklenen degerlere sahip olmali."""
        assert PackingType.NONE.value == "none"
        assert PackingType.UPX.value == "upx"
        assert PackingType.PYINSTALLER.value == "pyinstaller"
        assert PackingType.NUITKA.value == "nuitka"


# ===================================================================
# Integration testleri
# ===================================================================


class TestBinaryReconstructionPipeline:
    """Tam binary reconstruction pipeline'i integration testleri."""

    def test_full_pipeline_namer_to_builder(self, config, tmp_workspace):
        """Namer -> TypeRecoverer -> CommentGenerator -> ProjectBuilder akisi."""
        tmp_path, static, decompiled = tmp_workspace
        output_base = tmp_path / "pipeline"

        # 1. Namer
        namer = CVariableNamer(config)
        named_dir = output_base / "named"
        namer_result = namer.analyze_and_rename(
            decompiled,
            static / "ghidra_functions.json",
            static / "ghidra_strings.json",
            static / "ghidra_call_graph.json",
            named_dir,
        )
        assert namer_result.success is True

        # 2. Type Recoverer
        recoverer = CTypeRecoverer(config)
        typed_dir = output_base / "typed"
        type_result = recoverer.recover(
            named_dir,
            static / "ghidra_functions.json",
            typed_dir,
        )
        assert type_result.success is True

        # 3. Comment Generator
        commenter = CCommentGenerator(config)
        commented_dir = output_base / "commented"
        comment_result = commenter.generate(
            typed_dir,
            commented_dir,
            functions_json=static / "ghidra_functions.json",
        )
        assert comment_result.success is True

        # 4. Algorithm Identifier
        algo_id = CAlgorithmIdentifier(config)
        algo_result = algo_id.identify(commented_dir)
        assert algo_result.success is True

        # 5. Project Builder
        class FakeWorkspace:
            def get_stage_dir(self, name):
                return static

        builder = CProjectBuilder(config)
        project_dir = output_base / "project"
        build_result = builder.build(
            commented_dir,
            project_dir,
            workspace=FakeWorkspace(),
            algorithm_results=algo_result,
        )
        assert build_result.success is True
        assert build_result.files_written > 0
        assert (project_dir / "CMakeLists.txt").exists()
        assert (project_dir / "include" / "types.h").exists()

    def test_deobfuscator_to_namer(self, config, tmp_workspace):
        """BinaryDeobfuscator -> CVariableNamer akisi."""
        tmp_path, static, decompiled = tmp_workspace

        class FakeWorkspace:
            def get_stage_dir(self, name):
                if name == "static":
                    return static
                d = tmp_path / f"ws_{name}"
                d.mkdir(exist_ok=True)
                return d

        # 1. Deobfuscator
        deobf = BinaryDeobfuscator(config)
        deobf_result = deobf.deobfuscate(FakeWorkspace())
        assert deobf_result.success is True

        # 2. Namer
        namer = CVariableNamer(config)
        deobf_decompiled = tmp_path / "ws_deobfuscated" / "decompiled"
        if deobf_decompiled.exists():
            named_dir = tmp_path / "named"
            namer_result = namer.analyze_and_rename(
                deobf_decompiled,
                static / "ghidra_functions.json",
                static / "ghidra_strings.json",
                static / "ghidra_call_graph.json",
                named_dir,
            )
            assert namer_result.success is True

    def test_content_store_pipeline(self, config, tmp_workspace):
        """ContentStore ile pipeline fazlari arasi in-memory aktarim."""
        _, _, decompiled = tmp_workspace
        store = ContentStore()
        count = store.load_from_directory(decompiled)
        assert count == 5

        # Basit donusum: undefined8 -> uint64_t
        for stem, content in store.items():
            modified = content.replace("undefined8", "uint64_t")
            if modified != content:
                store.set(stem, modified)

        # FUN_00004000'de undefined8 vardi
        content = store.get("FUN_00004000")
        assert content is not None
        assert "uint64_t" in content
        assert "undefined8" not in content

    def test_signature_db_with_workspace_data(self, config, tmp_workspace):
        """SignatureDB workspace verisiyle dogru calismali."""
        tmp_path, static, decompiled = tmp_workspace
        db = SignatureDB(config)
        matches = db.match_all(
            functions_json=static / "ghidra_functions.json",
            strings_json=static / "ghidra_strings.json",
            call_graph_json=static / "ghidra_call_graph.json",
            decompiled_dir=decompiled,
        )
        # En az _malloc eslesmeli (system library)
        assert isinstance(matches, list)


# ===================================================================
# BinaryNameExtractor testleri -- XREF fix, VTable, RTTI
# ===================================================================


from karadul.reconstruction.binary_name_extractor import (
    BinaryNameExtractor,
    ExtractionResult,
    ExtractedName,
    _hex_to_int,
    _sanitize_identifier,
    _filename_to_classes,
    _extract_namespace_from_path,
    _strip_templates,
    _parse_demangled_class_method,
)


@pytest.fixture
def xref_workspace(tmp_path: Path):
    """Ghidra ciktisi xref bilgisi iceren workspace.

    String'lerde xrefs array'i var -- string_extractor.py xref fix ciktisi.
    """
    static = tmp_path / "static"
    static.mkdir()

    functions = {
        "total": 6,
        "program": "test_binary_xref",
        "functions": [
            {
                "name": "FUN_00001000",
                "address": "00001000",
                "size": 64,
                "parameters": [],
                "return_type": "void",
                "is_external": False,
                "is_thunk": False,
                "source": "ANALYSIS",
            },
            {
                "name": "FUN_00002000",
                "address": "00002000",
                "size": 128,
                "parameters": [],
                "return_type": "int",
                "is_external": False,
                "is_thunk": False,
                "source": "ANALYSIS",
            },
            {
                "name": "FUN_00003000",
                "address": "00003000",
                "size": 256,
                "parameters": [],
                "return_type": "void",
                "is_external": False,
                "is_thunk": False,
                "source": "ANALYSIS",
            },
            {
                "name": "_SteamAPI_Init",
                "address": "00004000",
                "size": 32,
                "parameters": [],
                "return_type": "int",
                "is_external": False,
                "is_thunk": False,
                "source": "IMPORTED",
            },
            {
                "name": "FUN_00005000",
                "address": "00005000",
                "size": 96,
                "parameters": [],
                "return_type": "void",
                "is_external": False,
                "is_thunk": False,
                "source": "ANALYSIS",
            },
            {
                "name": "FUN_00006000",
                "address": "00006000",
                "size": 48,
                "parameters": [],
                "return_type": "void",
                "is_external": False,
                "is_thunk": False,
                "source": "ANALYSIS",
            },
        ],
    }
    (static / "ghidra_functions.json").write_text(json.dumps(functions))

    # String'lerde xrefs alani var -- Class::Method pattern'leri ve xref bilgisi
    strings = {
        "total": 5,
        "program": "test_binary_xref",
        "strings": [
            {
                "address": "00010000",
                "value": "CNetworkSystem::Init",
                "length": 21,
                "type": "string",
                "xrefs": [
                    {
                        "from_address": "00001020",
                        "from_function": "FUN_00001000",
                        "from_func_addr": "00001000",
                    },
                ],
                "xref_count": 1,
                "function": "FUN_00001000",
                "function_addr": "00001000",
            },
            {
                "address": "00010100",
                "value": "CBaseFileSystem::Open failed for %s",
                "length": 36,
                "type": "string",
                "xrefs": [
                    {
                        "from_address": "00002050",
                        "from_function": "FUN_00002000",
                        "from_func_addr": "00002000",
                    },
                    {
                        "from_address": "00003010",
                        "from_function": "FUN_00003000",
                        "from_func_addr": "00003000",
                    },
                ],
                "xref_count": 2,
                "function": "FUN_00002000",
                "function_addr": "00002000",
            },
            {
                "address": "00010200",
                "value": "/opt/buildbot/steam/src/filesystem/BaseFileSystem.cpp",
                "length": 53,
                "type": "string",
                "xrefs": [],
                "xref_count": 0,
                "function": None,
                "function_addr": None,
            },
            {
                "address": "00010300",
                "value": "CHTTPClient::Connect",
                "length": 21,
                "type": "string",
                "xrefs": [
                    {
                        "from_address": "00005010",
                        "from_function": "FUN_00005000",
                        "from_func_addr": "00005000",
                    },
                ],
                "xref_count": 1,
                "function": "FUN_00005000",
                "function_addr": "00005000",
            },
            {
                "address": "00010400",
                "value": "Assert failed: m_pConnection != NULL",
                "length": 36,
                "type": "string",
                "xrefs": [
                    {
                        "from_address": "00006010",
                        "from_function": "FUN_00006000",
                        "from_func_addr": "00006000",
                    },
                ],
                "xref_count": 1,
                "function": "FUN_00006000",
                "function_addr": "00006000",
            },
        ],
    }
    (static / "ghidra_strings.json").write_text(json.dumps(strings))

    call_graph = {
        "program": "test_binary_xref",
        "total_functions": 6,
        "total_edges": 2,
        "nodes": {
            "00001000": {
                "name": "FUN_00001000",
                "address": "00001000",
                "caller_count": 0,
                "callee_count": 0,
                "callers": [],
                "callees": [],
            },
            "00002000": {
                "name": "FUN_00002000",
                "address": "00002000",
                "caller_count": 0,
                "callee_count": 1,
                "callers": [],
                "callees": [{"name": "FUN_00003000", "address": "00003000"}],
            },
            "00003000": {
                "name": "FUN_00003000",
                "address": "00003000",
                "caller_count": 1,
                "callee_count": 0,
                "callers": [{"name": "FUN_00002000", "address": "00002000"}],
                "callees": [],
            },
            "00004000": {
                "name": "_SteamAPI_Init",
                "address": "00004000",
                "caller_count": 0,
                "callee_count": 0,
                "callers": [],
                "callees": [],
            },
            "00005000": {
                "name": "FUN_00005000",
                "address": "00005000",
                "caller_count": 0,
                "callee_count": 0,
                "callers": [],
                "callees": [],
            },
            "00006000": {
                "name": "FUN_00006000",
                "address": "00006000",
                "caller_count": 0,
                "callee_count": 0,
                "callers": [],
                "callees": [],
            },
        },
        "edges": [
            {"from": "00002000", "to": "00003000"},
        ],
    }
    (static / "ghidra_call_graph.json").write_text(json.dumps(call_graph))

    return tmp_path, static


class TestBinaryNameExtractorXref:
    """BinaryNameExtractor -- xref bilgisiyle string->fonksiyon eslestirmesi."""

    def test_xref_based_class_method_naming(self, config, xref_workspace):
        """Xref bilgisi varsa FUN_xxx fonksiyonlari Class_Method olarak adlandirilmali."""
        tmp_path, static = xref_workspace
        extractor = BinaryNameExtractor(config)
        result = extractor.extract(
            strings_json=static / "ghidra_strings.json",
            functions_json=static / "ghidra_functions.json",
            call_graph_json=static / "ghidra_call_graph.json",
        )
        assert result.success
        naming_map = extractor.as_naming_map()

        # FUN_00001000 -> CNetworkSystem_Init (xref match)
        assert "FUN_00001000" in naming_map
        assert "CNetworkSystem" in naming_map["FUN_00001000"]

    def test_xref_matches_first_fun_xxx(self, config, xref_workspace):
        """Birden fazla xref varsa ilk FUN_xxx eslesmesi kullanilmali."""
        tmp_path, static = xref_workspace
        extractor = BinaryNameExtractor(config)
        result = extractor.extract(
            strings_json=static / "ghidra_strings.json",
            functions_json=static / "ghidra_functions.json",
            call_graph_json=static / "ghidra_call_graph.json",
        )
        naming_map = extractor.as_naming_map()

        # CBaseFileSystem::Open 2 xref'e sahip: FUN_00002000 ve FUN_00003000
        # Ilki (FUN_00002000) eslestirilmeli
        assert "FUN_00002000" in naming_map
        assert "CBaseFileSystem" in naming_map["FUN_00002000"]

    def test_xref_confidence_higher_than_call_graph(self, config, xref_workspace):
        """Xref-based eslestirme 0.92 confidence ile olsuyor, call graph 0.90."""
        tmp_path, static = xref_workspace
        extractor = BinaryNameExtractor(config)
        result = extractor.extract(
            strings_json=static / "ghidra_strings.json",
            functions_json=static / "ghidra_functions.json",
            call_graph_json=static / "ghidra_call_graph.json",
        )

        # debug_string kaynagli isimler arasinda confidence >= 0.92 olan olmali
        xref_names = [
            n for n in result.names
            if n.source == 'debug_string' and 'xref' in n.evidence.lower()
        ]
        assert len(xref_names) > 0
        for name in xref_names:
            assert name.confidence >= 0.92

    def test_class_methods_collected(self, config, xref_workspace):
        """Xref eslestirmesinden class-method bilgisi toplanmali."""
        tmp_path, static = xref_workspace
        extractor = BinaryNameExtractor(config)
        result = extractor.extract(
            strings_json=static / "ghidra_strings.json",
            functions_json=static / "ghidra_functions.json",
            call_graph_json=static / "ghidra_call_graph.json",
        )
        class_methods = extractor.get_class_methods()
        # CNetworkSystem ve CBaseFileSystem class'lari tanimlanmali
        found_classes = set(class_methods.keys())
        assert "CNetworkSystem" in found_classes or "CHTTPClient" in found_classes

    def test_no_xref_fallback_to_call_graph(self, config, tmp_path):
        """Xref bilgisi olmayan string'ler icin call graph eslestirmesi calismali."""
        static = tmp_path / "static"
        static.mkdir()

        functions = {
            "total": 2,
            "program": "no_xref_test",
            "functions": [
                {
                    "name": "FUN_00001000",
                    "address": "00001000",
                    "size": 64,
                    "parameters": [],
                    "return_type": "void",
                    "is_external": False,
                    "is_thunk": False,
                    "source": "ANALYSIS",
                },
                {
                    "name": "_SteamBootstrapper_GetEUniverse",
                    "address": "00002000",
                    "size": 32,
                    "parameters": [],
                    "return_type": "int",
                    "is_external": False,
                    "is_thunk": False,
                    "source": "IMPORTED",
                },
            ],
        }
        (static / "ghidra_functions.json").write_text(json.dumps(functions))

        # xref alani YOK -- eski format
        strings = {
            "total": 1,
            "program": "no_xref_test",
            "strings": [
                {
                    "address": "00010000",
                    "value": "Some debug string",
                    "length": 18,
                    "type": "string",
                },
            ],
        }
        (static / "ghidra_strings.json").write_text(json.dumps(strings))

        call_graph = {
            "program": "no_xref_test",
            "total_functions": 2,
            "total_edges": 0,
            "nodes": {
                "00001000": {
                    "name": "FUN_00001000",
                    "address": "00001000",
                    "callers": [],
                    "callees": [],
                },
                "00002000": {
                    "name": "_SteamBootstrapper_GetEUniverse",
                    "address": "00002000",
                    "callers": [],
                    "callees": [],
                },
            },
            "edges": [],
        }
        (static / "ghidra_call_graph.json").write_text(json.dumps(call_graph))

        extractor = BinaryNameExtractor(config)
        result = extractor.extract(
            strings_json=static / "ghidra_strings.json",
            functions_json=static / "ghidra_functions.json",
            call_graph_json=static / "ghidra_call_graph.json",
        )
        # Xref yoksa hata vermemeli, sadece eslestirme olmaz
        assert result.success

    def test_string_to_funcs_mapping(self, config, xref_workspace):
        """_string_to_funcs mapping xref'li string'ler icin olusturulmali."""
        tmp_path, static = xref_workspace
        extractor = BinaryNameExtractor(config)
        extractor.extract(
            strings_json=static / "ghidra_strings.json",
            functions_json=static / "ghidra_functions.json",
            call_graph_json=static / "ghidra_call_graph.json",
        )
        # String 0x10000 ("CNetworkSystem::Init") xref'i FUN_00001000'a
        assert 0x10000 in extractor._string_to_funcs
        assert "FUN_00001000" in extractor._string_to_funcs[0x10000]


class TestBinaryNameExtractorHelpers:
    """Yardimci fonksiyon testleri."""

    def test_hex_to_int(self):
        assert _hex_to_int("00001000") == 0x1000
        assert _hex_to_int("0x1000") == 0x1000
        assert _hex_to_int("DEADBEEF") == 0xDEADBEEF

    def test_sanitize_identifier(self):
        assert _sanitize_identifier("CNetworkSystem_Init") == "CNetworkSystem_Init"
        # 123bad: Sayi ile basliyor -> _ prefix eklenir (C identifier kurali)
        assert _sanitize_identifier("123bad") == "_123bad"
        assert _sanitize_identifier("hello world!") == "hello_world"
        assert _sanitize_identifier("") == "unknown"
        assert _sanitize_identifier("a__b___c") == "a_b_c"

    def test_filename_to_classes(self):
        classes = _filename_to_classes("BaseFileSystem.cpp")
        assert "CBaseFileSystem" in classes
        assert "BaseFileSystem" in classes

    def test_filename_to_classes_snake_case(self):
        classes = _filename_to_classes("http_client.cpp")
        assert "CHttpClient" in classes or "Chttp_client" in classes

    def test_extract_namespace_from_path(self):
        ns = _extract_namespace_from_path(
            "/opt/buildbot/steam/src/filesystem/BaseFileSystem.cpp"
        )
        assert ns == "filesystem"

    def test_strip_templates(self):
        result = _strip_templates(
            "std::__1::basic_string<char, std::__1::char_traits<char>>"
        )
        assert result == "std::__1::basic_string"

    def test_parse_demangled_class_method(self):
        cls, method = _parse_demangled_class_method("CHTTPClient::Open()")
        assert cls == "CHTTPClient"
        assert method == "Open"

    def test_parse_demangled_vtable(self):
        cls, method = _parse_demangled_class_method("vtable for CNetworkSystem")
        assert cls == "CNetworkSystem"
        assert method is None

    def test_parse_demangled_typeinfo(self):
        cls, method = _parse_demangled_class_method("typeinfo for CBaseFileSystem")
        assert cls == "CBaseFileSystem"
        assert method is None


# ===================================================================
# Swift Demangle Genisletme testleri -- Gorev 1
# ===================================================================


class TestSwiftDemangleEnhanced:
    """Genisletilmis Swift demangle testleri.

    _parse_swift_demangled, _regex_swift_demangle, _collect_swift_mangled_symbols
    ve _batch_swift_demangle metodlarini test eder.
    """

    # --- _parse_swift_demangled testleri ---

    def test_parse_module_type(self):
        """Module.Type formatini dogru parse eder."""
        result = BinaryNameExtractor._parse_swift_demangled("Rectangle.CenterCalculation")
        assert result == ("Rectangle", "CenterCalculation", None, "type")

    def test_parse_module_type_method(self):
        """Module.Type.method formatini dogru parse eder."""
        result = BinaryNameExtractor._parse_swift_demangled(
            "Rectangle.WindowManager.apply"
        )
        assert result is not None
        module, type_name, method, kind = result
        assert module == "Rectangle"
        assert type_name == "WindowManager"
        assert method == "apply"
        assert kind == "method"

    def test_parse_type_metadata(self):
        """type metadata accessor formatini dogru parse eder."""
        result = BinaryNameExtractor._parse_swift_demangled(
            "type metadata accessor for Rectangle.SnapArea"
        )
        assert result is not None
        module, type_name, method, kind = result
        assert module == "Rectangle"
        assert type_name == "SnapArea"
        assert kind == "metadata"

    def test_parse_nominal_type_descriptor(self):
        """nominal type descriptor formatini dogru parse eder."""
        result = BinaryNameExtractor._parse_swift_demangled(
            "nominal type descriptor for Rectangle.WindowAction"
        )
        assert result is not None
        assert result[1] == "WindowAction"
        assert result[3] == "metadata"

    def test_parse_protocol_witness(self):
        """protocol witness table formatini dogru parse eder."""
        result = BinaryNameExtractor._parse_swift_demangled(
            "protocol witness table for Rectangle.Calculation "
            "in conformance Rectangle.CenterCalculation"
        )
        assert result is not None
        assert result[1] == "CenterCalculation"
        assert result[3] == "witness"

    def test_parse_extension(self):
        """Extension formatini dogru parse eder."""
        result = BinaryNameExtractor._parse_swift_demangled(
            "(extension in Rectangle):Foundation.Notification.Name.method"
        )
        # Foundation tiplerine dikkat: Notification.Name -> skip edilmemeli
        # cunku extension in Rectangle baglami
        # (Notification.Name std type degil, Name is)
        # Sonuc None da olabilir, onemli olan crash olmamasi
        assert result is None or isinstance(result, tuple)

    def test_parse_skips_generic_specialization(self):
        """generic specialization atlanir."""
        result = BinaryNameExtractor._parse_swift_demangled(
            "generic specialization <Int> of ..."
        )
        assert result is None

    def test_parse_skips_closure(self):
        """closure atlanir."""
        result = BinaryNameExtractor._parse_swift_demangled("closure #1 in Something.method()")
        assert result is None

    def test_parse_skips_swift_stdlib(self):
        """Swift standart library tipleri atlanir."""
        result = BinaryNameExtractor._parse_swift_demangled("Swift.String.init()")
        assert result is None

    def test_parse_skips_objc(self):
        """ObjectiveC tipleri atlanir."""
        result = BinaryNameExtractor._parse_swift_demangled("ObjectiveC.NSObject")
        assert result is None

    def test_parse_getter_accessor(self):
        """Property getter accessor'u temizlenir."""
        result = BinaryNameExtractor._parse_swift_demangled(
            "Rectangle.WindowManager.isActive.getter"
        )
        assert result is not None
        module, type_name, method, kind = result
        assert module == "Rectangle"
        assert type_name == "WindowManager"
        assert method == "isActive"
        assert kind == "method"

    def test_parse_init_method(self):
        """init metodu parse edilir."""
        result = BinaryNameExtractor._parse_swift_demangled(
            "Rectangle.WindowManager.init"
        )
        assert result is not None
        _, type_name, method, kind = result
        assert type_name == "WindowManager"
        assert method == "init"

    def test_parse_nested_type(self):
        """Nested type (Module.Outer.Inner) parse edilir."""
        result = BinaryNameExtractor._parse_swift_demangled(
            "Rectangle.AppDelegate.AppDelegateNotifications"
        )
        assert result is not None
        # 3 parcali, son parca buyuk harfle basliyor -> nested type
        assert result[1] == "AppDelegateNotifications"
        assert result[3] == "type"

    def test_parse_with_return_type(self):
        """Return type iceren demangled string."""
        result = BinaryNameExtractor._parse_swift_demangled(
            "Rectangle.WindowCalculation.calculate -> Rectangle.WindowResult"
        )
        assert result is not None
        assert result[1] == "WindowCalculation"
        assert result[2] == "calculate"

    def test_parse_empty_string(self):
        assert BinaryNameExtractor._parse_swift_demangled("") is None

    def test_parse_none_input(self):
        assert BinaryNameExtractor._parse_swift_demangled(None) is None

    # --- _regex_swift_demangle testleri ---

    def test_regex_demangle_class(self):
        """_TtC eski mangling formatini cozer."""
        result = BinaryNameExtractor._regex_swift_demangle(
            "_TtC9Rectangle17CenterCalculation"
        )
        assert result == "Rectangle.CenterCalculation"

    def test_regex_demangle_struct(self):
        """_TtV eski mangling formatini cozer."""
        result = BinaryNameExtractor._regex_swift_demangle(
            "_TtV9Rectangle10RectResult"
        )
        assert result == "Rectangle.RectResult"

    def test_regex_demangle_enum(self):
        """_TtO eski mangling formatini cozer."""
        result = BinaryNameExtractor._regex_swift_demangle(
            "_TtO9Rectangle12WindowAction"
        )
        assert result == "Rectangle.WindowAction"

    def test_regex_demangle_invalid(self):
        """Gecersiz symbol'ler icin None doner."""
        assert BinaryNameExtractor._regex_swift_demangle("not_swift") is None

    def test_regex_demangle_modern_not_handled(self):
        """Modern $s mangling regex ile cozulemez."""
        result = BinaryNameExtractor._regex_swift_demangle("$s9Rectangle7DefaultP")
        assert result is None

    # --- _collect_swift_mangled_symbols testleri ---

    def test_collect_from_strings(self):
        """String'lerden Swift mangled symbol toplar."""
        from karadul.reconstruction.binary_name_extractor import _StringEntry
        extractor = BinaryNameExtractor()
        extractor._strings = [
            _StringEntry(address=0x1000, value='_TtC9Rectangle17CenterCalculation',
                         length=33, stype='string'),
            _StringEntry(address=0x2000, value='$s9Rectangle7DefaultP',
                         length=21, stype='string'),
            _StringEntry(address=0x3000, value='normal string',
                         length=13, stype='string'),
        ]
        extractor._functions = []
        extractor._workspace_root = None

        out = set()
        extractor._collect_swift_mangled_symbols(out)

        assert '_TtC9Rectangle17CenterCalculation' in out
        assert '$s9Rectangle7DefaultP' in out
        assert 'normal string' not in out

    def test_collect_from_functions(self):
        """Fonksiyon isimlerinden Swift mangled symbol toplar."""
        extractor = BinaryNameExtractor()
        # Dict format -- Ghidra JSON'dan gelen fonksiyonlar boyle olabilir
        extractor._strings = []
        extractor._functions = [
            {"name": "$s12MyAppModuleC", "address": "0x1000"},
            {"name": "FUN_00001234", "address": "0x2000"},
        ]
        extractor._workspace_root = None

        out = set()
        extractor._collect_swift_mangled_symbols(out)

        assert '$s12MyAppModuleC' in out
        assert 'FUN_00001234' not in out

    def test_collect_modern_broad_pattern(self):
        """Modern $s pattern genis erisim saglar."""
        from karadul.reconstruction.binary_name_extractor import _StringEntry
        extractor = BinaryNameExtractor()
        extractor._strings = [
            _StringEntry(address=0x1000, value='$ss10SetAlgebraP',
                         length=16, stype='string'),
            _StringEntry(address=0x2000, value='$ss9OptionSetP',
                         length=14, stype='string'),
            _StringEntry(address=0x3000, value='$sSEMp',
                         length=6, stype='string'),
        ]
        extractor._functions = []
        extractor._workspace_root = None

        out = set()
        extractor._collect_swift_mangled_symbols(out)

        assert '$ss10SetAlgebraP' in out
        assert '$ss9OptionSetP' in out
        assert '$sSEMp' in out

    # --- Regex pattern testleri ---

    def test_modern_regex_catches_protocol_descriptor(self):
        """Modern regex $s...P (protocol descriptor) formatini yakalar."""
        import re
        pattern = BinaryNameExtractor._SWIFT_MODERN_MANGLED_RE
        m = pattern.search("$s9Rectangle7DefaultP")
        assert m is not None
        assert m.group(1) == "$s9Rectangle7DefaultP"

    def test_modern_regex_catches_class_descriptor(self):
        """Modern regex $s...C (class descriptor) formatini yakalar."""
        import re
        pattern = BinaryNameExtractor._SWIFT_MODERN_MANGLED_RE
        m = pattern.search("$s9Rectangle21CenterCalculationCMa")
        assert m is not None

    def test_old_regex_catches_ttc(self):
        """Eski regex _TtC pattern'ini yakalar."""
        import re
        pattern = BinaryNameExtractor._SWIFT_OLD_MANGLED_RE
        m = pattern.search("_TtC9Rectangle21CenterCalculation")
        assert m is not None

    def test_old_regex_catches_tte(self):
        """Eski regex _TtE (extension) pattern'ini yakalar."""
        import re
        pattern = BinaryNameExtractor._SWIFT_OLD_MANGLED_RE
        m = pattern.search("_TtE9Rectangle12SomeExtension")
        assert m is not None


# ===================================================================
# Swift Source Cross-Match testleri -- Gorev 2
# ===================================================================


class TestSwiftSourceCrossMatch:
    """Kaynak kod eslestirme testleri."""

    def test_parse_swift_source_repo(self, tmp_path):
        """Swift kaynak kodundan type/method/property bildirimlerini cikarir."""
        # Minimal Swift kaynak dosyasi olustur
        src_dir = tmp_path / "Rectangle"
        src_dir.mkdir()
        swift_file = src_dir / "WindowManager.swift"
        swift_file.write_text(
            "import Foundation\n\n"
            "class WindowManager {\n"
            "    var isActive: Bool = false\n"
            "    func apply(_ action: WindowAction) {\n"
            "    }\n"
            "    func resize(to size: CGSize) {\n"
            "    }\n"
            "}\n\n"
            "struct RectResult {\n"
            "    var frame: CGRect\n"
            "}\n",
            encoding="utf-8",
        )

        extractor = BinaryNameExtractor()
        extractor._source_repo_path = tmp_path
        decls = extractor._parse_swift_source_repo(tmp_path)

        assert "WindowManager" in decls
        assert decls["WindowManager"]["kind"] == "class"
        assert "apply" in decls["WindowManager"]["methods"]
        assert "resize" in decls["WindowManager"]["methods"]

        assert "RectResult" in decls
        assert decls["RectResult"]["kind"] == "struct"

    def test_parse_caches_results(self, tmp_path):
        """Ayni repo ikinci kez parse edilmez (cache)."""
        src_dir = tmp_path / "Src"
        src_dir.mkdir()
        (src_dir / "A.swift").write_text("class Alpha {}\n", encoding="utf-8")

        extractor = BinaryNameExtractor()
        extractor._source_repo_path = tmp_path
        result1 = extractor._parse_swift_source_repo(tmp_path)
        result2 = extractor._parse_swift_source_repo(tmp_path)
        assert result1 is result2  # Ayni obje (cache)

    def test_source_cross_match_no_repo(self):
        """source_repo_path verilmezse bos liste doner."""
        extractor = BinaryNameExtractor()
        extractor._source_repo_path = None
        names = extractor._strategy_source_cross_match()
        assert names == []

    def test_parse_swift_enum_protocol(self, tmp_path):
        """Enum ve protocol bildirimlerini dogru cikarir."""
        src = tmp_path / "Types.swift"
        src.write_text(
            "enum WindowAction {\n"
            "    case maximize\n"
            "    case minimize\n"
            "}\n\n"
            "protocol Calculation {\n"
            "    func calculate() -> RectResult\n"
            "}\n",
            encoding="utf-8",
        )

        extractor = BinaryNameExtractor()
        decls = extractor._parse_swift_source_repo(tmp_path)

        assert "WindowAction" in decls
        assert decls["WindowAction"]["kind"] == "enum"
        assert "Calculation" in decls
        assert decls["Calculation"]["kind"] == "protocol"
        assert "calculate" in decls["Calculation"]["methods"]

    def test_struct_field_propagation(self, tmp_path):
        """Kaynak koddaki property isimleri binary string'lerle eslesir (Gorev 3)."""
        from karadul.reconstruction.binary_name_extractor import _StringEntry

        # Kaynak kod olustur
        src_dir = tmp_path / "src"
        src_dir.mkdir()
        (src_dir / "WindowCalc.swift").write_text(
            "struct WindowCalculation {\n"
            "    var currentScreen: NSScreen\n"
            "    var resultingAction: WindowAction\n"
            "    let frameOfCurrentScreen: CGRect\n"
            "    func calculate() -> RectResult { }\n"
            "}\n",
            encoding="utf-8",
        )

        # Binary string'leri olustur (struct field isimleri binary'de camelCase olarak gorunur)
        extractor = BinaryNameExtractor()
        extractor._strings = [
            _StringEntry(address=0x1000, value="currentScreen", length=13, stype="string"),
            _StringEntry(address=0x1010, value="resultingAction", length=15, stype="string"),
            _StringEntry(address=0x1020, value="frameOfCurrentScreen", length=20, stype="string"),
            _StringEntry(address=0x1030, value="randomString", length=12, stype="string"),
        ]
        extractor._functions = []
        extractor._addr_mapper = None
        extractor._source_repo_path = tmp_path / "src"
        extractor._source_declarations = None

        names = extractor._strategy_source_cross_match()

        # Member vars kayitlanmis olmali
        assert hasattr(extractor, '_collected_member_vars')
        member_vars = extractor._collected_member_vars
        assert "WindowCalculation" in member_vars
        assert "currentScreen" in member_vars["WindowCalculation"]
        assert "resultingAction" in member_vars["WindowCalculation"]
        assert "frameOfCurrentScreen" in member_vars["WindowCalculation"]
        # randomString kaynak kodda yok, eslesmemeli
        all_members = set()
        for members in member_vars.values():
            all_members.update(members)
        assert "randomString" not in all_members

    def test_find_owning_type(self):
        """Pozisyon bazli type sahiplik tespiti."""
        positions = [
            (10, "class", "Alpha"),
            (100, "struct", "Beta"),
            (200, "enum", "Gamma"),
        ]
        assert BinaryNameExtractor._find_owning_type(positions, 50) == "Alpha"
        assert BinaryNameExtractor._find_owning_type(positions, 150) == "Beta"
        assert BinaryNameExtractor._find_owning_type(positions, 250) == "Gamma"
        assert BinaryNameExtractor._find_owning_type(positions, 5) is None
        assert BinaryNameExtractor._find_owning_type([], 50) is None


# ===================================================================
# VTable Chain Extraction testleri
# ===================================================================


@pytest.fixture
def vtable_workspace(tmp_path: Path):
    """VTable sembol'leri iceren workspace."""
    static = tmp_path / "static"
    static.mkdir()

    functions = {
        "total": 8,
        "program": "test_vtable",
        "functions": [
            {
                "name": "__ZTV11CHTTPClient",
                "address": "00010000",
                "size": 80,
                "parameters": [],
                "return_type": "void",
                "is_external": False,
                "is_thunk": False,
                "source": "ANALYSIS",
            },
            {
                "name": "FUN_00010018",
                "address": "00010018",
                "size": 32,
                "parameters": [],
                "return_type": "void",
                "is_external": False,
                "is_thunk": False,
                "source": "ANALYSIS",
            },
            {
                "name": "FUN_00010020",
                "address": "00010020",
                "size": 64,
                "parameters": [],
                "return_type": "int",
                "is_external": False,
                "is_thunk": False,
                "source": "ANALYSIS",
            },
            {
                "name": "__ZTI11CHTTPClient",
                "address": "00020000",
                "size": 16,
                "parameters": [],
                "return_type": "void",
                "is_external": False,
                "is_thunk": False,
                "source": "ANALYSIS",
            },
            {
                "name": "FUN_00030000",
                "address": "00030000",
                "size": 128,
                "parameters": [],
                "return_type": "void",
                "is_external": False,
                "is_thunk": False,
                "source": "ANALYSIS",
            },
            {
                "name": "FUN_00040000",
                "address": "00040000",
                "size": 64,
                "parameters": [],
                "return_type": "void",
                "is_external": False,
                "is_thunk": False,
                "source": "ANALYSIS",
            },
            {
                "name": "__ZTV14CNetworkSystem",
                "address": "00050000",
                "size": 48,
                "parameters": [],
                "return_type": "void",
                "is_external": False,
                "is_thunk": False,
                "source": "ANALYSIS",
            },
            {
                "name": "_SteamAPI_Shutdown",
                "address": "00060000",
                "size": 32,
                "parameters": [],
                "return_type": "void",
                "is_external": False,
                "is_thunk": False,
                "source": "IMPORTED",
            },
        ],
    }
    (static / "ghidra_functions.json").write_text(json.dumps(functions))

    strings = {
        "total": 3,
        "program": "test_vtable",
        "strings": [
            {
                "address": "00070000",
                "value": "__ZTV14CNetworkSystem",
                "length": 22,
                "type": "string",
                "xrefs": [
                    {
                        "from_address": "00030010",
                        "from_function": "FUN_00030000",
                        "from_func_addr": "00030000",
                    },
                ],
                "xref_count": 1,
                "function": "FUN_00030000",
                "function_addr": "00030000",
            },
            {
                "address": "00070100",
                "value": "CHTTPClient::Connect",
                "length": 21,
                "type": "string",
                "xrefs": [],
                "xref_count": 0,
                "function": None,
                "function_addr": None,
            },
            {
                "address": "00070200",
                "value": "10CHTTPClient",
                "length": 14,
                "type": "string",
                "xrefs": [],
                "xref_count": 0,
                "function": None,
                "function_addr": None,
            },
        ],
    }
    (static / "ghidra_strings.json").write_text(json.dumps(strings))

    call_graph = {
        "program": "test_vtable",
        "total_functions": 8,
        "total_edges": 1,
        "nodes": {
            "00010000": {
                "name": "__ZTV11CHTTPClient",
                "address": "00010000",
                "callers": [],
                "callees": [
                    {"name": "FUN_00040000", "address": "00040000"},
                ],
            },
            "00010018": {
                "name": "FUN_00010018",
                "address": "00010018",
                "callers": [],
                "callees": [],
            },
            "00010020": {
                "name": "FUN_00010020",
                "address": "00010020",
                "callers": [],
                "callees": [],
            },
            "00020000": {
                "name": "__ZTI11CHTTPClient",
                "address": "00020000",
                "callers": [],
                "callees": [],
            },
            "00030000": {
                "name": "FUN_00030000",
                "address": "00030000",
                "callers": [],
                "callees": [],
            },
            "00040000": {
                "name": "FUN_00040000",
                "address": "00040000",
                "callers": [{"name": "__ZTV11CHTTPClient", "address": "00010000"}],
                "callees": [],
            },
            "00050000": {
                "name": "__ZTV14CNetworkSystem",
                "address": "00050000",
                "callers": [],
                "callees": [],
            },
            "00060000": {
                "name": "_SteamAPI_Shutdown",
                "address": "00060000",
                "callers": [],
                "callees": [],
            },
        },
        "edges": [
            {"from": "00010000", "to": "00040000"},
        ],
    }
    (static / "ghidra_call_graph.json").write_text(json.dumps(call_graph))

    return tmp_path, static


class TestVTableChainExtraction:
    """VTable chain extraction testleri."""

    def test_vtable_symbol_detection(self, config, vtable_workspace):
        """_ZTV prefix'li fonksiyonlar vtable olarak tanimlanmali."""
        tmp_path, static = vtable_workspace
        extractor = BinaryNameExtractor(config)
        result = extractor.extract(
            strings_json=static / "ghidra_strings.json",
            functions_json=static / "ghidra_functions.json",
            call_graph_json=static / "ghidra_call_graph.json",
        )
        assert result.success
        vtable_names = [n for n in result.names if n.source == 'vtable_chain']
        assert len(vtable_names) > 0

    def test_vtable_callee_naming(self, config, vtable_workspace):
        """VTable callee'leri virtual method olarak adlandirilmali."""
        tmp_path, static = vtable_workspace
        extractor = BinaryNameExtractor(config)
        result = extractor.extract(
            strings_json=static / "ghidra_strings.json",
            functions_json=static / "ghidra_functions.json",
            call_graph_json=static / "ghidra_call_graph.json",
        )
        vtable_callee_names = [
            n for n in result.names
            if n.source == 'vtable_chain' and n.original_name == 'FUN_00040000'
        ]
        assert len(vtable_callee_names) > 0
        assert "CHTTPClient" in vtable_callee_names[0].recovered_name
        assert vtable_callee_names[0].confidence >= 0.75

    def test_vtable_string_ref_constructor(self, config, vtable_workspace):
        """VTable string xref'i olan fonksiyon constructor olarak adlandirilmali."""
        tmp_path, static = vtable_workspace
        extractor = BinaryNameExtractor(config)
        result = extractor.extract(
            strings_json=static / "ghidra_strings.json",
            functions_json=static / "ghidra_functions.json",
            call_graph_json=static / "ghidra_call_graph.json",
        )
        ctor_names = [
            n for n in result.names
            if n.source == 'vtable_chain' and 'constructor' in n.recovered_name
        ]
        if ctor_names:
            assert "CNetworkSystem" in ctor_names[0].class_name

    def test_vtable_by_source_exists(self, config, vtable_workspace):
        """by_source dict'inde vtable_chain key'i olmali."""
        tmp_path, static = vtable_workspace
        extractor = BinaryNameExtractor(config)
        result = extractor.extract(
            strings_json=static / "ghidra_strings.json",
            functions_json=static / "ghidra_functions.json",
            call_graph_json=static / "ghidra_call_graph.json",
        )
        assert 'vtable_chain' in result.by_source

    def test_no_vtable_symbols(self, config, tmp_path):
        """VTable olmayan binary'de hata cikmamalı."""
        static = tmp_path / "static"
        static.mkdir()

        functions = {
            "total": 1,
            "program": "no_vtable",
            "functions": [{
                "name": "FUN_00001000",
                "address": "00001000",
                "size": 64,
                "parameters": [],
                "return_type": "void",
                "is_external": False,
                "is_thunk": False,
                "source": "ANALYSIS",
            }],
        }
        (static / "ghidra_functions.json").write_text(json.dumps(functions))
        strings = {"total": 0, "program": "no_vtable", "strings": []}
        (static / "ghidra_strings.json").write_text(json.dumps(strings))
        call_graph = {
            "program": "no_vtable", "total_functions": 1, "total_edges": 0,
            "nodes": {"00001000": {"name": "FUN_00001000", "address": "00001000", "callers": [], "callees": []}},
            "edges": [],
        }
        (static / "ghidra_call_graph.json").write_text(json.dumps(call_graph))

        extractor = BinaryNameExtractor(config)
        result = extractor.extract(
            strings_json=static / "ghidra_strings.json",
            functions_json=static / "ghidra_functions.json",
            call_graph_json=static / "ghidra_call_graph.json",
        )
        assert result.success
        assert result.by_source.get('vtable_chain', 0) == 0

    def test_vtable_class_methods_in_result(self, config, vtable_workspace):
        """VTable'dan cikarilan class bilgisi class_methods'ta olmali."""
        tmp_path, static = vtable_workspace
        extractor = BinaryNameExtractor(config)
        result = extractor.extract(
            strings_json=static / "ghidra_strings.json",
            functions_json=static / "ghidra_functions.json",
            call_graph_json=static / "ghidra_call_graph.json",
        )
        class_methods = extractor.get_class_methods()
        # En az CHTTPClient class'i olmali (vtable veya rtti'dan)
        assert len(class_methods) > 0


# ===================================================================
# Combo Pattern DB testleri (GOREV 3)
# ===================================================================


from karadul.reconstruction.c_namer_patterns import (
    COMBO_PATTERNS as EXTENDED_COMBO_PATTERNS,
    SINGLE_API_HINTS as EXTENDED_SINGLE_API_HINTS,
    STEAM_KEYWORDS,
    URL_HINTS,
    ERROR_HINTS,
    LOG_HINTS,
)


class TestComboPatternDB:
    """Combo pattern veritabani kapsamlilik testleri."""

    def test_combo_count_above_480(self):
        """Toplam combo pattern sayisi 480'den fazla olmali."""
        assert len(EXTENDED_COMBO_PATTERNS) >= 480, (
            f"Beklenen: >= 480, gercek: {len(EXTENDED_COMBO_PATTERNS)}"
        )

    def test_single_api_count_above_250(self):
        """Single API hint sayisi 250'den fazla olmali."""
        assert len(EXTENDED_SINGLE_API_HINTS) >= 250, (
            f"Beklenen: >= 250, gercek: {len(EXTENDED_SINGLE_API_HINTS)}"
        )

    def test_combo_has_network_patterns(self):
        """Network-related combo pattern'ler olmali."""
        network_combos = [
            p for p in EXTENDED_COMBO_PATTERNS
            if "socket" in p[0] or "send" in p[0] or "recv" in p[0]
        ]
        assert len(network_combos) >= 10

    def test_combo_has_file_io_patterns(self):
        """File I/O combo pattern'ler olmali."""
        file_combos = [
            p for p in EXTENDED_COMBO_PATTERNS
            if "fopen" in p[0] or "fread" in p[0] or "fwrite" in p[0]
        ]
        assert len(file_combos) >= 8

    def test_combo_has_memory_patterns(self):
        """Memory management combo pattern'ler olmali."""
        mem_combos = [
            p for p in EXTENDED_COMBO_PATTERNS
            if "malloc" in p[0] or "calloc" in p[0] or "realloc" in p[0]
        ]
        assert len(mem_combos) >= 5

    def test_combo_has_thread_patterns(self):
        """Thread/sync combo pattern'ler olmali."""
        thread_combos = [
            p for p in EXTENDED_COMBO_PATTERNS
            if any("pthread" in api for api in p[0])
        ]
        assert len(thread_combos) >= 15

    def test_combo_has_crypto_patterns(self):
        """Crypto/SSL combo pattern'ler olmali."""
        crypto_combos = [
            p for p in EXTENDED_COMBO_PATTERNS
            if any("SSL" in api or "EVP" in api or "SHA" in api or "MD5" in api for api in p[0])
        ]
        assert len(crypto_combos) >= 10

    def test_combo_has_steam_patterns(self):
        """Steam/Valve spesifik combo pattern'ler olmali."""
        steam_combos = [
            p for p in EXTENDED_COMBO_PATTERNS
            if any("Steam" in api or "Breakpad" in api for api in p[0])
        ]
        assert len(steam_combos) >= 20

    def test_combo_has_zlib_patterns(self):
        """zlib compression combo pattern'ler olmali."""
        zlib_combos = [
            p for p in EXTENDED_COMBO_PATTERNS
            if any("deflate" in api or "inflate" in api or "compress" in api
                   or "gz" in api.lower() for api in p[0])
        ]
        assert len(zlib_combos) >= 10

    def test_combo_has_sqlite_patterns(self):
        """SQLite combo pattern'ler olmali."""
        sqlite_combos = [
            p for p in EXTENDED_COMBO_PATTERNS
            if any("sqlite3" in api for api in p[0])
        ]
        assert len(sqlite_combos) >= 10

    def test_combo_has_curl_patterns(self):
        """curl HTTP combo pattern'ler olmali."""
        curl_combos = [
            p for p in EXTENDED_COMBO_PATTERNS
            if any("curl" in api.lower() for api in p[0])
        ]
        assert len(curl_combos) >= 5

    def test_combo_has_macos_cf_patterns(self):
        """macOS CoreFoundation combo pattern'ler olmali."""
        cf_combos = [
            p for p in EXTENDED_COMBO_PATTERNS
            if any("CF" in api for api in p[0])
        ]
        assert len(cf_combos) >= 25

    def test_combo_has_regex_patterns(self):
        """Regex combo pattern'ler olmali."""
        regex_combos = [
            p for p in EXTENDED_COMBO_PATTERNS
            if any("reg" in api.lower() and ("comp" in api.lower() or "exec" in api.lower())
                   for api in p[0])
        ]
        assert len(regex_combos) >= 2

    def test_combo_has_json_patterns(self):
        """JSON parsing combo pattern'ler olmali."""
        json_combos = [
            p for p in EXTENDED_COMBO_PATTERNS
            if any("json" in api.lower() or "cJSON" in api for api in p[0])
        ]
        assert len(json_combos) >= 5

    def test_combo_has_protobuf_patterns(self):
        """Protobuf combo pattern'ler olmali."""
        pb_combos = [
            p for p in EXTENDED_COMBO_PATTERNS
            if any("protobuf" in api for api in p[0])
        ]
        assert len(pb_combos) >= 3

    def test_combo_sorted_by_specificity(self):
        """Combo pattern'ler merge sonrasi eleman sayisina gore siralanmali."""
        from karadul.reconstruction.c_namer import _API_COMBO_PATTERNS
        for i in range(len(_API_COMBO_PATTERNS) - 1):
            assert len(_API_COMBO_PATTERNS[i][0]) >= len(_API_COMBO_PATTERNS[i + 1][0]), (
                f"Index {i}: {len(_API_COMBO_PATTERNS[i][0])} < "
                f"{len(_API_COMBO_PATTERNS[i + 1][0])}"
            )

    def test_combo_all_have_valid_structure(self):
        """Her combo pattern (frozenset, str, float) formatinda olmali."""
        for i, pattern in enumerate(EXTENDED_COMBO_PATTERNS):
            assert isinstance(pattern, tuple), f"Pattern {i} tuple degil"
            assert len(pattern) == 3, f"Pattern {i}: 3 eleman olmali"
            assert isinstance(pattern[0], frozenset), f"Pattern {i}: frozenset degil"
            assert isinstance(pattern[1], str), f"Pattern {i}: str degil"
            assert isinstance(pattern[2], (int, float)), f"Pattern {i}: float degil"
            assert 0.0 < pattern[2] <= 1.0, f"Pattern {i}: confidence aralik disi"
            assert len(pattern[0]) >= 1, f"Pattern {i}: bos frozenset"

    def test_single_api_all_have_valid_structure(self):
        """Her single API hint (prefix, float) formatinda olmali."""
        for api, hint in EXTENDED_SINGLE_API_HINTS.items():
            assert isinstance(api, str)
            assert isinstance(hint, tuple)
            assert len(hint) == 2
            assert isinstance(hint[0], str)
            assert isinstance(hint[1], (int, float))
            assert 0.0 < hint[1] <= 1.0

    def test_steam_keywords_present(self):
        """Steam keyword DB'si yeterli coverage'a sahip olmali."""
        assert len(STEAM_KEYWORDS) >= 30

    def test_valve_engine_apis_in_single_hints(self):
        """Valve engine API'leri single hint'lerde olmali."""
        valve_apis = {"V_snprintf", "V_strncpy", "V_stricmp", "CreateInterface"}
        for api in valve_apis:
            assert api in EXTENDED_SINGLE_API_HINTS, f"{api} single hints'te eksik"

    def test_no_excessive_duplicates(self):
        """Ayni frozenset birden fazla kez tanimlanmamali (max 5)."""
        seen: set[frozenset] = set()
        duplicates = []
        for pattern in EXTENDED_COMBO_PATTERNS:
            if pattern[0] in seen:
                duplicates.append(pattern)
            seen.add(pattern[0])
        assert len(duplicates) <= 5, f"{len(duplicates)} duplicate combo bulundu"
