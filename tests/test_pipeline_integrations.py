"""Pipeline entegrasyon testleri -- InlineDetector, DtsNamer, Reverse Propagation, Callee-Based Naming.

Bu testler LLM-siz pipeline iyilestirmelerini dogrular:
1. InlineDetector stages.py entegrasyonu (annotasyon C dosyalarina ekleniyor mu)
2. APIParamDB reverse_propagate_function_names (FUN_xxx callback tespiti)
3. CVariableNamer callee-based naming (callee kombinasyonundan isim tahmini)
4. DtsNamer lokal mod (network yapmadan lokal .d.ts eslestirme)
"""

from __future__ import annotations

import json
import re
import tempfile
from pathlib import Path

import pytest

from karadul.analyzers.inline_detector import InlineDetector
from karadul.reconstruction.api_param_db import APIParamDB
from karadul.reconstruction.dts_namer import DtsNamer


# ---------------------------------------------------------------
# 1. InlineDetector pipeline entegrasyonu
# ---------------------------------------------------------------


class TestInlineDetectorIntegration:
    """InlineDetector'un pipeline'da dogru calistigini dogrula."""

    def test_annotate_code_adds_inline_comments(self):
        """annotate_code() inline pattern bulunca yorum eklemeli."""
        detector = InlineDetector()
        c_code = """\
void func(int x) {
    if (x < 0) x = -x;
    return x;
}
"""
        annotated = detector.annotate_code(c_code)
        assert "/* INLINE: abs()" in annotated
        # Orijinal kod hala mevcut olmali
        assert "if (x < 0) x = -x;" in annotated

    def test_annotate_code_no_match_returns_unchanged(self):
        """Pattern bulunmazsa kod degismemeli."""
        detector = InlineDetector()
        c_code = """\
void func(void) {
    printf("hello");
}
"""
        annotated = detector.annotate_code(c_code)
        assert annotated == c_code

    def test_annotate_writes_to_file(self, tmp_path):
        """Pipeline'da yaptigi gibi dosyaya yazma testi."""
        detector = InlineDetector()
        c_file = tmp_path / "test.c"
        c_file.write_text("""\
void swap_values(int *a, int *b) {
    int tmp = a; a = b; b = tmp;
}
""")
        content = c_file.read_text()
        matches = detector.detect_in_code(content)
        if matches:
            annotated = detector.annotate_code(content)
            c_file.write_text(annotated)
        result = c_file.read_text()
        assert "/* INLINE: swap()" in result

    def test_multiple_files_annotation(self, tmp_path):
        """Birden fazla dosyada inline detection."""
        detector = InlineDetector()

        # abs iceren dosya
        f1 = tmp_path / "file1.c"
        f1.write_text("void f(int x) { if (x < 0) x = -x; }")

        # strlen iceren dosya
        f2 = tmp_path / "file2.c"
        f2.write_text("int f(char *s) { while (*s++) count++; }")

        # Pattern olmayan dosya
        f3 = tmp_path / "file3.c"
        f3.write_text("void f(void) { return; }")

        total_detected = 0
        for c_file in sorted(tmp_path.rglob("*.c")):
            content = c_file.read_text()
            matches = detector.detect_in_code(content)
            if matches:
                annotated = detector.annotate_code(content)
                c_file.write_text(annotated)
                total_detected += len(matches)

        assert total_detected >= 2
        assert "INLINE" in f1.read_text()
        assert "INLINE" not in f3.read_text()

    def test_ternary_min_max(self):
        """min/max ternary pattern tespiti."""
        detector = InlineDetector()
        code = "result = a < b ? a : b;"
        matches = detector.detect_in_code(code)
        assert len(matches) >= 1
        assert matches[0].function_name == "min"

    def test_bswap32_detection(self):
        """32-bit byte swap pattern tespiti."""
        detector = InlineDetector()
        code = "((x >> 24) & 0xFF) | ((x >> 8) & 0xFF00) | ((x << 8) & 0xFF0000) | ((x << 24))"
        matches = detector.detect_in_code(code)
        assert any(m.function_name == "bswap32" for m in matches)


# ---------------------------------------------------------------
# 2. APIParamDB reverse propagation
# ---------------------------------------------------------------


class TestReversePropagate:
    """API callback reverse propagation testleri."""

    def test_ssl_verify_callback(self):
        """SSL_CTX_set_verify'nin 3. parametresi callback olmali."""
        db = APIParamDB()
        c_code = "SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, FUN_1000abc);"
        result = db.reverse_propagate_function_names(c_code)
        assert "FUN_1000abc" in result
        assert result["FUN_1000abc"] == "verify_callback"

    def test_qsort_compare_func(self):
        """qsort'un 4. parametresi compare fonksiyonu olmali."""
        db = APIParamDB()
        c_code = "qsort(arr, n, sizeof(int), FUN_deadbeef);"
        result = db.reverse_propagate_function_names(c_code)
        assert "FUN_deadbeef" in result
        assert result["FUN_deadbeef"] == "compare_func"

    def test_pthread_create_start_routine(self):
        """pthread_create'in 3. parametresi start_routine olmali."""
        db = APIParamDB()
        c_code = "pthread_create(&thread, NULL, FUN_cafebabe, arg);"
        result = db.reverse_propagate_function_names(c_code)
        assert "FUN_cafebabe" in result
        assert result["FUN_cafebabe"] == "thread_start_routine"

    def test_signal_handler(self):
        """signal'in 2. parametresi signal_handler olmali."""
        db = APIParamDB()
        c_code = "signal(SIGINT, FUN_00012345);"
        result = db.reverse_propagate_function_names(c_code)
        assert "FUN_00012345" in result
        assert result["FUN_00012345"] == "signal_handler"

    def test_no_fun_xxx_no_rename(self):
        """FUN_xxx olmayan parametreler rename edilmemeli."""
        db = APIParamDB()
        c_code = "qsort(arr, n, sizeof(int), my_compare);"
        result = db.reverse_propagate_function_names(c_code)
        assert len(result) == 0

    def test_sqlite3_exec_callback(self):
        """sqlite3_exec'in 3. parametresi callback olmali."""
        db = APIParamDB()
        c_code = 'sqlite3_exec(db, "SELECT *", FUN_aabbccdd, NULL, &errmsg);'
        result = db.reverse_propagate_function_names(c_code)
        assert "FUN_aabbccdd" in result
        assert result["FUN_aabbccdd"] == "exec_callback"

    def test_dispatch_async_block(self):
        """dispatch_async'in 2. parametresi block olmali."""
        db = APIParamDB()
        c_code = "dispatch_async(queue, FUN_11223344);"
        result = db.reverse_propagate_function_names(c_code)
        assert "FUN_11223344" in result
        assert result["FUN_11223344"] == "dispatch_block"

    def test_multiple_callbacks_in_same_code(self):
        """Ayni kodda birden fazla callback tespiti."""
        db = APIParamDB()
        c_code = """\
signal(SIGINT, FUN_00001111);
signal(SIGTERM, FUN_00002222);
pthread_create(&t, NULL, FUN_00003333, arg);
"""
        result = db.reverse_propagate_function_names(c_code)
        assert len(result) == 3
        assert result["FUN_00001111"] == "signal_handler"
        assert result["FUN_00002222"] == "signal_handler"
        assert result["FUN_00003333"] == "thread_start_routine"

    def test_atexit_handler(self):
        """atexit'in 1. parametresi exit_handler olmali."""
        db = APIParamDB()
        c_code = "atexit(FUN_aabbcc00);"
        result = db.reverse_propagate_function_names(c_code)
        assert "FUN_aabbcc00" in result
        assert result["FUN_aabbcc00"] == "exit_handler"

    def test_underscore_prefixed_api(self):
        """Mach-O underscore prefix'li API'ler de calismali."""
        db = APIParamDB()
        c_code = "_signal(SIGINT, FUN_00001111);"
        result = db.reverse_propagate_function_names(c_code)
        assert "FUN_00001111" in result


# ---------------------------------------------------------------
# 3. Callee-Based Naming
# ---------------------------------------------------------------


class TestCalleeBasedNaming:
    """CVariableNamer callee-based naming stratejisi testleri."""

    def test_callee_combo_pattern_from_body(self):
        """Fonksiyon body'sindeki callee kombinasyonundan isim tahmini."""
        from karadul.config import Config
        from karadul.reconstruction.c_namer import CVariableNamer

        config = Config()
        namer = CVariableNamer(config)

        # Minimal setup: fonksiyon bilgisi ve body
        namer._func_by_name["FUN_00001234"] = type("Info", (), {
            "name": "FUN_00001234",
            "address": "0x1234",
            "size": 100,
            "params": [],
            "return_type": "void",
            "calling_convention": "",
        })()
        namer._functions["0x1234"] = namer._func_by_name["FUN_00001234"]

        # Body icinde fopen+fread+fclose cagrisi
        namer._func_bodies["FUN_00001234"] = """\
void FUN_00001234(char *path) {
    FILE *f = fopen(path, "rb");
    fread(buf, 1, size, f);
    fclose(f);
}
"""
        # Call graph verisini ekle
        namer._call_graph_in["0x1234"] = 2
        namer._call_graph_out["0x1234"] = 3
        namer._callee_names["0x1234"] = {"fopen", "fread", "fclose"}

        # Stratejiyi calistir
        namer._strategy_call_graph(namer._functions["0x1234"])

        # Callee-based naming sonucu kontrol
        candidates = namer._candidates.get("FUN_00001234", [])
        assert len(candidates) > 0
        callee_candidates = [c for c in candidates if c.strategy == "callee_based"]
        assert len(callee_candidates) > 0
        assert callee_candidates[0].new_name == "read_file"

    def test_callee_single_api_fallback(self):
        """Combo bulunamazsa single API hint'ten isim ver."""
        from karadul.config import Config
        from karadul.reconstruction.c_namer import CVariableNamer

        config = Config()
        namer = CVariableNamer(config)

        namer._func_by_name["FUN_00005678"] = type("Info", (), {
            "name": "FUN_00005678",
            "address": "0x5678",
            "size": 50,
            "params": [],
            "return_type": "int",
            "calling_convention": "",
        })()
        namer._functions["0x5678"] = namer._func_by_name["FUN_00005678"]

        namer._func_bodies["FUN_00005678"] = """\
int FUN_00005678(size_t size) {
    void *ptr = malloc(size);
    return ptr;
}
"""
        namer._call_graph_in["0x5678"] = 5
        namer._call_graph_out["0x5678"] = 1
        namer._callee_names["0x5678"] = {"malloc"}

        namer._strategy_call_graph(namer._functions["0x5678"])

        candidates = namer._candidates.get("FUN_00005678", [])
        callee_candidates = [c for c in candidates if c.strategy == "callee_based"]
        # malloc -> alloc_ prefix
        assert len(callee_candidates) > 0
        assert "alloc_" in callee_candidates[0].new_name

    def test_no_callee_naming_for_non_ghidra(self):
        """Ghidra otomatik ismi olmayan fonksiyonlara callee naming uygulanmamali."""
        from karadul.config import Config
        from karadul.reconstruction.c_namer import CVariableNamer

        config = Config()
        namer = CVariableNamer(config)

        namer._func_by_name["my_function"] = type("Info", (), {
            "name": "my_function",
            "address": "0x9999",
            "size": 100,
            "params": [],
            "return_type": "void",
            "calling_convention": "",
        })()
        namer._functions["0x9999"] = namer._func_by_name["my_function"]
        namer._call_graph_in["0x9999"] = 1
        namer._call_graph_out["0x9999"] = 1
        namer._callee_names["0x9999"] = {"malloc"}

        namer._strategy_call_graph(namer._functions["0x9999"])

        candidates = namer._candidates.get("my_function", [])
        assert len(candidates) == 0


# ---------------------------------------------------------------
# 4. DtsNamer lokal mod
# ---------------------------------------------------------------


class TestDtsNamerLocalMode:
    """DtsNamer network yapmadan lokal eslestirme testleri."""

    def test_namer_with_null_fetcher_returns_no_fetch(self):
        """Network yapmayan DtsNamer fetch_dts_content None donmeli."""
        namer = DtsNamer(fetcher=lambda url: None)
        result = namer.fetch_dts_content("lodash")
        assert result is None

    def test_lokal_dts_file_parsing(self, tmp_path):
        """Lokal .d.ts dosyasindan export parse etme."""
        namer = DtsNamer(fetcher=lambda url: None)
        dts_file = tmp_path / "index.d.ts"
        dts_file.write_text("""\
export declare function createElement(type: string, props?: any): Element;
export declare function render(element: Element, container: HTMLElement): void;
export declare class Component {}
export declare const version: string;
""")
        exports = namer.load_dts_from_file(dts_file)
        assert len(exports) == 4
        names = [e.name for e in exports]
        assert "createElement" in names
        assert "render" in names
        assert "Component" in names
        assert "version" in names

    def test_match_exports_exact(self):
        """Exact match calismali."""
        namer = DtsNamer(fetcher=lambda url: None)
        from karadul.reconstruction.dts_namer import DtsExport
        dts_exports = [
            DtsExport(name="createElement", kind="function"),
            DtsExport(name="render", kind="function"),
        ]
        result = namer.match_exports(
            ["createElement", "render"], dts_exports,
        )
        assert result.method == "exact"
        assert result.confidence == 1.0
        assert len(result.matched) == 2

    def test_match_exports_order_based(self):
        """Order-based eslestirme calismali."""
        namer = DtsNamer(fetcher=lambda url: None)
        from karadul.reconstruction.dts_namer import DtsExport
        dts_exports = [
            DtsExport(name="createElement", kind="function"),
            DtsExport(name="render", kind="function"),
            DtsExport(name="hydrate", kind="function"),
        ]
        result = namer.match_exports(
            ["a", "b", "c"], dts_exports,
        )
        assert "a" in result.matched
        assert result.matched["a"] == "createElement"
        assert result.matched["b"] == "render"
        assert result.matched["c"] == "hydrate"

    def test_dts_integration_with_filesystem(self, tmp_path):
        """Tam entegrasyon: lokal .d.ts + minified exports eslestirme."""
        namer = DtsNamer(fetcher=lambda url: None)

        # Sahte node_modules yapisi olustur
        dts_dir = tmp_path / "node_modules" / "@types" / "lodash"
        dts_dir.mkdir(parents=True)
        dts_file = dts_dir / "index.d.ts"
        dts_file.write_text("""\
export declare function chunk(array: any[], size: number): any[][];
export declare function compact(array: any[]): any[];
export declare function concat(...arrays: any[]): any[];
export declare function difference(array: any[], ...values: any[][]): any[];
""")

        exports = namer.load_dts_from_file(dts_file)
        assert len(exports) == 4

        # Minified export'larla eslesitir
        result = namer.match_exports(
            ["e", "t", "n", "r"], exports,
        )
        assert result.matched.get("e") == "chunk"
        assert result.matched.get("t") == "compact"
        assert result.matched.get("n") == "concat"
        assert result.matched.get("r") == "difference"
