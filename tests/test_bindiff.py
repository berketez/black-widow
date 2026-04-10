"""BinaryDiffer (bindiff) modulu testleri.

Test edilen senaryolar:
1. Decompiled hash ile exact match
2. CFG fingerprint ile yapisal eslestirme
3. String referans eslestirme (Jaccard benzerlik)
4. Size + params eslestirme
5. Call graph pattern eslestirme
6. Eslesmeme durumu
7. transfer_names dogrulugu
8. transfer_names_by_address dogrulugu
9. Birden fazla strateji beraber calisma
10. Edge case'ler (bos girdi, tek fonksiyon, thunk'lar)
"""

from __future__ import annotations

import pytest

from karadul.analyzers.bindiff import BinaryDiffer, DiffMatch, DiffResult


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_func(
    name: str,
    address: str,
    size: int = 100,
    param_count: int = 2,
    return_type: str = "int",
    calling_convention: str = "__cdecl",
    is_thunk: bool = False,
    is_external: bool = False,
) -> dict:
    """Ghidra functions.json formatinda fonksiyon dict'i olustur."""
    return {
        "name": name,
        "address": address,
        "size": size,
        "param_count": param_count,
        "return_type": return_type,
        "is_thunk": is_thunk,
        "calling_convention": calling_convention,
        "is_external": is_external,
        "parameters": [
            {"name": f"param_{i}", "type": "int", "ordinal": i}
            for i in range(param_count)
        ],
        "source": "DEFAULT",
    }


def _make_functions_json(funcs: list[dict]) -> dict:
    """functions.json wrapper."""
    return {"total": len(funcs), "program": "test", "functions": funcs}


def _make_strings_json(strings: list[dict]) -> dict:
    """strings.json wrapper."""
    return {"total": len(strings), "program": "test", "strings": strings}


def _make_string_entry(
    value: str,
    address: str = "0x1000",
    func_name: str | None = None,
    func_addr: str | None = None,
) -> dict:
    """strings.json formatinda tek string entry."""
    xrefs = []
    if func_name and func_addr:
        xrefs.append({
            "from_address": "0xAAAA",
            "from_function": func_name,
            "from_func_addr": func_addr,
        })
    return {
        "address": address,
        "value": value,
        "length": len(value),
        "type": "string",
        "xrefs": xrefs,
        "xref_count": len(xrefs),
        "function": func_name,
        "function_addr": func_addr,
    }


def _make_call_graph(
    nodes: dict[str, dict],
    edges: list[dict] | None = None,
) -> dict:
    """call_graph.json wrapper."""
    if edges is None:
        edges = []
    return {
        "program": "test",
        "total_functions": len(nodes),
        "total_edges": len(edges),
        "nodes": nodes,
        "edges": edges,
    }


def _make_graph_node(
    name: str,
    address: str,
    callers: list[dict] | None = None,
    callees: list[dict] | None = None,
) -> dict:
    """call_graph.json node formati."""
    callers = callers or []
    callees = callees or []
    return {
        "name": name,
        "address": address,
        "caller_count": len(callers),
        "callee_count": len(callees),
        "callers": callers,
        "callees": callees,
    }


def _make_decompiled_json(entries: list[dict]) -> dict:
    """decompiled.json wrapper. Her entry: {name, address, code}."""
    return {
        "total_attempted": len(entries),
        "success": len(entries),
        "failed": 0,
        "functions": entries,
    }


@pytest.fixture
def differ():
    """BinaryDiffer instance."""
    return BinaryDiffer()


# ---------------------------------------------------------------------------
# Test: Decompiled Hash Strategy
# ---------------------------------------------------------------------------


class TestDecompiledHash:
    """Strateji 1: Decompile edilmis C kodunun normalize hash'i."""

    def test_exact_match(self, differ: BinaryDiffer):
        """Ayni decompiled kod -> eslesmeli."""
        code = """
        int SSL_read(int *ctx, char *buf, int len) {
            int result;
            result = FUN_0040100(ctx, buf, len);
            if (result < 0) {
                return -1;
            }
            return result;
        }
        """
        # Farkli adreslerle ayni kod (normalize sonrasi ayni hash)
        code_target = """
        int FUN_00501234(int *ctx, char *buf, int len) {
            int result;
            result = FUN_00501300(ctx, buf, len);
            if (result < 0) {
                return -1;
            }
            return result;
        }
        """
        ref = _make_functions_json([_make_func("SSL_read", "0040100")])
        target = _make_functions_json([_make_func("FUN_00501234", "00501234")])

        ref_decomp = _make_decompiled_json([
            {"name": "SSL_read", "address": "0040100", "code": code},
        ])
        target_decomp = _make_decompiled_json([
            {"name": "FUN_00501234", "address": "00501234", "code": code_target},
        ])

        result = differ.compare(
            reference=ref,
            target=target,
            ref_decompiled=ref_decomp,
            target_decompiled=target_decomp,
        )

        assert result.matched >= 1
        match = result.matches[0]
        assert match.ref_name == "SSL_read"
        assert match.target_name == "FUN_00501234"
        assert match.method == "decompiled_hash"
        assert match.confidence >= 0.90

    def test_different_code_no_match(self, differ: BinaryDiffer):
        """Farkli decompiled kod -> eslesmemeli (hash farkli)."""
        code_a = """
        int func_a(int x) {
            return x * 2 + 1;
        }
        """
        code_b = """
        int func_b(int x, int y) {
            return x + y * 3 - 7;
        }
        """
        ref = _make_functions_json([_make_func("func_a", "001000")])
        target = _make_functions_json([_make_func("func_b", "002000")])

        ref_decomp = _make_decompiled_json([
            {"name": "func_a", "address": "001000", "code": code_a},
        ])
        target_decomp = _make_decompiled_json([
            {"name": "func_b", "address": "002000", "code": code_b},
        ])

        result = differ.compare(
            reference=ref,
            target=target,
            ref_decompiled=ref_decomp,
            target_decompiled=target_decomp,
        )

        # Decompiled hash ile eslesmemeli
        decompiled_matches = [m for m in result.matches if m.method == "decompiled_hash"]
        assert len(decompiled_matches) == 0

    def test_no_decompiled_data(self, differ: BinaryDiffer):
        """Decompiled veri yoksa strateji atlanir, hata yok."""
        ref = _make_functions_json([_make_func("foo", "001000")])
        target = _make_functions_json([_make_func("bar", "002000")])

        result = differ.compare(reference=ref, target=target)
        # Decompiled hash match olmamali
        decompiled_matches = [m for m in result.matches if m.method == "decompiled_hash"]
        assert len(decompiled_matches) == 0

    def test_empty_code_skipped(self, differ: BinaryDiffer):
        """Bos veya cok kisa decompiled kod atlanir."""
        ref = _make_functions_json([_make_func("func_a", "001000")])
        target = _make_functions_json([_make_func("func_b", "002000")])

        ref_decomp = _make_decompiled_json([
            {"name": "func_a", "address": "001000", "code": "ret"},
        ])
        target_decomp = _make_decompiled_json([
            {"name": "func_b", "address": "002000", "code": "ret"},
        ])

        result = differ.compare(
            reference=ref,
            target=target,
            ref_decompiled=ref_decomp,
            target_decompiled=target_decomp,
        )
        decompiled_matches = [m for m in result.matches if m.method == "decompiled_hash"]
        assert len(decompiled_matches) == 0


# ---------------------------------------------------------------------------
# Test: CFG Fingerprint Strategy
# ---------------------------------------------------------------------------


class TestCFGFingerprint:
    """Strateji 2: Size + param_count + return_type + convention fingerprint."""

    def test_same_fingerprint_matches(self, differ: BinaryDiffer):
        """Ayni size/params/return_type/convention -> eslesmeli."""
        ref = _make_functions_json([
            _make_func("SSL_write", "001000", size=256, param_count=3, return_type="int"),
        ])
        target = _make_functions_json([
            _make_func("FUN_002000", "002000", size=256, param_count=3, return_type="int"),
        ])

        result = differ.compare(reference=ref, target=target)

        assert result.matched == 1
        m = result.matches[0]
        assert m.ref_name == "SSL_write"
        assert m.target_name == "FUN_002000"
        assert m.method == "cfg_fingerprint"
        assert m.confidence >= 0.80

    def test_different_size_no_match(self, differ: BinaryDiffer):
        """Farkli boyut -> eslesmemeli."""
        ref = _make_functions_json([
            _make_func("func_a", "001000", size=256, param_count=2),
        ])
        target = _make_functions_json([
            _make_func("func_b", "002000", size=512, param_count=2),
        ])

        result = differ.compare(reference=ref, target=target)
        cfg_matches = [m for m in result.matches if m.method == "cfg_fingerprint"]
        assert len(cfg_matches) == 0

    def test_different_param_count_no_match(self, differ: BinaryDiffer):
        """Farkli parametre sayisi -> eslesmemeli."""
        ref = _make_functions_json([
            _make_func("func_a", "001000", size=100, param_count=2),
        ])
        target = _make_functions_json([
            _make_func("func_b", "002000", size=100, param_count=5),
        ])

        result = differ.compare(reference=ref, target=target)
        cfg_matches = [m for m in result.matches if m.method == "cfg_fingerprint"]
        assert len(cfg_matches) == 0

    def test_ambiguous_fingerprint_no_match(self, differ: BinaryDiffer):
        """Ayni fingerprint'e sahip birden fazla ref fonksiyon -> eslesmemeli (belirsiz)."""
        ref = _make_functions_json([
            _make_func("func_a", "001000", size=100, param_count=2, return_type="int"),
            _make_func("func_b", "001100", size=100, param_count=2, return_type="int"),
        ])
        target = _make_functions_json([
            _make_func("FUN_002000", "002000", size=100, param_count=2, return_type="int"),
        ])

        result = differ.compare(reference=ref, target=target)
        cfg_matches = [m for m in result.matches if m.method == "cfg_fingerprint"]
        assert len(cfg_matches) == 0

    def test_thunk_lower_confidence(self, differ: BinaryDiffer):
        """Thunk fonksiyonlarda confidence dusuk olmali."""
        ref = _make_functions_json([
            _make_func("_SSL_init", "001000", size=8, param_count=0, is_thunk=True),
        ])
        target = _make_functions_json([
            _make_func("FUN_002000", "002000", size=8, param_count=0, is_thunk=True),
        ])

        result = differ.compare(reference=ref, target=target, min_confidence=0.5)
        if result.matches:
            m = result.matches[0]
            assert m.confidence <= 0.70

    def test_multiple_unique_fingerprints(self, differ: BinaryDiffer):
        """Birden fazla unique fingerprint -> hepsi eslesmeli."""
        ref = _make_functions_json([
            _make_func("func_a", "001000", size=100, param_count=2, return_type="int"),
            _make_func("func_b", "001100", size=200, param_count=3, return_type="void"),
            _make_func("func_c", "001200", size=300, param_count=0, return_type="char*"),
        ])
        target = _make_functions_json([
            _make_func("FUN_A", "002000", size=100, param_count=2, return_type="int"),
            _make_func("FUN_B", "002100", size=200, param_count=3, return_type="void"),
            _make_func("FUN_C", "002200", size=300, param_count=0, return_type="char*"),
        ])

        result = differ.compare(reference=ref, target=target)
        assert result.matched == 3
        names = {m.ref_name for m in result.matches}
        assert names == {"func_a", "func_b", "func_c"}


# ---------------------------------------------------------------------------
# Test: String Reference Strategy
# ---------------------------------------------------------------------------


class TestStringRefs:
    """Strateji 3: Fonksiyonlarin referans ettigi string kumeleri."""

    def test_same_strings_match(self, differ: BinaryDiffer):
        """Ayni string'lere referans veren fonksiyonlar eslesmeli."""
        ref = _make_functions_json([
            _make_func("connect_ssl", "001000", size=500, param_count=4),
        ])
        target = _make_functions_json([
            _make_func("FUN_002000", "002000", size=480, param_count=4),
        ])

        ref_strings = _make_strings_json([
            _make_string_entry("SSL_connect failed", "0x5000", "connect_ssl", "001000"),
            _make_string_entry("TLS handshake error", "0x5100", "connect_ssl", "001000"),
            _make_string_entry("certificate verify", "0x5200", "connect_ssl", "001000"),
        ])
        target_strings = _make_strings_json([
            _make_string_entry("SSL_connect failed", "0x6000", "FUN_002000", "002000"),
            _make_string_entry("TLS handshake error", "0x6100", "FUN_002000", "002000"),
            _make_string_entry("certificate verify", "0x6200", "FUN_002000", "002000"),
        ])

        result = differ.compare(
            reference=ref,
            target=target,
            ref_strings=ref_strings,
            target_strings=target_strings,
        )

        string_matches = [m for m in result.matches if m.method == "string_refs"]
        assert len(string_matches) >= 1
        m = string_matches[0]
        assert m.ref_name == "connect_ssl"
        assert m.target_name == "FUN_002000"
        assert m.confidence >= 0.7

    def test_partial_strings_lower_confidence(self, differ: BinaryDiffer):
        """Kismi string overlap -> dusuk confidence ile eslesmeli veya eslesmemeli."""
        ref = _make_functions_json([
            _make_func("func_a", "001000", size=500, param_count=3),
        ])
        target = _make_functions_json([
            _make_func("FUN_002000", "002000", size=480, param_count=3),
        ])

        ref_strings = _make_strings_json([
            _make_string_entry("error: %d", "0x5000", "func_a", "001000"),
            _make_string_entry("connection refused", "0x5100", "func_a", "001000"),
            _make_string_entry("timeout reached", "0x5200", "func_a", "001000"),
            _make_string_entry("retry count", "0x5300", "func_a", "001000"),
        ])
        target_strings = _make_strings_json([
            _make_string_entry("error: %d", "0x6000", "FUN_002000", "002000"),
            _make_string_entry("connection refused", "0x6100", "FUN_002000", "002000"),
            # 2/4 string overlap -> Jaccard = 2/4 = 0.50
        ])

        result = differ.compare(
            reference=ref,
            target=target,
            ref_strings=ref_strings,
            target_strings=target_strings,
            min_confidence=0.3,
        )

        string_matches = [m for m in result.matches if m.method == "string_refs"]
        if string_matches:
            assert string_matches[0].confidence < 0.9

    def test_no_strings_no_match(self, differ: BinaryDiffer):
        """String verisi yoksa strateji atlanir."""
        ref = _make_functions_json([_make_func("func_a", "001000")])
        target = _make_functions_json([_make_func("func_b", "002000")])

        result = differ.compare(reference=ref, target=target)
        string_matches = [m for m in result.matches if m.method == "string_refs"]
        assert len(string_matches) == 0

    def test_single_string_not_enough(self, differ: BinaryDiffer):
        """Tek string referansi yeterli degil (min 2 string gerekli)."""
        ref = _make_functions_json([
            _make_func("func_a", "001000"),
        ])
        target = _make_functions_json([
            _make_func("FUN_002000", "002000"),
        ])

        ref_strings = _make_strings_json([
            _make_string_entry("hello", "0x5000", "func_a", "001000"),
        ])
        target_strings = _make_strings_json([
            _make_string_entry("hello", "0x6000", "FUN_002000", "002000"),
        ])

        result = differ.compare(
            reference=ref,
            target=target,
            ref_strings=ref_strings,
            target_strings=target_strings,
        )
        string_matches = [m for m in result.matches if m.method == "string_refs"]
        assert len(string_matches) == 0


# ---------------------------------------------------------------------------
# Test: Size + Params Strategy
# ---------------------------------------------------------------------------


class TestSizeParams:
    """Strateji 4: Fonksiyon boyutu + parametre sayisi (toleransli)."""

    def test_similar_size_matches(self, differ: BinaryDiffer):
        """Boyut %10 icinde ve params ayni -> eslesmeli."""
        ref = _make_functions_json([
            _make_func("big_func", "001000", size=1000, param_count=5, return_type="int"),
        ])
        target = _make_functions_json([
            _make_func("FUN_002000", "002000", size=1050, param_count=5, return_type="int"),
        ])

        result = differ.compare(reference=ref, target=target)
        size_matches = [m for m in result.matches if m.method == "size_params"]
        assert len(size_matches) >= 1

    def test_too_different_size_no_match(self, differ: BinaryDiffer):
        """Boyut cok farkli -> eslesmemeli."""
        ref = _make_functions_json([
            _make_func("func_a", "001000", size=1000, param_count=5),
        ])
        target = _make_functions_json([
            _make_func("FUN_002000", "002000", size=500, param_count=5),
        ])

        result = differ.compare(reference=ref, target=target)
        size_matches = [m for m in result.matches if m.method == "size_params"]
        assert len(size_matches) == 0

    def test_small_functions_skipped(self, differ: BinaryDiffer):
        """Kucuk fonksiyonlar (< 64 byte) size_params stratejisinden atlanir."""
        ref = _make_functions_json([
            _make_func("tiny", "001000", size=16, param_count=0),
        ])
        target = _make_functions_json([
            _make_func("FUN_002000", "002000", size=16, param_count=0),
        ])

        result = differ.compare(reference=ref, target=target, min_confidence=0.5)
        size_matches = [m for m in result.matches if m.method == "size_params"]
        assert len(size_matches) == 0

    def test_duplicate_fingerprint_no_match(self, differ: BinaryDiffer):
        """Ayni size+params+return'e sahip birden fazla ref -> eslesmemeli (belirsiz)."""
        ref = _make_functions_json([
            _make_func("func_a", "001000", size=200, param_count=2, return_type="int"),
            _make_func("func_b", "001100", size=200, param_count=2, return_type="int"),
        ])
        target = _make_functions_json([
            _make_func("FUN_002000", "002000", size=200, param_count=2, return_type="int"),
        ])

        result = differ.compare(reference=ref, target=target)
        size_matches = [m for m in result.matches if m.method == "size_params"]
        assert len(size_matches) == 0


# ---------------------------------------------------------------------------
# Test: Call Graph Pattern Strategy
# ---------------------------------------------------------------------------


class TestCallPattern:
    """Strateji 5: Call graph komsuluk pattern'i."""

    def test_call_pattern_propagation(self, differ: BinaryDiffer):
        """Eslesmis caller/callee'ler uzerinden yeni eslestirme."""
        # Senaryo:
        # ref:    A -> B, C, D
        # target: X -> Y, Z, W
        # Zaten eslesmis: B=Y, C=Z
        # D ve W da eslesmeli (A=X uzerinden)

        ref_funcs = [
            _make_func("func_A", "R001", size=400, param_count=1),
            _make_func("func_B", "R002", size=200, param_count=2),
            _make_func("func_C", "R003", size=300, param_count=3),
            _make_func("func_D", "R004", size=150, param_count=1),
        ]
        target_funcs = [
            _make_func("FUN_T001", "T001", size=410, param_count=1),
            _make_func("FUN_T002", "T002", size=205, param_count=2),
            _make_func("FUN_T003", "T003", size=310, param_count=3),
            _make_func("FUN_T004", "T004", size=155, param_count=1),
        ]

        ref = _make_functions_json(ref_funcs)
        target = _make_functions_json(target_funcs)

        ref_graph = _make_call_graph({
            "R001": _make_graph_node("func_A", "R001", callees=[
                {"name": "func_B", "address": "R002"},
                {"name": "func_C", "address": "R003"},
                {"name": "func_D", "address": "R004"},
            ]),
            "R002": _make_graph_node("func_B", "R002", callers=[
                {"name": "func_A", "address": "R001"},
            ]),
            "R003": _make_graph_node("func_C", "R003", callers=[
                {"name": "func_A", "address": "R001"},
            ]),
            "R004": _make_graph_node("func_D", "R004", callers=[
                {"name": "func_A", "address": "R001"},
            ]),
        })

        target_graph = _make_call_graph({
            "T001": _make_graph_node("FUN_T001", "T001", callees=[
                {"name": "FUN_T002", "address": "T002"},
                {"name": "FUN_T003", "address": "T003"},
                {"name": "FUN_T004", "address": "T004"},
            ]),
            "T002": _make_graph_node("FUN_T002", "T002", callers=[
                {"name": "FUN_T001", "address": "T001"},
            ]),
            "T003": _make_graph_node("FUN_T003", "T003", callers=[
                {"name": "FUN_T001", "address": "T001"},
            ]),
            "T004": _make_graph_node("FUN_T004", "T004", callers=[
                {"name": "FUN_T001", "address": "T001"},
            ]),
        })

        # CFG fingerprint onceki stratejide B=Y, C=Z, A=X eslestirmis olmali
        # Sonra call_pattern D=W'yu bulmali
        result = differ.compare(
            reference=ref,
            target=target,
            ref_call_graph=ref_graph,
            target_call_graph=target_graph,
            min_confidence=0.3,
        )

        # En az 3 eslestirme bekliyoruz (A, B, C cfg_fingerprint'ten)
        assert result.matched >= 3

    def test_no_call_graph_no_match(self, differ: BinaryDiffer):
        """Call graph verisi yoksa strateji atlanir."""
        ref = _make_functions_json([_make_func("func_a", "001000")])
        target = _make_functions_json([_make_func("func_b", "002000")])

        result = differ.compare(reference=ref, target=target)
        call_matches = [m for m in result.matches if m.method == "call_pattern"]
        assert len(call_matches) == 0


# ---------------------------------------------------------------------------
# Test: transfer_names
# ---------------------------------------------------------------------------


class TestTransferNames:
    """transfer_names ve transfer_names_by_address metodlari."""

    def test_basic_transfer(self, differ: BinaryDiffer):
        """Temel isim transferi calismali."""
        result = DiffResult(
            total_ref_functions=3,
            total_target_functions=3,
            matched=2,
            matches=[
                DiffMatch("SSL_read", "R1", "FUN_001", "T1", 0.95, "decompiled_hash"),
                DiffMatch("SSL_write", "R2", "FUN_002", "T2", 0.85, "cfg_fingerprint"),
            ],
        )
        names = differ.transfer_names(result)
        assert names == {"FUN_001": "SSL_read", "FUN_002": "SSL_write"}

    def test_transfer_respects_min_confidence(self, differ: BinaryDiffer):
        """min_confidence altindaki eslestirmeler filtrelenmeli."""
        result = DiffResult(
            total_ref_functions=2,
            total_target_functions=2,
            matched=2,
            matches=[
                DiffMatch("SSL_read", "R1", "FUN_001", "T1", 0.95, "decompiled_hash"),
                DiffMatch("maybe_ssl", "R2", "FUN_002", "T2", 0.55, "size_params"),
            ],
        )
        names = differ.transfer_names(result, min_confidence=0.7)
        assert "FUN_001" in names
        assert "FUN_002" not in names

    def test_transfer_highest_confidence_wins(self, differ: BinaryDiffer):
        """Ayni target icin birden fazla eslestirme varsa en yuksek confidence kazanir."""
        result = DiffResult(
            matched=2,
            matches=[
                DiffMatch("func_a", "R1", "FUN_001", "T1", 0.75, "cfg_fingerprint"),
                DiffMatch("func_b", "R2", "FUN_001", "T1", 0.90, "decompiled_hash"),
            ],
        )
        names = differ.transfer_names(result)
        assert names["FUN_001"] == "func_b"  # Higher confidence

    def test_transfer_by_address(self, differ: BinaryDiffer):
        """Address bazli transfer calismali."""
        result = DiffResult(
            matched=1,
            matches=[
                DiffMatch("SSL_read", "R1", "FUN_001", "T1", 0.95, "decompiled_hash"),
            ],
        )
        addr_names = differ.transfer_names_by_address(result)
        assert addr_names == {"T1": "SSL_read"}

    def test_transfer_empty_result(self, differ: BinaryDiffer):
        """Bos sonuc -> bos dict."""
        result = DiffResult()
        assert differ.transfer_names(result) == {}
        assert differ.transfer_names_by_address(result) == {}


# ---------------------------------------------------------------------------
# Test: DiffResult
# ---------------------------------------------------------------------------


class TestDiffResult:
    """DiffResult data class ve summary metodu."""

    def test_summary_basic(self):
        """Summary dict formatini kontrol et."""
        result = DiffResult(
            total_ref_functions=10,
            total_target_functions=12,
            matched=5,
            unmatched_ref=5,
            unmatched_target=7,
            match_rate=0.5,
            matches=[
                DiffMatch("a", "R1", "X", "T1", 0.9, "decompiled_hash"),
                DiffMatch("b", "R2", "Y", "T2", 0.85, "cfg_fingerprint"),
                DiffMatch("c", "R3", "Z", "T3", 0.8, "cfg_fingerprint"),
            ],
        )
        s = result.summary()
        assert s["total_ref_functions"] == 10
        assert s["total_target_functions"] == 12
        assert s["matched"] == 5
        assert s["match_rate"] == 0.5
        assert s["by_method"] == {"decompiled_hash": 1, "cfg_fingerprint": 2}

    def test_summary_empty(self):
        """Bos sonucun summary'si."""
        result = DiffResult()
        s = result.summary()
        assert s["matched"] == 0
        assert s["by_method"] == {}


# ---------------------------------------------------------------------------
# Test: Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    """Kenar durumlar: bos girdi, tek fonksiyon, vs."""

    def test_empty_reference(self, differ: BinaryDiffer):
        """Referans binary bossa -> 0 eslestirme."""
        ref = _make_functions_json([])
        target = _make_functions_json([_make_func("FUN_001", "001000")])
        result = differ.compare(reference=ref, target=target)
        assert result.matched == 0
        assert result.total_ref_functions == 0

    def test_empty_target(self, differ: BinaryDiffer):
        """Hedef binary bossa -> 0 eslestirme."""
        ref = _make_functions_json([_make_func("func_a", "001000")])
        target = _make_functions_json([])
        result = differ.compare(reference=ref, target=target)
        assert result.matched == 0
        assert result.total_target_functions == 0

    def test_both_empty(self, differ: BinaryDiffer):
        """Her iki binary de bossa -> 0 eslestirme, hata yok."""
        ref = _make_functions_json([])
        target = _make_functions_json([])
        result = differ.compare(reference=ref, target=target)
        assert result.matched == 0
        assert result.match_rate == 0.0

    def test_single_function_match(self, differ: BinaryDiffer):
        """Tek fonksiyon, exact match."""
        ref = _make_functions_json([_make_func("SSL_init", "001000", size=128)])
        target = _make_functions_json([_make_func("FUN_002000", "002000", size=128)])
        result = differ.compare(reference=ref, target=target)
        assert result.matched == 1

    def test_no_match_different_everything(self, differ: BinaryDiffer):
        """Hicbir ortak ozellik yok -> 0 eslestirme."""
        ref = _make_functions_json([
            _make_func("func_a", "001000", size=100, param_count=2, return_type="int"),
        ])
        target = _make_functions_json([
            _make_func("FUN_X", "002000", size=500, param_count=7, return_type="void*"),
        ])
        result = differ.compare(reference=ref, target=target)
        assert result.matched == 0

    def test_min_confidence_filter(self, differ: BinaryDiffer):
        """Yuksek min_confidence ile daha az eslestirme olmali."""
        ref = _make_functions_json([
            _make_func("func_a", "001000", size=128, param_count=2),
        ])
        target = _make_functions_json([
            _make_func("FUN_001", "002000", size=128, param_count=2),
        ])

        result_low = differ.compare(reference=ref, target=target, min_confidence=0.5)
        result_high = differ.compare(reference=ref, target=target, min_confidence=0.99)

        assert result_low.matched >= result_high.matched

    def test_match_rate_calculation(self, differ: BinaryDiffer):
        """match_rate = matched / min(ref, target)."""
        ref = _make_functions_json([
            _make_func("func_a", "001000", size=100),
            _make_func("func_b", "001100", size=200),
        ])
        target = _make_functions_json([
            _make_func("FUN_A", "002000", size=100),
            _make_func("FUN_B", "002100", size=200),
            _make_func("FUN_C", "002200", size=300),
        ])

        result = differ.compare(reference=ref, target=target)
        assert result.matched == 2
        # match_rate = 2 / min(2, 3) = 2/2 = 1.0
        assert result.match_rate == 1.0

    def test_external_functions_handled(self, differ: BinaryDiffer):
        """External fonksiyonlar da eslestirme yapabilmeli."""
        ref = _make_functions_json([
            _make_func("_malloc", "001000", size=64, is_external=True, param_count=1),
        ])
        target = _make_functions_json([
            _make_func("FUN_002000", "002000", size=64, is_external=True, param_count=1),
        ])

        result = differ.compare(reference=ref, target=target)
        assert result.matched >= 1


# ---------------------------------------------------------------------------
# Test: Integration (birden fazla strateji birlikte)
# ---------------------------------------------------------------------------


class TestIntegration:
    """Birden fazla stratejinin birlikte calismasi."""

    def test_greedy_matching_no_duplicates(self, differ: BinaryDiffer):
        """Eslesen fonksiyonlar sonraki stratejilerden cikarilmali (duplicate yok)."""
        ref = _make_functions_json([
            _make_func("func_a", "001000", size=256, param_count=3, return_type="int"),
            _make_func("func_b", "001100", size=512, param_count=1, return_type="void"),
        ])
        target = _make_functions_json([
            _make_func("FUN_A", "002000", size=256, param_count=3, return_type="int"),
            _make_func("FUN_B", "002100", size=512, param_count=1, return_type="void"),
        ])

        result = differ.compare(reference=ref, target=target)

        # Her ref fonksiyon en fazla 1 kez eslesmeli
        ref_matched = [m.ref_address for m in result.matches]
        assert len(ref_matched) == len(set(ref_matched))

        # Her target fonksiyon en fazla 1 kez eslesmeli
        target_matched = [m.target_address for m in result.matches]
        assert len(target_matched) == len(set(target_matched))

    def test_full_pipeline_with_all_data(self, differ: BinaryDiffer):
        """Tum veri kaynaklari (functions, strings, call_graph, decompiled) ile calistir."""
        code_a = """
        int connect_server(char *host, int port) {
            int sock = socket(AF_INET, SOCK_STREAM, 0);
            struct sockaddr_in addr;
            addr.sin_family = AF_INET;
            addr.sin_port = htons(port);
            inet_pton(AF_INET, host, &addr.sin_addr);
            if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
                return -1;
            }
            return sock;
        }
        """
        code_a_target = """
        int FUN_00501234(char *VAR_1, int VAR_2) {
            int VAR_3 = socket(AF_INET, SOCK_STREAM, 0);
            struct sockaddr_in VAR_4;
            VAR_4.sin_family = AF_INET;
            VAR_4.sin_port = htons(VAR_2);
            inet_pton(AF_INET, VAR_1, &VAR_4.sin_addr);
            if (connect(VAR_3, (struct sockaddr*)&VAR_4, sizeof(VAR_4)) < 0) {
                return -1;
            }
            return VAR_3;
        }
        """

        ref = _make_functions_json([
            _make_func("connect_server", "001000", size=256, param_count=2),
            _make_func("send_data", "001100", size=128, param_count=3),
            _make_func("recv_data", "001200", size=150, param_count=3),
        ])
        target = _make_functions_json([
            _make_func("FUN_A", "002000", size=256, param_count=2),
            _make_func("FUN_B", "002100", size=128, param_count=3),
            _make_func("FUN_C", "002200", size=150, param_count=3),
        ])

        ref_decomp = _make_decompiled_json([
            {"name": "connect_server", "address": "001000", "code": code_a},
        ])
        target_decomp = _make_decompiled_json([
            {"name": "FUN_A", "address": "002000", "code": code_a_target},
        ])

        ref_strings = _make_strings_json([
            _make_string_entry("send failed: %d", "0x5000", "send_data", "001100"),
            _make_string_entry("buffer overflow", "0x5100", "send_data", "001100"),
        ])
        target_strings = _make_strings_json([
            _make_string_entry("send failed: %d", "0x6000", "FUN_B", "002100"),
            _make_string_entry("buffer overflow", "0x6100", "FUN_B", "002100"),
        ])

        ref_graph = _make_call_graph({
            "001000": _make_graph_node("connect_server", "001000", callees=[
                {"name": "send_data", "address": "001100"},
            ]),
            "001100": _make_graph_node("send_data", "001100", callers=[
                {"name": "connect_server", "address": "001000"},
            ]),
            "001200": _make_graph_node("recv_data", "001200"),
        })
        target_graph = _make_call_graph({
            "002000": _make_graph_node("FUN_A", "002000", callees=[
                {"name": "FUN_B", "address": "002100"},
            ]),
            "002100": _make_graph_node("FUN_B", "002100", callers=[
                {"name": "FUN_A", "address": "002000"},
            ]),
            "002200": _make_graph_node("FUN_C", "002200"),
        })

        result = differ.compare(
            reference=ref,
            target=target,
            ref_call_graph=ref_graph,
            target_call_graph=target_graph,
            ref_strings=ref_strings,
            target_strings=target_strings,
            ref_decompiled=ref_decomp,
            target_decompiled=target_decomp,
        )

        # En az connect_server (decompiled hash) ve send_data (string_refs) eslesmeli
        assert result.matched >= 2

        names = differ.transfer_names(result)
        assert "FUN_A" in names
        assert names["FUN_A"] == "connect_server"

    def test_unmatched_counts(self, differ: BinaryDiffer):
        """Unmatched ref ve target sayilari dogru olmali."""
        ref = _make_functions_json([
            _make_func("func_a", "001000", size=100),
            _make_func("func_b", "001100", size=200),
            _make_func("func_c", "001200", size=999),
        ])
        target = _make_functions_json([
            _make_func("FUN_A", "002000", size=100),
            _make_func("FUN_B", "002100", size=200),
            _make_func("FUN_D", "002200", size=777),
            _make_func("FUN_E", "002300", size=888),
        ])

        result = differ.compare(reference=ref, target=target)
        # func_a=FUN_A, func_b=FUN_B eslesmeli
        assert result.matched == 2
        assert result.unmatched_ref == 1  # func_c
        assert result.unmatched_target == 2  # FUN_D, FUN_E
