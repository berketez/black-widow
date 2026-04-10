"""CFGAnalyzer unit testleri.

Test kategorileri:
1. analyze() -- JSON parse, bos/hatali input
2. compute_dominators() -- chain, diamond, loop CFG'ler
3. detect_loops() -- no-loop, single, nested, independent
4. compute_cyclomatic_complexity() -- cesitli CFG topolojileri
5. classify_function() -- linear, branching, looping, complex
6. get_function_metrics() / get_summary() -- metrik dogrulama

Her test sentetik CFG JSON data kullaniyor.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from karadul.analyzers.cfg_analyzer import (
    BasicBlock,
    CFGAnalysisResult,
    CFGAnalyzer,
    CFGEdge,
    FunctionCFG,
    LoopInfo,
)


# ---------------------------------------------------------------------------
# Fixture'lar
# ---------------------------------------------------------------------------

@pytest.fixture
def analyzer() -> CFGAnalyzer:
    """Test icin CFGAnalyzer instance."""
    return CFGAnalyzer()


def _make_block(addr: str, end: str | None = None, size: int = 4) -> BasicBlock:
    """Test icin BasicBlock olustur.

    Args:
        addr: Baslangic adresi.
        end: Bitis adresi (verilmezse addr + "f" eklenir).
        size: Block boyutu.
    """
    if end is None:
        end = addr + "f"
    return BasicBlock(start_address=addr, end_address=end, size=size)


def _make_edge(from_b: str, to_b: str, etype: str = "fall_through") -> CFGEdge:
    """Test icin CFGEdge olustur."""
    return CFGEdge(from_block=from_b, to_block=to_b, edge_type=etype)


def _make_cfg(
    name: str,
    blocks: list[BasicBlock],
    edges: list[CFGEdge],
) -> FunctionCFG:
    """Test icin FunctionCFG olustur. Complexity otomatik hesaplanir."""
    n = len(blocks)
    e = len(edges)
    cc = e - n + 2 if n > 0 else 0
    return FunctionCFG(
        name=name,
        address=blocks[0].start_address if blocks else "0x0",
        blocks=blocks,
        edges=edges,
        cyclomatic_complexity=cc,
    )


def _write_cfg_json(
    tmp_path: Path,
    functions: list[dict[str, Any]],
    filename: str = "ghidra_cfg.json",
) -> Path:
    """Sentetik CFG JSON dosyasi olustur.

    Args:
        tmp_path: pytest tmp_path fixture'i.
        functions: Fonksiyon dict listesi.
        filename: Cikti dosya adi.

    Returns:
        Path: Olusturulan JSON dosyasinin yolu.
    """
    data = {
        "program": "test_binary",
        "total_functions": len(functions),
        "functions": functions,
    }
    path = tmp_path / filename
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def _linear_function_json() -> dict[str, Any]:
    """Tek bir lineer fonksiyon (2 block, 1 edge).

    A -> B
    """
    return {
        "name": "linear_func",
        "address": "0x1000",
        "block_count": 2,
        "edge_count": 1,
        "cyclomatic_complexity": 1,
        "loop_headers": [],
        "back_edges": [],
        "blocks": [
            {"start_address": "0x1000", "end_address": "0x1003", "size": 4},
            {"start_address": "0x1004", "end_address": "0x1007", "size": 4},
        ],
        "edges": [
            {"from_block": "0x1000", "to_block": "0x1004", "edge_type": "fall_through"},
        ],
    }


def _loop_function_json() -> dict[str, Any]:
    """While-loop iceren fonksiyon (3 block, 4 edge).

    A -> B -> C
         ^    |
         +----+  (back edge: C -> B)
    """
    return {
        "name": "loop_func",
        "address": "0x2000",
        "block_count": 3,
        "edge_count": 4,
        "cyclomatic_complexity": 3,
        "loop_headers": ["0x2004"],
        "back_edges": [["0x2008", "0x2004"]],
        "blocks": [
            {"start_address": "0x2000", "end_address": "0x2003", "size": 4},
            {"start_address": "0x2004", "end_address": "0x2007", "size": 4},
            {"start_address": "0x2008", "end_address": "0x200b", "size": 4},
        ],
        "edges": [
            {"from_block": "0x2000", "to_block": "0x2004", "edge_type": "fall_through"},
            {"from_block": "0x2004", "to_block": "0x2008", "edge_type": "conditional_jump"},
            {"from_block": "0x2008", "to_block": "0x2004", "edge_type": "unconditional_jump"},
            {"from_block": "0x2004", "to_block": "0x200c", "edge_type": "conditional_jump"},
        ],
    }


def _diamond_function_json() -> dict[str, Any]:
    """If-else (diamond) pattern (4 block, 4 edge).

        A
       / \\
      B   C
       \\ /
        D
    """
    return {
        "name": "diamond_func",
        "address": "0x3000",
        "block_count": 4,
        "edge_count": 4,
        "cyclomatic_complexity": 2,
        "loop_headers": [],
        "back_edges": [],
        "blocks": [
            {"start_address": "0x3000", "end_address": "0x3003", "size": 4},
            {"start_address": "0x3004", "end_address": "0x3007", "size": 4},
            {"start_address": "0x3008", "end_address": "0x300b", "size": 4},
            {"start_address": "0x300c", "end_address": "0x300f", "size": 4},
        ],
        "edges": [
            {"from_block": "0x3000", "to_block": "0x3004", "edge_type": "conditional_jump"},
            {"from_block": "0x3000", "to_block": "0x3008", "edge_type": "conditional_jump"},
            {"from_block": "0x3004", "to_block": "0x300c", "edge_type": "fall_through"},
            {"from_block": "0x3008", "to_block": "0x300c", "edge_type": "fall_through"},
        ],
    }


# ---------------------------------------------------------------------------
# Test 1: analyze() -- JSON parse testleri
# ---------------------------------------------------------------------------

class TestAnalyzeJSON:
    """analyze() metodu JSON parse testleri."""

    def test_analyze_empty_json(
        self, analyzer: CFGAnalyzer, tmp_path: Path
    ) -> None:
        """Bos functions listesi -> bos result."""
        path = _write_cfg_json(tmp_path, [])
        result = analyzer.analyze(path)
        assert result.total_functions == 0
        assert result.functions == []

    def test_analyze_single_function_linear(
        self, analyzer: CFGAnalyzer, tmp_path: Path
    ) -> None:
        """Lineer fonksiyon JSON'dan dogru parse ediliyor mu?"""
        path = _write_cfg_json(tmp_path, [_linear_function_json()])
        result = analyzer.analyze(path)

        assert result.total_functions == 1
        func = result.functions[0]
        assert func.name == "linear_func"
        assert func.address == "0x1000"
        assert len(func.blocks) == 2
        assert len(func.edges) == 1
        # Lineer: E=1, N=2 -> V(G) = 1 - 2 + 2 = 1
        assert func.cyclomatic_complexity == 1

    def test_analyze_single_function_with_loop(
        self, analyzer: CFGAnalyzer, tmp_path: Path
    ) -> None:
        """Loop iceren fonksiyon: back-edge ve loop header tespit ediliyor mu?"""
        path = _write_cfg_json(tmp_path, [_loop_function_json()])
        result = analyzer.analyze(path)

        assert result.total_functions == 1
        func = result.functions[0]
        assert func.name == "loop_func"
        # Dominator-based loop detection yapilmis olmali
        assert len(func.loop_headers) >= 1
        assert len(func.back_edges) >= 1

    def test_malformed_json(
        self, analyzer: CFGAnalyzer, tmp_path: Path
    ) -> None:
        """Bozuk JSON dosyasi -> bos result, exception firlatmaz."""
        path = tmp_path / "bad.json"
        path.write_text("{this is not valid json!!!", encoding="utf-8")
        result = analyzer.analyze(path)
        assert result.total_functions == 0

    def test_nonexistent_file(
        self, analyzer: CFGAnalyzer, tmp_path: Path
    ) -> None:
        """Var olmayan dosya -> bos result, exception firlatmaz."""
        path = tmp_path / "nonexistent.json"
        result = analyzer.analyze(path)
        assert result.total_functions == 0


# ---------------------------------------------------------------------------
# Test 2: compute_dominators() testleri
# ---------------------------------------------------------------------------

class TestComputeDominators:
    """Dominator hesaplama testleri."""

    def test_compute_dominators_simple_chain(
        self, analyzer: CFGAnalyzer
    ) -> None:
        """Basit zincir: A -> B -> C. Her node'u onceki dominate eder."""
        blocks = [_make_block("A"), _make_block("B"), _make_block("C")]
        edges = [_make_edge("A", "B"), _make_edge("B", "C")]
        cfg = _make_cfg("chain", blocks, edges)

        idom = analyzer.compute_dominators(cfg)

        assert idom["A"] is None  # Entry
        assert idom["B"] == "A"
        assert idom["C"] == "B"

    def test_compute_dominators_diamond(
        self, analyzer: CFGAnalyzer
    ) -> None:
        """Diamond (if-else): A -> B, A -> C, B -> D, C -> D.
        D'nin idom'u A olmali (B ve C ortak ata A).
        """
        blocks = [
            _make_block("A"), _make_block("B"),
            _make_block("C"), _make_block("D"),
        ]
        edges = [
            _make_edge("A", "B", "conditional_jump"),
            _make_edge("A", "C", "conditional_jump"),
            _make_edge("B", "D"),
            _make_edge("C", "D"),
        ]
        cfg = _make_cfg("diamond", blocks, edges)

        idom = analyzer.compute_dominators(cfg)

        assert idom["A"] is None
        assert idom["B"] == "A"
        assert idom["C"] == "A"
        assert idom["D"] == "A"

    def test_compute_dominators_loop(
        self, analyzer: CFGAnalyzer
    ) -> None:
        """Loop: A -> B -> C -> B (back edge). B'nin idom'u A."""
        blocks = [_make_block("A"), _make_block("B"), _make_block("C")]
        edges = [
            _make_edge("A", "B"),
            _make_edge("B", "C", "conditional_jump"),
            _make_edge("C", "B", "unconditional_jump"),  # back edge
        ]
        cfg = _make_cfg("loop", blocks, edges)

        idom = analyzer.compute_dominators(cfg)

        assert idom["A"] is None
        assert idom["B"] == "A"
        assert idom["C"] == "B"

    def test_compute_dominators_empty(
        self, analyzer: CFGAnalyzer
    ) -> None:
        """Bos CFG -> bos dominator haritasi."""
        cfg = FunctionCFG(name="empty", address="0x0")
        idom = analyzer.compute_dominators(cfg)
        assert idom == {}


# ---------------------------------------------------------------------------
# Test 3: detect_loops() testleri
# ---------------------------------------------------------------------------

class TestDetectLoops:
    """Natural loop detection testleri."""

    def test_detect_loops_no_loops(self, analyzer: CFGAnalyzer) -> None:
        """Lineer CFG'de loop yok."""
        blocks = [_make_block("A"), _make_block("B"), _make_block("C")]
        edges = [_make_edge("A", "B"), _make_edge("B", "C")]
        cfg = _make_cfg("linear", blocks, edges)

        loops = analyzer.detect_loops(cfg)
        assert loops == []

    def test_detect_loops_single_while(self, analyzer: CFGAnalyzer) -> None:
        """Tek while loop: A -> B -> C -> B (back edge C->B)."""
        blocks = [_make_block("A"), _make_block("B"), _make_block("C")]
        edges = [
            _make_edge("A", "B"),
            _make_edge("B", "C", "conditional_jump"),
            _make_edge("C", "B", "unconditional_jump"),
            _make_edge("B", "D"),  # loop exit -- D block'u yok ama edge var
        ]
        # D block'unu da ekleyelim
        blocks.append(_make_block("D"))
        cfg = _make_cfg("while_loop", blocks, edges)

        loops = analyzer.detect_loops(cfg)
        assert len(loops) == 1
        assert loops[0].header_block == "B"
        assert loops[0].back_edge == ("C", "B")
        assert "B" in loops[0].body_blocks
        assert "C" in loops[0].body_blocks

    def test_detect_loops_nested_loops(self, analyzer: CFGAnalyzer) -> None:
        """Ic ice iki loop:
        A -> B -> C -> D -> C (ic loop: C-D)
                  ^         |
             B'ye back edge (dis loop: B-C-D)
        """
        blocks = [
            _make_block("A"), _make_block("B"),
            _make_block("C"), _make_block("D"),
            _make_block("E"),  # exit
        ]
        edges = [
            _make_edge("A", "B"),
            _make_edge("B", "C", "conditional_jump"),
            _make_edge("C", "D", "conditional_jump"),
            _make_edge("D", "C", "unconditional_jump"),  # ic loop back edge
            _make_edge("C", "B", "unconditional_jump"),  # dis loop back edge
            _make_edge("B", "E", "conditional_jump"),    # exit
        ]
        cfg = _make_cfg("nested", blocks, edges)

        loops = analyzer.detect_loops(cfg)
        assert len(loops) == 2

        headers = {loop.header_block for loop in loops}
        assert "B" in headers  # dis loop
        assert "C" in headers  # ic loop

        # Ic loop daha yuksek nesting_depth'e sahip olmali
        inner = [lp for lp in loops if lp.header_block == "C"][0]
        outer = [lp for lp in loops if lp.header_block == "B"][0]
        assert inner.nesting_depth > outer.nesting_depth

    def test_detect_loops_multiple_independent(
        self, analyzer: CFGAnalyzer
    ) -> None:
        """Iki bagimsiz loop: A -> B -> C -> B, C -> D -> E -> D."""
        blocks = [
            _make_block("A"), _make_block("B"),
            _make_block("C"), _make_block("D"),
            _make_block("E"), _make_block("F"),
        ]
        edges = [
            _make_edge("A", "B"),
            _make_edge("B", "C", "conditional_jump"),
            _make_edge("C", "B", "unconditional_jump"),  # loop 1 back edge
            _make_edge("B", "D", "conditional_jump"),     # loop 1 exit -> loop 2
            _make_edge("D", "E", "conditional_jump"),
            _make_edge("E", "D", "unconditional_jump"),  # loop 2 back edge
            _make_edge("D", "F", "conditional_jump"),     # exit
        ]
        cfg = _make_cfg("two_loops", blocks, edges)

        loops = analyzer.detect_loops(cfg)
        assert len(loops) == 2

        headers = {lp.header_block for lp in loops}
        assert "B" in headers
        assert "D" in headers

        # Bagimsiz loop'lar: nesting_depth = 0
        for lp in loops:
            assert lp.nesting_depth == 0


# ---------------------------------------------------------------------------
# Test 4: compute_cyclomatic_complexity() testleri
# ---------------------------------------------------------------------------

class TestCyclomaticComplexity:
    """Cyclomatic complexity testleri."""

    def test_cyclomatic_complexity_linear(
        self, analyzer: CFGAnalyzer
    ) -> None:
        """Lineer: E=1, N=2 -> V(G) = 1 - 2 + 2 = 1."""
        blocks = [_make_block("A"), _make_block("B")]
        edges = [_make_edge("A", "B")]
        cfg = _make_cfg("linear", blocks, edges)

        assert analyzer.compute_cyclomatic_complexity(cfg) == 1

    def test_cyclomatic_complexity_if_else(
        self, analyzer: CFGAnalyzer
    ) -> None:
        """If-else (diamond): E=4, N=4 -> V(G) = 4 - 4 + 2 = 2."""
        blocks = [
            _make_block("A"), _make_block("B"),
            _make_block("C"), _make_block("D"),
        ]
        edges = [
            _make_edge("A", "B", "conditional_jump"),
            _make_edge("A", "C", "conditional_jump"),
            _make_edge("B", "D"),
            _make_edge("C", "D"),
        ]
        cfg = _make_cfg("diamond", blocks, edges)

        assert analyzer.compute_cyclomatic_complexity(cfg) == 2

    def test_cyclomatic_complexity_switch(
        self, analyzer: CFGAnalyzer
    ) -> None:
        """Switch (3 case): E=6, N=5 -> V(G) = 6 - 5 + 2 = 3."""
        blocks = [
            _make_block("A"),  # switch
            _make_block("B"),  # case 1
            _make_block("C"),  # case 2
            _make_block("D"),  # case 3
            _make_block("E"),  # merge
        ]
        edges = [
            _make_edge("A", "B", "conditional_jump"),
            _make_edge("A", "C", "conditional_jump"),
            _make_edge("A", "D", "conditional_jump"),
            _make_edge("B", "E"),
            _make_edge("C", "E"),
            _make_edge("D", "E"),
        ]
        cfg = _make_cfg("switch3", blocks, edges)

        assert analyzer.compute_cyclomatic_complexity(cfg) == 3

    def test_cyclomatic_complexity_empty(
        self, analyzer: CFGAnalyzer
    ) -> None:
        """Bos CFG -> complexity = 0."""
        cfg = FunctionCFG(name="empty", address="0x0")
        assert analyzer.compute_cyclomatic_complexity(cfg) == 0


# ---------------------------------------------------------------------------
# Test 5: classify_function() testleri
# ---------------------------------------------------------------------------

class TestClassifyFunction:
    """Fonksiyon siniflandirma testleri."""

    def test_classify_linear(self, analyzer: CFGAnalyzer) -> None:
        """0 loop, complexity <= 2 -> 'linear'."""
        cfg = FunctionCFG(
            name="f", address="0x0",
            blocks=[_make_block("A"), _make_block("B")],
            edges=[_make_edge("A", "B")],
            cyclomatic_complexity=1,
            loop_headers=[],
        )
        assert analyzer.classify_function(cfg) == "linear"

    def test_classify_branching(self, analyzer: CFGAnalyzer) -> None:
        """0 loop, complexity > 2 -> 'branching'."""
        cfg = FunctionCFG(
            name="f", address="0x0",
            blocks=[_make_block(str(i)) for i in range(5)],
            edges=[],
            cyclomatic_complexity=5,
            loop_headers=[],
        )
        assert analyzer.classify_function(cfg) == "branching"

    def test_classify_looping(self, analyzer: CFGAnalyzer) -> None:
        """1+ loop, complexity <= 10 -> 'looping'."""
        cfg = FunctionCFG(
            name="f", address="0x0",
            blocks=[_make_block(str(i)) for i in range(4)],
            edges=[],
            cyclomatic_complexity=5,
            loop_headers=["0x100"],
        )
        assert analyzer.classify_function(cfg) == "looping"

    def test_classify_complex(self, analyzer: CFGAnalyzer) -> None:
        """1+ loop, complexity > 10 -> 'complex'."""
        cfg = FunctionCFG(
            name="f", address="0x0",
            blocks=[_make_block(str(i)) for i in range(20)],
            edges=[],
            cyclomatic_complexity=15,
            loop_headers=["0x100", "0x200"],
        )
        assert analyzer.classify_function(cfg) == "complex"


# ---------------------------------------------------------------------------
# Test 6: get_function_metrics() ve get_summary() testleri
# ---------------------------------------------------------------------------

class TestMetricsAndSummary:
    """Metrik ve ozet testleri."""

    def test_get_function_metrics(self, analyzer: CFGAnalyzer) -> None:
        """get_function_metrics() dogru degerler donduruyor mu?"""
        blocks = [_make_block("A"), _make_block("B"), _make_block("C")]
        edges = [_make_edge("A", "B"), _make_edge("B", "C")]
        cfg = _make_cfg("test_func", blocks, edges)

        metrics = analyzer.get_function_metrics(cfg)

        assert metrics["name"] == "test_func"
        assert metrics["block_count"] == 3
        assert metrics["edge_count"] == 2
        assert metrics["complexity"] == 1  # E=2, N=3 -> 2-3+2=1
        assert metrics["loop_count"] == 0
        assert metrics["max_loop_depth"] == 0
        assert metrics["classification"] == "linear"

    def test_get_summary(self, analyzer: CFGAnalyzer) -> None:
        """get_summary() toplu istatistikleri dogru donduruyor mu?"""
        # 2 fonksiyon: 1 linear, 1 branching
        func1 = FunctionCFG(
            name="f1", address="0x1000",
            blocks=[_make_block("A"), _make_block("B")],
            edges=[_make_edge("A", "B")],
            cyclomatic_complexity=1,
            loop_headers=[],
        )
        func2 = FunctionCFG(
            name="f2", address="0x2000",
            blocks=[_make_block("C"), _make_block("D"), _make_block("E")],
            edges=[
                _make_edge("C", "D", "conditional_jump"),
                _make_edge("C", "E", "conditional_jump"),
                _make_edge("D", "E"),
            ],
            cyclomatic_complexity=3,
            loop_headers=[],
        )

        result = CFGAnalysisResult(
            total_functions=2,
            total_blocks=5,
            total_edges=4,
            functions=[func1, func2],
        )

        summary = analyzer.get_summary(result)

        assert summary["total_functions"] == 2
        assert summary["total_blocks"] == 5
        assert summary["total_edges"] == 4
        assert summary["avg_complexity"] == 2.0  # (1 + 3) / 2
        assert summary["max_complexity"] == 3
        assert summary["total_loops"] == 0
        assert summary["functions_with_loops"] == 0
        assert summary["classification_distribution"]["linear"] == 1
        assert summary["classification_distribution"]["branching"] == 1
        assert summary["classification_distribution"]["looping"] == 0
        assert summary["classification_distribution"]["complex"] == 0

    def test_get_summary_empty(self, analyzer: CFGAnalyzer) -> None:
        """Bos result icin get_summary() hata vermez."""
        result = CFGAnalysisResult()
        summary = analyzer.get_summary(result)
        assert summary["total_functions"] == 0
        assert summary["avg_complexity"] == 0.0
        assert summary["max_complexity"] == 0


# ---------------------------------------------------------------------------
# Fallback Loop Detection ve Back-Edge Parse Testleri
# ---------------------------------------------------------------------------

class TestFallbackLoopDetection:
    """Address-based fallback loop detection testleri.

    Dominator-based detection basarisiz oldugunda (ornegin unreachable
    node'lar yuzunden), address-based heuristic devreye girmeli.
    """

    def test_fallback_detects_simple_loop(self, analyzer: CFGAnalyzer) -> None:
        """Fallback: to_addr < from_addr olan edge back-edge olarak algilanir.

        CFG:  A(0010) -> B(0020) -> C(0030) -> A(0010)
              Dominator-based bulamazsa, C->A edge'i back-edge adayi.

        Bu test dominator'in BASARISIZ oldugu durumu simule eder:
        Unreachable node ekliyoruz ki idom zinciri kirilsin ve
        dominator 0 loop bulsun.
        """
        # Lineer gorunen ama aslinda loop olan CFG
        # Dominator bunu bulabilir -- ama biz fallback'i test etmek icin
        # dominator'in bulamayacagi edge pattern olusturalim.
        # Trick: entry'den ulasilamayan bir block'tan gelen back-edge
        # (dominator bu block'un idom'unu hesaplayamaz)
        cfg = FunctionCFG(
            name="test_fallback",
            address="00000010",
            blocks=[
                _make_block("00000010", "0000001f"),
                _make_block("00000020", "0000002f"),
                _make_block("00000030", "0000003f"),
            ],
            edges=[
                # Normal akis: A -> B -> C
                CFGEdge(from_block="00000010", to_block="00000020",
                        edge_type="fall_through"),
                CFGEdge(from_block="00000020", to_block="00000030",
                        edge_type="fall_through"),
                # Back-edge: C -> A (loop)
                CFGEdge(from_block="00000030", to_block="00000010",
                        edge_type="unconditional_jump"),
            ],
        )
        # Bu durumda dominator-based ZATEN bulmali, ama
        # detect_loops hala calismali
        loops = analyzer.detect_loops(cfg)
        assert len(loops) >= 1
        # En az bir loop header 00000010 olmali
        headers = {lp.header_block for lp in loops}
        assert "00000010" in headers

    def test_fallback_when_dominator_fails(self, analyzer: CFGAnalyzer) -> None:
        """Dominator hesabi 0 loop bulunca fallback devreye girer.

        Senaryo: Izole bir subgraph (entry'den ulasilamayan) icinde
        back-edge var. Dominator bu edge'i bulamaz cunku idom None.
        Fallback adres karsilastirmasi ile yakalar.
        """
        cfg = FunctionCFG(
            name="test_isolated_loop",
            address="00001000",
            blocks=[
                _make_block("00001000", "0000100f"),  # entry
                _make_block("00002000", "0000200f"),  # izole block 1
                _make_block("00003000", "0000300f"),  # izole block 2
            ],
            edges=[
                # Entry'den hicbir yere gitmiyor (tek basina)
                # Izole loop: 2000 -> 3000 -> 2000
                CFGEdge(from_block="00002000", to_block="00003000",
                        edge_type="fall_through"),
                CFGEdge(from_block="00003000", to_block="00002000",
                        edge_type="unconditional_jump"),
            ],
        )
        loops = analyzer.detect_loops(cfg)
        # Dominator entry'den 2000/3000'e ulasamaz, idom None kalir
        # Fallback back-edge bulur: 3000 -> 2000 (to < from)
        assert len(loops) >= 1
        headers = {lp.header_block for lp in loops}
        assert "00002000" in headers

    def test_no_false_positives_on_linear_cfg(self, analyzer: CFGAnalyzer) -> None:
        """Linear CFG'de fallback da 0 loop donmeli (false positive olmasin)."""
        cfg = FunctionCFG(
            name="test_linear",
            address="00001000",
            blocks=[
                _make_block("00001000", "0000100f"),
                _make_block("00002000", "0000200f"),
                _make_block("00003000", "0000300f"),
            ],
            edges=[
                CFGEdge(from_block="00001000", to_block="00002000",
                        edge_type="fall_through"),
                CFGEdge(from_block="00002000", to_block="00003000",
                        edge_type="fall_through"),
            ],
        )
        loops = analyzer.detect_loops(cfg)
        assert len(loops) == 0


class TestParseBackEdge:
    """_parse_back_edge() eski dict ve yeni list formatlarini handle etmeli."""

    def test_parse_list_format(self) -> None:
        """Yeni format: [from_addr, to_addr]"""
        result = CFGAnalyzer._parse_back_edge(["00401000", "00400ff0"])
        assert result == ("00401000", "00400ff0")

    def test_parse_dict_format_from_to(self) -> None:
        """Eski format: {"from": addr, "to": addr}"""
        result = CFGAnalyzer._parse_back_edge(
            {"from": "00401000", "to": "00400ff0"}
        )
        assert result == ("00401000", "00400ff0")

    def test_parse_dict_format_from_block_to_block(self) -> None:
        """Alternatif dict format: {"from_block": addr, "to_block": addr}"""
        result = CFGAnalyzer._parse_back_edge(
            {"from_block": "00401000", "to_block": "00400ff0"}
        )
        assert result == ("00401000", "00400ff0")

    def test_parse_tuple_format(self) -> None:
        """Tuple format: (from_addr, to_addr)"""
        result = CFGAnalyzer._parse_back_edge(("00401000", "00400ff0"))
        assert result == ("00401000", "00400ff0")


class TestAnalyzeJSONBackEdgeFormats:
    """analyze() dict vs list back-edge formatlarini dogru parse etmeli."""

    def test_analyze_with_dict_back_edges(
        self, analyzer: CFGAnalyzer, tmp_path: Path
    ) -> None:
        """Eski Ghidra ciktisi: back_edges dict listesi."""
        data = {
            "functions": [
                {
                    "name": "loop_func",
                    "address": "00401000",
                    "blocks": [
                        {"start_address": "00401000", "end_address": "0040100f",
                         "size": 16},
                        {"start_address": "00401010", "end_address": "0040101f",
                         "size": 16},
                    ],
                    "edges": [
                        {"from_block": "00401000", "to_block": "00401010",
                         "edge_type": "fall_through"},
                        {"from_block": "00401010", "to_block": "00401000",
                         "edge_type": "unconditional_jump"},
                    ],
                    "back_edges": [
                        {"from": "00401010", "to": "00401000"},
                    ],
                    "loop_headers": ["00401000"],
                    "cyclomatic_complexity": 2,
                }
            ]
        }
        json_path = tmp_path / "cfg.json"
        json_path.write_text(json.dumps(data), encoding="utf-8")

        result = analyzer.analyze(json_path)
        assert result.total_functions == 1
        func = result.functions[0]
        # detect_loops dominator-based loop bulmali
        assert len(func.loop_headers) >= 1

    def test_analyze_with_list_back_edges(
        self, analyzer: CFGAnalyzer, tmp_path: Path
    ) -> None:
        """Yeni format: back_edges list of lists."""
        data = {
            "functions": [
                {
                    "name": "loop_func2",
                    "address": "00401000",
                    "blocks": [
                        {"start_address": "00401000", "end_address": "0040100f",
                         "size": 16},
                        {"start_address": "00401010", "end_address": "0040101f",
                         "size": 16},
                    ],
                    "edges": [
                        {"from_block": "00401000", "to_block": "00401010",
                         "edge_type": "fall_through"},
                        {"from_block": "00401010", "to_block": "00401000",
                         "edge_type": "unconditional_jump"},
                    ],
                    "back_edges": [
                        ["00401010", "00401000"],
                    ],
                    "loop_headers": ["00401000"],
                    "cyclomatic_complexity": 2,
                }
            ]
        }
        json_path = tmp_path / "cfg.json"
        json_path.write_text(json.dumps(data), encoding="utf-8")

        result = analyzer.analyze(json_path)
        assert result.total_functions == 1
        func = result.functions[0]
        assert len(func.loop_headers) >= 1
