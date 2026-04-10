"""P-Code analyzer testleri.

Sentetik JSON data ile PcodeAnalyzer'in tum metodlarini test eder.
Gercek binary veya Ghidra gerektirmez — tamamen bagimsiz calisir.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from karadul.analyzers.pcode_analyzer import (
    FunctionPcode,
    PcodeAnalysisResult,
    PcodeAnalyzer,
    PcodeOpInfo,
    VarnodeInfo,
)


# ---------------------------------------------------------------------------
# Fixtures — sentetik P-Code verisi
# ---------------------------------------------------------------------------

def _make_varnode(
    space: str = "register",
    offset: int = 0,
    size: int = 8,
    is_constant: bool = False,
    is_register: bool = False,
    is_unique: bool = False,
    high_variable: str | None = None,
) -> dict:
    """JSON-uyumlu varnode dict olustur."""
    return {
        "space": space,
        "offset": offset,
        "size": size,
        "is_constant": is_constant,
        "is_register": is_register,
        "is_unique": is_unique,
        "high_variable": high_variable,
    }


def _make_op(
    mnemonic: str = "INT_ADD",
    seq_num: int = 0,
    address: str = "0x1000",
    output: dict | None = None,
    inputs: list[dict] | None = None,
) -> dict:
    """JSON-uyumlu PcodeOp dict olustur."""
    return {
        "mnemonic": mnemonic,
        "seq_num": seq_num,
        "address": address,
        "output": output,
        "inputs": inputs or [],
    }


def _make_function_json(
    name: str = "test_func",
    address: str = "0x1000",
    ops: list[dict] | None = None,
    high_variables: list[dict] | None = None,
) -> dict:
    """JSON-uyumlu fonksiyon dict olustur."""
    return {
        "name": name,
        "address": address,
        "ops": ops or [],
        "high_variables": high_variables or [],
    }


@pytest.fixture
def analyzer() -> PcodeAnalyzer:
    """PcodeAnalyzer instance."""
    return PcodeAnalyzer()


@pytest.fixture
def simple_copy_function() -> FunctionPcode:
    """COPY operasyonu iceren basit fonksiyon.

    r0 = COPY r1 (seq 0)
    r2 = INT_ADD r0, r3 (seq 1)
    """
    return FunctionPcode(
        name="simple_copy",
        address="0x1000",
        ops=[
            PcodeOpInfo(
                mnemonic="COPY",
                seq_num=0,
                address="0x1000",
                output=VarnodeInfo(space="register", offset=0, size=8, is_register=True, high_variable="local_a"),
                inputs=[VarnodeInfo(space="register", offset=1, size=8, is_register=True, high_variable="param_x")],
            ),
            PcodeOpInfo(
                mnemonic="INT_ADD",
                seq_num=1,
                address="0x1004",
                output=VarnodeInfo(space="register", offset=2, size=8, is_register=True, high_variable="result"),
                inputs=[
                    VarnodeInfo(space="register", offset=0, size=8, is_register=True, high_variable="local_a"),
                    VarnodeInfo(space="register", offset=3, size=8, is_register=True, high_variable="local_b"),
                ],
            ),
        ],
        high_variables=[
            {"name": "local_a", "type": "int", "size": 8, "is_parameter": False},
            {"name": "param_x", "type": "int", "size": 8, "is_parameter": True},
            {"name": "result", "type": "int", "size": 8, "is_parameter": False},
            {"name": "local_b", "type": "int", "size": 8, "is_parameter": False},
        ],
    )


@pytest.fixture
def multi_use_function() -> FunctionPcode:
    """Bir degiskenin 6+ kez kullanildigi fonksiyon (yuksek confidence icin)."""
    ops = []
    # counter degiskeni: 1 def, 7 use
    ops.append(PcodeOpInfo(
        mnemonic="COPY",
        seq_num=0,
        address="0x2000",
        output=VarnodeInfo(space="register", offset=10, size=8, is_register=True, high_variable="counter"),
        inputs=[VarnodeInfo(space="const", offset=0, size=8, is_constant=True)],
    ))
    for i in range(1, 8):
        ops.append(PcodeOpInfo(
            mnemonic="INT_ADD",
            seq_num=i,
            address="0x%04x" % (0x2000 + i * 4),
            output=VarnodeInfo(space="register", offset=20 + i, size=8, is_register=True, high_variable="tmp_%d" % i),
            inputs=[
                VarnodeInfo(space="register", offset=10, size=8, is_register=True, high_variable="counter"),
                VarnodeInfo(space="const", offset=1, size=8, is_constant=True),
            ],
        ))
    return FunctionPcode(
        name="multi_use_func",
        address="0x2000",
        ops=ops,
        high_variables=[
            {"name": "counter", "type": "int", "size": 8, "is_parameter": False},
        ],
    )


# ---------------------------------------------------------------------------
# Test: analyze() — JSON yukle ve parse et
# ---------------------------------------------------------------------------

class TestAnalyze:
    """analyze() metodu testleri."""

    def test_analyze_empty_json(self, analyzer: PcodeAnalyzer, tmp_path: Path) -> None:
        """Bos JSON dosyasi — bos result donmeli, exception firlatmamali."""
        json_path = tmp_path / "empty.json"
        json_path.write_text("{}", encoding="utf-8")

        result = analyzer.analyze(json_path)

        assert result.total_functions == 0
        assert result.total_pcode_ops == 0
        assert result.functions == []

    def test_analyze_single_function(self, analyzer: PcodeAnalyzer, tmp_path: Path) -> None:
        """Tek fonksiyonlu JSON — dogru parse edilmeli."""
        func = _make_function_json(
            name="main",
            address="0x1000",
            ops=[
                _make_op(
                    mnemonic="INT_ADD",
                    seq_num=0,
                    output=_make_varnode(space="register", offset=0, size=8),
                    inputs=[
                        _make_varnode(space="register", offset=1, size=8),
                        _make_varnode(space="const", offset=42, size=8, is_constant=True),
                    ],
                ),
                _make_op(
                    mnemonic="RETURN",
                    seq_num=1,
                    output=None,
                    inputs=[_make_varnode(space="register", offset=0, size=8)],
                ),
            ],
            high_variables=[
                {"name": "result", "type": "int", "size": 8, "is_parameter": False},
            ],
        )
        data = {
            "program": "test_binary",
            "total_functions_analyzed": 1,
            "total_pcode_ops": 2,
            "functions": [func],
            "stats": {"avg_ops_per_function": 2.0},
        }
        json_path = tmp_path / "pcode.json"
        json_path.write_text(json.dumps(data), encoding="utf-8")

        result = analyzer.analyze(json_path)

        assert result.total_functions == 1
        assert result.total_pcode_ops == 2
        assert result.functions[0].name == "main"
        assert len(result.functions[0].ops) == 2
        assert result.functions[0].ops[0].mnemonic == "INT_ADD"
        assert result.functions[0].ops[1].mnemonic == "RETURN"

    def test_analyze_malformed_json(self, analyzer: PcodeAnalyzer, tmp_path: Path) -> None:
        """Bozuk JSON — exception firlatmadan bos result donmeli."""
        json_path = tmp_path / "malformed.json"
        json_path.write_text("{{{invalid json!!!", encoding="utf-8")

        result = analyzer.analyze(json_path)

        assert result.total_functions == 0
        assert result.total_pcode_ops == 0

    def test_analyze_missing_fields(self, analyzer: PcodeAnalyzer, tmp_path: Path) -> None:
        """Kismi veri — eksik alanlar varsayilan degerlerle doldurulmali."""
        data = {
            "functions": [
                {
                    "name": "partial_func",
                    # address yok
                    "ops": [
                        {
                            "mnemonic": "COPY",
                            "seq_num": 0,
                            # address yok, output yok
                            "inputs": [None, {"space": "register", "offset": 5, "size": 4}],
                        },
                    ],
                    # high_variables yok
                },
            ],
        }
        json_path = tmp_path / "partial.json"
        json_path.write_text(json.dumps(data), encoding="utf-8")

        result = analyzer.analyze(json_path)

        assert result.total_functions == 1
        func = result.functions[0]
        assert func.name == "partial_func"
        assert func.address == "0x0"  # varsayilan
        assert len(func.ops) == 1
        op = func.ops[0]
        assert op.mnemonic == "COPY"
        assert op.output is None
        # None input atlanir, sadece valid input kalir
        assert len(op.inputs) == 1
        assert op.inputs[0].offset == 5

    def test_analyze_nonexistent_file(self, analyzer: PcodeAnalyzer, tmp_path: Path) -> None:
        """Mevcut olmayan dosya — bos result donmeli."""
        result = analyzer.analyze(tmp_path / "does_not_exist.json")

        assert result.total_functions == 0


# ---------------------------------------------------------------------------
# Test: compute_def_use_chains()
# ---------------------------------------------------------------------------

class TestDefUseChains:
    """compute_def_use_chains() testleri."""

    def test_compute_def_use_chains_copy(
        self, analyzer: PcodeAnalyzer, simple_copy_function: FunctionPcode
    ) -> None:
        """COPY op: kaynak varnode use, hedef varnode def olarak gorunmeli."""
        chains = analyzer.compute_def_use_chains(simple_copy_function)

        # r0 (register:0:8) — COPY output (def seq=0), INT_ADD input (use seq=1)
        r0_key = "register:0:8"
        assert r0_key in chains
        assert 0 in chains[r0_key]["defs"]
        assert 1 in chains[r0_key]["uses"]

    def test_compute_def_use_chains_int_add(
        self, analyzer: PcodeAnalyzer, simple_copy_function: FunctionPcode
    ) -> None:
        """INT_ADD op: output def, her iki input use olmali."""
        chains = analyzer.compute_def_use_chains(simple_copy_function)

        # r2 (register:2:8) — INT_ADD output (def seq=1)
        r2_key = "register:2:8"
        assert r2_key in chains
        assert 1 in chains[r2_key]["defs"]

        # r3 (register:3:8) — INT_ADD input (use seq=1)
        r3_key = "register:3:8"
        assert r3_key in chains
        assert 1 in chains[r3_key]["uses"]

    def test_compute_def_use_chains_empty_function(self, analyzer: PcodeAnalyzer) -> None:
        """Bos fonksiyon — bos chains donmeli."""
        empty_func = FunctionPcode(name="empty", address="0x0", ops=[], high_variables=[])
        chains = analyzer.compute_def_use_chains(empty_func)
        assert chains == {}


# ---------------------------------------------------------------------------
# Test: detect_aliases()
# ---------------------------------------------------------------------------

class TestDetectAliases:
    """detect_aliases() testleri."""

    def test_detect_aliases_simple(
        self, analyzer: PcodeAnalyzer, simple_copy_function: FunctionPcode
    ) -> None:
        """COPY op iceren fonksiyon — 1 alias cifti donmeli."""
        aliases = analyzer.detect_aliases(simple_copy_function)

        assert len(aliases) == 1
        source_key, target_key = aliases[0]
        assert source_key == "register:1:8"  # r1 (kaynak)
        assert target_key == "register:0:8"  # r0 (hedef)

    def test_detect_aliases_no_copies(self, analyzer: PcodeAnalyzer) -> None:
        """COPY olmayan fonksiyon — bos alias listesi donmeli."""
        func = FunctionPcode(
            name="no_copies",
            address="0x3000",
            ops=[
                PcodeOpInfo(
                    mnemonic="INT_ADD",
                    seq_num=0,
                    address="0x3000",
                    output=VarnodeInfo(space="register", offset=0, size=8),
                    inputs=[
                        VarnodeInfo(space="register", offset=1, size=8),
                        VarnodeInfo(space="register", offset=2, size=8),
                    ],
                ),
                PcodeOpInfo(
                    mnemonic="STORE",
                    seq_num=1,
                    address="0x3004",
                    output=None,
                    inputs=[
                        VarnodeInfo(space="ram", offset=0x5000, size=8),
                        VarnodeInfo(space="register", offset=0, size=8),
                    ],
                ),
            ],
        )
        aliases = analyzer.detect_aliases(func)
        assert aliases == []


# ---------------------------------------------------------------------------
# Test: variable_lifetime_analysis()
# ---------------------------------------------------------------------------

class TestVariableLifetime:
    """variable_lifetime_analysis() testleri."""

    def test_variable_lifetime_single_def_multi_use(
        self, analyzer: PcodeAnalyzer, multi_use_function: FunctionPcode
    ) -> None:
        """1 def + 7 use degisken — lifetime (0, 7) olmali."""
        lifetimes = analyzer.variable_lifetime_analysis(multi_use_function)

        # counter: register:10:8 — def seq=0, uses seq=1..7
        counter_key = "register:10:8"
        assert counter_key in lifetimes
        first_def, last_use = lifetimes[counter_key]
        assert first_def == 0
        assert last_use == 7

    def test_variable_lifetime_no_defs(self, analyzer: PcodeAnalyzer) -> None:
        """Sadece use olan varnode — first_def -1 olmali (parametre/global)."""
        func = FunctionPcode(
            name="no_def_func",
            address="0x4000",
            ops=[
                PcodeOpInfo(
                    mnemonic="INT_ADD",
                    seq_num=5,
                    address="0x4000",
                    output=VarnodeInfo(space="register", offset=99, size=8),
                    inputs=[
                        VarnodeInfo(space="register", offset=50, size=8),
                        VarnodeInfo(space="const", offset=1, size=8, is_constant=True),
                    ],
                ),
            ],
        )
        lifetimes = analyzer.variable_lifetime_analysis(func)

        # register:50:8 sadece use var, def yok
        key = "register:50:8"
        assert key in lifetimes
        first_def, last_use = lifetimes[key]
        assert first_def == -1
        assert last_use == 5

    def test_variable_lifetime_dead_definition(self, analyzer: PcodeAnalyzer) -> None:
        """Sadece def olan varnode (dead definition) — last_use = def seq olmali."""
        func = FunctionPcode(
            name="dead_def_func",
            address="0x5000",
            ops=[
                PcodeOpInfo(
                    mnemonic="COPY",
                    seq_num=3,
                    address="0x5000",
                    output=VarnodeInfo(space="register", offset=77, size=8),
                    inputs=[VarnodeInfo(space="const", offset=0, size=8, is_constant=True)],
                ),
            ],
        )
        lifetimes = analyzer.variable_lifetime_analysis(func)

        key = "register:77:8"
        assert key in lifetimes
        first_def, last_use = lifetimes[key]
        assert first_def == 3
        assert last_use == 3  # dead def: last_use = def seq


# ---------------------------------------------------------------------------
# Test: naming_confidence_boost()
# ---------------------------------------------------------------------------

class TestNamingConfidence:
    """naming_confidence_boost() testleri."""

    def test_naming_confidence_high_use_count(
        self, analyzer: PcodeAnalyzer, multi_use_function: FunctionPcode
    ) -> None:
        """6+ use degisken — yuksek boost (>=0.7) almali."""
        boosts = analyzer.naming_confidence_boost(multi_use_function)

        assert "counter" in boosts
        assert boosts["counter"] >= 0.7

    def test_naming_confidence_constant_only(self, analyzer: PcodeAnalyzer) -> None:
        """Sadece constant iceren degisken — 0.0 boost almali."""
        func = FunctionPcode(
            name="const_func",
            address="0x6000",
            ops=[
                PcodeOpInfo(
                    mnemonic="INT_ADD",
                    seq_num=0,
                    address="0x6000",
                    output=VarnodeInfo(space="register", offset=0, size=8, high_variable="magic_num"),
                    inputs=[
                        # const_val: sadece constant olarak kullaniliyor, hic def yok
                        VarnodeInfo(space="const", offset=42, size=8, is_constant=True, high_variable="const_val"),
                        VarnodeInfo(space="const", offset=7, size=8, is_constant=True, high_variable="const_val"),
                    ],
                ),
            ],
        )
        boosts = analyzer.naming_confidence_boost(func)

        assert "const_val" in boosts
        assert boosts["const_val"] == 0.0

    def test_naming_confidence_register_based(self, analyzer: PcodeAnalyzer) -> None:
        """Register-based degisken, 2-3 use — orta boost (0.4-0.6) almali."""
        func = FunctionPcode(
            name="reg_func",
            address="0x7000",
            ops=[
                PcodeOpInfo(
                    mnemonic="COPY",
                    seq_num=0,
                    address="0x7000",
                    output=VarnodeInfo(space="register", offset=0, size=8, is_register=True, high_variable="reg_var"),
                    inputs=[VarnodeInfo(space="const", offset=0, size=8, is_constant=True)],
                ),
                PcodeOpInfo(
                    mnemonic="INT_ADD",
                    seq_num=1,
                    address="0x7004",
                    output=VarnodeInfo(space="register", offset=1, size=8),
                    inputs=[
                        VarnodeInfo(space="register", offset=0, size=8, is_register=True, high_variable="reg_var"),
                        VarnodeInfo(space="const", offset=1, size=8, is_constant=True),
                    ],
                ),
                PcodeOpInfo(
                    mnemonic="INT_ADD",
                    seq_num=2,
                    address="0x7008",
                    output=VarnodeInfo(space="register", offset=2, size=8),
                    inputs=[
                        VarnodeInfo(space="register", offset=0, size=8, is_register=True, high_variable="reg_var"),
                        VarnodeInfo(space="const", offset=2, size=8, is_constant=True),
                    ],
                ),
            ],
        )
        boosts = analyzer.naming_confidence_boost(func)

        assert "reg_var" in boosts
        assert 0.4 <= boosts["reg_var"] <= 0.6

    def test_naming_confidence_single_use(self, analyzer: PcodeAnalyzer) -> None:
        """Tek use degisken — dusuk boost (0.1) almali."""
        func = FunctionPcode(
            name="single_use_func",
            address="0x8000",
            ops=[
                PcodeOpInfo(
                    mnemonic="COPY",
                    seq_num=0,
                    address="0x8000",
                    output=VarnodeInfo(space="register", offset=0, size=8, high_variable="once_used"),
                    inputs=[VarnodeInfo(space="const", offset=0, size=8, is_constant=True)],
                ),
                PcodeOpInfo(
                    mnemonic="RETURN",
                    seq_num=1,
                    address="0x8004",
                    output=None,
                    inputs=[
                        VarnodeInfo(space="register", offset=0, size=8, high_variable="once_used"),
                    ],
                ),
            ],
        )
        boosts = analyzer.naming_confidence_boost(func)

        assert "once_used" in boosts
        assert boosts["once_used"] <= 0.2


# ---------------------------------------------------------------------------
# Test: get_dataflow_summary()
# ---------------------------------------------------------------------------

class TestDataflowSummary:
    """get_dataflow_summary() testleri."""

    def test_get_dataflow_summary(
        self, analyzer: PcodeAnalyzer, simple_copy_function: FunctionPcode
    ) -> None:
        """Ozet istatistikleri dogru hesaplanmali."""
        result = PcodeAnalysisResult(
            total_functions=1,
            total_pcode_ops=2,
            functions=[simple_copy_function],
            stats={"avg_ops_per_function": 2.0},
        )
        summary = analyzer.get_dataflow_summary(result)

        assert summary["total_functions"] == 1
        assert summary["total_pcode_ops"] == 2
        assert summary["total_aliases"] == 1  # 1 COPY op
        assert summary["total_high_variables"] == 4
        assert "mnemonic_distribution_top10" in summary
        assert "COPY" in summary["mnemonic_distribution_top10"]
        assert "INT_ADD" in summary["mnemonic_distribution_top10"]

    def test_get_dataflow_summary_empty(self, analyzer: PcodeAnalyzer) -> None:
        """Bos result — sifir degerleri donmeli."""
        result = PcodeAnalysisResult()
        summary = analyzer.get_dataflow_summary(result)

        assert summary["total_functions"] == 0
        assert summary["total_pcode_ops"] == 0
        assert summary["total_aliases"] == 0
        assert summary["avg_variable_lifetime_span"] == 0.0


# ---------------------------------------------------------------------------
# Test: performans — buyuk fonksiyon
# ---------------------------------------------------------------------------

class TestPerformance:
    """Performans regresyon testleri."""

    def test_large_function_performance(self, analyzer: PcodeAnalyzer) -> None:
        """1000+ op'lu fonksiyon — tum analizler 1 saniye icinde tamamlanmali."""
        # 1200 op'lu sentetik fonksiyon olustur
        ops = []
        for i in range(1200):
            ops.append(PcodeOpInfo(
                mnemonic="INT_ADD" if i % 3 != 0 else "COPY",
                seq_num=i,
                address="0x%04x" % (0x10000 + i * 4),
                output=VarnodeInfo(
                    space="register",
                    offset=i % 32,
                    size=8,
                    is_register=True,
                    high_variable="var_%d" % (i % 20),
                ),
                inputs=[
                    VarnodeInfo(
                        space="register",
                        offset=(i + 1) % 32,
                        size=8,
                        is_register=True,
                        high_variable="var_%d" % ((i + 1) % 20),
                    ),
                    VarnodeInfo(
                        space="const" if i % 5 == 0 else "register",
                        offset=i % 100,
                        size=8,
                        is_constant=(i % 5 == 0),
                        is_register=(i % 5 != 0),
                        high_variable=None if i % 5 == 0 else "var_%d" % ((i + 2) % 20),
                    ),
                ],
            ))

        large_func = FunctionPcode(
            name="large_function",
            address="0x10000",
            ops=ops,
            high_variables=[{"name": "var_%d" % j, "type": "int", "size": 8} for j in range(20)],
        )

        result = PcodeAnalysisResult(
            total_functions=1,
            total_pcode_ops=1200,
            functions=[large_func],
            stats={},
        )

        start = time.monotonic()

        # Tum analizleri calistir
        chains = analyzer.compute_def_use_chains(large_func)
        aliases = analyzer.detect_aliases(large_func)
        lifetimes = analyzer.variable_lifetime_analysis(large_func)
        boosts = analyzer.naming_confidence_boost(large_func)
        summary = analyzer.get_dataflow_summary(result)

        elapsed = time.monotonic() - start

        # Sanity kontroller
        assert len(chains) > 0
        assert len(aliases) > 0  # COPY op'lar var (her 3. op)
        assert len(lifetimes) > 0
        assert len(boosts) > 0
        assert summary["total_pcode_ops"] == 1200

        # Performans: 1 saniye icinde tamamlanmali
        assert elapsed < 1.0, "1200 op analizi %.2fs surdu (limit: 1.0s)" % elapsed
