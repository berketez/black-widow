"""v1.21 -- Engineering algorithm fusion -> NameMerger candidate testleri.

Kapsam:
    1. _add_engineering_naming -- modul yoksa graceful skip.
    2. _add_engineering_naming -- algoritma yoksa no-matches.
    3. _add_engineering_constant_naming -- detection_method "constant"/"structural"
       AlgorithmMatch listelerini engineering_constant source ile candidate'a cevirir.
    4. _add_engineering_api_naming -- detection_method "api" AlgorithmMatch listelerini
       engineering_api source ile candidate'a cevirir.
    5. _add_engineering_formula_naming -- FormulaInfo listesindeki algoritma adlari
       icin engineering_formula source ile candidate uretir.
    6. _is_unnamed filter -- mevcut adi olan fonksiyona oneri yapilmaz.
    7. Confidence floor -- 0.40/0.50/0.45 altindaki match'ler atlanir.
    8. Algo name -> func hint normalize -- override + sanitize calisir.
    9. collect_candidates entegrasyon -- decompiled_dir + functions_json verildiginde
       3 engineering kanali tetiklenir.
   10. NameMergerConfig.source_weights -- 3 yeni anahtar mevcut.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from karadul.config import NameMergerConfig
from karadul.pipeline.steps._feedback_naming_candidates import (
    _add_engineering_api_naming,
    _add_engineering_constant_naming,
    _add_engineering_formula_naming,
    _add_engineering_naming,
    _algo_name_to_func_hint,
    _sanitize_algo_to_func_name,
    collect_candidates,
)


# ---------------------------------------------------------------------------
# Test fixtures -- AlgorithmMatch ve FormulaInfo mock'lari
# ---------------------------------------------------------------------------


@dataclass
class _MockAlgoMatch:
    """AlgorithmMatch mock -- gercek dataclass ile ayni alanlar."""
    name: str
    category: str = "linear_algebra"
    confidence: float = 0.8
    detection_method: str = "constant"
    evidence: list[str] = field(default_factory=list)
    function_name: str = "FUN_400100"
    address: str = "0x400100"


@dataclass
class _MockFormulaInfo:
    """FormulaInfo mock -- algorithm alanini kullanir."""
    algorithm: str


# ---------------------------------------------------------------------------
# 1. Sanitize / hint normalize
# ---------------------------------------------------------------------------


class TestNormalize:
    def test_sanitize_basic(self) -> None:
        assert _sanitize_algo_to_func_name("AES-256-CBC") == "aes_256_cbc"
        assert _sanitize_algo_to_func_name("Gauss Legendre 3pt") == "gauss_legendre_3pt"
        assert _sanitize_algo_to_func_name("matrix_multiply") == "matrix_multiply"

    def test_sanitize_leading_digit_prefixed(self) -> None:
        # Leading digit isim olmaz -- algo_ prefix eklenir.
        assert _sanitize_algo_to_func_name("3pt_quad").startswith("algo_")

    def test_sanitize_empty_fallback(self) -> None:
        assert _sanitize_algo_to_func_name("") == "algo_unknown"

    def test_hint_override(self) -> None:
        # Override tablosu daha okunabilir isimler uretir.
        assert _algo_name_to_func_hint("matrix_multiply") == "matrix_multiply"
        assert _algo_name_to_func_hint("FFT") == "fft_transform"
        assert _algo_name_to_func_hint("dot_product") == "vector_dot"

    def test_hint_unknown_falls_back_to_sanitize(self) -> None:
        # Override yoksa sanitize sonucu donmeli.
        assert _algo_name_to_func_hint("Some-Custom-Algo") == "some_custom_algo"


# ---------------------------------------------------------------------------
# 2. Constant naming helper
# ---------------------------------------------------------------------------


class TestConstantNaming:
    def test_constant_match_added(self) -> None:
        algos = [_MockAlgoMatch(
            name="gauss_quadrature_3pt",
            detection_method="constant",
            confidence=0.85,
            function_name="FUN_400100",
        )]
        candidates: dict[str, list[Any]] = {}
        added = _add_engineering_constant_naming(
            algorithms=algos, candidates=candidates,
        )
        assert added == 1
        assert "FUN_400100" in candidates
        cand = candidates["FUN_400100"][0]
        # cand NamingCandidate veya dict olabilir (test mock).
        name = cand.name if hasattr(cand, "name") else cand["name"]
        source = cand.source if hasattr(cand, "source") else cand["source"]
        assert name == "gauss_quad_3pt"
        assert source == "engineering_constant"

    def test_structural_method_also_constant_channel(self) -> None:
        algos = [_MockAlgoMatch(
            name="lu_factorization",
            detection_method="structural",
            confidence=0.50,
            function_name="FUN_400200",
        )]
        candidates: dict[str, list[Any]] = {}
        added = _add_engineering_constant_naming(
            algorithms=algos, candidates=candidates,
        )
        assert added == 1
        cand = candidates["FUN_400200"][0]
        source = cand.source if hasattr(cand, "source") else cand["source"]
        assert source == "engineering_constant"

    def test_api_method_skipped(self) -> None:
        # API detection method constant helper'a takilmamali.
        algos = [_MockAlgoMatch(
            name="axpy",
            detection_method="api",
            function_name="FUN_400300",
        )]
        candidates: dict[str, list[Any]] = {}
        added = _add_engineering_constant_naming(
            algorithms=algos, candidates=candidates,
        )
        assert added == 0

    def test_named_function_skipped(self) -> None:
        # Mevcut adi olan fonksiyona oneri yapma.
        algos = [_MockAlgoMatch(
            name="fft",
            detection_method="constant",
            function_name="my_real_fft_impl",
        )]
        candidates: dict[str, list[Any]] = {}
        added = _add_engineering_constant_naming(
            algorithms=algos, candidates=candidates,
        )
        assert added == 0

    def test_low_confidence_skipped(self) -> None:
        algos = [_MockAlgoMatch(
            name="some_algo",
            detection_method="constant",
            confidence=0.35,
            function_name="FUN_400400",
        )]
        candidates: dict[str, list[Any]] = {}
        added = _add_engineering_constant_naming(
            algorithms=algos, candidates=candidates,
        )
        assert added == 0


# ---------------------------------------------------------------------------
# 3. API naming helper
# ---------------------------------------------------------------------------


class TestAPINaming:
    def test_api_match_added(self) -> None:
        algos = [_MockAlgoMatch(
            name="dgemm",
            detection_method="api",
            confidence=0.95,
            function_name="FUN_500100",
            evidence=["dgemm_", "BLAS"],
        )]
        candidates: dict[str, list[Any]] = {}
        added = _add_engineering_api_naming(
            algorithms=algos, candidates=candidates,
        )
        assert added == 1
        cand = candidates["FUN_500100"][0]
        source = cand.source if hasattr(cand, "source") else cand["source"]
        reason = cand.reason if hasattr(cand, "reason") else cand["reason"]
        assert source == "engineering_api"
        assert "dgemm" in reason.lower()

    def test_constant_method_skipped(self) -> None:
        algos = [_MockAlgoMatch(
            name="gauss",
            detection_method="constant",
            function_name="FUN_500200",
        )]
        candidates: dict[str, list[Any]] = {}
        added = _add_engineering_api_naming(
            algorithms=algos, candidates=candidates,
        )
        assert added == 0

    def test_api_low_confidence_skipped(self) -> None:
        algos = [_MockAlgoMatch(
            name="fftw",
            detection_method="api",
            confidence=0.45,  # API floor 0.50
            function_name="FUN_500300",
        )]
        candidates: dict[str, list[Any]] = {}
        added = _add_engineering_api_naming(
            algorithms=algos, candidates=candidates,
        )
        assert added == 0


# ---------------------------------------------------------------------------
# 4. Formula naming helper
# ---------------------------------------------------------------------------


class TestFormulaNaming:
    def test_formula_match_added(self) -> None:
        algos = [_MockAlgoMatch(
            name="black_scholes",
            detection_method="constant",
            confidence=0.80,
            function_name="FUN_600100",
        )]
        formulas = [_MockFormulaInfo(algorithm="black_scholes")]
        candidates: dict[str, list[Any]] = {}
        added = _add_engineering_formula_naming(
            algorithms=algos, formulas=formulas, candidates=candidates,
        )
        assert added == 1
        cand = candidates["FUN_600100"][0]
        source = cand.source if hasattr(cand, "source") else cand["source"]
        assert source == "engineering_formula"

    def test_empty_formulas_no_op(self) -> None:
        algos = [_MockAlgoMatch(name="fft", function_name="FUN_600200")]
        candidates: dict[str, list[Any]] = {}
        added = _add_engineering_formula_naming(
            algorithms=algos, formulas=[], candidates=candidates,
        )
        assert added == 0
        assert candidates == {}

    def test_formula_named_func_skipped(self) -> None:
        algos = [_MockAlgoMatch(
            name="dgemm",
            function_name="real_matrix_mul",
        )]
        formulas = [_MockFormulaInfo(algorithm="dgemm")]
        candidates: dict[str, list[Any]] = {}
        added = _add_engineering_formula_naming(
            algorithms=algos, formulas=formulas, candidates=candidates,
        )
        assert added == 0


# ---------------------------------------------------------------------------
# 5. Dispatcher -- _add_engineering_naming graceful skip ve happy path
# ---------------------------------------------------------------------------


class TestDispatcherGraceful:
    def test_missing_decompiled_dir_skips(self, tmp_path: Path) -> None:
        # Dispatcher cagrilmaz cunku collect_candidates icindeki guard
        # decompiled_dir.exists() ile filtreliyor; dogrudan dispatcher'i
        # cagirinca da identify-error/no-matches doner.
        stats: dict[str, Any] = {}
        candidates: dict[str, list[Any]] = {}
        # Bos bir tmp dizin -> identify "no C files" doner.
        functions_json = tmp_path / "functions.json"
        functions_json.write_text("[]", encoding="utf-8")
        _add_engineering_naming(
            decompiled_dir=tmp_path,
            functions_json=functions_json,
            candidates=candidates,
            stats=stats,
        )
        # Bos dizin -> identify success=False, no-matches statusunde durmali.
        assert stats.get("engineering_naming_status") in {
            "no-matches", "identify-error", "no-module",
        }
        # Hicbir candidate eklenmemis olmali.
        assert candidates == {}


# ---------------------------------------------------------------------------
# 6. collect_candidates entegrasyon
# ---------------------------------------------------------------------------


class TestCollectCandidatesIntegration:
    @pytest.fixture
    def empty_kwargs(self) -> dict[str, Any]:
        return dict(
            extracted_names={},
            naming_result=None,
            bindiff_confidence_map={},
            refdiff_naming={},
            fid_json=None,
            computation_result=None,
            pcode_naming_candidates=[],
            iter_index=0,
            stats={},
        )

    def test_no_decompiled_dir_no_engineering(self, empty_kwargs) -> None:
        """decompiled_dir verilmedikce engineering kanali tetiklenmez."""
        result = collect_candidates(**empty_kwargs)
        assert "engineering_naming_status" not in empty_kwargs["stats"]
        assert result == {}

    def test_decompiled_dir_without_functions_json_no_engineering(
        self, empty_kwargs, tmp_path: Path,
    ) -> None:
        result = collect_candidates(
            **empty_kwargs,
            decompiled_dir=tmp_path,
            functions_json=None,
        )
        # Engineering hic tetiklenmemis olmali.
        assert "engineering_naming_status" not in empty_kwargs["stats"]
        assert result == {}

    def test_empty_decompiled_dir_engineering_no_matches(
        self, empty_kwargs, tmp_path: Path,
    ) -> None:
        """Bos C dizini + valid functions.json -> identify cagrilir ama match yok."""
        functions_json = tmp_path / "functions.json"
        functions_json.write_text("[]", encoding="utf-8")
        # Dispatcher cagrilmali (path'ler valid).
        result = collect_candidates(
            **empty_kwargs,
            decompiled_dir=tmp_path,
            functions_json=functions_json,
        )
        # status set edilmis olmali ama candidate yok.
        status = empty_kwargs["stats"].get("engineering_naming_status")
        assert status in {"no-matches", "identify-error"}
        assert result == {}


# ---------------------------------------------------------------------------
# 7. NameMergerConfig source_weights -- yeni 3 anahtar
# ---------------------------------------------------------------------------


class TestSourceWeights:
    def test_engineering_weights_registered(self) -> None:
        cfg = NameMergerConfig()
        assert "engineering_constant" in cfg.source_weights
        assert "engineering_api" in cfg.source_weights
        assert "engineering_formula" in cfg.source_weights
        # API yuksek-precision (BLAS/LAPACK) -> agirlik en yuksek olmali.
        assert cfg.source_weights["engineering_api"] >= cfg.source_weights[
            "engineering_constant"
        ]

    def test_engineering_weights_in_sane_range(self) -> None:
        cfg = NameMergerConfig()
        for key in ("engineering_constant", "engineering_api", "engineering_formula"):
            w = cfg.source_weights[key]
            assert 0.5 <= w <= 1.0, f"{key}={w} aralik disi"
