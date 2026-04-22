"""v1.11.0 Hafta 2 — BSim shadow -> NameMerger fusion kopru testleri.

Kapsam:
    1. Shadow mode (default) -> BSim evidence fusion'a YAZILMAZ (regresyon).
    2. shadow_mode=False AMA use_bsim_fusion=False -> yine YAZILMAZ (opt-in).
    3. shadow_mode=False + use_bsim_fusion=True -> evidence source="bsim"
       olarak NameMerger candidate'larina eklenir.
    4. fusion_min_similarity esigi altindaki adaylar atlanir.
    5. fusion_max_candidates_per_function top-N sinirlamasi.
    6. Bayesian merge: source_weights["bsim"]=0.85 * similarity etkin.
"""

from __future__ import annotations

from typing import Any

import pytest

from karadul.config import BSimConfig, NameMergerConfig
from karadul.pipeline.steps._feedback_naming_candidates import (
    collect_candidates,
    _add_bsim,
)
from karadul.reconstruction.name_merger import NameMerger
from karadul.reconstruction.recovery_layers.signature_fusion import (
    NamingCandidate,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def sample_shadow_payload() -> dict[str, Any]:
    """Tipik shadow payload — iki fonksiyon, birkac aday."""
    return {
        "version": "1",
        "mode": "live-dump-only",
        "timestamp": "2026-04-22T00:00:00+00:00",
        "database": "karadul_bsim",
        "total_matches": 5,
        "matches": [
            {
                "function_addr": "0x100000460",
                "function_name": "FUN_100000460",
                "bsim_candidates": [
                    {
                        "name": "print_banner",
                        "similarity": 0.92,
                        "binary": "sample_a",
                    },
                    {
                        "name": "show_info",
                        "similarity": 0.81,
                        "binary": "sample_b",
                    },
                    {
                        "name": "banner_print",
                        "similarity": 0.72,
                        "binary": "sample_c",
                    },
                    {
                        "name": "low_sim_noise",
                        "similarity": 0.55,
                        "binary": "sample_d",
                    },
                ],
            },
            {
                "function_addr": "0x100000500",
                "function_name": "FUN_100000500",
                "bsim_candidates": [
                    {
                        "name": "parse_args",
                        "similarity": 0.88,
                        "binary": "sample_a",
                    },
                ],
            },
        ],
    }


@pytest.fixture
def empty_kwargs() -> dict[str, Any]:
    """collect_candidates icin "hic evidence yok" parametre seti."""
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


# ---------------------------------------------------------------------------
# 1. Shadow (default) -- evidence YAZILMAZ
# ---------------------------------------------------------------------------


class TestShadowModeDoesNotWriteEvidence:
    def test_default_no_bsim_param_means_no_candidates(
        self, empty_kwargs,
    ) -> None:
        """collect_candidates'a bsim_shadow=None verilmemisse BSim evidence 0."""
        result = collect_candidates(**empty_kwargs)
        assert result == {}

    def test_explicit_none_shadow_is_noop(
        self, empty_kwargs,
    ) -> None:
        """bsim_shadow=None explicit verilse bile evidence eklenmez."""
        result = collect_candidates(**empty_kwargs, bsim_shadow=None)
        assert result == {}

    def test_empty_shadow_dict_is_noop(
        self, empty_kwargs,
    ) -> None:
        """Bos dict (matches=[]) evidence uretmez."""
        result = collect_candidates(
            **empty_kwargs,
            bsim_shadow={"version": "1", "mode": "shadow", "matches": []},
        )
        assert result == {}


# ---------------------------------------------------------------------------
# 2. Fusion (opt-in) -- evidence YAZILIR
# ---------------------------------------------------------------------------


class TestFusionModeWritesEvidence:
    def test_bsim_candidates_added_with_source_bsim(
        self, empty_kwargs, sample_shadow_payload,
    ) -> None:
        """Shadow payload verildiginde FUN_xxx altinda source='bsim' eklenir."""
        result = collect_candidates(
            **empty_kwargs,
            bsim_shadow=sample_shadow_payload,
            bsim_fusion_min_similarity=0.7,
            bsim_fusion_max_candidates=3,
        )
        # Iki fonksiyon key olarak bulunmali
        assert "FUN_100000460" in result
        assert "FUN_100000500" in result

        # FUN_460: top-3 filtre (0.92, 0.81, 0.72), 0.55 atlandi
        cands_460 = result["FUN_100000460"]
        assert len(cands_460) == 3
        for c in cands_460:
            assert c.source == "bsim"
        sims_460 = [c.confidence for c in cands_460]
        assert sims_460 == sorted(sims_460, reverse=True)
        names_460 = {c.name for c in cands_460}
        assert "print_banner" in names_460
        assert "low_sim_noise" not in names_460  # sim<0.7 filtrelendi

        # FUN_500: tek aday
        cands_500 = result["FUN_100000500"]
        assert len(cands_500) == 1
        assert cands_500[0].name == "parse_args"
        assert cands_500[0].confidence == pytest.approx(0.88)
        assert cands_500[0].source == "bsim"

    def test_evidence_count_matches_filtered_bsim(
        self, empty_kwargs, sample_shadow_payload,
    ) -> None:
        """Toplam eklenen candidate = top-N ve min_sim filtresi sonucu."""
        stats: dict[str, Any] = {}
        kwargs = dict(empty_kwargs)
        kwargs["stats"] = stats
        result = collect_candidates(
            **kwargs,
            bsim_shadow=sample_shadow_payload,
            bsim_fusion_min_similarity=0.7,
            bsim_fusion_max_candidates=3,
        )
        total = sum(len(v) for v in result.values())
        # FUN_460: 3 (0.55 atlandi), FUN_500: 1
        assert total == 4
        assert stats.get("bsim_fusion_candidates") == 4

    def test_source_weight_applied_in_merger(
        self, empty_kwargs, sample_shadow_payload,
    ) -> None:
        """NameMerger `source_weights['bsim']` (0.85) Bayesian log-odds'a
        damping olarak etkili — weight=0 hayali bir kaynakla karsilastirinca
        log-odds katkisi w*log(p/(1-p)) seviyesinde kalmali.

        Burada basitce: tek-kaynak BSim evidence icin NameMerger sonucu
        `bayesian_single` branch'ine duser ve confidence ~0.85'e orantili
        shrink edilir. 0.92 raw -> ~0.85^1 = 0.85*log(0.92/0.08) shrink.
        """
        result = collect_candidates(
            **empty_kwargs,
            bsim_shadow=sample_shadow_payload,
            bsim_fusion_min_similarity=0.7,
            bsim_fusion_max_candidates=1,  # top-1 -> tek aday
        )
        # FUN_500 zaten tek aday
        cfg = NameMergerConfig()
        # config.py'da source_weights["bsim"] varsayilanini dogrula
        assert cfg.source_weights.get("bsim") == pytest.approx(0.85)

        merger = NameMerger(min_confidence=0.3, merger_config=cfg)
        merged = merger.merge(
            {"FUN_100000500": result["FUN_100000500"]},
        )
        # Tek aday -> bayesian_single
        assert "FUN_100000500" in merged.merged_names
        out = merged.merged_names["FUN_100000500"]
        assert out.final_name == "parse_args"
        assert out.merge_method == "bayesian_single"
        # Raw 0.88, weight 0.85 -> shrink'lenmis olmali (< 0.88)
        assert out.final_confidence < 0.88
        # Ama min_confidence'in altina dusmemeli
        assert out.final_confidence > cfg.min_confidence


# ---------------------------------------------------------------------------
# 3. Filtre ve sinir testleri
# ---------------------------------------------------------------------------


class TestBSimFilters:
    def test_min_similarity_threshold_zero_accepts_all(
        self, empty_kwargs, sample_shadow_payload,
    ) -> None:
        """min_sim=0.0 tum adaylari kabul eder."""
        result = collect_candidates(
            **empty_kwargs,
            bsim_shadow=sample_shadow_payload,
            bsim_fusion_min_similarity=0.0,
            bsim_fusion_max_candidates=10,
        )
        # FUN_460: 4 aday (hepsi), FUN_500: 1
        assert len(result["FUN_100000460"]) == 4
        assert len(result["FUN_100000500"]) == 1

    def test_max_candidates_top_n(
        self, empty_kwargs, sample_shadow_payload,
    ) -> None:
        """max_per_function=1 -> her fonksiyondan sadece top-1."""
        result = collect_candidates(
            **empty_kwargs,
            bsim_shadow=sample_shadow_payload,
            bsim_fusion_min_similarity=0.0,
            bsim_fusion_max_candidates=1,
        )
        assert len(result["FUN_100000460"]) == 1
        assert result["FUN_100000460"][0].name == "print_banner"  # highest

    def test_named_function_skipped(
        self, empty_kwargs,
    ) -> None:
        """Zaten adlandirilmis fonksiyon (FUN_/sub_/thunk_ disi) atlanir."""
        payload = {
            "version": "1",
            "mode": "live-dump-only",
            "matches": [
                {
                    "function_addr": "0x100000460",
                    "function_name": "real_name_already_set",
                    "bsim_candidates": [
                        {"name": "other", "similarity": 0.95, "binary": "x"},
                    ],
                },
                {
                    "function_addr": "0x100000500",
                    "function_name": "FUN_100000500",
                    "bsim_candidates": [
                        {"name": "ok", "similarity": 0.85, "binary": "x"},
                    ],
                },
            ],
        }
        result = collect_candidates(
            **empty_kwargs,
            bsim_shadow=payload,
            bsim_fusion_min_similarity=0.7,
            bsim_fusion_max_candidates=3,
        )
        assert "real_name_already_set" not in result
        assert "FUN_100000500" in result

    def test_addr_fallback_when_function_name_empty(
        self, empty_kwargs,
    ) -> None:
        """function_name bossa function_addr'den FUN_XXX uretilir."""
        payload = {
            "version": "1",
            "mode": "live-dump-only",
            "matches": [{
                "function_addr": "0x00401a20",
                "function_name": "",
                "bsim_candidates": [
                    {"name": "cand", "similarity": 0.9, "binary": "x"},
                ],
            }],
        }
        result = collect_candidates(
            **empty_kwargs,
            bsim_shadow=payload,
            bsim_fusion_min_similarity=0.7,
            bsim_fusion_max_candidates=3,
        )
        assert "FUN_401a20" in result

    def test_malformed_entries_tolerated(self, empty_kwargs) -> None:
        """Bozuk girdiler (non-dict, bos similarity, bos name) patlatmaz."""
        payload = {
            "version": "1",
            "matches": [
                "not-a-dict",
                {"function_addr": "", "function_name": ""},
                {
                    "function_addr": "0x1",
                    "function_name": "FUN_1",
                    "bsim_candidates": [
                        {"name": "", "similarity": 0.9},          # bos name
                        {"similarity": "NaN"},                    # bozuk sim
                        {"name": "ok", "similarity": 0.85,
                         "binary": "x"},
                    ],
                },
            ],
        }
        result = collect_candidates(
            **empty_kwargs,
            bsim_shadow=payload,
            bsim_fusion_min_similarity=0.7,
            bsim_fusion_max_candidates=3,
        )
        # Sadece saglam aday eklendi
        assert result == {"FUN_1": [
            NamingCandidate(
                "ok", 0.85, "bsim",
                reason="BSim match (sim=0.850, binary=x)",
            ),
        ]}


# ---------------------------------------------------------------------------
# 4. BSimConfig flag'leri
# ---------------------------------------------------------------------------


class TestBSimConfigFlags:
    def test_defaults_preserve_shadow_mode(self) -> None:
        """Default config shadow_mode=True ve use_bsim_fusion=False."""
        cfg = BSimConfig()
        assert cfg.shadow_mode is True
        assert cfg.use_bsim_fusion is False
        assert cfg.fusion_min_similarity == pytest.approx(0.7)
        assert cfg.fusion_max_candidates_per_function == 3

    def test_fusion_activation_requires_both_flags(self) -> None:
        """shadow_mode=False AND use_bsim_fusion=True gerekli; tek flag yetmez.

        Bu invariant'i collector'in caller'i (run_name_merger) dogrular.
        Burada BSimConfig'in rollback guvenligini smoke-test ediyoruz:
        default degerler fusion'i aktif etmez.
        """
        cfg = BSimConfig()
        # Default: fusion OFF
        assert not (not cfg.shadow_mode and cfg.use_bsim_fusion)
        # Sadece shadow kapatilsa: yine OFF
        cfg.shadow_mode = False
        assert not (not cfg.shadow_mode and cfg.use_bsim_fusion)
        # Sadece fusion flag acilsa: yine OFF (shadow yeniden True)
        cfg.shadow_mode = True
        cfg.use_bsim_fusion = True
        assert not (not cfg.shadow_mode and cfg.use_bsim_fusion)
        # Her ikisi: ON
        cfg.shadow_mode = False
        cfg.use_bsim_fusion = True
        assert (not cfg.shadow_mode and cfg.use_bsim_fusion)


# ---------------------------------------------------------------------------
# 5. _add_bsim dogrudan unit
# ---------------------------------------------------------------------------


class TestAddBsimDirect:
    def test_add_bsim_idempotent_under_empty_matches(self) -> None:
        """matches=[] -> candidates degismez, stats dokunulmaz."""
        candidates: dict[str, list[Any]] = {}
        stats: dict[str, Any] = {}
        _add_bsim(
            bsim_shadow={"matches": []},
            candidates=candidates,
            min_similarity=0.7,
            max_per_function=3,
            stats=stats,
        )
        assert candidates == {}
        assert "bsim_fusion_candidates" not in stats

    def test_add_bsim_appends_not_replaces(self) -> None:
        """Mevcut candidate listesine append eder, silmez."""
        existing = NamingCandidate("c_namer_guess", 0.7, "c_namer")
        candidates: dict[str, list[Any]] = {
            "FUN_1": [existing],
        }
        payload = {
            "matches": [{
                "function_addr": "0x1",
                "function_name": "FUN_1",
                "bsim_candidates": [
                    {"name": "bsim_guess", "similarity": 0.88, "binary": "x"},
                ],
            }],
        }
        _add_bsim(
            bsim_shadow=payload,
            candidates=candidates,
            min_similarity=0.7,
            max_per_function=3,
            stats={},
        )
        assert len(candidates["FUN_1"]) == 2
        sources = {c.source for c in candidates["FUN_1"]}
        assert sources == {"c_namer", "bsim"}
