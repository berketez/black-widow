"""v1.11.0 — `karadul.ghidra._bsim_shadow.build_shadow_payload` odakli testler.

Kapsam (saf data transform — Ghidra/binary mock GEREKMEZ):
    1. Happy path: shadow mode + dolu raw_data -> v1 shadow yapisi.
    2. Mode dallanmasi: shadow_mode=True/False -> "shadow"/"live-dump-only".
    3. Bos / None / uyumsuz girdi -> guvenli bos base payload.
    4. Bozuk eleman / bozuk similarity -> defansif filtre / fallback.
    5. Determinism: tekrar cagri, ayni siralama. Adres bazli sort, candidate
       similarity DESC sirali.
    6. SHADOW_VERSION sabit "1" regresyon koruyucusu.
    7. BSimMatchStep._build_shadow_payload shim'i ile birebir ayni cikti
       (geriye uyumluluk garantisi).
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

import pytest

from karadul.ghidra._bsim_shadow import (
    SHADOW_VERSION,
    build_shadow_payload,
)
from karadul.pipeline.steps.bsim_match import BSimMatchStep


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def headless_raw_three_matches() -> dict[str, Any]:
    """headless.py BSim format — 2 unique fonksiyon, 3 match."""
    return {
        "total_matches": 3,
        "database": "karadul_bsim",
        "matches": [
            {
                "query_function": "FUN_100000460",
                "query_address": "0x100000460",
                "matched_function": "_print_info",
                "matched_program": "sample_a",
                "similarity": 0.92,
            },
            {
                "query_function": "FUN_100000460",
                "query_address": "0x100000460",
                "matched_function": "_print_banner",
                "matched_program": "sample_b",
                "similarity": 0.81,
            },
            {
                "query_function": "FUN_100000500",
                "query_address": "0x100000500",
                "matched_function": "_parse_args",
                "matched_program": "sample_a",
                "similarity": 0.75,
            },
        ],
    }


# ---------------------------------------------------------------------------
# 1) Happy path — shadow mode
# ---------------------------------------------------------------------------

class TestBuildShadowPayloadHappyPath:
    def test_returns_v1_shadow_envelope(
        self, headless_raw_three_matches: dict[str, Any],
    ) -> None:
        """Temel zarf alanlari (version/mode/database/total) dogru."""
        out = build_shadow_payload(
            raw_data=headless_raw_three_matches, shadow_mode=True,
        )
        assert out["version"] == "1"
        assert out["mode"] == "shadow"
        assert out["database"] == "karadul_bsim"
        assert out["total_matches"] == 3
        assert isinstance(out["matches"], list)

    def test_timestamp_is_iso8601_utc(
        self, headless_raw_three_matches: dict[str, Any],
    ) -> None:
        """timestamp ISO-8601 parse edilebilir olmali."""
        out = build_shadow_payload(
            raw_data=headless_raw_three_matches, shadow_mode=True,
        )
        # fromisoformat ISO-8601 (UTC tz dahil) parse eder.
        parsed = datetime.fromisoformat(out["timestamp"])
        assert parsed.tzinfo is not None

    def test_groups_by_query_function(
        self, headless_raw_three_matches: dict[str, Any],
    ) -> None:
        """Ayni query_function+query_address tek entry'de toplanir."""
        out = build_shadow_payload(
            raw_data=headless_raw_three_matches, shadow_mode=True,
        )
        # 3 raw match -> 2 unique fonksiyon
        assert len(out["matches"]) == 2

        fun460 = next(
            m for m in out["matches"]
            if m["function_addr"] == "0x100000460"
        )
        assert fun460["function_name"] == "FUN_100000460"
        assert len(fun460["bsim_candidates"]) == 2

    def test_candidates_sorted_by_similarity_desc(
        self, headless_raw_three_matches: dict[str, Any],
    ) -> None:
        """bsim_candidates similarity DESC sirali."""
        out = build_shadow_payload(
            raw_data=headless_raw_three_matches, shadow_mode=True,
        )
        fun460 = next(
            m for m in out["matches"]
            if m["function_addr"] == "0x100000460"
        )
        sims = [c["similarity"] for c in fun460["bsim_candidates"]]
        assert sims == sorted(sims, reverse=True)
        # En yuksek similarity ilk sirada
        assert fun460["bsim_candidates"][0]["name"] == "_print_info"
        assert fun460["bsim_candidates"][0]["similarity"] == 0.92
        assert fun460["bsim_candidates"][0]["binary"] == "sample_a"

    def test_matches_sorted_by_address(
        self, headless_raw_three_matches: dict[str, Any],
    ) -> None:
        """Ust seviye matches listesi (function_addr, function_name) bazli sort."""
        out = build_shadow_payload(
            raw_data=headless_raw_three_matches, shadow_mode=True,
        )
        addrs = [m["function_addr"] for m in out["matches"]]
        assert addrs == sorted(addrs)


# ---------------------------------------------------------------------------
# 2) Mode dallanmasi
# ---------------------------------------------------------------------------

class TestBuildShadowPayloadMode:
    def test_shadow_mode_true_yields_shadow(
        self, headless_raw_three_matches: dict[str, Any],
    ) -> None:
        out = build_shadow_payload(
            raw_data=headless_raw_three_matches, shadow_mode=True,
        )
        assert out["mode"] == "shadow"

    def test_shadow_mode_false_yields_live_dump_only(
        self, headless_raw_three_matches: dict[str, Any],
    ) -> None:
        """shadow_mode=False -> mode='live-dump-only' (gozlem-only mode)."""
        out = build_shadow_payload(
            raw_data=headless_raw_three_matches, shadow_mode=False,
        )
        assert out["mode"] == "live-dump-only"
        # Diger alanlar yine ayni sekilde dolu
        assert out["total_matches"] == 3
        assert len(out["matches"]) == 2


# ---------------------------------------------------------------------------
# 3) Bos / None / uyumsuz girdi
# ---------------------------------------------------------------------------

class TestBuildShadowPayloadEmptyInput:
    def test_none_raw_data_returns_empty_base(self) -> None:
        out = build_shadow_payload(raw_data=None, shadow_mode=True)
        assert out["version"] == "1"
        assert out["mode"] == "shadow"
        assert out["database"] == ""
        assert out["total_matches"] == 0
        assert out["matches"] == []

    def test_empty_dict_returns_empty_base(self) -> None:
        out = build_shadow_payload(raw_data={}, shadow_mode=True)
        # `not raw_data` -> base'e kisa devre
        assert out["total_matches"] == 0
        assert out["matches"] == []
        assert out["database"] == ""

    def test_matches_field_not_a_list_is_defensive(self) -> None:
        """matches alani string ise -> sessiz, bos matches."""
        out = build_shadow_payload(
            raw_data={"matches": "not-a-list", "database": "x"},
            shadow_mode=True,
        )
        assert out["total_matches"] == 0
        assert out["matches"] == []
        # database yine de okunur
        assert out["database"] == "x"

    def test_missing_matches_key_is_safe(self) -> None:
        """matches key yok -> [] varsayilani."""
        out = build_shadow_payload(
            raw_data={"database": "only_meta"}, shadow_mode=True,
        )
        assert out["total_matches"] == 0
        assert out["matches"] == []
        assert out["database"] == "only_meta"


# ---------------------------------------------------------------------------
# 4) Bozuk / eksik eleman
# ---------------------------------------------------------------------------

class TestBuildShadowPayloadMalformedItems:
    def test_non_dict_match_items_skipped(self) -> None:
        """matches icinde dict olmayan eleman atlanir."""
        raw = {
            "database": "db",
            "matches": [
                "string-eleman",
                None,
                123,
                {
                    "query_function": "FUN_a",
                    "query_address": "0xa",
                    "matched_function": "m",
                    "matched_program": "p",
                    "similarity": 0.5,
                },
            ],
        }
        out = build_shadow_payload(raw_data=raw, shadow_mode=True)
        assert out["total_matches"] == 1
        assert len(out["matches"]) == 1
        assert out["matches"][0]["function_name"] == "FUN_a"

    def test_missing_q_name_and_q_addr_skipped(self) -> None:
        """q_name VE q_addr ikisi de bos -> eleman atlanir."""
        raw = {
            "database": "db",
            "matches": [
                {  # Atlanmali
                    "query_function": "",
                    "query_address": "",
                    "matched_function": "ghost",
                    "matched_program": "p",
                    "similarity": 0.99,
                },
                {  # Sadece addr var -> alinmali
                    "query_function": "",
                    "query_address": "0xb",
                    "matched_function": "real",
                    "matched_program": "p",
                    "similarity": 0.5,
                },
                {  # Sadece name var -> alinmali
                    "query_function": "FUN_only_name",
                    "query_address": "",
                    "matched_function": "real2",
                    "matched_program": "p",
                    "similarity": 0.4,
                },
            ],
        }
        out = build_shadow_payload(raw_data=raw, shadow_mode=True)
        assert out["total_matches"] == 2
        names = {m["function_name"] for m in out["matches"]}
        assert "" in names or "FUN_only_name" in names
        # 'ghost' candidate hicbir entry'de yok (kaynak match atlandi)
        all_candidates = [
            c["name"]
            for m in out["matches"]
            for c in m["bsim_candidates"]
        ]
        assert "ghost" not in all_candidates

    @pytest.mark.parametrize("bad_sim,expected", [
        (None, 0.0),
        ("yuksek", 0.0),
        ("", 0.0),
        ([0.9], 0.0),
        (float("nan"), float("nan")),  # NaN float() basarir, NaN kalir
    ])
    def test_non_numeric_similarity_falls_back_to_zero(
        self, bad_sim: Any, expected: float,
    ) -> None:
        """similarity numerik degil -> 0.0 fallback (NaN haric)."""
        raw = {
            "database": "db",
            "matches": [{
                "query_function": "FUN_a",
                "query_address": "0xa",
                "matched_function": "m",
                "matched_program": "p",
                "similarity": bad_sim,
            }],
        }
        out = build_shadow_payload(raw_data=raw, shadow_mode=True)
        sim = out["matches"][0]["bsim_candidates"][0]["similarity"]
        if expected != expected:  # NaN check
            assert sim != sim
        else:
            assert sim == expected

    def test_non_dict_raw_data_returns_base(self) -> None:
        """raw_data dict degilse (liste, string) -> bos base."""
        out = build_shadow_payload(
            raw_data=["not", "a", "dict"],  # type: ignore[arg-type]
            shadow_mode=True,
        )
        assert out["total_matches"] == 0
        assert out["matches"] == []


# ---------------------------------------------------------------------------
# 5) Determinism
# ---------------------------------------------------------------------------

class TestBuildShadowPayloadDeterminism:
    def test_same_input_yields_same_structure(
        self, headless_raw_three_matches: dict[str, Any],
    ) -> None:
        """Iki cagri -> matches+candidates siralamasi ayni (timestamp haric)."""
        a = build_shadow_payload(
            raw_data=headless_raw_three_matches, shadow_mode=True,
        )
        b = build_shadow_payload(
            raw_data=headless_raw_three_matches, shadow_mode=True,
        )
        # timestamp'i kiyastan cikar
        a.pop("timestamp")
        b.pop("timestamp")
        assert a == b

    def test_input_order_independent(self) -> None:
        """Raw matches sirasi degisse de output ayni grupla+sort sonucu uretir."""
        m_high = {
            "query_function": "FUN_a",
            "query_address": "0xa",
            "matched_function": "high",
            "matched_program": "p",
            "similarity": 0.9,
        }
        m_low = {
            "query_function": "FUN_a",
            "query_address": "0xa",
            "matched_function": "low",
            "matched_program": "p",
            "similarity": 0.1,
        }
        out_a = build_shadow_payload(
            raw_data={"database": "d", "matches": [m_high, m_low]},
            shadow_mode=True,
        )
        out_b = build_shadow_payload(
            raw_data={"database": "d", "matches": [m_low, m_high]},
            shadow_mode=True,
        )
        out_a.pop("timestamp")
        out_b.pop("timestamp")
        assert out_a == out_b
        # Ve candidate sirasi DESC
        sims = [
            c["similarity"]
            for c in out_a["matches"][0]["bsim_candidates"]
        ]
        assert sims == [0.9, 0.1]


# ---------------------------------------------------------------------------
# 6) Sabit regresyon
# ---------------------------------------------------------------------------

class TestShadowVersionConstant:
    def test_shadow_version_is_one(self) -> None:
        """Shadow format versiyonu artirilirsa bilincli kararla degisecek."""
        assert SHADOW_VERSION == "1"

    def test_payload_version_matches_constant(self) -> None:
        out = build_shadow_payload(raw_data=None, shadow_mode=True)
        assert out["version"] == SHADOW_VERSION


# ---------------------------------------------------------------------------
# 7) BSimMatchStep shim — geriye uyumluluk
# ---------------------------------------------------------------------------

class TestBSimMatchStepShim:
    def test_shim_returns_same_payload_as_utility(
        self, headless_raw_three_matches: dict[str, Any],
    ) -> None:
        """Step._build_shadow_payload <-> utility birebir ayni cikti."""
        via_shim = BSimMatchStep._build_shadow_payload(
            raw_data=headless_raw_three_matches, shadow_mode=True,
        )
        via_util = build_shadow_payload(
            raw_data=headless_raw_three_matches, shadow_mode=True,
        )
        # timestamp farkli olabilir (datetime.now her cagride farkli)
        via_shim.pop("timestamp")
        via_util.pop("timestamp")
        assert via_shim == via_util

    def test_shim_handles_none_like_utility(self) -> None:
        via_shim = BSimMatchStep._build_shadow_payload(
            raw_data=None, shadow_mode=False,
        )
        assert via_shim["version"] == "1"
        assert via_shim["mode"] == "live-dump-only"
        assert via_shim["total_matches"] == 0
        assert via_shim["matches"] == []
