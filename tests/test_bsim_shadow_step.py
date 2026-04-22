"""v1.11.0 Hafta 1 — BSimMatchStep shadow mode testleri.

Kapsam:
    1. Step registry'de kayitli mi (name, requires, produces).
    2. config.bsim.enabled=False -> NO-OP (disabled status).
    3. bsim_matches.json yoksa shadow payload bos (sessiz).
    4. Gercek format JSON verilince shadow payload dogru normalize oluyor.
    5. shadow_mode=True iken NameMerger/fusion'a HIC yazilmiyor
       (artifacts yalnizca bsim_shadow + bsim_shadow_path).
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from karadul.pipeline.context import StepContext
from karadul.pipeline.registry import get_step
from karadul.pipeline.steps.bsim_match import BSimMatchStep


@pytest.fixture
def fake_pc(tmp_path: Path):
    static_dir = tmp_path / "static"
    deob_dir = tmp_path / "deobfuscated"
    recon_dir = tmp_path / "reconstructed"
    for d in (static_dir, deob_dir, recon_dir):
        d.mkdir(parents=True, exist_ok=True)

    def _stage_dir(name: str) -> Path:
        return {
            "static": static_dir,
            "deobfuscated": deob_dir,
            "reconstructed": recon_dir,
        }[name]

    saved: dict[str, Path] = {}

    def _save_json(stage: str, name: str, data: dict) -> Path:
        p = _stage_dir(stage) / f"{name}.json"
        p.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
        saved[name] = p
        return p

    pc = MagicMock()
    pc.workspace.get_stage_dir.side_effect = _stage_dir
    pc.workspace.save_json.side_effect = _save_json
    pc.workspace._saved = saved  # test inspection
    pc.metadata = {}
    pc.config = MagicMock()
    pc.config.bsim.enabled = True
    pc.config.bsim.shadow_mode = True
    pc.report_progress = MagicMock()
    return pc


@pytest.fixture
def base_ctx(fake_pc, tmp_path: Path):
    ctx = StepContext(pipeline_context=fake_pc)
    ctx._write_artifacts({
        "functions_json_path": tmp_path / "functions.json",
    })
    return ctx


# --- Registry -----------------------------------------------------------

class TestBSimShadowRegistry:
    def test_registered_with_expected_contract(self) -> None:
        import karadul.pipeline  # noqa: F401 — decorator register
        spec = get_step("bsim_match")
        assert "functions_json_path" in spec.requires
        assert "bsim_shadow" in spec.produces
        assert "bsim_shadow_path" in spec.produces


# --- Disabled -----------------------------------------------------------

class TestBSimShadowDisabled:
    def test_disabled_noop(self, fake_pc, base_ctx) -> None:
        fake_pc.config.bsim.enabled = False
        out = BSimMatchStep().run(base_ctx)
        assert out == {"bsim_shadow": None, "bsim_shadow_path": None}
        assert base_ctx.stats["bsim_shadow_status"] == "disabled"
        # Hicbir JSON yazilmadi (workspace.save_json cagrilmadi)
        assert not fake_pc.workspace._saved
        # NameMerger'a sinyal gitmedi
        assert "artifacts_pending" not in fake_pc.metadata or \
            "bsim" not in (fake_pc.metadata.get("artifacts_pending") or {})


# --- No raw JSON --------------------------------------------------------

class TestBSimShadowNoRawJson:
    def test_missing_bsim_matches_json_yields_empty_shadow(
        self, fake_pc, base_ctx,
    ) -> None:
        """bsim_matches.json yoksa step sessizce bos shadow uretir."""
        out = BSimMatchStep().run(base_ctx)
        shadow = out["bsim_shadow"]
        assert shadow is not None
        assert shadow["version"] == "1"
        assert shadow["mode"] == "shadow"
        assert shadow["total_matches"] == 0
        assert shadow["matches"] == []
        # Artifact yine de yazilir (mode gozlemi icin)
        assert out["bsim_shadow_path"] is not None
        assert out["bsim_shadow_path"].exists()
        assert base_ctx.stats["bsim_shadow_total"] == 0
        assert base_ctx.stats["bsim_shadow_status"] == "shadow"


# --- Happy path ---------------------------------------------------------

class TestBSimShadowWithRawMatches:
    def test_normalizes_headless_output_format(
        self, fake_pc, base_ctx, tmp_path,
    ) -> None:
        """Headless bsim_matches.json -> bsim_shadow.json normalize akisi."""
        # headless.py L406-L419'un yazdigi gercek format
        raw = {
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
        static_dir = fake_pc.workspace.get_stage_dir("static")
        gout = static_dir / "ghidra_output"
        gout.mkdir(parents=True, exist_ok=True)
        (gout / "bsim_matches.json").write_text(
            json.dumps(raw), encoding="utf-8",
        )

        out = BSimMatchStep().run(base_ctx)
        shadow = out["bsim_shadow"]
        assert shadow["mode"] == "shadow"
        assert shadow["database"] == "karadul_bsim"
        assert shadow["total_matches"] == 3
        # 2 unique fonksiyon
        assert len(shadow["matches"]) == 2

        # Determinism: fonksiyonlar adrese gore sirali
        addrs = [m["function_addr"] for m in shadow["matches"]]
        assert addrs == sorted(addrs)

        # Ilk fonksiyonun candidate'lari similarity desc sirali
        fun460 = next(
            m for m in shadow["matches"]
            if m["function_addr"] == "0x100000460"
        )
        sims = [c["similarity"] for c in fun460["bsim_candidates"]]
        assert sims == sorted(sims, reverse=True)
        assert fun460["bsim_candidates"][0]["name"] == "_print_info"
        assert fun460["bsim_candidates"][0]["similarity"] == 0.92

        # Artifact dosyasi gercekten yazildi
        assert out["bsim_shadow_path"].exists()
        on_disk = json.loads(
            out["bsim_shadow_path"].read_text(encoding="utf-8"),
        )
        assert on_disk["total_matches"] == 3

    def test_shadow_mode_does_not_touch_name_merger(
        self, fake_pc, base_ctx,
    ) -> None:
        """shadow_mode=True iken NameMerger/fusion sinyali YOK kurali."""
        # Raw JSON yaz
        raw = {
            "total_matches": 1,
            "database": "karadul_bsim",
            "matches": [{
                "query_function": "FUN_100000460",
                "query_address": "0x100000460",
                "matched_function": "_print_info",
                "matched_program": "sample",
                "similarity": 0.9,
            }],
        }
        static_dir = fake_pc.workspace.get_stage_dir("static")
        gout = static_dir / "ghidra_output"
        gout.mkdir(parents=True, exist_ok=True)
        (gout / "bsim_matches.json").write_text(
            json.dumps(raw), encoding="utf-8",
        )

        BSimMatchStep().run(base_ctx)

        # Fusion/NameMerger kanallarina YAZIM olmamali.
        # Pipeline convention: naming_candidates, name_merger_evidence,
        # fusion_sources vs. artifact'lar shadow mode'da dokunulmaz.
        forbidden_keys = {
            "name_merger_evidence",
            "fusion_sources",
            "bsim_evidence",
            "naming_candidates_bsim",
        }
        pending = (fake_pc.metadata or {}).get("artifacts_pending", {})
        leaked = forbidden_keys.intersection(pending.keys())
        assert not leaked, f"Shadow mode fusion sizintisi: {leaked}"
        # Ve step artifact'larinin da NameMerger key'i yok
        assert set(base_ctx.artifacts.keys()) & forbidden_keys == set()


# --- Malformed input guard ----------------------------------------------

class TestBSimShadowMalformed:
    def test_malformed_json_does_not_crash(self, fake_pc, base_ctx) -> None:
        """Bozuk bsim_matches.json parse hatasi yakalanir, step patlamaz."""
        static_dir = fake_pc.workspace.get_stage_dir("static")
        gout = static_dir / "ghidra_output"
        gout.mkdir(parents=True, exist_ok=True)
        (gout / "bsim_matches.json").write_text(
            "{not valid json", encoding="utf-8",
        )

        out = BSimMatchStep().run(base_ctx)
        # Bos shadow, ama yine de yazilmis
        assert out["bsim_shadow"]["total_matches"] == 0
        assert any("bsim_match parse" in e for e in base_ctx.errors)
