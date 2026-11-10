"""v1.10.0 M1 T3.5 — FlowSimplifyStep testleri."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from karadul.pipeline.context import StepContext
from karadul.pipeline.registry import get_step
from karadul.pipeline.steps.flow_simplify import FlowSimplifyStep


@pytest.fixture
def fake_pc():
    pc = MagicMock()
    pc.metadata = {}
    return pc


@pytest.fixture
def base_ctx(fake_pc, tmp_path: Path):
    ctx = StepContext(pipeline_context=fake_pc)
    ctx._write_artifacts({
        "semantic_naming_decompiled_dir": tmp_path / "decompiled",
    })
    return ctx


class TestRegistry:
    def test_registered(self) -> None:
        spec = get_step("flow_simplify")
        assert "semantic_naming_decompiled_dir" in spec.requires
        assert "flow_simplify_decompiled_dir" in spec.produces
        assert "timing_flow_simplify" in spec.produces


class TestHappyPath:
    def test_simplifier_stats_propagated(self, base_ctx, tmp_path: Path) -> None:
        fake_result = MagicMock(
            gotos_eliminated=5,
            labels_renamed=3,
            labels_inlined=2,
            early_returns=1,
            breaks_continues=4,
            ifelse_restructured=0,
            cascading_collapsed=6,
            multi_target_inlined=1,
        )
        fake_cls = MagicMock()
        fake_cls.return_value.simplify_directory.return_value = fake_result

        with patch(
            "karadul.reconstruction.c_flow_simplifier.CFlowSimplifier", fake_cls,
        ):
            out = FlowSimplifyStep().run(base_ctx)

        assert out["flow_simplify_decompiled_dir"] == tmp_path / "decompiled"
        assert base_ctx.stats["flow_gotos_eliminated"] == 5
        assert base_ctx.stats["flow_cascading_collapsed"] == 6


class TestException:
    def test_simplifier_exception_swallowed(self, base_ctx) -> None:
        fake_cls = MagicMock()
        fake_cls.return_value.simplify_directory.side_effect = RuntimeError("boom")
        with patch(
            "karadul.reconstruction.c_flow_simplifier.CFlowSimplifier", fake_cls,
        ):
            out = FlowSimplifyStep().run(base_ctx)
        # Hata sessizce yutuluyor, timing yine yazilmali
        assert "timing_flow_simplify" in out


class TestGuardCounters:
    """Ard koşul sayaçları rapora ulaşır; geri alınan fonksiyon sessiz kalmaz (2026-11-10)."""

    def _run(self, base_ctx, **alanlar):
        from karadul.reconstruction.c_flow_simplifier import SimplifyResult
        fake_cls = MagicMock()
        fake_cls.return_value.simplify_directory.return_value = SimplifyResult(**alanlar)
        with patch(
            "karadul.reconstruction.c_flow_simplifier.CFlowSimplifier", fake_cls,
        ):
            FlowSimplifyStep().run(base_ctx)

    def test_temiz_kosuda_sayaclar_sifir_ve_hata_yok(self, base_ctx) -> None:
        self._run(base_ctx, gotos_eliminated=3)
        assert base_ctx.stats["flow_functions_reverted"] == 0
        assert base_ctx.stats["flow_functions_skipped"] == 0
        assert base_ctx.stats["flow_files_failed"] == 0
        assert base_ctx.errors == []

    def test_geri_alinan_fonksiyon_uyari_olur(self, base_ctx) -> None:
        self._run(base_ctx, functions_reverted=2, functions_skipped=5)
        assert base_ctx.stats["flow_functions_reverted"] == 2
        assert base_ctx.stats["flow_functions_skipped"] == 5
        assert len(base_ctx.errors) == 1
        assert "2 fonksiyon" in base_ctx.errors[0] and "0 dosya" in base_ctx.errors[0]

    def test_islenemeyen_dosya_uyari_olur(self, base_ctx) -> None:
        self._run(base_ctx, files_failed=1)
        assert base_ctx.stats["flow_files_failed"] == 1
        assert len(base_ctx.errors) == 1 and "1 dosya" in base_ctx.errors[0]

    def test_yalniz_atlanan_fonksiyon_uyari_degildir(self, base_ctx) -> None:
        # Ayrıştırılamadığı için dokunulmayan fonksiyon hata değildir: girdi geçerli C olmayabilir
        self._run(base_ctx, functions_skipped=7)
        assert base_ctx.stats["flow_functions_skipped"] == 7
        assert base_ctx.errors == []

    def test_eski_sonuc_nesnesinde_sayac_uydurulmaz(self, base_ctx) -> None:
        fake_cls = MagicMock()
        fake_cls.return_value.simplify_directory.return_value = MagicMock(gotos_eliminated=1)
        with patch(
            "karadul.reconstruction.c_flow_simplifier.CFlowSimplifier", fake_cls,
        ):
            FlowSimplifyStep().run(base_ctx)
        assert not any(k.startswith("flow_functions_") or k == "flow_files_failed" for k in base_ctx.stats)
        assert base_ctx.errors == []
