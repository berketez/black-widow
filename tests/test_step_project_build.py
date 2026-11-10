"""v1.10.0 M1 T3.5 — ProjectBuildStep testleri."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from karadul.pipeline.context import StepContext
from karadul.pipeline.registry import get_step
from karadul.pipeline.steps.project_build import ProjectBuildStep


@pytest.fixture
def fake_pc(tmp_path: Path):
    pc = MagicMock()
    reconstructed = tmp_path / "reconstructed"
    reconstructed.mkdir()
    pc.workspace.get_stage_dir = MagicMock(return_value=reconstructed)
    pc.metadata = {}
    pc.report_progress = MagicMock()
    return pc


@pytest.fixture
def base_ctx(fake_pc, tmp_path: Path):
    ctx = StepContext(pipeline_context=fake_pc)
    ctx._write_artifacts({
        "engineering_annotation_decompiled_dir": tmp_path / "annotated",
        "algo_result": None,
    })
    return ctx


class TestRegistry:
    def test_registered(self) -> None:
        spec = get_step("project_build")
        assert "engineering_annotation_decompiled_dir" in spec.requires
        assert "project_dir" in spec.produces


class TestBuildSuccess:
    def test_success_publishes_artifact(self, base_ctx, fake_pc) -> None:
        fake_build = MagicMock(success=True, files_written=42)
        fake_cls = MagicMock()
        fake_cls.return_value.build.return_value = fake_build
        with patch(
            "karadul.reconstruction.c_project_builder.CProjectBuilder", fake_cls,
        ):
            out = ProjectBuildStep().run(base_ctx)
        assert out["project_dir"] is not None
        assert base_ctx.stats["project_files"] == 42
        assert "project_dir" in base_ctx.stage_artifacts


class TestBuildException:
    def test_exception_captured(self, base_ctx) -> None:
        fake_cls = MagicMock()
        fake_cls.return_value.build.side_effect = RuntimeError("disk full")
        with patch(
            "karadul.reconstruction.c_project_builder.CProjectBuilder", fake_cls,
        ):
            ProjectBuildStep().run(base_ctx)
        assert any("disk full" in e for e in base_ctx.errors)


class TestBuildReport:
    """Kurucunun sayımı ve hata listesi rapora ulaşır (2026-11-10: eskiden yutuluyordu)."""

    def _run(self, base_ctx, build_result):
        fake_cls = MagicMock()
        fake_cls.return_value.build.return_value = build_result
        with patch(
            "karadul.reconstruction.c_project_builder.CProjectBuilder", fake_cls,
        ):
            return ProjectBuildStep().run(base_ctx)

    def test_degismez_ihlali_hatalara_gecer(self, base_ctx) -> None:
        from karadul.reconstruction.c_project_builder import CProjectBuildResult
        sonuc = CProjectBuildResult(
            success=False, files_written=3,
            errors=["Değişmez ihlali: 2 fonksiyon çıktıda yok"],
            functions_total=5, functions_placed=3, functions_missing=2, functions_duplicated=0,
        )
        self._run(base_ctx, sonuc)
        assert base_ctx.errors == ["C project build: Değişmez ihlali: 2 fonksiyon çıktıda yok"]
        assert base_ctx.stats["project_functions_total"] == 5
        assert base_ctx.stats["project_functions_placed"] == 3
        assert base_ctx.stats["project_functions_missing"] == 2
        assert base_ctx.stats["project_functions_duplicated"] == 0
        assert "project_files" not in base_ctx.stats      # başarısız kurulum dosya sayısı yazmaz

    def test_basarili_kurulumda_sayim_yazilir_hata_yok(self, base_ctx) -> None:
        from karadul.reconstruction.c_project_builder import CProjectBuildResult
        sonuc = CProjectBuildResult(
            success=True, files_written=4,
            functions_total=4, functions_placed=4, functions_missing=0, functions_duplicated=0,
        )
        self._run(base_ctx, sonuc)
        assert base_ctx.errors == []
        assert base_ctx.stats["project_files"] == 4
        assert base_ctx.stats["project_functions_total"] == 4
        assert base_ctx.stats["project_functions_missing"] == 0

    def test_sayi_olmayan_alan_yazilmaz(self, base_ctx) -> None:
        # Eski biçimli sonuç nesnesi (alanlar yok ya da sayı değil): hiçbir sayaç uydurulmaz
        self._run(base_ctx, MagicMock(success=True, files_written=7))
        assert base_ctx.stats["project_files"] == 7
        assert not any(k.startswith("project_functions_") for k in base_ctx.stats)
        assert base_ctx.errors == []

    def test_liste_olmayan_hata_alani_harf_harf_yazilmaz(self, base_ctx) -> None:
        # errors yanlış türdeyse (dizgi) karakterleri tek tek hata diye yazılmaz
        self._run(base_ctx, MagicMock(success=True, files_written=1, errors="bozuk"))
        assert base_ctx.errors == []
