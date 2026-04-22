"""v1.10.0 fix sprint: batch.py ve platform_map.py regresyon testleri.

Kapsam:
    E9: platform_map.py tum TargetType'lari kapsamalı (JS, Electron, .NET,
        Delphi, Go, Bun, APK/JAR, Python).
    E10: resolve_targets bilinmeyen hedefler icin uyari + oneri uretmeli.
    H5: analyze_single_target skip_dynamic=False kosulunda DynamicAnalysisStage
        kullandigini belgelemeli (smoke test, Frida olmadan bile IMPORT
        polymorphism'i dogrulanabilir).
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest


# ===========================================================================
# E9: platform_map kapsami
# ===========================================================================

class TestPlatformMapCoverage:
    """TARGET_PLATFORM_MAP tum production TargetType'lari icermeli."""

    def test_native_binaries(self) -> None:
        from karadul.core.platform_map import TARGET_PLATFORM_MAP
        from karadul.core.target import TargetType

        assert TARGET_PLATFORM_MAP[TargetType.MACHO_BINARY] == "macho"
        assert TARGET_PLATFORM_MAP[TargetType.UNIVERSAL_BINARY] == "macho"
        assert TARGET_PLATFORM_MAP[TargetType.ELF_BINARY] == "elf"
        assert TARGET_PLATFORM_MAP[TargetType.PE_BINARY] == "pe"

    def test_js_targets(self) -> None:
        """v1.10.0 E9: JS_BUNDLE ve ELECTRON_APP eklendi."""
        from karadul.core.platform_map import TARGET_PLATFORM_MAP
        from karadul.core.target import TargetType

        assert TARGET_PLATFORM_MAP[TargetType.JS_BUNDLE] == "js"
        assert TARGET_PLATFORM_MAP[TargetType.ELECTRON_APP] == "js"

    def test_app_bundle(self) -> None:
        """macOS .app bundle -> macho (main executable Mach-O)."""
        from karadul.core.platform_map import TARGET_PLATFORM_MAP
        from karadul.core.target import TargetType

        assert TARGET_PLATFORM_MAP[TargetType.APP_BUNDLE] == "macho"

    def test_jvm_and_android(self) -> None:
        from karadul.core.platform_map import TARGET_PLATFORM_MAP
        from karadul.core.target import TargetType

        assert TARGET_PLATFORM_MAP[TargetType.JAVA_JAR] == "java"
        assert TARGET_PLATFORM_MAP[TargetType.ANDROID_APK] == "android"

    def test_dotnet_delphi(self) -> None:
        from karadul.core.platform_map import TARGET_PLATFORM_MAP
        from karadul.core.target import TargetType

        assert TARGET_PLATFORM_MAP[TargetType.DOTNET_ASSEMBLY] == "dotnet"
        assert TARGET_PLATFORM_MAP[TargetType.DELPHI_BINARY] == "pe"

    def test_go_and_bun(self) -> None:
        from karadul.core.platform_map import TARGET_PLATFORM_MAP
        from karadul.core.target import TargetType

        assert TARGET_PLATFORM_MAP[TargetType.GO_BINARY] == "go"
        assert TARGET_PLATFORM_MAP[TargetType.BUN_BINARY] == "macho"

    def test_python_packed(self) -> None:
        from karadul.core.platform_map import TARGET_PLATFORM_MAP
        from karadul.core.target import TargetType

        assert TARGET_PLATFORM_MAP[TargetType.PYTHON_PACKED] == "python"

    def test_all_non_unknown_types_have_mapping(self) -> None:
        """UNKNOWN disinda TUM TargetType'lar platform map'te olmali.

        v1.10.0 E9: Bu test regresyon guvenligi icin. Yeni TargetType
        eklendiginde platform_map'e de eklenmeli.
        """
        from karadul.core.platform_map import TARGET_PLATFORM_MAP
        from karadul.core.target import TargetType

        missing: list[str] = []
        for tt in TargetType:
            if tt == TargetType.UNKNOWN:
                continue
            if tt not in TARGET_PLATFORM_MAP:
                missing.append(tt.name)
        assert not missing, f"Platform map'te eksik tipler: {missing}"


# ===========================================================================
# E10: resolve_targets fuzzy match + uyari
# ===========================================================================

class TestResolveTargetsFuzzy:
    """Bilinmeyen hedef isimleri icin uyari ve oneri uretilmeli."""

    def test_known_name_resolves(self) -> None:
        from karadul.batch import resolve_targets

        result = resolve_targets("discord")
        assert "discord" in result

    def test_unknown_name_warns_with_suggestion(
        self, caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Bilinmeyen ama yakin isme sahip hedef -> oneri loglanmali."""
        from karadul.batch import resolve_targets

        with caplog.at_level(logging.WARNING, logger="karadul.batch"):
            result = resolve_targets("discrd")  # discord yazim hatasi

        assert result == {}
        # Uyari loglanmali
        warning_text = " ".join(rec.getMessage() for rec in caplog.records)
        assert "discrd" in warning_text
        assert "oneri" in warning_text.lower() or "discord" in warning_text

    def test_unknown_name_no_match_still_warns(
        self, caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Hicbir oneriye yakin olmayan isim icin bile uyari loglanmali."""
        from karadul.batch import resolve_targets

        with caplog.at_level(logging.WARNING, logger="karadul.batch"):
            result = resolve_targets("zzzzzzzxxxxxxxx")

        assert result == {}
        warning_text = " ".join(rec.getMessage() for rec in caplog.records)
        assert "zzzzzzzxxxxxxxx" in warning_text

    def test_mixed_known_unknown(
        self, caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Bilinen ve bilinmeyen hedefler karisikken bilinen resolve edilmeli."""
        from karadul.batch import resolve_targets

        with caplog.at_level(logging.WARNING, logger="karadul.batch"):
            result = resolve_targets("discord,totallyunknowntarget")

        assert "discord" in result
        assert "totallyunknowntarget" not in result
        # Bilinmeyen icin uyari
        warning_text = " ".join(rec.getMessage() for rec in caplog.records)
        assert "totallyunknowntarget" in warning_text

    def test_group_spec_unchanged(self) -> None:
        """Grup spec'leri (electron, binary, js, cursor, all) calismaya devam."""
        from karadul.batch import (
            resolve_targets,
            ELECTRON_TARGETS,
            BINARY_TARGETS,
            JS_TARGETS,
            CURSOR_TARGETS,
            ALL_TARGETS,
        )

        assert resolve_targets("electron") == dict(ELECTRON_TARGETS)
        assert resolve_targets("binary") == dict(BINARY_TARGETS)
        assert resolve_targets("js") == dict(JS_TARGETS)
        assert resolve_targets("cursor") == dict(CURSOR_TARGETS)
        assert resolve_targets("all") == dict(ALL_TARGETS)


# ===========================================================================
# H5: analyze_single_target skip_dynamic parametresi gercekten etkili
# ===========================================================================

class TestBatchSkipDynamic:
    """``skip_dynamic`` parametresinin pipeline stage listesini etkilemesi."""

    def test_nonexistent_target_skipped_gracefully(
        self, tmp_path: Path,
    ) -> None:
        """Olmayan dosya -> skipped=True, exception yok."""
        from karadul.batch import analyze_single_target

        result = analyze_single_target(
            name="bogus",
            path_str=str(tmp_path / "nope.bin"),
            project_root=tmp_path,
            skip_dynamic=True,
        )
        assert result.skipped is True
        assert "bulunamadi" in result.skip_reason.lower()

    def test_skip_dynamic_false_registers_dynamic_stage(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """v1.10.0 H5: skip_dynamic=False -> DynamicAnalysisStage register.

        Stage'in gercekten Frida calistirmasini beklemiyoruz; sadece
        pipeline'a kaydedildigini dogruluyoruz.
        """
        from karadul.batch import analyze_single_target

        # Pipeline.run ve stage cagrilarini mock'lamak yerine Pipeline
        # sinifinin register_stage'ini izliyoruz.
        registered: list[str] = []

        import karadul.core.pipeline as pipeline_mod
        real_register = pipeline_mod.Pipeline.register_stage

        def spy_register(self, stage):  # noqa: ANN001
            registered.append(stage.__class__.__name__)
            return real_register(self, stage)

        monkeypatch.setattr(
            pipeline_mod.Pipeline, "register_stage", spy_register,
        )

        # Pipeline.run'i mock'layip gercek analiz calistirmayi engelle
        def fake_run(self, target, stages=None):  # noqa: ANN001
            from karadul.core.result import PipelineResult
            return PipelineResult(
                target_name="fake",
                target_hash="00" * 32,
                workspace_path=tmp_path / "ws",
                stages={},
                success=True,
            )

        monkeypatch.setattr(pipeline_mod.Pipeline, "run", fake_run)

        # Workspace'i olusturma zorunlulugu olmasin diye gecici dosya olustur
        fake_bin = tmp_path / "fake.bin"
        fake_bin.write_bytes(b"\x7fELF" + b"\x00" * 100)

        analyze_single_target(
            name="fake",
            path_str=str(fake_bin),
            project_root=tmp_path,
            skip_dynamic=False,
        )

        # DynamicAnalysisStage register edilmis olmali
        assert "DynamicAnalysisStage" in registered, (
            f"skip_dynamic=False iken DynamicAnalysisStage eklenmedi. "
            f"Register edilenler: {registered}"
        )

    def test_skip_dynamic_true_omits_dynamic_stage(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """skip_dynamic=True -> DynamicAnalysisStage register EDILMEMELI."""
        from karadul.batch import analyze_single_target

        registered: list[str] = []

        import karadul.core.pipeline as pipeline_mod
        real_register = pipeline_mod.Pipeline.register_stage

        def spy_register(self, stage):  # noqa: ANN001
            registered.append(stage.__class__.__name__)
            return real_register(self, stage)

        monkeypatch.setattr(
            pipeline_mod.Pipeline, "register_stage", spy_register,
        )

        def fake_run(self, target, stages=None):  # noqa: ANN001
            from karadul.core.result import PipelineResult
            return PipelineResult(
                target_name="fake",
                target_hash="00" * 32,
                workspace_path=tmp_path / "ws",
                stages={},
                success=True,
            )

        monkeypatch.setattr(pipeline_mod.Pipeline, "run", fake_run)

        fake_bin = tmp_path / "fake.bin"
        fake_bin.write_bytes(b"\x7fELF" + b"\x00" * 100)

        analyze_single_target(
            name="fake",
            path_str=str(fake_bin),
            project_root=tmp_path,
            skip_dynamic=True,
        )

        assert "DynamicAnalysisStage" not in registered, (
            "skip_dynamic=True iken DynamicAnalysisStage register edildi!"
        )


# ===========================================================================
# C2+C3: Config defaults
# ===========================================================================

class TestConfigDeprecatedFusion:
    """ComputationRecoveryConfig.enable_signature_fusion default False olmali."""

    def test_signature_fusion_default_false(self) -> None:
        """v1.10.0 C2+C3: Dempster-Shafer deprecated -> default False."""
        from karadul.config import ComputationRecoveryConfig

        cfg = ComputationRecoveryConfig()
        assert cfg.enable_signature_fusion is False, (
            "enable_signature_fusion default False olmali (deprecated). "
            "Yerine ComputationConfig.enable_computation_fusion kullanilmali."
        )

    def test_new_computation_fusion_default_true(self) -> None:
        """Yeni fusion (log-odds) v1.10.0 "ship it" karari ile default True.

        Berke karari: Yeni pipeline varsayilan aktif, kapatmak icin
        ``--no-computation-fusion`` flag'i kullanilir. Eski D-S (enable_signature_fusion)
        hala False (deprecated, v1.11.0'da silinecek).
        """
        from karadul.computation.config import ComputationConfig

        cfg = ComputationConfig()
        assert cfg.enable_computation_fusion is True, (
            "v1.10.0'dan itibaren log-odds fusion default AKTIF. "
            "Kapatmak icin --no-computation-fusion flag'i kullanin."
        )
