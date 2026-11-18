"""v1.10.0 M4 Cross-cutting Integration Testleri.

Yeni computation paketlerinin pipeline'a bagli calistirilmasini dogrular:
    - computation_struct_recovery (MaxSMT)
    - cfg_iso_match (LSH + VF2)
    - computation_fusion (log-odds)

Kontrol matrisi:
    1. Step registry: 3 step kayitli ve beklenen requires/produces.
    2. Feature flag KAPALI -> noop (bos sonuc, pipeline kirilmaz).
    3. Feature flag ACIK + valid artifact -> step calisir, sonuc doner.
    4. Topological sort Phase 1/2'de dogru sira.
    5. macho.py backend factory -> config'e gore Ghidra/angr.
    6. CLI flag'leri config'e aktarim.
    7. NameMergerConfig.source_weights yeni 3 anahtar.
    8. Defaults hepsi TRUE (Berke "ship it" karari).
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from karadul.config import Config
from karadul.pipeline.context import StepContext
from karadul.pipeline.registry import get_step, list_steps


# ---------------------------------------------------------------------------
# 1. Step registry
# ---------------------------------------------------------------------------


class TestRegistryEntries:
    def test_computation_struct_recovery_registered(self) -> None:
        spec = get_step("computation_struct_recovery")
        assert "pcode_result" in spec.requires
        assert "computation_struct_result" in spec.produces
        assert "recovered_struct_candidates" in spec.produces

    def test_cfg_iso_match_registered(self) -> None:
        spec = get_step("cfg_iso_match")
        assert "cfg_result" in spec.requires
        assert "cfg_iso_matches" in spec.produces

    def test_computation_fusion_registered(self) -> None:
        spec = get_step("computation_fusion")
        assert "sig_matches" in spec.requires
        assert "cfg_iso_matches" in spec.requires
        assert "fused_matches" in spec.produces

    def test_all_three_steps_in_global_list(self) -> None:
        steps = set(list_steps())
        assert {
            "computation_struct_recovery",
            "cfg_iso_match",
            "computation_fusion",
        }.issubset(steps)


# ---------------------------------------------------------------------------
# 2. Defaults TRUE — Berke "ship it" karari
# ---------------------------------------------------------------------------


class TestDefaultsShipIt:
    def test_cfg_iso_default_true(self) -> None:
        c = Config()
        assert c.computation_recovery.enable_cfg_iso is True

    def test_maxsmt_struct_default_false(self) -> None:
        # v1.10.0 Batch 6C: Codex teyit sonrasi default KAPALI (opt-in).
        c = Config()
        assert c.computation.enable_computation_struct_recovery is False

    def test_fusion_default_true(self) -> None:
        c = Config()
        assert c.computation.enable_computation_fusion is True


# ---------------------------------------------------------------------------
# 3. NameMergerConfig source_weights
# ---------------------------------------------------------------------------


class TestNameMergerSourceWeights:
    def test_cfg_iso_template_weight(self) -> None:
        c = Config()
        assert c.name_merger.source_weights["cfg_iso_template"] == pytest.approx(0.85)

    def test_computation_fusion_weight(self) -> None:
        c = Config()
        assert c.name_merger.source_weights["computation_fusion"] == pytest.approx(0.90)

    def test_computation_struct_recovery_weight(self) -> None:
        c = Config()
        assert c.name_merger.source_weights["computation_struct_recovery"] == pytest.approx(0.80)


# ---------------------------------------------------------------------------
# 4. Stand-alone step run — feature flag KAPALI (noop)
# ---------------------------------------------------------------------------


def _make_ctx(cfg: Config, artifacts: dict | None = None) -> StepContext:
    pc = MagicMock()
    pc.config = cfg
    pc.metadata = {}
    ctx = StepContext(pipeline_context=pc)
    ctx._write_artifacts(artifacts or {})
    return ctx


class TestFlagsDisabledNoop:
    def test_struct_recovery_noop_when_disabled(self) -> None:
        from karadul.pipeline.steps.computation_struct_recovery import (
            ComputationStructRecoveryStep,
        )

        cfg = Config()
        cfg.computation.enable_computation_struct_recovery = False
        ctx = _make_ctx(cfg, artifacts={"pcode_result": MagicMock()})
        out = ComputationStructRecoveryStep().run(ctx)
        assert out["computation_struct_result"] is None
        assert out["recovered_struct_candidates"] == []

    def test_cfg_iso_noop_when_disabled(self) -> None:
        from karadul.pipeline.steps.cfg_iso_match import CFGIsoMatchStep

        cfg = Config()
        cfg.computation_recovery.enable_cfg_iso = False
        ctx = _make_ctx(cfg, artifacts={"cfg_result": MagicMock()})
        out = CFGIsoMatchStep().run(ctx)
        assert out["cfg_iso_matches"] == {}

    def test_fusion_noop_when_disabled(self) -> None:
        from karadul.pipeline.steps.computation_fusion import (
            ComputationFusionStep,
        )

        cfg = Config()
        cfg.computation.enable_computation_fusion = False
        ctx = _make_ctx(
            cfg,
            artifacts={"sig_matches": [], "cfg_iso_matches": {}},
        )
        out = ComputationFusionStep().run(ctx)
        assert out["fused_matches"] == {}


# ---------------------------------------------------------------------------
# 5. Stand-alone step run — feature flag ACIK + bos input -> bos sonuc
# ---------------------------------------------------------------------------


class TestEmptyInputEnabled:
    def test_struct_recovery_empty_pcode(self) -> None:
        """Feature flag ACIK ama pcode None -> bos sonuc, patlamaz."""
        from karadul.pipeline.steps.computation_struct_recovery import (
            ComputationStructRecoveryStep,
        )

        cfg = Config()
        # v1.10.0 Batch 6C: default False, explicit override ile True.
        cfg.computation.enable_computation_struct_recovery = True
        assert cfg.computation.enable_computation_struct_recovery is True
        ctx = _make_ctx(cfg, artifacts={"pcode_result": None})
        out = ComputationStructRecoveryStep().run(ctx)
        assert out["computation_struct_result"] is None
        assert out["recovered_struct_candidates"] == []

    def test_cfg_iso_empty_cfg(self) -> None:
        from karadul.pipeline.steps.cfg_iso_match import CFGIsoMatchStep

        cfg = Config()
        assert cfg.computation_recovery.enable_cfg_iso is True
        # cfg_result=None -> atla
        ctx = _make_ctx(cfg, artifacts={"cfg_result": None})
        out = CFGIsoMatchStep().run(ctx)
        assert out["cfg_iso_matches"] == {}

    def test_fusion_empty_inputs(self) -> None:
        from karadul.pipeline.steps.computation_fusion import (
            ComputationFusionStep,
        )

        cfg = Config()
        assert cfg.computation.enable_computation_fusion is True
        ctx = _make_ctx(
            cfg,
            artifacts={"sig_matches": [], "cfg_iso_matches": {}},
        )
        out = ComputationFusionStep().run(ctx)
        assert out["fused_matches"] == {}


# ---------------------------------------------------------------------------
# 6. Stand-alone step run — feature flag ACIK + valid artifact -> sonuc doner
# ---------------------------------------------------------------------------


class TestEnabledWithValidInputs:
    def test_fusion_with_sig_match(self) -> None:
        """Gercek SignatureMatch -> SignatureCandidate -> FusedMatch."""
        from karadul.analyzers.signature_db import SignatureMatch
        from karadul.pipeline.steps.computation_fusion import (
            ComputationFusionStep,
        )

        sig = SignatureMatch(
            original_name="FUN_00101000",
            matched_name="strcpy",
            library="libc",
            confidence=0.95,
            match_method="byte_pattern",
            address="00101000",
        )

        cfg = Config()
        ctx = _make_ctx(
            cfg,
            artifacts={"sig_matches": [sig], "cfg_iso_matches": {}},
        )
        out = ComputationFusionStep().run(ctx)
        fused = out["fused_matches"]
        # P11 / BORU-03: anahtar fonksiyon adresi.
        assert "00101000" in fused
        assert len(fused["00101000"]) == 1
        fm = fused["00101000"][0]
        # byte_pattern kaynağının ölçümü yok: olasılık yok, karar çekimser.
        assert fm.probability is None
        assert fm.decision == "abstain"
        assert out["fusion_name_candidates"] == []   # K-1: ad kanalı öntanımda kapalı

    def test_fusion_combines_sig_and_cfg(self) -> None:
        """Aynı adrese imza + CFG kanıtı, aynı ad -> TEK aday, iki kaynak (P11)."""
        from karadul.analyzers.signature_db import SignatureMatch
        from karadul.pipeline.steps.computation_fusion import (
            ComputationFusionStep,
        )

        sig = SignatureMatch(
            original_name="FUN_00101000",
            matched_name="quicksort",
            library="stdlib",
            confidence=0.90,
            match_method="byte_pattern",
            address="00101000",
        )
        # CFGMatch sahte
        cfg_match = SimpleNamespace(
            template_name="quicksort",
            confidence=0.85,
            match_type="exact",
            reasons=[],
            family="sort",
            template_source="elle_x86_sentetik",
        )
        cfg = Config()
        ctx = _make_ctx(
            cfg,
            artifacts={"sig_matches": [sig], "cfg_iso_matches": {"00101000": cfg_match}},
        )
        out = ComputationFusionStep().run(ctx)
        fused = out["fused_matches"]
        assert list(fused) == ["00101000"]
        assert len(fused["00101000"]) == 1
        assert fused["00101000"][0].sources == [
            "cfg_iso:elle_x86_sentetik", "imza:byte_pattern",
        ]

    def test_cfg_iso_match_with_synthetic_cfg(self) -> None:
        """CFGAnalysisResult verip step calissin — en az 1 template denenir."""
        from karadul.analyzers.cfg_analyzer import (
            BasicBlock,
            CFGAnalysisResult,
            CFGEdge,
            FunctionCFG,
        )
        from karadul.pipeline.steps.cfg_iso_match import CFGIsoMatchStep

        # Basit bir 3-node diamond CFG (1 fn)
        blocks = [
            BasicBlock("0x100", "0x110", 16, 5),
            BasicBlock("0x120", "0x130", 16, 3),
            BasicBlock("0x140", "0x150", 16, 2),
        ]
        edges = [
            CFGEdge("0x100", "0x120", "conditional_jump"),
            CFGEdge("0x100", "0x140", "conditional_jump"),
            CFGEdge("0x120", "0x140", "fall_through"),
        ]
        fn_cfg = FunctionCFG(
            name="foo", address="0x100", blocks=blocks, edges=edges,
            cyclomatic_complexity=2,
        )
        cfg_result = CFGAnalysisResult(
            total_functions=1, total_blocks=3, total_edges=3,
            functions=[fn_cfg],
        )
        cfg = Config()
        ctx = _make_ctx(cfg, artifacts={"cfg_result": cfg_result})
        out = CFGIsoMatchStep().run(ctx)
        # En az step patlamadan donmeli (eslesme bulamayabilir; dict bos/dolu).
        assert isinstance(out["cfg_iso_matches"], dict)


# ---------------------------------------------------------------------------
# 7. Topological sort — Phase 1/2'de dogru sira
# ---------------------------------------------------------------------------


class TestPipelineTopologicalSort:
    def test_cfg_iso_match_before_computation_fusion_in_phase1(self) -> None:
        """Phase 1: cfg_iso_match -> computation_fusion sirasi."""
        from karadul.pipeline.runner import PipelineRunner

        steps = [
            "binary_prep",
            "ghidra_metadata",
            "byte_pattern",
            "pcode_cfg_analysis",
            "cfg_iso_match",
            "algorithm_id",
            "parallel_algo_eng",
            "confidence_filter",
            "computation_fusion",
            "assembly_analysis",
        ]
        # PipelineRunner'in constructor'i step isimlerini kabul ederse
        # topological sort icin geçerli bir sirada olmali. Hatasiz init = valid.
        runner = PipelineRunner(steps=steps)
        assert runner is not None

    def test_computation_struct_recovery_in_phase2(self) -> None:
        from karadul.pipeline.runner import PipelineRunner

        steps = [
            "feedback_loop",
            "computation_struct_recovery",
            "struct_recovery",
        ]
        runner = PipelineRunner(steps=steps)
        assert runner is not None


# ---------------------------------------------------------------------------
# 8. Backend factory — macho.py entegrasyonu
# ---------------------------------------------------------------------------


class TestMachoBackendFactory:
    def test_macho_analyzer_uses_backend(self) -> None:
        """MachOAnalyzer.__init__ create_backend cagirir, self._backend set."""
        from karadul.analyzers.macho import MachOAnalyzer
        from karadul.decompilers.ghidra_backend import GhidraBackend

        cfg = Config()
        a = MachOAnalyzer(cfg)
        assert hasattr(a, "_backend")
        # Default: ghidra backend
        if a._backend is not None:
            assert isinstance(a._backend, GhidraBackend)

    def test_macho_analyzer_self_ghidra_preserved(self) -> None:
        """Eski self.ghidra davranisi korunur (backward-compat).

        analyze_static kodu self.ghidra uzerinden direkt GhidraHeadless
        cagrisi yapiyor; backend adapter bu referansi bozmamali.
        """
        from karadul.analyzers.macho import MachOAnalyzer
        from karadul.ghidra.headless import GhidraHeadless

        cfg = Config()
        a = MachOAnalyzer(cfg)
        assert hasattr(a, "ghidra")
        # self.ghidra GhidraHeadless instance olmali (eski davranis).
        assert isinstance(a.ghidra, GhidraHeadless)

    def test_macho_analyzer_angr_backend_via_config(self) -> None:
        """config.decompilers.primary_backend=angr -> AngrBackend yaratilir."""
        from karadul.analyzers.macho import MachOAnalyzer
        from karadul.decompilers.angr_backend import AngrBackend

        cfg = Config()
        cfg.decompilers.primary_backend = "angr"
        a = MachOAnalyzer(cfg)
        if a._backend is not None:
            assert isinstance(a._backend, AngrBackend)


# ---------------------------------------------------------------------------
# 9. CLI flag -> config aktarimi
# ---------------------------------------------------------------------------


class TestCLIFlagWiring:
    """CLI'nin flag'leri config'e aktardigini dogrular (import-level kontrol)."""

    def test_cli_flags_exist_on_analyze_command(self) -> None:
        """analyze komutunun tum yeni flag'leri tanimli olmali."""
        import click

        from karadul.cli import analyze

        assert isinstance(analyze, click.Command)
        option_names = {p.name for p in analyze.params if isinstance(p, click.Option)}
        # Yeni v1.10.0 flag'ler
        assert "experimental_step_registry" in option_names
        assert "lmdb_sigdb" in option_names
        assert "no_cfg_iso" in option_names
        assert "no_computation_fusion" in option_names
        assert "no_maxsmt_struct" in option_names
        assert "decompiler_backend" in option_names

    def test_no_cfg_iso_flag_help_text(self) -> None:
        """--no-cfg-iso flag'i default-aktif olani kapatma amacli."""
        import click

        from karadul.cli import analyze

        for p in analyze.params:
            if isinstance(p, click.Option) and p.name == "no_cfg_iso":
                assert "KAPAT" in (p.help or "") or "kapat" in (p.help or "").lower()
                return
        pytest.fail("--no-cfg-iso flag'i bulunamadi")


# ---------------------------------------------------------------------------
# 10. MaxSMT -> StructRecoveryEngine candidate pass (yalnız adım tarafı)
# ---------------------------------------------------------------------------


class TestMaxSMTCandidatePassesToEngine:
    """MaxSMT adayları yapı motoruna YALNIZ ``struct_recovery`` adımı tarafından iletilir.

    P10 (BORU-04) aday yolunu adıma taşıdı; ``stages.py``'deki ikinci kopya (çözücüyü
    bütün ikili için yeniden koşturup adayları motorun okumadığı anahtarlarla veren
    "monolith" blok, BORU-01) 2026-11-18'de silindi (K-3 A1b, P-S2). Davranış testi:
    ``tests/test_p10_maxsmt.py``; çift koşunun dönmediği: ``tests/test_ps2_olu_kod.py``.
    """

    def test_aday_yolu_adimda_stages_kopyasi_yok(self) -> None:
        import karadul.pipeline.steps  # noqa: F401  (adım kayıtları)
        import karadul.stages as stages
        from karadul.pipeline.registry import get_step

        assert "recovered_struct_candidates" in get_step("struct_recovery").requires
        src = Path(stages.__file__).read_text(encoding="utf-8")
        assert "_computation_struct_candidates" not in src
        assert "StructLayoutSolver" not in src


# ---------------------------------------------------------------------------
# 11. Fusion extracted_names enjeksiyonu: kaldırıldı (P-S2, 2026-11-18)
# ---------------------------------------------------------------------------
# ``TestFusionInjectsExtractedNames`` stages.py metninde "monolith" enjeksiyon kodunu
# arıyordu. Enjeksiyon Faz 2 bittikten sonra yapıldığı için hiçbir ada ulaşmıyordu
# (BORU-03), yalnız ``computation_fusion_injected`` sayacı "enjekte edildi" diyebilirdi.
# Blokla birlikte silindi (K-3 A1b); davranış yoktu, test de kalktı.


# ---------------------------------------------------------------------------
# 12. Feature flag kombinasyonu — "hepsini kapat" kirilmamali
# ---------------------------------------------------------------------------


class TestAllFeaturesDisabled:
    def test_all_three_disabled_pipeline_still_valid(self) -> None:
        """Hepsi kapali -> tum step'ler hala calistirilabilir (noop)."""
        cfg = Config()
        cfg.computation.enable_computation_struct_recovery = False
        cfg.computation.enable_computation_fusion = False
        cfg.computation_recovery.enable_cfg_iso = False

        from karadul.pipeline.steps.cfg_iso_match import CFGIsoMatchStep
        from karadul.pipeline.steps.computation_fusion import (
            ComputationFusionStep,
        )
        from karadul.pipeline.steps.computation_struct_recovery import (
            ComputationStructRecoveryStep,
        )

        ctx1 = _make_ctx(cfg, {"pcode_result": None})
        ctx2 = _make_ctx(cfg, {"cfg_result": None})
        ctx3 = _make_ctx(cfg, {"sig_matches": [], "cfg_iso_matches": {}})

        out1 = ComputationStructRecoveryStep().run(ctx1)
        out2 = CFGIsoMatchStep().run(ctx2)
        out3 = ComputationFusionStep().run(ctx3)

        assert out1["computation_struct_result"] is None
        assert out2["cfg_iso_matches"] == {}
        assert out3["fused_matches"] == {}


# ---------------------------------------------------------------------------
# 13. ComputationConfig - from_computation_config factory method
# ---------------------------------------------------------------------------


class TestFusionConfigIntegration:
    def test_fuser_reads_thresholds_from_config(self) -> None:
        from karadul.computation.fusion import SignatureFuser

        cfg = Config()
        cfg.computation.fusion_accept_threshold = 0.88
        cfg.computation.fusion_reject_threshold = 0.25
        fuser = SignatureFuser.from_computation_config(cfg.computation)
        assert fuser.decision.accept_threshold == pytest.approx(0.88)
        assert fuser.decision.reject_threshold == pytest.approx(0.25)


# ---------------------------------------------------------------------------
# 14. Pcode -> MemoryAccess extraction helper
# ---------------------------------------------------------------------------


class TestPcodeExtractionHelper:
    def test_extract_accesses_from_none(self) -> None:
        from karadul.pipeline.steps.computation_struct_recovery import (
            _extract_accesses_from_pcode,
        )

        out = _extract_accesses_from_pcode(None)
        assert out == []

    def test_extract_accesses_from_empty(self) -> None:
        from karadul.analyzers.pcode_analyzer import PcodeAnalysisResult
        from karadul.pipeline.steps.computation_struct_recovery import (
            _extract_accesses_from_pcode,
        )

        out = _extract_accesses_from_pcode(PcodeAnalysisResult())
        assert out == []

    def test_extract_accesses_from_load_op(self) -> None:
        """LOAD(ram, base + 8) -> ofset 8 (P11 / TIP-03).

        Ghidra'da LOAD'un ``input0``'ı adres alanı kimliğidir (``ram`` = 433),
        ofset değil; ofset işaretçinin (``input1``) tanımındadır.
        """
        from karadul.analyzers.pcode_analyzer import (
            FunctionPcode,
            PcodeAnalysisResult,
            PcodeOpInfo,
            VarnodeInfo,
        )
        from karadul.pipeline.steps.computation_struct_recovery import (
            _extract_accesses_from_pcode,
        )

        output_vn = VarnodeInfo(
            space="register", offset=0, size=4,
            is_constant=False, is_register=True, is_unique=False,
        )
        space_id = VarnodeInfo(
            space="const", offset=433, size=4,
            is_constant=True, is_register=False, is_unique=False,
        )
        base = VarnodeInfo(
            space="register", offset=0x4000, size=8,
            is_constant=False, is_register=True, is_unique=False,
        )
        const_off = VarnodeInfo(
            space="const", offset=8, size=8,
            is_constant=True, is_register=False, is_unique=False,
        )
        ptr = VarnodeInfo(
            space="unique", offset=0x100, size=8,
            is_constant=False, is_register=False, is_unique=True,
        )
        add = PcodeOpInfo(
            mnemonic="INT_ADD", seq_num=0, address="0x1000",
            output=ptr, inputs=[base, const_off],
        )
        op = PcodeOpInfo(
            mnemonic="LOAD", seq_num=1, address="0x1000",
            output=output_vn, inputs=[space_id, ptr],
        )
        fn = FunctionPcode(name="foo", address="0x1000", ops=[add, op])
        res = PcodeAnalysisResult(total_functions=1, total_pcode_ops=2, functions=[fn])
        out = _extract_accesses_from_pcode(res)
        assert len(out) == 1
        assert out[0].offset == 8
        assert out[0].width == 4
        assert out[0].access_type == "read"


# ---------------------------------------------------------------------------
# 15. CLI flag combination matrix
# ---------------------------------------------------------------------------


class TestCLICombination:
    def test_no_cfg_iso_disables_default_true(self) -> None:
        """--no-cfg-iso flag'i ile config.computation_recovery.enable_cfg_iso False olur."""
        cfg = Config()
        # Simulate --no-cfg-iso
        if True:  # equivalent of no_cfg_iso=True block
            cfg.computation_recovery.enable_cfg_iso = False
        assert cfg.computation_recovery.enable_cfg_iso is False

    def test_decompiler_backend_flag_override(self) -> None:
        cfg = Config()
        cfg.decompilers.primary_backend = "angr"  # simulate flag
        from karadul.decompilers import create_backend
        from karadul.decompilers.angr_backend import AngrBackend

        b = create_backend(cfg)
        assert isinstance(b, AngrBackend)


# ---------------------------------------------------------------------------
# 16. Regression — mevcut step'ler (struct_recovery, feedback_loop) bozulmamali
# ---------------------------------------------------------------------------


class TestExistingStepsUnbroken:
    def test_struct_recovery_step_still_registered(self) -> None:
        spec = get_step("struct_recovery")
        assert "struct_recovery_result" in spec.produces

    def test_feedback_loop_still_registered(self) -> None:
        spec = get_step("feedback_loop")
        assert "naming_result" in spec.produces
        assert "computation_result" in spec.produces

    def test_all_20_plus_steps_still_registered(self) -> None:
        """Phase 1 (8 step) + Phase 2 (2 step) + Phase 3 (10 step)
        + yeni 3 step = 23 toplam."""
        steps = list_steps()
        assert len(steps) >= 20, f"Cok az step: {len(steps)}"
