"""v1.10.0 M1 T3 — Step registry + runner + binary_prep step testleri.

Mevcut `test_pipeline.py` core Pipeline (Stage) testi; bu dosya yeni
step-based pipeline'i kapsar.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from karadul.pipeline.context import StepContext
from karadul.pipeline.registry import (
    Step,
    StepSpec,
    _REGISTRY,
    _clear_registry_for_tests,
    get_step,
    list_steps,
    register_step,
)
from karadul.pipeline.runner import PipelineRunner


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def snapshot_registry():
    """Global registry'i snapshot alir, test bitince geri yukler.

    Bu sayede testler binary_prep gibi kalici kayitlari bozmaz.
    """
    saved = dict(_REGISTRY)
    try:
        yield
    finally:
        _REGISTRY.clear()
        _REGISTRY.update(saved)


@pytest.fixture
def fake_pipeline_context():
    """Minimal PipelineContext stub'i."""
    ctx = MagicMock()
    ctx.metadata = {}
    return ctx


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


class TestRegistry:
    def test_register_step_and_retrieve(self, snapshot_registry) -> None:
        """register_step sonrasi get_step ile donuyor."""
        _clear_registry_for_tests()

        @register_step(name="t_a", produces=["x"])
        class StepA(Step):
            def run(self, ctx):
                return {"x": 1}

        spec = get_step("t_a")
        assert isinstance(spec, StepSpec)
        assert spec.name == "t_a"
        assert spec.cls is StepA
        assert spec.produces == ("x",)
        assert "t_a" in list_steps()

    def test_duplicate_name_raises(self, snapshot_registry) -> None:
        """Ayni isim iki kez kayit → ValueError."""
        _clear_registry_for_tests()

        @register_step(name="dup", produces=["y"])
        class S1(Step):
            def run(self, ctx):
                return {"y": 1}

        with pytest.raises(ValueError, match="zaten kayitli"):
            @register_step(name="dup", produces=["y"])
            class S2(Step):
                def run(self, ctx):
                    return {"y": 2}

    def test_get_step_missing_raises(self, snapshot_registry) -> None:
        _clear_registry_for_tests()
        with pytest.raises(KeyError):
            get_step("yok")


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------


class TestRunner:
    def test_topological_sort_two_steps(
        self, snapshot_registry, fake_pipeline_context,
    ) -> None:
        """A produces 'x', B requires 'x' → sirali calistirma."""
        _clear_registry_for_tests()
        call_order: list[str] = []

        @register_step(name="A", produces=["x"])
        class A(Step):
            def run(self, ctx):
                call_order.append("A")
                return {"x": 42}

        @register_step(name="B", requires=["x"], produces=["y"])
        class B(Step):
            def run(self, ctx):
                call_order.append("B")
                assert ctx.artifacts["x"] == 42
                return {"y": ctx.artifacts["x"] + 1}

        # Listeye B once verilse bile sort A-B yapmali
        runner = PipelineRunner(steps=["B", "A"])
        step_ctx = runner.run(fake_pipeline_context)

        assert call_order == ["A", "B"]
        assert step_ctx.artifacts["x"] == 42
        assert step_ctx.artifacts["y"] == 43

    def test_missing_requires_raises(
        self, snapshot_registry, fake_pipeline_context,
    ) -> None:
        """Requires saglanamiyorsa RuntimeError."""
        _clear_registry_for_tests()

        @register_step(name="needs_missing", requires=["nope"], produces=["z"])
        class Needy(Step):
            def run(self, ctx):
                return {"z": 0}

        runner = PipelineRunner(steps=["needs_missing"])
        with pytest.raises(RuntimeError, match="eksik girdi"):
            runner.run(fake_pipeline_context)

    def test_extra_produces_key_rejected(
        self, snapshot_registry, fake_pipeline_context,
    ) -> None:
        """Produces disinda key → RuntimeError."""
        _clear_registry_for_tests()

        @register_step(name="leaky", produces=["ok"])
        class Leaky(Step):
            def run(self, ctx):
                return {"ok": 1, "sneak": 2}

        runner = PipelineRunner(steps=["leaky"])
        with pytest.raises(RuntimeError, match="produces disinda"):
            runner.run(fake_pipeline_context)

    def test_empty_steps_list_raises(self, snapshot_registry) -> None:
        with pytest.raises(ValueError, match="bos"):
            PipelineRunner(steps=[])

    def test_artifacts_are_readonly(
        self, snapshot_registry, fake_pipeline_context,
    ) -> None:
        """ctx.artifacts'i step icinde yazmaya calisirsa TypeError."""
        _clear_registry_for_tests()

        @register_step(name="writer", produces=["w"])
        class W(Step):
            def run(self, ctx):
                with pytest.raises(TypeError):
                    ctx.artifacts["hack"] = 1  # MappingProxy → yazilamaz
                return {"w": 1}

        runner = PipelineRunner(steps=["writer"])
        runner.run(fake_pipeline_context)

    def test_seed_artifacts_satisfies_requires(
        self, snapshot_registry, fake_pipeline_context,
    ) -> None:
        """T3.5: seed_artifacts ile requires beslenebilmeli."""
        _clear_registry_for_tests()

        @register_step(name="needs_x", requires=["x"], produces=["y"])
        class NeedsX(Step):
            def run(self, ctx):
                assert ctx.artifacts["x"] == 99
                return {"y": ctx.artifacts["x"] * 2}

        runner = PipelineRunner(steps=["needs_x"])
        step_ctx = runner.run(
            fake_pipeline_context, seed_artifacts={"x": 99},
        )
        assert step_ctx.artifacts["y"] == 198

    def test_seed_overrides_metadata(
        self, snapshot_registry, fake_pipeline_context,
    ) -> None:
        """seed_artifacts key'i metadata key'iyle cakisirsa seed kazanir."""
        _clear_registry_for_tests()

        @register_step(name="reader", requires=["v"], produces=["out"])
        class R(Step):
            def run(self, ctx):
                return {"out": ctx.artifacts["v"]}

        fake_pipeline_context.metadata = {"v": "eski"}
        runner = PipelineRunner(steps=["reader"])
        step_ctx = runner.run(
            fake_pipeline_context, seed_artifacts={"v": "yeni"},
        )
        assert step_ctx.artifacts["out"] == "yeni"


# ---------------------------------------------------------------------------
# BinaryPrepStep — gercek fixture ile entegrasyon
# ---------------------------------------------------------------------------


class TestBinaryPrepStep:
    """Gercek decompiled_dir yapisi + fake target/workspace ile sanity."""

    @pytest.fixture
    def fake_workspace(self, tmp_path: Path):
        """deobfuscated/decompiled/foo.c, bar.c iceren fake workspace."""
        ws = MagicMock()
        stage_dirs = {
            "static": tmp_path / "static",
            "deobfuscated": tmp_path / "deobfuscated",
            "reconstructed": tmp_path / "reconstructed",
            "raw": tmp_path / "raw",
        }
        for d in stage_dirs.values():
            d.mkdir(parents=True, exist_ok=True)
        decomp = stage_dirs["deobfuscated"] / "decompiled"
        decomp.mkdir()
        (decomp / "foo.c").write_text("int foo(void) { return 1; }\n")
        (decomp / "bar.c").write_text("int bar(void) { return 2; }\n")

        ws.get_stage_dir.side_effect = lambda s: stage_dirs[s]
        return ws

    @pytest.fixture
    def fake_target_elf(self, tmp_path: Path):
        """Non-universal binary — arm64 slice logic tetiklenmez."""
        from karadul.core.target import TargetType
        t = MagicMock()
        t.path = tmp_path / "binary.elf"
        t.path.write_bytes(b"\x7fELF")
        # UNIVERSAL_BINARY disinda herhangi bir tip sec
        for tt in TargetType:
            if tt.name != "UNIVERSAL_BINARY":
                t.target_type = tt
                break
        t.name = "sample"
        return t

    def test_binary_prep_success(
        self, fake_workspace, fake_target_elf,
    ) -> None:
        """binary_prep: C dosyalarini bulur, cache'ler, 4 artifact uretir."""
        # binary_prep karadul.pipeline __init__ ile otomatik kayit olmus olmali
        from karadul.pipeline import PipelineRunner

        pc = MagicMock()
        pc.target = fake_target_elf
        pc.workspace = fake_workspace
        pc.metadata = {}

        runner = PipelineRunner(steps=["binary_prep"])
        step_ctx = runner.run(pc)

        a = step_ctx.artifacts
        assert len(a["c_files"]) == 2
        assert {p.name for p in a["c_files"]} == {"foo.c", "bar.c"}
        assert set(a["file_cache"].keys()) == {"foo.c", "bar.c"}
        assert "int foo" in a["file_cache"]["foo.c"]
        assert a["decompiled_dir"].exists()
        assert a["binary_for_byte_match"] == fake_target_elf.path
        # metadata shim
        assert pc.metadata["file_cache"] == a["file_cache"]
        # stats
        assert step_ctx.stats["source_c_files"] == 2

    def test_binary_prep_no_c_files(
        self, fake_workspace, fake_target_elf, tmp_path: Path,
    ) -> None:
        """C dosyasi yoksa RuntimeError."""
        # Mevcut .c dosyalarini sil
        for cf in (tmp_path / "deobfuscated" / "decompiled").glob("*.c"):
            cf.unlink()

        from karadul.pipeline import PipelineRunner

        pc = MagicMock()
        pc.target = fake_target_elf
        pc.workspace = fake_workspace
        pc.metadata = {}

        runner = PipelineRunner(steps=["binary_prep"])
        with pytest.raises(RuntimeError, match="Decompile"):
            runner.run(pc)

    def test_binary_prep_registered_in_global_registry(self) -> None:
        """Paket import edilince decorator registry'e binary_prep eklemis olmali."""
        import karadul.pipeline  # noqa: F401
        spec = get_step("binary_prep")
        assert "c_files" in spec.produces
        assert "file_cache" in spec.produces
        assert "binary_for_byte_match" in spec.produces
        assert "decompiled_dir" in spec.produces


# ---------------------------------------------------------------------------
# Config feature flag
# ---------------------------------------------------------------------------


class TestPipelineConfig:
    def test_default_is_false(self) -> None:
        from karadul.config import Config
        cfg = Config()
        assert cfg.pipeline.use_step_registry is False

    def test_yaml_override(self, tmp_path: Path) -> None:
        """YAML ile True override edilebilmeli."""
        import yaml
        from karadul.config import Config

        p = tmp_path / "karadul.yaml"
        p.write_text(yaml.safe_dump({"pipeline": {"use_step_registry": True}}))
        cfg = Config.load(p)
        assert cfg.pipeline.use_step_registry is True
