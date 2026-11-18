"""P14 / BORU-11: paralel düzeyde yerinde yazma / okuma yarışı ve önbellekten yeniden yazım.

Eski davranış (gösterim ``~/karadul_olcum/runs/onarim-2026-11-18/P14/goster/boru11_*``):
(a) aynı düzeydeki iki adım (biri dizini yerinde yeniden yazar, öbürü aynı dizini okur)
    ``parallel_steps=True`` iken eşzamanlı koşuyordu; okuyucunun kopyasına geçen yerinde
    yazım sayısı 12 koşuda 12 farklı değer aldı. Sıralı kipte düzey içi sıra alfabetikti,
    adım listesindeki sıra yok sayılıyordu.
(b) ``inline_detection`` içeriği ``file_cache``'ten (yapı kurtarma ÖNCESİ) okuyup dosyanın
    üstüne yazıyordu: yapı kurtarmanın yeniden yazımı geri alınıyordu.
"""

from __future__ import annotations

import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from karadul.pipeline.context import StepContext
from karadul.pipeline.registry import Step, _REGISTRY, get_step, register_step
from karadul.pipeline.runner import PipelineRunner

MARK = "/* YERINDE */"


def _pc(parallel: bool):
    return SimpleNamespace(metadata={}, config=SimpleNamespace(pipeline=SimpleNamespace(
        parallel_steps=parallel, parallel_max_workers=None)))


class _Probe:
    """Eşzamanlılık ölçer: aynı anda kaç adım içeride."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.active = 0
        self.max_active = 0
        self.order: list[str] = []

    def enter(self, name: str) -> None:
        with self.lock:
            self.active += 1
            self.max_active = max(self.max_active, self.active)
            self.order.append(name)

    def leave(self) -> None:
        with self.lock:
            self.active -= 1


@pytest.fixture
def steps():
    """'zz_yazici' dizini yerinde yazar (listede ilk); 'aa_okuyucu' aynı dizini kopyalar.

    Adlar bilerek seçildi: alfabetik sıra okuyucuyu öne alır, liste sırası yazıcıyı.
    """
    probe = _Probe()
    created = []

    def reg(name, **kw):
        created.append(name)
        return register_step(name=name, **kw)

    @reg("zz_yazici", requires=["y_dir"], produces=["y_done"])
    class _Yazici(Step):
        mutates_inputs = ("y_dir",)

        def run(self, ctx):
            probe.enter("yazici")
            try:
                time.sleep(0.15)
                for f in sorted(ctx.artifacts["y_dir"].glob("*.c")):
                    f.write_text(f.read_text() + MARK + "\n")
            finally:
                probe.leave()
            return {"y_done": True}

    @reg("aa_okuyucu", requires=["y_dir", "y_out"], produces=["y_copy"])
    class _Okuyucu(Step):
        def run(self, ctx):
            probe.enter("okuyucu")
            try:
                time.sleep(0.05)
                out = ctx.artifacts["y_out"]
                for f in sorted(ctx.artifacts["y_dir"].glob("*.c")):
                    (out / f.name).write_text(f.read_text())
            finally:
                probe.leave()
            return {"y_copy": out}

    @reg("mm_bagimsiz", requires=["y_other"], produces=["y_ind"])
    class _Bagimsiz(Step):
        def run(self, ctx):
            probe.enter("bagimsiz")
            try:
                time.sleep(0.15)
            finally:
                probe.leave()
            return {"y_ind": True}

    try:
        yield probe
    finally:
        for n in created:
            _REGISTRY.pop(n, None)


def _tree(tmp_path: Path) -> tuple[Path, Path, Path]:
    d, out, other = tmp_path / "struct_recovered", tmp_path / "semantic_named", tmp_path / "x"
    for p in (d, out, other):
        p.mkdir()
    for i in range(5):
        (d / f"FUN_{i}.c").write_text(f"int f{i}(void) {{ return {i}; }}\n")
    return d, out, other


def _marks(out: Path) -> int:
    return sum(1 for f in out.glob("*.c") if MARK in f.read_text())


class TestInPlaceWriterSerialized:
    @pytest.mark.parametrize("parallel", [True, False])
    def test_writer_and_reader_not_concurrent_list_order(self, steps, tmp_path, parallel) -> None:
        d, out, other = _tree(tmp_path)
        PipelineRunner(["zz_yazici", "aa_okuyucu"]).run(
            _pc(parallel), seed_artifacts={"y_dir": d, "y_out": out, "y_other": other})
        assert steps.max_active == 1
        assert steps.order == ["yazici", "okuyucu"]  # liste sırası, alfabetik değil
        assert _marks(out) == 5

    def test_parallel_and_sequential_same_output(self, steps, tmp_path) -> None:
        results = []
        for parallel in (True, False, True):
            sub = tmp_path / f"k{len(results)}"
            sub.mkdir()
            d, out, other = _tree(sub)
            PipelineRunner(["zz_yazici", "aa_okuyucu"]).run(
                _pc(parallel), seed_artifacts={"y_dir": d, "y_out": out, "y_other": other})
            results.append(sorted((f.name, f.read_text()) for f in out.glob("*.c")))
        assert results[0] == results[1] == results[2]

    def test_reader_listed_first_runs_first(self, steps, tmp_path) -> None:
        d, out, other = _tree(tmp_path)
        PipelineRunner(["aa_okuyucu", "zz_yazici"]).run(
            _pc(True), seed_artifacts={"y_dir": d, "y_out": out, "y_other": other})
        assert steps.order == ["okuyucu", "yazici"]
        assert _marks(out) == 0
        assert all(MARK in f.read_text() for f in d.glob("*.c"))

    def test_unrelated_steps_still_parallel(self, steps, tmp_path) -> None:
        d, out, other = _tree(tmp_path)
        PipelineRunner(["zz_yazici", "mm_bagimsiz"]).run(
            _pc(True), seed_artifacts={"y_dir": d, "y_out": out, "y_other": other})
        assert steps.max_active == 2  # çakışma yoksa paralellik korunur

    def test_nested_path_is_conflict(self, steps, tmp_path) -> None:
        d, out, other = _tree(tmp_path)
        runner = PipelineRunner(["zz_yazici", "mm_bagimsiz"])
        specs = [get_step("zz_yazici"), get_step("mm_bagimsiz")]
        # bağımsız adımın girdisi yazıcının dizininin ÜST dizini → örtüşme → iki dalga
        waves = runner._waves(specs, {"y_dir": d, "y_other": tmp_path})
        assert [[s.name for s in w] for w in waves] == [["zz_yazici"], ["mm_bagimsiz"]]
        # girdisi yazıcının dizininin ALTINDA → yine örtüşme
        (d / "alt").mkdir()
        assert len(runner._waves(specs, {"y_dir": d, "y_other": d / "alt"})) == 2
        # ilgisiz yol → tek dalga
        assert len(runner._waves(specs, {"y_dir": d, "y_other": other})) == 1
        # yol olmayan yapıt (dizgi, sayı) çakışma sayılmaz
        assert len(runner._waves(specs, {"y_dir": d, "y_other": str(d)})) == 1


class TestRealPhase3Levels:
    PHASE3 = [
        "inline_detection", "semantic_naming", "flow_simplify", "comment_generation",
        "capa_annotation", "engineering_annotation", "project_build",
        "engineering_analysis", "deep_tracing", "finalize",
    ]

    def test_inline_detection_before_semantic_naming(self, tmp_path) -> None:
        import karadul.pipeline.steps  # noqa: F401  (kayıt)

        runner = PipelineRunner(self.PHASE3)
        levels = runner._topological_levels(runner._specs)
        first = levels[0]
        assert sorted(s.name for s in first) == ["inline_detection", "semantic_naming"]
        d = tmp_path / "typed_iter1"
        d.mkdir()
        # stages.py tohumu: decompiled_dir ve final_decompiled_dir aynı dizin
        waves = runner._waves(first, {"decompiled_dir": d, "final_decompiled_dir": d})
        assert [[s.name for s in w] for w in waves] == [["inline_detection"], ["semantic_naming"]]

    def test_inline_detection_contract(self) -> None:
        import karadul.pipeline.steps  # noqa: F401

        spec = get_step("inline_detection")
        assert "final_decompiled_dir" in getattr(spec.cls, "mutates_inputs", ())
        assert "file_cache" not in spec.requires


ONCE = "int f(long p) {\n  int x = *(int *)(p + 8);\n  if (x < 0) x = -x;\n  return x;\n}\n"
SONRA = "int f(struct_X *p) {\n  int x = p->count;\n  if (x < 0) x = -x;\n  return x;\n}\n"


class TestInlineReadsDisk:
    def test_struct_rewrite_survives_inline_annotation(self, tmp_path) -> None:
        from karadul.pipeline.steps.inline_detection import InlineDetectionStep

        d = tmp_path / "struct_recovered"
        d.mkdir()
        (d / "f.c").write_text(SONRA)  # yapı kurtarmanın yeniden yazdığı (diskte)
        (d / "g.c").write_text("int g(void) { return 0; }\n")  # desensiz: dokunulmaz
        ctx = StepContext(pipeline_context=SimpleNamespace(metadata={}))
        # Bayat önbellek (yapı kurtarma öncesi) hâlâ bağlamda olabilir.
        ctx._write_artifacts({"final_decompiled_dir": d,
                              "file_cache": {"f.c": ONCE, "g.c": "bayat"}})
        out = InlineDetectionStep().run(ctx)
        assert out["inline_patterns_detected"] == 1
        icerik = (d / "f.c").read_text()
        assert "p->count" in icerik
        assert "*(int *)(p + 8)" not in icerik
        assert "INLINE:" in icerik
        assert (d / "g.c").read_text() == "int g(void) { return 0; }\n"

    def test_runs_without_file_cache(self, tmp_path) -> None:
        from karadul.pipeline.steps.inline_detection import InlineDetectionStep

        d = tmp_path / "dec"
        d.mkdir()
        (d / "f.c").write_text(SONRA)
        ctx = StepContext(pipeline_context=SimpleNamespace(metadata={}))
        ctx._write_artifacts({"final_decompiled_dir": d})
        assert InlineDetectionStep().run(ctx)["inline_patterns_detected"] == 1
