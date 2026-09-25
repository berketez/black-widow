""".app paketi (APP_BUNDLE) hattı: sayaç, bileşen izolasyonu, ana bileşen hedefi.

Bug (2026-09-25, Tiny.app ve 3 bileşenli Multi.app ölçümü):
1. Statik sayaç 0: AppBundleAnalyzer bileşen sonucunda ``result.functions_found``
   niteliğini arıyordu; analyzer'lar StageResult döndürür ve sayaç
   ``result.stats["ghidra_function_count"]`` içindedir. Bundle statik stats'ında da
   CLI/raporların okuduğu ``functions_found`` yoktu -> "Functions recovered 0".
2. Bileşenler aynı workspace'e yazıyordu (``create_sub_workspace`` Workspace'te
   yoktu, hasattr koruması sessizce paylaşılan workspace'e düşüyordu):
   ``static/ghidra_functions.json`` son bileşene aitti, ``decompiled/`` üç
   binary'nin C dosyalarını karışık taşıyordu.
3. Reconstruction bundle context'iyle koşuyordu: ``pc.target.path`` .app DİZİNİ
   -> binary_prep/byte_pattern/anti_debug/packer_fingerprint "Hedef dosya
   bulunamadi" / "Is a directory".
4. Bileşenler ThreadPoolExecutor işçisinde analiz ediliyordu -> JVM işçi
   thread'inde doğuyordu -> çıkışta DestroyJavaVM asılı (ayrı dosya:
   test_app_bundle_jvm_exit.py).
"""
from __future__ import annotations

import hashlib
import json
import struct
import threading
from pathlib import Path

import pytest

import karadul.analyzers.app_bundle as app_bundle_mod
from karadul.analyzers.app_bundle import (
    AppBundleAnalyzer,
    build_component_target,
    component_context,
    promote_component_outputs,
)
from karadul.config import Config
from karadul.core.pipeline import PipelineContext
from karadul.core.result import StageResult
from karadul.core.target import Language, TargetInfo, TargetType
from karadul.core.workspace import SUB_WORKSPACE_DIR, Workspace
from karadul.stages import ReconstructionStage, StaticAnalysisStage

# Bileşen adı -> sahte Ghidra fonksiyon sayısı. Ana bileşen (en çok fonksiyon)
# kasıtlı olarak ORTADA analiz edilir: ne ilk ne son. Eski kodda "son yazan
# kazanır" ya da "hepsi 0, ilk seçilir" hatası ana bileşeni yanlış gösterirdi.
_FUNCS = {"Helper": 4, "Main": 14, "Framework: Engine": 3}
_MACHO_64 = b"\xcf\xfa\xed\xfe"


class _FakeComponentAnalyzer:
    """MachOAnalyzer yerine: StageResult döndürür, workspace'e Ghidra-benzeri çıktı yazar."""

    calls: list[tuple[TargetInfo, Workspace, threading.Thread]] = []

    def __init__(self, config=None):
        self.config = config

    def analyze_static(self, target, workspace):
        _FakeComponentAnalyzer.calls.append(
            (target, workspace, threading.current_thread()),
        )
        n = _FUNCS[target.name]
        workspace.save_json(
            "static", "ghidra_functions",
            {"program": target.name, "total": n},
        )
        dec = workspace.get_stage_dir("static") / "ghidra_output" / "decompiled"
        dec.mkdir(parents=True, exist_ok=True)
        (dec / f"{target.name.replace(':', '_').replace(' ', '_')}_fn.c").write_text(
            "int f(void) { return 0; }\n", encoding="utf-8",
        )
        (workspace.get_stage_dir("static") / "ghidra_project").mkdir(exist_ok=True)
        (workspace.get_stage_dir("raw") / target.name).write_bytes(
            target.path.read_bytes(),
        )
        # MachOAnalyzer'ın gerçek anahtarları: functions_found YOK.
        return StageResult(
            stage_name="static", success=True, duration_seconds=0.0,
            stats={
                "ghidra_function_count": n,
                "ghidra_string_count": n * 2,
                "string_count": n * 10,
            },
        )


@pytest.fixture
def fake_analyzer(monkeypatch):
    _FakeComponentAnalyzer.calls.clear()
    monkeypatch.setattr(
        app_bundle_mod, "get_analyzer", lambda _tt: _FakeComponentAnalyzer,
    )
    return _FakeComponentAnalyzer


def _make_bundle(tmp_path: Path) -> TargetInfo:
    """Gerçek dosya ağacıyla 3 bileşenli bir .app ve onun TargetInfo'su."""
    app = tmp_path / "Multi.app"
    macos = app / "Contents" / "MacOS"
    fw = app / "Contents" / "Frameworks" / "Engine.framework"
    macos.mkdir(parents=True)
    fw.mkdir(parents=True)
    files = {
        "Helper": macos / "Helper",
        "Main": macos / "Main",
        "Framework: Engine": fw / "Engine",
    }
    components = []
    for name, path in files.items():  # keşif sırası: Helper, Main, Engine
        path.write_bytes(_MACHO_64 + name.encode() * 8)
        components.append({
            "path": str(path), "type": "macho_binary",
            "size": path.stat().st_size, "name": name,
        })
    return TargetInfo(
        path=app, name="Multi", target_type=TargetType.APP_BUNDLE,
        language=Language.UNKNOWN, file_size=0, file_hash="b" * 64,
        metadata={
            "bundle": True, "bundle_id": "com.example.multi",
            "bundle_version": "2.0", "components": components,
        },
    )


def _make_ws(tmp_path: Path) -> Workspace:
    ws = Workspace(base_dir=tmp_path / "out", target_name="Multi")
    ws.create()
    return ws


# ---------------------------------------------------------------------------
# Workspace.create_sub_workspace
# ---------------------------------------------------------------------------

class TestSubWorkspace:
    def test_creates_isolated_workspace_under_components(self, tmp_path):
        ws = _make_ws(tmp_path)
        sub = ws.create_sub_workspace("Framework: Engine")
        assert sub.path == (ws.path / SUB_WORKSPACE_DIR / "Framework__Engine").resolve()
        for stage in ("raw", "static", "reconstructed"):
            assert (sub.path / stage).is_dir()
        sub.save_json("static", "x", {"a": 1})
        assert (sub.path / "static" / "x.json").exists()
        assert not (ws.path / "static" / "x.json").exists()

    def test_same_name_gets_distinct_directory(self, tmp_path):
        ws = _make_ws(tmp_path)
        a = ws.create_sub_workspace("libfoo.dylib")
        b = ws.create_sub_workspace("libfoo.dylib")
        assert a.path != b.path
        assert b.path.name == "libfoo.dylib_2"

    @pytest.mark.parametrize("name", ["..", ".", "../../evil", "a/b"])
    def test_hostile_names_stay_inside_components(self, tmp_path, name):
        ws = _make_ws(tmp_path)
        sub = ws.create_sub_workspace(name)
        sub.path.relative_to((ws.path / SUB_WORKSPACE_DIR).resolve())
        assert sub.path.parent == (ws.path / SUB_WORKSPACE_DIR).resolve()


# ---------------------------------------------------------------------------
# AppBundleAnalyzer
# ---------------------------------------------------------------------------

class TestAppBundleAnalyzer:
    def test_counts_come_from_stage_result_stats(self, tmp_path, fake_analyzer):
        target = _make_bundle(tmp_path)
        result = AppBundleAnalyzer(Config()).analyze_static(target, _make_ws(tmp_path))
        per = {r.name: (r.functions_found, r.strings_found) for r in result.component_results}
        # strings: ghidra_string_count (CLI önceliği), strings(1) sayısı DEĞİL
        assert per == {"Helper": (4, 8), "Main": (14, 28), "Framework: Engine": (3, 6)}
        assert result.total_functions == 21
        assert result.total_strings == 42
        assert result.main_component.name == "Main"

    def test_each_component_writes_to_its_own_workspace(self, tmp_path, fake_analyzer):
        target = _make_bundle(tmp_path)
        ws = _make_ws(tmp_path)
        result = AppBundleAnalyzer(Config()).analyze_static(target, ws)

        used = [w.path for _t, w, _th in fake_analyzer.calls]
        assert len(set(used)) == 3, "bileşenler ayni workspace'i paylasiyor"
        assert all(ws.path not in (p,) for p in used)
        for r in result.component_results:
            data = json.loads(
                (ws.path / r.workspace / "static" / "ghidra_functions.json").read_text(),
            )
            assert data["program"] == r.name
            decompiled = list((ws.path / r.workspace / "static" / "ghidra_output" / "decompiled").glob("*.c"))
            assert len(decompiled) == 1, f"{r.name}: baska bilesenin C dosyasi karismis"
        # Üst workspace'e analyzer doğrudan bir şey yazmadı (yalnız bundle_analysis).
        assert not (ws.path / "static" / "ghidra_functions.json").exists()

    def test_components_run_in_calling_thread(self, tmp_path, fake_analyzer):
        target = _make_bundle(tmp_path)
        AppBundleAnalyzer(Config()).analyze_static(target, _make_ws(tmp_path))
        threads = {th for _t, _w, th in fake_analyzer.calls}
        assert threads == {threading.current_thread()}, (
            "bilesen analizi isci thread'inde: JVM orada dogarsa cikista asilir"
        )

    def test_failed_component_result_is_reported(self, tmp_path, monkeypatch):
        class _Failing(_FakeComponentAnalyzer):
            def analyze_static(self, target, workspace):
                return StageResult(
                    stage_name="static", success=False, duration_seconds=0.0,
                    errors=["Ghidra analiz basarisiz (rc=1)"],
                    stats={"ghidra_function_count": 0},
                )

        monkeypatch.setattr(app_bundle_mod, "get_analyzer", lambda _tt: _Failing)
        result = AppBundleAnalyzer(Config()).analyze_static(
            _make_bundle(tmp_path), _make_ws(tmp_path),
        )
        assert result.analyzed_components == 0
        assert result.failed_components == 3
        assert all("rc=1" in r.error for r in result.component_results)

    def test_bundle_analysis_json_records_workspace_and_main(self, tmp_path, fake_analyzer):
        ws = _make_ws(tmp_path)
        AppBundleAnalyzer(Config()).analyze_static(_make_bundle(tmp_path), ws)
        data = ws.load_json("static", "bundle_analysis")
        assert data["main_component"] == "Main"
        assert data["main_component_path"].endswith("Contents/MacOS/Main")
        assert {c["workspace"] for c in data["component_results"]} == {
            f"{SUB_WORKSPACE_DIR}/Helper",
            f"{SUB_WORKSPACE_DIR}/Main",
            f"{SUB_WORKSPACE_DIR}/Framework__Engine",
        }


# ---------------------------------------------------------------------------
# Yardımcılar: bileşen hedefi / context / taşıma
# ---------------------------------------------------------------------------

class TestComponentTargetAndContext:
    def test_component_target_points_at_real_binary(self, tmp_path):
        bundle = _make_bundle(tmp_path)
        comp = bundle.metadata["components"][1]
        t = build_component_target(comp, "Multi")
        assert t.path == Path(comp["path"]) and t.path.is_file()
        assert t.target_type == TargetType.MACHO_BINARY
        assert t.name == "Main"
        assert t.file_hash == hashlib.sha256(t.path.read_bytes()).hexdigest()

    def test_fat_component_is_universal_binary(self, tmp_path):
        # TargetDetector paket bileşenlerini "macho_binary" listeler; fat dosya
        # MACHO_BINARY kalırsa Ghidra ilk dilimi (Safari'de x86_64) yüklüyordu.
        fat = tmp_path / "Fat"
        fat.write_bytes(struct.pack(">II", 0xCAFEBABE, 2) + b"\0" * 64)
        t = build_component_target(
            {"path": str(fat), "type": "macho_binary", "name": "Fat"}, "B",
        )
        assert t.target_type == TargetType.UNIVERSAL_BINARY
        # Aynı magic'li Java class (ofset 4 = sürüm, > 30) universal DEĞİL.
        cls = tmp_path / "A.class"
        cls.write_bytes(struct.pack(">II", 0xCAFEBABE, 0x00000041) + b"\0" * 64)
        t2 = build_component_target(
            {"path": str(cls), "type": "macho_binary", "name": "A"}, "B",
        )
        assert t2.target_type == TargetType.MACHO_BINARY

    def test_component_target_without_size_uses_stat(self, tmp_path):
        bundle = _make_bundle(tmp_path)
        comp = dict(bundle.metadata["components"][0])
        comp.pop("size")
        t = build_component_target(comp, "Multi")
        assert t.file_size == Path(comp["path"]).stat().st_size

    def test_component_context_only_swaps_target(self, tmp_path):
        bundle = _make_bundle(tmp_path)
        ws = _make_ws(tmp_path)
        ctx = PipelineContext(target=bundle, workspace=ws, config=Config())
        ctx.metadata["k"] = "v"
        comp_t = build_component_target(bundle.metadata["components"][1], "Multi")
        sub = component_context(ctx, comp_t)
        assert sub.target is comp_t and ctx.target is bundle
        assert sub.workspace is ws and sub.config is ctx.config
        assert sub.metadata is ctx.metadata  # adımların metadata yazımı paylaşılır


class TestPromoteComponentOutputs:
    def test_promotes_main_component_without_overwriting(self, tmp_path, fake_analyzer):
        ws = _make_ws(tmp_path)
        result = AppBundleAnalyzer(Config()).analyze_static(_make_bundle(tmp_path), ws)
        main = result.main_component
        before = ws.load_json("static", "bundle_analysis")

        promoted = promote_component_outputs(ws, main.workspace)

        assert "static/ghidra_functions.json" in promoted
        assert ws.load_json("static", "ghidra_functions")["program"] == "Main"
        assert [p.name for p in (ws.path / "static" / "ghidra_output" / "decompiled").glob("*.c")] == ["Main_fn.c"]
        assert (ws.path / "raw" / "Main").is_file()
        assert not (ws.path / "static" / "ghidra_project").exists()
        assert ws.load_json("static", "bundle_analysis") == before  # ezilmedi

    def test_rejects_paths_outside_workspace(self, tmp_path):
        ws = _make_ws(tmp_path)
        with pytest.raises(ValueError):
            promote_component_outputs(ws, "../../elsewhere")
        with pytest.raises(ValueError):
            promote_component_outputs(ws, ".")


# ---------------------------------------------------------------------------
# Stage dalları
# ---------------------------------------------------------------------------

def _run_static(tmp_path: Path) -> tuple[PipelineContext, StageResult]:
    bundle = _make_bundle(tmp_path)
    ctx = PipelineContext(target=bundle, workspace=_make_ws(tmp_path), config=Config())
    return ctx, StaticAnalysisStage().execute(ctx)


class TestStaticStageAppBundle:
    def test_stats_use_canonical_counter_keys(self, tmp_path, fake_analyzer):
        _ctx, res = _run_static(tmp_path)
        assert res.success
        # CLI "Functions recovered" / JSON rapor total_functions bu anahtarları okur.
        assert res.stats["functions_found"] == 21
        assert res.stats["strings_found"] == 42
        assert res.stats["bundle_functions"] == 21
        assert res.stats["main_component"] == "Main"
        assert res.stats["main_component_functions"] == 14

    def test_top_level_static_is_the_main_component(self, tmp_path, fake_analyzer):
        ctx, _res = _run_static(tmp_path)
        assert ctx.metadata["main_component"].endswith("Contents/MacOS/Main")
        assert ctx.metadata["main_component_workspace"] == f"{SUB_WORKSPACE_DIR}/Main"
        # Engine SON analiz edildi; eski paylaşılan workspace'te üst static Engine'di.
        assert ctx.workspace.load_json("static", "ghidra_functions")["program"] == "Main"
        c_files = sorted(p.name for p in (ctx.workspace.path / "static" / "ghidra_output" / "decompiled").glob("*.c"))
        assert c_files == ["Main_fn.c"]


class TestReconstructStageAppBundle:
    @staticmethod
    def _capture(monkeypatch, success=True):
        seen: list[PipelineContext] = []

        def _fake_binary(self, context, start):
            seen.append(context)
            return StageResult(
                stage_name="reconstruct", success=success, duration_seconds=0.0,
                stats={"source_c_files": 1}, errors=[] if success else ["boom"],
            )

        monkeypatch.setattr(ReconstructionStage, "_execute_binary", _fake_binary)
        return seen

    def test_binary_steps_see_main_component_not_app_dir(self, tmp_path, fake_analyzer, monkeypatch):
        ctx, _ = _run_static(tmp_path)
        seen = self._capture(monkeypatch)

        res = ReconstructionStage().execute(ctx)

        assert res.success and res.stats["reconstructed_components"] == 1
        (sub,) = seen
        main_bin = Path(ctx.metadata["main_component"])
        assert sub.target.path == main_bin and sub.target.path.is_file()
        assert sub.target.path != ctx.target.path  # .app dizini değil
        assert sub.target.target_type == TargetType.MACHO_BINARY
        assert sub.target.name == "Main"
        assert sub.target.file_hash == hashlib.sha256(main_bin.read_bytes()).hexdigest()
        assert sub.workspace is ctx.workspace
        assert res.stats["main_component_path"] == str(main_bin)

    def test_main_is_found_from_json_without_metadata(self, tmp_path, fake_analyzer, monkeypatch):
        ctx, _ = _run_static(tmp_path)
        ctx.metadata.clear()  # ör. yeniden başlatılmış hat: metadata kalıcı değil
        seen = self._capture(monkeypatch)
        ReconstructionStage().execute(ctx)
        assert seen[0].target.name == "Main"

    def test_failed_main_reconstruction_is_not_counted(self, tmp_path, fake_analyzer, monkeypatch):
        ctx, _ = _run_static(tmp_path)
        self._capture(monkeypatch, success=False)
        res = ReconstructionStage().execute(ctx)
        assert not res.success
        assert res.stats["reconstructed_components"] == 0
        assert "boom" in res.errors
