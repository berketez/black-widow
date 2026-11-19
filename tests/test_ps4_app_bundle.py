"""P-S4 kalem 3: `.app` paketinde ana bileşen türe göre seçilir ve doğru hatta gider.

BICIM-09: ana bileşen "en çok fonksiyonlu" seçiliyordu; Electron bileşeni fonksiyon
saymadığı (0) için Electron `.app`'inde ana bileşen en büyük yerel çerçeve (Chromium)
oluyordu; APP_BUNDLE deobfuscation'ı hep atlandığı için Electron seçilse bile JS
yeniden kurma düşüyordu. BORU-08: ana bileşen JAR ise reconstruct "Bilinmeyen
bilesen tipi: java_jar".
"""

from __future__ import annotations

from pathlib import Path

from karadul.analyzers.app_bundle import BundleAnalysisResult, ComponentResult
from karadul.config import Config
from karadul.core.pipeline import PipelineContext
from karadul.core.result import StageResult
from karadul.core.target import Language, TargetInfo, TargetType
from karadul.core.workspace import Workspace
from karadul.stages import DeobfuscationStage, ReconstructionStage

_APP = "/x/Fiddle.app/Contents"


def _sonuc(*comps: ComponentResult) -> BundleAnalysisResult:
    return BundleAnalysisResult(
        bundle_name="Fiddle", bundle_id="", bundle_version="", total_components=len(comps),
        analyzed_components=len(comps), failed_components=0, total_functions=0,
        total_strings=0, total_duration=0.0, component_results=list(comps),
    )


def _cr(name, path, ctype, fn):
    return ComponentResult(name=name, path=path, component_type=ctype, success=True,
                           functions_found=fn)


def test_electron_paketinde_ana_bilesen_uygulamanin_js_i():
    r = _sonuc(
        _cr("Framework: Electron Framework",
            f"{_APP}/Frameworks/Electron Framework.framework/Electron Framework",
            "macho_binary", 90000),
        _cr("Electron Fiddle", f"{_APP}/MacOS/Electron Fiddle", "macho_binary", 120),
        _cr("Electron App", f"{_APP}/Resources/app.asar", "electron_app", 0),
    )
    assert r.main_component.component_type == "electron_app"
    d = r.to_dict()
    assert d["main_component_type"] == "electron_app"
    assert "Electron" in d["main_selection_reason"]
    roller = {c["name"]: c["role"] for c in d["component_results"]}
    assert roller["Framework: Electron Framework"] == "cerceve_dylib"
    assert roller["Electron Fiddle"] == "ana_ikili"


def test_yerel_pakette_ana_ikili_cerceveden_once():
    r = _sonuc(
        _cr("Framework: Big", f"{_APP}/Frameworks/Big.framework/Big", "macho_binary", 5000),
        _cr("App", f"{_APP}/MacOS/App", "macho_binary", 100),
    )
    assert r.main_component.name == "App"
    assert "Contents/MacOS" in r.main_selection_reason


def _bundle_ctx(tmp_path: Path, main: dict, comps: list[dict]) -> PipelineContext:
    app = tmp_path / "J.app"
    app.mkdir(exist_ok=True)
    ws = Workspace(base_dir=tmp_path / "ws", target_name="J")
    ws.create()
    ws.save_json("static", "bundle_analysis", {
        "bundle_name": "J", "main_component_path": main["path"],
        "component_results": comps,
    })
    target = TargetInfo(path=app, name="J", target_type=TargetType.APP_BUNDLE,
                        language=Language.UNKNOWN, file_size=0, file_hash="c" * 64,
                        metadata={"bundle": True, "components": []})
    ctx = PipelineContext(target=target, workspace=ws, config=Config())
    ctx.metadata.update({"main_component": main["path"], "main_component_type": main["type"],
                         "main_component_name": main["name"]})
    return ctx


def test_jar_ana_bilesen_java_hattina_gider(tmp_path, monkeypatch):
    jar = tmp_path / "app.jar"
    jar.write_bytes(b"PK\x03\x04jar")
    launcher = tmp_path / "J.app" / "Contents" / "MacOS" / "launcher"
    main = {"name": "app.jar", "path": str(jar), "type": "java_jar", "success": True,
            "functions": 300}
    ctx = _bundle_ctx(tmp_path, main, [
        main, {"name": "launcher", "path": str(launcher), "type": "macho_binary",
               "success": True, "functions": 20}])
    cagri: list[TargetType] = []

    def _kayit(self, c, start):
        cagri.append(c.target.target_type)
        return StageResult(stage_name="reconstruct", success=True, duration_seconds=0.0,
                           stats={"reconstructed": True})

    monkeypatch.setattr(ReconstructionStage, "_execute_analyzer_reconstruct", _kayit)
    res = ReconstructionStage().execute(ctx)
    assert cagri == [TargetType.JAVA_JAR]
    assert res.success is True
    assert res.stats["main_reconstruction"] == "analyzer"
    assert not any("Bilinmeyen bilesen tipi" in e for e in res.errors)


def test_electron_ana_bilesende_deobfuscation_bilesen_uzerinde_kosar(tmp_path, monkeypatch):
    asar = tmp_path / "J.app" / "Contents" / "Resources" / "app.asar"
    asar.parent.mkdir(parents=True)
    asar.write_bytes(b"\x04\x00\x00\x00asar")
    main = {"name": "Electron App", "path": str(asar), "type": "electron_app",
            "success": True, "functions": 0}
    ctx = _bundle_ctx(tmp_path, main, [main])
    cagri: list[tuple[TargetType, Path]] = []

    def _deep(self, c, start):
        cagri.append((c.target.target_type, c.target.path))
        return StageResult(stage_name="deobfuscate", success=True, duration_seconds=0.0,
                           stats={"status": "ok"})

    monkeypatch.setattr(DeobfuscationStage, "_execute_deep", _deep)
    res = DeobfuscationStage().execute(ctx)
    assert cagri == [(TargetType.ELECTRON_APP, asar)]
    assert res.skipped is False
    assert res.stats["bundle_main_component_type"] == "electron_app"
