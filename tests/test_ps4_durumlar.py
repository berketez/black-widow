"""P-S4 kalem 5: dürüst durumlar.

- Tanınan kapsayıcıda (wheel, nupkg …) ve tanınmayan türde static aşaması
  "Analyzer bulunamadi: No analyzer registered for TargetType.UNKNOWN", deobfuscate
  "Hedef türü tanınmadı" diyordu (P-S1 notu). Artık ``desteklenmiyor`` + gerçek neden.
- ``ReconstructionStage._execute_binary``'nin üç ``except RuntimeError`` dalı
  (Faz 1 / 2 / 3 adım koşucusu düştü) ``reconstruct_status`` yazmıyordu (P14 notu).
"""

from __future__ import annotations

import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest

import karadul.stages as stages_mod

from karadul.config import Config
from karadul.core.pipeline import PipelineContext
from karadul.core.target import TargetDetector, TargetType
from karadul.core.workspace import Workspace
from karadul.stages import DeobfuscationStage, ReconstructionStage, StaticAnalysisStage


def _wheel(tmp_path: Path) -> Path:
    p = tmp_path / "ornek-1.0-py3-none-any.whl"
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("ornek/__init__.py", "x = 1\n")
        z.writestr("ornek-1.0.dist-info/WHEEL", "Wheel-Version: 1.0\nTag: py3-none-any\n")
        z.writestr("ornek-1.0.dist-info/METADATA", "Name: ornek\nVersion: 1.0\n")
        z.writestr("ornek-1.0.dist-info/RECORD", "")
    return p


def _ctx(tmp_path: Path, path: Path) -> PipelineContext:
    target = TargetDetector().detect(path)
    ws = Workspace(base_dir=tmp_path / "ws", target_name="ornek")
    ws.create()
    return PipelineContext(target=target, workspace=ws, config=Config())


def test_kapsayicida_static_desteklenmiyor_gercek_neden(tmp_path):
    ctx = _ctx(tmp_path, _wheel(tmp_path))
    assert ctx.target.target_type == TargetType.UNKNOWN
    assert ctx.target.metadata.get("container") == "python_wheel"
    res = StaticAnalysisStage().execute(ctx)
    assert res.success is False
    assert res.stats["static_status"] == "desteklenmiyor"
    assert res.errors[0].startswith("Desteklenmiyor: kapsayıcı tanındı (python_wheel)")
    assert "Analyzer bulunamadi" not in " ".join(res.errors)
    assert res.stats["container"] == "python_wheel"


def test_kapsayicida_deobfuscate_neden_kapsayiciyi_soyler(tmp_path):
    ctx = _ctx(tmp_path, _wheel(tmp_path))
    res = DeobfuscationStage().execute(ctx)
    assert res.skipped is True
    assert "python_wheel" in res.stats["skip_reason"]
    assert "Hedef türü tanınmadı" not in res.stats["skip_reason"]


def test_taninmayan_tur_static_sihirli_sayi(tmp_path):
    p = tmp_path / "bilinmeyen.bin"
    p.write_bytes(b"\x11\x22\x33\x44" + b"\x00" * 60)
    ctx = _ctx(tmp_path, p)
    assert ctx.target.target_type == TargetType.UNKNOWN
    res = StaticAnalysisStage().execute(ctx)
    assert res.stats["static_status"] == "desteklenmiyor"
    assert "hedef türü tanınmadı" in res.errors[0]


# --- Adım koşucusu düştü: reconstruct_status ---------------------------------

_FAZ1 = {
    "decompiled_dir": None, "functions_json_path": None, "strings_json_path": None,
    "call_graph_json_path": None, "xrefs_json_path": None, "functions_data": {},
    "strings_data": {}, "call_graph_data": {}, "sig_matches": [],
    "algo_result_filtered": None, "eng_result_filtered": None, "extracted_names": {},
    "capa_capabilities": None,
}
_FAZ2 = {
    "naming_result": None, "computation_result": None, "updated_algo_result": None,
    "updated_eng_result": None, "final_decompiled_dir": None,
}


@pytest.mark.parametrize("dusen", [1, 2, 3])
def test_kosucu_duserse_reconstruct_status_basarisiz(tmp_path, monkeypatch, dusen):
    import karadul.pipeline.runner as runner_mod

    sayac = {"n": 0}

    class _Kosucu:
        def __init__(self, steps):
            self.steps = steps

        def run(self, context, seed_artifacts=None):
            sayac["n"] += 1
            if sayac["n"] == dusen:
                raise RuntimeError(f"test: koşucu {dusen} düştü")
            arts = dict(_FAZ1 if sayac["n"] == 1 else _FAZ2)
            return SimpleNamespace(artifacts=arts, stats={}, errors=[], stage_artifacts={})

    monkeypatch.setattr(runner_mod, "PipelineRunner", _Kosucu)
    p = tmp_path / "ikili"
    p.write_bytes(b"\x7fELF" + b"\x00" * 60)
    ctx = _ctx(tmp_path, p)
    stage = ReconstructionStage()
    monkeypatch.setattr(stage, "_seed_recovery_pre_names", lambda *a, **k: {})
    res = stage._execute_binary(ctx, 0.0)
    assert res.success is False
    assert res.stats["reconstruct_status"] == "basarisiz"
    faz = {1: "Faz 1", 2: "Faz 2", 3: "Faz 3"}[dusen]
    assert res.stats["reconstruct_failure_reasons"][0].startswith(f"{faz} adım koşucusu düştü")
    assert f"test: koşucu {dusen} düştü" in res.errors


# --- Decompiler yok: iskelet 'başarılı' değil, arac_yok + neden ----------------

@pytest.mark.parametrize("decompiled,beklenen", [(False, "arac_yok"), (True, None)])
def test_decompiler_yoksa_arac_yok_yazilir(tmp_path, monkeypatch, decompiled, beklenen):
    from karadul.core.result import StageResult

    class _SahteJava:
        def __init__(self, config=None):
            pass

        def reconstruct(self, target, workspace):
            return StageResult(stage_name="x", success=True, duration_seconds=0.0,
                               stats={"reconstructed": True})

    monkeypatch.setattr(stages_mod, "get_analyzer", lambda _t: _SahteJava)
    p = tmp_path / "a.jar"
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")
        z.writestr("a/B.class", b"\xca\xfe\xba\xbe\x00\x00\x00\x34")
    ctx = _ctx(tmp_path, p)
    ctx.results["static"] = StageResult(
        stage_name="static", success=True, duration_seconds=0.0,
        stats={"decompiled": decompiled},
        errors=[] if decompiled else ["jadx bulunamadi — 'brew install jadx' ile kurun"],
    )
    res = ReconstructionStage()._execute_analyzer_reconstruct(ctx, 0.0)
    assert res.stats.get("decompiler_status") == beklenen
    if beklenen:
        assert "jadx bulunamadi" in res.stats["decompiler_reason"]
        assert any(e.startswith("Kaynak kod kurulmadı (jadx bulunamadi") for e in res.errors)
    else:
        assert res.errors == []
