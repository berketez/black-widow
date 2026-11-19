"""P-S4 kalem 4 (BICIM-10 stages tarafı): evrensel ikilide tanınan Go / Bun dilimi.

P19 ``core/target.py`` evrensel dosyada dilim başına Go / Bun işaretini metadata'ya
yazıyor ama tür UNIVERSAL_BINARY kalıyor (analizcileri şişman dosyayı açmıyor). Eskiden
akışta bu hiç görünmüyordu: Go hattının koşmadığı sessizdi. Artık static aşaması
``go_hatti_status: desteklenmiyor`` + neden yazar ve aşama kısmi olur.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import karadul.stages as stages_mod
from karadul.config import Config
from karadul.core.pipeline import PipelineContext
from karadul.core.result import StageResult
from karadul.core.target import Language, TargetInfo, TargetType
from karadul.core.workspace import Workspace
from karadul.stages import StaticAnalysisStage


class _SahteMacho:
    def __init__(self, config=None):
        self.config = config

    def analyze_static(self, target, workspace):
        return StageResult(stage_name="static", success=True, duration_seconds=0.0,
                           stats={"universal_slice": "arm64"})


def _calistir(tmp_path: Path, monkeypatch, meta: dict) -> StageResult:
    monkeypatch.setattr(stages_mod, "get_analyzer", lambda _t: _SahteMacho)
    monkeypatch.setattr(stages_mod, "_run_yara_scan", lambda *a, **k: None)
    monkeypatch.setattr(stages_mod, "_run_capa_scan", lambda *a, **k: None)
    p = tmp_path / "fat"
    p.write_bytes(b"\xca\xfe\xba\xbe" + b"\x00" * 60)
    target = TargetInfo(path=p, name="fat", target_type=TargetType.UNIVERSAL_BINARY,
                        language=Language.UNKNOWN, file_size=64, file_hash="d" * 64,
                        metadata={"arch": "universal", **meta})
    ws = Workspace(base_dir=tmp_path / "ws", target_name="fat")
    ws.create()
    return StaticAnalysisStage().execute(PipelineContext(target=target, workspace=ws,
                                                         config=Config()))


@pytest.mark.parametrize("anahtar,tur", [("go_slice", "go"), ("bun_slice", "bun")])
def test_evrensel_ozel_dilim_desteklenmiyor_yazilir(tmp_path, monkeypatch, anahtar, tur):
    res = _calistir(tmp_path, monkeypatch, {anahtar: True})
    assert res.stats[f"{tur}_hatti_status"] == "desteklenmiyor"
    assert "şişman dosyayı açmıyor" in res.stats[f"{tur}_hatti_reason"]
    assert any(e.startswith("Desteklenmiyor: evrensel ikilide") for e in res.errors)


def test_duz_evrenselde_not_yok(tmp_path, monkeypatch):
    res = _calistir(tmp_path, monkeypatch, {})
    assert "go_hatti_status" not in res.stats and "bun_hatti_status" not in res.stats
    assert res.errors == []
