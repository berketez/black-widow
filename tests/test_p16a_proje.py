"""P16a / B-C4: Ghidra projesinin akıbeti (silindi / kaldı) sonuçta ve durum dosyasında yazılı.

Eski davranış: ``_run_ghidra_legacy`` ``finally``'de projeyi sessizce siliyordu; silinemezse yalnız
uyarı. "Yeniden hesapla" (tek fonksiyonu yeniden derleme, ``docs/arge/2026-11-11_yeniden_hesapla``)
projeyi neden bulamadığını hiçbir çıktıdan öğrenemiyordu.
"""
from __future__ import annotations

import json

from karadul.analyzers.macho import MachOAnalyzer
from karadul.config import Config
from karadul.core.workspace import Workspace


class _Gh:
    def is_available(self):
        return True

    def get_default_scripts(self):
        return []

    @staticmethod
    def pyghidra_available():
        return True

    def analyze(self, project_dir, **kw):
        (project_dir / "karadul_x.gpr").write_text("proje")
        return {"success": True, "scripts_output": {}}


def _kur(tmp_path):
    cfg = Config()
    cfg.project_root = tmp_path
    an = MachOAnalyzer(cfg)
    an.ghidra = _Gh()
    ws = Workspace(tmp_path / "ws", "ikili")
    ws.create()
    return an, ws


def test_proje_silinir_ve_akibeti_yazilir(tmp_path):
    an, ws = _kur(tmp_path)
    sonuc = an._run_ghidra_legacy(tmp_path / "ikili", ws)
    proje = sonuc["project"]
    assert proje["kept"] is False and "silindi" in proje["reason"]
    assert not (ws.get_stage_dir("static") / "ghidra_project").exists()

    stats: dict = {}
    MachOAnalyzer._record_ghidra_outcome(sonuc, ws, {}, stats)
    durum = json.loads((ws.get_stage_dir("static") / "ghidra_status.json").read_text(encoding="utf-8"))
    assert durum["project"]["kept"] is False


def test_proje_silinemezse_kaldigi_yazilir(tmp_path, monkeypatch):
    import karadul.ghidra.project as proje_mod

    def patla(p):
        raise OSError("izin yok")

    monkeypatch.setattr(proje_mod.shutil, "rmtree", patla)
    an, ws = _kur(tmp_path)
    sonuc = an._run_ghidra_legacy(tmp_path / "ikili", ws)
    assert sonuc["project"]["kept"] is True
    assert "silinemedi" in sonuc["project"]["reason"]
