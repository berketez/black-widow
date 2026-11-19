"""P02b kalem 3: anti-debug dedektörü tarama durumunu kendisi döndürür; adım onu yazar.

Eski davranış (taban 0984090): ``detect()`` katman istisnalarını yutuyordu; adım
(``pipeline/steps/anti_debug.py``) dedektörün iç adlarını (``detect_by_imports`` …,
``_code_layout``, ``_X86_ARCHES``) sarıp gözleyerek durumu kendisi çıkarıyordu.
Dedektörde bir katmanın adı değişse adım durumu yanlış yazardı. Şimdi
``AntiDebugDetector.scan()`` → ``AntiDebugScan`` (bulgular + durum + katman
durumları + taranan bayt); ``detect()`` aynı bulguları döndürür.
"""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from karadul.analyzers import anti_debug_detector as ad_mod
from karadul.analyzers.anti_debug_detector import AntiDebugDetector, AntiDebugScan
from karadul.pipeline.context import StepContext
from karadul.pipeline.steps.anti_debug import AntiDebugStep


@pytest.fixture
def bilinmeyen(tmp_path: Path) -> Path:
    p = tmp_path / "x.bin"
    p.write_bytes(b"\x00" * 64 + b"TracerPid:" + b"\x00" * 64)
    return p


class TestDedektorDurumu:
    def test_temiz_tarama(self, bilinmeyen):
        r = AntiDebugDetector(binary_path=bilinmeyen).scan()
        assert r.status == "calisti" and r.status_reason == ""
        assert r.layers["imports"]["status"] == "calisti"
        assert r.layers["strings"]["status"] == "calisti"
        assert r.layers["bytes"]["status"] == "desteklenmiyor"
        assert "uygulanmaz" in r.layers["bytes"]["reason"]
        assert r.file_size == r.scanned_bytes == bilinmeyen.stat().st_size
        assert [f.technique for f in r.findings] == ["Linux_TracerPid"]

    def test_detect_ayni_bulgular(self, bilinmeyen):
        d = AntiDebugDetector(binary_path=bilinmeyen)
        assert [f.to_dict() for f in d.detect()] == [
            f.to_dict() for f in AntiDebugDetector(binary_path=bilinmeyen).scan().findings]

    def test_katman_hatasi_kismi(self, bilinmeyen, monkeypatch):
        def boom(self):
            raise RuntimeError("dizgi tablosu bozuk")
        monkeypatch.setattr(AntiDebugDetector, "detect_by_strings", boom)
        r = AntiDebugDetector(binary_path=bilinmeyen).scan()
        assert r.status == "kismi"
        assert r.layers["strings"] == {"status": "hata",
                                       "reason": "RuntimeError: dizgi tablosu bozuk"}
        assert "dizgi tablosu bozuk" in r.status_reason
        assert r.layer_errors == ["strings katmani: RuntimeError: dizgi tablosu bozuk"]

    def test_hepsi_hata(self, bilinmeyen, monkeypatch):
        def boom(self):
            raise RuntimeError("x")
        for _, meth in ad_mod.SCAN_LAYERS:
            monkeypatch.setattr(AntiDebugDetector, meth, boom)
        assert AntiDebugDetector(binary_path=bilinmeyen).scan().status == "hata"

    def test_kesik_tarama_kismi(self, bilinmeyen):
        r = AntiDebugDetector(binary_path=bilinmeyen, max_bytes_scan=32).scan()
        assert r.status == "kismi" and r.scanned_bytes == 32
        assert "32" in r.status_reason

    @pytest.mark.skipif(hasattr(os, "geteuid") and os.geteuid() == 0, reason="root")
    def test_okunamayan_dosya_hata(self, bilinmeyen):
        bilinmeyen.chmod(0)
        try:
            r = AntiDebugDetector(binary_path=bilinmeyen).scan()
        finally:
            bilinmeyen.chmod(0o644)
        assert r.status == "hata" and "okunamadi" in r.status_reason
        assert r.findings == [] and r.scanned_bytes is None


class _IcAdsizDedektor:
    """Katman yöntemleri ve ``_code_layout`` olmayan dedektör: yalnız scan + summary."""

    def __init__(self, target=None, binary_path=None):
        self.binary_path = binary_path

    def scan(self):
        return AntiDebugScan([], "kismi", "bytes katmani: neden-X",
                             {"imports": {"status": "calisti", "reason": ""},
                              "bytes": {"status": "hata", "reason": "neden-X"}},
                             128, 100, ["bytes katmani: neden-X"])

    def summary(self, findings):
        return {"total": 0}


def test_adim_dedektor_durumunu_yazar(tmp_path):
    """Adım dedektörün iç adlarına bakmadan ``scan()`` durumunu aynen yazar."""
    ikili = tmp_path / "b.bin"
    ikili.write_bytes(b"\x00" * 128)
    pc = MagicMock()
    pc.config.binary_reconstruction.enable_anti_debug_detection = True
    pc.workspace.save_json.return_value = tmp_path / "anti_debug_findings.json"
    ctx = StepContext(pipeline_context=pc)
    ctx._write_artifacts({"binary_for_byte_match": ikili})
    with patch("karadul.analyzers.anti_debug_detector.AntiDebugDetector", _IcAdsizDedektor):
        AntiDebugStep().run(ctx)
    payload = pc.workspace.save_json.call_args[0][2]
    assert payload["status"] == "kismi"
    assert payload["status_reason"] == "bytes katmani: neden-X"
    assert payload["layers"]["bytes"] == {"status": "hata", "reason": "neden-X"}
    assert payload["scanned_bytes"] == 100 and payload["file_size"] == 128
    assert payload["total_findings"] is None
    assert ctx.stats["anti_debug_status"] == "kismi"
    assert any("neden-X" in e for e in ctx.errors)
