"""P13b / BORU-10 = MUH-08: parametre adı yayılımı uygulanmıyor; sayaç uygulanmayanı "yayıldı" saymaz.

Eski davranış: ``stats["param_names_propagated"] = len(adaylar)`` (119 ikilide toplam 1 835) ama
adlar hiçbir yere yazılmıyordu (``out/src``'de 0).
"""
from __future__ import annotations

from pathlib import Path

from karadul.pipeline.steps import _deep_tracing_helpers as DH
from karadul.reconstruction import engineering


def test_counter_reports_applied_zero_and_candidates_separately(monkeypatch, tmp_path) -> None:
    class Fake:
        def propagate_param_names(self, **_kw):
            return ["a", "b", "c"]

    monkeypatch.setattr(engineering, "InterProceduralDataFlow", Fake)
    stats: dict = {}
    errors: list[str] = []
    DH.propagate_param_names(tmp_path, tmp_path / "f.json", tmp_path / "cg.json", None, None,
                             stats, errors)
    assert errors == []
    assert stats["param_names_propagated"] == 0
    assert stats["param_name_propagation_candidates"] == 3
    assert stats["param_name_propagation_status"] == "uygulanmadi"
    assert stats["param_name_propagation_reason"]


def test_no_candidates_writes_no_counter(monkeypatch, tmp_path: Path) -> None:
    class Fake:
        def propagate_param_names(self, **_kw):
            return []

    monkeypatch.setattr(engineering, "InterProceduralDataFlow", Fake)
    stats: dict = {}
    DH.propagate_param_names(tmp_path, tmp_path / "f.json", tmp_path / "cg.json", None, None,
                             stats, [])
    assert "param_names_propagated" not in stats
