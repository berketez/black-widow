"""P13a / AD-09 (c_namer yaması): Faz 1 dizgi kanalı önerisi c_namer'da ``string_context`` adayıdır.

Ön ad kanalından çıkarılan öneri (``parallel_algo_eng`` → ``phase1_string_candidates``) c_namer'a
aday olarak verilir; susturma açıkken ``Class::Method`` kalıbı (alt kanal ``agresif``) susar ve
``naming_silenced``'a sayılır, susturma kapalıyken klasik seçimden geçer. Yamasız c_namer bu
argümanı tanımaz (TypeError): test yamayla birlikte gelir.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
import test_c_namer_determinism as T  # noqa: E402

from karadul.config import Config  # noqa: E402
from karadul.reconstruction import c_namer  # noqa: E402
from karadul.reconstruction.c_namer import CVariableNamer  # noqa: E402
from karadul.reconstruction.tarif import alt_kanal  # noqa: E402

ADAY = {"key": "FUN_00007000", "name": "Foo_bar", "confidence": 0.92, "source": "debug_string",
        "evidence": 'String xref: "Foo::bar failed" -> FUN_00007000'}


@pytest.fixture
def seri(monkeypatch):
    monkeypatch.setattr(c_namer, "ProcessPoolExecutor", T._SerialExecutor)
    monkeypatch.setattr(c_namer, "_worker_namer", None)


def _kos(tmp_path: Path, **kurucu):
    ws = T.build_workspace(tmp_path / "ws")
    out = tmp_path / "out"
    namer = CVariableNamer(Config(), min_confidence=0.15, **kurucu)
    res = namer.analyze_and_rename(ws["decompiled"], ws["functions"], ws["strings"],
                                   ws["call_graph"], out, phase1_string_candidates=[ADAY])
    assert res.success, res.errors
    prov = json.loads((out / c_namer.NAMING_PROVENANCE_FILE).read_text(encoding="utf-8"))
    return res, prov


def test_susturma_acikken_agresif_aday_susar(seri, tmp_path) -> None:
    res, _ = _kos(tmp_path, silenced_subchannels=alt_kanal.SILENCED_SUBCHANNELS)
    assert res.naming_map.get("FUN_00007000") != "foo_bar"
    assert res.silenced_counts.get("agresif", 0) >= 1


def test_susturma_kapaliyken_string_context_adayi_olarak_secilir(seri, tmp_path) -> None:
    res, prov = _kos(tmp_path)
    # ad ön ad yolundaki temizleyiciden geçer (CamelCase yoksa küçük harf)
    assert res.naming_map.get("FUN_00007000") == "foo_bar"
    assert res.strategy_map["FUN_00007000"] == "string_context"
    kayit = prov["global"]["FUN_00007000"]
    assert kayit["code_path"] == "aggressive" and kayit["rule"] == "phase1_extractor"
