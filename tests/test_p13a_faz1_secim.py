"""P13a / AD-06: Faz 1 ön adı çıkarıcının kendi seçimidir (eşik, fonksiyon başına en iyi, tek ad).

Eski boru hattı ``extract_result.names`` ham listesini sözlüğe çeviriyordu: eşik altı öneri ön ad
oluyor, aynı fonksiyonda listedeki SON öneri kazanıyor, aynı ad iki fonksiyona gidiyordu.
Kulvar AD-06'nın denemesi gerçek çıkarıcıyla (stratejiler sabit listeye bağlanarak) yinelenir.
"""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from karadul.config import Config
from karadul.pipeline.steps.parallel_algo_eng import _run_binary_name_extraction
from karadul.reconstruction import binary_name_extractor as bne
from karadul.reconstruction.binary_name_extractor import BinaryNameExtractor, ExtractedName


def _n(orig: str, name: str, source: str, conf: float, evidence: str = "e") -> ExtractedName:
    return ExtractedName(orig, name, source, conf, evidence, None, None)


# Kulvar AD-06'nın örneği (sıra önemli: zayıf öneri güçlüden SONRA geliyor)
AD06_ORNEGI = [
    _n("FUN_1", "Foo_render", "rtti", 0.90),
    _n("FUN_1", "handle_enum_x", "enum_handler", 0.35),
    _n("FUN_2", "Foo_init", "build_path", 0.40),
    _n("FUN_3", "Foo_init", "vtable_chain", 0.65),
    _n("FUN_4", "Bar_draw", "rtti", 0.80),
    _n("FUN_5", "Bar_draw", "vtable_chain", 0.75),
]


@pytest.fixture
def girdiler(tmp_path: Path) -> dict[str, Path]:
    static = tmp_path / "static"
    static.mkdir()
    yollar = {
        "strings_json": static / "ghidra_strings.json",
        "functions_json": static / "ghidra_functions.json",
        "call_graph_json": static / "ghidra_call_graph.json",
    }
    yollar["strings_json"].write_text(json.dumps({"strings": []}))
    yollar["functions_json"].write_text(json.dumps({"functions": []}))
    yollar["call_graph_json"].write_text(json.dumps({"nodes": {}}))
    return yollar


@pytest.fixture
def sabit_stratejiler(monkeypatch: pytest.MonkeyPatch) -> None:
    """Bütün stratejiler boş; tek strateji AD06_ORNEGI listesini döndürür."""
    for ad in ("_strategy_debug_strings", "_strategy_build_paths", "_strategy_enum_handlers",
               "_strategy_string_intelligence", "_strategy_swift_demangle",
               "_strategy_vtable_chain"):
        monkeypatch.setattr(BinaryNameExtractor, ad, lambda self: [])
    monkeypatch.setattr(BinaryNameExtractor, "_strategy_rtti_demangle",
                        lambda self: list(AD06_ORNEGI))


def _pc(tmp_path: Path) -> MagicMock:
    pc = MagicMock()
    pc.config = Config()
    kayit: dict = {}

    def save_json(stage: str, name: str, data: dict) -> Path:
        kayit[(stage, name)] = json.loads(json.dumps(data))
        return tmp_path / f"{name}.json"

    pc.workspace.save_json = save_json
    pc.kayit = kayit
    return pc


def test_boru_hatti_cikaricinin_secimini_on_ad_yapar(girdiler, sabit_stratejiler, tmp_path) -> None:
    pc = _pc(tmp_path)
    out = _run_binary_name_extraction(pc=pc, **girdiler)
    # Eşik (0,7) altı FUN_2 / FUN_3 ad almaz; FUN_1'de güçlü öneri kalır; Bar_draw tek fonksiyonda
    assert out["result"] == {"FUN_1": "Foo_render", "FUN_4": "Bar_draw"}
    assert out["stats"]["binary_names_extracted"] == 2
    assert out["stats"]["binary_name_proposals"] == len(AD06_ORNEGI)


def test_binary_names_json_secilen_kaydi_ve_nedenleri_yazar(girdiler, sabit_stratejiler,
                                                             tmp_path) -> None:
    pc = _pc(tmp_path)
    _run_binary_name_extraction(pc=pc, **girdiler)
    kayit = pc.kayit[("reconstructed", "binary_names")]
    assert kayit["total"] == 2
    assert kayit["names"]["FUN_1"]["source"] == "rtti"
    assert kayit["names"]["FUN_1"]["confidence"] == 0.90
    assert set(kayit["names"]) == {"FUN_1", "FUN_4"}
    nedenler = {(c["original"], c["recovered"]): c["reason"] for c in kayit["candidates"]}
    assert nedenler == {
        ("FUN_1", "handle_enum_x"): bne.REASON_BELOW_MIN,
        ("FUN_2", "Foo_init"): bne.REASON_BELOW_MIN,
        ("FUN_3", "Foo_init"): bne.REASON_BELOW_MIN,
        ("FUN_5", "Bar_draw"): bne.REASON_NAME_ELSEWHERE,
    }


def test_ayni_fonksiyonda_daha_guvenli_oneri_kazanir() -> None:
    ext = BinaryNameExtractor(Config())
    naming, secilen, secilmeyen = ext._select([
        _n("FUN_9", "zayif_ad", "build_path", 0.71),
        _n("FUN_9", "guclu_ad", "rtti", 0.95),
        _n("FUN_9", "orta_ad", "vtable_chain", 0.80),
    ])
    assert naming == {"FUN_9": "guclu_ad"}
    assert secilen["FUN_9"].source == "rtti"
    assert sorted((n.recovered_name, r) for n, r in secilmeyen) == [
        ("orta_ad", bne.REASON_BETTER_EXISTS), ("zayif_ad", bne.REASON_BETTER_EXISTS)]
