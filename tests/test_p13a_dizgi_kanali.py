"""P13a / AD-09: dizgi içeriğinden kurulan Faz 1 adı ön ad kanalına girmez; c_namer adayı olur.

N0b, c_namer'ın ``string_context`` alt kanallarından ``agresif`` (``Class::Method``) ve
``hata_iletisi``'ni ölçüp susturdu. Aynı sinyali Faz 1 çıkarıcısı da üretiyor; eskiden onun adı
ön ad olarak susturmayı, ürün eşiğini ve ad geçerliliğini atlayıp koda yazılıyordu. Sınama:
``"Foo::bar failed"`` dizgisini başvuran sentetik fonksiyon ön ad almaz; öneri kanıtıyla aday
kalır ve c_namer'a giden listede durur.
"""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from karadul.config import Config
from karadul.pipeline.steps.parallel_algo_eng import ParallelAlgoEngStep, _run_binary_name_extraction
from karadul.reconstruction import binary_name_extractor as bne
from karadul.reconstruction.binary_name_extractor import BinaryNameExtractor, ExtractedName


def _ws(tmp_path: Path) -> dict[str, Path]:
    static = tmp_path / "static"
    static.mkdir()
    strings = {"strings": [{
        "address": "0x00005000", "value": "Foo::bar failed", "length": 15, "type": "string",
        "xrefs": [{"from_address": "0x00001010", "from_function": "FUN_00001000",
                   "from_func_addr": "0x00001000"}],
        "function": "FUN_00001000", "function_addr": "0x00001000",
    }]}
    functions = {"functions": [
        {"name": "FUN_00001000", "address": "0x00001000", "size": 64},
        {"name": "FUN_00002000", "address": "0x00002000", "size": 64},
    ]}
    yollar = {
        "strings_json": static / "ghidra_strings.json",
        "functions_json": static / "ghidra_functions.json",
        "call_graph_json": static / "ghidra_call_graph.json",
    }
    yollar["strings_json"].write_text(json.dumps(strings))
    yollar["functions_json"].write_text(json.dumps(functions))
    yollar["call_graph_json"].write_text(json.dumps({"nodes": {}}))
    return yollar


def _pc() -> MagicMock:
    pc = MagicMock()
    pc.config = Config()
    pc.kayit = {}

    def save_json(stage: str, name: str, data: dict) -> Path:
        pc.kayit[(stage, name)] = json.loads(json.dumps(data))
        return Path("/dev/null")

    pc.workspace.save_json = save_json
    return pc


def test_class_method_dizgisi_on_ad_olmaz_c_namer_adayi_olur(tmp_path) -> None:
    pc = _pc()
    out = _run_binary_name_extraction(pc=pc, **_ws(tmp_path))
    # Çıkarıcı öneriyi üretiyor (eski arayüz hâlâ görür) ...
    ext = BinaryNameExtractor(Config())
    (tmp_path / "ikinci").mkdir()
    ext.extract(**_ws(tmp_path / "ikinci"))
    assert ext.as_naming_map().get("FUN_00001000") == "Foo_bar"
    # ... ama ön ad kanalına girmiyor; c_namer'a aday olarak gidiyor.
    assert "FUN_00001000" not in out["result"]
    adaylar = out["string_candidates"]
    # İki dizgi stratejisi de (debug_string, string_intel) aynı dizgiden öneri verir; ikisi de aday.
    assert {(a["key"], a["name"], a["source"]) for a in adaylar} == {
        ("FUN_00001000", "Foo_bar", "debug_string"), ("FUN_00001000", "Foo_bar", "string_intel")}
    assert all("Foo::bar failed" in a["evidence"] for a in adaylar)
    kayit = pc.kayit[("reconstructed", "binary_names")]
    assert kayit["names"] == {}
    assert {(c["original"], c["reason"]) for c in kayit["candidates"]} == {
        ("FUN_00001000", bne.REASON_STRING_CHANNEL)}
    assert out["stats"]["binary_name_string_candidates"] == len(adaylar) == 2


def _n(source: str, evidence: str) -> ExtractedName:
    return ExtractedName("FUN_1", "Foo_bar", source, 0.95, evidence, "Foo", None)


@pytest.mark.parametrize(("source", "evidence", "beklenen"), [
    ("debug_string", 'String xref: "Foo::bar failed" -> FUN_1', True),
    ("debug_string", 'String: "Foo::bar"', True),
    ("string_intel", 'error_message: "cannot open"', True),
    ("debug_string", f"{bne.EXPORT_EVIDENCE_PREFIX}__Foo_GetX", False),
    ("rtti", "typeinfo for Foo", False),
    ("vtable_chain", "vtable for Foo", False),
])
def test_dizgi_kanali_siniflamasi(source: str, evidence: str, beklenen: bool) -> None:
    assert bne.is_string_channel(_n(source, evidence)) is beklenen


def test_dizgi_onerisi_ayni_fonksiyondaki_dizgi_disi_oneriyi_ezmez() -> None:
    ext = BinaryNameExtractor(Config())
    res = MagicMock()
    res.names = [
        ExtractedName("FUN_1", "Foo_bar", "debug_string", 0.92, 'String xref: "Foo::bar"', "Foo",
                      None),
        ExtractedName("FUN_1", "Foo_render", "rtti", 0.90, "typeinfo", "Foo", None),
    ]
    res.class_methods, res.member_vars, res.source_files = {}, {}, {}
    ext._merge_results(res)
    assert ext.as_pre_name_map() == {"FUN_1": "Foo_render"}
    assert ext.as_naming_map() == {"FUN_1": "Foo_bar"}  # eski arayüz değişmedi


def test_adim_dizgi_adaylarini_yapit_olarak_uretir() -> None:
    from karadul.pipeline.registry import get_step

    assert get_step("parallel_algo_eng").cls is ParallelAlgoEngStep
    assert "phase1_string_candidates" in get_step("parallel_algo_eng").produces
