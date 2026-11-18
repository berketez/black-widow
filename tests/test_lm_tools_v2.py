"""karadul/lm/tools — araç kaydı v2 (KaradulLM v2 tasarımı §3.5; P22d).

Sözleşme: ``docs/arge/2026-11-18_karadullm_v2/arac_sozlesmeleri_v2.md``. Bütün testler geçici dizinde
kurulan SENTETİK çalışma alanıyla (``tests/test_lm_tools.py::build_ws`` + bu dosyanın ek dosyaları)
çalışır: Ghidra, model, ağ yok. Gerçek çalışma alanlarındaki sayımlar ``docs/arge/2026-11-18_onarim/P22d.md``.

Kilitlenen davranışlar:
  (a) kayıt v2: kapalı şemalar, serbest yol / komut / desen alanı yok, sınıf O / R, H giremez,
      ``default_registry`` (K0 / K1 / K2) değişmedi,
  (b) O5 ``get_function_facts``: CFG + fonksiyon kaydı + imzadan parametre sayısı; eksik kaynak null,
  …  (sonraki kalemler aşağıda kendi başlıklarıyla)

Mutasyon koruması: ``scripts/measurement/mutation_specs_lm_arac.json``.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from karadul.lm import protocol as P
from karadul.lm import tools as T
from karadul.lm.context import strip_header
from karadul.lm.events import touched_refs
from karadul.lm.tools import read_more as RM
from tests.test_lm_tools import (
    A, B, BIG, CB, D, ENTRY, HUB, HUB_CALLEES, MALLOC, SIGNAL, body, default_ws, fun,
)


def call(ws: T.Workspace, tool: str, args: dict, **ctx) -> T.ToolResult:
    return T.full_registry().call(ws, tool, args, result_id="r1", ctx=T.ToolContext(**ctx))


def cfg_record(a: str, *, blocks=(5, 7), edges=3, cc=2, loops=1, back=1) -> dict:
    return {"name": fun(a), "address": a, "block_count": len(blocks), "edge_count": edges,
            "cyclomatic_complexity": cc,
            "blocks": [{"start_address": a, "end_address": a, "size": 4 * n, "instruction_count": n} for n in blocks],
            "edges": [], "back_edges": [{"from": a, "to": a}] * back, "loop_headers": [a] * loops}


def write_cfg(root: Path, records: list[dict]) -> None:
    (root / "static" / "ghidra_cfg.json").write_text(
        json.dumps({"program": "t", "total_functions": len(records), "functions": records}), encoding="utf-8")


def set_function_fields(root: Path, a: str, **fields) -> None:
    p = root / "static" / "ghidra_functions.json"
    data = json.loads(p.read_text())
    for f in data["functions"]:
        if f["address"] == a:
            f.update(fields)
    p.write_text(json.dumps(data), encoding="utf-8")


@pytest.fixture()
def root(tmp_path) -> Path:
    r = default_ws(tmp_path / "ws")
    write_cfg(r, [cfg_record(A), cfg_record(B, blocks=(3,), edges=0, cc=1, loops=0, back=0)])
    set_function_fields(r, A, size=96, param_count=0)
    set_function_fields(r, B, size=12, param_count=2)
    return r


@pytest.fixture()
def ws(root) -> T.Workspace:
    return T.Workspace(root)


# --------------------------------------------------------------------------------------------
# (a) kayıt v2

YASAK_ARGUMAN = {"path", "file", "url", "command", "cmd", "regex", "pattern", "shell", "glob", "dir"}


def test_kayit_v2_semalar_ve_siniflar():
    reg = T.full_registry()
    assert reg.names()[:3] == T.default_registry().names() == ("get_evidence", "get_decompiled", "get_xrefs")
    for name in reg.names():
        s = reg.spec(name)
        P.check_schema(s.args_schema)
        assert s.args_schema["type"] == "object" and s.args_schema["additionalProperties"] is False
        assert not (set(s.args_schema["properties"]) & YASAK_ARGUMAN), name
        assert s.cls in ("O", "R") and reg.action(name) == "oku"
        assert "\n" not in s.definition_line() and s.max_result_bytes > 0
        for prop in s.args_schema["properties"].values():
            # Metin argümanı ya adres desenidir ya da uzunluğu sınırlı düz metin / kapalı küme.
            if prop.get("type") == "string" and "pattern" not in prop:
                assert "maxLength" in prop, (name, prop)
    assert reg.action("yok") is None
    # K0 / K1 / K2'nin kümesi ve sürümü değişmedi (sabit önek bayt bayt aynı).
    assert T.default_registry().names() == ("get_evidence", "get_decompiled", "get_xrefs")


def test_kayit_h_sinifi_ve_bilinmeyen_sinif_giremez():
    temel = dict(name="t", signature="t(addr)", description="d",
                 args_schema={"type": "object", "properties": {"addr": {"type": "string", "pattern": T.ADDR_PATTERN}},
                              "required": ["addr"], "additionalProperties": False},
                 max_result_bytes=100, func=lambda w, a, c: T.ToolOutput({}, T.KIND_FACT, "s", ()))
    for cls in ("H", "X", ""):
        with pytest.raises(ValueError):
            T.ToolRegistry([T.ToolSpec(cls=cls, **temel)])
    for cls in ("O", "R", "Ö"):
        assert T.ToolRegistry([T.ToolSpec(cls=cls, **temel)]).names() == ("t",)


# --------------------------------------------------------------------------------------------
# (b) O5 get_function_facts


def test_facts_cfg_fonksiyon_kaydi_ve_imza(ws):
    r = call(ws, "get_function_facts", {"addr": fun(A)})
    assert r.ok and r.kind == "olgu+vekil" and r.source == RM.SOURCE_FACTS
    d = r.data
    assert d["addr"] == fun(A) and d["size_bytes"] == 96
    assert (d["blocks"], d["edges"], d["cyclomatic"], d["loops"], d["back_edges"]) == (2, 3, 2, 1, 1)
    assert d["instructions"] == 12
    # ghidra_functions.json 0 diyor, imza 1 parametre: ikisi ayrı alanlarda, karıştırılmaz.
    assert d["params_ghidra"] == 0 and d["params_signature"] == 1 and d["variadic"] is False
    assert d["ghidra_warning_total"] == 1 and d["ghidra_warnings"] == ["Subroutine does not return"]
    assert d["missing"] == [] and d["lines"] == len(strip_header(ws.read_code(A)).splitlines()) == 10
    b = call(ws, "get_function_facts", {"addr": fun(B)}).data
    assert (b["blocks"], b["loops"], b["params_ghidra"], b["params_signature"]) == (1, 0, 2, 0)
    assert touched_refs(r.envelope()) == []


@pytest.mark.parametrize("sig, beklenen", [
    ("void FUN_00001000(void)", (0, False)),
    ("void FUN_00001000()", (0, False)),
    ("int FUN_00001000(int param_1,long param_2)", (2, False)),
    ("int FUN_00001000(char *param_1,...)", (1, True)),
    ("void FUN_00001000(void (*param_1)(int,int),long param_2)", (2, False)),
    ("undefined1 (*) [16] FUN_00001000(undefined8 param_1,undefined1 (*param_2) [16])", (2, False)),
    ("undefined8 FUN_00001000(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,\n"
     "                       undefined8 param_5)", (5, False)),
])
def test_facts_imza_ayristirma(sig, beklenen):
    code = f"/* WARNING: x */\n\n{sig}\n\n{{\n  return;\n}}\n"
    assert RM.signature_params(code, "FUN_00001000") == beklenen


@pytest.mark.parametrize("code", ["void FUN_00001000(int param_1\n\n{\n}\n", "no brace here\n",
                                  "int FUN_00001000(int a,,int b)\n\n{\n}\n"])
def test_facts_imza_okunamazsa_none(code):
    assert RM.signature_params(code, "FUN_00001000") == (None, False)


def test_facts_eksik_kaynak_null_ve_adi(root):
    (root / "static" / "ghidra_cfg.json").unlink()
    ws = T.Workspace(root)
    d = call(ws, "get_function_facts", {"addr": fun(A)}).data
    assert d["blocks"] is None and d["loops"] is None and d["instructions"] is None
    assert d["missing"] == ["static/ghidra_cfg.json"] and d["params_signature"] == 1
    # cfg var ama bu fonksiyonun kaydı yok; thunk'ın decompile dosyası FUN_ değil (kod okunmaz).
    write_cfg(root, [cfg_record(B)])
    ws = T.Workspace(root)
    d = call(ws, "get_function_facts", {"addr": fun(A)}).data
    assert d["missing"] == ["ghidra_cfg.json: bu fonksiyonun kaydı"] and d["cyclomatic"] is None
    m = call(ws, "get_function_facts", {"addr": fun(MALLOC)}).data
    assert m["params_signature"] is None and m["lines"] is None and m["ghidra_warning_total"] is None
    assert "static/ghidra_output/decompiled: bu fonksiyonun dosyası" in m["missing"]


def test_facts_hata_kodlari(ws):
    assert call(ws, "get_function_facts", {"addr": "FUN_0000dead"}).error == "bilinmeyen_adres"
    assert call(ws, "get_function_facts", {"addr": "deadbeef"}).error == "gecersiz_arguman"
    assert call(ws, "get_function_facts", {"addr": fun(A), "x": 1}).error == "gecersiz_arguman"
