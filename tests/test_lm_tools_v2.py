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
    A, B, BIG, CB, D, ENTRY, HUB, HUB_CALLEES, MALLOC, SIGNAL, body, build_ws, default_ws, fun,
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


# --------------------------------------------------------------------------------------------
# (c) O7 get_call_graph, O7b find_path

def X(i: int) -> str:
    return f"{0x20000 + 0x10 * i:08x}"


@pytest.fixture()
def gws(tmp_path) -> T.Workspace:
    """Yol grafiği: elmas X0→{X1,X2}→X3→X4; uzun zincir X0→X5→…→X11 (7 adım); X0→Q1..Q5→X20
    (5 en kısa yol; Q = X40..X44); X12 → X0 (tek çağıran); X30 kopuk."""
    calls = {X(0): [X(1), X(2), X(5), *[X(40 + k) for k in range(5)]], X(1): [X(3)], X(2): [X(3)], X(3): [X(4)],
             X(4): [], X(12): [X(0)], X(20): [], X(30): []}
    for i in range(5, 11):
        calls[X(i)] = [X(i + 1)]
    calls[X(11)] = []
    for k in range(5):
        calls[X(40 + k)] = [X(20)]
    return T.Workspace(build_ws(tmp_path / "g", {a: {"calls": c} for a, c in calls.items()},
                                names={X(3): "mid_node"},
                                provenance={X(3): {"new_name": "mid_node", "label": "kesin"}}))


def test_graf_asagi_derinlik_sira_ve_kenarlar(ws):
    r = call(ws, "get_call_graph", {"addr": fun(D), "direction": "callees", "depth": 2})
    assert r.ok and r.kind == "olgu" and r.source == "static/ghidra_call_graph.json"
    d = r.data
    # ENTRY (Ghidra'nın adlandırdığı, FUN_ dosyası yok) düğüm değildir; öz çağrı (A→A) sayılmaz.
    beklenen = sorted([A, B, "0000c000", "0000c010", "00007000", "00008000", "0000c020"], key=lambda h: int(h, 16))
    assert [i["addr"] for i in d["items"]] == [fun(x) for x in beklenen]
    assert {i["depth"] for i in d["items"]} == {1}
    # Kenarlar: çağıran adresine, sonra çağrılana göre; öz çağrı (A→A) kenar değildir.
    assert d["edges"] == [[fun(A), fun(B)]] + [[fun(D), fun(x)] for x in beklenen]
    assert d["coverage"] == {"reached": 7, "shown": 7, "omitted": 0, "edges_total": len(d["edges"]),
                             "edges_omitted": 0} and r.truncated is None
    assert {i["addr"] for i in d["items"]} == set(touched_refs(r.envelope()))
    tag = {i["addr"]: i["name_tag"] for i in d["items"]}
    assert tag[fun(B)] == "[proven: parse_header]" and tag[fun(A)] == "[unverified: run_main]"


def test_graf_yukari_ve_derinlik(gws):
    d = call(gws, "get_call_graph", {"addr": fun(X(3)), "direction": "callers", "depth": 2}).data
    assert [(i["addr"], i["depth"]) for i in d["items"]] == [(fun(X(1)), 1), (fun(X(2)), 1), (fun(X(0)), 2)]
    d1 = call(gws, "get_call_graph", {"addr": fun(X(3)), "direction": "callers", "depth": 1}).data
    assert [i["addr"] for i in d1["items"]] == [fun(X(1)), fun(X(2))]
    # Öntanım derinlik 2: X0'ın aşağısı X1, X2, X5, Q1..Q5 (1) + X3, X6, X20 (2).
    d0 = call(gws, "get_call_graph", {"addr": fun(X(0)), "direction": "callees"}).data
    assert d0["depth"] == 2 and d0["coverage"]["reached"] == 11
    assert [i["depth"] for i in d0["items"]] == [1] * 8 + [2] * 3


def test_graf_dugum_tavani(ws):
    r = call(ws, "get_call_graph", {"addr": fun(HUB), "direction": "callees"})
    assert len(r.data["items"]) == T.CALL_GRAPH_MAX_NODES == 40
    assert r.data["coverage"]["omitted"] == len(HUB_CALLEES) - 40 and r.truncated["omitted"] == 5
    assert [i["addr"] for i in r.data["items"]] == [fun(x) for x in HUB_CALLEES[:40]]
    r3 = call(ws, "get_call_graph", {"addr": fun(HUB), "direction": "callees", "max_nodes": 3})
    assert len(r3.data["items"]) == 3 and r3.truncated == {"omitted": 42, "total": 45, "edges_omitted": 0}
    assert r.size_bytes() <= T.CALL_GRAPH_RESULT_MAX_BYTES
    assert call(ws, "get_call_graph", {"addr": fun(HUB), "direction": "callees", "depth": 3}).error == "gecersiz_arguman"


def test_graf_kenar_tavani_kirpmayi_soyler(tmp_path):
    nodes = [X(i) for i in range(12)]
    # 12 düğümlü tam yönlü grafik: 12 × 11 = 132 kenar > 80.
    ws = T.Workspace(build_ws(tmp_path / "k", {a: {"calls": [b for b in nodes if b != a]} for a in nodes}))
    r = call(ws, "get_call_graph", {"addr": fun(nodes[0]), "direction": "callees", "depth": 1})
    cov = r.data["coverage"]
    assert len(r.data["edges"]) == T.CALL_GRAPH_MAX_EDGES == 80 and cov["edges_total"] == 132
    assert cov["edges_omitted"] == 52 and r.truncated == {"omitted": 0, "total": 11, "edges_omitted": 52}


def test_graf_hatalar_ve_korluk(ws, tmp_path):
    assert call(ws, "get_call_graph", {"addr": "FUN_0000dead", "direction": "callees"}).error == "bilinmeyen_adres"
    # thunk'ın decompile dosyası FUN_ değil: grafikte düğüm değildir.
    assert call(ws, "get_call_graph", {"addr": fun(MALLOC), "direction": "callers"}).error == "veri_yok"
    grafiksiz = T.Workspace(default_ws(tmp_path / "g0", graph=None))
    assert call(grafiksiz, "get_call_graph", {"addr": fun(A), "direction": "callees"}).error == "veri_yok"
    assert call(grafiksiz, "find_path", {"addr": fun(D), "to": fun(B)}).error == "veri_yok"
    kor = call(ws, "get_call_graph", {"addr": fun(A), "direction": "callers"}, blind_target=B).data
    # D'nin adı elle verilmiş (köken kaydı başka adı anlatıyor): körlükte gösterilmez.
    assert [i["name_tag"] for i in kor["items"]] == [None]
    kor_b = call(ws, "get_call_graph", {"addr": fun(D), "direction": "callees"}, blind_target=B).data
    assert {i["addr"]: i["name_tag"] for i in kor_b["items"]}[fun(B)] is None


def test_yol_elmas_tum_en_kisa_yollar(gws):
    r = call(gws, "find_path", {"addr": fun(X(0)), "to": fun(X(4))})
    assert r.ok and r.kind == "olgu"
    d = r.data
    assert d["found"] is True and d["length"] == 3 and d["paths_total"] == 2 and r.truncated is None
    assert d["paths"] == [[fun(X(0)), fun(X(1)), fun(X(3)), fun(X(4))],
                          [fun(X(0)), fun(X(2)), fun(X(3)), fun(X(4))]]
    assert [i["addr"] for i in d["items"]] == [fun(X(1)), fun(X(3)), fun(X(4)), fun(X(2))]
    assert {i["addr"]: i["name_tag"] for i in d["items"]}[fun(X(3))] == "[proven: mid_node]"
    assert set(touched_refs(r.envelope())) == {fun(X(i)) for i in (1, 2, 3, 4)}


def test_yol_derinlik_siniri_ve_yon(gws):
    assert call(gws, "find_path", {"addr": fun(X(0)), "to": fun(X(10))}).data["length"] == 6
    uzak = call(gws, "find_path", {"addr": fun(X(0)), "to": fun(X(11))})
    assert uzak.ok and uzak.data["found"] is False and uzak.data["paths"] == [] and uzak.data["length"] is None
    assert touched_refs(uzak.envelope()) == []
    assert call(gws, "find_path", {"addr": fun(X(0)), "to": fun(X(4)), "max_depth": 2}).data["found"] is False
    # Yön: X4 X0'ı çağırmaz.
    assert call(gws, "find_path", {"addr": fun(X(4)), "to": fun(X(0))}).data["found"] is False
    assert call(gws, "find_path", {"addr": fun(X(12)), "to": fun(X(4))}).data["length"] == 4
    assert call(gws, "find_path", {"addr": fun(X(0)), "to": fun(X(0))}).error == "gecersiz_arguman"
    assert call(gws, "find_path", {"addr": fun(X(0)), "to": "FUN_0000dead"}).error == "bilinmeyen_adres"
    assert call(gws, "find_path", {"addr": fun(X(0)), "to": fun(X(4)), "max_depth": 7}).error == "gecersiz_arguman"


def test_yol_tavani_kirpmayi_soyler(gws):
    r = call(gws, "find_path", {"addr": fun(X(0)), "to": fun(X(20))})
    d = r.data
    assert d["length"] == 2 and d["paths_total"] == 5 and len(d["paths"]) == T.PATH_MAX_PATHS == 3
    assert [p[1] for p in d["paths"]] == [fun(X(40)), fun(X(41)), fun(X(42))]
    assert r.truncated == {"omitted": 2, "total": 5}


# --------------------------------------------------------------------------------------------
# (d) R1 find_refs + ters dizin

def refs(ws, target, value, **kw) -> T.ToolResult:
    return call(ws, "find_refs", {"target": target, "value": value, **kw})


def test_refs_ithal_ve_evidence_ile_ayni(ws):
    r = refs(ws, "import", "malloc")
    assert r.ok and r.kind == "olgu" and r.data["value"] == "malloc" and r.data["total"] == 1
    assert r.data["items"] == [{"addr": fun(A), "name_tag": "[unverified: run_main]", "calls": 1}]
    # Mach-O yazımı (baştaki alt çizgiler) aynı ada iner; get_evidence.apis ile aynı kural.
    assert refs(ws, "import", "__malloc").data["items"] == r.data["items"]
    assert set(touched_refs(r.envelope())) == {fun(A)}
    for name in ("malloc", "signal"):
        beklenen = {fun(a) for a, p in ws.packs.items() if name in p.apis}
        assert {i["addr"] for i in refs(ws, "import", name).data["items"]} == beklenen
    # İkilinin ithal etmediği ad: uydurma liste değil, geçersiz çağrı.
    for yok in ("free", "mallo", "MALLOC", "FUN_00001000", "_"):
        assert refs(ws, "import", yok).error == "bilinmeyen_ad"
    assert "bilinmeyen_ad" in T.INVALID_CALL_ERRORS


def test_refs_ithal_cagri_sayisi(tmp_path):
    """Ghidra'nın çağrı listesinde aynı ithal iki kez; ayrıca adı farklı ama adresi thunk olan bir çağrı
    (get_evidence bunu ``PTR_write`` adıyla ``apis``'e yazar: find_refs aynı adı tanımalı)."""
    root = build_ws(tmp_path / "w", {X(1): {"calls": []}, X(2): {"calls": []}}, imports={X(9): "_write"})
    xp = root / "static" / "ghidra_xrefs.json"
    x = json.loads(xp.read_text())
    x["function_xrefs"][X(1)]["functions_called"] = [{"name": "_write", "address": X(9)}] * 2
    x["function_xrefs"][X(2)]["functions_called"] = [{"name": "PTR_write", "address": X(9)}]
    xp.write_text(json.dumps(x), encoding="utf-8")
    ws = T.Workspace(root)
    assert refs(ws, "import", "write").data["items"] == [{"addr": fun(X(1)), "name_tag": None, "calls": 2}]
    assert ws.packs[X(1)].api_counts == {"write": 2}
    assert ws.packs[X(2)].apis == ["PTR_write"]
    assert refs(ws, "import", "PTR_write").data["items"] == [{"addr": fun(X(2)), "name_tag": None, "calls": 1}]


def test_refs_ithal_cagirani_yoksa_bos_liste(tmp_path):
    root = build_ws(tmp_path / "w", {X(1): {"calls": []}}, imports={X(9): "_unused_import"})
    r = refs(T.Workspace(root), "import", "unused_import")
    assert r.ok and r.data["items"] == [] and r.data["total"] == 0 and r.truncated is None


def test_refs_dizgi_duz_alt_dizgi_harf_duyarli(ws):
    r = refs(ws, "string", "usage")
    assert r.ok and [i["addr"] for i in r.data["items"]] == [fun(A)]
    assert r.data["items"][0]["matches"] == ["usage: %s <file>"] and r.data["items"][0]["matches_total"] == 1
    assert refs(ws, "string", "USAGE").data["total"] == 0
    assert [i["addr"] for i in refs(ws, "string", 'd "q').data["items"]] == [fun(A)]
    # Düzenli ifade değil: özel karakterler harfiyen aranır; felaket geri izleme deseni anında 0 döner.
    assert refs(ws, "string", "(a+)+$").data["total"] == 0
    assert refs(ws, "string", "%s <").data["total"] == 1
    hub = refs(ws, "string", "dizgi").data["items"]
    assert [i["addr"] for i in hub] == [fun(HUB)] and hub[0]["matches_total"] == 50
    assert len(hub[0]["matches"]) == T.FIND_REFS_MATCHES_PER_ROW
    assert hub[0]["matches"][0] == "dizgi 0 " + "x" * 112 + "…[+18]"   # 138 karakter → 120 + kırpma eki
    for kisa in ("us", "", "x" * 65):
        assert refs(ws, "string", kisa).error == "gecersiz_arguman"
    assert refs(ws, "string", "x" * 129).error == "gecersiz_arguman"   # şema tavanı


def test_refs_sayfalama(tmp_path):
    funcs = {X(i): {"calls": [], "strings": [f"ortak dizgi {i}"]} for i in range(40)}
    ws = T.Workspace(build_ws(tmp_path / "s", funcs))
    r = refs(ws, "string", "ortak dizgi")
    assert r.data["total"] == 40 and len(r.data["items"]) == T.FIND_REFS_MAX_ROWS == 30
    assert r.truncated == {"omitted": 10, "total": 40}
    r2 = refs(ws, "string", "ortak dizgi", offset=30)
    assert [i["addr"] for i in r2.data["items"]] == [fun(X(i)) for i in range(30, 40)] and r2.data["offset"] == 30
    assert r.size_bytes() <= T.FIND_REFS_RESULT_MAX_BYTES


def test_refs_ters_dizin_bir_kez_kurulur_bayatligi_denetlenir(root):
    ws = T.Workspace(root)
    for _ in range(3):
        assert refs(ws, "import", "malloc").data["total"] == 1
        assert refs(ws, "string", "usage").data["total"] == 1
    assert ws._cache["reverse_index_builds"] == 1
    # ghidra_xrefs.json değişti (yeni bir malloc çağıranı): dizin yeniden kurulur, yeni veri görünür.
    xp = root / "static" / "ghidra_xrefs.json"
    x = json.loads(xp.read_text())
    x["function_xrefs"][B]["functions_called"].append({"name": "malloc", "address": MALLOC})
    xp.write_text(json.dumps(x), encoding="utf-8")
    assert [i["addr"] for i in refs(ws, "import", "malloc").data["items"]] == [fun(A), fun(B)]
    assert ws._cache["reverse_index_builds"] == 2
    # ghidra_functions.json değişti: çalışma alanının adres tablosu bayat; dizin kurulmaz.
    fp = root / "static" / "ghidra_functions.json"
    fp.write_text(fp.read_text() + " ", encoding="utf-8")
    assert refs(ws, "import", "malloc").error == "veri_bayat"
    assert T.Workspace(root).reverse_index() is not None   # yeni oturum yeniden açar
    xp.unlink()
    assert refs(T.Workspace(root), "import", "malloc").error == "veri_yok"


# --------------------------------------------------------------------------------------------
# (e) O11 search_code

def search(ws, text, **kw) -> T.ToolResult:
    return call(ws, "search_code", {"text": text, **kw})


def test_arama_satir_no_get_decompiled_ile_ayni(ws):
    r = search(ws, "malloc")
    assert r.ok and r.kind == "vekil" and r.source == "static/ghidra_output/decompiled"
    assert r.data["items"] == [{"addr": fun(A), "line_no": 5, "line": "p = malloc(0x20);"}]
    assert (r.data["total"], r.data["functions"]) == (1, 1) and r.truncated is None
    dec = call(ws, "get_decompiled", {"addr": fun(A), "part": "aralik", "line_from": 5, "line_to": 5})
    assert dec.data["code"].strip() == "p = malloc(0x20);"
    assert set(touched_refs(r.envelope())) == {fun(A)}
    assert r.data["functions_total"] == r.data["scanned_functions"] == len(ws.program_addresses())


def test_arama_duz_metin_harf_duyarli_baslik_disi(ws):
    assert search(ws, "MALLOC").data["total"] == 0
    assert search(ws, "Address:").data["total"] == 0          # Karadul başlığı aranmaz
    assert search(ws, "(0x20)").data["total"] == 1             # parantez harfiyen
    assert search(ws, "p = .*").data["total"] == 0             # düzenli ifade değil
    assert search(ws, "(a+)+$").data["total"] == 0
    for bozuk in ("ab", "x" * 65, "mal\nloc"):
        assert search(ws, bozuk).error == "gecersiz_arguman"


def test_arama_tavan_ve_limit(ws):
    r = search(ws, "param_1 +")
    assert r.data["total"] == 400 and r.data["functions"] == 1 and len(r.data["items"]) == T.SEARCH_MAX_ROWS
    assert r.truncated == {"omitted": 380, "total": 400}
    assert [i["line_no"] for i in r.data["items"]] == list(range(4, 24))
    assert len(search(ws, "param_1 +", limit=5).data["items"]) == 5
    assert search(ws, "param_1 +", limit=21).error == "gecersiz_arguman"
    assert r.size_bytes() <= T.SEARCH_RESULT_MAX_BYTES


def test_arama_uzun_satir_penceresi_ve_hiz(tmp_path):
    uzun = "a" * 300 + " NEEDLE " + "b" * 300
    dev = "a" * 200_000
    root = build_ws(tmp_path / "u", {X(1): {"code": body(X(1), [uzun])}, X(2): {"code": body(X(2), [dev])}})
    ws = T.Workspace(root)
    row = search(ws, "NEEDLE").data["items"][0]
    assert row["cut"] is True and "NEEDLE" in row["line"]
    assert row["line"].startswith("…") and row["line"].endswith("…")
    assert len(row["line"]) == T.SEARCH_LINE_MAX_CHARS + 2
    kisa = search(ws, "return").data["items"][0]
    assert "cut" not in kisa and kisa["line"] == "return;"
    # Aynı dosyada iki yazım: yalnız harfi harfine tutan satır sayılır.
    root2 = build_ws(tmp_path / "h", {X(3): {"code": body(X(3), ["Foo_bar();", "foo_bar();"])}})
    h = search(T.Workspace(root2), "Foo_bar").data
    assert h["total"] == 1 and h["items"][0]["line"] == "Foo_bar();"
    import time
    t0 = time.perf_counter()
    assert search(ws, "a" * 63 + "b").data["total"] == 0
    assert time.perf_counter() - t0 < 1.0


def test_arama_tarama_butcesi_durunca_soyler(ws, monkeypatch):
    boyutlar = sorted(p.stat().st_size for p in ws.code_files.values())
    monkeypatch.setattr(RM, "SEARCH_SCAN_MAX_BYTES", sum(boyutlar[:3]))
    r = search(ws, "return")
    assert r.truncated["scan_stopped"] is True
    assert r.data["scanned_functions"] < r.data["functions_total"]


def test_refs_korluk(ws):
    r = refs(ws, "import", "malloc", )
    kor = call(ws, "find_refs", {"target": "import", "value": "malloc"}, blind_target=A)
    assert r.data["items"][0]["name_tag"] == "[unverified: run_main]" and kor.data["items"][0]["name_tag"] is None
