"""P11 / TIP-01: CFG-iso düğüm histogramı gerçek komut adlarından; dürüst durum; süreç içi VF2.

Eski kod düğüme ``{"instr": komut sayısı}`` veriyordu; şablonlar gerçek komut
adı taşıdığından WL renkleri ayrışıyor ve LSH hiç aday döndürmüyordu (aynı
topolojide bile). Veriler ``cfg.json`` biçiminde kurulur (Ghidra dökümü:
``blocks[].mnemonics``).
"""

from __future__ import annotations

import json
import time
from collections import Counter
from types import SimpleNamespace

import pytest

from karadul.computation.cfg_iso import HybridCFGMatcher
from karadul.computation.cfg_iso.template_db import AlgorithmTemplate
from karadul.computation.kol_durumu import (
    CALISTI, DESTEKLENMIYOR, KAPALI, STAT_CFG_ISO,
)
from karadul.config import ComputationRecoveryConfig
from karadul.pipeline.steps import cfg_iso_match as cim

# AArch64 benzeri komut adlarıyla 5 bloklu bir döngü (gerçek dökümdeki biçim).
FN = {
    "name": "FUN_00104000",
    "address": "00104000",
    "blocks": [
        {"start_address": "00104000", "instruction_count": 4,
         "mnemonics": ["stp", "mov", "cbz", "ldr"]},
        {"start_address": "00104010", "instruction_count": 3,
         "mnemonics": ["ldr", "cmp", "b.eq"]},
        {"start_address": "0010401c", "instruction_count": 3,
         "mnemonics": ["add", "str", "b"]},
        {"start_address": "00104028", "instruction_count": 2,
         "mnemonics": ["ldr", "cbnz"]},
        {"start_address": "00104030", "instruction_count": 2,
         "mnemonics": ["ldp", "ret"]},
    ],
    "edges": [
        {"from_block": "00104000", "to_block": "00104010"},
        {"from_block": "00104000", "to_block": "00104030"},
        {"from_block": "00104010", "to_block": "0010401c"},
        {"from_block": "00104010", "to_block": "00104028"},
        {"from_block": "0010401c", "to_block": "00104028"},
        {"from_block": "00104028", "to_block": "00104010"},
        {"from_block": "00104028", "to_block": "00104030"},
    ],
}


def _cfg_json(tmp_path, functions):
    p = tmp_path / "cfg.json"
    p.write_text(json.dumps({"functions": functions}), encoding="utf-8")
    return p


def _fn_obj(fn: dict, with_mnemonics: bool = False):
    """``cfg_result`` içindeki FunctionCFG gibi (``cfg_analyzer`` komut adını taşımaz)."""
    blocks = [SimpleNamespace(start_address=b["start_address"],
                              instruction_count=b["instruction_count"],
                              **({"mnemonics": b["mnemonics"]} if with_mnemonics else {}))
              for b in fn["blocks"]]
    edges = [SimpleNamespace(**e) for e in fn["edges"]]
    return SimpleNamespace(name=fn["name"], address=fn["address"], blocks=blocks, edges=edges)


def _template_from(fn: dict, name: str = "gercek_sablon") -> AlgorithmTemplate:
    cfg = cim.attributed_cfg(fn, None)
    return AlgorithmTemplate(name=name, cfg=cfg, source="gercek_kod")


def _ctx(cfg_json, functions, flag: bool = True):
    crc = ComputationRecoveryConfig()
    crc.enable_cfg_iso = flag
    pc = SimpleNamespace(config=SimpleNamespace(computation_recovery=crc))
    cfg_result = SimpleNamespace(functions=[_fn_obj(f) for f in functions])
    return SimpleNamespace(pipeline_context=pc, stats={}, errors=[],
                           artifacts={"cfg_result": cfg_result, "cfg_json_path": cfg_json})


def test_dokum_okunur_dokumsuz_blok_girmez(tmp_path):
    eski = {"address": "00105000", "blocks": [{"start_address": "00105000", "instruction_count": 3}]}
    m = cim.load_block_mnemonics(_cfg_json(tmp_path, [FN, eski]))
    assert set(m) == {"00104000"}
    assert m["00104000"]["00104010"] == ["ldr", "cmp", "b.eq"]


def test_histogram_gercek_komut_adlarindan():
    cfg = cim.attributed_cfg(_fn_obj(FN), {b["start_address"]: b["mnemonics"] for b in FN["blocks"]})
    hist = {n.id: n.mnemonic_histogram for n in cfg.nodes}
    assert hist["00104010"] == {"ldr": 1, "cmp": 1, "b.eq": 1}
    assert all("instr" not in h for h in hist.values())
    assert [n.id for n in cfg.nodes if n.is_entry] == ["00104000"]
    assert [n.id for n in cfg.nodes if n.is_exit] == ["00104030"]


def test_dokumsuz_blokta_sahte_histogram_kurulmaz():
    assert cim.attributed_cfg(_fn_obj(FN), None) is None


def test_gercek_koddan_sablon_kendini_bulur_eski_sorgu_bulamaz():
    tmpl = _template_from(FN)
    m = HybridCFGMatcher(ComputationRecoveryConfig(), [tmpl])
    yeni = cim.attributed_cfg(_fn_obj(FN, with_mnemonics=True), None)
    sonuc = m.match(yeni)
    assert sonuc and sonuc[0].template_name == "gercek_sablon"
    assert sonuc[0].confidence >= 0.9
    # Eski adımın sorgusu: {"instr": N} — aynı topolojide aday yok (TIP-01).
    eski = cim.attributed_cfg(_fn_obj(FN), None) or yeni
    for n, b in zip(eski.nodes, FN["blocks"]):
        n.mnemonic_histogram = {"instr": b["instruction_count"]}
    assert m.match(eski) == []


def test_adim_bayrak_kapali(tmp_path):
    ctx = _ctx(_cfg_json(tmp_path, [FN]), [FN], flag=False)
    out = cim.CFGIsoMatchStep().run(ctx)
    assert out["cfg_iso_matches"] == {}
    assert ctx.stats[STAT_CFG_ISO]["durum"] == KAPALI


def test_adim_dokum_yoksa_desteklenmiyor(tmp_path):
    eski = dict(FN, blocks=[{k: v for k, v in b.items() if k != "mnemonics"} for b in FN["blocks"]])
    ctx = _ctx(_cfg_json(tmp_path, [eski]), [eski])
    cim.CFGIsoMatchStep().run(ctx)
    d = ctx.stats[STAT_CFG_ISO]
    assert d["durum"] == DESTEKLENMIYOR and "döküm" in d["neden"]
    assert d["dokumsuz_fonksiyon"] == 1
    assert "cfg_iso_matched_functions" not in ctx.stats   # "çalıştı, 0" yazılmaz


def test_adim_sentetik_bankayla_desteklenmiyor(tmp_path):
    ctx = _ctx(_cfg_json(tmp_path, [FN]), [FN])
    out = cim.CFGIsoMatchStep().run(ctx)
    d = ctx.stats[STAT_CFG_ISO]
    assert out["cfg_iso_matches"] == {}
    assert d["durum"] == DESTEKLENMIYOR and "şablon düğümü" in d["neden"]
    assert d["uyumlu_fonksiyon"] == 0
    assert d["banka"] == {"elle_x86_sentetik": 8, "json_sentetik": 307}


def test_adim_gercek_sablonla_calisti_adres_anahtari(tmp_path, monkeypatch):
    import karadul.computation.cfg_iso as pkg
    monkeypatch.setattr(pkg, "default_template_bank", lambda: [_template_from(FN)])
    ctx = _ctx(_cfg_json(tmp_path, [FN]), [FN])
    out = cim.CFGIsoMatchStep().run(ctx)
    d = ctx.stats[STAT_CFG_ISO]
    assert d["durum"] == CALISTI and d["eslesen"] == 1 and d["cikti"] == "fuzyon_girdisi"
    assert list(out["cfg_iso_matches"]) == ["00104000"]
    assert out["cfg_iso_matches"]["00104000"].template_source == "gercek_kod"
    assert d["banka"] == {"gercek_kod": 1}


def test_adim_fonksiyon_hatasi_sayilir(tmp_path, monkeypatch):
    import karadul.computation.cfg_iso as pkg
    monkeypatch.setattr(pkg, "default_template_bank", lambda: [_template_from(FN)])

    def _patla(self, cfg, top_k=None):
        raise RuntimeError("bozuk")
    monkeypatch.setattr(HybridCFGMatcher, "match", _patla)
    ctx = _ctx(_cfg_json(tmp_path, [FN]), [FN])
    cim.CFGIsoMatchStep().run(ctx)
    d = ctx.stats[STAT_CFG_ISO]
    assert d["durum"] == CALISTI and d["fonksiyon_hatasi"] == 1 and d["eslesen"] == 0


def test_vf2_surec_acmaz(monkeypatch):
    import multiprocessing

    from karadul.computation.cfg_iso import vf2_matcher

    def _yasak(*a, **k):
        raise AssertionError("VF2 süreç açtı")
    monkeypatch.setattr(multiprocessing, "get_context", _yasak)
    cfg = cim.attributed_cfg(_fn_obj(FN, with_mnemonics=True), None)
    assert vf2_matcher.vf2_match_with_timeout(cfg, cfg, timeout_s=5.0) == (True, False)


def test_vf2_sure_siniri_sureci_icinde_keser():
    from karadul.computation.cfg_iso import vf2_matcher
    from karadul.computation.cfg_iso.fingerprint import AttributedCFG, CFGNode

    # Tam yönlü 9 düğüm ↔ bir kenarı eksik tam 8 düğüm: çözüm yok, ama eksik
    # kenar ancak iki ucu da eşlenince fark edilir; arama ağacı büyük.
    big = AttributedCFG(
        nodes=[CFGNode(id=f"n{i}", mnemonic_histogram={"mov": 1}) for i in range(9)],
        edges=[(f"n{i}", f"n{j}") for i in range(9) for j in range(9) if i != j])
    pat = AttributedCFG(
        nodes=[CFGNode(id=f"p{i}", mnemonic_histogram={"mov": 1}) for i in range(8)],
        edges=[(f"p{i}", f"p{j}") for i in range(8) for j in range(8)
               if i != j and (i, j) != (0, 1)])
    yavas_sayac = Counter()

    def yavas(a, b):
        yavas_sayac["c"] += 1
        time.sleep(0.002)
        return True
    t0 = time.monotonic()
    sonuc = vf2_matcher.vf2_match_with_timeout(big, pat, node_match_fn=yavas, timeout_s=0.05)
    gecen = time.monotonic() - t0
    assert sonuc == (False, True)
    assert gecen < 1.0
    n = yavas_sayac["c"]
    time.sleep(0.05)
    assert yavas_sayac["c"] == n   # arka planda süren arama yok


@pytest.mark.parametrize("anahtar", ["elle_x86_sentetik", "json_sentetik"])
def test_banka_kaynagi_etiketli(anahtar):
    from karadul.computation.cfg_iso import default_template_bank
    assert anahtar in cim.bank_composition(default_template_bank())
