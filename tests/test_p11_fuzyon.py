"""P11 / TIP-02 + BORU-03: füzyon adres anahtarlı, tek adayda birleşir, ölçülmüş kesinlik.

Eskiden imza kanıtı ``original_name`` (ad), CFG kanıtı adresle anahtarlanıyordu
(kesişim 0); her aday ayrı puanlanıyordu; tek kanıtlı en iyi aday sabit
ağırlıklarla 0,182 olasılık alıyordu (eşik 0,90); CFG adayında
``cfg_hash`` = ``reference_cfg_hash`` = şablon adı (totoloji).
"""

from __future__ import annotations

import json
from types import SimpleNamespace

from karadul.analyzers.signature_db import SignatureMatch
from karadul.computation.config import ComputationConfig
from karadul.computation.fusion import measured as fm
from karadul.computation.kol_durumu import CALISTI, KAPALI, STAT_FUZYON
from karadul.pipeline.steps import computation_fusion as cf

OLCUM_TABLOSU_TEST = {
    "imza:string_ref": {"n": 132, "dogru": 0, "wilson_alt": 0.0},
    "imza:byte_pattern": {"n": 50, "dogru": 49, "wilson_alt": 0.91},
    "cfg_iso:gercek_kod": {"n": 40, "dogru": 38, "wilson_alt": 0.84},
}


def _sig(addr: str, name: str, method: str, original: str = None, conf: float = 0.95):
    return SignatureMatch(original_name=original or f"FUN_{addr}", matched_name=name,
                          library="x", confidence=conf, match_method=method, address=addr)


def _cfgm(name: str, conf: float = 0.95, source: str = "gercek_kod"):
    return SimpleNamespace(template_name=name, confidence=conf, match_type="exact",
                           reasons=[], family="generic", template_source=source)


def test_iki_kaynak_ayni_adreste_tek_adayda_birlesir():
    kan = cf.collect_evidence(
        [_sig("00104000", "hash_insert", "byte_pattern")],
        {"00104000": _cfgm("hash_insert")},
    )
    out = fm.fuse_by_address(kan, OLCUM_TABLOSU_TEST)
    assert list(out) == ["00104000"]
    assert len(out["00104000"]) == 1
    a = out["00104000"][0]
    assert a.name == "hash_insert"
    assert sorted(a.sources) == ["cfg_iso:gercek_kod", "imza:byte_pattern"]


def test_olasilik_olculmus_alt_sinirdan_bagimsizlik_varsayilmaz():
    kan = cf.collect_evidence(
        [_sig("00104000", "hash_insert", "byte_pattern")],
        {"00104000": _cfgm("hash_insert")},
    )
    a = fm.fuse_by_address(kan, OLCUM_TABLOSU_TEST)["00104000"][0]
    assert a.probability == 0.91          # max(0,91; 0,84), çarpım değil
    assert a.decision == "accept"


def test_olcumu_sifir_kaynak_reddedilir():
    kan = cf.collect_evidence([_sig("00104000", "read_env_var", "string_ref", conf=0.79)], {})
    a = fm.fuse_by_address(kan, OLCUM_TABLOSU_TEST)["00104000"][0]
    assert a.probability == 0.0 and a.decision == "reject"


def test_olculmemis_kaynak_cekimser_ve_olasilik_yok():
    kan = cf.collect_evidence([_sig("00104000", "foo", "call_pattern")], {})
    a = fm.fuse_by_address(kan, OLCUM_TABLOSU_TEST)["00104000"][0]
    assert a.probability is None and a.decision == "abstain"
    assert "ölçülmemiş" in a.reason


def test_celisen_kabul_adlari_cekimser():
    kan = cf.collect_evidence(
        [_sig("00104000", "hash_insert", "byte_pattern")],
        {"00104000": _cfgm("hash_lookup")},
    )
    out = fm.fuse_by_address(kan, OLCUM_TABLOSU_TEST)["00104000"]
    assert {a.name for a in out} == {"hash_insert", "hash_lookup"}
    assert all(a.decision == "abstain" for a in out)


def test_adli_fonksiyon_ve_adressiz_imza_aday_degil():
    kan = cf.collect_evidence(
        [_sig("00104000", "getcwd", "symbol", original="getcwd"),
         SignatureMatch(original_name="FUN_1", matched_name="x", library="", confidence=1.0,
                        match_method="byte_pattern")],
        {},
    )
    assert kan == {}


def test_adres_bicimi_birlesir():
    kan = cf.collect_evidence([_sig("0x104000", "a", "byte_pattern")], {"00104000": _cfgm("a")})
    assert list(kan) == ["00104000"]


def _ctx(tmp_path, sig, cfgm, **comp):
    c = ComputationConfig(**comp)
    pc = SimpleNamespace(config=SimpleNamespace(computation=c),
                         workspace=SimpleNamespace(get_stage_dir=lambda _n: tmp_path))
    return SimpleNamespace(pipeline_context=pc, stats={}, errors=[],
                           artifacts={"sig_matches": sig, "cfg_iso_matches": cfgm})


def test_adim_bayrak_kapali(tmp_path):
    ctx = _ctx(tmp_path, [], {}, enable_computation_fusion=False)
    out = cf.ComputationFusionStep().run(ctx)
    assert out["fused_matches"] == {} and out["fusion_name_candidates"] == []
    assert ctx.stats[STAT_FUZYON]["durum"] == KAPALI


def test_adim_aday_yapiti_ad_kanalina_bagli_degil(tmp_path, monkeypatch):
    monkeypatch.setattr(fm, "load_measured_precision", lambda _p=None: dict(OLCUM_TABLOSU_TEST))
    ctx = _ctx(tmp_path, [_sig("00104000", "hash_insert", "byte_pattern")],
               {"00104000": _cfgm("hash_insert")})
    out = cf.ComputationFusionStep().run(ctx)
    d = ctx.stats[STAT_FUZYON]
    assert d["durum"] == CALISTI and d["cikti"] == "bagli_degil"
    assert d["iki_kaynakli_adres"] == 1 and d["kabul"] == 1
    # öntanımda ad kanalına giden yapıt BOŞ (K-1); aday dosyası yazılır
    assert out["fusion_name_candidates"] == []
    kayit = json.loads((tmp_path / cf.CANDIDATES_FILE).read_text(encoding="utf-8"))
    assert kayit["adaylar"][0]["ad"] == "hash_insert" and kayit["ad_kanalina_bagli"] is False


def test_adim_bayrakla_ad_adayi(tmp_path, monkeypatch):
    monkeypatch.setattr(fm, "load_measured_precision", lambda _p=None: dict(OLCUM_TABLOSU_TEST))
    ctx = _ctx(tmp_path, [_sig("00104000", "hash_insert", "byte_pattern")], {},
               enable_fusion_naming=True)
    out = cf.ComputationFusionStep().run(ctx)
    assert ctx.stats[STAT_FUZYON]["cikti"] == "ad_adayi"
    assert out["fusion_name_candidates"] == [
        {"address": "00104000", "name": "hash_insert", "probability": 0.91,
         "sources": ["imza:byte_pattern"]}]


def test_varsayilan_tablo_depoda_ve_kokenli():
    t = fm.load_measured_precision()
    assert t["imza:string_ref"]["dogru"] == 0 and t["imza:string_ref"]["n"] > 0
    assert "_kaynak" in fm.load_measured_precision_document()


def test_cfg_adayinda_totoloji_yok():
    # Eski kodda cfg_hash = reference_cfg_hash = şablon adı → benzerlik hep 1,0.
    kan = cf.collect_evidence([], {"00104000": _cfgm("x")})
    e = kan["00104000"][0]
    assert e.source == "cfg_iso:gercek_kod" and not hasattr(e, "cfg_hash")
