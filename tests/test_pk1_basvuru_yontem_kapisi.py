"""PK-1 — var olan başvuru yollarına yöntem kapısı (KARARLAR A-2, A-13, A-25, A-30).

Sorun (KİMLİK O1): ``BinaryDiffer`` (``reference_binary`` / ``ref_db``) ve ``ReferenceDiffer`` her
eşleşmeyi ad olarak yazıyordu; ``_add_refdiff`` her ada sabit 0,95 güven basıyordu. Ölçülmüş tam ad
kesinliği yöntemden yönteme 0,15 ile 0,96 arası (``kimlik/BULGULAR.md`` §2.2).

Kural: Wilson %95 alt sınırı ≥ ``AD_ESIGI`` (10 / 11) olan yöntem ad yazar; kalan kanıt satırı
(``reference_evidence``). Güven = yöntemin ölçülmüş alt sınırı.

Mutasyon koruması: ``scripts/measurement/mutation_specs_pk1.json``.
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from karadul.analyzers.bindiff import BinaryDiffer, DiffMatch, DiffResult
from karadul.config import Config
from karadul.core.naming_labels import AD_ESIGI
from karadul.pipeline.steps import _feedback_naming_bindiff as FB
from karadul.pipeline.steps import _feedback_naming_candidates as FC
from karadul.pipeline.steps import _feedback_naming_refdiff as FR
from karadul.reconstruction import reference_differ as RD
from karadul.reconstruction.kimlik import yontem_kapisi as K
from karadul.reconstruction.tarif import baglama

_KOK = Path(__file__).resolve().parents[1]
_ON_KAYIT = _KOK / "docs" / "arge" / "2026-11-19_mythos" / "kimlik" / "PK-1_on_kayit.md"

# Ön kayıttaki (plan PK-1) "TÜM GRUPLAR" satırları: yöntem → (doğru, ad verilen, Wilson alt, 3 basamak)
ON_KAYIT = {
    "string_refs": (414, 438, 0.920),
    "string_fingerprint": (476, 494, 0.943),
    "call_pattern": (222, 283, 0.733),
    "cfg_fingerprint": (445, 584, 0.726),
    "size_params": (99, 540, 0.153),
    "cfg_similarity": (1529, 2748, 0.538),
    "size_constant": (43, 157, 0.210),
    "call_propagation": (8, 16, 0.280),
}


def _betik_wilson():
    """Ölçüm betiğinin Wilson'u (``scripts/measurement/macho_f1.py``; ürün kodundan bağımsız)."""
    path = _KOK / "scripts" / "measurement" / "macho_f1.py"
    spec = importlib.util.spec_from_file_location("macho_f1_pk1", path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod.wilson_interval


# ---------------------------------------------------------------------------
# (a) Tablo ve kapı
# ---------------------------------------------------------------------------


def test_tablo_on_kayitla_ve_betigin_wilsonuyla_ayni():
    assert {k: v[:2] for k, v in K.OLCULMUS_YONTEM.items()} == {k: v[:2] for k, v in ON_KAYIT.items()}
    wilson_interval = _betik_wilson()
    metin = _ON_KAYIT.read_text(encoding="utf-8")
    for yontem, (d, n, alt3) in ON_KAYIT.items():
        betik_alt = wilson_interval(d, n)[0]
        assert round(betik_alt, 3) == alt3, yontem
        # üründeki değer 4 basamağa aşağı yuvarlanmış: betiğin değerinden yüksek değil
        urun_alt = K.olculmus_alt(yontem)
        assert urun_alt <= round(betik_alt, 4) + 1e-12, yontem
        assert abs(urun_alt - baglama.wilson(d, n)[0]) < 1e-4, yontem
        # ön kayıt metninde sayılar geçiyor (Türkçe yazım: binlik ayırıcı boşluk)
        d_s = f"{d:,}".replace(",", " ")
        n_s = f"{n:,}".replace(",", " ")
        assert f"`{yontem}` {d_s} / {n_s} ({alt3:.3f}".replace(".", ",") in metin, yontem


def test_ad_verebilir_yalniz_iki_dizgi_yontemi():
    assert K.ad_veren_yontemler() == ("string_fingerprint", "string_refs")
    for yontem in ON_KAYIT:
        beklenen = yontem in ("string_refs", "string_fingerprint")
        assert K.ad_verebilir(yontem) is beklenen, yontem
    # eşik naming_labels'tan (kesir); kendi sabiti yok
    assert K.AD_ESIGI is AD_ESIGI
    assert AD_ESIGI == 10 / 11


def test_tablo_disi_yontem_ad_veremez():
    for yontem in ("decompiled_hash", "bilinmeyen", "", None):
        assert K.ad_verebilir(yontem) is False, yontem
        assert K.olculmus_alt(yontem) is None, yontem
    assert K.red_nedeni("decompiled_hash") == K.NEDEN_OLCULMEMIS
    assert K.red_nedeni("size_params") == K.NEDEN_YONTEM_KAPISI


def test_esik_karsilastirmasi_yuvarlamasiz(monkeypatch):
    # string_refs'in alt sınırı 0,9197…; eşik bunun hemen üstüne çekilince kapı kapanmalı
    ham = baglama.wilson(414, 438)[0]
    monkeypatch.setattr(K, "AD_ESIGI", ham + 1e-9)
    assert K.ad_verebilir("string_refs") is False
    monkeypatch.setattr(K, "AD_ESIGI", ham)
    assert K.ad_verebilir("string_refs") is True


# ---------------------------------------------------------------------------
# (b) _config_source / _refdb_source / _match_against_db
# ---------------------------------------------------------------------------


def _pc(tmp_path: Path, **br) -> SimpleNamespace:
    cfg = Config()
    for k, v in br.items():
        setattr(cfg.binary_reconstruction, k, v)
    ws = SimpleNamespace(get_stage_dir=lambda name: tmp_path / "ws" / name)
    return SimpleNamespace(config=cfg, workspace=ws)


def _match(t: str, r: str, conf: float, method: str, addr: str) -> DiffMatch:
    return DiffMatch(ref_name=r, ref_address="0x" + addr, target_name=t, target_address="0x" + addr,
                     confidence=conf, method=method)


def _sahte_differ(matches: list[DiffMatch]) -> BinaryDiffer:
    differ = BinaryDiffer()
    differ.compare = lambda **kw: DiffResult(matches=list(matches), matched=len(matches),
                                             match_rate=0.5)
    return differ


def _ref_binary(tmp_path: Path) -> Path:
    d = tmp_path / "ref"
    d.mkdir()
    (d / "ghidra_functions.json").write_text(json.dumps({"functions": []}), encoding="utf-8")
    ref = d / "ref_bin"
    ref.write_bytes(b"\0")
    return ref


MATCHES = [
    _match("FUN_00101000", "parse_args", 0.85, "string_refs", "101000"),
    _match("FUN_00102000", "yanlis_ad", 0.76, "size_params", "102000"),
    _match("FUN_00103000", "cfg_ad", 0.80, "cfg_fingerprint", "103000"),
]


def test_config_source_kapi_ad_ve_kanit(tmp_path):
    pc = _pc(tmp_path, reference_binary=str(_ref_binary(tmp_path)))
    conf_map: dict = {}
    names: dict = {}
    stats: dict = {}
    FB._config_source(pc=pc, differ=_sahte_differ(MATCHES), target_func_data={"functions": [1]},
                      target_str_data=None, bindiff_confidence_map=conf_map,
                      bindiff_names=names, stats=stats)
    assert names == {"FUN_00101000": "parse_args"}
    assert set(conf_map) == {"FUN_00101000"}
    assert "FUN_00102000" not in names and "FUN_00103000" not in names
    kanit = {r["anahtar"]: r for r in stats["bindiff_evidence"]}
    assert set(kanit) == {"FUN_00102000", "FUN_00103000"}
    r = kanit["FUN_00102000"]
    assert r["kaynak"] == "bindiff" and r["ozgun_ad"] == "yanlis_ad"
    assert r["yontem"] == "size_params" and r["nedenler"] == ["yontem_kapisi"]
    assert r["olculmus_alt"] == K.olculmus_alt("size_params")
    assert r["adres"] == "0x102000" and r["basvuru"] == "ref_bin"
    assert stats["bindiff_method_gate"] == {
        "string_refs": {"ad": 1, "kanit": 0},
        "size_params": {"ad": 0, "kanit": 1},
        "cfg_fingerprint": {"ad": 0, "kanit": 1},
    }


def test_olculmemis_yontem_kanit_satiri_olculmemis_nedeniyle(tmp_path):
    pc = _pc(tmp_path, reference_binary=str(_ref_binary(tmp_path)))
    stats: dict = {}
    names: dict = {}
    FB._config_source(pc=pc, differ=_sahte_differ(
        [_match("FUN_00104000", "hash_ad", 0.95, "decompiled_hash", "104000")]),
        target_func_data={"functions": [1]}, target_str_data=None,
        bindiff_confidence_map={}, bindiff_names=names, stats=stats)
    assert names == {}
    (r,) = stats["bindiff_evidence"]
    assert r["nedenler"] == ["olculmemis_yontem"] and r["olculmus_alt"] is None


class _Entry(SimpleNamespace):
    pass


def test_refdb_source_call_pattern_ad_vermez(tmp_path, monkeypatch):
    db = tmp_path / "ref_db"
    db.mkdir()
    fj = db / "f.json"
    fj.write_text(json.dumps({"functions": []}), encoding="utf-8")
    entry = _Entry(library="libx", version="1.0", functions_json=fj, strings_json=None,
                   call_graph_json=None)

    class _DB:
        def __init__(self, path):
            pass

        def all_entries(self):
            return [entry]

    monkeypatch.setattr(RD, "ReferenceDB", _DB)
    pc = _pc(tmp_path, reference_db_path=str(db))
    names: dict = {}
    conf_map: dict = {}
    stats: dict = {}
    FB._refdb_source(pc=pc, differ=_sahte_differ([
        _match("FUN_00105000", "cagri_ad", 0.74, "call_pattern", "105000"),
        _match("FUN_00106000", "dizgi_ad", 0.88, "string_refs", "106000"),
    ]), target_func_data={"functions": [1]}, target_str_data=None,
        call_graph_json=tmp_path / "yok.json", bindiff_confidence_map=conf_map,
        bindiff_names=names, stats=stats)
    assert names == {"FUN_00106000": "dizgi_ad"}
    assert set(conf_map) == {"FUN_00106000"}
    (r,) = stats["bindiff_evidence"]
    assert r["anahtar"] == "FUN_00105000" and r["yontem"] == "call_pattern"
    assert r["basvuru"] == "libx/1.0"


def _rd_sonuc(matches: list) -> RD.ReferenceMatchResult:
    det = RD.Detection(library="libz", version="1.2", confidence=0.9)
    res = RD.ReferenceMatchResult(detection=det, matches=list(matches), matched=len(matches))
    res.naming_map = RD.ReferenceDiffer._build_naming_map(res.matches)
    return res


def _fm(t, r, conf, method, addr):
    return RD.FunctionMatch(ref_name=r, ref_address="0x" + addr, target_name=t,
                            target_address="0x" + addr, confidence=conf, method=method)


def test_match_against_db_kapi(tmp_path, monkeypatch):
    sonuc = _rd_sonuc([
        _fm("FUN_00107000", "inflate", 0.9, "string_fingerprint", "107000"),
        _fm("FUN_00108000", "yanlis", 0.7, "cfg_similarity", "108000"),
        _fm("FUN_00109000", "boyut", 0.6, "size_constant", "109000"),
    ])

    class _Differ:
        def __init__(self, **kw):
            pass

        def match(self, **kw):
            return sonuc

    monkeypatch.setattr(RD, "ReferenceDiffer", _Differ)
    pc = _pc(tmp_path, reference_db_path=str(tmp_path / "db"))
    naming: dict = {}
    stats: dict = {}
    FR._match_against_db(pc=pc, detections=[sonuc.detection], func_data={"functions": []},
                         string_data={}, functions_json=tmp_path / "f.json",
                         call_graph_json=tmp_path / "cg.json", cfg_json=tmp_path / "cfg.json",
                         refdiff_naming=naming, stats=stats)
    assert naming == {"FUN_00107000": "inflate"}
    assert stats["refdiff_methods"] == {"FUN_00107000": "string_fingerprint"}
    kanit = {r["anahtar"]: r for r in stats["refdiff_evidence"]}
    assert set(kanit) == {"FUN_00108000", "FUN_00109000"}
    assert kanit["FUN_00108000"]["kaynak"] == "reference_differ"
    assert kanit["FUN_00108000"]["basvuru"] == "libz/1.2"
    assert stats["refdiff_method_gate"]["cfg_similarity"] == {"ad": 0, "kanit": 1}
    # köken kaydı: c_namer koşmadı → yedek dosya
    yedek = tmp_path / "ws" / "reconstructed" / FB.REFERENCE_EVIDENCE_FALLBACK_FILE
    data = json.loads(yedek.read_text(encoding="utf-8"))
    assert {r["anahtar"] for r in data["reference_evidence"]} == {"FUN_00108000", "FUN_00109000"}


def test_gate_reference_matches_yontem_naming_map_kuralindan():
    # aynı hedefe iki eşleşme: naming_map en yüksek güvenliyi seçer; kapı o eşleşmenin yöntemine bakar
    sonuc = _rd_sonuc([
        _fm("FUN_0010a000", "dizgi", 0.6, "string_fingerprint", "10a000"),
        _fm("FUN_0010a000", "cfg", 0.9, "cfg_similarity", "10a000"),
    ])
    stats: dict = {}
    names, methods, kanit = FR.gate_reference_matches(sonuc, stats=stats)
    assert names == {} and methods == {}
    assert [r["ozgun_ad"] for r in kanit] == ["cfg"]
    assert kanit[0]["yontem"] == "cfg_similarity" and kanit[0]["nedenler"] == ["yontem_kapisi"]
    # ters sıra: sonra gelen daha güvenli dizgi eşleşmesi naming_map'te kazanır → ad yazılır
    sonuc2 = _rd_sonuc([
        _fm("FUN_0010b000", "cfg", 0.7, "cfg_similarity", "10b000"),
        _fm("FUN_0010b000", "dizgi", 0.9, "string_fingerprint", "10b000"),
    ])
    names2, methods2, kanit2 = FR.gate_reference_matches(sonuc2, stats={})
    assert names2 == {"FUN_0010b000": "dizgi"}
    assert methods2 == {"FUN_0010b000": "string_fingerprint"} and kanit2 == []


# ---------------------------------------------------------------------------
# (c) güven: _add_bindiff, _add_refdiff
# ---------------------------------------------------------------------------


def _conf(c):
    return c.get("confidence") if isinstance(c, dict) else c.confidence


def test_add_refdiff_guveni_sabit_095_degil():
    cands: dict = {}
    FC._add_refdiff({"FUN_00107000": "inflate"}, cands)
    (c,) = cands["FUN_00107000"]
    assert _conf(c) != 0.95
    assert _conf(c) == K.olculmus_alt("string_fingerprint")
    assert _conf(c) >= AD_ESIGI


def test_add_refdiff_yontemle_ve_kapi_alti():
    cands: dict = {}
    FC._add_refdiff({"FUN_1": "a", "FUN_2": "b"}, cands,
                    refdiff_methods={"FUN_1": "string_fingerprint", "FUN_2": "size_constant"})
    assert set(cands) == {"FUN_1"}
    assert _conf(cands["FUN_1"][0]) == K.olculmus_alt("string_fingerprint")


def test_add_bindiff_guveni_olculmus_alt_sinir():
    cands: dict = {}
    FC._add_bindiff({
        "FUN_00101000": ("parse_args", 0.80, "string_refs"),
        "FUN_00102000": ("yanlis_ad", 0.76, "size_params"),
        "FUN_00104000": ("hash_ad", 0.95, "decompiled_hash"),
    }, cands)
    assert set(cands) == {"FUN_00101000"}
    (c,) = cands["FUN_00101000"]
    assert _conf(c) == K.olculmus_alt("string_refs") != 0.80
    src = c.get("source") if isinstance(c, dict) else c.source
    assert src == "bindiff_string_refs"


# ---------------------------------------------------------------------------
# (d) korunan ön ad, öntanımlı koşu, köken kaydı
# ---------------------------------------------------------------------------


def test_run_bindiff_korunan_on_adi_ezmez(tmp_path, monkeypatch):
    ref = _ref_binary(tmp_path)
    pc = _pc(tmp_path, reference_binary=str(ref), reference_db_path=str(tmp_path / "yok"))
    ctx = SimpleNamespace(pipeline_context=pc, artifacts={"pre_name_meta": {
        "FUN_00101000": {"kind": baglama.KIND_MAIN, "name": "main"}}})
    monkeypatch.setattr(BinaryDiffer, "compare", lambda self, **kw: DiffResult(matches=[
        _match("FUN_00101000", "parse_args", 0.85, "string_refs", "101000"),
        _match("FUN_00106000", "dizgi_ad", 0.85, "string_refs", "106000"),
        _match("FUN_00102000", "yanlis_ad", 0.76, "size_params", "102000"),
    ]))
    extracted = {"FUN_00101000": "main"}
    names: dict = {}
    stats: dict = {}
    errors: list = []
    FB.run_bindiff(ctx=ctx, func_data={"functions": [1]}, string_data={"strings": []},
                   functions_json=tmp_path / "f.json", strings_json=tmp_path / "s.json",
                   call_graph_json=tmp_path / "cg.json", bindiff_confidence_map={},
                   bindiff_names=names, extracted_names=extracted, stats=stats, errors=errors)
    assert errors == []
    assert extracted == {"FUN_00101000": "main", "FUN_00106000": "dizgi_ad"}
    assert "FUN_00102000" not in extracted
    assert stats["bindiff_protected_pre_names"] == 1


def test_run_bindiff_ontanimli_ayarla_hicbir_sey_yazmaz(tmp_path):
    pc = _pc(tmp_path, reference_db_path=str(tmp_path / "yok"))   # reference_binary boş
    ctx = SimpleNamespace(pipeline_context=pc, artifacts={})
    extracted = {"FUN_1": "x"}
    names: dict = {}
    stats: dict = {}
    FB.run_bindiff(ctx=ctx, func_data={"functions": [1]}, string_data=None,
                   functions_json=tmp_path / "f.json", strings_json=tmp_path / "s.json",
                   call_graph_json=tmp_path / "cg.json", bindiff_confidence_map={},
                   bindiff_names=names, extracted_names=extracted, stats=stats, errors=[])
    assert names == {} and extracted == {"FUN_1": "x"} and stats == {}
    assert not (tmp_path / "ws").exists()


def test_kanit_satiri_naming_provenance_bolumu_ve_oburlerini_korur(tmp_path):
    src = tmp_path / "ws" / "reconstructed" / "src"
    src.mkdir(parents=True)
    prov = src / "naming_provenance.json"
    prov.write_text(json.dumps({"schema": "karadul.naming_provenance", "name_merger": {"x": 1}}),
                    encoding="utf-8")
    pc = _pc(tmp_path)
    stats: dict = {}
    b = K.kanit_satiri(kaynak="bindiff", anahtar="FUN_2", ad="b", yontem="size_params")
    r = K.kanit_satiri(kaynak="reference_differ", anahtar="FUN_3", ad="c", yontem="cfg_similarity")
    FB.write_reference_evidence(pc=pc, kaynak="bindiff", rows=[b], stats=stats)
    FB.write_reference_evidence(pc=pc, kaynak="reference_differ", rows=[r], stats=stats)
    data = json.loads(prov.read_text(encoding="utf-8"))
    assert data["name_merger"] == {"x": 1} and data["schema"] == "karadul.naming_provenance"
    assert [x["kaynak"] for x in data["reference_evidence"]] == ["bindiff", "reference_differ"]
    assert stats["reference_evidence_provenance"] == "yazildi:naming_provenance.json"
    # aynı kaynak yeniden yazılınca eskisi değişir, öbürü kalır
    FB.write_reference_evidence(pc=pc, kaynak="bindiff", rows=[b, b], stats=stats)
    data = json.loads(prov.read_text(encoding="utf-8"))
    assert [x["kaynak"] for x in data["reference_evidence"]] == [
        "bindiff", "bindiff", "reference_differ"]
    # P-ÜV6a ust_veri_kanit satırıyla aynı temel alanlar
    assert {"kaynak", "adres", "ozgun_ad", "nedenler"} <= set(b)


def test_kanit_yoksa_dosyaya_dokunulmaz(tmp_path):
    pc = _pc(tmp_path)
    stats: dict = {}
    FB.write_reference_evidence(pc=pc, kaynak="bindiff", rows=[], stats=stats)
    assert stats == {} and not (tmp_path / "ws").exists()


@pytest.mark.parametrize("yontem", sorted(ON_KAYIT))
def test_kanit_satiri_olculmus_alt(yontem):
    r = K.kanit_satiri(kaynak="bindiff", anahtar="FUN_1", ad="a", yontem=yontem, eslesme_guveni=0.81234)
    assert r["olculmus_alt"] == K.olculmus_alt(yontem)
    assert r["eslesme_guveni"] == 0.8123
