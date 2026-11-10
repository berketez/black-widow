"""c_namer: susturma süzgeci, künyeli ön adlar, ürün eşiği ve güven etiketi (plan v2.2 N1 adım 3).

Kilitlenen davranışlar:
  - öntanımlı kurucuyla ``naming_map.json`` ve ``.c`` çıktıları değişiklik öncesiyle bayt bayt aynı;
  - süzgeç yalnız genel anahtarlarda ve yalnız ``string_context`` adaylarında çalışır; susan
    dizginin yerine başka bir dizgiye geçilmez;
  - ürün eşiği yalnız genel adlara uygulanır, yerel adlar etkilenmez;
  - künyeli ön ad öncelik sırasıyla işlenir, tam ad temizlenmez, "kesin" etiketi yalnız geçerli
    KS-1 künyesinden gelir;
  - her aday anahtarı seçim döngüsünden tam bir kez çıkar (yeni nedenler dahil).

Mutasyon koruması: ``scripts/measurement/mutation_specs_adim3_c_namer.json``.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_c_namer_determinism as T  # noqa: E402

from karadul.config import Config  # noqa: E402
from karadul.core import naming_labels as nl  # noqa: E402
from karadul.reconstruction import c_namer  # noqa: E402
from karadul.reconstruction.c_namer import CVariableNamer  # noqa: E402
from karadul.reconstruction.tarif import alt_kanal, baglama  # noqa: E402

# Değişiklik öncesi (89fd724) c_namer'ın belirlenimcilik fikstüründeki çıktısı: köken kaydı
# dışındaki bütün dosyaların (ad, içerik) sha256'sı. Köken kaydına alan eklendiği için o hariç.
ONCEKI_CIKTI_OZETI = "350c1ef4b0ac46e287350f9dd2dacade7692ce5805ee9725d44c1236a626f8de"
DIZGI_ADLI = ("FUN_00001000", "FUN_00002000", "FUN_00003000", "FUN_00004000", "FUN_00008000",
              "FUN_00009000")


@pytest.fixture
def seri(monkeypatch):
    monkeypatch.setattr(c_namer, "ProcessPoolExecutor", T._SerialExecutor)
    monkeypatch.setattr(c_namer, "_worker_namer", None)


def _kos(ws, out, *, pre_names=None, meta=None, **kurucu):
    namer = CVariableNamer(Config(), min_confidence=0.15, **kurucu)
    res = namer.analyze_and_rename(ws["decompiled"], ws["functions"], ws["strings"], ws["call_graph"],
                                   out, pre_names=pre_names, pre_name_meta=meta)
    assert res.success, res.errors
    prov = json.loads((out / c_namer.NAMING_PROVENANCE_FILE).read_text(encoding="utf-8"))
    harita = json.loads((out / "naming_map.json").read_text(encoding="utf-8"))
    return res, prov, harita


def _ozet(out: Path) -> str:
    h = hashlib.sha256()
    for p in sorted(out.iterdir()):
        if p.is_file() and p.name != c_namer.NAMING_PROVENANCE_FILE:
            h.update(p.name.encode() + b"\0" + p.read_bytes() + b"\0")
    return h.hexdigest()


def _hesap_tutar(prov) -> bool:
    """Her aday anahtarı tam bir kez: ya ad aldı ya bir nedenle elendi."""
    elenen = sum(n for kapsamlar in prov["eliminated_keys"].values()
                 for stratejiler in kapsamlar.values() for n in stratejiler.values())
    s = prov["summary"]
    return s["candidate_keys"] == s["renamed_global"] + s["renamed_local"] + elenen


# --------------------------------------------------------------------------------------------
# Öntanımlı: davranış değişmez


def test_ontanimli_kurucuyla_cikti_bayt_bayt_ayni(tmp_path, seri):
    ws = T.build_workspace(tmp_path / "ws")
    res, prov, harita = _kos(ws, tmp_path / "out")
    assert _ozet(tmp_path / "out") == ONCEKI_CIKTI_OZETI
    assert res.silenced_counts == {} and prov["silencing"]["enabled"] is False
    assert prov["silencing"]["candidates_dropped"] == {} and prov["global_min_confidence"] is None
    assert prov["eliminated_keys"]["all_candidates_silenced"] == {}
    assert prov["eliminated_keys"]["below_global_min_confidence"] == {}
    assert _hesap_tutar(prov)
    # süzgeç kapalıyken de her genel ad etiket taşır ve hiçbiri "kesin" değildir
    assert set(res.label_map) == set(harita["global"])
    assert set(res.label_map.values()) == {nl.LABEL_UNVERIFIED}
    assert prov["summary"]["labels_global"] == {nl.LABEL_UNVERIFIED: len(harita["global"])}
    for anahtar in DIZGI_ADLI:
        assert prov["global"][anahtar]["sub_channel"] == "duz_metin"
        assert prov["global"][anahtar]["label"] == nl.LABEL_UNVERIFIED
    assert "sub_channel" not in prov["global"]["DAT_00011234"]       # yalnız string_context'te
    assert all("label" not in k for f in prov["per_function"].values() for k in f.values())


def test_bos_kume_ve_susmayan_kanal_ciktiyi_degistirmez(tmp_path, seri):
    ws = T.build_workspace(tmp_path / "ws")
    # fikstürdeki bütün dizgi adayları duz_metin; başka bir alt kanalı susturmak hiçbir şeyi atmaz
    res, prov, _ = _kos(ws, tmp_path / "out", silenced_subchannels=frozenset({"agresif", "hata_iletisi"}))
    assert _ozet(tmp_path / "out") == ONCEKI_CIKTI_OZETI
    assert res.silenced_counts == {} and prov["silencing"]["enabled"] is True
    assert prov["silencing"]["silenced"] == ["agresif", "hata_iletisi"]


def test_bilinmeyen_alt_kanal_reddedilir():
    with pytest.raises(ValueError, match="bilinmeyen alt kanal"):
        CVariableNamer(Config(), silenced_subchannels=frozenset({"oz_ad", "uydurma_kanal"}))


# --------------------------------------------------------------------------------------------
# Susturma


def test_susan_alt_kanalin_adaylari_atilir(tmp_path, seri):
    ws = T.build_workspace(tmp_path / "ws")
    taban, taban_prov, taban_harita = _kos(ws, tmp_path / "taban")
    res, prov, harita = _kos(ws, tmp_path / "out", silenced_subchannels=alt_kanal.SILENCED_SUBCHANNELS)
    assert "duz_metin" in alt_kanal.SILENCED_SUBCHANNELS
    # altı dizgi adı gitti; yerlerine yapısal aday (api_call) geçmedi: fonksiyonlar FUN_ kaldı
    for anahtar in DIZGI_ADLI:
        assert anahtar in taban_harita["global"] and anahtar not in harita["global"]
    assert res.silenced_counts == {"duz_metin": 6}
    assert prov["silencing"] == {"enabled": True, "definition_version": alt_kanal.DEFINITION_VERSION,
                                 "silenced": sorted(alt_kanal.SILENCED_SUBCHANNELS),
                                 "candidates_dropped": {"duz_metin": 6}}
    assert "string_context" not in res.by_strategy and taban.by_strategy["string_context"] == 6
    # dizgi dışı adlar ve yerel adlar aynen duruyor
    kalan = {k: v for k, v in taban_harita["global"].items() if k not in DIZGI_ADLI}
    assert harita["global"] == kalan
    assert harita["per_function"] == taban_harita["per_function"]
    assert prov["summary"]["renamed_local"] == taban_prov["summary"]["renamed_local"]
    assert _hesap_tutar(prov) and _hesap_tutar(taban_prov)


def _iki_dizgili(root: Path, dizgiler: list[str], govde_cagrilari: str = "") -> dict[str, Path]:
    """Tek fonksiyon, verilen dizgilere başvuruyor; başka aday üretecek çağrı yok."""
    root.mkdir(parents=True)
    dec = root / "decompiled"
    dec.mkdir()
    ad, adres = "FUN_00001000", "00001000"
    (root / "ghidra_functions.json").write_text(json.dumps({"functions": [
        {"name": ad, "address": adres, "size": 64, "return_type": "undefined", "parameters": []}]}))
    (root / "ghidra_strings.json").write_text(json.dumps({"strings": [
        {"address": f"0002{k:04x}", "value": s, "length": len(s), "type": "string", "function": adres}
        for k, s in enumerate(dizgiler)]}))
    (root / "ghidra_call_graph.json").write_text(json.dumps(
        {"nodes": {adres: {"name": ad, "address": adres}}, "edges": []}))
    (dec / f"{ad}.c").write_text(
        f"// Function: {ad}\n// Address: {adres}\n\nvoid {ad}(void)\n{{\n{govde_cagrilari}  return;\n}}\n")
    return {"functions": root / "ghidra_functions.json", "strings": root / "ghidra_strings.json",
            "call_graph": root / "ghidra_call_graph.json", "decompiled": dec}


def test_susan_dizginin_yerine_sonraki_dizgiye_gecilmez(tmp_path, seri):
    """Strateji yalnız en iyi dizgiyi aday yapar. O aday susunca, aynı fonksiyondaki kalan kanala
    ait (tek başına ad verebilecek) ikinci dizgi denenmez: fonksiyon adsız kalır."""
    tek = _iki_dizgili(tmp_path / "tek", ["sampler_reset"])
    _, tek_prov, tek_harita = _kos(tek, tmp_path / "tek_out", silenced_subchannels=alt_kanal.SILENCED_SUBCHANNELS)
    # ikinci dizgi tek başına: kalan kanal (oz_ad), süzgeç açıkken de ad verir
    assert tek_harita["global"] == {"FUN_00001000": "sampler_reset"}
    assert tek_prov["global"]["FUN_00001000"]["sub_channel"] == "oz_ad"
    assert "oz_ad" in alt_kanal.KEPT_SUBCHANNELS

    iki = _iki_dizgili(tmp_path / "iki", ["telemetry sampler queue drained", "sampler_reset"])
    _, taban_prov, taban_harita = _kos(iki, tmp_path / "iki_taban")
    kazanan = taban_prov["global"]["FUN_00001000"]
    # önkoşul: iki dizgi varken kazanan, susan kanaldaki düz metindir
    assert kazanan["evidence"] == "telemetry sampler queue drained" and kazanan["sub_channel"] == "duz_metin"
    res, prov, harita = _kos(iki, tmp_path / "iki_out", silenced_subchannels=alt_kanal.SILENCED_SUBCHANNELS)
    assert harita["global"] == {}                               # sampler_reset'e geçilmedi
    assert res.silenced_counts == {"duz_metin": 1}
    assert prov["eliminated_keys"]["all_candidates_silenced"] == {"global": {"string_context": 1}}
    assert _hesap_tutar(prov)


def _aday(eski, ad, guven, strateji="string_context", kanit="telemetry sampler queue drained"):
    return c_namer._NamingCandidate(eski, ad, guven, strateji, evidence=kanit, code_path="classic",
                                    evidence_origin="string_ref")


def test_suzgec_yalniz_genel_anahtar_ve_yalniz_dizgi_adayi():
    """Süzgeç doğrudan: yerel anahtar ve dizgi dışı strateji dokunulmadan kalır; sıra korunur."""
    namer = CVariableNamer(Config())
    yerel = _aday("local_8", "telemetry_sampler_queue", 0.9)
    dizgi = _aday("FUN_00002000", "telemetry_sampler_queue", 0.9)
    assert alt_kanal.classify(evidence=dizgi.evidence, name=dizgi.new_name, code_path="classic",
                              evidence_origin="string_ref") == "duz_metin"
    api1 = _aday("FUN_00002000", "copy_2000", 0.5, strateji="api_call", kanit="")
    api2 = _aday("FUN_00002000", "proc_2000", 0.25, strateji="type_based", kanit="")
    oz = _aday("FUN_00003000", "sampler_reset", 0.9, kanit="sampler_reset")
    tek = _aday("FUN_00004000", "telemetry_sampler_queue", 0.9)
    # dizgi dışı strateji, kanıtı düz metin olsa da sınıflanmaz
    veri = _aday("DAT_00005000", "global_5000", 0.3, strateji="dataflow")
    namer._candidates = {"FUN_00001000::local_8": [yerel], "FUN_00002000": [api1, dizgi, api2],
                         "FUN_00003000": [oz], "FUN_00004000": [tek], "DAT_00005000": [veri], "FUN_bos": []}
    kaydedici = c_namer._ProvenanceRecorder(0.15)
    atilan = namer._silence_candidates(alt_kanal.SILENCED_SUBCHANNELS, kaydedici)
    assert atilan == {"duz_metin": 2}
    assert namer._candidates["FUN_00001000::local_8"] == [yerel]          # yerel anahtar aynen
    assert namer._candidates["FUN_00002000"] == [api1, api2]              # sıra korunur
    assert namer._candidates["FUN_00003000"] == [oz]                      # kalan kanal
    assert namer._candidates["FUN_00004000"] == [] and namer._candidates["DAT_00005000"] == [veri]
    assert kaydedici.eliminated_keys["all_candidates_silenced"] == {"global": {"string_context": 1}}
    # boş küme hiçbir şeyi atmaz
    namer._candidates = {"FUN_00004000": [tek]}
    assert namer._silence_candidates(frozenset(), None) == {} and namer._candidates["FUN_00004000"] == [tek]
    assert CVariableNamer._string_sub_channel(api1) is None


# --------------------------------------------------------------------------------------------
# Ürün eşiği


def test_urun_esigi_yalniz_genel_adlara(tmp_path, seri):
    ws = T.build_workspace(tmp_path / "ws")
    taban, taban_prov, taban_harita = _kos(ws, tmp_path / "taban")
    res, prov, harita = _kos(ws, tmp_path / "out", global_min_confidence=0.7)
    dusen = {k for k in taban_harita["global"] if taban.confidence_map[k] < 0.7}
    assert {k for k in dusen if k.startswith("DAT_")} == set(T._DATS)     # global_1234 (0,30) adları
    assert "FUN_00007000" in dusen                                        # proc_7000 (type_based 0,25)
    assert set(harita["global"]) == set(taban_harita["global"]) - dusen
    assert all(res.confidence_map[k] >= 0.7 for k in harita["global"])
    assert harita["global"]["FUN_0000c000"] == taban_harita["global"]["FUN_0000c000"]   # 0,75 kalır
    assert prov["global_min_confidence"] == 0.7
    assert sum(prov["eliminated_keys"]["below_global_min_confidence"]["global"].values()) == len(dusen)
    assert "local" not in prov["eliminated_keys"]["below_global_min_confidence"]
    # yerel adlar eşikten etkilenmez (0,15 ile sürer)
    assert harita["per_function"] == taban_harita["per_function"]
    assert _hesap_tutar(prov)
    # eşiğe eşit güven kalır
    _, _, esit = _kos(ws, tmp_path / "esit", global_min_confidence=0.75)
    assert "FUN_0000c000" in esit["global"]


# --------------------------------------------------------------------------------------------
# Künyeli ön adlar


def _ks1_kunye(ad, etiket=nl.LABEL_CERTAIN, satirlar=("func_kalibi",)):
    return {"kind": baglama.KIND_KS1, "name": ad, "exact": True, "label": etiket,
            "ks1": {"adres": "1000", "turler": ["func_kalibi"], "rol": "kendi",
                    "satirlar": list(satirlar), "kanitlar": [{"tur": "func_kalibi"}]}}


def test_ks1_on_adi_tam_yazilir_ve_kesin_etiketi_tasir(tmp_path, seri):
    ws = T.build_workspace(tmp_path / "ws")
    on = {"FUN_00001000": "Vector_add", "FUN_00002000": "_grid_check", "FUN_00003000": "Vector_sub"}
    meta = {"FUN_00001000": _ks1_kunye("Vector_add"), "FUN_00002000": _ks1_kunye("_grid_check", nl.LABEL_UNVERIFIED)}
    res, prov, harita = _kos(ws, tmp_path / "out", pre_names=on, meta=meta)
    # künyeli ad olduğu gibi; künyesiz ad eskisi gibi temizlenir
    assert harita["global"]["FUN_00001000"] == "Vector_add"
    assert harita["global"]["FUN_00002000"] == "_grid_check"
    assert harita["global"]["FUN_00003000"] == "vector_sub"
    assert res.label_map["FUN_00001000"] == nl.LABEL_CERTAIN
    assert res.label_map["FUN_00002000"] == res.label_map["FUN_00003000"] == nl.LABEL_UNVERIFIED
    assert res.strategy_map["FUN_00001000"] == "ks1" and res.strategy_map["FUN_00003000"] == "binary_extract"
    assert res.by_strategy["ks1"] == 2 and res.by_strategy["binary_extract"] == 1
    k = prov["global"]["FUN_00001000"]
    assert (k["source"], k["strategy"], k["label"], k["pre_name_kind"]) == ("pre_names", "ks1", "kesin", "ks1")
    assert k["ks1"]["satirlar"] == ["func_kalibi"] and k["confidence"] == 0.95
    assert "pre_name_kind" not in prov["global"]["FUN_00003000"]
    assert prov["summary"]["labels_global"][nl.LABEL_CERTAIN] == 1
    # ön adı olan anahtarın dizgi adayları yarıştan çıkar
    assert prov["eliminated_keys"]["pre_named"]["global"]["string_context"] == 3
    assert _hesap_tutar(prov)
    # biçimlendirici kanalı ve etiketi bu kayıttan okur
    assert nl.provenance_channel(k) == "ks1:func_kalibi" and nl.provenance_label(k) == "kesin"


def test_kunye_baska_adi_anlatiyorsa_yok_sayilir(tmp_path, seri):
    """Ad künyeden sonra başka bir kaynakça ezilmişse "kesin" etiketi yanlış ada geçmez."""
    ws = T.build_workspace(tmp_path / "ws")
    res, prov, harita = _kos(ws, tmp_path / "out", pre_names={"FUN_00001000": "Ezen_Ad"},
                             meta={"FUN_00001000": _ks1_kunye("Vector_add")})
    assert harita["global"]["FUN_00001000"] == "Ezen_Ad" or harita["global"]["FUN_00001000"] == "ezen_ad"
    assert res.label_map["FUN_00001000"] == nl.LABEL_UNVERIFIED
    assert res.strategy_map["FUN_00001000"] == "binary_extract"
    assert "ks1" not in prov["global"]["FUN_00001000"]


def test_on_ad_onceligi_ve_ayni_adin_dusmesi(tmp_path, seri):
    ws = T.build_workspace(tmp_path / "ws")
    # sözlük sırası: künyesiz, KS-1, elle. Aynı adı (ortak_ad) üçü de istiyor.
    on = {"FUN_00001000": "ortak_ad", "FUN_00002000": "ortak_ad", "FUN_00003000": "ortak_ad",
          "FUN_00004000": "Elle_Verilen"}
    meta = {"FUN_00002000": _ks1_kunye("ortak_ad"),
            "FUN_00003000": {"kind": baglama.KIND_MANUAL, "name": "ortak_ad", "exact": True},
            "FUN_00004000": {"kind": baglama.KIND_MANUAL, "name": "Elle_Verilen", "exact": True}}
    res, prov, harita = _kos(ws, tmp_path / "out", pre_names=on, meta=meta)
    # elle > KS-1 > künyesiz: adı elle verilen anahtar alır
    assert harita["global"]["FUN_00003000"] == "ortak_ad"
    assert harita["global"].get("FUN_00002000") != "ortak_ad"
    assert harita["global"].get("FUN_00001000") != "ortak_ad"
    assert prov["summary"]["pre_names_dropped_duplicate"] == 2
    assert prov["summary"]["pre_names_applied"] == 2 and prov["summary"]["pre_names_given"] == 4
    # elle verilen ad tam yazılır ve etiket taşımaz
    assert harita["global"]["FUN_00004000"] == "Elle_Verilen"
    assert "FUN_00003000" not in res.label_map and "FUN_00004000" not in res.label_map
    assert "label" not in prov["global"]["FUN_00004000"]
    assert prov["global"]["FUN_00004000"]["pre_name_kind"] == "elle"
    assert nl.provenance_label(prov["global"]["FUN_00004000"]) is None
    # künye yokken sıra eskisi gibi sözlük sırasıdır: ilk anahtar kazanır
    _, _, duz = _kos(ws, tmp_path / "duz", pre_names={"FUN_00001000": "ortak_ad", "FUN_00002000": "ortak_ad"})
    assert duz["global"]["FUN_00001000"] == "ortak_ad" and duz["global"].get("FUN_00002000") != "ortak_ad"


def test_tam_ad_gecerli_tanimlayici_degilse_temizlenir(tmp_path, seri):
    ws = T.build_workspace(tmp_path / "ws")
    meta = {"FUN_00001000": {"kind": baglama.KIND_MANUAL, "name": "iki sozcuk", "exact": True}}
    _, _, harita = _kos(ws, tmp_path / "out", pre_names={"FUN_00001000": "iki sozcuk"}, meta=meta)
    ad = harita["global"]["FUN_00001000"]
    assert " " not in ad and ad != "iki sozcuk"


def test_ks1_disi_tur_kesin_etiketi_alamaz(tmp_path, seri):
    ws = T.build_workspace(tmp_path / "ws")
    meta = {"FUN_00001000": {"kind": baglama.KIND_GNULIB, "name": "xmalloc", "exact": False, "label": "kesin"}}
    res, prov, _ = _kos(ws, tmp_path / "out", pre_names={"FUN_00001000": "xmalloc"}, meta=meta)
    assert res.label_map["FUN_00001000"] == nl.LABEL_UNVERIFIED
    assert prov["global"]["FUN_00001000"]["label"] == nl.LABEL_UNVERIFIED
    assert prov["global"]["FUN_00001000"]["pre_name_kind"] == "gnulib"
    assert res.strategy_map["FUN_00001000"] == "binary_extract"


def test_uc_ozellik_birlikte(tmp_path, seri):
    """Ürün kolu: KS-1 ön adı + susturma + eşik. Kalan her genel ad ya KS-1 ya eşiği geçen aday."""
    ws = T.build_workspace(tmp_path / "ws")
    res, prov, harita = _kos(ws, tmp_path / "out", pre_names={"FUN_00001000": "telemetry_drain"},
                             meta={"FUN_00001000": _ks1_kunye("telemetry_drain")},
                             silenced_subchannels=alt_kanal.SILENCED_SUBCHANNELS, global_min_confidence=0.7)
    assert harita["global"] == {"FUN_00001000": "telemetry_drain", "FUN_0000c000": "exit_handler"}
    assert res.label_map == {"FUN_00001000": "kesin", "FUN_0000c000": "doğrulanmadı"}
    assert res.silenced_counts == {"duz_metin": 6}       # ön adlı anahtarın adayı da süzgeçte sayılır
    assert _hesap_tutar(prov)
