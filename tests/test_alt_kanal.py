"""scripts/measurement/alt_kanal.py — string_context alt kanal sınıflayıcısının testleri (plan v2.2 N0b).

Bütün testler sentetik kayıtlarla koşar; etiket, gerçek ad ya da taban koşusu verisi kullanılmaz.
Kilitlenen davranışlar:
  (a) alt kanal listesi ve öncelik sırası; her kaydın tam olarak bir alt kanala düşmesi,
  (b) her alt kanalın yüklemi ve sınır durumları (gövde literali / dizgi tablosu, ``%%``, boşluk
      bayrağı, dördüncü anahtar sözcük, büyük harfli sabit, çakışma eki, sözcük sınırı …),
  (c) halef: susturulan adın yerine geçen aday, yapısal süzgeç, eşik, kayda geçmeyen aday,
  (d) Wilson aralığı, örneklem sınırları (35, 73) ve ön kayıtlı karar kuralı ("yalnız zayıflar":
      belirsiz kalır ve "doğrulanmadı" etiketi taşır, ölçülemeyen ve zayıf kanal susar),
  (e) taban koşusuyla eşleşme ve kayıt tablosu,
  (f) dondurulmuş kopyaların motorla (c_namer) aynı davrandığı (sapma denetimi),
  (g) depoya konan alt kanal atamalarının bugünkü sınıflayıcıyla yeniden üretildiği.

Mutasyon koruması: ``scripts/measurement/mutation_specs_alt_kanal.json``
(``PYTHONDONTWRITEBYTECODE=1 python scripts/mutation_probe.py --spec <o dosya>``).
"""
from __future__ import annotations

import importlib.util
import inspect
import json
import random
import sys
from pathlib import Path

import pytest

_KOK = Path(__file__).resolve().parents[1]
_PATH = _KOK / "scripts" / "measurement" / "alt_kanal.py"
_spec = importlib.util.spec_from_file_location("alt_kanal_under_test", _PATH)
ak = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = ak
_spec.loader.exec_module(ak)

ONKAYIT_DIZINI = _KOK / "docs" / "arge" / "2026-10-21_g10_n0b"


def klasik(kanit, kaynak="string_ref", **ek):
    """Klasik yolun bu kanıttan kuracağı kayıt (ad ve güven dondurulmuş kopyadan)."""
    ad, k = ak.klasik_ad(kanit)
    kayit = {"strategy": "string_context", "new_name": ad, "confidence": ak.klasik_guven(k),
             "evidence": kanit, "code_path": "classic", "rule": "keywords",
             "evidence_origin": kaynak}
    kayit.update(ek)
    return kayit


def agresif(kanit, ad, guven, kural="error_verb", kaynak="string_ref"):
    return {"strategy": "string_context", "new_name": ad, "confidence": guven, "evidence": kanit,
            "code_path": "aggressive", "rule": kural, "evidence_origin": kaynak}


def kanal(kanit, **kw):
    return ak.sinifla(klasik(kanit, **kw))["alt_kanal"]


# --------------------------------------------------------------------------------------------
# (a) liste, sıra, ayrıklık


def test_alt_kanal_listesi_ve_sirasi():
    assert ak.ALT_KANAL_ADLARI == (
        "agresif", "kod_parcasi", "bicim_parcasi", "oz_ad", "tek_sozcuk", "tanimlayici",
        "kebap_ad", "hata_iletisi", "bicim_dizgisi", "duz_metin", "diger")
    assert len(set(ak.ALT_KANAL_ADLARI)) == len(ak.ALT_KANAL_ADLARI)
    assert ak.TANIM_SURUMU == 1


def _cesitli_dizgiler():
    sabit = [
        "", "ab", "abc", "window", "cmdq_append", "TERM_PROGRAM_VERSION", "grid_set_cells",
        "monitor-activity", "%lld", "took %llu milliseconds", "%%sessions-changed",
        "invalid sort order", "remove wait channel %s", "#{session_name}:#{window_index}",
        "window only linked to one session", "kern.osrelease", "gl->cellused <= gl->cellsize",
        ");\n  FUN_1000a1d6c(&local_28,", "Available Columns", "/tmp/tmux.XXXXXXXX",
        "usage: tmux [-2CDlNuVv]", "r:%siB/s w:%siB/s", "MouseMoveStatusRight", "50% done now",
    ]
    rng = random.Random(20261021)
    abece = "abcXYZ_- %#{}\n0123456789:.;()dsul"
    rastgele = ["".join(rng.choice(abece) for _ in range(rng.randint(0, 40))) for _ in range(400)]
    return sabit + rastgele


@pytest.mark.parametrize("kaynak", ["string_ref", "body_literal"])
def test_her_kayit_tam_bir_alt_kanala_duser_ve_ilk_tutan_kazanir(kaynak):
    for kanit in _cesitli_dizgiler():
        for kayit in (klasik(kanit, kaynak=kaynak), agresif(kanit, "handle_x", 0.55)):
            s = ak.sinifla(kayit)
            assert s["alt_kanal"] in ak.ALT_KANAL_ADLARI
            assert s["yuklemler"]["diger"] is True
            ilk = next(ad for ad in ak.ALT_KANAL_ADLARI if s["yuklemler"][ad])
            assert s["alt_kanal"] == ilk, kanit


# --------------------------------------------------------------------------------------------
# (b) yüklemler ve öncelik


def test_agresif_kod_yolu_her_bicimden_once():
    # Kanıt tanımlayıcı biçiminde olsa da agresif kod yolu kendi kanalına düşer.
    kayit = agresif("cmdq_append() failed", "cmdq_append", 0.80, kural="func_paren")
    s = ak.sinifla(kayit)
    assert s["alt_kanal"] == "agresif"
    assert s["klasik_tutarli"] is None


def test_kod_parcasi_yalniz_gercek_olmayan_govde_literali():
    kod = ");\n  FUN_1000a1d6c(&local_28,"
    assert kanal(kod, kaynak="body_literal") == "kod_parcasi"
    # Aynı satırdaki kod parçası: satır sonu yok ama Ghidra kendiliğinden adı var.
    assert kanal(",0x2000);  FUN_10002286c(lVar1,", kaynak="body_literal") == "kod_parcasi"
    # Gövdeden okunmuş gerçek literal kod parçası değildir.
    assert kanal("synchronize-panes", kaynak="body_literal") == "kebap_ad"
    # Dizgi tablosundaki gerçek bir satır sonu kod parçası sayılmaz.
    assert kanal("Usage:\n  tmux new-session", kaynak="string_ref") == "hata_iletisi"
    # Gerçek literaldeki İngilizce sözcük Ghidra adı sayılmaz; rakamlı tip adı sayılır.
    assert kanal("value is undefined here", kaynak="body_literal") == "duz_metin"
    assert kanal("x = *(undefined4 *)", kaynak="body_literal") == "kod_parcasi"


def test_kod_parcasi_bicim_parcasindan_once():
    kanit = ";\n  _printf(\"%lld"
    assert ak.sinifla(klasik(kanit, kaynak="body_literal"))["yuklemler"]["bicim_parcasi"]
    assert kanal(kanit, kaynak="body_literal") == "kod_parcasi"


def test_bicim_parcasi_ad_kuran_sozcuk_belirtece_tasiyor():
    assert kanal("%lld") == "bicim_parcasi"
    assert kanal("r:%siB/s w:%siB/s") == "bicim_parcasi"
    # Belirtece taşan sözcük adın ikinci parçası.
    assert ak.klasik_ad("took %llu milliseconds")[0] == "took_llu_milliseconds"
    assert kanal("took %llu milliseconds") == "bicim_parcasi"


def test_bicim_parcasi_dorduncu_sozcuk_ada_girmez():
    # Dördüncü anahtar sözcük güveni yükseltir ama ada girmez: belirteç parçası sayılmaz.
    ad, k = ak.klasik_ad("alpha beta gamma %lld")
    assert (ad, k) == ("alpha_beta_gamma", 4)
    assert kanal("alpha beta gamma %lld") == "bicim_dizgisi"


def test_bicim_belirteci_yuzde_yuzde_ve_bosluk_bayragi():
    assert ak.bicim_belirtecleri("%%sessions-changed") == []
    assert kanal("%%sessions-changed") == "diger"
    assert ak.bicim_belirtecleri("%%%u bytes") == [(2, 4)]
    # Boşluk bayrağı alınmaz: düz metindeki "50% done" belirteç değil.
    assert ak.bicim_belirtecleri("50% done now") == []
    assert kanal("50% done now") == "duz_metin"
    # Belirtece taşmayan sözcükler: biçim dizgisi.
    assert kanal("%s: received secondary DA %.*s") == "bicim_dizgisi"


def test_oz_ad_ve_tanimlayici():
    assert kanal("cmdq_append") == "oz_ad"
    assert kanal("  cmdq_append ") == "oz_ad"           # baştaki ve sondaki boşluk atılır
    assert kanal("Panel_new") == "oz_ad"                # küçük harf var, ad dizginin küçüğü
    # Tümü büyük harf: sabit ya da ortam değişkeni, kendi adı sayılmaz.
    assert ak.klasik_ad("TERM_PROGRAM_VERSION")[0] == "term_program_version"
    assert kanal("TERM_PROGRAM_VERSION") == "tanimlayici"
    # Ad dizgiden farklı: durak sözcük, kısa parça, rakam, dördüncü parça.
    assert ak.klasik_ad("grid_set_cells")[0] == "grid_cells"
    assert kanal("grid_set_cells") == "tanimlayici"
    assert kanal("cmd_if_shell_exec") == "tanimlayici"
    assert kanal("input_key_mode1") == "tanimlayici"
    assert kanal("cmd_find_from_session_window") == "tanimlayici"


def test_oz_ad_cakisma_ekinden_once_gelen_adla():
    kayit = klasik("args_copy", new_name="args_copy_2", proposed_name="args_copy")
    assert ak.sinifla(kayit)["alt_kanal"] == "oz_ad"
    assert ak.sinifla(kayit)["klasik_tutarli"] is True


def test_tek_sozcuk_bicim_kanallarindan_once():
    assert kanal("window") == "tek_sozcuk"
    assert kanal("too small") == "tek_sozcuk"              # "too" durak sözcük
    assert kanal("gettimeofday failed") == "tek_sozcuk"    # hata iletisinden önce
    assert kanal("server_client_lost") == "tek_sozcuk"     # tanımlayıcıdan önce
    assert kanal("MouseMoveStatusRight") == "tek_sozcuk"


def test_kebap_ad():
    assert kanal("monitor-activity") == "kebap_ad"
    assert kanal("remain-on-exit") == "kebap_ad"
    assert kanal("Monitor-Activity") == "diger"            # büyük harf: kebap değil
    assert kanal("no-detach-on-destroy,") == "diger"       # sondaki virgül


def test_hata_iletisi_ve_sozcuk_siniri():
    assert kanal("invalid sort order") == "hata_iletisi"
    assert kanal("usage: tmux [-2CDlNuVv] [-c shell-command]") == "hata_iletisi"
    assert kanal("cannot swap down on floating pane") == "hata_iletisi"
    assert kanal("couldn't create window %d") == "hata_iletisi"   # biçim dizgisinden önce
    assert kanal("user option %s must be a string") == "hata_iletisi"
    assert kanal("badge count changed") == "duz_metin"            # "bad" sözcük sınırında


def test_bicim_dizgisi_duz_metin_diger():
    assert kanal("remove wait channel %s") == "bicim_dizgisi"
    assert kanal("#{session_name}:#{window_index}") == "bicim_dizgisi"
    assert kanal("window only linked to one session") == "duz_metin"
    assert kanal("Available Columns") == "duz_metin"
    assert kanal("kern.osrelease") == "diger"
    assert kanal("gl->cellused <= gl->cellsize") == "diger"       # C işleci
    assert kanal("/tmp/tmux.XXXXXXXX") == "diger"


def test_klasik_tutarlilik_denetimi():
    kayit = klasik("invalid sort order")
    assert ak.sinifla(kayit)["klasik_tutarli"] is True
    kayit["new_name"] = "baska_ad"
    assert ak.sinifla(kayit)["klasik_tutarli"] is False
    kayit = klasik("invalid sort order", confidence=0.95)
    assert ak.sinifla(kayit)["klasik_tutarli"] is False


# --------------------------------------------------------------------------------------------
# (c) halef


def _rakip(strateji, guven, ad="x"):
    return {"strategy": strateji, "confidence": guven, "new_name": ad}


def test_halef_ilk_susturulmamis_rakip():
    kayit = klasik("invalid sort order", runners_up=[_rakip("api_param_reverse", 0.75, "cb")],
                   n_candidates=2)
    h = ak.halef(kayit, {"hata_iletisi"}, 0.7)
    assert h == {"sonuc": "ad", "aday": "api_param_reverse", "guven": 0.75, "ad": "cb"}
    assert ak.halef_etiketi(h) == "ad:api_param_reverse"


def test_halef_yapisal_suzgec_yalniz_en_iyiye_bakar():
    kayit = klasik("invalid sort order", n_candidates=3,
                   runners_up=[_rakip("call_graph", 0.6), _rakip("api_param_reverse", 0.5)])
    h = ak.halef(kayit, {"hata_iletisi"}, 0.15)
    assert h["sonuc"] == "yapisal_suzgec" and h["aday"] == "call_graph"


def test_halef_esik_iki_duzeyde():
    rakip = agresif("Failed to connect", "handle_connect", 0.55)
    kayit = klasik("invalid sort order", runners_up=[rakip], n_candidates=2)
    assert ak.halef_etiketi(ak.halef(kayit, {"hata_iletisi"}, 0.7)) == \
        "esik_alti:string_context/agresif"
    assert ak.halef_etiketi(ak.halef(kayit, {"hata_iletisi"}, 0.15)) == \
        "ad:string_context/agresif"


def test_halef_ayni_kanaldaki_rakip_de_susturulur_ve_bilinmeyen():
    rakip = agresif("Failed to connect", "handle_connect", 0.55)
    kayit = klasik("invalid sort order", runners_up=[rakip], n_candidates=5)
    assert ak.halef(kayit, {"hata_iletisi", "agresif"}, 0.15) == {"sonuc": "bilinmiyor"}
    kayit["n_candidates"] = 2
    assert ak.halef(kayit, {"hata_iletisi", "agresif"}, 0.15) == {"sonuc": "yok"}
    assert ak.halef(klasik("line", n_candidates=1), {"tek_sozcuk"}, 0.7) == {"sonuc": "yok"}


def test_halef_susturulmayan_kanal_ve_baska_strateji():
    kayit = klasik("invalid sort order", runners_up=[_rakip("api_param_reverse", 0.75)])
    assert ak.halef(kayit, {"oz_ad"}, 0.7) == {"sonuc": "susturulmadi"}
    assert ak.halef(_rakip("api_param_reverse", 0.75), {"oz_ad"}, 0.7) == {"sonuc": "susturulmadi"}


# --------------------------------------------------------------------------------------------
# (d) Wilson, örneklem sınırları, karar


def test_wilson_bilinen_deger_ve_sinirlar():
    alt, ust = ak.wilson(5, 50)
    assert alt == pytest.approx(0.04347, abs=1e-4)
    assert ust == pytest.approx(0.21361, abs=1e-4)
    assert ak.wilson(0, 0) == (0.0, 1.0)
    assert ak.wilson(0, 35)[1] <= 0.10 < ak.wilson(0, 34)[1]
    assert ak.wilson(73, 73)[0] >= 0.95 > ak.wilson(72, 72)[0]


def test_ornekleme_siniri_35_ve_73():
    assert ak.en_az_n_ust_sinir(0.10) == 35
    assert ak.en_az_n_alt_sinir(0.95) == 73


@pytest.mark.parametrize("n, yanlis, beklenen", [
    (0, 0, "olculemedi"),
    (35, 0, "dogrulandi"),
    (34, 0, "belirsiz"),
    (60, 1, "dogrulandi"),
    (60, 2, "belirsiz"),
    (20, 1, "belirsiz"),      # nokta tahmin %5, üst sınır ~%24
    (40, 20, "zayif"),
    (10, 4, "zayif"),
    (14, 11, "zayif"),
])
def test_karar_kurali(n, yanlis, beklenen):
    k = ak.karar(n, yanlis)
    assert k["karar"] == beklenen
    # "Yalnız zayıflar": doğrulanan ve belirsiz kalan kanal ad vermeyi sürdürür.
    assert ak.urunde_kalir(k) is (beklenen in ("dogrulandi", "belirsiz"))
    assert k["urunde"] is ak.urunde_kalir(k)
    assert k["guven_etiketi"] == ak.guven_etiketi(k)


def test_yalniz_zayiflar_susturulur_ve_guven_etiketi():
    dogrulandi, belirsiz = ak.karar(35, 0), ak.karar(20, 1)
    zayif, olculemedi = ak.karar(40, 20), ak.karar(0, 0)
    assert [k["karar"] for k in (dogrulandi, belirsiz, zayif, olculemedi)] == [
        "dogrulandi", "belirsiz", "zayif", "olculemedi"]
    # Belirsiz kanal kalır ama "doğrulanmadı" etiketiyle; doğrulanan "doğrulandı" taşır.
    assert ak.urunde_kalir(belirsiz) and belirsiz["guven_etiketi"] == "doğrulanmadı"
    assert ak.urunde_kalir(dogrulandi) and dogrulandi["guven_etiketi"] == "doğrulandı"
    # Zayıf kanal susturulur; hakkında hiç kanıt olmayan (n = 0) kanal da susturulur.
    assert not ak.urunde_kalir(zayif) and zayif["guven_etiketi"] is None
    assert not ak.urunde_kalir(olculemedi) and olculemedi["guven_etiketi"] is None
    assert ak.URUNDE_KALAN_KARARLAR == frozenset({"dogrulandi", "belirsiz"})


def test_hepsini_kapatir_yalniz_hepsi_zayif_ya_da_olculemediyse():
    zayif, olculemedi, belirsiz = ak.karar(40, 20), ak.karar(0, 0), ak.karar(20, 1)
    assert ak.hepsini_kapatir({"kod_parcasi": zayif, "agresif": olculemedi})
    assert not ak.hepsini_kapatir({"kod_parcasi": zayif, "agresif": olculemedi,
                                   "oz_ad": belirsiz})
    assert not ak.hepsini_kapatir({"oz_ad": ak.karar(35, 0)})


def test_karar_gecersiz_sayilar():
    with pytest.raises(ValueError):
        ak.karar(5, 6)
    with pytest.raises(ValueError):
        ak.karar(-1, 0)


# --------------------------------------------------------------------------------------------
# (e) eşleşme ve kayıt tablosu


def test_taban_ad_ve_eslesme():
    assert ak.taban_ad("cmd_find_session_4") == "cmd_find_session"
    assert ak.taban_ad(None) is None
    assert ak.eslesme("small_2", "small", True) == "taban_ad"
    assert ak.eslesme("small", "small", True) == "tam"
    assert ak.eslesme("small", None, True) == "taban_adsiz"
    assert ak.eslesme("small", None, False) == "satir_yok"
    assert ak.eslesme("small", "large", True) == "farkli"


def _koken():
    return {
        "schema": "karadul.naming_provenance", "schema_version": 1, "min_confidence": 0.15,
        "global": {
            "FUN_100000b00": klasik("invalid sort order", key="FUN_100000b00", n_candidates=2,
                                   runners_up=[_rakip("api_param_reverse", 0.75, "cb")]),
            "FUN_100000a00": klasik("cmdq_append", key="FUN_100000a00", n_candidates=1),
            "FUN_100000c00": {"strategy": "binary_extract", "new_name": "close_stdout",
                              "confidence": 0.95, "source": "pre_names", "n_candidates": 0,
                              "runners_up": []},
            "DAT_100000d00": {"strategy": "dataflow", "new_name": "g_x", "confidence": 0.8},
        },
        "per_function": {},
    }


def test_kayitlari_kur_ve_ters_eslesme():
    tahmin = {"0x100000a00": "cmdq_append", "0x100000b00": "sort_order_2", "0x100000e00": "z"}
    adl = {"FUN_100000a00": {"ad": "cmdq_append", "kaynak": "c_namer"},
           "FUN_100000f00": {"ad": "fatal", "kaynak": "c_namer"}}
    satirlar = ak.kayitlari_kur(_koken(), "deneme", 0.7, tahmin, adl)
    assert [s["anahtar"] for s in satirlar] == ["FUN_100000a00", "FUN_100000b00", "FUN_100000c00"]
    a, b, c = satirlar
    assert a["adres"] == "0x100000a00" and a["alt_kanal"] == "oz_ad"
    assert a["halef_urun"] == "yok" and a["taban_eslesme"] == "tam"
    assert b["alt_kanal"] == "hata_iletisi" and b["halef_urun"] == "ad:api_param_reverse"
    assert b["taban_eslesme"] == "taban_ad" and b["naming_map_eslesme"] == "satir_yok"
    assert b["rakipler"] == [{"etiket": "api_param_reverse", "guven": 0.75, "ad": "cb"}]
    assert c["alt_kanal"] is None and c["taban_eslesme"] == "satir_yok"
    assert all(s["urun_esigini_gecer"] for s in satirlar)
    ters = ak.ters_eslesme(satirlar, tahmin, adl)
    assert ters == {"pred_var_kayit_yok": ["0x100000e00"],
                    "naming_map_c_namer_kayit_yok": ["FUN_100000f00"]}


def test_program_kapsami_esikler_ve_nihai():
    satirlar = ak.kayitlari_kur(_koken(), "deneme", 0.7,
                                {"0x100000a00": "cmdq_append", "0x100000b00": None})
    satirlar.append(dict(satirlar[0], anahtar="FUN_100000a10", adres="0x100000a10", guven=0.45,
                         urun_esigini_gecer=False, taban_eslesme="satir_yok"))
    oz = ak.program_kapsami(satirlar)
    assert oz["alt_kanal"]["cnamer_esigi"]["oz_ad"] == 2
    assert oz["alt_kanal"]["urun_esigi"]["oz_ad"] == 1
    assert oz["alt_kanal"]["nihai_puanlanan"]["oz_ad"] == 1
    assert oz["alt_kanal"]["nihai_puanlanan"]["hata_iletisi"] == 0   # taban satırı adsız
    assert list(oz["alt_kanal"]["urun_esigi"]) == list(ak.ALT_KANAL_ADLARI)
    assert oz["klasik_tutarsiz"] == 0


def test_koken_semasi_denetlenir(tmp_path):
    yol = tmp_path / "k.json"
    yol.write_text(json.dumps({"schema": "baska", "schema_version": 1}))
    with pytest.raises(ValueError):
        ak.koken_yukle(yol)


# --------------------------------------------------------------------------------------------
# (f) dondurulmuş kopyalar ↔ motor (c_namer)


def _sapma_dizgileri():
    durak = sorted(ak.DURAK_SOZCUKLER)
    return ([f"xyzw {d} qrst" for d in durak] + [d.upper() for d in durak]
            + _cesitli_dizgiler()
            + ["Failed to open database connection", "a1b2c3 dEf GHIJ", "x" * 120 + " tail"])


def test_anahtar_sozcukler_motorla_ayni():
    cn = pytest.importorskip("karadul.reconstruction.c_namer")
    for s in _sapma_dizgileri():
        assert [w for w, _, _ in ak.anahtar_sozcukler(s)] == cn._extract_keywords_from_string(s), s


def test_ad_temizle_motorla_ayni():
    cn = pytest.importorskip("karadul.reconstruction.c_namer")
    for s in _sapma_dizgileri() + ["__a__b__", "9lives", "", "___", "Mixed_Case"]:
        assert ak.ad_temizle(s) == cn._sanitize_c_name(s), s


def test_klasik_yol_motorla_ayni():
    """c_namer'ın kendi string_context stratejisi: klasik aday adı ve güveni kopyayla aynı."""
    cn = pytest.importorskip("karadul.reconstruction.c_namer")
    from karadul.config import Config

    denenen = 0
    for s in _sapma_dizgileri():
        adlandirici = cn.CVariableNamer(Config())
        adlandirici._string_refs_by_func = {"1000": [s]}
        adlandirici._func_bodies = {}
        adlandirici._strategy_string_context(cn._FunctionInfo(name="FUN_00001000", address="1000"))
        for aday in adlandirici._candidates.get("FUN_00001000", []):
            if aday.code_path != "classic":
                continue
            ad, k = ak.klasik_ad(s)
            assert (aday.new_name, aday.evidence) == (ad, s)
            assert aday.confidence == pytest.approx(ak.klasik_guven(k), abs=1e-12)
            denenen += 1
    assert denenen > 100


def test_motor_kod_yollari_ve_sema_degismedi():
    cn = pytest.importorskip("karadul.reconstruction.c_namer")
    assert cn.STRING_CONTEXT_CODE_PATHS == (ak.AGRESIF_YOL, ak.KLASIK_YOL)
    assert cn.STRING_CONTEXT_EVIDENCE_ORIGINS == ("string_ref", "body_literal")
    assert cn.NAMING_PROVENANCE_SCHEMA == ak.KOKEN_SEMASI
    assert cn.NAMING_PROVENANCE_SCHEMA_VERSION == ak.KOKEN_SEMA_SURUMU


def test_yapisal_suzgec_motorla_ayni():
    cn = pytest.importorskip("karadul.reconstruction.c_namer")
    kaynak = inspect.getsource(cn.CVariableNamer.analyze_and_rename)
    beklenen = ("if not func_name and best.strategy in (\n                "
                + ", ".join(f'"{s}"' for s in ak.YAPISAL_SUZGEC) + ",\n            ):")
    assert beklenen in kaynak


# --------------------------------------------------------------------------------------------
# (g) depodaki atamalar


def _depodaki_kayitlar():
    return sorted(ONKAYIT_DIZINI.glob("kayitlar_*.jsonl"))


@pytest.mark.skipif(not _depodaki_kayitlar(), reason="ön kayıt kayıt dosyaları yok")
def test_depodaki_atamalar_yeniden_uretilir():
    n = 0
    for yol in _depodaki_kayitlar():
        for satir in yol.read_text(encoding="utf-8").splitlines():
            s = json.loads(satir)
            if s["strateji"] != "string_context":
                assert s["alt_kanal"] is None
                continue
            kayit = {"strategy": s["strateji"], "new_name": s["ad"],
                     "proposed_name": s["onerilen_ad"], "confidence": s["guven"],
                     "evidence": s["kanit"], "code_path": s["kod_yolu"], "rule": s["kural"],
                     "evidence_origin": s["kanit_kaynagi"]}
            yeni = ak.sinifla(kayit)
            assert yeni["alt_kanal"] == s["alt_kanal"], (yol.name, s["anahtar"])
            assert yeni["k"] == s["k"]
            assert yeni["klasik_tutarli"] == s["klasik_tutarli"]
            assert [a for a, d in yeni["yuklemler"].items() if d] == s["yuklemler"]
            n += 1
    assert n > 0
