"""docs/arge/2026-11-10_n4/fiil_tavani.py — N4 fiil tavanı sayımının testleri.

Bütün testler sentetik verilerle koşar: uydurma adlar, sentetik ``static/`` dizini, elle kurulan
kayıtlar. Gerçek GT okunmaz. Kilitlenen davranışlar:
  (a) GT adından fiil: platform öneki, derleyici eki, parça, takma adların birleşimi, dört durum;
  (b) ad biçimi ve modül öneki vekili;
  (c) ölçme listesi: kesimler, sözlükle ve kendi içinde kesişme denetimi;
  (d) erişim: K/I/Y, F-API (fk2 sınırı), ayırıcı/bırakıcı ve sarmalayıcı vekili, F-ROL adres kaydı;
  (e) aile isabetleri ve birleşik tavan; çok sınıflı duyarlılık;
  (f) sayım, tekil görünüm, program makrosu, ön sayımla karşılaştırma;
  (g) çıktıda ad ve liste belirteci yok; kayıt sırasından bağımsızlık.
"""
from __future__ import annotations

import importlib.util
import json
import random
import sys
from pathlib import Path

import pytest

_KOK = Path(__file__).resolve().parents[1]
_PATH = _KOK / "docs" / "arge" / "2026-11-10_n4" / "fiil_tavani.py"
_spec = importlib.util.spec_from_file_location("n4_fiil_tavani_under_test", _PATH)
ft = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = ft
_spec.loader.exec_module(ft)

EK = {"acik": frozenset({"zorp", "blen"}), "belirsiz": frozenset({"quix"})}


# --------------------------------------------------------------------------------------------
# (a) GT adından fiil


def test_gt_yok_ve_parca():
    assert ft.gt_fiili(None, "mac")["durum"] == "gt_yok"
    p = ft.gt_fiili(["_OUTLINED_FUNCTION_12"], "mac")
    assert p["durum"] == "parca" and p["klon_ekli"] and p["anahtar"] is None


def test_tek_sinif_platform_oneki_ve_klon_eki():
    k = ft.gt_fiili(["_thing_list_destroy"], "mac")
    assert (k["durum"], k["fiil"], k["siniflar"]) == ("tek_sinif", "destroy", ("destroy",))
    assert k["adlar"] == ("thing_list_destroy",) and not k["klon_ekli"]
    e = ft.gt_fiili(["thing_free.cold", "thing_free.part.0"], "debian")
    assert (e["durum"], e["fiil"], e["klon_ekli"], e["cok_adli"]) == ("tek_sinif", "destroy", True, False)
    # ekli ve eksiz ad birlikte: klon sayılmaz
    assert not ft.gt_fiili(["thing_free", "thing_free.isra.0"], "debian")["klon_ekli"]


def test_durumlar_ve_takma_ad_birlesimi():
    assert ft.gt_fiili(["event_callback"], "debian")["durum"] == "yalniz_genel"
    assert ft.gt_fiili(["status_line_width"], "debian")["durum"] == "fiilsiz"
    c = ft.gt_fiili(["thing_get_or_create"], "debian")
    assert c["durum"] == "cok_sinif" and c["fiil"] is None and c["siniflar"] == ("create", "get")
    # iki takma ad, iki ayrı sınıf: birleşim çok sınıflıdır
    b = ft.gt_fiili(["node_insert", "node_remove"], "debian")
    assert b["durum"] == "cok_sinif" and b["siniflar"] == ("add", "remove") and b["cok_adli"]
    # deve yazımı da bölünür; genel sınıf tek sınıfı bozmaz
    d = ft.gt_fiili(["handleReadBuffer"], "debian")
    assert (d["durum"], d["fiil"]) == ("tek_sinif", "read")


def test_tekil_anahtar_takma_ad_kumesini_ayirir():
    assert ft.gt_fiili(["a_b"], "debian")["anahtar"] != ft.gt_fiili(["a", "b"], "debian")["anahtar"]


def test_sozluk_disi_belirtec_yalniz_fiilsiz_ve_genelde():
    f = ft.gt_fiili(["colour_zorp_quix"], "debian", EK)
    assert f["durum"] == "fiilsiz" and f["ek_acik"] == ("zorp",) and f["ek_belirsiz"] == ("quix",)
    g = ft.gt_fiili(["blen_handler"], "debian", EK)
    assert g["durum"] == "yalniz_genel" and g["ek_acik"] == ("blen",)
    t = ft.gt_fiili(["zorp_and_free"], "debian", EK)
    assert t["durum"] == "tek_sinif" and t["ek_acik"] == () and t["ek_belirsiz"] == ()


# --------------------------------------------------------------------------------------------
# (b) ad biçimi, önek


@pytest.mark.parametrize("ad,beklenen", [
    ("free", "yalniz_fiil"), ("free_thing", "fiil_nesne"), ("thing_free", "nesne_fiil"),
    ("mod_free_thing", "onek_fiil_nesne"), ("thing_free2", "nesne_fiil"),
    ("mod_thing_free_3", "nesne_fiil"), ("callback_free_thing", "onek_fiil_nesne"),
    ("status_line", None), ("on_event", None),
])
def test_ad_bicimi(ad, beklenen):
    assert ft.ad_bicimi(ad) == beklenen


def test_bicim_fiil_tasiyan_ilk_taban_addan():
    k = ft.gt_fiili(["aaa_thing", "zzz_free_thing"], "debian")
    assert k["durum"] == "tek_sinif" and k["bicim"] == "onek_fiil_nesne" and k["ilk_belirtec"] == "aaa"


def _kayit(**kw):
    k = {"birim": "debian/p", "elf": "e", "adres": 0, "sinif": "K", "durum": "fiilsiz", "fiil": None,
         "siniflar": (), "klon_ekli": False, "cok_adli": False, "anahtar": None, "adlar": (),
         "bicim": None, "ilk_belirtec": None, "ek_acik": (), "ek_belirsiz": (),
         "ks1_nufusunda": False, "onekli": False, "rol": (),
         "api_fk2": False, "api_genis": False, "create_dogrudan": False, "destroy_dogrudan": False,
         "create_sarmalayici": False, "destroy_sarmalayici": False, "cagri_yapan": True,
         "yaprak": False, "yazmaz": False, "ayirmaz": False}
    k.update(kw)
    if k["durum"] == "tek_sinif" and not k["siniflar"]:
        k["siniflar"] = (k["fiil"],)
    if k["durum"] == "tek_sinif" and k["bicim"] is None:
        k["bicim"] = "fiil_nesne"
    return k


def test_onek_isaretle_bes_farkli_ad_ve_sozluk_belirteci_haric():
    ks = [_kayit(adres=i, anahtar=f"win_{i}", ilk_belirtec="win") for i in range(5)]
    ks += [_kayit(adres=10 + i, anahtar=f"pane_{i}", ilk_belirtec="pane") for i in range(4)]
    ks += [_kayit(adres=20 + i, anahtar=f"get_{i}", ilk_belirtec="get") for i in range(6)]
    # aynı ad 9 ELF'te: tek ad sayılır
    ks += [_kayit(adres=30 + i, elf=f"e{i}", anahtar="xa_same", ilk_belirtec="xa") for i in range(9)]
    ks += [_kayit(adres=40, birim="mac/q", anahtar="win_x", ilk_belirtec="win")]
    ft.onek_isaretle(ks)
    onekli = {k["ilk_belirtec"] for k in ks if k["onekli"]}
    assert onekli == {"win"}
    assert not ks[-1]["onekli"]            # başka birimde tek ad


# --------------------------------------------------------------------------------------------
# (c) ölçme listesi


def test_ek_liste_okuma_ve_denetimler(tmp_path):
    y = tmp_path / "l.txt"
    y.write_text("# yorum\n[acik]\nzorp blen  # satır sonu yorumu\n\n[belirsiz]\nquix\n", encoding="utf-8")
    assert ft.ek_listeyi_oku(y) == EK
    for metin in ("[acik]\nzorp free\n",            # sözlük v0 belirteci
                  "[acik]\nzorp\n[belirsiz]\nzorp\n",   # iki kesimde
                  "zorp\n",                         # başlıksız
                  "[baska]\nzorp\n",                # bilinmeyen kesim
                  "[acik]\nZo_rp\n",                # biçim
                  "[belirsiz]\nquix\n"):               # acik boş
        y.write_text(metin, encoding="utf-8")
        with pytest.raises(ValueError):
            ft.ek_listeyi_oku(y)


# --------------------------------------------------------------------------------------------
# (d) erişim


def _b(lib=(), ic=(), hata=(), bellek=None, yazar=False):
    lib = set(lib)
    return {"lib": lib, "ic": set(ic), "hata": set(hata),
            "bellek": lib & ft.on_sayim.BELLEK_DIZGI if bellek is None else set(bellek),
            "ozet": {"yazar": yazar, "n": 4}}


def test_sarmalayici_vekili_kosullari():
    bilgi = {
        1: _b(lib={"malloc"}),                                   # temel
        2: _b(lib={"malloc", "strerror"}, hata={"strerror"}, ic={90}),   # hata çıkarılır, 1 iç çağrı
        3: _b(lib={"malloc", "open"}),                           # kalan aile dışına taşıyor
        4: _b(lib={"malloc"}, ic={90, 91}),                      # iki iç çağrı
        5: _b(lib={"malloc"}),                                   # büyük gövde
        6: _b(ic={1}),                                           # iletici
        7: _b(ic={6}),                                           # ileticinin ileticisi
        8: _b(ic={1, 2}),                                        # iki hedef: iletici değil
        9: _b(lib={"strerror"}, hata={"strerror"}),              # kalan boş
        10: _b(lib={"free"}),                                    # öbür aile
        11: _b(lib={"malloc", "free"}),                          # iki aile birden
        12: _b(lib={"open"}, ic={1}),                            # kütüphane de çağırıyor: iletici değil
    }
    komut = {a: 8 for a in bilgi}
    komut[5] = ft.SARMALAYICI_AZAMI_KOMUT + 1
    assert ft.sarmalayici_vekilleri(bilgi, komut, ft.AYIRICI) == {1, 2, 6, 7}
    assert ft.sarmalayici_vekilleri(bilgi, komut, ft.BIRAKICI) == {10}
    komut[2] = ft.SARMALAYICI_AZAMI_KOMUT          # sınır dahil
    assert 2 in ft.sarmalayici_vekilleri(bilgi, komut, ft.AYIRICI)
    komut[6] = ft.SARMALAYICI_AZAMI_KOMUT + 1      # iletici de boyut sınırına bağlı; 7 de düşer
    assert ft.sarmalayici_vekilleri(bilgi, komut, ft.AYIRICI) == {1, 2}


def test_iletici_zinciri_adim_siniri():
    n = ft.SARMALAYICI_AZAMI_ADIM + 3
    bilgi = {0: _b(lib={"free"})}
    bilgi.update({i: _b(ic={i - 1}) for i in range(1, n)})
    komut = {a: 4 for a in bilgi}
    assert ft.sarmalayici_vekilleri(bilgi, komut, ft.BIRAKICI) == set(range(ft.SARMALAYICI_AZAMI_ADIM + 1))


def test_erisim_bayraklari():
    e = ft.erisim_bayraklari(_b(lib={"open", "free"}, ic={1, 2, 3}), {7}, {8}, ["compare"])
    assert e["sinif"] == "K" and e["api_genis"] and e["api_fk2"]
    assert e["destroy_dogrudan"] and e["destroy_sarmalayici"] and not e["create_dogrudan"]
    assert not e["create_sarmalayici"] and e["cagri_yapan"] and not e["yaprak"] and e["ayirmaz"]
    assert e["rol"] == ("compare",)
    # fk2 sınırı: 3 dahil, 4 hariç
    assert not ft.erisim_bayraklari(_b(lib={"open"}, ic={1, 2, 3, 4}), set(), set(), [])["api_fk2"]
    assert ft.erisim_bayraklari(_b(lib={"open"}, ic={1, 2, 3, 4}), set(), set(), [])["api_genis"]
    # yalnız bellek/dizgi ya da yalnız hata/ileti: ayırt edici değil
    assert not ft.erisim_bayraklari(_b(lib={"malloc", "strlen"}), set(), set(), [])["api_genis"]
    assert not ft.erisim_bayraklari(_b(lib={"fprintf"}, hata={"fprintf"}), set(), set(), [])["api_genis"]
    i = ft.erisim_bayraklari(_b(ic={7}), {7}, {8}, [])
    assert i["sinif"] == "I" and i["create_sarmalayici"] and not i["destroy_sarmalayici"]
    y = ft.erisim_bayraklari(_b(yazar=True), {7}, {8}, [])
    assert y["sinif"] == "Y" and y["yaprak"] and not y["cagri_yapan"] and not y["yazmaz"]
    assert ft.erisim_bayraklari(_b(), set(), set(), [])["yazmaz"]
    ozetsiz = _b()
    ozetsiz["ozet"] = None
    assert ft.erisim_bayraklari(ozetsiz, set(), set(), [])["yazmaz"]
    assert not ft.erisim_bayraklari(_b(lib={"calloc"}), set(), set(), [])["ayirmaz"]


def test_rol_erisimi_gercek_tarayiciyla():
    bilgi = {0x1300: _b(lib={"qsort"}), 0x1400: _b(), 0x1500: _b(lib={"open"}), 0x1600: _b(),
             0x1700: _b(lib={"pthread_create", "signal"}), 0x1800: _b()}
    kod = {
        0x1300: [(0x1300, "adrp", "x1,0x1000"), (0x1304, "add", "x1,x1,#0x400"), (0x1308, "bl", "0x9020")],
        # kayıt API'si çağırmayan fonksiyondaki adres: rol değil
        0x1500: [(0x1500, "adrp", "x1,0x1000"), (0x1504, "add", "x1,x1,#0x600"), (0x1508, "bl", "0x9030")],
        0x1700: [(0x1700, "adr", "x2,0x1800"), (0x1704, "adr", "x3,0x1700"), (0x1708, "bl", "0x9050")],
    }
    assert ft.rol_erisimi(bilgi, kod) == {0x1400: {"compare"}, 0x1800: {"yok", "handle"}}


def test_rol_sinifi_kaynak_kuralla_ayni():
    """ROL_SINIFI, rules.callback_role'un verdiği rol adının ilk belirtecinin sınıfıdır."""
    from karadul.reconstruction.tarif import rules
    for api, sinif in ft.ROL_SINIFI.items():
        rol = rules.callback_role(api, "", "0")
        assert rol is not None, api
        ilk = ft.on_sayim.belirtecler(rol)[0]
        assert ft.on_sayim.BELIRTEC_SINIFI.get(ilk) == sinif, (api, rol)
    assert ft.F_ROL_SINIFLARI == {"compare", "fini"}
    assert rules.callback_role("strlen", "", "0") is None


# --------------------------------------------------------------------------------------------
# (e) isabetler


def test_isabet_erisim_ve_sinif_birlikte():
    acik = dict(api_fk2=True, api_genis=True, create_dogrudan=True, destroy_dogrudan=True,
                create_sarmalayici=True, destroy_sarmalayici=True, yaprak=True, yazmaz=True,
                ayirmaz=True, rol=("compare", "handle"))
    i = ft.isabetler(_kayit(durum="tek_sinif", fiil="open", **acik))
    assert i["f_api_fk2"] and i["f_api_genis"] and not i["f_etki_cagri"] and not i["f_rol"]
    assert i["birlesik_ilk_dar"] and i["erisimsiz_ilk"] and i["sozluk"]
    # fk2 dışı ayırt edici API: dar birleşime girmez, genişe girer
    i = ft.isabetler(_kayit(durum="tek_sinif", fiil="open", api_genis=True))
    assert not i["f_api_fk2"] and not i["birlesik_ilk_dar"] and i["birlesik_ilk_genis"]
    # erişim yoksa isabet yok; erişimsiz sınır yine sayar
    i = ft.isabetler(_kayit(durum="tek_sinif", fiil="open"))
    assert not i["f_api_genis"] and not i["birlesik_aday_genis"] and i["erisimsiz_ilk"]
    # aile dışı sınıf: erişim olsa da isabet yok
    i = ft.isabetler(_kayit(durum="tek_sinif", fiil="add", **acik))
    assert not any(i[a] for a in i if a != "sozluk")
    # create ↔ ayırıcı, destroy ↔ bırakıcı
    i = ft.isabetler(_kayit(durum="tek_sinif", fiil="create", destroy_dogrudan=True,
                            destroy_sarmalayici=True))
    assert not i["f_etki_dogrudan"] and not i["f_etki_sarmalayici"] and i["f_etki_cagri"]
    assert not i["birlesik_ilk_dar"] and i["birlesik_ilk_genis"]
    i = ft.isabetler(_kayit(durum="tek_sinif", fiil="destroy", destroy_sarmalayici=True))
    assert not i["f_etki_dogrudan"] and i["f_etki_sarmalayici"] and i["f_etki_destroy_sarmalayici"]
    assert not i["f_etki_create_sarmalayici"]
    # yaprak create/destroy: çağrı yapan düzeyinde de erişilmez
    i = ft.isabetler(_kayit(durum="tek_sinif", fiil="destroy", cagri_yapan=False, yaprak=True))
    assert not i["f_etki_cagri"] and i["erisimsiz_ilk"]


def test_isabet_rol_ve_adaylar():
    i = ft.isabetler(_kayit(durum="tek_sinif", fiil="compare", rol=("compare",)))
    assert i["f_rol"] and i["f_rol_erisimsiz"] and i["birlesik_ilk_dar"] and i["aday_compare"]
    i = ft.isabetler(_kayit(durum="tek_sinif", fiil="compare", rol=("handle",)))
    assert not i["f_rol"] and i["f_rol_erisimsiz"] and not i["birlesik_ilk_genis"]
    assert i["birlesik_aday_genis"]                 # compare aday fiil, koşulsuz
    i = ft.isabetler(_kayit(durum="tek_sinif", fiil="fini", rol=("compare",)))
    assert not i["f_rol"]                           # rol sınıfı GT sınıfıyla aynı olmalı
    # genel rol hiçbir zaman isabet değil
    assert not ft.isabetler(_kayit(durum="yalniz_genel", rol=("handle",)))["f_rol"]
    for fiil, bayrak in (("get", "yaprak"), ("set", "yaprak"), ("is", "yazmaz"), ("init", "ayirmaz")):
        assert not ft.isabetler(_kayit(durum="tek_sinif", fiil=fiil))["f_etki_aday"]
        i = ft.isabetler(_kayit(durum="tek_sinif", fiil=fiil, **{bayrak: True}))
        assert i["f_etki_aday"] and i[f"aday_{fiil}"] and not i["birlesik_ilk_genis"]
        assert i["erisimsiz_aday"] and not i["erisimsiz_ilk"]
    assert ft.isabetler(_kayit(durum="tek_sinif", fiil="copy"))["f_etki_aday"]


def test_cok_sinif_yalniz_duyarlilikta():
    k = _kayit(durum="cok_sinif", siniflar=("add", "open"), api_fk2=True, api_genis=True)
    assert not any(ft.isabetler(k).values())
    d = ft.isabetler(k, cok_dahil=True)
    assert d["f_api_fk2"] and d["birlesik_ilk_dar"] and d["sozluk"]
    # tek sınıflı ad iki tanımda da aynı
    t = _kayit(durum="tek_sinif", fiil="open", api_genis=True)
    assert ft.isabetler(t) == ft.isabetler(t, cok_dahil=True)
    # fiilsiz ad duyarlılıkta da isabet değil
    assert not any(ft.isabetler(_kayit(api_genis=True, siniflar=()), cok_dahil=True).values())


# --------------------------------------------------------------------------------------------
# (f) sayım, tekil, makro


def _ornek_kayitlar():
    return [
        _kayit(adres=1, sinif="K", durum="tek_sinif", fiil="open", api_fk2=True, api_genis=True,
               anahtar="GIZLI_AD_bir", adlar=("GIZLI_AD_bir",), ks1_nufusunda=True, bicim="nesne_fiil"),
        _kayit(adres=2, sinif="K", durum="tek_sinif", fiil="destroy", destroy_dogrudan=True,
               destroy_sarmalayici=True, anahtar="GIZLI_AD_iki", klon_ekli=True),
        _kayit(adres=3, sinif="I", durum="tek_sinif", fiil="create", anahtar="GIZLI_AD_uc"),
        _kayit(adres=4, sinif="Y", durum="tek_sinif", fiil="get", cagri_yapan=False, yaprak=True,
               yazmaz=True, anahtar="GIZLI_AD_dort"),
        _kayit(adres=5, sinif="I", durum="cok_sinif", siniflar=("add", "open"), api_genis=True,
               anahtar="GIZLI_AD_bes", cok_adli=True),
        _kayit(adres=6, sinif="Y", durum="yalniz_genel", cagri_yapan=False, yaprak=True,
               rol=("handle",), anahtar="GIZLI_AD_alti", ek_acik=("zorp",)),
        _kayit(adres=7, sinif="K", durum="fiilsiz", anahtar="GIZLI_AD_yedi", ek_acik=("zorp", "blen"),
               ek_belirsiz=("quix",)),
        _kayit(adres=8, sinif="K", durum="fiilsiz", anahtar="GIZLI_AD_sekiz", ek_belirsiz=("quix",)),
        _kayit(adres=9, sinif="K", durum="gt_yok"),
        _kayit(adres=10, sinif="Y", durum="parca", cagri_yapan=False, yaprak=True, klon_ekli=True),
        _kayit(adres=11, sinif="I", durum="cpp_disarida"),
    ]


def test_say_sayilari():
    s = ft.say(_ornek_kayitlar())
    assert s["nufus"] == 11
    assert s["durum"] == {"tek_sinif": 4, "cok_sinif": 1, "yalniz_genel": 1, "fiilsiz": 2,
                          "parca": 1, "gt_yok": 1, "cpp_disarida": 1}
    assert s["sozlukte_fiil_var"] == 5 and sum(s["durum"].values()) == s["nufus"]
    pay = {a: n for a, n in s["sinif_payi"].items() if n}
    assert pay == {"open": 1, "destroy": 1, "create": 1, "get": 1}
    assert set(s["sinif_payi"]) == set(ft.on_sayim.FIIL_SOZLUGU)
    uye = {a: n for a, n in s["sinif_uyeligi_cok_dahil"].items() if n}
    assert uye == {"open": 2, "destroy": 1, "create": 1, "get": 1, "add": 1}
    assert s["kiy_durum"]["K"]["tek_sinif"] == 2 and s["kiy_durum"]["I"]["cok_sinif"] == 1
    assert s["kiy_durum"]["Y"]["parca"] == 1 and s["kiy_durum"]["I"]["cpp_disarida"] == 1
    assert sum(sum(v.values()) for v in s["kiy_durum"].values()) == s["nufus"]
    t = s["tavan"]["tek_sinif"]
    assert (t["f_api_fk2"], t["f_api_genis"], t["f_etki_dogrudan"], t["f_etki_sarmalayici"]) == (1, 1, 1, 1)
    assert t["f_etki_cagri"] == 2          # destroy (K) ve create (I)
    assert (t["birlesik_ilk_dar"], t["birlesik_ilk_genis"], t["birlesik_aday_genis"]) == (2, 3, 4)
    assert (t["erisimsiz_ilk"], t["erisimsiz_aday"], t["sozluk"]) == (3, 4, 4)
    d = s["tavan"]["cok_sinif_dahil"]
    assert (d["f_api_genis"], d["f_api_fk2"], d["birlesik_ilk_genis"], d["sozluk"]) == (2, 1, 4, 5)
    assert s["erisim"]["rol"] == 1 and s["rol_erisim_durum"]["yalniz_genel"] == 1
    assert s["rol_erisim_sinifi"] == {"handle": 1}
    assert s["erisim"]["api_genis"] == 2 and s["erisim"]["yaprak"] == 3
    z = s["sozluk_disi"]
    assert (z["aday_ad"], z["acik_tasiyan"], z["acik_ya_da_belirsiz_tasiyan"]) == (3, 2, 3)
    assert (z["farkli_acik"], z["farkli_acik_ya_da_belirsiz"]) == (2, 3)
    assert z["en_sik_acik"] == [2, 1] and z["en_sik_acik_ya_da_belirsiz"] == [2, 2, 1]
    assert s["ad_bicimi"] == {"yalniz_fiil": 0, "fiil_nesne": 3, "nesne_fiil": 1, "onek_fiil_nesne": 0}
    assert s["klon_ekli"]["tek_sinif"] == 1 and s["klon_ekli"]["parca"] == 1
    assert s["diger"]["cok_adli"] == 1 and s["diger"]["ks1_nufusunda"] == 1 and s["diger"]["adli"] == 8


def test_en_sik_on_ile_sinirli():
    ks = [_kayit(adres=i, durum="fiilsiz", ek_acik=(f"t{i % 13}",)) for i in range(40)]
    z = ft.say(ks)["sozluk_disi"]
    assert len(z["en_sik_acik"]) == ft.EN_SIK and z["farkli_acik"] == 13
    assert z["en_sik_acik"] == sorted(z["en_sik_acik"], reverse=True) and z["en_sik_acik"][0] == 4


def test_cikti_ad_ve_belirtec_tasimaz_ve_siradan_bagimsiz():
    ks = _ornek_kayitlar()
    ft.onek_isaretle(ks)
    belge = ft.ozetle(ks)
    metin = json.dumps(belge, ensure_ascii=False, sort_keys=True) + ft.markdown(belge)
    for yasak in ("GIZLI_AD", "zorp", "blen", "quix", "FUN_"):
        assert yasak not in metin
    karisik = _ornek_kayitlar()
    random.Random(3).shuffle(karisik)
    assert json.dumps(ft.ozetle(karisik), sort_keys=True) == json.dumps(belge, sort_keys=True)


def test_tekil_birim_icinde_veya_ile_birlesir():
    ks = [
        _kayit(elf="a", adres=1, durum="tek_sinif", fiil="open", anahtar="x", api_genis=False),
        _kayit(elf="b", adres=1, durum="tek_sinif", fiil="open", anahtar="x", api_genis=True,
               rol=("compare",), ks1_nufusunda=True),
        _kayit(elf="c", adres=1, durum="tek_sinif", fiil="open", anahtar="x", rol=("handle",)),
        _kayit(elf="a", adres=2, durum="fiilsiz", anahtar="y"),
        _kayit(elf="a", adres=3, durum="gt_yok"),
        _kayit(elf="a", adres=4, durum="cpp_disarida"),
        _kayit(birim="mac/p", elf="a", adres=1, durum="tek_sinif", fiil="open", anahtar="x"),
    ]
    t = ft.tekil(ks)
    assert [(k["birim"], k["anahtar"]) for k in t] == [("debian/p", "x"), ("debian/p", "y"), ("mac/p", "x")]
    assert t[0]["api_genis"] and t[0]["ks1_nufusunda"] and t[0]["rol"] == ("compare", "handle")
    assert not t[2]["api_genis"]                  # başka birimin örneği karışmaz
    assert not ks[0]["api_genis"]                 # girdi kayıtları değişmez
    s = ft.say(t)
    assert s["nufus"] == 3 and s["tavan"]["tek_sinif"]["f_api_genis"] == 1


def test_makro_once_program_sonra_esit_agirlik():
    def b(nufus, tek):
        s = ft.say([_kayit(adres=i, durum="tek_sinif" if i < tek else "fiilsiz",
                           fiil="add" if i < tek else None) for i in range(nufus)])
        return s
    m = ft.makro({"mac/tmux": b(10, 10), "debian/tmux": b(10, 0), "debian/tree": b(4, 1),
                  "debian/bos": b(0, 0)})
    assert m["programlar"] == {"tmux": ["debian/tmux", "mac/tmux"], "tree": ["debian/tree"]}
    # tmux (1,0 + 0,0) / 2 = 0,5; tree 0,25; makro 0,375 (havuz 11/24 değil)
    assert m["oran"]["durum.tek_sinif"] == pytest.approx(0.375)
    assert m["oran"]["sinif_payi.add"] == pytest.approx(0.375)
    assert m["oran"]["durum.fiilsiz"] == pytest.approx(0.625)


def test_ozetle_bolumleri():
    ks = _ornek_kayitlar() + [_kayit(birim="mac/tmux", adres=1, durum="tek_sinif", fiil="add", anahtar="m")]
    o = ft.ozetle(ks)
    assert sorted(o["birimler"]) == ["debian/p", "mac/tmux"]
    assert o["havuz"]["ornek"]["nufus"] == 12 and o["mac_ikilisi"]["ornek"]["nufus"] == 1
    assert o["havuz"]["tekil"]["nufus"] == 9      # gt_yok, parça ve C++ tekilde yok
    assert o["birimler"]["debian/p"]["tekil"]["durum"]["gt_yok"] == 0


def test_on_sayimla_karsilastirma(tmp_path):
    ks = _ornek_kayitlar()
    birimler = ft.ozetle(ks)["birimler"]
    j = tmp_path / "on.json"

    def yaz(**degisen):
        sayim = {"isim_bekleyen": 11, "sinif_K": 5, "sinif_I": 3, "sinif_Y": 3}
        sayim.update(degisen)
        j.write_text(json.dumps({"birimler": {"debian/p": {"sayim": sayim}}}), encoding="utf-8")

    yaz()
    assert ft.on_sayimla_karsilastir(birimler, j)["eslesen_birim"] == 1
    for alan in ("isim_bekleyen", "sinif_K", "sinif_I", "sinif_Y"):
        yaz(**{alan: 99})
        with pytest.raises(RuntimeError):
            ft.on_sayimla_karsilastir(birimler, j)
    j.write_text(json.dumps({"birimler": {"debian/baska": {"sayim": {}}}}), encoding="utf-8")
    with pytest.raises(RuntimeError):
        ft.on_sayimla_karsilastir(birimler, j)


def test_elle_denetim_ornegi_tabakalar_ve_tohum():
    ks = []
    for p, birim in enumerate(("mac/a", "debian/b")):
        for d in ("tek_sinif", "fiilsiz", "cok_sinif", "yalniz_genel", "gt_yok"):
            ks += [_kayit(birim=birim, adres=1000 * p + 100 * len(ks) + i, durum=d,
                          fiil="add" if d == "tek_sinif" else None) for i in range(30)]
    o = ft.elle_denetim_ornegi(ks)
    assert len(o) == 40 and len({(k["birim"], k["adres"]) for k in o}) == 40
    say = {(d, m): sum(1 for k in o if k["durum"] == d and k["birim"].startswith("mac/") == m)
           for d, _ in ft.ELLE_TABAKALAR for m in (True, False)}
    assert say == {("tek_sinif", True): 8, ("tek_sinif", False): 8, ("fiilsiz", True): 7,
                   ("fiilsiz", False): 7, ("cok_sinif", True): 3, ("cok_sinif", False): 2,
                   ("yalniz_genel", True): 3, ("yalniz_genel", False): 2}
    karisik = list(ks)
    random.Random(5).shuffle(karisik)
    assert [(k["birim"], k["adres"]) for k in ft.elle_denetim_ornegi(karisik)] == \
        [(k["birim"], k["adres"]) for k in o]


# --------------------------------------------------------------------------------------------
# Uçtan uca: sentetik static/ → on_sayim.elf_say → kayıtlar


def _static_kur(kok: Path) -> Path:
    lib = {0x9000: "_malloc", 0x9010: "_free", 0x9020: "_qsort", 0x9030: "_open", 0x9040: "_fprintf"}
    cagri = {
        0x1000: [0x9000],                           # ayırıcı sarmalayıcısı
        0x1100: [0x1000],                           # sarmalayıcıyı çağıran (kendisi de iletici)
        0x1200: [0x9010],                           # bırakıcıyı doğrudan çağıran
        0x1300: [0x9020],                           # qsort'a 0x1400'ün adresini veriyor
        0x1400: [],                                 # yaprak; karşılaştırıcı
        0x1500: [0x9030, 0x1000, 0x1100, 0x1200, 0x1400],   # ayırt edici API, 4 iç çağrı
        0x1600: [0x9030, 0x9040],                   # ayırt edici API + ileti
        0x1700: [0x1200, 0x1400],                   # bırakıcı sarmalayıcısını çağıran
        0x1900: [0x9000, 0x9030],                   # ayırıcı + başka API: sarmalayıcı değil
        0x1A00: [0x1900, 0x1400],                   # sarmalayıcı olmayanı çağıran
    }
    fonk = [{"address": f"{a:08x}", "name": n, "is_external": False, "is_thunk": True,
             "source": "IMPORTED", "size": 12} for a, n in lib.items()]
    fonk += [{"address": f"{a:08x}", "name": f"FUN_{a:08x}", "is_external": False, "is_thunk": False,
              "source": "DEFAULT", "size": 16} for a in cagri]
    fonk.append({"address": "00001800", "name": "adli_fonksiyon", "is_external": False,
                 "is_thunk": False, "source": "IMPORTED", "size": 16})
    xref = {f"FUN_{a:08x}": {"address": f"{a:08x}", "strings_used": [], "called_by": [],
                             "functions_called": [{"name": "x", "address": f"{h:08x}"} for h in hs]}
            for a, hs in cagri.items()}
    st = kok / "static"
    (st / "ghidra_output" / "decompiled").mkdir(parents=True)
    (st / "ghidra_functions.json").write_text(json.dumps({"functions": fonk}), encoding="utf-8")
    (st / "ghidra_xrefs.json").write_text(json.dumps({"function_xrefs": xref}), encoding="utf-8")
    (st / "ghidra_combined_results.json").write_text(json.dumps(
        {"program_info": {"executable_format": "Mac OS X Mach-O", "processor": "AARCH64"}}),
        encoding="utf-8")
    for a, hs in cagri.items():
        komut = [f"// {a + 4 * i:08x}  bl 0x{h:x}" for i, h in enumerate(hs)]
        if a == 0x1300:
            komut = [f"// {a:08x}  adrp x3,0x1000", f"// {a + 4:08x}  add x3,x3,#0x400",
                     f"// {a + 8:08x}  bl 0x9020"]
        if a == 0x1400:
            komut = [f"// {a:08x}  str w1,[x0, #0x8]"]
        komut.append(f"// {a + 0x40:08x}  ret")
        (st / "ghidra_output" / "decompiled" / f"f_{a:x}.c").write_text(
            f"// Address: {a:08x}\nvoid f(void) {{}}\n\n// --- DISASSEMBLY ({len(komut)} instructions) ---\n"
            + "\n".join(komut) + "\n", encoding="utf-8")
    return st


GT = {0x1000: ["_xgrab"], 0x1100: ["_thing_new"], 0x1200: ["_thing_free"], 0x1300: ["_sort_things"],
      0x1400: ["_thing_cmp"], 0x1500: ["_do_everything"], 0x1600: ["_file_open"],
      0x1700: ["_thing_list_destroy"], 0x1900: ["_OUTLINED_FUNCTION_1"]}


def test_uctan_uca_sentetik_static(tmp_path):
    st = _static_kur(tmp_path)
    sonuc, yerel = ft.elf_ayrinti(st)
    assert set(yerel) == set(ft.GEREKLI_YERELLER)
    ks = ft.elf_kayitlari("mac/p", "p", "mac", yerel, GT, ks1_nufus={0x1100, 0x1800}, ek=EK)
    k = {x["adres"]: x for x in ks}
    assert sorted(k) == [0x1000, 0x1100, 0x1200, 0x1300, 0x1400, 0x1500, 0x1600, 0x1700, 0x1900, 0x1A00]
    assert 0x1800 not in k                                   # adı FUN_ olmayan nüfusta değil
    assert [k[a]["sinif"] for a in sorted(k)] == ["K", "I", "K", "K", "Y", "K", "K", "I", "K", "I"]
    yeniden = ft.yeniden_say(ks)
    for alan in ("isim_bekleyen", "sinif_K", "sinif_I", "sinif_Y"):
        assert yeniden[alan] == sonuc["sayim"][alan]
    assert sum(1 for x in ks if x["api_genis"]) == sonuc["sayim"]["K_ayirt_edici"] == 4
    # F-ETKİ: sarmalayıcı üzerinden create, doğrudan destroy
    assert not k[0x1100]["create_dogrudan"] and k[0x1100]["create_sarmalayici"]
    assert k[0x1200]["destroy_dogrudan"] and k[0x1700]["destroy_sarmalayici"]
    assert not k[0x1700]["destroy_dogrudan"]
    assert not k[0x1A00]["create_sarmalayici"]               # 0x1900 sarmalayıcı değil
    assert k[0x1900]["create_dogrudan"]
    # F-API: fk2 sınırı
    assert k[0x1500]["api_genis"] and not k[0x1500]["api_fk2"] and k[0x1600]["api_fk2"]
    # F-ROL: adresi qsort çağıranda kurulan yaprak
    assert k[0x1400]["rol"] == ("compare",) and k[0x1300]["rol"] == ()
    assert not k[0x1400]["yazmaz"] and k[0x1400]["yaprak"]
    # GT
    assert (k[0x1100]["durum"], k[0x1100]["fiil"]) == ("tek_sinif", "create")
    assert k[0x1500]["durum"] == "yalniz_genel" and k[0x1900]["durum"] == "parca"
    assert k[0x1A00]["durum"] == "gt_yok" and k[0x1000]["durum"] == "fiilsiz"
    assert k[0x1100]["ks1_nufusunda"] and not k[0x1200]["ks1_nufusunda"]
    t = ft.say(ks)["tavan"]["tek_sinif"]
    assert t["f_api_fk2"] == 2               # sort_things (qsort), file_open
    assert (t["f_etki_dogrudan"], t["f_etki_sarmalayici"], t["f_etki_cagri"]) == (1, 3, 3)
    assert t["f_rol"] == 1 and t["birlesik_ilk_dar"] == 6 and t["erisimsiz_ilk"] == 6
    # C++ ELF: GT okunmaz
    cpp = ft.elf_kayitlari("debian/z", "z", "debian", yerel, None)
    assert {x["durum"] for x in cpp} == {"cpp_disarida"} and len(cpp) == len(ks)
    assert not any(ft.say(cpp)["tavan"]["tek_sinif"].values())


def test_elf_ayrinti_degisen_on_sayimi_yakalar(tmp_path, monkeypatch):
    st = _static_kur(tmp_path)
    monkeypatch.setattr(ft, "GEREKLI_YERELLER", ft.GEREKLI_YERELLER | {"olmayan_yerel"})
    with pytest.raises(RuntimeError):
        ft.elf_ayrinti(st)
    assert sys.getprofile() is None


def test_aile_kumeleri_taslakla_ayni():
    assert len(ft.F_API_SINIFLARI) == 14 and len(ft.ILK_SURUM_SINIFLARI) == 18
    assert len(ft.ADAYLI_SINIFLAR) == 23               # compare hem aday hem F-ROL
    assert ft.F_ETKI_ILK == {"create", "destroy"}
    assert not ft.F_API_SINIFLARI & (ft.F_ETKI_ILK | ft.F_ETKI_ADAY)
