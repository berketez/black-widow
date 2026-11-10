"""scripts/measurement/urun_olc.py — ürün adlarının GT'ye karşı ölçümünün testleri.

Bütün testler sentetik verilerle koşar: sentetik çalışma alanları (``naming_map.json``,
``naming_provenance.json``, ``ghidra_functions.json``) ve sentetik GT (``GtBirimi``). Gerçek GT,
dbgsym ya da dSYM okunmaz; GT yükleyiciler (``ks1_olc.gt_elf`` / ``gt_mac``) yerine sentetik
sözlük konur.
Kilitlenen davranışlar:
  (a) anahtar sınıfı: fonksiyon (``FUN_<onaltılık>``), veri, öbür; ölçüye girmeyen girişler,
  (b) hükümler: tam eşitlik, klon satırında taban eşitliği, eşlenemeyen ad yanlış, Mach-O ``_``,
  (c) etiket ve kanal: kayıttaki etiket; etiket alanı olmayan eski koşu; alt kanalın kayıttan ya
      da ürün sınıflayıcısından gelmesi,
  (d) ölçüler: kesinlik paydası (ad verilen), kapsam paydası (ad bekleyen nüfus), Wilson, program
      düzeyi makro, havuz, tabaka,
  (e) kararlar: yanlış oranı hedefi, "kesin" etiketli adların kesinliği, kaybedilen doğru ad,
  (f) eksiksizlik: ikili sayısı, bitmemiş koşu, ad haritası olmayan koşu; C++ ikili dışarıda,
  (g) çıktıda ad yok; aynı girdi aynı çıktı,
  (h) ``karsilastir``: geçiş tablosu, farklar, aynı dosya koşulu.

Mutasyon koruması: ``scripts/measurement/mutation_specs_urun_olc.json``.
"""
from __future__ import annotations

import importlib.util
import json
import math
import sys
from pathlib import Path

import pytest

_KOK = Path(__file__).resolve().parents[1]
_PATH = _KOK / "scripts" / "measurement" / "urun_olc.py"
_spec = importlib.util.spec_from_file_location("urun_olc_under_test", _PATH)
uo = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = uo
_spec.loader.exec_module(uo)
ks1 = uo.ks1

ZAMAN = "20261110_000000"


# --------------------------------------------------------------------------------------------
# Sentetik çalışma alanı ve GT


def fonk(adres, ad=None, thunk=False, dis=False):
    return {"name": ad or f"FUN_{adres:08x}", "address": f"{adres:08x}", "is_thunk": thunk,
            "is_external": dis, "size": 4}


def gt(adlar, nufus=None):
    return ks1.GtBirimi(adlar=dict(adlar), nufus=set(adlar if nufus is None else nufus),
                        export_gt=set(), kunye={"gt": "sentetik"})


def alan_kur(kok, platform_, program, elf, fonksiyonlar, harita, koken=None, bitti=True,
             harita_yaz=True, dosya="sha-1", ust=None, surum="12.1.2"):
    """Bir ikilinin koşu dizini: ``ks1_olc`` yerleşimiyle (Debian'da ``BITTI`` dosyalı)."""
    taban = kok / program / elf if platform_ == "debian" else kok / program
    ws = taban / "ws" / "workspaces" / elf / ZAMAN
    (ws / "static").mkdir(parents=True)
    (ws / "static" / "ghidra_functions.json").write_text(json.dumps({"functions": fonksiyonlar}))
    (ws / "static" / "ghidra_strings.json").write_text(json.dumps({"strings": []}))
    (ws / "raw").mkdir()
    (ws / "raw" / "target_info.json").write_text(json.dumps({"file_hash": dosya}))
    (ws / "reports").mkdir()
    (ws / "reports" / "report.json").write_text(json.dumps(
        {"environment": {"ghidra": {"version": surum, "matches_pinned": True}}}))
    if harita_yaz:
        src = ws / "reconstructed" / "src"
        src.mkdir(parents=True)
        (src / "naming_map.json").write_text(json.dumps({"global": harita, "per_function": {}}))
        if koken is not None:
            (src / "naming_provenance.json").write_text(json.dumps(
                {"schema": "karadul.naming_provenance", "schema_version": 1, "global": koken,
                 **(ust or {})}))
    if bitti and platform_ == "debian":
        (taban / "BITTI").write_text("")
    return ws


def gt_tak(monkeypatch, tablo):
    """GT yükleyiciler yerine sentetik tablo (ikili adı → GtBirimi)."""
    monkeypatch.setattr(ks1, "gt_elf", lambda e, indir: tablo[e.ad])
    monkeypatch.setattr(ks1, "gt_mac", lambda e, veri: tablo[e.ad])


def kayit(ad, durum="dogru", satir="ana", nufusta=True, etiket="etiketsiz", kanal="k", proje=None):
    return {"adres": 0, "ad": ad, "durum": durum, "satir": satir, "nufusta": nufusta,
            "etiket": etiket, "kanal": kanal, "proje": durum == "dogru" if proje is None else proje}


def degerlendir(harita, koken, fonksiyonlar, gt_, platform_="debian"):
    gfonk = [{"addr": int(f["address"], 16), "name": f["name"], "is_thunk": f["is_thunk"], "size": 4}
             for f in fonksiyonlar]
    return uo.degerlendir_elf(harita, koken, gfonk, gt_, platform_)


# --------------------------------------------------------------------------------------------
# (a) anahtar sınıfı ve ölçüye girmeyen girişler


def test_sabitler_ks1_ve_urunden():
    """Aynı kavram yeniden tanımlanmaz: eşikler ``ks1_olc``'den, etiketler ürün sözlüğünden."""
    assert (uo.N_MIN, uo.EN_AZ_PROGRAM, uo.KESIN_ETIKET_ESIGI) == (ks1.N_MIN, ks1.EN_AZ_PROGRAM,
                                                                   ks1.KESINLIK_ESIGI)
    assert (uo.YANLIS_HEDEFI, uo.KAYIP_INCELEME_SINIRI) == (0.10, 0.15)
    assert uo.ETIKETLER == ("kesin", "doğrulandı", "doğrulanmadı", "etiketsiz")
    assert uo.ETIKET_KESIN == "kesin"
    assert uo.BOYUT_SIRASI == ("kucuk", "orta", "buyuk")
    assert uo.HARITA_REL == Path("reconstructed/src/naming_map.json")
    assert uo.KOKEN_REL == Path("reconstructed/src/naming_provenance.json")


def test_anahtar_sinifi():
    assert uo.anahtar_sinifi("FUN_00101000") == ("fonksiyon", 0x101000)
    assert uo.anahtar_sinifi("FUN_100003f00") == ("fonksiyon", 0x100003F00)
    assert uo.anahtar_sinifi("DAT_00130650") == ("veri", None)
    assert uo.anahtar_sinifi("PTR_00130650") == ("veri", None)
    assert uo.anahtar_sinifi("thunk_FUN_00101000") == ("diger", None)   # önek değil, tam biçim
    assert uo.anahtar_sinifi("FUN_xyz") == ("diger", None)
    assert uo.anahtar_sinifi("kayit_yaz") == ("diger", None)


def test_fonksiyon_veri_ayrimi_ve_atlamalar():
    fl = [fonk(0x101000), fonk(0x102000), fonk(0x103000, "bilinen_ad"), fonk(0x104000),
          fonk(0x105000, "entry")]
    harita = {"FUN_00101000": "urun_ad_bir",           # ölçülür
              "FUN_00102000": "FUN_00102000",          # özdeş: ad değil
              "FUN_00103000": "urun_ad_uc",            # Ghidra zaten adlandırmış
              "FUN_00104000": "helper_4000",           # adres etiketi: kimlik iddiası değil
              "FUN_00105000": "urun_ad_bes",           # Ghidra adı jenerik (entry): ölçülür
              "FUN_00109000": "urun_ad_dokuz",         # o adreste Ghidra fonksiyonu yok
              "DAT_00130650": "global_0650", "DAT_00130660": "DAT_00130660",
              "bilinen_ad": "baska_ad"}
    ks, sayac = degerlendir(harita, {}, fl, gt({0x101000: ["urun_ad_bir"], 0x105000: ["_start"]}))
    assert [(k["adres"], k["durum"]) for k in ks] == [(0x101000, "dogru"), (0x105000, "yanlis")]
    assert sayac == {"fonksiyon_anahtari": 6, "ozdes": 1, "ghidra_adli": 1, "jenerik_ad": 1,
                     "ghidra_yok": 1, "veri_anahtari": 2, "veri_ad_verilen": 1,
                     "diger_anahtari": 1, "diger_ad_verilen": 1}


def test_ayni_adres_iki_kez_olcumu_durdurur():
    fl = [fonk(0x101000)]
    with pytest.raises(uo.OnkosulHatasi, match="aynı adres iki kez"):
        degerlendir({"FUN_00101000": "urun_ad_bir", "FUN_101000": "urun_ad_iki"}, {}, fl, gt({}))


# --------------------------------------------------------------------------------------------
# (b) hükümler


def test_hukumler_dogru_yanlis_klon_eslenemeyen():
    fl = [fonk(0x101000 + 0x1000 * i) for i in range(7)]
    harita = {"FUN_00101000": "kume_kur",        # tam eşit
              "FUN_00102000": "Kume_Sil",        # harf farkı: yanlış
              "FUN_00103000": "satir_birak",     # klon ekli GT: taban eşit → doğru
              "FUN_00104000": "kayit_yaz",       # klon ekli GT, taban başka → yanlış
              "FUN_00105000": "gt_siz_ad",       # GT'de karşılığı yok → yanlış
              "FUN_00106000": "agac_gez_2",      # çakışma ekli: tam eşitlikte yanlış, projede doğru
              "FUN_00107000": "takma_iki"}       # GT'nin takma adlarından biri
    g = gt({0x101000: ["kume_kur"], 0x102000: ["kume_sil"], 0x103000: ["satir_birak.cold"],
            0x104000: ["dosya_ac.isra.0"], 0x106000: ["agac_gez"],
            0x107000: ["takma_bir", "takma_iki"]}, nufus={0x101000, 0x102000, 0x106000})
    ks, _ = degerlendir(harita, {}, fl, g)
    assert {k["ad"]: (k["satir"], k["durum"], k["nufusta"]) for k in ks} == {
        "kume_kur": ("ana", "dogru", True), "Kume_Sil": ("ana", "yanlis", True),
        "satir_birak": ("klon", "dogru", False), "kayit_yaz": ("klon", "yanlis", False),
        "gt_siz_ad": ("eslenemedi", "yanlis", False), "agac_gez_2": ("ana", "yanlis", True),
        "takma_iki": ("ana", "dogru", False)}
    proje = {k["ad"]: k["proje"] for k in ks}
    assert proje["agac_gez_2"] is True and proje["gt_siz_ad"] is False and proje["kume_kur"] is True


def test_hukum_macho_alt_cizgi():
    fl = [fonk(0x100001000), fonk(0x100002000)]
    harita = {"FUN_100001000": "komut_bul", "FUN_100002000": "_komut_sil"}
    g = gt({0x100001000: ["_komut_bul"], 0x100002000: ["_komut_sil"]})
    mac, _ = degerlendir(harita, {}, fl, g, "mac")
    assert [k["durum"] for k in mac] == ["dogru", "yanlis"]      # yalnız GT'nin tek ``_``'ı soyulur
    deb, _ = degerlendir(harita, {}, fl, g, "debian")
    assert [k["durum"] for k in deb] == ["yanlis", "dogru"]


# --------------------------------------------------------------------------------------------
# (c) etiket ve kanal


def test_etiket_oku():
    assert uo.etiket_oku({"label": "kesin"}) == "kesin"
    assert uo.etiket_oku({"label": "doğrulanmadı"}) == "doğrulanmadı"
    assert uo.etiket_oku({"strategy": "string_context"}) == "etiketsiz"     # eski koşu: alan yok
    assert uo.etiket_oku({"label": "cok_emin"}) == "etiketsiz"              # sözlük dışı değer
    assert uo.etiket_oku(None) == "etiketsiz"


def test_kanal_oku():
    k = uo.kanal_oku
    assert k({"strategy": "ks1", "ks1": {"satirlar": ["func_kalibi"]}}) == ("ks1:func_kalibi", None)
    assert k({"strategy": "ks1", "ks1": {"satirlar": ["assert", "func_kalibi"]},
              "pre_name_kind": "ks1"}) == ("ks1:assert+func_kalibi", None)
    assert k({"strategy": "binary_extract", "pre_name_kind": "main_giris"}) == ("on_ad:main_giris", None)
    assert k({"strategy": "binary_extract"}) == ("binary_extract", None)
    assert k({"strategy": "api_param_reverse"}) == ("api_param_reverse", None)
    assert k(None) == ("koken_yok", None) and k({}) == ("koken_yok", None)
    assert k({"new_name": "x"}) == ("koken_yok", None)                      # strateji yok
    # string_context: alt kanal kayıtta
    oz = {"strategy": "string_context", "evidence": "kume_kur", "new_name": "kume_kur",
          "code_path": "classic", "evidence_origin": "string_ref"}
    assert k({**oz, "sub_channel": "oz_ad"}) == ("string_context/oz_ad", "kayittan")
    # eski koşu: alt kanal yok → ürün sınıflayıcısıyla
    assert k(oz) == ("string_context/oz_ad", "sonradan")
    assert k({**oz, "evidence": "monitor-activity", "new_name": "monitor_activity"}) == (
        "string_context/kebap_ad", "sonradan")
    assert k({**oz, "code_path": "aggressive"}) == ("string_context/agresif", "sonradan")
    # kayıttaki alt kanal sınıflayıcıyla uyuşmuyor: kayıttaki kullanılır, uyuşmazlık işaretlenir
    assert k({**oz, "sub_channel": "kebap_ad"}) == ("string_context/kebap_ad", "uyusmuyor")


def test_degerlendir_etiket_kanal_ve_alt_kanal_sayaci():
    fl = [fonk(0x101000 + 0x1000 * i) for i in range(5)]
    harita = {f"FUN_{0x101000 + 0x1000 * i:08x}": f"urun_ad_{i}" for i in range(5)}
    oz = {"strategy": "string_context", "evidence": "urun_ad_1", "new_name": "urun_ad_1",
          "code_path": "classic", "evidence_origin": "string_ref"}
    koken = {"FUN_00101000": {"strategy": "ks1", "label": "kesin", "ks1": {"satirlar": ["func_kalibi"]}},
             "FUN_00102000": {**oz, "label": "doğrulanmadı", "sub_channel": "oz_ad"},
             "FUN_00103000": {**oz, "evidence": "urun_ad_2", "new_name": "urun_ad_2"},
             "FUN_00104000": {**oz, "sub_channel": "tek_sozcuk", "label": "doğrulanmadı"}}
    ks, sayac = degerlendir(harita, koken, fl, gt({}))
    assert [(k["etiket"], k["kanal"]) for k in ks] == [
        ("kesin", "ks1:func_kalibi"), ("doğrulanmadı", "string_context/oz_ad"),
        ("etiketsiz", "string_context/oz_ad"), ("doğrulanmadı", "string_context/tek_sozcuk"),
        ("etiketsiz", "koken_yok")]
    assert (sayac["alt_kanal_kayittan"], sayac["alt_kanal_sonradan"], sayac["alt_kanal_uyusmuyor"]) == (1, 1, 1)


# --------------------------------------------------------------------------------------------
# (d) ölçüler


def _wilson(k, n, z=1.959963984540054):
    p = k / n
    payda = 1 + z * z / n
    merkez = (p + z * z / (2 * n)) / payda
    yari = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / payda
    return [max(0.0, merkez - yari), min(1.0, merkez + yari)]


def test_olcu_paydalari_ve_wilson():
    """Kesinliğin paydası ad verilen bütün fonksiyonlar; kapsamın paydası ad bekleyen nüfus ve payı
    yalnız nüfustaki adlar."""
    ks = ([kayit(f"a{i}") for i in range(6)] + [kayit(f"b{i}", "yanlis") for i in range(2)]
          + [kayit("c0", nufusta=False), kayit("c1", "yanlis", nufusta=False)])
    o = uo.olcu(ks, nufus=40)
    assert (o["ad_verilen"], o["dogru"], o["yanlis"], o["nufus"]) == (10, 7, 3, 40)
    assert (o["kesinlik"]["k"], o["kesinlik"]["n"]) == (7, 10)
    assert (o["yanlis_orani"]["k"], o["yanlis_orani"]["n"]) == (3, 10)
    assert (o["kapsam"]["k"], o["kapsam"]["n"]) == (8, 40)
    assert (o["dogru_kapsam"]["k"], o["dogru_kapsam"]["n"]) == (6, 40)
    assert o["kesinlik"]["oran"] == 0.7 and o["kapsam"]["oran"] == 0.2
    for alan, (k, n) in {"kesinlik": (7, 10), "yanlis_orani": (3, 10), "kapsam": (8, 40),
                         "dogru_kapsam": (6, 40)}.items():
        assert o[alan]["aralik"] == pytest.approx(_wilson(k, n), abs=1e-4)
    bos = uo.olcu([], nufus=5)
    assert bos["kesinlik"] == {"k": 0, "n": 0, "oran": None, "aralik": None}
    assert (bos["kapsam"]["k"], bos["kapsam"]["n"]) == (0, 5)


def test_fonksiyon_ozeti_dokum_ve_duyarlilik():
    ks = [kayit("xmalloc"), kayit("xmalloc", "yanlis"), kayit("quote"), kayit("quote"),
          kayit("klon_ad", satir="klon", nufusta=False),
          kayit("klon_yanlis", "yanlis", satir="klon", nufusta=False),
          kayit("gt_siz", "yanlis", satir="eslenemedi", nufusta=False, proje=False),
          kayit("ekli_2", "yanlis", proje=True)]
    o = uo.fonksiyon_ozeti(ks, nufus=20)
    assert o["satir"] == {"ana": {"n": 5, "dogru": 3}, "klon": {"n": 2, "dogru": 1},
                          "eslenemedi": {"n": 1, "dogru": 0}}
    assert (o["nufus_ici_kesinlik"]["k"], o["nufus_ici_kesinlik"]["n"]) == (3, 5)
    assert (o["proje_normallestirmesi"]["k"], o["proje_normallestirmesi"]["n"]) == (5, 8)
    # tekil: xmalloc (bir örneği yanlış → yanlış), quote, klon_ad doğru; 6 ayrı ad
    assert (o["tekil_kesinlik"]["k"], o["tekil_kesinlik"]["n"]) == (2, 6)
    assert (o["kesinlik"]["k"], o["kesinlik"]["n"]) == (4, 8)


def test_kirilim_etiket_ve_kanal():
    ks = [kayit("a", etiket="kesin", kanal="ks1:func_kalibi"),
          kayit("b", "yanlis", etiket="kesin", kanal="ks1:func_kalibi"),
          kayit("c", etiket="doğrulanmadı", kanal="string_context/oz_ad", nufusta=False)]
    o = uo.birim_ozeti(ks, nufus=10)
    assert list(o["etiket"]) == ["doğrulanmadı", "kesin"]
    assert (o["etiket"]["kesin"]["kesinlik"]["k"], o["etiket"]["kesin"]["kesinlik"]["n"]) == (1, 2)
    assert o["etiket"]["kesin"]["kapsam"]["k"] == 2 and o["etiket"]["kesin"]["kapsam"]["n"] == 10
    assert o["etiket"]["doğrulanmadı"]["kapsam"]["k"] == 0
    assert list(o["kanal"]) == ["ks1:func_kalibi", "string_context/oz_ad"]
    assert o["kanal"]["string_context/oz_ad"]["ad_verilen"] == 1
    assert o["fonksiyon"]["ad_verilen"] == 3
    assert list(o["kanal_grubu"]) == ["kalan"] and o["kanal_grubu"]["kalan"]["ad_verilen"] == 3


def test_kanal_grubu_urunun_susan_kumesi():
    """Grup ürünün karar tablosundan okunur: susan dokuz ``string_context`` alt kanalı, kalan her şey."""
    g = uo.kanal_grubu
    alt = uo.alt_kanal
    assert {a for a in alt.SUBCHANNEL_NAMES if g(f"string_context/{a}") == "susan"} == set(alt.SILENCED_SUBCHANNELS)
    assert len(alt.SILENCED_SUBCHANNELS) == 9
    assert g("string_context/tek_sozcuk") == "susan" and g("string_context/agresif") == "susan"
    assert g("string_context/oz_ad") == "kalan" and g("string_context/kebap_ad") == "kalan"
    for kanal in ("ks1:func_kalibi", "binary_extract", "api_param_reverse", "on_ad:main_giris",
                  "koken_yok", "string_context", "api_param_reverse/tek_sozcuk"):
        assert g(kanal) == "kalan"
    ks = [kayit("a", kanal="string_context/tek_sozcuk"), kayit("b", "yanlis", kanal="string_context/duz_metin"),
          kayit("c", kanal="string_context/oz_ad"), kayit("d", kanal="binary_extract", nufusta=False)]
    o = uo.birim_ozeti(ks, nufus=10)["kanal_grubu"]
    assert (o["susan"]["ad_verilen"], o["susan"]["dogru"]) == (2, 1)
    assert (o["kalan"]["ad_verilen"], o["kalan"]["dogru"], o["kalan"]["kapsam"]["k"]) == (2, 2, 1)


def test_program_makrosu():
    """Aynı programın platform birimleri önce ortalanır, sonra programlar eşit ağırlıkla; paydası
    N_MIN'in altındaki birim girmez."""
    o = ks1.oran
    m = uo.program_makrosu({"mac/tmux": o(100, 100), "debian/tmux": o(25, 50),
                            "debian/openssl": o(4, 16), "debian/tree": o(9, 9), "debian/htop": o(0, 0)})
    assert m["giren_birimler"] == ["debian/openssl", "debian/tmux", "mac/tmux"]
    assert m["kucuk_birimler"] == ["debian/tree"]
    assert m["program"] == {"openssl": 0.25, "tmux": 0.75}
    assert m["makro"] == 0.5          # birim düzeyinde ortalama (1 + 0,5 + 0,25) / 3 = 0,583 olurdu
    assert uo.program_makrosu({})["makro"] is None
    assert uo.program_makrosu({"debian/tree": o(9, 9)})["makro"] is None
    assert uo.program_makrosu({"debian/tree": o(10, 10)})["makro"] == 1.0    # sınır: n = N_MIN girer


def test_havuz_toplar():
    a, b = uo.fonksiyon_ozeti([kayit("x"), kayit("y", "yanlis")], 10), uo.fonksiyon_ozeti([kayit("z")], 30)
    h = uo.havuz([a, b], uo.KARAR_OLCULERI)
    assert (h["ad_verilen"], h["dogru"], h["yanlis"], h["nufus"]) == (3, 2, 1, 40)
    assert (h["kesinlik"]["k"], h["kesinlik"]["n"]) == (2, 3)
    assert (h["kapsam"]["k"], h["kapsam"]["n"]) == (3, 40)


def _birim(kayitlar, nufus, boyut="orta", zenginlik="zengin", ortanca=1000):
    return {"ozet": uo.birim_ozeti(kayitlar, nufus), "nufus": nufus,
            "sinif": {"boyut_tabakasi": boyut, "zenginlik_sinifi": zenginlik,
                      "ic_fonksiyon_ortanca": ortanca}}


def _cok(n, dogru, on="a", **kw):
    return [kayit(f"{on}{i}", "dogru" if i < dogru else "yanlis", **kw) for i in range(n)]


def test_toplam_ve_tabaka_ozeti():
    birimler = {"debian/tmux": _birim(_cok(20, 10, etiket="kesin"), 100, "orta"),
                "mac/tmux": _birim(_cok(20, 20), 200, "buyuk"),
                "debian/tree": _birim(_cok(10, 1), 50, "kucuk", "yoksul")}
    t = uo.toplam_ozeti(birimler)
    assert t["fonksiyon"]["havuz"]["ad_verilen"] == 50 and t["fonksiyon"]["havuz"]["nufus"] == 350
    assert t["fonksiyon"]["makro"]["kesinlik"]["makro"] == pytest.approx((0.75 + 0.1) / 2)
    assert t["fonksiyon"]["makro"]["yanlis_orani"]["makro"] == pytest.approx((0.25 + 0.9) / 2)
    # etiket kırılımı: etiketi taşımayan birim kapsam paydasına nüfusuyla girer
    kesin = t["etiket"]["kesin"]["havuz"]
    assert (kesin["ad_verilen"], kesin["kapsam"]["n"]) == (20, 350)
    assert t["etiket"]["kesin"]["makro"]["kesinlik"]["giren_birimler"] == ["debian/tmux"]
    tb = uo.tabaka_ozeti(birimler)
    assert set(tb) == {"boyut_tabakasi", "zenginlik_sinifi"}
    assert tb["boyut_tabakasi"]["kucuk"]["birimler"] == ["debian/tree"]
    assert tb["boyut_tabakasi"]["kucuk"]["havuz"]["dogru"] == 1
    assert tb["zenginlik_sinifi"]["zengin"]["birimler"] == ["debian/tmux", "mac/tmux"]
    assert tb["zenginlik_sinifi"]["zengin"]["makro"]["kesinlik"]["makro"] == 0.75
    assert uo.birim_sirasi(birimler) == ["debian/tree", "debian/tmux", "mac/tmux"]   # küçükten büyüğe


# --------------------------------------------------------------------------------------------
# (e) kol kararları


def test_karar_yanlis_orani_hedefi():
    """(a) makro yanlış oranı ≤ %10: sınırda tutar; kesirle karşılaştırılır."""
    b = {"debian/a": _birim(_cok(10, 9), 50), "debian/b": _birim(_cok(20, 18), 50)}
    k = uo.kol_kararlari(b)["yanlis_orani"]
    assert (k["makro"], k["karar"], k["esik"]) == (0.1, "tutuyor", 0.10)
    b["debian/b"] = _birim(_cok(20, 17), 50)
    assert uo.kol_kararlari(b)["yanlis_orani"]["karar"] == "tutmuyor"
    # tek program: yetersiz (aynı programın iki platformu tek programdır)
    tek = {"debian/tmux": _birim(_cok(10, 10), 50), "mac/tmux": _birim(_cok(10, 10), 50)}
    k = uo.kol_kararlari(tek)["yanlis_orani"]
    assert (k["makro"], k["karar"]) == (0.0, "yetersiz")
    assert uo.kol_kararlari({})["yanlis_orani"]["karar"] == "yetersiz"


def test_karar_kesin_etiketli_adlar():
    """(b) "kesin" etiketli adların makro kesinliği ≥ %95; öbür etiketler karara girmez."""
    def birim(n, dogru):
        return _birim(_cok(n, dogru, etiket="kesin") + _cok(30, 0, on="z", etiket="doğrulanmadı"), 1000)
    b = {"debian/a": birim(10, 10), "debian/b": birim(10, 9)}
    k = uo.kol_kararlari(b)["kesin_etiket"]
    assert (k["makro"], k["karar"], k["esik"], k["etiket"]) == (0.95, "tutuyor", 0.95, "kesin")
    assert k["wilson_ihlali"] == []
    b["debian/b"] = birim(20, 17)
    assert uo.kol_kararlari(b)["kesin_etiket"]["karar"] == "tutmuyor"
    # Wilson üst sınırı eşiğin altındaki birim listelenir (100'de 90: üst sınır %94,5)
    b = {"debian/a": birim(100, 100), "debian/b": birim(100, 90)}
    k = uo.kol_kararlari(b)["kesin_etiket"]
    assert k["wilson_ihlali"] == ["debian/b"] and k["makro"] == 0.95
    # "kesin" etiketli ad yok (eski koşu): yetersiz
    eski = {"debian/a": _birim(_cok(10, 9), 50), "debian/b": _birim(_cok(10, 9), 50)}
    k = uo.kol_kararlari(eski)["kesin_etiket"]
    assert (k["makro"], k["karar"], k["giren_birimler"]) == (None, "yetersiz", [])


# --------------------------------------------------------------------------------------------
# Uçtan uca: sentetik koşu kökü


GIZLI = ["urun_ad_bir", "urun_ad_iki", "urun_ad_uc", "urun_ad_dort", "gercek_ad_iki", "gercek_ad_dort",
         "mac_ad_bir", "veri_ad_gizli", "cpp_ad_gizli"]
BEKLENEN = {"debian/tmux": 1, "debian/zstd": 2, "mac/tmux": 1}


def kok_kur(tmp_path, ad="taban", yeni=False):
    """Üç birimli sentetik koşu kökü. ``yeni``: etiketli köken kaydı ve değişmiş adlarla ikinci kol."""
    deb, mac = tmp_path / ad / "debian", tmp_path / ad / "mac"
    fl = [fonk(0x101000 + 0x1000 * i) for i in range(4)] + [fonk(0x109000, "puts", thunk=True)]
    oz = {"strategy": "string_context", "code_path": "classic", "evidence_origin": "string_ref"}
    if not yeni:
        harita = {"FUN_00101000": "urun_ad_bir", "FUN_00102000": "urun_ad_iki",
                  "FUN_00103000": "urun_ad_uc", "DAT_00130000": "veri_ad_gizli"}
        koken = {"FUN_00101000": {**oz, "evidence": "urun_ad_bir", "new_name": "urun_ad_bir"},
                 "FUN_00102000": {**oz, "evidence": "urun kayit yaz %s", "new_name": "urun_ad_iki"},
                 "FUN_00103000": {"strategy": "binary_extract"}}
        ust = None
    else:
        harita = {"FUN_00101000": "urun_ad_bir", "FUN_00102000": "gercek_ad_iki",
                  "FUN_00104000": "urun_ad_dort"}
        koken = {"FUN_00101000": {**oz, "evidence": "urun_ad_bir", "new_name": "urun_ad_bir",
                                  "sub_channel": "oz_ad", "label": "doğrulanmadı"},
                 "FUN_00102000": {"strategy": "ks1", "label": "kesin", "pre_name_kind": "ks1",
                                  "ks1": {"satirlar": ["func_kalibi"]}},
                 "FUN_00104000": {"strategy": "api_param_reverse", "label": "doğrulanmadı"}}
        ust = {"silencing": {"enabled": True}, "global_min_confidence": 0.7}
    alan_kur(deb, "debian", "tmux", "tmux", fl, harita, koken, ust=ust)
    alan_kur(deb, "debian", "zstd", "zstd", fl, {"FUN_00101000": "urun_ad_bir"}, {}, dosya="sha-2", ust=ust)
    cpp = fl + [fonk(0x10A000, "__gxx_personality_v0", thunk=True)]
    alan_kur(deb, "debian", "zstd", "pzstd", cpp, {"FUN_00101000": "cpp_ad_gizli"}, {}, dosya="sha-3")
    mfl = [fonk(0x100001000), fonk(0x100002000)]
    alan_kur(mac, "mac", "tmux", "tmux", mfl, {"FUN_100001000": "mac_ad_bir"}, {}, dosya="sha-4", ust=ust)
    return mac, deb


GT_TABLOSU = {
    "zstd": gt({0x101000: ["baska_ad"], 0x102000: ["x"], 0x103000: ["y"]}),
    "pzstd": gt({0x101000: ["cpp_ad_gizli"]}),     # C++ ikili: GT'si olsa da ölçülmemeli
}


def gt_tablosu(monkeypatch):
    deb_tmux = gt({0x101000: ["urun_ad_bir"], 0x102000: ["gercek_ad_iki"], 0x103000: ["urun_ad_uc.isra.0"],
                   0x104000: ["gercek_ad_dort"]}, nufus={0x101000, 0x102000, 0x104000})
    mac_tmux = gt({0x100001000: ["_mac_ad_bir"], 0x100002000: ["_mac_ad_iki"]})
    monkeypatch.setattr(ks1, "gt_elf", lambda e, indir: deb_tmux if e.ad == "tmux" else GT_TABLOSU[e.ad])
    monkeypatch.setattr(ks1, "gt_mac", lambda e, veri: mac_tmux)


def olc_kos(tmp_path, monkeypatch, ad="taban", yeni=False, **kw):
    mac, deb = kok_kur(tmp_path, ad, yeni)
    gt_tablosu(monkeypatch)
    kw.setdefault("beklenen", BEKLENEN)
    return uo.olc(ks1.elfleri_topla(mac, deb), None, None, kol={"ad": ad}, **kw)


def test_olc_uctan_uca_eski_kosu(tmp_path, monkeypatch):
    s = olc_kos(tmp_path, monkeypatch)
    assert s["sema"] == "karadul-urun-olc/1" and list(s["birimler"]) == ["debian/tmux", "debian/zstd", "mac/tmux"]
    t = s["birimler"]["debian/tmux"]
    f = t["ozet"]["fonksiyon"]
    # urun_ad_bir doğru; urun_ad_iki yanlış; urun_ad_uc klon satırında doğru (nüfus dışı)
    assert (f["ad_verilen"], f["dogru"], f["yanlis"], t["nufus"]) == (3, 2, 1, 3)
    assert (f["kapsam"]["k"], f["kapsam"]["n"]) == (2, 3)
    assert (f["dogru_kapsam"]["k"], f["dogru_kapsam"]["n"]) == (1, 3)
    assert f["satir"]["klon"] == {"n": 1, "dogru": 1}
    # etiket alanı olmayan eski koşu: hepsi etiketsiz; alt kanal sonradan sınıflanır
    assert list(t["ozet"]["etiket"]) == ["etiketsiz"]
    assert list(t["ozet"]["kanal"]) == ["binary_extract", "string_context/bicim_dizgisi", "string_context/oz_ad"]
    assert t["anahtar_sayaci"] == {"alt_kanal_sonradan": 2, "fonksiyon_anahtari": 3, "veri_ad_verilen": 1,
                                   "veri_anahtari": 1}
    assert s["kol_kimligi"] == {'{"genel_esik": null, "koken_var": true, "susturma": null}': 3}
    assert s["kararlar"]["kesin_etiket"]["karar"] == "yetersiz"
    # kanal grubu: bicim_dizgisi üründe susan kanal; oz_ad ve ön ad kalır
    assert {d: (o["ad_verilen"], o["dogru"]) for d, o in t["ozet"]["kanal_grubu"].items()} == {
        "kalan": (2, 2), "susan": (1, 0)}
    kalan = s["toplam"]["kanal_grubu"]["kalan"]["havuz"]
    assert (kalan["ad_verilen"], kalan["dogru"], kalan["kapsam"]["n"]) == (4, 3, 8)
    # C++ ikili ölçü dışı: adı sayılmaz, nüfusa girmez
    z = s["birimler"]["debian/zstd"]
    assert z["cpp_disarida"] == ["pzstd"] and list(z["elfler"]) == ["zstd"]
    assert z["ozet"]["fonksiyon"]["ad_verilen"] == 1 and z["nufus"] == 3
    # Mach-O: GT'nin baştaki ``_``'ı soyulur
    m = s["birimler"]["mac/tmux"]["ozet"]["fonksiyon"]
    assert (m["ad_verilen"], m["dogru"], m["kapsam"]["n"]) == (1, 1, 2)
    h = s["toplam"]["fonksiyon"]["havuz"]
    assert (h["ad_verilen"], h["dogru"], h["yanlis"], h["nufus"]) == (5, 3, 2, 8)
    assert s["ogeler"]["debian/tmux"]["tmux"] == {
        "101000": "dogru ana 1 etiketsiz string_context/oz_ad",
        "102000": "yanlis ana 1 etiketsiz string_context/bicim_dizgisi",
        "103000": "dogru klon 0 etiketsiz binary_extract"}
    assert s["birimler"]["debian/tmux"]["elfler"]["tmux"]["dosya_sha256"] == "sha-1"
    assert s["arac"]["ghidra_surumleri"] == {"12.1.2": 4}
    assert s["nufus"]["sorunlar"] == [] and s["ayni_dosyalar"] == []


def test_olc_yeni_kosu_etiket_ve_kimlik(tmp_path, monkeypatch):
    s = olc_kos(tmp_path, monkeypatch, "yeni", yeni=True)
    t = s["birimler"]["debian/tmux"]["ozet"]
    assert list(t["etiket"]) == ["doğrulanmadı", "kesin"]
    assert (t["etiket"]["kesin"]["ad_verilen"], t["etiket"]["kesin"]["dogru"]) == (1, 1)
    assert (t["etiket"]["doğrulanmadı"]["ad_verilen"], t["etiket"]["doğrulanmadı"]["dogru"]) == (2, 1)
    assert list(t["kanal"]) == ["api_param_reverse", "ks1:func_kalibi", "string_context/oz_ad"]
    assert s["birimler"]["debian/tmux"]["anahtar_sayaci"]["alt_kanal_kayittan"] == 1
    assert '{"genel_esik": 0.7, "koken_var": true, "susturma": true}' in s["kol_kimligi"]
    kesin = s["toplam"]["etiket"]["kesin"]["havuz"]
    assert (kesin["ad_verilen"], kesin["dogru"], kesin["kapsam"]["n"]) == (1, 1, 8)
    # etiket × kanal: "kesin" etiketi yalnız KS-1 kanalından; susan grupta ad yok
    assert s["etiket_kanal"] == {
        "doğrulanmadı": {"api_param_reverse": {"ad_verilen": 1, "dogru": 0},
                         "string_context/oz_ad": {"ad_verilen": 1, "dogru": 1}},
        "etiketsiz": {"koken_yok": {"ad_verilen": 2, "dogru": 1}},
        "kesin": {"ks1:func_kalibi": {"ad_verilen": 1, "dogru": 1}}}
    assert list(s["toplam"]["kanal_grubu"]) == ["kalan"]
    assert "| `kesin` | `ks1:func_kalibi` | 1 | 1 |" in uo.olc_markdown(s)


def test_ciktida_ad_yok_ve_belirlenimci(tmp_path, monkeypatch):
    s1 = olc_kos(tmp_path / "bir", monkeypatch)
    s2 = olc_kos(tmp_path / "bir2", monkeypatch)
    m1 = json.dumps(s1, ensure_ascii=False, indent=1)
    md = uo.olc_markdown(s1)
    for ad in GIZLI + ["baska_ad"]:
        assert ad not in m1 and ad not in md
    # aynı girdi aynı çıktı (kök yolu künyede olmadığı için iki ayrı dizin de aynı belgeyi verir)
    assert m1 == json.dumps(s2, ensure_ascii=False, indent=1)
    assert "| debian/tmux | 1 | `kucuk` |" in md and "C++ (ölçü dışı): debian/zstd: pzstd." in md
    assert "| Havuz | 5 | 3 | 2 | 3/5 (%60,0;" in md


def test_koken_dosyasi_yoksa_kanal_koken_yok(tmp_path, monkeypatch):
    deb = tmp_path / "debian"
    alan_kur(deb, "debian", "tmux", "tmux", [fonk(0x101000)], {"FUN_00101000": "urun_ad_bir"}, None)
    monkeypatch.setattr(ks1, "gt_elf", lambda e, indir: gt({0x101000: ["urun_ad_bir"]}))
    s = uo.olc(ks1.elfleri_topla(None, deb), None, None, beklenen={"debian/tmux": 1})
    o = s["birimler"]["debian/tmux"]["ozet"]
    assert list(o["kanal"]) == ["koken_yok"] and list(o["etiket"]) == ["etiketsiz"]
    assert s["kol_kimligi"] == {'{"genel_esik": null, "koken_var": false, "susturma": null}': 1}


def test_haritayi_oku_global_yoksa_durur(tmp_path):
    ws = alan_kur(tmp_path, "debian", "tmux", "tmux", [fonk(0x101000)], {})
    (ws / "reconstructed" / "src" / "naming_map.json").write_text(json.dumps({"mappings": {}}))
    with pytest.raises(uo.OnkosulHatasi, match="'global' sözlüğü yok"):
        uo.haritayi_oku(ws)


# --------------------------------------------------------------------------------------------
# (f) eksiksizlik


def test_eksiksizlik_ikili_sayisi_bitmemis_ve_haritasiz(tmp_path, monkeypatch):
    gt_tablosu(monkeypatch)
    mac, deb = kok_kur(tmp_path)
    elfler = ks1.elfleri_topla(mac, deb)
    # beklenen sayı tutmuyor: ölçüm durur
    with pytest.raises(uo.OnkosulHatasi, match="debian/zstd: 2 ELF bulundu, beklenen 3"):
        uo.olc(elfler, None, None, beklenen={**BEKLENEN, "debian/zstd": 3})
    # varsayılan beklenti geliştirme setinin tamamıdır (119 ikili)
    with pytest.raises(uo.OnkosulHatasi, match="debian/coreutils: 0 ELF bulundu, beklenen 106"):
        uo.olc(elfler, None, None)
    # ad haritası yazılmamış koşu bitmemiş sayılır
    (ks1.debian_elfleri(deb)[0].kosu / uo.HARITA_REL).unlink()
    elfler = ks1.elfleri_topla(mac, deb)
    with pytest.raises(uo.OnkosulHatasi, match="1 ELF bitmemiş"):
        uo.olc(elfler, None, None, beklenen=BEKLENEN)
    s = uo.olc(elfler, None, None, beklenen=BEKLENEN, eksik_izinli=True)
    assert len(s["nufus"]["sorunlar"]) == 1 and "debian/tmux/tmux" in s["nufus"]["sorunlar"][0]
    assert "debian/tmux" not in s["birimler"] and s["nufus"]["eksik_izinli"] is True
    # BITTI dosyası olmayan Debian koşusu da bitmemiştir
    (deb / "zstd" / "zstd" / "BITTI").unlink()
    with pytest.raises(uo.OnkosulHatasi, match="2 ELF bitmemiş"):
        uo.olc(ks1.elfleri_topla(mac, deb), None, None, beklenen=BEKLENEN)


def test_haritasizlari_isaretle(tmp_path):
    ws = alan_kur(tmp_path, "debian", "tmux", "tmux", [fonk(0x101000)], {}, harita_yaz=False)
    e = ks1.Elf("debian", "tmux", "tmux", ws / "static", ws)
    bekleyen = ks1.Elf("debian", "tmux", "x", None, ws)
    isaretli = uo.haritasizlari_isaretle([e, bekleyen])
    assert [x.static for x in isaretli] == [None, None]
    (ws / "reconstructed" / "src").mkdir(parents=True)
    (ws / "reconstructed" / "src" / "naming_map.json").write_text("{}")
    assert uo.haritasizlari_isaretle([e])[0].static == ws / "static"


def test_ayni_dosyalar_listelenir(tmp_path, monkeypatch):
    deb = tmp_path / "debian"
    for elf in ("redis-a", "redis-b", "redis-c"):
        alan_kur(deb, "debian", "redis", elf, [fonk(0x101000)], {}, {},
                 dosya="ayni" if elf != "redis-c" else "ayri")
    monkeypatch.setattr(ks1, "gt_elf", lambda e, indir: gt({}))
    s = uo.olc(ks1.elfleri_topla(None, deb), None, None, beklenen={"debian/redis": 3})
    assert s["ayni_dosyalar"] == [["debian/redis/redis-a", "debian/redis/redis-b"]]


# --------------------------------------------------------------------------------------------
# (h) karsilastir


def iki_kol(tmp_path, monkeypatch):
    return (olc_kos(tmp_path, monkeypatch, "taban"), olc_kos(tmp_path, monkeypatch, "yeni", yeni=True))


def test_karsilastir_gecis_ve_farklar(tmp_path, monkeypatch):
    """debian/tmux: 101000 doğru→doğru, 102000 yanlış→doğru (kazanılan), 103000 doğru→adsız
    (kaybedilen), 104000 adsız→yanlış (yeni yanlış)."""
    taban, yeni = iki_kol(tmp_path, monkeypatch)
    k = uo.karsilastir(taban, yeni)
    assert k["sema"] == "karadul-urun-karsilastir/1" and k["sorunlar"] == [] and k["ghidra_ayni"] is True
    t = k["birimler"]["debian/tmux"]
    assert t["taban"] == {"ad_verilen": 3, "dogru": 2, "yanlis": 1, "yanlis_orani": ks1.oran(1, 3)}
    assert (t["yeni"]["ad_verilen"], t["yeni"]["dogru"], t["yeni"]["yanlis"]) == (3, 2, 1)
    assert t["gecis"] == {"adsiz>dogru": 0, "adsiz>yanlis": 1, "dogru>adsiz": 1, "dogru>dogru": 1,
                          "dogru>yanlis": 0, "yanlis>adsiz": 0, "yanlis>dogru": 1, "yanlis>yanlis": 0}
    assert (t["kaybedilen_dogru"], t["kaybedilen_silinen"], t["kaybedilen_yanlisa_donen"]) == (1, 1, 0)
    assert (t["kazanilan_dogru"], t["giderilen_yanlis"], t["yeni_yanlis"]) == (1, 1, 1)
    assert (t["kayip_orani"]["k"], t["kayip_orani"]["n"]) == (1, 2)
    assert t["kayip_kanali"] == {"binary_extract": 1} and t["kazanc_kanali"] == {"ks1:func_kalibi": 1}
    assert t["nufus"] == {"taban": 3, "yeni": 3} and t["elf"] == 1
    top = k["toplam"]
    assert (top["taban"]["ad_verilen"], top["taban"]["dogru"], top["yeni"]["dogru"]) == (5, 3, 3)
    assert (top["kaybedilen_dogru"], top["kazanilan_dogru"], top["yeni_yanlis"]) == (1, 1, 1)
    assert (top["kayip_orani"]["havuz"]["k"], top["kayip_orani"]["havuz"]["n"]) == (1, 3)
    assert top["kayip_kanali"] == {"binary_extract": 1}
    kd = k["kararlar"]["kaybedilen_dogru"]
    assert kd["karar"] == "incele" and kd["sinir"] == 0.15 and kd["siniri_asan_birimler"] == []
    assert k["kollar"]["yeni"]["kesin_etiket"]["havuz"]["ad_verilen"] == 1
    assert k["kollar"]["taban"]["kesin_etiket"] == {}
    metin = json.dumps(k, ensure_ascii=False) + uo.karsilastir_markdown(k)
    for ad in GIZLI:
        assert ad not in metin
    md = uo.karsilastir_markdown(k)
    assert "| debian/tmux | 1 | 3 / 2 / 1 | 3 / 2 / 1 |" in md and "| **Toplam** | 3 | 5 / 3 / 2 |" in md
    assert "| kaybedilen (taban kanalı) | `binary_extract` | 1 |" in md


def _sahte_kol(birim_ogeleri, dosya="s"):
    """Öğe listesinden en küçük 'olc' belgesi: birim → {adres: durum}."""
    birimler, ogeler = {}, {}
    for b, og in birim_ogeleri.items():
        ks = [kayit(a, d) for a, d in og.items()]
        birimler[b] = {"ozet": uo.birim_ozeti(ks, 1000), "nufus": 1000,
                       "elfler": {"e": {"nufus": 1000, "dosya_sha256": dosya}}}
        ogeler[b] = {"e": {a: uo.oge_yaz(kayit(a, d)) for a, d in og.items()}}
    return {"sema": uo.SEMA, "komut": "olc", "kol": {}, "arac": {"ghidra_surumleri": {"12.1.2": 1}},
            "kol_kimligi": {}, "birimler": birimler, "ogeler": ogeler, "kararlar": {},
            "toplam": {"fonksiyon": {}, "etiket": {}}}


def _ogeler(n, dogru, bas=0):
    return {f"{bas + i:x}": ("dogru" if i < dogru else "yanlis") for i in range(n)}


def test_karsilastir_kayip_siniri():
    """(c) kaybedilen doğru / tabandaki doğru > %15 → incele; tam %15 aşmaz."""
    taban = _sahte_kol({"debian/a": _ogeler(20, 20)})
    def yeni(kalan_dogru):
        return _sahte_kol({"debian/a": _ogeler(kalan_dogru, kalan_dogru)})
    k = uo.karsilastir(taban, yeni(17))["kararlar"]["kaybedilen_dogru"]
    assert (k["havuz"]["k"], k["havuz"]["n"], k["karar"]) == (3, 20, "beklenen_aralikta")
    k = uo.karsilastir(taban, yeni(16))["kararlar"]["kaybedilen_dogru"]
    assert (k["havuz"]["k"], k["karar"], k["siniri_asan_birimler"]) == (4, "incele", ["debian/a"])
    # havuz sınırın altında, ama bir birim aşıyor → incele (büyük birim küçüğü örtmesin)
    taban = _sahte_kol({"debian/a": _ogeler(100, 100), "debian/b": _ogeler(10, 10)})
    yeni2 = _sahte_kol({"debian/a": _ogeler(100, 100), "debian/b": _ogeler(8, 8)})
    k = uo.karsilastir(taban, yeni2)["kararlar"]["kaybedilen_dogru"]
    assert (k["havuz"]["k"], k["havuz"]["n"]) == (2, 110)
    assert k["siniri_asan_birimler"] == ["debian/b"] and k["karar"] == "incele"
    # tabanda doğru ad yok: yetersiz
    bos = _sahte_kol({"debian/a": _ogeler(5, 0)})
    assert uo.karsilastir(bos, bos)["kararlar"]["kaybedilen_dogru"]["karar"] == "yetersiz"


def test_karsilastir_yanlis_yonu():
    """Yeni kolun yanlış oranı, iki kolda da en az N_MIN ad verilen her birimde düşmeli."""
    taban = _sahte_kol({"debian/a": _ogeler(20, 10), "debian/b": _ogeler(20, 10), "debian/c": _ogeler(9, 0)})
    yeni = _sahte_kol({"debian/a": _ogeler(10, 9), "debian/b": _ogeler(10, 5), "debian/c": _ogeler(9, 0)})
    y = uo.karsilastir(taban, yeni)["kararlar"]["yanlis_yonu"]
    assert y["karsilastirilan_birimler"] == ["debian/a", "debian/b"]
    assert y["dusmeyen_birimler"] == ["debian/b"] and y["karar"] == "incele"    # eşit oran düşmüş sayılmaz
    yeni = _sahte_kol({"debian/a": _ogeler(10, 9), "debian/b": _ogeler(10, 6), "debian/c": _ogeler(9, 0)})
    assert uo.karsilastir(taban, yeni)["kararlar"]["yanlis_yonu"]["karar"] == "beklenen_aralikta"
    kucuk = _sahte_kol({"debian/c": _ogeler(9, 0)})
    assert uo.karsilastir(kucuk, kucuk)["kararlar"]["yanlis_yonu"]["karar"] == "yetersiz"


def test_karsilastir_ayni_ikili_kosulu(tmp_path, monkeypatch):
    taban, yeni = iki_kol(tmp_path, monkeypatch)
    # dosya farklı: adresle eşleme anlamsız → durur
    bozuk = json.loads(json.dumps(yeni))
    bozuk["birimler"]["debian/tmux"]["elfler"]["tmux"]["dosya_sha256"] = "baska"
    with pytest.raises(uo.OnkosulHatasi, match="debian/tmux/tmux: iki kolda dosya sha256'sı farklı"):
        uo.karsilastir(taban, bozuk)
    k = uo.karsilastir(taban, bozuk, eksik_izinli=True)
    assert "debian/tmux" not in k["birimler"] and len(k["sorunlar"]) == 1
    # yalnız bir kolda bulunan ikili
    eksik = json.loads(json.dumps(yeni))
    del eksik["birimler"]["mac/tmux"]
    del eksik["ogeler"]["mac/tmux"]
    with pytest.raises(uo.OnkosulHatasi, match="mac/tmux/tmux: yalnız taban kolda"):
        uo.karsilastir(taban, eksik)
    # 'olc' çıktısı olmayan belge
    with pytest.raises(uo.OnkosulHatasi, match="yeni kolu bir 'olc' çıktısı değil"):
        uo.karsilastir(taban, {**yeni, "sema": "baska/1"})
    with pytest.raises(uo.OnkosulHatasi, match="taban kolu bir 'olc' çıktısı değil"):
        uo.karsilastir({**taban, "komut": "karsilastir"}, yeni)
    # öğe listesi özetle tutmuyor (elle düzenlenmiş dosya)
    oynanmis = json.loads(json.dumps(yeni))
    oynanmis["ogeler"]["debian/tmux"]["tmux"].pop("104000")
    with pytest.raises(uo.OnkosulHatasi, match="yeni kolu, debian/tmux: öğe listesi özetle tutmuyor"):
        uo.karsilastir(taban, oynanmis)


def test_oge_yaz_oku():
    k = kayit("gizli", "yanlis", satir="klon", nufusta=False, etiket="doğrulanmadı",
              kanal="string_context/oz_ad")
    metin = uo.oge_yaz(k)
    assert metin == "yanlis klon 0 doğrulanmadı string_context/oz_ad" and "gizli" not in metin
    assert uo.oge_oku(metin) == {"durum": "yanlis", "satir": "klon", "nufusta": False,
                                 "etiket": "doğrulanmadı", "kanal": "string_context/oz_ad"}
    assert uo.oge_oku(uo.oge_yaz(kayit("x")))["nufusta"] is True


# --------------------------------------------------------------------------------------------
# CLI


def test_cli_olc_ve_karsilastir(tmp_path, monkeypatch, capsys):
    gt_tablosu(monkeypatch)
    monkeypatch.setattr(ks1, "BEKLENEN_ELF", BEKLENEN)      # CLI beklentiyi çağrı anında okur
    yollar = {}
    for ad, yeni in (("taban", False), ("yeni", True)):
        mac, deb = kok_kur(tmp_path, ad, yeni)
        yollar[ad] = tmp_path / f"{ad}.json"
        assert uo.main(["olc", "--kok-debian", str(deb), "--kok-mac", str(mac), "--kol", ad,
                        "--json", str(yollar[ad]), "--md", str(tmp_path / f"{ad}.md")]) == 0
        belge = json.loads(yollar[ad].read_text(encoding="utf-8"))
        assert belge["kol"] == {"ad": ad, "kok_debian": str(deb), "kok_mac": str(mac)}
        assert (tmp_path / f"{ad}.md").read_text(encoding="utf-8").startswith(f"# Ürün adlarının ölçümü: {ad}")
    fark = tmp_path / "fark.json"
    assert uo.main(["karsilastir", "--taban", str(yollar["taban"]), "--yeni", str(yollar["yeni"]),
                    "--json", str(fark), "--md", str(tmp_path / "fark.md")]) == 0
    assert json.loads(fark.read_text(encoding="utf-8"))["toplam"]["kaybedilen_dogru"] == 1
    assert "## Birim başına farklar" in (tmp_path / "fark.md").read_text(encoding="utf-8")
    # eksik kök: ölçüm durur, çıktı yazılmaz
    capsys.readouterr()
    yok = tmp_path / "yok.json"
    assert uo.main(["olc", "--kok-debian", str(tmp_path / "taban" / "debian"), "--json", str(yok)]) == 2
    assert "DURDU: nüfus eksik" in capsys.readouterr().err and not yok.exists()
    assert uo.main(["olc", "--kok-debian", str(tmp_path / "taban" / "debian"), "--json", str(yok),
                    "--eksik-izinli"]) == 0
    assert json.loads(yok.read_text(encoding="utf-8"))["nufus"]["eksik_izinli"] is True
