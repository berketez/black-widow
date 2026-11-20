"""ÖK-5 ölçüm betiği (``scripts/measurement/ozkod_olc.py``) testleri.

Sentetik veriyle: dondurulmuş betik denetimi, taraf (ayar / kör) ayrımı, Wilson, ön kayıtlı eşikler,
çapa kipleri (A / C / C-kapılı / D), G1 kapısı, K1 karakter eki ve körlük temizliği. Gerçek nüfus
verisi okunmaz (kör taraf yalnız betikle sayılır).
"""
from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts" / "measurement"))

import ozkod_olc as Z  # noqa: E402


# ---------------------------------------------------------------------------------------------
# Dondurulmuş betikler


def test_dondurulmus_betikler_degismedi():
    h = Z.dondurulmus_denetle()
    assert set(h) == set(Z.DONDURULMUS)
    assert h["ek_kurali.py"].startswith("7d02a6b5")
    assert h["oz_ad_ayrim.py"].startswith("ccc73f5c")
    assert h["oz_ad_uretici.py"].startswith("7ee4edfc")


def test_dondurulmus_denetle_sapmayi_yakalar(tmp_path):
    for ad in Z.DONDURULMUS:
        shutil.copy(Z.OZKOD / ad, tmp_path / ad)
    Z.dondurulmus_denetle(tmp_path)
    (tmp_path / "ek_kurali.py").write_text((tmp_path / "ek_kurali.py").read_text() + "\n# ayar\n")
    with pytest.raises(Z.DondurmaHatasi):
        Z.dondurulmus_denetle(tmp_path)


# ---------------------------------------------------------------------------------------------
# Birim listesi ve taraf ayrımı


def _nufus():
    return {"paketler": [
        {"paket": "a1", "taraf": "ayar", "olculur": 1, "secilen": 1},
        {"paket": "k1", "taraf": "kör", "olculur": 2, "secilen": 2},
        {"paket": "k2", "taraf": "kör", "olculur": 1, "secilen": 1},
        {"paket": "kpp", "taraf": "kör", "olculur": 0, "secilen": 1},   # C++: seçildi, ölçülmez
        {"paket": "a2", "taraf": "ayar", "olculur": 0, "secilen": 0},
    ]}


def test_nufus_birimleri_taraf_ayrimi_ve_olculmeyen_disarida():
    b = Z.nufus_birimleri(_nufus())
    assert b[Z.AYAR] == ("debian/a1",)
    assert b[Z.KOR] == ("debian/k1", "debian/k2")


def _veri(tmp_path):
    return Z.Veri("deneme", tmp_path / "kosu", tmp_path / "indir", tmp_path / "mac", tmp_path / "cikti",
                  kesif=("debian/a1",), sinama=("debian/k1", "debian/k2"), atla=frozenset({("debian/k1", "e01")}),
                  olgu=tmp_path / "cikti" / "olgu_bos.jsonl.gz")


def test_etkin_yalniz_gorunur_taraf_ve_geri_yukleme(tmp_path):
    V = Z.kurallar()["V"]
    eski = (V.KESIF_BIRIMLERI, V.SINAMA_BIRIMLERI, V.BIRIMLER, V.ONBELLEK, V.ARGE_KOKU)
    v = _veri(tmp_path)
    with Z.etkin(v, ("sinama",)):
        assert V.KESIF_BIRIMLERI == ()
        assert V.SINAMA_BIRIMLERI == ("debian/k1", "debian/k2")
        assert V.BIRIMLER == ("debian/k1", "debian/k2")
        assert V.taraf("debian/k2") == "sinama"
        with pytest.raises(KeyError):
            V.taraf("debian/a1")                      # ayar birimi kör sayımında tanınmaz
        assert V.AYNI_DOSYA_ATLA == {("debian/k1", "e01")}
        assert V.ONBELLEK == tmp_path / "cikti" / "onbellek"
        assert Z.kurallar()["K"].CAGRI_ONBELLEK == tmp_path / "cikti" / "onbellek_cagri"
    with Z.etkin(v, ("kesif",)):
        assert V.BIRIMLER == ("debian/a1",)
        assert V.SINAMA_BIRIMLERI == ()
    assert (V.KESIF_BIRIMLERI, V.SINAMA_BIRIMLERI, V.BIRIMLER, V.ONBELLEK, V.ARGE_KOKU) == eski


def test_etkin_bilinmeyen_taraf(tmp_path):
    with pytest.raises(ValueError):
        with Z.etkin(_veri(tmp_path), ("kör",)):
            pass


def test_kaynak_grubu():
    assert Z.kaynak_grubu("debian/libtcl8.6") == "tcl8.6"
    assert Z.kaynak_grubu("debian/libpython3.13-stdlib") == "python3.13-minimal"
    assert Z.kaynak_grubu("debian/lua-cjson") == "lua-socket"
    assert Z.kaynak_grubu("debian/bash") == "bash"


# ---------------------------------------------------------------------------------------------
# Wilson ve eşikler


def test_oran_wilson():
    o = Z.oran(9, 10)
    assert o["k"] == 9 and o["n"] == 10
    assert o["alt"] == pytest.approx(0.5958, abs=1e-3)
    assert o["ust"] == pytest.approx(0.9821, abs=1e-3)
    assert o["alt"] < 0.9 < o["ust"]
    z = Z.oran(0, 0)
    assert z["alt"] is None and z["n"] == 0


def _k1_birim(dogru_ad):
    return {f"debian/p{i}": {"kahin_ad": n, "kahin_dogru": k} for i, (k, n) in enumerate(dogru_ad)}


def test_k1a_esik_sinirinda_tutar():
    # havuz 850 / 1000 = %85 (eşik dahil), Wilson alt ≈ %82,7; 5 pakette ≥ 10 ad
    h = Z.hukum_k1a(_k1_birim([(170, 200)] * 5))
    assert h["oran"]["k"] == 850 and h["oran"]["n"] == 1000
    assert h["tuttu"] is True and h["karar"] == "ÖK-4b açılır"


def test_k1a_kesinlik_esik_altinda_tutmaz():
    h = Z.hukum_k1a(_k1_birim([(170, 200)] * 4 + [(169, 200)]))
    assert h["tuttu"] is False


def test_k1a_paket_sarti():
    # dört pakette ≥ 10 ad: hacim şartı tutmaz (kesinlik yüksek)
    h = Z.hukum_k1a(_k1_birim([(98, 100)] * 4 + [(9, 9)] * 20))
    assert h["paket_10_ad"] == 4 and h["tuttu"] is False
    assert "hacim" in h["karar"]


def test_k1a_ad_sayisi_sarti():
    h = Z.hukum_k1a(_k1_birim([(39, 39)] * 5))      # 195 ad < 200
    assert h["tuttu"] is False


def test_k1a_karar_kollari():
    orta = Z.hukum_k1a(_k1_birim([(160, 200)] * 5))  # %80; Wilson alt ≈ %77
    assert 0.70 <= orta["oran"]["alt"] < 0.80
    assert "yeniden ön kayıt" in orta["karar"]
    dusuk = Z.hukum_k1a(_k1_birim([(130, 200)] * 5))  # %65
    assert dusuk["oran"]["alt"] < 0.70
    assert "bırakılır" in dusuk["karar"]


def test_k1b_yarisi_ve_payda():
    birim = {f"debian/p{i}": {"nufus": 100, "VC_var": 5 if i < 7 else 4} for i in range(14)}
    birim["debian/bos"] = {"nufus": 0, "VC_var": 0}          # nüfus 0: paydaya girmez
    h = Z.hukum_k1b(birim)
    assert h["paket"] == 14 and h["esigi_gecen"] == 7 and h["tuttu"] is True
    birim["debian/p6"]["VC_var"] = 4
    assert Z.hukum_k1b(birim)["tuttu"] is False


def test_k1c_n_kucukse_hukme_girmez():
    h = Z.hukum_k1c({"debian/a": {"ad": 29, "dogru": 29, "nufus": 10000}})
    assert h["hukme_girer"] is False and h["tuttu"] is None and h["kucuk"] is True
    h = Z.hukum_k1c({"debian/a": {"ad": 30, "dogru": 27, "nufus": 10000}})
    assert h["hukme_girer"] is True and h["tuttu"] is True
    h = Z.hukum_k1c({"debian/a": {"ad": 30, "dogru": 26, "nufus": 10000}})
    assert h["tuttu"] is False


def test_g1_esikleri():
    g = {"debian/a": {"duz_ad": 100, "duz_dogru": 85, "kapili_ad": 50, "kapili_dogru": 49}}
    h = Z.hukum_g1(g)
    assert h["G1-a"]["tuttu"] is True
    assert h["G1-b"]["tuttu"] is True and h["G1-b"]["karar"] == "ÖK-3 açılır"
    g["debian/a"]["kapili_ad"], g["debian/a"]["kapili_dogru"] = 49, 49    # ad < 50
    assert Z.hukum_g1(g)["G1-b"]["tuttu"] is False
    g["debian/a"].update(kapili_ad=60, kapili_dogru=54)                    # %90 ama Wilson alt < %85
    assert Z.hukum_g1(g)["G1-b"]["tuttu"] is False
    g["debian/a"]["duz_dogru"] = 84
    assert Z.hukum_g1(g)["G1-a"]["tuttu"] is False


def test_oa_esigi():
    on = {"sinama|hepsi": {"sandvic_32_karar": 100, "sandvic_32_dogru": 85, "sandvic_0_karar": 200,
                           "sandvic_0_dogru": 150}}
    assert Z.hukum_oa(on, "sinama")["tuttu"] is True
    on["sinama|hepsi"]["sandvic_32_dogru"] = 84
    assert Z.hukum_oa(on, "sinama")["tuttu"] is False
    assert Z.hukum_oa(on, "kesif")["aralik_32"]["n"] == 0      # başka tarafın anahtarı okunmaz


# ---------------------------------------------------------------------------------------------
# Sentetik ikili kaydı: çapa kipleri ve G1 kapısı


def _d(tmp_path, *, capalar=None, ice=("malloc",), platform="debian"):
    kosu = tmp_path / "kosu_ws"
    (kosu / "reconstructed").mkdir(parents=True, exist_ok=True)
    if capalar is not None:
        (kosu / "reconstructed" / "kesin_capalar.json").write_text(json.dumps({"capalar": capalar}))
    static = tmp_path / "static"
    (static / "ghidra_output" / "decompiled").mkdir(parents=True, exist_ok=True)
    fonk = {0x1000: {"ad": "FUN_00001000", "boyut": 10, "thunk": False, "dis": False},
            0x2000: {"ad": "FUN_00002000", "boyut": 10, "thunk": False, "dis": False},
            0x3000: {"ad": "FUN_00003000", "boyut": 10, "thunk": False, "dis": False},
            0x4000: {"ad": "FUN_00004000", "boyut": 10, "thunk": False, "dis": False},
            0x5000: {"ad": "parse_args", "boyut": 10, "thunk": False, "dis": False}}
    for i, ad in enumerate(ice):
        fonk[0x9000 + i] = {"ad": ad, "boyut": 4, "thunk": True, "dis": False}
    # 0x4000 tek tanımlayıcı dizgi anıyor ("do_work_item") → G1 adı
    return {"birim": "debian/k1", "ad": "e00", "platform": platform, "kosu": str(kosu), "static": str(static),
            "fonk": fonk, "yuvalar": [], "bolum_dokumu": {},
            "dizgi_metin": {0x7000: "do_work_item"}, "fn_dizgi": {0x4000: [0x7000]},
            "dizgi_fn": {0x7000: [0x4000]},
            "urun": {0x1000: {"ad": "x_main", "kanal": "on_ad:main_giris"},
                     0x2000: {"ad": "x_ks1", "kanal": "ks1:func_kalibi"},
                     0x3000: {"ad": "x_ozad", "kanal": "string_context/oz_ad"}}}


def test_capa_kipleri(tmp_path):
    v = _veri(tmp_path)
    d = _d(tmp_path)
    with Z.etkin(v, ("sinama",)):
        k = Z._capa_kaynaklari(d, kapi_acik=False)
        assert set(k["A"]) == {0x1000, 0x2000, 0x5000}          # on_ad + ks1 + Ghidra'nın adı
        assert 0x3000 not in k["A"] and 0x3000 in k["D"]        # oz_ad çapa değil (yalnız D)
        assert k["C"][0x4000] == ["do_work_item"]               # C = A + düz G1
        assert 0x4000 not in k["C_kapili"]                      # kapı kapalı: G1 yok
        k2 = Z._capa_kaynaklari(d, kapi_acik=True)
        assert k2["C_kapili"][0x4000] == ["do_work_item"]


def test_g1_kapisi(tmp_path):
    v = _veri(tmp_path)
    with Z.etkin(v, ("sinama",)):
        assert Z.g1_kapisi(_d(tmp_path, capalar=[{"a": 1}])) is True
        shutil.rmtree(tmp_path / "kosu_ws")
        assert Z.g1_kapisi(_d(tmp_path, capalar=[])) is False
        shutil.rmtree(tmp_path / "kosu_ws")
        assert Z.g1_kapisi(_d(tmp_path, capalar=[], ice=("__assert_fail",))) is True
        shutil.rmtree(tmp_path / "kosu_ws")
        assert Z.g1_kapisi(_d(tmp_path, capalar=None)) is False        # dosya yok, assert yok
        shutil.rmtree(tmp_path / "kosu_ws")
        assert Z.g1_kapisi(_d(tmp_path, capalar=None, ice=("___assert_rtn",), platform="mac")) is True
        shutil.rmtree(tmp_path / "kosu_ws")
        assert Z.g1_kapisi(_d(tmp_path, capalar=None, ice=("__assert_perror_fail",))) is False


# ---------------------------------------------------------------------------------------------
# K1 karakter eki


def _grup(uyeler):
    g = ("T", ".data", 1, 0, -1)
    return {g: list(uyeler)}, g


def test_karakter_eki_onek_harfleri_korunur():
    gruplar, g = _grup([(1, "next"), (2, "print"), (3, "pairs")])
    kaynak = {1: ["luaB_next"], 2: ["luaB_print"]}
    norm, kar, don = Z.karakter_adi(3, [(g, "pairs")], gruplar, kaynak, tuple(Z.DONUSUM_ADAYLARI))
    assert norm == "lua_b_pairs"
    assert kar == "luaB_pairs" and don == "aynen"


def test_karakter_eki_kebap_alt_cizgi():
    gruplar, g = _grup([(1, "cursor-right"), (2, "page-up"), (3, "scroll-down")])
    kaynak = {1: ["window_copy_cmd_cursor_right"], 2: ["window_copy_cmd_page_up"]}
    norm, kar, don = Z.karakter_adi(3, [(g, "scroll-down")], gruplar, kaynak, tuple(Z.DONUSUM_ADAYLARI))
    assert norm == kar == "window_copy_cmd_scroll_down" and don == "alt_cizgi"


def test_karakter_eki_sonek():
    gruplar, g = _grup([(1, "CPU"), (2, "Memory"), (3, "Swap")])
    kaynak = {1: ["CPUMeter_display"], 2: ["MemoryMeter_display"]}
    norm, kar, _ = Z.karakter_adi(3, [(g, "Swap")], gruplar, kaynak, tuple(Z.DONUSUM_ADAYLARI))
    assert norm == "swap_meter_display"
    assert kar == "SwapMeter_display"


def test_karakter_eki_tek_destekli_yuzey_yazilmaz():
    # norm kararı iki çapayla ad veriyor; yüzey biçimini yalnız bir çapa destekliyor → norm adı yazılır
    gruplar, g = _grup([(1, "next"), (2, "cursorRight"), (3, "pairs")])
    kaynak = {1: ["luaB_next"], 2: ["luaB_cursor_Right"]}
    norm, kar, _ = Z.karakter_adi(3, [(g, "pairs")], gruplar, kaynak, tuple(Z.DONUSUM_ADAYLARI))
    assert norm == "lua_b_pairs"
    assert kar is None


def test_karakter_eki_tek_capa_ogrenmez():
    # norm kararı da tek çapayla ad vermez (MIN_DESTEK = 2): K1'in kararı değişmez
    gruplar, g = _grup([(1, "next"), (3, "pairs")])
    norm, kar, _ = Z.karakter_adi(3, [(g, "pairs")], gruplar, {1: ["luaB_next"]}, tuple(Z.DONUSUM_ADAYLARI))
    assert norm is None and kar is None


def test_karakter_eki_donusum_kumesiyle_sinirli():
    gruplar, g = _grup([(1, "cursor-right"), (2, "page-up"), (3, "scroll-down")])
    kaynak = {1: ["window_copy_cmd_cursor_right"], 2: ["window_copy_cmd_page_up"]}
    norm, kar, _ = Z.karakter_adi(3, [(g, "scroll-down")], gruplar, kaynak, ("aynen",))
    assert norm == "window_copy_cmd_scroll_down" and kar is None     # yüzey öğrenilemedi: norm yazılır


def test_donusum_dondurma_kurali():
    say = {"aynen": {"ad": 40, "karakter": 38}, "bitisik": {"ad": 5, "karakter": 2},
           "deve": {"ad": 4, "karakter": 0}, "pascal": {"ad": 10, "karakter": 5}}
    d = Z.donusum_dondur(say)
    assert "bitisik" not in d                  # n = 5, %40 < %50: çıkar
    assert "deve" in d                         # n = 4 < 5: kalır
    assert "pascal" in d                       # %50: kalır
    assert d[0] == "aynen" and list(d) == [x for x in Z.DONUSUM_ADAYLARI if x in d]


# ---------------------------------------------------------------------------------------------
# Körlük


def test_temizle_ad_tasiyan_alanlari_atar():
    s = {"taraf": "sinama", "birim": {"debian/k1": {"kahin_ad": 3}},
         "gruplar": [{"grup": "('C', 'gizli_ad', 2, 0, 1)"}], "ornek": {"x": [("gt_adi", "aday")]}}
    t = Z.temizle(s)
    assert "ornek" not in t and "gruplar" not in t and t["grup_sayisi"] == 1
    assert "gizli_ad" not in json.dumps(t) and "gt_adi" not in json.dumps(t)
