"""docs/arge/2026-11-10_n4/tablo_yuvasi_sayim.py — veri tablosu fonksiyon yuvası sayımı (N4 §5 A1).

Sentetik baytlarla kilitlenen tanımlar:
  (a) dizgi yuvası: salt okunur bölümde NUL sonlu, yazdırılabilir UTF-8; boş dizgi ayrı tür;
      biçim sınıfları (tanımlayıcı, tire/noktalı kısa ad, biçim, boşluklu, öbür),
  (b) sözcük türleri: yer değişimi olmayan sözcük Z/V; hedef fonksiyon girişi F, metin içi T,
      dizgi S/E, öbür D; içe aktarılan fonksiyon X; 8 bayt hizası,
  (c) tablo: aynı adımla en az 3 kayıt ve her kayıtta aynı ofsette fonksiyon yuvası; ardışık
      gösterici dizisinde adım en küçük dönem; kayıt içi ardışık göstericiler daha büyük adımlı
      tabloya yenilir; benzerlik eşiği ve kenar kaydı atma; aynı puanda farklı adım → belirsiz,
  (d) kayıt dizgisi: aynı kayıttaki dizgi; faz çapayla ya da tutarlılıkla; eşit fazlarda kesin
      (kesişim) ve gevşek (birleşim),
  (e) kodda adres alma (adrp + add, adr), naming_map yalnız anahtar, ön sayım denetimi.
"""
from __future__ import annotations

import importlib.util
import json
import struct
import sys
from pathlib import Path

import pytest

_KOK = Path(__file__).resolve().parents[1] / "docs" / "arge" / "2026-11-10_n4"


def _yukle(ad: str, dosya: str):
    spec = importlib.util.spec_from_file_location(ad, _KOK / dosya)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


ty = _yukle("tablo_yuvasi_sayim_under_test", "tablo_yuvasi_sayim.py")


# --------------------------------------------------------------------------------------------
# Yardımcılar


def turler_dizisi(desen: str) -> list[str]:
    """'SFSF0V' → ['S','F','S','F','Z','V'] ('0' sıfır sözcük)."""
    return [ty.TUR_Z if c == "0" else c for c in desen]


def tablolar(desen: str, capalar=(), **kw):
    t = turler_dizisi(desen)
    return t, *ty.tablolari_sec(t, frozenset(capalar), **kw)


# --------------------------------------------------------------------------------------------
# (a) dizgiler


def test_dizgi_oku_nul_sonlu_yazdirilabilir():
    b = b"abc\0\x01x\0\0caf\xc3\xa9\0\xff\xfe\0tab\tok\0son"
    assert ty.dizgi_oku(b, 0) == "abc"
    assert ty.dizgi_oku(b, 1) == "bc"                      # dizginin ortası da dizgidir
    assert ty.dizgi_oku(b, 4) is None                      # yazdırılamayan bayt
    assert ty.dizgi_oku(b, 7) == ""                        # boş dizgi
    assert ty.dizgi_oku(b, 8) == "café"                    # UTF-8
    assert ty.dizgi_oku(b, 14) is None                     # geçersiz UTF-8
    assert ty.dizgi_oku(b, 17) == "tab\tok"
    assert ty.dizgi_oku(b, len(b) - 3) is None             # NUL yok
    assert ty.dizgi_oku(b, len(b)) is None and ty.dizgi_oku(b, -1) is None


def test_dizgi_sinifi_sirasi():
    s = ty.dizgi_sinifi
    assert s("do_thing") == "tanimlayici" and s("_x9") == "tanimlayici" and s("q") == "tanimlayici"
    assert s("foo-bar") == "kisa_ad" and s("conf.d") == "kisa_ad"
    assert s("1.2.3") == "diger"                           # harfsiz: kısa ad değil
    assert s("a-" + "b" * 39) == "diger"                   # 41 karakter: kısa ad sınırı aşıldı
    assert s("a-" + "b" * 38) == "kisa_ad"                 # 40 karakter: sınırda
    assert s("%s: %d") == "bicim" and s("x%") == "bicim"
    assert s("hello world") == "bosluklu"
    assert s("--help") == "diger" and s("#{x}") == "diger"
    assert s("9lives") == "diger"                          # rakamla başlayan, tiresiz
    assert s("abc\n") == "diger" and s("a-b\n") == "diger"  # sondaki satır sonu ad değildir


# --------------------------------------------------------------------------------------------
# (b) sözcük türleri


def _hedefci():
    ro = b"\0name\0\0\x01\x02\0"                           # 0x2000: '' 'name' '' ...
    return ty.Hedefci({0x1000: "ic", 0x1040: "ic"}, [(0x1000, 0x1100)], [(0x2000, 0x2000 + len(ro), ro)])


def test_hedefci_turleri():
    h = _hedefci()
    assert h.tur(0x1000) == ty.TUR_F
    assert h.tur(0x1004) == ty.TUR_T                       # metin içi, giriş değil
    assert h.tur(0x2001) == ty.TUR_S
    assert h.tur(0x2000) == ty.TUR_E
    assert h.tur(0x2007) == ty.TUR_D                       # \x01: dizgi değil
    assert h.tur(0x3000) == ty.TUR_D                       # hiçbir bölümde değil


def test_bolum_turleri_hiza_ve_yer_degisimi():
    h = _hedefci()
    bas = 0x5004                                           # hizasız bölüm başı: ilk sözcük 0x5008
    bayt = b"\xaa" * 4 + struct.pack("<7Q", 0, 7, 0, 0, 0, 0, 0)
    yd = {0x5010: ("hedef", 0x1040), 0x5018: ("hedef", 0x2001), 0x5020: ("dis_fonksiyon", None),
          0x5028: ("dis_veri", None), 0x5030: ("hedef", 0x1004)}
    ilk, turler, hedefler = ty.bolum_turleri(bayt, bas, yd, h)
    assert ilk == 0x5008
    assert turler == [ty.TUR_Z, ty.TUR_F, ty.TUR_S, ty.TUR_X, ty.TUR_D, ty.TUR_T, ty.TUR_Z]
    assert hedefler[1] == 0x1040 and hedefler[0] is None and hedefler[3] is None
    # yer değişimi olmayan sıfır olmayan sözcük V
    _, t2, _ = ty.bolum_turleri(struct.pack("<2Q", 5, 0), 0x6000, {}, h)
    assert t2 == [ty.TUR_V, ty.TUR_Z]


# --------------------------------------------------------------------------------------------
# (c) tablo tanımı


def test_ad_isleyici_tablosu_ve_kayit_dizgisi():
    t, tbl, belirsiz, _ = tablolar("00SFSFSFSF00", capalar=[2])
    assert len(tbl) == 1 and not belirsiz
    tb = tbl[0]
    assert tb["adim"] == 2 and tb["kayit"] == 4 and tb["fazlar"] == [0]
    assert tb["faz_kaynagi"] == "capa"
    kd = ty.kayit_dizgileri(t, tb)
    assert sorted(kd) == [3, 5, 7, 9]
    for p, (kesin, gevsek) in kd.items():
        assert kesin == gevsek == frozenset({p - 1})
    y = ty.tablo_yapisi(t, tb)
    assert y["kayit"] == 4 and y["fn_sutun"] == 1 and y["dizgi_sutun"] == 1
    assert ty.tablo_sinifi(y) == "tek_fn_dizgili"


def test_iki_kayit_tablo_degil():
    _, tbl, _, _ = tablolar("00SFSF00")
    assert tbl == []
    _, tbl, _, _ = tablolar("00SFSFSF00")
    assert len(tbl) == 1


def test_gosterici_dizisinde_adim_en_kucuk_donem():
    t, tbl, _, _ = tablolar("0FFFFFF0")
    assert [(g["adim"], g["kayit"]) for g in tbl] == [(1, 6)]
    assert all(not k and not g for k, g in ty.kayit_dizgileri(t, tbl[0]).values())
    assert ty.tablo_sinifi(ty.tablo_yapisi(t, tbl[0])) == "gosterici_dizisi"
    # alt örnek koşular (adım 2, 3) aday bile olmaz
    adaylar = ty.aday_tablolar(t)
    assert {g["adim"] for g in adaylar} == {1}


def test_kayit_ici_ardisik_gosterici_buyuk_adima_yenilir():
    t, tbl, _, _ = tablolar("0" + "DFFFS" * 3 + "0", capalar=[1, 6, 11])
    assert [(g["adim"], g["kayit"]) for g in tbl] == [(5, 3)]
    tb = tbl[0]
    assert tb["fazlar"] == [1]                              # çapa: D'nin olduğu konum (mod 5 = 1)
    y = ty.tablo_yapisi(t, tb)
    assert y["fn_sutun"] == 3 and y["kayitta_en_cok_fn"] == 3
    assert ty.tablo_sinifi(y) == "cok_fn_dizgili"
    kd = ty.kayit_dizgileri(t, tb)
    assert kd[2][0] == frozenset({5}) and kd[12][0] == frozenset({15})


def test_benzer_olmayan_kayitlar_tablo_degil_ve_kenar_atilir():
    # adım 3: sütun 1'de F, ama öbür sütunlar kayıttan kayda farklı göstericiler
    t, tbl, _, sayac = tablolar("0" + "DFS" + "SFD" + "FFT" + "0")
    assert tbl == [] and sayac["benzerlik_esigi_alti"] >= 1
    # üç benzer kayıt + sonda yabancı bir kayıt: yabancı kayıt atılır
    t, tbl, _, _ = tablolar("0" + "DFS" * 3 + "TFD" + "000", capalar=[1, 4, 7, 10])
    assert [(g["adim"], g["kayit"]) for g in tbl] == [(3, 3)]
    assert tbl[0]["bolge"] == (1, 10)


def test_ortalama_gecse_de_yabanci_kenar_kaydi_atilir():
    # 10 benzer kayıt + başta yabancı bir kayıt: ortalama (0.25 + 9) / 10 ≥ 0.9, ilk çift < 0.5
    desen = "0FFF" + "S00F" * 10 + "0"
    t, tbl, _, sayac = tablolar(desen, capalar=[4])
    assert sayac["yabanci_kenar_kaydi"] == 1
    assert [(g["adim"], g["kayit"], g["bolge"]) for g in tbl] == [(1, 3, (1, 4)), (4, 10, (4, 44))]
    assert ty.tablo_sinifi(ty.tablo_yapisi(t, tbl[1])) == "tek_fn_dizgili"
    assert ty.tablo_sinifi(ty.tablo_yapisi(t, tbl[0])) == "gosterici_dizisi"


def test_ortadaki_benzemeyen_kayit_tabloyu_boler():
    # kenar çiftleri 1, ortadaki iki çift 2/3: ortalama 0,83 < 0,9 → bölünür, parçalar < 3 kayıt
    t, tbl, _, sayac = tablolar("0" + "DFS" "DFS" "DFD" "DFS" "DFS" + "0", capalar=[1])
    assert tbl == [] and sayac["benzerlik_esigi_alti"] == 1
    assert ty.cift_benzerlikleri(t, 3, range(1, 16, 3)) == pytest.approx([1, 2 / 3, 2 / 3, 1])


def test_benzerlik_esigi_sinirda():
    pen = range(0, 9, 3)
    t = turler_dizisi("DFS" + "DFS" + "DFD")                # ikinci çift 2/3
    assert ty.kayit_benzerligi(t, 3, pen) == pytest.approx((1 + 2 / 3) / 2)
    t = turler_dizisi("DF0" + "DF0" + "DF0")
    assert ty.kayit_benzerligi(t, 3, pen) == 1.0
    assert ty.kayit_benzerligi(t, 1, range(0, 3)) == 1.0


def test_ayni_puanda_farkli_adim_belirsiz():
    # F: {0,2,4} (adım 2) ve {0,5,10} (adım 5) aynı yuvayı paylaşıyor, ikisi de 3 yuva
    t, tbl, belirsiz, sayac = tablolar("F0F0FF0000F", esik=0.0, kenar=0.0)
    assert tbl == []
    assert sayac["adim_belirsiz_aday"] == 2
    assert {0, 2, 4, 5, 10} <= belirsiz


# --------------------------------------------------------------------------------------------
# (d) faz


def test_faz_capasiz_esitlikte_kesin_kesisim_gevsek_birlesim():
    t, tbl, _, _ = tablolar("SFSFSFS")
    tb = tbl[0]
    assert tb["fazlar"] == [0, 1] and tb["faz_kaynagi"] == "tutarlilik"
    kd = ty.kayit_dizgileri(t, tb)
    assert kd[3] == (frozenset(), frozenset({2, 4}))
    assert ty.tablo_yapisi(t, tb)["faz_belirsiz"] is True


def test_faz_capayla_cozulur():
    t, tbl, _, _ = tablolar("SFSFSFS", capalar=[1])
    tb = tbl[0]
    assert tb["fazlar"] == [1] and tb["faz_kaynagi"] == "capa"
    assert ty.kayit_dizgileri(t, tb)[3] == (frozenset({4}), frozenset({4}))


def test_faz_tutarliliktan_sonlandirici_ile():
    t, tbl, _, _ = tablolar("0SFSFSF00")
    tb = tbl[0]
    assert tb["fazlar"] == [1] and tb["bolge"] == (1, 7)
    assert ty.kayit_dizgileri(t, tb)[2] == (frozenset({1}), frozenset({1}))


# --------------------------------------------------------------------------------------------
# (e) kod, naming_map, ön sayım


def test_kodda_alinan_adresler():
    kod = {0x100: [
        (0x100, "adrp", "x0,0x16a000"),
        (0x104, "add", "x0,x0,#0xcb0"),                     # 0x16acb0
        (0x108, "adrp", "x1,0x170000"),
        (0x10c, "ldr", "x1,[x1, #0x8]"),                    # x1 üzerine yazıldı
        (0x110, "add", "x2,x1,#0x10"),                      # sayfa yok: alınmaz
        (0x114, "adr", "x3,0x113400"),
        (0x118, "adrp", "x4,0x180000"),
        (0x11c, "str", "x4,[sp, #0x10]"),                   # saklama yazmacı bozmaz
        (0x120, "add", "x5,x4,#0x8"),
    ]}
    assert ty.kodda_alinan_adresler(kod) == {0x16acb0, 0x113400, 0x180008}


def test_naming_map_yalniz_global_anahtarlari(tmp_path):
    src = tmp_path / "reconstructed" / "src"
    src.mkdir(parents=True)
    (src / "naming_map.json").write_text(json.dumps(
        {"global": {"FUN_1": "a", "DAT_2": "b"}, "per_function": {"FUN_3": {"x": "y"}}}))
    assert ty.naming_anahtarlari(tmp_path) == {"FUN_1", "DAT_2"}
    assert ty.naming_anahtarlari(tmp_path / "yok") is None


def test_on_sayim_denetimi():
    on = {"birimler": {"mac/htop": {"sayim": {"isim_bekleyen": 5, "cagiran_K_0": 1,
                                              "cagiran_I_0": 2, "cagiran_Y_0": 0,
                                              "cagiran_K_1": 9, "sinif_K": 2, "sinif_I": 2,
                                              "sinif_Y": 1}}}}
    from collections import Counter
    dogru = Counter(isim_bekleyen=5, cagirani_yok=3, sinif_K=2, sinif_I=2, sinif_Y=1)
    assert ty.on_sayim_denetimi(on, "mac/htop", dogru)["cagirani_yok"] == [3, 3]
    for k, v in (("cagirani_yok", 2), ("isim_bekleyen", 4), ("sinif_Y", 0)):
        with pytest.raises(SystemExit):
            ty.on_sayim_denetimi(on, "mac/htop", Counter({**dogru, k: v}))


def test_tablo_sinifi_bes_sinif():
    taban = {"adim": 2, "kayit": 3, "fn_sutun": 1, "faz_belirsiz": False}
    assert ty.tablo_sinifi({**taban, "adim": 1, "kayitta_en_cok_fn": 1,
                            "dizgi_sutun": 0}) == "gosterici_dizisi"
    assert ty.tablo_sinifi({**taban, "kayitta_en_cok_fn": 2, "dizgi_sutun": 0}) == "cok_fn_dizgisiz"
    assert ty.tablo_sinifi({**taban, "kayitta_en_cok_fn": 1, "dizgi_sutun": 1}) == "tek_fn_dizgili"
    assert ty.tablo_sinifi({**taban, "kayitta_en_cok_fn": 3, "dizgi_sutun": 2}) == "cok_fn_dizgili"
    assert ty.tablo_sinifi({**taban, "kayitta_en_cok_fn": 1, "dizgi_sutun": 0}) == "tek_fn_dizgisiz"
