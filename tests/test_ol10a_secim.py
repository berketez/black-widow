"""OL10A: ÖL-10 seçim kuralı (kural sürümü 1; ``OL10_TASARIM.md`` §2). Ghidra yok, sentetik girdi."""
from __future__ import annotations

import importlib.util
import random
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from karadul.analyzers.ustveri import go_pclntab
from karadul.core import tembel_girdi as tg
from karadul.core import tembel_secim as ts

DEPO = Path(__file__).resolve().parents[1]

K, B, S, U, T = ts.SECIM_KENDI, ts.SECIM_BAGIMLILIK, ts.SECIM_STANDART, ts.SECIM_BILINMIYOR, ts.SECIM_TASLAK


def girdi(fonks, *, sinif=None, taslak=(), dizgi=None, cagri=None, giris=(), ana_bilinmiyor=False):
    return ts.SecimGirdisi(
        boyut={a: 10 for a in fonks},
        taslak=frozenset(taslak),
        dizgiler={a: frozenset(v) for a, v in (dizgi or {}).items()},
        cagrilan={a: frozenset(v) for a, v in (cagri or {}).items()},
        giris=frozenset(giris),
        sinif=dict(sinif or {}),
        ana_modul_bilinmiyor=ana_bilinmiyor,
    )


def basamaklar(sonuc):
    return {o.adres: o.basamak for o in sonuc.sira}


def sira(sonuc):
    return [o.adres for o in sonuc.sira]


def _kuru():
    spec = importlib.util.spec_from_file_location(
        "tembel_kuru_test", DEPO / "scripts" / "measurement" / "tembel_kuru.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["tembel_kuru_test"] = mod
    spec.loader.exec_module(mod)
    return mod


# --- sabitler -------------------------------------------------------------------------------

def test_sabitler_tasarimdaki_gibi():
    assert (ts.KURAL_SURUMU, ts.GIRIS_DERINLIGI, ts.GIRIS_UST_SINIR) == (1, 2, 256)
    assert ts.BASAMAKLAR == ("B0", "B1", "B2", "B3", "B4a", "B4b", "B5", "B6")


def test_go_sinif_eslemesi_okuyucunun_sabitlerinden():
    assert ts.go_sinifi(go_pclntab.SINIF_KENDI) == K
    assert ts.go_sinifi(go_pclntab.SINIF_UCUNCU_TARAF) == B
    for s in (go_pclntab.SINIF_STANDART, go_pclntab.SINIF_CALISMA_ZAMANI, go_pclntab.SINIF_DERLEYICI):
        assert ts.go_sinifi(s) == S
    assert ts.go_sinifi(go_pclntab.SINIF_PAKETSIZ) == U
    assert ts.go_sinifi(go_pclntab.SINIF_ADSIZ) == U


# --- basamaklar -----------------------------------------------------------------------------

def test_basamak_sirasi_kendi_once_sonra_kanitli_bilinmiyor():
    # 1: KENDI kanıtsız, 2: BILINMIYOR kanıtlı, 3: BILINMIYOR kanıtsız, 4: BAGIMLILIK, 5: taslak
    g = girdi([1, 2, 3, 4, 5], sinif={1: K, 4: B}, taslak=[5], dizgi={2: {100}})
    s = ts.sec(g)
    assert sira(s) == [1, 2, 3, 4, 5]
    assert basamaklar(s) == {1: "B2", 2: "B3", 3: "B4b", 4: "B5", 5: "B6"}


def test_kanitli_basamakta_anahtar_eksi_kanit_sonra_adres():
    g = girdi([1, 2, 3, 4], dizgi={1: {100}, 2: {100, 101, 102}, 3: {100, 101}, 4: {105, 106}})
    s = ts.sec(g)
    assert sira(s) == [2, 3, 4, 1]
    assert [o.anahtar for o in s.sira] == [(-3, 2), (-2, 3), (-2, 4), (-1, 1)]


def test_kanit_kume_boyutudur_ve_ice_aktarim_sayilir():
    # f, aynı dizgiye iki kez başvuruyor (strings.json'da iki xref) ve bir taslak çağırıyor.
    fdoc = {"functions": [{"address": "1000", "size": 4, "name": "FUN_1000"},
                          {"address": "2000", "size": 4, "name": "puts", "is_thunk": True}]}
    sdoc = {"strings": [{"address": "5000", "value": "a", "xrefs": [
        {"from_address": "1004", "from_func_addr": "1000"},
        {"from_address": "1008", "from_func_addr": "1000"}]}]}
    cdoc = {"nodes": {"1000": {"address": "1000", "callees": [{"address": "2000"}, {"address": "2000"}]}}}
    g = tg.girdiden_kur(fdoc, sdoc, cdoc)
    assert ts.kanit_hesapla(g)[0x1000] == 2  # 1 dizgi + 1 içe aktarım


def test_b4a_secilenin_cagirdigi_b4b_kalan():
    # 1 KENDI, 1 → 3 çağırıyor; 2 ve 3 kanıtsız BILINMIYOR
    g = girdi([1, 2, 3], sinif={1: K}, cagri={1: {3}})
    s = ts.sec(g)
    assert basamaklar(s) == {1: "B2", 3: "B4a", 2: "B4b"}
    assert sira(s) == [1, 3, 2]


def test_b4a_istegin_cagirdigini_de_sayar():
    g = girdi([1, 2, 3], sinif={1: S}, cagri={1: {3}})
    s = ts.sec(g, istek=[1])
    assert basamaklar(s) == {1: "B0", 3: "B4a", 2: "B4b"}


def test_taslak_yalniz_b6da():
    g = girdi([1, 2, 3], taslak=[2, 3], cagri={1: {2}})
    s = ts.sec(g)
    assert basamaklar(s) == {1: "B3", 2: "B6", 3: "B6"}  # 1'in kanıtı: çağırdığı taslak


def test_standart_kendiliginden_secilmez_istekle_secilir():
    g = girdi([1, 2], sinif={1: S, 2: S})
    s = ts.sec(g)
    assert sira(s) == [] and s.secilmeyen == (1, 2)
    s2 = ts.sec(g, istek=[2])
    assert sira(s2) == [2] and basamaklar(s2) == {2: "B0"} and s2.secilmeyen == (1,)


def test_istek_sirasi_korunur_yinelenen_ve_bulunamayan():
    g = girdi([1, 2, 3])
    s = ts.sec(g, istek=[3, 1, 3, 99])
    assert sira(s)[:2] == [3, 1]
    assert [o.anahtar for o in s.sira[:2]] == [(0,), (1,)]
    assert s.istek_bulunamayan == (99,)
    assert s.basamak_sayimi["B0"] == 2


# --- B1 giriş -------------------------------------------------------------------------------

def test_giris_uyesi_sinifina_bakilmadan_secilir():
    g = girdi([1, 2], sinif={1: S}, taslak=[2], giris=[1, 2])
    s = ts.sec(g)
    assert basamaklar(s) == {1: "B1", 2: "B1"}


def test_genisleme_standart_ve_taslaga_girmez_onlardan_gecmez():
    # E=1 → 2 (STANDART) → 3; 1 → 4 (TASLAK) → 5; 1 → 6 (BILINMIYOR) → 7
    g = girdi([1, 2, 3, 4, 5, 6, 7], sinif={2: S}, taslak=[4],
              cagri={1: {2, 4, 6}, 2: {3}, 4: {5}, 6: {7}}, giris=[1])
    b = basamaklar(ts.sec(g))
    assert b[1] == "B1" and b[6] == "B1" and b[7] == "B1"
    assert 2 not in b  # STANDART
    assert b[4] == "B6"
    assert b[3] != "B1" and b[5] != "B1"


def test_standart_giris_uyesinden_genisleme_ilerlemez():
    g = girdi([1, 2], sinif={1: S}, cagri={1: {2}}, giris=[1])
    b = basamaklar(ts.sec(g))
    assert b == {1: "B1", 2: "B4a"}  # B1'e girmez; seçilen (1) çağırdığı için B4a


def test_giris_derinligi_iki():
    g = girdi([1, 2, 3, 4], cagri={1: {2}, 2: {3}, 3: {4}}, giris=[1])
    s = ts.sec(g)
    b = basamaklar(s)
    assert [b[1], b[2], b[3]] == ["B1", "B1", "B1"] and b[4] == "B4a"
    assert [o.anahtar for o in s.sira[:3]] == [(0, 1), (1, 2), (2, 3)]


def test_giris_ust_siniri_256_derinlik_sonra_adres():
    fonks = [1] + list(range(1000, 1300))
    g = girdi(fonks, cagri={1: set(range(1000, 1300))}, giris=[1])
    s = ts.sec(g)
    b1 = [o.adres for o in s.sira if o.basamak == "B1"]
    assert len(b1) == ts.GIRIS_UST_SINIR
    assert b1 == [1] + list(range(1000, 1255))
    # sınırın dışında kalanlar sonraki basamakta (seçilenin çağırdığı)
    assert basamaklar(s)[1255] == "B4a"


# --- ana modül ------------------------------------------------------------------------------

def test_ana_modul_bulunamazsa_bagimlilik_b2de():
    g = girdi([1, 2, 3], sinif={1: K, 2: B}, dizgi={2: {7}}, ana_bilinmiyor=True)
    s = ts.sec(g)
    assert basamaklar(s) == {2: "B2", 1: "B2", 3: "B4b"}
    assert sira(s) == [2, 1, 3]  # aynı anahtar: (−kanıt, adres)
    assert s.basamak_sayimi["B5"] == 0 and s.ana_modul == ts.ANA_MODUL_BILINMIYOR


# --- adres, belirlenimcilik, kesim ------------------------------------------------------------

def test_adres_tam_sayiyla_karsilastirilir():
    fdoc = {"functions": [{"address": "1000", "size": 4, "name": "a"},
                          {"address": "9f0", "size": 4, "name": "b"}]}
    s = ts.sec(tg.girdiden_kur(fdoc, None, None))
    assert sira(s) == [0x9F0, 0x1000]


def _sentetik_belgeler(n=60, tohum=7):
    rng = random.Random(tohum)
    adresler = [0x1000 + 0x10 * i for i in range(n)]
    funcs = [{"address": f"{a:08x}", "size": rng.randint(1, 50), "name": f"FUN_{a:08x}",
              "is_thunk": i % 9 == 0} for i, a in enumerate(adresler)]
    funcs.append({"address": f"{adresler[1]:08x}", "size": 1, "name": "entry"})  # yinelenen adres
    strings = [{"address": f"{0x90000 + j:x}", "value": str(j), "xrefs": [
        {"from_address": f"{a + 4:x}", "from_func_addr": f"{a:08x}"}
        for a in rng.sample(adresler, rng.randint(0, 3))]} for j in range(30)]
    nodes = {f"{a:08x}": {"address": f"{a:08x}", "name": f"FUN_{a:08x}",
                          "callers": [], "callees": [{"address": f"{c:08x}", "name": "x"}
                                                     for c in rng.sample(adresler, rng.randint(0, 4))]}
             for a in adresler}
    return {"functions": funcs}, {"strings": strings}, {"nodes": nodes}


def test_yirmi_permutasyonda_ayni_sha():
    kuru = _kuru()
    docs = _sentetik_belgeler()
    ilk = ts.sec(tg.girdiden_kur(*docs)).sha256
    for tohum in range(20):
        pdocs = kuru._karistir(docs, random.Random(tohum))
        assert ts.sec(tg.girdiden_kur(*pdocs)).sha256 == ilk


def test_kes_ilk_n_ve_sifir_sinirsiz():
    g = girdi([1, 2, 3, 4], dizgi={4: {9}})
    s = ts.sec(g)
    k2 = ts.kes(s, 2)
    assert sira(k2) == sira(s)[:2] and len(k2.sira) == 2
    assert k2.tam_sha256 == s.sha256 and k2.sha256 != s.sha256 and k2.ust_sinir == 2
    assert sira(ts.kes(s, 0)) == sira(s)
    assert sira(ts.kes(s, 99)) == sira(s)
    with pytest.raises(ValueError):
        ts.kes(s, -1)


def test_bos_girdi():
    s = ts.sec(girdi([]))
    assert s.sira == () and s.secilmeyen == () and s.tam_uzunluk == 0
    assert s.sha256 == ts.sira_ozeti([])


def test_c_ikilisinde_sinirsiz_secim_butun_fonksiyonlar():
    g = girdi([1, 2, 3, 4, 5], taslak=[5], dizgi={2: {1}}, cagri={1: {3}}, giris=[1])
    s = ts.sec(g)
    assert sorted(sira(s)) == [1, 2, 3, 4, 5] and s.secilmeyen == ()


def test_gecersiz_sinif_reddedilir():
    with pytest.raises(ValueError):
        ts.sec(girdi([1], sinif={1: "kendi"}))


# --- girdi bağdaştırıcısı -------------------------------------------------------------------------

def _go(ad, giris, sinif):
    return SimpleNamespace(ad=ad, giris=giris, sinif=sinif)


def test_girdiden_kur_go_objc_giris_ve_delta():
    fdoc = {"functions": [
        {"address": "101000", "size": 64, "name": "FUN_101000"},   # main.main (Go kendi)
        {"address": "101100", "size": 64, "name": "FUN_101100"},   # Go runtime
        {"address": "101200", "size": 64, "name": "FUN_101200"},   # Go paketsiz + ObjC
        {"address": "101300", "size": 64, "name": "FUN_101300"},   # giriş adresini içeren
        {"address": "101400", "size": 4, "name": "objc_stub", "is_thunk": True},
    ]}
    go_s = SimpleNamespace(durum="calisti", buildinfo={"mod": "example.com/x"}, fonksiyonlar=[
        _go("main.main", 0x1000, go_pclntab.SINIF_KENDI),
        _go("runtime.x", 0x1100, go_pclntab.SINIF_CALISMA_ZAMANI),
        _go("", 0x1200, go_pclntab.SINIF_ADSIZ),
        _go("x.y", 0x1400, go_pclntab.SINIF_KENDI),  # taslağa düşen: sınıf almaz
    ])
    objc_s = SimpleNamespace(durum="calisti", yontemler=[
        SimpleNamespace(imp=0x1200), SimpleNamespace(imp=0x1100), SimpleNamespace(imp=0)])
    gor = SimpleNamespace(giris_adresi=0x1320)
    g = tg.girdiden_kur(fdoc, None, None, gor, delta=0x100000, go_sonuc=go_s, objc_sonuc=objc_s)
    sinif = ts.siniflandir(g)
    assert sinif[0x101000] == K and sinif[0x101100] == S and sinif[0x101200] == K
    assert sinif[0x101300] == U and sinif[0x101400] == T
    assert g.giris == frozenset({0x101000, 0x101300})
    assert g.ana_modul_bilinmiyor is False
    assert g.kunye["go_eslenen"] == 3 and g.kunye["objc_eslenen"] == 1


def test_girdiden_kur_ana_modul_yoksa_bilinmiyor():
    fdoc = {"functions": [{"address": "1000", "size": 8, "name": "FUN_1000"}]}
    go_s = SimpleNamespace(durum="calisti", buildinfo=None,
                           fonksiyonlar=[_go("a.b", 0x1000, go_pclntab.SINIF_UCUNCU_TARAF)])
    g = tg.girdiden_kur(fdoc, None, None, None, go_sonuc=go_s,
                        objc_sonuc=SimpleNamespace(durum="veri_yok", yontemler=[]))
    assert g.ana_modul_bilinmiyor is True
    assert basamaklar(ts.sec(g)) == {0x1000: "B2"}


def test_ghidra_entry_adi_girise_girer_gorunu_olmadan():
    fdoc = {"functions": [{"address": "10", "size": 8, "name": "entry"},
                          {"address": "20", "size": 8, "name": "FUN_20"}]}
    cdoc = {"nodes": {"10": {"address": "10", "callees": [{"address": "20"}]}}}
    s = ts.sec(tg.girdiden_kur(fdoc, None, cdoc))
    assert basamaklar(s) == {0x10: "B1", 0x20: "B1"}
