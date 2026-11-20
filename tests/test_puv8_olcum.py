"""P-ÜV8 kalem 1–4 ölçü işlevleri (HEDEF paketi): ad eşitliği, kanal sayımı, Wilson / A-2, bütçe, H1,
set bölmesi ve ürün adı süzgeci. Hepsi sentetik veriyle; gerçek ikiliye bağlı test yok (PLAN §0)."""
from __future__ import annotations

import struct
import sys
from pathlib import Path

import pytest

DEPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(DEPO / "scripts" / "measurement"))

import ustveri_olc as uo  # noqa: E402
import ustveri_set as us  # noqa: E402
from ks1_olc import oran  # noqa: E402


# --------------------------------------------------------------------------------------------
# Kalem 2 — ad eşitliği


class TestGoYazimi:
    def test_birebir_mach_o_oneki_soyulur(self):
        assert uo.go_yazimi("main.main", "_main.main") == uo.YAZIM_BIREBIR

    def test_abi0_ve_abiinternal_eki(self):
        assert uo.go_yazimi("runtime.memmove", "_runtime.memmove.abi0") == uo.YAZIM_ABI
        assert uo.go_yazimi("runtime.memmove", "_runtime.memmove.abiinternal") == uo.YAZIM_ABI

    def test_abi_kurali_baska_eki_soymaz(self):
        # `.func1` kapanış adıdır, ABI eki değil: soyulursa yanlış ad doğru sayılır.
        assert uo.go_yazimi("pkg.Run", "_pkg.Run.func1") is None
        assert uo.abi_eki_soy("pkg.Run.func1") == "pkg.Run.func1"

    def test_orta_nokta_yazimi(self):
        assert uo.go_yazimi("pkg.T·M", "_pkg.T.M") == uo.YAZIM_ORTA_NOKTA
        assert uo.go_yazimi("pkg.T·M", "_pkg.T.N") is None


class TestObjcYazimi:
    def test_birebir(self):
        assert uo.objc_yazimi("-[AppDelegate run:]", "-[AppDelegate run:]") == uo.YAZIM_BIREBIR

    def test_kategori_soyulur_sinif_kalir(self):
        assert uo.kategori_soy("-[NSUserDefaults(Ek) oku:]") == "-[NSUserDefaults oku:]"
        assert uo.objc_yazimi("-[NSUserDefaults oku:]", "-[NSUserDefaults(Ek) oku:]") == uo.YAZIM_KATEGORI

    def test_kategori_kurali_baska_sinifi_esitlemez(self):
        assert uo.objc_yazimi("-[Baska oku:]", "-[NSUserDefaults(Ek) oku:]") is None
        assert uo.objc_yazimi("+[NSUserDefaults oku:]", "-[NSUserDefaults(Ek) oku:]") is None


class TestSwiftVeRtti:
    def test_swift_enjekte_cozucu(self):
        cozum = uo.swift_cozum(["_$s4Uyg3FooCMa", "_main"], cozucu=lambda xs: [f"type metadata accessor for Uyg.Foo"])
        assert cozum == {"_$s4Uyg3FooCMa": "type metadata accessor for Uyg.Foo"}
        assert uo.yazim(uo.KANAL_SWIFT, "type metadata accessor for Uyg.Foo", "_$s4Uyg3FooCMa", cozum) == uo.YAZIM_DEMANGLE
        assert uo.yazim(uo.KANAL_SWIFT, "type metadata accessor for Uyg.Bar", "_$s4Uyg3FooCMa", cozum) is None

    def test_swift_cozucu_satir_sayisi_tutmazsa_hata(self):
        with pytest.raises(RuntimeError):
            uo.swift_cozum(["_$sA", "_$sB"], cozucu=lambda xs: ["tek satır"])

    def test_rtti_onekleri_karismaz(self):
        assert uo.yazim(uo.KANAL_RTTI_TI, "3Foo", "__ZTI3Foo") == uo.YAZIM_ONEK
        assert uo.yazim(uo.KANAL_RTTI_VT, "3Foo", "__ZTV3Foo") == uo.YAZIM_ONEK
        assert uo.yazim(uo.KANAL_RTTI_TI, "3Foo", "__ZTV3Foo") is None


def test_urun_esit_birebir_go_objc():
    assert uo.urun_esit("main", "_main")
    assert uo.urun_esit("runtime.memmove", "_runtime.memmove.abi0")
    assert uo.urun_esit("-[A b]", "-[A(K) b]")
    assert not uo.urun_esit("usage", "_main")


# --------------------------------------------------------------------------------------------
# Kalem 3 — kanal sayımı, Wilson, A-2


def test_kanal_olc_gt_siz_paydaya_girmez():
    cikti = {0x10: {"a"}, 0x20: {"b"}, 0x30: {"c"}}
    gt = {0x10: ["_a"], 0x20: ["_x"]}
    r = uo.kanal_olc(cikti, gt, uo.KANAL_GO)
    assert (r["ad_verilen"], r["dogru"], r["yanlis"], r["gt_siz"]) == (3, 1, 1, 1)
    assert r["kesinlik"]["n"] == 2 and r["kesinlik"]["k"] == 1
    assert r["yazim"] == {uo.YAZIM_BIREBIR: 1}


def test_cok_adli_adreste_butun_adlar_dogru_olmali():
    assert uo.kanal_olc({1: {"a", "b"}}, {1: ["_a"]}, uo.KANAL_GO)["yanlis"] == 1
    r = uo.kanal_olc({1: {"a", "b"}}, {1: ["_a", "_b"]}, uo.KANAL_GO)
    assert (r["dogru"], r["cok_adli"]) == (1, 1)


def test_wilson_alt_kesin_ks1_ile_ayni():
    import macho_f1 as mf
    for k, n in ((32, 32), (35048, 35048), (300, 303), (5, 9)):
        assert round(uo.wilson_alt_kesin(k, n), 4) == oran(k, n)["aralik"][0]
    z = mf.WILSON_Z_95
    assert uo.wilson_alt_kesin(32, 32) == pytest.approx(1 / (1 + z * z / 32))
    assert uo.wilson_alt_kesin(0, 0) is None


def test_a2_satiri_esik_ve_n():
    # k = n iken alt sınır 1 / (1 + z²/n) ≥ 10/11 ⇔ n ≥ 10 z² ≈ 38,4
    assert uo.a2_satiri(38, 0)["karar"] == uo.A2_HAYIR
    assert uo.a2_satiri(39, 0)["karar"] == uo.A2_EVET
    assert uo.a2_satiri(32, 0)["karar"] == uo.A2_HAYIR
    assert uo.a2_satiri(0, 0)["karar"] == uo.A2_VERI_YOK
    assert uo.a2_satiri(300, 3)["alt_sinir"] == round(uo.wilson_alt_kesin(300, 303), 6)


def test_h1_farki():
    a = {"kanallar": {k: {"durum": uo.DURUM_VERI_YOK, "adlar": {}} for k in uo.KANALLAR}}
    b = {"kanallar": {k: {"durum": uo.DURUM_VERI_YOK, "adlar": {}} for k in uo.KANALLAR}}
    a["kanallar"][uo.KANAL_GO] = {"durum": uo.DURUM_CALISTI, "adlar": {1: {"x"}, 2: {"y"}}}
    b["kanallar"][uo.KANAL_GO] = {"durum": uo.DURUM_CALISTI, "adlar": {1: {"x"}, 2: {"z"}}}
    f = uo.h1_farki(a, b)
    assert f[uo.KANAL_GO]["ad_farkli"] == 1 and not f[uo.KANAL_GO]["ayni"]
    assert f[uo.KANAL_OBJC]["ayni"]


def test_tsv_oku_go_ve_objc(tmp_path):
    g = tmp_path / "g.tsv"
    g.write_text("0x100\t0x110\tkendi\tmain\tmain.main\t/a.go\t0\t0\n0x110\t0x120\tadsiz\t\t\t\t0\t0\n")
    assert uo.tsv_oku(uo.KANAL_GO, g) == {0x100: {"main.main"}}
    o = tmp_path / "o.tsv"
    o.write_text("0x200\t-\tA\t\tb:\t0\t0\tv24\n0x210\t+\tA\tK\tc\t0\t0\t\n")
    assert uo.tsv_oku(uo.KANAL_OBJC, o) == {0x200: {"-[A b:]"}, 0x210: {"+[A c]"}}


# --------------------------------------------------------------------------------------------
# Bütçe (kalem 4 planı)


def test_butce_say_kesin_veya_sembol_birlesim():
    nufus = {1, 2, 3, 4, 5, 6}
    r = uo.butce_say(nufus, go={1, 2, 99}, objc={3}, sw_erisim=set(), sw_yuva={4}, rtti={3, 5},
                     sembol={2, 6, 98})
    assert r["kesin"] == 3                   # 1, 2, 3 (99 nüfus dışı)
    assert r["kesin_veya_sembol"] == 4       # 1, 2, 3, 6 (2 ikisinde de)
    assert r["kalan"] == 2                   # 4, 5
    assert r["yuva"] == 2 and r["rtti_yuva"] == 1   # 3 kesin olduğu için yuva sayılmaz
    assert r["kalanin_yuvalisi"] == 2


# --------------------------------------------------------------------------------------------
# Kalem 1 — set


def test_bolme_sabit_ve_ayrik():
    assert set(us.KESIF_IKILILERI) == {"terminal-notifier", "docker-cli"}
    assert set(us.SINAMA_IKILILERI) == {"docker-compose", "iTerm2", "llama-server"}
    assert set(us.KESIF_IKILILERI) | set(us.SINAMA_IKILILERI) == set(us.SET)
    assert us.bolme("iTerm2") == us.BOLME_SINAMA


def test_sinama_ikilisinde_kanal_kesinligi_reddedilir(tmp_path):
    with pytest.raises(SystemExit):
        uo.kanal_olcumu("docker-compose", tmp_path)


def _fat(dilimler: list[tuple[int, bytes]]) -> bytes:
    bas = struct.pack(">II", us.FAT_MAGIC, len(dilimler))
    ofs = 4096
    govde = b""
    for cpu, veri in dilimler:
        bas += struct.pack(">IIIII", cpu, 0, ofs + len(govde), len(veri), 12)
        govde += veri
    return bas + b"\0" * (ofs - len(bas)) + govde


def test_dilim_kes_evrensel_ve_ince():
    x86 = struct.pack("<II", 0xFEEDFACF, 0x01000007) + b"X" * 24
    arm = struct.pack("<II", 0xFEEDFACF, 0x0100000C) + b"A" * 40
    ham = _fat([(0x01000007, x86), (0x0100000C, arm)])
    assert us.dilim_kes(ham, "arm64") == arm
    assert us.dilim_kes(ham, "x86_64") == x86
    with pytest.raises(us.SetHatasi):
        us.dilim_kes(ham, None)
    assert us.dilim_kes(arm, None) == arm


def test_nm_ayristir_fonksiyon_ve_rtti():
    metin = ("0000000100000000 T __mh_execute_header\n"
             "0000000100001000 T _main\n"
             "0000000100001000 t _main_takma\n"
             "0000000100002000 t -[A b:]\n"
             "0000000100008000 S __ZTI3Foo\n"
             "0000000100008100 s __ZTV3Foo\n"
             "0000000100008200 S _veri\n")
    fonk, rtti = us.nm_ayristir(metin)
    assert fonk == {0x100001000: ["_main", "_main_takma"], 0x100002000: ["-[A b:]"]}
    assert rtti == {0x100008000: ["__ZTI3Foo"], 0x100008100: ["__ZTV3Foo"]}
    s = us.gt_sayilari(fonk, rtti)
    assert (s["typeinfo_adi"], s["vtable_adi"], s["cok_adli_adres"]) == (1, 1, 1)
    assert s["ad_turu_adres"]["objc"] == 1 and s["ad_turu_adres"]["diger"] == 1


# --------------------------------------------------------------------------------------------
# Kalem 4 — ürün adı süzgeci


def test_urun_kayitlari_suzgec_ve_hukum():
    gfonk = [{"addr": 0x1000, "name": "FUN_00001000", "is_thunk": False, "size": 8},
             {"addr": 0x2000, "name": "Ghidra_adi", "is_thunk": False, "size": 8},
             {"addr": 0x3000, "name": "FUN_00003000", "is_thunk": False, "size": 8},
             {"addr": 0x4000, "name": "FUN_00004000", "is_thunk": False, "size": 8}]
    genel = {"FUN_00001000": "main", "FUN_00002000": "x", "FUN_00003000": "usage",
             "FUN_00004000": "gt_siz_ad", "FUN_00005000": "yok", "DAT_00006000": "veri"}
    gt = {0x1000: ["_main"], 0x2000: ["_x"], 0x3000: ["_dogrusu"]}
    nufus = uo.urun_nufusu(gt, gfonk)
    assert nufus == {0x1000, 0x3000}
    kayitlar, sayac = uo.urun_kayitlari(genel, {}, gfonk, gt, nufus)
    durum = {k["adres"]: k["durum"] for k in kayitlar}
    assert durum == {0x1000: uo.DOGRU, 0x3000: uo.YANLIS, 0x4000: uo.GT_SIZ}
    assert sayac["ghidra_adli"] == 1 and sayac["ghidra_fonksiyonu_yok"] == 1
    oz = uo.urun_ozeti(kayitlar, nufus)
    assert (oz["toplam"]["dogru"], oz["toplam"]["yanlis"], oz["toplam"]["gt_siz"]) == (1, 1, 1)
    assert oz["dogru_kapsam"]["k"] == 1 and oz["dogru_kapsam"]["n"] == 2
