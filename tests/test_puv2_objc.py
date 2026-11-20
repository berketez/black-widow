"""P-ÜV2 — Objective-C yöntem listesi okuyucu ve ``objc_metadata_recovery`` adımı (sentetik görüntü).

Test verisi kuralı (ustveri/PLAN.md §0): gerçek ikili yok; ``struct.pack`` ile kurulan küçük bir görüntü:
bir sınıf + meta sınıfı (küçük biçimli 2 yöntem seçici başvurusu üstünden, meta sınıfta büyük biçimli 1
yöntem), Swift işaretli ikinci sınıf (``bits`` yeniden konumlamayla), dış sınıfa kategori (bağ, seçici
doğrudan), protokol. Biçim kaynağı: objc4 ``runtime/objc-runtime-new.h``.
"""

from __future__ import annotations

import json
import struct
from pathlib import Path
from typing import Any, Optional
from unittest.mock import MagicMock

import pytest

from karadul.analyzers.ustveri import objc
from karadul.analyzers.ustveri.goruntu import Bag, BellekGoruntu, GoruntuHatasi
from karadul.config import BinaryReconstructionConfig, Config
from karadul.pipeline.context import StepContext
from karadul.pipeline.registry import get_step
from karadul.pipeline.steps import objc_metadata_recovery as adim_mod
from karadul.pipeline.steps.objc_metadata_recovery import ObjcMetadataRecoveryStep

# =============================================================================================
# Sentetik görüntü kurucusu

TEXT, METHNAME, CLASSNAME, METHTYPE, METHLIST = 0x100001000, 0x100002000, 0x100002400, 0x100002600, 0x100003000
SELREFS, CLASSLIST, CATLIST, PROTOLIST = 0x100004000, 0x100005000, 0x100005100, 0x100005200
CONST, DATA, PROTO_DATA = 0x100006000, 0x100007000, 0x100008000
F0, F1, F2, F3, F4 = TEXT, TEXT + 0x20, TEXT + 0x40, TEXT + 0x60, TEXT + 0x80
SMALL, DIRECT = 0x80000000, 0x40000000


class Kurucu:
    """Bölümlere bayt yazan küçük yardımcı. Göstericiler ham sözcük (eski ``LC_DYLD_INFO`` düzeni);
    bağlar ve yeniden konumlamalar ``BellekGoruntu`` sözlükleriyle (zincirli düzeltmenin karşılığı)."""

    def __init__(self) -> None:
        self.bolum: dict[str, list[Any]] = {}
        self.baglar: dict[int, Bag] = {}
        self.rk: dict[int, int] = {}
        self.listeler: dict[str, tuple[int, list[int]]] = {}
        for ad, adres, boy, kod, bolut in (
            ("__text", TEXT, 0x400, True, "__TEXT"),
            ("__objc_methname", METHNAME, 0x400, False, "__TEXT"),
            ("__objc_classname", CLASSNAME, 0x200, False, "__TEXT"),
            ("__objc_methtype", METHTYPE, 0x400, False, "__TEXT"),
            ("__objc_methlist", METHLIST, 0x400, False, "__TEXT"),
            ("__objc_selrefs", SELREFS, 0x200, False, "__DATA"),
            ("__objc_const", CONST, 0x800, False, "__DATA_CONST"),
            ("__objc_data", DATA, 0x400, False, "__DATA"),
            ("__data", PROTO_DATA, 0x400, False, "__DATA"),
        ):
            self.bolum[ad] = [adres, bytearray(boy), kod, bolut, 0]

    def ayir(self, ad: str, n: int, hiza: int = 8) -> int:
        b = self.bolum[ad]
        imlec = (b[4] + hiza - 1) // hiza * hiza
        b[4] = imlec + n
        assert b[4] <= len(b[1]), ad
        return b[0] + imlec

    def yaz(self, adres: int, veri: bytes) -> None:
        for bas, buf, *_ in self.bolum.values():
            if bas <= adres < bas + len(buf):
                buf[adres - bas:adres - bas + len(veri)] = veri
                return
        raise AssertionError(hex(adres))

    def p64(self, adres: int, deger: int) -> None:
        self.yaz(adres, struct.pack("<Q", deger))

    def dizgi(self, ad: str, metin: str) -> int:
        veri = metin.encode() + b"\0"
        a = self.ayir(ad, len(veri), 1)
        self.yaz(a, veri)
        return a

    def selref(self, secici: str) -> int:
        s = self.dizgi("__objc_methname", secici)
        r = self.ayir("__objc_selrefs", 8)
        self.p64(r, s)
        return r

    def kucuk_liste(self, kayitlar: list[tuple[str, str, int]], dogrudan: bool = False) -> int:
        """Küçük biçimli liste: (seçici, tip, IMP); ofsetler her alanın kendi adresine göre."""
        a = self.ayir("__objc_methlist", 8 + 12 * len(kayitlar), 4)
        self.yaz(a, struct.pack("<II", 12 | SMALL | (DIRECT if dogrudan else 0), len(kayitlar)))
        for i, (sec, tip, imp) in enumerate(kayitlar):
            e = a + 8 + 12 * i
            ad_yeri = self.dizgi("__objc_methname", sec) if dogrudan else self.selref(sec)
            t = self.dizgi("__objc_methtype", tip)
            self.yaz(e, struct.pack("<iii", ad_yeri - e, t - (e + 4), imp - (e + 8)))
        return a

    def buyuk_liste(self, kayitlar: list[tuple[str, str, int]]) -> int:
        a = self.ayir("__objc_const", 8 + 24 * len(kayitlar))
        self.yaz(a, struct.pack("<II", 24, len(kayitlar)))
        for i, (sec, tip, imp) in enumerate(kayitlar):
            e = a + 8 + 24 * i
            self.yaz(e, struct.pack("<QQQ", self.dizgi("__objc_methname", sec),
                                    self.dizgi("__objc_methtype", tip), imp))
        return a

    def ro(self, ad: str, yontemler: int = 0, protokoller: int = 0, meta: bool = False) -> int:
        r = self.ayir("__objc_const", 72)
        self.yaz(r, struct.pack("<I", 1 if meta else 0))
        self.p64(r + 24, self.dizgi("__objc_classname", ad))
        self.p64(r + 32, yontemler)
        self.p64(r + 40, protokoller)
        return r

    def sinif(self, ro: int, isa: int = 0, ust: Any = 0, swift_bitleri: int = 0,
              bits_rk: bool = False) -> int:
        c = self.ayir("__objc_data", 40)
        self.p64(c, isa)
        if isinstance(ust, Bag):
            self.baglar[c + 8] = ust
        else:
            self.p64(c + 8, ust)
        if bits_rk:  # zincirli düzeltme gibi: dosyadaki sözcük anlamsız, hedef gosterici()'den
            self.p64(c + 32, 0x00F0_0000_DEAD_BEEF)
            self.rk[c + 32] = ro | swift_bitleri
        else:
            self.p64(c + 32, ro | swift_bitleri)
        return c

    def protokol(self, ad: str, ornek_yontemleri: int = 0) -> int:
        p = self.ayir("__data", 56)
        self.p64(p + 8, self.dizgi("__objc_classname", ad))
        self.p64(p + 24, ornek_yontemleri)
        return p

    def protokol_listesi(self, protokoller: list[int]) -> int:
        a = self.ayir("__objc_const", 8 + 8 * len(protokoller))
        self.p64(a, len(protokoller))
        for i, p in enumerate(protokoller):
            self.p64(a + 8 + 8 * i, p)
        return a

    def kategori(self, ad: str, sinif: Any, ornek: int = 0, sinif_yontemleri: int = 0) -> int:
        k = self.ayir("__objc_const", 48)
        self.p64(k, self.dizgi("__objc_classname", ad))
        if isinstance(sinif, Bag):
            self.baglar[k + 8] = sinif
        else:
            self.p64(k + 8, sinif)
        self.p64(k + 16, ornek)
        self.p64(k + 24, sinif_yontemleri)
        return k

    def liste(self, ad: str, adres: int, girdiler: list[int]) -> None:
        self.listeler[ad] = (adres, girdiler)

    def goruntu(self, fonksiyon_baslangiclari: Optional[list[int]] = None, **kw: Any) -> Any:
        bolumler = [(ad, b[0], bytes(b[1]), b[2], b[3]) for ad, b in self.bolum.items()]
        for ad, (adres, girdiler) in self.listeler.items():
            bolumler.append((ad, adres, b"".join(struct.pack("<Q", g) for g in girdiler), False, "__DATA_CONST"))
        return BellekGoruntu(bolumler, fonksiyon_baslangiclari=fonksiyon_baslangiclari,
                             yeniden_konumlamalar=self.rk, baglar=self.baglar, **kw)


def ornek_kurucu() -> Kurucu:
    k = Kurucu()
    sesli = k.protokol("Sesli", k.buyuk_liste([("miyavla", "v16@0:8", 0)]))
    k.liste("__objc_protolist", PROTOLIST, [sesli])
    meta_ro = k.ro("Kedi", k.buyuk_liste([("yeni", "@16@0:8", F2)]), meta=True)
    meta = k.sinif(meta_ro, ust=Bag("_OBJC_METACLASS_$_NSObject"))
    kedi_ro = k.ro("Kedi", k.kucuk_liste([("miyavla", "v16@0:8", F0), ("ye:", "v24@0:8@16", F1)]),
                   k.protokol_listesi([sesli]))
    kedi = k.sinif(kedi_ro, isa=meta, ust=Bag("_OBJC_CLASS_$_NSObject"))
    kopek_ro = k.ro("_TtC4Ornek5Kopek", k.kucuk_liste([("havla", "v16@0:8", F4)]))
    kopek = k.sinif(kopek_ro, ust=kedi, swift_bitleri=2, bits_rk=True)
    k.liste("__objc_classlist", CLASSLIST, [kedi, kopek])
    kat = k.kategori("Ek", Bag("_OBJC_CLASS_$_NSString"),
                     ornek=k.kucuk_liste([("kedice", "@16@0:8", F3)], dogrudan=True))
    k.liste("__objc_catlist", CATLIST, [kat])
    return k


def ornek_goruntu(fb: Optional[list[int]] = None) -> Any:
    return ornek_kurucu().goruntu(fonksiyon_baslangiclari=[F0, F1, F2, F3, F4] if fb is None else fb)


def _satirlar(sonuc: objc.ObjcSonuc) -> list[tuple]:
    return [(y.imp, y.tur, y.sinif, y.kategori, y.secici) for y in sonuc.yontemler]


ORNEK_KAYITLAR = [
    (F0, "-", "Kedi", None, "miyavla"),
    (F1, "-", "Kedi", None, "ye:"),
    (F2, "+", "Kedi", None, "yeni"),
    (F4, "-", "_TtC4Ornek5Kopek", None, "havla"),
    (F3, "-", "NSString", "Ek", "kedice"),
]


# =============================================================================================
# Okuyucu


class TestOkuyucu:
    def test_butun_kayitlar_adres_ve_ad(self) -> None:
        s = objc.oku(ornek_goruntu())
        assert s.durum == objc.DURUM_CALISTI, s.neden
        assert _satirlar(s) == ORNEK_KAYITLAR
        assert s.okuma_hatasi == 0

    def test_kucuk_bicim_secici_basvurusu_uzerinden(self) -> None:
        s = objc.oku(ornek_goruntu())
        kedi = [y for y in s.yontemler if y.sinif == "Kedi" and y.tur == "-"]
        assert [(y.secici, y.tip, y.imp, y.liste_bicimi) for y in kedi] == [
            ("miyavla", "v16@0:8", F0, objc.BICIM_KUCUK), ("ye:", "v24@0:8@16", F1, objc.BICIM_KUCUK)]

    def test_secici_dogrudan_bayragi(self) -> None:
        s = objc.oku(ornek_goruntu())
        kat = [y for y in s.yontemler if y.kategori == "Ek"]
        assert [(y.secici, y.tip, y.imp) for y in kat] == [("kedice", "@16@0:8", F3)]

    def test_meta_sinif_yontemi_arti_ve_buyuk_bicim(self) -> None:
        s = objc.oku(ornek_goruntu())
        arti = [y for y in s.yontemler if y.tur == "+"]
        assert [(y.sinif, y.secici, y.imp, y.liste_bicimi) for y in arti] == [
            ("Kedi", "yeni", F2, objc.BICIM_BUYUK)]
        assert arti[0].tam_ad == "+[Kedi yeni]"

    def test_tam_ad_ve_secici_ayri_alan(self) -> None:
        s = objc.oku(ornek_goruntu())
        d = s.yontemler[1].as_dict()
        assert d["tam_ad"] == "-[Kedi ye:]" and d["secici"] == "ye:"
        assert d["adres"] == f"{F1:#x}" and d["imp"] == F1

    def test_kategori_dis_sinif_bagi_onek_soyulur(self) -> None:
        s = objc.oku(ornek_goruntu())
        y = s.yontemler[-1]
        assert (y.sinif, y.kategori, y.sinif_dis, y.kaynak) == ("NSString", "Ek", True, objc.KAYNAK_KATEGORI)
        assert y.tam_ad == "-[NSString kedice]"  # kategori adı ayrı alanda, tam adda değil
        assert s.kategori_sayisi == 1

    def test_swift_isareti_ve_veri_maskesi(self) -> None:
        s = objc.oku(ornek_goruntu())
        kopek = [y for y in s.yontemler if y.secici == "havla"]
        assert len(kopek) == 1 and kopek[0].swift is True
        assert [y.swift for y in s.yontemler if y.sinif == "Kedi"] == [False, False, False]
        siniflar = {c.ad: c for c in s.siniflar}
        assert siniflar["_TtC4Ornek5Kopek"].swift and not siniflar["Kedi"].swift

    def test_protokolde_isareti(self) -> None:
        s = objc.oku(ornek_goruntu())
        pr = {y.secici: y.protokolde for y in s.yontemler}
        assert pr == {"miyavla": True, "ye:": False, "yeni": False, "havla": False, "kedice": False}
        assert s.protokol_sayisi == 1
        assert {c.ad: c.protokoller for c in s.siniflar}["Kedi"] == ["Sesli"]

    def test_ust_sinif_ve_zincir(self) -> None:
        s = objc.oku(ornek_goruntu())
        c = {c.ad: c for c in s.siniflar}
        assert (c["Kedi"].ust, c["Kedi"].ust_dis, c["Kedi"].ust_zinciri) == ("NSObject", True, ["NSObject"])
        assert (c["_TtC4Ornek5Kopek"].ust, c["_TtC4Ornek5Kopek"].ust_dis) == ("Kedi", False)
        assert c["_TtC4Ornek5Kopek"].ust_zinciri == ["Kedi", "NSObject"]
        assert c["Kedi"].meta is True and c["Kedi"].sinif_yontemi == 1 and c["Kedi"].ornek_yontem == 2

    def test_dongusel_ust_sinif_sayacla_kesilir(self) -> None:
        k = Kurucu()
        a_ro, b_ro = k.ro("A"), k.ro("B")
        a = k.sinif(a_ro)
        b = k.sinif(b_ro, ust=a)
        k.p64(a + 8, b)  # A → B → A
        k.liste("__objc_classlist", CLASSLIST, [a, b])
        s = objc.oku(k.goruntu())
        assert s.durum == objc.DURUM_CALISTI
        assert {c.ad: c.ust_zinciri for c in s.siniflar} == {"A": ["B"], "B": ["A"]}
        assert s.sayaclar[objc.H_DONGUSEL_UST] == 2

    def test_denetimler_ve_ozet(self) -> None:
        s = objc.oku(ornek_goruntu())
        d = s.denetim
        assert d["ayrik_imp"] == 5 and d["imp_kod_bolumunde"] == 5 and d["imp_kod_disi"] == 0
        assert d["imp_fonksiyon_baslangici"] == 5 and d["birden_cok_adli_imp"] == 0
        assert d["arite"] == {"uyan": 5, "uymayan": 0, "cozulemedi": 0}
        assert all(y.ad_yazilabilir for y in s.yontemler)
        oz = s.ozet()
        assert (oz["sinif"], oz["swift_sinifi"], oz["kategori"], oz["yontem_kaydi"]) == (2, 1, 1, 5)

    def test_fonksiyon_baslangici_olmayan_imp_ad_yazilmaz(self) -> None:
        s = objc.oku(ornek_goruntu(fb=[F0, F1, F2, F3]))
        y = [y for y in s.yontemler if y.imp == F4][0]
        assert y.imp_baslangic is False and y.ad_yazilabilir is False
        assert s.durum == objc.DURUM_CALISTI  # kayıt düzeyi; durum bozulmaz
        assert s.denetim["imp_fonksiyon_baslangici"] == 4

    def test_baslangic_tablosu_yoksa_none(self) -> None:
        g = ornek_kurucu().goruntu(fonksiyon_baslangiclari=None)
        s = objc.oku(g)
        assert all(y.imp_baslangic is None and y.ad_yazilabilir for y in s.yontemler)
        assert s.denetim["imp_fonksiyon_baslangici"] is None

    def test_kod_disi_imp_tutarsiz(self) -> None:
        k = Kurucu()
        ro = k.ro("X", k.kucuk_liste([("a", "v16@0:8", F0), ("b", "v16@0:8", CONST + 0x10)]))
        k.liste("__objc_classlist", CLASSLIST, [k.sinif(ro)])
        s = objc.oku(k.goruntu(fonksiyon_baslangiclari=[F0]))
        assert s.durum == objc.DURUM_TUTARSIZ and "kod bölümü dışında 1 IMP" in s.neden
        y = [y for y in s.yontemler if y.secici == "b"][0]
        assert y.imp_kodda is False and not y.ad_yazilabilir

    def test_bolum_disi_goreli_ofset_kayit_atlanir(self) -> None:
        k = Kurucu()
        ro = k.ro("X", k.kucuk_liste([("a", "v16@0:8", F0), ("b", "v16@0:8", 0x100100000)]))
        k.liste("__objc_classlist", CLASSLIST, [k.sinif(ro)])
        s = objc.oku(k.goruntu(fonksiyon_baslangiclari=[F0]))
        assert [y.secici for y in s.yontemler] == ["a"]
        assert s.sayaclar[objc.H_BOLUM_DISI] == 1
        assert s.durum == objc.DURUM_TUTARSIZ

    def test_kategori_listede_olmayan_yerel_sinifa(self) -> None:
        k = Kurucu()
        gizli = k.sinif(k.ro("Gizli"))  # sınıf listesinde yok
        kat = k.kategori("Ek2", gizli, ornek=k.kucuk_liste([("x", "v16@0:8", F0)]))
        k.liste("__objc_catlist", CATLIST, [kat])
        s = objc.oku(k.goruntu(fonksiyon_baslangiclari=[F0]))
        y = s.yontemler[0]
        assert (y.sinif, y.kategori, y.sinif_dis, y.tam_ad) == ("Gizli", "Ek2", False, "-[Gizli x]")
        assert s.sayaclar[objc.B_SINIF_LISTEDE_YOK] == 1 and s.okuma_hatasi == 0

    def test_bolumde_sinirlar(self) -> None:
        g = BellekGoruntu([("buyuk", 0x1000, b"\0" * 0x1000), ("ic", 0x1100, b"\0" * 0x10),
                           ("bitisik", 0x2000, b"\0" * 0x10), ("uzak", 0x9000, b"\0" * 0x10)])
        o = objc.ObjcOkuyucu(g)
        assert [o._bolumde(a) for a in (0xFFF, 0x1000, 0x1105, 0x1500, 0x1FFF, 0x2000, 0x200F)] == [
            False, True, True, True, True, True, True]
        assert [o._bolumde(a) for a in (0x2010, 0x8FFF, 0x900F, 0x9010)] == [False, False, True, False]

    def test_paylasimli_imp_ad_yazilmaz(self) -> None:
        k = Kurucu()
        ro = k.ro("X", k.kucuk_liste([("a", "v16@0:8", F0), ("b", "v16@0:8", F0)]))
        k.liste("__objc_classlist", CLASSLIST, [k.sinif(ro)])
        s = objc.oku(k.goruntu(fonksiyon_baslangiclari=[F0]))
        assert s.denetim["birden_cok_adli_imp"] == 1
        assert all(y.imp_paylasimli and not y.ad_yazilabilir for y in s.yontemler)

    def test_yontem_sayisi_ust_siniri(self) -> None:
        k = Kurucu()
        a = k.ayir("__objc_methlist", 8, 4)
        k.yaz(a, struct.pack("<II", 12 | SMALL, objc.MAX_METHODS_PER_LIST + 1))
        ro = k.ro("X", a)
        k.liste("__objc_classlist", CLASSLIST, [k.sinif(ro)])
        s = objc.oku(k.goruntu())
        assert s.yontemler == []
        assert s.sayaclar[objc.H_LISTE_SINIR] == 1
        assert objc.H_KAYIT_OKUNAMADI not in s.sayaclar

    def test_kucuk_liste_kayit_boyu_12_degilse_atlanir(self) -> None:
        k = Kurucu()
        a = k.ayir("__objc_methlist", 8, 4)
        k.yaz(a, struct.pack("<II", 24 | SMALL, 1))
        ro = k.ro("X", a)
        k.liste("__objc_classlist", CLASSLIST, [k.sinif(ro)])
        s = objc.oku(k.goruntu())
        assert s.yontemler == [] and s.sayaclar[objc.H_KUCUK_BOYUT] == 1

    def test_imp_ice_aktarim_bagi_buyuk_bicimde(self) -> None:
        k = Kurucu()
        lst = k.buyuk_liste([("a", "v16@0:8", 0)])
        k.baglar[lst + 8 + 16] = Bag("_dis_islev")
        ro = k.ro("X", lst)
        k.liste("__objc_classlist", CLASSLIST, [k.sinif(ro)])
        s = objc.oku(k.goruntu())
        assert [(y.secici, y.imp) for y in s.yontemler] == [("a", 0)]
        assert s.sayaclar[objc.B_IMP_BAG] == 1 and s.okuma_hatasi == 0

    def test_objc_bolumu_yoksa_veri_yok(self) -> None:
        g = BellekGoruntu([("__text", TEXT, b"\0" * 16, True, "__TEXT")])
        s = objc.oku(g)
        assert (s.durum, s.yontemler) == (objc.DURUM_VERI_YOK, [])

    def test_elf_veri_yok_ve_desteklenmiyor(self) -> None:
        g = BellekGoruntu([(".text", TEXT, b"\0" * 16, True)], bicim="elf")
        assert objc.oku(g).durum == objc.DURUM_VERI_YOK
        g2 = BellekGoruntu([("__objc_classlist", CLASSLIST, b"\0" * 8)], bicim="elf")
        assert objc.oku(g2).durum == objc.DURUM_DESTEKLENMIYOR

    def test_32_bit_desteklenmiyor(self) -> None:
        g = ornek_kurucu().goruntu(gosterici_boyutu=4)
        s = objc.oku(g)
        assert s.durum == objc.DURUM_DESTEKLENMIYOR and s.yontemler == []

    def test_bozuk_goruntu_istisna_atmaz(self) -> None:
        # sınıf listesi görüntü dışına gösteriyor; sınıf verisi okunamaz
        g = BellekGoruntu([("__objc_classlist", CLASSLIST, struct.pack("<QQ", 0x300000000, 0x7FFF_FFFF_FFF0))])
        s = objc.oku(g)
        assert s.durum == objc.DURUM_CALISTI and s.yontemler == []
        assert s.sayaclar[objc.H_SINIF_VERISI] == 2

    def test_beklenmeyen_hata_durumla_doner(self) -> None:
        g = ornek_goruntu()
        g.fonksiyon_baslangiclari = MagicMock(side_effect=RuntimeError("bozuk"))  # type: ignore[method-assign]
        s = objc.oku(g)
        assert s.durum == objc.DURUM_HATA and "bozuk" in s.neden


class TestTipKodlamasi:
    @pytest.mark.parametrize("enc,beklenen", [
        ("v16@0:8", 3),
        ("v24@0:8@16", 4),
        ("@48@0:8{CGRect={CGPoint=dd}{CGSize=dd}}16", 4),
        ('{CGPoint="x"d"y"d}16@0:8', 3),
        ("v32@0:8@?<v@?@\"NSError\">16^{_NSZone=}24", 5),
        ("v24@0:8@\"NSString\"16", 4),
        ("v28@0:8[4i]16b3", 5),
        ("r*16@0:8", 3),
        ("Vv16@0:8", 3),
        ("v16@-0:+8", 3),
        ("{bozuk", None),
        ('@"Kapanmayan', None),
    ])
    def test_tip_arguman_sayisi(self, enc: str, beklenen: Optional[int]) -> None:
        assert objc.tip_arguman_sayisi(enc) == beklenen

    def test_arite_hukmu(self) -> None:
        assert objc.arite_hukmu("ye:", "v24@0:8@16") == objc.ARITE_UYAN
        assert objc.arite_hukmu("ye:ic:", "v24@0:8@16") == objc.ARITE_UYMAYAN
        assert objc.arite_hukmu("miyavla", "v16@0:8") == objc.ARITE_UYAN
        assert objc.arite_hukmu(None, "v16@0:8") == objc.ARITE_COZULEMEDI
        assert objc.arite_hukmu("a", "{bozuk") == objc.ARITE_COZULEMEDI

    def test_sinif_bagi_adi(self) -> None:
        assert objc.sinif_bagi_adi("_OBJC_CLASS_$_NSString") == "NSString"
        assert objc.sinif_bagi_adi("OBJC_CLASS_$_NSString") == "NSString"
        assert objc.sinif_bagi_adi("_OBJC_METACLASS_$_NSObject") == "NSObject"
        assert objc.sinif_bagi_adi("_baska") == "_baska"


# =============================================================================================
# Üretici adım


class _Calisma:
    def __init__(self, kok: Path) -> None:
        self.kok = kok

    def save_json(self, stage: str, name: str, data: dict[str, Any]) -> Path:
        p = self.kok / stage / f"{name}.json"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
        return p


def _ctx(tmp_path: Path, bayrak: Any = True, ikili: Optional[Path] = None) -> StepContext:
    pc = MagicMock()
    pc.workspace = _Calisma(tmp_path / "ws")
    cfg = Config()
    if bayrak is not None:
        cfg.binary_reconstruction.enable_objc_metadata_recovery = bayrak
    pc.config = cfg
    ctx = StepContext(pipeline_context=pc)
    yol = ikili if ikili is not None else tmp_path / "ikili"
    yol.write_bytes(b"\0")
    ctx._write_artifacts({"binary_for_byte_match": yol})
    return ctx


@pytest.fixture
def sahte_ac(monkeypatch: pytest.MonkeyPatch):
    def kur(goruntu: Any = None, hata: Optional[Exception] = None) -> list[Path]:
        cagri: list[Path] = []

        def ac(yol: Path) -> Any:
            cagri.append(yol)
            if hata is not None:
                raise hata
            return goruntu

        monkeypatch.setattr(adim_mod, "_goruntu_ac", ac)
        return cagri
    return kur


class TestAdim:
    def test_kayit(self) -> None:
        spec = get_step("objc_metadata_recovery")
        assert spec.requires == ("binary_for_byte_match",)
        assert set(spec.produces) == {"objc_methods", "objc_classes", "objc_status", "objc_methods_path"}

    def test_bayrak_alani_ontanim_kapali(self) -> None:
        # bağlayan paketin kilidi (bayrak ön paketinin tür / öntanım kilidi bağlanınca kalkar)
        assert BinaryReconstructionConfig().enable_objc_metadata_recovery is False
        assert BinaryReconstructionConfig.__annotations__["enable_objc_metadata_recovery"] in (bool, "bool")

    @pytest.mark.parametrize("bayrak", [None, False, 1, "evet", MagicMock()])
    def test_bayrak_tam_true_degilse_kapali(self, tmp_path: Path, sahte_ac, bayrak: Any) -> None:
        cagri = sahte_ac(ornek_goruntu())
        ctx = _ctx(tmp_path, bayrak=bayrak)
        if isinstance(bayrak, MagicMock):
            ctx.pipeline_context.config = MagicMock()
        out = ObjcMetadataRecoveryStep().run(ctx)
        assert out["objc_status"]["durum"] == objc.DURUM_KAPALI
        assert out["objc_methods"] == [] and out["objc_methods_path"] is None
        assert cagri == [] and not (tmp_path / "ws").exists()
        assert ctx.stats["objc_status"] == objc.DURUM_KAPALI

    def test_calisti_yapit_ve_dosya(self, tmp_path: Path, sahte_ac) -> None:
        cagri = sahte_ac(ornek_goruntu())
        ctx = _ctx(tmp_path)
        out = ObjcMetadataRecoveryStep().run(ctx)
        assert cagri == [tmp_path / "ikili"]
        assert out["objc_status"]["durum"] == objc.DURUM_CALISTI
        assert [(m["imp"], m["tam_ad"], m["secici"]) for m in out["objc_methods"]] == [
            (F0, "-[Kedi miyavla]", "miyavla"), (F1, "-[Kedi ye:]", "ye:"), (F2, "+[Kedi yeni]", "yeni"),
            (F4, "-[_TtC4Ornek5Kopek havla]", "havla"), (F3, "-[NSString kedice]", "kedice")]
        p = out["objc_methods_path"]
        assert p == tmp_path / "ws" / "static" / "objc_methods.json"
        belge = json.loads(p.read_text(encoding="utf-8"))
        assert belge["durum"] == objc.DURUM_CALISTI and len(belge["yontemler"]) == 5
        assert belge["ozet"]["yontem_kaydi"] == 5 and len(belge["siniflar"]) == 2
        assert ctx.stats["objc_method_count"] == 5 and ctx.errors == []

    def test_gercek_calisma_alani_ile(self, tmp_path: Path, sahte_ac) -> None:
        from karadul.core.workspace import Workspace

        sahte_ac(ornek_goruntu())
        ctx = _ctx(tmp_path)
        ws = Workspace(tmp_path, "ornek", workspace_dir=tmp_path / "gercek_ws")
        ws.create()
        ctx.pipeline_context.workspace = ws
        out = ObjcMetadataRecoveryStep().run(ctx)
        belge = json.loads(Path(out["objc_methods_path"]).read_text(encoding="utf-8"))
        assert Path(out["objc_methods_path"]).parent.name == "static"
        assert belge["schema"] == "karadul.objc_methods.v1"
        assert [m["tam_ad"] for m in belge["yontemler"]][-1] == "-[NSString kedice]"
        assert ctx.stage_artifacts["objc_methods_path"] == out["objc_methods_path"]

    def test_objc_olmayan_ikili_veri_yok(self, tmp_path: Path, sahte_ac) -> None:
        sahte_ac(BellekGoruntu([("__text", TEXT, b"\0" * 16, True, "__TEXT")]))
        out = ObjcMetadataRecoveryStep().run(_ctx(tmp_path))
        assert out["objc_status"]["durum"] == objc.DURUM_VERI_YOK and out["objc_methods"] == []

    def test_tutarsizsa_ad_listesi_yok_kanit_var(self, tmp_path: Path, sahte_ac) -> None:
        k = Kurucu()
        ro = k.ro("X", k.kucuk_liste([("a", "v16@0:8", F0), ("b", "v16@0:8", CONST + 0x10)]))
        k.liste("__objc_classlist", CLASSLIST, [k.sinif(ro)])
        sahte_ac(k.goruntu(fonksiyon_baslangiclari=[F0]))
        out = ObjcMetadataRecoveryStep().run(_ctx(tmp_path))
        assert out["objc_status"]["durum"] == objc.DURUM_TUTARSIZ
        assert out["objc_methods"] == []
        assert out["objc_status"]["ozet"]["yontem_kaydi"] == 2  # kanıt: sayılar yazılır
        belge = json.loads(out["objc_methods_path"].read_text(encoding="utf-8"))
        assert belge["yontemler"] == [] and "kod bölümü dışında" in belge["neden"]

    def test_goruntu_acilamazsa_durum_ve_hata(self, tmp_path: Path, sahte_ac) -> None:
        sahte_ac(hata=OSError("okunamadı"))
        ctx = _ctx(tmp_path)
        out = ObjcMetadataRecoveryStep().run(ctx)
        assert out["objc_status"]["durum"] == objc.DURUM_HATA
        assert "görüntü açılamadı" in out["objc_status"]["neden"]
        assert ctx.errors and "objc_metadata_recovery" in ctx.errors[0]

    def test_goruntu_bicimi_desteklenmiyor(self, tmp_path: Path, sahte_ac) -> None:
        sahte_ac(hata=GoruntuHatasi("biçim tanınmadı", objc.DURUM_DESTEKLENMIYOR))
        ctx = _ctx(tmp_path)
        out = ObjcMetadataRecoveryStep().run(ctx)
        assert out["objc_status"]["durum"] == objc.DURUM_DESTEKLENMIYOR
        assert "biçim tanınmadı" in out["objc_status"]["neden"]
        assert ctx.errors == []

    def test_gercek_ac_tanimsiz_bicim(self, tmp_path: Path) -> None:
        # sahte açıcı yok: gerçek goruntu.ac, metin dosyası → GoruntuHatasi (istisna adımdan sızmaz)
        ikili = tmp_path / "metin.txt"
        ctx = _ctx(tmp_path, ikili=ikili)
        ikili.write_bytes(b"merhaba dunya\n" * 8)
        out = ObjcMetadataRecoveryStep().run(ctx)
        assert out["objc_status"]["durum"] in (objc.DURUM_DESTEKLENMIYOR, objc.DURUM_HATA)
        assert out["objc_status"]["neden"].startswith("görüntü açılamadı")
        assert out["objc_methods"] == []
