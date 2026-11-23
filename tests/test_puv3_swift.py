"""P-ÜV3: Swift tip üst verisi okuyucu (``karadul.analyzers.ustveri.swift``) ve üretici adım
(``karadul.pipeline.steps.swift_metadata_recovery``).

Testler sentetik görüntü (``BellekGoruntu``) üstünde koşar; gerçek ikiliye bağlı test yoktur (yerel doğrulama
``scripts/arge/ustveri/puv3_olc.py``). Yerleşim yerel derlenen örneklerden doğrulandı (``swift.py`` belgesi).
"""
from __future__ import annotations

import json
import struct
from pathlib import Path
from typing import Any, Optional
from unittest.mock import MagicMock

import pytest

from karadul.analyzers.ustveri import swift
from karadul.analyzers.ustveri.goruntu import Bag, BellekGoruntu, GoruntuHatasi
from karadul.config import BinaryReconstructionConfig, Config
from karadul.pipeline.context import StepContext
from karadul.pipeline.registry import get_step
from karadul.pipeline.steps import swift_metadata_recovery as adim_mod
from karadul.pipeline.steps.swift_metadata_recovery import SwiftMetadataRecoveryStep

TEXT = 0x100001000
CONST = 0x100010000
TYPES = 0x100020000
PROTO = 0x100021000
DATA = 0x100030000
CLASSLIST = 0x100040000
DISC = "_0123456789ABCDEF0123456789ABCDEF"


class Kurucu:
    """Sentetik Swift görüntüsü: bölümlere sırayla bayt ekler, göreli göstericileri yamalar."""

    def __init__(self) -> None:
        self.b: dict[str, tuple[int, bytearray, bool, str]] = {
            "__text": (TEXT, bytearray(), True, "__TEXT"),
            "__const": (CONST, bytearray(), False, "__TEXT"),
            "__swift5_types": (TYPES, bytearray(), False, "__TEXT"),
            "__swift5_proto": (PROTO, bytearray(), False, "__TEXT"),
            "__data": (DATA, bytearray(), False, "__DATA"),
            "__objc_classlist": (CLASSLIST, bytearray(), False, "__DATA"),
        }
        self.fonk: list[int] = []

    def ekle(self, bolum: str, veri: bytes, hiza: int = 4) -> int:
        taban, buf, _k, _s = self.b[bolum]
        while len(buf) % hiza:
            buf.append(0)
        a = taban + len(buf)
        buf += veri
        return a

    def yaz(self, adres: int, veri: bytes) -> None:
        for _ad, (taban, buf, _k, _s) in self.b.items():
            if taban <= adres < taban + len(buf):
                buf[adres - taban:adres - taban + len(veri)] = veri
                return
        raise AssertionError(f"adres yok {adres:#x}")

    def rel(self, alan: int, hedef: Optional[int], dolayli: bool = False) -> None:
        v = 0 if hedef is None else hedef - alan
        self.yaz(alan, struct.pack("<i", v | (1 if dolayli else 0)))

    def kod(self) -> int:
        a = self.ekle("__text", b"\xc0\x03\x5f\xd6" * 2)  # ret; fonksiyon başlangıcı
        self.fonk.append(a)
        return a

    def cstr(self, s: str | bytes) -> int:
        return self.ekle("__const", (s.encode() if isinstance(s, str) else s) + b"\0", 1)

    def modul(self, ad: str) -> int:
        d = self.ekle("__const", bytes(12))
        self.rel(d + 8, self.cstr(ad))
        return d

    def tip(self, tur: int, ad: str | bytes, ust: Optional[int], *, ks: int = 0, genel: bool = False,
            ust_dolayli_yuva: Optional[int] = None, artci: bytes = b"", erisim: Optional[int] = -1,
            sinif_sabit: bool = True) -> int:
        bayrak = tur | 0x40 | (0x80 if genel else 0) | (ks << 16)
        sabit = 44 if tur == swift.KIND_CLASS else 28
        d = self.ekle("__const", struct.pack("<I", bayrak) + bytes(sabit - 4) + artci)
        if ust_dolayli_yuva is not None:
            self.rel(d + 4, ust_dolayli_yuva, dolayli=True)
        else:
            self.rel(d + 4, ust)
        self.rel(d + 8, self.cstr(ad))
        if erisim == -1:
            erisim = self.kod()
        self.rel(d + 12, erisim)
        return d

    def adsiz(self, ust: int, karisik: Optional[str] = None) -> int:
        ks = swift.ANON_HAS_MANGLED_NAME if karisik is not None else 0
        d = self.ekle("__const", struct.pack("<I", 2 | 0x40 | (ks << 16)) + bytes(4) + (bytes(4) if karisik else b""))
        self.rel(d + 4, ust)
        if karisik is not None:
            self.rel(d + 8, self.cstr(karisik))
        return d

    def uzanti(self, ust: int, genisletilen: bytes, gereksinim: int = 0) -> int:
        genel = gereksinim > 0
        artci = b""
        if genel:  # temel genel başlık: 1 parametre, n gereksinim; parametre baytı + dolgu; gereksinimler
            artci = struct.pack("<HHHH", 1, gereksinim, 1, 0) + b"\x80\0\0\0" + bytes(12 * gereksinim)
        d = self.ekle("__const", struct.pack("<I", 1 | 0x40 | (0x80 if genel else 0)) + bytes(8) + artci)
        self.rel(d + 4, ust)
        self.rel(d + 8, self.cstr(genisletilen))
        return d

    def kayit(self, d: int, dolayli_yuva: Optional[int] = None) -> None:
        a = self.ekle("__swift5_types", bytes(4))
        if dolayli_yuva is not None:
            self.rel(a, dolayli_yuva, dolayli=True)
        else:
            self.rel(a, d)

    def gosterici(self, bolum: str, deger: int) -> int:
        return self.ekle(bolum, struct.pack("<Q", deger), 8)

    def goruntu(self, **kw: Any) -> BellekGoruntu:
        bolumler = [(ad, taban, bytes(buf), kod, bolut) for ad, (taban, buf, kod, bolut) in self.b.items() if buf]
        kw.setdefault("fonksiyon_baslangiclari", list(self.fonk))
        return BellekGoruntu(bolumler, **kw)


def vtable(yontemler: list[tuple[int, Optional[int]]], k: Kurucu, d_yeri: int) -> None:
    """``d_yeri``: vtable başlığının adresi; yöntem betimleyicilerinin uygulama göstericilerini yamalar."""
    for i, (_bayrak, impl) in enumerate(yontemler):
        k.rel(d_yeri + 8 + 8 * i + 4, impl)


def vt_bayt(yontemler: list[tuple[int, Optional[int]]]) -> bytes:
    return struct.pack("<II", 0, len(yontemler)) + b"".join(struct.pack("<Ii", f, 0) for f, _ in yontemler)


class Ornek:
    """Sentetik örnek: modül + sınıf (vtable 3) + iç içe yapı + genel sınıf + adsız bağlamda tipler + uzantı +
    içe aktarılan C tipi + bir yerel uyum (tanık tablosu)."""

    def __init__(self) -> None:
        k = self.k = Kurucu()
        self.M = k.modul("Mod")
        # sınıf: vtable 3 yöntem (örnek yöntem, getter, uygulaması boş init)
        self.A1, self.A2 = k.kod(), k.kod()
        yon = [(0x10 | 0, self.A1), (0x10 | 2, self.A2), (1, None)]
        self.Sinif = k.tip(swift.KIND_CLASS, "Sinif", self.M, ks=swift.CLASS_HAS_VTABLE, artci=vt_bayt(yon))
        vtable(yon, k, self.Sinif + 44)
        # iç içe yapı (üst bağlam dolaylı: GOT yuvası üstünden)
        yuva = k.gosterici("__data", self.Sinif)
        self.Ic = k.tip(swift.KIND_STRUCT, "Ic", None, ust_dolayli_yuva=yuva)
        # genel sınıf: 1 parametre (1 bayt + 3 dolgu) + vtable 1 yöntem
        self.G1 = k.kod()
        gen = struct.pack("<iiHHHH", 0, 0, 1, 0, 1, 0) + b"\x80\0\0\0"
        yon_g = [(0x10, self.G1)]
        self.Kutu = k.tip(swift.KIND_CLASS, "Kutu", self.M, genel=True, ks=swift.CLASS_HAS_VTABLE,
                          artci=gen + vt_bayt(yon_g))
        vtable(yon_g, k, self.Kutu + 44 + len(gen))
        # tekil başlatma (12 bayt) + vtable 1
        self.T1 = k.kod()
        yon_t = [(0x10, self.T1)]
        self.Tekil = k.tip(swift.KIND_CLASS, "Tekil", self.M, ks=swift.CLASS_HAS_VTABLE | swift.MI_SINGLETON,
                           artci=bytes(12) + vt_bayt(yon_t))
        vtable(yon_t, k, self.Tekil + 44 + 12)
        # dirençli üst sınıf (4) + vtable 1 + geçersiz kılma 1
        self.R1, self.O1 = k.kod(), k.kod()
        yon_r = [(0x10, self.R1)]
        self.Direncli = k.tip(swift.KIND_CLASS, "Direncli", self.M,
                              ks=swift.CLASS_HAS_VTABLE | swift.CLASS_HAS_RESILIENT_SUPER | swift.CLASS_HAS_OVERRIDE_TABLE,
                              artci=bytes(4) + vt_bayt(yon_r) + struct.pack("<I", 1) + bytes(12))
        vtable(yon_r, k, self.Direncli + 44 + 4)
        k.rel(self.Direncli + 44 + 4 + 16 + 4 + 8, self.O1)
        # adsız bağlam: karışık adlı (yapı), ObjC adlı (sınıf), kaynaksız (yapı)
        a1 = k.adsiz(self.M, karisik=f"$s3Mod5Gizli{len(DISC)}{DISC}LLV")
        self.Gizli = k.tip(swift.KIND_STRUCT, "Gizli", a1)
        a2 = k.adsiz(self.M)
        self.GizliSinif = k.tip(swift.KIND_CLASS, "GizliSinif", a2)
        self.GizliIc = k.tip(swift.KIND_STRUCT, "Ic", self.GizliSinif)
        a3 = k.adsiz(self.M)
        self.Kaynaksiz = k.tip(swift.KIND_STRUCT, "Kaynaksiz", a3)
        # ObjC sınıf nesnesi (Swift işareti) → GizliSinif betimleyicisi
        ro = k.ekle("__data", bytes(48), 8)
        k.yaz(ro + 24, struct.pack("<Q", k.cstr(f"_TtC3ModP{len(DISC)}{DISC}10GizliSinif")))
        cls = k.ekle("__data", bytes(72), 8)
        k.yaz(cls + 32, struct.pack("<Q", ro | 1))
        k.yaz(cls + 64, struct.pack("<Q", self.GizliSinif))
        k.gosterici("__objc_classlist", cls)
        # uzantı: Swift.String içinde yapı; kısıtlı uzantı içinde yapı
        u1 = k.uzanti(self.M, b"SS")
        self.UzIc = k.tip(swift.KIND_STRUCT, "UzIc", u1)
        u2 = k.uzanti(self.M, b"SaySiG", gereksinim=1)
        self.Kisitli = k.tip(swift.KIND_STRUCT, "Kisitli", u2)
        # içe aktarılan C tipi (__C; içe aktarım bilgisi N)
        self.C = k.modul("__C")
        self.Ithal = k.tip(swift.KIND_STRUCT, b"Kisa\0NUzun_Ad\0", self.C,
                           ks=swift.MI_FOREIGN | swift.TYPE_HAS_IMPORT_INFO, artci=bytes(4))
        self.tipler = [self.Sinif, self.Ic, self.Kutu, self.Tekil, self.Direncli, self.Gizli, self.GizliSinif,
                       self.GizliIc, self.Kaynaksiz, self.UzIc, self.Kisitli, self.Ithal]
        for i, d in enumerate(self.tipler):
            if i == 1:  # Ic: dolaylı kayıt
                k.kayit(d, dolayli_yuva=k.gosterici("__data", d))
            else:
                k.kayit(d)
        # yerel protokol (2 gereksinim) + Ic'nin uyumu + tanık tablosu
        self.P = k.ekle("__const", struct.pack("<I", 3 | 0x40) + bytes(20))
        k.rel(self.P + 4, self.M)
        k.rel(self.P + 8, k.cstr("Sesli"))
        k.yaz(self.P + 16, struct.pack("<I", 2))
        self.W1, self.W2 = k.kod(), k.kod()
        self.U = k.ekle("__const", bytes(16))
        self.WT = k.ekle("__data", struct.pack("<QQQ", self.U, self.W1, self.W2), 8)
        k.rel(self.U + 0, self.P)
        k.rel(self.U + 4, self.Ic)
        k.rel(self.U + 8, self.WT)
        pk = k.ekle("__swift5_proto", bytes(4))
        k.rel(pk, self.U)
        # dış protokole uyum (bağ) + ardından gelen doğrulanmamış tablo (ilk sözcüğü kod)
        self.W3, self.W4 = k.kod(), k.kod()
        self.U2 = k.ekle("__const", bytes(16))
        self.U3 = k.ekle("__const", bytes(16))
        self.dis_yuva = k.gosterici("__data", 0)
        self.WT2 = k.ekle("__data", struct.pack("<QQ", self.U2, self.W3), 8)
        self.WT3 = k.ekle("__data", struct.pack("<QQ", self.W4, 0), 8)
        k.rel(self.U2 + 0, self.dis_yuva, dolayli=True)
        k.rel(self.U2 + 4, self.Sinif)
        k.rel(self.U2 + 8, self.WT2)
        k.rel(self.U3 + 0, self.P)
        k.rel(self.U3 + 4, self.Sinif)
        k.rel(self.U3 + 8, self.WT3)
        for u in (self.U2, self.U3):
            pk = k.ekle("__swift5_proto", bytes(4))
            k.rel(pk, u)

    def goruntu(self, **kw: Any) -> BellekGoruntu:
        kw.setdefault("baglar", {self.dis_yuva: Bag("_$sSQMp")})
        return self.k.goruntu(**kw)


def ornek_goruntu(**kw: Any) -> BellekGoruntu:
    return Ornek().goruntu(**kw)


def _tip(s: swift.SwiftSonuc, adres: int) -> swift.SwiftTip:
    return next(t for t in s.tipler if t.adres == adres)


# --- okuyucu --------------------------------------------------------------------------------
class TestOkuyucu:
    def test_tipler_ve_erisim(self) -> None:
        o = Ornek()
        s = swift.oku(o.goruntu())
        assert s.durum == swift.DURUM_CALISTI, s.neden
        assert [t.adres for t in s.tipler] == o.tipler
        assert s.okuma_hatasi == 0
        for t in s.tipler:
            assert t.erisim is not None and t.erisim_kodda is True and t.erisim_baslangic is True

    def test_nitelikli_adlar(self) -> None:
        o = Ornek()
        s = swift.oku(o.goruntu())
        adlar = {t.adres: t.nitelikli_ad for t in s.tipler}
        assert adlar[o.Sinif] == "Mod.Sinif"
        assert adlar[o.Ic] == "Mod.Sinif.Ic"
        assert adlar[o.Kutu] == "Mod.Kutu"
        assert adlar[o.Gizli] == f"Mod.(Gizli in {DISC})"
        assert adlar[o.GizliSinif] == f"Mod.(GizliSinif in {DISC})"
        assert adlar[o.GizliIc] == f"Mod.(GizliSinif in {DISC}).Ic"
        assert adlar[o.UzIc] == "(extension in Mod):Swift.String.UzIc"
        assert adlar[o.Ithal] == "__C.Uzun_Ad"

    def test_kaynaksiz_adsiz_ve_kisitli_uzanti_ad_almaz(self) -> None:
        o = Ornek()
        s = swift.oku(o.goruntu())
        t = _tip(s, o.Kaynaksiz)
        assert t.nitelikli_ad is None and t.ad_neden == swift.N_AYRAC_YOK and t.alt_kume == swift.ALT_ADSIZ
        t = _tip(s, o.Kisitli)
        assert t.nitelikli_ad is None and t.ad_neden == swift.N_UZANTI_KISITLI and t.alt_kume == swift.ALT_UZANTI
        assert not t.ad_yazilabilir and t.erisim is not None  # erişim yine okunur
        assert s.sayaclar[swift.N_AYRAC_YOK] == 1 and s.sayaclar[swift.N_UZANTI_KISITLI] == 1

    def test_alt_kume(self) -> None:
        o = Ornek()
        s = swift.oku(o.goruntu())
        assert _tip(s, o.Gizli).alt_kume == swift.ALT_ADSIZ
        assert _tip(s, o.GizliIc).alt_kume == swift.ALT_ADSIZ
        assert _tip(s, o.UzIc).alt_kume == swift.ALT_UZANTI
        assert _tip(s, o.Ithal).alt_kume == swift.ALT_ICE_AKTARIM
        assert _tip(s, o.Sinif).alt_kume == swift.ALT_DIGER

    def test_vtable_yuvalari(self) -> None:
        o = Ornek()
        s = swift.oku(o.goruntu())
        t = _tip(s, o.Sinif)
        assert t.artci_cozuldu is True
        assert [(y[0], y[1], y[4]) for y in t.yontemler] == [("yontem", True, o.A1), ("getter", True, o.A2),
                                                              ("init", False, None)]
        assert [y[4] for y in _tip(s, o.Kutu).yontemler] == [o.G1]
        assert [y[4] for y in _tip(s, o.Tekil).yontemler] == [o.T1]
        assert [y[4] for y in _tip(s, o.Direncli).yontemler] == [o.R1]
        assert _tip(s, o.Direncli).gecersiz_kilma == [o.O1]

    def test_tanik_yuvalari(self) -> None:
        o = Ornek()
        s = swift.oku(o.goruntu())
        tanik = [y for y in s.yuvalar if y["tur"] == swift.YUVA_TANIK]
        assert [(y["adres"], y["sira"], y["tip"]) for y in tanik] == [(o.W1, 1, "Mod.Sinif.Ic"), (o.W2, 2, "Mod.Sinif.Ic"),
                                                                       (o.W3, 1, "Mod.Sinif")]
        assert s.denetim["ilk_sozcugu_dogrulanan"] == 2
        assert s.denetim["tanik_tablosu_olan"] == 3
        assert s.denetim["yerel_protokole"] == 2

    def test_denetim_sayilari(self) -> None:
        s = swift.oku(ornek_goruntu())
        d = s.denetim
        assert d["erisim_fonksiyonu"] == 12 and d["erisim_kodda"] == 12 and d["erisim_fonksiyon_baslangici"] == 12
        assert d["yontem_betimleyici"] == 6 and d["impl_bos"] == 1 and d["ayrik_impl"] == 5
        assert d["impl_kodda"] == 5 and d["gecersiz_kilma_kaydi"] == 1
        assert d["tanik_kod_gostericisi_ayrik"] == 3

    def test_swift_slots_ad_adayi_degil(self) -> None:
        s = swift.oku(ornek_goruntu())
        yuvalar = s.swift_slots()
        assert yuvalar and all("ad" not in y and "nitelikli_ad" not in y for y in yuvalar)
        tipler = s.swift_types()
        assert len(tipler) == 12
        assert all(set(x) >= {"ad", "adres", "nitelikli_ad"} for x in tipler)
        assert {x["ad"] for x in tipler if x["ad"]} >= {"type metadata accessor for Mod.Sinif"}
        assert not any(x.get("tur") in (swift.YUVA_VTABLE, swift.YUVA_TANIK) for x in tipler)

    def test_ice_aktarim_iliskili_varlik(self) -> None:
        k = Kurucu()
        c = k.modul("__C_Synthesized")
        d = k.tip(swift.KIND_STRUCT, b"KDHata\0Re\0", c, ks=swift.MI_FOREIGN | swift.TYPE_HAS_IMPORT_INFO,
                  artci=bytes(4))
        d2 = k.tip(swift.KIND_STRUCT, b"Ad\0St\0", k.modul("__C"), ks=swift.MI_FOREIGN | swift.TYPE_HAS_IMPORT_INFO,
                   artci=bytes(4))
        d3 = k.tip(swift.KIND_STRUCT, b"Ad\0Xbilinmeyen\0", k.modul("__C"),
                   ks=swift.MI_FOREIGN | swift.TYPE_HAS_IMPORT_INFO, artci=bytes(4))
        for x in (d, d2, d3):
            k.kayit(x)
        s = swift.oku(k.goruntu())
        assert [t.nitelikli_ad for t in s.tipler] == ["__C_Synthesized.related decl 'e' for KDHata", "__C.Ad", None]
        assert s.tipler[2].ad_neden == swift.N_ICE_AKTARIM

    @pytest.mark.parametrize("karisik, beklenen", [
        (b"SS", "Swift.String"), (b"Si", "Swift.Int"), (b"SayxG", "Swift.Array"), (b"SDyxq_G", "Swift.Dictionary"),
        (b"xSg", "Swift.Optional"), (b"So8NSObjectC", "__C.NSObject"), (b"10Foundation4DateV", "Foundation.Date"),
        (b"s12CaseIterableP", None), (b"SaySiG", None), (b"S0_", None), (b"ScT", "Swift.Task"),
    ])
    def test_karisik_tip_adi(self, karisik: bytes, beklenen: Optional[str]) -> None:
        k = Kurucu()
        a = k.cstr(karisik)
        k.kayit(k.tip(swift.KIND_STRUCT, "X", k.modul("M")))
        r = swift.SwiftOkuyucu(k.goruntu())
        assert r.karisik_tip_adi(a) == beklenen

    def test_karisik_simgesel_baslanti(self) -> None:
        k = Kurucu()
        m = k.modul("Mod")
        hedef = k.tip(swift.KIND_STRUCT, "Hedef", m)
        a = k.ekle("__const", b"\x01" + bytes(4) + b"\0", 1)
        k.rel(a + 1, hedef)
        yuva = k.gosterici("__data", 0)
        a2 = k.ekle("__const", b"\x02" + bytes(4) + b"\0", 1)
        k.rel(a2 + 1, yuva)
        k.kayit(hedef)
        r = swift.SwiftOkuyucu(k.goruntu(baglar={yuva: Bag("_$s10Foundation4DateVMn")}))
        assert r.karisik_tip_adi(a) == "Mod.Hedef"
        assert r.karisik_tip_adi(a2) == "Foundation.Date"

    def test_gecersiz_kilma_hedefi_ve_async_govde(self) -> None:
        k = Kurucu()
        m = k.modul("M")
        b0, g1 = k.kod(), k.kod()
        afp = k.ekle("__data", bytes(8), 8)  # zaman uyumsuz işlev göstericisi: +0 → g1
        k.rel(afp, g1)
        yon = [(0x10, b0), (0x10 | 0x40, afp)]
        taban = k.tip(swift.KIND_CLASS, "Taban", m, ks=swift.CLASS_HAS_VTABLE, artci=vt_bayt(yon))
        vtable(yon, k, taban + 44)
        x, y = k.kod(), k.kod()
        afp2 = k.ekle("__data", bytes(8), 8)
        k.rel(afp2, y)
        alt = k.tip(swift.KIND_CLASS, "Alt", m, ks=swift.CLASS_HAS_OVERRIDE_TABLE,
                    artci=struct.pack("<I", 2) + bytes(24))
        for i, (hedef_sira, impl) in enumerate([(0, x), (1, afp2)]):
            kayit = alt + 44 + 4 + 12 * i
            k.rel(kayit, taban)
            k.rel(kayit + 4, taban + 44 + 8 + 8 * hedef_sira)
            k.rel(kayit + 8, impl)
        k.kayit(taban)
        k.kayit(alt)
        s = swift.oku(k.goruntu())
        vt = [y_ for y_ in s.yuvalar if y_["tur"] == swift.YUVA_VTABLE]
        assert vt[1]["zaman_uyumsuz"] is True and vt[1]["kodda"] is False and vt[1]["govde"] == g1
        assert "govde" not in vt[0]
        gk = [y_ for y_ in s.yuvalar if y_["tur"] == swift.YUVA_GECERSIZ_KILMA]
        assert [(g["ust_tip"], g["ust_sira"], g["adres"]) for g in gk] == [("M.Taban", 0, x), ("M.Taban", 1, afp2)]
        assert gk[1]["govde"] == y and "govde" not in gk[0]
        assert s.denetim["impl_kodda"] == 1 and s.denetim["ayrik_impl"] == 2  # H1 sayımı ham uygulamayla

    def test_paylasimli_erisim_ad_yazilamaz(self) -> None:
        k = Kurucu()
        m = k.modul("M")
        f = k.kod()
        d1 = k.tip(swift.KIND_STRUCT, "A", m, erisim=f)
        d2 = k.tip(swift.KIND_STRUCT, "B", m, erisim=f)
        d3 = k.tip(swift.KIND_STRUCT, "C", m)
        for d in (d1, d2, d3):
            k.kayit(d)
        s = swift.oku(k.goruntu())
        assert [t.ad_yazilabilir for t in s.tipler] == [False, False, True]
        assert [t.nitelikli_ad for t in s.tipler] == ["M.A", "M.B", "M.C"]
        g = k.goruntu(fonksiyon_baslangiclari=[])
        assert [t.ad_yazilabilir for t in swift.oku(g).tipler] == [False, False, False]

    def test_ayrac_yardimcilari(self) -> None:
        assert swift._karisik_ayrac(f"$s3Mod5Gizli{len(DISC)}{DISC}LLV", "Gizli") == DISC
        assert swift._karisik_ayrac("$s3Mod1f5YerelL_V", "Yerel") is None  # yerel tip: ayraç yok
        assert swift._karisik_ayrac("$s3Mod5Gizli3abcV", "Gizli") is None  # ad + tanımlayıcı ama LL yok
        assert swift._karisik_ayrac(f"$s3Mod5Gizli3abcV5Gizli{len(DISC)}{DISC}LLV", "Gizli") == DISC
        assert swift._objc_ayrac(f"_TtC3ModP{len(DISC)}{DISC}10GizliSinif", "GizliSinif") == DISC
        assert swift._objc_ayrac("_TtC3Mod10GizliSinif", "GizliSinif") is None
        assert swift._objc_ayrac("_TtCF3Mod1fFT_T_L_10GizliSinif", "GizliSinif") is None
        ic = f"_TtCV3ModP{len(DISC)}{DISC}3Kap7IcSinif"
        assert swift._objc_ayrac(ic, "Kap") == DISC and swift._objc_ayrac(ic, "IcSinif") is None
        iki = f"_TtCV3ModP{len(DISC)}{DISC}1AP{len(DISC)}{DISC[::-1]}1A"
        assert swift._objc_ayrac(iki, "A") is None  # iki farklı ayraç: tahmin yok

    def test_ayrac_ic_sinifin_objc_adindan(self) -> None:
        k = Kurucu()
        m = k.modul("Mod")
        a = k.adsiz(m)
        kap = k.tip(swift.KIND_STRUCT, "Kap", a)
        ic = k.tip(swift.KIND_CLASS, "IcSinif", kap)
        yapi = k.tip(swift.KIND_STRUCT, "IcIc", kap)
        b = k.adsiz(m)
        yalniz = k.tip(swift.KIND_STRUCT, "Yalniz", b)
        ro = k.ekle("__data", bytes(48), 8)
        k.yaz(ro + 24, struct.pack("<Q", k.cstr(f"_TtCV3ModP{len(DISC)}{DISC}3Kap7IcSinif")))
        cls = k.ekle("__data", bytes(72), 8)
        k.yaz(cls + 32, struct.pack("<Q", ro | 2))
        k.yaz(cls + 64, struct.pack("<Q", ic))
        k.gosterici("__objc_classlist", cls)
        for d in (kap, ic, yapi, yalniz):
            k.kayit(d)
        s = swift.oku(k.goruntu())
        assert [t.nitelikli_ad for t in s.tipler] == [f"Mod.(Kap in {DISC})", f"Mod.(Kap in {DISC}).IcSinif",
                                                      f"Mod.(Kap in {DISC}).IcIc", None]
        assert all(t.alt_kume == swift.ALT_ADSIZ for t in s.tipler)


# --- sağlamlık -------------------------------------------------------------------------------
class TestSaglamlik:
    def test_vtable_ust_siniri(self) -> None:
        k = Kurucu()
        m = k.modul("M")
        d = k.tip(swift.KIND_CLASS, "Dev", m, ks=swift.CLASS_HAS_VTABLE,
                  artci=struct.pack("<II", 0, swift.MAX_VTABLE + 1))
        k.kayit(d)
        s = swift.oku(k.goruntu())
        assert s.sayaclar[swift.H_VTABLE_ASIRI] == 1
        assert s.tipler[0].yontemler == [] and s.tipler[0].artci_cozuldu is False
        assert s.tipler[0].nitelikli_ad == "M.Dev" and s.tipler[0].erisim is not None

    def test_desteklenmeyen_genel_bayrak(self) -> None:
        k = Kurucu()
        m = k.modul("M")
        gen = struct.pack("<iiHHHH", 0, 0, 1, 0, 1, 0x4) + b"\x80\0\0\0"
        d = k.tip(swift.KIND_CLASS, "Paket", m, genel=True, ks=swift.CLASS_HAS_VTABLE,
                  artci=gen + vt_bayt([(0x10, None)]))
        k.kayit(d)
        s = swift.oku(k.goruntu())
        t = s.tipler[0]
        assert s.sayaclar[swift.H_GENEL_BAYRAK] == 1 and t.artci_cozuldu is False and t.yontemler == []
        assert t.nitelikli_ad == "M.Paket" and t.erisim is not None  # ad ve erişim yine okunur

    def test_kesik_goruntu_istisna_yok(self) -> None:
        g = ornek_goruntu()
        bolumler = []
        for b in g.bolumler:
            veri = g.oku(b.adres, b.boyut) or b""
            bolumler.append((b.ad, b.adres, veri[: max(0, len(veri) // 3)], b.kod, b.bolut))
        s = swift.oku(BellekGoruntu(bolumler))
        assert s.durum in (swift.DURUM_CALISTI, swift.DURUM_TUTARSIZ)
        for t in s.tipler:
            assert t.nitelikli_ad is None or isinstance(t.nitelikli_ad, str)

    def test_dongusel_baglam_siniri(self) -> None:
        k = Kurucu()
        d = k.ekle("__const", struct.pack("<I", swift.KIND_STRUCT | 0x40) + bytes(24))
        k.rel(d + 4, d)  # üst bağlam kendisi
        k.rel(d + 8, k.cstr("Dongu"))
        k.rel(d + 12, k.kod())
        k.kayit(d)
        s = swift.oku(k.goruntu())
        assert s.tipler[0].nitelikli_ad is None and s.tipler[0].ad_neden == swift.N_DERINLIK

    def test_kod_disi_erisim_tutarsiz(self) -> None:
        k = Kurucu()
        d = k.tip(swift.KIND_STRUCT, "Bozuk", k.modul("M"), erisim=CONST + 4)
        k.kayit(d)
        s = swift.oku(k.goruntu())
        assert s.durum == swift.DURUM_TUTARSIZ and "erişim fonksiyonu" in s.neden

    def test_objc_tip_kaydi_atlanir(self) -> None:
        k = Kurucu()
        d = k.tip(swift.KIND_STRUCT, "X", k.modul("M"))
        a = k.ekle("__swift5_types", bytes(4))
        k.yaz(a, struct.pack("<i", (d - a) | 2))
        k.kayit(d)
        s = swift.oku(k.goruntu())
        assert len(s.tipler) == 1 and s.sayaclar[swift.H_TIP_OBJC] == 1

    def test_veri_yok_ve_bicimler(self) -> None:
        g = BellekGoruntu([("__text", TEXT, b"\0" * 16, True, "__TEXT")])
        assert swift.oku(g).durum == swift.DURUM_VERI_YOK
        g = BellekGoruntu([(".text", TEXT, b"\0" * 16, True)], bicim="elf")
        assert swift.oku(g).durum == swift.DURUM_VERI_YOK
        g = BellekGoruntu([("swift5_types", TYPES, b"\0" * 4)], bicim="elf")
        assert swift.oku(g).durum == swift.DURUM_DESTEKLENMIYOR
        g = BellekGoruntu([("__swift5_types", TYPES, b"\0" * 4)], gosterici_boyutu=4)
        assert swift.oku(g).durum == swift.DURUM_DESTEKLENMIYOR

    def test_beklenmeyen_hata_durumla_doner(self) -> None:
        g = MagicMock()
        g.bicim = "macho"
        type(g).bolumler = property(lambda self: (_ for _ in ()).throw(RuntimeError("patladı")))
        s = swift.oku(g)
        assert s.durum == swift.DURUM_HATA and "patladı" in s.neden


# --- üretici adım ------------------------------------------------------------------------------
class _Calisma:
    def __init__(self, kok: Path) -> None:
        self.kok = kok

    def save_json(self, stage: str, name: str, data: dict[str, Any]) -> Path:
        p = self.kok / stage / f"{name}.json"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(data, ensure_ascii=False, default=str), encoding="utf-8")
        return p


def _ctx(tmp_path: Path, bayrak: Any = True, ikili: Optional[Path] = None) -> StepContext:
    pc = MagicMock()
    pc.workspace = _Calisma(tmp_path / "ws")
    cfg = Config()
    if bayrak is not None:
        cfg.binary_reconstruction.enable_swift_metadata_recovery = bayrak
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
        spec = get_step("swift_metadata_recovery")
        assert spec.requires == ("binary_for_byte_match",)
        assert set(spec.produces) == {"swift_types", "swift_slots", "swift_status", "swift_types_path"}

    def test_bayrak_alani_ontanim_kapali(self) -> None:
        assert BinaryReconstructionConfig().enable_swift_metadata_recovery is False

    @pytest.mark.parametrize("bayrak", [None, False, 1, "evet", MagicMock()])
    def test_bayrak_tam_true_degilse_kapali(self, tmp_path: Path, sahte_ac, bayrak: Any) -> None:
        cagri = sahte_ac(ornek_goruntu())
        ctx = _ctx(tmp_path, bayrak=bayrak)
        if isinstance(bayrak, MagicMock):
            ctx.pipeline_context.config = MagicMock()
        out = SwiftMetadataRecoveryStep().run(ctx)
        assert out["swift_status"]["durum"] == swift.DURUM_KAPALI
        assert out["swift_types"] == [] and out["swift_slots"] == [] and out["swift_types_path"] is None
        assert cagri == [] and not (tmp_path / "ws").exists()
        assert ctx.stats["swift_status"] == swift.DURUM_KAPALI

    def test_calisti_yapit_ve_dosya(self, tmp_path: Path, sahte_ac) -> None:
        o = Ornek()
        cagri = sahte_ac(o.goruntu())
        ctx = _ctx(tmp_path)
        out = SwiftMetadataRecoveryStep().run(ctx)
        assert cagri == [tmp_path / "ikili"]
        assert out["swift_status"]["durum"] == swift.DURUM_CALISTI
        assert len(out["swift_types"]) == 12
        assert out["swift_types"][0]["ad"] == "type metadata accessor for Mod.Sinif"
        assert all("ad" not in y for y in out["swift_slots"])
        belge = json.loads(Path(out["swift_types_path"]).read_text(encoding="utf-8"))
        assert belge["schema"] == "karadul.swift_metadata.v1"
        assert Path(out["swift_types_path"]).parent.name == "static"
        assert len(belge["swift_types"]) == 12 and len(belge["swift_slots"]) == len(out["swift_slots"])
        assert ctx.stats["swift_type_count"] == 12

    def test_tutarsizsa_ad_listesi_yok_kanit_var(self, tmp_path: Path, sahte_ac) -> None:
        k = Kurucu()
        k.kayit(k.tip(swift.KIND_STRUCT, "Bozuk", k.modul("M"), erisim=CONST + 4))
        sahte_ac(k.goruntu())
        out = SwiftMetadataRecoveryStep().run(_ctx(tmp_path))
        assert out["swift_status"]["durum"] == swift.DURUM_TUTARSIZ
        assert out["swift_types"] == [] and out["swift_slots"] == []
        assert out["swift_status"]["ozet"]["tip"] == 1
        belge = json.loads(out["swift_types_path"].read_text(encoding="utf-8"))
        assert belge["swift_types"] == [] and "erişim fonksiyonu" in belge["neden"]

    def test_swift_olmayan_veri_yok(self, tmp_path: Path, sahte_ac) -> None:
        sahte_ac(BellekGoruntu([("__text", TEXT, b"\0" * 16, True, "__TEXT")]))
        out = SwiftMetadataRecoveryStep().run(_ctx(tmp_path))
        assert out["swift_status"]["durum"] == swift.DURUM_VERI_YOK and out["swift_types"] == []

    def test_goruntu_acilamazsa(self, tmp_path: Path, sahte_ac) -> None:
        sahte_ac(hata=OSError("okunamadı"))
        ctx = _ctx(tmp_path)
        out = SwiftMetadataRecoveryStep().run(ctx)
        assert out["swift_status"]["durum"] == swift.DURUM_HATA
        assert ctx.errors and "swift_metadata_recovery" in ctx.errors[0]
        sahte_ac(hata=GoruntuHatasi("biçim tanınmadı", swift.DURUM_DESTEKLENMIYOR))
        ctx = _ctx(tmp_path)
        out = SwiftMetadataRecoveryStep().run(ctx)
        assert out["swift_status"]["durum"] == swift.DURUM_DESTEKLENMIYOR and ctx.errors == []

    def test_gercek_ac_ve_calisma_alani(self, tmp_path: Path) -> None:
        from karadul.core.workspace import Workspace

        ikili = tmp_path / "metin.txt"
        ctx = _ctx(tmp_path, ikili=ikili)
        ikili.write_bytes(b"merhaba dunya\n" * 8)
        ws = Workspace(tmp_path, "ornek", workspace_dir=tmp_path / "gercek_ws")
        ws.create()
        ctx.pipeline_context.workspace = ws
        out = SwiftMetadataRecoveryStep().run(ctx)
        assert out["swift_status"]["durum"] in (swift.DURUM_DESTEKLENMIYOR, swift.DURUM_HATA)
        assert out["swift_status"]["neden"].startswith("görüntü açılamadı")
        assert Path(out["swift_types_path"]).parent.name == "static"
