"""P-ÜV4 — C++ (Itanium) RTTI sembolsüz tarayıcı ve ``rtti_recovery`` adımı (sentetik görüntü).

Test verisi kuralı (ustveri/PLAN.md §0): gerçek ikili yok; ``struct.pack`` ile kurulan küçük bir görüntü. Sınıflar:
``Taban`` (class_type_info; ad göstericisinde "tekil değil" biti), ``Tekli : Taban`` (si), ``Ikinci`` (class),
``Coklu : Tekli, Ikinci`` (vmi; birincil + ikincil vtable), ``Zayif : Taban`` (si; ad ve bir yuva ada göre zayıf bağ).
``Ikinci``'nin ilk yuvası saf sanal (``__cxa_pure_virtual`` içe aktarımı). İki tuzak: tepeye uzaklığı düzeltme yeri
olan ve tepeye uzaklığı pozitif olan "vtable benzeri" diziler. Biçim kaynağı: Itanium C++ ABI §2.5, §2.9.5.
"""

from __future__ import annotations

import json
import random
import struct
from pathlib import Path
from typing import Any, Optional
from unittest.mock import MagicMock

import pytest

from karadul.analyzers.ustveri import cpp_rtti_tara as rt
from karadul.analyzers.ustveri.goruntu import (
    BICIM_ELF,
    BICIM_PE,
    SEMBOL_KOD,
    SEMBOL_VERI,
    Bag,
    BellekGoruntu,
    GoruntuHatasi,
    Sembol,
)
from karadul.config import BinaryReconstructionConfig, Config
from karadul.pipeline.context import StepContext
from karadul.pipeline.registry import get_step
from karadul.pipeline.steps import rtti_recovery as adim_mod
from karadul.pipeline.steps.rtti_recovery import RttiRecoveryStep

# =============================================================================================
# Sentetik görüntü

TEXT, STR, DATA = 0x1000, 0x2000, 0x3000
F = [TEXT + 0x10 * i for i in range(12)]  # F0 … F11
TEKIL_DEGIL = 1 << 63
TI_TABAN, TI_TEKLI, TI_IKINCI, TI_COKLU, TI_ZAYIF = DATA, DATA + 0x10, DATA + 0x28, DATA + 0x38, DATA + 0x70
VT_TABAN, VT_TEKLI, VT_IKINCI = DATA + 0x100, DATA + 0x130, DATA + 0x158
VT_COKLU, VT_COKLU2, VT_ZAYIF = DATA + 0x180, DATA + 0x1B0, DATA + 0x1D0
TUZAK_DUZELTME, TUZAK_POZITIF = DATA + 0x300, DATA + 0x340
MACHO_CLASS = "__ZTVN10__cxxabiv117__class_type_infoE"
MACHO_SI = "__ZTVN10__cxxabiv120__si_class_type_infoE"
MACHO_VMI = "__ZTVN10__cxxabiv121__vmi_class_type_infoE"
RTTI_ORNEK_ADLARI = {"Taban": "5Taban", "Tekli": "5Tekli", "Ikinci": "6Ikinci", "Coklu": "5Coklu", "Zayif": "5Zayif"}


class Kurucu:
    """Bölümlere bayt yazan küçük yardımcı; göstericiler ``BellekGoruntu`` sözlükleriyle (yeniden konumlama
    ``rk``: dosyadaki sözcük 0, RELA gibi; bağ ``baglar``)."""

    def __init__(self, elf: bool = False) -> None:
        self.elf = elf
        self.text = bytearray(0x200)
        self.str = bytearray(0x100)
        self.data = bytearray(0x400)
        self.rk: dict[int, int] = {}
        self.baglar: dict[int, Bag] = {}
        self.semboller: list[Sembol] = []
        self.str_son = 0
        self.ad_adres: dict[str, int] = {}

    def ad(self, a: str) -> str:
        return a[1:] if self.elf and a.startswith("__") else a

    def dizgi(self, s: str) -> int:
        adres = STR + self.str_son
        b = s.encode() + b"\0"
        self.str[self.str_son:self.str_son + len(b)] = b
        self.str_son += len(b)
        self.ad_adres[s] = adres
        return adres

    def sozcuk(self, adres: int, deger: int) -> None:
        struct.pack_into("<Q", self.data, adres - DATA, deger % (1 << 64))

    def u32(self, adres: int, deger: int) -> None:
        struct.pack_into("<I", self.data, adres - DATA, deger)

    def gosterici(self, adres: int, hedef: int) -> None:
        self.rk[adres] = hedef

    def bag(self, adres: int, ad: str, ek: int = 0) -> None:
        self.baglar[adres] = Bag(self.ad(ad), ek)

    def goruntu(self, **kw: Any) -> BellekGoruntu:
        return BellekGoruntu(
            [("__text", TEXT, bytes(self.text), True, "__TEXT"), ("__const", STR, bytes(self.str), False, "__TEXT"),
             ("__const", DATA, bytes(self.data), False, "__DATA_CONST")],
            bicim=BICIM_ELF if self.elf else "macho", yeniden_konumlamalar=self.rk, baglar=self.baglar,
            semboller=self.semboller, **kw)


def ornek_kurucu(elf: bool = False, vmi_sayisi: int = 2, coklu_taban1: Optional[int] = None) -> Kurucu:
    k = Kurucu(elf)
    ad = {n: k.dizgi(m) for n, m in RTTI_ORNEK_ADLARI.items()}
    # typeinfo nesneleri
    k.bag(TI_TABAN, MACHO_CLASS, 16)
    k.gosterici(TI_TABAN + 8, ad["Taban"] | TEKIL_DEGIL)
    k.bag(TI_TEKLI, MACHO_SI, 16)
    k.gosterici(TI_TEKLI + 8, ad["Tekli"])
    k.gosterici(TI_TEKLI + 16, TI_TABAN)
    k.bag(TI_IKINCI, MACHO_CLASS, 16)
    k.gosterici(TI_IKINCI + 8, ad["Ikinci"])
    k.bag(TI_COKLU, MACHO_VMI, 16)
    k.gosterici(TI_COKLU + 8, ad["Coklu"])
    k.u32(TI_COKLU + 16, 0)
    k.u32(TI_COKLU + 20, vmi_sayisi)
    k.gosterici(TI_COKLU + 24, TI_TEKLI if coklu_taban1 is None else coklu_taban1)
    k.sozcuk(TI_COKLU + 32, 0)                       # gizli taban, ofset 0 (tepeye uzaklık gibi görünür)
    k.gosterici(TI_COKLU + 40, TI_IKINCI)
    k.sozcuk(TI_COKLU + 48, (0x10 << 8) | 2)          # açık taban, ofset 16 (değer kod aralığına düşer)
    k.bag(TI_ZAYIF, MACHO_SI, 16)
    k.bag(TI_ZAYIF + 8, "__ZTS5Zayif")                 # ad dizgisi ada göre zayıf bağ
    k.gosterici(TI_ZAYIF + 16, TI_TABAN)
    k.semboller.append(Sembol(k.ad("__ZTS5Zayif"), ad["Zayif"], SEMBOL_VERI, True))
    k.semboller.append(Sembol(k.ad("__ZN5Zayif1fEv"), F[9], SEMBOL_KOD, True))

    def vtable(adres: int, ti: int, yuvalar: list[Any], ott: int = 0) -> None:
        k.sozcuk(adres, ott)
        k.gosterici(adres + 8, ti)
        for i, y in enumerate(yuvalar):
            if isinstance(y, str):
                k.bag(adres + 16 + 8 * i, y)
            else:
                k.gosterici(adres + 16 + 8 * i, y)

    vtable(VT_TABAN, TI_TABAN, [F[0], F[1], F[2], F[10]])
    vtable(VT_TEKLI, TI_TEKLI, [F[0], F[3], F[2]])
    vtable(VT_IKINCI, TI_IKINCI, ["___cxa_pure_virtual", F[4], F[10]])
    vtable(VT_COKLU, TI_COKLU, [F[5], F[3], F[2], F[6]])
    vtable(VT_COKLU2, TI_COKLU, [F[8], F[7]], ott=-16)
    vtable(VT_ZAYIF, TI_ZAYIF, [F[0], "__ZN5Zayif1fEv", F[2]])
    # tuzak 1: tepeye uzaklık sözcüğü yeniden konumlama yeri (vtable değil)
    k.gosterici(TUZAK_DUZELTME, F[1])
    k.gosterici(TUZAK_DUZELTME + 8, TI_TABAN)
    k.gosterici(TUZAK_DUZELTME + 16, F[1])
    # tuzak 2: tepeye uzaklık pozitif (vtable değil)
    k.sozcuk(TUZAK_POZITIF, 16)
    k.gosterici(TUZAK_POZITIF + 8, TI_TABAN)
    k.gosterici(TUZAK_POZITIF + 16, F[1])
    return k


def ornek_goruntu(**kw: Any) -> BellekGoruntu:
    return ornek_kurucu(**kw).goruntu()


def _vt(sonuc: rt.RttiSonuc) -> dict[int, rt.VtableKaydi]:
    return {v.adres: v for v in sonuc.vtablelar}


def _sinif(sonuc: rt.RttiSonuc, ad: str) -> dict[str, Any]:
    return next(c for c in sonuc.rtti_classes() if c["name"] == ad)


# =============================================================================================
# Tarayıcı


class TestTypeinfo:
    def test_bes_typeinfo_tur_ve_ad(self) -> None:
        s = rt.tara(ornek_goruntu())
        assert s.durum == rt.DURUM_CALISTI
        assert [(t.adres, t.tur, t.ad) for t in s.typeinfolar] == [
            (TI_TABAN, "class", "5Taban"), (TI_TEKLI, "si", "5Tekli"), (TI_IKINCI, "class", "6Ikinci"),
            (TI_COKLU, "vmi", "5Coklu"), (TI_ZAYIF, "si", "5Zayif")]
        assert s.okuma_hatasi == 0

    def test_tekil_olmayan_bit_maskelenir_ve_kaydedilir(self) -> None:
        s = rt.tara(ornek_goruntu())
        t = s.ti_sozlugu()[TI_TABAN]
        assert t.tekil_olmayan is True and t.ad_adresi < (1 << 56) and t.ad == "5Taban"
        assert s.ti_sozlugu()[TI_TEKLI].tekil_olmayan is False
        assert s.sayaclar[rt.B_TEKIL_OLMAYAN] == 1

    def test_tabanlar_si_ve_vmi(self) -> None:
        ti = rt.tara(ornek_goruntu()).ti_sozlugu()
        assert [b.typeinfo for b in ti[TI_TEKLI].tabanlar] == [TI_TABAN]
        coklu = ti[TI_COKLU].tabanlar
        assert [b.typeinfo for b in coklu] == [TI_TEKLI, TI_IKINCI]
        assert [(b.acik, b.ofset, b.sanal) for b in coklu] == [(False, 0, False), (True, 16, False)]
        assert ti[TI_COKLU].boyut == 24 + 16 * 2

    def test_zayif_bagli_ad_yerel_adrese_cevrilir(self) -> None:
        s = rt.tara(ornek_goruntu())
        t = s.ti_sozlugu()[TI_ZAYIF]
        assert t.ad == "5Zayif" and t.zayif_adla_bagli is True
        assert s.sayaclar[rt.B_ZAYIF_TI] == 1

    def test_zayif_bag_adi_tanimsizsa_typeinfo_atlanir_sayilir(self) -> None:
        k = ornek_kurucu()
        k.semboller.clear()
        s = rt.tara(k.goruntu())
        assert TI_ZAYIF not in s.ti_sozlugu() and s.sayaclar[rt.H_AD_DIS_BAG] == 1

    def test_ad_cozumu(self) -> None:
        s = rt.tara(ornek_goruntu())
        adlar = [t.cozulmus for t in s.typeinfolar]
        if all(a is None for a in adlar):
            pytest.skip("Itanium ad çözücüsü (cxxfilt / c++filt) yok")
        assert adlar == ["Taban", "Tekli", "Ikinci", "Coklu", "Zayif"]


class TestVtable:
    def test_vtable_listesi_ve_tuzaklar(self) -> None:
        s = rt.tara(ornek_goruntu())
        assert sorted(_vt(s)) == [VT_TABAN, VT_TEKLI, VT_IKINCI, VT_COKLU, VT_COKLU2, VT_ZAYIF]
        assert TUZAK_DUZELTME not in _vt(s) and TUZAK_POZITIF not in _vt(s)

    def test_typeinfo_icindeki_basvuru_vtable_sayilmaz(self) -> None:
        # Coklu'nun ikinci taban göstericisi (+40) ofset 0 sözcüğünden sonra geliyor; ardından kod aralığında sayı
        s = rt.tara(ornek_goruntu())
        assert TI_COKLU + 32 not in _vt(s)

    def test_birincil_ikincil_ve_yuvalar(self) -> None:
        vt = _vt(rt.tara(ornek_goruntu()))
        assert vt[VT_COKLU].tepeye_uzaklik == 0 and vt[VT_COKLU].yuvalar == [F[5], F[3], F[2], F[6]]
        assert vt[VT_COKLU2].tepeye_uzaklik == -16 and vt[VT_COKLU2].typeinfo == TI_COKLU
        assert vt[VT_COKLU2].yuvalar == [F[8], F[7]] and not vt[VT_COKLU2].birincil

    def test_ice_aktarim_yuvasi_sirayi_ilerletir(self) -> None:
        s = rt.tara(ornek_goruntu())
        assert _vt(s)[VT_IKINCI].yuvalar == [None, F[4], F[10]]
        assert _sinif(s, "Ikinci")["methods"][:2] == [0, F[4]]

    def test_zayif_bagli_yuva_yerel_adrese_cevrilir(self) -> None:
        s = rt.tara(ornek_goruntu())
        assert _vt(s)[VT_ZAYIF].yuvalar == [F[0], F[9], F[2]] and _vt(s)[VT_ZAYIF].zayif_yuva == 1

    def test_yuva_ust_siniri_keser_ve_sayar(self) -> None:
        s = rt.tara(ornek_goruntu(), azami_yuva=2)
        assert _vt(s)[VT_TABAN].yuvalar == [F[0], F[1]] and _vt(s)[VT_TABAN].kesildi
        assert not _vt(s)[VT_COKLU2].kesildi
        assert s.sayaclar[rt.H_YUVA_SINIR] == 5  # Taban, Tekli, Ikinci, Coklu, Zayif: hepsi 2'yi aşıyor

    def test_yuva_ust_siniri_config_ontanimi(self) -> None:
        assert rt.YUVA_AZAMI_ONTANIM == BinaryReconstructionConfig().rtti_max_vtable_entries

    def test_sayilar(self) -> None:
        o = rt.tara(ornek_goruntu()).ozet()
        assert (o["typeinfo"], o["vtable"], o["birincil_vtable"], o["ayrik_islev"]) == (5, 6, 5, 11)
        assert o["ice_aktarim_yuvasi"] == 1 and o["yuva"] == 19


class TestYuvaSinif:
    def test_devralinan_yuva_en_taban_sinifa(self) -> None:
        s = rt.tara(ornek_goruntu())
        bag = {i.adres: i for i in s.islevler}
        assert bag[F[2]].sinif == TI_TABAN and bag[F[2]].karar == rt.BAG_TABAN
        assert bag[F[3]].sinif == TI_TEKLI and bag[F[3]].karar == rt.BAG_TABAN
        assert bag[F[6]].sinif == TI_COKLU and bag[F[6]].karar == rt.BAG_TEK

    def test_taban_iliskisi_yoksa_belirsiz_aday_yok(self) -> None:
        s = rt.tara(ornek_goruntu())
        bag = {i.adres: i for i in s.islevler}
        assert bag[F[10]].karar == rt.BAG_BELIRSIZ and bag[F[10]].sinif is None
        assert all(F[10] not in c["methods"] for c in s.rtti_classes())
        assert s.ozet()["belirsiz_islev"] == 1

    def test_rtti_classes_add_rtti_bicimi(self) -> None:
        s = rt.tara(ornek_goruntu())
        siniflar = s.rtti_classes()
        assert len(siniflar) == 5
        for c in siniflar:
            assert set(c) >= {"name", "mangled", "methods", "bases", "vtable"}
            assert all(isinstance(m, int) for m in c["methods"])
        tekli = next(c for c in siniflar if c["mangled"] == "5Tekli")
        # F0 / F2 Taban'a bağlı (devralınan): Tekli'de 0; F3 Tekli'nin kendi yuvası
        assert tekli["methods"] == [0, F[3], 0] and tekli["vtable"] == VT_TEKLI
        taban = next(c for c in siniflar if c["mangled"] == "5Taban")
        assert taban["methods"] == [F[0], F[1], F[2], 0]

    def test_dongusel_taban_sonlanir_ve_sayilir(self) -> None:
        # Coklu'nun ilk tabanı kendisi (bozuk / düşman girdi): döngü sayaçla kesilir
        s = rt.tara(ornek_goruntu(coklu_taban1=TI_COKLU))
        assert s.durum == rt.DURUM_CALISTI and s.sayaclar.get(rt.H_DONGUSEL_TABAN, 0) >= 1


class TestElf:
    def test_elf_adlari_ve_gcc_yerel_ad(self) -> None:
        k = ornek_kurucu(elf=True)
        yerel = k.dizgi("*N12_GLOBAL__N_15GizliE")
        k.bag(DATA + 0x88, MACHO_CLASS, 16)
        k.gosterici(DATA + 0x90, yerel)
        s = rt.tara(k.goruntu())
        ti = s.ti_sozlugu()
        assert s.durum == rt.DURUM_CALISTI and len(ti) == 6
        assert ti[DATA + 0x88].ad == "N12_GLOBAL__N_15GizliE" and ti[DATA + 0x88].yerel_ad
        assert sorted(_vt(s)) == [VT_TABAN, VT_TEKLI, VT_IKINCI, VT_COKLU, VT_COKLU2, VT_ZAYIF]
        assert _vt(s)[VT_IKINCI].yuvalar == [None, F[4], F[10]]


class TestSaglamlik:
    def test_pe_desteklenmiyor(self) -> None:
        g = BellekGoruntu([("__text", TEXT, b"\0" * 16, True)], bicim=BICIM_PE)
        assert rt.tara(g).durum == rt.DURUM_DESTEKLENMIYOR

    def test_32_bit_desteklenmiyor(self) -> None:
        g = BellekGoruntu([("__text", TEXT, b"\0" * 16, True)], gosterici_boyutu=4)
        assert rt.tara(g).durum == rt.DURUM_DESTEKLENMIYOR

    def test_typeinfo_yoksa_veri_yok(self) -> None:
        g = BellekGoruntu([("__text", TEXT, b"\0" * 16, True), ("__const", DATA, b"\1" * 64, False)])
        s = rt.tara(g)
        assert s.durum == rt.DURUM_VERI_YOK and s.rtti_classes() == []

    def test_vmi_taban_sayisi_siniri(self) -> None:
        s = rt.tara(ornek_goruntu(vmi_sayisi=rt.VMI_TABAN_AZAMI + 1))
        assert s.sayaclar[rt.H_VMI_SINIR] == 1 and s.ti_sozlugu()[TI_COKLU].tabanlar == []

    def test_kesik_vtable(self) -> None:
        k = ornek_kurucu()
        son = VT_TABAN + 24  # dosya ilk yuvadan sonra bitiyor: sonrası yok
        g = BellekGoruntu([("__text", TEXT, bytes(k.text), True), ("__const", STR, bytes(k.str), False),
                           ("__const", DATA, bytes(k.data[:son - DATA]), False)],
                          yeniden_konumlamalar={a: h for a, h in k.rk.items() if a < son},
                          baglar={a: b for a, b in k.baglar.items() if a < son}, semboller=k.semboller)
        s = rt.tara(g)
        assert s.durum == rt.DURUM_CALISTI and _vt(s)[VT_TABAN].yuvalar == [F[0]]

    def test_sure_siniri(self) -> None:
        saat = iter(range(0, 10**9, 100))  # her okumada 100 sn ilerleyen sahte saat
        # süre her 4 096 adımda bir denetlenir; küçük taramada denetim adımına gelmek için sayaç öne alınır
        tar = rt.RttiTarayici(ornek_goruntu(), sure_siniri=1.0, zaman=lambda: float(next(saat)))
        tar._adim = 4095  # bir sonraki adım denetim adımı
        sonuc = tar.tara()
        assert sonuc.durum == rt.DURUM_HATA and "süre sınırı" in (sonuc.neden or "")

    def test_beklenmeyen_hata_istisna_atmaz(self) -> None:
        g = MagicMock()
        g.bicim = "macho"
        g.gosterici_boyutu = 8
        g.bolumler = None  # yineleme TypeError
        s = rt.tara(g)
        assert s.durum == rt.DURUM_HATA

    def test_bozuk_zincir_durumu_hata(self) -> None:
        g = ornek_goruntu()
        g._durum_yaz("duzeltme", "hata", "zincir okunamadı")
        s = rt.tara(g)
        assert s.durum == rt.DURUM_HATA and "bozuk" in (s.neden or "")

    def test_bulanik_girdi_istisna_yok(self) -> None:
        k = ornek_kurucu()
        rng = random.Random(20261123)
        for _ in range(60):
            veri = bytearray(k.data)
            for _ in range(200):
                veri[rng.randrange(len(veri))] = rng.randrange(256)
            rk = {a: (h if rng.random() > 0.1 else rng.randrange(1 << 64)) for a, h in k.rk.items()}
            g = BellekGoruntu([("__text", TEXT, bytes(k.text), True), ("__const", STR, bytes(k.str), False),
                               ("__const", DATA, bytes(veri), False)],
                              yeniden_konumlamalar=rk, baglar=k.baglar, semboller=k.semboller)
            s = rt.tara(g)
            assert s.durum in (rt.DURUM_CALISTI, rt.DURUM_VERI_YOK)


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


def _ctx(tmp_path: Path, bayrak: Any = True, sinir: Any = None) -> StepContext:
    pc = MagicMock()
    pc.workspace = _Calisma(tmp_path / "ws")
    cfg = Config()
    if bayrak is not None:
        cfg.binary_reconstruction.enable_rtti_recovery = bayrak
    if sinir is not None:
        cfg.binary_reconstruction.rtti_max_vtable_entries = sinir
    pc.config = cfg
    ctx = StepContext(pipeline_context=pc)
    yol = tmp_path / "ikili"
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
        spec = get_step("rtti_recovery")
        assert spec.requires == ("binary_for_byte_match",)
        assert set(spec.produces) == {"rtti_classes", "rtti_status", "rtti_classes_path"}

    def test_bayrak_alani_ontanim_kapali(self) -> None:
        assert BinaryReconstructionConfig().enable_rtti_recovery is False

    @pytest.mark.parametrize("bayrak", [None, False, 1, "evet", MagicMock()])
    def test_bayrak_tam_true_degilse_kapali(self, tmp_path: Path, sahte_ac, bayrak: Any) -> None:
        cagri = sahte_ac(ornek_goruntu())
        ctx = _ctx(tmp_path, bayrak=bayrak)
        if isinstance(bayrak, MagicMock):
            ctx.pipeline_context.config = MagicMock()
        out = RttiRecoveryStep().run(ctx)
        assert out["rtti_status"] == (rt.DURUM_KAPALI, "bayrak kapalı")
        assert out["rtti_classes"] == [] and out["rtti_classes_path"] is None
        assert cagri == [] and not (tmp_path / "ws").exists()

    def test_calisti_yapit_ve_dosya(self, tmp_path: Path, sahte_ac) -> None:
        cagri = sahte_ac(ornek_goruntu())
        ctx = _ctx(tmp_path)
        out = RttiRecoveryStep().run(ctx)
        assert cagri == [tmp_path / "ikili"]
        assert out["rtti_status"] == (rt.DURUM_CALISTI, None)
        assert [c["mangled"] for c in out["rtti_classes"]] == list(RTTI_ORNEK_ADLARI.values())
        p = out["rtti_classes_path"]
        assert p == tmp_path / "ws" / "static" / "rtti_classes.json"
        belge = json.loads(p.read_text(encoding="utf-8"))
        assert belge["schema"] == "karadul.rtti_classes.v1" and belge["durum"] == rt.DURUM_CALISTI
        assert len(belge["vtablelar"]) == 6 and belge["ozet"]["belirsiz_islev"] == 1
        assert {i["karar"] for i in belge["islevler"]} == {rt.BAG_TEK, rt.BAG_TABAN, rt.BAG_BELIRSIZ}
        assert ctx.stats["rtti_class_count"] == 5 and ctx.stats["rtti_vtable_count"] == 6 and ctx.errors == []

    def test_yuva_siniri_configden(self, tmp_path: Path, sahte_ac) -> None:
        sahte_ac(ornek_goruntu())
        out = RttiRecoveryStep().run(_ctx(tmp_path, sinir=2))
        belge = json.loads(out["rtti_classes_path"].read_text(encoding="utf-8"))
        assert belge["ozet"]["sayaclar"][rt.H_YUVA_SINIR] == 5

    @pytest.mark.parametrize("sinir", [0, -3, True, "64"])
    def test_gecersiz_sinir_ontanima_duser(self, sinir: Any) -> None:
        cfg = Config()
        cfg.binary_reconstruction.rtti_max_vtable_entries = sinir
        assert adim_mod.rtti_slot_limit(cfg) == rt.YUVA_AZAMI_ONTANIM

    def test_goruntu_acilamazsa_durum_ve_hata(self, tmp_path: Path, sahte_ac) -> None:
        sahte_ac(hata=OSError("okunamadı"))
        ctx = _ctx(tmp_path)
        out = RttiRecoveryStep().run(ctx)
        assert out["rtti_status"][0] == rt.DURUM_HATA and "görüntü açılamadı" in out["rtti_status"][1]
        assert ctx.errors and "rtti_recovery" in ctx.errors[0]

    def test_bicim_desteklenmiyor(self, tmp_path: Path, sahte_ac) -> None:
        sahte_ac(hata=GoruntuHatasi("biçim tanınmadı", "desteklenmiyor"))
        out = RttiRecoveryStep().run(_ctx(tmp_path))
        assert out["rtti_status"][0] == rt.DURUM_DESTEKLENMIYOR and out["rtti_classes"] == []

    def test_gercek_calisma_alani_ile(self, tmp_path: Path, sahte_ac) -> None:
        from karadul.core.workspace import Workspace

        sahte_ac(ornek_goruntu())
        ctx = _ctx(tmp_path)
        ws = Workspace(tmp_path, "ornek", workspace_dir=tmp_path / "gercek_ws")
        ws.create()
        ctx.pipeline_context.workspace = ws
        out = RttiRecoveryStep().run(ctx)
        assert Path(out["rtti_classes_path"]).parent.name == "static"
        assert ctx.stage_artifacts["rtti_classes_path"] == out["rtti_classes_path"]
