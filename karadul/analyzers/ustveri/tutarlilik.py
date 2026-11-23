"""Go ``pclntab`` adlarının zorunlu yapılarla tutarlılık denetimi (P-ÜV7; ÜST VERİ hattı, I4).

Go fonksiyon adı (``_func.nameOff``) çalışma için zorunlu değildir: yığın açma adı okumaz, ad
yalnız hata dökümüne gider. Bu yüzden ad metni değiştirilebilir. Bu modül adı, çalışma için
zorunlu ikinci bir yapıyla karşılaştırır ve fonksiyon başına damga üretir:

- ``cift_kaynak``: ad, ikinci bir zorunlu yapıyla (T1 ∪ T2 ∪ T5) karşılaştırıldı ve uyuştu;
- ``tek_kaynak``: adın ikinci kaynağı yok (karşılaştırılamadı);
- ``tutarsiz``: güçlü denetimlerden biri uyuşmazlık buldu ya da P-ÜV1'in fonksiyon başına K4
  sonucu (``pcsp_kapsama``) üst verinin gövdeye uymadığını gösteriyor.

Denetim adın gerçekliğini **kanıtlamaz**: tip verisi ve ``pclntab`` birlikte, tutarlı biçimde
değiştirilirse (bozma deneyi D türü) yakalanmaz. Ucuz tahrifatı ve bozuk üst veriyi yakalar.

Denetimler (``docs/arge/2026-11-19_mythos/ustveri/BULGULAR.md`` §6.2):

- T1 (güçlü) itab: ``itab.Fun[i]``'nin gösterdiği fonksiyonun adı arayüzün i. yöntem adıyla
  biter (``runtime.unreachableMethod`` hedefi dışlanır: bağlayıcının budadığı yöntemin yeri).
- T2 (güçlü) yöntem tablosu: somut tipin ``Tfn`` / ``Ifn`` adresindeki fonksiyonun adı yöntem
  adıyla biter (son bileşen: köşeli ayraç öbekleri atılır, ``-fm`` eki soyulur).
- T2p (güçlü) paket yolu: aynı fonksiyonun adı (``%2e`` kaçışları çözülerek) tipin
  ``PkgPath``'i + ``.`` ile başlar (``ad_paketle_baslar``; araştırmanın ``paket_adi`` eşitliği
  yükseltilmiş dışa kapalı yöntemlerde yanlış alarm veriyordu, sayacı ayrıca raporlanır).
- T5 (güçlü) ``funcID`` çapası: özel ``funcID`` taşıyan fonksiyon beklenen ``runtime.`` adını
  taşır (sürüm tablosu eşleşmiyorsa yalnız ``runtime.`` öneki).
- T6 (güçlü) biçim: ad geçerli UTF-8, denetim karakteri yok.
- T3 (zayıf) dosya ↔ paket; T4 (zayıf) derleme birimi çoğunluk paketi. Hesaplanır, ayrı
  raporlanır; damgaya ve ikili kararına girmez (T3'ün yanlış alarmı derleme düzenine bağlı).
- K4 (yapısal, P-ÜV1) ``pcsp`` tablosu gövdeyi kaplamıyor (``kisa`` / ``tasan``); K10 (yapısal,
  yalnız arm64) ``pcsp``'nin ilk sıfırdan farklı değeri, o pc'den önceki komutun yığın
  ayarlamasıyla aynı değil (üst veriyi fonksiyonun içeriğine bağlar; bozma E türü). İkisi
  fonksiyonun damgasını ``tutarsiz`` yapar; güçlü işaret oranına (ikili kararı) girmez.

İkili kararı: güçlü işaretli fonksiyon varsa ``uyari``; oranı ``UST_VERI_SUPHELI_ESIGI``'ni
aşarsa ya da P-ÜV1'in yapı kararı ihlal veriyorsa ``ust_veri_supheli``; yoksa ``temiz``.

Başvuru (araştırma) betiği: ``scripts/arge/ustveri/go_tutarlilik.py``; bu modül ondan yeniden
yazıldı. Damga ad kanalına P-ÜV6b'de bağlanır; bu modül yalnız kitaplıktır.
"""

from __future__ import annotations

import collections
import re
from dataclasses import dataclass, field
from typing import Any

from karadul.analyzers.ustveri.go_pclntab import (
    DURUM_TUTARSIZ,
    FUNC_FLAG_ASM,
    PCSP_KISA,
    PCSP_TASAN,
    GoOkumaHatasi,
    GoPclntab,
    _Kesik,
    butunluk_denetle,
    buildinfo_oku,
    paket_adi,
    tutarsizlik_nedeni,
)
from karadul.analyzers.ustveri.go_tip import GoTipVerisi
from karadul.analyzers.ustveri.goruntu import DURUM_CALISTI, DURUM_HATA

# ---------------------------------------------------------------------------
# Adlandırılmış sabitler (P-ÜV6b içe aktarır)
# ---------------------------------------------------------------------------

DAMGA_CIFT_KAYNAK = "cift_kaynak"
DAMGA_TEK_KAYNAK = "tek_kaynak"
DAMGA_TUTARSIZ = "tutarsiz"
DAMGALAR = (DAMGA_CIFT_KAYNAK, DAMGA_TEK_KAYNAK, DAMGA_TUTARSIZ)

KARAR_TEMIZ = "temiz"
KARAR_UYARI = "uyari"
KARAR_UST_VERI_SUPHELI = "ust_veri_supheli"
IKILI_KARARLARI = (KARAR_TEMIZ, KARAR_UYARI, KARAR_UST_VERI_SUPHELI)

# İkili düzeyi eşik: güçlü işaretli fonksiyon / bütün ftab girişleri bu oranı aşarsa
# ``ust_veri_supheli`` (ön kayıt: on_kayit_PUV7.md, H7).
UST_VERI_SUPHELI_ESIGI = 0.01

GUCLU_DENETIMLER = frozenset({"T1", "T2", "T2p", "T5", "T6"})
ZAYIF_DENETIMLER = frozenset({"T3", "T4"})
IKINCI_KAYNAK_DENETIMLERI = ("T1", "T2", "T5")
# P-ÜV1'in fonksiyon başına K4 sonucu: bu değerlerde üst veri gövdeye uymuyor → tutarsız.
K4_UYUMSUZ = frozenset({PCSP_KISA, PCSP_TASAN})
DENETIM_K4 = "K4"
# K10 (kalem 6; yalnız arm64): pcsp'nin ilk sıfırdan farklı değeri, o pc'den önceki komutun
# yaptığı yığın ayarlamasıyla aynı olmalı (üst veriyi fonksiyonun içeriğine bağlar). Bozulmamış
# gh / limactl / Ollama / colima'da uyum %99,56 / %99,89 / %99,85 / %99,87 (P-UV7.md, kalem 6).
DENETIM_K10 = "K10"
K10_UYUMLU = "uyumlu"
K10_UYUMSUZ = "uyumsuz"          # komut yığın ayarı ama büyüklük farklı
K10_TANINMAYAN = "taninmayan"    # pc'den önceki komut yığın ayarı değil
K10_OKUNAMADI = "okunamadi"
K10_CERCEVESIZ = "cercevesiz"    # pcsp hep 0: bakılmaz
K10_IHLAL = frozenset({K10_UYUMSUZ, K10_TANINMAYAN, K10_OKUNAMADI})
K10_GERI_ARAMA = 8               # büyük çerçevede `sub xR, sp, #N` için geriye bakılan en çok komut
YAPISAL_ISARETLER = frozenset({DENETIM_K4, DENETIM_K10})

UNREACHABLE_METHOD = "runtime.unreachableMethod"

# funcID sırası (Go 1.26 / 1.27 ``internal/abi/symtab.go``; ARGE başvurusu
# ``scripts/arge/ustveri/go_pclntab.py`` ``FUNC_ID``). Sarmalayıcı kimliği bu tablonun son
# girdisiyle aynıysa tam ad denetlenir; değilse (başka sürüm) yalnız ``runtime.`` öneki.
FUNC_ID = (
    "Normal", "abort", "asmcgocall", "asyncPreempt", "cgocallback", "corostart", "debugCallV2",
    "gcBgMarkWorker", "goexit", "gogo", "gopanic", "handleAsyncEvent", "mcall", "morestack", "mstart",
    "panicwrap", "rt0_go", "runtime_main", "runFinalizers", "runCleanups", "sigpanic", "systemstack",
    "systemstack_switch", "Wrapper",
)
FUNC_ID_SARMALAYICI = len(FUNC_ID) - 1
FUNC_ID_ADI = {k: "runtime." + k for k in FUNC_ID[1:-1]}
FUNC_ID_ADI["runtime_main"] = "runtime.main"

_SURUM_EKI_RE = re.compile(r"@v[^/]+")
_KACIS_RE = re.compile(r"%([0-9a-fA-F]{2})")
_GECERSIZ_KARAKTER = "�"


# ---------------------------------------------------------------------------
# Ad yardımcıları
# ---------------------------------------------------------------------------


def koseli_soy(ad: str) -> str:
    """Tip parametresi köşeli ayraç öbeklerini (iç içe dahil) at: ``T[go.shape.int].M`` → ``T.M``."""
    out = []
    d = 0
    for c in ad:
        if c == "[":
            d += 1
        elif c == "]":
            d = max(0, d - 1)
        elif d == 0:
            out.append(c)
    return "".join(out)


def kacis_coz(paket: str) -> str:
    """Bağlayıcının ad içindeki kaçışlarını çöz (son yol öğesindeki nokta ``%2e`` yazılır)."""
    return _KACIS_RE.sub(lambda m: chr(int(m.group(1), 16)), paket)


def son_bilesen(ad: str) -> str:
    """Adın son bileşeni: ``pkg.(*T[…]).M-fm`` → ``M``."""
    g = koseli_soy(ad)
    if g.endswith("-fm"):
        g = g[:-3]
    return g.rsplit(".", 1)[-1]


def dosya_paketi(dosya: str) -> str:
    """Kaynak dosya yolundan paket dizini (sürüm eki ``@v1.2.3`` atılır)."""
    d = dosya.rsplit("/", 1)[0] if "/" in dosya else ""
    return _SURUM_EKI_RE.sub("", d)


def ad_paketle_baslar(ad: str, paket: str) -> bool:
    """T2p: ad (kaçışları çözülerek) ``paket + "."`` ile başlıyor mu.

    ``paket_adi`` (``runtime.funcpkgpath`` kuralı: son ``/``'tan sonraki ilk nokta) başka paketten
    yükseltilmiş dışa kapalı yöntemlerde yanılır: o yöntemin sembolü yöntem paketinin yoluyla
    nitelenir (``a/b.(*T).golang.org/x/net/http2.streamEnded``) ve son ``/`` yöntem adının
    içindedir. Önek denetimi bu adlarda doğru paketi (alıcının paketi) görür.
    """
    return kacis_coz(ad).startswith(paket + ".")


def bicim_bozuk(ad: str) -> bool:
    """T6: çözülemeyen bayt ya da denetim karakteri."""
    return _GECERSIZ_KARAKTER in ad or any(ord(c) < 0x20 for c in ad)


# ---------------------------------------------------------------------------
# K10: arm64 giriş bölümü yığın ayarlaması (Arm ARM, A64 komut kodlaması)
# ---------------------------------------------------------------------------

_SP = 31


def _isaretli(v: int, bit: int) -> int:
    return v - (1 << bit) if v & (1 << (bit - 1)) else v


def arm64_yigin_komutu(w: int) -> tuple[str, int, int] | None:
    """Tek A64 komutunun yığın etkisi; ilgisizse None.

    - ``("dus", N, 0)``: ``str x30, [sp, #-N]!`` / ``stp x29, x30, [sp, #-N]!`` /
      ``sub sp, sp, #N`` (sp N azalır);
    - ``("kayit", N, R)``: ``sub xR, sp, #N`` (büyük çerçeve hazırlığı);
    - ``("mov", 0, R)``: ``mov sp, xR`` (= ``add sp, xR, #0``).
    """
    if w & 0xFFE00C00 == 0xF8000C00:            # STR (64 bit, ön indeksli)
        rt, rn, imm9 = w & 31, (w >> 5) & 31, _isaretli((w >> 12) & 0x1FF, 9)
        if rn == _SP and rt == 30 and imm9 < 0:
            return "dus", -imm9, 0
        return None
    if w & 0xFFC00000 == 0xA9800000:            # STP (64 bit, ön indeksli)
        rt, rn, rt2 = w & 31, (w >> 5) & 31, (w >> 10) & 31
        imm7 = _isaretli((w >> 15) & 0x7F, 7)
        if rn == _SP and rt == 29 and rt2 == 30 and imm7 < 0:
            return "dus", -imm7 * 8, 0
        return None
    if w & 0xFF800000 == 0xD1000000:            # SUB (anlık, 64 bit)
        rd, rn = w & 31, (w >> 5) & 31
        deger = ((w >> 10) & 0xFFF) << (12 if (w >> 22) & 1 else 0)
        if rn == _SP:
            return ("dus", deger, 0) if rd == _SP else ("kayit", deger, rd)
        if rn == rd:
            return "ek", deger, rd                  # sub xR, xR, #N (iki parçalı büyük çerçeve)
        return None
    if w & 0xFF800000 == 0x91000000:            # ADD (anlık, 64 bit): mov sp, xR
        rd, rn = w & 31, (w >> 5) & 31
        if rd == _SP and rn != _SP and (w >> 10) & 0xFFF == 0:
            return "mov", 0, rn
    return None


def arm64_buyuk_cerceve_komutu(w: int) -> tuple[str, int, int, int] | None:
    """Büyük çerçeve sabiti: ``("sub_reg", Rd, Rm, 0)`` = ``sub xRd, sp, xRm`` (UXTX, kaydırma 0);
    ``("movz", Rd, değer, kaydırma)``; ``("movk", Rd, değer, kaydırma)``. İlgisizse None."""
    if w & 0xFFE0FC00 == 0xCB206000 and (w >> 5) & 31 == _SP:   # SUB (genişletilmiş yazmaç), UXTX #0
        return "sub_reg", w & 31, (w >> 16) & 31, 0
    if w & 0xFF800000 == 0xD2800000:            # MOVZ (64 bit)
        return "movz", w & 31, (w >> 5) & 0xFFFF, 16 * ((w >> 21) & 3)
    if w & 0xFF800000 == 0xF2800000:            # MOVK (64 bit)
        return "movk", w & 31, (w >> 5) & 0xFFFF, 16 * ((w >> 21) & 3)
    return None


def _buyuk_cerceve_degeri(g: Any, mov_pc: int, reg: int) -> int | None:
    """``mov sp, xR``'den geriye: xR = sp − N ise N; bulunamazsa None.

    Go arm64 büyük çerçeve kalıpları: ``sub xR, sp, #N[, lsl #12]``; ``sub xR, sp, #a`` +
    ``sub xR, xR, #b, lsl #12``; ``mov xK, #N`` [+ ``movk``] + ``sub xR, sp, xK``.
    """
    toplam = 0
    sabit_reg: int | None = None
    parcalar = 0
    for geri in range(1, 1 + K10_GERI_ARAMA):
        w = _u32(g, mov_pc - 4 * geri)
        if w is None:
            return None
        if sabit_reg is None:
            k = arm64_yigin_komutu(w)
            if k is not None and k[2] == reg and k[0] == "kayit":
                return toplam + k[1]
            if k is not None and k[2] == reg and k[0] == "ek":
                toplam += k[1]
                continue
            b = arm64_buyuk_cerceve_komutu(w)
            if b is not None and b[0] == "sub_reg" and b[1] == reg:
                sabit_reg = b[2]
            continue
        b = arm64_buyuk_cerceve_komutu(w)
        if b is not None and b[1] == sabit_reg and b[0] == "movk":
            parcalar |= b[2] << b[3]
        elif b is not None and b[1] == sabit_reg and b[0] == "movz":
            return toplam + ((b[2] << b[3]) | parcalar)
    return None


def _u32(g: Any, adres: int) -> int | None:
    try:
        b = g.oku(adres, 4)
    except Exception:  # noqa: BLE001
        return None
    return int.from_bytes(b, "little") if b is not None and len(b) == 4 else None


def k10_sinifi(g: Any, tablo: list[tuple[int, int, int]]) -> tuple[str, int | None]:
    """Bir fonksiyonun K10 sınıfı: pcsp tablosunun ilk sıfırdan farklı değeri ↔ önceki komut."""
    ilk = next(((v, a) for v, a, _b in tablo if v != 0), None)
    if ilk is None:
        return K10_CERCEVESIZ, None
    deger, pc = ilk
    w = _u32(g, pc - 4)
    if w is None:
        return K10_OKUNAMADI, None
    k = arm64_yigin_komutu(w)
    n = None
    if k is not None and k[0] == "dus":
        n = k[1]
    elif k is not None and k[0] == "mov":
        n = _buyuk_cerceve_degeri(g, pc - 4, k[2])
    if n is None:
        return K10_TANINMAYAN, None
    return (K10_UYUMLU if n == deger else K10_UYUMSUZ), n


def k10_denetle(g: Any, pcln: GoPclntab, fs: list) -> tuple[set[int], dict[str, Any]]:
    """K10 bütün fonksiyonlarda (yalnız arm64). Döner: (ihlal veren girişler, sayım).

    Bakılmayanlar: ``pcsp`` tablosu yok, birleştirici dili bayraklı, çerçevesiz (pcsp hep 0).
    """
    if getattr(g, "mimari", "") != "arm64":
        return set(), {"durum": "desteklenmiyor", "neden": f"mimari {getattr(g, 'mimari', '')!r}"}
    say: collections.Counter = collections.Counter()
    ihlal: set[int] = set()
    for f in fs:
        if f.pcsp == 0:
            say["pcsp_yok"] += 1
            continue
        if f.flag & FUNC_FLAG_ASM:
            say["asm"] += 1
            continue
        try:
            tablo = pcln.pc_tablosu(f.pcsp, f.giris)
        except _Kesik:
            say[K10_OKUNAMADI] += 1
            ihlal.add(f.giris)
            continue
        sinif, _n = k10_sinifi(g, tablo)
        say[sinif] += 1
        if sinif in K10_IHLAL:
            ihlal.add(f.giris)
    bakilan = sum(say[k] for k in (K10_UYUMLU, *K10_IHLAL))
    return ihlal, {"durum": DURUM_CALISTI, "sayim": dict(say), "bakilan": bakilan,
                   "ihlal": len(ihlal), "uyumlu": say[K10_UYUMLU]}


# ---------------------------------------------------------------------------
# Sonuç
# ---------------------------------------------------------------------------


@dataclass
class TutarlilikSonucu:
    durum: str
    neden: str = ""
    # giriş adresi → damga (bütün ftab girişleri; adsız giriş tek_kaynak)
    damgalar: dict[int, str] = field(default_factory=dict)
    # giriş adresi → işaret kümesi (güçlü + zayıf + K4 / K10)
    isaretler: dict[int, frozenset[str]] = field(default_factory=dict)
    # denetim → kapsanan giriş adresleri
    kapsam: dict[str, set[int]] = field(default_factory=dict)
    ozet: dict[str, Any] = field(default_factory=dict)
    karar: str | None = None
    karar_nedeni: str = ""

    def damga(self, giris: int) -> str | None:
        return self.damgalar.get(giris)


# ---------------------------------------------------------------------------
# Denetim
# ---------------------------------------------------------------------------


def denetle(
    goruntu: Any,
    pcln: GoPclntab | None = None,
    fonksiyonlar: list | None = None,
    buildinfo: dict[str, Any] | None = None,
    butunluk: dict[str, Any] | None = None,
    k10: bool = True,
) -> TutarlilikSonucu:
    """Görüntüdeki Go modülünün adlarını denetle. İstisna atmaz.

    ``pcln`` / ``fonksiyonlar`` / ``buildinfo`` / ``butunluk`` verilmezse burada okunur
    (``go_pclntab.oku`` sonucundan gelenler yeniden kullanılabilir). ``butunluk`` verilmezse
    P-ÜV1'in yapı denetimleri koşulur (fonksiyon başına ``pcsp_kapsama`` için de gerekir).
    ``k10`` yanlışsa K10 koşulmaz (yalnız ölçüm karşılaştırması için).
    """
    try:
        return _denetle_ic(goruntu, pcln, fonksiyonlar, buildinfo, butunluk, k10)
    except GoOkumaHatasi as e:
        return TutarlilikSonucu(durum=e.durum, neden=e.neden)
    except _Kesik as e:
        return TutarlilikSonucu(durum=DURUM_TUTARSIZ, neden=f"tablo kesik: {e}")
    except Exception as e:  # noqa: BLE001 - denetim analizi düşürmez
        return TutarlilikSonucu(durum=DURUM_HATA, neden=f"{type(e).__name__}: {e}")


def _denetle_ic(goruntu, pcln, fonksiyonlar, buildinfo, butunluk, k10) -> TutarlilikSonucu:
    p = pcln if pcln is not None else GoPclntab(goruntu)
    fs = fonksiyonlar if fonksiyonlar is not None else p.fonksiyonlar()
    if butunluk is None:
        butunluk = butunluk_denetle(p, fs)
    bi = buildinfo if buildinfo is not None else (buildinfo_oku(goruntu) or {})
    es = {f.giris: f for f in fs}
    isaret: dict[int, set[str]] = collections.defaultdict(set)
    kapsam: dict[str, set[int]] = collections.defaultdict(set)
    ozet: dict[str, Any] = {}

    # ---- tip verisi: T1 / T2 / T2p ---------------------------------------
    tip = GoTipVerisi(goruntu, p, bi.get("surum"))
    ozet["tip_verisi"] = tip.ozet()
    itablar = tip.itablar() if tip.calisti else []
    t1_bak = t1_uy = 0
    for it in itablar:
        for (mad, _off), adr in zip(it.yontemler, it.fun):
            f = es.get(adr) if adr is not None else None
            if f is None or mad is None:
                continue
            if f.ad == UNREACHABLE_METHOD:
                continue
            t1_bak += 1
            kapsam["T1"].add(adr)
            if son_bilesen(f.ad) == mad:
                t1_uy += 1
            else:
                isaret[adr].add("T1")
    tipler = tip.ulasilan_tipler(itablar) if tip.calisti else set()
    t2_bak = t2_uy = t2p_bak = t2p_uy = t2p_ar_uy = 0
    yontemli_tip = 0
    for t in tipler:
        u = tip.uncommon(t)
        if not u:
            continue
        if u.yontemler:
            yontemli_tip += 1
        for y in u.yontemler:
            for adr in (y.ifn, y.tfn):
                f = es.get(adr) if adr is not None else None
                if f is None or y.ad is None:
                    continue
                t2_bak += 1
                kapsam["T2"].add(adr)
                if son_bilesen(f.ad) == y.ad:
                    t2_uy += 1
                else:
                    isaret[adr].add("T2")
                if u.paket:
                    t2p_bak += 1
                    # araştırma tanımı (yalnız sayaç; başvuruyla karşılaştırma için)
                    t2p_ar_uy += kacis_coz(paket_adi(f.ad)) == u.paket
                    if ad_paketle_baslar(f.ad, u.paket):
                        t2p_uy += 1
                    else:
                        isaret[adr].add("T2p")
    ozet["T1"] = {"itab": len(itablar), "bakilan_yuva": t1_bak, "uyan": t1_uy,
                  "kapsanan_fonksiyon": len(kapsam["T1"])}
    ozet["T2"] = {"ulasilan_tip": len(tipler), "yontemli_tip": yontemli_tip, "bakilan": t2_bak,
                  "uyan": t2_uy, "paket_bakilan": t2p_bak, "paket_uyan": t2p_uy,
                  "paket_uyan_arastirma_tanimi": t2p_ar_uy,
                  "kapsanan_fonksiyon": len(kapsam["T2"])}

    # ---- T3: dosya ↔ paket (zayıf) ---------------------------------------
    ana_paket = bi.get("path")
    t3_bak = t3_uy = 0
    for f in fs:
        if not f.ad:
            continue
        pkg = kacis_coz(paket_adi(f.ad))
        dosya = f.dosya if f.dosya is not None else _dosya(p, f)
        if not dosya or not pkg or pkg.startswith(("type:", "go:")) or dosya.startswith("<"):
            continue
        dp = dosya_paketi(dosya)
        t3_bak += 1
        kapsam["T3"].add(f.giris)
        if (dp == pkg or (pkg == "main" and ana_paket and dp == ana_paket) or dp.endswith("/" + pkg)
                or (pkg.startswith("vendor/") and dp.endswith(pkg))):
            t3_uy += 1
        else:
            isaret[f.giris].add("T3")
    ozet["T3"] = {"bakilan": t3_bak, "uyan": t3_uy}

    # ---- T4: derleme birimi çoğunluğu (zayıf) -----------------------------
    cu: dict[int, list] = collections.defaultdict(list)
    for f in fs:
        if f.ad:
            cu[f.cu_offset].append(f)
    t4_bak = t4_uy = 0
    for liste in cu.values():
        say = collections.Counter(pk for pk in (paket_adi(f.ad) for f in liste)
                                  if pk and not pk.startswith(("type:", "go:")))
        if not say:
            continue
        cogunluk = say.most_common(1)[0][0]
        for f in liste:
            pk = paket_adi(f.ad)
            if not pk or pk.startswith(("type:", "go:")):
                continue
            t4_bak += 1
            kapsam["T4"].add(f.giris)
            if pk == cogunluk:
                t4_uy += 1
            else:
                isaret[f.giris].add("T4")
    ozet["T4"] = {"derleme_birimi": len(cu), "bakilan": t4_bak, "uyan": t4_uy}

    # ---- T5: funcID çapası ------------------------------------------------
    sarma = max((f.func_id for f in fs), default=0)
    t5_bak = t5_uy = 0
    for f in fs:
        if 0 < f.func_id < sarma:
            t5_bak += 1
            kapsam["T5"].add(f.giris)
            bek = FUNC_ID_ADI.get(FUNC_ID[f.func_id]) if sarma == FUNC_ID_SARMALAYICI else None
            if (bek is not None and f.ad == bek) or (bek is None and f.ad.startswith("runtime.")):
                t5_uy += 1
            else:
                isaret[f.giris].add("T5")
    ozet["T5"] = {"bakilan": t5_bak, "uyan": t5_uy, "sarmalayici_kimligi": sarma,
                  "tam_ad_tablosu": sarma == FUNC_ID_SARMALAYICI}

    # ---- T6: biçim ---------------------------------------------------------
    t6 = 0
    for f in fs:
        if f.ad and bicim_bozuk(f.ad):
            isaret[f.giris].add("T6")
            t6 += 1
    ozet["T6"] = {"bicimsiz": t6}

    # ---- K4 (P-ÜV1, fonksiyon başına) --------------------------------------
    k4 = 0
    for f in fs:
        if getattr(f, "pcsp_kapsama", "") in K4_UYUMSUZ:
            isaret[f.giris].add(DENETIM_K4)
            k4 += 1

    # ---- K10 (yalnız arm64; içerik ↔ pcsp) -----------------------------------
    if k10:
        k10_ihlal, k10_sayim = k10_denetle(goruntu, p, fs)
        for e in k10_ihlal:
            isaret[e].add(DENETIM_K10)
    else:
        k10_sayim = {"durum": "kapali"}
    ozet["K10"] = k10_sayim

    # ---- damga --------------------------------------------------------------
    ikinci = kapsam["T1"] | kapsam["T2"] | kapsam["T5"]
    damgalar: dict[int, str] = {}
    guclu_isaretli = 0
    for f in fs:
        im = isaret.get(f.giris, ())
        guclu = bool(GUCLU_DENETIMLER.intersection(im))
        guclu_isaretli += guclu
        if guclu or YAPISAL_ISARETLER.intersection(im):
            damgalar[f.giris] = DAMGA_TUTARSIZ
        elif f.giris in ikinci:
            damgalar[f.giris] = DAMGA_CIFT_KAYNAK
        else:
            damgalar[f.giris] = DAMGA_TEK_KAYNAK

    n = len(fs)
    adli = [f for f in fs if f.ad]
    ozet["fonksiyon"] = n
    ozet["adli"] = len(adli)
    # T denetimleri (araştırma tanımı; K4 / K10 ayrı satırda).
    ozet["isaretli_fonksiyon"] = sum(1 for v in isaret.values() if v - YAPISAL_ISARETLER)
    ozet["isaret_dagilimi"] = dict(collections.Counter(
        k for v in isaret.values() for k in v if k not in YAPISAL_ISARETLER))
    ozet["K10_ihlal_fonksiyon"] = sum(1 for v in isaret.values() if DENETIM_K10 in v)
    ozet["cift_kaynakli_fonksiyon"] = len(ikinci)
    ozet["guclu_isaretli_fonksiyon"] = guclu_isaretli
    ozet["guclu_isaret_orani"] = guclu_isaretli / n if n else 0.0
    ozet["K4_uyumsuz_fonksiyon"] = k4
    ozet["damga"] = {d: 0 for d in DAMGALAR} | dict(collections.Counter(damgalar.values()))
    ozet["adli_damga"] = {d: 0 for d in DAMGALAR} | dict(
        collections.Counter(damgalar[f.giris] for f in adli))
    ozet["K_ihlal"] = {k: (v.get("ihlal") if isinstance(v, dict) else None)
                       for k, v in butunluk.items() if k.startswith("K")}
    k_neden = tutarsizlik_nedeni(butunluk, n)
    ozet["K_karari"] = k_neden

    # ---- ikili kararı ---------------------------------------------------------
    if k_neden is not None:
        karar, karar_nedeni = KARAR_UST_VERI_SUPHELI, f"yapı denetimi: {k_neden}"
    elif n and guclu_isaretli > UST_VERI_SUPHELI_ESIGI * n:
        karar = KARAR_UST_VERI_SUPHELI
        karar_nedeni = (f"güçlü işaretli {guclu_isaretli} / {n} fonksiyon "
                        f"(> %{UST_VERI_SUPHELI_ESIGI * 100:g})")
    elif guclu_isaretli > 0:
        karar, karar_nedeni = KARAR_UYARI, f"güçlü işaretli {guclu_isaretli} / {n} fonksiyon"
    else:
        karar, karar_nedeni = KARAR_TEMIZ, ""

    return TutarlilikSonucu(
        durum=DURUM_CALISTI,
        damgalar=damgalar,
        isaretler={k: frozenset(v) for k, v in isaret.items()},
        kapsam={k: set(v) for k, v in kapsam.items()},
        ozet=ozet,
        karar=karar,
        karar_nedeni=karar_nedeni,
    )


def _dosya(p: GoPclntab, f: Any) -> str | None:
    try:
        return p.dosya_oku(f)
    except _Kesik:
        return None
