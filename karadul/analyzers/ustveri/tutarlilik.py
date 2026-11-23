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
- T2p (güçlü) paket yolu: aynı fonksiyonun ad paket öneki (``%2e`` kaçışları çözülerek) tipin
  ``PkgPath``'iyle aynı.
- T5 (güçlü) ``funcID`` çapası: özel ``funcID`` taşıyan fonksiyon beklenen ``runtime.`` adını
  taşır (sürüm tablosu eşleşmiyorsa yalnız ``runtime.`` öneki).
- T6 (güçlü) biçim: ad geçerli UTF-8, denetim karakteri yok.
- T3 (zayıf) dosya ↔ paket; T4 (zayıf) derleme birimi çoğunluk paketi. Hesaplanır, ayrı
  raporlanır; damgaya ve ikili kararına girmez (T3'ün yanlış alarmı derleme düzenine bağlı).

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


def bicim_bozuk(ad: str) -> bool:
    """T6: çözülemeyen bayt ya da denetim karakteri."""
    return _GECERSIZ_KARAKTER in ad or any(ord(c) < 0x20 for c in ad)


# ---------------------------------------------------------------------------
# Sonuç
# ---------------------------------------------------------------------------


@dataclass
class TutarlilikSonucu:
    durum: str
    neden: str = ""
    # giriş adresi → damga (bütün ftab girişleri; adsız giriş tek_kaynak)
    damgalar: dict[int, str] = field(default_factory=dict)
    # giriş adresi → işaret kümesi (güçlü + zayıf + K4)
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
) -> TutarlilikSonucu:
    """Görüntüdeki Go modülünün adlarını denetle. İstisna atmaz.

    ``pcln`` / ``fonksiyonlar`` / ``buildinfo`` / ``butunluk`` verilmezse burada okunur
    (``go_pclntab.oku`` sonucundan gelenler yeniden kullanılabilir). ``butunluk`` verilmezse
    P-ÜV1'in yapı denetimleri koşulur (fonksiyon başına ``pcsp_kapsama`` için de gerekir).
    """
    try:
        return _denetle_ic(goruntu, pcln, fonksiyonlar, buildinfo, butunluk)
    except GoOkumaHatasi as e:
        return TutarlilikSonucu(durum=e.durum, neden=e.neden)
    except _Kesik as e:
        return TutarlilikSonucu(durum=DURUM_TUTARSIZ, neden=f"tablo kesik: {e}")
    except Exception as e:  # noqa: BLE001 - denetim analizi düşürmez
        return TutarlilikSonucu(durum=DURUM_HATA, neden=f"{type(e).__name__}: {e}")


def _denetle_ic(goruntu, pcln, fonksiyonlar, buildinfo, butunluk) -> TutarlilikSonucu:
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
    t2_bak = t2_uy = t2p_bak = t2p_uy = 0
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
                    if kacis_coz(paket_adi(f.ad)) == u.paket:
                        t2p_uy += 1
                    else:
                        isaret[adr].add("T2p")
    ozet["T1"] = {"itab": len(itablar), "bakilan_yuva": t1_bak, "uyan": t1_uy,
                  "kapsanan_fonksiyon": len(kapsam["T1"])}
    ozet["T2"] = {"ulasilan_tip": len(tipler), "yontemli_tip": yontemli_tip, "bakilan": t2_bak,
                  "uyan": t2_uy, "paket_bakilan": t2p_bak, "paket_uyan": t2p_uy,
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

    # ---- damga --------------------------------------------------------------
    ikinci = kapsam["T1"] | kapsam["T2"] | kapsam["T5"]
    damgalar: dict[int, str] = {}
    guclu_isaretli = 0
    for f in fs:
        im = isaret.get(f.giris, ())
        guclu = bool(GUCLU_DENETIMLER.intersection(im))
        guclu_isaretli += guclu
        if guclu or DENETIM_K4 in im:
            damgalar[f.giris] = DAMGA_TUTARSIZ
        elif f.giris in ikinci:
            damgalar[f.giris] = DAMGA_CIFT_KAYNAK
        else:
            damgalar[f.giris] = DAMGA_TEK_KAYNAK

    n = len(fs)
    adli = [f for f in fs if f.ad]
    ozet["fonksiyon"] = n
    ozet["adli"] = len(adli)
    # T denetimleri (araştırma tanımı; K4 ayrı satırda).
    ozet["isaretli_fonksiyon"] = sum(1 for v in isaret.values() if v - {DENETIM_K4})
    ozet["isaret_dagilimi"] = dict(collections.Counter(
        k for v in isaret.values() for k in v if k != DENETIM_K4))
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
