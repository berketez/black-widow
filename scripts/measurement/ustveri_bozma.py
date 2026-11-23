"""P-ÜV7 ölçüm betiği: Go tutarlılık denetimi tabanı, bozma deneyi (A–E) ve K10 ölçüsü.

Alt komutlar (hepsi ikiliyi ÇALIŞTIRMAZ; özgün dosya değişmez, bozuk kopyalar yalnız bellekte):

- ``taban <ikili> [--dilim arm64]``: bozulmamış ikilide ``tutarlilik.denetle`` özeti (T1–T6,
  damga dökümü, ikili kararı, güçlü işaret oranı) + P-ÜV1 yapı denetimleri.
- ``deney <ince ikili>``: araştırma deneyinin (``scripts/arge/ustveri/dusman_deney.py``) ürün
  okuyucusuna bağlanmış hâli. Türler: A son bileşen, B paketler arası takas, C paket içi takas,
  D tutarlı sahtecilik (tip verisi + pclntab birlikte), E komşu ``_func`` takası. Tohum
  ``DUSMAN_DENEY_TOHUMU`` (20261119), tür başına ``N`` (200). Örneklem araştırmanınkiyle aynı
  olsun diye aday dışlaması araştırmanın tanımıyla (T3 dahil güçlü işaret) yapılır. Rapor iki
  sütunludur: ``arastirma`` (T3 dahil; başvuruyla karşılaştırma) ve ``urun`` (ürün damgası
  ``tutarsiz``; ürünün gerçek davranışı). K4 de iki sütun: araştırma kuralı ve ürünün
  ``pcsp_kapsama`` sonucu.
- ``k10 <ince ikili>``: kalem 6 ölçüsü (yalnız arm64): ``pcsp`` değerinin ilk kez sıfırdan farklı
  olduğu pc'den önceki komut, aynı büyüklükte yığın ayarlaması mı? (``capstone``.) ``--deney``
  verilirse aynı ölçü E türü bozuk kopyada da yapılır (yakalama sayısı).

Kullanım:
    PYTHONDONTWRITEBYTECODE=1 python scripts/measurement/ustveri_bozma.py taban <ikili> --cikti x.json
    PYTHONDONTWRITEBYTECODE=1 python scripts/measurement/ustveri_bozma.py deney <ince ikili> --cikti x.json
    PYTHONDONTWRITEBYTECODE=1 python scripts/measurement/ustveri_bozma.py k10 <ince ikili> [--deney] --cikti x.json

Ön kayıt: ``docs/arge/2026-11-19_mythos/ustveri/on_kayit_PUV7.md``.
"""

from __future__ import annotations

import argparse
import collections
import json
import math
import random
import re
import struct
import sys
import time
from pathlib import Path
from typing import Any

# Depo kökü önde: betik worktree'den koşulunca karadul o worktree'den yüklenir (editable kurulumun
# gösterdiği ana ağaçtan değil).
REPO = Path(__file__).resolve().parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from karadul.analyzers.ustveri import goruntu as GR  # noqa: E402
from karadul.analyzers.ustveri import tutarlilik as TU  # noqa: E402
from karadul.analyzers.ustveri.go_pclntab import (  # noqa: E402
    FUNC_FLAG_ASM,
    GoPclntab,
    butunluk_denetle,
    buildinfo_oku,
    paket_adi,
)
from karadul.analyzers.ustveri.go_tip import GoTipVerisi  # noqa: E402

DUSMAN_DENEY_TOHUMU = 20261119   # ön kayıt (araştırma DEFTER §7.3 ile aynı tohum)
N = 200
# Araştırmanın "güçlü" tanımı (T3 dahil): yalnız örneklem ve başvuruyla karşılaştırma sütunu için.
ARASTIRMA_GUCLU = frozenset({"T1", "T2", "T2p", "T3", "T5", "T6"})
# Ürünün T2p'si önek kuralıyla (``tutarlilik.ad_paketle_baslar``); araştırmanın T2p'si
# ``paket_adi`` eşitliği. Örneklem araştırmanınkiyle aynı kalsın diye araştırma T2p'si ayrı hesaplanır.
ARASTIRMA_GUCLU_T2P_SIZ = ARASTIRMA_GUCLU - {"T2p"}
K10_ESIGI = 0.99                 # kalem 6: bozulmamış ikilide uyum ≥ %99 ise K10 eklenir


# ---------------------------------------------------------------------------
# Yardımcılar
# ---------------------------------------------------------------------------


def kaydir(b: bytes) -> bytes:
    """ASCII harfleri bir ileri kaydır (a→b … z→a); uzunluk değişmez."""
    out = bytearray(b)
    for i, c in enumerate(out):
        if 97 <= c <= 122:
            out[i] = 97 + (c - 97 + 1) % 26
        elif 65 <= c <= 90:
            out[i] = 65 + (c - 65 + 1) % 26
    return bytes(out)


def son_bilesen_araligi(ad: str) -> tuple[int, int] | None:
    """Adın son bileşeninin (köşeli ayraç dışındaki son noktadan sonrası) bayt aralığı; yoksa None."""
    d = 0
    son_nokta = -1
    for i, c in enumerate(ad):
        if c == "[":
            d += 1
        elif c == "]":
            d -= 1
        elif c == "." and d == 0:
            son_nokta = i
    if son_nokta < 0:
        return None
    kuyruk = ad[son_nokta + 1:]
    kes = kuyruk.find("[")
    if kes >= 0:
        kuyruk = kuyruk[:kes]
    if kuyruk.endswith("-fm"):
        kuyruk = kuyruk[:-3]
    if not any(c.isascii() and c.isalpha() for c in kuyruk):
        return None
    bas = len(ad[:son_nokta + 1].encode())
    return bas, bas + len(kuyruk.encode())


def k4_arastirma(p: GoPclntab, fs: list) -> set[int]:
    """Araştırma betiğinin K4 kuralı (birleştirici dili ayrımı yok): yalnız başvuruyla karşılaştırma."""
    hiza = 0
    for f in fs:
        hiza = math.gcd(hiza, f.giris - fs[0].giris)
    out = set()
    for f in fs:
        if f.pcsp == 0:
            continue
        try:
            tb = p.pc_tablosu(f.pcsp, f.giris)
        except Exception:  # noqa: BLE001
            out.add(f.giris)
            continue
        son = tb[-1][2] if tb else f.giris
        if son == f.bitis or (son < f.bitis and f.bitis - son < hiza):
            continue
        out.add(f.giris)
    return out


def t2p_arastirma(g: Any, p: GoPclntab, fs: list, bi: dict) -> set[int]:
    """Araştırmanın T2p'si: yöntem girdisinin adresindeki adın ``paket_adi``'si tipin paket yolu değil."""
    es = {f.giris: f for f in fs}
    tip = GoTipVerisi(g, p, bi.get("surum"))
    if not tip.calisti:
        return set()
    out = set()
    for t in tip.ulasilan_tipler(tip.itablar()):
        u = tip.uncommon(t)
        if not u or not u.paket:
            continue
        for y in u.yontemler:
            for adr in (y.ifn, y.tfn):
                f = es.get(adr) if adr is not None else None
                if f is not None and y.ad is not None and TU.kacis_coz(paket_adi(f.ad)) != u.paket:
                    out.add(adr)
    return out


def wilson(k: int, n: int, z: float = 1.959963984540054) -> tuple[float, float] | None:
    if n <= 0:
        return None
    ph = k / n
    pay = ph + z * z / (2 * n)
    sap = z * math.sqrt(ph * (1 - ph) / n + z * z / (4 * n * n))
    payda = 1 + z * z / n
    return (pay - sap) / payda, (pay + sap) / payda


# ---------------------------------------------------------------------------
# Durum (bir görüntünün bütün denetimleri)
# ---------------------------------------------------------------------------


class Durum:
    def __init__(self, veri: bytes, kaynak: str, k10: bool = False) -> None:
        self.g = GR.baytlardan(veri, kaynak=kaynak)
        self.p = GoPclntab(self.g)
        self.fs = self.p.fonksiyonlar()
        self.butunluk = butunluk_denetle(self.p, self.fs)
        self.bi = buildinfo_oku(self.g) or {}
        self.s = TU.denetle(self.g, self.p, self.fs, self.bi, self.butunluk)
        if self.s.durum != GR.DURUM_CALISTI:
            raise RuntimeError(f"denetim {self.s.durum}: {self.s.neden}")
        self.isaret = self.s.isaretler
        self.kapsam = self.s.kapsam
        self.k4_arastirma = k4_arastirma(self.p, self.fs)
        self.k4_urun = {f.giris for f in self.fs if f.pcsp_kapsama in TU.K4_UYUMSUZ}
        self.k10 = k10_isaretleri(self.g, self.p, self.fs)[0] if k10 else set()
        self.t2p_arastirma = t2p_arastirma(self.g, self.p, self.fs, self.bi)

    def isaret_arastirma(self, e: int) -> set[str]:
        """Araştırmanın güçlü işaretleri (T3 dahil; T2p araştırmanın ``paket_adi`` eşitliğiyle)."""
        s = set(self.isaret.get(e, frozenset()) & ARASTIRMA_GUCLU_T2P_SIZ)
        if e in self.t2p_arastirma:
            s.add("T2p")
        return s

    def guclu_arastirma(self, e: int) -> bool:
        return bool(self.isaret_arastirma(e))

    def tutarsiz(self, e: int) -> bool:
        return self.s.damga(e) == TU.DAMGA_TUTARSIZ


def olc(taban: Durum, veri: bytearray, hedefler: set[int], kaynak: str, k10: bool = False) -> dict[str, Any]:
    """Bozulmuş kopyayı denetle; bozulan fonksiyonların kaçı yakalandı (iki sütun)."""
    try:
        d = Durum(bytes(veri), kaynak, k10=k10)
    except Exception as exc:  # noqa: BLE001
        return {"okuyucu_hatasi": f"{type(exc).__name__}: {exc}"[:200], "bozulan": len(hedefler)}
    ikinci = taban.kapsam.get("T1", set()) | taban.kapsam.get("T2", set()) | taban.kapsam.get("T5", set())
    yak = {e for e in hedefler if d.guclu_arastirma(e) and not taban.guclu_arastirma(e)}
    yak_t4 = {e for e in hedefler if "T4" in d.isaret.get(e, ()) and "T4" not in taban.isaret.get(e, ())}
    yak_k4 = {e for e in hedefler if e in d.k4_arastirma and e not in taban.k4_arastirma}
    urun = {e for e in hedefler if d.tutarsiz(e) and not taban.tutarsiz(e)}
    urun_k4 = {e for e in hedefler if e in d.k4_urun and e not in taban.k4_urun}
    urun_guclu = {e for e in hedefler
                  if d.isaret.get(e, frozenset()) & TU.GUCLU_DENETIMLER
                  and not taban.isaret.get(e, frozenset()) & TU.GUCLU_DENETIMLER}
    r: dict[str, Any] = {
        "bozulan": len(hedefler),
        "ikinci_kaynakli_bozulan": len(hedefler & ikinci),
        "arastirma": {
            "guclu_denetim_yakaladi": len(yak),
            "ikinci_kaynaklida_yakalanan": len(yak & ikinci),
            "ikinci_kaynaksizda_yakalanan": len(yak - ikinci),
            "yalniz_T4_yakaladi": len(yak_t4 - yak),
            "K4_yakaladi": len(yak_k4),
            "hicbiri_yakalamadi": len(hedefler - yak - yak_t4 - yak_k4),
            "yakalayan_denetim": dict(collections.Counter(
                k for e in yak for k in d.isaret_arastirma(e) - taban.isaret_arastirma(e))),
            "bozulmayanda_yeni_guclu_isaret": sum(
                1 for f in d.fs if f.giris not in hedefler and d.guclu_arastirma(f.giris)
                and not taban.guclu_arastirma(f.giris)),
        },
        "urun": {
            "tutarsiz_damgasi_yakaladi": len(urun),
            "yakalama_wilson": wilson(len(urun), len(hedefler)),
            "guclu_T_yakaladi": len(urun_guclu),
            "K4_pcsp_kapsama_yakaladi": len(urun_k4),
            "ikinci_kaynaklida_yakalanan": len(urun & ikinci),
            "ikinci_kaynaksizda_yakalanan": len(urun - ikinci),
            "bozulmayanda_yeni_tutarsiz": sum(
                1 for f in d.fs if f.giris not in hedefler and d.tutarsiz(f.giris)
                and not taban.tutarsiz(f.giris)),
            "ikili_karari": d.s.karar,
            "karar_nedeni": d.s.karar_nedeni,
        },
    }
    if k10:
        yak_k10 = {e for e in hedefler if e in d.k10 and e not in taban.k10}
        r["K10"] = {
            "yakaladi": len(yak_k10),
            "urun_veya_K10_yakaladi": len(urun | yak_k10),
            "bozulmayanda_yeni_K10": sum(1 for f in d.fs if f.giris not in hedefler
                                         and f.giris in d.k10 and f.giris not in taban.k10),
        }
    return r


# ---------------------------------------------------------------------------
# Deney
# ---------------------------------------------------------------------------


def deney(path: str, k10: bool = False) -> dict[str, Any]:
    ham = Path(path).read_bytes()
    t0 = time.perf_counter()
    taban = Durum(ham, path, k10=k10)
    p, fs, g = taban.p, taban.fs, taban.g
    rng = random.Random(DUSMAN_DENEY_TOHUMU)
    sonuc: dict[str, Any] = {
        "ikili": path, "tohum": DUSMAN_DENEY_TOHUMU, "fonksiyon": len(fs),
        "taban": {k: taban.s.ozet[k] for k in ("T1", "T2", "T3", "T4", "T5", "isaret_dagilimi",
                                                "cift_kaynakli_fonksiyon", "damga")},
        "taban_guclu_isaretli_arastirma": sum(1 for f in fs if taban.guclu_arastirma(f.giris)),
        "taban_K4_arastirma": len(taban.k4_arastirma),
        "taban_K4_urun": len(taban.k4_urun),
    }
    if k10:
        sonuc["taban_K10"] = len(taban.k10)
    ad_kullanimi = collections.Counter(f.name_off for f in fs)
    pclntab_dosya = g.dosya_ofseti(p.adres)
    if pclntab_dosya is None:
        raise RuntimeError("pclntab dosyada yok")
    ad_ofs = pclntab_dosya + p.funcname_off
    pcln = pclntab_dosya + p.pcln_off

    def paket(f) -> str:
        return TU.kacis_coz(paket_adi(f.ad))

    uygun = [f for f in fs if f.ad and not taban.guclu_arastirma(f.giris)
             and paket(f) and not paket(f).startswith(("type:", "go:"))]

    # ---- A: son bileşeni yerinde değiştir ------------------------------
    adaylar = [f for f in uygun if ad_kullanimi[f.name_off] == 1 and son_bilesen_araligi(f.ad)]
    secilen = rng.sample(adaylar, N)
    veri = bytearray(ham)
    for f in secilen:
        a, b = son_bilesen_araligi(f.ad)
        o = ad_ofs + f.name_off
        veri[o + a:o + b] = kaydir(bytes(veri[o + a:o + b]))
    sonuc["A_son_bilesen"] = olc(taban, veri, {f.giris for f in secilen}, path)
    sonuc["A_son_bilesen"]["aday"] = len(adaylar)

    def takas(ciftler) -> bytearray:
        v = bytearray(ham)
        for f, h in ciftler:
            of = pcln + f.func_off + 4
            oh = pcln + h.func_off + 4
            v[of:of + 4], v[oh:oh + 4] = struct.pack("<i", h.name_off), struct.pack("<i", f.name_off)
        return v

    # ---- B: paketler arası takas ----------------------------------------
    ciftler = []
    kullanilan: set[int] = set()
    havuz = list(uygun)
    while len(ciftler) < N // 2:
        f, h = rng.sample(havuz, 2)
        if f.giris in kullanilan or h.giris in kullanilan or paket(f) == paket(h) or f.ad == h.ad:
            continue
        kullanilan |= {f.giris, h.giris}
        ciftler.append((f, h))
    sonuc["B_paketler_arasi_takas"] = olc(taban, takas(ciftler), kullanilan, path)

    # ---- C: paket içi takas ---------------------------------------------
    grup = collections.defaultdict(list)
    for f in uygun:
        grup[(f.cu_offset, paket(f))].append(f)
    gruplar = [x for x in grup.values() if len(x) >= 2]
    ciftler = []
    kullanilan = set()
    deneme = 0
    while len(ciftler) < N // 2 and deneme < 100000:
        deneme += 1
        f = rng.choice(havuz)
        g_l = grup[(f.cu_offset, paket(f))]
        if len(g_l) < 2:
            continue
        h = rng.choice(g_l)
        if h.giris == f.giris or f.giris in kullanilan or h.giris in kullanilan \
                or TU.son_bilesen(f.ad) == TU.son_bilesen(h.ad):
            continue
        kullanilan |= {f.giris, h.giris}
        ciftler.append((f, h))
    sonuc["C_paket_ici_takas"] = olc(taban, takas(ciftler), kullanilan, path)
    sonuc["C_paket_ici_takas"]["uygun_grup"] = len(gruplar)

    # ---- D: tutarlı sahtecilik (tip verisi + pclntab birlikte) ----------
    tip = GoTipVerisi(g, p, taban.bi.get("surum"))
    itablar = tip.itablar() if tip.calisti else []
    ad_ofseti: dict[str, set[int]] = {}
    for it in itablar:
        u = tip.uncommon(it.tip)
        pk = u.paket if u else None
        if not pk or "." not in pk.split("/", 1)[0]:
            continue  # standart kitaplık tipleri dışarıda: saldırganın kendi kodu modellenir
        for mad, off in it.yontemler:
            if mad and len(mad) >= 4 and mad.isascii() and mad.isalpha():
                ad_ofseti.setdefault(mad, set()).add(off)
    for t in tip.ulasilan_tipler(itablar) if tip.calisti else set():
        u = tip.uncommon(t)
        if not u:
            continue
        for y in u.yontemler:
            if y.ad in ad_ofseti:
                ad_ofseti[y.ad].add(y.ad_ofseti)
    secili_adlar = rng.sample(sorted(ad_ofseti), min(20, len(ad_ofseti)))
    veri = bytearray(ham)
    hedef: set[int] = set()
    yazilan: set[int] = set()
    for mad in secili_adlar:
        for off in ad_ofseti[mad]:
            r = tip.ad_ayrintili(tip.types + off)
            if r is None:
                continue
            _ad, adr, n = r
            fo = g.dosya_ofseti(adr)
            if fo is None or fo in yazilan:
                continue
            yazilan.add(fo)
            veri[fo:fo + n] = kaydir(bytes(veri[fo:fo + n]))
    for f in fs:
        if f.ad and TU.son_bilesen(f.ad) in secili_adlar:
            ar = son_bilesen_araligi(f.ad)
            if not ar:
                continue
            o = ad_ofs + f.name_off
            if o not in yazilan:
                yazilan.add(o)
                veri[o + ar[0]:o + ar[1]] = kaydir(bytes(ham[o + ar[0]:o + ar[1]]))
            hedef.add(f.giris)
    sonuc["D_tutarli_sahtecilik"] = olc(taban, veri, hedef, path)
    sonuc["D_tutarli_sahtecilik"]["degistirilen_yontem_adi"] = len(secili_adlar)
    sonuc["D_tutarli_sahtecilik"]["aday_yontem_adi"] = len(ad_ofseti)

    # ---- E: yapısal — komşu _func kayıtlarını takas et ------------------
    veri = bytearray(ham)
    hedef = set()
    sira = list(range(1, len(fs) - 2))
    rng.shuffle(sira)
    alinan: set[int] = set()
    say = 0
    for i in sira:
        if say >= N // 2:
            break
        if i in alinan or i + 1 in alinan or i - 1 in alinan:
            continue
        f, h = fs[i], fs[i + 1]
        if not f.ad or not h.ad or f.pcsp == 0 or h.pcsp == 0:
            continue
        alinan |= {i, i + 1}
        # ftab'da funcoff takası; _func.entryOff yeni adrese uydurulur (çalışma zamanı denetimi geçsin diye)
        struct.pack_into("<I", veri, pcln + 8 * i + 4, h.func_off)
        struct.pack_into("<I", veri, pcln + 8 * (i + 1) + 4, f.func_off)
        struct.pack_into("<I", veri, pcln + h.func_off, f.giris - p.text)
        struct.pack_into("<I", veri, pcln + f.func_off, h.giris - p.text)
        hedef |= {f.giris, h.giris}
        say += 1
    sonuc["E_yapisal_takas"] = olc(taban, veri, hedef, path, k10=k10)
    sonuc["sure_sn"] = round(time.perf_counter() - t0, 1)
    return sonuc


# ---------------------------------------------------------------------------
# K10: pcsp ↔ giriş bölümündeki yığın ayarlaması (yalnız arm64)
# ---------------------------------------------------------------------------

_IMM = r"#(-?0x[0-9a-f]+|-?\d+)"
_RE_ON_INDEKS = re.compile(r"^(?:x30|x29, x30), \[sp, " + _IMM + r"\]!$")
_RE_SUB_SP = re.compile(r"^sp, sp, " + _IMM + r"(?:, lsl #(\d+))?$")
_RE_MOV_SP = re.compile(r"^sp, (x\d+)$")


def _sayi(s: str) -> int:
    return int(s, 16) if s.lstrip("-").startswith("0x") else int(s)


def k10_sinifla(g: Any, f: Any, tb: list, md: Any, genis: bool = True) -> tuple[str, int | None]:
    """Bir fonksiyonun K10 sonucu: (sınıf, komuttan okunan yığın ayarı)."""
    ilk = next(((v, a, b) for v, a, b in tb if v != 0), None)
    if ilk is None:
        return "cercevesiz", None
    deger, pc, _son = ilk
    b = g.oku(pc - 4, 4)
    if b is None or len(b) < 4:
        return "okunamadi", None
    ins = next(md.disasm(b, pc - 4, 1), None)
    if ins is None:
        return "taninmayan", None
    mn, op = ins.mnemonic, ins.op_str
    n = None
    if mn in ("str", "stp"):
        m = _RE_ON_INDEKS.match(op)
        if m:
            n = -_sayi(m.group(1))
    elif mn == "sub":
        m = _RE_SUB_SP.match(op)
        if m:
            n = _sayi(m.group(1)) << int(m.group(2) or 0)
    elif mn in ("mov", "add"):
        m = _RE_MOV_SP.match(op) if mn == "mov" else re.match(r"^sp, (x\d+), #0$", op)
        if m:
            n = _buyuk_cerceve(g, md, pc - 4, m.group(1), genis)
    if n is None:
        return "taninmayan", None
    return ("uyumlu" if n == deger else "uyumsuz"), n


def _buyuk_cerceve(g: Any, md: Any, mov_pc: int, reg: str, genis: bool) -> int | None:
    """``mov sp, xR``'den geriye (en çok 8 komut): xR = sp − N ise N.

    Ön kayıtlı kural (``genis`` yanlış): yalnız ``sub xR, sp, #N[, lsl #12]``. Genişletilmiş
    kural (keşif ikililerinde görülen Go kalıpları): ek olarak ``sub xR, xR, #b[, lsl #12]``
    parçaları ve ``mov xK, #N`` [+ ``movk xK, #M, lsl #s``] + ``sub xR, sp, xK``.
    """
    toplam = 0
    sabit: str | None = None
    parcalar = 0
    for geri in range(1, 9):
        bb = g.oku(mov_pc - 4 * geri, 4)
        if not bb:
            return None
        i2 = next(md.disasm(bb, mov_pc - 4 * geri, 1), None)
        if i2 is None:
            continue
        mn, op = i2.mnemonic, i2.op_str
        if sabit is None:
            m2 = re.match(rf"^{reg}, sp, " + _IMM + r"(?:, lsl #(\d+))?$", op)
            if mn == "sub" and m2:
                return toplam + (_sayi(m2.group(1)) << int(m2.group(2) or 0))
            if not genis:
                continue
            m3 = re.match(rf"^{reg}, {reg}, " + _IMM + r"(?:, lsl #(\d+))?$", op)
            if mn == "sub" and m3:
                toplam += _sayi(m3.group(1)) << int(m3.group(2) or 0)
                continue
            m4 = re.match(rf"^{reg}, sp, (x\d+)$", op)
            if mn == "sub" and m4:
                sabit = m4.group(1)
            continue
        m5 = re.match(rf"^{sabit}, " + _IMM + r"(?:, lsl #(\d+))?$", op)
        if mn == "movk" and m5:
            parcalar |= _sayi(m5.group(1)) << int(m5.group(2) or 0)
        elif mn == "mov" and m5:
            return toplam + (_sayi(m5.group(1)) | parcalar)
    return None


def k10_isaretleri(g: Any, p: GoPclntab, fs: list, genis: bool = True) -> tuple[set[int], dict[str, Any]]:
    """K10 ölçüsü. Döner: (uyumsuz / tanınmayan fonksiyon girişleri, sayım)."""
    if g.mimari != "arm64":
        return set(), {"durum": "desteklenmiyor", "neden": f"mimari {g.mimari}"}
    import capstone  # noqa: PLC0415 - yalnız bu ölçüde gerekli

    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    say: collections.Counter = collections.Counter()
    isaret: set[int] = set()
    ornek: dict[str, list] = collections.defaultdict(list)
    for f in fs:
        if f.pcsp == 0:
            say["pcsp_yok"] += 1
            continue
        if f.flag & FUNC_FLAG_ASM:
            say["asm"] += 1
            continue
        try:
            tb = p.pc_tablosu(f.pcsp, f.giris)
        except Exception:  # noqa: BLE001
            say["tablo_okunamadi"] += 1
            isaret.add(f.giris)
            continue
        sinif, _n = k10_sinifla(g, f, tb, md, genis)
        say[sinif] += 1
        if sinif in ("uyumsuz", "taninmayan", "okunamadi"):
            isaret.add(f.giris)
            if len(ornek[sinif]) < 5:
                ornek[sinif].append(f.ad)
    bakilan = say["uyumlu"] + say["uyumsuz"] + say["taninmayan"] + say["okunamadi"]
    return isaret, {"durum": "calisti", "sayim": dict(say), "bakilan": bakilan,
                    "uyum_orani": say["uyumlu"] / bakilan if bakilan else None,
                    "uyum_wilson": wilson(say["uyumlu"], bakilan), "ornek_ad_sayisi": {
                        k: len(v) for k, v in ornek.items()}}


# ---------------------------------------------------------------------------
# Taban
# ---------------------------------------------------------------------------


def taban(path: str, dilim: str | None) -> dict[str, Any]:
    t0 = time.perf_counter()
    g = GR.ac(path, dilim)
    s = TU.denetle(g)
    oz = dict(s.ozet)
    sure = round(time.perf_counter() - t0, 2)
    t1 = oz.get("T1", {})
    t2 = oz.get("T2", {})
    return {
        "ikili": path, "dilim": dilim, "durum": s.durum, "neden": s.neden, "karar": s.karar,
        "karar_nedeni": s.karar_nedeni, "sure_sn": sure,
        "T1_uyum": (t1.get("uyan"), t1.get("bakilan_yuva")),
        "T2_uyum": (t2.get("uyan"), t2.get("bakilan")),
        "T2p_uyum": (t2.get("paket_uyan"), t2.get("paket_bakilan")),
        "ozet": oz,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    alt = ap.add_subparsers(dest="komut", required=True)
    a1 = alt.add_parser("taban")
    a1.add_argument("ikili")
    a1.add_argument("--dilim")
    a1.add_argument("--cikti")
    a2 = alt.add_parser("deney")
    a2.add_argument("ikili")
    a2.add_argument("--k10", action="store_true")
    a2.add_argument("--cikti")
    a3 = alt.add_parser("k10")
    a3.add_argument("ikili")
    a3.add_argument("--cikti")
    a = ap.parse_args(argv)
    if a.komut == "taban":
        r = taban(a.ikili, a.dilim)
    elif a.komut == "deney":
        r = deney(a.ikili, k10=a.k10)
    else:
        g = GR.ac(a.ikili)
        p = GoPclntab(g)
        fs = p.fonksiyonlar()
        i_on, r_on = k10_isaretleri(g, p, fs, genis=False)
        i_gen, r = k10_isaretleri(g, p, fs, genis=True)
        # ürün çözücüsüyle (bit maskesi) bağımsız karşılaştırma: aynı küme mi?
        u_ihlal, u_sayim = TU.k10_denetle(g, p, fs)
        r["ikili"] = a.ikili
        r["esik"] = K10_ESIGI
        r["on_kayitli_kural"] = r_on
        r["urun_cozucusu"] = {"sayim": u_sayim.get("sayim"), "ayni_kume": u_ihlal == i_gen}
        r["on_kayitli_ile_fark"] = len(i_on ^ i_gen)
    s = json.dumps(r, ensure_ascii=False, indent=1, default=str)
    if a.cikti:
        Path(a.cikti).write_text(s + "\n", encoding="utf-8")
    print(s if len(s) < 20000 else s[:20000])
    return 0


if __name__ == "__main__":
    sys.exit(main())
