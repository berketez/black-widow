#!/usr/bin/env python
"""KİMLİK hattı — çapalı yayılım prototipi (araştırma betiği; ürün kodu değil, öğrenme yok).

Sorgu Q (soyulmuş ikili) ile başvuru R (aynı kaynağın başka derlemesi) arasında fonksiyon eşlemesi:

  A. Çapalar
     - ad çapası: Q'da Ghidra'nın zaten bildiği ad (dinamik simge) R'de tek bir fonksiyonun adıysa;
     - tekil dizgi çapası: iki tarafta da yalnız BİR fonksiyonda geçen dizgi; oylar çelişmiyorsa.
  B. Yayılım: eşlenmemiş q için kanıt kümesi = dizgiler + içe aktarım çağrıları + P-code sabitleri +
     eşlenmiş çağrılanlar (↓) + eşlenmiş çağıranlar (↑). İsteğe bağlı (v2): tablo yuvası kanıtı —
     aynı kayıtta duran dizgi (t) ve eşlenmiş fonksiyon (k), göreli yuva farkıyla (``veri.yuva_komsulari``). Her kanıtın ağırlığı tekilliğiyle artar
     (1 / log2(1 + df); df = o kanıtı taşıyan EŞLENMEMİŞ fonksiyon sayısı). Puan = ağırlıklı Jaccard.
     Kapı: puan ≥ T, ortak kanıt kütlesi ≥ kutle, en iyi aday ikinciden ≥ marj ayrı, karşılıklı en iyi.
     Kapıdan geçenler eşlenir, df'ler yenilenir, yeni eşleşme kalmayana dek döner.
  C. Kapıda kalanlar için aday kümesi (ad ailesi çözümlemesi ``ikiz.py``'de).

Parametreler ``Param``'da; yalnız keşif çiftinde (htop) ayarlanır, ``DONUK``'ta dondurulur.
"""
from __future__ import annotations

import math
import re
import sys
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Iterable, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))
import veri  # noqa: E402
from veri import Fonk, Ikili, ks1  # noqa: E402

# ---- içe aktarım adı normalleştirmesi (htop çiftinde okundu) ----
_IMP_ON_EK = re.compile(r"^(?:isoc\d\d_)")
_IMP_SON_EK = re.compile(r"(?:_chk|\$[A-Z0-9_]+)$")
IMP_ES = {"errno_location": "errno", "error": "errno"}
# Derleyicinin kendi koyduğu / platforma özgü çalışma zamanı çağrıları: kanıt değil
IMP_GURULTU = {"stack_chk_fail", "stack_chk_guard", "ITM_deregisterTMCloneTable", "ITM_registerTMCloneTable",
               "cxa_finalize", "libc_start_main", "chkstk_darwin", "gmon_start__", "gmon_start", "cxa_atexit",
               "darwin_check_fd_set_overflow", "fdelt"}
# Derleyicinin birbirine çevirdiği yerleşikler (printf → puts, memset → bzero, strcpy → memcpy …): kanıt değil
IMP_OYNAK = {"printf", "puts", "putchar", "fprintf", "fputs", "fputc", "fwrite", "putc", "sprintf", "snprintf",
             "memcpy", "memmove", "memset", "bzero", "memset_pattern16", "memcmp", "bcmp", "memchr",
             "strlen", "strnlen", "strcpy", "stpcpy", "strncpy", "strcat", "strncat", "strchr", "strrchr",
             "strcmp", "strncmp", "strchrnul", "rawmemchr"}


def norm_imp(ad: str) -> Optional[str]:
    a = ad.lstrip("_")
    a = _IMP_SON_EK.sub("", a)
    a = _IMP_ON_EK.sub("", a)
    a = IMP_ES.get(a, a)
    if not a or a in IMP_GURULTU or a in IMP_OYNAK:
        return None
    return a


ADAY_LISTE = 12     # q başına tutulan en iyi aday sayısı (aile çözümlemesi en çok 8 üyeye bakar)


@dataclass(frozen=True)
class Param:
    dizgi_min: int = 4            # kanıt sayılan en kısa dizgi
    sabit_alt: int = 16           # kanıt sayılan en küçük P-code sabiti
    sabit_ust: int = 1 << 40      # adres benzeri büyük değerler dışarıda
    turler: tuple[str, ...] = ("d", "i", "s", "v", "^")   # d dizgi, i içe aktarım, s sabit, v çağrılan, ^ çağıran
    carpan: tuple[tuple[str, float], ...] = (("d", 1.0), ("i", 1.0), ("s", 0.5), ("v", 1.0), ("^", 1.0))
    T: float = 0.5                # puan eşiği (ağırlıklı Jaccard)
    marj: float = 0.15            # en iyi − ikinci
    kutle: float = 1.0            # ortak kanıtın ağırlık toplamı
    tur_ust: int = 40
    aday_df_ust: int = 40         # aday üretiminde kullanılan kanıtın en büyük df'i
    capa_dizgi: bool = True
    capa_ad: bool = True
    yayilim: bool = True
    komsu_sart: bool = False      # yayılımda en az bir eşlenmiş komşu kanıtı iste
    yuva_pencere: int = 8         # tablo yuvası kanıtında (t, k) komşuluk penceresi, yuva sayısı

    def c(self, tur: str) -> float:
        return dict(self.carpan).get(tur, 1.0)


def statik_kanit(f: Fonk, p: Param, I: Optional[Ikili] = None) -> set[tuple[str, Any]]:
    k: set[tuple[str, Any]] = set()
    if "t" in p.turler and I is not None:
        # tablo yuvası: aynı kayıtta duran dizgi, göreli yuva farkıyla
        for fark, tur, hedef in veri.yuva_komsulari(I).get(f.adres, ()):
            if tur == "d" and abs(fark) <= p.yuva_pencere and len(hedef) >= p.dizgi_min:
                k.add(("t", hedef, fark))
    if "d" in p.turler:
        k.update(("d", s) for s in f.dizgiler if len(s) >= p.dizgi_min)
    if "i" in p.turler:
        for i in f.iceaktarim:
            n = norm_imp(i)
            if n:
                k.add(("i", n))
    if "s" in p.turler:
        k.update(("s", c) for c in f.sabitler if p.sabit_alt <= c < p.sabit_ust)
    return k


@dataclass
class Esleme:
    q: int
    r: int
    asama: str        # "ad", "dizgi", "yayilim"
    tur: int
    puan: float
    ikinci: float
    kutle: float
    wq: float = 0.0   # q'nun kabul anındaki toplam kanıt kütlesi
    wr: float = 0.0   # r'nin kabul anındaki toplam kanıt kütlesi

    @property
    def denge(self) -> float:
        """Kanıt kütlesi dengesi min / max (1 = iki taraf eşit kanıtlı; küçükse biri öbürünü içeriyor olabilir)."""
        b = max(self.wq, self.wr)
        return min(self.wq, self.wr) / b if b > 0 else 1.0


@dataclass
class Sonuc:
    esler: dict[int, Esleme]                      # q → eşleme
    adaylar: dict[int, list[tuple[float, float, int]]] = field(default_factory=dict)   # kapıda kalan q → [(puan, kütle, r)]
    tur_sayisi: int = 0


def ad_capalari(Q: Ikili, R: Ikili) -> dict[int, int]:
    """Q'da Ghidra'nın bildiği ad R'de tek bir fonksiyonun GT adıysa çapa."""
    r_ad: dict[str, list[int]] = {}
    for a, f in R.fonk.items():
        for n in f.gt:
            r_ad.setdefault(n, []).append(a)
    out: dict[int, int] = {}
    alinan: set[int] = set()
    for a, f in sorted(Q.fonk.items()):
        if not f.bilinen:
            continue
        ad = ks1.platform_adi(f.ghidra_adi, Q.platform)
        c = r_ad.get(ad, [])
        if len(c) == 1 and c[0] not in alinan:
            out[a] = c[0]
            alinan.add(c[0])
    return out


def tekil_dizgi_capalari(Q: Ikili, R: Ikili, p: Param, haric_q: Iterable[int] = (),
                         haric_r: Iterable[int] = ()) -> dict[int, int]:
    """İki tarafta da yalnız bir fonksiyonda geçen dizgiler oy verir; oylar tek hedefte birleşiyorsa çapa."""
    hq, hr = set(haric_q), set(haric_r)

    def sahip(I: Ikili) -> dict[str, list[int]]:
        d: dict[str, list[int]] = {}
        for a, f in I.fonk.items():
            for s in f.dizgiler:
                if len(s) >= p.dizgi_min:
                    d.setdefault(s, []).append(a)
        return d

    sq, sr = sahip(Q), sahip(R)
    oy_q: dict[int, set[int]] = {}
    oy_r: dict[int, set[int]] = {}
    for s, qa in sq.items():
        ra = sr.get(s)
        if ra is None or len(qa) != 1 or len(ra) != 1:
            continue
        if qa[0] in hq or ra[0] in hr:
            continue
        oy_q.setdefault(qa[0], set()).add(ra[0])
        oy_r.setdefault(ra[0], set()).add(qa[0])
    return {q: next(iter(rs)) for q, rs in sorted(oy_q.items())
            if len(rs) == 1 and len(oy_r[next(iter(rs))]) == 1}


def esle(Q: Ikili, R: Ikili, p: Param) -> Sonuc:
    esler: dict[int, Esleme] = {}
    r_alinan: dict[int, int] = {}

    def ekle(q: int, r: int, asama: str, tur: int, puan: float = 1.0, ikinci: float = 0.0, kutle: float = 0.0,
             wq_: float = 0.0, wr_: float = 0.0):
        esler[q] = Esleme(q, r, asama, tur, puan, ikinci, kutle, wq_, wr_)
        r_alinan[r] = q

    if p.capa_ad:
        for q, r in ad_capalari(Q, R).items():
            ekle(q, r, "ad", 0)
    if p.capa_dizgi:
        # çapanın kanıt kütlesi dengesi için statik kanıt (bütün fonksiyonlar üstünde df)
        sq0 = {a: statik_kanit(f, p, Q) for a, f in Q.fonk.items()}
        sr0 = {a: statik_kanit(f, p, R) for a, f in R.fonk.items()}
        dq0: dict[tuple, int] = {}
        dr0: dict[tuple, int] = {}
        for k0 in sq0.values():
            for x in k0:
                dq0[x] = dq0.get(x, 0) + 1
        for k0 in sr0.values():
            for x in k0:
                dr0[x] = dr0.get(x, 0) + 1
        for q, r in tekil_dizgi_capalari(Q, R, p, esler.keys(), r_alinan.keys()).items():
            ekle(q, r, "dizgi", 0,
                 wq_=math.fsum(p.c(x[0]) / math.log2(1 + dq0[x]) for x in sq0[q]),
                 wr_=math.fsum(p.c(x[0]) / math.log2(1 + dr0[x]) for x in sr0[r]))
    sonuc = Sonuc(esler)
    if not p.yayilim:
        return sonuc

    sk_q = {a: statik_kanit(f, p, Q) for a, f in Q.fonk.items()}
    sk_r = {a: statik_kanit(f, p, R) for a, f in R.fonk.items()}
    yk_q = veri.yuva_komsulari(Q) if "k" in p.turler else {}
    yk_r = veri.yuva_komsulari(R) if "k" in p.turler else {}
    son_adaylar: dict[int, list[tuple[float, float, int]]] = {}

    for tur in range(1, p.tur_ust + 1):
        bos_q = [a for a in sorted(Q.fonk) if a not in esler]
        bos_r = [a for a in sorted(R.fonk) if a not in r_alinan]
        if not bos_q or not bos_r:
            break

        def kanit(I: Ikili, a: int, statik: dict, eslenen: dict[int, Any], kimlik, yk: dict) -> set:
            k = set(statik[a])
            f = I.fonk[a]
            for fark, tur_, hedef in yk.get(a, ()):
                # tablo yuvası: aynı kayıtta duran EŞLENMİŞ fonksiyon, göreli yuva farkıyla
                if tur_ == "f" and abs(fark) <= p.yuva_pencere and hedef in eslenen and hedef != a:
                    k.add(("k", kimlik(hedef), fark))
            if "v" in p.turler:
                k.update(("v", kimlik(c)) for c in f.cagrilan if c in eslenen)
            if "^" in p.turler:
                k.update(("^", kimlik(c)) for c in f.cagiran if c in eslenen)
            return k

        # komşu kimliği: eşlenmiş çiftin R adresi (iki tarafta aynı anahtar)
        kq = {a: kanit(Q, a, sk_q, esler, lambda c: esler[c].r, yk_q) for a in bos_q}
        kr = {a: kanit(R, a, sk_r, r_alinan, lambda c: c, yk_r) for a in bos_r}
        df_q: dict[tuple, int] = {}
        df_r: dict[tuple, int] = {}
        for k in kq.values():
            for x in k:
                df_q[x] = df_q.get(x, 0) + 1
        ters_r: dict[tuple, list[int]] = {}
        for a, k in kr.items():
            for x in k:
                df_r[x] = df_r.get(x, 0) + 1
                ters_r.setdefault(x, []).append(a)

        def w(x: tuple, df: int) -> float:
            return p.c(x[0]) / math.log2(1 + df)

        wq = {a: math.fsum(w(x, df_q[x]) for x in k) for a, k in kq.items()}
        wr = {a: math.fsum(w(x, df_r[x]) for x in k) for a, k in kr.items()}

        en_iyi_q: dict[int, list[tuple[float, float, int]]] = {}
        en_iyi_r: dict[int, list[tuple[float, int]]] = {}
        for a in bos_q:
            k = kq[a]
            if not k:
                continue
            ortak: dict[int, float] = {}
            komsulu: set[int] = set()
            for x in k:
                rs = ters_r.get(x)
                if not rs or len(rs) > p.aday_df_ust or df_q[x] > p.aday_df_ust:
                    continue
                agirlik = w(x, max(df_q[x], df_r[x]))
                for r in rs:
                    ortak[r] = ortak.get(r, 0.0) + agirlik
                    if x[0] in ("v", "^", "k"):
                        komsulu.add(r)
            if not ortak:
                continue
            liste = []
            for r, _ in ortak.items():
                if p.komsu_sart and r not in komsulu:
                    continue
                # tam ortak kütle (aday üretiminde atlanan yaygın kanıtlar dahil)
                kes = k & kr[r]
                m = math.fsum(w(x, max(df_q[x], df_r[x])) for x in kes)
                # toplamalar math.fsum ile: sonuç küme dolaşım sırasından (PYTHONHASHSEED) bağımsız
                birlesim = math.fsum([wq[a], wr[r], m,
                                      -math.fsum(w(x, df_q[x]) for x in kes),
                                      -math.fsum(w(x, df_r[x]) for x in kes)])
                puan = m / birlesim if birlesim > 0 else 0.0
                liste.append((puan, m, r))
            liste.sort(key=lambda t: (-t[0], -t[1], t[2]))
            if liste:
                en_iyi_q[a] = liste[:ADAY_LISTE]
                for puan, m, r in liste[:ADAY_LISTE]:
                    en_iyi_r.setdefault(r, []).append((puan, a))
        for r in en_iyi_r:
            en_iyi_r[r].sort(key=lambda t: (-t[0], t[1]))

        yeni = []
        for a, liste in en_iyi_q.items():
            puan, m, r = liste[0]
            ikinci = liste[1][0] if len(liste) > 1 else 0.0
            if puan < p.T or m < p.kutle or puan - ikinci < p.marj:
                continue
            geri = en_iyi_r[r]
            if geri[0][1] != a:
                continue
            if len(geri) > 1 and geri[0][0] - geri[1][0] < p.marj:
                continue
            yeni.append((a, r, puan, ikinci, m, wq[a], wr[r]))
        son_adaylar = en_iyi_q
        sonuc.tur_sayisi = tur
        if not yeni:
            break
        for a, r, puan, ikinci, m, wq_, wr_ in yeni:
            if a in esler or r in r_alinan:
                continue
            ekle(a, r, "yayilim", tur, puan, ikinci, m, wq_, wr_)

    sonuc.adaylar = {a: l for a, l in son_adaylar.items() if a not in esler}
    return sonuc


# ---------------------------------------------------------------------------------------------
# Hüküm


def hukum(Q: Ikili, R: Ikili, q: int, r: int) -> str:
    """dogru / yanlis / adsiz (R'de GT adı yok) / hukumsuz (Q'da GT yok)."""
    fq, fr = Q.fonk[q], R.fonk[r]
    if not fq.gt:
        return "hukumsuz"
    if not fr.gt:
        return "adsiz"
    return "dogru" if set(fq.gt) & set(fr.gt) else "yanlis"


def olc(Q: Ikili, R: Ikili, esler: dict[int, Esleme], asamalar: Optional[set[str]] = None) -> dict[str, Any]:
    """Nüfus içi kesinlik (Wilson) ve kapsam; aşama süzgeci verilebilir."""
    nufus = set(Q.nufus)
    r_adlar = {n for f in R.fonk.values() for n in f.gt}
    tavan = sum(1 for a in nufus if set(Q.fonk[a].gt) & r_adlar)
    say = {"dogru": 0, "yanlis": 0, "adsiz": 0, "hukumsuz": 0}
    for q, e in esler.items():
        if q not in nufus:
            continue
        if asamalar is not None and e.asama not in asamalar:
            continue
        say[hukum(Q, R, q, e.r)] += 1
    n = say["dogru"] + say["yanlis"]
    return {"nufus": len(nufus), "tavan": tavan, **say,
            "kesinlik": ks1.oran(say["dogru"], n),
            "kapsam": ks1.oran(say["dogru"], len(nufus)),
            "kapsam_tavan": ks1.oran(say["dogru"], tavan)}


def kisa(o: dict[str, Any]) -> str:
    k = o["kesinlik"]
    alt = k["aralik"][0] if k["aralik"] else float("nan")
    return (f"doğru {o['dogru']:5d} yanlış {o['yanlis']:4d} adsız {o['adsiz']:3d} | kesinlik "
            f"{(k['oran'] or 0):.3f} (Wilson alt {alt:.3f}) | kapsam {o['dogru']}/{o['nufus']} = "
            f"{(o['kapsam']['oran'] or 0) * 100:.1f}% (tavanın {(o['kapsam_tavan']['oran'] or 0) * 100:.1f}%'i)")


# Dondurulmuş parametreler: yalnız htop çiftinde ayarlandı (DEFTER.md §5.3; ızgara ``ayar.py``,
# çıktı ``ayar_htop_1.json``). Sınama birimlerinde değişmez.
#   DONUK        — birincil ("kural" noktası): ızgarada Wilson alt ≥ 0,95 olanlar içinde en yüksek kapsam.
#   DONUK_TUTUCU — ikincil: ortak kanıt kütlesi ≥ 1,0 kolunda en yüksek kapsam (htop yanlışlarının çoğu
#                  kütlesi < 1,0 olan eşlemelerdi).
_ESIT_CARPAN = (("d", 1.0), ("i", 1.0), ("s", 1.0), ("v", 1.0), ("^", 1.0))
DONUK = Param(T=0.3, marj=0.1, kutle=0.5, carpan=_ESIT_CARPAN)
DONUK_TUTUCU = Param(T=0.3, marj=0.1, kutle=1.0, carpan=_ESIT_CARPAN)
# v2: v1 + tablo yuvası kanıtı (t: kayıttaki dizgi, k: kayıttaki eşlenmiş fonksiyon). Pencere ve çarpanlar
# yalnız htop'ta ayarlandı (DEFTER.md §5.8; aynı seçim kuralı). tmux / coreutils çiftlerinde v2 sayıları
# "ikinci bakış"tır (v1 sonuçları görüldükten sonra tasarlandı), ön kayıtlı sınama değildir.
_V2_TURLER = ("d", "i", "s", "v", "^", "t", "k")
_V2_CARPAN = _ESIT_CARPAN + (("t", 0.5), ("k", 1.0))
DONUK_V2 = Param(T=0.3, marj=0.1, kutle=0.5, carpan=_V2_CARPAN, turler=_V2_TURLER, yuva_pencere=8)
DONUK_V2_TUTUCU = Param(T=0.3, marj=0.1, kutle=1.0, carpan=_V2_CARPAN, turler=_V2_TURLER, yuva_pencere=8)
NOKTALAR = {"kural": DONUK, "tutucu": DONUK_TUTUCU, "kural_v2": DONUK_V2, "tutucu_v2": DONUK_V2_TUTUCU}
