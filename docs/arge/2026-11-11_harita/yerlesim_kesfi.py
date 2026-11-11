#!/usr/bin/env python3
"""Yerleşim keşfi: adres sırasına dayalı bölme seçeneklerinin ÇEVRİMDIŞI, ÖN KAYITSIZ keşfi.

Bu betik bir tasarım girdisi üretir; ürün iddiası üretmez. Geliştirme setinde koşar, seçenekler bu
sette denenmiştir; sayılar "geliştirme setinde keşif" olarak okunur.

Veri
----
- Nüfus, ürün modülü ve GT sınıf kodları: ön kayıtlı ölçümün çıktısı ``harita_olcumu.json``
  (``birimler/<birim>/elfler/<ikili>/ogeler``: adres → "modül_no dosya_kodu dizin_kodu"; ad yok).
  GT yalnız değerlendirmede kullanılır.
- GT'siz sinyaller: ölçülen koşunun çalışma alanı (``static/ghidra_functions.json``: adres, boyut,
  thunk; ``static/ghidra_call_graph.json``: çağrı kenarları). Salt okunur.
- Ölçüler, B1 bölmesi, toplama kuralı ve sabitler ``scripts/measurement/harita_olc.py``'den içe
  aktarılır (betik değişmez).

Seçenekler (hepsi adres sırasındaki evren üzerinde çalışır: hedefsiz thunk olmayan Ghidra
fonksiyonları, ``elf_sinyalleri``; sonra etiketler ölçüm nüfusuna indirgenip değerlendirilir)
----------
- ``s1``: eşit, bitişik parça; parça sayısı ürünün modül sayısından bağımsız (``⌈√N⌉`` ya da sabit
  ortalama parça boyu).
- ``s2``: sınır, ardışık iki fonksiyon arasındaki dolgu (boşluk) eşiği geçtiğinde. Ek kısıt
  (``hiza``): parça yalnız adresi ``HIZA``'nın katı olan fonksiyonda başlayabilir.
- ``s3b`` / ``s4b`` / ``s3c`` / ``s4c`` / ``s3d`` / ``s3e``: ``s2``'nin kesin sınırları (ve hizalama
  kısıtı) içinde çağrı grafıyla ikinci aşama.
- ``s3``: bitişik modülerlik dilimlemesi: adres sırasındaki dizinin bitişik dilimlere bölünmesi,
  çağrı grafının modülerliği dinamik programlamayla en büyüklenir (parça sayısı çıktıdır).
- ``s4``: ``s3`` + statik ipucu: kenar ağırlığı 1 / (çağrılanın farklı çağıran sayısı).
- ``s5``: LTO göstergeleri (çağrı uzaklığı, en iyi bitişik modülerlik) ve bitişik olmayan dilimlerin
  modülerlik kazancıyla açgözlü birleştirilmesi.
- ``tavan`` (yöntem DEĞİL; GT kullanır): GT sınıfının her değişiminde kesen bitişik bölme; bitişik
  bir yöntemin ulaşabileceği üst sınır.

Kullanım
--------
    python docs/arge/2026-11-11_harita/yerlesim_kesfi.py \\
        --debian-kosu ~/karadul_olcum/runs/urun-yeni-93a2956/debian \\
        --olcum docs/arge/2026-11-11_harita/harita_olcumu.json \\
        --json docs/arge/2026-11-11_harita/yerlesim_kesfi.json [--gt-sagla tree htop]
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import math
import sys
from collections import Counter, defaultdict
from fractions import Fraction
from pathlib import Path
from types import ModuleType
from typing import Any, Callable, Optional, Sequence

import numpy as np

SEMA = "karadul-yerlesim-kesfi/1"
REPO = Path(__file__).resolve().parents[3]
HARITA_YOLU = REPO / "scripts" / "measurement" / "harita_olc.py"


def _harita_yukle() -> ModuleType:
    """``harita_olc.py``'yi dosya yolundan yükle (ön kayıtla sabit dosya; içe aktarılır, değişmez)."""
    spec = importlib.util.spec_from_file_location("harita_olc", HARITA_YOLU)
    modul = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = modul
    spec.loader.exec_module(modul)
    return modul


h = _harita_yukle()
ks1 = h.ks1

DUZEY = h.KARAR_DUZEYI                # dosya
OLCULER = ("ari", "kesinlik", "duyarlilik")
SAGLAMA_HANE = ks1.ONDALIK            # B1 sağlaması: ölçüm JSON'undaki yuvarlamayla aynı hane

# ---- Keşif ızgaraları (hiçbiri ürün sabiti değildir; duyarlılık eğrisi için) ----
S1_PARCA_BOYLARI = (2, 3, 4, 6, 8, 12, 16, 24, 32, 48)      # sabit ortalama parça boyu (fonksiyon)
S2_ESIKLER = (1, 4, 8, 12, 16, 20, 24, 28, 32, 64)          # dolgu eşiği (bayt)
GAMALAR = (Fraction(1, 4), Fraction(1, 2), Fraction(1), Fraction(2), Fraction(4), Fraction(8),
           Fraction(16), Fraction(32))                      # modülerlik çözünürlüğü; 1 = ayarsız tanım
GAMA_AYARSIZ = Fraction(1)
S2_SECILEN_ESIK = 16                  # BU SETTE ızgaradan seçildi (aşırı uyum riski; belgeye bak)
BIRLESIK_GAMALAR = (Fraction(1, 8), Fraction(1, 4), Fraction(1, 2), Fraction(1), Fraction(2),
                    Fraction(4))    # s2 kesin sınırı + dilimleme
HIZA = 32                             # BU SETTE gözlemden seçildi: dosya başı adresi 32'nin katı
YOGUNLUK_ESIGI = 0.018                # BU SETTE seçildi (tek LTO programı; yoğunluğun tanımı değişince
                                      # 0,015'ten taşındı): s5 kapısı. Aralık dar: belgeye bak
DOLGU_KUTULARI = ((0, 0), (1, 11), (12, 15), (16, 31), (32, None))   # bayt; (alt, üst) kapalı
RASTGELE_UZAKLIK = Fraction(1, 3)     # rastgele sırada iki fonksiyonun beklenen |sıra farkı| / N


# --------------------------------------------------------------------------------------------
# GT'siz sinyaller


def elf_sinyalleri(static: Path) -> dict[str, Any]:
    """Yöntemlerin evreni: programın kendi fonksiyonları (adres sırasında), boyutları, çağrı kenarları.

    Evren (GT'siz kural): Ghidra fonksiyonlarından hedefsiz thunk olmayanlar (hedefsiz thunk: çağrı
    grafında Ghidra fonksiyonu olan hiçbir hedefi yok; dış fonksiyon yer tutucuları ve saplamalar).
    Kitaplık geçidi = bütün hedefleri dış yer tutucusu olan thunk (PLT girişleri ve dış fonksiyona
    atlayan sarmalayıcılar); dış yer tutucusu = hedefsiz thunk ve adresi thunk olmayan son fonksiyonun
    adresinden büyük (Ghidra'nın ``EXTERNAL`` bloğu). Kitaplık geçitleri evrende kalır (PLT girişi ile
    metin içi sarmalayıcı GT'siz ayrılamadı; bir kısmı ölçüm nüfusundadır) ama ``kitaplik`` ile
    işaretlenir: uçlarından biri kitaplık geçidi olan kenar atılır (kitaplık çağrıları derleme
    birimi bilgisi taşımaz sayılır) ve sayıya dayalı kurallar (s1, yoğunluk) onları saymaz.
    Kenarlar sıra numarasıyla, yönlü ve tekil (çağıran, çağrılan); kendine çağrı atılır.
    """
    fonk = h._json(Path(static) / "ghidra_functions.json")["functions"]
    kenarlar = [(int(k["from"], 16), int(k["to"], 16))
                for k in h._json(Path(static) / "ghidra_call_graph.json")["edges"]]
    hepsi = {int(f["address"], 16) for f in fonk}
    thunk = {int(f["address"], 16) for f in fonk if f["is_thunk"]}
    hedefler: dict[int, set[int]] = defaultdict(set)
    for u, v in kenarlar:
        if v in hepsi and v != u:
            hedefler[u].add(v)
    son_ic = max(hepsi - thunk)
    yer_tutucu = {a for a in thunk if not hedefler.get(a) and a > son_ic}
    gecit = {a for a in thunk if hedefler.get(a) and hedefler[a] <= yer_tutucu}
    ic = sorted({int(f["address"], 16): int(f["size"]) for f in fonk
                 if not f["is_thunk"] or hedefler.get(int(f["address"], 16))}.items())
    adres = [a for a, _ in ic]
    sira = {a: i for i, a in enumerate(adres)}
    yonlu = set()
    for a, b in kenarlar:
        u, v = sira.get(a), sira.get(b)
        if u is not None and v is not None and u != v and a not in gecit and b not in gecit:
            yonlu.add((u, v))
    return {"adres": adres, "boyut": [b for _, b in ic], "sira": sira, "yonlu": sorted(yonlu),
            "kitaplik": [a in gecit for a in adres], "dis_thunk": len(hepsi) - len(adres)}


def cekirdege_yay(kitaplik: Sequence[bool], bolme: Callable[[int], list[int]]) -> list[int]:
    """Sayıya dayalı bir bölmeyi yalnız kitaplık geçidi olmayan fonksiyonlara uygula; kitaplık geçidi
    kendinden önceki çekirdek fonksiyonun parçasını alır (önünde yoksa ilk parçayı)."""
    cekirdek = bolme(sum(1 for k in kitaplik if not k))
    out, i, son = [], 0, 0
    for k in kitaplik:
        if not k:
            son = cekirdek[i]
            i += 1
        out.append(son)
    return out


def agirliklar(yonlu: Sequence[tuple[int, int]], statik: bool) -> dict[tuple[int, int], float]:
    """Yönsüz kenar ağırlıkları (küçük sıra, büyük sıra) → ağırlık.

    ``statik`` değilse her yönlü kenar 1; ``statik`` ise 1 / (çağrılanın farklı çağıran sayısı):
    tek yerden çağrılan fonksiyon büyük olasılıkla çağıranının dosyasındaki ``static`` fonksiyondur,
    çok yerden çağrılan ortak yardımcıdır.
    """
    giren = Counter(v for _, v in yonlu)
    w: dict[tuple[int, int], float] = defaultdict(float)
    for u, v in yonlu:
        w[(u, v) if u < v else (v, u)] += (1.0 / giren[v]) if statik else 1.0
    return dict(w)


# --------------------------------------------------------------------------------------------
# Bölmeler (GT'siz; dönen: adres sırasındaki her fonksiyonun parça numarası)


def s1_karekok(n: int) -> list[int]:
    return h.b1_bolme(n, min(max(math.isqrt(n - 1) + 1, 1), n)) if n else []


def s1_sabit_boy(n: int, boy: int) -> list[int]:
    return h.b1_bolme(n, min(max(round(n / boy), 1), n)) if n else []


def s2_dolgu(adres: Sequence[int], boyut: Sequence[int], esik: int) -> list[int]:
    """Ardışık iki fonksiyon arasındaki dolgu ``esik`` baytı bulduğunda yeni parça başlar."""
    out, parca = [], 0
    for i, a in enumerate(adres):
        if i and a - (adres[i - 1] + boyut[i - 1]) >= esik:
            parca += 1
        out.append(parca)
    return out


def s2_hizali(adres: Sequence[int], hiza: int) -> list[int]:
    """Adresi ``hiza``'nın katı olan her fonksiyonda yeni parça başlar (aşırı bölmenin üst ucu)."""
    out, parca = [], 0
    for i, a in enumerate(adres):
        if i and a % hiza == 0:
            parca += 1
        out.append(parca)
    return out


def sifir_gecisli(kesin: Sequence[int], izin: Sequence[bool], yonlu: Sequence[tuple[int, int]],
                  bagli: bool) -> list[int]:
    """Kesin parçaların içinde, hiçbir parça içi çağrı kenarının aşmadığı izinli sıralardan kes.

    ``kesin``: kesin sınırlarla (dolgu) bulunan parça numaraları. Bir parçanın içinde ``p`` sırası
    kesim adayıdır: ``izin[p]`` ve parçanın içindeki hiçbir kenar ``p``'yi aşmıyor (solu ile sağı
    arasında çağrı yok). ``bagli`` ise, parça içi kenarı olmayan (kanıt taşımayan) blok ayrı parça
    olmaz: soldaki bloğa katılır; parçanın başındaki kanıtsız bloklar ilk kanıtlı bloğa katılır.
    Ayarlanabilir parametre yok.
    """
    n = len(kesin)
    fark = [0] * (n + 1)              # asan[p] = p sırasını aşan parça içi kenar sayısı (u < p ≤ v)
    uclu = [False] * n                # parça içi kenarı olan fonksiyon
    for u, v in yonlu:
        if kesin[u] != kesin[v]:
            continue
        a, b = (u, v) if u < v else (v, u)
        fark[a + 1] += 1
        fark[b + 1] -= 1
        uclu[u] = uclu[v] = True
    out, parca, asan = [0] * n, 0, 0
    bloklar: list[tuple[int, int, int]] = []     # (kesin parça, baş, son)
    bas = 0
    for p in range(1, n + 1):
        asan += fark[p] if p <= n else 0
        if p == n or kesin[p] != kesin[p - 1] or (izin[p] and asan == 0):
            bloklar.append((kesin[bas], bas, p))
            bas = p
    onceki_k: Optional[int] = None
    kanit = False                      # bu kesin parçada kanıtlı blok görüldü mü
    for no, (k, a, b) in enumerate(bloklar):
        kanitli = any(uclu[a:b])
        if k != onceki_k:              # yeni kesin parça
            parca += int(no > 0)
            kanit, onceki_k = kanitli, k
        elif not bagli or (kanitli and kanit):
            parca += 1                 # yeni parça: önünde kanıtlı blok var ve bu blok da kanıtlı
        else:
            kanit = kanit or kanitli   # kanıtsız blok soldakine; baştaki kanıtsızlar ilk kanıtlıya katılır
        for i in range(a, b):
            out[i] = parca
    return out


def moduler_dilimle(n: int, w: dict[tuple[int, int], float], gama: Fraction = GAMA_AYARSIZ,
                    zorunlu: Optional[Sequence[int]] = None,
                    izinli: Optional[Sequence[bool]] = None) -> tuple[list[int], float]:
    """Bitişik modülerlik dilimlemesi (dinamik programlama, kesin en iyi).

    Dizi bitişik dilimlere bölünür; amaç Σ_dilim [ iç ağırlık / m − γ · (derece toplamı / 2m)² ]
    (Newman-Girvan modülerliği; γ = 1 ayarsız tanım). ``en_iyi[j] = max_i en_iyi[i] + q(i, j)``.
    Eşitlikte en küçük ``i`` (en uzun son dilim) seçilir: yalıtık fonksiyon öncekine katılır.
    ``zorunlu``: mutlaka dilim başı olacak sıra numaraları (kesin sınırlar); hiçbir dilim bunları
    aşamaz. ``izinli``: verilirse dilim yalnız izinli sıralarda başlayabilir (0 ve zorunlu sınırlar
    her zaman izinli). Dönen: (parça numaraları, modülerlik).
    """
    if n == 0:
        return [], 0.0
    m = sum(w.values())
    # alt[j]: j'de biten dilimin başlayabileceği en küçük sıra (j'den küçük en büyük zorunlu sınır)
    alt = [0] * (n + 1)
    isaret = set(zorunlu or ())
    son = 0
    for j in range(1, n + 1):
        if (j - 1) in isaret:
            son = j - 1
        alt[j] = son
    if m <= 0:
        return [alt[k + 1] for k in range(n)], 0.0
    yasak = None
    if izinli is not None:
        yasak = ~np.asarray(izinli, dtype=bool)
        yasak[0] = False
        for p in isaret:
            yasak[p] = False
    g = float(gama)
    derece = np.zeros(n)
    onceki: list[list[tuple[int, float]]] = [[] for _ in range(n)]
    for (a, b), x in w.items():
        derece[a] += x
        derece[b] += x
        onceki[b].append((a, x))
    onek = np.concatenate(([0.0], np.cumsum(derece)))
    en_iyi = np.zeros(n + 1)
    geri = np.zeros(n + 1, dtype=np.int64)
    ic = np.zeros(n + 1)              # ic[i] = [i, j) diliminin iç ağırlığı (o anki j için)
    for j in range(1, n + 1):
        dugum = j - 1
        if onceki[dugum]:
            c = np.zeros(j)
            for p, x in onceki[dugum]:
                c[p] += x
            ic[:j] += np.cumsum(c[::-1])[::-1]
        d = (onek[j] - onek[:j]) / (2.0 * m)
        aday = en_iyi[:j] + ic[:j] / m - g * d * d
        if yasak is not None:
            aday = np.where(yasak[:j], -np.inf, aday)
        i = alt[j] + int(np.argmax(aday[alt[j]:]))
        en_iyi[j], geri[j] = aday[i], i
    sinirlar, j = [], n
    while j > 0:
        sinirlar.append(int(geri[j]))
        j = int(geri[j])
    sinirlar.reverse()
    etiket = [0] * n
    for no, bas in enumerate(sinirlar):
        son = sinirlar[no + 1] if no + 1 < len(sinirlar) else n
        for k in range(bas, son):
            etiket[k] = no
    return etiket, float(en_iyi[n])


def birlestir(etiket: Sequence[int], w: dict[tuple[int, int], float], gama: Fraction = GAMA_AYARSIZ
              ) -> list[int]:
    """Dilimleri (bitişik olmasalar da) modülerlik kazancı pozitif oldukça açgözlü birleştir.

    Her adımda ΔQ = e_ab / m − γ · 2 · D_a · D_b / (2m)² en büyük olan çift birleşir; eşitlikte küçük
    numaralı çift. LTO'da bir kaynak dosyanın adres sırasında birkaç öbeğe dağılmasına karşılık.
    """
    m = sum(w.values())
    if m <= 0 or not etiket:
        return list(etiket)
    g = float(gama)
    derece: dict[int, float] = defaultdict(float)
    komsu: dict[int, dict[int, float]] = defaultdict(dict)
    for (a, b), x in w.items():
        sa, sb = etiket[a], etiket[b]
        derece[sa] += x
        derece[sb] += x
        if sa != sb:
            komsu[sa][sb] = komsu[sa].get(sb, 0.0) + x
            komsu[sb][sa] = komsu[sb].get(sa, 0.0) + x
    temsilci = {s: s for s in set(etiket)}
    while True:
        en: Optional[tuple[float, int, int]] = None
        for a in sorted(komsu):
            for b in sorted(komsu[a]):
                if b <= a:
                    continue
                dq = komsu[a][b] / m - g * 2.0 * derece[a] * derece[b] / (2.0 * m) ** 2
                if dq > 1e-12 and (en is None or dq > en[0]):
                    en = (dq, a, b)
        if en is None:
            break
        _, a, b = en
        for c, x in komsu.pop(b).items():
            del komsu[c][b]
            if c != a:
                komsu[a][c] = komsu[a].get(c, 0.0) + x
                komsu[c][a] = komsu[a][c]
        derece[a] += derece.pop(b)
        for s, t in temsilci.items():
            if t == b:
                temsilci[s] = a
    return [temsilci[s] for s in etiket]


def cagri_uzakligi(n: int, yonlu: Sequence[tuple[int, int]]) -> Optional[float]:
    """Çağrı kenarlarının ortalama |sıra farkı| / N (rastgele sırada beklenen 1/3; yerel yerleşimde 0'a yakın)."""
    if not yonlu or n < 2:
        return None
    return sum(abs(u - v) for u, v in yonlu) / (len(yonlu) * n)


# --------------------------------------------------------------------------------------------
# Değerlendirme (GT yalnız burada)


def ogeleri_ac(elf: dict[str, Any]) -> tuple[list[int], list[int], list[int]]:
    """Ölçüm JSON'undaki öğeler: (adresler, modül numaraları, dosya sınıf kodları), adres sırasında."""
    sirali = sorted((int(a, 16), v.split()) for a, v in elf["ogeler"].items())
    return [a for a, _ in sirali], [int(v[0]) for _, v in sirali], [int(v[1]) for _, v in sirali]


def tavan_bolmesi(siniflar: Sequence[int]) -> list[int]:
    """GT sınıfının her değişiminde kesen bitişik bölme (GT KULLANIR; yöntem değil, üst sınır)."""
    out, parca = [], 0
    for i, s in enumerate(siniflar):
        if i and s != siniflar[i - 1]:
            parca += 1
        out.append(parca)
    return out


def secenekler(sin: dict[str, Any]) -> tuple[dict[str, list[int]], dict[str, Any]]:
    """Bir ikilinin bütün GT'siz bölmeleri (ad → adres sırasındaki parça numaraları) ve göstergeleri."""
    n = len(sin["adres"])
    kit = sin["kitaplik"]
    n_cekirdek = sum(1 for k in kit if not k)
    out: dict[str, list[int]] = {"s1_karekok": cekirdege_yay(kit, s1_karekok)}
    for boy in S1_PARCA_BOYLARI:
        out[f"s1_boy{boy}"] = cekirdege_yay(kit, lambda m, boy=boy: s1_sabit_boy(m, boy))
    for esik in S2_ESIKLER:
        out[f"s2_dolgu{esik}"] = s2_dolgu(sin["adres"], sin["boyut"], esik)
    w3, w4 = agirliklar(sin["yonlu"], False), agirliklar(sin["yonlu"], True)
    q = {}
    for gama in GAMALAR:
        ad = f"g{float(gama):g}"
        out[f"s3_{ad}"], q3 = moduler_dilimle(n, w3, gama)
        out[f"s4_{ad}"], q4 = moduler_dilimle(n, w4, gama)
        if gama == GAMA_AYARSIZ:
            q = {"q_s3": q3, "q_s4": q4}
    out["s5_s3_birlesik"] = birlestir(out["s3_g1"], w3)
    out["s5_s4_birlesik"] = birlestir(out["s4_g1"], w4)
    # s2'nin seçilen eşiği kesin sınır; aralarında s3 / s4 dilimlemesi
    kesin = out[f"s2_dolgu{S2_SECILEN_ESIK}"]
    zorunlu = [i for i in range(1, n) if kesin[i] != kesin[i - 1]]
    for gama in BIRLESIK_GAMALAR:
        ad = f"g{float(gama):g}"
        out[f"s3b_dolgu{S2_SECILEN_ESIK}_{ad}"] = moduler_dilimle(n, w3, gama, zorunlu)[0]
        out[f"s4b_dolgu{S2_SECILEN_ESIK}_{ad}"] = moduler_dilimle(n, w4, gama, zorunlu)[0]
    # dilim yalnız adresi HIZA'nın katı olan fonksiyonda başlayabilir (+ kesin sınırlar)
    izin = [a % HIZA == 0 for a in sin["adres"]]
    out[f"s2_hiza{HIZA}"] = s2_hizali(sin["adres"], HIZA)
    for gama in BIRLESIK_GAMALAR:
        ad = f"g{float(gama):g}"
        out[f"s3c_hiza{HIZA}_{ad}"] = moduler_dilimle(n, w3, gama, zorunlu, izin)[0]
        out[f"s4c_hiza{HIZA}_{ad}"] = moduler_dilimle(n, w4, gama, zorunlu, izin)[0]
    # kesin parçaların içinde sıfır geçişli, izinli kesimler (parametresiz ikinci aşama)
    out["s3d_sifir_gecis"] = sifir_gecisli(kesin, izin, sin["yonlu"], False)
    out["s3e_sifir_gecis_bagli"] = sifir_gecisli(kesin, izin, sin["yonlu"], True)
    # s5 kapısı: kesin sınır yoğunluğu düşükse (nesne sınırı az: LTO ya da çok büyük dosyalar) adres
    # kısıtlarına güvenme, kısıtsız s4'e dön
    yogunluk = len(zorunlu) / n_cekirdek if n_cekirdek else 0.0
    yogun = yogunluk >= YOGUNLUK_ESIGI
    out["s5_kapili_g1"] = out[f"s4c_hiza{HIZA}_g1"] if yogun else out["s4_g1"]
    out["s5_kapili_g2"] = out[f"s4c_hiza{HIZA}_g1"] if yogun else out["s4_g2"]
    out["s5_kapili_s2_g1"] = kesin if yogun else out["s4_g1"]
    out["s5_kapili_s2_g2"] = kesin if yogun else out["s4_g2"]
    gosterge = {"n_evren": n, "kenar": len(sin["yonlu"]), "dis_thunk": sin["dis_thunk"],
                "kapi_adres": yogun,
                "cagri_uzakligi": cagri_uzakligi(n, sin["yonlu"]),
                "n_cekirdek": n_cekirdek, "kesin_sinir_yogunlugu": yogunluk,
                "hizali32": sum(1 for a in sin["adres"] if a % 32 == 0) / n if n else None,
                "hizali16": sum(1 for a in sin["adres"] if a % 16 == 0) / n if n else None, **q}
    return out, gosterge


def spearman(x: Sequence[float], y: Sequence[float]) -> Optional[float]:
    """Sıra korelasyonu (eşitlerde ortalama sıra)."""
    def sira(v: Sequence[float]) -> list[float]:
        idx = sorted(range(len(v)), key=lambda i: v[i])
        r = [0.0] * len(v)
        i = 0
        while i < len(idx):
            j = i
            while j + 1 < len(idx) and v[idx[j + 1]] == v[idx[i]]:
                j += 1
            for k in range(i, j + 1):
                r[idx[k]] = (i + j) / 2.0
            i = j + 1
        return r
    if len(x) < 3:
        return None
    rx, ry = sira(x), sira(y)
    mx, my = sum(rx) / len(rx), sum(ry) / len(ry)
    pay = sum((a - mx) * (b - my) for a, b in zip(rx, ry))
    payda = math.sqrt(sum((a - mx) ** 2 for a in rx) * sum((b - my) ** 2 for b in ry))
    return pay / payda if payda else None


def kos(debian_kosu: Path, olcum_yolu: Path) -> dict[str, Any]:
    olcum = h._json(olcum_yolu)
    elfler = {(ks1.birim_anahtari(e), e.ad): e
              for e in h.projesizleri_isaretle(ks1.elfleri_topla(None, debian_kosu))}
    # birim → ikili → satır → ölçü
    tablo: dict[str, dict[str, dict[str, dict[str, Any]]]] = {}
    parca: dict[str, dict[str, dict[str, int]]] = {}
    gostergeler: dict[str, dict[str, Any]] = {}
    evren_disi = 0
    dolgu_dokumu: dict[str, dict[str, list[int]]] = defaultdict(lambda: defaultdict(lambda: [0, 0]))
    hiza_dokumu: dict[str, dict[str, list[int]]] = defaultdict(lambda: defaultdict(lambda: [0, 0]))
    for birim, v in sorted(olcum["birimler"].items()):
        for ad, elf in sorted(v["elfler"].items()):
            d = elf["duzeyler"][DUZEY]
            if not d["giris"]:
                continue
            adresler, moduller, siniflar = ogeleri_ac(elf)
            n = len(adresler)
            if n != d["n"]:
                raise SystemExit(f"DURDU: {birim}/{ad}: öğe sayısı {n} ≠ ölçümdeki nüfus {d['n']}")
            e = elfler[(birim, ad)]
            sin = elf_sinyalleri(e.static)
            eksik = [a for a in adresler if a not in sin["sira"]]
            evren_disi += len(eksik)
            if eksik:
                raise SystemExit(f"DURDU: {birim}/{ad}: nüfustan {len(eksik)} adres evrende (hedefsiz "
                                 "thunk olmayan Ghidra fonksiyonları) yok")
            konum = [sin["sira"][a] for a in adresler]
            # dolgu ↔ GT sınıf değişimi (yalnız değerlendirme): evrende ardışık ve ikisi de nüfusta olan çiftler
            for i in range(1, n):
                if konum[i] != konum[i - 1] + 1:
                    continue
                k = konum[i]
                bosluk = sin["adres"][k] - (sin["adres"][k - 1] + sin["boyut"][k - 1])
                kutu = next((f"{a}-{u if u is not None else 'ust'}" for a, u in DOLGU_KUTULARI
                             if bosluk >= a and (u is None or bosluk <= u)), "negatif")
                degisti = int(siniflar[i] != siniflar[i - 1])
                dolgu_dokumu[ks1.birim_programi(birim)][kutu][degisti] += 1
                kalan = "kat" if sin["adres"][k] % HIZA == 0 else "kat_degil"
                hiza_dokumu[ks1.birim_programi(birim)][kalan][degisti] += 1
            satirlar: dict[str, dict[str, Any]] = {
                # sağlama: ön kayıtlı ölçümle aynı tanım (nüfus üzerinde; içe aktarılan fonksiyonlarla)
                "urun": h.olculer(moduller, siniflar),
                "b1": h.olculer(h.b1_bolme(n, len(set(moduller))), siniflar),
                "b1_gt": h.olculer(h.b1_bolme(n, len(set(siniflar))), siniflar),
                "tavan": h.olculer(tavan_bolmesi(siniflar), siniflar),
            }
            # B1 kuralı, yöntemlerin gördüğü evrende (thunk olmayan bütün fonksiyonlar) uygulanırsa
            b1_e = cekirdege_yay(sin["kitaplik"], lambda m: h.b1_bolme(m, min(len(set(moduller)), m)))
            satirlar["b1_evren"] = h.olculer([b1_e[k] for k in konum], siniflar)
            bolmeler, gosterge = secenekler(sin)
            for yontem, etiket in bolmeler.items():
                satirlar[yontem] = h.olculer([etiket[k] for k in konum], siniflar)
            tablo.setdefault(birim, {})[ad] = satirlar
            parca.setdefault(birim, {})[ad] = {s: o["modul"] for s, o in satirlar.items()}
            gostergeler[f"{birim}/{ad}"] = {
                **gosterge, "n": n, "sinif": d["sinif"], "lto": bool(elf["lto"]),
                "bitisiklik": float(Fraction(d["bitisiklik"]["sinif"], d["bitisiklik"]["kosu"]))}
    satir_adlari = list(next(iter(next(iter(tablo.values())).values())))
    ozet: dict[str, Any] = {}
    for s in satir_adlari:
        ozet[s] = {o: h.makro({b: h.ortalama(e[s][o] for e in v.values()) for b, v in tablo.items()})
                   for o in OLCULER}
        # yalnız bilgi: parça sayısı / GT sınıf sayısı (ikili ortalaması → program → makro)
        ozet[s]["parca_bolu_sinif"] = h.makro({
            b: h.ortalama(Fraction(parca[b][ad][s], gostergeler[f"{b}/{ad}"]["sinif"]) for ad in v)
            for b, v in tablo.items()})
    saglama = sagla(olcum, ozet)
    return {"sema": SEMA, "uyari": "ÖN KAYITSIZ keşif; geliştirme seti; ürün iddiası değil",
            "arac": {"harita_olc_sha256": ks1.sha256_dosya(HARITA_YOLU),
                     "olcum_sha256": ks1.sha256_dosya(olcum_yolu),
                     "git_head": ks1._git("rev-parse", "HEAD").stdout.strip()},
            "izgaralar": {"s1_parca_boylari": list(S1_PARCA_BOYLARI), "s2_esikler": list(S2_ESIKLER),
                          "gamalar": [float(g) for g in GAMALAR],
                          "birlesik_gamalar": [float(g) for g in BIRLESIK_GAMALAR],
                          "s2_secilen_esik": S2_SECILEN_ESIK, "hiza": HIZA, "yogunluk_esigi": YOGUNLUK_ESIGI},
            "secimler": {"n_min": h.N_MIN, "en_az_program": h.EN_AZ_PROGRAM, "duzey": DUZEY},
            "saglama": saglama, "ozet": ozet, "gosterge_ozeti": gosterge_ozeti(gostergeler, tablo),
            # program → dolgu kutusu → [sınıf değişmeyen çift, sınıf değişen çift]
            "dolgu_dokumu": {p: {k: list(v) for k, v in sorted(d.items())} for p, d in sorted(dolgu_dokumu.items())},
            # program → başlangıç adresi HIZA'nın katı mı → [sınıf değişmeyen çift, sınıf değişen çift]
            "hiza_dokumu": {p: {k: list(v) for k, v in sorted(d.items())} for p, d in sorted(hiza_dokumu.items())},
            "gostergeler": gostergeler,
            "ikili_ari": {b: {ad: {s: e[s]["ari"] for s in e} for ad, e in v.items()}
                          for b, v in tablo.items()}}


def sagla(olcum: dict[str, Any], ozet: dict[str, Any]) -> dict[str, Any]:
    """B1 ve ürün satırları ön kayıtlı ölçümün özetiyle aynı mı (makro ve program başına)."""
    out: dict[str, Any] = {"tuttu": True}
    for satir, kaynak in (("b1", h.SATIR_B1), ("urun", h.SATIR_URUN), ("b1_gt", h.SATIR_B1_GT)):
        beklenen = olcum["ozet"][DUZEY]["satirlar"][kaynak]["ari"]
        bulunan = h.yuvarla(ozet[satir]["ari"])
        esit = (bulunan["makro"] == beklenen["makro"] and bulunan["program"] == beklenen["program"])
        out[satir] = {"beklenen_makro": beklenen["makro"], "bulunan_makro": bulunan["makro"],
                      "program_esit": bulunan["program"] == beklenen["program"], "esit": esit}
        out["tuttu"] = out["tuttu"] and esit
    return out


def gosterge_ozeti(gostergeler: dict[str, dict[str, Any]], tablo: dict[str, Any]) -> dict[str, Any]:
    """LTO göstergeleri: program başına ortalama ve ikili düzeyinde sıra korelasyonları."""
    program: dict[str, dict[str, list[float]]] = {}
    satir: dict[str, list[float]] = defaultdict(list)
    for anahtar, g in sorted(gostergeler.items()):
        birim, ad = anahtar.rsplit("/", 1)
        p = program.setdefault(ks1.birim_programi(birim), defaultdict(list))
        for alan in ("cagri_uzakligi", "q_s3", "q_s4", "bitisiklik", "kesin_sinir_yogunlugu", "hizali32",
                     "hizali16"):
            if g.get(alan) is not None:
                p[alan].append(g[alan])
        p["ari_s3"].append(float(tablo[birim][ad]["s3_g1"]["ari"]))
        p["ari_s4"].append(float(tablo[birim][ad]["s4_g1"]["ari"]))
        p["ari_tavan"].append(float(tablo[birim][ad]["tavan"]["ari"]))
        if g.get("cagri_uzakligi") is not None:
            satir["cagri_uzakligi"].append(g["cagri_uzakligi"])
            satir["q_s3"].append(g["q_s3"])
            satir["bitisiklik"].append(g["bitisiklik"])
            satir["ari_s4"].append(float(tablo[birim][ad]["s4_g1"]["ari"]))
            satir["lto"].append(1.0 if g["lto"] else 0.0)
            satir["kesin_sinir_yogunlugu"].append(g["kesin_sinir_yogunlugu"])
    lto = [u for u, l in zip(satir["cagri_uzakligi"], satir["lto"]) if l]
    ltosuz = [u for u, l in zip(satir["cagri_uzakligi"], satir["lto"]) if not l]
    y_lto = [u for u, l in zip(satir["kesin_sinir_yogunlugu"], satir["lto"]) if l]
    y_ltosuz = [u for u, l in zip(satir["kesin_sinir_yogunlugu"], satir["lto"]) if not l]
    return {"program": {p: {a: sum(v) / len(v) for a, v in sorted(d.items())} for p, d in sorted(program.items())},
            "ikili": len(satir["bitisiklik"]),
            "spearman": {
                "cagri_uzakligi~bitisiklik": spearman(satir["cagri_uzakligi"], satir["bitisiklik"]),
                "q_s3~bitisiklik": spearman(satir["q_s3"], satir["bitisiklik"]),
                "cagri_uzakligi~ari_s4": spearman(satir["cagri_uzakligi"], satir["ari_s4"]),
                "kesin_sinir_yogunlugu~bitisiklik": spearman(satir["kesin_sinir_yogunlugu"], satir["bitisiklik"])},
            "kesin_sinir_yogunlugu_araligi": {
                "lto": [min(y_lto), max(y_lto), len(y_lto)] if y_lto else None,
                "ltosuz": [min(y_ltosuz), max(y_ltosuz), len(y_ltosuz)] if y_ltosuz else None},
            "cagri_uzakligi_araligi": {
                "lto": [min(lto), max(lto), len(lto)] if lto else None,
                "ltosuz": [min(ltosuz), max(ltosuz), len(ltosuz)] if ltosuz else None}}


def gt_sagla(debian_kosu: Path, olcum_yolu: Path, indir: Path, programlar: Sequence[str]) -> dict[str, Any]:
    """İkinci sağlama: seçilen programlarda GT ve ürün tarafı ``harita_olc`` yardımcılarıyla YENİDEN
    okunur; nüfus ve iki bölme (modül, dosya sınıfı) ölçüm JSON'undaki öğelerle aynı mı?"""
    olcum = h._json(olcum_yolu)
    out: dict[str, Any] = {}
    onbellek: dict = {}
    for e in h.projesizleri_isaretle(ks1.elfleri_topla(None, debian_kosu)):
        if e.program not in programlar or e.static is None:
            continue
        birim = ks1.birim_anahtari(e)
        elf = olcum["birimler"].get(birim, {}).get("elfler", {}).get(e.ad)
        if elf is None:
            continue
        ghidra, _, _ = h._ghidra_adresleri(e)
        adresler, moduller, siniflar = h.sinif_dizileri(h.urun_oku(e.kosu, ghidra), h.gt_oku(e, indir, onbellek))
        a2, m2, s2 = ogeleri_ac(elf)
        ayni_bolme = (len(set(zip(moduller, m2))) == len(set(moduller)) == len(set(m2))
                      and len(set(zip(siniflar[DUZEY], s2))) == len(set(siniflar[DUZEY])) == len(set(s2)))
        out[f"{birim}/{e.ad}"] = {"n": len(adresler), "adres_esit": adresler == a2, "bolme_esit": ayni_bolme}
    return out


# --------------------------------------------------------------------------------------------
# Çıktı


def _s(v: Any) -> str:
    return h.sayi(v)


def tablo_yaz(s: dict[str, Any]) -> str:
    oz = s["ozet"]
    programlar = sorted(oz["b1"]["ari"]["program"])
    satirlar = ["| Satır | Makro ARI | Kesinlik | Duyarlılık | Parça / GT sınıf | "
                + " | ".join(programlar) + " |", "|---|---|---|---|---|" + "---|" * len(programlar)]
    for ad, o in oz.items():
        satirlar.append(f"| `{ad}` | {_s(o['ari']['makro'])} | {_s(o['kesinlik']['makro'])} | "
                        f"{_s(o['duyarlilik']['makro'])} | {_s(o['parca_bolu_sinif']['makro'], )} | "
                        + " | ".join(_s(o["ari"]["program"].get(p)) for p in programlar) + " |")
    g = s["gosterge_ozeti"]
    satirlar += ["", "| Program | Çağrı uzaklığı | Q (s3) | Q (s4) | Kesin sınır yoğunluğu | 32'ye hizalı | "
                 "16'ya hizalı | GT bitişikliği | ARI s3 | ARI s4 | ARI tavan |",
                 "|---|---|---|---|---|---|---|---|---|---|---|"]
    for p, d in g["program"].items():
        satirlar.append(f"| {p} | " + " | ".join(_s(d.get(a)) for a in (
            "cagri_uzakligi", "q_s3", "q_s4", "kesin_sinir_yogunlugu", "hizali32", "hizali16", "bitisiklik",
            "ari_s3", "ari_s4", "ari_tavan")) + " |")
    kutular = sorted({k for d in s["dolgu_dokumu"].values() for k in d},
                     key=lambda k: -1 if k == "negatif" else int(k.split("-")[0]))
    satirlar += ["", "Dolgu ↔ GT sınıf değişimi (ardışık çiftler; hücre: sınıf aynı / sınıf değişti)", "",
                 "| Program | " + " | ".join(kutular) + " |", "|---|" + "---|" * len(kutular)]
    toplam = {k: [0, 0] for k in kutular}
    for p, d in s["dolgu_dokumu"].items():
        for k in kutular:
            toplam[k][0] += d.get(k, [0, 0])[0]
            toplam[k][1] += d.get(k, [0, 0])[1]
        satirlar.append(f"| {p} | " + " | ".join("{} / {}".format(*d.get(k, [0, 0])) for k in kutular) + " |")
    satirlar.append("| havuz | " + " | ".join("{} / {}".format(*toplam[k]) for k in kutular) + " |")
    satirlar += ["", f"Başlangıç adresi {HIZA}'nin katı mı ↔ GT sınıf değişimi (sınıf aynı / sınıf değişti)", "",
                 "| Program | kat | kat değil |", "|---|---|---|"]
    for p, d in s["hiza_dokumu"].items():
        satirlar.append(f"| {p} | " + " | ".join("{} / {}".format(*d.get(k, [0, 0])) for k in ("kat", "kat_degil")) + " |")
    satirlar += ["", f"Kesin sınır yoğunluğu aralığı [en küçük, en büyük, ikili]: LTO "
                 f"{g['kesin_sinir_yogunlugu_araligi']['lto']}; LTO'suz {g['kesin_sinir_yogunlugu_araligi']['ltosuz']}"]
    satirlar += ["", "Sıra korelasyonları (ikili düzeyi, n = %d): " % g["ikili"]
                 + "; ".join(f"{k} = {_s(v)}" for k, v in g["spearman"].items()),
                 f"Çağrı uzaklığı aralığı [en küçük, en büyük, ikili]: LTO {g['cagri_uzakligi_araligi']['lto']}; "
                 f"LTO'suz {g['cagri_uzakligi_araligi']['ltosuz']}",
                 "", "Sağlama: " + json.dumps(s["saglama"], ensure_ascii=False)]
    return "\n".join(satirlar)


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--debian-kosu", type=Path, required=True)
    ap.add_argument("--olcum", type=Path, default=h.ONKAYIT_DIZINI / "harita_olcumu.json")
    ap.add_argument("--debian-indir", type=Path,
                    default=Path.home() / "karadul_olcum" / "downloads" / "debian13")
    ap.add_argument("--json", type=Path, required=True)
    ap.add_argument("--gt-sagla", nargs="*", default=[],
                    help="bu programlarda GT'yi harita_olc yardımcılarıyla yeniden oku ve öğelerle karşılaştır")
    a = ap.parse_args(argv)
    sonuc = kos(a.debian_kosu, a.olcum)
    if a.gt_sagla:
        sonuc["gt_saglama"] = gt_sagla(a.debian_kosu, a.olcum, a.debian_indir, a.gt_sagla)
    a.json.parent.mkdir(parents=True, exist_ok=True)
    a.json.write_text(json.dumps(h.yuvarla(sonuc), ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    print(tablo_yaz(sonuc))
    if a.gt_sagla:
        print("GT sağlaması: " + json.dumps(sonuc["gt_saglama"], ensure_ascii=False))
    if not sonuc["saglama"]["tuttu"]:
        print("DURDU: B1 sağlaması tutmadı", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
