#!/usr/bin/env python3
"""string_context alt kanalları (plan v2.2 N0b): ön kayıtlı tanımlar ve etiketsiz kapsam.

Taban v2'de fonksiyon adlarının neredeyse hepsi tek stratejiden (``string_context``) ve tek kod
yolundan (``classic/keywords``) geliyor; "kanal başına kesinlik" bu yüzden tek bir sayı. Bu betik
``string_context`` kayıtlarını kod yolundan ve kanıt dizgisinin biçiminden kurulan belirlenimci,
ayrık ve öncelik sıralı alt kanallara böler. Tanımlar G4 etiketlerine bakılmadan yazıldı. Bir adın
doğru olup olmadığına dair hiçbir bilgi kullanılmaz: gerçek ad, ``status``, etiket okunmaz.

Girdi
-----
c_namer'ın isim kökeni kaydı (``naming_provenance.json``, şema ``karadul.naming_provenance`` 1).
Sınıflama bir kaydın yalnız şu alanlarını okur: ``strategy``, ``new_name``, ``proposed_name``,
``confidence``, ``evidence``, ``code_path``, ``rule``, ``evidence_origin``, ``n_candidates``,
``runners_up``. Taban koşusuyla eşleşme sayımı ``macho_score.json``'dan yalnız ``addr`` ve
``pred`` alanlarını, ``naming_map.json``'dan yalnız ``new_name`` ve ``source`` alanlarını okur.

Dondurulmuş kopyalar
--------------------
Klasik yolun anahtar sözcük çıkarımı (``c_namer._extract_keywords_from_string``), ad temizleme
(``_sanitize_c_name``) ve genel adlardaki yapısal süzgeç (``analyze_and_rename``) burada kopya
olarak durur. Böylece motor kodu değişse de sınıflama değişmez; tanım ön kayıtta betiğin sha256'sıyla
dondurulur. Kopyaların motorla aynı davrandığını ``tests/test_alt_kanal.py`` denetler; motor
değişirse test kırmızıya döner ve ön kayıt yeniden ele alınır.

Alt kanallar (tanım sürümü 1)
-----------------------------
Gösterim:
- ``e``: kanıt dizgisinin baştaki ve sondaki boşlukları atılmış hâli.
- ``ad``: önerilen ad. Çakışma eki eklenmeden önceki addır: ``proposed_name``, yoksa ``new_name``.
- ``k``: klasik yolun kanıttan çıkardığı anahtar sözcük sayısı (1-4). Klasik güven
  min(0,9; 0,7 + 0,05·k)'dir; ad ilk üç anahtar sözcükten kurulur.

Her kanal kendi yüklemi ile kendisinden önceki bütün yüklemlerin olumsuzlamasıdır: ilk tutan
yüklem kazanır, ``diger`` her kaydı tutar. Bu yüzden her kayıt tam olarak bir alt kanala düşer.

1. ``agresif``: kod yolu ``aggressive`` (kural ``rule`` alanında). Taban v2'de hiç kazanmıyor.
2. ``kod_parcasi``: kanıt gövde literali (``body_literal``) ama gerçek bir C dizgi literali değil.
   Ham satır sonu ya da Ghidra'nın kendiliğinden verdiği bir ad (``FUN_…``, ``pcVar1``,
   ``param_2``, ``local_28``, ``auStack_58``, ``undefined4`` …) taşıyor. Gövdedeki
   ``"([^"]{3,80})"`` taraması iki literalin arasındaki kodu yakalamıştır (Ghidra C çıktısında
   dizgi literali tek satırdır).
3. ``bicim_parcasi``: adı kuran anahtar sözcüklerden (ilk üç) en az biri bir printf dönüşüm
   belirtecinin (``%%`` hariç) içine taşıyor: ``%lld`` → ``lld``, ``%siB`` → ``sib``.
4. ``oz_ad``: ``e`` tek bir C tanımlayıcısı; en az bir alt çizgi ve en az bir küçük harf taşıyor;
   ``ad``, ``e``'nin küçük harfli hâline eşit. Kendi adını yazan tanımlayıcı biçimidir. Dizginin bu
   fonksiyonun adı olduğu ayrıca doğrulanmaz (``__func__`` ile biçim değişkeni ayırt edilmez).
5. ``tek_sozcuk``: ``k == 1``; ad tek anahtar sözcükten kurulmuş (klasik güven 0,75).
6. ``tanimlayici``: ``e`` alt çizgili tek bir C tanımlayıcısı ama 4'e girmedi. Ad dizgiden farklı
   (durak sözcük, 3 harften kısa parça ya da rakam düştü, 3'ten çok parça kırpıldı) ya da
   tanımlayıcının tamamı büyük harf (sabit, ortam değişkeni).
7. ``kebap_ad``: ``e`` küçük harfli, tireyle bağlanmış sözcüklerden oluşan tek belirteç
   (``monitor-activity``). Seçenek, kanca, komut ya da bildirim adı biçimi.
8. ``hata_iletisi``: kanıtta hata ya da kullanım iletisi belirteci var (``HATA_RE``).
9. ``bicim_dizgisi``: kanıtta printf dönüşüm belirteci (``%%`` hariç) ya da şablon yer tutucusu
   (``#{``, ``#[``, ``${``, ``{{``) var.
10. ``duz_metin``: ``e`` boşlukla ayrılmış birden çok parçadan oluşuyor ve C işleci (``->``,
    ``==``, ``!=``, ``<=``, ``>=``, ``&&``, ``||``) taşımıyor.
11. ``diger``: kalanlar (noktalı anahtarlar, virgüllü listeler, yollar, boşluksuz ifadeler …).

Halef (susturulan adın yerine geçen aday)
-----------------------------------------
Bir alt kanal susturulursa kazanan aday yarıştan çıkar, ad doğrudan silinmez. Yerine
``runners_up``'taki (güvene göre sıralı, en çok 3) ilk susturulmamış aday geçer; aynı alt kanaldaki
rakipler de susturulmuş sayılır. c_namer'ın seçim döngüsü yalnız en iyi adaya bakar:
- en iyi aday yapısal süzgeçteyse (``call_graph``, ``callee_based``, ``api_call``) anahtar ad almaz;
- güveni eşiğin altındaysa anahtar ad almaz.
Kayda geçmeyen aday varsa (``n_candidates`` > 1 + kayıtlı rakip sayısı) ve kayıtlı rakiplerin hepsi
susturulmuşsa sonuç ``bilinmiyor``dur. Eşik iki düzeyde uygulanır: c_namer (``min_confidence``,
0,15) ve ürün (NameMerger, ``binary_reconstruction.min_naming_confidence``, 0,7).

Karar kuralı (ön kayıt, adım 2'de uygulanır)
-------------------------------------------
``karar(n, yanlis)``: alt kanalın G4'te etiketlenmiş ``n`` öğesinden ``yanlis`` tanesi rubrikte
(sürüm 2; yanlış fiil dahil) ``yanlis`` etiketini aldıysa, yanlış oranının Wilson %95 aralığı
``[L, U]`` ile:
- ``dogrulandi``: ``U <= %10`` (sıfır yanlışla bile en az 35 öğe ister). Ad vermeyi sürdürür,
  güven etiketi "doğrulandı".
- ``belirsiz``: aralık %10'u içeriyor. Ad vermeyi sürdürür, güven etiketi "doğrulanmadı"; N2'nin
  taze örnekleminde yeniden ölçülür.
- ``zayif``: ``L > %10``. N1'de KS-1 ile birlikte susturulur.
- ``olculemedi``: ``n == 0``. Hakkında hiç kanıt yok; susturulur.
Kural "yalnız zayıflar" (ana oturum kararı, 2026-10-21). Bütün alt kanallar ``zayif`` ya da
``olculemedi`` çıkarsa ``string_context`` tümüyle susar (``hepsini_kapatir``). Gerekçe
``docs/arge/2026-10-21_g10_n0b/alt_kanal_onkayit.md`` §5'te.

Alt komutlar
------------
    uret     --calisma <static/ ve deobfuscated/ içeren dizin> --program <ad> -o <dizin>
             (Ghidra yok: taban koşusunun Ghidra çıktısında yalnız c_namer, seri yürütücüyle)
    sinifla  <naming_provenance.json> --program <ad> [--macho-score <json>]
             [--naming-map <json>] [--ters-json <json>] -o <kayitlar.jsonl>
    kapsam   <kayitlar.jsonl ...> [--json <yol>]
    tanimlar (alt kanal tablosu ve betiğin sha256'sı)
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import contextlib
import hashlib
import json
import math
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import time
from collections import Counter
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator, NamedTuple, Optional

TANIM_SURUMU = 1
SEMA_KAYIT = "karadul-alt-kanal-kayit/1"
SEMA_KAPSAM = "karadul-alt-kanal-kapsam/1"
SEMA_URETIM = "karadul-alt-kanal-uretim/1"
KOKEN_SEMASI = "karadul.naming_provenance"
KOKEN_SEMA_SURUMU = 1

STRATEJI = "string_context"
AGRESIF_YOL = "aggressive"
KLASIK_YOL = "classic"
FONKSIYON_ANAHTARI_RE = re.compile(r"^FUN_([0-9a-fA-F]+)$")

# --- Dondurulmuş kopya: c_namer._extract_keywords_from_string (2026-10-21, 9a36142)
ANAHTAR_SOZCUK_RE = re.compile(r"[a-zA-Z]{3,}")
DURAK_SOZCUKLER = frozenset({
    "the", "and", "for", "not", "but", "has", "had", "was", "are",
    "can", "did", "does", "with", "from", "that", "this", "will",
    "you", "your", "all", "been", "have", "its", "may", "our",
    "too", "use", "way", "who", "how", "let", "put",
    "say", "she", "his", "her", "him", "get", "got", "set",
    "try", "yes", "yet", "than", "into", "just", "also",
    "failed", "error", "success", "warning", "info", "debug",
    "true", "false", "null", "none", "invalid", "unknown",
    "opt", "usr", "lib", "bin", "var", "tmp", "etc",
    "build", "buildbot", "buildworker", "hotfix",
    "release", "client", "server", "public",
    "src", "include", "framework", "frameworks",
    "system", "library", "versions", "darwin",
})
KISA_DIZGI = 3      # len(s) < 3 ise anahtar sözcük yok
AZAMI_ANAHTAR = 4   # filtered[:4]
AD_PARCASI = 3      # "_".join(best_keywords[:3])

# --- Dondurulmuş kopya: analyze_and_rename'deki genel ad süzgeci (yalnız en iyi adaya bakar)
YAPISAL_SUZGEC = ("call_graph", "callee_based", "api_call")

# --- Biçim yüklemleri
# printf dönüşüm belirteci. "%%" ayrı bir seçenek olarak eşlenir ki "%%u" yanlışlıkla "%u"
# sayılmasın. Boşluk bayrağı alınmaz: düz metindeki "50% done" belirteç sayılmasın.
BICIM_BELIRTECI_RE = re.compile(
    r"%(?:(?:\d+\$)?[-+#0']*(?:\d+|\*)?(?:\.(?:\d+|\*)?)?(?:hh|h|ll|l|L|q|j|z|t)?"
    r"[diouxXeEfFgGaAcspnmCS@]|%)")
SABLON_YER_TUTUCULARI = ("#{", "#[", "${", "{{")
TANIMLAYICI_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
KEBAP_RE = re.compile(r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)+$")
C_ISLECI_RE = re.compile(r"->|==|!=|<=|>=|&&|\|\|")
# Ghidra'nın kendiliğinden verdiği adlar. Gerçek bir literaldeki İngilizce sözcüğe uymasın diye
# rakamsız "undefined" ve "in_…" alınmaz (Ghidra kodunda bunlar zaten başka adlarla birlikte geçer).
GHIDRA_OTO_AD_RE = re.compile(
    r"\b(?:(?:FUN|DAT|PTR|LAB|SUB|UNK|thunk_FUN)_[0-9a-fA-F]+|param_\d+|local_[0-9a-fA-F]+"
    r"|[a-z]{1,3}Var\d+|a[a-z]{0,2}Stack_[0-9a-fA-F]+|(?:extraout|unaff)_[A-Za-z0-9]+"
    r"|undefined\d+)\b")
HATA_RE = re.compile(
    r"\b(?:errors?|fail(?:s|ed|ure)?|fatal|invalid|illegal|bad|wrong|unknown|unsupported"
    r"|unexpected|unrecogni[sz]ed|cannot|can'?t|could\s+not|couldn'?t|unable|not\s+able"
    r"|missing|no\s+such|not\s+found|not\s+allowed|denied|refused"
    r"|too\s+(?:many|few|long|big|large|small)|overflow|out\s+of|usage|must|expected)\b",
    re.IGNORECASE)

# --- Karar kuralı (ön kayıt)
WILSON_Z = 1.96              # %95
YANLIS_HEDEFI = 0.10         # plan v2 §7 G13 / v2.2 Kapı 1: yanlış (yanlış fiil dahil) <= %10
CAPA_KESINLIK_HEDEFI = 0.95  # plan v2.2 N1: KS-1 çapa kesinliği >= %95 (yalnız örneklem hesabı)
KARARLAR = ("dogrulandi", "zayif", "belirsiz", "olculemedi")
# "Yalnız zayıflar" (ana oturum kararı, 2026-10-21): zayıf ya da ölçülemeyen kanal susturulur,
# doğrulanan ve belirsiz kalan kanal ad vermeyi güven etiketiyle sürdürür.
URUNDE_KALAN_KARARLAR = frozenset({"dogrulandi", "belirsiz"})
GUVEN_ETIKETLERI = {"dogrulandi": "doğrulandı", "belirsiz": "doğrulanmadı"}


# --------------------------------------------------------------------------------------------
# Dondurulmuş klasik yol


def anahtar_sozcukler(s: str) -> list[tuple[str, int, int]]:
    """Klasik yolun anahtar sözcükleri, kanıttaki konumlarıyla: [(sözcük, başlangıç, bitiş)]."""
    if len(s) < KISA_DIZGI:
        return []
    cikti: list[tuple[str, int, int]] = []
    for m in ANAHTAR_SOZCUK_RE.finditer(s):
        sozcuk = m.group(0).lower()
        if sozcuk not in DURAK_SOZCUKLER:
            cikti.append((sozcuk, m.start(), m.end()))
    return cikti[:AZAMI_ANAHTAR]


def ad_temizle(ad: str) -> str:
    """c_namer._sanitize_c_name(ad, preserve_case=False) kopyası."""
    ad = re.sub(r"[^a-zA-Z0-9_]", "_", ad)
    if ad and ad[0].isdigit():
        ad = "_" + ad
    ad = re.sub(r"_+", "_", ad)
    ad = ad.strip("_")
    if not ad:
        ad = "unnamed"
    return ad.lower()


def klasik_ad(kanit: str) -> tuple[str, int]:
    """Klasik yolun bu kanıttan kuracağı ad ve anahtar sözcük sayısı (k)."""
    sozcukler = anahtar_sozcukler(kanit)
    return ad_temizle("_".join(s for s, _, _ in sozcukler[:AD_PARCASI])), len(sozcukler)


def klasik_guven(k: int) -> float:
    return min(0.9, 0.7 + k * 0.05)


def taban_ad(ad: Optional[str]) -> Optional[str]:
    """Çakışma eki (``_2``, ``_3`` …) atılmış ad. Rubrik kural 2 ekleri yok sayar."""
    if ad is None:
        return None
    return re.sub(r"_\d+$", "", ad)


# --------------------------------------------------------------------------------------------
# Yüklemler


class Girdi(NamedTuple):
    kod_yolu: str
    kaynak: str
    kanit: str
    e: str
    ad: str
    sozcukler: list[tuple[str, int, int]]

    @property
    def k(self) -> int:
        return len(self.sozcukler)


def girdi_kur(kayit: dict[str, Any]) -> Girdi:
    kanit = str(kayit.get("evidence") or "")
    ad = str(kayit.get("proposed_name") or kayit.get("new_name") or "")
    return Girdi(kod_yolu=str(kayit.get("code_path") or ""),
                 kaynak=str(kayit.get("evidence_origin") or ""),
                 kanit=kanit, e=kanit.strip(), ad=ad, sozcukler=anahtar_sozcukler(kanit))


def bicim_belirtecleri(s: str) -> list[tuple[int, int]]:
    """``%%`` dışındaki printf dönüşüm belirteçlerinin [başlangıç, bitiş) aralıkları."""
    return [(m.start(), m.end()) for m in BICIM_BELIRTECI_RE.finditer(s) if m.group(0) != "%%"]


def _agresif(g: Girdi) -> bool:
    return g.kod_yolu == AGRESIF_YOL


def _kod_parcasi(g: Girdi) -> bool:
    return g.kaynak == "body_literal" and ("\n" in g.kanit or bool(GHIDRA_OTO_AD_RE.search(g.kanit)))


def _bicim_parcasi(g: Girdi) -> bool:
    belirtecler = bicim_belirtecleri(g.kanit)
    return any(bas < b_son and b_bas < son
               for _, bas, son in g.sozcukler[:AD_PARCASI] for b_bas, b_son in belirtecler)


def _alt_cizgili_tanimlayici(e: str) -> bool:
    return bool(TANIMLAYICI_RE.match(e)) and "_" in e


def _oz_ad(g: Girdi) -> bool:
    return (_alt_cizgili_tanimlayici(g.e) and any(c.islower() for c in g.e)
            and g.ad == g.e.lower())


def _tek_sozcuk(g: Girdi) -> bool:
    return g.k == 1


def _tanimlayici(g: Girdi) -> bool:
    return _alt_cizgili_tanimlayici(g.e)


def _kebap_ad(g: Girdi) -> bool:
    return bool(KEBAP_RE.match(g.e))


def _hata_iletisi(g: Girdi) -> bool:
    return bool(HATA_RE.search(g.kanit))


def _bicim_dizgisi(g: Girdi) -> bool:
    return bool(bicim_belirtecleri(g.kanit)) or any(y in g.kanit for y in SABLON_YER_TUTUCULARI)


def _duz_metin(g: Girdi) -> bool:
    return len(g.e.split()) > 1 and not C_ISLECI_RE.search(g.e)


def _diger(g: Girdi) -> bool:
    return True


class AltKanal(NamedTuple):
    ad: str
    yuklem: Callable[[Girdi], bool]
    aciklama: str


# Öncelik sırası: ilk tutan yüklem kazanır. Sıra ve tanımlar ön kayıttır.
ALT_KANALLAR: tuple[AltKanal, ...] = (
    AltKanal("agresif", _agresif, "agresif kod yolu (kural rule alanında)"),
    AltKanal("kod_parcasi", _kod_parcasi,
             "gövde literali gerçek literal değil: ham satır sonu ya da Ghidra kendiliğinden adı"),
    AltKanal("bicim_parcasi", _bicim_parcasi,
             "adı kuran anahtar sözcük printf dönüşüm belirtecine taşıyor (%lld → lld)"),
    AltKanal("oz_ad", _oz_ad, "kendi adını yazan tanımlayıcı: dizgi tek tanımlayıcı, ad ona eşit"),
    AltKanal("tek_sozcuk", _tek_sozcuk, "ad tek anahtar sözcükten (k = 1)"),
    AltKanal("tanimlayici", _tanimlayici,
             "alt çizgili tanımlayıcı dizgi, ad dizgiden farklı ya da tümü büyük harf"),
    AltKanal("kebap_ad", _kebap_ad, "tireli küçük harf belirteç: seçenek, kanca, komut adı"),
    AltKanal("hata_iletisi", _hata_iletisi, "hata ya da kullanım iletisi belirteci"),
    AltKanal("bicim_dizgisi", _bicim_dizgisi, "printf belirteci ya da şablon yer tutucusu"),
    AltKanal("duz_metin", _duz_metin, "boşluklu düz metin, C işleci yok"),
    AltKanal("diger", _diger, "kalanlar"),
)
ALT_KANAL_ADLARI = tuple(a.ad for a in ALT_KANALLAR)


def sinifla(kayit: dict[str, Any]) -> dict[str, Any]:
    """Bir string_context kaydının alt kanalı.

    Döndürülen sözlük: ``alt_kanal`` (öncelik sırasında ilk tutan yüklem), ``yuklemler`` (her
    yüklemin tek başına değeri; şeffaflık için), ``k`` ve ``klasik_tutarli`` (klasik kayıtta ad ve
    güven bu kanıttan yeniden kurulabiliyor mu; değilse kayıt ile dondurulmuş kopya ayrışmıştır).
    """
    g = girdi_kur(kayit)
    yuklemler = {a.ad: bool(a.yuklem(g)) for a in ALT_KANALLAR}
    kanal = next(a.ad for a in ALT_KANALLAR if yuklemler[a.ad])
    tutarli: Optional[bool] = None
    if g.kod_yolu == KLASIK_YOL:
        yeniden_ad, k = klasik_ad(g.kanit)
        guven = float(kayit.get("confidence", -1.0))
        tutarli = yeniden_ad == g.ad and math.isclose(guven, klasik_guven(k), abs_tol=1e-9)
    return {"alt_kanal": kanal, "yuklemler": yuklemler, "k": g.k, "klasik_tutarli": tutarli}


def kanal_ya_da_strateji(aday: dict[str, Any]) -> str:
    """Rakip aday için kısa etiket: string_context ise alt kanalı, değilse stratejisi."""
    if aday.get("strategy") == STRATEJI:
        return f"{STRATEJI}/{sinifla(aday)['alt_kanal']}"
    return str(aday.get("strategy"))


# --------------------------------------------------------------------------------------------
# Halef


def halef(kayit: dict[str, Any], susturulan: Iterable[str], esik: float) -> dict[str, Any]:
    """``susturulan`` alt kanallar yarıştan çıkarılırsa bu anahtar için ne olur.

    Kazanan string_context adayı susturulan bir kanaldaysa yerine ``runners_up``'taki ilk
    susturulmamış aday geçer. Sonuç: ``ad`` (yeni ad verilir), ``yapisal_suzgec`` ve ``esik_alti``
    (anahtar ad almaz, ``FUN_`` kalır), ``yok`` (rakip yok), ``bilinmiyor`` (kayda geçmeyen aday
    var) ya da ``susturulmadi`` (kazanan susturulan kanalda değil).
    """
    susturulan = set(susturulan)
    if kayit.get("strategy") != STRATEJI or sinifla(kayit)["alt_kanal"] not in susturulan:
        return {"sonuc": "susturulmadi"}
    rakipler = list(kayit.get("runners_up") or [])
    for r in rakipler:
        if r.get("strategy") == STRATEJI and sinifla(r)["alt_kanal"] in susturulan:
            continue
        etiket = kanal_ya_da_strateji(r)
        guven = float(r.get("confidence", 0.0))
        if r.get("strategy") in YAPISAL_SUZGEC:
            return {"sonuc": "yapisal_suzgec", "aday": etiket, "guven": guven}
        if guven < esik:
            return {"sonuc": "esik_alti", "aday": etiket, "guven": guven}
        return {"sonuc": "ad", "aday": etiket, "guven": guven, "ad": r.get("new_name")}
    if int(kayit.get("n_candidates") or 0) > 1 + len(rakipler):
        return {"sonuc": "bilinmiyor"}
    return {"sonuc": "yok"}


def halef_etiketi(h: dict[str, Any]) -> str:
    if h["sonuc"] == "ad":
        return f"ad:{h['aday']}"
    if h["sonuc"] in ("yapisal_suzgec", "esik_alti"):
        return f"{h['sonuc']}:{h['aday']}"
    return h["sonuc"]


# --------------------------------------------------------------------------------------------
# Wilson ve karar kuralı


def wilson(basari: int, n: int, z: float = WILSON_Z) -> tuple[float, float]:
    """Oranın Wilson skor aralığı. n == 0 için (0, 1)."""
    if n <= 0:
        return 0.0, 1.0
    p = basari / n
    z2 = z * z
    payda = 1.0 + z2 / n
    merkez = (p + z2 / (2 * n)) / payda
    yari = z * math.sqrt(p * (1 - p) / n + z2 / (4 * n * n)) / payda
    return max(0.0, merkez - yari), min(1.0, merkez + yari)


def en_az_n_ust_sinir(esik: float, z: float = WILSON_Z) -> int:
    """Hiç olay gözlenmezse Wilson üst sınırının ``esik``e inmesi için gereken en küçük n.

    0 olayda üst sınır z²/(n+z²)'dir; ≤ esik ⇔ n ≥ z²(1−esik)/esik.
    """
    return math.ceil(z * z * (1 - esik) / esik - 1e-12)


def en_az_n_alt_sinir(hedef: float, z: float = WILSON_Z) -> int:
    """Her öğe başarılıysa Wilson alt sınırının ``hedef``e çıkması için gereken en küçük n.

    n/n'de alt sınır n/(n+z²)'dir; ≥ hedef ⇔ n ≥ z²·hedef/(1−hedef).
    """
    return math.ceil(z * z * hedef / (1 - hedef) - 1e-12)


def karar(n: int, yanlis: int, esik: float = YANLIS_HEDEFI) -> dict[str, Any]:
    """Ön kayıtlı susturma kuralı: bir alt kanalın G4 etiketleriyle kararı.

    ``yanlis``: rubrik sürüm 2'de ``yanlis`` etiketli öğe sayısı (yanlış fiil dahil).
    Sözlükte ``urunde`` (N1'den sonra ad verir mi) ve ``guven_etiketi`` ("doğrulandı",
    "doğrulanmadı"; susturulan kanalda ``None``) da durur.
    """
    if n < 0 or yanlis < 0 or yanlis > n:
        raise ValueError(f"geçersiz sayılar: n={n}, yanlis={yanlis}")
    if n == 0:
        k: dict[str, Any] = {"karar": "olculemedi", "n": 0, "yanlis": 0, "oran": None,
                             "alt": None, "ust": None}
    else:
        alt, ust = wilson(yanlis, n)
        if ust <= esik:
            sonuc = "dogrulandi"
        elif alt > esik:
            sonuc = "zayif"
        else:
            sonuc = "belirsiz"
        k = {"karar": sonuc, "n": n, "yanlis": yanlis, "oran": yanlis / n, "alt": alt, "ust": ust}
    k["urunde"] = urunde_kalir(k)
    k["guven_etiketi"] = guven_etiketi(k)
    return k


def urunde_kalir(k: dict[str, Any]) -> bool:
    """N1'den sonra üründe ad vermeyi sürdürür mü: doğrulanan ve belirsiz kanal evet."""
    return k["karar"] in URUNDE_KALAN_KARARLAR


def guven_etiketi(k: dict[str, Any]) -> Optional[str]:
    """Kalan kanalın adlarına eklenecek güven etiketi; susturulan kanalda ``None``."""
    return GUVEN_ETIKETLERI.get(k["karar"]) if urunde_kalir(k) else None


def hepsini_kapatir(kararlar: dict[str, dict[str, Any]]) -> bool:
    """Bütün alt kanallar zayıf ya da ölçülemedi çıktıysa string_context tümüyle susar."""
    return not any(urunde_kalir(k) for k in kararlar.values())


# --------------------------------------------------------------------------------------------
# Yardımcılar


def sha256_dosya(yol: Path) -> str:
    h = hashlib.sha256()
    with open(yol, "rb") as f:
        for parca in iter(lambda: f.read(1 << 20), b""):
            h.update(parca)
    return h.hexdigest()


def sha256_dizin(dizin: Path, desen: str = "*.c") -> dict[str, Any]:
    """Dizindeki dosyaların (ada göre sıralı) ad + içerik özetlerinin özeti."""
    h = hashlib.sha256()
    n = 0
    for yol in sorted(dizin.glob(desen)):
        h.update(yol.name.encode("utf-8") + b"\0" + bytes.fromhex(sha256_dosya(yol)))
        n += 1
    return {"sha256": h.hexdigest(), "dosya": n}


def _git(*arglar: str) -> Optional[str]:
    try:
        return subprocess.run(["git", *arglar], cwd=Path(__file__).resolve().parent,
                              capture_output=True, text=True, timeout=30).stdout.strip()
    except Exception:
        return None


def arac_kunyesi() -> dict[str, Any]:
    betik = Path(__file__).resolve()
    kirli = _git("status", "--porcelain")
    return {"betik": "scripts/measurement/alt_kanal.py", "betik_sha256": sha256_dosya(betik),
            "tanim_surumu": TANIM_SURUMU, "git_head": _git("rev-parse", "HEAD"),
            "kirli_dosyalar": kirli.splitlines() if kirli else [],
            "python": platform.python_version()}


def _yaz_json(yol: Path, veri: Any) -> None:
    yol.parent.mkdir(parents=True, exist_ok=True)
    yol.write_text(json.dumps(veri, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")


def adres(anahtar: str) -> Optional[str]:
    m = FONKSIYON_ANAHTARI_RE.match(anahtar)
    return f"0x{m.group(1).lower()}" if m else None


# --------------------------------------------------------------------------------------------
# uret: taban koşusunun Ghidra çıktısında yalnız c_namer


class SeriYurutucu:
    """ProcessPoolExecutor yerine: işleri gönderim sırasıyla aynı süreçte yürütür.

    Aday listelerinin sırası (eşit güvende kazananı belirler) böylece belirlenimci olur.
    """

    def __init__(self, max_workers: Any = None, initializer: Any = None, initargs: tuple = ()):
        if initializer is not None:
            initializer(*initargs)

    def __enter__(self) -> "SeriYurutucu":
        return self

    def __exit__(self, *exc: Any) -> bool:
        return False

    def submit(self, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> cf.Future:
        fut: cf.Future = cf.Future()
        try:
            fut.set_result(fn(*args, **kwargs))
        except BaseException as hata:  # noqa: BLE001 -- havuzun davranışı: hata future'da
            fut.set_exception(hata)
        return fut


def _seri_as_completed(fs: Iterable[cf.Future], timeout: Any = None) -> list[cf.Future]:
    return list(fs)


@contextlib.contextmanager
def seri_c_namer(modul: Any) -> Iterator[None]:
    eski = (modul.ProcessPoolExecutor, modul.as_completed)
    modul.ProcessPoolExecutor, modul.as_completed = SeriYurutucu, _seri_as_completed
    try:
        yield
    finally:
        modul.ProcessPoolExecutor, modul.as_completed = eski


def uret(calisma: Path, program: str, cikti: Path) -> dict[str, Any]:
    """Boru hattının c_namer çağrısını taban koşusunun girdileriyle yeniden yürüt.

    Girdiler boru hattındaki gibi seçilir: JSON'lar önce ``deobfuscated/``'ta, yoksa ``static/``'te
    (``ghidra_metadata._resolve_json_paths``); C dosyaları ``deobfuscated/decompiled``, yoksa
    ``static/ghidra_output/decompiled``. ``pre_names`` boru hattının belirlenimci kurtarma
    tohumlarıyla kurulur (``ReconstructionStage``: main, gnulib parmak izi, ELF önyükü). Analist
    geçersiz kılma deposu (``~/.karadul/overrides``) okunmaz; doluysa künyeye yazılır.
    c_namer kurucusunun öntanımlı eşiğiyle koşar (boru hattında olduğu gibi).
    """
    import karadul.reconstruction.c_namer as cn
    from karadul.config import Config
    from karadul.stages import ReconstructionStage

    static = calisma / "static"
    deob = calisma / "deobfuscated"

    def sec(ad: str) -> Path:
        p = deob / ad
        return p if p.exists() else static / ad

    c_dizini = deob / "decompiled"
    if not c_dizini.is_dir():
        c_dizini = static / "ghidra_output" / "decompiled"
    jsonlar = {ad: sec(ad) for ad in ("ghidra_functions.json", "ghidra_strings.json",
                                      "ghidra_call_graph.json", "ghidra_xrefs.json")}

    asama = ReconstructionStage.__new__(ReconstructionStage)
    on_adlar: dict[str, str] = {}
    tohum_sayimlari: dict[str, Any] = {}
    asama._recover_main_from_entry(on_adlar, static, tohum_sayimlari)
    asama._recover_gnulib_from_fingerprints(on_adlar, static, tohum_sayimlari)
    asama._recover_elf_boilerplate(on_adlar, static, tohum_sayimlari)
    gecersiz_kilma = Path.home() / ".karadul" / "overrides"
    gecersiz_kilma_dosyalari = (sorted(p.name for p in gecersiz_kilma.glob("*.json"))
                                if gecersiz_kilma.is_dir() else [])

    cikti.mkdir(parents=True, exist_ok=True)
    gecici = Path(tempfile.mkdtemp(prefix="c_namer_", dir=cikti))
    try:
        adlandirici = cn.CVariableNamer(Config())
        bas = time.time()
        with seri_c_namer(cn):
            sonuc = adlandirici.analyze_and_rename(
                c_dizini, jsonlar["ghidra_functions.json"], jsonlar["ghidra_strings.json"],
                jsonlar["ghidra_call_graph.json"], gecici,
                pre_names=on_adlar or None,
                xrefs_json=jsonlar["ghidra_xrefs.json"] if jsonlar["ghidra_xrefs.json"].exists()
                else None)
        sure = time.time() - bas
        if not sonuc.success:
            raise RuntimeError(f"c_namer başarısız: {sonuc.errors[:5]}")
        for ad in (cn.NAMING_PROVENANCE_FILE, "naming_map.json"):
            shutil.move(str(gecici / ad), str(cikti / ad))
    finally:
        shutil.rmtree(gecici, ignore_errors=True)

    kunye = {
        "sema": SEMA_URETIM, "arac": arac_kunyesi(), "program": program,
        "calisma": str(calisma),
        "girdiler": {ad: {"yol": str(p), "sha256": sha256_dosya(p)} for ad, p in jsonlar.items()
                     if p.exists()},
        "c_dizini": {"yol": str(c_dizini), **sha256_dizin(c_dizini)},
        "c_namer_sha256": sha256_dosya(Path(cn.__file__)),
        "min_confidence": adlandirici._min_confidence,
        "pre_names": on_adlar, "tohum_sayimlari": tohum_sayimlari,
        "gecersiz_kilma_dosyalari": gecersiz_kilma_dosyalari,
        "pythonhashseed": os.environ.get("PYTHONHASHSEED"),
        "yurutucu": "seri (ProcessPoolExecutor yerine SeriYurutucu)",
        "by_strategy": sonuc.by_strategy, "total_renamed": sonuc.total_renamed,
        "genel_ad": len(sonuc.naming_map), "sure_s": round(sure, 1),
        "ciktilar": {ad: sha256_dosya(cikti / ad)
                     for ad in (cn.NAMING_PROVENANCE_FILE, "naming_map.json")},
    }
    _yaz_json(cikti / "uretim.json", kunye)
    return kunye


# --------------------------------------------------------------------------------------------
# sinifla: köken kaydı → alt kanallı kayıt tablosu


def taban_tahminleri(macho_score: Path) -> dict[str, Optional[str]]:
    """macho_score.json → {addr: pred}. Satırın başka hiçbir alanı okunmaz."""
    veri = json.loads(macho_score.read_text(encoding="utf-8"))
    return {str(satir["addr"]).lower(): satir.get("pred") for satir in veri["rows"]}


def taban_adlandirma(naming_map: Path) -> dict[str, dict[str, Any]]:
    """naming_map.json → {FUN_…: {"ad": new_name, "kaynak": source}} (yalnız fonksiyonlar)."""
    veri = json.loads(naming_map.read_text(encoding="utf-8"))
    return {k: {"ad": v.get("new_name"), "kaynak": v.get("source")}
            for k, v in (veri.get("mappings") or {}).items() if FONKSIYON_ANAHTARI_RE.match(k)}


def eslesme(ad: str, beklenen: Optional[str], var: bool) -> str:
    """Kaydın adı ile taban koşusunun adı: tam, taban_ad (yalnız çakışma eki farklı), farkli,
    taban_adsiz (satır var, ad yok) ya da satir_yok."""
    if not var:
        return "satir_yok"
    if not beklenen:
        return "taban_adsiz"
    if beklenen == ad:
        return "tam"
    if taban_ad(beklenen) == taban_ad(ad):
        return "taban_ad"
    return "farkli"


def koken_yukle(yol: Path) -> dict[str, Any]:
    veri = json.loads(yol.read_text(encoding="utf-8"))
    if veri.get("schema") != KOKEN_SEMASI or veri.get("schema_version") != KOKEN_SEMA_SURUMU:
        raise ValueError(f"{yol}: beklenmeyen köken şeması {veri.get('schema')!r} "
                         f"{veri.get('schema_version')!r}")
    return veri


def kayitlari_kur(koken: dict[str, Any], program: str, urun_esigi: float,
                  tahminler: Optional[dict[str, Optional[str]]] = None,
                  adlandirma: Optional[dict[str, dict[str, Any]]] = None) -> list[dict[str, Any]]:
    """Köken kaydının genel fonksiyon adlarından (``FUN_…``) alt kanallı kayıt satırları."""
    cnamer_esigi = float(koken.get("min_confidence", 0.0))
    satirlar: list[dict[str, Any]] = []
    for anahtar in sorted(koken.get("global") or {}, key=lambda a: (adres(a) or "", a)):
        kayit = koken["global"][anahtar]
        ad_adres = adres(anahtar)
        if ad_adres is None:
            continue
        satir: dict[str, Any] = {
            "sema": SEMA_KAYIT, "program": program, "anahtar": anahtar, "adres": ad_adres,
            "strateji": kayit.get("strategy"), "ad": kayit.get("new_name"),
            "onerilen_ad": kayit.get("proposed_name") or kayit.get("new_name"),
            "guven": kayit.get("confidence"), "kod_yolu": kayit.get("code_path"),
            "kural": kayit.get("rule"), "kanit_kaynagi": kayit.get("evidence_origin"),
            "kanit": kayit.get("evidence"), "n_aday": kayit.get("n_candidates"),
            "rakipler": [{"etiket": kanal_ya_da_strateji(r), "guven": r.get("confidence"),
                          "ad": r.get("new_name")} for r in kayit.get("runners_up") or []],
            "urun_esigini_gecer": float(kayit.get("confidence", 0.0)) >= urun_esigi,
        }
        if kayit.get("strategy") == STRATEJI:
            s = sinifla(kayit)
            satir.update(alt_kanal=s["alt_kanal"], k=s["k"], klasik_tutarli=s["klasik_tutarli"],
                         yuklemler=[a for a, d in s["yuklemler"].items() if d])
            kendisi = [s["alt_kanal"]]
            satir["halef_urun"] = halef_etiketi(halef(kayit, kendisi, urun_esigi))
            satir["halef_cnamer"] = halef_etiketi(halef(kayit, kendisi, cnamer_esigi))
        else:
            satir.update(alt_kanal=None, k=None, klasik_tutarli=None, yuklemler=[],
                         halef_urun=None, halef_cnamer=None)
        if tahminler is not None:
            var = ad_adres in tahminler
            satir["taban_pred"] = tahminler.get(ad_adres)
            satir["taban_eslesme"] = eslesme(str(satir["ad"]), tahminler.get(ad_adres), var)
        if adlandirma is not None:
            nm = adlandirma.get(anahtar)
            satir["naming_map_ad"] = nm["ad"] if nm else None
            satir["naming_map_eslesme"] = eslesme(str(satir["ad"]), nm["ad"] if nm else None,
                                                  nm is not None)
        satirlar.append(satir)
    return satirlar


def ters_eslesme(satirlar: list[dict[str, Any]], tahminler: dict[str, Optional[str]],
                 adlandirma: Optional[dict[str, dict[str, Any]]]) -> dict[str, Any]:
    """Taban koşusunda adı olup kayıtta ürün eşiğini geçen karşılığı olmayanlar."""
    gecen = {s["adres"] for s in satirlar if s["urun_esigini_gecer"]}
    gecen_anahtar = {s["anahtar"] for s in satirlar if s["urun_esigini_gecer"]}
    pred_kayitsiz = sorted(a for a, p in tahminler.items() if p and a not in gecen)
    sonuc: dict[str, Any] = {"pred_var_kayit_yok": pred_kayitsiz}
    if adlandirma is not None:
        sonuc["naming_map_c_namer_kayit_yok"] = sorted(
            k for k, v in adlandirma.items() if v["kaynak"] == "c_namer" and k not in gecen_anahtar)
    return sonuc


def _jsonl_yaz(yol: Path, satirlar: Iterable[dict[str, Any]]) -> None:
    yol.parent.mkdir(parents=True, exist_ok=True)
    with open(yol, "w", encoding="utf-8") as f:
        for s in satirlar:
            f.write(json.dumps(s, ensure_ascii=False, sort_keys=True) + "\n")


def _jsonl_oku(yol: Path) -> list[dict[str, Any]]:
    with open(yol, encoding="utf-8") as f:
        return [json.loads(satir) for satir in f if satir.strip()]


# --------------------------------------------------------------------------------------------
# kapsam: etiketsiz sayımlar


def _sayim(satirlar: Iterable[dict[str, Any]], anahtar: Callable[[dict[str, Any]], Any]
           ) -> dict[str, int]:
    c = Counter(str(anahtar(s)) for s in satirlar)
    return dict(sorted(c.items()))


def _kanal_sirali(c: dict[str, int]) -> dict[str, int]:
    return {k: c.get(k, 0) for k in ALT_KANAL_ADLARI}


def program_kapsami(satirlar: list[dict[str, Any]]) -> dict[str, Any]:
    sc = [s for s in satirlar if s["strateji"] == STRATEJI]
    sc_urun = [s for s in sc if s["urun_esigini_gecer"]]
    # Puanlanan nihai ad: ürün eşiğini geçen ve taban koşusunda adı olan satır
    sc_nihai = [s for s in sc_urun if s.get("taban_eslesme") in ("tam", "taban_ad", "farkli")]
    kanal_basina: dict[str, Any] = {}
    for kanal in ALT_KANAL_ADLARI:
        ks = [s for s in sc_urun if s["alt_kanal"] == kanal]
        kanal_basina[kanal] = {
            "n": len(ks),
            "kanit_kaynagi": _sayim(ks, lambda s: s["kanit_kaynagi"]),
            "k": _sayim(ks, lambda s: s["k"]),
            "halef_urun": _sayim(ks, lambda s: s["halef_urun"]),
            "halef_cnamer": _sayim(ks, lambda s: s["halef_cnamer"]),
            "ilk_rakip": _sayim(ks, lambda s: s["rakipler"][0]["etiket"] if s["rakipler"]
                                else "yok"),
        }
    sonuc = {
        "genel_fonksiyon_adi": len(satirlar),
        "strateji": {"cnamer_esigi": _sayim(satirlar, lambda s: s["strateji"]),
                     "urun_esigi": _sayim([s for s in satirlar if s["urun_esigini_gecer"]],
                                          lambda s: s["strateji"])},
        "alt_kanal": {"cnamer_esigi": _kanal_sirali(_sayim(sc, lambda s: s["alt_kanal"])),
                      "urun_esigi": _kanal_sirali(_sayim(sc_urun, lambda s: s["alt_kanal"])),
                      "nihai_puanlanan": _kanal_sirali(_sayim(sc_nihai, lambda s: s["alt_kanal"]))},
        "kanal_basina_urun": kanal_basina,
        "klasik_tutarsiz": sum(1 for s in sc if s["klasik_tutarli"] is False),
    }
    if any("taban_eslesme" in s for s in satirlar):
        sonuc["taban_eslesme_urun"] = _sayim([s for s in satirlar if s["urun_esigini_gecer"]],
                                             lambda s: s["taban_eslesme"])
    if any("naming_map_eslesme" in s for s in satirlar):
        sonuc["naming_map_eslesme_urun"] = _sayim(
            [s for s in satirlar if s["urun_esigini_gecer"]], lambda s: s["naming_map_eslesme"])
    return sonuc


def kapsam(dosyalar: list[Path]) -> dict[str, Any]:
    satirlar: list[dict[str, Any]] = []
    girdiler = []
    for yol in dosyalar:
        ss = _jsonl_oku(yol)
        satirlar.extend(ss)
        girdiler.append({"yol": str(yol), "sha256": sha256_dosya(yol), "satir": len(ss)})
    programlar = sorted({s["program"] for s in satirlar})
    return {
        "sema": SEMA_KAPSAM, "arac": arac_kunyesi(), "girdiler": girdiler,
        "alt_kanallar": [{"sira": i + 1, "ad": a.ad, "aciklama": a.aciklama}
                         for i, a in enumerate(ALT_KANALLAR)],
        "programlar": {p: program_kapsami([s for s in satirlar if s["program"] == p])
                       for p in programlar},
        "birlesik": program_kapsami(satirlar),
        "ornekleme_siniri": {
            "yanlis_hedefi": YANLIS_HEDEFI,
            "en_az_n_yanlis_ust_sinir": en_az_n_ust_sinir(YANLIS_HEDEFI),
            "capa_kesinlik_hedefi": CAPA_KESINLIK_HEDEFI,
            "en_az_n_kesinlik_alt_sinir": en_az_n_alt_sinir(CAPA_KESINLIK_HEDEFI),
        },
    }


def kapsam_yazdir(oz: dict[str, Any]) -> None:
    adlar = list(oz["programlar"]) + ["birlesik"]
    tablolar = {p: oz["programlar"][p] for p in oz["programlar"]}
    tablolar["birlesik"] = oz["birlesik"]
    print("alt kanal          " + "".join(f"{p:>22}" for p in adlar))
    print("                   " + "".join(f"{'0,15 / 0,7 / nihai':>22}" for _ in adlar))
    for kanal in ALT_KANAL_ADLARI:
        hucreler = []
        for p in adlar:
            ak = tablolar[p]["alt_kanal"]
            hucreler.append(f"{ak['cnamer_esigi'][kanal]:>6} /{ak['urun_esigi'][kanal]:>4} /"
                            f"{ak['nihai_puanlanan'][kanal]:>5}")
        print(f"{kanal:<19}" + "".join(f"{h:>22}" for h in hucreler))
    for p in adlar:
        t = tablolar[p]
        print(f"[{p}] strateji (ürün eşiği): {t['strateji']['urun_esigi']}; "
              f"klasik tutarsız: {t['klasik_tutarsiz']}; "
              f"taban eşleşme: {t.get('taban_eslesme_urun')}; "
              f"naming_map eşleşme: {t.get('naming_map_eslesme_urun')}")


# --------------------------------------------------------------------------------------------
# CLI


def _urun_esigi() -> float:
    from karadul.config import Config
    return float(Config().binary_reconstruction.min_naming_confidence)


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="komut", required=True)
    u = sub.add_parser("uret", help="taban koşusunun Ghidra çıktısında yalnız c_namer (seri)")
    u.add_argument("--calisma", type=Path, required=True,
                   help="static/ ve deobfuscated/ içeren çalışma dizini")
    u.add_argument("--program", required=True)
    u.add_argument("-o", "--out", type=Path, required=True, help="çıktı dizini")
    s = sub.add_parser("sinifla", help="köken kaydı → alt kanallı kayıt tablosu (JSONL)")
    s.add_argument("koken", type=Path, help="naming_provenance.json")
    s.add_argument("--program", required=True)
    s.add_argument("--macho-score", type=Path, default=None,
                   help="taban koşusunun macho_score.json'ı (yalnız addr ve pred okunur)")
    s.add_argument("--naming-map", type=Path, default=None,
                   help="taban koşusunun naming_map.json'ı (yalnız new_name ve source okunur)")
    s.add_argument("-o", "--out", type=Path, required=True)
    s.add_argument("--ters-json", type=Path, default=None,
                   help="taban adı olup kaydı olmayan adresleri bu dosyaya yaz")
    k = sub.add_parser("kapsam", help="alt kanal başına etiketsiz kapsam tablosu")
    k.add_argument("kayitlar", nargs="+", type=Path)
    k.add_argument("--json", type=Path, default=None)
    sub.add_parser("tanimlar", help="alt kanal tablosu ve betiğin sha256'sı")
    a = ap.parse_args(argv)

    if a.komut == "uret":
        kunye = uret(a.calisma, a.program, a.out)
        print(f"{a.out}: by_strategy={kunye['by_strategy']} pre_names={kunye['pre_names']} "
              f"süre={kunye['sure_s']} s")
        return 0
    if a.komut == "sinifla":
        koken = koken_yukle(a.koken)
        tahminler = taban_tahminleri(a.macho_score) if a.macho_score else None
        adlandirma = taban_adlandirma(a.naming_map) if a.naming_map else None
        satirlar = kayitlari_kur(koken, a.program, _urun_esigi(), tahminler, adlandirma)
        _jsonl_yaz(a.out, satirlar)
        sc = Counter(s["alt_kanal"] for s in satirlar if s["strateji"] == STRATEJI)
        print(f"{a.out}: {len(satirlar)} genel fonksiyon adı; string_context alt kanalları: "
              f"{dict(sorted(sc.items()))}")
        if a.ters_json and tahminler is not None:
            _yaz_json(a.ters_json, ters_eslesme(satirlar, tahminler, adlandirma))
        return 0
    if a.komut == "kapsam":
        oz = kapsam(a.kayitlar)
        kapsam_yazdir(oz)
        if a.json:
            _yaz_json(a.json, oz)
        return 0
    kunye = arac_kunyesi()
    print(f"alt kanal tanımları, sürüm {TANIM_SURUMU}; betik sha256 {kunye['betik_sha256']}")
    for i, kanal in enumerate(ALT_KANALLAR, 1):
        print(f"{i:>2}. {kanal.ad:<14} {kanal.aciklama}")
    print(f"karar: Wilson %95, yanlış hedefi {YANLIS_HEDEFI:.2f}; sıfır yanlışla doğrulama için "
          f"en az {en_az_n_ust_sinir(YANLIS_HEDEFI)} öğe; çapa kesinliği "
          f"{CAPA_KESINLIK_HEDEFI:.2f} için en az {en_az_n_alt_sinir(CAPA_KESINLIK_HEDEFI)} öğe")
    kalan = ", ".join(f"{kr} ({GUVEN_ETIKETLERI[kr]})" for kr in KARARLAR
                      if kr in URUNDE_KALAN_KARARLAR)
    susan = ", ".join(kr for kr in KARARLAR if kr not in URUNDE_KALAN_KARARLAR)
    print(f"üründe kalır: {kalan}; susturulur: {susan}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
