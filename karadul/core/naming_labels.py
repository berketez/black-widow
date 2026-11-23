"""Ad etiketi sözlüğü ve köken kaydının ortak adları (plan v2.2 N1 adım 3).

Çekirdek modül: ağır bağımlılığı yoktur; biçimlendirici, arayüz sunucusu ve
``karadul.reconstruction`` buradan içe aktarır. Değerler N0b'nin sözlüğüyle aynı yazılır
(``scripts/measurement/alt_kanal.py`` ``GUVEN_ETIKETLERI``); eşitlik testle kilitlidir.

Etiketin anlamı:
  - ``kesin``: ad ikilinin kendi ad yuvasından okundu ve o kanalın tam ad kesinliği ön kayıtlı
    ölçümde hedefi (≥ %95) tuttu;
  - ``doğrulandı``: kanal ölçüldü ve yanlış oranı hedefin altında (bugün hiçbir kanal üretmiyor);
  - ``doğrulanmadı``: kanal ölçülmedi ya da ölçüm hedefi göstermedi;
  - ``üst veriden`` (P-ÜV6a, KARARLAR A-10 / A-27): ad ikilinin dil üst verisinden (Go ``pclntab``,
    Objective-C yöntem listesi) okundu; derleyicinin yazdığı hâliyle kanal düzeyi kesinliği ölçüldü
    (``MEASURED_METADATA_PRECISION``), ama ad metni çalışma için zorunlu olmadığından değiştirilebilir:
    ``kesin`` DEĞİLDİR, doğrulanamaz.
Analistin elle verdiği ad etiket taşımaz.
"""
from __future__ import annotations

import math
from typing import Any, Mapping, Optional

LABEL_CERTAIN = "kesin"
LABEL_VERIFIED = "doğrulandı"
LABEL_UNVERIFIED = "doğrulanmadı"
LABEL_METADATA = "üst veriden"
NAME_LABELS = (LABEL_CERTAIN, LABEL_VERIFIED, LABEL_UNVERIFIED, LABEL_METADATA)

# c_namer'ın ``naming_map.json``'ın yanına yazdığı köken kaydı
NAMING_PROVENANCE_FILE = "naming_provenance.json"
PROVENANCE_GLOBAL = "global"

# Köken kaydındaki strateji ve ön ad türü adları
STRATEGY_KS1 = "ks1"
STRATEGY_STRING_CONTEXT = "string_context"
PRE_NAME_KIND_MANUAL = "elle"        # analistin verdiği ad
PRE_NAME_KIND_MAIN = "main_giris"    # yükleyici bilgisinden (``__libc_start_main``) kurtarılan main
PRE_NAME_KIND_KS1 = "ks1"            # KS-1 kesin çapası
# Künyesinde ``exact`` olan ön ad temizlenmeden yazılır; ad bu biçimde değilse künye yok sayılır.
EXACT_NAME_PATTERN = r"[A-Za-z_][A-Za-z0-9_]*"

SOURCE_C_NAMER = "c_namer"

# P12a / AD-07: ön ad kanallarının ölçülmüş tam ad kesinliği. Eskiden her ön ada kanıt gücünden
# bağımsız sabit 0,95 yazılıyordu (gnulib parmak izinin ölçülmüş kesinliği %73,7 iken).
# Kaynak: ``docs/arge/2026-11-10_n1_adim3/urun_olcumu_yeni2.md`` "Kanal başına" (geliştirme seti,
# 119 ikili, HEAD 2be12ed, hüküm tam eşitlik). Değer: (doğru, ad verilen, Wilson %95 alt sınırı;
# 3 basamak). Güven olarak ALT SINIR yazılır: tek ölçümün belirsizliği taşınsın, küçük n'li kanal
# (3/3) yüksek görünmesin. Tabloda olmayan kanal ölçülmemiştir: güven yazılmaz (``None``).
# Kanal anahtarı ``provenance_channel`` biçimindedir. Alt sınırların ``baglama.wilson`` ile aynı
# olduğunu ``tests/test_p12a_on_ad_guveni.py`` kilitler. Kanal davranışı değişince (ör. gnulib
# koşulu, AD-03) tablo yeniden ölçülmelidir.
MEASURED_PRECISION_SOURCE = "docs/arge/2026-11-10_n1_adim3/urun_olcumu_yeni2.md@2be12ed"
MEASURED_PRE_NAME_PRECISION: dict[str, tuple[int, int, float]] = {
    "on_ad:gnulib": (621, 843, 0.706),
    "on_ad:elf_onyuk": (458, 458, 0.992),
    "on_ad:main_giris": (110, 110, 0.966),
    "ks1:func_kalibi": (246, 259, 0.916),
    "ks1:func_aktarma": (33, 33, 0.896),
    "ks1:func_kalibi+func_aktarma": (3, 3, 0.438),
    "ks1:assert_ust": (5, 7, 0.359),
}


def measured_channel_confidence(channel: Optional[str]) -> Optional[float]:
    """Kanalın ölçülmüş kesinliğinin Wilson %95 alt sınırı; ölçülmemiş kanalda ``None``."""
    row = MEASURED_PRE_NAME_PRECISION.get(channel) if channel else None
    return row[2] if row else None


def provenance_confidence(record: Optional[Mapping[str, Any]]) -> Optional[float]:
    """Köken kaydındaki gerçek güven; kayıt ya da sayı yoksa ``None`` (uydurma değer yazılmaz)."""
    if not record:
        return None
    value = record.get("confidence")
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)


def provenance_label(record: Optional[Mapping[str, Any]]) -> Optional[str]:
    """Kaydın etiketi.

    Kayıtta geçerli bir ``label`` varsa o; elle verilen ad etiketsizdir (``None``); etiket
    taşımayan ya da hiç bulunmayan kayıt ``doğrulanmadı``'dır: ölçülmemiş ad "kesin" görünmez.
    """
    if not record:
        return LABEL_UNVERIFIED
    label = record.get("label")
    if label in NAME_LABELS:
        return str(label)
    if record.get("pre_name_kind") == PRE_NAME_KIND_MANUAL:
        return None
    return LABEL_UNVERIFIED


def provenance_channel(record: Optional[Mapping[str, Any]]) -> Optional[str]:
    """Adın geldiği kanal: ``ks1:<satırlar>``, ``string_context/<alt kanal>``, ``on_ad:<tür>``
    ya da strateji adı; kayıt yoksa ``None``."""
    if not record:
        return None
    strategy = record.get("strategy")
    if strategy == STRATEGY_KS1:
        rows = (record.get(STRATEGY_KS1) or {}).get("satirlar") or []
        return f"{STRATEGY_KS1}:{'+'.join(str(r) for r in rows)}" if rows else STRATEGY_KS1
    kind = record.get("pre_name_kind")
    if kind:
        return f"on_ad:{kind}"
    if record.get(METADATA_CHANNEL_FIELD):
        return f"{CHANNEL_METADATA_PREFIX}:{record[METADATA_CHANNEL_FIELD]}"
    if strategy == STRATEGY_STRING_CONTEXT and record.get("sub_channel"):
        return f"{STRATEGY_STRING_CONTEXT}/{record['sub_channel']}"
    return str(strategy) if strategy else None


def provenance_evidence(record: Optional[Mapping[str, Any]]) -> Any:
    """Kısa kanıt: KS-1'de rol ve kanıt sayısı, öbür kanallarda kanıt dizgisi; yoksa ``None``."""
    if not record:
        return None
    if record.get("strategy") == STRATEGY_KS1:
        ks1 = record.get(STRATEGY_KS1) or {}
        return {"rol": ks1.get("rol"), "kanit_sayisi": len(ks1.get("kanitlar") or [])}
    evidence = record.get("evidence")
    return evidence if isinstance(evidence, str) and evidence else None


# Bayrak ön paketi (KARARLAR A-2, A-13, A-14; 2026-11-20): ad eşiğinin TEK tanımı. Kanal
# paketleri (PK-1, PK-4, P-ÜV6, ÖK-4b …) bu iki sabiti içe aktarır, kendi eşiğini yazmaz.
MALIYET_ORANI_L: int = 10
"""Maliyet oranı L (KARARLAR A-2): yanlış ad, eksik adın L katı kötü sayılır."""

AD_ESIGI: float = MALIYET_ORANI_L / (MALIYET_ORANI_L + 1)
"""Ad eşiği = L / (L + 1) = 10 / 11 = 0,90909… (KARARLAR A-2, A-13, A-14).

A-13'teki "0,909" bu kesrin yuvarlanmış yazımıdır; karşılaştırma kesrin kendisiyle yapılır.
``1 − e / L`` (0,900) kullanılmaz: kanıt satırının değeri (e) ölçülmedi.

Kural: bir kanal öntanımda ad yazar ancak ölçülmüş tam ad kesinliğinin Wilson %95 alt
sınırı ≥ AD_ESIGI ise; sayım örnek düzeyinde ve yön başına (hedef → başvuru) yapılır ve
kanal en az 3 bağımsız programda ölçülmüş olmalıdır. Şartı sağlamayan kanal ad yerine
kanıt satırı yazar ya da bayrak arkasında kalır (A-14). Var olan ön ad kanalları (gnulib,
ELF önyükü, ``main``) set dışı ölçümler gelene kadar ad yazmayı sürdürür; geriye dönük
susturma yok.
"""


# P-ÜV6a (KARARLAR A-10, A-13, A-27, A-28; 2026-11-23): üst veri ad kanalları.
# Kaynak adları ``stats["naming_channels"]`` ve birleştiricinin köken kaydında aynı yazılır.
SOURCE_GO_PCLNTAB = "go_pclntab"
SOURCE_OBJC_METHOD = "objc_method"
METADATA_SOURCES: tuple[str, ...] = (SOURCE_GO_PCLNTAB, SOURCE_OBJC_METHOD)
SOURCE_METADATA = "ust_veri"     # ad haritasının ``sources`` listesindeki adı

# Köken kaydı alanları (birleştiricinin ``name_merger`` kararları ve ad haritası kaydı).
METADATA_CHANNEL_FIELD = "ust_veri_kanali"      # go_pclntab / objc_method
ORIGINAL_NAME_FIELD = "ozgun_ad"                # derleyicinin yazdığı ad (C tanımlayıcısı değil)
METADATA_CHECK_FIELD = "ust_veri_dogrulama"     # cift_kaynak / tek_kaynak / tutarsiz / olculmedi
METADATA_EVIDENCE_FIELD = "ust_veri_kanit"      # ad yazılmayan üst veri kayıtları (kanıt satırı)
CHANNEL_METADATA_PREFIX = "ust_veri"            # ``provenance_channel`` biçimi: ust_veri:<kaynak>
# ``ust_veri_dogrulama`` değerleri (plan P-ÜV6 kalem 5). Tutarlılık denetimi (P-ÜV7) main'de
# değil: bugün her kayıt ``olculmedi``; öbür değerler P-ÜV6b'de yazılır.
METADATA_CHECK_UNMEASURED = "olculmedi"

# Ölçülmüş kanal düzeyi kesinliği: (doğru, ad verilen, Wilson %95 alt sınırı). Değerler SINAMA
# ikililerinin soyulmuş kopyasında kanal ↔ özgün ikilinin sembol tablosu ölçümünden (P-ÜV8 tanımı;
# Ghidra'sız): Go docker-compose (``ustveri/P-UV1.md`` H2 sınama yarısı), ObjC iTerm2 arm64
# (``ustveri/P-UV2.md`` H2). Alt sınır ``baglama.wilson`` ile hesaplanır ve 4 basamağa AŞAĞI
# yuvarlanır (yukarı yuvarlama 1,0 yazardı: kesinlik görüntüsü); eşitliği
# ``tests/test_puv6a_baglama.py`` kilitler. Bu kaynaklar ``UNMEASURED_SOURCES``'ta değildir.
# A-14: öntanımda açılmak için en az 3 bağımsız program gerekir; bugün kanal başına 2 program
# ölçüldü (Go: docker-cli, docker-compose; ObjC: terminal-notifier, iTerm2) → bayraklar kapalı.
MEASURED_METADATA_SOURCE = (
    "docs/arge/2026-11-19_mythos/ustveri/P-UV1.md (docker-compose), P-UV2.md (iTerm2)")
MEASURED_METADATA_PRECISION: dict[str, tuple[int, int, float]] = {
    SOURCE_GO_PCLNTAB: (90077, 90077, 0.9999),
    SOURCE_OBJC_METHOD: (33611, 33611, 0.9998),
}
METADATA_MEASURED_PROGRAMS: dict[str, tuple[str, ...]] = {
    SOURCE_GO_PCLNTAB: ("docker-cli", "docker-compose"),
    SOURCE_OBJC_METHOD: ("terminal-notifier", "iTerm2"),
}


def floor_confidence(value: float, digits: int = 4) -> float:
    """Güveni ``digits`` basamağa AŞAĞI yuvarla (alt sınır yukarı yuvarlanıp 1,0 görünmesin)."""
    scale = 10 ** digits
    return math.floor(value * scale) / scale


def metadata_confidence(source: Optional[str]) -> Optional[float]:
    """Üst veri kanalının ölçülmüş kesinliğinin Wilson alt sınırı; tabloda yoksa ``None``."""
    row = MEASURED_METADATA_PRECISION.get(source) if source else None
    return row[2] if row else None


def metadata_writes_names(source: Optional[str]) -> bool:
    """Kanal ad yazabilir mi (A-2 / A-13): ölçülmüş alt sınır ≥ ``AD_ESIGI``; değilse kanıt satırı."""
    conf = metadata_confidence(source)
    return conf is not None and conf >= AD_ESIGI
