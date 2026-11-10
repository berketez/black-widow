"""Ad etiketi sözlüğü ve köken kaydının ortak adları (plan v2.2 N1 adım 3).

Çekirdek modül: ağır bağımlılığı yoktur; biçimlendirici, arayüz sunucusu ve
``karadul.reconstruction`` buradan içe aktarır. Değerler N0b'nin sözlüğüyle aynı yazılır
(``scripts/measurement/alt_kanal.py`` ``GUVEN_ETIKETLERI``); eşitlik testle kilitlidir.

Etiketin anlamı:
  - ``kesin``: ad ikilinin kendi ad yuvasından okundu ve o kanalın tam ad kesinliği ön kayıtlı
    ölçümde hedefi (≥ %95) tuttu;
  - ``doğrulandı``: kanal ölçüldü ve yanlış oranı hedefin altında (bugün hiçbir kanal üretmiyor);
  - ``doğrulanmadı``: kanal ölçülmedi ya da ölçüm hedefi göstermedi.
Analistin elle verdiği ad etiket taşımaz.
"""
from __future__ import annotations

from typing import Any, Mapping, Optional

LABEL_CERTAIN = "kesin"
LABEL_VERIFIED = "doğrulandı"
LABEL_UNVERIFIED = "doğrulanmadı"
NAME_LABELS = (LABEL_CERTAIN, LABEL_VERIFIED, LABEL_UNVERIFIED)

# c_namer'ın ``naming_map.json``'ın yanına yazdığı köken kaydı
NAMING_PROVENANCE_FILE = "naming_provenance.json"
PROVENANCE_GLOBAL = "global"

# Köken kaydındaki strateji ve ön ad türü adları
STRATEGY_KS1 = "ks1"
STRATEGY_STRING_CONTEXT = "string_context"
PRE_NAME_KIND_MANUAL = "elle"

SOURCE_C_NAMER = "c_namer"


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
