"""CTypeRecoverer extension helpers -- harici struct kaynaklarini birlestir.

Bu modul ``c_type_recoverer.py``'nin mevcut ``recover()`` akisina dokunmadan
opsiyonel struct kaynaklarini (TypeForge, ileride TRex vb.) mevcut
``RecoveredStruct`` listesiyle birlestirir.

Tasarim karari (v1.10.0 M3 T8):
    - Mevcut merge (computation_structs, c_type_recoverer.py L861-901) isimle
      atliyor: ayni isim varsa eski kalir, yeni atlanir. Bu guvenli ama
      yuksek-guven yeni kaynaklar icin kayip.
    - TypeForge icin FARKLI kural: **guven karsilastirmasi**.
      - TypeForge conf > mevcut min_conf esigi: adayla merge dusun.
      - Ayni isim varsa: TypeForge conf > mevcut avg field conf -> TypeForge kazanir.
      - Tie-break: **TypeForge kazanir** (re-analyst kararina gore).

Disariya acik API:
    - merge_typeforge_structs(existing, tf_result, min_conf) -> (merged, stats)

Bu fonksiyon ``CTypeRecoverer.recover_types_with_typeforge`` tarafindan cagrilir.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from karadul.analyzers.typeforge_adapter import TypeForgeResult, TypeForgeStruct
from karadul.reconstruction.c_type_recoverer import RecoveredStruct, StructField

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Merge sonuc raporu
# ---------------------------------------------------------------------------


@dataclass
class TypeForgeMergeStats:
    """Merge raporu (test + log amacli)."""

    added: int = 0           # Yeni eklenen TypeForge struct sayisi
    replaced: int = 0        # TypeForge'un mevcudu degistirdigi sayi
    kept_existing: int = 0   # Mevcut kazandi (conf karsilastirmasi)
    filtered_low_conf: int = 0  # min_confidence esigini gecemeyen
    notes: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Donusum yardimcilari
# ---------------------------------------------------------------------------


def _infer_field_size(field_dict: dict[str, Any]) -> int:
    """Field size'i tahmin et (field payload'unda 'size' yoksa tip-bazli)."""
    explicit = field_dict.get("size")
    if isinstance(explicit, int) and explicit > 0:
        return explicit
    # Tip-bazli (kaba ama makul) tahmin
    type_str = str(field_dict.get("type", "")).lower()
    if "char" in type_str and "*" not in type_str:
        return 1
    if "short" in type_str or "int16" in type_str:
        return 2
    if "int32" in type_str or (type_str.startswith("int") and "64" not in type_str):
        return 4
    if "int64" in type_str or "long" in type_str or "*" in type_str:
        return 8
    # Default (x64 word)
    return 8


def typeforge_to_recovered(tf: TypeForgeStruct) -> RecoveredStruct:
    """TypeForgeStruct -> RecoveredStruct cevirimi.

    Field'lar offset'e gore sirali dondurulur. TypeForge confidence
    her field'a yansitilir (TypeForge field-bazli degil, struct-bazli
    confidence uretir -- bu yuzden tum field'lara ayni deger atanir).
    """
    fields: list[StructField] = []
    for idx, f in enumerate(tf.fields):
        offset = f.get("offset")
        if not isinstance(offset, int):
            continue
        name = f.get("name")
        if not isinstance(name, str) or not name:
            name = f"field_{offset:02x}"
        type_str = f.get("type")
        if not isinstance(type_str, str) or not type_str:
            type_str = "undefined8"
        size = _infer_field_size(f)
        fields.append(
            StructField(
                offset=offset,
                name=name,
                type=type_str,
                size=size,
                confidence=tf.confidence,
            )
        )
        # Unused index var -- lint warning'i engelle
        del idx
    fields.sort(key=lambda sf: sf.offset)
    return RecoveredStruct(
        name=tf.name,
        fields=fields,
        total_size=tf.size,
        source_functions=[],  # TypeForge kaynak fonksiyon saglamiyor
        alignment=8,
    )


def _avg_field_confidence(rs: RecoveredStruct) -> float:
    """RecoveredStruct icin ortalama field confidence (fallback 0.0)."""
    if not rs.fields:
        return 0.0
    total = sum(f.confidence for f in rs.fields)
    return total / len(rs.fields)


# ---------------------------------------------------------------------------
# Merge ana fonksiyonu
# ---------------------------------------------------------------------------


def merge_typeforge_structs(
    existing: list[RecoveredStruct],
    tf_result: TypeForgeResult,
    min_confidence: float,
) -> tuple[list[RecoveredStruct], TypeForgeMergeStats]:
    """TypeForge struct'larini mevcut listeyle birlestir.

    Kurallar:
        1. TypeForge conf < min_confidence -> elenir, filtered_low_conf++
        2. TypeForge.name mevcut listede YOK -> eklenir, added++
        3. TypeForge.name mevcut listede VAR:
            a) TypeForge conf > mevcut avg field conf -> degistirilir, replaced++
            b) TypeForge conf == mevcut (tie) -> TypeForge kazanir, replaced++
            c) TypeForge conf < mevcut -> mevcut kalir, kept_existing++

    Args:
        existing: Ghidra/pattern/computation kaynakli mevcut RecoveredStruct listesi.
        tf_result: TypeForgeAdapter.analyze_binary() sonucu.
        min_confidence: Esik (0.0-1.0). TypeForge struct'larinin kabul
            edilmesi icin minimum guven.

    Returns:
        (merged_list, stats): Birlestirilmis yeni liste + istatistik raporu.

    Not:
        - Girdi listesi mutate edilmez (saf fonksiyon).
        - Liste sirasi: mevcut sira korunur, TypeForge yeni eklemeleri sona.
          Replace durumunda ayni pozisyonda kalir.
    """
    stats = TypeForgeMergeStats()
    # Mevcut index'leme (name -> list index)
    by_name: dict[str, int] = {s.name: i for i, s in enumerate(existing)}
    # Kopya olustur (dis listeyi mutate etme)
    merged: list[RecoveredStruct] = list(existing)

    for tf in tf_result.structs:
        if tf.confidence < min_confidence:
            stats.filtered_low_conf += 1
            stats.notes.append(
                f"low_conf({tf.confidence:.2f}<{min_confidence:.2f}):{tf.name}"
            )
            continue

        candidate = typeforge_to_recovered(tf)

        if tf.name not in by_name:
            merged.append(candidate)
            by_name[tf.name] = len(merged) - 1
            stats.added += 1
            continue

        # Conflict -- conf karsilastirmasi
        idx = by_name[tf.name]
        current = merged[idx]
        current_conf = _avg_field_confidence(current)
        tf_conf = tf.confidence

        if tf_conf >= current_conf:
            # Tie veya typeforge yuksek -> TypeForge kazanir
            merged[idx] = candidate
            stats.replaced += 1
            stats.notes.append(
                f"replaced({tf_conf:.2f}>={current_conf:.2f}):{tf.name}"
            )
        else:
            stats.kept_existing += 1
            stats.notes.append(
                f"kept({tf_conf:.2f}<{current_conf:.2f}):{tf.name}"
            )

    if stats.added or stats.replaced or stats.kept_existing:
        logger.info(
            "TypeForge merge: +%d added, %d replaced, %d kept, %d filtered",
            stats.added, stats.replaced, stats.kept_existing,
            stats.filtered_low_conf,
        )

    return merged, stats


__all__ = [
    "TypeForgeMergeStats",
    "typeforge_to_recovered",
    "merge_typeforge_structs",
]
