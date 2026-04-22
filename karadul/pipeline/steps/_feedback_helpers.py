"""Feedback loop pure helper'lari — test edilebilir sade fonksiyonlar.

stages.py L2079-3346 `_execute_binary` feedback loop'unun yardimci
hesaplamalari. FeedbackLoopStep icin orchestration'dan ayrilmis parcalar:

- build_cg_neighbors: call graph adjacency index (iter'lar arasi shared).
- extract_named_set: bir iter'in isimlendirdigi sembolleri al.
- check_convergence: yeni isim orani esigin altindaysa True.
- compute_incremental_files: iter>0'da islenecek dosyalar (degisen + 1-hop).
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def build_cg_neighbors(
    call_graph_data: dict | None,
) -> dict[str, set[str]]:
    """Call graph adjacency index'i insa et.

    stages.py L2086-2106 davranisinin birebir kopyasi. caller/callee listesi
    dict olabilir ya da string — her iki forma da sakin.

    Args:
        call_graph_data: Ghidra call_graph JSON'dan parse edilmis dict
            ({func_name: {"callers": [...], "callees": [...]}, ...}).

    Returns:
        {func_name: {neighbor1, neighbor2, ...}} — symmetric (hem caller
        hem callee yonu dolduruldu).
    """
    neighbors: dict[str, set[str]] = {}
    if not call_graph_data:
        return neighbors

    for fn, node in call_graph_data.items():
        if not isinstance(node, dict):
            continue
        bucket = neighbors.setdefault(fn, set())
        for c in node.get("callees", []):
            name = c.get("name", c) if isinstance(c, dict) else str(c)
            if name:
                bucket.add(name)
                neighbors.setdefault(name, set()).add(fn)
        for c in node.get("callers", []):
            name = c.get("name", c) if isinstance(c, dict) else str(c)
            if name:
                bucket.add(name)
                neighbors.setdefault(name, set()).add(fn)

    return neighbors


def extract_named_set(
    *,
    naming_result: Any,
    final_naming_map: dict[str, str] | None,
) -> set[str]:
    """Bir iterasyonda isimlendirilen sembollerin kumesini al.

    Orijinal kodda (L2920) Name Merger sonrasi `final_naming_map.keys()`
    kumeyi olusturuyor. Eger Name Merger calismadiysa naming_result'tan
    dogrudan al.

    Args:
        naming_result: CVariableNamer sonucu (naming_map'i olabilir).
        final_naming_map: NameMerger sonrasi birlestirilmis map (varsa).

    Returns:
        Isimlendirilmis orijinal sembol adlari kumesi.
    """
    if final_naming_map:
        return set(final_naming_map.keys())
    if naming_result is not None and hasattr(naming_result, "naming_map"):
        try:
            return set(naming_result.naming_map.keys())
        except Exception:  # pragma: no cover
            logger.debug("naming_result.naming_map okunamadi", exc_info=True)
    return set()


def check_convergence(
    *,
    iter_index: int,
    prev_named: set[str],
    current_named: set[str],
    threshold: float,
    min_absolute_new: int = 1,
) -> tuple[bool, str]:
    """Iterasyon sonrasi convergence kontrolu.

    v1.10.0 M2 T6 bug fix: NameMerger bossa (prev_named = empty) eski kod
    ZeroDivision'u try/except ile yutuyor ve converged=True donuyordu. Bu
    "empty merger" early-exit hatasiydi. Yeni davranis:

    Kurallar:
      - iter_index == 0: DAIMA False (ilk iter tamamlanmali).
      - iter_index >= 1 AND |prev_named| == 0 AND |current_named| == 0:
        iki iter boyunca hic naming verisi yok -> True
        (reason="no_naming_data_two_iters").
      - iter_index >= 1 AND |prev_named| == 0 AND |current_named| > 0:
        olcum yapamiyoruz ama yeni sinyal var -> False
        (reason="empty_prev_first_signal"). BUG FIX: eski kod burada
        `current_named - prev_named == current_named` uretip 1.0 ratio
        ile "not_converged" donuyordu; ama len(prev_named)==0 iken once
        try/except ZeroDivision yolunda tutulu hata silinip converged
        True uretilen baska kod yollari vardi (stages.py). Simdi explicit.
      - iter_index >= 1 AND new_names < min_absolute_new: True
        (reason="no_new_names"). min_absolute_new=1 default -> hic yeni
        isim yoksa converge.
      - iter_index >= 1 AND |new_names| / |prev_named| < threshold: True
        (reason="convergence_ratio_{ratio:.3f}"). Strict <, sinirda False.
      - Diger: False (reason="continuing").

    Args:
        iter_index: 0-tabanli iterasyon index'i.
        prev_named: Bir onceki turun isimlendirdigi sembol kumesi.
        current_named: Bu turun isimlendirdigi sembol kumesi.
        threshold: Esik orani (ornek 0.01 = %1). Ratio bunun strictly
            altindaysa converge.
        min_absolute_new: Minimum mutlak yeni isim sayisi. Bu altindaysa
            (varsayilan 1 => hic yeni isim yok) converge kabul edilir.

    Returns:
        (converged, reason)
    """
    if iter_index == 0:
        return False, "first_iteration"

    new_names = current_named - prev_named

    if len(prev_named) == 0:
        # EMPTY MERGER FIX: onceki iter boss. Ratio hesaplanamaz.
        # Iki iter ust uste boss -> gercekten veri yok, converge.
        # Aksi halde ilk anlamli sinyal -> devam et.
        if len(current_named) == 0:
            return True, "no_naming_data_two_iters"
        return False, "empty_prev_first_signal"

    if len(new_names) < min_absolute_new:
        return True, "no_new_names"

    ratio = len(new_names) / len(prev_named)
    if ratio < threshold:
        return True, f"convergence_ratio_{ratio:.3f}"

    return False, "continuing"


def compute_incremental_files(
    *,
    iter_index: int,
    newly_named: set[str],
    cg_neighbors: dict[str, set[str]],
    current_cfiles: dict[str, Path],
    func_count: int,
) -> list[Path] | None:
    """Sonraki iterasyonda islenecek dosya setini hesapla.

    stages.py L3273-3326 davranisinin birebir kopyasi.

    iter_index == 0 baslarken (yani iter 1'e hazirlik) ve newly_named bossa
    veya cg_neighbors bossa: None (full processing).

    Aksi halde:
    1. affected = newly_named ∪ {neighbor | sembol ∈ newly_named'in 1-hop'u}
    2. current_cfiles'tan affected ile stem eslesen dosyalari topla.
    3. Eger set cok buyukse (> %80 tum fonksiyon sayisinin) -> None (full).
    4. Aksi halde list.

    Args:
        iter_index: Su anki iterasyon (BITMIS olanin) 0-tabanli index'i;
            sonraki iter_index+1 icin incremental hesaplanir.
        newly_named: Bu turda yeni eklenen sembol adlari.
        cg_neighbors: build_cg_neighbors ciktisi.
        current_cfiles: Ad -> Path mapping (decompiled_dir'deki .c'ler).
        func_count: Toplam fonksiyon (dosya) sayisi (yuzde hesabi icin).

    Returns:
        Dosya listesi veya None (full processing sinyali).
    """
    if not newly_named or not cg_neighbors:
        return None

    affected: set[str] = set()
    for sym in newly_named:
        affected.add(sym)
        affected.update(cg_neighbors.get(sym, set()))

    next_incr: list[Path] = []
    for fname, fpath in current_cfiles.items():
        stem = fpath.stem  # "FUN_001234" from "FUN_001234.c"
        if stem in affected:
            next_incr.append(fpath)

    if not next_incr:
        return None

    if len(next_incr) > 0.80 * func_count:
        logger.info(
            "Incremental set too large (%d/%d > 80%%), falling back to full",
            len(next_incr), func_count,
        )
        return None

    # Cok kucuk (< %2) veya ortada ise kabul et.
    return next_incr
