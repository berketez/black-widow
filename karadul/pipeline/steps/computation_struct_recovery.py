"""ComputationStructRecoveryStep -- MaxSMT struct layout kurtarma step'i.

``ComputationConfig.enable_computation_struct_recovery`` açıksa (öntanım
kapalı) Z3 MaxSMT çözücüsüyle fonksiyon başına yapı yerleşimi adayları
hesaplar. Çıktıyı ``struct_recovery`` adımı ``StructRecoveryEngine``'e aday
olarak verir (P10); koda yazım P10'un K-1 bayrağıyla kapalıdır.

Erişim çıkarımı (TIP-03, P11): yalnız LOAD/STORE erişimdir. İkisinin de
``input0``'ı adres alanı kimliğidir (sabit; ``ram`` = 433), ofset DEĞİL. Ofset
işaretçi girdisinin (``input1``) tanım zincirinden okunur: ``PTRADD(b, i, n)``
→ ``i*n``, ``INT_ADD(b, c)`` → ``c``, ``INT_SUB(b, c)`` → ``-c``, ``COPY``
geçilir. Değişken kimliği zincirin kök varnode'u + tanım sırasıdır. JSONL'de
kaydedilmeyen işlemlerle (CAST, PTRSUB, MULTIEQUAL) tanımlanan geçici
değerler çözülemez ve sayılarak atlanır (``kol_maxsmt.erisim``).

Durum: ``ctx.stats["kol_maxsmt"]`` (``karadul.computation.kol_durumu``).
"""

from __future__ import annotations

import bisect
import logging
import time
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Optional

from karadul.pipeline.context import StepContext
from karadul.pipeline.registry import Step, register_step

logger = logging.getLogger(__name__)


#: Alan ofseti sayılan en büyük bayt ofseti; ötesi dizi ya da küresel bellek sayılır.
MAX_FIELD_OFFSET = 4096
#: İşaretçi tanım zincirinde izlenen en çok adım.
_MAX_CHAIN_DEPTH = 8
_ACCESS_WIDTHS = (1, 2, 4, 8)
_IN = "in"  # tanımı fonksiyonda olmayan kök (giriş yazmacı / parametre)


@dataclass
class AccessExtraction:
    """P-code'dan çıkarılan alan erişimleri ve sayımı (TIP-03).

    ``per_function``: ``{fonksiyon: [MemoryAccess]}``.
    ``bases``: ``{var_name: künye}``; künye taban varnode'u (alan, ofset, boyut),
    tanım sırası (``"in"`` = fonksiyonda tanımı yok) ve varsa Ghidra'nın aynı
    depolamadaki yüksek düzey değişken adı (``high_name``).
    ``counts``: LOAD/STORE başına sonuç (``kabul`` ya da düşme nedeni).
    """

    per_function: dict[str, list[Any]] = field(default_factory=dict)
    bases: dict[str, dict[str, Any]] = field(default_factory=dict)
    counts: Counter = field(default_factory=Counter)


def _vn_key(vn: Any) -> tuple[str, int, int]:
    return (
        str(getattr(vn, "space", "")),
        int(getattr(vn, "offset", 0) or 0),
        int(getattr(vn, "size", 0) or 0),
    )


def _is_const(vn: Any) -> bool:
    return bool(getattr(vn, "is_constant", False)) or getattr(vn, "space", "") == "const"


def _is_unique(vn: Any) -> bool:
    return bool(getattr(vn, "is_unique", False)) or getattr(vn, "space", "") == "unique"


def _signed_const(vn: Any) -> int:
    """Sabit varnode değerini işaretli tamsayıya çevir.

    Ghidra ``Varnode.getOffset()`` Java ``long`` döndürür (64 bitte zaten
    işaretli); daha dar sabitlerde değer işaretsiz yazılmış olabilir.
    """
    value = int(getattr(vn, "offset", 0) or 0)
    size = int(getattr(vn, "size", 0) or 0)
    if value < 0 or size <= 0 or size > 8:
        return value
    bits = 8 * size
    if value >= 1 << (bits - 1):
        value -= 1 << bits
    return value


def _resolve_pointer(
    vn: Any, use_idx: int, defs: dict[tuple, list[int]], ops: list[Any],
) -> tuple[Optional[tuple[tuple[str, int, int], Any, int]], Optional[str]]:
    """İşaretçi varnode'unu taban + sabit ofsete çöz.

    Erişimden geriye, kullanımdan önceki en yakın tanımı (liste sırası = Ghidra
    sıra numarası) izler: ``PTRADD(b, i, n)`` (``i``, ``n`` sabit) ``i*n``,
    ``INT_ADD(b, c)`` ``c``, ``INT_SUB(b, c)`` ``-c`` ekler; ``COPY`` geçilir.
    Başka bir işlemle tanımlanan (LOAD, CALL …) ya da fonksiyonda tanımı
    olmayan yazmaç kök sayılır. Dönüş ``((kök anahtarı, tanım sırası, ofset), None)``
    ya da ``(None, neden)``.
    """
    total = 0
    cur, cur_idx = vn, use_idx
    for _ in range(_MAX_CHAIN_DEPTH):
        if cur is None:
            return None, "eksik_girdi"
        if _is_const(cur):
            return None, "sabit_adres"
        key = _vn_key(cur)
        idxs = defs.get(key, [])
        pos = bisect.bisect_left(idxs, cur_idx)
        if pos == 0:
            if idxs:
                # Yalnız kullanımdan SONRA tanımlanıyor (döngü taşıması):
                # hangi değerin geldiği bilinmez.
                return None, "dongu_tanimi"
            if _is_unique(cur):
                # Geçici değer kaydedilmeyen bir işlemle (CAST, PTRSUB …) tanımlanmış.
                return None, "tanimsiz_gecici"
            return (key, _IN, total), None
        d = idxs[pos - 1]
        op = ops[d]
        mnem = getattr(op, "mnemonic", "")
        ins = list(getattr(op, "inputs", []) or [])
        if mnem == "PTRADD" and len(ins) >= 3:
            if _is_const(ins[1]) and _is_const(ins[2]):
                total += _signed_const(ins[1]) * int(getattr(ins[2], "offset", 0) or 0)
                cur, cur_idx = ins[0], d
                continue
            return None, "dizi_indeksi"
        if mnem in ("INT_ADD", "INT_SUB") and len(ins) >= 2:
            a, b = ins[0], ins[1]
            if _is_const(a) and _is_const(b):
                return None, "sabit_adres"
            if _is_const(b):
                total += _signed_const(b) if mnem == "INT_ADD" else -_signed_const(b)
                cur, cur_idx = a, d
                continue
            if mnem == "INT_ADD" and _is_const(a):
                total += _signed_const(a)
                cur, cur_idx = b, d
                continue
            return None, "dizi_indeksi"
        if mnem == "COPY" and ins:
            cur, cur_idx = ins[0], d
            continue
        return (key, d, total), None
    return None, "zincir_derin"


def _high_names_by_storage(high_variables: Any) -> dict[str, str]:
    """``(register, 0x4000, 8)`` → yüksek düzey ad; aynı depolamayı paylaşan adlar düşer."""
    seen: dict[str, set[str]] = {}
    for hv in high_variables or []:
        if not isinstance(hv, dict):
            continue
        storage = str(hv.get("storage", "") or "")
        name = str(hv.get("name", "") or "")
        if storage and name:
            seen.setdefault(storage, set()).add(name)
    return {s: next(iter(n)) for s, n in seen.items() if len(n) == 1}


def extract_struct_accesses(pcode_result: Any) -> AccessExtraction:
    """P-code'dan fonksiyon başına alan erişimlerini çıkar (TIP-03 onarımı).

    Yalnız LOAD ve STORE erişimdir (PTRADD adres hesabıdır). Ghidra'da ikisinin
    de ``input0``'ı adres alanının kimliğini taşıyan sabittir (``ram`` = 433);
    eski kod onu alan ofseti sanıyordu. İşaretçi ``input1``'dir; ofset onun tanım
    zincirinden okunur (``_resolve_pointer``), değişken kimliği zincirin kök
    varnode'u ve tanım sırasıdır (aynı yazmaç farklı tanımlarda farklı değişken).
    Genişlik LOAD'da çıktı, STORE'da yazılan değer (``input2``) boyutudur.
    """
    from karadul.computation.struct_recovery import MemoryAccess

    out = AccessExtraction()
    if pcode_result is None:
        return out
    used_keys: dict[str, str] = {}
    for fn in getattr(pcode_result, "functions", []) or []:
        fn_name = str(getattr(fn, "name", "") or "")
        fn_addr = str(getattr(fn, "address", "") or "")
        fn_key = fn_name or fn_addr or "?"
        if used_keys.get(fn_key, fn_addr) != fn_addr:
            fn_key = f"{fn_key}@{fn_addr}"  # aynı adlı iki fonksiyon birleşmesin
        used_keys.setdefault(fn_key, fn_addr)
        ops = list(getattr(fn, "ops", []) or [])
        defs: dict[tuple, list[int]] = {}
        for i, op in enumerate(ops):
            o = getattr(op, "output", None)
            if o is not None:
                defs.setdefault(_vn_key(o), []).append(i)
        high_names = _high_names_by_storage(getattr(fn, "high_variables", None))
        accesses: list[Any] = []
        for i, op in enumerate(ops):
            mnem = getattr(op, "mnemonic", "")
            if mnem not in ("LOAD", "STORE"):
                continue
            out.counts["erisim"] += 1
            ins = list(getattr(op, "inputs", []) or [])
            if len(ins) < 2:
                out.counts["eksik_girdi"] += 1
                continue
            if mnem == "LOAD":
                width_vn = getattr(op, "output", None)
            else:
                width_vn = ins[2] if len(ins) >= 3 else None
            width = int(getattr(width_vn, "size", 0) or 0) if width_vn is not None else 0
            if width not in _ACCESS_WIDTHS:
                out.counts["genislik"] += 1
                continue
            resolved, reason = _resolve_pointer(ins[1], i, defs, ops)
            if resolved is None:
                out.counts[reason or "cozulemedi"] += 1
                continue
            root, def_idx, offset = resolved
            if offset < 0:
                out.counts["negatif_ofset"] += 1
                continue
            if offset >= MAX_FIELD_OFFSET:
                out.counts["buyuk_ofset"] += 1
                continue
            var_name = f"{fn_key}:{root[0]}:0x{root[1]:x}:{root[2]}@{def_idx}"
            if var_name not in out.bases:
                storage = f"({root[0]}, 0x{root[1]:x}, {root[2]})"
                out.bases[var_name] = {
                    "function": fn_key,
                    "function_address": fn_addr,
                    "space": root[0],
                    "offset": root[1],
                    "size": root[2],
                    "definition": def_idx,
                    "high_name": high_names.get(storage) if def_idx == _IN else None,
                }
            try:
                accesses.append(MemoryAccess(
                    var_name=var_name,
                    offset=offset,
                    width=width,
                    access_type="write" if mnem == "STORE" else "read",
                ))
            except ValueError:
                out.counts["gecersiz"] += 1
                continue
            out.counts["kabul"] += 1
        if accesses:
            out.per_function.setdefault(fn_key, []).extend(accesses)
    return out


def _extract_accesses_from_pcode(pcode_result: Any) -> list[Any]:
    """Düz erişim listesi (eski test / hata ayıklama uyumu)."""
    flat: list[Any] = []
    for fn_accesses in _extract_accesses_per_function(pcode_result).values():
        flat.extend(fn_accesses)
    return flat


def _extract_accesses_per_function(pcode_result: Any) -> dict[str, list[Any]]:
    """``{fonksiyon: [MemoryAccess]}`` (``extract_struct_accesses`` üstünden).

    Çözücü fonksiyon başına çağrılır (v1.10.0 Batch 6A): farklı fonksiyonların
    bilinmeyen değişkenleri tek Z3 oturumunda birbirine kilitlenmez.
    """
    return extract_struct_accesses(pcode_result).per_function


@register_step(
    name="computation_struct_recovery",
    requires=["pcode_result"],
    produces=[
        "computation_struct_result",
        "recovered_struct_candidates",
        "timing_computation_struct_recovery",
    ],
)
class ComputationStructRecoveryStep(Step):
    """Hesaplama bazli struct kurtarma -- MaxSMT layout cozucu."""

    def run(self, ctx: StepContext) -> dict[str, Any]:
        from karadul.computation.kol_durumu import (
            CALISTI, DESTEKLENMIYOR, HATA, KAPALI, STAT_MAXSMT, YAPI_ADAYI,
            kol_durumu,
        )

        pc = ctx.pipeline_context
        cfg_computation = getattr(pc.config, "computation", None)

        step_start = time.monotonic()
        empty_result: dict[str, Any] = {
            "computation_struct_result": None,
            "recovered_struct_candidates": [],
            "timing_computation_struct_recovery": 0.0,
        }

        def _empty(durum: str, neden: str, **sayac: Any) -> dict[str, Any]:
            ctx.stats[STAT_MAXSMT] = kol_durumu(durum, neden, YAPI_ADAYI, **sayac)
            empty_result["timing_computation_struct_recovery"] = round(
                time.monotonic() - step_start, 3,
            )
            return empty_result

        # Feature flag
        if cfg_computation is None or not getattr(
            cfg_computation, "enable_computation_struct_recovery", False,
        ):
            return _empty(
                KAPALI,
                "bayrak kapalı (computation.enable_computation_struct_recovery)",
            )

        pcode_result = ctx.artifacts.get("pcode_result")
        if pcode_result is None:
            logger.debug(
                "computation_struct_recovery: pcode_result yok, atlaniyor",
            )
            return _empty(DESTEKLENMIYOR, "P-code yok (pcode_result)")

        try:
            from karadul.computation.struct_recovery import StructLayoutSolver

            # v1.10.0 Batch 6A: fonksiyon başına çözüm (farklı fonksiyonların
            # bilinmeyen değişkenleri tek Z3 oturumunda birbirine kilitlenmez).
            # TIP-03: ofset LOAD/STORE işaretçisinin tanım zincirinden okunur.
            extraction = extract_struct_accesses(pcode_result)
            per_fn_accesses = extraction.per_function
            access_counts = {k: int(v) for k, v in sorted(extraction.counts.items())}
            if not per_fn_accesses:
                logger.info(
                    "computation_struct_recovery: pcode'dan access cikmadi",
                )
                return _empty(
                    CALISTI, "P-code'da sabit ofsetli alan erişimi bulunmadı",
                    erisim=access_counts, fonksiyon=0, aday=0,
                )

            # Fonksiyon başına ayrı StructLayoutSolver (temiz Z3 kapsamı).
            # ``enable_parallel_solve`` açıksa fonksiyon içinde birden çok
            # bileşen ProcessPool ile çözülür; tek bileşende sıralı yola düşer.
            all_candidates: list[Any] = []
            total_accesses = 0
            total_explained = 0
            total_solver_time = 0.0
            per_fn_results: dict[str, Any] = {}
            timeout_per_fn = cfg_computation.struct_solver_timeout
            use_parallel = getattr(cfg_computation, "enable_parallel_solve", False)
            for fn_key, accesses in per_fn_accesses.items():
                if not accesses:
                    continue
                solver = StructLayoutSolver(cfg_computation)
                if use_parallel:
                    fn_result = solver.solve_parallel(
                        accesses=accesses,
                        max_time_seconds=timeout_per_fn,
                    )
                else:
                    fn_result = solver.solve_from_raw(
                        accesses=accesses,
                        max_time_seconds=timeout_per_fn,
                    )
                per_fn_results[fn_key] = fn_result
                fn_candidates = list(fn_result.assigned_structs.values())
                all_candidates.extend(fn_candidates)
                total_accesses += len(accesses)
                explained_here = len(accesses) - len(fn_result.unknown_accesses)
                total_explained += max(0, explained_here)
                total_solver_time += fn_result.solver_time_seconds

            # Açıklanan erişim oranı: kalibre güven DEĞİL, yalnız oran.
            aggregate_confidence = (
                total_explained / total_accesses if total_accesses else 0.0
            )
            ctx.stats["computation_struct_solved"] = len(all_candidates)
            ctx.stats["computation_struct_confidence"] = round(
                aggregate_confidence, 3,
            )
            ctx.stats["computation_struct_functions"] = len(per_fn_results)
            ctx.stats[STAT_MAXSMT] = kol_durumu(
                CALISTI, "", YAPI_ADAYI,
                erisim=access_counts,
                fonksiyon=len(per_fn_results),
                aday=len(all_candidates),
                aciklanan_erisim=total_explained,
                toplam_erisim=total_accesses,
            )
            logger.info(
                "MaxSMT struct recovery (per-fn): %d fn, %d struct aday, "
                "%.0f%% access acilanmis, %.2fs toplam solver",
                len(per_fn_results),
                len(all_candidates),
                aggregate_confidence * 100,
                total_solver_time,
            )
            timing = round(time.monotonic() - step_start, 3)
            ctx.stats["timing_computation_struct_recovery"] = timing
            # ``computation_struct_result`` = {fonksiyon: RecoveredStructLayout};
            # yapı motoru (``struct_recovery`` adımı) aday olarak okur (P10).
            return {
                "computation_struct_result": per_fn_results,
                "recovered_struct_candidates": all_candidates,
                "timing_computation_struct_recovery": timing,
            }
        except ImportError as exc:
            logger.debug(
                "computation_struct_recovery import hatasi (z3 yok?): %s", exc,
            )
            return _empty(DESTEKLENMIYOR, f"bağımlılık yok: {exc}")
        except Exception as exc:
            logger.warning(
                "computation_struct_recovery hatasi (atlaniyor): %s", exc,
            )
            ctx.errors.append(f"computation_struct_recovery: {exc}")
            return _empty(HATA, f"{type(exc).__name__}: {exc}")
