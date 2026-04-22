"""ComputationStructRecoveryStep -- MaxSMT struct layout kurtarma step'i.

v1.10.0 M4 entegrasyonu: ``karadul.computation.struct_recovery`` paketini
pipeline'a bagliyor. Feature flag
``ComputationConfig.enable_computation_struct_recovery`` True ise Z3 MaxSMT
cozucusu ile struct layout adaylarini hesaplar; ESKI StructRecoveryEngine'a
aday listesi olarak aktarilmak uzere artifact'larda yayinlar.

Tasarim kararlari:
    - Eski StructRecoveryEngine ile CAKISMAZ, yerine onu besler
      (Berke'nin karari: "MaxSMT ciktisi eski engine'e candidate olarak gecsin").
    - Pcode/fonksiyon verisinden MemoryAccess cikarma best-effort; gerekli
      alan yoksa bos sonuc doner (pipeline kirilmaz).
    - Feature flag kapaliysa noop (bos/None sonuc, produce ettigi key'ler
      downstream tarafindan sessizce gecilir).
"""

from __future__ import annotations

import logging
import time
from typing import Any

from karadul.pipeline.context import StepContext
from karadul.pipeline.registry import Step, register_step

logger = logging.getLogger(__name__)


def _extract_accesses_from_pcode(pcode_result: Any) -> list:
    """PcodeAnalysisResult'tan MemoryAccess listesi cikar (best-effort).

    v1.10.0 Batch 6A: ``_extract_accesses_per_function`` kullan (bu duz
    liste donen fonksiyon eski test/debug uyumu icin korundu; pipeline
    step artik per-function cagirisi yapiyor).
    """
    grouped = _extract_accesses_per_function(pcode_result)
    flat: list = []
    for _fn_key, fn_accesses in grouped.items():
        flat.extend(fn_accesses)
    return flat


def _extract_accesses_per_function(pcode_result: Any) -> dict:
    """PcodeAnalysisResult'tan fonksiyon-basina MemoryAccess haritasi cikar.

    v1.10.0 Batch 6A (Codex __unknown__ coupling fix):
        Type hint yoksa aliasing analyzer her must_alias component'ini
        BENZERSIZ __unknown_<hash>__ ailesine dusurur; ama bu yine de
        tek Z3 oturumunda tek bir binary-genisliginde solver demektir ve
        H2 geometri kisitlari 50 erisim x 10 aday x 5 alan'i gecince
        exponential patlar. Cozum: solver'i per-function cagirip
        scope'u fonksiyon basina sinirla. Boylece farkli fonksiyonlardaki
        bilinmeyen variables birbirini ETKILEMEZ (encoder H4 skip + per-fn
        scope beraber koruma).

    Returns:
        ``{fn_key: [MemoryAccess, ...]}`` fonksiyon key'i: isim veya adres.
    """
    from karadul.computation.struct_recovery import MemoryAccess

    per_fn: dict[str, list] = {}
    if pcode_result is None:
        return per_fn

    # PcodeAnalysisResult.functions: list[FunctionPcode]
    functions = getattr(pcode_result, "functions", []) or []
    for fn in functions:
        fn_name = getattr(fn, "name", "") or getattr(fn, "address", "?")
        fn_key = fn_name or "?"
        accesses: list = []
        ops = getattr(fn, "ops", []) or []
        # FonksiyonBazli SSA/var isimleri yoksa fn adresinden fallback key uret.
        for op in ops:
            mnem = getattr(op, "mnemonic", "")
            if mnem not in ("LOAD", "STORE", "PTRADD"):
                continue
            output = getattr(op, "output", None)
            inputs = getattr(op, "inputs", []) or []
            # LOAD/STORE: input[1] tipik olarak pointer + offset icerir.
            # Ghidra'nin Pcode JSON'unda offset/width bilgisini cikarmak
            # icin output veya input size'ini kullan.
            width = None
            if output is not None:
                width = getattr(output, "size", None)
            if width is None and inputs:
                # Son input value tasir (STORE icin).
                width = getattr(inputs[-1], "size", None)
            if width not in (1, 2, 4, 8):
                continue

            # Offset tespiti — ptr aritmetigi icin sabit input arariz.
            offset = None
            for inp in inputs:
                if getattr(inp, "is_constant", False):
                    off_val = getattr(inp, "offset", None)
                    if off_val is not None and 0 <= int(off_val) < 4096:
                        offset = int(off_val)
                        break
            if offset is None:
                # PTRADD'da ikinci input offset olabilir; best-effort.
                if mnem == "PTRADD" and len(inputs) >= 2:
                    second = inputs[1]
                    off_val = getattr(second, "offset", None)
                    if off_val is not None and 0 <= int(off_val) < 4096:
                        offset = int(off_val)
            if offset is None:
                continue

            # var_name icin SSA high_variable varsa onu, yoksa fn adresli
            # placeholder kullan. Bu isimler aliasing analyzer'a gider;
            # dogru isim olmasi sart degil, tek kural: ayni varsa ayni string.
            hv = None
            if output is not None:
                hv = getattr(output, "high_variable", None)
            var_name = hv or f"{fn_name}_var_{offset:x}"

            access_type = "write" if mnem == "STORE" else "read"
            try:
                accesses.append(MemoryAccess(
                    var_name=var_name,
                    offset=offset,
                    width=int(width),
                    access_type=access_type,
                ))
            except ValueError as e:
                # Graceful: width/offset sanity hatasi -> atla (invalid access).
                logger.debug(
                    "MemoryAccess sanity fail (var=%s, off=%s, w=%s): %s",
                    var_name, offset, width, e,
                )
                continue

        if accesses:
            # Ayni fn_key ile birden fazla kayit olusursa merge et (idempotent).
            per_fn.setdefault(fn_key, []).extend(accesses)

    return per_fn


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
        pc = ctx.pipeline_context
        cfg_computation = getattr(pc.config, "computation", None)

        step_start = time.monotonic()
        empty_result = {
            "computation_struct_result": None,
            "recovered_struct_candidates": [],
            "timing_computation_struct_recovery": 0.0,
        }

        # Feature flag
        if cfg_computation is None or not getattr(
            cfg_computation, "enable_computation_struct_recovery", False,
        ):
            empty_result["timing_computation_struct_recovery"] = round(
                time.monotonic() - step_start, 3,
            )
            return empty_result

        pcode_result = ctx.artifacts.get("pcode_result")
        if pcode_result is None:
            logger.debug(
                "computation_struct_recovery: pcode_result yok, atlaniyor",
            )
            empty_result["timing_computation_struct_recovery"] = round(
                time.monotonic() - step_start, 3,
            )
            return empty_result

        try:
            from karadul.computation.struct_recovery import StructLayoutSolver

            # v1.10.0 Batch 6A: Codex __unknown__ coupling fix.
            # Type hint yoksa TUM binary'deki bilinmeyen variables tek
            # __unknown__ ailesine dusup H4 ile birbirine kilitleniyordu
            # (farkli fonksiyonlar, farkli struct'lar sessizce ayni adaya
            # zorlaniyordu). Cozum: per-function scope — her fonksiyon
            # kendi scope'unda cozulur, fonksiyonlar arasi yanlislikla
            # couple olmaz. Fonksiyonun kendi icinde aliasing analyzer
            # zaten component basina benzersiz __unknown_<hash>__ uretir.
            per_fn_accesses = _extract_accesses_per_function(pcode_result)
            if not per_fn_accesses:
                logger.info(
                    "computation_struct_recovery: pcode'dan access cikmadi",
                )
                empty_result["timing_computation_struct_recovery"] = round(
                    time.monotonic() - step_start, 3,
                )
                return empty_result

            # Per-function solve: her fonksiyon icin AYRI StructLayoutSolver
            # instance (temiz Z3 Optimize scope). solver.solve_from_raw()
            # __init__'te olusturulan persistent Optimize'i push/pop ile
            # yonettigi icin ayri instance yerine ayni solver'da push da
            # olurdu ama test/trace temizligi icin instance seviyesinde
            # izolasyon tercih ediliyor.
            #
            # v1.10.0 Batch 6D (FIX 5 full): Fonksiyon icinde birden cok
            # component varsa ``solve_parallel`` kullanilir (ProcessPool +
            # per-worker Z3 Context). Tek component veya
            # ``enable_parallel_solve=False`` ise otomatik olarak sequential
            # solve_from_raw'a duser.
            all_candidates: list = []
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

            aggregate_confidence = (
                total_explained / total_accesses if total_accesses else 0.0
            )
            ctx.stats["computation_struct_solved"] = len(all_candidates)
            ctx.stats["computation_struct_confidence"] = round(
                aggregate_confidence, 3,
            )
            ctx.stats["computation_struct_functions"] = len(per_fn_results)
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
            # Geriye uyumlu: ``computation_struct_result`` tek bir sonuc
            # olarak kullaniliyordu; artik (per-fn dict + aggregate candidate
            # listesi) tuple degil, per-fn dict'i esas sonuc olarak verelim.
            # Downstream step'ler ``recovered_struct_candidates`` listesini
            # kullaniyor (bu list tek dogruluk kaynagi).
            return {
                "computation_struct_result": per_fn_results,
                "recovered_struct_candidates": all_candidates,
                "timing_computation_struct_recovery": timing,
            }
        except ImportError as exc:
            logger.debug(
                "computation_struct_recovery import hatasi (z3 yok?): %s", exc,
            )
        except Exception as exc:
            logger.warning(
                "computation_struct_recovery hatasi (atlaniyor): %s", exc,
            )
            ctx.errors.append(f"computation_struct_recovery: {exc}")

        empty_result["timing_computation_struct_recovery"] = round(
            time.monotonic() - step_start, 3,
        )
        return empty_result
