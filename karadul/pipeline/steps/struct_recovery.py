"""StructRecoveryStep — algoritma-bazli struct field isimlendirme.

stages.py L3356-3404'ten tasindi. StructRecoveryEngine algoritma bilgisine
dayanarak struct field'larini anlamli isimlerle yeniden adlandirir ve
types_header enrich eder.

P10 (BORU-04): MaxSMT yapı adaylarını (``computation_struct_recovery``
adımının ``recovered_struct_candidates`` / ``computation_struct_result``
yapıtları) motora ileten tek yol bu adımdır. Önceden bu iş yalnız
``stages.py``'deki "eski monolit" kopyada, çözücü ikinci kez koşturularak
yapılıyordu; o blok silindiğinde ``--maxsmt-struct`` etkisiz kalırdı.
Bayrak kapalıyken (öntanım) üretici adım boş liste döndürür; davranış aynı.
"""

from __future__ import annotations

import logging
import re
import time
from pathlib import Path
from typing import Any

from karadul.pipeline.context import StepContext
from karadul.pipeline.registry import Step, register_step

logger = logging.getLogger(__name__)


_IDENT_UNSAFE = re.compile(r"[^0-9A-Za-z_]")


def maxsmt_structs_for_engine(
    per_fn_results: Any, candidates: Any,
) -> list[dict[str, Any]]:
    """MaxSMT sonucunu ``StructRecoveryEngine.recover(computation_structs=)`` biçimine çevir.

    Motorun okuduğu anahtarlar: ``name``, ``total_size``, ``fields`` (her biri
    ``offset``, ``size``, ``type``, ``confidence``), ``source_functions``.
    (Silinecek ``stages.py`` kopyası ``size`` / ``type_hint`` yazıyordu; motor
    bunları okumadığı için boyut 0, tip ``undefined8`` oluyordu.)

    Kaynak fonksiyon ``computation_struct_result``'tan ({fonksiyon:
    RecoveredStructLayout}) gelir; adaylar fonksiyon başına çözüldüğü için ad
    çakışmasın diye ada fonksiyon ve tip ailesi eklenir (motor aynı adlı ikinci
    yapıyı atlar). ``type_hint`` yalnız genişlik söylediği için (``int32``)
    alan tipi Ghidra'nın "N baytlık bilinmeyen" tipi ``undefinedN`` olur.
    Sonuç dict değilse düz aday listesi kaynak fonksiyonsuz kullanılır.
    """
    def _fields(cand: Any) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for f in getattr(cand, "fields", None) or []:
            size = int(getattr(f, "size", 0) or 0)
            if size <= 0:
                continue
            out.append({
                "offset": int(getattr(f, "offset", 0) or 0),
                "size": size,
                "type": f"undefined{size}" if size in (1, 2, 4, 8) else "undefined",
                "type_hint": getattr(f, "type_hint", None),
                "confidence": 0.0,  # kalibre güven yok (TIP-03 düzelene kadar)
            })
        return out

    result: list[dict[str, Any]] = []
    if isinstance(per_fn_results, dict) and per_fn_results:
        for fn_key in sorted(per_fn_results, key=str):
            layout = per_fn_results[fn_key]
            assigned = getattr(layout, "assigned_structs", None) or {}
            for family in sorted(assigned, key=str):
                cand = assigned[family]
                name = _IDENT_UNSAFE.sub(
                    "_", f"maxsmt_{fn_key}_{getattr(cand, 'name', family)}",
                )
                result.append({
                    "name": name,
                    "total_size": int(getattr(cand, "size", 0) or 0),
                    "fields": _fields(cand),
                    "source_functions": [str(fn_key)],
                    "source": "computation_struct_recovery",
                })
        return result
    for i, cand in enumerate(candidates or []):
        result.append({
            "name": _IDENT_UNSAFE.sub(
                "_", f"maxsmt_{i}_{getattr(cand, 'name', 'struct')}",
            ),
            "total_size": int(getattr(cand, "size", 0) or 0),
            "fields": _fields(cand),
            "source_functions": [],
            "source": "computation_struct_recovery",
        })
    return result


@register_step(
    name="struct_recovery",
    requires=[
        "final_decompiled_dir",
        "functions_json_path",
        "ghidra_types_json_path",
        "call_graph_json_path",
        "updated_algo_result",
        "updated_eng_result",
        "computation_result",
        # P10 (BORU-04): MaxSMT adayları. Üretici adım bayrak kapalıyken
        # boş liste / None verir; bu bağımlılık sırayı da açıkça kurar.
        "recovered_struct_candidates",
        "computation_struct_result",
    ],
    produces=[
        "struct_recovery_decompiled_dir",
        "struct_recovery_result",
        "timing_struct_recovery",
    ],
    parallelizable_with=[],
)
class StructRecoveryStep(Step):
    """StructRecoveryEngine ile struct field'larini isimlendir."""

    def run(self, ctx: StepContext) -> dict[str, Any]:
        pc = ctx.pipeline_context
        a = ctx.artifacts
        decompiled_dir: Path = a["final_decompiled_dir"]
        functions_json: Path = a["functions_json_path"]
        ghidra_types_json: Path = a["ghidra_types_json_path"]
        call_graph_json: Path = a["call_graph_json_path"]
        algo_result: Any = a["updated_algo_result"]
        eng_result: Any = a["updated_eng_result"]
        computation_result: Any = a["computation_result"]
        maxsmt_candidates: Any = a["recovered_struct_candidates"]
        maxsmt_per_fn: Any = a["computation_struct_result"]

        step_start = time.monotonic()
        struct_result: Any = None
        resulting_dir = decompiled_dir

        if pc.config.binary_reconstruction.enable_struct_recovery and eng_result:
            try:
                from karadul.reconstruction.engineering import StructRecoveryEngine
                struct_engine = StructRecoveryEngine(pc.config)

                all_algos = self._collect_all_algorithms(algo_result, eng_result)
                reconstructed_dir = pc.workspace.get_stage_dir("reconstructed")
                struct_dir = reconstructed_dir / "struct_recovered"
                struct_dir.mkdir(parents=True, exist_ok=True)

                # v1.5.2: Computation Recovery struct verilerini hazirla
                comp_structs_for_eng = None
                if computation_result and computation_result.success:
                    cs_layer = computation_result.layer_results.get(
                        "constraint_solver",
                    )
                    if cs_layer and hasattr(cs_layer, "structs") and cs_layer.structs:
                        comp_structs_for_eng = [
                            s.to_dict() for s in cs_layer.structs
                        ]

                # P10 (BORU-04): MaxSMT adaylarını EK aday olarak geçir.
                maxsmt_structs = maxsmt_structs_for_engine(
                    maxsmt_per_fn, maxsmt_candidates,
                )
                if maxsmt_structs:
                    comp_structs_for_eng = (
                        list(comp_structs_for_eng or []) + maxsmt_structs
                    )
                    ctx.stats["struct_maxsmt_candidates_passed"] = len(
                        maxsmt_structs,
                    )
                    logger.debug(
                        "StructRecoveryEngine'e %d MaxSMT adayi gecildi",
                        len(maxsmt_structs),
                    )

                struct_result = struct_engine.recover(
                    decompiled_dir=decompiled_dir,
                    functions_json=functions_json,
                    ghidra_types_json=ghidra_types_json,
                    call_graph_json=call_graph_json,
                    output_dir=struct_dir,
                    algorithm_matches=all_algos,
                    computation_structs=comp_structs_for_eng,
                )
                if struct_result.success:
                    # P10 (TIP-04): yalnız koda bağlanan yapılar "kurtarıldı";
                    # K-1 bekletmesinde 0. Adaylar ve Ghidra'nın kendi yapıları
                    # ayrı satır (sessiz kaybolmasın, iddia sayılmasın).
                    ctx.stats["structs_enriched"] = struct_result.total_structs
                    ctx.stats["field_access_rewrites"] = (
                        struct_result.field_access_rewrites
                    )
                    ctx.stats["struct_candidates"] = len(
                        getattr(struct_result, "candidate_structs", []) or [],
                    )
                    ctx.stats["struct_rewrites_proposed"] = getattr(
                        struct_result, "proposed_field_access_rewrites", 0,
                    )
                    ctx.stats["struct_reference_ghidra"] = len(
                        getattr(struct_result, "reference_structs", []) or [],
                    )
                    if struct_result.types_header_path:
                        ctx.produce_artifact(
                            "enriched_types_header",
                            struct_result.types_header_path,
                        )
                    # P10: Faz 3 kaynağı çıktı ağacıdır (değişmemiş kopyalar dahil);
                    # rewritten_files artık yalnız gerçekten değişen dosyaları tutar.
                    if struct_result.output_files:
                        resulting_dir = struct_dir
                    logger.info(
                        "Struct Recovery: %d struct, %d field rewrite",
                        struct_result.total_structs,
                        struct_result.field_access_rewrites,
                    )
            except ImportError:
                logger.debug("StructRecoveryEngine bulunamadi, atlaniyor")
            except Exception as exc:
                logger.warning("Struct recovery hatasi (atlaniyor): %s", exc)
                ctx.errors.append(f"Struct recovery hatasi: {exc}")

        timing = round(time.monotonic() - step_start, 1)
        ctx.stats["timing_struct_recovery"] = timing

        return {
            "struct_recovery_decompiled_dir": resulting_dir,
            "struct_recovery_result": struct_result,
            "timing_struct_recovery": timing,
        }

    # --- helpers -----------------------------------------------------

    @staticmethod
    def _collect_all_algorithms(algo_result: Any, eng_result: Any) -> list[Any]:
        """stages.py `_collect_all_algorithms` ile ayni."""
        all_algos: list[Any] = []
        if algo_result and getattr(algo_result, "success", False):
            all_algos.extend(algo_result.algorithms)
        if eng_result and getattr(eng_result, "success", False):
            all_algos.extend(eng_result.algorithms)
        return all_algos
