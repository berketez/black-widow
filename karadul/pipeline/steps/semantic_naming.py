"""SemanticNamingStep — algoritma-bazli parametre isimlendirme.

stages.py L3433-3468 'den tasindi. SemanticParameterNamer ile eng_result
varsa parametreleri anlamli isimlerle yeniden adlandirir. Output dizini
`reconstructed/semantic_named` — rename basarili olursa downstream icin
`decompiled_dir` bu dizine yonlenir (artifact olarak).
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any

from karadul.core.naming_labels import NAMING_PROVENANCE_FILE
from karadul.pipeline.context import StepContext
from karadul.pipeline.registry import Step, register_step

logger = logging.getLogger(__name__)


@register_step(
    name="semantic_naming",
    requires=[
        "decompiled_dir",
        "functions_json_path",
        "call_graph_json_path",
        "sig_matches",
    ],
    produces=[
        "semantic_naming_decompiled_dir",
        "params_renamed",
        "timing_semantic_naming",
    ],
    parallelizable_with=[],
)
class SemanticNamingStep(Step):
    """Algoritma-bazli parametre isimlendirme (SemanticParameterNamer)."""

    def run(self, ctx: StepContext) -> dict[str, Any]:
        pc = ctx.pipeline_context
        decompiled_dir: Path = ctx.artifacts["decompiled_dir"]
        functions_json: Path = ctx.artifacts["functions_json_path"]
        call_graph_json: Path = ctx.artifacts["call_graph_json_path"]
        sig_matches: Any = ctx.artifacts["sig_matches"]

        # Feedback loop sonrasi eng_result/algo_result guncel halleri seed
        # olarak ctx'te bulunur (T3.5 shim tarafindan inject edilir).
        eng_result = ctx.artifacts.get("eng_result")
        algo_result = ctx.artifacts.get("algo_result")

        step_start = time.monotonic()
        resulting_dir = decompiled_dir  # Rename basarisiz ise dokunulmaz
        params_renamed = 0

        if pc.config.binary_reconstruction.enable_semantic_naming and eng_result:
            try:
                from karadul.reconstruction.engineering import SemanticParameterNamer
                sem_namer = SemanticParameterNamer(pc.config)

                all_algos = self._collect_all_algorithms(algo_result, eng_result)

                reconstructed_dir = pc.workspace.get_stage_dir("reconstructed")
                sem_dir = reconstructed_dir / "semantic_named"
                sem_dir.mkdir(parents=True, exist_ok=True)

                sem_result = sem_namer.rename(
                    decompiled_dir=decompiled_dir,
                    functions_json=functions_json,
                    call_graph_json=call_graph_json,
                    output_dir=sem_dir,
                    algorithm_matches=all_algos,
                    signature_matches=sig_matches if sig_matches else None,
                )
                if sem_result and sem_result.success:
                    params_renamed = sem_result.total_renamed
                    ctx.stats["params_renamed"] = params_renamed
                    ctx.stats["semantic_naming_provenance"] = self._write_provenance(
                        reconstructed_dir, sem_result.provenance,
                    )
                    if sem_result.output_files:
                        resulting_dir = sem_dir
                    logger.info(
                        "Semantic Naming: %d parametre yeniden isimlendi",
                        params_renamed,
                    )
            except ImportError:
                logger.debug("SemanticParameterNamer bulunamadi, atlaniyor")
            except Exception as exc:
                logger.warning("Semantic naming hatasi (atlaniyor): %s", exc)
                ctx.errors.append(f"Semantic naming hatasi: {exc}")

        timing = round(time.monotonic() - step_start, 1)
        ctx.stats["timing_semantic_naming"] = timing

        return {
            "semantic_naming_decompiled_dir": resulting_dir,
            "params_renamed": params_renamed,
            "timing_semantic_naming": timing,
        }

    # --- internals -----------------------------------------------------

    @staticmethod
    def _latest_c_namer_dir(reconstructed_dir: Path) -> Path | None:
        """c_namer'ın son yinelemesinin çıktı dizini (``src``, sonra artan ``src_iterN``).

        Seçim kuralı çıktı biçimlendiricininkiyle aynıdır (``output_formatter``: ``src`` önce,
        ``src_iterN`` artan sırada, son yineleme kazanır). Köken kaydı olmayan dizin atlanır.
        """
        candidates: list[tuple[int, Path]] = []
        base = reconstructed_dir / "src"
        if (base / NAMING_PROVENANCE_FILE).is_file():
            candidates.append((0, base))
        for d in reconstructed_dir.glob("src_iter*"):
            suffix = d.name[len("src_iter"):]
            if suffix.isdigit() and (d / NAMING_PROVENANCE_FILE).is_file():
                candidates.append((int(suffix), d))
        if not candidates:
            return None
        return max(candidates, key=lambda item: item[0])[1]

    @classmethod
    def _write_provenance(cls, reconstructed_dir: Path, section: dict[str, Any]) -> str:
        """Parametre adlarının köken bölümünü c_namer'ın ``naming_provenance.json``'ına ekle.

        Bölüm ``semantic_params`` anahtarıyla, c_namer'ın son yinelemesinin kaydına yazılır
        (MUH-11: koda yazılan her ad köken kaydında kanalıyla görünür). Dönen değer
        ``stats["semantic_naming_provenance"]``'a girer: ``yazildi:<dizin>``,
        ``koken_kaydi_yok`` (c_namer kaydı yazılmamış; parametre adlarının ayrıntısı yine
        ``param_naming_map.json``'da) ya da ``yazilamadi:<hata>``.
        """
        from karadul.reconstruction.engineering.semantic_namer import (
            PARAM_PROVENANCE_SECTION,
        )

        target_dir = cls._latest_c_namer_dir(reconstructed_dir)
        if target_dir is None:
            return "koken_kaydi_yok"
        path = target_dir / NAMING_PROVENANCE_FILE
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                return "yazilamadi:kayit_sozluk_degil"
            data[PARAM_PROVENANCE_SECTION] = section
            # c_namer'ın yazım biçimiyle aynı (indent=1, ensure_ascii, sort_keys)
            path.write_text(
                json.dumps(data, indent=1, ensure_ascii=True, sort_keys=True),
                encoding="utf-8",
            )
        except (OSError, ValueError, TypeError) as exc:
            logger.warning("%s yazilamadi: %s", path, exc)
            return f"yazilamadi:{type(exc).__name__}"
        return f"yazildi:{target_dir.name}"

    @staticmethod
    def _collect_all_algorithms(algo_result: Any, eng_result: Any) -> list[Any]:
        """stages.py _collect_all_algorithms'in step-local kopyasi.

        Downstream step'ler de ayni veriyi seed'den alacagi icin ortak helper
        daha sonra (M2+) karadul.pipeline.steps._common_helpers'a tasinabilir.
        """
        all_algos: list[Any] = []
        if algo_result and getattr(algo_result, "success", False):
            all_algos.extend(algo_result.algorithms)
        if eng_result and getattr(eng_result, "success", False):
            all_algos.extend(eng_result.algorithms)
        return all_algos
