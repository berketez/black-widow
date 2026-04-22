"""GhidraMetadataStep — Ghidra JSON yollarini resolve eder, parse cache'ler
ve Signature DB matching'i calistirir.

stages.py `_execute_binary` L1242-1359'dan tasindi. Davranis birebir korundu:
- Ghidra JSON'larini deobfuscated/ onceligi ile static/'te ara
- P-Code/CFG/FID/decompiled JSON yollarini resolve et
- functions_json, strings_json, call_graph_json'u bir kez parse edip cache'le
- Platform-aware SignatureDB matching (Bug 7 fix — v1.8.0)
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any

from karadul.core.target import TargetType
from karadul.pipeline.context import StepContext
from karadul.pipeline.registry import Step, register_step

logger = logging.getLogger(__name__)

# v1.10.0 M2: karadul/core/platform_map.py'dan merkezi import (DRY, kural 11).
from karadul.core.platform_map import TARGET_PLATFORM_MAP as _TARGET_PLATFORM_MAP


@register_step(
    name="ghidra_metadata",
    requires=["decompiled_dir"],
    produces=[
        "functions_json_path",
        "strings_json_path",
        "call_graph_json_path",
        "ghidra_types_json_path",
        "xrefs_json_path",
        "pcode_json_path",
        "cfg_json_path",
        "fid_json_path",
        "decompiled_json_path",
        "functions_data",
        "strings_data",
        "call_graph_data",
        "output_dir",
        "sig_matches",
    ],
    parallelizable_with=[],
)
class GhidraMetadataStep(Step):
    """Ghidra metadata dosyalarini topla + parse cache'le + Signature DB match."""

    def run(self, ctx: StepContext) -> dict[str, Any]:
        pc = ctx.pipeline_context
        target = pc.target
        static_dir = pc.workspace.get_stage_dir("static")
        deob_dir = pc.workspace.get_stage_dir("deobfuscated")
        reconstructed_dir = pc.workspace.get_stage_dir("reconstructed")
        decompiled_dir = ctx.artifacts["decompiled_dir"]

        paths = self._resolve_json_paths(static_dir, deob_dir)
        output_dir = reconstructed_dir / "src"
        output_dir.mkdir(parents=True, exist_ok=True)

        func_data, string_data, call_graph_data = self._parse_core_jsons(
            paths["functions_json_path"],
            paths["strings_json_path"],
            paths["call_graph_json_path"],
            ctx,
        )

        sig_matches = self._run_signature_db(
            pc=pc,
            target=target,
            functions_json=paths["functions_json_path"],
            strings_json=paths["strings_json_path"],
            call_graph_json=paths["call_graph_json_path"],
            decompiled_dir=decompiled_dir,
            ctx=ctx,
        )

        return {
            **paths,
            "output_dir": output_dir,
            "functions_data": func_data,
            "strings_data": string_data,
            "call_graph_data": call_graph_data,
            "sig_matches": sig_matches,
        }

    # --- internals -----------------------------------------------------

    @staticmethod
    def _resolve_json_paths(static_dir: Path, deob_dir: Path) -> dict[str, Path]:
        """Her JSON icin once deobfuscated/'te, yoksa static/'te ara.

        stages.py L1244-1281 ile birebir ayni yol resolving davranisi.
        """

        def pick(name: str) -> Path:
            p = deob_dir / name
            if not p.exists():
                p = static_dir / name
            return p

        functions_json = pick("ghidra_functions.json")
        strings_json = pick("ghidra_strings.json")
        call_graph_json = pick("ghidra_call_graph.json")
        ghidra_types_json = pick("ghidra_types.json")
        xrefs_json = pick("ghidra_xrefs.json")
        pcode_json = pick("ghidra_pcode.json")
        cfg_json = pick("ghidra_cfg.json")
        fid_json = pick("ghidra_function_id.json")

        # decompiled.json ozel: static/ghidra_output/ da olabilir
        decompiled_json = pick("decompiled.json")
        if not decompiled_json.exists():
            alt = static_dir / "ghidra_output" / "decompiled.json"
            if alt.exists():
                decompiled_json = alt

        return {
            "functions_json_path": functions_json,
            "strings_json_path": strings_json,
            "call_graph_json_path": call_graph_json,
            "ghidra_types_json_path": ghidra_types_json,
            "xrefs_json_path": xrefs_json,
            "pcode_json_path": pcode_json,
            "cfg_json_path": cfg_json,
            "fid_json_path": fid_json,
            "decompiled_json_path": decompiled_json,
        }

    @staticmethod
    def _parse_core_jsons(
        functions_json: Path,
        strings_json: Path,
        call_graph_json: Path,
        ctx: StepContext,
    ) -> tuple[Any, Any, Any]:
        """Uc core Ghidra JSON'u bir kez parse et (stages.py L1289-1318).

        Hatalari ctx.errors'a yazar, basarisiz olanlar None doner.
        """
        func_data: Any = None
        if functions_json and functions_json.exists():
            try:
                func_data = json.loads(
                    functions_json.read_text(encoding="utf-8", errors="replace"),
                )
            except Exception as exc:
                logger.warning(
                    "functions_json parse hatasi: %s -- %s",
                    functions_json, exc,
                )
                ctx.errors.append(f"functions_json parse hatasi: {exc}")

        string_data: Any = None
        if strings_json and strings_json.exists():
            try:
                string_data = json.loads(
                    strings_json.read_text(encoding="utf-8", errors="replace"),
                )
            except Exception as exc:
                logger.warning(
                    "strings_json parse hatasi: %s -- %s",
                    strings_json, exc,
                )
                ctx.errors.append(f"strings_json parse hatasi: {exc}")

        call_graph_data: Any = None
        if call_graph_json and call_graph_json.exists():
            try:
                call_graph_data = json.loads(
                    call_graph_json.read_text(encoding="utf-8", errors="replace"),
                )
            except Exception as exc:
                logger.warning(
                    "call_graph_json parse hatasi: %s -- %s",
                    call_graph_json, exc,
                )
                ctx.errors.append(f"call_graph_json parse hatasi: {exc}")

        return func_data, string_data, call_graph_data

    @staticmethod
    def _run_signature_db(
        *,
        pc,
        target,
        functions_json: Path,
        strings_json: Path,
        call_graph_json: Path,
        decompiled_dir: Path,
        ctx: StepContext,
    ) -> list:
        """Signature DB matching — stages.py L1320-1359.

        Hatalari atip bos liste doner (downstream'a engel olma).
        """
        pc.report_progress("Signature DB matching...", 0.05)
        step_start = time.monotonic()
        sig_matches: list = []

        platform = _TARGET_PLATFORM_MAP.get(target.target_type)

        try:
            from karadul.analyzers.signature_db import SignatureDB

            sig_db = SignatureDB(pc.config, target_platform=platform)
            sig_matches = sig_db.match_all(
                functions_json,
                strings_json,
                call_graph_json,
                decompiled_dir,
                target_platform=platform,
            )
            ctx.stats["signature_matches"] = len(sig_matches)
            if sig_matches:
                sig_path = pc.workspace.save_json(
                    "reconstructed", "signature_matches",
                    {
                        "total": len(sig_matches),
                        "matches": [
                            {
                                "original": m.original_name,
                                "matched": m.matched_name,
                                "library": m.library,
                                "confidence": m.confidence,
                                "purpose": m.purpose,
                            }
                            for m in sig_matches
                        ],
                    },
                )
                # Shim: eski yoldaki artifacts dict'e yazilsin diye metadata'ya
                # da iliyoruz.
                if pc.metadata is None:
                    pc.metadata = {}  # type: ignore[attr-defined]
                pc.metadata.setdefault("artifacts_pending", {})[
                    "signature_matches"
                ] = sig_path
                logger.info(
                    "Signature DB: %d fonksiyon tanindi", len(sig_matches),
                )
        except ImportError:
            logger.debug("SignatureDB modulu bulunamadi, atlaniyor")
        except Exception as exc:
            logger.warning("Signature DB hatasi: %s", exc)
            ctx.errors.append(f"Signature DB hatasi: {exc}")

        ctx.stats["timing_signature_db"] = round(
            time.monotonic() - step_start, 1,
        )
        return sig_matches
