"""JSON rapor uretici -- makine-okunabilir tam rapor.

Pipeline sonuclarini karadul_version, target bilgileri, stage istatistikleri
ve artifact listesiyle birlikte structured JSON formatinda uretir.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from karadul import __version__
from karadul.core.result import PipelineResult
from karadul.core.workspace import Workspace

logger = logging.getLogger(__name__)


class JSONReporter:
    """Makine-okunabilir tam JSON rapor uretici.

    Pipeline sonuclarini detayli JSON formatinda workspace/reports/ altina yazar.
    """

    def generate(self, result: PipelineResult, workspace: Workspace) -> Path:
        """JSON rapor uret ve kaydet.

        Args:
            result: Pipeline calisma sonucu.
            workspace: Calisma dizini yoneticisi.

        Returns:
            Kaydedilen JSON dosyasinin yolu.
        """
        report = self._build_report(result, workspace)
        content = json.dumps(report, indent=2, ensure_ascii=False, default=str)
        return workspace.save_artifact("reports", "report.json", content)

    def _build_report(self, result: PipelineResult, workspace: Workspace) -> dict[str, Any]:
        """Rapor dict'ini olustur."""
        now = datetime.now(tz=timezone.utc).isoformat()

        # Target bilgileri
        target_info = self._extract_target_info(result, workspace)

        # Stage sonuclari
        stages_data = {}
        for name, sr in result.stages.items():
            stages_data[name] = {
                "success": sr.success,
                "duration": round(sr.duration_seconds, 3),
                "stats": sr.stats,
                "errors": sr.errors,
                "artifact_count": len(sr.artifacts),
            }

        # Artifact listesi
        artifacts = {}
        for name, path in result.get_all_artifacts().items():
            artifacts[name] = str(path)

        # Ozet istatistikler
        summary = self._build_summary(result)

        return {
            "karadul_version": __version__,
            "generated_at": now,
            "target": target_info,
            "pipeline": {
                "total_duration": round(result.total_duration, 3),
                "success": result.success,
                "stages": stages_data,
            },
            "artifacts": artifacts,
            "summary": summary,
        }

    def _extract_target_info(self, result: PipelineResult, workspace: Workspace) -> dict[str, Any]:
        """Target bilgilerini pipeline sonucundan veya workspace'ten cek."""
        info: dict[str, Any] = {
            "name": result.target_name,
            "hash": result.target_hash,
        }

        # Identify stage sonuclarindan ek bilgi cek
        if "identify" in result.stages:
            identify_stats = result.stages["identify"].stats
            info["type"] = identify_stats.get("target_type", "N/A")
            info["language"] = identify_stats.get("language", "N/A")
            info["size"] = identify_stats.get("file_size", 0)
            info["bundler"] = identify_stats.get("bundler", "N/A")
        else:
            info["type"] = "N/A"
            info["language"] = "N/A"
            info["size"] = 0
            info["bundler"] = "N/A"

        # Workspace'ten target_info.json yuklenebilirse ekstra metadata ekle
        raw_info = workspace.load_json("raw", "target_info")
        if raw_info:
            info.setdefault("type", raw_info.get("target_type", "N/A"))
            info.setdefault("language", raw_info.get("language", "N/A"))
            info.setdefault("size", raw_info.get("file_size", 0))
            if "metadata" in raw_info:
                info["metadata"] = raw_info["metadata"]

        return info

    def _build_summary(self, result: PipelineResult) -> dict[str, Any]:
        """Ozet istatistikleri hesapla."""
        summary: dict[str, Any] = {
            "total_stages": len(result.stages),
            "successful_stages": sum(1 for sr in result.stages.values() if sr.success),
            "failed_stages": result.get_failed_stages(),
        }

        # Statik analiz istatistikleri
        if "static" in result.stages:
            static_stats = result.stages["static"].stats
            summary["total_functions"] = static_stats.get(
                "functions_found",
                static_stats.get("ghidra_function_count", static_stats.get("functions", 0)),
            )
            summary["total_strings"] = static_stats.get(
                "strings_found",
                static_stats.get("ghidra_string_count", static_stats.get("string_count", static_stats.get("strings", 0))),
            )
            summary["total_imports"] = static_stats.get("imports_found", 0)
        else:
            summary["total_functions"] = "N/A"
            summary["total_strings"] = "N/A"
            summary["total_imports"] = "N/A"

        # Deobfuscation istatistikleri
        if "deobfuscate" in result.stages:
            deob_stats = result.stages["deobfuscate"].stats
            summary["deobfuscation_steps"] = deob_stats.get("steps_completed", "N/A")
        else:
            summary["deobfuscation_steps"] = "N/A"

        # Reconstruct istatistikleri
        if "reconstruct" in result.stages:
            recon_stats = result.stages["reconstruct"].stats
            summary["total_modules"] = recon_stats.get("modules_extracted", 0)
            summary["variables_renamed"] = recon_stats.get("variables_renamed", 0)
            summary["runnable_project"] = recon_stats.get("runnable_project", False)
            summary["coverage_percent"] = recon_stats.get("coverage_percent", 0)
        else:
            summary["total_modules"] = "N/A"
            summary["variables_renamed"] = "N/A"
            summary["runnable_project"] = False
            summary["coverage_percent"] = "N/A"

        return summary
