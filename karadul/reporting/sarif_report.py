"""SARIF 2.1.0 rapor uretici.

OASIS SARIF (Static Analysis Results Interchange Format) standardi
ile uyumlu rapor uretir. GitHub Code Scanning, VS Code SARIF Viewer
ve diger guvenlik araclariyla entegrasyon saglar.

Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
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

# SARIF 2.1.0 sabitleri
_SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0-rtm.5.json"
_SARIF_VERSION = "2.1.0"
_TOOL_NAME = "Black Widow"
_TOOL_INFORMATION_URI = "https://github.com/black-widow/karadul"

# Kural tanimlari -- her biri (id, name, level, description) tuple'i
_RULE_DEFINITIONS: list[dict[str, Any]] = [
    {
        "id": "KRDL001",
        "name": "CryptoAlgorithmDetected",
        "level": "note",
        "shortDescription": "Kriptografik algoritma tespit edildi",
        "fullDescription": (
            "Hedef binary'de bilinen bir kriptografik algoritma "
            "tespit edildi. Bu algoritmalar genellikle sabit tablolar "
            "(S-box, round constant) veya opcode pattern'leri ile tanimlanir."
        ),
    },
    {
        "id": "KRDL002",
        "name": "LowNamingConfidence",
        "level": "warning",
        "shortDescription": "Degisken/fonksiyon isim guvenilirligi dusuk",
        "fullDescription": (
            "Statik analizde tanimlanan degisken veya fonksiyon isimlerinin "
            "guvenilirlik skoru dusuk. Obfuscation veya strip edilmis "
            "sembol tablosu nedeniyle isimler yaniltici olabilir."
        ),
    },
    {
        "id": "KRDL003",
        "name": "SuspiciousPattern",
        "level": "warning",
        "shortDescription": "Supheli kod pattern'i (packing, anti-debug)",
        "fullDescription": (
            "YARA kurallari ile supheli bir kod pattern'i tespit edildi. "
            "Anti-debug teknikleri, packer imzalari veya kotu amacli "
            "yazilim davranisi gosterebilir."
        ),
    },
    {
        "id": "KRDL004",
        "name": "PackedBinary",
        "level": "warning",
        "shortDescription": "Paketlenmis/korunmali binary tespit edildi",
        "fullDescription": (
            "Hedef binary bir packer veya protector ile paketlenmis. "
            "UPX, Themida, VMProtect gibi araclar tespit edildi. "
            "Analiz sonuclari sinirli olabilir."
        ),
    },
    {
        "id": "KRDL005",
        "name": "ObfuscatedCode",
        "level": "note",
        "shortDescription": "Obfuscate edilmis kod bolgeleri",
        "fullDescription": (
            "Kontrol akisi duzlestirme, opaque predicate veya "
            "string sifreleme gibi obfuscation teknikleri tespit edildi. "
            "Deobfuscation asamasi uygulanmis olabilir."
        ),
    },
]

# YARA esine gore kural ID esleme tablosu
# YARA match tag/name icerigine gore hangi KRDL kuralinin tetiklenecegini belirler.
_YARA_TAG_RULE_MAP: dict[str, str] = {
    "packer": "KRDL004",
    "packed": "KRDL004",
    "upx": "KRDL004",
    "themida": "KRDL004",
    "vmprotect": "KRDL004",
    "anti_debug": "KRDL003",
    "anti_vm": "KRDL003",
    "suspicious": "KRDL003",
    "obfuscation": "KRDL005",
    "obfuscated": "KRDL005",
    "cff": "KRDL005",  # control flow flattening
}


class SARIFReporter:
    """SARIF 2.1.0 formatinda rapor uretici.

    Pipeline sonuclarini SARIF standardinda workspace/reports/ altina yazar.
    GitHub Code Scanning ve VS Code SARIF Viewer ile uyumludur.
    """

    def generate(self, result: PipelineResult, workspace: Workspace) -> Path:
        """SARIF rapor uret ve kaydet.

        Args:
            result: Pipeline calisma sonucu.
            workspace: Calisma dizini yoneticisi.

        Returns:
            Kaydedilen SARIF dosyasinin yolu.
        """
        sarif = self._build_sarif(result)
        content = json.dumps(sarif, indent=2, ensure_ascii=False, default=str)
        return workspace.save_artifact("reports", "report.sarif.json", content)

    # ------------------------------------------------------------------
    # Ana SARIF yapisi
    # ------------------------------------------------------------------

    def _build_sarif(self, result: PipelineResult) -> dict[str, Any]:
        """Tam SARIF 2.1.0 yapisini olustur.

        Args:
            result: Pipeline calisma sonucu.

        Returns:
            SARIF 2.1.0 uyumlu dict.
        """
        now = datetime.now(tz=timezone.utc).isoformat()
        results = self._build_results(result)
        artifacts = [self._build_artifact(result)]

        return {
            "$schema": _SARIF_SCHEMA,
            "version": _SARIF_VERSION,
            "runs": [
                {
                    "tool": {
                        "driver": self._build_tool_driver(),
                    },
                    "results": results,
                    "artifacts": artifacts,
                    "invocations": [
                        {
                            "executionSuccessful": result.success,
                            "startTimeUtc": now,
                        }
                    ],
                    "properties": {
                        "karadul_version": __version__,
                        "total_duration_seconds": round(result.total_duration, 3),
                        "pipeline_success": result.success,
                    },
                }
            ],
        }

    # ------------------------------------------------------------------
    # Tool driver
    # ------------------------------------------------------------------

    def _build_tool_driver(self) -> dict[str, Any]:
        """tool.driver bolumunu olustur.

        Returns:
            SARIF tool.driver dict'i (name, version, rules).
        """
        return {
            "name": _TOOL_NAME,
            "version": __version__,
            "semanticVersion": __version__,
            "informationUri": _TOOL_INFORMATION_URI,
            "rules": self._build_rules(),
        }

    # ------------------------------------------------------------------
    # Kural tanimlari
    # ------------------------------------------------------------------

    def _build_rules(self) -> list[dict[str, Any]]:
        """SARIF kural (reportingDescriptor) listesini olustur.

        Returns:
            5 kural tanimini iceren liste.
        """
        rules: list[dict[str, Any]] = []
        for rule_def in _RULE_DEFINITIONS:
            rules.append({
                "id": rule_def["id"],
                "name": rule_def["name"],
                "shortDescription": {"text": rule_def["shortDescription"]},
                "fullDescription": {"text": rule_def["fullDescription"]},
                "defaultConfiguration": {"level": rule_def["level"]},
                "properties": {
                    "tags": [rule_def["name"]],
                },
            })
        return rules

    # ------------------------------------------------------------------
    # Sonuclar (results)
    # ------------------------------------------------------------------

    def _build_results(self, result: PipelineResult) -> list[dict[str, Any]]:
        """Pipeline sonuclarindan SARIF result listesi olustur.

        Uc kaynaktan result toplanir:
        1. Algorithms (crypto tespit) -> KRDL001
        2. YARA matches -> KRDL003/KRDL004/KRDL005
        3. Naming stats (dusuk guvenilirlik) -> KRDL002

        Args:
            result: Pipeline calisma sonucu.

        Returns:
            SARIF result dict listesi.
        """
        results: list[dict[str, Any]] = []
        target_name = result.target_name

        # 1. Kripto algoritma tespitleri (KRDL001)
        results.extend(self._extract_algorithm_results(result, target_name))

        # 2. YARA match tespitleri (KRDL003/KRDL004/KRDL005)
        results.extend(self._extract_yara_results(result, target_name))

        # 3. Naming confidence uyarilari (KRDL002)
        results.extend(self._extract_naming_results(result, target_name))

        return results

    def _extract_algorithm_results(
        self, result: PipelineResult, target_name: str
    ) -> list[dict[str, Any]]:
        """Kripto algoritma tespitlerini SARIF result'larina donustur.

        PipelineResult.stages["static"].stats icerisindeki
        algorithms_detected listesinden veya artifacts'taki algorithm
        JSON'undan bilgi cikarir.
        """
        results: list[dict[str, Any]] = []

        # stats'tan algorithms_detected kontrolu
        if "static" not in result.stages:
            return results

        static_stats = result.stages["static"].stats
        algorithms = static_stats.get("algorithms_detected", [])

        if isinstance(algorithms, list):
            for algo in algorithms:
                if isinstance(algo, dict):
                    algo_name = algo.get("name", "Unknown")
                    address = algo.get("address", "0x00000000")
                    confidence = algo.get("confidence", 0.0)
                    category = algo.get("category", "unknown")
                    method = algo.get("method", "unknown")
                else:
                    # String olarak gelirse
                    algo_name = str(algo)
                    address = "0x00000000"
                    confidence = 0.5
                    category = "unknown"
                    method = "unknown"

                results.append(self._make_result(
                    rule_id="KRDL001",
                    level="note",
                    message=f"{algo_name} tespit edildi",
                    target_name=target_name,
                    address=address,
                    properties={
                        "confidence": confidence,
                        "category": category,
                        "detection_method": method,
                    },
                ))

        return results

    def _extract_yara_results(
        self, result: PipelineResult, target_name: str
    ) -> list[dict[str, Any]]:
        """YARA eslesmelerini SARIF result'larina donustur.

        PipelineResult.stages["static"].stats icerisindeki
        yara_matches ve detected_tech bilgilerinden cikarir.
        """
        results: list[dict[str, Any]] = []

        if "static" not in result.stages:
            return results

        static_stats = result.stages["static"].stats

        # yara_matches kontrolu
        yara_matches = static_stats.get("yara_matches", [])
        if isinstance(yara_matches, list):
            for match in yara_matches:
                if isinstance(match, dict):
                    rule_name = match.get("rule", "unknown")
                    tags = match.get("tags", [])
                    description = match.get("description", rule_name)
                    meta = match.get("meta", {})
                else:
                    rule_name = str(match)
                    tags = []
                    description = rule_name
                    meta = {}

                # YARA tag'lerine gore SARIF kuralini sec
                sarif_rule_id = self._map_yara_to_rule(rule_name, tags)
                sarif_level = self._get_rule_level(sarif_rule_id)

                results.append(self._make_result(
                    rule_id=sarif_rule_id,
                    level=sarif_level,
                    message=f"YARA eslesmesi: {description}",
                    target_name=target_name,
                    address="0x00000000",
                    properties={
                        "yara_rule": rule_name,
                        "tags": tags if isinstance(tags, list) else [],
                        "meta": meta if isinstance(meta, dict) else {},
                    },
                ))

        # detected_tech kontrolu (packer/protector tespitleri)
        detected_tech = static_stats.get("detected_tech", [])
        if isinstance(detected_tech, list):
            for tech in detected_tech:
                if isinstance(tech, dict):
                    tech_name = tech.get("name", "unknown")
                    tech_type = tech.get("type", "unknown")
                else:
                    tech_name = str(tech)
                    tech_type = "unknown"

                # Packer tespiti
                if tech_type in ("packer", "protector"):
                    sarif_rule_id = "KRDL004"
                elif tech_type == "obfuscator":
                    sarif_rule_id = "KRDL005"
                else:
                    sarif_rule_id = "KRDL003"

                results.append(self._make_result(
                    rule_id=sarif_rule_id,
                    level=self._get_rule_level(sarif_rule_id),
                    message=f"Teknoloji tespit edildi: {tech_name} ({tech_type})",
                    target_name=target_name,
                    address="0x00000000",
                    properties={
                        "technology_name": tech_name,
                        "technology_type": tech_type,
                    },
                ))

        return results

    def _extract_naming_results(
        self, result: PipelineResult, target_name: str
    ) -> list[dict[str, Any]]:
        """Dusuk isim guvenilirligi uyarilarini olustur.

        PipelineResult.stages["reconstruct"].stats veya
        stages["deobfuscate"].stats icerisindeki naming ile ilgili
        metrikleri kontrol eder.
        """
        results: list[dict[str, Any]] = []

        # Reconstruct stage'den naming bilgisi
        if "reconstruct" in result.stages:
            recon_stats = result.stages["reconstruct"].stats
            coverage = recon_stats.get("coverage_percent", 100)
            variables_renamed = recon_stats.get("variables_renamed", 0)
            avg_confidence = recon_stats.get("avg_naming_confidence", 1.0)

            # Dusuk naming confidence genel uyarisi
            if avg_confidence < 0.5 or (variables_renamed > 0 and coverage < 30):
                results.append(self._make_result(
                    rule_id="KRDL002",
                    level="warning",
                    message=(
                        f"Isim guvenilirligi dusuk: "
                        f"ortalama confidence={avg_confidence:.2f}, "
                        f"coverage={coverage}%"
                    ),
                    target_name=target_name,
                    address="0x00000000",
                    properties={
                        "avg_naming_confidence": avg_confidence,
                        "coverage_percent": coverage,
                        "variables_renamed": variables_renamed,
                    },
                ))

        # Deobfuscate stage'den naming ipucu
        if "deobfuscate" in result.stages:
            deob_stats = result.stages["deobfuscate"].stats
            low_confidence_count = deob_stats.get("low_confidence_names", 0)

            if low_confidence_count > 0:
                results.append(self._make_result(
                    rule_id="KRDL002",
                    level="warning",
                    message=(
                        f"Deobfuscation sonrasi {low_confidence_count} "
                        f"fonksiyon/degisken dusuk guvenilirlikli"
                    ),
                    target_name=target_name,
                    address="0x00000000",
                    properties={
                        "low_confidence_count": low_confidence_count,
                    },
                ))

        return results

    # ------------------------------------------------------------------
    # Artifact
    # ------------------------------------------------------------------

    def _build_artifact(self, result: PipelineResult) -> dict[str, Any]:
        """Analiz edilen hedef dosyanin artifact tanimini olustur.

        Args:
            result: Pipeline calisma sonucu.

        Returns:
            SARIF artifact dict'i.
        """
        artifact: dict[str, Any] = {
            "location": {
                "uri": result.target_name,
            },
            "hashes": {
                "sha-256": result.target_hash,
            },
        }

        # Identify stage'den dosya boyutu ve tur bilgisi
        if "identify" in result.stages:
            identify_stats = result.stages["identify"].stats
            file_size = identify_stats.get("file_size", 0)
            if file_size:
                artifact["length"] = file_size

            mime_type = identify_stats.get("mime_type", "")
            if mime_type:
                artifact["mimeType"] = mime_type

            target_type = identify_stats.get("target_type", "")
            if target_type:
                artifact["properties"] = {"target_type": target_type}

        return artifact

    # ------------------------------------------------------------------
    # Yardimci metodlar
    # ------------------------------------------------------------------

    def _make_result(
        self,
        rule_id: str,
        level: str,
        message: str,
        target_name: str,
        address: str = "0x00000000",
        properties: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Tek bir SARIF result dict'i olustur.

        Args:
            rule_id: Kural ID'si (orn: KRDL001).
            level: Onem seviyesi (note, warning, error).
            message: Insan-okunabilir mesaj.
            target_name: Hedef dosya adi.
            address: Adres bilgisi (binary icin).
            properties: Ek ozellikler dict'i.

        Returns:
            SARIF result dict'i.
        """
        result: dict[str, Any] = {
            "ruleId": rule_id,
            "level": level,
            "message": {"text": message},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": target_name,
                            "index": 0,
                        },
                        "region": {
                            "startLine": 1,
                            "snippet": {"text": address},
                        },
                    }
                }
            ],
        }

        if properties:
            result["properties"] = properties

        return result

    def _map_yara_to_rule(self, rule_name: str, tags: list[str]) -> str:
        """YARA eslesmesini en uygun SARIF kural ID'sine esle.

        Oncelik: tag eslesmesi > kural adi icerigi > varsayilan KRDL003.

        Args:
            rule_name: YARA kural adi.
            tags: YARA kural tag'leri.

        Returns:
            Eslenen SARIF kural ID'si.
        """
        # Tag'lere bak
        for tag in tags:
            tag_lower = tag.lower()
            if tag_lower in _YARA_TAG_RULE_MAP:
                return _YARA_TAG_RULE_MAP[tag_lower]

        # Kural adina bak
        name_lower = rule_name.lower()
        for key, rule_id in _YARA_TAG_RULE_MAP.items():
            if key in name_lower:
                return rule_id

        # Varsayilan: genel supheli pattern
        return "KRDL003"

    @staticmethod
    def _get_rule_level(rule_id: str) -> str:
        """Kural ID'sine gore varsayilan seviyeyi dondur.

        Args:
            rule_id: SARIF kural ID'si.

        Returns:
            Onem seviyesi (note, warning).
        """
        for rule_def in _RULE_DEFINITIONS:
            if rule_def["id"] == rule_id:
                return rule_def["level"]
        return "warning"
