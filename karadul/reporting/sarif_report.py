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
from karadul.reporting.report_data import (
    SECTION_CLEAN,
    SECTION_DISABLED,
    SECTION_FINDINGS,
    SECTION_ORDER,
    SECTION_UNSUPPORTED,
    ReportData,
    build_report_data,
    status_label,
    to_json_dict,
)

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
    {
        "id": "KRDL006",
        "name": "KnownMalwareSymbol",
        "level": "error",
        "shortDescription": "Bilinen zararli yazilim ailesinin simgesi eslesti",
        "fullDescription": (
            "Imza veritabaninin zararli yazilim paketi (Sliver, Cobalt Strike) "
            "ikilideki bir simge adiyla eslesti (reconstructed/signature_matches.json: "
            "family / tier)."
        ),
    },
    {
        "id": "KRDL007",
        "name": "TechnologyFingerprint",
        "level": "note",
        "shortDescription": "Derleyici / kitaplik parmak izi (supheli degil)",
        "fullDescription": (
            "YARA kurali ikilide bir derleyici ya da sikistirma kitapliginin izini buldu "
            "(MSVC, GCC, zlib, zstd ...). Bilgi amaclidir; supheli davranis iddiasi degildir."
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
    # yerlesik YARA kurallarinin gercek etiketleri (analyzers/yara_scanner.py)
    "antidebug": "KRDL003",
    "antivm": "KRDL003",
    "suspicious": "KRDL003",
    "obfuscation": "KRDL005",
    "obfuscated": "KRDL005",
    "cff": "KRDL005",  # control flow flattening
    # Kripto sabiti / kitapligi (AES S-box, SHA-256 sabitleri, OpenSSL dizgileri): KRDL001.
    "crypto": "KRDL001",
    # Derleyici / sikistirma kitapligi parmak izi supheli degildir: KRDL007 (note).
    # Eskiden "MSVC_Compiler", "Zlib_Library" KRDL003 "SuspiciousPattern" uyarisi oluyordu.
    "compiler": "KRDL007",
    "compression": "KRDL007",
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
        sarif = self._build_sarif(result, workspace)
        content = json.dumps(sarif, indent=2, ensure_ascii=False, default=str)
        return workspace.save_artifact("reports", "report.sarif.json", content)

    # ------------------------------------------------------------------
    # Ana SARIF yapisi
    # ------------------------------------------------------------------

    def _build_sarif(
        self, result: PipelineResult, workspace: Workspace
    ) -> dict[str, Any]:
        """Tam SARIF 2.1.0 yapisini olustur.

        Args:
            result: Pipeline calisma sonucu.
            workspace: static/*.json artifact'larini okumak icin.

        Returns:
            SARIF 2.1.0 uyumlu dict.
        """
        now = datetime.now(tz=timezone.utc).isoformat()
        data = build_report_data(result, workspace)
        results = self._build_results(result, workspace, data)
        artifacts = [self._build_artifact(result)]

        invocation: dict[str, Any] = {
            "executionSuccessful": result.success,
            "startTimeUtc": now,
        }
        # Atlanan asamalar + taranamayan / verisi olmayan bolumler (IMZA-15: "temiz" ile
        # "taranmadi" ayrilir; sonuc yoklugu temizlik sanilmasin).
        skip_notes = (self._build_skip_notifications(result)
                      + self._build_section_notifications(data))
        if skip_notes:
            invocation["toolExecutionNotifications"] = skip_notes

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
                    "invocations": [invocation],
                    "properties": {
                        "karadul_version": __version__,
                        "total_duration_seconds": round(result.total_duration, 3),
                        "pipeline_success": result.success,
                        # report.json summary'deki ayrimla ayni: atlanan != basarisiz
                        "skipped_stages": [
                            name for name, sr in result.stages.items()
                            if getattr(sr, "skipped", False)
                        ],
                        # Bolum durumlari (JSON / HTML / Markdown ile ayni katman ve cumle).
                        "report_sections": to_json_dict(data),
                    },
                }
            ],
        }

    # ------------------------------------------------------------------
    # Atlanan asamalar (toolExecutionNotifications)
    # ------------------------------------------------------------------

    @staticmethod
    def _build_skip_notifications(result: PipelineResult) -> list[dict[str, Any]]:
        """Atlanan (skipped=True) her asama icin SARIF 'note' bildirimi.

        Atlanan asama bir HATA degildir (executionSuccessful etkilenmez); SARIF
        2.1.0 notification nesnesi (message zorunlu, level "note") ile arac
        yurutmesi hakkinda bilgi olarak raporlanir. Gerekce stats["skip_reason"].
        """
        notes: list[dict[str, Any]] = []
        for name, sr in result.stages.items():
            if not getattr(sr, "skipped", False):
                continue
            stats = sr.stats if isinstance(sr.stats, dict) else {}
            raw = stats.get("skip_reason")
            reason = " ".join(str(raw).split()) if raw is not None else ""
            text = f"Stage '{name}' skipped (not a failure)"
            text += f": {reason}" if reason else ": no reason recorded"
            notes.append({
                "level": "note",
                "message": {"text": text},
                "properties": {"stage": name, "skip_reason": reason or None},
            })
        return notes

    @staticmethod
    def _build_section_notifications(data: ReportData) -> list[dict[str, Any]]:
        """Bulgu ya da temiz sonucu olmayan her bolum icin bildirim (neden ile).

        Desteklenmeyen / kapali bolum "note"; taranamayan / kismi / durumu kaydedilmemis /
        verisi olmayan bolum "warning".
        """
        notes: list[dict[str, Any]] = []
        for key in SECTION_ORDER:
            sec = data.sections.get(key)
            if sec is None or sec.status in (SECTION_FINDINGS, SECTION_CLEAN):
                continue
            level = "note" if sec.status in (SECTION_UNSUPPORTED, SECTION_DISABLED) else "warning"
            notes.append({
                "level": level,
                "message": {"text": f"{sec.title}: {status_label(sec.status)} — {sec.summary}"},
                "properties": {"section": key, "status": sec.status, "source": sec.source},
            })
        return notes

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

    def _build_results(
        self, result: PipelineResult, workspace: Workspace, data: ReportData | None = None,
    ) -> list[dict[str, Any]]:
        """Rapor verisi katmanindan SARIF result listesi olustur (P07).

        Kaynaklar (HTML / Markdown / JSON ile ayni bolumler):
        1. reconstructed/algorithms.json, kripto kategorileri -> KRDL001
        2. YARA isabetleri (static.stats yara_hits; P-S1 oncesi detected_tech) -> KRDL003/4/5
           (etiketten: packer -> KRDL004)
        3. Ad etiket dagilimi (reconstruct.stats naming_by_label) -> KRDL002
        4. packer_fingerprints.json -> KRDL004
        5. anti_debug_findings.json -> KRDL003
        6. signature_matches.json bilinen zararli aile -> KRDL006
        capa yetenekleri K-1 geregi sonuc olarak yazilmaz (dogrulanmamis aday); durumu
        bildirimde ve run.properties.report_sections'ta.
        """
        if data is None:
            data = build_report_data(result, workspace)
        target_name = result.target_name
        results: list[dict[str, Any]] = []
        results.extend(self._extract_algorithm_results(data, target_name))
        results.extend(self._extract_yara_results(data, target_name))
        results.extend(self._extract_naming_results(result, data, target_name))
        results.extend(self._extract_packer_fingerprint_results(data, target_name))
        results.extend(self._extract_anti_debug_results(data, target_name))
        results.extend(self._extract_ioc_results(data, target_name))
        return results

    def _extract_algorithm_results(
        self, data: ReportData, target_name: str
    ) -> list[dict[str, Any]]:
        """reconstructed/algorithms.json'daki kripto tespitleri -> KRDL001.

        Eskiden static.stats.algorithms_detected LISTESI okunuyordu; o alan hic yazilmiyor
        (algoritma tespiti reconstruct'a SAYI yaziyor) -> openssl'de bile 0 KRDL001
        (ARAYUZ-17).
        """
        sec = data.sections["crypto"]
        results: list[dict[str, Any]] = []
        if not sec.has_items:
            return results
        for algo in sec.items:
            name = str(algo.get("name", "Unknown"))
            func = algo.get("function") or None
            evidence = [str(e) for e in (algo.get("evidence") or [])]
            where = f" in {func}" if func else ""
            ev_txt = f" Evidence: {'; '.join(evidence)[:200]}" if evidence else ""
            r = self._make_result(
                rule_id="KRDL001",
                level="note",
                message=f"{name} ({algo.get('category', '?')}) detected{where}.{ev_txt}",
                target_name=target_name,
                properties={
                    "confidence": algo.get("confidence"),
                    "category": algo.get("category"),
                    "function": func,
                    "evidence": evidence,
                    "source": sec.source,
                },
            )
            if func:
                r["locations"][0]["logicalLocations"] = [{"name": str(func), "kind": "function"}]
            results.append(r)
        return results

    def _extract_yara_results(
        self, data: ReportData, target_name: str
    ) -> list[dict[str, Any]]:
        """YARA isabetleri -> KRDL003/004/005 (etiketten).

        P-S1 sonrasi ``yara_hits`` (kural, etiket, meta.condition, dizgi ofsetleri) okunur;
        oncesinde ``detected_tech`` duz dizgisi ``"<kural> (<etiket>)"`` kural + etikete
        ayrilir. Eskiden dizgi dalinda tip "unknown" ataniyor, paketleyici isabeti KRDL004
        yerine KRDL003'e dusuyor, ileti "(unknown)" oluyordu (ARAYUZ-17).
        """
        sec = data.sections["yara"]
        results: list[dict[str, Any]] = []
        if not sec.has_items:
            return results
        for hit in sec.items:
            rule_name = str(hit.get("rule", "unknown"))
            tags = [str(t) for t in (hit.get("tags") or [])]
            meta = hit.get("meta") if isinstance(hit.get("meta"), dict) else {}
            sarif_rule_id = self._map_yara_to_rule(rule_name, tags)
            offsets = [s.get("offset") for s in (hit.get("strings") or []) if isinstance(s, dict)]
            parts = [f"YARA rule {rule_name} matched"]
            if tags:
                parts.append(f"(tags: {','.join(tags)})")
            if meta.get("condition"):
                parts.append(f"condition: {meta['condition']}")
            if offsets:
                parts.append(f"file offsets: {', '.join(str(o) for o in offsets[:8])}")
            if hit.get("legacy"):
                parts.append("(matched strings not recorded in this run)")
            level = self._get_rule_level(sarif_rule_id)
            if str(meta.get("severity", "")).lower() == "info":
                level = "note"  # kuralin kendi onemi bilgi duzeyi
            results.append(self._make_result(
                rule_id=sarif_rule_id,
                level=level,
                message=" ".join(parts),
                target_name=target_name,
                properties={
                    "yara_rule": rule_name,
                    "tags": tags,
                    "meta": meta,
                    "strings": hit.get("strings") or [],
                    "source": "yara",
                },
            ))
        return results

    def _extract_naming_results(
        self, result: PipelineResult, data: ReportData, target_name: str
    ) -> list[dict[str, Any]]:
        """Ad guvenilirligi -> KRDL002.

        Eskiden hic uretilmeyen ``coverage_percent`` (ontanimli 100) ve
        ``avg_naming_confidence`` (ontanimli 1.0) okunuyordu: uyari hicbir kosuda cikmiyordu
        (ARAYUZ-17). Simdi olculmus etiket dagilimi (naming_by_label) okunur: "dogrulanmadi"
        etiketli ad varsa ya da ad degistirildigi halde dagilim kaydedilmemisse uyari verilir.
        """
        results: list[dict[str, Any]] = []
        sec = data.sections["naming"]
        warn = sec.status == SECTION_FINDINGS or (
            sec.status != SECTION_CLEAN and bool(sec.extra.get("variables_renamed")))
        if warn:
            props: dict[str, Any] = {"section_status": sec.status}
            props.update({k: v for k, v in sec.extra.items() if v is not None})
            results.append(self._make_result(
                rule_id="KRDL002",
                level="warning",
                message=f"Recovered names are not verified: {sec.summary}",
                target_name=target_name,
                properties=props,
            ))

        # Deobfuscate stage'den naming ipucu (JS hatti)
        if "deobfuscate" in result.stages:
            deob_stats = result.stages["deobfuscate"].stats
            low_confidence_count = deob_stats.get("low_confidence_names", 0)
            if isinstance(low_confidence_count, int) and low_confidence_count > 0:
                results.append(self._make_result(
                    rule_id="KRDL002",
                    level="warning",
                    message=(
                        f"Deobfuscation sonrasi {low_confidence_count} "
                        f"fonksiyon/degisken dusuk guvenilirlikli"
                    ),
                    target_name=target_name,
                    properties={"low_confidence_count": low_confidence_count},
                ))
        return results

    def _extract_packer_fingerprint_results(
        self, data: ReportData, target_name: str
    ) -> list[dict[str, Any]]:
        """packer_fingerprints.json -> KRDL004 (karadul'un asil paketleyici tespiti).

        confidence -> SARIF level: >=0.7 error, >=0.4 warning, else note.
        """
        results: list[dict[str, Any]] = []
        sec = data.sections["packer"]
        if not sec.has_items:
            return results
        for fp in sec.items:
            name = str(fp.get("packer_name") or fp.get("technique") or fp.get("name") or "unknown")
            version = fp.get("version")
            try:
                conf = float(fp.get("confidence", 0.0) or 0.0)
            except (TypeError, ValueError):
                conf = 0.0
            category = fp.get("category", "packer")
            layers = fp.get("layers_matched", 0)
            ev_raw = fp.get("evidence", "")
            if isinstance(ev_raw, (list, tuple)):
                ev_text = "; ".join(str(e) for e in ev_raw)
            else:
                ev_text = str(ev_raw)
            if conf >= 0.7:
                level = "error"
            elif conf >= 0.4:
                level = "warning"
            else:
                level = "note"
            ver_txt = f" {version}" if version else ""
            msg = (
                f"Paketlenmis binary tespit edildi: {name}{ver_txt} "
                f"(guven {conf:.2f}, {layers} katman). Decompile yalnizca "
                "acici stub'i gosterir; gercek kod sikistirilmis. Once paketi "
                "acin (orn. 'upx -d'), sonra yeniden analiz edin."
            )
            if ev_text:
                msg += f" Kanit: {ev_text[:200]}"
            results.append(self._make_result(
                rule_id="KRDL004",
                level=level,
                message=msg,
                target_name=target_name,
                properties={
                    "packer_name": name,
                    "version": version,
                    "confidence": conf,
                    "category": category,
                    "layers_matched": layers,
                    "evidence": ev_raw,
                    "source": "packer_fingerprints",
                },
            ))
        return results

    def _extract_anti_debug_results(
        self, data: ReportData, target_name: str
    ) -> list[dict[str, Any]]:
        """anti_debug_findings.json -> KRDL003 (HTML / Markdown ile ayni bulgular).

        confidence >= 0.7 warning, alti note (P02 sonrasi kalan bulgularin cogu bilgi duzeyi).
        """
        results: list[dict[str, Any]] = []
        sec = data.sections["anti_debug"]
        if not sec.has_items:
            return results
        for f in sec.items:
            try:
                conf = float(f.get("confidence", 0.0) or 0.0)
            except (TypeError, ValueError):
                conf = 0.0
            tech = str(f.get("technique", "?"))
            results.append(self._make_result(
                rule_id="KRDL003",
                level="warning" if conf >= 0.7 else "note",
                message=(f"Anti-debug technique {tech} ({f.get('category', '?')}, confidence "
                         f"{conf:.2f}). Evidence: {str(f.get('evidence', ''))[:200]}"),
                target_name=target_name,
                properties={"technique": tech, "category": f.get("category"),
                            "confidence": conf, "evidence": f.get("evidence"),
                            "source": "anti_debug_findings"},
            ))
        return results

    def _extract_ioc_results(
        self, data: ReportData, target_name: str
    ) -> list[dict[str, Any]]:
        """signature_matches.json bilinen zararli aile kayitlari -> KRDL006."""
        results: list[dict[str, Any]] = []
        sec = data.sections["ioc"]
        if not sec.has_items:
            return results
        for m in sec.items:
            sym = str(m.get("original", m.get("symbol", m.get("name", "?"))))
            results.append(self._make_result(
                rule_id="KRDL006",
                level="error",
                message=(f"Known-malware symbol {sym} (family {m.get('family') or '?'}, tier "
                         f"{m.get('tier') or '?'}): {str(m.get('purpose', ''))[:160]}"),
                target_name=target_name,
                address=str(m.get("address") or "0x00000000"),
                properties={"symbol": sym, "matched": m.get("matched"),
                            "family": m.get("family"), "tier": m.get("tier"),
                            "category": m.get("category"), "source": "signature_matches"},
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
