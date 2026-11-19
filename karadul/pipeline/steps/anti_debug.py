"""AntiDebugStep — anti-debug teknik tespiti pipeline entegrasyonu.

v1.13 Dalga 1: ``karadul/analyzers/anti_debug_detector.py`` (24 PASS) modulunu
pipeline'a entegre eder. ``binary_prep`` sonrasi calisir; arm64 thin slice
resolve edildikten sonra binary uzerinde 3 katmanli tarama yapar (import,
string, bytes).

Akis:
    1. Flag kontrolu: ``config.binary_reconstruction.enable_anti_debug_detection``
       False -> tarama yok; JSON yine yazilir, durum ``kapali``.
    2. Binary path: ``binary_for_byte_match`` artifact'ini kullan
       (universal binary'lerde arm64 slice'a bagli, ``binary_prep`` cozdu).
       Bulunamazsa ``pc.target.path`` fallback'i.
    3. ``AntiDebugDetector(target=pc.target, binary_path=binary_path).detect()``
       ile findings listesi al; katman cagrilari gozlenir (asagida).
    4. ``static/anti_debug_findings.json`` artifact'ini yaz; stats'a ozet.

Durum (P-S1 / IMZA-15): "taranamadi" ile "tarandi, temiz" ayrilir. JSON her
kosulda ``status``, ``status_reason``, ``file_size``, ``scanned_bytes`` ve
katman basina durum (``layers``) tasir. Degerler P03'un tarayici durumlariyla
ayni dizgilerdir (``yara_scanner.STATUS_*`` / ``capa_scanner.STATUS_*``):

    calisti         uc katman calisti, dosyanin tamami tarandi; 0 bulgu = temiz
    kismi           bir katman hata verdi ya da dizgi/bayt katmanlari dosyanin
                    yalniz basini taradi (``max_bytes_scan``)
    hata            hicbir katman calismadi (dosya yok/okunamadi, dedektor kurulamadi,
                    uc katman da hata)
    arac_yok        dedektor modulu yuklenemedi
    kapali          ayarla kapatildi

``calisti`` disindaki her durumda ``total_findings`` 0 DEGIL ``None``dir
(bulunanlar ``findings``'te durur; sayi alt sinirdir).

Durum kaynagi (P02b kalem 3): dedektorun ``scan()``'i bulgularla birlikte
durumu kendisi dondurur (``AntiDebugScan``: katman basina calisti / hata /
desteklenmiyor + neden, taranan bayt). Adim dedektorun ic adlarina bagli
degildir; yalniz sonucu yazar.

Pipeline'da yer:
    binary_prep (binary_for_byte_match resolve eder)
        -> ghidra_metadata
        -> bsim_match
        -> byte_pattern
        -> anti_debug   <-- BURADA (v1.13 Dalga 1)
        -> packer_fingerprint
        -> pcode_cfg_analysis
        ... -> assembly_analysis
"""

from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Any

from karadul.pipeline.context import StepContext
from karadul.pipeline.registry import Step, register_step

logger = logging.getLogger(__name__)

# Tarama durumu sozlugu (P-S1). P03'un tarayicilariyla ayni dizgiler
# (yara_scanner.STATUS_* / capa_scanner.STATUS_*); paketleyici adimi ve statik
# asamanin YARA / capa bloklari bu sabitleri buradan alir.
SCAN_RAN = "calisti"
SCAN_PARTIAL = "kismi"
SCAN_ERROR = "hata"
SCAN_NO_TOOL = "arac_yok"
SCAN_UNSUPPORTED = "desteklenmiyor"
SCAN_DISABLED = "kapali"

def probe_readable(path: Path) -> tuple[int | None, str]:
    """Dosya boyutu ve okunabilirlik: (boyut, hata nedeni). Neden bos = okunabilir.

    Dedektorler okuma hatasini yutup bos veriyle "temiz" donuyor; bu yuzden
    okunabilirlik taramadan once burada denetlenir.
    """
    try:
        size = path.stat().st_size
        with open(path, "rb") as fh:
            fh.read(1)
    except OSError as exc:
        return None, f"ikili okunamadi: {exc}"
    return size, ""


@register_step(
    name="anti_debug",
    requires=[
        "binary_for_byte_match",  # binary_prep'ten gelir (arm64 slice resolve)
    ],
    produces=[
        "anti_debug_findings",       # list[dict] — to_dict() ciktilari
        "anti_debug_summary",        # dict — kategori/teknik ozeti
        "anti_debug_findings_path",  # Path | None — JSON artifact yolu
    ],
    parallelizable_with=[
        # ghidra_metadata sirasi farkli dosyalar uzerinde calisir (functions.json),
        # anti_debug ise ham binary'i okur. Yine de Phase 1 sirali kosulur,
        # ileride paralelleştirme icin not.
        "ghidra_metadata",
        "byte_pattern",
        "packer_fingerprint",
    ],
)
class AntiDebugStep(Step):
    """Anti-debug teknik tespiti — 3 katman (import/string/bytes)."""

    def run(self, ctx: StepContext) -> dict[str, Any]:
        pc = ctx.pipeline_context
        step_start = time.monotonic()

        findings_dicts: list[dict[str, Any]] = []
        summary: dict[str, Any] = {}
        record: dict[str, Any] = {
            "binary_path": None,
            "status": SCAN_ERROR,
            "status_reason": "",
            "file_size": None,
            "scanned_bytes": None,
            "layers": {},
        }

        recon_cfg = getattr(pc.config, "binary_reconstruction", None)
        enabled = bool(getattr(recon_cfg, "enable_anti_debug_detection", True))
        binary_path = self._resolve_binary_path(ctx) if enabled else None

        if not enabled:
            # 1) Ayarla kapali: tarama yok, durum yine yazilir.
            record["status"] = SCAN_DISABLED
            record["status_reason"] = "enable_anti_debug_detection=False"
        elif binary_path is None or not binary_path.exists():
            # 2) Taranacak ikili yok
            logger.warning("anti_debug: binary path bulunamadi/erisilemedi -> skip")
            record["binary_path"] = str(binary_path) if binary_path else None
            record["status_reason"] = f"taranacak ikili yok: {binary_path}"
        else:
            record["binary_path"] = str(binary_path)
            findings_dicts, summary = self._scan(ctx, binary_path, record)

        status = record["status"]
        # "0 bulgu" yalniz tam taramada yazilir; hata/kismi/kapali -> None.
        payload = {
            **record,
            "total_findings": len(findings_dicts) if status == SCAN_RAN else None,
            "findings": findings_dicts,
            "summary": summary,
        }

        # 4) JSON artifact yaz: static/anti_debug_findings.json (her durumda)
        findings_path: Path | None = None
        try:
            findings_path = pc.workspace.save_json(
                "static", "anti_debug_findings", payload,
            )
            ctx.produce_artifact("anti_debug_findings", findings_path)
        except Exception as exc:  # pragma: no cover - defansif
            logger.warning("anti_debug_findings.json yazilamadi: %s", exc)
            ctx.errors.append(f"anti_debug artifact yazimi: {exc}")

        # 5) Stat'lar
        ctx.stats["anti_debug_status"] = status
        if record["status_reason"]:
            ctx.stats["anti_debug_status_reason"] = record["status_reason"]
        if status == SCAN_RAN:
            ctx.stats["anti_debug_total"] = len(findings_dicts)
        if findings_dicts:
            # En yuksek confidence'li teknigi log'a yaz (top-1)
            top = findings_dicts[0]
            ctx.stats["anti_debug_top_technique"] = top.get("technique", "?")
            ctx.stats["anti_debug_top_confidence"] = float(
                top.get("confidence", 0.0),
            )
            # Kategori dagilimini stats'a koy (UI/rapor icin)
            cat_counts: dict[str, int] = {}
            for f in findings_dicts:
                cat = f.get("category", "unknown")
                cat_counts[cat] = cat_counts.get(cat, 0) + 1
            ctx.stats["anti_debug_categories"] = cat_counts
        ctx.stats["timing_anti_debug"] = round(
            time.monotonic() - step_start, 3,
        )

        if findings_dicts:
            logger.info(
                "Anti-debug (%s): %d teknik tespit edildi (top: %s @ %.2f)",
                status, len(findings_dicts),
                ctx.stats.get("anti_debug_top_technique", "?"),
                ctx.stats.get("anti_debug_top_confidence", 0.0),
            )
        elif status == SCAN_RAN:
            logger.info("Anti-debug: tarandi, teknik tespit edilmedi")
        else:
            logger.info("Anti-debug %s: %s", status, record["status_reason"])

        return {
            "anti_debug_findings": findings_dicts,
            "anti_debug_summary": summary,
            "anti_debug_findings_path": findings_path,
        }

    # --- internals -----------------------------------------------------

    @staticmethod
    def _scan(
        ctx: StepContext, binary_path: Path, record: dict[str, Any],
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        """Dedektoru calistir; ``record``'a durum alanlarini yaz."""
        pc = ctx.pipeline_context
        # 3) Detector cagrisi (okunabilirlik denetimi de dedektorun scan()'inde) — analyzer modulunden import (lazy ki test ile mockla)
        try:
            from karadul.analyzers.anti_debug_detector import AntiDebugDetector
        except ImportError as exc:
            logger.debug("AntiDebugDetector bulunamadi: %s", exc)
            record["status"] = SCAN_NO_TOOL
            record["status_reason"] = f"anti_debug_detector yuklenemedi: {exc}"
            return [], {}

        try:
            detector = AntiDebugDetector(target=pc.target, binary_path=binary_path)
            result = detector.scan()
        except Exception as exc:
            logger.warning("Anti-debug tarama hatasi (atlaniyor): %s", exc)
            ctx.errors.append(f"anti_debug: {exc}")
            record["status_reason"] = f"{type(exc).__name__}: {exc}"
            return [], {}

        # Durum dedektorun kendisinden (P02b kalem 3): katman durumu, neden,
        # taranan bayt. Adim yalniz yazar.
        record.update(result.record())
        for err in result.layer_errors:
            ctx.errors.append(f"anti_debug: {err}")
        if result.status == SCAN_ERROR and not result.layer_errors and result.status_reason:
            ctx.errors.append(f"anti_debug: {result.status_reason}")

        findings_dicts = [f.to_dict() for f in result.findings]
        summary: dict[str, Any] = {}
        try:
            summary = detector.summary(result.findings)
        except Exception as exc:  # pragma: no cover - defansif
            logger.debug("AntiDebugDetector.summary() basarisiz, atlanildi: %s", exc)
        return findings_dicts, summary

    @staticmethod
    def _resolve_binary_path(ctx: StepContext) -> Path | None:
        """Tarama yapilacak binary path'ini cozumle.

        Oncelik:
            1. ``binary_for_byte_match`` artifact'i (binary_prep'ten gelir,
               universal binary'lerde arm64 thin slice'i resolve eder).
            2. ``pc.target.path`` (fallback).
        """
        bpm = ctx.artifacts.get("binary_for_byte_match")
        if isinstance(bpm, Path) and bpm.exists():
            return bpm
        pc = ctx.pipeline_context
        target_path = getattr(pc.target, "path", None)
        if target_path is None:
            return None
        return Path(target_path) if not isinstance(target_path, Path) else target_path
