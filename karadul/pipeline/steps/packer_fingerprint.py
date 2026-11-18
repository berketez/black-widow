"""PackerFingerprintStep — packer/protector fingerprint pipeline entegrasyonu.

v1.13 Dalga 1: ``karadul/analyzers/packer_fingerprint.py`` (35 PASS) modulunu
pipeline'a entegre eder. ``binary_prep`` sonrasi calisir; 3 katmanli tarama
yapar (section names, string markers, entry-point byte pattern).

Akis:
    1. Flag kontrolu: ``config.binary_reconstruction.enable_packer_fingerprint``
       False -> tarama yok; JSON yine yazilir, durum ``kapali``.
    2. Binary path: ``binary_for_byte_match`` artifact'i tercih edilir
       (universal binary -> arm64 slice). Yoksa ``pc.target.path``.
    3. ``PackerFingerprintDetector(binary_path).detect()`` cagrir, multi-layer
       boost edilmis fingerprint listesi gelir.
    4. ``static/packer_fingerprints.json`` artifact'i yaz; stats'a ozet
       (toplam, top packer, kategori dagilimi).

Durum (P-S1 / IMZA-15): JSON her kosulda ``status``, ``status_reason``,
``file_size``, ``scanned_bytes`` (bolum + giris noktasi katmanlarinin okudugu)
ve ``string_scan_bytes`` (dizgi katmaninin taradigi) tasir; sozluk
``anti_debug`` adimindakiyle ayni (``calisti`` / ``kismi`` / ``hata`` /
``arac_yok`` / ``kapali``). ``calisti`` disinda ``total_fingerprints`` 0 DEGIL
``None``dir: kismi taramada dosya sonundaki isaretler (or. PyInstaller TOC)
kacabilir, hata durumunda hic tarama yoktur.

Tasarim notu:
    Packer fingerprinting **erken** bir analiz adimi: yuksek confidence ile
    UPX/VMProtect/Themida tespit edildiyse downstream component'ler (decompile,
    unpack, capa) bunu metadata olarak kullanabilir. ``packed_binary.py``
    icindeki ``PackingDetector`` ile entegrasyon Wave 3'e ertelendi (analyzer
    icindeki entegrasyon notuna bakin).

Pipeline'da yer:
    binary_prep
        -> ghidra_metadata
        -> bsim_match
        -> byte_pattern
        -> anti_debug
        -> packer_fingerprint   <-- BURADA (v1.13 Dalga 1)
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
from karadul.pipeline.steps.anti_debug import (
    SCAN_DISABLED,
    SCAN_ERROR,
    SCAN_NO_TOOL,
    SCAN_PARTIAL,
    SCAN_RAN,
    probe_readable,
)

logger = logging.getLogger(__name__)


@register_step(
    name="packer_fingerprint",
    requires=[
        "binary_for_byte_match",  # binary_prep'ten gelir
    ],
    produces=[
        "packer_fingerprints",        # list[dict] — to_dict() ciktilari
        "packer_top_match",           # dict | None — en yuksek confidence
        "packer_fingerprints_path",   # Path | None — JSON artifact yolu
    ],
    parallelizable_with=[
        "ghidra_metadata",
        "byte_pattern",
        "anti_debug",
    ],
)
class PackerFingerprintStep(Step):
    """Packer fingerprint tarayicisi — section/string/entry pattern."""

    def run(self, ctx: StepContext) -> dict[str, Any]:
        pc = ctx.pipeline_context
        step_start = time.monotonic()

        fingerprints_dicts: list[dict[str, Any]] = []
        record: dict[str, Any] = {
            "binary_path": None,
            "status": SCAN_ERROR,
            "status_reason": "",
            "file_size": None,
            "scanned_bytes": None,
            "string_scan_bytes": None,
        }

        # 1) Flag — opt-out icin BinaryReconstructionConfig.enable_packer_fingerprint
        recon_cfg = getattr(pc.config, "binary_reconstruction", None)
        enabled = bool(
            getattr(recon_cfg, "enable_packer_fingerprint", True),
        )
        binary_path = self._resolve_binary_path(ctx) if enabled else None

        if not enabled:
            record["status"] = SCAN_DISABLED
            record["status_reason"] = "enable_packer_fingerprint=False"
        elif binary_path is None or not binary_path.exists():
            # 2) Binary yolu cozumle (anti_debug ile ayni mantik)
            logger.warning("packer_fingerprint: binary path yok -> skip")
            record["binary_path"] = str(binary_path) if binary_path else None
            record["status_reason"] = f"taranacak ikili yok: {binary_path}"
        else:
            record["binary_path"] = str(binary_path)
            fingerprints_dicts = self._scan(ctx, binary_path, record)

        status = record["status"]
        # "0 paketleyici" yalniz tam taramada yazilir; hata/kismi/kapali -> None.
        payload = {
            **record,
            "total_fingerprints": len(fingerprints_dicts) if status == SCAN_RAN else None,
            "fingerprints": fingerprints_dicts,
        }

        # 4) JSON artifact yaz: static/packer_fingerprints.json (her durumda)
        fp_path: Path | None = None
        try:
            fp_path = pc.workspace.save_json(
                "static", "packer_fingerprints", payload,
            )
            ctx.produce_artifact("packer_fingerprints", fp_path)
        except Exception as exc:  # pragma: no cover - defansif
            logger.warning(
                "packer_fingerprints.json yazilamadi: %s", exc,
            )
            ctx.errors.append(f"packer_fingerprint artifact: {exc}")

        # 5) Stat'lar
        top_match: dict[str, Any] | None = None
        ctx.stats["packer_fingerprint_status"] = status
        if record["status_reason"]:
            ctx.stats["packer_fingerprint_status_reason"] = record["status_reason"]
        if status == SCAN_RAN:
            ctx.stats["packer_total"] = len(fingerprints_dicts)
        if fingerprints_dicts:
            top_match = fingerprints_dicts[0]  # detect() confidence DESC sort
            ctx.stats["packer_top_name"] = top_match.get("packer_name", "?")
            ctx.stats["packer_top_confidence"] = float(
                top_match.get("confidence", 0.0),
            )
            ctx.stats["packer_top_layers"] = int(
                top_match.get("layers_matched", 0),
            )
            cat_counts: dict[str, int] = {}
            for fp in fingerprints_dicts:
                cat = fp.get("category", "unknown")
                cat_counts[cat] = cat_counts.get(cat, 0) + 1
            ctx.stats["packer_categories"] = cat_counts
        ctx.stats["timing_packer_fingerprint"] = round(
            time.monotonic() - step_start, 3,
        )

        if fingerprints_dicts:
            logger.info(
                "Packer fingerprint (%s): %d eslesme (top: %s @ %.2f, %d katman)",
                status, len(fingerprints_dicts),
                ctx.stats.get("packer_top_name", "?"),
                ctx.stats.get("packer_top_confidence", 0.0),
                ctx.stats.get("packer_top_layers", 0),
            )
        elif status == SCAN_RAN:
            logger.info("Packer fingerprint: tarandi, paketleyici izi yok")
        else:
            logger.info("Packer fingerprint %s: %s", status, record["status_reason"])

        return {
            "packer_fingerprints": fingerprints_dicts,
            "packer_top_match": top_match,
            "packer_fingerprints_path": fp_path,
        }

    # --- internals -----------------------------------------------------

    @staticmethod
    def _scan(
        ctx: StepContext, binary_path: Path, record: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """Dedektoru calistir; ``record``'a durum alanlarini yaz."""
        file_size, read_error = probe_readable(binary_path)
        record["file_size"] = file_size
        if read_error:
            record["status_reason"] = read_error
            ctx.errors.append(f"packer_fingerprint: {read_error}")
            return []

        # 3) Detector cagrisi
        try:
            from karadul.analyzers.packer_fingerprint import (
                PackerFingerprintDetector,
            )
        except ImportError as exc:
            logger.debug("PackerFingerprintDetector bulunamadi: %s", exc)
            record["status"] = SCAN_NO_TOOL
            record["status_reason"] = f"packer_fingerprint dedektoru yuklenemedi: {exc}"
            return []

        try:
            detector = PackerFingerprintDetector(binary_path)
            fingerprints = detector.detect()
        except Exception as exc:
            # detect() katman istisnasini yutmaz: biri duserse hic sonuc yok.
            logger.warning(
                "Packer fingerprint hatasi (atlaniyor): %s", exc,
            )
            ctx.errors.append(f"packer_fingerprint: {exc}")
            record["status_reason"] = f"{type(exc).__name__}: {exc}"
            return []

        # Dedektor dosyanin ilk MAX_READ_BYTES'ini okur; dizgi katmani bunun
        # ilk MAX_STRING_SCAN_BYTES'ini tarar (OOM korumasi). Kisitlar
        # dedektorun kendi sabitlerinden okunur (IMZA-15).
        scanned = min(file_size, int(detector.MAX_READ_BYTES))
        string_scanned = min(scanned, int(detector.MAX_STRING_SCAN_BYTES))
        record["scanned_bytes"] = scanned
        record["string_scan_bytes"] = string_scanned
        reasons: list[str] = []
        if scanned < file_size:
            reasons.append(
                f"bolum ve giris noktasi katmanlari dosyanin ilk {scanned} baytini "
                f"okudu (dosya {file_size} bayt)",
            )
        if string_scanned < file_size:
            reasons.append(
                f"dizgi katmani dosyanin ilk {string_scanned} baytini taradi "
                f"(dosya {file_size} bayt)",
            )
        record["status"] = SCAN_PARTIAL if reasons else SCAN_RAN
        record["status_reason"] = "; ".join(reasons)
        return [fp.to_dict() for fp in fingerprints]

    @staticmethod
    def _resolve_binary_path(ctx: StepContext) -> Path | None:
        """``binary_for_byte_match`` -> ``pc.target.path`` fallback."""
        bpm = ctx.artifacts.get("binary_for_byte_match")
        if isinstance(bpm, Path) and bpm.exists():
            return bpm
        pc = ctx.pipeline_context
        target_path = getattr(pc.target, "path", None)
        if target_path is None:
            return None
        return Path(target_path) if not isinstance(target_path, Path) else target_path
