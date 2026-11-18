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

Katman gozlemi: dedektorun ``detect()``'i katman istisnalarini yutup yalniz
uyari gunlugune yazar. Orkestrasyon (katman sirasi, cok-katman artirimi,
siralama) dedektorde kalsin diye ``detect()`` cagrilir; adim yalniz bu ornegin
katman yontemlerini sararak hangisinin istisna attigini kaydeder (istisna yine
``detect()``'e iletilir, davranis degismez).

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

# Dedektorun detect()'te sirayla cagirdigi katmanlar: rapordaki ad -> yontem
_LAYERS = (
    ("imports", "detect_by_imports"),
    ("strings", "detect_by_strings"),
    ("bytes", "detect_by_bytes"),
)


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


def _observe_layers(detector: Any) -> dict[str, dict[str, str]]:
    """``detector``'un katman yontemlerini bu ornek icin sar; sonucu kaydet.

    Donen sozluk ``detect()`` cagrildikca dolar: katman adi -> {"status", "reason"}.
    Istisna kaydedilip yeniden firlatilir (``detect()`` onu eskisi gibi yutar).
    """
    observed: dict[str, dict[str, str]] = {}
    for layer, meth_name in _LAYERS:
        original = getattr(detector, meth_name)

        def wrapped(*args: Any, _orig: Any = original, _layer: str = layer,
                    **kwargs: Any) -> Any:
            try:
                found = _orig(*args, **kwargs)
            except Exception as exc:
                observed[_layer] = {
                    "status": SCAN_ERROR,
                    "reason": f"{type(exc).__name__}: {exc}",
                }
                raise
            observed[_layer] = {"status": SCAN_RAN, "reason": ""}
            return found

        setattr(detector, meth_name, wrapped)
    return observed


def _bytes_layer_scope(detector: Any) -> str:
    """Bayt katmani bu ikilide uygulanabilir mi? Uygulanamazsa neden, yoksa ''.

    Dedektor x86 islem kodu taramasini yalniz x86 / x86-64 kod bolgelerinde
    yapar; baska mimaride katman sessizce bos doner. Bunu "tarandi, temiz"
    saymamak icin yerlesim (dedektorun onbellegi) okunur.
    """
    from karadul.analyzers.anti_debug_detector import _X86_ARCHES

    layout = detector._code_layout()
    if layout.arch in _X86_ARCHES and layout.regions:
        return ""
    if layout.arch in _X86_ARCHES:
        return f"{layout.fmt}/{layout.arch}: yurutulebilir kod bolgesi bulunamadi"
    return (f"{layout.fmt}/{layout.arch}: x86 islem kodu taramasi (RDTSC, PEB, INT3) "
            "bu mimaride uygulanmaz")


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
        file_size, read_error = probe_readable(binary_path)
        record["file_size"] = file_size
        if read_error:
            record["status_reason"] = read_error
            ctx.errors.append(f"anti_debug: {read_error}")
            return [], {}

        # 3) Detector cagrisi — analyzer modulunden import (lazy ki test ile mockla)
        try:
            from karadul.analyzers.anti_debug_detector import AntiDebugDetector
        except ImportError as exc:
            logger.debug("AntiDebugDetector bulunamadi: %s", exc)
            record["status"] = SCAN_NO_TOOL
            record["status_reason"] = f"anti_debug_detector yuklenemedi: {exc}"
            return [], {}

        try:
            detector = AntiDebugDetector(target=pc.target, binary_path=binary_path)
            layers = _observe_layers(detector)
            findings = detector.detect()
        except Exception as exc:
            logger.warning("Anti-debug tarama hatasi (atlaniyor): %s", exc)
            ctx.errors.append(f"anti_debug: {exc}")
            record["status_reason"] = f"{type(exc).__name__}: {exc}"
            return [], {}

        findings_dicts = [f.to_dict() for f in findings]
        summary: dict[str, Any] = {}
        try:
            summary = detector.summary(findings)
        except Exception as exc:  # pragma: no cover - defansif
            logger.debug("AntiDebugDetector.summary() basarisiz, atlanildi: %s", exc)

        for layer, _ in _LAYERS:
            layers.setdefault(layer, {
                "status": SCAN_ERROR,
                "reason": "katman detect() icinde cagrilmadi",
            })
        if layers["bytes"]["status"] == SCAN_RAN:
            try:
                scope = _bytes_layer_scope(detector)
            except Exception as exc:  # pragma: no cover - defansif
                scope = ""
                logger.debug("anti_debug: bayt katmani kapsami okunamadi: %s", exc)
            if scope:
                layers["bytes"] = {"status": SCAN_UNSUPPORTED, "reason": scope}
        record["layers"] = layers

        max_scan = getattr(detector, "max_bytes_scan", None)
        scanned = file_size if not isinstance(max_scan, int) else min(file_size, max_scan)
        record["scanned_bytes"] = scanned

        failed = [(n, s["reason"]) for n, s in layers.items() if s["status"] == SCAN_ERROR]
        reasons = [f"{n} katmani: {r}" for n, r in failed]
        for r in reasons:
            ctx.errors.append(f"anti_debug: {r}")
        if scanned < file_size:
            reasons.append(
                f"dizgi ve bayt katmanlari dosyanin ilk {scanned} baytini taradi "
                f"(dosya {file_size} bayt)",
            )
        if len(failed) == len(layers):
            record["status"] = SCAN_ERROR
        elif reasons:
            record["status"] = SCAN_PARTIAL
        else:
            record["status"] = SCAN_RAN
        record["status_reason"] = "; ".join(reasons)
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
