"""BSimMatchStep — BSim fonksiyon benzerligi SHADOW MODE entegrasyonu.

v1.11.0 Hafta 1 minimum viable wiring. KRITIK: NameMerger'a YAZMAZ, fusion'a
sinyal vermez; yalnizca ``artifacts/bsim_shadow.json`` dump eder. Hafta 2
sonunda shadow verisi kalibre edildikten sonra ``shadow_mode=False`` ile
evidence kanalina baglanacak.

Akis:
    1. Flag kontrolu: ``config.bsim.enabled`` False -> NO-OP.
    2. Girdi: headless asamasinda yazilmis ``bsim_matches.json`` (varsa).
       Yolu resolve et: ``static/ghidra_output/bsim_matches.json``.
       Yoksa: ``reconstructed/bsim_shadow.json`` bos-mode ile dump edilir,
       step sessizce gecer (fail-fast yok).
    3. Shadow dump: match'leri fonksiyon bazli grupla, normalize et,
       ``bsim_shadow.json`` artifact'i olarak kaydet.
    4. shadow_mode=False ise (ileride) fusion'a evidence yayini burada
       eklenecek. Bu sprint'te sadece uyari logu + ayni dump davranisi.

Tasarim notu:
    Step live Ghidra ``program`` objesine erismek icin ``BSimDatabase``
    cagirmaz; headless zaten ``bsim_matches.json``'u yaziyor. Pipeline step
    bunu okuyup normalize eder. Bu sayede:
    - Test kolay (mock JSON yeterli).
    - Ghidra bagimliligi pipeline katmanina sizmaz.
    - Rollback: shadow_mode=True sabit kalir veya config.bsim.enabled=False.
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any

from karadul.ghidra._bsim_shadow import (
    build_shadow_payload as _build_shadow_payload_impl,
)
from karadul.pipeline.context import StepContext
from karadul.pipeline.registry import Step, register_step

logger = logging.getLogger(__name__)


@register_step(
    name="bsim_match",
    requires=[
        "functions_json_path",  # ghidra_metadata.py'den gelir (resolve edildi)
    ],
    produces=[
        "bsim_shadow",          # dict: {mode, matches, total_matches, ...}
        "bsim_shadow_path",     # Path | None — yazildiysa artifact yolu
    ],
    parallelizable_with=[],
)
class BSimMatchStep(Step):
    """BSim shadow mode step — dump-only, NameMerger'a yazmaz."""

    def run(self, ctx: StepContext) -> dict[str, Any]:
        pc = ctx.pipeline_context
        step_start = time.monotonic()

        bsim_cfg = getattr(pc.config, "bsim", None)
        enabled = bool(getattr(bsim_cfg, "enabled", False))
        shadow_mode = bool(getattr(bsim_cfg, "shadow_mode", True))

        empty: dict[str, Any] = {
            "bsim_shadow": None,
            "bsim_shadow_path": None,
        }

        if not enabled:
            ctx.stats["timing_bsim_match"] = round(
                time.monotonic() - step_start, 3,
            )
            ctx.stats["bsim_shadow_status"] = "disabled"
            return empty

        # 1) Headless ciktisini bul: static/ghidra_output/bsim_matches.json
        raw_matches_json = self._locate_raw_matches(pc)
        raw_data: dict[str, Any] | None = None
        if raw_matches_json is not None and raw_matches_json.exists():
            try:
                raw_data = json.loads(
                    raw_matches_json.read_text(
                        encoding="utf-8", errors="replace",
                    ),
                )
            except Exception as exc:  # pragma: no cover - defansif
                logger.warning(
                    "bsim_matches.json parse hatasi: %s -- %s",
                    raw_matches_json, exc,
                )
                ctx.errors.append(f"bsim_match parse hatasi: {exc}")
                raw_data = None

        # 2) Shadow payload'i kur
        shadow_payload = self._build_shadow_payload(
            raw_data=raw_data,
            shadow_mode=shadow_mode,
        )

        # 3) Artifact'a yaz (shadow dump)
        shadow_path: Path | None = None
        try:
            shadow_path = pc.workspace.save_json(
                "reconstructed", "bsim_shadow", shadow_payload,
            )
            ctx.produce_artifact("bsim_shadow_matches", shadow_path)
        except Exception as exc:  # pragma: no cover - defansif
            logger.warning("bsim_shadow dump basarisiz: %s", exc)
            ctx.errors.append(f"bsim_shadow dump hatasi: {exc}")

        # 4) Stat'lar
        ctx.stats["bsim_shadow_status"] = (
            "shadow" if shadow_mode else "live-dump-only"
        )
        ctx.stats["bsim_shadow_total"] = shadow_payload["total_matches"]
        ctx.stats["bsim_shadow_functions"] = len(shadow_payload["matches"])
        ctx.stats["timing_bsim_match"] = round(
            time.monotonic() - step_start, 3,
        )

        use_bsim_fusion = bool(getattr(bsim_cfg, "use_bsim_fusion", False))
        if shadow_mode:
            logger.info(
                "BSim SHADOW: %d fonksiyon, %d esleme — fusion'a YAZILMADI",
                len(shadow_payload["matches"]),
                shadow_payload["total_matches"],
            )
        elif use_bsim_fusion:
            # v1.11.0 Hafta 2: kopru aktif. Bu step yalnizca dump'i
            # garanti eder; asil evidence enjeksiyonunu _feedback_naming_merger
            # (run_name_merger) bu payload'i okuyarak yapiyor.
            logger.info(
                "BSim FUSION aktif: %d fonksiyon, %d esleme shadow dump'tan "
                "NameMerger'a gonderilecek (source=bsim, weight=0.85).",
                len(shadow_payload["matches"]),
                shadow_payload["total_matches"],
            )
        else:
            # shadow_mode=False AMA use_bsim_fusion=False — opt-in bekleniyor
            logger.warning(
                "BSim shadow_mode=False AMA use_bsim_fusion=False — "
                "kopru kapali. NameMerger'a YAZILMADI. Aktifleştirmek "
                "icin: config.bsim.use_bsim_fusion = True.",
            )

        return {
            "bsim_shadow": shadow_payload,
            "bsim_shadow_path": shadow_path,
        }

    # --- internals -----------------------------------------------------

    @staticmethod
    def _locate_raw_matches(pc: Any) -> Path | None:
        """Headless'in yazdigi bsim_matches.json'u bul.

        Oncelik: static/ghidra_output/bsim_matches.json. Fallback olarak
        deobfuscated/ altinda da aranir (obfuscation pass sonrasi ayri
        tarama olmus olabilir).
        """
        try:
            static_dir = pc.workspace.get_stage_dir("static")
            deob_dir = pc.workspace.get_stage_dir("deobfuscated")
        except Exception as e:
            # Workspace stage-dir yoksa (pipeline init eksik) -> None don.
            logger.debug(
                "workspace stage-dir alinamadi, bsim_matches aranmayacak: %s",
                e, exc_info=True,
            )
            return None

        candidates = [
            static_dir / "ghidra_output" / "bsim_matches.json",
            static_dir / "bsim_matches.json",
            deob_dir / "ghidra_output" / "bsim_matches.json",
            deob_dir / "bsim_matches.json",
        ]
        for c in candidates:
            try:
                if c.exists():
                    return c
            except OSError as e:
                # Graceful: mount/izin hatasi olan path'i atla.
                logger.debug("bsim_matches path erisim hatasi %s: %s", c, e)
                continue
        return None

    @staticmethod
    def _build_shadow_payload(
        *,
        raw_data: dict[str, Any] | None,
        shadow_mode: bool,
    ) -> dict[str, Any]:
        """Geriye uyumluluk shim'i — gercek implementasyon
        ``karadul.ghidra._bsim_shadow.build_shadow_payload``."""
        return _build_shadow_payload_impl(
            raw_data=raw_data,
            shadow_mode=shadow_mode,
        )
