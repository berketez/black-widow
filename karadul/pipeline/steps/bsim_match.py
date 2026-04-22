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
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from karadul.pipeline.context import StepContext
from karadul.pipeline.registry import Step, register_step

logger = logging.getLogger(__name__)

_SHADOW_VERSION = "1"


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

        if shadow_mode:
            logger.info(
                "BSim SHADOW: %d fonksiyon, %d esleme — fusion'a YAZILMADI",
                len(shadow_payload["matches"]),
                shadow_payload["total_matches"],
            )
        else:
            # KRITIK: shadow_mode False olsa bile bu sprint'te fusion'a
            # YAZMIYORUZ. Sadece uyari ile iz birak — takim kararinda
            # fusion wiring'i ayri commit'te eklenecek.
            logger.warning(
                "BSim shadow_mode=False AMA fusion wiring henuz yok. "
                "Shadow dump ile devam ediliyor. NameMerger baglanmadi.",
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
        """bsim_matches.json'i fonksiyon bazli gruplanmis shadow formatina cevir.

        Input (headless.py L406-L419 format):
            {
              "total_matches": N,
              "database": "...",
              "matches": [
                {"query_function": str, "query_address": hex-str,
                 "matched_function": str, "matched_program": str,
                 "similarity": float}, ...
              ]
            }

        Output (v1 shadow):
            {
              "version": "1",
              "mode": "shadow" | "live-dump-only",
              "timestamp": iso8601,
              "database": str,
              "total_matches": int,
              "matches": [
                {"function_addr": hex-str, "function_name": str,
                 "bsim_candidates": [
                    {"name": str, "similarity": float, "binary": str}, ...
                 ]}, ...
              ]
            }
        """
        mode = "shadow" if shadow_mode else "live-dump-only"
        now = datetime.now(timezone.utc).isoformat()

        base: dict[str, Any] = {
            "version": _SHADOW_VERSION,
            "mode": mode,
            "timestamp": now,
            "database": "",
            "total_matches": 0,
            "matches": [],
        }

        if not raw_data or not isinstance(raw_data, dict):
            return base

        base["database"] = str(raw_data.get("database", "") or "")
        raw_matches = raw_data.get("matches") or []
        if not isinstance(raw_matches, list):
            return base

        # Fonksiyon bazli grupla: query_function + query_address anahtarli
        grouped: dict[tuple[str, str], dict[str, Any]] = {}
        total = 0
        for m in raw_matches:
            if not isinstance(m, dict):
                continue
            q_name = str(m.get("query_function", "") or "")
            q_addr = str(m.get("query_address", "") or "")
            if not q_name and not q_addr:
                continue
            key = (q_addr, q_name)
            entry = grouped.setdefault(key, {
                "function_addr": q_addr,
                "function_name": q_name,
                "bsim_candidates": [],
            })
            try:
                sim = float(m.get("similarity", 0.0) or 0.0)
            except (TypeError, ValueError):
                sim = 0.0
            entry["bsim_candidates"].append({
                "name": str(m.get("matched_function", "") or ""),
                "similarity": sim,
                "binary": str(m.get("matched_program", "") or ""),
            })
            total += 1

        # Deterministik cikti: function_addr -> function_name'e gore sirala,
        # her fonksiyonun candidate'larini similarity desc sirala.
        matches_out: list[dict[str, Any]] = []
        for key in sorted(grouped.keys()):
            entry = grouped[key]
            entry["bsim_candidates"].sort(
                key=lambda c: c.get("similarity", 0.0), reverse=True,
            )
            matches_out.append(entry)

        base["total_matches"] = total
        base["matches"] = matches_out
        return base
