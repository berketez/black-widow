"""BSim shadow payload format utility (v1.11.0+).

Hem `karadul.pipeline.steps.bsim_match.BSimMatchStep` (registry yolu) hem de
`karadul.ghidra.headless` (legacy yolu) ayni shadow JSON formatini uretsin
diye payload kurma mantigi tek noktada toplanmistir.

Tasarim notu:
    - Pipeline registry'ye yan etki yapmaz (bsim_match.py decorator import
      etmiyor) — bu yuzden legacy headless'tan import edildiginde step kayiti
      tetiklenmez.
    - Saf veri donusumu: dis bagimliligi yok, datetime + dict reshape.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

SHADOW_VERSION = "1"


def build_shadow_payload(
    *,
    raw_data: dict[str, Any] | None,
    shadow_mode: bool,
) -> dict[str, Any]:
    """bsim_matches.json'i fonksiyon bazli gruplanmis shadow formatina cevir.

    Input (headless.py BSim query format):
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
                {"name": str, "similarity": float, "binary": str,
                 "exe_md5": str, "exe_sha256": str, "source": str}, ...
             ]}, ...
          ],
          "bsim_mode": "native" | "lite" | None,
          "bsim_status": "ok" | "fallback_lite" | "skipped_busy" | ... | None,
          "bsim_detail": {...} | None
        }

    ``bsim_mode`` / ``bsim_status`` / ``bsim_detail`` ham veride yoksa (eski
    headless) ``None`` yazilir: "bilinmiyor", "basarili" degil (P16b).
    Adayin kaynagi (``exe_md5``, ``exe_sha256``, ``source``) ham kayitta
    yoksa bos dizgi kalir.
    """
    mode = "shadow" if shadow_mode else "live-dump-only"
    now = datetime.now(timezone.utc).isoformat()

    base: dict[str, Any] = {
        "version": SHADOW_VERSION,
        "mode": mode,
        "timestamp": now,
        "database": "",
        "total_matches": 0,
        "matches": [],
        "bsim_mode": None,
        "bsim_status": None,
        "bsim_detail": None,
    }

    if not raw_data or not isinstance(raw_data, dict):
        return base

    base["database"] = str(raw_data.get("database", "") or "")
    for key in ("bsim_mode", "bsim_status"):
        val = raw_data.get(key)
        base[key] = str(val) if val else None
    detail = raw_data.get("bsim_detail")
    base["bsim_detail"] = detail if isinstance(detail, dict) else None
    raw_matches = raw_data.get("matches") or []
    if not isinstance(raw_matches, list):
        return base

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
            "exe_md5": str(m.get("matched_exe_md5", "") or ""),
            "exe_sha256": str(m.get("matched_exe_sha256", "") or ""),
            "source": str(m.get("matched_source", "") or ""),
        })
        total += 1

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
