"""Feedback loop — ReferenceDiffer alt-fazi.

stages.py L2566-2650. String'lerden versiyon tespiti + CFG matching.
Yalnizca iter==0 cagrilir.
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any

from karadul.pipeline.steps._feedback_naming_bindiff import (
    KAYNAK_REFDIFF,
    gate_counter,
    pre_name_meta_of,
    update_unprotected,
    write_reference_evidence,
)
from karadul.reconstruction.kimlik import yontem_kapisi as _kapi

logger = logging.getLogger(__name__)


def gate_reference_matches(
    rd_result: Any, *, stats: dict[str, Any], basvuru: str | None = None,
) -> tuple[dict[str, str], dict[str, str], list[dict[str, Any]]]:
    """PK-1: ``ReferenceMatchResult``'ın adlarını yöntem kapısından geçir.

    Her hedef adın yöntemi, ``naming_map``'i kuran kuralla (``ReferenceDiffer._build_naming_map``:
    hedef başına en yüksek güvenli eşleşme, eşitlikte ilk gelen) ``matches``'ten bulunur. Dönen:
    (ad yazabilen ``hedef → başvuru adı``, ``hedef → yöntem``, kanıt satırları). Yöntemi bulunamayan
    ad ölçülmemiş sayılır (kanıt satırı). Sayaçlar ``stats["refdiff_method_gate"]``.
    """
    best: dict[str, tuple[str, float, str | None, str | None]] = {}
    for m in getattr(rd_result, "matches", None) or ():
        t, r = getattr(m, "target_name", None), getattr(m, "ref_name", None)
        if not t or not r:
            continue
        conf = float(getattr(m, "confidence", 0.0) or 0.0)
        prev = best.get(t)
        if prev is None or conf > prev[1]:
            best[t] = (r, conf, getattr(m, "method", None), getattr(m, "target_address", None))
    names: dict[str, str] = {}
    methods: dict[str, str] = {}
    evidence: list[dict[str, Any]] = []
    for t_name, ref_name in (getattr(rd_result, "naming_map", None) or {}).items():
        b = best.get(t_name)
        method = b[2] if b is not None and b[0] == ref_name else None
        if _kapi.ad_verebilir(method):
            names[t_name] = ref_name
            methods[t_name] = str(method)
            gate_counter(stats, "refdiff_method_gate", method, "ad")
            continue
        gate_counter(stats, "refdiff_method_gate", method, "kanit")
        evidence.append(_kapi.kanit_satiri(
            kaynak=KAYNAK_REFDIFF, anahtar=t_name, ad=ref_name, yontem=method,
            adres=b[3] if b is not None else None,
            eslesme_guveni=b[1] if b is not None else None, basvuru=basvuru,
        ))
    return names, methods, evidence


def run_reference_differ(
    *,
    ctx: Any,
    iter_index: int,
    func_data: Any,
    string_data: Any,
    functions_json: Path,
    strings_json: Path,
    call_graph_json: Path,
    cfg_json: Path,
    refdiff_naming: dict[str, str],
    extracted_names: dict[str, str],
    stats: dict[str, Any],
    errors: list[str],
) -> None:
    """ReferenceDiffer: versiyon tespit + naming_map."""
    pc = ctx.pipeline_context
    step_start = time.monotonic()
    if not (
        getattr(pc.config.binary_reconstruction, "enable_reference_differ", True)
        and iter_index == 0
    ):
        stats[f"timing_reference_differ_iter{iter_index}"] = round(
            time.monotonic() - step_start, 1,
        )
        return

    try:
        from karadul.reconstruction.reference_differ import (
            ReferenceDiffer, VersionDetector,
        )
        string_data_for_refdiff = string_data if string_data is not None else (
            json.loads(strings_json.read_text(encoding="utf-8", errors="replace"))
            if strings_json.exists() else None
        )
        if not string_data_for_refdiff:
            return

        vdetector = VersionDetector()
        detections = vdetector.detect_from_strings(string_data_for_refdiff)
        if not detections:
            return

        stats["refdiff_detections"] = [
            {"lib": d.library, "ver": d.version, "conf": d.confidence}
            for d in detections
        ]

        _match_against_db(
            pc=pc, detections=detections,
            func_data=func_data, string_data=string_data_for_refdiff,
            functions_json=functions_json,
            call_graph_json=call_graph_json, cfg_json=cfg_json,
            refdiff_naming=refdiff_naming, stats=stats,
        )

        if refdiff_naming:
            # P13a / AD-11: elle, main ve KS-1 künyeli ön ad ezilmez.
            protected = update_unprotected(
                extracted_names, refdiff_naming, pre_name_meta_of(ctx))
            if protected:
                stats["refdiff_protected_pre_names"] = len(protected)
            logger.info(
                "ReferenceDiffer: %d fonksiyon eslesti", len(refdiff_naming),
            )
    except ImportError:
        logger.debug("ReferenceDiffer modulu bulunamadi, atlaniyor")
    except Exception as exc:
        logger.warning("ReferenceDiffer hatasi (atlaniyor): %s", exc)
        errors.append(f"ReferenceDiffer hatasi: {exc}")
    finally:
        stats[f"timing_reference_differ_iter{iter_index}"] = round(
            time.monotonic() - step_start, 1,
        )


def reference_download_allowed(config: Any) -> bool:
    """Başvuru kaynağı ağdan indirilebilir mi: ana ağ anahtarı ve indirme izni birlikte açık olmalı."""
    net = getattr(config, "network", None)
    return bool(net is not None and getattr(net, "enabled", False)
                and getattr(net, "allow_reference_download", False))


def _match_against_db(
    *,
    pc: Any, detections: Any,
    func_data: Any,
    string_data: Any,
    functions_json: Path,
    call_graph_json: Path,
    cfg_json: Path,
    refdiff_naming: dict[str, str],
    stats: dict[str, Any],
) -> None:
    from karadul.reconstruction.reference_differ import ReferenceDiffer

    ref_db_path = getattr(
        pc.config.binary_reconstruction, "reference_db_path", "",
    )
    ref_path = Path(ref_db_path) if ref_db_path else (
        Path.home() / ".cache" / "karadul" / "ref_db"
    )
    ref_path.mkdir(parents=True, exist_ok=True)
    # Başvuru kaynağını ağdan indirip derlemek (auto_populate) yalnız ağ açıkça açılmışsa:
    # ``network.enabled`` VE ``network.allow_reference_download``. Eskiden koşulsuz True idi;
    # analiz, kullanıcı ağı açmadan kaynak indirmeyi ve ``./Configure`` + ``make`` çalıştırmayı
    # deniyordu ("çevrimdışı öntanımlı" sözüne aykırı).
    differ = ReferenceDiffer(
        reference_db_path=ref_path, auto_populate=reference_download_allowed(pc.config),
    )
    func_data_for_refdiff = func_data if func_data is not None else (
        json.loads(functions_json.read_text(encoding="utf-8", errors="replace"))
        if functions_json.exists() else None
    )
    cfg_data = None
    if cfg_json.exists():
        try:
            cfg_data = json.loads(
                cfg_json.read_text(encoding="utf-8", errors="replace"),
            )
        except Exception:
            logger.debug("CFG JSON parse basarisiz (refdiff)", exc_info=True)
    cg_data = None
    if call_graph_json.exists():
        try:
            cg_data = json.loads(
                call_graph_json.read_text(encoding="utf-8", errors="replace"),
            )
        except Exception:
            logger.debug(
                "Call graph JSON parse basarisiz (refdiff)", exc_info=True,
            )

    for det in detections:
        rd_result = differ.match(
            target_functions=func_data_for_refdiff or {},
            target_strings=string_data,
            target_cfg=cfg_data,
            target_call_graph=cg_data,
            detection=det,
        )
        if rd_result and rd_result.naming_map:
            # PK-1: yalnız kapıdan geçen yöntemin adı ``refdiff_naming``'e; kalan kanıt satırı
            names, methods, evidence = gate_reference_matches(
                rd_result, stats=stats,
                basvuru=f"{det.library}/{getattr(det, 'version', '')}",
            )
            refdiff_naming.update(names)
            stats.setdefault("refdiff_methods", {}).update(methods)
            stats.setdefault("refdiff_evidence", []).extend(evidence)
            stats[f"refdiff_{det.library}_matches"] = rd_result.matched
            stats[f"refdiff_{det.library}_rate"] = rd_result.match_rate
    write_reference_evidence(
        pc=pc, kaynak=KAYNAK_REFDIFF,
        rows=stats.get("refdiff_evidence") or [], stats=stats,
    )
