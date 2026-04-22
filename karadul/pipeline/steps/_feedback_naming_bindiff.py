"""Feedback loop — BinDiff alt-fazi.

stages.py L2396-2564'un birebir kopyasi. BinDiff iki kaynaktan eslestirir:
(a) reference_binary config (geriye uyum), (b) ref_db cache auto-scan.
Per-match confidence map iter'lar arasi persistent tutulur.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def run_bindiff(
    *,
    ctx: Any,
    func_data: Any,
    string_data: Any,
    functions_json: Path,
    strings_json: Path,
    call_graph_json: Path,
    bindiff_confidence_map: dict[str, tuple[str, float, str]],
    bindiff_names: dict[str, str],
    extracted_names: dict[str, str],
    stats: dict[str, Any],
    errors: list[str],
) -> None:
    """BinDiff (config + ref_db) eslestirme; yalnizca iter==0 cagrilir."""
    pc = ctx.pipeline_context
    try:
        from karadul.analyzers.bindiff import BinaryDiffer
        differ = BinaryDiffer()

        target_func_data = func_data if isinstance(func_data, dict) else (
            json.loads(functions_json.read_text(encoding="utf-8", errors="replace"))
            if functions_json.exists() else None
        )
        target_str_data = string_data if string_data is not None else (
            json.loads(strings_json.read_text(encoding="utf-8", errors="replace"))
            if strings_json.exists() else None
        )

        _config_source(
            pc=pc, differ=differ,
            target_func_data=target_func_data,
            target_str_data=target_str_data,
            bindiff_confidence_map=bindiff_confidence_map,
            bindiff_names=bindiff_names,
            stats=stats,
        )

        if target_func_data:
            _refdb_source(
                pc=pc, differ=differ,
                target_func_data=target_func_data,
                target_str_data=target_str_data,
                call_graph_json=call_graph_json,
                bindiff_confidence_map=bindiff_confidence_map,
                bindiff_names=bindiff_names,
                stats=stats,
            )

        if bindiff_names:
            stats["bindiff_matches"] = len(bindiff_names)
            extracted_names.update(bindiff_names)
            logger.info(
                "BinDiff toplam: %d fonksiyon eslesti", len(bindiff_names),
            )
    except ImportError:
        logger.debug("BinDiff modulu bulunamadi, atlaniyor")
    except Exception as exc:
        logger.warning("BinDiff hatasi (atlaniyor): %s", exc)
        errors.append(f"BinDiff hatasi: {exc}")


def _config_source(
    *,
    pc: Any, differ: Any,
    target_func_data: Any,
    target_str_data: Any,
    bindiff_confidence_map: dict[str, tuple[str, float, str]],
    bindiff_names: dict[str, str],
    stats: dict[str, Any],
) -> None:
    """Kaynak (a): reference_binary config."""
    ref_binary = getattr(
        pc.config.binary_reconstruction, "reference_binary", "",
    )
    if not (ref_binary and Path(ref_binary).exists()):
        return
    try:
        ref_functions_json = Path(ref_binary).parent / "ghidra_functions.json"
        ref_strings_json = Path(ref_binary).parent / "ghidra_strings.json"
        if not (ref_functions_json.exists() and target_func_data):
            logger.debug(
                "BinDiff(config): referans Ghidra ciktilari bulunamadi (%s)",
                ref_functions_json if ref_binary else "N/A",
            )
            return

        ref_data = json.loads(
            ref_functions_json.read_text(encoding="utf-8", errors="replace"),
        )
        ref_str_data = None
        if ref_strings_json.exists():
            ref_str_data = json.loads(
                ref_strings_json.read_text(encoding="utf-8", errors="replace"),
            )
        diff_result = differ.compare(
            reference=ref_data, target=target_func_data,
            ref_strings=ref_str_data, target_strings=target_str_data,
        )
        conf_map = differ.transfer_names_with_confidence(diff_result)
        if conf_map:
            bindiff_confidence_map.update(conf_map)
            bindiff_names.update(differ.transfer_names(diff_result))
            stats["bindiff_config_matches"] = len(conf_map)
            stats["bindiff_config_match_rate"] = diff_result.match_rate
            logger.info(
                "BinDiff(config): %d fonksiyon eslesti (match_rate=%.2f)",
                len(conf_map), diff_result.match_rate,
            )
    except Exception as exc:
        logger.warning("BinDiff(config) hatasi (atlaniyor): %s", exc)


def _refdb_source(
    *,
    pc: Any, differ: Any,
    target_func_data: Any,
    target_str_data: Any,
    call_graph_json: Path,
    bindiff_confidence_map: dict[str, tuple[str, float, str]],
    bindiff_names: dict[str, str],
    stats: dict[str, Any],
) -> None:
    """Kaynak (b): ref_db auto-scan (reference_binary gerektirmez)."""
    try:
        ref_db_path = getattr(
            pc.config.binary_reconstruction, "reference_db_path", "",
        )
        ref_db_dir = Path(ref_db_path) if ref_db_path else (
            Path.home() / ".cache" / "karadul" / "ref_db"
        )
        if not ref_db_dir.exists():
            return

        from karadul.reconstruction.reference_differ import ReferenceDB
        ref_db = ReferenceDB(ref_db_dir)
        ref_db_entries = ref_db.all_entries()

        target_cg_data = None
        if call_graph_json.exists():
            try:
                target_cg_data = json.loads(
                    call_graph_json.read_text(encoding="utf-8", errors="replace"),
                )
            except Exception:
                logger.debug(
                    "Call graph JSON parse basarisiz (refdb)", exc_info=True,
                )

        refdb_total = 0
        for rdb_entry in ref_db_entries:
            if not rdb_entry.functions_json.exists():
                continue
            try:
                rdb_funcs = json.loads(
                    rdb_entry.functions_json.read_text(
                        encoding="utf-8", errors="replace",
                    ),
                )
                rdb_strings = None
                if rdb_entry.strings_json and rdb_entry.strings_json.exists():
                    rdb_strings = json.loads(
                        rdb_entry.strings_json.read_text(
                            encoding="utf-8", errors="replace",
                        ),
                    )
                rdb_call_graph = None
                if (
                    rdb_entry.call_graph_json
                    and rdb_entry.call_graph_json.exists()
                ):
                    rdb_call_graph = json.loads(
                        rdb_entry.call_graph_json.read_text(
                            encoding="utf-8", errors="replace",
                        ),
                    )

                rdb_diff = differ.compare(
                    reference=rdb_funcs,
                    target=target_func_data,
                    ref_strings=rdb_strings,
                    target_strings=target_str_data,
                    ref_call_graph=rdb_call_graph,
                    target_call_graph=target_cg_data,
                )
                rdb_conf = differ.transfer_names_with_confidence(rdb_diff)
                if rdb_conf:
                    for t_name, (ref_name, conf, method) in rdb_conf.items():
                        existing = bindiff_confidence_map.get(t_name)
                        if existing is None or conf > existing[1]:
                            bindiff_confidence_map[t_name] = (
                                ref_name, conf, method,
                            )
                            bindiff_names[t_name] = ref_name
                    refdb_total += len(rdb_conf)
                    logger.debug(
                        "BinDiff(ref_db): %s/%s -- %d eslesti",
                        rdb_entry.library, rdb_entry.version, len(rdb_conf),
                    )
            except Exception as rdb_exc:
                logger.debug(
                    "BinDiff(ref_db): %s/%s hatasi: %s",
                    rdb_entry.library, rdb_entry.version, rdb_exc,
                )
                continue

        if refdb_total > 0:
            stats["bindiff_refdb_matches"] = refdb_total
            logger.info(
                "BinDiff(ref_db): toplam %d fonksiyon eslesti (%d kutuphane)",
                refdb_total, len(ref_db_entries),
            )
    except ImportError:
        logger.debug("BinDiff(ref_db): ReferenceDB import edilemedi")
    except Exception as exc:
        logger.warning("BinDiff(ref_db) hatasi (atlaniyor): %s", exc)
