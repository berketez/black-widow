"""CFGIsoMatchStep -- hibrit CFG isomorphism template matching step'i.

v1.10.0 M4 entegrasyonu: ``karadul.computation.cfg_iso`` paketini pipeline'a
bagliyor. Feature flag
``ComputationRecoveryConfig.enable_cfg_iso`` True ise, Ghidra'nin
CFGAnalysisResult'undan her fonksiyon icin bir AttributedCFG uretilir,
``HybridCFGMatcher`` ile template bank'ina karsi LSH + VF2 + anchor
pipeline'i kosulur ve min_confidence uzerindeki en iyi eslemeler
artifact olarak yayinlanir.

Cikti format:
    cfg_iso_matches: dict[str, CFGMatch]  -- fn_addr -> en iyi match.

Downstream: fusion step'i veya eski feedback loop bu map'i
``computation_fusion`` sinyali olarak kullanabilir.
"""

from __future__ import annotations

import logging
import time
from typing import Any

from karadul.pipeline.context import StepContext
from karadul.pipeline.registry import Step, register_step

logger = logging.getLogger(__name__)


def _ghidra_cfg_to_attributed(fn_cfg: Any) -> Any:
    """FunctionCFG (ghidra) -> AttributedCFG (computation.cfg_iso).

    Ghidra basic block'larinda mnemonic histogram yok; instruction_count'tan
    zayif bir approximation uretiyoruz (tek bucket "instr"). Template bank
    histogram-aware oldugu icin bu zayif olabilir; production'da
    decompile_all.py output'undaki per-bb mnemonic'leri dogrudan okumak
    gerek. Bu ticket icin best-effort yeterli.
    """
    from karadul.computation.cfg_iso import AttributedCFG, CFGNode

    blocks = getattr(fn_cfg, "blocks", []) or []
    edges_raw = getattr(fn_cfg, "edges", []) or []

    nodes: list = []
    # in/out degree degerlerini edges uzerinden hesapla.
    in_deg: dict[str, int] = {}
    out_deg: dict[str, int] = {}
    for e in edges_raw:
        src = getattr(e, "from_block", "")
        dst = getattr(e, "to_block", "")
        if src:
            out_deg[src] = out_deg.get(src, 0) + 1
        if dst:
            in_deg[dst] = in_deg.get(dst, 0) + 1

    # Giris/cikis: ilk blok giris, out_deg=0 olanlar exit.
    entry_addr = blocks[0].start_address if blocks else None
    exit_addrs = {b.start_address for b in blocks if out_deg.get(b.start_address, 0) == 0}

    for b in blocks:
        addr = getattr(b, "start_address", "")
        ic = int(getattr(b, "instruction_count", 0) or 0)
        nodes.append(
            CFGNode(
                id=addr,
                mnemonic_histogram={"instr": ic} if ic > 0 else {},
                in_degree=in_deg.get(addr, 0),
                out_degree=out_deg.get(addr, 0),
                is_entry=(addr == entry_addr),
                is_exit=(addr in exit_addrs),
            ),
        )

    edges: list[tuple[str, str]] = [
        (getattr(e, "from_block", ""), getattr(e, "to_block", ""))
        for e in edges_raw
        if getattr(e, "from_block", "") and getattr(e, "to_block", "")
    ]

    return AttributedCFG(nodes=nodes, edges=edges, api_calls=[], string_refs=[])


@register_step(
    name="cfg_iso_match",
    requires=["cfg_result"],
    produces=["cfg_iso_matches", "timing_cfg_iso_match"],
)
class CFGIsoMatchStep(Step):
    """Hibrit CFG isomorphism match -- LSH + VF2 + anchor template eslemesi."""

    def run(self, ctx: StepContext) -> dict[str, Any]:
        pc = ctx.pipeline_context
        cfg_comp_recovery = getattr(pc.config, "computation_recovery", None)

        step_start = time.monotonic()
        empty_result = {"cfg_iso_matches": {}, "timing_cfg_iso_match": 0.0}

        # Feature flag ComputationRecoveryConfig.enable_cfg_iso uzerinden
        # (cfg_iso paketi ConputationRecoveryConfig alanlarini okuyor).
        if cfg_comp_recovery is None or not getattr(
            cfg_comp_recovery, "enable_cfg_iso", False,
        ):
            empty_result["timing_cfg_iso_match"] = round(
                time.monotonic() - step_start, 3,
            )
            return empty_result

        cfg_result = ctx.artifacts.get("cfg_result")
        if cfg_result is None or not getattr(cfg_result, "functions", None):
            logger.debug(
                "cfg_iso_match: cfg_result bos, atlaniyor",
            )
            empty_result["timing_cfg_iso_match"] = round(
                time.monotonic() - step_start, 3,
            )
            return empty_result

        try:
            from karadul.computation.cfg_iso import (
                HybridCFGMatcher,
                default_template_bank,
            )

            matcher = HybridCFGMatcher(
                config=cfg_comp_recovery,
                templates=default_template_bank(),
            )
            top_k = int(getattr(
                cfg_comp_recovery, "cfg_iso_top_k_candidates", 10,
            ))
            min_conf = float(getattr(
                cfg_comp_recovery, "cfg_iso_min_confidence", 0.7,
            ))

            matches_by_fn: dict[str, Any] = {}
            fn_list = cfg_result.functions
            for fn in fn_list:
                fn_addr = getattr(fn, "address", None)
                if not fn_addr:
                    continue
                try:
                    attr_cfg = _ghidra_cfg_to_attributed(fn)
                    if attr_cfg.node_count() == 0:
                        continue
                    top = matcher.match(attr_cfg, top_k=top_k)
                    if top and top[0].confidence >= min_conf:
                        matches_by_fn[fn_addr] = top[0]
                except Exception as exc:  # pragma: no cover - defensive
                    logger.debug(
                        "cfg_iso_match fn=%s hata: %s", fn_addr, exc,
                    )

            ctx.stats["cfg_iso_matched_functions"] = len(matches_by_fn)
            ctx.stats["cfg_iso_total_functions"] = len(fn_list)
            logger.info(
                "CFG iso match: %d / %d fonksiyon template'le eslesti (>=%.2f)",
                len(matches_by_fn), len(fn_list), min_conf,
            )

            timing = round(time.monotonic() - step_start, 3)
            ctx.stats["timing_cfg_iso_match"] = timing
            return {
                "cfg_iso_matches": matches_by_fn,
                "timing_cfg_iso_match": timing,
            }
        except ImportError as exc:
            logger.debug(
                "cfg_iso_match import hatasi (networkx yok?): %s", exc,
            )
        except Exception as exc:
            logger.warning(
                "cfg_iso_match hatasi (atlaniyor): %s", exc,
            )
            ctx.errors.append(f"cfg_iso_match: {exc}")

        empty_result["timing_cfg_iso_match"] = round(
            time.monotonic() - step_start, 3,
        )
        return empty_result
