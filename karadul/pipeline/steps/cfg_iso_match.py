"""CFGIsoMatchStep -- hibrit CFG izomorfizm şablon eşlemesi (LSH + VF2 + çapa).

``ComputationRecoveryConfig.enable_cfg_iso`` açıksa her fonksiyon için Ghidra
CFG'sinden ``AttributedCFG`` kurulur ve ``HybridCFGMatcher`` ile şablon
bankasına karşı eşlenir; ``cfg_iso_min_confidence`` üstündeki en iyi eşleşme
``cfg_iso_matches`` (``{fonksiyon adresi: CFGMatch}``) yapıtına yazılır. Bu
yapıtı yalnız ``computation_fusion`` okur (K-1: ad haritasına doğrudan girmez).

TIP-01 (P11): eski kod düğüme ``{"instr": komut sayısı}`` veriyordu; şablonlar
gerçek komut adı taşıdığı için WL renkleri 0. adımda ayrışıyor, LSH hiç aday
döndüremiyordu. Artık histogram Ghidra'nın blok başına komut adı dökümünden
(``cfg.json`` → ``blocks[].mnemonics``) kurulur. Döküm yoksa (eski çıktı) adım
koşmaz ve ``desteklenmiyor`` yazar. WL rengi düğümün tam histogramını içerdiği
için bir sorgu bloğunun histogramı hiçbir şablon düğümününkine eşit değilse o
fonksiyon için LSH adayı çıkamaz; böyle fonksiyonlar eşlenmeden sayılır, hiçbir
fonksiyonda uyumlu blok yoksa adım ``desteklenmiyor`` + neden yazar ("çalıştı,
0" değil).

Durum: ``ctx.stats["kol_cfg_iso"]`` (``karadul.computation.kol_durumu``).
"""

from __future__ import annotations

import json
import logging
import time
from collections import Counter
from pathlib import Path
from typing import Any, Optional

from karadul.pipeline.context import StepContext
from karadul.pipeline.registry import Step, register_step

logger = logging.getLogger(__name__)


def _get(obj: Any, name: str, default: Any = None) -> Any:
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


def load_block_mnemonics(cfg_json_path: Any) -> Optional[dict[str, dict[str, list[str]]]]:
    """``cfg.json``'dan ``{fonksiyon adresi: {blok başı: [komut adı]}}``.

    Dosya yoksa ``None``. Komut adı dökümü olmayan bloklar haritaya girmez
    (eski Ghidra çıktısı: blokta yalnız ``instruction_count`` var).
    """
    if not cfg_json_path:
        return None
    path = Path(cfg_json_path)
    if not path.is_file():
        return None
    data = json.loads(path.read_text(encoding="utf-8"))
    out: dict[str, dict[str, list[str]]] = {}
    for fn in data.get("functions", []) or []:
        addr = str(fn.get("address", ""))
        blocks = {
            str(b.get("start_address", "")): [str(m) for m in b["mnemonics"]]
            for b in fn.get("blocks", []) or []
            if isinstance(b.get("mnemonics"), list)
        }
        if addr and blocks:
            out[addr] = blocks
    return out


def attributed_cfg(fn_cfg: Any, block_mnemonics: Optional[dict[str, list[str]]]) -> Any:
    """Ghidra fonksiyon CFG'si (nesne ya da ``cfg.json`` sözlüğü) → ``AttributedCFG``.

    Düğüm histogramı blok komut adlarının sayımıdır. ``instruction_count > 0``
    olup dökümü olmayan bir blok varsa ``None`` döner (eksik veriyle sahte
    histogram kurulmaz).
    """
    from karadul.computation.cfg_iso import AttributedCFG, CFGNode

    blocks = list(_get(fn_cfg, "blocks", []) or [])
    edges_raw = list(_get(fn_cfg, "edges", []) or [])
    mn = block_mnemonics or {}

    in_deg: Counter = Counter()
    out_deg: Counter = Counter()
    for e in edges_raw:
        src, dst = _get(e, "from_block", ""), _get(e, "to_block", "")
        if src:
            out_deg[src] += 1
        if dst:
            in_deg[dst] += 1

    entry_addr = _get(blocks[0], "start_address") if blocks else None
    nodes: list = []
    for b in blocks:
        addr = str(_get(b, "start_address", ""))
        ic = int(_get(b, "instruction_count", 0) or 0)
        mnems = mn.get(addr)
        if mnems is None:
            mnems = _get(b, "mnemonics", None)
        if mnems is None:
            if ic > 0:
                return None
            mnems = []
        nodes.append(CFGNode(
            id=addr,
            mnemonic_histogram=dict(Counter(mnems)),
            in_degree=in_deg.get(addr, 0),
            out_degree=out_deg.get(addr, 0),
            is_entry=(addr == entry_addr),
            is_exit=(out_deg.get(addr, 0) == 0),
        ))
    edges = [
        (_get(e, "from_block", ""), _get(e, "to_block", ""))
        for e in edges_raw
        if _get(e, "from_block", "") and _get(e, "to_block", "")
    ]
    return AttributedCFG(nodes=nodes, edges=edges, api_calls=[], string_refs=[])


def _hist_key(hist: dict[str, int]) -> tuple:
    return tuple(sorted(hist.items()))


def template_node_histograms(templates: list[Any]) -> set[tuple]:
    """Bankadaki bütün şablon düğümlerinin tam histogramları."""
    return {_hist_key(n.mnemonic_histogram) for t in templates for n in t.cfg.nodes}


def bank_composition(templates: list[Any]) -> dict[str, int]:
    """Şablonların kaynağa göre sayımı (``AlgorithmTemplate.source``)."""
    return dict(Counter(getattr(t, "source", "bilinmiyor") for t in templates))


@register_step(
    name="cfg_iso_match",
    requires=["cfg_result", "cfg_json_path"],
    produces=["cfg_iso_matches", "timing_cfg_iso_match"],
)
class CFGIsoMatchStep(Step):
    """Hibrit CFG isomorphism match -- LSH + VF2 + anchor template eslemesi."""

    def run(self, ctx: StepContext) -> dict[str, Any]:
        from karadul.computation.kol_durumu import (
            CALISTI, DESTEKLENMIYOR, FUZYON_GIRDISI, HATA, KAPALI, STAT_CFG_ISO,
            kol_durumu,
        )

        pc = ctx.pipeline_context
        cfg_comp_recovery = getattr(pc.config, "computation_recovery", None)

        step_start = time.monotonic()

        def _bitir(durum: str, neden: str, matches: dict, **sayac: Any) -> dict[str, Any]:
            ctx.stats[STAT_CFG_ISO] = kol_durumu(durum, neden, FUZYON_GIRDISI, **sayac)
            timing = round(time.monotonic() - step_start, 3)
            if durum == CALISTI:
                ctx.stats["timing_cfg_iso_match"] = timing
            return {"cfg_iso_matches": matches, "timing_cfg_iso_match": timing}

        if cfg_comp_recovery is None or not getattr(
            cfg_comp_recovery, "enable_cfg_iso", False,
        ):
            return _bitir(KAPALI, "bayrak kapalı (computation_recovery.enable_cfg_iso)", {})

        cfg_result = ctx.artifacts.get("cfg_result")
        if cfg_result is None or not getattr(cfg_result, "functions", None):
            return _bitir(DESTEKLENMIYOR, "CFG yok (cfg_result boş)", {})

        try:
            from karadul.computation.cfg_iso import (
                HybridCFGMatcher,
                default_template_bank,
            )

            fn_list = list(cfg_result.functions)
            mnemonics = load_block_mnemonics(ctx.artifacts.get("cfg_json_path"))
            templates = default_template_bank()
            banka = bank_composition(templates)

            queries: list[tuple[str, Any]] = []
            dokumsuz = 0
            for fn in fn_list:
                fn_addr = getattr(fn, "address", None)
                if not fn_addr:
                    continue
                attr_cfg = attributed_cfg(fn, (mnemonics or {}).get(str(fn_addr)))
                if attr_cfg is None:
                    dokumsuz += 1
                    continue
                if attr_cfg.node_count() > 0:
                    queries.append((str(fn_addr), attr_cfg))

            if not queries:
                return _bitir(
                    DESTEKLENMIYOR,
                    "blok komut adı dökümü yok (Ghidra çıktısı eski; cfg.json "
                    "blocks[].mnemonics)",
                    {}, fonksiyon=len(fn_list), dokumsuz_fonksiyon=dokumsuz,
                    banka=banka,
                )

            node_hists = template_node_histograms(templates)
            uyumlu = [
                (addr, q) for addr, q in queries
                if any(_hist_key(n.mnemonic_histogram) in node_hists for n in q.nodes)
            ]
            sayac = {
                "fonksiyon": len(fn_list),
                "dokumsuz_fonksiyon": dokumsuz,
                "sorgu": len(queries),
                "uyumlu_fonksiyon": len(uyumlu),
                "banka": banka,
            }
            if not uyumlu:
                return _bitir(
                    DESTEKLENMIYOR,
                    "hiçbir blok histogramı hiçbir şablon düğümüyle aynı değil "
                    "(WL rengi ayrışır, LSH adayı çıkamaz); banka "
                    + ", ".join(f"{k} {v}" for k, v in sorted(banka.items())),
                    {}, **sayac,
                )

            matcher = HybridCFGMatcher(config=cfg_comp_recovery, templates=templates)
            top_k = int(getattr(cfg_comp_recovery, "cfg_iso_top_k_candidates", 10))
            min_conf = float(getattr(cfg_comp_recovery, "cfg_iso_min_confidence", 0.7))

            matches_by_fn: dict[str, Any] = {}
            fn_hata = 0
            for fn_addr, attr_cfg in uyumlu:
                try:
                    top = matcher.match(attr_cfg, top_k=top_k)
                except Exception as exc:  # fonksiyon başına: sayılır, yutulmaz
                    fn_hata += 1
                    logger.debug("cfg_iso_match fn=%s hata: %s", fn_addr, exc)
                    continue
                if top and top[0].confidence >= min_conf:
                    matches_by_fn[fn_addr] = top[0]

            ctx.stats["cfg_iso_matched_functions"] = len(matches_by_fn)
            ctx.stats["cfg_iso_total_functions"] = len(fn_list)
            logger.info(
                "CFG iso match: %d / %d uyumlu fonksiyon şablonla eşleşti (>=%.2f)",
                len(matches_by_fn), len(uyumlu), min_conf,
            )
            return _bitir(
                CALISTI, "", matches_by_fn,
                eslesen=len(matches_by_fn), fonksiyon_hatasi=fn_hata, **sayac,
            )
        except ImportError as exc:
            logger.debug("cfg_iso_match import hatasi (networkx yok?): %s", exc)
            return _bitir(DESTEKLENMIYOR, f"bağımlılık yok: {exc}", {})
        except Exception as exc:
            logger.warning("cfg_iso_match hatasi (atlaniyor): %s", exc)
            ctx.errors.append(f"cfg_iso_match: {exc}")
            return _bitir(HATA, f"{type(exc).__name__}: {exc}", {})
