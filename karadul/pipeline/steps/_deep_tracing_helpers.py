"""DeepTracingStep icin yardimci fonksiyonlar.

stages.py L3762-3931 'deki 4 alt-adimi (dispatch, data flow, param propagate,
composition, trace) daha yonetilebilir parcalara boldu. Davranis birebir
korunuyor.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def resolve_dispatch(
    decompiled_dir: Path,
    functions_json: Path,
    call_graph_json: Path,
    strings_json: Path,
    call_graph_data: Any,
    reconstructed_dir: Path,
    stats: dict,
    errors: list,
    workspace,
) -> tuple[Any, Path | None]:
    """Virtual dispatch resolution (ObjC/Swift/C++). stages.py L3769-3814.

    Returns:
        (dispatch_result, augmented_cg_json_path or None)
    """
    dispatch_result = None
    augmented_cg_json: Path | None = None

    try:
        from karadul.reconstruction.engineering import VirtualDispatchResolver
        dispatch_resolver = VirtualDispatchResolver()
        dispatch_result = dispatch_resolver.resolve(
            decompiled_dir=decompiled_dir,
            functions_json=functions_json,
            call_graph_json=call_graph_json,
            strings_json=strings_json,
        )
        if dispatch_result and dispatch_result.success:
            stats["dispatch_sites"] = dispatch_result.total_dispatch_sites
            stats["dispatch_resolved"] = dispatch_result.resolved_count
            stats["dispatch_resolution_rate"] = (
                f"{dispatch_result.resolution_rate:.1%}"
            )
            workspace.save_json(
                "reconstructed", "dispatch_resolution",
                dispatch_result.to_dict(),
            )
            logger.info(
                "Dispatch Resolution: %d/%d resolved (%.1f%%)",
                dispatch_result.resolved_count,
                dispatch_result.total_dispatch_sites,
                dispatch_result.resolution_rate * 100,
            )
            if dispatch_result.augmented_edges:
                # v1.10.0 H4 (perf fix): copy.deepcopy(call_graph_data)
                # buyuk CG'de 200MB+ allocate ediyordu. Kullanim pattern'i
                # sadece top-level "edges" listesini genisletmek; bu yuzden
                # 1-seviye derin kopya yeterli. Tipik CG: 50K fn -> deepcopy
                # ~3-5s vs comprehension ~50ms.
                if call_graph_data:
                    original_cg = {
                        k: (list(v) if isinstance(v, list) else v)
                        for k, v in call_graph_data.items()
                    }
                else:
                    original_cg = {}
                if "edges" not in original_cg:
                    original_cg["edges"] = []
                for edge in dispatch_result.augmented_edges:
                    original_cg["edges"].append(edge)
                augmented_cg_path = reconstructed_dir / "augmented_call_graph.json"
                augmented_cg_path.write_text(
                    json.dumps(original_cg, indent=2), encoding="utf-8",
                )
                augmented_cg_json = augmented_cg_path
                logger.info(
                    "Augmented CG: %d yeni edge eklendi",
                    len(dispatch_result.augmented_edges),
                )
    except ImportError:
        logger.debug("VirtualDispatchResolver bulunamadi, atlaniyor")
    except Exception as exc:
        logger.warning("Dispatch resolution hatasi (atlaniyor): %s", exc)
        errors.append(f"Dispatch resolution hatasi: {exc}")

    return dispatch_result, augmented_cg_json


def analyze_data_flow(
    decompiled_dir: Path,
    functions_json: Path,
    call_graph_json: Path,
    augmented_cg_json: Path | None,
    xrefs_json: Path,
    reconstructed_dir: Path,
    stats: dict,
    errors: list,
) -> Any:
    """Inter-procedural data flow. stages.py L3817-3840."""
    data_flow_result = None
    try:
        from karadul.reconstruction.engineering import InterProceduralDataFlow
        data_flow_analyzer = InterProceduralDataFlow()
        data_flow_dir = reconstructed_dir / "data_flow"
        data_flow_dir.mkdir(parents=True, exist_ok=True)
        data_flow_result = data_flow_analyzer.analyze(
            decompiled_dir=decompiled_dir,
            functions_json=functions_json,
            call_graph_json=augmented_cg_json or call_graph_json,
            xrefs_json=xrefs_json if xrefs_json.exists() else None,
            output_dir=data_flow_dir,
        )
        if data_flow_result and data_flow_result.success:
            stats["data_flow_edges"] = data_flow_result.total_edges
            stats["data_flow_pipelines"] = len(data_flow_result.pipelines)
            logger.info(
                "Data Flow: %d edges, %d pipelines",
                data_flow_result.total_edges,
                len(data_flow_result.pipelines),
            )
    except ImportError:
        logger.debug("InterProceduralDataFlow bulunamadi, atlaniyor")
    except Exception as exc:
        logger.warning("Data flow analysis hatasi (atlaniyor): %s", exc)
        errors.append(f"Data flow hatasi: {exc}")
    return data_flow_result


def propagate_param_names(
    decompiled_dir: Path,
    functions_json: Path,
    call_graph_json: Path,
    augmented_cg_json: Path | None,
    sig_matches: Any,
    stats: dict,
    errors: list,
) -> None:
    """Inter-procedural parameter name propagation. stages.py L3843-3862."""
    try:
        from karadul.reconstruction.engineering import InterProceduralDataFlow
        param_prop_analyzer = InterProceduralDataFlow()
        param_prop_result = param_prop_analyzer.propagate_param_names(
            decompiled_dir=decompiled_dir,
            functions_json=functions_json,
            call_graph_json=augmented_cg_json or call_graph_json,
            signature_matches=sig_matches if sig_matches else None,
        )
        if param_prop_result:
            stats["param_names_propagated"] = len(param_prop_result)
            logger.info(
                "Param name propagation: %d isim yayildi",
                len(param_prop_result),
            )
    except ImportError:
        logger.debug(
            "InterProceduralDataFlow (param propagation) bulunamadi, atlaniyor",
        )
    except Exception as exc:
        logger.warning("Param name propagation hatasi (atlaniyor): %s", exc)
        errors.append(f"Param name propagation hatasi: {exc}")


def resolve_call_graph(
    augmented_cg_json: Path | None,
    call_graph_data: Any,
) -> Any:
    """Augmented varsa dosyadan yukle ve cache'e merge et, yoksa cache'i dondur.

    v1.10.0 C4: Onceki yapinin dolaylı bugu duzeltildi. Orijinal stages.py
    (L3867-3871) `augmented_cgjson` typo'su yuzunden NameError'a dusuyor
    ve augmented dosya hic okunmuyordu. Biz de bu dosyada "dogrudur ama
    kullanmiyoruz" diyen bir docstring birakmistik; simdi gercekten
    kullaniyoruz:

    - augmented_cg_json None degil ve dosya varsa: JSON'u oku.
        * call_graph_data None/bos ise direkt augmented'i dondur.
        * Aksi halde edges listesini cache ustune merge et (mevcut edge'ler
          kaybolmasin diye). Dictionary shallow merge + edges list concat.
    - Disk hatasi / JSON parse hatasi durumunda cache'e geri dus (non-fatal);
      hatayi cagiran try/except'e tasimayi gerektirmez.
    """
    if call_graph_data is None:
        call_graph_data = {}

    if augmented_cg_json is None or not augmented_cg_json.exists():
        return call_graph_data

    try:
        augmented = json.loads(
            augmented_cg_json.read_text(encoding="utf-8"),
        )
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning(
            "Augmented call graph okunamadi (%s), cache kullaniliyor: %s",
            augmented_cg_json, exc,
        )
        return call_graph_data

    if not isinstance(augmented, dict):
        # Beklenmeyen yapi — cache'e gerile
        return call_graph_data

    # Cache bosuna yakinsa augmented'i dogrudan dondur
    if not call_graph_data:
        return augmented

    # Cache zengin — edges merge (dict.update augmented'i tercih eder)
    merged: dict[str, Any] = dict(call_graph_data)
    aug_edges = augmented.get("edges")
    cache_edges = merged.get("edges")
    if isinstance(cache_edges, list) and isinstance(aug_edges, list):
        seen = {json.dumps(e, sort_keys=True) for e in cache_edges if e}
        for e in aug_edges:
            key = json.dumps(e, sort_keys=True) if e else None
            if key and key not in seen:
                cache_edges.append(e)
                seen.add(key)
    elif isinstance(aug_edges, list):
        merged["edges"] = list(aug_edges)
    # Diger top-level key'ler (nodes, metadata vs) augmented'tan eklensin
    for k, v in augmented.items():
        if k == "edges":
            continue
        if k not in merged:
            merged[k] = v
    return merged


def analyze_composition(
    call_graph_data: Any,
    all_algos: list,
    data_flow_result: Any,
    dispatch_result: Any,
    reconstructed_dir: Path,
    stats: dict,
    errors: list,
    workspace,
    publish_artifact,
) -> None:
    """Algorithm Composition Analysis. stages.py L3874-3901."""
    logger.info(
        "Step 7.3: Algorithm Composition Analysis basliyor (%d node, %d edge)",
        len(call_graph_data) if call_graph_data else 0,
        sum(
            len(v) if isinstance(v, list) else 0
            for v in (call_graph_data or {}).values()
        ),
    )
    try:
        from karadul.reconstruction.engineering import (
            AlgorithmCompositionAnalyzer,
        )
        comp_analyzer = AlgorithmCompositionAnalyzer()
        comp_result = comp_analyzer.analyze(
            call_graph=call_graph_data,
            algorithms=all_algos,
            data_flow=data_flow_result,
            dispatch_result=dispatch_result,
        )
        if comp_result and comp_result.success:
            stats["compositions"] = comp_result.total_compositions
            workspace.save_json(
                "reconstructed", "algorithm_compositions",
                comp_result.to_dict(),
            )
            comp_md = comp_analyzer.generate_report(comp_result)
            comp_md_path = reconstructed_dir / "compositions.md"
            comp_md_path.write_text(comp_md, encoding="utf-8")
            publish_artifact("compositions", comp_md_path)
            logger.info(
                "Compositions: %d found", comp_result.total_compositions,
            )
    except ImportError:
        logger.debug("AlgorithmCompositionAnalyzer bulunamadi, atlaniyor")
    except Exception as exc:
        logger.warning("Composition analysis hatasi (atlaniyor): %s", exc)
        errors.append(f"Composition analysis hatasi: {exc}")


def deep_trace(
    call_graph_data: Any,
    all_algos: list,
    dispatch_result: Any,
    reconstructed_dir: Path,
    stats: dict,
    errors: list,
    publish_artifact,
) -> None:
    """Deep Call Chain Tracing. stages.py L3904-3931."""
    logger.info(
        "Step 7.4: Deep Call Chain Tracing basliyor (max_depth=8, max_targets=3)",
    )
    try:
        from karadul.reconstruction.engineering import DeepCallChainTracer
        # v1.2.3: max_depth 10->8, max_targets 5->3 (performance)
        tracer = DeepCallChainTracer(max_depth=8, max_targets=3)
        trace_results = tracer.trace_auto(
            call_graph=call_graph_data if call_graph_data else {},
            algorithms=all_algos if all_algos else None,
            dispatch_result=dispatch_result,
            top_n=3,
        )
        if trace_results:
            stats["trace_targets"] = len(trace_results)
            stats["trace_total_nodes"] = sum(
                t.total_nodes for t in trace_results
            )
            trace_md = tracer.generate_report(trace_results)
            trace_md_path = reconstructed_dir / "call_traces.md"
            trace_md_path.write_text(trace_md, encoding="utf-8")
            publish_artifact("call_traces", trace_md_path)
            logger.info(
                "Deep Trace: %d targets, %d total nodes",
                len(trace_results),
                sum(t.total_nodes for t in trace_results),
            )
    except ImportError:
        logger.debug("DeepCallChainTracer bulunamadi, atlaniyor")
    except Exception as exc:
        logger.warning("Deep trace hatasi (atlaniyor): %s", exc)
        errors.append(f"Deep trace hatasi: {exc}")
