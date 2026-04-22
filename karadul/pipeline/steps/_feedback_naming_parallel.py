"""M2 T2 — ParallelNamingRunner entegrasyon helper'lari.

`_feedback_naming.py` dosyasinin 300 satir sinirini asmamasi icin runner
shim'i buraya bolundu.  Davranis feature flag'e bagli:

  config.perf.parallel_naming = False (default) -> bu modul devreye girmez,
  eski `c_namer.analyze_and_rename()` yolu korunur.

  config.perf.parallel_naming = True -> `ParallelNamingRunner` c_files'i
  chunk'lar halinde thread'lere dagitir, extracted_names'i zenginlestirir
  ve sonuclardan dogrudan bir `CNamingResult` sentezler.  v1.10.0 H2
  (Pipeline) oncesi burada bir de serial `analyze_and_rename` cagrisi
  vardi — CPU'yu iki kez tuketiyor ve paralelizasyonu etkisiz kiliyordu.
  Artik runner tek gercek kaynak; downstream (NameMerger + AhoReplacer)
  isim haritasini uygulayip `merged/` dizinini uretiyor, dolayisiyla
  runner'in dosya yazmamasi pipeline'in butunlugunu bozmaz.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def _should_use_parallel_runner(config: Any, c_namer: Any) -> bool:
    """parallel_naming feature flag aktif mi + namer uyumlu mu."""
    if c_namer is None:
        return False
    perf = getattr(config, "perf", None)
    if not perf or not getattr(perf, "parallel_naming", False):
        return False
    has_per_file = (
        callable(getattr(c_namer, "rename_c_file", None))
        or callable(getattr(c_namer, "extract_names_from_file", None))
    )
    if not has_per_file:
        logger.warning(
            "parallel_naming=True ama namer'da rename_c_file/"
            "extract_names_from_file yok; serial yola duslu.",
        )
        return False
    return True


def _run_with_parallel_runner(
    *,
    c_namer: Any,
    namer_dir: Path,
    namer_output: Path,
    functions_json: Path,
    strings_json: Path,
    call_graph_json: Path,
    xrefs_json: Path,
    extracted_names: dict[str, str],
    config: Any,
    stats: dict[str, Any],
    errors: list[str],
) -> Any:
    """ParallelNamingRunner ile naming calistir (v1.10.0 H2: serial cagri yok).

    Akis:
      1. Runner c_files'i chunk'lara bolup thread'lerde namer'in per-file
         metodunu cagirir; extracted_names ve naming_map'i hazirlayacagimiz
         icin sonuclari dogrudan kullaniriz.
      2. Runner'in ciktisindan minimal bir `CNamingResult` sentezlenir:
            - success: en az bir isim onerisi varsa True
            - naming_map: eski_ad -> ilk aday (confidence'i en yuksegi)
            - total_renamed: naming_map boyutu
            - output_files: BOS (runner diske yazmiyor; downstream
              NameMerger + AhoReplacer isim haritasini uygular)
      3. Runner istatistikleri `stats[f"parallel_naming_{k}"]` altina yazilir.

    Parametreler `functions_json`, `strings_json`, `call_graph_json`,
    `xrefs_json`, `namer_output` su an kullanilmiyor (runner per-file;
    analiz zincirini namer'in kendi metodu bes yildir). API kararli tutuluyor
    ki downstream `_feedback_naming._run_c_namer` imzasi degismesin.
    """
    from karadul.naming import ParallelNamingRunner
    from karadul.reconstruction.c_namer import CNamingResult

    # namer_output unused — keep parameter for API stability; compiler-lint
    # uyarisini devre disi birak.
    del namer_output, functions_json, strings_json, call_graph_json, xrefs_json

    c_files = sorted(namer_dir.glob("*.c")) if namer_dir.exists() else []
    runner = ParallelNamingRunner(config)
    runner_result = runner.run(c_files=c_files, namer=c_namer)

    for k, v in runner_result.stats.items():
        stats[f"parallel_naming_{k}"] = v
    if runner_result.errors:
        errors.extend(runner_result.errors)

    # Runner'dan toplanan isim adaylari extracted_names ve naming_map'e
    # aktarilir. dict[str, list] -> dict[str, str]: confidence'i yuksek olani
    # secmek icin adaylari (varsa) confidence'a gore sirala.
    naming_map: dict[str, str] = {}
    by_strategy: dict[str, int] = {}
    high_confidence = 0
    medium_confidence = 0
    low_confidence = 0

    for old_name, cands in runner_result.extracted_names.items():
        if not cands:
            continue

        def _cand_key(c: Any) -> float:
            # _NamingCandidate veya str olabilir; confidence'a erisemezsek 0.
            return float(getattr(c, "confidence", 0.0) or 0.0)

        sorted_cands = sorted(cands, key=_cand_key, reverse=True)
        best = sorted_cands[0]
        new_name = (
            best.new_name if hasattr(best, "new_name") else str(best)
        )
        if not new_name:
            continue

        if old_name not in extracted_names:
            extracted_names[old_name] = new_name
        naming_map[old_name] = new_name

        strategy = getattr(best, "strategy", "parallel_runner")
        by_strategy[strategy] = by_strategy.get(strategy, 0) + 1
        conf = _cand_key(best)
        if conf >= 0.7:
            high_confidence += 1
        elif conf >= 0.4:
            medium_confidence += 1
        else:
            low_confidence += 1

    return CNamingResult(
        success=bool(naming_map),
        output_files=[],  # runner diske yazmiyor; downstream merger handle eder
        naming_map=naming_map,
        total_renamed=len(naming_map),
        by_strategy=by_strategy,
        high_confidence=high_confidence,
        medium_confidence=medium_confidence,
        low_confidence=low_confidence,
        errors=list(runner_result.errors),
    )


__all__ = ["_should_use_parallel_runner", "_run_with_parallel_runner"]
