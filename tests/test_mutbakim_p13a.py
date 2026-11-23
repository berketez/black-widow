"""MUTBAKIM (2026-11-20): P13a / AD-04 kilidi, ölçülmüş kanaldaki ön adla.

``tests/test_p13a_birlestirici.py::test_ad04_bindiff_adi_on_ad_olarak_ikinci_kez_sayilmaz``
künyesiz ön ad kullanıyor. ``07d81e8`` (P12c kalem 5) sonrası künyesiz ön ad birleştiriciye
hiç girmiyor (ölçülmemiş kanal → aday değil), bu yüzden o test AD-04 kapısını artık sınamıyor:
``mutation_specs_p13a.json`` ``p13a_ad04_on_ad_iki_kez`` mutantı (``if not
pre_names_via_c_namer`` → hep doğru) hayatta kaldı. Aynı senaryo burada ölçülmüş kanaldaki
(gnulib künyeli) ön adla kurulur: c_namer koştuysa ön ad ``binary_extractor`` adayı olarak
ikinci kez girmez, BinDiff'in aynı adı tek kaynak sayılır.
"""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from karadul.config import Config
from karadul.pipeline.steps import _feedback_naming_merger as FM


def _ctx(pre_name_meta: dict) -> SimpleNamespace:
    cfg = Config()
    cfg.binary_reconstruction.apply_global_naming_threshold = True
    return SimpleNamespace(pipeline_context=SimpleNamespace(config=cfg, metadata={}),
                           artifacts={"pre_name_meta": pre_name_meta})


def _functions(tmp_path: Path) -> Path:
    p = tmp_path / "ghidra_functions.json"
    p.write_text(json.dumps({"functions": [
        {"name": "FUN_00104000", "address": "00104000"},
    ]}))
    return p


def _kos(tmp_path: Path, *, extracted: dict, meta: dict, bindiff: dict):
    dec = tmp_path / "src"
    dec.mkdir(parents=True)
    (dec / "a.c").write_text("void FUN_00104000(void){}\n", encoding="utf-8")
    stats: dict = {}
    errors: list[str] = []
    harita, _, _ = FM.run_name_merger(
        ctx=_ctx(meta), iter_index=0, decompiled_dir=dec, reconstructed_dir=tmp_path,
        incremental_files=None, extracted_names=dict(extracted),
        # c_namer koştu, bu anahtara ad vermedi (BinDiff adı ön ad sözlüğüne SONRA yazdı)
        naming_result=SimpleNamespace(success=True, naming_map={}, confidence_map={},
                                      strategy_map={}),
        bindiff_confidence_map=dict(bindiff), refdiff_naming={},
        fid_json=tmp_path / "fid.json", computation_result=None, pcode_naming_candidates=[],
        stats=stats, errors=errors, artifacts={}, functions_json=_functions(tmp_path))
    assert errors == []
    return harita or {}, stats


def test_ad04_olculmus_on_ad_bindiff_ile_iki_kaynak_sayilmaz(tmp_path) -> None:
    extracted = {"FUN_00104000": "ref_ad"}
    meta = {"FUN_00104000": {"kind": "gnulib", "name": "ref_ad"}}  # ölçülmüş kanal
    harita, stats = _kos(tmp_path, extracted=extracted, meta=meta,
                         bindiff={"FUN_00104000": ("ref_ad", 0.8, "string_refs")})
    assert stats["name_merger_c_namer_decided"] == 0
    assert stats["name_merger_exact_multi"] == 0       # ön ad ikinci kaynak olarak girmedi
    assert stats["name_merger_total"] == 1
    assert harita == {"FUN_00104000": "ref_ad"}
