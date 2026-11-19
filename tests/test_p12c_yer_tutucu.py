"""P12c kalem 6 (P13a kalanı b): Ghidra yer tutucu adları ad sayılmaz.

FunctionID / ANALYSIS kaynağı ``caseD_0`` / ``caseD_1`` (switch etiketi) adlarını fonksiyon adı
diye bildiriyordu; birleştirici bunları ``function_id`` adayı olarak kabul edip köken kaydına
"uygulanan ad" yazıyordu (14 ikilide zstd 6, pzstd 6; iki yinelemede 24 karar). Kural
``name_validity`` içindedir (ikili kapsamlı ad; yerel adda sorulmaz).
"""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from karadul.config import Config
from karadul.core.naming_labels import NAMING_PROVENANCE_FILE
from karadul.pipeline.steps import _feedback_naming_merger as FM
from karadul.reconstruction import name_validity as nv


def test_yer_tutucu_ad_sayilmaz():
    for ad in ("caseD_0", "caseD_1f", "switchD_00184688", "switchdataD_00101234",
               "LAB_00101abc"):
        assert nv.reject_reason(ad) == nv.REASON_GHIDRA_PLACEHOLDER, ad
        assert nv.reject_reason(ad, local=True) is None, ad  # yerel adda sorulmaz


def test_benzer_gercek_adlar_serbest():
    for ad in ("caseDefault", "case_d_0", "switch_data", "LABEL_init", "caseD_", "caseD_0x",
               "parse_caseD_0"):
        assert nv.reject_reason(ad) is None, ad


def test_neden_sirasi():
    assert nv.REJECT_REASONS.index(nv.REASON_GHIDRA_PLACEHOLDER) == \
        nv.REJECT_REASONS.index(nv.REASON_COLLISION) - 1
    # var olan fonksiyon adı da olsa yer tutucu nedeni önce gelir
    var = nv.existing_function_names([("caseD_0", False)])
    assert nv.reject_reason("caseD_0", existing_functions=var) == nv.REASON_GHIDRA_PLACEHOLDER


def _ctx() -> SimpleNamespace:
    cfg = Config()
    cfg.binary_reconstruction.apply_global_naming_threshold = True
    return SimpleNamespace(pipeline_context=SimpleNamespace(config=cfg, metadata={}), artifacts={})


def test_birlestirici_fid_yer_tutucusunu_uygulamaz(tmp_path: Path) -> None:
    """Gerçek biçim: zstd ``function_id.json`` → ``caseD_0`` FUN_001cb840'a, 0,95 güvenle."""
    dec = tmp_path / "src"
    dec.mkdir()
    (dec / "a.c").write_text("void FUN_001cb840(void){ FUN_001cd0e0(); }\n", encoding="utf-8")
    (dec / NAMING_PROVENANCE_FILE).write_text(json.dumps({"schema": "x", "global": {}}))
    fid = tmp_path / "fid.json"
    fid.write_text(json.dumps({"total_matches": 2, "matches": [
        {"name": "caseD_0", "address": "001cb840"},
        {"name": "inflate_fast", "address": "001cd0e0"},
    ]}))
    fn = tmp_path / "ghidra_functions.json"
    fn.write_text(json.dumps({"functions": [
        {"name": "FUN_001cb840", "address": "001cb840"},
        {"name": "FUN_001cd0e0", "address": "001cd0e0"},
    ]}))
    rec = tmp_path / "rec"
    rec.mkdir()
    stats: dict = {}
    errors: list[str] = []
    harita, _adli, _dizin = FM.run_name_merger(
        ctx=_ctx(), iter_index=0, decompiled_dir=dec, reconstructed_dir=rec,
        incremental_files=None, extracted_names={}, naming_result=None,
        bindiff_confidence_map={}, refdiff_naming={}, fid_json=fid, computation_result=None,
        pcode_naming_candidates=[], stats=stats, errors=errors, artifacts={},
        functions_json=fn)
    assert errors == []
    assert harita == {"FUN_001cd0e0": "inflate_fast"}
    assert stats["name_merger_rejected"] == {nv.REASON_GHIDRA_PLACEHOLDER: 1}
    karar = json.loads((dec / NAMING_PROVENANCE_FILE).read_text())["name_merger"]["decisions"]
    assert karar["FUN_001cb840"]["applied_name"] is None
    assert karar["FUN_001cb840"]["dropped"] == nv.REASON_GHIDRA_PLACEHOLDER
