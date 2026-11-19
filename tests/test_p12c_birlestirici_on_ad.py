"""P12c kalem 5 (P13a kalanı a): c_namer koşmadığında ön adlar birleştiriciye sabit 0,85 ile
girmez; güven kanalın ölçülmüş kesinliğinin Wilson alt sınırıdır, ölçülmemişse aday olmaz.

Bu test ``yamalar/P12c___feedback_naming_candidates.py.patch`` ve
``yamalar/P12c___feedback_naming_merger.py.patch`` ile birlikte uygulanır.
"""
from __future__ import annotations

from karadul.core.naming_labels import MEASURED_PRE_NAME_PRECISION
from karadul.pipeline.steps._feedback_naming_candidates import collect_candidates


def _topla(extracted, meta):
    stats: dict = {}
    c = collect_candidates(
        extracted_names=extracted, naming_result=None, bindiff_confidence_map={},
        refdiff_naming={}, fid_json=None, computation_result=None,
        pcode_naming_candidates=[], iter_index=0, stats=stats, pre_name_meta=meta,
    )
    return {k: [(x.name, x.confidence, x.source) for x in v] for k, v in c.items()}, stats


def test_olculmus_kanal_guveni_sabit_degil():
    meta = {"FUN_00101000": {"kind": "gnulib", "name": "xmalloc"}}
    c, stats = _topla({"FUN_00101000": "xmalloc"}, meta)
    assert c == {"FUN_00101000": [
        ("xmalloc", MEASURED_PRE_NAME_PRECISION["on_ad:gnulib"][2], "binary_extractor")]}
    assert "name_merger_pre_name_unmeasured" not in stats


def test_olculmemis_on_ad_aday_olmaz_ve_sayilir():
    # künyesiz ön ad ve künyesi başka adı anlatan ön ad (ad sonradan ezilmiş): ölçülmemiş
    meta = {"FUN_00102000": {"kind": "gnulib", "name": "baska_ad"}}
    c, stats = _topla({"FUN_00101000": "read_config", "FUN_00102000": "xstrdup"}, meta)
    assert c == {}
    assert stats["name_merger_pre_name_unmeasured"] == 2
