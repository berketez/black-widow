"""P-S3b kalem 3: ``full_write`` çağrı şeklinde ``_exit`` dışlaması.

gnulib ``full-write.c`` / ``safe-write.c`` ``_exit`` çağırmaz. Geliştirme setinde (coreutils
``sort``) ``strlen`` + ``write`` + ``_exit`` yapan bir hata yolu ikilide tek aday olup
``full_write`` adını alıyordu (GT'ye göre yanlış; P-S3'ün kalan tek yanlışı).
"""

from __future__ import annotations

import json
from pathlib import Path

from karadul.analyzers.gnulib_fingerprints import GNULIB_CALL_SHAPES, match_call_shape
from karadul.stages import ReconstructionStage

GNULIB_LIB = Path(__file__).resolve().parents[1] / "vendor" / "gnulib-ref" / "lib"
GETOPT_GHIDRA = "%s: option \\'%s%s\\' doesn\\'t allow an argument\\n"
VERSION_ETC_GHIDRA = "General help using GNU software: <%s>\\n"


def _node(addr: str, callees: list[str], callers: list[str] = ()) -> dict:
    return {"name": f"FUN_{addr}", "address": addr, "callee_count": len(callees),
            "callees": [{"name": c} for c in callees],
            "callers": [{"name": f"FUN_{c}", "address": c} for c in callers]}


def _static(tmp_path: Path, nodes: dict) -> Path:
    static_dir = tmp_path / "static"
    dec = static_dir / "decompiled"
    dec.mkdir(parents=True)
    (dec / "FUN_00100000.c").write_text("void FUN_00100000(void){return;}\n", encoding="utf-8")
    (dec / "emit_bug_reporting_address.c").write_text(
        f'void f(void){{printf("{VERSION_ETC_GHIDRA}");}}\n', encoding="utf-8")
    (dec / "process_long_option.c").write_text(
        f'void g(void){{fprintf(stderr,"{GETOPT_GHIDRA}");}}\n', encoding="utf-8")
    (static_dir / "call_graph.json").write_text(json.dumps({"nodes": nodes}), encoding="utf-8")
    return static_dir


def _genis(addr: str, hedef: str) -> dict:
    return _node(addr, [f"x{i}" for i in range(20)] + [f"FUN_{hedef}"])


def test_exit_cagiran_write_sarmalayici_full_write_olmaz(tmp_path):
    """sort düzeni: strlen + write + _exit + iç fonksiyon, geniş çağıranlar -> ad yok."""
    nodes = {"001079e0": _node("001079e0", ["strlen", "write", "_exit", "FUN_0010e300"],
                               ["00108a20", "00108cd0"]),
             "00108a20": _genis("00108a20", "001079e0"),
             "00108cd0": _genis("00108cd0", "001079e0")}
    names: dict[str, str] = {}
    ReconstructionStage()._recover_gnulib_from_fingerprints(names, _static(tmp_path, nodes), {})
    assert "FUN_001079e0" not in names


def test_exit_cagirmayan_write_sarmalayici_full_write_olur(tmp_path):
    """LTO'lu Ubuntu 9.4 düzeni (GT'ye göre doğru): write + errno, geniş çağıran -> full_write."""
    nodes = {"00102000": _node("00102000", ["write", "__errno_location"], ["00109000"]),
             "00109000": _genis("00109000", "00102000")}
    names: dict[str, str] = {}
    ReconstructionStage()._recover_gnulib_from_fingerprints(names, _static(tmp_path, nodes), {})
    assert names.get("FUN_00102000") == "full_write"


def test_match_call_shape_dislama():
    assert match_call_shape({"write", "__errno_location"}, 2) == "full_write"
    assert match_call_shape({"write", "_exit"}, 2) is None
    # dışlama yalnız full_write'ın: _exit çağıran close_stream şekli etkilenmez
    assert match_call_shape({"__fpending", "_exit"}, 2) == "close_stream"


def test_dislanan_cagri_upstream_kaynakta_yok():
    """Dışlanan her çağrı ilgili gnulib kaynağında (ve full_write'ın safe_write'ında) geçmez."""
    for cs in GNULIB_CALL_SHAPES:
        kaynaklar = [cs.source] + (["safe-write.c", "safe-read.c"] if cs.name == "full_write" else [])
        for src in kaynaklar:
            metin = (GNULIB_LIB / src).read_text(encoding="utf-8", errors="replace")
            for x in cs.excluded_callees:
                assert x not in metin, (cs.name, src, x)
    assert {cs.name for cs in GNULIB_CALL_SHAPES if cs.excluded_callees} == {"full_write"}
