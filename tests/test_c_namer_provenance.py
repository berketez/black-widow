"""c_namer isim kökeni kaydı (naming_provenance.json) testleri — plan v2.2 N0 (b).

Kayıt her yeniden adlandırmanın stratejisini, güvenini, gerekçesini, kazananın
ardındaki en çok 3 adayı ve `string_context` için tam kanıt dizgisini, kod
yolunu (aggressive / classic), kuralı ve kanıtın kaynağını (string tablosu /
gövde literali) taşır. Eşik altında elenen adaylar yalnız sayı olarak yazılır.

Sözleşme: kayıt YALNIZ okur. naming_map.json, isimlendirilmiş .c dosyaları ve
CNamingResult kayıt açıkken ve kapalıyken bayt bayt aynıdır.

Bayt bayt karşılaştırmalar `serial_pool` ile yapılır: c_namer sezgisel
sonuçları `as_completed` sırasıyla birleştirir; gerçek süreç havuzunda bu sıra
koşudan koşuya değişebilir (eşit güvenli adaylar ve çakışma son ekleri buna
bağlı). Sabit sıra, bu var olan belirsizliği kaydın etkisinden ayırır. Gerçek
havuz ayrıca `test_real_process_pool_carries_evidence` ile sınanır.
"""
from __future__ import annotations

import concurrent.futures as cf
import dataclasses
import json
import logging
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from karadul.config import Config
from karadul.reconstruction import c_namer
from karadul.reconstruction.c_namer import (
    NAMING_PROVENANCE_FILE,
    NAMING_PROVENANCE_MAX_RUNNERS_UP,
    NAMING_PROVENANCE_SCHEMA,
    NAMING_PROVENANCE_SCHEMA_VERSION,
    STRING_CONTEXT_CODE_PATHS,
    STRING_CONTEXT_EVIDENCE_ORIGINS,
    STRING_CONTEXT_RULES,
    CVariableNamer,
    _extract_name_from_string_aggressive,
    _match_string_aggressive,
    _NamingCandidate,
    _ProvenanceRecorder,
    _sanitize_c_name,
)

# ---------------------------------------------------------------------------
# Sentetik Ghidra çıktısı
# ---------------------------------------------------------------------------

# 76 karakter; agresif kural yok -> klasik yol; string tablosundan (ref)
LONG_REF = "compression dictionary window management for streaming decoder state machine"
# FUN_00002000: kaybeden referans (skor 3) + kazanan gövde literali (skor 28)
LOSING_REF = "zip"
INLINE_WIN = "parser recovery buffer overflow detected"
# 73 karakter; agresif class_method (0.85 >= 0.75 -> klasik atlanır)
AGGR_LONG = "CStreamDecoder::ResetDictionaryWindowAfterCorruptedFrameHeader: bad magic"
# agresif error_verb (0.55) + klasik (0.9): iki string_context adayı
ERR_STR = "Unable to rebuild compression dictionary index"
PRE_NAMED_STR = "checksum ledger reconciliation pass"
# aynı ada çıkan iki fonksiyon -> çakışma son eki
DUP_A = "telemetry sampler queue drained"
DUP_B = "telemetry sampler queue stalled"

_FUNCS = [
    ("FUN_00001000", "00001000", [("param_1", "char *")], "int"),
    ("FUN_00002000", "00002000", [], "void"),
    ("FUN_00003000", "00003000", [], "void"),
    ("FUN_00004000", "00004000",
     [("param_1", "int"), ("param_2", "char *"), ("param_3", "long")], "int"),
    ("FUN_00005000", "00005000", [], "void"),
    ("FUN_00006000", "00006000", [], "void"),
    ("FUN_00007000", "00007000", [], "void"),
    ("FUN_00009000", "00009000", [], "void"),
    ("_main", "0000a000", [], "int"),
]

_STRING_REFS = [
    ("00010000", LONG_REF, "00001000"),
    ("00010100", LOSING_REF, "00002000"),
    ("00010200", AGGR_LONG, "00003000"),
    ("00010300", ERR_STR, "00004000"),
    ("00010400", PRE_NAMED_STR, "00005000"),
    ("00010500", DUP_A, "00006000"),
    ("00010600", DUP_B, "00007000"),
]

_BODIES = {
    "FUN_00001000": (
        "int FUN_00001000(char *param_1)\n{\n"
        "  int local_8;\n"
        "  local_8 = strlen(param_1);\n"
        "  FUN_00009000();\n"
        "  return local_8;\n}\n"
    ),
    "FUN_00002000": (
        "void FUN_00002000(void)\n{\n"
        f'  puts("{INLINE_WIN}");\n'
        "  FUN_00009000();\n"
        "  return;\n}\n"
    ),
    "FUN_00003000": (
        "void FUN_00003000(void)\n{\n"
        "  FUN_00009000();\n"
        "  return;\n}\n"
    ),
    "FUN_00004000": (
        "int FUN_00004000(int param_1, char *param_2, long param_3)\n{\n"
        "  long lVar1;\n"
        "  lVar1 = send(param_1, param_2, param_3, 0);\n"
        "  return (int)lVar1;\n}\n"
    ),
    "FUN_00005000": "void FUN_00005000(void)\n{\n  return;\n}\n",
    "FUN_00006000": "void FUN_00006000(void)\n{\n  return;\n}\n",
    "FUN_00007000": "void FUN_00007000(void)\n{\n  return;\n}\n",
    "FUN_00009000": "void FUN_00009000(void)\n{\n  return;\n}\n",
    "_main": (
        "int _main(void)\n{\n"
        + "".join(f"  {n}();\n" for n, *_ in _FUNCS if n != "_main")
        + "  return 0;\n}\n"
    ),
}

_EDGES = (
    [("0000a000", addr) for _n, addr, *_ in _FUNCS if addr != "0000a000"]
    + [(src, "00009000") for src in ("00001000", "00002000", "00003000")]
)


def _build_workspace(root: Path) -> dict[str, Path]:
    static = root / "static"
    decompiled = static / "decompiled"
    decompiled.mkdir(parents=True)
    functions = {"functions": [
        {
            "name": name, "address": addr, "size": 64,
            "parameters": [
                {"name": p, "type": t, "ordinal": i} for i, (p, t) in enumerate(params)
            ],
            "return_type": ret, "calling_convention": "cdecl",
        }
        for name, addr, params, ret in _FUNCS
    ]}
    strings = {"strings": [
        {"address": a, "value": v, "length": len(v), "type": "string", "function": f}
        for a, v, f in _STRING_REFS
    ]}
    names = {addr: name for name, addr, *_ in _FUNCS}
    call_graph = {
        "nodes": {addr: {"name": name, "address": addr} for addr, name in names.items()},
        "edges": [
            {"from": s, "to": d, "from_name": names[s], "to_name": names[d]}
            for s, d in _EDGES
        ],
    }
    paths = {
        "functions": static / "ghidra_functions.json",
        "strings": static / "ghidra_strings.json",
        "call_graph": static / "ghidra_call_graph.json",
        "decompiled": decompiled,
    }
    paths["functions"].write_text(json.dumps(functions), encoding="utf-8")
    paths["strings"].write_text(json.dumps(strings), encoding="utf-8")
    paths["call_graph"].write_text(json.dumps(call_graph), encoding="utf-8")
    for name, addr, *_ in _FUNCS:
        (decompiled / f"{name}.c").write_text(
            f"// Function: {name}\n// Address: {addr}\n\n{_BODIES[name]}",
            encoding="utf-8",
        )
    return paths


@pytest.fixture
def ws(tmp_path: Path) -> dict[str, Path]:
    return _build_workspace(tmp_path / "ws")


class _SerialExecutor:
    """ProcessPoolExecutor yerine: aynı süreçte, gönderim sırasıyla çalıştırır."""

    def __init__(self, max_workers=None, initializer=None, initargs=()):
        if initializer is not None:
            initializer(*initargs)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def submit(self, fn, *args, **kwargs):
        fut: cf.Future = cf.Future()
        try:
            fut.set_result(fn(*args, **kwargs))
        except BaseException as exc:  # noqa: BLE001 - Future'a aynen taşınır
            fut.set_exception(exc)
        return fut


@pytest.fixture
def serial_pool(monkeypatch):
    monkeypatch.setattr(c_namer, "ProcessPoolExecutor", _SerialExecutor)
    monkeypatch.setattr(c_namer, "as_completed", lambda fs, timeout=None: list(fs))
    monkeypatch.setattr(c_namer, "_worker_namer", None)


def _run(
    ws: dict[str, Path], out: Path, *, min_confidence: float = 0.15,
    record_provenance: bool = True, pre_names: dict[str, str] | None = None,
) -> tuple[CVariableNamer, Any]:
    namer = CVariableNamer(
        Config(), min_confidence=min_confidence, record_provenance=record_provenance,
    )
    result = namer.analyze_and_rename(
        ws["decompiled"], ws["functions"], ws["strings"], ws["call_graph"], out,
        pre_names=pre_names,
    )
    assert result.success, result.errors
    return namer, result


def _prov(out: Path) -> dict[str, Any]:
    return json.loads((out / "naming_provenance.json").read_text(encoding="utf-8"))


def _result_fields(result: Any) -> dict[str, Any]:
    fields = dataclasses.asdict(result)
    fields["output_files"] = [Path(p).name for p in fields["output_files"]]
    return fields


def _dir_bytes(out: Path) -> dict[str, bytes]:
    return {p.name: p.read_bytes() for p in sorted(out.iterdir()) if p.is_file()}


def _all_records(prov: dict[str, Any]):
    for old, rec in prov["global"].items():
        yield old, "", rec
    for func, recs in prov["per_function"].items():
        for old, rec in recs.items():
            yield old, func, rec


def _entry(c: _NamingCandidate) -> dict[str, Any]:
    e: dict[str, Any] = {
        "new_name": c.new_name, "strategy": c.strategy, "confidence": c.confidence,
    }
    for fld in ("evidence", "code_path", "rule", "evidence_origin"):
        if getattr(c, fld):
            e[fld] = getattr(c, fld)
    return e


# ---------------------------------------------------------------------------
# Şema
# ---------------------------------------------------------------------------


def test_provenance_file_schema(ws, tmp_path, serial_pool):
    out = tmp_path / "out"
    _run(ws, out, pre_names={"FUN_00005000": "ledger-reconcile"})
    assert NAMING_PROVENANCE_FILE == "naming_provenance.json"
    prov = _prov(out)

    assert set(prov) == {
        "schema", "schema_version", "min_confidence", "max_runners_up", "summary",
        "global", "per_function", "eliminated_keys", "below_min_confidence_candidates",
    }
    assert prov["schema"] == NAMING_PROVENANCE_SCHEMA == "karadul.naming_provenance"
    assert prov["schema_version"] == NAMING_PROVENANCE_SCHEMA_VERSION == 1
    assert prov["min_confidence"] == 0.15
    assert prov["max_runners_up"] == NAMING_PROVENANCE_MAX_RUNNERS_UP == 3
    assert set(prov["summary"]) == {
        "candidate_keys", "renamed_global", "renamed_local",
        "pre_names_given", "pre_names_applied",
    }
    assert set(prov["eliminated_keys"]) == set(_ProvenanceRecorder.ELIMINATION_REASONS)

    required = {"key", "source", "new_name", "strategy", "confidence", "reason",
                "n_candidates", "runners_up"}
    allowed = required | {"proposed_name", "evidence", "code_path", "rule",
                          "evidence_origin"}
    n_cand_global = n_local = 0
    for old, func, rec in _all_records(prov):
        assert required <= set(rec) <= allowed, rec
        assert rec["key"] == (f"{func}::{old}" if func else old)
        assert rec["source"] in ("candidate", "pre_names")
        assert isinstance(rec["new_name"], str) and rec["new_name"]
        assert isinstance(rec["confidence"], float)
        assert isinstance(rec["n_candidates"], int)
        assert len(rec["runners_up"]) <= 3
        for ru in rec["runners_up"]:
            assert {"new_name", "strategy", "confidence"} <= set(ru)
        if rec["strategy"] == "string_context":
            assert rec["code_path"] in STRING_CONTEXT_CODE_PATHS
            assert rec["rule"] in STRING_CONTEXT_RULES[rec["code_path"]]
            assert rec["evidence_origin"] in STRING_CONTEXT_EVIDENCE_ORIGINS
            assert rec["evidence"]
        if rec["source"] == "candidate":
            n_cand_global += not func
            n_local += bool(func)

    summary = prov["summary"]
    assert summary["renamed_global"] == n_cand_global > 0
    assert summary["renamed_local"] == n_local > 0
    assert summary["pre_names_given"] == summary["pre_names_applied"] == 1
    # Her aday anahtarı seçim döngüsünden tam bir kez çıkar
    eliminated = sum(
        n for by_scope in prov["eliminated_keys"].values()
        for counts in by_scope.values() for n in counts.values()
    )
    assert summary["candidate_keys"] == n_cand_global + n_local + eliminated


def test_records_match_naming_map(ws, tmp_path, serial_pool):
    out = tmp_path / "out"
    _namer, result = _run(ws, out, pre_names={"FUN_00005000": "ledger-reconcile"})
    nm = json.loads((out / "naming_map.json").read_text(encoding="utf-8"))
    prov = _prov(out)

    assert set(prov["global"]) == set(nm["global"])
    assert set(prov["per_function"]) == set(nm["per_function"])
    for func, mapping in nm["per_function"].items():
        assert set(prov["per_function"][func]) == set(mapping)
        for old, new in mapping.items():
            assert prov["per_function"][func][old]["new_name"] == new
    for old, new in nm["global"].items():
        rec = prov["global"][old]
        assert rec["new_name"] == new
        assert rec["strategy"] == result.strategy_map[old]
        assert rec["confidence"] == result.confidence_map[old]


# ---------------------------------------------------------------------------
# string_context kanıtı
# ---------------------------------------------------------------------------


def test_string_context_evidence_is_full_string(ws, tmp_path, serial_pool):
    out = tmp_path / "out"
    _run(ws, out)
    g = _prov(out)["global"]

    classic = g["FUN_00001000"]
    assert len(LONG_REF) > 60
    assert classic["strategy"] == "string_context"
    assert classic["evidence"] == LONG_REF            # kırpılmamış
    assert classic["code_path"] == "classic"
    assert classic["rule"] == "keywords"
    assert LONG_REF[:60] in classic["reason"]         # reason bugünkü gibi kesik
    assert LONG_REF not in classic["reason"]
    assert classic["new_name"] == "compression_dictionary_window"

    aggressive = g["FUN_00003000"]
    assert len(AGGR_LONG) > 60
    assert aggressive["evidence"] == AGGR_LONG
    assert aggressive["code_path"] == "aggressive"
    assert aggressive["rule"] == "class_method"
    assert aggressive["confidence"] == 0.85


def test_evidence_origin_ref_vs_body_literal(ws, tmp_path, serial_pool):
    out = tmp_path / "out"
    _run(ws, out)
    g = _prov(out)["global"]

    assert g["FUN_00001000"]["evidence_origin"] == "string_ref"
    assert g["FUN_00003000"]["evidence_origin"] == "string_ref"
    # Fonksiyonun tek referansı ("zip") kaybeder; kazanan gövdedeki literal.
    # all_strings indeksi tam len(strings): sınır durumu.
    body = g["FUN_00002000"]
    assert body["evidence"] == INLINE_WIN
    assert body["evidence_origin"] == "body_literal"
    assert body["new_name"] == "parser_recovery_buffer"


def test_string_present_in_both_sources_counts_as_ref():
    """Aynı dizgi hem tabloda hem gövdede: ilk görülen (tablo) kazanır, eskisi gibi."""
    namer = CVariableNamer(Config(), min_confidence=0.15)
    namer._string_refs_by_func["0x1"] = [LONG_REF]
    namer._func_bodies["FUN_00000001"] = f'void FUN_00000001(void)\n{{\n  puts("{LONG_REF}");\n}}\n'
    namer._strategy_string_context(SimpleNamespace(name="FUN_00000001", address="0x1", params=[]))
    (cand,) = namer._candidates["FUN_00000001"]
    assert cand.evidence == LONG_REF
    assert cand.evidence_origin == "string_ref"


# ---------------------------------------------------------------------------
# İkincil adaylar
# ---------------------------------------------------------------------------


def test_runners_up_follow_sorted_candidates(ws, tmp_path, serial_pool):
    out = tmp_path / "out"
    namer, _ = _run(ws, out, pre_names={"FUN_00005000": "ledger-reconcile"})
    prov = _prov(out)

    multi = 0
    for old, func, rec in _all_records(prov):
        cands = namer._candidates.get(rec["key"], [])
        assert rec["n_candidates"] == len(cands)
        behind = cands if rec["source"] == "pre_names" else cands[1:]
        assert rec["runners_up"] == [_entry(c) for c in behind[:3]], rec["key"]
        multi += len(rec["runners_up"]) > 0
    assert multi > 0

    # Klasik kazanır; agresif error_verb adayı tam kanıtıyla ardında durur
    err = prov["global"]["FUN_00004000"]
    assert err["code_path"] == "classic" and err["confidence"] == pytest.approx(0.9)
    sc_behind = [ru for ru in err["runners_up"] if ru["strategy"] == "string_context"]
    assert sc_behind == [{
        "new_name": "handle_rebuild", "strategy": "string_context", "confidence": 0.55,
        "evidence": ERR_STR, "code_path": "aggressive", "rule": "error_verb",
        "evidence_origin": "string_ref",
    }]


def test_recorder_keeps_at_most_three_runners_up_in_order():
    cands = [
        _NamingCandidate("FUN_1", f"name_{i}", 0.9 - 0.1 * i, f"strategy_{i}")
        for i in range(6)
    ]
    rec = _ProvenanceRecorder(0.15)
    rec.add_rename("FUN_1", "", "FUN_1", "name_0", cands)
    got = rec.global_records["FUN_1"]
    assert not rec.failed
    assert got["n_candidates"] == 6
    assert [r["new_name"] for r in got["runners_up"]] == ["name_1", "name_2", "name_3"]
    assert [r["confidence"] for r in got["runners_up"]] == [c.confidence for c in cands[1:4]]
    assert "proposed_name" not in got


def test_collision_suffix_records_proposed_name(ws, tmp_path, serial_pool):
    out = tmp_path / "out"
    _run(ws, out)
    g = _prov(out)["global"]
    first, second = g["FUN_00006000"], g["FUN_00007000"]
    assert first["new_name"] == "telemetry_sampler_queue"
    assert "proposed_name" not in first
    assert second["new_name"] == "telemetry_sampler_queue_2"
    assert second["proposed_name"] == "telemetry_sampler_queue"


def test_pre_names_record(ws, tmp_path, serial_pool):
    out = tmp_path / "out"
    _namer, result = _run(ws, out, pre_names={"FUN_00005000": "ledger-reconcile"})
    rec = _prov(out)["global"]["FUN_00005000"]
    assert rec["source"] == "pre_names"
    assert rec["new_name"] == _sanitize_c_name("ledger-reconcile") == "ledger_reconcile"
    assert rec["proposed_name"] == "ledger-reconcile"
    assert rec["strategy"] == result.strategy_map["FUN_00005000"] == "binary_extract"
    assert rec["confidence"] == result.confidence_map["FUN_00005000"]
    # pre_names'in yendiği sezgisel aday kayda geçer (string_context, tam kanıt)
    assert rec["runners_up"][0]["strategy"] == "string_context"
    assert rec["runners_up"][0]["evidence"] == PRE_NAMED_STR


# ---------------------------------------------------------------------------
# Eleme sayıları
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("min_conf", [0.15, 0.7])
def test_eliminated_counts_by_strategy(ws, tmp_path, serial_pool, min_conf):
    out = tmp_path / "out"
    namer, _ = _run(ws, out, min_confidence=min_conf,
                    pre_names={"FUN_00005000": "ledger-reconcile"})
    prov = _prov(out)
    pre_named = {o for o, r in prov["global"].items() if r["source"] == "pre_names"}

    # Bağımsız kâhin: döngünün çıkış koşulları aday listelerinden yeniden kurulur
    expected = {r: {} for r in _ProvenanceRecorder.ELIMINATION_REASONS}
    expected_cands: dict[str, dict[str, int]] = {}

    def bump(d, scope, strategy, n=1):
        d.setdefault(scope, {})
        d[scope][strategy] = d[scope].get(strategy, 0) + n

    for key, cands in namer._candidates.items():
        best = cands[0]
        scope = "local" if "::" in key else "global"
        func, old = key.split("::", 1) if "::" in key else ("", key)
        if best.confidence < min_conf:
            bump(expected["below_min_confidence"], scope, best.strategy)
            for c in cands:
                bump(expected_cands, scope, c.strategy)
        elif not func and best.strategy in ("call_graph", "callee_based", "api_call"):
            bump(expected["global_structural_filter"], scope, best.strategy)
        elif old in pre_named:
            bump(expected["pre_named"], scope, best.strategy)

    assert prov["eliminated_keys"] == expected
    assert prov["below_min_confidence_candidates"] == expected_cands
    # FUN_00009000 yalnız call_graph adayı taşır: 0.15'te yapısal süzgeç, 0.7'de eşik
    reason = "global_structural_filter" if min_conf < 0.55 else "below_min_confidence"
    assert prov["eliminated_keys"][reason]["global"]["call_graph"] >= 1
    if min_conf == 0.7:
        assert prov["below_min_confidence_candidates"]


# ---------------------------------------------------------------------------
# Davranış değişmez
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("min_conf", [0.15, 0.7])
@pytest.mark.parametrize("pre_names", [None, {"FUN_00005000": "ledger-reconcile"}])
def test_outputs_identical_with_and_without_provenance(
    ws, tmp_path, serial_pool, min_conf, pre_names,
):
    on, off = tmp_path / "on", tmp_path / "off"
    _n1, r_on = _run(ws, on, min_confidence=min_conf, pre_names=pre_names)
    _n2, r_off = _run(ws, off, min_confidence=min_conf, pre_names=pre_names,
                      record_provenance=False)

    b_on, b_off = _dir_bytes(on), _dir_bytes(off)
    assert "naming_provenance.json" in b_on
    assert "naming_provenance.json" not in b_off
    del b_on["naming_provenance.json"]
    assert set(b_on) == set(b_off)
    assert b_on["naming_map.json"] == b_off["naming_map.json"]
    c_files = [n for n in b_off if n.endswith(".c")]
    assert len(c_files) == len(_FUNCS)
    for name in c_files:
        assert b_on[name] == b_off[name], name
    assert _result_fields(r_on) == _result_fields(r_off)
    # Adlar gerçekten değişti (boş karşılaştırma değil)
    assert any(b_on[n] != (ws["decompiled"] / n).read_bytes() for n in c_files)


def test_write_failure_is_silent(ws, tmp_path, serial_pool, caplog):
    ref = tmp_path / "ref"
    _n0, r_ref = _run(ws, ref, record_provenance=False)

    out = tmp_path / "out"
    blocker = out / "naming_provenance.json"
    blocker.mkdir(parents=True)            # yazma IsADirectoryError verir
    with caplog.at_level(logging.DEBUG, logger="karadul.reconstruction.c_namer"):
        _n1, r_out = _run(ws, out)

    assert blocker.is_dir() and not any(blocker.iterdir())
    assert _result_fields(r_out) == _result_fields(r_ref)
    assert _dir_bytes(out) == _dir_bytes(ref)
    assert any("naming_provenance.json yazilamadi" in r.getMessage()
               and r.levelno == logging.DEBUG for r in caplog.records)


def test_recorder_failure_never_touches_naming(ws, tmp_path, serial_pool,
                                               monkeypatch, caplog):
    ref = tmp_path / "ref"
    _n0, r_ref = _run(ws, ref, record_provenance=False)

    def boom(_cand):
        raise RuntimeError("kayıt hatası")

    monkeypatch.setattr(_ProvenanceRecorder, "_candidate_entry", staticmethod(boom))
    out = tmp_path / "out"
    with caplog.at_level(logging.WARNING, logger="karadul.reconstruction.c_namer"):
        _n1, r_out = _run(ws, out)

    assert not (out / "naming_provenance.json").exists()   # yarım kayıt yazılmaz
    assert _result_fields(r_out) == _result_fields(r_ref)
    assert _dir_bytes(out) == _dir_bytes(ref)
    assert any("naming_provenance.json yazilmadi" in r.getMessage() for r in caplog.records)


def test_real_process_pool_carries_evidence(ws, tmp_path):
    """Gerçek ProcessPool: yeni aday alanları işçi süreçten pickle ile döner."""
    out = tmp_path / "out"
    _run(ws, out)
    nm = json.loads((out / "naming_map.json").read_text(encoding="utf-8"))
    prov = _prov(out)
    assert set(prov["global"]) == set(nm["global"])
    rec = prov["global"]["FUN_00001000"]
    assert rec["evidence"] == LONG_REF
    assert rec["evidence_origin"] == "string_ref"
    assert rec["code_path"] == "classic"


# ---------------------------------------------------------------------------
# Birim: kural etiketleri, sarmalayıcı eşliği, eski seçim kenarları
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("text, rule", [
    ("CFoo::BarBaz", "class_method"),
    ("flushJournal()", "func_paren"),
    ("/src/codec/huffman.c", "src_path_pair"),
    ("/src/huffman.c", "src_path_single"),
    ("lobby join", "steam_keyword"),
    ("https://example.org/metrics", "url_hint"),
    ("Unable to rebuild compression dictionary index", "error_verb"),
    ("handleGetURLEvent:withReplyEvent:", "objc_selector"),
    ("frame_len > 0", "assert_expr"),
])
def test_aggressive_rule_labels(text, rule):
    name, conf, got = _match_string_aggressive(text)
    assert got == rule
    assert got in STRING_CONTEXT_RULES["aggressive"]
    assert _extract_name_from_string_aggressive(text) == (name, conf)


def test_aggressive_wrapper_returns_none_without_match():
    assert _match_string_aggressive(LONG_REF) is None
    assert _extract_name_from_string_aggressive(LONG_REF) is None


def test_classic_tie_keeps_first_seen():
    """Eşit klasik skor (10 == 10): ilk görülen kazanır. Kayıt için skor
    demetine eklenen indeks sıralamaya katılmamalı."""
    namer = CVariableNamer(Config(), min_confidence=0.15)
    namer._string_refs_by_func["0x1"] = ["alpha bravo", "delta gamma"]
    namer._func_bodies["FUN_00000001"] = ""
    namer._strategy_string_context(SimpleNamespace(name="FUN_00000001", address="0x1", params=[]))
    (cand,) = namer._candidates["FUN_00000001"]
    assert cand.new_name == "alpha_bravo"
    assert cand.evidence == "alpha bravo"


def test_candidate_new_fields_default_empty():
    cand = _NamingCandidate("param_1", "buf", 0.5, "dataflow", "r")
    assert (cand.evidence, cand.code_path, cand.rule, cand.evidence_origin) == ("",) * 4
