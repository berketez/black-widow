"""P13b / BORU-14 (a) = IMZA-13: K-4 ad kanalları gerçek koşuda çağrılır, anahtarı Ghidra'yla tutar.

Eski davranış: ``run_name_merger`` ``collect_candidates``'e ``binary_path`` / ``pdb_symbols`` /
``bn_functions`` / ``trex_structs`` geçirmiyordu → ``_add_dwarf`` … ``_add_trex_structs`` hiçbir
koşuda çağrılmıyordu. Açılsalardı da: PDB adresi bölüm içi ofsetti (anahtar ``FUN_<ofset>``),
C++ ``_ZN…`` adları Rust kanalına düşüyordu (``foo::bar`` / ``MyClass``), çözülmüş ad (``a::b``)
C tanımlayıcısı değildi, TRex ``related_functions`` arıyordu (üretici ``function`` yazar).
"""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from karadul.config import Config
from karadul.core.naming_labels import NAMING_PROVENANCE_FILE
from karadul.pipeline.steps import _feedback_naming_candidates as FC
from karadul.pipeline.steps import _feedback_naming_merger as FM

PE_BASE = 0x180000000


def _index(*addrs: int, named: dict[int, str] | None = None) -> FC.GhidraFunctionIndex:
    by_addr = {a: f"FUN_{a:08x}" for a in addrs}
    by_addr.update(named or {})
    return FC.GhidraFunctionIndex(by_addr=by_addr, names=frozenset(by_addr.values()))


def _flags(**on: bool) -> dict[str, bool]:
    return {src: bool(on.get(src)) for src in FC.K4_CHANNEL_FLAGS}


def _k4(index, **kw):
    base = dict(flags=_flags(), index=index, binary_path=None, pdb_symbols=[], pdb_status=None,
                bn_functions=[], bn_status=None, trex_structs=[], trex_status=None)
    base.update(kw)
    return base


@pytest.fixture
def fake_pe(monkeypatch):
    monkeypatch.setattr(FC, "pe_section_rvas", lambda _p: [0x1000, 0x5000])
    monkeypatch.setattr(FC, "_binary_link_base", lambda _p: PE_BASE)


def test_pdb_section_offset_becomes_ghidra_va_key(fake_pe) -> None:
    cands: dict = {}
    stats: dict = {}
    FC.add_k4_channels(**_k4(
        _index(PE_BASE + 0x1010, named={PE_BASE + 0x1020: "Z3_mk_context"}),
        flags=_flags(pdb=True), binary_path=Path("x.dll"), pdb_status="ok",
        pdb_symbols=[
            {"name": "smt::context::assert_expr", "section": 1, "address": 0x10,
             "kind": "function"},
            {"name": "Z3_mk_context", "section": 1, "address": 0x20, "kind": "function"},
            {"name": "g_table", "section": 2, "address": 0x8, "kind": "global"},
        ]), candidates=cands, stats=stats)
    key = f"FUN_{PE_BASE + 0x1010:08x}"
    assert list(cands) == [key]
    assert cands[key][0].name == "smt_context_assert_expr"
    assert cands[key][0].source == "pdb"
    ch = stats["naming_channels"]["pdb"]
    assert ch["durum"] == "calisti" and ch["aday"] == 1 and ch["ghidra_adli"] == 1


def test_rust_channel_excludes_cpp_itanium_names() -> None:
    syms = [("_ZN3foo3barEi", 0x1000), ("_ZN7MyClassC2Ev", 0x1010),
            ("_ZN4core3fmt5write17h0123456789abcdefE", 0x1020)]
    cands: dict = {}
    stats: dict = {}
    FC._add_rust_demangler(syms, _index(0x1000, 0x1010, 0x1020), cands, stats)
    assert {k: [c.name for c in v] for k, v in cands.items()} == {
        "FUN_00001020": ["core_fmt_write"]}
    assert stats["naming_channels"]["rust_demangler"]["rust_simge"] == 1


def test_mangled_ghidra_name_is_the_key_when_address_does_not_match() -> None:
    sym = "_ZN4core3fmt5write17h0123456789abcdefE"
    idx = FC.GhidraFunctionIndex(by_addr={0x9000: sym}, names=frozenset({sym}))
    cands: dict = {}
    FC._add_rust_demangler([(sym, 0x1234)], idx, cands, {})
    assert [c.name for c in cands[sym]] == ["core_fmt_write"]


def test_trex_function_field_is_read() -> None:
    cands: dict = {}
    stats: dict = {}
    FC._add_trex_structs([{"name": "HttpRequest", "function": "FUN_00004000"}], "ok",
                         _index(0x4000), cands, stats)
    assert [c.name for c in cands["FUN_00004000"]] == ["http_request"]


def test_flags_off_channels_do_no_work(monkeypatch) -> None:
    def boom(*_a, **_k):
        raise AssertionError("kapalı kanal iş yaptı")
    monkeypatch.setattr(FC, "_extract_binary_symbols", boom)
    monkeypatch.setattr(FC, "_add_dwarf", boom)
    cands: dict = {}
    stats: dict = {}
    FC.add_k4_channels(**_k4(_index(0x1000), binary_path=Path("x")), candidates=cands,
                       stats=stats)
    assert cands == {}
    assert {v["durum"] for v in stats["naming_channels"].values()} == {"kapali"}
    assert set(stats["naming_channels"]) == set(FC.K4_CHANNEL_FLAGS)
    # bir kanal (PDB) açıkken de kapalı DWARF / Rust / Go iş yapmaz
    stats2: dict = {}
    FC.add_k4_channels(**_k4(_index(0x1000), flags=_flags(pdb=True), binary_path=Path("x"),
                             pdb_status="no_pdb_file"), candidates=cands, stats=stats2)
    assert stats2["naming_channels"]["pdb"]["durum"] == "veri_yok"
    assert stats2["naming_channels"]["dwarf"]["durum"] == "kapali"


def test_tool_missing_and_unsupported_statuses() -> None:
    stats: dict = {}
    FC.add_k4_channels(**_k4(_index(0x1000), flags=_flags(bn_symbol=True, trex_struct=True),
                             bn_status="arac_yok", trex_status="desteklenmiyor"),
                       candidates={}, stats=stats)
    assert stats["naming_channels"]["bn_symbol"]["durum"] == "arac_yok"
    assert stats["naming_channels"]["trex_struct"]["durum"] == "desteklenmiyor"
    assert stats["naming_channels"]["trex_struct"]["neden"]


def test_load_ghidra_index_applies_image_base_delta(tmp_path) -> None:
    fj = tmp_path / "ghidra_functions.json"
    fj.write_text(json.dumps({"functions": [{"name": "FUN_00101234", "address": "00101234"}]}))
    idx = FC.load_ghidra_index(fj, ghidra_image_base=0x100000)
    assert idx.key_for(0x101234) == ("FUN_00101234", "tuttu")
    # bağlama tabanı bilinmiyorsa (ikili yok) delta 0: PIE adresi tutmaz, sayılır
    assert idx.key_for(0x1234) == (None, "ghidra_fonksiyonu_yok")


# --- uçtan uca: run_name_merger bayrak açıkken PDB adını koda yazar, güveni null -----------

def _ctx(flags: dict[str, bool], artifacts: dict) -> SimpleNamespace:
    cfg = Config()
    for src, on in flags.items():
        setattr(cfg.binary_reconstruction, FC.K4_CHANNEL_FLAGS[src], on)
    return SimpleNamespace(
        pipeline_context=SimpleNamespace(config=cfg, metadata={}, target=None, workspace=None),
        artifacts=artifacts)


def _merge(tmp_path: Path, ctx) -> SimpleNamespace:
    dec = tmp_path / "src"
    dec.mkdir()
    key = f"FUN_{PE_BASE + 0x1010:08x}"
    (dec / "a.c").write_text(f"void FUN_{PE_BASE + 0x2000:08x}(void){{ {key}(); }}\n")
    (dec / NAMING_PROVENANCE_FILE).write_text(json.dumps({"schema": "x", "global": {}}))
    fj = tmp_path / "ghidra_functions.json"
    fj.write_text(json.dumps({"functions": [
        {"name": key, "address": f"{PE_BASE + 0x1010:x}"},
        {"name": f"FUN_{PE_BASE + 0x2000:08x}", "address": f"{PE_BASE + 0x2000:x}"}]}))
    rec = tmp_path / "rec"
    rec.mkdir()
    stats: dict = {}
    errors: list[str] = []
    harita, _adli, dizin = FM.run_name_merger(
        ctx=ctx, iter_index=0, decompiled_dir=dec, reconstructed_dir=rec,
        incremental_files=None, extracted_names={}, naming_result=None,
        bindiff_confidence_map={}, refdiff_naming={}, fid_json=tmp_path / "fid.json",
        computation_result=None, pcode_naming_candidates=[], stats=stats, errors=errors,
        artifacts={}, functions_json=fj)
    assert errors == []
    return SimpleNamespace(harita=harita, stats=stats, dec=dec, dizin=dizin, key=key)


PDB_ARTS = {
    "binary_for_byte_match": Path("hedef.dll"),
    "pdb_symbols": [{"name": "Z3_solver_check", "section": 1, "address": 0x10,
                     "kind": "function"}],
    "pdb_status": "ok",
}


def test_run_name_merger_feeds_pdb_channel_when_flag_on(tmp_path, fake_pe) -> None:
    k = _merge(tmp_path, _ctx({"pdb": True}, dict(PDB_ARTS)))
    assert k.harita == {k.key: "Z3_solver_check"}
    assert "Z3_solver_check();" in (k.dizin / "a.c").read_text()
    karar = json.loads((k.dec / NAMING_PROVENANCE_FILE).read_text())["name_merger"][
        "decisions"][k.key]
    assert karar["sources"] == ["pdb"]
    assert karar["confidence"] is None and karar["unmeasured_sources"] == ["pdb"]
    assert k.stats["naming_channels"]["pdb"]["aday"] == 1


def test_run_name_merger_flag_off_changes_nothing(tmp_path, fake_pe) -> None:
    """Bayrak kapalı (config yaması öncesi alan yok = kapalı; yamayla PDB öntanımı açık)."""
    k = _merge(tmp_path, _ctx({src: False for src in FC.K4_CHANNEL_FLAGS}, dict(PDB_ARTS)))
    assert not k.harita
    assert k.stats["naming_channels"]["pdb"]["durum"] == "kapali"


def test_pdb_parser_reads_llvm_pdbutil_offset_as_decimal() -> None:
    """Gerçek ``llvm-pdbutil dump --symbols`` satırı (libz3.pdb): ofset ONLUK.

    ``Z3_mk_context`` ofseti 207056; ihraç tablosunda RVA 0x338d0 = 0x1000 (.text) + 207056.
    Eski ayrıştırıcı onaltılık okuyordu (0x207056).
    """
    from karadul.analyzers.pdb_parser import _parse_addr

    assert _parse_addr("parent = 0, end = 488, addr = 0001:0672, code size = 6") == (1, 672)
    assert _parse_addr("addr = 0001:207056, code size = 118") == (1, 207056)
    assert 0x1000 + _parse_addr("addr = 0001:207056")[1] == 0x338D0


def test_disabled_producer_and_unwired_rtti_are_not_reported_as_no_data() -> None:
    """Sac ürün koşusunda görüldü: BN üreticisi kapalıyken kanal "veri_yok (disabled)", RTTI
    üreticisi hiç yokken "sınıf bulunamadı" diyordu (aranmadığı hâlde)."""
    stats: dict = {}
    FC.add_k4_channels(**_k4(_index(0x1000), flags=_flags(bn_symbol=True, rtti=True),
                             bn_status="disabled"), candidates={}, stats=stats)
    assert stats["naming_channels"]["bn_symbol"]["durum"] == "kapali"
    assert stats["naming_channels"]["rtti"]["durum"] == "desteklenmiyor"
