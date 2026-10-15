"""Tarif katmanı (karadul/reconstruction/tarif) birim testleri.

Ölçümle seçilmiş davranışları kilitler: geri çağrı rolleri, log mesajından isim ve hata
mesajı süzgeci, sabit argümandan nesne, yan API çağrısını eleme, yayılım ve modül çıkarımı.
"""

from __future__ import annotations

import json
from pathlib import Path

from karadul.reconstruction.tarif import run_tarif
from karadul.reconstruction.tarif.evidence import EvidencePack, build_evidence
from karadul.reconstruction.tarif.module import ModuleLocator, apply_modules
from karadul.reconstruction.tarif.propagate import propagate
from karadul.reconstruction.tarif.rules import (
    Naming,
    callback_role,
    find_logger,
    literal_object,
    name_from_log,
    name_function,
)


def _static_dir(tmp_path: Path, functions: list[dict], xrefs: dict, code: dict[str, str]) -> Path:
    static = tmp_path / "static"
    (static / "ghidra_output" / "decompiled").mkdir(parents=True)
    (static / "ghidra_functions.json").write_text(json.dumps({"functions": functions}))
    (static / "ghidra_xrefs.json").write_text(json.dumps({"function_xrefs": xrefs}))
    for addr, body in code.items():
        (static / "ghidra_output" / "decompiled" / f"FUN_{addr}.c").write_text(body)
    return static


def _pack(addr: str, **kw) -> EvidencePack:
    return EvidencePack(address=addr, ghidra_name=f"FUN_{addr}", **kw)


# --- kanıt paketi --------------------------------------------------------------------------

def test_build_evidence_separates_apis_and_finds_callback_registrations(tmp_path):
    functions = [
        {"name": "_event_set", "address": "100009000", "is_external": True},
        {"name": "FUN_100001000", "address": "100001000"},
        {"name": "FUN_100002000", "address": "100002000"},
    ]
    xrefs = {
        "100001000": {"name": "FUN_100001000", "functions_called": [
            {"name": "_event_set", "address": "100009000"},
            {"name": "FUN_100003000", "address": "100003000"}], "called_by": [], "strings_used": []},
        "100002000": {"name": "FUN_100002000", "functions_called": [], "called_by": [], "strings_used": []},
    }
    code = {"100001000": "void f(void){ _event_set(p,0xffffffff,0,FUN_100002000,q); FUN_100003000(1); }"}
    packs = build_evidence(_static_dir(tmp_path, functions, xrefs, code))
    assert packs["100001000"].apis == ["event_set"]
    assert packs["100001000"].internal_callees == ["100003000"]
    # çağrılan FUN_100003000 geri çağrı sayılmaz, argüman olarak geçen FUN_100002000 sayılır
    assert packs["100001000"].callback_registrations == [{"api": "event_set", "target": "100002000"}]
    assert packs["100002000"].registered_as_callback == [{"api": "event_set", "registrar": "100001000"}]


# --- kurallar ------------------------------------------------------------------------------

def test_callback_role_from_event_flags_and_argument_position():
    assert callback_role("event_set", "_event_set(e,0xffffffff,0,FUN_abc,x);", "abc") == "on_timer"
    assert callback_role("event_set", "_event_set(e,fd,2,FUN_abc,x);", "abc") == "on_readable"
    assert callback_role("event_set", "_event_set(e,fd,0x14,FUN_abc,x);", "abc") == "on_writable"
    code = "_bufferevent_new(fd,FUN_r,FUN_w,FUN_e,x);"
    assert callback_role("bufferevent_new", code, "r") == "on_read"
    assert callback_role("bufferevent_new", code, "e") == "on_error"
    assert callback_role("qsort", "", "abc") == "compare_for_sort"


def test_name_from_log_uses_action_message_and_skips_failure_messages():
    code = 'FUN_log("%s: index out of range"); FUN_log("@%u alerts timer reset %u");'
    assert name_from_log(code, "FUN_log") == "alerts_timer_reset"
    assert name_from_log('FUN_log("%s: out of range"); FUN_log("bad osc");', "FUN_log") is None
    assert name_from_log(code, None) is None


def test_find_logger_needs_many_distinct_format_strings():
    # Ghidra adları onaltılık adres taşır (FUN_10004cb14)
    many = "".join(f'FUN_10004cb14("msg {i} %d"); ' for i in range(25))
    packs = {"a": _pack("a"), "b": _pack("b")}
    packs["a"].read_code = lambda: many  # type: ignore[method-assign]
    packs["b"].read_code = lambda: 'FUN_1000a7440("%s"); FUN_1000a7440("%d");'  # type: ignore[method-assign]
    assert find_logger(packs) == "FUN_10004cb14"
    packs["a"].read_code = lambda: 'FUN_10004cb14("x %d");'  # type: ignore[method-assign]
    assert find_logger(packs) is None


def test_literal_argument_becomes_object():
    assert literal_object('_sysctlbyname("hw.memsize",&v,&l,0,0);', "query_system_info") == "get_hw_memsize"
    assert literal_object('_fopen$DARWIN_EXTSN("/etc/os-release","r");', "read_file") == "read_os_release"
    assert literal_object("_sysctl(mib,2,&v,&l,0,0);", "query_system_info") is None


def test_incidental_api_in_big_function_gives_no_name():
    big = _pack("a", apis=["event_del"], api_counts={"event_del": 1},
                internal_callees=[f"{i:x}" for i in range(10)])
    assert name_function(big, {"a": big}, {}, None) is None
    small = _pack("b", apis=["fgets", "fopen$DARWIN_EXTSN"], api_counts={"fgets": 1, "fopen$DARWIN_EXTSN": 1})
    n = name_function(small, {"b": small}, {}, None)
    assert n is not None and n.name == "read_file"


# --- yayılım ve modül ----------------------------------------------------------------------

def test_propagate_adds_registrar_context_to_callback_role():
    packs = {
        "1": _pack("1", registered_as_callback=[{"api": "event_set", "registrar": "2"}]),
        "2": _pack("2"),
    }
    names = {"1": Naming("on_timer", "geri_cagri:event_set", 9.0), "2": Naming("alerts_reset", "kesin:dize", 7.4)}
    propagate(names, packs, {"1", "2"})
    assert names["1"].name == "alerts_on_timer"


def test_propagate_wrapper_does_not_carry_log_names():
    packs = {
        "w1": _pack("w1", internal_callees=["c1"], line_count=5),
        "w2": _pack("w2", internal_callees=["c2"], line_count=5),
        "c1": _pack("c1"), "c2": _pack("c2"),
    }
    names = {"c1": Naming("index_out_range", "log", 7.5), "c2": Naming("read_file", "api:fgets+fopen", 9.0)}
    propagate(names, packs, {"w1", "w2"})
    assert "w1" not in names
    assert names["w2"].name == "read_file" and names["w2"].source == "yayilim:Y2"


def test_module_locator_and_apply_modules():
    kesin = {"1000": "grid_clear", "1100": "grid_move_lines", "1200": "grid_view_x", "1300": "grid_y",
             "2000": "tty_draw", "2100": "tty_write", "2200": "tty_init"}
    loc = ModuleLocator(kesin)
    assert loc.module_of("1050") == "grid"
    assert loc.module_of("1500") is None  # komşular farklı modüllerde
    names = {"1150": Naming("on_timer", "geri_cagri:event_set", 9.0), "2050": Naming("open_read_file", "log", 7.5)}
    apply_modules(names, kesin, {"1050", "1150", "2050"})
    assert names["1050"] == Naming("grid", "ipucu:modul", 2.0)
    assert names["1150"].name == "grid_on_timer"
    assert names["2050"].name == "open_read_file"  # log isimlerine önek eklenmez


def test_run_tarif_keeps_kesin_and_marks_hints(tmp_path):
    functions = [{"name": "_fgets", "address": "100009000", "is_external": True},
                 {"name": "_fopen$DARWIN_EXTSN", "address": "100009100", "is_external": True}]
    xrefs = {"100001000": {"name": "FUN_100001000", "functions_called": [
        {"name": "_fgets", "address": "100009000"}, {"name": "_fopen$DARWIN_EXTSN", "address": "100009100"}],
        "called_by": [], "strings_used": []}}
    packs = build_evidence(_static_dir(tmp_path, functions, xrefs, {}))
    names = run_tarif(packs, {"100000500": "config_load"}, {"100000500", "100001000"})
    assert names["100000500"].source.startswith("kesin")
    assert names["100001000"].name == "read_file" and not names["100001000"].is_hint
