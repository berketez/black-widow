"""scripts/measurement/function_f1.py — fonksiyon-ismi ölçüm harness'inin birim testleri.

Sentetik GT + Ghidra fonksiyon listesi + naming_map ile harness'in sahte-F1
tuzaklarına düşmediğini kilitler:
  (a) GT'de olmayan fonksiyon TP sayılmaz,
  (b) FUN_xxx / adres etiketli jenerik isimler "isimlendirilmiş" sayılmaz,
  (c) PLT/EXTERNAL thunk'ları tespit paydasına girmez, CRT puanlanmaz,
  (d) GCC sufiksleri (.constprop/.part) FIX-4 kuralıyla normalize edilir,
  (e) yanlış isim hem FP hem FN'dir (recall = TP / |puanlanan GT|).
Mutation koruması: scripts/measurement/mutation_specs_function_f1.json
(``python scripts/mutation_probe.py --spec <o dosya>``).
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

_PATH = Path(__file__).resolve().parents[1] / "scripts" / "measurement" / "function_f1.py"
_spec = importlib.util.spec_from_file_location("function_f1_under_test", _PATH)
f1 = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = f1
_spec.loader.exec_module(f1)

BASE = 0x100000  # Ghidra ELF PIE image base (entry'den türetilmeli)


def _gt_fn(addr: int, name: str, crt: bool = False) -> dict:
    return {"addr": f"0x{addr:x}", "names": [name], "bind": "LOCAL", "size": 16,
            "section": ".text", "crt": crt}


def _gh(addr: int, name: str | None = None, thunk: bool = False) -> dict:
    return {"addr": addr, "name": name or f"FUN_{addr:08x}", "is_thunk": thunk, "size": 16}


@pytest.fixture
def synthetic():
    gt = {
        "corpus": "test", "binary": "toy", "build_id": "ab" * 20,
        "elf_type": "ET_DYN", "entry": "0x1000", "stripped_sha256": "0" * 64,
        "exec_sections": [
            {"name": ".init", "start": "0xf00", "end": "0xf20"},
            {"name": ".plt", "start": "0xf20", "end": "0x1000"},
            {"name": ".text", "start": "0x1000", "end": "0x2000"},
        ],
        "functions": [
            _gt_fn(0x1000, "_start", crt=True),
            _gt_fn(0x1100, "main"),
            _gt_fn(0x1200, "full_write.constprop.0"),
            _gt_fn(0x1300, "gettext_quote.part.0"),
            _gt_fn(0x1400, "safe_read"),
            _gt_fn(0x1500, "write_error"),
            _gt_fn(0x1600, "next_line_num"),
            _gt_fn(0x1700, "never_detected"),
            _gt_fn(0x1800, "frame_dummy", crt=True),
        ],
    }
    ghidra = [
        _gh(BASE + 0x1000, "entry"),
        _gh(BASE + 0xf30, "malloc", thunk=True),       # .plt thunk
        _gh(BASE + 0x21000, "malloc", thunk=True),     # EXTERNAL blok
        _gh(BASE + 0x1100), _gh(BASE + 0x1200), _gh(BASE + 0x1300),
        _gh(BASE + 0x1400), _gh(BASE + 0x1500), _gh(BASE + 0x1600),
        _gh(BASE + 0x1800),
        _gh(BASE + 0x1900), _gh(BASE + 0x1a00),        # GT'de yok
    ]
    naming = {
        "FUN_00101100": "main",                  # TP
        "FUN_00101200": "full_write",            # TP (.constprop sufiksi)
        "FUN_00101300": "gettext_quote",         # TP (.part sufiksi)
        "FUN_00101400": "read_fd_1400",          # jenerik (kendi adresi) -> isimsiz
        "FUN_00101500": "write",                 # strict yanlış, lenient partial
        "FUN_00101600": "FUN_00101600",          # yer tutucu -> isimsiz
        "FUN_00101800": "frame_dummy",           # CRT -> puanlanmaz
        "FUN_00101900": "helper_function",       # GT dışı -> doğrulanamaz
        "FUN_00101a00": "leaf_1a00",             # GT dışı + jenerik
        "FUN_00101000": "start",                 # Ghidra adı 'entry', anahtar FUN_
        "malloc": "malloc",                      # thunk; puanlamaya girmez
    }
    return gt, ghidra, naming


def _by_gt(result: dict) -> dict:
    return {p["gt"]: p for p in result["per_function"]}


# (d) GCC sufiksleri -------------------------------------------------------

def test_suffix_normalization_matches_gcc_clones(synthetic):
    gt, ghidra, naming = synthetic
    r = f1.score(gt, ghidra, naming)
    fx = _by_gt(r)
    assert fx["full_write.constprop.0"]["status"] == "tp"
    assert fx["gettext_quote.part.0"]["status"] == "tp"
    assert f1.normalize_name("force_symlinkat.part.0.constprop.0") == "force_symlinkat"
    assert f1.normalize_name("quotearg_buffer_restyled.cold") == "quotearg_buffer_restyled"


# (b) jenerik isimler ------------------------------------------------------

def test_generic_names_are_not_predictions(synthetic):
    gt, ghidra, naming = synthetic
    fx = _by_gt(f1.score(gt, ghidra, naming))
    # Kendi adresini taşıyan isim ve yer tutucu: FP DEĞİL, isimsiz (FN).
    assert fx["safe_read"]["status"] == "unnamed"
    assert fx["next_line_num"]["status"] == "unnamed"


@pytest.mark.parametrize("name,addrs,expected", [
    ("FUN_00102de0", [0x2de0], True),
    ("sub_401000", [0x401000], True),
    ("thunk_FUN_00101234", [0x1234], True),
    ("leaf_2de0", [0x2de0, 0x102de0], True),
    ("read_fd_3144", [0x3144], True),
    ("entry", [0x2cc0], True),
    ("_INIT_0", [0x2dd0], True),
    ("uVar3", [0x1234], True),               # yalnız metrics._is_unnamed yakalar
    ("DAT_00203000", [0x1234], True),        # başka adres taşıyan yer tutucu
    ("", [], True),
    ("calls_nl_langinfo", [0x2ee0], False),   # adres taşımıyor: tahmin sayılır
    ("write", [0x1500], False),
    ("sha256_process_block", [0x1234], False),
    ("leaf_2de0", [0x3000], False),          # başka fonksiyonun adresi
])
def test_is_generic_name(name, addrs, expected):
    assert f1.is_generic_name(name, addrs) is expected


# (a) GT dışı fonksiyonlar -------------------------------------------------

def test_outside_gt_named_function_is_not_tp(synthetic):
    gt, ghidra, naming = synthetic
    r = f1.score(gt, ghidra, naming)
    assert r["strict"]["tp"] == 3
    assert r["outside_gt"] == {"detected_code_not_in_gt": 2, "named_non_generic": 1}
    # GT dışına daha çok isim eklemek P/R/F1'i DEĞİŞTİRMEMELİ.
    more = dict(naming, **{"FUN_00101a00": "another_real_looking_name"})
    r2 = f1.score(gt, ghidra, more)
    assert r2["strict"] == r["strict"]
    assert r2["outside_gt"]["named_non_generic"] == 2


# (c) thunk + CRT ----------------------------------------------------------

def test_thunks_excluded_from_detected_and_coverage(synthetic):
    gt, ghidra, naming = synthetic
    r = f1.score(gt, ghidra, naming)
    assert r["detected"] == {"ghidra_total": 12, "code": 10, "plt": 1, "external": 1,
                             "thunk_flagged": 2}
    # kod fonksiyonları: entry + 6 + frame_dummy + 2 GT-dışı = 10; GT'de 8'i var.
    assert r["coverage"]["gt_in_detected"] == 8
    assert r["coverage"]["ratio"] == 0.8
    assert r["coverage"]["gt_detection_ratio"] == round(8 / 9, 4)


def test_crt_functions_not_scored(synthetic):
    gt, ghidra, naming = synthetic
    r = f1.score(gt, ghidra, naming)
    assert r["gt"] == {"functions": 9, "scored": 7, "crt": 2, "exported": 0}
    assert "frame_dummy" not in _by_gt(r) and "_start" not in _by_gt(r)
    # 'start' Ghidra'da 'entry' adıyla durur ama karadul FUN_ anahtarıyla isimlendirir.
    assert r["crt_named"] == 2


# (e) metrik tanımı --------------------------------------------------------

def test_strict_prf_and_breakdown(synthetic):
    gt, ghidra, naming = synthetic
    r = f1.score(gt, ghidra, naming)
    assert r["breakdown"] == {"tp": 3, "wrong": 1, "unnamed": 2, "undetected": 1}
    # yanlış isim hem FP hem FN: FN = 7 - 3 = 4 (1 tespitsiz + 2 isimsiz + 1 yanlış)
    assert r["strict"] == {"tp": 3, "fp": 1, "fn": 4, "precision": 0.75,
                           "recall": round(3 / 7, 4), "f1": round(2 * 0.75 * (3 / 7) / (0.75 + 3 / 7), 4)}


def test_lenient_uses_compare_name(synthetic):
    gt, ghidra, naming = synthetic
    r = f1.score(gt, ghidra, naming)
    # write ~ write_error: kısmi eşleşme lenient'te TP, strict'te FP.
    assert _by_gt(r)["write_error"]["status"] == "wrong"
    assert _by_gt(r)["write_error"]["lenient_tp"] is True
    assert r["lenient"] == {"tp": 4, "fp": 0, "fn": 3, "precision": 1.0,
                            "recall": round(4 / 7, 4), "f1": round(2 * (4 / 7) / (1 + 4 / 7), 4)}


def test_image_offset_derived_from_entry(synthetic):
    gt, ghidra, naming = synthetic
    r = f1.score(gt, ghidra, naming)
    assert (r["image_offset"], r["image_offset_source"]) == ("0x100000", "ghidra_entry")
    # entry'siz: PIE varsayılanı; ET_EXEC: 0.
    no_entry = [g for g in ghidra if g["name"] != "entry"]
    assert f1.derive_image_offset(no_entry, 0x1000, "ET_DYN") == (0x100000, "default")
    assert f1.derive_image_offset(no_entry, 0x401000, "ET_EXEC") == (0, "default")
    # Farklı taban (0x400000) da entry'den doğru çözülmeli.
    shifted = [dict(g, addr=g["addr"] - BASE + 0x400000) for g in ghidra]
    shifted_map = {f"FUN_{int(k[4:], 16) - BASE + 0x400000:08x}" if k.startswith("FUN_") else k: v
                   for k, v in naming.items()}
    r2 = f1.score(gt, shifted, shifted_map)
    assert r2["image_offset"] == "0x400000"
    assert r2["strict"] == r["strict"]


def test_ghidra_self_named_function_is_flagged_not_predicted(synthetic):
    gt, ghidra, naming = synthetic
    # Ghidra bir GT fonksiyonunu kendisi isimlendirmiş (debug sızıntısı belirtisi):
    # karadul'un iddiası değil -> TP sayılmaz, ama uyarı listesine düşer.
    leaked = [dict(g, name="next_line_num") if g["addr"] == BASE + 0x1600 else g for g in ghidra]
    nm = {k: v for k, v in naming.items() if k != "FUN_00101600"}
    r = f1.score(gt, leaked, nm)
    assert r["ghidra_named_scored"] == ["next_line_num"]
    assert _by_gt(r)["next_line_num"]["status"] == "unnamed"
    assert r["strict"]["tp"] == 3


def test_ghidra_thunk_autoname_is_not_prediction(synthetic):
    gt, ghidra, naming = synthetic
    # fdadvise gibi tek 'b posix_fadvise' olan fonksiyon: Ghidra thunk hedef adını koyar.
    thunked = [dict(g, name="posix_fadvise", is_thunk=True) if g["addr"] == BASE + 0x1600 else g
               for g in ghidra]
    nm = {k: v for k, v in naming.items() if k != "FUN_00101600"}
    r = f1.score(gt, thunked, nm)
    assert _by_gt(r)["next_line_num"]["status"] == "unnamed"
    assert r["ghidra_thunk_named"] == ["next_line_num"] and r["ghidra_named_scored"] == []
    assert r["strict"]["fp"] == 1  # yalnız write_error; thunk adı FP'ye eklenmez


def test_exported_functions_not_scored(synthetic):
    gt, ghidra, naming = synthetic
    # .dynsym'den ihraç edilen fonksiyonun adı stripped binary'de duruyor: puanlanmaz.
    gt2 = dict(gt, functions=[dict(f, exported=(f["names"] == ["main"])) for f in gt["functions"]])
    r = f1.score(gt2, ghidra, naming)
    assert "main" not in _by_gt(r)
    assert r["gt"]["scored"] == 6 and r["gt"]["exported"] == 1
    assert r["exported_named"] == 1
    assert r["strict"]["tp"] == 2


# GT çıkarımı --------------------------------------------------------------

def _sym(name, value, typ="STT_FUNC", bind="STB_LOCAL", section=".text", exec_=True, size=8):
    return {"name": name, "value": value, "size": size, "type": typ, "bind": bind,
            "section": section, "section_exec": exec_}


def test_build_gt_functions_filters_and_groups():
    syms = [
        _sym("$x", 0x1000, typ="STT_NOTYPE"),
        _sym("$x.12", 0x1100, typ="STT_NOTYPE"),
        _sym("main", 0x1000, bind="STB_GLOBAL"),
        _sym("main_alias", 0x1000, bind="STB_WEAK"),
        _sym("helper.part.0", 0x1100),
        _sym("memcpy@GLIBC_2.17", 0, bind="STB_GLOBAL", section="SHN_UNDEF", exec_=False),
        _sym("table", 0x3000, typ="STT_OBJECT", section=".rodata", exec_=False),
        _sym("weird", 0x3100, section=".rodata", exec_=False),
        _sym("frame_dummy", 0x1200),
        _sym("_start", 0x1300, bind="STB_GLOBAL"),
        _sym("ifunc_impl", 0x1400, typ="STT_GNU_IFUNC", bind="STB_GLOBAL"),
    ]
    fns = f1.build_gt_functions(syms)
    assert [f["addr"] for f in fns] == ["0x1000", "0x1100", "0x1200", "0x1300", "0x1400"]
    assert fns[0]["names"] == ["main", "main_alias"] and fns[0]["bind"] == "GLOBAL"
    assert fns[1]["names"] == ["helper.part.0"] and fns[1]["bind"] == "LOCAL"
    assert [f["crt"] for f in fns] == [False, False, True, True, False]


def test_extract_gt_rejects_mismatched_or_unstripped(monkeypatch, tmp_path):
    info = {
        "dbg": {"build_id": "aa", "elf_type": "ET_DYN", "machine": "EM_AARCH64", "entry": 0x1000,
                "exec_sections": [], "has_symtab": True, "debug_sections": [".debug_info"],
                "dynsym_funcs": {}},
        "bin": {"build_id": "aa", "elf_type": "ET_DYN", "machine": "EM_AARCH64", "entry": 0x1000,
                "exec_sections": [{"name": ".text", "start": 0x1000, "end": 0x2000}],
                "has_symtab": False, "debug_sections": [], "dynsym_funcs": {0x1100: "_obstack_free"}},
    }
    monkeypatch.setattr(f1, "read_elf_info", lambda p: info["dbg" if p.name.endswith(".debug") else "bin"])
    monkeypatch.setattr(f1, "read_function_symbols", lambda p: [
        _sym("main", 0x1000, bind="STB_GLOBAL"), _sym("_obstack_free", 0x1100, bind="STB_GLOBAL")])
    monkeypatch.setattr(f1, "sha256_file", lambda p: "f" * 64)
    dbg, stp = tmp_path / "x.debug", tmp_path / "x"
    gt = f1.extract_gt(dbg, stp, corpus="c", binary="x")
    assert gt["counts"]["functions"] == 2 and gt["build_id"] == "aa"
    assert [f["exported"] for f in gt["functions"]] == [False, True]
    assert gt["counts"]["scored"] == 1 and gt["counts"]["exported"] == 1
    info["bin"] = dict(info["bin"], build_id="bb")
    with pytest.raises(ValueError, match="BuildID"):
        f1.extract_gt(dbg, stp)
    info["bin"] = dict(info["bin"], build_id="aa", has_symtab=True)
    with pytest.raises(ValueError, match="stripped"):
        f1.extract_gt(dbg, stp)


# Yükleyiciler + toplama ---------------------------------------------------

def test_load_naming_map_formats(tmp_path):
    p = tmp_path / "nm.json"
    p.write_text(json.dumps({"global": {"FUN_1": "a"}, "per_function": {"FUN_1": {"param_1": "x"}}}))
    assert f1.load_naming_map(p) == {"FUN_1": "a"}
    p.write_text(json.dumps({"mappings": {"FUN_1": {"new_name": "a", "source": "c_namer"}}}))
    assert f1.load_naming_map(p) == {"FUN_1": "a"}
    p.write_text(json.dumps({"FUN_1": "a", "meta": 3}))
    assert f1.load_naming_map(p) == {"FUN_1": "a"}


def test_aggregate_micro_and_macro():
    def res(tp, fp, n):
        return {"strict": f1._prf(tp, fp, n), "lenient": f1._prf(tp, fp, n),
                "gt": {"scored": n}, "detected": {"code": n}, "coverage": {"gt_in_detected": n}}
    agg = f1.aggregate([res(1, 0, 2), res(9, 1, 10)])
    assert agg["strict"]["micro"]["tp"] == 10 and agg["strict"]["micro"]["fn"] == 2
    assert agg["strict"]["micro"]["recall"] == round(10 / 12, 4)
    assert agg["strict"]["macro"]["recall"] == round((0.5 + 0.9) / 2, 4)


def test_legacy_bridge_runs(synthetic, tmp_path):
    gt, ghidra, naming = synthetic
    p = tmp_path / "naming_map.json"
    p.write_text(json.dumps({"global": naming, "per_function": {}}))
    leg = f1.legacy_metrics(gt, ghidra, p, None)
    # eski SKIP önekleri _start/frame_dummy'yi atar -> 7 sembol
    assert leg["gt_symbols"] == 7
    assert 0.0 <= leg["f1"] <= 1.0


def test_ab_sign_test_p_values():
    # measure.py compare: eşleştirilmiş işaret testi (kazanılan vs kaybedilen TP).
    mpath = _PATH.parent / "measure.py"
    spec = importlib.util.spec_from_file_location("measure_under_test", mpath)
    measure = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = measure
    spec.loader.exec_module(measure)
    assert measure.sign_test_p(0, 0) == 1.0
    assert measure.sign_test_p(3, 3) == 1.0
    assert measure.sign_test_p(5, 0) == 2 / 32
    assert measure.sign_test_p(10, 2) == 2 * (1 + 12 + 66) / 4096
