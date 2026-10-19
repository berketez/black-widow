"""scripts/measurement/macho_f1.py — Mac (Mach-O) puanlayıcısının birim testleri.

Sentetik ``nm`` metni + Ghidra fonksiyon listesi + naming_map ile kilitlenenler:
  (a) GT: yalnız T/t, ``__mh_execute_header`` hariç, aynı adresteki adlar tek kayıt;
      çok mimarili nm çıktısı reddedilir; nm mutlak yoldan çağrılır;
  (b) popülasyon: thunk ve Ghidra'nın kendisinin adlandırdığı fonksiyonlar dışarıda;
  (c) ``.cold.N`` / ``OUTLINED_FUNCTION_N`` ayrı sınıf (``sinif``);
  (d) sonek indirgeme (``.cold``, ``.llvm.N``, ``.__uniq.N``, ``$VARYANT``);
  (e) satır şeması: 15 Ekim anahtarları (addr, gt, pred, status, lenient) aynen;
  (f) eski özet anahtarları 15 Ekim puanlayıcısının tanımıyla aynı sayıyı verir
      (aşağıdaki ``_legacy_summary`` o betiğin çekirdeğinin kopyasıdır).
"""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

import pytest

_DIR = Path(__file__).resolve().parents[1] / "scripts" / "measurement"
if str(_DIR) not in sys.path:
    sys.path.insert(0, str(_DIR))
_spec = importlib.util.spec_from_file_location("macho_f1_under_test", _DIR / "macho_f1.py")
mf = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = mf
_spec.loader.exec_module(mf)

import function_f1 as f1  # noqa: E402

OLD_ROW_KEYS = ["addr", "gt", "pred", "status", "lenient"]
OLD_SUMMARY_KEYS = ["binary", "gt_functions", "ghidra_known_from_exports", "undetected",
                    "population_needing_names", "named_by_karadul", "tp", "wrong", "unnamed",
                    "precision", "recall", "lenient_tp", "named_outside_gt", "f1"]

NM_TEXT = """\
0000000100000000 T __mh_execute_header
0000000100001000 T _main
0000000100001010 t _parse_args
0000000100001010 t _parse_args_alias
0000000100001040 t _known_by_ghidra
0000000100001080 T _thunked
00000001000010c0 t _vanished
0000000100001100 t _render.cold.1
0000000100001140 t _OUTLINED_FUNCTION_0
0000000100001180 t _server_client_lost
00000001000011c0 t _named_later
0000000100001200 t -[Foo bar:]
0000000100008000 S _some_data
0000000100009000 D _global_var
                 U _malloc
"""


def _gh(addr: int, name: str | None = None, thunk: bool = False) -> dict:
    return {"addr": addr, "name": name or f"FUN_{addr:x}", "is_thunk": thunk, "size": 16}


@pytest.fixture
def scenario():
    gt = mf.parse_nm(NM_TEXT)
    ghidra = [
        _gh(0x100001000, "entry"),                 # main: Ghidra oto-adı (jenerik) -> popülasyonda
        _gh(0x100001010),                          # parse_args
        _gh(0x100001040, "_known_by_ghidra"),      # Ghidra adı biliyor -> dışarıda
        _gh(0x100001080, "thunk_FUN_1000010c0", thunk=True),  # GT fonksiyonu Ghidra'da thunk
        _gh(0x100001100),                          # render.cold.1
        _gh(0x100001140),                          # OUTLINED_FUNCTION_0
        _gh(0x100001180),                          # server_client_lost
        _gh(0x1000011c0),                          # named_later (isimsiz)
        _gh(0x100001200),                          # ObjC metodu
        _gh(0x100002000),                          # GT dışı, isimli
    ]
    naming = {
        "FUN_100001000": "main",                   # 'entry' anahtarı yok; FUN_<adres> anahtarı
        "FUN_100001010": "parse_args",
        "FUN_100001100": "render",                 # parça ebeveyn adıyla -> tp (cold sınıfı)
        "FUN_100001140": "render_helper",          # outlined -> wrong
        "FUN_100001180": "client_lost",            # strict yanlış, lenient tutar (semantic)
        "FUN_1000011c0": "leaf_11c0",              # kendi adresini taşıyan ad -> jenerik
        "FUN_100002000": "outside_name",           # GT dışı
    }
    return gt, ghidra, naming


def _legacy_summary(gt, gfuncs, nmap):
    """15 Ekim ``score_macho.py`` çekirdeği (karşılaştırma kâhini; bilerek kopyalandı)."""
    by_addr = {}
    for fn in gfuncs:
        if fn["is_thunk"]:
            continue
        by_addr.setdefault(fn["addr"], fn)
    stats = defaultdict(int)
    rows = []
    for addr, names in sorted(gt.items()):
        fn = by_addr.get(addr)
        if fn is None:
            stats["undetected"] += 1
            continue
        if not f1.is_generic_name(fn["name"], [addr]):
            stats["ghidra_known"] += 1
            continue
        stats["population"] += 1
        pred = f1.lookup_prediction(nmap, fn)
        if pred is None or f1.is_generic_name(pred, [addr]):
            status = "unnamed"
        elif f1.match_strict(pred, names):
            status = "tp"
        else:
            status = "wrong"
        stats[status] += 1
        rows.append({"addr": hex(addr), "gt": names, "pred": pred, "status": status,
                     "lenient": bool(pred) and status != "unnamed" and f1.match_lenient(pred, names)})
    outside = 0
    for fn in by_addr.values():
        if fn["addr"] in set(gt):
            continue
        pred = f1.lookup_prediction(nmap, fn)
        if pred and not f1.is_generic_name(pred, [fn["addr"]]):
            outside += 1
    tp, wr, pop = stats["tp"], stats["wrong"], stats["population"]
    named = tp + wr
    res = {"binary": "x", "gt_functions": len(gt), "ghidra_known_from_exports": stats["ghidra_known"],
           "undetected": stats["undetected"], "population_needing_names": pop,
           "named_by_karadul": named, "tp": tp, "wrong": wr, "unnamed": stats["unnamed"],
           "precision": round(tp / named, 4) if named else None,
           "recall": round(tp / pop, 4) if pop else None,
           "lenient_tp": sum(1 for r in rows if r["lenient"]), "named_outside_gt": outside}
    p, r = res["precision"] or 0, res["recall"] or 0
    res["f1"] = round(2 * p * r / (p + r), 4) if (p + r) else 0.0
    return res, rows


# ---------------------------------------------------------------------------
# GT
# ---------------------------------------------------------------------------

def test_parse_nm_keeps_only_text_functions_and_merges_aliases():
    gt = mf.parse_nm(NM_TEXT)
    assert 0x100000000 not in gt                      # __mh_execute_header
    assert gt[0x100001010] == ["_parse_args", "_parse_args_alias"]
    assert gt[0x100001200] == ["-[Foo bar:]"]         # boşluklu ad bütün kalır
    assert 0x100008000 not in gt and 0x100009000 not in gt  # S/D veri sembolleri
    assert len(gt) == 10


def test_parse_nm_rejects_fat_binary_output():
    text = "\nx (for architecture arm64):\n0000000100001000 T _main\n"
    with pytest.raises(ValueError, match="çok mimarili"):
        mf.parse_nm(text)


def test_nm_called_by_absolute_apple_path(monkeypatch):
    assert mf.NM_PATH == "/usr/bin/nm"
    seen = []

    def fake_run(cmd, **kw):
        seen.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, stdout=NM_TEXT, stderr="")

    monkeypatch.setattr(mf.subprocess, "run", fake_run)
    assert mf.gt_from_binary(Path("/x/htop")) == mf.parse_nm(NM_TEXT)
    assert seen == [["/usr/bin/nm", "-n", "-U", "/x/htop"]]
    with pytest.raises(ValueError, match="mutlak"):
        mf.run_nm(Path("/x/htop"), nm_path="nm")
    assert len(seen) == 1                             # göreli yolla çağrı yapılmadı


# ---------------------------------------------------------------------------
# Sınıflar ve sonek kuralları
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("names, cls", [
    (["_grid_check_is_clear.cold.1"], "cold"),
    (["_grid_check_is_clear.cold.10"], "cold"),
    (["_foo.cold"], "cold"),
    (["_OUTLINED_FUNCTION_0"], "outlined"),
    (["OUTLINED_FUNCTION_12"], "outlined"),
    (["_grid_create"], "program"),
    (["_cold_start"], "program"),
    (["_foo.cold.1", "_foo_alias"], "program"),       # karışık takma ad: program
    (["_my_OUTLINED_FUNCTION_0"], "program"),
])
def test_fragment_class(names, cls):
    assert mf.fragment_class(names) == cls


@pytest.mark.parametrize("name, base", [
    ("_grid_create.cold.1", "_grid_create"),
    ("_foo.cold", "_foo"),
    ("_foo.llvm.1234567890123", "_foo"),
    ("_foo.__uniq.98765", "_foo"),
    ("_stat$INODE64", "_stat"),
    ("_close$NOCANCEL$UNIX2003", "_close"),
    ("_foo.llvm.12.cold.1", "_foo"),
    ("_$s4main3fooyyF", "_$s4main3fooyyF"),           # Swift adı: $ baştaki bir sonek değil
    ("$foo", "$foo"),
    ("_plain_name", "_plain_name"),
    ("_v2.cold.3", "_v2"),
])
def test_reduce_suffixes(name, base):
    assert mf.reduce_suffixes(name) == base


def test_suffix_rules_used_in_matching():
    a, b, c = 0x100001000, 0x100001100, 0x100001200
    gt = {a: ["_parse_opts.llvm.4242424242"], b: ["_stat_file$INODE64"], c: ["_draw.__uniq.77"]}
    ghidra = [_gh(a), _gh(b), _gh(c)]
    naming = {f"FUN_{a:x}": "parse_opts", f"FUN_{b:x}": "stat_file", f"FUN_{c:x}": "draw_box"}
    res = mf.score(gt, ghidra, naming, binary="t")
    st = {r["addr"]: r["status"] for r in res["rows"]}
    assert st[hex(a)] == "tp"
    assert st[hex(b)] == "tp"
    assert st[hex(c)] == "wrong"                      # temel ad draw ≠ draw_box


# ---------------------------------------------------------------------------
# Popülasyon, durumlar, satır şeması
# ---------------------------------------------------------------------------

def test_population_and_statuses(scenario):
    gt, ghidra, naming = scenario
    res = mf.score(gt, ghidra, naming, binary="x")
    s = res["summary"]
    st = {r["addr"]: (r["status"], r["lenient"], r["sinif"]) for r in res["rows"]}
    assert st[hex(0x100001000)] == ("tp", True, "program")       # entry -> FUN_ anahtarıyla main
    assert st[hex(0x100001010)] == ("tp", True, "program")       # takma adlardan biri yeter
    assert st[hex(0x100001100)] == ("tp", True, "cold")
    assert st[hex(0x100001140)][0::2] == ("wrong", "outlined")
    assert st[hex(0x100001180)] == ("wrong", True, "program")  # lenient (semantic)
    assert st[hex(0x1000011c0)] == ("unnamed", False, "program")  # leaf_11c0 jenerik
    assert st[hex(0x100001200)] == ("unnamed", False, "program")
    assert hex(0x100001040) not in st                            # Ghidra biliyor
    assert hex(0x100001080) not in st and hex(0x1000010c0) not in st
    assert s["ghidra_known_from_exports"] == 1 and s["ghidra_known_names"] == ["_known_by_ghidra"]
    assert s["undetected"] == 2
    assert s["undetected_thunk"] == 1 and s["undetected_missing"] == 1
    assert s["population_needing_names"] == 7
    assert (s["tp"], s["wrong"], s["unnamed"]) == (3, 2, 2)
    assert s["named_outside_gt"] == 1
    assert s["gt_names"] == 11


def test_class_blocks_separate_fragments(scenario):
    gt, ghidra, naming = scenario
    sn = mf.score(gt, ghidra, naming, binary="x")["summary"]["siniflar"]
    assert set(sn) == {"program", "cold", "outlined"}
    p = sn["program"]
    assert (p["population"], p["named"], p["tp"], p["wrong"], p["unnamed"]) == (5, 3, 2, 1, 2)
    assert p["precision"] == round(2 / 3, 4) and p["recall"] == round(2 / 5, 4)
    assert p["lenient_tp"] == 3                       # 2 tp + 1 lenient yanlış
    assert (sn["cold"]["population"], sn["cold"]["tp"]) == (1, 1)
    assert (sn["outlined"]["population"], sn["outlined"]["wrong"]) == (1, 1)


def test_rows_keep_legacy_schema(scenario):
    gt, ghidra, naming = scenario
    res = mf.score(gt, ghidra, naming, binary="x")
    assert set(res) == {"summary", "rows"}
    for r in res["rows"]:
        assert list(r)[:5] == OLD_ROW_KEYS
        assert r["addr"] == hex(int(r["addr"], 16))
        assert isinstance(r["gt"], list)
        assert r["sinif"] in mf.CLASS_ORDER
    assert [r["addr"] for r in res["rows"]] == sorted(
        (r["addr"] for r in res["rows"]), key=lambda a: int(a, 16))


def test_legacy_summary_keys_match_legacy_scorer(scenario):
    gt, ghidra, naming = scenario
    res = mf.score(gt, ghidra, naming, binary="x")
    legacy, legacy_rows = _legacy_summary(gt, ghidra, naming)
    assert list(res["summary"])[:len(OLD_SUMMARY_KEYS)] == OLD_SUMMARY_KEYS
    assert {k: res["summary"][k] for k in OLD_SUMMARY_KEYS} == legacy
    assert [{k: r[k] for k in OLD_ROW_KEYS} for r in res["rows"]] == legacy_rows


def test_precision_none_when_nothing_named():
    a = 0x100001000
    s = mf.score({a: ["_foo"]}, [_gh(a)], {}, binary="z")["summary"]
    assert s["precision"] is None and s["recall"] == 0.0 and s["f1"] == 0.0
    assert s["siniflar"]["program"]["precision_ci95"] is None


def test_ghidra_known_threshold_warns():
    gt = {0x100001000 + 0x10 * i: [f"_f{i}"] for i in range(10)}
    ghidra = [_gh(a, names[0]) for a, names in gt.items()]       # hepsini Ghidra biliyor
    s = mf.score(gt, ghidra, {}, binary="leak")["summary"]
    assert s["ghidra_known_from_exports"] == 10 and s["population_needing_names"] == 0
    assert any("kendisi adlandırdı" in w for w in s["warnings"])
    clean = mf.score(gt, [_gh(a) for a in gt], {}, binary="ok")["summary"]
    assert not any("kendisi adlandırdı" in w for w in clean["warnings"])


def test_detection_ratio_warns_on_address_mismatch():
    gt = {0x100001000 + 0x10 * i: [f"_f{i}"] for i in range(10)}
    shifted = [_gh(a + 0x4000) for a in gt]                      # yanlış görüntü tabanı
    s = mf.score(gt, shifted, {}, binary="s")["summary"]
    assert s["gt_detection_ratio"] == 0.0
    assert any("adres eşlemesi" in w for w in s["warnings"])


def test_wilson_interval_known_values():
    assert mf.wilson_interval(0, 0) is None
    lo, hi = mf.wilson_interval(5, 10)
    assert (lo, hi) == (0.2366, 0.7634)
    lo, hi = mf.wilson_interval(0, 10)
    assert lo == 0.0 and hi == pytest.approx(0.2775, abs=1e-4)


# ---------------------------------------------------------------------------
# Koşu dizini
# ---------------------------------------------------------------------------

def _make_run(root: Path, ghidra: list[dict], naming: dict) -> Path:
    run = root / "run"
    ts = run / "ws" / "workspaces" / "x" / "20261019_000000"
    (ts / "static").mkdir(parents=True)
    (ts / "reconstructed" / "src").mkdir(parents=True)
    funcs = [{"name": g["name"], "address": f"{g['addr']:x}", "is_thunk": g["is_thunk"],
              "size": g["size"]} for g in ghidra]
    (ts / "static" / "ghidra_functions.json").write_text(json.dumps({"functions": funcs}))
    (ts / "reconstructed" / "src" / "naming_map.json").write_text(
        json.dumps({"global": naming, "per_function": {}}))
    return run


def test_score_run_writes_two_key_file(tmp_path, scenario):
    gt, ghidra, naming = scenario
    run = _make_run(tmp_path, ghidra, naming)
    gt_doc = {"binary": "x", "functions": [{"addr": hex(a), "names": n} for a, n in gt.items()]}
    gpath = tmp_path / "x.gt.json"
    gpath.write_text(json.dumps(gt_doc))
    res = mf.score_run(run, gt_path=gpath)
    on_disk = json.loads((run / mf.SCORE_FILE_NAME).read_text(encoding="utf-8"))
    assert set(on_disk) == {"summary", "rows"}
    assert on_disk["summary"]["tp"] == res["summary"]["tp"] == 3
    other = tmp_path / "elsewhere" / "score.json"
    (run / mf.SCORE_FILE_NAME).unlink()
    mf.score_run(run, gt_path=gpath, out=other)
    assert other.is_file() and not (run / mf.SCORE_FILE_NAME).exists()
    with pytest.raises(ValueError):
        mf.score_run(run)


# ---------------------------------------------------------------------------
# ÖL-3: erişim sınıfları, fixup ayrıştırma, kod taraması, talimat ağırlığı
# ---------------------------------------------------------------------------

FIXUPS_TEXT = """\
/x/demo [arm64]:
    -fixups:
        segment         section          address             type   target
        __DATA_CONST    __got            0x100028000           bind  libSystem/_free
        __DATA_CONST    __const          0x100028648         rebase  0x100001040
        __DATA_CONST    __const          0x100028650         rebase  0x100001040
        __DATA          __data           0x10002C000         rebase  0x100008000
        __DATA_CONST    __const          0x100028658         rebase  0x1000010C0
"""

DISASM = """\
/x/demo:\tfile format mach-o arm64

Disassembly of section __TEXT,__text:

0000000100001000 <__text>:
100001000:     \tadrp\tx1, 0x100001000 <__text>
100001004:     \tadd\tx1, x1, #0x80
100001008:     \tbl\t0x100001100 <__text+0x100>
10000100c:     \tadrp\tx2, 0x100001000 <__text>
100001010:     \tmov\tx2, #0x0               ; =0
100001014:     \tadd\tx0, x2, #0x40
100001018:     \tadr\tx3, 0x1000011c0 <__text+0x1c0>
10000101c:     \tb\t0x100001180 <__text+0x180>
100001020:     \tadrp\tx8, 0x100001000 <__text>
100001024:     \tldr\tx8, [x8, #0x40]
100001028:     \tb\t0x100001000 <__text>
10000102c:     \tadrp\tx5, 0x100001000 <__text>
100001030:     \tmov\tw5, #0x1               ; =1
100001034:     \tadd\tx0, x5, #0x40
"""
STARTS = {0x100001000, 0x100001040, 0x100001080, 0x100001100, 0x100001180, 0x1000011c0}


def test_parse_dyld_fixups_rebase_and_bind():
    fx = mf.parse_dyld_fixups(FIXUPS_TEXT)
    assert len(fx) == 5
    assert fx[0]["kind"] == "bind" and fx[0]["target"] == "libSystem/_free"
    assert fx[1] == {"segment": "__DATA_CONST", "section": "__const", "slot": 0x100028648,
                     "kind": "rebase", "target": 0x100001040}
    assert mf.pointer_targets(fx) == {0x100001040: 2, 0x100008000: 1, 0x1000010C0: 1}
    with pytest.raises(ValueError, match="-fixups"):
        mf.parse_dyld_fixups("dyld_info: unknown option\n")
    with pytest.raises(ValueError, match="çok mimarili"):
        mf.parse_dyld_fixups(FIXUPS_TEXT + "/x/demo [x86_64]:\n    -fixups:\n")


def test_scan_code_refs_address_taken_and_tail_calls():
    refs = mf.scan_code_refs(DISASM, STARTS)
    # adrp+add -> 0x...080; adr -> 0x...1c0. mov x2 / mov w5 sayfayı siler; ldr adres değil.
    assert refs["address_taken"] == {0x100001080, 0x1000011c0}
    # başka fonksiyona b -> kuyruk çağrısı; kendi başına dönen b sayılmaz; bl çağrıdır
    assert refs["tail_called"] == {0x100001180}


@pytest.mark.parametrize("gap, taken", [(mf.ADRP_PAIR_WINDOW - 1, True), (mf.ADRP_PAIR_WINDOW + 1, False)])
def test_adrp_pair_window(gap, taken):
    lines = ["100002000:     \tadrp\tx9, 0x100001000 <__text>"]
    lines += [f"{0x100002004 + 4 * i:x}:     \tnop" for i in range(gap)]
    lines.append(f"{0x100002004 + 4 * gap:x}:     \tadd\tx0, x9, #0x40")
    refs = mf.scan_code_refs("\n".join(lines), STARTS)
    assert (0x100001040 in refs["address_taken"]) is taken


def test_access_class_precedence_and_self_edges():
    a, b, c, d, e = (0x100001000 + 0x40 * i for i in range(5))
    callers = {a: {b}, b: set(), c: set(), d: {d}, e: {a}}
    pointers = {c, d, e}
    assert mf.access_class(a, callers, pointers) == "dogrudan"
    assert mf.access_class(b, callers, pointers) == "referanssiz"
    assert mf.access_class(c, callers, pointers) == "tablo"
    assert mf.access_class(d, callers, pointers) == "tablo"        # yalnız kendini çağırıyor
    assert mf.access_class(e, callers, pointers) == "dogrudan"     # çağıran + işaretçi: doğrudan önce
    assert mf.access_class(0x1, callers, pointers) == "referanssiz"


def test_load_call_graph_drops_self_edges(tmp_path):
    p = tmp_path / "cg.json"
    p.write_text(json.dumps({"nodes": {
        "100001000": {"callers": [{"name": "FUN_100001000", "address": "100001000"},
                                  {"name": "FUN_100002000", "address": "100002000"}]},
        "100002000": {"callers": []}}}))
    assert mf.load_call_graph(p) == {0x100001000: {0x100002000}, 0x100002000: set()}


def _weighted_case():
    a, b, c = 0x100001000, 0x100001200, 0x100001300
    gt = {a: ["_big"], b: ["_mid"], c: ["_tiny"]}
    ghidra = [dict(_gh(a), size=400), dict(_gh(b), size=40), dict(_gh(c), size=4)]
    naming = {f"FUN_{a:x}": "big", f"FUN_{b:x}": "wrong_name"}
    return gt, ghidra, naming


def test_instruction_weighting():
    gt, ghidra, naming = _weighted_case()
    res = mf.score(gt, ghidra, naming, binary="w")
    assert [r["talimat"] for r in res["rows"]] == [100, 10, 1]
    p = res["summary"]["siniflar"]["program"]
    assert (p["coverage"], p["precision"]) == (round(2 / 3, 4), 0.5)
    assert p["talimat"] == {"population": 111, "named": 110, "tp": 100,
                            "coverage": round(110 / 111, 4), "precision": round(100 / 110, 4),
                            "recall": round(100 / 111, 4)}
    none = mf.score(gt, ghidra, naming, binary="w", insn_bytes=None)
    assert none["rows"][0]["talimat"] is None and none["summary"]["siniflar"]["program"]["talimat"] is None


def test_rows_schema_appends_erisim_and_talimat(scenario):
    gt, ghidra, naming = scenario
    callers = {g["addr"]: set() for g in ghidra}
    res = mf.score(gt, ghidra, naming, binary="x", callers=callers, pointers=set())
    for r in res["rows"]:
        assert list(r) == OLD_ROW_KEYS + ["sinif", "erisim", "talimat"]
        assert r["erisim"] in mf.ACCESS_ORDER and r["talimat"] == 4
    plain = mf.score(gt, ghidra, naming, binary="x")
    assert all(r["erisim"] is None for r in plain["rows"])
    assert plain["summary"]["erisim_siniflari"] is None


def test_access_blocks_and_diagnostics(scenario):
    gt, ghidra, naming = scenario
    callers = {g["addr"]: set() for g in ghidra}
    callers[0x100001000] = {0x100001010}                       # main çağrılıyor
    pointers = {0x100001180}                                     # server_client_lost tablodan
    code_refs = {"address_taken": {0x1000011c0}, "tail_called": set()}
    s = mf.score(gt, ghidra, naming, binary="x", callers=callers, pointers=pointers,
                 code_refs=code_refs)["summary"]
    acc = s["erisim_siniflari"]
    assert {k: acc[k]["population"] for k in mf.ACCESS_ORDER} == {
        "dogrudan": 1, "tablo": 1, "referanssiz": 3}             # yalnız program sınıfı (5)
    assert acc["dogrudan"]["tp"] == 1 and acc["tablo"]["wrong"] == 1
    assert acc["referanssiz"]["kod_referansi"] == {"adresi_alinan": 1, "kuyruk_cagrisi": 0, "hicbiri": 2}


def test_combine_blocks_sums_counts_and_weights():
    gt, ghidra, naming = _weighted_case()
    b1 = mf.score(gt, ghidra, naming, binary="w")["summary"]["siniflar"]["program"]
    both = mf.combine_blocks([b1, b1])
    assert (both["population"], both["named"], both["tp"]) == (6, 4, 2)
    assert both["talimat"]["population"] == 222 and both["talimat"]["precision"] == b1["talimat"]["precision"]
    assert mf.combine_blocks([b1, dict(b1, talimat=None)])["talimat"] is None


def test_score_run_with_stripped_binary(tmp_path, scenario, monkeypatch):
    gt, ghidra, naming = scenario
    run = _make_run(tmp_path, ghidra, naming)
    static = next(run.glob("ws/workspaces/*/*/static"))
    (static / mf.CALL_GRAPH_FILE).write_text(json.dumps({"nodes": {
        f"{g['addr']:x}": {"callers": [{"address": "100001010"}] if g["addr"] == 0x100001000 else []}
        for g in ghidra}}))
    gpath = tmp_path / "x.gt.json"
    gpath.write_text(json.dumps({"binary": "x", "functions": [{"addr": hex(a), "names": n}
                                                              for a, n in gt.items()]}))
    stripped = tmp_path / "x.bin"
    stripped.write_bytes(b"bin")
    monkeypatch.setattr(mf, "read_fixups", lambda p: FIXUPS_TEXT.replace("0x1000010C0", "0x100001180"))
    monkeypatch.setattr(mf, "read_disassembly", lambda p: "")
    res = mf.score_run(run, gt_path=gpath, stripped=stripped, write=False)
    st = {r["addr"]: r["erisim"] for r in res["rows"]}
    assert st[hex(0x100001000)] == "dogrudan" and st[hex(0x100001180)] == "tablo"
    assert st[hex(0x1000011c0)] == "referanssiz"
    info = res["summary"]["erisim_kaynaklari"]
    assert info["fixups"]["rebase"] == 4 and info["fixups"]["bind"] == 1
    assert info["fixups"]["functions_pointed"] == 2               # 0x100001040 ve 0x100001180
    assert info["fixups"]["rebase_to_function_start"] == 3        # 0x...040 iki yuvadan

    def boom(p):
        raise subprocess.CalledProcessError(1, ["dyld_info"])

    monkeypatch.setattr(mf, "read_fixups", boom)
    res = mf.score_run(run, gt_path=gpath, stripped=stripped, write=False)
    assert all(r["erisim"] is None for r in res["rows"]) and res["summary"]["tp"] == 3
    assert any("erişim sınıfları hesaplanamadı" in w for w in res["summary"]["warnings"])
