"""P05 kalem 1 (MUH-01, MUH-11): anlamsal parametre adlandırıcısının tek ad kapısı.

Kapı: eşik + ad geçerliliği (``name_validity`` yerel ad kuralı) + Ghidra ad biçimi + çakışma eki +
köken kaydı. Yayılım yalnız çağıranın kendi değişkeni olan düz tanımlayıcıdan ad verir; argümanlar
ayraç dengeli ayrıştırılır.
"""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

from karadul.config import Config
from karadul.pipeline.context import StepContext
from karadul.pipeline.steps.semantic_naming import SemanticNamingStep
from karadul.reconstruction.engineering.semantic_namer import (
    PARAM_PROVENANCE_SECTION,
    SemanticName,
    SemanticParameterNamer,
    _declared_variables,
    _gate_name_reason,
    _sanitize_c_name,
    _split_call_args,
)


def _sn(orig: str, name: str, func: str, conf: float, source: str = "type_heuristic") -> SemanticName:
    return SemanticName(
        original_name=orig, semantic_name=name, function_name=func, confidence=conf,
        source=source, reason="test", domain="generic",
    )


def _namer(codes: dict[str, str] | None = None) -> SemanticParameterNamer:
    namer = SemanticParameterNamer(Config())
    namer._func_codes = dict(codes or {})
    return namer


# ---------------------------------------------------------------------------
# Süzgeç ve argüman ayrıştırma
# ---------------------------------------------------------------------------

def test_sanitize_rakamla_baslayan_ad_bos():
    assert _sanitize_c_name("0xffffffffffffffff") == ""
    assert _sanitize_c_name("10") == ""
    assert _sanitize_c_name("0x1b6") == ""
    assert _sanitize_c_name("buf_9") == "buf_9"


def test_kapi_ad_nedenleri():
    assert _gate_name_reason("0xffffffffffffffff") == "invalid_c_identifier"
    assert _gate_name_reason("") == "invalid_c_identifier"
    assert _gate_name_reason("long") == "invalid_c_keyword"
    assert _gate_name_reason("double") == "invalid_c_keyword"
    assert _gate_name_reason("return") == "invalid_c_keyword"
    assert _gate_name_reason("uint64_t") == "invalid_type_name"
    assert _gate_name_reason("uint8_t") == "invalid_type_name"
    assert _gate_name_reason("undefined8") == "invalid_type_name"
    assert _gate_name_reason("DAT_00130770") == "ghidra_generated_name"
    assert _gate_name_reason("PTR_DAT_00130770") == "ghidra_generated_name"
    assert _gate_name_reason("FUN_00105cd0") == "ghidra_generated_name"
    assert _gate_name_reason("local_100") == "ghidra_generated_name"
    assert _gate_name_reason("uVar1") == "ghidra_generated_name"
    assert _gate_name_reason("auStack_858") == "ghidra_generated_name"
    assert _gate_name_reason("count") is None
    assert _gate_name_reason("buf_9") is None
    assert _gate_name_reason("data_ptr") is None


def test_arguman_ayristirma_ayrac_dengeli():
    code = 'x = f(a,(uint64_t)b,g(c,d),"x,)",\'(\',arr[i,j]);'
    args = _split_call_args(code, code.index("("))
    assert args == ["a", "(uint64_t)b", "g(c,d)", '"x,)"', "'('", "arr[i,j]"]
    assert _split_call_args("f()", 1) == []
    assert _split_call_args("f(a, b", 1) is None


def test_bildirilen_degiskenler():
    code = (
        "void FUN_00101000(long len_5,char *buf_9)\n\n{\n"
        "  long cnt;\n  undefined1 auStack_858 [2048];\n  struct stat st_1;\n"
        "  cnt = 0;\n  return;\n}\n"
    )
    assert _declared_variables(code) == {"len_5", "buf_9", "cnt", "auStack_858", "st_1"}


# ---------------------------------------------------------------------------
# Kapı: _resolve_conflicts
# ---------------------------------------------------------------------------

def test_gecersiz_aday_reddedilir_siradaki_aday_kazanir():
    namer = _namer({"f": "int f(long param_1)\n{\n  return 0;\n}"})
    namer._functions = {"f": {"params": [{"name": "param_1", "type": "long", "position": 0}]}}
    cands = [
        _sn("param_1", "long", "f", 0.90, "call_graph_propagation"),
        _sn("param_1", "uint64_t", "f", 0.85, "call_graph_propagation"),
        _sn("param_1", "DAT_00130770", "f", 0.80, "call_graph_propagation"),
        _sn("param_1", "0xff", "f", 0.70, "call_graph_propagation"),
        _sn("param_1", "count", "f", 0.50),
    ]
    won = namer._resolve_conflicts(cands)
    assert [(w.original_name, w.semantic_name) for w in won] == [("param_1", "count")]
    prov = namer.provenance_section()
    assert prov["rejected"] == {"call_graph_propagation": {
        "invalid_c_keyword": 1, "invalid_type_name": 1, "ghidra_generated_name": 1,
        "invalid_c_identifier": 1,
    }}
    assert prov["accepted"] == [{
        "function": "f", "param": "param_1", "name": "count", "source": "type_heuristic",
        "confidence": 0.50, "reason": "test",
    }]


def test_hicbir_aday_gecmezse_parametre_adsiz():
    namer = _namer({"f": "int f(long param_1)\n{\n  return 0;\n}"})
    won = namer._resolve_conflicts([
        _sn("param_1", "uint64_t", "f", 0.9, "call_graph_propagation"),
        _sn("param_1", "long", "f", 0.5),
    ])
    assert won == []
    assert namer.provenance_section()["unnamed"] == {"call_graph_propagation": 1}


def test_esik_altindaki_aday_verilmez():
    namer = _namer({"f": "int f(long param_1)\n{\n  return 0;\n}"})
    assert namer._min_confidence == Config().min_confidence.c_namer_apply
    namer._min_confidence = 0.6
    won = namer._resolve_conflicts([_sn("param_1", "count", "f", 0.55)])
    assert won == []
    assert namer.provenance_section()["rejected"] == {
        "type_heuristic": {"below_min_confidence": 1},
    }


def test_govdedeki_ad_ile_cakisma_ek_alir():
    """Gövdede ``count`` adlı bir yerel varken parametre ``count`` olursa iki değişken tek ada
    çöker; ad ``count_2`` olmalı ve köken kaydı önerilen adı taşımalı."""
    code = "int f(int param_1)\n{\n  int count;\n  count = param_1 + 1;\n  return count;\n}"
    namer = _namer({"f": code})
    won = namer._resolve_conflicts([_sn("param_1", "count", "f", 0.55)])
    assert [w.semantic_name for w in won] == ["count_2"]
    rec = namer.provenance_section()["accepted"][0]
    assert rec["name"] == "count_2" and rec["proposed_name"] == "count"
    out = namer._apply_names_to_code(code, won)
    assert "int count;" in out and "count = count_2 + 1;" in out


def test_ekli_ad_ghidra_bicimindeyse_siradaki_aday():
    """``src`` çakışınca ``src_2`` olur; bu Ghidra'nın kendi ad biçimidir, verilmez
    (yeniden oynatmada redis'te 4 ad). Sıradaki geçerli aday kazanır."""
    code = "int f(long param_1,long param_2)\n{\n  long src;\n  src = param_1;\n  return 0;\n}"
    namer = _namer({"f": code})
    won = namer._resolve_conflicts([
        _sn("param_1", "src", "f", 0.65, "call_context"),
        _sn("param_1", "data_ptr", "f", 0.50),
    ])
    assert [w.semantic_name for w in won] == ["data_ptr"]
    assert namer.provenance_section()["rejected"] == {
        "call_context": {"ghidra_generated_name": 1},
    }


def test_govdede_cagrilan_fonksiyon_adi_ile_cakisma():
    code = "int f(int param_1)\n{\n  return fcntl(param_1,0);\n}"
    namer = _namer({"f": code})
    won = namer._resolve_conflicts([_sn("param_1", "fcntl", "f", 0.55)])
    assert [w.semantic_name for w in won] == ["fcntl_2"]


def test_dizgi_ve_yorumdaki_ad_cakisma_sayilmaz():
    code = 'int f(int param_1)\n{\n  /* count */\n  puts("count");\n  return param_1;\n}'
    namer = _namer({"f": code})
    won = namer._resolve_conflicts([_sn("param_1", "count", "f", 0.55)])
    assert [w.semantic_name for w in won] == ["count"]


# ---------------------------------------------------------------------------
# Yayılım (MUH-01)
# ---------------------------------------------------------------------------

CALLER = (
    "void FUN_00101000(long len_5,char *buf_9)\n\n{\n"
    "  long cnt;\n  long lVar1;\n"
    "  cnt = 0;\n"
    "  FUN_00102000(buf_9,(uint64_t)len_5,0xffffffffffffffff,cnt != 0,"
    '"OK: %lld keys\\n",&cnt,DAT_00130770,FUN_00103000(len_5,cnt),cnt,lVar1,_stdout);\n'
    "  return;\n}\n"
)
CALLEE = (
    "void FUN_00102000(long param_1,long param_2,long param_3,long param_4,long param_5,"
    "long param_6,long param_7,long param_8,long param_9,long param_10,long param_11)\n\n{\n"
    "  FUN_00104000(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,"
    "param_10,param_11);\n  return;\n}\n"
)


def _yayilim_namer() -> SemanticParameterNamer:
    namer = _namer({"FUN_00101000": CALLER, "FUN_00102000": CALLEE})
    namer._reverse_graph = {"FUN_00102000": ["FUN_00101000"]}
    return namer


def test_yayilim_yalniz_cagiranin_degiskeninden():
    namer = _yayilim_namer()
    params = namer._get_function_params("FUN_00102000")
    got = {sn.original_name: sn.semantic_name
           for sn in namer._propagate_from_callers("FUN_00102000", params, {})}
    # param_1 <- buf_9 (çağıranın parametresi), param_9 <- cnt (iç içe çağrıdan sonra doğru konum)
    assert got == {"param_1": "buf_9", "param_9": "cnt"}


def test_rapordaki_birim_ornegi_ad_uretmez():
    # Çağıran FUN_ adlı: CALLER_NAME_HINTS'in iki yönlü alt dizgi kuralı (kapsam dışı; P05.md)
    # kısa adlı çağıranda ("g" ⊂ "assembleglobal") ipucu verir; burada sınanan yayılım.
    caller = (
        "void FUN_00109000(long a,long b,long c)\n{\n  FUN_x(a,(uint64_t)b,0xff,c != 0);\n"
        "  return;\n}\n"
    )
    callee = "void FUN_x(long param_1,long param_2,long param_3,long param_4)\n{\n  return;\n}\n"
    namer = _namer({"FUN_00109000": caller, "FUN_x": callee})
    namer._reverse_graph = {"FUN_x": ["FUN_00109000"]}
    params = namer._get_function_params("FUN_x")
    assert namer._propagate_from_callers("FUN_x", params, {}) == []


def _yaz_girdi(tmp_path: Path, files: dict[str, str]) -> tuple[Path, Path, Path]:
    dec = tmp_path / "decompiled"
    dec.mkdir()
    funcs, nodes = [], []
    for i, (name, code) in enumerate(files.items()):
        (dec / f"{name}.c").write_text(code, encoding="utf-8")
        addr = f"0x{0x101000 + i * 0x1000:x}"
        funcs.append({"name": name, "address": addr})
        nodes.append({"name": name, "address": addr})
    fj = tmp_path / "functions.json"
    fj.write_text(json.dumps({"functions": funcs}), encoding="utf-8")
    addr = {n["name"]: n["address"] for n in nodes}
    cg = tmp_path / "call_graph.json"
    cg.write_text(json.dumps({"nodes": nodes, "edges": [
        {"from": addr["FUN_00101000"], "to": addr["FUN_00102000"]},
    ]}), encoding="utf-8")
    return dec, fj, cg


def test_rename_ucta_uca_kusurlu_ad_yok_ve_koken_tam(tmp_path: Path):
    dec, fj, cg = _yaz_girdi(tmp_path, {"FUN_00101000": CALLER, "FUN_00102000": CALLEE})
    out = tmp_path / "rec" / "semantic_named"
    namer = SemanticParameterNamer(Config())
    res = namer.rename(dec, fj, cg, out)
    assert res.success and res.total_renamed > 0
    for sn in res.names:
        assert _gate_name_reason(sn.semantic_name) is None, sn
    by = {(sn.function_name, sn.original_name): sn.semantic_name for sn in res.names}
    assert by[("FUN_00102000", "param_1")] == "buf_9"
    assert by[("FUN_00102000", "param_9")] == "cnt"
    text = (out / "FUN_00102000.c").read_text(encoding="utf-8")
    for bad in ("uint64_t /*", "0xffffffffffffffff /*", "DAT_00130770 /*", "OK_lld", "long /*"):
        assert bad not in text
    # Köken: kabul edilen her ad kanalı ve güveniyle
    prov = res.provenance
    assert len(prov["accepted"]) == res.total_renamed
    assert {(r["function"], r["param"]) for r in prov["accepted"]} == set(by)
    assert all(r["source"] and isinstance(r["confidence"], float) for r in prov["accepted"])
    pm = json.loads((out.parent / "param_naming_map.json").read_text(encoding="utf-8"))
    assert pm["gate"]["min_confidence"] == Config().min_confidence.c_namer_apply
    n = 0
    for fname, f in pm["functions"].items():
        assert set(f["names"]) == set(f["renames"])
        for old, d in f["names"].items():
            n += 1
            assert d["name"] == f["renames"][old]
            assert {"source", "confidence", "reason"} <= set(d)
    assert n == res.total_renamed


# ---------------------------------------------------------------------------
# Adım: köken kaydına yazım
# ---------------------------------------------------------------------------

def _koken(d: Path, extra: dict | None = None) -> None:
    d.mkdir(parents=True, exist_ok=True)
    data = {"schema": "karadul.naming_provenance", "global": {"FUN_1": {"name": "x"}}}
    data.update(extra or {})
    (d / "naming_provenance.json").write_text(json.dumps(data), encoding="utf-8")


def test_adim_son_yinelemenin_kaydina_yazar(tmp_path: Path):
    rec = tmp_path / "reconstructed"
    _koken(rec / "src")
    _koken(rec / "src_iter1")
    _koken(rec / "src_iter2")
    (rec / "src_iter10").mkdir()  # kaydı olmayan dizin atlanır
    section = {"accepted": [{"function": "f", "param": "param_1", "name": "n"}]}
    durum = SemanticNamingStep._write_provenance(rec, section)
    assert durum == "yazildi:src_iter2"
    data = json.loads((rec / "src_iter2" / "naming_provenance.json").read_text(encoding="utf-8"))
    assert data[PARAM_PROVENANCE_SECTION] == section
    assert data["global"] == {"FUN_1": {"name": "x"}}
    for other in ("src", "src_iter1"):
        d = json.loads((rec / other / "naming_provenance.json").read_text(encoding="utf-8"))
        assert PARAM_PROVENANCE_SECTION not in d


def test_adim_koken_kaydi_yoksa_durum_yazar(tmp_path: Path):
    rec = tmp_path / "reconstructed"
    rec.mkdir()
    assert SemanticNamingStep._write_provenance(rec, {"accepted": []}) == "koken_kaydi_yok"


def test_adim_calisinca_koken_bolumu_ve_sayac(tmp_path: Path):
    dec, fj, cg = _yaz_girdi(tmp_path, {"FUN_00101000": CALLER, "FUN_00102000": CALLEE})
    rec = tmp_path / "reconstructed"
    _koken(rec / "src")
    pc = MagicMock()
    pc.workspace.get_stage_dir = MagicMock(return_value=rec)
    pc.config = Config()
    ctx = StepContext(pipeline_context=pc)
    ctx._write_artifacts({
        "decompiled_dir": dec, "functions_json_path": fj, "call_graph_json_path": cg,
        "sig_matches": None, "eng_result": SimpleNamespace(success=True, algorithms=[]),
        "algo_result": None,
    })
    out = SemanticNamingStep().run(ctx)
    assert out["params_renamed"] > 0
    assert ctx.stats["semantic_naming_provenance"] == "yazildi:src"
    data = json.loads((rec / "src" / "naming_provenance.json").read_text(encoding="utf-8"))
    sec = data[PARAM_PROVENANCE_SECTION]
    assert len(sec["accepted"]) == out["params_renamed"]
    assert sec["min_confidence"] == Config().min_confidence.c_namer_apply
