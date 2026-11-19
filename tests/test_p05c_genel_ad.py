"""P05c Kalem 1-2 — tip sezgisinin kanıtsız genel adları aday kaydına iner (K-2).

Taban (P05b sonu, DWARF'lı 22 ikili): tip sezgisinin genel adları yalnız tip uyumuna bakıyordu
(``count`` 13 / 2 300 doğru, ``enabled`` 1 / 389, ``value`` 2 / 308, ``byte_buffer`` 0 / 18,
``context`` 0 / 32). Ön kayıt ``docs/arge/2026-11-18_onarim/P05c_on_kayit.md`` §4: şablon adı
ya bir kanıt türüne bağlanır ya da koda yazılmaz, köken kaydının ``candidates`` listesine aday
olarak girer (Ghidra'nın adı kalır).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from karadul.config import Config
from karadul.reconstruction.engineering import semantic_namer as sn
from karadul.reconstruction.engineering.semantic_namer import SemanticParameterNamer

_KOD = """// Address: 00101000
int FUN_00101000(int param_1, uint param_2, void *param_3, void *param_4, code *param_5,
                void *param_6, long param_7, int param_8)
{
  int i;
  if (param_1 == 0) {
    return 1;
  }
  if (!param_1) return 2;
  for (i = 0; i < param_2; i = i + 1) {
    FUN_00102000(i);
  }
  memcpy(param_3, param_4, (size_t)param_2);
  (*param_5)(param_6, 3);
  if (param_7 == 5) {
    return 4;
  }
  return param_8 + param_8 * 3 + FUN_00102000(param_8);
}
"""


@pytest.mark.parametrize("sablon,tip,param,beklenen", [
    ("enabled", "int", "param_1", True),          # yalnız doğruluk sınaması
    ("enabled", "int", "param_8", False),         # aritmetik
    ("enabled", "bool", "param_8", True),         # bildirilen bool
    ("count", "uint", "param_2", True),           # döngü koşulu + memcpy boyutu
    ("count", "long", "param_7", False),          # yalnız sabitle karşılaştırma
    ("byte_buffer", "void *", "param_3", True),   # memcpy tamponu
    ("byte_buffer", "void *", "param_6", False),
    ("byte_buffer", "uchar *", "param_6", True),  # bildirilen bayt işaretçisi
    ("context", "void *", "param_6", True),       # işlev göstericisiyle çağrının argümanı
    ("context", "void *", "param_3", False),
    ("userdata", "void *", "param_6", True),
    ("value", "int", "param_8", False),           # tanımlı kanıt türü yok
    ("status", "int", "param_8", False),
    ("flags", "uint", "param_2", False),          # bit maskesi yok
])
def test_kanit_turleri(sablon: str, tip: str, param: str, beklenen: bool) -> None:
    assert sn._generic_name_evidence(sablon, tip, _KOD, param) is beklenen


def test_kapsam_disi_sablon_none() -> None:
    assert sn._generic_name_evidence("self", "long", _KOD, "param_7") is None
    assert sn._generic_name_evidence("str", "char *", _KOD, "param_7") is None


def test_flags_bit_maskesi() -> None:
    kod = "uint FUN_1(uint param_1)\n{\n  if ((param_1 & 4) != 0) {\n    return 1;\n  }\n" \
          "  return 0;\n}\n"
    assert sn._generic_name_evidence("flags", "uint", kod, "param_1") is True
    kod2 = "uint FUN_1(uint param_1)\n{\n  if (param_1 && FUN_2()) {\n    return 1;\n  }\n" \
           "  return 0;\n}\n"
    assert sn._generic_name_evidence("flags", "uint", kod2, "param_1") is False


def test_dogruluk_sinamasi_karakter_sabiti() -> None:
    kod = "int FUN_1(char param_1)\n{\n  if (param_1 != '\\0') {\n    return 1;\n  }\n" \
          "  return 0;\n}\n"
    assert sn._generic_name_evidence("enabled", "char", kod, "param_1") is True
    kod2 = "int FUN_1(char param_1)\n{\n  if (param_1 != 'a') {\n    return 1;\n  }\n" \
           "  return 0;\n}\n"
    assert sn._generic_name_evidence("enabled", "char", kod2, "param_1") is False


def test_boyut_konumu_chk_ve_macho() -> None:
    kod = "void FUN_1(void *p, ulong param_2)\n{\n  ___memcpy_chk(p, p, param_2, 8);\n}\n"
    assert sn._generic_name_evidence("count", "ulong", kod, "param_2") is True
    kod2 = "void FUN_1(void *p, ulong param_2)\n{\n  memcpy(p, param_2, 8);\n}\n"
    assert sn._generic_name_evidence("count", "ulong", kod2, "param_2") is False


def _params() -> list[dict]:
    return [{"name": n, "type": t, "position": i} for i, (n, t) in enumerate([
        ("param_1", "int"), ("param_2", "uint"), ("param_3", "void *"), ("param_4", "void *"),
        ("param_5", "code *"), ("param_6", "void *"), ("param_7", "long"), ("param_8", "int"),
    ])]


def _namer() -> SemanticParameterNamer:
    namer = SemanticParameterNamer(Config())
    namer._func_codes = {"FUN_00101000": _KOD}
    return namer


@pytest.mark.parametrize("yol", ["dizisel", "paralel"])
def test_kanitsiz_aday_kanitli_ad(yol: str) -> None:
    if yol == "dizisel":
        out = _namer()._infer_from_type_and_usage("FUN_00101000", _params(), _KOD, None)
    else:
        out = sn._worker_infer_from_type_and_usage("FUN_00101000", _params(), _KOD, "generic")
    by = {o.original_name: o for o in out}
    # kanıtsız: param_7 (long, yalnız sabitle karşılaştırma) ve param_8 (int, aritmetik)
    assert by["param_7"].candidate_only is True
    assert by["param_8"].candidate_only is True
    assert sn.GATE_REASON_NO_EVIDENCE in by["param_8"].reason
    # kanıt var ama kural G ölçümünde eşiğin altında (enabled 2 / 167, count 2 / 60): aday
    assert by["param_1"].candidate_only is True  # count (0,55) ya da enabled (0,50) adayı
    assert sn.GATE_REASON_RULE_BELOW in by["param_2"].reason  # döngü koşulu + memcpy boyutu
    assert by["param_2"].candidate_only is True


@pytest.mark.parametrize("yol", ["dizisel", "paralel"])
def test_flags_bit_maskesiyle_yazilir(yol: str) -> None:
    # G ölçümünde eşiği geçen tek daraltılmış kural: flags (bit maskesi; G 18 / 66)
    kod = ("uint FUN_00101000(uint param_1, uint param_2)\n{\n"
           "  if (param_1 == 0) {\n    return 0;\n  }\n  if ((param_1 & 4) != 0) {\n    return 1;\n  }\n"
           "  if (param_2 == 3) {\n    return 2;\n  }\n  return 0;\n}\n")
    params = [{"name": "param_1", "type": "uint", "position": 0},
              {"name": "param_2", "type": "uint", "position": 1}]
    if yol == "dizisel":
        namer = _namer()
        namer._func_codes = {"FUN_00101000": kod}
        out = namer._infer_from_type_and_usage("FUN_00101000", params, kod, None)
    else:
        out = sn._worker_infer_from_type_and_usage("FUN_00101000", params, kod, "generic")
    by = {o.original_name: o for o in out}
    assert (by["param_1"].semantic_name, by["param_1"].candidate_only) == ("flags", False)
    assert by["param_2"].candidate_only is True
    assert sn._GENERIC_NAME_KEPT == frozenset({"flags"})


def test_kapi_adayi_koda_yazmaz_kokene_yazar() -> None:
    namer = _namer()
    namer._reset_gate()
    aday = sn.SemanticName(
        original_name="param_8", semantic_name="value", function_name="FUN_00101000",
        confidence=0.45, source="type_heuristic", reason="Type 'int'; P05c: kanıt yok (aday)",
        domain="generic", candidate_only=True,
    )
    assert namer._resolve_conflicts([aday]) == []
    koken = namer.provenance_section()
    assert koken["schema_version"] == 2
    assert koken["candidates"] == [{
        "function": "FUN_00101000", "param": "param_8", "name": "value",
        "source": "type_heuristic", "confidence": 0.45,
        "reason": "Type 'int'; P05c: kanıt yok (aday)",
        "rejected": sn.GATE_NO_EVIDENCE,
    }]
    assert koken["rejected"] == {"type_heuristic": {sn.GATE_NO_EVIDENCE: 1}}
    assert koken["unnamed"] == {"type_heuristic": 1}
    assert koken["accepted"] == []
    assert sn.GATE_NO_EVIDENCE in koken["reject_reasons"]


def test_aday_baska_kanalin_adini_engellemez() -> None:
    namer = _namer()
    namer._reset_gate()
    aday = sn.SemanticName(
        original_name="param_8", semantic_name="value", function_name="FUN_00101000",
        confidence=0.9, source="type_heuristic", reason="aday", domain="generic",
        candidate_only=True,
    )
    yayilim = sn.SemanticName(
        original_name="param_8", semantic_name="len", function_name="FUN_00101000",
        confidence=0.675, source="call_graph_propagation", reason="Propagated", domain="generic",
    )
    out = namer._resolve_conflicts([aday, yayilim])
    assert [(o.original_name, o.semantic_name) for o in out] == [("param_8", "len")]


def test_aday_yayilmaz() -> None:
    namer = _namer()
    aday = sn.SemanticName(
        original_name="param_8", semantic_name="value", function_name="FUN_00101000",
        confidence=0.45, source="type_heuristic", reason="aday", domain="generic",
        candidate_only=True,
    )
    assert namer._build_known_names([], [aday]) == {}


def test_uctan_uca_aday_kodda_yok(tmp_path: Path) -> None:
    import json

    girdi = tmp_path / "in"
    girdi.mkdir()
    (girdi / "FUN_00101000.c").write_text(_KOD, encoding="utf-8")
    fj = tmp_path / "functions.json"
    fj.write_text(json.dumps({"functions": [{
        "name": "FUN_00101000", "address": "00101000",
        "parameters": [{"name": n["name"], "type": n["type"]} for n in _params()],
    }]}), encoding="utf-8")
    cg = tmp_path / "cg.json"
    cg.write_text(json.dumps({"nodes": {}, "edges": []}), encoding="utf-8")
    namer = SemanticParameterNamer(Config())
    sonuc = namer.rename(decompiled_dir=girdi, functions_json=fj, call_graph_json=cg,
                         output_dir=tmp_path / "out")
    harita = sonuc.naming_map.get("FUN_00101000", {})
    assert "param_8" not in harita and "param_7" not in harita
    adaylar = {(c["param"], c["name"]) for c in sonuc.provenance["candidates"]}
    # param_8 dönüş değerinde (``status`` şablonu), param_7 yalnız sabitle karşılaştırılıyor
    assert {("param_8", "status"), ("param_7", "count")} <= adaylar
    metin = (tmp_path / "out" / "FUN_00101000.c").read_text(encoding="utf-8")
    assert "param_8" in metin
