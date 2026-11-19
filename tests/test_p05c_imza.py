"""P05c Kalem 3 — imza deseni ``uint64_t`` / ``int32_t`` / ``__off_t`` dönüşlü fonksiyonları tanıyor.

Taban: ``_FUNC_SIG_RE`` dönüş tipini sabit bir listeden (``void``, ``int``, ``long`` …) ya da
``\\w+ *`` biçiminden alıyordu; ``uint64_t FUN_…(…)`` adlandırıcıya hiç girmiyordu (cat'te 296
fonksiyonun 11'i; 5 ikilinin girdisinde 4 343 dosyanın 465'i). P05b K1'in parametre ayrıştırması
(işaretçi tipi) değişmez.
"""

from __future__ import annotations

import pytest

from karadul.reconstruction.engineering import semantic_namer as sn


@pytest.mark.parametrize("donus", [
    "uint64_t", "int32_t", "__off_t", "uint8_t", "kern_return_t", "longlong",
    "struct stat *", "const char *", "unsigned int", "char *", "undefined8 *", "void",
])
def test_donus_tipi_taninir(donus: str) -> None:
    kod = f"{donus} FUN_00101000(double *param_1,long param_2)\n\n{{\n  return 0;\n}}\n"
    m = sn._FUNC_SIG_RE.search(kod)
    assert m is not None and m.group(1) == "FUN_00101000"
    params = sn._params_from_signature(m)
    assert [(p["name"], p["type"]) for p in params] == [
        ("param_1", "double *"), ("param_2", "long")]


def test_bitisik_isaretci() -> None:
    m = sn._FUNC_SIG_RE.search("char *FUN_1(int param_1)\n{\n  return 0;\n}\n")
    assert m is not None and m.group(1) == "FUN_1"


@pytest.mark.parametrize("satir", [
    "else if (param_1 == 0) {\n",
    "if (x) {\n",
    "return foo(x) {\n",
    "  int FUN_1(int a) {\n",  # girintili satır imza değil (Ghidra imzayı sütun 0'a yazar)
])
def test_deyim_imza_sayilmaz(satir: str) -> None:
    assert sn._FUNC_SIG_RE.search(satir) is None


def test_uint64_t_fonksiyonu_ad_alir() -> None:
    from karadul.config import Config
    from karadul.reconstruction.engineering.semantic_namer import SemanticParameterNamer

    kod = ("// Address: 00101000\n"
           "uint64_t FUN_00101000(uint param_1)\n{\n"
           "  if (param_1 == 0) {\n    return 0;\n  }\n"
           "  if ((param_1 & 4) != 0) {\n    return 1;\n  }\n  return 2;\n}\n")
    namer = SemanticParameterNamer(Config())
    namer._func_codes = {"FUN_00101000": kod}
    params = namer._get_function_params("FUN_00101000")
    assert [(p["name"], p["type"]) for p in params] == [("param_1", "uint")]
    assert "FUN_00101000" in SemanticParameterNamer._find_all_function_spans(kod)
    out = namer._infer_from_type_and_usage("FUN_00101000", params, kod, None)
    assert [(o.original_name, o.semantic_name, o.candidate_only) for o in out] == [
        ("param_1", "flags", False)]
