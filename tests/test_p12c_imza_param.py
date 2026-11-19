"""P12c kalem 3B: imza parametre ayrıştırıcıları dengeli parantezle (aynı kalıp).

Kusur (P12c kalem 1): ``_extract_sig_params`` ve ``_strategy_body_param_naming`` imzayı
``^\\s*[A-Za-z_][\\w\\s*]*?\\b<ad>\\s*\\(([^;{]*)\\)`` ile arıyordu: dönüş tipini adla aynı
satırda ve yalnız ``[\\w\\s*]`` karakterleriyle istiyordu. Gövdesi alınan fonksiyonlarda
bağımsız ayrıştırmayla uyuşmayan 441 / 13 820 (``undefined1  [16]`` 216; Ghidra'nın dönüş
tipini ayrı satıra yazdığı imza 199; C++ ``ns::`` 25 ...). Sonuç ``None``: parametreler
parametre adlandırmaya ve geçiş mirasına kapalıydı. İmza bulunamayınca gövdedeki özyineli
``return ad(x);`` çağrısını imza sanabiliyordu.
"""
from __future__ import annotations

from karadul.config import Config
from karadul.reconstruction.c_namer import (
    CVariableNamer,
    _FunctionInfo,
    _extract_sig_params,
)


def test_donus_tipi_onceki_satirda():
    # Ghidra: "undefined8 *" bir satırda, "FUN_00111720(...)" sonraki satırda; gövde ad satırından başlar
    govde = (
        "FUN_00111720(undefined8 param_1,undefined8 *param_2,code *param_3,code *param_4,"
        "undefined8 param_5)\n\n{\n  return param_2;\n}"
    )
    assert _extract_sig_params(govde, "FUN_00111720") == [
        ("param_1", False), ("param_2", True), ("param_3", True), ("param_4", True),
        ("param_5", False),
    ]


def test_donus_tipi_onceki_satirda_ve_cok_satirli():
    govde = (
        "FUN_001504ec(long param_1,long param_2,long param_3,long param_4,char *param_5,long param_6\n"
        "            ,long param_7,long param_8)\n\n{\n  return;\n}"
    )
    params = _extract_sig_params(govde, "FUN_001504ec")
    assert [p for p, _ in params] == ["param_%d" % i for i in range(1, 9)]
    assert params[4] == ("param_5", True)


def test_koseli_parantezli_donus_tipi():
    govde = "undefined1  [16] FUN_00119e68(long param_1)\n\n{\n  return;\n}"
    assert _extract_sig_params(govde, "FUN_00119e68") == [("param_1", False)]
    assert _extract_sig_params("undefined1  [16] FUN_00110ab0(void)\n\n{\n}", "FUN_00110ab0") == []


def test_cpp_nitelemeli_ad():
    govde = "void std::__cxx11::string::_M_append(char *param_1,ulong param_2)\n\n{\n  return;\n}"
    assert _extract_sig_params(govde, "_M_append") == [("param_1", True), ("param_2", False)]


def test_ozyineli_cagri_imza_sayilmaz():
    # imza satırı olmayan (ör. kesik) gövdede `return ad(x);` çağrısı parametre listesi değildir
    govde = "  uVar1 = FUN_00100900(param_1,param_2);\n  return FUN_00100900(local_10);\n}"
    assert _extract_sig_params(govde, "FUN_00100900") is None


def test_yorum_satiri_imza_sayilmaz():
    govde = (
        "/**\n * FUN_00100a00(int param_9)\n */\n"
        "int FUN_00100a00(int param_1,char *param_2)\n{\n  return param_1;\n}"
    )
    assert _extract_sig_params(govde, "FUN_00100a00") == [("param_1", False), ("param_2", True)]


def test_ad_sozcuk_siniriyla_aranir():
    # başka bir adın son eki imza sayılmaz (eski desenin `\b` koşulu)
    assert _extract_sig_params("int xFUN_00100b00(int a)\n{\n}", "FUN_00100b00") is None


def test_tek_satirlik_govde_eskisi_gibi():
    assert _extract_sig_params("void f(int a, char *b) { g(a); }", "f") == [("a", False), ("b", True)]
    assert _extract_sig_params("int f(int a, ...)\n{\n}", "f") is None  # variadic: eskisi gibi


def test_govde_param_stratejisi_koseli_donus_tipinde_calisir():
    """`_strategy_body_param_naming` aynı ayrıştırıcıyı kullanır: `[16]` dönüşlü fonksiyonda
    da param_1 sınıflanır (eski desen imzayı bulamıyor, aday üretmiyordu)."""
    namer = CVariableNamer(Config(), min_confidence=0.15)
    govde = (
        "undefined1  [16] FUN_00119e68(long *param_1)\n\n{\n"
        "  a = *param_1; b = param_1[1]; c = param_1[2]; d = param_1[3];\n  return;\n}"
    )
    namer._func_bodies = {"FUN_00119e68": govde}
    namer._candidates = {}
    namer._strategy_body_param_naming(_FunctionInfo(name="FUN_00119e68", address="0", params=[]))
    assert {k: [c.new_name for c in v] for k, v in namer._candidates.items()} == {
        "FUN_00119e68::param_1": ["ctx"],
    }
