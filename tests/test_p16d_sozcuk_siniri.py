"""P16d yaması: tip değişimi tanımlayıcı sınırına uyar (``uVar1`` kalıbı ``uVar15``'e düşmez)."""
from karadul.reconstruction.c_type_recoverer import _apply_per_func_replacements, _replace_first_in_code


def test_onek_degiskene_dusmez():
    text = "void f(void) {\n  undefined8 uVar15;\n  undefined8 uVar1;\n}\n"
    assert _replace_first_in_code(text, "undefined8 uVar1", "long uVar1") == (
        "void f(void) {\n  undefined8 uVar15;\n  long uVar1;\n}\n")


def test_yalniz_onekli_bildirim_varsa_dokunulmaz():
    text = "  undefined8 uVar15;\n"
    assert _replace_first_in_code(text, "undefined8 uVar1", "long uVar1") == text


def test_sol_sinir():
    text = "  xundefined8 a;\n  undefined8 a;\n"
    assert _replace_first_in_code(text, "undefined8 a", "long a") == "  xundefined8 a;\n  long a;\n"


def test_uygulama_sirasindan_bagimsiz():
    text = "void FUN_00001000(void)\n{\n  undefined8 uVar15;\n  undefined8 uVar1;\n}\n"
    a = {"FUN_00001000": {"undefined8 uVar1": "long uVar1", "undefined8 uVar15": "char * uVar15"}}
    b = {"FUN_00001000": {"undefined8 uVar15": "char * uVar15", "undefined8 uVar1": "long uVar1"}}
    assert _apply_per_func_replacements(text, a) == _apply_per_func_replacements(text, b)
    assert "char * uVar15;" in _apply_per_func_replacements(text, a)
