"""_apply_per_func_replacements sisme (bloat) regresyon testleri.

Kok sebep: `_func_def` regex'i girintili CAGRI satirlarini ("  setlocale(6,\"\");")
fonksiyon TANIMI saniyordu; ic-ice eslesme `last_end`'i geri sicratiyor ve zaten
yazilmis metin ikinci kez ciktiya giriyordu.  Gercek olcum: tek fonksiyon dosyasi
60.822 B -> 9.718.831 B (160x), benzersiz satir orani 0,93 -> 0,008, tekrarli
`LAB_x:` etiketleri => DERLENEMEZ C.

Bu testler sismenin sessizce geri gelmesini yakalar.  Kritik nokta: sismeyi
durdurup tip degisimini de oldurmek kolay -- bu yuzden "tip hala uygulaniyor"
testi de burada (test_per_func_replacement_still_applies).
"""
from __future__ import annotations

import re

from karadul.reconstruction.c_type_recoverer import (
    _apply_per_func_replacements,
)

# Gercek Ghidra ciktisinin bicimi: donus tipi sutun-0'da, govde 2 bosluk girintili,
# etiketler ve cagrilar girintili.  Girintili `setlocale(...)` + `else if (...)`
# satirlari eski regex'in tanim sandigi tam desenlerdir.
GHIDRA_C = """\
// Function: FUN_00101b00
// Address:  00101b00

void FUN_00101b00(int param_1,undefined8 *param_2)

{
  char *__s1;
  undefined8 uVar13;
  int iVar10;

  setlocale(6,"");
  bindtextdomain("coreutils","/usr/share/locale");
  if (param_1 == 0) {
    uVar13 = 0;
    goto LAB_00101c40;
  }
  else if (param_1 == 1) {
    iVar10 = strncmp(__s1,"--",2);
    exit(iVar10);
  }
LAB_00101c40:
  free(__s1);
  fputs_unlocked("done",stderr);
  error(0,0,"fail");
  return;
}
"""

PER_FUNC = {
    # Gercek tanim -- uygulanmali
    "FUN_00101b00": {"undefined8 uVar13": "void * uVar13"},
    # TUZAK: bunlar binary'de GERCEK fonksiyon (PLT thunk) oldugu icin
    # per_func'ta anahtar olarak bulunurlar; govde icindeki girintili
    # CAGRILARI tanim sanilmamali.
    "setlocale": {"int x": "long x"},
    "free": {"int y": "long y"},
    "exit": {"int z": "long z"},
    "error": {"int w": "long w"},
    "fputs_unlocked": {"int v": "long v"},
    "strncmp": {"int u": "long u"},
    "bindtextdomain": {"int t": "long t"},
    # "else if (...)" satiri fname='if' olarak eslesir -- tanim degil.
    "if": {"int q": "long q"},
}


def _uniq_ratio(text: str) -> float:
    lines = text.split("\n")
    return len(set(lines)) / len(lines) if lines else 0.0


def _label_defs(text: str) -> int:
    """Satir basindaki `LAB_xxxx:` etiket TANIMLARI (goto hedefi degil)."""
    return len(re.findall(r"(?m)^\s*LAB_[0-9a-f]+:", text))


def test_no_bloat_single_pass() -> None:
    """Tek gecis metni cogaltmamali (tasarim niyeti: tipi DEGISTIR, kopyalama yok)."""
    out = _apply_per_func_replacements(GHIDRA_C, PER_FUNC)
    ratio = len(out) / len(GHIDRA_C)
    assert ratio < 1.05, f"sisme: {ratio:.2f}x -- metin cogaltiliyor"


def test_unique_line_ratio_preserved() -> None:
    """Benzersiz satir orani cokmemeli (olculen bug: 0,93 -> 0,008)."""
    out = _apply_per_func_replacements(GHIDRA_C, PER_FUNC)
    assert _uniq_ratio(out) > 0.5, (
        f"benzersiz oran {_uniq_ratio(out):.3f} -- satirlar tekrarlaniyor"
    )


def test_label_count_preserved() -> None:
    """Tekrarli `LAB_x:` tanimi = derlenemez C.  Etiket sayisi korunmali."""
    out = _apply_per_func_replacements(GHIDRA_C, PER_FUNC)
    assert _label_defs(out) == _label_defs(GHIDRA_C)


def test_function_signature_not_duplicated() -> None:
    """Fonksiyon imzasi tek kalmali."""
    out = _apply_per_func_replacements(GHIDRA_C, PER_FUNC)
    assert out.count("void FUN_00101b00(") == 1


def test_indented_call_not_treated_as_definition() -> None:
    """Govde icindeki girintili cagri sayisi degismemeli (ic-ice eslesme kalkani)."""
    out = _apply_per_func_replacements(GHIDRA_C, PER_FUNC)
    assert out.count("setlocale") == GHIDRA_C.count("setlocale")
    assert out.count("free(__s1)") == 1


def test_per_func_replacement_still_applies() -> None:
    """KALKAN: sismeyi durdurup tip degisimini oldurmek kolay -- uygulanmali."""
    out = _apply_per_func_replacements(GHIDRA_C, PER_FUNC)
    assert "void * uVar13" in out
    assert "undefined8 uVar13" not in out


def test_idempotent() -> None:
    """Ayni icerik tekrar gecirilince degismemeli (pipeline cok kez cagiriyor)."""
    once = _apply_per_func_replacements(GHIDRA_C, PER_FUNC)
    twice = _apply_per_func_replacements(once, PER_FUNC)
    assert once == twice


def test_three_passes_no_compound_bloat() -> None:
    """Gercek pipeline ardisik gecis yapiyor: bilesik sisme ~1,0x kalmali."""
    cur = GHIDRA_C
    for _ in range(3):
        cur = _apply_per_func_replacements(cur, PER_FUNC)
    ratio = len(cur) / len(GHIDRA_C)
    assert ratio < 1.05, f"3-gecis bilesik sisme: {ratio:.2f}x"


def test_control_keyword_not_a_function_name() -> None:
    """'else if (x)' satiri fname='if' olarak eslesir.

    'if' gercek fonksiyon olmadigi icin scope'u da yoktur: eski kod if-blogunu
    fonksiyon govdesi sanip ICINDE replacement uyguluyordu (yanlis scope).
    """
    out = _apply_per_func_replacements(GHIDRA_C, {"if": {"iVar10": "WRONG"}})
    assert "WRONG" not in out, "'if' fonksiyon scope'u sanildi -- yanlis kapsamda replace"
    assert out == GHIDRA_C


def test_empty_per_func_is_noop() -> None:
    assert _apply_per_func_replacements(GHIDRA_C, {}) == GHIDRA_C


def test_multiple_real_definitions_all_processed() -> None:
    """Birden fazla GERCEK tanimda hepsi islenmeli (kalkan asiri kisitlamasin)."""
    src = (
        "void FUN_00001000(undefined8 param_1)\n\n{\n  undefined8 a;\n"
        "  helper(a);\n  return;\n}\n\n"
        "int FUN_00002000(undefined8 param_1)\n\n{\n  undefined8 b;\n"
        "  helper(b);\n  return 0;\n}\n"
    )
    per_func = {
        "FUN_00001000": {"undefined8 a": "long a"},
        "FUN_00002000": {"undefined8 b": "char * b"},
        "helper": {"int n": "long n"},
    }
    out = _apply_per_func_replacements(src, per_func)
    assert "long a" in out, "1. tanim islenmedi"
    assert "char * b" in out, "2. tanim islenmedi"
    assert len(out) / len(src) < 1.1
