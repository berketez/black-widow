"""Tip değişimi ikilinin metnine sadık kalır (çıktı sağlamlığı denetimi, kusur 9).

Kök neden: ``_apply_types_worker`` ``undefined*`` sözcüklerini tek bir
``\\b...\\b`` deseniyle BÜTÜN dosya metninde değiştiriyordu.  Ölçüm (119 ikili,
2026-11-10): openssl'de 5 fonksiyonda dizgi içindeki "undefined" sözcüğü
"uint64_t" oldu (``"iv undefined\\n"`` -> ``"iv uint64_t\\n"``); c_namer'ın
``undefined`` adını verdiği fonksiyonun tanımı ``int uint64_t(long ...)``,
gösterici olarak geçtiği yer ``EVP_MD_do_all_sorted(uint64_t,...)`` oldu.

Bu testler üç şeyi sabitler:
  1. Dizgi sabitleri, karakter sabitleri ve yorumlar değişmez.
  2. Tip sözcüğü yalnız TİP konumunda değişir; ad konumunda (fonksiyon adı,
     çıplak ad, üye, etiket) olduğu gibi kalır.
  3. Son koşul: kod dışı birimlerin çoklu kümesi bozulursa dosya özgün
     metniyle yazılır, sayaç artar, günlüğe yazılır.
Gerçek tip konumlarının hâlâ değiştiği de burada sınanır: korumayı kurup tip
değişimini öldürmek kolaydır.
"""
from __future__ import annotations

import json
import logging
import re

import pytest

from karadul.config import Config
from karadul.reconstruction.c_type_recoverer import (
    _UNDEFINED_DEFAULTS,
    CTypeRecoverer,
    _apply_per_func_replacements,
    _apply_types_to_text,
    _apply_types_worker,
    _blank_ghidra_warnings,
    _is_type_position,
    _noncode_multiset,
    _parse_c_file_worker,
    _replace_first_in_code,
    _replace_type_words,
)


def _apply(src: str) -> str:
    """Varsayılan ``undefined*`` değişimini uygula; geri alınmadığını doğrula."""
    out, reverted = _apply_types_to_text(src, {})
    assert reverted is False
    return out


def _old_global_replace(src: str) -> str:
    """Düzeltmeden önceki davranış: tek ``\\b...\\b`` deseni, bütün metin."""
    keys = sorted(_UNDEFINED_DEFAULTS, key=len, reverse=True)
    pat = re.compile(r"\b(" + "|".join(re.escape(k) for k in keys) + r")\b")
    return pat.sub(lambda m: _UNDEFINED_DEFAULTS[m.group(0)], src)


# ---------------------------------------------------------------------------
# 1. Dizgi sabitleri
# ---------------------------------------------------------------------------

# openssl FUN_001653a0, FUN_0016dc6c, FUN_001b26a0, FUN_001b624c ham çıktısından
OPENSSL_STRINGS = [
    '"iv undefined\\n"',
    '"<undefined>"',
    '"(undefined)"',
    '"undefined"',
]


@pytest.mark.parametrize("literal", OPENSSL_STRINGS)
def test_dizgi_icindeki_undefined_degismez(literal):
    src = f"  BIO_printf(DAT_00218150,{literal});\n"
    assert _apply(src) == src


@pytest.mark.parametrize(
    "literal",
    [
        '"undefined8 uVar1"',
        '"cast (undefined4)x"',
        '"a \\" undefined \\" b"',        # kaçışlı tırnak dizgiyi bitirmez
        '"a \\"undefined8 uVar1\\" b"',   # ... tip konumu gibi görünse de
        '"a \\"(undefined4)x\\" b"',
        '"undefined1 \\\\"',              # kaçışlı ters bölü + kapanış tırnağı
        '"/* undefined8 */"',             # dizgi içindeki yorum başı yorum değil
        '"// undefined4"',
        'L"undefined"',
    ],
)
def test_dizgi_icindeki_tip_sozcukleri_degismez(literal):
    src = f"  pcVar1 = {literal};\n"
    assert _apply(src) == src


def test_dizgi_degismez_ama_ayni_satirdaki_tip_degisir():
    src = '  undefined8 uVar1 = FUN_1("undefined8 uVar1",(undefined4)x);\n'
    assert _apply(src) == (
        '  uint64_t uVar1 = FUN_1("undefined8 uVar1",(int32_t)x);\n'
    )


def test_dizgiden_sonraki_kod_degismeye_devam_eder():
    """Dizgi kapanınca tarama koda döner (kaçışlı ters bölü tuzağı)."""
    src = '  s = "undefined1 \\\\"; undefined8 uVar1;\n'
    assert _apply(src) == '  s = "undefined1 \\\\"; uint64_t uVar1;\n'


def test_kapanmayan_dizgi_satir_sonuna_kadar_dokunulmaz():
    """Bozuk girdi: kapanmayan dizgi satır sonuna kadar kod dışı sayılır."""
    src = '  s = "undefined8 kapanmadı;\n  undefined8 uVar1;\n'
    assert _apply(src) == '  s = "undefined8 kapanmadı;\n  uint64_t uVar1;\n'


# ---------------------------------------------------------------------------
# 2. Karakter sabitleri
# ---------------------------------------------------------------------------


def test_karakter_sabiti_degismez():
    src = "  c = 'undefined';\n"
    assert _apply(src) == src


def test_cift_tirnak_karakter_sabiti_dizgi_baslatmaz():
    """``'"'`` bir karakter sabitidir; ardındaki kod dizgi sanılmamalı."""
    src = "  c = '\"'; undefined8 uVar1; d = '\"';\n"
    assert _apply(src) == "  c = '\"'; uint64_t uVar1; d = '\"';\n"


def test_kacisli_tek_tirnak_karakter_sabiti():
    src = "  c = '\\''; undefined4 uVar2; s = \"undefined\";\n"
    assert _apply(src) == "  c = '\\''; int32_t uVar2; s = \"undefined\";\n"


def test_tek_tirnak_iceren_dizgi_karakter_sabiti_baslatmaz():
    src = '  s = "it\'s"; undefined8 uVar1; t = "undefined\'s";\n'
    assert _apply(src) == '  s = "it\'s"; uint64_t uVar1; t = "undefined\'s";\n'


# ---------------------------------------------------------------------------
# 3. Yorumlar
# ---------------------------------------------------------------------------


def test_satir_yorumu_degismez():
    src = "// Function: undefined\n  undefined8 uVar1; // undefined8 burada\n"
    assert _apply(src) == (
        "// Function: undefined\n  uint64_t uVar1; // undefined8 burada\n"
    )


def test_blok_yorum_degismez():
    src = "  /* undefined8 param_1 */ undefined8 uVar1;\n"
    assert _apply(src) == "  /* undefined8 param_1 */ uint64_t uVar1;\n"


def test_cok_satirli_blok_yorum_degismez():
    src = (
        "/* WARNING: Type propagation algorithm not settling\n"
        "   undefined8 uVar1 (undefined4)x\n"
        " */\n"
        "undefined8 FUN_00101b00(void)\n"
    )
    assert _apply(src) == src.replace(
        "undefined8 FUN_00101b00", "uint64_t FUN_00101b00",
    )


def test_yorum_icindeki_tirnak_dizgi_baslatmaz():
    src = "  /* don't \" */ undefined8 uVar1; /* \" */\n"
    assert _apply(src) == "  /* don't \" */ uint64_t uVar1; /* \" */\n"


def test_kapanmayan_blok_yorum_dosya_sonuna_kadar_dokunulmaz():
    src = "undefined8 uVar1;\n/* kapanmadı undefined8\nundefined4 x;\n"
    assert _apply(src) == "uint64_t uVar1;\n/* kapanmadı undefined8\nundefined4 x;\n"


def test_bolme_isleci_yorum_sanilmaz():
    src = "  uVar1 = (undefined8)a / (undefined8)b;\n"
    assert _apply(src) == "  uVar1 = (uint64_t)a / (uint64_t)b;\n"


# ---------------------------------------------------------------------------
# 4. Ad konumu: fonksiyon tanımı, çağrı, çıplak ad, üye, etiket
# ---------------------------------------------------------------------------

# openssl FUN_0016dc6c: c_namer fonksiyona "undefined" adını verdi.
OPENSSL_UNDEFINED_FUNC = """\
// Function: undefined
// Address:  0016dc6c

int undefined(long param_1,char *param_2,char *param_3,BIO *param_4)

{
  char *pcVar1;
  undefined8 uVar2;

  if (param_1 != 0) {
    uVar2 = EVP_MD_get0_name();
    return BIO_printf(param_4,"  %s\\n",uVar2);
  }
  pcVar1 = "<undefined>";
  return 0;
}
"""


def test_adi_tip_sozcugu_olan_fonksiyonun_tanimi_degismez():
    out = _apply(OPENSSL_UNDEFINED_FUNC)
    assert "int undefined(long param_1,char *param_2" in out
    assert "// Function: undefined\n" in out
    assert 'pcVar1 = "<undefined>";' in out
    # Aynı dosyadaki gerçek tip hâlâ değişir
    assert "  uint64_t uVar2;\n" in out
    assert "undefined8" not in out
    # Tek değişen yer o bildirim
    assert out == OPENSSL_UNDEFINED_FUNC.replace("undefined8 uVar2", "uint64_t uVar2")


@pytest.mark.parametrize(
    "line",
    [
        "  undefined(param_1);\n",                       # çağrı
        "  iVar1 = undefined(param_1,param_2);\n",       # değeri kullanılan çağrı
        "  undefined (param_1);\n",                      # boşluklu çağrı
        "  undefined(*param_1);\n",                      # gösterici argümanlı çağrı
        "  undefined();\n",
        "  EVP_MD_do_all_sorted(undefined,DAT_00218158);\n",  # openssl FUN_0016bea0
        "  FUN_1(param_1,undefined);\n",                 # son argüman
        "  FUN_1(undefined);\n",                         # tek argüman
        "  x = FUN_1(undefined) - 1;\n",                 # çağrıdan sonra işleç
        "  if ((FUN_1(undefined) & 1) != 0) {\n",
        "  x = FUN_1 (undefined) * 2;\n",
        "  pcVar1 = undefined;\n",                       # atama
        "  pcVar1 = &undefined;\n",
        "  if (pcVar1 == undefined) {\n",
        "  return undefined;\n",
    ],
)
def test_fonksiyon_adi_cagri_ve_ciplak_ad_degismez(line):
    assert _apply(line) == line


@pytest.mark.parametrize("word", sorted(_UNDEFINED_DEFAULTS))
def test_her_tip_sozcugu_fonksiyon_adi_olarak_korunur(word):
    src = f"int {word}(long param_1)\n\n{{\n  return {word}(param_1);\n}}\n"
    assert _apply(src) == src


@pytest.mark.parametrize(
    "line",
    [
        "  param_1->undefined = 3;\n",
        "  iVar1 = param_1->undefined4 * 2;\n",
        "  local_10.undefined = 0;\n",
        "  local_10 . undefined8 = 0;\n",
        "  goto undefined;\n",
        "undefined:\n",
        "  struct undefined *psVar1;\n",
        "  union undefined8 *puVar1;\n",
        "  enum undefined eVar1;\n",
        "  case undefined:\n",
    ],
)
def test_uye_ve_etiket_adi_degismez(line):
    assert _apply(line) == line


@pytest.mark.parametrize(
    "line",
    [
        "  long undefined;\n",                 # bildirgeç adı
        "  long undefined = 3;\n",
        "  char undefined [16];\n",
        "void FUN_1(char *undefined)\n",
        "void FUN_1(long undefined,int x)\n",
        "  x = (undefined);\n",                # parantezli değer, cast değil
        "  x = undefined + 1;\n",
        "  x = undefined[3];\n",
        "  if (undefined) {\n",
    ],
)
def test_degisken_adi_konumu_degismez(line):
    assert _apply(line) == line


# ---------------------------------------------------------------------------
# 5. Gerçek tip konumları hâlâ değişir (regresyon yok)
# ---------------------------------------------------------------------------

# Her satır 117 ikilinin ham Ghidra çıktısında görülen bir biçim.
TYPE_POSITION_CASES = [
    # 1. W ad
    ("  undefined8 uVar1;\n", "  uint64_t uVar1;\n"),
    ("  undefined1 auStack_20 [16];\n", "  uint8_t auStack_20 [16];\n"),
    ("undefined4 FUN_00106080(undefined4 *param_1)\n",
     "int32_t FUN_00106080(int32_t *param_1)\n"),
    ("void FUN_00107784(undefined8 param_1,undefined8 param_2)\n",
     "void FUN_00107784(uint64_t param_1,uint64_t param_2)\n"),
    ("  undefined2 uVar3;\n", "  uint16_t uVar3;\n"),
    ("  undefined uVar4;\n", "  uint64_t uVar4;\n"),
    # 2. W *ad / W *)
    ("  undefined8 *in_x4;\n", "  uint64_t *in_x4;\n"),
    ("  undefined *puVar1;\n", "  uint64_t *puVar1;\n"),
    ("undefined * FUN_00104340(char *param_1,int param_2)\n",
     "uint64_t * FUN_00104340(char *param_1,int param_2)\n"),
    ("  uVar8 = FUN_00106d60(*(undefined8 *)(lVar2 + lVar10));\n",
     "  uVar8 = FUN_00106d60(*(uint64_t *)(lVar2 + lVar10));\n"),
    ("  ppuVar1 = (undefined8 **)param_1;\n", "  ppuVar1 = (uint64_t **)param_1;\n"),
    ("byte FUN_001021c0(uint param_1,undefined8 *param_2)\n",
     "byte FUN_001021c0(uint param_1,uint64_t *param_2)\n"),
    # 3. (W)işlenen, sizeof(W)
    ("    local_e8 = (undefined1)param_2;\n", "    local_e8 = (uint8_t)param_2;\n"),
    ("    return (undefined4)local_1070.gl_pathc;\n",
     "    return (int32_t)local_1070.gl_pathc;\n"),
    ("  local_440 = CONCAT44((undefined4)local_498,iVar42);\n",
     "  local_440 = CONCAT44((int32_t)local_498,iVar42);\n"),
    ("  FUN_1(param_1,\n        (undefined1)local_3bc);\n",
     "  FUN_1(param_1,\n        (uint8_t)local_3bc);\n"),
    ("  x = (undefined8)0x10;\n", "  x = (uint64_t)0x10;\n"),
    ("  x = (undefined4)-1;\n", "  x = (int32_t)-1;\n"),
    ("  x = (undefined8)(a + b);\n", "  x = (uint64_t)(a + b);\n"),
    ("  x = (long)(undefined4)y;\n", "  x = (long)(int32_t)y;\n"),
    ("  n = sizeof(undefined8);\n", "  n = sizeof(uint64_t);\n"),
    ("  n = sizeof (undefined4) * 2;\n", "  n = sizeof (int32_t) * 2;\n"),
    # 4. W [N] ad / (W [N])
    ("undefined1  [16] FUN_00111c80(undefined1 param_1 [16])\n",
     "uint8_t  [16] FUN_00111c80(uint8_t param_1 [16])\n"),
    ("            local_90 = (undefined1  [8])0xc066800000000000;\n",
     "            local_90 = (uint8_t  [8])0xc066800000000000;\n"),
    # 5. W (*ad) [N] / W (*)(...)
    ("  undefined1 (*pauVar2) [16];\n", "  uint8_t (*pauVar2) [16];\n"),
    ("      pauVar2 = *(undefined1 (**) [16])(param_1 + 0x58);\n",
     "      pauVar2 = *(uint8_t (**) [16])(param_1 + 0x58);\n"),
    ("undefined1 (*) [16] FUN_0010c360(undefined8 param_1,undefined1 (*param_3) [16])\n",
     "uint8_t (*) [16] FUN_0010c360(uint64_t param_1,uint8_t (*param_3) [16])\n"),
    ("  undefined8 (*pcVar1)(int);\n", "  uint64_t (*pcVar1)(int);\n"),
]


@pytest.mark.parametrize("src,expected", TYPE_POSITION_CASES)
def test_gercek_tip_konumlari_degisir(src, expected):
    assert _apply(src) == expected


@pytest.mark.parametrize("src,_expected", TYPE_POSITION_CASES)
def test_tip_konumlarinda_eski_davranisla_ayni(src, _expected):
    """Dizgi, yorum ve ad içermeyen metinde çıktı düzeltme öncesiyle bayt bayt aynı."""
    assert _apply(src) == _old_global_replace(src)


# coreutils/tree ham çıktısının biçimi: başlık yorumları, sütun-0 imza, gövde.
GHIDRA_FILE = """\
// Function: FUN_001060e8
// Address:  001060e8
// Size:     60 bytes


undefined8 FUN_001060e8(long *param_1,undefined8 *param_2,undefined4 param_3)

{
  uint uVar1;
  undefined8 uVar2;
  undefined1 auStack_28 [16];
  undefined1 (*pauVar3) [16];

  if (*(byte *)(*param_2 + 0x10) == *(byte *)(*param_1 + 0x10)) {
    uVar2 = (*(code *)PTR_FUN_00130110)();
    return uVar2;
  }
  uVar1 = (undefined4)param_3 + sizeof(undefined8);
  *(undefined8 *)(param_1 + 8) = (undefined8)uVar1;
  pauVar3 = (undefined1 (*) [16])auStack_28;
  return (undefined8)uVar1;
}
"""


def test_dizgisiz_dosyada_cikti_eski_davranisla_bayt_bayt_ayni():
    out = _apply(GHIDRA_FILE)
    assert out == _old_global_replace(GHIDRA_FILE)
    assert "undefined" not in out
    assert out.count("uint64_t") == GHIDRA_FILE.count("undefined8") == 7
    assert out.count("uint8_t") == GHIDRA_FILE.count("undefined1") == 3
    assert out.count("int32_t") == GHIDRA_FILE.count("undefined4") == 2


def test_degisim_idempotent():
    once = _apply(GHIDRA_FILE + OPENSSL_UNDEFINED_FUNC)
    assert _apply(once) == once


def test_ozel_degisim_anahtari_da_ayni_kurala_uyar():
    """``replacements`` ile gelen anahtar da dizgi ve ad konumunda değişmez."""
    src = 'code *pcVar1; s = "code"; code(1); x = (code *)y;\n'
    out, reverted = _apply_types_to_text(src, {"code": "func_t"})
    assert reverted is False
    assert out == 'func_t *pcVar1; s = "code"; code(1); x = (func_t *)y;\n'


def test_bos_degisim_tablosu_metni_degistirmez():
    assert _replace_type_words(GHIDRA_FILE, {}) == GHIDRA_FILE


# ---------------------------------------------------------------------------
# _is_type_position: kuralın kendisi
# ---------------------------------------------------------------------------


def _pos(text: str, word: str = "undefined") -> bool:
    start = text.index(word)
    return _is_type_position(text, start, start + len(word))


@pytest.mark.parametrize(
    "text,expected",
    [
        ("undefined x;", True),
        ("undefined *x;", True),
        ("(undefined *)x", True),
        ("(undefined **)x", True),
        ("(undefined)x", True),
        ("sizeof(undefined)", True),
        ("sizeof(undefined);", True),
        ("return (undefined)x;", True),
        ("undefined [16] f(void)", True),
        ("(undefined [8])x", True),
        ("undefined (*p) [16];", True),
        ("undefined (*)(int)", True),
        ("undefined(x)", False),
        ("undefined (x)", False),
        ("undefined(*p);", False),          # çağrı: ``)`` ardından ``[`` ya da ``(`` yok
        ("f(undefined)", False),            # tek argümanlı çağrı
        ("f(undefined);", False),
        ("x = (undefined);", False),        # ``)`` ardından işlenen yok
        ("x = (undefined) ;", False),
        ("undefined * 4", False),           # yıldızdan sonra sayı: çarpma
        ("undefined *", False),
        ("undefined[3] = 1;", False),       # dizin: ``]`` ardından ad ya da ``)`` yok
        ("undefined [3];", False),
        ("undefined", False),               # metin sonu
        ("undefined ", False),
        ("undefined;", False),
        ("undefined,", False),
        ("a.undefined x", False),
        ("a->undefined *x", False),
        ("struct undefined *x", False),
        ("goto undefined x", False),
    ],
)
def test_tip_konumu_kurali(text, expected):
    assert _pos(text) is expected


# ---------------------------------------------------------------------------
# 6. Fonksiyon bazlı değişim (_apply_per_func_replacements)
# ---------------------------------------------------------------------------


def test_fonksiyon_bazli_degisim_dizgiyi_atlar_bildirimi_degistirir():
    """İlk geçiş dizgi içindeyse eski kod dizgiyi değiştirir, bildirimi bırakırdı."""
    src = (
        "void FUN_00101b00(undefined8 param_1)\n"
        "\n"
        "{\n"
        '  puts("undefined8 uVar13");\n'
        "  undefined8 uVar13;\n"
        "  uVar13 = 0;\n"
        "}\n"
    )
    out = _apply_per_func_replacements(
        src, {"FUN_00101b00": {"undefined8 uVar13": "void * uVar13"}},
    )
    assert '  puts("undefined8 uVar13");\n' in out
    assert "  void * uVar13;\n" in out
    assert out == src.replace("  undefined8 uVar13;", "  void * uVar13;")


def test_fonksiyon_bazli_degisim_yorumu_atlar():
    src = (
        "void FUN_00101b00(void)\n"
        "\n"
        "{\n"
        "  /* undefined8 uVar13 burada */\n"
        "  // undefined8 uVar13\n"
        "  undefined8 uVar13;\n"
        "}\n"
    )
    out = _apply_per_func_replacements(
        src, {"FUN_00101b00": {"undefined8 uVar13": "char * uVar13"}},
    )
    assert out == src.replace("  undefined8 uVar13;", "  char * uVar13;")


def test_fonksiyon_bazli_degisim_yalniz_dizgide_gecerse_hicbir_sey_degismez():
    src = 'void FUN_00101b00(void)\n\n{\n  puts("undefined8 uVar13");\n}\n'
    out = _apply_per_func_replacements(
        src, {"FUN_00101b00": {"undefined8 uVar13": "void * uVar13"}},
    )
    assert out == src


def test_replace_first_in_code_kod_disi_yoksa_str_replace_ile_ayni():
    text = "undefined8 a; undefined8 a; undefined8 b;"
    assert _replace_first_in_code(text, "undefined8 a", "long a") == (
        text.replace("undefined8 a", "long a", 1)
    )
    assert _replace_first_in_code(text, "yok", "x") == text
    assert _replace_first_in_code(text, "", "x") == text


def test_replace_first_in_code_kesisen_gecisi_atlar():
    # Geçiş dizginin içinde başlıyor / bitiyor / tam ortasında: hepsi atlanır.
    text = 's = "ab undefined8 a"; undefined8 a;'
    assert _replace_first_in_code(text, "undefined8 a", "long a") == (
        's = "ab undefined8 a"; long a;'
    )
    # Dizgi sınırını aşan geçiş de koda ait değildir
    text2 = 'f("x") y; f("x") y;'
    assert _replace_first_in_code(text2, '") y', '") z') == text2
    # Yorumdan hemen sonra başlayan geçiş koddadır (sınır dahil değil)
    text3 = "/* c */undefined8 a;"
    assert _replace_first_in_code(text3, "undefined8 a", "long a") == "/* c */long a;"
    # Dizgiden hemen önce biten geçiş koddadır
    text4 = 'undefined8 a"s";'
    assert _replace_first_in_code(text4, "undefined8 a", "long a") == 'long a"s";'


# ---------------------------------------------------------------------------
# 7. Son koşul: bozulma yakalanır, özgün metin korunur
# ---------------------------------------------------------------------------

POSTCOND_SRC = (
    "void FUN_00101b00(void)\n"
    "\n"
    "{\n"
    "  undefined8 uVar13;\n"
    '  puts("merhaba");\n'
    "  c = 'x';\n"
    "  /* yorum */\n"
    "}\n"
)


def test_noncode_multiset_dizgi_karakter_ve_yorumu_sayar():
    ms = _noncode_multiset(POSTCOND_SRC + '  puts("merhaba");\n')
    assert ms == {'"merhaba"': 2, "'x'": 1, "/* yorum */": 1}


def test_son_kosul_yeni_yorum_eklenirse_ozgun_metin_doner():
    out, reverted = _apply_types_to_text(
        POSTCOND_SRC, {"undefined8": 'char * /*x*/'},
    )
    assert reverted is True
    assert out == POSTCOND_SRC


def test_son_kosul_yeni_dizgi_eklenirse_ozgun_metin_doner():
    out, reverted = _apply_types_to_text(
        POSTCOND_SRC, {"undefined8": 'char * "x"'},
    )
    assert reverted is True
    assert out == POSTCOND_SRC


def test_son_kosul_yeni_karakter_sabiti_eklenirse_ozgun_metin_doner():
    out, reverted = _apply_types_to_text(
        POSTCOND_SRC, {"undefined8": "char 'y'"},
    )
    assert reverted is True
    assert out == POSTCOND_SRC


def test_son_kosul_fonksiyon_bazli_degisim_dizgi_eklerse_yakalar():
    out, reverted = _apply_types_to_text(
        POSTCOND_SRC, {},
        {"FUN_00101b00": {"undefined8 uVar13": 'char * uVar13 = "yeni"'}},
    )
    assert reverted is True
    assert out == POSTCOND_SRC


def test_son_kosul_ayni_dizgiden_bir_tane_daha_eklenirse_yakalar():
    """Küme değil ÇOKLU küme: var olan dizginin sayısı artarsa da bozulmadır."""
    out, reverted = _apply_types_to_text(
        POSTCOND_SRC, {},
        {"FUN_00101b00": {"undefined8 uVar13": 'char * uVar13 = "merhaba"'}},
    )
    assert reverted is True
    assert out == POSTCOND_SRC


def test_son_kosul_dizgi_silinirse_yakalar():
    """Tip değişimi dizgiyi yuttuğunda (yorum açan değişim) özgün metin döner."""
    out, reverted = _apply_types_to_text(
        POSTCOND_SRC, {},
        {"FUN_00101b00": {"undefined8 uVar13;": "long uVar13; /*"}},
    )
    assert reverted is True
    assert out == POSTCOND_SRC


def test_son_kosul_saglaninca_geri_alinmaz():
    out, reverted = _apply_types_to_text(
        POSTCOND_SRC, {},
        {"FUN_00101b00": {"undefined8 uVar13": "char * uVar13"}},
    )
    assert reverted is False
    assert out == POSTCOND_SRC.replace("undefined8 uVar13", "char * uVar13")


def test_isci_geri_alinan_dosyayi_ozgun_metinle_yazar(tmp_path):
    src_file = tmp_path / "in" / "FUN_00101b00.c"
    src_file.parent.mkdir()
    src_file.write_text(POSTCOND_SRC, encoding="utf-8")
    out_file = tmp_path / "out" / "FUN_00101b00.c"

    path, reverted = _apply_types_worker(
        str(src_file), str(out_file), {},
        {"FUN_00101b00": {"undefined8 uVar13": 'char * uVar13 = "yeni"'}},
    )
    assert path == str(out_file)
    assert reverted is True
    # Özgün metin + yalnız types.h include'u
    assert out_file.read_text(encoding="utf-8") == '#include "types.h"\n\n' + POSTCOND_SRC


def test_isci_normal_dosyada_geri_almaz_ve_tipi_degistirir(tmp_path):
    src_file = tmp_path / "FUN_00101b00.c"
    src_file.write_text(POSTCOND_SRC, encoding="utf-8")
    out_file = tmp_path / "out" / "FUN_00101b00.c"

    path, reverted = _apply_types_worker(str(src_file), str(out_file), {})
    assert (path, reverted) == (str(out_file), False)
    assert out_file.read_text(encoding="utf-8") == (
        '#include "types.h"\n\n' + POSTCOND_SRC.replace("undefined8", "uint64_t")
    )


def test_isci_okunamayan_dosyada_bos_yol_doner(tmp_path):
    assert _apply_types_worker(
        str(tmp_path / "yok.c"), str(tmp_path / "out.c"), {},
    ) == ("", False)


def _write_recover_inputs(tmp_path):
    decompiled = tmp_path / "decompiled"
    decompiled.mkdir()
    (decompiled / "FUN_00101b00.c").write_text(POSTCOND_SRC, encoding="utf-8")
    (decompiled / "FUN_00101c00.c").write_text(
        "undefined8 FUN_00101c00(undefined8 param_1)\n"
        "\n"
        "{\n"
        '  puts("iv undefined\\n");\n'
        "  return param_1;\n"
        "}\n",
        encoding="utf-8",
    )
    functions = tmp_path / "functions.json"
    functions.write_text(json.dumps({"functions": [
        {"name": "FUN_00101b00", "address": "00101b00", "size": 16,
         "parameters": [], "return_type": "void"},
        {"name": "FUN_00101c00", "address": "00101c00", "size": 16,
         "parameters": [{"name": "param_1", "type": "undefined8"}],
         "return_type": "undefined8"},
    ]}), encoding="utf-8")
    return decompiled, functions


def test_recover_geri_alinan_dosyayi_sayar_ve_gunluge_yazar(tmp_path, caplog):
    """Uçtan uca: işçinin bayrağı sonuca, sayaca ve günlüğe ulaşır."""
    decompiled, functions = _write_recover_inputs(tmp_path)
    recoverer = CTypeRecoverer(Config())
    # Tip yayılımı bir dosyada dizgi ekleyen (bozuk) bir değişim üretsin
    recoverer._propagate_types_v2 = lambda *a, **k: (  # type: ignore[method-assign]
        dict(_UNDEFINED_DEFAULTS),
        {"FUN_00101b00": {"undefined8 uVar13": 'char * uVar13 = "yeni"'}},
    )
    out_dir = tmp_path / "typed"
    with caplog.at_level(logging.WARNING, logger="karadul.reconstruction.c_type_recoverer"):
        result = recoverer.recover(decompiled, functions, out_dir)

    assert result.success is True
    assert result.type_recovery_reverted == 1
    assert [p.name for p in result.reverted_files] == ["FUN_00101b00.c"]
    # Geri alınan dosya yine yazıldı: özgün metin + include
    assert (out_dir / "FUN_00101b00.c").read_text(encoding="utf-8") == (
        '#include "types.h"\n\n' + POSTCOND_SRC
    )
    # Öbür dosya normal işlendi: tip değişti, dizgi değişmedi
    other = (out_dir / "FUN_00101c00.c").read_text(encoding="utf-8")
    assert "uint64_t FUN_00101c00(uint64_t param_1)" in other
    assert '"iv undefined\\n"' in other
    assert len(result.output_files) == 2
    geri = [r for r in caplog.records if "geri alındı" in r.getMessage()]
    assert len(geri) == 1
    assert "FUN_00101b00.c" in geri[0].getMessage()
    assert geri[0].levelno == logging.WARNING


def test_recover_normal_kosuda_geri_alinan_yok(tmp_path, caplog):
    decompiled, functions = _write_recover_inputs(tmp_path)
    out_dir = tmp_path / "typed"
    with caplog.at_level(logging.WARNING, logger="karadul.reconstruction.c_type_recoverer"):
        result = CTypeRecoverer(Config()).recover(decompiled, functions, out_dir)
    assert result.success is True
    assert result.type_recovery_reverted == 0
    assert result.reverted_files == []
    assert not [r for r in caplog.records if "geri alındı" in r.getMessage()]
    assert '"iv undefined\\n"' in (out_dir / "FUN_00101c00.c").read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# 8. Korunan Ghidra uyarıları tip analizini kirletmez
# ---------------------------------------------------------------------------

WARNING_FILE = """\
// Function: FUN_00105df4
// Address:  00105df4


/* WARNING: Removing unreachable block (ram,0x00105e04) */
/* WARNING: Unknown calling convention -- yet parameter storage is locked */

undefined8 FUN_00105df4(undefined8 param_1)

{
  undefined8 uVar1;

  uVar1 = strlen(param_1);
  if (uVar1 == 0) {
                    /* WARNING: Bad instruction - Truncating control flow here */
    halt_baddata();
  }
                    /* WARNING: Subroutine does not return */
  exit(1);
}
"""


def test_blank_ghidra_warnings_uzunlugu_ve_satirlari_korur():
    blanked = _blank_ghidra_warnings(WARNING_FILE)
    assert len(blanked) == len(WARNING_FILE)
    assert blanked.count("\n") == WARNING_FILE.count("\n")
    assert "WARNING" not in blanked
    assert "unreachable" not in blanked
    # Kod ve başlık yorumları yerinde
    assert "undefined8 FUN_00105df4(undefined8 param_1)" in blanked
    assert "// Function: FUN_00105df4" in blanked
    assert "  exit(1);" in blanked


def test_blank_ghidra_warnings_dizgi_ve_baska_yoruma_dokunmaz():
    src = (
        '  puts("/* WARNING: Script requires that X be disabled */\\n");\n'
        "  /* ANTI-DEBUG: ptrace */\n"
        "  // /* WARNING: satır yorumu içinde */\n"
        "  /* DISPLAY WARNING: bad instruction */\n"
        "  /* WARNING: çok\n     satırlı */\n"
    )
    blanked = _blank_ghidra_warnings(src)
    assert '"/* WARNING: Script requires that X be disabled */\\n"' in blanked
    assert "/* ANTI-DEBUG: ptrace */" in blanked
    assert "// /* WARNING: satır yorumu içinde */" in blanked
    assert "DISPLAY" not in blanked
    assert "satırlı" not in blanked
    assert len(blanked) == len(src)
    assert blanked.count("\n") == src.count("\n")


def test_blank_ghidra_warnings_uyari_yoksa_ayni_nesneyi_doner():
    assert _blank_ghidra_warnings(GHIDRA_FILE) is GHIDRA_FILE


def test_parse_isci_uyari_metnini_kod_sanmaz(tmp_path):
    """Uyarılı ve uyarısız dosyanın analiz sonucu aynı olmalı."""
    with_w = tmp_path / "a" / "FUN_00105df4.c"
    without_w = tmp_path / "b" / "FUN_00105df4.c"
    with_w.parent.mkdir()
    without_w.parent.mkdir()
    with_w.write_text(WARNING_FILE, encoding="utf-8")
    without_w.write_text(
        re.sub(r"/\*\s*WARNING:[^*]*\*/", "", WARNING_FILE), encoding="utf-8",
    )

    r1 = _parse_c_file_worker(str(with_w))
    r2 = _parse_c_file_worker(str(without_w))
    # Uyarı metninden türeyen sahte değişkenler yok
    assert "ram" not in r1["type_usages"]
    assert "instruction" not in r1["type_usages"]
    assert not any("call_arg:block:" in t for tags in r1["type_usages"].values() for t in tags)
    for key in ("type_usages", "switch_vars", "compare_vars", "string_context",
                "case_comments", "vtable_entries", "errors"):
        assert r1[key] == r2[key], key
    # Gerçek kullanım hâlâ yakalanıyor
    assert "string_func_arg" in r1["type_usages"]["param_1"]
    assert "declared:undefined8" in r1["type_usages"]["uVar1"]
