"""P05b kalem 1: anlamsal adlandırıcının imza ayrıştırması işaretçi tipini korur.

Eski ``_PARAM_PARSE_RE`` tip ile ad arasında boşluk istiyordu; Ghidra ``double *param_1`` yazar,
yedek ``rsplit`` tipi ``double`` okuyordu. Gerçek koşularda ``ghidra_functions.json``'da ``params``
alanı olmadığı için bütün işaretçi parametreleri taban tip sayılıyordu: ``char *`` → ``bool``
şablonu → ``enabled``, ``int *`` → ``count``. Ayrıca "şablon ``long``, gerçek tip işaretçi →
uyumlu" ters istisnası işaretçi parametreye skaler ad veriyordu.
"""
from __future__ import annotations

import pytest

from karadul.config import Config
from karadul.reconstruction.engineering import semantic_namer as sn_mod
from karadul.reconstruction.engineering.semantic_namer import (
    SemanticParameterNamer,
    _FUNC_SIG_RE,
    _declared_variables,
    _params_from_signature,
    _parse_param_decl,
    _types_compatible,
)


@pytest.mark.parametrize("raw, beklenen", [
    ("double *param_1", ("param_1", "double *")),
    ("char *param_3", ("param_3", "char *")),
    ("const char *s", ("s", "char *")),
    ("const char **argv", ("argv", "char **")),
    ("uint64_t **pp", ("pp", "uint64_t **")),
    ("unsigned char * p", ("p", "unsigned char *")),
    ("char buf[16]", ("buf", "char *")),
    ("void (*cb)(int, long)", ("cb", "code *")),
    ("code *param_2", ("param_2", "code *")),
    ("struct foo *const s", ("s", "struct foo *")),
    ("ulong param_3", ("param_3", "ulong")),
    ("uint8_t (*param_3) [16]", ("param_3", "uint8_t **")),
])
def test_bildirim_ayristirma(raw, beklenen):
    assert _parse_param_decl(raw) == beklenen


@pytest.mark.parametrize("raw", ["void", "...", "x", "int", "  "])
def test_parametre_olmayan_bildirim(raw):
    assert _parse_param_decl(raw) is None


def test_imza_islev_gostericisi_fonksiyonu_dusurmez():
    code = "void f(int a,void (*cb)(int, long),char *s)\n{\n  return;\n}\n"
    m = _FUNC_SIG_RE.search(code)
    assert m is not None and m.group(1) == "f"
    assert _params_from_signature(m) == [
        {"name": "a", "type": "int", "position": 0},
        {"name": "cb", "type": "code *", "position": 1},
        {"name": "s", "type": "char *", "position": 2},
    ]
    assert {"a", "cb", "s"} <= _declared_variables(code)


def test_tip_uyumu_tek_yonlu_istisna():
    # Ghidra'nın işaretçi istisnası: tamsayı parametre işaretçi şablonuyla uyumlu
    assert _types_compatible("char *", "ulong")
    assert _types_compatible("double *", "long")
    # Gerçek işaretçi skaler şablon almaz (eski ters istisna)
    assert not _types_compatible("long", "char *")
    assert not _types_compatible("long", "FILE *")
    assert not _types_compatible("ulong", "void *")
    assert not _types_compatible("int", "int *")
    assert not _types_compatible("bool", "char *")
    # İşaretçi derinliği
    assert not _types_compatible("char *", "char **")
    # Niteleyici eşleşmeyi bozmaz
    assert _types_compatible("char *", "const char *")


def _namer(code: str) -> tuple[SemanticParameterNamer, str]:
    namer = SemanticParameterNamer(Config())
    name = _FUNC_SIG_RE.search(code).group(1)
    namer._func_codes = {name: code}
    return namer, name


CODE = (
    "void FUN_00101000(char *param_1,int *param_2,FILE *param_3,double *param_4,int param_5)\n"
    "{\n"
    "  int i;\n"
    "  if (param_5 < 3) {\n"
    "    fputs(param_1,param_3);\n"
    "  }\n"
    "  *param_2 = param_5;\n"
    "  *param_4 = 0.0;\n"
    "  return;\n"
    "}\n"
)


def test_sirali_yol_isaretciye_skaler_ad_vermez():
    namer, name = _namer(CODE)
    params = namer._get_function_params(name)
    assert [p["type"] for p in params] == ["char *", "int *", "FILE *", "double *", "int"]
    got = {s.original_name: s.semantic_name
           for s in namer._infer_from_type_and_usage(name, params, CODE, "generic")}
    skaler = {"count", "value", "status", "enabled", "handle", "threshold", "scalar", "n_size"}
    for p in ("param_1", "param_2", "param_3", "param_4"):
        assert got.get(p) not in skaler, (p, got.get(p))
    # skaler parametre skaler ad almaya devam eder (kanal susturulmadı)
    assert got.get("param_5") == "count"


def test_paralel_yol_ayni_ayristirici():
    namer, name = _namer(CODE)
    sn_mod._W_FUNC_CODES = {name: CODE}
    sn_mod._W_FUNCTIONS = {}
    try:
        assert sn_mod._worker_get_params(name) == namer._get_function_params(name)
        params = sn_mod._worker_get_params(name)
        got = {s.original_name: s.semantic_name for s in
               sn_mod._worker_infer_from_type_and_usage(name, params, CODE, "generic")}
    finally:
        sn_mod._W_FUNC_CODES = {}
    skaler = {"count", "value", "status", "enabled", "handle", "threshold", "scalar", "n_size"}
    for p in ("param_1", "param_2", "param_3", "param_4"):
        assert got.get(p) not in skaler, (p, got.get(p))
