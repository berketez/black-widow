"""P05b kalem 2: işaretçi şablonuna kanıt şartı (kanıtsız ``str``).

``char *`` şablonları (``str`` / ``text`` / ``name``) Ghidra'nın işaretçi istisnasıyla
(``long`` / ``ulong`` / ``undefined8``) tamsayı parametrelere kanıtsız düşüyordu (cat
``rpl_fcntl``'in ``ulong param_3``'ü ``str``). Artık ``char *`` şablonu bildirilen ``char *``
tipini ya da koddaki dizgi kanıtını ister; istisnayla gelen öbür işaretçi şablonları
(``unsigned char *``, ``int *``, ``void *``) öğe erişimi kanıtını ister.
"""
from __future__ import annotations

import pytest

from karadul.config import Config
from karadul.reconstruction.engineering import semantic_namer as sn_mod
from karadul.reconstruction.engineering.semantic_namer import (
    SemanticParameterNamer,
    _FUNC_SIG_RE,
    _has_string_evidence,
    _pointer_template_evidence,
)

STR_AILESI = {"str", "text", "name", "string"}


def _adlar(code: str, paralel: bool = False) -> dict[str, str]:
    name = _FUNC_SIG_RE.search(code).group(1)
    if paralel:
        sn_mod._W_FUNC_CODES = {name: code}
        sn_mod._W_FUNCTIONS = {}
        try:
            params = sn_mod._worker_get_params(name)
            res = sn_mod._worker_infer_from_type_and_usage(name, params, code, "generic")
        finally:
            sn_mod._W_FUNC_CODES = {}
    else:
        namer = SemanticParameterNamer(Config())
        namer._func_codes = {name: code}
        params = namer._get_function_params(name)
        res = namer._infer_from_type_and_usage(name, params, code, "generic")
    return {s.original_name: s.semantic_name for s in res}


# cat rpl_fcntl'in biçimi: ulong param_3 yalnız fcntl'e geçiyor, dizgi kanıtı yok
RPL_FCNTL = (
    "int FUN_00103b80(int fd_2,uint cmd,ulong param_3)\n{\n"
    "  int __fd;\n"
    "  __fd = fcntl(fd_2,0,param_3 & 0xffffffff);\n"
    "  return __fd;\n}\n"
)


@pytest.mark.parametrize("paralel", [False, True])
def test_kanitsiz_tamsayi_parametre_str_almaz(paralel):
    assert _adlar(RPL_FCNTL, paralel).get("param_3") not in STR_AILESI


@pytest.mark.parametrize("paralel", [False, True])
def test_dizgi_islevine_arguman_str_alir(paralel):
    code = (
        "ulong FUN_00104000(ulong param_1)\n{\n"
        "  size_t n;\n"
        "  n = strlen((char *)param_1);\n"
        "  return n;\n}\n"
    )
    assert _adlar(code, paralel).get("param_1") in STR_AILESI


def test_dizgi_kaniti_bicimleri():
    assert _has_string_evidence("x = strcmp(param_1,\"-\");", "param_1")
    assert _has_string_evidence("x = strcmp(\"-\",(const char *)param_2);", "param_2")
    assert _has_string_evidence("__printf_chk(1,param_1,x);", "param_1")
    assert _has_string_evidence("x = _strlen(param_1);", "param_1")  # Mach-O öneki
    assert _has_string_evidence("c = *(char *)(param_1 + i);", "param_1")
    assert _has_string_evidence("if (*param_1 == '/') {", "param_1")
    assert _has_string_evidence("if (param_1[i] != '\\0') {", "param_1")
    # Dizgi konumu dışındaki argüman kanıt değildir (strncpy'nin uzunluğu)
    assert not _has_string_evidence("strncpy(a,b,param_1);", "param_1")
    # Dizgi sabitinin ya da yorumun içindeki metin kanıt değildir
    assert not _has_string_evidence('x = "strlen(param_1)";', "param_1")
    assert not _has_string_evidence("/* strlen(param_1) */ x = 1;", "param_1")
    # Ad tam sözcük
    assert not _has_string_evidence("strlen(param_10);", "param_1")
    # Dizgi işlevi olmayan çağrı
    assert not _has_string_evidence("fcntl(fd,0,param_1);", "param_1")


def test_isaretci_sablonu_kanit_kurali():
    code_bos = "void f(ulong p)\n{\n  g(p);\n}\n"
    # Bildirilen char * Ghidra'nın tip kanıtıdır
    assert _pointer_template_evidence("char *", "char *", code_bos, "p", False)
    assert _pointer_template_evidence("char *", "const char *", code_bos, "p", False)
    # void * / unsigned char * bildirilen tip dizgi kanıtı değildir
    assert not _pointer_template_evidence("char *", "void *", code_bos, "p", False)
    assert not _pointer_template_evidence("char *", "unsigned char *", code_bos, "p", False)
    # İşaretçi istisnası: öğe erişimi kanıtı
    assert not _pointer_template_evidence("char *", "ulong", code_bos, "p", False)
    assert not _pointer_template_evidence("int *", "ulong", code_bos, "p", False)
    assert not _pointer_template_evidence("unsigned char *", "long", code_bos, "p", False)
    assert not _pointer_template_evidence("void *", "undefined8", code_bos, "p", False)
    assert _pointer_template_evidence("int *", "ulong", "x = *(int *)(p + 4);", "p", False)
    assert not _pointer_template_evidence("int *", "ulong", "x = *(long *)(p + 4);", "p", False)
    assert _pointer_template_evidence(
        "unsigned char *", "long", "x = *(byte *)(p + i);", "p", False)
    assert _pointer_template_evidence("void *", "undefined8", "x = *(long *)p;", "p", False)
    # Kayan noktalı şablon P05 kuralıyla (float_ok)
    assert not _pointer_template_evidence("double *", "long", code_bos, "p", False)
    assert _pointer_template_evidence("double *", "long", code_bos, "p", True)
    # Skaler şablon bu kurala girmez
    assert _pointer_template_evidence("int", "ulong", code_bos, "p", False)


@pytest.mark.parametrize("paralel", [False, True])
def test_void_isaretci_kanitsiz_str_almaz(paralel):
    code = (
        "void FUN_00105000(void *param_1,char *param_2)\n{\n"
        "  if (param_1 == 0) {\n    return;\n  }\n"
        "  FUN_00106000(param_1,param_2);\n"
        "  return;\n}\n"
    )
    got = _adlar(code, paralel)
    assert got.get("param_1") not in STR_AILESI
    # Bildirilen char * dizgi şablonunu alır (kanal susturulmadı)
    assert got.get("param_2") in STR_AILESI


@pytest.mark.parametrize("paralel", [False, True])
def test_istisna_yolu_int_dizi_adi_kanit_ister(paralel):
    kanitsiz = (
        "void FUN_00107000(ulong param_1,int param_2)\n{\n"
        "  int i;\n"
        "  for (i = 0; i < param_2; i = i + 1) {\n"
        "    FUN_00108000(param_1,i);\n"
        "  }\n"
        "  return;\n}\n"
    )
    kanitli = kanitsiz.replace("FUN_00108000(param_1,i);", "*(int *)(param_1 + (long)i * 4) = 0;")
    assert _adlar(kanitsiz, paralel).get("param_1") != "index_array"
    assert _adlar(kanitli, paralel).get("param_1") == "index_array"
