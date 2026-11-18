"""P05 kalem 2 (MUH-02): döngü derinliği gerçek döngü yapısından; matris/vektör adı kanıtla.

Eskiden "döngü derinliği" satırdaki süslü parantezlerin toplamıydı: fonksiyon gövdesi 1, gövdedeki
her ``if`` bloğu 2 sayılıyordu ve ``if`` içinde geçen her ``long/ulong/undefined8`` parametre
``M_matrix`` / ``v_vector`` oluyordu (59 ikili, 308 ad; coreutils'te 78).
"""
from __future__ import annotations

import pytest

from karadul.config import Config
from karadul.reconstruction.engineering import semantic_namer as sn_mod
from karadul.reconstruction.engineering.semantic_namer import (
    SemanticParameterNamer,
    _get_loop_depth_for_param,
    _has_float_access,
    _worker_infer_from_type_and_usage,
)

FCNTL = (
    "int FUN_00103b80(int fd_2,uint cmd,ulong param_3)\n\n{\n"
    "  int __fd;\n"
    "  if (cmd == 0) {\n"
    "    __fd = fcntl(fd_2,0,param_3 & 0xffffffff);\n"
    "    if (__fd < 0) {\n"
    "      __fd = fcntl(fd_2,1,param_3);\n"
    "    }\n"
    "  }\n"
    "  return __fd;\n}\n"
)

MATMUL = (
    "void FUN_00101000(double *param_1,double *param_2,double *param_3,int param_4)\n\n{\n"
    "  int i;\n  int j;\n  int k;\n"
    "  for (i = 0; i < param_4; i = i + 1) {\n"
    "    for (j = 0; j < param_4; j = j + 1) {\n"
    "      for (k = 0; k < param_4; k = k + 1) {\n"
    "        param_3[i * param_4 + j] = param_3[i * param_4 + j] +"
    " param_1[i * param_4 + k] * param_2[k * param_4 + j];\n"
    "      }\n"
    "    }\n"
    "  }\n"
    "  return;\n}\n"
)

# Ghidra'nın işaretçiyi ``ulong`` gösterdiği, öğeleri kayan noktalı okunan üç katlı döngü
MATMUL_ULONG = (
    "void FUN_00102000(ulong param_1,int param_2)\n\n{\n"
    "  int i;\n  int j;\n  int k;\n  double acc;\n"
    "  for (i = 0; i < param_2; i = i + 1) {\n"
    "    for (j = 0; j < param_2; j = j + 1) {\n"
    "      for (k = 0; k < param_2; k = k + 1) {\n"
    "        acc = acc + *(double *)(param_1 + (long)(i * param_2 + k) * 8) *\n"
    "              *(double *)(param_1 + (long)(k * param_2 + j) * 8);\n"
    "      }\n"
    "    }\n"
    "  }\n"
    "  return;\n}\n"
)

# Aynı yapı, ama öğeler tamsayı okunuyor: kayan noktalı kanıt yok
LOOP_ULONG_INT = MATMUL_ULONG.replace("*(double *)", "*(long *)").replace("double acc", "long acc")


def test_if_blogu_dongu_sayilmaz():
    assert _get_loop_depth_for_param(FCNTL, "param_3") == 0


def test_uc_katli_dongu():
    assert _get_loop_depth_for_param(MATMUL, "param_1") == 3
    # döngü başlığındaki kullanım dıştaki derinlikte sayılır
    assert _get_loop_depth_for_param(MATMUL, "param_4") == 3  # gövdede de geçiyor
    code = "void f(int param_2)\n{\n  int i;\n  for (i = 0; i < param_2; i++) {\n    g(i);\n  }\n}\n"
    assert _get_loop_depth_for_param(code, "param_2") == 0


def test_while_ve_do_dongusu():
    code = (
        "void f(long param_1)\n{\n  while( true ) {\n    do {\n      x = param_1;\n"
        "    } while (x != 0);\n  }\n}\n"
    )
    assert _get_loop_depth_for_param(code, "param_1") == 2


def test_tam_sozcuk_eslesmesi():
    code = (
        "void f(long param_1,long param_10)\n{\n  int i;\n"
        "  for (i = 0; i < 4; i++) {\n    g(param_10);\n  }\n  h(param_1);\n}\n"
    )
    assert _get_loop_depth_for_param(code, "param_1") == 0
    assert _get_loop_depth_for_param(code, "param_10") == 1


def test_dizgi_ve_yorum_icindeki_ayrac_sayilmaz():
    code = (
        "void f(long param_1)\n{\n  /* for (;;) { */\n  puts(\"while (1) {\");\n"
        "  g(param_1);\n}\n"
    )
    assert _get_loop_depth_for_param(code, "param_1") == 0


def test_kayan_nokta_kaniti():
    assert _has_float_access(MATMUL, "param_1", "double *")
    assert _has_float_access(MATMUL_ULONG, "param_1", "ulong")
    assert not _has_float_access(LOOP_ULONG_INT, "param_1", "ulong")
    assert not _has_float_access(FCNTL, "param_3", "ulong")


def _params(code: str, types: dict[str, str] | None) -> tuple[str, list[dict]]:
    """İmzadan parametreler; ``types`` verilirse functions.json'daki gibi tipli liste.

    Not: koddan ayrıştırmada ``double *param_1`` tipi ``double`` okunur (yıldız adın
    yanında olduğu için; P05 kapsamı dışında, P05.md "riskler"). Tipli liste gerçek
    ``double *`` parametreyi sınamak içindir.
    """
    name = sn_mod._FUNC_SIG_RE.search(code).group(1)
    namer = SemanticParameterNamer(Config())
    namer._func_codes = {name: code}
    if types:
        namer._functions = {name: {"params": [
            {"name": n, "type": t, "position": i} for i, (n, t) in enumerate(types.items())
        ]}}
    return name, namer._get_function_params(name)


def _seq(code: str, types: dict[str, str] | None = None) -> dict[str, str]:
    name, params = _params(code, types)
    namer = SemanticParameterNamer(Config())
    out = namer._infer_from_type_and_usage(name, params, code, "generic")
    return {s.original_name: s.semantic_name for s in out}


def _par(code: str, types: dict[str, str] | None = None) -> dict[str, str]:
    name, params = _params(code, types)
    out = _worker_infer_from_type_and_usage(name, params, code, "generic")
    return {s.original_name: s.semantic_name for s in out}


_MV_ADLARI = {"M_matrix", "v_vector", "K_matrix", "A_matrix", "u_vector", "phi_vector"}


@pytest.mark.parametrize("yol", [_seq, _par], ids=["dizisel", "paralel"])
def test_if_icindeki_ulong_matris_olmaz(yol):
    names = yol(FCNTL)
    assert names.get("param_3") not in _MV_ADLARI | {"scalar_ref"}


@pytest.mark.parametrize("yol", [_seq, _par], ids=["dizisel", "paralel"])
def test_gercek_matris_carpimi_adi_korunur(yol):
    types = {"param_1": "double *", "param_2": "double *", "param_3": "double *",
             "param_4": "int"}
    names = yol(MATMUL, types)
    assert names["param_1"] == "M_matrix"
    assert names["param_2"] == "M_matrix"
    assert names["param_3"] == "M_matrix"


@pytest.mark.parametrize("yol", [_seq, _par], ids=["dizisel", "paralel"])
def test_ulong_isaretci_kayan_nokta_kanitiyla_matris(yol):
    assert yol(MATMUL_ULONG)["param_1"] == "M_matrix"
    assert yol(LOOP_ULONG_INT).get("param_1") not in _MV_ADLARI | {"scalar_ref"}
