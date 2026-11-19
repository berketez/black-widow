"""P12c kalem 3A: c_namer gövde çıkarıcısı çok satırlı ve iç parantezli imzayı görür.

Kusur (P12b yan bulgusu, P12c kalem 1): ``_extract_function_bodies`` fonksiyon başını
``ad\\s*\\([^)]*\\)\\s*\\{?\\s*$`` ile arıyordu. Ghidra uzun imzayı satırlara bölünce ya da
parametrede iç parantez olunca (işlev işaretçisi) gövde alınmıyordu; 14 ikilide 689 / 13 860
fonksiyon gövdeye bakan bütün stratejilere görünmezdi.

Sentetik metinler gerçek Ghidra biçimindedir (openssl ``FUN_001680a0`` ve zstd
``FUN_001bc5f0`` / ``FUN_001bca00`` çiftinden kısaltıldı).
"""
from __future__ import annotations

from karadul.config import Config
from karadul.reconstruction.c_namer import CVariableNamer, _FunctionInfo


def _namer(*names: str) -> CVariableNamer:
    n = CVariableNamer(Config())
    n._func_by_name = {a: _FunctionInfo(name=a, address=str(i)) for i, a in enumerate(names)}
    return n


P12C_COK_SATIRLI_METIN = """// Function: FUN_001680a0
// Callers:  1 (FUN_001686c4)
// Callees:  2 (BIO_printf, FUN_00168000)


bool FUN_001680a0(BIO *param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,long param_5
                 ,long param_6)

{
  BIO_printf(param_1,"%*s%s = %s\\n",4,"signature-digest-check",param_6);
  return true;
}
"""


def test_cok_satirli_imza_govdesi_alinir():
    n = _namer("FUN_001680a0", "BIO_printf", "FUN_00168000", "FUN_001686c4")
    n._extract_function_bodies(P12C_COK_SATIRLI_METIN)
    assert list(n._func_bodies) == ["FUN_001680a0"]
    # gövde imzanın ilk satırından başlar, iki satırlık imzayı (bir kez) ve kapanışı taşır
    beklenen = P12C_COK_SATIRLI_METIN.split("\n\n\n", 1)[1].rstrip("\n")
    assert n._func_bodies["FUN_001680a0"] == beklenen
    assert beklenen.startswith("bool FUN_001680a0(BIO *param_1,")
    assert '"signature-digest-check"' in beklenen


P12C_IC_PARANTEZ_METIN = """// Function: FUN_00100400

void FUN_00100400(code *param_1,void (*param_2)(int,long),long param_3)

{
  (*param_2)(1,param_3);
  return;
}
"""


def test_ic_parantezli_imza_govdesi_alinir():
    n = _namer("FUN_00100400")
    n._extract_function_bodies(P12C_IC_PARANTEZ_METIN)
    assert "FUN_00100400" in n._func_bodies
    assert "(*param_2)(1,param_3);" in n._func_bodies["FUN_00100400"]


# zstd'deki gerçek çift: çağıranın gövdesinde çağrı iki satıra bölünmüş (``)`` satır sonunda,
# ``;`` alt satırda). Çağıranın imzası çok satırlıyken eski kod çağıranı görmüyor, çağrı
# satırını callee'nin tanımı sanıp çağıranın gövdesini callee'ye yazıyordu.
P12C_CAGIRAN_METIN = """// Function: FUN_001bca00

ulong FUN_001bca00(long param_1,long param_2,long param_3,long param_4,ulong param_5,ulong param_6,
                  undefined8 param_7)

{
  ulong uVar4;

  uVar4 = FUN_001bc5f0(param_1,param_6,param_5,param_2,param_3,param_4,param_7,param_5)
  ;
  return uVar4;
}
"""

P12C_CALLEE_METIN = """// Function: FUN_001bc5f0

ulong FUN_001bc5f0(long param_1,long param_2,long param_3,long param_4,ulong param_5,ulong param_6,
                  undefined8 param_7,ulong param_8)

{
  return param_1 + param_8;
}
"""


def test_cagri_satiri_tanim_sayilmaz_ve_callee_govdesi_dogru():
    n = _namer("FUN_001bca00", "FUN_001bc5f0")
    for metin in (P12C_CALLEE_METIN, P12C_CAGIRAN_METIN):  # dosyalar ad sırasıyla okunur
        n._extract_function_bodies(metin)
    assert set(n._func_bodies) == {"FUN_001bca00", "FUN_001bc5f0"}
    assert "return param_1 + param_8;" in n._func_bodies["FUN_001bc5f0"]
    assert "uVar4 = FUN_001bc5f0(" not in n._func_bodies["FUN_001bc5f0"]
    assert "uVar4 = FUN_001bc5f0(" in n._func_bodies["FUN_001bca00"]


def test_cok_satirli_cagri_ve_kosul_tanim_degil():
    """Gövdesi alınmayan bölgede (ör. tanımı bilinmeyen fonksiyonun gövdesi) bölünmüş çağrı,
    koşul içindeki çağrı ve dizgideki parantez tanım başlatmaz."""
    metin = """  FUN_00100500(param_1,
               param_2);
  if (FUN_00100500(param_1,
                   param_2)) {
    return;
  }
  puts("FUN_00100500(x)");
"""
    n = _namer("FUN_00100500")
    n._extract_function_bodies(metin)
    assert n._func_bodies == {}


def test_kesik_metinde_acik_parantez_tanim_uydurmaz():
    """Parantez açıkken `{` ya da `;` görülürse imza değildir (Ghidra çıktısı kesik kalabilir);
    tarama sonraki bir `)` satırına kadar sürüp sahte tanım kurmaz."""
    metin = """  FUN_00100500(param_1,
  {
    uVar1 = 1;
  }
  )
"""
    n = _namer("FUN_00100500")
    n._extract_function_bodies(metin)
    assert n._func_bodies == {}


def test_tek_satirli_imza_davranisi_ayni():
    metin = """// Function: FUN_00100600

int FUN_00100600(int param_1)

{
  return param_1 + 1;
}

// Function: FUN_00100700

void FUN_00100700(void) {
  FUN_00100600(2);
}
"""
    n = _namer("FUN_00100600", "FUN_00100700")
    n._extract_function_bodies(metin)
    assert n._func_bodies == {
        "FUN_00100600": "int FUN_00100600(int param_1)\n\n{\n  return param_1 + 1;\n}",
        "FUN_00100700": "void FUN_00100700(void) {\n  FUN_00100600(2);\n}",
    }


def test_belirlenimci():
    a = _namer("FUN_001bca00", "FUN_001bc5f0", "FUN_001680a0", "FUN_00100400")
    b = _namer("FUN_00100400", "FUN_001680a0", "FUN_001bc5f0", "FUN_001bca00")
    for n in (a, b):
        for metin in (P12C_CALLEE_METIN, P12C_CAGIRAN_METIN, P12C_COK_SATIRLI_METIN, P12C_IC_PARANTEZ_METIN):
            n._extract_function_bodies(metin)
    assert a._func_bodies == b._func_bodies
    assert len(a._func_bodies) == 4
