"""P04b / MUH-10: mühendislik çözümleyicisinin sabit katmanı, yapısal katmanı ve alan kapısı.

Eski kural ondalık sabiti gövdede alt dizgi olarak arıyordu (``"0" in code`` → RC4 %90);
kapı ``func_meta.keys()`` üstünde dolaştığı için ad taraması ölüydü ve göstergeler alt
dizgiyle eşleşiyordu (``fft`` ⊂ ``_difftime``). Bu testler eski kodda kırmızıdır.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from karadul.reconstruction.engineering import analyzer as A
from karadul.reconstruction.engineering.analyzer import EngineeringAlgorithmAnalyzer


@pytest.fixture(scope="module")
def an() -> EngineeringAlgorithmAnalyzer:
    return EngineeringAlgorithmAnalyzer()


def _names(matches) -> set[str]:
    return {m.name for m in matches}


# ---------------------------------------------------------------------------
# Sabit katmanı: masum gövdeler
# ---------------------------------------------------------------------------

# coreutils sort'un gerçek gövdesine benzeyen, küçük tam sayılarla dolu kod (eski kod: RC4 0,90,
# Halton 0,90 …).
_SORT_LIKE = """
{
  int iVar1;
  long lVar2;
  if (param_1 == 0) {
    iVar1 = 4;
  }
  lVar2 = (long)param_2 * 8 + 6;
  for (iVar1 = 0; iVar1 < 10; iVar1 = iVar1 + 1) {
    *(int *)(lVar2 + 9) = 7 + 11 + 13 + 3;
  }
  return 0;
}
"""


def test_kucuk_tam_sayilar_sabit_kaniti_degil(an):
    assert an._scan_constants(_SORT_LIKE, "FUN_00103b80", "0x103b80") == []


def test_if_x_esittir_0_y_4(an):
    assert an._scan_constants("{ if (x == 0) y = 4; }", "f", "0x1") == []


def test_dizgi_ve_yorumdaki_sabit_sayilmaz(an):
    body = (
        '{\n  puts("0.7745966692414834 0.5555555555555556 0.8888888888888888");\n'
        "  /* 0.7745966692414834 0.5555555555555556 */\n"
        "  // 0.8888888888888888\n  return 0;\n}\n"
    )
    assert an._scan_constants(body, "usage", "0x1") == []


def test_alt_dizgi_degil_tam_belirtec(an):
    # 10.7745966692414834 ve 0.55555555555555561 başka sayılar; Gauss sabitinin öneki değil.
    body = "{ a = 10.7745966692414834 * b; c = d * 0.888888888888888899e3; }"
    assert "gauss_quadrature_3pt" not in _names(an._scan_constants(body, "f", "0x1"))


def test_tam_sayi_belirteci_double_sabit_degil(an):
    # SHA-256 başlangıç değerlerinin ondalık yazımı: tam sayı belirteci double değildir;
    # kripto sabiti tespiti c_algorithm_id'nin işi (ab986da), bu katman IEEE-754 içindir.
    body = "{ h[0] = 1779033703; h[1] = 3144134277; h[2] = 1013904242; h[3] = 2773480762; }"
    assert an._scan_constants(body, "f", "0x1") == []


def test_tek_ayirt_edici_sabit_etiket_vermez(an):
    body = "{ x = y * 0.7745966692414834; return x; }"
    assert an._scan_constants(body, "f", "0x1") == []


def test_basit_kesirler_rk4_degil(an):
    # Ghidra'nın 1/3 ve 1/6 yazımı (CalculiX'te 29 fonksiyona "runge_kutta_4" yazılıyordu).
    body = "{ v = (a + b + c) * 0.333333333333333 + d * 0.166666666666667; }"
    assert an._scan_constants(body, "_e_c3d_em_", "0x1") == []


def test_zayif_degerler():
    for v in (0.0, 4.0, 0.95, 1.4, 1e-6, 100.0, 0.5, 0.375, 2.25, 252.0, 1708.0,
              1 / 3, 1 / 6, 2 / 3):
        assert A.is_weak_double(v), v
    for v in (0.7745966692414834, 5 / 9, 8 / 9, 101325.0, 0.5773502691896258, 1.645):
        assert not A.is_weak_double(v), v


# ---------------------------------------------------------------------------
# Sabit katmanı: gerçek pozitif
# ---------------------------------------------------------------------------

def test_gauss_3_nokta_ondalik(an):
    # CalculiX _e_c3d_se_'deki Ghidra yazımı.
    body = (
        "{\n  dVar1 = -0.774596669241483;\n  dVar2 = 0.555555555555555 * dVar3;\n"
        "  dVar4 = 0.888888888888888 * dVar5;\n}\n"
    )
    m = [x for x in an._scan_constants(body, "_e_c3d_se_", "0x1") if x.name == "gauss_quadrature_3pt"]
    assert len(m) == 1
    assert m[0].detection_method == "constant"
    assert len(m[0].evidence) == 3


def test_gauss_3_nokta_ieee_onaltilik(an):
    body = "{ *(undefined8 *)p = 0x3fe8c97ef43f7248; *(undefined8 *)q = 0x3fec71c71c71c71c; }"
    assert "gauss_quadrature_3pt" in _names(an._scan_constants(body, "f", "0x1"))


def test_isaret_esi_tek_sabit(an):
    # ±sqrt(3/5) tek sabittir; ikinci ayırt edici değer yoksa etiket yok.
    body = "{ a = 0.7745966692414834; b = -0.7745966692414834; }"
    assert "gauss_quadrature_3pt" not in _names(an._scan_constants(body, "f", "0x1"))


# ---------------------------------------------------------------------------
# Yapısal katman
# ---------------------------------------------------------------------------

def test_anahtar_sozcuk_deseni_kanit_degil(an):
    # pid_controller deseni yalnız sözcüklerden oluşuyor (pid, error, integral …).
    body = "{ pid = getpid(); error = integral + derivative; controller(pid, error); }"
    assert "pid_controller" not in _names(an._scan_structural(body, "f", "0x1"))


def test_ayni_metin_iki_desen_iki_kanit_degil(an):
    # nelder_mead'in iki regex'i aynı satırı eşliyor (Mac tmux FUN_10008f9b0).
    body = "{ uVar2 = iVar6 + iVar12 * (uVar9 - uVar15); return uVar2; }"
    assert "nelder_mead" not in _names(an._scan_structural(body, "f", "0x1"))


def test_dizgideki_yapi_sayilmaz(an):
    body = '{ puts("x = a + b * (c - d); y = a - b * (c - d);"); }'
    assert an._scan_structural(body, "f", "0x1") == []


def test_keyword_regex_siniflamasi():
    assert A.is_keyword_regex(r"(?i)\bpid\b")
    assert A.is_keyword_regex(r"(?i)\btwo\ loop\ recursion\b")
    assert not A.is_keyword_regex(r"\w+\s*=\s*\w+\s*\+\s*\w+\s*\*\s*\(\s*\w+\s*-\s*\w+\s*\)")


def test_yapisal_desen_iki_farkli_metinle_etiket_verir(an):
    # Aynı iki regex iki AYRI satırda: ikinci satır yeni kanıttır (pozitif bekçi).
    body = "{ a = b + c * (d - e); f = g - h * (i - j); return a; }"
    hits = [m for m in an._scan_structural(body, "f", "0x1") if m.name == "nelder_mead"]
    assert len(hits) == 1
    assert hits[0].detection_method == "structural"
    assert hits[0].confidence <= A._STRUCTURAL_ONLY_CAP


# ---------------------------------------------------------------------------
# Alan kapısı
# ---------------------------------------------------------------------------

def _funcs(*names: str) -> dict:
    return {"total": len(names), "program": "x",
            "functions": [{"name": n, "address": "0x1"} for n in names]}


def test_kapi_bugunku_json_bicimini_okur():
    assert EngineeringAlgorithmAnalyzer._detect_domain(_funcs("main", "dgesv_"), []) is True
    assert EngineeringAlgorithmAnalyzer._detect_domain(_funcs("main", "_mafillsm_"), []) is True
    assert EngineeringAlgorithmAnalyzer._detect_domain(_funcs("PetscInitialize"), []) is True


def test_kapi_alt_dizgiyle_acilmaz():
    # Mac htop: _difftime ⊃ fft; coreutils: bindtextdomain ⊃ dt.
    assert EngineeringAlgorithmAnalyzer._detect_domain(
        _funcs("_difftime", "bindtextdomain", "_DT_INIT", "transform_fields"), []) is False


def test_kiril_harf_yok():
    for ind in A._ALL_DOMAIN_INDICATORS:
        assert ind.isascii(), ind
    assert "snessolve" in A._FEA_INDICATORS


def test_kapi_dosya_taramasi_dizgiyi_saymaz(tmp_path: Path):
    f = tmp_path / "FUN_1.c"
    f.write_text('void FUN_1(void) {\n  puts("uses fftw and torch");\n  difftime(a, b);\n}\n')
    assert EngineeringAlgorithmAnalyzer._detect_domain({}, [f]) is False
    g = tmp_path / "FUN_2.c"
    g.write_text("void FUN_2(void) {\n  fftw_execute(plan);\n}\n")
    assert EngineeringAlgorithmAnalyzer._detect_domain({}, [g]) is True


def test_identify_kapi_kapaliyken_sabit_kosmaz(tmp_path: Path, an):
    dec = tmp_path / "decompiled"
    dec.mkdir()
    (dec / "FUN_1.c").write_text(
        "void FUN_1(void) {\n  a = 0.774596669241483; b = 0.555555555555555;"
        " c = 0.888888888888888;\n}\n")
    fj = tmp_path / "ghidra_functions.json"
    fj.write_text(json.dumps(_funcs("FUN_1", "_difftime")))
    res = an.identify(dec, fj)
    assert res.success and res.total_detected == 0
    fj.write_text(json.dumps(_funcs("FUN_1", "dgemm_")))
    res = an.identify(dec, fj)
    assert "gauss_quadrature_3pt" in {m.name for m in res.algorithms}
