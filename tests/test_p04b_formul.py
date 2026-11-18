"""P04b / MUH-12: formül çıkarıcı belirsiz / zayıf tespiti belirli bir algoritmaya yükseltmez.

Eski eşleme alias'ı tespit adında alt dizgi olarak arıyordu: redis'te
"S-box substitution (AES, DES)" (`dumpX86Calls`) → DES formülü, "Password-based key
derivation (PBKDF2, scrypt)" (`from_chars_advanced`) → PBKDF2 formülü. Bu testler eski
kodda kırmızıdır.
"""
from __future__ import annotations

import pytest

from karadul.reconstruction.c_algorithm_id import AlgorithmMatch
from karadul.reconstruction.engineering import FormulaReconstructor
from karadul.reconstruction.engineering import formula_reconstructor as F


def _m(name: str, func: str = "f", conf: float = 0.5, method: str = "structural") -> AlgorithmMatch:
    return AlgorithmMatch(name=name, category="symmetric_cipher", confidence=conf,
                          detection_method=method, evidence=[], function_name=func,
                          address="0x1")


@pytest.fixture()
def fr() -> FormulaReconstructor:
    return FormulaReconstructor()


@pytest.mark.parametrize("name", [
    "S-box substitution (AES, DES)",
    "Password-based key derivation (PBKDF2, scrypt)",
    "Elliptic curve operations (ECDSA, ECDH)",
    "Galois field operations (ECC, AES-GF)",
    "BLAKE2/SHA-512",
    "Hash function rounds (SHA, MD5)",
])
def test_belirsiz_tespit_formul_almaz(fr, name):
    assert fr.reconstruct([_m(name, "dumpX86Calls")]) == []


@pytest.mark.parametrize("name", ["AES-256-CBC with desync", "rounds", "cbc", "des3_variant_x"])
def test_alt_dizgi_ve_ters_alt_dizgi_eslesmez(fr, name):
    assert fr.match_detection(name) is None


def test_redis_ornegi(fr):
    algos = [_m("S-box substitution (AES, DES)", "dumpX86Calls"),
             _m("Password-based key derivation (PBKDF2, scrypt)", "from_chars_advanced_double_char_")]
    assert fr.reconstruct(algos) == []


def test_tam_ad_formul_ve_kaynak_fonksiyon(fr):
    algos = [_m("PBKDF2", "PKCS5_PBKDF2_HMAC", 0.9, "api"),
             _m("PBKDF2", "kdf_pbkdf2_derive", 0.85, "api"),
             _m("Password-based key derivation (PBKDF2, scrypt)", "usage")]
    out = fr.reconstruct(algos)
    assert [f.algorithm for f in out] == ["pbkdf2"]
    assert out[0].functions == ["PKCS5_PBKDF2_HMAC", "kdf_pbkdf2_derive"]
    assert out[0].detected_as == ["PBKDF2"]
    assert out[0].detection_confidence == 0.9
    d = out[0].to_dict()
    assert d["functions"] == ["PKCS5_PBKDF2_HMAC", "kdf_pbkdf2_derive"]
    assert d["confidence_note"] == "uncalibrated detector score"


def test_gauss_gercek_pozitif(fr):
    # CalculiX _e_c3d_se_: sabit katmanının Gauss 3 nokta tespiti formül alır.
    out = fr.reconstruct([_m("gauss_quadrature_3pt", "_e_c3d_se_", 0.9, "constant")])
    assert len(out) == 1 and out[0].functions == ["_e_c3d_se_"]


def test_sablonlar_paylasilmaz(fr):
    fr.reconstruct([_m("PBKDF2", "a")])
    assert F.FORMULA_TEMPLATES["pbkdf2"].functions == []


def test_otomatik_ascii_isleç_kaybi_gosterilmez(fr):
    # pbkdf2 (otomatik): "DK = T_1 | T_2 | , T_i = U_1 U_2 U_c" — \oplus ve \ldots kayıp.
    assert "pbkdf2" in F.ASCII_OMITTED_TEMPLATES
    out = fr.reconstruct([_m("PBKDF2", "a")])
    assert out[0].ascii == "" and out[0].ascii_omitted
    rapor = fr.generate_report(out)
    assert "omitted" in rapor and "U_1 U_2" not in rapor
    assert "`a`" in rapor


def test_isleç_kaybi_denetimi():
    assert F.ascii_lost_operators(r"C_i = E_K(P_i \oplus C_{i-1})", "C_i = E_K(P_i C_i-1)") == [r"\oplus"]
    assert F.ascii_lost_operators(r"C_i = E_K(P_i \oplus C_{i-1})", "C_i = E_K(P_i XOR C_i-1)") == []
    assert F.ascii_lost_operators(r"x = \frac{a}{b}", "x = a / b") == []


def test_el_yazimi_sablon_ascii_korunur(fr):
    # Elle yazılmış şablonların ASCII'sine dokunulmaz (yalnız "Auto-generated" denetlenir).
    hand = [k for k, t in F.FORMULA_TEMPLATES.items() if "Auto-generated" not in t.reference]
    assert hand and not (set(hand) & F.ASCII_OMITTED_TEMPLATES)
