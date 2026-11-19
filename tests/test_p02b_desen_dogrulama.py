"""P02b kalem 5: gerçek örnekle doğrulanmamış paketleyici desenleri etiket taşır (K-1).

FSG / Petite / MPRESS / ASPack / VMProtect (ve tablodaki öbür paketleyiciler)
yerelde gerçek bir paketlenmiş örnekle sınanmadı; desenleri yalnız sentetik
saplamayla denendi. İddiaları ``pattern_verified=False`` ve kanıt listesinde
"desen dogrulanmadi" satırı taşır. Gerçek örnekle doğrulananlar (UPX, NSIS,
PyInstaller) etiketsiz kalır.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import karadul.analyzers.packer_fingerprint as pf
from karadul.analyzers.packer_fingerprint import PackerFingerprintDetector
from scripts.measurement.p02_pozitif.pe_sentetik import pe_olustur

ETIKET = "desen dogrulanmadi"
FSG_SAPLAMA = bytes.fromhex("bbd0014000bf00104000be00000000")
PETITE_SAPLAMA = bytes.fromhex("b800104000669c60e800000000")
ASPACK_SAPLAMA = bytes.fromhex("60e803000000e9eb045d")
MPRESS_SAPLAMA = bytes.fromhex("60e8000000005831c0c3")
UPX_SAPLAMA = bytes.fromhex("60be004041008dbe00d0feff5783cdffeb10909090909090")
POZITIF = Path.home() / "karadul_olcum/masum_kapi/pozitif"


def _bulgular(veri: bytes) -> dict:
    return {f.packer_name: f for f in PackerFingerprintDetector("x", _data=veri).detect()}


@pytest.mark.parametrize("ad, saplama", [
    ("FSG", FSG_SAPLAMA), ("Petite", PETITE_SAPLAMA),
    ("ASPack", ASPACK_SAPLAMA), ("MPRESS", MPRESS_SAPLAMA),
])
def test_giris_deseni_dogrulanmadi_etiketi(ad, saplama):
    f = _bulgular(pe_olustur("x86", saplama, {}))[ad]
    assert f.pattern_verified is False
    assert any(ETIKET in e for e in f.evidence)
    d = f.to_dict()
    assert d["pattern_verified"] is False and ETIKET in d["verification"]


def test_vmprotect_dizgisi_dogrulanmadi_etiketi():
    veri = pe_olustur("x86", bytes.fromhex("558bec5dc3"), {}, tuzak=b"\0VMProtect begin\0")
    f = _bulgular(veri)["VMProtect"]
    assert f.pattern_verified is False
    assert any(ETIKET in e for e in f.evidence)


def test_upx_etiketsiz():
    f = _bulgular(pe_olustur("x86", UPX_SAPLAMA, {}))["UPX"]
    assert f.pattern_verified is True
    assert not any(ETIKET in e for e in f.evidence)
    assert "gercek ornekle dogrulandi" in f.verification


def test_etiket_bir_kez():
    """Etiket katman sayısından bağımsız tek satır; güveni değiştirmez."""
    veri = pe_olustur("x86", ASPACK_SAPLAMA, {})
    f = _bulgular(veri)["ASPack"]
    assert sum(ETIKET in e for e in f.evidence) == 1
    assert f.confidence == pytest.approx(0.78)


def test_dogrulananlar_tablosu_dar():
    """Doğrulanan küme yalnız gerçek örneği olanlar: kalemde adı geçen beşi içinde değil."""
    assert set(pf._REAL_SAMPLE_VERIFIED) == {"UPX", "NSIS", "PyInstaller"}


@pytest.mark.skipif(not (POZITIF / "upx_t32.exe").exists(), reason="masum kapı pozitif seti yok")
def test_gercek_upx_dogrulandi():
    f = _bulgular((POZITIF / "upx_t32.exe").read_bytes())["UPX"]
    assert f.pattern_verified is True and f.confidence >= 0.9
