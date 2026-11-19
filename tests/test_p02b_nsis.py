"""P02b kalem 4: NSIS derleyicisi (makensis.exe) NSIS kurucusu sanılmıyor.

Eski davranış (taban 0984090): "Nullsoft.NSIS.exehead" / "NSIS Error" dizgisi tek
başına NSIS kurucusu iddiası kuruyordu (0,92). Derleyici makensis.exe kurucu
saplamasını veri olarak taşıdığı için bu dizgiler onda da var (masum PE setinde
makensis.exe → "NSIS"). Kurucu = saplama + ek veri; ek verinin başındaki
firstheader (0xDEADBEEF + "NullsoftInst", 512 bayta hizalı) yalnız kurucuda olur.
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from karadul.analyzers.packer_fingerprint import (
    PackerFingerprintDetector,
    nsis_firstheader_offset,
    pe_overlay_start,
)
from scripts.measurement.p02_pozitif.pe_sentetik import pe_olustur

NSIS_KOK = Path("/opt/homebrew/Cellar/makensis/3.13/share/nsis")
FIRSTHEADER = struct.pack("<I", 0) + b"\xef\xbe\xad\xdeNullsoftInst" + struct.pack("<II", 0x40, 0x80)
SAPLAMA_DIZGISI = b"\0Nullsoft.NSIS.exehead\0NSIS Error\0"
OLAGAN_KOD = bytes.fromhex("558bec31c05dc3")


def _saplama() -> bytes:
    """NSIS dizgileri .rdata'da, ek veri yok (derleyicinin taşıdığı saplama gibi)."""
    return pe_olustur("x86", OLAGAN_KOD, {}, tuzak=SAPLAMA_DIZGISI)


def _kurucu(hizali: bool = True) -> bytes:
    veri = bytearray(_saplama())
    while len(veri) % 512:
        veri += b"\0"
    if not hizali:
        veri += b"\0" * 8
    veri += FIRSTHEADER + b"\x5a" * 0x80
    return bytes(veri)


def _paketleyiciler(veri: bytes) -> dict:
    return {f.packer_name: f for f in PackerFingerprintDetector("x", _data=veri).detect()}


class TestSentetik:
    def test_ek_verisiz_saplama_nsis_degil(self):
        """Derleyici biçimi: dizgiler var, ek veri yok → iddia yok (eski: NSIS 0,92)."""
        assert "NSIS" not in _paketleyiciler(_saplama())

    def test_kurucu_nsis(self):
        veri = _kurucu()
        f = _paketleyiciler(veri)["NSIS"]
        off = nsis_firstheader_offset(veri)
        assert off is not None and off % 512 == 0 and off >= pe_overlay_start(veri)
        assert any("firstheader" in e and f"@0x{off:x}" in e for e in f.evidence)
        assert f.confidence == pytest.approx(0.92)

    def test_hizasiz_baslik_sayilmaz(self):
        assert nsis_firstheader_offset(_kurucu(hizali=False)) is None
        assert "NSIS" not in _paketleyiciler(_kurucu(hizali=False))

    def test_bolum_icindeki_baslik_sayilmaz(self):
        """İmza bölüm verisinin içinde (ek veri değil), 512'ye hizalı: yine sayılmaz."""
        def kur(dolgu: int) -> bytes:
            return pe_olustur("x86", OLAGAN_KOD, {},
                              tuzak=SAPLAMA_DIZGISI + b"\0" * dolgu + FIRSTHEADER)
        konum = kur(0).find(FIRSTHEADER)
        veri = kur((512 - konum % 512) % 512)
        konum = veri.find(FIRSTHEADER)
        assert konum % 512 == 0 and konum < pe_overlay_start(veri)
        assert nsis_firstheader_offset(veri) is None
        assert "NSIS" not in _paketleyiciler(veri)

    def test_pe_disi_nsis_yok(self):
        assert nsis_firstheader_offset(b"\x7fELF" + b"\0" * 600 + FIRSTHEADER) is None


@pytest.mark.skipif(not NSIS_KOK.exists(), reason="makensis 3.13 (Homebrew) yok")
class TestGercek:
    def test_derleyici_makensis_nsis_degil(self):
        assert "NSIS" not in _paketleyiciler((NSIS_KOK / "Bin/makensis.exe").read_bytes())

    def test_gercek_kurucu_nsis_exe(self):
        """NSIS dağıtımındaki NSIS.exe NSIS ile derlenmiş gerçek bir kurucu (firstheader @0x12c00)."""
        f = _paketleyiciler((NSIS_KOK / "NSIS.exe").read_bytes())["NSIS"]
        assert any("@0x12c00" in e for e in f.evidence)
