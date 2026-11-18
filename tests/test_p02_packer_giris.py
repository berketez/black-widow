"""P02 / IMZA-04: paketleyici giriş noktası desenleri yalnız PE giriş noktasında, yalnız
kendi mimarisinde ve en az 6 baytlık (maskeli) desenle aranır.

Eski davranış (taban e9d2d08): ``detect_by_entry_pattern`` AddressOfEntryPoint'i
okumuyor, deseni dosyanın ilk 0x2000-0x4000 baytının herhangi bir yerinde
arıyordu; FSG kuralı tek ``0xBB`` baytıydı (masum PE'lerin 30/39'u "FSG", ARM64
PE dahil), UPX kuralı iki bayt (``60 BE``), Petite üç bayt (``66 9C 60``).
Ayrıca ``layers_matched`` aynı katmanın her kuralını ayrı katman sayıyordu.
"""

from __future__ import annotations

import struct
from pathlib import Path
from unittest import mock

import pytest

import karadul.analyzers.packer_fingerprint as pf
from karadul.analyzers.packer_fingerprint import PackerFingerprintDetector, parse_pe_layout
from scripts.measurement.p02_pozitif.pe_sentetik import pe_olustur

UPX_SAPLAMA = bytes.fromhex("60be004041008dbe00d0feff5783cdffeb10909090909090")  # UPX 5.3.0 w32
FSG_SAPLAMA = bytes.fromhex("bbd0014000bf00104000be00000000")
ASPACK_SAPLAMA = bytes.fromhex("60e803000000e9eb045d")
OLAGAN_GIRIS = bytes.fromhex("558bec83ec10bb0100000053e8000000005b5dc3")  # push ebp; mov ebp,esp …


def _pe(kod: bytes, mimari: str = "x86") -> bytes:
    return pe_olustur(mimari, kod, {})


def _adlar(veri: bytes) -> dict[str, object]:
    return {f.packer_name: f for f in PackerFingerprintDetector("x", _data=veri).detect_by_entry_pattern()}


class TestGirisNoktasi:
    def test_giris_ofseti_hesaplanir(self):
        veri = _pe(UPX_SAPLAMA)
        pe = parse_pe_layout(veri)
        assert pe is not None and pe.arch == "x86"
        assert pe.rva_to_offset(pe.entry_rva, len(veri)) == 0x200

    def test_olagan_giriste_fsg_yok(self):
        """Girişte olağan prolog, ilk baytlarda 0xBB var: FSG DEĞİL (eski: FSG 0,3)."""
        assert _adlar(_pe(OLAGAN_GIRIS)) == {}

    def test_desen_giris_disinda_aranmaz(self):
        """UPX saplaması girişten 32 bayt sonra: giriş deseni değil."""
        assert _adlar(_pe(OLAGAN_GIRIS + b"\x90" * 12 + UPX_SAPLAMA)) == {}

    def test_kisa_desen_tek_basina_eslesmez(self):
        """Girişte yalnız "60 BE" (PUSHAD; MOV ESI) — UPX saplamasının geri kalanı yok."""
        assert "UPX" not in _adlar(_pe(b"\x60\xbe\x00\x10\x40\x00\x31\xc0\xc3"))

    def test_upx_saplamasi_giriste(self):
        f = _adlar(_pe(UPX_SAPLAMA))["UPX"]
        assert "giris noktasi deseni" in f.evidence[0]
        assert "RVA 0x1000" in f.evidence[0]

    def test_fsg_saplamasi_giriste_korunur(self):
        assert _adlar(_pe(FSG_SAPLAMA))["FSG"].confidence == pytest.approx(0.30)

    def test_arm64_pe_x86_desenleri_atlanir(self):
        """ARM64 PE girişinde FSG / ASPack baytları: x86 deseni aranmaz (eski: FSG)."""
        assert _adlar(_pe(FSG_SAPLAMA + ASPACK_SAPLAMA, "arm64")) == {}

    def test_x64_pe_x86_desenleri_atlanir(self):
        assert _adlar(_pe(ASPACK_SAPLAMA, "x86_64")) == {}

    def test_giris_bolum_disinda(self):
        veri = bytearray(_pe(UPX_SAPLAMA))
        struct.pack_into("<I", veri, 0x40 + 4 + 20 + 16, 0x9000)  # AddressOfEntryPoint
        assert _adlar(bytes(veri)) == {}

    def test_kisa_desen_kurali_atlanir(self):
        """6 bayttan kısa bir kural (eski FSG "BB") girişte eşleşse bile kullanılmaz."""
        kisa = (pf._EntryRule("BB", "FSG", "compressor", 0.30),)
        with mock.patch.object(pf, "_ENTRY_RULES", kisa):
            assert _adlar(_pe(FSG_SAPLAMA)) == {}

    def test_tum_kurallar_en_az_alti_bayt(self):
        assert all(r.length() >= pf._ENTRY_MIN_PATTERN_LEN for r in pf._ENTRY_RULES)


class TestKatmanSayaci:
    def test_ayni_katmanin_kurallari_tek_katman(self):
        """Üç UPX dizgisi (tek katman): layers_matched 1, çok katman artırımı yok (eski: 3, 0,99)."""
        veri = _pe(b"\xc3") + (b"UPX 3.96 Copyright \x00$Info: This file is packed with the UPX"
                               b" executable packer\x00UPX!\x00")
        upx = next(f for f in PackerFingerprintDetector("x", _data=veri).detect()
                   if f.packer_name == "UPX")
        assert upx.layers_matched == 1
        assert upx.confidence == pytest.approx(0.92)

    def test_farkli_katmanlar_sayilir(self, tmp_path):
        """Bölüm adı + dizgi + giriş deseni: üç katman."""
        poz = Path.home() / "karadul_olcum/runs/onarim-2026-11-18/P02/pozitif/upx_w32.exe"
        if not poz.is_file():
            pytest.skip("P02 pozitif seti üretilmemiş")
        upx = next(f for f in PackerFingerprintDetector(poz).detect() if f.packer_name == "UPX")
        assert upx.layers_matched == 3
        assert upx.confidence >= 0.95


DISTLIB = Path("/opt/anaconda3/lib/python3.12/site-packages/pip/_vendor/distlib")
MASUM = sorted(DISTLIB.glob("*.exe")) + sorted(
    Path("/opt/homebrew/Cellar/makensis/3.13/share/nsis/Bin").glob("*.exe"))


@pytest.mark.skipif(not MASUM, reason="masum PE'ler yerelde yok")
@pytest.mark.parametrize("yol", MASUM, ids=[p.name for p in MASUM])
def test_gercek_masum_pe_giris_deseni_yok(yol):
    """Kulvar IMZA-04 kanıtı: bu PE'ler eskiden "FSG 0,3" alıyordu (t64-arm.exe dahil)."""
    det = PackerFingerprintDetector(yol)
    assert det.detect_by_entry_pattern() == []
    assert "FSG" not in {f.packer_name for f in det.detect()}
