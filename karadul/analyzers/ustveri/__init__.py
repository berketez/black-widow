"""Üst veri okuyucuları (ÜST VERİ hattı; KARARLAR A-10, A-27).

İkilinin içinde yazılı ad / tip / ilişki üst verisini (Go ``pclntab``, Objective-C yöntem
listeleri, Swift tip üst verisi, C++ RTTI …) Ghidra'sız, yalnız dosya baytlarından okur.
Ortak zemin ``goruntu.Goruntu``: adresten bayt okuma, gösterici çözme (Mach-O zincirli
düzeltme, ELF yeniden konumlama, içe aktarım bağı), bölümler, fonksiyon başlangıçları,
semboller, giriş adresi. Hiçbir okuyucu ikiliyi çalıştırmaz ya da değiştirmez.
"""
from __future__ import annotations

from karadul.analyzers.ustveri.goruntu import (
    BICIM_ELF,
    BICIM_MACHO,
    BICIM_PE,
    DURUM_CALISTI,
    DURUM_DESTEKLENMIYOR,
    DURUM_HATA,
    DURUM_VERI_YOK,
    Bag,
    BellekGoruntu,
    Bolum,
    Goruntu,
    GoruntuHatasi,
    Sembol,
    ac,
    baytlardan,
)

__all__ = [
    "BICIM_ELF", "BICIM_MACHO", "BICIM_PE",
    "DURUM_CALISTI", "DURUM_DESTEKLENMIYOR", "DURUM_HATA", "DURUM_VERI_YOK",
    "Bag", "BellekGoruntu", "Bolum", "Goruntu", "GoruntuHatasi", "Sembol",
    "ac", "baytlardan",
]
