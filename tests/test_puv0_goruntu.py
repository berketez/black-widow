"""P-ÜV0: ikili görüntü okuyucu (``karadul.analyzers.ustveri.goruntu``).

Bütün testler ``struct.pack`` ile kurulan sentetik baytlar üstünde koşar (PLAN §0 test verisi
kuralı); gerçek ikiliye bağlı test yoktur. Gerçek ikili kabulü:
``docs/arge/2026-11-19_mythos/ustveri/P-UV0.md``.
"""
from __future__ import annotations

import struct

import pytest

from karadul.analyzers.ustveri import goruntu as G
from karadul.analyzers.ustveri.goruntu import (
    Bag,
    BellekGoruntu,
    Goruntu,
    GoruntuHatasi,
    Sembol,
    ac,
    baytlardan,
)

# ---------------------------------------------------------------------------------------
# Sentetik Mach-O 64 (arm64): __TEXT (__text), __DATA (__data, __got), __LINKEDIT
# ---------------------------------------------------------------------------------------
MACHO_TABAN = 0x100000000
TEXT_OFS = 0x1000
DATA_OFS = 0x4000
LINK_OFS = 0x8000
FS_OFS = LINK_OFS            # LC_FUNCTION_STARTS
SYM_OFS = LINK_OFS + 0x10    # 2 x nlist_64
STR_OFS = LINK_OFS + 0x30    # dizgi tablosu (16 bayt)
ZD_OFS = LINK_OFS + 0x40     # LC_DYLD_CHAINED_FIXUPS
DI_OFS = LINK_OFS + 0xA0     # LC_DYLD_INFO bağ işlem kodları

# ULEB farkları: 0x1000 (iki bayt), 0x20 (bir bayt), 0x200 (iki bayt), 0 (son)
FS_BLOB = bytes([0x80, 0x20, 0x20, 0x80, 0x04, 0x00, 0x00, 0x00])
FS_BEKLENEN = [MACHO_TABAN + 0x1000, MACHO_TABAN + 0x1020, MACHO_TABAN + 0x1220]

R0 = MACHO_TABAN + 0x4000   # yeniden konumlama (hedef 0x1000), sonraki 2 -> +8
R1 = MACHO_TABAN + 0x4008   # yeniden konumlama (hedef 0x1010, high8 0x80), sonraki 62 -> +0x100
B0 = MACHO_TABAN + 0x4100   # __got[0]: bağ (içe aktarım 0 = _printf)
HAM = MACHO_TABAN + 0x4010  # düzeltme yeri değil: ham 0x1234
BOS_ADRES = MACHO_TABAN + 0x4018


def _seg(ad: bytes, vmaddr: int, vmsize: int, fileoff: int, filesize: int, bolumler: list[bytes]) -> bytes:
    return struct.pack("<II16sQQQQiiII", 0x19, 72 + 80 * len(bolumler), ad, vmaddr, vmsize, fileoff,
                       filesize, 7, 5, len(bolumler), 0) + b"".join(bolumler)


def _bolum(sect: bytes, seg: bytes, addr: int, size: int, off: int, flags: int) -> bytes:
    return struct.pack("<16s16sQQIIIIIIII", sect, seg, addr, size, off, 2, 0, 0, flags, 0, 0, 0)


def _zincir_blob(pointer_format: int = 6, page_start: int = 0) -> bytes:
    hdr = struct.pack("<IIIIIII", 0, 32, 72, 76, 1, 1, 0) + b"\0" * 4
    image = struct.pack("<IIII", 3, 0, 16, 0)
    seg = struct.pack("<IHHQIHH", 24, 0x4000, pointer_format, 0x4000, 0, 1, page_start)
    imports = struct.pack("<I", 1 | (0 << 8) | (1 << 9))
    syms = b"\0_printf\0"
    blob = hdr + image + seg + imports + syms
    return blob + b"\0" * (-len(blob) % 8)


def _zincir_veri(pointer_format: int = 6) -> bytes:
    h0 = 0x1000 if pointer_format == 6 else MACHO_TABAN + 0x1000
    h1 = 0x1010 if pointer_format == 6 else MACHO_TABAN + 0x1010
    d = bytearray(0x4000)
    struct.pack_into("<Q", d, 0x0, h0 | (2 << 51))
    struct.pack_into("<Q", d, 0x8, h1 | (0x80 << 36) | (62 << 51))
    struct.pack_into("<Q", d, 0x10, 0x1234)
    struct.pack_into("<Q", d, 0x100, 1 << 63)
    return bytes(d)


def macho_kur(pointer_format: int = 6, page_start: int = 0, cputype: int = 0x0100000C,
              cpusubtype: int = 0, dyld_info: bool = False) -> bytes:
    """Tek zincirli (iki yeniden konumlama + bir bağ) ya da LC_DYLD_INFO'lu sentetik Mach-O."""
    text = _seg(b"__TEXT", MACHO_TABAN, 0x4000, 0, 0x4000,
                [_bolum(b"__text", b"__TEXT", MACHO_TABAN + TEXT_OFS, 0x300, TEXT_OFS, 0x80000400)])
    data = _seg(b"__DATA", MACHO_TABAN + 0x4000, 0x4000, DATA_OFS, 0x4000,
                [_bolum(b"__data", b"__DATA", MACHO_TABAN + 0x4000, 0x100, DATA_OFS, 0),
                 _bolum(b"__got", b"__DATA", MACHO_TABAN + 0x4100, 0x10, DATA_OFS + 0x100, 6),
                 _bolum(b"__bss", b"__DATA", MACHO_TABAN + 0x5000, 0x100, 0, 1)])
    link = _seg(b"__LINKEDIT", MACHO_TABAN + 0x8000, 0x4000, LINK_OFS, 0x100, [])
    main = struct.pack("<IIQQ", 0x80000028, 24, 0x1000, 0)
    fs = struct.pack("<IIII", 0x26, 16, FS_OFS, len(FS_BLOB))
    symtab = struct.pack("<IIIIII", 0x2, 24, SYM_OFS, 2, STR_OFS, 16)
    if dyld_info:
        bag = struct.pack("<IIIIIIIIIIII", 0x80000022, 48, 0, 0, DI_OFS, len(_DI_KODLAR),
                          0, 0, 0, 0, 0, 0)
    else:
        bag = struct.pack("<IIII", 0x80000034, 16, ZD_OFS, len(_zincir_blob()))
    cmds = [text, data, link, main, fs, symtab, bag]
    lc = b"".join(cmds)
    hdr = struct.pack("<IIIIIIII", 0xFEEDFACF, cputype, cpusubtype, 2, len(cmds), len(lc), 0, 0)
    d = bytearray(LINK_OFS + 0x100)
    d[0:len(hdr) + len(lc)] = hdr + lc
    d[TEXT_OFS:TEXT_OFS + 4] = b"\x1f\x20\x03\xd5"
    if dyld_info:
        veri = bytearray(0x4000)
        struct.pack_into("<Q", veri, 0, MACHO_TABAN + 0x1000)  # eski düzen: ham sanal adres
        d[DATA_OFS:DATA_OFS + 0x4000] = veri
        d[DI_OFS:DI_OFS + len(_DI_KODLAR)] = _DI_KODLAR
    else:
        d[DATA_OFS:DATA_OFS + 0x4000] = _zincir_veri(pointer_format)
        z = _zincir_blob(pointer_format, page_start)
        d[ZD_OFS:ZD_OFS + len(z)] = z
    d[FS_OFS:FS_OFS + len(FS_BLOB)] = FS_BLOB
    struct.pack_into("<IBBHQ", d, SYM_OFS, 1, 0x0F, 1, 0, MACHO_TABAN + 0x1000)    # _main (tanımlı, dış)
    struct.pack_into("<IBBHQ", d, SYM_OFS + 16, 7, 0x01, 0, 0x100, 0)        # _printf (tanımsız)
    d[STR_OFS:STR_OFS + 15] = b"\0_main\0_printf\0"
    return bytes(d)


# LC_DYLD_INFO bağ işlem kodları: kitaplık 1, "_printf", tür gösterici, bölüt 1 + 0x100, bağla, son
_DI_KODLAR = bytes([0x11, 0x40]) + b"_printf\0" + bytes([0x51, 0x71, 0x80, 0x02, 0x90, 0x00])


def fat_kur(dilimler: list[tuple[int, int, bytes]]) -> bytes:
    """Evrensel başlık + dilimler ((cputype, cpusubtype, veri) …), 0x4000 hizalı."""
    hizali = 0x4000
    out = bytearray(struct.pack(">II", 0xCAFEBABE, len(dilimler)))
    ofs = hizali
    govde = bytearray()
    for cpu, sub, veri in dilimler:
        out += struct.pack(">iiIII", cpu, sub, ofs, len(veri), 14)
        govde += veri + b"\0" * (-len(veri) % hizali)
        ofs += len(veri) + (-len(veri) % hizali)
    out += b"\0" * (hizali - len(out))
    return bytes(out + govde)


# ---------------------------------------------------------------------------------------
# Arayüz
# ---------------------------------------------------------------------------------------
class TestArayuz:
    def test_goruntu_soyut_sinif(self):
        with pytest.raises(TypeError):
            Goruntu()  # type: ignore[abstract]

    def test_bag_esitligi_ad_ve_ek(self):
        assert Bag("_x") == Bag("_x", 0)
        assert Bag("_x") != Bag("_x", 8)
        assert Bag("_x") != Bag("_y")

    def test_bellek_goruntu_okuma_ve_gosterici(self):
        veri = struct.pack("<QQ", 0x1004, 0) + b"abc\0"
        g = BellekGoruntu([("__text", 0x1000, b"\0" * 16, True, "__TEXT"),
                           ("__data", 0x2000, veri, False, "__DATA")],
                          baglar={0x2008: Bag("_x")}, yeniden_konumlamalar={0x2010: 0x1008})
        assert g.bolum_adli("__DATA,__data").adres == 0x2000
        assert g.bolum_adli("__TEXT,__data") is None
        assert [b.ad for b in g.kod_bolumleri] == ["__text"]
        assert g.gosterici(0x2000) == 0x1004
        assert g.gosterici(0x2008) == Bag("_x")
        assert g.gosterici(0x2010) == 0x1008
        assert g.cstr(0x2010) == "abc"
        assert g.u32(0x2000) == 0x1004 and g.i32(0x3000) is None
        assert g.oku(0x2012, 4) is None  # bölüm sonunu aşan okuma
        assert g.adres_bolumu(0x1004).ad == "__text" and g.kod_mu(0x1004) and not g.kod_mu(0x2000)

    def test_cstr_nul_yoksa_none(self):
        g = BellekGoruntu([("d", 0x10, b"abcd")])
        assert g.cstr(0x10) is None
        assert g.cstr(0x10, azami=2) is None

    def test_uleb_sleb(self):
        assert G.uleb128(bytes([0xE5, 0x8E, 0x26]), 0) == (624485, 3)
        assert G.uleb128(bytes([0x80]), 0) is None  # kesik
        assert G.sleb128(bytes([0x7F]), 0) == (-1, 1)
        assert G.sleb128(bytes([0x80, 0x7F]), 0) == (-128, 2)


# ---------------------------------------------------------------------------------------
# Mach-O 64
# ---------------------------------------------------------------------------------------
class TestMachO:
    def test_kimlik_bolumler_giris(self):
        g = baytlardan(macho_kur())
        assert (g.bicim, g.mimari, g.gosterici_boyutu) == ("macho", "arm64", 8)
        assert g.giris_adresi == MACHO_TABAN + 0x1000
        assert [b.tam_ad for b in g.bolumler] == ["__TEXT,__text", "__DATA,__data", "__DATA,__got",
                                                  "__DATA,__bss"]
        assert [b.ad for b in g.kod_bolumleri] == ["__text"]
        assert g.bolum_adli("__bss").dosya_ofseti is None
        assert g.oku(MACHO_TABAN + TEXT_OFS, 4) == b"\x1f\x20\x03\xd5"

    def test_zincir_iki_yeniden_konumlama_bir_bag(self):
        g = baytlardan(macho_kur())
        assert g.gosterici(R0) == MACHO_TABAN + 0x1000          # biçim 6: görüntü tabanı eklenir
        assert g.gosterici(R1) == (MACHO_TABAN + 0x1010) | (0x80 << 56)  # high8 56. bite
        assert g.gosterici(B0) == Bag("_printf")
        assert g.gosterici(HAM) == 0x1234                 # düzeltme yeri değil: ham sözcük
        assert g.gosterici(BOS_ADRES) is None
        o = g.ozet()
        assert (o["duzeltme_yeri"], o["yeniden_konumlama"], o["ice_aktarim"]) == (3, 2, 1)
        assert set(g.duzeltmeler()) == {R0, R1, B0}

    def test_bicim_2_hedef_mutlak(self):
        g = baytlardan(macho_kur(pointer_format=2))
        assert g.gosterici(R0) == MACHO_TABAN + 0x1000
        assert g.gosterici(B0) == Bag("_printf")

    def test_arm64e_ve_cok_baslangicli_sayfa_desteklenmiyor(self):
        for kw in ({"pointer_format": 1}, {"page_start": 0x8000}):
            g = baytlardan(macho_kur(**kw))
            assert g.gosterici(R0) is None  # kodlu ham sözcük gösterici diye verilmez
            assert g.durum["duzeltme"]["durum"] == "desteklenmiyor"
            assert g.ozet()["duzeltme_yeri"] == 0

    def test_fonksiyon_baslangiclari_uleb(self):
        g = baytlardan(macho_kur())
        assert g.fonksiyon_baslangiclari() == FS_BEKLENEN

    def test_semboller(self):
        g = baytlardan(macho_kur())
        s = g.semboller()
        assert s[0] == Sembol("_main", MACHO_TABAN + 0x1000, "kod", True, None, "LC_SYMTAB")
        assert (s[1].ad, s[1].tur, s[1].disa_acik) == ("_printf", "tanimsiz", True)

    def test_dyld_info_bag(self):
        g = baytlardan(macho_kur(dyld_info=True))
        assert g.gosterici(B0) == Bag("_printf")
        assert g.gosterici(R0) == MACHO_TABAN + 0x1000  # ham sanal adres
        o = g.ozet()
        assert (o["zincirli_duzeltme"], o["duzeltme_yeri"], o["dyld_info_bag"]) == (False, 0, 1)

    def test_zincir_dosya_disina_tasarsa_hata_istisna_yok(self):
        d = bytearray(macho_kur())
        struct.pack_into("<Q", d, DATA_OFS + 0x100, (1 << 63) | (0xFFF << 51))  # bağdan sonra uzak sıçrama
        g = baytlardan(bytes(d))
        assert g.gosterici(R0) is None and g.gosterici(B0) is None  # bozuk zincire güvenilmez
        assert g.durum["duzeltme"]["durum"] == "hata"
        assert g.ozet()["duzeltme_yeri"] == 0


# ---------------------------------------------------------------------------------------
# Evrensel dosya
# ---------------------------------------------------------------------------------------
class TestEvrensel:
    def _fat(self) -> bytes:
        return fat_kur([(0x01000007, 3, macho_kur(cputype=0x01000007, cpusubtype=3)),
                        (0x0100000C, 0, macho_kur())])

    def test_dilim_zorunlu(self):
        with pytest.raises(GoruntuHatasi):
            baytlardan(self._fat())
        with pytest.raises(GoruntuHatasi):
            baytlardan(self._fat(), dilim="arm64e")

    def test_dilim_secimi_ve_ad(self):
        f = self._fat()
        assert [s["arch"] for s in G.dilimler(f)] == ["x86_64", "arm64"]
        assert G.urun_dilimi(f) == "arm64"  # ürünün tercih sırası: arm64 > … > x86_64
        g = baytlardan(f, dilim="x86_64")
        assert g.mimari == "x86_64"
        assert g.gosterici(B0) == Bag("_printf")
        assert baytlardan(f, dilim="arm64").mimari == "arm64"

    def test_ince_dosyada_yanlis_dilim(self):
        with pytest.raises(GoruntuHatasi):
            baytlardan(macho_kur(), dilim="x86_64")
        assert baytlardan(macho_kur(), dilim="arm64").mimari == "arm64"

    def test_ac_dosyadan_ve_cli(self, tmp_path, capsys):
        p = tmp_path / "fat"
        p.write_bytes(self._fat())
        assert ac(p, "arm64").fonksiyon_baslangiclari() == FS_BEKLENEN
        assert G.main([str(p)]) == 0
        assert '"duzeltme_yeri": 3' in capsys.readouterr().out
        with pytest.raises(GoruntuHatasi):
            ac(tmp_path / "yok")


# ---------------------------------------------------------------------------------------
# Sağlamlık: kesik / bozuk dosya
# ---------------------------------------------------------------------------------------
def _hepsini_cagir(g: Goruntu) -> None:
    for b in g.bolumler:
        g.oku(b.adres, 8)
        g.cstr(b.adres)
        g.gosterici(b.adres)
        g.u32(b.adres)
        g.u64(b.adres)
        g.bolum_baytlari(b)
    _ = (g.kod_bolumleri, g.giris_adresi, g.mimari, g.gosterici_boyutu, g.bicim, g.durum)
    g.semboller()
    g.fonksiyon_baslangiclari()
    for a in (R0, R1, B0, HAM, 0, -8, 1 << 70):
        g.gosterici(a)
        g.oku(a, 16)
        g.cstr(a)
    g.ozet()


@pytest.mark.parametrize("kur", [lambda: macho_kur(), lambda: macho_kur(dyld_info=True)])
def test_kesik_dosyada_istisna_yok(kur):
    tam = kur()
    for kesim in (4, 31, 32, 100, 300, 0x1000, DATA_OFS + 0x8, LINK_OFS, ZD_OFS + 30, len(tam) - 1):
        try:
            g = baytlardan(tam[:kesim])
        except GoruntuHatasi:
            continue
        _hepsini_cagir(g)


def test_bozuk_yuk_komutu_boyu():
    d = bytearray(macho_kur())
    struct.pack_into("<I", d, 32 + 4, 4)  # ilk komutun boyu 4 (< 8)
    g = baytlardan(bytes(d))
    assert g.durum["baslik"]["durum"] == "hata"
    _hepsini_cagir(g)


def test_taninmayan_bicim():
    with pytest.raises(GoruntuHatasi) as e:
        baytlardan(b"\0\0\0\0" * 8)
    assert e.value.durum == "desteklenmiyor"
    with pytest.raises(GoruntuHatasi):
        baytlardan(b"ab")
