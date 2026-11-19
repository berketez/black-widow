#!/usr/bin/env python3
"""OLGU paketinin ikili okuyucuları: bölümler, C dizgisi, veri yuvaları ve kayıt çiftleri.

Bu modül ürün kodunu ve ölçüm betiklerini içe aktarmaz; yalnız ``struct`` ve (ELF için)
pyelftools kullanır. Saf fonksiyonlar (``rela_coz``, ``yuva_haritasi_rela``, ``komsu_dizgiler``,
``kayit_ciftleri``, ``cagri_dizgileri``) sentetik girdiyle sınanır (``test_olgu_tablosu.py``).

Adres uzayı: bu modüldeki bütün adresler ikilinin kendi sanal adresleridir (ELF ``p_vaddr`` /
``sh_addr``, Mach-O ``vmaddr``). Ghidra adresine çevirmek (ELF PIE'de +0x100000) çağıranın işidir.

Tanımlar
--------
Veri yuvası (``yuva``)
    İkilinin bir veri bölümünde, yükleyicinin bir işaretçi yazdığı adres. ELF'te ``.rela.dyn``
    kayıtları: ``R_*_RELATIVE`` (hedef = ekleme değeri) ve tanımlı dinamik sembole giden
    ``R_*_ABS64`` / ``R_*_GLOB_DAT`` (hedef = sembol değeri + ekleme). Yeniden konumlanmayan
    (ET_EXEC) ELF'te veri bölümlerinin işaretçi hizalı sözcükleri okunur; değeri ayrılmış bir
    bölümün içine düşen sözcük yuvadır. Mach-O'da ``xcrun dyld_info -fixups`` çıktısının rebase
    satırları (``macho_f1.parse_dyld_fixups``; zincirli fixup'lar dahil).
Kayıt çifti (veri)
    Hedefi F (fonksiyon başı) olan her yuva Y için Y ± k·w (k = 1..``KOMSU``, w işaretçi
    genişliği) yuvalarından hedefi bir C dizgisi olanlar. Dizgi ``cstr_oku`` ile ikiliden okunur.
Çağrı dizgisi (P-code)
    Ghidra'nın yüksek P-code dökümünde bir ``CALL``'ın argümanı, ya doğrudan dizgi adresi olan bir
    sabit ya da tek tanımı ``COPY(sabit dizgi adresi)`` olan bir ara değer (``unique``) ise
    (çağrılan, argüman sırası, dizgi). Fonksiyon işaretçisi argümanı dökümde yok (``PTRSUB``
    yazılmıyor): bkz. ``DEFTER.md`` §0.
"""
from __future__ import annotations

import posixpath
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Optional

# ---- ELF yeniden konumlandırma türleri (makine → ad → kod)
EM_AARCH64 = 183
EM_X86_64 = 62
RELOC_TURLERI = {
    EM_AARCH64: {"RELATIVE": 1027, "ABS64": 257, "GLOB_DAT": 1025},
    EM_X86_64: {"RELATIVE": 8, "ABS64": 1, "GLOB_DAT": 6},
}
RELA64 = struct.Struct("<QQq")          # r_offset, r_info, r_addend (Elf64_Rela)

# ---- Seçimler
ISARETCI_GENISLIGI = 8                  # LP64 (AArch64 Linux, Apple arm64)
KOMSU = 4                               # kayıt çifti: ± 4 işaretçi genişliği
DIZGI_SINIRI = 4096                     # C dizgisi en çok bu kadar bayt okunur (NUL aranır)
KIRPMA_SINIRI = 200                     # tabloya yazılan dizgi en çok bu kadar karakter
IZINLI_DENETIM = frozenset("\t\n\r\x1b")  # basılabilir sayılan denetim karakterleri

# ---- P-code uzayları (ürün ``karadul/ghidra/headless.py`` ``_SPACE_MAP``)
UZAY_UNIQUE, UZAY_REGISTER, UZAY_CONST, UZAY_RAM, UZAY_STACK = 0, 1, 2, 3, 4


@dataclass(frozen=True)
class Bolum:
    ad: str
    adres: int
    boyut: int
    dosya_ofseti: Optional[int]          # NOBITS / zerofill: None
    yurutulebilir: bool
    yazilabilir: bool

    def icerir(self, adres: int) -> bool:
        return self.adres <= adres < self.adres + self.boyut


@dataclass
class Goruntu:
    """İkilinin bölümleri ve dosya baytları."""

    bicim: str                           # "elf" | "macho"
    bolumler: list[Bolum]
    veri: bytes
    tur: Optional[str] = None            # ELF: ET_DYN | ET_EXEC; Mach-O: None
    makine: Optional[int] = None

    def bolum_bul(self, adres: int) -> Optional[Bolum]:
        for b in self.bolumler:
            if b.icerir(adres):
                return b
        return None

    def oku(self, adres: int, n: int) -> Optional[bytes]:
        b = self.bolum_bul(adres)
        if b is None or b.dosya_ofseti is None:
            return None
        bas = b.dosya_ofseti + (adres - b.adres)
        son = min(bas + n, b.dosya_ofseti + b.boyut)
        return self.veri[bas:son]


def dizgi_gecerli(metin: str) -> bool:
    """Boş değil, her karakter basılabilir ya da izinli denetim karakteri."""
    return bool(metin) and all(c.isprintable() or c in IZINLI_DENETIM for c in metin)


def cstr_oku(g: Goruntu, adres: int, sinir: int = DIZGI_SINIRI) -> Optional[str]:
    """``adres``'teki NUL sonlu UTF-8 dizgi; yürütülebilir bölümde, sınırda NUL yoksa, çözülmezse
    ya da basılamayan karakter taşıyorsa None."""
    b = g.bolum_bul(adres)
    if b is None or b.yurutulebilir or b.dosya_ofseti is None:
        return None
    ham = g.oku(adres, sinir)
    if not ham:
        return None
    son = ham.find(b"\x00")
    if son < 0:
        return None
    try:
        metin = ham[:son].decode("utf-8")
    except UnicodeDecodeError:
        return None
    return metin if dizgi_gecerli(metin) else None


def kirp(metin: str, sinir: int = KIRPMA_SINIRI) -> tuple[str, bool]:
    return (metin, False) if len(metin) <= sinir else (metin[:sinir], True)


# --------------------------------------------------------------------------------------------
# ELF


def rela_coz(veri: bytes) -> list[tuple[int, int, int, int]]:
    """Ham ``Elf64_Rela`` dizisi → [(r_offset, tür, sembol dizini, ekleme)] (küçük sonlu)."""
    if len(veri) % RELA64.size:
        raise ValueError(f"RELA bölümü {RELA64.size}'in katı değil: {len(veri)} bayt")
    out = []
    for r_offset, r_info, r_addend in RELA64.iter_unpack(veri):
        out.append((r_offset, r_info & 0xFFFFFFFF, r_info >> 32, r_addend))
    return out


def yuva_haritasi_rela(relalar: Iterable[tuple[int, int, int, int]], makine: int,
                       semboller: dict[int, int]) -> tuple[dict[int, int], dict[str, int]]:
    """RELA kayıtlarından yuva → hedef. ``semboller``: dinamik sembol dizini → değer (yalnız
    tanımlı semboller). Döner: (harita, tür sayacı)."""
    turler = RELOC_TURLERI.get(makine)
    if turler is None:
        raise ValueError(f"desteklenmeyen ELF makinesi: {makine}")
    harita: dict[int, int] = {}
    sayac = {"relative": 0, "sembollu": 0, "atlanan": 0}
    for r_offset, tur, sym, ek in relalar:
        if tur == turler["RELATIVE"]:
            harita[r_offset] = ek
            sayac["relative"] += 1
        elif tur in (turler["ABS64"], turler["GLOB_DAT"]) and sym in semboller:
            harita[r_offset] = semboller[sym] + ek
            sayac["sembollu"] += 1
        else:
            sayac["atlanan"] += 1
    return harita, sayac


def elf_oku(yol: Path) -> tuple[Goruntu, dict[int, int], dict[str, Any]]:
    """ELF'in görüntüsü, veri yuvası haritası ve künyesi."""
    from elftools.elf.elffile import ELFFile
    from elftools.elf.relocation import RelocationSection
    from elftools.elf.sections import SymbolTableSection

    veri = Path(yol).read_bytes()
    with open(yol, "rb") as f:
        elf = ELFFile(f)
        makine_adi = elf["e_machine"]
        makine = {"EM_AARCH64": EM_AARCH64, "EM_X86_64": EM_X86_64}.get(makine_adi)
        tur = elf["e_type"]
        bolumler = []
        relalar: list[tuple[int, int, int, int]] = []
        semboller: dict[int, int] = {}
        for sec in elf.iter_sections():
            bayrak = sec["sh_flags"]
            if bayrak & 0x2 and sec["sh_addr"]:            # SHF_ALLOC
                bolumler.append(Bolum(sec.name, sec["sh_addr"], sec["sh_size"],
                                      None if sec["sh_type"] == "SHT_NOBITS" else sec["sh_offset"],
                                      bool(bayrak & 0x4), bool(bayrak & 0x1)))
            if isinstance(sec, RelocationSection) and sec.is_RELA() and sec["sh_type"] == "SHT_RELA" \
                    and sec.name != ".rela.plt":
                relalar.extend(rela_coz(sec.data()))
            if isinstance(sec, SymbolTableSection) and sec.name == ".dynsym":
                for i, s in enumerate(sec.iter_symbols()):
                    if s["st_shndx"] != "SHN_UNDEF" and s["st_value"]:
                        semboller[i] = s["st_value"]
    g = Goruntu("elf", sorted(bolumler, key=lambda b: b.adres), veri, tur, makine)
    kunye: dict[str, Any] = {"bicim": "elf", "tur": tur, "makine": makine_adi}
    if tur == "ET_DYN":
        harita, sayac = yuva_haritasi_rela(relalar, makine, semboller)
        kunye["yuva_kaynagi"] = "rela"
        kunye["rela"] = sayac
    else:
        harita = ham_yuvalar(g)
        kunye["yuva_kaynagi"] = "ham_sozcuk"
    kunye["yuva"] = len(harita)
    return g, harita, kunye


def ham_yuvalar(g: Goruntu, w: int = ISARETCI_GENISLIGI) -> dict[int, int]:
    """Yeniden konumlanmayan ikili: veri bölümlerinin hizalı sözcüklerinden ayrılmış bir bölüme
    düşenler (yuva → hedef)."""
    harita: dict[int, int] = {}
    for b in g.bolumler:
        if b.yurutulebilir or b.dosya_ofseti is None or not b.yazilabilir:
            continue
        bas = (b.adres + w - 1) // w * w
        for a in range(bas, b.adres + b.boyut - w + 1, w):
            ham = g.oku(a, w)
            if ham is None or len(ham) < w:
                continue
            deger = int.from_bytes(ham, "little")
            if deger and g.bolum_bul(deger) is not None:
                harita[a] = deger
    return harita


# --------------------------------------------------------------------------------------------
# Mach-O (yalnız ince 64 bit, küçük sonlu)

MH_MAGIC_64 = 0xFEEDFACF
LC_SEGMENT_64 = 0x19
S_ATTR_PURE_INSTRUCTIONS = 0x80000000
S_ATTR_SOME_INSTRUCTIONS = 0x00000400
S_ZEROFILL_TURLERI = (0x1, 0xC, 0x12)    # S_ZEROFILL, S_GB_ZEROFILL, S_THREAD_LOCAL_ZEROFILL


def macho_bolumleri(veri: bytes) -> list[Bolum]:
    """Mach-O yük komutlarındaki ``LC_SEGMENT_64`` bölümleri (``segment,bölüm`` adıyla)."""
    magic, _cpu, _sub, _ftype, ncmds, _sizeofcmds, _flags, _res = struct.unpack_from("<IiiIIIII", veri, 0)
    if magic != MH_MAGIC_64:
        raise ValueError(f"ince 64 bit Mach-O değil (magic 0x{magic:x})")
    bolumler = []
    off = 32
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", veri, off)
        if cmd == LC_SEGMENT_64:
            segname = veri[off + 8:off + 24].rstrip(b"\x00").decode()
            _vmaddr, _vmsize, _fileoff, _filesize, _maxprot, initprot, nsects, _fl = \
                struct.unpack_from("<QQQQiiII", veri, off + 24)
            s = off + 72
            for _i in range(nsects):
                sectname = veri[s:s + 16].rstrip(b"\x00").decode()
                addr, size, offset, _align, _reloff, _nreloc, flags = struct.unpack_from("<QQIIIII", veri, s + 32)
                tur = flags & 0xFF
                yurut = bool(flags & (S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS))
                bolumler.append(Bolum(f"{segname},{sectname}", addr, size,
                                      None if tur in S_ZEROFILL_TURLERI else offset,
                                      yurut, bool(initprot & 0x2)))
                s += 80
        off += cmdsize
    return sorted(bolumler, key=lambda b: b.adres)


def macho_oku(yol: Path, fixup_metni: str, parse_dyld_fixups: Any
              ) -> tuple[Goruntu, dict[int, int], dict[str, Any]]:
    """Mach-O görüntüsü ve rebase yuvaları (``parse_dyld_fixups``: ``macho_f1``'in ayrıştırıcısı)."""
    veri = Path(yol).read_bytes()
    g = Goruntu("macho", macho_bolumleri(veri), veri)
    fixup = parse_dyld_fixups(fixup_metni)
    harita = {f["slot"]: f["target"] for f in fixup if isinstance(f["target"], int)}
    return g, harita, {"bicim": "macho", "yuva_kaynagi": "dyld_info_fixups", "yuva": len(harita),
                       "bind": sum(1 for f in fixup if not isinstance(f["target"], int))}


# --------------------------------------------------------------------------------------------
# Kayıt çiftleri ve çağrı dizgileri (saf)


def komsu_dizgiler(yer: int, yuva: dict[int, int], dizgi_bul: Any, w: int = ISARETCI_GENISLIGI,
                   komsu: int = KOMSU) -> list[dict[str, Any]]:
    """``yer``'in ± ``komsu`` yuva komşularından hedefi dizgi olanlar: [{o, a, m, k}].

    ``o``: komşunun yer'e göre yuva farkı (−4..4, 0 hariç); ``a``: dizginin adresi;
    ``m``: kırpılmış metin; ``k``: kırpıldı mı. ``dizgi_bul(adres) → Optional[str]``.
    """
    out = []
    for k in range(-komsu, komsu + 1):
        if k == 0:
            continue
        hedef = yuva.get(yer + k * w)
        if hedef is None:
            continue
        metin = dizgi_bul(hedef)
        if metin is None:
            continue
        m, kirpildi = kirp(metin)
        out.append({"o": k, "a": hedef, "m": m, "k": kirpildi})
    return out


def kayit_ciftleri(fonksiyonlar: Iterable[int], yuva: dict[int, int], dizgi_bul: Any,
                   bolum_adi: Any, w: int = ISARETCI_GENISLIGI, komsu: int = KOMSU
                   ) -> dict[int, list[dict[str, Any]]]:
    """Fonksiyon başı → [{y: yuva, b: bölüm adı, d: komşu dizgiler}] (yuva sırasıyla).

    Yalnız hedefi tam fonksiyon başı olan yuvalar sayılır. ``bolum_adi(adres) → Optional[str]``.
    """
    istenen = set(fonksiyonlar)
    out: dict[int, list[dict[str, Any]]] = {}
    for yer in sorted(yuva):
        hedef = yuva[yer]
        if hedef not in istenen:
            continue
        out.setdefault(hedef, []).append({"y": yer, "b": bolum_adi(yer),
                                          "d": komsu_dizgiler(yer, yuva, dizgi_bul, w, komsu)})
    return out


def cagri_dizgileri(ops: list[Any], dizgi_bul: Any) -> tuple[list[dict[str, Any]], bool]:
    """Bir fonksiyonun P-code işlemlerinden çağrı yerindeki dizgi argümanları ve CALLIND varlığı.

    ``ops``: ``[[mnemonic, çıktı, [girdiler]], ...]``; varnode ``[uzay, ofset, boyut]``.
    Ara değer (``unique``) yalnız bir kez tanımlanmış ve tanımı ``COPY(sabit)`` ise sabite çözülür.
    Döner: ([{c: çağrılan adres, i: argüman sırası (1 tabanlı), a: dizgi adresi, m, k}], callind).
    """
    tanim_sayisi: dict[tuple, int] = {}
    sabit: dict[tuple, int] = {}
    callind = False
    for op, cikti, girdiler in ops:
        if op == "CALLIND":
            callind = True
        if cikti is None:
            continue
        anahtar = tuple(cikti)
        tanim_sayisi[anahtar] = tanim_sayisi.get(anahtar, 0) + 1
        if op == "COPY" and girdiler and girdiler[0][0] == UZAY_CONST:
            sabit[anahtar] = girdiler[0][1]
    out = []
    for op, _cikti, girdiler in ops:
        if op != "CALL" or not girdiler or girdiler[0][0] != UZAY_RAM:
            continue
        cagrilan = girdiler[0][1]
        for i, vn in enumerate(girdiler[1:], start=1):
            deger = None
            if vn[0] == UZAY_CONST:
                deger = vn[1]
            elif vn[0] == UZAY_UNIQUE and tanim_sayisi.get(tuple(vn)) == 1:
                deger = sabit.get(tuple(vn))
            if deger is None:
                continue
            metin = dizgi_bul(deger)
            if metin is None:
                continue
            m, kirpildi = kirp(metin)
            out.append({"c": cagrilan, "i": i, "a": deger, "m": m, "k": kirpildi})
    return out, callind


# --------------------------------------------------------------------------------------------
# Kaynak yolu


def kaynak_yolu(ad: Optional[str], derleme_dizini: Optional[str]) -> Optional[str]:
    """Derleme birimi adı (ya da tanım dosyası) → sadeleşmiş yol. Göreli ad derleme dizinine
    eklenir; baştaki ``../`` ve ``./`` atılır. Mutlak yol, paket-sürüm dizininden (ör.
    ``redis-8.0.2``) sonrasına indirilir; yoksa olduğu gibi kalır."""
    if not ad:
        return None
    if posixpath.isabs(ad):
        yol = posixpath.normpath(ad)
    else:
        yol = posixpath.normpath(posixpath.join(derleme_dizini or "", ad))
    parcalar = [p for p in yol.split("/") if p not in ("", ".")]
    if posixpath.isabs(yol):
        kes = None
        for i, p in enumerate(parcalar):
            if _paket_dizini_mi(p):
                kes = i
        if kes is None:
            return "/" + "/".join(parcalar)
        parcalar = parcalar[kes + 1:]
    while parcalar and parcalar[0] == "..":
        parcalar.pop(0)
    return "/".join(parcalar) if parcalar else None


def _paket_dizini_mi(p: str) -> bool:
    """``<ad>-<sürüm>`` biçimli dizin (``redis-8.0.2``, ``coreutils-9.7``)."""
    ad, ayrac, surum = p.rpartition("-")
    return bool(ad and ayrac and surum[:1].isdigit() and "." in surum)
