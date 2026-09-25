"""Mach-O arm64 okuyucu: dilim seçimi, __TEXT, LC_FUNCTION_STARTS, sembol tablosu.

Seçici FLIRT imza üreticisi (``build_selective_signatures.py``) ve ölçüm betiği
(``scripts/measurement/flirt_precision.py``) aynı okuyucuyu kullanır; iki yerde
iki ayrı "fonksiyon uzunluğu" tanımı olmasın diye.

Yalnız okur, bağımlılık yok (struct). Fat (universal) dosyada arm64 dilimi seçilir.

Fonksiyon uzunluğu = bir sonraki fonksiyon başlangıcına (LC_FUNCTION_STARTS) ya da
``__text`` sonuna kadar olan aralık. Homebrew arm64 ``tree``'de Ghidra'nın
fonksiyon boyutu bu aralıkla 118/118 fonksiyonda aynı (fonksiyonlar arası
dolgu yok) -- pipeline'daki functions.json ``size`` alanıyla karşılaştırılabilir.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path

CPU_TYPE_ARM64 = 0x0100000C
MH_MAGIC_64 = 0xFEEDFACF
FAT_MAGIC = 0xCAFEBABE
FAT_MAGIC_64 = 0xCAFEBABF
LC_SYMTAB = 0x2
LC_SEGMENT_64 = 0x19
LC_FUNCTION_STARTS = 0x26
N_STAB = 0xE0
N_TYPE = 0x0E
N_SECT = 0x0E
N_EXT = 0x01


class MachOError(ValueError):
    """Dosya beklenen (arm64, 64-bit) Mach-O değil."""


@dataclass(frozen=True)
class Section:
    segname: str
    sectname: str
    addr: int
    size: int
    index: int  # 1 tabanlı bölüm numarası (nlist n_sect)


@dataclass(frozen=True)
class Symbol:
    address: int
    name: str
    external: bool
    sect: int


@dataclass
class MachOImage:
    """arm64 dilimi. ``data`` dilimin kendisi (fat ise yalnız o dilim)."""

    path: Path
    data: bytes
    slice_offset: int
    text_vmaddr: int
    text_fileoff: int
    sections: list[Section] = field(default_factory=list)
    function_starts: list[int] = field(default_factory=list)
    symbols: list[Symbol] = field(default_factory=list)

    def section(self, segname: str, sectname: str) -> Section | None:
        for s in self.sections:
            if s.segname == segname and s.sectname == sectname:
                return s
        return None

    def text_section(self) -> Section:
        sec = self.section("__TEXT", "__text")
        if sec is None:
            raise MachOError(f"{self.path}: __TEXT,__text yok")
        return sec

    def read_vm(self, addr: int, size: int) -> bytes:
        off = addr - self.text_vmaddr + self.text_fileoff
        if off < 0:
            return b""
        return self.data[off: off + size]


def _arm64_slice(data: bytes) -> tuple[bytes, int]:
    magic = struct.unpack_from(">I", data, 0)[0]
    if magic not in (FAT_MAGIC, FAT_MAGIC_64):
        return data, 0
    nfat = struct.unpack_from(">I", data, 4)[0]
    pos = 8
    for _ in range(min(nfat, 64)):
        if magic == FAT_MAGIC_64:
            cpu, _sub, off, size, _align, _res = struct.unpack_from(">iiQQII", data, pos)
            pos += 32
        else:
            cpu, _sub, off, size, _align = struct.unpack_from(">iiIII", data, pos)
            pos += 20
        if cpu == CPU_TYPE_ARM64:
            return data[off: off + size], off
    raise MachOError("fat dosyada arm64 dilimi yok")


def _uleb128_starts(data: bytes, dataoff: int, datasize: int, base: int) -> list[int]:
    starts: list[int] = []
    pos, end, cur = dataoff, dataoff + datasize, base
    while pos < end:
        val = shift = 0
        while True:
            b = data[pos]
            pos += 1
            val |= (b & 0x7F) << shift
            shift += 7
            if not b & 0x80:
                break
        if val == 0:
            break
        cur += val
        starts.append(cur)
    return starts


def load_macho_arm64(path: str | Path) -> MachOImage:
    """Mach-O arm64 dosyasını oku (thin ya da fat). Uymayan dosyada MachOError."""
    path = Path(path)
    raw = path.read_bytes()
    if len(raw) < 32:
        raise MachOError(f"{path}: çok kısa")
    data, slice_off = _arm64_slice(raw)
    magic, cputype, _sub, _ftype, ncmds, _sizeofcmds, _flags, _res = struct.unpack_from(
        "<IiiIIIII", data, 0,
    )
    if magic != MH_MAGIC_64 or cputype != CPU_TYPE_ARM64:
        raise MachOError(f"{path}: arm64 Mach-O değil (magic=0x{magic:x}, cpu=0x{cputype:x})")

    text_vm = text_fo = None
    sections: list[Section] = []
    fs_cmd = symtab = None
    off = 32
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", data, off)
        if cmd == LC_SEGMENT_64:
            segname = data[off + 8: off + 24].rstrip(b"\0").decode("ascii", "replace")
            vmaddr, _vmsize, fileoff, _filesize, _maxp, _initp, nsects, _fl = struct.unpack_from(
                "<QQQQiiII", data, off + 24,
            )
            if segname == "__TEXT":
                text_vm, text_fo = vmaddr, fileoff
            so = off + 72
            for _s in range(nsects):
                sect = data[so: so + 16].rstrip(b"\0").decode("ascii", "replace")
                seg = data[so + 16: so + 32].rstrip(b"\0").decode("ascii", "replace")
                addr, size = struct.unpack_from("<QQ", data, so + 32)
                sections.append(Section(seg, sect, addr, size, len(sections) + 1))
                so += 80
        elif cmd == LC_FUNCTION_STARTS:
            fs_cmd = struct.unpack_from("<II", data, off + 8)
        elif cmd == LC_SYMTAB:
            symtab = struct.unpack_from("<IIII", data, off + 8)
        off += cmdsize
    if text_vm is None or text_fo is None:
        raise MachOError(f"{path}: __TEXT segmenti yok")

    starts = _uleb128_starts(data, fs_cmd[0], fs_cmd[1], text_vm) if fs_cmd else []

    symbols: list[Symbol] = []
    if symtab:
        symoff, nsyms, stroff, _strsize = symtab
        for i in range(nsyms):
            strx, ntype, nsect, _desc, nvalue = struct.unpack_from("<IBBhQ", data, symoff + 16 * i)
            if ntype & N_STAB or (ntype & N_TYPE) != N_SECT:
                continue
            end = data.find(b"\0", stroff + strx)
            name = data[stroff + strx: end].decode("utf-8", "replace")
            symbols.append(Symbol(nvalue, name, bool(ntype & N_EXT), nsect))

    return MachOImage(
        path=path, data=data, slice_offset=slice_off, text_vmaddr=text_vm,
        text_fileoff=text_fo, sections=sections,
        function_starts=sorted(set(starts)), symbols=symbols,
    )


def text_symbols(img: MachOImage, *, external_only: bool) -> dict[int, list[str]]:
    """``__TEXT,__text`` içindeki semboller: adres -> isimler (sembol tablosu sırası)."""
    sec = img.text_section()
    out: dict[int, list[str]] = {}
    for s in img.symbols:
        if s.sect != sec.index or (external_only and not s.external):
            continue
        out.setdefault(s.address, []).append(s.name)
    return out


def function_extents(img: MachOImage, extra_starts: tuple[int, ...] | list[int] = ()) -> dict[int, int]:
    """Fonksiyon başlangıcı -> uzunluk (bayt).

    Başlangıçlar: LC_FUNCTION_STARTS (+ ``extra_starts``; üretici sembol
    adreslerini de ekler). Uzunluk bir sonraki başlangıca ya da ``__text``
    sonuna kadardır. Stripped ölçümde ``extra_starts`` VERİLMEZ: sembol adresi
    gerçeği sızdırır.
    """
    sec = img.text_section()
    lo, hi = sec.addr, sec.addr + sec.size
    starts = sorted({a for a in (*img.function_starts, *extra_starts) if lo <= a < hi})
    return {a: (starts[i + 1] if i + 1 < len(starts) else hi) - a for i, a in enumerate(starts)}
