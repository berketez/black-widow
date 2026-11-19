"""Mach-O 64 okuyucu (ARGE, ÜST VERİ hattı).

Yalnız araştırma betikleri içindir; ürün kodu değildir. Biçim kaynağı:
- <mach-o/loader.h>, <mach-o/nlist.h>, <mach-o/fat.h>, <mach-o/fixup-chains.h>
  (Xcode SDK; bu makinede `xcrun --show-sdk-path` altında, 2026-11-19'da okundu).

İkiliyi çalıştırmaz; yalnız baytları okur.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path

MH_MAGIC_64 = 0xFEEDFACF
FAT_MAGIC = 0xCAFEBABE
FAT_MAGIC_64 = 0xCAFEBABF

LC_REQ_DYLD = 0x80000000
LC_SYMTAB = 0x2
LC_UNIXTHREAD = 0x5
LC_DYSYMTAB = 0xB
LC_LOAD_DYLIB = 0xC
LC_SEGMENT_64 = 0x19
LC_UUID = 0x1B
LC_CODE_SIGNATURE = 0x1D
LC_DYLD_INFO = 0x22
LC_DYLD_INFO_ONLY = 0x22 | LC_REQ_DYLD
LC_FUNCTION_STARTS = 0x26
LC_MAIN = 0x28 | LC_REQ_DYLD
LC_DATA_IN_CODE = 0x29
LC_BUILD_VERSION = 0x32
LC_DYLD_EXPORTS_TRIE = 0x33 | LC_REQ_DYLD
LC_DYLD_CHAINED_FIXUPS = 0x34 | LC_REQ_DYLD

LC_NAMES = {
    LC_SYMTAB: "LC_SYMTAB", LC_UNIXTHREAD: "LC_UNIXTHREAD", LC_DYSYMTAB: "LC_DYSYMTAB",
    LC_LOAD_DYLIB: "LC_LOAD_DYLIB", LC_SEGMENT_64: "LC_SEGMENT_64", LC_UUID: "LC_UUID",
    LC_CODE_SIGNATURE: "LC_CODE_SIGNATURE", LC_DYLD_INFO: "LC_DYLD_INFO",
    LC_DYLD_INFO_ONLY: "LC_DYLD_INFO_ONLY", LC_FUNCTION_STARTS: "LC_FUNCTION_STARTS",
    LC_MAIN: "LC_MAIN", LC_DATA_IN_CODE: "LC_DATA_IN_CODE", LC_BUILD_VERSION: "LC_BUILD_VERSION",
    LC_DYLD_EXPORTS_TRIE: "LC_DYLD_EXPORTS_TRIE", LC_DYLD_CHAINED_FIXUPS: "LC_DYLD_CHAINED_FIXUPS",
}

CPU_TYPE_X86_64 = 0x01000007
CPU_TYPE_ARM64 = 0x0100000C
CPU_NAMES = {CPU_TYPE_X86_64: "x86_64", CPU_TYPE_ARM64: "arm64"}

N_STAB = 0xE0
N_TYPE = 0x0E
N_EXT = 0x01
N_SECT = 0x0E
N_UNDF = 0x00

# <mach-o/fixup-chains.h>
DYLD_CHAINED_PTR_ARM64E = 1
DYLD_CHAINED_PTR_64 = 2
DYLD_CHAINED_PTR_64_OFFSET = 6
DYLD_CHAINED_PTR_START_NONE = 0xFFFF
DYLD_CHAINED_PTR_START_MULTI = 0x8000


@dataclass
class Section:
    segname: str
    sectname: str
    addr: int
    size: int
    offset: int
    flags: int
    index: int  # 1 tabanlı bölüm sırası (n_sect)

    @property
    def ad(self) -> str:
        return f"{self.segname},{self.sectname}"


@dataclass
class Segment:
    name: str
    vmaddr: int
    vmsize: int
    fileoff: int
    filesize: int
    maxprot: int
    initprot: int
    sections: list = field(default_factory=list)


@dataclass
class Symbol:
    name: str
    n_type: int
    n_sect: int
    n_desc: int
    value: int


def uleb(data: bytes, pos: int):
    result = 0
    shift = 0
    while True:
        b = data[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not b & 0x80:
            return result, pos
        shift += 7


def fat_slices(raw: bytes):
    """(cpu adı, ofset, boyut) listesi; ince dosyada tek öğe."""
    magic_be = struct.unpack_from(">I", raw, 0)[0]
    if magic_be in (FAT_MAGIC, FAT_MAGIC_64):
        n = struct.unpack_from(">I", raw, 4)[0]
        out = []
        pos = 8
        for _ in range(n):
            if magic_be == FAT_MAGIC:
                cpu, _sub, off, size, _al = struct.unpack_from(">IIIII", raw, pos)
                pos += 20
            else:
                cpu, _sub, off, size, _al, _r = struct.unpack_from(">IIQQII", raw, pos)
                pos += 32
            out.append((CPU_NAMES.get(cpu, hex(cpu)), off, size))
        return out
    magic = struct.unpack_from("<I", raw, 0)[0]
    if magic != MH_MAGIC_64:
        raise ValueError(f"Mach-O 64 değil: magic={magic:#x}")
    cpu = struct.unpack_from("<I", raw, 4)[0]
    return [(CPU_NAMES.get(cpu, hex(cpu)), 0, len(raw))]


class MachO:
    """Tek dilim (ince) Mach-O 64."""

    def __init__(self, data: bytes, kaynak: str = ""):
        self.data = data
        self.kaynak = kaynak
        magic, cpu, _sub, self.filetype, ncmds, _sz, self.flags, _r = struct.unpack_from("<IIIIIIII", data, 0)
        if magic != MH_MAGIC_64:
            raise ValueError(f"Mach-O 64 değil: {magic:#x}")
        self.cpu = CPU_NAMES.get(cpu, hex(cpu))
        self.segments: list[Segment] = []
        self.sections: list[Section] = []
        self.cmds: list[tuple[int, int, int]] = []  # (cmd, ofset, boyut)
        self.symtab = None
        self.dysymtab = None
        self.entryoff = None
        self.unixthread_pc = None
        self.dylibs: list[str] = []
        self.function_starts_cmd = None
        self.chained_fixups_cmd = None
        self.exports_trie_cmd = None
        self.dyld_info = None
        self.uuid = None
        pos = 32
        for _ in range(ncmds):
            cmd, size = struct.unpack_from("<II", data, pos)
            self.cmds.append((cmd, pos, size))
            if cmd == LC_SEGMENT_64:
                name = data[pos + 8:pos + 24].split(b"\0")[0].decode()
                vmaddr, vmsize, fileoff, filesize, maxprot, initprot, nsects, _fl = struct.unpack_from(
                    "<QQQQiiII", data, pos + 24)
                seg = Segment(name, vmaddr, vmsize, fileoff, filesize, maxprot, initprot)
                sp = pos + 72
                for _i in range(nsects):
                    sectname = data[sp:sp + 16].split(b"\0")[0].decode()
                    segname = data[sp + 16:sp + 32].split(b"\0")[0].decode()
                    addr, ssize, off, _al, _ro, _nr, sflags = struct.unpack_from("<QQIIIII", data, sp + 32)
                    sec = Section(segname, sectname, addr, ssize, off, sflags, len(self.sections) + 1)
                    seg.sections.append(sec)
                    self.sections.append(sec)
                    sp += 80
                self.segments.append(seg)
            elif cmd == LC_SYMTAB:
                self.symtab = struct.unpack_from("<IIII", data, pos + 8)
            elif cmd == LC_DYSYMTAB:
                self.dysymtab = struct.unpack_from("<IIIIII", data, pos + 8)
            elif cmd == LC_MAIN:
                self.entryoff = struct.unpack_from("<Q", data, pos + 8)[0]
            elif cmd == LC_UNIXTHREAD:
                flavor, count = struct.unpack_from("<II", data, pos + 8)
                st = pos + 16
                if self.cpu == "arm64":  # ARM_THREAD_STATE64: x0..x28, fp, lr, sp, pc
                    self.unixthread_pc = struct.unpack_from("<Q", data, st + 32 * 8)[0]
                elif self.cpu == "x86_64":  # x86_THREAD_STATE64: rip 16. yazmaç
                    self.unixthread_pc = struct.unpack_from("<Q", data, st + 16 * 8)[0]
            elif cmd == LC_LOAD_DYLIB:
                noff = struct.unpack_from("<I", data, pos + 8)[0]
                self.dylibs.append(data[pos + noff:pos + size].split(b"\0")[0].decode())
            elif cmd == LC_FUNCTION_STARTS:
                self.function_starts_cmd = struct.unpack_from("<II", data, pos + 8)
            elif cmd == LC_DYLD_CHAINED_FIXUPS:
                self.chained_fixups_cmd = struct.unpack_from("<II", data, pos + 8)
            elif cmd == LC_DYLD_EXPORTS_TRIE:
                self.exports_trie_cmd = struct.unpack_from("<II", data, pos + 8)
            elif cmd in (LC_DYLD_INFO, LC_DYLD_INFO_ONLY):
                self.dyld_info = struct.unpack_from("<IIIIIIIIII", data, pos + 8)
            elif cmd == LC_UUID:
                self.uuid = data[pos + 8:pos + 24].hex()
            pos += size
        self._fixups = None
        self._imports = None

    # ---- adres dönüşümü -------------------------------------------------
    @property
    def image_base(self) -> int:
        for s in self.segments:
            if s.name == "__TEXT":
                return s.vmaddr
        raise ValueError("__TEXT yok")

    def seg(self, name):
        for s in self.segments:
            if s.name == name:
                return s
        return None

    def sec(self, segname, sectname):
        for s in self.sections:
            if s.segname == segname and s.sectname == sectname:
                return s
        return None

    def secs_named(self, sectname):
        return [s for s in self.sections if s.sectname == sectname]

    def sec_bytes(self, sec: Section) -> bytes:
        if sec.offset == 0:
            return b""
        return self.data[sec.offset:sec.offset + sec.size]

    def vm_to_off(self, addr: int):
        for s in self.segments:
            if s.vmaddr <= addr < s.vmaddr + s.filesize:
                return s.fileoff + (addr - s.vmaddr)
        return None

    def off_to_vm(self, off: int):
        for s in self.segments:
            if s.filesize and s.fileoff <= off < s.fileoff + s.filesize:
                return s.vmaddr + (off - s.fileoff)
        return None

    def sec_of(self, addr: int):
        for s in self.sections:
            if s.addr <= addr < s.addr + s.size:
                return s
        return None

    def read(self, addr: int, n: int):
        off = self.vm_to_off(addr)
        if off is None:
            return None
        return self.data[off:off + n]

    def u32(self, addr):
        b = self.read(addr, 4)
        return struct.unpack("<I", b)[0] if b and len(b) == 4 else None

    def i32(self, addr):
        b = self.read(addr, 4)
        return struct.unpack("<i", b)[0] if b and len(b) == 4 else None

    def u64(self, addr):
        b = self.read(addr, 8)
        return struct.unpack("<Q", b)[0] if b and len(b) == 8 else None

    def cstr(self, addr: int, azami: int = 4096):
        off = self.vm_to_off(addr)
        if off is None:
            return None
        end = self.data.find(b"\0", off, off + azami)
        if end < 0:
            return None
        return self.data[off:end].decode("utf-8", "replace")

    @property
    def entry_vm(self):
        if self.entryoff is not None:
            return self.image_base + self.entryoff
        return self.unixthread_pc

    # ---- sembol tablosu -------------------------------------------------
    def symbols(self) -> list[Symbol]:
        if not self.symtab:
            return []
        symoff, nsyms, stroff, strsize = self.symtab
        out = []
        d = self.data
        for i in range(nsyms):
            strx, n_type, n_sect, n_desc, value = struct.unpack_from("<IBBHQ", d, symoff + 16 * i)
            end = d.find(b"\0", stroff + strx, stroff + strsize)
            name = d[stroff + strx:end].decode("utf-8", "replace") if strx else ""
            out.append(Symbol(name, n_type, n_sect, n_desc, value))
        return out

    def defined_symbols(self) -> list[Symbol]:
        """Hata ayıklama (stab) dışı, bir bölümde tanımlı semboller."""
        return [s for s in self.symbols() if not (s.n_type & N_STAB) and (s.n_type & N_TYPE) == N_SECT]

    def text_sections(self):
        """Yürütülebilir kod bölümleri (S_ATTR_PURE_INSTRUCTIONS / SOME_INSTRUCTIONS)."""
        return [s for s in self.sections if s.flags & 0x80000400]

    # ---- LC_FUNCTION_STARTS --------------------------------------------
    def function_starts(self):
        if not self.function_starts_cmd:
            return None
        off, size = self.function_starts_cmd
        blob = self.data[off:off + size]
        addr = self.image_base
        out = []
        pos = 0
        while pos < len(blob):
            delta, pos = uleb(blob, pos)
            if delta == 0:
                break
            addr += delta
            out.append(addr)
        return out

    # ---- zincirli düzeltmeler (LC_DYLD_CHAINED_FIXUPS) ------------------
    def imports(self):
        if self._imports is not None:
            return self._imports
        self._imports = []
        if not self.chained_fixups_cmd:
            return self._imports
        base, _size = self.chained_fixups_cmd
        d = self.data
        _ver, _starts, imports_off, symbols_off, imports_count, imports_format, _sf = struct.unpack_from(
            "<IIIIIII", d, base)
        for i in range(imports_count):
            if imports_format == 1:  # DYLD_CHAINED_IMPORT
                v = struct.unpack_from("<I", d, base + imports_off + 4 * i)[0]
                name_off = v >> 9
            elif imports_format == 2:  # DYLD_CHAINED_IMPORT_ADDEND
                v = struct.unpack_from("<I", d, base + imports_off + 8 * i)[0]
                name_off = v >> 9
            else:  # DYLD_CHAINED_IMPORT_ADDEND64
                v = struct.unpack_from("<Q", d, base + imports_off + 16 * i)[0]
                name_off = v >> 32
            p = base + symbols_off + name_off
            end = d.find(b"\0", p)
            self._imports.append(d[p:end].decode("utf-8", "replace"))
        return self._imports

    def fixups(self) -> dict:
        """Düzeltme yeri (vm adresi) → ('rebase', hedef vm) | ('bind', içe aktarım sırası).

        Zincirli düzeltme yoksa boş sözlük döner (o zaman göstericiler dosyada ham vm adresidir).
        """
        if self._fixups is not None:
            return self._fixups
        self._fixups = {}
        if not self.chained_fixups_cmd:
            return self._fixups
        base, _size = self.chained_fixups_cmd
        d = self.data
        _ver, starts_off = struct.unpack_from("<II", d, base)
        sbase = base + starts_off
        seg_count = struct.unpack_from("<I", d, sbase)[0]
        img = self.image_base
        for si in range(seg_count):
            seg_info_off = struct.unpack_from("<I", d, sbase + 4 + 4 * si)[0]
            if seg_info_off == 0:
                continue
            p = sbase + seg_info_off
            _size, page_size, pointer_format, segment_offset, _maxp, page_count = struct.unpack_from(
                "<IHHQIH", d, p)
            if pointer_format not in (DYLD_CHAINED_PTR_64, DYLD_CHAINED_PTR_64_OFFSET):
                raise NotImplementedError(f"gösterici biçimi {pointer_format} desteklenmiyor ({self.kaynak})")
            for pi in range(page_count):
                start = struct.unpack_from("<H", d, p + 22 + 2 * pi)[0]
                if start == DYLD_CHAINED_PTR_START_NONE:
                    continue
                if start & DYLD_CHAINED_PTR_START_MULTI:
                    raise NotImplementedError("çok başlangıçlı sayfa")
                vm = img + segment_offset + pi * page_size + start
                while True:
                    off = self.vm_to_off(vm)
                    raw = struct.unpack_from("<Q", d, off)[0]
                    nxt = (raw >> 51) & 0xFFF
                    if raw >> 63:
                        self._fixups[vm] = ("bind", raw & 0xFFFFFF)
                    else:
                        target = raw & 0xFFFFFFFFF
                        high8 = (raw >> 36) & 0xFF
                        if pointer_format == DYLD_CHAINED_PTR_64_OFFSET:
                            target += img
                        self._fixups[vm] = ("rebase", target | (high8 << 56))
                    if nxt == 0:
                        break
                    vm += nxt * 4
        return self._fixups

    def ptr(self, addr: int):
        """addr'deki 8 baytlık göstericiyi çöz. Dönen: hedef vm adresi, içe aktarımsa ('bind', ad), yoksa None."""
        fx = self.fixups()
        if fx:
            e = fx.get(addr)
            if e is None:
                v = self.u64(addr)
                return v if v else None  # düzeltme yeri değil: ham değer (çoğu kez 0)
            if e[0] == "rebase":
                return e[1]
            imps = self.imports()
            return ("bind", imps[e[1]] if e[1] < len(imps) else f"#{e[1]}")
        v = self.u64(addr)
        return v if v else None


def load(path, dilim: str | None = None) -> MachO:
    raw = Path(path).read_bytes()
    sl = fat_slices(raw)
    if len(sl) == 1:
        cpu, off, size = sl[0]
    else:
        if dilim is None:
            raise ValueError(f"evrensel ikili, dilim seç: {[s[0] for s in sl]}")
        m = [s for s in sl if s[0] == dilim]
        if not m:
            raise ValueError(f"dilim yok: {dilim}")
        cpu, off, size = m[0]
    return MachO(raw[off:off + size], kaynak=f"{path}[{cpu}]")


def load_all(path) -> list[MachO]:
    raw = Path(path).read_bytes()
    return [MachO(raw[off:off + size], kaynak=f"{path}[{cpu}]") for cpu, off, size in fat_slices(raw)]
