#!/usr/bin/python3 -I
"""Mach-O (arm64, ince) bölümlerinin boyut ve sha256 özeti; içerik BASILMAZ.

Yeniden derleme denemesinde kodun (__TEXT,__text) ve sabit verinin bayt bayt aynı
olup olmadığını görmek için. Kullanım: bolum_ozeti.py <ikili> [bölüm ...]
"""
import hashlib
import struct
import sys

LC_SEGMENT_64 = 0x19


def bolumler(veri):
    magic, _cpu, _sub, _ftype, ncmds, _size, _flags, _res = struct.unpack_from("<IiiIIIII", veri, 0)
    if magic != 0xFEEDFACF:
        raise SystemExit("ince 64-bit Mach-O değil")
    off = 32
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", veri, off)
        if cmd == LC_SEGMENT_64:
            nsects = struct.unpack_from("<I", veri, off + 64)[0]
            s = off + 72
            for _ in range(nsects):
                sect = veri[s:s + 16].rstrip(b"\0").decode()
                seg = veri[s + 16:s + 32].rstrip(b"\0").decode()
                _addr, size, offset = struct.unpack_from("<QQI", veri, s + 32)
                flags = struct.unpack_from("<I", veri, s + 64)[0]
                yield seg, sect, size, offset, flags
                s += 80
        off += cmdsize


def main():
    yol = sys.argv[1]
    istenen = set(sys.argv[2:])
    veri = open(yol, "rb").read()
    for seg, sect, size, offset, flags in bolumler(veri):
        ad = f"{seg},{sect}"
        if istenen and ad not in istenen:
            continue
        zerofill = (flags & 0xFF) in (0x1, 0xC, 0x12)
        h = "-" if zerofill else hashlib.sha256(veri[offset:offset + size]).hexdigest()
        print(f"{ad:28s} {size:10d} {h}")


if __name__ == "__main__":
    main()
