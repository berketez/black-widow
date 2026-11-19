"""Go tip verisi: itab ve yöntem tabloları (ARGE, ÜST VERİ hattı; ürün kodu değil).

Amaç: `pclntab` adını ZORUNLU yapılarla çapraz denetlemek (I4).
Biçim kaynağı (Go kaynak ağacı, `release-branch.go1.27`, 2026-11-19):
- `src/internal/abi/type.go`: `Type` (48 bayt; TFlag, Kind_, Str, PtrToThis), `TFlagUncommon` 1, `TFlagExtraStar` 2,
  `UncommonType` (PkgPath, Mcount, Xcount, Moff, _), `Method` (Name, Mtyp, Ifn, Tfn), `Imethod` (Name, Typ),
  `InterfaceType` (Type, PkgPath, Methods), ad kodlaması (bayrak baytı, varint uzunluk, baytlar), `Uncommon()`.
- `src/runtime/iface.go`: `itabInit` (arayüz yöntemi ↔ somut tip yöntemi eşlemesi AD DİZGİSİ ve tip üzerinden),
  `addModuleItabs` (1.27: `types + itaboffset`, boyut `itabsize`, adım `itab.Size()`); 1.26'da `__itablink` bölümü.
- `src/runtime/symtab.go`: `moduledata` alan sırası (1.26 ve 1.27 ayrı).
"""
from __future__ import annotations

import struct

KIND_ADI = {17: "array", 18: "chan", 19: "func", 20: "interface", 21: "map", 22: "pointer", 23: "slice",
            25: "struct"}
# Uncommon()'dan: türe özgü yapının boyutu (64 bit). Map ve Func yerleşimi sürüme bağlı → atlanır.
UNCOMMON_OFSETI = {25: 80, 22: 56, 23: 56, 17: 72, 18: 64, 20: 80}


class GoTipleri:
    def __init__(self, m, p, surum: str):
        """m: MachO, p: PclnTab, surum: 'go1.27.4' gibi."""
        self.m = m
        self.p = p
        self.surum = surum
        self.minor = int(surum.split(".")[1]) if surum and surum.startswith("go1.") else 0
        ham = p.md["ham_24_47"] if p.md else None
        self.types = self.etypes = None
        self.itab_araligi = None
        if ham and self.minor >= 27:
            # … end, gcdata, gcbss, types, typedesclen, etypes, itaboffset, itabsize, rodata, gofunc, epclntab
            self.types, self.typedesclen, self.etypes = ham[13], m.u64(p.md["adres"] + 8 * 38), ham[15]
            itaboff = m.u64(p.md["adres"] + 8 * 40)
            itabsize = m.u64(p.md["adres"] + 8 * 41)
            self.itab_araligi = (self.types + itaboff, self.types + itaboff + itabsize)
        elif ham:
            # … end, gcdata, gcbss, types, etypes, rodata, gofunc, …
            self.types, self.etypes = ham[13], ham[14]
        self.text = p.text

    # ---- temel okuma ----------------------------------------------------
    def name_at(self, off: int):
        """`types + off` adresindeki kodlanmış ad."""
        if off <= 0 or self.types is None:
            return None
        return self.name_ptr(self.types + off)

    def name_ptr(self, addr: int):
        b = self.m.read(addr, 12)
        if not b:
            return None
        n = 0
        shift = 0
        i = 1
        while True:
            c = b[i]
            n |= (c & 0x7F) << shift
            i += 1
            if not c & 0x80:
                break
            shift += 7
        raw = self.m.read(addr + i, n)
        if raw is None:
            return None
        return raw.decode("utf-8", "replace")

    def name_bytes_addr(self, off: int):
        """Ad baytlarının (uzunluk önekinden sonraki) adresi ve uzunluğu — bozma deneyi için."""
        addr = self.types + off
        b = self.m.read(addr, 12)
        n = 0
        shift = 0
        i = 1
        while True:
            c = b[i]
            n |= (c & 0x7F) << shift
            i += 1
            if not c & 0x80:
                break
            shift += 7
        return addr + i, n

    def type_hdr(self, t: int):
        b = self.m.read(t, 48)
        if not b or len(b) < 48:
            return None
        _size, _ptrb, _hash, tflag, _al, _fal, kind, _eq, _gc, strr, ptt = struct.unpack("<QQIBBBBQQii", b)
        return {"tflag": tflag, "kind": kind & 0x1F, "str": strr, "ptr_to_this": ptt}

    def type_str(self, t: int):
        h = self.type_hdr(t)
        if not h:
            return None
        s = self.name_at(h["str"])
        if s and h["tflag"] & 2 and s.startswith("*"):
            s = s[1:]
        return s

    def uncommon(self, t: int):
        """(paket yolu, [(yöntem adı, ad ofseti, ifn adresi, tfn adresi)]) ya da None."""
        h = self.type_hdr(t)
        if not h or not h["tflag"] & 1:
            return None
        k = h["kind"]
        if k in UNCOMMON_OFSETI:
            u = t + UNCOMMON_OFSETI[k]
        elif k in (19, 21):
            return None
        else:
            u = t + 48
        b = self.m.read(u, 16)
        if not b:
            return None
        pkgpath, mcount, _xcount, moff, _ = struct.unpack("<iHHII", b)
        if mcount > 4096 or moff > 1 << 20:
            return None
        pkg = self.name_at(pkgpath) if pkgpath > 0 else None
        out = []
        mb = self.m.read(u + moff, 16 * mcount) if mcount else b""
        if mb is None:
            return None
        for i in range(mcount):
            name, _mtyp, ifn, tfn = struct.unpack_from("<iiii", mb, 16 * i)
            out.append((self.name_at(name), name, self.text + ifn if ifn not in (-1, 0) else None,
                        self.text + tfn if tfn not in (-1, 0) else None))
        return pkg, out

    def iface_methods(self, t: int):
        """Arayüz tipinin yöntem adları (ad, ad ofseti)."""
        h = self.type_hdr(t)
        if not h or h["kind"] != 20:
            return None
        mp = self.m.ptr(t + 56)
        n = self.m.u64(t + 64)
        if not isinstance(mp, int) or n is None or n > 4096:
            return None
        out = []
        for i in range(n):
            name = self.m.i32(mp + 8 * i)
            out.append((self.name_at(name), name))
        return out

    # ---- itab'lar -------------------------------------------------------
    def itabs(self):
        """[(itab adresi, arayüz tipi, somut tip, [Fun adresleri])]"""
        m = self.m
        adresler = []
        if self.itab_araligi:
            a, son = self.itab_araligi
            while a < son:
                inter = m.ptr(a)
                if not isinstance(inter, int):
                    break
                ms = self.iface_methods(inter)
                if ms is None:
                    break
                adresler.append(a)
                a += 24 + 8 * max(len(ms), 1)
        else:
            for sec in m.secs_named("__itablink"):
                for i in range(sec.size // 8):
                    v = m.ptr(sec.addr + 8 * i)
                    if isinstance(v, int):
                        adresler.append(v)
        out = []
        for a in adresler:
            inter = m.ptr(a)
            typ = m.ptr(a + 8)
            if not isinstance(inter, int) or not isinstance(typ, int):
                continue
            ms = self.iface_methods(inter)
            if ms is None:
                continue
            fun = []
            for i in range(len(ms)):
                v = m.ptr(a + 24 + 8 * i)
                fun.append(v if isinstance(v, int) else None)
            out.append((a, inter, typ, ms, fun))
        return out

    def ulasilan_tipler(self, itablar):
        """itab'lardan ulaşılan somut tipler: itab tipi, gösterici ise öğesi, PtrToThis."""
        gor = set()
        sira = [t for _a, _i, t, _m, _f in itablar]
        if self.minor < 27:
            for sec in self.m.secs_named("__typelink"):
                for i in range(sec.size // 4):
                    off = self.m.i32(sec.addr + 4 * i)
                    if off and off > 0:
                        sira.append(self.types + off)
        while sira:
            t = sira.pop()
            if t in gor or t is None:
                continue
            h = self.type_hdr(t)
            if not h or h["kind"] == 0 or h["kind"] > 26:
                continue
            gor.add(t)
            if h["kind"] == 22:
                e = self.m.ptr(t + 48)
                if isinstance(e, int):
                    sira.append(e)
            if h["ptr_to_this"] > 0:
                sira.append(self.types + h["ptr_to_this"])
        return gor
