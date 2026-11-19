"""Go `pclntab` / `moduledata` okuyucu (ARGE, ÜST VERİ hattı; ürün kodu değil).

Biçim kaynağı (resmî Go kaynak ağacı; 2026-11-19'da okundu, dal `release-branch.go1.26` ve `release-branch.go1.27`):
- `src/runtime/symtab.go`: `pcHeader`, `moduledata`, `functab`, `findfuncbucket`, `moduledataverify1`,
  `pcvalue`, `step`, `readvarint`, `funcfile`, `funcpkgpath`
- `src/runtime/runtime2.go`: `_func`
- `src/internal/abi/symtab.go`: `Go118PCLnTabMagic` 0xfffffff0, `Go120PCLnTabMagic` 0xfffffff1,
  `FuncTabBucketSize` 4096, `FuncID*`, `PCDATA_*`, `FUNCDATA_*`
- `src/debug/buildinfo/buildinfo.go`: `__go_buildinfo` başlığı

Go 1.26'dan başlayarak `pcHeader`'ın eski `textStart` alanı kullanılmıyor (0 yazılıyor; kaynakta `_ uintptr`);
metin tabanı `moduledata.text`'ten okunur. Bu betik iki durumu da ele alır ve hangisini kullandığını yazar.

İkiliyi çalıştırmaz.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass

MAGIC_118 = 0xFFFFFFF0
MAGIC_120 = 0xFFFFFFF1
MAGIC_ADLARI = {0xFFFFFFFB: "go1.2", 0xFFFFFFFA: "go1.16", MAGIC_118: "go1.18", MAGIC_120: "go1.20+"}
FUNC_TAB_BUCKET = 4096
FUNC_SABIT = 44  # _func sabit kısmı (bayt)

FUNC_ID = [
    "Normal", "abort", "asmcgocall", "asyncPreempt", "cgocallback", "corostart", "debugCallV2",
    "gcBgMarkWorker", "goexit", "gogo", "gopanic", "handleAsyncEvent", "mcall", "morestack", "mstart",
    "panicwrap", "rt0_go", "runtime_main", "runFinalizers", "runCleanups", "sigpanic", "systemstack",
    "systemstack_switch", "Wrapper",
]
# funcID → çalışma zamanının beklediği ad (internal/abi/symtab.go; cmd/internal/objabi/funcid.go eşlemesi).
FUNC_ID_ADI = {
    "abort": "runtime.abort", "asmcgocall": "runtime.asmcgocall", "asyncPreempt": "runtime.asyncPreempt",
    "cgocallback": "runtime.cgocallback", "corostart": "runtime.corostart",
    "debugCallV2": "runtime.debugCallV2", "gcBgMarkWorker": "runtime.gcBgMarkWorker",
    "goexit": "runtime.goexit", "gogo": "runtime.gogo", "gopanic": "runtime.gopanic",
    "handleAsyncEvent": "runtime.handleAsyncEvent", "mcall": "runtime.mcall",
    "morestack": "runtime.morestack", "mstart": "runtime.mstart", "panicwrap": "runtime.panicwrap",
    "rt0_go": "runtime.rt0_go", "runtime_main": "runtime.main", "runFinalizers": "runtime.runFinalizers",
    "runCleanups": "runtime.runCleanups", "sigpanic": "runtime.sigpanic",
    "systemstack": "runtime.systemstack", "systemstack_switch": "runtime.systemstack_switch",
}


@dataclass
class GoFunc:
    sira: int
    entry: int       # vm adresi
    end: int         # sonraki girişin adresi
    func_off: int    # pclntable içindeki ofset
    name_off: int
    name: str
    args: int
    deferreturn: int
    pcsp: int
    pcfile: int
    pcln: int
    npcdata: int
    cu_offset: int
    start_line: int
    func_id: int
    flag: int
    nfuncdata: int


def _varint(buf, pos):
    v = 0
    shift = 0
    while True:
        b = buf[pos]
        pos += 1
        v |= (b & 0x7F) << (shift & 31)
        if not b & 0x80:
            return v, pos
        shift += 7


def pkg_of(name: str) -> str:
    """`runtime.funcpkgpath` ile aynı kural; ek olarak tip parametresi köşeli ayracı önce kesilir."""
    kes = name.find("[")
    govde = name if kes < 0 else name[:kes]
    i = govde.rfind("/")
    j = govde.find(".", i + 1)
    if j < 0:
        return ""
    return govde[:j]


def sinif(pkg: str, ana_modul: str | None) -> str:
    """Paket sınıfı: çalışma zamanı / standart kitaplık / üçüncü taraf / programın kendi / derleyici üretimi."""
    if pkg == "":
        return "paketsiz"
    if pkg.startswith(("type:", "go:")):
        return "derleyici"
    if ana_modul and pkg.startswith(ana_modul + "/vendor/"):
        return "ucuncu_taraf"  # ana modülün içine kopyalanmış bağımlılıklar (vendor dizini)
    if pkg == "main" or (ana_modul and (pkg == ana_modul or pkg.startswith(ana_modul + "/"))):
        return "kendi"
    if pkg == "runtime" or pkg.startswith(("runtime/", "internal/runtime/")):
        return "calisma_zamani"
    ilk = pkg.split("/", 1)[0]
    if pkg.startswith("vendor/"):
        return "standart"  # standart kitaplığın kendi içine aldığı golang.org/x kopyaları
    if "." in ilk:
        return "ucuncu_taraf"
    return "standart"


class PclnTab:
    def __init__(self, m, addr: int | None = None):
        self.m = m
        self.notlar: list[str] = []
        if addr is None:
            sec = next(iter(m.secs_named("__gopclntab")), None)
            if sec is not None:
                addr = sec.addr
                self.bulma = "bölüm adı (__gopclntab)"
            else:
                addr = self._tara()
                self.bulma = "imza taraması"
        else:
            self.bulma = "verilen adres"
        if addr is None:
            raise ValueError("pclntab bulunamadı")
        self.addr = addr
        h = m.read(addr, 72)
        (self.magic, self.pad1, self.pad2, self.min_lc, self.ptr_size, self.nfunc, self.nfiles,
         self.text_start_hdr, self.funcname_off, self.cu_off, self.filetab_off, self.pctab_off,
         self.pcln_off) = struct.unpack("<IBBBBQQQQQQQQ", h)
        if self.magic not in (MAGIC_118, MAGIC_120):
            raise NotImplementedError(f"pclntab imzası desteklenmiyor: {self.magic:#x}")
        if self.ptr_size != 8:
            raise NotImplementedError("yalnız 64 bit")
        self.off0 = m.vm_to_off(addr)
        self.md = self._moduledata()
        if self.md and self.md.get("text"):
            self.text = self.md["text"]
            self.text_kaynagi = "moduledata.text"
            if self.text_start_hdr and self.text_start_hdr != self.text:
                self.notlar.append(
                    f"başlıktaki textStart ({self.text_start_hdr:#x}) ≠ moduledata.text ({self.text:#x})")
        elif self.text_start_hdr:
            self.text = self.text_start_hdr
            self.text_kaynagi = "pcHeader.textStart"
        else:
            self.text = None
            self.text_kaynagi = "yok"
        self._funcs = None

    # ---- bulma ----------------------------------------------------------
    def _tara(self):
        d = self.m.data
        for magic in (MAGIC_120, MAGIC_118):
            pat = struct.pack("<I", magic) + b"\0\0"
            pos = d.find(pat)
            while pos >= 0:
                if d[pos + 6] in (1, 2, 4) and d[pos + 7] == 8:
                    vm = self.m.off_to_vm(pos)
                    if vm is not None:
                        return vm
                pos = d.find(pat, pos + 1)
        return None

    def _moduledata(self):
        """`moduledata`'yı bul: ilk alanı `pcHeader`'a gösterici; ikinci alan funcnametab dilimi."""
        m = self.m
        adaylar = []
        fx = m.fixups()
        if fx:
            adaylar = [loc for loc, e in fx.items() if e[0] == "rebase" and e[1] == self.addr]
        else:
            pat = struct.pack("<Q", self.addr)
            for seg in m.segments:
                if seg.name in ("__DATA", "__DATA_CONST") and seg.filesize:
                    blob = m.data[seg.fileoff:seg.fileoff + seg.filesize]
                    pos = blob.find(pat)
                    while pos >= 0:
                        if pos % 8 == 0:
                            adaylar.append(seg.vmaddr + pos)
                        pos = blob.find(pat, pos + 1)
        self.md_adaylari = len(adaylar)
        for loc in adaylar:
            def p(i, loc=loc):
                v = m.ptr(loc + 8 * i)
                return v if isinstance(v, int) else None

            def u(i, loc=loc):
                return m.u64(loc + 8 * i)
            if p(1) != self.addr + self.funcname_off:
                continue
            md = {
                "adres": loc,
                "funcnametab": (p(1), u(2)), "cutab": (p(4), u(5)), "filetab": (p(7), u(8)),
                "pctab": (p(10), u(11)), "pclntable": (p(13), u(14)), "ftab": (p(16), u(17)),
                "findfunctab": p(19), "minpc": p(20), "maxpc": p(21), "text": p(22), "etext": p(23),
            }
            # 1.26: … end, gcdata, gcbss, types, etypes, rodata, gofunc, epclntab
            # 1.27: … end, gcdata, gcbss, types, typedesclen, etypes, itaboffset, itabsize, rodata, gofunc, epclntab
            ham = [m.ptr(loc + 8 * i) for i in range(24, 48)]
            md["ham_24_47"] = [v if isinstance(v, int) else None for v in ham]
            return md
        return None

    # ---- tablolar -------------------------------------------------------
    def _b(self, rel: int, n: int) -> bytes:
        return self.m.data[self.off0 + rel:self.off0 + rel + n]

    def name_at(self, name_off: int) -> str:
        if name_off == 0:
            return ""
        p = self.off0 + self.funcname_off + name_off
        end = self.m.data.find(b"\0", p)
        return self.m.data[p:end].decode("utf-8", "replace")

    def funcs(self) -> list[GoFunc]:
        if self._funcs is not None:
            return self._funcs
        d = self.m.data
        base = self.off0 + self.pcln_off
        n = self.nfunc
        ftab = struct.unpack_from(f"<{2 * (n + 1)}I", d, base)
        text = self.text or 0
        out = []
        for i in range(n):
            entryoff, funcoff = ftab[2 * i], ftab[2 * i + 1]
            (e2, name_off, args, deferreturn, pcsp, pcfile, pcln, npcdata, cu_offset, start_line, func_id,
             flag, _pad, nfuncdata) = struct.unpack_from("<IiiIIIIIIiBBBB", d, base + funcoff)
            if e2 != entryoff:
                self.notlar.append(f"func[{i}] entryOff uyuşmuyor: ftab {entryoff:#x} ≠ _func {e2:#x}")
            out.append(GoFunc(i, text + entryoff, text + ftab[2 * (i + 1)], funcoff, name_off,
                              self.name_at(name_off), args, deferreturn, pcsp, pcfile, pcln, npcdata,
                              cu_offset, start_line, func_id, flag, nfuncdata))
        self.son_entryoff = ftab[2 * n]
        self._funcs = out
        return out

    def pc_table(self, off: int, entry: int):
        """pc-değer tablosunu çöz: [(değer, başlangıç pc, bitiş pc)]. `runtime.pcvalue` / `step` ile aynı."""
        if off == 0:
            return []
        d = self.m.data
        pos = self.off0 + self.pctab_off + off
        pc = entry
        val = -1
        out = []
        ilk = True
        while True:
            uv, pos2 = _varint(d, pos)
            if uv == 0 and not ilk:
                break
            pos = pos2
            val += -(uv & 1) ^ (uv >> 1)
            pcdelta, pos = _varint(d, pos)
            npc = pc + pcdelta * self.min_lc
            out.append((val, pc, npc))
            pc = npc
            ilk = False
        return out

    def file_of(self, f: GoFunc):
        """Fonksiyonun giriş adresindeki kaynak dosya yolu (`funcline1` → `funcfile`)."""
        if f.pcfile == 0:
            return None
        d = self.m.data
        pos = self.off0 + self.pctab_off + f.pcfile
        uv, pos = _varint(d, pos)
        fileno = -1 + (-(uv & 1) ^ (uv >> 1))
        if fileno < 0:
            return None
        fileoff = struct.unpack_from("<I", d, self.off0 + self.cu_off + 4 * (f.cu_offset + fileno))[0]
        if fileoff == 0xFFFFFFFF:
            return None
        p = self.off0 + self.filetab_off + fileoff
        end = d.find(b"\0", p)
        return d[p:end].decode("utf-8", "replace")

    def funcname_strings(self):
        """funcnametab içindeki bütün dizgiler (ofset → ad). Satır içi (inline) fonksiyon adları da buradadır."""
        start = self.off0 + self.funcname_off
        end = self.off0 + self.cu_off
        blob = self.m.data[start:end]
        out = {}
        pos = 0
        while pos < len(blob):
            e = blob.find(b"\0", pos)
            if e < 0:
                break
            if e > pos:
                out[pos] = blob[pos:e].decode("utf-8", "replace")
            pos = e + 1
        return out


def buildinfo(m):
    """`__go_buildinfo`: (sürüm, modinfo metni). Kaynak: debug/buildinfo/buildinfo.go (satır içi biçim, 1.18+)."""
    sec = next(iter(m.secs_named("__go_buildinfo")), None)
    if sec is None:
        return None
    b = m.sec_bytes(sec)
    if not b.startswith(b"\xff Go buildinf:"):
        return None
    flags = b[15]
    if not flags & 2:
        return {"surum": None, "not": "gösterici biçimi (1.18 öncesi)"}
    n, pos = _varint(b, 32)
    surum = b[pos:pos + n].decode()
    pos += n
    n, pos = _varint(b, pos)
    mod = b[pos:pos + n]
    if len(mod) >= 33 and mod[-17:-16] == b"\n":
        mod = mod[16:-16]
    else:
        mod = b""
    mod = mod.decode("utf-8", "replace")
    bilgi = {"surum": surum, "path": None, "mod": None, "dep": 0, "build": {}}
    for satir in mod.splitlines():
        p = satir.split("\t")
        if p[0] == "path" and len(p) > 1:
            bilgi["path"] = p[1]
        elif p[0] == "mod" and len(p) > 1:
            bilgi["mod"] = p[1]
            bilgi["mod_surum"] = p[2] if len(p) > 2 else None
        elif p[0] == "dep":
            bilgi["dep"] += 1
        elif p[0] == "build" and len(p) > 1 and "=" in p[1]:
            k, v = p[1].split("=", 1)
            bilgi["build"][k] = v
    return bilgi
