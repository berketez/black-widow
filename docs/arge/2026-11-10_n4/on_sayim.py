#!/usr/bin/env python3
"""N4 (fiil) ön kaydı için GT'siz ön sayım.

Soru: geliştirme setinde isim bekleyen (Ghidra adı ``FUN_<adres>``) fonksiyonların kaçı doğrudan
kütüphane çağırıyor, kaçı yalnız iç fonksiyon çağırıyor, kaçı yaprak?

Girdi yalnız Karadul'un ``static/`` çıktılarıdır:

- ``ghidra_functions.json``: adres, ad, thunk/dış, ad kaynağı;
- ``ghidra_xrefs.json``: çağrılanlar, çağıranlar, başvurulan dizgiler;
- ``ghidra_combined_results.json``: işlemci ve dosya biçimi;
- ``ghidra_output/decompiled/*.c``: başlıktaki ``// Address:`` satırı ve dosya sonundaki
  gömülü disassembly (kuyruk çağrısı, dolaylı çağrı, komut sayısı için).

GT, ``raw/``, ``macho_score.json``, ``naming_map.json`` ve ikilinin kendisi okunmaz.
Çıktıda fonksiyon adı ve adres yoktur; yalnız sayılar ve kütüphane (import) adları vardır.
Betik ad üretmez, hiçbir Karadul modülünü içe aktarmaz.

Kullanım:
    python3 -I -B on_sayim.py --mac-kosu <koşu> --debian-kosu <koşu> --cikti on_sayim.json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import platform
import re
import sys
from collections import Counter, deque
from pathlib import Path

SURUM = 1
# Birim (platform/program) başına beklenen ELF sayısı: Mac 2, Debian 117. Değerler
# scripts/measurement/ks1_olc.py'deki BEKLENEN_ELF ile aynıdır (KS-1 ön kaydı §7). Bu betik bağımsız
# çalışsın diye oradan içe aktarılmadı; biri değişirse öbürü de değişmelidir.
BEKLENEN_ELF = {
    "mac/tmux": 1, "mac/htop": 1,
    "debian/tmux": 1, "debian/htop": 1, "debian/tree": 1, "debian/zstd": 2,
    "debian/redis-tools": 4, "debian/sqlite3": 1, "debian/openssl": 1, "debian/coreutils": 106,
}

# ---------------------------------------------------------------------------------------------
# Tanımlar (ön sayıma özgü; ürün sözlüğü değildir)

BEKLEYEN_RE = re.compile(r"^FUN_[0-9A-Fa-f]+$")
JENERIK_RE = re.compile(r"^(?:(?:thunk_)?FUN|LAB|SUB|sub)_[0-9A-Fa-f]+$")
# Ghidra'nın simge tablosu dışından koyduğu adlar (KS-1 ön kaydı §3.4 ile aynı liste)
EXPORT_DISI = frozenset({
    "entry", "_start", "_init", "_fini", "_DT_INIT", "_DT_FINI", "__libc_csu_init",
    "__libc_csu_fini", "_mh_execute_header", "__mh_execute_header",
})
EXPORT_DISI_RE = re.compile(r"^_(?:INIT|FINI)_\d+$")
# C++ ikili işareti (KS-1 ön kaydı §7): bu adlardan biri içe aktarılıyorsa ikili C++ sayılır
CPP_ISARET = ("_Z", "__gxx_personality", "__cxa_begin_catch", "__cxa_end_catch", "__cxa_throw",
              "__cxa_rethrow")

# Kütüphane adı aileleri. Adlar normalize edilmiş biçimdedir (``import_adi``).
DERLEYICI = frozenset({"stack_chk_fail", "chkstk_darwin"})          # derleyicinin eklediği çağrılar
CRT = frozenset({"cxa_finalize", "gmon_start__", "libc_start_main",
                 "ITM_deregisterTMCloneTable", "ITM_registerTMCloneTable"})
DONMEZ = frozenset({"exit", "Exit", "abort", "err", "errx", "verr", "verrx", "assert_fail",
                    "assert_rtn", "assert_perror_fail", "pthread_exit", "longjmp", "siglongjmp",
                    "quick_exit", "cxa_throw", "cxa_rethrow", "chk_fail", "fortify_fail"})
ILETI = frozenset({"printf", "fprintf", "vfprintf", "vprintf", "dprintf", "vdprintf", "puts",
                   "fputs", "perror", "warn", "warnx", "vwarn", "vwarnx", "syslog", "vsyslog",
                   "strerror", "strerror_r"})
ILETI_YALNIZ_ELF = frozenset({"error", "error_at_line"})            # glibc error(3)
BELLEK_DIZGI = frozenset({
    "malloc", "calloc", "realloc", "reallocarray", "free", "memcpy", "memmove", "mempcpy", "memset",
    "bzero", "memcmp", "memchr", "strlen", "strnlen", "strcmp", "strncmp", "strcasecmp",
    "strncasecmp", "strchr", "strrchr", "strstr", "strcpy", "strncpy", "stpcpy", "strcat",
    "strncat", "strlcpy", "strlcat", "strdup", "strndup", "memset_pattern16",
})
# errno erişimi ham adla tanınır: Darwin ``___error`` ile glibc ``error`` aynı ada normalize olur
ERRNO_HAM = {"mach-o": frozenset({"___error"}), "elf": frozenset({"__errno_location"})}

# Fiil sözlüğü v0 (ön kayıt taslağı §3). Her belirteç tek sınıftadır. ``handle`` geneldir.
FIIL_SOZLUGU = {
    "get": ("get", "fetch", "peek", "query"),
    "set": ("set", "put", "assign", "update", "store", "modify", "change"),
    "is": ("is", "has", "can", "should", "check", "test", "validate", "verify", "exists", "contains"),
    "create": ("create", "new", "alloc", "allocate", "make", "build", "construct", "dup", "clone"),
    "destroy": ("destroy", "free", "delete", "release", "dealloc", "dispose", "unref"),
    "init": ("init", "initialize", "setup", "prepare", "configure"),
    "fini": ("fini", "finish", "cleanup", "teardown", "deinit", "uninit", "shutdown", "terminate"),
    "reset": ("reset", "clear", "zero", "empty", "wipe", "flush"),
    "add": ("add", "insert", "push", "append", "prepend", "enqueue", "attach", "register", "link"),
    "remove": ("remove", "erase", "pop", "dequeue", "detach", "unregister", "unlink", "drop",
               "discard"),
    "find": ("find", "search", "lookup", "locate", "match"),
    "compare": ("compare", "cmp", "equal", "equals", "diff"),
    "copy": ("copy", "cpy", "move", "swap"),
    "open": ("open", "connect", "accept", "listen", "bind"),
    "close": ("close", "disconnect"),
    "read": ("read", "load", "recv", "receive", "input"),
    "write": ("write", "save", "send", "emit", "output", "dump"),
    "print": ("print", "show", "display", "draw", "render", "paint", "format", "log", "report",
              "warn"),
    "parse": ("parse", "decode", "tokenize", "scan", "unpack", "decompress", "unescape"),
    "encode": ("encode", "serialize", "pack", "compress", "escape"),
    "lock": ("lock", "acquire"),
    "unlock": ("unlock",),
    "start": ("start", "begin", "spawn", "launch", "fork", "enable", "resume"),
    "stop": ("stop", "end", "kill", "cancel", "abort", "disable", "suspend", "pause", "exit", "quit"),
    "run": ("run", "exec", "execute", "apply", "perform"),
    "compute": ("compute", "calc", "calculate", "count", "sum", "hash", "measure"),
    "sort": ("sort",),
    "wait": ("wait", "sleep", "poll"),
    "resize": ("resize", "grow", "shrink", "expand", "extend", "reserve", "truncate"),
    "handle": ("handle", "process", "dispatch", "do", "on", "callback", "cb", "handler", "helper"),
}
GENEL_SINIF = "handle"
KARSITLAR = (("get", "set"), ("create", "destroy"), ("init", "fini"), ("init", "run"),
             ("add", "remove"), ("open", "close"), ("read", "write"), ("parse", "encode"),
             ("lock", "unlock"), ("start", "stop"))
BELIRTEC_SINIFI = {t: s for s, ts in FIIL_SOZLUGU.items() for t in ts}
assert len(BELIRTEC_SINIFI) == sum(len(ts) for ts in FIIL_SOZLUGU.values()), "belirteç iki sınıfta"

KOMUT_DILIMLERI = ((8, "<=8"), (32, "9-32"), (128, "33-128"), (None, ">=129"))
DF_DILIMLERI = ((1, "1"), (5, "2-5"), (20, "6-20"), (None, ">=21"))

_DISASM_BASLIK = "// --- DISASSEMBLY"
_ADRES_BASLIK = re.compile(r"^// Address:\s+([0-9A-Fa-f]+)\s*$", re.M)
_KOMUT_SATIRI = re.compile(r"^// ([0-9A-Fa-f]+)  (\S+)(?:\s+(.*?))?\s*$")
_HEDEF = re.compile(r"0x([0-9A-Fa-f]+)\s*$")
_ONALTILIK = re.compile(r"^(?:0x)?([0-9a-fA-F]+)$")
_BELLEK = re.compile(r"\[\s*([a-z0-9]+)")
_KOSULLU = re.compile(r"^(?:b\.[a-z]{2}|cbn?z|tbn?z)$")
_YAZMA = ("str", "stur", "stp", "stnp", "stlr", "stxr", "stlxr", "st1", "st2", "st3", "st4")
# FORTIFY (``__memcpy_chk``) ve ISO C sürüm (``__isoc99_sscanf``) biçimli ham kütüphane adı
HAM_EK_RE = re.compile(r"_chk(?:\$|$)|^_*isoc(?:99|23)_")
_DEVE = re.compile(r"[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[A-Z]+|\d+")


def onaltilik(metin: object) -> int | None:
    m = _ONALTILIK.match(str(metin).strip())
    return int(m.group(1), 16) if m else None


def import_adi(ham: str) -> str:
    """Kütüphane adını aile karşılaştırması için sadeleştirir.

    Baştaki alt çizgiler, ``$…`` eki (``fopen$DARWIN_EXTSN``), FORTIFY ``_chk`` eki ve
    ``isoc99_`` / ``isoc23_`` öneki atılır.
    """
    ad = ham.split("$", 1)[0].lstrip("_")
    ad = re.sub(r"^isoc(?:99|23)_", "", ad)
    if ad.endswith("_chk") and len(ad) > 4:
        ad = ad[:-4]
    return ad


def dilim(deger: int, dilimler) -> str:
    for ust, ad in dilimler:
        if ust is None or deger <= ust:
            return ad
    raise AssertionError


def belirtecler(ad: str) -> list[str]:
    """Tanımlayıcıyı alt çizgi ve küçük/büyük harf geçişinden böler; küçük harfe çevirir."""
    cikti: list[str] = []
    for parca in re.split(r"[^A-Za-z0-9]+", ad):
        cikti.extend(m.group(0).lower() for m in _DEVE.finditer(parca))
    return cikti


def fiil_durumu(ad: str) -> tuple[str, str | None]:
    """Addaki sözlük belirteçlerinin sınıfları: (durum, sınıf). Ad dışarı verilmez."""
    siniflar = {BELIRTEC_SINIFI[t] for t in belirtecler(ad) if t in BELIRTEC_SINIFI}
    ozel = siniflar - {GENEL_SINIF}
    if len(ozel) == 1:
        return "tek_sinif", next(iter(ozel))
    if len(ozel) > 1:
        return "cok_sinif", None
    return ("yalniz_genel" if siniflar else "fiilsiz"), None


# ---------------------------------------------------------------------------------------------
# Bir static/ dizininin okunması


def komutlari_oku(kod_dizini: Path) -> dict[int, list[tuple[int, str, str]]]:
    kod: dict[int, list[tuple[int, str, str]]] = {}
    if not kod_dizini.is_dir():
        return kod
    for yol in sorted(kod_dizini.glob("*.c")):
        metin = yol.read_text(encoding="utf-8", errors="replace")
        m = _ADRES_BASLIK.search(metin[:2000])
        i = metin.find(_DISASM_BASLIK)
        if not m or i < 0:
            continue
        komutlar = []
        for satir in metin[i:].splitlines()[1:]:
            k = _KOMUT_SATIRI.match(satir)
            if k:
                komutlar.append((int(k.group(1), 16), k.group(2).lower(), k.group(3) or ""))
        if komutlar:
            kod.setdefault(int(m.group(1), 16), komutlar)
    return kod


def govde_ozeti(komutlar: list[tuple[int, str, str]]) -> dict:
    govde = {pc for pc, _, _ in komutlar}
    oz = {"n": len(komutlar), "bl": set(), "kuyruk": set(), "dolayli_cagri": False,
          "dolayli_dal": False, "kosullu_dis": False, "ret": 0, "yazar": False, "cset_w0": False,
          "cagri_yeri": Counter()}
    for _, mn, isl in komutlar:
        hedef = None
        m = _HEDEF.search(isl)
        if m:
            hedef = int(m.group(1), 16)
        if mn == "bl":
            if hedef is not None:
                oz["bl"].add(hedef)
                oz["cagri_yeri"][hedef] += 1
        elif mn.startswith("blr"):
            oz["dolayli_cagri"] = True
        elif mn == "b":
            if hedef is not None and hedef not in govde:
                oz["kuyruk"].add(hedef)
                oz["cagri_yeri"][hedef] += 1
        elif mn.startswith("br") and mn != "brk":
            oz["dolayli_dal"] = True
        elif _KOSULLU.match(mn):
            if hedef is not None and hedef not in govde:
                oz["kosullu_dis"] = True
        elif mn.startswith("ret"):
            oz["ret"] += 1
        elif mn.startswith(_YAZMA):
            b = _BELLEK.search(isl)
            if b and b.group(1) not in ("sp", "x29"):
                oz["yazar"] = True
        elif mn in ("cset", "csetm"):
            ilk = isl.split(",", 1)[0].strip()
            if ilk in ("w0", "x0"):
                oz["cset_w0"] = True
    return oz


def elf_say(static_dir: Path) -> dict:
    """Tek bir static/ dizini için sayımlar ve birim toplamına girecek ara veriler."""
    fham = (static_dir / "ghidra_functions.json").read_bytes()
    xham = (static_dir / "ghidra_xrefs.json").read_bytes()
    fdoc, xdoc = json.loads(fham), json.loads(xham)
    bicim = ""
    birlesik = static_dir / "ghidra_combined_results.json"
    if birlesik.is_file():
        bilgi = json.loads(birlesik.read_text(encoding="utf-8")).get("program_info") or {}
        bicim = str(bilgi.get("executable_format") or "").lower()
        islemci = str(bilgi.get("processor") or "")
    else:
        islemci = ""
    aile = "mach-o" if "mach-o" in bicim else "elf"

    # fonksiyonlar
    f: dict[int, dict] = {}
    for kayit in fdoc.get("functions", []):
        a = onaltilik(kayit.get("address", ""))
        if a is None or a in f:
            continue
        ad = str(kayit.get("name") or "")
        dis = bool(kayit.get("is_external")) or bool(kayit.get("is_thunk"))
        if dis:
            tur = "ic_thunk" if JENERIK_RE.match(ad) else "lib"
        else:
            tur = "ic"
        f[a] = {"ad": ad, "tur": tur, "kaynak": str(kayit.get("source") or ""),
                "boyut": int(kayit.get("size") or 0)}
    ham_importlar = {v["ad"] for v in f.values() if v["tur"] == "lib"}
    cpp = any(ad.startswith(CPP_ISARET) for ad in ham_importlar)

    # xrefs
    x_cagrilan: dict[int, set[int]] = {}
    x_cagiran: dict[int, set[int]] = {}
    dizgi_sayisi: dict[int, int] = {}
    for anahtar, x in sorted(xdoc.get("function_xrefs", {}).items()):
        a = onaltilik(x.get("address") or anahtar)
        if a is None:
            continue
        x_cagrilan[a] = {h for h in (onaltilik(c.get("address", ""))
                                     for c in x.get("functions_called", [])) if h is not None} - {a}
        x_cagiran[a] = {h for h in (onaltilik(c.get("address", ""))
                                    for c in x.get("called_by", [])) if h is not None} - {a}
        dizgi_sayisi[a] = len(x.get("strings_used", []))

    kod = komutlari_oku(static_dir / "ghidra_output" / "decompiled")
    ozet = {a: govde_ozeti(k) for a, k in kod.items()}

    def ham_hedefler(a: int) -> tuple[set[int], set[int]]:
        """(xrefs çağrılanları, yalnız disassembly'de görünen fonksiyon başı hedefleri)."""
        xs = set(x_cagrilan.get(a, set()))
        o = ozet.get(a)
        ek: set[int] = set()
        if o:
            ek = {h for h in (o["bl"] | o["kuyruk"]) if h in f and h != a} - xs
        return xs, ek

    def coz(h: int, derinlik: int = 0) -> set[int]:
        """Jenerik adlı thunk'ı hedefine çözer (en çok 4 adım)."""
        v = f.get(h)
        if v is None or v["tur"] != "ic_thunk" or derinlik >= 4:
            return {h}
        xs, ek = ham_hedefler(h)
        alt = (xs | ek) - {h}
        if not alt:
            return {h}
        cikti: set[int] = set()
        for t in sorted(alt):
            cikti |= coz(t, derinlik + 1)
        return cikti

    # iç (thunk olmayan) fonksiyon başına çağrı özeti
    bilgi_f: dict[int, dict] = {}
    for a in sorted(f):
        if f[a]["tur"] != "ic":
            continue
        xs, ek = ham_hedefler(a)
        o = ozet.get(a)
        kuyruk_ek = {h for h in ek if o and h in o["kuyruk"]}
        lib_ham: set[str] = set()
        ic: set[int] = set()
        bilinmeyen = 0
        for h in sorted(xs | ek):
            for t in sorted(coz(h)):
                v = f.get(t)
                if v is None:
                    bilinmeyen += 1
                elif v["tur"] == "lib":
                    lib_ham.add(v["ad"])
                elif v["tur"] == "ic":
                    if t != a:
                        ic.add(t)
                else:
                    bilinmeyen += 1      # çözülemeyen jenerik thunk
        x_lib_ham = {f[t]["ad"] for h in xs for t in coz(h) if t in f and f[t]["tur"] == "lib"}
        x_ic = {t for h in xs for t in coz(h) if t in f and f[t]["tur"] == "ic" and t != a}
        errno = bool(lib_ham & ERRNO_HAM[aile])
        lib = {import_adi(n) for n in lib_ham}
        x_lib = {import_adi(n) for n in x_lib_ham}
        ileti = ILETI | (ILETI_YALNIZ_ELF if aile == "elf" else frozenset())
        hata_ailesi = DONMEZ | ileti
        # Darwin'de ``___error`` → "error": errno erişimi sayılır, ileti değil
        errno_adlari = {import_adi(n) for n in ERRNO_HAM[aile]}
        anlamli = lib - DERLEYICI - CRT
        x_anlamli = x_lib - DERLEYICI - CRT
        bilgi_f[a] = {
            "lib": anlamli, "x_lib": x_anlamli, "ic": ic, "x_ic": x_ic,
            "crt": bool(lib & CRT), "errno": errno, "bilinmeyen": bilinmeyen,
            "kuyruk_ek": len(kuyruk_ek), "bl_ek": len(ek - kuyruk_ek),
            "kuyruk_var": bool(o and any(h in f and h != a for h in o["kuyruk"])),
            "jenerik_thunk": any(h in f and f[h]["tur"] == "ic_thunk" for h in xs),
            "ek_adli": any(HAM_EK_RE.search(n) for n in lib_ham),
            # aynı kütüphane adı iki ayrı adreste (ELF'te PLT çifti): xrefs'te iki kayıt olur
            "ayni_ad_iki_adres": len({h for h in xs if h in f and f[h]["tur"] == "lib"})
            > len({f[h]["ad"] for h in xs if h in f and f[h]["tur"] == "lib"}),
            # bir kütüphane hedefine birden çok çağrı yeri (xrefs bunu tek kayıt olarak verir)
            "cok_cagri_yeri": bool(o) and any(
                n >= 2 and any(t in f and f[t]["tur"] == "lib" for t in coz(h))
                for h, n in o["cagri_yeri"].items() if h in f),
            "hata": anlamli & (hata_ailesi | errno_adlari),
            "donmez": bool(anlamli & DONMEZ),
            "bellek": anlamli & BELLEK_DIZGI,
            "ozet": o,
        }
    # çağıranlar: çözülmüş iç kenarların tersi (A → thunk → B, A → B sayılır) ∪ xrefs called_by
    cagiran: dict[int, set[int]] = {a: set() for a in bilgi_f}
    for a, b in bilgi_f.items():
        for t in b["ic"]:
            cagiran.setdefault(t, set()).add(a)
    for a in bilgi_f:
        cagiran[a] |= {c for c in x_cagiran.get(a, set()) if c in bilgi_f and c != a}

    # iç çağrı grafında kütüphane çağıranına uzaklık (0 = kendisi çağırıyor)
    uzaklik: dict[int, int] = {a: 0 for a, b in bilgi_f.items() if b["lib"]}
    kuyruk = deque(sorted(uzaklik))
    while kuyruk:
        t = kuyruk.popleft()
        for c in sorted(cagiran.get(t, ())):
            if c not in uzaklik:
                uzaklik[c] = uzaklik[t] + 1
                kuyruk.append(c)

    nufus = [a for a in sorted(bilgi_f) if BEKLEYEN_RE.match(f[a]["ad"])]
    df = Counter(n for a in nufus for n in bilgi_f[a]["lib"])
    kume_sayisi = Counter(frozenset(bilgi_f[a]["lib"]) for a in nufus if bilgi_f[a]["lib"])

    s: Counter = Counter()
    s["elf"] = 1
    s["cpp_elf"] = int(cpp)
    s["fonksiyon_kaydi"] = len(f)
    s["ic_fonksiyon"] = len(bilgi_f)
    s["kutuphane_thunk_kaydi"] = sum(1 for v in f.values() if v["tur"] == "lib")
    s["jenerik_thunk"] = sum(1 for v in f.values() if v["tur"] == "ic_thunk")
    s["isim_bekleyen"] = len(nufus)
    s["disasm_olan_ic"] = sum(1 for b in bilgi_f.values() if b["ozet"])
    imza: set[str] = set()
    for a in nufus:
        b = bilgi_f[a]
        o = b["ozet"]
        n_komut = o["n"] if o else max(1, f[a]["boyut"] // 4)
        if not o:
            s["bekleyen_disasm_yok"] += 1
        else:
            dizi = "\n".join(mn for _, mn, _ in kod[a])
            imza.add(hashlib.sha1(dizi.encode()).hexdigest())
        # ana sınıf (xrefs ∪ disassembly)
        if b["lib"]:
            sinif = "K"
        elif b["ic"]:
            sinif = "I"
        else:
            sinif = "Y"
        s[f"sinif_{sinif}"] += 1
        # yalnız xrefs ile sınıf (evidence.py'nin bugün gördüğü)
        xs_sinif = "K" if b["x_lib"] else ("I" if b["x_ic"] else "Y")
        s[f"xrefs_sinif_{xs_sinif}"] += 1
        if xs_sinif != sinif:
            s[f"sinif_degisen_{xs_sinif}>{sinif}"] += 1
        s["kuyruk_cagrili_fonksiyon"] += int(b["kuyruk_var"])
        s["kuyruk_cagrisi_xrefs_disi_fonksiyon"] += int(bool(b["kuyruk_ek"]))
        s["bl_xrefs_disi_fonksiyon"] += int(bool(b["bl_ek"]))
        s["cozulemeyen_hedefli_fonksiyon"] += int(bool(b["bilinmeyen"]))
        s["jenerik_thunk_cagiran"] += int(b["jenerik_thunk"])
        s["chk_ya_da_isoc_import_cagiran"] += int(b["ek_adli"])
        s["ayni_import_adi_iki_adres"] += int(b["ayni_ad_iki_adres"])
        s["cok_cagri_yerli_kutuphane_hedefi"] += int(b["cok_cagri_yeri"])
        if b["crt"]:
            s["crt_import_cagiran"] += 1
        if o and o["dolayli_cagri"]:
            s[f"dolayli_cagri_{sinif}"] += 1
        if dizgi_sayisi.get(a, 0) > 0:
            s[f"dizgi_var_{sinif}"] += 1
        nc = len(cagiran.get(a, ()))
        s[f"cagiran_{sinif}_{'0' if nc == 0 else ('1' if nc == 1 else '2+')}"] += 1
        s[f"komut_{sinif}_{dilim(n_komut, KOMUT_DILIMLERI)}"] += 1
        toplam_hedef = len(b["lib"]) + len(b["ic"])
        if toplam_hedef == 1:
            tur = "lib" if b["lib"] else "ic"
            s[f"tek_hedef_{tur}_{dilim(n_komut, KOMUT_DILIMLERI)}"] += 1
        if sinif == "K":
            nl = len(b["lib"])
            s[f"K_import_{'1' if nl == 1 else ('2' if nl == 2 else ('3-5' if nl <= 5 else '6+'))}"] += 1
            ni = len(b["ic"])
            s[f"K_ic_cagri_{'0' if ni == 0 else ('1-3' if ni <= 3 else '4+')}"] += 1
            disi = b["lib"] - b["hata"] - b["bellek"]
            if disi:
                s["K_ayirt_edici"] += 1
                nd = len(disi)
                s[f"K_ayirt_edici_import_{'1' if nd == 1 else ('2' if nd == 2 else '3+')}"] += 1
                s[f"K_ayirt_edici_ic_cagri_{'0' if ni == 0 else ('1-3' if ni <= 3 else '4+')}"] += 1
                if b["hata"]:
                    s["K_ayirt_edici_ve_hata_ileti"] += 1
            elif b["hata"] and b["bellek"]:
                s["K_yalniz_karisim"] += 1
            elif b["hata"]:
                s["K_yalniz_hata_ileti"] += 1
            else:
                s["K_yalniz_bellek_dizgi"] += 1
            if b["errno"]:
                s["K_errno"] += 1
            if b["donmez"]:
                s["K_donmez"] += 1
            s[f"K_en_secici_df_{dilim(min(df[n] for n in b['lib']), DF_DILIMLERI)}"] += 1
            cok = kume_sayisi[frozenset(b["lib"])]
            s[f"K_kume_{'tek' if nl == 1 else 'cok'}_import_{'tekil' if cok == 1 else 'paylasilan'}"] += 1
        elif sinif == "I":
            u = uzaklik.get(a)
            s[f"I_zincir_{'yok' if u is None else ('1' if u == 1 else ('2' if u == 2 else '3+'))}"] += 1
        else:
            if o:
                if o["dolayli_dal"]:
                    s["Y_dolayli_dal"] += 1
                s[f"Y_{'yazar' if o['yazar'] else 'yazmaz'}"] += 1
                if o["cset_w0"]:
                    s["Y_cset_w0"] += 1
                if o["kosullu_dis"]:
                    s["Y_kosullu_dis_dal"] += 1
                if o["ret"] == 0:
                    s["Y_ret_yok"] += 1
    s["bekleyen_tekil_komut_dizisi_elf_ici"] = len(imza)

    # ikilide adı görünen iç fonksiyonlar (export): yalnız sayı; ad dışarı verilmez
    adli: Counter = Counter()
    adli_fiil: dict[str, tuple[str, str | None, str]] = {}
    for a in sorted(bilgi_f):
        ad = f[a]["ad"]
        if JENERIK_RE.match(ad):
            continue
        if ad in EXPORT_DISI or EXPORT_DISI_RE.match(ad) or f[a]["kaynak"] != "IMPORTED":
            adli["adli_diger"] += 1
            continue
        b = bilgi_f[a]
        sinif = "K" if b["lib"] else ("I" if b["ic"] else "Y")
        durum, fs = fiil_durumu(ad)
        adli["export"] += 1
        adli[f"export_sinif_{sinif}"] += 1
        adli[f"export_fiil_{durum}"] += 1
        if durum == "tek_sinif":
            adli[f"export_tek_sinif_{sinif}"] += 1
        adli_fiil[ad] = (durum, fs, sinif)

    return {
        "sayim": s, "adli": adli, "df": df, "imza": imza,
        "aile": aile, "islemci": islemci, "cpp": cpp,
        "ham_import": ham_importlar, "adli_fiil": adli_fiil,
        "girdi_ozeti": hashlib.sha256(hashlib.sha256(fham).digest()
                                      + hashlib.sha256(xham).digest()).hexdigest(),
    }


# ---------------------------------------------------------------------------------------------
# Koşu dizinleri ve birimler


def static_dizinleri(mac: Path, debian: Path) -> list[tuple[str, str, str, Path]]:
    """(platform, program, elf, static_dir) listesi; her ELF için tam bir static/ olmalı."""
    cikti: list[tuple[str, str, str, Path]] = []
    for program_dizini in sorted(p for p in mac.iterdir() if p.is_dir()):
        bulunan = sorted(program_dizini.glob("ws/workspaces/*/*/static"))
        if len(bulunan) != 1:
            raise SystemExit(f"{program_dizini}: {len(bulunan)} static/ (1 bekleniyordu)")
        cikti.append(("mac", program_dizini.name, program_dizini.name, bulunan[0]))
    for program_dizini in sorted(p for p in debian.iterdir() if p.is_dir()):
        for elf_dizini in sorted(p for p in program_dizini.iterdir() if p.is_dir()):
            bulunan = sorted(elf_dizini.glob("ws/workspaces/*/*/static"))
            if len(bulunan) != 1:
                raise SystemExit(f"{elf_dizini}: {len(bulunan)} static/ (1 bekleniyordu)")
            if not (elf_dizini / "BITTI").is_file():
                raise SystemExit(f"{elf_dizini}: BITTI yok (koşu bitmemiş)")
            cikti.append(("debian", program_dizini.name, elf_dizini.name, bulunan[0]))
    return cikti


def ev_kisalt(yol: Path) -> str:
    """Ev dizinini ``~`` ile yazar (çıktı depoya girer; kullanıcı yolu taşımasın)."""
    metin = str(yol.expanduser())
    ev = str(Path.home())
    return "~" + metin[len(ev):] if metin.startswith(ev) else metin


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("--mac-kosu", type=Path, required=True)
    ap.add_argument("--debian-kosu", type=Path, required=True)
    ap.add_argument("--cikti", type=Path, required=True)
    ap.add_argument("--en-sik", type=int, default=25, help="birim başına listelenecek import sayısı")
    args = ap.parse_args()

    dizinler = static_dizinleri(args.mac_kosu.expanduser(), args.debian_kosu.expanduser())
    bulunan = Counter(f"{p}/{program}" for p, program, _, _ in dizinler)
    for birim in sorted(set(BEKLENEN_ELF) | set(bulunan)):
        if bulunan.get(birim, 0) != BEKLENEN_ELF.get(birim, 0):
            raise SystemExit(f"{birim}: {bulunan.get(birim, 0)} ELF bulundu, "
                             f"{BEKLENEN_ELF.get(birim, 0)} bekleniyordu (eksik koşu ölçülmez)")

    birimler: dict[str, dict] = {}
    elfler: list[dict] = []
    for platform_adi, program, elf, sd in dizinler:
        r = elf_say(sd)
        if r["islemci"].upper() != "AARCH64":
            raise SystemExit(f"{sd}: işlemci {r['islemci']!r} (yalnız AArch64)")
        anahtar = f"{platform_adi}/{program}"
        b = birimler.setdefault(anahtar, {
            "sayim": Counter(), "adli": Counter(), "df": Counter(),
            "imza": set(), "ham_import": set(), "adli_fiil": {}, "ozetler": [], "bicim": r["aile"]})
        b["sayim"].update(r["sayim"])
        b["adli"].update(r["adli"])
        b["df"].update(r["df"])
        b["imza"] |= r["imza"]
        b["ham_import"] |= r["ham_import"]
        b["ozetler"].append(r["girdi_ozeti"])
        for ad, deger in r["adli_fiil"].items():
            b["adli_fiil"].setdefault(ad, deger)
        elfler.append({"birim": anahtar, "elf": elf, "cpp": r["cpp"], "bicim": r["aile"],
                       **{k: r["sayim"][k] for k in
                          ("ic_fonksiyon", "isim_bekleyen", "sinif_K", "sinif_I", "sinif_Y")}})

    cikti_birim: dict[str, dict] = {}
    toplam: Counter = Counter()
    for anahtar in sorted(birimler):
        b = birimler[anahtar]
        s = b["sayim"]
        s["bekleyen_tekil_komut_dizisi_birim"] = len(b["imza"])
        # export adları birim içinde tekilleştirilir (aynı ad birden çok ELF'te bir kez sayılır)
        tekil: Counter = Counter()
        tekil_fiil: Counter = Counter()
        for _ad, (durum, fs, sinif) in sorted(b["adli_fiil"].items()):
            tekil["export_tekil_ad"] += 1
            tekil[f"export_tekil_fiil_{durum}"] += 1
            if durum == "tek_sinif":
                tekil[f"export_tekil_tek_sinif_{sinif}"] += 1
                tekil_fiil[fs] += 1
        ham = sorted(b["ham_import"])
        norm = {import_adi(n) for n in ham}
        cikti_birim[anahtar] = {
            "bicim": b["bicim"],
            "sayim": dict(sorted(s.items())),
            "adli": dict(sorted((b["adli"] + tekil).items())),
            "export_tekil_fiil_sinifi": dict(sorted(tekil_fiil.items())),
            "import": {
                "ham_ad": len(ham), "normalize_ad": len(norm),
                "chk_ya_da_isoc_ham": sum(1 for n in ham if HAM_EK_RE.search(n)),
                "dolar_ekli_ham": sum(1 for n in ham if "$" in n),
                "bekleyenlerin_cagirdigi_normalize_ad": len(b["df"]),
                "en_sik": [[n, c] for n, c in sorted(b["df"].items(), key=lambda kv: (-kv[1], kv[0]))
                           [:args.en_sik]],
            },
            "girdi_ozeti": hashlib.sha256("".join(sorted(b["ozetler"])).encode()).hexdigest(),
        }
        toplam.update(s)

    belge = {
        "kunye": {
            "betik": "docs/arge/2026-11-10_n4/on_sayim.py", "surum": SURUM,
            "betik_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "python": platform.python_version(),
            "mac_kosu": ev_kisalt(args.mac_kosu), "debian_kosu": ev_kisalt(args.debian_kosu),
            "elf_sayisi": dict(sorted(bulunan.items())),
            "nufus": "thunk ve dış olmayan, adı ^FUN_<onaltılık>$ olan Ghidra fonksiyonu (GT'siz vekil)",
            "siniflar": {
                "K": "en az bir kütüphane fonksiyonu çağırıyor (derleyici eki ve CRT hariç)",
                "I": "kütüphane çağırmıyor, en az bir iç fonksiyon çağırıyor",
                "Y": "hiçbir fonksiyonu doğrudan çağırmıyor (yaprak)",
                "kaynak": "ghidra_xrefs.json functions_called ∪ disassembly'deki bl ve fonksiyon "
                          "başına giden gövde dışı b; jenerik adlı thunk hedefine çözülür",
            },
            "aileler": {
                "derleyici": sorted(DERLEYICI), "crt": sorted(CRT), "donmez": sorted(DONMEZ),
                "ileti": sorted(ILETI), "ileti_yalniz_elf": sorted(ILETI_YALNIZ_ELF),
                "bellek_dizgi": sorted(BELLEK_DIZGI),
                "errno_ham": {k: sorted(v) for k, v in sorted(ERRNO_HAM.items())},
            },
            "komut_dilimleri": [ad for _, ad in KOMUT_DILIMLERI],
            "df_dilimleri": [ad for _, ad in DF_DILIMLERI],
            "fiil_sozlugu_v0": {k: list(v) for k, v in FIIL_SOZLUGU.items()},
            "genel_sinif": GENEL_SINIF,
            "karsitlar": [list(c) for c in KARSITLAR],
        },
        "birimler": cikti_birim,
        "toplam": dict(sorted(toplam.items())),
        "elfler": sorted(elfler, key=lambda e: (e["birim"], e["elf"])),
    }
    args.cikti.write_text(json.dumps(belge, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")

    print(f"{'birim':<22}{'ELF':>5}{'iç':>7}{'bekleyen':>9}{'K':>7}{'I':>7}{'Y':>7}")
    for anahtar, b in cikti_birim.items():
        s = b["sayim"]
        print(f"{anahtar:<22}{s['elf']:>5}{s['ic_fonksiyon']:>7}{s['isim_bekleyen']:>9}"
              f"{s.get('sinif_K', 0):>7}{s.get('sinif_I', 0):>7}{s.get('sinif_Y', 0):>7}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
