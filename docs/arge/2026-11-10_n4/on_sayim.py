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
Betik ad üretmez. Sayım kipi hiçbir Karadul modülünü içe aktarmaz.

Sürüm 2 (``on_olcum_gt_siz.md``) iki GT'siz ön ölçüm ekler; sürüm 1'in sayaçları değişmez:

- riskli deyim sayımı: fiil taslağının ``is`` / ``init`` / ``create`` / ``destroy`` kurallarının ve
  Onuncu Adam §3'teki kalıp 1-4'ün işlemsel tanımları (``N4_TANIMLAR``), gömülü disassembly
  üstünde fonksiyon içi ileri veri akışıyla (``deger_akisi``);
- M1 temsil denetimi: aynı ölçüler export, isim bekleyen ve KS-1 ``func_kalibi`` çapası
  nüfuslarında; fark oran farkı ve oran olarak, aralıklarıyla (``m1_temsil``).

``--capa-cikar`` kipi KS-1 çapalarını ``karadul/reconstruction/tarif/kesin.py`` ile çıkarır (bu
betiğin Karadul koduna dokunan tek yeri; dosyanın sha256'sı KS-1 ölçümündekiyle aynı olmalı) ve
depo dışına yalnız adres + addaki fiil sınıfını yazar; ad yazılmaz.

Kullanım:
    python3 -I -B on_sayim.py --mac-kosu <koşu> --debian-kosu <koşu> --capa-cikar capalar.json
    python3 -I -B on_sayim.py --mac-kosu <koşu> --debian-kosu <koşu> [--capalar capalar.json]
        [--ornekler ornekler.json] --cikti on_sayim.json
"""
from __future__ import annotations

import argparse
import hashlib
import heapq
import importlib.util
import json
import math
import platform
import re
import statistics
import sys
from collections import Counter, deque
from pathlib import Path

SURUM = 2
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


def kod_oku(kod_dizini: Path) -> tuple[dict[int, list[tuple[int, str, str]]], dict[int, dict]]:
    """(adres → komutlar, adres → decompile özeti). Aynı adresin ilk dosyası geçerlidir."""
    kod: dict[int, list[tuple[int, str, str]]] = {}
    meta: dict[int, dict] = {}
    if not kod_dizini.is_dir():
        return kod, meta
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
            a = int(m.group(1), 16)
            if a not in kod:
                kod[a] = komutlar
                meta[a] = c_ozeti(metin[:i])
    return kod, meta


def komutlari_oku(kod_dizini: Path) -> dict[int, list[tuple[int, str, str]]]:
    return kod_oku(kod_dizini)[0]


_IMZA_RE = re.compile(r"^(.*?)\b([A-Za-z_][\w.$:@]*)\s*\(")
GHIDRA_DONMEZ_UYARISI = "Subroutine does not return"


def c_ozeti(c_metni: str) -> dict:
    """Decompile metninden: imzadaki dönüş türü ve Ghidra'nın dönmeyen çağrı uyarısı.

    İmza, başlık yorumlarından sonraki ilk yorum dışı satırdır; dönüş türü işlev adından önceki
    metindir (``void``, ``undefined8``, ``char *`` …). Bulunamazsa ``None``.
    """
    donus = None
    yorumda = False
    for satir in c_metni.splitlines():
        s = satir.strip()
        if yorumda:
            if "*/" in s:
                yorumda = False
            continue
        if not s or s.startswith("//"):
            continue
        if s.startswith("/*"):
            yorumda = "*/" not in s
            continue
        m = _IMZA_RE.match(s)
        if m:
            donus = m.group(1).strip()
        break
    # uyarıdan sonraki ilk dolu satır çağrıdır; yığın koruyucu (stack_chk_fail) sayılmaz
    satirlar = c_metni.splitlines()
    ghidra_donmez = False
    for i, s in enumerate(satirlar):
        if GHIDRA_DONMEZ_UYARISI in s:
            sonraki = next((t for t in satirlar[i + 1:] if t.strip()), "")
            if "stack_chk_fail" not in sonraki:
                ghidra_donmez = True
                break
    return {"donus": donus, "ghidra_donmez": ghidra_donmez}


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


# ---------------------------------------------------------------------------------------------
# Sürüm 2: N4 riskli deyim sayımı ve M1 temsil denetimi (GT'siz)
#
# Bütün tanımlar gömülü disassembly üstündedir (AArch64). Decompile metninden yalnız iki bilgi
# alınır: imzadaki dönüş türü (``void`` mi) ve Ghidra'nın "Subroutine does not return" uyarısı
# (yalnız denetim sayacı). p-code kullanılmaz: dışa aktarımda SSA kimliği yok (taslak §2.1).

AYIRICI = frozenset({"malloc", "calloc", "realloc", "reallocarray", "strdup", "strndup",
                     "aligned_alloc", "valloc", "memalign"})
BUYUTUCU = frozenset({"realloc", "reallocarray"})
BIRAKICI = frozenset({"free"})
# Belleğe yazmayan, yalnız okuyan kütüphane çağrıları (kalıp 1'in alt kırılımı için; kapalı liste)
SALT_OKUR = frozenset({
    "strlen", "strnlen", "strcmp", "strncmp", "strcasecmp", "strncasecmp", "memcmp", "memchr",
    "strchr", "strrchr", "strstr", "strspn", "strcspn", "strpbrk", "wcslen", "wcscmp",
    "ctype_b_loc", "ctype_tolower_loc", "ctype_toupper_loc", "maskrune", "tolower", "toupper",
})
DONMEZ_DERLEYICI = frozenset({"stack_chk_fail"})   # dönmez, ama hata yolu (FK3) sayılmaz
CAGRI_DILIMLERI = ((0, "0"), (3, "1-3"), (10, "4-10"), (None, ">=11"))
DEGER_SINIRI = 8          # bir yazmacın olası değer kümesi en çok bu kadar öğe; aşarsa bilinmez
TUR_SINIRI = 64           # blok başına en çok yeniden değerlendirme
ORNEK_SAYISI = 10
# Onuncu Adam §7 eşikleri (onuncu_adam.md:156-157)
RISK_ESIGI = 0.25
HTOP_B4_ESIGI = 0.05
ORAN_BANDI = (0.5, 2.0)
CAGIRANSIZ_PUAN_ESIGI = 30.0
# KS-1'in kilitli program sınıfı (docs/arge/2026-10-21_g11_n1/ks1_sinif.json → boyut_tabakasi).
# Bağımsız çalışsın diye oradan okunmadı; test bu sözlüğü dosyayla karşılaştırır.
BOYUT_TABAKASI = {
    "debian/coreutils": "kucuk", "debian/htop": "orta", "debian/openssl": "orta",
    "debian/redis-tools": "buyuk", "debian/sqlite3": "kucuk", "debian/tmux": "orta",
    "debian/tree": "kucuk", "debian/zstd": "orta", "mac/htop": "orta", "mac/tmux": "buyuk",
}
# KS-1 ölçümündeki kesin.py (ks1_say.json → kesin_sha256); --capa-cikar yalnız bu sürümle çalışır
KS1_KESIN_SHA256 = "2a412e8a4467cff152a8ed271d0216a5fcb3038f1299ca6e8927e3319838cc48"
KS1_KESIN_YOLU = "karadul/reconstruction/tarif/kesin.py"

N4_TANIMLAR = {
    "deger_akisi": (
        "Fonksiyon içi ileri veri akışı, blok düzeyinde sabit nokta; birleştirme küme birleşimi "
        "(olası değerler). Değerler: p_i (girişteki x_i, i<8), k_c (sabit; w hedefte 32 bit "
        "işaretli), b (0/1 üreten: cset, csinc zr,zr, and #1, ubfx #,1, lsr #31/#63), r_pc "
        "(pc'deki çağrının dönüşü), f_i,o (p_i'nin o ofsetinden yüklenen alan), s (yığın "
        "adresi), ? (bilinmez). Çağrı x0-x18, x30 ve vektör yazmaçlarını öldürür; x0 = r_pc. "
        "[sp]/[x29] yuvaları izlenir. Küme 8 öğeyi aşarsa ?. Önceli olmayan bloklar, "
        "fonksiyonda dolaylı dallanma (br) varsa atlama tablosu hedefi sayılır ve ? girişle "
        "çözülür; yoksa dolgu/ölü kod sayılır ve akışa girmez"),
    "cfg": (
        "Blok sonu: dallanma, ret, br, brk/udf/hlt ve dönmeyen hedefe bl. Dönen çıkış: ret, br "
        "(bilinmez x0 ile), gövde dışına dönen hedefli b (kuyruk çağrısı; x0 = r_pc)"),
    "donmez": (
        "Kütüphane: donmez ailesi ve stack_chk_fail. İç: girişten dönen çıkışa ulaşamayan iç "
        "fonksiyon; sabit nokta (dönmeyen hedefe bl blok sonudur, gövde sonundan düşen blok "
        "dönmez sayılır)"),
    "ana_yol": "Dönen bir çıkışa ulaşabilen blok (FK3'ün tümleyeni)",
    "fk3_genis": (
        "Fonksiyonda dönen çıkışa ulaşamayan ve gerçek dönmeyen çağrıya (donmez ailesi ya da "
        "dönmeyen iç fonksiyon; stack_chk_fail değil) ulaşan en az bir blok var ve fonksiyonun "
        "dönen bir yolu var"),
    "fk3_dar": "fk3_genis, ama dönmeyen hedef doğrudan donmez ailesinden bir kütüphane çağrısı",
    "ayirici": "AYIRICI kütüphane adları ∪ FK1 ayırıcı sarmalayıcıları (dar ya da geniş)",
    "birakici": "BIRAKICI (free) ∪ FK1 free sarmalayıcıları",
    "fk1_free": (
        "Bütün (derleyici dışı) çağrı yerleri free'ye iniyor, dolaylı çağrı yok, her çağrıda "
        "x0 = {p_0}"),
    "fk1_ayirici_dar": (
        "Bütün çağrı yerleri tek bir AYIRICI adına iniyor, dolaylı çağrı yok, her çağrıda "
        "x0 = {p_0}, ayrılan nesneye saklama yok (taslağın FK1 metninde yok; eklenmezse boyutu "
        "parametreden alan kurucu sarmalayıcı sayılır), bütün çıkışların x0'ı bu çağrıların "
        "dönüşü"),
    "fk1_ayirici_genis": (
        "Çağrı hedefleri ⊆ AYIRICI ∪ donmez ∪ ileti ∪ errno ∪ dönmeyen iç fonksiyon, en az bir "
        "AYIRICI, dolaylı çağrı yok, her ayırıcı çağrısında x0 bir p_i içeriyor, ayrılan "
        "nesneye saklama yok, bütün çıkışların x0'ı ⊆ ayırıcı dönüşü ∪ {k_0} ve en az biri "
        "ayırıcı dönüşü (ayırıcı + hata bildirimi sarmalayıcısı; kurucu değil)"),
    "cagri_yeri": "bl, blr ve kuyruk çağrısı; derleyici eki ve CRT hedefleri hariç",
    "yazar": "Tabanı sp ya da x29 olmayan saklama komutu (sürüm 1'in Y_yazar işaretiyle aynı)",
    "donus_void": "Decompile imzasının dönüş türü tam olarak 'void'",
    "fire_destroy": (
        "taslak :306. FK1 free sarmalayıcısı değil; ana yolda bir bırakıcı çağrısının x0'ı "
        "tam olarak {p_i}"),
    "destroy_her_yolda": "fire_destroy ve girişten o bırakmalardan geçmeden dönen çıkışa yol yok",
    "fire_create": (
        "taslak :307. Sarmalayıcı değil; bütün dönen çıkışların x0'ı ⊆ ayırıcı dönüşü ∪ {k_0}, "
        "en az biri ayırıcı dönüşü içeriyor; tabanı ⊆ ayırıcı dönüşü olan en az bir saklama "
        "(dar: dar ayırıcı kümesi; geniş: geniş)"),
    "create_buyutme": "fire_create_genis ve döndürülen ayırıcılardan biri realloc/reallocarray",
    "fire_init": (
        "taslak :308. Geniş ayırıcıya çağrı yok; tabanı {p_i} olan, kaynağı ⊆ {k_*, p_*} "
        "saklamalarla p_i'nin en az iki ayrı ofsetine yazılıyor"),
    "fire_is": (
        "taslak :311. Dönüş türü void değil; 'yazar' değil; en az bir dönen çıkış ve hepsinin "
        "x0'ı ⊆ {k_0, k_1, b}"),
    "kalip1": (
        "Onuncu Adam §7(a): dönüş türü void değil; bütün dönen çıkışların x0'ı ⊆ {k_0, k_1, b}; "
        "en az bir çağrı yeri. kalip1_is: ayrıca fire_is (yani doğrudan saklama yok). Alt "
        "kırılım (kalip1_is içinde): kalip1_is_salt_okur = bütün çağrılar SALT_OKUR "
        "kütüphanesine; kalip1_is_yan = öbürleri (iç çağrı ya da başka kütüphane); "
        "kalip1_is_yan_kutuphane = SALT_OKUR dışı en az bir kütüphane çağrısı"),
    "kalip2": (
        "§7(b): bir bırakıcı çağrısının x0'ı {f_i,o}; p_i'nin en az iki ofsetine sabit/parametre "
        "yazılıyor; hiçbir bırakıcı çağrısının x0'ı p_i'yi içermiyor. kalip2_init: ayrıca fire_init"),
    "kalip3": (
        "§7(c): fire_destroy ve bırakıcı olmayan en az bir çağrı yeri daha. kalip3_arg: o "
        "çağrılardan birinde x0 = {p_i} (bırakılan parametrenin kendisi)"),
    "kalip4": (
        "§7(d): fire_destroy'u veren p_i için: girişten bırakmaya uğramadan dönen çıkış var ve "
        "onlardan biri negatif sabit dışında dönüyor; her bırakmadan sonra ulaşılan bütün dönen "
        "çıkışların x0'ı negatif sabit (return -1). Değerler yol duyarlıdır: bırakmasız yollar "
        "ve bırakma sonrası yollar ayrı akıtılır, ortak dönüş bloğunda karışmaz. kalip4_sifir: "
        "aynı, ama bırakma sonrası çıkışlar {k_0} ve bırakmasız yolda {k_0} dışı dönen çıkış var"),
    "fetki_ilk": "fire_create_genis ∪ fire_destroy (taslağın ilk sürümü, :295)",
    "fetki_ilk_riskli": "fire_destroy ∩ (kalip3 ∪ kalip4)",
    "fetki_tum": "fire_is ∪ fire_init ∪ fire_create_genis ∪ fire_destroy",
    "fetki_tum_riskli": "kalip1_is ∪ kalip2_init ∪ (fire_destroy ∩ (kalip3 ∪ kalip4))",
    "ad_tekil": (
        "B4 biçiminde ad = fiil + genel nesne; ELF içinde bir fiil tek fonksiyonda ateşliyorsa o "
        "ad tekildir. Sayaç: o fiil için tekil ad sayısı (ELF başına 0 ya da 1)"),
}

BILINMEZ = frozenset({("?",)})
SIFIR = frozenset({("k", 0)})
YIGIN = frozenset({("s",)})
MANTIKSAL = frozenset({("k", 0), ("k", 1), ("b",)})

_YAZMAC_X = re.compile(r"^([xw])(\d{1,2})$")
_YAZMAC_V = re.compile(r"^([qdshbv])(\d{1,2})(?:\.\w+)?$")
_BELLEK_ISL = re.compile(r"^\[\s*([a-z0-9]+)\s*(?:,\s*(.+?))?\s*\](!?)$")
_RMW = ("ldadd", "ldclr", "ldeor", "ldset", "ldsmax", "ldsmin", "ldumax", "ldumin", "swp", "cas")
_YAZMAYAN = frozenset({
    "cmp", "cmn", "tst", "ccmp", "ccmn", "fcmp", "fcmpe", "fccmp", "fccmpe", "prfm", "prfum",
    "nop", "dmb", "dsb", "isb", "hint", "msr", "svc", "clrex", "yield", "bti", "csdb", "sev",
    "sevl", "wfe", "wfi", "paciasp", "autiasp", "pacibsp", "autibsp", "xpaclri"})
_BAYT_SAKLAMA = ("strb", "sturb", "stlrb", "stllrb", "stlurb")
_YARIM_SAKLAMA = ("strh", "sturh", "stlrh", "stllrh", "stlurh")
_DURUMLU_SAKLAMA = ("stxr", "stlxr", "stxp", "stlxp")
_YIGIN_TABANI = ("sp", "x29")


def isleneler(metin: str) -> tuple[str, ...]:
    """Virgülle ayır; köşeli ayraç içindeki virgüller bölmez."""
    parcalar: list[str] = []
    derinlik = 0
    cur: list[str] = []
    for ch in metin:
        if ch == "[":
            derinlik += 1
        elif ch == "]":
            derinlik -= 1
        if ch == "," and derinlik == 0:
            parcalar.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    son = "".join(cur).strip()
    if son:
        parcalar.append(son)
    return tuple(parcalar)


def yazmac(metin: str) -> str | None:
    """Yazmaç adı → anahtar: ``x0``-``x30``, ``v0``-``v31``, ``zr``, ``sp``; değilse None."""
    t = metin.strip().lower()
    if t in ("xzr", "wzr"):
        return "zr"
    if t in ("sp", "wsp"):
        return "sp"
    if t == "fp":
        return "x29"
    if t == "lr":
        return "x30"
    m = _YAZMAC_X.match(t)
    if m and int(m.group(2)) <= 30:
        return f"x{int(m.group(2))}"
    m = _YAZMAC_V.match(t)
    if m and int(m.group(2)) <= 31:
        return f"v{int(m.group(2))}"
    return None


def sayi(metin: str) -> int | None:
    t = metin.strip()
    if t.startswith("#"):
        t = t[1:]
    try:
        return int(t, 0)
    except ValueError:
        return None


def sabit(deger: int, hedef: str) -> int:
    """Sabiti hedef yazmacın genişliğinde işaretli yorumlar (``w`` → 32 bit, öbürü 64 bit)."""
    if hedef.strip().lower().startswith("w"):
        deger &= 0xFFFFFFFF
        return deger - (1 << 32) if deger >= (1 << 31) else deger
    deger &= (1 << 64) - 1
    return deger - (1 << 64) if deger >= (1 << 63) else deger


def dal_turu(mn: str, ops: tuple[str, ...]) -> tuple[str, int | None]:
    """('cagri'|'atla'|'kosul'|'dcagri'|'don'|'ddal'|'tuzak'|'yok', hedef)."""
    if mn == "bl":
        return "cagri", sayi(ops[0]) if ops else None
    if mn == "b":
        return "atla", sayi(ops[0]) if ops else None
    if re.match(r"^b\.[a-z]{2}$", mn):
        return "kosul", sayi(ops[0]) if ops else None
    if mn in ("cbz", "cbnz"):
        return "kosul", sayi(ops[1]) if len(ops) > 1 else None
    if mn in ("tbz", "tbnz"):
        return "kosul", sayi(ops[2]) if len(ops) > 2 else None
    if mn.startswith("blr"):
        return "dcagri", None
    if mn.startswith("ret") or mn == "eret":
        return "don", None
    if mn.startswith("br") and mn != "brk":
        return "ddal", None
    if mn in ("brk", "udf", "hlt"):
        return "tuzak", None
    return "yok", None


def bellek(ops: tuple[str, ...]) -> tuple[int, str | None, int | None, bool] | None:
    """İlk bellek işleneni: (indeks, taban, erişim ofseti ya da None, geri yazma var mı)."""
    for i, o in enumerate(ops):
        if o.startswith("["):
            m = _BELLEK_ISL.match(o.strip())
            if not m:
                return i, None, None, False
            ofs = 0 if m.group(2) is None else sayi(m.group(2))
            return i, yazmac(m.group(1)), ofs, bool(m.group(3)) or i + 1 < len(ops)
    return None


def genislik(mn: str, yazmac_metni: str) -> int:
    if mn in _BAYT_SAKLAMA or mn in ("ldrb", "ldurb", "ldarb", "ldrsb", "ldursb", "ldaprb"):
        return 1
    if mn in _YARIM_SAKLAMA or mn in ("ldrh", "ldurh", "ldarh", "ldrsh", "ldursh", "ldaprh"):
        return 2
    if mn in ("ldrsw", "ldursw", "ldpsw"):
        return 4
    return {"w": 4, "x": 8, "q": 16, "d": 8, "s": 4, "h": 2, "b": 1}.get(
        yazmac_metni.strip().lower()[:1], 8)


def kume(*degerler) -> frozenset:
    return frozenset(degerler)


def tek_param(v: frozenset) -> int | None:
    """Değer kümesi tam olarak {p_i} ise i."""
    if len(v) == 1:
        d = next(iter(v))
        if d[0] == "p":
            return d[1]
    return None


def giris_durumu() -> "Durum":
    """Fonksiyon girişi: x0-x7 parametredir; öbür yazmaçlar ve yığın bilinmez."""
    return Durum({f"x{n}": kume(("p", n)) for n in range(8)})


class Durum:
    """Yazmaç ve yığın yuvası değer kümeleri. Eksik anahtar = bilinmez."""

    __slots__ = ("y", "s")

    def __init__(self, y: dict | None = None, s: dict | None = None):
        self.y: dict[str, frozenset] = dict(y or {})
        self.s: dict[tuple[str, int], frozenset] = dict(s or {})

    def kopya(self) -> "Durum":
        return Durum(self.y, self.s)

    def __eq__(self, o: object) -> bool:
        return isinstance(o, Durum) and self.y == o.y and self.s == o.s

    def oku(self, r: str | None) -> frozenset:
        if r == "zr":
            return SIFIR
        if r == "sp":
            return YIGIN
        if r is None:
            return BILINMEZ
        return self.y.get(r, BILINMEZ)

    def yigin_sil(self, taban: str | None = None) -> None:
        if taban is None:
            self.s.clear()
        else:
            for k in [k for k in self.s if k[0] == taban]:
                del self.s[k]

    def yaz(self, r: str | None, v: frozenset) -> None:
        if r is None or r == "zr":
            return
        if r == "sp":
            self.yigin_sil()
            return
        if r == "x29":
            self.yigin_sil("x29")
        if v == BILINMEZ or len(v) > DEGER_SINIRI:
            self.y.pop(r, None)
        else:
            self.y[r] = v


def durum_birlestir(durumlar: list[Durum]) -> Durum:
    if len(durumlar) == 1:
        return durumlar[0].kopya()
    yeni = Durum()
    for alan in ("y", "s"):
        hedef = getattr(yeni, alan)
        anahtarlar = set()
        for d in durumlar:
            anahtarlar |= getattr(d, alan).keys()
        for k in sorted(anahtarlar):
            u = frozenset().union(*(getattr(d, alan).get(k, BILINMEZ) for d in durumlar))
            if u != BILINMEZ and len(u) <= DEGER_SINIRI:
                hedef[k] = u
    return yeni


def _artir(v: frozenset, adim: int) -> frozenset:
    return frozenset(("k", d[1] + adim) if d[0] == "k" else ("?",) for d in v)


def _ters(v: frozenset) -> frozenset:
    return frozenset(("k", ~d[1]) if d[0] == "k" else ("?",) for d in v)


def _saklama(d: Durum, pc: int, mn: str, ops: tuple[str, ...], olay) -> None:
    b = bellek(ops)
    if b is None:
        return
    i, taban, ofs, geri = b
    kaynaklar = list(ops[:i])
    if mn.startswith(_DURUMLU_SAKLAMA) and kaynaklar:
        d.yaz(yazmac(kaynaklar.pop(0)), BILINMEZ)
    gen = genislik(mn, kaynaklar[0] if kaynaklar else "x")
    degerler = [d.oku(yazmac(k)) for k in kaynaklar]
    taban_degeri = d.oku(taban)
    if olay is not None:
        olay(("saklama", pc, taban, taban_degeri, ofs, gen, tuple(degerler)))
    if taban in _YIGIN_TABANI:
        obur = "x29" if taban == "sp" else "sp"
        d.yigin_sil(obur)     # sp ile x29 arasındaki ilişki izlenmiyor: öbür tabanın yuvaları silinir
        if geri or ofs is None:
            d.yigin_sil(taban)
            if geri and taban == "sp":
                d.yigin_sil()
            return
        for k, deger in enumerate(degerler):
            alt, ust = ofs + k * gen, ofs + (k + 1) * gen
            for yuva in [y for y in d.s if y[0] == taban and y[1] < ust and y[1] + 8 > alt]:
                del d.s[yuva]
            if deger != BILINMEZ and gen in (4, 8, 16):
                d.s[(taban, alt)] = deger
    elif geri:
        d.yaz(taban, BILINMEZ)


def _yukleme(d: Durum, mn: str, ops: tuple[str, ...]) -> None:
    b = bellek(ops)
    if b is None:
        for o in ops[:2]:
            d.yaz(yazmac(o), BILINMEZ)
        return
    i, taban, ofs, geri = b
    hedefler = ops[:i]
    taban_degeri = d.oku(taban)
    p = tek_param(taban_degeri)
    gen = genislik(mn, hedefler[0] if hedefler else "x")
    yeni = []
    for k, h in enumerate(hedefler):
        o = None if ofs is None else ofs + k * gen
        if o is None:
            v = BILINMEZ
        elif taban in _YIGIN_TABANI:
            v = d.s.get((taban, o), BILINMEZ)
        elif p is not None:
            v = kume(("f", p, o))
        else:
            v = BILINMEZ
        yeni.append((yazmac(h), v))
    for r, v in yeni:
        d.yaz(r, v)
    if geri:
        if taban == "sp":
            d.yigin_sil()
        elif taban == "x29":
            d.yigin_sil("x29")
        else:
            d.yaz(taban, BILINMEZ)


def komut_isle(d: Durum, pc: int, mn: str, ops: tuple[str, ...], olay=None) -> None:
    """Dallanma ve çağrı dışı bir komutun durum üzerindeki etkisi; saklamalar olay olarak."""
    if mn.startswith(_YAZMA):
        _saklama(d, pc, mn, ops, olay)
        return
    if mn.startswith(_RMW):
        for o in ops[:2]:
            d.yaz(yazmac(o), BILINMEZ)
        return
    if mn.startswith("ld"):
        _yukleme(d, mn, ops)
        return
    if mn in _YAZMAYAN or not ops:
        return
    hedef = yazmac(ops[0])
    if hedef is None:
        return
    v = BILINMEZ
    n = len(ops)
    if mn == "mov" and n == 2:
        c = sayi(ops[1]) if ops[1].strip().startswith("#") else None
        if c is not None:
            v = kume(("k", sabit(c, ops[0]))) if hedef[0] == "x" else (SIFIR if c == 0 else BILINMEZ)
        else:
            v = d.oku(yazmac(ops[1]))
    elif mn in ("movz", "movn") and n >= 2:
        c = sayi(ops[1])
        kaydir = re.search(r"lsl\s*#(\w+)", ops[2], re.I) if n > 2 else None
        if c is not None:
            c <<= (sayi(kaydir.group(1)) or 0) if kaydir else 0
            v = kume(("k", sabit(c if mn == "movz" else ~c, ops[0])))
    elif mn == "movi" and n >= 2:
        v = SIFIR if sayi(ops[1]) == 0 else BILINMEZ
    elif mn == "orr" and n == 3 and yazmac(ops[1]) == "zr":
        c = sayi(ops[2]) if ops[2].strip().startswith("#") else None
        v = kume(("k", sabit(c, ops[0]))) if c is not None else d.oku(yazmac(ops[2]))
    elif mn == "cset":
        v = kume(("b",))
    elif mn == "csetm":
        v = kume(("k", 0), ("k", -1))
    elif mn == "csel" and n >= 3:
        v = d.oku(yazmac(ops[1])) | d.oku(yazmac(ops[2]))
    elif mn == "csinc" and n >= 3:
        v = d.oku(yazmac(ops[1])) | _artir(d.oku(yazmac(ops[2])), 1)
    elif mn == "cinc" and n >= 2:
        a = d.oku(yazmac(ops[1]))
        v = a | _artir(a, 1)
    elif mn == "csinv" and n >= 3:
        v = d.oku(yazmac(ops[1])) | _ters(d.oku(yazmac(ops[2])))
    elif mn == "cinv" and n >= 2:
        a = d.oku(yazmac(ops[1]))
        v = a | _ters(a)
    elif mn in ("and", "ands") and n == 3 and sayi(ops[2]) == 1:
        v = kume(("b",))
    elif mn == "eor" and n == 3 and sayi(ops[2]) == 1 and d.oku(yazmac(ops[1])) <= MANTIKSAL:
        v = kume(("b",))
    elif mn == "ubfx" and n == 4 and sayi(ops[3]) == 1:
        v = kume(("b",))
    elif mn == "lsr" and n == 3 and sayi(ops[2]) == (31 if ops[0].strip()[:1] == "w" else 63):
        v = kume(("b",))
    elif mn in ("add", "sub") and n == 3 and ops[2].strip().startswith("#") and (
            yazmac(ops[1]) == "sp" or d.oku(yazmac(ops[1])) == YIGIN):
        v = YIGIN
    d.yaz(hedef, v)


class Fonksiyon:
    """Bir iç fonksiyonun CFG'si ve veri akışı olayları (çağrı, saklama, çıkış)."""

    def __init__(self, adres: int, komutlar: list[tuple[int, str, str]]):
        self.adres = adres
        self.k = [(pc, mn, isleneler(isl)) for pc, mn, isl in komutlar]
        self.govde = {pc for pc, _, _ in self.k}
        self.cagrilar: list[tuple] = []    # (pc, tür, hedef, (x0..x7), blok)
        self.saklamalar: list[tuple] = []  # (pc, taban, taban değeri, ofset, genişlik, değerler, blok)
        self.cikislar: list[tuple] = []    # (pc, tür, x0, blok)

    def hedefler(self) -> set[int]:
        """bl ve gövde dışına (koşullu ya da koşulsuz) b hedefleri."""
        out = set()
        for _, mn, ops in self.k:
            tur, t = dal_turu(mn, ops)
            if t is not None and (tur == "cagri" or (tur in ("atla", "kosul")
                                                     and t not in self.govde)):
                out.add(t)
        return out

    def cfg(self, donmez_mi) -> None:
        """Bloklar, ardıllar, dönen çıkışlı bloklar ve ardılsız blokların sonu.

        ``donmez_mi(hedef)`` → None | 'gercek' | 'derleyici'. Gövde dışına koşullu dallanma
        koşullu kuyruk çağrısıdır: blok hem ardılına gider hem (hedef dönüyorsa) dönen çıkış taşır.
        """
        k = self.k
        pcs = [pc for pc, _, _ in k]
        sira = {pc: i for i, pc in enumerate(pcs)}
        self.sira = sira
        liderler = {pcs[0]}
        for i, (pc, mn, ops) in enumerate(k):
            tur, t = dal_turu(mn, ops)
            son = tur in ("atla", "kosul", "don", "ddal", "tuzak") or (
                tur == "cagri" and donmez_mi(t) is not None)
            if tur in ("atla", "kosul") and t in self.govde:
                liderler.add(t)
            if i + 1 < len(k) and (son or pcs[i + 1] != pc + 4):
                liderler.add(pcs[i + 1])
        self.baslar = sorted(liderler)
        self.blok: dict[int, tuple[int, int]] = {}
        for j, b in enumerate(self.baslar):
            bitis = sira[self.baslar[j + 1]] if j + 1 < len(self.baslar) else len(k)
            self.blok[b] = (sira[b], bitis)
        self.ardil: dict[int, list[int]] = {}
        self.donen: set[int] = set()            # dönen bir çıkış taşıyan bloklar
        self.son_tur: dict[int, str] = {}       # ardılsız ve dönmeyen blokların sonu
        self.donmez_hedef: dict[int, int | None] = {}
        for b, (i0, i1) in self.blok.items():
            pc, mn, ops = k[i1 - 1]
            tur, t = dal_turu(mn, ops)
            dis = t is None or t not in self.govde
            out = []
            if tur in ("atla", "kosul") and not dis:
                out.append(t)
            dm = donmez_mi(t) if tur in ("cagri", "atla", "kosul") and dis else None
            duz = tur not in ("atla", "don", "ddal", "tuzak") and not (tur == "cagri" and dm)
            if duz and i1 < len(k) and pcs[i1] == pc + 4:
                out.append(pcs[i1])
            self.ardil[b] = sorted(set(out))
            if tur in ("don", "ddal") or (tur in ("atla", "kosul") and dis and not dm):
                self.donen.add(b)
            elif self.ardil[b]:
                pass
            elif dm:
                self.son_tur[b] = f"donmez_{dm}"
                self.donmez_hedef[b] = t
            elif tur == "tuzak":
                self.son_tur[b] = "tuzak"
            else:
                self.son_tur[b] = "yok"   # gövde sonundan düşüyor: dönmez sayılır
        self.onceller: dict[int, list[int]] = {b: [] for b in self.baslar}
        for b in self.baslar:
            for t in self.ardil[b]:
                self.onceller[t].append(b)
        # dönen çıkışa ulaşabilen bloklar (ana yol)
        self.ana = set(self.donen)
        kuyruk = deque(sorted(self.donen))
        while kuyruk:
            b = kuyruk.popleft()
            for p in self.onceller[b]:
                if p not in self.ana:
                    self.ana.add(p)
                    kuyruk.append(p)

    def erisilen(self, baslangic: list[int], yasak: set[int] = frozenset()) -> set[int]:
        gorulen = set()
        kuyruk = deque(b for b in baslangic if b not in yasak)
        while kuyruk:
            b = kuyruk.popleft()
            if b in gorulen:
                continue
            gorulen.add(b)
            kuyruk.extend(t for t in self.ardil[b] if t not in yasak and t not in gorulen)
        return gorulen

    def geri_erisilen(self, hedefler: set[int]) -> set[int]:
        """Hedef bloklardan birine ulaşabilen bloklar (hedefler dahil)."""
        gorulen = set(hedefler)
        kuyruk = deque(sorted(hedefler))
        while kuyruk:
            b = kuyruk.popleft()
            for p in self.onceller[b]:
                if p not in gorulen:
                    gorulen.add(p)
                    kuyruk.append(p)
        return gorulen

    def donen_cikis_erisilir(self) -> bool:
        return bool(self.donen & self.erisilen([self.baslar[0]]))

    def akis(self, donmez_mi) -> None:
        """İleri veri akışı (sabit nokta), sonra olayların toplanması."""
        giris = giris_durumu()
        kok = self.baslar[0]
        # Önceli olmayan bloklara yalnız dolaylı dallanma (atlama tablosu) varsa ulaşılabilir;
        # yoksa dolgu ya da ölü koddur ve akışa bilinmez durum sokmamalıdır.
        dolayli = any(dal_turu(mn, ops)[0] == "ddal" for _, mn, ops in self.k)
        yetim = {b for b in self.baslar if b != kok and not self.onceller[b]} if dolayli else set()
        ic: dict[int, Durum] = {}
        dis: dict[int, Durum] = {}
        tur_say: Counter = Counter()
        bekleyen = sorted({kok} | yetim)
        sirada = set(bekleyen)
        heapq.heapify(bekleyen)
        while bekleyen:
            b = heapq.heappop(bekleyen)
            sirada.discard(b)
            gelen = [dis[p] for p in sorted(self.onceller[b]) if p in dis]
            if b == kok:
                gelen = [giris] + gelen
            elif b in yetim:
                gelen = [Durum()] + gelen
            if not gelen:
                continue
            yeni = durum_birlestir(gelen)
            if b in ic and ic[b] == yeni:
                continue
            tur_say[b] += 1
            if tur_say[b] > TUR_SINIRI:
                yeni = Durum()
                if b in ic and ic[b] == yeni:
                    continue
            ic[b] = yeni
            dis[b] = self._blok_isle(b, yeni.kopya(), donmez_mi, None)
            for t in self.ardil[b]:
                if t not in sirada:
                    sirada.add(t)
                    heapq.heappush(bekleyen, t)
        self.ic_durum = ic
        for b in self.baslar:
            if b in ic:
                self._blok_isle(b, ic[b].kopya(), donmez_mi, b)

    def _blok_isle(self, b: int, d: Durum, donmez_mi, kayit: int | None, bas: int = 0,
                   son: int | None = None, cikis_listesi: list | None = None) -> Durum:
        """Bloğun [bas, son) komutlarını işler. ``kayit`` verilirse olaylar fonksiyona yazılır;
        ``cikis_listesi`` verilirse dönen çıkışlar yalnız oraya yazılır (yol duyarlı okuma)."""
        i0, i1 = self.blok[b]
        olay = None
        if kayit is not None:
            def olay(o, _b=kayit):
                self.saklamalar.append(o[1:] + (_b,))
        cikis = self.cikislar if kayit is not None else cikis_listesi
        for pc, mn, ops in self.k[i0 + bas:(i1 if son is None else i0 + son)]:
            tur, t = dal_turu(mn, ops)
            kuyruk = tur in ("atla", "kosul") and (t is None or t not in self.govde)
            if tur in ("cagri", "dcagri") or kuyruk:
                if kayit is not None:
                    self.cagrilar.append((pc, "kuyruk" if kuyruk else ("bl" if tur == "cagri"
                                                                     else "blr"),
                                          t, tuple(d.oku(f"x{n}") for n in range(8)), kayit))
                if kuyruk and cikis is not None and not donmez_mi(t):
                    cikis.append((pc, "kuyruk", kume(("r", pc)), b))
                if kuyruk:
                    continue   # koşulsuz kuyruk çağrısı zaten bloğun son komutu
                for n in list(range(19)) + [30]:
                    d.yaz(f"x{n}", BILINMEZ)
                for r in [r for r in d.y if r.startswith("v")]:
                    del d.y[r]
                d.yaz("x0", kume(("r", pc)))
            elif tur == "don":
                if cikis is not None:
                    cikis.append((pc, "ret", d.oku("x0"), b))
            elif tur == "ddal":
                if cikis is not None:
                    cikis.append((pc, "br", BILINMEZ, b))
            elif tur in ("kosul", "atla", "tuzak"):
                pass
            else:
                komut_isle(d, pc, mn, ops, olay)
        return d

    def durum_sonra(self, b: int, j: int, donmez_mi) -> Durum:
        """Blok ``b``'nin ``j``. komutu (bloğa göre sıra) işlendikten sonraki durum."""
        return self._blok_isle(b, self.ic_durum[b].kopya(), donmez_mi, None, son=j + 1)

    def yol_cikislari(self, baslangic: list[tuple[int, int, Durum]], yasak: set[int],
                      donmez_mi) -> list[tuple]:
        """(blok, komut sırası, durum) noktalarından, yasak bloklara girmeden ulaşılan dönen
        çıkışlar ve x0'ları. Birleştirme yalnız bu yolların durumları arasında yapılır; böylece
        ortak bir dönüş bloğunda öbür yolların değeri karışmaz."""
        cikislar: list[tuple] = []
        tohum: dict[int, list[Durum]] = {}
        for b, j, d in baslangic:
            if j == 0:
                if b not in yasak:
                    tohum.setdefault(b, []).append(d)
                continue
            dd = self._blok_isle(b, d.kopya(), donmez_mi, None, bas=j, cikis_listesi=cikislar)
            for t in self.ardil[b]:
                if t not in yasak:
                    tohum.setdefault(t, []).append(dd)
        ic: dict[int, Durum] = {}
        dis: dict[int, Durum] = {}
        tur_say: Counter = Counter()
        sira = sorted(tohum)
        sirada = set(sira)
        heapq.heapify(sira)
        while sira:
            b = heapq.heappop(sira)
            sirada.discard(b)
            gelen = list(tohum.get(b, [])) + [dis[p] for p in sorted(self.onceller[b]) if p in dis]
            yeni = durum_birlestir(gelen)
            if b in ic and ic[b] == yeni:
                continue
            tur_say[b] += 1
            if tur_say[b] > TUR_SINIRI:
                yeni = Durum()
                if b in ic and ic[b] == yeni:
                    continue
            ic[b] = yeni
            dis[b] = self._blok_isle(b, yeni.kopya(), donmez_mi, None)
            for t in self.ardil[b]:
                if t not in yasak and t not in sirada:
                    sirada.add(t)
                    heapq.heappush(sira, t)
        for b in sorted(ic):
            self._blok_isle(b, ic[b].kopya(), donmez_mi, None, cikis_listesi=cikislar)
        return cikislar


def _ham_hedef_coz(f: dict, coz) -> dict:
    """hedef adresi → (normalize kütüphane adları, iç fonksiyonlar, çözülemeyen var mı)."""
    bilgi: dict[int, tuple[frozenset, frozenset, bool]] = {}
    for t in f:
        rs = coz(t)
        libs = frozenset(import_adi(f[x]["ad"]) for x in rs if x in f and f[x]["tur"] == "lib")
        ics = frozenset(x for x in rs if x in f and f[x]["tur"] == "ic")
        bilinmez = any(x not in f or f[x]["tur"] == "ic_thunk" for x in rs)
        bilgi[t] = (libs, ics, bilinmez)
    return bilgi


def n4_elf(f: dict, kod: dict, meta: dict, coz, aile: str, uyeler: dict[str, set[int]],
           sinif: dict[int, str], cagiran_sayisi: dict[int, int], n_komut: dict[int, int],
           yazar: dict[int, bool]) -> dict:
    """Bir ELF için N4 sayaçları. Ad ve adres dışarı verilmez (örnekler ayrı, depo dışına)."""
    hedef = _ham_hedef_coz(f, coz)
    ileti = ILETI | (ILETI_YALNIZ_ELF if aile == "elf" else frozenset())
    errno_adlari = {import_adi(n) for n in ERRNO_HAM[aile]}
    fonk: dict[int, Fonksiyon] = {a: Fonksiyon(a, kod[a]) for a in sorted(kod)
                                  if a in f and f[a]["tur"] == "ic"}

    def bilgi(t):
        return hedef.get(t, (frozenset(), frozenset(), True)) if t is not None else None

    donmez_ic: set[int] = set()

    def donmez_mi(t):
        h = bilgi(t)
        if h is None:
            return None
        libs, ics, bilinmez = h
        if bilinmez or not (libs or ics):
            return None
        if all(n in DONMEZ for n in libs) and all(i in donmez_ic for i in ics):
            return "gercek"
        if not ics and all(n in DONMEZ | DONMEZ_DERLEYICI for n in libs):
            return "derleyici"
        return None

    # dönmeyen iç fonksiyonlar: sabit nokta (yalnız yeni dönmez hedefi çağıranlar yeniden bakılır)
    cagiranlar: dict[int, set[int]] = {}
    for a, fn in fonk.items():
        for t in fn.hedefler():
            for i in bilgi(t)[1]:
                cagiranlar.setdefault(i, set()).add(a)
    bakilacak = sorted(fonk)
    while bakilacak:
        yeni = set()
        for a in bakilacak:
            if a in donmez_ic:
                continue
            fn = fonk[a]
            fn.cfg(donmez_mi)
            if not fn.donen_cikis_erisilir():
                yeni.add(a)
        donmez_ic |= yeni
        bakilacak = sorted({c for a in yeni for c in cagiranlar.get(a, ())} - donmez_ic)
    for a in sorted(fonk):
        fonk[a].cfg(donmez_mi)
        fonk[a].akis(donmez_mi)

    def derleyici_mi(t):
        h = bilgi(t)
        return h is not None and not h[1] and not h[2] and h[0] and h[0] <= (DERLEYICI | CRT)

    def anlamli_cagrilar(fn):
        return [c for c in fn.cagrilar if not derleyici_mi(c[2])]

    # FK1 sarmalayıcıları (bütün iç fonksiyonlarda)
    fk1_free: set[int] = set()
    fk1_dar: dict[int, frozenset] = {}
    fk1_genis: dict[int, frozenset] = {}
    for a, fn in fonk.items():
        cs = anlamli_cagrilar(fn)
        if not cs or any(c[1] == "blr" for c in cs):
            continue
        bilgiler = [bilgi(c[2]) for c in cs]
        if any(h[2] for h in bilgiler):
            continue
        x0_param = all(c[3][0] == kume(("p", 0)) for c in cs)
        if x0_param and all(h[0] == BIRAKICI and not h[1] for h in bilgiler):
            fk1_free.add(a)
            continue
        ayirici_pc = {c[0] for c, h in zip(cs, bilgiler) if h[0] and h[0] <= AYIRICI and not h[1]}
        donus = [c[2] for c in fn.cikislar]
        r_ayirici = frozenset(("r", pc) for pc in ayirici_pc)
        adlar = frozenset(n for c, h in zip(cs, bilgiler) if c[0] in ayirici_pc for n in h[0])
        nesneye_yazmiyor = not any(s[2] and s[2] <= r_ayirici for s in fn.saklamalar)
        if (len({h[0] for h in bilgiler}) == 1 and ayirici_pc == {c[0] for c in cs}
                and len(adlar) == 1 and x0_param and nesneye_yazmiyor and donus
                and all(v <= r_ayirici for v in donus)):
            fk1_dar[a] = adlar
        izinli = AYIRICI | DONMEZ | ileti | errno_adlari
        param_gidiyor = all(any(d[0] == "p" for d in c[3][0]) for c in cs if c[0] in ayirici_pc)
        if (ayirici_pc and donus and all(v <= r_ayirici | SIFIR for v in donus)
                and any(v & r_ayirici for v in donus) and param_gidiyor and nesneye_yazmiyor
                and all((h[0] <= izinli) and all(i in donmez_ic for i in h[1]) for h in bilgiler)):
            fk1_genis[a] = adlar
    fk1_genis.update(fk1_dar)

    def ayirici_mi(t, mod):
        h = bilgi(t)
        if h is None or h[2] or not (h[0] or h[1]):
            return False
        sar = fk1_dar if mod == "dar" else fk1_genis
        return all(n in AYIRICI for n in h[0]) and all(i in sar for i in h[1])

    def ayirici_adlari(t):
        h = bilgi(t)
        out = set(h[0])
        for i in h[1]:
            out |= fk1_genis.get(i, frozenset())
        return out

    def birakici_mi(t):
        h = bilgi(t)
        if h is None or h[2] or not (h[0] or h[1]):
            return False
        return all(n in BIRAKICI for n in h[0]) and all(i in fk1_free for i in h[1])

    say: Counter = Counter()
    ham: dict[str, list[tuple[int, int]]] = {p: [] for p in uyeler}
    ornek: dict[str, list[int]] = {}
    ates_fiil: Counter = Counter()          # yalnız bekleyen: fiil → ateşleme sayısı

    for a in sorted(set().union(*uyeler.values()) if uyeler else ()):
        fn = fonk.get(a)
        olcu: set[str] = {"n"}
        if cagiran_sayisi.get(a, 0) == 0:
            olcu.add("cagiransiz")
        olcu.add(f"komut_{dilim(n_komut[a], KOMUT_DILIMLERI)}")
        n_cagri = 0
        if fn is None:
            olcu.add("disasm_yok")
        else:
            olcu |= _n4_fonksiyon(fn, meta.get(a, {}), yazar.get(a, False), anlamli_cagrilar,
                                  ayirici_mi, ayirici_adlari, birakici_mi, bilgi,
                                  fk1_free, fk1_dar, fk1_genis, donmez_ic, donmez_mi)
            n_cagri = len(anlamli_cagrilar(fn))
        olcu.add(f"cagri_{dilim(n_cagri, CAGRI_DILIMLERI)}")
        for pop, kumesi in uyeler.items():
            if a not in kumesi:
                continue
            ham[pop].append((n_komut[a], n_cagri))
            for o in olcu:
                say[f"{pop}:{o}"] += 1
                say[f"{pop}:{o}:{sinif[a]}"] += 1
                if pop == "bekleyen" and not o.startswith("komut_"):
                    say[f"{pop}:{o}:komut_{dilim(n_komut[a], KOMUT_DILIMLERI)}"] += 1
            if pop == "bekleyen":
                for o in sorted(olcu):
                    ornek.setdefault(o, []).append(a)
                for fiil in ("create_dar", "create_genis", "destroy", "is", "init"):
                    if f"fire_{fiil}" in olcu:
                        ates_fiil[fiil] += 1
    for fiil in ("create_dar", "create_genis", "destroy", "is", "init"):
        say[f"bekleyen:ad_tekil:{fiil}"] += int(ates_fiil[fiil] == 1)
    say["elf:fk1_free"] = len(fk1_free)
    say["elf:fk1_ayirici_dar"] = len(fk1_dar)
    say["elf:fk1_ayirici_genis"] = len(fk1_genis)
    say["elf:donmez_ic"] = len(donmez_ic)
    return {"sayac": say, "ham": ham, "ornek": ornek}


def _n4_fonksiyon(fn: Fonksiyon, meta: dict, yazar: bool, anlamli_cagrilar, ayirici_mi,
                  ayirici_adlari, birakici_mi, bilgi, fk1_free, fk1_dar, fk1_genis,
                  donmez_ic, donmez_mi) -> set[str]:
    """Bir fonksiyonun N4 ölçüleri (doğru olan ölçü adlarının kümesi)."""
    out: set[str] = set()
    donus = meta.get("donus")
    void = donus == "void"
    if donus is None:
        out.add("donus_bilinmiyor")
    elif void:
        out.add("donus_void")
    if yazar:
        out.add("yazar")
    if meta.get("ghidra_donmez"):
        out.add("ghidra_donmez")
    a = fn.adres
    if a in fk1_free:
        out.add("fk1_free")
    if a in fk1_dar:
        out.add("fk1_ayirici_dar")
    if a in fk1_genis:
        out.add("fk1_ayirici_genis")
    cs = anlamli_cagrilar(fn)
    cikis = fn.cikislar
    if not fn.donen_cikis_erisilir():
        out.add("tum_yollar_donmez")
    # FK3: dönen çıkışa ulaşamayan ve gerçek dönmeyen çağrıya ulaşan blok
    gercek_son = {b for b in fn.baslar if fn.son_tur.get(b) == "donmez_gercek"}
    hata = fn.geri_erisilen(gercek_son) - fn.ana
    if hata and fn.ana:
        out.add("fk3_genis")
        dar_son = {b for b in gercek_son if not bilgi(fn.donmez_hedef[b])[1]}
        if hata & fn.geri_erisilen(dar_son):
            out.add("fk3_dar")
    # ayırıcı ve bırakıcı çağrıları
    ayirici_pc = {m: {c[0] for c in cs if c[1] != "blr" and ayirici_mi(c[2], m)}
                  for m in ("dar", "genis")}
    if ayirici_pc["genis"]:
        out.add("ayirici_cagiran")
    birakma = [c for c in cs if c[1] != "blr" and birakici_mi(c[2])]
    if birakma:
        out.add("birakici_cagiran")
    # dönüşler
    donusler = [c[2] for c in cikis]
    mantiksal = bool(donusler) and not void and all(v <= MANTIKSAL for v in donusler)
    if mantiksal and not yazar:
        out.add("fire_is")
    if mantiksal and cs:
        out.add("kalip1")
        if not yazar:
            out.add("kalip1_is")
            hedefler = [bilgi(c[2]) for c in cs]
            if all(h is not None and not h[1] and not h[2] and h[0] and h[0] <= SALT_OKUR
                   for h in hedefler):
                out.add("kalip1_is_salt_okur")
            else:
                out.add("kalip1_is_yan")
                if any(h is not None and h[0] - SALT_OKUR for h in hedefler):
                    out.add("kalip1_is_yan_kutuphane")
    # parametre ofsetlerine sabit/parametre yazımı (init, kalıp 2)
    yazilan: dict[int, set[int]] = {}
    for _pc, _taban, tdeger, ofs, gen, degerler, _b in fn.saklamalar:
        p = tek_param(tdeger)
        if p is None or ofs is None:
            continue
        for k, v in enumerate(degerler):
            if v and all(d[0] in ("k", "p") for d in v):
                yazilan.setdefault(p, set()).add(ofs + k * gen)
    coklu_yazim = {p for p, o in yazilan.items() if len(o) >= 2}
    if coklu_yazim and not ayirici_pc["genis"]:
        out.add("fire_init")
    # create (dar, geniş)
    for m in ("dar", "genis"):
        sar = fk1_dar if m == "dar" else fk1_genis
        r_ay = frozenset(("r", pc) for pc in ayirici_pc[m])
        if (a not in sar and r_ay and donusler and all(v <= r_ay | SIFIR for v in donusler)
                and any(v & r_ay for v in donusler)
                and any(s[2] and s[2] <= r_ay for s in fn.saklamalar)):
            out.add(f"fire_create_{m}")
            if m == "genis":
                donen_pc = {d[1] for v in donusler for d in v if d[0] == "r"}
                if any(ayirici_adlari(c[2]) & BUYUTUCU for c in cs if c[0] in donen_pc):
                    out.add("create_buyutme")
    # destroy ve kalıp 2-4
    param_birakma: dict[int, list[tuple]] = {}
    alan_birakma: set[int] = set()
    birakilan_param: set[int] = set()
    for c in birakma:
        x0 = c[3][0]
        p = tek_param(x0)
        if p is not None and c[4] in fn.ana:
            param_birakma.setdefault(p, []).append(c)
        for d in x0:
            if d[0] == "p":
                birakilan_param.add(d[1])
        if len(x0) == 1 and next(iter(x0))[0] == "f":
            alan_birakma.add(next(iter(x0))[1])
    if any(p in coklu_yazim and p not in birakilan_param for p in alan_birakma):
        out.add("kalip2")
        if "fire_init" in out:
            out.add("kalip2_init")
    if param_birakma and a not in fk1_free:
        out.add("fire_destroy")
        birakma_pc = {c[0] for c in birakma}
        obur = [c for c in cs if c[0] not in birakma_pc]
        if obur:
            out.add("kalip3")
            if any(c[3][0] == kume(("p", p)) for c in obur for p in param_birakma):
                out.add("kalip3_arg")
        her_yolda = False
        for p in sorted(param_birakma):
            siteler = param_birakma[p]
            yasak = {c[4] for c in siteler}
            # yol duyarlı: bırakmasız yolların ve bırakma sonrası yolların çıkışları ayrı akıtılır
            kacak = fn.yol_cikislari([(fn.baslar[0], 0, giris_durumu())], yasak, donmez_mi)
            if not kacak:
                her_yolda = True
                continue
            sonra: list[tuple] = []
            for c in siteler:
                if c[1] == "kuyruk":
                    sonra.append((c[0], "kuyruk", kume(("r", c[0])), c[4]))
                    continue
                j = fn.sira[c[0]] - fn.blok[c[4]][0]
                sonra += fn.yol_cikislari([(c[4], j + 1, fn.durum_sonra(c[4], j, donmez_mi))],
                                          set(), donmez_mi)
            if not sonra:
                continue

            def negatif(v):
                return bool(v) and all(d[0] == "k" and d[1] < 0 for d in v)

            if all(negatif(e[2]) for e in sonra) and any(not negatif(e[2]) for e in kacak):
                out.add("kalip4")
            if all(e[2] == SIFIR for e in sonra) and any(e[2] != SIFIR for e in kacak):
                out.add("kalip4_sifir")
        if her_yolda:
            out.add("destroy_her_yolda")
    # aile birleşimleri
    if out & {"fire_create_genis", "fire_destroy"}:
        out.add("fetki_ilk")
    destroy_riskli = "fire_destroy" in out and bool(out & {"kalip3", "kalip4"})
    if destroy_riskli:
        out.add("fetki_ilk_riskli")
        out.add("destroy_riskli")
    if out & {"fire_is", "fire_init", "fire_create_genis", "fire_destroy"}:
        out.add("fetki_tum")
    if destroy_riskli or out & {"kalip1_is", "kalip2_init"}:
        out.add("fetki_tum_riskli")
    return out


def elf_say(static_dir: Path, capalar: dict[int, tuple[str, str | None]] | None = None) -> dict:
    """Tek bir static/ dizini için sayımlar ve birim toplamına girecek ara veriler.

    ``capalar``: KS-1 ``func_kalibi`` çapaları (adres → addaki fiil durumu ve sınıfı); verilirse
    N4 temsil denetiminde ayrı nüfus olur.
    """
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

    kod, meta = kod_oku(static_dir / "ghidra_output" / "decompiled")
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
    export_adres: set[int] = set()
    export_tek: set[int] = set()
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
            export_tek.add(a)
        export_adres.add(a)
        adli_fiil[ad] = (durum, fs, sinif)

    # N4 (sürüm 2): nüfuslar aynı ölçülerle
    uyeler = {"bekleyen": set(nufus), "export": export_adres, "export_tek": export_tek}
    if capalar is not None:
        uyeler["capa"] = {a for a in capalar if a in bilgi_f}
        uyeler["capa_tek"] = {a for a in uyeler["capa"] if capalar[a][0] == "tek_sinif"}
    n4 = n4_elf(
        f, kod, meta, coz, aile, uyeler,
        sinif={a: ("K" if b["lib"] else ("I" if b["ic"] else "Y")) for a, b in bilgi_f.items()},
        cagiran_sayisi={a: len(cagiran.get(a, ())) for a in bilgi_f},
        n_komut={a: (b["ozet"]["n"] if b["ozet"] else max(1, f[a]["boyut"] // 4))
                 for a, b in bilgi_f.items()},
        yazar={a: bool(b["ozet"] and b["ozet"]["yazar"]) for a, b in bilgi_f.items()})

    return {
        "sayim": s, "adli": adli, "df": df, "imza": imza,
        "aile": aile, "islemci": islemci, "cpp": cpp,
        "ham_import": ham_importlar, "adli_fiil": adli_fiil, "n4": n4,
        "girdi_ozeti": hashlib.sha256(hashlib.sha256(fham).digest()
                                      + hashlib.sha256(xham).digest()).hexdigest(),
    }


# ---------------------------------------------------------------------------------------------
# Koşu dizinleri ve birimler


# ---------------------------------------------------------------------------------------------
# Sürüm 2: istatistik, hüküm ve karşılaştırma


Z95 = 1.959963984540054


def yuvarla(x: float | None) -> float | None:
    return None if x is None else round(x, 4)


def wilson(k: int, n: int) -> tuple[float, float] | None:
    if n == 0:
        return None
    p = k / n
    z2 = Z95 * Z95
    payda = 1 + z2 / n
    merkez = (p + z2 / (2 * n)) / payda
    yari = Z95 * math.sqrt(p * (1 - p) / n + z2 / (4 * n * n)) / payda
    return max(0.0, merkez - yari), min(1.0, merkez + yari)


def newcombe(k1: int, n1: int, k2: int, n2: int) -> tuple[float, float] | None:
    """İki bağımsız oranın farkı (p1 − p2) için Newcombe (Wilson tabanlı) %95 aralığı."""
    if n1 == 0 or n2 == 0:
        return None
    p1, p2 = k1 / n1, k2 / n2
    l1, u1 = wilson(k1, n1)
    l2, u2 = wilson(k2, n2)
    d = p1 - p2
    return (d - math.sqrt((p1 - l1) ** 2 + (u2 - p2) ** 2),
            d + math.sqrt((u1 - p1) ** 2 + (p2 - l2) ** 2))


def katz(k1: int, n1: int, k2: int, n2: int) -> tuple[float, float] | None:
    """Oran oranı (p1 / p2) için Katz log %95 aralığı; iki sayı da > 0 olmalı."""
    if min(k1, k2) == 0 or n1 == 0 or n2 == 0:
        return None
    rr = (k1 / n1) / (k2 / n2)
    se = math.sqrt(1 / k1 - 1 / n1 + 1 / k2 - 1 / n2)
    return rr * math.exp(-Z95 * se), rr * math.exp(Z95 * se)


def oran_kaydi(k: int, n: int) -> dict:
    w = wilson(k, n)
    return {"k": k, "n": n, "oran": yuvarla(k / n) if n else None,
            "wilson95": [yuvarla(w[0]), yuvarla(w[1])] if w else None}


def ortanca_ozeti(liste: list[tuple[int, int]]) -> dict:
    if not liste:
        return {"n": 0, "komut": None, "cagri_yeri": None}
    return {"n": len(liste), "komut": statistics.median(k for k, _ in liste),
            "cagri_yeri": statistics.median(c for _, c in liste)}


RISK_ORANLARI = (
    # (ad, pay ölçüsü, payda ölçüsü)
    ("is", "kalip1_is", "fire_is"),
    ("is_yan", "kalip1_is_yan", "fire_is"),
    ("is_yan_kutuphane", "kalip1_is_yan_kutuphane", "fire_is"),
    ("init", "kalip2_init", "fire_init"),
    ("destroy", "destroy_riskli", "fire_destroy"),
    ("destroy_kalip3", "kalip3", "fire_destroy"),
    ("destroy_kalip3_arg", "kalip3_arg", "fire_destroy"),
    ("destroy_kalip4", "kalip4", "fire_destroy"),
    ("destroy_kalip4_sifir", "kalip4_sifir", "fire_destroy"),
    ("fetki_ilk", "fetki_ilk_riskli", "fetki_ilk"),
    ("fetki_tum", "fetki_tum_riskli", "fetki_tum"),
)


def olcum1_hukum(sayac: dict, pop: str = "bekleyen") -> dict:
    """Ölçüm 1'in Onuncu Adam §7.1 ölçütüne göre okunuşu (bir nüfus, bir birim ya da toplam)."""
    def g(o: str) -> int:
        return int(sayac.get(f"{pop}:{o}", 0))
    n = g("n")
    risk = {}
    for ad, pay, payda in RISK_ORANLARI:
        r = oran_kaydi(g(pay), g(payda))
        r["esik_asildi"] = None if r["oran"] is None else r["oran"] > RISK_ESIGI
        risk[ad] = r
    ates = {o: oran_kaydi(g(o), n) for o in (
        "fire_is", "fire_init", "fire_create_dar", "fire_create_genis", "fire_destroy",
        "destroy_her_yolda", "create_buyutme", "fetki_ilk", "fetki_tum", "kalip1", "kalip1_is",
        "kalip1_is_salt_okur", "kalip1_is_yan", "kalip1_is_yan_kutuphane", "kalip2", "kalip2_init", "kalip3", "kalip3_arg", "kalip4", "kalip4_sifir", "fk3_dar",
        "fk3_genis", "ghidra_donmez", "tum_yollar_donmez", "ayirici_cagiran",
        "birakici_cagiran", "fk1_free", "fk1_ayirici_dar", "fk1_ayirici_genis")}
    tekil = {}
    for fiil in ("create_dar", "create_genis", "destroy", "is", "init"):
        tekil[fiil] = oran_kaydi(int(sayac.get(f"{pop}:ad_tekil:{fiil}", 0)), g(f"fire_{fiil}"))
    return {"n": n, "riskli_pay": risk, "atesleme": ates, "ad_tekil": tekil,
            "create_destroy_esik_alti": None if n == 0 else g("fetki_ilk") / n < HTOP_B4_ESIGI}


KARSILASTIRMALAR = (
    ("debian/htop", "export", "debian/htop", "bekleyen"),
    ("debian/htop", "export_tek", "debian/htop", "bekleyen"),
    ("debian/htop", "export", "mac/htop", "bekleyen"),
    ("debian/htop", "export_tek", "mac/htop", "bekleyen"),
    ("debian/redis-tools", "export", "debian/redis-tools", "bekleyen"),
    ("debian/redis-tools", "export_tek", "debian/redis-tools", "bekleyen"),
    ("debian/redis-tools", "export_tek", "mac/tmux", "bekleyen"),
    ("mac/tmux", "capa", "mac/tmux", "bekleyen"),
    ("mac/tmux", "capa_tek", "mac/tmux", "bekleyen"),
    ("debian/tmux", "capa", "debian/tmux", "bekleyen"),
    ("debian/openssl", "capa", "debian/openssl", "bekleyen"),
)
KARSILASTIRMA_OLCULERI = (
    "cagiransiz", "n:K", "n:I", "n:Y", "komut_<=8", "komut_>=129", "cagri_0", "cagri_>=11",
    "kalip1", "kalip1_is", "kalip1_is_yan", "kalip2", "kalip2_init", "kalip3", "kalip3_arg", "kalip4",
    "kalip4_sifir", "fire_is", "fire_init", "fire_create_dar", "fire_create_genis",
    "fire_destroy", "destroy_riskli", "fetki_ilk", "fetki_tum", "ayirici_cagiran",
    "birakici_cagiran", "fk3_genis",
)
KURAL_OLCULERI = ("fire_create_genis", "fire_destroy", "fire_is", "fire_init", "fetki_ilk")


def m1_temsil(cikti_birim: dict) -> list[dict]:
    """M1 evreni (export ya da çapa) ile isim bekleyen nüfusun aynı ölçülerle karşılaştırması."""
    out = []
    for ub, pa, uk, pb in KARSILASTIRMALAR:
        sa, sb = cikti_birim.get(ub, {}).get("n4", {}), cikti_birim.get(uk, {}).get("n4", {})
        na, nb = int(sa.get(f"{pa}:n", 0)), int(sb.get(f"{pb}:n", 0))
        if na == 0 or nb == 0:
            out.append({"a": f"{ub}:{pa}", "b": f"{uk}:{pb}", "n_a": na, "n_b": nb,
                        "hukum": "olculemedi"})
            continue
        olculer = {}
        for o in KARSILASTIRMA_OLCULERI:
            ka, kb = int(sa.get(f"{pa}:{o}", 0)), int(sb.get(f"{pb}:{o}", 0))
            nc = newcombe(ka, na, kb, nb)
            kz = katz(ka, na, kb, nb)
            pa_, pb_ = ka / na, kb / nb
            olculer[o] = {
                "a": ka, "b": kb, "oran_a": yuvarla(pa_), "oran_b": yuvarla(pb_),
                "fark_puan": yuvarla(100 * (pa_ - pb_)),
                "fark_puan_95": [yuvarla(100 * nc[0]), yuvarla(100 * nc[1])],
                "oran_orani": yuvarla(pa_ / pb_) if kb else None,
                "oran_orani_95": [yuvarla(kz[0]), yuvarla(kz[1])] if kz else None,
            }
        kurallar = {}
        for o in KURAL_OLCULERI:
            r = olculer[o]
            if r["a"] == 0 and r["b"] == 0:
                kurallar[o] = "olculemedi"
            elif r["b"] == 0 or r["oran_orani"] is None:
                kurallar[o] = "bant_disi"
            else:
                kurallar[o] = ("bant_ici" if ORAN_BANDI[0] <= r["oran_orani"] <= ORAN_BANDI[1]
                               else "bant_disi")
        cagiransiz_ok = abs(olculer["cagiransiz"]["fark_puan"]) <= CAGIRANSIZ_PUAN_ESIGI
        ilk_ok = all(kurallar[o] == "bant_ici"
                     for o in ("fire_create_genis", "fire_destroy", "fetki_ilk"))
        out.append({
            "a": f"{ub}:{pa}", "b": f"{uk}:{pb}", "n_a": na, "n_b": nb,
            "ortanca_a": cikti_birim[ub]["n4_ortanca"].get(pa),
            "ortanca_b": cikti_birim[uk]["n4_ortanca"].get(pb),
            "olculer": olculer, "kural_bandi": kurallar,
            "cagiransiz_esik_ici": cagiransiz_ok,
            "hukum_fetki_ilk": ("oldurme_dayanagi_olabilir" if cagiransiz_ok and ilk_ok
                                else "yalniz_akil_sagligi"),
        })
    return out


ORNEK_OLCULERI = ("kalip1_is", "kalip1_is_yan", "kalip1", "kalip2", "kalip2_init", "kalip3",
                  "kalip3_arg",
                  "kalip4", "kalip4_sifir", "fire_create_dar", "fire_create_genis",
                  "fire_destroy", "fire_init", "fire_is", "fk3_genis")


def ornekleri_yaz(havuz: dict, yol: Path) -> None:
    """Elle okuma için ölçü başına en çok ORNEK_SAYISI ateşleme; seçim sha1 sırasıyla (tohumsuz,
    PYTHONHASHSEED'den bağımsız). Dosya adres taşır; depo dışına yazılır."""
    out = {}
    for o in ORNEK_OLCULERI:
        for kapsam in ("", "@mac"):
            aday = [t for t in havuz.get(o, []) if not kapsam or t[0].startswith("mac/")]
            sirali = sorted(aday, key=lambda t: hashlib.sha1(
                f"{o}|{t[0]}|{t[1]}|{t[3]:x}".encode()).hexdigest())
            out[o + kapsam] = {"toplam": len(aday),
                               "secilen": [{"birim": u, "elf": e,
                                            "static": str(Path(s).resolve()), "adres": f"{a:x}"}
                                           for u, e, s, a in sirali[:ORNEK_SAYISI]]}
    yol.write_text(json.dumps(out, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")


def capa_cikar(dizinler: list[tuple[str, str, str, Path]], yol: Path) -> int:
    """KS-1 ``func_kalibi`` çapaları: kesin.py (KS-1 ölçümündeki sha256) ile, bütün türler açık.

    Dosyaya ad yazılmaz: adres, addaki fiil durumu ve sınıfı (``fiil_durumu``).
    """
    kok = Path(__file__).resolve().parents[3]
    kesin_yolu = kok / KS1_KESIN_YOLU
    sha = hashlib.sha256(kesin_yolu.read_bytes()).hexdigest()
    if sha != KS1_KESIN_SHA256:
        raise SystemExit(f"{KS1_KESIN_YOLU}: sha256 {sha} (KS-1'deki {KS1_KESIN_SHA256} değil)")
    spec = importlib.util.spec_from_file_location("ks1_kesin_n4", kesin_yolu)
    kesin = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = kesin
    spec.loader.exec_module(kesin)
    birimler: dict[str, dict[str, list]] = {}
    for platform_adi, program, elf, sd in dizinler:
        r = kesin.extract_anchors(sd)
        liste = []
        for adres, c in sorted(r.anchors.items()):
            if kesin.TYPE_FUNC in c.types and c.role != kesin.ROLE_FRAGMENT:
                durum, fs = fiil_durumu(c.name)
                liste.append([adres, durum, fs])
        birimler.setdefault(f"{platform_adi}/{program}", {})[elf] = liste
    belge = {"kunye": {"betik": "docs/arge/2026-11-10_n4/on_sayim.py --capa-cikar",
                       "kesin_sha256": sha, "tur": kesin.TYPE_FUNC,
                       "not": "ad yazılmaz; adres + addaki fiil durumu ve sınıfı"},
             "birimler": birimler}
    yol.expanduser().write_text(json.dumps(belge, ensure_ascii=False, indent=1) + "\n",
                                encoding="utf-8")
    for u, e in sorted(birimler.items()):
        print(f"{u:<22}{sum(len(v) for v in e.values()):>6}")
    return 0


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
    ap.add_argument("--cikti", type=Path)
    ap.add_argument("--en-sik", type=int, default=25, help="birim başına listelenecek import sayısı")
    ap.add_argument("--capa-cikar", type=Path,
                    help="KS-1 func_kalibi çapalarını kesin.py ile çıkar, bu dosyaya yaz ve çık")
    ap.add_argument("--capalar", type=Path, help="--capa-cikar çıktısı; çapa nüfusunu ekler")
    ap.add_argument("--ornekler", type=Path,
                    help="elle okuma örnekleri (adresli; depo dışına yazılmalı)")
    args = ap.parse_args()
    if args.cikti is None and args.capa_cikar is None:
        ap.error("--cikti ya da --capa-cikar gerekli")

    dizinler = static_dizinleri(args.mac_kosu.expanduser(), args.debian_kosu.expanduser())
    bulunan = Counter(f"{p}/{program}" for p, program, _, _ in dizinler)
    for birim in sorted(set(BEKLENEN_ELF) | set(bulunan)):
        if bulunan.get(birim, 0) != BEKLENEN_ELF.get(birim, 0):
            raise SystemExit(f"{birim}: {bulunan.get(birim, 0)} ELF bulundu, "
                             f"{BEKLENEN_ELF.get(birim, 0)} bekleniyordu (eksik koşu ölçülmez)")
    if args.capa_cikar is not None:
        return capa_cikar(dizinler, args.capa_cikar)

    capa_verisi: dict = {}
    capa_kunye = None
    if args.capalar is not None:
        capa_ham = args.capalar.expanduser().read_bytes()
        capa_belge = json.loads(capa_ham)
        capa_verisi = capa_belge["birimler"]
        capa_kunye = {"dosya": ev_kisalt(args.capalar),
                      "sha256": hashlib.sha256(capa_ham).hexdigest(),
                      "kesin_sha256": capa_belge["kunye"]["kesin_sha256"],
                      "tur": capa_belge["kunye"]["tur"],
                      "capa_sayisi": {u: sum(len(v) for v in e.values())
                                      for u, e in sorted(capa_verisi.items())}}

    birimler: dict[str, dict] = {}
    elfler: list[dict] = []
    ornek_havuzu: dict[str, list[tuple[str, str, str, int]]] = {}
    for platform_adi, program, elf, sd in dizinler:
        anahtar = f"{platform_adi}/{program}"
        capalar = None
        if args.capalar is not None:
            capalar = {int(a, 16): (d, s) for a, d, s in capa_verisi.get(anahtar, {}).get(elf, [])}
        r = elf_say(sd, capalar)
        if r["islemci"].upper() != "AARCH64":
            raise SystemExit(f"{sd}: işlemci {r['islemci']!r} (yalnız AArch64)")
        b = birimler.setdefault(anahtar, {
            "sayim": Counter(), "adli": Counter(), "df": Counter(),
            "imza": set(), "ham_import": set(), "adli_fiil": {}, "ozetler": [], "bicim": r["aile"],
            "n4": Counter(), "n4_ham": {}})
        b["n4"].update(r["n4"]["sayac"])
        for pop, liste in r["n4"]["ham"].items():
            b["n4_ham"].setdefault(pop, []).extend(liste)
        for olcu, adresler in r["n4"]["ornek"].items():
            ornek_havuzu.setdefault(olcu, []).extend((anahtar, elf, str(sd), a) for a in adresler)
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
            "n4": dict(sorted(b["n4"].items())),
            "n4_ortanca": {pop: ortanca_ozeti(liste) for pop, liste in sorted(b["n4_ham"].items())},
        }
        toplam.update(s)
    toplam_n4: Counter = Counter()
    tabaka: dict[str, Counter] = {}
    for anahtar in sorted(birimler):
        toplam_n4.update(birimler[anahtar]["n4"])
        for k, v in birimler[anahtar]["n4"].items():
            if k.startswith("bekleyen:") and (k.count(":") == 1 or k.startswith("bekleyen:ad_tekil:")):
                tabaka.setdefault(f"{anahtar.split('/')[0]}/{BOYUT_TABAKASI[anahtar]}",
                                  Counter())[k] += v
    olcum1 = {u: olcum1_hukum(cikti_birim[u]["n4"]) for u in sorted(cikti_birim)}
    olcum1["toplam"] = olcum1_hukum(toplam_n4)
    for t, sayac in sorted(tabaka.items()):
        olcum1[f"tabaka:{t}"] = olcum1_hukum(sayac)
    m1 = m1_temsil(cikti_birim)
    if args.ornekler is not None:
        ornekleri_yaz(ornek_havuzu, args.ornekler.expanduser())

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
            "n4": {
                "belge": "docs/arge/2026-11-10_n4/on_olcum_gt_siz.md",
                "tanimlar": N4_TANIMLAR,
                "ayirici": sorted(AYIRICI), "buyutucu": sorted(BUYUTUCU),
                "birakici": sorted(BIRAKICI), "donmez_derleyici": sorted(DONMEZ_DERLEYICI),
                "salt_okur": sorted(SALT_OKUR),
                "cagri_dilimleri": [ad for _, ad in CAGRI_DILIMLERI],
                "deger_siniri": DEGER_SINIRI, "tur_siniri": TUR_SINIRI,
                "nufuslar": {
                    "bekleyen": "sürüm 1'in isim_bekleyen nüfusu",
                    "export": "sürüm 1'in export tanımı (adli.export); örnek düzeyinde",
                    "export_tek": "export ve adı tek fiil sınıfı taşıyor (M1'in evreni)",
                    "capa": "KS-1 func_kalibi çapası (parça değil); --capalar verilirse",
                    "capa_tek": "capa ve çapa adı tek fiil sınıfı taşıyor",
                },
                "anahtar_bicimi": "<nüfus>:<ölçü>[:<K|I|Y>|:komut_<dilim>]; elf:<sayaç> ELF düzeyi",
                "esikler": {"riskli_pay": RISK_ESIGI, "htop_create_destroy": HTOP_B4_ESIGI,
                            "oran_bandi": list(ORAN_BANDI),
                            "cagiransiz_puan": CAGIRANSIZ_PUAN_ESIGI},
                "boyut_tabakasi": BOYUT_TABAKASI,
                "capalar": capa_kunye,
            },
        },
        "birimler": cikti_birim,
        "toplam": dict(sorted(toplam.items())),
        "elfler": sorted(elfler, key=lambda e: (e["birim"], e["elf"])),
        "toplam_n4": dict(sorted(toplam_n4.items())),
        "n4_tabaka": {t: dict(sorted(c.items())) for t, c in sorted(tabaka.items())},
        "olcum1_hukum": olcum1,
        "m1_temsil": m1,
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
