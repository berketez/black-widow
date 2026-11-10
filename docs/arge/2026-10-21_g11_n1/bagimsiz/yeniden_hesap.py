#!/usr/bin/env python3
"""KS-1 adım 2 ölçümünün bağımsız yeniden hesabı (yalnız puanlama).

Amaç: ``ks1_olcum.json``'daki sayıları, ölçüm betiğinin puanlama kodu kullanılmadan, yalnız ön
kayıt belgelerindeki tanımlardan yeniden üretmek ve hücre hücre karşılaştırmak.

Tanımların kaynağı (her sabitin ve işlevin yanında bölüm numarası yazılı):
- ``ks1_onkayit.md`` (commit a22d833), §3-§9;
- ``ks1_sapma_1.md`` (commit 0da58cf), S1: ELF ofseti Ghidra'nın görüntü tabanından.

Bağımsızlık:
- ``ks1_olc.py``, ``function_f1.py``, ``macho_f1.py``, ``macho_measure.py`` ve ``test_ks1_olc.py``
  okunmadı, içe aktarılmadı. Sabitler bu yüzden bilerek burada, belgeden yeniden yazıldı.
- Çapalar ``kesin.py``'den (dosya yolundan yüklenir, ``extract_anchors``) gelir: sınanan çıkarıcı
  değil, puanlamadır.
- GT bu betikte kendi yolundan okunur: ELF'te dbgsym ``.debug`` dosyasının ``.symtab``'ı
  (pyelftools), Mac'te strip'siz özgün ikili üzerinde ``/usr/bin/nm``. Hazır ``*.gt.json`` yalnız
  karşılaştırma için açılır.

Çıktı (``yeniden_hesap.json``) fonksiyon adı içermez: yalnız sayılar, birim ve ikili adları,
adresler. ``--goz-ornegi`` kipi adları yalnız ekrana basar (dosyaya yazmaz).

Belgede tam verilmeyen tanımlar için seçilen yorumlar ``YORUMLAR`` listesindedir ve çıktıya
yazılır. Üç duyarlılık hesabı ayrıca verilir (``duyarlilik``): C++ işaretinin kaynağı, bayt bayt
aynı ikililerin tek sayılması, nüfus tanımının ölçümle uzlaştırılması.
"""

from __future__ import annotations

import argparse
import glob
import hashlib
import importlib.util
import json
import math
import random
import re
import struct
import subprocess
import sys
from collections import Counter, defaultdict
from fractions import Fraction
from pathlib import Path

sys.dont_write_bytecode = True  # kesin.py yüklenirken depoya .pyc yazılmasın

from elftools.elf.elffile import ELFFile  # noqa: E402

BURASI = Path(__file__).resolve().parent
DEPO = BURASI.parents[3]
EV = Path.home()

# ---------------------------------------------------------------------------------------------
# Tanımlar (ön kayıt bölüm numaralarıyla)

N_MIN = 10                      # §8 madde 2
EN_AZ_PROGRAM = 2               # §8 madde 3
ESIK = Fraction(95, 100)        # §8 madde 5; karşılaştırma kesirlerle
Z = 1.96                        # §8 madde 1

DIZGI_TUR_ADLARI = ("assert", "func_kalibi", "func_aktarma")              # §3.1-§3.3
KARAR_SATIR_ADLARI = ("assert", "assert_ust", "func_kalibi", "func_aktarma")  # §8
RAPOR_SATIR_ADLARI = ("export", "dizgi_turleri")                          # §8 "yalnız raporlananlar"
SATIRLAR = KARAR_SATIR_ADLARI + RAPOR_SATIR_ADLARI

# §7: birim başına beklenen ELF sayısı
BEKLENEN_ELF = {
    "mac/tmux": 1, "mac/htop": 1,
    "debian/tmux": 1, "debian/htop": 1, "debian/tree": 1, "debian/zstd": 2,
    "debian/redis-tools": 4, "debian/sqlite3": 1, "debian/openssl": 1, "debian/coreutils": 106,
}

# §6 "Klon satırı": derleyici ekleri, zincirleri dahil
DERLEYICI_EKI = r"\.(?:isra|constprop|part|cold|lto_priv|clone|llvm|__uniq)(?:\.\d+)*"
EKLI_AD_RE = re.compile(rf"^(?P<taban>.+?)(?:{DERLEYICI_EKI})+$")
OUTLINED_RE = re.compile(r"^OUTLINED_FUNCTION_\d+$")   # §6: tabanı yok
COLD_RE = re.compile(r"\.cold(?:\.\d+)*$")              # §7 Mac nüfusu: `cold` sınıfı

# §7 "C++ ikililer": içe aktarılan adın başlangıcı
CPP_ISARETLERI = ("_Z", "__gxx_personality", "__cxa_begin_catch", "__cxa_end_catch",
                  "__cxa_throw", "__cxa_rethrow")

# §5 K5: Ghidra'nın jenerik adları (belge önekleri veriyor)
JENERIK_ONEKLER = ("FUN_", "thunk_FUN_", "LAB_", "SUB_", "sub_")
JENERIK_TAM_RE = re.compile(r"^(?:entry|_INIT_\d+|_FINI_\d+)$")

# §7 ELF nüfusu "CRT ya da export değil": belge CRT'nin hangi fonksiyonlar olduğunu vermiyor
# (tanım, okunması yasak olan yardımcıda). Bu betiğin yorumu: C çalışma zamanı başlangıç kodu,
# yani crt1.o, crti.o/crtn.o ve crtbegin.o'nun fonksiyon simgeleri (giriş noktası, .init/.fini
# gövdeleri, zayıf simge çağrısı, TM klon kayıt/silme, global kurucu/yıkıcı yardımcıları, eski
# glibc'nin csu başlatıcıları, statik PIE yer değiştirmesi): 12 ad.
# Çıktılarda fonksiyon adı geçmesin diye liste ad olarak değil, adların sha256'sının ilk 16
# hanesi olarak tutulur; hiçbiri bir programın kendi adı değildir.
CRT_OZETLERI = frozenset({
    "19630376a90509eb", "3bbe887672235fd7", "4430e6d2c3807538", "4dc7c8aff21f4deb",
    "55dba8ca1648df0c", "586798338a5433fa", "7037683f4c0ddfba", "789b864acd6cc04b",
    "96e8e6647c1e830d", "a1fe4b08604a7101", "f3836790aa3747da", "f3e204c8c9c4417e",
})
# Uzlaştırma (yalnız duyarlılık; ilk karşılaştırmadaki nüfus farkını açıklayan iki ek):
#  1. libc_nonshared.a'dan ikiliye statik bağlanan çıkış işleyicisi kayıt sarmalayıcısı da CRT
#     sayılır (bir ad; yine özet olarak);
#  2. Ghidra'nın switch etiketi adı (caseD_N) da "ad bekleyen" sayılır.
UZLASTIRMA_CRT_OZETLERI = frozenset({"e07a84105c6827d5"})
UZLASTIRMA_JENERIK_RE = re.compile(r"^caseD_[0-9A-Fa-f]+$")

GOZ_TOHUMU = 20261110

YORUMLAR = [
    {"konu": "ELF GT'si", "belge": "§6 (function_f1.extract_gt'ye havale)",
     "yorum": "dbgsym .debug dosyasının .symtab'ındaki tanımlı (SHN_UNDEF olmayan) STT_FUNC "
              "simgeleri; aynı adresteki adlar takma ad. Boyut ya da bağlama süzgeci yok."},
    {"konu": "Mac GT'si", "belge": "§6 (macho_measure prepare'e havale)",
     "yorum": "özgün ikilide /usr/bin/nm -m; (__TEXT,__text) bölümünde tanımlı ve adresi "
              "__text bölümünün içinde olan simgeler (Mach-O başlığı simgesi bölüm dışındadır)."},
    {"konu": "derleyici eki", "belge": "§6 Klon satırı",
     "yorum": "ad, taban + bir ya da daha çok (.isra|.constprop|.part|.cold|.lto_priv|.clone|"
              ".llvm|.__uniq)(.N)* ekiyle bitiyorsa eklidir; taban ilk ekten önceki kısımdır. "
              "OUTLINED_FUNCTION_N eklidir, tabanı yoktur. Listede olmayan ekler (.localalias) "
              "ek sayılmaz."},
    {"konu": "klon satırında doğruluk", "belge": "§6",
     "yorum": "bütün takma adlar ekliyse: çapa adı takma adlardan birinin tabanına eşitse doğru."},
    {"konu": "parça çapasının doğruluğu", "belge": "§6 (ölçütü açık yazılmamış)",
     "yorum": "öbür çapalarla aynı ölçüt: ana satırda tam eşitlik, klon satırında taban eşitliği."},
    {"konu": "satır üyeliği", "belge": "§8, §4 Roller",
     "yorum": "assert: türü assert ve rolü kendi; assert_ust: türü assert ve rolü ust; "
              "func_kalibi/func_aktarma: o türü taşıyan, parça olmayan; export: türü export; "
              "dizgi_turleri: herhangi bir dizgi türünü taşıyan, parça olmayan (çapa başına bir). "
              "Parça (rol parca) ayrı sayılır: assert_ust ve dizgi_turleri satırlarında."},
    {"konu": "tekil öğe", "belge": "§7 [karar 16]",
     "yorum": "birim içinde (satır, ad); birimin bütün ELF'lerindeki örnekleri doğruysa doğru."},
    {"konu": "CRT fonksiyonları (ELF nüfusu)", "belge": "§7 (liste verilmemiş)",
     "yorum": "C çalışma zamanı başlangıç kodu (crt1.o, crti.o, crtbegin.o simgeleri; 12 ad, "
              "betikte özet olarak): takma adlarından biri listedeyse CRT. Yalnız kapsam "
              "paydasını etkiler."},
    {"konu": "ad bekleyen Ghidra fonksiyonu (nüfus)", "belge": "§7 'adı jenerik'; liste §5 K5",
     "yorum": "K5'teki jenerik ad listesi: FUN_, thunk_FUN_, LAB_, SUB_, sub_, entry, _INIT_N, "
              "_FINI_N. Yalnız kapsam paydasını etkiler."},
    {"konu": "Ghidra'nın `code` sınıfı (ELF nüfusu)", "belge": "§7 (tanım verilmemiş)",
     "yorum": "dış (is_external) olmayan ve adresi çalıştırılabilir, .plt ailesinden olmayan bir "
              "bellek bloğunda olan fonksiyon. Yalnız kapsam paydasını etkiler."},
    {"konu": "export GT'si (ELF)", "belge": "§7, §8",
     "yorum": "adresi strip'li ikilinin .dynsym'inde tanımlı bir FUNC/IFUNC simgesinin adresi "
              "olan GT fonksiyonu (adres düzeyinde)."},
    {"konu": "Mac sınıfı", "belge": "§7 (macho_f1.fragment_class'a havale)",
     "yorum": "bütün adları OUTLINED_FUNCTION_N ise outlined; bütün adları .cold(.N) ile "
              "bitiyorsa cold; yoksa program."},
    {"konu": "C++ işareti", "belge": "§7",
     "yorum": "belge işaretleri Ghidra'nın verdiği adlar üzerinden anlatıyor: Ghidra'nın thunk ya "
              "da dış fonksiyon adları (Mach-O'da baştaki tek _ soyulur). İkilinin kendi içe "
              "aktarma tablosu (.dynsym tanımsızları; nm -u) duyarlılık olarak ayrıca hesaplanır."},
    {"konu": "C++ ikilinin nüfusu", "belge": "§7 'kesinlik dışı, GT'siz sayılır'",
     "yorum": "C++ ikili kesinliğe de kapsam paydasına da girmez."},
    {"konu": "havuz", "belge": "§8 madde 6",
     "yorum": "satırın bütün birimleri (küçükler dahil) üzerinden Σ doğru / Σ n."},
]

# ---------------------------------------------------------------------------------------------
# Yardımcılar


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def kisa_yol(path: Path | str) -> str:
    """Çıktıya yazılan yol: depo ya da ev dizinine göre."""
    p = Path(path)
    for kok, on in ((DEPO, ""), (EV, "~/")):
        try:
            return on + str(p.resolve().relative_to(kok.resolve()))
        except ValueError:
            continue
    return str(p)


def wilson(k: int, n: int) -> tuple[float, float] | None:
    """Wilson %95 aralığı (§8 madde 1, z = 1,96)."""
    if n == 0:
        return None
    p = k / n
    payda = 1 + Z * Z / n
    merkez = (p + Z * Z / (2 * n)) / payda
    yari = Z * math.sqrt(p * (1 - p) / n + Z * Z / (4 * n * n)) / payda
    return (max(0.0, merkez - yari), min(1.0, merkez + yari))


def oran_kaydi(k: int, n: int) -> dict:
    w = wilson(k, n)
    return {"dogru": k, "n": n, "oran": None if n == 0 else round(k / n, 6),
            "aralik": None if w is None else [round(w[0], 4), round(w[1], 4)]}


def load_kesin(path: Path):
    spec = importlib.util.spec_from_file_location("kesin_bagimsiz", str(path))
    mod = importlib.util.module_from_spec(spec)
    sys.modules["kesin_bagimsiz"] = mod
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------------------------
# Ad karşılaştırması (§6)


def derleyici_eki(ad: str) -> tuple[bool, str | None]:
    """(ekli mi, taban). OUTLINED_FUNCTION_N eklidir, tabanı yoktur."""
    if OUTLINED_RE.match(ad):
        return True, None
    m = EKLI_AD_RE.match(ad)
    if m:
        return True, m.group("taban")
    return False, None


def hepsi_ekli(adlar: frozenset[str]) -> bool:
    return bool(adlar) and all(derleyici_eki(a)[0] for a in adlar)


def hukum(capa_adi: str, gt_adlari: frozenset[str] | None) -> tuple[str, bool]:
    """(sınıf, doğru). Sınıf: ``ana`` (tam eşitlik), ``klon`` (taban eşitliği),
    ``eslenemeyen`` (adreste GT fonksiyonu yok; yanlış)."""
    if not gt_adlari:
        return "eslenemeyen", False
    if hepsi_ekli(gt_adlari):
        tabanlar = {derleyici_eki(a)[1] for a in gt_adlari} - {None}
        return "klon", capa_adi in tabanlar
    return "ana", capa_adi in gt_adlari


def jenerik_ad(ad: str, uzlastirma: bool = False) -> bool:
    """§5 K5: Ghidra'nın yer tutucu adı."""
    if ad.startswith(JENERIK_ONEKLER) or bool(JENERIK_TAM_RE.match(ad)):
        return True
    return uzlastirma and bool(UZLASTIRMA_JENERIK_RE.match(ad))


def ad_ozeti(ad: str) -> str:
    return hashlib.sha256(ad.encode("utf-8")).hexdigest()[:16]


def crt_mi(adlar: frozenset[str], ozetler: frozenset[str]) -> bool:
    """Takma adlarından biri CRT listesinde mi (liste özet olarak tutulur)."""
    return any(ad_ozeti(a) in ozetler for a in adlar)


def cpp_mi(adlar: set[str]) -> bool:
    """§7: içe aktarılan adlardan biri işaretlerden biriyle başlıyor."""
    return any(a.startswith(CPP_ISARETLERI) for a in adlar)


# ---------------------------------------------------------------------------------------------
# Ghidra çıktısı (static/)


def read_ghidra(static: Path) -> dict:
    fdoc = json.loads((static / "ghidra_functions.json").read_text(encoding="utf-8"))
    funcs: dict[int, dict] = {}
    yinelenen = 0
    for f in fdoc.get("functions", []):
        try:
            a = int(str(f.get("address", "")), 16)
        except ValueError:
            continue
        if a in funcs:
            yinelenen += 1
            continue
        funcs[a] = {"ad": str(f.get("name") or ""), "thunk": bool(f.get("is_thunk")),
                    "dis": bool(f.get("is_external")), "kaynak": str(f.get("source") or "")}
    info = json.loads((static / "ghidra_combined_results.json").read_text(encoding="utf-8")).get(
        "program_info") or {}
    bloklar = []
    for b in info.get("memory_blocks", []):
        try:
            bloklar.append((int(b["start"], 16), int(b["end"], 16), str(b.get("name") or ""),
                            str(b.get("permissions") or "")))
        except (ValueError, KeyError):
            continue   # yüklenmeyen bölümler: ".shstrtab::00000000"
    taban = info.get("image_base")
    return {"fonksiyonlar": funcs, "yinelenen_adres": yinelenen, "bloklar": bloklar,
            "goruntu_tabani": None if taban in (None, "") else int(str(taban), 16),
            "bicim": str(info.get("executable_format") or "")}


def blok_of(g: dict, adres: int) -> tuple[str, str] | None:
    for bas, son, ad, izin in g["bloklar"]:
        if bas <= adres <= son:
            return ad, izin
    return None


def kod_sinifi(g: dict, adres: int, f: dict, varyant: str = "varsayilan") -> bool:
    """§7 ELF nüfusu: Ghidra'nın ``code`` sınıfı (belgede tanımsız; yorum YORUMLAR'da)."""
    if varyant == "kosulsuz":
        return True
    if f["dis"]:
        return False
    b = blok_of(g, adres)
    if b is None:
        return False
    ad, izin = b
    if varyant == "yalniz_text":
        return ad == ".text"
    return "x" in izin and not ad.startswith(".plt")


SNAKE_RE = re.compile(r"^[a-z][a-z0-9]*(?:_[a-z0-9]+)+$")   # §9 dizgi zenginliği
ZENGINLIK_ESIGI = 0.05                                       # §9 [karar 22]


def sinif_sayimi(static: Path, g: dict) -> dict:
    """§9 program sınıfı (GT'siz): iç fonksiyon (thunk ve dış olmayan) ve snake_case dizgi
    (``ghidra_strings.json`` girdisi, adres başına) sayıları."""
    sdoc = json.loads((static / "ghidra_strings.json").read_text(encoding="utf-8"))
    adresler = {str(s.get("address")) for s in sdoc.get("strings", [])
                if isinstance(s.get("value"), str) and SNAKE_RE.match(s["value"])}
    ic = sum(1 for f in g["fonksiyonlar"].values() if not f["thunk"] and not f["dis"])
    return {"ic_fonksiyon": ic, "snake_dizgi": len(adresler)}


def sinif_ozeti(kayitlar: list[dict]) -> dict:
    """§9: birim başına dizgi zenginliği ve sınıfı, ELF ortancası ve boyut tabakası."""
    out = {}
    for u in sorted(BEKLENEN_ELF):
        ks = [k["sinif"] for k in kayitlar if k["birim"] == u]
        ic = sum(k["ic_fonksiyon"] for k in ks)
        snake = sum(k["snake_dizgi"] for k in ks)
        sirali = sorted(k["ic_fonksiyon"] for k in ks)
        n = len(sirali)
        ortanca = sirali[n // 2] if n % 2 else (sirali[n // 2 - 1] + sirali[n // 2]) / 2
        out[u] = {"elf": n, "ic_fonksiyon": ic, "snake_dizgi": snake,
                  "dizgi_zenginligi": round(snake / ic, 6),
                  "zenginlik_sinifi": "zengin"
                  if Fraction(snake, ic) >= Fraction(str(ZENGINLIK_ESIGI)) else "yoksul",
                  "ic_fonksiyon_ortanca": float(ortanca),
                  "boyut_tabakasi": "kucuk" if ortanca < 500 else "orta" if ortanca < 2000
                  else "buyuk"}
    return out


def ghidra_ice_aktarilan(g: dict, macho: bool) -> set[str]:
    """Ghidra'nın içe aktarılan adları: thunk ya da dış fonksiyonların adları (§7)."""
    adlar = set()
    for f in g["fonksiyonlar"].values():
        if f["thunk"] or f["dis"]:
            adlar.add(f["ad"][1:] if macho and f["ad"].startswith("_") else f["ad"])
    return adlar


# ---------------------------------------------------------------------------------------------
# ELF


def read_elf_binary(path: Path) -> dict:
    """Analiz edilen (strip'li) ikili: build-id, yükleme adresi, giriş, dışa/içe aktarılanlar."""
    with open(path, "rb") as fh:
        e = ELFFile(fh)
        build_id = None
        sec = e.get_section_by_name(".note.gnu.build-id")
        if sec is not None:
            for note in sec.iter_notes():
                if note["n_type"] == "NT_GNU_BUILD_ID":
                    build_id = note["n_desc"]
        yuklemeler = [s["p_vaddr"] for s in e.iter_segments() if s["p_type"] == "PT_LOAD"]
        export: dict[int, set[str]] = defaultdict(set)
        ice_aktarilan: set[str] = set()
        dyn = e.get_section_by_name(".dynsym")
        if dyn is not None:
            for s in dyn.iter_symbols():
                if not s.name:
                    continue
                if s["st_shndx"] == "SHN_UNDEF":
                    ice_aktarilan.add(s.name)
                elif s["st_info"]["type"] in ("STT_FUNC", "STT_GNU_IFUNC"):
                    export[s["st_value"]].add(s.name)
        return {"build_id": build_id, "en_dusuk_yukleme": min(yuklemeler),
                "giris": e["e_entry"], "tur": e["e_type"], "export": dict(export),
                "ice_aktarilan": ice_aktarilan,
                "symtab_var": e.get_section_by_name(".symtab") is not None}


def read_elf_gt(debug: Path) -> tuple[dict[int, frozenset[str]], str | None]:
    """dbgsym ``.debug`` dosyasının ``.symtab``'ı: adres → takma adlar (§6 GT, ELF)."""
    by: dict[int, set[str]] = defaultdict(set)
    with open(debug, "rb") as fh:
        e = ELFFile(fh)
        build_id = None
        sec = e.get_section_by_name(".note.gnu.build-id")
        if sec is not None and sec["sh_type"] == "SHT_NOTE":
            for note in sec.iter_notes():
                if note["n_type"] == "NT_GNU_BUILD_ID":
                    build_id = note["n_desc"]
        st = e.get_section_by_name(".symtab")
        if st is None:
            raise RuntimeError(f"{debug}: .symtab yok")
        for s in st.iter_symbols():
            if s["st_info"]["type"] == "STT_FUNC" and s["st_shndx"] != "SHN_UNDEF" and s.name:
                by[s["st_value"]].add(s.name)
    return {a: frozenset(n) for a, n in by.items()}, build_id


def find_debug(indirme: Path, build_id: str) -> Path:
    """§6: ``x_*-dbgsym_*/usr/lib/debug/.build-id/`` altında build-id'yle; tam bir tane."""
    hits = sorted(glob.glob(str(indirme / "x_*-dbgsym_*" / "usr" / "lib" / "debug" / ".build-id"
                                / build_id[:2] / f"{build_id[2:]}.debug")))
    if len(hits) != 1:
        raise RuntimeError(f"build-id {build_id}: {len(hits)} hata ayıklama dosyası")
    return Path(hits[0])


# ---------------------------------------------------------------------------------------------
# Mach-O


def macho_text(path: Path) -> dict:
    """64 bit ince Mach-O'da (__TEXT,__text) bölümünün adresi, boyutu ve içeriğinin sha256'sı."""
    data = Path(path).read_bytes()
    magic, _cpu, _sub, _ft, ncmds, _sz, _fl, _res = struct.unpack_from("<IiiIIIII", data, 0)
    if magic != 0xFEEDFACF:
        raise RuntimeError(f"{path}: 64 bit ince Mach-O değil")
    off = 32
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", data, off)
        if cmd == 0x19:  # LC_SEGMENT_64
            nsects = struct.unpack_from("<I", data, off + 64)[0]
            so = off + 72
            for _s in range(nsects):
                sect, seg, addr, size, foff = struct.unpack_from("<16s16sQQI", data, so)
                if sect.rstrip(b"\0") == b"__text" and seg.rstrip(b"\0") == b"__TEXT":
                    return {"adres": addr, "boyut": size,
                            "sha256": hashlib.sha256(data[foff:foff + size]).hexdigest()}
                so += 80
        off += cmdsize
    raise RuntimeError(f"{path}: __text bölümü yok")


NM_SATIRI = re.compile(r"^([0-9a-f]{16}) \(([^)]*)\) (.*?) ?(\S+)$")


def read_macho_gt(orig: Path, text: dict) -> dict[int, frozenset[str]]:
    """Özgün (strip'siz) ikilide nm: adres → takma adlar; baştaki tek ``_`` soyulur (§6)."""
    out = subprocess.run(["/usr/bin/nm", "-n", "-m", str(orig)], capture_output=True, text=True,
                         check=True).stdout
    by: dict[int, set[str]] = defaultdict(set)
    for line in out.splitlines():
        m = NM_SATIRI.match(line)
        if not m or m.group(2) != "__TEXT,__text":
            continue
        a = int(m.group(1), 16)
        if not text["adres"] <= a < text["adres"] + text["boyut"]:
            continue   # Mach-O başlığı simgesi: bölümün dışında
        ad = m.group(4)
        by[a].add(ad[1:] if ad.startswith("_") else ad)
    return {a: frozenset(n) for a, n in by.items()}


def macho_imports(path: Path) -> set[str]:
    out = subprocess.run(["/usr/bin/nm", "-u", str(path)], capture_output=True, text=True,
                         check=True).stdout
    adlar = set()
    for line in out.splitlines():
        ad = line.strip().split(" ")[0]
        if ad:
            adlar.add(ad[1:] if ad.startswith("_") else ad)
    return adlar


def macho_sinifi(adlar: frozenset[str]) -> str:
    if all(OUTLINED_RE.match(a) for a in adlar):
        return "outlined"
    if all(COLD_RE.search(a) for a in adlar):
        return "cold"
    return "program"


# ---------------------------------------------------------------------------------------------
# Keşif (§7 Nüfus)


def kesfet(mac_kosu: Path, debian_kosu: Path) -> list[dict]:
    out = []
    for prog_dir in sorted(p for p in mac_kosu.iterdir() if p.is_dir()):
        statics = sorted(prog_dir.glob("ws/workspaces/*/*/static"))
        if len(statics) != 1:
            raise RuntimeError(f"{prog_dir}: {len(statics)} static dizini")
        out.append({"birim": f"mac/{prog_dir.name}", "program": prog_dir.name,
                    "elf": prog_dir.name, "platform": "mac", "static": statics[0], "bitti": True})
    for prog_dir in sorted(p for p in debian_kosu.iterdir() if p.is_dir()):
        for elf_dir in sorted(p for p in prog_dir.iterdir() if p.is_dir()):
            statics = sorted(elf_dir.glob("ws/workspaces/*/*/static"))
            if len(statics) != 1:
                raise RuntimeError(f"{elf_dir}: {len(statics)} static dizini")
            out.append({"birim": f"debian/{prog_dir.name}", "program": prog_dir.name,
                        "elf": elf_dir.name, "platform": "debian", "static": statics[0],
                        "bitti": (elf_dir / "BITTI").is_file()})
    return out


# ---------------------------------------------------------------------------------------------
# İkili başına: GT, nüfus, çapaların hükmü


def capalari_al(kesin, static: Path, onbellek: Path | None, anahtar: str) -> list[dict]:
    """``kesin.extract_anchors``: adres, ad, türler, rol. Önbellek (ad içerir) yalnız geçici
    dizinde tutulur; depoya yazılmaz."""
    dosya = None if onbellek is None else onbellek / f"{anahtar}.json"
    if dosya is not None and dosya.is_file():
        return json.loads(dosya.read_text(encoding="utf-8"))
    sonuc = kesin.extract_anchors(static)
    capalar = [{"adres": int(a.address, 16), "ad": a.name, "turler": list(a.types), "rol": a.role,
                "kanit_rolleri": sorted({e.role for e in a.evidence})}
               for a in sonuc.anchors.values()]
    if dosya is not None:
        dosya.write_text(json.dumps(capalar), encoding="utf-8")
    return capalar


def elf_gt(ikili: Path, g: dict, indirme: Path) -> dict:
    den = Counter()
    b = read_elf_binary(ikili)
    den["elf_strip_li"] += int(not b["symtab_var"])
    debug = find_debug(indirme, b["build_id"])
    gt_dosya, debug_bid = read_elf_gt(debug)
    den["elf_debug_build_id_ayni"] += int(debug_bid == b["build_id"])
    # Sapma kaydı S1: ofset = görüntü tabanı − en düşük PT_LOAD; iki çapraz denetim
    if g["goruntu_tabani"] is None:
        raise RuntimeError(f"{ikili}: görüntü tabanı kayıtlı değil")
    ofset = g["goruntu_tabani"] - b["en_dusuk_yukleme"]
    kaynak = "goruntu_tabani"
    entry = [a for a, f in g["fonksiyonlar"].items() if f["ad"] == "entry"]
    if entry:
        if len(entry) != 1 or entry[0] - b["giris"] != ofset:
            raise RuntimeError(f"{ikili}: entry'den türetilen ofset görüntü tabanıyla çelişiyor")
        kaynak = "goruntu_tabani+ghidra_entry"
    if b["giris"] != 0 and ofset + b["giris"] not in g["fonksiyonlar"]:
        raise RuntimeError(f"{ikili}: giriş adresinde Ghidra fonksiyonu yok")
    gt = {a + ofset: adlar for a, adlar in gt_dosya.items()}
    # Adres eşlemesinin bağımsız sağlaması: giriş adresinde ve dışa aktarılan her adreste GT
    # fonksiyonu var mı; dışa aktarılan ad GT'nin o adresteki adlarından biri mi?
    if b["giris"] != 0:
        den["elf_giris_adresinde_gt_var"] += int(ofset + b["giris"] in gt)
        den["elf_giris_adresli"] += 1
    for a, adlar in b["export"].items():
        den["elf_export_simgesi"] += 1
        den["elf_export_simgesi_gt_ile_ayni_ad"] += int(bool(adlar & gt.get(a + ofset, frozenset())))
    export_gt = {a for a in gt if a - ofset in b["export"]}

    def nufus(crt: frozenset[str] = CRT_OZETLERI, kod: str = "varsayilan",
              uzlastirma: bool = False) -> set[int]:
        """§7 ad bekleyen nüfus (ELF)."""
        out = set()
        for a, adlar in gt.items():
            if crt_mi(adlar, crt) or a in export_gt:
                continue
            f = g["fonksiyonlar"].get(a)
            if f is None or f["thunk"] or not jenerik_ad(f["ad"], uzlastirma):
                continue
            if not kod_sinifi(g, a, f, kod) or hepsi_ekli(adlar):
                continue
            out.add(a)
        return out

    return {"gt": gt, "nufus": nufus(), "export_gt": export_gt,
            "nufus_uzlastirma": nufus(crt=CRT_OZETLERI | UZLASTIRMA_CRT_OZETLERI,
                                      uzlastirma=True),
            "nufus_varyantlari": {"crt_dahil": len(nufus(crt=frozenset())),
                                  "kod_kosulsuz": len(nufus(kod="kosulsuz")),
                                  "kod_yalniz_text": len(nufus(kod="yalniz_text"))},
            "ice_aktarilan": b["ice_aktarilan"], "denetim": den,
            "gt_mangled": {a for a, adlar in gt.items() if any(x.startswith("_Z") for x in adlar)},
            "kunye": {"debug": kisa_yol(debug), "ofset": hex(ofset), "ofset_kaynagi": kaynak,
                      "gt_fonksiyon": len(gt)}}


def mac_gt(ikili: Path, g: dict, corpus: Path, p: str, hedef: dict) -> dict:
    ozgun = corpus / p / "orig" / p
    den = Counter()
    t_ozgun, t_ikili = macho_text(ozgun), macho_text(ikili)
    den["mac_text_bolumu_ayni"] += int(t_ozgun == t_ikili)   # adres, boyut ve içerik
    gt = read_macho_gt(ozgun, t_ozgun)   # Mac'te Ghidra adresi = VM adresi (§6)
    # Hazır GT dosyası: yalnız karşılaştırma
    hazir = json.loads((corpus / p / "gt" / f"{p}.gt.json").read_text(encoding="utf-8"))
    hazir_gt = {int(f["addr"], 16): frozenset(n[1:] if n.startswith("_") else n
                                              for n in f["names"]) for f in hazir["functions"]}
    den["mac_hazir_gt_ayni"] += int(hazir_gt == gt)
    den["mac_hazir_gt_strip_sha_ayni"] += int(hazir.get("stripped_sha256") == hedef.get("file_hash"))
    den["mac_hazir_gt_ozgun_sha_ayni"] += int(hazir.get("orig_sha256") == sha256_of(ozgun))
    den["mac_hazir_gt_sinif_ayni"] += int(all(
        macho_sinifi(gt[int(f["addr"], 16)]) == f.get("sinif") for f in hazir["functions"]
        if int(f["addr"], 16) in gt))

    def nufus(uzlastirma: bool = False) -> set[int]:
        """§7 ad bekleyen nüfus (Mac)."""
        out = set()
        for a, adlar in gt.items():
            f = g["fonksiyonlar"].get(a)
            if f is None or f["thunk"] or not jenerik_ad(f["ad"], uzlastirma):
                continue
            if macho_sinifi(adlar) != "program" or hepsi_ekli(adlar):
                continue
            out.add(a)
        return out

    return {"gt": gt, "nufus": nufus(), "export_gt": set(), "nufus_uzlastirma": nufus(True),
            "nufus_varyantlari": {}, "ice_aktarilan": macho_imports(ikili), "denetim": den,
            "gt_mangled": {a for a, adlar in gt.items() if any(x.startswith("_Z") for x in adlar)},
            "kunye": {"gt_kaynagi": kisa_yol(ozgun), "gt_fonksiyon": len(gt)}}


def ikilileri_isle(args) -> tuple[list[dict], Counter, dict]:
    """Her ikili için: çapalar, GT, hüküm, nüfus. C++ (Ghidra adlarıyla) ikilide GT okunmaz."""
    kesin_yolu = Path(args.kesin)
    kesin = load_kesin(kesin_yolu)
    onbellek = Path(args.onbellek) if args.onbellek else None
    if onbellek is not None:
        onbellek.mkdir(parents=True, exist_ok=True)
    kayitlar = kesfet(Path(args.mac_kosu), Path(args.debian_kosu))
    bulunan = Counter(k["birim"] for k in kayitlar)
    biten = Counter(k["birim"] for k in kayitlar if k["bitti"])
    if dict(bulunan) != BEKLENEN_ELF or dict(biten) != BEKLENEN_ELF:
        raise RuntimeError(f"nüfus eksik ya da fazla: bulunan {dict(bulunan)}")
    denetim = Counter()
    for k in kayitlar:
        macho = k["platform"] == "mac"
        g = read_ghidra(k["static"])
        hedef = json.loads((k["static"].parent / "raw" / "target_info.json").read_text(
            encoding="utf-8"))
        ikili = Path(hedef["path"])
        k["sha256"] = sha256_of(ikili)
        denetim["ikili"] += 1
        denetim["ikili_sha256_kunyeyle_ayni"] += int(k["sha256"] == hedef.get("file_hash"))
        denetim["ghidra_yinelenen_adres"] += g["yinelenen_adres"]
        # Jenerik ad tanımı (belge önekleri) ile çıkarıcının tanımı aynı kümeyi mi veriyor?
        denetim["jenerik_tanim_farki"] += sum(
            jenerik_ad(f["ad"]) != kesin.is_generic_name(f["ad"])
            for f in g["fonksiyonlar"].values())
        k["sinif"] = sinif_sayimi(k["static"], g)
        k["capalar"] = capalari_al(kesin, k["static"], onbellek,
                                   f'{k["birim"].replace("/", "_")}__{k["elf"]}')
        k["cpp_ghidra"] = cpp_mi(ghidra_ice_aktarilan(g, macho))
        if k["cpp_ghidra"]:
            # §7: GT'siz sayılır. İçe aktarma tablosu yine de okunur (yalnız C++ işareti için).
            k["cpp_ikili"] = cpp_mi(macho_imports(ikili) if macho
                                    else read_elf_binary(ikili)["ice_aktarilan"])
            k["veri"] = None
            continue
        veri = (mac_gt(ikili, g, Path(args.mac_corpus), k["program"], hedef) if macho
                else elf_gt(ikili, g, Path(args.debian_indirme)))
        denetim.update(veri["denetim"])
        k["cpp_ikili"] = cpp_mi(veri["ice_aktarilan"])
        gt = veri["gt"]
        for c in k["capalar"]:
            adlar = gt.get(c["adres"])
            sinif, dogru = hukum(c["ad"], adlar)
            c.update({"birim": k["birim"], "elf": k["elf"], "sinif": sinif, "dogru": dogru,
                      "nufusta": c["adres"] in veri["nufus"],
                      "nufusta_uzlastirma": c["adres"] in veri["nufus_uzlastirma"],
                      "export_gt": c["adres"] in veri["export_gt"],
                      "gt_adlari": sorted(adlar) if adlar else []})
            if c["rol"] == "ust" and c["turler"] != ["assert"]:
                denetim["ust_rolde_assert_disi_tur"] += 1
            if c["rol"] != "parca" and len(c["kanit_rolleri"]) > 1:
                denetim["karisik_kanit_rollu_capa"] += 1
        k["veri"] = veri
    girdi = {"kesin": kisa_yol(kesin_yolu), "kesin_sha256": sha256_of(kesin_yolu),
             "ks1_surumu": getattr(kesin, "KS1_VERSION", None),
             "mac_kosu": kisa_yol(args.mac_kosu), "mac_corpus": kisa_yol(args.mac_corpus),
             "debian_kosu": kisa_yol(args.debian_kosu),
             "debian_indirme": kisa_yol(args.debian_indirme), "python": sys.version.split()[0],
             "bulunan": dict(sorted(bulunan.items())), "beklenen": BEKLENEN_ELF}
    return kayitlar, denetim, girdi


# ---------------------------------------------------------------------------------------------
# Satırlar ve sayım (§6-§9)


def satirlari(turler: list[str], rol: str) -> list[str]:
    """Parça olmayan çapanın girdiği satırlar (§8)."""
    out = []
    if "assert" in turler:
        out.append("assert" if rol == "kendi" else "assert_ust")
    for t in ("func_kalibi", "func_aktarma", "export"):
        if t in turler:
            out.append(t)
    if any(t in turler for t in DIZGI_TUR_ADLARI):
        out.append("dizgi_turleri")
    return out


def tekil_say(capalar: list[dict]) -> tuple[int, int]:
    """(doğru, n): ad başına bir öğe; bütün örnekleri doğruysa doğru (§7 [karar 16])."""
    by: dict[str, bool] = {}
    for c in capalar:
        by[c["ad"]] = by.get(c["ad"], True) and c["dogru"]
    return sum(by.values()), len(by)


def ornek_say(capalar: list[dict]) -> tuple[int, int]:
    return sum(c["dogru"] for c in capalar), len(capalar)


def satir_ozeti(satir: str, capalar: list[dict], parcalar: list[dict], nufus: int,
                export_gt: int, nufus_alani: str) -> dict:
    tk, tn = tekil_say(capalar)
    ok, on = ornek_say(capalar)
    ana = [c for c in capalar if c["sinif"] == "ana"]
    klon = [c for c in capalar if c["sinif"] == "klon"]
    tek = [c for c in capalar if len(c["turler"]) == 1]
    ak, an = tekil_say(ana)
    ek, en = tekil_say(tek)
    if satir == "export":   # §8: pay ve payda dışa aktarılan GT
        payda = export_gt
        icinde = [c for c in capalar if c["export_gt"]]
    else:                   # §9: nüfusta çapalanan / nüfus (örnek düzeyi)
        payda = nufus
        icinde = [c for c in capalar if c[nufus_alani]]
    return {
        "tekil": oran_kaydi(tk, tn),
        "ornek": oran_kaydi(ok, on),
        "yalniz_ana": {"dogru": ak, "n": an},
        "tek_turlu": {"dogru": ek, "n": en},
        "klon": {"dogru": sum(c["dogru"] for c in klon), "n": len(klon)},
        "eslenemeyen": sum(c["sinif"] == "eslenemeyen" for c in capalar),
        "parca": {"dogru": sum(c["dogru"] for c in parcalar), "n": len(parcalar)},
        "kapsam": {"nufus": payda, "pay": len(icinde),
                   "dogru_pay": sum(c["dogru"] for c in icinde),
                   "oran": None if payda == 0 else round(len(icinde) / payda, 6)},
    }


def topla(kayitlar: list[dict], cpp_alani: str = "cpp_ghidra", nufus_alani: str = "nufus",
          yinelenen_tek: bool = False) -> dict:
    """Birim × satır sayımı. ``cpp_alani``: C++ işaretinin kaynağı; ``nufus_alani``: nüfus
    tanımı; ``yinelenen_tek``: birim içinde bayt bayt aynı ikililerden yalnız ilki sayılır."""
    capa_alani = "nufusta" if nufus_alani == "nufus" else "nufusta_uzlastirma"
    birimler: dict[str, dict] = {u: {"elfler": {}, "cpp_disarida": [], "yinelenen_disarida": [],
                                     "nufus": 0, "export_gt": 0,
                                     "nufus_varyantlari": Counter(), "_capalar": []}
                                 for u in sorted(BEKLENEN_ELF)}
    gorulen: set[tuple[str, str]] = set()
    for k in kayitlar:
        b = birimler[k["birim"]]
        if k[cpp_alani] or k["veri"] is None:
            b["cpp_disarida"].append(k["elf"])
            continue
        if yinelenen_tek and (k["birim"], k["sha256"]) in gorulen:
            b["yinelenen_disarida"].append(k["elf"])
            continue
        gorulen.add((k["birim"], k["sha256"]))
        veri = k["veri"]
        b["_capalar"].extend(k["capalar"])
        b["elfler"][k["elf"]] = {"capa": len(k["capalar"]), "nufus": len(veri[nufus_alani]),
                                 "kunye": veri["kunye"]}
        b["nufus"] += len(veri[nufus_alani])
        b["export_gt"] += len(veri["export_gt"])
        b["nufus_varyantlari"].update(veri["nufus_varyantlari"])
    for b in birimler.values():
        capalar = b.pop("_capalar")
        parcalar = [c for c in capalar if c["rol"] == "parca"]
        govde = [c for c in capalar if c["rol"] != "parca"]
        b["satirlar"] = {}
        for s in SATIRLAR:
            uye = [c for c in govde if s in satirlari(c["turler"], c["rol"])]
            if s == "assert_ust":
                parca = [c for c in parcalar if "assert" in c["turler"]]
            elif s == "dizgi_turleri":
                parca = parcalar
            else:
                parca = []
            b["satirlar"][s] = satir_ozeti(s, uye, parca, b["nufus"], b["export_gt"], capa_alani)
        b["nufus_varyantlari"] = dict(sorted(b["nufus_varyantlari"].items()))
        b["cpp_disarida"] = sorted(b["cpp_disarida"])
    return birimler


def karar_ver(birimler: dict) -> dict:
    """§8 karar kuralı."""
    out = {}
    for satir in KARAR_SATIR_ADLARI:
        sayim = {u: b["satirlar"][satir] for u, b in sorted(birimler.items())}
        giren = [u for u, s in sayim.items() if s["tekil"]["n"] >= N_MIN]
        kucuk = [u for u, s in sayim.items() if 0 < s["tekil"]["n"] < N_MIN]
        programlar = sorted({u.split("/", 1)[1] for u in giren})
        gorunum = {}
        for ad in ("tekil", "ornek"):
            prog_kes = {}
            for p in programlar:
                kesirler = [Fraction(sayim[u][ad]["dogru"], sayim[u][ad]["n"]) for u in giren
                            if u.split("/", 1)[1] == p]
                prog_kes[p] = sum(kesirler) / len(kesirler)
            makro = sum(prog_kes.values()) / len(prog_kes) if prog_kes else None
            ust = {u: wilson(sayim[u][ad]["dogru"], sayim[u][ad]["n"])[1] for u in giren}
            gorunum[ad] = {
                "program_kesinligi": prog_kes, "makro": makro,
                "wilson_ust": ust, "wilson_ihlali": [u for u in giren if ust[u] < float(ESIK)]}
        karar_makrosu = None
        if programlar:
            karar_makrosu = min(gorunum["tekil"]["makro"], gorunum["ornek"]["makro"])
        if len(programlar) < EN_AZ_PROGRAM:
            karar = "yetersiz"
        else:
            ihlal = gorunum["tekil"]["wilson_ihlali"] or gorunum["ornek"]["wilson_ihlali"]
            karar = "kesin" if karar_makrosu >= ESIK and not ihlal else "kesin_degil"

        def kesir(x):
            return None if x is None else {"kesir": f"{x.numerator}/{x.denominator}",
                                           "oran": round(float(x), 6)}
        out[satir] = {
            "giren_birimler": giren, "giren_programlar": programlar, "kucuk_birimler": kucuk,
            "gorunumler": {ad: {
                "birim_kesinligi": {u: f'{sayim[u][ad]["dogru"]}/{sayim[u][ad]["n"]}'
                                    for u in giren},
                "program_kesinligi": {p: kesir(x) for p, x in v["program_kesinligi"].items()},
                "makro": kesir(v["makro"]),
                "wilson_ust": {u: round(x, 4) for u, x in v["wilson_ust"].items()},
                "wilson_ihlali": v["wilson_ihlali"]} for ad, v in gorunum.items()},
            "karar_makrosu": kesir(karar_makrosu),
            "esik_gecildi": None if karar_makrosu is None else bool(karar_makrosu >= ESIK),
            "karar": karar,
            "havuz": oran_kaydi(sum(s["tekil"]["dogru"] for s in sayim.values()),
                                sum(s["tekil"]["n"] for s in sayim.values())),
            "havuz_ornek": oran_kaydi(sum(s["ornek"]["dogru"] for s in sayim.values()),
                                      sum(s["ornek"]["n"] for s in sayim.values())),
        }
    return out


def kirilganlik(birimler: dict, kararlar: dict) -> dict:
    """`kesin` çıkan satırda kararı bozan en az ek yanlış sayısı (tek bir giren birimde; iki
    görünümde de aynı sayıda öğe yanlışa döner). Karar kuralının kendisi değil; okuma yardımı."""
    out = {}
    for satir, k in kararlar.items():
        if k["karar"] != "kesin":
            continue
        out[satir] = {}
        for u in k["giren_birimler"]:
            n = birimler[u]["satirlar"][satir]["tekil"]["dogru"]
            for j in range(1, n + 1):
                kopya = {b: {"satirlar": {satir: {g: dict(v["satirlar"][satir][g])
                                                  for g in ("tekil", "ornek")}}}
                         for b, v in birimler.items()}
                for g in ("tekil", "ornek"):
                    kopya[u]["satirlar"][satir][g]["dogru"] = max(
                        0, kopya[u]["satirlar"][satir][g]["dogru"] - j)
                yeni = karar_ver_satir(kopya, satir)
                if yeni["karar"] != "kesin":
                    neden = ("makro" if not yeni["esik_gecildi"] else "wilson")
                    out[satir][u] = {"ek_yanlis": j, "bozan_kosul": neden,
                                     "karar_makrosu": yeni["karar_makrosu"]}
                    break
    return out


def karar_ver_satir(birimler: dict, satir: str) -> dict:
    """Tek satır için karar (kirilganlik'in kullandığı, karar_ver ile aynı kural)."""
    tam = {u: {"satirlar": {s: (b["satirlar"][satir] if s == satir else
                                {"tekil": {"dogru": 0, "n": 0}, "ornek": {"dogru": 0, "n": 0}})
                            for s in KARAR_SATIR_ADLARI}} for u, b in birimler.items()}
    return karar_ver(tam)[satir]


MD_SATIRI = re.compile(
    r"^\| (debian|mac)/(\S+) \| `(\w+)` \| (\d+) \| (\S+) \| (\S+) \| (\d+)/(\d+) \| (\d+)/(\d+) "
    r"\| (\d+)/(\d+) \| (\d+)/(\d+) \| (\d+)/(\d+) \| (\d+) \| (\d+)/(\d+) \| (\S+) "
    r"\((\d+)/(\d+)\) \| (\S+) \|$")


def md_karsilastir(birimler: dict, md: str) -> dict:
    """``ks1_olcum.md``'nin "Birim başına" tablosu ile bağımsız hesap (nüfus paydası dışında)."""
    def yuzde(x: float) -> str:
        return ("%" + f"{x * 100:.1f}").replace(".", ",")
    hucre = 0
    satir_sayisi = 0
    farklar = []
    for line in md.splitlines():
        m = MD_SATIRI.match(line)
        if not m:
            continue
        g = m.groups()
        u, s = f"{g[0]}/{g[1]}", g[2]
        v = birimler[u]["satirlar"][s]
        satir_sayisi += 1
        ciftler = [
            ("tekil.n", int(g[3]), v["tekil"]["n"]),
            ("tekil.oran", g[4], yuzde(v["tekil"]["dogru"] / v["tekil"]["n"])),
            ("tekil.aralik", g[5],
             yuzde(v["tekil"]["aralik"][0]) + "-" + yuzde(v["tekil"]["aralik"][1])),
            ("ornek", [int(g[6]), int(g[7])], [v["ornek"]["dogru"], v["ornek"]["n"]]),
            ("yalniz_ana", [int(g[8]), int(g[9])],
             [v["yalniz_ana"]["dogru"], v["yalniz_ana"]["n"]]),
            ("tek_turlu", [int(g[10]), int(g[11])],
             [v["tek_turlu"]["dogru"], v["tek_turlu"]["n"]]),
            ("klon", [int(g[14]), int(g[15])], [v["klon"]["dogru"], v["klon"]["n"]]),
            ("eslenemeyen", int(g[16]), v["eslenemeyen"]),
            ("parca", [int(g[17]), int(g[18])], [v["parca"]["dogru"], v["parca"]["n"]]),
            ("kapsam.pay", int(g[20]), v["kapsam"]["pay"]),
        ]
        for ad, onlarin, benim in ciftler:
            hucre += 1
            if onlarin != benim:
                farklar.append({"hucre": f"md|{u}|{s}|{ad}", "bagimsiz": benim, "olcum": onlarin})
    beklenen = sum(1 for b in birimler.values() for v in b["satirlar"].values()
                   if v["tekil"]["n"] > 0)
    return {"tablo_satiri": satir_sayisi, "sifir_olmayan_satir_bagimsiz": beklenen,
            "hucre": hucre, "farkli": len(farklar), "farklar": farklar}


def rapor_satirlari(birimler: dict) -> dict:
    out = {}
    for s in RAPOR_SATIR_ADLARI:
        out[s] = {g: oran_kaydi(sum(b["satirlar"][s][g]["dogru"] for b in birimler.values()),
                                sum(b["satirlar"][s][g]["n"] for b in birimler.values()))
                  for g in ("tekil", "ornek")}
    return out


# ---------------------------------------------------------------------------------------------
# Karşılaştırma (ks1_olcum.json ile hücre hücre)


def duzlestir_benim(sonuc: dict) -> dict:
    d = {}
    for u, b in sonuc["birimler"].items():
        d[f"birim|{u}|nufus"] = b["nufus"]
        d[f"birim|{u}|export_gt"] = b["export_gt"]
        d[f"birim|{u}|cpp_disarida"] = sorted(b["cpp_disarida"])
        d[f"birim|{u}|elf_sayisi"] = len(b["elfler"])
        for e, k in b["elfler"].items():
            for alan in ("capa", "nufus"):
                d[f"elf|{u}|{e}|{alan}"] = k[alan]
            for alan in ("gt_fonksiyon", "ofset", "ofset_kaynagi"):
                if alan in k["kunye"]:
                    d[f"elf|{u}|{e}|{alan}"] = k["kunye"][alan]
        for s, v in b["satirlar"].items():
            on = f"satir|{u}|{s}|"
            for g in ("tekil", "ornek"):
                d[on + f"{g}.n"] = v[g]["n"]
                d[on + f"{g}.dogru"] = v[g]["dogru"]
                d[on + f"{g}.aralik"] = v[g]["aralik"]
            for g in ("yalniz_ana", "tek_turlu", "klon", "parca"):
                d[on + f"{g}.n"] = v[g]["n"]
                d[on + f"{g}.dogru"] = v[g]["dogru"]
            d[on + "eslenemeyen"] = v["eslenemeyen"]
            d[on + "kapsam.nufus"] = v["kapsam"]["nufus"]
            d[on + "kapsam.pay"] = v["kapsam"]["pay"]
            d[on + "kapsam.dogru_pay"] = v["kapsam"]["dogru_pay"]
    for s, k in sonuc["kararlar"].items():
        on = f"karar|{s}|"
        for alan in ("giren_birimler", "giren_programlar", "kucuk_birimler", "karar"):
            d[on + alan] = k[alan]
        d[on + "karar_makrosu"] = None if k["karar_makrosu"] is None else k["karar_makrosu"]["oran"]
        for g in ("tekil", "ornek"):
            v = k["gorunumler"][g]
            d[on + f"{g}.makro"] = None if v["makro"] is None else v["makro"]["oran"]
            d[on + f"{g}.wilson_ihlali"] = v["wilson_ihlali"]
            for p, x in v["program_kesinligi"].items():
                d[on + f"{g}.program|{p}"] = x["oran"]
            d[on + f"{g}.program_sayisi"] = len(v["program_kesinligi"])
        for h in ("havuz", "havuz_ornek"):
            d[on + f"{h}.dogru"] = k[h]["dogru"]
            d[on + f"{h}.n"] = k[h]["n"]
            d[on + f"{h}.aralik"] = k[h]["aralik"]
    for s, v in sonuc["rapor_satirlari"].items():
        for g in ("tekil", "ornek"):
            d[f"rapor|{s}|{g}.dogru"] = v[g]["dogru"]
            d[f"rapor|{s}|{g}.n"] = v[g]["n"]
            d[f"rapor|{s}|{g}.aralik"] = v[g]["aralik"]
    for u, v in sonuc["sinif"].items():
        for alan in SINIF_ALANLARI:
            d[f"sinif|{u}|{alan}"] = v[alan]
    return d


def duzlestir_olcum(olc: dict) -> dict:
    d = {}
    for u, b in olc["birimler"].items():
        d[f"birim|{u}|nufus"] = b["nufus"]
        d[f"birim|{u}|export_gt"] = b["export_gt"]
        d[f"birim|{u}|cpp_disarida"] = sorted(b["cpp_disarida"])
        d[f"birim|{u}|elf_sayisi"] = len(b["elfler"])
        for e, k in b["elfler"].items():
            for alan in ("capa", "nufus"):
                d[f"elf|{u}|{e}|{alan}"] = k[alan]
            for alan in ("gt_fonksiyon", "ofset", "ofset_kaynagi"):
                if alan in k["kunye"]:
                    d[f"elf|{u}|{e}|{alan}"] = k["kunye"][alan]
        for s, v in b["turler"].items():
            on = f"satir|{u}|{s}|"
            for g, go in (("tekil", "tekil"), ("ornek", "ornek_duzeyi")):
                d[on + f"{g}.n"] = v[go]["kesinlik"]["n"]
                d[on + f"{g}.dogru"] = v[go]["kesinlik"]["k"]
                d[on + f"{g}.aralik"] = v[go]["kesinlik"]["aralik"]
            for g in ("yalniz_ana", "tek_turlu"):
                d[on + f"{g}.n"] = v["duyarlilik"][g]["kesinlik"]["n"]
                d[on + f"{g}.dogru"] = v["duyarlilik"][g]["kesinlik"]["k"]
            for g in ("klon", "parca"):
                d[on + f"{g}.n"] = v["ayri"][g]["n"]
                d[on + f"{g}.dogru"] = v["ayri"][g]["dogru"]
            d[on + "eslenemeyen"] = v["ayri"]["eslenemedi"]["n"]
            d[on + "kapsam.nufus"] = v["kapsam"]["kapsam"]["n"]
            d[on + "kapsam.pay"] = v["kapsam"]["kapsam"]["k"]
            d[on + "kapsam.dogru_pay"] = v["kapsam"]["dogru_kapsam"]["k"]
    for s, k in olc["kararlar"].items():
        on = f"karar|{s}|"
        for alan in ("giren_birimler", "giren_programlar", "kucuk_birimler", "karar",
                     "karar_makrosu"):
            d[on + alan] = k[alan]
        for g, go in (("tekil", "tekil"), ("ornek", "ornek_duzeyi")):
            v = k["gorunumler"][go]
            d[on + f"{g}.makro"] = v["makro_kesinlik"]
            d[on + f"{g}.wilson_ihlali"] = v["wilson_ihlali"]
            for p, x in v["program_kesinligi"].items():
                d[on + f"{g}.program|{p}"] = x
            d[on + f"{g}.program_sayisi"] = len(v["program_kesinligi"])
        for h in ("havuz", "havuz_ornek"):
            d[on + f"{h}.dogru"] = k[h]["k"]
            d[on + f"{h}.n"] = k[h]["n"]
            d[on + f"{h}.aralik"] = k[h]["aralik"]
    for s, v in olc["rapor_satirlari"].items():
        for g, go in (("tekil", "tekil"), ("ornek", "ornek_duzeyi")):
            d[f"rapor|{s}|{g}.dogru"] = v[go]["k"]
            d[f"rapor|{s}|{g}.n"] = v[go]["n"]
            d[f"rapor|{s}|{g}.aralik"] = v[go]["aralik"]
    for u, v in olc.get("sinif", {}).items():
        for alan in SINIF_ALANLARI:
            d[f"sinif|{u}|{alan}"] = v.get(alan)
    return d


SINIF_ALANLARI = ("elf", "ic_fonksiyon", "snake_dizgi", "dizgi_zenginligi", "zenginlik_sinifi",
                  "ic_fonksiyon_ortanca", "boyut_tabakasi")


def esit_mi(a, b) -> bool:
    """Tam sayılar ve listeler tam eşitlikle; 6 haneye yuvarlanmış oranlar 1e-6 payla."""
    if isinstance(a, float) and isinstance(b, float):
        return abs(a - b) <= 1.0e-6
    return a == b


def hucre_grubu(anahtar: str) -> str:
    """Kapsam paydası (nüfus) hücreleri ayrı gruptur: belgede tam tanımlı değil."""
    g = anahtar.split("|", 1)[0]
    if anahtar.endswith("|nufus") or anahtar.endswith("|kapsam.nufus"):
        return "nufus" if "|export|" not in anahtar else "export_paydasi"
    return {"birim": "birim", "elf": "elf_kunyesi", "satir": "kesinlik_ve_pay", "karar": "karar",
            "rapor": "rapor_satiri", "sinif": "program_sinifi"}[g]


def karsilastir(sonuc: dict, olc: dict) -> dict:
    benim, onlarin = duzlestir_benim(sonuc), duzlestir_olcum(olc)
    farklar = []
    grup = Counter()
    grup_fark = Counter()
    for anahtar in sorted(set(benim) | set(onlarin)):
        g = hucre_grubu(anahtar)
        grup[g] += 1
        if anahtar not in benim or anahtar not in onlarin:
            farklar.append({"hucre": anahtar, "bagimsiz": benim.get(anahtar, "YOK"),
                            "olcum": onlarin.get(anahtar, "YOK")})
            grup_fark[g] += 1
        elif not esit_mi(benim[anahtar], onlarin[anahtar]):
            farklar.append({"hucre": anahtar, "bagimsiz": benim[anahtar],
                            "olcum": onlarin[anahtar]})
            grup_fark[g] += 1
    return {"hucre": sum(grup.values()), "tutan": sum(grup.values()) - len(farklar),
            "farkli": len(farklar),
            "gruplar": {g: {"hucre": grup[g], "farkli": grup_fark[g]} for g in sorted(grup)},
            "farklar": farklar}


# ---------------------------------------------------------------------------------------------
# Ana akış


def sonuc_kur(kayitlar: list[dict], **secim) -> dict:
    birimler = topla(kayitlar, **secim)
    return {"birimler": birimler, "kararlar": karar_ver(birimler),
            "rapor_satirlari": rapor_satirlari(birimler)}


def karar_ozeti(kararlar: dict) -> dict:
    return {s: {"karar": k["karar"], "karar_makrosu": k["karar_makrosu"],
                "giren_programlar": k["giren_programlar"],
                "tekil": {"birim_kesinligi": k["gorunumler"]["tekil"]["birim_kesinligi"],
                          "makro": k["gorunumler"]["tekil"]["makro"],
                          "wilson_ihlali": k["gorunumler"]["tekil"]["wilson_ihlali"]},
                "ornek": {"birim_kesinligi": k["gorunumler"]["ornek"]["birim_kesinligi"],
                          "makro": k["gorunumler"]["ornek"]["makro"],
                          "wilson_ihlali": k["gorunumler"]["ornek"]["wilson_ihlali"]}}
            for s, k in kararlar.items()}


def kural_yollari(capalar: list[dict]) -> dict:
    """Hangi puanlama kuralı bu veri setinde gerçekten çalıştı? Sıfır çıkan yol, iki hesabın
    tutmasıyla doğrulanmış sayılmaz (o kuralı yanlış uygulayan bir betik de aynı sayıyı verirdi)."""
    ornekler: dict[tuple[str, str, str], list[bool]] = defaultdict(list)
    for c in capalar:
        if c["rol"] == "parca":
            continue
        for s in satirlari(c["turler"], c["rol"]):
            if s in KARAR_SATIR_ADLARI:
                ornekler[(c["birim"], s, c["ad"])].append(c["dogru"])
    dizgi = [c for c in capalar if any(t in c["turler"] for t in DIZGI_TUR_ADLARI)]
    return {
        "tekil_oge_karar_satirlarinda": len(ornekler),
        "cok_ornekli_tekil_oge": sum(len(v) > 1 for v in ornekler.values()),
        "ornekleri_karisik_hukumlu_tekil_oge": sum(len(set(v)) > 1 for v in ornekler.values()),
        "eslenemeyen_capa": sum(c["sinif"] == "eslenemeyen" for c in capalar),
        "klon_satirina_dusen_dizgi_capasi": sum(c["sinif"] == "klon" and c["rol"] != "parca"
                                              for c in dizgi),
        "cok_takma_adli_gt_ye_dusen_dizgi_capasi": sum(len(c["gt_adlari"]) > 1 for c in dizgi),
        "cok_takma_adli_gt_ye_dusen_export_capasi": sum(
            len(c["gt_adlari"]) > 1 for c in capalar if "export" in c["turler"]),
        "cok_turlu_capa": sum(len(c["turler"]) > 1 for c in capalar),
        "mach_o_dizgi_capasi": sum(c["birim"].startswith("mac/") for c in dizgi),
    }


def goz_ornegi(capalar: list[dict], tohum: int, adet: int) -> dict:
    """30 + 30 göz denetimi için sabit tohumlu örnek. Havuz: karar satırlarına giren dizgi
    çapaları (parça ve export dışarıda). Adlar yalnız ekrana basılır."""
    havuz = sorted((c for c in capalar
                    if c["rol"] != "parca" and any(t in c["turler"] for t in DIZGI_TUR_ADLARI)),
                   key=lambda c: (c["birim"], c["elf"], c["adres"]))
    dogru = [c for c in havuz if c["dogru"]]
    yanlis = [c for c in havuz if not c["dogru"]]
    rng = random.Random(tohum)
    return {"havuz": {"dogru": len(dogru), "yanlis": len(yanlis)}, "tohum": tohum,
            "dogru": rng.sample(dogru, min(adet, len(dogru))),
            "yanlis": rng.sample(yanlis, min(adet, len(yanlis)))}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--kesin", default=str(DEPO / "karadul/reconstruction/tarif/kesin.py"))
    ap.add_argument("--mac-kosu", default=str(DEPO / "workspaces/olcum_mac/runs/ol7-a-9a36142"))
    ap.add_argument("--mac-corpus", default=str(DEPO / "workspaces/olcum_mac/corpus"))
    ap.add_argument("--debian-kosu", default=str(EV / "karadul_olcum/n1_debian13"))
    ap.add_argument("--debian-indirme", default=str(EV / "karadul_olcum/downloads/debian13"))
    ap.add_argument("--olcum", default=str(BURASI.parent / "ks1_olcum.json"),
                    help="karşılaştırılacak ölçüm çıktısı")
    ap.add_argument("--cikti", default=str(BURASI / "yeniden_hesap.json"))
    ap.add_argument("--onbellek", default=None,
                    help="çapa önbelleği dizini (ad içerir; yalnız geçici dizin)")
    ap.add_argument("--goz-ornegi", action="store_true",
                    help="30 + 30 örneği adlarıyla EKRANA bas (dosyaya yazılmaz)")
    ap.add_argument("--goz-hukmu", default=None,
                    help="elle göz denetiminin sonucu (JSON dosyası); çıktıya 'elle' diye yazılır")
    args = ap.parse_args()

    kayitlar, denetim, girdi = ikilileri_isle(args)
    ana = sonuc_kur(kayitlar)
    hukumlu = [c for k in kayitlar if k["veri"] is not None and not k["cpp_ghidra"]
               for c in k["capalar"]]
    sonuc = {
        "sema": "karadul-ks1-bagimsiz/1",
        "aciklama": "KS-1 adım 2 ölçümünün bağımsız yeniden hesabı; fonksiyon adı içermez.",
        "girdi": girdi,
        "secimler": {"n_min": N_MIN, "en_az_program": EN_AZ_PROGRAM, "esik": float(ESIK), "z": Z},
        "yorumlar": YORUMLAR,
        "denetimler": dict(sorted(denetim.items())),
        **ana,
        "sinif": sinif_ozeti(kayitlar),
        "kirilganlik": kirilganlik(ana["birimler"], ana["kararlar"]),
        "kural_yollari": kural_yollari(hukumlu),
        "yanlis_capalar": [
            {"birim": c["birim"], "elf": c["elf"], "adres": f'{c["adres"]:x}',
             "satirlar": satirlari(c["turler"], c["rol"]) if c["rol"] != "parca" else ["parca"],
             "sinif": c["sinif"], "gt_takma_ad_sayisi": len(c["gt_adlari"])}
            for c in hukumlu if not c["dogru"]],
    }

    # Duyarlılık 1: C++ işareti ikilinin kendi içe aktarma tablosundan
    cpp_fark = sorted(f'{k["birim"]}:{k["elf"]}' for k in kayitlar
                      if k["cpp_ghidra"] != k["cpp_ikili"])
    d1 = sonuc_kur(kayitlar, cpp_alani="cpp_ikili")
    # Duyarlılık 2: birim içinde bayt bayt aynı ikililer tek sayılır
    ozet = Counter((k["birim"], k["sha256"]) for k in kayitlar)
    yinelenen = sorted(f'{k["birim"]}:{k["elf"]}' for k in kayitlar
                       if ozet[(k["birim"], k["sha256"])] > 1)
    d2 = sonuc_kur(kayitlar, yinelenen_tek=True)
    # Duyarlılık 3: nüfus tanımının ölçümle uzlaştırılması (CRT eki + caseD_N)
    d3 = sonuc_kur(kayitlar, nufus_alani="nufus_uzlastirma")

    def degisen(alt: dict) -> dict:
        return {u: {"elf_sayisi": len(b["elfler"]), "cpp_disarida": b["cpp_disarida"],
                    "yinelenen_disarida": b["yinelenen_disarida"], "nufus": b["nufus"],
                    "export_gt": b["export_gt"],
                    "satirlar": {s: v for s, v in b["satirlar"].items()
                                 if v != ana["birimler"][u]["satirlar"][s]}}
                for u, b in alt["birimler"].items()
                if b["satirlar"] != ana["birimler"][u]["satirlar"]}

    cpp_ayrinti = {}
    for k in kayitlar:
        if k["cpp_ghidra"] == k["cpp_ikili"] or k["veri"] is None:
            continue
        v = k["veri"]
        dizgi = [c for c in k["capalar"] if c["rol"] != "parca"
                 and any(t in c["turler"] for t in DIZGI_TUR_ADLARI)]
        cpp_ayrinti[f'{k["birim"]}:{k["elf"]}'] = {
            "ice_aktarilan_ad": len(v["ice_aktarilan"]),
            "isaretli_ice_aktarilan": sum(a.startswith(CPP_ISARETLERI)
                                          for a in v["ice_aktarilan"]),
            "gt_fonksiyon": len(v["gt"]), "gt_mangled_adli": len(v["gt_mangled"]),
            "dizgi_capasi": len(dizgi), "dizgi_capasi_dogru": sum(c["dogru"] for c in dizgi),
            "mangled_gt_ye_dusen_dizgi_capasi": sum(c["adres"] in v["gt_mangled"]
                                                   for c in dizgi)}
    nufus_farki = {}
    for k in kayitlar:
        if k["veri"] is None:
            continue
        v = k["veri"]
        b = nufus_farki.setdefault(k["birim"], {"farkli_elf": 0, "yalniz_bagimsiz": 0,
                                                "yalniz_uzlastirma": 0, "ornek": []})
        eksi, arti = v["nufus"] - v["nufus_uzlastirma"], v["nufus_uzlastirma"] - v["nufus"]
        b["farkli_elf"] += int(bool(eksi or arti))
        b["yalniz_bagimsiz"] += len(eksi)
        b["yalniz_uzlastirma"] += len(arti)
        for yon, kume in (("yalniz_bagimsiz", eksi), ("yalniz_uzlastirma", arti)):
            for a in sorted(kume):
                if len(b["ornek"]) < 6:
                    b["ornek"].append({"elf": k["elf"], "ghidra_adresi": f"{a:x}", "yon": yon})
    sonuc["duyarlilik"] = {
        "cpp_ikili_tablosu": {
            "tanim": "C++ işareti Ghidra adları yerine ikilinin içe aktarma tablosundan",
            "iki_kaynagin_ayristigi_ikililer": cpp_fark, "ayrinti": cpp_ayrinti,
            "degisen_birimler": degisen(d1), "kararlar": karar_ozeti(d1["kararlar"]),
            "rapor_satirlari": d1["rapor_satirlari"]},
        "yinelenen_ikili_tek": {
            "tanim": "birim içinde sha256'sı aynı ikililerden yalnız ilki sayılır",
            "ayni_ozetli_ikililer": yinelenen, "farkli_dosya_sayisi": len(ozet),
            "degisen_birimler": degisen(d2), "kararlar": karar_ozeti(d2["kararlar"]),
            "rapor_satirlari": d2["rapor_satirlari"]},
        "nufus_uzlastirma": {
            "tanim": "CRT listesine libc_nonshared sarmalayıcısı eklenir; Ghidra'nın caseD_N "
                     "adı da ad bekleyen sayılır",
            "birim_nufusu": {u: {"bagimsiz": ana["birimler"][u]["nufus"],
                                 "uzlastirma": b["nufus"]} for u, b in d3["birimler"].items()},
            "fark_dokumu": {u: v for u, v in sorted(nufus_farki.items()) if v["farkli_elf"]},
            "farkli_elf_sayisi": sum(
                e["nufus"] != ana["birimler"][u]["elfler"][n]["nufus"]
                for u, b in d3["birimler"].items() for n, e in b["elfler"].items())},
    }

    olcum_yolu = Path(args.olcum)
    if olcum_yolu.is_file():
        olc = json.loads(olcum_yolu.read_text(encoding="utf-8"))
        k3 = karsilastir({**sonuc, **d3}, olc)
        sonuc["karsilastirma"] = {
            "olcum": kisa_yol(olcum_yolu), "olcum_sha256": sha256_of(olcum_yolu),
            **karsilastir(sonuc, olc),
            "nufus_uzlastirma_sonrasi": {"hucre": k3["hucre"], "farkli": k3["farkli"],
                                         "gruplar": k3["gruplar"], "farklar": k3["farklar"]}}
        md_yolu = olcum_yolu.with_suffix(".md")
        if md_yolu.is_file():
            sonuc["karsilastirma"]["olcum_md"] = {
                "dosya": kisa_yol(md_yolu),
                **md_karsilastir(ana["birimler"], md_yolu.read_text(encoding="utf-8"))}
    ornek = goz_ornegi(hukumlu, GOZ_TOHUMU, 30)
    sonuc["goz_denetimi"] = {
        "havuz_tanimi": "karar satırlarına giren dizgi çapaları (parça ve export dışarıda), "
                        "bağımsız hesabın hükmüyle; ölçüm çıktısı öğe düzeyinde hüküm taşımaz",
        "tohum": ornek["tohum"], "havuz": ornek["havuz"],
        "secilen": {h: [{"birim": c["birim"], "elf": c["elf"], "adres": f'{c["adres"]:x}',
                         "sinif": c["sinif"]} for c in ornek[h]] for h in ("dogru", "yanlis")},
        "elle": (json.loads(Path(args.goz_hukmu).read_text(encoding="utf-8"))
                 if args.goz_hukmu else None),
    }
    if args.goz_ornegi:
        for h in ("dogru", "yanlis"):
            print(f"== hüküm: {h} ({len(ornek[h])} örnek) ==")
            for i, c in enumerate(ornek[h], 1):
                print(f'{i:2d} {c["birim"]:18s} {c["elf"]:16s} {c["adres"]:x} {c["sinif"]:11s} '
                      f'{",".join(c["turler"])}/{c["rol"]}  çapa={c["ad"]}  GT={c["gt_adlari"]}')
    Path(args.cikti).write_text(json.dumps(sonuc, ensure_ascii=False, indent=1) + "\n",
                                encoding="utf-8")
    k = sonuc.get("karsilastirma")
    if k:
        print(f'karşılaştırma: {k["hucre"]} hücre, {k["tutan"]} tutuyor, {k["farkli"]} farklı; '
              f'gruplar: {json.dumps(k["gruplar"], ensure_ascii=False)}')
        print(f'nüfus uzlaştırmasından sonra farklı: {k["nufus_uzlastirma_sonrasi"]["farkli"]}')
    for s, v in sonuc["kararlar"].items():
        print(f'{s}: {v["karar"]}')
    return 0


if __name__ == "__main__":
    sys.exit(main())
