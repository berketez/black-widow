#!/usr/bin/env python3
"""Fonksiyon-ismi ölçüm harness'i (karadul) — TEK puanlama kaynağı.

Stripped bir ELF üzerinde karadul'un fonksiyonlara verdiği isimleri, AYNI
build'in debug sembollerinden (``.symtab``: global T + static t) çıkarılan
ground truth (GT) ile ADRES bazında karşılaştırır; binary başına
precision / recall / F1 ve kapsama verir.

Tanımlar (gerekçeler ``scripts/measurement/README.md``'de)
----------------------------------------------------------
GT
    Debug ELF ``.symtab``'ındaki ``STT_FUNC``/``STT_GNU_IFUNC`` semboller:
    yürütülebilir bir bölümde, adresi 0 olmayan. Aynı adresteki semboller
    tek fonksiyondur (takma adlar). AArch64 mapping sembolleri (``$x``) hariç.
    İki sınıf GT'de tutulur (kapsama için) ama PUANLANMAZ:
    CRT/linker kökenliler (``_start``, ``frame_dummy`` ...) ve stripped
    binary'nin ``.dynsym``'inden zaten dışa aktarılanlar (``_obstack_begin``
    gibi; isim binary'de duruyor, çıkarım gerekmiyor).
tespit (code)
    Ghidra fonksiyonlarından stripped binary'nin yürütülebilir ve PLT olmayan
    bölümlerine düşenler. PLT thunk'ları ile Ghidra'nın EXTERNAL bloğundaki
    sahte fonksiyonlar hariçtir: isimleri import tablosundan gelir, karadul'un
    isimlendirme işi değildir. (cat'te 146 fonksiyonun 121'i böyle thunk'tır.)
kapsama
    ``|GT ∩ tespit| / |tespit|``
tahmin
    Puanlanan bir GT fonksiyonu için karadul'un naming_map'te verdiği,
    JENERİK OLMAYAN isim. Jenerik: ``FUN_``/``sub_``/``thunk_FUN_``/``LAB_``
    gibi yer tutucular, Ghidra oto-isimleri (``entry``, ``_INIT_0``) ve
    fonksiyonun KENDİ adresini taşıyan isimler (``leaf_2de0``, ``read_fd_3144``).
    Yalnız naming_map sayılır: Ghidra'nın kendi koyduğu isim (ör. tek
    ``b posix_fadvise`` olan fonksiyona thunk adı) karadul'un iddiası değildir;
    tanı amaçlı ayrı listelenir (thunk dışıysa sızıntı uyarısı).
strict (birincil)
    TP: normalize(tahmin) == normalize(GT adı). Normalizasyon projenin tek
    kaynağından gelir: ``tests/benchmark/metrics.py``
    ``AccuracyCalculator._normalize`` (FIX-4 GCC sufiks kuralı dahil:
    ``full_write.constprop.0`` -> ``full_write``).
    FP: jenerik olmayan ama yanlış tahmin.
    FN: puanlanan GT - TP (tespit edilmeyen + isimsiz + yanlış).
    precision = TP / (TP + FP), recall = TP / |puanlanan GT|.
lenient (ikincil)
    Aynı popülasyon; TP = ``AccuracyCalculator.compare_name`` exact/semantic/
    partial. Tarihsel tanıma yakın, gevşek sayı.

GT'de olmayan (doğrulanamayan) tespit edilmiş fonksiyonlar TP de FP de
sayılmaz; ayrıca raporlanır. GT hiçbir zaman karadul'a verilmez; harness
yalnızca koşu SONRASI okur.

Kullanım
--------
    # GT çıkar (debug ELF + stripped ELF aynı build olmalı: BuildID eşleşmesi)
    python scripts/measurement/function_f1.py gt \
        --debug cat.debug --stripped cat --corpus debian-9.4-3 --out cat.gt.json

    # Bir karadul koşusunu puanla
    python scripts/measurement/function_f1.py score \
        --gt cat.gt.json --run-dir ~/karadul_olcum/runs/<etiket>/<korpus>/cat
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Iterable, Optional

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tests.benchmark.metrics import AccuracyCalculator  # noqa: E402

GT_SCHEMA = "karadul-function-gt/1"
SCORE_SCHEMA = "karadul-function-f1/1"

_CALC = AccuracyCalculator()

# Stripped binary'de import stub'larının yaşadığı bölümler.
PLT_SECTION_NAMES = frozenset({".plt", ".plt.got", ".plt.sec", ".iplt"})

# CRT / linker / libc_nonshared kökenli fonksiyonlar: programın kendi kodu
# değil. Tam ad eşleşmesi (eski harness'teki "__" önek joker'i gnulib'in
# __argmatch_die / __xargmatch_internal gibi GERÇEK fonksiyonlarını da
# siliyordu; burada bilinçli olarak açık liste kullanılır).
CRT_FUNCTION_NAMES = frozenset({
    "_start", "_init", "_fini", "call_weak_fn",
    "deregister_tm_clones", "register_tm_clones",
    "__do_global_dtors_aux", "__do_global_ctors_aux", "frame_dummy",
    "atexit", "at_quick_exit", "__libc_csu_init", "__libc_csu_fini",
    "__stack_chk_fail_local", "_dl_relocate_static_pie",
})
CRT_NAME_PREFIXES = ("__x86.get_pc_thunk.",)

# AArch64/ARM mapping sembolleri ($x, $d, $x.12 ...) fonksiyon değildir.
_MAPPING_SYMBOL_RE = re.compile(r"^\$[adtx](?:\.\d+)?$")

# metrics.py'deki yer tutucu desenlerine ek olarak Ghidra'ya özgü oto-isimler.
_EXTRA_GENERIC_PATTERNS = (
    re.compile(r"^thunk_FUN_[0-9a-fA-F]+$"),
    re.compile(r"^(?:LAB|caseD|switchD)_[0-9a-fA-F]+"),
    re.compile(r"^_(?:INIT|FINI)_\d+$"),
    re.compile(r"^_DT_(?:INIT|FINI)$"),
    re.compile(r"^entry$"),
)
_HEX_TOKEN_RE = re.compile(r"^[0-9a-f]{4,}$")

# Eski harness'in (mac_f1_eval / benchmark_runner) SKIP önekleri — yalnız
# "legacy" köprü sayısı için, birebir aynı kural.
LEGACY_SKIP_PREFIXES = ("__", "GCC_", "GLIBC_", "atexit", "frame_dummy",
                        "register_tm", "deregister_tm", "_start", "_init",
                        "_fini")

# Ghidra ELF PIE (ET_DYN) varsayılan image base'i; yalnız entry fonksiyonu
# bulunamazsa kullanılır (normalde ofset entry'den türetilir).
GHIDRA_DEFAULT_PIE_BASE = 0x100000


# ---------------------------------------------------------------------------
# İsim kuralları
# ---------------------------------------------------------------------------

def normalize_name(name: str) -> str:
    """Karşılaştırma için normalize et — projenin tek kuralı (metrics.py).

    FIX-4: ``.constprop.N`` / ``.isra.N`` / ``.part.N`` / ``.cold`` /
    ``.lto_priv.N`` / ``.clone.N`` sufiksleri soyulur; ayrıca baştaki ``_``,
    camelCase->snake, küçük harf, sondaki ``_<rakam>`` dedup eki.
    """
    return _CALC._normalize(name)


def _embeds_own_address(name: str, addresses: Iterable[int]) -> bool:
    """İsim, fonksiyonun kendi adresinin son hex hanelerini token olarak taşıyor mu?

    karadul'un yapısal geri-dönüş isimleri ``{rol}_{adres[-4:]}`` biçimindedir
    (``leaf_2de0``, ``read_fd_3144``, ``helper_1a2b``): kimlik iddiası değil,
    adres etiketi. ≥4 haneli, tamamı hex bir token adresin sonuyla eşleşirse
    isim jeneriktir.
    """
    hexes = [f"{a:x}" for a in addresses if a]
    if not hexes:
        return False
    for tok in re.split(r"[_.]", name.lower()):
        if not _HEX_TOKEN_RE.match(tok):
            continue
        for h in hexes:
            if h.zfill(len(tok)).endswith(tok):
                return True
    return False


def is_generic_name(name: Optional[str], addresses: Iterable[int] = ()) -> bool:
    """İsim bir kimlik iddiası DEĞİL mi (yer tutucu / oto-isim / adres etiketi)?"""
    if not name or not name.strip():
        return True
    if _CALC._is_unnamed(name):
        return True
    if any(p.match(name) for p in _EXTRA_GENERIC_PATTERNS):
        return True
    return _embeds_own_address(name, addresses)


def is_crt_name(name: str) -> bool:
    return name in CRT_FUNCTION_NAMES or name.startswith(CRT_NAME_PREFIXES)


def match_strict(predicted: str, gt_names: Iterable[str]) -> bool:
    p = normalize_name(predicted)
    return any(p == normalize_name(g) for g in gt_names)


def match_lenient(predicted: str, gt_names: Iterable[str]) -> bool:
    for g in gt_names:
        if _CALC.compare_name(g, predicted).match_type in ("exact", "semantic", "partial"):
            return True
    return False


# ---------------------------------------------------------------------------
# ELF okuma (pyelftools) — GT ve stripped binary bilgisi
# ---------------------------------------------------------------------------

def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def read_elf_info(path: Path) -> dict[str, Any]:
    """Build-ID, tip, entry, yürütülebilir bölümler, strip durumu, .dynsym ihraçları."""
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import NoteSection, SymbolTableSection

    with open(path, "rb") as f:
        elf = ELFFile(f)
        build_id = None
        exec_sections = []
        has_symtab = False
        debug_sections = []
        dynsym_funcs: dict[int, str] = {}
        for sec in elf.iter_sections():
            if isinstance(sec, NoteSection):
                for note in sec.iter_notes():
                    if note["n_type"] == "NT_GNU_BUILD_ID":
                        build_id = note["n_desc"]
            if sec.name == ".symtab":
                has_symtab = True
            if sec.name.startswith((".debug_", ".zdebug_")):
                debug_sections.append(sec.name)
            if sec["sh_flags"] & 0x4 and sec["sh_size"]:  # SHF_EXECINSTR
                exec_sections.append({
                    "name": sec.name,
                    "start": sec["sh_addr"],
                    "end": sec["sh_addr"] + sec["sh_size"],
                })
            if sec.name == ".dynsym" and isinstance(sec, SymbolTableSection):
                # Strip .dynsym'e dokunmaz: burada TANIMLI fonksiyonlar (ihraç)
                # stripped binary'de de isimleriyle durur -> çıkarım problemi değil.
                # (--only-keep-debug dosyasında .dynsym NOBITS'tir; atlanır.)
                for sym in sec.iter_symbols():
                    if (sym["st_info"]["type"] in ("STT_FUNC", "STT_GNU_IFUNC")
                            and sym["st_shndx"] != "SHN_UNDEF" and sym["st_value"] and sym.name):
                        dynsym_funcs.setdefault(sym["st_value"], sym.name)
        return {
            "build_id": build_id,
            "elf_type": elf["e_type"],
            "machine": elf["e_machine"],
            "entry": elf["e_entry"],
            "exec_sections": exec_sections,
            "has_symtab": has_symtab,
            "debug_sections": debug_sections,
            "dynsym_funcs": dynsym_funcs,
        }


def read_function_symbols(debug_path: Path) -> list[dict[str, Any]]:
    """Debug ELF .symtab'ından ham sembol kayıtları (filtre build_gt_functions'ta)."""
    from elftools.elf.elffile import ELFFile

    records: list[dict[str, Any]] = []
    with open(debug_path, "rb") as f:
        elf = ELFFile(f)
        sections = list(elf.iter_sections())
        symtab = elf.get_section_by_name(".symtab")
        if symtab is None:
            raise ValueError(f"{debug_path}: .symtab yok — GT çıkarılamaz")
        for sym in symtab.iter_symbols():
            shndx = sym["st_shndx"]
            if isinstance(shndx, int) and 0 < shndx < len(sections):
                sec = sections[shndx]
                sec_name, sec_exec = sec.name, bool(sec["sh_flags"] & 0x4)
            else:
                sec_name, sec_exec = str(shndx), False
            records.append({
                "name": sym.name,
                "value": sym["st_value"],
                "size": sym["st_size"],
                "type": sym["st_info"]["type"],
                "bind": sym["st_info"]["bind"],
                "section": sec_name,
                "section_exec": sec_exec,
            })
    return records


def build_gt_functions(symbols: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Ham sembol kayıtlarından GT fonksiyon listesi (adres başına bir kayıt).

    Kural: STT_FUNC/STT_GNU_IFUNC + yürütülebilir bölüm + adres≠0 + mapping
    sembolü değil. Aynı adresteki isimler ``names``'te (GLOBAL önce).
    """
    by_addr: dict[int, dict[str, Any]] = {}
    for s in symbols:
        if s["type"] not in ("STT_FUNC", "STT_GNU_IFUNC"):
            continue
        if not s["section_exec"] or not s["value"] or not s["name"]:
            continue
        if _MAPPING_SYMBOL_RE.match(s["name"]):
            continue
        ent = by_addr.setdefault(s["value"], {
            "addr": s["value"], "names": [], "binds": [], "size": 0,
            "section": s["section"],
        })
        if s["name"] not in ent["names"]:
            ent["names"].append(s["name"])
            ent["binds"].append(s["bind"])
        ent["size"] = max(ent["size"], s["size"])
    out = []
    for addr in sorted(by_addr):
        ent = by_addr[addr]
        order = sorted(range(len(ent["names"])),
                       key=lambda i: (ent["binds"][i] != "STB_GLOBAL", ent["names"][i]))
        names = [ent["names"][i] for i in order]
        binds = [ent["binds"][i] for i in order]
        out.append({
            "addr": f"0x{addr:x}",
            "names": names,
            "bind": binds[0].replace("STB_", ""),
            "size": ent["size"],
            "section": ent["section"],
            "crt": all(is_crt_name(n) for n in names),
        })
    return out


def extract_gt(debug_path: Path, stripped_path: Path, *, corpus: str = "",
               binary: str = "") -> dict[str, Any]:
    """Debug + stripped çiftinden GT JSON'u üret; aynı build olduğunu kanıtla."""
    dbg = read_elf_info(debug_path)
    stp = read_elf_info(stripped_path)
    if not dbg["build_id"] or dbg["build_id"] != stp["build_id"]:
        raise ValueError(
            f"BuildID uyuşmuyor: debug={dbg['build_id']} stripped={stp['build_id']}"
            " — farklı build'in sembolleri GT olamaz")
    if stp["has_symtab"] or stp["debug_sections"]:
        raise ValueError(
            f"{stripped_path} stripped değil (.symtab={stp['has_symtab']}, "
            f"debug={stp['debug_sections']}) — ölçüm sızıntılı olur")
    functions = build_gt_functions(read_function_symbols(debug_path))
    exported = stp.get("dynsym_funcs") or {}
    for fn in functions:
        fn["exported"] = _hex(fn["addr"]) in exported
    return {
        "schema": GT_SCHEMA,
        "corpus": corpus,
        "binary": binary or stripped_path.name,
        "build_id": stp["build_id"],
        "stripped_sha256": sha256_file(stripped_path),
        "debug_sha256": sha256_file(debug_path),
        "elf_type": stp["elf_type"],
        "machine": stp["machine"],
        "entry": f"0x{stp['entry']:x}",
        "exec_sections": [
            {"name": s["name"], "start": f"0x{s['start']:x}", "end": f"0x{s['end']:x}"}
            for s in stp["exec_sections"]
        ],
        "functions": functions,
        "counts": {
            "functions": len(functions),
            "scored": sum(1 for f in functions if not (f["crt"] or f["exported"])),
            "crt": sum(1 for f in functions if f["crt"]),
            "exported": sum(1 for f in functions if f["exported"]),
            "global": sum(1 for f in functions if f["bind"] == "GLOBAL"),
            "local": sum(1 for f in functions if f["bind"] == "LOCAL"),
        },
    }


# ---------------------------------------------------------------------------
# karadul koşu çıktıları
# ---------------------------------------------------------------------------

def _hex(v: Any) -> int:
    if isinstance(v, int):
        return v
    return int(str(v), 16)


def load_ghidra_functions(path: Path) -> list[dict[str, Any]]:
    """ghidra_functions.json -> [{addr:int, name, is_thunk, size}] (ham Ghidra adları)."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    out = []
    for fn in data.get("functions", []):
        addr = fn.get("address")
        if addr in (None, ""):
            continue
        out.append({
            "addr": _hex(addr),
            "name": fn.get("name") or "",
            "is_thunk": bool(fn.get("is_thunk")),
            "size": fn.get("size") or 0,
        })
    return out


def load_naming_map(path: Path) -> dict[str, str]:
    """karadul naming_map.json -> {eski_ad: yeni_ad} (yalnız fonksiyon adları).

    Desteklenen şemalar: ``{"global": {...}, "per_function": {...}}`` (workspace
    ``reconstructed/src``; per_function değişken adlarıdır, alınmaz),
    ``{"mappings": {eski: {"new_name": ...}}}`` (temiz çıktı) ve düz sözlük.
    """
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        return {}
    if isinstance(data.get("global"), dict) or "per_function" in data:
        g = data.get("global") or {}
        return {k: v for k, v in g.items() if isinstance(v, str)}
    if isinstance(data.get("mappings"), dict):
        out: dict[str, str] = {}
        for k, v in data["mappings"].items():
            if isinstance(v, dict) and isinstance(v.get("new_name"), str):
                out[k] = v["new_name"]
            elif isinstance(v, str):
                out[k] = v
        return out
    return {k: v for k, v in data.items() if isinstance(v, str)}


def find_run_artifacts(run_dir: Path) -> dict[str, Optional[Path]]:
    """Bir koşu dizininde (``ws/`` + ``out/``) puanlama girdilerini bul.

    Workspace yapısı: ``<ws>/workspaces/<ad>/<zaman>/{static,reconstructed,raw}``.
    Birden fazla zaman damgası varsa en yenisi alınır ve ``ambiguous`` işaretlenir.
    """
    run_dir = Path(run_dir)
    hits = sorted(run_dir.glob("ws/**/static/ghidra_functions.json"))
    ts_dir = hits[-1].parent.parent if hits else None
    naming = None
    if ts_dir is not None:
        cand = ts_dir / "reconstructed" / "src" / "naming_map.json"
        naming = cand if cand.is_file() else None
    if naming is None:
        cand = run_dir / "out" / "naming_map.json"
        naming = cand if cand.is_file() else None
    target_info = ts_dir / "raw" / "target_info.json" if ts_dir else None
    report = run_dir / "out" / "report.json"
    return {
        "ts_dir": ts_dir,
        "ghidra_functions": hits[-1] if hits else None,
        "naming_map": naming,
        "target_info": target_info if target_info and target_info.is_file() else None,
        "report": report if report.is_file() else None,
        "ambiguous": len(hits) > 1,
    }


# ---------------------------------------------------------------------------
# Puanlama
# ---------------------------------------------------------------------------

def derive_image_offset(ghidra_funcs: list[dict[str, Any]], entry: int,
                        elf_type: str) -> tuple[int, str]:
    """Ghidra adresi = dosya adresi + ofset. Ofset ELF entry'den türetilir.

    Ghidra ELF giriş noktasında ``entry`` adlı fonksiyon oluşturur; onun adresi
    ile ``e_entry`` farkı image-base ofsetidir (PIE için tipik 0x100000). Böylece
    sabit kodlanmış taban yerine koşunun kendi kanıtı kullanılır.
    """
    for fn in ghidra_funcs:
        if fn["name"] == "entry":
            return fn["addr"] - entry, "ghidra_entry"
    base = GHIDRA_DEFAULT_PIE_BASE if elf_type == "ET_DYN" else 0
    return base, "default"


def classify_detected(ghidra_funcs: list[dict[str, Any]], exec_sections: list[dict[str, Any]],
                      offset: int) -> dict[int, str]:
    """Ghidra fonksiyonu (dosya adresi) -> 'code' | 'plt' | 'external'."""
    secs = [(_hex(s["start"]), _hex(s["end"]), s["name"]) for s in exec_sections]
    kinds: dict[int, str] = {}
    for fn in ghidra_funcs:
        faddr = fn["addr"] - offset
        kind = "external"
        for start, end, name in secs:
            if start <= faddr < end:
                kind = "plt" if name in PLT_SECTION_NAMES else "code"
                break
        # Aynı dosya adresine birden fazla Ghidra kaydı düşerse 'code' kazanır.
        if kinds.get(faddr) != "code":
            kinds[faddr] = kind
    return kinds


def lookup_prediction(naming_map: dict[str, str], fn: dict[str, Any]) -> Optional[str]:
    """karadul'un bir Ghidra fonksiyonuna verdiği isim (yoksa None).

    naming_map anahtarı Ghidra'nın o anki adıdır; ama Ghidra fonksiyonu kendisi
    oto-isimlendirmişse (``entry``, ``_FINI_0``) karadul yine ``FUN_<adres>``
    anahtarını kullanabiliyor (ölçüldü: cat'te ``FUN_00102cc0 -> start``).
    İkisi de denenir; Ghidra adı önceliklidir.
    """
    for key in (fn["name"], f"FUN_{fn['addr']:08x}"):
        if key in naming_map:
            return naming_map[key]
    return None


def _prf(tp: int, fp: int, n_gt: int) -> dict[str, Any]:
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / n_gt if n_gt else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return {"tp": tp, "fp": fp, "fn": n_gt - tp,
            "precision": round(precision, 4), "recall": round(recall, 4),
            "f1": round(f1, 4)}


def score(gt: dict[str, Any], ghidra_funcs: list[dict[str, Any]],
          naming_map: dict[str, str]) -> dict[str, Any]:
    """GT + Ghidra fonksiyon listesi + karadul naming_map -> metrikler."""
    offset, offset_src = derive_image_offset(ghidra_funcs, _hex(gt["entry"]), gt["elf_type"])
    kinds = classify_detected(ghidra_funcs, gt["exec_sections"], offset)

    # Dosya adresi -> Ghidra kaydı (yalnız 'code'; thunk/external puanlanmaz).
    code_funcs: dict[int, dict[str, Any]] = {}
    for fn in ghidra_funcs:
        faddr = fn["addr"] - offset
        if kinds.get(faddr) == "code" and faddr not in code_funcs:
            code_funcs[faddr] = fn

    gt_by_addr = {_hex(f["addr"]): f for f in gt["functions"]}

    per_function: list[dict[str, Any]] = []
    strict_status: Counter[str] = Counter()
    lenient_tp = 0
    ghidra_named_scored: list[str] = []   # thunk DEĞİL + Ghidra isim biliyor: sızıntı şüphesi
    ghidra_thunk_named: list[str] = []    # Ghidra'nın thunk hedef adı (ör. fdadvise->posix_fadvise)
    unscored_named = Counter()            # CRT / ihraç edilmiş fonksiyona verilen isimler

    for faddr in sorted(gt_by_addr):
        g = gt_by_addr[faddr]
        names = g["names"]
        fn = code_funcs.get(faddr)
        ghidra_name = fn["name"] if fn else None
        addrs = (faddr, faddr + offset)
        # Tahmin YALNIZ karadul'un naming_map'idir; Ghidra'nın kendi koyduğu isim
        # karadul'un iddiası değildir (tanı listelerine düşer).
        predicted = lookup_prediction(naming_map, fn) if fn is not None else None
        skip = "crt" if g["crt"] else ("exported" if g.get("exported") else None)
        if skip:
            if predicted and not is_generic_name(predicted, addrs):
                unscored_named[skip] += 1
            continue
        if fn is not None and predicted is None and not is_generic_name(ghidra_name, addrs):
            (ghidra_thunk_named if fn["is_thunk"] else ghidra_named_scored).append(names[0])

        if fn is None:
            status = "undetected"
        elif predicted is None or is_generic_name(predicted, addrs):
            status = "unnamed"
        elif match_strict(predicted, names):
            status = "tp"
        else:
            status = "wrong"
        strict_status[status] += 1
        lenient_ok = status == "tp" or (
            status == "wrong" and match_lenient(predicted, names))
        lenient_tp += int(lenient_ok)
        per_function.append({
            "addr": f"0x{faddr:x}",
            "gt": names[0] if len(names) == 1 else names,
            "ghidra": ghidra_name,
            "predicted": predicted,
            "status": status,
            "lenient_tp": lenient_ok,
        })

    # GT dışı tespit edilmiş fonksiyonlar: isim doğru mu yanlış mı BİLİNEMEZ —
    # TP de FP de sayılmaz (eski harness'in "isimli FUN_xxx = partial TP"
    # sahte-F1 hatası); yalnız ayrı sayaçta raporlanır.
    outside = [a for a in code_funcs if a not in gt_by_addr]
    outside_named = 0
    for a in outside:
        nm = lookup_prediction(naming_map, code_funcs[a])
        if nm and not is_generic_name(nm, (a, a + offset)):
            outside_named += 1

    n_scored = len(per_function)
    tp = strict_status["tp"]
    fp = strict_status["wrong"]
    strict = _prf(tp, fp, n_scored)
    lenient = _prf(lenient_tp, (tp + fp) - lenient_tp, n_scored)

    n_code = len(code_funcs)
    gt_in_code = sum(1 for a in gt_by_addr if a in code_funcs)
    kind_counts = Counter(kinds.values())
    return {
        "schema": SCORE_SCHEMA,
        "corpus": gt.get("corpus", ""),
        "binary": gt.get("binary", ""),
        "build_id": gt.get("build_id"),
        "image_offset": f"0x{offset:x}",
        "image_offset_source": offset_src,
        "detected": {
            "ghidra_total": len(ghidra_funcs),
            "code": n_code,
            "plt": kind_counts.get("plt", 0),
            "external": kind_counts.get("external", 0),
            "thunk_flagged": sum(1 for f in ghidra_funcs if f["is_thunk"]),
        },
        "gt": {
            "functions": len(gt_by_addr),
            "scored": n_scored,
            "crt": sum(1 for f in gt["functions"] if f["crt"]),
            "exported": sum(1 for f in gt["functions"] if f.get("exported") and not f["crt"]),
        },
        "coverage": {
            "gt_in_detected": gt_in_code,
            "detected_code": n_code,
            "ratio": round(gt_in_code / n_code, 4) if n_code else 0.0,
            "gt_detection_ratio": round(gt_in_code / len(gt_by_addr), 4) if gt_by_addr else 0.0,
        },
        "strict": strict,
        "lenient": lenient,
        "breakdown": {k: strict_status.get(k, 0) for k in ("tp", "wrong", "unnamed", "undetected")},
        "outside_gt": {"detected_code_not_in_gt": len(outside), "named_non_generic": outside_named},
        "crt_named": unscored_named["crt"],
        "exported_named": unscored_named["exported"],
        "ghidra_named_scored": ghidra_named_scored,
        "ghidra_thunk_named": ghidra_thunk_named,
        "per_function": per_function,
    }


def legacy_metrics(gt: dict[str, Any], ghidra_funcs: list[dict[str, Any]],
                   naming_map_path: Path, ts_dir: Optional[Path]) -> dict[str, Any]:
    """Eski harness sayısı (mac_f1_eval / benchmark_runner Mode 3) — tarihsel köprü.

    Aynı GT, eski SKIP önekleri ve eski tanım (TP=exact+semantic+partial,
    FP=wrong, FN=missing; GT'siz FUN_xxx 'unverified'). Kod YENİDEN YAZILMAZ,
    ``BenchmarkRunner``'ın kendisi çağrılır.
    """
    from tests.benchmark.benchmark_runner import BenchmarkRunner

    offset, _ = derive_image_offset(ghidra_funcs, _hex(gt["entry"]), gt["elf_type"])
    legacy_gt: dict[str, str] = {}
    for f in gt["functions"]:
        name = f["names"][0]
        if name.startswith(LEGACY_SKIP_PREFIXES):
            continue
        legacy_gt[f"FUN_{_hex(f['addr']) + offset:08x}"] = name
    runner = BenchmarkRunner(output_dir=None)
    naming_map = runner._load_naming_map(naming_map_path)
    unresolved = runner.collect_unresolved_funs(ts_dir)
    comparisons = runner._compare_maps(legacy_gt, naming_map, unresolved_funs=unresolved)
    m = runner.calculator.calculate_metrics(comparisons)
    return {
        "definition": "legacy benchmark_runner (TP=exact+semantic+partial, FN=missing only)",
        "gt_symbols": len(legacy_gt),
        "precision": round(m.precision, 4),
        "recall": round(m.recall, 4),
        "f1": round(m.f1, 4),
        "exact": m.exact_matches, "semantic": m.semantic_matches,
        "partial": m.partial_matches, "wrong": m.wrong_names,
        "missing": m.missing_names, "unverified": m.unverified_names,
    }


def score_run(gt_path: Path, run_dir: Path, *, naming_map_path: Optional[Path] = None,
              with_legacy: bool = True) -> dict[str, Any]:
    """Bir koşu dizinini puanla + koşunun doğru binary üzerinde yapıldığını doğrula."""
    gt = json.loads(Path(gt_path).read_text(encoding="utf-8"))
    art = find_run_artifacts(run_dir)
    if art["ghidra_functions"] is None:
        raise FileNotFoundError(f"{run_dir}: ghidra_functions.json yok (koşu başarısız?)")
    nm_path = Path(naming_map_path) if naming_map_path else art["naming_map"]
    if nm_path is None:
        raise FileNotFoundError(f"{run_dir}: naming_map.json yok")
    ghidra_funcs = load_ghidra_functions(art["ghidra_functions"])
    result = score(gt, ghidra_funcs, load_naming_map(nm_path))

    checks: dict[str, Any] = {"ambiguous_workspace": art["ambiguous"]}
    if art["target_info"] is not None:
        ti = json.loads(art["target_info"].read_text(encoding="utf-8"))
        checks["analyzed_sha256_matches_gt"] = ti.get("file_hash") == gt["stripped_sha256"]
    else:
        checks["analyzed_sha256_matches_gt"] = None
    checks["ghidra_named_scored"] = len(result["ghidra_named_scored"])
    result["checks"] = checks
    result["inputs"] = {
        "gt": str(gt_path),
        "ghidra_functions": str(art["ghidra_functions"]),
        "naming_map": str(nm_path),
        "naming_map_sha256": sha256_file(nm_path),
    }
    if with_legacy:
        try:
            result["legacy"] = legacy_metrics(gt, ghidra_funcs, nm_path, art["ts_dir"])
        except Exception as exc:  # köprü sayı; ana ölçümü düşürmesin
            result["legacy"] = {"error": f"{type(exc).__name__}: {exc}"}
    return result


def aggregate(results: list[dict[str, Any]]) -> dict[str, Any]:
    """Binary sonuçlarını birleştir: mikro (havuzlanmış TP/FP) + makro (F1 ortalaması)."""
    if not results:
        return {}
    out: dict[str, Any] = {"binaries": len(results)}
    for key in ("strict", "lenient"):
        tp = sum(r[key]["tp"] for r in results)
        fp = sum(r[key]["fp"] for r in results)
        n = sum(r["gt"]["scored"] for r in results)
        micro = _prf(tp, fp, n)
        macro = {m: round(sum(r[key][m] for r in results) / len(results), 4)
                 for m in ("precision", "recall", "f1")}
        out[key] = {"micro": micro, "macro": macro}
    det = sum(r["detected"]["code"] for r in results)
    hit = sum(r["coverage"]["gt_in_detected"] for r in results)
    out["coverage"] = {"gt_in_detected": hit, "detected_code": det,
                       "ratio": round(hit / det, 4) if det else 0.0}
    out["gt_scored"] = sum(r["gt"]["scored"] for r in results)
    return out


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _print_score(r: dict[str, Any]) -> None:
    s, lz, c = r["strict"], r["lenient"], r["coverage"]
    print(f"{r['corpus']}/{r['binary']}: GT={r['gt']['functions']} (puanlanan {r['gt']['scored']}) "
          f"tespit={r['detected']['ghidra_total']} (kod {r['detected']['code']}) "
          f"kapsama={c['ratio']:.1%}")
    print(f"  strict : TP={s['tp']} FP={s['fp']} FN={s['fn']}  "
          f"P={s['precision']:.3f} R={s['recall']:.3f} F1={s['f1']:.3f}")
    print(f"  lenient: TP={lz['tp']} FP={lz['fp']} FN={lz['fn']}  "
          f"P={lz['precision']:.3f} R={lz['recall']:.3f} F1={lz['f1']:.3f}")
    print(f"  kırılım: {r['breakdown']}  GT-dışı isimli={r['outside_gt']['named_non_generic']}")


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("gt", help="debug+stripped çiftinden GT JSON üret")
    g.add_argument("--debug", type=Path, required=True)
    g.add_argument("--stripped", type=Path, required=True)
    g.add_argument("--corpus", default="")
    g.add_argument("--binary", default="")
    g.add_argument("--out", type=Path, required=True)

    s = sub.add_parser("score", help="bir karadul koşusunu puanla")
    s.add_argument("--gt", type=Path, required=True)
    s.add_argument("--run-dir", type=Path, required=True,
                   help="ws/ (--output-dir) ve out/ (--output) içeren koşu dizini")
    s.add_argument("--naming-map", type=Path, default=None)
    s.add_argument("--no-legacy", action="store_true")
    s.add_argument("--json", type=Path, default=None, help="sonucu JSON'a yaz")

    args = ap.parse_args(argv)
    if args.cmd == "gt":
        gt = extract_gt(args.debug, args.stripped, corpus=args.corpus, binary=args.binary)
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(gt, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
        print(f"{args.out}: {gt['counts']}")
        return 0
    result = score_run(args.gt, args.run_dir, naming_map_path=args.naming_map,
                       with_legacy=not args.no_legacy)
    _print_score(result)
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(result, indent=1, ensure_ascii=False) + "\n",
                             encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
