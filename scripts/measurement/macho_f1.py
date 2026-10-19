#!/usr/bin/env python3
"""Mach-O fonksiyon-ismi puanlayıcısı (karadul) — Mac ölçüm hattının puanlama kaynağı.

Sembollü özgün Mach-O'nun ``nm`` tablosu gerçek veridir (GT). Karadul yalnız
Apple ``/usr/bin/strip`` ile soyulmuş kopyayı görür; GT ona hiçbir zaman verilmez,
puanlayıcı yalnız koşu SONRASI okur. İsim kuralları (normalizasyon, jenerik isim,
strict/lenient eşleşme) projenin tek kaynağından gelir: ``function_f1.py``.
Bu dosya yalnız Mach-O'ya özgü kısmı ekler: GT okuma, popülasyon, derleyici
parçası sınıfları ve sonek indirgeme.

Tanımlar (gerekçeler ``scripts/measurement/README.md`` §Mac)
------------------------------------------------------------
GT
    ``/usr/bin/nm -n -U <özgün>`` çıktısındaki ``T``/``t`` (``__TEXT,__text``)
    semboller; ``__mh_execute_header`` hariç. Aynı adresteki adlar tek
    fonksiyondur (takma ad; tmux'ta ortak gövdeli ``*_RB_NEXT`` aileleri).
    nm mutlak yoldan çağrılır: PATH'te ``/opt/anaconda3/bin/nm`` önde.
Popülasyon (isim bekleyen)
    GT'de olup strip'li kopyada Ghidra'nın thunk OLMAYAN ve kendisinin
    adlandıramadığı (jenerik adlı: ``FUN_``, ``entry`` ...) fonksiyonları.
    Dışarıda kalanlar ayrı sayılır:
      - ``undetected``: o adreste thunk olmayan Ghidra fonksiyonu yok
        (``undetected_thunk``: Ghidra thunk diyor; ``undetected_missing``: hiç yok);
      - ``ghidra_known_from_exports``: adı Ghidra kendisi biliyor (export trie,
        FID). Apple strip'te ~0 olmalı; ``GHIDRA_KNOWN_WARN_FRACTION`` aşılırsa uyarı.
Sınıf (``sinif``)
    ``program`` | ``cold`` | ``outlined``. Derleyici parçaları (``foo.cold.N``
    sıcak-soğuk bölme, ``OUTLINED_FUNCTION_N`` makine dışlayıcısı) kaynakta
    fonksiyon değildir; ayrı sınıfta raporlanır (plan v2 §4 "Payda"). Başlık
    sayısı ``siniflar.program``'dır. Eski özet anahtarları (``tp``, ``wrong`` ...)
    15 Ekim puanlayıcısıyla süreklilik için bütün sınıfları birlikte sayar.
Durum (strict, function_f1 ile aynı kural)
    ``tp``: normalize(temel(tahmin)) == normalize(temel(GT adlarından biri)).
    ``wrong``: jenerik olmayan yanlış tahmin. ``unnamed``: tahmin yok ya da jenerik.
    temel(): ``SUFFIX_RULES`` eklerini (``.cold.N``, ``.llvm.<sayı>``,
    ``.__uniq.<sayı>``, ``$INODE64`` gibi Darwin varyantları) soyar.
lenient
    ``tp`` ya da ``function_f1.match_lenient`` (exact/semantic/partial) tutan ``wrong``.
Tahmin
    Yalnız karadul'un naming_map'i (``function_f1.lookup_prediction``); Ghidra'nın
    kendi koyduğu ad karadul'un iddiası değildir.
Erişim sınıfı (``erisim``, ÖL-3; strip'li ikili verilirse)
    ``dogrudan``: koşunun ``ghidra_call_graph.json``'ında en az bir çağıranı var
    (öz-kenar hariç). ``tablo``: çağıranı yok, ama strip'li ikilideki bir rebase
    fixup'ı (``xcrun dyld_info -fixups``; chained fixup'lar dahil) tam fonksiyon
    başını gösteriyor. ``referanssiz``: ikisi de yok. Erişim tablosu program sınıfı
    içinde verilir. ``referanssiz`` için tanı: kodda adresi alınanlar (``adrp``+``add``
    / ``adr``) ve kuyruk çağrısıyla (``b`` / ``b.cond``) gidilenler (objdump taraması).
Talimat (``talimat``)
    Ghidra fonksiyon gövdesi baytı / 4 (arm64). Sınıf bloklarında sayıyla kapsamın
    yanında talimat ağırlıklı kapsam, doğruluk (P) ve R.

Kullanım
--------
    # GT çıkar
    python scripts/measurement/macho_f1.py gt --orig <özgün> --stripped <strip'li> --out <gt.json>
    # Bir koşuyu puanla (macho_score.json koşu dizinine yazılır; --out ile başka yere)
    python scripts/measurement/macho_f1.py score --gt <gt.json> --run-dir <koşu> [--stripped <strip'li>]
    python scripts/measurement/macho_f1.py score --orig <özgün> --run-dir <koşu> --out <json>
"""
from __future__ import annotations

import argparse
import bisect
import json
import math
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Iterable, Optional

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import function_f1 as f1  # noqa: E402
from function_f1 import (  # noqa: E402
    find_run_artifacts,
    is_generic_name,
    load_ghidra_functions,
    load_naming_map,
    lookup_prediction,
    match_lenient,
    match_strict,
    sha256_file,
)

MACHO_GT_SCHEMA = "karadul-macho-gt/1"
MACHO_SCORE_SCHEMA = "karadul-macho-f1/1"
SCORE_FILE_NAME = "macho_score.json"

# PATH'te /opt/anaconda3/bin/nm önde (bkz. README §Mac tuzaklar); daima mutlak yol.
NM_PATH = "/usr/bin/nm"
XCRUN_PATH = "/usr/bin/xcrun"
OBJDUMP_PATH = "/usr/bin/objdump"   # Apple llvm-objdump
TOOL_TIMEOUT_S = 120
MACH_HEADER_SYMBOL = "__mh_execute_header"
# nm sembol türleri: T = dışa açık, t = yerel; ikisi de (__TEXT,__text) bölümünde.
GT_SYMBOL_TYPES = frozenset({"T", "t"})
_NM_LINE_RE = re.compile(r"^([0-9A-Fa-f]+) ([A-Za-z]) (.+)$")
# Çok mimarili (fat) ikilide nm her mimariyi ayrı başlıkla yazar; adresler karışır.
_NM_FAT_MARKER = "(for architecture"

# Sınıflar. Bir GT fonksiyonunun BÜTÜN adları aynı parça kuralına uyuyorsa o sınıftadır.
CLASS_PROGRAM = "program"
CLASS_COLD = "cold"
CLASS_OUTLINED = "outlined"
CLASS_ORDER = (CLASS_PROGRAM, CLASS_COLD, CLASS_OUTLINED)
FRAGMENT_CLASS_RULES = (
    # clang/GCC sıcak-soğuk bölme: _grid_check_is_clear.cold.1
    (CLASS_COLD, re.compile(r"\.cold(?:\.\d+)?$")),
    # LLVM makine dışlayıcısı (MachineOutliner): _OUTLINED_FUNCTION_0
    (CLASS_OUTLINED, re.compile(r"^_?OUTLINED_FUNCTION_\d+$")),
)

# Eşleştirmede adın sonundan soyulan ekler (temel ada indirgeme). GT'ye ve tahmine
# simetrik uygulanır, sabit noktaya kadar tekrarlanır. GCC ekleri (.constprop/.isra/
# .part/.lto_priv/.clone) zaten normalize_name içinde (metrics.py FIX-4).
SUFFIX_RULES = (
    re.compile(r"\.cold(?:\.\d+)?$"),            # sıcak-soğuk bölme parçası
    re.compile(r"\.llvm\.\d+$"),                 # ThinLTO'nun dışa açtığı yerel sembol
    re.compile(r"\.__uniq\.\d+$"),               # -funique-internal-linkage-names
    re.compile(r"(?<=[A-Za-z0-9])\$[A-Za-z0-9_]+$"),  # Darwin varyantı: $INODE64, $DARWIN_EXTSN, $NOCANCEL
)

# Ghidra'nın kendisinin adlandırdığı GT fonksiyonlarının oranı bunu aşarsa uyarı
# (Apple strip export trie'yi boşaltır; isimler sızıyor olabilir).
GHIDRA_KNOWN_WARN_FRACTION = 0.01
# GT fonksiyonlarının bu orandan azı Ghidra'da bulunursa adres eşlemesi şüphelidir.
MIN_GT_DETECTION_FRACTION = 0.9
# Oranların %95 güven aralığı (Wilson; plan v2 §3 madde 4).
WILSON_Z_95 = 1.959963984540054
_ROUND = 4

# --- ÖL-3: erişim sınıfları ve talimat ağırlığı (plan v2 §4 "Payda") ---
ACCESS_DIRECT = "dogrudan"        # çağrı grafında en az bir çağıranı var (öz-kenar hariç)
ACCESS_TABLE = "tablo"            # çağıranı yok; bir veri işaretçisi fonksiyon başını gösteriyor
ACCESS_NONE = "referanssiz"       # ikisi de yok
ACCESS_ORDER = (ACCESS_DIRECT, ACCESS_TABLE, ACCESS_NONE)
CALL_GRAPH_FILE = "ghidra_call_graph.json"
# arm64'te her komut 4 bayt: talimat = Ghidra gövde baytı / 4.
ARM64_INSN_BYTES = 4
FIXUP_REBASE = "rebase"
_FIXUPS_HEADER = "-fixups:"
# adrp ile add/ldr arasındaki en çok komut sayısı. Uzak eşleşme bayat sayfadır:
# htop'ta 'add x20, x20, #0x8' döngü artışı 2219 komut önceki adrp ile eşleşip
# bir fonksiyon başına denk geliyordu (yanlış pozitif).
ADRP_PAIR_WINDOW = 16
# İlk işleneni hedef yazmaç OLMAYAN komutlar (yazmacın sayfa bilgisini silmez).
NON_WRITING_MNEMONICS = frozenset({
    "str", "stp", "stur", "strb", "strh", "sturb", "sturh", "stlr", "stlrb", "stlrh",
    "cmp", "cmn", "tst", "ccmp", "ccmn", "cbz", "cbnz", "tbz", "tbnz",
    "b", "bl", "br", "blr", "ret", "prfm",
})
_INSN_RE = re.compile(r"^\s*([0-9a-fA-F]+):\s+(\S+)\s*(.*)$")
_HEX_TARGET_RE = re.compile(r"^0x([0-9a-fA-F]+)")
_GPR_RE = re.compile(r"^[xw](\d+)$")   # wN yazımı xN'i de siler (sıfırla genişletme)
_IMM_RE = re.compile(r"^#(0x[0-9a-fA-F]+|\d+)$")
# Talimat bilgisinden blok sayaçları.
_BLOCK_COUNT_KEYS = ("population", "named", "tp", "wrong", "unnamed", "lenient_tp")
_TALIMAT_KEYS = ("population", "named", "tp")


# ---------------------------------------------------------------------------
# İsim kuralları (Mach-O'ya özgü kısım)
# ---------------------------------------------------------------------------

def reduce_suffixes(name: str) -> str:
    """Derleyici/bağlayıcı eklerini soyup temel adı döndür (boş ada asla indirgemez)."""
    cur = name
    while True:
        for rule in SUFFIX_RULES:
            new = rule.sub("", cur)
            if new != cur and new.strip("_"):
                cur = new
                break
        else:
            return cur


def fragment_class(names: Iterable[str]) -> str:
    """GT adlarından sınıf: hepsi aynı parça kuralına uyuyorsa o, değilse ``program``."""
    names = list(names)
    for cls, rule in FRAGMENT_CLASS_RULES:
        if names and all(rule.search(n) for n in names):
            return cls
    return CLASS_PROGRAM


def judge(predicted: Optional[str], gt_names: list[str], addr: int) -> tuple[str, bool]:
    """(durum, lenient). Durum: tp | wrong | unnamed (function_f1 strict kuralı)."""
    if predicted is None or is_generic_name(predicted, [addr]):
        return "unnamed", False
    base_pred = reduce_suffixes(predicted)
    base_gt = [reduce_suffixes(g) for g in gt_names]
    if match_strict(predicted, gt_names) or match_strict(base_pred, base_gt):
        return "tp", True
    lenient = match_lenient(predicted, gt_names) or match_lenient(base_pred, base_gt)
    return "wrong", lenient


def wilson_interval(k: int, n: int, z: float = WILSON_Z_95) -> Optional[list[float]]:
    """k/n oranının Wilson güven aralığı [alt, üst]; n=0 ise None (ölçülemez)."""
    if n <= 0:
        return None
    p = k / n
    denom = 1 + z * z / n
    center = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return [round(max(0.0, center - half), _ROUND), round(min(1.0, center + half), _ROUND)]


# ---------------------------------------------------------------------------
# GT (nm)
# ---------------------------------------------------------------------------

def run_nm(path: Path, nm_path: str = NM_PATH) -> str:
    """``nm -n -U`` çıktısı. nm yolu mutlak olmalı (conda nm tuzağı)."""
    if not Path(nm_path).is_absolute():
        raise ValueError(f"nm yolu mutlak olmalı (PATH'teki conda nm'ye düşmemek için): {nm_path!r}")
    return subprocess.run([nm_path, "-n", "-U", str(path)], capture_output=True, text=True,
                          check=True, timeout=TOOL_TIMEOUT_S).stdout


def nm_version(nm_path: str = NM_PATH) -> str:
    out = subprocess.run([nm_path, "-V"], capture_output=True, text=True, timeout=TOOL_TIMEOUT_S)
    return " / ".join(line.strip() for line in (out.stdout or out.stderr).splitlines()[:2])


def parse_nm(text: str) -> dict[int, list[str]]:
    """nm metninden adres -> ad listesi (T/t, ``__mh_execute_header`` hariç; nm sırası korunur)."""
    if _NM_FAT_MARKER in text:
        raise ValueError("çok mimarili ikili: GT tek mimariden çıkarılmalı (önce lipo -thin)")
    by_addr: dict[int, list[str]] = {}
    for line in text.splitlines():
        m = _NM_LINE_RE.match(line.strip())
        if not m or m.group(2) not in GT_SYMBOL_TYPES:
            continue
        name = m.group(3)
        if name == MACH_HEADER_SYMBOL:
            continue
        names = by_addr.setdefault(int(m.group(1), 16), [])
        if name not in names:
            names.append(name)
    return by_addr


def gt_from_binary(orig: Path, nm_path: str = NM_PATH) -> dict[int, list[str]]:
    return parse_nm(run_nm(orig, nm_path))


def build_gt(orig: Path, *, binary: str = "", stripped: Optional[Path] = None,
             nm_path: str = NM_PATH) -> dict[str, Any]:
    """Özgün ikiliden GT JSON'u (macho_measure prepare yazar)."""
    by_addr = gt_from_binary(orig, nm_path)
    functions = [{"addr": f"0x{a:x}", "names": names, "sinif": fragment_class(names)}
                 for a, names in sorted(by_addr.items())]
    cls_counts = Counter(fn["sinif"] for fn in functions)
    return {
        "schema": MACHO_GT_SCHEMA,
        "binary": binary or orig.name,
        "orig_sha256": sha256_file(orig),
        "stripped_sha256": sha256_file(stripped) if stripped else None,
        "nm": {"path": nm_path, "version": nm_version(nm_path), "args": "-n -U"},
        "functions": functions,
        "counts": {
            "functions": len(functions),
            "names": sum(len(fn["names"]) for fn in functions),
            **{c: cls_counts.get(c, 0) for c in CLASS_ORDER},
        },
    }


def gt_from_json(gt: dict[str, Any]) -> dict[int, list[str]]:
    return {int(fn["addr"], 16): list(fn["names"]) for fn in gt["functions"]}


# ---------------------------------------------------------------------------
# Erişim sınıfları (ÖL-3): çağrı grafı + veri işaretçileri + kod taraması
# ---------------------------------------------------------------------------

def read_fixups(path: Path) -> str:
    """``xcrun dyld_info -fixups`` çıktısı (chained fixup zincirlerini ve klasik rebase'i çözer)."""
    return subprocess.run([XCRUN_PATH, "dyld_info", "-fixups", str(path)], capture_output=True,
                          text=True, check=True, timeout=TOOL_TIMEOUT_S).stdout


def parse_dyld_fixups(text: str) -> list[dict[str, Any]]:
    """dyld_info satırları -> [{segment, section, slot, kind, target}].

    Rebase hedefi mutlak sanal adrestir (int); bind hedefi ``kütüphane/sembol`` metnidir.
    Çıktı tanınmazsa ya da birden çok mimari varsa hata (sessiz geçiş yok).
    """
    if _FIXUPS_HEADER not in text:
        raise ValueError("dyld_info çıktısında '-fixups:' bölümü yok; veri işaretçileri okunamadı")
    if sum(1 for ln in text.splitlines() if ln.rstrip().endswith("]:")) > 1:
        raise ValueError("çok mimarili ikili: fixup'lar tek mimariden okunmalı")
    out = []
    for ln in text.splitlines():
        parts = ln.split()
        if len(parts) < 5 or not parts[2].lower().startswith("0x"):
            continue
        kind = parts[3]
        target: Any = int(parts[4], 16) if kind == FIXUP_REBASE else " ".join(parts[4:])
        out.append({"segment": parts[0], "section": parts[1], "slot": int(parts[2], 16),
                    "kind": kind, "target": target})
    return out


def pointer_targets(fixups: list[dict[str, Any]]) -> Counter[int]:
    """Rebase yuvalarının hedefleri -> yuva sayısı (bind'ler dış semboldür, sayılmaz)."""
    return Counter(f["target"] for f in fixups if f["kind"] == FIXUP_REBASE)


def read_disassembly(path: Path) -> str:
    return subprocess.run([OBJDUMP_PATH, "-d", "--no-show-raw-insn", str(path)], capture_output=True,
                          text=True, check=True, timeout=TOOL_TIMEOUT_S).stdout


def _imm(text: str) -> Optional[int]:
    m = _IMM_RE.match(text.strip())
    return int(m.group(1), 0) if m else None


def _hex_target(text: str) -> Optional[int]:
    m = _HEX_TARGET_RE.match(text)
    return int(m.group(1), 16) if m else None


def scan_code_refs(disasm: str, starts: Iterable[int]) -> dict[str, set[int]]:
    """objdump metninde fonksiyon başına kod içi referanslar (yalnız tanı amaçlı).

    ``address_taken``: ``adrp xN`` + ``ADRP_PAIR_WINDOW`` komut içinde ``add xD, xN, #imm``
    ya da ``adr xD, hedef`` ile adresi hesaplanan fonksiyon başları (geri çağırma).
    Hedef yazmacı başka bir komutla yazılırsa sayfa bilgisi silinir.
    ``tail_called``: başka bir fonksiyonun içinden ``b`` / ``b.cond`` ile gidilen fonksiyon
    başları (içeren fonksiyon = başlangıcı komut adresinden küçük-eşit en büyük başlangıç).
    """
    start_list = sorted(set(starts))
    start_set = set(start_list)
    pages: dict[str, tuple[int, int]] = {}
    taken: set[int] = set()
    tail: set[int] = set()
    n = 0
    for line in disasm.splitlines():
        m = _INSN_RE.match(line)
        if not m:
            continue
        n += 1
        pc, mnem = int(m.group(1), 16), m.group(2)
        args = [a.strip() for a in m.group(3).split(";")[0].split(",")]
        target = _hex_target(args[1]) if len(args) >= 2 else None
        if mnem == "adrp" and target is not None:
            pages[args[0]] = (target, n)
            continue
        if mnem == "add" and len(args) == 3 and args[1] in pages:
            page, at = pages[args[1]]
            imm = _imm(args[2])
            if imm is not None and n - at <= ADRP_PAIR_WINDOW and page + imm in start_set:
                taken.add(page + imm)
        elif mnem == "adr" and target is not None and target in start_set:
            taken.add(target)
        elif mnem == "b" or mnem.startswith("b."):
            dest_fn = _hex_target(args[0]) if args else None
            i = bisect.bisect_right(start_list, pc) - 1
            if dest_fn in start_set and (i < 0 or start_list[i] != dest_fn):
                tail.add(dest_fn)
        dest = _GPR_RE.match(args[0]) if args else None
        if dest and mnem not in NON_WRITING_MNEMONICS:
            pages.pop(f"x{dest.group(1)}", None)
    return {"address_taken": taken, "tail_called": tail}


def load_call_graph(path: Path) -> dict[int, set[int]]:
    """ghidra_call_graph.json -> fonksiyon başı -> çağıranlar (öz-kenar hariç)."""
    nodes = json.loads(Path(path).read_text(encoding="utf-8"))["nodes"]
    out: dict[int, set[int]] = {}
    for key, node in nodes.items():
        addr = int(key, 16)
        out[addr] = {int(c["address"], 16) for c in node.get("callers", []) if c.get("address")} - {addr}
    return out


def access_class(addr: int, callers: dict[int, set[int]], pointers: set[int]) -> str:
    """dogrudan > tablo > referanssiz (öncelik sırası)."""
    if callers.get(addr, set()) - {addr}:
        return ACCESS_DIRECT
    if addr in pointers:
        return ACCESS_TABLE
    return ACCESS_NONE


def access_inputs(ts_dir: Path, stripped: Path, ghidra_funcs: list[dict[str, Any]]
                  ) -> tuple[dict[int, set[int]], set[int], dict[str, set[int]], dict[str, Any]]:
    """Koşunun çağrı grafı + strip'li ikilinin fixup'ları + kod taraması; künyesiyle."""
    cg_path = Path(ts_dir) / "static" / CALL_GRAPH_FILE
    callers = load_call_graph(cg_path)
    fixups = parse_dyld_fixups(read_fixups(stripped))
    ptr = pointer_targets(fixups)
    starts = {fn["addr"] for fn in ghidra_funcs}
    code_refs = scan_code_refs(read_disassembly(stripped), starts)
    info = {
        "call_graph": str(cg_path),
        "stripped": str(stripped),
        "stripped_sha256": sha256_file(stripped),
        "fixups": {"rebase": sum(ptr.values()),
                   "bind": sum(1 for f in fixups if f["kind"] != FIXUP_REBASE),
                   "rebase_to_function_start": sum(c for t, c in ptr.items() if t in starts),
                   "functions_pointed": len(set(ptr) & starts)},
        "code_scan": {"address_taken_functions": len(code_refs["address_taken"]),
                      "tail_called_functions": len(code_refs["tail_called"]),
                      "adrp_pair_window": ADRP_PAIR_WINDOW},
    }
    return callers, set(ptr), code_refs, info


# ---------------------------------------------------------------------------
# Puanlama
# ---------------------------------------------------------------------------

def _ratio(k: int, n: int) -> float:
    return round(k / n, _ROUND) if n else 0.0


def block_from_counts(c: dict[str, Any]) -> dict[str, Any]:
    """Sayaçlardan sınıf bloğu: P = TP/(TP+yanlış), R = TP/popülasyon (function_f1._prf).

    ``talimat`` alt bloğu: Ghidra gövde talimatlarıyla ağırlıklı kapsam (isim verilen /
    popülasyon), doğruluk (TP / isim verilen) ve R (TP / popülasyon). Ağırlıklı oran
    binom değildir; Wilson aralığı yalnız sayıyla oranlarda verilir.
    """
    pop, named, tp = c["population"], c["named"], c["tp"]
    prf = f1._prf(tp, c["wrong"], pop)
    block = {
        "population": pop, "named": named, "tp": tp, "wrong": c["wrong"], "unnamed": c["unnamed"],
        "precision": prf["precision"], "recall": prf["recall"], "f1": prf["f1"],
        "precision_ci95": wilson_interval(tp, named),
        "recall_ci95": wilson_interval(tp, pop),
        "lenient_tp": c["lenient_tp"],
        "lenient_precision": _ratio(c["lenient_tp"], named),
        "coverage": _ratio(named, pop),
        "coverage_ci95": wilson_interval(named, pop),
        "talimat": None,
    }
    t = c.get("talimat")
    if t is not None:
        block["talimat"] = {**{k: t[k] for k in _TALIMAT_KEYS},
                            "coverage": _ratio(t["named"], t["population"]),
                            "precision": _ratio(t["tp"], t["named"]),
                            "recall": _ratio(t["tp"], t["population"])}
    return block


def class_block(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Satırlardan sınıf bloğu (talimat bilgisi her satırda varsa ağırlıklı oranlarla)."""
    st = Counter(r["status"] for r in rows)
    counts: dict[str, Any] = {
        "population": len(rows), "named": st["tp"] + st["wrong"], "tp": st["tp"],
        "wrong": st["wrong"], "unnamed": st["unnamed"],
        "lenient_tp": sum(1 for r in rows if r["lenient"]), "talimat": None,
    }
    if all(r.get("talimat") is not None for r in rows):
        counts["talimat"] = {
            "population": sum(r["talimat"] for r in rows),
            "named": sum(r["talimat"] for r in rows if r["status"] in ("tp", "wrong")),
            "tp": sum(r["talimat"] for r in rows if r["status"] == "tp"),
        }
    return block_from_counts(counts)


def combine_blocks(blocks: list[dict[str, Any]]) -> dict[str, Any]:
    """Aynı şemadaki blokları topla (ikililer arası mikro toplam)."""
    counts: dict[str, Any] = {k: sum(b[k] for b in blocks) for k in _BLOCK_COUNT_KEYS}
    talimats = [b["talimat"] for b in blocks if b.get("talimat") is not None]
    counts["talimat"] = ({k: sum(t[k] for t in talimats) for k in _TALIMAT_KEYS}
                         if blocks and len(talimats) == len(blocks) else None)
    return block_from_counts(counts)


def score(gt: dict[int, list[str]], ghidra_funcs: list[dict[str, Any]],
          naming_map: dict[str, str], *, binary: str = "",
          callers: Optional[dict[int, set[int]]] = None, pointers: Optional[set[int]] = None,
          code_refs: Optional[dict[str, set[int]]] = None,
          insn_bytes: Optional[int] = ARM64_INSN_BYTES) -> dict[str, Any]:
    """GT (adres -> adlar) + Ghidra fonksiyonları + naming_map -> {"summary", "rows"}.

    ``callers`` ve ``pointers`` verilirse satırlara ``erisim`` yazılır (yoksa None);
    ``insn_bytes`` verilirse ``talimat`` = Ghidra gövde baytı // insn_bytes (yoksa None).
    """
    access_known = callers is not None and pointers is not None
    by_addr: dict[int, dict[str, Any]] = {}
    thunk_addrs: set[int] = set()
    for fn in ghidra_funcs:
        if fn["is_thunk"]:
            thunk_addrs.add(fn["addr"])
            continue
        by_addr.setdefault(fn["addr"], fn)

    stats: Counter[str] = Counter()
    rows: list[dict[str, Any]] = []
    known_names: list[str] = []
    for addr, names in sorted(gt.items()):
        gfn = by_addr.get(addr)
        if gfn is None:
            stats["undetected"] += 1
            stats["undetected_thunk" if addr in thunk_addrs else "undetected_missing"] += 1
            continue
        if not is_generic_name(gfn["name"], [addr]):
            # Ghidra adı kendisi biliyor -> isim kurtarma gerektirmiyor (popülasyon dışı)
            stats["ghidra_known"] += 1
            known_names.append(names[0])
            continue
        pred = lookup_prediction(naming_map, gfn)
        status, lenient = judge(pred, names, addr)
        stats[status] += 1
        # Eski anahtarlar (addr, gt, pred, status, lenient) 15 Ekim biçimiyle AYNEN;
        # etiket araçları bu şemayı okuyor. Yeni anahtarlar yalnız sona eklenir.
        rows.append({"addr": hex(addr), "gt": names, "pred": pred, "status": status,
                     "lenient": lenient, "sinif": fragment_class(names),
                     "erisim": access_class(addr, callers, pointers) if access_known else None,  # type: ignore[arg-type]
                     "talimat": gfn["size"] // insn_bytes if insn_bytes else None})

    # GT dışı adreslere verilen isimler (Ghidra'nın bölünmüş/fazladan fonksiyonları):
    # doğru mu yanlış mı bilinemez, TP/yanlış sayılmaz.
    outside = 0
    for fn in by_addr.values():
        if fn["addr"] in gt:
            continue
        pred = lookup_prediction(naming_map, fn)
        if pred and not is_generic_name(pred, [fn["addr"]]):
            outside += 1

    tp, wr, pop = stats["tp"], stats["wrong"], len(rows)
    named = tp + wr
    summary: dict[str, Any] = {
        "binary": binary,
        "gt_functions": len(gt),
        "ghidra_known_from_exports": stats["ghidra_known"],
        "undetected": stats["undetected"],
        "population_needing_names": pop,
        "named_by_karadul": named,
        "tp": tp, "wrong": wr, "unnamed": stats["unnamed"],
        "precision": round(tp / named, _ROUND) if named else None,
        "recall": round(tp / pop, _ROUND) if pop else None,
        "lenient_tp": sum(1 for r in rows if r["lenient"]),
        "named_outside_gt": outside,
    }
    # Eski tanım: F1 yuvarlanmış P ve R'den (15 Ekim özetiyle birebir süreklilik).
    p, r = summary["precision"] or 0, summary["recall"] or 0
    summary["f1"] = round(2 * p * r / (p + r), _ROUND) if (p + r) else 0.0

    # --- yeni anahtarlar (yalnız eklenir) ---
    summary["schema"] = MACHO_SCORE_SCHEMA
    summary["undetected_thunk"] = stats["undetected_thunk"]
    summary["undetected_missing"] = stats["undetected_missing"]
    summary["gt_names"] = sum(len(v) for v in gt.values())
    summary["gt_detection_ratio"] = (
        round((len(gt) - stats["undetected"]) / len(gt), _ROUND) if gt else 0.0)
    summary["ghidra_known_names"] = known_names
    summary["siniflar"] = {c: class_block([x for x in rows if x["sinif"] == c]) for c in CLASS_ORDER}
    # ÖL-3: erişim sınıfları program sınıfı içinde (parçalar ebeveynden dallanmayla girer).
    program_rows = [x for x in rows if x["sinif"] == CLASS_PROGRAM]
    summary["erisim_siniflari"] = None
    warnings: list[str] = []
    if access_known:
        assert callers is not None
        acc_blocks = {a: class_block([x for x in program_rows if x["erisim"] == a]) for a in ACCESS_ORDER}
        summary["erisim_siniflari"] = acc_blocks
        not_in_graph = sum(1 for x in rows if int(x["addr"], 16) not in callers)
        if not_in_graph:
            warnings.append(f"{not_in_graph} popülasyon fonksiyonu çağrı grafında düğüm değil "
                            "(çağıransız sayıldı)")
        if code_refs is not None:
            none_addrs = [int(x["addr"], 16) for x in program_rows if x["erisim"] == ACCESS_NONE]
            taken, tail = code_refs["address_taken"], code_refs["tail_called"]
            acc_blocks[ACCESS_NONE]["kod_referansi"] = {
                "adresi_alinan": sum(1 for a in none_addrs if a in taken),
                "kuyruk_cagrisi": sum(1 for a in none_addrs if a in tail),
                "hicbiri": sum(1 for a in none_addrs if a not in taken and a not in tail),
            }
    if gt and stats["ghidra_known"] / len(gt) > GHIDRA_KNOWN_WARN_FRACTION:
        warnings.append(
            f"Ghidra {stats['ghidra_known']} GT fonksiyonunu kendisi adlandırdı "
            f"(eşik %{GHIDRA_KNOWN_WARN_FRACTION:.0%}); export trie boşalmamış ya da isim "
            f"sızıyor olabilir: {known_names[:10]}")
    if gt and summary["gt_detection_ratio"] < MIN_GT_DETECTION_FRACTION:
        warnings.append(
            f"GT fonksiyonlarının yalnız {summary['gt_detection_ratio']:.1%}'i Ghidra'da bulundu "
            f"(eşik {MIN_GT_DETECTION_FRACTION:.0%}); adres eşlemesi şüpheli")
    summary["warnings"] = warnings
    return {"summary": summary, "rows": rows}


def score_run(run_dir: Path, *, gt_path: Optional[Path] = None, orig: Optional[Path] = None,
              binary: str = "", out: Optional[Path] = None, write: bool = True,
              stripped: Optional[Path] = None,
              insn_bytes: Optional[int] = ARM64_INSN_BYTES) -> dict[str, Any]:
    """Bir koşu dizinini puanla; ``macho_score.json``'u koşu dizinine (ya da ``out``'a) yaz.

    ``stripped`` (karadul'un analiz ettiği strip'li ikili) verilirse erişim sınıfları
    hesaplanır. Erişim girdisi okunamazsa isim puanı yine üretilir; hata
    ``summary.erisim_kaynaklari.error``'a ve uyarılara yazılır.
    """
    if (gt_path is None) == (orig is None):
        raise ValueError("GT kaynağı olarak ya gt_path ya da orig verilmeli (yalnız biri)")
    if gt_path is not None:
        gt_doc = json.loads(Path(gt_path).read_text(encoding="utf-8"))
        gt = gt_from_json(gt_doc)
        binary = binary or gt_doc.get("binary", "")
    else:
        assert orig is not None
        gt = gt_from_binary(Path(orig))
        binary = binary or Path(orig).name
    art = find_run_artifacts(Path(run_dir))
    if art["ghidra_functions"] is None or art["naming_map"] is None:
        raise FileNotFoundError(f"{run_dir}: ghidra_functions.json ya da naming_map.json yok "
                                f"(koşu başarısız?): {art}")
    ghidra_funcs = load_ghidra_functions(art["ghidra_functions"])
    callers = pointers = code_refs = None
    access_info: Optional[dict[str, Any]] = None
    if stripped is not None:
        try:
            callers, pointers, code_refs, access_info = access_inputs(
                art["ts_dir"], Path(stripped), ghidra_funcs)
        except (OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
            access_info = {"error": f"{type(exc).__name__}: {exc}"}
    result = score(gt, ghidra_funcs, load_naming_map(art["naming_map"]), binary=binary,
                   callers=callers, pointers=pointers, code_refs=code_refs, insn_bytes=insn_bytes)
    result["summary"]["erisim_kaynaklari"] = access_info
    if access_info and "error" in access_info:
        result["summary"]["warnings"].append(f"erişim sınıfları hesaplanamadı: {access_info['error']}")
    result["summary"]["inputs"] = {
        "gt": str(gt_path) if gt_path else f"nm {orig}",
        "ghidra_functions": str(art["ghidra_functions"]),
        "naming_map": str(art["naming_map"]),
        "naming_map_sha256": sha256_file(art["naming_map"]),
        "ambiguous_workspace": art["ambiguous"],
    }
    if write:
        dest = Path(out) if out else Path(run_dir) / SCORE_FILE_NAME
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(json.dumps(result, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    return result


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _fmt_ci(ci: Optional[list[float]]) -> str:
    return f"[{ci[0]:.3f}-{ci[1]:.3f}]" if ci else "[—]"


def print_summary(s: dict[str, Any]) -> None:
    print(f"{s['binary']}: GT={s['gt_functions']} thunk={s['undetected_thunk']} "
          f"yok={s['undetected_missing']} Ghidra-biliyor={s['ghidra_known_from_exports']} "
          f"isim-bekleyen={s['population_needing_names']} GT-dışı-isimli={s['named_outside_gt']}")
    print(f"  tümü (15 Ekim tanımı): isim={s['named_by_karadul']} TP={s['tp']} yanlış={s['wrong']} "
          f"isimsiz={s['unnamed']} P={s['precision']} R={s['recall']} F1={s['f1']} "
          f"lenient-TP={s['lenient_tp']}")
    blocks = [(c, s["siniflar"][c]) for c in CLASS_ORDER]
    if s.get("erisim_siniflari"):
        blocks += [(f"  {a}", s["erisim_siniflari"][a]) for a in ACCESS_ORDER]
    for c, b in blocks:
        t = b.get("talimat")
        tw = (f" | talimat: kapsam={t['coverage']:.3f} doğruluk={t['precision']:.3f} R={t['recall']:.3f}"
              if t else "")
        print(f"  {c:13s}: pop={b['population']} isim={b['named']} TP={b['tp']} yanlış={b['wrong']} "
              f"isimsiz={b['unnamed']} kapsam={b['coverage']:.3f}{_fmt_ci(b['coverage_ci95'])} "
              f"P={b['precision']:.3f}{_fmt_ci(b['precision_ci95'])} "
              f"R={b['recall']:.3f}{_fmt_ci(b['recall_ci95'])} F1={b['f1']:.3f}{tw}")
    kr = (s.get("erisim_siniflari") or {}).get(ACCESS_NONE, {}).get("kod_referansi")
    if kr:
        print(f"  referanssız tanısı: kodda adresi alınan {kr['adresi_alinan']}, kuyruk çağrısı "
              f"{kr['kuyruk_cagrisi']}, hiçbiri {kr['hicbiri']}")
    for w in s["warnings"]:
        print(f"  UYARI: {w}")


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("gt", help="özgün (sembollü) Mach-O'dan GT JSON üret")
    g.add_argument("--orig", type=Path, required=True)
    g.add_argument("--stripped", type=Path, default=None)
    g.add_argument("--binary", default="")
    g.add_argument("--out", type=Path, required=True)
    s = sub.add_parser("score", help="bir karadul koşusunu puanla")
    src = s.add_mutually_exclusive_group(required=True)
    src.add_argument("--gt", type=Path, help="prepare'in yazdığı GT JSON'u")
    src.add_argument("--orig", type=Path, help="özgün ikili (GT nm ile buradan çıkarılır)")
    s.add_argument("--run-dir", type=Path, required=True,
                   help="ws/ (--output-dir) ve out/ (--output) içeren koşu dizini")
    s.add_argument("--binary", default="")
    s.add_argument("--stripped", type=Path, default=None,
                   help="karadul'un analiz ettiği strip'li ikili (erişim sınıfları için)")
    s.add_argument("--out", type=Path, default=None,
                   help=f"sonuç yolu (varsayılan <koşu>/{SCORE_FILE_NAME})")
    args = ap.parse_args(argv)
    if args.cmd == "gt":
        gt = build_gt(args.orig, binary=args.binary, stripped=args.stripped)
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(gt, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
        print(f"{args.out}: {gt['counts']}")
        return 0
    res = score_run(args.run_dir, gt_path=args.gt, orig=args.orig, binary=args.binary, out=args.out,
                    stripped=args.stripped)
    print_summary(res["summary"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
