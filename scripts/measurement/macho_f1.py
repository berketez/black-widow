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

Kullanım
--------
    # GT çıkar
    python scripts/measurement/macho_f1.py gt --orig <özgün> --stripped <strip'li> --out <gt.json>
    # Bir koşuyu puanla (macho_score.json koşu dizinine yazılır; --out ile başka yere)
    python scripts/measurement/macho_f1.py score --gt <gt.json> --run-dir <koşu>
    python scripts/measurement/macho_f1.py score --orig <özgün> --run-dir <koşu> --out <json>
"""
from __future__ import annotations

import argparse
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
NM_TIMEOUT_S = 120
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
                          check=True, timeout=NM_TIMEOUT_S).stdout


def nm_version(nm_path: str = NM_PATH) -> str:
    out = subprocess.run([nm_path, "-V"], capture_output=True, text=True, timeout=NM_TIMEOUT_S)
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
# Puanlama
# ---------------------------------------------------------------------------

def class_block(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Bir sınıfın sayıları: P = TP/(TP+yanlış), R = TP/popülasyon (function_f1._prf)."""
    st = Counter(r["status"] for r in rows)
    tp, wrong = st["tp"], st["wrong"]
    named = tp + wrong
    prf = f1._prf(tp, wrong, len(rows))
    lenient_tp = sum(1 for r in rows if r["lenient"])
    return {
        "population": len(rows), "named": named, "tp": tp, "wrong": wrong,
        "unnamed": st["unnamed"],
        "precision": prf["precision"], "recall": prf["recall"], "f1": prf["f1"],
        "precision_ci95": wilson_interval(tp, named),
        "recall_ci95": wilson_interval(tp, len(rows)),
        "lenient_tp": lenient_tp,
        "lenient_precision": round(lenient_tp / named, _ROUND) if named else 0.0,
    }


def score(gt: dict[int, list[str]], ghidra_funcs: list[dict[str, Any]],
          naming_map: dict[str, str], *, binary: str = "") -> dict[str, Any]:
    """GT (adres -> adlar) + Ghidra fonksiyonları + naming_map -> {"summary", "rows"}."""
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
                     "lenient": lenient, "sinif": fragment_class(names)})

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
    warnings: list[str] = []
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
              binary: str = "", out: Optional[Path] = None, write: bool = True) -> dict[str, Any]:
    """Bir koşu dizinini puanla; ``macho_score.json``'u koşu dizinine (ya da ``out``'a) yaz."""
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
    result = score(gt, load_ghidra_functions(art["ghidra_functions"]),
                   load_naming_map(art["naming_map"]), binary=binary)
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
    for c in CLASS_ORDER:
        b = s["siniflar"][c]
        print(f"  {c:8s}: pop={b['population']} isim={b['named']} TP={b['tp']} yanlış={b['wrong']} "
              f"isimsiz={b['unnamed']} P={b['precision']:.3f}{_fmt_ci(b['precision_ci95'])} "
              f"R={b['recall']:.3f}{_fmt_ci(b['recall_ci95'])} F1={b['f1']:.3f} "
              f"lenient-P={b['lenient_precision']:.3f}")
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
    s.add_argument("--out", type=Path, default=None,
                   help=f"sonuç yolu (varsayılan <koşu>/{SCORE_FILE_NAME})")
    args = ap.parse_args(argv)
    if args.cmd == "gt":
        gt = build_gt(args.orig, binary=args.binary, stripped=args.stripped)
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(gt, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
        print(f"{args.out}: {gt['counts']}")
        return 0
    res = score_run(args.run_dir, gt_path=args.gt, orig=args.orig, binary=args.binary, out=args.out)
    print_summary(res["summary"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
