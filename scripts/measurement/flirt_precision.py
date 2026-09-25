#!/usr/bin/env python3
"""FLIRT bayt imzası seçicilik ölçümü (Mach-O arm64) -- isimlenen / doğru / yanlış.

Sembollü bir Mach-O'yu stripped gibi karadul'a verir ve FLIRT'ün verdiği
isimleri aynı dosyanın sembol tablosuyla ADRES bazında karşılaştırır.

Düzenek (``/private/tmp/flirt_debug/fp_check.py``'nin repo hâli):
  * Fonksiyon başlangıçları YALNIZ ``LC_FUNCTION_STARTS``'tan (stripped
    binary'de de vardır; sembol adresi kullanılmaz, gerçeği sızdırır).
    Her fonksiyon ``FUN_<adres>`` adıyla, uzunluğu bir sonraki başlangıca
    kadar olan aralıkla functions.json'a yazılır (Homebrew arm64 ``tree``'de
    Ghidra boyutuyla 118/118 aynı; ``--no-size`` ile 0 yazılır).
  * Eşleştirici pipeline'daki gibi çağrılır: ``BytePatternMatcher`` +
    ``min_naming_confidence`` (config) + imza sayısı eşiği aşıldığı için trie
    yolu (``--path linear`` ile linear).
  * Gerçek: ``__TEXT,__text`` içindeki TÜM semboller (T + t), adres -> isimler.

Sınıflar (isimlenen her fonksiyon için):
  doğru          FLIRT ismi o adresteki sembollerden biri
  yanlış         o adreste başka sembol var; ya da adreste sembol yok ama isim
                 binary'de BAŞKA bir adreste tanımlı (isim o fonksiyona ait değil)
  doğrulanamaz   adreste sembol yok ve isim binary'de hiç yok

``--size-diagnosis``: v1 eşleşmelerinden kaçı YALNIZ uzunluk kontrolüyle
elenirdi? Kaynak fonksiyonun uzunluğu, v1 üreticisinin kaynak kütüphanelerinden
(aynı isim + kütüphane) okunur; v1 deseni kaynağın bugünkü ilk 32 baytıyla aynı
değilse (kütüphane güncellenmiş) "kaynak değişmiş" diye ayrı sayılır.

Kullanım:
    python scripts/measurement/flirt_precision.py \
        /opt/homebrew/bin/redis-server /opt/homebrew/bin/jxl_from_tree \
        /opt/homebrew/lib/libzstd.1.5.7.dylib --size-diagnosis --json-out out.json
    # DB'ler varsayılan olarak depo kökünden: v1=signatures_homebrew_bytes.json,
    # v2=signatures_homebrew_bytes_v2.json (--db ETIKET=YOL ile değişir)

Pozitif kontrol (imza kaynağı DEĞİL ama aynı kodu içeren binary): Homebrew'un
libzstd.a'sını statik bağlayan küçük program; dylib'e göre adresler farklı,
yani maske kuralı gerçekten sınanır:
    printf '#include <zstd.h>\\nint main(void){return (int)ZSTD_versionNumber();}\\n' > z.c
    clang -O2 -I/opt/homebrew/include z.c \\
        -Wl,-force_load,/opt/homebrew/lib/libzstd.a -o zstd_static_forceload

2026-09-25 ölçümünde kümeler (ayrık):
  ayar (v2 kuralları buna bakılarak seçildi; 17 binary): yosys-abc, gtk4-icon-editor,
    verilator_bin, cmake, qmlls, gst-dots-viewer, elan-init, rsvg-convert, binwalk,
    rsaperf, vvp, upx, gcc-16, thrift, ccx_2.23, geosop, gpg
  değerlendirme: redis-server, jxl_from_tree, libzstd, zstd_static_forceload, tmux,
    srt-live-transmit, qmake, pk11ectest, benchmark_xl, ctest
"""
from __future__ import annotations

import argparse
import json
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
for _p in (REPO_ROOT, REPO_ROOT / "scripts" / "flirt"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from karadul.analyzers.byte_pattern_matcher import BytePatternMatcher  # noqa: E402
from karadul.analyzers.flirt_parser import FLIRTParser  # noqa: E402
from karadul.config import BinaryReconstructionConfig  # noqa: E402
import macho_arm64 as mo  # noqa: E402

DEFAULT_DBS = {
    "v1": REPO_ROOT / "signatures_homebrew_bytes.json",
    "v2": REPO_ROOT / "signatures_homebrew_bytes_v2.json",
}
_EXAMPLES = 5


def write_functions_json(img: mo.MachOImage, out: Path, *, with_size: bool) -> dict[int, int]:
    """LC_FUNCTION_STARTS -> Ghidra biçiminde functions.json; {adres: uzunluk} döner."""
    extents = mo.function_extents(img)
    out.write_text(json.dumps({"functions": [
        {"name": f"FUN_{a:x}", "address": f"{a:x}", "size": s if with_size else 0}
        for a, s in extents.items()
    ]}))
    return extents


def classify(
    matches: dict[str, dict[str, Any]],
    truth: dict[int, set[str]],
    all_names: set[str],
) -> dict[str, Any]:
    """Eşleşmeleri doğru / yanlış / doğrulanamaz diye ayır."""
    correct: list[tuple[int, str]] = []
    wrong: list[tuple[int, str, list[str]]] = []
    unverifiable: list[tuple[int, str]] = []
    for fun, info in matches.items():
        addr = int(fun.split("_", 1)[1], 16)
        name = info["matched_name"]
        here = truth.get(addr, set())
        if name in here:
            correct.append((addr, name))
        elif here or name in all_names:
            wrong.append((addr, name, sorted(here)[:2]))
        else:
            unverifiable.append((addr, name))
    return {"correct": correct, "wrong": wrong, "unverifiable": unverifiable}


def source_index() -> dict[tuple[str, str], tuple[int, bytes]]:
    """(kütüphane, isim) -> (kaynak fonksiyon uzunluğu, adresteki ham 32 bayt); takma adlar dahil.

    32 bayt fonksiyon uzunluğundan bağımsız okunur: v1 deseni de 32 bayttı ve
    kısa fonksiyonda sonraki fonksiyonun baytlarını içeriyordu.
    """
    import build_selective_signatures as bss

    idx: dict[tuple[str, str], tuple[int, bytes]] = {}
    for lib_path, label in bss.source_libraries():
        if not Path(lib_path).exists():
            continue
        try:
            img = mo.load_macho_arm64(lib_path)
            funcs = bss.extract_library_functions(lib_path, label)
        except (mo.MachOError, OSError, ValueError):
            continue
        for f in funcs:
            for n in f.names:
                idx.setdefault((label, n), (f.size, img.read_vm(f.address, 32)))
    return idx


def size_diagnosis(
    matches: dict[str, dict[str, Any]],
    classes: dict[str, Any],
    img: mo.MachOImage,
    extents: dict[int, int],
    src_idx: dict[tuple[str, str], tuple[int, bytes]],
) -> dict[str, dict[str, int]]:
    """v1 eşleşmelerinde uzunluk kontrolünün etkisi (sınıf başına)."""
    by_addr = {int(k.split("_", 1)[1], 16): v for k, v in matches.items()}
    out: dict[str, dict[str, int]] = {}
    for cls in ("correct", "wrong", "unverifiable"):
        c = {"eleniyor": 0, "kaliyor": 0, "kaynak_degismis_eleniyor": 0,
             "kaynak_degismis_kaliyor": 0, "kaynak_yok": 0}
        for item in classes[cls]:
            addr, name = item[0], item[1]
            src = src_idx.get((by_addr[addr]["library"], name))
            if src is None:
                c["kaynak_yok"] += 1
                continue
            src_size, src_head = src
            exact = src_head == img.read_vm(addr, 32)
            gone = src_size != extents[addr]
            key = ("" if exact else "kaynak_degismis_") + ("eleniyor" if gone else "kaliyor")
            c[key] += 1
        out[cls] = c
    return out


def measure_binary(
    path: Path,
    dbs: dict[str, list[Any]],
    *,
    method: str,
    with_size: bool,
    src_idx: dict | None,
) -> list[dict[str, Any]]:
    img = mo.load_macho_arm64(path)
    truth = {a: set(ns) for a, ns in mo.text_symbols(img, external_only=False).items()}
    all_names = {n for ns in truth.values() for n in ns}
    min_conf = BinaryReconstructionConfig().min_naming_confidence
    rows: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="flirt_precision_") as td:
        fj = Path(td) / "functions.json"
        extents = write_functions_json(img, fj, with_size=with_size)
        for label, sigs in dbs.items():
            matcher = BytePatternMatcher(min_confidence=min_conf)
            t0 = time.monotonic()
            res = getattr(matcher, method)(path, fj, sigs)
            elapsed = time.monotonic() - t0
            cls = classify(res.matches, truth, all_names)
            row = {
                "binary": path.name,
                "db": label,
                "functions": len(extents),
                "with_symbol": sum(1 for a in extents if a in truth),
                "scanned": res.functions_scanned,
                "named": res.total_matched,
                "correct": len(cls["correct"]),
                "wrong": len(cls["wrong"]),
                "unverifiable": len(cls["unverifiable"]),
                "selective": {
                    "prefix_hits": res.selective_prefix_hits,
                    "rejected_size": res.selective_rejected_size,
                    "rejected_crc": res.selective_rejected_crc,
                    "rejected_ref": res.selective_rejected_ref,
                    "ambiguous": res.selective_ambiguous,
                    "duplicate_name": res.selective_duplicate_name,
                },
                "seconds": round(elapsed, 2),
                "wrong_examples": [
                    {"addr": hex(a), "flirt": n, "truth": t} for a, n, t in cls["wrong"][:_EXAMPLES]
                ],
                "unverifiable_examples": [
                    {"addr": hex(a), "flirt": n} for a, n in cls["unverifiable"][:_EXAMPLES]
                ],
            }
            if src_idx is not None and label == "v1":
                row["size_diagnosis"] = size_diagnosis(res.matches, cls, img, extents, src_idx)
            rows.append(row)
    return rows


def _print_table(rows: list[dict[str, Any]]) -> None:
    print("| binary | DB | fonksiyon | taranan | isimlenen | doğru | yanlış | doğrulanamaz "
          "| belirsiz | isim tekrarı | red uzunluk | red CRC | red referans |")
    print("|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|")
    for r in rows:
        s = r["selective"]
        print(f"| {r['binary']} | {r['db']} | {r['functions']} | {r['scanned']} | {r['named']} "
              f"| {r['correct']} | {r['wrong']} | {r['unverifiable']} | {s['ambiguous']} "
              f"| {s['duplicate_name']} | {s['rejected_size']} | {s['rejected_crc']} "
              f"| {s['rejected_ref']} |")
    for r in rows:
        if r["wrong_examples"]:
            print(f"  {r['binary']} [{r['db']}] yanlış örnek: {r['wrong_examples']}")
        if "size_diagnosis" in r:
            print(f"  {r['binary']} [{r['db']}] uzunluk teşhisi: {r['size_diagnosis']}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("binaries", nargs="+", type=Path)
    ap.add_argument("--db", action="append", default=[], metavar="ETIKET=YOL",
                    help="imza DB'si (tekrarlanabilir); verilmezse v1 + v2 depo kökünden")
    ap.add_argument("--path", choices=("trie", "linear"), default="trie",
                    help="eşleştirici yolu (pipeline >50 imzada trie kullanır)")
    ap.add_argument("--no-size", action="store_true",
                    help="functions.json'a uzunluk 0 yaz (uzunluk bilinmiyor senaryosu)")
    ap.add_argument("--size-diagnosis", action="store_true",
                    help="v1 eşleşmelerinden kaçı yalnız uzunlukla elenirdi")
    ap.add_argument("--json-out", type=Path)
    args = ap.parse_args(argv)

    if args.db:
        db_paths = {}
        for item in args.db:
            label, _, p = item.partition("=")
            db_paths[label] = Path(p)
    else:
        db_paths = {k: v for k, v in DEFAULT_DBS.items() if v.exists()}
    if not db_paths:
        ap.error("imza DB'si bulunamadi")

    parser = FLIRTParser()
    dbs = {label: parser.load_json_signatures(p) for label, p in db_paths.items()}
    method = "match_unknown_functions_trie" if args.path == "trie" else "match_unknown_functions"
    src_idx = source_index() if args.size_diagnosis else None

    rows: list[dict[str, Any]] = []
    for b in args.binaries:
        try:
            rows.extend(measure_binary(b.resolve(), dbs, method=method,
                                       with_size=not args.no_size, src_idx=src_idx))
        except (mo.MachOError, OSError) as exc:
            print(f"ATLA {b}: {exc}", file=sys.stderr)
    _print_table(rows)
    if args.json_out:
        args.json_out.write_text(json.dumps({
            "dbs": {k: str(v) for k, v in db_paths.items()},
            "path": args.path,
            "with_size": not args.no_size,
            "rows": rows,
        }, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
