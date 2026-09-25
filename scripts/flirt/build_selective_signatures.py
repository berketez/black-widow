#!/usr/bin/env python3
"""Seçici (v2) FLIRT bayt imza DB'si üretici -- IDA FLIRT mantığı.

v1 (``scripts/build_byte_signatures.py`` -> ``signatures_homebrew_bytes.json``)
her ihraç edilen fonksiyonun yalnız ilk 32 baytını maskesiz saklıyordu; tipik
arm64 prologları bu baytları paylaştığı için imzaların kaynağında olmayan
binary'lerde isimlerin tamamı yanlıştı (redis-server 162/0, jxl_from_tree 104/0).

v2 girdisi (``karadul.analyzers.flirt_parser.build_selective_entry``):
  * ``byte_pattern`` + ``mask``: ilk 32 bayt, adrese bağlı bitler (ADRP/ADR,
    B/BL, LDR literal, ADRP'ye bağlı ``:lo12:`` ADD/LDR/STR) maskeli;
  * ``size``: fonksiyon uzunluğu (sonraki fonksiyon başlangıcına kadar);
  * ``crc_len`` + ``crc16``: ön ekten sonraki en fazla 255 baytın maskeli CRC16'sı;
  * ``aliases``: aynı adresteki diğer ihraç isimleri (tek imza, kanonik isim);
  * ``refs``: fonksiyon dışına giden B/BL'lerden hedefi aynı kütüphanede imzalı
    bir fonksiyon olanlar -- (ofset, isim). Eşleştirici hedefte o ofsetteki
    dallanmanın o isimle doğrulanmış bir fonksiyona gittiğini arar (IDA
    ``^OFFSET name``); çağrı hedefi maskelendiği için bayt olarak ikiz olan
    küçük sarmalayıcıları ayıran tek bilgi budur.
32 bayttan kısa fonksiyonlar imzalanmaz (ön ek fonksiyonun dışına taşar).
Çağrı referansı olmayan ve ``--min-content``'ten az içerik kelimesi taşıyan
fonksiyonlar (sarmalayıcı, yıkıcı thunk'ı, erişimci, enum->metin tablosu) da
imzalanmaz: başka programlarda maskeli olarak birebir tekrar ediyorlar.

Kaynak kütüphane listesi ``scripts/build_byte_signatures.py``'deki listedir
(tek kaynak). /opt/homebrew altındaki dosyalar yalnız OKUNUR. Çıktı YENİ bir
dosyadır; v1 DB'sinin ve ``sigs/``'in üzerine yazmayı reddeder.

Kullanım:
    python scripts/flirt/build_selective_signatures.py
    python scripts/flirt/build_selective_signatures.py --out /tmp/x.json
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import logging
import os
import sys
import time
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
_HERE = Path(__file__).resolve().parent
for _p in (REPO_ROOT, _HERE):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from karadul.analyzers.flirt_parser import (  # noqa: E402
    MASK_RULE_ARM64,
    SELECTIVE_ENTRY_KEY,
    SELECTIVE_MAX_CRC_LEN,
    SELECTIVE_MIN_CONTENT_WORDS,
    SELECTIVE_PREFIX_LEN,
    SELECTIVE_SIG_FORMAT,
    FLIRTParser,
    arm64_call_refs,
    build_selective_entry,
    is_weak_selective,
)
import macho_arm64 as mo  # noqa: E402

logger = logging.getLogger("build_selective_signatures")

DEFAULT_OUT = REPO_ROOT / "signatures_homebrew_bytes_v2.json"
# Üzerine yazılması yasak mevcut DB'ler (v1 + isim DB'si) ve sigs/ dizini.
_PROTECTED_NAMES = frozenset({"signatures_homebrew_bytes.json", "signatures_homebrew.json"})


@dataclass
class SourceFunction:
    """Kaynak kütüphanede ihraç edilen bir fonksiyon (aynı adresteki isimler tek kayıt)."""

    library: str
    names: list[str]   # names[0] kanonik, gerisi takma ad
    address: int
    size: int
    body: bytes


def source_libraries() -> list[tuple[str, str]]:
    """v1 üreticisinin kütüphane listesi (tek kaynak: scripts/build_byte_signatures.py)."""
    path = REPO_ROOT / "scripts" / "build_byte_signatures.py"
    spec = importlib.util.spec_from_file_location("_build_byte_signatures_v1", path)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return list(mod.PRIORITY_LIBRARIES) + list(mod.SYSTEM_LIBRARIES)


def canonical_name(names: list[str]) -> str:
    """Takma ad grubunun kanonik ismi: en kısa, eşitlikte alfabetik (deterministik)."""
    return min(names, key=lambda n: (len(n), n))


def extract_library_functions(lib_path: str | Path, label: str) -> list[SourceFunction]:
    """Kütüphanenin ``__text`` içindeki ihraç fonksiyonları (v1 ile aynı isim filtresi)."""
    img = mo.load_macho_arm64(lib_path)
    exported = mo.text_symbols(img, external_only=True)
    extents = mo.function_extents(img, extra_starts=list(exported))
    skip = FLIRTParser()._should_skip_symbol
    out: list[SourceFunction] = []
    for addr in sorted(exported):
        names = sorted({n for n in exported[addr] if not skip(n)})
        size = extents.get(addr, 0)
        if not names or size <= 0:
            continue
        body = img.read_vm(addr, size)
        if len(body) != size:
            continue
        canon = canonical_name(names)
        out.append(SourceFunction(label, [canon] + [n for n in names if n != canon], addr, size, body))
    return out


def select_signed(
    funcs: list[SourceFunction], *, min_size: int, min_content: int,
) -> tuple[dict[int, SourceFunction], dict[int, list[tuple[int, str]]], int]:
    """İmzalanacak fonksiyonlar, referansları ve zayıf diye elenen sayısı.

    Referans = fonksiyon dışına giden B/BL'nin hedefi İMZALANAN bir fonksiyonun
    başı (ofset, kanonik isim); imzasız hedef hedefte doğrulanamaz. Zayıf
    (referanssız + az içerik) fonksiyon elenince ona giden referanslar da düşer
    ve başka fonksiyonlar zayıflayabilir -> sabit noktaya kadar tekrarlanır.
    """
    signed = {f.address: f for f in funcs if f.size >= min_size}
    weak_total = 0
    while True:
        refs_of = {
            a: [
                (off, signed[t].names[0])
                for off, t in arm64_call_refs(f.body, a)
                if t in signed
            ]
            for a, f in signed.items()
        }
        weak = [
            a for a, f in signed.items()
            if is_weak_selective(f.body, bool(refs_of[a]), min_content)
        ]
        if not weak:
            return signed, refs_of, weak_total
        weak_total += len(weak)
        for a in weak:
            del signed[a]


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _signature_key(e: dict[str, Any]) -> tuple:
    """Eşleştiricinin ayırt edebildiği her şey: maskeli ön ek + uzunluk + CRC + referanslar."""
    return (
        e["mask_rule"], e["byte_pattern"], e["mask"], e["size"], e["crc_len"], e["crc16"],
        tuple(tuple(r) for r in e.get("refs", ())),
    )


def build(
    libraries: list[tuple[str, str]], *, min_size: int,
    min_content: int = SELECTIVE_MIN_CONTENT_WORDS,
) -> dict[str, Any]:
    """İmzaları üret; JSON'a yazılacak sözlüğü döndür."""
    entries: list[dict[str, Any]] = []
    sources: list[dict[str, Any]] = []
    seen: set[tuple] = set()
    for lib_path, label in libraries:
        p = Path(lib_path)
        src: dict[str, Any] = {"library": label, "path": str(p)}
        sources.append(src)
        if not p.exists():
            src["status"] = "bulunamadi"
            logger.info("  ATLA (bulunamadi): %s", p)
            continue
        try:
            funcs = extract_library_functions(p, label)
        except (mo.MachOError, OSError, ValueError) as exc:
            src["status"] = f"okunamadi: {exc}"
            logger.info("  ATLA (%s): %s", exc, p)
            continue
        real = p.resolve()
        signed, refs_of, weak = select_signed(funcs, min_size=min_size, min_content=min_content)
        src.update(status="ok", realpath=str(real), sha256=_sha256(real),
                   functions=len(funcs), too_short=len(funcs) - len(signed) - weak,
                   weak=weak, signatures=0, duplicate=0, with_refs=0)
        for f in signed.values():
            refs = refs_of[f.address]
            e = build_selective_entry(
                f.names[0], label, f.body, aliases=f.names[1:], refs=refs,
                min_content_words=min_content,
            )
            if e is None:  # select_signed ile aynı kurallar; olmamalı
                raise RuntimeError(f"imza uretilemedi: {label} {f.names[0]}")
            dedup = (e["name"], e["library"], _signature_key(e))
            if dedup in seen:  # aynı dosya listede iki kez (ör. sembolik bağ) olabilir
                src["duplicate"] += 1
                continue
            seen.add(dedup)
            entries.append(e)
            src["signatures"] += 1
            src["with_refs"] += bool(refs)
        logger.info(
            "  %-10s %-32s fonksiyon=%5d imza=%5d kisa=%4d zayif=%4d refli=%5d",
            label, real.name, src["functions"], src["signatures"], src["too_short"],
            src["weak"], src["with_refs"],
        )

    by_prefix: dict[str, set[str]] = defaultdict(set)
    by_key: dict[tuple, set[str]] = defaultdict(set)
    for e in entries:
        by_prefix[e["byte_pattern"]].add(e["name"])
        by_key[_signature_key(e)].add(e["name"])
    prefix_multi = {k for k, v in by_prefix.items() if len(v) > 1}
    key_multi = {k for k, v in by_key.items() if len(v) > 1}

    return {
        "meta": {
            "generator": "scripts/flirt/build_selective_signatures.py",
            "format": SELECTIVE_SIG_FORMAT,
            "created_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "arch": "arm64",
            "mask_rule": MASK_RULE_ARM64,
            "prefix_len": SELECTIVE_PREFIX_LEN,
            "max_crc_len": SELECTIVE_MAX_CRC_LEN,
            "min_function_size": min_size,
            "min_content_words_without_refs": min_content,
            "description": (
                "Secici FLIRT bayt imzalari: maskeli 32 bayt on ek + fonksiyon "
                "uzunlugu + on ek otesi maskeli CRC16 (IDA FLIRT mantigi)."
            ),
            "sources": sources,
            "collisions": {
                # Yalnız ön ekle ayırt edilemeyen isim grupları (v1'in durumu)
                "prefix_only_patterns_multi_name": len(prefix_multi),
                "prefix_only_signatures_in_multi": sum(len(by_prefix[k]) for k in prefix_multi),
                # Ön ek + uzunluk + CRC16 ile de ayırt edilemeyenler: eşleştirici
                # bunlara isim VERMEZ (belirsiz)
                "full_key_groups_multi_name": len(key_multi),
                "full_key_signatures_in_multi": sum(
                    1 for e in entries if _signature_key(e) in key_multi
                ),
            },
        },
        "signatures": entries,
        "total": len(entries),
    }


def _check_output_path(out: Path) -> None:
    out_res = out.resolve()
    sigs_dir = (REPO_ROOT / "sigs").resolve()
    if out_res.name in _PROTECTED_NAMES or sigs_dir == out_res.parent or sigs_dir in out_res.parents:
        raise SystemExit(f"REDDEDILDI: mevcut imza DB'sinin/sigs'in uzerine yazilmaz: {out_res}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT, help="cikti JSON (varsayilan: %(default)s)")
    ap.add_argument(
        "--min-size", type=int, default=SELECTIVE_PREFIX_LEN,
        help="bu uzunluktan kisa fonksiyon imzalanmaz (en az on ek uzunlugu; varsayilan %(default)s)",
    )
    ap.add_argument(
        "--min-content", type=int, default=SELECTIVE_MIN_CONTENT_WORDS,
        help="cagri referansi olmayan fonksiyonda gereken en az icerik kelimesi (varsayilan %(default)s)",
    )
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    if args.min_size < SELECTIVE_PREFIX_LEN:
        ap.error(f"--min-size en az {SELECTIVE_PREFIX_LEN} olmali (on ek fonksiyon disina tasar)")
    _check_output_path(args.out)

    t0 = time.monotonic()
    data = build(source_libraries(), min_size=args.min_size, min_content=args.min_content)
    tmp = args.out.with_name(args.out.name + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=1, ensure_ascii=False)
    os.replace(tmp, args.out)

    col = data["meta"]["collisions"]
    logger.info("\n=== Sonuc ===")
    logger.info("Imza: %d  (%s alani ile v%d)", data["total"], SELECTIVE_ENTRY_KEY, SELECTIVE_SIG_FORMAT)
    logger.info(
        "Yalniz on ekle cok-isimli desen: %d (%d imza); tam anahtarla: %d grup (%d imza)",
        col["prefix_only_patterns_multi_name"], col["prefix_only_signatures_in_multi"],
        col["full_key_groups_multi_name"], col["full_key_signatures_in_multi"],
    )
    logger.info("Kaydedildi: %s (%.1fs)", args.out, time.monotonic() - t0)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
