#!/usr/bin/env python3
"""Build LMDB signature database from existing JSON sources (v1.10.0 M1 T1).

Kaynak dosyalari tarayip ``~/.karadul/signatures.lmdb`` altinda LMDB
environment olusturur. Idempotent: kaynaklarin hash'i (mtime + size)
son build'den farkli degilse skip eder.

Kullanim
--------

    # Normal build (hash ayni ise skip)
    python scripts/build_sig_lmdb.py

    # Zorla rebuild (hash'e bakmaksizin sil + yeniden yap)
    python scripts/build_sig_lmdb.py --rebuild

    # Farkli cikti yolu
    python scripts/build_sig_lmdb.py --output /tmp/test.lmdb

    # Belirli bir kaynak dizini (project_root)
    python scripts/build_sig_lmdb.py --project-root /path/to/black-widow

Kaynaklar (proje kokunden okunur)
----------------------------------

* ``signatures_homebrew.json``          — C++ mangled symbol'ler
* ``signatures_homebrew_bytes.json``    — libdb symbol extend
* ``sigs_macos_system.json``            — macOS framework sembolleri
* ``sigs/**/*.json``                    — tum expansion'lar (homebrew_deep, combined_1M, vb.)
* ``sigs/**/*.pat``                     — FLIRT pattern dosyalari (opsiyonel)

Cikti
-----

``<output>/data.mdb`` ve ``<output>/lock.mdb`` -- LMDB dizini.
``<output>/version.txt`` -- kaynak hash + build time metadata.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import shutil
import sys
import time
from pathlib import Path
from typing import Any, Iterator, Optional

# Proje root'u sys.path'e ekle (scripts/ altindan calissin)
_PROJECT_ROOT = Path(__file__).parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from karadul.analyzers.sigdb_lmdb import (  # noqa: E402
    DEFAULT_MAP_SIZE,
    LMDBSignatureDB,
    default_lmdb_path,
    is_lmdb_available,
)

logger = logging.getLogger("build_sig_lmdb")

# ----- Sabitler -----

# Platform tahmini dosya adindan (sigdb_lmdb'da _infer_platform ile ayni mantik)
_PLATFORM_PREFIX_MAP = {
    "windows_": ["pe"],
    "win_": ["pe"],
    "linux_": ["elf"],
    "macos_": ["macho"],
    "darwin_": ["macho"],
}

# Meta dict icindeki gecerli ust seviye key'ler (format 3 icin skip edilecek)
_META_KEYS = frozenset({
    "meta", "total", "version", "generator", "stats",
    "framework_stats", "library_stats", "category_stats",
})


def _infer_platform(name: str) -> Optional[list[str]]:
    lower = name.lower()
    for prefix, plats in _PLATFORM_PREFIX_MAP.items():
        if lower.startswith(prefix):
            return plats
    return None


# ---------------------------------------------------------------------------
# Versiyon hash
# ---------------------------------------------------------------------------


# v1.10.0 H5: ~100 byte altindaki dosyalar tipik olarak tas sablon / bos
# JSON'lar ("signatures": []) -- kaynak sayimini ve hash'i bozuyorlar.
_MIN_SOURCE_BYTES = 100


def compute_source_hash(paths: list[Path]) -> str:
    """Tum kaynak dosyalarin mtime + size kombinasyonundan deterministik hash.

    Icerigi okumaz (hizli). Dosya degistiginde mtime veya size degisir.
    v1.10.0 H5: < _MIN_SOURCE_BYTES olan dosyalar (bos signatures.json)
    atlanir; yanlis idempotency imzasi ve gereksiz discover sonuclari
    olusturmasinlar.
    """
    h = hashlib.sha256()
    for p in sorted(paths):
        try:
            st = p.stat()
        except OSError:
            continue
        if st.st_size < _MIN_SOURCE_BYTES:
            continue
        h.update(str(p).encode("utf-8"))
        h.update(b":")
        h.update(str(st.st_size).encode("ascii"))
        h.update(b":")
        # mtime'i integer'a truncate (float precision'dan kacin)
        h.update(str(int(st.st_mtime)).encode("ascii"))
        h.update(b"\n")
    return h.hexdigest()


def discover_sources(project_root: Path) -> list[Path]:
    """Build icin taranacak tum kaynak JSON/pat dosyalarini bul.

    v1.10.0 H5: Bos/plaka JSON'lar (_MIN_SOURCE_BYTES altindaki) atlanir.
    """
    sources: list[Path] = []

    def _add_if_nontrivial(p: Path) -> None:
        if not p.is_file():
            return
        try:
            if p.stat().st_size < _MIN_SOURCE_BYTES:
                logger.debug("Kaynak atlandi (boyut<%d): %s", _MIN_SOURCE_BYTES, p)
                return
        except OSError:
            return
        sources.append(p)

    # Proje kokundeki JSON'lar
    for name in ("signatures_homebrew.json", "signatures_homebrew_bytes.json",
                 "sigs_macos_system.json"):
        _add_if_nontrivial(project_root / name)

    # Proje kokunde signatures_*.json (genisletilebilir pattern)
    for p in sorted(project_root.glob("signatures_*.json")):
        if p not in sources:
            _add_if_nontrivial(p)

    # sigs/ altindaki JSON'lar
    sigs_dir = project_root / "sigs"
    if sigs_dir.is_dir():
        for p in sorted(sigs_dir.rglob("*.json")):
            _add_if_nontrivial(p)
        # FLIRT .pat (boyut filtresi yok -- pat'ler kucuk olabilir)
        for p in sorted(sigs_dir.rglob("*.pat")):
            if p.is_file():
                sources.append(p)

    return sources


# ---------------------------------------------------------------------------
# JSON parser (iterator -- build memory footprint dusuk olsun)
# ---------------------------------------------------------------------------


def iter_symbols_from_json(path: Path) -> Iterator[tuple[str, dict]]:
    """JSON dosyasindan ``(name, info_dict)`` yield et.

    Uc format destekler (signature_db.load_external_signatures ile ayni):
      1. ``{"signatures": [{"name": ..., "library": ..., ...}, ...]}``
      2. ``{"signatures": {"name": {"lib": ..., ...}, ...}}``
      3. ``{"name": {"lib": ..., ...}, ...}`` (flat, meta key'ler skip)
    """
    try:
        with open(path, "rb") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("JSON okunamadi %s: %s", path, exc)
        return

    if not isinstance(data, dict):
        return

    file_default_platforms = _infer_platform(path.name)
    signatures_value = data.get("signatures")

    # Format 1: list
    if isinstance(signatures_value, list):
        for entry in signatures_value:
            if not isinstance(entry, dict):
                continue
            name = entry.get("name", "")
            if not name:
                continue
            info: dict[str, Any] = {
                "lib": entry.get("library", "unknown"),
                "purpose": entry.get("purpose", ""),
                "category": entry.get("category", entry.get("library", "unknown")),
            }
            platforms = entry.get("platforms") or file_default_platforms
            # v1.10.0 H3: bazi JSON kaynaklarinda "platforms": "pe" (string)
            # olabiliyor; list'e normalize et (downstream _is_platform_compatible
            # 'in in list' varsayar, substring match beklemez).
            if isinstance(platforms, str):
                platforms = [platforms]
            if platforms:
                info["_platforms"] = platforms
            if "params" in entry:
                info["params"] = entry["params"]
            yield name, info
        return

    # Format 2: dict under "signatures"
    if isinstance(signatures_value, dict):
        for name, entry in signatures_value.items():
            if not isinstance(entry, dict):
                continue
            info = {
                "lib": entry.get("lib", entry.get("library", "unknown")),
                "purpose": entry.get("purpose", ""),
                "category": entry.get("category", entry.get("lib", "unknown")),
            }
            platforms = entry.get("platforms") or file_default_platforms
            # v1.10.0 H3: bazi JSON kaynaklarinda "platforms": "pe" (string)
            # olabiliyor; list'e normalize et (downstream _is_platform_compatible
            # 'in in list' varsayar, substring match beklemez).
            if isinstance(platforms, str):
                platforms = [platforms]
            if platforms:
                info["_platforms"] = platforms
            if "params" in entry:
                info["params"] = entry["params"]
            yield name, info
        return

    # Format 3: flat top-level
    if signatures_value is None:
        for name, entry in data.items():
            if name in _META_KEYS or not isinstance(entry, dict):
                continue
            info = {
                "lib": entry.get("lib", entry.get("library", "unknown")),
                "purpose": entry.get("purpose", ""),
                "category": entry.get("category", entry.get("lib", "unknown")),
            }
            platforms = entry.get("platforms") or file_default_platforms
            # v1.10.0 H3: bazi JSON kaynaklarinda "platforms": "pe" (string)
            # olabiliyor; list'e normalize et (downstream _is_platform_compatible
            # 'in in list' varsayar, substring match beklemez).
            if isinstance(platforms, str):
                platforms = [platforms]
            if platforms:
                info["_platforms"] = platforms
            if "params" in entry:
                info["params"] = entry["params"]
            yield name, info


# ---------------------------------------------------------------------------
# Build pipeline
# ---------------------------------------------------------------------------


def build(
    project_root: Path,
    output: Path,
    *,
    rebuild: bool = False,
    map_size: int = DEFAULT_MAP_SIZE,
) -> dict[str, Any]:
    """LMDB build'i calistir. Idempotent.

    Returns
    -------
    dict: summary -- {status, sources, symbols, elapsed_sec, size_bytes}
    """
    if not is_lmdb_available():
        raise RuntimeError("lmdb modulu bulunamadi. pip install lmdb msgpack")

    output = Path(output).expanduser().resolve()
    version_file = output / "version.txt"

    t0 = time.monotonic()

    sources = discover_sources(project_root)
    if not sources:
        logger.warning("Hicbir kaynak bulunamadi: %s", project_root)
        return {"status": "no_sources", "sources": 0, "elapsed_sec": 0.0}

    source_hash = compute_source_hash(sources)
    logger.info("%d kaynak dosya, hash=%s", len(sources), source_hash[:12])

    # Idempotent: hash ayniysa skip
    if not rebuild and version_file.exists():
        try:
            existing = version_file.read_text("utf-8").strip().split("\n")[0]
        except OSError:
            existing = ""
        if existing == source_hash:
            logger.info("LMDB guncel (hash match). Skip. Rebuild icin --rebuild.")
            size = _dir_size(output)
            return {
                "status": "skip_uptodate",
                "sources": len(sources),
                "symbols": -1,
                "elapsed_sec": time.monotonic() - t0,
                "size_bytes": size,
                "hash": source_hash,
            }

    # Rebuild modunda mevcut LMDB'yi sil
    if output.exists():
        logger.info("Mevcut LMDB siliniyor: %s", output)
        shutil.rmtree(output)

    # Build
    logger.info("LMDB olusturuluyor: %s (map_size=%d MB)", output, map_size // 1024 // 1024)
    output.mkdir(parents=True, exist_ok=True)

    # Lazy import: MapFullError LMDB binding'den
    import lmdb as _lmdb

    current_map_size = map_size
    db = LMDBSignatureDB(output, readonly=False, map_size=current_map_size)

    def _write_batch(batch_items: list[tuple[str, dict]]) -> int:
        """MapFull olursa map_size'i 2x buyutup tekrar dene (en fazla 3 kez)."""
        nonlocal current_map_size
        attempts = 0
        while True:
            try:
                return db.bulk_write_symbols(batch_items)
            except _lmdb.MapFullError:
                if attempts >= 3:
                    raise
                attempts += 1
                current_map_size *= 2
                logger.warning(
                    "MapFullError -- map_size 2x buyutuluyor: %d MB",
                    current_map_size // 1024 // 1024,
                )
                db._env.set_mapsize(current_map_size)

    try:
        total_symbols = 0
        duplicate_skipped = 0
        seen_names: set[str] = set()  # Ayni dosyalarda tekrar edenler icin

        for i, src in enumerate(sources, 1):
            if src.suffix != ".json":
                # .pat dosyalari henuz LMDB'ye yazilmiyor (FLIRTParser
                # runtime'da calisiyor, binary-specific matching).
                continue

            batch: list[tuple[str, dict]] = []
            for name, info in iter_symbols_from_json(src):
                # Ilk gelen kazanir (builtin DB ile ayni mantik)
                if name in seen_names:
                    duplicate_skipped += 1
                    continue
                seen_names.add(name)
                batch.append((name, info))

                # 50K'lik chunk'larda yaz (RAM disiplini)
                if len(batch) >= 50_000:
                    total_symbols += _write_batch(batch)
                    batch.clear()

            if batch:
                total_symbols += _write_batch(batch)

            if i % 10 == 0 or i == len(sources):
                logger.info(
                    "[%d/%d] %s -- toplam %d symbol",
                    i, len(sources), src.name, total_symbols,
                )

        # v1.10.0 C3: Builtin string / call / byte signature'lari da LMDB'ye
        # yaz. Onceden sadece _symbol_db LMDB'ye aliniyor, ancak
        # _STRING_REFERENCE_SIGNATURES, _CALL_PATTERN_SIGNATURES ve
        # _FINDCRYPT_CONSTANTS builtin dict'lerinden gelen pattern'ler
        # LMDB mode'da sorgulanamiyordu.
        str_written, call_written, byte_written = _write_builtin_secondary_sigs(db)

        # Version metadata yaz
        db.put_metadata("source_hash", source_hash.encode("utf-8"))
        db.put_metadata("build_time", str(int(time.time())).encode("ascii"))
        db.put_metadata("source_count", str(len(sources)).encode("ascii"))
        db.put_metadata("symbol_count", str(total_symbols).encode("ascii"))
        db.put_metadata("string_sig_count", str(str_written).encode("ascii"))
        db.put_metadata("call_sig_count", str(call_written).encode("ascii"))
        db.put_metadata("byte_sig_count", str(byte_written).encode("ascii"))
        db.sync()
    finally:
        db.close()

    # version.txt yaz (LMDB disinda, idempotency icin)
    version_file.write_text(
        f"{source_hash}\n"
        f"build_time={int(time.time())}\n"
        f"sources={len(sources)}\n"
        f"symbols={total_symbols}\n"
        f"duplicates_skipped={duplicate_skipped}\n",
        encoding="utf-8",
    )

    elapsed = time.monotonic() - t0
    size = _dir_size(output)
    logger.info(
        "Build tamamlandi. %d symbol, %d duplicate skip, %.2fs, %.1f MB disk",
        total_symbols, duplicate_skipped, elapsed, size / 1024 / 1024,
    )

    return {
        "status": "built",
        "sources": len(sources),
        "symbols": total_symbols,
        "duplicates_skipped": duplicate_skipped,
        "elapsed_sec": elapsed,
        "size_bytes": size,
        "hash": source_hash,
    }


def _write_builtin_secondary_sigs(db: LMDBSignatureDB) -> tuple[int, int, int]:
    """v1.10.0 C3: Builtin string / call / byte signature dict'lerini LMDB'ye yaz.

    Kaynaklar (signature_db module-level):
      * ``_STRING_REFERENCE_SIGNATURES`` -> string_sigs DB
      * ``_CALL_PATTERN_SIGNATURES``    -> call_sigs DB
      * ``_FINDCRYPT_CONSTANTS``        -> byte_sigs DB (FindCrypt kripto
        sabitleri, mask tamamen 0xFF)

    Returns
    -------
    ``(string_count, call_count, byte_count)``

    Notlar
    ------
    LMDB aktif mode'da runtime artik builtin dict'leri de dolduruyor
    (backward-compat), ancak ``_match_by_strings/calls/bytes`` fonksiyonlari
    LMDB'de aynı payload'lari da sorgulayabilmeli -- bu fonksiyon onu saglar.
    """
    try:
        from karadul.analyzers.signature_db import (  # noqa: E402
            _STRING_REFERENCE_SIGNATURES,
            _CALL_PATTERN_SIGNATURES,
            _FINDCRYPT_CONSTANTS,
        )
    except ImportError as exc:
        logger.warning("Builtin sigs import edilemedi: %s", exc)
        return 0, 0, 0

    # String signatures: dict[frozenset, tuple[name, lib, purpose]]
    try:
        str_items = list(_STRING_REFERENCE_SIGNATURES.items())
        str_written = db.bulk_write_string_sigs(str_items)
    except Exception as exc:
        logger.warning("String sig yazimi basarisiz: %s", exc)
        str_written = 0

    # Call signatures: list[tuple[frozenset, name, lib, purpose, confidence]]
    # bulk_write_call_sigs: (frozenset, (name, lib, purpose, confidence))
    try:
        call_items = [
            (callees, (matched, library, purpose, conf))
            for (callees, matched, library, purpose, conf) in _CALL_PATTERN_SIGNATURES
        ]
        call_written = db.bulk_write_call_sigs(call_items)
    except Exception as exc:
        logger.warning("Call sig yazimi basarisiz: %s", exc)
        call_written = 0

    # Byte signatures: FindCrypt constants -> {name, library, byte_pattern_hex,
    # byte_mask_hex, purpose, category}
    try:
        byte_entries: list[dict] = []
        for name, hex_pattern, category, purpose in _FINDCRYPT_CONSTANTS:
            try:
                plen = len(bytes.fromhex(hex_pattern))
            except ValueError:
                continue
            byte_entries.append({
                "name": name,
                "library": "crypto_constants",
                "category": category,
                "byte_pattern_hex": hex_pattern,
                "byte_mask_hex": "ff" * plen,  # FindCrypt mask tamamen 0xFF
                "purpose": purpose,
            })
        byte_written = db.bulk_write_byte_sigs(byte_entries)
    except Exception as exc:
        logger.warning("Byte sig yazimi basarisiz: %s", exc)
        byte_written = 0

    logger.info(
        "Builtin secondary sigs yazildi: string=%d call=%d byte=%d",
        str_written, call_written, byte_written,
    )
    return str_written, call_written, byte_written


def _dir_size(path: Path) -> int:
    """Dizin toplam boyutu (byte)."""
    total = 0
    try:
        for p in path.rglob("*"):
            if p.is_file():
                total += p.stat().st_size
    except OSError:
        pass
    return total


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="build_sig_lmdb",
        description="Build LMDB signature database from JSON sources.",
    )
    parser.add_argument(
        "--output", "-o",
        type=Path,
        default=None,
        help="Cikti LMDB dizini. Varsayilan: ~/.karadul/signatures.lmdb",
    )
    parser.add_argument(
        "--project-root", "-p",
        type=Path,
        default=_PROJECT_ROOT,
        help=f"Proje koku (kaynak taramasi). Varsayilan: {_PROJECT_ROOT}",
    )
    parser.add_argument(
        "--rebuild", "-r",
        action="store_true",
        help="Zorla rebuild (mevcut LMDB'yi sil, hash bakma).",
    )
    parser.add_argument(
        "--map-size",
        type=int,
        default=DEFAULT_MAP_SIZE,
        help=f"LMDB map_size byte. Varsayilan: {DEFAULT_MAP_SIZE} ({DEFAULT_MAP_SIZE // 1024 // 1024} MB).",
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Sadece ozet ciktisi.",
    )

    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.WARNING if args.quiet else logging.INFO,
        format="%(asctime)s %(levelname)-5s %(name)s: %(message)s",
    )

    output = args.output or default_lmdb_path()

    try:
        summary = build(
            project_root=args.project_root,
            output=output,
            rebuild=args.rebuild,
            map_size=args.map_size,
        )
    except Exception as exc:
        logger.error("Build basarisiz: %s", exc, exc_info=True)
        return 2

    status = summary.get("status", "?")
    print(f"[build_sig_lmdb] status={status}")
    print(f"  output  : {output}")
    print(f"  sources : {summary.get('sources', 0)}")
    if status == "built":
        print(f"  symbols : {summary.get('symbols', 0):,}")
        print(f"  dup skip: {summary.get('duplicates_skipped', 0):,}")
    print(f"  elapsed : {summary.get('elapsed_sec', 0.0):.2f}s")
    size = summary.get("size_bytes", 0)
    print(f"  size    : {size / 1024 / 1024:.1f} MB")
    if "hash" in summary:
        print(f"  hash    : {summary['hash'][:16]}...")

    return 0


if __name__ == "__main__":
    sys.exit(main())
