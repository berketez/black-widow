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
import re
import tempfile
import zlib
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


# ---------------------------------------------------------------------------
# Şema 2 (P08 / IMZA-07): kaynak tablosu ve ad başına sağlayıcı listesi
# ---------------------------------------------------------------------------
#
# Şema 1'de LMDB anahtarı yalnız addı; aynı ad birden çok kitaplıkta geçince
# ilk yazılan kalıyor, öbürleri kayboluyordu. Kaynaklardan ikisi içe aktarılan
# simgeleri de "tanım" diye kaydetmişti (glibc'nin __printf_chk'ı →
# "opencv_python_headless"). Şema 2'de her ad için SAĞLAYICI LİSTESİ tutulur
# ([kitaplık, kategori, platformlar, kaynak dizini]); bir ad platformla süzüldükten
# sonra birden çok kitaplık ailesinde kalıyorsa eşleme tek kitaplık uydurmaz.
#
# Kaynak tablosu: her dosyanın ürettiği betik ve neden "yalnız tanımlanan /
# dışa aktarılan simge" sayıldığı. Platform, girdinin kendi "platforms" alanı
# yoksa buradan gelir. Tabloda olmayan dosya "gözden geçirilmedi" diye yüklenir
# ve künyede ayrıca listelenir; DIŞLANAN dosyalar hiç yüklenmez.
SCHEMA_VERSION = 2

SOURCE_TABLE: dict[str, dict[str, Any]] = {
    "signatures_homebrew.json": {
        "provenance": "exports", "platforms": ["macho"],
        "note": "scripts/build-signature-db.py: nm -g -U (yalnız tanımlı, dışa aktarılan); Homebrew macOS kitaplıkları"},
    "signatures_homebrew_bytes.json": {
        "provenance": "exports", "platforms": ["macho"],
        "note": "scripts/build_byte_signatures.py: tanımlı fonksiyonların gövde baytları (Homebrew + sistem kitaplıkları)"},
    "signatures_homebrew_bytes_v2.json": {
        "provenance": "exports", "platforms": ["macho"],
        "note": "scripts/flirt/build_selective_signatures.py: tanımlı fonksiyonların seçici bayt imzası"},
    "sigs/anaconda_symbols.json": {
        "provenance": "exports", "platforms": ["macho"],
        "note": "scripts/gen_anaconda_sigs.py: nm -gU (dışa aktarılan text simgeleri), macOS Anaconda"},
    "sigs/combined_1M.json": {
        "provenance": "exports", "platforms": ["macho"],
        "note": "scripts/mega-harvest-signatures.py: nm -g -U ve .tbd exports/re-exports blokları (macOS)"},
    "sigs/extra/combined_swift_extra.json": {
        "provenance": "exports", "platforms": ["macho"],
        "note": "scripts/mega-harvest-signatures.py: Swift simgeleri (macOS dışa aktarımları)"},
    "sigs/dyld_cache_exports.json": {
        "provenance": "exports", "platforms": ["macho"],
        "note": "scripts/gen_dyld_sigs.py: dyld_info -exports (dyld paylaşılan önbelleği, arm64e)"},
    "sigs/sdk_tbd_symbols.json": {
        "provenance": "exports", "platforms": ["macho"],
        "note": "scripts/gen_tbd_sigs.py: macOS SDK .tbd exports / reexported-symbols"},
    "sigs/macos_system_symbols.json": {
        "provenance": "exports", "platforms": ["macho"],
        "note": "tools/extract_macos_system_symbols.py: nm -gU"},
    "sigs/homebrew_symbols.json": {
        "provenance": "exports", "platforms": ["macho"],
        "note": "tools/extract_homebrew_sigs.py: nm -gU"},
    "sigs/homebrew_deep.json": {
        "provenance": "exports", "platforms": ["macho"],
        "note": "scripts/gen_homebrew_sigs.py: nm -gU (dylib), nm -g + yalnız 'T' (statik .a)"},
    "sigs/homebrew_extra.json": {
        "provenance": "exports", "platforms": ["macho"],
        "note": "scripts/gen_homebrew_extra_sigs.py: nm -gU (dylib), nm -g + yalnız T/S/D (statik .a)"},
    "sigs/swift_objc_signatures.json": {
        "provenance": "exports", "platforms": ["macho"],
        "note": "gen_swift_objc_sigs.py: dyld paylaşılan önbelleği + elle yazılmış ObjC yöntemleri"},
    "sigs/windows_real_exports.json": {
        "provenance": "exports", "platforms": ["pe"],
        "note": "scripts/gen_windows_real_sigs.py: PE dışa aktarım tablosu (Windows 11 DLL'leri)"},
    "sigs/wine_dll_exports.json": {
        "provenance": "exports", "platforms": ["pe"],
        "note": "scripts/gen_wine_sigs.py: Wine/ReactOS .spec dışa aktarımları"},
    "sigs/msys2_mingw_exports.json": {
        "provenance": "exports", "platforms": ["pe"],
        "note": "scripts/gen_msys2_sigs.py: PE dışa aktarım tablosu (adlı)"},
    "sigs/mingw_headers.json": {
        "provenance": "exports", "platforms": ["pe"],
        "note": "scripts/gen_mingw_headers_sigs.py: mingw-w64 .def dışa aktarım listeleri + başlıklar"},
    "sigs/windows_api_signatures.json": {
        "provenance": "curated", "platforms": ["pe"],
        "note": "sigs/gen_windows_sigs.py: elle yazılmış Windows API listesi"},
    "sigs/windows_expanded.json": {
        "provenance": "curated", "platforms": ["pe"],
        "note": "scripts/gen_win_linux_sigs.py: elle yazılmış liste"},
    "sigs/linux_signatures.json": {
        "provenance": "curated", "platforms": ["elf"],
        "note": "sigs/gen_linux_sigs.py: elle yazılmış glibc/musl/sistem çağrısı listesi"},
    "sigs/linux_expanded.json": {
        "provenance": "curated", "platforms": ["elf"],
        "note": "scripts/gen_win_linux_sigs.py: elle yazılmış liste"},
    "sigs/ubuntu_elf_signatures.json": {
        "provenance": "exports_glibc_only", "platforms": ["elf"],
        "note": ("scripts/gen_ubuntu_sigs.py içe aktarılan (SHN_UNDEF) simgeleri de yazıyor ve "
                 "'_undef' işaretini yazmadan önce siliyor (:619-627, :738-740): tanım / içe aktarım "
                 "ayırt edilemez. YALNIZ libc6 paketinin kayıtları (kategori 'linux_glibc') alınır: o "
                 "paketin .so'ları yalnız birbirinden içe aktarır, kitaplık ailesi her durumda glibc; "
                 "kitaplık adı 'glibc' olarak yazılır. Öbür kayıtlar dışlanır.")},
    "sigs/flirt_github.json": {
        "provenance": "exports", "platforms": None,
        "note": "scripts/gen_flirt_sigs.py: FLIRT .pat (statik kitaplıklarda tanımlı fonksiyonlar); platform kategoriden"},
    "sigs/go_expanded.json": {
        "provenance": "exports", "platforms": None,
        "note": "scripts/gen_go_sigs.py: Go simgeleri (Go içe aktarım yapmaz)"},
    "sigs/go_stdlib_signatures.json": {
        "provenance": "exports", "platforms": None, "note": "Go standart kitaplığı simgeleri"},
    "sigs/rust_expanded.json": {
        "provenance": "exports", "platforms": None, "note": "scripts/gen_rust_sigs.py: nm -gU"},
    "sigs/rust_signatures.json": {
        "provenance": "exports", "platforms": None, "note": "scripts/gen_rust_sigs.py: nm -gU"},
    "sigs/cpp_stl_mangled.json": {
        "provenance": "curated", "platforms": None,
        "note": "scripts/gen_cpp_stl_sigs.py: derlenmiş STL şablon örnekleri (kitaplık C++ standart kitaplığı)"},
    "sigs/cpp_signatures.json": {
        "provenance": "curated", "platforms": None, "note": "gen_cpp_sigs.py: elle yazılmış C++ listesi"},
    "sigs/compiler_intrinsics.json": {
        "provenance": "curated", "platforms": None, "note": "scripts/gen_intrinsics_sigs.py: derleyici iç fonksiyonları"},
    "sigs/runtime_signatures.json": {
        "provenance": "curated", "platforms": None, "note": "Python C API / JNI / V8 / Ruby / Lua API adları"},
    "sigs/generated_signatures.json": {
        "provenance": "curated", "platforms": None, "note": "sigs/gen_expanded_sigs.py: elle yazılmış liste"},
    "sigs/fortran_ccx.json": {
        "provenance": "curated", "platforms": None, "note": "CalculiX Fortran yordamları"},
}

EXCLUDED_SOURCES: dict[str, str] = {
    "sigs/pypi_native_symbols.json": (
        "karışık: scripts/gen_pypi_sigs.py ELF .dynsym'deki içe aktarılan (SHN_UNDEF) simgeleri de "
        "alıyor (:216-221, 'Simdilik hepsini alalim'); kitaplık adı PyPI paketi (gömülü kopyalar dahil). "
        "glibc __printf_chk → opencv_python_headless kusurunun kaynağı (IMZA-07)"),
    "sigs/extra/quantitative_finance.json": (
        "bir kitaplığın dışa aktarımı değil: model üretimi algoritma adı listesi (generator: codex-consultant)"),
    "sigs/tuned_weights.json": "imza değil (ağırlık tablosu); şema 1'de 'weights' adlı sahte bir simge yazıyordu",
    "sigs/fortran_params.json": "imza kaydı yok (parametre tablosu)",
    "sigs_macos_system.json": "boş",
}

# Kitaplık adı olmayan "kitaplık" değerleri (başlık dosyası, bilinmiyor): sağlayıcı sayılmaz.
_NON_LIBRARY_RE = re.compile(r"(\.h$|^unknown$|^$)")


def _source_key(project_root: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(project_root.resolve()).as_posix()
    except ValueError:
        return path.name


def _flirt_platform(category: str) -> Optional[list[str]]:
    c = (category or "").lower()
    if "ubuntu" in c or "linux" in c or "glibc" in c or "debian" in c:
        return ["elf"]
    if "msvc" in c or "windows" in c or "vc" == c[-2:]:
        return ["pe"]
    return None


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


def iter_byte_sigs_from_json(path: Path) -> Iterator[dict]:
    """v1.20.5 B9: JSON dosyasindan byte signature dict'leri yield et.

    Beklenen format (signatures_homebrew_bytes.json ornegi):

        {
            "signatures": [
                {
                    "name": "_BIO_f_ssl",
                    "library": "openssl",
                    "category": "openssl",
                    "purpose": "",
                    "confidence": 0.9,
                    "size": 0,
                    "byte_pattern": "<hex string>",
                    "byte_mask": "<hex string>" (opsiyonel)
                },
                ...
            ]
        }

    Sadece ``byte_pattern`` alani bulunan entry'ler dikkate alinir. Mask
    yoksa otomatik tum-FF mask uretilir (downstream match exact byte
    karsilastirir).
    """
    try:
        with open(path, "rb") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("Byte sig JSON okunamadi %s: %s", path, exc)
        return

    if not isinstance(data, dict):
        return

    signatures_value = data.get("signatures")
    if not isinstance(signatures_value, list):
        return

    for entry in signatures_value:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name", "")
        pattern_hex = entry.get("byte_pattern") or entry.get("byte_pattern_hex")
        if not name or not pattern_hex:
            continue
        # Hex validation
        try:
            plen = len(bytes.fromhex(pattern_hex))
        except ValueError:
            continue
        if plen == 0:
            continue
        mask_hex = entry.get("byte_mask") or entry.get("byte_mask_hex") or ("ff" * plen)
        yield {
            "name": name,
            "library": entry.get("library", "unknown"),
            "category": entry.get("category", entry.get("library", "unknown")),
            "purpose": entry.get("purpose", ""),
            "byte_pattern_hex": pattern_hex,
            "byte_mask_hex": mask_hex,
            "confidence": entry.get("confidence", 0.9),
            "size": entry.get("size", 0),
        }


def iter_call_sigs_from_json(path: Path) -> Iterator[tuple[frozenset[str], tuple[str, str, str, float]]]:
    """v1.20.5 B9: JSON dosyasindan call pattern signature'lari yield et.

    Beklenen format (esnek; iki varyant kabul edilir):

        {
            "call_signatures": [
                {
                    "callees": ["malloc", "memcpy", "free"],
                    "name": "copy_buf",
                    "library": "libc",
                    "purpose": "buffer copy",
                    "confidence": 0.85
                },
                ...
            ]
        }

    Veya top-level ``call_patterns`` ya da ``signatures`` listesi icinde
    ``type: "call_pattern"`` etiketli entry'ler.
    """
    try:
        with open(path, "rb") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("Call sig JSON okunamadi %s: %s", path, exc)
        return

    if not isinstance(data, dict):
        return

    candidates: list[dict] = []
    for key in ("call_signatures", "call_patterns", "calls"):
        value = data.get(key)
        if isinstance(value, list):
            candidates.extend(v for v in value if isinstance(v, dict))

    # signatures listesinde type:call_pattern olanlar
    sigs = data.get("signatures")
    if isinstance(sigs, list):
        for v in sigs:
            if not isinstance(v, dict):
                continue
            if v.get("type") == "call_pattern" and "callees" in v:
                candidates.append(v)

    for entry in candidates:
        callees = entry.get("callees")
        name = entry.get("name") or entry.get("matched_name")
        if not isinstance(callees, list) or not callees or not name:
            continue
        callee_set = frozenset(c for c in callees if isinstance(c, str) and c)
        if not callee_set:
            continue
        yield (
            callee_set,
            (
                name,
                entry.get("library", "unknown"),
                entry.get("purpose", ""),
                float(entry.get("confidence", 0.8)),
            ),
        )


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
    shards: int = 4,
) -> dict[str, Any]:
    """LMDB build'i calistir. Idempotent.

    Şema 2 (P08 / IMZA-07): ad başına sağlayıcı listesi; kaynak tablosu
    (``SOURCE_TABLE`` / ``EXCLUDED_SOURCES``); çıktı dizinine ``kunye.json``.
    Var olan eski şemalı (künyesiz) bir veritabanının üstüne yazmaz.

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

    # Eski şemalı veritabanını EZME (A/B için korunur; ör. ~/.karadul/signatures.lmdb).
    if output.exists() and (output / "data.mdb").exists() and not _is_schema2_dir(output):
        raise RuntimeError(
            f"{output}: şema 2 künyesi olmayan bir veritabanı var; üstüne yazılmıyor. "
            "Başka bir --output verin (ör. ~/karadul_olcum/sigdb/<sürüm>/signatures.lmdb).")

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
        # Şema 2 (IMZA-07): ad başına sağlayıcı listesi. Bellek sınırı için
        # tek geçişte kayıtlar ad özetine göre parçalara (shard) ayrılır, sonra
        # her parça ayrı toplanıp yazılır.
        src_table, excluded, unreviewed = classify_sources(project_root, sources)
        agg = aggregate_providers(project_root, src_table, shards=shards)
        total_symbols = 0
        duplicate_skipped = 0  # birden çok sağlayıcılı ad sayısı (şema 1'de atlanan)
        multi_family = 0
        for batch, stats in agg:
            total_symbols += _write_batch(batch)
            duplicate_skipped += stats["multi_provider"]
            multi_family += stats["multi_library"]
        logger.info(
            "Simge: %d ad, %d ad birden çok sağlayıcılı, %d ad birden çok kitaplıklı",
            total_symbols, duplicate_skipped, multi_family,
        )

        # v1.10.0 C3: Builtin string / call / byte signature'lari da LMDB'ye
        # yaz. Onceden sadece _symbol_db LMDB'ye aliniyor, ancak
        # _STRING_REFERENCE_SIGNATURES, _CALL_PATTERN_SIGNATURES ve
        # _FINDCRYPT_CONSTANTS builtin dict'lerinden gelen pattern'ler
        # LMDB mode'da sorgulanamiyordu.
        str_written, call_written, byte_written = _write_builtin_secondary_sigs(db)

        # v1.20.5 B9: JSON kaynaklarindan byte_sigs ve call_sigs yazimi.
        # Builtin uzerine yaziyor (son yazan kazanir); JSON kaynaklarinda
        # binlerce ek pattern bulunabilir (signatures_homebrew_bytes.json
        # 22K entry).
        json_byte_written, json_call_written = _write_external_secondary_sigs(
            db, sources,
        )
        byte_written += json_byte_written
        call_written += json_call_written

        # Version metadata yaz
        build_id = f"s{SCHEMA_VERSION}-{source_hash[:12]}-{time.strftime('%Y%m%d')}"
        db.put_metadata("schema_version", str(SCHEMA_VERSION).encode("ascii"))
        db.put_metadata("build_id", build_id.encode("utf-8"))
        db.put_metadata("sources_json", json.dumps(
            [{"source": k, **{kk: vv for kk, vv in v.items() if kk != "path"}}
             for k, v in src_table.items()], ensure_ascii=False).encode("utf-8"))
        db.put_metadata("source_hash", source_hash.encode("utf-8"))
        db.put_metadata("build_time", str(int(time.time())).encode("ascii"))
        db.put_metadata("source_count", str(len(sources)).encode("ascii"))
        db.put_metadata("symbol_count", str(total_symbols).encode("ascii"))
        db.put_metadata("string_sig_count", str(str_written).encode("ascii"))
        db.put_metadata("call_sig_count", str(call_written).encode("ascii"))
        db.put_metadata("byte_sig_count", str(byte_written).encode("ascii"))
        db.sync()

        # v1.20.5 B20: Integrity manifest. sync() sonrasi data.mdb sabit.
        try:
            db.write_integrity_manifest()
        except Exception as exc:
            logger.warning("Integrity manifest yazimi basarisiz: %s", exc)
    finally:
        db.close()

    # version.txt yaz (LMDB disinda, idempotency icin)
    version_file.write_text(
        f"{source_hash}\n"
        f"build_time={int(time.time())}\n"
        f"sources={len(sources)}\n"
        f"symbols={total_symbols}\n"
        f"duplicates_skipped={duplicate_skipped}\n"
        f"schema_version={SCHEMA_VERSION}\n"
        f"build_id={build_id}\n",
        encoding="utf-8",
    )

    elapsed = time.monotonic() - t0
    size = _dir_size(output)
    # Sürüm künyesi (insan okur; DMG'ye gömülürken yanında gider).
    kunye = {
        "schema_version": SCHEMA_VERSION,
        "build_id": build_id,
        "source_hash": source_hash,
        "build_time": int(time.time()),
        "project_root": str(project_root),
        "symbols": total_symbols,
        "multi_provider_names": duplicate_skipped,
        "multi_library_names": multi_family,
        "sources": [{"source": k, **{kk: vv for kk, vv in v.items() if kk != "path"}}
                    for k, v in src_table.items()],
        "excluded_sources": excluded,
        "unreviewed_sources": unreviewed,
        "elapsed_sec": round(elapsed, 1),
        "size_bytes": size,
    }
    (output / "kunye.json").write_text(json.dumps(kunye, indent=1, ensure_ascii=False), encoding="utf-8")
    logger.info(
        "Build tamamlandi. %d symbol, %d cok saglayicili, %.2fs, %.1f MB disk",
        total_symbols, duplicate_skipped, elapsed, size / 1024 / 1024,
    )

    return {
        "status": "built",
        "sources": len(sources),
        "symbols": total_symbols,
        "duplicates_skipped": duplicate_skipped,
        "multi_library_names": multi_family,
        "excluded_sources": excluded,
        "unreviewed_sources": unreviewed,
        "build_id": build_id,
        "elapsed_sec": elapsed,
        "size_bytes": size,
        "hash": source_hash,
    }


# ---------------------------------------------------------------------------
# Şema 2: kaynak sınıflaması ve sağlayıcı toplama
# ---------------------------------------------------------------------------


def _is_schema2_dir(output: Path) -> bool:
    """Dizindeki veritabanı bu betiğin şema 2 çıktısı mı (künye ya da version.txt'den)."""
    try:
        if json.loads((output / "kunye.json").read_text("utf-8")).get("schema_version") == SCHEMA_VERSION:
            return True
    except (OSError, json.JSONDecodeError, AttributeError):
        pass
    try:
        return f"schema_version={SCHEMA_VERSION}" in (output / "version.txt").read_text("utf-8")
    except OSError:
        return False


def classify_sources(
    project_root: Path, sources: list[Path],
) -> tuple[dict[str, dict], list[dict], list[str]]:
    """Kaynakları tabloya göre ayır: (yüklenecekler, dışlananlar, gözden geçirilmemişler)."""
    table: dict[str, dict] = {}
    excluded: list[dict] = []
    unreviewed: list[str] = []
    for src in sources:
        if src.suffix != ".json":
            continue  # .pat: FLIRTParser çalışma zamanında okur, LMDB'ye yazılmaz
        key = _source_key(project_root, src)
        if key in EXCLUDED_SOURCES:
            excluded.append({"source": key, "reason": EXCLUDED_SOURCES[key]})
            logger.info("Kaynak dışlandı: %s -- %s", key, EXCLUDED_SOURCES[key][:80])
            continue
        spec = SOURCE_TABLE.get(key)
        if spec is None:
            spec = {"provenance": "unreviewed", "platforms": None,
                    "note": "kaynak tablosunda yok (gözden geçirilmedi)"}
            unreviewed.append(key)
            logger.warning("Gözden geçirilmemiş kaynak yükleniyor: %s", key)
        table[key] = {**spec, "path": str(src)}
    return table, excluded, unreviewed


def _provider_from(key: str, spec: dict, info: dict) -> Optional[tuple[str, str, Optional[tuple]]]:
    """Bir kaynak kaydından sağlayıcı ``(lib, category, platforms)``; sayılmazsa None."""
    lib = str(info.get("lib") or "").strip()
    cat = str(info.get("category") or "")
    if spec["provenance"] == "exports_glibc_only":
        if cat != "linux_glibc":
            return None
        lib = "glibc"
    if _NON_LIBRARY_RE.search(lib):
        return None
    plats = info.get("_platforms")
    if not plats:
        plats = spec.get("platforms")
        if plats is None and key == "sigs/flirt_github.json":
            plats = _flirt_platform(cat)
    return lib, cat, (tuple(sorted(plats)) if plats else None)


def aggregate_providers(
    project_root: Path, src_table: dict[str, dict], *, shards: int = 4,
) -> Iterator[tuple[list[tuple[str, dict]], dict]]:
    """Kaynakları bir kez okuyup ada göre parçala; her parça için (yazılacak kayıtlar, sayaç).

    Kayıt (şema 2)::

        {"providers": [[lib, category, [platform...] | None, kaynak_dizini], ...],
         "lib": <tek kitaplık ailesi varsa o, yoksa "">, "libs": [...],
         "category": <tek ailede ilk sağlayıcının kategorisi, yoksa "">,
         "purpose": <ilk boş olmayan>, "params": <varsa>, "schema": 2}
    """
    import msgpack

    from karadul.analyzers.signature_db import _lib_family

    keys = list(src_table)
    tmpdir = Path(tempfile.mkdtemp(prefix="sigdb_shard_"))
    try:
        files = [open(tmpdir / f"p{k}.mp", "wb") for k in range(shards)]
        try:
            for si, key in enumerate(keys):
                spec = src_table[key]
                kept = dropped = 0
                for name, info in iter_symbols_from_json(Path(spec["path"])):
                    prov = _provider_from(key, spec, info)
                    if prov is None:
                        dropped += 1
                        continue
                    kept += 1
                    rec = (name, prov[0], prov[1], list(prov[2]) if prov[2] else None, si,
                           info.get("purpose") or "", info.get("params"))
                    files[zlib.crc32(name.encode("utf-8")) % shards].write(
                        msgpack.packb(rec, use_bin_type=True))
                spec["kept"] = kept
                spec["dropped"] = dropped
                logger.info("[%d/%d] %s -- alınan %d, düşülen %d", si + 1, len(keys), key, kept, dropped)
        finally:
            for f in files:
                f.close()

        for k in range(shards):
            names: dict[str, dict] = {}
            with open(tmpdir / f"p{k}.mp", "rb") as f:
                for name, lib, cat, plats, si, purpose, params in msgpack.Unpacker(f, raw=False):
                    ent = names.get(name)
                    if ent is None:
                        ent = names[name] = {"providers": [], "_seen": set(), "purpose": "", "params": None}
                    sig = (lib, tuple(plats) if plats else None)
                    if sig not in ent["_seen"]:
                        ent["_seen"].add(sig)
                        ent["providers"].append([lib, cat, plats, si])
                    if purpose and not ent["purpose"]:
                        ent["purpose"] = purpose
                    if params is not None and ent["params"] is None:
                        ent["params"] = params
            batch: list[tuple[str, dict]] = []
            st = {"multi_provider": 0, "multi_library": 0}
            for name, ent in names.items():
                provs = ent["providers"]
                fams: list[str] = []
                libs: list[str] = []
                for p in provs:
                    fam = _lib_family(p[0])
                    if fam not in fams:
                        fams.append(fam)
                        libs.append(p[0])
                val: dict[str, Any] = {
                    "schema": SCHEMA_VERSION,
                    "providers": provs,
                    "libs": libs,
                    "lib": libs[0] if len(fams) == 1 else "",
                    "category": provs[0][1] if len(fams) == 1 else "",
                    "purpose": ent["purpose"],
                }
                if ent["params"] is not None:
                    val["params"] = ent["params"]
                if len(provs) > 1:
                    st["multi_provider"] += 1
                if len(fams) > 1:
                    st["multi_library"] += 1
                batch.append((name, val))
                if len(batch) >= 50_000:
                    yield batch, {"multi_provider": 0, "multi_library": 0}
                    batch = []
            yield batch, st
            names.clear()
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


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


def _write_external_secondary_sigs(
    db: LMDBSignatureDB,
    sources: list[Path],
) -> tuple[int, int]:
    """v1.20.5 B9: JSON dosyalarindan byte/call signature LMDB'ye yaz.

    Sirayla:
      1. signatures_homebrew_bytes.json + signatures_*_bytes*.json -> byte_sigs
      2. sigs/**/*.json icinde byte_pattern bulunan entry'ler -> byte_sigs
      3. signatures_*.json + sigs/**/*.json icinde call_signatures/
         call_patterns alanlari -> call_sigs

    Returns
    -------
    ``(byte_sig_count, call_sig_count)`` -- yazilan toplam entry sayisi.

    Notlar
    ------
    LMDB ``dupsort=False`` oldugu icin ayni (pattern+name_hash) key'ine
    yazan ikinci entry birinciyi ezer. Bu pratikte sorun yaratmaz cunku
    ayni isim ayni pattern'i tasir. Builtin'lerin uzerine yazma riski:
    sadece ayni name+pattern olursa, payload neredeyse aynidir.
    """
    byte_entries: list[dict] = []
    call_entries: list[tuple[frozenset[str], tuple[str, str, str, float]]] = []
    seen_byte_keys: set[tuple[str, str]] = set()  # (name, pattern_hex)

    for src in sources:
        if src.suffix != ".json":
            continue
        # Byte sig'ler
        try:
            for entry in iter_byte_sigs_from_json(src):
                key = (entry["name"], entry["byte_pattern_hex"])
                if key in seen_byte_keys:
                    continue
                seen_byte_keys.add(key)
                byte_entries.append(entry)
        except Exception as exc:
            logger.debug("Byte sig iter hata %s: %s", src.name, exc)
        # Call sig'ler
        try:
            for callee_set, payload in iter_call_sigs_from_json(src):
                call_entries.append((callee_set, payload))
        except Exception as exc:
            logger.debug("Call sig iter hata %s: %s", src.name, exc)

    byte_count = 0
    if byte_entries:
        try:
            byte_count = db.bulk_write_byte_sigs(byte_entries)
            logger.info("Harici byte_sigs yazildi: %d", byte_count)
        except Exception as exc:
            logger.warning("Harici byte_sigs yazimi basarisiz: %s", exc)

    call_count = 0
    if call_entries:
        try:
            call_count = db.bulk_write_call_sigs(call_entries)
            logger.info("Harici call_sigs yazildi: %d", call_count)
        except Exception as exc:
            logger.warning("Harici call_sigs yazimi basarisiz: %s", exc)

    return byte_count, call_count


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
        "--shards",
        type=int,
        default=4,
        help="Bellek sınırı için ad parçası sayısı (şema 2 toplaması). Varsayılan: 4.",
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
            shards=args.shards,
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
