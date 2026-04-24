"""Reference Binary Auto-Populator -- source download, debug compile, Ghidra analysis.

VersionDetector bir kutuphane/versiyon tespit ettiginde (orn. "sqlite3 3.46.0"),
kaynak kodunu indirir, debug flag'leriyle derler, Ghidra ile analiz eder ve
sonuclari reference DB'ye kaydeder.

Desteklenen kutuphaneler (v1):
    - sqlite3: amalgamation, tek dosya, gcc -g
    - zlib: configure && make CFLAGS="-g -O2"

Ileride eklenecekler (URL tanimli, compile karmasik):
    - openssl, libcurl

Kullanim:
    from karadul.reconstruction.reference_populator import ReferencePopulator
    from karadul.reconstruction.reference_differ import Detection

    populator = ReferencePopulator()
    entry = populator.populate(Detection("sqlite3", "3.46.0", 0.95))
    # entry: ReferenceDBEntry veya None

Cache dizinleri:
    ~/.cache/karadul/sources/          -- indirilen kaynak arsivler
    ~/.cache/karadul/ref_db/           -- Ghidra analiz sonuclari (JSON)
    ~/.cache/karadul/build/            -- gecici derleme dizinleri

v1.7.3: Ilk implementasyon.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import platform
import re
import shutil
import subprocess
import tarfile
import tempfile
import urllib.error
import urllib.request
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from karadul.reconstruction.reference_differ import (
    Detection,
    ReferenceDB,
    ReferenceDBEntry,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Sabitler
# ---------------------------------------------------------------------------

# Cache dizinleri
_DEFAULT_CACHE_DIR = Path.home() / ".cache" / "karadul"
_SOURCES_DIR_NAME = "sources"
_REF_DB_DIR_NAME = "ref_db"
_BUILD_DIR_NAME = "build"

# Download timeout (saniye)
_DOWNLOAD_TIMEOUT = 120

# Compile timeout (saniye)
_COMPILE_TIMEOUT = 300

# Izin verilen compiler ve shell komutlari (CWE-78 onlemi)
# v1.10.0 Fix Sprint HIGH-3: Whitelist daraltildi. cp/mv/mkdir/install/echo
# KALDIRILDI cunku arsiv ek compile adimi disinda beklenmiyor ve metachar
# enjeksiyonunu zenginlestiriyorlar. Sadece gercek build komutlari kaldi.
_ALLOWED_COMPILERS = frozenset({"cc", "gcc", "clang", "g++", "clang++", "c99"})
_ALLOWED_SHELL_CMDS = frozenset({"make", "cmake", "ar", "ranlib", "strip", "ln", "./configure", "./Configure"})

# v1.10.0 Fix Sprint HIGH-3: Shell metachar karakterleri (argument icerisinde
# izinsiz). "CFLAGS=-g -O2" gibi tek tirnak gerektirmeyen arg'lar kalir.
_SHELL_METACHARS = frozenset(";&|`$<>\n\r(){}\\\"'")

# v1.10.0 Fix Sprint HIGH-2: ZIP/TAR bomb koruma sinir (byte).
# config.SecurityConfig.max_archive_extract_size degerini kullaniyor, ama
# config erisimi olmayan static code path'leri icin default yazildi.
_DEFAULT_MAX_ARCHIVE_SIZE = 2 * 1024 ** 3  # 2GB

# Desteklenen kutuphaneler ve URL sablonlari
# Her kutuphane icin: url_template, archive_type, compile_steps
# url_template: {version} ve opsiyonel {url_code} placeholder'lari kabul eder

_SUPPORTED_LIBRARIES: dict[str, dict[str, Any]] = {
    "sqlite3": {
        "url_template": "https://sqlite.org/{year}/sqlite-amalgamation-{url_code}.zip",
        "url_builder": "_build_sqlite_url",  # ozel URL builder
        "archive_type": "zip",
        "compile_steps": [
            {
                "type": "compile",
                "compiler": "cc",
                "args": [
                    "-g", "-O2",
                    "-DSQLITE_ENABLE_FTS5",
                    "-DSQLITE_ENABLE_JSON1",
                    "-DSQLITE_ENABLE_RTREE",
                    "-c", "sqlite3.c",
                    "-o", "sqlite3.o",
                ],
                "source_file": "sqlite3.c",
                "output_file": "sqlite3.o",
            },
        ],
        "debug_binary": "sqlite3.o",  # Ghidra'ya verilecek dosya
    },
    "zlib": {
        "url_template": "https://zlib.net/zlib-{version}.tar.gz",
        "archive_type": "tar.gz",
        "compile_steps": [
            {
                "type": "shell",
                "command": "./configure",
                "args": [],
            },
            {
                "type": "shell",
                "command": "make",
                "args": ["CFLAGS=-g -O2"],
            },
        ],
        "debug_binary": "libz.a",  # static library
        # zlib configure + make dizin icinde birden fazla .o uretir
        # Ghidra icin .a veya en buyuk .o kullanilir
        "fallback_binaries": ["adler32.o", "crc32.o", "inflate.o", "deflate.o"],
    },
    "openssl": {
        "url_template": "https://www.openssl.org/source/openssl-{version}.tar.gz",
        "archive_type": "tar.gz",
        "compile_steps": [
            {
                "type": "shell",
                "command": "./Configure",
                "args": ["--debug", "no-shared"],
            },
            {
                "type": "shell",
                "command": "make",
                "args": ["-j4"],
            },
        ],
        "debug_binary": "libcrypto.a",
        "requires_system_deps": True,  # perl, etc.
    },
    "libcurl": {
        "url_template": "https://curl.se/download/curl-{version}.tar.gz",
        "archive_type": "tar.gz",
        "compile_steps": [
            {
                "type": "shell",
                "command": "./configure",
                "args": ["--disable-shared", "CFLAGS=-g -O2"],
            },
            {
                "type": "shell",
                "command": "make",
                "args": ["-j4"],
            },
        ],
        "debug_binary": "lib/.libs/libcurl.a",
        "requires_system_deps": True,
    },
}

# SQLite URL yil lookup: major.minor -> yil
# SQLite ayri bir URL formatinda: https://sqlite.org/YYYY/sqlite-amalgamation-VVVVVVV.zip
# Tam yil bilgisi olmadan deneme-yanilma ile bulunur
_SQLITE_YEAR_CANDIDATES = [2026, 2025, 2024, 2023, 2022, 2021, 2020]


# ---------------------------------------------------------------------------
# URL Builder Fonksiyonlari
# ---------------------------------------------------------------------------


def _sqlite_version_to_url_code(version: str) -> str:
    """SQLite versiyon string'ini URL kod formatina cevir.

    Ornek: "3.46.0" -> "3460000"
            "3.45.2" -> "3450200"
            "3.8.11" -> "3081100"
            "3.8.11.1" -> "3081101"

    Format: X * 1000000 + Y * 10000 + Z * 100 + W
    Burada X.Y.Z.W versiyon parcalari.
    """
    parts = version.split(".")
    if len(parts) < 3:
        raise ValueError(f"Gecersiz SQLite versiyon: {version}")

    x = int(parts[0])  # major
    y = int(parts[1])  # minor
    z = int(parts[2])  # patch
    w = int(parts[3]) if len(parts) > 3 else 0  # sub-patch

    code = x * 1000000 + y * 10000 + z * 100 + w
    return str(code)


def _build_sqlite_url(version: str) -> list[str]:
    """SQLite icin olasi URL'lerin listesini dondur (yil bilinmiyor, denenir).

    Returns:
        URL listesi, yeniden eskiye.
    """
    try:
        url_code = _sqlite_version_to_url_code(version)
    except (ValueError, IndexError) as exc:
        logger.warning("SQLite versiyon parse hatasi: %s -- %s", version, exc)
        return []

    urls = []
    for year in _SQLITE_YEAR_CANDIDATES:
        urls.append(
            f"https://sqlite.org/{year}/sqlite-amalgamation-{url_code}.zip"
        )
    return urls


def _build_generic_url(template: str, version: str) -> list[str]:
    """Generic URL template'ten URL olustur. Tek URL dondurur."""
    url = template.replace("{version}", version)
    return [url]


def build_download_urls(library: str, version: str) -> list[str]:
    """Kutuphane ve versiyon icin indirme URL'lerinin listesini dondur.

    Returns:
        URL listesi (deneme sirasiyla). Bos liste = desteklenmiyor.
    """
    lib_config = _SUPPORTED_LIBRARIES.get(library)
    if not lib_config:
        return []

    url_builder = lib_config.get("url_builder")
    if url_builder == "_build_sqlite_url":
        return _build_sqlite_url(version)

    template = lib_config.get("url_template", "")
    if not template:
        return []

    return _build_generic_url(template, version)


def parse_version_tuple(version: str) -> tuple[int, ...]:
    """Versiyon string'ini tuple'a cevir: "3.46.0" -> (3, 46, 0).

    Sayi olmayan son parcalari atar (orn "3.1.2a" -> (3, 1, 2)).
    """
    parts = []
    for part in version.split("."):
        # Sadece rakamlari al
        num_match = re.match(r"(\d+)", part)
        if num_match:
            parts.append(int(num_match.group(1)))
        else:
            break
    return tuple(parts)


# ---------------------------------------------------------------------------
# ReferencePopulator
# ---------------------------------------------------------------------------


@dataclass
class PopulateResult:
    """Populate isleminin sonucu."""
    library: str
    version: str
    success: bool
    entry: Optional[ReferenceDBEntry] = None
    error: Optional[str] = None
    steps_completed: list[str] = field(default_factory=list)
    cached: bool = False  # Onceki sonuc kullanildi mi


class ReferencePopulator:
    """Reference binary veritabanini otomatik doldurur.

    Surec:
    1. Kaynak kodunu indir (veya cache'den al)
    2. Debug flag'leriyle derle
    3. Ghidra ile analiz et (fonksiyon, string, CFG cikart)
    4. Sonuclari ref_db'ye kaydet

    Args:
        cache_dir: Cache dizini. Default: ~/.cache/karadul/
        auto_populate: True ise populate() otomatik tetiklenir.
        skip_ghidra: True ise Ghidra analiz adimi atlanir (test icin).
        compiler: Kullanilacak C compiler. Default: "cc" (macOS: clang alias).
    """

    def __init__(
        self,
        cache_dir: Optional[Path] = None,
        auto_populate: bool = True,
        skip_ghidra: bool = False,
        compiler: Optional[str] = None,
    ) -> None:
        self._cache_dir = Path(cache_dir) if cache_dir else _DEFAULT_CACHE_DIR
        self._sources_dir = self._cache_dir / _SOURCES_DIR_NAME
        self._ref_db_dir = self._cache_dir / _REF_DB_DIR_NAME
        self._build_dir = self._cache_dir / _BUILD_DIR_NAME
        self._auto_populate = auto_populate
        self._skip_ghidra = skip_ghidra
        self._compiler = compiler or self._detect_compiler()

        # Dizinleri olustur
        self._sources_dir.mkdir(parents=True, exist_ok=True)
        self._ref_db_dir.mkdir(parents=True, exist_ok=True)
        self._build_dir.mkdir(parents=True, exist_ok=True)

    @property
    def ref_db_path(self) -> Path:
        """Reference DB dizin yolu."""
        return self._ref_db_dir

    @staticmethod
    def _detect_compiler() -> str:
        """Sistemde mevcut C compiler'i bul."""
        for compiler in ["cc", "gcc", "clang"]:
            if shutil.which(compiler):
                return compiler
        return "cc"  # fallback

    @staticmethod
    def is_library_supported(library: str) -> bool:
        """Kutuphane destekleniyor mu?"""
        return library in _SUPPORTED_LIBRARIES

    @staticmethod
    def supported_libraries() -> list[str]:
        """Desteklenen kutuphane listesi."""
        return list(_SUPPORTED_LIBRARIES.keys())

    def is_cached(self, library: str, version: str) -> bool:
        """Bu kutuphane+versiyon icin sonuc cache'de var mi?"""
        ref_path = self._ref_db_dir / library / version / "ghidra_functions.json"
        return ref_path.exists()

    def get_cached_entry(self, library: str, version: str) -> Optional[ReferenceDBEntry]:
        """Cache'deki entry'yi dondur, yoksa None."""
        lib_dir = self._ref_db_dir / library / version
        functions_json = lib_dir / "ghidra_functions.json"
        if not functions_json.exists():
            return None

        return ReferenceDBEntry(
            library=library,
            version=version,
            db_path=lib_dir,
            functions_json=functions_json,
            strings_json=lib_dir / "ghidra_strings.json" if (lib_dir / "ghidra_strings.json").exists() else None,
            cfg_json=lib_dir / "ghidra_cfg.json" if (lib_dir / "ghidra_cfg.json").exists() else None,
            call_graph_json=lib_dir / "ghidra_call_graph.json" if (lib_dir / "ghidra_call_graph.json").exists() else None,
            metadata={"auto_populated": True},
        )

    def populate(self, detection: Detection) -> PopulateResult:
        """Tespit edilen kutuphane icin reference data olustur.

        Args:
            detection: VersionDetector sonucu.

        Returns:
            PopulateResult: basari/basarisizlik durumu ve opsiyonel entry.
        """
        library = detection.library
        version = detection.version
        result = PopulateResult(library=library, version=version, success=False)

        # 0. Destekleniyor mu?
        if not self.is_library_supported(library):
            result.error = f"Kutuphane desteklenmiyor: {library}"
            logger.info("ReferencePopulator: %s desteklenmiyor, skip", library)
            return result

        # 1. Cache kontrolu
        if self.is_cached(library, version):
            entry = self.get_cached_entry(library, version)
            if entry:
                result.success = True
                result.entry = entry
                result.cached = True
                result.steps_completed.append("cache_hit")
                logger.info(
                    "ReferencePopulator: %s %s cache'de mevcut", library, version
                )
                return result

        # 2. Kaynak indir
        source_dir = self._download_source(library, version)
        if source_dir is None:
            result.error = f"Kaynak indirilemedi: {library} {version}"
            return result
        result.steps_completed.append("download")

        # 3. Derle
        lib_config = _SUPPORTED_LIBRARIES[library]
        if lib_config.get("requires_system_deps"):
            logger.warning(
                "ReferencePopulator: %s sistem bagimliliklari gerektiriyor, "
                "derleme basarisiz olabilir", library
            )

        debug_binary = self._compile_source(library, version, source_dir)
        if debug_binary is None:
            result.error = f"Derleme basarisiz: {library} {version}"
            return result
        result.steps_completed.append("compile")

        # 4. Ghidra analiz
        if self._skip_ghidra:
            # Ghidra atlanirsa minimal JSON kaydet (test icin)
            entry = self._save_minimal_reference(library, version, debug_binary)
            result.steps_completed.append("minimal_save")
        else:
            entry = self._analyze_with_ghidra(library, version, debug_binary)
            if entry is None:
                # Ghidra basarisiz olursa minimal kaydet
                entry = self._save_minimal_reference(library, version, debug_binary)
                result.steps_completed.append("ghidra_failed_minimal_save")
            else:
                result.steps_completed.append("ghidra_analyze")

        if entry:
            result.success = True
            result.entry = entry

        return result

    # ------------------------------------------------------------------
    # Download
    # ------------------------------------------------------------------

    def _download_source(
        self, library: str, version: str
    ) -> Optional[Path]:
        """Kutuphane kaynak kodunu indir ve arsivden cikar.

        Returns:
            Cikarilmis kaynak dizini veya None.
        """
        # Cache kontrol: arsiv zaten indirilmis mi?
        source_cache_dir = self._sources_dir / library / version
        if source_cache_dir.exists() and any(source_cache_dir.iterdir()):
            logger.info(
                "ReferencePopulator: %s %s kaynak cache'de", library, version
            )
            return self._find_source_root(source_cache_dir)

        # URL'leri al
        urls = build_download_urls(library, version)
        if not urls:
            logger.error(
                "ReferencePopulator: %s %s icin URL olusturulamadi",
                library, version,
            )
            return None

        source_cache_dir.mkdir(parents=True, exist_ok=True)

        # URL'leri sirayla dene
        lib_config = _SUPPORTED_LIBRARIES.get(library, {})
        archive_type = lib_config.get("archive_type", "tar.gz")

        for url in urls:
            logger.info("ReferencePopulator: indiriliyor %s", url)
            archive_path = source_cache_dir / f"archive.{archive_type}"

            try:
                self._download_file(url, archive_path)
            except Exception as exc:
                logger.debug("Indirme basarisiz: %s -- %s", url, exc)
                if archive_path.exists():
                    archive_path.unlink()
                continue

            # Arsivden cikar
            try:
                self._extract_archive(archive_path, source_cache_dir, archive_type)
                logger.info(
                    "ReferencePopulator: %s %s indirildi ve cikarildi",
                    library, version,
                )
                return self._find_source_root(source_cache_dir)
            except Exception as exc:
                logger.warning("Arsiv cikarma hatasi: %s", exc)
                if archive_path.exists():
                    archive_path.unlink()
                continue

        logger.error(
            "ReferencePopulator: %s %s -- tum URL'ler basarisiz", library, version
        )
        return None

    @staticmethod
    def _download_file(
        url: str,
        dest: Path,
        max_bytes: int = 500 * 1024 ** 2,
        allowed_schemes: tuple[str, ...] = ("https",),
        same_host_redirects: bool = True,
    ) -> None:
        """URL'den dosya indir.

        v1.10.0 Fix Sprint MED-1:
        - URL scheme whitelist (default: yalniz "https").
        - max_bytes chunked read; limit asilirsa partial dosya silinir.
        - Redirect: ayni hostname disina yonlendirme reddedilir
          (SSRF ve data exfiltration koruma).
        """
        from urllib.parse import urlparse

        parsed = urlparse(url)
        scheme = (parsed.scheme or "").lower()
        if scheme not in {s.lower() for s in allowed_schemes}:
            raise ValueError(
                f"Izin verilmeyen URL scheme: {scheme!r} (izinli: {allowed_schemes})"
            )
        initial_host = parsed.hostname

        class _SameHostRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                new_parsed = urlparse(newurl)
                new_scheme = (new_parsed.scheme or "").lower()
                if new_scheme not in {s.lower() for s in allowed_schemes}:
                    raise urllib.error.HTTPError(
                        newurl, code,
                        f"Redirect scheme reddedildi: {new_scheme!r}",
                        headers, fp,
                    )
                if same_host_redirects and new_parsed.hostname != initial_host:
                    raise urllib.error.HTTPError(
                        newurl, code,
                        f"Redirect host reddedildi: {new_parsed.hostname!r} "
                        f"(initial: {initial_host!r})",
                        headers, fp,
                    )
                return super().redirect_request(
                    req, fp, code, msg, headers, newurl,
                )

        opener = urllib.request.build_opener(_SameHostRedirect)
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "karadul-reference-populator/1.0"},
        )

        chunk = 1024 * 1024  # 1MB
        total = 0
        try:
            with opener.open(req, timeout=_DOWNLOAD_TIMEOUT) as resp:
                if resp.status != 200:
                    raise urllib.error.URLError(f"HTTP {resp.status}")
                with open(dest, "wb") as f:
                    while True:
                        buf = resp.read(chunk)
                        if not buf:
                            break
                        total += len(buf)
                        if total > max_bytes:
                            raise ValueError(
                                f"Download {total} byte, limit {max_bytes}"
                            )
                        f.write(buf)
        except Exception:
            # Partial dosyayi sil (kirli state birakma)
            if dest.exists():
                try:
                    dest.unlink()
                except OSError:
                    pass
            raise

    @staticmethod
    def _extract_archive(
        archive_path: Path,
        dest_dir: Path,
        archive_type: str,
        max_extract_size: int = _DEFAULT_MAX_ARCHIVE_SIZE,
    ) -> None:
        """Arsiv dosyasini cikar.

        v1.10.0 Fix Sprint HIGH-1/HIGH-2:
        - Path traversal: Path.relative_to kullanilir (prefix confusion yok).
        - ZIP/TAR bomb: uncompressed toplam max_extract_size'i asarsa reddedilir.
        """
        dest_root = dest_dir.resolve()

        def _assert_inside(member_path: Path, member_name: str) -> None:
            try:
                member_path.resolve().relative_to(dest_root)
            except ValueError:
                raise ValueError(
                    f"Guvenlik: arsiv path traversal engellendi: {member_name}"
                ) from None

        if archive_type == "zip":
            with zipfile.ZipFile(archive_path, "r") as zf:
                total = 0
                for member in zf.infolist():
                    _assert_inside(dest_dir / member.filename, member.filename)
                    total += member.file_size
                    if total > max_extract_size:
                        raise ValueError(
                            f"Guvenlik: arsiv {total} byte (ZIP bomb?), "
                            f"limit {max_extract_size}"
                        )
                zf.extractall(dest_dir)
        elif archive_type in ("tar.gz", "tgz"):
            with tarfile.open(archive_path, "r:gz") as tf:
                total = 0
                for tmember in tf.getmembers():
                    _assert_inside(Path(dest_dir / tmember.name), tmember.name)
                    total += max(0, tmember.size)
                    if total > max_extract_size:
                        raise ValueError(
                            f"Guvenlik: arsiv {total} byte (TAR bomb?), "
                            f"limit {max_extract_size}"
                        )
                tf.extractall(dest_dir, filter="data")
        elif archive_type == "tar.xz":
            with tarfile.open(archive_path, "r:xz") as tf:
                total = 0
                for tmember in tf.getmembers():
                    _assert_inside(Path(dest_dir / tmember.name), tmember.name)
                    total += max(0, tmember.size)
                    if total > max_extract_size:
                        raise ValueError(
                            f"Guvenlik: arsiv {total} byte (TAR bomb?), "
                            f"limit {max_extract_size}"
                        )
                tf.extractall(dest_dir, filter="data")
        else:
            raise ValueError(f"Desteklenmeyen arsiv tipi: {archive_type}")

    @staticmethod
    def _find_source_root(cache_dir: Path) -> Path:
        """Cache dizininde gercek kaynak kodun bulundugu alt dizini bul.

        Cogu arsiv tek ust dizin icinde cikar (orn. sqlite-amalgamation-3460000/).
        O dizini dondur. Yoksa cache_dir'in kendisi.
        """
        # Arsiv dosyalarini atla
        subdirs = [
            d for d in cache_dir.iterdir()
            if d.is_dir() and not d.name.startswith(".")
        ]

        if len(subdirs) == 1:
            return subdirs[0]
        return cache_dir

    # ------------------------------------------------------------------
    # Compile
    # ------------------------------------------------------------------

    def _compile_source(
        self, library: str, version: str, source_dir: Path
    ) -> Optional[Path]:
        """Kaynak kodunu debug flag'leriyle derle.

        Returns:
            Debug binary path veya None.
        """
        lib_config = _SUPPORTED_LIBRARIES.get(library)
        if not lib_config:
            return None

        compile_steps = lib_config.get("compile_steps", [])
        if not compile_steps:
            return None

        # Build dizini
        build_dir = self._build_dir / library / version
        if build_dir.exists():
            shutil.rmtree(build_dir)
        shutil.copytree(source_dir, build_dir)

        for step in compile_steps:
            step_type = step.get("type", "shell")

            try:
                if step_type == "compile":
                    success = self._run_compile_step(build_dir, step)
                elif step_type == "shell":
                    success = self._run_shell_step(build_dir, step)
                else:
                    logger.warning("Bilinmeyen step tipi: %s", step_type)
                    success = False

                if not success:
                    logger.error(
                        "ReferencePopulator: %s %s derleme adimi basarisiz: %s",
                        library, version, step,
                    )
                    return None

            except Exception as exc:
                logger.error(
                    "ReferencePopulator: derleme hatasi: %s %s -- %s",
                    library, version, exc,
                )
                return None

        # Debug binary'yi bul
        debug_binary_name = lib_config.get("debug_binary", "")
        debug_binary = build_dir / debug_binary_name

        if debug_binary.exists():
            return debug_binary

        # Fallback binary'ler dene
        for fb in lib_config.get("fallback_binaries", []):
            fb_path = build_dir / fb
            if fb_path.exists():
                logger.info(
                    "ReferencePopulator: fallback binary bulundu: %s", fb
                )
                return fb_path

        # Son care: en buyuk .o dosyasini bul
        o_files = list(build_dir.rglob("*.o"))
        if o_files:
            biggest = max(o_files, key=lambda p: p.stat().st_size)
            logger.info(
                "ReferencePopulator: en buyuk .o kullaniliyor: %s (%d bytes)",
                biggest.name, biggest.stat().st_size,
            )
            return biggest

        logger.error(
            "ReferencePopulator: %s %s -- debug binary bulunamadi",
            library, version,
        )
        return None

    def _run_compile_step(self, build_dir: Path, step: dict) -> bool:
        """Tek dosya derleme adimi."""
        compiler = step.get("compiler", self._compiler)
        args = step.get("args", [])
        source_file = step.get("source_file", "")

        # CWE-78: Compiler whitelist kontrolu
        compiler_base = Path(compiler).name
        if compiler_base not in _ALLOWED_COMPILERS:
            logger.warning("Izin verilmeyen compiler: %s", compiler)
            return False

        if source_file and not (build_dir / source_file).exists():
            logger.error("Kaynak dosya bulunamadi: %s", build_dir / source_file)
            return False

        cmd = [compiler] + args
        logger.info("Derleniyor: %s (cwd: %s)", " ".join(cmd), build_dir)

        try:
            result = subprocess.run(
                cmd,
                cwd=str(build_dir),
                capture_output=True,
                text=True,
                timeout=_COMPILE_TIMEOUT,
            )
            if result.returncode != 0:
                logger.error("Derleme hatasi (rc=%d):\n%s", result.returncode, result.stderr[:2000])
                return False
            return True
        except subprocess.TimeoutExpired:
            logger.error("Derleme timeout (%ds)", _COMPILE_TIMEOUT)
            return False
        except FileNotFoundError:
            logger.error("Compiler bulunamadi: %s", compiler)
            return False

    def _run_shell_step(self, build_dir: Path, step: dict) -> bool:
        """Shell komutu calistirma adimi."""
        command = step.get("command", "")
        args = step.get("args", [])

        if not command:
            return False

        # CWE-78: Shell komutu whitelist kontrolu.
        # v1.10.0 Fix Sprint HIGH-3: ./configure ve ./Configure tam match'le
        # kabul, diger komutlar basename ile.
        if command in _ALLOWED_SHELL_CMDS:
            pass
        else:
            command_base = Path(command).name
            if command_base not in _ALLOWED_SHELL_CMDS:
                logger.warning("Izin verilmeyen komut: %s", command)
                return False

        # v1.10.0 Fix Sprint HIGH-3: args injection onleme.
        # - Mutlak path (/etc/..., /bin/..., C:\...) yasak: cwd build_dir disina
        #   cikilmamasi icin. CFLAGS=-g -O2 gibi arg'lar sorun degil.
        # - Shell metacharakter (;, &, |, `, $, <, >, newline, vb.) yasak:
        #   subprocess.run shell=False olsa bile argv[i] ile komut zincirleme
        #   bazi build tool'larinda (make -f ...) yan etkili olabilir.
        for arg in args:
            if not isinstance(arg, str):
                logger.warning("Non-string argument reddedildi: %r", arg)
                return False
            if arg.startswith("/") or (len(arg) >= 3 and arg[1:3] == ":\\"):
                logger.warning("Mutlak path argumanda reddedildi: %s", arg)
                return False
            if any(c in _SHELL_METACHARS for c in arg):
                logger.warning("Shell metacharacter argumanda reddedildi: %r", arg)
                return False

        cmd = [command] + args
        logger.info("Shell komutu: %s (cwd: %s)", " ".join(cmd), build_dir)

        try:
            result = subprocess.run(
                cmd,
                cwd=str(build_dir),
                capture_output=True,
                text=True,
                timeout=_COMPILE_TIMEOUT,
            )
            if result.returncode != 0:
                logger.error(
                    "Shell komutu basarisiz (rc=%d):\n%s",
                    result.returncode, result.stderr[:2000],
                )
                return False
            return True
        except subprocess.TimeoutExpired:
            logger.error("Shell komutu timeout (%ds)", _COMPILE_TIMEOUT)
            return False
        except FileNotFoundError:
            logger.error("Komut bulunamadi: %s", command)
            return False

    # ------------------------------------------------------------------
    # Ghidra Analiz
    # ------------------------------------------------------------------

    def _analyze_with_ghidra(
        self, library: str, version: str, binary_path: Path
    ) -> Optional[ReferenceDBEntry]:
        """PyGhidra ile debug binary'yi analiz et, sonuclari kaydet.

        Returns:
            ReferenceDBEntry veya None.
        """
        try:
            import pyghidra
        except ImportError:
            logger.warning(
                "ReferencePopulator: PyGhidra mevcut degil, Ghidra analizi atlaniyor"
            )
            return None

        output_dir = self._ref_db_dir / library / version
        output_dir.mkdir(parents=True, exist_ok=True)

        project_dir = self._build_dir / "ghidra_projects" / library
        project_dir.mkdir(parents=True, exist_ok=True)

        logger.info(
            "ReferencePopulator: Ghidra analizi baslatiliyor: %s %s (%s)",
            library, version, binary_path.name,
        )

        try:
            # PyGhidra JVM baslatma
            if not pyghidra.started():
                # Ghidra install dizinini bul
                ghidra_install = self._find_ghidra_install()
                if ghidra_install is None:
                    logger.warning("Ghidra install dizini bulunamadi")
                    return None

                from pyghidra.launcher import HeadlessPyGhidraLauncher
                launcher = HeadlessPyGhidraLauncher(install_dir=ghidra_install)
                launcher.start()

            with pyghidra.open_program(
                binary_path=str(binary_path),
                project_location=str(project_dir),
                project_name=f"ref_{library}_{version}",
                analyze=True,
            ) as flat_api:
                program = flat_api.getCurrentProgram()

                # Fonksiyonlari cikart
                functions_data = self._extract_functions_pyghidra(program)
                (output_dir / "ghidra_functions.json").write_text(
                    json.dumps(functions_data, indent=2), encoding="utf-8"
                )

                # String'leri cikart
                strings_data = self._extract_strings_pyghidra(program)
                (output_dir / "ghidra_strings.json").write_text(
                    json.dumps(strings_data, indent=2), encoding="utf-8"
                )

                # CFG cikart
                cfg_data = self._extract_cfg_pyghidra(program)
                (output_dir / "ghidra_cfg.json").write_text(
                    json.dumps(cfg_data, indent=2), encoding="utf-8"
                )

                # Metadata kaydet
                metadata = {
                    "library": library,
                    "version": version,
                    "source": "auto_populated",
                    "binary": str(binary_path),
                    "arch": str(program.getLanguage()),
                    "compiler": self._compiler,
                    "platform": platform.system(),
                }
                (output_dir / "metadata.json").write_text(
                    json.dumps(metadata, indent=2), encoding="utf-8"
                )

            logger.info(
                "ReferencePopulator: %s %s Ghidra analizi tamamlandi: %d fonksiyon",
                library, version, len(functions_data.get("functions", [])),
            )

            return ReferenceDBEntry(
                library=library,
                version=version,
                db_path=output_dir,
                functions_json=output_dir / "ghidra_functions.json",
                strings_json=output_dir / "ghidra_strings.json",
                cfg_json=output_dir / "ghidra_cfg.json",
                metadata=metadata,
            )

        except Exception as exc:
            logger.error(
                "ReferencePopulator: Ghidra analiz hatasi: %s %s -- %s",
                library, version, exc,
            )
            return None

    @staticmethod
    def _find_ghidra_install() -> Optional[Path]:
        """Ghidra install dizinini bul."""
        # Cevresel degisken
        ghidra_home = os.environ.get("GHIDRA_INSTALL_DIR")
        if ghidra_home:
            p = Path(ghidra_home)
            if p.exists():
                return p

        # Bilinen yollar
        candidates = [
            Path.home() / "ghidra",
            Path("/opt/ghidra"),
            Path("/usr/local/ghidra"),
            Path("/Applications/ghidra"),
        ]
        # Home altinda ghidra_* dizinleri
        home = Path.home()
        for d in home.iterdir() if home.exists() else []:
            if d.is_dir() and d.name.startswith("ghidra_"):
                candidates.insert(0, d)

        for candidate in candidates:
            if candidate.exists() and (candidate / "Ghidra").exists():
                return candidate

        return None

    @staticmethod
    def _extract_functions_pyghidra(program) -> dict:
        """PyGhidra program objesinden fonksiyon listesi cikart."""
        functions = []
        func_mgr = program.getFunctionManager()
        for func in func_mgr.getFunctions(True):
            entry = func.getEntryPoint()
            body = func.getBody()
            size = body.getNumAddresses() if body else 0

            functions.append({
                "name": func.getName(),
                "address": str(entry),
                "size": int(size),
                "param_count": func.getParameterCount(),
                "return_type": str(func.getReturnType()),
                "calling_convention": str(func.getCallingConventionName() or ""),
                "is_thunk": func.isThunk(),
                "is_external": func.isExternal(),
            })

        return {
            "total": len(functions),
            "program": program.getName(),
            "functions": functions,
        }

    @staticmethod
    def _extract_strings_pyghidra(program) -> dict:
        """PyGhidra program objesinden string listesi cikart."""
        from ghidra.program.model.data import StringDataInstance
        from ghidra.program.util import DefinedDataIterator

        strings = []
        for data in DefinedDataIterator.definedStrings(program):
            value = StringDataInstance.getStringDataInstance(data)
            if value is None:
                continue
            str_value = value.getStringValue()
            if str_value and len(str_value) >= 3:
                addr = str(data.getAddress())

                # Xref'leri bul
                xrefs = []
                ref_mgr = program.getReferenceManager()
                for ref in ref_mgr.getReferencesTo(data.getAddress()):
                    from_addr = ref.getFromAddress()
                    containing_func = program.getFunctionManager().getFunctionContaining(from_addr)
                    if containing_func:
                        xrefs.append({
                            "from_address": str(from_addr),
                            "from_func_addr": str(containing_func.getEntryPoint()),
                        })

                strings.append({
                    "address": addr,
                    "value": str_value,
                    "type": "string",
                    "xrefs": xrefs,
                })

        return {
            "total": len(strings),
            "program": program.getName(),
            "strings": strings,
        }

    @staticmethod
    def _extract_cfg_pyghidra(program) -> dict:
        """PyGhidra program objesinden CFG verisi cikart."""
        from ghidra.program.model.block import BasicBlockModel

        functions_cfg = []
        func_mgr = program.getFunctionManager()
        block_model = BasicBlockModel(program)

        for func in func_mgr.getFunctions(True):
            entry = func.getEntryPoint()
            body = func.getBody()
            if body is None:
                continue

            blocks = []
            edges = []
            block_addrs = set()

            # Fonksiyon icindeki basic block'lari bul
            code_blocks = block_model.getCodeBlocksContaining(body, None)
            while code_blocks.hasNext():
                block = code_blocks.next()
                start = str(block.getFirstStartAddress())
                block_addrs.add(start)

                # Instruction count
                listing = program.getListing()
                inst_count = 0
                inst_iter = listing.getInstructions(block, True)
                has_call = False
                while inst_iter.hasNext():
                    inst = inst_iter.next()
                    inst_count += 1
                    if inst.getFlowType().isCall():
                        has_call = True

                blocks.append({
                    "start_address": start,
                    "instruction_count": inst_count,
                    "size": int(block.getNumAddresses()),
                    "has_call": has_call,
                })

                # Edges
                dest_iter = block.getDestinations(None)
                while dest_iter.hasNext():
                    dest_ref = dest_iter.next()
                    dest_block = dest_ref.getDestinationBlock()
                    if dest_block:
                        dst_addr = str(dest_block.getFirstStartAddress())
                        flow = dest_ref.getFlowType()
                        edge_type = "fall_through"
                        if flow.isConditional():
                            edge_type = "conditional_jump"
                        elif flow.isUnConditional() and not flow.isFallthrough():
                            edge_type = "unconditional_jump"
                        edges.append({
                            "from_block": start,
                            "to_block": dst_addr,
                            "edge_type": edge_type,
                        })

            # Cyclomatic complexity: E - N + 2
            n_blocks = len(blocks)
            n_edges = len(edges)
            complexity = max(1, n_edges - n_blocks + 2)

            # Back edges (basit heuristik: dst < src)
            back_edges = [
                e for e in edges
                if e["to_block"] in block_addrs and e["to_block"] < e["from_block"]
            ]
            loop_headers = list(set(e["to_block"] for e in back_edges))

            functions_cfg.append({
                "name": func.getName(),
                "address": str(entry),
                "blocks": blocks,
                "edges": edges,
                "cyclomatic_complexity": complexity,
                "loop_headers": loop_headers,
                "back_edges": back_edges,
            })

        return {
            "total": len(functions_cfg),
            "program": program.getName(),
            "functions": functions_cfg,
        }

    # ------------------------------------------------------------------
    # Minimal Save (Ghidra yoksa)
    # ------------------------------------------------------------------

    def _save_minimal_reference(
        self, library: str, version: str, binary_path: Path
    ) -> Optional[ReferenceDBEntry]:
        """Ghidra olmadan minimal reference kaydet.

        Binary'nin varligini ve metadata'sini kaydeder.
        Fonksiyon/string verisi olmadan eslestirme yapilmaz ama
        cache'de isaretlenerek tekrar denenmez.
        """
        output_dir = self._ref_db_dir / library / version
        output_dir.mkdir(parents=True, exist_ok=True)

        # Bos ama gecerli fonksiyon JSON'i
        functions_data = {
            "total": 0,
            "program": f"{library}_{version}_no_ghidra",
            "functions": [],
            "_note": "Ghidra analizi yapilamadi. Manuel analiz gerekiyor.",
        }
        (output_dir / "ghidra_functions.json").write_text(
            json.dumps(functions_data, indent=2), encoding="utf-8"
        )

        metadata = {
            "library": library,
            "version": version,
            "source": "auto_populated_no_ghidra",
            "binary": str(binary_path),
            "compiler": self._compiler,
            "platform": platform.system(),
        }
        (output_dir / "metadata.json").write_text(
            json.dumps(metadata, indent=2), encoding="utf-8"
        )

        return ReferenceDBEntry(
            library=library,
            version=version,
            db_path=output_dir,
            functions_json=output_dir / "ghidra_functions.json",
            metadata=metadata,
        )

    # ------------------------------------------------------------------
    # Temizlik
    # ------------------------------------------------------------------

    def clean_build_cache(self, library: Optional[str] = None) -> None:
        """Build cache'ini temizle.

        Args:
            library: Sadece bu kutuphaneyi temizle. None ise tumunu temizle.
        """
        if library:
            target = self._build_dir / library
        else:
            target = self._build_dir

        if target.exists():
            shutil.rmtree(target)
            # Sadece ust dizini (build/) yeniden olustur, alt dizini degil
            if not library:
                target.mkdir(parents=True, exist_ok=True)
            logger.info("Build cache temizlendi: %s", target)

    def clean_all(self, library: Optional[str] = None, version: Optional[str] = None) -> None:
        """Tum cache'leri temizle.

        Args:
            library: Sadece bu kutuphane. None ise tumunu temizle.
            version: Sadece bu versiyon. library gerektirir.
        """
        if library and version:
            for base in [self._sources_dir, self._ref_db_dir, self._build_dir]:
                target = base / library / version
                if target.exists():
                    shutil.rmtree(target)
        elif library:
            for base in [self._sources_dir, self._ref_db_dir, self._build_dir]:
                target = base / library
                if target.exists():
                    shutil.rmtree(target)
        else:
            for base in [self._sources_dir, self._ref_db_dir, self._build_dir]:
                if base.exists():
                    shutil.rmtree(base)
                    base.mkdir(parents=True, exist_ok=True)

        logger.info("Cache temizlendi: library=%s version=%s", library, version)
