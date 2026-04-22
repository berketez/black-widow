"""ReferencePopulator testleri.

Test edilen senaryolar:
1. URL uretimi: SQLite versiyon -> URL kod donusumu
2. URL uretimi: zlib, openssl, libcurl generic URL
3. Versiyon parse: string -> tuple
4. Desteklenen kutuphane kontrolu
5. Cache mekanizmasi
6. Download + extract (mock ile)
7. Compile step (mock ile)
8. Populate pipeline (skip_ghidra=True ile)
9. Edge case'ler (bos versiyon, desteklenmeyen kutuphane, vb.)
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
from pathlib import Path
from unittest import mock

import pytest

from karadul.reconstruction.reference_differ import Detection, ReferenceDBEntry
from karadul.reconstruction.reference_populator import (
    PopulateResult,
    ReferencePopulator,
    _build_sqlite_url,
    _sqlite_version_to_url_code,
    build_download_urls,
    parse_version_tuple,
)


# ---------------------------------------------------------------------------
# SQLite URL Kod Testleri
# ---------------------------------------------------------------------------


class TestSqliteVersionToUrlCode:
    """_sqlite_version_to_url_code testleri."""

    def test_basic_version(self):
        """3.46.0 -> 3460000"""
        assert _sqlite_version_to_url_code("3.46.0") == "3460000"

    def test_patch_version(self):
        """3.45.2 -> 3450200"""
        assert _sqlite_version_to_url_code("3.45.2") == "3450200"

    def test_double_digit_minor(self):
        """3.8.11 -> 3081100"""
        assert _sqlite_version_to_url_code("3.8.11") == "3081100"

    def test_four_part_version(self):
        """3.8.11.1 -> 3081101"""
        assert _sqlite_version_to_url_code("3.8.11.1") == "3081101"

    def test_version_39(self):
        """3.39.4 -> 3390400"""
        assert _sqlite_version_to_url_code("3.39.4") == "3390400"

    def test_invalid_version_too_short(self):
        """Kisa versiyon ValueError firlatir."""
        with pytest.raises(ValueError):
            _sqlite_version_to_url_code("3.46")

    def test_invalid_version_non_numeric(self):
        """Sayi olmayan parcalar ValueError firlatir."""
        with pytest.raises(ValueError):
            _sqlite_version_to_url_code("abc.def.ghi")


class TestBuildSqliteUrl:
    """_build_sqlite_url testleri."""

    def test_returns_multiple_urls(self):
        """Birden fazla yil icin URL uretir."""
        urls = _build_sqlite_url("3.46.0")
        assert len(urls) >= 3
        assert all("sqlite.org" in u for u in urls)
        assert all("3460000" in u for u in urls)

    def test_url_contains_year(self):
        """URL'ler farkli yillari icerir."""
        urls = _build_sqlite_url("3.46.0")
        years = set()
        for u in urls:
            # https://sqlite.org/YYYY/...
            parts = u.split("/")
            years.add(parts[3])
        assert len(years) >= 3

    def test_invalid_version_returns_empty(self):
        """Gecersiz versiyon bos liste dondurur."""
        urls = _build_sqlite_url("invalid")
        assert urls == []


# ---------------------------------------------------------------------------
# Generic URL Builder Testleri
# ---------------------------------------------------------------------------


class TestBuildDownloadUrls:
    """build_download_urls testleri."""

    def test_sqlite_urls(self):
        """SQLite URL'leri ozel builder kullanir."""
        urls = build_download_urls("sqlite3", "3.46.0")
        assert len(urls) >= 1
        assert "3460000" in urls[0]

    def test_zlib_url(self):
        """zlib URL'i versiyon icerir."""
        urls = build_download_urls("zlib", "1.3.1")
        assert len(urls) == 1
        assert "zlib-1.3.1.tar.gz" in urls[0]

    def test_openssl_url(self):
        """openssl URL'i versiyon icerir."""
        urls = build_download_urls("openssl", "3.1.2")
        assert len(urls) == 1
        assert "openssl-3.1.2.tar.gz" in urls[0]

    def test_curl_url(self):
        """libcurl URL'i versiyon icerir."""
        urls = build_download_urls("libcurl", "8.4.0")
        assert len(urls) == 1
        assert "curl-8.4.0.tar.gz" in urls[0]

    def test_unsupported_library(self):
        """Desteklenmeyen kutuphane bos liste dondurur."""
        urls = build_download_urls("unknown_lib", "1.0.0")
        assert urls == []


# ---------------------------------------------------------------------------
# Version Parse Testleri
# ---------------------------------------------------------------------------


class TestParseVersionTuple:
    """parse_version_tuple testleri."""

    def test_three_part(self):
        assert parse_version_tuple("3.46.0") == (3, 46, 0)

    def test_four_part(self):
        assert parse_version_tuple("3.8.11.1") == (3, 8, 11, 1)

    def test_two_part(self):
        assert parse_version_tuple("1.22") == (1, 22)

    def test_with_suffix(self):
        """Sayi olmayan suffix atlanir."""
        assert parse_version_tuple("3.1.2a") == (3, 1, 2)

    def test_empty(self):
        assert parse_version_tuple("") == ()

    def test_single(self):
        assert parse_version_tuple("42") == (42,)


# ---------------------------------------------------------------------------
# ReferencePopulator Temel Testleri
# ---------------------------------------------------------------------------


class TestReferencePopulatorBasic:
    """ReferencePopulator temel islevsellik testleri."""

    def test_is_library_supported(self):
        """Desteklenen kutuphaneler."""
        assert ReferencePopulator.is_library_supported("sqlite3")
        assert ReferencePopulator.is_library_supported("zlib")
        assert ReferencePopulator.is_library_supported("openssl")
        assert ReferencePopulator.is_library_supported("libcurl")
        assert not ReferencePopulator.is_library_supported("unknown_lib")

    def test_supported_libraries_list(self):
        """Desteklenen kutuphane listesi."""
        libs = ReferencePopulator.supported_libraries()
        assert "sqlite3" in libs
        assert "zlib" in libs
        assert len(libs) >= 4

    def test_cache_dir_created(self):
        """Cache dizinleri olusturulur."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache_dir = Path(tmpdir) / "cache"
            pop = ReferencePopulator(cache_dir=cache_dir)

            assert (cache_dir / "sources").exists()
            assert (cache_dir / "ref_db").exists()
            assert (cache_dir / "build").exists()

    def test_ref_db_path(self):
        """ref_db_path property'si dogru yol dondurur."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache_dir = Path(tmpdir) / "cache"
            pop = ReferencePopulator(cache_dir=cache_dir)
            assert pop.ref_db_path == cache_dir / "ref_db"

    def test_detect_compiler(self):
        """Compiler tespiti bir sonuc dondurur."""
        compiler = ReferencePopulator._detect_compiler()
        assert compiler in ("cc", "gcc", "clang")


# ---------------------------------------------------------------------------
# Cache Testleri
# ---------------------------------------------------------------------------


class TestReferencePopulatorCache:
    """Cache mekanizmasi testleri."""

    def test_is_cached_false(self):
        """Bos cache'de hicbir sey yok."""
        with tempfile.TemporaryDirectory() as tmpdir:
            pop = ReferencePopulator(cache_dir=Path(tmpdir) / "cache")
            assert not pop.is_cached("sqlite3", "3.46.0")

    def test_is_cached_true(self):
        """Mevcut cache entry tespiti."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache_dir = Path(tmpdir) / "cache"
            pop = ReferencePopulator(cache_dir=cache_dir)

            # Manuel cache entry olustur
            ref_dir = cache_dir / "ref_db" / "sqlite3" / "3.46.0"
            ref_dir.mkdir(parents=True)
            (ref_dir / "ghidra_functions.json").write_text(
                '{"functions": [], "total": 0}'
            )

            assert pop.is_cached("sqlite3", "3.46.0")

    def test_get_cached_entry(self):
        """Cache'den entry okuma."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache_dir = Path(tmpdir) / "cache"
            pop = ReferencePopulator(cache_dir=cache_dir)

            # Manuel cache entry olustur
            ref_dir = cache_dir / "ref_db" / "zlib" / "1.3.1"
            ref_dir.mkdir(parents=True)
            (ref_dir / "ghidra_functions.json").write_text(
                '{"functions": [{"name": "inflateInit", "address": "0x1000"}], "total": 1}'
            )
            (ref_dir / "ghidra_strings.json").write_text(
                '{"strings": [], "total": 0}'
            )

            entry = pop.get_cached_entry("zlib", "1.3.1")
            assert entry is not None
            assert entry.library == "zlib"
            assert entry.version == "1.3.1"
            assert entry.functions_json.exists()
            assert entry.strings_json is not None

    def test_get_cached_entry_nonexistent(self):
        """Olmayan cache entry None dondurur."""
        with tempfile.TemporaryDirectory() as tmpdir:
            pop = ReferencePopulator(cache_dir=Path(tmpdir) / "cache")
            assert pop.get_cached_entry("sqlite3", "9.99.99") is None

    def test_populate_returns_cached(self):
        """Populate, cache'de entry varsa tekrar indirmez."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache_dir = Path(tmpdir) / "cache"
            pop = ReferencePopulator(cache_dir=cache_dir, skip_ghidra=True)

            # Cache'e elle ekle
            ref_dir = cache_dir / "ref_db" / "sqlite3" / "3.46.0"
            ref_dir.mkdir(parents=True)
            (ref_dir / "ghidra_functions.json").write_text(
                '{"functions": [], "total": 0}'
            )

            det = Detection("sqlite3", "3.46.0", 0.95)
            result = pop.populate(det)

            assert result.success
            assert result.cached
            assert "cache_hit" in result.steps_completed
            assert result.entry is not None


# ---------------------------------------------------------------------------
# Populate Pipeline Testleri
# ---------------------------------------------------------------------------


class TestReferencePopulatorPopulate:
    """populate() pipeline testleri."""

    def test_unsupported_library(self):
        """Desteklenmeyen kutuphane basarisiz doner."""
        with tempfile.TemporaryDirectory() as tmpdir:
            pop = ReferencePopulator(cache_dir=Path(tmpdir) / "cache")
            det = Detection("unknown_lib", "1.0.0", 0.80)
            result = pop.populate(det)

            assert not result.success
            assert "desteklenmiyor" in (result.error or "")

    def test_populate_download_failure(self):
        """Indirme basarisiz olursa hata dondurur."""
        with tempfile.TemporaryDirectory() as tmpdir:
            pop = ReferencePopulator(cache_dir=Path(tmpdir) / "cache", skip_ghidra=True)

            # Download'i mocklayalim -- tum URL'ler fail
            with mock.patch.object(pop, "_download_file", side_effect=Exception("Network error")):
                det = Detection("sqlite3", "99.99.99", 0.80)
                result = pop.populate(det)

                assert not result.success
                assert "indirilemedi" in (result.error or "").lower()

    def test_populate_compile_failure(self):
        """Derleme basarisiz olursa hata dondurur."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache_dir = Path(tmpdir) / "cache"
            pop = ReferencePopulator(cache_dir=cache_dir, skip_ghidra=True)

            # Sahte source dir hazirla (download basarili gibi goster)
            source_dir = cache_dir / "sources" / "sqlite3" / "3.46.0" / "src"
            source_dir.mkdir(parents=True)
            (source_dir / "sqlite3.c").write_text("// dummy")

            # Compile'i basarisiz yap
            with mock.patch.object(pop, "_compile_source", return_value=None):
                det = Detection("sqlite3", "3.46.0", 0.95)
                result = pop.populate(det)

                # download basarili ama compile basarisiz
                assert not result.success
                assert "derleme" in (result.error or "").lower()

    def test_populate_full_pipeline_skip_ghidra(self):
        """skip_ghidra=True ile tam pipeline (sahte source + compile)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache_dir = Path(tmpdir) / "cache"
            pop = ReferencePopulator(cache_dir=cache_dir, skip_ghidra=True)

            # Sahte source dir ve compile sonucu hazirla
            source_dir = cache_dir / "sources" / "sqlite3" / "3.46.0" / "src"
            source_dir.mkdir(parents=True)
            (source_dir / "sqlite3.c").write_text("// dummy")

            build_dir = cache_dir / "build" / "sqlite3" / "3.46.0"
            build_dir.mkdir(parents=True)
            fake_binary = build_dir / "sqlite3.o"
            fake_binary.write_bytes(b"\x00" * 100)

            with mock.patch.object(pop, "_download_source", return_value=source_dir):
                with mock.patch.object(pop, "_compile_source", return_value=fake_binary):
                    det = Detection("sqlite3", "3.46.0", 0.95)
                    result = pop.populate(det)

                    assert result.success
                    assert "download" in result.steps_completed
                    assert "compile" in result.steps_completed
                    assert "minimal_save" in result.steps_completed
                    assert result.entry is not None
                    assert result.entry.functions_json.exists()


# ---------------------------------------------------------------------------
# Download Testleri
# ---------------------------------------------------------------------------


class TestReferencePopulatorDownload:
    """Indirme ve arsiv cikarma testleri."""

    def test_find_source_root_single_subdir(self):
        """Tek alt dizinli arsiv: o dizini dondurur."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache_dir = Path(tmpdir)
            subdir = cache_dir / "sqlite-amalgamation-3460000"
            subdir.mkdir()
            (subdir / "sqlite3.c").write_text("// code")

            result = ReferencePopulator._find_source_root(cache_dir)
            assert result == subdir

    def test_find_source_root_multiple_subdirs(self):
        """Birden fazla alt dizin: ust dizini dondurur."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache_dir = Path(tmpdir)
            (cache_dir / "dir1").mkdir()
            (cache_dir / "dir2").mkdir()

            result = ReferencePopulator._find_source_root(cache_dir)
            assert result == cache_dir

    def test_find_source_root_no_subdirs(self):
        """Alt dizin yok: ust dizini dondurur."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache_dir = Path(tmpdir)
            (cache_dir / "file.txt").write_text("data")

            result = ReferencePopulator._find_source_root(cache_dir)
            assert result == cache_dir

    def test_extract_archive_zip(self):
        """ZIP arsiv cikarma."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Bir zip dosyasi olustur
            zip_path = Path(tmpdir) / "test.zip"
            dest_dir = Path(tmpdir) / "output"
            dest_dir.mkdir()

            import zipfile
            with zipfile.ZipFile(zip_path, "w") as zf:
                zf.writestr("test_dir/hello.txt", "world")
                zf.writestr("test_dir/code.c", "int main() {}")

            ReferencePopulator._extract_archive(zip_path, dest_dir, "zip")

            assert (dest_dir / "test_dir" / "hello.txt").exists()
            assert (dest_dir / "test_dir" / "code.c").exists()

    def test_extract_archive_tar_gz(self):
        """tar.gz arsiv cikarma."""
        with tempfile.TemporaryDirectory() as tmpdir:
            import tarfile

            tar_path = Path(tmpdir) / "test.tar.gz"
            dest_dir = Path(tmpdir) / "output"
            dest_dir.mkdir()

            # Gecici dosyalar olustur
            src_dir = Path(tmpdir) / "src"
            src_dir.mkdir()
            (src_dir / "hello.txt").write_text("world")

            with tarfile.open(tar_path, "w:gz") as tf:
                tf.add(src_dir / "hello.txt", arcname="test_dir/hello.txt")

            ReferencePopulator._extract_archive(tar_path, dest_dir, "tar.gz")
            assert (dest_dir / "test_dir" / "hello.txt").exists()


# ---------------------------------------------------------------------------
# Compile Testleri
# ---------------------------------------------------------------------------


class TestReferencePopulatorCompile:
    """Derleme adimi testleri."""

    def test_run_compile_step_success(self):
        """Basarili derleme adimi (sahte compiler)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache_dir = Path(tmpdir) / "cache"
            pop = ReferencePopulator(cache_dir=cache_dir)

            build_dir = Path(tmpdir) / "build"
            build_dir.mkdir()
            (build_dir / "test.c").write_text("int main() { return 0; }")

            step = {
                "type": "compile",
                "compiler": "cc",
                "args": ["-g", "-c", "test.c", "-o", "test.o"],
                "source_file": "test.c",
                "output_file": "test.o",
            }

            # cc mevcut mu kontrol et
            if shutil.which("cc"):
                success = pop._run_compile_step(build_dir, step)
                assert success
                assert (build_dir / "test.o").exists()
            else:
                pytest.skip("C compiler mevcut degil")

    def test_run_compile_step_missing_source(self):
        """Kaynak dosya yoksa basarisiz."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache_dir = Path(tmpdir) / "cache"
            pop = ReferencePopulator(cache_dir=cache_dir)

            build_dir = Path(tmpdir) / "build"
            build_dir.mkdir()

            step = {
                "type": "compile",
                "compiler": "cc",
                "args": ["-c", "nonexistent.c"],
                "source_file": "nonexistent.c",
            }

            success = pop._run_compile_step(build_dir, step)
            assert not success

    def test_run_shell_step_success(self):
        """Basarili shell komutu.

        v1.10.0 Fix Sprint HIGH-3: 'echo' whitelist'ten cikarildi
        (CWE-78 icin _ALLOWED_SHELL_CMDS: make/cmake/ar/ranlib/strip/ln/
        ./configure/./Configure). Testi whitelist'teki 'make --version'
        ile calistiriyoruz (macOS'ta stock GNU Make, returncode=0 doner).
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            cache_dir = Path(tmpdir) / "cache"
            pop = ReferencePopulator(cache_dir=cache_dir)

            build_dir = Path(tmpdir) / "build"
            build_dir.mkdir()

            step = {
                "type": "shell",
                "command": "make",
                "args": ["--version"],
            }

            success = pop._run_shell_step(build_dir, step)
            assert success

    def test_run_shell_step_nonexistent_command(self):
        """Mevcut olmayan komut basarisiz."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache_dir = Path(tmpdir) / "cache"
            pop = ReferencePopulator(cache_dir=cache_dir)

            build_dir = Path(tmpdir) / "build"
            build_dir.mkdir()

            step = {
                "type": "shell",
                "command": "nonexistent_command_xyz",
                "args": [],
            }

            success = pop._run_shell_step(build_dir, step)
            assert not success


# ---------------------------------------------------------------------------
# Minimal Save Testleri
# ---------------------------------------------------------------------------


class TestReferencePopulatorMinimalSave:
    """Minimal kayit testleri (Ghidra yokken)."""

    def test_save_minimal_reference(self):
        """Minimal reference kaydedilir."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache_dir = Path(tmpdir) / "cache"
            pop = ReferencePopulator(cache_dir=cache_dir, skip_ghidra=True)

            fake_binary = Path(tmpdir) / "test.o"
            fake_binary.write_bytes(b"\x00" * 64)

            entry = pop._save_minimal_reference("sqlite3", "3.46.0", fake_binary)

            assert entry is not None
            assert entry.library == "sqlite3"
            assert entry.version == "3.46.0"
            assert entry.functions_json.exists()

            # JSON gecerli mi?
            data = json.loads(entry.functions_json.read_text())
            assert data["total"] == 0
            assert data["functions"] == []

            # Metadata dosyasi da var mi?
            metadata_path = entry.db_path / "metadata.json"
            assert metadata_path.exists()


# ---------------------------------------------------------------------------
# Temizlik Testleri
# ---------------------------------------------------------------------------


class TestReferencePopulatorCleanup:
    """Cache temizleme testleri."""

    def test_clean_build_cache(self):
        """Build cache temizlenir."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache_dir = Path(tmpdir) / "cache"
            pop = ReferencePopulator(cache_dir=cache_dir)

            # Build cache'e dosya ekle
            build = cache_dir / "build" / "sqlite3" / "3.46.0"
            build.mkdir(parents=True)
            (build / "test.o").write_bytes(b"\x00" * 64)

            pop.clean_build_cache("sqlite3")
            assert not (cache_dir / "build" / "sqlite3").exists()

    def test_clean_all_specific(self):
        """Belirli kutuphane+versiyon temizligi."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache_dir = Path(tmpdir) / "cache"
            pop = ReferencePopulator(cache_dir=cache_dir)

            # Her cache'e dosya ekle
            for subdir in ["sources", "ref_db", "build"]:
                d = cache_dir / subdir / "sqlite3" / "3.46.0"
                d.mkdir(parents=True)
                (d / "dummy").write_text("data")

            pop.clean_all(library="sqlite3", version="3.46.0")

            for subdir in ["sources", "ref_db", "build"]:
                assert not (cache_dir / subdir / "sqlite3" / "3.46.0").exists()

    def test_clean_all_library(self):
        """Tum kutuphane temizligi."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache_dir = Path(tmpdir) / "cache"
            pop = ReferencePopulator(cache_dir=cache_dir)

            for ver in ["3.45.0", "3.46.0"]:
                for subdir in ["sources", "ref_db", "build"]:
                    d = cache_dir / subdir / "sqlite3" / ver
                    d.mkdir(parents=True)
                    (d / "dummy").write_text("data")

            pop.clean_all(library="sqlite3")

            for subdir in ["sources", "ref_db", "build"]:
                assert not (cache_dir / subdir / "sqlite3").exists()
