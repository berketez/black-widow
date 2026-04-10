"""v1.8.0 Bug 7 LOW -- Platform-Aware Signature Filtering testleri.

macOS binary'de Windows API (msvcrt, kernel32) false positive engelleme.
ELF binary'de macOS framework false positive engelleme.
PE binary'de Linux syscall false positive engelleme.
target_platform=None ise filtre devre disi (geriye uyumlu).
External JSON'dan platform tahmini (dosya adi bazli).
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from karadul.analyzers.signature_db import (
    SignatureDB,
    SignatureMatch,
    _PE_ONLY_LIBS,
    _MACHO_ONLY_LIBS,
    _ELF_ONLY_LIBS,
    _is_platform_compatible,
    _infer_platform_from_filename,
)


# ===================================================================
# _is_platform_compatible unit testleri
# ===================================================================

class TestIsPlatformCompatible:
    """Lib/category/explicit-platform bazli filtreleme."""

    # -- target_platform=None -> her zaman True --

    def test_none_platform_always_compatible(self) -> None:
        assert _is_platform_compatible("kernel32", "win_file", None) is True
        assert _is_platform_compatible("CoreFoundation", "macos_cf", None) is True
        assert _is_platform_compatible("libsystemd", "linux_io", None) is True

    # -- PE-only lib'ler --

    @pytest.mark.parametrize("lib", [
        "kernel32", "user32", "advapi32", "ntdll", "ws2_32",
        "msvcrt", "shell32", "crypt32", "ole32", "oleaut32",
        "d3d11", "d3d12", "dxgi", "winhttp", "wininet",
    ])
    def test_pe_only_libs_blocked_on_macho(self, lib: str) -> None:
        assert _is_platform_compatible(lib, "misc", "macho") is False

    @pytest.mark.parametrize("lib", [
        "kernel32", "user32", "advapi32", "ntdll", "ws2_32", "msvcrt",
    ])
    def test_pe_only_libs_blocked_on_elf(self, lib: str) -> None:
        assert _is_platform_compatible(lib, "misc", "elf") is False

    @pytest.mark.parametrize("lib", [
        "kernel32", "user32", "advapi32", "ntdll", "ws2_32", "msvcrt",
    ])
    def test_pe_only_libs_allowed_on_pe(self, lib: str) -> None:
        assert _is_platform_compatible(lib, "misc", "pe") is True

    # -- macOS-only lib'ler --

    @pytest.mark.parametrize("lib", [
        "libdispatch", "libobjc", "swift_runtime", "CoreFoundation",
        "Foundation", "AppKit", "Metal", "IOKit", "Security",
    ])
    def test_macho_only_libs_blocked_on_pe(self, lib: str) -> None:
        assert _is_platform_compatible(lib, "misc", "pe") is False

    @pytest.mark.parametrize("lib", [
        "libdispatch", "libobjc", "CoreFoundation",
    ])
    def test_macho_only_libs_blocked_on_elf(self, lib: str) -> None:
        assert _is_platform_compatible(lib, "misc", "elf") is False

    @pytest.mark.parametrize("lib", [
        "libdispatch", "libobjc", "CoreFoundation", "Metal",
    ])
    def test_macho_only_libs_allowed_on_macho(self, lib: str) -> None:
        assert _is_platform_compatible(lib, "misc", "macho") is True

    # -- ELF-only lib'ler --

    def test_elf_only_libs_blocked_on_macho(self) -> None:
        assert _is_platform_compatible("libsystemd", "misc", "macho") is False

    def test_elf_only_libs_blocked_on_pe(self) -> None:
        assert _is_platform_compatible("libsystemd", "misc", "pe") is False

    def test_elf_only_libs_allowed_on_elf(self) -> None:
        assert _is_platform_compatible("libsystemd", "misc", "elf") is True

    # -- Category prefix filtreleme --

    @pytest.mark.parametrize("category", [
        "win_file", "win_process", "win_memory", "win_thread",
        "win_registry", "win_crypto",
    ])
    def test_win_category_blocked_on_macho(self, category: str) -> None:
        # lib "custom" ama category "win_*" -> PE-only
        assert _is_platform_compatible("custom", category, "macho") is False

    @pytest.mark.parametrize("category", [
        "linux_io", "linux_process", "linux_memory",
    ])
    def test_linux_category_blocked_on_pe(self, category: str) -> None:
        assert _is_platform_compatible("custom", category, "pe") is False

    @pytest.mark.parametrize("category", [
        "macos_cf", "macos_io", "objc_runtime",
    ])
    def test_macos_category_blocked_on_elf(self, category: str) -> None:
        assert _is_platform_compatible("custom", category, "elf") is False

    # -- Cross-platform lib'ler --

    @pytest.mark.parametrize("lib", [
        "openssl", "zlib", "sqlite3", "libcurl", "libuv",
    ])
    @pytest.mark.parametrize("platform", ["macho", "elf", "pe"])
    def test_cross_platform_libs_always_allowed(self, lib: str, platform: str) -> None:
        assert _is_platform_compatible(lib, "misc", platform) is True

    # -- Explicit platforms parameter --

    def test_explicit_platforms_overrides_lib_heuristic(self) -> None:
        # kernel32 normalde PE-only, ama explicit platforms = ["macho", "pe"] ise macho'da da gecerli
        assert _is_platform_compatible(
            "kernel32", "win_file", "macho", platforms=["macho", "pe"],
        ) is True

    def test_explicit_platforms_restricts(self) -> None:
        # Cross-platform lib ama explicit platforms = ["elf"] ise sadece elf'te gecerli
        assert _is_platform_compatible(
            "openssl", "crypto", "macho", platforms=["elf"],
        ) is False
        assert _is_platform_compatible(
            "openssl", "crypto", "elf", platforms=["elf"],
        ) is True


# ===================================================================
# _infer_platform_from_filename unit testleri
# ===================================================================

class TestInferPlatformFromFilename:
    def test_windows_prefix(self) -> None:
        assert _infer_platform_from_filename("windows_crypto.json") == ["pe"]
        assert _infer_platform_from_filename("win_api.json") == ["pe"]

    def test_linux_prefix(self) -> None:
        assert _infer_platform_from_filename("linux_syscalls.json") == ["elf"]

    def test_macos_prefix(self) -> None:
        assert _infer_platform_from_filename("macos_frameworks.json") == ["macho"]
        assert _infer_platform_from_filename("darwin_system.json") == ["macho"]

    def test_no_platform_prefix(self) -> None:
        assert _infer_platform_from_filename("openssl_signatures.json") is None
        assert _infer_platform_from_filename("crypto.json") is None

    def test_case_insensitive(self) -> None:
        assert _infer_platform_from_filename("Windows_API.json") == ["pe"]
        assert _infer_platform_from_filename("LINUX_io.json") == ["elf"]


# ===================================================================
# SignatureDB.match_function platform filtreleme testleri
# ===================================================================

class TestMatchFunctionPlatformFilter:
    """match_function ile platform filtreleme."""

    @pytest.fixture()
    def sig_db(self) -> SignatureDB:
        return SignatureDB()

    # -- Windows API macOS'ta bulunamamali --

    def test_kernel32_blocked_on_macho(self, sig_db: SignatureDB) -> None:
        """CreateFileA gibi kernel32 fonksiyonlari macOS target'ta eslesmemeli."""
        result = sig_db.match_function(
            func_name="CreateFileA", target_platform="macho",
        )
        assert result is None

    def test_kernel32_allowed_on_pe(self, sig_db: SignatureDB) -> None:
        """CreateFileA PE target'ta eslesmeli."""
        result = sig_db.match_function(
            func_name="CreateFileA", target_platform="pe",
        )
        assert result is not None
        assert result.library == "kernel32"

    def test_msvcrt_blocked_on_macho(self, sig_db: SignatureDB) -> None:
        """msvcrt fonksiyonlari macOS'ta eslesmemeli (Bug 7 root cause)."""
        # msvcrt lib isimli entry var mi kontrol et
        msvcrt_entries = [
            name for name, info in sig_db._symbol_db.items()
            if info.get("lib") == "msvcrt"
        ]
        if not msvcrt_entries:
            pytest.skip("No msvcrt entries in DB")
        # Herhangi bir msvcrt entry'si macOS'ta eslesmemeli
        for entry_name in msvcrt_entries[:5]:
            result = sig_db.match_function(
                func_name=entry_name, target_platform="macho",
            )
            assert result is None, f"{entry_name} macOS'ta eslesmemeli"

    # -- macOS framework ELF'te bulunamamali --

    def test_dispatch_blocked_on_elf(self, sig_db: SignatureDB) -> None:
        """libdispatch fonksiyonlari ELF target'ta eslesmemeli."""
        result = sig_db.match_function(
            func_name="_dispatch_async", target_platform="elf",
        )
        assert result is None

    def test_dispatch_allowed_on_macho(self, sig_db: SignatureDB) -> None:
        """libdispatch fonksiyonlari macOS target'ta eslesmeli."""
        result = sig_db.match_function(
            func_name="_dispatch_async", target_platform="macho",
        )
        assert result is not None
        assert result.library == "libdispatch"

    def test_objc_blocked_on_pe(self, sig_db: SignatureDB) -> None:
        """ObjC runtime fonksiyonlari PE target'ta eslesmemeli."""
        result = sig_db.match_function(
            func_name="_objc_msgSend", target_platform="pe",
        )
        assert result is None

    # -- Cross-platform her yerde eslesmeli --

    def test_openssl_on_all_platforms(self, sig_db: SignatureDB) -> None:
        """OpenSSL fonksiyonlari tum platformlarda eslesmeli."""
        # _SSL_read builtin'de var mi kontrol et
        ssl_names = [
            n for n in sig_db._symbol_db
            if "SSL" in n and sig_db._symbol_db[n].get("lib") in ("openssl", "boringssl")
        ]
        if not ssl_names:
            pytest.skip("No OpenSSL entries in DB")
        test_name = ssl_names[0]
        for platform in ("macho", "elf", "pe"):
            result = sig_db.match_function(
                func_name=test_name, target_platform=platform,
            )
            assert result is not None, f"{test_name} {platform}'da eslesmeli"

    # -- target_platform=None geriye uyumlu --

    def test_no_platform_backwards_compatible(self, sig_db: SignatureDB) -> None:
        """target_platform=None tum eslestirmeleri yapabilmeli (mevcut davranis)."""
        # Windows API, target_platform=None ise eslesmeli
        result = sig_db.match_function(func_name="CreateFileA")
        assert result is not None
        assert result.library == "kernel32"

        # macOS API, target_platform=None ise eslesmeli
        result = sig_db.match_function(func_name="_dispatch_async")
        assert result is not None

    # -- Linux syscall PE'de bulunamamali --

    def test_linux_syscall_blocked_on_pe(self, sig_db: SignatureDB) -> None:
        """epoll_create gibi Linux syscall'lari PE'de eslesmemeli."""
        result = sig_db.match_function(
            func_name="epoll_create", target_platform="pe",
        )
        assert result is None

    def test_linux_syscall_allowed_on_elf(self, sig_db: SignatureDB) -> None:
        """epoll_create ELF'te eslesmeli."""
        result = sig_db.match_function(
            func_name="epoll_create", target_platform="elf",
        )
        assert result is not None


# ===================================================================
# SignatureDB.match_all platform filtreleme testleri
# ===================================================================

class TestMatchAllPlatformFilter:
    """match_all'in target_platform parametresini dogru ilettigini dogrula."""

    @pytest.fixture()
    def sig_db(self) -> SignatureDB:
        return SignatureDB()

    @pytest.fixture()
    def tmp_functions_json(self, tmp_path: Path) -> Path:
        """Windows + macOS + cross-platform fonksiyonlar iceren test JSON."""
        functions = {
            "functions": [
                {"name": "CreateFileA", "address": "0x1000", "size": 100},
                {"name": "_dispatch_async", "address": "0x2000", "size": 50},
                {"name": "epoll_create", "address": "0x3000", "size": 30},
                {"name": "SSL_read", "address": "0x4000", "size": 80},
            ]
        }
        p = tmp_path / "ghidra_functions.json"
        p.write_text(json.dumps(functions))
        return p

    @pytest.fixture()
    def tmp_strings_json(self, tmp_path: Path) -> Path:
        p = tmp_path / "ghidra_strings.json"
        p.write_text("[]")
        return p

    @pytest.fixture()
    def tmp_call_graph_json(self, tmp_path: Path) -> Path:
        p = tmp_path / "ghidra_call_graph.json"
        p.write_text('{"edges": []}')
        return p

    @pytest.fixture()
    def tmp_decompiled_dir(self, tmp_path: Path) -> Path:
        d = tmp_path / "decompiled"
        d.mkdir()
        return d

    def test_macho_platform_filters_win_and_linux(
        self,
        sig_db: SignatureDB,
        tmp_functions_json: Path,
        tmp_strings_json: Path,
        tmp_call_graph_json: Path,
        tmp_decompiled_dir: Path,
    ) -> None:
        """macOS target ile match_all: kernel32, epoll filtrelenmeli."""
        matches = sig_db.match_all(
            tmp_functions_json, tmp_strings_json,
            tmp_call_graph_json, tmp_decompiled_dir,
            target_platform="macho",
        )
        matched_names = {m.original_name for m in matches}

        # macOS lib'leri eslesmeli
        assert "_dispatch_async" in matched_names

        # Windows ve Linux eslesmemeli
        assert "CreateFileA" not in matched_names
        assert "epoll_create" not in matched_names

    def test_pe_platform_filters_macos_and_linux(
        self,
        sig_db: SignatureDB,
        tmp_functions_json: Path,
        tmp_strings_json: Path,
        tmp_call_graph_json: Path,
        tmp_decompiled_dir: Path,
    ) -> None:
        """PE target ile match_all: dispatch, epoll filtrelenmeli."""
        matches = sig_db.match_all(
            tmp_functions_json, tmp_strings_json,
            tmp_call_graph_json, tmp_decompiled_dir,
            target_platform="pe",
        )
        matched_names = {m.original_name for m in matches}

        # Windows lib'leri eslesmeli
        assert "CreateFileA" in matched_names

        # macOS ve Linux eslesmemeli
        assert "_dispatch_async" not in matched_names
        assert "epoll_create" not in matched_names

    def test_none_platform_no_filtering(
        self,
        sig_db: SignatureDB,
        tmp_functions_json: Path,
        tmp_strings_json: Path,
        tmp_call_graph_json: Path,
        tmp_decompiled_dir: Path,
    ) -> None:
        """target_platform=None (default) filtre yok -> hepsi eslesmeli."""
        matches = sig_db.match_all(
            tmp_functions_json, tmp_strings_json,
            tmp_call_graph_json, tmp_decompiled_dir,
        )
        matched_names = {m.original_name for m in matches}

        assert "CreateFileA" in matched_names
        assert "_dispatch_async" in matched_names
        assert "epoll_create" in matched_names


# ===================================================================
# External JSON platform tahmini testleri
# ===================================================================

class TestExternalSignaturePlatformInference:
    """load_external_signatures dosya adi bazli platform tahmini."""

    @pytest.fixture()
    def sig_db(self) -> SignatureDB:
        return SignatureDB()

    def test_windows_named_file_sets_platform(
        self, sig_db: SignatureDB, tmp_path: Path,
    ) -> None:
        """windows_*.json dosyasindan yuklenen signature'lar PE-only olmali."""
        sig_data = {
            "signatures": {
                "MyWinFunc": {"lib": "custom_win", "purpose": "test", "category": "misc"},
            }
        }
        win_file = tmp_path / "windows_custom.json"
        win_file.write_text(json.dumps(sig_data))

        sig_db.load_external_signatures(win_file)

        # Entry'nin _platforms key'i olmali
        entry = sig_db._symbol_db.get("MyWinFunc")
        assert entry is not None
        assert entry.get("_platforms") == ["pe"]

        # macOS'ta eslesmemeli
        result = sig_db.match_function(
            func_name="MyWinFunc", target_platform="macho",
        )
        assert result is None

        # PE'de eslesmeli
        result = sig_db.match_function(
            func_name="MyWinFunc", target_platform="pe",
        )
        assert result is not None

    def test_linux_named_file_sets_platform(
        self, sig_db: SignatureDB, tmp_path: Path,
    ) -> None:
        """linux_*.json dosyasindan yuklenen signature'lar ELF-only olmali."""
        sig_data = {
            "MyLinuxFunc": {"lib": "custom_linux", "purpose": "test", "category": "misc"},
        }
        linux_file = tmp_path / "linux_syscalls.json"
        linux_file.write_text(json.dumps(sig_data))

        sig_db.load_external_signatures(linux_file)

        entry = sig_db._symbol_db.get("MyLinuxFunc")
        assert entry is not None
        assert entry.get("_platforms") == ["elf"]

    def test_macos_named_file_sets_platform(
        self, sig_db: SignatureDB, tmp_path: Path,
    ) -> None:
        """macos_*.json dosyasindan yuklenen signature'lar Mach-O-only olmali."""
        sig_data = {
            "signatures": [
                {"name": "MyMacFunc", "library": "custom_mac", "category": "misc"},
            ]
        }
        mac_file = tmp_path / "macos_frameworks.json"
        mac_file.write_text(json.dumps(sig_data))

        sig_db.load_external_signatures(mac_file)

        entry = sig_db._symbol_db.get("MyMacFunc")
        assert entry is not None
        assert entry.get("_platforms") == ["macho"]

    def test_generic_file_no_platform_restriction(
        self, sig_db: SignatureDB, tmp_path: Path,
    ) -> None:
        """Platform prefix'i olmayan dosya -> platform kisitlamasi yok."""
        sig_data = {
            "signatures": {
                "MyGenericFunc": {"lib": "custom", "purpose": "test", "category": "misc"},
            }
        }
        generic_file = tmp_path / "custom_signatures.json"
        generic_file.write_text(json.dumps(sig_data))

        sig_db.load_external_signatures(generic_file)

        entry = sig_db._symbol_db.get("MyGenericFunc")
        assert entry is not None
        assert "_platforms" not in entry

    def test_explicit_platforms_in_json_overrides_filename(
        self, sig_db: SignatureDB, tmp_path: Path,
    ) -> None:
        """JSON icindeki explicit 'platforms' key dosya adindan once gelir."""
        sig_data = {
            "signatures": [
                {
                    "name": "CrossPlatFunc",
                    "library": "mylib",
                    "category": "misc",
                    "platforms": ["macho", "elf", "pe"],
                },
            ]
        }
        # Dosya adi "windows_" ile basliyor ama entry'de explicit platforms var
        win_file = tmp_path / "windows_but_cross.json"
        win_file.write_text(json.dumps(sig_data))

        sig_db.load_external_signatures(win_file)

        entry = sig_db._symbol_db.get("CrossPlatFunc")
        assert entry is not None
        assert entry.get("_platforms") == ["macho", "elf", "pe"]

        # macOS'ta da eslesmeli (explicit platforms sayesinde)
        result = sig_db.match_function(
            func_name="CrossPlatFunc", target_platform="macho",
        )
        assert result is not None


# ===================================================================
# Platform lib set completeness testleri
# ===================================================================

class TestPlatformLibSets:
    """Platform-specific lib setlerinin dogru tanimlandigini kontrol et."""

    def test_pe_only_libs_contains_windows_essentials(self) -> None:
        essentials = {"kernel32", "user32", "advapi32", "ntdll", "ws2_32", "msvcrt"}
        assert essentials.issubset(_PE_ONLY_LIBS)

    def test_macho_only_libs_contains_apple_essentials(self) -> None:
        essentials = {
            "CoreFoundation", "Foundation", "AppKit", "Metal",
            "libdispatch", "libobjc", "swift_runtime",
        }
        assert essentials.issubset(_MACHO_ONLY_LIBS)

    def test_no_overlap_between_platform_sets(self) -> None:
        """Platform-specific setler arasinda cakisma olmamali."""
        assert _PE_ONLY_LIBS.isdisjoint(_MACHO_ONLY_LIBS)
        assert _PE_ONLY_LIBS.isdisjoint(_ELF_ONLY_LIBS)
        assert _MACHO_ONLY_LIBS.isdisjoint(_ELF_ONLY_LIBS)

    def test_cross_platform_libs_not_in_any_set(self) -> None:
        """Cross-platform lib'ler hicbir platform-specific set'te olmamali."""
        cross_platform = {"openssl", "zlib", "sqlite3", "libcurl", "libuv", "libc"}
        for lib in cross_platform:
            assert lib not in _PE_ONLY_LIBS, f"{lib} should not be PE-only"
            assert lib not in _MACHO_ONLY_LIBS, f"{lib} should not be macOS-only"
            assert lib not in _ELF_ONLY_LIBS, f"{lib} should not be ELF-only"
