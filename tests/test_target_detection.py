"""
TargetDetector testleri — dosya turu tanima, hash dogrulama.

Core modulleri henuz yazilmadiysa testler SKIP edilir.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

import pytest

# Core moduller henuz mevcut olmayabilir — import hatasi durumunda tum modul skip
try:
    from karadul.core.target import Language, TargetDetector, TargetInfo, TargetType

    CORE_AVAILABLE = True
except ImportError:
    CORE_AVAILABLE = False

pytestmark = pytest.mark.skipif(
    not CORE_AVAILABLE,
    reason="karadul.core.target henuz mevcut degil",
)


# ─────────────────────────────────────────────────────────
# JS Bundle tespiti
# ─────────────────────────────────────────────────────────
class TestJSDetection:
    """JavaScript bundle / minified dosya tespiti."""

    def test_detect_js_bundle(self, sample_js_file: Path) -> None:
        """Bir .js dosyasi JS_BUNDLE olarak tanimlanmali."""
        detector = TargetDetector()
        info = detector.detect(sample_js_file)

        assert info.target_type == TargetType.JS_BUNDLE
        assert info.language == Language.JAVASCRIPT

    def test_detect_minified_js(self, tmp_path: Path) -> None:
        """__webpack_require__ iceren dosya JS_BUNDLE olmali."""
        js_file = tmp_path / "app.js"
        js_file.write_text(
            'var __webpack_require__ = function(id) { return modules[id]; };\n'
            '__webpack_require__(0);',
            encoding="utf-8",
        )

        detector = TargetDetector()
        info = detector.detect(js_file)

        assert info.target_type == TargetType.JS_BUNDLE

    def test_detect_from_fixture(self, fixtures_dir: Path) -> None:
        """tests/fixtures/sample_minified.js dosyasindan tespit."""
        fixture = fixtures_dir / "sample_minified.js"
        if not fixture.exists():
            pytest.skip("Fixture dosyasi mevcut degil")

        detector = TargetDetector()
        info = detector.detect(fixture)

        assert info.target_type == TargetType.JS_BUNDLE
        assert info.language == Language.JAVASCRIPT


# ─────────────────────────────────────────────────────────
# Mach-O binary tespiti
# ─────────────────────────────────────────────────────────
class TestMachODetection:
    """Mach-O binary tespiti."""

    def test_detect_macho_binary(self, sample_macho_file: Path) -> None:
        """Mach-O magic bytes iceren dosya MACHO_BINARY olmali."""
        detector = TargetDetector()
        info = detector.detect(sample_macho_file)

        assert info.target_type == TargetType.MACHO_BINARY


# ─────────────────────────────────────────────────────────
# App bundle tespiti
# ─────────────────────────────────────────────────────────
class TestAppBundle:
    """macOS .app bundle tespiti."""

    def test_detect_app_bundle(self, tmp_path: Path) -> None:
        """.app dizin yapisi olusturup test et.

        v1.2.x: TargetDetector tum .app bundle'lari APP_BUNDLE olarak
        siniflandirir. Icerik bilgisi metadata.components icerisindedir.
        """
        app_dir = tmp_path / "Test.app"
        contents = app_dir / "Contents"
        macos = contents / "MacOS"
        macos.mkdir(parents=True)

        # Minimal Info.plist
        plist = contents / "Info.plist"
        plist.write_text(
            '<?xml version="1.0"?>\n<plist version="1.0"><dict>'
            "<key>CFBundleName</key><string>Test</string>"
            "</dict></plist>",
            encoding="utf-8",
        )

        # Dummy executable (Mach-O 64-bit magic)
        exe = macos / "Test"
        exe.write_bytes(b"\xcf\xfa\xed\xfe" + b"\x00" * 60)

        detector = TargetDetector()
        info = detector.detect(app_dir)

        # v1.2.x: APP_BUNDLE olarak siniflandirilir, metadata.bundle=True
        assert info.target_type == TargetType.APP_BUNDLE
        assert info.metadata.get("bundle") is True
        assert info.metadata.get("electron") is False

    def test_detect_electron_app_bundle(self, tmp_path: Path) -> None:
        """Electron .app bundle'i ELECTRON_APP olarak tanimlanmali."""
        app_dir = tmp_path / "ElectronApp.app"
        contents = app_dir / "Contents"
        macos = contents / "MacOS"
        resources = contents / "Resources"
        macos.mkdir(parents=True)
        resources.mkdir(parents=True)

        # app.asar -> Electron belirteci
        asar = resources / "app.asar"
        asar.write_bytes(b"\x04\x00\x00\x00" + b"\x00" * 60)

        # Dummy executable
        exe = macos / "ElectronApp"
        exe.write_bytes(b"\xcf\xfa\xed\xfe" + b"\x00" * 60)

        detector = TargetDetector()
        info = detector.detect(app_dir)

        # v1.2.x: APP_BUNDLE olarak siniflandirilir, electron=True metadata'da
        assert info.target_type == TargetType.APP_BUNDLE
        assert info.metadata.get("electron") is True


# ─────────────────────────────────────────────────────────
# Hata durumlari
# ─────────────────────────────────────────────────────────
class TestEdgeCases:
    """Kenar durumlar ve hata yonetimi."""

    def test_detect_nonexistent(self) -> None:
        """Var olmayan dosya icin hata firlatmali."""
        fake_path = Path("/tmp/this_file_does_not_exist_karadul_test_12345")
        detector = TargetDetector()

        with pytest.raises((FileNotFoundError, ValueError, OSError)):
            detector.detect(fake_path)


# ─────────────────────────────────────────────────────────
# Gercek binary testleri (varsa calistir)
# ─────────────────────────────────────────────────────────
CLAUDE_CODE_PATH = Path("/opt/homebrew/bin/claude")
CODEX_PATH = Path("/opt/homebrew/bin/codex")


class TestRealBinaries:
    """Sistemdeki gercek binary'lerle entegrasyon testleri."""

    @pytest.mark.skipif(
        not CLAUDE_CODE_PATH.exists(),
        reason=f"Claude Code CLI bulunamadi: {CLAUDE_CODE_PATH}",
    )
    def test_detect_claude_code(self) -> None:
        """Gercek Claude Code CLI dosyasini tani."""
        detector = TargetDetector()
        info = detector.detect(CLAUDE_CODE_PATH)

        assert info is not None
        # Symlink resolve olabilir, bu yuzden resolve ile karsilastir
        assert info.path == CLAUDE_CODE_PATH.resolve()
        assert info.file_size > 0

    @pytest.mark.skipif(
        not CODEX_PATH.exists(),
        reason=f"Codex binary bulunamadi: {CODEX_PATH}",
    )
    def test_detect_codex_binary(self) -> None:
        """Gercek Codex binary'sini tani."""
        detector = TargetDetector()
        info = detector.detect(CODEX_PATH)

        assert info is not None
        # Symlink resolve olabilir, bu yuzden resolve ile karsilastir
        assert info.path == CODEX_PATH.resolve()
        assert info.file_size > 0


# ─────────────────────────────────────────────────────────
# SHA-256 hash dogrulama
# ─────────────────────────────────────────────────────────
class TestHash:
    """Dosya hash hesaplama dogrulamasi."""

    def test_file_hash_sha256(self, sample_js_file: Path) -> None:
        """Hash'in gecerli SHA-256 formatinda oldugunu dogrula."""
        detector = TargetDetector()
        info = detector.detect(sample_js_file)

        assert info.file_hash is not None
        assert len(info.file_hash) > 0
        # SHA-256: 64 hex karakter
        assert re.fullmatch(r"[0-9a-f]{64}", info.file_hash), (
            f"Gecersiz SHA-256 formati: {info.file_hash}"
        )

        # Dosya iceriginden bagimsiz dogrulama
        expected = hashlib.sha256(sample_js_file.read_bytes()).hexdigest()
        assert info.file_hash == expected
