"""
Pytest fixture'lari — Black Widow (Karadul) test altyapisi.
"""

from __future__ import annotations

from pathlib import Path
from typing import Generator

import pytest

from karadul.config import Config


# ---------------------------------------------------------------------------
# Session-scoped fixtures -- tum test suite boyunca 1 kez calisir
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session", autouse=True)
def _warm_signature_db_cache() -> None:
    """SignatureDB class-level cache'ini test suite basinda doldur.

    SignatureDB init ~1.3s suruyor (1.5M+ signature, 240MB JSON parse).
    Bu fixture session basinda 1 kez calisarak, sonraki tum SignatureDB()
    cagrilarinin ~0.01s'de tamamlanmasini saglar.
    """
    try:
        from karadul.analyzers.signature_db import SignatureDB
        _db = SignatureDB(Config())
        del _db
    except Exception:
        pass  # Import/init hatasi test suite'i durdurmamali


# ---------------------------------------------------------------------------
# Step registry test izolasyonu
# ---------------------------------------------------------------------------
#
# Sorun: `karadul.pipeline.steps` paketi ilk import edildiginde, her step
# modulunun `@register_step` decorator'u global `_REGISTRY` dict'ine
# yazar. Python sys.modules cache'ledigi icin paket ikinci kez import
# edilince decorator'lar tekrar calismaz. Bazi test'ler
# `_clear_registry_for_tests()` cagirip registry'yi bosaltiyor ama
# save/restore yapmiyor — bu durumda sonraki test'ler bos registry ile
# karsilasiyor ve `get_step(...)` KeyError firlatiyor (25 test fail).
#
# Cozum: session basinda paketi bir kez import edip baseline snapshot al;
# her test'ten sonra registry'yi baseline'a geri yukle (autouse=True).

@pytest.fixture(scope="session")
def _step_registry_baseline() -> dict:
    """Session basinda tam yuklu registry'nin snapshot'i.

    karadul.pipeline.steps paketi import edilir (decorator yan etkisi
    registry'yi doldurur), ardindan mevcut `_REGISTRY` dict'inin kopyasi
    dondurulur. Sonraki test'lerin restore'u bu snapshot'a gore yapilir.
    """
    try:
        import karadul.pipeline  # noqa: F401 — decorator yan etkisi icin
        from karadul.pipeline.registry import _REGISTRY
        return dict(_REGISTRY)
    except Exception:
        # Import basarisiz olursa bos baseline dondur; etkilenen test'ler
        # zaten kendi hatalarini verir.
        return {}


@pytest.fixture(autouse=True)
def _restore_step_registry(_step_registry_baseline: dict) -> Generator[None, None, None]:
    """Her test sonrasi `_REGISTRY`'yi session baseline'ina geri yukle.

    Test icinde `_clear_registry_for_tests()` veya baska mutasyon
    yapilmis olsa bile, sonraki test'e gecerken registry tam yuklu halde
    olur. Test ICINDE mutasyon serbest — yalnizca test sinirinda resetlenir.
    """
    yield
    try:
        from karadul.pipeline.registry import _REGISTRY
        _REGISTRY.clear()
        _REGISTRY.update(_step_registry_baseline)
    except Exception:
        pass  # teardown hatasi test sonucunu gizlememeli


@pytest.fixture
def tmp_workspace(tmp_path: Path) -> Path:
    """Gecici workspace dizini olustur ve dondur."""
    ws = tmp_path / "workspace"
    ws.mkdir()
    (ws / "logs").mkdir()
    (ws / "output").mkdir()
    (ws / "intermediate").mkdir()
    return ws


@pytest.fixture
def sample_js_content() -> str:
    """Kucuk minified webpack-formati JS string."""
    return (
        '(function(e){var t={};function n(r){if(t[r])return t[r].exports;'
        'var o=t[r]={i:r,l:!1,exports:{}};return e[r].call(o.exports,o,o.exports,n),'
        'o.l=!0,o.exports}n.m=e,n.c=t,n.d=function(e,t,r){'
        'n.o(e,t)||Object.defineProperty(e,t,{enumerable:!0,get:r})},'
        'n.r=function(e){"undefined"!=typeof Symbol&&Symbol.toStringTag&&'
        'Object.defineProperty(e,Symbol.toStringTag,{value:"Module"}),'
        'Object.defineProperty(e,"__esModule",{value:!0})},n(0)})'
        '({0:function(e,t,n){"use strict";const r=n(1);console.log(r.hello())},'
        '1:function(e,t){"use strict";t.hello=function(){return"Hello from webpack bundle"}}});'
    )


@pytest.fixture
def sample_macho_header() -> bytes:
    """Mach-O 64-bit magic bytes + minimal header padding."""
    # MH_MAGIC_64 = 0xFEEDFACF (little-endian: CF FA ED FE)
    magic = b"\xcf\xfa\xed\xfe"
    # CPU type: x86_64 = 0x01000007 (LE)
    cpu_type = b"\x07\x00\x00\x01"
    # CPU subtype: ALL = 0x03
    cpu_subtype = b"\x03\x00\x00\x00"
    # File type: EXECUTE = 0x02
    filetype = b"\x02\x00\x00\x00"
    # Number of load commands (dummy: 0)
    ncmds = b"\x00\x00\x00\x00"
    # Size of load commands
    sizeofcmds = b"\x00\x00\x00\x00"
    # Flags
    flags = b"\x00\x00\x00\x00"
    # Reserved (64-bit)
    reserved = b"\x00\x00\x00\x00"
    # Padding to 64 bytes
    header = magic + cpu_type + cpu_subtype + filetype + ncmds + sizeofcmds + flags + reserved
    padding = b"\x00" * (64 - len(header))
    return header + padding


@pytest.fixture
def config() -> Config:
    """Test icin varsayilan Config instance."""
    return Config()


@pytest.fixture
def sample_js_file(tmp_path: Path, sample_js_content: str) -> Path:
    """Gecici dizinde minified JS dosyasi olustur."""
    js_file = tmp_path / "bundle.min.js"
    js_file.write_text(sample_js_content, encoding="utf-8")
    return js_file


@pytest.fixture
def sample_macho_file(tmp_path: Path, sample_macho_header: bytes) -> Path:
    """Gecici dizinde Mach-O binary olustur."""
    bin_file = tmp_path / "test_binary"
    bin_file.write_bytes(sample_macho_header)
    return bin_file


@pytest.fixture
def fixtures_dir() -> Path:
    """tests/fixtures/ dizinini dondur."""
    return Path(__file__).parent / "fixtures"
