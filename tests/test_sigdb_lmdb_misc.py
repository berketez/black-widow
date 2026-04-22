"""v1.10.0 M7 + H5: Diger kucuk fix'ler icin regression testleri.

M7: BytePatternMatcher.max_selective artik pattern uzunluguna orantili
    (``max(2, min_pattern_length // 8)``).
H5: build_sig_lmdb kucuk (bos) JSON'lari skip etmeli.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest


from karadul.analyzers.byte_pattern_matcher import BytePatternMatcher


# ---------------------------------------------------------------------------
# M7: max_selective formula
# ---------------------------------------------------------------------------


class TestM7MaxSelectiveFormula:
    """``max_selective = max(2, min_pattern_length // 8)`` kontrolu."""

    def test_default_formula_min_length_16(self):
        """min_pattern_length=16 -> max_selective = max(2, 2) = 2."""
        m = BytePatternMatcher(min_pattern_length=16)
        assert m._max_selective == 2

    def test_default_formula_min_length_64(self):
        """min_pattern_length=64 -> max_selective = max(2, 8) = 8."""
        m = BytePatternMatcher(min_pattern_length=64)
        assert m._max_selective == 8

    def test_default_formula_min_length_128(self):
        """min_pattern_length=128 -> max_selective = max(2, 16) = 16."""
        m = BytePatternMatcher(min_pattern_length=128)
        assert m._max_selective == 16

    def test_explicit_override_retained(self):
        """Kullanici max_selective verdiginde formula override edilir."""
        m = BytePatternMatcher(min_pattern_length=16, max_selective=10)
        assert m._max_selective == 10

    def test_formula_minimum_floor_two(self):
        """min_pattern_length cok kucuk (8) -> floor 2."""
        m = BytePatternMatcher(min_pattern_length=8)
        assert m._max_selective == 2  # max(2, 8//8=1) = 2


# ---------------------------------------------------------------------------
# H5: Bos JSON skip
# ---------------------------------------------------------------------------


class TestH5SkipEmptyJson:
    """build_sig_lmdb <100 byte (bos) JSON'lari skip etmeli."""

    def _load_mod(self):
        import importlib.util
        import sys as _sys
        spec = importlib.util.spec_from_file_location(
            "build_sig_lmdb_h5",
            "/Users/apple/Desktop/black-widow/scripts/build_sig_lmdb.py",
        )
        mod = importlib.util.module_from_spec(spec)
        _sys.modules["build_sig_lmdb_h5"] = mod
        spec.loader.exec_module(mod)
        return mod

    def test_tiny_json_skipped_by_discover(self, tmp_path):
        """Boyut <100 byte -> discover_sources donuste olmamali."""
        mod = self._load_mod()
        proj = tmp_path / "proj"
        proj.mkdir()

        # 60 byte bos plaka
        tiny = proj / "signatures_tiny.json"
        tiny.write_text('{"signatures":[],"total":0}', encoding="utf-8")
        assert tiny.stat().st_size < 100

        # Normal boyutlu gercek kaynak
        normal = proj / "signatures_real.json"
        normal.write_text(json.dumps({
            "signatures": {
                "_foo": {"lib": "x", "purpose": "", "category": ""},
                "_bar": {"lib": "y", "purpose": "", "category": ""},
            }
        }), encoding="utf-8")
        assert normal.stat().st_size >= 100

        sources = mod.discover_sources(proj)
        names = [p.name for p in sources]
        assert "signatures_real.json" in names
        assert "signatures_tiny.json" not in names, (
            f"Bos JSON atlanamadi: {names}"
        )

    def test_tiny_json_excluded_from_hash(self, tmp_path):
        """compute_source_hash kucuk dosyayi dikkate almamali.

        Eklenip silinmesi hash'i degistirmemeli (idempotency kararli olmali).
        """
        mod = self._load_mod()
        proj = tmp_path / "proj"
        proj.mkdir()

        normal = proj / "signatures_real.json"
        normal.write_text(json.dumps({
            "signatures": {"_foo": {"lib": "x", "purpose": "", "category": ""}}
        }) + " " * 150, encoding="utf-8")

        # Ilk hash: sadece real var
        srcs1 = mod.discover_sources(proj)
        h1 = mod.compute_source_hash(srcs1)

        # Simdi kucuk bir plaka ekle
        tiny = proj / "signatures_plate.json"
        tiny.write_text('{"signatures":[]}', encoding="utf-8")

        srcs2 = mod.discover_sources(proj)
        h2 = mod.compute_source_hash(srcs2)

        assert h1 == h2, (
            "Kucuk dosya ekleme hash'i degistirdi -- H5 skip calismiyor."
        )
