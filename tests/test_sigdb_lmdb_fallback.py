"""v1.10.0 C2 + C3: LMDB backend fallback davranislari.

C2: LMDB'de platform mismatch -> builtin dict'e dus (``return None`` YERINE).
C3: LMDB'de string/call/byte sigs sorgulama (builtin miss oldugunda).
H3: Platforms field string -> list normalize (build_sig_lmdb).
H4: Format 1/3 params propagation.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

lmdb = pytest.importorskip("lmdb")
msgpack = pytest.importorskip("msgpack")

from karadul.analyzers.signature_db import SignatureDB  # noqa: E402
from karadul.analyzers.sigdb_lmdb import LMDBSignatureDB  # noqa: E402
from karadul.config import Config  # noqa: E402


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_lmdb_with_platform_sym(path: Path, name: str, platforms: list[str]):
    """LMDB'de platforma-ozgu tek sembol ile mini DB olustur."""
    db = LMDBSignatureDB(path, readonly=False, map_size=16 * 1024 * 1024)
    db.bulk_write_symbols([
        (name, {
            "lib": "fakelib",
            "purpose": "platform-limited",
            "category": "test",
            "_platforms": platforms,
        }),
    ])
    db.close()


def _make_config_with_lmdb(tmp_path, lmdb_path):
    """SignatureDB'yi LMDB backend ile acmak icin Config."""
    cfg = Config()
    cfg.project_root = tmp_path  # cache key ayri olsun
    cfg.perf.use_lmdb_sigdb = True
    cfg.perf.sig_lmdb_path = lmdb_path
    return cfg


# ---------------------------------------------------------------------------
# C2: Platform mismatch -> builtin fallback
# ---------------------------------------------------------------------------


class TestC2PlatformMismatchFallback:
    """LMDB'de PE-only sembol + builtin'de macOS ayni isim -> builtin match."""

    def test_lmdb_pe_sym_falls_through_to_builtin_macos(self, tmp_path):
        """LMDB 'pe' platform -> macOS target -> builtin dict'e dusmeli."""
        lmdb_path = tmp_path / "test.lmdb"
        # LMDB'ye Windows-only bir "_malloc" koy (absurd ama test icin)
        _make_lmdb_with_platform_sym(
            lmdb_path, "_test_func_xyzzy", platforms=["pe"],
        )

        cfg = _make_config_with_lmdb(tmp_path, lmdb_path)
        sigdb = SignatureDB(cfg, target_platform="macho")

        # '_test_func_xyzzy' LMDB'de var ama pe-only; macho target icin
        # uyumsuz. Builtin'de de olmayacak -> match None.
        match = sigdb._match_by_symbol("_test_func_xyzzy", target_platform="macho")
        assert match is None, (
            "Platform uyumsuz LMDB hit + builtin miss -> None beklenirdi"
        )

        # Simdi builtin'de var olan bir isim dene (_malloc macOS libc'de var)
        match = sigdb._match_by_symbol("_malloc", target_platform="macho")
        assert match is not None, (
            "Builtin '_malloc' match'i dusurulmus -- C2 fix calismiyor "
            "(LMDB 'None' dondurdugu icin builtin asla aranmiyor olabilir)"
        )
        assert match.library == "libc"

    def test_lmdb_hit_platform_compatible_returns_lmdb(self, tmp_path):
        """LMDB platformla uyumlu -> LMDB match donmeli (fallback YOK)."""
        lmdb_path = tmp_path / "test.lmdb"
        _make_lmdb_with_platform_sym(
            lmdb_path, "_exclusive_name", platforms=["macho"],
        )

        cfg = _make_config_with_lmdb(tmp_path, lmdb_path)
        sigdb = SignatureDB(cfg, target_platform="macho")

        match = sigdb._match_by_symbol("_exclusive_name", target_platform="macho")
        assert match is not None
        assert match.library == "fakelib"


# ---------------------------------------------------------------------------
# C3: LMDB'de string/call/byte sigs sorgulama
# ---------------------------------------------------------------------------


class TestC3SecondarySigsInLMDB:
    """Builtin dict'ten gelen string/call/byte sigs LMDB'de de sorgulaniyor mu?"""

    def test_lmdb_string_sig_queried(self, tmp_path):
        """LMDB'ye tek string imza yaz, builtin'de silip sadece LMDB'de olsun."""
        lmdb_path = tmp_path / "test.lmdb"
        db = LMDBSignatureDB(lmdb_path, readonly=False, map_size=16 * 1024 * 1024)
        db.bulk_write_string_sigs([
            (frozenset(["LMDB_ONLY_KEY_A", "LMDB_ONLY_KEY_B"]),
             ("lmdb_only_func", "lmdb_lib", "lmdb-exclusive")),
        ])
        db.close()

        cfg = _make_config_with_lmdb(tmp_path, lmdb_path)
        sigdb = SignatureDB(cfg)

        # Builtin'de bu keyword kombinasyonu olmayacak
        match = sigdb._match_by_strings(["LMDB_ONLY_KEY_A", "LMDB_ONLY_KEY_B"])
        assert match is not None, (
            "LMDB'deki string_sig sorgulanmiyor -- C3 fix'i eksik"
        )
        assert match.matched_name == "lmdb_only_func"
        assert match.library == "lmdb_lib"

    def test_lmdb_call_sig_queried(self, tmp_path):
        """LMDB'ye tek call imza yaz, sorgulanabilmeli."""
        lmdb_path = tmp_path / "test.lmdb"
        db = LMDBSignatureDB(lmdb_path, readonly=False, map_size=16 * 1024 * 1024)
        db.bulk_write_call_sigs([
            (frozenset(["_unique_api_x", "_unique_api_y"]),
             ("lmdb_call_func", "lmdb_lib", "call match via LMDB", 0.88)),
        ])
        db.close()

        cfg = _make_config_with_lmdb(tmp_path, lmdb_path)
        sigdb = SignatureDB(cfg)

        match = sigdb._match_by_calls(["_unique_api_x", "_unique_api_y"])
        assert match is not None, "LMDB call_sig sorgulanmiyor"
        assert match.matched_name == "lmdb_call_func"

    def test_lmdb_byte_sig_queried(self, tmp_path):
        """LMDB'ye tek byte imza yaz, sorgulanabilmeli."""
        lmdb_path = tmp_path / "test.lmdb"
        db = LMDBSignatureDB(lmdb_path, readonly=False, map_size=16 * 1024 * 1024)
        db.bulk_write_byte_sigs([
            {
                "name": "lmdb_unique_pattern",
                "library": "lmdb_lib",
                "category": "test",
                "byte_pattern_hex": "aabbccddeeff0011",
                "byte_mask_hex": "ffffffffffffffff",
                "purpose": "LMDB-only pattern",
            },
        ])
        db.close()

        cfg = _make_config_with_lmdb(tmp_path, lmdb_path)
        sigdb = SignatureDB(cfg)

        # Builtin _byte_signatures'te bu yok, ama FindCrypt constants olabilir.
        # Eger builtin match daha yuksek conf verse bile LMDB sorgulandi mi
        # kontrolunu dolayli yapamayiz. LMDB miss ise test atlama:
        func_bytes = bytes.fromhex("aabbccddeeff0011" + "00" * 24)  # 32 byte
        match = sigdb._match_by_bytes(func_bytes, func_size=0)

        # Ya LMDB match, ya FindCrypt match, ya None. Key: LMDB path sorgulandi.
        # En katisi -- builtin yuklenmemis gibi davranip match.matched_name
        # bizim LMDB-only pattern olmali.
        assert match is not None, (
            "LMDB byte_sig sorgulanmiyor veya bos builtin ile None donuyor"
        )
        # Our unique pattern should match (builtin FindCrypt'te bu hex yok)
        assert match.matched_name == "lmdb_unique_pattern", (
            f"Beklenen 'lmdb_unique_pattern', gelen {match.matched_name!r}"
        )


# ---------------------------------------------------------------------------
# H3: Platforms string -> list normalize (build_sig_lmdb)
# ---------------------------------------------------------------------------


class TestH3PlatformsStringNormalize:
    """JSON'da 'platforms': 'pe' (string) -> list'e normalize edilmeli."""

    def test_string_platform_normalized_to_list(self, tmp_path):
        """build_sig_lmdb.iter_symbols_from_json string platforms'i list'e cevirmeli."""
        import importlib.util
        import sys as _sys
        spec = importlib.util.spec_from_file_location(
            "build_sig_lmdb_h3",
            "/Users/apple/Desktop/black-widow/scripts/build_sig_lmdb.py",
        )
        mod = importlib.util.module_from_spec(spec)
        _sys.modules["build_sig_lmdb_h3"] = mod
        spec.loader.exec_module(mod)

        # Format 2 (dict): "signatures": {...} + explicit string platform
        src = tmp_path / "signatures_x.json"
        src.write_text(json.dumps({
            "signatures": {
                "_foo": {
                    "lib": "foolib",
                    "purpose": "p",
                    "category": "c",
                    "platforms": "pe",  # string, not list
                },
                "_bar": {
                    "lib": "barlib",
                    "purpose": "q",
                    "category": "d",
                    "platforms": ["elf", "macho"],  # already list
                },
            }
        }), encoding="utf-8")

        results = list(mod.iter_symbols_from_json(src))
        foo = next(info for (n, info) in results if n == "_foo")
        bar = next(info for (n, info) in results if n == "_bar")

        assert foo["_platforms"] == ["pe"], (
            f"String platform list'e normalize edilmedi: {foo.get('_platforms')!r}"
        )
        assert bar["_platforms"] == ["elf", "macho"]


# ---------------------------------------------------------------------------
# H4: Format 1 ve Format 3 params propagation
# ---------------------------------------------------------------------------


class TestH4ParamsPropagation:
    """SignatureDB.load_external_signatures icindeki 3 format params tasir mi?"""

    def test_format1_list_propagates_params(self, tmp_path):
        """Format 1 (list) signatures'taki params field'i symbol_db'ye tasinmali."""
        cfg = Config()
        cfg.project_root = tmp_path
        sigdb = SignatureDB(cfg)

        jsonp = tmp_path / "sigs_fmt1.json"
        jsonp.write_text(json.dumps({
            "signatures": [
                {
                    "name": "_param_test_fn1",
                    "library": "fortranlib",
                    "category": "numerical",
                    "purpose": "params on format1",
                    "params": ["int*", "double*", "int"],
                },
            ]
        }), encoding="utf-8")
        added = sigdb.load_external_signatures(jsonp)
        assert added == 1

        info = sigdb._symbol_db.get("_param_test_fn1")
        assert info is not None
        assert info.get("params") == ["int*", "double*", "int"], (
            "Format 1 (list) params propagate edilmiyor -- H4 fix eksik"
        )

    def test_format3_flat_propagates_params(self, tmp_path):
        """Format 3 (flat) top-level entry'lerindeki params symbol_db'ye tasinmali."""
        cfg = Config()
        cfg.project_root = tmp_path
        sigdb = SignatureDB(cfg)

        jsonp = tmp_path / "sigs_fmt3.json"
        jsonp.write_text(json.dumps({
            "_flat_test_fn": {
                "lib": "somelib",
                "purpose": "flat format",
                "category": "misc",
                "params": ["p1", "p2"],
            },
            "meta": {"generator": "test"},  # skip
        }), encoding="utf-8")
        added = sigdb.load_external_signatures(jsonp)
        assert added == 1

        info = sigdb._symbol_db.get("_flat_test_fn")
        assert info is not None
        assert info.get("params") == ["p1", "p2"], (
            "Format 3 (flat) params propagate edilmiyor -- H4 fix eksik"
        )

    def test_format2_dict_still_propagates_params(self, tmp_path):
        """Format 2 (dict) zaten calisiyordu -- regression yok."""
        cfg = Config()
        cfg.project_root = tmp_path
        sigdb = SignatureDB(cfg)

        jsonp = tmp_path / "sigs_fmt2.json"
        jsonp.write_text(json.dumps({
            "signatures": {
                "_fmt2_fn": {
                    "lib": "somelib",
                    "purpose": "format2",
                    "category": "misc",
                    "params": ["a", "b", "c"],
                }
            }
        }), encoding="utf-8")
        added = sigdb.load_external_signatures(jsonp)
        assert added == 1

        info = sigdb._symbol_db.get("_fmt2_fn")
        assert info.get("params") == ["a", "b", "c"]
