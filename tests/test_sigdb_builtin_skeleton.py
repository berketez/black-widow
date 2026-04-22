"""sig_db Faz 1 iskelet testleri.

v1.12.0 ``karadul/analyzers/sigdb_builtin/`` dizini 17 kategori placeholder
modulu + dispatcher icerir. Bu testler:

1. 17 kategori modulu import edilebiliyor mu?
2. Her modul ``SIGNATURES`` dict expose ediyor mu (Faz 1: bos)?
3. Dispatcher ``get_category("crypto")`` bos dict donduruyor mu?
4. Dispatcher tanimsiz kategoride ValueError atiyor mu?
5. LMDB auto-detect: default True, LMDB dosyasi yokken fallback calisiyor
   mu?
6. ``list_categories()`` 17 eleman donduruyor mu?
"""
from __future__ import annotations

import importlib

import pytest


_EXPECTED_CATEGORIES = [
    "calls",
    "compression",
    "crypto",
    "database",
    "event_utils",
    "game_ml",
    "graphics_media",
    "languages",
    "linux_system",
    "logging",
    "macos_apple",
    "network",
    "posix_system",
    "runtimes",
    "serialization",
    "strings_module",
    "windows_api",
]


class TestSigdbBuiltinImports:
    """Her kategori modulu ayri ayri import edilebilir."""

    @pytest.mark.parametrize("name", _EXPECTED_CATEGORIES)
    def test_module_importable(self, name: str) -> None:
        mod = importlib.import_module(f"karadul.analyzers.sigdb_builtin.{name}")
        assert hasattr(mod, "SIGNATURES"), f"{name}.SIGNATURES yok"
        assert isinstance(mod.SIGNATURES, dict), f"{name}.SIGNATURES dict degil"

    @pytest.mark.parametrize("name", _EXPECTED_CATEGORIES)
    def test_module_placeholder_empty(self, name: str) -> None:
        """Faz 1: placeholder dosyalari bos dict ile gelir (Faz 2 doldurur)."""
        mod = importlib.import_module(f"karadul.analyzers.sigdb_builtin.{name}")
        assert mod.SIGNATURES == {}, (
            f"{name}.SIGNATURES Faz 1'de bos olmali; Faz 2 data migration'da dolar"
        )

    def test_count_is_17(self) -> None:
        assert len(_EXPECTED_CATEGORIES) == 17


class TestSigdbBuiltinDispatcher:
    """Dispatcher API."""

    def test_get_category_known(self) -> None:
        from karadul.analyzers.sigdb_builtin import get_category

        sigs = get_category("crypto")
        assert isinstance(sigs, dict)
        assert sigs == {}  # placeholder

    def test_get_category_unknown_raises(self) -> None:
        from karadul.analyzers.sigdb_builtin import get_category

        with pytest.raises(ValueError, match="Unknown signature category"):
            get_category("bogus_category_xyz")

    @pytest.mark.parametrize("name", _EXPECTED_CATEGORIES)
    def test_get_category_all_known(self, name: str) -> None:
        from karadul.analyzers.sigdb_builtin import get_category

        sigs = get_category(name)
        assert isinstance(sigs, dict)

    def test_list_categories(self) -> None:
        from karadul.analyzers.sigdb_builtin import list_categories

        cats = list_categories()
        assert len(cats) == 17
        assert sorted(cats) == _EXPECTED_CATEGORIES
        # Siralanmis donmeli
        assert cats == sorted(cats)


class TestLmdbAutoDetect:
    """Faz 1 config flag + graceful fallback."""

    def test_default_flag_is_true(self) -> None:
        """v1.12.0: ``use_lmdb_sigdb`` default True (auto-detect)."""
        from karadul.config import Config

        cfg = Config()
        assert cfg.perf.use_lmdb_sigdb is True, (
            "v1.12.0 Faz 1: use_lmdb_sigdb default True olmali"
        )

    def test_lmdb_missing_file_fallback_to_dict(self, tmp_path) -> None:
        """LMDB dosyasi yoksa graceful fallback (dict yolu, hata atmaz)."""
        from karadul.analyzers.signature_db import SignatureDB
        from karadul.config import Config

        cfg = Config()
        cfg.perf.use_lmdb_sigdb = True
        cfg.perf.sig_lmdb_path = tmp_path / "does_not_exist.lmdb"

        # Hata atmamali, _lmdb_backend None, dict dolu
        db = SignatureDB(cfg)
        assert db._lmdb_backend is None
        assert len(db._symbol_db) > 100, "Dict fallback builtin yuklemeli"
