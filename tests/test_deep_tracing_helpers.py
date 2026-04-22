"""v1.10.0 H8: _deep_tracing_helpers unit testleri.

stages.py L3762-3931 refaktor sonrasi bu modul pure/orchestration
helper'larini barindiriyor. Her fonksiyon icin ImportError / Exception
fallback davranisi ve temel success path'leri test edilir.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from karadul.pipeline.steps import _deep_tracing_helpers as _dth


# ---------------------------------------------------------------------------
# resolve_dispatch
# ---------------------------------------------------------------------------


class TestResolveDispatch:
    def test_import_error_graceful(self, tmp_path: Path):
        """VirtualDispatchResolver import edilemezse sessiz atlamali."""
        errors: list[str] = []
        stats: dict = {}
        workspace = MagicMock()

        with patch(
            "karadul.reconstruction.engineering.VirtualDispatchResolver",
            side_effect=ImportError("mock"),
        ):
            result, augmented = _dth.resolve_dispatch(
                decompiled_dir=tmp_path,
                functions_json=tmp_path / "f.json",
                call_graph_json=tmp_path / "cg.json",
                strings_json=tmp_path / "s.json",
                call_graph_data={},
                reconstructed_dir=tmp_path,
                stats=stats,
                errors=errors,
                workspace=workspace,
            )

        assert result is None
        assert augmented is None
        # ImportError icin errors listesi bos kalir (debug-level)
        assert errors == []

    def test_generic_exception_adds_error(self, tmp_path: Path):
        """Genel exception errors listesine eklenmeli."""
        errors: list[str] = []
        stats: dict = {}
        workspace = MagicMock()

        with patch(
            "karadul.reconstruction.engineering.VirtualDispatchResolver",
        ) as mock_resolver:
            mock_resolver.side_effect = RuntimeError("mock hata")
            result, augmented = _dth.resolve_dispatch(
                decompiled_dir=tmp_path,
                functions_json=tmp_path / "f.json",
                call_graph_json=tmp_path / "cg.json",
                strings_json=tmp_path / "s.json",
                call_graph_data={},
                reconstructed_dir=tmp_path,
                stats=stats,
                errors=errors,
                workspace=workspace,
            )

        assert result is None
        assert augmented is None
        assert len(errors) == 1
        assert "mock hata" in errors[0]


# ---------------------------------------------------------------------------
# resolve_call_graph (v1.10.0 C4 bug fix)
# ---------------------------------------------------------------------------


class TestResolveCallGraph:
    def test_none_cache_none_augmented(self):
        """Hem cache hem augmented None -> bos dict."""
        result = _dth.resolve_call_graph(None, None)
        assert result == {}

    def test_augmented_missing_file_returns_cache(self, tmp_path: Path):
        """Augmented path verilmis ama dosya yok -> cache dondur."""
        cache = {"foo": {"callers": []}}
        nonexistent = tmp_path / "yok.json"
        result = _dth.resolve_call_graph(nonexistent, cache)
        assert result == cache

    def test_augmented_empty_cache_returns_augmented(self, tmp_path: Path):
        """Cache bos + augmented var -> augmented aynen dondurulur."""
        aug_path = tmp_path / "aug.json"
        aug_data = {"nodes": ["A", "B"], "edges": [{"src": "A", "dst": "B"}]}
        aug_path.write_text(json.dumps(aug_data), encoding="utf-8")
        result = _dth.resolve_call_graph(aug_path, {})
        assert result == aug_data

    def test_augmented_merges_edges_with_cache(self, tmp_path: Path):
        """Cache zengin + augmented edges var -> edges concat (dedupe)."""
        aug_path = tmp_path / "aug.json"
        aug_data = {
            "nodes": ["X"],
            "edges": [
                {"src": "A", "dst": "B"},  # dup with cache
                {"src": "C", "dst": "D"},  # yeni
            ],
        }
        aug_path.write_text(json.dumps(aug_data), encoding="utf-8")
        cache = {"edges": [{"src": "A", "dst": "B"}]}  # mevcut edge

        result = _dth.resolve_call_graph(aug_path, cache)

        # edges dedupe edildi, yeni edge eklendi.
        assert len(result["edges"]) == 2
        edge_strs = {json.dumps(e, sort_keys=True) for e in result["edges"]}
        assert json.dumps({"src": "A", "dst": "B"}, sort_keys=True) in edge_strs
        assert json.dumps({"src": "C", "dst": "D"}, sort_keys=True) in edge_strs
        # Augmented'tan yeni top-level key eklendi.
        assert "nodes" in result

    def test_invalid_json_falls_back_to_cache(self, tmp_path: Path):
        """Bozuk JSON -> cache geri dondurulur, exception atilmaz."""
        aug_path = tmp_path / "bozuk.json"
        aug_path.write_text("{ bu gecerli json degil", encoding="utf-8")
        cache = {"ok": True}
        result = _dth.resolve_call_graph(aug_path, cache)
        assert result == cache

    def test_non_dict_augmented_falls_back(self, tmp_path: Path):
        """Augmented JSON dict degilse cache'e geri dondur."""
        aug_path = tmp_path / "liste.json"
        aug_path.write_text(json.dumps(["bu", "liste"]), encoding="utf-8")
        cache = {"hello": "world"}
        result = _dth.resolve_call_graph(aug_path, cache)
        assert result == cache


# ---------------------------------------------------------------------------
# analyze_data_flow
# ---------------------------------------------------------------------------


class TestAnalyzeDataFlow:
    def test_import_error_graceful(self, tmp_path: Path):
        """InterProceduralDataFlow import edilmezse None doner."""
        errors: list[str] = []
        stats: dict = {}
        with patch(
            "karadul.reconstruction.engineering.InterProceduralDataFlow",
            side_effect=ImportError("yok"),
        ):
            result = _dth.analyze_data_flow(
                decompiled_dir=tmp_path,
                functions_json=tmp_path / "f.json",
                call_graph_json=tmp_path / "cg.json",
                augmented_cg_json=None,
                xrefs_json=tmp_path / "xr.json",
                reconstructed_dir=tmp_path,
                stats=stats,
                errors=errors,
            )
        assert result is None
        assert errors == []


# ---------------------------------------------------------------------------
# propagate_param_names
# ---------------------------------------------------------------------------


class TestPropagateParamNames:
    def test_import_error_silent(self, tmp_path: Path):
        """InterProceduralDataFlow yoksa sessizce doner."""
        errors: list[str] = []
        stats: dict = {}
        with patch(
            "karadul.reconstruction.engineering.InterProceduralDataFlow",
            side_effect=ImportError("yok"),
        ):
            _dth.propagate_param_names(
                decompiled_dir=tmp_path,
                functions_json=tmp_path / "f.json",
                call_graph_json=tmp_path / "cg.json",
                augmented_cg_json=None,
                sig_matches=None,
                stats=stats,
                errors=errors,
            )
        assert errors == []
