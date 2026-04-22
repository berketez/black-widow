"""CFG template integration tests — 8 builtin + 310 JSON algoritma.

v1.10.0 Batch 5A: `template_db.default_template_bank()` hem sentetik
8 template'i hem `known_algorithms.json`'daki 310 template'i yuklemeli.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from karadul.computation.cfg_iso.fingerprint import AttributedCFG, CFGNode
from karadul.computation.cfg_iso.template_db import (
    AlgorithmTemplate,
    _builtin_template_bank,
    _json_entry_to_template,
    default_template_bank,
    load_from_json,
)


class TestLoadFromJson:
    """JSON yukleyici temel davranis."""

    def test_default_path_loads(self) -> None:
        """Varsayilan yol ile yukleme (repo icindeki known_algorithms.json)."""
        templates = load_from_json()
        assert len(templates) >= 300  # ~310 bekleniyor

    def test_all_templates_have_required_fields(self) -> None:
        templates = load_from_json()
        for t in templates:
            assert t.name
            assert isinstance(t.cfg, AttributedCFG)
            assert t.family  # her template'in category'si olmali

    def test_invalid_path_returns_empty(self, tmp_path: Path) -> None:
        """Olmayan dosya -> bos liste (hata atmaz)."""
        result = load_from_json(tmp_path / "nonexistent.json")
        assert result == []

    def test_invalid_json_returns_empty(self, tmp_path: Path) -> None:
        """Bozuk JSON -> bos liste."""
        p = tmp_path / "bad.json"
        p.write_text("{not valid json")
        assert load_from_json(p) == []

    def test_non_list_json_returns_empty(self, tmp_path: Path) -> None:
        """Root objesi list degilse -> bos."""
        p = tmp_path / "dict.json"
        p.write_text('{"not": "a list"}')
        assert load_from_json(p) == []


class TestJsonEntryToTemplate:
    """Tek entry -> AlgorithmTemplate donusumu."""

    def test_basic_entry(self) -> None:
        entry = {
            "name": "test_algo",
            "category": "test",
            "fingerprint": [0.5, 0.3, 0.2] + [0.1] * 21,
            "structure_hash": "wl_test_0001",
            "description": "Test algorithm",
        }
        t = _json_entry_to_template(entry)
        assert t is not None
        assert t.name == "test_algo"
        assert t.family == "test"
        assert "test_algo_entry" in [n.id for n in t.cfg.nodes]

    def test_entry_with_no_name_rejected(self) -> None:
        entry = {"category": "test", "fingerprint": []}
        t = _json_entry_to_template(entry)
        assert t is None

    def test_empty_fingerprint_handled(self) -> None:
        """Fingerprint bos olsa bile template dondurulmeli (body histogram bos)."""
        entry = {"name": "empty_fp", "category": "misc", "fingerprint": []}
        t = _json_entry_to_template(entry)
        assert t is not None
        # Body histogramı bos olabilir
        body = [n for n in t.cfg.nodes if "body" in n.id][0]
        assert body.mnemonic_histogram == {}

    def test_structure_hash_in_string_refs(self) -> None:
        entry = {
            "name": "hashed",
            "category": "x",
            "fingerprint": [0.1] * 24,
            "structure_hash": "wl_my_hash_0042",
        }
        t = _json_entry_to_template(entry)
        assert t is not None
        assert "wl_my_hash_0042" in t.cfg.string_refs


class TestDefaultTemplateBank:
    """Hem builtin + JSON birlesik davranıs."""

    def test_include_json_default(self) -> None:
        """Default: JSON dahil -> 300+ template."""
        bank = default_template_bank()
        assert len(bank) >= 300

    def test_exclude_json(self) -> None:
        """include_json=False -> sadece 8 builtin."""
        bank = default_template_bank(include_json=False)
        assert len(bank) == 8

    def test_builtin_names_preserved(self) -> None:
        """Builtin isimleri (quicksort, BFS vs) JSON ile override olmamali."""
        builtin = _builtin_template_bank()
        builtin_names = {t.name for t in builtin}

        bank = default_template_bank()
        bank_names = [t.name for t in bank]
        # Ilk 8 builtin olmali
        for i, name in enumerate([t.name for t in builtin]):
            assert bank_names[i] == name, f"Expected {name} at position {i}"

    def test_no_duplicate_names(self) -> None:
        """Birlesik bank'te isim çakışması olmamalı."""
        bank = default_template_bank()
        names = [t.name for t in bank]
        assert len(names) == len(set(names)), "Duplicate template names"

    def test_categories_diverse(self) -> None:
        """310 template çoklu kategoriyi kapsamalı."""
        bank = default_template_bank()
        categories = {t.family for t in bank}
        # En azindan sorting + crypto + memory + string
        assert "sorting" in categories or "sort" in categories
        assert "crypto" in categories or "crypto_extended" in categories
        assert len(categories) >= 5

    def test_alternative_json_path(self, tmp_path: Path) -> None:
        """Alternatif JSON yolu ile yukleme."""
        p = tmp_path / "custom.json"
        p.write_text('[{"name": "custom_algo", "category": "test", "fingerprint": [0.1]}]')
        bank = default_template_bank(json_path=p)
        names = [t.name for t in bank]
        assert "custom_algo" in names

    def test_integration_with_existing_pipeline(self) -> None:
        """Yuklenen template'ler CFGNode ve AttributedCFG tipli olmali."""
        bank = default_template_bank()
        sample = bank[10]  # 8 builtin sonrasi JSON'dan biri
        assert isinstance(sample.cfg, AttributedCFG)
        assert all(isinstance(n, CFGNode) for n in sample.cfg.nodes)
        # WL hash hesaplanabilmeli
        from karadul.computation.cfg_iso.fingerprint import weisfeiler_lehman_hash
        h = weisfeiler_lehman_hash(sample.cfg)
        assert isinstance(h, (bytes, str))
