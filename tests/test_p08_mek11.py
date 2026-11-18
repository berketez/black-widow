"""P08 / MEK-11: Ghidra'nın yapay "entry" etiketi imza eşlemesine girmez."""


from __future__ import annotations

import json
from pathlib import Path

import pytest

from karadul.analyzers.signature_db import SignatureDB
from karadul.config import Config


def _cfg(root: Path) -> Config:
    cfg = Config()
    cfg.project_root = root
    cfg.perf.use_lmdb_sigdb = False
    return cfg


@pytest.fixture()
def db_factory(tmp_path):
    def make(platform: str | None) -> SignatureDB:
        return SignatureDB(_cfg(tmp_path), target_platform=platform)
    return make



def test_ghidra_entry_label_is_not_a_library_symbol(db_factory):
    db = db_factory("macho")
    db.add_symbol("entry", {"lib": "CoreGraphics", "purpose": "", "category": "graphics"})
    assert db._match_by_symbol("entry", target_platform="macho") is None
    assert db._match_by_symbol("entry", target_platform=None) is None


def test_ghidra_init_array_labels_are_not_symbols(db_factory):
    db = db_factory("elf")
    db.add_symbol("_INIT_0", {"lib": "libx", "purpose": "", "category": "x"})
    db.add_symbol("_FINI_1", {"lib": "libx", "purpose": "", "category": "x"})
    assert db._match_by_symbol("_INIT_0", target_platform="elf") is None
    assert db._match_by_symbol("_FINI_1", target_platform="elf") is None
    # benzer ama gerçek bir ad etkilenmez
    db.add_symbol("entry_point_init", {"lib": "libx", "purpose": "", "category": "x"})
    assert db._match_by_symbol("entry_point_init", target_platform="elf") is not None
