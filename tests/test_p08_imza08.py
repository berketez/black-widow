"""P08 / IMZA-08: ELF/PE'de ad olduğu gibi kalır; Mach-O'da yalnız TEK C öneki "_" atılır."""


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



def test_elf_keeps_leading_underscores(db_factory):
    db = db_factory("elf")
    db.add_symbol("__p08_chk", {"lib": "libx", "purpose": "", "category": "x"})
    m = db._match_by_symbol("__p08_chk", target_platform="elf")
    assert m is not None and m.matched_name == "__p08_chk"


def test_pe_keeps_name(db_factory):
    db = db_factory("pe")
    db.add_symbol("__p08_pe", {"lib": "libx", "purpose": "", "category": "x"})
    m = db._match_by_symbol("__p08_pe", target_platform="pe")
    assert m is not None and m.matched_name == "__p08_pe"


def test_macho_strips_single_c_prefix(db_factory):
    db = db_factory("macho")
    db.add_symbol("_p08_fn", {"lib": "libx", "purpose": "", "category": "x"})
    db.add_symbol("___p08_chk", {"lib": "libx", "purpose": "", "category": "x"})
    assert db._match_by_symbol("_p08_fn", target_platform="macho").matched_name == "p08_fn"
    assert db._match_by_symbol("___p08_chk", target_platform="macho").matched_name == "__p08_chk"
