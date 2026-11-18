"""P08 / IMZA-12: yerleşik sözlükte aynı adın POSIX ve MSVC kayıtları birbirini ezmez."""


from __future__ import annotations

import json
from pathlib import Path

import pytest

from karadul.analyzers.signature_db import SignatureDB
from karadul.config import Config


def _cfg(root: Path) -> Config:
    cfg = Config()
    cfg.project_root = root
    cfg.data_root = root  # GHIDRA-14: dış imzalar veri kökünden
    cfg.perf.use_lmdb_sigdb = False
    return cfg


@pytest.fixture()
def db_factory(tmp_path):
    def make(platform: str | None) -> SignatureDB:
        return SignatureDB(_cfg(tmp_path), target_platform=platform)
    return make



@pytest.mark.parametrize("name", ["_open", "_read", "_write", "_close", "_getpid", "_snprintf"])
def test_posix_names_match_on_macho(db_factory, name):
    m = db_factory("macho")._match_by_symbol(name, target_platform="macho")
    assert m is not None
    assert m.library not in ("msvcrt", "")


def test_msvc_record_still_wins_on_pe(db_factory):
    m = db_factory("pe")._match_by_symbol("_open", target_platform="pe")
    assert m is not None and m.library == "msvcrt"
