"""P08 / IMZA-09: protobuf kısmi eşleşmesi yalnız google::protobuf:: ad alanında."""


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



@pytest.mark.parametrize("name", ["MyCache::Get", "Parser::Init", "Init", "Timer::Reset",
                                  "std::map::Clear", "Next", "Set"])
def test_generic_method_names_are_not_protobuf(db_factory, name):
    m = db_factory("elf")._match_by_symbol(name, target_platform="elf")
    assert m is None or "protobuf" not in (m.library or "").lower()


def test_protobuf_namespace_still_matches(db_factory):
    db = db_factory("elf")
    full = db._match_by_symbol("google::protobuf::Message::Clear", target_platform="elf")
    assert full is not None and full.library == "protobuf"
    part = db._match_by_symbol("google::protobuf::util::Differ::Clear", target_platform="elf")
    assert part is not None and part.library == "protobuf"
    # kısmi eşleşme başka bir yöntemin adını ödünç vermez
    assert part.matched_name == "google::protobuf::util::Differ::Clear"
