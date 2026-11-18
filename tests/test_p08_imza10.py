"""P08 / IMZA-10: süreç önbelleği hedef platformu ve LMDB durumunu anahtara katar."""


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



def test_cache_does_not_leak_platform_filtered_externals(tmp_path):
    root = tmp_path / "proj"
    (root / "sigs").mkdir(parents=True)
    (root / "sigs" / "linux_p08.json").write_text(json.dumps(
        {"signatures": {"p08_only_linux_fn": {"lib": "liblinuxonly", "purpose": "", "category": "x"}}}),
        encoding="utf-8")
    (root / "sigs" / "windows_p08.json").write_text(json.dumps(
        {"signatures": {"p08_only_win_fn": {"lib": "libwinonly", "purpose": "", "category": "x"}}}),
        encoding="utf-8")
    pe = SignatureDB(_cfg(root), target_platform="pe")
    assert pe._match_by_symbol("p08_only_win_fn", target_platform="pe") is not None
    elf = SignatureDB(_cfg(root), target_platform="elf")  # aynı süreç, önbellek sıcak
    m = elf._match_by_symbol("p08_only_linux_fn", target_platform="elf")
    assert m is not None and m.library == "liblinuxonly"
