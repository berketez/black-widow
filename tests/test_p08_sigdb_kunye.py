"""P08 / IMZA-11: koşu hangi imza veritabanıyla yapıldığını söylemeli.

"Eşleşme yok" ile "veritabanı yok" ayrılmalı: LMDB açılamazsa nedeni,
arka uç, ad sayısı, yol ve künye her koşuda istatistiğe yazılır.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from karadul.analyzers.signature_db import SignatureDB
from karadul.config import Config
from karadul.core.target import TargetType

lmdb = pytest.importorskip("lmdb")


def _cfg(tmp_path: Path, *, use_lmdb: bool, lmdb_path: Path | None) -> Config:
    cfg = Config()
    cfg.project_root = tmp_path  # sigs/ yok: yalnız yerleşik sözlük
    cfg.perf.use_lmdb_sigdb = use_lmdb
    cfg.perf.sig_lmdb_path = lmdb_path
    return cfg


def _tiny_lmdb(path: Path) -> Path:
    from karadul.analyzers.sigdb_lmdb import LMDBSignatureDB

    db = LMDBSignatureDB(path, readonly=False, map_size=16 * 1024 * 1024)
    db.bulk_write_symbols([
        ("p08_only_in_lmdb_a", {"lib": "liba", "purpose": "", "category": "x"}),
        ("p08_only_in_lmdb_b", {"lib": "libb", "purpose": "", "category": "x"}),
    ])
    db.put_metadata("schema_version", b"2")
    db.put_metadata("build_id", b"p08-test-build")
    db.sync()
    db.close()
    return path


def test_missing_lmdb_is_reported_not_silent(tmp_path):
    missing = tmp_path / "yok.lmdb"
    db = SignatureDB(_cfg(tmp_path, use_lmdb=True, lmdb_path=missing), target_platform="elf")
    info = db.backend_info()
    assert info["sigdb_backend"] == "builtin_dict"
    assert info["sigdb_lmdb_symbol_count"] is None
    assert info["sigdb_lmdb_error"] is not None
    assert info["sigdb_lmdb_error"].startswith("bulunamadı")
    assert str(missing) in info["sigdb_lmdb_error"]
    assert info["sigdb_path"] == str(missing)
    assert info["sigdb_path_source"] == "config:perf.sig_lmdb_path"
    # Yerleşik sözlük birkaç bin ad; LMDB'nin milyonları değil.
    assert 1000 < info["sigdb_symbol_count"] == info["sigdb_dict_symbol_count"] < 50_000


def test_disabled_lmdb_reason(tmp_path):
    db = SignatureDB(_cfg(tmp_path, use_lmdb=False, lmdb_path=None), target_platform="elf")
    info = db.backend_info()
    assert info["sigdb_backend"] == "builtin_dict"
    assert info["sigdb_lmdb_error"] == "kapalı: perf.use_lmdb_sigdb=False"
    assert info["sigdb_path"] is None


def test_lmdb_backend_counts_and_version(tmp_path):
    p = _tiny_lmdb(tmp_path / "mini.lmdb")
    db = SignatureDB(_cfg(tmp_path, use_lmdb=True, lmdb_path=p), target_platform="elf")
    info = db.backend_info()
    assert info["sigdb_backend"] == "lmdb"
    assert info["sigdb_lmdb_error"] is None
    assert info["sigdb_lmdb_symbol_count"] == 2
    assert info["sigdb_symbol_count"] == info["sigdb_dict_symbol_count"] + 2
    assert info["sigdb_schema_version"] == "2"
    assert info["sigdb_build_id"] == "p08-test-build"


def test_env_path_source(tmp_path, monkeypatch):
    p = _tiny_lmdb(tmp_path / "env.lmdb")
    monkeypatch.setenv("KARADUL_SIG_LMDB_PATH", str(p))
    db = SignatureDB(_cfg(tmp_path, use_lmdb=True, lmdb_path=None), target_platform="elf")
    info = db.backend_info()
    assert info["sigdb_backend"] == "lmdb"
    assert info["sigdb_path_source"] == "env:KARADUL_SIG_LMDB_PATH"


class _WS:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.saved: dict[str, dict] = {}

    def save_json(self, stage: str, name: str, data: dict) -> Path:
        p = self.root / stage / f"{name}.json"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(data), encoding="utf-8")
        self.saved[f"{stage}/{name}"] = data
        return p


def _run_step(tmp_path: Path, cfg: Config, functions: list[dict]):
    from karadul.pipeline.steps.ghidra_metadata import GhidraMetadataStep

    fj = tmp_path / "ghidra_functions.json"
    fj.write_text(json.dumps({"functions": functions}), encoding="utf-8")
    sj = tmp_path / "ghidra_strings.json"
    sj.write_text("[]", encoding="utf-8")
    cj = tmp_path / "ghidra_call_graph.json"
    cj.write_text("{}", encoding="utf-8")
    dec = tmp_path / "decompiled"
    dec.mkdir(exist_ok=True)
    ws = _WS(tmp_path / "ws")
    pc = SimpleNamespace(config=cfg, workspace=ws, report_progress=lambda *a, **k: None)
    ctx = SimpleNamespace(stats={}, errors=[], produce_artifact=lambda *a, **k: None)
    target = SimpleNamespace(target_type=TargetType.ELF_BINARY)
    matches = GhidraMetadataStep._run_signature_db(
        pc=pc, target=target, functions_json=fj, strings_json=sj,
        call_graph_json=cj, decompiled_dir=dec, ctx=ctx,
    )
    return matches, ctx, ws


def test_step_writes_backend_stats_on_no_match(tmp_path):
    cfg = _cfg(tmp_path, use_lmdb=True, lmdb_path=tmp_path / "yok.lmdb")
    matches, ctx, _ = _run_step(tmp_path, cfg, [{"name": "FUN_00001000", "address": "00001000"}])
    assert matches == []
    assert ctx.stats["sigdb_status"] == "no_match"
    assert ctx.stats["sigdb_backend"] == "builtin_dict"
    assert ctx.stats["sigdb_lmdb_error"].startswith("bulunamadı")
    assert ctx.stats["sigdb_symbol_count"] > 1000


def test_step_status_matched(tmp_path):
    cfg = _cfg(tmp_path, use_lmdb=False, lmdb_path=None)
    matches, ctx, _ = _run_step(tmp_path, cfg, [{"name": "SSL_CTX_new", "address": "00002000"}])
    assert matches
    assert ctx.stats["sigdb_status"] == "matched"
    assert ctx.stats["sigdb_backend"] == "builtin_dict"
