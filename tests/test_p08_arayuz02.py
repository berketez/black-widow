"""P08 / ARAYUZ-02 (yazıcı tarafı): signature_matches.json IOC süzgecinin okuduğu
alanları (category, family, tier) ve veritabanı künyesini taşır.

Gerçek ürün biçimi: ``GhidraMetadataStep._run_signature_db`` ile yazılan dosya
(sentetik şema değil); girdi Sliver içerik paketindeki gerçek bir simge adı.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from karadul.config import Config
from karadul.core.target import TargetType

SLIVER = "github.com/bishopfox/sliver/implant/sliver/handlers"


class _WS:
    def __init__(self, root: Path) -> None:
        self.root = root

    def save_json(self, stage: str, name: str, data: dict) -> Path:
        p = self.root / stage / f"{name}.json"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(data), encoding="utf-8")
        return p


def _run(tmp_path: Path, names: list[str]):
    from karadul.pipeline.steps.ghidra_metadata import GhidraMetadataStep

    cfg = Config()
    cfg.project_root = tmp_path
    cfg.perf.use_lmdb_sigdb = False
    fj = tmp_path / "ghidra_functions.json"
    fj.write_text(json.dumps({"functions": [
        {"name": n, "address": f"{0x1000 + i:08x}"} for i, n in enumerate(names)]}), encoding="utf-8")
    (tmp_path / "s.json").write_text("[]", encoding="utf-8")
    (tmp_path / "c.json").write_text("{}", encoding="utf-8")
    (tmp_path / "dec").mkdir(exist_ok=True)
    ws = _WS(tmp_path / "ws")
    pc = SimpleNamespace(config=cfg, workspace=ws, report_progress=lambda *a, **k: None)
    ctx = SimpleNamespace(stats={}, errors=[], produce_artifact=lambda *a, **k: None)
    GhidraMetadataStep._run_signature_db(
        pc=pc, target=SimpleNamespace(target_type=TargetType.ELF_BINARY),
        functions_json=fj, strings_json=tmp_path / "s.json", call_graph_json=tmp_path / "c.json",
        decompiled_dir=tmp_path / "dec", ctx=ctx)
    out = ws.root / "reconstructed" / "signature_matches.json"
    return (json.loads(out.read_text("utf-8")) if out.exists() else None), ctx


def test_ioc_fields_written_for_tier1_symbol(tmp_path):
    data, ctx = _run(tmp_path, [SLIVER, "SSL_CTX_new"])
    assert data is not None
    rec = {m["original"]: m for m in data["matches"]}
    s = rec[SLIVER]
    assert s["family"] == "sliver"
    assert s["tier"] == "1"
    assert s["category"] == "malware"
    assert rec["SSL_CTX_new"]["family"] == "" and rec["SSL_CTX_new"]["tier"] == ""
    assert ctx.stats["sigdb_ioc_matches"] == 1
    # künye dosyada da var
    assert data["database"]["sigdb_backend"] == "builtin_dict"
    assert data["schema"] == 2


def test_no_ioc_is_zero_not_missing(tmp_path):
    data, ctx = _run(tmp_path, ["SSL_CTX_new"])
    assert ctx.stats["sigdb_status"] == "matched"
    assert ctx.stats["sigdb_ioc_matches"] == 0
    assert all(m["family"] == "" for m in data["matches"])
