"""P20 kalem 2 — BICIM-03: JS ad / parametre sayaçları gerçeği söylesin.

Önce (ürünün örneği `sample_minified.js`, d2f205d + kalem 1):
  variables_renamed 3, rename_high 0 / medium 1 / low 20 (toplam 21 ≠ 3:
  kovalar analizcinin eşik ÖNCESİ aday sayısıydı); params_recovered 6,
  params_applied 7 (uygulanan > kurtarılan: parametre + gövde başvurusu
  toplanıyordu). apply-names.mjs flat kipte "renamed" başvuru (identifier
  düğümü) sayısıydı.
Sonra: kovalar UYGULANAN adlardan (toplam == variables_renamed), adaylar
`candidates_*` alanında; params_applied = yeniden adlandırılan parametre sayısı
(gövde başvuruları `references_renamed`); flat kipte renamed = ad sayısı.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from karadul.config import Config
from karadul.reconstruction.context_namer import ContextNamer
from karadul.reconstruction.param_recovery import ParamRecovery

_CONFIG = Config()
_SCRIPTS = _CONFIG.scripts_dir
_FIXTURE_JS = Path(__file__).parent / "fixtures" / "sample_minified.js"

pytestmark = pytest.mark.skipif(
    shutil.which("node") is None or not (_SCRIPTS / "node_modules").is_dir(),
    reason="node ya da scripts/node_modules yok",
)


def _node_json(*args: str) -> dict:
    proc = subprocess.run(
        ["node", *args], capture_output=True, text=True, timeout=120, cwd=_SCRIPTS,
    )
    return json.loads(proc.stdout.strip().splitlines()[-1])


# ---------------------------------------------------------------------------
# ContextNamer: kovalar uygulanan adlardan
# ---------------------------------------------------------------------------

def test_confidence_buckets_sum_to_applied_renames(tmp_path):
    inp = tmp_path / "sample.js"
    inp.write_text(_FIXTURE_JS.read_text(encoding="utf-8"), encoding="utf-8")
    res = ContextNamer(_CONFIG).analyze_and_rename(inp, tmp_path / "out.js")
    assert res.success, res.errors
    assert res.variables_renamed > 0
    assert res.high_confidence + res.medium_confidence + res.low_confidence == (
        res.variables_renamed
    )
    # Analizcinin aday sayıları ayrı alanda ve uygulanandan fazla olabilir.
    cands = res.candidates_high + res.candidates_medium + res.candidates_low
    assert cands >= res.variables_renamed
    assert not any("güven dağılımı" in e for e in res.errors)


def test_buckets_unknown_when_applier_does_not_report(tmp_path, monkeypatch):
    """Uygulayıcı dağılım vermezse 0 uydurulmaz: None (bilinmiyor)."""
    namer = ContextNamer(_CONFIG)
    monkeypatch.setattr(namer, "analyze", lambda _p: {
        "stats": {"named_high_confidence": 4, "named_medium_confidence": 2,
                  "named_low_confidence": 9},
        "variables": {"x": {}}, "errors": [],
    })
    monkeypatch.setattr(namer, "apply", lambda *_a: {
        "renamed": 2, "mappings": {"a": "b", "c": "d"}, "errors": [],
    })
    inp = tmp_path / "in.js"
    inp.write_text("var a;\n", encoding="utf-8")
    res = namer.analyze_and_rename(inp, tmp_path / "out.js")
    assert res.variables_renamed == 2
    assert res.high_confidence is None
    assert res.medium_confidence is None
    assert res.low_confidence is None
    assert (res.candidates_high, res.candidates_medium, res.candidates_low) == (4, 2, 9)


def test_inconsistent_distribution_is_reported(tmp_path, monkeypatch):
    namer = ContextNamer(_CONFIG)
    monkeypatch.setattr(namer, "analyze", lambda _p: {
        "stats": {}, "variables": {"x": {}}, "errors": [],
    })
    monkeypatch.setattr(namer, "apply", lambda *_a: {
        "renamed": 3, "mappings": {}, "errors": [],
        "applied_by_confidence": {"high": 1, "medium": 0, "low": 0},
    })
    inp = tmp_path / "in.js"
    inp.write_text("var a;\n", encoding="utf-8")
    res = namer.analyze_and_rename(inp, tmp_path / "out.js")
    assert any("güven dağılımı" in e for e in res.errors)


# ---------------------------------------------------------------------------
# apply-names.mjs: scope-aware dağılım + flat kipte ad sayısı
# ---------------------------------------------------------------------------

def test_apply_names_scope_aware_reports_applied_distribution(tmp_path):
    src = tmp_path / "in.js"
    src.write_text("function f(a, b) { var c = a + b; return c; }\n", encoding="utf-8")
    ctx = ContextNamer(_CONFIG).analyze(src)
    out = tmp_path / "out.js"
    res = ContextNamer(_CONFIG, min_confidence=0.0).apply(src, ctx, out)
    dist = res["applied_by_confidence"]
    assert dist["high"] + dist["medium"] + dist["low"] == res["renamed"]


def test_apply_names_flat_mode_counts_names_not_references(tmp_path):
    src = tmp_path / "in.js"
    src.write_text("var e = 1; e = e + e; console.log(e);\n", encoding="utf-8")
    names = tmp_path / "names.json"
    names.write_text(json.dumps({
        "variables": {"e": {"suggested_name": "counter", "confidence": 0.6}},
    }), encoding="utf-8")
    out = tmp_path / "out.js"
    res = _node_json(str(_SCRIPTS / "apply-names.mjs"), str(src), str(names), str(out))
    assert res["success"] is True and res["scope_aware"] is False
    assert res["renamed"] == 1            # bir ad
    assert res["references_renamed"] == 5  # beş başvuru (bildirim + 4 kullanım)
    assert res["applied_by_confidence"] == {"high": 1, "medium": 0, "low": 0}
    assert "counter" in out.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# apply-params.mjs / ParamRecovery: uygulanan <= kurtarılan
# ---------------------------------------------------------------------------

def test_params_applied_counts_parameters_not_references(tmp_path):
    inp = tmp_path / "sample.js"
    inp.write_text(_FIXTURE_JS.read_text(encoding="utf-8"), encoding="utf-8")
    pr = ParamRecovery(_CONFIG)
    rec = pr.recover(inp)
    assert rec.success and rec.recovered > 0 and rec.recovery_json is not None
    out = tmp_path / "params.js"
    applied = pr.apply_to_file(inp, rec.recovery_json, out)
    assert 0 < applied <= rec.recovered

    # Ham betik çıktısı: renamed == eşleme sayısı; başvurular ayrı.
    raw = _node_json(
        str(_SCRIPTS / "apply-params.mjs"), str(inp), str(rec.recovery_json),
        str(tmp_path / "raw.js"), "--min-confidence", "0.0",
    )
    assert raw["renamed"] == len(raw["mappings"])
    assert raw["references_renamed"] == sum(
        m["body_refs"] for m in raw["mappings"].values()
    )
