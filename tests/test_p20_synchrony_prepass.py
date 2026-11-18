"""P20 kalem 6 — eski deobfuscation zincirinin derin hatta katacağı tek şey: synchrony.

Ölçüm (P20.md kalem 6): obfuscator.io ile korunmuş girdide derin hat dize
dizisini çözmüyor (ürün örneğinin korunmuş hâlinde özgün dizgilerden 1/8
görünür, 51 çözücü çağrısı kalır); synchrony 8/8 ve 0. Eski zincirin
babel_transforms adımı her girdide başarısız (deobfuscate.mjs çıktı dosyası
yazmıyor), beautify derin hatta zaten var. Bağlama: yalnız synchrony, derin
hatta ön geçiş olarak, ``analysis.deep_synchrony_prepass`` bayrağıyla,
öntanımlı KAPALI; synchrony çıktısı ayrıştırılamıyorsa kullanılmaz (gerçek
Electron Fiddle paketinde görüldü).

``tests/fixtures/p20_sample_obfuscated.js``: ürünün kendi örneği
(``sample_minified.js``) javascript-obfuscator 4.1.1 ile korundu
(string-array base64, control-flow-flattening, seed 42).
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

import karadul.deobfuscators.synchrony_wrapper as sw
from karadul.config import Config
from karadul.core.workspace import Workspace
from karadul.deobfuscators.deep_pipeline import DeepDeobfuscationPipeline

_FIX = Path(__file__).parent / "fixtures"
_OBF = _FIX / "p20_sample_obfuscated.js"
_SECRET_LITERAL = "Welcome to __webpack_require__ land."


def _cfg(flag: bool | None) -> Config:
    cfg = Config()
    if flag is not None:
        cfg.analysis.deep_synchrony_prepass = flag
    return cfg


def test_prepass_is_off_by_default():
    pipe = DeepDeobfuscationPipeline(Config())
    assert pipe._synchrony_prepass_enabled() is False


def test_prepass_flag_requires_true_not_truthy():
    assert DeepDeobfuscationPipeline(_cfg(True))._synchrony_prepass_enabled() is True
    cfg = Config()
    cfg.analysis.deep_synchrony_prepass = "false"  # YAML'dan dize gelirse açılmaz
    assert DeepDeobfuscationPipeline(cfg)._synchrony_prepass_enabled() is False


def test_unparseable_synchrony_output_is_rejected(tmp_path, monkeypatch):
    if shutil.which("node") is None:
        pytest.skip("node yok")

    def _fake_deob(self, inp, out):
        out.write_text("function (e) { return e; }\n", encoding="utf-8")  # geçersiz JS
        return True

    monkeypatch.setattr(sw.SynchronyWrapper, "is_available", lambda self: True)
    monkeypatch.setattr(sw.SynchronyWrapper, "deobfuscate", _fake_deob)
    src = tmp_path / "in.js"
    src.write_text("var a = 1;\n", encoding="utf-8")
    out = tmp_path / "01b_synchrony.js"
    step = DeepDeobfuscationPipeline(_cfg(True))._step_synchrony_prepass(src, out)
    assert step["success"] is False
    assert "ayrıştırılamıyor" in step["error"]
    assert not out.exists()


def test_missing_synchrony_is_skipped_not_failure(tmp_path, monkeypatch):
    monkeypatch.setattr(sw.SynchronyWrapper, "is_available", lambda self: False)
    step = DeepDeobfuscationPipeline(_cfg(True))._step_synchrony_prepass(
        tmp_path / "in.js", tmp_path / "out.js",
    )
    assert step["success"] is False and step["skipped"] is True


def _real_ok() -> bool:
    cfg = Config()
    return (
        shutil.which("node") is not None
        and (cfg.scripts_dir / "node_modules").is_dir()
        and sw.SynchronyWrapper(cfg).is_available()
    )


@pytest.mark.skipif(not _real_ok(), reason="node / scripts/node_modules / synchrony yok")
@pytest.mark.parametrize("flag", [False, True], ids=["kapali", "acik"])
def test_obfuscated_strings_recovered_only_with_prepass(tmp_path, flag):
    ws = Workspace(base_dir=tmp_path / "ws", target_name="obf")
    ws.create()
    res = DeepDeobfuscationPipeline(_cfg(flag)).run(_OBF, ws)
    text = res.output_file.read_text(encoding="utf-8")
    if flag:
        assert res.steps["synchrony"]["success"] is True
        assert _SECRET_LITERAL in text
    else:
        assert "synchrony" not in res.steps
        assert _SECRET_LITERAL not in text
