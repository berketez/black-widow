"""P-S4 kalem 2 (BICIM-13): ModuleSplitter / ProjectReconstructor doğru dizini okur;
``reconstruct-project.mjs`` modülleri bölmez / birleştirmez, her çıktıyı ayrıştırıcıyla sınar.

Eskiden ``_execute_js`` ``webpack_modules/module_*.js`` arıyordu (derin hat
``webpack_modules/modules/``'a yazıyor) → ayırıcı ve proje kurucu hiç koşmuyordu.
``reconstruct-project.mjs`` 500 satırdan uzun modülü satır sayısıyla bölüyor, küçük
modülleri tek dosyada yan yana koyuyordu (ayrıştırılamayan çıktı).
"""

from __future__ import annotations

import json
import shutil
import subprocess

import pytest

from karadul.core.result import StageResult
from karadul.stages import ReconstructionStage
from tests.test_ps4_js_kaynak import _DEPO, _ctx, _deob_dosyalari, adimlar_bos  # noqa: F401

_MJS = _DEPO / "scripts" / "reconstruct-project.mjs"


def test_modul_ayirici_dogru_dizini_okur(tmp_path, adimlar_bos):
    ctx = _ctx(tmp_path)
    deob = _deob_dosyalari(ctx, {"03_enhanced_renamed.js": 100})
    mdir = deob / "webpack_modules" / "modules"
    mdir.mkdir(parents=True)
    for i in range(3):
        (mdir / f"module_{i}.js").write_text(f"module.exports = {i};\n", encoding="utf-8")
    ctx.results["deobfuscate"] = StageResult(
        stage_name="deobfuscate", success=True, duration_seconds=0.0,
        artifacts={"output_file": deob / "03_enhanced_renamed.js"}, stats={"status": "ok"},
    )
    ReconstructionStage(use_project_reconstructor=False)._execute_js(ctx, 0.0)
    assert adimlar_bos["split"] == [mdir]


_NODE = shutil.which("node")
_BABEL = (_DEPO / "scripts" / "node_modules" / "@babel" / "parser").is_dir()


@pytest.mark.skipif(not (_NODE and _BABEL), reason="node ya da scripts/node_modules yok")
def test_reconstruct_project_ciktisi_ayrisir(tmp_path):
    """Uzun modül satırla bölünmez, küçük modüller yan yana konmaz; her çıktı ayrışır."""
    mdir = tmp_path / "modules"
    mdir.mkdir()
    uzun = ["function buyuk() {", "  const s = \"{ { {\";"]
    uzun += [f"  var v{i} = {{ a: {i}, b: \"}}\" }};" for i in range(700)]
    uzun += ["  return s;", "}", "module.exports = buyuk;"]
    (mdir / "module_1.js").write_text("\n".join(uzun) + "\n", encoding="utf-8")
    for i in range(2, 6):
        (mdir / f"module_{i}.js").write_text(
            f"const ortak = {i};\nmodule.exports = ortak;\n", encoding="utf-8")
    out = tmp_path / "out"
    p = subprocess.run([_NODE, str(_MJS), str(mdir), str(out)], capture_output=True,
                       text=True, timeout=120, cwd=str(_DEPO / "scripts"))
    sonuc = json.loads(p.stdout.strip().splitlines()[-1])
    assert sonuc["success"] is True
    js = sorted(f for f in out.rglob("*.js") if f.name != "index.js" and f.parent.name != "src")
    assert len(js) == 5
    bozuk = [f.name for f in js
             if subprocess.run([_NODE, "--check", str(f)], capture_output=True).returncode]
    assert bozuk == []
    assert sonuc["modules_parse_ok"] == 5 and sonuc["modules_parse_failed"] == 0


def test_proje_kurucu_ayrismayan_modulu_bildirir(tmp_path, adimlar_bos, monkeypatch):
    """ProjectReconstructor'ın betik sayaçları aşamaya geçer; ayrışmayan modül hata satırı."""
    import karadul.reconstruction.module_splitter as ms
    import karadul.reconstruction.project_reconstructor as prc

    class _Split:
        success = True
        total_modules = 12
        categorized = {"utils": 12}
        output_dir = None
        errors: list = []

    monkeypatch.setattr(ms.ModuleSplitter, "split", lambda self, a, b: _Split())

    class _Recon:
        success = True
        files_written = 12
        dependencies: dict = {}
        categories = {"utils": 12}
        project_dir = None
        package_json = None
        entry_point = None
        errors: list = []
        stats = {"reconstruct_script": {"modules_parse_ok": 11, "modules_parse_failed": 1,
                                        "parse_failed_files": [{"file": "lib/x.js"}]}}

    monkeypatch.setattr(prc.ProjectReconstructor, "reconstruct", lambda self, w, t: _Recon())
    ctx = _ctx(tmp_path)
    deob = _deob_dosyalari(ctx, {"03_enhanced_renamed.js": 100})
    mdir = deob / "webpack_modules" / "modules"
    mdir.mkdir(parents=True)
    (mdir / "module_0.js").write_text("module.exports = 0;\n", encoding="utf-8")
    ctx.results["deobfuscate"] = StageResult(
        stage_name="deobfuscate", success=True, duration_seconds=0.0,
        artifacts={"output_file": deob / "03_enhanced_renamed.js"}, stats={"status": "ok"},
    )
    res = ReconstructionStage(use_project_reconstructor=True)._execute_js(ctx, 0.0)
    assert res.stats["reconstruction_mode"] == "project_reconstructor"
    assert res.stats["project_modules_parse_ok"] == 11
    assert res.stats["project_modules_parse_failed"] == 1
    assert any("lib/x.js" in e for e in res.errors)
