"""P20 kalem 4 — BICIM-12: üretilen proje analiz edilen kodu çalıştırmayı önermesin.

Önce (d2f205d, ürünün örneği): `project/README.md` "## Quick Start / npm install /
npm start" diyordu; Dockerfile `npm ci --only=production` (kilit dosyası yok,
uyarısız); giriş bulunamazsa hedefle ilgisiz `console.log("Reconstructed project -
ready for development")` yazılıyordu; sürüm 25 yerde sabit "Karadul v1.0" ve
var olmayan `https://github.com/karadul` bağlantısı.
Sonra: README başında "çalıştırmayın" uyarısı, Quick Start yok; Dockerfile
paket betikleri kapalı + `--network none` uyarısı; uydurma giriş yok (hata
listesinde "giriş bulunamadı"); sürüm `karadul.__version__`; ad hattının son
çıktısı (``named_source``) verilirse giriş odur.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import karadul
from karadul.config import Config
from karadul.core.target import Language, TargetInfo, TargetType
from karadul.core.workspace import Workspace
from karadul.reconstruction.project_builder import ProjectBuilder
from karadul.reconstruction.project_reconstructor import ProjectReconstructor


@pytest.fixture
def target(tmp_path: Path) -> TargetInfo:
    src = tmp_path / "bundle.min.js"
    src.write_text("var a=1;\n", encoding="utf-8")
    return TargetInfo(path=src, name="bundle", target_type=TargetType.JS_BUNDLE,
                      language=Language.JAVASCRIPT, file_size=src.stat().st_size,
                      file_hash="0" * 64)


@pytest.fixture
def workspace(tmp_path: Path) -> Workspace:
    ws = Workspace(base_dir=tmp_path / "ws", target_name="bundle")
    ws.create()
    return ws


def _assert_no_run_advice(readme: str) -> None:
    assert "Quick Start" not in readme
    assert "\nnpm start\n" not in readme
    assert "\nnpm install\n" not in readme
    assert "Do not run this code / Bu kodu çalıştırmayın" in readme
    assert "Karadul v1.0" not in readme
    assert "github.com/karadul" not in readme
    assert f"Karadul {karadul.__version__}" in readme


def test_builder_readme_warns_instead_of_quick_start(workspace, target):
    (workspace.get_stage_dir("deobfuscated") / "app.js").write_text("run();\n")
    result = ProjectBuilder(Config()).build(workspace, target)
    _assert_no_run_advice((result.project_dir / "README.md").read_text(encoding="utf-8"))


def test_builder_dockerfile_disables_scripts_and_warns(workspace, target):
    (workspace.get_stage_dir("deobfuscated") / "app.js").write_text("run();\n")
    result = ProjectBuilder(Config()).build(workspace, target)
    docker = (result.project_dir / "Dockerfile").read_text(encoding="utf-8")
    assert "npm install --ignore-scripts" in docker
    assert "npm ci" not in docker
    assert "--network none" in docker
    assert "ANALYZED (untrusted" in docker


def test_builder_does_not_invent_entry_point(workspace, target):
    result = ProjectBuilder(Config()).build(workspace, target)
    assert result.entry_point is None
    assert not (result.project_dir / "src" / "index.js").exists()
    assert "Dockerfile" not in result.files_created
    assert any("Giriş dosyası bulunamadı" in e for e in result.errors)
    pkg = json.loads((result.project_dir / "package.json").read_text(encoding="utf-8"))
    assert "main" not in pkg and "scripts" not in pkg
    readme = (result.project_dir / "README.md").read_text(encoding="utf-8")
    assert "no entry point could be identified" in readme


def test_builder_prefers_named_source(workspace, target, tmp_path):
    (workspace.get_stage_dir("deobfuscated") / "webpack_modules").mkdir()
    (workspace.get_stage_dir("deobfuscated") / "webpack_modules" / "module_0.js").write_text(
        "(function (e, t, n) { n(1); });\n"
    )
    named = tmp_path / "00_original.nsa_named.typed.commented.js"
    named.write_text("const fileSystem = require('fs');\n", encoding="utf-8")
    result = ProjectBuilder(Config()).build(workspace, target, named_source=named)
    entry = (result.project_dir / "src" / "index.js").read_text(encoding="utf-8")
    assert "const fileSystem = require('fs');" in entry
    assert "named output 00_original.nsa_named.typed.commented.js" in entry
    assert "(function (e, t, n)" not in entry


def test_reconstructor_readme_warns_instead_of_quick_start(target, tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    readme = ProjectReconstructor._generate_readme(project, target, {}, {"src/api": 2}, 2)
    _assert_no_run_advice(readme.read_text(encoding="utf-8"))
