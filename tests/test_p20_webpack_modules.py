"""P20 kalem 1 — BICIM-01 + MEK-12: çıkarılan webpack modülleri ayrıştırılabilir olmalı.

Önce (d2f205d): `smart-webpack-unpack.mjs` modül düğümünü (paket nesnesindeki
`function (e, t, n) {...}`) tek başına dosyaya yazıyordu; adsız `function (`
deyimi geçersiz JS → ürünün kendi örneğinde 3/3 modül `node --check`'te
"Function statements require a function name", Electron Fiddle'ın gerçek
`renderer/816/index.js` paketinde 17/17, `main/index.js`'te 2/10 bozuk. İkinci ad
geçişi (module_rename) 3/3 başarısızdı.

Sonra: modül ifade deyimi olarak yazılıyor (`(function (e, t, n) {...});`),
nesne yöntemi (`0(e, t, n) {...}`) adsız işlev ifadesine çevriliyor; betik her
modülü Babel'le (hata kurtarmasız) sınayıp ``modules_parse_ok`` /
``modules_parse_failed`` sayıyor; Python hattı ayrıştırılamayanı "kısmi" sayıp
adıyla bildiriyor.

Testler iki bağımsız ayrıştırıcı kullanır: betiğin kendi Babel sınaması ve V8
(`node --check`).
"""

from __future__ import annotations

import json
import shutil
import subprocess
import time
from pathlib import Path

import pytest

from karadul.config import Config
from karadul.core.pipeline import PipelineContext
from karadul.core.subprocess_runner import SubprocessResult
from karadul.core.target import Language, TargetInfo, TargetType
from karadul.core.workspace import Workspace
from karadul.deobfuscators.deep_pipeline import (
    STATUS_PARTIAL,
    DeepDeobfuscationPipeline,
)
from karadul.stages import DeobfuscationStage

_FIXTURE_JS = Path(__file__).parent / "fixtures" / "sample_minified.js"
_SCRIPTS = Config().scripts_dir
_UNPACK = _SCRIPTS / "smart-webpack-unpack.mjs"

# webpack 4 dizi biçimi: iki klasik `function` modülü + bir ok işlevi modülü.
_WP4_ARRAY = (
    '!function(e){var t={};function n(r){if(t[r])return t[r].exports;'
    'var o=t[r]={i:r,l:!1,exports:{}};return e[r].call(o.exports,o,o.exports,n),'
    'o.l=!0,o.exports}n(0)}([function(e,t,n){"use strict";var r=n(1);'
    'console.log(r.a("x"))},function(e,t){t.a=function(e){return "Hello "+e}},'
    '(e,t)=>{t.b=1}]);\n'
)
# Nesne biçimi: nesne yöntemi (`0(e,t,n){}`), ok işlevi ve dizgi anahtarlı işlev.
_WP_OBJECT_METHOD = (
    '(function(modules){function __webpack_require__(id){var m={exports:{}};'
    'modules[id](m,m.exports,__webpack_require__);return m.exports}'
    '__webpack_require__(0)})({0(e,t,n){var r=n(1);console.log(r.x)},'
    '1:(e,t)=>{t.x=42},"./src/a.js":function(module,exports){'
    'exports.y=function(){return 2}}});\n'
)


def _node_ok() -> bool:
    return (
        shutil.which("node") is not None
        and _UNPACK.exists()
        and (_SCRIPTS / "node_modules").is_dir()
    )


needs_node = pytest.mark.skipif(not _node_ok(), reason="node ya da scripts/node_modules yok")


def _unpack(tmp_path: Path, source: str) -> tuple[dict, list[Path]]:
    src = tmp_path / "bundle.js"
    src.write_text(source, encoding="utf-8")
    out = tmp_path / "out"
    proc = subprocess.run(
        ["node", str(_UNPACK), str(src), str(out)],
        capture_output=True, text=True, timeout=120,
    )
    payload = json.loads(proc.stdout.strip().splitlines()[-1])
    return payload, sorted((out / "modules").glob("*.js"))


def _node_check(path: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["node", "--check", str(path)], capture_output=True, text=True, timeout=60,
    )


@needs_node
@pytest.mark.parametrize(
    ("source", "expected_format", "expected_modules"),
    [
        (_FIXTURE_JS.read_text(encoding="utf-8"), "webpack_object", 3),
        (_WP4_ARRAY, "webpack_array", 3),
        (_WP_OBJECT_METHOD, "webpack_object", 3),
    ],
    ids=["urun_ornegi", "wp4_dizi", "nesne_yontemi"],
)
def test_every_extracted_module_parses(tmp_path, source, expected_format, expected_modules):
    payload, modules = _unpack(tmp_path, source)
    assert payload["bundle_format"] == expected_format
    assert payload["total_modules"] == expected_modules == len(modules)
    # V8 (bağımsız ayrıştırıcı): her modül geçerli JS.
    for mf in modules:
        proc = _node_check(mf)
        assert proc.returncode == 0, f"{mf.name}: {proc.stderr[-300:]}"
    # Betiğin kendi sayacı gerçeği söylüyor ve toplamı tutuyor.
    assert payload["modules_parse_ok"] == expected_modules
    assert payload["modules_parse_failed"] == 0
    assert payload["parse_failed_modules"] == []
    assert all(m["parse_ok"] is True for m in payload["modules"])


@needs_node
def test_module_body_is_preserved_not_invented(tmp_path):
    """Sarmalama gövdeyi değiştirmez: özgün dizgi ve çağrılar modülde durur."""
    _, modules = _unpack(tmp_path, _FIXTURE_JS.read_text(encoding="utf-8"))
    by_name = {m.name: m.read_text(encoding="utf-8") for m in modules}
    assert "Welcome to __webpack_require__ land." in by_name["module_1.js"]
    assert "maxRetries: 3" in by_name["module_2.js"]
    m0 = by_name["module_0.js"]
    assert "(function (e, t, n) {" in m0
    assert m0.rstrip().endswith("});")
    # Sürüm uydurulmuyor (eskiden sabit "Karadul v1.0").
    assert "Karadul v1.0" not in m0


@needs_node
def test_object_method_module_becomes_function_expression(tmp_path):
    _, modules = _unpack(tmp_path, _WP_OBJECT_METHOD)
    m0 = next(m for m in modules if m.name == "module_0.js").read_text(encoding="utf-8")
    assert "(function (e, t, n) {" in m0
    assert "0(e, t, n)" not in m0


@needs_node
def test_unparseable_module_is_counted_and_named(tmp_path):
    """Ayrıştırılamayan modül sayılır ve adıyla bildirilir (sessiz bozuk dosya yok).

    Girdi Babel'in hata kurtarmasıyla ayrışan ama geçersiz bir dosya: aynı
    `let` adı iki kez. Paket yapısı yok → betik üst düzey parça yazar; parça
    hata kurtarmasız ayrıştırılamaz (V8 de reddeder).
    """
    padding = "".join(
        f'var paddingValue{k} = "uzun bir dizgi değeri, parça 200 baytı aşsın";\n'
        for k in range(40)
    )
    payload, modules = _unpack(tmp_path, "let dup = 1;\nlet dup = 2;\n" + padding)
    assert len(modules) >= 1
    assert payload["modules_parse_failed"] >= 1
    assert payload["modules_parse_ok"] + payload["modules_parse_failed"] == len(modules)
    failed = {m["file"] for m in payload["parse_failed_modules"]}
    assert failed
    for name in failed:
        assert _node_check(tmp_path / "out" / "modules" / name).returncode != 0
    flags = {m["file"]: m["parse_ok"] for m in payload["modules"]}
    assert all(flags[name] is False for name in failed)


# ---------------------------------------------------------------------------
# Python hattı: betiğin ayrıştırma sayacı adıma ve istatistiğe dürüstçe yansır
# ---------------------------------------------------------------------------

class _UnpackOnlyRunner:
    def __init__(self, payload: dict) -> None:
        self.payload = payload

    def run_command(self, cmd, timeout=None, cwd=None, env=None):  # noqa: ARG002
        return SubprocessResult(
            success=True, returncode=0, stdout=json.dumps(self.payload),
            stderr="", parsed_json=self.payload,
        )


def _step(tmp_path: Path, payload: dict) -> dict:
    pipe = DeepDeobfuscationPipeline(Config())
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    (scripts / "smart-webpack-unpack.mjs").write_text("// sahte\n")
    pipe._scripts_dir = scripts
    pipe._runner = _UnpackOnlyRunner(payload)
    return pipe._step_smart_unpack(tmp_path / "in.js", tmp_path / "out")


def test_step_reports_unparseable_modules_as_partial(tmp_path):
    step = _step(tmp_path, {
        "success": True, "total_modules": 5, "bundle_format": "webpack_array",
        "errors": [], "modules_parse_ok": 3, "modules_parse_failed": 2,
        "parse_failed_modules": [
            {"file": "module_3.js", "error": "Unexpected token (12:9)"},
            {"file": "module_4.js", "error": "Unexpected token (1:1)"},
        ],
    })
    assert step["success"] is True
    assert step["partial"] is True
    assert step["modules_parse_ok"] == 3
    assert step["modules_parse_failed"] == 2
    assert "2/5 modül ayrıştırılamıyor" in step["error"]
    assert "module_3.js" in step["error"]
    assert [m["file"] for m in step["parse_failed_modules"]] == ["module_3.js", "module_4.js"]


def test_step_all_parseable_is_not_partial(tmp_path):
    step = _step(tmp_path, {
        "success": True, "total_modules": 3, "bundle_format": "webpack_object",
        "errors": [], "modules_parse_ok": 3, "modules_parse_failed": 0,
        "parse_failed_modules": [],
    })
    assert step["success"] is True
    assert "partial" not in step and "error" not in step
    assert step["modules_parse_failed"] == 0


def test_step_without_counter_does_not_invent_zero(tmp_path):
    """Sayaç yoksa (eski betik) 0 uydurulmaz: anahtar hiç yazılmaz."""
    step = _step(tmp_path, {
        "success": True, "total_modules": 3, "bundle_format": "webpack_object",
        "errors": [],
    })
    assert "modules_parse_failed" not in step
    assert "modules_parse_ok" not in step


# ---------------------------------------------------------------------------
# Uçtan uca (gerçek node araç zinciri): ürünün kendi örneği
# ---------------------------------------------------------------------------

def _real_ctx(base: Path) -> PipelineContext:
    base.mkdir(parents=True, exist_ok=True)
    src = base / "sample.js"
    src.write_bytes(_FIXTURE_JS.read_bytes())
    ws = Workspace(base_dir=base / "ws", target_name="t")
    ws.create()
    target = TargetInfo(path=src, name="t", target_type=TargetType.JS_BUNDLE,
                        language=Language.JAVASCRIPT, file_size=src.stat().st_size,
                        file_hash="0" * 64)
    return PipelineContext(target=target, workspace=ws, config=Config())


@needs_node
def test_sample_second_pass_now_renames_all_modules(tmp_path):
    """MEK-12: örnekte module_rename 3/3 başarısızdı; şimdi 3/3 ve modüller geçerli."""
    ctx = _real_ctx(tmp_path)
    sr = DeobfuscationStage()._execute_deep(ctx, time.monotonic())
    steps = sr.stats["steps"]
    unpack = steps["smart_unpack"]
    assert unpack["modules_parse_ok"] == 3
    assert unpack["modules_parse_failed"] == 0
    rename = steps["module_rename"]
    assert rename["renamed_count"] == 3
    assert "failed_count" not in rename
    mods = sorted((ctx.workspace.get_stage_dir("deobfuscated")
                   / "webpack_modules" / "modules").glob("*.js"))
    assert len(mods) == 3
    for mf in mods:
        assert _node_check(mf).returncode == 0, mf.name
    assert sr.stats["status"] != STATUS_PARTIAL or not any(
        "module_rename" in w for w in sr.stats.get("warnings", [])
    )
