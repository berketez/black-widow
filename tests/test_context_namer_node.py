"""context_namer JS isimlendirme hattının gerçek node + Babel ile uçtan uca testleri.

Hat:
    ContextNamer.analyze() -> scripts/context-analyzer.mjs (Babel AST bağlam analizi -> JSON)
    ContextNamer.apply()   -> scripts/apply-names.mjs      (scope-aware yeniden adlandırma)

Bu hattı çalıştıran bir test yoktu; script'lerdeki eski mutlak yol (810b4ca) ve
hiç çalışmayan Scope yedek dalı (ee494a8) bu yüzden fark edilmemişti. Buradaki
testler node'u gerçekten çalıştırır; node ya da scripts/node_modules içindeki
Babel paketleri yoksa modül tümüyle atlanır.

Kapsam:
    (a) Python API ile uçtan uca beklenen yeniden adlandırmalar
    (b) min_confidence eşiği (eşiğe eşit güven dahil sınır durumları)
    (c) çıktı JS'in sözdizimsel geçerliliği (node --check)
    (d) iç içe scope'larda aynı kısa ad: her binding kendi bağlamından ad alır,
        referans çözümü (hangi ad hangi binding'e bağlı) korunur
    (e) Scope yedek dalı (lib/scope/index.js doğrudan import): hem blok düzeyinde
        hem de ana dal devre dışıyken script'lerin kendisiyle; scope-aware yol
        çöküp flat yedeğe düşünce tek rapor satırı
    (f) Babel'in "Duplicate declaration" verdiği girdilerde hattın çökmemesi
    (g) Anlam korunumu: yeniden bildirim, destructuring atama, for-init tekrarı,
        metod/static blok scope'ları, ayrılmış sözcük önerileri, export edilen
        bildirimler (node --check + alfa-denklik + çalıştırma sonucu)

Eskiden xfail(strict=True) ile belgelenen kusurlar (ad yakalama, blok scope'ları,
kanıtın binding'e ulaşmaması, prototip anahtarları) düzeltildi; testleri artık
normal regresyon testidir.
"""

from __future__ import annotations

import json
import math
import re
import shutil
import subprocess
import urllib.parse
from collections.abc import Callable
from pathlib import Path

import pytest

from karadul.config import Config
from karadul.reconstruction.context_namer import ContextNamer, NamingResult

_CONFIG = Config()
_SCRIPTS_DIR = _CONFIG.scripts_dir.resolve()
_ANALYZER = _SCRIPTS_DIR / "context-analyzer.mjs"
_APPLIER = _SCRIPTS_DIR / "apply-names.mjs"
# createRequire için taban: dosyanın var olması gerekmez, yalnız dizini önemli.
_REQUIRE_BASE = str(_SCRIPTS_DIR / "noop.js")
_NODE = shutil.which(str(_CONFIG.tools.node))
_BABEL_PACKAGES = ("parser", "traverse", "generator", "types")
_NODE_TIMEOUT_S = 60
# ContextNamer'ın varsayılan eşiği (Config.min_confidence.context_namer, 0.1);
# testler bunu açıkça verir.
_MIN_CONFIDENCE = _CONFIG.min_confidence.context_namer
_WEBPACK_FIXTURE = Path(__file__).parent / "fixtures" / "sample_minified.js"

if _NODE is None:
    pytest.skip("node bulunamadı (Config.tools.node)", allow_module_level=True)
_MISSING = [
    p for p in _BABEL_PACKAGES
    if not (_SCRIPTS_DIR / "node_modules" / "@babel" / p / "package.json").is_file()
]
if _MISSING:
    pytest.skip(
        f"scripts/node_modules içinde eksik paket: {['@babel/' + p for p in _MISSING]}",
        allow_module_level=True,
    )


# ---------------------------------------------------------------------------
# Girdiler
# ---------------------------------------------------------------------------

_SAMPLE_JS = (
    'var a = require("fs");\n'
    'function b(c) { var d = a.readFileSync(c, "utf-8"); return d.length; }\n'
    "module.exports = b;\n"
)
# Anahtar biçimi apply-names.mjs'nin mappings'i: "<scopeId>::<eski ad>".
_SAMPLE_ALL = {
    "program@1:0::a": "fileSystem",   # require kaynağı, güven 0.5
    "b@2:0::c": "filePath",           # readFileSync 0. argüman, güven tam 0.2
    "b@2:0::d": "fileContent",        # readFileSync dönüşü + .length, güven ~0.3
}

_NESTED_JS = """\
var a = require("fs");
var b = require("path");
function c(d) {
  var e = a.readFileSync(d, "utf-8");
  function f(a) {
    var b = new Map();
    b.set("size", a.length);
    return b;
  }
  return f(e).get("size") + b.basename(d).length;
}
module.exports = c;
"""

# Yamasız Babel scope'unun "Duplicate declaration" fırlattığı, pre-process'in
# (duplicate var -> atama dönüşümü) ise DÜZELTMEDİĞİ girdiler: yalnız
# Scope.registerBinding yaması hattı ayakta tutar.
_DUP_CASES = {
    "param-let": 'function f(a) { let a = require("fs"); return a; }\nmodule.exports = f;\n',
    "let-function": 'let a = require("fs");\nfunction a() {}\nmodule.exports = a;\n',
    "pattern-const": 'const { a } = require("fs");\nconst a = 2;\nmodule.exports = a;\n',
}


def _webpack_source() -> str:
    return _WEBPACK_FIXTURE.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# Node yardımcıları
# ---------------------------------------------------------------------------

def _precondition(ok: bool, message: str) -> None:
    """Senaryo kurulamazsa pytest.fail (AssertionError değil): kurulamayan senaryo kusurla karışmaz."""
    if not ok:
        pytest.fail(message)


def _run_node(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [_NODE, *args],
        capture_output=True,
        text=True,
        timeout=_NODE_TIMEOUT_S,
        check=False,
    )


def _json_lines(stdout: str) -> list[dict]:
    return [json.loads(line) for line in stdout.splitlines() if line.startswith("{")]


def _node_json(*args: str) -> dict:
    """node'u çalıştır, stdout'taki son JSON satırını döndür (altyapı hatasında fail)."""
    proc = _run_node(*args)
    if proc.returncode != 0:
        pytest.fail(f"node başarısız (rc={proc.returncode}): {proc.stderr[-2000:]}")
    lines = _json_lines(proc.stdout)
    if not lines:
        pytest.fail(f"node JSON üretmedi: {proc.stdout[-500:]!r}")
    return lines[-1]


def _applied(mappings: dict) -> dict[str, str]:
    """apply-names mappings'ini {anahtar: yeni ad} biçimine indir.

    Scope-aware kip: {"<scope>::<ad>": {"from": .., "to": ..}}; flat kip: {"<ad>": "<yeni>"}.
    """
    return {k: (v["to"] if isinstance(v, dict) else v) for k, v in mappings.items()}


# Alfa-denklik: iki programın Identifier dizisi aynı sırada olmalı ve her
# değişken adı aynı binding'e (ya da aynı global'e) çözülmeli; özellik adları
# değişmemeli. Yeniden adlandırma yalnız binding adlarını değiştirebilir.
_ALPHA_EQ_JS = r"""
const { createRequire } = require("node:module");
const fs = require("node:fs");
const [requireBase, origFile, renamedFile] = process.argv.slice(1);
const req = createRequire(requireBase);
const { parse } = req("@babel/parser");
const traverse = req("@babel/traverse").default;

function signature(file) {
  const ast = parse(fs.readFileSync(file, "utf-8"), {
    sourceType: "unambiguous", allowReturnOutsideFunction: true,
  });
  const paths = [];
  const index = new Map();
  traverse(ast, { Identifier(p) { index.set(p.node, paths.length); paths.push(p); } });
  return paths.map((p) => {
    const name = p.node.name;
    // `export { a as b }`: b modülün dış adıdır, binding değil (Babel onu binding kimliği sayar)
    if (p.parentPath.isExportSpecifier() && p.key === "exported") return { sig: "export:" + name, name };
    // `t: for (...)`: etiket ayrı bir ad alanıdır (Babel onu da binding kimliği sayar)
    if (p.parentPath.isLabeledStatement() && p.key === "label") return { sig: "label:" + name, name };
    if (!(p.isReferencedIdentifier() || p.isBindingIdentifier())) return { sig: "name:" + name, name };
    let binding = null;
    if (p.isBindingIdentifier()) {
      // function f(f) {} gibi durumlarda bildirim kimliği iç scope'ta değil dışta kayıtlı
      for (let s = p.scope; s && !binding; s = s.parent) {
        const own = s.getOwnBinding(name);
        if (own && own.identifier === p.node) binding = own;
      }
    }
    if (!binding) binding = p.scope.getBinding(name);
    if (!binding) return { sig: "global:" + name, name };
    const at = index.has(binding.identifier) ? index.get(binding.identifier) : "?" + name;
    return { sig: "binding#" + at, name };
  });
}

const a = signature(origFile);
const b = signature(renamedFile);
const diffs = [];
for (let i = 0; i < Math.max(a.length, b.length); i++) {
  if (!a[i] || !b[i] || a[i].sig !== b[i].sig) diffs.push({ index: i, original: a[i] ?? null, renamed: b[i] ?? null });
}
const renamed = {};
for (let i = 0; i < Math.min(a.length, b.length); i++) {
  if (a[i].name !== b[i].name) renamed[a[i].sig] = [a[i].name, b[i].name];
}
process.stdout.write(JSON.stringify({
  equal: a.length === b.length && diffs.length === 0,
  counts: [a.length, b.length], diffs: diffs.slice(0, 10), renamed,
}) + "\n");
"""


def _alpha_equivalence(original: Path, renamed: Path) -> dict:
    return _node_json("-e", _ALPHA_EQ_JS, _REQUIRE_BASE, str(original), str(renamed))


_CALL_EXPORT_JS = "console.log(JSON.stringify(require(process.argv[1])(process.argv[2])));"


def _call_export(module: Path, arg: str) -> object:
    proc = _run_node("-e", _CALL_EXPORT_JS, str(module), arg)
    if proc.returncode != 0:
        pytest.fail(f"{module.name} çalıştırılamadı: {proc.stderr[-1000:]}")
    return json.loads(proc.stdout)


# Yamasız Babel: parse(errorRecovery) + scope'lu traverse. Hata mesajını döndürür.
_RAW_BABEL_JS = r"""
const { createRequire } = require("node:module");
const req = createRequire(process.argv[1]);
const { parse } = req("@babel/parser");
const traverse = req("@babel/traverse").default;
const ast = parse(process.argv[2], { sourceType: "unambiguous", errorRecovery: true });
let error = null;
try { traverse(ast, { Identifier() {} }); } catch (err) { error = String(err && err.message); }
process.stdout.write(JSON.stringify({ error }) + "\n");
"""


def _raw_babel_error(source: str) -> str | None:
    return _node_json("-e", _RAW_BABEL_JS, _REQUIRE_BASE, source)["error"]


# ---------------------------------------------------------------------------
# Fixture'lar
# ---------------------------------------------------------------------------

PipelineRun = tuple[NamingResult, Path, Path]


@pytest.fixture(scope="module")
def run_pipeline(tmp_path_factory: pytest.TempPathFactory) -> Callable[..., PipelineRun]:
    """ContextNamer.analyze_and_rename'i çalıştır; aynı girdi+eşik modül içinde bir kez koşar."""
    cache: dict[tuple[str, str, float], PipelineRun] = {}

    def _run(name: str, source: str, min_confidence: float = _MIN_CONFIDENCE) -> PipelineRun:
        key = (name, source, min_confidence)
        if key not in cache:
            work = tmp_path_factory.mktemp(f"cn_{name}")
            inp = work / f"{name}.js"
            inp.write_text(source, encoding="utf-8")
            out = work / f"{name}.named.js"
            namer = ContextNamer(_CONFIG, min_confidence=min_confidence)
            cache[key] = (namer.analyze_and_rename(inp, out), inp, out)
        return cache[key]

    return _run


@pytest.fixture(scope="module")
def sample_context(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, dict]:
    """Örnek girdinin analizör çıktısı (eşik testleri aynı analizi paylaşır)."""
    inp = tmp_path_factory.mktemp("cn_threshold") / "sample.js"
    inp.write_text(_SAMPLE_JS, encoding="utf-8")
    return inp, ContextNamer(_CONFIG).analyze(inp)


# ---------------------------------------------------------------------------
# (a) Python API ile uçtan uca
# ---------------------------------------------------------------------------

def test_python_api_renames_sample_end_to_end(run_pipeline) -> None:
    res, inp, out = run_pipeline("sample", _SAMPLE_JS)

    assert res.success, res.errors
    assert res.errors == []
    assert res.context_json is not None and res.context_json["scope_aware"] is True
    assert res.output_file == out
    assert _applied(res.mappings) == _SAMPLE_ALL
    assert res.variables_renamed == len(_SAMPLE_ALL)

    text = out.read_text(encoding="utf-8")
    assert re.search(r'\bvar fileSystem = require\("fs"\)', text), text
    assert re.search(r"\bfunction b\(filePath\)", text), text
    assert re.search(
        r'\bvar fileContent = fileSystem\.readFileSync\(filePath, "utf-8"\)', text
    ), text
    assert re.search(r"\breturn fileContent\.length\b", text), text
    assert re.search(r"\bmodule\.exports = b\b", text), text

    # Davranış korunur: iki modül aynı dosyayı okuyup aynı uzunluğu döndürür.
    assert _call_export(out, str(inp)) == _call_export(inp, str(inp)) == len(_SAMPLE_JS)


# ---------------------------------------------------------------------------
# (b) min_confidence eşiği
# ---------------------------------------------------------------------------

def test_sample_confidences_behind_threshold_cases(sample_context) -> None:
    """Eşik testlerinin dayanağı: a=0.5 ve c=0.2 tam, d ≈ 0.3 (float toplamı ≥ 0.3)."""
    _, ctx = sample_context
    conf = {f"{r['scopeId']}::{r['originalName']}": r["confidence"] for r in ctx["scope_renames"]}
    assert conf["program@1:0::a"] == 0.5
    assert conf["b@2:0::c"] == 0.2
    assert 0.3 <= conf["b@2:0::d"] < 0.31
    # Geri kalan öneriler (tek harf yedeği vb.) en düşük test eşiğinin de altında.
    others = {k: v for k, v in conf.items() if k not in _SAMPLE_ALL}
    assert others and all(v < _MIN_CONFIDENCE for v in others.values()), others


@pytest.mark.parametrize(
    ("threshold", "expected_keys"),
    [
        pytest.param(0.1, ("program@1:0::a", "b@2:0::c", "b@2:0::d"), id="0.1-all"),
        # "bu değerin altındaki öneriler uygulanmaz": güveni eşiğe EŞİT olan c uygulanır
        pytest.param(0.2, ("program@1:0::a", "b@2:0::c", "b@2:0::d"), id="0.2-equal-to-c"),
        pytest.param(0.3, ("program@1:0::a", "b@2:0::d"), id="0.3-drops-c"),
        pytest.param(0.5, ("program@1:0::a",), id="0.5-equal-to-a"),
        pytest.param(0.51, (), id="0.51-none"),
    ],
)
def test_min_confidence_threshold_selects_renames(
    sample_context, tmp_path: Path, threshold: float, expected_keys: tuple[str, ...]
) -> None:
    inp, ctx = sample_context
    out = tmp_path / "out.js"

    result = ContextNamer(_CONFIG, min_confidence=threshold).apply(inp, ctx, out)

    assert result["success"] is True
    assert result["errors"] == []
    assert result["min_confidence"] == threshold  # Python -> --min-confidence -> parseFloat
    expected = {k: _SAMPLE_ALL[k] for k in expected_keys}
    assert _applied(result["mappings"]) == expected
    assert result["renamed"] == len(expected)

    text = out.read_text(encoding="utf-8")
    for key, new_name in _SAMPLE_ALL.items():
        present = re.search(rf"\b{new_name}\b", text) is not None
        assert present == (key in expected), (key, text)


# ---------------------------------------------------------------------------
# (c) Çıktı geçerli JS
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("case", ["sample", "nested", "webpack"])
def test_output_is_valid_javascript(run_pipeline, case: str) -> None:
    source = {"sample": _SAMPLE_JS, "nested": _NESTED_JS, "webpack": None}[case]
    res, inp, out = run_pipeline(case, source if source is not None else _webpack_source())

    assert res.success and res.errors == [], res.errors
    assert res.variables_renamed > 0
    assert out.read_text(encoding="utf-8") != inp.read_text(encoding="utf-8")

    check = _run_node("--check", str(out))
    assert check.returncode == 0, check.stderr


# ---------------------------------------------------------------------------
# (d) Scope-aware davranış
# ---------------------------------------------------------------------------

def test_nested_scopes_same_short_name_get_separate_names(run_pipeline) -> None:
    """Dış a/b (fs/path) ile iç a/b (parametre/Map) ayrı binding'ler: ayrı ad almalı."""
    res, inp, out = run_pipeline("nested", _NESTED_JS)
    assert res.success and res.errors == [], res.errors
    applied = _applied(res.mappings)

    assert applied["program@1:0::a"] == "fileSystem"
    assert applied["program@1:0::b"] == "pathUtils"
    assert applied["f@5:2::b"] == "mapInstance"
    assert "f@5:2::a" in applied, applied
    assert applied["f@5:2::a"] not in ("a", applied["program@1:0::a"])

    eq = _alpha_equivalence(inp, out)
    assert eq["equal"], eq
    assert _call_export(out, str(inp)) == _call_export(inp, str(inp))


def test_webpack_bundle_shadowing_preserved(run_pipeline) -> None:
    """Gerçek webpack önyükleyicisi: e/t/n/r/o iç içe tekrar tekrar gölgeleniyor."""
    res, inp, out = run_pipeline("webpack", _webpack_source())
    assert res.success and res.errors == [], res.errors
    assert res.variables_renamed > 0

    eq = _alpha_equivalence(inp, out)
    assert eq["equal"], eq

    before, after = _run_node(str(inp)), _run_node(str(out))
    assert before.returncode == after.returncode == 0, (before.stderr, after.stderr)
    assert after.stdout == before.stdout != ""


# (kaynak, dış binding anahtarı, iç binding anahtarı, önce adlandırılan).
# İç fonksiyon dış binding'e başvuruyor; analizör ikisine de AYNI adı öneriyor.
_CAPTURE_CASES = {
    # iç d (0.75) önce adlandırılır; dış a (0.6) aynı adı isteyince iç fonksiyondaki
    # a.set referansı iç binding'e bağlanırdı (ad tablosu: iç scope'ta yeni ad var)
    "inner-renamed-first": (
        "var a = new Map();\n"
        "function b(c) {\n"
        "  var d = new Map();\n"
        "  d.set(c, 1);\n"
        "  a.set(c, 2);\n"
        "  return d.get(c) + d.size;\n"
        "}\n"
        "module.exports = function (k) { return [b(k), a.get(k)]; };\n",
        "program@1:0::a",
        "b@2:0::d",
        "b@2:0::d",
    ),
    # güvenler eşit (0.5); önce Program scope'u (dış a) adlandırılır; iç d aynı adı
    # alsaydı iç fonksiyondaki `a === d` referansını yakalardı (dış yakalama)
    "outer-renamed-first": (
        'var a = require("fs");\n'
        "function b(c) {\n"
        '  var d = require("fs");\n'
        "  return a === d && c;\n"
        "}\n"
        "module.exports = b;\n",
        "program@1:0::a",
        "b@2:0::d",
        "program@1:0::a",
    ),
}


@pytest.mark.parametrize("case", sorted(_CAPTURE_CASES))
def test_rename_does_not_capture_outer_reference(run_pipeline, case: str) -> None:
    """İki binding aynı adı isteyince ikincisi çakışmasız sonek alır ya da atlanır.

    Hiçbir referans başka binding'e bağlanmamalı (alfa-denklik) ve davranış
    korunmalı. Eski kusur: iç fonksiyondaki dış referans iç binding'e bağlanıyordu
    (inner-renamed-first: [2, 2] -> [3, null]); node --check yine de geçiyordu.
    """
    source, outer_key, inner_key, first_key = _CAPTURE_CASES[case]
    res, inp, out = run_pipeline(f"capture_{case}", source)
    _precondition(res.success and res.errors == [], f"hat başarısız: {res.errors}")
    suggested = {f"{r['scopeId']}::{r['originalName']}": r for r in res.context_json["scope_renames"]}
    second_key = inner_key if first_key == outer_key else outer_key
    first, second = suggested.get(first_key), suggested.get(second_key)
    _precondition(
        first is not None and second is not None
        and first["newName"] == second["newName"]
        and first["confidence"] >= second["confidence"] >= _MIN_CONFIDENCE,
        f"senaryo kurulamadı (iki binding'e aynı ad, bu sırayla önerilmeli): {first}, {second}",
    )
    name = first["newName"]

    applied = _applied(res.mappings)
    assert applied.get(first_key) == name, applied
    # ikinci rename ya sonek aldı ya atlandı (shadow_suffixed / shadow_skipped)
    assert applied.get(second_key) in {None, *(f"{name}_{i}" for i in range(1, 6))}, applied

    eq = _alpha_equivalence(inp, out)
    assert eq["equal"], f"referans başka binding'e bağlandı: {eq['diffs']}"
    assert _call_export(out, "k") == _call_export(inp, "k")


_BLOCK_SCOPE_CASES = {
    # if bloğundaki const, for-let sayacı, catch parametresi
    "statements": (
        """\
function g(x) {
  try {
    if (x) {
      const a = require("fs");
      return a.readFileSync(x, "utf-8");
    }
    for (let i = 0; i < 3; i++) { x += i; }
  } catch (e) {
    return e.message;
  }
  return x;
}
module.exports = g;
""",
        {("BlockStatement", "a"), ("ForStatement", "i"), ("CatchClause", "e")},
    ),
    # sınıfın özel metodunun parametresi, for-of değişkeni
    "private-method-for-of": (
        """\
class K {
  #m(a) { return a.length; }
  run(v) { let r = 0; for (const e of v) { r += this.#m(e); } return r; }
}
module.exports = (v) => new K().run(v);
""",
        {("ClassPrivateMethod", "a"), ("ForOfStatement", "e")},
    ),
}


@pytest.mark.parametrize("case", sorted(_BLOCK_SCOPE_CASES))
def test_block_scoped_bindings_are_renamed(run_pipeline, case: str) -> None:
    """Blok scope'lu binding'ler de yeniden adlandırılır.

    Eski kusur: apply-names PASS 1 yalnız Function/Program/ClassMethod/ObjectMethod
    scope'larını geziyordu; iç blokta let/const, for-let, for-of, catch parametresi,
    ClassPrivateMethod binding'leri analizör önerse de hiç uygulanmıyordu.
    """
    source, bindings = _BLOCK_SCOPE_CASES[case]
    res, inp, out = run_pipeline(f"block_scope_{case}", source)
    _precondition(res.success and res.errors == [], f"hat başarısız: {res.errors}")
    suggested = {
        f"{r['scopeId']}::{r['originalName']}": r["newName"]
        for r in res.context_json["scope_renames"]
        if (r["scopeId"].split("@")[0], r["originalName"]) in bindings
        and r["confidence"] >= _MIN_CONFIDENCE
    }
    _precondition(
        len(suggested) == len(bindings),
        f"analizör blok binding'lerinin hepsine öneri üretmedi: {suggested}",
    )

    applied = _applied(res.mappings)
    missing = {k: v for k, v in suggested.items() if applied.get(k) != v}
    assert not missing, f"uygulanmayan blok scope önerileri: {missing}"

    assert _alpha_equivalence(inp, out)["equal"]
    assert _call_export(out, "abc") == _call_export(inp, "abc")


_NESTED_USE_JS = (
    'var a = require("fs");\n'
    'function b(c) { if (c) { return a.readFileSync(c, "utf-8"); } return null; }\n'
    "module.exports = b;\n"
)


def test_evidence_from_nested_use_reaches_declaring_binding(run_pipeline) -> None:
    """İç bloktaki kullanımın kanıtı binding'in kendisine yazılır.

    Eski kusur: kanıt referansın bulunduğu scope'a yazılıyordu (getOrCreate ->
    getScopeId(path)); c'nin if bloğundaki kullanımı binding'i olmayan
    'BlockStatement@2:23::c' anahtarına düşüyor, asıl binding tek harf yedeğiyle
    'count' oluyordu.
    """
    res, inp, out = run_pipeline("nested_use", _NESTED_USE_JS)
    _precondition(res.success and res.errors == [], f"hat başarısız: {res.errors}")

    applied = _applied(res.mappings)
    assert applied.get("b@2:0::c") == "filePath", applied


_PROTOTYPE_CASES = {
    # özellik ipucu tablosu (PROPERTY_HINTS)
    "property-hint": (
        'function f(e) { return e.hasOwnProperty("then") ? e : null; }\n'
        "module.exports = f;\n"
    ),
    # metod dönüşü tablosu: önerilen ad Object.prototype.hasOwnProperty fonksiyonunun
    # kendisi oluyordu; aynı scope'taki ikincisi koda
    # "function hasOwnProperty() { [native code] }2" adıyla yazılıyordu
    "method-return": (
        "function f(e, t) { var r = e.hasOwnProperty(t), n = t.hasOwnProperty(e); return r && n; }\n"
        "module.exports = f;\n"
    ),
    # modül adı, typeof karşılaştırması ve çağrılan fonksiyon adı tabloları
    "require-typeof-call": (
        'var o = require("constructor");\n'
        'function g(e) { var x = toString(); return typeof e === "toString" ? e : x; }\n'
        "module.exports = g;\n"
    ),
}
_IDENTIFIER_RE = re.compile(r"[A-Za-z_$][\w$]*")


@pytest.mark.parametrize("case", sorted(_PROTOTYPE_CASES))
def test_prototype_property_name_does_not_poison_confidence(tmp_path: Path, case: str) -> None:
    """Object.prototype anahtarları kural tablolarında eşleşmez.

    Eski kusur: kural tabloları düz nesneydi; hasOwnProperty, constructor, toString
    gibi adlar Object.prototype'tan değer çekiyordu: güven NaN (JSON'da null),
    önerilen ad bir fonksiyon nesnesi (JSON'da kayıp) ya da fonksiyonun kaynak metni.
    """
    inp = tmp_path / "proto.js"
    inp.write_text(_PROTOTYPE_CASES[case], encoding="utf-8")
    ctx = ContextNamer(_CONFIG).analyze(inp)
    _precondition(bool(ctx["scope_renames"]), f"öneri yok: {ctx}")

    bad = [
        r for r in ctx["scope_renames"]
        if not isinstance(r["confidence"], (int, float)) or not math.isfinite(r["confidence"])
        or not isinstance(r.get("newName"), str) or not _IDENTIFIER_RE.fullmatch(r["newName"])
    ]
    assert not bad, bad

    out = tmp_path / "proto.named.js"
    result = ContextNamer(_CONFIG, min_confidence=_MIN_CONFIDENCE).apply(inp, ctx, out)
    assert result["success"] is True and result["errors"] == [], result
    check = _run_node("--check", str(out))
    assert check.returncode == 0, check.stderr


# ---------------------------------------------------------------------------
# (e) Scope yedek dalı
# ---------------------------------------------------------------------------

_FALLBACK_IMPORT = "node_modules/@babel/traverse/lib/scope/index.js"


def _fallback_block(script: Path) -> str:
    """Script'teki yedek dalın `try { ... } catch(_) {}` bloğunu olduğu gibi çıkar.

    import.meta.url, script'in kendi file URL'siyle değiştirilir; böylece göreli
    `./node_modules/...` yolu script'in yanındaki gerçek node_modules'a çözülür.
    """
    lines = script.read_text(encoding="utf-8").splitlines()
    hits = [i for i, line in enumerate(lines) if _FALLBACK_IMPORT in line and "import(" in line]
    _precondition(len(hits) == 1, f"{script.name}: yedek dal import satırı tek değil: {hits}")
    at = hits[0]
    start = next((j for j in range(at, -1, -1) if re.fullmatch(r"\s*try\s*\{\s*", lines[j])), None)
    end = next(
        (j for j in range(at, len(lines))
         if re.fullmatch(r"\s*\}\s*catch\s*\(\s*_\s*\)\s*\{\s*\}\s*", lines[j])),
        None,
    )
    _precondition(start is not None and end is not None, f"{script.name}: yedek blok bulunamadı")
    block = "\n".join(lines[start:end + 1])
    _precondition(block.count("import.meta.url") == 1, f"{script.name}: beklenmeyen blok:\n{block}")
    return block.replace("import.meta.url", json.dumps(script.resolve().as_uri()))


@pytest.mark.parametrize("script", [_ANALYZER, _APPLIER], ids=lambda p: p.name)
def test_scope_fallback_block_patches_real_scope_class(script: Path) -> None:
    """Yedek dal, gerçek node_modules'tan Scope sınıfını bulup registerBinding'i yamalamalı.

    Yama görünür olduysa blok içindeki ifade (S2) registerBinding'i olan ve
    @babel/traverse'in kullandığı sınıfın ta kendisini bulmuş demektir.
    """
    probe = "\n".join([
        'import { createRequire } from "node:module";',
        f"const require = createRequire({json.dumps(script.resolve().as_uri())});",
        'const Scope = require("@babel/traverse").Scope;',
        "const original = Scope.prototype.registerBinding;",
        _fallback_block(script),
        "const patched = Scope.prototype.registerBinding !== original;",
        'const { parse } = require("@babel/parser");',
        'const traverse = require("@babel/traverse").default;',
        "let error = null;",
        "try {",
        f"  traverse(parse({json.dumps(_DUP_CASES['param-let'])}, {{ errorRecovery: true }}),"
        " { Identifier() {} });",
        "} catch (err) { error = String(err?.message); }",
        'process.stdout.write(JSON.stringify({ scope: Scope.name, patched, error }) + "\\n");',
    ])

    got = _node_json("--input-type=module", "-e", probe)

    assert got["scope"] == "Scope"
    assert got["patched"] is True, f"{script.name}: yedek dal registerBinding'i yamalamadı"
    assert got["error"] is None, got["error"]


def _write_force_fallback_hook(directory: Path, *, block_direct_scope: bool = False) -> Path:
    """`--import` ile yüklenecek hook: script'lerin `@babel/traverse` import'u Scope'u
    dışa vermeyen bir shim'e yönlenir (yalnız default = traverse). Ana dal Scope'u
    bulamaz; yedek dal lib/scope/index.js'i göreli URL ile import ettiği için hook'a
    takılmadan gerçek sınıfa ulaşır.

    block_direct_scope=True: yedek dalın lib/scope/index.js import'u da boş bir
    modüle yönlenir; registerBinding hiç yamalanmaz ve "Duplicate declaration"
    scope'lu traverse'ü düşürür.
    """
    shim = "\n".join([
        'import { createRequire } from "node:module";',
        f"const require = createRequire({json.dumps(Path(_REQUIRE_BASE).as_uri())});",
        'process.stderr.write("[test-hook] @babel/traverse -> Scope vermeyen shim\\n");',
        'export default require("@babel/traverse").default;',
    ])
    hook = "\n".join([
        'import { registerHooks } from "node:module";',
        f"const SHIM = {json.dumps('data:text/javascript,' + urllib.parse.quote(shim))};",
        "const TARGET = /\\/(context-analyzer|apply-names)\\.mjs$/;",
        f"const BLOCK_DIRECT = {json.dumps(block_direct_scope)};",
        "registerHooks({",
        "  resolve(specifier, context, nextResolve) {",
        '    if (!TARGET.test(context.parentURL ?? "")) return nextResolve(specifier, context);',
        '    if (specifier === "@babel/traverse") {',
        '      return { url: SHIM, format: "module", shortCircuit: true };',
        "    }",
        '    if (BLOCK_DIRECT && specifier.endsWith("/@babel/traverse/lib/scope/index.js")) {',
        '      return { url: "data:text/javascript,export%20default%20%7B%7D", format: "module", shortCircuit: true };',
        "    }",
        "    return nextResolve(specifier, context);",
        "  },",
        "});",
    ])
    name = "force_no_scope_patch.mjs" if block_direct_scope else "force_scope_fallback.mjs"
    path = directory / name
    path.write_text(hook, encoding="utf-8")
    return path


def test_scope_fallback_branch_keeps_real_scripts_scope_aware(tmp_path: Path) -> None:
    """Ana dal devre dışıyken (hook) iki script de duplicate declaration'da scope-aware kalmalı."""
    has_hooks = _run_node(
        "-e", 'process.exit(typeof require("node:module").registerHooks === "function" ? 0 : 3)'
    )
    if has_hooks.returncode != 0:
        pytest.skip("bu node sürümünde module.registerHooks yok")
    source = _DUP_CASES["param-let"]
    assert "Duplicate declaration" in (_raw_babel_error(source) or ""), "girdi yamayı sınamıyor"

    hook = ("--import", _write_force_fallback_hook(tmp_path).as_uri())
    inp = tmp_path / "dup.js"
    inp.write_text(source, encoding="utf-8")
    ctx_path, out = tmp_path / "ctx.json", tmp_path / "out.js"

    analyzer = _run_node(*hook, str(_ANALYZER), str(inp), str(ctx_path))
    assert analyzer.returncode == 0, analyzer.stderr
    assert "[test-hook]" in analyzer.stderr, analyzer.stderr
    ctx = json.loads(ctx_path.read_text(encoding="utf-8"))
    assert ctx["scope_aware"] is True, (ctx["errors"], analyzer.stderr)
    assert ctx["errors"] == [], analyzer.stderr

    applier = _run_node(
        *hook, str(_APPLIER), str(inp), str(ctx_path), str(out),
        "--min-confidence", str(_MIN_CONFIDENCE),
    )
    assert applier.returncode == 0, applier.stderr
    assert "[test-hook]" in applier.stderr, applier.stderr
    emitted = _json_lines(applier.stdout)
    # Scope-aware yol çökerse flat yedeğe düşüp İKİ JSON satırı basıyor.
    assert len(emitted) == 1, (applier.stdout, applier.stderr)
    assert emitted[0]["scope_aware"] is True and emitted[0]["errors"] == [], applier.stderr
    assert emitted[0]["renamed"] >= 1


def test_flat_fallback_emits_single_accurate_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Scope-aware yol çöküp flat yedeğe düşünce tek JSON satırı ve doğru rapor.

    Eski kusur: yedek flatRename kendi raporunu bastıktan sonra scope-aware dal da
    ikinci satırı basıyordu; stdout'un SON satırını okuyan SubprocessRunner
    Python'a "scope_aware: true, renamed: 0, mappings: {}" veriyordu (flat rename
    yapılmış, çıktı dosyası değişmiş olsa bile).
    """
    has_hooks = _run_node(
        "-e", 'process.exit(typeof require("node:module").registerHooks === "function" ? 0 : 3)'
    )
    if has_hooks.returncode != 0:
        pytest.skip("bu node sürümünde module.registerHooks yok")
    source = _DUP_CASES["param-let"]
    inp = tmp_path / "dup.js"
    inp.write_text(source, encoding="utf-8")
    ctx = ContextNamer(_CONFIG).analyze(inp)  # hook yok: analizör scope-aware
    _precondition(ctx["scope_aware"] and bool(ctx["scope_renames"]), f"analiz: {ctx['errors']}")
    ctx_path, out = tmp_path / "ctx.json", tmp_path / "out.js"
    ctx_path.write_text(json.dumps(ctx), encoding="utf-8")
    hook = _write_force_fallback_hook(tmp_path, block_direct_scope=True)

    applier = _run_node(
        "--import", hook.as_uri(), str(_APPLIER), str(inp), str(ctx_path), str(out),
        "--min-confidence", str(_MIN_CONFIDENCE),
    )
    assert applier.returncode == 0, applier.stderr
    _precondition("[test-hook]" in applier.stderr, f"hook yüklenmedi: {applier.stderr}")
    _precondition("patched" not in applier.stderr, f"Scope yaması yine uygulandı: {applier.stderr}")
    emitted = _json_lines(applier.stdout)
    assert len(emitted) == 1, applier.stdout
    report = emitted[0]
    assert report["scope_aware"] is False, report
    assert any("Scope-aware rename hatasi" in e for e in report["errors"]), report["errors"]
    assert report["mappings"] == {"a": "fileSystem"}, report
    assert report["renamed"] == 3  # flat kip: param, let ve return'deki üç `a`
    assert re.search(r"\bfunction f\(fileSystem\)", out.read_text(encoding="utf-8"))

    # Python yolu (SubprocessRunner son JSON satırını okur) aynı raporu görmeli
    monkeypatch.setenv("NODE_OPTIONS", f"--import={hook.as_uri()}")
    result = ContextNamer(_CONFIG, min_confidence=_MIN_CONFIDENCE).apply(
        inp, ctx, tmp_path / "out_py.js"
    )
    assert (result["scope_aware"], result["renamed"], result["mappings"]) == (
        False, report["renamed"], report["mappings"]
    )


# ---------------------------------------------------------------------------
# (f) Duplicate declaration toleransı
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("case", sorted(_DUP_CASES))
def test_duplicate_declaration_does_not_break_pipeline(run_pipeline, case: str) -> None:
    source = _DUP_CASES[case]
    # Ön koşul: yamasız Babel bu girdide gerçekten hata veriyor.
    error = _raw_babel_error(source)
    assert error is not None and "Duplicate declaration" in error, error

    res, inp, out = run_pipeline(f"dup_{case}", source)

    assert res.success, res.errors
    # Yama olmasa analizör "Scope traverse hatasi" ile noScope'a, applier
    # "Scope-aware rename hatasi" ile flat yedeğe düşer.
    assert res.errors == [], res.errors
    assert res.context_json["scope_aware"] is True
    assert res.output_file == out and out.is_file()
    assert res.variables_renamed >= 1


# ---------------------------------------------------------------------------
# (g) Anlam korunumu
# ---------------------------------------------------------------------------

# (kaynak, yeniden adlandırılması gereken binding anahtarı ya da None).
# Hepsi eski hatta node --check'ten geçen ama farklı çalışan (ya da hiç
# derlenmeyen) çıktı veriyordu.
_SEMANTIC_CASES = {
    # for-init'teki `var` tekrarının başlangıç ataması siliniyordu:
    # `for (var t = X, n = 0, r = t.length; ...)` -> `for (var t = X; ...)`
    "for-init-var-redeclared": (
        "module.exports = function (o) {\n"
        "  var s = 0;\n"
        "  for (var n = 0, r = 3; n < r; n++) s += n;\n"
        "  for (var t = Object.keys(o), n = 0, r = t.length; n < r; n++) s += o[t[n]];\n"
        "  return s;\n"
        "};\n",
        None,
    ),
    # sınıf metodları fonksiyon scope'u sayılmıyordu: ikinci metodun `var a`'sı
    # bildirimsiz atamaya dönüyordu (sınıf gövdesi strict: ReferenceError)
    "method-var": (
        "class K {\n"
        "  m(x) { var a = x + 1; return a; }\n"
        '  n(y) { var a = y + "!"; return a; }\n'
        "}\n"
        "module.exports = (v) => [new K().m(v), new K().n(v)];\n",
        None,
    ),
    # static blok scope sayılmıyordu: içteki `const a` dıştaki const'a atamaya dönüyordu
    "static-block-const": (
        'const a = "outer";\n'
        'class K { static { const a = "inner"; K.v = a; } }\n'
        "module.exports = (v) => [a, K.v, v];\n",
        None,
    ),
    # parametrenin `var` ile yeniden bildirimi (constant violation) yeniden adlandırılmıyordu
    "param-redeclared-by-var": (
        "function f(a) { var a = 1; return a; }\n"
        "module.exports = (v) => f(v);\n",
        "f@1:0::a",
    ),
    # destructuring atama hedefleri yeniden adlandırılmıyordu ([b] = ... örtük global'e yazıyordu)
    "destructuring-assignment": (
        "function g(b) { var c; ({ c } = b); [b] = [c]; return b; }\n"
        "module.exports = (v) => g({ c: v });\n",
        "g@1:0::b",
    ),
    # ayrılmış sözcük önerileri (`{ default: a }` -> "default") geçersiz JS üretiyordu
    "reserved-word-suggestion": (
        "const { default: a, delete: b } = { default: 1, delete: 2 };\n"
        "module.exports = (v) => [a, b, v];\n",
        "program@1:0::a",
    ),
}


@pytest.mark.parametrize("case", sorted(_SEMANTIC_CASES))
def test_rename_preserves_behavior(run_pipeline, case: str) -> None:
    source, key = _SEMANTIC_CASES[case]
    res, inp, out = run_pipeline(f"semantic_{case}", source)
    _precondition(res.success and res.errors == [], f"hat başarısız: {res.errors}")
    applied = _applied(res.mappings)
    if key is not None:
        _precondition(key in applied, f"{key} yeniden adlandırılmadı: {applied}")
        assert isinstance(applied[key], str) and _IDENTIFIER_RE.fullmatch(applied[key])
    else:
        _precondition(res.variables_renamed > 0, "hiç rename yok")

    check = _run_node("--check", str(out))
    assert check.returncode == 0, check.stderr
    eq = _alpha_equivalence(inp, out)
    assert eq["equal"], eq["diffs"]
    assert _call_export(out, "abc") == _call_export(inp, "abc")


_EXPORT_JS = (
    'import e from "node:fs";\n'
    'const t = require("node:path");\n'
    "export var a = new Map();\n"
    "export function b(c) { return a.get(c) + e.sep + t.sep; }\n"
    "export { t };\n"
)


def test_exported_declarations_keep_their_names(run_pipeline) -> None:
    """`export var/function` ile dışa verilen binding'in adı değişirse modülün
    arayüzü değişir; atlanmalı. `export { t }` ise `export { yeni as t }` olur."""
    res, inp, out = run_pipeline("exports", _EXPORT_JS)
    _precondition(res.success and res.errors == [], f"hat başarısız: {res.errors}")
    suggested = {
        f"{r['scopeId']}::{r['originalName']}"
        for r in res.context_json["scope_renames"]
        if r["confidence"] >= _MIN_CONFIDENCE
    }
    _precondition("program@1:0::a" in suggested, f"a için öneri yok: {suggested}")

    applied = _applied(res.mappings)
    assert "program@1:0::a" not in applied, applied
    text = out.read_text(encoding="utf-8")
    assert re.search(r"\bexport var a = new Map\(\)", text), text
    assert re.search(r"\bexport function b\(", text), text
    assert applied.get("program@1:0::t") == "pathUtils", applied
    assert re.search(r"\bexport \{ pathUtils as t \}", text), text
    assert _alpha_equivalence(inp, out)["equal"]


def test_min_confidence_default_comes_from_config() -> None:
    """ContextNamer eşiği Config.min_confidence.context_namer'dan okur (0.1 sabiti değil)."""
    config = Config()
    assert ContextNamer(config).min_confidence == config.min_confidence.context_namer == 0.1
    config.min_confidence.context_namer = 0.35
    assert ContextNamer(config).min_confidence == 0.35
    assert ContextNamer(config, min_confidence=0.2).min_confidence == 0.2


def test_rename_never_takes_an_implicit_global_name(tmp_path: Path) -> None:
    """Bildirimsiz global (burada yalnız `typeof foo`) adına yeniden adlandırma yapılmaz.

    `a -> foo` uygulansaydı `typeof foo` yerel değişkeni görür, sonuç 1'den 2'ye
    değişirdi. isSafeRename program.globals'ı denetliyor; öneri sonek alır.
    """
    src = (
        "function f(){ var a = 1; return a + (typeof foo === 'undefined' ? 0 : 1); }\n"
        "console.log(f());\n"
    )
    inp = tmp_path / "global.js"
    inp.write_text(src, encoding="utf-8")
    names = tmp_path / "names.json"
    names.write_text(json.dumps({
        "scope_renames": [
            {"scopeId": "f@1:0", "originalName": "a", "newName": "foo", "confidence": 0.9},
        ],
        "variables": {},
    }), encoding="utf-8")
    out = tmp_path / "global.named.js"

    rep = _node_json(str(_APPLIER), str(inp), str(names), str(out), "--min-confidence", "0.1")

    assert rep["success"], rep
    assert _applied(rep["mappings"]) == {"f@1:0::a": "foo_1"}
    assert _run_node(str(inp)).stdout == _run_node(str(out)).stdout == "1\n"
