"""Deobfuscation katmanında sahte başarı raporlaması (2026-09-25).

Kusurlar (düzeltmeden önce ölçüldü, /private/tmp/deobf_honest):
1. deep_pipeline._step_beautify: beautify.mjs hata verince girdi "01_beautified.js"
   adıyla kopyalanıp adım success=True dönüyordu.
2. deep_pipeline.run / _run_chunked: success = any(adım başarılı) -- beautify'ın
   "başarısı" tek başına tüm hattı başarılı sayıyordu (Python kaynağı ve ikili
   içerik JS_BUNDLE olarak "OK"). Ayrıca deep-deobfuscate.mjs ayrıştıramadığı
   girdide 0 ile çıkıp kopya yazdığı için modül ikinci geçişi ve chunked bloklar
   çıkış koduna bakılarak "başarılı" sayılıyordu; chunked modda < 100 baytlık
   bloklar birleşik çıktıdan düşüyordu (Python kaynağında birleşik çıktı 0 bayt).
3. JavaBinaryAnalyzer.deobfuscate: static JSON yokken success=True + boş sonuç;
   mapping.txt parse edilip atılıyor, girdi dosyası "artifact" diye raporlanıyordu.
4. DotNetBinaryAnalyzer.deobfuscate: hiçbir şey yapmayan taslak success=True
   (tests/test_dotnet_binary.py'de ayrıca kilitli).

Bölümler: (A) sahte runner ile deterministik deep-pipeline birim testleri,
(B) aşama (StageResult) dönüşümü, (C) gerçek node araç zinciriyle uçtan uca,
(D) Java.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import time
import zipfile
from pathlib import Path

import pytest

import karadul.deobfuscators.deep_pipeline as dp
from karadul.analyzers.java_binary import JavaBinaryAnalyzer
from karadul.config import Config
from karadul.core.pipeline import PipelineContext
from karadul.core.result import PipelineResult, StageResult
from karadul.core.subprocess_runner import SubprocessResult
from karadul.core.target import Language, TargetInfo, TargetType
from karadul.core.workspace import Workspace
from karadul.deobfuscators.deep_pipeline import (
    STATUS_FAILED,
    STATUS_OK,
    STATUS_PARTIAL,
    DeepDeobfuscationPipeline,
    DeepDeobfuscationResult,
)
from karadul.stages import DeobfuscationStage

_FIXTURE_JS = Path(__file__).parent / "fixtures" / "sample_minified.js"
_STUB_SCRIPTS = (
    "beautify.mjs",
    "deep-deobfuscate.mjs",
    "cursor-enhanced-rename.mjs",
    "smart-webpack-unpack.mjs",
    "stream-parse.mjs",
)


# ---------------------------------------------------------------------------
# Sahte runner: node script'lerinin JSON sözleşmesini taklit eder
# ---------------------------------------------------------------------------

def _res(exit_ok: bool, payload: dict) -> SubprocessResult:
    return SubprocessResult(
        success=exit_ok, returncode=0 if exit_ok else 1,
        stdout=json.dumps(payload), stderr="", parsed_json=payload,
    )


class _FakeRunner:
    """SubprocessRunner yerine geçer; script adına göre senaryodaki davranışı taklit eder.

    Senaryo anahtarları: beautify ("ok"|"fail"), deep ("ok"|"fallback"|"no_output"),
    enhanced ("ok"|"fail"), unpack (int modül sayısı|"none"|"fail"),
    modules (modül başına "ok"|"fallback"), blocks (chunked blok içerikleri),
    chunk_deep (blok başına "ok"|"fallback").
    Gerçek deep-deobfuscate.mjs gibi ayrıştıramadığı girdide 0 ile çıkar ve kopya yazar.
    """

    def __init__(self, scenario: dict) -> None:
        self.s = scenario
        self.calls: list[tuple[str, list[str]]] = []

    def run_command(self, cmd, timeout=None, cwd=None, env=None):  # noqa: ARG002
        cmd = [str(c) for c in cmd]
        i = next(k for k, c in enumerate(cmd) if c.endswith(".mjs"))
        script, args = Path(cmd[i]).name, cmd[i + 1:]
        self.calls.append((script, args))
        if script == "beautify.mjs":
            return self._beautify(Path(args[0]), Path(args[1]))
        if script == "deep-deobfuscate.mjs":
            src = Path(args[0])
            if "stream_chunks" in src.parts:
                mode = self.s["chunk_deep"][int(src.stem.split("_")[1]) - 1]
            elif "webpack_modules" in src.parts:
                mode = self.s["modules"][int(src.stem.split("_")[1])]
            else:
                mode = self.s["deep"]
            return self._deep(src, Path(args[1]), mode)
        if script == "cursor-enhanced-rename.mjs":
            return self._enhanced(Path(args[0]), Path(args[1]))
        if script == "smart-webpack-unpack.mjs":
            return self._unpack(Path(args[1]))
        if script == "stream-parse.mjs":
            return self._stream(Path(args[1]))
        raise AssertionError(f"beklenmeyen script: {script}")

    def _beautify(self, src: Path, out: Path) -> SubprocessResult:
        if self.s["beautify"] == "ok":
            out.write_text(src.read_text() + "\n/* beautified */\n")
            return _res(True, {"success": True, "stats": {}})
        return _res(False, {"success": False, "errors": ["Beautify hatasi: sahte çökme"]})

    @staticmethod
    def _deep(src: Path, out: Path, mode: str) -> SubprocessResult:
        if mode == "ok":
            out.write_text("/* deep */\n" + src.read_text())
            return _res(True, {"success": True, "phases_completed": [1, 9],
                               "stats": {}, "errors": []})
        if mode == "no_output":
            return _res(True, {"success": True, "phases_completed": [1],
                               "stats": {}, "errors": []})
        out.write_text(src.read_text())  # fallback_copy: dönüştürülmemiş kopya, çıkış 0
        return _res(True, {"success": False, "phases_completed": [], "stats": {},
                           "errors": ["Babel parse basarisiz: sahte"], "fallback_copy": True})

    def _enhanced(self, src: Path, out: Path) -> SubprocessResult:
        if self.s["enhanced"] == "ok":
            out.write_text("/* enhanced */\n" + src.read_text())
            return _res(True, {"success": True, "renamed": 1, "stats": {}, "errors": []})
        return _res(True, {"success": False, "errors": ["Parse hatasi: sahte"]})

    def _unpack(self, out_dir: Path) -> SubprocessResult:
        mode = self.s["unpack"]
        if isinstance(mode, int):
            mods = out_dir / "modules"
            mods.mkdir(parents=True, exist_ok=True)
            for k in range(mode):
                (mods / f"module_{k}.js").write_text(f"var m{k} = {k};\n")
            return _res(True, {"success": True, "total_modules": mode,
                               "bundle_format": "webpack_object", "errors": []})
        if mode == "none":  # sorunsuz ayrıştı, paket yapısı yok
            return _res(True, {"success": False, "total_modules": 0,
                               "bundle_format": "unknown", "errors": []})
        return _res(True, {"success": False, "total_modules": 0, "bundle_format": "unknown",
                           "errors": ["Babel parse basarisiz: sahte"], "regex_module_ids": 0})

    def _stream(self, chunks_dir: Path) -> SubprocessResult:
        for k, text in enumerate(self.s["blocks"], start=1):
            (chunks_dir / f"block_{k:05d}.js").write_text(text)
        return _res(True, {"success": True, "total_blocks": len(self.s["blocks"]),
                           "total_lines": 0, "input_size_mb": 0})


_OK = {"beautify": "ok", "deep": "ok", "enhanced": "ok", "unpack": "none"}


def _stub_scripts(base: Path) -> Path:
    scripts = base / "scripts"
    scripts.mkdir(parents=True, exist_ok=True)
    for name in _STUB_SCRIPTS:
        (scripts / name).write_text("// sahte: çalıştırılmaz, _FakeRunner taklit eder\n")
    return scripts


def _run_fake(tmp_path: Path, scenario: dict, *, chunked: bool = False,
              **run_kw) -> tuple[DeepDeobfuscationResult, _FakeRunner, Path]:
    pipe = DeepDeobfuscationPipeline(Config())
    pipe._scripts_dir = _stub_scripts(tmp_path)
    fake = _FakeRunner(scenario)
    pipe._runner = fake
    if chunked:
        pipe.LARGE_FILE_THRESHOLD_MB = 0  # küçük girdiyle chunked yolu zorla
    src = tmp_path / "in.js"
    src.write_text("var a = 1;\n" * 20)
    ws = Workspace(base_dir=tmp_path / "ws", target_name="t")
    ws.create()
    result = pipe.run(src, ws, **run_kw)
    return result, fake, ws.get_stage_dir("deobfuscated")


# ---------------------------------------------------------------------------
# (A) Deep pipeline: genel başarı / durum / adım sözleşmesi
# ---------------------------------------------------------------------------

class TestDeepPipelineHonestSuccess:

    def test_all_steps_ok_is_ok(self, tmp_path: Path):
        result, _, deob = _run_fake(tmp_path, {**_OK, "unpack": 2, "modules": ["ok", "ok"]})
        assert result.success is True
        assert result.status == STATUS_OK
        assert result.warnings == []
        assert result.output_file == deob / "03_enhanced_renamed.js"
        assert result.steps["module_rename"]["renamed_count"] == 2

    def test_beautify_failure_is_not_success_and_writes_no_fake_copy(self, tmp_path: Path):
        result, fake, deob = _run_fake(tmp_path, {**_OK, "beautify": "fail"})
        step = result.steps["beautify"]
        assert step["success"] is False
        assert "Beautify hatasi: sahte çökme" in step["error"]  # stdout JSON'daki neden
        assert not (deob / "01_beautified.js").exists()          # sahte "beautified" yok
        assert "beautified_size" not in result.stats
        # deep, orijinalle devam etti
        deep_in = next(a for s, a in fake.calls if s == "deep-deobfuscate.mjs")[0]
        assert Path(deep_in).name == "00_original.js"
        # asıl çıktı üretildi -> başarı, ama dürüstçe "kısmi"
        assert result.success is True
        assert result.status == STATUS_PARTIAL
        assert any(w.startswith("beautify başarısız") for w in result.warnings)

    def test_beautify_success_alone_is_not_pipeline_success(self, tmp_path: Path):
        """Kök kusur: eskiden any(adım) -> beautify OK = hat OK."""
        result, _, deob = _run_fake(
            tmp_path, {**_OK, "deep": "fallback", "enhanced": "fail", "unpack": "fail"},
        )
        assert result.steps["beautify"]["success"] is True
        assert result.success is False
        assert result.status == STATUS_FAILED
        assert "Asıl çıktı üretilmedi" in result.warnings[0]
        # output_file dönüştürülmemiş fallback kopyası DEĞİL, gerçek son ürün
        assert result.output_file == deob / "01_beautified.js"
        assert result.stats["deep_deob_fallback_copy"] is True
        assert result.steps["deep_deobfuscate"]["fallback_copy"] is True

    def test_nothing_produced_has_no_output_file(self, tmp_path: Path):
        result, _, deob = _run_fake(
            tmp_path,
            {"beautify": "fail", "deep": "fallback", "enhanced": "fail", "unpack": "fail"},
        )
        assert result.success is False and result.status == STATUS_FAILED
        assert result.output_file is None  # 02_... var ama girdinin kopyası
        assert (deob / "02_deep_deobfuscated.js").exists()

    def test_deep_success_without_output_is_failure(self, tmp_path: Path):
        result, _, _ = _run_fake(tmp_path, {**_OK, "deep": "no_output"})
        assert result.steps["deep_deobfuscate"]["success"] is False
        assert "çıktı dosyası yok" in result.steps["deep_deobfuscate"]["error"]
        assert result.success is False

    def test_enhanced_failure_is_partial(self, tmp_path: Path):
        result, _, deob = _run_fake(tmp_path, {**_OK, "enhanced": "fail"})
        assert result.success is True and result.status == STATUS_PARTIAL
        assert result.output_file == deob / "02_deep_deobfuscated.js"
        assert result.steps["enhanced_rename"]["error"] == "cursor-enhanced-rename.mjs başarısız"

    def test_not_a_bundle_is_skipped_not_failure(self, tmp_path: Path):
        """Düz JS'te modül bulunmaması hata değil: durum 'ok' kalır."""
        result, _, _ = _run_fake(tmp_path, _OK)
        step = result.steps["smart_unpack"]
        assert step["success"] is False and step["skipped"] is True
        assert "error" not in step
        assert result.status == STATUS_OK and result.warnings == []

    def test_unpack_parse_failure_is_failure(self, tmp_path: Path):
        result, _, _ = _run_fake(tmp_path, {**_OK, "unpack": "fail"})
        assert result.steps["smart_unpack"].get("skipped") is not True
        assert result.status == STATUS_PARTIAL

    def test_module_rename_counts_only_real_renames(self, tmp_path: Path):
        """Script 0 ile çıkıp kopya yazsa da (JSON success=false) modül sayılmaz."""
        result, _, _ = _run_fake(
            tmp_path, {**_OK, "unpack": 3, "modules": ["ok", "fallback", "fallback"]},
        )
        step = result.steps["module_rename"]
        assert step["renamed_count"] == 1
        assert step["failed_count"] == 2
        assert step["failed_modules"] == ["module_1.js", "module_2.js"]
        assert step["success"] is True and step["partial"] is True
        assert "ilk hata: module_1.js: Babel parse basarisiz" in step["error"]
        assert result.stats["modules_renamed"] == 1
        assert result.status == STATUS_PARTIAL

    def test_module_rename_all_failed_is_failed_step(self, tmp_path: Path):
        result, _, deob = _run_fake(
            tmp_path, {**_OK, "unpack": 2, "modules": ["fallback", "fallback"]},
        )
        step = result.steps["module_rename"]
        assert step["success"] is False and step["renamed_count"] == 0
        # başarısız modül dosyası yerinde, geçici dosya kalmadı
        mods = deob / "webpack_modules" / "modules"
        assert sorted(p.name for p in mods.iterdir()) == ["module_0.js", "module_1.js"]
        assert result.success is True and result.status == STATUS_PARTIAL

    def test_skip_beautify_is_skipped_not_success(self, tmp_path: Path):
        result, fake, _ = _run_fake(tmp_path, _OK, skip_beautify=True)
        assert result.steps["beautify"] == {
            "success": False, "skipped": True,
            "reason": "skip_beautify=True: çağıran beautify'ı atladı",
        }
        assert all(s != "beautify.mjs" for s, _ in fake.calls)
        assert result.status == STATUS_OK

    def test_missing_input_is_failed(self, tmp_path: Path):
        pipe = DeepDeobfuscationPipeline(Config())
        ws = Workspace(base_dir=tmp_path / "ws", target_name="t")
        ws.create()
        result = pipe.run(tmp_path / "yok.js", ws)
        assert result.success is False and result.status == STATUS_FAILED

    def test_summary_reflects_status(self, tmp_path: Path):
        result, _, _ = _run_fake(tmp_path, {**_OK, "beautify": "fail"})
        assert result.summary().startswith("[PARTIAL] Deep deob: ")
        assert "1 skipped" in result.summary()  # smart_unpack: paket değil

    def test_status_defaults_without_finalize(self):
        assert DeepDeobfuscationResult().status == STATUS_FAILED
        assert DeepDeobfuscationResult(success=True).status == STATUS_OK


class TestChunkedHonestSuccess:

    _BIG = "var big = 1;\n" * 12  # >= CHUNK_MIN_BYTES

    def test_fallback_blocks_are_not_counted(self, tmp_path: Path):
        small = "x;\n"
        result, _, deob = _run_fake(
            tmp_path,
            {**_OK, "blocks": [self._BIG, self._BIG.replace("big", "b2"), small],
             "chunk_deep": ["ok", "fallback", "ok"]},
            chunked=True,
        )
        step = result.steps["deep_deobfuscate_chunks"]
        assert step["deob_success"] == 1       # çıkış kodu 0 ama JSON success=false
        assert step["failed_chunks"] == 1
        assert step["skipped_small"] == 1
        assert step["success"] is True and step["partial"] is True
        assert result.success is True and result.status == STATUS_PARTIAL
        combined = (deob / "02_deep_deobfuscated.js").read_text()
        assert "b2" in combined
        assert small.strip() in combined        # küçük blok birleşik çıktıdan düşmedi

    def test_no_block_deobfuscated_is_failed(self, tmp_path: Path):
        result, _, deob = _run_fake(
            tmp_path, {**_OK, "blocks": [self._BIG], "chunk_deep": ["fallback"]},
            chunked=True,
        )
        assert result.steps["deep_deobfuscate_chunks"]["success"] is False
        assert result.success is False and result.status == STATUS_FAILED
        assert result.output_file is None
        # içerik yine de kaybolmadı
        assert "big" in (deob / "02_deep_deobfuscated.js").read_text()

    def test_only_small_blocks_is_failed_but_content_kept(self, tmp_path: Path):
        result, fake, deob = _run_fake(
            tmp_path, {**_OK, "blocks": ["a;\n", "b;\n"], "chunk_deep": []}, chunked=True,
        )
        assert all(s != "deep-deobfuscate.mjs" for s, _ in fake.calls)
        assert result.success is False
        assert "hepsi <" in result.steps["deep_deobfuscate_chunks"]["error"]
        assert (deob / "02_deep_deobfuscated.js").read_text() == "a;\n\n\nb;\n\n\n"


# ---------------------------------------------------------------------------
# (B) StageResult dönüşümü (stages.py değişmedi; stats aracılığıyla taşınır)
# ---------------------------------------------------------------------------

def _stage_with_fake(tmp_path: Path, monkeypatch, scenario: dict) -> StageResult:
    cfg = Config()
    cfg.scripts_dir = _stub_scripts(tmp_path)
    fake = _FakeRunner(scenario)
    monkeypatch.setattr(dp, "SubprocessRunner", lambda config: fake)
    src = tmp_path / "bundle.js"
    src.write_text("var a = 1;\n" * 20)
    ws = Workspace(base_dir=tmp_path / "ws", target_name="t")
    ws.create()
    target = TargetInfo(path=src, name="t", target_type=TargetType.JS_BUNDLE,
                        language=Language.JAVASCRIPT, file_size=src.stat().st_size,
                        file_hash="0" * 64)
    ctx = PipelineContext(target=target, workspace=ws, config=cfg)
    return DeobfuscationStage(use_deep=True)._execute_deep(ctx, time.monotonic())


class TestStageResultIsHonest:

    def test_partial_stays_success_but_surfaces_failure(self, tmp_path: Path, monkeypatch):
        sr = _stage_with_fake(tmp_path, monkeypatch, {**_OK, "beautify": "fail"})
        assert sr.success is True
        assert sr.stats["status"] == STATUS_PARTIAL
        assert any(e.startswith("beautify: beautify.mjs başarısız") for e in sr.errors)
        assert sr.stats["warnings"]

    def test_failed_main_output_fails_stage(self, tmp_path: Path, monkeypatch):
        sr = _stage_with_fake(
            tmp_path, monkeypatch,
            {**_OK, "deep": "fallback", "enhanced": "fail", "unpack": "fail"},
        )
        assert sr.success is False and sr.skipped is False
        assert sr.stats["status"] == STATUS_FAILED
        assert "output_file" in sr.artifacts  # 01_beautified gerçek ürün
        assert sr.artifacts["output_file"].name == "01_beautified.js"
        pr = PipelineResult(target_name="t", target_hash="0" * 64)
        pr.add_stage_result(sr)
        assert pr.get_failed_stages() == ["deobfuscate"]


# ---------------------------------------------------------------------------
# (C) Gerçek node araç zinciri (beautify.mjs gerçekten çöker)
# ---------------------------------------------------------------------------

def _js_toolchain_available() -> bool:
    scripts = Config().scripts_dir
    return (
        shutil.which("node") is not None
        and all((scripts / n).exists() for n in _STUB_SCRIPTS[:4])
        and (scripts / "node_modules").is_dir()
    )


# js-beautify eşleşmeyen ")" ardından "/" görünce çöker ("reading 'previous'");
# Babel jsx eklentisiyle bu geçerli JSX'i sorunsuz ayrıştırır.
_JSX_BREAKS_BEAUTIFY = "\nvar __jsx_note = <p>a)/b</p>;\n"
# ELF başlığı + aynı çökme dizisi: beautify de Babel de başarısız.
_ELF_LIKE = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8 + b")\x05\x00\x11\xe9/" + b"\x00" * 16


def _real_ctx(base: Path, name: str, content: bytes) -> PipelineContext:
    base.mkdir(parents=True, exist_ok=True)
    src = base / name
    src.write_bytes(content)
    ws = Workspace(base_dir=base / "ws", target_name="t")
    ws.create()
    target = TargetInfo(path=src, name="t", target_type=TargetType.JS_BUNDLE,
                        language=Language.JAVASCRIPT, file_size=src.stat().st_size,
                        file_hash="0" * 64)
    return PipelineContext(target=target, workspace=ws, config=Config())


@pytest.mark.skipif(not _js_toolchain_available(), reason="node veya scripts/node_modules yok")
class TestRealToolchain:

    def test_sample_main_output_success(self, tmp_path: Path):
        ctx = _real_ctx(tmp_path, "sample.js", _FIXTURE_JS.read_bytes())
        sr = DeobfuscationStage(use_deep=True)._execute_deep(ctx, time.monotonic())
        steps = sr.stats["steps"]
        assert sr.success is True
        assert steps["deep_deobfuscate"]["success"] is True
        assert sr.stats["status"] in (STATUS_OK, STATUS_PARTIAL)
        assert sr.artifacts["output_file"].name == "03_enhanced_renamed.js"

    def test_sample_module_rename_count_matches_reality(self, tmp_path: Path):
        """modules_renamed, phase-9'un gerçekten işleyebildiği modül sayısını aşamaz.

        Ölçüm (2026-09-25): webpack_object modülleri adsız 'function (…) {…}'
        olarak yazılıyor, tek başına ayrıştırılamıyor; eski kod 3/3 "renamed" diyordu.
        """
        ctx = _real_ctx(tmp_path, "sample.js", _FIXTURE_JS.read_bytes())
        sr = DeobfuscationStage(use_deep=True)._execute_deep(ctx, time.monotonic())
        mods = sorted((ctx.workspace.get_stage_dir("deobfuscated")
                       / "webpack_modules" / "modules").glob("*.js"))
        assert mods
        script = ctx.config.scripts_dir / "deep-deobfuscate.mjs"
        processable = 0
        for mf in mods:
            out = tmp_path / f"check_{mf.name}"
            proc = subprocess.run(
                ["node", str(script), str(mf), str(out), "--phases", "9"],
                capture_output=True, text=True, timeout=120,
            )
            processable += bool(json.loads(proc.stdout.strip().splitlines()[-1])["success"])
        step = sr.stats["steps"]["module_rename"]
        assert step["renamed_count"] == processable
        assert step["success"] is (processable > 0)

    def test_real_beautify_crash_is_reported_partial(self, tmp_path: Path):
        ctx = _real_ctx(tmp_path, "jsx.js",
                        (_FIXTURE_JS.read_text() + _JSX_BREAKS_BEAUTIFY).encode())
        sr = DeobfuscationStage(use_deep=True)._execute_deep(ctx, time.monotonic())
        deob = ctx.workspace.get_stage_dir("deobfuscated")
        beautify = sr.stats["steps"]["beautify"]
        assert beautify["success"] is False
        assert "reading 'previous'" in beautify["error"]
        assert not (deob / "01_beautified.js").exists()
        assert sr.success is True  # deep dönüşümü gerçekten üretildi
        assert sr.stats["status"] == STATUS_PARTIAL
        assert any(e.startswith("beautify: ") for e in sr.errors)

    def test_binary_content_is_failed(self, tmp_path: Path):
        ctx = _real_ctx(tmp_path, "bin.js", _ELF_LIKE)
        sr = DeobfuscationStage(use_deep=True)._execute_deep(ctx, time.monotonic())
        assert sr.success is False
        assert sr.stats["status"] == STATUS_FAILED
        assert "output_file" not in sr.artifacts
        assert not (ctx.workspace.get_stage_dir("deobfuscated") / "01_beautified.js").exists()

    def test_non_js_text_beautified_but_not_deobfuscated_is_failed(self, tmp_path: Path):
        """beautify Python'u da "biçimler"; bu tek başına başarı değildir."""
        ctx = _real_ctx(tmp_path, "py.js", b"def foo(x):\n    return x + 1\n")
        sr = DeobfuscationStage(use_deep=True)._execute_deep(ctx, time.monotonic())
        assert sr.stats["steps"]["beautify"]["success"] is True
        assert sr.success is False
        assert sr.stats["status"] == STATUS_FAILED


# ---------------------------------------------------------------------------
# (D) Java: ProGuard/R8
# ---------------------------------------------------------------------------

def _java_ws(tmp_path: Path, analysis: dict | str | None) -> Workspace:
    ws = Workspace(base_dir=tmp_path / "ws", target_name="app")
    ws.create()
    if analysis is not None:
        path = ws.get_stage_dir("static") / "java_analysis.json"
        path.write_text(analysis if isinstance(analysis, str) else json.dumps(analysis))
    return ws


def _jar_target(path: Path) -> TargetInfo:
    return TargetInfo(path=path, name="app", target_type=TargetType.JAVA_JAR,
                      language=Language.JAVA, file_size=0, file_hash="0" * 64)


_MAPPING = """\
# compiler: R8
# {"id":"com.android.tools.r8.mapping","version":"2.0"}
com.example.app.MainActivity -> a.a:
    java.lang.String title -> a
    1:5:void onCreate(android.os.Bundle):12:16 -> onCreate
com.example.app.Repository -> a.b:
    int size -> a
"""


class TestJavaDeobfuscateHonest:

    @pytest.fixture
    def analyzer(self) -> JavaBinaryAnalyzer:
        return JavaBinaryAnalyzer(Config())

    def test_missing_static_is_failure_not_success(self, analyzer, tmp_path: Path):
        ws = _java_ws(tmp_path, None)
        result = analyzer.deobfuscate(_jar_target(tmp_path / "app.jar"), ws)
        assert result.success is False and result.skipped is False
        assert "java_analysis.json yok" in result.errors[0]

    def test_corrupt_static_is_failure(self, analyzer, tmp_path: Path):
        ws = _java_ws(tmp_path, "{bozuk")
        result = analyzer.deobfuscate(_jar_target(tmp_path / "app.jar"), ws)
        assert result.success is False
        assert "okunamadı" in result.errors[0]

    def test_missing_detection_is_not_claimed_unobfuscated(self, analyzer, tmp_path: Path):
        ws = _java_ws(tmp_path, {"jar_info": {}})
        result = analyzer.deobfuscate(_jar_target(tmp_path / "app.jar"), ws)
        assert result.success is False
        assert "obfuscated" not in result.stats

    def test_not_obfuscated_is_checked_success(self, analyzer, tmp_path: Path):
        ws = _java_ws(tmp_path, {"obfuscation": {"detected": False}})
        result = analyzer.deobfuscate(_jar_target(tmp_path / "app.jar"), ws)
        assert result.success is True and result.skipped is False
        assert result.stats == {"obfuscated": False}

    def test_obfuscated_without_mapping_is_skipped(self, analyzer, tmp_path: Path):
        ws = _java_ws(tmp_path, {"obfuscation": {
            "detected": True, "type": "proguard_r8", "mapping_file": None}})
        result = analyzer.deobfuscate(_jar_target(tmp_path / "app.jar"), ws)
        assert result.success is False and result.skipped is True
        assert result.errors == [] and result.artifacts == {}
        assert result.stats["mapping_found"] is False
        assert result.stats["mapping_applied"] is False
        assert "mapping.txt yok" in result.stats["skip_reason"]

    def test_obfuscated_with_mapping_reports_not_applied(self, analyzer, tmp_path: Path):
        mapping = tmp_path / "mapping.txt"
        mapping.write_text(_MAPPING)
        ws = _java_ws(tmp_path, {"obfuscation": {
            "detected": True, "type": "proguard_r8", "mapping_file": str(mapping)}})
        result = analyzer.deobfuscate(_jar_target(tmp_path / "app.jar"), ws)
        assert result.success is False and result.skipped is True
        assert result.artifacts == {}  # girdi mapping.txt ürün (artifact) değildir
        assert result.stats["mapping_found"] is True
        assert result.stats["mapping_applied"] is False
        assert result.stats["mapping_class_count"] == 2  # üye/yorum satırları sayılmaz
        assert result.stats["mapping_file"] == str(mapping)
        assert "UYGULANMADI" in result.stats["skip_reason"]

    def test_recorded_mapping_path_gone(self, analyzer, tmp_path: Path):
        gone = tmp_path / "yok" / "mapping.txt"
        ws = _java_ws(tmp_path, {"obfuscation": {"detected": True, "mapping_file": str(gone)}})
        result = analyzer.deobfuscate(_jar_target(tmp_path / "app.jar"), ws)
        assert result.skipped is True and result.stats["mapping_found"] is False
        assert "artık yok" in result.stats["skip_reason"]

    def test_static_to_deobfuscate_end_to_end(self, analyzer, tmp_path: Path):
        """Gerçek static tespiti (tek harfli paketler + yandaki mapping.txt) -> atlandı."""
        jar = tmp_path / "app.jar"
        with zipfile.ZipFile(jar, "w") as zf:
            for pkg in ("a", "b", "c", "d", "e", "f", "g"):
                zf.writestr(f"{pkg}/A.class", b"\xca\xfe\xba\xbe\x00")
        (tmp_path / "mapping.txt").write_text(_MAPPING)
        analyzer._jadx_path = None  # ortamdan bağımsız: jadx koşmasın
        ws = Workspace(base_dir=tmp_path / "ws", target_name="app")
        ws.create()
        analyzer.analyze_static(_jar_target(jar), ws)
        result = analyzer.deobfuscate(_jar_target(jar), ws)
        assert result.skipped is True and result.success is False
        assert result.stats["mapping_found"] is True
        assert result.stats["mapping_applied"] is False

    def test_stage_skip_does_not_fail_pipeline(self, tmp_path: Path):
        ws = _java_ws(tmp_path, {"obfuscation": {"detected": True}})
        jar = tmp_path / "app.jar"
        jar.write_bytes(b"PK\x05\x06" + b"\x00" * 18)
        ctx = PipelineContext(target=_jar_target(jar), workspace=ws, config=Config())
        sr = DeobfuscationStage().execute(ctx)
        assert sr.stage_name == "deobfuscate" and sr.skipped is True
        pr = PipelineResult(target_name="app", target_hash="0" * 64)
        pr.add_stage_result(StageResult("identify", True, 0.0))
        pr.add_stage_result(sr)
        assert pr.success is True and pr.get_skipped_stages() == ["deobfuscate"]
