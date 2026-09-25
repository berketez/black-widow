"""DeobfuscationStage hedef-türü yönlendirmesi.

Bug (2026-09-25): ``DeobfuscationStage.execute`` native olmayan HER türü, türüne
bakmadan JS derin hattına (DeepDeobfuscationPipeline: beautify.mjs, Babel, webpack
unpack) yolluyordu. JAR/APK/.NET/PyInstaller/.pyc ikili dosyalarında beautify
adımının "başarısı" (ya da hata sonrası kopyası) aşamayı sahte başarıya çeviriyordu;
PyInstaller'da deobfuscated/ altına ~30 MB, .NET'te ~59 MB çöp yazılıyordu.
ReconstructionStage'deki aynı tuzak 61f6bba'da düzeltilmişti.

Bu dosya:
- her TargetType için beklenen yolu (deep/legacy modunda) kilitler,
- JS-dışı türlerin JS hattına hiç ulaşmadığını gerçek koşuyla (dosya sistemi) gösterir,
- "atlandı" sonucunun sözleşmesini (skipped=True, hata değil) doğrular,
- JS/Electron davranış-nötrlüğünü gerçek JS hattıyla karşılaştırır.

Beklenen yol tablosu uygulamanın tablolarından BAĞIMSIZ yazıldı: yönlendirme eski
hâline döndürülürse (else -> JS hattı) buradaki testler patlar.
"""

from __future__ import annotations

import hashlib
import shutil
import time
from enum import Enum
from pathlib import Path

import pytest

from karadul.config import Config
from karadul.core.pipeline import PipelineContext
from karadul.core.result import PipelineResult, StageResult
from karadul.core.target import Language, TargetInfo, TargetType
from karadul.core.workspace import Workspace
from karadul.stages import DeobfuscationStage

_FIXTURE_JS = Path(__file__).parent / "fixtures" / "sample_minified.js"

# (use_deep=True yolu, use_deep=False yolu). "skipped" = aşama atlandı.
_EXPECTED_ROUTE: dict[TargetType, tuple[tuple[str, ...], tuple[str, ...]]] = {
    # JS ailesi: derin / legacy JS hattı (değişmedi)
    TargetType.JS_BUNDLE: (("deep",), ("legacy",)),
    TargetType.ELECTRON_APP: (("deep",), ("legacy",)),
    # Native: BinaryDeobfuscator (değişmedi)
    TargetType.MACHO_BINARY: (("binary",), ("binary",)),
    TargetType.UNIVERSAL_BINARY: (("binary",), ("binary",)),
    TargetType.ELF_BINARY: (("binary",), ("binary",)),
    TargetType.PE_BINARY: (("binary",), ("binary",)),
    TargetType.BUN_BINARY: (("binary",), ("binary",)),
    TargetType.DELPHI_BINARY: (("binary",), ("binary",)),
    # Go hibrit (değişmedi)
    TargetType.GO_BINARY: (("go", "binary"), ("go", "binary")),
    # JVM/Dalvik: kendi analizcisi (eskiden deep modda JS hattı)
    TargetType.JAVA_JAR: (("analyzer",), ("analyzer",)),
    TargetType.ANDROID_APK: (("analyzer",), ("analyzer",)),
    # Anlamlı deobfuscation yok: atlandı (eskiden deep modda JS hattı)
    TargetType.DOTNET_ASSEMBLY: (("skipped",), ("skipped",)),
    TargetType.PYTHON_PACKED: (("skipped",), ("skipped",)),
    TargetType.APP_BUNDLE: (("skipped",), ("skipped",)),
    TargetType.UNKNOWN: (("skipped",), ("skipped",)),
}

_JS_FAMILY = {TargetType.JS_BUNDLE, TargetType.ELECTRON_APP}
_SKIP_TYPES = [tt for tt, (deep, _) in _EXPECTED_ROUTE.items() if deep == ("skipped",)]

_HANDLERS = (
    ("_execute_deep", "deep"),
    ("_execute_legacy", "legacy"),
    ("_execute_binary", "binary"),
    ("_execute_go_binary", "go"),
    ("_execute_analyzer_deobfuscate", "analyzer"),
)


def _make_ctx(
    base: Path, target_type, *, path: Path | None = None,
    language: Language = Language.UNKNOWN,
) -> PipelineContext:
    base.mkdir(parents=True, exist_ok=True)
    if path is None:
        path = base / "sample.bin"
        path.write_bytes(b"\x7fELF" + b"\x00" * 60)  # içerik ikili; yönlendirme türe bakar
    ws = Workspace(base_dir=base / "ws", target_name="sample")
    ws.create()
    size = path.stat().st_size if path.is_file() else 0
    target = TargetInfo(
        path=path, name="sample", target_type=target_type, language=language,
        file_size=size, file_hash="0" * 64,
    )
    return PipelineContext(target=target, workspace=ws, config=Config())


def _route(target_type, tmp_path: Path, *, use_deep: bool) -> tuple[tuple[str, ...], StageResult]:
    """execute()'un hangi handler(lar)ı çağırdığını ölç.

    Handler'lar kayıt tutan sentinel'lerle değiştirilir (gerçek iş koşmaz).
    _skipped sentinel'lenmez: gerçek "atlandı" sonucu döner.
    """
    stage = DeobfuscationStage(use_deep=use_deep)
    calls: list[str] = []

    def _recorder(label: str):
        def _handler(ctx, start):
            calls.append(label)
            return StageResult(stage_name="deobfuscate", success=True, duration_seconds=0.0)
        return _handler

    for attr, label in _HANDLERS:
        setattr(stage, attr, _recorder(label))

    result = stage.execute(_make_ctx(tmp_path, target_type))
    if not calls and result.skipped:
        calls.append("skipped")
    return tuple(calls), result


def _deob_files(ctx: PipelineContext) -> list[Path]:
    deob = ctx.workspace.get_stage_dir("deobfuscated")
    return sorted(f for f in deob.rglob("*") if f.is_file())


# ---------------------------------------------------------------------------
# 1) Yönlendirme tablosu
# ---------------------------------------------------------------------------

class TestRoutingTable:

    def test_every_target_type_has_an_expected_route(self):
        """Yeni bir TargetType eklenirse bu tablo (ve yönlendirme kararı) güncellenmeli."""
        assert set(_EXPECTED_ROUTE) == set(TargetType)

    @pytest.mark.parametrize("use_deep", [True, False], ids=["deep", "legacy"])
    @pytest.mark.parametrize("target_type", list(TargetType), ids=lambda t: t.value)
    def test_route(self, target_type, use_deep, tmp_path: Path):
        calls, _ = _route(target_type, tmp_path, use_deep=use_deep)
        deep_route, legacy_route = _EXPECTED_ROUTE[target_type]
        assert calls == (deep_route if use_deep else legacy_route)

    @pytest.mark.parametrize("use_deep", [True, False], ids=["deep", "legacy"])
    @pytest.mark.parametrize(
        "target_type",
        [tt for tt in TargetType if tt not in _JS_FAMILY],
        ids=lambda t: t.value,
    )
    def test_non_js_types_never_reach_js_pipeline(self, target_type, use_deep, tmp_path: Path):
        calls, _ = _route(target_type, tmp_path, use_deep=use_deep)
        assert "deep" not in calls and "legacy" not in calls

    def test_type_outside_all_tables_is_skipped_not_js(self, tmp_path: Path):
        """Tablolarda olmayan (gelecekte eklenecek) bir tür JS hattına değil atlamaya düşer."""

        class _FutureType(Enum):
            NEW_FORMAT = "yeni_format"

        calls, result = _route(_FutureType.NEW_FORMAT, tmp_path, use_deep=True)
        assert calls == ("skipped",)
        assert "yeni_format" in result.stats["skip_reason"]


# ---------------------------------------------------------------------------
# 2) "Atlandı" sonucunun sözleşmesi + gerçek koşu (sentinel yok)
# ---------------------------------------------------------------------------

class TestSkippedIsHonest:

    @pytest.mark.parametrize("target_type", _SKIP_TYPES, ids=lambda t: t.value)
    def test_skip_result_contract(self, target_type, tmp_path: Path):
        """Ne sahte başarı ne başarısızlık: success=False + skipped=True, hata yok, gerekçe var."""
        _, result = _route(target_type, tmp_path, use_deep=True)
        assert result.skipped is True
        assert result.success is False
        assert result.errors == []
        assert result.stage_name == "deobfuscate"
        assert isinstance(result.stats.get("skip_reason"), str) and result.stats["skip_reason"]

    @pytest.mark.parametrize("target_type", _SKIP_TYPES, ids=lambda t: t.value)
    def test_skip_does_not_fail_pipeline(self, target_type, tmp_path: Path):
        _, result = _route(target_type, tmp_path, use_deep=True)
        pr = PipelineResult(target_name="sample", target_hash="0" * 64)
        pr.add_stage_result(StageResult("identify", True, 0.0))
        pr.add_stage_result(result)
        assert pr.success is True
        assert pr.get_failed_stages() == []
        assert pr.get_skipped_stages() == ["deobfuscate"]

    @pytest.mark.parametrize("use_deep", [True, False], ids=["deep", "legacy"])
    def test_python_packed_real_run_writes_nothing(self, use_deep, tmp_path: Path):
        """Gerçek execute (sentinel yok): JS hattı koşsaydı deobfuscated/00_original kopyası olurdu."""
        ctx = _make_ctx(tmp_path, TargetType.PYTHON_PACKED, language=Language.PYTHON)
        result = DeobfuscationStage(use_deep=use_deep).execute(ctx)
        assert result.skipped is True
        assert _deob_files(ctx) == []

    def test_dotnet_real_run_writes_nothing(self, tmp_path: Path):
        ctx = _make_ctx(tmp_path, TargetType.DOTNET_ASSEMBLY, language=Language.CSHARP)
        result = DeobfuscationStage().execute(ctx)
        assert result.skipped is True
        assert _deob_files(ctx) == []

    def test_app_bundle_directory_is_skipped_not_crashed(self, tmp_path: Path):
        """Eskiden JS derin hattı .app dizinini kopyalamaya çalışıp IsADirectoryError veriyordu."""
        app = tmp_path / "Tiny.app"
        (app / "Contents" / "MacOS").mkdir(parents=True)
        ctx = _make_ctx(tmp_path / "run", TargetType.APP_BUNDLE, path=app)
        result = DeobfuscationStage().execute(ctx)
        assert result.skipped is True
        assert result.errors == []
        assert _deob_files(ctx) == []

    def test_unknown_text_is_skipped_with_actionable_reason(self, tmp_path: Path):
        """Uzantısız JS UNKNOWN olarak tespit edilir; gerekçe kullanıcıya ne yapacağını söyler."""
        src = tmp_path / "bundle_noext"
        shutil.copy2(_FIXTURE_JS, src)
        ctx = _make_ctx(tmp_path / "run", TargetType.UNKNOWN, path=src)
        result = DeobfuscationStage().execute(ctx)
        assert result.skipped is True
        assert ".js" in result.stats["skip_reason"]
        assert _deob_files(ctx) == []


# ---------------------------------------------------------------------------
# 3) JVM/Dalvik: kendi analizcisi
# ---------------------------------------------------------------------------

class TestAnalyzerDeobfuscate:

    def test_jar_reaches_real_java_analyzer(self, tmp_path: Path):
        """Gerçek JavaBinaryAnalyzer.deobfuscate çağrılır; JS çöpü üretilmez."""
        ctx = _make_ctx(tmp_path, TargetType.JAVA_JAR, language=Language.JAVA)
        ctx.workspace.save_json(
            "static", "java_analysis", {"obfuscation": {"detected": False}},
        )
        result = DeobfuscationStage().execute(ctx)
        assert result.stage_name == "deobfuscate"
        assert result.success is True and result.skipped is False
        assert result.stats == {"obfuscated": False}
        assert _deob_files(ctx) == []

    def test_analyzer_result_is_returned_with_stage_name(self, tmp_path: Path, monkeypatch):
        import karadul.stages as stages_mod

        class _FakeAnalyzer:
            def __init__(self, config):
                pass

            def deobfuscate(self, target, workspace):
                return StageResult(
                    stage_name="baska_ad", success=True, duration_seconds=0.0,
                    stats={"obfuscated": True},
                )

        monkeypatch.setattr(stages_mod, "get_analyzer", lambda tt: _FakeAnalyzer)
        ctx = _make_ctx(tmp_path, TargetType.ANDROID_APK)
        result = DeobfuscationStage()._execute_analyzer_deobfuscate(ctx, time.monotonic())
        assert result.stage_name == "deobfuscate"
        assert result.stats == {"obfuscated": True}

    def test_analyzer_exception_is_failure(self, tmp_path: Path, monkeypatch):
        import karadul.stages as stages_mod

        class _RaisingAnalyzer:
            def __init__(self, config):
                pass

            def deobfuscate(self, target, workspace):
                raise RuntimeError("boom")

        monkeypatch.setattr(stages_mod, "get_analyzer", lambda tt: _RaisingAnalyzer)
        ctx = _make_ctx(tmp_path, TargetType.JAVA_JAR)
        result = DeobfuscationStage()._execute_analyzer_deobfuscate(ctx, time.monotonic())
        assert result.success is False and result.skipped is False
        assert any("RuntimeError" in e and "boom" in e for e in result.errors)

    def test_analyzer_none_result_is_failure(self, tmp_path: Path, monkeypatch):
        import karadul.stages as stages_mod

        class _NoneAnalyzer:
            def __init__(self, config):
                pass

            def deobfuscate(self, target, workspace):
                return None

        monkeypatch.setattr(stages_mod, "get_analyzer", lambda tt: _NoneAnalyzer)
        ctx = _make_ctx(tmp_path, TargetType.JAVA_JAR)
        result = DeobfuscationStage()._execute_analyzer_deobfuscate(ctx, time.monotonic())
        assert result.success is False
        assert any("döndürmedi" in e for e in result.errors)


# ---------------------------------------------------------------------------
# 4) JS / Electron davranış-nötrlüğü (gerçek JS hattı)
# ---------------------------------------------------------------------------

def _js_toolchain_available() -> bool:
    scripts = Config().scripts_dir
    return (
        shutil.which("node") is not None
        and (scripts / "beautify.mjs").exists()
        and (scripts / "deep-deobfuscate.mjs").exists()
        and (scripts / "node_modules").is_dir()
    )


_VOLATILE_KEYS = {"duration", "duration_seconds", "duration_ms", "elapsed", "elapsed_ms", "time_ms"}


def _scrub(obj, ws_root: str):
    """Zaman alanlarını at, workspace yolunu soyutla (iki koşu karşılaştırılabilsin)."""
    if isinstance(obj, dict):
        return {
            k: _scrub(v, ws_root) for k, v in obj.items()
            if k not in _VOLATILE_KEYS and not k.endswith("_duration")
        }
    if isinstance(obj, list):
        return [_scrub(v, ws_root) for v in obj]
    if isinstance(obj, (str, Path)):
        return str(obj).replace(ws_root, "<WS>")
    return obj


def _fingerprint(ctx: PipelineContext, result: StageResult) -> dict:
    ws_root = str(ctx.workspace.path)
    deob = ctx.workspace.get_stage_dir("deobfuscated")
    return {
        "success": result.success,
        "skipped": result.skipped,
        "errors": _scrub(result.errors, ws_root),
        "stats": _scrub(result.stats, ws_root),
        "artifacts": _scrub({k: str(v) for k, v in result.artifacts.items()}, ws_root),
        "files": {
            str(f.relative_to(deob)): hashlib.md5(f.read_bytes()).hexdigest()
            for f in _deob_files(ctx)
        },
    }


def _js_bundle_ctx(base: Path) -> PipelineContext:
    base.mkdir(parents=True, exist_ok=True)
    src = base / "sample_minified.js"
    shutil.copy2(_FIXTURE_JS, src)
    return _make_ctx(base, TargetType.JS_BUNDLE, path=src, language=Language.JAVASCRIPT)


def _electron_ctx(base: Path) -> PipelineContext:
    base.mkdir(parents=True, exist_ok=True)
    asar = base / "app.asar"
    asar.write_bytes(b"\x04\x00\x00\x00" + b"\x00" * 60)
    ctx = _make_ctx(base, TargetType.ELECTRON_APP, path=asar, language=Language.JAVASCRIPT)
    extracted = ctx.workspace.get_stage_dir("raw") / "asar_extracted"
    (extracted / "node_modules" / "dep").mkdir(parents=True)
    (extracted / "package.json").write_text('{"name": "fake", "main": "main.js"}')
    shutil.copy2(_FIXTURE_JS, extracted / "main.js")
    # node_modules altında daha büyük dosya: giriş çözümü onu SEÇMEMELİ
    (extracted / "node_modules" / "dep" / "index.js").write_text(_FIXTURE_JS.read_text() * 3)
    ctx.results["static"] = StageResult(
        stage_name="static", success=True, duration_seconds=0.0,
        stats={"main_js": str(extracted / "main.js")},
    )
    return ctx


@pytest.mark.skipif(not _js_toolchain_available(), reason="node veya scripts/node_modules yok")
class TestJsBehaviourNeutral:
    """execute() JS ailesinde yönlendirme öncesi yolla (doğrudan _execute_deep /
    _execute_legacy) BİREBİR aynı çıktıyı üretmeli: dosya md5'leri + stats + hatalar."""

    def test_js_bundle_deep_equals_direct_deep(self, tmp_path: Path):
        ctx_a = _js_bundle_ctx(tmp_path / "a")
        ctx_b = _js_bundle_ctx(tmp_path / "b")
        via_execute = DeobfuscationStage(use_deep=True).execute(ctx_a)
        direct = DeobfuscationStage(use_deep=True)._execute_deep(ctx_b, time.monotonic())
        fp = _fingerprint(ctx_a, via_execute)
        assert fp == _fingerprint(ctx_b, direct)
        assert fp["success"] is True and fp["files"]  # boş-boşa eşitlik değil

    def test_js_bundle_legacy_equals_direct_legacy(self, tmp_path: Path):
        ctx_a = _js_bundle_ctx(tmp_path / "a")
        ctx_b = _js_bundle_ctx(tmp_path / "b")
        via_execute = DeobfuscationStage(use_deep=False).execute(ctx_a)
        direct = DeobfuscationStage(use_deep=False)._execute_legacy(ctx_b, time.monotonic())
        fp = _fingerprint(ctx_a, via_execute)
        assert fp == _fingerprint(ctx_b, direct)
        assert fp["success"] is True and fp["files"]

    def test_electron_deep_equals_direct_deep(self, tmp_path: Path):
        ctx_a = _electron_ctx(tmp_path / "a")
        ctx_b = _electron_ctx(tmp_path / "b")
        via_execute = DeobfuscationStage(use_deep=True).execute(ctx_a)
        direct = DeobfuscationStage(use_deep=True)._execute_deep(ctx_b, time.monotonic())
        fp = _fingerprint(ctx_a, via_execute)
        assert fp == _fingerprint(ctx_b, direct)
        assert fp["success"] is True and fp["files"]
        # Giriş, node_modules'taki büyük dosya değil main.js (beklenen Electron davranışı)
        original = ctx_a.workspace.get_stage_dir("deobfuscated") / "00_original.js"
        assert original.read_bytes() == _FIXTURE_JS.read_bytes()
