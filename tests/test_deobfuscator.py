"""
Deobfuscation pipeline ve Electron analyzer testleri.

Test 1: SynchronyWrapper.is_available() -- True donmeli (kurulu)
Test 2: DeobfuscationManager chain sirasi -- beautify -> synchrony -> babel
Test 3: sample_minified.js uzerinde beautify adimi -- cikti daha uzun olmali
Test 4: Gercek Claude Code CLI uzerinde tam chain (skip if not exists)
Test 5: ElectronAnalyzer._find_asar() -- Claude Desktop varsa test et
Test 6: extract-modules.mjs sample webpack bundle uzerinde
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from karadul.config import Config
from karadul.core.workspace import Workspace
from karadul.deobfuscators.synchrony_wrapper import SynchronyWrapper
from karadul.deobfuscators.babel_pipeline import BabelPipeline
from karadul.deobfuscators.manager import DeobfuscationManager, DeobfuscationResult


# --- Fixtures ---

@pytest.fixture
def deob_config() -> Config:
    """Deobfuscation testleri icin Config."""
    return Config()


@pytest.fixture
def deob_workspace(tmp_path: Path) -> Workspace:
    """Gecici deobfuscation workspace."""
    ws = Workspace(tmp_path, "deob-test")
    ws.create()
    return ws


@pytest.fixture
def sample_minified_js() -> Path:
    """Test fixture: sample_minified.js."""
    p = Path(__file__).parent / "fixtures" / "sample_minified.js"
    if not p.exists():
        pytest.skip("sample_minified.js fixture bulunamadi")
    return p


@pytest.fixture
def sample_webpack_js(tmp_path: Path) -> Path:
    """Test icin webpack bundle formati JS dosyasi olustur."""
    js_content = """\
(function(e) {
    var t = {};
    function n(r) {
        if (t[r]) return t[r].exports;
        var o = t[r] = { i: r, l: false, exports: {} };
        return e[r].call(o.exports, o, o.exports, n), o.l = true, o.exports
    }
    n.m = e;
    n.c = t;
    n(n.s = 0);
})({
    0: function(e, t, n) {
        "use strict";
        var r = n(1);
        var o = n(2);
        console.log(r.greet(o.name));
    },
    1: function(e, t) {
        "use strict";
        t.greet = function(name) {
            return "Hello, " + name + "!";
        };
    },
    2: function(e, t) {
        "use strict";
        t.name = "Karadul";
        t.version = "3.0.0";
    }
});
"""
    js_file = tmp_path / "webpack_bundle.js"
    js_file.write_text(js_content, encoding="utf-8")
    return js_file


# ====================================================================
# Test 1: SynchronyWrapper.is_available()
# ====================================================================

class TestSynchronyWrapper:
    """SynchronyWrapper testleri."""

    def test_is_available(self, deob_config: Config) -> None:
        """synchrony kurulu ve calisabilir olmali."""
        wrapper = SynchronyWrapper(deob_config)
        # /opt/homebrew/bin/synchrony mevcut
        assert wrapper.is_available() is True

    def test_deobfuscate_simple(
        self,
        deob_config: Config,
        sample_minified_js: Path,
        tmp_path: Path,
    ) -> None:
        """synchrony basit bir JS dosyasini deobfuscate edebilmeli."""
        wrapper = SynchronyWrapper(deob_config)
        if not wrapper.is_available():
            pytest.skip("synchrony mevcut degil")

        output = tmp_path / "deobfuscated.js"
        result = wrapper.deobfuscate(sample_minified_js, output)

        # synchrony basarili olabilir veya olmayabilir (dosya obfuscated olmayabilir)
        # Ama en azindan hata firlatmamali
        assert isinstance(result, bool)

    def test_deobfuscate_nonexistent_input(
        self,
        deob_config: Config,
        tmp_path: Path,
    ) -> None:
        """Varolmayan dosya icin False donmeli."""
        wrapper = SynchronyWrapper(deob_config)
        if not wrapper.is_available():
            pytest.skip("synchrony mevcut degil")

        output = tmp_path / "output.js"
        result = wrapper.deobfuscate(
            tmp_path / "nonexistent.js",
            output,
        )
        assert result is False


# ====================================================================
# Test 2: DeobfuscationManager chain sirasi
# ====================================================================

class TestDeobfuscationManager:
    """DeobfuscationManager testleri."""

    def test_default_chain_order(self, deob_config: Config) -> None:
        """Config'deki default zincir sirasi: beautify -> synchrony -> babel_transforms."""
        expected = ["beautify", "synchrony", "babel_transforms"]
        assert deob_config.analysis.deobfuscation_chain == expected

    def test_custom_chain(
        self,
        deob_config: Config,
        sample_minified_js: Path,
        deob_workspace: Workspace,
    ) -> None:
        """Ozel zincir sirasi ile calistirilabilmeli."""
        manager = DeobfuscationManager(deob_config)
        result = manager.run_chain(
            sample_minified_js,
            deob_workspace,
            chain=["beautify"],
        )
        assert isinstance(result, DeobfuscationResult)
        assert result.duration_seconds >= 0

    def test_nonexistent_input(
        self,
        deob_config: Config,
        deob_workspace: Workspace,
        tmp_path: Path,
    ) -> None:
        """Varolmayan girdi dosyasi icin basarisiz sonuc."""
        manager = DeobfuscationManager(deob_config)
        result = manager.run_chain(
            tmp_path / "does_not_exist.js",
            deob_workspace,
        )
        assert result.success is False
        assert "init" in result.steps_failed

    def test_unknown_step_filtered(
        self,
        deob_config: Config,
        sample_minified_js: Path,
        deob_workspace: Workspace,
    ) -> None:
        """Bilinmeyen adimlar filtrelenmeli."""
        manager = DeobfuscationManager(deob_config)
        result = manager.run_chain(
            sample_minified_js,
            deob_workspace,
            chain=["beautify", "unknown_step_xyz"],
        )
        # unknown_step_xyz filtrelenmeli, beautify calismali
        assert "unknown_step_xyz" not in result.steps_completed
        assert "unknown_step_xyz" not in result.steps_failed


# ====================================================================
# Test 3: Beautify adimi -- cikti daha uzun olmali
# ====================================================================

class TestBeautifyStep:
    """Beautify adimi testleri."""

    def test_beautify_expands_output(
        self,
        deob_config: Config,
        deob_workspace: Workspace,
    ) -> None:
        """Beautify adimi: cikti satir sayisi girdi satir sayisindan fazla olmali."""
        # Tek satirlik minified JS olustur
        minified = (
            'var a=1;var b=2;function c(d,e){return d+e}'
            'var f=c(a,b);console.log(f);'
            'if(f>2){console.log("yes")}else{console.log("no")}'
        )
        js_file = deob_workspace.path / "test_minified.js"
        js_file.write_text(minified, encoding="utf-8")

        input_lines = minified.count("\n") + 1
        assert input_lines <= 3  # Minified: 1-3 satir

        manager = DeobfuscationManager(deob_config)
        result = manager.run_chain(
            js_file,
            deob_workspace,
            chain=["beautify"],
        )

        # beautify.mjs mevcut degilse atlayabilir
        if "beautify" in result.steps_completed and result.output_file:
            output_text = result.output_file.read_text(encoding="utf-8")
            output_lines = output_text.count("\n") + 1
            assert output_lines > input_lines, (
                f"Beautify cikti ({output_lines} satir) "
                f"girdiden ({input_lines} satir) uzun olmali"
            )

    def test_beautify_with_sample_minified(
        self,
        deob_config: Config,
        sample_minified_js: Path,
        deob_workspace: Workspace,
    ) -> None:
        """sample_minified.js uzerinde beautify."""
        manager = DeobfuscationManager(deob_config)
        result = manager.run_chain(
            sample_minified_js,
            deob_workspace,
            chain=["beautify"],
        )

        assert isinstance(result, DeobfuscationResult)
        assert result.duration_seconds >= 0

        if "beautify" in result.steps_completed:
            assert result.output_file is not None
            assert result.output_file.exists()
            # Cikti bos olmamali
            assert result.output_file.stat().st_size > 0


# ====================================================================
# Test 4: Gercek Claude Code CLI uzerinde tam chain
# ====================================================================

CLAUDE_CODE_CLI = Path(
    "/Users/apple/.local/bin/claude"
)


class TestFullChainClaudeCode:
    """Claude Code CLI uzerinde tam deobfuscation chain testi."""

    @pytest.mark.skipif(
        not CLAUDE_CODE_CLI.exists(),
        reason="Claude Code CLI bulunamadi",
    )
    def test_full_chain_claude_code(
        self,
        deob_config: Config,
        deob_workspace: Workspace,
    ) -> None:
        """Claude Code CLI uzerinde beautify -> synchrony chain."""
        manager = DeobfuscationManager(deob_config)

        # Sadece beautify + synchrony (babel_transforms scripti yoksa basarisiz olur)
        result = manager.run_chain(
            CLAUDE_CODE_CLI,
            deob_workspace,
            chain=["beautify", "synchrony"],
        )

        assert isinstance(result, DeobfuscationResult)
        assert result.duration_seconds > 0

        # En az bir adim basarili olmali
        assert len(result.steps_completed) >= 1, (
            f"En az bir adim basarili olmali: "
            f"completed={result.steps_completed}, "
            f"failed={result.steps_failed}"
        )

        # Original boyut kaydi
        assert "original_size" in result.stats
        assert result.stats["original_size"] > 1_000_000  # 9MB+ dosya

        print(f"\nClaude Code CLI deobfuscation sonucu:")
        print(f"  {result.summary()}")
        print(f"  Stats: {json.dumps(result.stats, indent=2, default=str)}")


# ====================================================================
# Test 5: ElectronAnalyzer._find_asar()
# ====================================================================

CLAUDE_DESKTOP_APP = Path("/Applications/Claude.app")


class TestElectronAnalyzer:
    """ElectronAnalyzer testleri."""

    @pytest.mark.skipif(
        not CLAUDE_DESKTOP_APP.exists(),
        reason="Claude Desktop app bulunamadi",
    )
    def test_find_asar_claude_desktop(self, deob_config: Config) -> None:
        """Claude Desktop .app icinde app.asar bulunmali."""
        from karadul.analyzers.electron import ElectronAnalyzer

        analyzer = ElectronAnalyzer(deob_config)
        asar_path = analyzer._find_asar(CLAUDE_DESKTOP_APP)

        assert asar_path is not None, "Claude Desktop icinde app.asar bulunamadi"
        assert asar_path.exists()
        assert asar_path.name == "app.asar"
        assert asar_path.stat().st_size > 0

        print(f"\nClaude Desktop ASAR: {asar_path}")
        print(f"  Boyut: {asar_path.stat().st_size:,} bytes")

    def test_find_asar_nonexistent(self, deob_config: Config, tmp_path: Path) -> None:
        """Varolmayan .app icin None donmeli."""
        from karadul.analyzers.electron import ElectronAnalyzer

        analyzer = ElectronAnalyzer(deob_config)
        fake_app = tmp_path / "FakeApp.app"
        fake_app.mkdir()
        (fake_app / "Contents" / "Resources").mkdir(parents=True)

        result = analyzer._find_asar(fake_app)
        assert result is None

    def test_find_asar_direct_asar_file(
        self, deob_config: Config, tmp_path: Path,
    ) -> None:
        """.asar dosyasi dogrudan verildiginde o dosyayi dondurmeli."""
        from karadul.analyzers.electron import ElectronAnalyzer

        analyzer = ElectronAnalyzer(deob_config)
        asar_file = tmp_path / "test.asar"
        asar_file.write_bytes(b"ASAR content")

        result = analyzer._find_asar(asar_file)
        assert result == asar_file

    def test_find_js_files(
        self, deob_config: Config, tmp_path: Path,
    ) -> None:
        """JS dosyalarini bulma ve filtreleme testi."""
        from karadul.analyzers.electron import ElectronAnalyzer

        analyzer = ElectronAnalyzer(deob_config)

        # Test dizin yapisi olustur
        (tmp_path / "dist").mkdir()
        (tmp_path / "node_modules").mkdir()
        (tmp_path / "dist" / "main.js").write_text("console.log('main')" * 10)
        (tmp_path / "dist" / "utils.js").write_text("export const x = 1;" * 10)
        (tmp_path / "node_modules" / "dep.js").write_text("module.exports = {}")
        (tmp_path / "tiny.js").write_text("x")  # Cok kucuk, filtrelenmeli

        js_files = analyzer._find_js_files(tmp_path, min_size=10)

        # node_modules atlanmali
        file_names = [f.name for f in js_files]
        assert "dep.js" not in file_names
        # Kucuk dosya filtrelenmeli
        assert "tiny.js" not in file_names
        # Buyuk dosyalar bulunmali
        assert "main.js" in file_names
        assert "utils.js" in file_names


# ====================================================================
# Test 6: extract-modules.mjs
# ====================================================================

class TestExtractModules:
    """extract-modules.mjs script testi."""

    def test_extract_webpack_modules(
        self,
        deob_config: Config,
        sample_webpack_js: Path,
        tmp_path: Path,
    ) -> None:
        """Webpack bundle'dan modulleri cikarma."""
        from karadul.core.subprocess_runner import SubprocessRunner

        runner = SubprocessRunner(deob_config)
        extract_script = deob_config.scripts_dir / "extract-modules.mjs"

        if not extract_script.exists():
            pytest.skip("extract-modules.mjs bulunamadi")

        output_dir = tmp_path / "modules_output"

        result = runner.run_node_script(
            extract_script,
            args=[str(sample_webpack_js), str(output_dir)],
            timeout=30,
        )

        assert result["success"] is True
        assert result["total_modules"] >= 2, (
            f"En az 2 modul bekleniyor, bulundu: {result['total_modules']}"
        )

        # Dependency graph olmali
        assert "dependency_graph" in result
        assert isinstance(result["dependency_graph"], dict)

        # Modul dosyalari olusturulmus olmali
        module_files = list(output_dir.glob("module_*.js"))
        assert len(module_files) >= 2

        # dependency_graph.json dosyasi olmali
        dep_graph_file = output_dir / "dependency_graph.json"
        assert dep_graph_file.exists()

        # Her modul dosyasinda header yorum olmali
        for mf in module_files:
            content = mf.read_text(encoding="utf-8")
            assert content.startswith("/* Module ID:"), (
                f"{mf.name} header yorumu eksik"
            )

        print(f"\nExtract modules sonucu:")
        print(f"  Toplam modul: {result['total_modules']}")
        print(f"  Entry point: {result.get('entry_point')}")
        print(f"  Bundle format: {result.get('bundle_format')}")
        print(f"  Dependency graph: {json.dumps(result['dependency_graph'], indent=2)}")

    def test_extract_from_sample_minified(
        self,
        deob_config: Config,
        sample_minified_js: Path,
        tmp_path: Path,
    ) -> None:
        """sample_minified.js (webpack bundle) uzerinde module extraction."""
        from karadul.core.subprocess_runner import SubprocessRunner

        runner = SubprocessRunner(deob_config)
        extract_script = deob_config.scripts_dir / "extract-modules.mjs"

        if not extract_script.exists():
            pytest.skip("extract-modules.mjs bulunamadi")

        output_dir = tmp_path / "fixture_modules"

        result = runner.run_node_script(
            extract_script,
            args=[str(sample_minified_js), str(output_dir)],
            timeout=30,
        )

        assert result["success"] is True
        assert result["total_modules"] >= 3, (
            f"sample_minified.js 3 modul icermeli, bulundu: {result['total_modules']}"
        )


# ====================================================================
# Test 7: DeobfuscationResult repr ve summary
# ====================================================================

class TestDeobfuscationResult:
    """DeobfuscationResult dataclass testleri."""

    def test_summary(self) -> None:
        """Summary string formati."""
        result = DeobfuscationResult(
            success=True,
            steps_completed=["beautify", "synchrony"],
            steps_failed=["babel_transforms"],
            steps_skipped=[],
            duration_seconds=5.3,
        )
        summary = result.summary()
        assert "SUCCESS" in summary
        assert "2 completed" in summary
        assert "1 failed" in summary

    def test_repr(self) -> None:
        """repr formati."""
        result = DeobfuscationResult(success=False)
        r = repr(result)
        assert "DeobfuscationResult" in r
        assert "success=False" in r
