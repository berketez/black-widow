"""
JavaScript Analyzer testleri.

Test senaryolari:
1. sample_minified.js uzerinde analyze_static
2. Gercek Claude Code CLI JS uzerinde analyze_static (dosya yoksa skip)
3. Beautify ciktisinin orijinalden uzun oldugunu dogrula
4. Webpack module sayisinin > 0 oldugunu dogrula
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from karadul.analyzers.javascript import JavaScriptAnalyzer
from karadul.config import Config
from karadul.core.target import Language, TargetDetector, TargetInfo, TargetType
from karadul.core.workspace import Workspace

# Fixtures dizini
FIXTURES_DIR = Path(__file__).parent / "fixtures"
SAMPLE_JS = FIXTURES_DIR / "sample_minified.js"

# Gercek Claude Code CLI bundle yolu (yoksa test skip edilir)
CLAUDE_CLI_BUNDLE = Path("/Applications/Claude.app/Contents/Resources/app.asar")

# Scripts dizini
SCRIPTS_DIR = Path(__file__).parent.parent / "scripts"


@pytest.fixture
def js_config() -> Config:
    """JS analyzer icin Config instance."""
    cfg = Config()
    cfg.scripts_dir = SCRIPTS_DIR
    return cfg


@pytest.fixture
def js_analyzer(js_config: Config) -> JavaScriptAnalyzer:
    """JavaScriptAnalyzer instance."""
    return JavaScriptAnalyzer(js_config)


@pytest.fixture
def sample_target() -> TargetInfo:
    """sample_minified.js icin TargetInfo."""
    detector = TargetDetector()
    return detector.detect(SAMPLE_JS)


@pytest.fixture
def sample_workspace(tmp_path: Path) -> Workspace:
    """Gecici workspace."""
    ws = Workspace(base_dir=tmp_path, target_name="sample_test")
    ws.create()
    return ws


def _check_node_modules() -> bool:
    """scripts/ altinda node_modules var mi kontrol et."""
    return (SCRIPTS_DIR / "node_modules").is_dir()


# -----------------------------------------------------------------------
# Test 1: sample_minified.js uzerinde analyze_static
# -----------------------------------------------------------------------

@pytest.mark.skipif(
    not _check_node_modules(),
    reason="scripts/node_modules kurulu degil (npm install yapilmali)",
)
class TestStaticAnalysis:
    """Statik analiz testleri."""

    def test_analyze_static_success(
        self,
        js_analyzer: JavaScriptAnalyzer,
        sample_target: TargetInfo,
        sample_workspace: Workspace,
    ) -> None:
        """analyze_static basariyla tamamlanir ve sonuc dondurur."""
        result = js_analyzer.analyze_static(sample_target, sample_workspace)

        assert result.success, f"Statik analiz basarisiz: {result.errors}"
        assert result.stage_name == "static"
        assert result.duration_seconds > 0

    def test_analyze_static_produces_artifacts(
        self,
        js_analyzer: JavaScriptAnalyzer,
        sample_target: TargetInfo,
        sample_workspace: Workspace,
    ) -> None:
        """analyze_static artifact dosyalari olusturur."""
        result = js_analyzer.analyze_static(sample_target, sample_workspace)

        assert "ast_analysis" in result.artifacts
        assert "raw_copy" in result.artifacts

        # AST analiz dosyasi gecerli JSON mi?
        ast_path = result.artifacts["ast_analysis"]
        assert ast_path.exists()
        with open(ast_path) as f:
            data = json.load(f)
        assert "stats" in data
        assert "functions" in data

    def test_analyze_static_stats(
        self,
        js_analyzer: JavaScriptAnalyzer,
        sample_target: TargetInfo,
        sample_workspace: Workspace,
    ) -> None:
        """analyze_static istatistikleri doldurur."""
        result = js_analyzer.analyze_static(sample_target, sample_workspace)

        stats = result.stats
        assert "functions" in stats
        assert "strings" in stats
        assert "total_lines" in stats
        assert stats["functions"] > 0, "En az 1 fonksiyon bulunmali"
        assert stats["total_lines"] > 0

    def test_analyze_static_finds_webpack(
        self,
        js_analyzer: JavaScriptAnalyzer,
        sample_target: TargetInfo,
        sample_workspace: Workspace,
    ) -> None:
        """sample_minified.js webpack bundle olarak tespit edilir."""
        result = js_analyzer.analyze_static(sample_target, sample_workspace)

        # Webpack module sayisi kontrol (sample dosyada 3 module var)
        assert result.stats.get("webpack_modules", 0) > 0, \
            "Webpack modulleri tespit edilmeli"

    def test_analyze_static_finds_strings(
        self,
        js_analyzer: JavaScriptAnalyzer,
        sample_target: TargetInfo,
        sample_workspace: Workspace,
    ) -> None:
        """analyze_static string literal'leri cikarir."""
        result = js_analyzer.analyze_static(sample_target, sample_workspace)

        assert result.stats.get("strings", 0) > 0, "String literal'ler bulunmali"
        # strings.json dosyasi olmali
        if "strings" in result.artifacts:
            str_path = result.artifacts["strings"]
            with open(str_path) as f:
                str_data = json.load(f)
            assert len(str_data["strings"]) > 0


# -----------------------------------------------------------------------
# Test 2: Gercek Claude Code CLI JS (skip if not exists)
# -----------------------------------------------------------------------

@pytest.mark.skipif(
    not CLAUDE_CLI_BUNDLE.exists(),
    reason="Claude.app bulunamadi (gercek hedef testi)",
)
@pytest.mark.skipif(
    not _check_node_modules(),
    reason="scripts/node_modules kurulu degil",
)
class TestRealTarget:
    """Gercek hedef uzerinde testler (varsa)."""

    def test_claude_app_detected(self) -> None:
        """Claude.app Electron app olarak tespit edilir.

        v1.2.x: APP_BUNDLE tipinde donup metadata.electron=True olur.
        """
        detector = TargetDetector()
        app_path = Path("/Applications/Claude.app")
        if app_path.exists():
            info = detector.detect(app_path)
            assert info.target_type == TargetType.APP_BUNDLE
            assert info.metadata.get("electron") is True


# -----------------------------------------------------------------------
# Test 3: Beautify ciktisi orijinalden uzun
# -----------------------------------------------------------------------

@pytest.mark.skipif(
    not _check_node_modules(),
    reason="scripts/node_modules kurulu degil",
)
class TestBeautify:
    """Beautify islem testleri."""

    def test_beautify_expands_output(
        self,
        js_analyzer: JavaScriptAnalyzer,
        sample_target: TargetInfo,
        sample_workspace: Workspace,
    ) -> None:
        """Beautify ciktisi orijinalden daha fazla satir icerir."""
        # Once statik analiz calistir (raw copy olusturur)
        js_analyzer.analyze_static(sample_target, sample_workspace)

        # Deobfuscate calistir (beautify yapar)
        result = js_analyzer.deobfuscate(sample_target, sample_workspace)

        assert result.success, f"Deobfuscation basarisiz: {result.errors}"
        assert "beautified" in result.artifacts

        beautified_path = result.artifacts["beautified"]
        assert beautified_path.exists()

        # Beautified dosya orijinalden daha fazla satir olmali
        original_lines = SAMPLE_JS.read_text().count("\n") + 1
        beautified_lines = beautified_path.read_text().count("\n") + 1

        assert beautified_lines >= original_lines, \
            f"Beautified ({beautified_lines}) >= original ({original_lines}) olmali"


# -----------------------------------------------------------------------
# Test 4: Webpack module sayisi > 0
# -----------------------------------------------------------------------

@pytest.mark.skipif(
    not _check_node_modules(),
    reason="scripts/node_modules kurulu degil",
)
class TestWebpackUnpack:
    """Webpack unpack testleri."""

    def test_webpack_modules_found(
        self,
        js_analyzer: JavaScriptAnalyzer,
        sample_target: TargetInfo,
        sample_workspace: Workspace,
    ) -> None:
        """Webpack unpack en az 1 modul cikarir."""
        # Statik analiz (webpack tespiti icin gerekli)
        static_result = js_analyzer.analyze_static(sample_target, sample_workspace)
        assert static_result.success

        # Deobfuscate (webpack unpack dahil)
        deob_result = js_analyzer.deobfuscate(sample_target, sample_workspace)

        # Webpack unpack sonuclari
        if deob_result.stats.get("webpack_unpack"):
            unpack_stats = deob_result.stats["webpack_unpack"]
            assert unpack_stats.get("modules_written", 0) > 0, \
                "En az 1 webpack modulu yazilmali"

            # Modul dosyalari mevcut mu?
            modules_dir = sample_workspace.get_stage_dir("deobfuscated") / "webpack_modules"
            if modules_dir.exists():
                module_files = list(modules_dir.glob("module_*.js"))
                assert len(module_files) > 0, "module_*.js dosyalari olmali"

    def test_webpack_module_content(
        self,
        js_analyzer: JavaScriptAnalyzer,
        sample_target: TargetInfo,
        sample_workspace: Workspace,
    ) -> None:
        """Webpack modulleri gecerli JS icerigi tasir."""
        js_analyzer.analyze_static(sample_target, sample_workspace)
        deob_result = js_analyzer.deobfuscate(sample_target, sample_workspace)

        modules_dir = sample_workspace.get_stage_dir("deobfuscated") / "webpack_modules"
        if modules_dir.exists():
            module_files = list(modules_dir.glob("module_*.js"))
            for mf in module_files:
                content = mf.read_text()
                # Her modul dosyasi header ile baslamali
                assert "Webpack Module" in content, \
                    f"{mf.name} header icermeli"
                # Bos olmamali
                assert len(content.strip()) > 50, \
                    f"{mf.name} anlamli icerik icermeli"


# -----------------------------------------------------------------------
# Yardimci: Node.js script'lerini dogrudan test et
# -----------------------------------------------------------------------

@pytest.mark.skipif(
    not _check_node_modules(),
    reason="scripts/node_modules kurulu degil",
)
class TestNodeScripts:
    """Node.js script'lerinin dogrudan calismasini test eder."""

    def test_deobfuscate_script_runs(self) -> None:
        """deobfuscate.mjs basarili calisir ve JSON uretir."""
        result = subprocess.run(
            ["node", str(SCRIPTS_DIR / "deobfuscate.mjs"), str(SAMPLE_JS)],
            capture_output=True,
            text=True,
            timeout=30,
            cwd=str(SCRIPTS_DIR),
        )
        assert result.returncode == 0, f"Script basarisiz: {result.stderr}"
        data = json.loads(result.stdout.strip())
        assert data["success"] is True
        assert data["stats"]["functions"] > 0

    def test_beautify_script_runs(self, tmp_path: Path) -> None:
        """beautify.mjs basarili calisir."""
        output_file = tmp_path / "beautified.js"
        result = subprocess.run(
            [
                "node",
                str(SCRIPTS_DIR / "beautify.mjs"),
                str(SAMPLE_JS),
                str(output_file),
            ],
            capture_output=True,
            text=True,
            timeout=30,
            cwd=str(SCRIPTS_DIR),
        )
        assert result.returncode == 0, f"Script basarisiz: {result.stderr}"
        data = json.loads(result.stdout.strip())
        assert data["success"] is True
        assert output_file.exists()

    def test_unpack_webpack_script_runs(self, tmp_path: Path) -> None:
        """unpack-webpack.mjs basarili calisir."""
        output_dir = tmp_path / "modules"
        result = subprocess.run(
            [
                "node",
                str(SCRIPTS_DIR / "unpack-webpack.mjs"),
                str(SAMPLE_JS),
                str(output_dir),
            ],
            capture_output=True,
            text=True,
            timeout=30,
            cwd=str(SCRIPTS_DIR),
        )
        assert result.returncode == 0, f"Script basarisiz: {result.stderr}"
        data = json.loads(result.stdout.strip())
        assert data["success"] is True
        assert data["stats"]["modules_written"] > 0
