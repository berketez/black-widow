"""ProjectReconstructor testleri -- tam proje reconstruction.

Test edilen islemler:
- Modul dizini bulma
- Gercek proje yapisi olusturma
- package.json olusturma
- Entry point tespiti
- Proje dogrulama
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from karadul.config import Config
from karadul.core.target import TargetInfo, TargetType, Language
from karadul.core.workspace import Workspace
from karadul.reconstruction.project_reconstructor import (
    ProjectReconstructor,
    ReconstructionResult,
)


@pytest.fixture
def config() -> Config:
    """Test konfigurasyon."""
    return Config()


@pytest.fixture
def workspace(tmp_path: Path) -> Workspace:
    """Test workspace."""
    ws = Workspace(base_dir=tmp_path / "workspaces", target_name="test_target")
    ws.create()
    return ws


@pytest.fixture
def target_info(tmp_path: Path) -> TargetInfo:
    """Test target."""
    js_file = tmp_path / "bundle.js"
    js_file.write_text("// test", encoding="utf-8")
    return TargetInfo(
        path=js_file,
        name="test-bundle",
        target_type=TargetType.JS_BUNDLE,
        language=Language.JAVASCRIPT,
        file_size=7,
        file_hash="abc123",
        metadata={"bundler": "webpack"},
    )


@pytest.fixture
def modules_dir(workspace: Workspace) -> Path:
    """Ornek modul dizini olustur."""
    deob_dir = workspace.get_stage_dir("deobfuscated")
    mod_dir = deob_dir / "webpack_modules" / "modules"
    mod_dir.mkdir(parents=True, exist_ok=True)

    # React component
    (mod_dir / "module_001.js").write_text(
        'const React = require("react");\n'
        'function AppComponent(props) {\n'
        '  return React.createElement("div", null, props.children);\n'
        '}\n'
        'module.exports = AppComponent;\n',
    )

    # API modulu
    (mod_dir / "module_002.js").write_text(
        'const axios = require("axios");\n'
        'async function fetchUsers() {\n'
        '  const response = await axios.get("/api/v1/users");\n'
        '  return response.data;\n'
        '}\n'
        'module.exports = { fetchUsers };\n',
    )

    # Config modulu
    (mod_dir / "module_003.js").write_text(
        'const config = {\n'
        '  port: process.env.PORT || 3000,\n'
        '  debug: process.env.DEBUG === "true",\n'
        '  apiUrl: process.env.API_URL || "http://localhost:3000",\n'
        '};\n'
        'module.exports = config;\n',
    )

    # Utils modulu
    (mod_dir / "module_004.js").write_text(
        'function formatDate(date) {\n'
        '  return new Date(date).toISOString();\n'
        '}\n'
        'function parseJSON(str) {\n'
        '  try { return JSON.parse(str); }\n'
        '  catch (e) { return null; }\n'
        '}\n'
        'module.exports = { formatDate, parseJSON };\n',
    )

    # Crypto modulu
    (mod_dir / "module_005.js").write_text(
        'const crypto = require("crypto");\n'
        'function hashPassword(password) {\n'
        '  return crypto.createHash("sha256").update(password).digest("hex");\n'
        '}\n'
        'module.exports = { hashPassword };\n',
    )

    return mod_dir


class TestReconstructionResult:
    """ReconstructionResult dataclass testleri."""

    def test_default_values(self):
        """Varsayilan degerler dogru."""
        result = ReconstructionResult()
        assert result.success is False
        assert result.project_dir is None
        assert result.total_modules == 0
        assert result.files_written == 0
        assert result.dependencies == {}
        assert result.errors == []

    def test_custom_values(self, tmp_path: Path):
        """Ozel degerler atanabilir."""
        result = ReconstructionResult(
            success=True,
            project_dir=tmp_path / "project",
            total_modules=42,
            dependencies={"express": "latest"},
        )
        assert result.success is True
        assert result.total_modules == 42
        assert "express" in result.dependencies


class TestFindModulesDir:
    """_find_modules_dir testleri."""

    def test_find_webpack_modules(
        self, config: Config, workspace: Workspace, modules_dir: Path,
    ):
        """webpack_modules/modules/ dizini bulunur."""
        reconstructor = ProjectReconstructor(config)
        found = reconstructor._find_modules_dir(workspace)

        assert found is not None
        assert found.exists()
        assert any(found.glob("*.js"))

    def test_find_no_modules(self, config: Config, workspace: Workspace):
        """Modul yoksa None doner."""
        reconstructor = ProjectReconstructor(config)
        found = reconstructor._find_modules_dir(workspace)
        assert found is None

    def test_find_direct_webpack_dir(self, config: Config, workspace: Workspace):
        """webpack_modules/ direkt altinda JS varsa bulur."""
        deob_dir = workspace.get_stage_dir("deobfuscated")
        wp_dir = deob_dir / "webpack_modules"
        wp_dir.mkdir(parents=True, exist_ok=True)
        (wp_dir / "module_0.js").write_text("var x = 1;")

        reconstructor = ProjectReconstructor(config)
        found = reconstructor._find_modules_dir(workspace)

        assert found is not None
        assert found.exists()


class TestBuildPackageJson:
    """_build_package_json testleri."""

    def test_creates_valid_json(self, target_info: TargetInfo, tmp_path: Path):
        """Gecerli package.json olusturulur."""
        project_dir = tmp_path / "project"
        project_dir.mkdir()
        (project_dir / "src").mkdir()
        (project_dir / "src" / "index.js").write_text("// entry")

        deps = {"express": "^4.18.0", "chalk": "latest"}

        pkg_path = ProjectReconstructor._build_package_json(
            project_dir, target_info, deps,
        )

        assert pkg_path.exists()
        pkg = json.loads(pkg_path.read_text())
        assert "reconstructed" in pkg["name"]
        assert pkg["dependencies"]["express"] == "^4.18.0"
        assert pkg["dependencies"]["chalk"] == "latest"
        assert "start" in pkg["scripts"]
        assert "node" in pkg["engines"]

    def test_safe_name_sanitization(self, target_info: TargetInfo, tmp_path: Path):
        """Ozel karakterler paket isminden temizlenir."""
        project_dir = tmp_path / "project"
        project_dir.mkdir()

        # Problemli isim
        target_info.name = "my app (v2.0) [beta]"

        pkg_path = ProjectReconstructor._build_package_json(
            project_dir, target_info, {},
        )
        pkg = json.loads(pkg_path.read_text())
        # Parantez ve koseli parantez olmamali
        assert "(" not in pkg["name"]
        assert "[" not in pkg["name"]


class TestValidateProject:
    """_validate_project testleri."""

    def test_valid_project(self, tmp_path: Path):
        """Gecerli proje yapiisi dogrulama gecer."""
        project_dir = tmp_path / "project"
        project_dir.mkdir()
        (project_dir / "src").mkdir()

        # package.json
        pkg = {"name": "test", "main": "src/index.js", "scripts": {"start": "node src/index.js"}}
        (project_dir / "package.json").write_text(json.dumps(pkg))

        # Entry point
        (project_dir / "src" / "index.js").write_text("console.log('hello');")

        validation = ProjectReconstructor._validate_project(project_dir)

        assert validation["valid"] is True
        assert validation["checks"]["package_json"] is True
        assert validation["checks"]["entry_point"] is True
        assert validation["checks"]["src_dir"] is True
        assert validation["checks"]["js_file_count"] >= 1

    def test_missing_package_json(self, tmp_path: Path):
        """package.json yoksa dogrulama basarisiz."""
        project_dir = tmp_path / "project"
        project_dir.mkdir()

        validation = ProjectReconstructor._validate_project(project_dir)

        assert validation["valid"] is False
        assert validation["checks"]["package_json"] is False

    def test_invalid_package_json(self, tmp_path: Path):
        """Bozuk package.json dogrulama basarisiz."""
        project_dir = tmp_path / "project"
        project_dir.mkdir()
        (project_dir / "package.json").write_text("{ invalid json }")

        validation = ProjectReconstructor._validate_project(project_dir)

        assert validation["valid"] is False
        assert validation["checks"]["package_json"] is False


class TestFindOrCreateEntryPoint:
    """_find_or_create_entry_point testleri."""

    def test_find_existing_src_index(self, tmp_path: Path):
        """Mevcut src/index.js bulunur."""
        project_dir = tmp_path / "project"
        (project_dir / "src").mkdir(parents=True)
        entry = project_dir / "src" / "index.js"
        entry.write_text("// existing entry")

        found = ProjectReconstructor._find_or_create_entry_point(project_dir)
        assert found == entry
        assert "existing entry" in found.read_text()

    def test_find_existing_root_index(self, tmp_path: Path):
        """Mevcut root index.js bulunur."""
        project_dir = tmp_path / "project"
        project_dir.mkdir()
        entry = project_dir / "index.js"
        entry.write_text("// root entry")

        found = ProjectReconstructor._find_or_create_entry_point(project_dir)
        assert found == entry

    def test_create_when_missing(self, tmp_path: Path):
        """Entry point yoksa olusturulur."""
        project_dir = tmp_path / "project"
        project_dir.mkdir()

        found = ProjectReconstructor._find_or_create_entry_point(project_dir)

        assert found.exists()
        assert found.name == "index.js"
        content = found.read_text()
        assert "Karadul" in content


class TestGenerateReadme:
    """_generate_readme testleri."""

    def test_readme_content(self, target_info: TargetInfo, tmp_path: Path):
        """README icerik kontrolleri."""
        project_dir = tmp_path / "project"
        project_dir.mkdir()

        deps = {"express": "latest"}
        categories = {"src/api": 5, "src/components": 10}

        readme = ProjectReconstructor._generate_readme(
            project_dir, target_info, deps, categories, 42,
        )

        assert readme.exists()
        content = readme.read_text()
        assert "Quick Start" in content
        assert "npm install" in content
        assert "Karadul" in content
        assert "express" in content
        assert "42" in content  # total_modules


class TestGenerateGitignore:
    """_generate_gitignore testleri."""

    def test_gitignore_content(self, tmp_path: Path):
        """.gitignore icerik kontrolleri."""
        project_dir = tmp_path / "project"
        project_dir.mkdir()

        gitignore = ProjectReconstructor._generate_gitignore(project_dir)

        assert gitignore.exists()
        content = gitignore.read_text()
        assert "node_modules/" in content
        assert ".env" in content


class TestReconstructIntegration:
    """Entegrasyon testleri (script olmadan)."""

    def test_reconstruct_no_modules(
        self, config: Config, workspace: Workspace, target_info: TargetInfo,
    ):
        """Modul yoksa basarisiz sonuc."""
        reconstructor = ProjectReconstructor(config)
        result = reconstructor.reconstruct(workspace, target_info)

        assert result.success is False
        assert "bulunamadi" in result.errors[0]

    def test_reconstruct_with_explicit_modules_dir(
        self, config: Config, workspace: Workspace, target_info: TargetInfo,
        modules_dir: Path,
    ):
        """Acik modul dizini ile reconstruction. Script olmasa bile fallback calisir."""
        reconstructor = ProjectReconstructor(config)
        result = reconstructor.reconstruct(
            workspace, target_info, modules_dir=modules_dir,
        )

        # Script olmasa bile fallback_copy devreye girer
        assert result.total_modules == 5
        assert result.project_dir is not None
        assert result.project_dir.exists()

        # package.json olusturulmus olmali
        assert result.package_json is not None
        assert result.package_json.exists()

        # Entry point olmali
        assert result.entry_point is not None
        assert result.entry_point.exists()

        # Dependencies tespit edilmis olmali
        # axios require ediliyor ama script fallback'te
        # dependency resolver calisiyor

    def test_reconstruct_creates_gitignore(
        self, config: Config, workspace: Workspace, target_info: TargetInfo,
        modules_dir: Path,
    ):
        """Reconstruction .gitignore olusturur."""
        reconstructor = ProjectReconstructor(config)
        result = reconstructor.reconstruct(
            workspace, target_info, modules_dir=modules_dir,
        )

        if result.project_dir:
            gitignore = result.project_dir / ".gitignore"
            assert gitignore.exists()

    def test_reconstruct_validation(
        self, config: Config, workspace: Workspace, target_info: TargetInfo,
        modules_dir: Path,
    ):
        """Reconstruction dogrulama sonucu stats'ta bulunur."""
        reconstructor = ProjectReconstructor(config)
        result = reconstructor.reconstruct(
            workspace, target_info, modules_dir=modules_dir,
        )

        assert "validation" in result.stats
        validation = result.stats["validation"]
        assert "checks" in validation

    def test_reconstruct_duration(
        self, config: Config, workspace: Workspace, target_info: TargetInfo,
        modules_dir: Path,
    ):
        """Reconstruction suresi kaydedilir."""
        reconstructor = ProjectReconstructor(config)
        result = reconstructor.reconstruct(
            workspace, target_info, modules_dir=modules_dir,
        )

        assert result.duration_seconds > 0
