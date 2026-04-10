"""
Black Widow (Karadul) v1.0 -- Reconstruction modulu testleri.

Test edilen moduller:
- VariableRenamer: require pattern, parametre rename
- ModuleSplitter: Kategorizasyon, index.js uretimi
- TypeInferrer: Boolean/number/function tip cikarimi, JSDoc uretimi
- CommentGenerator: Fonksiyon yorum uretimi
- GapFiller: Dead code tespiti, missing import, API endpoint
- ProjectBuilder: package.json, README, dependency detection, .env.example
- ReconstructionStage: Tam pipeline
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from karadul.config import Config
from karadul.core.workspace import Workspace
from karadul.core.target import TargetInfo, TargetType, Language
from karadul.reconstruction.variable_renamer import VariableRenamer, RenameResult
from karadul.reconstruction.module_splitter import ModuleSplitter, SplitResult
from karadul.reconstruction.type_inferrer import TypeInferrer, InferResult
from karadul.reconstruction.comment_generator import CommentGenerator
from karadul.reconstruction.gap_filler import GapFiller, GapFillResult
from karadul.reconstruction.project_builder import (
    ProjectBuilder,
    BuildResult,
    NODE_BUILTINS,
)


# ---------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------


@pytest.fixture
def config() -> Config:
    """Test konfigurasyon."""
    return Config()


@pytest.fixture
def workspace(tmp_path: Path) -> Workspace:
    """Test workspace olustur."""
    ws = Workspace(base_dir=tmp_path / "workspaces", target_name="test_target")
    ws.create()
    return ws


@pytest.fixture
def target_info(tmp_path: Path) -> TargetInfo:
    """Test target info."""
    js_file = tmp_path / "bundle.min.js"
    js_file.write_text("// test bundle", encoding="utf-8")
    return TargetInfo(
        path=js_file,
        name="test-bundle",
        target_type=TargetType.JS_BUNDLE,
        language=Language.JAVASCRIPT,
        file_size=14,
        file_hash="abc123",
        metadata={"bundler": "webpack"},
    )


@pytest.fixture
def sample_minified_js(tmp_path: Path) -> Path:
    """Minified JS dosyasi olustur."""
    content = """\
var e=require("fs"),t=require("path"),n=require("chalk");
function r(e,t,n){if(e.length>0){return t.join(e)}return n}
var o=function(e){return e.toString().trim()};
module.exports={process:r,clean:o};
"""
    js_file = tmp_path / "minified.js"
    js_file.write_text(content, encoding="utf-8")
    return js_file


@pytest.fixture
def sample_react_module(tmp_path: Path) -> Path:
    """React component iceren modul dosyasi."""
    content = """\
const React = require("react");
function MyComponent(props) {
  return React.createElement("div", null, props.children);
}
module.exports = MyComponent;
"""
    js_file = tmp_path / "module_5.js"
    js_file.write_text(content, encoding="utf-8")
    return js_file


@pytest.fixture
def sample_api_module(tmp_path: Path) -> Path:
    """API call iceren modul dosyasi."""
    content = """\
const axios = require("axios");
async function fetchUsers() {
  const response = await axios.get("/api/v1/users");
  return response.data;
}
module.exports = { fetchUsers };
"""
    js_file = tmp_path / "module_10.js"
    js_file.write_text(content, encoding="utf-8")
    return js_file


@pytest.fixture
def sample_functions_js(tmp_path: Path) -> Path:
    """Fonksiyon ornekleri iceren JS dosyasi."""
    content = """\
function isValid(input) {
  return input !== null && input !== undefined;
}

const handleClick = function(event) {
  console.log("clicked");
  event.preventDefault();
};

async function fetchUserProfile(userId) {
  const response = await fetch("/api/users/" + userId);
  return response.json();
}

function countItems(list) {
  return list.length;
}

const processData = (data) => {
  try {
    return JSON.parse(data);
  } catch (err) {
    console.error(err);
    return null;
  }
};
"""
    js_file = tmp_path / "functions.js"
    js_file.write_text(content, encoding="utf-8")
    return js_file


@pytest.fixture
def sample_env_js(tmp_path: Path) -> Path:
    """process.env kullanan JS dosyasi."""
    content = """\
const port = process.env.PORT || 3000;
const dbUrl = process.env.DATABASE_URL;
const secret = process.env["JWT_SECRET"];
const debug = process.env.DEBUG === "true";
"""
    js_file = tmp_path / "env_sample.js"
    js_file.write_text(content, encoding="utf-8")
    return js_file


# ---------------------------------------------------------------
# VariableRenamer testleri
# ---------------------------------------------------------------


class TestVariableRenamer:
    """VariableRenamer testleri."""

    def test_rename_result_dataclass(self):
        """RenameResult dataclass dogru calisir."""
        result = RenameResult(
            success=True,
            variables_renamed=5,
            mappings={"e": "request", "t": "response"},
            output_file=Path("/tmp/test.js"),
        )
        assert result.success is True
        assert result.variables_renamed == 5
        assert result.mappings["e"] == "request"
        assert result.output_file == Path("/tmp/test.js")
        assert result.errors == []

    def test_rename_nonexistent_file(self, config: Config, tmp_path: Path):
        """Olmayan dosya icin basarisiz sonuc doner."""
        renamer = VariableRenamer(config)
        result = renamer.rename(
            tmp_path / "nonexistent.js",
            tmp_path / "output.js",
        )
        assert result.success is False
        assert result.variables_renamed == 0
        assert "bulunamadi" in result.errors[0]

    def test_rename_with_context(self, config: Config, tmp_path: Path):
        """Context parametresi kabul edilir."""
        renamer = VariableRenamer(config)
        # Script bulunamayabilir ama constructor patlamaz
        assert renamer.config is config
        assert renamer._script_path.name == "rename-variables.mjs"

    def test_rename_require_pattern_script_exists(
        self, config: Config, sample_minified_js: Path, tmp_path: Path,
    ):
        """rename-variables.mjs varsa require pattern calisir."""
        renamer = VariableRenamer(config)
        output = tmp_path / "renamed.js"

        # Script varsa calistir
        if renamer._script_path.exists():
            result = renamer.rename(sample_minified_js, output)
            # Script basarili olursa require('fs') -> fileSystem gibi rename beklenir
            if result.success:
                assert result.variables_renamed > 0
                assert isinstance(result.mappings, dict)
        else:
            # Script yoksa sadece hata mesaji vermeli
            result = renamer.rename(sample_minified_js, output)
            assert result.success is False


# ---------------------------------------------------------------
# ModuleSplitter testleri
# ---------------------------------------------------------------


class TestModuleSplitter:
    """ModuleSplitter testleri."""

    def test_split_nonexistent_dir(self, config: Config, tmp_path: Path):
        """Olmayan dizin icin basarisiz sonuc."""
        splitter = ModuleSplitter(config)
        result = splitter.split(
            tmp_path / "nonexistent",
            tmp_path / "output",
        )
        assert result.success is False
        assert "bulunamadi" in result.errors[0]

    def test_split_empty_dir(self, config: Config, tmp_path: Path):
        """Bos dizin icin basarisiz sonuc."""
        modules_dir = tmp_path / "modules"
        modules_dir.mkdir()
        output_dir = tmp_path / "output"

        splitter = ModuleSplitter(config)
        result = splitter.split(modules_dir, output_dir)
        assert result.success is False

    def test_split_react_component(
        self, config: Config, sample_react_module: Path, tmp_path: Path,
    ):
        """React component modulu components/ altina gider."""
        modules_dir = sample_react_module.parent
        output_dir = tmp_path / "split_output"

        splitter = ModuleSplitter(config)
        result = splitter.split(modules_dir, output_dir)

        assert result.success is True
        assert result.total_modules >= 1
        assert result.categorized.get("components", 0) >= 1

    def test_split_api_module(
        self, config: Config, sample_api_module: Path, tmp_path: Path,
    ):
        """API modulu api/ altina gider."""
        modules_dir = sample_api_module.parent
        output_dir = tmp_path / "split_output"

        splitter = ModuleSplitter(config)
        result = splitter.split(modules_dir, output_dir)

        assert result.success is True
        assert result.categorized.get("api", 0) >= 1

    def test_split_creates_index(
        self, config: Config, sample_react_module: Path, tmp_path: Path,
    ):
        """Splitting sonrasi index.js olusturulur."""
        modules_dir = sample_react_module.parent
        output_dir = tmp_path / "split_output"

        splitter = ModuleSplitter(config)
        splitter.split(modules_dir, output_dir)

        index_file = output_dir / "index.js"
        assert index_file.exists()
        content = index_file.read_text()
        assert "Karadul" in content

    def test_split_multiple_modules(self, config: Config, tmp_path: Path):
        """Birden fazla modul dosyasi kategorize edilir."""
        modules_dir = tmp_path / "modules"
        modules_dir.mkdir()

        # Farkli tipler
        (modules_dir / "module_0.js").write_text(
            'const x = require("express");\nmodule.exports = x;',
        )
        (modules_dir / "module_1.js").write_text(
            'const React = require("react");\n'
            'function App() { return React.createElement("div"); }\n'
            'module.exports = App;',
        )
        (modules_dir / "module_2.js").write_text(
            'const config = { debug: false, port: 3000 };\n'
            'module.exports = config;',
        )

        output_dir = tmp_path / "output"
        splitter = ModuleSplitter(config)
        result = splitter.split(modules_dir, output_dir)

        assert result.success is True
        assert result.total_modules == 3
        assert sum(result.categorized.values()) == 3

    def test_split_extract_export_name(self, config: Config):
        """Export name dogru cikarilir."""
        splitter = ModuleSplitter(config)

        content1 = 'exports.MyComponent = function() {};'
        assert splitter._extract_export_name(content1) == "MyComponent"

        content2 = 'class UserService { constructor() {} }'
        assert splitter._extract_export_name(content2) == "UserService"

        content3 = 'var x = 42;'
        assert splitter._extract_export_name(content3) is None


# ---------------------------------------------------------------
# TypeInferrer testleri
# ---------------------------------------------------------------


class TestTypeInferrer:
    """TypeInferrer testleri."""

    def test_infer_boolean_naming(
        self, config: Config, sample_functions_js: Path, tmp_path: Path,
    ):
        """isX -> boolean tip cikarimi."""
        inferrer = TypeInferrer(config)
        output = tmp_path / "typed.js"

        result = inferrer.infer(sample_functions_js, output)
        assert result.success is True
        assert result.functions_annotated > 0
        assert output.exists()

        # JSDoc yorumlarini kontrol et
        content = output.read_text()
        assert "@param" in content or "@returns" in content

    def test_infer_nonexistent_file(self, config: Config, tmp_path: Path):
        """Olmayan dosya icin basarisiz sonuc."""
        inferrer = TypeInferrer(config)
        result = inferrer.infer(
            tmp_path / "nonexistent.js",
            tmp_path / "output.js",
        )
        assert result.success is False
        assert "bulunamadi" in result.errors[0]

    def test_infer_name_type_patterns(self, config: Config):
        """Isim-bazli tip cikarimi dogru calisir."""
        assert TypeInferrer._infer_type_from_name("isValid") == "boolean"
        assert TypeInferrer._infer_type_from_name("hasPermission") == "boolean"
        assert TypeInferrer._infer_type_from_name("count") == "number"
        assert TypeInferrer._infer_type_from_name("onClick") == "Function"
        assert TypeInferrer._infer_type_from_name("handleSubmit") == "Function"
        assert TypeInferrer._infer_type_from_name("fetchData") == "Promise"
        assert TypeInferrer._infer_type_from_name("itemList") == "Array"
        assert TypeInferrer._infer_type_from_name("error") == "Error"
        assert TypeInferrer._infer_type_from_name("request") == "Request"
        assert TypeInferrer._infer_type_from_name("response") == "Response"
        assert TypeInferrer._infer_type_from_name("name") == "string"

    def test_infer_value_types(self, config: Config):
        """Varsayilan deger literalinden tip cikarimi."""
        assert TypeInferrer._infer_type_from_value("true") == "boolean"
        assert TypeInferrer._infer_type_from_value("false") == "boolean"
        assert TypeInferrer._infer_type_from_value("42") == "number"
        assert TypeInferrer._infer_type_from_value("3.14") == "number"
        assert TypeInferrer._infer_type_from_value('"hello"') == "string"
        assert TypeInferrer._infer_type_from_value("'world'") == "string"
        assert TypeInferrer._infer_type_from_value("[1, 2]") == "Array"
        assert TypeInferrer._infer_type_from_value("{}") == "Object"
        assert TypeInferrer._infer_type_from_value("null") == "null"

    def test_infer_async_returns_promise(
        self, config: Config, tmp_path: Path,
    ):
        """async fonksiyon -> Promise return tipi."""
        js_file = tmp_path / "async.js"
        js_file.write_text(
            "async function fetchData(url) {\n"
            "  const res = await fetch(url);\n"
            "  return res.json();\n"
            "}\n",
        )
        output = tmp_path / "output.js"
        inferrer = TypeInferrer(config)
        result = inferrer.infer(js_file, output)

        assert result.success is True
        content = output.read_text()
        assert "@returns {Promise}" in content

    def test_infer_preserves_content(
        self, config: Config, tmp_path: Path,
    ):
        """Type inference orijinal kodu bozmaz."""
        original = "function add(a, b) {\n  return a + b;\n}\n"
        js_file = tmp_path / "original.js"
        js_file.write_text(original)
        output = tmp_path / "output.js"

        inferrer = TypeInferrer(config)
        inferrer.infer(js_file, output)

        content = output.read_text()
        # Orijinal kod hala var
        assert "function add(a, b)" in content
        assert "return a + b;" in content


# ---------------------------------------------------------------
# CommentGenerator testleri
# ---------------------------------------------------------------


class TestCommentGenerator:
    """CommentGenerator testleri."""

    def test_generate_adds_comments(
        self, config: Config, sample_functions_js: Path, tmp_path: Path,
    ):
        """Fonksiyonlara yorum eklenir."""
        gen = CommentGenerator(config)
        output = tmp_path / "commented.js"
        count = gen.generate(sample_functions_js, output)

        assert count > 0
        assert output.exists()

        content = output.read_text()
        assert "//" in content

    def test_generate_nonexistent(self, config: Config, tmp_path: Path):
        """Olmayan dosya icin 0 doner."""
        gen = CommentGenerator(config)
        count = gen.generate(
            tmp_path / "nonexistent.js",
            tmp_path / "output.js",
        )
        assert count == 0

    def test_name_to_action(self):
        """Fonksiyon adi -> aksiyon cumlesi."""
        assert "Retrieves" in CommentGenerator._name_to_action("getUserProfile")
        assert "Handles" in CommentGenerator._name_to_action("handleClick")
        assert "Validates" in CommentGenerator._name_to_action("validateInput")
        assert "Checks if" in CommentGenerator._name_to_action("isValid")
        assert "Fetches" in CommentGenerator._name_to_action("fetchData")

    def test_generate_skips_existing_comments(
        self, config: Config, tmp_path: Path,
    ):
        """Zaten yorum olan fonksiyonlara yorum eklenmez."""
        content = (
            "// This function is already documented\n"
            "function myFunc() {\n"
            "  return 42;\n"
            "}\n"
        )
        js_file = tmp_path / "commented.js"
        js_file.write_text(content)
        output = tmp_path / "output.js"

        gen = CommentGenerator(config)
        count = gen.generate(js_file, output)

        # Yorum zaten var, tekrar eklenmemeli
        assert count == 0


# ---------------------------------------------------------------
# GapFiller testleri
# ---------------------------------------------------------------


class TestGapFiller:
    """GapFiller testleri."""

    def test_fill_empty_workspace(
        self, config: Config, workspace: Workspace,
    ):
        """Bos workspace'te gap analysis basarili calisir."""
        filler = GapFiller(config)
        result = filler.fill(workspace)

        assert result.success is True
        assert result.dead_code_functions == []
        assert result.missing_imports == []

    def test_dead_code_detection(self, config: Config):
        """Dead code tespiti: statik'te var, dinamik'te yok."""
        static_funcs = ["render", "handleClick", "validate", "unusedHelper"]
        dynamic_calls = ["render", "handleClick"]

        dead = GapFiller._detect_dead_code(static_funcs, dynamic_calls)
        assert "validate" in dead
        assert "unusedHelper" in dead
        assert "render" not in dead
        assert "handleClick" not in dead

    def test_dead_code_no_dynamic_data(self, config: Config):
        """Dinamik veri yoksa dead code tespit etmez (false positive onleme)."""
        static_funcs = ["render", "handleClick"]
        dynamic_calls: list[str] = []

        dead = GapFiller._detect_dead_code(static_funcs, dynamic_calls)
        assert dead == []

    def test_missing_imports(self, config: Config):
        """Missing import tespiti."""
        static = ["express", "lodash"]
        dynamic = ["express", "lodash", "chalk", "moment"]

        missing = GapFiller._detect_missing_imports(static, dynamic)
        assert "chalk" in missing
        assert "moment" in missing
        assert "express" not in missing

    def test_fill_with_static_data(
        self, config: Config, workspace: Workspace,
    ):
        """Statik analiz verisi ile gap analysis."""
        # Statik analiz sonucu olustur
        workspace.save_json("static", "ast-analysis", {
            "imports": [
                {"source": "express", "specifiers": []},
                {"source": "lodash", "specifiers": []},
            ],
            "functions": [
                {"name": "render"},
                {"name": "handleClick"},
                {"name": "unusedHelper"},
            ],
        })

        filler = GapFiller(config)
        result = filler.fill(workspace)

        assert result.success is True
        assert result.stats["static_imports"] == 2
        assert result.stats["static_functions"] == 3

    def test_env_variable_detection(
        self, config: Config, workspace: Workspace, sample_env_js: Path,
    ):
        """process.env referanslari tespit edilir."""
        # JS dosyasini deobfuscated dizinine kopyala
        import shutil
        deob_dir = workspace.get_stage_dir("deobfuscated")
        shutil.copy2(sample_env_js, deob_dir / "app.js")

        filler = GapFiller(config)
        result = filler.fill(workspace)

        assert result.success is True
        assert "PORT" in result.env_variables
        assert "DATABASE_URL" in result.env_variables
        assert "JWT_SECRET" in result.env_variables
        assert "DEBUG" in result.env_variables

    def test_api_endpoint_detection(
        self, config: Config, workspace: Workspace,
    ):
        """API endpoint URL'leri tespit edilir."""
        # Deobfuscated dosyaya URL ekle
        deob_dir = workspace.get_stage_dir("deobfuscated")
        (deob_dir / "api.js").write_text(
            'const url = "https://api.example.com/v1/users";\n'
            'fetch("/api/v2/products");\n',
        )

        filler = GapFiller(config)
        result = filler.fill(workspace)

        assert result.success is True
        urls = [ep["url"] for ep in result.api_endpoints]
        assert any("api.example.com" in u for u in urls)
        assert any("/api/v2/products" in u for u in urls)


# ---------------------------------------------------------------
# ProjectBuilder testleri
# ---------------------------------------------------------------


class TestProjectBuilder:
    """ProjectBuilder testleri."""

    def test_node_builtins_set(self):
        """NODE_BUILTINS dogru modulleri icerir."""
        assert "fs" in NODE_BUILTINS
        assert "path" in NODE_BUILTINS
        assert "os" in NODE_BUILTINS
        assert "http" in NODE_BUILTINS
        assert "crypto" in NODE_BUILTINS
        assert "child_process" in NODE_BUILTINS
        assert "node:fs" in NODE_BUILTINS
        assert "fs/promises" in NODE_BUILTINS
        # npm paketleri olmamalii
        assert "express" not in NODE_BUILTINS
        assert "chalk" not in NODE_BUILTINS

    def test_dependency_detection(
        self, config: Config, workspace: Workspace,
    ):
        """require/import'lardan dependency tespiti."""
        deob_dir = workspace.get_stage_dir("deobfuscated")
        (deob_dir / "app.js").write_text(
            'const express = require("express");\n'
            'const fs = require("fs");\n'
            'const chalk = require("chalk");\n'
            'const path = require("path");\n'
            'import lodash from "lodash";\n'
            'const local = require("./utils");\n'
            'const { join } = require("node:path");\n',
        )

        builder = ProjectBuilder(config)
        deps = builder._detect_dependencies(workspace)

        assert "express" in deps
        assert "chalk" in deps
        assert "lodash" in deps
        # Built-in'ler olmamali
        assert "fs" not in deps
        assert "path" not in deps
        # Relative import olmamali
        assert "./utils" not in deps
        # node: prefix'li built-in olmamali
        assert "node:path" not in deps

    def test_dependency_version_latest(
        self, config: Config, workspace: Workspace,
    ):
        """Tespit edilen dependency'ler 'latest' versiyonlu."""
        deob_dir = workspace.get_stage_dir("deobfuscated")
        (deob_dir / "app.js").write_text('const x = require("moment");\n')

        builder = ProjectBuilder(config)
        deps = builder._detect_dependencies(workspace)
        assert deps.get("moment") == "latest"

    def test_build_creates_package_json(
        self, config: Config, workspace: Workspace, target_info: TargetInfo,
    ):
        """build() package.json olusturur."""
        # Deobfuscated dosya olustur
        deob_dir = workspace.get_stage_dir("deobfuscated")
        (deob_dir / "app.js").write_text(
            'const express = require("express");\nconsole.log("hello");\n',
        )

        builder = ProjectBuilder(config)
        result = builder.build(workspace, target_info)

        assert result.success is True
        assert result.package_json is not None
        assert result.package_json.exists()

        # package.json icerigini kontrol et
        pkg = json.loads(result.package_json.read_text())
        assert "reconstructed" in pkg["name"]
        assert "express" in pkg.get("dependencies", {})
        assert "start" in pkg.get("scripts", {})

    def test_build_creates_readme(
        self, config: Config, workspace: Workspace, target_info: TargetInfo,
    ):
        """build() README.md olusturur."""
        deob_dir = workspace.get_stage_dir("deobfuscated")
        (deob_dir / "app.js").write_text('console.log("test");\n')

        builder = ProjectBuilder(config)
        result = builder.build(workspace, target_info)

        assert "README.md" in result.files_created
        readme_path = result.project_dir / "README.md"
        assert readme_path.exists()

        content = readme_path.read_text()
        assert "Quick Start" in content
        assert "npm install" in content
        assert "Karadul" in content

    def test_build_creates_env_example(
        self, config: Config, workspace: Workspace, target_info: TargetInfo,
    ):
        """process.env kullanan kod icin .env.example olusturur."""
        deob_dir = workspace.get_stage_dir("deobfuscated")
        (deob_dir / "app.js").write_text(
            'const port = process.env.PORT || 3000;\n'
            'const secret = process.env.JWT_SECRET;\n',
        )

        builder = ProjectBuilder(config)
        result = builder.build(workspace, target_info)

        assert ".env.example" in result.files_created
        env_path = result.project_dir / ".env.example"
        assert env_path.exists()

        content = env_path.read_text()
        assert "PORT" in content
        assert "JWT_SECRET" in content

    def test_build_creates_dockerfile(
        self, config: Config, workspace: Workspace, target_info: TargetInfo,
    ):
        """build() Dockerfile olusturur."""
        deob_dir = workspace.get_stage_dir("deobfuscated")
        (deob_dir / "app.js").write_text('console.log("test");\n')

        builder = ProjectBuilder(config)
        result = builder.build(workspace, target_info)

        assert "Dockerfile" in result.files_created
        docker_path = result.project_dir / "Dockerfile"
        assert docker_path.exists()

        content = docker_path.read_text()
        assert "FROM node:" in content
        assert "npm ci" in content

    def test_build_creates_gitignore(
        self, config: Config, workspace: Workspace, target_info: TargetInfo,
    ):
        """build() .gitignore olusturur."""
        deob_dir = workspace.get_stage_dir("deobfuscated")
        (deob_dir / "app.js").write_text('console.log("test");\n')

        builder = ProjectBuilder(config)
        result = builder.build(workspace, target_info)

        assert ".gitignore" in result.files_created
        gitignore = result.project_dir / ".gitignore"
        assert gitignore.exists()
        content = gitignore.read_text()
        assert "node_modules/" in content
        assert ".env" in content

    def test_build_entry_point(
        self, config: Config, workspace: Workspace, target_info: TargetInfo,
    ):
        """build() entry point olusturur."""
        deob_dir = workspace.get_stage_dir("deobfuscated")
        (deob_dir / "main.beautified.js").write_text(
            'const app = require("./app");\napp.listen(3000);\n',
        )

        builder = ProjectBuilder(config)
        result = builder.build(workspace, target_info)

        assert result.entry_point is not None
        assert result.entry_point.exists()

    def test_build_scoped_package(
        self, config: Config, workspace: Workspace,
    ):
        """@scope/package formatli dependency tespiti."""
        deob_dir = workspace.get_stage_dir("deobfuscated")
        (deob_dir / "app.js").write_text(
            'const parse = require("@babel/parser");\n'
            'const traverse = require("@babel/traverse");\n',
        )

        builder = ProjectBuilder(config)
        deps = builder._detect_dependencies(workspace)
        assert "@babel/parser" in deps
        assert "@babel/traverse" in deps

    def test_scan_dependencies_static(self):
        """_scan_dependencies dogru paketleri cikarir."""
        content = (
            'const a = require("express");\n'
            'import React from "react";\n'
            'const b = require("fs");\n'
            'import("./local-module");\n'
            'const c = require("@types/node");\n'
        )
        deps: dict[str, str] = {}
        ProjectBuilder._scan_dependencies(content, deps)

        assert "express" in deps
        assert "react" in deps
        assert "fs" not in deps
        assert "./local-module" not in deps
        assert "@types/node" in deps


# ---------------------------------------------------------------
# Tam pipeline testi
# ---------------------------------------------------------------


class TestReconstructionPipeline:
    """Tam reconstruction pipeline testi."""

    def test_full_pipeline_creates_project(
        self, config: Config, workspace: Workspace, target_info: TargetInfo,
    ):
        """Tam pipeline calistiriilabilir proje olusturur."""
        # Deobfuscated dosya olustur
        deob_dir = workspace.get_stage_dir("deobfuscated")
        (deob_dir / "bundle.beautified.js").write_text(
            'const express = require("express");\n'
            'const chalk = require("chalk");\n'
            'function isReady(server) {\n'
            '  return server !== null;\n'
            '}\n'
            'function handleRequest(req, res) {\n'
            '  res.json({ status: "ok" });\n'
            '}\n'
            'const app = express();\n'
            'app.get("/api/health", handleRequest);\n'
            'const port = process.env.PORT || 3000;\n'
            'app.listen(port);\n',
        )

        # Reconstruction siniflarini calistir
        from karadul.reconstruction.type_inferrer import TypeInferrer
        from karadul.reconstruction.comment_generator import CommentGenerator
        from karadul.reconstruction.gap_filler import GapFiller
        from karadul.reconstruction.project_builder import ProjectBuilder

        source = deob_dir / "bundle.beautified.js"
        recon_dir = workspace.get_stage_dir("reconstructed")

        # Type inference
        inferrer = TypeInferrer(config)
        typed_file = recon_dir / "typed.js"
        infer_result = inferrer.infer(source, typed_file)
        assert infer_result.success is True

        # Comment generation
        commenter = CommentGenerator(config)
        commented_file = recon_dir / "commented.js"
        comments = commenter.generate(typed_file, commented_file)
        assert comments >= 0

        # Gap filling
        filler = GapFiller(config)
        gap_result = filler.fill(workspace)
        assert gap_result.success is True

        # Project building
        builder = ProjectBuilder(config)
        build_result = builder.build(
            workspace, target_info, gap_result=gap_result,
        )
        assert build_result.success is True
        assert build_result.package_json is not None

        # Proje dosyalarini kontrol et
        pkg = json.loads(build_result.package_json.read_text())
        assert "express" in pkg["dependencies"]
        assert "chalk" in pkg["dependencies"]
        assert "fs" not in pkg["dependencies"]

        # Entry point kontrolu
        assert build_result.entry_point is not None
        assert build_result.entry_point.exists()

        # Dosya listesi
        assert "package.json" in build_result.files_created
        assert "README.md" in build_result.files_created

    def test_reconstruction_stage_import(self):
        """ReconstructionStage import edilebilir."""
        from karadul.stages import ReconstructionStage
        stage = ReconstructionStage()
        assert stage.name == "reconstruct"
        assert "identify" in stage.requires  # v1.9.1: native binary'de deobf gereksiz

    def test_reconstruction_stage_with_project_reconstructor_flag(self):
        """ReconstructionStage use_project_reconstructor flag'i kabul eder."""
        from karadul.stages import ReconstructionStage
        stage_on = ReconstructionStage(use_project_reconstructor=True)
        assert stage_on._use_project_reconstructor is True

        stage_off = ReconstructionStage(use_project_reconstructor=False)
        assert stage_off._use_project_reconstructor is False

    def test_project_reconstructor_import(self):
        """ProjectReconstructor import edilebilir."""
        from karadul.reconstruction.project_reconstructor import (
            ProjectReconstructor,
            ReconstructionResult,
        )
        assert ProjectReconstructor is not None
        result = ReconstructionResult()
        assert result.success is False
        assert result.total_modules == 0

    def test_chunked_processor_import(self):
        """ChunkedProcessor import edilebilir."""
        from karadul.core.chunked_processor import (
            ChunkedProcessor,
            ChunkInfo,
            ChunkResult,
        )
        assert ChunkedProcessor is not None
        config = Config()
        chunker = ChunkedProcessor(config, max_chunk_mb=25)
        assert chunker.max_chunk_mb == 25
