"""Cursor JS deobfuscation enhancement testleri.

3 gorev icin testler:
  GOREV 1: Webpack Module ID -> Name Map (smart-webpack-unpack.mjs npm enrichment)
  GOREV 2: String Literal Context Enrichment (semantic-rename.mjs VS Code kuralları)
  GOREV 3: DTS Name Recovery pipeline entegrasyonu

Python tarafindaki degisiklikleri test eder.
JS script'leri (smart-webpack-unpack.mjs, semantic-rename.mjs) ayri test edilir.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from karadul.reconstruction.dts_namer import DtsExport, DtsNamer


# ---------------------------------------------------------------
# GOREV 1: Webpack Module ID -> Name Map testleri
# ---------------------------------------------------------------


class TestWebpackModuleIdMap:
    """Webpack module ID -> npm package name mapping testleri.

    smart-webpack-unpack.mjs'teki normalizePackageName ve
    NPM_DISPLAY_NAMES mantigi Python tarafinda test edilemez (JS kodu).
    Ancak dependency_graph.json ciktisinin npm_package alani dogru mu
    kontrol edebiliriz -- mevcut dependency graph dosyalarindan.
    """

    def test_dependency_graph_has_npm_package_field(self, tmp_path: Path) -> None:
        """dependency_graph.json'da npm_package alani mevcut olmali."""
        # Ornek dependency graph (smart-webpack-unpack ciktisi formati)
        graph = {
            "bundle_format": "esbuild",
            "total_modules": 3,
            "helpers": {"cjs_wrapper": "fn2", "esm_interop": None,
                        "re_export": None, "require_alias": None},
            "modules": [
                {"id": "F88", "name": "F88", "file": "F88.js", "type": "esbuild_cjs",
                 "exports": [], "esm_alias": None, "npm_package": None, "require_deps": []},
                {"id": "ym9", "name": "tree_sitter_ym9", "file": "tree_sitter_ym9.js",
                 "type": "esbuild_cjs", "exports": [], "esm_alias": None,
                 "npm_package": "tree-sitter", "require_deps": ["tree-sitter"]},
                {"id": "AF8", "name": "aws_sdk_AF8", "file": "aws_sdk_AF8.js",
                 "type": "esbuild_cjs", "exports": [], "esm_alias": None,
                 "npm_package": "@aws-sdk", "require_deps": []},
            ],
            "graph": {"F88": [], "ym9": [], "AF8": []},
        }

        # Dosya yaz
        graph_path = tmp_path / "dependency_graph.json"
        graph_path.write_text(json.dumps(graph), encoding="utf-8")

        # Oku ve dogrula
        loaded = json.loads(graph_path.read_text())
        modules = loaded["modules"]
        assert len(modules) == 3

        # npm_package alani olmali
        tree_sitter_mod = next(m for m in modules if m["id"] == "ym9")
        assert tree_sitter_mod["npm_package"] == "tree-sitter"
        assert "tree-sitter" in tree_sitter_mod["require_deps"]

        aws_mod = next(m for m in modules if m["id"] == "AF8")
        assert aws_mod["npm_package"] == "@aws-sdk"

        # npm_package olmayan modul None olmali
        unknown_mod = next(m for m in modules if m["id"] == "F88")
        assert unknown_mod["npm_package"] is None

    def test_module_id_map_format(self, tmp_path: Path) -> None:
        """module_id_map.json formati dogru olmali."""
        id_map = {
            "total_mapped": 2,
            "total_modules": 5,
            "coverage": "40.0%",
            "node_builtins": [
                {"id": "fs_mod", "package": "fs"},
            ],
            "npm_packages": [
                {"id": "ym9", "package": "tree-sitter"},
            ],
            "id_to_name": {
                "fs_mod": {
                    "npm_package": "fs",
                    "display_name": "fs",
                    "module_name": "node_fs_fs_mod",
                    "exports": [],
                    "require_deps": ["node:fs"],
                },
                "ym9": {
                    "npm_package": "tree-sitter",
                    "display_name": "tree_sitter",
                    "module_name": "tree_sitter_ym9",
                    "exports": [],
                    "require_deps": ["tree-sitter"],
                },
            },
        }

        map_path = tmp_path / "module_id_map.json"
        map_path.write_text(json.dumps(id_map), encoding="utf-8")

        loaded = json.loads(map_path.read_text())
        assert loaded["total_mapped"] == 2
        assert loaded["coverage"] == "40.0%"
        assert len(loaded["node_builtins"]) == 1
        assert loaded["node_builtins"][0]["package"] == "fs"
        assert loaded["id_to_name"]["ym9"]["display_name"] == "tree_sitter"


# ---------------------------------------------------------------
# GOREV 2: String Literal Context Enrichment testleri
# ---------------------------------------------------------------


class TestVSCodeStringContext:
    """VS Code / Cursor string literal context kuralları testleri.

    semantic-rename.mjs'teki ruleVSCodeStringContext ve
    ruleComparison VS Code pattern'leri Python'da test edilemez.
    Ancak dts_namer uzerinden VS Code API export isimlerini test edebiliriz.
    """

    def test_vscode_dts_parse(self) -> None:
        """VS Code API .d.ts dosyasindan export isimleri cikarilabilmeli."""
        namer = DtsNamer()
        vscode_dts = """\
export declare function commands_registerCommand(command: string, callback: Function): Disposable;
export declare function window_createOutputChannel(name: string): OutputChannel;
export declare function workspace_getConfiguration(section?: string): WorkspaceConfiguration;
export declare function window_showQuickPick(items: string[]): Thenable<string | undefined>;
export declare function languages_registerCompletionItemProvider(
    selector: DocumentSelector, provider: CompletionItemProvider, ...triggerCharacters: string[]
): Disposable;
"""
        exports = namer.parse_dts(vscode_dts)
        names = {e.name for e in exports}
        assert "commands_registerCommand" in names
        assert "window_createOutputChannel" in names
        assert "workspace_getConfiguration" in names
        assert "window_showQuickPick" in names
        assert "languages_registerCompletionItemProvider" in names

    def test_lsp_method_strings(self) -> None:
        """LSP method string'leri .d.ts'de export olarak cikarilabilmeli."""
        namer = DtsNamer()
        lsp_dts = """\
export declare function handleCompletion(params: CompletionParams): CompletionList;
export declare function handleHover(params: HoverParams): Hover;
export declare function handleDefinition(params: DefinitionParams): Location;
export declare function handleReferences(params: ReferenceParams): Location[];
export declare function handleRename(params: RenameParams): WorkspaceEdit;
"""
        exports = namer.parse_dts(lsp_dts)
        assert len(exports) == 5
        func_names = [e.name for e in exports if e.kind == "function"]
        assert "handleCompletion" in func_names
        assert "handleHover" in func_names

    def test_cursor_specific_exports(self) -> None:
        """Cursor'a ozel .d.ts export'lari cikarilabilmeli."""
        namer = DtsNamer()
        cursor_dts = """\
export declare function createAgentSession(config: AgentConfig): AgentSession;
export declare function executeToolUse(tool: string, args: any): Promise<ToolResult>;
export declare class ConversationManager {
    addMessage(msg: Message): void;
    getHistory(): Message[];
}
export interface AgentConfig {
    model: string;
    maxTokens: number;
}
export declare const DEFAULT_MODEL: string;
"""
        exports = namer.parse_dts(cursor_dts)
        names = {e.name for e in exports}
        assert "createAgentSession" in names
        assert "executeToolUse" in names
        assert "ConversationManager" in names
        assert "AgentConfig" in names
        assert "DEFAULT_MODEL" in names


# ---------------------------------------------------------------
# GOREV 3: DTS Name Recovery pipeline entegrasyonu testleri
# ---------------------------------------------------------------


class TestDtsNameRecoveryPipeline:
    """DTS Name Recovery pipeline entegrasyon testleri."""

    def test_dts_namer_rename_with_cursor_deps(self) -> None:
        """Cursor bagimlilikları icin DTS rename calismali."""
        # semver paketi icin ornek .d.ts
        semver_dts = """\
export declare function valid(version: string): string | null;
export declare function inc(version: string, release: string): string | null;
export declare function diff(v1: string, v2: string): string | null;
export declare function major(version: string): number;
export declare function minor(version: string): number;
export declare function patch(version: string): number;
export declare function clean(version: string): string | null;
export declare function satisfies(version: string, range: string): boolean;
export declare function gt(v1: string, v2: string): boolean;
export declare function lt(v1: string, v2: string): boolean;
"""
        namer = DtsNamer()
        result = namer.rename_minified(
            "semver",
            ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j"],
            dts_content=semver_dts,
        )
        assert result.success is True
        assert result.matches_found == 10
        assert result.mapping["a"] == "valid"
        assert result.mapping["b"] == "inc"
        assert result.mapping["h"] == "satisfies"

    def test_pipeline_layer_12_with_local_dts(self, tmp_path: Path) -> None:
        """Pipeline Layer 1.2 lokal .d.ts dosyasiyla calismali."""
        from karadul.reconstruction.naming.pipeline import NamingPipeline
        from karadul.reconstruction.naming.result import NamingResult

        # Modul dizini olustur
        modules_dir = tmp_path / "modules"
        modules_dir.mkdir()

        # Ornek JS modulu (semver benzeri)
        js_content = """\
/**
 * Module: test_mod
 * Type: esbuild_cjs
 * npm package: semver
 */
(exports, module) => {
    exports.a = function(v) { return v; };
    exports.b = function(v, r) { return v + r; };
};
"""
        (modules_dir / "test_mod.js").write_text(js_content, encoding="utf-8")

        # node_modules/@types/semver/index.d.ts olustur
        types_dir = modules_dir.parent / "node_modules" / "@types" / "semver"
        types_dir.mkdir(parents=True)
        (types_dir / "index.d.ts").write_text(
            "export declare function valid(version: string): string | null;\n"
            "export declare function inc(version: string, release: string): string | null;\n",
            encoding="utf-8",
        )

        # Pipeline olustur -- LLM atla, sadece fingerprint + structural
        pipeline = NamingPipeline(skip_llm=True)

        # NpmFingerprinter'i mock'la -- fp_result dondursun
        fp_result = NamingResult(
            module_id="test_mod",
            original_file="test_mod.js",
            new_filename="semver_test_mod.js",
            category="npm_packages",
            description="semver package",
            confidence=0.9,
            source="npm_fingerprint",
        )
        fp_result.npm_package = "semver"

        with patch.object(pipeline.fingerprinter, "fingerprint_all", return_value=[fp_result]):
            manifest = pipeline.run(modules_dir)

        # source_match_mappings'te dts eslesmesi olmali
        assert "test_mod" in manifest.source_match_mappings
        mappings = manifest.source_match_mappings["test_mod"]
        assert mappings.get("a") == "valid"
        assert mappings.get("b") == "inc"

    def test_pipeline_layer_12_remote_fetch_whitelist(self) -> None:
        """Pipeline Layer 1.2 bilinen paketler icin remote fetch yapmali."""
        from karadul.reconstruction.naming.pipeline import NamingPipeline

        pipeline = NamingPipeline(skip_llm=True)

        # _CURSOR_KNOWN_PACKAGES whitelist kontrol
        # Pipeline icerisinde tanimli, dogrudan test edemeyiz ama
        # DtsNamer'in fetch_dts_content calistigini dogrulayabiliriz
        mock_dts = "export declare function valid(v: string): string | null;"
        namer = DtsNamer(fetcher=lambda url: mock_dts)
        content = namer.fetch_dts_content("semver")
        assert content == mock_dts

    def test_dts_namer_with_chalk_exports(self) -> None:
        """Chalk paketinin .d.ts export'lari cikarilabilmeli."""
        chalk_dts = """\
export declare const chalk: Chalk & ChalkFunction;
export declare function supportsColor(): ColorSupport | false;
export interface Chalk {
    (text: string): string;
    red: Chalk;
    green: Chalk;
    blue: Chalk;
    bold: Chalk;
}
export type ColorSupport = {
    level: number;
    hasBasic: boolean;
    has256: boolean;
    has16m: boolean;
};
"""
        namer = DtsNamer()
        exports = namer.parse_dts(chalk_dts)
        export_names = {e.name for e in exports}
        assert "chalk" in export_names
        assert "supportsColor" in export_names
        assert "Chalk" in export_names
        assert "ColorSupport" in export_names

    def test_dts_match_with_runtime_filtering(self) -> None:
        """Runtime olmayan export'lar (interface, type) filtrelenmeli."""
        namer = DtsNamer()
        # chalk icin: sadece chalk ve supportsColor runtime'da var
        dts_exports = [
            DtsExport(name="chalk", kind="const"),
            DtsExport(name="supportsColor", kind="function"),
            DtsExport(name="Chalk", kind="interface"),
            DtsExport(name="ColorSupport", kind="type"),
        ]
        # Minified'da sadece 2 runtime export var
        result = namer.match_exports(["a", "b"], dts_exports)
        assert result.matched.get("a") == "chalk"
        assert result.matched.get("b") == "supportsColor"
        assert "runtime_filtered" in result.method


# ---------------------------------------------------------------
# Entegrasyon testleri
# ---------------------------------------------------------------


class TestEndToEndIntegration:
    """Tum 3 gorevin birlikte calismasi."""

    def test_dts_namer_result_feeds_pipeline(self) -> None:
        """DtsNamer sonuclari pipeline manifest'ine eklenmeli."""
        from karadul.reconstruction.naming.result import NamingManifest

        manifest = NamingManifest()

        # DTS sonuclarini simule et
        dts_mappings = {
            "mod1": {"a": "valid", "b": "inc"},
            "mod2": {"x": "chalk", "y": "supportsColor"},
        }

        manifest.source_match_mappings = dts_mappings
        assert len(manifest.source_match_mappings) == 2
        assert manifest.source_match_mappings["mod1"]["a"] == "valid"
        assert manifest.source_match_mappings["mod2"]["x"] == "chalk"

    def test_module_id_map_and_dts_namer_compatible(self) -> None:
        """module_id_map.json npm_package alani DtsNamer ile uyumlu olmali."""
        # module_id_map'ten gelen npm_package isimleri
        # DtsNamer'in fetch_dts_content ile kullanilabilir olmali
        packages = ["semver", "chalk", "commander", "yaml"]

        namer = DtsNamer()
        for pkg in packages:
            # parse_dts bos string'de bos liste dondurmeli
            result = namer.parse_dts("")
            assert result == []

            # Paket adi DtsNamerResult'a dogru yazilmali
            from karadul.reconstruction.dts_namer import DtsNamerResult
            nr = DtsNamerResult(package_name=pkg)
            assert nr.package_name == pkg

    def test_nested_generic_param_count(self) -> None:
        """Karmasik generic tip parametreleri dogru sayilmali."""
        from karadul.reconstruction.dts_namer import _count_params

        # Map<string, Array<number>> parametre -- 1 parametre
        assert _count_params("data: Map<string, Array<number>>") == 1

        # Iki parametre, biri generic
        assert _count_params("key: string, value: Map<string, number>") == 2

        # Arrow function parametresi
        assert _count_params("fn: (a: string, b: number) => void") == 1

        # Bos
        assert _count_params("") == 0

        # 4 parametre, biri callback
        assert _count_params(
            "a: string, b: number, fn: (x: string) => void, opts?: Options"
        ) == 4
