"""ClaudeLLMNamer unit testleri.

Claude CLI'a bagimli olmayan testler -- subprocess mock ile.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from karadul.config import Config
from karadul.reconstruction.naming.llm_naming import (
    ClaudeLLMNamer,
    LLMNamingResult,
    CLAUDE_CLI_PATH,
    NAMING_PROMPT,
    VARIABLE_CONTEXT_TEMPLATE,
)


@pytest.fixture
def config() -> Config:
    return Config()


@pytest.fixture
def namer(config: Config) -> ClaudeLLMNamer:
    """ClaudeLLMNamer instance -- CLI available olarak ayarla."""
    n = ClaudeLLMNamer(config, model="sonnet")
    # Claude CLI'nin var olup olmadigina bakmaksizin test icin True yap
    n._cli_available = True
    return n


@pytest.fixture
def sample_context_json(tmp_path: Path) -> Path:
    """Ornek context-analyzer ciktisi."""
    data = {
        "variables": [
            {
                "name": "e",
                "scope_id": "func:main:1",
                "confidence": 0.2,
                "reference_count": 15,
                "declaration_type": "var",
                "api_calls": ["app", "screen"],
                "properties": ["getPath", "on"],
                "data_flow": "e = require('electron')",
                "line": 5,
            },
            {
                "name": "t",
                "scope_id": "func:main:1",
                "confidence": 0.1,
                "reference_count": 8,
                "declaration_type": "var",
                "api_calls": ["join", "dirname"],
                "properties": ["join"],
                "data_flow": "t = require('path')",
                "line": 6,
            },
            {
                "name": "goodName",
                "scope_id": "func:main:1",
                "confidence": 0.9,  # Yuksek confidence -- secilmemeli
                "reference_count": 20,
                "declaration_type": "const",
                "api_calls": [],
                "properties": [],
                "data_flow": "",
                "line": 10,
            },
            {
                "name": "x",
                "scope_id": "func:helper:20",
                "confidence": 0.3,
                "reference_count": 1,  # Dusuk referans -- secilmemeli (min_references=2)
                "declaration_type": "var",
                "api_calls": [],
                "properties": [],
                "data_flow": "",
                "line": 25,
            },
        ],
        "stats": {
            "total_variables": 4,
        },
    }
    json_path = tmp_path / "context.json"
    json_path.write_text(json.dumps(data))
    return json_path


@pytest.fixture
def sample_source_file(tmp_path: Path) -> Path:
    """Ornek JS kaynak dosyasi."""
    content = """\
// Line 1
// Line 2
// Line 3
// Line 4
var e = require('electron');
var t = require('path');
// Line 7
// Line 8
// Line 9
const goodName = "hello";
"""
    js_path = tmp_path / "source.js"
    js_path.write_text(content)
    return js_path


# ---------------------------------------------------------------
# LLMNamingResult testleri
# ---------------------------------------------------------------


class TestLLMNamingResult:
    def test_default_values(self):
        result = LLMNamingResult()
        assert result.success is False
        assert result.total_named == 0
        assert result.total_batches == 0
        assert result.failed_batches == 0
        assert result.mappings == {}
        assert result.reasons == {}
        assert result.errors == []
        assert result.model_used == ""

    def test_custom_values(self):
        result = LLMNamingResult(
            success=True,
            total_named=5,
            model_used="opus",
            mappings={"scope1": {"e": "electron"}},
        )
        assert result.success is True
        assert result.total_named == 5
        assert result.model_used == "opus"
        assert result.mappings["scope1"]["e"] == "electron"


# ---------------------------------------------------------------
# ClaudeLLMNamer init testleri
# ---------------------------------------------------------------


class TestClaudeLLMNamerInit:
    def test_default_model(self, config: Config):
        namer = ClaudeLLMNamer(config)
        assert namer.model == "sonnet"

    def test_custom_model(self, config: Config):
        namer = ClaudeLLMNamer(config, model="opus")
        assert namer.model == "opus"

    def test_custom_batch_size(self, config: Config):
        namer = ClaudeLLMNamer(config, batch_size=10)
        assert namer.batch_size == 10

    def test_custom_timeout(self, config: Config):
        namer = ClaudeLLMNamer(config, timeout=30)
        assert namer.timeout == 30

    def test_min_confidence(self, config: Config):
        namer = ClaudeLLMNamer(config, min_confidence=0.3)
        assert namer.min_confidence == 0.3


# ---------------------------------------------------------------
# Variable extraction testleri
# ---------------------------------------------------------------


class TestExtractLowConfidenceVars:
    def test_filters_by_confidence(self, namer: ClaudeLLMNamer):
        data = {
            "variables": [
                {"name": "e", "confidence": 0.2, "reference_count": 10},
                {"name": "goodName", "confidence": 0.9, "reference_count": 10},
            ]
        }
        result = namer._extract_low_confidence_vars(data)
        assert len(result) == 1
        assert result[0]["name"] == "e"

    def test_filters_by_reference_count(self, namer: ClaudeLLMNamer):
        data = {
            "variables": [
                {"name": "e", "confidence": 0.2, "reference_count": 10},
                {"name": "x", "confidence": 0.2, "reference_count": 1},  # Too few
            ]
        }
        result = namer._extract_low_confidence_vars(data)
        assert len(result) == 1
        assert result[0]["name"] == "e"

    def test_single_char_always_candidate(self, namer: ClaudeLLMNamer):
        """Tek harfli degiskenler confidence yuksek olsa bile aday."""
        data = {
            "variables": [
                {"name": "x", "confidence": 0.8, "reference_count": 5},
            ]
        }
        result = namer._extract_low_confidence_vars(data)
        assert len(result) == 1

    def test_empty_variables(self, namer: ClaudeLLMNamer):
        data = {"variables": []}
        result = namer._extract_low_confidence_vars(data)
        assert result == []

    def test_scopes_format(self, namer: ClaudeLLMNamer):
        """Alternatif format: scopes icinde variables."""
        data = {
            "scopes": {
                "func:main:1": {
                    "variables": [
                        {"name": "e", "confidence": 0.2, "reference_count": 10},
                    ]
                }
            }
        }
        result = namer._extract_low_confidence_vars(data)
        assert len(result) == 1
        assert result[0]["scope_id"] == "func:main:1"

    def test_sorted_by_reference_count(self, namer: ClaudeLLMNamer):
        data = {
            "variables": [
                {"name": "a", "confidence": 0.1, "reference_count": 5},
                {"name": "b", "confidence": 0.1, "reference_count": 50},
                {"name": "c", "confidence": 0.1, "reference_count": 20},
            ]
        }
        result = namer._extract_low_confidence_vars(data)
        refs = [v.get("reference_count", 0) for v in result]
        assert refs == [50, 20, 5]


# ---------------------------------------------------------------
# Prompt generation testleri
# ---------------------------------------------------------------


class TestPreparePrompt:
    def test_prompt_contains_variable_info(self, namer: ClaudeLLMNamer):
        variables = [
            {
                "old": "e",
                "scope": "func:main",
                "apis": ["app", "screen"],
                "props": ["getPath"],
                "confidence": 0.2,
                "reference_count": 10,
            }
        ]
        prompt = namer._prepare_batch_from_dicts(variables)

        assert "e" in prompt
        assert "func:main" in prompt
        assert "app" in prompt
        assert "screen" in prompt
        assert "getPath" in prompt
        assert "JSON" in prompt

    def test_prompt_multiple_variables(self, namer: ClaudeLLMNamer):
        variables = [
            {"old": "e", "scope": "s1", "apis": [], "props": [], "confidence": 0.1},
            {"old": "t", "scope": "s1", "apis": [], "props": [], "confidence": 0.1},
        ]
        prompt = namer._prepare_batch_from_dicts(variables)
        assert "Variable: e" in prompt
        assert "Variable: t" in prompt


# ---------------------------------------------------------------
# Response parsing testleri
# ---------------------------------------------------------------


class TestParseResponse:
    def test_parse_valid_json(self, namer: ClaudeLLMNamer):
        response = json.dumps({
            "renames": [
                {"id": "func:main::e", "new_name": "electron", "reason": "require('electron')"},
                {"id": "func:main::t", "new_name": "path", "reason": "require('path')"},
            ]
        })
        result = namer._parse_response(response)
        assert len(result) == 2
        assert result[0]["new_name"] == "electron"
        assert result[1]["new_name"] == "path"

    def test_parse_json_in_markdown_fence(self, namer: ClaudeLLMNamer):
        response = """Here are the renames:

```json
{"renames": [{"id": "scope::e", "new_name": "electronModule", "reason": "electron import"}]}
```
"""
        result = namer._parse_response(response)
        assert len(result) == 1
        assert result[0]["new_name"] == "electronModule"

    def test_parse_empty_renames(self, namer: ClaudeLLMNamer):
        response = json.dumps({"renames": []})
        result = namer._parse_response(response)
        assert result == []

    def test_parse_invalid_json(self, namer: ClaudeLLMNamer):
        response = "This is not JSON at all"
        result = namer._parse_response(response)
        assert result == []

    def test_parse_alternative_format(self, namer: ClaudeLLMNamer):
        """old_name + scope formatini da kabul et."""
        response = json.dumps({
            "renames": [
                {"old_name": "e", "scope": "func:main", "new_name": "electron", "reason": "import"},
            ]
        })
        result = namer._parse_response(response)
        assert len(result) == 1
        assert result[0]["new_name"] == "electron"
        assert result[0]["id"] == "func:main::e"

    def test_parse_json_with_surrounding_text(self, namer: ClaudeLLMNamer):
        response = """Based on my analysis, here are the suggested renames:

{"renames": [{"id": "s1::e", "new_name": "electron", "reason": "electron module"}]}

These names are based on the API usage patterns."""
        result = namer._parse_response(response)
        assert len(result) == 1
        assert result[0]["new_name"] == "electron"

    def test_parse_skips_invalid_items(self, namer: ClaudeLLMNamer):
        response = json.dumps({
            "renames": [
                {"id": "s1::e", "new_name": "electron", "reason": "ok"},
                {"invalid": True},  # no id/new_name
                "not a dict",
                {"id": "s1::t", "new_name": "path", "reason": "ok"},
            ]
        })
        result = namer._parse_response(response)
        assert len(result) == 2


# ---------------------------------------------------------------
# name_variables_from_list testleri (mock ile)
# ---------------------------------------------------------------


class TestNameVariablesFromList:
    def test_empty_list(self, namer: ClaudeLLMNamer):
        result = namer.name_variables_from_list([])
        assert result.success is True
        assert result.total_named == 0

    @patch.object(ClaudeLLMNamer, '_call_claude')
    def test_successful_naming(self, mock_call: MagicMock, namer: ClaudeLLMNamer):
        mock_call.return_value = json.dumps({
            "renames": [
                {"id": "func:main::e", "new_name": "electron", "reason": "require"},
            ]
        })

        variables = [
            {"old": "e", "scope": "func:main", "apis": ["app"], "props": [], "confidence": 0.1},
        ]
        result = namer.name_variables_from_list(variables)

        assert result.success is True
        assert result.total_named == 1
        assert result.mappings["func:main"]["e"] == "electron"
        assert "func:main::e" in result.reasons

    @patch.object(ClaudeLLMNamer, '_call_claude')
    def test_cli_error_handling(self, mock_call: MagicMock, namer: ClaudeLLMNamer):
        mock_call.side_effect = RuntimeError("CLI crashed")

        variables = [
            {"old": "e", "scope": "s1", "apis": [], "props": [], "confidence": 0.1},
        ]
        result = namer.name_variables_from_list(variables)

        assert result.failed_batches == 1
        assert len(result.errors) > 0

    @patch.object(ClaudeLLMNamer, '_call_claude')
    def test_multiple_batches(self, mock_call: MagicMock, namer: ClaudeLLMNamer):
        """Batch size'dan fazla degisken 2+ batch'e bolunur."""
        namer.batch_size = 2  # Kucuk batch

        mock_call.return_value = json.dumps({
            "renames": [
                {"id": "s::a", "new_name": "alpha", "reason": "r"},
                {"id": "s::b", "new_name": "beta", "reason": "r"},
            ]
        })

        variables = [
            {"old": "a", "scope": "s", "apis": [], "props": [], "confidence": 0.1},
            {"old": "b", "scope": "s", "apis": [], "props": [], "confidence": 0.1},
            {"old": "c", "scope": "s", "apis": [], "props": [], "confidence": 0.1},
        ]
        result = namer.name_variables_from_list(variables)

        assert result.total_batches == 2
        assert mock_call.call_count == 2

    def test_cli_not_available(self, config: Config):
        namer = ClaudeLLMNamer.__new__(ClaudeLLMNamer)
        namer.config = config
        namer.model = "sonnet"
        namer.batch_size = 15
        namer.max_code_lines = 40
        namer.timeout = 60
        namer.min_confidence = 0.5
        namer.min_references = 2
        namer._cli_available = False

        result = namer.name_variables_from_list([{"old": "e", "scope": "s"}])
        assert result.success is False
        assert "bulunamadi" in result.errors[0]


# ---------------------------------------------------------------
# name_variables testleri (mock ile)
# ---------------------------------------------------------------


class TestNameVariables:
    @patch.object(ClaudeLLMNamer, '_call_claude')
    def test_name_variables_from_context(
        self,
        mock_call: MagicMock,
        namer: ClaudeLLMNamer,
        sample_context_json: Path,
        sample_source_file: Path,
    ):
        mock_call.return_value = json.dumps({
            "renames": [
                {"id": "func:main:1::e", "new_name": "electron", "reason": "require"},
                {"id": "func:main:1::t", "new_name": "path", "reason": "require"},
            ]
        })

        result = namer.name_variables(sample_context_json, sample_source_file)

        assert result.success is True
        assert result.total_named == 2
        assert "func:main:1" in result.mappings
        assert result.mappings["func:main:1"]["e"] == "electron"
        assert result.mappings["func:main:1"]["t"] == "path"

    def test_invalid_context_json(
        self, namer: ClaudeLLMNamer, tmp_path: Path
    ):
        bad_json = tmp_path / "bad.json"
        bad_json.write_text("not json {{{")
        source = tmp_path / "source.js"
        source.write_text("var x = 1;")

        result = namer.name_variables(bad_json, source)
        assert result.success is False
        assert any("okunamadi" in e for e in result.errors)

    def test_nonexistent_source_file(
        self, namer: ClaudeLLMNamer, sample_context_json: Path, tmp_path: Path
    ):
        result = namer.name_variables(
            sample_context_json, tmp_path / "missing.js"
        )
        assert result.success is False
        assert any("okunamadi" in e for e in result.errors)


# ---------------------------------------------------------------
# Code snippet extraction testleri
# ---------------------------------------------------------------


class TestGetCodeSnippet:
    def test_with_line_number(self, namer: ClaudeLLMNamer):
        lines = ["line0", "line1", "line2", "line3", "line4", "line5"]
        variable = {"name": "e", "line": 3}
        snippet = namer._get_code_snippet(variable, lines)
        assert "line0" in snippet  # line 3 - 3 = 0
        assert "line2" in snippet

    def test_without_line_number(self, namer: ClaudeLLMNamer):
        lines = ["var x = 1;", "var e = require('electron');", "var y = 2;"]
        variable = {"name": "e"}
        snippet = namer._get_code_snippet(variable, lines)
        assert "require('electron')" in snippet

    def test_no_match(self, namer: ClaudeLLMNamer):
        lines = ["var x = 1;", "var y = 2;"]
        variable = {"name": "zzz_nonexistent"}
        snippet = namer._get_code_snippet(variable, lines)
        assert "not available" in snippet


# ---------------------------------------------------------------
# Config entegrasyon testleri
# ---------------------------------------------------------------


class TestConfigIntegration:
    def test_config_defaults(self):
        config = Config()
        assert config.analysis.use_llm_naming is False
        assert config.analysis.llm_model == "sonnet"

    def test_config_override(self):
        config = Config()
        config.analysis.use_llm_naming = True
        config.analysis.llm_model = "opus"
        assert config.analysis.use_llm_naming is True
        assert config.analysis.llm_model == "opus"
