"""TRex export adimi iskelet testleri (Faz 1).

Sadece:
- TRexExportStep import edilebiliyor mu?
- trex.enabled=false iken step sessizce atlanıyor mu?
- Java script dosyalari beklenen konumda mevcut mu?
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from karadul.pipeline.steps.trex_export import (
    PCODE_EXPORTER_JAVA,
    VARIABLE_EXPORTER_JAVA,
    TRexExportStep,
)


# ---------------------------------------------------------------------------
# Test 1: Import
# ---------------------------------------------------------------------------


def test_import():
    """TRexExportStep ve sabitler import edilebilmeli."""
    assert TRexExportStep is not None
    assert PCODE_EXPORTER_JAVA is not None
    assert VARIABLE_EXPORTER_JAVA is not None


# ---------------------------------------------------------------------------
# Test 2: Java dosyalari var mi?
# ---------------------------------------------------------------------------


def test_pcode_exporter_java_exists():
    """PCodeExporter.java karadul/ghidra/scripts/trex/ altinda olmali."""
    assert PCODE_EXPORTER_JAVA.exists(), (
        f"PCodeExporter.java bulunamadi: {PCODE_EXPORTER_JAVA}"
    )


def test_variable_exporter_java_exists():
    """VariableExporter.java karadul/ghidra/scripts/trex/ altinda olmali."""
    assert VARIABLE_EXPORTER_JAVA.exists(), (
        f"VariableExporter.java bulunamadi: {VARIABLE_EXPORTER_JAVA}"
    )


def test_pcode_exporter_java_nonempty():
    """PCodeExporter.java bos olmamali."""
    assert PCODE_EXPORTER_JAVA.stat().st_size > 100


def test_variable_exporter_java_nonempty():
    """VariableExporter.java bos olmamali."""
    assert VARIABLE_EXPORTER_JAVA.stat().st_size > 100


# ---------------------------------------------------------------------------
# Test 3: trex.enabled=false → skip (None donmeli)
# ---------------------------------------------------------------------------


def _make_ctx(trex_enabled: bool = False) -> MagicMock:
    """Minimal StepContext mock'u olustur."""
    ctx = MagicMock()
    ctx.pipeline_context.config = {"trex": {"enabled": trex_enabled}}
    ctx.pipeline_context.workspace.root = Path("/tmp")
    ctx.artifacts = {"binary_path": "/tmp/test_binary"}
    return ctx


def test_trex_disabled_returns_none():
    """trex.enabled=false iken her iki artifact None donmeli."""
    step = TRexExportStep()
    ctx = _make_ctx(trex_enabled=False)
    result = step.run(ctx)
    assert result["trex_lifted_path"] is None
    assert result["trex_vars_path"] is None


def test_trex_config_missing_defaults_to_disabled():
    """trex config hic yokken de step atlanmali."""
    step = TRexExportStep()
    ctx = MagicMock()
    ctx.pipeline_context.config = {}  # trex key yok
    ctx.pipeline_context.workspace.root = Path("/tmp")
    ctx.artifacts = {"binary_path": "/tmp/test_binary"}
    result = step.run(ctx)
    assert result["trex_lifted_path"] is None
    assert result["trex_vars_path"] is None
