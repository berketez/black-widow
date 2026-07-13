"""Karadul pipeline paketi — step-based pipeline (v1.10.0 M1).

Feature flag: `config.pipeline.use_step_registry` default True (B2, 2026-05-13).
Bu paket (step-DAG) canli yoldur; False ise eski stages.py monolith'i (obsolete).
"""

from __future__ import annotations

from karadul.pipeline.context import StepContext
from karadul.pipeline.registry import (
    Step,
    StepSpec,
    get_step,
    list_steps,
    register_step,
)
from karadul.pipeline.runner import PipelineRunner

# Steps import edilince decorator'lar kayit olur
from karadul.pipeline import steps as _steps  # noqa: F401

__all__ = [
    "PipelineRunner",
    "Step",
    "StepContext",
    "StepSpec",
    "get_step",
    "list_steps",
    "register_step",
]
