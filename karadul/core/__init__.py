"""Core modulleri -- pipeline, target detection, workspace, error recovery, chunked processing."""

from .chunked_processor import ChunkedProcessor, ChunkInfo, ChunkResult
from .error_recovery import (
    CircuitBreaker,
    CircuitBreakerOpenError,
    CircuitState,
    ErrorRecovery,
    with_retry,
)
from .pipeline import Pipeline, PipelineContext, Stage
from .result import PipelineResult, StageResult
from .subprocess_runner import SubprocessResult, SubprocessRunner
from .target import Language, TargetDetector, TargetInfo, TargetType
from .workspace import Workspace
from .output_formatter import OutputFormatter, FormatResult
from .report_generator import ReportGenerator

__all__ = [
    # result
    "StageResult",
    "PipelineResult",
    # target
    "TargetType",
    "Language",
    "TargetInfo",
    "TargetDetector",
    # workspace
    "Workspace",
    # error_recovery
    "CircuitState",
    "CircuitBreakerOpenError",
    "CircuitBreaker",
    "ErrorRecovery",
    "with_retry",
    # pipeline
    "Stage",
    "PipelineContext",
    "Pipeline",
    # subprocess_runner
    "SubprocessResult",
    "SubprocessRunner",
    # chunked_processor
    "ChunkedProcessor",
    "ChunkInfo",
    "ChunkResult",
    # output_formatter
    "OutputFormatter",
    "FormatResult",
    # report_generator
    "ReportGenerator",
]
