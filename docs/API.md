# API Reference

## Top-Level

```python
import karadul

karadul.__version__   # "1.0.0"
karadul.__codename__  # "Karadul"
```

## karadul.core.Pipeline

Main orchestrator. Runs registered stages sequentially against a target.

```python
from karadul.config import Config
from karadul.core import Pipeline

config = Config.load()              # load from karadul.yaml or defaults
pipeline = Pipeline(config)
pipeline.register_stage(stage)      # add a Stage instance
result = pipeline.run(target_path)  # run all stages
```

### Pipeline.__init__(config: Config)

| Parameter | Type | Description |
|-----------|------|-------------|
| config | `Config` | Central configuration object |

### Pipeline.register_stage(stage: Stage) -> None

Register a pipeline stage. Stages run in registration order.
Raises `ValueError` if a stage with the same name already exists.

### Pipeline.run(target_path, stages=None, on_stage_start=None, on_stage_complete=None) -> PipelineResult

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| target_path | `str \| Path` | required | Path to target file or directory |
| stages | `list[str] \| None` | `None` | Stage names to run (None = all) |
| on_stage_start | `Callable` | `None` | Callback(stage_name, index, total) |
| on_stage_complete | `Callable` | `None` | Callback(stage_name, result, index, total) |

Returns `PipelineResult`.

### Pipeline.registered_stages -> list[str]

Property. Returns list of registered stage names in execution order.

## karadul.core.Stage (ABC)

Abstract base class for pipeline stages.

```python
from karadul.core import Stage, PipelineContext, StageResult

class MyStage(Stage):
    name = "my_stage"
    requires = ["identify"]  # depends on identify stage

    def execute(self, context: PipelineContext) -> StageResult:
        # do work
        return StageResult(stage_name=self.name, success=True, duration_seconds=1.0)
```

### Attributes

| Attribute | Type | Description |
|-----------|------|-------------|
| name | `str` | Unique stage identifier |
| requires | `list[str]` | Stage names that must succeed before this one |

### Stage.execute(context: PipelineContext) -> StageResult

Abstract method. Implement your stage logic here.

## karadul.core.PipelineContext

Shared context passed to every stage.

| Attribute | Type | Description |
|-----------|------|-------------|
| target | `TargetInfo` | Detected target metadata |
| workspace | `Workspace` | Artifact storage manager |
| config | `Config` | Central configuration |
| results | `dict[str, StageResult]` | Previous stage results |
| extra | `dict[str, Any]` | Free-form inter-stage data |

### PipelineContext.get_artifact_path(stage: str, name: str) -> Path | None

Get a named artifact path from a previous stage's results.

### PipelineContext.has_stage_succeeded(stage: str) -> bool

Check whether a specific stage completed successfully.

## karadul.core.OutputFormatter

Converts raw workspace output into a clean, organized directory.

```python
from karadul.core import OutputFormatter

formatter = OutputFormatter(workspace, pipeline_result)
fmt_result = formatter.format_output(output_dir=Path("./output"))
```

### OutputFormatter.__init__(workspace: Workspace, pipeline_result: PipelineResult)

| Parameter | Type | Description |
|-----------|------|-------------|
| workspace | `Workspace` | Pipeline workspace with artifacts |
| pipeline_result | `PipelineResult` | Completed pipeline result |

### OutputFormatter.format_output(output_dir: Path, fmt: str = "clean") -> FormatResult

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| output_dir | `Path` | required | Target output directory |
| fmt | `str` | `"clean"` | Format type: `"clean"` or `"raw"` |

Returns `FormatResult` with `success`, `output_dir`, `files_written`, `src_files`,
`reports_generated`, `errors`.

## karadul.core.ReportGenerator

Generates a self-contained HTML report with dark theme, inline CSS/JS.

```python
from karadul.core import ReportGenerator

gen = ReportGenerator(pipeline_result, workspace)
html_string = gen.generate_html()

with open("report.html", "w") as f:
    f.write(html_string)
```

### ReportGenerator.__init__(result: PipelineResult, workspace: Workspace)

### ReportGenerator.generate_html() -> str

Returns complete HTML page as a string. No external dependencies needed to view.

## karadul.config.Config

Central configuration. All paths, timeouts, thresholds, and feature flags.

```python
from karadul.config import Config

config = Config.load()                     # from karadul.yaml or defaults
config = Config.load(Path("custom.yaml"))  # from specific file
warnings = config.validate()               # check tool availability
```

### Config.load(path: Path | None = None) -> Config (classmethod)

Load from YAML file. Falls back to `karadul.yaml` in cwd, then defaults.

### Config.validate() -> list[str]

Returns list of warning messages for missing external tools.

### Nested Config Sections

| Section | Class | Key Fields |
|---------|-------|------------|
| tools | `ToolPaths` | ghidra_headless, synchrony, radare2, node, nm, otool |
| timeouts | `Timeouts` | ghidra (7200s), subprocess (7200s), synchrony (120s) |
| retry | `RetryConfig` | max_retries (3), circuit_breaker_threshold (5) |
| analysis | `AnalysisConfig` | max_file_size_mb (500), deobfuscation_chain |
| binary_reconstruction | `BinaryReconstructionConfig` | min_naming_confidence (0.7) |
| ml | `MLConfig` | enable_llm4decompile, ml_device, ml_dtype |
| name_merger | `NameMergerConfig` | source_weights, unk_threshold (0.30) |

## Result Types

### StageResult

| Field | Type | Description |
|-------|------|-------------|
| stage_name | `str` | Stage identifier |
| success | `bool` | Whether stage completed successfully |
| duration_seconds | `float` | Wall clock time |
| artifacts | `dict[str, Path]` | Named artifact paths |
| stats | `dict[str, Any]` | Stage-specific statistics |
| errors | `list[str]` | Error messages |

### PipelineResult

| Field | Type | Description |
|-------|------|-------------|
| target_name | `str` | Target file name |
| target_hash | `str` | SHA-256 hash |
| stages | `dict[str, StageResult]` | All stage results |
| total_duration | `float` | Total pipeline time |
| success | `bool` | True if all stages passed |
| workspace_path | `Path` | Workspace directory |

Methods: `add_stage_result()`, `get_failed_stages()`, `get_all_artifacts()`,
`to_dict()`, `to_json()`, `summary()`.
