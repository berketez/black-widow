# API Reference

This page describes the Python interface as it is in the source tree today. There is no
stability promise yet: names outside `karadul.__all__` may change without notice.

## Top level

```python
import karadul

karadul.__all__       # ['analyze', 'Pipeline', 'Config', '__version__', '__codename__']
karadul.__version__   # version string defined in karadul/__init__.py
karadul.__codename__  # "Karadul"
```

`karadul.Pipeline` is `karadul.core.pipeline.Pipeline`; `karadul.Config` is
`karadul.config.Config`.

## karadul.analyze

```text
karadul.analyze(binary_path, *, config=None, stages=None) -> PipelineResult
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| binary_path | `str \| Path` | required | Must be an existing file (a directory raises `FileNotFoundError`) |
| config | `Config \| None` | `None` | `None` means `Config.load()` |
| stages | `list[str] \| None` | `None` | Stage names to run; unknown names are skipped with a warning |

**Known issue.** `analyze()` creates `Pipeline(cfg)` and calls `run()` without registering
any stage. The call therefore detects the target, creates a workspace and returns a
`PipelineResult` with no stage results. Until this is fixed, build the pipeline with the
helper the CLI uses (`karadul.cli_common` is internal, not part of `__all__`):

```python
from pathlib import Path

from karadul import Config
from karadul.cli_common import build_pipeline

cfg = Config.load()
pipeline = build_pipeline(cfg)                     # all six stages
# build_pipeline(cfg, stop_after="static")         # identify + static only
# build_pipeline(cfg, stages=["identify", "static", "report"])
result = pipeline.run(Path("/path/to/binary"))
print(result.summary())
```

`pipeline.run()` prints progress to the console unless callbacks are passed (see below).
It needs Ghidra for native binaries (see the README).

## Stages

Built-in stages (`karadul/stages.py`), in default order (`DEFAULT_STAGE_ORDER` in
`karadul/cli_common.py`):

| Name | Class | Notes |
|------|-------|-------|
| `identify` | `IdentifyStage` | Format, language, size |
| `static` | `StaticAnalysisStage` | For native binaries: Ghidra (PyGhidra if installed, otherwise `analyzeHeadless`) |
| `dynamic` | `DynamicAnalysisStage` | Skipped unless `config.security.allow_target_execution` is `True` (CLI: `--dynamic`); then runs the target under Frida |
| `deobfuscate` | `DeobfuscationStage` | |
| `reconstruct` | `ReconstructionStage` | Naming, types, comments. Imports `pyahocorasick` (`perf` extra) |
| `report` | `ReportStage` | |

Every stage other than `identify` declares `requires = ("identify",)`.

## karadul.core.Pipeline

```python
from karadul import Config, Pipeline

pipeline = Pipeline(Config.load())
pipeline.register_stage(stage)          # a Stage instance; duplicate name -> ValueError
pipeline.registered_stages              # property: list of names in registration order
result = pipeline.run(target_path)
```

### Pipeline.run

```text
run(target_path, stages=None, on_stage_start=None, on_stage_complete=None,
    on_progress=None, log_buffer=None) -> PipelineResult
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| target_path | `str \| Path` | required | Target file or directory |
| stages | `list[str] \| None` | `None` | Subset of registered stages (registration order is kept) |
| on_stage_start | `Callable[[str, int, int], None]` | `None` | `(stage_name, index, total)` |
| on_stage_complete | `Callable[[str, StageResult, int, int], None]` | `None` | `(stage_name, result, index, total)` |
| on_progress | `Callable[[str, str, float], None]` | `None` | `(stage_name, message, fraction)` |
| log_buffer | `collections.deque \| None` | `None` | Collects live log lines |

If `on_stage_start` or `on_stage_complete` is given, the pipeline does not print to the
console. The workspace is created under `config.project_root / "workspaces"`
(`project_root` defaults to the current directory).

## karadul.core.Stage (ABC)

```python
from karadul.core import PipelineContext, Stage, StageResult

class MyStage(Stage):
    name = "my_stage"
    requires = ("identify",)

    def execute(self, context: PipelineContext) -> StageResult:
        return StageResult(stage_name=self.name, success=True, duration_seconds=0.0)
```

`execute` is the only abstract method.

## karadul.core.PipelineContext

Passed to every stage.

| Attribute | Description |
|-----------|-------------|
| target | `TargetInfo` of the detected target |
| workspace | `Workspace` for artifacts |
| config | `Config` |
| results | `dict[str, StageResult]` of earlier stages |
| extra | free-form inter-stage data |
| metadata | free-form metadata |

Methods: `get_artifact_path(stage, name)`, `has_stage_succeeded(stage)`,
`report_progress(message, fraction=-1.0)`.

## Result types (`karadul.core`)

### StageResult

| Field | Type |
|-------|------|
| stage_name | `str` |
| success | `bool` |
| duration_seconds | `float` |
| artifacts | `dict[str, Path]` |
| stats | `dict[str, Any]` |
| errors | `list[str]` |
| skipped | `bool` (default `False`) |

Property `skip_reason`; methods `to_dict()`, `from_dict()`, `summary()`.

### PipelineResult

| Field | Type |
|-------|------|
| target_name | `str` |
| target_hash | `str` (SHA-256) |
| stages | `dict[str, StageResult]` |
| total_duration | `float` |
| success | `bool` (skipped stages do not count as failures) |
| workspace_path | `Path` |

Methods: `add_stage_result()`, `get_failed_stages()`, `get_skipped_stages()`,
`get_all_artifacts()`, `to_dict()`, `from_dict()`, `to_json(indent=2)`, `summary()`.

## karadul.core.OutputFormatter

Writes the clean output directory used by `karadul analyze --output`.

```python
from pathlib import Path
from karadul.core import OutputFormatter

fmt_result = OutputFormatter(workspace, pipeline_result).format_output(Path("./out"), fmt="clean")
```

`fmt` is `"clean"` or `"raw"`. Returns `FormatResult` with `success`, `output_dir`,
`files_written`, `src_files`, `reports_generated`, `errors`. The `naming_map.json` it
writes gives every name `confidence: 1.0`; this value is not a calibrated confidence.

## karadul.core.ReportGenerator

```python
from karadul.core import ReportGenerator

gen = ReportGenerator(pipeline_result, workspace)
html = gen.generate_html()                  # self-contained HTML string
gen.generate_to_file(Path("report.html"))   # returns the written path
```

## karadul.config.Config

```python
from pathlib import Path
from karadul.config import Config

cfg = Config.load()                       # ./karadul.yaml if present, else defaults
cfg = Config.load(Path("custom.yaml"))    # pass a Path, not a str
warnings = cfg.validate()                 # list[str]
```

- `Config.load(path)` expects a `Path`; a `str` raises `AttributeError`. If `path` does not
  exist, it silently falls back to `./karadul.yaml` and then to defaults.
- `validate()` reports a missing Ghidra `analyzeHeadless` or `synchrony`, and conflicting
  fusion settings.
- The Ghidra location comes from `GHIDRA_INSTALL_DIR` / `GHIDRA_HOME` or a search of common
  locations, not from YAML.

Sections (attributes of `Config`): `tools`, `timeouts`, `retry`, `analysis`,
`source_match`, `binary_reconstruction`, `network`, `min_confidence`, `name_merger`,
`deep_trace`, `bsim`, `debugger`, `computation_recovery`, `computation`, `pipeline`,
`perf`, `decompilers`, `security`; plus `project_root`, `scripts_dir`,
`ghidra_scripts_dir`.

Some defaults:

| Setting | Default |
|---------|---------|
| `security.allow_target_execution` | `False` |
| `network.enabled` | `False` |
| `binary_reconstruction.min_naming_confidence` | `0.7` |
| `timeouts.ghidra`, `timeouts.subprocess` | `7200` s |
| `retry.max_retries` | `3` |
| `analysis.max_file_size_mb` | `500` |
| `project_root` | current working directory |

There is no `ml` section; LLM-based naming was removed from the code.

## CLI: `karadul analyze --json`

Prints one JSON object to stdout instead of the result table (`_emit_analyze_json` in
`karadul/cli.py`):

```text
{
  "target": {"name", "type", "language", "size"},
  "success": bool,
  "workspace": str,
  "computation_recovery_enabled": bool,
  "summary": {...},          # counts the stages report, e.g. functions, strings
  "stages": {"<name>": {"success", "skipped", "duration_seconds", "stats", "skip_reason"?}},
  "skipped_stages": [...],
  "failed_stages": [...],
  "reports": {...}           # only if the report stage ran
}
```

The payload contains no accuracy metric. `--json` returns before `--output` is processed,
so the two cannot be combined today.
