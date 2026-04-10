# Contributing

## Development Setup

```bash
# Clone
git clone <repo-url>
cd black-widow

# Create virtual environment
python3.11 -m venv .venv
source .venv/bin/activate

# Install in editable mode with dev dependencies
pip install -e ".[all]"

# Verify
karadul version
pytest tests/ -x --tb=short
```

### External Tools

Some features require external tools:

| Tool | Required For | Install |
|------|-------------|---------|
| Ghidra 12.0+ | Binary decompilation | [ghidra-sre.org](https://ghidra-sre.org/) |
| Node.js 20+ | JS analysis scripts | `brew install node` |
| synchrony | obfuscator.io targets | `npm install -g deobfuscate` |
| Frida | Dynamic analysis | `pip install frida-tools` |

Configure tool paths in `karadul.yaml` or rely on auto-detection.

## Running Tests

```bash
# All tests
pytest tests/

# Specific test file
pytest tests/test_pipeline.py

# Specific test
pytest tests/test_pipeline.py::test_pipeline_run -v

# With coverage
pytest tests/ --cov=karadul --cov-report=html

# Skip network-dependent tests
pytest tests/ -m "not network"
```

## Adding a New Analyzer

To add support for a new binary format or language:

1. Create `karadul/analyzers/your_language.py`
2. Subclass `BaseAnalyzer` and implement `analyze_static()` and `deobfuscate()`
3. Register with `@register_analyzer(TargetType.YOUR_TYPE)`
4. Add the new `TargetType` to `karadul/core/target.py` if needed
5. Import your module in `karadul/analyzers/__init__.py`
6. Write tests in `tests/test_your_language.py`

Example skeleton:

```python
from karadul.analyzers import register_analyzer
from karadul.analyzers.base import BaseAnalyzer
from karadul.config import Config
from karadul.core.result import StageResult
from karadul.core.target import TargetInfo, TargetType
from karadul.core.workspace import Workspace


@register_analyzer(TargetType.YOUR_TYPE)
class YourAnalyzer(BaseAnalyzer):
    supported_types = [TargetType.YOUR_TYPE]

    def __init__(self, config: Config) -> None:
        super().__init__(config)

    def analyze_static(self, target: TargetInfo, workspace: Workspace) -> StageResult:
        # Extract functions, strings, symbols
        # Save artifacts via workspace.save_json() / workspace.save_artifact()
        return StageResult(stage_name="static", success=True, duration_seconds=0.0)

    def deobfuscate(self, target: TargetInfo, workspace: Workspace) -> StageResult:
        # Remove obfuscation if applicable
        return StageResult(stage_name="deobfuscate", success=True, duration_seconds=0.0)
```

## Code Style

- Formatter: `black` (line length 100)
- Linter: `ruff`
- Type hints on all public functions
- Docstrings on all public classes and methods

```bash
black karadul/ tests/ --line-length 100
ruff check karadul/ tests/
```

## Pull Request Guidelines

1. One PR per feature or fix. Keep changes focused.
2. All tests must pass: `pytest tests/`
3. New features require tests.
4. Update `CHANGELOG.md` with your changes.
5. Use clear commit messages: `fix: ...`, `feat: ...`, `refactor: ...`
6. Do not commit secrets, large binaries, or signature database files.

## Project Conventions

- All configuration values go in `karadul/config.py`. No hardcoded magic numbers.
- Stages communicate only through `PipelineContext` and `Workspace` artifacts.
- Analyzers register themselves via decorator; the pipeline discovers them automatically.
- External tool calls go through `SubprocessRunner` for timeout and retry handling.
