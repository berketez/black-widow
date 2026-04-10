# Examples

## 1. Binary Analysis (C++ Executable)

Analyze a stripped C++ Mach-O binary. Karadul runs Ghidra decompilation,
FLIRT signature matching, 6-layer naming, type recovery, algorithm
identification, and generates an HTML report.

```bash
# Basic analysis
karadul analyze /path/to/steam_osx --output ./output/steam/

# With LLM-assisted naming (requires Claude CLI)
karadul analyze /path/to/steam_osx --output ./output/steam/ --use-llm

# Inspect target before full analysis
karadul info /path/to/steam_osx
```

Output:
```
output/steam/
  src/
    main.c                     # Entry point with recovered function names
    modules/
      network_manager.c        # Grouped by call-graph clusters
      crypto_utils.c           # Algorithm-identified functions
      ui_renderer.c
    types/
      structs.h                # Recovered struct definitions
      enums.h                  # Recovered enum types
  report.html                  # Interactive report (open in browser)
  report.json                  # Machine-readable results
  naming_map.json              # FUN_xxxxx -> recovered_name mapping
```

Programmatic usage:

```python
from karadul.config import Config
from karadul.core import Pipeline
from karadul.stages import (
    IdentifyStage, StaticAnalysisStage, DynamicAnalysisStage,
    DeobfuscationStage, ReconstructionStage, ReportStage,
)

config = Config.load()
pipeline = Pipeline(config)
pipeline.register_stage(IdentifyStage())
pipeline.register_stage(StaticAnalysisStage())
pipeline.register_stage(DynamicAnalysisStage())
pipeline.register_stage(DeobfuscationStage())
pipeline.register_stage(ReconstructionStage())
pipeline.register_stage(ReportStage())

result = pipeline.run("/path/to/steam_osx")
print(result.summary())
# Pipeline: steam_osx (SUCCESS)
#   Duration: 342.1s
#   Stages (6):
#     [OK] identify: 0.1s, 1 artifact(s), 0 error(s)
#     [OK] static: 285.3s, 4 artifact(s), 0 error(s)
#     [OK] dynamic: 0.0s, 0 artifact(s), 0 error(s)
#     [OK] deobfuscate: 12.7s, 2 artifact(s), 0 error(s)
#     [OK] reconstruct: 38.4s, 6 artifact(s), 0 error(s)
#     [OK] report: 5.6s, 3 artifact(s), 0 error(s)
```

## 2. JavaScript Bundle Deobfuscation

Analyze an esbuild or webpack bundle. Karadul unpacks modules, deobfuscates
variable names, recovers npm package origins, and reconstructs a runnable
project.

```bash
# Analyze a JS bundle
karadul analyze /path/to/bundle.js --output ./output/bundle/

# Analyze with deep deobfuscation (9-phase pipeline)
karadul analyze /path/to/bundle.js --output ./output/bundle/ --deep-deobf
```

Output:
```
output/bundle/
  src/
    index.js                   # Entry module
    modules/
      react-dom.js             # Identified npm package
      lodash.debounce.js       # Matched by fingerprint
      app/
        router.js              # Application modules
        api-client.js
  package.json                 # Recovered dependencies
  report.html
  report.json
  naming_map.json              # module_42 -> "lodash.debounce"
```

Programmatic usage:

```python
from karadul.config import Config
from karadul.core import Pipeline, OutputFormatter
from karadul.stages import (
    IdentifyStage, StaticAnalysisStage, DynamicAnalysisStage,
    DeobfuscationStage, ReconstructionStage, ReportStage,
)
from pathlib import Path

config = Config.load()
pipeline = Pipeline(config)
pipeline.register_stage(IdentifyStage())
pipeline.register_stage(StaticAnalysisStage())
pipeline.register_stage(DynamicAnalysisStage())
pipeline.register_stage(DeobfuscationStage())
pipeline.register_stage(ReconstructionStage())
pipeline.register_stage(ReportStage())

result = pipeline.run("/path/to/bundle.js")

# Format output into clean directory
from karadul.core import Workspace
workspace = Workspace(
    base_dir=config.project_root / "workspaces",
    target_name="bundle.js",
)
formatter = OutputFormatter(workspace, result)
fmt_result = formatter.format_output(Path("./output/bundle/"))
print(f"Files written: {fmt_result.files_written}")
```

## 3. Swift App Analysis

Analyze a Swift Mach-O binary. Karadul leverages Swift metadata, demangled
symbols, and protocol conformance tables for higher recovery rates.

```bash
# Analyze a macOS .app bundle
karadul analyze /Applications/Rectangle.app --output ./output/rectangle/

# Analyze just the binary inside the app
karadul analyze /Applications/Rectangle.app/Contents/MacOS/Rectangle --output ./output/rectangle/
```

The Swift analyzer extracts:
- Demangled Swift symbols (types, methods, properties)
- Protocol conformance and witness tables
- Objective-C bridging metadata
- Swift-specific type metadata

```python
from karadul.core.target import TargetDetector

detector = TargetDetector()
info = detector.detect("/Applications/Rectangle.app/Contents/MacOS/Rectangle")
print(f"Type: {info.target_type}")    # TargetType.MACHO_BINARY
print(f"Language: {info.language}")    # Language.SWIFT
print(f"Size: {info.file_size:,}")    # 1,843,200
print(f"Arch: {info.metadata.get('arch')}")  # arm64
```

## 4. Docker-based Analysis with Claude Code Reconstruct

For CI/CD or isolated environments, run Karadul in Docker. This example
analyzes a JS bundle from Claude Code.

```bash
# Build the Docker image
docker build -t karadul:v1.0 -f Dockerfile .

# Analyze a target mounted as a volume
docker run --rm \
  -v /path/to/targets:/targets:ro \
  -v /path/to/output:/output \
  karadul:v1.0 \
  karadul analyze /targets/bundle.js --output /output/

# Interactive mode
docker run --rm -it \
  -v /path/to/targets:/targets:ro \
  -v /path/to/output:/output \
  karadul:v1.0 \
  bash
```

Dockerfile (minimal):

```dockerfile
FROM python:3.11-slim

RUN apt-get update && apt-get install -y nodejs npm && rm -rf /var/lib/apt/lists/*
RUN npm install -g deobfuscate

WORKDIR /app
COPY . .
RUN pip install -e ".[all]"

ENTRYPOINT ["karadul"]
```

Full pipeline from clone to report:

```bash
git clone <repo-url> && cd black-widow
docker build -t karadul:v1.0 .

# Analyze Claude Code's bundled JS
docker run --rm \
  -v ~/Desktop/targets:/targets:ro \
  -v ~/Desktop/output:/output \
  karadul:v1.0 \
  analyze /targets/bundle_unwrapped --output /output/claude-code/

# Open the report
open ~/Desktop/output/claude-code/report.html
```
