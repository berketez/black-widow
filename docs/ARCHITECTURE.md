# Architecture

## Overview

Karadul is a multi-stage reverse engineering pipeline that takes compiled binaries
or obfuscated JavaScript bundles as input and produces readable, named, commented
source code with an HTML report.

## Pipeline Flow

```
                                   Karadul Pipeline
                                   ================

  +----------+    +----------+    +----------+    +-------------+    +--------------+    +--------+
  |  Input   |--->| Identify |--->|  Static  |--->| Deobfuscate |--->| Reconstruct  |--->| Report |
  | (target) |    |          |    | Analysis |    |             |    |              |    |        |
  +----------+    +----------+    +----------+    +-------------+    +--------------+    +--------+
       |               |               |                |                  |                  |
   binary/JS     detect type     Ghidra/AST       CFF defl,         naming, typing,    HTML/JSON/MD
   bundle        language,       strings,         string decrypt,   module split,      report with
                 compiler,       symbols,         opaque pred,      comment gen,       confidence
                 metadata        FLIRT/YARA       babel transforms  project scaffold   metrics
```

## Stage Descriptions

### Stage 1: Identify

Detects the target file type, programming language, compiler, and packer.
Uses magic bytes, file headers, Mach-O/ELF/PE parsing, and heuristics.

- Input: file path
- Output: `TargetInfo` (type, language, file size, metadata)
- Module: `karadul/core/target.py` (`TargetDetector`)

### Stage 2: Static Analysis

Runs the appropriate analyzer for the detected target type. For binaries, this
invokes Ghidra headless decompilation, string extraction, symbol table parsing,
FLIRT signature matching, YARA scanning, and byte pattern matching. For JS bundles,
it parses the AST, extracts modules, and identifies the bundler.

- Input: `TargetInfo` + `Workspace`
- Output: decompiled functions, strings, symbols, call graph
- Module: `karadul/analyzers/` (per-language analyzers)

### Stage 3: Dynamic Analysis (optional)

Frida-based runtime tracing. Hooks function calls, captures arguments and return
values at runtime. Only runs when Frida is available and the target is executable.

- Input: `TargetInfo` + `Workspace`
- Output: runtime traces, API call logs
- Module: `karadul/frida/`

### Stage 4: Deobfuscation

Removes obfuscation layers. For binaries: control flow flattening (CFF)
deflattening, opaque predicate removal, string decryption. For JS: synchrony
deobfuscation, Babel AST transforms, deep 9-phase deobfuscation pipeline.

- Input: static analysis artifacts
- Output: cleaned/beautified code
- Module: `karadul/deobfuscators/`

### Stage 5: Reconstruction

The core value stage. Takes deobfuscated code and recovers meaningful structure:
variable/function naming (6-layer deterministic + Bayesian fusion), type recovery
(struct/enum/vtable), algorithm identification, comment generation, module
splitting, dependency resolution, and project scaffolding.

- Input: deobfuscated code + static analysis data
- Output: named source files, type definitions, comments
- Module: `karadul/reconstruction/`

### Stage 6: Report

Generates human-readable output. Produces a self-contained HTML report (dark theme,
inline CSS/JS), JSON machine-readable results, Markdown summary, and a clean output
directory with recovered source files.

- Input: all previous stage results
- Output: `report.html`, `report.json`, `naming_map.json`, source directory
- Module: `karadul/core/report_generator.py`, `karadul/reporting/`

## Module Map

```
karadul/
  __init__.py                  # Package root, version info
  config.py                    # Central configuration (all paths, timeouts, thresholds)
  cli.py                       # Click-based CLI (analyze, info, list, clean, run)
  hacker_cli.py                # Interactive hacker-style terminal UI
  stages.py                    # Pipeline stage definitions (6 stages)
  batch.py                     # Batch analysis runner

  core/
    pipeline.py                # Pipeline orchestrator, Stage base class, PipelineContext
    target.py                  # TargetDetector, TargetInfo, TargetType, Language enums
    workspace.py               # Workspace manager (artifact save/load per stage)
    result.py                  # StageResult, PipelineResult dataclasses
    output_formatter.py        # OutputFormatter (workspace -> clean output directory)
    report_generator.py        # ReportGenerator (self-contained HTML report)
    error_recovery.py          # ErrorRecovery, CircuitBreaker, retry logic
    chunked_processor.py       # ChunkedProcessor for large binary analysis
    subprocess_runner.py       # SubprocessRunner with timeout and retry
    content_store.py           # Content-addressable artifact storage

  analyzers/
    base.py                    # BaseAnalyzer abstract class
    macho.py                   # Mach-O binary analyzer (Ghidra integration)
    javascript.py              # JavaScript bundle analyzer (webpack/esbuild)
    electron.py                # Electron app analyzer (.app/.asar)
    swift_binary.py            # Swift binary analyzer (demangle, metadata)
    go_binary.py               # Go binary analyzer (pclntab, GOROOT)
    rust_binary.py             # Rust binary analyzer (panic strings, demangling)
    java_binary.py             # Java/Kotlin analyzer (CFR decompiler)
    dotnet_binary.py           # .NET/C# analyzer (ILSpy integration)
    signature_db.py            # 1.5M+ library function signature database
    flirt_parser.py            # FLIRT signature extraction and matching
    byte_pattern_matcher.py    # Byte pattern matching for library function ID
    yara_scanner.py            # YARA rule scanning
    binary_intelligence.py     # Binary metadata extraction (compiler, packer)
    assembly_analyzer.py       # ARM64/x86 assembly pattern analysis
    inline_detector.py         # Inlined function detection
    bindiff.py                 # BinDiff binary comparison
    packed_binary.py           # Packed/protected binary detection and unpacking

  deobfuscators/
    manager.py                 # DeobfuscationManager (chain orchestration)
    deep_pipeline.py           # 9-phase deep deobfuscation pipeline
    babel_pipeline.py          # Babel AST transform wrapper
    synchrony_wrapper.py       # synchrony CLI wrapper
    cff_deflattener.py         # Control flow flattening removal
    opaque_predicate.py        # Opaque predicate removal
    string_decryptor.py        # Encrypted string recovery
    binary_deobfuscator.py     # Binary-level deobfuscation

  reconstruction/
    c_namer.py                 # 6-layer C variable/function naming
    c_namer_patterns.py        # Pattern database for C naming
    c_type_recoverer.py        # Struct/enum/vtable recovery from Ghidra output
    c_algorithm_id.py          # Algorithm identification (crypto, hash, sort)
    c_comment_generator.py     # Smart comment generation for C code
    c_project_builder.py       # C project scaffolding (Makefile, headers)
    name_merger.py             # Bayesian name fusion from multiple sources
    string_intelligence.py     # String-based name inference
    binary_name_extractor.py   # Binary name/metadata extraction
    context_namer.py           # Context-aware naming
    param_recovery.py          # Function parameter recovery
    dts_namer.py               # TypeScript .d.ts mapping for API naming
    api_param_db.py            # API parameter name database
    variable_renamer.py        # JS variable rename (semantic rules)
    module_splitter.py         # Webpack module splitting
    type_inferrer.py           # JSDoc type inference
    comment_generator.py       # JS comment generation
    gap_filler.py              # Static + dynamic result merging
    dependency_resolver.py     # npm dependency resolution
    project_builder.py         # JS project scaffolding
    project_reconstructor.py   # Full project reconstruction
    inline_extractor.py        # Inline code extraction
    jsnice_renamer.py          # JSNice-style renaming
    naming/                    # 5-layer hybrid naming pipeline
    source_matcher/            # Minified-to-original source matching
    ml/                        # ML-assisted decompilation (LLM4Decompile)

  reporting/
    html_report.py             # HTML report template
    json_report.py             # JSON report output
    markdown_report.py         # Markdown report output

  frida/                       # Dynamic analysis Frida scripts and collectors
  ghidra/                      # Ghidra headless analysis scripts

scripts/                       # Build scripts (signature DB, Babel transforms, etc.)
tests/                         # 1,180+ tests
```

## Key Design Decisions

1. **Stage isolation**: Each stage communicates through `PipelineContext` and
   `Workspace` artifacts. Stages never call each other directly.

2. **Analyzer registry**: Analyzers register themselves via `@register_analyzer`
   decorator. The pipeline looks up the correct analyzer by `TargetType`.

3. **Error recovery**: `ErrorRecovery` with exponential backoff and circuit breaker
   protects against transient Ghidra/subprocess failures.

4. **Bayesian name fusion**: Multiple naming sources (symbol, string, API, call-graph,
   dataflow, type) are fused using source-weighted Bayesian combination with
   configurable correlation weights.

5. **Central config**: All thresholds, paths, timeouts live in `config.py`. No magic
   numbers scattered across modules.
