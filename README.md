<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11%2B-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/Ghidra-11%2B-red?style=for-the-badge&logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCI+PHBhdGggZmlsbD0id2hpdGUiIGQ9Ik0xMiAyTDIgN2wxMCA1IDEwLTV6TTIgMTdsMTAgNSAxMC01TTIgMTJsMTAgNSAxMC01Ii8+PC9zdmc+" alt="Ghidra">
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License">
  <img src="https://img.shields.io/badge/Lines-138K%2B-blue?style=for-the-badge" alt="Lines">
</p>

<h1 align="center">Black Widow</h1>
<h3 align="center">Karadul</h3>

<p align="center">
  <strong>Automated binary reverse engineering suite that decompiles, analyzes, and reconstructs closed-source binaries into readable, annotated source code with algorithm-level understanding.</strong>
</p>

<p align="center">
  Mach-O / ELF / PE / Electron / .NET / JVM -- C, C++, Objective-C, Swift, Go, Rust, Java, C#, JavaScript
</p>

---

## What It Does

Black Widow takes a stripped, closed-source binary as input and produces readable, structured source code as output. Not just raw decompilation -- it recovers variable names, struct layouts, algorithm identities, data flow pipelines, and inter-procedural dependencies. The output is annotated C with comments, recovered types, and a full HTML report.

```
 INPUT                           BLACK WIDOW                              OUTPUT
+----------+    +------------------------------------------------+    +------------------+
|          |    |                                                  |    |                  |
| Stripped |    |  Identify -> Static -> Dynamic -> Deobfuscate   |    | Named, commented |
| Binary   | -> |         -> Reconstruct -> Report                | -> | source code with |
| (Mach-O, |    |                                                  |    | recovered types, |
|  ELF,    |    |  6 pipeline stages, 27 analyzer modules,        |    | struct layouts,  |
|  PE,     |    |  10 naming strategies, Bayesian fusion,         |    | algorithm IDs,   |
|  .asar)  |    |  3-layer algorithm detection, struct recovery   |    | HTML report      |
|          |    |                                                  |    |                  |
+----------+    +------------------------------------------------+    +------------------+
```

## Architecture

```
                              karadul analyze /path/to/binary
                                         |
                    +--------------------+--------------------+
                    |                                          |
              IDENTIFICATION                            CONFIGURATION
              TargetDetector                             Config (YAML)
              Language/Format                            Ghidra paths
              Compiler/Packer                            Timeouts/Workers
                    |                                          |
                    +--------------------+--------------------+
                                         |
                    =============================================
                    |           STATIC ANALYSIS                 |
                    |                                           |
                    |  Ghidra Headless (PyGhidra API)           |
                    |    - Function decompilation               |
                    |    - String extraction                    |
                    |    - Call graph construction               |
                    |    - Cross-references (xrefs)             |
                    |    - Type information                     |
                    |                                           |
                    |  Binary Intelligence                      |
                    |    - Subsystem detection                  |
                    |    - Protocol identification              |
                    |    - Security mechanism analysis           |
                    |                                           |
                    |  Signature Matching                       |
                    |    - FLIRT signatures (1.5M+ functions)   |
                    |    - Byte pattern matching                |
                    |    - YARA rule scanning                   |
                    |    - CAPA capability detection            |
                    =============================================
                                         |
                    =============================================
                    |          DYNAMIC ANALYSIS (optional)      |
                    |                                           |
                    |  Frida Runtime Instrumentation             |
                    |    - Function tracing                     |
                    |    - Memory scanning                      |
                    |    - ObjC/Swift method hooking            |
                    |    - Node.js API interception             |
                    =============================================
                                         |
                    =============================================
                    |           DEOBFUSCATION                   |
                    |                                           |
                    |  Binary: opaque predicate removal,        |
                    |          string decryption                |
                    |  JS: CFF deflattening, Babel pipeline,    |
                    |      synchrony, deep deobfuscation        |
                    =============================================
                                         |
          +-------------+---------------+--------------+---------------+
          |             |               |              |               |
     ALGORITHM     TYPE RECOVERY    NAMING         DATA FLOW     STRUCT
     DETECTION                      ENGINE         TRACKER       RECOVERY
          |             |               |              |               |
   3-layer engine  Struct/Enum/    10-strategy    Inter-proc     Pointer
   IEEE-754 const  VTable from     Bayesian       4 patterns     arithmetic
   Structural      pointer         fusion         14K+ deps      -> field
   API correlation arithmetic      8 sources      discovered     access
          |             |               |              |               |
          +-------------+---------------+--------------+---------------+
                                         |
                    =============================================
                    |         RECONSTRUCTION                    |
                    |                                           |
                    |  Named C files with recovered types       |
                    |  Algorithm-aware comments                 |
                    |  Module/project structure                 |
                    |  Formula extraction (LaTeX/ASCII)         |
                    |  Dispatch resolution (ObjC/C++ vtable)    |
                    =============================================
                                         |
                    =============================================
                    |            REPORTING                      |
                    |                                           |
                    |  HTML report with metrics                 |
                    |  JSON machine-readable output             |
                    |  Markdown summary                         |
                    |  SARIF for CI/CD integration              |
                    =============================================
```

## Key Capabilities

### Multi-Domain Algorithm Intelligence Engine

Three-layer detection with Gaussian copula confidence fusion and Platt-calibrated scoring:

| Layer | Method | What It Finds |
|-------|--------|---------------|
| **Layer 1** | IEEE-754 Constant Fingerprinting | Crypto S-boxes, hash init vectors, mathematical constants embedded in code |
| **Layer 2** | Structural Code Pattern Matching | Loop structures, butterfly operations, accumulator patterns across 35+ formula types |
| **Layer 3** | API Correlation | Known crypto/math library calls, BLAS/LAPACK indicators, system API usage |

Confidence fusion uses correlation-aware Noisy-OR with negative evidence penalties and call-graph consistency checks. Results are classified into tiers: **CONFIRMED** / **HIGH** / **MEDIUM** / **LOW**.

35 formula extractors including: matrix operations, ODE discretization, FFT butterfly, Newton-Raphson, Adam optimizer, softmax, CRC/hash rounds, finite differences, convolution, gradient descent, Simpson's rule, and more.

### Bayesian Function Naming

8 evidence sources fused with correlation-aware Bayesian log-odds:

```
log_odds = log(prior / (1-prior)) + SUM_i  w_i * log(conf_i / (1 - conf_i))
P(correct) = sigmoid(log_odds)
```

Sources: symbol table, string context, API calls, call graph position, dataflow analysis, type information, byte pattern matching, source matching. Correlation weights (w_i < 1) prevent double-counting of dependent evidence.

10 naming strategies with confidence tiers from 0.20 to 0.95.

### Virtual Dispatch Resolution

Statically resolves **84% of dynamic method calls** in Objective-C and C++ binaries:

- ObjC: `objc_msgSend` / `objc_msgSendSuper` -> actual method implementations
- C++: vtable dispatch -> concrete function targets
- 4-phase pipeline: site scanning, selector mapping, type propagation, call graph augmentation

### Inter-Procedural Data Flow Tracking

Discovers **14,000+ cross-function data dependencies** through 4 pattern types:

1. **Parameter Passthrough** -- caller argument flows into callee argument
2. **Return-to-Argument** -- function return value passed as argument to another function
3. **Struct/Global Mediation** -- write to struct field, read from another function
4. **Allocation Chain** -- malloc -> fill -> use -> free lifecycle tracking

### Struct Recovery from Pointer Arithmetic

Transforms raw pointer arithmetic into semantic struct field accesses:

```c
// BEFORE (Ghidra output)
*(int *)(param_18 + 4)
*(double *)(param_18 + 0x10)

// AFTER (Black Widow reconstruction)
elem->num_nodes    /* was: *(int *)(param_18 + 4) */
elem->stiffness    /* was: *(double *)(param_18 + 0x10) */
```

3-phase pipeline: template matching from algorithm detection, call graph propagation, code rewrite.

### Computation Recovery

Extracts mathematical formulas from decompiled code and outputs LaTeX/ASCII representations. Recognizes 35+ computational patterns including BLAS/LAPACK calls, matrix operations, ODE solvers, FFT, neural network operations, and numerical methods.

## Supported Formats

| Category | Formats | Languages |
|----------|---------|-----------|
| **Native Binary** | Mach-O, ELF, PE, Universal Binary | C, C++, Objective-C, Swift, Go, Rust |
| **Managed Binary** | JAR, APK, .NET Assembly | Java, Kotlin, C# |
| **JavaScript Bundle** | webpack, esbuild, Terser, obfuscator.io | JavaScript, TypeScript |
| **Packed Application** | Electron .app / .asar | JS + native components |
| **Special** | Delphi, Python bytecode | Delphi (Object Pascal), Python |

## Technology Stack

| Component | Technology | Purpose |
|-----------|------------|---------|
| Decompilation | **Ghidra** (PyGhidra API) | Binary -> decompiled C |
| Disassembly | **Capstone** | Multi-arch instruction decoding |
| Binary Parsing | **LIEF** | Mach-O / ELF / PE format parsing |
| Dynamic Analysis | **Frida** | Runtime instrumentation and hooking |
| Pattern Matching | **YARA** | Rule-based binary pattern scanning |
| Constraint Solving | **Z3** | Deobfuscation, opaque predicate removal |
| ML Naming | **LLM4Decompile** | Neural decompilation assistance |
| Formula Extraction | **SymPy** | Symbolic math for computation recovery |
| Signature DB | Custom (1.5M+ sigs) | Library function identification |
| CLI | **Click** + **Rich** | Terminal interface with progress bars |

## Tested Targets

| Target | Type | Size | Functions | Recovery | Details |
|--------|------|------|-----------|----------|---------|
| Rectangle | Swift (Mach-O) | 1.8 MB | 2,852 | 89.9% | 257 structs, 24 enums recovered |
| Steam | C++ ARM64 (Mach-O) | 4.1 MB | 11,296 | 74.2% | 542 signature matches, 945 opaque predicates removed |
| Claude Code | JS (esbuild) | 11.8 MB | 43,747 | 57.3% | 1,590 modules, 83K comments added |
| Cursor | JS (3 bundles) | 5.97 MB | 17,705 | 65.4% | 72 modules unpacked |

Recovery % = named symbols / total symbols, weighted by confidence.

## Installation

**Requirements:** Python 3.11+, Ghidra 11+ (for binary decompilation), Node.js 20+ (for JS analysis)

```bash
# Clone
git clone https://github.com/berketez/black-widow.git
cd black-widow

# Base install
pip install -e .

# With binary analysis support
pip install -e ".[binary]"    # capstone + lief

# With dynamic analysis
pip install -e ".[dynamic]"   # frida

# With ML-assisted naming
pip install -e ".[ml]"        # torch + transformers

# With deobfuscation extras
pip install -e ".[deobf]"     # z3-solver

# Everything
pip install -e ".[all]"
```

Set `GHIDRA_INSTALL_DIR` environment variable to your Ghidra installation path.

## Quick Start

```bash
# Analyze a native binary
karadul analyze /path/to/binary

# Analyze an Electron app
karadul analyze /path/to/app.asar

# Analyze a JavaScript bundle
karadul analyze /path/to/bundle.js

# Get target information without full analysis
karadul info /path/to/binary

# Batch analyze multiple targets
karadul batch analyze --targets all

# List previous analyses
karadul list

# Run reconstructed project (JS targets)
karadul run <target-name>
```

## Output

```
workspace/<target>/
  static/
    ghidra_output/           # Raw Ghidra decompilation
    ghidra_functions.json    # Function metadata
    ghidra_strings.json      # Extracted strings
    ghidra_call_graph.json   # Call graph
  reconstruction/
    named_c/                 # Named and commented C files
    type_recovered/          # Files with recovered struct/enum types
    semantic_named/          # Algorithm-aware parameter names
  report/
    report.html              # Interactive HTML report
    report.json              # Machine-readable results
    report.md                # Markdown summary
    report.sarif             # SARIF for CI/CD
  naming_map.json            # Complete symbol mapping
```

## Project Structure

```
karadul/                         # 138K+ lines Python
  analyzers/                     # 27 binary analyzers
    binary_intelligence.py       #   Architecture extraction from strings/symbols
    signature_db.py              #   1.5M+ library function signatures
    macho.py                     #   Mach-O format analyzer
    go_binary.py                 #   Go binary recovery (string table, interfaces)
    swift_binary.py              #   Swift metadata, protocol conformances
    rust_binary.py               #   Rust panic strings, trait objects
    electron.py                  #   Electron app unpacking
    yara_scanner.py              #   YARA rule-based scanning
    capa_scanner.py              #   CAPA capability detection
    flirt_parser.py              #   FLIRT signature matching
    byte_pattern_matcher.py      #   Byte-level pattern matching
    cfg_analyzer.py              #   Control flow graph analysis
    packed_binary.py             #   Packer/protector detection
    ...
  core/                          # Pipeline infrastructure
    pipeline.py                  #   Stage-based execution engine
    target.py                    #   Target detection and classification
    report_generator.py          #   Multi-format report generation
    workspace.py                 #   Analysis workspace management
    ...
  deobfuscators/                 # Deobfuscation engines
    cff_deflattener.py           #   Control flow flattening recovery
    opaque_predicate.py          #   Opaque predicate removal
    string_decryptor.py          #   Encrypted string recovery
    deep_pipeline.py             #   Multi-pass JS deobfuscation
    binary_deobfuscator.py       #   Binary-level deobfuscation
    ...
  reconstruction/                # Source reconstruction
    c_namer.py                   #   10-strategy variable/function naming
    c_type_recoverer.py          #   Struct/enum/vtable recovery
    c_algorithm_id.py            #   3-layer algorithm detection
    c_comment_generator.py       #   Algorithm-aware comment generation
    name_merger.py               #   Bayesian multi-source name fusion
    string_intelligence.py       #   String-based intelligence extraction
    binary_name_extractor.py     #   Debug string / RTTI / build path extraction
    engineering/                  #   Advanced reconstruction
      dispatch_resolver.py       #     ObjC/C++ virtual dispatch resolution
      data_flow.py               #     Inter-procedural data flow tracking
      struct_recovery.py         #     Pointer arithmetic -> struct fields
      semantic_namer.py          #     Algorithm-aware parameter naming
      confidence_calibrator.py   #     Gaussian copula confidence fusion
      formula_reconstructor.py   #     Mathematical formula reconstruction
      patterns.py                #     9,600+ engineering algorithm patterns
      constants.py               #     4,000+ IEEE-754 constant fingerprints
      ...
    computation/                  #   Mathematical computation recovery
      formula_extractor.py       #     35+ formula pattern extractors
      constraint_solver.py       #     Z3-based constraint solving
      signature_fusion.py        #     Multi-source signature fusion
      cfg_fingerprint.py         #     CFG-based function fingerprinting
      ...
    naming/                       #   Advanced naming subsystem
      ...
    source_matcher/               #   Source code matching (npm, open-source)
      ...
    ml/                           #   ML-assisted reconstruction
      llm4decompile.py           #     Neural decompilation model
      ...
  ghidra/                        # Ghidra integration
    headless.py                  #   PyGhidra API wrapper
    bsim.py                      #   BSim function similarity
    program_diff.py              #   Binary diffing
    debugger_bridge.py           #   Ghidra debugger integration
    scripts/                     #   Ghidra analysis scripts
  frida/                         # Dynamic analysis
    session.py                   #   Frida session management
    collectors/                  #   Runtime data collectors
    hooks/                       #   ObjC/Node.js/generic hooks
  reporting/                     # Report generation
    html_report.py               #   Interactive HTML reports
    sarif_report.py              #   SARIF CI/CD integration
    markdown_report.py           #   Markdown reports
    json_report.py               #   JSON output
  stages.py                      #   Pipeline stage definitions
  cli.py                         #   Main CLI (Click-based)
  hacker_cli.py                  #   Hacker-style interactive CLI
  config.py                      #   Central configuration
  batch.py                       #   Batch analysis runner
scripts/                         # Auxiliary analysis scripts
tests/                           # 1,180+ tests
docs/                            # Technical documentation
tools/                           # Development utilities
```

## Tests

```bash
pytest tests/ -v
```

1,180+ tests covering target detection, binary analysis, signature matching, naming strategies, type recovery, algorithm detection, deobfuscation, pipeline integration, and report generation.

## License

MIT License. See [LICENSE](LICENSE).

## Author

**Berke Tezgocen**
