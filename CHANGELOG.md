# Changelog

## [1.10.0] - 2026-04-21

### Added — Yeni Paketler (CPU-only mimari)
- **`karadul/computation/`** — Hesaplama bazli kurtarma (LLM'siz): struct MaxSMT (Z3), CFG isomorphism hibrit (WL + LSH + VF2++ + anchor), signature fusion (log-odds ensemble + Platt)
- **`karadul/pipeline/`** — 20 atomik step registry + StepContext (binary_prep, ghidra_metadata, byte_pattern, pcode_cfg, algorithm_id, parallel_algo_eng, confidence_filter, assembly_analysis, feedback_loop, struct_recovery, inline_detection, semantic_naming, flow_simplify, comment_generation, capa_annotation, engineering_annotation, project_build, engineering_analysis, deep_tracing, finalize)
- **`karadul/quality/`** — Readability Scorer (6 boyut, dwarfdump ground truth, CLI `karadul score`, 13 dosya)
- **`karadul/naming/`** — Hybrid thread + process pool naming runner
- **`karadul/decompilers/`** — Protocol tabanli backend abstraction (Ghidra + angr adapter)
- **`karadul/resources/capa_name_map.json`** — 86 CAPA addr → funcname entry

### Added — Yeni Modüller
- **LMDB SignatureDB** (`karadul/analyzers/sigdb_lmdb.py`): 9.2M signature, 2GB on-disk, cold start 14,400x hizli, +0 MB RSS (mmap)
- **TypeForge adapter** (`karadul/analyzers/typeforge_adapter.py`): Subprocess + LLVM IR, kurulu degilse graceful skip
- **C++ RTTI scanner** (`karadul/analyzers/cpp_rtti.py`): Itanium ABI (single + multi + virtual inheritance, diamond) + MSVC RTTI (Windows x86/x64, Complete Object Locator + Class Hierarchy Descriptor + BaseClassDescriptor, `.?AV` / `.?AU` type_info demangling, template + nested namespace), cxxfilt entegre, CLI `karadul rtti`. Yeni public API: `CppRttiAnalyzer.analyze(binary_path) -> CppRttiResult` otomatik ELF/Mach-O -> Itanium, PE -> MSVC rotalamasi.
- **Platform map merkezi** (`karadul/core/platform_map.py`): `_TARGET_PLATFORM_MAP` tek kaynaktan import
- `karadul/reconstruction/ts_declarations_namer.py` — TypeScript `.d.ts` parser (standalone API, v1.11 pipeline entegrasyonu planli)
- `karadul/computation/struct_recovery/field_namer.py` — MaxSMT struct field naming (Bayesian fusion, standalone API, v1.11 pipeline entegrasyonu planli)

### Changed — Rename/Yeniden Yapilanma
- `karadul/reconstruction/computation/` → `karadul/reconstruction/recovery_layers/` (39 import guncellendi)
- Eski computation/*.py dosyalari silindi (callee_profile_propagator, cfg_fingerprint, constraint_solver, engine, formula_extractor, signature_fusion + templates/)
- **`gpu_utils.py` silindi** — CPU-only karar, GPU yolu v1.5.0+'a ertelendi
- Feedback loop karadul/pipeline/steps/feedback/ altina alindi (sub-runner, 12 helper, 3 faz + convergence)
- Semantic namer priority chain: sig DB params (0.95) > API patterns (0.92)

### Security — Fix Sprint Batch 1 + Batch 2 (2026-04-20/21)
- **HIGH** CWE-22: Path traversal `startswith` → `Path.resolve().relative_to()` (workspace.py 2x, reference_populator.py 3x, packed_binary.py 1x)
- **HIGH** CWE-409: ZIP bomb 2GB uncompressed limit + config alani (`reference_populator.py`)
- **HIGH** CWE-78: `_ALLOWED_SHELL_CMDS` daraltildi (cp/mv/mkdir/install/echo kaldirildi) + args validation
- **HIGH** CWE-88: `c++filt` argv injection — `--` separator eklendi (2 yer)
- **HIGH** CWE-404: Popen context manager (swift_binary, dwarf_extractor, binary_name_extractor)
- **MED** CWE-918: HTTPS scheme whitelist + max_bytes + same-host redirect (3 yer)
- **MED** CWE-116: YARA meta escape (", \, control char reddi)
- **MED** CWE-377: Ghidra script `/tmp` → `tempfile.mkdtemp()` (~10 dosya)
- **MED** CWE-459: `stages.py` NamedTemporaryFile cleanup NameError fix

### Algorithm / Correctness Fixes
- **Struct recovery**: `same_object` vs `same_type` ayrimi (aliasing semantigi)
- **CFG fingerprint**: Hibrit zorunlu — WL + LSH on + VF2++ + anchor (tek algoritma yasak)
- **Signature fusion**: Log-odds ensemble (eski Bayesian/D-S carpma kaldirildi), Platt calibration, 3-threshold abstain/reject/accept
- **Convergence bug**: Empty merger -> 5 reason kategorisi ile erken cikis
- **Feedback loop** 54 NameError (`functionsjson` vs `functions_json`)
- **Frida SIP** testleri `@pytest.mark.integration` ile isaretlendi
- **DWARF extractor**: `tests/test_dwarf_extractor.py` modernize (DWARF agent)

### Performance
- **LMDB mmap**: RAM 3GB → 0MB aktarimi (platform-aware SignatureDB korunuyor)
- **Naming parallel**: Hybrid ThreadPool + ProcessPool flag bazli, 3-5x hizlanma
- **Cold start**: Module-level signature dict parse'i LMDB cursor'a tasindi (14,400x)
- **Step registry**: 20 atomik step, ornegin yeniden calistirilabilir (incremental pipeline)

### Tests
- **Yeni test dosyalari**: test_batch_v1_10_0, test_capa_funcname_mapping, test_cfg_isomorphism, test_computation_integration, test_convergence_fix, test_struct_maxsmt, test_v1100_fix_sprint, test_v1100_pipeline_fixes, test_v1100_recon_naming_fixes, test_signature_fusion, test_parallel_naming_perf, test_cpp_rtti_msvc (28), test_cpp_rtti_multi_inheritance (16)
- **Test toplami: 2794 → 3241 PASS** (+447 yeni, 0 FAIL, 0 regression)

### Dependencies (pyproject.toml)
- Extras eklendi: `perf` (lmdb, msgpack), `cpp` (cxxfilt), `decompilers` (angr)
- `ml` extras (torch/transformers/...) CPU-only karar sonrasi opsiyonel kaldi
- Version: 1.9.2 → 1.10.0

### Kalan Teknik Borc (v1.11+)
- Eski `stages.py` feedback_loop kodu else branch'inde (feature flag ile yasiyor)
- `artifacts_pending` shim pattern (step izolasyonunu hafif bozuyor)
- TypeForge gercek kurulum (adapter hazir, kendisi yok)
- angr `stages.py` entegrasyonu (backend hazir, pipeline degil)
- Integration test (step-by-step full pipeline)

### Known Limitations (v1.10.0)

#### v1.10.1'e ertelenen
- (Bosaltildi — MSVC RTTI ve Itanium multi/virtual inheritance Batch 3E kapsaminda v1.10.0'a eklendi.)

#### v1.11.0'a ertelenen teknik borc
- **`artifacts_pending` shim pattern:** 14 step `pc.metadata.setdefault("artifacts_pending", {})` pattern'i ile step izolasyonunu gevsetiyor. Explicit `StepContext.produce_artifact(key, value)` API'sine gecirilmeli + registry `produces` validation'i ile baglanmali. Migration plani: `docs/ARTIFACTS_PENDING_MIGRATION.md`.
- **Eski `enable_signature_fusion` flag:** `karadul/config.py:367` DEPRECATED durumda, `ComputationConfig.enable_computation_fusion` kullanilmali. v1.11.0'da silinecek.
- **Eski Dempster-Shafer fusion yolu:** `karadul/reconstruction/recovery_layers/engine.py:171` `DeprecationWarning` atiyor. v1.11.0'da silinecek; log-odds ensemble tek yol olacak.
- **TypeForge gercek entegrasyon:** `karadul/analyzers/typeforge_adapter.py` subprocess + LLVM IR protokolu hazir, TypeForge'un kendisi kurulu degil. Optional extras ile opsiyonel kalacak.
- **angr `stages.py` entegrasyonu:** Backend hazir (`karadul/decompilers/`), ama `stages.py` pipeline'ina baglanmadi. Flag mevcut, aktif entegrasyon yok.
- **Integration smoke test kapsami:** `tests/test_pipeline_integration_smoke.py` lineer ve diamond zinciri kapsiyor; tum 20 step'i end-to-end gercek binary ile kosan integration test yok.

#### Bilincli tasarim kararlari
- **CPU-only:** v1.10.0 GPU kod yollarini tamamen kaldirdi. `gpu_utils.py` silindi. Onceki surumlerde GPU destegi yoktu ve geri de gelmeyecek — CPU-only, karadul'un temel tasarim prensibi.
- **LLM'siz:** Hesaplama bazli kurtarma (Z3 MaxSMT, CFG isomorphism, log-odds fusion) LLM tabanli yaklasimlara alternatif. LLM entegrasyonu planlanmiyor.
- **Struct recovery default `True`:** Ship-it karari. Kapatmak icin `--no-maxsmt-struct` CLI flag'i veya YAML config.

## [1.9.2] - 2026-04-09

### Security
- **CRITICAL** CWE-94: Frida JavaScript injection fix -- `module_name` artik `json.dumps` ile escape ediliyor (`memory_scanner.py`)
- **CRITICAL** CWE-22: ZIP path traversal fix -- `extractall` oncesi member path kontrolu (`reference_populator.py`)
- **HIGH** CWE-22: Workspace `load_artifact` path traversal korunmasi (`workspace.py`)
- **HIGH** CWE-94: `karadul run` komutu artik guvenlik uyarisi gosteriyor, `--yes` flag'i ile bypass
- **HIGH** CWE-78: Compiler/shell command whitelist -- izinsiz komutlar engelleniyor (`reference_populator.py`)
- **MEDIUM** CWE-459: Tempfile cleanup -- `delete=False` dosyalari `try/finally` ile temizleniyor (`param_recovery.py`)
- **MEDIUM** CWE-377: Ghidra script `/tmp` dizini tahmin edilemez hale getirildi (PID suffix)

### Fixed
- **88 bare `except Exception: pass`** → `logger.debug(exc_info=True)` (27 dosya, 78 fix). Silent hata yutma salgini duzeltildi.
- **Thread safety**: ThreadPool worker'lari artik kendi result dict'lerini donduruyor, main thread merge ediyor (GIL-free Python 3.13+ uyumu)
- **`dir()` anti-pattern**: `'naming_result' in dir()` → `naming_result is not None` (`stages.py`)
- **`_func_data` None check**: JSON parse hatasi durumunda `isinstance(dict)` kontrolu eklendi
- **Stats key overwrite**: Feedback loop timing key'leri iterasyon suffix'li (`timing_X_iterN`)
- **Mutable default**: `requires: list = []` → `tuple = ()` (`pipeline.py`, `stages.py`)
- **Dead files silindi**: `engine 2.py`, `__pycache__ 2/`, `constants_v1_backup.py`
- **Duplicate code birlesti**: `_merge_stage_results` module-level fonksiyon, `_collect_all_algorithms` helper
- **20+ re-import temizlendi**: Method body icindeki tekrarlanan `import X as _X` satirlari kaldirildi
- **target.py** docstring icine karismis `import logging` duzeltildi

### Algorithm Improvements
- **XTRIDE Typer**: Additive confidence merging → Bayesian log-odds fusion. 2x 0.85 → 0.97 (eski: 0.90). Minimum threshold 0.50 eklendi.
- **CFG Fingerprint**: Feature 18/22 (reserved zero) cosine similarity'den haric tutuldu (22 aktif boyut)
- **Signature Fusion**: D-S conflict metric duzeltildi: `1-(best-second)` → `second/best` (0=dominant, 1=belirsiz)

### Performance
- **Platform-aware SignatureDB**: Hedef platformla uyumsuz signature dosyalari yuklemiyor (~3GB RAM kazanci)
- **rglob cache**: `decompiled_dir.rglob("*.c")` 13x → 1x (invalidation destekli)
- **re.compile cache**: XTRIDE/Dynamic/Ngram naming loop icindeki regex precompile (3 pattern cache)
- **Module pre-instantiation**: ComputationRecoveryEngine, CVariableNamer, CTypeRecoverer loop oncesi olusturuluyor
- **InlineDetector file_cache**: `_file_cache.get()` ile disk I/O azaltildi
- **`_TARGET_PLATFORM_MAP`**: Method icinden module-level constant'a tasindi

### Tests
- 108 yeni test (51 security + 57 algorithm/perf)
- Test toplami: 2687 → **2795 PASS**, 0 FAIL

## [1.8.6] - 2026-04-07

### Added
- **CAPA Integration**: Mandiant CAPA capability detection (1385 kural). Fonksiyon capability tespiti: "encrypt data", "send HTTP request", vb. Naming + comment pipeline'a entegre. PE/ELF binary'ler icin.
- **XTRIDE Type Inference**: N-gram tabanli tip cikarimi, 1598 pattern (API params, return types, operators, loops, comparisons, casts). 10 inference katmani, <0.1ms/fonksiyon. undefined/long → spesifik tip donusumu.
- **Windows Real DLL Exports**: Winbindex + MS Symbol Server uzerinden 98 Windows 11 DLL'den gercek export tablolari (24,687 net new).
- **Homebrew Extra Packages**: opencv, vtk, qt, poco, bullet, grpc, gdal, hdf5, boost, protobuf + 8 diger paket (475,590 net new sembol).
- Signature DB: 7.09M → **7.35M unique** (+253K)
- 101 yeni test (CAPA: 38, XTRIDE: 63)

## [1.8.5] - 2026-04-06

### Fixed (7 Critical/High/Medium Bugs)
- **CRITICAL** Duplicate kod blogu: %45.6 dosyada fonksiyon kapanisindan sonra orijinal kod tekrarlaniyor -- `_apply_names_to_code` yeniden yazildi, span-based rename
- **CRITICAL** Duplicate parametre isimleri: Ayni fonksiyonda ayni isim 2+ parametreye ataniyor (C'de gecersiz) -- pre-seed collision check + suffix numbering
- **CRITICAL** Byte pattern 1:1200 noise: Ayni pattern binlerce fonksiyona 0.95 confidence ile ataniyor -- two-pass selectivity (>20 match discard, 6-20 halved)
- **HIGH** M_matrix pandemi: 91K parametrenin %30'u ayni isim -- context-aware override (memcpy->buffer, strlen->string, malloc->data)
- **HIGH** Feistel false positive (2407): XOR pattern cok genel -- min_matches 4->16, context keywords, BLAS suppression
- **MEDIUM** CFG fingerprint false positive: CFD/FEA/finance (Heston, FEA elements) -- threshold 0.75->0.85, domain-specific minimum block check
- **LOW** Platform-aware filtering: macOS binary'de Windows API false positive -- platform-specific lib/category sets + target_platform filter

### Added
- **__BUN Segment Parser**: Bun-compiled binary'lerde `__BUN` segmentini tespit ve JS bundle extraction. TargetType.BUN_BINARY, zlib decompress, hybrid pipeline
- **ProcessPoolExecutor Migration**: c_namer.py, c_comment_generator.py, semantic_namer.py ThreadPool->ProcessPool (GIL bypass, 10 core efektif kullanim)
- **Semantic Namer 2-Phase Parallel**: 5 bagimsiz strateji paralel + call graph propagation sequential
- **186 yeni test**: Bug fix regression + platform filter + BUN parser + byte pattern selectivity

### Performance
- c_namer: ~6 saat -> ~0.8 saat (7.5x hizlanma, ProcessPool)
- c_comment_generator: ~5 saat -> ~0.7 saat (7x hizlanma, ProcessPool)
- semantic_namer: ~7 saat -> ~1.5 saat (4.7x hizlanma, 2-phase parallel)
- Toplam pipeline tahmini: ~24 saat -> ~7-8 saat (3x hizlanma)

## [1.7.6] - 2026-04-05

### Added
- **Binary Diffing Auto-Activation**: Reference DB cache (`~/.cache/karadul/ref_db/`) otomatik taranir, reference_binary config'e gerek kalmadan BinDiff calisir. `transfer_names_with_confidence()` ile gercek confidence degerleri Name Merger'a iletilir.
- **Cross-Binary CFG Transfer**: Onceki analizlerde isimlendirilen fonksiyonlar CFG fingerprint cache ile yeni binary'lerde tanimlanir. Structure hash pre-filtering ile O(n) performans. Cache: `~/.cache/karadul/cfg_cache/`, max 100 binary, 50MB LRU.
- **Callee-Profile Seed Expansion**: Signature match'ler (confidence >= 0.70) otomatik seed olarak eklenir. 248 API seed -> 10K+ seed. callee_profile_propagator ve data_flow her ikisi de signature_matches'ten beslenir.
- **Source weights**: `cross_binary_transfer` (0.80) ve `callee_profile` (0.75) config.py'ye eklendi.

### Fixed
- `match_from_cache` O(U*C*F) brute-force -> structure hash pre-filtering ile O(U*bucket_size) (Codex audit)
- `call_graph_json.read_text()` loop icinde tekrarlanan I/O -> loop disinda bir kez okunur (Codex audit)
- Fortran DB zaten api_param_db uzerinden seed oluyor — ayri islem gereksiz (Codex teyit)

## [1.2.0] - 2026-03-26

### Added
- **Virtual Dispatch Resolution**: Obj-C `_objc_msgSend` ve C++ vtable cagrlarini gercek metot implementasyonlarina cozumler. Class hierarchy walking, RTTI-based vtable resolution.
- **Inter-Procedural Data Flow**: Fonksiyonlar arasi veri akisi izleme. 4 pattern: parameter passthrough, return-to-argument, struct field mediation, allocation chain. xrefs dogrulamasi ile confidence boost.
- **Algorithm Composition Analysis**: Tekil algoritma tespitlerini ust-seviye workflow'lara gruplama. 5 pattern: PIPELINE, PROTOCOL_SEQ, ITERATIVE, FORK_JOIN, PRODUCER_CONSUMER. 21 bilinen sablon (VPN, TLS, FEA, crypto KDF, roket simulasyonu dahil).
- **Deep Call Chain Tracing**: Hedef fonksiyonlardan DFS ile cagri agaci olusturma. ASCII tree ve Mermaid diagram ciktilari. Otomatik hedef secimi (algoritma yogunlugu, dispatch edge sayisi, composition entry point).
- **Struct Recovery Engine**: Algoritma-farkinda struct field isimlendirme. 3 fazli pipeline: template matching -> call graph propagation -> code rewrite. C header uretimi.
- **Augmented Call Graph**: Dispatch resolution sonuclarini orijinal call graph'a merge eden mekanizma. Downstream moduller augmented graph'i kullanir.
- **Benchmark Framework**: Ground truth generator (nm-based), libcrypto ve libsqlite3 benchmark hedefleri, CLI `benchmark` komutu.
- **Deep Analysis Reporting**: HTML ve Markdown raporlarina dispatch stats, composition listesi, call trace ASCII tree section'lari.
- **DeepTraceConfig**: Yeni konfigurasyon dataclass'i (max_trace_depth, composition_min_stages, vb.)

### Changed
- HTML report: Dark theme'e Deep Analysis section eklendi (expandable compositions, bar charts)
- Markdown report: Deep Algorithm Analysis section eklendi
- Config: `DeepTraceConfig` dataclass eklendi, `Config` sinifina `deep_trace` field eklendi

### Fixed
- Augmented call graph downstream'e gecirilmiyordu -- dispatch resolution sonuclari artik DataFlow, Composition ve DeepTracer tarafindan kullaniliyor
- `xrefs_json` parametresi InterProceduralDataFlow'a gecirilmiyordu
- `all_algos` ve `call_graph_data` degiskenleri try blogu icindeydi, downstream modullerde NameError riski vardi
- `_build_class_hierarchy()` superclass field'ini doldurmuyordu -- Obj-C metadata ve decompiled koddan 5 kaynakli hierarchy extraction eklendi
- C++ vtable resolution stub'i (confidence 0.1) -> RTTI-based resolution (confidence 0.4-0.6)
- DataFlowEdge'lerde FUN_xxx normalizasyonu eksikti

## [1.1.5] - 2026-03-25

### Added
- Engineering algorithm analysis integration into pipeline (Stage 7)
- Deep algorithm tracing scaffolding (dispatch, data flow, composition, trace stubs)
- Composition analyzer, deep tracer, struct recovery initial implementations

## v1.0.0 (2026-03-23)

First production release.

### Pipeline

- 6-stage pipeline: identify, static analysis, dynamic analysis, deobfuscation, reconstruction, report
- Error recovery with exponential backoff and circuit breaker
- Chunked processing for large binaries (224MB+ tested)
- Progress bar with Rich console output
- Workspace-based artifact isolation per analysis run

### Binary Analysis

- Ghidra headless integration with configurable timeout (up to 2 hours)
- 6-layer deterministic C naming: symbol, string-context, API-call, call-graph, dataflow, type-based
- Bayesian name fusion from multiple sources with configurable correlation weights
- FLIRT signature extraction and matching (1.5M+ signatures, 4,200+ libraries)
- Byte pattern matching for library function identification
- YARA rule scanning with built-in rule sets
- Struct/enum/vtable type recovery with confidence scoring
- Algorithm identification: crypto, compression, hash, sorting patterns
- Smart comment generation for decompiled C code
- String intelligence: assert/error/protocol-based name inference
- BinDiff integration for reference binary comparison

### Language Support

- C/C++ (Mach-O, ELF, PE)
- Swift (metadata, demangling, protocol conformance)
- Objective-C (class/method recovery)
- Go (pclntab, GOROOT/GOPATH strings)
- Rust (panic messages, symbol demangling)
- Java/Kotlin (CFR decompiler, class metadata)
- C#/.NET (ILSpy integration, IL metadata)
- JavaScript (webpack, esbuild, Terser bundles)
- Electron apps (.app/.asar unpacking)

### JavaScript Deobfuscation

- Module unpacking and dependency resolution
- 36-rule semantic variable rename (AST-based)
- Parameter recovery via 5-strategy call-site analysis
- TypeScript .d.ts mapping for API-level naming
- synchrony integration for obfuscator.io targets
- 9-phase deep deobfuscation pipeline
- Babel AST transform chain
- Control flow flattening deflattening
- Opaque predicate removal
- String decryption

### Reconstruction

- 5-layer hybrid module naming pipeline (npm fingerprint, source match, structural, LLM)
- Source matching: minified-to-original function matching
- Full project scaffolding (package.json, Makefile, Dockerfile)
- Module splitting with dependency graph
- JSDoc type inference
- Comment generation for both JS and C targets

### Output

- Self-contained HTML report (dark theme, inline CSS/JS, no external deps)
- JSON machine-readable report
- Markdown summary
- Clean output directory with recovered source structure
- Naming map JSON for downstream tooling

### CLI

- `karadul analyze` -- full pipeline
- `karadul info` -- target inspection
- `karadul list` -- list previous analyses
- `karadul clean` -- workspace cleanup
- `karadul run` -- run reconstructed JS project
- `karadul batch` -- batch analysis
- Hacker-style interactive terminal UI

### Infrastructure

- Central configuration via `karadul.yaml` (all paths, timeouts, thresholds)
- Optional ML-assisted decompilation (LLM4Decompile)
- Optional LLM-assisted naming (Claude CLI)
- 1,180+ tests
- pip installable with optional dependency groups
