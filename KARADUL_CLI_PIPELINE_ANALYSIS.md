# KARADUL CLI Akışı ve Pipeline Yapısı - Detaylı Analiz

## 1. CLI Entry Point ve `karadul analyze` Komutu

### Dosya Konumu
- **Ana Entry Point**: `/Users/apple/Desktop/black-widow/karadul/__main__.py`
- **CLI Tanımı**: `/Users/apple/Desktop/black-widow/karadul/cli.py`

### Framework
- **Framework**: Click (Click-based CLI)
- **Ana Komut**: `@click.group()` ile `main()` fonksiyonu tanımlı
- **Invoke Without Command**: `invoke_without_command=True` ile set edilmiş

### `karadul analyze` Komutu Tanımı (cli.py:216-391)

```python
@main.command()
@click.argument("target", type=click.Path(exists=True))
@click.option("--stage", type=click.Choice(STAGES, case_sensitive=False))
@click.option("--skip-dynamic", is_flag=True)
@click.option("--output-dir", type=click.Path())
@click.option("--config", "config_path", type=click.Path())
@click.option("--verbose", is_flag=True)
@click.option("--use-llm/--no-llm", default=False)  # <-- OPSIYONEL FLAG
@click.option("--llm-model", default="sonnet")
@click.option("--use-ml", is_flag=True)
@click.option("--output", "clean_output_dir", type=click.Path())
@click.option("--format", type=click.Choice(["clean", "raw"]))
def analyze(ctx, target, stage, skip_dynamic, ...):
```

### Kullanıcı Input Yöntemleri
1. **Komut satırı argümanları**: `target` path argümanı (zorunlu)
2. **Komut satırı flag'leri**: `--use-llm`, `--use-ml`, vb. (opsiyonel)
3. **Config dosyası**: `--config` ile YAML dosyası yüklenebilir
4. **Interactive Prompt YOKSUNLUK**: CLI interaktif prompt **KULLANMIYOR** - sadece flag tabanlı

---

## 2. Pipeline Akışı ve Stage Sırası

### Stage Listesi (cli.py:44-60)

```python
STAGES: list[str] = [
    "identify",
    "static",
    "dynamic",
    "deobfuscate",
    "reconstruct",
    "report",
]
```

### Pipeline Tarafından Calistirilan Stagelar (sira önemsemlidir)

#### **Stage 1: identify** (`IdentifyStage`)
- **Dosya**: `karadul/stages.py:33-79`
- **Amaç**: Hedef dosyayı tanı, metadata topla
- **Çıktı**: `target_info.json`
- **Bağımlılıklar**: Yok (ilk stage)

#### **Stage 2: static** (`StaticAnalysisStage`)
- **Dosya**: `karadul/stages.py:82-289`
- **Amaç**: Ghidra ile decompile, FLIRT/YARA taraması
- **Çıktılar**:
  - `ghidra_functions.json`
  - `ghidra_strings.json`
  - `ghidra_call_graph.json`
  - `ghidra_types.json` (Type recovery)
  - `ghidra_xrefs.json` (Cross-references)
  - `ghidra_pcode.json` (v1.2.3+, P-Code dataflow)
  - `ghidra_cfg.json` (Control Flow Graph)
  - `ghidra_function_id.json` (v1.2.4+, PDB/FID)
- **Bağımlılıklar**: `identify` başarılı olmalı
- **Opsiyonel Alt-Adımlar**:
  - YARA pattern taraması (yara_scanner.py)
  - FLIRT byte pattern matching (flirt_parser.py)
  - BinDiff (bindiff.py)

#### **Stage 3: dynamic** (`DynamicAnalysisStage`)
- **Dosya**: `karadul/stages.py:293-450`
- **Amaç**: Frida ile runtime izleme
- **Çıktılar**: Fonksiyon çağrıları, API kullanımı
- **Bağımlılıklar**: `identify` (static'ten bağımsız)
- **Atlanabilir**: `--skip-dynamic` flag ile

#### **Stage 4: deobfuscate** (`DeobfuscationStage`)
- **Dosya**: `karadul/stages.py:451-711`
- **Amaç**: Minifikasyon temizle, string decrypt, beautify
- **Çıktılar**:
  - `decompiled/` (deobfuscated C dosyaları - binary için)
  - `webpack_modules/` (JS bundle için)
- **Bağımlılıklar**: `static` başarılı olmalı
- **Opsiyonel Alt-Adımlar**:
  - Binary deobfuscation (CFG flattening, opaque predicate)
  - JS beautification (DeobfuscationStage yapıyorsa)

#### **Stage 5: reconstruct** (`ReconstructionStage`) - OPSIYONEL (Sprint 6+)
- **Dosya**: `karadul/stages.py:716-2650`
- **Amaç**: Çalışabilir proje oluştur
- **Bağımlılıklar**: `deobfuscate` başarılı olmalı
- **Hedef Tipine Göre Alt-Akışlar**:
  - Binary: C naming, type recovery, algoritma ID
  - JS: Variable renaming, module splitting, project building
  - Go: Go-specific reconstruction
  - App Bundle: Her component için uygun reconstruction

#### **Stage 6: report** (`ReportStage`)
- **Dosya**: `karadul/stages.py:2651-2652` (RefactorStage)
- **Amaç**: HTML/JSON rapor üret
- **Çıktılar**: `report.html`, `report.json`
- **Bağımlılıklar**: Tüm önceki stage'ler

### Stage'leri Etkinleştirme/Devre Dışı Bırakma

```python
def _get_active_stages(stop_after, skip_dynamic):
    stages = list(STAGES)
    if skip_dynamic and "dynamic" in stages:
        stages.remove("dynamic")  # --skip-dynamic ile dynamic stage'i kaldır
    if stop_after:
        idx = stages.index(stop_after)
        stages = stages[:idx + 1]  # --stage x ile x'te dur
    return stages
```

**Kontrol Yolları**:
1. `--skip-dynamic`: dynamic stage'i atlat
2. `--stage identify/static/dynamic/deobfuscate/reconstruct/report`: O stage'de dur
3. Hiçbir flag: Tüm 6 stage çalış

---

## 3. Config Sistemi ve Flag'ler

### Config Yükleme (config.py:294-369)

```python
@classmethod
def load(cls, path: Optional[Path] = None) -> Config:
    if path and path.exists():
        with open(path) as f:
            data = yaml.safe_load(f) or {}
        return cls._from_dict(data)
    default_path = Path.cwd() / "karadul.yaml"
    if default_path.exists():
        with open(default_path) as f:
            data = yaml.safe_load(f) or {}
        return cls._from_dict(data)
    return cls()  # Varsayılan config
```

### Opsiyonel Flag'ler ve Config Akışı

#### **Flag 1: `--use-llm` / `--no-llm` (Default: False)**

**Dosya**: `cli.py:227-228, 262-263`

```python
@click.option("--use-llm/--no-llm", default=False)
@click.option("--llm-model", default="sonnet")

# ... analyze() fonksiyonunda:
cfg.analysis.use_llm_naming = use_llm        # Config'te set
cfg.analysis.llm_model = llm_model
```

**Config Tanımı** (config.py:107-119):
```python
@dataclass
class AnalysisConfig:
    use_llm_naming: bool = False
    llm_model: str = "sonnet"
```

**Pipeline'a Geçiş**:
- `Pipeline(cfg)` oluşturulur
- `PipelineContext.config` ile stage'lere aktarılır
- `ReconstructionStage._execute_js()` içinde (stages.py:2268):
  ```python
  if context.config.analysis.use_llm_naming:
      llm_namer = ClaudeLLMNamer(
          context.config,
          model=context.config.analysis.llm_model,
      )
  ```

#### **Flag 2: `--use-ml` (Default: False)**

**Dosya**: `cli.py:231-232, 266-267`

```python
@click.option("--use-ml", is_flag=True, default=False)

# ... analyze() fonksiyonunda:
if use_ml:
    cfg.ml.enable_llm4decompile = True
```

**Config Tanımı** (config.py:140-152):
```python
@dataclass
class MLConfig:
    enable_llm4decompile: bool = False  # Kapalı: 30s/func
    llm4decompile_model_path: Path = ...
    ml_device: str = "auto"
    ml_dtype: str = "auto"
    max_new_tokens: int = 512
```

**Pipeline'a Geçiş**:
- Config'te `ml.enable_llm4decompile = True` set edilir
- Binary reconstruction'da (c_namer.py:771):
  ```python
  if self._config.ml.enable_llm4decompile:
      # LLM4Decompile 6.7B sequential execution
  ```

#### **Flag 3: `--output-dir` (Opsiyonel)**

Config'teki `project_root` override eder:
```python
if output_dir:
    cfg.project_root = Path(output_dir).resolve()
```

#### **Flag 4: `--output` / `--format` (Opsiyonel)**

Pipeline sonrasında `OutputFormatter` kullanılır (cli.py:361-391):
```python
if clean_output_dir:
    formatter = OutputFormatter(ws, result)
    fmt_result = formatter.format_output(out_path, fmt=output_format)
```

---

## 4. ReconstructionStage Alt-Adımları ve Opsiyonel Olanlar

### ReconstructionStage Sıradaki Alt-Adımlar (stages.py:716-764)

`_execute_js()` içinde (JavaScript reconstruction):

```
1. Context-Aware Variable Naming (ContextNamer - 300+ kural)
2. LLM-Assisted Naming (opsiyonel - --use-llm ile)
3. Parameter Recovery (5 strateji)
4. Module Splitting (webpack modülleri varsa)
5. Naming Pipeline + Source Matching (npm fingerprint)
6. Module Category Assignment
7. Type Inference (JSDoc)
8. Comment Generation
9. Gap Filling (eksiklikleri tamamla)
10. Project Building
```

#### **Opsiyonel Alt-Adımlar (Binary için)**

binary reconstruction (stages.py:906+):

```
0. Signature DB Matching (SignatureDB - binary_extractor.py)
0.5. Byte Pattern Matching (FLIRT - BytePatternMatcher)
0.7. P-Code Dataflow Analysis (opsiyonel - PcodeAnalyzer)
0.8. CFG Analysis (opsiyonel - CFGAnalyzer)
1. Algorithm ID (CAlgorithmIdentifier - varsayılan aktif)
1.5. Binary Name Extraction (BinaryNameExtractor - varsayılan aktif)
1.6. Engineering Algorithm Analysis (opsiyonel - EngineeringAlgorithmAnalyzer)
1.7. Confidence Calibration (opsiyonel - ConfidenceCalibrator)
1.8. Assembly Analysis (AssemblyAnalyzer - varsayılan aktif)
1.9. Assembly Analysis (varsayılan aktif)
2. C Variable/Function Naming (CVariableNamer)
2.4. BinDiff (referans binary varsa - bindiff.py)
2.5. Name Merger (Bayesian isim birleştirme)
3-9. [Diğer adımlar]
10. ProjectReconstructor (10+ modul varsa) VEYA ProjectBuilder (az modul varsa)
```

### Opsiyonel Feature'ler (Config ile Kontrol)

Config.binary_reconstruction içinde:

```python
enable_algorithm_id: bool = True
enable_c_naming: bool = True
enable_type_recovery: bool = True
enable_comment_generation: bool = True
enable_byte_pattern_matching: bool = True
enable_engineering_analysis: bool = True
enable_binary_name_extraction: bool = True
enable_string_decryption: bool = True
enable_packed_detection: bool = True
enable_function_id: bool = True
```

---

## 5. Mevcut Opsiyonel Feature: `--use-llm` Pattern'ı

### 5.1. CLI Flag Tanımı

**Dosya**: `cli.py:227-228`

```python
@click.option("--use-llm/--no-llm", default=False,
              help="LLM-assisted variable naming (Claude CLI).")
@click.option("--llm-model", default="sonnet",
              help="LLM model alias (varsayilan: sonnet, alternatif: opus).")
```

### 5.2. CLI'dan Config'e Akış

**Dosya**: `cli.py:238-263`

```python
def analyze(ctx, ..., use_llm, llm_model, ...) -> None:
    cfg = _load_config(config_path)
    # ... hedef tespiti ...
    
    # LLM naming ayarlari
    cfg.analysis.use_llm_naming = use_llm      # bool flag -> config
    cfg.analysis.llm_model = llm_model         # string -> config
    
    pipeline = Pipeline(cfg)
```

### 5.3. Config Tanımı

**Dosya**: `config.py:107-119`

```python
@dataclass
class AnalysisConfig:
    ...
    # LLM-assisted variable naming (Claude CLI)
    use_llm_naming: bool = False
    llm_model: str = "sonnet"
```

### 5.4. Pipeline'a Geçiş

**Dosya**: `core/pipeline.py:272-278`

```python
context = PipelineContext(
    target=target_info,
    workspace=workspace,
    config=self._config,  # <-- Config burada
    extra={...},
    _progress_callback=on_progress,
)
```

### 5.5. Stage İçinde Kullanım

**Dosya**: `stages.py:2268-2326` (_execute_js metodunda)

```python
if context.config.analysis.use_llm_naming:  # <-- config'ten oku
    from karadul.reconstruction.naming.llm_naming import ClaudeLLMNamer
    
    llm_namer = ClaudeLLMNamer(
        context.config,
        model=context.config.analysis.llm_model,  # <-- config'ten model oku
    )
    
    if llm_namer.is_available:
        try:
            context_json_data = naming_result.context_json
            
            # Temporary file ile JSON'u geç
            with tempfile.NamedTemporaryFile(...) as tmp:
                json.dump(context_json_data, tmp, ...)
                llm_ctx_path = Path(tmp.name)
            
            llm_result = llm_namer.name_variables(
                llm_ctx_path, current_file
            )
            
            if llm_result.success and llm_result.total_named > 0:
                stats["llm_variables_named"] = llm_result.total_named
                stats["llm_model"] = llm_result.model_used
                # Sonuçlar stats'a kaydedilir
```

### 5.6. ClaudeLLMNamer İmplementasyonu

**Dosya**: `reconstruction/naming/llm_naming.py:100-263`

```python
class ClaudeLLMNamer:
    CLAUDE_CLI_PATH = Path("/opt/homebrew/bin/claude")
    BATCH_SIZE = 15
    DEFAULT_MODEL = "sonnet"
    
    def __init__(self, config, model="sonnet", batch_size=15, ...):
        self.model = model
        self.batch_size = batch_size
        self._cli_available = CLAUDE_CLI_PATH.exists()
    
    def name_variables(self, context_json: Path, source_file: Path):
        """
        1. Context JSON oku -> dusuk-confidence degiskenleri cikart
        2. BATCH_SIZE gruplara bol
        3. Her batch: `claude -p` prompt gonder
        4. JSON response parse
        5. Birlestir -> mappings return
        """
        variables = self._extract_low_confidence_vars(context_data)
        batches = [variables[i:i+BATCH_SIZE] for i in range(0, len(variables), BATCH_SIZE)]
        
        for batch in batches:
            prompt = self._prepare_batch(batch, source_lines)
            response = self._call_claude(prompt)  # subprocess.run("claude", "-p", prompt)
            batch_mappings = self._parse_response(response)
            # Birlestir
```

**Claude CLI Çağrısı** (llm_naming.py:480+):

```python
def _call_claude(self, prompt: str) -> str:
    result = subprocess.run(
        [str(CLAUDE_CLI_PATH), "-p"],
        input=prompt,
        text=True,
        capture_output=True,
        timeout=self.timeout,
    )
    if result.returncode != 0:
        raise RuntimeError(f"Claude CLI hata: {result.stderr}")
    return result.stdout
```

---

## 6. Pattern Özet - Opsiyonel Feature Implementasyonu

### Template Pattern: CLI Flag -> Config -> Pipeline -> Stage -> Action

```
1. CLI LAYER (cli.py)
   ├─ @click.option("--use-llm/--no-llm", default=False)
   ├─ @click.option("--llm-model", default="sonnet")
   └─ def analyze(..., use_llm: bool, llm_model: str):
      └─ cfg.analysis.use_llm_naming = use_llm
      └─ cfg.analysis.llm_model = llm_model

2. CONFIG LAYER (config.py)
   ├─ AnalysisConfig.use_llm_naming: bool
   └─ AnalysisConfig.llm_model: str

3. PIPELINE LAYER (core/pipeline.py)
   └─ context = PipelineContext(config=cfg, ...)

4. STAGE LAYER (stages.py)
   └─ if context.config.analysis.use_llm_naming:
      └─ llm_namer = ClaudeLLMNamer(context.config, model=...)
      └─ result = llm_namer.name_variables(...)

5. IMPLEMENTATION LAYER (reconstruction/naming/llm_naming.py)
   └─ class ClaudeLLMNamer:
      ├─ is_available: CLI var mı kontrol
      ├─ name_variables(): ana logic
      ├─ _extract_low_confidence_vars(): filtre
      └─ _call_claude(): subprocess ile CLI çağır
```

### Diğer Opsiyonel Flag'leri Eklemek İçin Aynı Pattern

1. CLI'ye flag ekle (cli.py)
2. Config.py'de field ekle
3. analyze() da cfg'e set et
4. Stage'de `context.config.XX` ile oku
5. Opsiyonel logic eklenenekle

---

## 7. Dosya Yapısı Özeti

```
/Users/apple/Desktop/black-widow/karadul/
├── __main__.py                          # Entry: "python -m karadul"
├── cli.py                               # Click CLI komutları
├── config.py                            # Config dataclasses + load/validate
├── stages.py                            # 6 Stage implement
├── core/
│   ├── pipeline.py                      # Pipeline orkestrasyonu
│   ├── result.py                        # StageResult, PipelineResult
│   ├── target.py                        # TargetInfo, TargetDetector
│   ├── workspace.py                     # Workspace yönetim
│   └── ...
└── reconstruction/
    ├── naming/
    │   ├── llm_naming.py                # ClaudeLLMNamer
    │   ├── context_namer.py             # ContextNamer (NSA-grade)
    │   ├── pipeline.py                  # NamingPipeline
    │   └── ...
    ├── c_namer.py                       # CVariableNamer (binary)
    ├── param_recovery.py                # ParamRecovery
    ├── module_splitter.py               # ModuleSplitter
    ├── ...
```

---

## ÖZET

- **CLI Framework**: Click (no interactive prompts)
- **Pipeline**: 6-stage linear execution (identify → static → dynamic → deobfuscate → reconstruct → report)
- **Config System**: Dataclass-based, YAML load, CLI override
- **Optional Features**: `--use-llm`, `--use-ml`, `--use-*` şeklinde CLI flag + Config combo
- **LLM Integration**: Claude CLI subprocess call, batch processing
- **Pattern**: CLI Flag → AnalysisConfig → PipelineContext → ReconstructionStage → ClaudeLLMNamer
