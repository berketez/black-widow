# Karadul v1.0 Release Plan

**Tarih:** 2026-03-23
**Durum:** Aktif
**Hedef:** v1.0 production-ready release

---

## 1. Buyuk Binary Destegi (224MB+ Brave/Opera)

**Sorun:** Ghidra headless 224MB binary'de OOM/timeout riski. Signature matching 3.4M DB ile yavash.

**Cozum:**
- `karadul/core/pipeline.py`: Chunked Ghidra analizi (fonksiyonlari 5K'lik batch'lerde isle)
- `karadul/analyzers/binary_analyzer.py`: Memory-mapped file reading (mmap)
- `karadul/reconstruction/c_namer.py`: Lazy string loading (tum string'leri RAM'e alma)
- `karadul/core/signature_matcher.py`: Bloom filter pre-check (3.4M DB'de hizli lookup)
- Ghidra timeout: 30dk -> 120dk (buyuk binary icin)
- Progress bar: tqdm ile analiz ilerlemesi goster

**Dosyalar:** pipeline.py, binary_analyzer.py, c_namer.py, signature_matcher.py
**Tahmini:** ~200 satir degisiklik
**Risk:** ORTA (Ghidra memory limitleri test gerektirir)
**Test:** Brave 224MB + Opera 197MB uzerinde

---

## 2. Paket Dagitim — pip install karadul

**Hedef:** `pip install karadul && karadul analyze /path/to/binary`

**Adimlar:**
- pyproject.toml: entry_points, classifiers, description guncelle
- karadul/cli.py: `console_scripts` entry point
- Requirements: minimum (click, tqdm, yara-python)
- Optional: `pip install karadul[ghidra]`, `pip install karadul[js]` (Node.js gerek)
- `python -m karadul` calismali
- .gitignore, MANIFEST.in, LICENSE dosyalari
- PyPI test upload: `twine upload --repository testpypi dist/*`

**Dosyalar:** pyproject.toml, setup.cfg, MANIFEST.in, LICENSE
**Tahmini:** ~50 satir degisiklik + yeni dosyalar
**Risk:** DUSUK

---

## 3. Multi-Language Destegi (7 yeni dil)

### 3a. Go Binary
- pclntab (Go symbol table) parse
- GOROOT/GOPATH string extraction
- `go tool objdump` entegrasyonu
- Dosya: `karadul/analyzers/go_binary.py` (yeni, ~150 satir)

### 3b. Rust Binary
- Panic message string extraction ("called `Option::unwrap()`")
- Rust symbol demangling (rustfilt)
- Cargo.toml dependency detection
- Dosya: `karadul/analyzers/rust_binary.py` (yeni, ~120 satir)

### 3c. Java (.class / .jar)
- CFR decompiler entegrasyonu (subprocess)
- Class/method/field isim extraction
- Package structure recovery
- Dosya: `karadul/analyzers/java_binary.py` (mevcut, genislet ~100 satir)

### 3d. Kotlin
- Java analyzer + kotlin.Metadata annotation parse
- @JvmName, @JvmStatic detection
- Dosya: java_binary.py'ye ek (~50 satir)

### 3e. C# / .NET
- ILSpy/dnSpy CLI entegrasyonu (subprocess)
- IL metadata extraction
- Assembly/namespace/class recovery
- Dosya: `karadul/analyzers/dotnet_binary.py` (mevcut, genislet ~120 satir)

### 3f. Delphi
- RTTI (Run-Time Type Information) parse
- DFM form resource extraction
- VMT (Virtual Method Table) traversal
- Dosya: `karadul/analyzers/delphi_binary.py` (yeni, ~150 satir)

### 3g. Python (compiled/packaged)
- PyInstaller: pyinstxtractor ile unpack
- cx_Freeze / Nuitka detection
- .pyc decompile (uncompyle6/decompyle3)
- Dosya: `karadul/analyzers/python_binary.py` (yeni, ~100 satir)

**Toplam:** ~790 satir yeni kod, 7 analyzer
**Risk:** DUSUK-ORTA (hepsi "detect + extract" seviyesinde)

---

## 4. Dokumantasyon Tamamlama

- `docs/ARCHITECTURE.md`: Pipeline flow diyagrami (ASCII)
- `docs/API.md`: Public class/method reference
- `docs/CONTRIBUTING.md`: Katki rehberi
- `docs/EXAMPLES.md`: 4 ornek (binary, JS, Swift, Docker)
- `CHANGELOG.md`: v1.0 release notes
- README.md: final polish

**Toplam:** ~500 satir dokuman
**Risk:** DUSUK

---

## Uygulama Sirasi ve Agent Dagitimi

```
Developer 1 → Buyuk binary destegi (pipeline chunking + mmap)
Developer 2 → pip install karadul (PyPI hazirlik)
Developer 3 → Multi-language (Go + Rust + Python analyzers)
Developer 4 → Multi-language (Java + Kotlin + C# + Delphi analyzers)
Developer 5 → Dokumantasyon (ARCHITECTURE + API + EXAMPLES)
Coordinator  → Entegrasyon + test + final review
```

6 paralel agent, tamamlaninca coordinator entegre eder.

**Tahmini sure:** 4-6 saat (paralel agent'larla)
**Tahmini toplam yeni kod:** ~1,500 satir
**Test hedefi:** 1200+ test (mevcut 1180 + yeni dil testleri)
