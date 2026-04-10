# Karadul Multi-Language Decompilation Plan

**Tarih:** 2026-03-22
**Yazan:** Security Expert Agent
**Durum:** Tasarim Asamasinda

---

## Mevcut Durum Analizi

Karadul su an 3 hedef tipini destekliyor:

| TargetType | Language | Analyzer | Durum |
|---|---|---|---|
| `JS_BUNDLE` | JavaScript | `javascript.py` | Tam destek |
| `ELECTRON_APP` | JavaScript | `electron.py` | Tam destek |
| `MACHO_BINARY` | C/C++/Rust/Swift/ObjC | `macho.py` + `rust_binary.py` | Temel destek |
| `UNIVERSAL_BINARY` | (yukaridaki gibi) | `macho.py` | Temel destek |

**Sorun:** Tum native binary'ler ayni `MACHO_BINARY` tipiyle isleniyor. Go, Rust, Swift hepsi
ayni Ghidra decompilation hattindan geciyor ve dile ozgu metadata kayip.

**Mevcut Language enum:**
```python
class Language(Enum):
    JAVASCRIPT = "javascript"
    RUST = "rust"
    SWIFT = "swift"
    CPP = "cpp"
    OBJECTIVE_C = "objc"
    UNKNOWN = "unknown"
```

Eksik: `GO`, `PYTHON`, `JAVA`, `KOTLIN`, `CSHARP`

---

## 1. Go Binary Decompilation

### Binary Tespit Yontemi

**Kesinlik: YUKSEK** -- Go binary'ler cok belirgin iz birakir.

```
Section-bazli tespit (otool -l):
  __gopclntab    -> Go function table (kesin Go gostergesi)
  __go_buildinfo -> Go build metadata (versiyon, mod bilgisi)
  __go_fipsinfo  -> FIPS compliance bilgisi

String-bazli tespit:
  "runtime.gopanic"
  "runtime.goexit"
  "runtime.newproc"
  "go.shape"
  "github.com/" kaliplari
  "go1.XX.Y" versiyon string'i
```

**Dogrulama (Ollama - gercek Go binary):**
- `strings ollama | grep "go1\."` --> `go1.24.1` (Go versiyon tespiti basarili)
- `otool -l ollama | grep __go_buildinfo` --> section mevcut (kesin tespit)
- `otool -l ollama | grep __gopclntab` --> function table mevcut
- `strings ollama | grep "github.com/ollama"` --> modul yolu mevcut
- `nm ollama | grep "runtime\."` --> BOSSA (strip edilmis: `-ldflags="-s -w"`)

**Onemli:** Go binary'ler varsayilan olarak sembolleri korur, AMA cok sayida Go projesi
`-ldflags="-s -w"` ile build eder (Ollama dahil). Section-bazli tespit bu yuzden daha guvenilir.

### Metadata Extraction

| Bilgi | Kaynak | Yontem |
|---|---|---|
| Go versiyonu | `__go_buildinfo` | `go version -m binary` veya string parse |
| Module path | `__go_buildinfo` | `go version -m` --> mod satiri |
| Dependency listesi | `__go_buildinfo` | `go version -m` --> dep satirlari |
| Fonksiyon tablosu | `__gopclntab` | pclntab parser (binary format) |
| Goroutine bilgisi | strings | `"goroutine"`, `"runtime.goexit"` kaliplari |
| Interface bilgisi | `__go_itab` | itab section parse |
| Build flags | `__go_buildinfo` | `-tags`, `-ldflags` bilgisi |

### Araclar

| Arac | Kurulum | Amac | Oncelik |
|---|---|---|---|
| `go tool objdump` | `brew install go` | Go-aware disassembly | YUKSEK |
| `redress` | `go install github.com/goretk/redress@latest` | Go binary metadata parser, tip bilgisi, interface, struct recovery | YUKSEK |
| `GoReSym` | `go install github.com/mandiant/GoReSym@latest` | Go symbol recovery (strip edilmis binary'ler icin) | KRITIK |
| Ghidra + go-ghidra | Ghidra plugin | Ghidra icinde Go-aware analiz | ORTA |

**GoReSym ozellikle kritik:** Strip edilmis Go binary'lerde bile `__gopclntab` section'indan
fonksiyon isimlerini, dosya yollarini ve satir numaralarini kurtarir. Ollama gibi strip edilmis
binary'lerde tek cozum bu.

### Karadul Entegrasyon Plani

```
Yeni dosya: karadul/analyzers/go_binary.py

class GoBinaryAnalyzer(MachOAnalyzer):
    """Go binary'lere ozel analiz."""

    supported_types = [TargetType.MACHO_BINARY]  # language=GO filtresiyle

    def analyze_static(self, target, workspace):
        # 1. MachO analizi (parent)
        result = super().analyze_static(target, workspace)

        # 2. Go build info extraction
        go_info = self._extract_build_info(target.path)

        # 3. GoReSym ile symbol recovery
        symbols = self._run_goresym(target.path)

        # 4. Module dependency analizi
        deps = self._extract_dependencies(target.path)

        # 5. Goroutine/channel pattern tespiti
        patterns = self._detect_concurrency_patterns(workspace)

        return result
```

### Tahmini Gelistirme Suresi: 3-4 gun


---

## 2. Rust Binary Decompilation

### Binary Tespit Yontemi

**Kesinlik: YUKSEK** -- Zaten `rust_binary.py` mevcut.

```
Symbol-bazli tespit (mevcut):
  _ZN / _RN prefix -> Rust mangling
  "rust_begin_unwind"
  "rust_panic"
  "__rust_alloc"
  "core::panicking"

Ek tespit (yeni):
  .rustc section -> Rust compiler metadata
  panic_unwind crate varligi
  "Cargo.toml" string referanslari
```

**Dogrulama (Warp Terminal - gercek Rust binary):**
- `nm stable | wc -l` --> 347,960 sembol (semboller korunmus)
- Warp binary'de `warp::` namespace'i mevcut

### Mevcut Durum ve Eksikler

`rust_binary.py` zaten calisir durumda, sunlari yapar:
- Itanium ABI + v0 demangling (basit heuristic)
- Crate ismi cikarma
- Panic handler tespiti
- Rust-spesifik string pattern'leri

**Eksikler:**
1. `rustfilt` entegrasyonu yok (sadece mevcutluk kontrolu, kullanilmiyor)
2. Crate versiyon bilgisi cikarilmiyor
3. Trait/impl reconstruction yok
4. async/await pattern tespiti yok
5. Analyzer registry'ye kayitli degil (sadece MachOAnalyzer kayitli)

### Gerekli Iyilestirmeler

| Iyilestirme | Oncelik | Teshis |
|---|---|---|
| `rustfilt` ile tam demangling | YUKSEK | Basit heuristic yetersiz, v0 mangling dogru cozulmuyor |
| Registry'ye kayit | YUKSEK | Rust binary tespit edilse bile `RustBinaryAnalyzer` cagrilmiyor |
| Crate dependency graph | ORTA | Hangi crate'ler kullanilmis, versiyon tespiti |
| Async/await pattern | DUSUK | tokio, async-std kaliplarini tespit |
| Trait reconstruction | DUSUK | vtable analizi ile trait bound tespiti |

### Araclar

| Arac | Kurulum | Amac | Oncelik |
|---|---|---|---|
| `rustfilt` | `cargo install rustfilt` | Rust symbol demangling | YUKSEK |
| `cargo-bloat` | `cargo install cargo-bloat` | Crate boyut analizi (kaynak gerekli) | DUSUK |
| Ghidra | Mevcut | Decompilation | Mevcut |

### Tahmini Gelistirme Suresi: 1-2 gun (mevcut altyapi var)


---

## 3. Swift Binary Decompilation

### Binary Tespit Yontemi

**Kesinlik: YUKSEK** -- Swift section'lari cok belirgin.

```
Section-bazli tespit (otool -l):
  __swift5_typeref   -> Swift tip referanslari
  __swift5_proto     -> Protocol conformance
  __swift5_types     -> Type descriptors
  __swift5_protos    -> Protocol descriptors
  __swift5_entry     -> Entry points
  __swift5_fieldmd   -> Field metadata
  __swift5_builtin   -> Builtin type metadata
  __swift5_reflstr   -> Reflection strings
  __swift5_assocty   -> Associated types

Symbol-bazli tespit:
  "$s" prefix -> Swift mangled symbols
  "_swift_" prefix
  "Swift." string
```

**Dogrulama (Telegram - gercek Swift binary):**
- `otool -l Telegram | grep __swift5` --> 10 farkli Swift section tespit edildi
- `nm Telegram | grep '\$s'` --> Swift mangled semboller mevcut
- Universal binary (x86_64 + arm64)

### Metadata Extraction

| Bilgi | Kaynak | Yontem |
|---|---|---|
| Tip bilgileri | `__swift5_types` | Type descriptor parse |
| Protocol conformance | `__swift5_proto` | Protocol conformance table |
| Field metadata | `__swift5_fieldmd` | Struct/class field isimleri |
| Reflection strings | `__swift5_reflstr` | Okunabilir tip isimleri |
| ObjC bridge bilgisi | ObjC metadata | class-dump ile |

### Araclar

| Arac | Kurulum | Amac | Oncelik |
|---|---|---|---|
| `xcrun swift-demangle` | Xcode (mevcut) | Swift symbol demangling | YUKSEK |
| `class-dump` | `brew install class-dump` | ObjC/Swift class hiyerarsisi | YUKSEK |
| `dsdump` | `brew install dsdump` | Swift-aware class-dump alternatifi | ORTA |
| Ghidra | Mevcut | Decompilation | Mevcut |

**Not:** `xcrun swift-demangle` zaten sistemde mevcut (LLVM 17.0.0). Ek kurulum gereksiz.

### Karadul Entegrasyon Plani

```
Yeni dosya: karadul/analyzers/swift_binary.py

class SwiftBinaryAnalyzer(MachOAnalyzer):
    """Swift binary'lere ozel analiz."""

    def analyze_static(self, target, workspace):
        result = super().analyze_static(target, workspace)

        # 1. Swift section parse
        swift_sections = self._parse_swift_sections(target.path)

        # 2. swift-demangle ile symbol recovery
        demangled = self._demangle_swift_symbols(workspace)

        # 3. Type descriptor extraction
        types = self._extract_type_descriptors(target.path)

        # 4. Protocol conformance mapping
        protocols = self._extract_protocol_conformances(target.path)

        # 5. class-dump ile ObjC bridge
        objc_classes = self._run_class_dump(target.path)

        return result
```

### Tahmini Gelistirme Suresi: 3-4 gun


---

## 4. Python Packed Binary (PyInstaller/Nuitka)

### Mevcut Durum

`packed_binary.py` zaten PyInstaller ve Nuitka tespiti yapiyor:
- Entropy analizi ile packing tespiti
- UPX, PyInstaller, Nuitka tanima
- PyInstaller archive parse, TOC extraction
- `.pyc` decompile (uncompyle6/decompyle3 gerekli)

### Eksikler

| Eksik | Oncelik | Aciklama |
|---|---|---|
| uncompyle6/decompyle3 kurulumu | YUKSEK | `.pyc` --> Python kaynak donusumu icin gerekli |
| Nuitka C-level analiz | ORTA | Nuitka binary'ler C'ye cevrilmis, Ghidra ile analiz edilebilir |
| py2exe/cx_Freeze destegi | DUSUK | Windows'a ozgu, macOS'ta nadir |
| Cython `.so` analiz | DUSUK | `.pyx` --> `.c` --> `.so` zinciri |

### Araclar

| Arac | Kurulum | Amac | Durum |
|---|---|---|---|
| `uncompyle6` | `pip install uncompyle6` | Python 2.6-3.8 `.pyc` decompile | Kurulu degil |
| `decompyle3` | `pip install decompyle3` | Python 3.7+ `.pyc` decompile | Kurulu degil |
| `pycdc` | Build from source | Daha genis Python versiyon destegi | Kurulu degil |
| `pyinstxtractor` | `pip install pyinstxtractor` | PyInstaller archive extraction | packed_binary.py'de kendi parser'i var |

### Tahmini Gelistirme Suresi: 1 gun (altyapi hazir, arac kurulumu + entegrasyon)


---

## 5. Java/Kotlin (JVM + Android)

### Binary Tespit Yontemi

**Kesinlik: YUKSEK** -- Magic bytes ve dosya yapisi cok belirgin.

```
Magic bytes:
  0xCAFEBABE -> Java .class dosyasi (DIKKAT: Universal Mach-O ile cakisir!)
                Class dosyasinda version bytes ile ayirt edilir
  0x504B0304 -> ZIP/JAR/APK (PK header)
  0x6465780A -> DEX (Android Dalvik executable, "dex\n")

Dosya uzantisi:
  .jar   -> Java Archive
  .class -> Java Class
  .apk   -> Android Package
  .dex   -> Dalvik Executable
  .aar   -> Android Archive

Icerik tespiti (JAR icinde):
  META-INF/MANIFEST.MF -> JAR manifest
  AndroidManifest.xml  -> APK (Android)
  classes.dex          -> APK icindeki DEX
```

**KRITIK UYARI:** `0xCAFEBABE` hem Java `.class` hem macOS Universal Binary magic byte'i.
Ayristirma icin: Class dosyasinda 4-7. byte'lar minor/major version (orn: 0x0000 0x003D = Java 17).
Universal binary'de 4-7. byte'lar architecture count (genellikle 2-3 arasi kucuk sayi).

### Araclar

| Arac | Kurulum | Amac | Oncelik |
|---|---|---|---|
| `jadx` | `brew install jadx` | APK/DEX/JAR --> Java kaynak (en iyi) | KRITIK |
| `javap` | JDK (mevcut) | `.class` disassembly | YUKSEK |
| `CFR` | `brew install cfr-decompiler` | `.class` --> Java kaynak | YUKSEK |
| `fernflower` | IntelliJ ile gelir / standalone jar | `.class` decompile | ORTA |
| `procyon` | Maven/jar | `.class` decompile | DUSUK |
| `apktool` | `brew install apktool` | APK resource decode + smali | ORTA |
| Ghidra | Mevcut (JVM + Dalvik processor var) | `.class`/`.dex` analiz | Mevcut |

**Durum:** Java 21 ve `javap` zaten kurulu. `jadx` ve `CFR` kurulmali.

### Karadul Entegrasyon Plani

```
Yeni dosyalar:
  karadul/analyzers/java_analyzer.py   -> JVM bytecode analiz
  karadul/analyzers/android_analyzer.py -> APK/DEX analiz (ileride)

Yeni TargetType:
  JAR_ARCHIVE = "jar_archive"
  CLASS_FILE = "class_file"
  APK_PACKAGE = "apk_package"   # (ileride)
  DEX_FILE = "dex_file"         # (ileride)
```

### Tahmini Gelistirme Suresi: 3-4 gun (JAR/class), +3 gun (Android APK/DEX)


---

## 6. .NET/C# (MSIL)

### Binary Tespit Yontemi

```
Magic bytes / header:
  PE header (0x4D5A "MZ") + .NET metadata
  CLI header (IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR)
  #Strings, #US, #Blob, #GUID, #~ stream'leri

Section isimleri:
  .text icinde IL bytecode
  .rsrc icinde manifest

String tespiti:
  "mscorlib"
  "System."
  "Microsoft.CSharp"
  ".NETCoreApp"
  "Mono."

Dosya uzantisi:
  .exe (PE + .NET metadata)
  .dll (.NET assembly)
```

### Araclar

| Arac | Kurulum | Amac | Oncelik |
|---|---|---|---|
| ILSpy | dotnet tool / standalone | MSIL --> C# kaynak (acik kaynak) | YUKSEK |
| dnSpy | GitHub release | MSIL debug + decompile (Windows only) | DUSUK (macOS yok) |
| `ilspy-cli` | `dotnet tool install ilspycmd -g` | CLI ile MSIL decompile | YUKSEK |
| `monodis` | `brew install mono` | MSIL disassembler | ORTA |
| Ghidra | Mevcut | PE + .NET analiz (sinirli IL destek) | Mevcut |

### macOS Kapsami

.NET binary'ler macOS'ta 3 formda bulunabilir:
1. **Mono binary** -- mono runtime ile calisir
2. **.NET Core/5+** -- cross-platform, self-contained publish
3. **Avalonia/MAUI apps** -- cross-platform UI framework

macOS'ta .NET RE nadirdir. Oncelik dusuk.

### Tahmini Gelistirme Suresi: 4-5 gun (PE parser + MSIL decompile)


---

## TargetType ve Language Enum Guncellemeleri

### Language Enum (Onerilen)

```python
class Language(Enum):
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"   # YENi
    RUST = "rust"
    SWIFT = "swift"
    CPP = "cpp"
    C = "c"                    # YENI (cpp'den ayirmak icin)
    OBJECTIVE_C = "objc"
    GO = "go"                  # YENI
    PYTHON = "python"          # YENI
    JAVA = "java"              # YENI
    KOTLIN = "kotlin"          # YENI
    CSHARP = "csharp"          # YENI
    UNKNOWN = "unknown"
```

### TargetType Enum (Onerilen)

```python
class TargetType(Enum):
    # JavaScript
    JS_BUNDLE = "js_bundle"
    ELECTRON_APP = "electron_app"

    # Native binary (Mach-O)
    MACHO_BINARY = "macho_binary"
    UNIVERSAL_BINARY = "universal_binary"

    # JVM
    JAR_ARCHIVE = "jar_archive"       # YENI
    CLASS_FILE = "class_file"         # YENI

    # Android
    APK_PACKAGE = "apk_package"       # YENI (Faz 2)
    DEX_FILE = "dex_file"             # YENI (Faz 2)

    # .NET
    DOTNET_ASSEMBLY = "dotnet_assembly"  # YENI (Faz 3)

    # Packed/Bundled
    PYINSTALLER_BUNDLE = "pyinstaller_bundle"  # YENI

    # Cross-platform binary
    ELF_BINARY = "elf_binary"         # YENI (Linux target analiz)
    PE_BINARY = "pe_binary"           # YENI (Windows target analiz)

    UNKNOWN = "unknown"
```

### Language Detection Guncellemesi (target.py)

```python
_LANGUAGE_SIGNATURES: dict[str, Language] = {
    # Mevcut
    "rust_begin_unwind": Language.RUST,
    "rust_panic": Language.RUST,
    "__rust_alloc": Language.RUST,
    "core::panicking": Language.RUST,
    "_swift_": Language.SWIFT,
    "Swift.": Language.SWIFT,
    "swift::": Language.SWIFT,
    "__cxa_throw": Language.CPP,
    "std::": Language.CPP,
    "__gnu_cxx": Language.CPP,
    "objc_msgSend": Language.OBJECTIVE_C,
    "@objc": Language.OBJECTIVE_C,
    "NSObject": Language.OBJECTIVE_C,

    # YENI: Go
    "runtime.gopanic": Language.GO,
    "runtime.goexit": Language.GO,
    "runtime.newproc": Language.GO,
    "go.shape": Language.GO,

    # YENI: Java (binary icinde gomulu JVM icin)
    "java/lang/Object": Language.JAVA,
    "java/lang/String": Language.JAVA,

    # YENI: C# (Mono/CoreCLR binary icin)
    "mscorlib": Language.CSHARP,
    "System.Runtime": Language.CSHARP,
}

# Section-bazli dil tespiti (daha guvenilir)
_SECTION_LANGUAGE_MAP: dict[str, Language] = {
    "__gopclntab": Language.GO,
    "__go_buildinfo": Language.GO,
    "__swift5_types": Language.SWIFT,
    "__swift5_proto": Language.SWIFT,
    "__swift5_typeref": Language.SWIFT,
}
```


---

## Onceliklendirme ve Yol Haritasi

### Faz 1: Mevcut Altyapiyi Duzelt (1 hafta)

| Gorev | Sure | Aciklama |
|---|---|---|
| Rust analyzer registry kaydi | 0.5 gun | `RustBinaryAnalyzer` registry'ye kaydet, Language.RUST kontrolu ekle |
| Go Language tespiti | 1 gun | `Language.GO` ekle, section-bazli tespit |
| Swift Language tespiti iyilestir | 0.5 gun | Section-bazli tespit ekle (string yerine) |
| Section-bazli dil tespiti mekanizmasi | 1 gun | `_detect_language_from_sections()` metodu -- string'den daha guvenilir |
| `TargetDetector` refactor | 1 gun | JAR/CLASS/ELF/PE magic byte tespiti |

### Faz 2: Go + Swift Analyzer (2 hafta)

| Gorev | Sure | Aciklama |
|---|---|---|
| `go_binary.py` -- temel | 2 gun | GoBinaryAnalyzer, build info, module extraction |
| GoReSym entegrasyon | 1 gun | Strip edilmis binary'lerde symbol recovery |
| `swift_binary.py` -- temel | 2 gun | SwiftBinaryAnalyzer, section parse, swift-demangle |
| class-dump entegrasyon | 1 gun | ObjC/Swift class hiyerarsisi |
| Rust analyzer iyilestirme | 1 gun | rustfilt entegrasyonu, registry kaydi |
| Python decompile araclari | 1 gun | uncompyle6/decompyle3 kurulum + entegrasyon |

### Faz 3: JVM Destegi (1-2 hafta)

| Gorev | Sure | Aciklama |
|---|---|---|
| `java_analyzer.py` | 3 gun | JAR parse, class decompile (jadx/CFR) |
| Ghidra JVM processor entegrasyon | 1 gun | Ghidra'nin JVM destegini kullan |
| Android APK (opsiyonel) | 3 gun | apktool + jadx ile APK analiz |

### Faz 4: Cross-Platform + .NET (ileride)

| Gorev | Sure | Aciklama |
|---|---|---|
| ELF binary tespit | 1 gun | Linux binary magic bytes |
| PE binary tespit | 1 gun | Windows binary magic bytes |
| .NET MSIL decompile | 4 gun | ILSpy CLI entegrasyonu |


---

## Mevcut Araclarin Durumu

### Sistemde Kurulu

| Arac | Yol | Durum |
|---|---|---|
| Ghidra 12.0 DEV | `~/Desktop/dosyalar/uygulamalar/ghidra/` | Kurulu, calisiyor |
| radare2 | `/opt/homebrew/bin/r2` | Kurulu |
| binwalk | brew | Kurulu |
| otool | Xcode | Kurulu |
| nm | Xcode | Kurulu |
| strings | Xcode | Kurulu |
| lipo | Xcode | Kurulu |
| xcrun swift-demangle | Xcode (LLVM 17) | Kurulu |
| javap | JDK 21 | Kurulu |
| Java 21 | `/opt/homebrew/opt/openjdk@21/` | Kurulu |

### Kurulmasi Gereken

| Arac | Komut | Ne icin | Oncelik |
|---|---|---|---|
| `GoReSym` | `go install github.com/mandiant/GoReSym@latest` | Go symbol recovery | KRITIK (once `go` kur) |
| `go` | `brew install go` | Go toolchain | YUKSEK |
| `rustfilt` | `cargo install rustfilt` (once `rustup` kur) | Rust demangling | YUKSEK |
| `jadx` | `brew install jadx` | Java/Android decompile | YUKSEK |
| `class-dump` | `brew install class-dump` | ObjC/Swift class dump | ORTA |
| `uncompyle6` | `pip install uncompyle6` | Python .pyc decompile | ORTA |
| `CFR` | `brew install cfr-decompiler` | Java decompile | ORTA |
| `cargo` | `brew install rustup && rustup-init` | Rust toolchain | ORTA |
| `redress` | `go install github.com/goretk/redress@latest` | Go metadata parser | ORTA |
| `dsdump` | `brew install dsdump` | Swift class dump | DUSUK |
| `apktool` | `brew install apktool` | Android APK decode | DUSUK |


---

## Mimari Oneriler

### 1. Analyzer Secim Mekanizmasi

Mevcut sorun: `get_analyzer(target_type)` sadece `TargetType`'a bakar, `Language`'i gormezden gelir.

Oneri: Iki katmanli eslestirme:

```python
def get_analyzer(target_type: TargetType, language: Language = Language.UNKNOWN) -> type:
    """TargetType + Language icin en uygun analyzer'i dondur."""
    # Once (type, language) cifti ile ara
    key = (target_type, language)
    if key in _SPECIFIC_ANALYZERS:
        return _SPECIFIC_ANALYZERS[key]

    # Sonra sadece type ile ara (fallback)
    if target_type in _ANALYZERS:
        return _ANALYZERS[target_type]

    raise ValueError(f"No analyzer for {target_type}/{language}")

# Kayit ornekleri:
# register_analyzer(TargetType.MACHO_BINARY, Language.GO)   -> GoBinaryAnalyzer
# register_analyzer(TargetType.MACHO_BINARY, Language.RUST)  -> RustBinaryAnalyzer
# register_analyzer(TargetType.MACHO_BINARY, Language.SWIFT) -> SwiftBinaryAnalyzer
# register_analyzer(TargetType.MACHO_BINARY)                 -> MachOAnalyzer (fallback)
```

### 2. Config Genisletmesi

```python
@dataclass
class ToolPaths:
    # Mevcut ...

    # Go
    go: Path = field(default_factory=lambda: Path("go"))
    goresym: Path = field(default_factory=lambda: Path("GoReSym"))
    redress: Path = field(default_factory=lambda: Path("redress"))

    # Rust
    rustfilt: Path = field(default_factory=lambda: Path("rustfilt"))

    # Swift
    swift_demangle: Path = field(default_factory=lambda: Path("xcrun"))
    class_dump: Path = field(default_factory=lambda: Path("class-dump"))

    # Java
    jadx: Path = field(default_factory=lambda: Path("jadx"))
    cfr: Path = field(default_factory=lambda: Path("cfr-decompiler"))
    javap: Path = field(default_factory=lambda: Path("javap"))

    # Python
    uncompyle6: Path = field(default_factory=lambda: Path("uncompyle6"))
    decompyle3: Path = field(default_factory=lambda: Path("decompyle3"))
```

### 3. Ortak Binary Analiz Altyapisi

Her dile ozel analyzer ayni temel adimlari tekrar ediyor. Ortak altyapi:

```python
class NativeBinaryAnalyzer(MachOAnalyzer):
    """Dil-bagimsiz native binary analiz altyapisi."""

    def analyze_static(self, target, workspace):
        result = super().analyze_static(target, workspace)

        # 1. Dile ozel symbol demangling
        result = self._demangle_symbols(result, workspace)

        # 2. Dile ozel metadata extraction
        result = self._extract_language_metadata(result, target, workspace)

        # 3. Dile ozel string pattern tespiti
        result = self._find_language_patterns(result, workspace)

        return result

    # Alt siniflar bunlari override eder
    def _demangle_symbols(self, result, workspace): ...
    def _extract_language_metadata(self, result, target, workspace): ...
    def _find_language_patterns(self, result, workspace): ...
```


---

## Guvenlik Degerlendirmesi

### Risk Analizi

| Risk | Seviye | Aciklama | Mitigation |
|---|---|---|---|
| CAFEBABE cakismasi | ORTA | Java .class ve Universal Mach-O ayni magic byte | Version byte kontrolu ile ayristir |
| GoReSym guvenilirlik | DUSUK | Mandiant araci, guvenilir | Imza dogrulama |
| jadx memory kullanimi | ORTA | Buyuk APK'larda cok RAM yiyebilir | Timeout + heap limit |
| .pyc decompile hatalari | ORTA | Python 3.12+ icin decompile araclari eksik | pycdc fallback |
| Strip edilmis binary | YUKSEK | Go/Rust/Swift strip binary'lerde bilgi kaybi | GoReSym, section analiz |

### Guvenli Arac Kullanimi

- Tum dis araclar sandbox'lanmali (subprocess timeout, memory limit)
- Kullanici binary'lerini analiz ederken malware riski -- izole calisma ortami onerilir
- Ghidra headless zaten sandbox'li calisiyor (mevcut altyapi yeterli)


---

## Sonuc ve Oneri

**Oncelik Sirasi:**

1. **Go** -- macOS'ta cok yaygin (Docker, Ollama, Terraform, kubectl, Hugo...), section-bazli tespit cok guvenilir, GoReSym strip binary'lerde bile calisiyor
2. **Swift** -- macOS native uygulamalarin cogu Swift, zaten swift-demangle kurulu, section metadata cok zengin
3. **Rust** -- Mevcut altyapi var ama registry'ye kayitli degil, rustfilt ile iyilestirme kolay
4. **Java/JVM** -- JDK 21 kurulu, jadx ile hizli entegrasyon, Android destegi ileride eklenebilir
5. **Python packed** -- Mevcut altyapi var, sadece decompile araclari eksik
6. **.NET** -- macOS'ta nadir, en dusuk oncelik

**Toplam tahmini sure:** Faz 1+2 = ~3 hafta, Faz 3 = +2 hafta, Faz 4 = ileride.

**Ilk adim olarak:** Faz 1'i yapmak (1 hafta) en mantikli. Bu, mevcut altyapidaki en buyuk sorunu cozer: dil tespiti iyilesir, Rust analyzer kayda girer ve yeni diller icin temel atilir.
