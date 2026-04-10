# KARADUL v1.0 -- MASTER PLAN: %95+ Kayipsiz Tersine Muhendislik

**Tarih:** 2026-03-22
**Surumu:** 1.0
**Vizyon:** Dusmanlari alt edecegiz. Yapilmayani yapacagiz. Neredeyse %100 kayipsiz tum kodlara ulasacagiz.

---

## Mevcut Durum Ozeti

| Metrik | Deger |
|--------|-------|
| Toplam Python kodu | ~15,000 satir (karadul paketi) |
| Toplam JS tooling | ~10,000+ satir (scripts/) |
| Test sayisi | 427 |
| SignatureDB | 3,589 imza |
| API ParamDB | 435 API x parametre isimleri |
| Binary name extractor | 4 strateji (debug string, build path, enum handler, RTTI) |
| C namer | 6 strateji (symbol, string-context, api-call, call-graph, dataflow, type-based) |
| Type recovery | struct, enum, vtable, type propagation |
| Algorithm ID | constant, structural, API correlation |
| JS pipeline | deobfuscate + source match + npm fingerprint + module split |
| Packed binary | UPX, PyInstaller, Nuitka tespit ve acma |
| Steam RE sonucu | 11,398 fonksiyon, %25-30 isim kurtarma |
| Claude Code RE sonucu | 549K satir deobfuscated, 2,227 modul cikarildi |

**Mevcut basari orani: ~%25-30 (binary), ~%60-70 (JS)**

**Hedef: %95+ (her iki alan)**

---

## Bolum 1: ML Model Entegrasyonu

### 1.1 Model Karsilastirma ve Secim

| Model | Kaynak | Hedef | Dogruluk | Model Boyutu | Calistirma | Durum |
|-------|--------|-------|----------|--------------|------------|-------|
| **VarBERT** | S&P 2024 | Variable names (C) | %54.4 (Ghidra O2) | ~110M param (BERT) | CPU/MPS | EN UYGUN - ilk hedef |
| **GenNm** | NDSS 2025 | Variable names (C) | %22.8 unseen | 2B-34B (CodeGemma/Llama) | GPU gerekli | YUKSEK ROI - 4090'da |
| **SymGen** | NDSS 2025 | Function names | %489 F1 arttirma (obf) | LLM-based | GPU gerekli | YUKSEK ROI - obf binary |
| **DIRE/DIRECT** | ASE 2019/2021 | Identifier rename | %74.3 | ~50M param | CPU | ESKI ama basit |
| **Context2Name** | 2018 | JS variable names | %47.5 | ~10M param | CPU | MEVCUT pipeline ile entegre |
| **CodeBERT** | Microsoft | Genel kod anlama | - | 125M param | CPU/MPS | Fine-tune icin base |

### 1.2 Strateji: Iki Asamali Yaklasim

**Asama A -- Hafif modeller (Mac'te calisir, 1 hafta):**

1. **VarBERT entegrasyonu** -- En yuksek ROI
   - GitHub: `sefcom/VarBERT` + `binsync/varbert_api`
   - Ghidra decompile ciktisini dogrudan besleyebilir
   - BERT-base boyutu, MPS'te inference 50ms/fonksiyon
   - Mevcut `c_namer.py`'ye 7. strateji olarak eklenir
   - Confidence: 0.6-0.8 (ML-based, diger stratejilerden dusuk onde)

   ```
   Dosya degisiklikleri:
   - karadul/reconstruction/c_namer.py        -- VarBERT strateji ekleme
   - karadul/reconstruction/ml_models.py       -- YENI: ML model wrapper
   - karadul/config.py                         -- ML config ekleme
   - requirements-ml.txt                       -- YENI: torch, transformers
   ```

2. **Context2Name entegrasyonu** -- JS pipeline icin
   - Token-based static analysis + autoencoder
   - 2.9ms/tahmin -- pipeline'i yavassatmaz
   - Mevcut `variable_renamer.py` ile entegre
   - NPM fingerprint bulamadiginda fallback olarak calisir

   ```
   Dosya degisiklikleri:
   - karadul/reconstruction/variable_renamer.py  -- Context2Name fallback
   - scripts/rename-variables.mjs                -- Node.js tarafinda ML hook
   ```

**Asama B -- Buyuk modeller (4090'da calisir, 2 hafta):**

3. **GenNm (CodeGemma-2B)** -- Variable name recovery
   - CodeGemma-2B fine-tuned: 4090'da 16GB VRAM'e sigar
   - Caller/callee context dahil -- en zengin baglamsal bilgi
   - %22.8 unseen names (rakiplerin 2-3x ustu)
   - SSH uzerinden batch inference, sonuc JSON olarak Mac'e transfer

   ```
   Dosya degisiklikleri:
   - karadul/reconstruction/ml_models.py     -- GenNm remote inference
   - scripts/ml-inference-server.py          -- YENI: 4090'da FastAPI server
   - karadul/config.py                       -- remote_ml_endpoint ekleme
   ```

4. **SymGen** -- Function name recovery (obfuscated binary icin)
   - Domain-adapted LLM, Ghidra decompile output kullanir
   - Obfuscated binary'lerde %489 F1 artisi (kritik!)
   - Antlr4 ile source code ve decompiled code isleme
   - 4090'da inference

   ```
   Dosya degisiklikleri:
   - karadul/reconstruction/symgen_namer.py  -- YENI: SymGen entegrasyonu
   - karadul/reconstruction/binary_name_extractor.py -- SymGen fallback
   ```

### 1.3 ML Pipeline Mimarisi

```
Binary/JS Input
      |
      v
+------------------+
| Mevcut Heuristik |  (c_namer 6 strateji + binary_name_extractor 4 strateji)
| Katman           |  Confidence: 0.2 - 0.95
+------------------+
      |
      | Isimlendirilemeyen fonksiyonlar (FUN_xxx, var_N)
      v
+------------------+
| VarBERT (local)  |  Mac MPS, 50ms/fonk
| Katman           |  Confidence: 0.5 - 0.8
+------------------+
      |
      | Hala isimlendirilemeyen + dusuk confidence'lilar
      v
+------------------+
| GenNm (remote)   |  4090 GPU, 200ms/fonk
| Katman           |  Confidence: 0.6 - 0.9
+------------------+
      |
      v
+------------------+
| Confidence Merge |  En yuksek confidence'li ismi sec
| + Conflict Res   |  Conflict: coklu model arasinda oylama
+------------------+
      |
      v
   Final Named Output
```

### 1.4 Tahmini Etki

| Kaynak | Mevcut | +VarBERT | +GenNm | +SymGen | Toplam |
|--------|--------|----------|--------|---------|--------|
| Heuristik (binary) | %25-30 | - | - | - | %25-30 |
| VarBERT | - | +%15-20 | - | - | %40-50 |
| GenNm | - | - | +%10-15 | - | %50-65 |
| SymGen (func name) | - | - | - | +%10-15 | %60-80 |
| **Binary toplam** | **%25-30** | **%40-50** | **%50-65** | **%60-80** | |

Kalan %15-20 Bolum 2-7'deki tekniklerle kapatilacak.

---

## Bolum 2: Assembly-Level Analiz

### 2.1 Neden Gerekli

Ghidra decompiler bazen basarisiz olur:
- Agir optimizasyon (O3, LTO)
- Hand-written assembly (crypto, SIMD)
- Obfuscated code (opaque predicates, flattened CFG)
- Exotic calling conventions

Bu durumlarda assembly'den dogrudan bilgi cikarilmali.

### 2.2 Register Allocation Analizi

**Amac:** Register kullanimindan degisken mapping cikarmak.

```
Strateji:
1. Calling convention'dan parametre registerlari tespit et
   - x86_64 System V: rdi, rsi, rdx, rcx, r8, r9 (ilk 6 param)
   - ARM64 (Apple): x0-x7 (ilk 8 param)
   - Windows x64: rcx, rdx, r8, r9

2. Register lifetime analysis:
   - Bir register'a ilk yazildigi ve son okundugu yer arasindaki aralik
   - Farkli lifetime'lar = farkli degiskenler
   - Overlapping lifetime = register reuse, ayri degisken

3. Callee-saved register tracking:
   - rbx, rbp, r12-r15 (System V) fonksiyon basinda push edilirse
   - Bu register'lar local degisken tasir, stack'e spill olur
```

```
Dosya degisiklikleri:
- karadul/analyzers/assembly_analyzer.py       -- YENI
- karadul/reconstruction/register_tracker.py   -- YENI
- karadul/ghidra/scripts/asm_extractor.py      -- YENI: Ghidra'dan raw asm cikart
```

**Tahmini sure:** 1 hafta
**Bagimliliklar:** capstone (mevcut dependency), Ghidra raw assembly export

### 2.3 Stack Frame Analysis

**Amac:** Local degisken layout'unu stack frame'den cikar.

```
Strateji:
1. Fonksiyon prolog analizi:
   - sub rsp, 0x48 -> 72 byte stack frame
   - Frame icindeki erisimleri (rbp-0x8, rbp-0x10 vb.) takip et

2. Stack slot clustering:
   - Ayni offset'e yapilan tum erisimler = tek degisken
   - Offset araliklari = struct veya array
   - Alignment pattern'lerinden tip tahmini:
     - 1-byte aligned: char/bool
     - 4-byte aligned: int/float
     - 8-byte aligned: pointer/long/double

3. Array detection:
   - base + i*stride pattern'i -> array
   - Sabit stride -> eleman boyutu
```

```
Dosya degisiklikleri:
- karadul/reconstruction/stack_analyzer.py     -- YENI
```

**Tahmini sure:** 3 gun
**Bagimliliklar:** capstone, assembly_analyzer.py

### 2.4 SIMD/Vectorization Reconstruction

**Amac:** SIMD instruction'lardan orijinal loop yapisini cikar.

```
Strateji:
1. SIMD instruction pattern tanima:
   - SSE: movaps, addps, mulps -> float[4] array isleme
   - AVX: vmovaps, vaddps -> float[8] array isleme
   - NEON (ARM): fmla, fadd -> float[4] vector isleme

2. Loop reconstruction:
   - SIMD + scalar epilog = vectorized loop
   - unrolled SIMD = loop unrolling + vectorization
   - Stride pattern -> orjinal loop step

3. Anlamli isimlendirme:
   - addps + mulps pattern = "vector_dot_product" veya "matrix_multiply"
   - pshufb + pxor = "aes_encrypt_round"
```

```
Dosya degisiklikleri:
- karadul/reconstruction/simd_analyzer.py      -- YENI
- karadul/analyzers/signature_db.py            -- SIMD pattern signatures ekleme
```

**Tahmini sure:** 1 hafta
**Bagimliliklar:** capstone

### 2.5 Tahmini Etki

Assembly-level analiz, decompiler basarisiz oldugunda devreye girer.
Tahmini kapsam: toplam fonksiyonlarin %5-10'u sadece assembly ile anlasilabilir.
Bu %5-10'luk dilimde %60-70 basari orani = toplam %3-7 ek kurtarma.

---

## Bolum 3: Multi-Language Decompiler Destegi

### 3.1 Mevcut Durum ve Hedef

| Dil | Mevcut Destek | Hedef | Zorluk |
|-----|--------------|-------|--------|
| C/C++ | Ghidra decompile + 10 strateji | %80+ | ORTA |
| JavaScript | Deobfuscate + source match + npm FP | %85+ | ORTA |
| Go | YOK | %90+ | DUSUK (zengin metadata) |
| Rust | Basit rustfilt | %85+ | ORTA |
| Swift | YOK | %85+ | ORTA |
| Python (packed) | PyInstaller/Nuitka unpack | %95+ | DUSUK |
| Java/Kotlin | YOK | %90+ | DUSUK |
| .NET/C# | YOK | %95+ | DUSUK |

### 3.2 Go Binary Analizi

Go binary'leri isim kurtarma icin EN KOLAY hedef -- runtime metadata cok zengin.

```
Strateji:
1. go tool objdump -> tum fonksiyon isimleri (GOPCLNTAB'dan)
   - Go binary'leri STRIP edilse bile GOPCLNTAB genelde kalir
   - Fonksiyon isimleri, dosya adlari, satir numaralari

2. BUILDINFO section -> Go versiyonu, modul listesi, dependency tree

3. Type descriptor -> tum struct ve interface tanimlari
   - reflect metadata icinde tam tip bilgisi var

4. Goroutine analizi -> concurrent yapi kurtarma
```

```
Dosya degisiklikleri:
- karadul/analyzers/go_binary.py               -- YENI: Go binary analyzer
- karadul/reconstruction/go_reconstructor.py   -- YENI: Go proje rebuild
```

**Tahmini sure:** 3 gun
**Bagimliliklar:** go tool (system), objdump
**Beklenen basari:** %90+ (metadata sayesinde)

### 3.3 Rust Binary Analizi

```
Strateji:
1. rustfilt ile mangled symbol demangling (mevcut: basit, genisletilecek)
2. DWARF debug info (debug build'lerde tam bilgi)
3. cargo metadata extraction (Cargo.toml kalintilari)
4. Panic message parsing -> fonksiyon ismi + dosya yolu
5. Trait vtable analizi -> interface/impl recovery
```

```
Dosya degisiklikleri:
- karadul/analyzers/rust_binary.py             -- GENISLETME (mevcut)
- karadul/reconstruction/rust_reconstructor.py -- YENI
```

**Tahmini sure:** 4 gun
**Bagimliliklar:** rustfilt (cargo install rustfilt)
**Beklenen basari:** %85+ (panic string'ler cok bilgi verir)

### 3.4 Swift Binary Analizi

```
Strateji:
1. swift demangle -> Swift mangled isimleri coz
2. ObjC interop metadata -> @objc class'lar, bridge fonksiyonlar
3. Swift protocol witness table -> protocol conformance
4. Swift type metadata -> struct/class/enum tanimlari
5. String interpolation kalintilari -> degisken isimleri
```

```
Dosya degisiklikleri:
- karadul/analyzers/swift_binary.py            -- YENI
- karadul/reconstruction/swift_reconstructor.py -- YENI
```

**Tahmini sure:** 4 gun
**Bagimliliklar:** swift (Xcode), xcrun swift-demangle

### 3.5 Java/Kotlin Decompilation

```
Strateji:
1. jadx ile APK/JAR decompile -> neredeyse tam kaynak (obfuscation haric)
2. ProGuard/R8 mapping.txt ters cevirme
3. Kotlin metadata annotation parsing -> data class, extension function
4. Resource dosyalari (AndroidManifest, layout XML) -> class isimleri
```

```
Dosya degisiklikleri:
- karadul/analyzers/java_binary.py             -- YENI
- karadul/reconstruction/java_reconstructor.py -- YENI
```

**Tahmini sure:** 3 gun
**Bagimliliklar:** jadx (brew install jadx), dex2jar
**Beklenen basari:** %90+ (JVM bytecode cok bilgi tasir)

### 3.6 .NET/C# Decompilation

```
Strateji:
1. ILSpy / dnSpyEx CLI ile IL -> C# decompile
2. .NET metadata tamamen korunur: class, method, field isimleri
3. NuGet paket referanslari -> dependency recovery
4. Obfuscation (ConfuserEx vb.) tespit ve geri alma
```

```
Dosya degisiklikleri:
- karadul/analyzers/dotnet_binary.py           -- YENI
- karadul/reconstruction/dotnet_reconstructor.py -- YENI
```

**Tahmini sure:** 2 gun
**Bagimliliklar:** ilspycmd (dotnet tool install), dnSpyEx
**Beklenen basari:** %95+ (.NET metadata en zengin kaynak)

### 3.7 Dil Tespit Otomasyonu

Mevcut `TargetDetector` genisletilecek:

```
Dosya degisiklikleri:
- karadul/core/target.py                       -- Language enum genisletme
- karadul/analyzers/__init__.py                -- Yeni analyzer register
- karadul/stages.py                            -- Dil-spesifik stage routing
```

---

## Bolum 4: Source Matching Engine

### 4.1 Rosetta Stone Yaklasimi

**Prensip:** Bilinen kaynak kodunu referans alarak, bilinmeyen kodu tanimla.

```
Katman 1: SDK/Framework Matching
- Bilinen SDK versiyonlarini indirip fingerprint cikart
- Binary'deki fonksiyonlari bu fingerprint'lerle eslesir
- Ornek: Steam SDK, Electron, Qt, Boost

Katman 2: NPM/Package Registry Matching (MEVCUT, genisletilecek)
- npm registry'den populer paketleri cekip AST fingerprint
- Minified JS fonksiyonlarini orijinal kaynak ile eslestir
- Mevcut: NpmFingerprinter + SourceResolver + ASTFingerprinter

Katman 3: GitHub Open Source Matching
- Bilinen acik kaynak projelerin compiled versiyonlarini DB'ye ekle
- Binary'deki fonksiyonlari bu DB ile karsilastir
- Byte pattern + string reference + call graph combined matching
```

### 4.2 Bilinen Kutuphane Byte Pattern DB

Mevcut `signature_db.py` (3,589 imza) genisletilecek:

```
Hedef: 50,000+ imza

Ek kaynaklar:
1. Homebrew formula'larindan populer C/C++ kutuphaneleri derleyip
   byte pattern cikar (otomatik script)
2. vcpkg/conan package manager'lardan prebuilt lib fingerprint
3. Ubuntu/Fedora paket repo'larindan .so dosyalarinin imzalari
4. Windows SDK DLL'lerinden export signature

Eslestirme iyilestirmesi:
- Mevcut: String reference + symbol matching
- Ek: Ilk 32 byte pattern + function size + call count hash
- Ek: Basic block count + edge count (CFG fingerprint)
```

```
Dosya degisiklikleri:
- karadul/analyzers/signature_db.py            -- 50K+ imza genisletme
- karadul/analyzers/lib_fingerprinter.py       -- YENI: Otomatik lib FP uretici
- scripts/build-signature-db.py                -- YENI: Homebrew'dan toplu imza cikar
```

**Tahmini sure:** 1 hafta (DB olusturma otomatik ama zaman alir)
**Tahmini etki:** Binary isim kurtarmada +%10-15

### 4.3 Cross-Reference Birlestirme

```
Birden fazla kaynaktan gelen isimlerin birlestirilmesi:

Source A: SignatureDB      -> send_http_request (conf: 0.7)
Source B: String analysis  -> http_send (conf: 0.6)
Source C: VarBERT          -> send_request (conf: 0.55)
Source D: GenNm            -> send_http_request (conf: 0.8)

Birlestirme stratejisi:
1. Exact match: A ve D ayni ismi veriyor, confidence ortala -> 0.75
2. Semantic similarity: B ve C benzer anlam, dusuk confidence
3. Final karar: "send_http_request" (2 kaynak + yuksek conf)
```

```
Dosya degisiklikleri:
- karadul/reconstruction/name_merger.py        -- YENI: Coklu kaynak birlestirme
```

---

## Bolum 5: String Intelligence

### 5.1 Mevcut Durum

- `binary_name_extractor.py`: Debug string parse + build path mapper
- `c_namer.py`: String-context strateji
- `string_extractor.py` (Ghidra script): String cikarim

### 5.2 Yeni String Intelligence Katmanlari

**Katman A: Assert/Debug String Parser (conf: 0.80-0.95)**

```
Pattern'ler:
- assert(condition) -> "file.cpp:123: MyClass::MyMethod: assertion failed"
  -> fonksiyon ismi: MyClass::MyMethod
  -> dosya: file.cpp, satir: 123

- __func__, __FUNCTION__ macro kalintilarindan isim cikarma
- Qt Q_ASSERT, Boost BOOST_ASSERT benzerleri

Mevcut binary_name_extractor.py bunu KISMEN yapiyor.
Genisletme: daha fazla assert framework destegi.
```

**Katman B: Error Message Pattern Matching (conf: 0.60-0.85)**

```
Pattern'ler:
- "Error in ParseConfig: invalid format" -> fonksiyon: ParseConfig
- "CSocket::Connect failed" -> class: CSocket, method: Connect
- "[WARNING] AudioManager: buffer underrun" -> class: AudioManager
- "Failed to initialize renderer" -> fonksiyon: initialize_renderer

Yeni regex seti:
- "Error in FUNC_NAME:" pattern
- "CLASS::METHOD failed" pattern
- "[LEVEL] MODULE: message" pattern
- "Failed to VERB NOUN" -> VERB_NOUN fonksiyon ismi
```

**Katman C: Protocol/Message Handler Naming (conf: 0.70-0.90)**

```
Steam ornegi:
- k_EMsgClientLogon (enum degeri) -> handler: HandleClientLogon
- String "k_EMsgXXX" referansi olan fonksiyon = o mesajin handler'i

Genel pattern:
- MSG_TYPE enum -> Handler_MSG_TYPE fonksiyon eslestirmesi
- gRPC service definition string -> method handler
- HTTP route string ("/api/v1/users") -> handler fonksiyon
```

**Katman D: Telemetry/Analytics Event Naming (conf: 0.65-0.80)**

```
Pattern'ler:
- "TrackEvent('page_load', ...)" -> fonksiyon: track_page_load
- "analytics.logEvent('user_login')" -> fonksiyon: log_user_login
- "[metric] render_time_ms" -> fonksiyon: measure_render_time
```

```
Dosya degisiklikleri:
- karadul/reconstruction/binary_name_extractor.py  -- Katman B,C,D ekleme
- karadul/reconstruction/string_intelligence.py    -- YENI: Merkezi string analiz
- karadul/analyzers/signature_db.py                -- String-based signature ekleme
```

**Tahmini sure:** 4 gun
**Tahmini etki:** +%5-10 (ozellikle buyuk binary'lerde)

---

## Bolum 6: Type Recovery -- Ileri Seviye

### 6.1 Mevcut Durum

- `c_type_recoverer.py`: struct, enum, vtable, type propagation
- 5 capability: struct recovery, enum recovery, vtable recovery, type propagation, Ghidra tip duzeltme

### 6.2 Struct Layout Fingerprint DB

**Amac:** Bilinen struct'larin layout'unu (field offset + size) DB'ye kaydet, binary'deki bilinmeyen struct'lari eslesir.

```
Ornek:
- struct sockaddr_in: {0: sa_family_t(2), 2: in_port_t(2), 4: in_addr(4), 8: zero(8)} = 16 byte
- Binary'de 16 byte struct, offset 0'da 2 byte, offset 4'te 4 byte erisim var
  -> sockaddr_in ile eslesti!

DB icerigi:
- POSIX struct'lari (~200): sockaddr, stat, iovec, pollfd, ...
- Windows struct'lari (~300): OVERLAPPED, SECURITY_ATTRIBUTES, ...
- Protobuf generated struct'lar (runtime): MessageLite, Arena, ...
- Qt struct'lari (~100): QObject, QWidget, QString internal, ...
- OpenSSL struct'lari (~50): SSL_CTX, BIO, EVP_MD_CTX, ...
```

```
Dosya degisiklikleri:
- karadul/reconstruction/struct_fingerprint_db.py  -- YENI: 50K+ struct layout
- karadul/reconstruction/c_type_recoverer.py       -- Fingerprint matching ekleme
```

**Tahmini sure:** 1 hafta (DB olusturma + matching logic)

### 6.3 VTable -> Class Hierarchy Reconstruction

```
Mevcut: vtable detection (c_type_recoverer.py)
Genisletme:

1. Tam inheritance tree cikarma:
   - vtable icindeki function pointer'larin eslesmesi
   - Base class vtable C derived vtable'in prefix'i
   - Diamond inheritance tespit (RTTI'dan)

2. Pure virtual function detection:
   - __cxa_pure_virtual adresine point eden vtable entry
   - = abstract base class

3. Virtual destructor chain:
   - vtable[0] veya vtable[1] destructor
   - Destructor icinde base destructor cagrisi = inheritance
```

```
Dosya degisiklikleri:
- karadul/reconstruction/c_type_recoverer.py  -- Hierarchy reconstruction ekleme
- karadul/reconstruction/class_hierarchy.py   -- YENI: Tam class tree
```

### 6.4 RTTI Chain Analizi

```
Mevcut: RTTI class name extraction (binary_name_extractor.py)
Genisletme:

1. Itanium ABI RTTI structure parsing:
   - __class_type_info (base class, no parent)
   - __si_class_type_info (single inheritance)
   - __vmi_class_type_info (multiple/virtual inheritance)

2. Her RTTI entry'den:
   - Class ismi (demangle)
   - Parent class(es) referansi
   - Virtual base offset
   - Public/protected/virtual flags

3. Sonuc: Tam inheritance graph
```

### 6.5 Union/Bitfield Detection

```
Strateji:
1. Union detection:
   - Ayni offset'e farkli boyutlarda erisim = union
   - Ornek: offset 0'a hem 4-byte hem 8-byte erisim

2. Bitfield detection:
   - AND mask + shift pattern = bitfield erisimi
   - Ornek: (val >> 5) & 0x7 = 3-bit field at bit 5-7

3. Flag field detection:
   - val | FLAG_X, val & ~FLAG_X, val & FLAG_X pattern
   - Her flag icin enum degeri cikar
```

```
Dosya degisiklikleri:
- karadul/reconstruction/c_type_recoverer.py   -- Union/bitfield detection ekleme
```

**Bolum 6 toplam tahmini sure:** 2 hafta
**Tahmini etki:** +%5-8 (ozellikle C++ binary'lerde, class/struct isimleri)

---

## Bolum 7: Obfuscation Defeat

### 7.1 Mevcut Durum

- JS: `synchrony_wrapper.py`, `babel_pipeline.py`, `deep_pipeline.py`
- Binary: `binary_deobfuscator.py` (basit)
- CFF destegi: YOK
- VM deobfuscation: YOK
- String decryption: Basit XOR

### 7.2 Control Flow Flattening (CFF) Deflattening

**JS CFF Deflattening:**

```
Strateji:
1. Switch-case dispatcher pattern tespiti:
   while(true) {
     switch(state) {
       case 0: ... state = 3; break;
       case 1: ... state = 5; break;
       ...
     }
   }

2. State transition graph cikart
3. Topological sort ile orijinal control flow'u yeniden olustur
4. Mevcut deep_pipeline.py'ye entegre et

Araclar: synchrony (mevcut) bazi CFF'leri cozer.
Ek: AST-based custom deflattener.
```

**Binary CFF Deflattening:**

```
Strateji:
1. Basic block'lari cikar (Ghidra/radare2)
2. Dispatcher block'u tespit et (en cok gelen edge'e sahip block)
3. Symbolic execution ile state degiskenini takip et
4. Her state icin gercek successor'u bul
5. Orijinal CFG'yi yeniden olustur

Araclar:
- Miasm (Python symbolic execution framework)
- angr (binary analysis, symbolic execution)
- D-810 yaklasimi (IDA microcode, Ghidra'ya uyarlanacak)
```

```
Dosya degisiklikleri:
- karadul/deobfuscators/cff_deflattener.py     -- YENI: Binary CFF
- karadul/deobfuscators/deep_pipeline.py       -- JS CFF ekleme
- scripts/deflat-js.mjs                        -- YENI: JS CFF Node.js tool
```

**Tahmini sure:** 2 hafta (karmasik)
**Bagimliliklar:** angr, miasm (pip install)

### 7.3 Opaque Predicate Elimination

```
Strateji:
1. Pattern tanima:
   - x * (x + 1) % 2 == 0 (her zaman true)
   - x^2 >= 0 (her zaman true)
   - (x | 1) != 0 (her zaman true)

2. Constant folding:
   - Sabit deger kullanilan branch -> dead branch eliminasyonu

3. Z3 SMT solver ile dogrulama:
   - Suphe edilen predicate'i Z3'e sor
   - Satisfiable mi? Her iki branch da aliyor mu?

4. Branch pruning:
   - Opaque predicate oldugu tespit edilen branch'i kaldir
   - Dead code'u temizle
```

```
Dosya degisiklikleri:
- karadul/deobfuscators/opaque_predicate.py    -- YENI
```

**Tahmini sure:** 4 gun
**Bagimliliklar:** z3-solver (pip install z3-solver)

### 7.4 String Decryption

```
Mevcut: Basit XOR (binary_deobfuscator.py)
Genisletme:

1. XOR variations:
   - Rolling XOR (her byte farkli key)
   - XOR + ADD/SUB combined
   - Multi-byte XOR key

2. RC4 decryption:
   - S-box initialization pattern tespiti (256 byte swap loop)
   - Key extraction (sabit key veya runtime key)

3. AES decryption:
   - AES S-box constant (0x637c777bf26b6fc5...) tespiti
   - Key schedule pattern

4. Custom string table:
   - Index-based string lookup (string_table[idx])
   - Base64 encoded string'ler
   - Stack string reconstruction (char-by-char push)

5. Stack string reconstruction:
   - mov [rbp-0x20], 'H'
   - mov [rbp-0x1f], 'e'
   - mov [rbp-0x1e], 'l'
   - ...
   -> "Hello"
```

```
Dosya degisiklikleri:
- karadul/deobfuscators/string_decryptor.py    -- YENI: Gelismis string decryption
- karadul/deobfuscators/binary_deobfuscator.py -- String decryptor entegrasyonu
```

**Tahmini sure:** 5 gun

### 7.5 VM Devirtualization (VMProtect/Themida)

**NOT:** Bu en zor ve en uzun sureli gorev. Sprint 3 icin planlanmistir.

```
Strateji:
1. VM entry/exit pattern tespiti:
   - pushad/pusha + jmp vm_dispatcher (VMProtect)
   - Context save + handler table lookup (Themida)

2. Handler table extraction:
   - VM opcode -> native handler mapping
   - Her handler'in emule ettigi instruction

3. LLVM lifting yaklasimi (Mergen benzeri):
   - VM bytecode'u LLVM IR'a cevir
   - LLVM optimization pass'leri uygula (dead code, constant fold)
   - LLVM IR'dan C kodu uret

4. Pattern-based kisa yol:
   - Bilinen VMProtect versiyon imzalari (3.4, 3.5, 3.6, 3.8)
   - Her versiyon icin handler mapping DB
```

```
Dosya degisiklikleri:
- karadul/deobfuscators/vm_devirtualizer.py    -- YENI
- karadul/deobfuscators/vmprotect_handler_db.py -- YENI: Handler mapping
```

**Tahmini sure:** 3-4 hafta (en zor gorev)
**Bagimliliklar:** LLVM/llvmlite, Mergen referans kodu
**Risk:** Yuksek -- her VMProtect versiyonu farkli, %100 basari garantisi yok

### 7.6 Bolum 7 Tahmini Etki

| Teknik | Kapsam | Basari | Net etki |
|--------|--------|--------|----------|
| CFF deflattening | Obfuscated binary'lerin %20-30'u | %60-70 | +%4-6 |
| Opaque predicate | Obfuscated binary'lerin %40-50'u | %80-90 | +%3-5 |
| String decryption | Obfuscated binary'lerin %60-70'u | %70-80 | +%5-8 |
| VM devirtualization | VMProtect/Themida kullananlarin %30-40'i | %40-50 | +%2-3 |

---

## Bolum 8: Pipeline Optimization

### 8.1 ContentStore (Mevcut)

`content_store.py` mevcut. I/O %86 azaltma sagliyor.

```
Genisletme:
1. LRU cache boyutunu konfigurasyona tasima
2. Memory-mapped file destegi (buyuk binary icin)
3. Shared memory ile paralel worker'lar arasi paylasim
```

### 8.2 Paralel Processing

```
Mevcut: CPU_PERF_CORES (config.py) ile tespit, ama tam kullanilmiyor.

Strateji:
1. Fonksiyon bazinda paralel islem:
   - 11,398 fonksiyonu 10 P-core'a dagit
   - Her core bir fonksiyonu analiz eder (c_namer + type_recoverer + algo_id)
   - ProcessPoolExecutor ile (GIL bypass)

2. Stage bazinda pipeline paralelligi:
   - Static analysis ve string extraction paralel
   - Deobfuscation bitmeden reconstruction bekle (dependency)

3. ML inference batching:
   - VarBERT: 32 fonksiyonu bir batch'te isle (GPU efficiency)
   - GenNm: 8 fonksiyon/batch (buyuk model)
```

```
Dosya degisiklikleri:
- karadul/core/pipeline.py                     -- Paralel stage execution
- karadul/stages.py                            -- Worker pool ekleme
- karadul/reconstruction/c_namer.py            -- Paralel fonksiyon isleme
```

**Tahmini sure:** 3 gun
**Tahmini etki:** 5-10x hizlanma (10 P-core tam kullanim)

### 8.3 Incremental Analysis (Cache)

```
Strateji:
1. Fonksiyon hash'i ile cache:
   - Bir fonksiyonun byte pattern hash'i degismediyse, onceki sonucu kullan
   - Hash: SHA256(function_bytes + ghidra_version)

2. Partial re-analysis:
   - Binary guncellendiyse, sadece degisen fonksiyonlari yeniden analiz et
   - diff-based: onceki analiz sonucu ile karsilastir

3. Result cache:
   - naming_map, type_info, algorithm_matches SQLite DB'de sakla
   - Sonraki calistirmada once cache'e bak
```

```
Dosya degisiklikleri:
- karadul/core/cache.py                        -- YENI: Analiz cache
- karadul/core/pipeline.py                     -- Cache integration
```

**Tahmini sure:** 3 gun

### 8.4 Buyuk Binary Chunking

```
Mevcut: chunked_processor.py
Genisletme:

1. 577MB Excel binary gibi devasa dosyalar icin:
   - Section bazinda chunking (her section ayri islenebilir)
   - Memory-mapped I/O ile RAM tasarrufu
   - Streaming JSON output (tum sonucu RAM'de tutma)

2. Ghidra timeout yonetimi:
   - Buyuk binary icin Ghidra'ya 2 saat timeout (mevcut)
   - Ama 577MB icin yetmeyebilir -- adaptive timeout
   - Fonksiyon sayisina gore timeout hesapla: 30s + N_func * 0.5s
```

```
Dosya degisiklikleri:
- karadul/core/chunked_processor.py            -- Genisletme
- karadul/ghidra/headless.py                   -- Adaptive timeout
```

---

## Bolum 9: Kalite ve Test

### 9.1 %95+ Hedef icin Metrik Tanimi

```
NAMING_ACCURACY = (correctly_named_symbols / total_recoverable_symbols) * 100

"Correctly named" tanimi:
- Exact match: Orijinal isimle birebir ayni
- Semantic match: Ayni anlama gelen isim (send_data vs send_buffer)
- Partial match: Class veya method dogru, diger kisim farkli
  (CSocket::Send vs CSocket::SendData -> partial match)

Agirliklar:
- Exact match: 1.0 puan
- Semantic match: 0.8 puan
- Partial match: 0.5 puan
- Wrong name: 0.0 puan
- No name (FUN_xxx kaldi): 0.0 puan

"Total recoverable symbols" = debug binary'deki toplam named symbol sayisi
(compiler-generated ve inlined olanlar haric)
```

### 9.2 Benchmark Binary Seti

| # | Binary | Dil | Boyut | Neden | Kaynak |
|---|--------|-----|-------|-------|--------|
| 1 | coreutils (ls, cat, grep) | C | ~500KB | Basit C, bilinen isimler | GNU source |
| 2 | curl | C | ~2MB | Network + crypto, cok API | GitHub |
| 3 | nginx | C | ~5MB | Server, event loop, complex | nginx.org |
| 4 | Steam client | C++ | ~50MB | Production, partial strip | Mevcut target |
| 5 | ffmpeg | C | ~20MB | SIMD, codec, complex algo | GitHub |
| 6 | electron app | JS+native | ~100MB | Hybrid, webpack bundle | Mevcut target |
| 7 | Go binary (hugo) | Go | ~30MB | Go metadata test | GitHub |
| 8 | Rust binary (ripgrep) | Rust | ~5MB | Rust metadata test | GitHub |
| 9 | .NET app | C# | ~10MB | .NET metadata test | GitHub |
| 10 | Obfuscated sample | C++ | ~5MB | VMProtect/Themida test | CTF sample |

### 9.3 Benchmark Harness

```
Dosya degisiklikleri:
- tests/benchmark/                              -- YENI dizin
- tests/benchmark/conftest.py                   -- Benchmark fixture'lari
- tests/benchmark/test_benchmark_c.py           -- C binary benchmark
- tests/benchmark/test_benchmark_js.py          -- JS benchmark
- tests/benchmark/test_benchmark_multilang.py   -- Multi-lang benchmark
- tests/benchmark/benchmark_runner.py           -- Otomatik benchmark calistirici
- tests/benchmark/metrics.py                    -- Metrik hesaplama
```

**Calisma mantigi:**
1. Debug binary'yi derle (sembollerle)
2. Strip et (sembolleri sil)
3. Karadul ile analiz et
4. Kurtarilan isimleri orijinal sembollerle karsilastir
5. Dogruluk metrigini hesapla

### 9.4 Regression Testing

```
Her commit'te:
1. 427 mevcut unit test (mevcut, ~10 saniye)
2. Benchmark binary seti uzerinde accuracy check (yeni, ~5 dakika)
3. Minimum accuracy threshold: %90 (altina duserse FAIL)
4. Accuracy trend takibi (her calistirmada JSON log)
```

### 9.5 CI/CD Pipeline

```
Dosya degisiklikleri:
- .github/workflows/test.yml                   -- YENI: GitHub Actions CI
- .github/workflows/benchmark.yml              -- YENI: Haftalik benchmark
- Makefile                                     -- YENI: make test, make bench
```

---

## Bolum 10: Yol Haritasi

### Sprint 0: Hazirlik (1-2 gun)

| Gorev | Dosya | Sure |
|-------|-------|------|
| VarBERT repo clone + model indirme | - | 2 saat |
| GenNm repo clone + CodeGemma-2B indirme | - (4090'a) | 4 saat |
| SymGen repo clone + setup | - (4090'a) | 2 saat |
| angr + miasm + z3 kurulum | requirements-deobf.txt | 1 saat |
| jadx + ilspycmd kurulum | - | 30 dk |
| Benchmark binary seti hazirlama (debug+strip) | tests/benchmark/ | 4 saat |
| Go, Rust, Swift toolchain kurulum dogrulama | - | 1 saat |

### Sprint 1: En Yuksek ROI Isler (1 hafta)

**Hedef: %25-30 -> %50-55 basari**

| # | Gorev | Etki | Sure | Oncelik |
|---|-------|------|------|---------|
| 1.1 | VarBERT entegrasyonu (c_namer.py 7. strateji) | +%15-20 | 3 gun | P0 |
| 1.2 | Error message pattern matching (string intelligence) | +%5-8 | 2 gun | P0 |
| 1.3 | Protocol handler naming (k_EMsg pattern) | +%3-5 | 1 gun | P0 |
| 1.4 | Go binary analyzer (kolay hedef) | %90+ Go | 2 gun | P1 |
| 1.5 | Benchmark harness kurulumu | - | 2 gun | P0 |
| 1.6 | Paralel processing (10 P-core) | 5-10x hiz | 2 gun | P1 |

**Sprint 1 sonu checkpoint:** Benchmark calistir, mevcut basari oranini ol.

### Sprint 2: ML Model Entegrasyonu (2 hafta)

**Hedef: %50-55 -> %70-80 basari**

| # | Gorev | Etki | Sure | Oncelik |
|---|-------|------|------|---------|
| 2.1 | GenNm 4090'da setup + inference server | +%10-15 | 3 gun | P0 |
| 2.2 | SymGen 4090'da setup + entegrasyon | +%10-15 | 3 gun | P0 |
| 2.3 | ML pipeline (confidence merge + conflict res) | - | 2 gun | P0 |
| 2.4 | Context2Name JS entegrasyonu | +%5-10 JS | 2 gun | P1 |
| 2.5 | SignatureDB 50K+ imza genisletme | +%10-15 | 4 gun | P1 |
| 2.6 | Struct fingerprint DB (50K+ struct) | +%5-8 | 3 gun | P1 |
| 2.7 | Rust binary analyzer | %85+ Rust | 3 gun | P2 |
| 2.8 | Java/Kotlin analyzer (jadx) | %90+ JVM | 2 gun | P2 |

**Sprint 2 sonu checkpoint:** Benchmark, ML model'lerin etkisini ol.

### Sprint 3: Advanced Teknikler (1 ay)

**Hedef: %70-80 -> %90-95+ basari**

| # | Gorev | Etki | Sure | Oncelik |
|---|-------|------|------|---------|
| 3.1 | CFF deflattening (JS + binary) | +%4-6 | 2 hafta | P0 |
| 3.2 | Opaque predicate elimination | +%3-5 | 4 gun | P1 |
| 3.3 | Gelismis string decryption (RC4/AES/stack) | +%5-8 | 5 gun | P0 |
| 3.4 | Assembly-level analysis (register + stack) | +%3-7 | 1 hafta | P1 |
| 3.5 | RTTI chain + class hierarchy | +%3-5 | 4 gun | P1 |
| 3.6 | Union/bitfield detection | +%1-2 | 2 gun | P2 |
| 3.7 | SIMD loop reconstruction | +%1-3 | 1 hafta | P2 |
| 3.8 | Swift binary analyzer | %85+ Swift | 3 gun | P2 |
| 3.9 | .NET analyzer (ILSpy) | %95+ .NET | 2 gun | P2 |
| 3.10 | VM devirtualization (VMProtect) | +%2-3 | 3 hafta | P3 |
| 3.11 | Cross-reference birlestirme (name_merger) | +%2-3 | 3 gun | P1 |
| 3.12 | Incremental analysis cache | Hiz | 3 gun | P1 |

### V1.0 Release Kriterleri

```
ZORUNLU:
[ ] Benchmark seti uzerinde ortalama %90+ accuracy
[ ] C/C++ binary: %85+ accuracy
[ ] JavaScript (obfuscated): %90+ accuracy
[ ] Go/Rust/Java: %85+ accuracy
[ ] .NET: %90+ accuracy
[ ] 427+ test PASS
[ ] Benchmark regression test PASS
[ ] Hic bir heuristik birbirini override etmiyor (conflict resolution calisiyor)

HEDEF (ideal):
[ ] C/C++ binary: %95+ accuracy (ML ile)
[ ] Her binary icin 10 dakika altinda analiz (paralel)
[ ] VMProtect 3.x deflattening calisiyor
[ ] CI/CD pipeline aktif
```

---

## Mimari Genel Bakis (V1.0 Hedef)

```
                         +------------------------------------------+
                         |         KARADUL v1.0 MASTER PLAN         |
                         +------------------------------------------+
                                           |
                    +----------------------------------------------+
                    |              Target Detection                 |
                    |  (C/C++, Go, Rust, Swift, JS, Java, .NET)    |
                    +----------------------------------------------+
                         |                    |
              +----------+----------+   +-----------+
              | Native Binary Path  |   |  JS Path  |
              +---------------------+   +-----------+
              |                     |   |           |
    +---------+--------+    +-------+   |  deobfusc |
    | Ghidra Analysis  |    | Multi |   |  source   |
    | - decompile      |    | Lang  |   |  match    |
    | - strings        |    | (Go,  |   |  npm fp   |
    | - call graph     |    | Rust, |   |  module   |
    | - types          |    | Swift |   |  split    |
    | - xrefs          |    | Java  |   +-----------+
    +---------+--------+    | .NET) |        |
              |             +-------+        |
              v                              v
    +-------------------+          +------------------+
    | Heuristik Layer   |          | JS Naming Layer  |
    | (10 stratejiler)  |          | (Context2Name    |
    | + String Intel    |          |  + structural    |
    | + SignatureDB     |          |  + LLM naming)   |
    | + Struct FP DB    |          +------------------+
    +-------------------+                    |
              |                              |
              v                              |
    +-------------------+                    |
    | ML Layer (local)  |                    |
    | VarBERT (MPS)     |                    |
    +-------------------+                    |
              |                              |
              v                              |
    +-------------------+                    |
    | ML Layer (remote) |                    |
    | GenNm + SymGen    |                    |
    | (RTX 4090)        |                    |
    +-------------------+                    |
              |                              |
              v                              v
    +------------------------------------------------+
    |           Confidence Merge Layer                |
    |  (cross-reference, conflict resolution,        |
    |   voting, semantic similarity)                 |
    +------------------------------------------------+
              |
              v
    +------------------------------------------------+
    |           Deobfuscation Layer                  |
    |  (CFF deflat, opaque pred, string decrypt,    |
    |   VM devirt, stack string reconstruct)         |
    +------------------------------------------------+
              |
              v
    +------------------------------------------------+
    |           Output Layer                          |
    |  - Named C files + naming_map.json             |
    |  - Reconstructed project (package.json, etc)   |
    |  - HTML/Markdown/JSON report                   |
    |  - Accuracy metrics                            |
    +------------------------------------------------+
```

---

## Risk Analizi

| Risk | Olasilik | Etki | Azaltma |
|------|----------|------|---------|
| VarBERT/GenNm model uyumsuzlugu | ORTA | YUKSEK | Fallback: sadece heuristik kullan |
| 4090 baglantisi kesilirse | DUSUK | ORTA | VarBERT local olarak calisir |
| VMProtect devirt basarisiz | YUKSEK | DUSUK | Toplam %2-3 kayip, ihmal edilebilir |
| Ghidra 577MB binary timeout | ORTA | ORTA | Adaptive timeout + chunking |
| Benchmark binary secimi bias | ORTA | ORTA | Farkli turde 10+ binary kullan |
| ML model false positive | ORTA | YUKSEK | Confidence threshold + heuristik override |

---

## Oncelik Siralama Ozeti

```
HEMEN YAP (Sprint 1, bu hafta):
  1. VarBERT entegrasyonu           -- En buyuk tek adim iyilestirme
  2. Benchmark harness              -- Olcemedigini iyilestiremezsin
  3. Error message string intel     -- Dusuk efor, yuksek etki
  4. Paralel processing             -- Her seyi hizlandirir

YAKIN VADE (Sprint 2, 2 hafta):
  5. GenNm + SymGen (4090)          -- ML'in tam gucu
  6. SignatureDB 50K+ genisletme    -- Bilinen kutuphane eslestirme
  7. Go/Rust/Java analyzer          -- Kolay hedefler, yuksek basari

ORTA VADE (Sprint 3, 1 ay):
  8. CFF deflattening               -- Obfuscated kod icin kritik
  9. Advanced string decryption     -- Gizli string'leri ac
  10. Assembly-level analysis       -- Decompiler bosaligini doldur
  11. Class hierarchy reconstruction -- C++ icin onemli

UZUN VADE (V1.0 sonrasi):
  12. VM devirtualization           -- Cok zor, marjinal etki
  13. SIMD reconstruction           -- Nicel
  14. Full CI/CD                    -- Proje buyuyunce gerekli
```

---

## Dosya Degisiklik Ozeti

### Yeni Dosyalar (23 dosya)

```
karadul/
  analyzers/
    assembly_analyzer.py           -- Assembly-level analiz
    go_binary.py                   -- Go binary analyzer
    swift_binary.py                -- Swift binary analyzer
    java_binary.py                 -- Java/Kotlin analyzer
    dotnet_binary.py               -- .NET/C# analyzer
    lib_fingerprinter.py           -- Otomatik kutuphane FP uretici
  reconstruction/
    ml_models.py                   -- ML model wrapper (VarBERT, GenNm, SymGen)
    symgen_namer.py                -- SymGen entegrasyonu
    register_tracker.py            -- Register allocation analizi
    stack_analyzer.py              -- Stack frame analizi
    simd_analyzer.py               -- SIMD/vectorization reconstruction
    string_intelligence.py         -- Merkezi string analiz
    name_merger.py                 -- Coklu kaynak isim birlestirme
    struct_fingerprint_db.py       -- Struct layout fingerprint DB
    class_hierarchy.py             -- Tam class tree reconstruction
    go_reconstructor.py            -- Go proje rebuild
    rust_reconstructor.py          -- Rust proje rebuild
    swift_reconstructor.py         -- Swift proje rebuild
    java_reconstructor.py          -- Java/Kotlin proje rebuild
    dotnet_reconstructor.py        -- .NET/C# proje rebuild
  deobfuscators/
    cff_deflattener.py             -- Binary CFF deflattening
    opaque_predicate.py            -- Opaque predicate elimination
    string_decryptor.py            -- Gelismis string decryption
    vm_devirtualizer.py            -- VM devirtualization
    vmprotect_handler_db.py        -- VMProtect handler mapping DB
  core/
    cache.py                       -- Analiz sonucu cache (SQLite)
  ghidra/scripts/
    asm_extractor.py               -- Raw assembly export

scripts/
  ml-inference-server.py           -- 4090'da FastAPI ML server
  build-signature-db.py            -- Toplu imza cikarma
  deflat-js.mjs                    -- JS CFF deflattening

tests/benchmark/
  conftest.py                      -- Benchmark fixture'lari
  test_benchmark_c.py             -- C benchmark
  test_benchmark_js.py            -- JS benchmark
  test_benchmark_multilang.py     -- Multi-lang benchmark
  benchmark_runner.py             -- Otomatik runner
  metrics.py                      -- Metrik hesaplama

requirements-ml.txt                -- ML bagimliliklari (torch, transformers)
requirements-deobf.txt             -- Deobfuscation bagimliliklari (angr, z3)
Makefile                           -- Build/test/bench komutlari
.github/workflows/test.yml        -- CI
.github/workflows/benchmark.yml   -- Benchmark CI
```

### Degistirilecek Mevcut Dosyalar (15 dosya)

```
karadul/config.py                  -- ML config, remote endpoint, cache config
karadul/core/target.py             -- Language enum genisletme
karadul/core/pipeline.py           -- Paralel execution, cache integration
karadul/core/chunked_processor.py  -- Buyuk binary iyilestirme
karadul/stages.py                  -- Dil-spesifik routing, worker pool
karadul/analyzers/__init__.py      -- Yeni analyzer register
karadul/analyzers/signature_db.py  -- 50K+ imza, SIMD patterns
karadul/analyzers/rust_binary.py   -- Genisletme
karadul/reconstruction/c_namer.py  -- VarBERT strateji, paralel
karadul/reconstruction/c_type_recoverer.py -- FP matching, union/bitfield
karadul/reconstruction/binary_name_extractor.py -- String intel, SymGen fallback
karadul/reconstruction/variable_renamer.py -- Context2Name fallback
karadul/deobfuscators/binary_deobfuscator.py -- String decryptor entegrasyonu
karadul/deobfuscators/deep_pipeline.py -- JS CFF ekleme
karadul/ghidra/headless.py         -- Adaptive timeout
```

---

## Son Soz

Bu plan, mevcut %25-30 basari oranini %95+ hedefine tasimak icin 10 farkli cepheden saldiri planlayan kapsamli bir strateji. Her adim bir oncekinin ustune insa eder. En buyuk atilimlar:

1. **ML modelleri** (%25-30 -> %60-80): Tek basina en buyuk etki
2. **String intelligence** (+%5-10): Dusuk efor, yuksek getiri
3. **SignatureDB genisletme** (+%10-15): Bilinen kutuphanelerin etkisi buyuk
4. **Deobfuscation** (+%5-10): Gizli bilgiyi aciga cikarir
5. **Multi-language** (yeni diller %85-95): Kapsami genisletir

Toplam tahmini sure: 6-8 hafta (tek developer, tam zamanli)
Sprint 1'den sonra ilk somut sonuclar gorulecek.

---

*Karadul v1.0 -- "Agimiz her yere uzanir."*
