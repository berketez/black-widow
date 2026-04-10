# Acik Kaynak RE Araclari Analizi -- Karadul Icin Ogrenimler

**Tarih:** 2026-03-23
**Hazirlayan:** Architect Agent
**Amac:** En iyi acik kaynak reverse engineering araclarinin kaynak kodlarini inceleyerek Karadul'a aktarilabilecek teknikleri belirlemek.

---

## YONETICI OZETI

7 arac incelendi. Karadul'un mevcut mimarisiyle en uyumlu ve en yuksek getiri/maliyet oranina sahip aktarimlar:

| Oncelik | Kaynak | Aktarim | Zorluk | Beklenen Etki |
|---------|--------|---------|--------|---------------|
| 1 | webcrack | Visitor-merge batch transform | Kolay | JS deobf 3-5x hizlanma |
| 2 | angr | CFGFast indirect jump resolution | Orta | Binary analiz dogrulugu artisi |
| 3 | Ghidra Decompiler | Rule-based iteratif simplification | Orta | Type recovery kalitesi artisi |
| 4 | Miasm | Expression simplification engine | Orta | CFF deflattening iyilesmesi |
| 5 | RetDec | Capstone2LlvmIr tiered translation | Zor | Multi-arch destek altyapisi |
| 6 | JADX | Plugin-based deobfuscation | Kolay | Java analyzer genisletilebilirlik |
| 7 | angr | Symbolic execution (Z3) | Zor | Opaque predicate cozumleme |

---

## 1. RetDec (Avast, C++)

**GitHub:** https://github.com/avast/retdec
**Star:** ~8.5k | **Dil:** C++ | **Tahmini Boyut:** ~500k satir (24 kutuphane + 8 arac)
**Durum:** "Limited maintenance mode" -- yeni ozellik eklenmez, PR kabul edilir

### Mimari Ozet

RetDec'in mimarisi 3 katmanli bir pipeline:

```
Binary --> [fileformat/loader] --> Bellek gorunumu
       --> [capstone2llvmir]   --> LLVM IR (ham)
       --> [bin2llvmir]        --> LLVM IR (optimize)
       --> [llvmir2hll]        --> C kodu
```

**En onemli tasarim karari:** Tum analizi LLVM IR uzerinde yapmak. Bu sayede:
- LLVM'in mevcut optimizasyon pass'lerini kullanabiliyorlar
- Yeni mimari ekleme = sadece instruction translation rutinleri yazma
- Dead code elimination, constant propagation gibi optimizasyonlar bedava geliyor

### Capstone2LlvmIr: Katmanli Ceviri Stratejisi

Bu RetDec'in en akilli tasarimi. Her assembly instruction'i 4 farkli seviyede cevirebiliyor:

1. **Tam Semantik Ceviri:** Instruction'in tam LLVM IR karsiligi (add, sub, load/store)
2. **Intrinsic Fonksiyon:** LLVM intrinsic'leri ile eslestirme (orn: bswap, ctlz)
3. **Pseudo Assembly:** `__asm_xxx()` seklinde fonksiyon cagrilarina ceviri
4. **Atlama:** Bazi instruction'lar kasitli olarak ihmal edilir

Bu yaklasim "her seyi mukemmel cevirmeye calisip basarisiz olmak" yerine "neyi iyi cevirebiliyorsak onu cevirelim, gerisini isaretle" diyor. Pragmatik ve dogru bir karar.

### bin2llvmir Optimizasyon Pass'leri

`src/bin2llvmir/optimizations/` altinda ~20 ozel LLVM pass var:
- Stack analizi (lokal degisken recovery)
- Value protection (LLVM'in agresif optimizasyonlarinin onemli veriyi silmesini engeller)
- Control flow reconstruction
- Dead code elimination
- x87 FPU stack optimizasyonu

### Type Recovery

RetDec'in type recovery'si limited:
- DWARF/PDB debug bilgisinden direkt okuma (varsa)
- RTTI ve vtable analizi ile C++ class hierarchy reconstruction
- Heuristic-based struct detection (alan erisim pattern'lerinden)

### Karadul'a Aktarilabilecek Teknik

**Katmanli Ceviri Stratejisi (Capstone2LlvmIr modeli):**
Karadul'un `c_type_recoverer.py`'si simdiden benzer bir yaklasim kullaniyor (confidence skorlari ile katmanli analiz). Ancak RetDec'in "ceviremedigini isaretle, gerisini temiz birak" yaklasimindan ogrenebiliriz. Su anda Karadul'un reconstruction modulleri basarisiz olunca sessizce atliyor -- bunun yerine explicit "unresolved marker" birakarak sonraki pass'lerin bu noktayi doldurmasi saglanabilir.

**Aktarma Zorlugu:** Zor (C++ -> Python, LLVM altyapisi gerekir)

---

## 2. Ghidra Decompiler (C++/Java)

**GitHub:** https://github.com/NationalSecurityAgency/ghidra
**Star:** ~55k+ | **Dil:** Java (GUI) + C++ (decompiler engine) | **Boyut:** Dev proje
**Durum:** Aktif gelistirme

### Mimari Ozet

Ghidra decompiler engine'i (SLEIGH + P-code) ayri bir C++ moduludur. Karadul zaten Ghidra'yi kullandigi icin asil soru "decompiler engine'ini DAHA IYI nasil kullaniriz?"

```
Machine Code --> SLEIGH --> Raw P-code
            --> Normalization
            --> SSA Construction (Heritage class)
            --> Type Propagation
            --> Control Flow Structuring
            --> Rule-based Simplification (iteratif)
            --> PrintC --> C output
```

### P-code ve SSA Form

P-code iki temel abstraksiyon uzerine kurulu:
- **PcodeOp:** Tek bir islem (CPUI_COPY, CPUI_INT_ADD, CPUI_LOAD, CPUI_STORE, CPUI_MULTIEQUAL)
- **Varnode:** Belirli bir storage lokasyonundaki deger

**Heritage sinifi** dominance-based SSA construction yapar:
1. Live range identification
2. Phi insertion (CPUI_MULTIEQUAL olarak)
3. Renaming (single-assignment property)

**LocationMap** ile incremental SSA: Sadece henuz heritaged olmamis adresleri isler. Bu buyuk binary'lerde cok onemli bir optimizasyon.

### Type Propagation Sistemi

Ghidra'nin type propagation'i BIDIRECTIONAL:
- Ileri yayilim: Instruction semantiginden tip cikarim (floating point instruction -> float)
- Geri yayilim: Kullanim noktasindan tanim noktasina
- Type locking: Yuksek guvenli tipler kilitlenir, daha fazla degismez
- typeOrder() ile precedence kurallari

Bu Karadul'un `c_type_recoverer.py`'sinden onemli olcude gelismis. Karadul simdiki haliyle tek yonlu calisir.

### Rule-Based Iteratif Simplification

Ghidra'nin en guclu ozelligi. Rule sistemi:
- Her Rule bir `applyOp()` metodu implement eder
- Pattern match yapar, 1 dondururse degisiklik yapilmistir
- Fixed-point'e ulasana kadar tekrar eder

Ornekler:
- `RuleEarlyRemoval`: Dead code elimination
- `RuleCollectTerms`: Cebirsel terim birlestirme
- `RulePiece2Zext`: Islem normalizasyonu
- `RuleOrMask`: Mask simplification

### Karadul'a Aktarilabilecek Teknikler

**1. Bidirectional Type Propagation:**
Karadul'un `c_type_recoverer.py`'si su anda tek yonlu calisiyor: kullanim pattern'lerinden tip cikarimi. Ghidra gibi geri yayilim da eklenmeli. Ornek: bir fonksiyonun return tipini bilen bir caller, o fonksiyonun icindekileri de tipleyebilir.

**2. Rule-Based Iteratif Simplification Framework:**
Karadul'un deobfuscation ve reconstruction modulleri simdiki haliyle sabit sirada tek gecis yapiyor. Ghidra'nin yaklasimiyla: her transform bir Rule olsun, fixed-point'e kadar tekrar etsin. Ozellikle CFF deflattening ve opaque predicate temizliginde buyuk fark yaratir.

**3. Ghidra Scripting API'yi Daha Iyi Kullanma:**
Karadul zaten analyzeHeadless kullaniyor ama Ghidra'nin decompiler API'sindeki type propagation, SSA form erisimi ve P-code sorgulamayi aktif kullanmiyor. Ghidra script'lerinde `DecompInterface.decompileFunction()` sonrasi `HighFunction` objesinden SSA grafi, tip bilgisi ve data flow'a dogrudan erisim var.

**Aktarma Zorlugu:** Orta (API kullanimi kolay, bidirectional propagation orta)

---

## 3. angr (Python)

**GitHub:** https://github.com/angr/angr
**Star:** ~8.6k | **Dil:** Python %97 | **Tahmini Boyut:** ~200k+ satir (49 repo)
**Durum:** Aktif gelistirme (UC Santa Barbara + Arizona State University)

### Mimari Ozet

angr'in mimarisi katmanli ve son derece moduler:

```
Binary --> CLE (loader) --> Project
       --> pyvex (VEX IR) veya pypcode (P-code IR)
       --> SimEngine (execution) + Claripy (constraint solving)
       --> Analyses (CFG, VSA, decompilation, ...)
       --> Knowledge Base (sonuc deposu)
```

### CFGFast Algoritmasi (En Guclu Ozellik)

4 asamali CFG recovery:

**Asama 1 - Giris Noktasi Tespiti:**
- Symbol table'dan export fonksiyonlari
- Prologue scanning (mimari-spesifik pattern matching)
- Exception handling metadata (.eh_frame)

**Asama 2 - Aktif Tarama:**
- Queue-based islem: her adres icin VEX/P-code'a lift et
- Basic block olustur, successor'lari cikar
- Yeni is ogeleri kuyruga ekle

**Asama 3 - Indirect Jump Resolution:**
```
JumpTableResolver:
  1. Pattern tanima: jmp [base + index*scale]
  2. Constant propagation ile base adres bulma
  3. Index range analizi ile tablo boyutu
  4. Bellekten target okuma
  5. Validation (executable + makul sinirlar)
```

**Asama 4 - Pasif Tarama:**
- Aktif taramanin kaciridigi calistirilabilir bolgeleri entropy ve pattern ile tespit

### Decompilation Pipeline

angr'in kendi decompiler'i var (Ghidra'dan bagimsiz):
1. **Clinic:** AIL (angr Intermediate Language) uzerinde SSA, constant propagation, variable recovery
2. **Structuring:** Phoenix/DREAM/SAILR algoritmalari ile dongu/kosul tespiti
3. **Code Generation:** C-like pseudocode + opsiyonel LLM isimlendirme

### Value Set Analysis (VSA) ve Z3 Entegrasyonu

- **Claripy:** Z3, CVC5, Boolector solver'lari icin unified frontend
- **SimState:** Her execution state ayri bellek modeli, register degerleri, constraint set'i
- **Symbolic forking:** Bir noktada N yol varsa N state olustur, hepsini paralel isle

### Karadul'a Aktarilabilecek Teknikler

**1. CFGFast Indirect Jump Resolution:**
Karadul'un binary analysis'i simdiki haliyle tamamen Ghidra'ya bagli. angr'in CFGFast algoritmasini TAMAMLAYICI olarak ekleyebiliriz. Ozellikle obfuscated binary'lerde Ghidra'nin bulamadigi jump table'lari angr bulabilir.

Uygulama yolu: angr'i pip dependency olarak ekle, `binary_intelligence.py`'de Ghidra sonrasi "second opinion" olarak angr CFGFast calistir, sonuclari merge et.

**2. Symbolic Execution ile Opaque Predicate Cozumleme:**
Karadul'un `opaque_predicate.py`'si simdiki haliyle heuristic-based. angr + Z3 ile:
```python
import angr, claripy
# Predicate'in her iki branch'ini symbolic olarak calistir
# Eger bir branch UNSAT ise -> opaque predicate
state = project.factory.blank_state()
if solver.eval(constraint) == [True]:  # Hep True -> dead branch
```

**3. LMDB-Backed Spilling:**
angr buyuk binary'lerde CFG node'larini LMDB'ye spill ediyor (LRU cache ile). Karadul'un workspace'i simdiki haliyle tamamen bellekte -- buyuk binary'lerde (100MB+) bu sorun olabilir.

**Aktarma Zorlugu:** Orta-Zor (Python-Python gecisi kolay, ancak angr agir bir dependency)

---

## 4. Miasm (CEA, Python)

**GitHub:** https://github.com/cea-sec/miasm
**Star:** ~3.8k | **Dil:** Python | **Tahmini Boyut:** ~100k satir
**Durum:** Aktif gelistirme (Fransiz CEA guvenlik ajansi)

### Mimari Ozet

```
Binary --> Disassembly Engine --> Architecture-specific ASM
       --> IR Lifter --> IRCFG (IRBlock'lar iceren CFG)
       --> Expression System (sembolik manipulasyon)
       --> JIT Engine (LLVM/GCC/Python backend) veya Symbolic Execution
```

### IR Tasarimi

Miasm'in IR'i hiyerarsik:
- **IRCFG:** IR seviyesinde control flow graph
- **IRBlock:** Bir lokasyondaki assignment bloklari dizisi
- **AssignBlock:** Paralel assignment'lar (instruction semantigi)
- **Expression System:** Tum degerleri temsil eden manipule edilebilir objeler

Expression tipleri:
| Tip | Anlam |
|-----|-------|
| ExprId | Register/degisken |
| ExprInt | Sabit |
| ExprMem | Bellek erisimi |
| ExprOp | Aritmetik/mantiksal islem |
| ExprCond | Kosullu ifade |
| ExprSlice | Bit extraction |
| ExprCompose | Concatenation |

### Expression Simplification (En Guclu Ozellik)

Miasm'in expression simplifier'i OTOMATIK DEOBFUSCATION yapar:
- Constant folding
- Algebraic simplification
- Dead expression elimination
- Pattern-based rewriting

Bu ozellik Karadul'un CFF deflattening'i icin cok degerli. Miasm sunu yapabiliyor:
```python
# Obfuscated: (x ^ 0xFF) ^ 0xFF  -->  x
# Miasm otomatik simplify eder
from miasm.expression.simplifications import expr_simp
result = expr_simp(obfuscated_expr)  # -> x
```

### JIT Emulation

3 backend: LLVM (en hizli), GCC (iyi), Python (tasinabilir)
- Shellcode emulasyonu
- Kismi binary emulasyonu
- Python callback'leri ile library function simulation

### Dynamic Symbolic Execution (DSE)

Concrete execution + symbolic analysis kombinasyonu:
- Gercek calisma trace'i ile symbolic analizi yonlendir
- Karmasik programlarda daha verimli path exploration

### Karadul'a Aktarilabilecek Teknikler

**1. Expression Simplification Engine:**
Karadul'un `cff_deflattener.py`'si simdiki haliyle regex-based pattern matching yapiyor. Miasm'in expression simplification yaklasimiyla:
- State transition graph'indaki degerleri sembolik olarak temsil et
- Otomatik simplify ile obfuscated state degisikliklerini coz
- Dead state'leri eliminate et

Uygulama: Miasm'in expression system'ini direkt import ederek kullanilabilir (Python-Python).

**2. JIT-Based Unpacking:**
Binary deobfuscation'da packed/encrypted code'u JIT ile calistirip dump etme. Miasm'in sandbox'u bunu guvenli yapabiliyor. Karadul'un `packed_binary.py` analyzer'ina eklenebilir.

**3. IR-Based Analysis Framework:**
Miasm'in IR'i Karadul'un C deobfuscation pipeline'ina eklenebilir. Ozellikle CFF deflattening'de ASM -> IR -> simplify -> reconstruct akisi cok daha saglam sonuc verir.

**Aktarma Zorlugu:** Orta (Python-Python, expression system direkt kullanilabilir)

---

## 5. JADX (Java)

**GitHub:** https://github.com/skylot/jadx
**Star:** ~47.7k | **Dil:** Java %92 | **Tahmini Boyut:** ~150k satir
**Durum:** Aktif gelistirme, v1.5.5 (Feb 2026)

### Mimari Ozet

```
APK/DEX --> jadx-core --> Dalvik bytecode parsing
         --> SSA construction
         --> Type inference (bidirectional)
         --> Control flow structuring
         --> Deobfuscation passes
         --> Java source code generation
```

4 ana modul:
- **jadx-core:** Decompilation engine
- **jadx-cli:** Komut satiri arayuzu
- **jadx-gui:** IDE-benzeri GUI
- **jadx-plugins:** Plugin sistemi

### SSA Form ve Type Inference

JADX SSA form kullaniyor. Type inference sistemi buyuk bir rewrite'dan gecmis (commit e026345):
- Bidirectional type propagation
- Type conflict resolution mekanizmasi
- Array type inference
- Method invoke uzerinde type variable resolution

4 decompilation modu:
1. **auto:** Optimal sonuc
2. **restructure:** Standart Java output
3. **simple:** Linear instructions + goto
4. **fallback:** Raw bytecode

### Deobfuscation Yetenekleri

- ProGuard/R8 mapping dosyasi destegi
- Konfigurasyon esasli isim kurtarma heuristic'leri
- Whitelist exclusions (standart Android kutuphaneleri)
- Coklu mapping formati destegi: Tiny, Enigma, ProGuard, SRG, TSRG, JAM, CSRG

### Karadul'a Aktarilabilecek Teknikler

**1. Plugin Sistemi Mimarisi:**
JADX'in plugin sistemi cok temiz. Karadul'un Java analyzer'i (`java_binary.py`) su anda monolitik. JADX benzeri bir plugin framework ile:
- Farkli obfuscator'lar icin farkli decoder plugin'leri
- Mapping dosyasi import/export
- Ucuncu parti extension'lar

**2. Multi-Format Mapping Destegi:**
JADX 8+ mapping formatini destekliyor. Karadul'un Java pipeline'i sadece ProGuard anlayabiliyor. Diger formatlari eklemek kolay ve degerli.

**3. Bidirectional Type Inference:**
JADX'in type inference algoritmasinin mantigi (bidirectional propagation + conflict resolution) Karadul'un hem Java hem C type recovery'sine uyarlanabilir.

**Aktarma Zorlugu:** Kolay-Orta (Java -> Python ceviri gerekir ama mantik basit)

---

## 6. webcrack (TypeScript)

**GitHub:** https://github.com/j4k0xb/webcrack
**Star:** ~2.5k | **Dil:** TypeScript %83 | **Tahmini Boyut:** ~15k satir
**Durum:** Aktif gelistirme

### Mimari Ozet

8 asamali pipeline:

```
JS Source --> Parse (Babel parser)
          --> Prepare (AST normalizasyonu)
          --> Deobfuscate (obfuscator.io pattern'leri)
          --> Unminify (~20 transform)
          --> Transpile (modern syntax restore)
          --> Post-process (JSX, mangling)
          --> Unpack (webpack/browserify module extraction)
          --> Generate (Babel generator)
```

### Bundle Detection Algoritmasi

Pattern matching ile webpack/browserify wrapper tespiti:
- webpack: IIFE icinde module factory map + `__webpack_require__` pattern
- browserify: `require` function definition + module registry object

`unpackAST()` fonksiyonu Bundle objesi dondurur:
```typescript
{
  type: 'webpack' | 'browserify',
  modules: Map<id, module>,
  index: string  // entry point
}
```

### AST Transform Sistemi (En Guclu Ozellik)

Her transform standart bir interface implement eder:
```typescript
{
  name: string,          // Logging icin
  tags: 'safe' | 'unsafe',  // Guvenlik siniflandirmasi
  scope?: boolean,       // Scope tracking gerekli mi
  run?: () => void,      // Setup
  visitor?: () => Visitor // Babel visitor
}
```

**3 uygulama stratejisi:**
1. `applyTransform()`: Tek senkron transform
2. `applyTransformAsync()`: Async (sandbox execution)
3. `applyTransforms()`: BATCH -- visitor merging ile N transform'u 1 AST traversal'da uygular

**Bu visitor-merge optimizasyonu kritik:** 20 transform varsa normalde 20 kez AST traverse edersin. webcrack hepsini birlestirir, 1 kez traverse eder. 3-5x hizlanma.

### Sandbox ile Guvenli Decoder Calistirma

Obfuscated kod icindeki string decoder fonksiyonlarini gercekten calistirmak gerekiyor (statik analiz yetmez). webcrack bunu `isolated-vm` (Node.js) veya `sandybox` (browser) ile guvenli yapiyoir.

### Karadul'a Aktarilabilecek Teknikler

**1. Visitor-Merge Batch Transform (EN YUKSEK ONCELIK):**
Karadul'un `deep_pipeline.py`'si ve `babel_pipeline.py`'si Babel transform'larini sirali calistiriyor. Her transform ayri bir AST traversal. webcrack'in visitor-merge teknigiyle:
- Birden fazla transform'u tek traversal'da birlestir
- `deep-deobfuscate.mjs`'deki 9 phase'i optimize et
- Tahmini hizlanma: 3-5x

Uygulama: `scripts/deep-deobfuscate.mjs`'i refactor et, transform'lari Babel visitor merge pattern'i ile birlestir.

**2. Transform Safety Tagging:**
webcrack her transform'a 'safe' veya 'unsafe' tag'i veriyor. Karadul'da bu yok -- tum transform'lar ayni guvenlik seviyesinde. Safety tagging ile:
- Oncelikle safe transform'lari calistir
- Kullanici tercihine gore unsafe'leri aktif et
- Hata durumunda safe noktaya geri don

**3. Sandbox Decoder Execution:**
Karadul'un string decryptor'u (`string_decryptor.py`) statik analiz yapiyor. webcrack gibi sandbox ile gercek calistirma eklenirse, dinamik string sifrelemelerini de cozebiliriz.

**Aktarma Zorlugu:** Kolay (TypeScript/JS -> JS, ayni ekosistem)

---

## 7. synchrony (TypeScript)

**GitHub:** https://github.com/relative/synchrony
**Star:** ~1.2k | **Dil:** TypeScript %97 | **Tahmini Boyut:** ~5k satir
**Durum:** Aktif, niches (sadece javascript-obfuscator/obfuscator.io)

### Mimari Ozet

```
Obfuscated JS --> Parse (AST)
              --> String Array Detection
              --> Decoder Detection
              --> Control Flow Deobfuscation
              --> Dead Code Removal
              --> Simplification
              --> .cleaned.js output
```

### AST Transformer'lar

Dahili transformer'lar:
- **Simplify:** Genel basitlestirme
- **jsc-controlflow:** javascript-obfuscator'un control flow obfuscation'ini coz
- **jsc-calculator:** Obfuscated aritmetik ifadeleri basitlestir
- **DeadCode:** Kullanilmayan kodu sil

### Karadul ile Overlap

Karadul zaten synchrony'yi wrapper olarak kullaniyor (`synchrony_wrapper.py`). Mevcut durum:
- synchrony CLI olarak cagriliyor
- Sonuc dosyasi okunuyor
- deep_pipeline onun sonucunu daha da isle

### Karadul'a Aktarilabilecek Teknikler

**1. Transformer API'sini Direkt Kullanma:**
synchrony'yi CLI olarak degil, Node.js API olarak cagirmak daha esnek:
```javascript
const { deobfuscate } = require('deobfuscator');
const result = deobfuscate(code, {
  ecmaVersion: 2022,
  transformers: ['Simplify', 'jsc-controlflow', 'jsc-calculator', 'DeadCode']
});
```
Bu sayede hangi transformer'larin uygulanacagi kontrol edilir, debug output alinir.

**2. Custom Transformer Yazma:**
synchrony ozel transformer eklemeye izin veriyor. Karadul'un tespit ettigi spesifik obfuscation pattern'leri icin ozel synchrony transformer'lari yazilabilir.

**Aktarma Zorlugu:** Kolay (zaten entegre, API gecismi yeterli)

---

## KARSILASTIRMALI ANALIZ

### Intermediate Representation (IR) Karsilastirmasi

| Arac | IR | Seviye | Karadul Uyumu |
|------|----|--------|---------------|
| RetDec | LLVM IR | Dusuk (makine kodu yakin) | Dusuk -- C++ altyapi gerekir |
| Ghidra | P-code + SSA | Orta | Yuksek -- zaten kullaniyoruz |
| angr | VEX IR + AIL | Dusuk + Yuksek | Orta -- Python, eklenebilir |
| Miasm | Ozel Expression IR | Orta | Yuksek -- Python, direkt import |
| JADX | SSA-based | Orta-Yuksek | Orta -- Java, mantik tasinabilir |

### Deobfuscation Yaklasim Karsilastirmasi

| Arac | Yaklasim | Guc | Zayiflik |
|------|----------|-----|----------|
| RetDec | LLVM pass'leri | Guclu optimizasyon | Sadece binary |
| Ghidra | Rule-based iteratif | Cok yonlu | Yavas, heavyweight |
| angr | Symbolic execution | Opaque predicate'ler | Bellek/zaman patlayabilir |
| Miasm | Expression simplification | Otomatik cebirsel basitlestirme | Sinirli mimari destek |
| webcrack | AST transform pipeline | Hizli, moduler | Sadece JS/obfuscator.io |
| synchrony | AST transform | javascript-obfuscator'a ozel | Dar kapsam |

### CFG Recovery Karsilastirmasi

| Arac | Yontem | Indirect Jump | Obfuscated Binary |
|------|--------|---------------|-------------------|
| RetDec | Statik | Sinirli | Zayif |
| Ghidra | Statik + heuristic | Orta | Orta |
| angr CFGFast | Statik + heuristic + spilling | Iyi (resolver sistemi) | Orta |
| angr CFGEmulated | Symbolic execution | Cok iyi | Iyi |
| Miasm | IR + symbolic | Iyi | Iyi |

---

## UYGULAMA YOLU HARITASI

### Faz 1: Hizli Kazanimlar (1-2 hafta)

1. **webcrack Visitor-Merge:** `deep-deobfuscate.mjs`'deki Babel transform'larini batch merge et
2. **synchrony API Gecisi:** CLI wrapper'dan Node.js API'ye gec
3. **JADX Mapping Format:** Java analyzer'a Enigma ve TSRG mapping destegi ekle

### Faz 2: Orta Vadeli Iyilestirmeler (2-4 hafta)

4. **Ghidra Bidirectional Type Propagation:** `c_type_recoverer.py`'ye geri yayilim ekle
5. **Ghidra Script Zenginlestirme:** HighFunction API'den SSA/type bilgisi cekmek icin yeni Ghidra script'leri
6. **webcrack Safety Tagging:** Transform'lara safe/unsafe tag sistemi ekle

### Faz 3: Ileri Seviye (4-8 hafta)

7. **Miasm Expression Simplification:** CFF deflattener'a sembolik expression engine entegre et
8. **angr CFGFast Entegrasyonu:** Binary analyzer'a "second opinion" CFG recovery ekle
9. **Sandbox Decoder Execution:** JS string decryptor'a isolated-vm sandbox ekle

### Faz 4: Arastirma (8+ hafta)

10. **angr Symbolic Execution:** Opaque predicate cozumleme icin Z3 entegrasyonu
11. **Miasm JIT Unpacking:** Packed binary'ler icin JIT-based unpacker
12. **Rule-Based Framework:** Ghidra-inspired iteratif simplification framework

---

## NOTLAR VE UYARILAR

### Dependency Riskleri
- **angr:** Agir dependency (~500MB+ pip install). Sadece gerekli modulleri import etmeyi dene.
- **Miasm:** Orta agirlikta. Expression system tek basina kullanilabilir.
- **JADX:** Java dependency. Karadul zaten JVM kullaniyor (Ghidra icin).

### Lisans Uyumu
| Arac | Lisans | Karadul Uyumu |
|------|--------|---------------|
| RetDec | MIT | Uyumlu |
| Ghidra | Apache 2.0 | Uyumlu |
| angr | BSD | Uyumlu |
| Miasm | GPLv2 | DIKKAT -- Karadul GPL olmayacaksa kod kopyalama yapma, sadece runtime dependency olarak kullan |
| JADX | Apache 2.0 | Uyumlu |
| webcrack | MIT | Uyumlu |
| synchrony | GPL-3.0 | DIKKAT -- Ayni durum, runtime dependency OK |

### RetDec "Limited Maintenance" Uyarisi
RetDec artik aktif gelistirilmiyor. Kod referans olarak degerli ama uzun vadeli dependency olarak riskli. Fikirlerini al, kodunu alma.
