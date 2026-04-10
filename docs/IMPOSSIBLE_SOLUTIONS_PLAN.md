# "Imkansiz" 3 Soruna Cozum Plani -- Mimari Tasarim Dokumani

**Tarih:** 2026-03-23
**Yazar:** Architect Agent
**Durum:** Onerilen
**Proje:** Karadul v1.0

---

## Ozet

Bu dokuman, tersine muhendislikte "cozulemez" kabul edilen 3 temel soruna somut, uygulanabilir cozum planlari sunar. Her cozum, Karadul'un mevcut mimari ve modul yapisi uzerine insa edilir -- sifirdan yeni sistemler yerine, mevcut pipeline'a entegre edilen genisletmeler.

| # | Sorun | Mevcut Basari | Hedef Basari | Tahmini Sure | Risk |
|---|-------|---------------|-------------|--------------|------|
| 1 | Compiler Inline Fonksiyonlar | ~%5 (sadece basit tespitler) | %35-50 | 4-5 hafta | ORTA |
| 2 | VM-Based Obfuscation | %0 (destek yok) | %40-60 | 6-8 hafta | YUKSEK |
| 3 | Minifier Sildigi Isimler | %60-70 (mevcut pipeline) | %85-90 | 3-4 hafta | DUSUK |

**Toplam Karadul etkisi:** Binary basari orani %25-30'dan %45-60'a, JS basari orani %60-70'den %85-90'a cikabilir.

---

## SORUN 1: Compiler Inline Fonksiyonlar

### 1.0 Problemin Ozeti

Compiler (GCC/Clang -O2/-O3) kucuk fonksiyonlari cagiran fonksiyonun icine gomer (inline). Kaynak kodda `abs()`, `strlen()`, `swap()`, `min()`, `max()` gibi yuzlerce fonksiyon var ama binary'de ayri fonksiyon olarak gorunmezler. Ghidra bu bolgeleri cagiran fonksiyonun parcasi olarak gosterir.

**Neden "imkansiz" deniliyor:** Inline edilen kod artik ayri bir fonksiyon degil, cagiran fonksiyonun instruction stream'ine karistirilmis. Geleneksel fonksiyon sinir tespiti islemez.

**Neden imkansiz DEGIL:** Inline edilen kod hala binary'de fiziksel olarak VAR. Compiler belirli, ogrenilebilir pattern'lerle inline eder. Ve en onemlisi: debug build'de ayri fonksiyon olarak duran kod, release build'de inline edilmis hali ile BinDiff karsilastirmasi yapilabilir.

### 1.1 Cozum Stratejisi: 4 Katmanli Yaklasim

```
Katman 1: Inline Pattern DB (Deterministik)
    |
    v
Katman 2: BinDiff Debug-Release Karsilastirma (Yakin-Deterministik)
    |
    v
Katman 3: Compiler Heuristic Emulation (Heuristik)
    |
    v
Katman 4: ML-Based Inline Detection (Ogrenme-Tabanli)
```

### 1.2 Katman 1: Inline Pattern DB

**Prensip:** Kucuk, sik kullanilan fonksiyonlarin inline edilmis hallerinin x86/ARM64 instruction pattern'lerini bir veritabaninda tut.

**Nasil calisir:**

```
Ornek: abs(x) inline pattern
---
Kaynak kod: if (x < 0) return -x; else return x;

x86-64 inline pattern'leri:
  Pattern A (cdq trick):
    mov eax, edi      ; x -> eax
    cdq                ; sign-extend eax -> edx:eax
    xor eax, edx      ; if negative, flip all bits
    sub eax, edx      ; if negative, add 1 (two's complement)

  Pattern B (cmov):
    mov eax, edi
    neg eax            ; eax = -x
    cmovs eax, edi     ; if result negative, use original

  Pattern C (branch):
    test edi, edi
    jns .positive
    neg edi
    .positive:
    mov eax, edi

ARM64 inline pattern'leri:
  Pattern A (csneg):
    cmp w0, #0
    csneg w0, w0, w0, ge

  Pattern B:
    eor w1, w0, w0, asr #31
    sub w0, w1, w0, asr #31
```

**DB Yapisi:**

```python
InlinePatternEntry = {
    "function_name": "abs",          # Orijinal fonksiyon ismi
    "source_signature": "int abs(int)",  # Kaynak imzasi
    "patterns": [
        {
            "arch": "x86_64",
            "compiler": "gcc",
            "opt_levels": ["O1", "O2", "O3"],
            "bytes_regex": r"89 f8 99 31 d0 29 d0",  # Pattern A
            "mnemonic_seq": ["mov", "cdq", "xor", "sub"],
            "confidence": 0.85,
        },
        {
            "arch": "x86_64",
            "compiler": "clang",
            "opt_levels": ["O2", "O3"],
            "bytes_regex": r"89 f8 f7 d8 0f 48 c7",  # Pattern B
            "mnemonic_seq": ["mov", "neg", "cmovs"],
            "confidence": 0.80,
        },
    ],
    "context_hints": [
        "Genellikle aritmetik hesaplamalarin icinde",
        "Sonuc her zaman >= 0",
    ],
}
```

**Ilk DB icerigi (150+ fonksiyon):**

| Kategori | Fonksiyonlar | Sayisi |
|----------|-------------|--------|
| Matematik | abs, min, max, clamp, sign, lerp, saturate | ~15 |
| String | strlen, strcmp, strcpy, memcpy, memset, memcmp | ~20 |
| Bit islemleri | popcount, clz, ctz, bswap, rotl, rotr | ~12 |
| Container | vector::push_back, vector::size, map::find | ~30 |
| Smart pointer | shared_ptr ctor/dtor, unique_ptr ctor/dtor/get | ~15 |
| Mutex/Lock | lock_guard ctor/dtor, mutex::lock/unlock | ~10 |
| I/O | fread inline, fwrite inline, putchar, getchar | ~10 |
| Allocator | operator new inline, operator delete inline | ~8 |
| Type traits | is_same, enable_if, decay (compile-time, bazen runtime kalinti) | ~10 |
| STL algorithm | find, count, accumulate (kisa versiyon) | ~20 |
| **Toplam** | | **~150** |

**DB nasil olusturulur (otomatik):**

```
1. libc/libstdc++ kaynak kodundan kucuk fonksiyonlari al
2. GCC -O0, -O1, -O2, -O3 ile derle
3. -O0 ciktisinda fonksiyon sinirlarini Ghidra ile belirle
4. -O2/-O3 ciktisinda ayni fonksiyonun inline halini BinDiff ile bul
5. Inline edilmis instruction sequence'i DB'ye kaydet
6. Farkli compiler versiyon ve arch icin tekrarla
```

**Dosya degisiklikleri:**
```
- karadul/reconstruction/inline_pattern_db.py      -- YENI: Pattern DB + matcher
- karadul/data/inline_patterns.json                -- YENI: 150+ pattern verisi
- scripts/build-inline-db.py                       -- YENI: Otomatik DB uretici
```

**Fizibilite:** YUKSEK -- deterministik pattern matching, false positive orani dusutulebilir.
**Tahmini etki:** Tum inline'larin %15-25'ini yakalar (en yaygin fonksiyonlar).
**Tahmini sure:** 1.5 hafta (DB olusturma 1 hafta, matcher 3 gun).
**Bagimliliklar:** capstone (mevcut), Ghidra (mevcut).

### 1.3 Katman 2: BinDiff Debug-Release Karsilastirma

**Prensip:** Ayni kaynak koddan uretilmis debug (-O0 -g) ve release (-O2) build'leri karsilastirildiginda, debug'da ayri fonksiyon olarak gorunen ama release'de inline edilen fonksiyonlar tespit edilir.

**Nasil calisir:**

```
Adim 1: Kullanici veya Karadul, hedef yazilimin kaynak kodunu bulur
        (acik kaynak veya reverse engineering ile elde edilen kaynak)

Adim 2: Debug build olustur: gcc -O0 -g source.c -o debug_binary
         Release build olustur: gcc -O2 source.c -o release_binary

Adim 3: BinDiff (veya diaphora) ile iki binary'yi karsilastir
        - debug binary: 500 fonksiyon (kucukler dahil)
        - release binary: 350 fonksiyon (150 tanesi inline olmus)
        - Eslesmeyen 150 fonksiyon = inline edilmis adaylar

Adim 4: Eslesen fonksiyonlarin icinde inline edilmisleri bul
        - Debug'daki caller_A 3 call instruction iceriyor
        - Release'daki caller_A'da bu call'lar yok ama kod daha uzun
        - Uzayan kisim = inline edilmis fonksiyon kodu

Adim 5: Inline mapping cikart
        {
          "caller": "process_data",     (release'de gorunen)
          "inlined": [
            {"name": "validate_input", "offset": 0x42, "size": 28},
            {"name": "clamp_value",    "offset": 0x8A, "size": 14},
          ]
        }
```

**Uygulama senaryolari:**

| Senaryo | Uygulanabilirlik | Not |
|---------|-----------------|-----|
| Acik kaynak proje (curl, nginx, ffmpeg) | IDEAL | Kaynak kodu mevcut, her iki build uretilir |
| Acik kaynak kutuphane kullanan kapali proje | IYI | Kutuphanenin debug build'i olusturulur, projenin release'i ile karsilastirilir |
| Tamamen kapali proje | SINIRLI | Sadece bilinen kutuphaneler icin (OpenSSL, zlib, vb.) |
| Onceki versiyon mevcut proje | IYI | Onceki debug build (beta/dev) varsa karsilastirma yapilir |

**Dosya degisiklikleri:**
```
- karadul/analyzers/bindiff_analyzer.py            -- YENI: BinDiff/Diaphora wrapper
- karadul/reconstruction/inline_mapper.py          -- YENI: Debug-release inline mapping
- scripts/build-debug-release.sh                   -- YENI: Acik kaynak projeler icin otomatik build
```

**Fizibilite:** YUKSEK (acik kaynak hedefler icin), ORTA (kapali kaynak icin sinirli).
**Tahmini etki:** Acik kaynak hedeflerde inline'larin %60-80'i. Kapali hedeflerde kutuphaneler icin %20-30.
**Tahmini sure:** 1 hafta.
**Bagimliliklar:** BinDiff veya Diaphora (IDA/Ghidra plugin), GCC/Clang.

### 1.4 Katman 3: Compiler Heuristic Emulation

**Prensip:** Compiler'in inline karari belirli kurallara dayanir. Bu kurallari emule ederek, binary'deki hangi bolgelerin inline oldugunu tahmin edebiliriz.

**Compiler inline karar kriterleri (GCC/Clang):**

```
1. Fonksiyon boyutu < threshold (GCC: ~40 instruction, Clang: ~75 instruction)
2. Tek cagri noktasi (sadece 1 yerden cagriliyor)
3. Static veya inline keyword
4. Template instantiation (C++)
5. -O2'de: hot fonksiyonlar inline, cold fonksiyonlar degil
6. -O3'te: agresif inline -- neredeyse her kucuk fonksiyon
7. LTO (Link Time Optimization): cross-module inline
```

**Binary'de inline tespiti icin ters heuristik:**

```
1. Fonksiyon icinde "baglantiksiz" kod blogu tespiti:
   - Bir basic block'un onceki ve sonraki bloklarla veri akisi zayif
   - Farkli register seti kullaniyor (fonksiyon boundary ipucu)
   - Kendi icinde tutarli ama caller ile baglantisi sadece birkas register

2. Tekrarlayan pattern:
   - Ayni instruction sequence birden fazla fonksiyonda gorunuyor
   - = muhtemelen ayni fonksiyonun farkli yerlerde inline edilmis hali

3. Calling convention ihlali:
   - Fonksiyon icinde "gereksiz" register save/restore
   - = inline edilmis fonksiyonun prolog/epilog kalintilarini

4. Dead code / unreachable code:
   - Inline edilen fonksiyonun kullanilmayan branch'leri
   - Compiler bunlari temizleyemediginde kalintilari gorunur
```

**Dosya degisiklikleri:**
```
- karadul/reconstruction/inline_heuristic.py       -- YENI: Compiler heuristic emulation
- karadul/reconstruction/c_namer.py                -- Inline heuristic strateji ekleme
```

**Fizibilite:** ORTA -- heuristik, false positive orani %15-25.
**Tahmini etki:** +%10-15 inline tespit.
**Tahmini sure:** 1 hafta.
**Bagimliliklar:** capstone (mevcut).

### 1.5 Katman 4: ML-Based Inline Detection

**Prensip:** Inline edilmis kod bloklarini taniyacak bir ML modeli egit.

**Egitim verisi nasil elde edilir:**

```
1. Acik kaynak projelerin (Linux kernel, ffmpeg, curl, nginx vb.)
   debug ve release build'lerini olustur
2. BinDiff ile inline mapping'leri cikar (Katman 2)
3. Her inline bolgesi icin feature vector cikar:
   - Basic block sayisi
   - Instruction sayisi
   - Register kullanim pattern'i
   - Caller'daki pozisyonu (baslangic/orta/son)
   - Onceki ve sonraki instruction'larin opcode dizisi
   - Stack frame erisim pattern'i
   - Veri akisi grafigi ozellikleri

4. Etiketli veri seti:
   - Pozitif: inline edilmis kod bloklari (BinDiff'ten)
   - Negatif: inline edilmemis normal kod bloklari
```

**Model mimarisi:**

```
Secenekler:
A) Instruction2Vec + Binary Classifier
   - Her instruction'i vector'e cevir (Word2Vec benzeri)
   - Sequence'i LSTM/Transformer ile isle
   - Binary cikti: inline/degil
   - Boyut: ~5M parametre, Mac MPS'te calisir
   - Dogruluk tahmini: %70-80

B) GNN (Graph Neural Network) on CFG
   - Control flow graph'i girdi olarak al
   - Her node = basic block, edge = control flow
   - Node classification: her node "inline baslangiic/orta/son/degil"
   - Boyut: ~10M parametre
   - Dogruluk tahmini: %75-85

C) Fine-tuned CodeBERT
   - Ghidra decompile ciktisini tokenize et
   - Inline bolgeleri maskeleyerek span detection
   - Boyut: ~125M parametre, MPS'te calisir
   - Dogruluk tahmini: %80-85

Oneri: Asama A'da A secenegi (hizli, basit), Asama B'de C secenegi (daha dogrusu)
```

**Dosya degisiklikleri:**
```
- karadul/reconstruction/ml/inline_detector.py     -- YENI: ML model wrapper
- scripts/train-inline-detector.py                 -- YENI: Model egitim scripti
- scripts/generate-inline-dataset.py               -- YENI: Egitim verisi uretici
```

**Fizibilite:** ORTA-YUKSEK (veri toplama zaman alir ama teknik olarak mumkun).
**Tahmini etki:** +%15-25 inline tespit (diger katmanlarin bulamadiklari).
**Tahmini sure:** 2 hafta (veri toplama 1 hafta, model egitimi 1 hafta).
**Bagimliliklar:** PyTorch (mevcut requirements-ml.txt), egitim verisi.

### 1.6 Sorun 1 Birlesmis Tahmini

| Katman | Inline Tespit Orani | Confidence | Sure |
|--------|---------------------|------------|------|
| Pattern DB | %15-25 | 0.80-0.95 | 1.5 hafta |
| BinDiff | %60-80 (acik kaynak) / %20-30 (kapali) | 0.90-0.98 | 1 hafta |
| Heuristic | %10-15 | 0.50-0.70 | 1 hafta |
| ML-based | %15-25 | 0.65-0.85 | 2 hafta |
| **Birlesmis** | **%35-50 (genel ortalama)** | **0.60-0.90** | **4-5 hafta** |

**Ilk adim (yarin ne yapilir):**
1. `scripts/build-inline-db.py` scripti yaz: `abs`, `min`, `max`, `strlen`, `memcpy` icin GCC/Clang -O0/-O2 ciktilari uret
2. Mevcut `karadul/reconstruction/inline_extractor.py`'nin JS-odakli yapisini incele (bu dosya JS inline extraction, binary inline detection FARKLI)
3. `karadul/reconstruction/inline_pattern_db.py` modulu icin iskelet yaz
4. Curl veya coreutils icin debug+release build uret, BinDiff ile ilk inline mapping cikart

---

## SORUN 2: VM-Based Obfuscation (VMProtect/Themida)

### 2.0 Problemin Ozeti

VMProtect ve Themida gibi protector'lar, x86/ARM64 instruction'larini custom bytecode'a cevirir. Binary'de artik gercek CPU instruction'lari degil, bir VM interpreter ve custom opcode'lar var. Ghidra bu bytecode'u analiz edemez -- sadece VM interpreter'in kendisini gorur.

**Neden "imkansiz" deniliyor:** Custom VM, her build'de farkli opcode mapping kullanabilir (mutation). Handler'lar obfuscate edilmis. Ic ice VM (VM icinde VM, "ultra" mode) tespiti daha da zorlastirir.

**Neden imkansiz DEGIL:**
- VM handler'lar binary'de NATIVE CODE olarak duruyor -- analiz edilebilir
- VM bytecode binary'nin data section'inda -- okunabilir
- VM her instruction'i execute etmek ZORUNDA -- trace alinabilir
- Handler'lar sonunda CPU register/memory'yi degistiriyor -- semantik cikarilabilir
- Akademik literaturde 10+ basarili devirtualization calismasi var (NoVMP, vtil, VMPAttack, Mergen)

### 2.1 Cozum Stratejisi: 3 Asamali Yaklasim

```
Asama 1: Trace-Based Devirtualization (Dinamik)
    |  Unicorn/Qiling ile bytecode execute, her adimi kaydet
    |  Native instruction sequence'e geri cevir
    |
    v
Asama 2: Handler Semantic Extraction (Statik + Dinamik)
    |  VM dispatcher'dan handler table cikart
    |  Her handler'in semantigini analiz et (symbolic execution)
    |  Opcode -> native instruction mapping olustur
    |
    v
Asama 3: LLVM Lifting (Statik)
    |  VM bytecode -> Custom IR -> LLVM IR -> Optimize -> C
    |  En genel, en guclu -- ama en zor
```

### 2.2 Asama 1: Trace-Based Devirtualization

**Prensip:** VM interpreter'i emulate et, her step'te VM state'ini kaydet. Bu trace'den orijinal semantigi cikar.

**Nasil calisir:**

```
Adim 1: VM entry point tespiti
  - Pattern: pushad/pusha + jmp [vm_dispatcher] (VMProtect)
  - Pattern: context save + computed goto (Themida)
  - Mevcut binary_deobfuscator.py pattern tanima genisletilir

Adim 2: Unicorn Engine ile emulation
  - Binary'yi Unicorn'a yukle
  - VM entry'den baslat
  - Her instruction'da callback:
    - Register state kaydet
    - Memory write/read kaydet
    - Branch target kaydet
  - VM exit'e kadar devam et

Adim 3: Trace filtreleme
  - VM interpreter overhead'i ayikla (dispatcher loop, handler dispatch)
  - Sadece "faydali" instruction'lari birak:
    - Memory'ye yazan instruction'lar
    - Register'i degistiren instruction'lar (VM overhead disinda)
    - External API cagrilari

Adim 4: Native instruction reconstruction
  - Filtrelenmis trace'den x86 instruction sequence olustur
  - Data flow analysis ile gereksiz ara register'lari temizle
  - Basic block'lara bol, CFG olustur

Ornek:
  VM trace (10,000 instruction) -> Filtrele -> Native trace (200 instruction)
  200 instruction: fonksiyonun gercek semantigi
```

**Sinirliliklar:**
- Sadece calistirilan path'i gorur (coverage sorunu)
- Farkli input'larla birden fazla trace gerekli
- Self-modifying VM bytecode varsa her calistirmada farkli olabilir

**Coverage sorunu cozumu:**

```
1. Forced execution: Her branch'in HER iki yonunu de calistir
   - Branch'a geldiginde state'i fork et
   - Iki kopyayi paralel emulate et
   - Merge: iki path'in union'u = tam coverage

2. Symbolic inputs: Concolic execution
   - Bazi register/memory degerleri sembolik
   - Z3 ile her branch icin satisfying input uret
   - Her path'i concrete olarak calistir

3. Iterative trace:
   - Ilk calistirma: default input -> Path A
   - Input mutate et -> yeni path'ler kesfet
   - 10-20 iterasyonda %80+ coverage
```

**Dosya degisiklikleri:**
```
- karadul/deobfuscators/vm_tracer.py               -- YENI: Unicorn-based VM tracer
- karadul/deobfuscators/trace_analyzer.py           -- YENI: Trace filtreleme + native reconstruction
- karadul/deobfuscators/vm_entry_detector.py        -- YENI: VM entry/exit pattern tespiti
```

**Fizibilite:** YUKSEK (Unicorn iyi dokumante, Python binding mevcut).
**Tahmini etki:** Trace alinan fonksiyonlarin %50-70'i icin calisir native sequence.
**Tahmini sure:** 2 hafta.
**Bagimliliklar:** unicorn-engine (pip install unicorn), qiling (opsiyonel).

### 2.3 Asama 2: Handler Semantic Extraction

**Prensip:** VM interpreter'in handler tablosunu cikar, her handler'in ne yaptigini anla. Boylece bytecode'u dogrudan interpret edebiliriz -- calistirmaya gerek kalmaz.

**Nasil calisir:**

```
Adim 1: VM Dispatcher tespiti
  VMProtect tipik dispatcher:
    vm_loop:
      movzx eax, byte ptr [esi]     ; opcode fetch (esi = bytecode pointer)
      inc esi                         ; advance bytecode pointer
      jmp dword ptr [handler_table + eax*4]  ; dispatch to handler

  Tespit:
  - "movzx + indirect jmp" pattern
  - Veya computed goto: "lea + jmp [reg + reg*scale]"

Adim 2: Handler table extraction
  - handler_table adresinden 256 (veya daha az) entry oku
  - Her entry bir handler fonksiyonunun adresi
  - Bazi entry'ler ayni adrese point edebilir (alias)
  - NULL entry'ler = kullanilmayan opcode

Adim 3: Handler semantik analizi
  Her handler icin:
  a) Static analysis: Ghidra ile decompile et
  b) Symbolic execution: angr ile girdi-cikti iliskisini cikar
  c) Pattern matching: bilinen handler pattern'leri ile eslesir

  Ornek handler'lar (VMProtect stack-based VM):

  vPush_imm32:     ; push immediate value onto VM stack
    mov eax, [esi]
    add esi, 4
    push eax       ; (VM stack'e push)
    jmp vm_loop

  vPop_reg:        ; pop from VM stack into VM register
    pop eax
    mov [ebp + ecx*4], eax  ; ebp = VM register file
    jmp vm_loop

  vAdd:            ; add top two VM stack elements
    pop eax
    pop ecx
    add eax, ecx
    push eax
    jmp vm_loop

  vNor:            ; NOR (VMProtect bazen tum logic'i NOR ile yapar)
    pop eax
    pop ecx
    not eax
    not ecx
    and eax, ecx
    push eax
    jmp vm_loop

Adim 4: Opcode -> Semantik mapping DB olustur
  {
    0x01: {"name": "vPush_imm32", "operands": ["imm32"], "effect": "push(imm32)"},
    0x02: {"name": "vPop_reg", "operands": ["reg_idx"], "effect": "reg[idx] = pop()"},
    0x03: {"name": "vAdd", "operands": [], "effect": "push(pop() + pop())"},
    0x04: {"name": "vNor", "operands": [], "effect": "push(~pop() & ~pop())"},
    ...
  }

Adim 5: Bytecode decompilation
  - Bytecode'u opcode mapping ile oku
  - VM stack machine instruction'larini register machine'e cevir (SSA form)
  - Dead code elimination, constant propagation
  - C kodu uret
```

**VMProtect versiyon farkliliklari:**

| Versiyon | Handler Table | Opcode Encoding | Zorluk |
|----------|---------------|-----------------|--------|
| VMProtect 2.x | Sabit table | Acik opcode byte | DUSUK |
| VMProtect 3.0-3.4 | XOR-encoded table | XOR'lanmis opcode | ORTA |
| VMProtect 3.5+ | Rolling key | Handler-dependent decode | YUKSEK |
| VMProtect Ultra | Nested VM | Handler'lar da VM'de | COK YUKSEK |

**Dosya degisiklikleri:**
```
- karadul/deobfuscators/vm_handler_extractor.py     -- YENI: Handler table + semantik analiz
- karadul/deobfuscators/vm_bytecode_decompiler.py   -- YENI: Bytecode -> C
- karadul/data/vmprotect_handlers.json              -- YENI: Bilinen handler pattern DB
- karadul/data/themida_handlers.json                -- YENI: Themida handler pattern DB
```

**Fizibilite:** ORTA -- handler analizi zorluk seviylesi VMProtect versiyonuna bagli.
**Tahmini etki:** VMProtect 2.x-3.4 icin %60-80, 3.5+ icin %30-50.
**Tahmini sure:** 3 hafta.
**Bagimliliklar:** angr (symbolic execution), z3-solver, capstone.

### 2.4 Asama 3: LLVM Lifting

**Prensip:** VM bytecode'u once custom IR'a, sonra LLVM IR'a cevir. LLVM'in optimizasyon pass'leri ile temizle, C'ye geri cevir.

**Pipeline:**

```
VM Bytecode
    |
    v
[VM Bytecode Parser]  -- Asama 2'deki mapping'i kullan
    |
    v
Custom IR (Stack-based -> SSA donusumu)
    |
    v
[LLVM IR Generator]
    |  - VM register'lari -> LLVM register allocation
    |  - VM stack ops -> LLVM alloca + load/store
    |  - VM flags -> LLVM icmp + select
    v
LLVM IR (unoptimized)
    |
    v
[LLVM Optimization Passes]
    |  - mem2reg (alloca -> SSA)
    |  - instcombine (instruction simplification)
    |  - simplifycfg (CFG cleanup)
    |  - dce (dead code elimination)
    |  - gvn (global value numbering)
    v
LLVM IR (optimized)
    |
    v
[LLVM -> C Backend / RetDec]
    |
    v
Readable C Code
```

**Mevcut araclar ve entegrasyon:**

```
- Mergen (GitHub): VMProtect LLVM lifting framework
  - vtil (Virtual Translation IL) kullanir
  - VMProtect 3.x icin iyi calisiyor
  - C++ yazilmis, Python binding yok ama output LLVM IR

- RetDec (Avast): LLVM IR -> C decompiler
  - LLVM IR alip okunabilir C uretir
  - Open source, pip install retdec-decompiler

- llvmlite (Python): LLVM IR olusturma
  - Python'dan dogrudan LLVM IR yaz
  - Karadul pipeline'a entegre edilebilir
```

**Dosya degisiklikleri:**
```
- karadul/deobfuscators/vm_llvm_lifter.py          -- YENI: Custom IR -> LLVM IR
- karadul/deobfuscators/vm_devirtualizer.py         -- YENI: Tum pipeline orchestration
```

**Fizibilite:** ORTA-DUSUK (en karmasik asama, Mergen entegrasyonu zorluk cikarabilir).
**Tahmini etki:** Dogrusu calistiginda %80-90 accuracy, ama coverage sinirli.
**Tahmini sure:** 3 hafta.
**Bagimliliklar:** llvmlite, retdec (opsiyonel), Mergen (reference).

### 2.5 Sorun 2 Birlesmis Tahmini

| Asama | Kapsam | Basari | Sure |
|-------|--------|--------|------|
| Trace-based | Tum VM-korunan fonksiyonlar | %50-70 (calistirilan path'ler) | 2 hafta |
| Handler extraction | VMProtect 2.x-3.4 | %60-80 | 3 hafta |
| LLVM lifting | VMProtect 3.x (Mergen ile) | %80-90 (kapsam dahilindekiler) | 3 hafta |
| **Birlesmis** | **Genel VMProtect/Themida** | **%40-60** | **6-8 hafta** |

**Neden %100 degil:**
- VMProtect Ultra (ic ice VM) hala cok zor
- Her VMProtect build farkli mutation uretir -- generic cozum sinirli
- Bazi handler'lar anti-analysis iceriyor (timing check, junk code)
- Ama %40-60 bile sektorde "cok iyi" kabul ediliyor

**Ilk adim (yarin ne yapilir):**
1. `pip install unicorn` ve basit x86 emulation testi
2. RE-ANTI-TECHNIQUES-RESEARCH.md'deki VMProtect tespit pattern'lerini `vm_entry_detector.py`'ye cevir
3. Basit bir VMProtect 2.x korunan CTF sample bul (GitHub CTF write-up'lardan)
4. Unicorn ile VM entry'den calistir, trace kaydet
5. Trace'deki VM overhead'i elle analiz et, filtreleme kurallari cikar

**Kritik karar noktasi (2. haftanin sonunda):**
- Trace-based yaklasim yeterli basari gosteriyorsa, Asama 2-3'e gecilir
- Gostermiyorsa, alternatif: Mergen'i dogrudan entegre et (C++ wrapper)

---

## SORUN 3: Minifier Sildigi Isimler

### 3.0 Problemin Ozeti

JavaScript minifier'lar (Terser, UglifyJS, esbuild) degisken ve fonksiyon isimlerini tek harfe indirir: `sendHttpRequest` -> `e`, `connectionPool` -> `t`. String literal'ler korunur ama identifier'lar gider. Bu kayip "geri donusumsuz" kabul edilir.

**Neden "imkansiz" deniliyor:** Isim bilgisi entropy olarak kaybolmus. `e` harfinden `sendHttpRequest` cikaramazsin -- bilgi yok.

**Neden imkansiz DEGIL:**
- Fonksiyonun YAPISI ayni: kac parametre, hangi API'leri cagiriyor, hangi string'leri kullaniyor
- NPM registry'de ORIJINAL kaynak kodu var -- 2M+ paket, hepsi acik kaynak
- AST (Abstract Syntax Tree) structural fingerprint ile eslestirme yapilabilir
- .d.ts (TypeScript definition) dosyalari isim bilgisi tasiyor
- Ayni fonksiyon baska projelerde kullaniliyor (cross-reference)
- LLM kodu okuyup semantik anlam cikarip isim onerebilir

**Karadul'un mevcut kapasitesi:**
- `source_matcher/ast_fingerprinter.py`: AST yapisal parmak izi
- `source_matcher/source_resolver.py`: NPM registry'den kaynak cozumleme
- `source_matcher/structural_matcher.py`: Yapisal eslestirme
- `naming/npm_fingerprinter.py`: NPM paket parmak izi
- `naming/llm_namer.py`: LLM-based isimlendirme
- Mevcut sonuc: %60-70 basari

### 3.1 Cozum Stratejisi: 5 Katmanli Yaklasim

```
Katman 1: Genisletilmis AST Structural Matching (Mevcut, iyilestirilecek)
    |
    v
Katman 2: TypeScript .d.ts Type-Driven Naming (Yeni)
    |
    v
Katman 3: Cross-Project Learning (Yeni)
    |
    v
Katman 4: LLM-Based Contextual Naming (Mevcut, iyilestirilecek)
    |
    v
Katman 5: Source Map Recovery (Yeni)
```

### 3.2 Katman 1: Genisletilmis AST Structural Matching

**Mevcut durum:** `ast_fingerprinter.py` fonksiyon yapisi fingerprint'i cikarir, `structural_matcher.py` NPM kaynaklari ile karsilastirir. Calisiyor ama kapsami dar.

**Iyilestirmeler:**

```
A) Daha hassas fingerprint:
   Mevcut: (node_count, depth, call_count)
   Yeni:   (node_count, depth, call_count,
            api_calls_hash, string_literals_hash,
            control_flow_pattern, param_count,
            return_type_hint, closure_depth)

   Ornek:
   Minified:  function e(t,n){return fetch(t,{method:"POST",body:JSON.stringify(n)})}
   Fingerprint: {
     params: 2,
     calls: ["fetch", "JSON.stringify"],
     strings: ["POST"],
     control_flow: "single_return",
     api_pattern: "fetch_post",
     depth: 3,
   }

   NPM kaynak: function sendPostRequest(url, data) { ... }
   Fingerprint: AYNI -> eslesti!

B) Fuzzy matching:
   - Tam eslesti yoksa benzerlik skoru hesapla
   - Jaccard benzerlik: ortak API cagrilari / tum API cagrilari
   - Edit distance: AST node siralamasi arasindaki fark
   - Threshold: 0.80 -> eslesti kabul

C) Registry genisletme:
   Mevcut: NPM top 1000 paket
   Hedef: NPM top 10,000 + kullanicinin package.json'undaki tum dependency tree

   Otomatik: package-lock.json'dan tam dependency agaci cikart,
             her paketin kaynak kodunu indir, fingerprint'le, DB'ye kaydet
```

**Dosya degisiklikleri:**
```
- karadul/reconstruction/source_matcher/ast_fingerprinter.py  -- Genisletme
- karadul/reconstruction/source_matcher/structural_matcher.py  -- Fuzzy matching
- scripts/build-npm-fingerprint-db.mjs                        -- YENI: Top 10K NPM fingerprint
```

**Fizibilite:** YUKSEK -- mevcut altyapi var, iyilestirme kapsamli.
**Tahmini etki:** Mevcut %60-70'i %70-78'e cikarir.
**Tahmini sure:** 1 hafta.
**Bagimliliklar:** Mevcut Babel + Node.js pipeline.

### 3.3 Katman 2: TypeScript .d.ts Type-Driven Naming

**Prensip:** Cogu NPM paketi TypeScript tanimlari (.d.ts dosyalari) ile gelir. Bu dosyalar fonksiyon isimleri, parametre isimleri ve tip bilgisi iceriyor -- minifier bunlara dokunmaz.

**Nasil calisir:**

```
Adim 1: Minified koddan modul tespiti
  - require('express') veya import from 'express' patternleri
  - Webpack __webpack_require__(42) -> modul ID eslesmesi
  - String literal ipuclari: "node_modules/express" path kalintilari

Adim 2: Tespit edilen modul icin .d.ts indir
  - NPM registry: @types/express, @types/lodash, vb.
  - DefinitelyTyped repo: 8000+ paket tanimlari
  - Paketin kendi icinde gomulu .d.ts (TypeScript native paketler)

Adim 3: .d.ts'deki export'lari minified kodla eslesir

  Ornek:
  express.d.ts:
    export function json(options?: express.OptionsJson): express.RequestHandler;
    export function urlencoded(options?: express.OptionsUrlencoded): express.RequestHandler;
    export interface Request { body: any; params: ParamsDictionary; query: ParsedQs; ... }

  Minified:
    var e = require("express");
    e.json({limit: "10mb"})     -> json (eslesti!)
    e.urlencoded({extended:true}) -> urlencoded (eslesti!)
    function(t,n,r) { t.body... } -> (request, response, next)

Adim 4: Parametre isimlendirme
  - .d.ts'deki parametre isimleri minified parametrelere map edilir
  - Pozisyon eslesmesi: 1. param -> 1. isim
  - Tip eslesmesi: string param = string kullaniliyorsa -> oncelik

Ornek sonuc:
  Oncesi: function(e,t,n){e.json(t.body)}
  Sonrasi: function(response,request,next){response.json(request.body)}
```

**Dosya degisiklikleri:**
```
- karadul/reconstruction/naming/dts_mapper.py       -- YENI: .d.ts isim eslestirme
- karadul/reconstruction/naming/dts_registry.py     -- YENI: .d.ts indirme + cache
- scripts/fetch-dts-definitions.mjs                 -- YENI: DefinitelyTyped scraper
```

**Fizibilite:** YUKSEK -- .d.ts dosyalari acik, parsing kolay (TypeScript compiler API).
**Tahmini etki:** NPM paket fonksiyonlarinin %40-60'i icin parametre + export isimleri.
**Tahmini sure:** 1 hafta.
**Bagimliliklar:** TypeScript compiler (npm install typescript).

**Mevcut calismalar ile uyum:** `docs/vscode-dts-mapping-report.md` mevcut -- VS Code .d.ts mapping zaten denenmis. Bu calisma genellestirilecek.

### 3.4 Katman 3: Cross-Project Learning

**Prensip:** Ayni NPM paketi binlerce projede kullaniliyor. Minified olmamis projelerdeki kullanim pattern'lerinden, minified projedeki isimleri cikar.

**Nasil calisir:**

```
Adim 1: GitHub'dan ornek projeler topla
  - Hedef paket kullanilan projeleri GitHub API ile bul
  - En az 100 farkli projeden ornek al
  - Her projede paketin fonksiyonlarinin nasil cagirildigini kaydet

Adim 2: Kullanim pattern'i cikar
  Ornek: lodash.debounce
  100 projede:
    - %80: const debouncedFn = _.debounce(handler, 300)
    - %15: const debounced = debounce(callback, delay)
    - %5:  diger varyasyonlar

  Pattern: debounce genellikle "debounced" + orijinal fonksiyon ismi ile adlandirilir

  Minified kodda:
    var e = t(n, 300)
    -> t = debounce (API cagri eslesmesi + sayi parametresi)
    -> e = "debouncedN" (kullanim pattern'inden)

Adim 3: Variable usage context pattern
  - Bir degisken nasil kullaniliyorsa, ismi belli olur:
    e.addEventListener("click", ...) -> e = element
    e.querySelector(".btn") -> e = container veya document
    e.send(JSON.stringify(data)) -> e = socket veya connection
    e.pipe(t) -> e = readableStream, t = writableStream

Adim 4: Cross-project isim consensus
  - 100 projede ayni kullanim pattern'ine verilen isimler toplanir
  - En sik kullanilan isim secilir (majority vote)
  - Confidence = (en sik / toplam) -- orn: 80/100 = 0.80
```

**Dosya degisiklikleri:**
```
- karadul/reconstruction/naming/cross_project_db.py -- YENI: GitHub cross-project mining
- karadul/reconstruction/naming/usage_pattern.py    -- YENI: Usage pattern extraction
- scripts/mine-github-patterns.py                   -- YENI: GitHub API ile pattern toplama
```

**Fizibilite:** ORTA-YUKSEK (GitHub API rate limit dikkat, ama veri zengin).
**Tahmini etki:** +%5-10 (ozellikle populer paketler icin).
**Tahmini sure:** 1 hafta.
**Bagimliliklar:** GitHub API token, mevcut AST fingerprinter.

### 3.5 Katman 4: Gelistirilmis LLM-Based Contextual Naming

**Mevcut durum:** `naming/llm_namer.py` ve `naming/llm_naming.py` mevcut. LLM'e kodu gonderip isim onerebiliyor ama genel amacli.

**Iyilestirmeler:**

```
A) Prompt engineering:
   Mevcut: "Bu fonksiyona isim ver"
   Yeni: Structured prompt with context:

   "Bu minified fonksiyonu analiz et:
    - Modul: express middleware icinde
    - Cagirdigi API'ler: res.json(), req.body, next()
    - String literal'ler: 'Content-Type', 'application/json'
    - Gelen parametreler: 3 (obje, obje, fonksiyon)
    - Cagiran fonksiyonlar: app.use(), router.post()

    Bu baglamda fonksiyon ve parametreleri icin isim oner.
    Format: {fn_name: '...', params: ['...', '...', '...']}"

B) Few-shot learning:
   - Pipeline'in onceki asamalarinda eslesen fonksiyonlari ornek olarak ver
   - "Ayni dosyadaki bu fonksiyon 'validateEmail' olarak eslesti.
     Hemen altindaki fonksiyon ne olabilir?"

C) Self-consistency:
   - Ayni fonksiyon icin 5 kere sor, farkli temperature
   - En cok tekrarlanan ismi sec (majority vote)
   - Confidence = tekrar sayisi / 5

D) Iterative refinement:
   - Ilk pass: tum fonksiyonlara isim ver
   - Ikinci pass: eslesen isimler baglam olarak geri besle
   - "Dosyada su isimler var: createServer, handleRequest,
     parseBody, sendResponse. Bu fonksiyon ne olabilir?"
```

**Dosya degisiklikleri:**
```
- karadul/reconstruction/naming/llm_namer.py       -- Structured prompt + few-shot
- karadul/reconstruction/naming/llm_naming.py      -- Self-consistency + iteration
```

**Fizibilite:** YUKSEK (mevcut altyapi var).
**Tahmini etki:** +%5-8 (ozellikle diger katmanlarin bulamadiklari icin).
**Tahmini sure:** 3 gun.
**Bagimliliklar:** LLM API erisiimi (mevcut config'de var).

### 3.6 Katman 5: Source Map Recovery

**Prensip:** Bazi production build'lerde source map kalintilari bulunabilir.

**Aranacak yerler:**

```
1. Dosya sonu yorumu:
   //# sourceMappingURL=main.js.map
   //# sourceMappingURL=data:application/json;base64,...

2. HTTP header (web uygulamalarda):
   SourceMap: /path/to/file.js.map
   X-SourceMap: /path/to/file.js.map

3. .map dosyasi ayni dizinde:
   main.min.js -> main.min.js.map (bazen silinmeyi unuturlar)

4. Webpack devtool kalintilari:
   "hidden-source-map" modu: .map dosyasi uretir ama referans koymaz
   Dosya adi pattern'i ile tahmin: bundle.js -> bundle.js.map

5. Partial source map:
   - eval() icinde source map fragment'leri
   - webpack:// protocol referanslari
   - //@ sourceURL= eski format kalintilari

6. CDN/archive sitelerinden:
   - Wayback Machine'de eski versiyon source map'leri olabilir
   - CDN'lerde .map dosyalari indekslenebilir
```

**Source map oldugunda:**

```
Source map JSON:
{
  "version": 3,
  "sources": ["src/utils/http.ts", "src/models/user.ts", ...],
  "names": ["sendHttpRequest", "connectionPool", "UserModel", ...],
  "mappings": "AAAA,SAAS..."
}

"names" array'i TUM orijinal identifier'lari icerir!
"mappings" VLQ-encoded pozisyon eslesmelerini icerir.

= Tam geri donum: minified -> orijinal her isim kurtarilir.
```

**Dosya degisiklikleri:**
```
- karadul/reconstruction/source_map_recovery.py     -- YENI: Source map arama + parse
- scripts/search-source-maps.mjs                    -- YENI: URL/CDN source map arama
```

**Fizibilite:** DUSUK-ORTA (source map olma ihtimali %10-20, ama oldugunda %100 basari).
**Tahmini etki:** Bulunan vakalarda %95+ isimlendirme. Genel ortalama +%2-4.
**Tahmini sure:** 3 gun.
**Bagimliliklar:** Yok (standart JSON parse).

### 3.7 Sorun 3 Birlesmis Tahmini

| Katman | Etki | Confidence | Sure |
|--------|------|------------|------|
| Genisletilmis AST matching | %70-78 (mevcut %60-70'ten) | 0.75-0.90 | 1 hafta |
| .d.ts type-driven naming | +%8-12 | 0.80-0.95 | 1 hafta |
| Cross-project learning | +%5-10 | 0.65-0.80 | 1 hafta |
| Gelistirilmis LLM naming | +%5-8 | 0.50-0.75 | 3 gun |
| Source map recovery | +%2-4 (ama %100 oldugunda) | 0.95+ | 3 gun |
| **Birlesmis** | **%85-90** | **0.70-0.90** | **3-4 hafta** |

**Ilk adim (yarin ne yapilir):**
1. Mevcut `ast_fingerprinter.py`'ye `api_calls_hash` ve `string_literals_hash` field'lari ekle
2. `structural_matcher.py`'ye Jaccard fuzzy matching ekle
3. Bir minified Express uygulamasi al, mevcut pipeline ile calistir, basari oranini olc
4. Ayni uygulamanin `@types/express` .d.ts'i ile eslestirme prototype'i yaz
5. Source map arama: test hedeflerinde `sourceMappingURL` grep'i yap

---

## UYGULAMA TAKVIMI

### Sprint 1 (Hafta 1-2): Temel Altyapi

| Gun | Gorev | Sorunda |
|-----|-------|---------|
| 1-2 | Inline Pattern DB: ilk 30 fonksiyon (abs, min, max, strlen, memcpy...) | Sorun 1 |
| 1-2 | AST fingerprint iyilestirmesi + fuzzy matching | Sorun 3 |
| 3-4 | BinDiff debug-release: curl icin ilk inline mapping | Sorun 1 |
| 3-4 | .d.ts mapper prototype: Express + Lodash | Sorun 3 |
| 5-6 | VM entry detector: VMProtect pattern'leri implementasyonu | Sorun 2 |
| 5-6 | Source map recovery modulu | Sorun 3 |
| 7-8 | Unicorn tracer: basit CTF sample ile ilk VM trace | Sorun 2 |
| 7-8 | LLM namer iyilestirmesi: structured prompt + self-consistency | Sorun 3 |
| 9-10 | Inline pattern DB'yi 100+ fonksiyona cikar | Sorun 1 |
| 9-10 | Cross-project learning: GitHub mining prototype | Sorun 3 |

### Sprint 2 (Hafta 3-4): Derinlestirme

| Gun | Gorev | Sorunda |
|-----|-------|---------|
| 11-14 | VM handler extractor: VMProtect 2.x/3.0-3.4 handler analizi | Sorun 2 |
| 11-12 | Compiler heuristic emulation | Sorun 1 |
| 13-14 | NPM top 10K fingerprint DB olusturma (arka planda calisir) | Sorun 3 |
| 15-18 | VM bytecode decompiler: handler mapping -> C cikti | Sorun 2 |
| 15-16 | Inline heuristic matcher'i c_namer'a entegre et | Sorun 1 |
| 17-18 | .d.ts registry: DefinitelyTyped entegrasyonu | Sorun 3 |
| 19-20 | Benchmark: tum iyilestirmeleri coreutils + Express app uzerinde olc | Hepsi |

### Sprint 3 (Hafta 5-6): Ileri Seviye

| Gun | Gorev | Sorunda |
|-----|-------|---------|
| 21-24 | LLVM lifting: VM bytecode -> LLVM IR (Mergen referansi ile) | Sorun 2 |
| 21-22 | ML inline detector: egitim verisi toplama | Sorun 1 |
| 23-24 | Cross-project DB: 100+ proje mining | Sorun 3 |
| 25-28 | ML inline detector: model egitimi ve entegrasyon | Sorun 1 |
| 25-28 | VM devirtualizer: VMProtect 3.5+ destegi | Sorun 2 |
| 29-30 | Full benchmark: 10 binary + 5 JS bundle uzerinde karar | Hepsi |

### Sprint 4 (Hafta 7-8): Stabilizasyon

| Gun | Gorev |
|-----|-------|
| 31-34 | Edge case'ler: yalanci pozitif azaltma, confidence kalibrasyonu |
| 35-38 | Pipeline entegrasyonu: tum yeni modullerin stages.py ile baglantisi |
| 39-40 | Dokumantasyon + benchmark raporu |

---

## MIMARI KARARLARI

### Karar 1: Yeni modul yerine mevcut modul genisletme

**Neden:** Karadul'un mevcut pipeline'i (`stages.py` + workspace modeli) iyi calisyor. Yeni bagimsiz moduller olusturmak pipeline entegrasyonunu zorlastirir. Bunun yerine:
- Sorun 1 -> `karadul/reconstruction/` altina inline_pattern_db.py, inline_mapper.py, inline_heuristic.py eklenir. `c_namer.py`'ye inline-aware strateji eklenir.
- Sorun 2 -> `karadul/deobfuscators/` altina vm_tracer.py, vm_handler_extractor.py, vm_bytecode_decompiler.py, vm_devirtualizer.py eklenir. `binary_deobfuscator.py` VM pipeline'i cagirir.
- Sorun 3 -> `karadul/reconstruction/naming/` altina dts_mapper.py, cross_project_db.py eklenir. `karadul/reconstruction/source_matcher/` genisletilir.

### Karar 2: Her katman bagimsiz calisabilir

Her katman kendi basina deger uretir. Bagimliliklari sekil:
- Katman 1 (Pattern DB) HIC bir sey gerektirmez -- dogrudan binary uzerinde calisir
- Katman 2 (BinDiff) kaynak kodu gerektirir -- opsiyonel
- Katman 3 (Heuristic) HIC bir sey gerektirmez
- Katman 4 (ML) egitilmis model gerektirir -- opsiyonel, yoksa atlanir

Bu sayede kismen uygulanmis halde bile deger uretir. Tum katmanlar hazir olmasini beklemeye gerek yok.

### Karar 3: Confidence-based merge

Tum katmanlar confidence degeri uretir. `name_merger.py` (zaten mevcut) tum kaynaklarin sonuclarini birlestirir:
- Ayni ismi veren birden fazla kaynak -> confidence artar
- Farkli isimler -> en yuksek confidence kazanir, ancak alternatifler yorum olarak saklanir
- Threshold altindaki sonuclar atilir (false positive azaltma)

### Karar 4: Incremental delivery

Hafta 1 sonunda her sorun icin en az 1 katman calisir durumda olacak. Tam cozum beklemeden erken deger gormek mumkun.

---

## RISK ANALIZI

| Risk | Olasilik | Etki | Mitigasyon |
|------|----------|------|-----------|
| VMProtect versyon degisikligi handler'lari bozar | YUKSEK | YUKSEK | Versiyon-spesifik handler DB, fallback olarak trace-based |
| Inline pattern DB false positive cok olur | ORTA | ORTA | Confidence threshold, context-aware filtering |
| NPM 10K fingerprint DB'si disk/RAM sorunu | ORTA | DUSUK | SQLite + lazy loading, sadece gerekli paketleri yukle |
| LLM API maliyeti yuksek olur (binlerce fonksiyon) | ORTA | DUSUK | Batch processing, sadece diger katmanlarin bulamadiklari icin LLM |
| Unicorn emulation performans sorunu | DUSUK | ORTA | Fonksiyon basina timeout, paralel emulation |
| ML inline detector yeterli egitim verisi bulanamaz | ORTA | ORTA | BinDiff ile otomatik veri uretimi, data augmentation |

---

## BASARI METRIKLERI

Her sorun icin olcum:

### Sorun 1 (Inline):
```
inline_detection_rate = correctly_detected_inlines / total_inlines_in_debug_build
false_positive_rate = wrong_inline_detections / total_detections
Hedef: detection_rate > 0.35, false_positive_rate < 0.15
```

### Sorun 2 (VM):
```
devirtualization_rate = successfully_devirtualized_functions / total_vm_protected_functions
semantic_accuracy = semantically_correct_decompilations / total_devirtualized
Hedef: devirtualization_rate > 0.40, semantic_accuracy > 0.70
```

### Sorun 3 (Minifier):
```
naming_accuracy = correctly_named_identifiers / total_identifiers
partial_accuracy = partially_correct_names / total_identifiers
Hedef: naming_accuracy > 0.50, (naming + partial) > 0.85
```

### Benchmark hedefleri:
| Hedef | Onceki | Sonrasi |
|-------|--------|---------|
| coreutils (C, inline) | %25-30 | %40-50 |
| curl (C, inline + lib) | %25-30 | %45-55 |
| VMProtect CTF sample | %0 | %40-60 |
| Express app (JS, minified) | %60-70 | %85-90 |
| Webpack bundle (JS, minified) | %55-65 | %80-88 |

---

## SONUC

Bu 3 sorun "imkansiz" degil -- sadece ZOR. Ve her biri icin akademik literaturde ve endistride calisir ornekler var. Karadul'un guclu yani: tum bu katmanlari TEK bir pipeline'da birlestirmek. Hicbir mevcut arac bu 3 sorunu birden adreslemiyorr.

**Stratejik avantaj:** Cok katmanli yaklasim. Her katman tek basina sinirli ama birlestikleirnde:
- Pattern DB + BinDiff + Heuristic + ML = inline'larin %35-50'si (sifirdan)
- Trace + Handler + LLVM = VM korumanin %40-60'i (sifirdan)
- AST + .d.ts + Cross-project + LLM + SourceMap = minified isimlerin %85-90'i (mevcut %60-70'den)

**Tek cumleyle:** Her katman tek basina "yetersiz" ama hepsi birlikte "imkansizi" "zorun" seviyesine indirir.
