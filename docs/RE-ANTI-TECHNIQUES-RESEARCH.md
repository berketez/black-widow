# Reverse Engineering Engelleyici Teknikler -- Kapsamli Arastirma Raporu

**Tarih:** 2026-03-23
**Amac:** Karadul v1.0 RE aracini guclendirmek icin tum RE engelleyici teknikleri, araclari ve algoritmalari belgeleme
**Yazar:** Security Expert Agent

---

## BOLUM 1: PAKETLEME / PACKING TEKNIKLERI

### 1.1 UPX (Ultimate Packer for eXecutables)

**Nasil Calisir:**
- Acik kaynakli, en yaygin packer. Section iceriklerini LZMA/NRV2B/UCL ile sikistirir.
- Calistirma aninda stub kodu bellekte decompression yapar, OEP'ye (Original Entry Point) ziplar.
- PE header'da "UPX0" (bos, RWX), "UPX1" (sikistirilmis veri) section adlari birakir.
- ELF'de de benzer pattern: PT_LOAD segment'leri sikistirilmis, stub ilk calisan kod.

**Tespit Yontemi:**
- Section adlari: "UPX0", "UPX1", "UPX2" string arama
- Magic bytes: UPX header'da `UPX!` magic (offset degisken ama genellikle dosya sonuna yakin)
- Entropy: UPX1 section'i 7.5+ entropy
- PE import table: sadece 1-3 import (LoadLibraryA, GetProcAddress)
- Entry point section'inin UPX1 olmasi

**Geri Alma Algoritmasi:**
1. `upx -d` komutu (en basit, %95 vakada calisir)
2. Modifiye edilmis UPX icin: UPX header'daki version/checksum byte'larini duzelt, sonra `upx -d`
3. Manual: LZMA/NRV2B decompression, IAT rebuild, OEP bulma (tail jump pattern)
4. Bellekten dump: Calistirilip, dekompresyon sonrasi process memory dump

**Karadul'da Mevcut mu:** EVET -- `packed_binary.py` UPX tespiti ve `upx -d` ile acma mevcut
**Oncelik:** P3 (zaten calisyor, iyilestirme dusuk oncelikli)

---

### 1.2 Themida / WinLicense (Oreans Technology)

**Nasil Calisir:**
- Ticari, ileri seviye protector. Birden fazla katman kullanir:
  - **Code mutation:** Orijinal x86 instruction'lari farkli ama esdeger instruction dizilerine donusturur
  - **VM protection:** Kritik kod bolumlerini ozel bytecode'a cevirir, runtime'da VM interpreter calistirir
  - **Anti-debug:** Ring0 kernel driver (Themida driver) ile kernel-level debug engelleme
  - **Anti-dump:** Bellekteki PE header'i bozar, section alignment degistirir
  - **Resource encryption:** PE resource'lari AES ile sifreler
  - **API wrapping:** Import'lari dolaysiz yapmak yerine runtime resolve + jmp stub kullanir
- WinLicense = Themida + lisans yonetim sistemi (hardware fingerprint, trial period)

**Tespit Yontemi:**
- Section adlari: ".themida", ".winlice", ".oreans" (bazen degistirilir)
- PE header anomalileri: section sayisi fazla, overlay data buyuk
- Import table: neredeyse bos (1-2 DLL), API'ler runtime resolve edilir
- Overlay: Dosya sonu PE header'dan sonra buyuk blok veri
- String scan: "Themida", "Oreans", "WinLicense", "THEMIDA_ANCHOR"
- YARA kurali: Themida VM dispatcher bytecode pattern'leri

**Geri Alma Algoritmasi:**
1. **OEP bulma:** Hardware breakpoint on `VirtualAlloc` -> dekompresyon izle -> son `jmp eax/ecx` OEP
2. **IAT reconstruct:** Scylla/Imports Fixer ile import table yeniden insa
3. **VM analysis (en zor kisim):**
   - VM handler table'i bul (genellikle buyuk switch/computed goto)
   - Her handler'in ne yaptigini tanimla (mov, add, push, pop, cmp, jmp...)
   - Bytecode'u x86'ya geri cevir (otomatize: Oreans UnVirtualizer, NoVMP)
4. **Anti-debug bypass:** ScyllaHide plugin (x64dbg) veya TitanHide (kernel driver)
5. **Dump + fix:** Process calisirken dump, PE header fix, section alignment duzelt

**Karadul'da Mevcut mu:** HAYIR
**Oncelik:** P1 -- Windows binary RE icin kritik, en cok karsilasilan ticari protector

---

### 1.3 VMProtect

**Nasil Calisir:**
- En guclu VM-tabanli protector. Cesitli VM mimarileri kullanir:
  - **RISC VM:** Basit register-based bytecode, her handler 1 islem yapar
  - **CISC VM:** Karmasik handler'lar, bir handler birden fazla x86 instruction'a karsilik gelir
  - **Mutation VM:** Her build'de farkli handler tablosu, farkli opcode mapping
  - **Ultra mode:** Ic ice VM (VM icinde VM), handler'lar da VM korumasinda
- **Handler obfuscation:** Her handler basinda/sonunda junk code, MBA, opaque predicate
- **Stack-based VM:** Cogu versiyon stack machine kullanir (push/pop bazli)
- **Context switch:** x86 context (registers) VM context'e donusturulur, cikista geri yuklenir

**Tespit Yontemi:**
- PE section: ".vmp0", ".vmp1", ".vmp2" section adlari
- Entry point: VMP section icinde
- Buyuk tek section (1MB+ sikistirilmis veri)
- String scan: "VMProtect begin", "VMProtect end" marker'lari (trial versiyonda)
- Import table: cok az, GetProcAddress agirlikli
- Code pattern: `push reg / pushfd / call vm_entry` tekrarlayan desen

**Geri Alma Algoritmasi:**
1. **VM handler tanimlama:** Dispatcher loop'u bul (genellikle `movzx eax, byte ptr [esi]; jmp [handler_table + eax*4]`)
2. **Handler clustering:** Semantik analiz ile handler'lari kategorize et (vPush, vPop, vAdd, vNor, vJmp...)
3. **Trace-based devirtualization:**
   - Bytecode uzerinden single-step trace al (unicorn/qiling ile)
   - Her VM instruction'i x86 karsligina cevir
   - Symbolic execution ile sabit degerleri propague et
4. **Otomatik araclar:**
   - **NoVMP:** Acik kaynak VMProtect devirtualizer (GitHub: can1357/NoVMP) -- eski VMProtect icin
   - **VMPAttack:** Symbolic execution tabanli (USENIX Security 2021 paper)
   - **vtil (Virtual-machine Translation Intermediate Language):** VMProtect lifting framework
5. **Pattern:** VMProtect v3.x icin handler tablosu genellikle XOR ile obfuscate -- XOR key runtime'da hesaplanir

**Karadul'da Mevcut mu:** HAYIR
**Oncelik:** P0 -- VM-based obfuscation en zor RE problemi, cozumu stratejik avantaj saglar

---

### 1.4 Enigma Protector

**Nasil Calisir:**
- Ticari protector + installer ozeligi. PE wrapper yaklasimiyla calisir.
- Orijinal PE'yi tamamen sifreler (AES-256), runtime'da bellekte acar.
- Virtual Box: Sanal dosya sistemi ve registry destegi (dosyalari PE icinde gomulu tutar).
- License system: RSA-2048 anahtar cifti ile hardware-locked lisanslama.
- Anti-debug: NtQueryInformationProcess, timing check, int2d, OutputDebugString tricks.

**Tespit Yontemi:**
- Overlay data: PE header'dan sonra buyuk sifreli blok
- Section adlari: ".enigma1", ".enigma2", ".enigma3"
- Import: sadece kernel32.dll ve advapi32.dll
- String: "Enigma protector", "enigma_fwk" pattern'leri
- EP (Entry Point): .enigma1 section icinde

**Geri Alma Algoritmasi:**
1. Calistirilip OEP bulunur (anti-debug bypass sonrasi)
2. Process dump + import table reconstruct (Scylla)
3. Virtual Box dosyalari: `enigma_virtual_box_unpacker.py` (acik kaynak) ile cikarilir
4. Alternatif: x64dbg + ScyllaHide + hardware BP on VirtualAlloc

**Karadul'da Mevcut mu:** HAYIR
**Oncelik:** P2 -- Themida/VMProtect kadar yaygin degil ama karsilasiliyor

---

### 1.5 ASPack / PECompact / MPRESS

**Nasil Calisir:**

**ASPack:**
- Eski ama hala kullanilan PE compressor. LZ-tabanli sikistirma.
- Section adlari: ".aspack", ".adata"
- Stub basit: decompress -> jmp OEP
- Anti-debug yok, sadece sikistirma.

**PECompact:**
- Moduler plugin mimarisi: sikistirma algoritmasi plugin olarak degistirilebilir
- Codec'ler: LZMA, aplib, JCalg1, aPLib
- Loader stub biraz daha karmasik: relocation processing, TLS callback
- Section: ".pec1", ".pec2"

**MPRESS:**
- Matcode Software tarafindan gelistirildi, artik bakimi yapilmiyor
- LZMA/LZMAT tabanli sikistirma
- Cok basit stub, hemen hemen UPX benzeri
- PE ve .NET binary destegi
- Section: ".MPRESS1", ".MPRESS2"

**Tespit Yontemi:**
- Section ad pattern'leri (yukaridakiler)
- ASPack: overlay'da ASPack magic header
- PECompact: "PEC2" string EP yakininda
- MPRESS: ".MPRESS" section adi
- Hepsinde: yuksek entropy + minimal import

**Geri Alma Algoritmasi:**
- ASPack: `unaspack` (eski ama islevsel), veya manual OEP + dump
- PECompact: `unpecompact` plugin (x64dbg), OEP genellikle `popad; jmp OEP`
- MPRESS: `upx -d` bazen calisir (benzer format); manual da basit
- Genel: Calistirilip, decompression sonrasi dump + IAT fix

**Karadul'da Mevcut mu:** HAYIR (UPX disinda)
**Oncelik:** P3 -- Eski protector'lar, nadiren karsilasilir

---

### 1.6 Obsidium

**Nasil Calisir:**
- Alman mensei ticari protector. Anti-debug odakli.
- Kod sifreleme + anti-debug + anti-dump + license management
- Ozellikle guclu anti-debug: Dr register manipulation, NtSetInformationThread (ThreadHideFromDebugger)
- Nanomites: INT3 (0xCC) instruction'larini orijinal kodun yerine koyar, exception handler gercek instruction'i calistirir
- Stolen bytes: EP'deki ilk birkac instruction silinir, baska yere tasinir

**Tespit Yontemi:**
- Section adlari: ".obsidium" (bazi versiyonlarda)
- PE anomalileri: SizeOfImage ile gercek dosya boyutu uyumsuz
- Overlay data mevcut
- Anti-debug katmanlarinin erken calisma belirtileri (NtSetInformationThread cagrisi)

**Geri Alma Algoritmasi:**
1. Anti-debug bypass: ScyllaHide, TitanHide
2. Nanomite restore: Exception handler'i hook'la, 0xCC -> orijinal instruction haritalamasi cikar
3. OEP: Stolen bytes'i exception handler'dan recover et, sonra dump
4. Import fix: Scylla + manual IAT analysis

**Karadul'da Mevcut mu:** HAYIR
**Oncelik:** P2

---

### 1.7 Code Virtualizer (Oreans -- Themida ile ayni firma)

**Nasil Calisir:**
- Themida'nin VM modulu tek basina satin alinabilir versiyonu
- Sadece VM protection (anti-debug, packing yok)
- Birden fazla VM mimarisi secenegi sunar: FISH, TIGER, SHARK, DOLPHIN, EAGLE
- Her mimari farkli register sayisi, opcode set ve handler yapisi kullanir
- Developer kaynak kodda `#pragma code_virtualizer_start/end` ile korumak istedigi bolgeleri isaretler

**Tespit Yontemi:**
- Themida ile benzer ama daha hafif: sadece VM bolumleri var
- ".cv" section adi (bazi versiyonlarda)
- Dispatcher pattern: computed goto / indirect branch table

**Geri Alma Algoritmasi:**
- Themida VM analysis ile ayni yaklasim
- Daha basit cunku anti-debug/packing katmanlari yok
- Oreans UnVirtualizer bazi versiyonlari cozer

**Karadul'da Mevcut mu:** HAYIR
**Oncelik:** P1 (Themida/VMProtect ile birlikte ele alinmali)

---

### 1.8 PyInstaller / Nuitka / cx_Freeze (Python)

**PyInstaller:**
- Python script'ini standalone executable'a paketler
- `.pyc` dosyalarini CArchive formatinda PE/ELF icine gomer
- `pyinstaller` magic: "MEI\014\013\012\013\016" (archive header)
- TOC (Table of Contents) ile icerik listelenir
- Python bytecode (`.pyc`) + runtime DLL'ler + import edilen kutuphaneler

**Nuitka:**
- Python'u gercek C'ye derler, sonra gcc/clang ile native binary uretir
- Bytecode yok, gercek makine kodu
- Ama Python semantigi korunur: string sabitler, modul yapisi, fonksiyon adlari
- `.nuitka-onefile` magic (onefile modunda)
- Data blob'u: compressed payload icinde Python stdlib + kullanici modulleri

**cx_Freeze:**
- PyInstaller'a benzer ama daha basit
- `__pycache__` dizini icerisindeki `.pyc` dosyalarini toplar
- Lib klasoru ile dagitir
- ZIP archive icinde moduller

**Tespit Yontemi:**
- PyInstaller: `MEI` magic, `_MEIPASS` string, `PyInstaller` import
- Nuitka: `NUITKA_ONEFILE_PAYLOAD` env var, C-compiled Python pattern'leri
- cx_Freeze: `cx_Freeze` string, `__startup__.py` dosyasi

**Geri Alma Algoritmasi:**
- **PyInstaller:** `pyinstxtractor.py` ile CArchive ici `.pyc` dosyalarini cikar -> `uncompyle6`/`decompyle3` ile Python kaynak koduna donustur
- **Nuitka:** Cok zor. C'ye derlenmis. Ghidra ile decompile, ancak Python semantigi kaybolmus. String analizi ve fonksiyon isimleri (genellikle korunur) ile anlamlandirma.
- **cx_Freeze:** ZIP extraction -> `.pyc` decompile

**Karadul'da Mevcut mu:** EVET -- `packed_binary.py` PyInstaller ve Nuitka tespiti mevcut, PyInstaller extraction calisiyor
**Oncelik:** P2 (Nuitka decompilation iyilestirmesi gerekli)

---

### 1.9 Electron ASAR

**Nasil Calisir:**
- Electron app'leri `app.asar` dosyasinda tum JS/HTML/CSS kodunu barindirir
- ASAR formati: JSON header (dosya listesi + offset/boyut) + concatenated data
- Sifreleme yok (varsayilan), sadece paketleme
- Bazi app'ler `asar` archive'i sifreleme (custom, AES genellikle) veya bytecode derleme (`bytenode` ile V8 snapshot) kullanir

**Tespit Yontemi:**
- Electron app bundle yapisi: `resources/app.asar` veya `resources/app/`
- ASAR magic: ilk 4 byte header boyutu (chromium pickle format)
- Electron framework: `Electron Framework.framework` (macOS), `electron.exe` (Windows)

**Geri Alma Algoritmasi:**
1. `npx asar extract app.asar ./extracted/` -- standart extraction
2. Sifrelenmis ASAR: Encryption key genellikle Electron main process'inde hardcoded -> string analizi
3. V8 bytecode (.jsc dosyalari): `v8-bytecode-disassembler`, `electron-inject` ile V8 snapshot debug
4. Source map varsa: `source-map` paketi ile orijinal kaynak koduna ulas

**Karadul'da Mevcut mu:** EVET -- `electron.py` analyzer mevcut, ASAR extraction calisiyor
**Oncelik:** P3 (temel islevsellik mevcut)

---

### 1.10 JavaScript Bundler'lar (esbuild, webpack, rollup, vite)

**Nasil Calisir:**

**webpack:**
- En yaygin bundler. Module federation, code splitting, tree shaking.
- Cikti: IIFE wrapper + `__webpack_require__` moduel sistemi + module ID map
- Obfuscation: Degisken minification (terser), modul ID'leri numara, scope hoisting
- Deger: Module boundary'leri genellikle korunur

**rollup:**
- ES module tabanli bundler. Tree shaking konusunda webpack'ten iyi.
- Cikti: Daha temiz, daha az boilerplate. ES module veya IIFE format.
- Moduel sinirlari bazen korunur (preserveModules), bazen tek dosya

**esbuild:**
- Go ile yazilmis, cok hizli. Minification + bundling.
- Cikti: webpack'e benzer ama daha temiz. `__require` yerine kendi moduel wrapper'i
- Daha az obfuscation: scope hoisting agresif degil

**vite:**
- Development: native ES modules (bundling yok). Production: rollup kullanir.
- Cikti: rollup ciktisi + HMR kodu (development modunda)
- Dev mode'da kaynak kodu neredeyse aynen korunur

**Bun single-file executable:**
- Bun runtime + uygulama kodunu tek binary'ye paketler
- Compile: `bun build --compile app.ts`
- Binary icinde: Bun runtime (Zig/C++) + bundled JS (minified)
- LZMA sikistirma, Bun header ile payload offset

**Tespit Yontemi:**
- webpack: `__webpack_require__`, `webpackChunk`, module ID map
- rollup: `rollup` banner comment, ES module syntax, `Object.defineProperty(exports...)`
- esbuild: `esbuild` banner, `__commonJS`, `__toModule`
- vite: `@vitejs` comment, rollup benzeri cikti
- Bun: ELF/Mach-O icinde Bun magic header, `BUN_RUNTIME` string

**Geri Alma Algoritmasi:**
- webpack: Module boundary tespiti (IIFE pattern, `__webpack_require__` cagrisi), webpack module ID -> dosya adi esleme, source map varsa kullan
- rollup/vite: Scope analizi ile fonksiyon gruplamalari, export/import chain takibi
- esbuild: webpack'e benzer ama daha basit wrapper, CommonJS pattern unwrap
- Bun: Binary'den payload cikarma (offset header'dan okunur), sonra standart JS deobfuscation
- **GENEL:** AST parse -> scope analysis -> module extraction -> deobfuscation -> source matching

**Karadul'da Mevcut mu:** EVET -- `javascript.py` analyzer + `deep_pipeline.py` + synchrony + babel pipeline webpack icin calisiyor. rollup/esbuild/vite icin kismen.
**Oncelik:** P2 (Bun binary, rollup/vite deobf iyilestirmesi)

---

## BOLUM 2: OBFUSCATION TEKNIKLERI

### 2.1 Control Flow Flattening (CFF)

**Nasil Calisir:**
- Orijinal control flow graph (CFG) parcalanir. Tum basic block'lar ayni seviyeye "duzlestirilir".
- Bir dispatcher (switch/case veya computed goto) hangi blogun sonra calisacagina karar verir.
- State degiskeni her blok sonunda guncellenir -> dispatcher sonraki state'e yonlendirir.
- Etki: CFG okunaksiz hale gelir, statik analiz zorlasir.

**Ornek:**
```c
// Orijinal:                    // CFF:
if (x > 0) {                   state = 0;
    a();                        while (1) {
} else {                            switch(state) {
    b();                                case 0: if (x > 0) state=1; else state=2; break;
}                                       case 1: a(); state=3; break;
c();                                    case 2: b(); state=3; break;
                                        case 3: c(); return;
                                    }
                                }
```

**Tespit Yontemi:**
- Pattern: `while(true) { switch(state_var) { ... } }` veya `for(;;) { switch ... }`
- CFG shape: Tek dispatcher node, tum basic block'lar dispatcher'a geri dallanir (star topology)
- State degiskeni: tek bir integer/long, her block sonunda degistirilir
- Yuksek cyclomatic complexity ama dusuk "gercek" karmasiklik

**Geri Alma Algoritmasi:**
1. Dispatcher node'u bul (en cok gelen edge'e sahip basic block)
2. State degiskenini tanimla (switch operand'i)
3. Her case icin: Baslangic state, bitis state(leri)ni cikar -> state transition graph
4. Topological sort: entry state'ten baslayip, transition graph'i sirala
5. Dispatcher + state degiskenini kaldir, block'lari dogrusal sirala
6. Kosula bagli gecisleri (if/else) yeniden olustur

**OLLVM varyanti:** OLLVM (Obfuscator-LLVM) CFF implementasyonu en yaygin. LLVM IR seviyesinde calisir, dolayisiyla her platform/arch icin gecerli.

**Karadul'da Mevcut mu:** EVET -- `cff_deflattener.py` mevcut (C ve JS icin)
**Oncelik:** P1 (mevcut implementasyon regex-tabanli, symbolic execution ile guclendirilmeli)

---

### 2.2 Bogus Control Flow (BCF)

**Nasil Calisir:**
- Gercek basic block'larin onune/arkasina sahte (bogus) basic block'lar eklenir.
- Opaque predicate ile gercek block'a dallanma garanti edilir.
- Bogus block'lar gercek koda benzer ama asla calistirilmaz (dead code).
- Etki: Fonksiyon boyutu 2-3x buyur, CFG'de sahte yollar olusur.

**Ornek:**
```c
// Orijinal:                    // BCF:
a();                            if (x*(x+1) % 2 == 0) { // opaque: always true
                                    a();
                                } else {
                                    fake_code_1(); // dead code
                                    fake_code_2();
                                }
```

**Tespit Yontemi:**
- Opaque predicate pattern'lerini tanimla (bilinen formuller)
- Dead code analizi: Ulasilamaz (unreachable) basic block'lar
- Code duplication: Ayni isi yapan birden fazla blok
- Branch profiling: Hic alinmayan branch'ler (dynamic analysis ile)

**Geri Alma Algoritmasi:**
1. Opaque predicate'lari tespit et (pattern matching + SMT solving)
2. Always-true branch'lerde else blogu sil
3. Always-false branch'lerde if blogu sil
4. Kalan dead code'u DCE (Dead Code Elimination) ile temizle

**Karadul'da Mevcut mu:** KISMEN -- `opaque_predicate.py` opaque predicate tespiti mevcut, ancak BCF-spesifik dead code elimination eksik
**Oncelik:** P1 (opaque predicate detector'u BCF ile birlestirilmeli)

---

### 2.3 Instruction Substitution

**Nasil Calisir:**
- Basit instruction'lar esdeger ama daha karmasik instruction dizileriyle degistirilir.
- Amac: Pattern matching tabanli analizi bozmak.

**Ornekler:**
```
a = b + c    -->    a = b - (-c)
a = b + c    -->    r = rand(); a = b + r; a = a + c; a = a - r;
a ^ b        -->    (a | b) & ~(a & b)
a + b        -->    (a ^ b) + 2*(a & b)
x = 0        -->    x = x ^ x
if (a == b)  -->    if ((a ^ b) == 0)
```

**Tespit Yontemi:**
- Peephole optimization pattern'leri: Birbiri ardindan gelen instruction'lar basitlestirilebilir mi?
- Compiler normalization: Standart optimizasyon pass'leri uygulandiginda kod kisalir mi?
- MBA (Mixed Boolean Arithmetic) pattern'leri: Tek bir aritmetik islem yapan karmasik ifade

**Geri Alma Algoritmasi:**
1. **Peephole simplification:** Bilinen substitution pattern'lerinin tersini uygula
2. **Algebraic simplification:** Cebirsel sadeleistirme kurallari (x ^ x = 0, x + 0 = x, x * 1 = x)
3. **Compiler reoptimization:** Kodu LLVM IR'a lift et, standard optimization pass'lerini calistir
4. **MBA solving:** (Bolum 2.8'de detayli)

**Karadul'da Mevcut mu:** HAYIR
**Oncelik:** P1 (peephole simplifier yazilmali)

---

### 2.4 String Encryption

**Nasil Calisir:**
- Kaynak koddaki string literal'ler sifrelenir, runtime'da cozulur.
- Yaygin yontemler:

| Yontem | Karmasiklik | Yayginlik |
|--------|-------------|-----------|
| XOR single-byte | Cok dusuk | Cok yaygin |
| XOR multi-byte key | Dusuk | Yaygin |
| Rolling XOR (key += delta) | Orta | Yaygin |
| RC4 | Orta | Orta |
| AES-128/256 | Yuksek | Ticari protector'larda |
| Custom algorithm | Degisken | Malware'de |
| Base64 + XOR | Dusuk | Script'lerde |
| Stack string (char by char) | Dusuk | C/C++ obf |
| Encrypted string table + index | Orta | Orta |

- Decryption fonksiyonu genellikle: `char* decrypt(int index)` veya `void decrypt(char* buf, int key)`
- String kullanilmadan hemen once decrypt cagrisi yapilir

**Tespit Yontemi:**
- Yuksek entropili data section'lar (7.0+ ama 7.99'dan dusuk)
- Tekrarlayan decryption fonksiyon cagrisi pattern'i (ayni fonksiyon onlarca kez cagrilir)
- XOR: `buf[i] ^= key` loop pattern'i
- RC4: S-box initialization pattern (256 byte permutasyon)
- Stack string: Ardisik `mov [rbp-N], imm8` instruction'lari
- Base64: `[A-Za-z0-9+/=]` uzun string + base64_decode cagrisi

**Geri Alma Algoritmasi:**
1. **Emulation-based:** Decryption fonksiyonunu emulate et (unicorn/qiling), sonucu yakala
2. **Pattern-based:** XOR key brute force (single byte: 256 deneme), frequency analysis
3. **Symbolic execution:** Decrypt fonksiyonunu angr ile sembolik calistir
4. **Dynamic:** Frida ile decrypt fonksiyonunu hook'la, return degerini logla
5. **Stack string:** Assembly'de ardisik mov'lari birlestir

**Karadul'da Mevcut mu:** EVET -- `string_decryptor.py` XOR (single, multi, rolling), RC4, Base64, stack string destegi mevcut
**Oncelik:** P1 (AES decryption, emulation-based generic decryptor eksik)

---

### 2.5 Opaque Predicates

**Nasil Calisir:**
- Derleme zamaninda degeri bilinen ama statik analizle belirlenemeyen kosullar.
- Compiler'in "bu her zaman true" diyemedigi ama matematiksel olarak her zaman true olan ifadeler.

**Bilinen formüller (always true):**
```
x * (x + 1) % 2 == 0           // Ardisik iki tamsayi carpimi her zaman cift
x^2 >= 0                        // Kare her zaman negatif olmaz
(x | 1) != 0                    // OR 1 hic 0 olamaz
7 * y^2 - 1 != x^2             // Number theory: 7y^2-1 hicbir zaman tam kare degil
x^2 + x ise her zaman cift     // x(x+1) cift
(x^3 - x) % 3 == 0             // Fermat's little theorem
```

**Bilinen formuller (always false):**
```
x * (x + 1) % 2 == 1
x^2 < 0
x^2 + y^2 + 1 == 0             // Pozitif tamsayilarda imkansiz
```

**Tespit Yontemi:**
1. **Pattern matching:** Bilinen formuller icin regex
2. **Z3/SMT solving:** Ifadeyi `forall x: expr == true` olarak dogrula
3. **Abstract interpretation:** Sayi araligi analizi ile kosul degerlendirme
4. **Dynamic:** Branch never-taken / always-taken profiling

**Geri Alma Algoritmasi:**
1. Tespit edilen opaque predicate'i sabit degeriyle degistir (true -> if body, false -> else body sil)
2. Dead code elimination

**Karadul'da Mevcut mu:** EVET -- `opaque_predicate.py` pattern matching + opsiyonel Z3 destegi
**Oncelik:** P2 (daha fazla pattern eklenmeli, Z3 entegrasyonu guclendirilmeli)

---

### 2.6 Dead Code Insertion

**Nasil Calisir:**
- Programa hicbir etkisi olmayan (side-effect-free) kod eklenir.
- Amac: Analiz zamanini artirmak, gercek mantigi gizlemek.
- Cesitler:
  - **Unreachable code:** Ulasilamayan fonksiyonlar/bloklar
  - **Semantic NOP:** Calisir ama sonucu kullanilmayan hesaplamalar
  - **Junk after return:** Return/goto'dan sonra eklenen kod
  - **Fake library calls:** Sonucu kullanilmayan API cagrialri

**Tespit Yontemi:**
- Liveness analysis: Degiskene atama yapilir ama hic okunmaz
- Reaching definitions: Tanimlanmis ama ulasilamayan degerler
- Side-effect analysis: Fonksiyon cagrisi sonucu kullanilmiyorsa ve side-effect yoksa dead
- CFG reachability: Entry point'ten ulasilamayan basic block'lar

**Geri Alma Algoritmasi:**
1. **DCE (Dead Code Elimination):** Standart compiler pass'i -- live variable analysis + unreachable code elimination
2. **Aggressive DCE:** Side-effect-free fonksiyon cagrlarini da sil
3. **Slice-based:** Program slicing ile sadece output'a etki eden kodu tut

**Karadul'da Mevcut mu:** HAYIR (opaque predicate ile isaretleme var ama genel DCE yok)
**Oncelik:** P2

---

### 2.7 Register Reassignment

**Nasil Calisir:**
- Degiskenler farkli register'lara rastgele atanir.
- Ayni fonksiyonun farkli derlemelerinde farkli register allocation.
- Amac: Fonksiyon signature'ina bakarak tanima (bindiff, function matching) zorlasmali.

**Tespit Yontemi:**
- Register reassignment tek basina tespit edilmez -- diger tekniklerle birlikte gelir
- Normalized form'a cevrildiginde gorulur (tum register adlari soyut isimlerle degistirilir)

**Geri Alma Algoritmasi:**
1. **Register normalization:** Tum register'lari kanonik formda yeniden adlandir (ilk kullanilan = r0, ikinci = r1, ...)
2. **SSA form:** Kodu SSA (Static Single Assignment) formuna cevir -- register ismi irrelevan olur
3. BinDiff zaten bunu yapiyor (graph isomorphism + semantic hashing)

**Karadul'da Mevcut mu:** HAYIR (dogrudan degil ama bindiff benzeri karsilastirma mevcut)
**Oncelik:** P3

---

### 2.8 Mixed Boolean Arithmetic (MBA)

**Nasil Calisir:**
- Aritmetik ve boolean islemleri karistirir. Basit bir ifadeyi cok karmasik hale getirir.
- Lineer MBA: `x + y = (x ^ y) + 2*(x & y)` (bu dogrulanabilir)
- Polinom MBA: `x + y = (2*(x | y)) - (x ^ y)` (bu da dogru)
- Karmasik MBA zincirleri: Birden fazla katman ic ice gelerek `x + 1` gibi basit bir islemi 50+ instruction'a donusturur.
- MBA ifadeleri SMT solver'lar icin bile zor olabilir (ozellikle non-linear MBA).

**Ornek:**
```c
// Basit: x + y
// MBA: ((x ^ y) + 2 * (x & y))
// Daha karmasik MBA:
// (((~x & y) | (x & ~y)) + 2 * ((~(~x | ~y)) | (~(x | y) & 0)) )
// En karmasik: Polinom MBA
// 39*x + 39*y - 41*(x^y) - 79*(x&y) + 2*(~x&y) + 78*(x|y)
```

**Tespit Yontemi:**
- Bir basic block'ta asiri fazla boolean islem (AND, OR, XOR, NOT) + aritmetik (ADD, SUB, MUL)
- Ara sonuclar hep kullanilir ama final sonuc basit bir deger
- Pattern: Cok fazla temp degisken, hepsi ayni scope'ta

**Geri Alma Algoritmasi:**
1. **Brute-force truth table:** 8-bit veya 16-bit inputlar icin tum kombinasyonlari dene, sonucu bilinen islemlere esle
2. **Pattern matching:** Bilinen MBA pattern'lerinin veritabani (SSPAM projesi)
3. **Simba (SIMplification of Boolean Arithmetic):** DIMVA 2021 paper -- MBA'yi polynomial form'a cevirip sadeleistir
4. **GAMBA:** RAID 2024 paper -- MBA'yi grafik siniflandirma ile cozen ML yaklasimi
5. **Algebraic simplification:** Bilinmeyen katsayilari sembolik cozme (lineer MBA icin Gaussian elimination)
6. **Synthesis-based:** Program synthesis ile esdeger basit ifadeyi bul

**Karadul'da Mevcut mu:** HAYIR
**Oncelik:** P0 -- VMProtect ve modern obfuscator'larin temel yapitasi, cozmek stratejik

---

### 2.9 Constant Unfolding

**Nasil Calisir:**
- Sabit degerlerin tek seferde kullanilmasi yerine parcalara bolunur ve runtime'da hesaplanir.
- Ornek: `key = 0xDEADBEEF` yerine `key = 0xDE000000; key |= 0x00AD0000; key |= 0x0000BE00; key |= 0x000000EF;`
- Daha ileri: Sabitler aritmetik islemlerle hesaplanir: `key = 17 * 3 + 42 - 7` (= 86, dogrudan yazilabilir ama obfuscated)

**Tespit Yontemi:**
- Ardisik assignment/OR/ADD islemleri ayni degiskene
- Sabit ifadeler (constant expressions) compile-time'da hesaplanabilir
- Data flow: Degisken sadece sabitlerden turetilmis

**Geri Alma Algoritmasi:**
1. **Constant folding/propagation:** Standart compiler pass'i -- sabit ifadeleri hesapla
2. **Forward substitution:** Sabit tanimlamalari kullanim noktasina propagate et
3. **Symbolic evaluation:** z3 veya basit evaluator ile ifadeyi hesapla

**Karadul'da Mevcut mu:** HAYIR (ama string decryptor icindeki XOR key tespiti bunu kismen yapiyor)
**Oncelik:** P2

---

### 2.10 VM-Based Obfuscation (Custom Bytecode Interpreter)

**Nasil Calisir:**
- Korunan kod, ozel bir sanal makine icin bytecode'a derlenir.
- Binary icine gomulu interpreter bu bytecode'u calistirir.
- VMProtect ve Themida bunu yapan ticari araclar, ama custom VM'ler de var.

**Mimari:**
```
[Orijinal x86 kodu]
        |
        v
[VM Compiler] --> [Custom bytecode]
        |
        v
[Binary icinde:]
  - VM Interpreter (x86 native kod)
  - Handler table (her opcode icin bir fonksiyon)
  - Bytecode blob (sifreli olabilir)
  - VM Context (sanal register'lar, sanal stack)
```

**VM Interpreter calisma dongusu:**
```c
while (1) {
    opcode = bytecode[vpc++];    // fetch
    handler_table[opcode]();     // dispatch
}
```

**Tespit Yontemi:**
- Interpreter loop pattern: Tekrarlayan fetch-decode-execute dongusu
- Handler table: Fonksiyon pointer dizisi (genellikle 50-256 eleman)
- Bytecode blob: Yuksek entropy ama executable degil (data section'da)
- VM context init: Buyuk struct allocation, register save/restore
- Computed/indirect branch: `jmp [table + index*8]` pattern'i cok yogun

**Geri Alma Algoritmasi:**
Detayli analiz Bolum 5.1'de.

**Karadul'da Mevcut mu:** HAYIR
**Oncelik:** P0 -- En kritik ve en zor RE sorunu

---

## BOLUM 3: ANTI-DEBUG / ANTI-TAMPER TEKNIKLERI

### 3.1 ptrace / IsDebuggerPresent

**Linux/macOS -- ptrace:**
```c
// Kendine ptrace ile attach -- ikinci bir debugger attach edemez
if (ptrace(PT_DENY_ATTACH, 0, 0, 0) == -1) {
    exit(1);  // Debugger algilandi
}
// Veya:
if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1) {
    exit(1);  // Zaten trace ediliyor = debugger var
}
```

**Windows -- IsDebuggerPresent:**
```c
if (IsDebuggerPresent()) { exit(1); }
// Veya dogrudan PEB kontrolu:
// NtQueryInformationProcess(ProcessDebugPort)
// PEB->BeingDebugged flag
// NtQueryInformationProcess(ProcessDebugObjectHandle)
```

**Tespit Yontemi:**
- Static: `ptrace`, `IsDebuggerPresent`, `NtQueryInformationProcess` import/cagrisi
- Decompiled kodda pattern: anti-debug sonrasi `exit`/`abort`/`_exit`

**Bypass:**
- **ptrace:** `LD_PRELOAD` ile ptrace'i NOP'la, veya debugger'da `ptrace` syscall'i intercept et
- **IsDebuggerPresent:** PEB->BeingDebugged byte'ini 0 yap, veya fonksiyonu hook'la
- **Genel:** ScyllaHide (x64dbg plugin) tum Windows anti-debug'lari otomatik bypass eder

**Karadul'da Mevcut mu:** KISMEN -- `binary_deobfuscator.py` ptrace ve IsDebuggerPresent pattern tespiti var, ama bypass yok (statik isaretleme)
**Oncelik:** P2 (Frida hook script'leri ile dinamik bypass eklenebilir)

---

### 3.2 Timing Checks (RDTSC, QueryPerformanceCounter)

**Nasil Calisir:**
- Kodun belirli bolumleri arasinda gecen sureyi olcer.
- Debugger altinda kod yavaslar -> sure esigi asilirsa debugger algilandi.
- x86: `RDTSC` (Read Time Stamp Counter) instruction'i, `RDTSCP` (serialized versiyon)
- Windows: `QueryPerformanceCounter()`, `GetTickCount()`, `timeGetTime()`
- macOS/Linux: `clock_gettime()`, `gettimeofday()`, `mach_absolute_time()`

**Ornek:**
```c
uint64_t t1 = __rdtsc();
sensitive_code();
uint64_t t2 = __rdtsc();
if (t2 - t1 > THRESHOLD) {  // Debugger yavassatti
    exit(1);
}
```

**Tespit Yontemi:**
- `RDTSC` / `RDTSCP` instruction pattern (0x0F31)
- API cagrisi: `QueryPerformanceCounter`, `GetTickCount`, `mach_absolute_time`
- Iki olcum arasi karsilastirma: `if (t2 - t1 > constant)`

**Bypass:**
- x64dbg: RDTSC emulation plugin (sabit deger dondurur)
- Frida: `QueryPerformanceCounter` hook, sahte deger dondur
- Kernel: TSC offsetting (hypervisor-level)
- Patch: Threshold degerini cok buyuk yap, veya karsilastirmayi NOP'la

**Karadul'da Mevcut mu:** KISMEN -- `binary_deobfuscator.py` timing-based pattern tespiti var
**Oncelik:** P2

---

### 3.3 Hardware Breakpoint Detection

**Nasil Calisir:**
- x86 Debug Register'lari (DR0-DR3) hardware breakpoint adreslerini tutar.
- DR7 kontrol register'i breakpoint tipini (execute/read/write) belirler.
- Anti-debug: Debug register'lari okur, sifir degilse debugger var.

**Ornek:**
```c
// Windows
CONTEXT ctx;
ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
GetThreadContext(GetCurrentThread(), &ctx);
if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3) {
    exit(1);  // Hardware breakpoint bulundu
}
```
```c
// Linux -- ptrace ile
// Veya: signal handler icinde ucontext'ten DR okuma
```

**Tespit Yontemi:**
- `GetThreadContext` + `CONTEXT_DEBUG_REGISTERS` pattern
- `DR0`-`DR7` register referanslari assembly'de
- Inline assembly ile `mov rax, dr0` cagrisi

**Bypass:**
- Debug register'lari exception handler icinde sifirla
- VEH (Vectored Exception Handler) ile DR read'i intercept et
- x64dbg: Anti-anti-debug plugin'leri DR okumalarini 0 dondurur

**Karadul'da Mevcut mu:** HAYIR
**Oncelik:** P2

---

### 3.4 Software Breakpoint Detection (0xCC Scan)

**Nasil Calisir:**
- Debugger software breakpoint koyunca orijinal instruction'in ilk byte'ini `0xCC` (INT3) ile degistirir.
- Anti-debug: Kendi kodunun belli bolumlerini okur, `0xCC` byte'i varsa breakpoint var.
- Alternatif: CRC/hash hesaplayip bilinen degerle karsilastirma (integrity check de olur)

**Ornek:**
```c
unsigned char* func_ptr = (unsigned char*)&my_function;
for (int i = 0; i < FUNC_SIZE; i++) {
    if (func_ptr[i] == 0xCC) {
        exit(1);  // Software breakpoint bulundu
    }
}
```

**Tespit Yontemi:**
- Kod segmentini okuyan memcmp/loop pattern'i
- `0xCC` ile karsilastirma
- Fonksiyon pointer'ini data olarak okuma

**Bypass:**
- Hardware breakpoint kullan (0xCC yazmaz)
- Scan fonksiyonunu hook'la, temiz bellek kopyasi dondur
- Single-step debugging (breakpoint koymadan)

**Karadul'da Mevcut mu:** HAYIR
**Oncelik:** P3

---

### 3.5 Parent Process Check

**Nasil Calisir:**
- Normal calistirildiginda parent process explorer.exe (Windows) veya shell (Linux/macOS).
- Debugger altinda parent process debugger olur.
- Parent process adini kontrol eder.

**Ornek:**
```c
// Linux
char path[256];
snprintf(path, sizeof(path), "/proc/%d/cmdline", getppid());
// Oku ve bilinen debugger isimlerini kontrol et

// Windows
DWORD ppid = ...; // NtQueryInformationProcess ile
// ppid'nin process adini kontrol et: "x64dbg.exe", "ollydbg.exe", "ida.exe" vs.
```

**Tespit Yontemi:**
- `getppid()`, `NtQueryInformationProcess(ProcessBasicInformation)` cagrisi
- `/proc/*/cmdline` veya `/proc/*/status` okuma
- `CreateToolhelp32Snapshot` + process enumeration

**Bypass:**
- Debugger'dan degil, arac uzerinden baslat (loader process araciligi ile)
- Parent PID donduren API'yi hook'la

**Karadul'da Mevcut mu:** KISMEN -- `binary_deobfuscator.py` `getppid` pattern tespiti var
**Oncelik:** P3

---

### 3.6 Exception-Based Anti-Debug

**Nasil Calisir:**
- Program bilerek exception olusturur (INT3, INT2D, divide by zero, access violation).
- Exception handler icinde kritik islemleri yapar.
- Debugger exception'i yakalarsa handler calismaz -> program yanlis yola girer.
- SEH (Structured Exception Handling) zincirine kod gizleme.

**Ornekler:**
```c
// INT2D -- debugger bu exception'i yutar
__try {
    __asm { int 0x2d }
    // Buraya gelirse debugger var
    exit(1);
} __except(EXCEPTION_EXECUTE_HANDLER) {
    // Normal calisma: debugger yok, exception handler buraya gelir
    real_code();
}
```

**Tespit Yontemi:**
- SEH handler kaydettirme + kasitli exception pattern
- `INT 0x2D`, `INT 0x03`, `UD2` instruction'lari fonksiyon icinde (normal kodda bulunmaz)
- Divide by zero setup: `mov ecx, 0; div ecx` kasitli desen
- `RaiseException`, `NtRaiseException` cagrisi

**Bypass:**
- Debugger'da exception'i pass etme (x64dbg: pass all exceptions ayari)
- Exception handler'i onceden analiz et, kritik kodu bul

**Karadul'da Mevcut mu:** HAYIR
**Oncelik:** P2

---

### 3.7 Self-Modifying Code (SMC)

**Nasil Calisir:**
- Program calisma aninda kendi kodunu degistirir.
- Bir kod bolgesi baska bir bolgedeki instruction'lari yazar/degistirir/decrypt eder.
- Katmanli olabilir: A kodu B'yi acar, B kodu C'yi acar, C gercek islemdir.
- Code page protection: `VirtualProtect(PAGE_EXECUTE_READWRITE)` veya `mprotect(PROT_EXEC|PROT_WRITE)` gerektirir.

**Ornek:**
```c
// Encrypted fonksiyon:
unsigned char encrypted_func[] = { 0x55, 0x12, 0x34, ... };

// Runtime'da decrypt:
void decrypt_and_run() {
    VirtualProtect(encrypted_func, size, PAGE_EXECUTE_READWRITE, &old);
    for (int i = 0; i < size; i++) {
        encrypted_func[i] ^= 0x42;  // XOR decrypt
    }
    ((void(*)())encrypted_func)();  // Calistir
}
```

**Tespit Yontemi:**
- `VirtualProtect(PAGE_EXECUTE_READWRITE)`, `mprotect(PROT_WRITE|PROT_EXEC)` cagrisi
- Kod segmentine write islemi (data olarak erisen pointer + loop)
- W^X violation pattern'i

**Bypass / Analiz:**
Detayli analiz Bolum 5.3'te.

**Karadul'da Mevcut mu:** HAYIR
**Oncelik:** P1

---

### 3.8 Integrity Checks (CRC, Hash)

**Nasil Calisir:**
- Program kendi kodunun/verilerinin hash'ini hesaplar, bilinen degerle karsilastirir.
- Patching algilamasi: Herhangi bir byte degisirse hash uyusmaz.
- Surekli kontrol: Thread olarak surekli hash hesaplayip dogrulamak.
- Nested: A fonksiyonu B fonksiyonunun hash'ini kontrol eder, B de A'nin hash'ini kontrol eder (circular integrity).

**Ornek:**
```c
uint32_t expected_crc = 0xDEADBEEF;
uint32_t actual_crc = crc32(code_start, code_end - code_start);
if (actual_crc != expected_crc) {
    // Kod degistirilmis!
    subtle_corruption(); // Hemen crash yerine ince bozma
}
```

**Tespit Yontemi:**
- CRC32/MD5/SHA hesaplama fonksiyonu cagrisi + sabit deger karsilastirma
- `crc32` tablosu (256 entry, her biri 4 byte) data section'da
- Kendi kod segmentini okuyan pointer aritmetigi
- Thread: `CreateThread` + sonsuz dongu icinde hash hesaplama

**Bypass:**
- Hash hesaplayan fonksiyonu NOP'la veya her zaman "dogru" dondur
- Hash icin kullanilan "beklenen deger"i patch'lenmis kodun hash'i ile degistir
- Memory breakpoint: hash hesaplama fonksiyonu tetiklendiginde, orijinal byte'lari geri koy, hash sonrasi tekrar patch'le (on-the-fly)

**Karadul'da Mevcut mu:** HAYIR
**Oncelik:** P1

---

### 3.9 Anti-VM Detection

**Nasil Calisir:**
- Malware ve protector'lar sandbox/VM ortamini tespit edip farkli davranir.
- Arastirmacilarin VM icinde analiz yapmalarini engellemek icin.

**Tespit Vektorleri:**
| Yontem | Detay |
|--------|-------|
| CPUID | Hypervisor brand string: "VMwareVMware", "KVMKVMKVM", "VBoxVBoxVBox" |
| MAC address | OUI prefix: VMware (00:0C:29, 00:50:56), VBox (08:00:27) |
| Registry/Files | VMware Tools, VBox Guest Additions dosya/servis/registry |
| Process list | vmtoolsd.exe, VBoxService.exe, qemu-ga |
| Hardware model | SMBIOS: "VMware Virtual Platform", "VirtualBox" |
| Timing | VM exit/entry gecikmeleri (CPUID instruction süresi) |
| Disk | SCSI: "VMware", "VBOX HARDDISK", disk boyutu < 60GB |
| Memory | Toplam RAM < 4GB (sandbox'lar genellikle az RAM verir) |
| Screen | Dusuk cozunurluk, az renk derinligi |
| User activity | Mouse hareket etmiyor, klavye giris yok (sandbox otomasyon) |

**Bypass:**
- **VMCloak:** VM artifact'lerini gizleyen araç (registry, dosya, MAC, CPUID)
- **Pafish bypass:** Her anti-VM kontrolunü tek tek patch'le
- **Bare-metal sandbox:** VM kullanmadan fiziksel makinede analiz (Cuckoo bare metal)
- **Hypervisor-level:** Nested VM ile CPUID sonuclarini spoof et

**Karadul'da Mevcut mu:** HAYIR
**Oncelik:** P3 (RE araci olarak anti-VM bypass oncelikli degil, daha cok malware analizi icin)

---

## BOLUM 4: RE ARACLARI VE KABILIYETLERI

### 4.1 IDA Pro + Hex-Rays Decompiler

| Ozellik | Detay |
|---------|-------|
| Tip | Ticari (lisans $2,500+) |
| Platform | Windows, Linux, macOS |
| Desteklenen Arch | x86, x64, ARM, ARM64, MIPS, PPC, SPARC, ve daha fazlasi |
| Decompiler | Hex-Rays: en iyi C pseudocode uretici |
| Plugin ekosistemi | En buyuk: 1000+ plugin (IDAPython, IDC) |
| Guc | Hemen hemen her binary'yi acacak analiz derinligi, FLIRT signature, type library, debugger entegrasyonu |
| Zayiflik | Pahali, kapali kaynak, script API bazen sinirli |
| Obfuscation | CFF/VMProtect icin plugin'ler var ama built-in destek yok |

**Karadul entegrasyonu:** Yok (Ghidra tercih edilmis, dogru karar -- acik kaynak)

### 4.2 Ghidra (NSA)

| Ozellik | Detay |
|---------|-------|
| Tip | Acik kaynak (Apache 2.0) |
| Platform | Cross-platform (Java) |
| Desteklenen Arch | x86, ARM, MIPS, PPC, SPARC, 68K, Z80, ve daha fazlasi |
| Decompiler | Pcode-tabanli, IDA'ya yakin kalite (bazi durumlarda daha iyi) |
| Plugin | Ghidra scripts (Java/Python), Extension framework |
| Guc | Ucretsiz, genisletilebilir, headless mode (batch analiz), Pcode IR |
| Zayiflik | UI yavasabilir buyuk binary'lerde, bazi edge case'lerde Hex-Rays'den geride |
| Obfuscation | Plugin'lerle: ghidra-deobfuscator, ghidra-vm-deobfuscator |

**Karadul entegrasyonu:** EVET -- `ghidra/` modulu, headless analiz, script'ler mevcut

### 4.3 Binary Ninja

| Ozellik | Detay |
|---------|-------|
| Tip | Ticari ($299 personal, $2499 commercial) |
| Platform | Cross-platform |
| Guc | Modern API, BNIL (Binary Ninja IL) -- cok katmanli IR, guzel Python API |
| Zayiflik | Decompiler Hex-Rays/Ghidra kadar olgun degil, daha az plugin |
| IR Katmanlari | Lifted IL -> Low Level IL -> Medium Level IL -> High Level IL |
| Obfuscation | BNIL uzerinde analysis pass yazma kolayligi |

**Karadul entegrasyonu:** Yok (gelecekte BNIL uzerinden obfuscation analizi dusunulebilir)

### 4.4 radare2 / rizin / Cutter

| Ozellik | Detay |
|---------|-------|
| Tip | Acik kaynak (LGPL) |
| radare2 | CLI-first RE framework. Cok guclu ama ogrenme egrisi dik. |
| rizin | radare2 fork'u, daha temiz API, Cutter GUI'nin backend'i |
| Cutter | rizin icin Qt-based GUI, Ghidra decompiler entegrasyonu |
| Guc | Cok hafif, scriptable, ELF/PE/Mach-O/raw, debug, emulation (ESIL) |
| Zayiflik | Decompiler yok (Ghidra/r2dec plugin gerekli), kararsiz olabilir |
| ESIL | Evaluable Strings Intermediate Language -- symbolic emulation |

**Karadul entegrasyonu:** EVET -- `config.py` icinde `radare2` tool path tanimli

### 4.5 angr (Symbolic Execution Framework)

| Ozellik | Detay |
|---------|-------|
| Tip | Acik kaynak (BSD) |
| Dil | Python |
| Motor | VEX IR (Valgrind'den) uzerine symbolic execution |
| Guc | Tam sembolik calistirma, constraint solving (Z3), path exploration, CFG recovery |
| Zayiflik | Bellek tuketimi yuksek, buyuk binary'lerde path explosion, yavas |
| Kullanim | CTF, otomatik exploit generation, anti-obfuscation |
| Alt projeler | claripy (constraint solving), cle (binary loading), archinfo (arch abstractions) |

**Obfuscation icin kullanim:**
- CFF: Sembolik calistirma ile state transition'lari coz
- Opaque predicate: Z3 ile always-true/false dogrulama
- VM deobfuscation: Bytecode trace + symbolic lifting
- String decryption: Decrypt fonksiyonunu sembolik calistirip sonucu al

**Karadul entegrasyonu:** HAYIR
**Oncelik:** P0 -- CFF deflattener ve VM deobfuscation icin kritik

### 4.6 Frida (Dynamic Instrumentation)

| Ozellik | Detay |
|---------|-------|
| Tip | Acik kaynak |
| Platform | Windows, macOS, Linux, iOS, Android |
| Guc | Runtime hooking, fonksiyon intercept, bellek okuma/yazma, JS API |
| Zayiflik | Anti-Frida teknikleri (Frida-specific string/module detection) |
| Kullanim | Anti-debug bypass, string decryption hook, API tracing |

**Karadul entegrasyonu:** EVET -- `frida/` modulu, session.py, collectors, hooks mevcut

### 4.7 x64dbg / OllyDbg

| Ozellik | Detay |
|---------|-------|
| x64dbg | Acik kaynak, Windows, x86/x64 debugger. Modern ve aktif gelistirme. |
| OllyDbg | Kaynagi kapali, sadece x86 (32-bit), artik gelistirilmiyor ama efsanevi. |
| Guc | Guclu plugin ekosistemi (ScyllaHide, Scylla, x64dbg scripts), trace |
| Zayiflik | Sadece Windows, GUI-only (headless yok) |
| Plugin'ler | ScyllaHide (anti-anti-debug), Scylla (import reconstruct), ret-sync |

**Karadul entegrasyonu:** Yok (Windows-only, ama Frida ile benzer isi platformlar arasi yapiyoruz)

### 4.8 Hopper Disassembler

| Ozellik | Detay |
|---------|-------|
| Tip | Ticari ($99) |
| Platform | macOS, Linux |
| Guc | Mach-O analizi icin iyi, Objective-C/Swift decompile, ucuz |
| Zayiflik | x86/ARM only, decompiler kalitesi IDA/Ghidra altinda |

**Karadul entegrasyonu:** Yok

### 4.9 RetDec (Retargetable Decompiler)

| Ozellik | Detay |
|---------|-------|
| Tip | Acik kaynak (Avast/NowSecure) |
| Guc | LLVM-tabanli, retargetable, online decompiler mevcut |
| Zayiflik | Cikti kalitesi Ghidra/IDA'nin altinda, buyuk binary'lerde yavas |
| Kullanim | Ikincil dogrulama, Ghidra'dan farkli perspektif |

**Karadul entegrasyonu:** Yok (Ghidra kullaniliyor)

### 4.10 JADX / JEB Decompiler (Java/Android)

| Ozellik | JADX | JEB |
|---------|------|-----|
| Tip | Acik kaynak | Ticari |
| Platform | Cross-platform | Cross-platform |
| Hedef | APK, DEX, JAR | APK, DEX, native ARM |
| Guc | Iyi Java decompile, kaynak goruntusu | En iyi Android decompiler, native code destegi |
| Zayiflik | ProGuard/R8 obf ile bazi zorluklar | Pahali |

**Karadul entegrasyonu:** KISMEN -- `java_binary.py` analyzer mevcut

### 4.11 dnSpy / ILSpy (.NET)

| Ozellik | dnSpy | ILSpy |
|---------|-------|-------|
| Tip | Acik kaynak (arsivlenmis) | Acik kaynak (aktif) |
| Platform | Windows | Cross-platform |
| Hedef | .NET Framework/Core/5+ | .NET Framework/Core/5+ |
| Guc | Debug + edit + recompile, muhtesem | Temiz UI, Roslyn decompiler |
| Zayiflik | Artik bakimi yapilmiyor | Debug ozeligi yok |

**Karadul entegrasyonu:** KISMEN -- `dotnet_binary.py` analyzer mevcut

### 4.12 uncompyle6 / decompyle3 (Python)

| Ozellik | Detay |
|---------|-------|
| uncompyle6 | Python 2.6-3.8 bytecode decompiler |
| decompyle3 | Python 3.7+ bytecode decompiler (uncompyle6 fork) |
| Guc | .pyc -> .py kaynak kodu, yuksek dogruluk |
| Zayiflik | Python 3.9+ destegi sinirli, pycdc alternatifi denenebilir |

**Karadul entegrasyonu:** EVET -- PyInstaller extraction sonrasi kullaniliyor

### 4.13 Miasm / Triton

| Ozellik | Miasm | Triton |
|---------|-------|--------|
| Tip | Acik kaynak (CEA) | Acik kaynak (Quarkslab) |
| Dil | Python | Python/C++ |
| Guc | Symbolic exec + IR lifting + JIT emulation | Dynamic symbolic execution + taint analysis |
| Kullanim | Obfuscation analysis, exploit dev | VM deobfuscation, opaque predicate solving |
| IR | Miasm IR (kendi formati) | Triton AST (SMT-ready) |

**Karadul entegrasyonu:** HAYIR
**Oncelik:** P1 (Triton ozellikle VM deobfuscation icin degerli)

### 4.14 LIEF / capstone / unicorn / Qiling

| Arac | Tip | Islem | Karadul'da |
|------|-----|-------|------------|
| LIEF | Binary parsing (PE/ELF/Mach-O modify) | Section ekleme/silme, import modify | Hayir (ama eklenebilir) |
| capstone | Disassembly engine | Multi-arch disassembler, Python binding | Hayir |
| unicorn | CPU emulation | Kod parcalarini emulate etme (sandbox) | Hayir |
| Qiling | Binary emulation | Full OS emulation (syscall, filesystem) | Hayir |
| keystone | Assembly engine | Instruction encoding (capstone'un tersi) | Hayir |

**Oncelik:** P0 -- unicorn/Qiling string decryption emulation icin kritik, capstone instruction analizi icin

---

## BOLUM 5: EN ZOR RE SORUNLARI VE COZUM STRATEJILERI

### 5.1 VM-Based Obfuscation Nasil Kirilir?

**Zorluk Seviyesi:** 10/10

**Problem:** Orijinal x86/ARM kodu custom bytecode'a donusturulmus. Bu bytecode'un ne anlama geldigini anlamak icin VM interpreter'i tam olarak tersine muhendislik yapmak gerekiyor.

**Sistematik Yaklasim:**

**Adim 1: VM Entry Point'i Bul**
- `call vm_entry` pattern: Register save (pushad/push all), context switch, dispatcher'a jump
- VM context struct'i: Sanal register'lar (genellikle 8-16 adet), vpc (virtual program counter), vsp (virtual stack pointer)

**Adim 2: Dispatcher ve Handler Table**
```
VM Dispatcher:
    fetch:  movzx eax, byte ptr [esi]     ; opcode fetch (esi = vpc)
            inc esi                         ; vpc++
    decode: lea ecx, [handler_table]       ; handler table base
            mov ecx, [ecx + eax*4]         ; handler address
    exec:   jmp ecx                        ; dispatch
```
- Handler table'i dump et (her entry bir fonksiyon adresi)
- Handler sayisi: Genellikle 30-150 arasi (basit: ~30, karmasik: 150+)

**Adim 3: Handler Semantik Analizi**
Her handler ne yapiyor? Kategoriler:
| Kategori | Ornekler | Nasil Tanimlanir |
|----------|----------|------------------|
| Stack ops | vPush, vPop | Stack pointer degisimi |
| Arithmetic | vAdd, vSub, vMul, vDiv | ALU islemleri |
| Logic | vAnd, vOr, vXor, vNor | Boolean islemleri |
| Memory | vLoad, vStore | Bellek okuma/yazma |
| Control | vJmp, vJcc, vCall, vRet | Instruction pointer degisimi |
| Context | vSaveReg, vLoadReg | x86 register save/restore |

**Adim 4: Trace + Lifting**
1. Unicorn ile bytecode uzerinden single-step trace al
2. Her adimda: hangi handler calisti, ne degisti (register, memory, stack)
3. Trace'i x86 instruction dizisine "lift" et
4. Symbolic execution ile sabit degerleri basitlestir

**Adim 5: Devirtualization**
- Lifted x86 kodunu LLVM IR'a cevir
- Optimization pass'leri calistir (dead code elimination, constant propagation, control flow simplification)
- Sonuc: Okunaklı C kodu (Ghidra/RetDec ile decompile)

**Otomatik Araclar:**
- **VMHunt (CCS 2018):** Execution trace tabanli, handler identification + semantik cikartma
- **VMAttack (USENIX Security 2021):** Symbolic execution + pattern matching
- **Syntia (USENIX Security 2017):** Program synthesis ile handler semantigi ogrenme
- **NoVMP:** VMProtect 1.x-3.x icin devirtualizer (sinirli)
- **vtil + NoVMP (can1357):** VMProtect lifting framework

**Karadul Stratejisi:**
- unicorn/Qiling ile trace engine yaz
- Handler tanimlama icin pattern library + ML classifier
- Lifted kodu LLVM IR veya Ghidra Pcode ile temsil et
- Iteratif sadeleistirme pipeline'i

**Oncelik:** P0

---

### 5.2 Mixed Boolean Arithmetic (MBA) Nasil Sadeleistirilir?

**Zorluk Seviyesi:** 8/10

**Problem:** `x + y` gibi basit bir islem `39*x + 39*y - 41*(x^y) - 79*(x&y) + 2*(~x&y) + 78*(x|y)` olarak yazilmis. Bunu geri cevirmek gerekiyor.

**Yaklasim 1: Brute-Force Truth Table (en guvenilir)**
```python
# 8-bit icin: 256*256 = 65536 kombinasyon
def identify_mba(expr_func):
    # Tum 8-bit input ciftleri icin sonucu hesapla
    truth_table = {}
    for x in range(256):
        for y in range(256):
            truth_table[(x, y)] = expr_func(x, y) & 0xFF

    # Bilinen islemlerle karsilastir
    known_ops = {
        'x + y': lambda x, y: (x + y) & 0xFF,
        'x - y': lambda x, y: (x - y) & 0xFF,
        'x ^ y': lambda x, y: x ^ y,
        'x & y': lambda x, y: x & y,
        'x | y': lambda x, y: x | y,
        '~x': lambda x, y: (~x) & 0xFF,
        # ... daha fazla
    }

    for name, op in known_ops.items():
        match = all(truth_table[(x,y)] == op(x,y) for x,y in truth_table)
        if match:
            return name
    return None
```

**Yaklasim 2: SSPAM (Symbolic Simplification)**
- MBA ifadesini boolean ve aritmetik bilesenlere ayir
- Lineer MBA icin: `f(x,y) = a0 + a1*x + a2*y + a3*(x&y) + a4*(x|y) + a5*(x^y) + a6*(~x&y) + a7*(~x&~y)`
- Katsayilari (a0..a7) bulmak icin 8 sample noktasi yeterli (Gaussian elimination)
- Bulduktan sonra basitlestir: `a1*x + a2*y` ise `x + y` (a1=a2=1)

**Yaklasim 3: Simba (DIMVA 2021)**
- MBA'yi lineer cebir problemi olarak modelleyip, Z3 + sampling ile coz
- Polinom MBA icin de calisir (non-linear)

**Yaklasim 4: GAMBA (ML-based)**
- MBA ifadesini AST olarak temsil et
- GNN (Graph Neural Network) ile siniflandir
- Egitim verisi: Bilinen MBA -> basit ifade ciftleri

**Karadul Stratejisi:**
- Oncelikle truth table yaklasimiyla basla (en robust)
- SSPAM lineer cozucu ile destekle
- Buyuk MBA'lar icin sampling + Z3

**Oncelik:** P0

---

### 5.3 Self-Modifying Code Nasil Analiz Edilir?

**Zorluk Seviyesi:** 7/10

**Problem:** Kod calisirken kendini degistiriyor. Statik analiz yaniltici, cunku disassemble edilen kod calisacak kod degil.

**Yaklasim 1: Multi-Snapshot Analiz**
1. Breakpoint: `VirtualProtect` / `mprotect` cagrisi uzerine
2. Her cagrida: Degistirilen bellek bolgesini dump et
3. Her snapshot'i ayri ayri disassemble et
4. Katmanlari sirala: Hangi kod hangi kodu aciyor?

**Yaklasim 2: Write-Trace Analiz**
- Unicorn/Qiling ile emulate et
- Her bellek yazma islemini logla (adres, boyut, deger)
- Execute edilen adreslerdeki final halini al
- "Write, then execute" pattern'ini tespit et

**Yaklasim 3: Emulation + Hook**
- Frida ile `VirtualProtect`/`mprotect` hook'la
- Her cagri sonrasi degisen bolgeyi otomatik dump et
- Dump'lari zaman sirasina gore analiz et

**Karadul Stratejisi:**
- Frida hook'lari ile mprotect/VirtualProtect izleme
- Unicorn emulation ile write-trace
- Katmanli decryption otomasyonu

**Oncelik:** P1

---

### 5.4 Anti-Tamper Bypass Without Patching

**Zorluk Seviyesi:** 6/10

**Problem:** Binary'yi patch'lerseniz integrity check (CRC, hash) basarisiz olur. Patch'lemeden analiz etmek gerekiyor.

**Yaklasim 1: Emulation**
- Binary'yi dogrudan calistirmak yerine emulate et
- Emulator icinde anti-tamper kontrol fonksiyonlarinin return degerini degistir
- Binary'nin kendisi degismez, sadece emulator davranisi degisir

**Yaklasim 2: Frida In-Memory Patching**
- Disk'teki binary'ye dokunma
- Runtime'da bellekte fonksiyonlari hook'la / NOP'la
- Integrity check disk hash'i ile bellegi karsilastiriyorsa bile, Frida hook'u check fonksiyonunun kendisini atlatiyor

**Yaklasim 3: Hardware Breakpoint + Single Step**
- Software breakpoint koymadan (0xCC yazmadan) analiz et
- Hardware breakpoint + single step tracing
- 0xCC scan anti-debug'i tetiklenmez

**Yaklasim 4: Snapshot-Based**
- Process'i calistir, anti-tamper check'ten ONCE dump al
- Dump uzerinde statik analiz yap
- Integrity check olmadan analiz et

**Karadul Stratejisi:**
- Frida in-memory hooking altyapisi zaten var
- Integrity check pattern tespiti ekle
- Emulation-based bypass icin Qiling entegrasyonu

**Oncelik:** P1

---

### 5.5 Whitebox Crypto Analysis

**Zorluk Seviyesi:** 9/10

**Problem:** Kriptografik anahtar kodun icine gomulmus (whitebox implementation). Anahtar bellekte hic cleartext olarak gorulmuyor. Lookup table'lar ile hesaplama yapiliyor.

**Nasil Calisir:**
- Standart AES: `Ciphertext = AES(Key, Plaintext)` -- Key bellekte acik
- Whitebox AES: AES round islemleri + key, dev lookup table'lara (T-table) donusturulmus
- T-table'lar: 256x16 byte (her round icin), toplam ~1MB veri
- Anahtar table icinde eritilmis, dogrudan cikarilmasi zor

**Saldiri Yontemleri:**
1. **DCA (Differential Computation Analysis):** Side-channel saldirisi -- trace'ler uzerinden korelasyon analizi
   - Cok sayida (10,000+) input/output cifti toplanir
   - Her ara deger icin power analysis benzeri korelasyon hesaplanir
   - Anahtar byte'lari tek tek recover edilir
2. **DFA (Differential Fault Analysis):** Hesaplamaya hata enjekte et, cikti farkina bak
   - Son round'dan once tek bit hata -> 4 byte key recover
3. **Algebraic attack:** T-table yapisini coz, lineer bagintilari bul
4. **BGE attack:** Billet, Gilbert, Ech-Chatbi (2004) -- T-table'dan affine donusumleri cikar, anahtar recover et

**Otomatik Araclar:**
- **SideChannelMarvels/Deadpool:** DCA + DFA framework (GitHub)
- **JeanGrey:** Whitebox AES key extraction
- **Tracer (Intel PIN):** Execution trace toplama

**Karadul Stratejisi:**
- Execution trace toplama altyapisi (Frida veya unicorn)
- DCA implementasyonu (NumPy ile correlation matrix)
- T-table tespiti (256 entry, belirli boyut pattern)

**Oncelik:** P2 (ileri seviye, ana pipeline'dan sonra)

---

## BOLUM 6: KARADUL v1.0 ONCELIK MATRISI

### P0 -- Kritik (Ilk Sprint)

| # | Teknik/Arac | Mevcut Durum | Gerekli Is |
|---|-------------|-------------|------------|
| 1 | VM-based deobfuscation | Yok | Trace engine (unicorn) + handler ID + lifter |
| 2 | MBA simplification | Yok | Truth table + SSPAM lineer cozucu |
| 3 | angr entegrasyonu | Yok | Symbolic execution altyapisi |
| 4 | unicorn/capstone/Qiling | Yok | Emulation + disassembly engine |

### P1 -- Yuksek (Ikinci Sprint)

| # | Teknik/Arac | Mevcut Durum | Gerekli Is |
|---|-------------|-------------|------------|
| 5 | CFF deflattener guclendir | Regex-tabanli var | Symbolic execution + SSA form ile yeniden yaz |
| 6 | BCF + Opaque predicate | Kismen | BCF-spesifik dead code elimination |
| 7 | Instruction substitution | Yok | Peephole simplifier |
| 8 | Themida/WinLicense | Yok | OEP finder + IAT reconstruct + VM handler ID |
| 9 | VMProtect | Yok | P0 VM engine ile entegre |
| 10 | Code Virtualizer | Yok | P0 VM engine ile entegre |
| 11 | Self-modifying code | Yok | Write-trace + multi-snapshot |
| 12 | Integrity check bypass | Yok | Pattern detect + Frida hook |
| 13 | Triton entegrasyonu | Yok | Dynamic symbolic execution |
| 14 | String encryption (AES, custom) | Kismen (XOR/RC4) | Emulation-based generic decryptor |
| 15 | LIEF entegrasyonu | Yok | Binary modification altyapisi |

### P2 -- Orta (Ucuncu Sprint)

| # | Teknik/Arac | Mevcut Durum | Gerekli Is |
|---|-------------|-------------|------------|
| 16 | Enigma Protector | Yok | OEP + dump + VirtualBox extractor |
| 17 | Obsidium | Yok | Nanomite restore + stolen bytes |
| 18 | Nuitka decompilation | Tespit var, decompile kismen | Ghidra + string analizi iyilestir |
| 19 | Anti-debug bypass (dinamik) | Statik tespit var | Frida hook library |
| 20 | Timing check bypass | Statik tespit var | Hook library |
| 21 | Exception-based anti-debug | Yok | Pattern detect + bypass |
| 22 | Hardware BP detection | Yok | Pattern detect |
| 23 | Opaque predicate Z3 | Opsiyonel Z3 var | Full SMT entegrasyonu |
| 24 | Constant unfolding | Yok | Constant propagation pass |
| 25 | Dead code elimination | Yok | Liveness analysis + DCE |
| 26 | Whitebox crypto | Yok | DCA framework |
| 27 | Bun binary extraction | Yok | Header parse + payload extract |
| 28 | rollup/vite deobf | Kismen | Bundler-specific module extraction |

### P3 -- Dusuk (Gelecek)

| # | Teknik/Arac | Mevcut Durum | Gerekli Is |
|---|-------------|-------------|------------|
| 29 | UPX iyilestirme | Calisiyor | Modifiye UPX icin header fix |
| 30 | ASPack/PECompact/MPRESS | Yok | Generic unpacker (emulation-based) |
| 31 | Anti-VM detection | Yok | Dusuk oncelik (malware analizi icin) |
| 32 | SW breakpoint detection | Yok | Pattern detect |
| 33 | Parent process check | Kismen | Ek pattern'ler |
| 34 | Register reassignment | Yok | SSA normalization |

---

## BOLUM 7: ONERILEN MIMARI

### 7.1 Yeni Moduller

```
karadul/
  deobfuscators/
    vm_deobfuscator.py          # YENI: VM-based obfuscation cozucu
    mba_simplifier.py           # YENI: Mixed Boolean Arithmetic sadeleistirici
    instruction_simplifier.py   # YENI: Peephole + instruction substitution
    dead_code_eliminator.py     # YENI: DCE + unreachable code removal
    constant_folder.py          # YENI: Constant propagation/folding
    integrity_bypass.py         # YENI: CRC/hash check tespit + bypass
    smc_analyzer.py             # YENI: Self-modifying code analiz
  analyzers/
    anti_debug_catalog.py       # YENI: Tum anti-debug pattern veritabani
    packer_catalog.py           # YENI: Tum packer tespit veritabani (Themida, VMProtect, Enigma, ...)
  engines/
    emulation.py                # YENI: unicorn/Qiling wrapper
    symbolic.py                 # YENI: angr/Triton wrapper
    trace.py                    # YENI: Execution trace toplama + analiz
    lifter.py                   # YENI: VM bytecode -> IR lifting
```

### 7.2 Bagimlilik Haritasi

```
VM Deobfuscation
  |-- Emulation Engine (unicorn/Qiling)
  |-- Trace Engine
  |-- Handler Identifier
  |-- Lifter (bytecode -> IR)
  |-- MBA Simplifier
  |-- Instruction Simplifier
  |-- Dead Code Eliminator

CFF Deflattening v2
  |-- Symbolic Execution (angr)
  |-- State Transition Graph
  |-- Topological Sort (mevcut)

Anti-Tamper Bypass
  |-- Integrity Check Detector
  |-- Frida Hook Library (mevcut)
  |-- Emulation-based Bypass

String Decryption v2
  |-- Emulation Engine (unicorn)
  |-- Mevcut pattern-based (XOR, RC4, ...)
  |-- Symbolic Execution fallback (angr)
```

### 7.3 Kurulacak Python Paketleri

```
# requirements-deobf-advanced.txt
unicorn>=2.0.0          # CPU emulation
capstone>=5.0.0         # Disassembly
keystone-engine>=0.9    # Assembly
angr>=9.2               # Symbolic execution
z3-solver>=4.12         # SMT solver (opaque predicates, MBA)
lief>=0.14              # Binary parsing/modification
qiling>=1.4             # Full binary emulation
triton>=1.0             # Dynamic symbolic execution
```

---

## BOLUM 8: SONUC VE YOLT HARITASI

### Mevcut Karadul Yetenekleri (Ozet)

| Kategori | Durum | Detay |
|----------|-------|-------|
| Packer tespiti | Iyi | UPX, PyInstaller, Nuitka calisiyor |
| Packer acma | Kismen | UPX + PyInstaller calisiyor, Themida/VMProtect yok |
| String decryption | Iyi | XOR (3 varyant), RC4, Base64, stack string |
| CFF deflattening | Var | Regex-tabanli, symbolic destekli degil |
| Opaque predicate | Var | Pattern matching + opsiyonel Z3 |
| Anti-debug tespit | Kismen | Statik pattern tespiti, dinamik bypass yok |
| VM deobfuscation | YOK | En buyuk eksik |
| MBA simplification | YOK | Ikinci buyuk eksik |
| Emulation | YOK | unicorn/Qiling yok |
| Symbolic execution | YOK | angr/Triton yok |
| Dead code elimination | YOK | Genel DCE yok |
| Binary modification | YOK | LIEF yok |

### Yol Haritasi

**Hafta 1-2: Altyapi (P0)**
- unicorn + capstone + Qiling kurulumu ve wrapper
- angr entegrasyonu ve temel symbolic execution pipeline
- MBA truth table cozucu

**Hafta 3-4: VM Deobfuscation (P0)**
- Trace engine (unicorn-tabanli)
- Handler identifier (pattern library)
- Basit VM lifter prototipi
- VMProtect v2 icin ilk deneme

**Hafta 5-6: Guclu Deobfuscation (P1)**
- CFF deflattener v2 (angr destekli)
- BCF + dead code eliminator
- Instruction substitution simplifier
- Self-modifying code analyzer

**Hafta 7-8: Anti-RE Bypass (P1-P2)**
- Frida anti-debug hook library
- Integrity check bypass
- Themida/Enigma basic unpacker
- String decryption v2 (emulation-based)

**Hafta 9-10: Polish + Test (P2)**
- Whitebox crypto DCA
- Ek packer destegi
- Kapsamli test suite
- Benchmark: Obfuscated binary collection uzerinde basari orani olcumu

---

*Bu rapor Karadul v1.0 development roadmap'i icin referans dokumani olarak kullanilacaktir.*
*Her teknik icin implementasyon detaylari ayri ADR (Architecture Decision Record) dosyalarinda belgelenecektir.*
