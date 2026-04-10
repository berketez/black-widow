# %80+ Okunabilirlik Plani -- Somut Adimlar

**Tarih:** 2026-03-23
**Yazar:** Architect Agent
**Durum:** Onerilen
**Kisitlama:** LLM KULLANILMAYACAK. Tamamen deterministik, heuristik, pattern-based.

---

## Mevcut Durum Ozeti

| Hedef | Tip | Mevcut % | Hedef % | Toplam Sembol | Isimli | Isimsiz |
|-------|-----|----------|---------|---------------|--------|---------|
| Rectangle | Swift (Mach-O) | %75 | %90 | 2,852 fonk + 2,532 var | ~2,139 fonk | ~713 fonk |
| Cursor | JS (minified) | %82 | %90 | 3,656 fonk + 3,422 var | ~3,000 fonk | ~656 fonk |
| Claude Code | JS (esbuild) | %55 | %80 | ~22,064 fonk + 25,076 var | ~12,135 | ~9,929 |
| Steam | C++ (Mach-O arm64) | %18 | %50 | 11,296 fonk + 9,144 var | ~2,033 fonk | ~9,263 fonk |
| **Ortalama** | | **%57** | **%77.5** | | | |

**Not:** "Okunabilirlik %" = isimlendirilen sembol orani + naming confidence agirlikli skor. Tam formul: `(high_conf * 1.0 + med_conf * 0.7 + low_conf * 0.3) / toplam`.

---

## 1. RECTANGLE: %75 -> %90

### Mevcut Durum Detay

Rectangle bir Swift uygulamasi. Ghidra analizi:
- 2,852 fonksiyon, 11,427 string, 671 sembol
- `binary_name_extractor`: 224 isim kurtardi
- `c_namer` stratejileri: api_param 114, binary_extract 180, call_graph 886, dataflow 1,054, string_context 297, type_based 1
- Toplam: 2,532 degisken rename, 591 high confidence
- `name_merger`: 2,564 birlestirme, 168 exact multi-source
- 257 struct, 24 enum, 282 tip kurtarildi
- 61 dynamic library, Swift compiler tespit edildi

### Darbogazlar

1. **59 GitHub class bulunamadi:** Rectangle'in GitHub kaynak kodu `rxhanson/Rectangle` reposunda. Ancak binary'deki class isimleri ile repo dosyalari arasinda 59 tane eslesmeyen class var. Bunlarin cogu Swift compiler tarafindan eklenen internal class'lar veya extension'lardan gelen fonksiyonlar.

2. **Swift mangling eksiklikleri:** `$s` prefix'li Swift mangled name'lerin bir kismi mevcut demangle tarafindan cozulmuyor. Ozellikle `Sixteenth`, `Twelfth` gibi Rectangle'a ozgu hesaplama class'lari binary'de string olarak mevcut ama fonksiyonlarla eslestirilemedi.

3. **Protocol witness table kullanilmiyor:** Swift'in protocol witness table'lari class-protocol conformance bilgisini tutar. Mevcut pipeline bunu kullanmiyor.

### Adimlar

| # | Adim | Tahmini Etki | Sure | Bagimlilik | Aciklama |
|---|------|-------------|------|------------|----------|
| R1 | Swift Demangle Genisletme | +%5 (~143 fonk) | 2 gun | Yok | `xcrun swift-demangle` ile toplu demangle, mevcut basit regex yerine. `$s`, `$S`, `$sSS`, `$sSo` prefix'lerini tam coz. Mevcut `_try_demangle_swift()` sadece basit pattern'leri yakaliyor. |
| R2 | Protocol Witness Table Parse | +%4 (~114 fonk) | 2 gun | R1 | Ghidra'nin `__swift5_protos` ve `__swift5_proto` section'larindan protocol conformance cikar. Her witness entry bir class+protocol eslesmesi = fonksiyon isimleri. Rectangle'da Equatable, Codable, CustomStringConvertible gibi conformance'lar fonksiyon isimleri verir. |
| R3 | GitHub Source Cross-Match | +%3 (~86 fonk) | 1 gun | Yok | `rxhanson/Rectangle` reposundaki `.swift` dosyalarindaki class/struct/enum isimlerini topla. Binary string'leriyle eslestir. 59 bulunamayan class'in %80'i bu yontemle kurtarilabilir. Offline islem -- GitHub API gerektirmez, repo'yu bir kez clone et. |
| R4 | Extension Method Recovery | +%2 (~57 fonk) | 1 gun | R1 | Swift extension method'lari binary'de `ExtendedType.methodName` olarak mangled. Mevcut pipeline extension fonksiyonlarini taniyamiyor. Demangle output'unda `(extension in ModuleName):` pattern'ini parse et. |
| R5 | Struct Field Name Propagation | +%1 (~29 var) | 0.5 gun | Yok | Rectangle'da `WindowCalculation`, `RectResult` gibi struct'larin field isimleri Swift metadata'da sakli. Bu isimleri `c_namer`'in dataflow stratejisine besle. |

### Toplam Tahmini

```
Mevcut:  %75
R1:      +%5  -> %80
R2:      +%4  -> %84
R3:      +%3  -> %87
R4:      +%2  -> %89
R5:      +%1  -> %90
Hedef:   %90
```

**Risk:** DUSUK. Swift binary'ler metadata-zengin, deterministik cikarim mumkun.
**Toplam sure:** ~6.5 gun

---

## 2. CURSOR: %82 -> %90

### Mevcut Durum Detay

Cursor'un `main.js` bundle'i (1.35 MB):
- 3,656 fonksiyon, 9,725 string, 171 import
- Deobfuscation: beautify (322 -> 23,738 satir) + deep deobfuscation 5 faz
- Rename: 3,422 mapping, 723 high conf, 3,848 medium, 17,453 low conf
- `cursor-enhanced-rename.mjs` zaten 25 kural uyguladi (Phase 11-25)
- Kalan ~656 fonksiyon + ~6,230 minified identifier

### Darbogazlar

1. **Cross-module reference eksik:** Webpack/esbuild bundle'da moduller birbirini `require(N)` ile cagiriyor. N numarasindan modul ismini cikarabilsek, cagiran tarafta da isim propagate olur.

2. **Export ismi -> internal isim eslesmesi:** Module'un export ettigi isimler bilinebilir ama internal degiskenleri minified. Export isimleri kullanarak internal'lere isim propagasyonu yapilmiyor.

3. **npm paket isimleri:** 171 import var ama bunlarin cogu eslestirilmemis. `package.json` dependencies bilgisi yoksa paket isimleri bilinemez.

### Adimlar

| # | Adim | Tahmini Etki | Sure | Bagimlilik | Aciklama |
|---|------|-------------|------|------------|----------|
| C1 | Webpack Module ID -> Name Map | +%3 (~110 id) | 1.5 gun | Yok | Bundle'daki `require(42)` cagrilarini, module 42'nin export string'leri ile eslestir. Her module'un ilk satirindaki comment veya banner'dan paket ismi cikar. Eger modul `node_modules/xxx` ise, xxx paket adi. Mevcut `smart-webpack-unpack.mjs` zaten modul cikariyor ama ID->name mapping yapmiyormuyor. |
| C2 | Export Name Backpropagation | +%2 (~74 id) | 1 gun | C1 | Module export eden `module.exports = { createEditor, loadConfig, ... }` satirlarindan export isimlerini cikar. Bu isimler o module'daki fonksiyonlarin gercek isimleri. Export isimlerini module scope'undaki tum kullanicilarına propgate et. |
| C3 | Cross-Module Import Resolution | +%2 (~74 id) | 1.5 gun | C1, C2 | Module A'daki `const x = require(42)` ile Module 42'nin export'larini eslestir. `x.createEditor()` -> fonksiyon ismi `createEditor`. Bu bilgiyi module A'daki `x` degiskenini `editorModule` olarak adlandir, `x.createEditor`'u `createEditor` olarak adlandir. |
| C4 | String Literal Context Enrichment | +%1 (~37 id) | 0.5 gun | Yok | Mevcut string-context kurallarini genislet: `"vscode.workspace.getConfiguration"` gibi VS Code API string'leri fonksiyon baglamini verir. `"editor.fontSize"` -> cevreleyen degisken `fontSizeConfig`. Cursor VS Code fork'u, VS Code API string'leri cok zengin. |
| C5 | DTS Name Recovery | +%1 (~37 id) | 1 gun | Yok | Mevcut `dts_namer.py` zaten var ama Cursor analizinde kullanilmamis. Cursor'un bagimli oldugu paketlerin `.d.ts` dosyalarindan export isimleri cikar. Offline: `@anthropic-ai/sdk`, `vscode`, `electron` gibi bilinen bagimliliklarin .d.ts'lerini cache'le. |

### Toplam Tahmini

```
Mevcut:  %82
C1:      +%3  -> %85
C2:      +%2  -> %87
C3:      +%2  -> %89
C4:      +%1  -> %90
C5:      +%1  -> %91
Hedef:   %90
```

**Risk:** DUSUK-ORTA. JS tarafinda AST manipulasyonu olgun, parse hatalari olusabilir.
**Toplam sure:** ~5.5 gun

---

## 3. CLAUDE CODE: %55 -> %80

### Mevcut Durum Detay

Claude Code (`bundle_unwrapped`, esbuild bundle, 16.9 MB):
- 22,064 fonksiyon annotated, 25,076 degisken rename
- Avg confidence: 0.464 (DUSUK -- cogu rename dusuk guvenli)
- High conf: 2,960, Medium: 23,549, Low: 121,750
- Source match: 16 paket resolve, sadece 9 isim kurtarildi (CIDDIYE ALINMAYACAK KADAR AZ)
- npm fingerprint: 128, structural: 1,020, heuristic: 247
- Toplam naming: 1,395 (22K fonksiyona kiyasla %6.3!)

**Gercek okunabilirlik skoru yeniden hesaplama:**
- `(2960*1.0 + 23549*0.7 + 121750*0.3) / (2960+23549+121750)` = `(2960 + 16484 + 36525) / 148259` = `55970 / 148259` = **%37.7**
- Berke'nin verdigi %55, muhtemelen fonksiyon-bazli (naming pipeline'dan gecen fonksiyon orani). Variable-level'da cok daha dusuk.

### Darbogazlar

1. **Source matching calismadi:** 16 paket resolve edildi ama sadece 9 isim geldi. Pipeline dogru calissa 16 paketten yuzlerce isim gelmeli. Bug var.

2. **Enhanced rename kurallari uygulanmadi:** `cursor-enhanced-rename.mjs`'deki Phase 11-25 kurallari Claude Code'a uygulanmamis. Bu kurallar Cursor'da %82 yapti, Claude Code'da da benzer etki beklenir.

3. **esbuild module boundary:** esbuild, webpack'ten farkli bundle yapar -- module ID'ler yerine inline ESM kullanir. Mevcut webpack unpack esbuild icin calismaz.

4. **Buyuk dosya boyutu:** 16.9 MB, 22K fonksiyon. Performans sorunlari var (param-recovery.mjs zaten fail etmis).

### Adimlar

| # | Adim | Tahmini Etki | Sure | Bagimlilik | Aciklama |
|---|------|-------------|------|------------|----------|
| CL1 | Source Matching Bug Fix | +%8 (~1,765 id) | 2 gun | Yok | `source_matcher/pipeline.py`'de 16 paket resolve edilmis ama sadece 9 isim. Bug: `ast_fingerprinter.py`'nin eslestirme esigi cok yuksek veya fonksiyon cikarimi hatali. `min_similarity: 0.65` dusurulerek `0.45`'e ayarlanabilir. Her resolve edilen paketten ortalama 50-100 isim gelmeli. 16 paket x 50 = 800 isim. High confidence bunlar. |
| CL2 | Enhanced Rename Kurallari Uygulama | +%7 (~1,544 id) | 1.5 gun | Yok | `cursor-enhanced-rename.mjs`'deki Phase 11-25 kurallarini `rename-variables.mjs`'e entegre et veya Claude Code icin de `cursor-enhanced-rename.mjs`'i calistir. Cursor'da 3,422 rename ile %82 yapti. Claude Code'da 25K rename var ama cogu dusuk conf. Enhanced kurallar medium conf'u high conf'a cevirebilir. |
| CL3 | esbuild Module Boundary Detection | +%4 (~882 id) | 2 gun | Yok | esbuild bundle pattern'i: `var xxx = __toESM(require_yyy())`. Bu pattern'den modul sinirlari cikar. `require_yyy` fonksiyon isminden paket adi cikar (`require_fs` -> `fs`, `require_path` -> `path`). esbuild genellikle `require_PAKET` convention'i kullanir. |
| CL4 | npm Cache Offline Match | +%3 (~662 id) | 1.5 gun | CL1 | npm cache (`~/.npm/_cacache/`) icerisinde zaten indirilmis paketler var. Bu paketlerin kaynak kodunu cache'ten okuyarak fingerprint eslestirme yap. Network gerektirmez. Claude Code'un bagimlilik agaci Anthropic SDK + VS Code altyapisi + Electron. Bilinen paketlerin listesini hardcode et. |
| CL5 | require() Chain Isim Propagasyonu | +%2 (~441 id) | 1 gun | CL3 | `const x = require_fs()` sonrasinda `x.readFileSync()` kullanimlari. `x`'i `fileSystemModule` olarak, `x.readFileSync`'i `readFileSync` olarak adlandir. Mevcut rename-variables.mjs'de require pattern zaten var (Strateji 1) ama esbuild'in `require_xxx()` convention'ina uyarlanmamis. |
| CL6 | Anthropic SDK API String Match | +%1 (~221 id) | 0.5 gun | Yok | Claude Code icinde `"anthropic"`, `"claude"`, `"messages.create"`, `"completions"` gibi API string'leri mevcut. Bu string'leri cevresindeki fonksiyonlara propgate et. Ornegin: bir fonksiyon icinde `"messages.create"` string'i varsa ve `"model"`, `"max_tokens"` gibi property'ler kullaniliyorsa -> `createMessage` fonksiyonu. |

### Toplam Tahmini

```
Mevcut:  %55
CL1:     +%8  -> %63
CL2:     +%7  -> %70
CL3:     +%4  -> %74
CL4:     +%3  -> %77
CL5:     +%2  -> %79
CL6:     +%1  -> %80
Hedef:   %80
```

**Risk:** ORTA. Source matching bug fix kritik -- bu calismadan +%8 gelmezse hedef tutmaz. Enhanced rename kurallari test edilmeli (Cursor'daki basari Claude Code'a dogrudan transfer olmayabilir, bundle yapisi farkli).
**Toplam sure:** ~8.5 gun

---

## 4. STEAM: %18 -> %50

### Mevcut Durum Detay

Steam arm64 binary (3.9 MB, Mach-O):
- 11,296 fonksiyon, 13,228 Ghidra string, 588 sembol
- `signature_matches`: 542 (kutuphane fonksiyon eslesmesi)
- `byte_pattern_matched`: 1,404 (22,277 DB'den 10,754 bilinmeyen fonksiyon uzerinde %13.1 match rate)
- `binary_name_extractor`: 2,689 isim (debug string 590, call_graph 3,260, dataflow 2,662, string_context 2,532, api_param 99, api_call 1)
- `naming_high_confidence`: 3,222
- 137 class, 206 struct, 79 enum, 287 tip kurtarildi
- RTTI: 144 entry tespit edildi
- Build path: 112 kaynak dosya yolu
- `m_` prefixli member: 289
- `Class::Method` pattern: 248

**Gercek okunabilirlik hesabi:**
- Toplam named fonksiyon: signature (542) + byte_pattern (1,404) + high_conf_naming (3,222) = ~5,168 bilinir
- Ama bunlarin bir kismi overlap. Unique sayisi: ~4,500 (tahmin, overlap dusme)
- Bilinmeyen: 11,296 - 4,500 = ~6,796
- Oran: 4,500 / 11,296 = **%39.8** fonksiyon bazli ama confidence-weighted %18.

### Darbogazlar

1. **Byte pattern DB kucuk:** 22,277 imza var ama sadece ARM64 Homebrew kutuphaneleri. Steam x86_64 kutuphanelerini kullanir (Rosetta cevirmeli). ARM64 DB'de olmayan fonksiyonlar eslesmez.

2. **Ghidra string xref sorunu:** `ghidra_strings.json`'da `"function": null`. 13,228 string'in hicbiri fonksiyona baglanmamis. Bu, debug string parse ve build path mapper'in yarim kapasiteyle calismasina neden oluyor. ADR-002'de tespit edilmis ama duzeltilmemis.

3. **RTTI tam kullanilmiyor:** 144 RTTI entry tespit edildi ama vtable -> virtual method zinciri kurulmamis. Her class'in vtable'indan 3-10 virtual method adresi cikarilabilir = ~700 ek fonksiyon ismi.

4. **Callee combo naming sinirli:** Mevcut system sadece 30 combo taniyor. Genisletilmeli.

### Adimlar

| # | Adim | Tahmini Etki | Sure | Bagimlilik | Aciklama |
|---|------|-------------|------|------------|----------|
| S1 | Ghidra String XREF Duzeltmesi | +%8 (~904 fonk) | 1.5 gun | Yok | **ONCELIK 0.** `ghidra/scripts/string_extractor.py`'de `getReferencesTo()` kullan. String -> referans veren fonksiyon eslesmesi. 13,228 string'in ~%40'i en az 1 fonksiyona referans verir = ~5,291 string-fonksiyon baglantisi. Mevcut debug string parse (248 Class::Method + 289 m_ member) bu baglantilar uzerinden calisir. Bug fix olmadan Strateji B ve C'nin gucune darbe. |
| S2 | RTTI VTable Chain Extraction | +%6 (~678 fonk) | 2 gun | Yok | 144 RTTI class'in her birinin vtable adresini bul. VTable'dan virtual method pointer'larini oku. Her pointer bir fonksiyon adresi = `ClassName_vmethod_N` ismi. Ortalama class basina 4-5 virtual method = 144 * 4.7 = ~677 fonksiyon. `c++filt` ile demangled RTTI string'lerden namespace ve class ismi. |
| S3 | x86_64 Byte Pattern DB | +%5 (~565 fonk) | 3 gun | Yok | Steam Rosetta ile x86_64 kutuphaneleri kullanir. Homebrew x86_64 formulalarini derleyip byte pattern cikar. `arch -x86_64 brew install` ile populer kutuphaneleri x86_64 derle. ~50K yeni imza hedefi. Match rate %13 -> %20+ beklenir. |
| S4 | Build Path -> Fonksiyon Gruplama | +%4 (~452 fonk) | 1 gun | S1 | 112 build path (`/build/src/filesystem/BaseFileSystem.cpp` vb.) tespit edilmis. Her build path bir kaynak dosyayi temsil eder. Ayni kaynak dosyaya ait fonksiyonlar adres olarak ardisiktir. Gruplandirma: path string'in xref'inden fonksiyonu bul, civar fonksiyonlari ayni module ata. Sonuc: fonksiyon isimlerine module prefix ekle (`filesystem_FUN_1234`). |
| S5 | Debug String Deep Parse (Genisletilmis) | +%3 (~339 fonk) | 1.5 gun | S1 | S1 duzeltmesinden sonra, 248 `Class::Method` pattern'ini fonksiyonlarla eslestir. Ek pattern'ler: `"Error in X"`, `"X failed"`, `"X: invalid"` gibi hata mesajlarindan fonksiyon ismi cikar. Assert expression'lardan (`"m_bIsPackFile"`) member variable ismi. Telemetry string'lerden (`"TrackEvent('x')"`) handler ismi. |
| S6 | Callee Combo DB Genisletme | +%3 (~339 fonk) | 1.5 gun | Yok | Mevcut 30 combo -> 200+ combo. Yeni combo'lar: `(malloc + memcpy + free)` -> `clone_buffer`, `(socket + connect + send + recv + close)` -> `network_request`, `(fopen + fread + fclose)` -> `read_file`, `(pthread_create + pthread_join)` -> `spawn_thread`. Valve/Source Engine spesifik combo'lar: `(CUtlVector::AddToTail + CUtlVector::Count)` -> `vector_operation`. |
| S7 | String Reference Propagation | +%2 (~226 fonk) | 1 gun | S1 | String iceren bir fonksiyon isimlendirildiginde, onu cagiran fonksiyonlara isim propgate et. Ornek: `FUN_1234` icerisinde `"HTTP/1.1"` string'i var -> `http_handler`. `FUN_5678` `FUN_1234`'u cagiriyor ve baska sey yapmiyor -> `call_http_handler`. 1 seviye propagasyon, her seviyede confidence 0.1 dusur. |
| S8 | Protobuf Field Recovery | +%1 (~113 fonk) | 1 gun | Yok | 307 protobuf-related string. Protobuf message descriptor string'lerinden field isimleri cikar. `SerializeWithCachedSizes`, `MergePartialFromCodedStream` gibi bilinen method isimlerini fonksiyonlara ata. Protobuf generated code pattern tanimasi deterministik. |

### Toplam Tahmini

```
Mevcut:  %18
S1:      +%8  -> %26
S2:      +%6  -> %32
S3:      +%5  -> %37
S4:      +%4  -> %41
S5:      +%3  -> %44
S6:      +%3  -> %47
S7:      +%2  -> %49
S8:      +%1  -> %50
Hedef:   %50
```

**Risk:** YUKSEK. Ghidra string xref fix (S1) kritik yoldur -- bu olmadan S4, S5, S7 yarim kapasiteyle calisir. x86_64 byte pattern DB (S3) zaman alici. Gercekci hedef: S1+S2+S5+S6 yapilirsa %40-44 elde edilir.
**Toplam sure:** ~12.5 gun

---

## Uygulama Oncelik Sirasi

```
Hafta 1 (6.5 gun):  Rectangle %75 -> %90   [DUSUK RISK, YUKSEK GETIRI/RISK ORANI]
                     R1 -> R2 -> R3 -> R4 -> R5

Hafta 2 (5.5 gun):  Cursor %82 -> %90       [DUSUK-ORTA RISK]
                     C1 -> C2 -> C3 -> C4 -> C5

Hafta 3 (8.5 gun):  Claude Code %55 -> %80  [ORTA RISK]
                     CL1 -> CL2 -> CL3 -> CL4 -> CL5 -> CL6

Hafta 4-5 (12.5 gun): Steam %18 -> %50      [YUKSEK RISK]
                     S1 (oncelik 0) -> S2 -> S5 -> S6 -> S4 -> S3 -> S7 -> S8
```

### Kritik Yol (Tum hedefler icin en riskli adimlar)

```
1. S1: Ghidra String XREF Fix      -- Steam'in yarisi buna bagimli
2. CL1: Source Match Bug Fix        -- Claude Code'un %8'i buna bagimli
3. R1: Swift Demangle Genisletme    -- Rectangle'in temeli
4. C1: Webpack Module ID Map        -- Cursor'un geri kalani buna bagimli
```

Bu 4 adim ilk 4 gunde yapilirsa, geri kalan adimlar birbirinden bagimsiz paralel ilerleyebilir.

---

## Teknik Detaylar -- Her Adimin Implementation Plani

### R1: Swift Demangle Genisletme

**Dosya:** `karadul/reconstruction/binary_name_extractor.py` (mevcut `_try_demangle_swift` metodu)

**Mevcut kod sorunu:** Sadece basit `_$s...` pattern'lerini regex ile cozuyor. Swift mangling spec'i karmasik -- nested generics, protocol witness, key path vb.

**Cozum:**
```
1. `xcrun swift-demangle` subprocess cagrisini ekle (macOS'ta default kurulu)
2. Toplu demangle: tum `$s` ve `$S` prefix'li string'leri bir dosyaya yaz
3. `swift-demangle < input.txt > output.txt` ile tek seferde coz
4. Sonuclari parse et: "ModuleName.ClassName.methodName" formatinda
5. Fonksiyon adresine eslestir: symbol tablosundan veya string xref'inden
```

**Tahmini satir degisikligi:** ~80 satir ek (subprocess wrapper + batch demangle + result parser)

### R2: Protocol Witness Table Parse

**Dosya:** `karadul/reconstruction/binary_name_extractor.py` (yeni strateji)

**Swift binary structure:**
```
__swift5_protos section:
  - Her entry: (protocol descriptor offset, conformance descriptor offset)
  - Conformance descriptor: conforming type + witness table

Witness table icerigi:
  - Fonksiyon pointer'lari (protocol method implementation'lari)
  - Metadata pointer'lari
```

**Cozum:**
```
1. Ghidra'nin section listesinden __swift5_protos bul
2. Her conformance entry'sini parse et
3. Protocol descriptor'dan protocol ismini al (zaten demangled)
4. Conforming type descriptor'dan class/struct ismini al
5. Witness table'daki fonksiyon pointer'larini oku
6. Her pointer'a ClassName_protocolMethod ismi ata
```

**Tahmini satir degisikligi:** ~150 satir (yeni class: `SwiftProtocolWitnessExtractor`)

### S1: Ghidra String XREF Duzeltmesi

**Dosya:** `karadul/ghidra/scripts/string_extractor.py`

**Mevcut kod:**
```python
func = getFunctionContaining(data.getAddress())  # YANLIS: string'in data adresi
```

**Duzeltme:**
```python
refs = getReferencesTo(data.getAddress())
referring_funcs = set()
for ref in refs:
    func = getFunctionContaining(ref.getFromAddress())  # DOGRU: referans veren instruction
    if func is not None:
        referring_funcs.add(func.getName())
entry["referring_functions"] = list(referring_funcs)
```

**Tahmini satir degisikligi:** ~15 satir degisiklik + downstream consumer'larda `"referring_functions"` alani okuma (~30 satir)

### S2: RTTI VTable Chain

**Dosya:** `karadul/reconstruction/binary_name_extractor.py` (mevcut RTTI stratejisi genisletme)

**Mevcut kod:** Sadece `_ZTI`, `_ZTS` string'lerden class ismi cikariyor. VTable okumasi yok.

**Ekleme:**
```
1. _ZTV prefix'li symbol'lerden vtable adreslerini topla
2. Her vtable: ilk 2 entry skip (RTTI pointer + offset-to-top)
3. Kalan entry'ler = virtual method fonksiyon adresleri
4. Her adrese ClassName_vmethod_N ismi ata
5. Eger RTTI'dan inheritance bilgisi varsa, base class vtable ile karsilastirarak
   override edilen method'lari belirle
```

**Tahmini satir degisikligi:** ~200 satir (yeni class: `VTableChainExtractor`)

### CL1: Source Match Bug Fix

**Dosya:** `karadul/reconstruction/source_matcher/pipeline.py` + `ast_fingerprinter.py`

**Sorun analizi:**
- 16 paket resolve edilmis (source_resolver calisiyor)
- Sadece 9 isim kurtarilmis (ast_fingerprinter veya applier'da bug)
- Muhtemel sebepler:
  1. `min_similarity` esigi cok yuksek (0.65). esbuild bundle'da fonksiyonlar agir optimize
  2. `ast_fingerprinter.py`'de AST parse hatasi (esbuild ciktisi Babel'in bekledigi formatla uyumsuz)
  3. `applier.py`'de rename uygulama basarisiz (scope conflict)

**Debug stratejisi:**
```
1. Source matcher pipeline'i verbose mode ile calistir
2. Her paket icin: kac fonksiyon fingerprint'lendi, kac eslesti, neden reddedildi
3. min_similarity 0.65 -> 0.45 dusur, test et
4. esbuild output formatini Babel parser'a uyumlu hale getir (gerekirse)
5. Eslesen ama uygulanmayan rename'leri debug et
```

**Tahmini satir degisikligi:** ~50 satir (config tweak + bug fix + logging)

### CL2: Enhanced Rename Kurallari

**Dosya:** `scripts/rename-variables.mjs` veya pipeline entegrasyonu

**Cozum:** `cursor-enhanced-rename.mjs`'i generic hale getir:
```
1. Phase 11-25 kurallarini ayri bir fonksiyon olarak cikar
2. Cursor-specific isimler (e.g. "cursor", "vscode") yerine genel pattern kullan
3. rename-variables.mjs'in sonuna bu kurallari ekle
4. Veya ayri bir pass olarak pipeline'a ekle: deobfuscate -> rename -> enhanced-rename
```

**Alternatif (daha az is):** Claude Code analizinde de `cursor-enhanced-rename.mjs`'i calistir. Cursor-specific kurallar (19, 23) ignore edilir, geri kalan 13 kural generic.

**Tahmini satir degisikligi:** ~30 satir (pipeline entegrasyonu) veya 0 satir (ayni scripti farkli target'a uygula)

### CL3: esbuild Module Boundary Detection

**Dosya:** `scripts/esbuild-unpack.mjs` (mevcut ama icerigini bilmiyorum)

**esbuild bundle pattern:**
```javascript
// esbuild tipik cikti:
var require_fs = __commonJS({
  "node_modules/graceful-fs/graceful-fs.js"(exports, module) {
    // ... modul kodu ...
  }
});

// Kullanim:
var import_fs = __toESM(require_fs());
```

**Cikarim:**
```
1. `__commonJS({` pattern'ini bul
2. Icindeki string key = kaynak dosya yolu ("node_modules/graceful-fs/graceful-fs.js")
3. Dosya yolundan paket adi cikar: "graceful-fs"
4. Wrapper fonksiyon ismi: require_fs -> paket: fs (veya graceful-fs)
5. `__toESM(require_XXX())` pattern'inden import mapping olustur
```

**Tahmini satir degisikligi:** ~120 satir (yeni parser fonksiyonu)

---

## Olcum ve Dogrulama

Her adim sonrasinda okunabilirlik skoru yeniden hesaplanmali:

```python
def readability_score(report_json):
    """Pipeline report.json'dan okunabilirlik skoru hesapla."""
    stats = report_json["pipeline"]["stages"]["reconstruct"]["stats"]

    # Binary hedefler icin
    if "naming_high_confidence" in stats:
        high = stats["naming_high_confidence"]
        total_funcs = report_json["pipeline"]["stages"]["static"]["stats"].get(
            "ghidra_function_count", 0
        )
        sig = stats.get("signature_matches", 0)
        byte_pat = stats.get("byte_pattern_matched", 0)

        named = high + sig + byte_pat
        # Overlap dusme: ~%15 overlap varsayimi
        named_unique = int(named * 0.85)
        return min(100, (named_unique / total_funcs) * 100)

    # JS hedefler icin
    if "rename_high_confidence" in stats:
        high = stats["rename_high_confidence"]
        med = stats["rename_medium_confidence"]
        low = stats["rename_low_confidence"]
        total = high + med + low

        if total == 0:
            return 0
        score = (high * 1.0 + med * 0.7 + low * 0.3) / total * 100
        return score
```

**Dogrulama yontemi:** Her adim sonrasi pipeline'i yeniden calistir ve skor degisimini olc. "Before/after" kiyaslamasi ZORUNLU.

---

## Bagimlilik Grafi

```
Rectangle:
  R1 (Swift Demangle) -----> R2 (Protocol Witness) --> R4 (Extension)
  R3 (GitHub Cross-Match) [bagimsiz]
  R5 (Struct Field) [bagimsiz]

Cursor:
  C1 (Module ID Map) -----> C2 (Export Backprop) --> C3 (Cross-Module)
  C4 (String Context) [bagimsiz]
  C5 (DTS Recovery) [bagimsiz]

Claude Code:
  CL1 (Source Match Fix) --> CL4 (npm Cache)
  CL2 (Enhanced Rename) [bagimsiz]
  CL3 (esbuild Boundary) --> CL5 (require Chain)
  CL6 (API String) [bagimsiz]

Steam:
  S1 (String XREF Fix) --> S4 (Build Path Group)
                       --> S5 (Debug String Deep)
                       --> S7 (String Propagation)
  S2 (RTTI VTable) [bagimsiz]
  S3 (x86_64 Byte DB) [bagimsiz]
  S6 (Callee Combo) [bagimsiz]
  S8 (Protobuf) [bagimsiz]
```

**Paralel calisma firsatlari:**
- R3, R5 ile R1-R2 paralel
- C4, C5 ile C1-C3 paralel
- CL2, CL6 ile CL1 ve CL3 paralel
- S2, S3, S6, S8 ile S1 paralel (S1 sadece S4, S5, S7 icin blocker)

---

## Maliyet/Getiri Ozet Tablosu

| Adim | Hedef | Etki (%) | Sure (gun) | Risk | ROI (etki/sure) |
|------|-------|----------|------------|------|-----------------|
| R1 | Rectangle | +5 | 2.0 | Dusuk | 2.5 |
| R2 | Rectangle | +4 | 2.0 | Dusuk | 2.0 |
| R3 | Rectangle | +3 | 1.0 | Dusuk | 3.0 |
| R4 | Rectangle | +2 | 1.0 | Dusuk | 2.0 |
| R5 | Rectangle | +1 | 0.5 | Dusuk | 2.0 |
| C1 | Cursor | +3 | 1.5 | Orta | 2.0 |
| C2 | Cursor | +2 | 1.0 | Dusuk | 2.0 |
| C3 | Cursor | +2 | 1.5 | Orta | 1.3 |
| C4 | Cursor | +1 | 0.5 | Dusuk | 2.0 |
| C5 | Cursor | +1 | 1.0 | Dusuk | 1.0 |
| CL1 | Claude Code | +8 | 2.0 | Orta | 4.0 |
| CL2 | Claude Code | +7 | 1.5 | Dusuk | 4.7 |
| CL3 | Claude Code | +4 | 2.0 | Orta | 2.0 |
| CL4 | Claude Code | +3 | 1.5 | Dusuk | 2.0 |
| CL5 | Claude Code | +2 | 1.0 | Dusuk | 2.0 |
| CL6 | Claude Code | +1 | 0.5 | Dusuk | 2.0 |
| S1 | Steam | +8 | 1.5 | Dusuk | 5.3 |
| S2 | Steam | +6 | 2.0 | Orta | 3.0 |
| S3 | Steam | +5 | 3.0 | Yuksek | 1.7 |
| S4 | Steam | +4 | 1.0 | Orta | 4.0 |
| S5 | Steam | +3 | 1.5 | Dusuk | 2.0 |
| S6 | Steam | +3 | 1.5 | Dusuk | 2.0 |
| S7 | Steam | +2 | 1.0 | Dusuk | 2.0 |
| S8 | Steam | +1 | 1.0 | Dusuk | 1.0 |

**En yuksek ROI adimlar (oncelikli):**
1. S1: Ghidra String XREF Fix (5.3)
2. CL2: Enhanced Rename (4.7)
3. CL1: Source Match Fix (4.0)
4. S4: Build Path Group (4.0)
5. R3: GitHub Cross-Match (3.0)
6. S2: RTTI VTable (3.0)

---

## Beklenen Nihai Sonuc

| Hedef | Mevcut | Hedef | Gercekci Min | Gercekci Max | Aciklama |
|-------|--------|-------|-------------|-------------|----------|
| Rectangle | %75 | %90 | %87 | %92 | En guvenilir hedef |
| Cursor | %82 | %90 | %88 | %92 | Olgun JS pipeline |
| Claude Code | %55 | %80 | %72 | %82 | Source match fix kritik |
| Steam | %18 | %50 | %38 | %52 | En riskli hedef |
| **Ortalama** | **%57** | **%77.5** | **%71** | **%79.5** | |

**Toplam sure:** ~33 gun (tek gelistirici)
**Paralel calisma ile:** ~20-22 gun (2 gelistirici: biri JS pipeline, biri binary pipeline)
**LLM gereksinimi:** SIFIR. Tum adimlar deterministik pattern matching, heuristik ve metadata extraction.

---

*Bu plan Karadul v1.0 mevcut mimarisi uzerine insa edilir. Yeni modul/framework gerektirmez. Mevcut dosyalara ekleme ve genisletme yapar.*
