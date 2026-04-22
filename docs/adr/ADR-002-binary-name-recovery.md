# ADR-002: LLM'siz Binary Name Recovery Mimarisi

**Tarih:** 2026-03-22
**Durum:** Onerilen
**Karar:** Binary metadata'dan (RTTI, debug string, ObjC, protobuf, build path, struct layout) orijinal isimleri kurtaran cok katmanli pipeline

---

## Bağlam ve Problem

Mevcut `c_namer.py` 6 strateji ile calisir: symbol, string-context, api-call, call-graph, dataflow, type-based. Ancak bunlar **genel heuristik'ler** -- binary'nin icindeki **somut ipuclarini** yeterince kullanmiyor.

Steam binary'si uzerinde yapilan analizde sunlar tespit edildi:

| Kaynak | Sayi | Ornek |
|--------|------|-------|
| Build path (kaynak dosya adlari) | 112 | `/build/src/filesystem/BaseFileSystem.cpp` |
| `m_` prefixli member degisken adlari | 289 | `m_SearchPaths`, `m_PackFileHandles` |
| `Class::Method` pattern'leri | 248 | `CHTTPClient::SendRequestForHandle` |
| Benzersiz class isimleri | 135 | `CNetConnection`, `CUDPSocket`, `CHTTPClient` |
| RTTI typeinfo entry'leri | 144 | `N6google8protobuf11MessageLiteE` |
| VTable symbol'leri | 12 | `__ZTVSt12length_error` |
| Protobuf referanslari | 307 | `google/protobuf/arena.cc` |
| Toplam string | 13889 | - |
| Toplam fonksiyon | 11398 | 575 named, 10823 auto-named |

**Sorun:** 10823 fonksiyonun ismi `FUN_XXXXXX`. Mevcut namer bunlarin bir kismini generic isimlerle adlandiriyor (`read_file`, `send_network_request` gibi), ama `CHTTPClient::SendRequestForHandle` gibi **spesifik orijinal isimleri** kurtaramiyor.

**Binary'de ZATEN var olan ama kullanilmayan bilgiler:**
1. Debug/assert string'lerinde member adlari ve class::method pattern'leri
2. RTTI tablosunda class isimleri
3. Build path'lerinde kaynak dosya ve namespace bilgisi
4. Protobuf descriptor'larinda field isimleri
5. Struct layout + bilinen framework struct'lari arasinda eslesme

---

## Karar

`c_namer.py`'nin mevcut 6 stratejisine ek olarak, 7 yeni **binary metadata extraction** stratejisi eklenir. Bunlar mevcut stratejilerin USTUNE calisir ve daha yuksek confidence degerlerine sahiptir.

### Mimari Genel Bakis

```
                    Binary (Mach-O / ELF / PE)
                              |
                    +--------------------+
                    |  Ghidra Analysis   |
                    +--------------------+
                              |
         +--------------------+--------------------+
         |                    |                    |
    ghidra_strings.json  ghidra_functions.json  ghidra_types.json
    ghidra_xrefs.json    ghidra_call_graph.json  symbols.json
         |                    |                    |
         +--------------------+--------------------+
                              |
                   +-----------------------+
                   | BinaryNameExtractor   |  <-- YENI MODUL
                   +-----------------------+
                   | 1. RTTI Extractor     |
                   | 2. Debug String Parse |
                   | 3. Build Path Map     |
                   | 4. ObjC Metadata      |
                   | 5. Protobuf Fields    |
                   | 6. Exception Types    |
                   | 7. Struct Layout Match|
                   +-----------------------+
                              |
                     BinaryNameDB (dict)
                     {
                       classes: {addr: name},
                       members: {(class, offset): name},
                       methods: {addr: (class, method)},
                       source_files: {addr_range: path},
                       field_names: {struct_name: {offset: name}},
                     }
                              |
                   +--------------------+
                   |  CVariableNamer    |  <-- MEVCUT (genisletilir)
                   |  (6+7 strateji)    |
                   +--------------------+
                              |
                   Named C files + naming_map.json
```

---

## 7 Yeni Strateji Detayi

### Strateji A: RTTI Class Name Recovery (conf: 0.92)

**Kaynak:** Binary'deki `_ZTI*` (typeinfo) ve `_ZTS*` (typeinfo name) symbol'leri + RTTI string'ler.

**Nasil Calisir:**
1. `ghidra_strings.json`'dan `_ZTI`, `_ZTS`, `_ZTV` prefix'li string'leri topla
2. `symbols.json`'dan `_Z` prefix'li export'lari topla
3. Itanium ABI mangled name'leri demangle et:
   - `_ZTI14CNetworkSocket` -> `typeinfo for CNetworkSocket` -> class name = `CNetworkSocket`
   - `N6google8protobuf11MessageLiteE` -> `google::protobuf::MessageLite`
4. Demangle icin `c++filt` subprocess calistir (mevcut `_try_demangle_cpp` yetersiz, sadece basit pattern'leri yakalyior)
5. Class name -> typeinfo address -> vtable address -> virtual method fonksiyon adreslerini zincirle
6. Bu fonksiyonlara `ClassName_virtualMethodN` ismi ver

**Neden `c++filt`:** Mevcut `_try_demangle_cpp` metodu sadece `_ZN...E` pattern'ini yakalyor. Gercek binary'lerde template, const, operator overload, nested namespace gibi durumlar var. `c++filt` bunlarin tamamini cozuyor ve macOS'ta default kurulu. Subprocess overhead negligible (tek seferlik batch call).

**Calisir:** C++ binary'ler (ELF, Mach-O). RTTI strip edilmemis olmali.

**Implementation:**
```
Dosya: karadul/reconstruction/binary_name_extractor.py
Sinif: RTTIExtractor
Metod: extract_class_names(strings_json, symbols_json) -> dict[str, str]
        # address -> demangled class/method name
```

**Tahmini Kazanim:** Steam binary'de 144 RTTI entry = ~144 class ismi kurtarilir. Bu class'larin vtable'larindan ek ~200-500 method ismi cikabilir.

---

### Strateji B: Debug String Deep Parse (conf: 0.85)

**Kaynak:** Assert, CHECK, log mesajlarindaki degisken ve fonksiyon adlari.

**Nasil Calisir:**
1. Tum string'leri tara, su pattern'leri cikart:

   a. **Assert member pattern:**
      ```
      "packfile.m_bIsPackFile"
      "m_FindData[ iFind ].wildCardString"
      "!m_LogFuncs.IsValidIndex(m_LogFuncs.Find(logFunc))"
      ```
      Regex: `m_[A-Za-z_][A-Za-z0-9_]*` -> member variable isimleri

   b. **Class::Method pattern:**
      ```
      "CHTTPClient::SendRequestForHandle"
      "CBaseFileSystem::Open"
      ```
      Regex: `([A-Z][A-Za-z]+)::([A-Za-z_][A-Za-z0-9_]*)` -> class + method

   c. **Assert expression pattern:**
      ```
      "assertion failed: temp != sh.freelist[slist]"
      "CHECK failed: (table_[b]) == (table_[b ^ 1])"
      ```
      Bu ifadelerden local degisken isimleri cikarilir

   d. **Member erisimleri:**
      ```
      "m_FindData[ iFind ].m_VisitedSearchPaths"
      ```
      Nested member field zinciri -> struct field isimleri

2. String'in referans verdigi fonksiyonu (`ghidra_xrefs.json`'dan) bul
3. O fonksiyon icindeki `param_1->` erisimlerini build path'ten gelen class ismiyle eslestir
4. Eger string "CHTTPClient::SendRequestForHandle" ise VE bu string `FUN_1234`'te referans ediliyorsa -> `FUN_1234` = `CHTTPClient_SendRequestForHandle`

**Critical Insight:** Steam binary'de 547 `m_` prefixli string + 248 `Class::Method` pattern var. Bunlarin cogu assert/CHECK macro'larindan geliyor. Derleyici bu string'leri binary'ye gommek zorunda cunku runtime'da assert mesaji yazdirmak icin kullaniliyorlar. Bu, debug symbol'ler strip edilse bile isim bilgisinin kaybolmamasinin sebebi.

**Calisir:** Tum C++ binary'ler (ozellikle debug/release with asserts). Valve/Source Engine binary'leri ozellikle zengin.

**Implementation:**
```
Dosya: karadul/reconstruction/binary_name_extractor.py
Sinif: DebugStringParser
Metod: parse_debug_strings(strings, xrefs) -> DebugNameDB
        # class_methods: {func_addr: (class, method)}
        # member_names: set[str]  (m_XXX isimleri)
        # local_var_names: dict[func_addr, list[str]]
```

**Tahmini Kazanim:**
- 248 Class::Method -> 248 fonksiyon ismi (dogrudan)
- 289 member variable ismi -> struct field renaming
- ~50 local variable ismi (assert expression'lardan)

---

### Strateji C: Build Path Mapper (conf: 0.80)

**Kaynak:** Build path string'leri: `/opt/buildbot/.../src/filesystem/BaseFileSystem.cpp`

**Nasil Calisir:**
1. String'lerden build path pattern'ini cikart:
   ```
   /opt/buildbot/buildworker/steam_rel_client_hotfix_osx/build/src/(.+)\.(cpp|h|cc|mm)
   ```
2. Kaynak dosya adini parse et:
   - `filesystem/BaseFileSystem.cpp` -> module=`filesystem`, class=`BaseFileSystem`
   - `vstdlib/commandline.cpp` -> module=`vstdlib`, class=`CommandLine`
   - `steamexe/main.cpp` -> module=`steamexe`
3. Build path string'inin xref'inden fonksiyonu bul
4. Ayni fonksiyondan referans edilen diger string'lerle birlestir:
   - Build path `filesystem/BaseFileSystem.cpp` + debug string `CBaseFileSystem::Open` = tam isim
5. Build path'i olmayan fonksiyonlar icin, ayni moduldeki digerleriyle gruplandir

**Ek Deger:** Build path, fonksiyonun hangi SOURCE DOSYAYA ait oldugunu verir. Bu bilgi project_builder (kaynak dosya yeniden olusturma) icin de degerli. Fonksiyonlari dogru .c dosyalarina ayirabilir.

**Calisir:** Assert/debug macro'lu tum C/C++ binary'ler. Valve, Google, Mozilla binary'lerinde yaygin.

**Implementation:**
```
Dosya: karadul/reconstruction/binary_name_extractor.py
Sinif: BuildPathMapper
Metod: map_build_paths(strings, xrefs) -> BuildPathDB
        # func_to_source: {func_addr: source_path}
        # source_to_module: {source_path: (module, class_hint)}
```

**Tahmini Kazanim:** 112 build path = ~112 fonksiyonun modulu/sinifi belirlenir. Dolayli olarak yaklasik ~500-1000 fonksiyon ayni module gruplanir (ayni kaynak dosyadaki fonksiyonlarin adresleri ardisik olur).

---

### Strateji D: ObjC Runtime Metadata (conf: 0.93)

**Kaynak:** Objective-C class/method isimleri binary'de plaintext olarak saklanir. Mach-O `__objc_methname`, `__objc_classname`, `__objc_methtype` section'lari.

**Nasil Calisir:**
1. `symbols.json`'dan `_OBJC_CLASS_$_XXX` export'lari -> class isimleri
2. `ghidra_strings.json`'dan ObjC selector pattern'leri: `initWithFrame:`, `viewDidLoad` vb.
3. Ghidra'nin zaten parse ettigi ObjC metadata'yi kullan (Ghidra ObjC binary'leri iyi parse eder)
4. `[ClassName methodName:]` pattern'lerini string'lerden cikart
5. ObjC dispatch (`objc_msgSend`) call site'larindaki selector string'ini oku -> method adini kur

**Mevcut Durum:** `c_namer.py` zaten `_OBJC_CLASS_$_XXX` pattern'ini taniyor (Strateji 1, satir 881-891). Ancak:
- Sadece fonksiyon adi icinde gecen ObjC class'lari yakaliyor
- String'lerdeki selector'leri isle**mi**yor
- `objc_msgSend` call site'larindaki selector parametresini isle**mi**yor

**Genisletme:**
- ObjC selector string'lerini `objc_msgSend` cagiran fonksiyonlarla eslestir
- Her `objc_msgSend(receiver, "selectorName:", ...)` -> fonksiyon icindeki bu cagriyi `[receiver selectorName:]` olarak adlandir

**Calisir:** macOS/iOS Mach-O binary'ler (ObjC iceren). Steam'de sinirli ObjC (UI katmani).

**Implementation:**
```
Dosya: karadul/reconstruction/binary_name_extractor.py
Sinif: ObjCMetadataExtractor
Metod: extract_objc_names(strings, symbols, xrefs) -> ObjCNameDB
        # classes: {addr: class_name}
        # methods: {addr: (class, selector)}
```

**Tahmini Kazanim:** Steam binary'de sinirli (UI katmani). Tipik bir ObjC app'te fonksiyonlarin %60-80'i kurtarilabilir.

---

### Strateji E: Protobuf Field Recovery (conf: 0.75)

**Kaynak:** Protobuf compile ciktisinda field name'ler string olarak kalir.

**Nasil Calisir:**
1. Protobuf-related string'leri bul:
   - `.proto` uzantili dosya path'leri
   - `google/protobuf/` prefix'li string'ler
   - Protobuf message descriptor pattern'leri
2. Protobuf generated code pattern'lerini tani:
   - `SerializeWithCachedSizes`, `MergePartialFromCodedStream` gibi method isimleri
   - Field number constant'lari (1-536870911 araliginda)
   - `_has_bits_` pattern
3. Message field name'lerini cikart:
   - Protobuf reflection descriptor string'lerinde field isimleri saklanir
   - `"name"`, `"email"`, `"phone_number"` gibi
4. Descriptor'dan field -> offset eslesmesiyle struct field'larini adlandir

**Calisir:** Protobuf kullanan tum binary'ler. Steam binary'de 307 proto-related string tespit edildi.

**Implementation:**
```
Dosya: karadul/reconstruction/binary_name_extractor.py
Sinif: ProtobufFieldExtractor
Metod: extract_proto_fields(strings, structs) -> ProtoFieldDB
        # message_names: set[str]
        # field_names: dict[message_name, dict[field_num, field_name]]
```

**Tahmini Kazanim:** ~50-100 protobuf message field ismi.

---

### Strateji F: Exception Type Recovery (conf: 0.88)

**Kaynak:** C++ exception handling'de `catch` bloklarinin type bilgisi binary'de RTTI olarak saklanir.

**Nasil Calisir:**
1. RTTI typeinfo string'lerinden exception class'larini tani:
   - `N6google8protobuf14FatalExceptionE` -> `google::protobuf::FatalException`
   - `__ZTISt12length_error` -> `std::length_error`
2. Exception personality function (`__gxx_personality_v0`) referanslarindan try-catch fonksiyonlarini bul
3. LSDA (Language Specific Data Area) tablosundan catch edilen tip -> typeinfo eslesmesini coz
4. Fonksiyon icindeki `___cxa_throw` cagrilarindan throw edilen tip bilgisini cikart

**Not:** Bu strateji sinirli bilgi verir ama verdigi bilgi cok guvenilir (exception tipi = class ismi).

**Calisir:** C++ binary'ler (RTTI + exception handling etkin).

**Implementation:**
```
Dosya: karadul/reconstruction/binary_name_extractor.py
Sinif: ExceptionTypeExtractor
Metod: extract_exception_types(strings, functions) -> dict[str, str]
        # func_addr -> exception class name
```

**Tahmini Kazanim:** ~25-50 exception tipi = ek class isimleri.

---

### Strateji G: Struct Layout Fingerprinting (conf: 0.70)

**Kaynak:** Recovered struct'larin field layout'u (offset, type, size) bilinen framework struct'lariyla eslestirilir.

**Nasil Calisir:**
1. `c_type_recoverer.py`'nin urettigi `RecoveredStruct` listesini al
2. Bilinen framework struct database'iyle karsilastir:
   ```
   Bilinen struct: sockaddr_in
     offset 0x00: sa_len (uint8_t, 1 byte)
     offset 0x01: sa_family (sa_family_t, 1 byte)
     offset 0x02: sin_port (in_port_t, 2 bytes)
     offset 0x04: sin_addr (struct in_addr, 4 bytes)
     offset 0x08: sin_zero (char[8], 8 bytes)
     total: 16 bytes
   ```
3. Recovered struct'in field offset + type + size pattern'ini hash'le
4. Bilinen struct hash'leriyle karsilastir
5. Eslesme varsa:
   - Struct ismini degistir (`recovered_struct_001` -> `sockaddr_in`)
   - Field isimlerini degistir (`field_0` -> `sa_len`, `field_2` -> `sin_port`)

**Bilinen Struct Database Kaynaklari:**
- POSIX/BSD: `sockaddr_in`, `stat`, `dirent`, `timeval`, `pollfd`, `msghdr`
- macOS: `mach_header_64`, `load_command`, `segment_command_64`, `dispatch_queue_s`
- OpenSSL: `SSL_CTX`, `SSL`, `EVP_MD_CTX`, `BIO`
- Valve/Source: `CUtlVector` (m_Memory, m_Size, m_Elements pattern'i), `CUtlString`
- Protobuf: `google::protobuf::Arena`, `MessageLite`

**Calisir:** Tum binary tipleri. Layout bilgisi dile bagli degil.

**Implementation:**
```
Dosya: karadul/reconstruction/struct_fingerprint_db.py  (yeni)
Sinif: StructFingerprintDB
Metod: match_struct(recovered: RecoveredStruct) -> Optional[(name, field_names, conf)]

Dosya: karadul/reconstruction/binary_name_extractor.py
Sinif: StructLayoutMatcher
Metod: match_all_structs(recovered_structs, fingerprint_db) -> dict[str, str]
```

**Tahmini Kazanim:** ~20-40 struct ismi (POSIX + framework struct'lar). Valve-specific struct'lar icin (`CUtlVector`, `CUtlString` vb.) ek ~30-50.

---

## Teknik Kararlar

### Yeni Dosyalar

| Dosya | Icerik | Satir (tahmin) |
|-------|--------|----------------|
| `karadul/reconstruction/binary_name_extractor.py` | 7 extractor sinifi + BinaryNameDB | ~800 |
| `karadul/reconstruction/struct_fingerprint_db.py` | Bilinen struct layout database | ~400 |
| `karadul/reconstruction/itanium_demangler.py` | c++filt wrapper + fallback pure-Python demangle | ~150 |
| `tests/test_binary_name_extractor.py` | Unit testler | ~300 |

### Mevcut Dosya Degisiklikleri

| Dosya | Degisiklik |
|-------|------------|
| `karadul/reconstruction/c_namer.py` | `BinaryNameDB`'yi input olarak al, 7 yeni stratejiye dispatch et. `analyze_and_rename()` signature'i genisler. |
| `karadul/reconstruction/c_type_recoverer.py` | `StructFingerprintDB` ile eslestirme adimi eklenir. RecoveredStruct isimleri guncellenir. |
| `karadul/ghidra/scripts/string_extractor.py` | String'lere xref (referans veren fonksiyon adresi) bilgisini ekle. SU AN `function` alani var ama bos geliyor (Ghidra API'si dogru kullanilmiyor). |
| `karadul/stages.py` | Reconstruct stage'ine `BinaryNameExtractor` cagrisini ekle. |
| `karadul/analyzers/macho.py` | `nm` ciktisindaki mangled name'leri ayri JSON olarak kaydet (RTTI extraction icin). |

### Kritik Duzeltme: String-Function XREF Sorunu

Mevcut `ghidra_strings.json`'da `"function": null` geliyor -- 13889 string'in HICBIRI fonksiyon referansi tasimiyor. Bu buyuk bir kayip.

**Neden:** `string_extractor.py`'de `getFunctionContaining(data.getAddress())` kullaniliyor. Bu sadece string DATA'sinin fonksiyon icinde oldugu durumu yakalyor. Oysa string genelde `.rodata` section'da, fonksiyon `.text` section'da. Dogru yaklasim: string'e XREF veren fonksiyonlari bulmak.

**Cozum:** Ghidra script'inde su degisiklik:
```python
# YANLIS: String'in kendisinin fonksiyon icinde olmasi
func = getFunctionContaining(data.getAddress())

# DOGRU: String'e referans veren fonksiyonlari bul
refs = getReferencesTo(data.getAddress())
referring_funcs = set()
for ref in refs:
    func = getFunctionContaining(ref.getFromAddress())
    if func is not None:
        referring_funcs.add(func.getName())
entry["refs"] = list(referring_funcs)
```

Bu duzeltme YAPILMADAN Strateji B ve C'nin calisma gucune buyuk darbe vurur. **Oncelik 0.**

---

## Strateji Oncelik Sirasi (Implementation Order)

| Oncelik | Strateji | Neden |
|---------|----------|-------|
| 0 | Ghidra string xref duzeltmesi | Diger tum stratejiler buna bagimli |
| 1 | B: Debug String Parse | En fazla isim kurtaran (248 class::method + 289 member) |
| 2 | C: Build Path Mapper | Fonksiyon->kaynak dosya eslesmesi, proje yapisi icin kritik |
| 3 | A: RTTI Extractor | 144 class ismi, vtable chain'leri |
| 4 | G: Struct Layout Match | Struct isimleri + field isimleri |
| 5 | F: Exception Types | Ek class isimleri |
| 6 | E: Protobuf Fields | Protobuf message field isimleri |
| 7 | D: ObjC Metadata | Steam'de sinirli, ama genelde degerli |

---

## Confidence Hiyerarsisi (Tum 13 Strateji)

```
 Conf   Strateji                 Kaynak
 ----   --------                 ------
 0.95   Symbol-Based (mevcut)    Export/debug symbol
 0.93   D: ObjC Metadata         ObjC runtime, derleyici garantili
 0.92   A: RTTI                  C++ ABI, derleyici garantili
 0.88   F: Exception Types       RTTI + LSDA, derleyici garantili
 0.85   B: Debug String          Assert/CHECK macro, derleyici embed etti
 0.80   C: Build Path            __FILE__ macro, derleyici embed etti
 0.75   E: Protobuf Fields       Protobuf descriptor, code-gen garantili
 0.70   G: Struct Layout         Fingerprint eslesmesi, istatistiksel
 ----   --- mevcut stratejiler ---
 0.7-0.9 String-Context (mevcut) Genel string heuristic
 0.6-0.8 API-Call (mevcut)       API kullanim pattern
 0.5-0.7 Call-Graph (mevcut)     Graf pozisyonu
 0.3-0.5 Dataflow (mevcut)       Parametre kullanimi
 0.2-0.4 Type-Based (mevcut)     Tip bilgisi
```

---

## Tahmini Isim Kurtarma Yuzdeleri

### Steam binary (mevcut vs yeni)

```
                        Mevcut     Yeni (tahmini)
Fonksiyonlar:           10823 auto + 575 named
  High conf (>=0.7):     ~100      ~650-800
  Medium conf (0.4-0.7): ~300      ~500-700
  Low conf (<0.4):       ~800      ~400-500
  Isimsiz kalan:        ~9600      ~8800-9300
  ---------
  Kurtarma orani:        ~11%      ~18-24%
```

**Neden %100 degil:** Strip edilmis release binary'de fonksiyonlarin cogunun isim bilgisi YOKTUR. assert/debug string'ler sadece debug macro'lu fonksiyonlarda bulunur. RTTI sadece class isimleri verir, standalone C fonksiyonlari icin bilgi yoktur. ~75-80% isimsiz kalma normaldi.

### Binary tipine gore tahmini kurtarma oranlari

| Binary Tipi | Mevcut | Yeni | Aciklama |
|-------------|--------|------|----------|
| C++ (RTTI + asserts, Valve gibi) | ~11% | ~20-25% | RTTI + debug string'ler zengin |
| C++ (stripped, RTTI off) | ~8% | ~10-12% | Sadece API + dataflow calisir |
| ObjC (macOS app) | ~30% | ~75-85% | ObjC metadata hemen her seyi verir |
| Swift (macOS app) | ~20% | ~50-60% | Swift type descriptor zengin (gelecek is) |
| Pure C (no debug) | ~5% | ~7-10% | Build path + struct layout katkisi |
| Protobuf-heavy (gRPC service) | ~10% | ~25-30% | Proto descriptor field isimleri |
| Electron (Node.js native) | ~15% | ~20-25% | npm fingerprint + V8 internal |

---

## Veri Akis Diyagrami

```
ghidra_strings.json ----+
                        |
symbols.json -----------+
                        |     +------------------+
ghidra_functions.json --+---->| BinaryNameExtract|
                        |     |                  |
ghidra_xrefs.json ------+     | A: RTTI          |---> class_names{}
                        |     | B: DebugString   |---> class_methods{}
ghidra_types.json ------+     | C: BuildPath     |---> func_to_source{}
                        |     | D: ObjC          |---> objc_names{}
ghidra_call_graph.json -+     | E: Protobuf      |---> proto_fields{}
                              | F: Exception     |---> exception_types{}
                              | G: StructLayout  |---> struct_names{}
                              +--------+---------+
                                       |
                                  BinaryNameDB
                                       |
                              +--------v---------+
                              |  CVariableNamer  |
                              |  (enhanced)      |
                              |                  |
                              | lookup order:    |
                              | 1. BinaryNameDB  |
                              | 2. Symbol-Based  |
                              | 3. String-Context|
                              | 4. API-Call      |
                              | 5. Call-Graph    |
                              | 6. Dataflow      |
                              | 7. Type-Based    |
                              +--------+---------+
                                       |
                                 named_c/*.c
                                 naming_map.json
```

---

## Dikkat Edilecek Noktalar

### 1. False Positive Riski
Debug string'lerdeki isimler bazen YANLIS fonksiyona atanabilir. Ornegin bir assert string'i fonksiyon A'da kullanilir ama string xref'i fonksiyon B'yi gosterir (inline edilmis fonksiyonlar). **Cozum:** Birden fazla kaynaktan gelen isimleri cross-validate et. Ayni fonksiyon icin RTTI + debug string + build path tutarliysa confidence artir, tutarsizsa dusur.

### 2. Inline Fonksiyon Sorunu
Derleyici optimizasyonu ile fonksiyonlar inline edildiginde, assert string'leri baska bir fonksiyonun body'sine gomer. **Cozum:** Bir fonksiyonda birden fazla CLASS::METHOD string'i varsa, buyuk ihtimalle inline edilmistir. En disttaki (en genel) ismi kullan veya `inlined_` prefix ekle.

### 3. Performans
13889 string * 11398 fonksiyon = ~158M potansiyel eslesme. Bunu brute-force yapma. **Cozum:** Xref-based lookup (string -> referans veren fonksiyonlar, O(1) dict lookup). Xref yoksa adres-proximity heuristic (string adresi ile fonksiyon adresi yakinsa).

### 4. Struct Fingerprint Collision
Farkli struct'lar ayni layout'a sahip olabilir (ornegin 2 pointer + 1 int). **Cozum:** Fingerprint'e sadece offset+type degil, ayni fonksiyonda kullanilan API/string bilgisini de ekle. Minimum 4 field eslesme gerekmeli.

---

## Alternatifler

### A. LLM Kullanimini Tamamen Reddetme
Bu yaklasim LLM kullanmiyor, iyi. Ama kurtarma orani %20-25'te tavanliyor. Gelecekte **hibrit yaklasim** (LLM-assisted naming for low-confidence ones) dusunulebilir. Ama ONCE bu pipeline tamamlanmali.

### B. IDA Pro + HexRays Kullanimi
IDA'nin FLIRT signature'lari ve Lumina veritabani ek isim kurtarma saglar. Ancak IDA lisansi gerektirir ve Ghidra pipeline'a entegrasyon zordur. **Reddedildi.**

### C. Binary Diffing (BinDiff/Diaphora)
Eger ayni yazilimin debug build'i veya eski bir versiyonu mevcutsa, binary diff ile isim transferi yapilabilir. Bu cok guvenilir ama her hedef icin debug binary bulmak gerekir. **Gelecek is olarak not edildi.**

---

## Sonuc

7 yeni strateji ile isim kurtarma orani ~11%'den ~20-25%'e cikarilabilir. En buyuk kazanc Debug String Parse (Strateji B) ve RTTI (Strateji A)'dan gelir. Bunlar binary'de ZATEN mevcut olan bilgiyi kullanir, LLM veya tahmin gerektirmez.

Oncelik 0 olarak Ghidra string xref sorunu duzeltilmelidir -- bu olmadan stratejilerin cogu yarim kapasiteyle calisir.
