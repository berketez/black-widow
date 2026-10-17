# rea incelemesi 2: Apple/Mach-O ve dil meta verisi okuyucuları

- **Tarih:** 2026-10-17
- **İnceleyen:** Architect ajanı. Yalnız okuma yapıldı; rea'nın hiçbir betiği, testi ya da npm komutu çalıştırılmadı.
- **İncelenen depo:** `github.com/morluto/rea` (MIT, "Copyright (c) 2026 morluto"), sığ klon.
- **Karşılaştırılanlar:**
  - Karadul: `~/Black_Widow` çalışma ağacı.
  - Ghidra 12.0 DEV kaynak ağacı: `~/Desktop/dosyalar/uygulamalar/ghidra`, git `4fcc1febdd`.
  - Uygulamanın gömülü Ghidra 12.1.2 `Base.jar`'ı: `~/Library/BlackWidowBuild/ghidra_12.1.2_PUBLIC`, `javap` ile okundu.
- **İşaretler:** **[D]** koddan doğrulandı (dosya:satır verildi). **[T]** tahmin ya da ölçülmemiş.
- **Ghidra atıfları:** "12.0 DEV" kaynak satırını, "12.1.2" jar bayt kodunu gösterir.

## Özet

1. rea'nın Mach-O katmanının çoğu Ghidra 12.1.2'nin zaten yaptığını tekrarlıyor: chained fixups (Ghidra 13 biçim, rea 5), ObjC metot adları ve tip kodlamaları; LC_FUNCTION_STARTS'ı rea hiç okumuyor [D].
2. Karadul'a yeni üç parça var [D]: (a) AArch64 Swift String literal çözücüsü, (b) Swift vtable ve tanık yuvasından IMP'ye eşleme, (c) harici sınıf kategorisinin sahibini bind sembolünden çözme.
3. Hiçbiri doğrudan tam isim vermiyor: (a) kanıt, (b) sınıf aidiyeti ve metot türü verir; (c) Ghidra'nın büyük olasılıkla atladığı kategori metotlarını kurtarır [T, ölçülmeli].
4. Swift'te asıl büyük kesin isim kaynağı rea'da yok: harici protokol tanıkları (`…Tq` import adları) üzerinden isimlendirme (Fikir 2) [T].
5. Mac hedefi için değersiz olanlar [D]: NativeAOT (yalnız x64 PE, ad yok), Go (yalnız buildinfo), Rust (yalnız cargo-auditable), Flutter (yalnız APK kimliği). Go'da ve Rust demangle'da Karadul önde.
6. Kilitli test seti 15 C programı [D: `docs/arge/test_seti_kilidi.md`]; makale sayılarına etki ≈0. Swift/ObjC için ayrı küme gerekir (KS-7, ÖL-2).

## Kullanılabilir özellikler

### Genel tablo: rea Mach-O'dan ne okuyor? (Soru 1 ve Soru 6'nın Karadul tarafı)

| Yapı | rea | Ghidra 12.1.2 ve Karadul | İsim, tip ya da işaretçi haritasına katkı |
|---|---|---|---|
| LC_FUNCTION_STARTS | Okumuyor [D: `src` ve `bridge` altında `FUNCTION_STARTS` geçmiyor] | **Ghidra:** "Mach-O Function Starts" çözümleyicisi varsayılan olarak açık [D: 12.1.2 javap `setDefaultEnablement(true)`; 12.0 DEV `MachoFunctionStartsAnalyzer.java:54,89`]. <br>**Karadul:** Ghidra boyutu 118/118 fonksiyonda bu aralıkla örtüşüyor (`karadul/analyzers/byte_pattern_matcher.py:743`) | KS-2: rea'dan katkı yok |
| Chained fixups (LC_DYLD_CHAINED_FIXUPS) | Saf TS çözücü [D: `src/native/AppleMachoFixups.ts`]: <br>• 5 işaretçi biçimi (1, 2, 6, 9, 12) (`:53-59`); <br>• içe aktarma biçimi 1-3 (`:97-150`); <br>• işaretçi çözme (`:153-192`). <br>Eski `LC_DYLD_INFO`'da yalnız bind çözülüyor; rebase opkodları sayılıp bırakılıyor (`:48`) | **Ghidra:** 13 biçimin hepsini uyguluyor ve her fixup'ı relocation tablosuna adres, değer ve sembolle yazıyor [D: 12.0 DEV `DyldChainedPtr.java:28-40`, `DyldChainedFixups.java:164-221`; 12.1.2'de 3 `RelocationTable.add` çağrısı]. <br>**Karadul:** relocation tablosunu dışa aktarmıyor [D: `karadul/ghidra` altında `getRelocationTable` yok] | TR-4 ve TP-4 işaretçi haritası. Kaynak rea değil, Ghidra olmalı (Fikir 1) |
| Export trie | `dyld_info -exports` ve `nm -gjU` çağırıyor; kendi ayrıştırıcısı yok [D: `src/native/NativeMachoInspection.ts:47-56`] | **Ghidra:** `DyldExportsTrieCommand` | Apple `strip` trie'yi `__mh_execute_header`'a indiriyor (sentez Kİ-2). İsim kaynağı değil |
| LC_BUILD_VERSION | **TS okuyucu:** yalnız platform [D: `src/artifacts/apple/MachoLoadCommandReader.ts:401-417`]. <br>**`otool -l` ayrıştırıcısı:** platform, minos, sdk ve araç kayıtları (CLANG/SWIFT/LD/LLD…) [D: `src/native/parsers/otool.ts:72-110, 381-394`] | **Karadul:** `otool -l` çıktısını ham saklıyor, ayrıştırmıyor [D: `karadul/analyzers/macho.py:491-521`; `minos`/`BUILD_VERSION` hiçbir yerde geçmiyor] | KS-5 profiline girdi (Kalem 4) |
| Kod imzası ve entitlements | **TS:** yalnız "var mı" [D: `MachoLoadCommandReader.ts:391-400`]. <br>**Ayrıntı:** `codesign -d --verbose=4` ve `--entitlements :-` ile [D: `src/native/parsers/codesign.ts:6-13`, `src/native/NativeMacOSProvider.ts:641`] | — | Yalnız kimlik; isim yok |
| `__objc_*` | `__objc_protolist`, `__objc_classlist`, `__objc_catlist` okunuyor [D: `src/native/AppleObjcDispatchFacets.ts`, `src/native/AppleObjcCategories.ts:42`]: <br>• sınıf ve üst sınıf; harici üst sınıf bind'den (`:49-70`); <br>• göreli ve mutlak metot listeleri, seçici → IMP (`:101-197`); <br>• ivar: ad, tip kodlaması, ofset, boyut, hizalama (`:280-320`); <br>• özellikler, protokoller, kategoriler. <br>Metot tip kodlaması okunmuyor (yalnız ivar'ınki: `:307`) | **Ghidra:** `ObjcTypeMetadataAnalyzer` varsayılan olarak açık [D: 12.1.2 javap]. Göreli metot listesi destekleniyor [D: 12.1.2 `Objc2MethodList.isSmallMethods`]. Tip kodlamasıyla imza kuruluyor [D: 12.0 DEV `ObjectiveC1_Utilities.java:318,342`]. <br>**Karadul:** ObjC tarafı tümüyle bu Ghidra adlarına dayanıyor [D: `karadul/reconstruction/engineering/dispatch_resolver.py:555-595`] | Metot adlarını Ghidra zaten veriyor. Fark iki yerde: harici sınıf kategorileri (Kalem 3) ve ivar düzeni (Kalem 5) |
| `__swift5_*` | Yalnız iki bölüm okunuyor: `__swift5_types` (vtable) ve `__swift5_proto` (uyum ve statik tanık) [D: `src/native/AppleDispatchMetadata.ts:140`, `src/native/AppleSwiftDispatchFacets.ts:100`]. `__swift5_fieldmd`, `__swift5_reflstr` ve `__swift5_typeref` okunmuyor [D: grep boş] | **Ghidra:** Swift bölümlerinin çoğunu ayrıştırıp veri yapısı olarak işaretliyor, fonksiyona ad koymuyor [D: 12.1.2 javap; `SwiftTypeMetadataAnalyzer` ayrıştırıcıyı kurup yalnız `markup()` çağırıyor; `markup()` içinde etiket ya da fonksiyon oluşturan çağrı yok]. <br>**Karadul:** Swift desteği sembol tabanlı [D: `karadul/analyzers/swift_binary.py:586-736`] | vtable ve tanık yuvasından IMP'ye aidiyet (Kalem 2) |
| Swift String literal (kod içinde gömülü) | AArch64 için Ghidra köprüsünde bir çözücü var [D: `bridge/ghidra/ReaGhidraBridge.java:3960-4272`] | **Ghidra:** yok. <br>**Karadul:** dize ile fonksiyonu yalnız tanımlı veri ve xref üstünden bağlıyor [D: `karadul/ghidra/scripts/string_extractor.py:67, 94, 108`] | Kanıt (Kalem 1) |

### 1. Swift String literal çözücüsü (AArch64), en değerli parça

**Ne yapıyor?**
- Swift `String`'i iki yazmaçla taşır. 15 bayta kadar olan dizeler bu yazmaçlara anlık değer olarak gömülür, yani veri bölümünde hiç yer almazlar.
- Büyük literallerde ikinci kelimeyi oluşturmak için dizenin adresinden 0x20 çıkarılır ve sonuç `0x80…` ile işaretlenir.
- rea, Ghidra'nın `SymbolicPropogator`'ıyla her fonksiyonda sabit değerli yazmaç çiftlerini izliyor. Baktığı yerler: çağrılarda x0..x7 içindeki ardışık çiftler, dönüşte x0/x1, kuyruk çağrıları ve `stp` çiftleri [D: `:4064-4096`].
- Biçim ayrımı [D: `:4164-4199`]:
  - **Küçük dize:** üst dört bit 0xE (ASCII) ya da 0xA; uzunluk 56-59. bitlerde.
  - **Büyük dize:** bayrak 0xD ya da 0x1; uzunluk alt 48 bitte; adres `(object & 0x00FF…) + 0x20`.
- Yola bağlı (koşullu seçimden gelen) değerleri eliyor [D: `:4106-4138`]. Çözülemeyen atlamaları ayrı bir "eksik" listesine yazıyor [D: `:4041-4048`].

**Kanıt:**
- Çözücü: `bridge/ghidra/ReaGhidraBridge.java:3952-4272`; hatta bağlandığı yer `:1585-1631`.
- Doğrulama betiği: `swiftc -O` ile bilinen küçük, büyük, Unicode ve boş literalleri sınıyor [D: `scripts/verify-real-ghidra-swift.mjs:60-61, 100-110, 227-235`; çalıştırılmadı].

**Karadul'da karşılığı:** Yok [D].
- `string_extractor.py:67` yalnız `DefinedDataIterator.definedStrings`'i geziyor; `:94` xref topluyor. Küçük Swift dizeleri bu yolla hiç görünmez [D].
- Büyük literallerde kod adresi 0x20 geriden kurduğu için xref'in ya hiç oluşmaması ya da yanlış adrese gitmesi beklenir. Bu rea'nın yorumunda yazıyor (`:3961-3964`); Karadul'da ölçülmedi [T].

**Plan kalemi:** Yeni kalem önerisi; KS-7'nin "Swift dize kanıtı" alt kalemi olabilir. Kayıtta hangi çağrının hangi argüman çiftinde geçtiği tutuluyor (`source_address`, `registers`). Bu, TR-2'nin "argüman olarak geçen dize çağırana aittir" kuralına ve MD-2 kanıt paketine doğrudan girer.

**Beklenen etki:**
- Swift fonksiyonlarında dize kanıtının kapsamı artar (KP↑). Bunun ne kadar yakın isme dönüşeceği Karadul'un dize tabanlı tarif kurallarına bağlı [T].
- C programlarında etki 0. Çözücü yalnız `__swift5_` bölümü olan programda açılıyor [D: `:3952-3958`].

**Uyarlama yolu: M.**
- Karadul'un Ghidra betikleri PyGhidra 3.0 ile yazılıyor [D: `string_extractor.py:1`].
- Yaklaşık 300 satırlık Java mantığı PyGhidra'ya taşınır. Python'dan `ContextEvaluator` uygulanamazsa küçük bir Java GhidraScript yazılır (Açık soru 6).
- MIT telif notu korunur.

**Nasıl ölçülür?**
- (a) Bilinen literalleri içeren bir Swift kaynağı `swiftc -O` ile derlenir, Apple `strip` ile soyulur. Her literalin doğru fonksiyona bağlanmasının kesinliği ve duyarlılığı ölçülür; GT, strip öncesi sembollerden gelir.
- (b) Gerçek bir Mac Swift uygulamasında "en az bir dize kanıtı olan Swift fonksiyonu oranı" önce ve sonra karşılaştırılır.
- (c) C programlarında kayıt sayısının 0 olduğu denetlenir.

### 2. Swift sınıf vtable'ı ve statik tanık tablosundan IMP eşlemesi

**Ne yapıyor?**
- `__swift5_types`'taki sınıf tanımlayıcısından vtable başlığını buluyor. Yalnız jenerik olmayan ve dayanıklı üst sınıfı olmayan sınıflar işleniyor [D: `src/native/AppleSwiftVtables.ts:20-125`].
- Başlığın yeri: tanımlayıcı + 44, artı başlatma türüne göre 0/4/12 bayt [D: `:60`].
- Her `MethodDescriptor` için bayrağı ve göreli uygulama işaretçisini okuyor. Sonuç: "X sınıfının N. yuvası → IMP adresi".
- `__swift5_proto`'dan üçlüyü (tip adı, protokol adı, tanık tablosu) alıyor ve statik tanık yuvalarını IMP'ye bağlıyor [D: `src/native/AppleSwiftDispatchFacets.ts:85-243`].
- Gereksinim adını vermiyor: `requirement: null` [D: `AppleSwiftVtables.ts:97`, `AppleSwiftDispatchFacets.ts:201`].
- async, coroutine ve kalıtılmış override yuvalarını "kısmi" diye işaretliyor [D: `AppleSwiftVtables.ts:90, 127`].

**Karadul'da karşılığı:** Yok [D].
- `swift_binary.py` yalnız `nm`, `strings` ve `swift-demangle` kullanıyor. Strip'li ikilide yerel Swift sembolü kalmaz.
- Ghidra 12.1.2 vtable'ı ve metot tanımlayıcılarını ayrıştırıyor [D: javap; `TargetClassDescriptor`'da `vtableHeader` ve `methodDescriptors` alanları var]. Ama yalnız veri yapısı işaretliyor, fonksiyona ad koymuyor [D: javap].

**Plan kalemi:** KS-7.

**Beklenen etki:**
- Swift sınıf metotları kesin sınıf öneki kazanır.
- Metot türü de bayraktan kesin olarak okunur: init, getter, setter, method. rea bu bilgiyi yalnız süzgeçte kullanıp atıyor (`:90`); Karadul bunu ada taşımalı (`Foo.init`, `Foo.getter_3`).
- Sonuç "tam isim" değil, "sınıf + metot türü" düzeyinde bir yakın isimdir. Kapsamı ve doğruluğu ölçülmedi [T].

**Uyarlama yolu: S–M.**
- rea'nın mantığı yaklaşık 150 satır; göreli işaretçi okumak PyGhidra'da kolay [T].
- Öbür yol, Ghidra'nın uyguladığı tanımlayıcı veri yapılarını gezmek. Bu daha kırılgan [T].

**Nasıl ölçülür?**
- Swift sınıfları içeren bir test programı derlenir. Strip öncesi `$s…` sembolleri `swift-demangle` ile çözülüp GT olarak kullanılır.
- Ölçütler: yuvadan doğru sınıf metoduna eşleşme kesinliği, metot türü isabeti, sınıf öneki alan Swift fonksiyonlarının oranı.

### 3. ObjC kategori sahibini bind sembolünden çözme (ayrıca Ghidra'dan bağımsız bir ObjC kehaneti)

**Ne yapıyor?**
- `category_t.cls` alanı başka bir imajdaki sınıfı gösterebilir (ör. `NSString`). rea bu durumda sınıf adını fixup bind sembolünden (`_OBJC_CLASS_$_NSString`) çıkarıyor [D: `src/native/AppleObjcCategories.ts:10-16, 55-66`].
- Ardından kategorinin metotlarını, protokollerini ve özelliklerini çözüyor.
- Harici üst sınıfı da aynı yolla buluyor [D: `AppleObjcDispatchFacets.ts:49-70`].

**Ghidra ve Karadul'da karşılığı:**
- Ghidra 12.1.2'de `Objc2Category` kurucusu iki durumda kategorinin örnek ve sınıf metotlarını, protokollerini ve özelliklerini hiç okumuyor: `cls == null` ya da `cls.getISA() == null` [D: javap bayt kodu, iki `ifnull 57` dalı; 12.0 DEV kaynağında da aynı: `ObjectiveC2_Category.java:46-51`].
- `readClass` bind edilmiş ya da harici sınıf için özel bir yol içermiyor [D: javap; 12.0 DEV `:90-104`].
- Bu yüzden NSString, NSView gibi harici sınıflara eklenen kategori metotları büyük olasılıkla adsız `FUN_` kalıyor [T: ölçülmedi, Açık soru 1].
- Karadul'un ObjC tarafı tümüyle Ghidra'nın adlarına dayanıyor [D: `dispatch_resolver.py:555-595`].

**Plan kalemi:** KS-7. Bağımsız çözücü aynı zamanda ÖL-2'de ObjC kesin isim kanalı için bir kehanet olur.

**Beklenen etki:** AppKit ve Foundation'a kategori ekleyen ObjC uygulamalarında TM↑ ve KP↑ [T]. C programlarında 0.

**Uyarlama yolu: S–M.**
- Ghidra bind'i relocation tablosuna sembol adıyla zaten yazıyor [D: 12.0 DEV `DyldChainedFixups.java:218-221`].
- PyGhidra betiği şunu yapar:
  - `__objc_catlist`'i gezer;
  - `cls` alanının relocation sembolünden sınıf adını alır;
  - metot listesini rea'nın `methods()` mantığıyla çözer; göreli ve mutlak listeler, seçici dolaylılığı dahil (`AppleObjcDispatchFacets.ts:101-197`, özellikle `:111, :113, :147`);
  - yalnız Ghidra'nın adsız bıraktığı IMP'lere `-[NSString(Kategori) seçici]` yazar.

**Nasıl ölçülür?**
- Önce ucuz deney: biri harici, biri yerel sınıfa iki kategori içeren küçük bir ObjC programı derlenir, Apple `strip` ile soyulur ve Karadul'dan geçirilir. Kategori metotlarından kaçının adlandırıldığı sayılır; GT strip öncesi `nm`'den gelir.
- Sonra aynı oran gerçek bir Mac ObjC uygulamasında ölçülür.

### 4. LC_BUILD_VERSION araç kayıtları (derleme kökeni profili)

**Ne yapıyor?** `otool -l` çıktısından platform, minos, sdk ve araç kayıtlarını alıp kodları adlandırıyor [D: `src/native/parsers/otool.ts:66-110, 337-338, 375-403`].
- Araç kodları: CLANG=1, SWIFT=2, LD=3, LLD=4, METAL=1024…
- Platform kodları: 1-24.

**Karadul'da karşılığı:** Yok [D: `minos`, `BUILD_VERSION` ve `ntools` Karadul'un hiçbir yerinde geçmiyor; `macho.py:491-521` `otool -l` metnini ayrıştırmadan tutuyor].

**Plan kalemi:** KS-5.

**Beklenen etki:** Dolaylı, orta (O).
- `SWIFT` araç kaydı Swift çözücülerini (Kalem 1 ve 2) açan kesin bir kapı olur [T].
- `LLD` kaydı Apple dışı bir bağlayıcıyı gösterir. TR-6'nın yerleşim modeli Apple `ld` varsayımıyla kurulduysa bu durumda kural kapanmalı [T].

**Uyarlama yolu: S.** rea'nın kod tablosu sabit liste olarak alınır. Değerler LIEF'in `BuildVersion`'ından ya da Ghidra'nın `BuildVersionCommand`'ından okunur [T: LIEF API'si bu oturumda denenmedi].

**Nasıl ölçülür?** KS-5'in kendi ölçütüyle: profilin korpus künyesine (Homebrew formülü, derleme bayrakları) göre doğruluğu ve kural kapısı açık/kapalı A/B.

### 5. ObjC ivar düzeni ve özellik nitelikleri → `self` yapısı (tip)

**Ne yapıyor?**
- Her sınıf için ivar adını, tip kodlamasını, ofsetini, boyutunu ve hizalamasını okuyor [D: `AppleObjcDispatchFacets.ts:280-320`]. Hizalama objc4 kuralına göre çözülüyor: `~0` → 8, öbürleri `2^n`.
- Özellik nitelik dizesini çözüyor [D: `src/native/AppleObjcProperties.ts:21-50`].
- `instance_size` değerini alıyor [D: `:361`].

**Ghidra ve Karadul'da karşılığı:**
- Ghidra `ivar_t` kayıtlarını işaretliyor ve ivar ofseti global'lerine ad koyuyor [D: 12.0 DEV `ObjectiveC2_InstanceVariable.java:100-110`].
- Örnek düzenini bir yapı tipine çevirip metotların `self` parametresine uygulayan bir kod görmedim [T].
- Karadul'da TP-5 yok.

**Plan kalemi:** TP-5 (yapı birleştirme) ve TP-1 (ucuz, kesin tip kanıtı). Yeni alt kalem: "ObjC örnek yapısı".

**Beklenen etki:** ObjC metotlarındaki `self->_alan` erişimleri ad ve tip kazanır. Bunlar değişken değil alan adlarıdır; tip doğruluğu ölçütüne girer [T].

**Uyarlama yolu: M.**
- rea yalnız olguları veriyor, yapı kurmuyor. Karadul ivar listesinden `struct Sınıf { isa; …ivar'lar }` yapısını kendisi kurar.
- Tip kodlaması için Ghidra 12.1.2'de `Objc1TypeEncodings` var [D: jar listesi]. ivar tipleri için kullanılabilir olduğu doğrulanmadı [T].

**Nasıl ölçülür?** ObjC sınıfları içeren test programının DWARF yapılarına göre alan ofseti ve tip kesinliği ölçülür [T: ObjC ivar'larının DWARF'ta üye olarak tutulduğu doğrulanmadı].

## Fikir olarak değerli, kod olarak alınmaz

### Fikir 1. İşaretçi haritası (TR-4, TP-4) Ghidra'dan alınmalı

- rea'nın chained fixup çözücüsü doğru, ama yetenek olarak Ghidra'nın alt kümesi.
- Karadul için doğru yol: PyGhidra'da `currentProgram.getRelocationTable()` dökümü. Her kayıtta adres, hedef değer ve bind sembolü bulunur [D: 12.0 DEV `DyldChainedFixups.java:218-221`].
- İş büyüklüğü: S.
- Ölçüm: önce relocation sayısı `dyld_info -fixups` satır sayısıyla karşılaştırılır [T: bu bayrak denenmedi]. Ardından TR-4'ün kendi ölçütü uygulanır.

### Fikir 2. Swift'te harici protokol tanıklarından kesin isim (rea'da yok, yeni kalem)

**rea neden yapamıyor?**
- Harici protokole uyumu çözemiyor: göreli dolaylı işaretçi bir bind'e gidince `read.pointer()` 0 döndürüyor [D: `AppleDispatchMetadata.ts:47-50`, `AppleSwiftDispatchFacets.ts:59`]. Protokol tanımlayıcısı bu yüzden okunamıyor.
- Statik tanık süzgeci `(flags & ~0x38) === 0` dayanıklı tanıkları da dışlıyor [D: `:128`].

**Mekanizma:**
1. `Equatable`, `Hashable`, `Codable`, `CustomStringConvertible`, `SwiftUI.View` gibi harici protokollere uyumda gereksinim tanımlayıcısı GOT üzerinden bir import'a bağlanır.
2. Bu import adları (`…Tq` metot tanımlayıcısı, `…Mp` protokol tanımlayıcısı) strip'ten sağ çıkar.
3. Demangle edilince gereksinimin tam adını verirler.
4. Böylece tanık thunk'ı kesin isim alır. TR-1'in thunk katlamasıyla asıl uygulama da adlanır: `Foo.==`, `Foo.hash(into:)`, `Foo.body.getter`.

[T: Mekanizma Swift ABI'sine dayanıyor; bir Mac uygulamasında denenmedi.]

**Ghidra durumu:** 12.1.2'de `TargetResilientWitness` sınıfı var ama ad koymuyor [D: jar ve javap].

**Değerlendirme:** Kalem 2 ve 3'ün yapı taşları (relocation sembolü, göreli işaretçi) üstüne kurulur. Swift için potansiyeli en yüksek kesin isim kaynağı olabilir [T]. İş büyüklüğü: M.

### Fikir 3. Mach-O ölçüm düzeni (ÖL-2, KS-7)

- rea aynı ObjC/Swift kaynağını üç bağlama kipinde derliyor [D: `scripts/verify/apple/dispatch.mjs:31-41`]:
  - `-Wl,-no_fixup_chains` (eski `LC_DYLD_INFO`);
  - chained fixups;
  - `-arch arm64e` (kimlik doğrulamalı işaretçiler).
- Ama yalnız `strip -x` kullanıyor, yani ikililer yarı soyulmuş [D: `:203, :251`]. Karadul tam Apple `strip` kullanmalı (sentez Kİ-2).
- rea'nın bir notu: llvm-nm varsayılan "dyld-info" geçişinde sembol tablosunda olmayan adlar üretiyor; rea bu yüzden `--no-dyldinfo` kullanıyor [D: `NativeMachoInspection.ts:44-48`].
  - Karadul'da bu bayrak yok [D: grep].
  - Kilitli setin `nm -U` sayımlarını etkilemesi beklenmez [T].
  - Mac GT hattı (ÖL-2) yazılırken yine de not edilmeli.

## İşimize yaramayanlar

**LC_FUNCTION_STARTS (KS-2)**
- rea okumuyor; Ghidra zaten kullanıyor (genel tabloya bakınız).

**Export trie, kod imzası, entitlements**
- Apple araçlarının sarmalayıcısı; isim kaynağı değil.

**`MachoLoadCommandReader.ts`**
- Okudukları:
  - dylib bağımlılıkları, yeni `dylib_use_command` kodlaması dahil [D: `:85, :433-464`];
  - rpath ve `LC_DYLD_ENVIRONMENT`.
- Bunlar bağımlılık çözümü için. Karadul aynı bilgiyi `otool -L` ile alıyor [D: `macho.py:464-489`].
- İki düzeyli ad alanı (kütüphane sırası → install name) Ghidra'da da var [D: 12.0 DEV `DyldChainedFixups.java:203-207`].
- rea `.tbd` okumuyor [D: grep boş]. KS-7'nin `.tbd` API sözlüğü için rea'dan bir şey çıkmaz.

**`MachOSliceArtifactReader.ts`, `machoView.ts`, `MachoImage.fixture.ts`**
- Evrensel ikiliden dilim seçimi, görünüm projeksiyonu ve test fikstürü.

**Swift demangle**
- İkisi de `swift-demangle` çağırıyor; Karadul'da zaten var [D: `swift_binary.py:456-525`].

**NativeAOT (Soru 2)**
- Yalnız x64 PE ve RTR 9.1 (.NET 8) destekleniyor.
- MethodTable ilişkilerini, sanal yuvaları ve donmuş dizeleri çıkarıyor. Özgün sınıf ve üye adlarını kurtarmıyor [D: `docs/ghidra-nativeaot.md:3-21, 80-81, 133-136`].
- Mac arm64 Mach-O NativeAOT için hiçbir şey yok.
- Karadul'da NativeAOT desteği yok [D: grep boş].

**Go (Soru 3)**
- rea yalnız buildinfo, modül ve sürüm okuyor (Mach-O'da `__go_buildinfo`); pclntab okumuyor [D: `docs/go-binaries.md:1-6`, `src/go/GoMachoImage.ts:129`].
- Karadul önde: pclntab ve buildinfo okuyor [D: `karadul/analyzers/go_binary.py:388-418, 609-630`].
- Ama Karadul'un pclntab yolu `go tool objdump`'a bağlı. Go kurulu değilse `nm`'ye ya da `strings` regex'ine düşüyor ve adres bağı kuramıyor [D]. Bu rea dışı bir açık.

**Rust (Soru 4)**
- rea iki şey okuyor [D: `docs/rust-binaries.md:3-4, 25-45`, `src/rust/RustBinaryImage.ts:17-18, 109-119`]:
  - cargo-auditable `.dep-v0` (zlib'li JSON paket grafiği);
  - `/rustc/<40 hex>/` yollarından rustc commit'i.
- Demangle ve panik `Location` ayrıştırması yok [D].
- Crate listesi ilke olarak modül öneki verebilir. Ama panik yolları (`…/serde_json-1.0.x/src/de.rs`) aynı bilgiyi dosya düzeyinde zaten taşıyor (sentez Kİ-5). Homebrew ikililerinde `.dep-v0` de nadir [T].
- Karadul'da Rust demangle var: legacy ve v0'ın bir alt kümesi [D: `karadul/analyzers/rust_demangler.py:1-30`].
- rustc commit'i KS-5 profiline küçük bir girdi olabilir.

**Flutter (Soru 5)**
- Yalnız APK destekleniyor (`libapp.so`, ELF).
- Bayt deseniyle şunları çıkarıyor: snapshot hash'i, `package:` ve `dart:` URI envanteri, tanımlayıcı biçimli parçalar.
- Tipli sınıf ya da fonksiyon kurtarmıyor. hash → SDK eşlemesi de yapmıyor [D: `docs/flutter-analysis.md:3-8, 73-79, 156-163`].
- Mac `App.framework` desteği yok; Karadul'da da Flutter yok [D: grep boş].
- Sonuç: isim kurtarma yok, yalnız kimlik.

**.NET yönetilen kod ve WASM**
- .NET: PE/CLI meta verisi zaten adlı; Karadul'da DOTNET yönlendirmesi var [D: `karadul/core/target.py:33, 547`].
- WASM: rea yalnız WABT sarmalayıcısı [D: `docs/wasm-artifacts.md:3-5, 21-23`]. Karadul WASM'ı bilerek dışarıda bıraktı.

## Açık sorular

1. **Ghidra 12.1.2 harici sınıf kategorilerinin metotlarını gerçekten atlıyor mu?**
   - Bayt kodu koşulu gösteriyor. Ama `readClass`'ın EXTERNAL bloktaki adresle ne yaptığı denenmedi.
   - Kalem 3'ün bütün değeri buna bağlı; ilk yapılacak deney bu.
2. **Ghidra, Swift büyük literalleri için 0x20 geriye, başka bir dizenin ortasına xref kuruyor mu?**
   - ADRP/ADD analizinin davranışı denenmedi.
   - Kuruyorsa Karadul bugün yanlış dize-fonksiyon bağı üretiyor demektir. Bu TR-2'yi ilgilendiren bir YN kaynağı olur.
3. **Fikir 2 uygulanabilir mi?**
   - Gerçek Mac Swift uygulamalarında harici protokol uyumlarının oranı ne?
   - Dayanıklı tanık listeleri `…Tq` import'larını gerçekten taşıyor mu?
4. **Swift vtable'daki getter/setter sırası `__swift5_fieldmd` alan sırasıyla örtüşüyor mu?**
   - Örtüşüyorsa `Foo.alan.getter` kesin isim olur.
   - Ghidra 12.1.2 `FieldDescriptor`'ı zaten ayrıştırıyor [D: jar].
5. **Makale ölçümü:**
   - Kilitli test seti 15 C programı [D: `docs/arge/test_seti_kilidi.md`]. Bu kalemlerin etkisi makale sayılarında görünmez.
   - Swift/ObjC için ayrı bir geliştirme kümesi gerekir; makaleye girecekse ayrıca önceden kilitlenmiş bir küme de.
   - Karar Berke'nin.
6. **Kalem 1 PyGhidra'ya taşınabilir mi?**
   - `SymbolicPropogator` geri çağırmalı bir `ContextEvaluator` istiyor.
   - JPype ile bu Java arayüzünü Python'dan uygulamanın PyGhidra 3.0'da sorunsuz çalıştığı doğrulanmadı. Çalışmazsa küçük bir Java GhidraScript gerekir.
7. **Ghidra sürüm farkı:**
   - ObjC katmanı 12.0 DEV'den 12.1.2'ye yeniden düzenlenmiş: `objc2/ObjectiveC2_*` → `objc/objc2/Objc2*`, çözümleyici `ObjcTypeMetadataAnalyzer`.
   - 12.1.2'de bayt koduyla doğrulananlar: kategori kurucusu, göreli metot listesi, Swift çözümleyicisi, `MachoFunctionStartsAnalyzer` ve chained fixup relocation kaydı.
   - `ObjectiveC1_Utilities:318,342` ve `ObjectiveC2_InstanceVariable:100-110` atıfları yalnız 12.0 DEV kaynağından.
8. **Lisans:** Taşınan her dosyada rea'nın MIT telif notu korunmalı.
