# rea incelemesi 1: native analiz çekirdeği (Ghidra, Hopper, IDA, Kuna)

- **Tarih:** 2026-10-17
- **İncelenen:** `morluto/rea` (MIT), sığ klon, HEAD `2092f90`. Klonda tek commit var; commit mesajları aranamadı, bu yüzden "signature facts" için `CHANGELOG.md` ve `src/` tarandı.
- **Kapsam:** `bridge/ghidra/*.java`, `src/ghidra/**`, Ghidra doğrulama betikleri ve fixture'ları, `bridge/hopper_bridge.py`, IDA ve Kuna sağlayıcıları, Cutter'a kısa bakış.
- **Yöntem:** Yalnız okundu, hiçbir rea betiği ya da testi çalıştırılmadı. Karadul tarafı `grep` ve `Read` ile kontrol edildi. Ghidra 12.1.2 kurulumunun (`~/Library/BlackWidowBuild/ghidra_12.1.2_PUBLIC`) veri dosyaları ve jar'larındaki sınıf adları okundu.
- **İşaretler:** **[D]** koddan ya da dosyadan doğrulandı; **[T]** tahmin, ölçülmedi.
- **Rea yolu kısaltması:** `RGB` = `bridge/ghidra/ReaGhidraBridge.java`.

## Özet

1. rea'nın Ghidra köprüsü büyük ölçüde gözlemci. Varsayılan otomatik analizi koşturuyor. Veritabanını değiştiren tek varsayılan adım yanlış "dönmez" bayrağı onarımı. Tohum ve analizör kapatma isteğe bağlı. [D]
2. Karadul için en değerli üç kalem şunlar. Birincisi, dönmezlik onarımı ve onun gerektirdiği analiz öncesi/sonrası kanca (KS-2). İkincisi, çağrı ilişkisi kapsam sinyalleri; bunlar "tek çağıran / tek çağrılan / yaprak" kurallarını korur (TR-1, TR-5, ÖL-3). Üçüncüsü, Ghidra relocation tablosundan işaretçi haritası yolu (TR-4). Bu sonuncuda rea yalnız tabloyu döküyor; haritayı kurmuyor. [D]
3. TR-4'e doğrudan katkı yok. rea'da işaretçi tablosu, vtable ya da dolaylı çağrı çözümü yok. Switch tarafında yalnız Ghidra'nın zaten bulduğu tabloları kanıtla raporluyor. [D]
4. "Native signature facts" kod imzası demek: takım kimliği, cdhash, entitlements. Kütüphane fonksiyonu tanıma (FLIRT, FID, BSim) yok. [D]
5. Kuna ELF'i ve ince Mach-O arm64'ü okuyor. Tip kurtarma, tipli referans ve CFG yok. `--jobs` 1'den büyük olunca çıktı değişiyor. En fazla sınır karşılaştırması için ikinci görüş olabilir. [D, belgeden]
6. Depoda hiçbir düzeltmenin gerçek ikilideki sayısı yok. Doğrulamalar sentetik fixture'larla yapılmış. Karadul'a alınan her şey önce tanı sayısıyla ölçülmeli. [D]

## Kullanılabilir özellikler

**Sorulara kısa cevap**

| Soru | Kısa cevap | Madde |
|---|---|---|
| 1. Ghidra'ya uygulanan düzeltmeler ve seçenekler | Analiz varsayılan. İsteğe bağlı olarak analizör kapatma ve tohum (ikisi de `-preScript`). Dönmezlik onarımı `-postScript`; Windows'ta kapalı. Decompiler'da komut sınırı yok, `toggleJumpLoads(true)`, fonksiyon başına süre sınırı yok. Karadul'da her şey varsayılan, süre 30 sn. | 1, 4, 6 |
| 2. NoReturnFix ve ApplySeeds: sınırlar, doğrulama, en kısa yol | Doğrulama sentetik. En kısa yol Python'a port ve `open_program(analyze=False)` + elle `analyzeAll` kancası. Java betiği doğrudan çalıştırmak Karadul'un PyGhidra kipine uymuyor. | 1, 4 |
| 3. Switch, işaretçi tablosu, dolaylı çağrı | Switch yalnız raporlanıyor, kurtarılmıyor. İşaretçi tablosu ve dolaylı çağrı çözümü yok. Kullanılabilir tek parça relocation tablosu dökümünün API deseni. | 3; Fikir 4 |
| 4. Kuna | İkinci görüş adayı, alternatif değil. | Fikir 5 |
| 5. Kanıt modeli | Statü üçlüsü, sınırlama listesi, kapsam durumu, ebeveyn bağları alınmalı. Sabit güven seviyeleri alınmamalı. | 2; Fikir 1 |
| 6. Başka | p-code def-use bağları, gövde aralıkları, Swift literal çözücü, derleyici kâhini fixture'ları. | 5, 7, 8; Fikir 3 |

### 1. Yanlış "dönmez" bayrağı onarımı ve bunun için analiz kancası (`ReaGhidraNoReturnFix`)

**Ne yapıyor.** Ghidra otomatik analizi bazı fonksiyonları yanlışlıkla "dönmez" (noreturn) diye işaretliyor. O zaman çağıranın gövdesi çağrıda kesiliyor ve sonraki baytlar ya çözülmüyor ya da başka yere kayıyor. rea analizden sonra bayrağı iki durumda siliyor [D]:

- Dış fonksiyonun adı bilinen 6 "dönen" içe aktarmadan biriyse.
- Yerel fonksiyonun gövdesinde gerçek bir RETURN p-code'u varsa.

Sonra yalnız bu hedeflere giden "çağrı + terminal" komutlarını yeniden çözüyor ve sahibi olan fonksiyonun gövdesini yerinde genişletiyor; isim ve imza korunuyor. Onarılan çağıranın kendisi de dönüyorsa zincir aynı geçişte onarılıyor; thunk'lar da buna dahil. [D]

**Kanıt (rea).**

- `bridge/ghidra/ReaGhidraNoReturnFix.java:22-23`: liste `malloc, __tls_get_addr, memcpy, memset, strlen, __errno_location`. [D]
- `:101-107`: Mach-O'da baştaki tek alt çizgi atılıyor. [D]
- `:109-122`: RETURN denetimi. Thunk'lar, atlama ve çağrı komutları atlanıyor. [D]
- `:48-85`: yeniden çözme ve `CreateFunctionCmd.fixupFunctionBody`. `:71`: çağrının hemen arkasında bağımsız fonksiyon varsa dokunmuyor. [D]
- `:86`: `analyzeChanges` bilerek yok; yorumda "libpl2.so'da 70 sn ekliyor" yazıyor. `:28`: Windows'ta kapalı. [D]
- Sıra: `src/ghidra/GhidraLauncher.ts:826-864`. Tohum ve analizör seçenekleri `-preScript`, onarım `-postScript`, köprü en son. [D]
- Profilde sürümleniyor: `src/ghidra/GhidraAnalysisProfile.ts:148-151` → `returning-imports-decoded-return-v2`. [D]

**Sınırlar.**

- Yalnız bayrak siliyor. Eksik bayrağı eklemiyor; oysa KS-2'nin asıl istediği yön bu (`xalloc_die`, `err` gibi). [D]
- RET'i olmayan, kuyruk çağrısıyla dönen fonksiyonu tanımıyor; atlama komutlarını atlıyor (`:114`). [D]
- Ghidra çağrının arkasında ayrı bir fonksiyon yaratmışsa hasar kalıyor (`:71`). [D]
- `analyzeChanges` olmadığı için yeniden açılan bölgede yeni çağrı hedefleri fonksiyon olmuyor, veri ve string referans analizi koşmuyor. [T]
- Liste glibc'ye göre yazılmış. Mac'in errno fonksiyonu `___error` listede yok. [D]
- **Doğrulama yalnız sentetik.** `tests/conformance/ghidra/no-return.c` `-O0 -fno-builtin -fPIC` ile paylaşımlı kütüphane olarak derleniyor (`scripts/verify-real-ghidra-noreturn.mjs:68-76`). Yanlış bayraklar elle enjekte ediliyor (`tests/conformance/ghidra/ReaNoReturnProbe.java:207-230`). Denetimler: `independent_entry_preserved`, `propagated_flag_repaired_rea_tls_outer`, `recovered_pseudocode` (`:133-135`). Gerçek ikilide kaç bayrak silindiği depoda yok; tek iz `libpl2.so` yorumu. [D]

**Karadul'da karşılığı.** Yok. [D]

- `karadul/` altında `hasNoReturn`, `setNoReturn`, `noreturn` hiç geçmiyor. Fonksiyon ihracında bayrak yok (`karadul/ghidra/headless.py:556-575`). [D]
- Analiz öncesi kanca yok. `headless.py:247-251` `pyghidra.open_program(..., analyze=True)` çağırıyor; analiz bu çağrının içinde bitiyor. GDT arşivleri (`:259`) ve PDB yolu (`:267`, `:2004`) bile analizden sonra giriyor. [D]
- Ghidra 12.1.2 tarafında iki analizör var [D, `Base.jar` sınıf dizgilerinden]:
  - "Non-Returning Functions - Discovered" (`FindNoReturnFunctionsAnalyzer`). Seçenekleri `evidenceThresholdFunctions` ve `repairDamageEnabled`.
  - "Non-Returning Functions - Known" (ad listeleri).
- Ad listelerinde eksikler var: `MachOFunctionsThatDoNotReturn`'de `errx` var, `err` yok; `ElfFunctionsThatDoNotReturn`'de `err/errx/verr/error/xalloc_die` yok. Dosyalar `Ghidra/Features/Base/data/` altında. [D]

**Plan kalemi.** KS-2: sınır düzeltmesi, "dönmeyen fonksiyon listesi ve dönmezlik özeti analizden önce Ghidra'ya". Dolaylı olarak:

- TR-2: hata yolu budaması dönmezlik bilgisine dayanıyor.
- KS-6: `x*alloc` kalıbı "dönmeyen çağrı" arıyor.

**Beklenen etki.** O (tahmin). Yanlış bayrak çağıranın gövdesini kesiyor; kesik gövde çağrı ve string kanıtını kaybettiriyor ve sonraki baytları komşuya bırakıyor. Eksik bayrak tersini yapıyor: iki fonksiyon tek gövdede birleşiyor. Karadul'un ikililerinde ikisinin sıklığı ölçülmedi. [T]

**Uyarlama yolu (S).**

1. **Önce yalnız tanı, ürün değişmez.** Analizden sonra iki sayı alınır: "dönmez bayraklı ama RET'li yerel fonksiyon sayısı" (rea'nın `clearDecodedReturn` yüklemi) ve "dönmez bayraklı hedefe giden terminal çağrı yeri sayısı". Sayılar küçükse kalem ertelenir.
2. **Kanca.** Akış: `open_program(analyze=False)` → analiz öncesi adımlar → `flat_api.analyzeAll(program)` + `GhidraProgramUtilities.markProgramAnalyzed(program)` → analiz sonrası onarım → mevcut çıkarım. pyghidra'nın kendisi de tam bunu yapıyor (`/opt/anaconda3/lib/python3.12/site-packages/pyghidra/core.py:183-190`). [D] Var olan projeyi yeniden açarken çift analiz olmamalı; pyghidra bunu `shouldAskToAnalyze` ile engelliyor. [D]
3. **Java mı Python mu: Python'a port.** Karadul PyGhidra kipinde GhidraScript çalıştırmıyor. Java/py betikleri yalnız CLI yedeğinde `-preScript/-postScript` ile geçiyor (`headless.py:2167`, `:2174`). [D] 123 satırlık betiğin kullandığı API'ler JPype'tan erişilebilir [T]. Veritabanı değişikliği `program.startTransaction` içinde olmalı; Karadul bu deseni zaten kullanıyor (`headless.py:1948`, `:2004`). [D]
4. **Ters yön.** Analizden önce bilinen dönmez dış fonksiyonlara `setNoReturn(True)` konur. Liste derleme kökenine göre seçilir (KS-5). `error` gibi koşullu dönmezler listeye girmez.
5. **Sürüm manifest'e yazılır** (`no_return_repair: v1`). Bkz. Fikir 2.

**Nasıl ölçülür.**

- Tanı sayıları geliştirme setinde, Mac ve Debian ayrı.
- Sınır F1: DWARF `low_pc/high_pc` ile Ghidra gövdeleri. "Öncülüne katılan" ve "kesik gövde" sayıları önce/sonra (KS-2 ölçütü).
- İsim: `scripts/measurement/measure.py compare` ile A/B. Kabul kapısı: yanlış isim sayısı artmayacak.

### 2. Çağrı ilişkisi kapsamı: çözülmemiş çağrı yerleri, temsil edilmeyen çağıranlar, gövde içine gelen referanslar

**Ne yapıyor.** rea her fonksiyon için çağrı ilişkisinin tam olup olmadığını ayrıca raporluyor:

- Hedefi olmayan çağrı komutları (`unresolved_calls`).
- Gövdeye gelen ama Ghidra'nın çağıran listesinde görünmeyen çağrı referansları.
- Bunlardan türeyen `complete / partial / unknown` durumu ve hangi yönün (callers, callees) eksik olduğu.

Referanslar yalnız giriş adresine gelenlerden değil, gövdenin tamamından toplanıyor. Böylece fonksiyonun ortasına gelen çağrılar da görünüyor. [D]

**Kanıt (rea).**

- `RGB:3439-3469` `callBoundaryObservation`. Gerekçe metni: "Instruction decoder identifies a call but ReferenceManager supplies no call destination". [D]
- `RGB:3416-3420` `unrepresentedCaller`; `RGB:3371-3403` `callRelationshipCoverage`. [D]
- `RGB:3665-3684`: gövde kapsamında kaynak ve hedef yineleyicisi. `RGB:3703-3706`: giriş noktası referansları dışlanıyor. [D]
- Dürüstlük notu: `facet_availability` alanlarının çoğu sabit `true` yazılıyor (`RGB:1598-1602`). Gerçekten hesaplanan sinyal `relationship_coverage`. [D]

**Karadul'da karşılığı.** Kısmen yok, bir yerde ters çalışıyor. [D]

- `headless.py:663-667`: çağıranlar yalnız giriş adresine gelen `isCall` referanslarından çıkarılıyor ve öz-kenarlar atılıyor.
- `headless.py:683`: çağrı hedefi bir fonksiyonun ortasındaysa `getFunctionContaining` ile o fonksiyona yazılıyor. Sınır hatası böylece sessizce "geçerli kenar" oluyor. Aynı desen `:835`'te de var.
- Dolaylı çağrı yeri sayısı hiç ihraç edilmiyor.
- Bu eksikliğe duyarlı kurallar:
  - `karadul/reconstruction/tarif/propagate.py:61` (Y2 sarmalayıcı, `len(p.internal_callees) == 1`)
  - `:69` (Y4 yardımcı, `len(p.callers) == 1`)
  - `karadul/reconstruction/tarif/rules.py:320` (tek-API, `not p.internal_callees`)

  Dolaylı çağrısı olan ya da tablodan çağrılan fonksiyonda bu sayılar yanıltıcı.

**Plan kalemi.**

- TR-1: çağrı grafı onarımı; "sarmalayıcılar şu an yaprak görünüyor olabilir".
- TR-5: çelişkide isimsiz bırak.
- ÖL-3: erişim sınıfları (doğrudan, yalnız adres, referanssız) ve kanıt erişimi raporu.
- KS-2: ortaya gelen çağrı, kaçmış fonksiyon başının adayıdır.
- MD-2.

**Beklenen etki.** YN↓, O (tahmin). "Yokluk" kanıtına dayanan kurallar (tek çağıran, tek çağrılan, yaprak) kapsam eksikken susar. Bedeli var: bu kuralların bir kısmı susacağı için KP biraz düşebilir. [T]

**Uyarlama yolu (S).**

- Ghidra ihracına fonksiyon başına üç alan eklenir:
  - `indirect_call_sites`: çağrı komutu var, çağrı referansı yok.
  - `interior_call_refs`: gövdenin içine gelen, girişe gelmeyen çağrı referansları.
  - `data_refs_to_entry`: veri bloğundan girişe gelen referanslar; tablo yuvası adayı, madde 3'e köprü.
- `EvidencePack`'e (`tarif/evidence.py:34`) `callers_complete` ve `callees_complete` eklenir.
- Y2, Y4 ve tek-API kuralları yalnız kapsam tamken çalışır.
- `headless.py:683`'teki geri düşüş silinmez. Ortaya gelen çağrılar ayrı sınıfa yazılır; böylece hem kenar korunur hem sınır hatası görünür olur.

**Nasıl ölçülür.**

- Önce dağılım: dolaylı çağrı yeri olan fonksiyon oranı ve ortaya gelen çağrı sayısı; htop, tmux ve test seti dışı geliştirme ikilileri, Mac ve Debian ayrı.
- Sonra Y2/Y4 isimlerinin gevşek mod kesinliği, kapsam "tam" ve "kısmi" diye iki tabloda.
- Ortaya gelen çağrıların GT'de gerçekten fonksiyon başı olup olmadığı (KS-2 sınır F1).

### 3. Relocation tablosundan işaretçi haritası (TR-4'ün hammaddesi)

**Ne yapıyor.** rea yükleme görüntüsü incelemesinde Ghidra'nın relocation tablosunu satır satır döküyor: adres, durum, tür, değerler, dosyadaki özgün baytlar ve düzeltme sonrası bellek baytları. Yuva rolü çıkarmıyor. Bu kalemde rea'dan alınan şey yalnız API deseni; işaretçi haritası Karadul'un yazacağı yeni kod. [D]

**Kanıt.**

- rea: `RGB:647-671`. `getRelocationTable().getRelocations()` çağrılıyor; `original_bytes_hex` ve `memory_bytes_hex` alanları üretiliyor. [D]
- rea'nın kendi sınır metni, `RGB:1394`: "Objective-C, Swift, vtable and closure mechanisms are not identified by this reference-only boundary." [D]
- Ghidra 12.1.2 Mach-O chained fixup'larını relocation tablosuna yazıyor: `DyldChainedFixups` sınıfı `RelocationTable` ekleme metoduna başvuruyor. ELF yükleyicisi de yazıyor (`ElfProgramBuilder.processRelocations`). [D, `Base.jar` sınıf dizgilerinden]

**Karadul'da karşılığı.** Yok. [D]

- `karadul/` altında `getRelocationTable`, `chained`, `R_*_RELATIVE` geçmiyor.
- Geri çağrı kaydı yalnız decompile metninde `FUN_xxx` argümanı aranarak bulunuyor (`tarif/evidence.py:22`, `:85`). Veri bölümündeki statik tablolar bu yüzden görünmüyor.

**Plan kalemi.**

- TR-4 (M4): işaretçi haritası; ELF `R_*_RELATIVE` ve `.data.rel.ro`, Mach-O chained fixups.
- TP-4: işaretçi/tamsayı ayrımı ve yapı periyodu.
- DG-4: getopt `struct option` tablosu.

**Beklenen etki.** Y (tahmin). Gerekçe katalogdan: htop'ta fonksiyonların çoğu tablolardan çağrılıyor; oran ölçülmedi.

**Uyarlama yolu (M).**

1. Analizden sonra relocation tablosu taranır.
2. Düzeltme sonrası değeri bir fonksiyon girişine düşen yuvalar `(blok, ofset, hedef)` olarak ihraç edilir.
3. Aynı bloktaki ardışık yuvalar adım uzunluğuyla gruplanır; bu yapı dizisi verir (TP-4).

Ayrı bir fixup ayrıştırıcısı gerekmeyebilir. Önce Ghidra'nın kaydettiği satırın chained pointer'ın hedefini doğrudan verip vermediği doğrulanmalı; rea'nın `memory_bytes_hex` karşılaştırması bunun için iyi bir yol. [T]

**Nasıl ölçülür.**

- TR-4'ün kendi ölçütü: htop/tmux'ta "çağıranı yalnız tablo olan" fonksiyon oranı.
- Yuva → hedef eşlemesinin DWARF'lı derlemedeki sembollerle doğruluğu.
- M4 öncesi ve sonrası kanıt erişimi ve yakın isim oranı.

### 4. Analiz öncesi tohumlar ve analizör seçenekleri (`ReaGhidraApplySeeds`, `ReaGhidraAnalysisOptions`)

**Ne yapıyor.**

- **Tohum betiği** otomatik analizden önce `function`, `code` ve `label` tohumlarını uyguluyor. Fonksiyonlar en yüksek adresten aşağı doğru yaratılıyor. Önceden hesaplanan gövde var olan bir girişte durduğu için alttaki fonksiyon üsttekini yutamıyor. Sonuç sayıları programın seçeneklerine JSON olarak yazılıyor: yaratılan, zaten var olan, başarısız, çözülen, eşlenemeyen. [D]
- **Analizör betiği** verilen analizörleri kapatıyor, sonra seçeneği geri okuyup gerçekten kapandığını doğruluyor. Bilinmeyen bir ad analizi başlamadan durduruyor. [D]

**Kanıt (rea).**

- `bridge/ghidra/ReaGhidraApplySeeds.java:61-67` azalan sıranın gerekçesi; `:73` geçiş sırası; `:92-106` var olan fonksiyona isim, yoksa çözüp yaratma; `:118-128` rapor. [D]
- `bridge/ghidra/ReaGhidraAnalysisOptions.java:18-35`: doğrula → kapat → geri oku. [D]
- `docs/installation.md:1029` ve `:1035`: tohum biçimi ve amacı ("auto-analysis cannot reach (computed jumps, pointers in data)"). [D]
- Doğrulama sentetik. 3 baytlık x86 ham ikili (`90 90 c3`) ve iki tohum kullanılıyor (`scripts/verify/ghidra/seeds.mjs:30-41`). Analizör kapatma "Decompiler Switch Analysis" adıyla geri okunuyor, bilinmeyen adda durma deneniyor (`:53-86`). Gerçek ikilide etki ölçümü yok. [D]

**Sınırlar.**

- Tohumun doğruluğu sorgulanmıyor. [D]
- `code` tohumu akışı izleyerek çözüyor; yanlış tohum çöp kod yaratabilir. [D]
- Var olan bir komutun içine düşen tohum başarısız sayılıyor. [D]
- İsimler `USER_DEFINED` kaynağıyla yazılıyor. [D]

**Karadul'da karşılığı.** Yok; analiz öncesi kanca da yok (madde 1). [D]

Önemli not: Ghidra 12.1.2'de "Mach-O Function Starts" analizörü var (`MachoFunctionStartsAnalyzer`, LC_FUNCTION_STARTS). [D, `Base.jar`] Karadul'un kendi notu Homebrew `tree`'de 118/118 boyut eşleşmesi bulmuş (`karadul/analyzers/byte_pattern_matcher.py:742-743`). [D] Yani Mac'te fonksiyon başlangıçları büyük olasılıkla zaten giriyor. [T] Tohumun Mac'teki asıl işi işaretçi hedefleri (madde 3) ve sınır onarımı olabilir.

**Plan kalemi.**

- KS-2: kesin sınır kaynakları analizden önce Ghidra'ya.
- TR-4: yuva hedefi fonksiyon değilse `function` tohumu.
- ÖL-7: analizör seçenekleri geri okunup manifest'e yazılır.

**Beklenen etki.** D–O (tahmin). Mac'te LC_FUNCTION_STARTS zaten kullanıldığı için küçük. ELF stripped'da Ghidra'nın `.eh_frame` FDE başlangıçlarını fonksiyona çevirip çevirmediği bilinmiyor (Açık soru 3).

**Uyarlama yolu (S).** Madde 1'deki kanca kurulunca Python'da:

- Azalan sırayla `createFunction` çağrılır.
- Sayılar hem `Program.PROGRAM_INFO` seçeneklerine hem Karadul çıktısına yazılır.
- Analizör seçenekleri `setAnalysisOption` ile değiştirilir ve geri okunur.

**Nasıl ölçülür.** Önce GT başlangıç kümesi (DWARF) ile Ghidra'nın başlangıç kümesi karşılaştırılır, Mac ve Debian ayrı. Fark küçükse tohum ertelenir. Büyükse A/B yapılır: sınır F1 ve `measure.py compare`.

### 5. p-code def-use ve parametre kullanım bağları (`nativeValueFlow`)

**Ne yapıyor.** Her high p-code işlemine `adres#sıra` biçiminde bir kimlik veriyor. Her girdiden onu tanımlayan işleme kenar çekiyor (`VarnodeAST.getDef()`). Girdi bir `HighParam` ise "parametre N, şu işlemin i. girdisinde kullanılıyor" kaydı tutuyor. Bellek okuma/yazma, dal ve çağrıları ayrı "etki" olarak işaretliyor. Ölü işlemleri ve kesilmeyi sayılarla açıkça raporluyor. [D]

**Kanıt (rea).**

- `RGB:1655-1795`. [D]
- Sınırlar `RGB:121-123`: 3000 işlem, işlem başına 64 girdi, 12000 kenar. [D]
- Kesilme sayaçları `RGB:1768-1776`. [D]

**Karadul'da karşılığı.** Kısmen var. p-code ihracı işlemi, çıktıyı ve girdileri yazıyor; ama def-use kenarı ve parametre bağı yok (`karadul/ghidra/scripts/pcode_analysis.py:62-93`). [D] Tarif katmanı argümanları decompile metninden regex'le okuyor (`tarif/evidence.py:18-22`). [D]

**Plan kalemi.**

- DG-2: prototipten argüman adı taşıma; ad kopya kökü ve φ-ağı boyunca yürür.
- TR-7: argüman konumu ve sabit argümanlar.
- TP-2: `formal = actual` birleştirmesi.

**Beklenen etki.** O (tahmin). Bu bağlar yoksa DG-2 ve TR-7 metin üstünde regex'le yapılmak zorunda kalıyor. Regex φ'yi, kopyayı ve yazmaç yeniden kullanımını göremez. [T]

**Uyarlama yolu (S).** Karadul'un JSONL p-code yazıcısına girdi başına iki alan eklenir: `def` (tanımlayan işlemin kimliği) ve `param_slot`. Sınır konacaksa rea'daki gibi kesilme sayısı da yazılır; sessiz kesme olmamalı.

**Nasıl ölçülür.** Asıl ölçüt DG-2'ninki (ÖL-4 hizalaması). Ara ölçüt: regex ile çıkarılan "argüman i sabittir" kayıtlarıyla def-use'tan çıkarılanların örtüşmesi; ayrışmalar elle incelenir.

### 6. Decompiler ayarları: süresiz decompile, sınırsız komut, tablo yükleri

**Ne yapıyor.** rea tek bir kalıcı `DecompInterface` açıyor. Ayarlar şunlar [D]:

- `setMaxInstructions(Integer.MAX_VALUE)`
- `toggleJumpLoads(true)`
- `decompileFunction(function, 0, monitor)`: fonksiyon başına süre sınırı yok.

İptal ve başarısızlık ayrı hata koduyla dönüyor. [D]

**Kanıt (rea).**

- `RGB:914-925` ve `RGB:3305-3324`. [D]
- `docs/ghidra-provider.md:157`: "no fixed per-function deadline". [D]
- Profilde `decompiler_jump_loads: true` (`src/ghidra/GhidraAnalysisProfile.ts:158`). [D]

**Karadul'da karşılığı.** [D]

- Varsayılan `DecompileOptions`: `headless.py:994`, `:1268`, `:1505`; `scripts/decompile_all.py:262`.
- Fonksiyon başına 30 sn: `config.py:425`, `scripts/decompile_all.py:40`, `headless.py:1514`.
- Paralel decompile ve parça başına toplam süre: `headless.py:1017-1027`.
- Ghidra varsayılanları: komut sınırı 100000, tablo girdi sınırı 1024, süre 30 sn (`javap -constants ghidra.app.decompiler.DecompileOptions`).

**Plan kalemi.**

- ÖL-7: determinizm; aynı girdi aynı `naming_map`'i vermeli.
- DG-4 ve TK-14: switch ve tablo bilgisi.

**Beklenen etki.** İsim F1'ine D (tahmin). Asıl kazanç ölçüm güvenilirliği. Gerekçe: 30 sn sınırı makine yüküne bağlı. Yüklü makinede bir fonksiyonun decompile'ı düşerse o fonksiyonun ismi ve ondan yayılan isimler değişir. [T] 100000 komut sınırının dolması nadirdir. [T]

**Uyarlama yolu (S).** Ölçüm koşularında süre 0 ya da çok yüksek tutulur; düşen fonksiyonların listesi manifest'e yazılır. `toggleJumpLoads(true)` yalnız tablo bilgisi gerektiğinde açılır.

**Nasıl ölçülür.** Aynı ikili iki kez koşturulur: boşta ve yük altında. Düşen decompile sayısı ile `naming_map` farkı karşılaştırılır (ÖL-7 testi).

### 7. Fonksiyon kimliği ihracı: gövde aralıkları, bitişik olmayan gövde, thunk hedefi

**Ne yapıyor.** Her fonksiyonun gövdesini tek bir boyut sayısı olarak değil aralık listesi olarak veriyor. Alanlar: `ranges`, `total_bytes`, `span_bytes`, `non_contiguous`, `contains_entry`. Sınıflandırmada `external`, `thunk` ve `thunk_target` var. [D]

**Kanıt (rea).** `RGB:4389-4436` (`functionBody`), `RGB:3784-3797` (`functionClassification`). [D]

**Karadul'da karşılığı.** Yalnız `size = getBody().getNumAddresses()`, `is_thunk` ve `is_external` var (`headless.py:556-575`). Aralık, bitişik olmama, thunk hedefi ve dönmezlik bayrağı yok. [D]

**Plan kalemi.**

- ÖL-3: "sınır F1" isim F1'inden ayrı ölçülür; parça sınıfı.
- KS-3: `.cold.N` parçası ebeveyn gövdesine katılmışsa `non_contiguous` olarak görünür. [T]
- KS-2.

**Beklenen etki.** Ölçümün önkoşulu; isme doğrudan etkisi yok.

**Uyarlama yolu (S).** `_extract_functions`'a dört alan eklenir; madde 1'deki `has_no_return` da bunlardan biri.

**Nasıl ölçülür.** Sınır F1 hattı bu alanlarla kurulur. Mac korpusunda `non_contiguous` fonksiyonların `.cold` GT'siyle örtüşmesine bakılır.

### 8. Swift String literal çözücü (yalnız Swift ikilileri)

**Ne yapıyor.** Swift bir `String`'i iki 64 bitlik kelimeyle geçirir:

- 15 bayta kadar olan metin kelimelerin içinde durur.
- Daha uzun metin, sayı artı 32 kaydırılmış bir işaretçiyle temsil edilir.

Ghidra ikisini de veri referansı olarak tutmuyor; bu yüzden bu string'ler fonksiyona bağlanmıyor. rea `SymbolicPropogator` ile sabit yazmaç çiftlerini (x0-x7) çağrı, kuyruk çağrısı, dönüş ve `stp` noktalarında okuyor. ABI düzenini doğrulayıp metni çıkarıyor. Koşullu seçimle gelen değerleri ve çözülemeyen atlamaları "bilinmiyor" diye ayırıyor. [D]

**Kanıt (rea).**

- `RGB:3952-3958`: Swift tespiti, `__swift5_*` blokları. [D]
- `RGB:3960-4055` çözücü; `RGB:4064-4095` yazmaç çiftleri. [D]
- `RGB:4165-4199` düzen kuralları [D]:
  - Küçük literal: ayırıcı 0xE ya da 0xA, uzunluk 56-59. bitlerde.
  - Büyük immortal literal: üst bayt 0x80, bayrak 0xD ya da 0x1, işaretçi + 0x20.
- Doğrulama gerçek `swiftc -O -g` ile yapılıyor (`scripts/verify-real-ghidra-swift.mjs:79`). Beklenenler `:227-238` arasında: "SleepDisabled" küçük, "The power setting could not be changed." büyük, "café", boş string. [D]

**Karadul'da karşılığı.** Yok. `karadul/analyzers/swift_binary.py:283-296` `strings` çıktısını filtreliyor. 15 bayta kadar olan literaller komutların içinde durduğu için `strings`'te hiç görünmüyor; büyükler de fonksiyona bağlanmıyor. [D: kod; etkinin büyüklüğü T]

**Plan kalemi.** KS-7 (Mac zorunlu isimleri: ObjC ve Swift). Alt kalem olarak önerilir: "Swift literal → fonksiyon string kanıtı".

**Beklenen etki.** Swift programlarında O (tahmin). Kilitli test setinde 0, çünkü ana kümenin 15 programının hepsi C (`docs/arge/test_seti_kilidi.md` §1). Ürün değeri var, makale değeri yok. [D]

**Uyarlama yolu (M).** Yaklaşık 250 satır Java. Python'a port etmek için `ContextEvaluatorAdapter` alt sınıfını JPype ile yazmak gerekiyor; denenmedi. [T] Bellek bütçesi kısmı alınmaz.

**Nasıl ölçülür.** `swiftc -O -g` ile derlenmiş birkaç Swift programında üç sayı:

- Çözülen literal sayısı.
- Yanlış çözüm oranı; GT kaynak koddaki literaller.
- Swift fonksiyonlarında literal kanıtı eklenince isim kesinliği.

## Fikir olarak değerli, kod olarak alınmaz

1. **Kanıt modeli → isim künyesi (MD-1, MD-2, TR-5; KK §6, §8).**
   - rea'da her kayıt şunları taşıyor (`src/domain/evidence.ts:126-145`): `confidence: observed | derived | inferred`, `limitations[]`, `relationship_coverage`, `locations[]`, `evidence_links[]` (ebeveyn kayıtların içerik özetiyle kurulmuş bir DAG) ve `analysis_profile`. [D]
   - Tek tek çıkarımlar da `{kind, source, detail}` biçiminde kanıt listesi taşıyor (`RGB:3279-3289`). [D]
   - Karadul'un `Naming` kaydı yalnız `name, source, score` (`tarif/rules.py:27-33`). [D]
   - **Alınacaklar:**
     - Statü üçlüsü. Karadul'un "kesin / tarif / model" ayrımına (ÖL-1) birebir oturuyor: observed = binary'de yazılı, derived = deterministik kural, inferred = ipucu.
     - İsim başına ebeveyn bağları. Yayılım zinciri denetlenebilir hâle gelir; TR-5'teki çelişki tespiti bunun üstüne kurulur.
     - İsim başına sınırlama listesi; örneğin "çağıranlar kısmi", "gövde terminal çağrıda kesilmiş olabilir".
   - **Alınmayacak:** rea'nın sabit `high/medium/low` güven seviyeleri (`RGB:3291-3303`). Katalog güvenin ölçülmüş isabetten türetilmesini istiyor.
2. **Analiz profilini sürümleme → ölçüm manifest'i (ÖL-7, ÖL-2).**
   - rea her onarımın ve seçeneğin sürümünü profile yazıyor (`GhidraAnalysisProfile.ts:130-165`). Tohum dosyasının sha256'sı da profilde. Uygulanan tohumlar farklıysa oturum açılmıyor (`docs/installation.md:1035`). [D]
   - Karadul `measure.py` yalnız Ghidra sürümünü kaydediyor (`scripts/measurement/measure.py:201-207`). [D]
   - Eklenmesi gerekenler: analizör seti, kanca adımlarının sürümleri, decompiler ayarları, düşen decompile listesi.
3. **Derleyici kâhini ve işaret baytları (ÖL-8, TR-11).** rea switch doğrulamasında GT'yi derleyicinin kendi çıktısından alıyor (`tests/conformance/ghidra/switch-fixture.mjs:112-190`):
   - Her case bloğu benzersiz bir `mov eax, imm32` işaretiyle başlıyor.
   - Derleyici tablo biçimini değiştirirse test açıkça düşüyor; "derleyici artık tek bir 8 baytlık tablo üretmiyor" denetimi var.

   Karadul aynı tekniği kontrol akışı GT'si için kullanabilir: -O0/-O2 arasında aynı tarifi alma (TR-11), döngü rolleri (DG-3). [D: teknik; T: uygulanabilirlik]
4. **Switch kanıtı (DG-4, TK-14).** rea Ghidra'nın `getJumpTables()` sonucunu `ClangCaseToken` ile eşliyor: case değeri → hedef blok. Bir blok birden çok dolaylı dağıtımdan geliyorsa ya da bir değer iki hedefe gidiyorsa "bilinmiyor" diyor (`RGB:2724-2795`). [D]

   AArch64 göreli bayt/yarım kelime tablolarını komut zinciriyle çözüyor: ADRP/ADD, LDRB/LDRH, ADR, ADD [LSL #2], BR; koruma olarak CMP #imm ve B.HI/B.HS (`RGB:2914-2921`, `:2922`). Ama yalnız Ghidra'nın yük tablosuyla aynı baytları anlatıyorsa kanıt ekliyor (`RGB:2445-2456`). Yani Ghidra'nın kaçırdığı switch'i kurtarmıyor. [D]

   Karadul'a getirisi DG-4'te "case 'v' → bayrak" eşlemesini metinden değil yapıdan almak olabilir. Etkisi küçük, çünkü decompile metninde case etiketleri zaten var. [T]
5. **Kuna ikinci görüş olarak (KS-2, TR-1).**
   - Desteklenen hedefler: ELF ve ince Mach-O; x86-64, AArch64, ARM. Evrensel Mach-O ve PE reddediliyor (`docs/kuna-provider.md:27`). [D]
   - Tipli referans, temel blok, tip kurtarma yok (`:42`). [D]
   - Fonksiyon sınırları "bir sonraki girişe kadar üst sınır"; Kuna kendi çıkarımıyla bir fonksiyonu bölebiliyor (`:107`). [D]
   - **Determinizm:** referans cevap `--jobs 1`. Daha fazla iş parçacığı, ölçülen ikililerde fonksiyon gövdelerinin yaklaşık %40-60'ını değiştiriyor (`:23`). Tek fonksiyonluk koşu tüm-program prototiplerinden yoksun olduğu için başka metin verebiliyor (`:55`). [D]
   - **Hız:** rea PR #3854 yorumunda yalnız Linux x86-64 için tek koşu var:
     - zlib `uncompress`: Kuna ilk cevap 0,55 sn, dışa aktarma toplam ≈12 sn; Ghidra 17,5 sn.
     - SQLite `sqlite3VdbeExec`: Kuna ≈146 sn; Ghidra 120 sn.

     Mac arm64 karşılaştırması yok; doğruluk karşılaştırması da yok (`docs/testing.md:936`: "not a correctness judgement"). [T: tek koşu, doğrulanmadı]
   - **Öneri:** Ghidra'nın yerine değil. `kuna functions --json` çıktısı GT ve Ghidra başlangıçlarıyla karşılaştırılırsa iki bağımsız motorun ayrıştığı fonksiyonlar "şüpheli sınır" listesi verir. Bu küçük bir deneydir. Ürüne girmesi için önce bu deneyin sonucu gerekir. Makalede kıyas tabanı olarak kullanılabilir; sürüm ve sha256 sabitlenmeli. [T]
6. **ObjC analizörü takılması (Mac uygulamaları).** rea belgesi "Objective-C Message Analyzer"ın Swift/ObjC arm64 Mach-O'da takılabildiğini yazıyor ve kapatma yolu sunuyor (`docs/installation.md:1039-1043`). [D] Karadul'un Mac uygulaması yolunda analiz süresi sorunu görülürse ilk bakılacak yer burası. Bu bir sağlamlık notu; doğruluk kalemi değil. [T]

## İşimize yaramayanlar

- **Hopper köprüsü** (`bridge/hopper_bridge.py`, 1181 satır): ticari Hopper için ince bir API sarmalayıcısı. Algoritma yok; sözde kod, string ve prosedür listesini aktarıyor. [D]
- **IDA sağlayıcısı** (`docs/ida-provider.md`, `src/ida/`): `ida-pro-mcp` üstüne bir MCP bağdaştırıcısı ve lisanslı IDA gerektiriyor. Makaledeki IDA kıyası için IDA'nın kendi çıktısı doğrudan kullanılmalı; bu katman gereksiz. [D]
- **Cutter köprüsü** (`bridge/cutter/rea_bridge.py`): rizin komut aktarıcısı (`:420`). [D]
- **NativeAOT eklentisi** (`ReaGhidraExtensions.java`): .NET NativeAOT metaverisi. Test seti C. [D]
- **Mimariye özgü profiller:** MIPS soft-float, PSP, DOS COM/MZ, ham ikili hazırlığı, PPC, RISC-V. Karadul'un hedefi arm64 Mach-O ve ELF. [D]
- **"Native signature facts":** kod imzası gözlemi (`src/domain/native/nativeInspection.ts:149-155`: `team_identifier`, `cdhashes`, `entitlements`). Fonksiyon imzası ya da kütüphane tanıma değil. KS-8 için rea'da alınacak bir şey yok. [D]
- **Taşıma ve sahiplik makinesi:** soket kimlik doğrulaması, sha256 kabulü, süreç ve dizin temizliği, yığın bütçeleri. Çok kiracılı MCP sunucusu için gerekli; Karadul tek süreç. [D]
- **Maskeli bayt arama** (`docs/ghidra-provider.md`, "Masked byte search"): Karadul'un kendi bayt deseni eşleştiricisi var (`analyzers/byte_pattern_matcher.py`). [D]

## Açık sorular

1. **Gerçek ikilide dönmezlik hatası ne sıklıkta?** rea'da sayı yok. Karadul geliştirme setinde madde 1'in tanı adımıyla ölçülmeli: yanlış bayrak (RET'li dönmez fonksiyon) ve eksik bayrak (dönmeyen çağrıdan sonra komşuya akış), Mac ve Debian ayrı.
2. **`MachoFunctionStartsAnalyzer` Karadul koşularında açık mı?** Varsayılan değeri doğrulanmadı. Bir koşuda `getCurrentAnalysisOptionsAndValues` ile okunmalı. [T]
3. **Ghidra stripped ELF'te `.eh_frame` FDE başlangıçlarından fonksiyon yaratıyor mu?** `EhFrameSection` ve `FdeTable` sınıfları jar'da var [D], ama fonksiyon yaratma davranışı ve seçeneği okunmadı. KS-2'nin Debian tarafı buna bağlı.
4. **Chained fixup satırları hedefi doğrudan veriyor mu?** Relocation tablosu satırındaki `values` ve bellek baytları chained pointer'ın çözülmüş hedefini veriyor mu? Madde 3'ün iş büyüklüğü bu cevaba bağlı (M ya da S).
5. **GDT ve PDB analizden sonra yükleniyor** (`headless.py:259`, `:267`). İthal prototiplerinin analize ve decompile'a ne kadar yansıdığı bilinmiyor; yani TP-2'ye etkisi bilinmiyor. Madde 1'deki kanca bunları analiz öncesine de alabilir. Etkisi ayrıca ölçülmeli. [T]
6. **Java betiği PyGhidra içinden doğrudan çalıştırılabilir mi?** OSGi bundle host üstünden `GhidraScriptUtil` ile mümkün olabilir; denenmedi. Swift çözücü (madde 8) gibi büyük betiklerde port yerine bu yol daha ucuz olabilir. [T]
7. **Kuna'nın Mac arm64'te kalitesi ve `--jobs 1` ile ardışık koşu determinizmi** ölçülmemiş; elde yalnız rea'nın belgesi ve tek bir Linux PR yorumu var.
8. **Yetişmedi:** `src/ghidra/GhidraFunctionValues.ts` ve `GhidraInventoryValues.ts` (TS tarafı doğrulayıcıları) ile `trace_native_values`'ın çağrılar arası değer izleme mantığı (`src/application/EnhancedTools.ts`) okunmadı. DG-2 için ikincisinde yararlı bir birleştirme kuralı olabilir.
