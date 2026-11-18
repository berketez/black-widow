# Bulgu dizini — Karadul genel tarama 2026-11-18

Üretici: `mekanik/dizin_md.py` (kulvar dosyalarından). **D** = ana oturum bulguyu koddan ya da gerçek çıktıdan ayrıca doğruladı; boş = ajan bulgusu (onarımdan önce "Nasıl sınanır" denemesiyle görülmeli).

"Etkin" sütunu: evet = bugünkü öntanımlı akışta çalışan kod; bayrak = öntanımlı kapalı bayrağın arkasında; bağlı değil = KaradulLM (hiçbir giriş noktasına bağlı değil); ölü = hiç çağrılmıyor.

Toplam **137** bulgu: KRİTİK 11, YÜKSEK 47, ORTA 66, DÜŞÜK 13. Ana oturumun doğruladığı: 48. Ayrıca kulvar dosyalarının "Küçükler" bölümlerinde tek satırlık 105 kalem var.

| Kulvar | KRİTİK | YÜKSEK | ORTA | DÜŞÜK | Toplam |
|---|---|---|---|---|---|
| MEK | 0 | 2 | 7 | 5 | 14 |
| BORU | 0 | 3 | 9 | 2 | 14 |
| AD | 1 | 4 | 6 | 1 | 12 |
| TIP | 0 | 6 | 4 | 1 | 11 |
| IMZA | 4 | 6 | 5 | 1 | 16 |
| ARAYUZ | 1 | 4 | 12 | 2 | 19 |
| MUH | 2 | 3 | 6 | 1 | 12 |
| BICIM | 2 | 8 | 5 | 0 | 15 |
| GHIDRA | 1 | 7 | 8 | 0 | 16 |
| LM | 0 | 4 | 4 | 0 | 8 |

## KRİTİK

| Kimlik | D | Güven | Etkin | Başlık |
|---|---|---|---|---|
| AD-01 | D | yüksek | evet | `kebap_ad` alt kanalı tasarım gereği yanlış ad üretiyor ve 0,80–0,85 güvenle "doğrulanmadı" etiketiyle yayımlanıyor |
| ARAYUZ-01 | D | kesin | evet | Raporlar her ikilide "CFD", "roket yörüngesi", "matris çözücü" bileşimi; 16 ikilide "VPN tüneli kurulumu" iddia ediyor |
| BICIM-01 | D | kesin | evet | Webpack 4 nesne/dizi biçimli paketten çıkarılan her modül sözdizimi bozuk JS (adsız `function (…) {` deyimi); ikinci geçiş, adlı proje ve "çalıştırılabilir proje" hepsi bozuk girdiyle sürüyor |
| BICIM-04 | D | yüksek | evet | Düşman girdiden gelen metin, üretilen `build.gradle` ve `.csproj` içine kaçışsız yazılıyor: projeyi IDE'de açmak ya da derlemek analistin makinesinde saldırgan kodu çalıştırır |
| GHIDRA-11 | D | yüksek | bayrak | Dinamik analiz (`--dynamic`): hedef süreç kancalar yüklenmeden SÜRDÜRÜLÜYOR ve analiz bitince HİÇ öldürülmüyor; zararlı ikili Karadul çıktıktan sonra kancasız çalışmaya devam ediyor |
| IMZA-01 | D | kesin | evet | `binary_intelligence` her ikiliye "Bluetooth", "Encryption", "OpenGL", "SHA-256" yapıştırıyor: büyük harfli kısa belirteçler sınırsız ve büyük/küçük harf duyarsız alt dizgi olarak aranıyor |
| IMZA-02 |  | kesin | evet | Anti-debug dedektörü x86 işlem kodlarını (RDTSC `0F 31`, RDTSCP, INT3) mimariye bakmadan bütün dosyada arıyor: AArch64 coreutils ikilileri "Anti-Debug [MED]" alıyor |
| IMZA-05 | D | kesin | evet | Yerleşik YARA kuralları `nocase` + `any of them` ile tek alt dizgiye hüküm veriyor: coreutils `ls` "MPRESS ile paketli", redis "Delphi ile derlenmiş", `tree` "ASPack ile paketli" çıkıyor |
| IMZA-07 | D | kesin | evet | LMDB imza veritabanı her ada tek kitaplık tutuyor ve bu kitaplık "o adı içe aktaran Python paketi" olabiliyor: glibc `__printf_chk` → `opencv_python_headless`, `__assert_fail` → `cffi`, libselinux `fgetfilecon` → `psycopg2_binary`; hepsi 0,98 güvenle |
| MUH-01 | D | kesin | evet | `semantic_namer` parametrelere geçersiz C adı, C anahtar sözcüğü, tip adı ve küresel değişken adı veriyor; gövdede parametre sabite/küresele dönüşüyor (117 ikili, 1 163 imza) |
| MUH-03 | D | kesin | evet | Bileşim çözümleyicisi 119 ikilinin 119'una "Transient CFD Time-Stepping", "Matrix Solve Pipeline" ve "Rocket / Trajectory Simulation Loop" yazıyor; rapora giriyor |

## YÜKSEK

| Kimlik | D | Güven | Etkin | Başlık |
|---|---|---|---|---|
| AD-02 |  | yüksek | evet | `api_param_reverse` fonksiyona özgün ad değil ROL etiketi veriyor (`compare_func_5`, `event_callback_17`); güven 0,75 eşiği geçiyor |
| AD-03 |  | yüksek | evet | gnulib parmak izi ve çağrı şekli kanalı programa/platforma bakmadan HER ikilide ateşleniyor (Mach-O tmux'ta `close_stdout`) |
| AD-06 | D | kesin | evet | Faz 1 ad çıkarıcısının (BinaryNameExtractor) güven eşiği, "fonksiyon başına en iyi" seçimi ve çift ad temizliği boru hattında atlanıyor |
| AD-07 | D | yüksek | evet | Ön adların hepsine sabit 0,95 güven yazılıyor; ölçülmüş yanlış oranları (gnulib kabaca dörtte bir) analiste gösterilmiyor |
| ARAYUZ-02 |  | yüksek | evet | "Malware IOC" bölümü iki ayrı nedenle hiçbir zaman dolamaz (B-B6'nın eki: yol düzeltilse de dolmaz) |
| ARAYUZ-03 | D | kesin | evet | "Hakkında" penceresi eskimiş ve çürütülmüş bir doğruluk iddiası gösteriyor ("F1 ~0.45-0.49") |
| ARAYUZ-08 |  | yüksek | evet | Analistin açtığı temiz rapor (`<--output>/report.html`) paketleyici, anti-debug ve IOC bölümlerini hiç içermiyor |
| ARAYUZ-17 | D | kesin | evet | SARIF raporu kripto ve ad güvenilirliği bulgularını hiç üretmiyor, YARA isabetlerini yanlış kurala ve yanlış paket iddiasıyla basıyor |
| BICIM-02 |  | kesin | evet | JS yeniden kurma, deobfuscation çıktısını değil `deobfuscated/` altındaki EN BÜYÜK `.js` dosyasını işliyor (çoğu zaman özgün ya da yalnız güzelleştirilmiş dosya) |
| BICIM-05 |  | yüksek | evet | jadx ve ILSpy "başarılı" denetimi her zaman doğru: araç çökse de `decompiled: True` |
| BICIM-06 |  | yüksek | evet | Ağ bayrağı kapalıyken iki yol yine ağa çıkıyor: `.d.ts` indirmesi (unpkg) ve Electron ASAR açma (`npx --yes @electron/asar`) |
| BICIM-07 | D | kesin | evet | Hedef çözücü, var olmayan noktalı bir ad verildiğinde çalışma dizinindeki Python modülünü İÇE AKTARIYOR (kod yürütme); ayrıca sessizce başka bir ikiliyi hedef seçebiliyor |
| BICIM-08 |  | kesin | evet | Yerel (native) bir PE, içinde `mscoree.dll` / `mscorlib` / `System.Runtime` dizgisi geçti diye .NET sayılıyor; Ghidra hiç çalışmıyor, aşamalar "başarılı" |
| BICIM-09 |  | yüksek | evet | .app paketinde ana bileşen "en çok fonksiyonlu" seçiliyor: Electron/Java uygulamalarında asıl kod (JS, JAR) hiç yeniden kurulmuyor |
| BICIM-11 |  | kesin | evet | npm parmak izi, genel alt dizgilerle (eşiksiz) zararlı modülleri "Vendored <paket>" diye `vendor/` altına koyuyor |
| BICIM-12 |  | kesin | evet | JS "yeniden kurulmuş proje" yanıltıcı: giriş dosyası tek bir webpack modülü, ad/tip/yorum adımlarının çıktısı projeye girmiyor, README zararlıyı `npm install && npm start` ile çalıştırmayı öneriyor |
| BORU-01 | D | kesin | evet | Adım kipinde `stages.py` "eski monolit" bloğu hâlâ koşuyor: yapı kurtarma, CFG-iso ve füzyon her ikilide İKİ KEZ çalışıyor, ikinci yapı kurtarma kendi `originals/` yedeğini girdi sayıyor |
| BORU-05 | D | yüksek | evet | `reconstruct` aşamasının "başarılı" bayrağı fiilen hep True: ölçüt "en az bir yapıt var mı", hata listesi ve proje kurulumunun sonucu hesaba girmiyor |
| BORU-14 |  | kesin | evet | PDB, BinaryNinja, TRex, DWARF, Rust ve Go ad kanalları akışa BAĞLI DEĞİL: ad birleştiricisi bu girdiler olmadan çağrılıyor, ara tüketici adım üreticileriyle aynı paralel düzeyde koşup hiçbir şey görmüyor |
| GHIDRA-01 | D | kesin | evet | BSim'in "yedeğe düşme"si (B-B9, 78 ikili) eşzamanlı koşuda H2 veritabanı kilidinden; yedek yol ikiliyi iki kez daha decompile ediyor ve 5,7 bin fonksiyonlu ikilide Ghidra süresini ~5,5 katına çıkarıyor |
| GHIDRA-02 |  | kesin | evet | BSim ortak deposu sızıyor: sorgulanan ikili kendisiyle eşleşiyor (native) ve önceki koşulardaki SEMBOLLÜ kopyaların gerçek adları stripped ikiliye "BSim adayı" olarak geliyor (B-D2'nin kökü) |
| GHIDRA-04 |  | kesin | evet | `karadul.yaml` yükleyicisi yanlış yazılmış bölüm/anahtarı, yanlış tipi ve `min_confidence` bölümünü sessizce yutuyor; boş bölüm çöküyor; `karadul config validate` bunların hepsine "OK" diyor |
| GHIDRA-07 | D | kesin | evet | Hedef programı çalıştırma kapısı (`security.allow_target_execution`) dizgi değerini doğru sayıyor ve YAML'dan açıldığında hiçbir uyarı basılmıyor: `"false"`/`"no"` yazan kullanıcıda zararlı ikili Frida ile çalıştırılır |
| GHIDRA-09 |  | yüksek | evet | Ghidra'nın hata nedeni hiçbir çıktıya yazılmıyor; decompile/dizgi/tip/xref/CFG başarısızlığı "Ghidra başarılı" sayılıyor; Ghidra tamamen düşse de `static` aşaması başarılı görünüyor |
| GHIDRA-10 |  | kesin | evet | "Functions recovered" sayacı ve çıktı kaynak ağacı içe aktarım taslaklarını (PLT thunk + EXTERNAL blok taslağı) program fonksiyonu sayıyor: 119 ikilide sayılan 66 983 fonksiyonun %50,1'i thunk; her içe aktarım iki kez sayılıyor ve `fputs.c` gibi `halt_baddata()` gövdeli sahte dosyalar üretiliyor |
| GHIDRA-14 |  | yüksek | evet | `config.project_root` hem "çıktı kökü" hem "veri kökü": `--output-dir` (arayüz ve ölçüm her zaman, CLI verildiğinde) dış imza JSON'larını, FLIRT bayt imzalarını ve n-gram veritabanını sessizce devre dışı bırakıyor; sonuç komutun hangi dizinden/girişten çalıştırıldığına bağlı (AD-10, IMZA-11, B-D3'ün ortak kökü) |
| IMZA-03 |  | kesin | evet | PE'de MSVC çalışma zamanının olağan içe aktarımları ve 0xCC dolgusu anti-debug sayılıyor; puan "teknik sayısı × 0,05" ile şişiyor: pip'in başlatıcısı `w32.exe` "[HIGH]" alıyor |
| IMZA-04 | D | kesin | evet | Paketleyici dedektörü tek bir `0xBB` baytını "FSG" giriş imzası sayıyor: masum PE'lerin 10/11'inde FSG çıkıyor (ARM64 PE dahil) |
| IMZA-06 | D | kesin | evet | capa hiç çalışmıyor: Python API yolu `backend="auto"` ile capa 9.4'te her girdide `ValueError` veriyor, CLI yolu güvenli dizin listesi yüzünden bulunmuyor; durum yalnız `debug` günlüğüne düşüyor |
| IMZA-09 |  | kesin | evet | Protobuf "kısmi eşleşmesi" `Get`, `Set`, `Init`, `Next`, `Reset`, `Clear`, `Skip`, `Map` gibi 55 genel yöntem adını Google protobuf fonksiyonuna bağlıyor (0,85) |
| IMZA-11 |  | yüksek | evet | İmza veritabanının kapsamı depoda olmayan yerel dosyalara bağlı ve hiçbir çıktı hangi veritabanıyla koşulduğunu söylemiyor: taze kurulumda 9,2 M yerine ~7,7 bin ad, "eşleşme yok" ile "veritabanı yok" ayırt edilemiyor |
| IMZA-13 |  | yüksek | ölü | PDB, Binary Ninja, TRex, DWARF, Rust ve Go demangler ad kanalları etkin akışta hiç beslenmiyor: tek çağıran `binary_path`/`pdb_symbols`/`bn_functions`/`trex_structs` geçmiyor, `consumed_symbols`'u okuyan kimse yok |
| LM-01 | D | kesin | bağlı değil | Model önerisi hiçbir belirlenimci denetimden geçmiyor: tasarımın 15 kuralından (D0–D14) yalnız D0'ın yarısı ve D3'ün sınıflaması var |
| LM-02 | D | kesin | bağlı değil | Akış ya da gövde okunurken bağlantı kopması / zaman aşımı `LMError`'a sarılmıyor; ajan görevi "beklenmeyen hata" ile düşürüp istisna fırlatıyor |
| LM-03 |  | yüksek | bağlı değil | İstem enjeksiyonuna karşı yalnız kaçışlama ve istem kuralı var; ikiliden gelen dizgi ya da sembol adı modelin ad önerisine doğrudan dönüşebilir ve hiçbir şey bunu işaretlemez |
| LM-08 |  | kesin | bağlı değil | K0'ın gördüğü kanıt pilotunkinden fakir: bugünkü ürün çıktısında çağrılanların hiçbirinin adı yok; 5/5 çekimserliğin doğrudan nedeni |
| MEK-01 | D | kesin | evet | `karadul analyze` boru hattı başarısız olunca da çıkış kodu 0 veriyor ve hatayı ekrana yazmıyor |
| MEK-03 | D | yüksek | evet | "Öntanımlı çevrimdışı" sözü JS hattında tutmuyor: `.d.ts` indirmesi ağ bayrağına bakmadan unpkg.com'a gidiyor |
| MUH-02 |  | kesin | evet | "Döngü derinliği" aslında süslü parantez derinliği: `if` içinde kullanılan her `long/ulong/undefined8` parametre `M_matrix` / `v_vector` oluyor (59 ikili, 308 ad) |
| MUH-10 |  | kesin | evet | Mühendislik çözümleyicisinin sabit katmanı alt dizgiyle eşleşiyor (`"0" in code` → RC4 %90); 119 ikilide sessiz kalması yalnız bozuk bir "alan kapısı" sayesinde. Kapı açılınca `sort`'ta 1 384 sahte tespit |
| MUH-11 |  | yüksek | evet | `semantic_namer` adları ürün eşiğinden, ad süzgecinden ve köken kaydından geçmiyor: 0,40 güvenli sezgisel ad bile koda yazılıyor, `naming_map.json`'da izi yok |
| TIP-01 | D | kesin | evet | CFG-iso hiçbir zaman eşleşemez: sorgu düğümleri `{"instr": N}` histogramı taşıyor, şablonlar gerçek mnemonik; WL renkleri 0. adımda ayrışıyor, LSH hiç aday döndürmüyor |
| TIP-02 |  | kesin | evet | Hesaplama füzyonu kabul eşiğine matematiksel olarak ulaşamaz, iki kanıtı hiç birleştirmez ve sonucunu tüketen etkin adım yok |
| TIP-06 | D | kesin | evet | Tip kurtarma değişken kullanımını ikili genelinde yalnız ADA göre birleştiriyor ve dizgi sabitindeki "8.0.2"yi kayan nokta sanıyor: yanlış fonksiyona yanlış tip yazılıyor, ürüne ulaşıyor |
| TIP-07 | D | kesin | evet | Ürünün `types.h`'sindeki `recovered_struct_NNN`'ler ölçeklenmemiş işaretçi aritmetiğinden ve ilgisiz fonksiyonların aynı adlı değişkenlerinden kuruluyor: yanlış ofset, üst üste binen alan, 0,80 "güven"; 5 585 yapının koda bağlanan yalnız 3'ü |
| TIP-09 | D | kesin | evet | Yapısal algoritma katmanı hâlâ alt dizgi ve tek eşleşmeyle kripto etiketi basıyor: `mode`/`mode_t` → "Galois field operations (ECC, AES-GF)", ürün koduna `ALGORITHM:` yorumu olarak giriyor |
| TIP-11 | D | kesin | evet | XTRIDE tip katmanı Ghidra'nın somut `long`/`ulong` bildirimini eziyor ve dizgi sabitindeki "2.5"i kayan nokta kanıtı sayıyor: `long lVar1` → `double lVar1` |

## ORTA

| Kimlik | D | Güven | Etkin | Başlık |
|---|---|---|---|---|
| AD-04 |  | kesin | evet | NameMerger ön adı iki bağımsız kaynak sayıyor: aynı kanıt `binary_extractor` (0,85) + `c_namer` (0,95) → 0,99 ve sahte "exact_multi" sayacı |
| AD-05 |  | kesin | evet | NameMerger'ın kararı koda neredeyse hiç ulaşmıyor ve hiçbir yere kaydedilmiyor; ulaştığı tek yol c_namer süzgeçlerini atlayan bir yan yol |
| AD-08 | D | kesin | evet | Yerel değişken/parametre adları ikili GENELİNDE tekilleştiriliyor: htop'ta yerel adların %93'ü `buf_308` türü sayaç eki taşıyor |
| AD-09 |  | yüksek | evet | Susturma yan yolu: c_namer'da susan dizgi sinyalleri (Class::Method "agresif", hata iletisi) Faz 1 çıkarıcısından ÖN AD olarak geçiyor |
| AD-10 |  | yüksek | bkz. dosya | N-gram yerel ad kanalı `--output-dir` ile hiç çalışmıyor (sessizce), çalıştığında ad süzgeçsiz ve kökensiz regex ile yazıyor |
| AD-11 | D | yüksek | bkz. dosya | BinDiff / ReferenceDiffer adları ön ad sözlüğünü koşulsuz eziyor (`extracted_names.update`); elle verilen ad ve `main` sonraki yinelemede kaybolabilir, elle adı zorlayan aşama yalnız ölü monolitte |
| ARAYUZ-04 |  | kesin | evet | Ayarlardaki "Maks. fonksiyon" düğmesi hiçbir yerde okunmuyor |
| ARAYUZ-05 |  | yüksek | evet | "Çevrimiçi kaynak eşleştirme" düğmesi etkisiz |
| ARAYUZ-06 | D | yüksek | evet | Arayüzden "Kaydet" `karadul.yaml`'daki diğer bütün ayarları sessizce siliyor |
| ARAYUZ-07 |  | kesin | evet | Raporlarda hiç dolmayan sayaçlar: "Coverage N/A%", "Modules N/A/0", "Deobf Steps N/A/0"; JSON'da 0 olarak yazılıyor |
| ARAYUZ-09 |  | kesin | evet | Aynı `--output` dizinine ikinci koşu eski dosyaları bırakıyor; "Names Recovered" eski kodla şişiyor |
| ARAYUZ-10 |  | yüksek | evet | Analiz ekranında iptal yok; iş kaybolunca ya da sunucu hata verince ekran sonsuza dek "çalışıyor…" kalıyor |
| ARAYUZ-11 |  | yüksek | evet | Sonuç ekranı kısmi başarısızlığı gizliyor; desteklenmeyen hedefte "pipeline hata verdi" diye yanlış ileti veriyor |
| ARAYUZ-12 | D | kesin | evet | Fonksiyon listesi 600 satırda sessizce kesiliyor ve sayaç kesilmiş sayıyı "toplam" gibi gösteriyor |
| ARAYUZ-13 |  | yüksek | evet | Arayüz her ad atanmış fonksiyonu "çözüldü" ve "RECONSTRUCTED" sayıyor; zayıf ve doğrulanmamış adlar dahil |
| ARAYUZ-14 |  | yüksek | evet | Ad düzeltme: kalıcılık sessizce düşebiliyor, yanlış ikiliye bağlanabiliyor, çakışan ad engellenmiyor |
| ARAYUZ-18 |  | kesin | evet | Çıktıdaki `types.h`'de kurtarılan yapıların 1 168'i kendi açıklamasındaki ofsetlerle çelişen, üst üste binen alanlar taşıyor |
| ARAYUZ-19 |  | yüksek | bkz. dosya | Vizyona göre arayüzde eksik olanlar (eksik özellik; 6 kalem) |
| BICIM-03 |  | kesin | evet | JS ad/parametre sayaçları birbirini tutmuyor; CLI "Results" tablosunun dört satırı hiç üretilmeyen anahtarları okuyor |
| BICIM-10 |  | kesin | evet | "Desteklenen" birçok biçim tanınmıyor ya da yanlış hatta gidiyor (tek `.pyc`, cx_Freeze, wheel/IPA/nupkg, FAT64, evrensel ikili içindeki Go/PyInstaller/Bun); UNKNOWN türü JS yeniden kurmasına düşüp yanıltıcı hata veriyor |
| BICIM-13 |  | kesin | evet | Modül ayırma (ModuleSplitter) ve çok modüllü proje kurucu (ProjectReconstructor) hiç çalışmıyor: yanlış dizin aranıyor |
| BICIM-14 |  | yüksek | evet | PyInstaller CArchive açmada toplam boyut bütçesi yok; aynı adlı girdiler sessizce birbirini eziyor |
| BICIM-15 |  | yüksek | ölü | Kulvarda çağrılmayan modüller ve dallar (ölü kod) |
| BORU-02 |  | kesin | evet | `originals/` yedeği çıktı dizininin İÇİNE yazılıyor; sonraki adımlar onu kaynak sanıp işliyor, `inline_patterns_detected` iki katı sayılıyor |
| BORU-03 |  | yüksek | evet | CFG-iso → füzyon zincirinin çıktısını hiçbir adım okumuyor; üstelik iki kaynağın anahtarları hiç kesişmiyor |
| BORU-06 |  | kesin | evet | Aşama içinden kaçan HER istisna aşamayı baştan 4 kez koşturuyor (belirlenimci hatalar dahil); adım koşucusu tekli düzeyde özgün istisnayı yükseltiyor, `except RuntimeError` bunu yakalamıyor |
| BORU-07 |  | yüksek | evet | `karadul batch analyze`: her hedef "BAŞARILI" sayılıyor, kullanıcı ayarı okunmuyor, tek bir işçi sürecinin çökmesi bütün partiyi düşürüyor |
| BORU-08 |  | yüksek | evet | `.app` paketinde ana bileşen bir JAR ise reconstruct "Bilinmeyen bilesen tipi" ile düşüyor (JAR'ın kendi hattı varken) |
| BORU-09 |  | kesin | evet | Çalışma dizini saniye çözünürlüklü ve `exist_ok=True`: aynı adlı iki hedef aynı saniyede başlarsa AYNI dizine yazıyor |
| BORU-10 |  | yüksek | evet | Fonksiyonlar arası parametre adı yayılımı hesaplanıp ATILIYOR; `param_names_propagated` sayacı hiçbir koda yansımayan adları "yayıldı" diye sayıyor |
| BORU-11 |  | yüksek | evet | Adım listesindeki sıra yok sayılıyor; Faz 3'te `inline_detection` aynı dizini yerinde yazarken `semantic_naming` paralel olarak okuyor, `inline_detection` da yapı kurtarma ÖNCESİ önbellekle dosyaların üstüne yazıyor |
| BORU-12 |  | kesin | bkz. dosya | `stages.py` ölü kod haritası: ~2 750 satır hiç çalışmıyor ama hâlâ bakımı yapılıp testle sınanıyor (son örnek 2026-11-12) |
| GHIDRA-03 |  | yüksek | evet | BSim lite dizini ortak bir JSON dosyası: eşzamanlı koşular birbirinin kaydını siliyor, yazım atomik değil, okunamayan dosya sessizce SIFIRDAN başlatılıp üstüne yazılıyor |
| GHIDRA-05 |  | yüksek | evet | `decompiled.json`'daki 500 fonksiyon iş parçacıklarının bitiş sırasına göre seçiliyor; Ghidra'nın yüksek düzey değişken tipleri yalnız bu rastgele altkümeye uygulanıyor (B-B4'ün belirlenimsizlik yüzü) |
| GHIDRA-06 |  | yüksek | evet | PyGhidra yolunda Ghidra zaman aşımı fiilen yok: otomatik analiz sınırsız, paralel decompile'daki toplam süre denetimi hiç tetiklenemez; `timeouts.ghidra`, büyük ikili çarpanı, `ghidra_batch_size`, `analysis.ghidra_max_heap_mb`, `max_decompile_timeout_per_func` öntanımlı yolda etkisiz |
| GHIDRA-08 |  | bkz. dosya | bkz. dosya | `analyzeHeadless` (CLI) yedeği sabitlenen Ghidra 12.1.2 ile çalışamaz durumda ve çıktı dosya adları PyGhidra yoluyla tutmuyor: CFG ve P-Code yedek yolda `ghidra_ghidra_cfg.json` olarak kaydedilip aşağı akışta kayboluyor; Ghidra'nın betik hatası "başarı" sayılıyor |
| GHIDRA-12 |  | bkz. dosya | evet | `karadul bsim` alt komutları analizin kullandığı veritabanını yönetmiyor: `create`/`list` JVM'siz koştuğu için hep lite kipte, `query --db` seçeneği yok sayılıyor, `ingest`/`query` Ghidra projesini incelenen ikilinin yanına bırakıyor, `list` her çağrıda dizini yeniden yazıyor |
| GHIDRA-13 |  | yüksek | evet | `karadul run` analiz edilen (güvenilmeyen) kodu yerelde, ağ ayarına bakmadan çalıştırıyor: `npm install` analiz edilen paketten çıkarılan bağımlılık adlarını npm kayıt deposundan indiriyor, `npm start`/`node` korumasız koşuyor; uyarı metni riski küçümsüyor; çalışma alanı yoksa yığın izi |
| GHIDRA-15 |  | yüksek | ölü | Ghidra kulvarında ölü/koşmayan katmanlar (~7 000 satır): çoklu decompiler arka ucu, 10 Ghidra betiği + 10 Jython yedeği, hata ayıklayıcı köprüsünün yakalama kısmı; bakım yükü ve iki yolun ayrışması |
| GHIDRA-16 |  | kesin | evet | PyGhidra yolunun dizgi kaydında fonksiyon bağı yapısal olarak hep boş (80 545 dizginin 0'ı); düzeltme yalnız koşmayan betikte yapılmış; yorum üreticisinin "fonksiyonun kullandığı dizgiler" kanalı ölü |
| IMZA-08 |  | kesin | evet | ELF'te imza eşleşmesi adın baştaki bütün alt çizgilerini siliyor: `__printf_chk` → `printf_chk`, `__cxa_atexit` → `cxa_atexit` (var olmayan adlar) "kurtarılan ad" olarak raporlanıyor |
| IMZA-10 |  | kesin | bkz. dosya | İmza veritabanının süreç düzeyindeki önbelleği yalnız `project_root` ile anahtarlanıyor; platform süzgeciyle yüklenen dış imzalar sonraki farklı platformlu hedefe yanlış küme olarak geçiyor |
| IMZA-12 |  | kesin | evet | Yerleşik imza sözlükleri birleştirilirken sonraki sözlük öncekini ezer: 28 temel POSIX adı (`_open`, `_read`, `_write`, `_close`, `_stat`, `_getpid`, `_snprintf`…) MSVC CRT kaydıyla ezildiği için Mach-O'da hiç eşleşmiyor (B-C7'nin ölçülmüş etkisi) |
| IMZA-14 |  | kesin | bkz. dosya | Rust legacy demangler `$…$` kaçışlarını çözmüyor: her kapanış (`{{closure}}`) ve her `<impl X for Y>` adı yarı bozuk çıkıyor; v0'da punycode, geri başvuru ve sabit jenerik yer tutucuyla "tam ad" gibi dönüyor |
| IMZA-15 |  | yüksek | evet | Anti-debug, paketleyici ve YARA taramalarında "taranamadı" ile "temiz" aynı görünüyor: hata ya da kısmi tarama durumunda JSON "0 bulgu" yazılıyor, rapor bölümü hiç basılmıyor |
| LM-04 |  | yüksek | bağlı değil | Jeton kestirimi ikiliden gelen onaltılık adres listelerini düz İngilizce metin oranıyla (4,294 bayt/jeton) sayıyor; ~%8 düşük kestirimin ana kaynağı bu |
| LM-05 |  | yüksek | bağlı değil | Yerel model sunucusu ana süreç çökerse ya da arayüzün ebeveyn bekçisi `os._exit` ile çıkarsa yetim kalıyor (≈16 GiB, `mlock`'lu); tasarımdaki "ebeveyn bekçisi" yazılmamış |
| LM-06 | D | yüksek | bağlı değil | İptal olayı hiç sıfırlanmıyor (bir kez iptal edilen ajan sonraki bütün görevleri model çağırmadan `iptal` ile bitiriyor); süre bütçesi öntanımda hiç uygulanmıyor |
| LM-07 |  | kesin | bkz. dosya | Testlerin tamamı sahte arka uç / sahte taşıma ile; kopma, yapışkan iptal, tamsayı biçimli kayan nokta argüman ve K1/K2 şemasının motorda derlenmesi hiç sınanmıyor |
| MEK-02 | D | kesin | evet | `karadul diff` Ghidra projesini incelenen ikilinin yanına yazıyor |
| MEK-04 | D | yüksek | evet | Uygulama her açılışta, ağ ayarından bağımsız olarak GitHub'a güncelleme sorgusu atıyor; kapatma ayarı yok |
| MEK-05 | D | yüksek | evet | 231 ayar alanının 83'üne kodda öznitelik erişimi yok; ~50'si hiçbir biçimde okunmuyor |
| MEK-07 | D | yüksek | bkz. dosya | Ürün giriş noktalarından erişilemeyen 46 modül / 8 149 satır |
| MEK-08 | D | kesin | evet | Arayüz: adsız fonksiyon etiketi adresin son 6 hanesinden üretiliyor; yeniden adlandırma kutusu bu uydurma etiketle doluyor |
| MEK-11 | D | kesin | bkz. dosya | İmza veritabanı Ghidra'nın yapay `entry` etiketini CoreGraphics simgesi sayıyor (güven 0,98) |
| MEK-12 | D | kesin | bkz. dosya | JS hattı kendi örnek dosyasında kısmi başarısız: çıkarılan modüller ayrıştırılamıyor; sayaçlar birbirini tutmuyor |
| MUH-04 |  | kesin | evet | Alan sınıflandırıcısı ikilinin BÜTÜN dizgilerini her fonksiyona aynı kanıt diye ekliyor ve eşitlikte "structural"ı seçiyor: redis'te SHA-256 fonksiyonu `ACLHashPassword` "structural" (yapısal mühendislik) alanında |
| MUH-05 |  | yüksek | bkz. dosya | Güven "kalibrasyonu" hiçbir karara girmiyor; `confidence_calibration.py` ölü ve "Platt" katsayıları iki elle seçilmiş noktadan |
| MUH-06 |  | kesin | evet | C++ sanal çağrı çözücüsü Ghidra'nın gerçek biçimini tanımıyor: 119 ikilide 0 çağrı yeri (C++ `pzstd`'de 178 `(**(code **)` dahil) |
| MUH-08 |  | yüksek | evet | `deep_tracing` adımının "parametre adı yayılımı" ad hesaplayıp hiçbir yere uygulamıyor; raporda "param_names_propagated" sayacı uygulanmamış adları sayıyor (119 ikilide 1 835) |
| MUH-09 |  | kesin | bkz. dosya | Başvuru karşılaştırması: sürüm tespiti "requires SQLite 3.8.12 or later" dizgisinden sürümü 3.8.12 / güven 0,99 diye okuyor; en yakın sürüm araması dizgi öneki ("3.8.12" ↔ "3.8.1"); boş `reference_db_path` "atla" değil ortak önbelleği kullan demek |
| MUH-12 |  | kesin | evet | Formül çıkarıcı belirsiz/zayıf tespiti belirli bir algoritmaya yükseltiyor ("S-box (AES, DES)" → DES formülü), formülü fonksiyonla bağlamıyor ve otomatik üretilmiş ASCII formüllerin bir kısmı işleç kaybından matematiksel olarak yanlış |
| TIP-03 |  | yüksek | bayrak | MaxSMT yapı kurtarmanın ofset kök nedeni: LOAD/STORE'un ilk sabit girdisi alan kimliği (433 = `ram`), alan ofseti sanılıyor; sonuç da hiçbir etkin adıma bağlı değil |
| TIP-04 |  | yüksek | evet | Öntanımlı açık mühendislik yapı kurtarması yalnız Ghidra'nın sistem yapılarını alıp gerçek alan adlarını genel tahminlerle eziyor, koda hiç bağlanmıyor; çıktısını kimse okumuyor |
| TIP-05 |  | yüksek | bkz. dosya | Yapı kurtarmanın koddan çıkarma ve yeniden yazma yolları değişkeni yalnız ADIYLA tanıyor: farklı fonksiyonlardaki `param_1`'ler tek yapıya birleşir, yeniden yazım her dosyada aynı ada uygulanır |
| TIP-08 | D | kesin | evet | `@security` başlık etiketi fonksiyon adında alt dizgi aramasıyla veriliyor: "dispatch"→"Code injection/hooking", "Token"→"authentication", Redis `Key`→"sensitive key material" |

## DÜŞÜK

| Kimlik | D | Güven | Etkin | Başlık |
|---|---|---|---|---|
| AD-12 |  | kesin | ölü | Paralel adlandırma koşucusu ölü kod: `CVariableNamer`'da beklenen dosya başı yöntemler yok |
| ARAYUZ-15 |  | kesin | evet | Teşhis kartı analisti var olmayan bir ayara yönlendiriyor |
| ARAYUZ-16 |  | kesin | evet | Uygulama her açılışta GitHub'a "güncelleme var mı" isteği atıyor; "varsayılan çevrimdışı" sözüyle çelişiyor |
| BORU-04 |  | yüksek | bayrak | `--maxsmt-struct` açıkken MaxSMT çözücüsü iki kez koşuyor; adımın ürettiği adayları hiçbir adım okumuyor, yapı motoruna yalnız "monolit" kopya iletiyor |
| BORU-13 |  | yüksek | bkz. dosya | Okunmayan ayarlar ve etkisiz CLI bayrakları (bu kulvarın akışı açısından) |
| IMZA-16 |  | kesin | ölü | `enable_rtti_recovery` ayarı hiçbir yerde okunmuyor; C++ RTTI kurtarma analiz akışına bağlı değil, yalnız ayrı `karadul rtti` komutuyla erişilebiliyor |
| MEK-06 | D | kesin | bkz. dosya | mypy 101 hata veriyor ve CI'da mypy koşmuyor |
| MEK-09 | D | kesin | bkz. dosya | CLI küçük kusurları |
| MEK-10 | D | kesin | bkz. dosya | Hiç koşmayan / hep atlanan testler |
| MEK-13 | D | kesin | bkz. dosya | Depoda kişisel/sabit yollar ve artıklar |
| MEK-14 | D | kesin | bkz. dosya | `dotnet_binary.py` aynı adı iki kez içe aktarıyor |
| MUH-07 |  | yüksek | evet | "Row-major matrix access" yorumu her `a[i*2 + 1]` dizi-içi-yapı erişimine yazılıyor ve ürüne giriyor (370 yorum) |
| TIP-10 |  | yüksek | evet | `karadul score` okunabilirlik puanı doğruluğu ölçmüyor: her FUN_ olmayan İngilizce köklü ad "anlamlı" sayılıyor, "temel" puan sabit 100 |
