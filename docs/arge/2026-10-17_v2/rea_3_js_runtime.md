# rea incelemesi 3: JavaScript/Electron, çalışma zamanı gözlemi, doğrulama altyapısı

- **Tarih:** 2026-10-17
- **İncelenen:** rea (MIT), sığ klon.
  - JS: `src/domain/javascript/**` (292 dosya; seçilenler okundu), `src/application/javascript/**` (dosya listesi).
  - Çalışma zamanı: `bridge/native/rea_lldb_tracer.py` ve testi, `bridge/process/*.swift`.
  - Belgeler: ilgili `docs/*.md` ve `.agents/.../runtime-observation.md`.
  - Doğrulama: `.github/workflows/{real-javascript-recovery,mutation}.yml`, `scripts/verify/javascript/recovery.mjs`, `scripts/verify-native-calls.mjs`.
- **Yöntem:** Yalnız okuma. rea'dan hiçbir betik, test ya da npm komutu çalıştırılmadı. Yerel ölçüm olarak yalnız `codesign -dv` ve `DevToolsSecurity -status` çalıştırıldı; ikisi de salt okuma.
- **İşaretler:**
  - **[D]**: koddan ya da yerel ölçümden doğrulandı.
  - **[T]**: tahmin.
- **Yollar:** rea yolları klon köküne, Karadul yolları `~/Black_Widow` köküne göredir.

## Özet

1. rea JS'de küçültülmüş adları kurtarmıyor. Sözdizimini dış motor Wakaru'ya bırakıyor ve "özgün değişken adları bilinmiyor" diyor [D]. Bu açıdan Karadul önde. rea'nın değeri isimde değil: Electron API'sini, IPC kanalını ve modül tablosunu **bağlama kimliğiyle**, yani addan bağımsız çözüyor [D].
2. LLDB izleyicisi yalnız fonksiyon girişlerini kaydediyor: ham argüman yazmaçları, ObjC seçicisi ve alıcı sınıfı, **dosya adresli çağıran çerçeveleri**. Dönüş değeri ve genel bellek okuması yok [D].
3. Karadul'un Frida izinde çağıran bilgisi yok. Buna rağmen `DynamicNamer` süreç genelindeki API listesinden 0,88 güvenle değişken adı yazıyor [D]. En değerli alım: önce bu kanalı dürüst yapmak, sonra kanıtı çağıran çerçevesiyle fonksiyona bağlamak (madde 1–2).
4. Karadul'un JS hattında isim doğruluğu ölçülmüyor ve Electron'da yalnız en büyük JS dosyası isimlendiriliyor [D]. rea'nın sabit sürümlü paketleyiciyle kurduğu fixture'lar ve kaynak haritası çözücüsü, JS ölçümüne zemin olabilir (madde 3–4).
5. Süreç yakalama (PTY ve dosya anlık görüntüsü) sistem çağrısı izi değildir; isimlendirmeye katkısı yok [D].
6. Soruların yeri:
   - S1: "İşimize yaramayanlar"; ayrıca madde 5 ve 7.
   - S2: madde 4 ve 7.
   - S3: madde 4, 5 ve 6.
   - S4: madde 1, 2 ve 8.
   - S5: "İşimize yaramayanlar".
   - S6: madde 3, madde 8 ve mutasyon fikri.

## Kullanılabilir özellikler

### 1. Dinamik isim kanalını dürüst yapmak: rea'nın "gözlem iddia değildir" ilkesi

**Ne yapıyor (rea)**

- rea çalışma zamanı gözleminden isim çıkarmıyor. Her sonuç kapsamı ve sınırlarıyla raporlanıyor [D].
- Hiç eşleşmeyen bir kesme noktası kapsamı "kısmi" yapıyor [D].
- Kaynak: `docs/native-investigation.md:460-464`, `:480-482`.

**Karadul'da karşılığı (sorunlu)**

- `DynamicNamer` yalnız süreç genelindeki API ad kümesini kullanıyor [D] (`karadul/reconstruction/dynamic_namer.py:183-194`).
- C metninde `api(` geçen her yere APIParamDB'deki parametre adını yazıyor [D] (`:285-350`). Güven sabit 0,88 [D] (`:76`).
- İzde çağıranın hangi fonksiyon olduğu yok (bkz. madde 2). Yani bu, statik APIParamDB eşlemesinin "çalışma zamanı" etiketi taşıyan bir kopyası [D].
- Varsayılan açık [D] (`karadul/config.py:415`). n-gram'dan önce uygulanıyor [D] (`karadul/stages.py:4500-4540`).
- `dynamic` aşaması varsayılan sırada [D] (`karadul/cli_common.py:46-53`). Frida yüklüyse `analyze` hedefi çalıştırıyor [D] (`karadul/stages.py:541-568`).
- Ölçüm hattı `--skip-dynamic` kullanıyor [D] (`scripts/measurement/measure.py:237`). Yani F1 kirlenmiyor; kirlenen ürün çıktısı.
- Ürün çıktısı Frida'nın kurulu olup olmamasına göre değişiyor [D].
- Bu makinede `frida` CLI kurulu (`/opt/anaconda3/bin/frida`) [D]. Karadul'un kendi Python ortamında modülün yüklü olup olmadığına bakmadım.

**Plan kalemi:** ÖL-7 (determinizm), ÖL-1 (her statü ayrı raporlanır), MD-1 türü statü ayrımı.

**Beklenen etki [T]:**

- Yanlış ad (YN) azalır.
- "Çalışma zamanı" güveniyle yazılan statik tahminler kalkar.
- Ürün varsayılan olarak bilinmeyen ikiliyi çalıştırmaz.

**Uyarlama yolu (S)**

1. Madde 2 bitene kadar `enable_dynamic_naming` kapalı kalsın. `dynamic` aşaması yalnız açık bayrakla çalışsın.
2. Madde 2 gelince yalnız fonksiyona bağlanmış olaylar kullanılsın. Statü "tarif" olsun; kanıt künyesi zorunlu.

**Nasıl ölçülür**

- Aynı ikiliyi Frida varken ve yokken çözümle. `naming_map` farkı 0 olmalı (ÖL-7).
- Bugünkü durumda dinamik kanalın yazdığı ad sayısını ve bu adların DWARF'a göre doğruluğunu çıkar.

### 2. Dinamik kanıtı fonksiyona bağlamak: kesme noktası ve dosya adresli çağıran çerçevesi (LLDB)

**Ne yapıyor (rea)** [D]

- İzleyici hedefi `lldb --batch` içinde kendisi başlatıyor ve girişte durduruyor.
- İstenen sembollere kesme noktası koyuyor: ad ile ya da ObjC seçicisiyle. Adres ile kesme noktası yok.
- Her vuruşta kaydettikleri:
  - iş parçacığı;
  - ham argüman yazmaçları (arm64'te x0–x7, x86-64'te rdi–r9);
  - ObjC metotlarında `_cmd`'den okunan seçici dizesi ve alıcının dinamik sınıfı;
  - istenen derinlikte çağıran çerçeveleri.
- Her çerçevede yükleme adresi, **dosya adresi** (ASLR kayması çıkarılmış), modül ve sembol var.
- Hiçbir ifade değerlendirilmiyor; hedefin adına kod çalıştırılmıyor.
- Görmedikleri: dönüş değeri, kayan nokta ve yığın argümanları, satır içi ve `objc_direct` çağrılar.

**Kanıt** [D]

- `bridge/native/rea_lldb_tracer.py`:
  - `:1-10`: amaç;
  - `:22-27`: argüman yazmaçları;
  - `:247-261`: `load_address`, `file_address`, modül, sembol;
  - `:268-296`: kesme noktası yalnız ad ya da seçiciyle;
  - `:299-313`: alıcı sınıfı `eDynamicDontRunTarget` ile okunuyor;
  - `:339-385`: olay kaydı;
  - `:403-450`: çağıran çerçeveleri;
  - `:593-597`: `target.skip-prologue false`, yani yazmaçlar hâlâ ABI argümanlarını tutarken durur.
- Sınırlar: `docs/native-investigation.md:438-458`, `:506-514`.

**macOS koşulları**

- Kullanıcıya hata ayıklama izni (Developer Tools) gerekir [D].
- Hardened runtime'lı olup `com.apple.security.get-task-allow` yetkisi taşımayan hedef izlenemez [D].
- rea yalnız kendi başlattığı süreci izler, var olana bağlanmaz [D] (`docs/native-investigation.md:457-458`, `:510-514`).
- Yerel ölçüm, 2026-10-17 [D]:

  | İkili | İmza | Hardened runtime | `get-task-allow` |
  |---|---|---|---|
  | Homebrew `tmux` | ad-hoc, `flags=0x2(adhoc)` | yok | — |
  | Homebrew `htop` | ad-hoc, `flags=0x2(adhoc)` | yok | — |
  | VS Code `Electron` | Developer ID | var, `flags=0x10000(runtime)` | yok |
  | Slack | Developer ID | var, `flags=0x10000(runtime)` | yok |

  Bu makinede `DevToolsSecurity` çıktısı: "Developer mode is currently disabled".
- Geliştirme setindeki Homebrew C programları izlenebilir görünüyor [T]. Electron uygulamaları ancak yeniden imzalanmış bir kopyayla izlenebilir [T].
- rea belgelerinde SIP hakkında bir ifade yok [D]. SIP'li sistem ikililerinin yerinde izlenemeyeceğini tahmin ediyorum [T].
- Debian ELF seti Mac'te çalışmaz. Karadul bu durumu zaten "atlandı" diye işliyor [D] (`karadul/stages.py:492-506`).

**Karadul'da karşılığı** [D]

- Frida kancaları yalnız libc dışa aktarımlarını yakalıyor (`karadul/frida/hooks/generic_hooks.js:42-341`).
- `returnAddress`, `backtrace`, `Thread.`, `DebugSymbol` üç kanca dosyasının hiçbirinde geçmiyor. Yani çağıran fonksiyon kaydedilmiyor.
- `karadul/ghidra/debugger_bridge.py` LLDB betiği üretiyor:
  - adres ya da ad ile kesme noktası (`:360-368`);
  - çerçeve başına yalnız `pc`, yani yükleme adresi (`:343-347`); dosya adresi yok.
- Bu köprüdeki `capture_at_breakpoints` (`:567`) hiçbir yerden çağrılmıyor. Aşama yalnız hata ayıklayıcının varlığını algılıyor (`karadul/stages.py:650-668`).

**Plan kalemi**

- TR-1: gözlenen dolaylı çağrı kenarları.
- TR-4: tablodan çağrılan fonksiyonun gerçek çağıranı.
- TR-7: argüman değerleri.
- KS-7: ObjC alıcı sınıfı.
- MD-2: kanıt paketine "dinamik" alanı.
- ÖL-3: kanıt erişimi.
- Dinamik kanala ait ayrı bir kalem yok. **Yeni kalem** önerisi: "DN-1: fonksiyona bağlı dinamik kanıt kanalı".

**Beklenen etki [T]**

- Statü "tarif" olur, "kesin" değil. Kapsama senaryoya bağlıdır.
- Kazanç iki yerde:
  - (a) Statik grafta görünmeyen dolaylı kenarlar. htop'ta fonksiyonların çoğu tablolardan çağrılıyor (TR-4; oran ölçülmedi).
  - (b) API argüman değerleri. Örneğin `open("…/htoprc")` çağıranı "ayar dosyası okuyucu" tarifini alır.
- Kapsama tavanı ölçülmeden yüzde verilemez.

**Uyarlama yolu (M)**

1. Karadul'un uykudaki `DebuggerBridge`'ini rea'nın kayıt biçimine çek:
   - her çerçeve için `GetFileAddress()`;
   - `skip-prologue=false`.
2. İki kesme noktası ailesi kur:
   - ithal API'lere, ad ile;
   - iç fonksiyonlara, Ghidra adresinden bölüm göreli `SBAddress` ile ve **tek atımlık** olarak: ilk N vuruşta çağıranı kaydet, sonra `SetEnabled(False)`. Maliyet tahmini [T].
3. İşaretçi argümanlarını `ReadCStringFromMemory` ile oku. rea bunu yalnız seçici için yapıyor [D] (`rea_lldb_tracer.py:357-363`).
4. İz, test setindeki **strip edilmiş** kopyada alınmalı. Çerçevelerdeki `symbol` alanı iç fonksiyonlar için atılmalı; yoksa özgün ad kanıta sızar [T].
5. Çıktı biçimi: `{fonksiyon, olay türü, kanıt, senaryo kimliği}`. Kanal isim yazmaz, yalnız tarife ve kanıt paketine girer.
6. Ölçümde kapalı kalır. Makalede yer alırsa yalnız ayrı tabloda.

**Nasıl ölçülür**

- Önce kâhin (madde 8): `-g` ile derlenmiş fixture ve strip edilmiş ikizi. Atfedilen çağıranın `file_address` değeri `nm`'deki adresle birebir tutmalı.
- Test setinde:
  - senaryo başına çalışan fonksiyon oranı;
  - statik grafa eklenen dinamik kenar sayısı;
  - kanıt erişimi, önce ve sonra (ÖL-3);
  - dinamik kanıtla verilen tariflerin rubrik sonucu (ÖL-1).

### 3. JS isim ölçüm zemini: sabit sürümlü paketleyici, kaynak haritası `names`, davranış kâhini

**Ne yapıyor (rea)** [D]

- JS kurtarma şeridi, kaynağı depoda duran fixture'ları CI'da sabit sürümlü araçlarla derliyor: `esbuild@0.25.10`, `webpack@5.101.3`, `--ignore-scripts`.
- Dış motoru SHA-256 ile doğruluyor.
- Kaynak: `.github/workflows/real-javascript-recovery.yml:37-50` (özellikle `:43` ve `:45`).
- Kurtarılan modül ile özgün paket aynı sonlu girdiyle çalıştırılıyor ve çıktıları karşılaştırılıyor (`scripts/verify/javascript/recovery.mjs:132-147`).
- Kaynak haritası çözücüsü her segmentin `names` dizinini de çözüyor (`src/javascript/sourceMaps/TraceSourceMap.ts:220`). Aynı konumdaki bütün adayları koruyor (`:30-31`).

**Karadul'da karşılığı** [D]

- JS isim doğruluğu ölçülmüyor. `scripts/measure-minified.mjs:1-6` yalnız kısa tanımlayıcıların oranını sayıyor.
- Karadul'un hiçbir yerinde kaynak haritası tüketilmiyor. `karadul/` ve `scripts/*.mjs` altında şu arama boş döndü: `sourceMappingURL|sourcesContent|SourceMapConsumer|source-map`.
- Örnek dosyalarda alfa-denklik ve davranış testleri var (`tests/test_context_namer_node.py:219-230`, `:397-408`). Ama bunlar gerçek paketleyici çıktısı üzerinde değil.

**Plan kalemi**

- Yeni kalem, öneri: "JS-ÖL-1". ÖL-1 rubriği ve ÖL-7 determinizmi aynen uygulanır.
- Derleyici sentezinde hiç JS kalemi yok [D].

**Beklenen etki [T]**

- Karadul'un JS isimlendirmesi ilk kez ölçülür.
- ContextNamer'ın "300+ kural"ından hangisinin isabet ettiği, hangisinin yanlış ürettiği kural başına görünür.
- Yeniden adlandırmanın davranışı bozduğu durumlar (kısaltılmış özellik, gölgeleme) gerçek paketleyici çıktısında yakalanır.

**Uyarlama yolu (M)**

1. Kaynağı bilinen 10–20 JS projesi seç: küçük kütüphaneler ve açık kaynak bir Electron uygulaması. Dev/test olarak kilitle.
2. Sabit sürümlü esbuild ya da webpack+terser ile, `sourcemap` açık derle. Çıktıları SHA-256 ile sabitle. Karadul native set için bunu zaten yapıyor (`ee0c34f`).
3. Altın standart (GT): küçültülmüş çıktıdaki her bağlama bildiriminin konumu için haritanın `names` girdisi.
4. ContextNamer çıktısını bağlama başına sınıfla: tam / amacı anlatan / yanlış / boş (ÖL-1).
5. Davranış kâhini: özgün paket ile yeniden adlandırılmış paket aynı girdilerde aynı çıktıyı vermeli.

Uyarı [T]: Paketleyicilerin `names` alanını ne kadar doldurduğu sürüme ve ayara bağlı. Önce küçük bir pilotla bakılmalı.

**Nasıl ölçülür**

- Bağlama başına kesinlik ve kapsama.
- Kural başına isabet.
- Kâhinden geçme oranı.
- İki koşu arasında `naming_map` farkı 0.

### 4. Electron'da bütün JS dosyalarını işlemek; parçaları birlikte çözmek

**Ne yapıyor (rea)** [D]

- Uygulamayı bir bütün olarak okuyor (`docs/javascript-artifact-reconstruction.md:230-254`):
  - `package.json` main girişi;
  - preload yolları ve renderer dosyaları;
  - HTML betik girişleri;
  - webpack ve Rspack parça kayıtları.
- Kod bölmeyle ayrılmış parçaları (16'ya kadar ek girdi) tek koşuda birlikte kurtarıyor. Böylece parçalar arası modül kimlikleri çözülüyor (`src/domain/javascript/javascriptRecovery.ts:11-17`; `docs/javascript-recovery.md:78-81`).

**Karadul'da karşılığı** [D]

- `ELECTRON_APP` ve `JS_BUNDLE` hedefleri `_execute_js`'e düşüyor (`karadul/stages.py:1135`).
- Orada yalnız **en büyük** deobfuscate edilmiş `.js` dosyası ContextNamer'dan geçiyor (`karadul/stages.py:5158-5168`).
- Aynı satırlardan çıkan sonuç: main ve preload gibi küçük dosyalar hiç isimlendirilmiyor.

**Plan kalemi:** Yeni kalem, öneri: "JS-KP-1" (kapsam).

**Beklenen etki [T]**

- Electron'da main ve preload isimlendirmesi sıfırdan pozitife çıkar.
- Madde 5'teki dosyalar arası eşleme ancak bununla mümkün olur.

**Uyarlama yolu (S; rol tespitiyle M)**

- Dosya başına döngü kur.
- Giriş rollerini `package.json` ve `BrowserWindow` `webPreferences.preload` alanından al. rea bunları statik olarak okuyor [D] (`docs/javascript-artifact-reconstruction.md:245-246`).

**Nasıl ölçülür**

- İşlenen dosya ve bağlama oranı, önce ve sonra.
- Süre.
- Madde 3 rubriğiyle dosya rolü başına isabet.

### 5. Electron IPC, preload ve contextBridge kanıtını bağlama kimliğiyle çıkarmak

**Ne yapıyor (rea)** [D]

- `require("electron")` sonucunu ada göre değil bağlama kimliğine göre izliyor. Takma adlardan, sayısal modül tablolarından (`load(id)`) ve kapanışlardan geçiyor.
  - Örnek test: üç modül sınırı ve bir kapanış yakalamasından sonra çağrı `["electron","ipcRenderer","send"]` dış yoluna, kanal argümanı `"test:copy"` literaline çözülüyor (`src/domain/javascript/javascriptSymbolicBindings.test.ts:62-91`).
- Modül tablosunu çalışma zamanı sözdiziminden tanıyor, değişken adından çıkarmıyor (`javascriptBootstrap.ts:24-103`).
- Her IPC çağrısı için kaydettikleri:
  - taraf: main ya da renderer;
  - işlem: `send`, `sendSync`, `invoke`, `postMessage`, `sendToHost`, `on`, `once`, `handle` vb.;
  - kanal literali ya da dinamik ifade;
  - işleyici fonksiyonun konumu.
  - Kaynak: `electronStaticAnalysisIpc.ts:36-70`, `:178-220`; kimlik çözümü `electronStaticAnalysisValues.ts:14-30`.
- `contextBridge.exposeInMainWorld` ve `exposeInIsolatedWorld` için API anahtarını ve API nesnesini çıkarıyor (`javascriptContextBridgeExposure.ts:14-35`).
- Değerleri bir kafeste tutuyor: "bilinmiyor + gerekçe", birleşim ve koşul taşıyabiliyor (`javascriptSymbolicValues.ts:44-81`).

**Karadul'da karşılığı** [D]

- `scripts/context-analyzer.mjs:1529-1553`: `x.on/once/addEventListener("olay", h)` → `onOlay`. Ama yalnız şu koşullarda:
  - `h` en çok 3 karakterlik bir tanımlayıcıysa;
  - olay adı doğrudan bir dize literaliyse.
- Bu kuralda `x`'in kimliği denetlenmiyor; `handle` ve `invoke` yok.
- `scripts/semantic-rename.mjs:790-797` VS Code'a özgü bir `vscode:` önek kuralı içeriyor. Bu dosyanın hatta bağlı olup olmadığına bakmadım.
- contextBridge, preload ya da `ipcMain` için başka kural yok; arama boş döndü.

**Plan kalemi**

- Yeni kalem, öneri: "JS-TR-1".
- Statü "tarif": kanal adı amacı anlatır, özgün adı iddia etmez.
- Native taraftaki karşılığı TR-4 (kayıt API'si ↔ işleyici).

**Beklenen etki [T]**

- Ana süreç işleyicileri (çoğu adsız ok fonksiyonu) kanal adından tarif alır: `"settings:get"` → `handleSettingsGet`.
- Preload'da `exposeInMainWorld("api", {openFile: …})` anahtarları küçültmeden sağ çıkar, çünkü özellik adı karıştırma varsayılan olarak kapalıdır. Açığa çıkan fonksiyonlar bu adları alır.
- Renderer `invoke` ↔ main `handle` eşlemesi dosyalar arasında bağ kurar.
- Kimlik denetimi, ilgisiz `.on("x", h)` çağrılarından gelen yanlış adları da azaltır.

**Uyarlama yolu (M)**

TypeScript kodu taşınmaz. Yöntem `context-analyzer.mjs`'e eklenir; Babel orada zaten var.

1. `require("electron")` bağlamasının kimliğini izle. Bunu Karadul'un paket açıcısının çıkardığı modül sınırları içinde yap.
2. Kanal dizesi için sınırlı sabit yayılımı ekle: `const`, ifadesiz şablon.
3. Kural seti: işleyici ← kanal, açığa çıkan fonksiyon ← anahtar.
4. Renderer ↔ main eşleme tablosunu rapora yaz.

Madde 4'e bağlı.

**Nasıl ölçülür**

- Madde 3'ün fixture'ında, açık kaynak bir Electron uygulamasıyla.
- IPC kaynaklı tariflerin rubrik sonucu.
- Çözülen işleyici sayısı; bugünkü "doğrudan literal + kısa tanımlayıcı" kuralıyla kıyaslı.

### 6. ASAR'ı yerinde okumak, bütünlüğünü denetlemek, `.asar.unpacked` içindeki `.node` eklentilerini native hatta vermek

**Ne yapıyor (rea)** [D]

- ASAR'ı kendisi okuyor (`docs/javascript-artifact-reconstruction.md:146-163`, `:206-210`):
  - Electron bütünlük üstverisinde beyan edilen SHA-256'yı hesaplananla karşılaştırıyor;
  - uyuşmazlık varsayılan olarak hata; istenirse "gözlenen ama güvenilmez" olarak devam ediyor;
  - `.asar.unpacked` eşlik dosyaları envantere giriyor.
- JS tarafında `.node` eklentisini isteyen içe aktarmaları ve yapı çözmeyle istenen dışa aktarım adlarını topluyor (`src/domain/javascript/electronStaticAnalysisNative.ts:39-40`, `:248-284`). Yalnız `.node` ile biten literal yolları tanıyor.
- Eklenti düğümünü içerik özetiyle native kanıta bağlıyor. Kanıt yoksa durum `requires-provider-analysis` oluyor (`javascriptNativeHandoff.ts:12-50`).

**Karadul'da karşılığı**

- `karadul/analyzers/electron.py:346-368`: `npx --yes @electron/asar extract` [D]. Paket yoksa ağdan indirileceğini tahmin ediyorum [T].
- Bütünlük denetimi yok; `electron.py` içinde `integrity|sha256` araması boş [D].
- `.asar.unpacked` ve `.node` eklentileri native hatta yönlendirilmiyor; arama boş [D].
- N-API ithal adları imza DB'sinde var (`karadul/analyzers/sigdb_builtin/languages.py:70-73`) [D].

**Plan kalemi**

- Yeni kalem, öneri: "JS-NT-1".
- N-API kayıt adları kısmı, TR-4'ün (kayıt API'leri, işaretçi haritası) özel bir hâli.
- Kİ-2 ve Kİ-4 mantığıyla, JS'e görünen bağlama adı "kesin" sayılabilir [T].

**Beklenen etki [T]**

- (a) Ağ ve tedarik zinciri bağımlılığı kalkar; çözümleme tekrarlanabilir olur.
- (b) Electron uygulamalarındaki native eklentiler Ghidra hattına girer.
- (c) `napi_create_function(env, "openFile", …, cb)` çağrılarında ya da `napi_property_descriptor` dizilerinde ad dizesi geri çağırma işaretçisine bağlanabilirse, eklenti fonksiyonları JS'e görünen adlarını kesin olarak alır. JS tarafındaki `requested_exports` ile çapraz denetlenir. (c) rea'da yok; Karadul uzantısıdır.

**Uyarlama yolu (M)**

- ASAR biçimi basit: Pickle başlık, JSON dizin ve ofsetler. Python okuyucu yazılır (S).
- `.node` dosyaları alt hedef olarak native hatta verilir (S).
- N-API kayıt bağlaması (M). TR-4'ün işaretçi haritasına bağlı.

**Nasıl ölçülür**

- Kaynaktan derlenmiş, sembollü küçük bir N-API eklentisi al ve strip et. Kayıt bağlamasının kesinliğini DWARF ya da `nm`'e göre ölç.
- Örnek uygulamalarda `.node` sayısını ve bu eklentilerin fonksiyon sayısını çıkar (kapsam).

### 7. Yeniden adlandırmaya dayanıklı AST parmak izi

**Ne yapıyor (rea)** [D]

- Fonksiyon gövdesini bir belirteç dizisine çeviriyor (`src/domain/javascript/javascriptAstFingerprint.ts:22-32`, `:76-134`):
  - düğüm türü, literaller ve işleçler;
  - hesaplanmamış özellik adları ve nesne anahtarları.
- Yerel tanımlayıcı adlarını dışarıda bırakıyor ve dizinin SHA-256'sını alıyor.
- Uygulama sürümlerini karşılaştırmada kullanılıyor (`docs/javascript-application-workflows.md:276-320`; `javascriptApplicationVersionMatching.test.ts:74-142`).

**Karadul'da karşılığı** [D]

- Yok. `scripts/*.mjs` içinde yapısal bir JS parmak izi yok.
- `createHash` yalnız isim sezgisinde bir dize olarak aranıyor (örnek: `scripts/smart-webpack-unpack.mjs:525`).

**Plan kalemi:** Yeni kalem, öneri: "JS-KS-1". KS-8 (kütüphane imza DB'si) ve ÖL-6'nın (görülen/görülmeyen) JS karşılığı.

**Beklenen etki [T]**

- (a) Haritası ya da küçültülmemiş hâli olan bir sürümden sonraki küçültülmüş sürüme ad taşıma.
- (b) Popüler npm paketlerinden bir JS imza DB'si. Paketler sabit küçültücü profilleriyle derlenir.

Uyarılar [T]:

- terser'in sıkıştırma dönüşümleri yapıyı değiştirir; tam özet profiller arasında kırılır.
- Küçük fonksiyonlar çakışır.
- Karadul'un "binary içinde tek" dersi burada da geçerli: tekillik ve en küçük boyut şartı konmalı.

**Uyarlama yolu (M)**

- Babel üzerinde aynı belirteç kümesi.
- Fonksiyon başına özet.
- Tekillik denetimi.
- Profil başına ayrı DB.

**Nasıl ölçülür**

- Aynı kaynağı iki farklı karıştırma tohumu ya da profille derle.
- Tekil eşleşmenin kesinliğini ve duyarlılığını ölç; GT haritadan gelir (madde 3).
- Fonksiyon boyutuna göre çakışma oranını çıkar.
- Görülen/görülmeyen ayrımını koru (ÖL-6).

### 8. Dinamik kanal için doğrulama kâhinleri ve dayanıklı kayıt

**Ne yapıyor (rea)** [D]

- Kaynağı depoda olan bir C/ObjC fixture'ı derliyor (`scripts/verify-native-calls.mjs:98-116`):
  - izlenen olaylarda yazmaç değerlerini ve çağıran sembolünü birebir doğruluyor;
  - olayın `file_address` değerini `nm`'deki sembol adresiyle karşılaştırıyor.
- Aynı ikilinin iki kopyasını deniyor (`:211-260`):
  - hardened runtime'lı kopya → `debugger-attach-denied` beklenir;
  - `get-task-allow` ile imzalanmış kopya → iz başarılı olmalı.
- İzleyici her olayı sınırlı bir JSONL günlüğüne hemen yazıyor; izleyici çökse de kısmi kanıt kalıyor (`bridge/native/rea_lldb_tracer.py:72-87`).
- Başlatmadan önce ve sonra SHA-256, inode ve modül UUID'sini karşılaştırıyor (`:598-612`, `:715-766`).
- Bayt, çerçeve ve olay bütçeleri açıkça tanımlı (`:31-37`).
- Birim testleri sahte bir `lldb` modülüyle hata ayıklayıcı olmadan koşuyor (`bridge/native/test_rea_lldb_tracer.py:14-25`).

**Karadul'da karşılığı** [D]

- Dinamik aşama için kâhin yok.
- Frida iletileri ancak `session.wait` bittikten sonra diske yazılıyor (`karadul/stages.py:586`, `:610-616`). Arada hata olursa toplanan iletiler kaybolur.

**Plan kalemi:** ÖL-7 (tekrarlanabilirlik), ÖL-3 (kanıt erişimi). Madde 2'nin kabul kapısı.

**Beklenen etki [T]**

- Dinamik kanıt tekrarlanabilir ve denetlenebilir olur.
- Strip edilmiş kopyada ad sızıntısı yakalanır.
- Uzun koşularda kısmi kanıt kaybolmaz.

**Uyarlama yolu (S, madde 2 ile birlikte)**

1. `-g` ile derlenmiş C fixture ve strip edilmiş ikizi.
2. Atıf kâhini: atfedilen çağıran adresi `nm` adresine eşit olmalı.
3. Yetenek çifti testi: hardened runtime kopyası ve `get-task-allow` kopyası.
4. Olay başına flush edilen JSONL.
5. Sahte `lldb` modülüyle birim testleri.

**Nasıl ölçülür**

- Fixture'da atıf doğruluğu %100 olmalı.
- Test setindeki her ikili için yetenek matrisi: izlenebilir mi, neden değil?
- Sızıntı denetimi: iz çıktısında özgün ad geçmemeli.

## Fikir olarak değerli, kod olarak alınmaz

**Süreç yakalama ve iki koşunun kıyası** [D]

- rea aynı senaryoyu "otorite" ve "yeniden inşa" ikilileriyle çalıştırıp terminal, çıkış ve dosya etkilerini karşılaştırıyor.
- Sıralamanın serbest olduğu olaylar için açık bir iz tanımı kabul ediyor.
- Kaynak: `docs/process-capture.md:3-7`, `:68-98`.
- Karadul'un derlenebilir yeniden inşa çıktısında "davranış sadakati" ölçüsü olabilir. İsimle ilgisi yok [T].

**Otomatik mutasyon**

- rea'da [D]:
  - Stryker, AST seçicileriyle belirlenen yöntem ve koruma bölgelerinde mutant üretiyor (`stryker.config.mjs:1`, `:29-60`; `scripts/lib/reverse-tools-mutation-targets.mjs`);
  - her gece koşuyor (`.github/workflows/mutation.yml:4-5`);
  - eşik yok, yalnız rapor (`stryker.config.mjs:20`).
- Karadul'da mutantlar elle yazılan bul/değiştir kalıpları (`scripts/mutation_probe.py:1-40`) [D].
- Python'da benzer bir araç, elle düşünülmeyen mutantları bulur. En çok ölçüm kodunda işe yarar (`measure.py`, F1 hesapları) [T].

**Sembolik değer kafesi tasarımı** [D]

- Kafes "bilinmiyor + gerekçe", birleşim ve koşul taşıyor.
- Birleşimdeki seçenekler çelişirse karar verilmiyor: `symbolicTruth` ancak bütün seçenekler aynıysa bir değer döndürüyor.
- Kaynak: `src/domain/javascript/javascriptSymbolicValues.ts:44-81`, `:97-120`.
- TR-5'teki "çelişkide isimsiz bırak" ilkesinin hazır bir örneği. Kodu TS/Babel'e bağlı olduğu için alınmaz.

**CDP ile pasif Electron/Node gözlemi, yürütme kapsamı ve fuse okuma** [D]

- Kaynak: `.agents/skills/reverse-engineer-anything/references/runtime-observation.md:3-15`, `:51-52`; `docs/electron-fuses.md:3-7`, `:28-31`.
- JS'de "senaryoda hangi fonksiyon çalıştı" kanıtı verir. Özellik izlemeye yarar, isim için zayıf [T].
- `EnableNodeCliInspectArguments` fuse'u kapalıysa `--inspect` boşa gider. Denemeden önce fuse okunmalı [D].

**Statik ↔ çalışma zamanı uzlaştırması** [D]

- Önce yakalanan kaynağın özetine bakılıyor. Yol ve özet çelişirse uyuşmazlık raporlanıyor. Belirsizlik korunuyor.
- Kaynak: `runtime-observation.md:59-63`.
- Madde 2'deki dinamik olay ↔ statik fonksiyon eşlemesine ilke olarak uyar.

## İşimize yaramayanlar

**JS kaynak kurtarma (S1'in cevabı: hayır)** [D]

- Wakaru'yu sarmalıyor; Linux x64 ve util-linux `prlimit` istiyor.
- İsim üretmiyor ve "özgün değişken adları bilinmiyor" diyor. `runtime_equivalence` her zaman `"unknown"`.
- Kaynak: `docs/javascript-recovery.md:8-22`, `:124-128`; `src/domain/javascript/javascriptRecovery.ts:109`.

**`function_names` testleri** [D]

- Ad kurtarma testi değiller. Adlandırılmış fonksiyon ifadesinde kapsam ve gölgeleme çözümünü sınıyorlar (`javascriptSemanticAnalysis.function_names.test.ts:5-54`).
- Çağrılabilir öğenin adı yalnız sözdiziminden alınıyor (`javascriptSemanticProjection.ts:271-300`).

**esbuild algılaması (S2)** [D]

- Yardımcı fonksiyonun adına bağlı: `__commonJS` / `__esm` (`javascriptStaticAnalysisBundler.ts:157-169`). Küçültülmüş çıktıda bu ad değişir ve paket tanınmaz.
- rea'nın kendi belgesi de bunu söylüyor: esbuild scope-hoisted fixture tek bir "unknown-format" betik olarak kalıyor (`docs/javascript-recovery.md:117-119`).
- Karadul küçültülmüş sarmalayıcıyı yapısal kalıpla buluyor (`scripts/esbuild-unpack.mjs:173`). Burada Karadul önde.

**Diğerleri**

| Özellik | Neden işe yaramaz | Kaynak |
|---|---|---|
| Çerçeve ve paketleyici işaretleri | Düz alt dize araması | `javascriptStaticAnalysisHelpers.ts:837-848` [D] |
| FeatureSeed | Uygulama grafında literal arama; isimlendirme değil | `javascriptFeatureSeed.ts:25-37` [D] |
| Kaynak ↔ paket kıyası | Yalnız yol ve özet sinyalleri; harita ya da kaynak yoksa eşleme yapamaz | `sourceToBundleComparisonSchemas.ts:13-21` [D] |
| Swift süreç kimliği yardımcısı | `KERN_PROC_ALL` + `p_starttime` ile PID yeniden kullanım koruması, `KERN_PROCARGS2` ile çalıştırma belirteci; sahiplik altyapısı | `bridge/process/ProcessRunTokenReader.swift:40-73`, `:193-204` [D] |
| Özetle sabitlenmiş fixture | Karadul'da test seti zaten SHA-256 ve BuildID ile sabit (`ee0c34f`); yeni olan yalnız JS araç zincirinin sabitlenmesi (madde 3) | [D] |
| MCP/Evidence şema düzeneği | Ürün mimarisi farklı; taşımaya değmez | [T] |

**Süreç yakalama (S5)** [D]

- Kaydettiği: PTY çıktısı, seçilen dizinlerin önce/sonra anlık görüntüsü, süreç ağacı örnekleri.
- Belge açıkça "sistem çağrısı izi değil" diyor; kısa ömürlü değişiklikler kaçabilir (`docs/process-capture.md:228-234`).
- Fonksiyona atıf yok, dolayısıyla isimlendirmeye katkısı yok.

## Açık sorular

**Çalışma zamanı**

1. Karadul `DebuggerBridge`'indeki `BreakpointCreateByAddress(int(addr, 16))` çağrısı (`karadul/ghidra/debugger_bridge.py:365`) ASLR kaymasıyla doğru yere düşüyor mu? Test edilmedi. Bölüm göreli `SBAddress` daha güvenli görünüyor [T].
2. Hardened Electron uygulamasının ad-hoc imza ve `get-task-allow` ile yeniden imzalanmış kopyası çalışıyor mu? Riskler: kısıtlı yetkiler, kütüphane doğrulaması, ASAR bütünlük fuse'u. rea bunu yalnız kendi fixture'ında denemiş [D]. Gerçek uygulamada ölçülmedi.
3. Test setindeki ikilileri Apple `strip` ile kopyalamak arm64 imzasını geçerli bırakıyor mu? Bırakmıyorsa strip edilmiş kopya çalışmaz. Doğrulanmadı.
4. tmux ve htop'ta tipik bir senaryoda fonksiyonların yüzde kaçı çalışıyor? Dinamik kanıtın kapsama tavanı bu. Ölçülmedi.
5. Debian ELF seti Mac'te çalışmıyor. Dinamik kanal yalnız Mac setiyle mi sınırlı kalacak, yoksa Linux/Docker'da bir eşleniği mi kurulacak?
6. Dinamik kanıt makaleye girmeli mi? "Hesaplamayla isim" iddiasıyla gerilimi var. Ayrı statü ve ayrı tablo öneriyorum [T]. Karar Berke'nin.

**JavaScript**

7. JS ölçümü makaleye mi girer, yalnız ürüne mi? Derleyici sentezinde JS yok [D].
8. Paketleyiciler (esbuild, terser, swc) kaynak haritasında `names` alanını ne oranda dolduruyor? Pilot gerekli.
9. Wakaru'nun kendi yeniden adlandırma kuralları Karadul'a karşı nasıl? Çalıştırma yasağı yüzünden ölçülmedi; `third_party/wakaru` kaynağı da okunmadı.
10. Karadul'un `deobfuscate` aşaması Electron'da bütün dosyaları işliyor mu? Yalnız reconstruct tarafını inceledim.
11. `@electron/asar extract` `.asar.unpacked` dosyalarını çıktıya kopyalıyor mu? Karadul'un çıkardığı ağaçta `.node` dosyası var mı? Doğrulanmadı.

**İnceleme kapsamı**

12. `javascriptSymbolicBindings.ts` (1481 satır) yalnız ana hatlarıyla okundu. `context-analyzer.mjs`'e taşımanın maliyeti belirsiz.
13. rea'nın öbür `real-*` şeritleri okunmadı: Ghidra, Hopper, Cutter, ağ yakalama vb. Yalnız JS kurtarma, mutasyon ve native çağrı doğrulaması incelendi.
