# Kulvar BICIM — bulgular
Kapsam: baştan sona okunanlar — `karadul/core/target.py`, `core/target_resolver.py` (çoğu), `deobfuscators/deep_pipeline.py`, `stages.py` içinde `StaticAnalysisStage` (150-476), `DeobfuscationStage` (725-1062), `ReconstructionStage.execute/_execute_app_bundle/_execute_analyzer_reconstruct` (1089-1354), `_execute_js` (5214-5530); `analyzers/app_bundle.py`, `analyzers/electron.py`, `reconstruction/naming/pipeline.py` (1-360), `reconstruction/context_namer.py` (sayaç kısmı), `reconstruction/param_recovery.py` (sayaç kısmı), `reconstruction/project_builder.py` (giriş/README), `reconstruction/naming/npm_fingerprinter.py` (eşleştirme), `analyzers/java_binary.py` (255-714, 1075-1120), `analyzers/dotnet_binary.py` (25-60, 270-300, 470-500, 520-960), `analyzers/packed_binary.py` (1380-1880), `analyzers/pyc_decompiler.py` (360-760), `core/safe_subprocess.py` (1-150), `scripts/smart-webpack-unpack.mjs` (590-830). Taranan (grep düzeyinde): kulvardaki tüm alt süreç ve ağ çağrıları, `SecurityConfig` okuyucuları, ölü modüller. Çalıştırılan: ağ kapalı kum havuzunda (`sandbox-exec … deny network-outbound`) `sample_minified.js`, elle kurulmuş `.NET` yükleyici PE ve `.pyc` koşuları; 9 sentetik dosyada `TargetDetector`; hedef çözücüde içe aktarma denemesi; üretici fonksiyonlara kötü niyetli girdi. Okunamayanlar: "Bakamadıklarım" bölümünde.
Özet: 15 bulgu (KRİTİK 2, YÜKSEK 8, ORTA 5) + 12 küçük kalem. En ağırları: (1) JAR/APK/.NET yeniden kurmasında `build.gradle` ve `.csproj`'a düşman girdinin kaçışsız yazılması — üretilen projeyi IDE'de açmak analistin makinesinde saldırgan kodu çalıştırır (BICIM-04); (2) webpack 4 paketlerinden çıkarılan her modül sözdizimi bozuk JS, bütün modül/proje çıktısı bu bozuk dosyalarla kuruluyor ve "başarılı" (BICIM-01) — üstelik yeniden kurma deobfuscation çıktısı yerine en büyük dosyayı (çoğu zaman özgün kodu) işliyor (BICIM-02); (3) hedef çözücü noktalı, var olmayan bir adda çalışma dizinindeki Python modülünü içe aktarıyor (BICIM-07), yerel CLR yükleyici PE'ler .NET sanılıp native analizden kaçıyor (BICIM-08), ağ bayrağı kapalıyken unpkg ve `npx --yes @electron/asar` ağa çıkıyor (BICIM-06).

## BICIM-01 — Webpack 4 nesne/dizi biçimli paketten çıkarılan her modül sözdizimi bozuk JS (adsız `function (…) {` deyimi); ikinci geçiş, adlı proje ve "çalıştırılabilir proje" hepsi bozuk girdiyle sürüyor
- Önem: KRİTİK
- Tür: hata
- Yer: `scripts/smart-webpack-unpack.mjs:595-641` (modül düğümü = `FunctionExpression`), `:711-753` (düğüm olduğu gibi `generate` edilip dosyaya yazılıyor); tüketenler `karadul/deobfuscators/deep_pipeline.py:553-672` (`_step_rename_modules`), `karadul/stages.py:5365-5405` (NamingPipeline), `karadul/reconstruction/project_builder.py` (entry `src/index.js`)
- Etkin mi: evet (çağıran: `deep_pipeline.py:218` `_step_smart_unpack` → `stages.py:820` `_execute_deep`; JS_BUNDLE/ELECTRON_APP öntanımlı yol)
- Ne: `extractWebpackObjectModules` / `extractWebpackArrayModules` modül olarak paket nesnesindeki `function(e,t,n){…}` ifadesini alıyor ve `@babel/generator` ile tek başına bir dosyaya yazıyor. Adsız bir `function` ifadesi dosyanın en üstünde deyim olarak duramaz; çıkan her dosya `SyntaxError: Function statements require a function name` verir. (Ok işlevli `(e,t)=>{}` modüller geçerli kalır; klasik webpack 4 `function` modülleri hep bozuk.) Sonuç zinciri: ikinci geçiş (`module_rename`) 3/3 modülde Babel parse hatası ("Unexpected token (12:9)" = başlık yorumundan sonraki `function (` sütunu), NamingPipeline aynı bozuk dosyaları `named_project/lib/` altına kopyalıyor, ProjectBuilder `module_0`'ı `project/src/index.js` "Entry Point" olarak yazıyor, `package.json` `start: node src/index.js`, `Dockerfile` `CMD ["node","src/index.js"]` üretiliyor. Aşama `deobfuscate` success=True (status partial), `reconstruct` success=True, çıkış kodu 0.
- Kanıt: `sandbox-exec (ağ kapalı) python -m karadul analyze <tmp>/sample_minified.js --skip-dynamic --output-dir <tmp>/ws` →
  ```
  $ node --check reconstructed/project/src/index.js
  function (elem, tmp, count) {
  ^^^^^^^^
  SyntaxError: Function statements require a function name
  ```
  `named_project/lib/module-0.js` için de aynı hata. `pipeline_result.json`: `module_rename {'success': False, 'failed_count': 3, …}`, `reconstruct success True`, `project_files ['src/index.js','package.json','README.md','Dockerfile','.gitignore']`.
- Etki: Analist "yeniden kurulmuş proje" ve "adlandırılmış modüller" diye çalışmayan, ayrıştırılamayan dosyalar alıyor; modül bazında ikinci ad geçişi webpack 4 paketlerinde hiç çalışmıyor (sessiz değil ama her koşuda %100 başarısız). Docker/npm ile "çalıştırılabilir" izlenimi veren dosyalar yanıltıcı.
- Güven: kesin (çalıştırıp gösterdim)
- Onarım kapsamı: `smart-webpack-unpack.mjs` — modül gövdesini geçerli bir sarmalayıcıyla yaz (`module.exports = function (module, exports, __webpack_require__) {…};` ya da `(function(...){…})` ifade deyimi); tüketen tarafta `.renamed.js` ve NamingPipeline aynı dosyayı okuduğu için başka değişiklik gerekmeyebilir. S. Tehlike: `module_rename` artık başarılı olunca modül adları değişir; NamingPipeline'ın yapısal analizi farklı sonuç verir.
- Nasıl sınanır: `sample_minified.js` koşusunda `node --check` her `webpack_modules/modules/*.js`, `named_project/lib/*.js` ve `project/src/index.js` için 0 dönmeli; `module_rename.renamed_count == 3`. Hem `function` hem ok işlevli webpack 4 dizisi için birim test.

## BICIM-02 — JS yeniden kurma, deobfuscation çıktısını değil `deobfuscated/` altındaki EN BÜYÜK `.js` dosyasını işliyor (çoğu zaman özgün ya da yalnız güzelleştirilmiş dosya)
- Önem: YÜKSEK
- Tür: hata
- Yer: `karadul/stages.py:5231-5243`
- Etkin mi: evet (çağıran: `stages.py:1142` `ReconstructionStage.execute` → `_execute_js`; JS_BUNDLE ve ELECTRON_APP)
- Ne: Kaynak seçimi `max(deob_dir.rglob("*.js"), key=size)`. Dizinde `00_original.js` (girdinin kopyası), `01_beautified.js`, `02_deep_deobfuscated.js`, `03_enhanced_renamed.js`, modüller ve büyük dosyada `stream_chunks/`, `deep_chunks/` var. Deep deobfuscation sabit katlama/ölü kod silme yaptığında çıktı küçülür; o zaman ya özgün ya da yalnız güzelleştirilmiş dosya seçilir ve bütün ad/tip/yorum adımları deobfuscate EDİLMEMİŞ kod üstünde koşar. `DeepDeobfuscationResult.output_file` (`artifacts["output_file"]`) zaten "son başarılı adımın dosyası"nı taşıyor ama okunmuyor. Deobfuscation başarısız olup `02_…` girdinin kopyası olduğunda da ayrım yapılmıyor.
- Kanıt: aynı koşu: `deobfuscated/` boyutları `00_original.js 1457`, `01_beautified.js 1322`, `02_deep_deobfuscated.js 1428`, `03_enhanced_renamed.js 1444`; `reconstruct.stats.source_file = "00_original.js"`; çıktılar `reconstructed/00_original.nsa_named*.js`.
- Etki: Analist "deobfuscate edilip adlandırılmış" diye özgün (gizlenmiş) kodun üstüne kurulmuş çıktı görür; deobfuscation aşamasının başarısı raporda var, ürüne yansımıyor. Hangi dosyanın seçildiği yalnız `source_file` istatistiğinde.
- Güven: kesin (çalıştırıp gösterdim)
- Onarım kapsamı: `stages.py` `_execute_js` — `context.results["deobfuscate"].artifacts["output_file"]`'ı tercih et; yoksa `03_` → `02_` (yalnız gerçek dönüşümse) → `01_` sırası; `00_original*` ve `stream_chunks/`, `deep_chunks/`, `webpack_modules/` asla aday olmasın. S.
- Nasıl sınanır: deep çıktısı özgünden küçük olan bir girdi (ör. bu fixture) ile `source_file == "03_enhanced_renamed.js"`; deep başarısızken (`fallback_copy`) seçimin bunu `stats`'ta açıkça söylemesi.

## BICIM-03 — JS ad/parametre sayaçları birbirini tutmuyor; CLI "Results" tablosunun dört satırı hiç üretilmeyen anahtarları okuyor
- Önem: ORTA
- Tür: sahte/yanlış gösterim
- Yer: `karadul/reconstruction/context_namer.py:335-341` (`high/medium/low_confidence` = analizcinin TÜM aday sayısı, `variables_renamed` = eşik sonrası uygulanan); `scripts/apply-params.mjs:418` (`renameCount += 1 + bodyRenames` → `params_applied` başvuru sayısı); `karadul/stages.py:5313-5317`; `karadul/cli.py:886,891,893,899-900`
- Etkin mi: evet (her JS koşusu; CLI tablosu her hedef türü)
- Ne: (1) `rename_low_confidence 20`, `rename_medium_confidence 1`, `rename_high_confidence 0` toplamı 21; `variables_renamed 3`. Kova sayıları `context-analyzer.mjs:2242-2257`'de eşik uygulanmadan sayılıyor; uygulanan adlarla ilgisi yok ama raporda yan yana "rename_*" diye duruyor. (2) `params_recovered 6` (param-recovery.mjs'in `recoveredParams`'ı), `params_applied 7` (parametre + gövde başvurusu), `params_recovery_rate "40.0%"` (betikten gelen dizgi); üçü farklı birimde, uygulanan > kurtarılan. (3) CLI tablosu `steps_completed`, `modules_extracted`, `coverage_percent`, `runnable_project` anahtarlarını okuyor; `grep` ile bu anahtarları üreten hiçbir aşama yok (`modules_extracted` yalnız Python analizcisinin iç sözlüğünde). Sonuç: "Deobf steps N/A", "Modules extracted N/A", "Coverage N/A" her koşuda; "Runnable project NO" her koşuda (package.json + Dockerfile üretilse de).
- Kanıt: koşu çıktısı `reconstruct` stats: `variables_renamed = 3`, `rename_low_confidence = 20`, `params_recovered = 6`, `params_applied = 7`, `params_recovery_rate = 40.0%`; `grep -rn '"steps_completed"\|"coverage_percent"\|"runnable_project"' karadul --include=*.py` → yalnız `cli.py` ve `hacker_cli.py:777` (okuyucu).
- Etki: Analist ad kapsamını 21/… sanabilir; uygulama sayısı kurtarma sayısını aşıyor; tablo satırları kalıcı N/A/NO olduğundan bilgi taşımıyor ama "ölçülüyor" izlenimi veriyor.
- Güven: kesin (çalıştırıp gösterdim)
- Onarım kapsamı: `context_namer.py` kovaları uygulanan eşlemelerden say (ya da anahtarları `candidates_*` diye adlandır); `apply-params.mjs` parametre ve başvuru sayısını ayrı alanlarda döndürsün; `cli.py` satırlarını gerçek anahtarlara bağla (`deobfuscate.stats.steps`, `reconstruct.stats.modules_split`) ya da kaldır. S.
- Nasıl sınanır: aynı koşuda `rename_high+medium+low == variables_renamed`; `params_applied <= params_recovered`; CLI tablosunda N/A yalnız gerçekten ölçülmeyen alanlarda.

## BICIM-04 — Düşman girdiden gelen metin, üretilen `build.gradle` ve `.csproj` içine kaçışsız yazılıyor: projeyi IDE'de açmak ya da derlemek analistin makinesinde saldırgan kodu çalıştırır
- Önem: KRİTİK
- Tür: güvenlik
- Yer: `karadul/analyzers/java_binary.py:1103-1114` (`Main-Class` → `mainClass = '{main_class}'`), `:1080-1092` (Android `package` → `namespace "{…}"`, `applicationId "{…}"`), kaynak `:543-571` (`_extract_manifest`: MANIFEST.MF satırı ve AndroidManifest içindeki ilk ≥4 baskılanabilir ASCII dizisi, süzgeçsiz); `karadul/analyzers/dotnet_binary.py:944-947` (`<PackageReference Include="{d}" …>`), kaynak `:640-645` (AssemblyRef tablosundaki ad, `:484-489` heap'ten ham dizgi), `:953` (`AssemblyName` = dosya adı kökü)
- Etkin mi: evet (çağıran: `stages.py:1140` `_execute_analyzer_reconstruct` → `JavaBinaryAnalyzer.reconstruct` `java_binary.py:483-484` / `DotNetBinaryAnalyzer.reconstruct` `dotnet_binary.py:712-714`; JAR/APK/.NET öntanımlı yol, jadx/ILSpy kurulu olmasa da)
- Ne: Yeniden kurma, `reconstructed/java_project/build.gradle` ve `reconstructed/dotnet_project/<ad>.csproj` üretiyor. Groovy betiğine ve MSBuild XML'ine giden değerler hedef dosyadan geliyor ve hiçbir kaçış/doğrulama yok. JAR'ın `META-INF/MANIFEST.MF`'indeki `Main-Class: a'; '<komut>'.execute(); def z='` satırı tek satırlık geçerli Groovy kodu olur; APK manifestindeki `com.a.b${"<komut>".execute()}` dizgisi çift tırnaklı GString içinde yorumlanır; .NET AssemblyRef adı `"/></ItemGroup><Target Name="BeforeBuild"><Exec Command="…"/></Target>…` olursa csproj'a hedef enjekte edilir. Gradle betiği IntelliJ/Android Studio'da "sync" sırasında, csproj Visual Studio/Rider'da tasarım zamanı derlemesinde değerlendirilir: analist yalnız "yeniden kurulmuş projeyi açarak" zararlının seçtiği komutu kendi makinesinde çalıştırır.
- Kanıt: `PYTHONDONTWRITEBYTECODE=1 python -c "…JavaBinaryAnalyzer(Config())._generate_build_gradle({'Main-Class': \"a'; 'touch /tmp/pwn'.execute(); def z='\"}, [])…"` →
  ```
      mainClass = 'a'; 'touch /tmp/pwn'.execute(); def z=''
      namespace "com.a.b${"touch /tmp/pwn".execute()}"
      <PackageReference Include="Evil" /></ItemGroup><Target Name="BeforeBuild"><Exec Command="touch /tmp/pwn" /></Target><ItemGroup><PackageReference Include="y" Version="*" />
  ```
  (Üretici fonksiyonlar doğrudan çağrıldı; kaynak tarafı — MANIFEST ayrıştırma ve AssemblyRef okuma — kod okunarak izlendi.)
- Etki: Zararlı yazılım analiz eden kişinin makinesi ele geçirilebilir. Ürünün hedef kullanıcısı tam bu kişi.
- Güven: yüksek (sink çalıştırılarak gösterildi; kaynak→sink yolu baştan sona okundu; AssemblyRef'e ulaşan sade tablo ayrıştırıcının hangi tablolarda durduğu (`dotnet_binary.py:490-500` "bilinmeyen tabloda break") gerçek bir .NET dosyasıyla denenmedi — saldırganın tablo kümesini kendisi seçtiği varsayılıyor)
- Onarım kapsamı: `java_binary.py` `_generate_build_gradle` — `Main-Class` ve `package` yalnız `^[A-Za-z_$][\w$]*(\.[A-Za-z_$][\w$]*)*$` ise yazılsın, değilse yorum satırına bile yazılmasın (ya da Groovy tek tırnak kaçışı + `$` yasak); `dotnet_binary.py` `_generate_csproj` — `xml.sax.saxutils.quoteattr`/`escape` ve NuGet kimliği kalıbı (`^[A-Za-z0-9_.-]+$`); `AssemblyName` de aynı süzgeçten. S. Ek öneri: üretilen projelerin README'sine "güvenilmeyen girdiden üretildi, IDE'de açmadan önce inceleyin" uyarısı.
- Nasıl sınanır: kötü niyetli `Main-Class`, Android `package` ve AssemblyRef adı içeren üç birim test; üretilen dosyada `'`, `"`, `$`, `<`, `>` hiç geçmemeli; geçerli adlar (com.example.Main, Newtonsoft.Json) aynen kalmalı.

## BICIM-05 — jadx ve ILSpy "başarılı" denetimi her zaman doğru: araç çökse de `decompiled: True`
- Önem: YÜKSEK
- Tür: sahte/yanlış gösterim
- Yer: `karadul/analyzers/java_binary.py:623` + `:642`; `karadul/analyzers/dotnet_binary.py:829` + `:844`
- Etkin mi: evet, araç kuruluysa (çağıran: `java_binary.py:318`, `dotnet_binary.py:628`; jadx/ilspycmd bu makinede kurulu değil, bkz. BICIM-07)
- Ne: Her iki işlev çıktı dizinini önce `mkdir(parents=True, exist_ok=True)` ile yaratıyor, sonra başarıyı `proc.returncode == 0 or output_dir.exists()` ile ölçüyor. İkinci koşul her zaman doğru olduğundan araç sıfır olmayan kodla çıksa, hiç `.java`/`.cs` üretmese de `result["success"] = True`, static istatistiğinde `"decompiled": True`, günlükte "jadx decompile basarili: 0 .java dosyasi". `reconstruct` bu bayrağa bakıp boş dizini "kaynak" diye kopyalıyor.
- Kanıt:
  ```
  output_dir.mkdir(parents=True, exist_ok=True)      # java_binary.py:623
  ...
  if proc.returncode == 0 or output_dir.exists():    # java_binary.py:642
      java_files = list(output_dir.rglob("*.java"))
      result["success"] = True
  ```
- Etki: Analist decompile'ın çalıştığını sanır; jadx'in bozuk/korumalı APK'da çökmesi ya da ILSpy'ın bir sürüm sorunuyla 0 dosya üretmesi raporda görünmez. Kısmi başarı (jadx "finished with errors") ile tam başarısızlık ayrılmıyor.
- Güven: yüksek (kodu baştan sona izledim; araç kurulu olmadığı için çalıştıramadım)
- Onarım kapsamı: iki dosya; başarı = `source_files > 0`; `returncode != 0 and source_files > 0` → `partial=True` + stderr'in ilk satırı. S.
- Nasıl sınanır: sahte araç (çıkış kodu 1, çıktı yok) ile `decompiled` False; çıkış kodu 1 + 3 dosya ile `partial`.

## BICIM-06 — Ağ bayrağı kapalıyken iki yol yine ağa çıkıyor: `.d.ts` indirmesi (unpkg) ve Electron ASAR açma (`npx --yes @electron/asar`)
- Önem: YÜKSEK
- Tür: güvenlik / okunmayan ayar
- Yer: `karadul/reconstruction/naming/pipeline.py:106-167` (`DtsNamer(timeout=8)` → `dts_namer.py:464-501` `urllib.request.urlopen("https://unpkg.com/…")`); `karadul/analyzers/electron.py:361-376` (`[npx, "--yes", "@electron/asar", "extract", …]`); okunmayan ayarlar `karadul/config.py:338-340` (`allow_dts_fetch`, `allow_reference_download` dışında `allow_source_match`), `:317` (`SourceMatchConfig.npm_pack_fallback`)
- Etkin mi: evet. DTS: `stages.py:5366-5375` webpack modülleri çıkarıldığında ve npm parmak izi `_CURSOR_KNOWN_PACKAGES` (semver, chalk, commander, yaml, …) içinden bir paket bulduğunda. ASAR: her `.asar` hedefi ve Electron `.app` (`electron.py:112`).
- Ne: `NetworkConfig` belgesine göre (`config.py:327-336`) karadul öntanımlı olarak hiçbir HTTP çağrısı yapmamalı. (1) DTS katmanı `config.network.enabled`'a da `allow_dts_fetch`'e de bakmadan unpkg.com'a gidiyor; istek URL'si analiz edilen zararlının içerdiği paket adını taşıyor (hangi zararlının incelendiği dışarı sızar). (2) Electron hattı ASAR'ı açmak için `npx --yes` ile npm kayıt deposundan sürüm sabitlenmemiş `@electron/asar`'ı indirip ÇALIŞTIRIYOR; `scripts/package.json`'da bu paket yok, yani ilk çağrıda (ya da npx önbelleği temizlenince) ağ zorunlu ve tedarik zinciri riski var. Ağ yoksa Electron statik aşaması "ASAR extract basarisiz" ile düşüyor; "ağ kapalı" kipinde Electron desteği fiilen yok. (3) `allow_dts_fetch`, `allow_source_match` hiçbir yerde okunmuyor; `--enable-network` yalnız `network.enabled` ve `source_match.enabled`'ı açıyor (`cli.py:645-646`), YAML'da `network.enabled: true` verilirse `source_match.enabled` açılmıyor. Kulvardaki diğer alt süreçler (node betikleri, synchrony, jadx, ilspycmd, monodis, pycdc/pycdas, strings) ağa çıkmıyor; `DependencyResolver._npm_lookup` (`npm view`) etkin yolda `verify_npm=False` ile kapalı (`stages.py:5491`, `project_reconstructor.py:78`).
- Kanıt: `pipeline.py:113-115` `dts_namer_local = DtsNamer(fetcher=lambda url: None)` / `dts_namer_remote = DtsNamer(timeout=8)` — ağ kararı yerel ↔ uzak örneğe göre veriliyor, ayara göre değil; `grep -rn "allow_dts_fetch\|allow_source_match" karadul` → yalnız `config.py`.
- Etki: Çevrimdışı/izole analiz ortamı varsayan analistin makinesi zararlı hakkında dışarıya bilgi verir; Electron incelemesi internetten kod indirip çalıştırır.
- Güven: yüksek (kod izlendi; DTS yolunu tetikleyen paketli bir girdiyle çalıştırmadım, örnek koşu ağ kapalı kum havuzunda yapıldı ve parmak izi eşleşmesi olmadığı için bu katmana girmedi)
- Onarım kapsamı: `naming/pipeline.py` uzak `DtsNamer`'ı yalnız `config.network.enabled and config.network.allow_dts_fetch` ise kur; `electron.py` ASAR'ı Python'da aç (biçim basit: 8+8 bayt başlık + JSON + gövde) ya da `@electron/asar`'ı `scripts/package.json`'a sabit sürümle ekleyip `node_modules/.bin/asar`'ı doğrudan çağır (`npx --yes` kalksın); `allow_*` bayraklarını ya bağla ya sil. M.
- Nasıl sınanır: `urllib.request.urlopen` ve `subprocess` çağrılarını yasaklayan bir test bekçisiyle (ör. monkeypatch) webpack + chalk parmak izli fixture ve küçük bir `.asar` üzerinde tam JS/Electron koşusu ağ çağrısı yapmamalı.

## BICIM-07 — Hedef çözücü, var olmayan noktalı bir ad verildiğinde çalışma dizinindeki Python modülünü İÇE AKTARIYOR (kod yürütme); ayrıca sessizce başka bir ikiliyi hedef seçebiliyor
- Önem: YÜKSEK
- Tür: güvenlik
- Yer: `karadul/core/target_resolver.py:213-245` (`_check_python_package` → `importlib.util.find_spec(name)`), `:57-61` (izinli karakterlere `.` dahil), çağıran `karadul/cli.py:623-635`
- Etkin mi: evet (her `karadul analyze <ad>` çağrısında, ad bir dosya/dizin değilse)
- Ne: Verilen ad dosya sistemi, PATH, /Applications ve Homebrew'da bulunamazsa `find_spec(name)` çağrılıyor. Noktalı adlarda `find_spec("a.b")` üst paketi `a`'yı gerçekten İÇE AKTARIR (modül kodu çalışır). `python -m karadul` ile çalıştırıldığında `sys.path[0]` çalışma dizinidir; analistin örnek klasöründe `evil.py` varken `karadul analyze evil.pyc` (yazım hatası ya da henüz çıkarılmamış dosya) `evil.py`'yi çalıştırır. Koddaki yorum "subprocess yerine find_spec (RCE önlemi)" diyor; önlem noktasız ad için geçerli, noktalı ad için değil. Ek olarak: ad bulunamayınca PATH'teki, /Applications'taki ya da Spotlight'ın bulduğu (`*ad*` jokerli) BAŞKA bir dosya hedef seçiliyor; yalnız INFO günlüğüne yazılıyor.
- Kanıt: geçici dizinde `evil.py` = `open("IMPORTED_MARKER","w").write("ran")`;
  ```
  $ cd <tmp>/rs && PYTHONPATH=/Users/apple/Black_Widow python -m karadul analyze evil.pyc --skip-dynamic
  ... 'evil.pyc' bulunamadi ... Tam dosya yolunu verin.
  $ ls
  IMPORTED_MARKER  evil.py
  ```
- Etki: Zararlı örneklerin durduğu dizinde bir yazım hatası analistin makinesinde örneğin Python kodunu çalıştırır. Bulunamayan ad için yanlış dosyanın analiz edilmesi de analisti yanıltır.
- Güven: kesin (çalıştırıp gösterdim)
- Onarım kapsamı: `target_resolver.py` — Python paketi aramasını kaldır ya da yalnız noktasız adla ve `sys.path`'ten cwd/'' çıkarılmış hâlde yap (find_spec yerine `importlib.machinery.PathFinder.find_spec(name, [site-packages yolları])` noktasız ad); yol gibi görünen girdide (`.`/uzantı içeren) yalnız dosya sistemine bak, bulunamazsa hata ver; Spotlight/PATH yedeğiyle seçilen hedef için açık onay ya da en azından ekrana uyarı. S.
- Nasıl sınanır: cwd'de `evil.py` varken `resolve_target("evil.pyc")` FileNotFoundError vermeli ve işaret dosyası OLUŞMAMALI.

## BICIM-08 — Yerel (native) bir PE, içinde `mscoree.dll` / `mscorlib` / `System.Runtime` dizgisi geçti diye .NET sayılıyor; Ghidra hiç çalışmıyor, aşamalar "başarılı"
- Önem: YÜKSEK
- Tür: hata (yanlış sınıflama) + sahte/yanlış gösterim
- Yer: `karadul/core/target.py:748-766` (`_is_dotnet`), yönlendirme `:544-551`; tüketen `karadul/analyzers/dotnet_binary.py:584-676` (CLI başlığı yokken de success=True), `:698-728` (reconstruct koşulsuz success, `.csproj` yazar)
- Etkin mi: evet (her PE hedefi)
- Ne: `.NET` kararı ilk 1 MB'da bayt dizgisi aramasıyla veriliyor; PE isteğe bağlı başlığındaki CLI veri dizini (dizin 14) hiç okunmuyor. CLR'yi kendisi yükleyen yerel yükleyiciler (zararlıda yaygın: "execute-assembly", donut benzeri yükleyiciler `mscoree.dll`'i içe aktarır ya da `CLRCreateInstance` çağırır), .NET barındıran C++ uygulamaları ve yalnız bu dizgileri taşıyan herhangi bir PE `DOTNET_ASSEMBLY` olur. Sonra `DotNetBinaryAnalyzer` CLI başlığı bulamasa da (`has_cli_header: False`) `success=True` döner, deobfuscation "atlandı", reconstruct `{'reconstructed': True}` ile boş bir `.csproj` üretir; yerel kod için Ghidra/decompile adımı hiç çalışmaz. Analizci `has_cli_header=False` gördüğünde PE yoluna geri dönmüyor.
- Kanıt: elle kurulmuş 436 baytlık `MZ…PE\0\0…mscoree.dll\0CLRCreateInstance` dosyası:
  ```
  identify True  {'target_type': 'dotnet_assembly', 'language': 'csharp', ...}
  static   True  {'functions': 0, 'decompiled': False, 'has_cli_header': False, ...} ['ilspycmd veya monodis bulunamadi']
  reconstruct True {'reconstructed': True}
  ```
- Etki: Tam da analistin en çok ilgileneceği yükleyici ikililer native analizden geçmeden "0 fonksiyon, başarılı" raporuyla kapanır.
- Güven: kesin (çalıştırıp gösterdim; gerçek bir CLR yükleyici örneğiyle denemedim, dizgi tetikleyicisi koddan açık)
- Onarım kapsamı: `target.py` `_is_dotnet` → PE başlığını ayrıştır (`e_lfanew` → OptionalHeader → DataDirectory[14] RVA/Size ≠ 0); dizgi araması en çok ikincil ipucu. `dotnet_binary.py` `analyze_static` → `has_cli` False ise başarısız ya da `PE_BINARY`'ye geri yönlendirme önerisi. S-M.
- Nasıl sınanır: CLI dizini boş + `mscoree.dll` dizgili PE → `PE_BINARY`; gerçek bir küçük .NET derlemesi (CLI dizini dolu) → `DOTNET_ASSEMBLY`; ikisi için birim test.

## BICIM-09 — .app paketinde ana bileşen "en çok fonksiyonlu" seçiliyor: Electron/Java uygulamalarında asıl kod (JS, JAR) hiç yeniden kurulmuyor
- Önem: YÜKSEK
- Tür: hata / eksik özellik
- Yer: `karadul/analyzers/app_bundle.py:70-75` (`main_component` = en çok `functions_found`), `:122-124` (sayaç anahtarları), `karadul/analyzers/electron.py:128-171` (Electron istatistiğinde fonksiyon sayacı yok → 0); `karadul/stages.py:1239-1267` (ana bileşen türü dallanması: `java_jar` dalı yok → "Bilinmeyen bilesen tipi"), `:771-774` (APP_BUNDLE için deobfuscation atlanıyor), `:5227-5238` (`_execute_js` yalnız `deobfuscated/*.js` okur); bileşen listesi `karadul/core/target.py:252-282` (Frameworks altındaki her `.framework` ve Resources altındaki her `.dylib`, boyut/tedarikçi süzgeci yok)
- Etkin mi: evet (her `.app` hedefi)
- Ne: (1) Electron bileşeni 0 fonksiyonlu sayıldığı için bir Electron `.app`'inde ana bileşen hep en büyük yerel çerçeve olur (tipik olarak "Electron Framework", yani Chromium); yeniden kurma uygulamanın JS'i yerine Chromium üstünde koşar. (2) Electron ana bileşen seçilse bile `_execute_js` `deobfuscated/` altında `.js` arar; APP_BUNDLE için deobfuscation aşaması atlanıyor ve bileşenlerde yalnız `analyze_static` koşuyor, dolayısıyla JS yeniden kurma "Deobfuscate edilmis dosya bulunamadi" ile düşer. (3) Bir Java uygulamasında JAR'ın metot sayısı en yüksekse ana bileşen `java_jar` olur ve reconstruct "Bilinmeyen bilesen tipi: java_jar" hatasıyla başarısız olur. (4) `Resources/**/*.dylib` ve tüm iç içe `.framework`'ler sırayla Ghidra'ya veriliyor; gömülü JRE ya da Chromium içeren paketlerde bu saatler sürer ve sınır/ilerleme bütçesi yok.
- Kanıt: kod: `main_component` → `max(successful, key=lambda r: r.functions_found)`; ElectronAnalyzer `stats` anahtarları `asar_*`, `js_file_count`, `total_js_size`, `main_js`, `js_files`, `webpack_bundles` (hiçbiri `_FUNCTION_COUNT_KEYS`'te değil); `stages.py:1266-1267` `else: errors.append(f"Bilinmeyen bilesen tipi: {main_type}")`.
- Etki: Electron ya da Java tabanlı zararlı bir `.app` verildiğinde analist zararlı kodun değil üçüncü taraf çalışma zamanının "yeniden kurulmuş" çıktısını görür; asıl JS/JAR mantığı raporda yer almaz.
- Güven: yüksek (kod izlendi; Ghidra gerektirdiği için gerçek bir `.app` ile çalıştırmadım)
- Onarım kapsamı: `app_bundle.py` ana bileşen seçimini türe göre öncelikle (electron_app / java_jar > Contents/MacOS ana ikilisi > çerçeveler), çerçeveleri bilinen tedarikçi listesiyle ya da boyut bütçesiyle süz; `stages.py` `_execute_app_bundle` — `java_jar` dalı (`_execute_analyzer_reconstruct`), Electron dalında bileşen deobfuscation'ını çalıştır ya da `_execute_js`'e asar çıkarım dizinini ver. M.
- Nasıl sınanır: Contents/MacOS'ta küçük Mach-O, Frameworks'te büyük sahte çerçeve ve `Resources/app.asar` olan sentetik paket — ana bileşen `electron_app`, reconstruct JS çıktısı üretir; JAR'lı paket için `java_project/` oluşur.

## BICIM-10 — "Desteklenen" birçok biçim tanınmıyor ya da yanlış hatta gidiyor (tek `.pyc`, cx_Freeze, wheel/IPA/nupkg, FAT64, evrensel ikili içindeki Go/PyInstaller/Bun); UNKNOWN türü JS yeniden kurmasına düşüp yanıltıcı hata veriyor
- Önem: ORTA
- Tür: eksik özellik / tutarsızlık
- Yer: `karadul/core/target.py:213-218` (yalnız `.js/.mjs/.cjs` uzantısı JS), `:448-458` (UNIVERSAL_BINARY dalında Go/Bun/PyInstaller denetimi yok), `:478` (Bun yalnız Mach-O), `:487-498, 520-530, 570-580` (PYTHON_PACKED yalnız PyInstaller MEI işaretiyle), `:587-607` (ZIP: yalnız JAR/APK), `:59-66` (`0xCAFEBABF` FAT_MAGIC_64 yok); `karadul/analyzers/python_binary.py:802-813` (cx_Freeze dalı — PYTHON_PACKED'e cx_Freeze ile girilen yol yok); `karadul/stages.py:1142` (UNKNOWN → `_execute_js`)
- Etkin mi: evet (yönlendirme); cx_Freeze dalı fiilen ölü
- Ne: Elle kurulan örneklerle `TargetDetector().detect`: tek `.pyc` → `unknown`; `.whl`, `.ipa`, `.nupkg` (ZIP) → `unknown`; `0xCAFEBABF` → `unknown`; yalnız "Go build" dizgisi taşıyan küçük C ELF'i → `go_binary` (bkz. aşağıdaki Küçükler). `PythonBinaryAnalyzer` cx_Freeze ve Nuitka'yı "destekliyor" ama hedef türü yalnız MEI işaretiyle atandığı için bir cx_Freeze ikilisi native hatta gider, Python katmanı hiç açılmaz. Evrensel (fat) ikili hep UNIVERSAL_BINARY: universal2 PyInstaller ya da fat Go/Bun ikilisinde özel hat atlanır. UNKNOWN türünde static "Analyzer bulunamadi" ile düşüyor, deobfuscation atlanıyor, reconstruct ise JS hattına girip "Deobfuscate edilmis dosya bulunamadi" diyor (yanlış gerekçe); CLI çıkış kodu 0.
- Kanıt:
  ```
  app.ipa                 unknown   {'magic': '0x504B0304'}
  fat64                   unknown   {'magic': '0xCAFEBABF'}
  m.pyc                   unknown   {'magic': '0xCB0D0D0A'}
  x-1.0-py3-none-any.whl  unknown   {'magic': '0x504B0304'}
  celf                    go_binary {'format': 'elf', ...}
  ```
  `python -m karadul analyze m.pyc` → `static False ['Analyzer bulunamadi: …UNKNOWN']`, `reconstruct False ['Deobfuscate edilmis dosya bulunamadi']`, süreç çıkış kodu 0.
- Etki: Analist "desteklenmiyor" yerine JS'e özgü anlamsız bir hata görür; zararlıda sık görülen tek `.pyc`, cx_Freeze ve universal2 PyInstaller örnekleri Python katmanı açılmadan geçer.
- Güven: kesin (tespit ve UNKNOWN koşusu çalıştırıldı); cx_Freeze yönlendirmesi kod okunarak
- Onarım kapsamı: `target.py` — `.pyc` sihirli sayısı → PYTHON_PACKED (ya da yeni tür), cx_Freeze imleri (`lib/library.zip` komşuluğu ya da `cx_Freeze` dizgisi) → PYTHON_PACKED, fat ikilide dilim seçip aynı denetimleri dilimde yap, FAT64; `stages.py` UNKNOWN için açık "tür tanınmadı" atlaması. M.
- Nasıl sınanır: her biçim için bir küçük fixture ile `detect` beklenen türü vermeli; UNKNOWN koşusunda reconstruct "tanınmadı/atlandı" demeli.

## BICIM-11 — npm parmak izi, genel alt dizgilerle (eşiksiz) zararlı modülleri "Vendored <paket>" diye `vendor/` altına koyuyor
- Önem: YÜKSEK
- Tür: sahte/yanlış gösterim
- Yer: `karadul/reconstruction/naming/npm_fingerprinter.py:604-650` (`_match_module`: `s in content` alt dizgi araması, `min_match` 2-3, güven alt sınırı yok), imza örnekleri `:77-108` (`"dsn"`, `"Sentry"`, `"pem"`, `"pkcs"`, `"forge."`), rxjs `"Subject"`, `"pipe("`, `"subscribe("`; tüketen `karadul/reconstruction/naming/pipeline.py:93-95` (Layer 1 sonucu doğrudan manifest'e), `:341-357` (`named_project/<category>/<paket>.js`), `:106-199` (eşleşen pakete göre `.d.ts` adları modüle uygulanıyor)
- Etkin mi: evet (çağıran: `stages.py:5366-5375`, webpack modülleri çıkarıldığında)
- Ne: Her paket için 9-14 dizgiden 2-3'ünün dosyada alt dizgi olarak geçmesi yetiyor; sözcük sınırı, AST bağlamı ya da en düşük güven yok. Seçilen modül "Vendored <paket> package" açıklamasıyla `vendor/<paket>/` kategorisine kopyalanıyor ve Layer 2 (yapısal) o modüle bakmıyor (`named` kümesine giriyor). Saldırgan, zararlı modüle birkaç tuzak dizgi ekleyerek onu "üçüncü parti kütüphane" klasörüne gönderebilir; tuzaksız gerçek kodda da olur (ör. anahtar dosyası okuyan kod `pem`/`pkcs` içerir).
- Kanıt:
  ```
  keyload  ('node-forge', 0.267, 'vendor/node-forge', 'Vendored node-forge package (2 string match)')
           # içerik: readFileSync(home+"/.ssh/id_rsa"); if(key.includes("pem")) send(key); // pkcs8
  stealer  ('@sentry/node', 0.36, 'vendor/sentry', 'Vendored @sentry/node package (3 string match)')
  pubsub   ('rxjs', 0.257, 'vendor/rxjs', 'Vendored rxjs package (3 string match)')
  ```
  (`NpmFingerprinter()._match_module(...)` doğrudan çağrıldı.)
- Etki: Analist, `vendor/` altını "üçüncü parti" diye atlarsa kimlik bilgisi çalan ya da C2'ye veri yollayan modülü görmez. Güven 0,27 olsa da dizin yerleşimi ve açıklama bunu göstermiyor.
- Güven: kesin (çalıştırıp gösterdim)
- Onarım kapsamı: `npm_fingerprinter.py` — dizgileri sözcük/token sınırında ara, paket başına ayırt edici (tekil) imzalar zorunlu olsun (ör. `@sentry/` önek dizgisi, sürüm sabiti), en düşük güven eşiği (ör. 0,6) ve altında yalnız "olası" etiketi; `pipeline.py` düşük güvenli eşleşmeyi `vendor/` yerine `suspected_vendor/` ya da `unnamed/` altına koysun, açıklamaya güveni yazsın. S-M.
- Nasıl sınanır: yukarıdaki üç örnek eşleşmemeli (ya da "olası", vendor dışı); gerçek highlight.js / rxjs paket parçası eşleşmeye devam etmeli.

## BICIM-12 — JS "yeniden kurulmuş proje" yanıltıcı: giriş dosyası tek bir webpack modülü, ad/tip/yorum adımlarının çıktısı projeye girmiyor, README zararlıyı `npm install && npm start` ile çalıştırmayı öneriyor
- Önem: YÜKSEK
- Tür: sahte/yanlış gösterim + güvenlik
- Yer: `karadul/reconstruction/project_builder.py:321-345` (giriş = `deobfuscated/**/module_0*.js`, yoksa en büyük `.js`), `:347-356` (hiçbir şey yoksa uydurma `console.log("Reconstructed project - ready for development")`), `:461-550` (README "Quick Start: npm install / npm start"), `:555-597` (Dockerfile `npm ci --only=production`, kilit dosyası yok); `karadul/reconstruction/project_reconstructor.py:384-405` (aynı README); `karadul/stages.py:5452-5512`
- Etkin mi: evet (`_execute_js` her JS koşusunun 7. adımı; 10'dan az modülde ProjectBuilder, çok modülde ProjectReconstructor)
- Ne: (1) ProjectBuilder `project/src/index.js`'i `deobfuscated/` altındaki `module_0.js`'ten kuruyor; diğer modüller projeye kopyalanmıyor, `require` edilen modül kimlikleri çözülmüyor. Aynı aşamanın 1-6. adımlarında üretilen ad verilmiş/tiplenmiş/yorumlanmış dosya (`reconstructed/*.nsa_named…commented.js`) projede yok; yani "yeniden kurulmuş proje" yeniden adlandırmanın sonucunu içermiyor. (2) Hiç aday yoksa giriş dosyasına hedefle ilgisiz, "hazır" diyen bir yer tutucu kod yazılıyor (sahte içerik). (3) README ve ProjectReconstructor README'si analiz edilen (zararlı olabilecek) kodu `npm install` + `npm start` ile ÇALIŞTIRMAYI öneriyor; uyarı yok. `npm install` paket betiklerini (postinstall) de çalıştırır ve bağımlılık adları zararlının `require` ettiği adlardır. Dockerfile kilit dosyası olmadan `npm ci` çağırdığı için zaten derlenmez. (4) README bağlantısı `https://github.com/karadul` ve sürüm "Karadul v1.0" (25 yerde sabit; ürün 1.23.1).
- Kanıt: örnek koşu: `project/src/index.js` = başlık + `module_0` gövdesi (BICIM-01'deki bozuk `function (elem, tmp, count) {`); `project/` içinde yalnız `src/index.js, package.json, README.md, Dockerfile, .gitignore`; README:
  ```
  ## Quick Start
  npm install
  npm start
  ```
- Etki: Analist ürünün "proje" çıktısını yeniden adlandırılmış kod sanır; README'yi izlerse zararlıyı kendi makinesinde çalıştırır.
- Güven: kesin (çalıştırıp gösterdim; uydurma giriş dalı kod okunarak)
- Onarım kapsamı: `project_builder.py` / `project_reconstructor.py` — giriş ve modüller için `_execute_js`'in son çıktısını ve `named_project/`'i kullan; uydurma giriş yerine dosya üretme ve `stats`'ta "giriş bulunamadı" de; README'de "Bu kod güvenilmeyen bir ikiliden üretildi; çalıştırmayın / yalnız yalıtılmış ortamda" uyarısı, Quick Start kaldırılsın; Dockerfile ya kaldırılsın ya `npm install --ignore-scripts`; sürüm `karadul.__version__`'dan. S-M.
- Nasıl sınanır: örnek koşuda `project/` adlandırılmış kodu içermeli; README'de `npm start` geçmemeli; hedefte modül yokken giriş dosyası uydurma `console.log` içermemeli.

## BICIM-13 — Modül ayırma (ModuleSplitter) ve çok modüllü proje kurucu (ProjectReconstructor) hiç çalışmıyor: yanlış dizin aranıyor
- Önem: ORTA
- Tür: hata (hiç çalışmayan özellik)
- Yer: `karadul/stages.py:5340-5357` (`webpack_dir = deob_dir / "webpack_modules"`; `any(webpack_dir.glob("module_*.js"))`), `:5456-5461` (`use_reconstructor` yalnız `split_result.total_modules >= 10`); yazan taraf `scripts/smart-webpack-unpack.mjs:53` (`modulesDir = join(outputDir, "modules")`)
- Etkin mi: evet (her JS koşusu), ama dal hiç girilmiyor
- Ne: Derin hat modülleri `deobfuscated/webpack_modules/modules/module_*.js`'e yazıyor; ModuleSplitter koşulu ise bir üst dizinde (`webpack_modules/module_*.js`) arıyor, `glob` özyinelemeli değil. Koşul hep yanlış → `split_result = None` → `modules_split`/`module_categories` hiç dolmuyor ve `use_reconstructor` hep yanlış → 10+ modüllü paketlerde de ProjectReconstructor (`reconstruct-project.mjs`) yerine tek-giriş ProjectBuilder (BICIM-12) çalışıyor. Hemen altındaki NamingPipeline doğru dizini (`webpack_modules/modules`) kullanıyor; iki adım birbirini tutmuyor. Eski `webpack_modules/` düzenini yalnız ölü legacy yol (`javascript.py:304`) yazıyordu.
- Kanıt: örnek koşuda 3 modül çıktı (`deobfuscated/webpack_modules/modules/module_{0,1,2}.js`), `reconstruct.stats`'ta `modules_split` yok, `reconstruction_mode = project_builder`.
- Etki: Kategori ayırma ve çok modüllü proje kurma "var" görünüyor ama hiçbir koşuda çalışmıyor; büyük paketlerde proje çıktısı tek modül.
- Güven: kesin (koşu çıktısı + kod)
- Onarım kapsamı: `stages.py` — `webpack_dir = deob_dir / "webpack_modules" / "modules"` (ya da `result.modules_dir`'i deobfuscate artefaktından al); ProjectReconstructor'ın BICIM-01 düzeltmesinden sonra gerçekten çalıştığını sına. S (tehlike: ölü kalmış ProjectReconstructor ilk kez koşacak; ayrıca gözden geçirilmeli).
- Nasıl sınanır: 12 modüllü bir webpack fixture'ında `modules_split == 12`, `reconstruction_mode == "project_reconstructor"`.

## BICIM-14 — PyInstaller CArchive açmada toplam boyut bütçesi yok; aynı adlı girdiler sessizce birbirini eziyor
- Önem: ORTA
- Tür: güvenlik (kaynak tüketimi) / sessiz hata
- Yer: `karadul/analyzers/packed_binary.py:1484-1492` (her TOC girdisi çıkarılıyor), `:1765-1768` (girdi başına `_MAX_PYINSTALLER_DECOMPRESS = 100 MB`, `:66`), `:1835-1838` (`O_TRUNC` ile yazım), `:1419` (`MAX_TOC_ENTRIES = 100_000`), `:1442-1443` (tüm dosya belleğe, boyut denetimi yok); çağıran `karadul/analyzers/python_binary.py:779-780`
- Etkin mi: evet (PYTHON_PACKED reconstruct)
- Ne: PYZ ve cx_Freeze için `security.max_archive_extract_size` (2 GB) paylaşılan bütçe olarak uygulanıyor, CArchive girdileri için uygulanmıyor: 100 000 girdinin her biri 100 MB'a kadar açılabilir (yüzlerce KB'lık sıkıştırılmış girdi başına 100 MB yazım). Aynı adı taşıyan iki TOC girdisi (ya da büyük/küçük harf duyarsız APFS'te `A`/`a`) aynı dosyaya `O_TRUNC` ile yazılır; ikisi de `extracted` listesine girer ve sayılır, diskte biri kalır. `SecurityConfig.max_decompress_bytes` ve `pyinstaller_reserved_names` hiç okunmuyor (sabitler modülde ayrıca tanımlı). `PyInstallerExtractor.extract` hedefi boyut sınırı olmadan tümüyle belleğe okuyor (`max_binary_size_bytes` yalnız `PackingDetector.detect`'te).
- Kanıt: `budget` yalnız `_extract_pyz_archives` (`:1561`) ve `python_binary.py:923`'te; `grep -rn "max_decompress_bytes\|pyinstaller_reserved_names" karadul --include=*.py` → yalnız `config.py`.
- Etki: Kasıtlı hazırlanmış bir PyInstaller örneği analist diskini doldurabilir (bu makinede disk dolması yaşanmış bir sorun); ezilen girdiler raporda var, diskte yok.
- Güven: yüksek (kod izlendi; bomba dosyası üretip çalıştırmadım)
- Onarım kapsamı: `packed_binary.py` `extract` — PYZ ile ortak toplam bütçe; ad çakışmasında `unique_casefold_name` (zaten PYZ için var, `:1203`); config sabitlerini oku. S.
- Nasıl sınanır: 50 × 100 MB'lık sıkıştırılmış girdili sentetik CArchive bütçede durmalı; aynı adlı iki girdi iki ayrı dosya ya da açık bir "çakışma" kaydı üretmeli.

## BICIM-15 — Kulvarda çağrılmayan modüller ve dallar (ölü kod)
- Önem: ORTA
- Tür: ölü kod / okunmayan ayar
- Yer: `karadul/analyzers/container_classifier.py` (1 148 satır), `karadul/reconstruction/jsnice_renamer.py`, `karadul/reconstruction/ts_declarations_namer.py` — içe aktaran yok; `karadul/stages.py:1034-1062` `_execute_legacy` (`DeobfuscationStage(use_deep=False)` hiçbir yerde kurulmuyor: `cli_common.py:109`, `batch.py:217`, `core/pipeline.py:164` öntanımlı `True`) → bununla birlikte `ElectronAnalyzer.deobfuscate` (`electron.py:201-284`), `DeobfuscationManager` (`deobfuscators/manager.py`), `SynchronyWrapper`, `BabelPipeline`; `config.deobfuscation.chain` (`config.py:297`) yalnız ölü yöneticide okunuyor; `PythonBinaryAnalyzer`'ın cx_Freeze dalı (BICIM-10)
- Etkin mi: ölü
- Ne: `grep -rln "jsnice_renamer\|ts_declarations_namer\|container_classifier" karadul --include=*.py` boş (yalnız kendi dosyaları). Legacy deobfuscation zinciri (beautify → synchrony → babel) yalnız `use_deep=False` ile seçiliyor; bu değeri veren çağıran yok. Belgeler ve `config.deobfuscation.chain` bu zinciri hâlâ yapılandırılabilir gibi gösteriyor.
- Kanıt: yukarıdaki grep çıktıları; `stages.py:781` `def __init__(self, *, use_deep: bool = True)`.
- Etki: Bakım yükü; ayar değiştiren kullanıcı/ajan etkisiz bir düğmeye dokunur; testler ölü yolu sınayıp "kapsam" verir.
- Güven: yüksek (grep ile çağıran arandı; dinamik `importlib` ile yükleme aramadım)
- Onarım kapsamı: kaldır ya da açıkça "deneysel/kapalı" işaretle; `deobfuscation.chain`'i belgeden ve config'ten düş. S.
- Nasıl sınanır: kaldırma sonrası tam takım; `python -c "import karadul.cli"` ve `analyze --stage deobfuscate` JS fixture'ı.

## Küçükler
- (ipucu c) `karadul/analyzers/dotnet_binary.py:39` ve `:45` aynı modülden (`karadul.core.safe_subprocess`) aynı `resolve_tool` nesnesini iki kez içe aktarıyor; ikincisi aynı nesneyi yeniden bağlar, davranış değişmez (yalnız temizlik). Asıl sorun başka: `resolve_tool` beyaz listesi (`safe_subprocess.py:52-61`) `~/.dotnet/tools`'u içermiyor; `ilspycmd`'nin standart kurulumu (`dotnet tool install -g`) oraya gider, yani ILSpy elle `/usr/local/bin`'e bağlanmadıkça HİÇ bulunmaz (bu makinede de yok) ve .NET hattı hep `strings` yedeğine düşer. jadx de bu makinede kurulu değil.
- `karadul/analyzers/electron.py:474-486`: `package.json`'daki `main` alanı süzülmeden `extract_dir / main_entry` yapılıyor; `"/abs/yol.js"` ya da `"../../x.js"` analistin diskindeki başka bir `.js` dosyasını "ana JS" seçtirir, deep hat onu `deobfuscated/00_original.js`'e kopyalar ve rapora girer (yerel dosya sızıntısı; `.js` uzantısıyla sınırlı).
- `karadul/core/target.py:666-677`: Go kararı ilk 2 MB'da `b"Go build"`, `go.buildid`, `runtime/internal` gibi düz dizgilerle veriliyor; yalnız `"usage: Go build helper"` dizgisi olan küçük bir C ELF'i `go_binary` oldu. Ölçüm setinde (`~/karadul_olcum/n1_debian13`, 117 ELF) yanlış pozitif 0 — risk kuramsal; bölüm başlığı denetimi (ELF `.gopclntab` / Mach-O `__gopclntab` bölüm tablosundan) yeterli olurdu.
- `karadul/core/target.py:193-211`: `.asar` uzantısı içerik denetimi olmadan ELECTRON_APP; `:323-333` paketin "main_binary"si ve `file_hash`'i Resources altındaki en büyük dylib olabiliyor (gömülü JRE'de `libjvm.dylib`).
- `karadul/analyzers/macho.py:183-190` + `pipeline/steps/binary_prep.py:99-111`: arm64 dilimi yoksa x86_64 dilimi yine `raw/<ad>_arm64` adıyla yazılıyor; bayt eşleştirme `byte_match_binary = "arm64_slice"` raporluyor.
- `karadul/analyzers/java_binary.py:624-629`: jadx `--no-debug-info` ile çağrılıyor; derlemede bırakılmış yerel değişken/parametre adları (LocalVariableTable) kullanılmıyor — ad kurtaran bir araç için bilerek atılan gerçek ad (şüphe: jadx sürümüne göre bayrağın etkisi doğrulanmadı).
- `karadul/analyzers/java_binary.py:558-571`: APK paket adı, ikili AndroidManifest'te (dizgi havuzu çoğunlukla UTF-16) ilk ≥4 baytlık ASCII dizisinden "en az iki nokta" kuralıyla seçiliyor; çoğu APK'da yanlış/boş paket adı üretir (ve BICIM-04'ün kaynağıdır).
- `karadul/analyzers/java_binary.py:658-674`: jadx yoksa `strings` sıkıştırılmış JAR üzerinde koşuyor; deflate'li `.class` adları görünmez, yedek fiilen boş.
- `karadul/reconstruction/param_recovery.py:143-148, 229-230`: her JS koşusu `$TMPDIR/bw_param_recovery_*.json` bırakıyor (hedeften kurtarılan adları içerir); bu oturumda iki tane bulundu (08:28, 08:35).
- `karadul/cli.py` (kulvar dışı, bilgi için): pipeline başarısızken (`static False`, `reconstruct False`) süreç çıkış kodu 0 (UNKNOWN `.pyc` koşusu).
- `karadul/reconstruction/project_builder.py`/`dependency_resolver.py`: `package.json` bağımlılıkları zararlının `require` ettiği adlardan `"latest"` sürümüyle yazılıyor; `npm install` (README önerisi) saldırganın yayımladığı bir paketi kurup kurulum betiğini çalıştırabilir (BICIM-12 ile birlikte düşünülmeli).
- `karadul/deobfuscators/deep_pipeline.py:513`: `smart-webpack-unpack.mjs` sabit 300 sn zaman aşımıyla çalışıyor, diğer adımlar dosya boyutuna göre ölçekleniyor; 100 MB altı büyük paketlerde bu adım tek başına düşebilir (şüphe; ölçülmedi).

## Bilinenlerin durumu
| Kalem | Durum | Kanıt |
|---|---|---|
| B-F3 `dis` yedeğinde güvenilmeyen `marshal.loads` | kısmen kapanmış | `pyc_decompiler.py:509-546, 686-724`: `marshal.loads` artık ayrı yorumlayıcıda (`-s -S -P`, `safe_env`, zaman aşımı, bellek bekçisi, çıktı tavanı); ana süreç unmarshal etmiyor. Çağrı hâlâ güvenilmeyen veriyle yapılıyor (yalıtılmış). |
| B-F3 decompyle3/uncompyle6 doğrulaması | kapanmış | `pyc_decompiler.py:419-472`: ayrı süreç + `_source_problems` doğrulaması. |
| B-F3 manifest "zPYZ" | kapanmış | `python_binary.py:1450-1456`: envanter TOC'tan, dizgi taramasından değil. |
| B-F3 static TOC little-endian | kapanmış | static envanter `PyInstallerExtractor._parse_toc` (`packed_binary.py:1668` `"!IIIBB"`) kullanıyor. |
| B-F3 iki stdlib tanımı | kapanmış | tek sınıflayıcı `packed_binary.py:1120-1150` (`_is_stdlib_top_level` + `_STDLIB_ADDED_IN/REMOVED_IN`); `python_binary.py`'de ayrı liste yok. |
| B-F3 cx_Freeze `__init__` çakışması | kapanmış (kod) / ölü (yol) | `python_binary.py:893-913` düzeltilmiş; ama cx_Freeze hedefi PYTHON_PACKED'e hiç yönlenmiyor (BICIM-10). |
| B-F3 üçüncü parti modül üst sınırı | kısmen | `max_python_decompile_modules=2000` hem CArchive (`packed_binary.py:1525`) hem PYZ zincirinde uygulanıyor; "üçüncü parti" sınıfının decompile'a girip girmediğini ayrıca doğrulamadım. |
| B-F3 CLI decompile sayıları | bakılmadı | — |
| B-F4 `context_namer` + `.mjs` hattı için test yok | kapanmış | `tests/test_context_namer_node.py` (gerçek node + Babel, 18 test işlevi; node yoksa atlanır). Buna karşılık `smart-webpack-unpack.mjs` çıktısının ayrıştırılabilirliğini sınayan test yok (BICIM-01). |
| B-C1 `stages.py` monolitleri emekli | kulvar için geçersiz | JS/analizci dalları (`_execute_js`, `_execute_deep`, `_execute_analyzer_reconstruct`, `_execute_app_bundle`) ETKİN; emekli olan yalnız `_execute_legacy` (BICIM-15). |
| B-F2 `vendor/pycdc` pakete girmiyor | bakılmadı | — |

## Bakamadıklarım
- Ghidra gerektiren uçtan uca koşular: gerçek bir `.app` (Electron/Java), Go/Swift/Rust/Delphi ikilileri; bu analizcilerin (`go_binary.py`, `swift_binary.py`, `rust_binary.py`, `delphi_binary.py`, `macho.py`) gövdelerini okumadım (yalnız alt süreç çağrılarını listeledim).
- `deobfuscators/binary_deobfuscator.py`, `string_decryptor.py`, `cff_deflattener.py`, `opaque_predicate.py` (native hatta etkin) — yalnız başlığa baktım.
- `reconstruction/source_matcher/*` (öntanımlı kapalı, `--enable-network` ile açılıyor), `dts_namer.py` ayrıştırıcısı, `comment_generator.py`, `type_inferrer.py`, `variable_renamer.py`, `go_reconstructor.py`, `module_splitter.py`'nin iç mantığı (ModuleSplitter zaten ulaşılmaz, BICIM-13).
- `@electron/asar`'ın kötü niyetli ASAR'da yol geçişi/simgesel bağ davranışı (npx her seferinde son sürümü çektiği için sürüme bağlı; denemedim).
- jadx/ILSpy kurulu olmadığı için BICIM-05 çalıştırılarak gösterilmedi; BICIM-04'ün .NET kaynak tarafı gerçek bir derlemeyle denenmedi.
- `scripts/*.mjs`'in iç dönüşüm doğruluğu (deep-deobfuscate 10 aşama, apply-names kapsam güvenliği): yalnız Python sözleşmesine ve örnek koşuya baktım; `context_namer` hattının ad yakalama testleri var.
- `pyc_decompiler.py`'nin pycdc çıktı doğrulaması ve `python_binary.py` reconstruct sayaçları (B-F3 "CLI decompile sayıları").

## KULVAR BİTTİ
