# Kulvar BORU — bulgular
Kapsam: `karadul/stages.py` (giriş, `IdentifyStage`, `StaticAnalysisStage.execute`, `DeobfuscationStage.execute`, `ReconstructionStage.execute/_execute_app_bundle/_execute_binary` tamamı yapısal, `_seed_recovery_pre_names`, `_apply_manual_overrides`, `ReportStage`; ölü aralıklar çağıran düzeyinde), `karadul/pipeline/runner.py`, `context.py` (kısmen), `registry.py` (kısmen), `steps/` içinden `binary_prep`, `feedback_loop`, `struct_recovery`, `cfg_iso_match`, `computation_fusion`, `inline_detection`, `semantic_naming`, `project_build`, `finalize`, `deep_tracing` (+ `_deep_tracing_helpers.propagate_param_names`), `type_recovery_consumer`, `trex_struct_recovery` (giriş), `anti_debug` (yapıt kısmı), `_feedback_naming.py` / `_feedback_naming_merger.py` / `_bindiff` / `_refdiff` (yalnız akış), `karadul/core/pipeline.py`, `core/result.py`, `core/workspace.py`, `core/error_recovery.py`, `core/overrides.py`, `karadul/batch.py`, `karadul/cli.py` (`analyze`, `batch analyze`, kesme dekoratörü), `karadul/cli_common.py`. Gerçek çıktı: `~/karadul_olcum/runs/urun-yeni2-f30ac9a/` (119 ikili, salt okur). Okunamayanlar: bkz. "Bakamadıklarım".
Özet:
- En ağır üç: (1) BORU-14 — PDB/BN/TRex/DWARF/Rust/Go ad kanalları akışa bağlı değil; ara tüketici adım üreticileriyle aynı paralel düzeyde koşup hiçbir şey görmüyor (deneyle gösterildi). (2) BORU-01 — "eski monolit" diye işaretli ama koşulsuz blok adım kipinde de koşuyor: yapı kurtarma, CFG-iso, füzyon her ikilide iki kez; 119/119 çıktıda `rewritten_files` dosya sayısının tam 2 katı, istatistikler ikinci koşunun değeri. (3) BORU-05 — `reconstruct` başarısı "en az bir yapıt var mı" ölçütüyle fiilen hep True; proje kurulamasa da OK.
- Ayrıca: CFG-iso → füzyon çıktısını okuyan yok ve iki kaynağın anahtarları hiç kesişmiyor (BORU-03); parametre adı yayılımı hesaplanıp atılıyor ama sayaç "yayıldı" diyor (BORU-10); aşamadan kaçan her istisna aşamayı 4 kez yeniden koşturuyor (BORU-06); aynı adlı iki hedef aynı saniyede aynı çalışma dizinine yazıyor (BORU-09).
- Bilinen B-C6 (elle adın birleştirme sonrası zorlanması) DURUYOR: zorlama yalnız ölü döngüde.

## BORU-01 — Adım kipinde `stages.py` "eski monolit" bloğu hâlâ koşuyor: yapı kurtarma, CFG-iso ve füzyon her ikilide İKİ KEZ çalışıyor, ikinci yapı kurtarma kendi `originals/` yedeğini girdi sayıyor
- Önem: YÜKSEK
- Tür: hata | sahte/yanlış gösterim
- Yer: `karadul/stages.py:4837-5100` (yorumu "ESKI monolith entegrasyon"; `if not _use_step_registry` korumasız), `karadul/pipeline/steps/struct_recovery.py:57-98`, `karadul/reconstruction/engineering/struct_recovery.py:822,949-970`
- Etkin mi: evet (çağıran: `stages.py:1125 ReconstructionStage.execute → _execute_binary`; `_use_step_registry` `stages.py:3100`'de her zaman True'ya zorlanıyor ama 4837-5100 arasında hiçbir koşul yok)
- Ne: Faz 2 koşucusu `struct_recovery` adımını zaten koşturuyor (`stages.py:3234-3238`) ve sonuç dizinini `decompiled_dir`'e atıyor (`stages.py:3263`). Ardından aynı fonksiyonda, "monolit" diye işaretli ama koşulsuz blok (a) CFG-iso eşlemesini `CFGAnalyzer().analyze(cfg_json)` ile baştan yapıyor (adım `cfg_iso_match` zaten yaptı), (b) log-odds füzyonunu baştan yapıyor (adım `computation_fusion` zaten yaptı), (c) `enable_struct_recovery` (öntanımlı True, `config.py:465`) açıkken `StructRecoveryEngine.recover`'ı bir kez daha, bu kez GİRDİ = ÇIKTI = `reconstructed/struct_recovered` ile çağırıyor. Motor girdiyi `rglob("*.c")` ile topladığı için ilk geçişin `struct_recovered/originals/*.c` yedekleri de girdi oluyor; `originals/` ilk geçişin ÇIKTISIYLA eziliyor (yedek artık özgün değil) ve her dosya iki kez işleniyor. İstatistikler (`cfg_iso_matched_functions`, `computation_fusion_matches/accepted`, `structs_enriched`, `field_access_rewrites`, `timing_struct_recovery`) adımın değerinin üstüne ikinci koşunun değeriyle yazılıyor.
- Kanıt: 119 ikilinin 1.22.1 çıktısında (`~/karadul_olcum/runs/urun-yeni2-f30ac9a/`) `reconstructed/struct_recovered/struct_recovery.json` içindeki `rewritten_files` sayısı 119/119 ikilide dizindeki `.c` sayısının TAM İKİ KATI (örnek debian/tree: 250 `.c`, `rewritten_files: 500`). Aynı ikilinin `pipeline_result.json`'ında `struct_recovery_duration_s = 0.0917` (adım) ama `timing_struct_recovery = 0.3` (ikinci koşunun üstüne yazdığı değer). Kod:
  ```python
  # stages.py:5026 — koşulsuz, adım kipinde de çalışır
  if context.config.binary_reconstruction.enable_struct_recovery and eng_result:
      ...
      struct_result = struct_engine.recover(decompiled_dir=decompiled_dir,  # = struct_recovered
                                            ..., output_dir=struct_dir)    # = struct_recovered
  ```
- Etki: Bugün `field_access_rewrites` 119/119 ikilide 0 olduğu için içerik bozulmuyor; ama alan yeniden yazımı bir gün çalışırsa yeniden yazım İKİ KEZ uygulanır ve `originals/` yedeği özgün kodu kaybeder. Bugün de: büyük ikilide CFG-iso + füzyon + yapı kurtarma iki kez ödeniyor; rapordaki yapı/füzyon sayaçları adımın ölçtüğü değil ikinci koşunun değeri; `struct_recovery.json` "500 dosya yeniden yazıldı" diyor (250 dosya var).
- Güven: kesin (119/119 çıktıda 2× sayısı gözlendi; kod yolu baştan sona izlendi)
- Onarım kapsamı: `karadul/stages.py` 4837-5100 bloğunun tamamı silinmeli (adımlar aynı işi yapıyor). Tek tehlike: MaxSMT adaylarını `StructRecoveryEngine`'e ileten TEK yol bu blok (bkz. BORU-04); silinirse `--maxsmt-struct` bütünüyle etkisiz kalır, bilerek karar verilmeli. S.
- Nasıl sınanır: bir ikilide `struct_recovery.json` `rewritten_files == ls struct_recovered/*.c | wc -l`; `originals/` içeriği Faz 2 girdisiyle (`final_decompiled_dir`) bayt bayt aynı; stats'ta `timing_struct_recovery == round(struct_recovery_duration_s,1)` civarı.

## BORU-02 — `originals/` yedeği çıktı dizininin İÇİNE yazılıyor; sonraki adımlar onu kaynak sanıp işliyor, `inline_patterns_detected` iki katı sayılıyor
- Önem: ORTA
- Tür: sahte/yanlış gösterim | hata
- Yer: `karadul/reconstruction/engineering/struct_recovery.py:949-961`, `karadul/pipeline/steps/inline_detection.py:55-87`, `karadul/pipeline/steps/_capa_comment_inject.py:88`
- Etkin mi: evet (Faz 3'ün ilk adımı `inline_detection`, tohumu `final_decompiled_dir = struct_recovered`, `stages.py:5122`)
- Ne: `StructRecoveryEngine` özgün dosyaları `output_dir/originals/` altına yedekliyor; çıktı dizini (`struct_recovered`) sonraki aşamaların KAYNAK dizini oluyor. `inline_detection` (ve CAPA yorum enjeksiyonu) kaynakları `rglob("*.c")` ile topladığından `originals/*.c`'yi de işliyor: yedeklere `/* INLINE: ... */` yorumu yazılıyor ve bulunan desenler iki kez sayılıyor. BORU-01'deki ikinci yapı kurtarmanın 2× dosya işlemesi de aynı kökten.
- Kanıt: debian/tree koşusu: `struct_recovered/*.c` içinde 2 `/* INLINE:` yorumu, `struct_recovered/originals/*.c` içinde 2, nihai `out/src` içinde 2; stats `inline_patterns_detected = 4`. 119 ikilinin 47'sinde `struct_recovered` ve `originals` aynı sayıda INLINE yorumu taşıyor (yedekler değiştirilmiş).
- Etki: Raporda inline desen sayısı gerçeğin 2 katı; "özgün" diye saklanan yedek özgün değil.
- Güven: kesin (sayım çıktı üzerinde yapıldı)
- Onarım kapsamı: yedek dizinini kaynak ağacın dışına al (ör. `reconstructed/struct_recovered_originals/`) ya da `rglob` yerine `glob` kullan; `struct_recovery.py` + belki `inline_detection.py`. S.
- Nasıl sınanır: tree benzeri küçük ikilide `inline_patterns_detected` == nihai `src` içindeki `/* INLINE:` sayısı.

## BORU-03 — CFG-iso → füzyon zincirinin çıktısını hiçbir adım okumuyor; üstelik iki kaynağın anahtarları hiç kesişmiyor
- Önem: ORTA
- Tür: hiç çalışmayan özellik (ölü çıktı) | tutarsızlık
- Yer: `karadul/pipeline/steps/computation_fusion.py:69-153`, `karadul/pipeline/steps/cfg_iso_match.py:131-140`, `karadul/stages.py:4997-5020`
- Etkin mi: evet (`enable_cfg_iso` öntanımlı True `config.py:702`; füzyon öntanımlı açık — stats'ta her koşuda `computation_fusion_matches` var)
- Ne: (1) `computation_fusion` adımının ürettiği `fused_matches` yapıtını depoda hiçbir adım/modül `requires` etmiyor ya da okumuyor (grep: yalnız kendi dosyası ve testleri). Kabul edilen bir füzyon adı ada dönüşemez. (2) Füzyonun tek amacı iki kaynağı birleştirmek; ama `sig_matches` fonksiyon ADINA göre (`original_name`, ör. `getcwd`, `FUN_...`), `cfg_iso_matches` ADRESE göre (`fn.address`, ör. `00103c98`) anahtarlanıyor. Anahtar kümeleri hiç kesişmez; her aday tek kaynaklı kalır. (3) `stages.py:5001-5020`'deki "monolit" enjeksiyonu kabul edilen adları `extracted_names`'e Faz 2 adlandırması BİTTİKTEN sonra yazıyor; Faz 3 tohumunda (`stages.py:5113-5150`) `extracted_names` yok, yani enjekte edilen ad hiçbir yere ulaşmıyor ama `computation_fusion_injected` sayacı "enjekte edildi" der.
- Kanıt: `grep -rn "fused_matches" karadul/` → yalnız `computation_fusion.py`; `ghidra_cfg.json` ilk kayıt `address: 00103c98`; `signature_matches.json` kayıtları `original: getcwd` biçiminde. Bilinen B-C3 (CFG-iso 0/14 376, füzyon 0/3 106 kabul) bu kusurun görünen yüzü olabilir: kesişme olmadığı için füzyon hiçbir zaman çift kanıt görmüyor.
- Etki: Her ikilide CFG-iso (debian/tree'de 0,78 sn; büyük ikilide fonksiyon sayısıyla büyür) ve füzyon boşa koşuyor; rapordaki "computation fusion" sayıları analistin adlarına hiçbir katkı yapmayan bir hattın sayıları. Arayüz bu sayıyı analiste gerekçe olarak gösteriyor: `ui/server.py:741-746` "hesaplama füzyonu hiçbir fonksiyona isim veremedi (N aday üretildi, hiçbiri güven eşiğini geçemedi)" — eşiği geçen olsa bile ad veremeyeceği için gerekçe yanlış.
- Güven: yüksek (kod ve gerçek çıktı anahtarları karşılaştırıldı; adın tüketilmediği grep ile)
- Onarım kapsamı: karar gerekli — ya zinciri kapat (öntanımlı False) ya da adres↔ad eşlemesini `functions_data` üzerinden kurup `fused_matches`'i Faz 2 aday kanalına (`extracted_names` öncesi) bağla. M.
- Nasıl sınanır: kesişen anahtar sayısını stats'a yaz (`fusion_two_source_keys`); kabul edilen bir füzyon adının `naming_map.json`'da göründüğü bir birim testi.

## BORU-04 — `--maxsmt-struct` açıkken MaxSMT çözücüsü iki kez koşuyor; adımın ürettiği adayları hiçbir adım okumuyor, yapı motoruna yalnız "monolit" kopya iletiyor
- Önem: DÜŞÜK
- Tür: ölü çıktı | tutarsızlık
- Yer: `karadul/pipeline/steps/computation_struct_recovery.py` (üretir: `recovered_struct_candidates`, `computation_struct_result`), `karadul/pipeline/steps/struct_recovery.py:21-31` (bunları `requires` etmiyor), `karadul/stages.py:4957-4995, 5046-5072`
- Etkin mi: bayrak arkasında (`computation.enable_computation_struct_recovery` öntanımlı False, `karadul/computation/config.py:51`; CLI `--maxsmt-struct`)
- Ne: Faz 2'de `computation_struct_recovery` adımı `feedback_loop` ile AYNI düzeyde (paralel) koşuyor ve adaylarını `recovered_struct_candidates` yapıtına yazıyor; `struct_recovery` adımı bu yapıtı istemiyor, depoda okuyan yok (grep boş). `stages.py:3231-3233` yorumu "MaxSMT adaylarını StructRecoveryEngine'e candidate olarak geçmeli" diyor; bu iş yalnız BORU-01'deki koşulsuz kopyada, çözücü İKİNCİ KEZ koşturularak (her biri `struct_solver_timeout = 60` sn'ye kadar) yapılıyor.
- Kanıt: `grep -rn "recovered_struct_candidates" karadul/` → yalnız üreten dosya. Gerçek düzen: `[['computation_struct_recovery', 'feedback_loop'], ['struct_recovery']]` (koşucunun `_topological_levels` çıktısı, bu oturumda hesaplandı).
- Etki: Bayrak açan analist en çok 2 dk fazladan bekler; BORU-01'in kopyası silinirse özellik sessizce bütünüyle etkisizleşir.
- Güven: yüksek
- Onarım kapsamı: `struct_recovery` adımına `recovered_struct_candidates`'i opsiyonel girdi olarak ekle, kopyayı sil. S.
- Nasıl sınanır: bayrak açıkken çözücünün tek kez çağrıldığını sayan birim testi; aday yapının `struct_recovery.json`'da göründüğü test.

## BORU-05 — `reconstruct` aşamasının "başarılı" bayrağı fiilen hep True: ölçüt "en az bir yapıt var mı", hata listesi ve proje kurulumunun sonucu hesaba girmiyor
- Önem: YÜKSEK
- Tür: sahte/yanlış gösterim
- Yer: `karadul/stages.py:5192`, `karadul/pipeline/steps/finalize.py:65`, `karadul/pipeline/steps/anti_debug.py:137-149`, `karadul/pipeline/steps/project_build.py:83-100`
- Etkin mi: evet (her native ikili)
- Ne: Faz 3 sonrası `_stage_result.success = len(_stage_result.artifacts) > 0`; yapıtlar Faz 1/2/3'ün birleşimi. `anti_debug` adımı bulgu olsun olmasın `static/anti_debug_findings.json`'u yazıp yapıt olarak kaydediyor; dolayısıyla Faz 1 geçildiği anda aşama başarılı sayılır. `project_build` kurulum başarısız olsa da `project_dir` yolunu döndürüyor (yapıt kaydetmeden) ve hata yalnız `errors`'a gidiyor; adlandırma (`feedback_loop`), anlamsal adlandırma, yapı kurtarma hataları da yalnız `errors`'a ekleniyor. Sonuç: proje kurulamamış, adlandırma çökmüş bir koşu `reconstruct: OK`, `PipelineResult.success = True` olarak görünür; CLI tablosu yeşil çerçeve çizer (`cli.py:862`).
- Kanıt:
  ```python
  # stages.py:5189-5192
  _stage_result.stats = {**stats, **_stage_result.stats}
  _stage_result.errors = errors + _stage_result.errors
  _stage_result.artifacts = {**artifacts, **_stage_result.artifacts}
  _stage_result.success = len(_stage_result.artifacts) > 0
  ```
- Etki: Analist ya da toplu çalıştırma (`batch.py` başarı sayımı) yarım çıktıyı tam sanır; ölçüm koşuları "başarılı" ikilileri sayarken boş/yarım projeleri ayıklayamaz.
- Güven: yüksek (kod izlendi; anti_debug yapıtının koşulsuz yazıldığı görüldü)
- Onarım kapsamı: başarı ölçütünü "proje kuruldu (`project_dir` yapıtı var) VE adlandırma adımı hatasız" olarak tanımla; kısmi durum için `success=True` + `stats["partial"]=True` ya da ayrı bir `degraded` alanı. `stages.py`, `finalize.py`; raporun bu alanı göstermesi ayrı iş. S-M.
- Nasıl sınanır: `CProjectBuilder.build` başarısız dönecek biçimde yamalanmış koşuda `reconstruct.success is False` (ya da `partial`); hatasız koşuda True.

## BORU-06 — Aşama içinden kaçan HER istisna aşamayı baştan 4 kez koşturuyor (belirlenimci hatalar dahil); adım koşucusu tekli düzeyde özgün istisnayı yükseltiyor, `except RuntimeError` bunu yakalamıyor
- Önem: ORTA
- Tür: hata | kaynak
- Yer: `karadul/core/pipeline.py:432-451` (`self._recovery.execute(stage.execute, ...)`), `karadul/core/error_recovery.py:265-298`, `karadul/config.py:282` (`max_retries = 3`), `karadul/pipeline/runner.py:136-142`, `karadul/stages.py:3153, 3244, 5176`
- Etkin mi: evet (her aşama `ErrorRecovery` ile sarılı)
- Ne: `Pipeline._execute_stage` aşamayı devre kesici + yeniden deneme ile çağırıyor: istisna türüne bakmadan (`except Exception`) 1, 2, 4 sn bekleyip aşamayı BAŞTAN koşturuyor. Yeniden deneme ağ/geçici hatalar için anlamlı; burada belirlenimci bir kod hatası (KeyError, TypeError) 4 kez aynı uzun işi (statik aşamada Ghidra, reconstruct'ta bütün adlandırma döngüsü) tekrarlatıyor, her deneme aynı çalışma dizinine yarım yazılmış dosyaların üstüne yazıyor ve `context.metadata`'yı önceki denemenin bıraktığı durumla görüyor. Ayrıca `PipelineRunner._execute_step` (tekli düzey / sıralı kip) adım istisnasını özgün türüyle yeniden fırlatıyor; `stages.py`'deki üç `except RuntimeError` yalnız paralel düzeyin sardığı RuntimeError'ı yakalıyor, yani tekli düzeydeki bir adımın KeyError'ı (Faz 1'de `binary_prep`; Faz 3'te `flow_simplify`, `comment_generation`, `capa_annotation`, `engineering_annotation`, `engineering_analysis`, `finalize`) aşamadan kaçıp 4 kat yeniden denemeye düşüyor.
- Kanıt: bu oturumda çalıştırıldı — KeyError fırlatan sahte bir `static` aşaması:
  ```
  stage cagri sayisi: 4 success: False max_retries(default): 3 base_delay(default): 1.0
  ```
- Etki: Büyük ikilide belirlenimci bir hata 4 × (Ghidra / adlandırma süresi) sonra görünür; kullanıcı arada "asıldı" sanar. Yeniden denemelerde yarım dosyalar üstüne yazılır.
- Güven: kesin (deneme çıktısı); adım istisnasının kaçış yolu kod okumasıyla yüksek
- Onarım kapsamı: aşama düzeyinde yeniden denemeyi kaldır (ya da yalnız `OSError`/`TimeoutError` gibi geçici türlerle sınırla); runner'da adım istisnasını her iki kipte de aynı türle (ör. `StepFailedError(RuntimeError)`) sar. `core/pipeline.py`, `pipeline/runner.py`. S.
- Nasıl sınanır: KeyError fırlatan aşama tek kez çağrılmalı; tekli düzeyde KeyError fırlatan sahte adımda `reconstruct` `success=False` ve hata iletisiyle dönmeli, aşama yeniden koşmamalı.

## BORU-07 — `karadul batch analyze`: her hedef "BAŞARILI" sayılıyor, kullanıcı ayarı okunmuyor, tek bir işçi sürecinin çökmesi bütün partiyi düşürüyor
- Önem: ORTA
- Tür: sahte/yanlış gösterim | okunmayan ayar | kaynak
- Yer: `karadul/batch.py:203-225`, `karadul/batch.py:298-315`, `karadul/cli.py:1344-1395`
- Etkin mi: evet (`karadul batch analyze` komutu, `cli.py:1344`)
- Ne: (1) `result.success = pipeline_result.success or any(sr.success for sr in stages)`; `identify` aşaması koşulsuz `success=True` döndüğü için (`stages.py:173-180`) pipeline çalıştığı sürece her hedef BAŞARILI basılır — statik aşama Ghidra'sız düşse bile. (2) `cfg = Config()` ile öntanımlı ayar kuruluyor; `Config.load()` (kullanıcının YAML'ı) hiç çağrılmıyor ve komutun `--config` seçeneği yok; `analyze`'daki bütün bayraklar (ağ, compute, overrides) burada yok. (3) `ProcessPoolExecutor`: bir işçi süreci sert biçimde ölürse (yerel modülde SIGSEGV, bellek yetmezliği) havuz `BrokenProcessPool` olur ve henüz bitmemiş BÜTÜN hedefler "Worker hatasi" ile düşer — bir ikilinin hatası öbürlerini etkiler. (4) Hedef listesi geliştiricinin makinesine ait sabit yollar (`/Applications/Discord.app/...`, `/Users/apple/.local/bin/claude`); keyfi dosya verilemiyor, yani komut ürünün parçası gibi duruyor ama yalnız geliştirici aracı.
- Kanıt:
  ```python
  # batch.py:223
  result.success = pipeline_result.success or any(
      sr.success for sr in pipeline_result.stages.values()
  )
  ```
- Etki: Toplu çalıştırma özeti başarısız analizleri yeşil "OK" gösterir; analist hangi hedefin eksik çıktığını bilemez.
- Güven: yüksek (kod izlendi; `identify`'nın koşulsuz başarısı görüldü)
- Onarım kapsamı: başarı = `pipeline_result.success`; `Config.load()` + `--config`; havuz kırılınca kalan hedefleri yeni havuzla yeniden kuyrukla ya da her hedefi ayrı alt süreçte koştur. `batch.py`, `cli.py`. S-M.
- Nasıl sınanır: statik aşaması düşen sahte hedefte satır `FAIL`; `os._exit` yapan sahte işçide yalnız o hedef düşer.

## BORU-08 — `.app` paketinde ana bileşen bir JAR ise reconstruct "Bilinmeyen bilesen tipi" ile düşüyor (JAR'ın kendi hattı varken)
- Önem: ORTA
- Tür: hata (yanlış yönlendirme)
- Yer: `karadul/stages.py:1239-1267`, `karadul/analyzers/app_bundle.py:69-75` (ana bileşen = en çok fonksiyonlu başarılı bileşen), `karadul/core/target.py:267-270` (bileşen türü `java_jar`)
- Etkin mi: evet (APP_BUNDLE hedefi, `stages.py:1097`)
- Ne: Paket bileşenleri `macho_binary`, `java_jar`, `electron_app` türünde üretiliyor; ana bileşen fonksiyon sayısına göre seçiliyor, türüne bakılmıyor. `_execute_app_bundle` yalnız `macho/universal/elf/pe`, `go_binary`, `electron_app/js_bundle` dallarını tanıyor; `java_jar` (ve olası `bun/delphi/python_packed`) `else` dalına düşüp `errors.append("Bilinmeyen bilesen tipi: ...")` ile `success=False` dönüyor. Oysa aynı sınıfta JAR için `_execute_analyzer_reconstruct` var ve `build_component_target` `java_jar → TargetType.JAVA_JAR` eşlemesini zaten yapıyor (`app_bundle.py:111,184`). Java tabanlı bir macOS uygulamasında (küçük başlatıcı + büyük JAR) JAR'ın metot sayısı başlatıcıyı geçer ve reconstruct tamamen boş kalır.
- Kanıt:
  ```python
  # stages.py:1260-1267
  elif main_type in ("electron_app", "js_bundle"):
      ...
  else:
      errors.append(f"Bilinmeyen bilesen tipi: {main_type}")
  ```
- Etki: Java tabanlı `.app` için rapor "reconstruct başarısız" der; analiste kaynak ağacı gelmez.
- Güven: yüksek (kod izlendi; gerçek bir Java `.app` ile denenmedi — JAR'ın ana bileşen seçildiği koşul varsayım)
- Onarım kapsamı: `else`'den önce `java_jar`/`android_apk`/`dotnet_assembly`/`python_packed` için `_execute_analyzer_reconstruct(comp_context, start)` dalı. `stages.py`. S.
- Nasıl sınanır: `component_results`'ında tek başarılı bileşen `java_jar` olan sahte `bundle_analysis.json` ile `reconstruct` analizör yoluna gitmeli.

## BORU-09 — Çalışma dizini saniye çözünürlüklü ve `exist_ok=True`: aynı adlı iki hedef aynı saniyede başlarsa AYNI dizine yazıyor
- Önem: ORTA
- Tür: hata | veri kaybı (eşzamanlılık)
- Yer: `karadul/core/workspace.py:56-62, 84`; tetikleyen: `karadul/batch.py:28-51, 289-302` (3 paralel işçi)
- Etkin mi: evet (her `Pipeline.run`, `core/pipeline.py:271-275`)
- Ne: Üst çalışma dizini `base/<hedef_adı>/<YYYYmmdd_HHMMSS>`; hedef adı dosyanın kökü (yol değil), oluşturma `mkdir(exist_ok=True)`. Farklı yollardaki aynı adlı iki hedef (ör. `a/main.js` ile `b/main.js`; Debian ve Mac `htop`) aynı saniyede başlarsa ikisi tek dizini paylaşır ve birbirinin `static/`, `reconstructed/`, `reports/` dosyalarını sessizce ezer. `batch.py`'nin `cursor` grubundaki 8 hedefin 7'si `.../dist/main.js` ya da `.../out/main.js` → hepsinin adı `main`; 3 işçi aynı anda başlattığı için çakışma beklenir. Alt çalışma dizinleri için (`create_sub_workspace`) atomik `mkdir` + `_2` eki çözümü zaten yazılmış; üst dizinde yok.
- Kanıt: bu oturumda çalıştırıldı:
  ```
  ad1 main ad2 main
  ayni dizin: True 20261118_052907
  ```
- Etki: Toplu çalıştırmada ya da arayüzden ardışık iki analizde bir hedefin raporu öbürünün çıktısını taşıyabilir; analist yanlış ikilinin adlarını görür.
- Güven: kesin (çakışma gösterildi; batch'te gerçek bir yarış denenmedi)
- Onarım kapsamı: üst dizini de atomik `mkdir` + ek (ya da mikro saniye / kısa uuid) ile oluştur. `workspace.py`. S.
- Nasıl sınanır: aynı ad + aynı zaman damgasıyla iki `Workspace.create()` farklı yol döndürmeli.

## BORU-10 — Fonksiyonlar arası parametre adı yayılımı hesaplanıp ATILIYOR; `param_names_propagated` sayacı hiçbir koda yansımayan adları "yayıldı" diye sayıyor
- Önem: ORTA
- Tür: sahte/yanlış gösterim | ölü çıktı
- Yer: `karadul/pipeline/steps/_deep_tracing_helpers.py:137-168`, `karadul/reconstruction/engineering/data_flow.py:873-1096`, çağıran `karadul/pipeline/steps/deep_tracing.py:97-105`
- Etkin mi: evet (`enable_engineering_analysis` açıkken; debian/tree koşusunda `param_names_propagated = 4`)
- Ne: `InterProceduralDataFlow.propagate_param_names` dosyaya yazmıyor, `list[PropagatedParamName]` döndürüyor. Yardımcı bu listenin yalnız uzunluğunu `stats["param_names_propagated"]`'e yazıyor ve listeyi atıyor; hiçbir adım bu adları kaynağa uygulamıyor, `naming_map`'e ya da rapora taşımıyor. Üstelik `deep_tracing` adımı `project_build` ile aynı düzeyde (paralel) koşuyor, yani uygulasaydı bile proje kurulduktan sonra ya da onunla yarışarak uygulayacaktı.
- Kanıt:
  ```python
  # _deep_tracing_helpers.py:150-160
  param_prop_result = param_prop_analyzer.propagate_param_names(...)
  if param_prop_result:
      stats["param_names_propagated"] = len(param_prop_result)
      logger.info("Param name propagation: %d isim yayildi", len(param_prop_result))
  ```
  `data_flow.py:873-1096` aralığında `write`/`open(` yok (grep boş).
- Etki: Günlük ve istatistik "N isim yayıldı" der; analistin kodunda bu adlar yoktur. Kaynak kod çıktısıyla sayaç birbirini tutmaz.
- Güven: yüksek
- Onarım kapsamı: ya sayacı `param_names_propagation_candidates` diye adlandırıp "uygulanmadı" etiketi koy, ya da adayları Faz 2 adlandırma kanalına (doğruluk ölçümüyle) bağla — ikincisi ad doğruluğunu etkiler, ölçümsüz açılmamalı. S (etiket) / L (bağlama).
- Nasıl sınanır: sayaç > 0 olan bir koşuda adayların ya çıktı kodunda göründüğü ya da istatistik adının "aday" olduğu.

## BORU-11 — Adım listesindeki sıra yok sayılıyor; Faz 3'te `inline_detection` aynı dizini yerinde yazarken `semantic_naming` paralel olarak okuyor, `inline_detection` da yapı kurtarma ÖNCESİ önbellekle dosyaların üstüne yazıyor
- Önem: ORTA
- Tür: belirlenimsizlik | hata (gizli)
- Yer: `karadul/pipeline/runner.py:68, 105-120, 298-368` (düzey içi alfabetik sıra + `parallel_steps`), `karadul/config.py:743` (`parallel_steps: bool = True`), `karadul/pipeline/steps/inline_detection.py:55-73`, `karadul/pipeline/steps/semantic_naming.py:42,67`, `karadul/stages.py:5113-5122, 5163-5174`
- Etkin mi: evet (öntanımlı paralel)
- Ne: `PipelineRunner` adımları verilen listeye göre değil `requires/produces` grafiğine göre düzeylere ayırıyor; düzey içi sıra alfabetik ve `parallel_steps=True` iken aynı düzeydeki adımlar iş parçacıklarında EŞZAMANLI koşuyor. `stages.py`'deki listeler ve yorumlar ("bsim_match byte_pattern oncesi", "computation_struct_recovery feedback_loop'tan sonra") gerçek sırayı belirlemiyor. Bu oturumda hesaplanan gerçek düzenler: Faz 2 `[[computation_struct_recovery, feedback_loop], [struct_recovery]]`; Faz 3 `[[inline_detection, semantic_naming], [flow_simplify], …, [deep_tracing, project_build], [engineering_analysis], [finalize]]`. (a) `inline_detection` girdisi `final_decompiled_dir` ile `semantic_naming` girdisi `decompiled_dir` aynı dizine (`struct_recovered`) tohumlanıyor; birincisi dosyaları `write_text` ile YERİNDE yeniden yazarken ikincisi aynı dosyaları okuyup `semantic_named/`'e kopyalıyor — INLINE yorumlarının `semantic_named`'e geçip geçmemesi (ya da yarım okunmuş dosya) iş parçacığı zamanlamasına bağlı. (b) `inline_detection` içeriği diskten değil `file_cache`'ten alıyor (`file_cache.get(name) or read_text`); bu önbellek `feedback_loop` sonunda `final_decompiled_dir`'den, yani yapı kurtarmadan ÖNCE dolduruluyor (`feedback_loop.py:245-252`). INLINE deseni bulunan dosyada yapı kurtarmanın yeniden yazdığı içerik eski önbellek içeriğiyle eziliyor. (c) `deep_tracing` ile `project_build` aynı düzeyde paralel.
- Kanıt: düzenler `PipelineRunner._topological_levels` ile hesaplandı (bu oturum). 119 ikilide gözlem: INLINE yorumu olan 47 ikilinin 47'sinde `struct_recovered` ve `semantic_named` aynı sayıda yorum taşıyor — yani bugünkü çıktıda yarış gözlenmedi; (b) bugün görünmüyor çünkü `field_access_rewrites` 119/119'da 0.
- Etki: Büyük ikilide ve yük altında çıktı koşudan koşuya değişebilir (belirlenimcilik ölçüm şartı); alan yeniden yazımı bir gün çalışırsa INLINE'lı dosyalarda sessizce geri alınır.
- Güven: yüksek (yapı ve veri akışı); etkinin bugün gözlendiği: hayır
- Onarım kapsamı: `inline_detection` kendi çıktı dizinine yazsın ve `semantic_naming` onun ürettiği yapıtı `requires` etsin (zincir sıralı olsun); önbellek yerine diskten okusun ya da `struct_recovery` sonrası önbelleği tazelesin. `inline_detection.py`, `semantic_naming.py`, `stages.py` tohumu. S-M.
- Nasıl sınanır: `parallel_steps=True` ve `False` ile aynı ikilide `out/src` bayt bayt aynı; `semantic_named` içindeki INLINE sayısı `inline_patterns_detected` (BORU-02 düzeltilmiş hâli) ile eşit.

## BORU-12 — `stages.py` ölü kod haritası: ~2 750 satır hiç çalışmıyor ama hâlâ bakımı yapılıp testle sınanıyor (son örnek 2026-11-12)
- Önem: ORTA
- Tür: ölü kod | test boşluğu (yanlış yere yatırım)
- Yer ve durum (`karadul analyze` ile bir native ikili; `use_step_registry` `stages.py:3100`'de her zaman True'ya zorlanıyor):
  - ÖLÜ: `stages.py:1397-2547` — `_load_binary`, `_run_signature_matching`, `_run_byte_pattern_matching`, `_run_anti_debug_and_packer`, `_run_pcode_analysis`, `_run_cfg_analysis`, `_run_algorithm_engineering` → `_run_parallel_analysis`, `_merge_analysis_results`, `_calibrate_and_clamp` → `_run_confidence_calibration`, `_write_merged_algorithms`, `_apply_match_budget`, `_apply_capa_naming`; modül düzeyinde `stages.py:100-133` (`_match_budget_total`, `_collect_tagged_matches`, `_match_budget_sort_key`, yalnız `_apply_match_budget` kullanıyor). Tek çağıranları `stages.py:3280-3337`'deki `else` dalı (ulaşılamaz).
  - ÖLÜ: `stages.py:3363-3450` (assembly `else`), `stages.py:3569-4823` (döngü `range(0)` — `_loop_iterations = 0 if _use_step_registry else ...`, `stages.py:3568`), `stages.py:4828-4835`, `stages.py:5195-5212` (ulaşılamaz `raise`).
  - ÇALIŞIYOR AMA İŞE YARAMIYOR: `stages.py:3462-3559` (sıfır turluk döngü için çağrı grafiği komşuluk dizini kuruluyor, `rglob` yapılıyor, `CVariableNamer`/`CTypeRecoverer` örnekleniyor; maliyet küçük).
  - ÇALIŞIYOR, KOPYA: `stages.py:4837-5100` (BORU-01).
  - ETKİN ÇEKİRDEK: `stages.py:3060-3279` (Faz 1/2 koşucuları), `3339-3350`, `5107-5193` (Faz 3).
- Ne: Ölü monolit sınanmaya ve düzeltilmeye devam ediyor: 2026-11-12'deki `86683e9` (imza kaydına adres) ve `e5b5259` (imza kaydına yöntem) düzeltmeleri ölü `_run_signature_matching`'e de yapıldı; `tests/test_cikti_hatalari.py:121-138, 305-321` ("monolit yolu ... eşlik testi"), `tests/test_stages_split_parity.py`, `tests/test_stages_calibrate_split.py`, `tests/test_stages_algorithm_engineering_split.py` yalnız bu ölü metotları çağırıyor. `tests/test_manual_overrides.py:225-226` yorumu "çağıran bu map'i merge SONRASI final_naming_map'e koşulsuz zorlar" diyor; bunu yapan tek yer ölü döngüde (`stages.py:4322-4327`, bkz. B-C6).
- Kanıt: `grep -rn "<metot_adı>" karadul/` her biri için yalnız ölü daldan çağrı; `git log -L1621,1678:karadul/stages.py` → `86683e9`, `e5b5259` (2026-11-12).
- Etki: Testler yeşil ama sınadıkları kod üründe koşmuyor; aynı düzeltme iki yere yapılıyor; okuyan ajan/insan ölü kodu etkin sanıp yanlış yere düzeltme yapıyor (BORU-01 bunun sonucu: "monolit" etiketli blok aslında etkin).
- Güven: kesin (çağıranlar grep ile; döngü sayısı kodda sabit 0)
- Onarım kapsamı: listelenen ölü aralıkları ve yalnız onları sınayan testleri sil; `_seed_recovery_pre_names` ve `_recover_*` etkin olduğu için kalır. `stages.py` + 4 test dosyası. M (silme büyük ama mekanik; §19 gereği onay ister).
- Nasıl sınanır: silme sonrası tam takım; 1-2 ikilide `out/` bayt bayt aynı.

## BORU-13 — Okunmayan ayarlar ve etkisiz CLI bayrakları (bu kulvarın akışı açısından)
- Önem: DÜŞÜK
- Tür: okunmayan ayar | sahte/yanlış gösterim (bayrak)
- Yer: `karadul/config.py:487, 558-559, 684, 723, 624-634, 742`; `karadul/cli.py:655-656, 694-715, 788-789`
- Etkin mi: ayar düzeyinde evet (her koşu)
- Ne: Depoda `config.py` dışında hiç okunmayan alanlar (bu oturumda `grep -rlw` ile, ölü aralıklar ayrıca elendi): `BinaryReconstructionConfig.function_id_db_paths`, `.max_decompile_timeout_per_func` (bilinen B-C2), `.enable_rtti_recovery`, `.rtti_abi` (RTTI kurtarma analiz akışına bağlı değil; yalnız ayrı `karadul rtti` komutu var, `cli.py:1962`); `ComputationRecoveryConfig.formula_min_complexity`, `.cfg_iso_vf2_node_cap`; `DeepTraceConfig`'in bütün alanları (bilinen B-C2) — `--deep` dört `deep_trace.enable_*` alanını True yapıyor (`cli.py:711-714`) ama hiçbirini okuyan yok ve zaten öntanımlı True; derin izleme yalnız `binary_reconstruction.enable_engineering_analysis` ile açılıp kapanıyor (`deep_tracing.py:67`). `--experimental-step-registry` (`cli.py:655`) öntanımlı True olan alanı True yapıyor, False yolu zaten zorla kapatılmış — bayrak etkisiz ama yardım metni "eski monolith yerine yeni yolu kullan" diyor. `PipelineContext.extra["is_large_binary"]` (`core/pipeline.py:286`) yazılıyor, okuyan yok.
- Kanıt: `grep -rnw enable_rtti_recovery karadul ui --include=*.py` → yalnız `config.py:558` ve bir test varsayılan değer denetimi.
- Etki: YAML'da `enable_rtti_recovery: true` yazan ya da `--deep` veren kullanıcı bir şey açıldığını sanır; hiçbir şey değişmez.
- Güven: yüksek (grep)
- Onarım kapsamı: alanları sil ya da bağla; `--deep`/`--experimental-step-registry` yardım metnini düzelt ya da bayrağı kaldır. `config.py`, `cli.py`. S.
- Nasıl sınanır: her alan için en az bir okuyucu ya da alanın yokluğu; `--deep` ile `--no-deep` arasında gözlenebilir fark (ya da bayrağın yokluğu).

## BORU-14 — PDB, BinaryNinja, TRex, DWARF, Rust ve Go ad kanalları akışa BAĞLI DEĞİL: ad birleştiricisi bu girdiler olmadan çağrılıyor, ara tüketici adım üreticileriyle aynı paralel düzeyde koşup hiçbir şey görmüyor
- Önem: YÜKSEK
- Tür: hiç çalışmayan özellik | tutarsızlık (adım sözleşmesi)
- Yer: `karadul/pipeline/steps/_feedback_naming_merger.py:129-146` (tek çağıran), `karadul/pipeline/steps/_feedback_naming_candidates.py:37-41, 80-91`, `karadul/pipeline/steps/type_recovery_consumer.py:95-120` (`requires=['binary_for_byte_match']`), `karadul/pipeline/steps/trex_struct_recovery.py:112-126`, `karadul/stages.py:3139-3143`
- Etkin mi: evet (adımlar her koşuda kayıtlı ve koşuyor)
- Ne: (a) `collect_candidates` "2026-05-13 yeni naming kanalları (B8 DWARF, B7 PDB/BN/TRex, B18 Rust/Go)" için `binary_path`, `pdb_symbols`, `bn_functions`, `trex_structs` parametreleri alıyor; depodaki TEK çağıran (`_feedback_naming_merger.py:129`) bunların hiçbirini geçmiyor → `_add_dwarf`, `_add_rust_demangler`, `_add_go_demangler`, `_add_pdb_symbols`, `_add_bn_symbols`, `_add_trex_structs` hiçbir koşuda çağrılmıyor. (b) Bu verileri toplaması gereken `type_recovery_consumer` yalnız `binary_for_byte_match`'i `requires` ediyor, üreticilerini (`pdb_symbol_recovery`, `binaryninja_analysis`, `trex_struct_recovery`) değil; koşucu dördünü aynı düzeye koyuyor ve öntanımlı paralel kipte düzey bitmeden yapıtlar yazılmadığı için tüketici üreticilerin çıktısını HİÇ göremiyor. Ürettiği `consumed_symbols`/`consumed_types`'ı da depoda okuyan yok (grep boş). (c) `trex_struct_recovery` `ghidra_lifted_il_path` yapıtını bekliyor; bunu üreten adım yok ("v1.15.5'te entegre edilecek").
- Kanıt: bu oturumda çalıştırıldı — `pdb_symbol_recovery`'nin `run`'ı sahte bir sembol döndürecek biçimde yamalanıp koşucu iki adımla koşturuldu:
  ```
  parallel_steps= True {'pdb_symbols_gorunuyor_mu': False} status= no-data
  parallel_steps= False {'pdb_symbols_gorunuyor_mu': True} status= active
  ```
  119 ikilinin 1.22.1 çıktısında: `trex_status = no_lifted_il` 119/119, `type_recovery_consumer_status = no-data` 119/119, `bn_status = disabled` 119/119.
- Etki: PDB'si olan bir PE'de PDB adları, hata ayıklama bilgili bir ELF'te DWARF kanalı, Rust/Go ikilisinde çözülmüş adlar ad birleştiricisine hiç ulaşmıyor; analist "PDB symbol recovery" adımının stats'ta koştuğunu (`pdb_status`) görüp adların oradan geldiğini sanabilir. Bu kanalların doğruluğu da hiç ölçülmemiş durumda (hiç çalışmadıkları için).
- Güven: kesin ((b) deneyle); (a) ve (c) yüksek (tek çağıran ve üretici yokluğu grep ile)
- Onarım kapsamı: önce karar — bu kanallar ad doğruluğunu etkiler, ölçümsüz açılmamalı (plan v2 ilkesi). Bağlanacaksa: `type_recovery_consumer`'a üreticileri `requires` ettir (ya da tüketiciyi kaldır), `feedback_loop` tohumuna `pdb_symbols`/`bn_functions`/`trex_structs`/hedef yolu ekle, `run_name_merger` → `collect_candidates`'e geçir. Bağlanmayacaksa adımları ve parametreleri kaldır. `type_recovery_consumer.py`, `feedback_loop.py`, `_feedback_naming_merger.py`, `stages.py`. M.
- Nasıl sınanır: PDB'li küçük bir PE ile (ya da yamalı birim testi) PDB adının `naming_map.json`'a `source=pdb` ile girdiği; `parallel_steps` True/False iki kipte aynı sonuç.

## Küçükler
- Ctrl+C iletisi yalan: "Yarım kalan workspace temizleniyor..." basılıyor ama `ctx.obj["pending_workspace"]`'i set eden yer yok (`cli.py:188-206`; grep yalnız okuyanı buluyor); yarım çalışma dizini kalıyor.
- `core/overrides.py:118-135, 188-193`: depo JSON'u bozuksa `_read` sessizce boş iskelet döndürüyor, ardından `set_name` iskeleti yazıyor → elle verilmiş ÖNCEKİ bütün adlar kaybolur (yalnız elle bozulmuş dosyada; arayüz atomik yazıyor). `overrides` alanı sözlük değilse `TypeError`.
- `--overrides` ile açıkça verilen dosya okunamazsa ya da `overrides` anahtarı yoksa yalnız DEBUG günlüğü; kullanıcı dosyasının uygulanmadığını görmez (`stages.py:3018-3032`; yorum "sessiz kalma" diyor).
- `overrides.set_param` / depodaki `params` alanı: ne arayüz yazıyor ne akış okuyor (grep) — ölü API.
- `karadul/pipeline/steps/_capa_comment_inject.py`, `stages._inject_capa_comments`'ın (`stages.py:5629`) bayt bayt kopyası; hiçbir yerden içe aktarılmıyor (etkin olan `stages.py` sürümü, `capa_annotation.py:48`).
- CLI sonuç tablosu: "Runnable project" hiçbir yerde yazılmayan `runnable_project`'ten → her hedefte NO; "Coverage" hiçbir yerde yazılmayan `coverage_percent`'ten → hep N/A (`cli.py:889-901`).
- `pipeline_iteration_timeout` gerçek bir zaman aşımı değil: tur BİTTİKTEN sonra ölçülüyor, yalnız sonraki turları atlıyor; asılan bir tur kesilmez (`feedback_loop.py:179-191`).
- `filter_stages` bilinmeyen `stop_after`'da sessizce bütün aşamaları döndürüyor (`cli_common.py:150-156`); CLI'da `click.Choice` koruyor, yalnız programatik çağrıda etkili.
- 119 çıktıda her koşuda boş dönen adımlar (iç mantık başka kulvar): `field_access_rewrites` 0/119, `dispatch_resolved` 0/119, `engineering_algorithms_detected` 0/119 ve `engineering_naming_status=no-matches` 119/119, `computation_annotations` 0/119, CAPA hiç koşmamış (`capa_rules_matched` 119/119'da yok, `timing_capa_comments` 0) — ortamda flare-capa yok olabilir.
- (Başka kulvar, gözlem) YARA yerleşik kuralları 119 ikilinin 13'ünde `MPRESS_Packed`, 1'inde `ASPack_Packed`, 2'sinde `Delphi_Compiler` diyor (Debian/Mac GNU araçları; büyük olasılıkla yanlış pozitif); `detected_tech` olarak statik istatistiğe giriyor (`stages.py:309-327`).
- (Şüphe) debian/tree `reconstruct` stats'ında `flirt_signature_sources` anahtarı başka bir koşunun çalışma dizinindeki ikilinin yolu (`.../n1_debian13/.../20261021_092848/raw/tree`); ölçüm kurulumundan mı geliyor ürün davranışı mı, bakılmadı.

## Bilinenlerin durumu
| Kalem | Durum | Kanıt |
|---|---|---|
| B-C1 `stages.py` monolit emekli / ölü kod | duruyor (kapsam daha geniş) | Ölü: `stages.py:100-133`, `1397-2547`, `3280-3337`, `3363-3450`, `3569-4835`, `5195-5212`. "Monolit" diye işaretli `4837-5100` ise ETKİN (BORU-01). Ayrıntı BORU-12. |
| B-C2 okunmayan ayarlar (`max_decompile_timeout_per_func`, `DeepTraceConfig`) | duruyor | `grep -rnw` → yalnız `config.py`; `--deep` `deep_trace.enable_*` yazıyor, okuyan yok (BORU-13). |
| B-C3 CFG-iso 0 eşleşme, füzyon 0 kabul | duruyor; ek kök neden bulundu | 119/119 `cfg_iso_matched_functions=0`, `computation_fusion_accepted=0`. Kabul olsa bile `fused_matches`'i okuyan yok ve sig/CFG anahtarları (ad ↔ adres) kesişmiyor (BORU-03). |
| B-C6 elle adın birleştirme sonrası yeniden uygulanması | duruyor | `_manual_overrides_map` (`stages.py:3347`) yalnız ölü döngüde kullanılıyor (`stages.py:4322-4327`). Etkin yolda bindiff/refdiff `extracted_names.update(...)` koşulsuz (`_feedback_naming_bindiff.py:69`, `_feedback_naming_refdiff.py:75`), birleştiricide (`_feedback_naming_merger.py`) elle ad/künye koruması yok (grep `meta|KIND_|manual` boş). Tohum aşaması (c_namer künyesi `PROTECTED_KINDS`) çalışıyor. `tests/test_manual_overrides.py:225-226` yorumu ölü davranışı anlatıyor. |
| B-C8 akış sadeleştirme öntanımlı kapalı | duruyor | `config.py:481 enable_flow_simplification = False`; 119/119 `flow_gotos_eliminated=0`. |
| B-C9 yerleşim bayrağı kapalı | duruyor | `config.py:590 enable_address_placement = False`. |
| B-B6 rapor `static/signature_matches.json`'u okuyor | duruyor | Adım `reconstructed/signature_matches.json` yazıyor (`ghidra_metadata.py:219-221`; çıktıda `static/` altında yok), rapor `static`'ten okuyor (`html_report.py:570`), yedek yol `static` stats'ında liste arıyor ama orada yok. Kayıtta `family/category/tier` alanı da yok → IOC bölümü dosya bulunsa da dolmaz. |
| B-C4, B-C5, B-C7 | bakılmadı | Kulvar dışı (`macho.py`, Ghidra betikleri, `data_flow.py`). |

## Bakamadıklarım
- `ReconstructionStage._execute_js` (`stages.py:5214-5532`) ve JS/Electron derin hattı satır satır okunmadı; yalnız yönlendirme denetlendi.
- Go/Bun karma yolları (`stages.py:230-305`, `_execute_go_binary`) ve `DynamicAnalysisStage` iç akışı yüzeysel.
- `_feedback_loop_iter.py`, `_feedback_typing*.py`, `_feedback_computation.py`, `_feedback_naming_parallel.py` yalnız çağrı düzeyinde; turlar arası durum taşınmasının (ör. `state.extracted_names` kopyası vs. özgün sözlük) ayrıntısı izlenmedi.
- Faz 1'in paralel düzeyindeki adımların paylaşılan DEĞİŞTİRİLEBİLİR nesnelere (ör. `functions_data`, `file_cache`) eşzamanlı yazıp yazmadığı yalnız yapıt anahtarı düzeyinde tarandı; nesne içi yazım taranmadı.
- `core/chunked_processor.py`, `pipeline/reconstruction_context.py` iç mantığı okunmadı.
- Gerçek doğrulama yapılmayanlar: BORU-08 gerçek bir Java `.app` ile; BORU-11 yarışı büyük ikilide; BORU-14 PDB'li gerçek bir PE ile (yalnız yamalı koşucu deneyi); BORU-07'nin havuz kırılması.

## KULVAR BİTTİ
