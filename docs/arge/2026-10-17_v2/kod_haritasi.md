# Karadul Mac (Mach-O) hattı: kod haritası (plan v2 için)

- **Tarih:** 2026-10-17
- **Taban:** `main` HEAD `b14b62a`. Satır numaraları bu commit'e göredir.
- **Yöntem:** Yalnız okuma. Kod, plan (`2026-10-15_isimlendirme_plani.md`), katalog (`derleyici_sentez.md` §4) ve geliştirme setinin 2026-10-15 koşu çıktıları (`workspaces/2026-10-15_oturum_scratchpad/macho/runs_apple/{htop,tmux}/`) okundu. Karadul hiçbir ikili üzerinde çalıştırılmadı; test çalıştırılmadı; kilitli test setine bakılmadı.
- **İşaretler:** **[T]** = tahmin ya da yalnız koddan çıkarım, ölçülmedi. İşaretsiz her atıf dosyadan doğrulandı.
- **Kısaltmalar:** `hl` = `karadul/ghidra/headless.py`, `st` = `karadul/stages.py`, `cn` = `karadul/reconstruction/c_namer.py`, `steps/` = `karadul/pipeline/steps/`.

## 0. Önce okunacak: v2'yi değiştiren bulgular

1. **htop, Go programı sanılıyor.** `karadul/core/target.py:661` ilk 2 MB içinde `FB FF FF FF 00 00` baytlarını arıyor (Go pclntab sihirli sayısı). htop'ta bu dizi `__TEXT,__const` içinde, dosya ofseti `0x26588`'de geçiyor (geliştirme kopyasında elle doğrulandı). Sonuç: `raw/target_info.json` → `"target_type": "go_binary"`. Mach-O'ya özgü statik adımlar (otool -L, otool -l, lief, BinaryIntelligence; `karadul/analyzers/macho.py:98-383`) htop'ta **hiç koşmadı**. Ghidra'ya "Go hibrit" yolundan girildi (`st:230-280`). Plan §1'deki htop taban sayıları bu yoldan geliyor. tmux doğru tanınıyor (`macho_binary`).
2. **Ad birleştirici, c_namer'ın verdiği adların üstüne yazamıyor.** Birleştiricinin girdi dizini c_namer'ın çıktısı (`reconstructed/src/`). c_namer o dosyalarda `FUN_xxx` literalini zaten değiştirmiş oluyor. AhoReplacer literal eşlediği için başka bir kaynağın aynı fonksiyona önerdiği ad sessizce uygulanmıyor. htop koşusunda `merged/` ile `src/` 790 dosyanın 790'ında birebir aynı. Sonuç: fiilî öncelik `pre_names > c_namer > geri kalan her şey`. **Tarif katmanı c_namer'dan önce, `pre_names` kanalından girmek zorunda.**
3. **Çağrı grafında yalnız `isCall()` var.** Veri referansı (tablodaki fonksiyon işaretçisi) hiçbir yerde toplanmıyor. htop'ta 597 `FUN_`'un 216'sının (%36), tmux'ta 2587'nin 787'sinin (%30) hiç çağıranı yok. Ghidra'nın Mach-O yükleyicisi chained fixup adreslerine işaretçi verisi koyuyor (`MachoProgramBuilder.markupChainedFixups`). Yani tablo bilgisi Ghidra'da hazır, Karadul onu atıyor. M4'ün (TR-4) en ucuz yolu `hl:_extract_xrefs`'e veri referanslarını eklemek.
4. **Analiz öncesi kanca yok, ama eklenebilir.** `hl:247-252` `pyghidra.open_program(..., analyze=True)` çağırıyor; analiz programın açılışında koşuyor. `analyze=False` + tohum/dönmezlik düzeltmesi + `pyghidra.analyze(program)` ile kanca kurulur (§2.3). Ghidra'nın "Mach-O Function Starts" analizörü varsayılan olarak açık. Bu yüzden KS-2'nin Mac'teki asıl getirisi tohum eklemek değil: sınır ölçümü ve yanlış dönmezlik düzeltmesi.
5. **Güven ve statü hattı baştan sona kopuk.** c_namer `pre_names`'e sabit 0,95 veriyor (`cn:1649`). Birleştirici `to_naming_map` ile güveni atıyor (`karadul/reconstruction/name_merger.py:548-553`). `output_formatter` her c_namer adına 1,0 yazıyor (`karadul/core/output_formatter.py:656`). Ayrıca kullanıcıya giden `naming_map.json` birleştiricinin değil, c_namer'ın haritasından kuruluyor (`output_formatter.py:614-660`).
6. **2026-10-14 denetiminin altı hatasının altısı da kodda duruyor** (§8).
7. **Okunabilirlik çıktısı zayıf.** htop `project/` ağacında:
   - `types.h`'de 201 `recovered_struct_*` tanımı var, kaynaklarda bir kez bile kullanılmıyor.
   - `->alan` erişimi 0; `*(T *)(x + 0xNN)` biçiminde 1934 ham ofset erişimi var.
   - Ghidra'nın varsayılan yerel adları (`uVar1`, `local_…` vb.) 3952 kez, `param_N` 1243 kez geçiyor.
   - htop'ta kripto yok, ama kaynaklara 139 "Keccak/SHA-3", 33 "Poly1305", 7 AES, 5 GOST, 1 DES yorumu girmiş.

---

## 1. Uçtan uca Mac hattı

**Giriş.** `karadul analyze <macho>` sırasıyla şu adımlardan geçer:
- `karadul/cli.py:462-548` (`analyze`);
- `TargetDetector.detect` (`karadul/core/target.py`; Mach-O dalı `:463-480`);
- `build_pipeline` (`karadul/cli_common.py:161`);
- aşama sırası `DEFAULT_STAGE_ORDER = identify, static, dynamic, deobfuscate, reconstruct, report` (`karadul/cli_common.py:46-53`);
- `pipeline.run`.

`--output` verilirse sonda `OutputFormatter` temiz bir çıktı dizini kurar (`cli.py:846-880`).

| Aşama | Kod | Ne yapar (Mach-O) | Yazdığı artifact (çalışma alanına göre) |
|---|---|---|---|
| identify | `st:134-180` | Hedef bilgisini kaydeder | `raw/target_info.json` |
| static | `st:183-394` → `MachOAnalyzer.analyze_static` `analyzers/macho.py:98` | Ham kopya; `otool -L`; `otool -l`; `strings`; `nm`; lief (yalnız başlık, segment, bölüm, kütüphane: `macho.py:561-630`); Ghidra (`macho.py:815` → `_run_ghidra_legacy:905` → `hl:156`); BinaryIntelligence; YARA; CAPA (`st:333-380`, Mach-O'da başarısız, §8f) | `raw/<ad>`, `static/dynamic_libraries.json`, `load_commands.txt`, `strings_raw.json`, `symbols.json`, `lief_analysis.json`, `ghidra_{functions,strings,call_graph,decompiled,types,xrefs,pcode,cfg,function_id,bsim,combined_results}.json`, `static/ghidra_output/decompiled/FUN_<adres>.c`, `intelligence_report.json` |
| static (Go yanlış yönü) | `st:230-280` | `GoBinaryAnalyzer.analyze_static` + yalnız `MachOAnalyzer._run_ghidra`. otool/lief/BinaryIntelligence koşmaz. `success` alanına sembol listesi düşüyor (`analyzers/go_binary.py:277-283`; `pipeline_result.json`'da görüldü) | `static/symbols.json`, `strings_raw.json`, `ghidra_*.json` |
| dynamic | `st:479-698` | Frida. Geliştirme koşularında atlandı (`pipeline_result.json`'da yok) | — |
| deobfuscate | `st:700-1056` | Ghidra C'sini temizler, opak yüklem/XOR tarar | `deobfuscated/decompiled/*.c` + Ghidra JSON kopyaları |
| reconstruct | `st:1058`; Mach-O → `_execute_binary` `st:3005-5140` (GO_BINARY ise önce Go, sonra `_execute_binary`, `st:1095-1106`) | Üç runner fazı (aşağıda) | `reconstructed/…` (aşağıda) |
| report | `st:5460-5553` | Rapor biçimleri | `reports/report.{json,md,html,sarif.json}`, `pipeline_result.json` |
| `--output` | `core/output_formatter.py:124-218` | `reconstructed/project/` ağacını kopyalar; `naming_map.json` + `dependency_graph.json` + `README` | temiz dizin `src/…`, `naming_map.json` |

**reconstruct içi (`_execute_binary`).** Varsayılan yol step registry'dir. `use_step_registry=False` verilse bile True'ya zorlanır: `st:3044-3057`, `config.py:652`.

| Faz | Kod | Adımlar (sırayla) ve ürettikleri |
|---|---|---|
| Faz 1 | `st:3067-3097` | Adımlar ve ürettikleri: <br>• `binary_prep`: `c_files`, `decompiled_dir` (önce `deobfuscated/decompiled`). <br>• `ghidra_metadata`: JSON yolları, `functions_data`, `call_graph_data`, `sig_matches` → `signature_matches.json`. <br>• `bsim_match`: `bsim_shadow.json`, gölge kip. <br>• `byte_pattern`: FLIRT; htop'ta `flirt_functions_named=0`. <br>• `anti_debug`, `packer_fingerprint`: `static/*_findings.json`. <br>• `pdb_symbol_recovery`: yalnız PE. <br>• `trex_struct_recovery`: htop'ta `no_lifted_il`; TRex Linux'a özgü. <br>• `binaryninja_analysis`: kapalı. <br>• `type_recovery_consumer`: htop'ta `no-data`. <br>• `pcode_cfg_analysis`: `pcode_naming_candidates`. <br>• `cfg_iso_match`. <br>• `algorithm_id`: `algorithms.json`; kripto sahte pozitifi burada. <br>• `parallel_algo_eng`: `BinaryNameExtractor` → `binary_names.json`; htop ve tmux'ta dosya yok. <br>• `confidence_filter`: CAPA birleştirme → `extracted_names`. <br>• `computation_fusion`, `assembly_analysis`. |
| Tohum | `st:3165` (`_seed_recovery_pre_names`, `st:2567-2596`) | Adımlar: <br>• main: `__libc_start_main` deseni (`st:2598`), yalnız ELF. <br>• gnulib parmak izi (`st:2659`). <br>• ELF boilerplate (`st:2836`). <br>• Elle verilen isimler (override, `st:2907`). <br>Mac'te main bulunmuyor. tmux'ta `gnulib_recovered=1` [T: şüpheli]. |
| Faz 2 | `st:3177-3181` | Adımlar: <br>• `feedback_loop` (`steps/feedback_loop.py`): her turda hesaplama → ad (c_namer + bindiff/refdiff + birleştirici) → tip; en çok 3 tur (`config.py:459`). <br>• `computation_struct_recovery`: MaxSMT, opt-in. <br>• `struct_recovery`. <br>Ürettikleri: `src/`, `merged/`, `typed/`, `src_iter1/`, `merged_iter1/`, `typed_iter1/`, `struct_recovered/`. |
| Ölü/mükerrer gövde | `st:3389-4757` döngü (`_loop_iterations = 0`, `st:3506`); `st:4767-4952` M4 kopyası (L2); `st:4956-5030` ikinci struct recovery (L3) | L3 yüzünden htop'ta `struct_recovered/` 1580 dosya içeriyor (790 × 2, `originals/` yedekleri). Ölü döngü `stats["pipeline_iterations_run"]`'u 0 ile eziyor (`st:4759-4760`). Raporda `pipeline_iterations_run=0`, `convergence_reason="unknown"` görünüyor (`steps/finalize.py:62`). |
| Faz 3 | `st:5090-5101` | Adımlar: <br>• `inline_detection` <br>• `semantic_naming` → `semantic_named/` <br>• `flow_simplify` <br>• `comment_generation` → `commented/` <br>• `capa_annotation` <br>• `engineering_annotation` → `annotated/` <br>• `project_build` → `project/` <br>• `engineering_analysis` <br>• `deep_tracing` → `data_flow/`, `dispatch_resolution.json` <br>• `finalize`: başarı = `len(artifacts) > 0`, `steps/finalize.py:65` |

`trex_export` adımı kayıtlı ama hiçbir runner listesinde yok; kullanılmıyor.

---

## 2. Ghidra çağrısı

### 2.1 Başlatma
- **Kip.** pyghidra kuruluysa pyghidra kullanılır, değilse `analyzeHeadless`'e düşülür (`hl:210-219`). Kurulu sürüm: pyghidra 3.0.0 (`/opt/anaconda3/.../pyghidra`). Mac hattı pyghidra'dan geçiyor.
- **JVM.** `HeadlessPyGhidraLauncher` başlatılıyor. Argümanlar: `-Djava.awt.headless=true`, G1GC ve `-Xmx` (`hl:42-93`).
- **Program.** `pyghidra.open_program(binary_path, project_location, project_name, analyze=True)` (`hl:247-252`). pyghidra bunu `_analyze_program` ile yapıyor: `shouldAskToAnalyze` doğruysa `flat_api.analyzeAll(program)` çağrılıyor (`pyghidra/core.py:181-189, 257-258`). Proje her koşudan sonra siliniyor (`karadul/ghidra/project.py:47-56`); önbellekten gelen analiz durumu yok.
- **Sürüm.** Bu kabukta `GHIDRA_INSTALL_DIR` yok. Bu durumda `config.py:156` (`_GHIDRA_KNOWN_DIR`) `~/Desktop/dosyalar/uygulamalar/ghidra/build/dist/ghidra_12.0_DEV` yolunu seçiyor. 12.1.2 uygulama paketinde ve Docker'da. Geliştirme koşularının hangi sürümle yapıldığı açık soru (§Açık sorular 1).

### 2.2 Analiz seçenekleri ve çıkarım sırası
- **Analiz seçenekleri.** Ghidra'nın analiz seçeneklerine hiç dokunulmuyor. `ANALYSIS_PROPERTIES`, `setNoReturn`, `createFunction`, `disassemble` karadul içinde hiçbir yerde geçmiyor (grep). Tüm analizörler Ghidra varsayılanlarıyla koşuyor.
- **Ek yüklemeler.** Analizden sonra GDT arşivleri (`hl:256-262`) ve, PE için, PDB yükleniyor.
- **Çıkarım sırası** (pyghidra yolu, her biri bir `_extract_*` fonksiyonu; JSON `static/ghidra_output/`'a, sonra `static/ghidra_*.json`'a yazılır):
  1. `functions` (`hl:556`)
  2. `strings` (`hl:595`)
  3. `call_graph` (`hl:647`)
  4. `decompiled`: paralel `DecompInterface` (`hl:894`). Her fonksiyon için `FUN_<adres>.c` yazılır; başlığa Callers/Callees/Stack, sona disassembly eklenir (`hl:1066-1170`).
  5. `types` (`hl:1331`)
  6. `xrefs` (`hl:1394`)
  7. `pcode`: seçici JSONL (`hl:1641`)
  8. `cfg` (`hl:1701`)
  9. `function_id` (`hl:2056`)
  10. BSim
  11. `combined_results`
- **CLI yolu.** `analyzeHeadless … -import … -preScript ApplyDataTypeArchive.py <gdt> … -postScript <10 betik>` (`hl:2135-2214`). Betik sırası `get_default_scripts` içinde (`hl:2251-2315`): `function_lister`, `string_extractor`, `call_graph`, `decompile_all`, `type_recovery`, `xref_analysis`, `pcode_analysis`, `cfg_extraction`, `function_id_extractor`, `export_results`. Betikler `karadul/ghidra/scripts/` altında. Mac'te bu yol yalnız pyghidra yoksa kullanılıyor.
- **Eşlik farkı.** CLI betiği `xref_analysis.py`, pyghidra yolunun üretmediği veriyi üretiyor: `globals_accessed`, string → kim referans veriyor listesi (`build_string_xref_map`, `scripts/xref_analysis.py:175-236`), global okuyan/yazan listesi (`:250-345`). Varsayılan pyghidra yolunda (`hl:1394-1490`) bunlar yok.

### 2.3 Analiz öncesine betik takılabilir mi? Evet, iki somut nokta
**(a) pyghidra yolu (`hl:247-252`).**
1. `analyze=True`, `analyze=False` olur. Bu durumda pyghidra analiz yapmaz (`pyghidra/core.py:257`).
2. `with` bloğunun başında, GDT yüklemesinden önce:
   - (i) `program.getOptions(Program.ANALYSIS_PROPERTIES)` ile seçenekler ayarlanır. Örnek: "Non-Returning Functions - Discovered" kapatılır ya da eşiği değiştirilir.
   - (ii) Bir transaction içinde fonksiyon başlangıcı tohumları eklenir: `flat_api.disassemble(addr)` + `flat_api.createFunction(addr, None)`.
   - (iii) Yanlış dönmez işaretlerinin düzeltilmesi için iki yol var. Ghidra'nın bilinen listesi `Ghidra/Features/Base/data/MachOFunctionsThatDoNotReturn` dosyasında, `noReturnFunctionConstraints.xml` üzerinden yükleniyor. Ya bu listeye karşı bir izin/ret listesi verilir ya da analizden sonra `func.setNoReturn(False)` çağrılır ve değişen bölge yeniden analiz edilir.
3. Sonra `pyghidra.analyze(program)` çağrılır (`pyghidra/api.py:137-150`). Bu çağrı `analyzeAll` + `markProgramAnalyzed` yapar.

Yeni kod `karadul/ghidra/` altında ayrı bir modül olmalı (ör. `prescript_seeds.py`). `hl` içine yalnız 5-10 satırlık bir çağrı girer.

**(b) CLI yolu (`hl:2159-2170`).** `analyzeHeadless` `-preScript` betiklerini içe aktarmadan sonra, analizden önce koşturuyor. GDT yüklemesi için bu mekanizma zaten kullanılıyor (`hl:2167`). Aynı yere `-preScript seed_starts.py <json>` eklenir.

**Mac için not.** Ghidra kaynak ağacında (12.0_DEV, `4fcc1febdd`) `MachoFunctionStartsAnalyzer.java:89` `setDefaultEnablement(true)`; yani LC_FUNCTION_STARTS Ghidra'da zaten tohum olarak kullanılıyor. 12.1.2'de de böyle olduğu [T]. Mac'te KS-2'nin kaldıraçları şunlar:
- dönmezlik yanlışları (fonksiyonun erken kesilmesi);
- `.cold`/`OUTLINED_FUNCTION` parçalarının ayrı fonksiyon sayılması;
- sınır F1 ölçümü (LC_FUNCTION_STARTS'ı okuyup Ghidra başlangıçlarıyla karşılaştırmak).

`byte_pattern_matcher.py:742-743`'teki yorum bir ölçüm kaydediyor: Homebrew `tree`'de Ghidra fonksiyon boyutu 118/118 fonksiyonda LC_FUNCTION_STARTS aralığına eşit.

---

## 3. Fonksiyon sınırları ve çağrı grafı

| Toplayıcı | Ne topluyor | Ne eksik |
|---|---|---|
| `hl:_extract_functions` (`:556-593`); CLI eşi `scripts/function_lister.py:60-89` | Ad, adres, gövde boyutu (`getNumAddresses`), parametreler, dönüş tipi, `is_thunk`, `is_external`, çağırma kuralı, `source` | `hasNoReturn()`; gövde aralıkları (parçalı/soğuk gövde); thunk hedefi (`getThunkedFunction`); bölüm adı; giriş noktası mı |
| `hl:_extract_call_graph` (`:647-736`); CLI eşi `scripts/call_graph.py:78-98` | Her fonksiyon için callers ve callees; **yalnız `ref.getReferenceType().isCall()`** (`:665`, `:680`). Öz-kenar dışarıda (`!= func_addr`, `:666`, `:684`). Kenarlar tekilleştiriliyor; çağrı yeri yok | Dolaylı çağrı (`COMPUTED_CALL` hedefi çözülmemişse kenar yok); veri referansı; `b`/`jmp` kuyruk çağrısı (Ghidra'nın "Shared Return Calls" çevirmediyse); çoklu kenar ve çağrı yeri etiketi; stub katlama |
| `hl:_extract_xrefs` (`:1394-1490`); CLI eşi `scripts/xref_analysis.py` | `functions_called` (isCall), `called_by` (isCall), `strings_used` (isData + tanımlı string verisi). Global sayısı yalnız toplam | **Fonksiyon girişine gelen veri referansı** (tablodaki işaretçi); string dışı global erişimler; string başına referans veren fonksiyon listesi (KS-1'in "kaç fonksiyondan referans" ölçütü buna muhtaç) |
| `hl:_extract_func_xrefs` (`:794-851`, decompile başlığı için) | Çağıranlar ve çağrılanlar, çağrı yeriyle | Yalnız `.c` başlığına ve `decompiled.json`'a gidiyor |

**Etki (geliştirme seti, `ghidra_xrefs.json`'dan sayıldı).** isCall ile hiç çağıranı olmayan `FUN_` sayısı htop'ta 216/597, tmux'ta 787/2587. htop örneği `show_processes` (`FUN_100003438`) başlığında `Callers: 0` yazıyor; htop'ta eylemler tablodan çağrılıyor.

**Kuyruk çağrısı.** htop `FUN_1000109b4` örneği `b 0x1000213fc` ile biterken başlıkta `_free` callee olarak görünüyor. Ghidra stub'a giden kuyruk çağrısını en azından bu örnekte çağrı olarak işaretlemiş. TR-1'in gerçek açığı ölçülmeden büyüklüğü bilinmiyor [T].

**Veri tablosu bilgisinin kaynağı.** Ghidra yükleyicisi chained fixup adreslerine `PointerDataType` koyuyor (`MachoProgramBuilder.java:1676-1687`). İşaretçi verisinin hedefe DATA referansı ürettiği [T]. Toplamak için `_extract_xrefs` içinde `getReferencesTo(entry)` döngüsünde `rt.isData()` olanları ayırmak yeter: kaynak adres, bellek bloğu adı (`__const`/`__data`) ve aynı bloktaki komşu işaretçilere göre yuva sırası tutulur.

---

## 4. İsim akışı

### 4.1 Kaynaklar ve hatta girdikleri yer

| Kaynak | Kod | Hatta giriş | Mac geliştirme setinde |
|---|---|---|---|
| İmza DB (sembol kataloğu) | `ghidra_metadata` adımı → `sig_matches` | Yalnız import/sembol eşlemesi; `signature_matches.json` | htop 112 eşleşme, ithal adlar |
| FLIRT bayt imzası | `steps/byte_pattern.py`, `analyzers/byte_pattern_matcher.py` | `byte_pattern_names` → `extracted_names` (`st:2448-2470` monolit; step yolunda `confidence_filter`) | htop/tmux `flirt_functions_named=0` |
| BinaryNameExtractor (RTTI, assert, `__func__`, StringIntelligence) | `steps/parallel_algo_eng.py:122-175` | `binary_names` → `extracted_names` | `binary_names.json` yok (htop, tmux) |
| CAPA | `steps/_confidence_helpers.py:231-291` | `extracted_names[func_addr] = …` (`:274`) | Mach-O'da capa başarısız; ad yok (§8f) |
| main / gnulib / ELF boilerplate / override | `st:2567-2596` | `extracted_names` (Faz 2'den önce, `st:3165`) | main yok (ELF deseni), tmux'ta gnulib 1 |
| **c_namer** | `cn:1435` `analyze_and_rename` | `extracted_names` → `pre_names` (`steps/_feedback_naming.py:283-288`) | **Fonksiyon adlarının neredeyse tamamı**: htop `string_context` 101, tmux 863 |
| bindiff / refdiff | `steps/_feedback_naming_bindiff.py`, `_feedback_naming_refdiff.py` | Yalnız 1. tur, birleştiriciye aday | — |
| BSim | `steps/bsim_match.py` → `bsim_shadow.json` | Gölge kipte birleştiriciye **girmiyor** (`steps/_feedback_naming_merger.py:211-240`; `config.py` `shadow_mode=True`) | `bsim_fusion_status=shadow` |
| FunctionID, hesaplama, p-code, mühendislik | `steps/_feedback_naming_candidates.py:470-985` | Birleştiriciye aday | — |
| Değişken adları (varname) | `cn` stratejileri (`local_var` `:3317`, `body_param` `:3162`, `dataflow` `:2888`, `api_param` `:3117`, `type_based` `:3038`, `passthrough` `:2279`); tip fazında xtride, dynamic ve ngram (`steps/_feedback_typing_extras.py`); Faz 3'te `semantic_naming` (`SemanticParameterNamer`) | Fonksiyon başına AhoReplacer (`cn:1750-1781`) | htop `local_var` 1562, `body_param` 668 |

### 4.2 Öncelik ve çakışma
1. **c_namer içinde** (`cn:1636-1703`):
   - `pre_names` önce yazılır; her birine güven 0,95 ve strateji `binary_extract` verilir (`cn:1649`).
   - Sezgisel adaylar güvene göre sıralanır (`cn:1665`) ve en iyisi alınır. Eşik `min_confidence=0,15` (`cn:1408`).
   - Global fonksiyon adında `call_graph`, `callee_based` ve `api_call` stratejileri yasak (`cn:1686-1690`).
   - `pre_names`'te bulunan ada dokunulmaz (`if old_name in naming_map: continue`).
   - Aynı yeni ad ikinci kez gelirse `_2`, `_3` eki alır (`cn:1697-1702`).
2. **Birleştirici** (`steps/_feedback_naming_merger.py:23-121`; `reconstruction/name_merger.py`):
   - Adayları toplayan `collect_candidates`. `binary_extractor` adayları 0,85 alır (`_feedback_naming_candidates.py:393-402`). c_namer adayları gerçek güvenle gelir; yapısal olanlar 0,25'e sabitlenir (`:405-432`).
   - Bayes birleştirme kaynak ağırlıklarını `config.py:296-350`'den alır.
   - UNK eşiği 0,30 (`name_merger.py:237`; `config.py:352`).
3. **Yapısal kusur.** Birleştiricinin girdisi c_namer'ın yeniden yazdığı dizin:
   - `_feedback_naming.py:120-129` → `src/`.
   - AhoReplacer `FUN_xxx` literalini arar (`_feedback_naming_merger.py:144-209`).
   - c_namer'ın adlandırdığı fonksiyonda bu literal artık yok. Birleştiricinin farklı seçimi sessizce düşer.
   - htop: `merged/` = `src/` (790/790 aynı). Birleştiricinin 205 adı, c_namer'ın 205 global adıyla aynı.
4. **Turlar arası.** 2. turda c_namer yalnız artımlı alt kümeyi işler (`_feedback_naming.py:240-258`). Yakınsama kontrolü `_feedback_helpers.py:87`.

### 4.3 Güven değerinin akışı
- c_namer gerçek güveni `confidence_map` olarak dışarı verir (`cn:1708-1711`; `CNamingResult`).
- `naming_map.json`'a güven yazılmaz. Dosyaya yalnız `{"global": …, "per_function": …}` gider (`cn:1782-1796`).
- Birleştiricinin `MergedName.final_confidence` değeri var, ama `to_naming_map` yalnız adı döndürür (`name_merger.py:548-553`). Güven diske yazılmaz.
- `output_formatter._build_naming_map` (`output_formatter.py:498-662`) içinde:
  - imza DB, bayt deseni ve hesaplama kaynakları kendi güvenleriyle gelir;
  - **c_namer adları `"confidence": 1.0`** ile yazılır (`:651-658`). Yorum satırı gerekçeyi şöyle veriyor: "uygulanan final isim olduğu için 1.0".
  - Okunan harita c_namer'ınki (`src/naming_map.json`, `src_iter*/naming_map.json`; `:616-631`), birleştiricinin değil.

---

## 5. Tarif paketinin hatta bağlanacağı nokta

### 5.1 Arayüz (`karadul/reconstruction/tarif/`)
- **Girdi 1: `build_evidence(static_dir)`** (`tarif/evidence.py:56-106`). Okuduğu dosyalar:
  - `static/ghidra_functions.json`: dış ve thunk adları;
  - `static/ghidra_xrefs.json`: `functions_called`, `called_by`, `strings_used`;
  - `static/ghidra_output/decompiled/FUN_<adres>.c`: geri çağrı kaydı (regex), büyük sabitler, satır sayısı.

  Çıktı `dict[adres → EvidencePack]`. Adres küçük harf, `0x`'siz Ghidra adresi.
- **Girdi 2: `run_tarif(packs, kesin, population)`** (`tarif/__init__.py:24-48`). Parametreler:
  - `kesin`: `{adres: özgün_ad}`;
  - `population`: isim bekleyen adresler.

  Çıktı `dict[adres → Naming(name, source, score)]` (`tarif/rules.py:27-37`). `source` öneki statüyü taşır: `kesin:…`, `geri_cagri:…`, `api:…`, `log`, `yayilim:…`, `ipucu:…`. `is_hint` doğruysa ad değil, yorumdur.
- **Bugünkü köprü.** `scripts/measurement/tarif_olc.py:28-39`. `kesin`'i Karadul'un c_namer haritasından kuruyor: ikilide birebir geçen tanımlayıcılar (kesinlik ~0,74). Ürüne girerken bunun yerine KS-1 gelmeli.

### 5.2 Doğru bağlanma noktası: c_namer'dan ÖNCE
**Gerekçe.**
- §4.2 madde 3: c_namer'dan sonra gelen hiçbir ad, c_namer'ın adlandırdığı fonksiyona uygulanamıyor.
- `pre_names`'e giren ad c_namer'ın tahmini tarafından ezilemiyor (`cn` guard).
- Kod belgesi aynı tuzağı main/gnulib için anlatıyor (`st:2582-2589`).

**Öneri (yeni dosyalar ağırlıklı).**
1. **Yeni adım `steps/tarif_naming.py`.**
   - Girdi: `static_dir`, ya da `ghidra_metadata`'dan gelen `xrefs_json_path` ve `functions_json_path`.
   - İşlev: `build_evidence` + `run_tarif`.
   - Ürettiği artifact: `tarif_names`; ayrıca `reconstructed/tarif_names.json`.
   - Faz 1 listesine `assembly_analysis`'ten sonra eklenir (`st:3096-3097`). **stages.py'ye dokunur.**
2. **Tohumlama.** `tarif_names` içindeki ipucu olmayan adlar `FUN_<adres>` anahtarıyla `extracted_names`'e yazılır. Tohumun yeri `_seed_recovery_pre_names` çağrısının hemen yanı (`st:3165`). Mevcut isme dokunulmaz; main, gnulib ve override tarif'ten önce gelir.
3. **Statü kanalı (c_namer'a dokunmadan).**
   - Ayrı bir `reconstructed/name_provenance.json` yazılır: `{FUN_x: {source, statü, puan, kanıt}}`.
   - `output_formatter.py:651-658` bu dosyayı okur. 1,0 yerine ölçülmüş kural isabetini ve statüyü yazar.
   - c_namer'ın `binary_extract`/0,95 etiketi iç sayaç olarak kalır.
   - İkinci adım (sıralı, c_namer): `pre_names` için `pre_names_meta` parametresi eklenir, böylece `confidence_map` gerçek değeri taşır (`cn:1636-1650`).
4. **İpuçları.** Ad olarak hiçbir kanala girmez. Faz 3'te `comment_generation` (`steps/comment_generation.py` → `reconstruction/c_comment_generator.py`) üzerinden `/* ipucu: … */` yorumu olur.
5. **c_namer'ın kimlik iddiası (TR-2).** Tarif açıkken `string_context`'ten gelen global fonksiyon adları kimlik olarak yazılmamalı. Bu `cn:2522-2610`'a dokunur ve ayrı, sıralı bir iştir. Yapılmazsa tarif yalnız c_namer'ın boş bıraktığı fonksiyonlara ulaşır. Tarif tohumu `pre_names`'ten girdiği için çakışmada kazanır.

### 5.3 Gereken veri hatta var mı?

| Veri | Durum | Kaynak |
|---|---|---|
| Kütüphane çağrıları | Var | `ghidra_xrefs.json` `functions_called` + `ghidra_functions.json` `is_external`/`is_thunk` |
| Kullanılan string'ler | Var (yalnız string verisine giden isData) | `hl:1431-1442` |
| String'i kaç fonksiyonun kullandığı | **Yok** (pyghidra yolunda); CLI betiğinde var | `scripts/xref_analysis.py:175-236` |
| Çağıranlar | Var (yalnız isCall) | `hl:1446-1453` |
| Veri tablosu yuvası (M4) | **Yok** | §3 |
| Sabit argümanlar | Dolaylı: C metni regex'i (`tarif/evidence.py:20-25`) | p-code JSONL seçici; çağrı argümanı sabitleri [T] |
| Ham decompile metni | Var | `static/ghidra_output/decompiled/` (temizlenmiş kopya `deobfuscated/decompiled/`) |
| Derleme kökeni (LC_BUILD_VERSION) | **Yok** | §7 |

---

## 6. Okunabilirlik çıktısı

### 6.1 Kullanıcıya giden son C dosyası
- **Dosya.** `reconstructed/project/src/<subsystem_…>/FUN_<adres>.c` (`steps/project_build.py` → `reconstruction/c_project_builder.py`). `--output` ile temiz dizine kopyalanır (`output_formatter.py:257-260`).
- **Dosya adı değişmiyor.** `show_processes` adlı fonksiyonun dosyası `FUN_100003438.c`.
- **İçerik (htop örnekleri):**
  - Ghidra başlığı (Function/Address/Size/Callers/Callees/Stack; `hl:1129-1160`);
  - doxygen yorumu (`@brief Function at address …`, `@param`, `@called_by`, `@calls`; `c_comment_generator`);
  - satır içi yorum (`// Free: release ptr_24`);
  - gövde;
  - sonda tam disassembly (`hl:1163-1167`).
- **Tutarsızlık.** Aynı dosyada başlık satırı yeni adları gösteriyor (`Callers: … sending, show_processes`), doxygen `@called_by` eski adları gösteriyor (`FUN_100003110, FUN_100003438`).

### 6.2 Değişken adları
- **Kim adlandırıyor.**
  - c_namer'ın yerel stratejileri;
  - tip fazındaki xtride, dynamic ve ngram;
  - Faz 3'te `semantic_naming`.
- **htop sonucu.** `variables_renamed=2720`, `params_renamed=185`. Ama `project/src`'de Ghidra varsayılan yerel adları 3952 kez, `param_N` 1243 kez geçiyor (geçiş sayısı; tekil değil).
- **Ad kalitesi.** Örnek `show_processes`: `offset_4` aslında bir yapı işaretçisi, `field_ptr` bir `int` uid, `buf_14` ise `State*`.
- **Regresyon koruması ölü** (§8d).

### 6.3 Tip kurtarma
- `CTypeRecoverer`: `reconstruction/c_type_recoverer.py`, tip fazında (`steps/_feedback_typing.py:150-185`). `types.h` üretiyor.
- htop `types.h` içeriği:
  - Ghidra'nın Mach-O yükleyici ve SDK tipleri (`dyld_chained_*`, `__sFILE` …);
  - 201 `recovered_struct_NNN`.
  - Geçersiz tanımlayıcı var: `dyld_chained_starts_in_segment.conflict` (satır 48 ve 886). Dosya derlenmez.
- `type_recovery_consumer`: `no-data`.
- TRex: `no_lifted_il`. TRex Linux ELF ister.
- BinaryNinja kapalı.

### 6.4 Yapı (struct) kurtarma
- `struct_recovery` (`StructRecoveryEngine`) ve opt-in `computation_struct_recovery` (MaxSMT) var.
- **Kaynaklara uygulanmıyor:** htop'ta `recovered_struct_` kullanan kaynak dosyası 0, `->alan` 0, ham ofset erişimi 1934.
- MaxSMT adaylarını tüketen tek yol ölü L2/L3 gövdesi (bkz. `docs/migrations/stages_split_plan.md:52-54`).

---

## 7. Mach-O'ya özgü olanaklar

`grep -rn "lief|macholib|function_starts|chained|objc|swift|LC_BUILD"` sonucu:

| Olanak | Karadul okuyor mu? | Not |
|---|---|---|
| LC_FUNCTION_STARTS | **Hayır.** Yalnız yorumda (`byte_pattern_matcher.py:743`) | Ghidra kendi analizörüyle kullanıyor (§2.3) |
| Chained fixups | **Hayır** | Ghidra yükleyicisi işaretçileri işaretliyor (`MachoProgramBuilder.java:144, 157, 1676`). Karadul bunları toplamıyor (§3) |
| Export trie | **Hayır** | Ghidra yükleyicisi kullanıyor (`MachoProgramBuilder.java:528-545`). Apple strip'li ikilide trie daralıyor |
| ObjC metaverisi | **Hayır** (yalnız `objc_msgSend` string'iyle dil tahmini, `core/target.py:156`). Swift hedeflerinde `_OBJC_CLASS_$_` referansları (`analyzers/swift_binary.py:239-242`) | Ghidra'nın ObjC analizörlerinin metot adlarını koyduğu [T]; Karadul bu adları korur mu ölçülmedi |
| Swift metaverisi | Yalnız `SWIFT_BINARY` hedef tipinde `swift_binary.py` | `__swift5_*` bölümleri okunmuyor |
| LC_BUILD_VERSION | **Hayır.** `container_classifier.py:959` APK'ya ait | KS-5 için gerekli |
| lief | Yalnız başlık, segment, bölüm, kütüphane (`macho.py:561-630`); hedef tespitinde bölüm adı (`core/target.py` `__BUN`) | htop'ta Go yanlış yönü yüzünden hiç koşmadı |
| macholib | Yok | — |
| `.cold.N` / `OUTLINED_FUNCTION` | Yok (grep boş) | KS-3, ÖL-2 |

---

## 8. 2026-10-14 denetim hataları: bugünkü durum

| # | Hata | Kod noktası | Durum |
|---|---|---|---|
| a | `output_formatter` her ada güven 1,0 yazıyor | `core/output_formatter.py:651-658` (`"confidence": 1.0`, `:656`). Okunan harita c_namer'ınki (`:616-631`) | **Duruyor** |
| b | Kripto sabit dedektörü sahte pozitif | `reconstruction/c_algorithm_id.py:869-950`. Alt dize eşleşmesi `if hex_lower in body_lower` (`:905`); tek sabitli grupta eşik 1 (`required = max(1, len//2)`, `:925`); `len(body) < 500` filtresi (`:882`) | **Duruyor.** Mac geliştirme setinde de görülüyor: htop `algorithms.json` 356 tespit (hash 265, mac 61, simetrik 29). `project/src`'de 139 Keccak, 33 Poly1305, 7 AES, 5 GOST, 1 DES yorumu |
| c | 2. tur boş kalınca 0 kaynak ama "success" | Başarı ölçütleri: `steps/finalize.py:65` (`success = len(artifacts) > 0`), `output_formatter.py:210` (`success = src_files > 0 or reports_generated > 0`). Dizin aktarımı: `_feedback_naming.py:120-129` (namer çıktısı yalnız tam turda yönlendiriliyor), `_feedback_naming_merger.py:134-136` (`merged_iter*` yalnız ad varsa), `_feedback_typing.py:80-87` | **Duruyor** (iki başarı ölçütü de kaynak sayısına bakmıyor). Boş dizine düşüş mekanizması bu okumada yeniden üretilmedi [T]; htop koşusunda `typed_iter1` dolu (790) |
| d | Varname regresyon koruması ölü | `scripts/varname_f1_eval.py:231` (`src_dir.glob("*.c")`, düz arama); `tests/test_varname_f1_baseline.py:158` (`clean / "src"`); test `@pytest.mark.benchmark` ve varsayılan `addopts` onu dışlıyor (`pyproject.toml:120`). Çıktı `src/src/subsystem_*/` iç içe | **Duruyor.** Bu iki dosyada 4b4f735'ten sonra commit yok |
| e | MAJOR-1: override merge sonrası zorlanmıyor | Zorlama yalnız ölü döngüde (`st:4255-4260`; döngü `st:3506`'da 0 tur). Tohum kısmı çalışıyor (`st:2596`, `st:2907-2997`). `steps/` altında `manual_overrides` referansı yok (grep) | **Duruyor.** Ayrıca §4.2'deki "birleştirici c_namer'ı ezemez" kusuru yüzünden tohum genelde yetiyor [T]; ezilme yalnız bindiff/refdiff/birleştirici ile olur |
| f | `config.py:331` capa'ya 0,85 güven veriyor | `config.py:331` `"capa_capability": 0.85`. **Bu kaynak anahtarını üreten kod yok** (grep: `capa_capability` yalnız config'te). Gerçek yol: `_confidence_helpers.py:274` → `extracted_names` → c_namer `pre_names` 0,95 (`cn:1649`) ve birleştirici `binary_extractor` 0,85. Statik aşama capa'yı Mach-O için de çağırıyor (`st:335-340`) | **Duruyor, ama kendisi ölü bir ağırlık.** capa Mach-O'yu reddettiği için (derleyici ajanı ölçümü) Mac'te ad gelmiyor. capa anahtarları adres, `extracted_names` anahtarları `FUN_` adı; eşleşmeme olasılığı [T] |

**Denetimde olmayan yeni bulgular:**
- Go yanlış tanıma (`core/target.py:661`).
- Birleştiricinin c_namer'ı ezememesi (§4.2).
- `pipeline_iterations_run` değerinin ölü döngü tarafından 0'a ezilmesi (`st:4759-4760`).
- `types.h`'nin derlenmemesi (§6.3).
- c_namer çakışma eklerinin sıraya bağlılığı. Adaylar `as_completed` sırasıyla birleşiyor (`cn:1570-1595`), ad kararı bu sözlük sırasıyla veriliyor (`cn:1659-1703`). Aynı adı isteyen iki fonksiyondan hangisinin `_2` alacağı koşudan koşuya değişebilir [T]. ÖL-7 bunu yakalamalı.

---

## Plan kalemleri → kod noktası

Notlar:
- **Büyüklük:** S = günler, M = 1-2 hafta, L = daha uzun.
- **Riskli** sütunu üç tehlikeli dosyayı (`c_namer.py`, `stages.py`, `config.py`) gösterir. "hl" ayrıca belirtilir: tehlikeli listede yok, ama bütün Ghidra verisi oradan geçer.
- Ürüne bağlamak için yeni bir adımı runner listesine eklemek her zaman `stages.py` demektir (`st:3067`, `3177`, `5090`).

### Kesin isim (KS)

| # | Değişecek dosya / fonksiyon | Büyüklük | Riskli dosya |
|---|---|---|---|
| KS-1 | Yeni `tarif/kesin.py` (kendi adını yazma, assert ve `__func__` tespiti). Girdiler: `ghidra_xrefs.json` + decompile metni. `hl:_extract_xrefs`'e string başına referans veren liste eklenir (CLI `xref_analysis.py:175-236` eşi). `tarif_olc.py:28` köprüsü yerine bu. Mevcut kaynaklar: `cn:_strategy_string_context` (`:2522`), `BinaryNameExtractor._strategy_string_intelligence` (`binary_name_extractor.py:1887`) | S–M | hl; tohum bağlantısı `stages.py` |
| KS-2 | Analiz öncesi kanca: `hl:247-252` (`analyze=False` + yeni `karadul/ghidra/prescript_seeds.py`) ve CLI'de `hl:2159-2170` `-preScript`. `hl:_extract_functions` (`:556`) `hasNoReturn`, gövde aralıkları, thunk hedefi. LC_FUNCTION_STARTS okuyucu: yeni `analyzers/macho_meta.py` (lief) | S (ölçüm), M (dönmezlik) | hl |
| KS-3 | Yeni `tarif/family.py` (`.cold`/OUTLINED/ICF aileleri). Ebeveyn bağı için `hl:_extract_xrefs`'e fonksiyonlar arası jump referansları. Ölçüm tarafı ÖL-2 | M | hl |
| KS-4 | `tarif/propagate.py` (sarmalayıcı testi; Y2 var). Debian tarafı: `st:_recover_gnulib_from_fingerprints` (`:2659-2835`) | M | `stages.py` (Linux kısmı) |
| KS-5 | Yeni `analyzers/macho_meta.py`: LC_BUILD_VERSION, export trie boyutu, `.cold` varlığı → `static/build_profile.json`. Kural kapısı `tarif/rules.py` içinde. Önkoşul: Go yanlış tanıma düzeltmesi (`core/target.py:648-671`) | M | Hayır (target.py merkezi, ama listede yok) |
| KS-6 | `tarif/rules.py` (COMBOS) + `tarif/evidence.py` (çağrı argümanı sabitleri) | M | Hayır |
| KS-7 | Ghidra ObjC adlarının korunduğunun ölçümü (`cn:_is_ghidra_auto_name` `:188-200`); `.tbd` sözlüğü yeni veri; Swift: `analyzers/swift_binary.py` | M | c_namer (yalnız auto-name kuralı değişirse) |
| KS-8 | `analyzers/byte_pattern_matcher.py`, `steps/byte_pattern.py`, `analyzers/sigdb_lmdb.py`, imza üretim betikleri | L | `config.py` (yol/eşik eklenirse) |
| KS-9 | Yeni adım ya da `st:_recover_gnulib_from_fingerprints` yanı; Linux | L | `stages.py` |

### Tarif (TR)

| # | Değişecek dosya / fonksiyon | Büyüklük | Riskli dosya |
|---|---|---|---|
| TR-1 | `hl:_extract_call_graph` (`:647-736`) ve `hl:_extract_xrefs` (`:1394-1490`): çağrı yeri listesi, öz-kenar, jump→giriş kenarları, `getThunkedFunction` ile stub katlama. Şema yalnız eklemeli değişmeli; okuyucular: `cn:_load_call_graph` (`:2020-2078`), `_feedback_helpers.build_cg_neighbors` (`:21`), `tarif/evidence.py` | S–M | hl |
| TR-2 | `cn:_strategy_string_context` (`:2522-2610`): kimlik yerine rol/yorum; hata yolu budaması | S | **c_namer** |
| TR-3 | `tarif/evidence.py:normalize_api` (`:28`) + `tarif/rules.py` | S | Hayır |
| TR-4 | `hl:_extract_xrefs`: fonksiyon girişine gelen `isData()` referansları + blok adı + yuva sırası; ya da yeni `_extract_pointer_tables`. `tarif/evidence.py` yeni alan (`table_slots`); `tarif/rules.py` yuva rolü | M | hl |
| TR-5 | `tarif/propagate.py` baştan (kafes, SCC sırası; bugün `MAX_ROUNDS=6`) | M | Hayır |
| TR-6 | `tarif/module.py` + KS-5 profili | S–M | Hayır |
| TR-7 | `tarif/rules.py` + argüman sabitleri: p-code JSONL (`hl:_decompile_single_function` seçici op'lar, `config.py` `pcode_selective_ops`) ya da C metni | M | `config.py` (yeni op eklenirse) |
| TR-8 | `tarif/rules.py` + birleştirme kuralı; ELF parmak izi tarafı `st:2659` | M | `stages.py` (ELF kısmı) |
| TR-9 | `reconstruction/c_algorithm_id.py:_scan_constants` (`:869-950`) baştan; `steps/algorithm_id.py` | M | Hayır |
| TR-10 | Yeni `tarif/effects.py` (p-code MOD/REF); p-code verisi `static/ghidra_output/pcode.jsonl` [T: seçici op kümesi yetiyor mu] | M | Hayır (`config.py` op listesi değişirse evet) |
| TR-11 | Yeni modül; `ghidra_cfg.json` + p-code | L | Hayır |
| TR-12 | Yeni p-code öykünücüsü; tam p-code çıkarımı gerekir (`hl:_extract_pcode` `:1493`, legacy kip) | L | hl, `config.py` |

### Değişken isimleri (DG)

| # | Değişecek dosya / fonksiyon | Büyüklük | Riskli dosya |
|---|---|---|---|
| DG-1 | `cn:_strategy_local_var_naming` (`:3317`), `cn:_is_ghidra_auto_name` (`:188`): `in_`/`extraout_`/`unaff_` ve dökme yuvalarına ad verme. Ayrıca `steps/_feedback_typing_extras.py` (dynamic, ngram) ve `steps/semantic_naming.py` | S | **c_namer** |
| DG-2 | `cn:_strategy_api_param_propagation` (`:3117`), `cn:_propagate_passthrough_params` (`:2279`). Ad değere bağlanacaksa Ghidra tarafı HighVariable bilgisi `hl:_decompile_single_function` | S–M | **c_namer**, hl |
| DG-3 | Yeni Faz 3 adımı (c_namer'a dokunmadan, `semantic_naming` gibi dosya üstünde) + p-code; ya da `cn:_strategy_local_var_naming` | M | `stages.py` (runner listesi) ya da c_namer |
| DG-4 | TR-4 işaretçi haritası + `struct option` çözücü (yeni modül) | M | hl |
| DG-5 | Ghidra tarafı HighFunction varnode'ları: `hl:_decompile_single_function` (`:1066`) | L | hl |
| DG-6 | Yeni modül, sızıntı denetimiyle | L | Hayır |

### Tipler (TP)

| # | Değişecek dosya / fonksiyon | Büyüklük | Riskli dosya |
|---|---|---|---|
| TP-1 | `reconstruction/c_type_recoverer.py` (metin düzeyi). Daha doğrusu decompile öncesi Ghidra'da tip uygulamak (`hl` analiz sonrası, decompile öncesi kanca) | S | hl (Ghidra tarafı seçilirse) |
| TP-2 | GDT yüklemesi `hl:256-262` (`config.py` `ghidra_data_type_archives`); union-find için yeni modül | M | `config.py` (GDT listesi) |
| TP-3 | `analyzers/byte_pattern_matcher.py` eşleşme kuralı + KS-3 aileleri | M | Hayır |
| TP-4 | TR-4 işaretçi haritası + yeni yapı periyodu modülü | M | hl |
| TP-5 | `steps/struct_recovery.py`, `steps/computation_struct_recovery.py`, `c_type_recoverer`. Önce kurtarılan yapıların kaynağa uygulanmaması kapatılmalı; L2/L3 ölü yol temizliği `stages.py` | L | `stages.py` |

### Ölçüm (ÖL)

| # | Değişecek dosya / fonksiyon | Büyüklük | Riskli dosya |
|---|---|---|---|
| ÖL-2 | `score_macho.py` scratchpad'den `scripts/measurement/`'a; `scripts/measurement/function_f1.py` yalnız ELF (`:195` pyelftools); `tests/benchmark/metrics.py:684` sonek regex'i (`llvm`, `specialized`, yalın `.N`, `localalias` yok) | S–M | Hayır |
| ÖL-3 | Yeni `scripts/measurement/payda.py`: `ghidra_functions.json` (`is_thunk`), `ghidra_xrefs.json` (çağıransız), TR-4 sonrası tablo referansları | M | Hayır |
| ÖL-7 | Yeni test: `run_tarif` karışık sırayla; `cn` aday birleştirme sırası (`:1570-1595`) ve çakışma eki (`:1697-1702`); `steps/feedback_loop.py` iki koşu + karıştırılmış koşu | S | Ölçüm için hayır; düzeltme c_namer |

---

## Riskler

1. **Tehlikeli dosyalar.**
   - `stages.py` 5669 satır. `_execute_binary` tek başına `st:3005-5140` (~2135 satır, god-function). İçinde ölü döngü (`st:3389-4757`), L2 (`st:4767-4952`) ve L3 (`st:4956-5030`) var.
   - `c_namer.py` 3595 satır. `config.py` 997 satır.
   - Tarif bağlantısı, MAJOR-1 portu, ölü yol temizliği (god-function M1-M6, `docs/migrations/stages_split_plan.md`) ve TR-2/DG-1 aynı iki dosyada kesişiyor. **Tek elden ve sıralı** yapılmalı.
2. **Önerilen sıra (çakışma haritası).**
   1. Go yanlış tanıma (`core/target.py:661`; tehlikeli listede yok, ama her Mac ölçümünü etkiler). Bundan sonra htop tabanı **yeniden ölçülmeli**.
   2. ÖL-2/ÖL-3/ÖL-7 (yeni dosyalar; paralel güvenli).
   3. `hl` çıkarım genişletmeleri: TR-1, TR-4, string başına referans. Tek ajan; şema yalnız eklemeli.
   4. `tarif/` paketi geliştirme (KS-1, TR-3, TR-5, TR-6, KS-6; yalnız paket dosyaları, paralel güvenli).
   5. `stages.py` bağlantısı: tarif adımı + tohum + MAJOR-1 portu, tek seferde.
   6. `output_formatter` statü kanalı (§8a).
   7. `c_namer` değişiklikleri (TR-2, DG-1, `pre_names_meta`) en son, tek başına.
3. **`headless.py` görünmez risk.** Listede yok, ama her Ghidra JSON'unun tek üreticisi. Mevcut okuyucular var (c_namer, `tarif/evidence.py`, ölçüm betikleri, CLI betikleri). Alan adı değiştirmek ya da öz-kenarı aniden açmak onları sessizce bozar. Yalnız yeni alan eklenmeli; öz-kenar ve çağrı yeri yeni anahtarlarla gelmeli.
4. **Ölçüm geçerliliği.**
   - htop taban sayıları Go hibrit yolundan geldi.
   - Dev ortamı Ghidra 12.0_DEV'i seçiyor (env yoksa).
   - App 12.1.2 taşıyor. Sürüm sabitlenmeden kapı ölçümü kıyaslanamaz.
5. **Sessiz düşüş.** Birleştiricinin c_namer adlarını ezememesi, tarif adları `pre_names` dışından girerse onları da sessizce yutar. Entegrasyon testinde "tarif adı son `.c` dosyasında var mı?" kontrolü zorunlu, yalnız `naming_map.json` kontrolü yetmez.
6. **Paralel çalıştırmada özel risk.** `steps/feedback_loop.py`, `_feedback_loop_iter.py`, `_feedback_naming*.py`, `_feedback_typing.py`, `output_formatter.py` ve `stages.py`'ye aynı dalgada iki ajan yazarsa 14 Mayıs fiyaskosu tekrarlar.

## Açık sorular

1. Geliştirme koşuları (htop, tmux 2026-10-15) hangi Ghidra ile yapıldı: 12.0_DEV mi, 12.1.2 mi? Koşu sırasındaki `GHIDRA_INSTALL_DIR` bilinmiyor.
2. Ghidra'nın chained fixup işaretçilerinden fonksiyon girişine DATA referansı ürettiği [T]. Doğrulamak için htop projesinde tek bir sorgu gerekir; bu görevde Ghidra çalıştırılmadı.
3. Hata (c)'nin boş dizine düşüş mekanizması bu okumada yeniden üretilmedi. Kanıt ikilisi `tests/fixtures/varname_bench/build/hashbench_O2.stripped` (denetim kaydı).
4. TR-1: Ghidra'nın "Shared Return Calls" çevirisi kuyruk çağrılarının ne kadarını zaten çağrı yapıyor? Ölçülmedi.
5. Ghidra ObjC analizörü metot adlarını koyuyorsa Karadul bunları koruyor mu (KS-7)? ObjC örnek ikilisi yok.
6. tmux'taki `gnulib_recovered=1` (Mach-O'da gnulib parmak izi) doğru mu?
7. CAPA anahtar biçimi (adres) ile `extracted_names` anahtarlarının (`FUN_` adı) uyuşmazlığı [T]; Linux'ta ölçülmeli.
8. `steps/_feedback_naming_candidates.py:769-985` mühendislik kanalları ve `computation_fusion` Mac'te hiç ad üretiyor mu? htop'ta `engineering_naming_status=no-matches`, `computation_fusion_accepted=0`. tmux'a bakılmadı.
