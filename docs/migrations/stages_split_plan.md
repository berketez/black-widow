# stages.py `_execute_binary` Split Planı (v1.12.0)

## 00. GÜNCEL DURUM (2026-09-25)

> **Geçerlilik:** Bu bölüm, aşağıdaki "§0 GÜNCEL DURUM (2026-07-16)" ve §1–§10 (2026-04-22)
> bölümlerinin ÜSTÜNDEDİR. **Çelişkide bu bölüm geçerlidir.** Eski bölümler tarihsel kayıt olarak
> değiştirilmeden korunuyor.
> **Kaynak:** Architect ajanı, salt okunur analiz. Kod değiştirilmedi; `karadul analyze` ve test
> suite koşturulmadı (yalnız `pytest --collect-only`).
> **Taban:** `main` HEAD `2304560`. Tüm satır numaraları `git show 2304560:karadul/stages.py`
> kopyasına göredir (5579 satır, md5 `67771a2f155f95eda3c8b3eb28181dca`). Analiz sürerken HEAD
> `accd1b2`'ye ilerledi (`810b4ca`, `ee494a8`, `accd1b2`). Bu commit'lerin hiçbiri
> `karadul/stages.py`'ye dokunmuyor (`git log 2304560..HEAD -- karadul/stages.py` boş).
> **Satır numarası uyarısı:** Analiz sırasında FLIRT ajanı çalışma ağacında
> `StaticAnalysisStage.execute` içindeki FLIRT yükleme bloğunu değiştirdi (net −66 satır).
> `ReconstructionStage` içeriği HEAD ile aynı, ancak satırları ~66 kaydı (ör. `_execute_binary`
> HEAD'de 2915–5049, çalışma ağacında 2849–4983). **Uygulamada sembol adları esastır; satır
> numaraları yalnız yardımcı bilgidir.**

### 00.1 Özet

1. **Bayrak fiilen emekli.** `_execute_binary` girişindeki coerce bloğu (`ec59ebc`),
   `use_step_registry=False` gelirse uyarı basıp değişkeni `True` yapıyor. Bu yüzden
   fonksiyondaki bütün `else` dalları ve bayrağa bağlı kod statik olarak **ulaşılamaz**.
2. **Phase 2 zaten step'lerde koşuyor:**
   `runner_phase2 = ["feedback_loop", "computation_struct_recovery", "struct_recovery"]`. Monolith
   geri besleme döngüsü `range(0)` ile hiç dönmüyor (`8d9a0e4`). "Phase 2'yi step'lere taşı"
   maddesinin bugünkü anlamı üç iş: ölü döngüyü silmek, canlı mükerrer blokları kaldırmak ve step
   yolunda eksik kalan **tek** özelliği (MAJOR-1) taşımak.
3. **`_execute_binary` = 2135 satır.** 1425'i ölü, 117'si yalnız ölü döngüye hizmet eden kurulum,
   270'i canlı ama mükerrer ya da maskeleyen monolith kodu.
4. **Legacy Phase 1 metot kümesi** (14 metot + 3 modül yardımcısı, ~1180 satır) yalnız ölü `else`
   dalından çağrılıyor. Bunlara doğrudan bağlı test sayısı **34**; §0'daki "25'in ~11'i" tahmini
   eksikti. Dağılım: parity dosyasında 8, `test_stages_algorithm_engineering_split.py`'de 10,
   `test_stages_calibrate_split.py`'de 16.
5. **Önceki planlarda olmayan bulgular** (kanıtlar §00.3):
   - **L1, istatistik maskeleme:** Döngü sonrası üç satır, `feedback_loop` step'inin
     `pipeline_iterations_run` / `pipeline_iteration_details` / `timing_pipeline_loop` değerlerini
     `0` / `[]` / `~0.0` ile eziyor. Gerçek koşuda rapor 0 iterasyon diyor, oysa diskte
     `src_iter1/merged_iter1/typed_iter1` var.
   - **L3, ikinci struct recovery:** Phase 2'deki `struct_recovery` step'inden sonra aynı
     `StructRecoveryEngine` ikinci kez koşuyor. Girdi ve çıktı dizini aynı
     (`reconstructed/struct_recovered`) ve `rglob` ilk koşunun `originals/` yedeklerini de girdi
     alıyor. Gerçek koşuda `rewritten_files` 294 kayıt, bunların yalnız 147'si benzersiz.
   - **L2, mükerrer M4 blokları:** cfg_iso ve fusion varsayılan açık ve Phase 1 step'lerinin
     ikinci kopyası olarak koşuyor. `extracted_names`'e yaptıkları enjeksiyonu sonraki hiçbir adım
     tüketmiyor.
   - **MAJOR-1 regresyonu:** Manuel override'ın merge SONRASI mutlak zorlaması (`a8b0acb`,
     2026-07-14) yalnız ölü döngünün içinde duruyor. 2026-07-17'den (`8d9a0e4`) beri varsayılan
     yolda uygulanmıyor; `karadul/pipeline/steps/` altında override referansı yok.
   - **MaxSMT kablolaması:** Opt-in `--maxsmt-struct` adaylarını `StructRecoveryEngine`'e taşıyan
     tek yol L2+L3. Step yolunda `recovered_struct_candidates` üretiliyor ama hiçbir step onu
     tüketmiyor.
6. **Orkestrasyon test dışında.** Hiçbir test `_execute_binary(...)` çağırmıyor ya da
   `PipelineRunner`'ı patch'lemiyor. Seed anahtarları, step listeleri ve stats birleştirme
   doğrulanmıyor. Geçmişte tam bu bölgede bir seed-anahtarı hatası (`final_decompiled_dir`)
   yaşandı.

### 00.2 Kanıt komutları (tekrar üretilebilir)

- **Commit geçmişi:** `git log --format='%h %ad %s' --date=short -- karadul/stages.py`.
  2026-07-16 sonrası stages.py'ye dokunan commit'ler:
  - `8d9a0e4` (07-17): döngü guard'ı
  - `ec59ebc` (07-18): Phase 3 monolith silindi + coerce
  - `bce0a2a` (07-19): R5, 4 sessiz except → debug
  - `61f6bba` (07-21): JVM/.NET/APK/PyInstaller yönlendirmesi

  `61f6bba..HEAD` aralığında stages.py'ye dokunan commit yok.
- **Blok haritası:** `_execute_binary` gövdesindeki üst düzey ifadelerin AST dökümü
  (`lineno`/`end_lineno`).
- **Def-use:** Döngü sonrası bölgede okunup ondan önce tanımlanan adlar (AST `Name`, Load/Store).
- **Çağrı grafı:** `self.<metot>(...)` ve modül fonksiyonu çağrıları (AST). Dış referanslar için
  `grep -rnw <sembol> karadul/ tests/ scripts/ tools/ benchmarks/ docker/`.
- **Test eşlemesi:** Test fonksiyonlarındaki `Attribute`/`Name` referansları (AST); test sayıları
  `pytest -q --collect-only` ile.
- **Ampirik kanıt (salt okuma):** FLIRT ajanının 2026-09-25 tarihli iki `cat` koşusu,
  `/private/tmp/flirt_debug/{before_cat,ctrl_cat}/workspaces/cat/<ts>/`. Dizin geçici olduğu için
  sayılar bu bölüme kopyalandı. Çalışma ağacındaki FLIRT farkı yalnız `StaticAnalysisStage`'e
  dokunuyor. Koşuların alındığı andaki ağaç durumu doğrulanamadı, ancak burada kullanılan
  gözlemler iki koşuda birebir aynı çıktı (farklı FLIRT kodu olsa bile).

### 00.3 Kalan monolitik kod envanteri

#### A. `ReconstructionStage._execute_binary` blok haritası (HEAD 2915–5049)

| Kod | Blok | HEAD satır | Satır | Durum | Kanıt / not |
|---|---|---|---|---|---|
| A1 | Coerce: `use_step_registry=False` → uyarı + `True` | 2954–2967 | 14 | canlı | Bayrak emekliliğinde (M5) gider |
| A2 | `if _use_step_registry:` gövdesi: Phase 1 runner (17 step) + köprü + Phase 2 öncesi tohum + Phase 2 runner (3 step) | 2968–3128 | 161 | **canlı çekirdek** | Kalır |
| D1 | `else:` legacy Phase 1 (`_load_binary` + 6 `_run_*` çağrısı) | 3129–3186 | 58 | **ölü** | A1 yüzünden ulaşılamaz |
| A3 | İkinci `_seed_recovery_pre_names` çağrısı → `_manual_overrides_map` | 3188–3198 | 11 | canlı, çıktısı tüketilmiyor | Dönüş değeri yalnız D3 içinde (HEAD 4168) okunuyor. `extracted_names` üzerindeki etkisini yalnız L2 enjeksiyonu görüyor, o da tüketilmiyor. Okuduğu dizin ham Ghidra çıktısı olduğundan silinmesi stats açısından nötr |
| D2 | Assembly: `if _use_step_registry: pass` / `else: AssemblyAnalyzer…` + ölü `_step_start` | 3200–3297 | 98 | **ölü** (`else`) | `TargetType`'ın `_execute_binary`'deki iki kullanımından biri burada (3234) |
| Z1 | Döngü öncesi kurulum: `_cg_neighbors`, `rglob`, `ComputationRecoveryEngine` / `CVariableNamer` / `CTypeRecoverer` ön-örnekleme | 3299–3406 | 108 | canlı, işlevsiz | Döngü sonrası yalnız `_iteration_stats` ve `_loop_start` okunuyor (L1). Kurucular yan etkisiz: yalnız atama + `threading.Lock` |
| Z2 | Guard: `_loop_iterations = 0 if _use_step_registry else _max_iterations` | 3408–3416 | 9 | her zaman 0 | `8d9a0e4` |
| D3 | Monolith geri besleme döngüsü `for _pipeline_iter in range(_loop_iterations)` | 3417–4667 | 1251 | **ölü** (`range(0)`) | Import/çağrı adı taraması ve FIX/MAJOR/tarih işaretli yorum taraması yapıldı: step modüllerinde karşılığı olmayan **tek** mantık MAJOR-1 (HEAD 4165–4170). `8d9a0e4` bu döngüyü 3 binary'de guard açık/kapalı bit-birebir doğruladı |
| L1 | Döngü sonrası `stats["pipeline_iterations_run"]`, `["pipeline_iteration_details"]`, `["timing_pipeline_loop"]` + log | 4669–4675 | 7 | **canlı, maskeleyen** | Step'in `feedback_loop.py` içinde yazdığı değerleri ezer. Kanıt: `pipeline_iterations_run=0` ve `timing_pipeline_loop=0.0`, ama `feedback_loop_duration_s=8.09` ve `_iter1` dizinleri mevcut |
| L2 | M4 monolith: cfg_iso (varsayılan **açık**), fusion (varsayılan **açık**), MaxSMT (varsayılan kapalı), fusion → `extracted_names` enjeksiyonu | 4677–4862 | 186 | **canlı, mükerrer** | Phase 1'deki `cfg_iso_match`/`computation_fusion` ve Phase 2'deki `computation_struct_recovery` step'lerinin ikinci kopyası; stats'ı ezer. Phase 3 seed'inde `extracted_names` yok ve hiçbir Phase 3 step'i onu `requires` etmiyor |
| L3 | Monolith struct recovery, ikinci koşu | 4864–4940 | 77 | **canlı, mükerrer, zararlı** | Girdi = step çıktısı = çıktı dizini (`struct_recovered`). `recover()` `rglob("*.c")` ile `originals/` yedeklerini de işliyor ve `originals/`'a birinci koşunun çıktısını yazıyor. Rewrite > 0 olan binary'lerde yedek artık orijinal olmaz (kod okuması; cat'te rewrite 0). Kanıt: `struct_recovered` 147 + 147 (`originals/`), `rewritten_files` 294/147 benzersiz. Step'in girebileceği ara dizinlerin (`src*`, `merged*`, `typed*`) hepsi 147 dosyalı ve alt dizinsiz |
| A4 | Phase 3 runner (10 step) + stats/errors/artifacts birleştirme + `return` | 4942–5030 | 89 | **canlı çekirdek** | Seed 17 anahtar |
| D4 | Defansif `raise NotImplementedError` | 5032–5049 | 18 | **ölü** | Coerce kalkana kadar mypy dönüş garantisi olarak kalsın (M5) |

Toplamlar:
- Ölü (D1–D4): **1425** satır.
- Ölü döngüye hizmet eden (Z1–Z2): **117** satır.
- Canlı ama mükerrer/maskeleyen (L1–L3): **270** satır.
- Kalan 323 satır: çekirdek (A2 + A4 = 250), docstring/kurulum (39), A1 (14), A3 (11), boş (9).

Ek olarak `deob_dir` yereli hiç okunmuyor (zaten ölü atama). `target` yalnız D2'de okunuyor.
`reconstructed_dir` ise canlı olarak yalnız L3'te okunuyor.

#### B. Yalnız D1'den çağrılan legacy metot kümesi (üretimde başka çağıran yok)

Çağrı grafı (AST):
- `_execute_binary` (D1) → `_load_binary`, `_run_signature_matching`, `_run_byte_pattern_matching`,
  `_run_anti_debug_and_packer`, `_run_pcode_analysis`, `_run_cfg_analysis`,
  `_run_algorithm_engineering`
- `_run_algorithm_engineering` → `_run_parallel_analysis`, `_merge_analysis_results`,
  `_calibrate_and_clamp`, `_apply_capa_naming`
- `_calibrate_and_clamp` → `_run_confidence_calibration`, `_write_merged_algorithms`,
  `_apply_match_budget`
- `_apply_match_budget` → modül yardımcıları: `_match_budget_total`, `_collect_tagged_matches`,
  `_match_budget_sort_key`

Dış referans taraması (`karadul/` içinde stages.py dışı, `scripts/`, `tools/`, `benchmarks/`,
`docker/`): **sıfır**. `karadul/analyzers/cpp_rtti.py`'deki `_load_binary` başka bir sınıfa ait.

| Sembol | HEAD satır | Satır | Canlı karşılığı (step) | Onu doğrudan test eden test |
|---|---|---|---|---|
| `_load_binary` | 1300–1513 | 214 | `binary_prep` + `ghidra_metadata` | parity: `test_load_binary_parity`, `test_load_binary_short_circuit_when_no_c_files` |
| `_run_signature_matching` | 1524–1578 | 55 | `ghidra_metadata` (sig) | parity: `test_run_signature_matching_parity`, `test_run_static_phase1_methods_exist` |
| `_run_byte_pattern_matching` | 1580–1684 | 105 | `byte_pattern` | parity: `test_run_byte_pattern_matching_parity`, `…_methods_exist` |
| `_run_anti_debug_and_packer` | 1686–1798 | 113 | `anti_debug` + `packer_fingerprint` | yok |
| `_run_pcode_analysis` | 1800–1892 | 93 | `pcode_cfg_analysis` | parity: `test_run_pcode_analysis_parity`, `…_methods_exist` |
| `_run_cfg_analysis` | 1894–1930 | 37 | `pcode_cfg_analysis` | parity: `test_run_cfg_analysis_parity`, `…_methods_exist` |
| `_run_algorithm_engineering` | 1932–1955 | 24 | `algorithm_id` + `parallel_algo_eng` + `confidence_filter` | parity: `test_run_algorithm_engineering_parity`, `…_methods_exist`. alg-eng: `test_full_pipeline_all_disabled`, `test_run_algorithm_engineering_is_thin_coordinator`, `test_dalga_6a_methods_exist` |
| `_run_parallel_analysis` | 1957–2119 | 163 | `parallel_algo_eng` | alg-eng: `test_run_parallel_analysis_all_skipped` (+ exists/thin) |
| `_merge_analysis_results` | 2121–2170 | 50 | `parallel_algo_eng` | alg-eng: 3 test (+ exists/thin) |
| `_calibrate_and_clamp` | 2172–2195 | 24 | `confidence_filter` | alg-eng: `test_calibrate_and_clamp_no_eng_result`. calibrate: 5 test |
| `_run_confidence_calibration` | 2197–2284 | 88 | `_confidence_helpers.run_calibration` (**doğrudan testi yok**) | calibrate: 2 test (+ exists/thin/order) |
| `_write_merged_algorithms` | 2286–2313 | 28 | `_confidence_helpers.run_merge` (**doğrudan testi yok**) | calibrate: 3 test |
| `_apply_match_budget` | 2315–2356 | 42 | `_confidence_helpers.run_match_budget` (testi var) | calibrate: 3 test |
| `_apply_capa_naming` | 2358–2440 | 83 | `run_byte_pattern_merge` + `run_capa_merge` (testi var) | alg-eng: 2 test |
| Modül: `_match_budget_total`, `_collect_tagged_matches`, `_match_budget_sort_key` | 91–131 | 41 | `run_match_budget` içinde | calibrate: 3 yardımcı testi |

Toplam: 14 metot 1119 satır (yorumlarla 1300–2440 = 1141) + 41 satır modül yardımcısı, yani
**~1180 satır** ve 34 test.

#### C. Canlı kalacaklar (dokunulmaz)

- `_prepare_workspace`
- `_seed_recovery_pre_names` ve yardımcıları: `_recover_main_from_entry`,
  `_recover_gnulib_from_fingerprints` (disambiguation dahil), `_recover_elf_boilerplate`,
  `_apply_manual_overrides`, `_find_decompiled_dir`
- `execute`, `_execute_app_bundle`, `_execute_go_binary`, `_execute_analyzer_reconstruct`,
  `_execute_js`, `_merge_stage_results` (metot ve modül fonksiyonu)
- Modül `_inject_capa_comments`: canlı Phase 3 step'i `steps/capa_annotation.py` bunu
  `karadul.stages`'ten import ediyor.

#### D. İskele ve yan kalemler

| Kalem | Durum |
|---|---|
| `karadul/pipeline/reconstruction_context.py` (232 satır) | `_prepare_workspace` yalnız `start/stage_name/artifacts/stats/errors/dirs/workspace_dir/binary_path/static_dir/reconstructed_dir` alanlarını dolduruyor; diğer alanları yalnız legacy metotlar kullanıyor. `ReconLoopState` ve `ensure_loop_state`'in üretimde kullanımı yok; yalnız parity'deki 5 dataclass testi kullanıyor. Modül docstring'i bayat ("3173 satır") |
| `_inject_capa_comments` (HEAD 5466–5579, 114 satır) | `steps/_capa_comment_inject.py:22–135` ile AST-özdeş (docstring hariç). Kopya |
| `_collect_all_algorithms` (HEAD 81–88) | stages.py'de yalnız L3 kullanıyor. Step'lerde 3 ayrı kopyası var (`semantic_naming`, `struct_recovery`, `deep_tracing`). `test_v192_fixes.py`'deki 4 test modül-seviyesi varlığını doğruluyor |
| Kullanılmaz kalacak importlar | M1 sonrası: `os`, `shutil`, `tempfile`, `CPU_PERF_CORES`; `as_completed` zaten kullanılmıyor. M2 sonrası: `ThreadPoolExecutor`, `_TARGET_PLATFORM_MAP`. `test_v192_fixes.py`'deki 2 test sonuncusunun stages modülünde bulunmasını doğruluyor |
| Bayat yorumlar | `_execute_binary` docstring'i ("Faz 4", `_use_step_registry=False` yolu). HEAD 2943–2949: "Feature flag False default", "Phase 2 eski yolda kalir". HEAD 4942–4946: "Eski Phase 3 kodu (L3405-3933)". `karadul/ghidra/headless.py` içindeki "use_step_registry=False olan koşumlarda" yorumu. ADR-006 durumu ("uygulama bekletiliyor") |
| `scripts/mac_f1_eval.py` | HEAD'de `sys.path`'e var olmayan `/Users/apple/Desktop/black-widow` yolunu ekliyor. Analiz sırasında başka bir ajan bunu çalışma ağacında depo köküne göre düzeltiyordu (commit'lenmemiş). M0'da düzeltmenin commit'lendiği teyit edilmeli |
| `--output-dir` tuzağı | `cli.py` bu seçenekle `cfg.project_root`'u değiştiriyor. HEAD'de `sigs/` (`signature_db.py`), ngram DB (`_feedback_typing_extras.py`) ve `workspaces/` bu kökten aranıyor. Sonuç: `--output-dir` ile yapılan koşular imza ve ngram DB'si olmadan çalışabilir. Analiz sırasında çalışma ağacında bu sorunu hedefleyen geçici bir `config.py` değişikliği (`signature_search_roots`) görüldü, sonra geri alındı; sonuç FLIRT işine bağlı. Parity betiği bu yüzden `--output-dir` **kullanmaz** (§00.6) |

#### E. Test eşlemesi ve gizli bağımlılıklar

Test sayıları `pytest --collect-only` ile doğrulandı.

`tests/test_stages_split_parity.py` = **25** test:
- **8**'i legacy metotlara bağlı (B tablosu)
- 1 canlı metot testi: `test_prepare_workspace_parity`
- 5 dataclass testi + 1 `byte_pattern_names` alan testi
- 5 golden fixture yapı testi (`skipif`) + 1 `@skip` yer tutucu
  (`test_execute_binary_artifact_parity_golden`)
- 4 normalize testi

`tests/test_stages_algorithm_engineering_split.py` (**10**) ve `tests/test_stages_calibrate_split.py`
(**16**) dosyalarındaki testlerin tamamı legacy metotlara bağlı.

Silme sırasında kırılacak, ilk bakışta görünmeyen bağımlılıklar:

| Test | Neden kırılır | Faz |
|---|---|---|
| `test_v160_fixes.py` → `test_reconstruction_stage_execute_binary_no_unbound` | `TargetType`'ın `_execute_binary.__code__.co_names` içinde olmasını istiyor; iki kullanım da D2 ve D3'te | M1 |
| `test_v192_fixes.py` → `TestStagesModuleLevelHelpers`, 2 `_TARGET_PLATFORM_MAP` testi | Import kullanılmaz kalıp silinirse | M2 |
| `test_v192_fixes.py` → `TestStagesModuleLevelHelpers`, 4 `_collect_all_algorithms` testi | L3 gidince fonksiyon silinirse | M6 (M4'te fonksiyon bırakılır) |
| `test_step_capa_annotation.py:59` | Patch hedefi `karadul.stages._inject_capa_comments` | M6 (yalnız kopya birleştirilirse) |
| `test_computation_integration.py:405` | CLI seçeneği `experimental_step_registry`'nin varlığını doğruluyor | M5 |
| `test_step_registry.py` (varsayılan-True ve `test_yaml_override`), `test_pipeline_e2e.py` (yer tutucu `test_step_registry_vs_monolith_equivalence` + 2 varsayılan testi) | Bayrak kalkarsa | M5 |
| `test_manual_overrides.py` | Sözleşme yorumları "çağıran merge sonrası zorlar" diyor; zorlama step'e taşınınca yorum güncellenmeli (davranış testleri kırılmaz) | M3 |

`_execute_binary`'yi çağıran ya da `PipelineRunner`'ı patch'leyen test: **yok**
(`grep "_execute_binary("` ve `grep PipelineRunner` ile `tests/` tarandı).

### 00.4 Önceki planların düzeltilen varsayımları

| Eski ifade | Bugünkü gerçek |
|---|---|
| "Phase 2 (feedback loop + struct recovery) step'lere taşınmadı" (§1, §6 Faz 3) | Taşındı ve `runner_phase2` ile koşuyor; inline döngü ölü. Kalan iş: ölü kodu silmek, L1–L3 mükerrerlerini kaldırmak ve MAJOR-1'i taşımak |
| "flag=False Phase 3'ü kaybeder, Phase 3 tek başına silinemez" (§0) | `ec59ebc` sonrası geçersiz. flag=False zaten coerce ediliyor; bütün `else` dalları ölü |
| "25 parity testinin ~11'i güncellenmeli" (§0) | 25'in **8**'i legacy'ye bağlı. İki dosyada **26** test daha var; toplam **34** |
| "`computation_fusion`/`cfg_iso`/`struct_recovery` monolith blokları kasıtlı, flag kapalıyken no-op" (§0) | cfg_iso, fusion ve struct_recovery varsayılan **açık**. Bloklar her koşuda step'lere ek olarak ikinci kez çalışıyor; L3 ayrıca zararlı (`originals/` ezilmesi) |
| "Tam emeklilik ~1350 satır" (§0) | `_execute_binary` içindeki ölü + ölüye hizmet eden kod 1542 satır, legacy küme ~1180 satır. Canlı mükerrerlerle birlikte stages.py 5579 → **~2400** (HEAD bazında) |
| ADR-006: "FIX-1/2/3/5 yalnız inline'da" | FIX-1/2/3 ve override tohumu `_seed_recovery_pre_names` ile Phase 2'nin ÖNCESİNE taşındı (`7c83288`). Inline'da yalnız FIX-5'in **ikinci aşaması** (merge sonrası zorlama) kaldı → M3 |

### 00.5 Fazlı plan (M0–M6)

**Genel kurallar**

- stages.py'ye dokunan fazlar (M1–M6) **sıralıdır**; aynı anda tek ajan çalışır. M0 yalnız yeni
  dosya yazar.
- **Önkoşul (M0 dahil):** Şu an paralel çalışan FLIRT, ölçüm zemini ve pycdc ajanları işlerini
  commit'lemiş olmalı ve `git status --short karadul/` boş olmalı. FLIRT değişiklikleri imza
  yüklemeyi, dolayısıyla isimlendirme çıktısını değiştirdiği için A/B tabanı ancak sakin bir ağaçta
  alınabilir.
- Her faz tek commit olarak yapılır (en fazla kod + test olmak üzere iki commit). Geri dönüş:
  `git revert <sha>`.
- Her fazın doğrulaması: tam suite (mevcut sayılar ± fazın beyan ettiği ekleme/silme), `ruff` +
  `mypy karadul/stages.py`, **§00.6 A/B parity** (cat/cut/wc).
- Ajan prompt'larındaki `## Files you may edit` / `## Do not edit` alanları aşağıdaki listelerden
  aynen kopyalanır.

#### M0 — Güvenlik ağı: A/B parity betiği + orkestrasyon testi (üretim kodu değişmez)

- **Tema:** ölçüm ve koruma altyapısı.
- **Files you may edit:** `scripts/stages_parity_ab.py` (yeni), `tests/test_execute_binary_wiring.py`
  (yeni).
- **Do not edit:** `karadul/**` ve mevcut testler.
- **Kalemler:**
  1. `scripts/stages_parity_ab.py`'yi §00.6'daki taslağa göre yaz.
  2. Gürültü tabanını ölç: HEAD'de cat/cut/wc ×2 koşu. Normalize edilmiş fark 0 olana kadar
     normalizer'ı genişlet. HARD kapı dosyalarında gerçek non-determinizm varsa DUR ve raporla.
  3. `tests/test_execute_binary_wiring.py`'yi yaz. `karadul.pipeline.runner.PipelineRunner`'ı sahte
     bir runner ile değiştir; `_execute_binary` sınıfı çağrı anında import ettiği için modül
     özniteliğini patch'lemek yeterli. Gerçek `Config()` ve tmp `Workspace` kullan. Sabitlenecekler:
     - (a) üç runner'ın step listeleri (17 / 3 / 10);
     - (b) Phase 2 seed'inin Phase 1 artifact'larına eşit olması;
     - (c) Phase 3 seed'inin anahtar kümesi (17 anahtar);
     - (d) stats/errors/artifacts birleştirmesi ve `success = len(artifacts) > 0`;
     - (e) flag=False → uyarı + aynı yol;
     - (f) her runner'da `RuntimeError` → `success=False`.
  4. Bugünkü kusurları **karakterizasyon** olarak sabitle; her birine "M4'te tersine dönecek" notu
     düş:
     - L1: Phase 2 sahte stats'ında `pipeline_iterations_run=2` verilse bile sonuç 0 çıkıyor.
     - L3: monolith'ten `StructRecoveryEngine.recover` çağrılıyor ve `decompiled_dir == output_dir`.
     - L2: fusion/cfg_iso spy'ı çağrılıyor.
- **Etkilenen testler:** yok.
- **Risk:** DÜŞÜK. **Geri dönüş:** iki yeni dosyayı sil.
- **Doğrulama:** Yeni test geçer; tam suite'e yalnız yeni testler eklenir; HEAD-vs-HEAD betik
  farkı 0.

#### M1 — `_execute_binary` içindeki ulaşılamaz blokları sil (sıfır fark)

- **Files you may edit:** `karadul/stages.py`, `tests/test_v160_fixes.py`.
- **Do not edit:** diğer her şey.
- **Silinecekler:**
  - D1;
  - D2'nin tamamı (ölü `_step_start` ataması dahil);
  - D3 (`_refresh_rglob_cache` kapanışı dahil);
  - Z1 (L1'in okuduğu `_iteration_stats` ve `_loop_start` tanımları hariç) ve Z2;
  - kullanılmaz kalan yereller: `target`, `deob_dir` ve 11 köprü okuması (`_cfg_result`,
    `_file_cache`, `_pcode_naming_candidates`, `binary_for_byte_match`, `byte_pattern_names`,
    `c_files`, `calibrated_matches`, `decompiled_json`, `fid_json`, `output_dir`, `pcode_json`);
  - kullanılmaz kalan importlar: `os`, `shutil`, `tempfile`, `CPU_PERF_CORES`, `as_completed`
    (ruff ile teyit edilir).
- **Dokunma:** A1, iki `if _use_step_registry:` sarmalayıcısı, D4 (M5'e kadar mypy dönüş
  garantisi), A3 (M3), L1–L3 (M4), legacy metotlar (M2).
- **Test güncellemesi:** `test_reconstruction_stage_execute_binary_no_unbound` içindeki
  `co_varnames` iddiası kalır; testin asıl amacı UnboundLocalError koruması. `co_names` iddiası
  `ReconstructionStage.execute`'a taşınır ya da düşürülür.
- **Not:** `_a["..."]` köprü okumalarının silinmesi, bir Phase 1 step'i beyan ettiği anahtarı
  üretmediğinde oluşacak örtük `KeyError`'ı da kaldırır; runner yalnız fazladan anahtarı yakalıyor.
  Davranış yalnız bu varsayımsal durumda değişir ve step sözleşme testleri bu durumu zaten kapsıyor.
- **Beklenen:** `_execute_binary` 2135 → ~600 satır; stages.py'de ~−1540 satır.
- **Risk:** DÜŞÜK. Kod statik olarak ulaşılamaz; D3 zaten `8d9a0e4`'te 3 binary'de bit-birebir
  doğrulandı.
- **Geri dönüş:** `git revert`.
- **Doğrulama:** ruff/mypy; tam suite; wiring testi **değişmeden** geçmeli; A/B tüm kapılarda
  sıfır fark. İsteğe bağlı: `pytest tests/test_varname_f1_baseline.py -m benchmark`.

#### M2 — Legacy Phase 1 metot kümesini ve bağlı testleri emekliye ayır (sıfır fark)

- **Files you may edit:** `karadul/stages.py`, `tests/test_stages_split_parity.py`,
  `tests/test_stages_algorithm_engineering_split.py` (silinir), `tests/test_stages_calibrate_split.py`
  (silinir), `tests/test_v192_fixes.py`, `tests/test_confidence_helpers.py` (yeni).
- **Do not edit:** `karadul/pipeline/**`.
- **Silinecekler (stages.py):**
  - B tablosundaki 14 metot ve 3 modül yardımcısı;
  - kullanılmaz kalan `ThreadPoolExecutor` ve `_TARGET_PLATFORM_MAP` importları;
  - "v1.12.0 Faz 3 split … KESE-YAPIŞTIR" yorum başlığı.
- **Kapsam taşıma:** Canlı karşılığının doğrudan testi olmayan 5 davranış,
  `tests/test_confidence_helpers.py`'ye uyarlanarak taşınır:
  - `run_calibration`: eng_result yok / boş;
  - `run_merge`: eng_result yok / artifact yazar / kalibre edilmişleri içerir.
- **Test güncellemesi:**
  - Parity dosyasından 8 test silinir. `_build_context_and_stage_from_golden` yalnız
    `test_prepare_workspace_parity` için kalır.
  - İki split dosyası (26 test) silinir.
  - `test_v192_fixes.py`'deki 2 `_TARGET_PLATFORM_MAP` testi
    `karadul.core.platform_map.TARGET_PLATFORM_MAP`'e yeniden hedeflenir.
- **Canlı kapsam zaten var:** `test_step_ghidra_metadata`, `test_step_byte_pattern`,
  `test_step_anti_debug`, `test_step_packer_fingerprint`, `test_step_pcode_cfg`,
  `test_step_algorithm_id`, `test_step_parallel_algo_eng`, `test_step_confidence_filter`.
- **Beklenen:** stages.py'de ~−1180 satır; testlerde −34 +~5. Tam suite'teki fark bu sayılarla
  birebir açıklanmalı.
- **Risk:** DÜŞÜK.
- **Geri dönüş:** `git revert` (silinen testler de geri gelir).
- **Doğrulama:** ruff/mypy; tam suite; wiring testi; A/B sıfır fark.

#### M3 — MAJOR-1: manuel override zorlamasını step yoluna taşı (bilinçli davranış onarımı)

- **Neden:** `_apply_manual_overrides` iki aşamalı bir sözleşme tanımlıyor: (1) tohum, (2) merge
  SONRASI koşulsuz zorlama. İkinci aşama yalnız D3'te duruyor ve `8d9a0e4`'ten beri varsayılan
  yolda uygulanmıyor, yani bindiff/refdiff/Bayes merge override'ı eritebilir. **Gerçek bir
  binary'de erimenin oluşup oluşmadığı ölçülmedi.** `~/.karadul/overrides/` şu an boş.
- **Files you may edit:** `karadul/stages.py`, `karadul/pipeline/steps/feedback_loop.py`,
  `karadul/pipeline/steps/_feedback_loop_iter.py`, `karadul/pipeline/steps/_feedback_naming.py`,
  `karadul/pipeline/steps/_feedback_naming_merger.py`, `tests/test_step_feedback_loop.py` (veya yeni
  `tests/test_manual_override_step_force.py`), `tests/test_manual_overrides.py` (yalnız yorumlar).
- **Kalemler:**
  1. stages.py: Phase 2 öncesindeki **ilk** `_seed_recovery_pre_names` çağrısının dönüş değerini
     yakala ve Phase 2 seed'ine `manual_overrides_map` olarak ekle. A3'ü (ikinci çağrı) sil.
  2. `FeedbackLoopStep.run` içinde `ctx.artifacts.get("manual_overrides_map") or {}` oku. Anahtarı
     `requires`'a **ekleme**, çünkü mevcut step testleri seed'siz koşuyor. `produces` değişmez.
  3. `_feedback_loop_iter` → `run_naming_phase` → `run_name_merger` zincirine opsiyonel bir
     parametre ekle (varsayılan `None`).
  4. `run_name_merger` içinde, boş/kısa anahtar filtresinden SONRA ve `_apply_aho_replace`'ten ÖNCE
     koşulsuz `final_naming_map[addr] = name` uygula. Mantık `a8b0acb`'deki satırlarla birebir
     aynı olmalı (`addr and len(addr) >= 2 and name`).
  5. Testler:
     - (a) merger sonucu override'ı ezse bile final map'te override kazanır;
     - (b) override yoksa sonuç değişmez;
     - (c) wiring testinde seed'de anahtar bulunur ve `_seed_recovery_pre_names` bir kez çağrılır.
- **Risk:** ORTA. İsimlendirme yoluna dokunuyor; override yoksa no-op.
- **Geri dönüş:** `git revert`.
- **Doğrulama:**
  - Override YOK → A/B tüm kapılarda sıfır fark.
  - Override VAR → `--overrides <tmp.json>` ile koş (biçim:
    `{"overrides": {"FUN_xxx": {"name": "..."}}}`; CLI bu seçeneği
    `binary_reconstruction.overrides_path`'e bağlıyor). A tabanında pipeline'ın zaten
    isimlendirdiği 2–3 `FUN_` adresine cat'te analist ismi ver. B'de clean `naming_map.json` ve
    ilgili `.c` dosyalarında analist isimleri **bulunmalı**. A–B farkı yalnız bu adresler ve onları
    çağıran dosyalardaki isim değişimleri olabilir; fazın beyan edilmiş farkı budur.

#### M4 — Canlı mükerrer ve maskeleyen monolith bloklarını kaldır: L1, L2, L3 (farklar önceden beyan edilir)

- **Önkoşul:** K1 (MaxSMT) ve K2 (L2'deki eski "Berke kararı" yorumu) yanıtlanmış olmalı.
- **Files you may edit:** `karadul/stages.py`, `karadul/pipeline/steps/struct_recovery.py`
  (yalnız K1=A ise), `tests/test_step_struct_recovery.py` (K1=A ise),
  `tests/test_execute_binary_wiring.py` (M0'daki karakterizasyon beklentilerini tersine çevir).
- **Silinecekler:**
  - L1 ve M1'de bırakılan `_iteration_stats` / `_loop_start`;
  - L2'nin tamamı;
  - L3. Bundan sonra Phase 3 seed'indeki `decompiled_dir` doğrudan Phase 2'nin
    `struct_recovery_decompiled_dir` değeri olur. Kullanılmaz kalan `reconstructed_dir` yereli ve
    onun `assert`'i de silinir.
  - `_collect_all_algorithms` stages.py'de kullanılmaz kalır ama testleri yüzünden **M6'ya kadar
    bırakılır**.
- **K1=A ise:** `StructRecoveryStep`, `recovered_struct_candidates`'ı opsiyonel olarak okur ve
  L3'teki aday → dict dönüşümünü (name/size/fields/source) birebir `computation_structs`'a ekler.
- **Beyan edilen beklenen farklar (allowlist):**
  - `stats.pipeline_iterations_run` (0 → gerçek sayı), `stats.pipeline_iteration_details`,
    `stats.timing_pipeline_loop`;
  - `stats.cfg_iso_matched_functions`, `stats.computation_fusion_matches`,
    `stats.computation_fusion_accepted` (artık step değerleri; eşit olmaları beklenir ama
    ölçülmedi);
  - `stats.computation_fusion_injected` (kaybolur);
  - `stats.computation_struct_*` (yalnız MaxSMT açıkken);
  - `stats.structs_enriched`, `stats.field_access_rewrites`, `stats.timing_struct_recovery`;
  - `reconstructed/struct_recovered/originals/**` (artık gerçek orijinaller);
  - `struct_recovered/struct_recovery.json` (cat'te `rewritten_files` 294 → 147);
  - `struct_recovered/types.h` (olası).
- **Hard gate (sıfır fark):** clean `naming_map.json`, `reconstructed/src*/naming_map.json`,
  `param_naming_map.json`. `.c` kaynaklarında `field_access_rewrites == 0` olan binary'lerde sıfır
  fark beklenir (cat'te 0). Rewrite > 0 olan binary'lerde her fark tek tek incelenir.
- **Risk:** ORTA.
- **Geri dönüş:** `git revert`.
- **Doğrulama:** tam suite; wiring testi (tersine çevrilmiş beklentilerle); A/B'de allowlist
  dışında sıfır fark. Ek A/B koşuları:
  - `field_access_rewrites > 0` üreten bir binary (aday M0'da seçilir; varname_bench/hashbench
    olabilir, ölçülmedi);
  - K1=A ise `--maxsmt-struct` açıkken bir koşu.

#### M5 — `use_step_registry` bayrağının tam emekliliği (yapısal düzleştirme)

- **Önkoşul:** FLIRT ajanının işi bitmiş ve commit'lenmiş olmalı (bu iş `stages.py`'ye, geçici
  olarak da `config.py`'ye dokundu). K3 yanıtlanmış olmalı.
- **Files you may edit:** `karadul/stages.py`, `karadul/config.py`, `karadul/cli.py`,
  `karadul/pipeline/__init__.py`, `tests/test_step_registry.py`, `tests/test_pipeline_e2e.py`,
  `tests/test_computation_integration.py`.
- **Kalemler:**
  1. stages.py'den A1 coerce'u, `_use_step_registry` değişkenini, iki `if _use_step_registry:`
     sarmalayıcısını ve D4 `raise`'ini kaldır; akış düzleşir. Yalnız girintisi değişen satırları
     `git diff -w` ile ayrıca incele.
  2. Bayat docstring ve yorumları güncelle (§00.3-D).
  3. `PipelineConfig.use_step_registry` için K3'e göre:
     - **deprecated seçeneği:** alan kalır ama okunmaz. `Config.load`, YAML'da
       `pipeline.use_step_registry: false` görürse bir kez uyarır. `--experimental-step-registry`
       bayrağı `hidden=True` bir no-op olur.
     - **tam silme seçeneği:** alan ve CLI bayrağı silinir. Dikkat: `Config.load` bilinmeyen
       anahtarı `if hasattr(cfg.pipeline, k)` ile **sessizce** yok sayıyor; uyarı eklenmezse eski
       YAML'lar sessizce etkisiz kalır.
  4. Varsayılan ve override testlerini K3'e göre güncelle. Yer tutucu
     `test_step_registry_vs_monolith_equivalence`'ı sil; işlevini A/B betiği üstleniyor.
     `test_computation_integration.py:405`'teki seçenek iddiasını K3'e göre güncelle.
- **Beklenen:** `_execute_binary` ~270 satırlık doğrusal bir akışa iner (3 runner + köprü + seed).
- **Risk:** DÜŞÜK-ORTA. config.py ve cli.py tehlikeli dosyalar; davranış ise coerce yüzünden zaten
  aynı.
- **Geri dönüş:** `git revert`.
- **Doğrulama:** tam suite; wiring testi; A/B sıfır fark; `karadul analyze --help` çıktısı K3 ile
  uyumlu.

#### M6 (opsiyonel) — İskele ve belge temizliği

- **Files you may edit:** `karadul/pipeline/reconstruction_context.py`, `karadul/stages.py`,
  `karadul/pipeline/steps/capa_annotation.py`, `tests/test_stages_split_parity.py`,
  `tests/test_step_capa_annotation.py`, `tests/test_v192_fixes.py`,
  `docs/adr/ADR-006-phase2-entanglement-cleanup.md`, `CHANGELOG.md`.
- **Kalemler:**
  1. `ReconstructionContext`'i `_prepare_workspace`'in doldurduğu alanlara indir. `ReconLoopState`,
     `ensure_loop_state` ve ilgili 5 dataclass testi + 1 alan testi gider.
  2. `_inject_capa_comments` gövdesini `steps/_capa_comment_inject`'ten yapılan bir re-export'a
     indir (AST-özdeş, −112 satır). `capa_annotation.py`'deki import'u ve
     `test_step_capa_annotation.py:59`'daki patch hedefini yeni modüle çevir.
  3. `_collect_all_algorithms`'i stages.py'den kaldır; 4 testi step kopyalarından birine yeniden
     hedefle.
  4. ADR-006 durumunu "uygulandı" yap. CHANGELOG'a iç refactor'u ve M3/M4'ün kullanıcıya görünen
     farklarını yaz.
- **Risk:** DÜŞÜK.
- **Doğrulama:** tam suite ve A/B sıfır fark.
- **Önerilmeyen:** `_execute_binary`'yi `_run_phase1/2/3` metotlarına bölmek. M5 sonrası ~270
  satırlık doğrusal akış okunur durumda; ek bölme yalnız churn üretir (Berke isterse M7).

**Faz özeti (HEAD bazında tahmini satır etkisi)**

| Faz | Tema | stages.py | Diğer dosyalar | Risk | Beklenen fark |
|---|---|---|---|---|---|
| M0 | Güvenlik ağı | — | 2 yeni | düşük | yok |
| M1 | Ulaşılamaz blokları sil | ~−1540 | 1 test | düşük | sıfır |
| M2 | Legacy metot kümesi + 34 test | ~−1180 | 5 test | düşük | sıfır |
| M3 | MAJOR-1 port | ~−8 | 4 step + 2 test | orta | override yoksa sıfır |
| M4 | L1/L2/L3 mükerrerleri | ~−275 | 0–2 step + 2 test | orta | beyan edilmiş stats + `struct_recovered` |
| M5 | Bayrak emekliliği + düzleştirme | ~−45 | config/cli/init + 3 test | düşük-orta | sıfır |
| M6 | İskele ve belge (opsiyonel) | ~−120 | 7 | düşük | sıfır |

Sonuç: stages.py 5579 → **~2400** satır, `_execute_binary` 2135 → **~270** satır. Bu HEAD bazında
bir tahmindir; FLIRT değişikliği ayrıca −66 satır getiriyor.

### 00.6 Davranış-nötrlük kanıt yöntemi

**İlke:** Karşılaştırma bayat bir golden'a karşı yapılmaz. Nisan 2026 tarihli golden fixture
(v1.11.x, yalnız JSON, `.c` yok) bugünkü pipeline'ı temsil etmiyor. Onun yerine her faz için aynı
makinede, aynı Ghidra, aynı imza DB'si ve aynı önbellek politikasıyla **önce (A) / sonra (B)**
koşusu yapılır.

**Protokol (her faz için)**

1. **Sakin ağaç:** Koşu süresince `karadul/` altına başka ajan yazmamalı. Betik her koşunun başında
   ve sonunda bir kod parmak izi alır: HEAD + `karadul/**/*.py` içerik hash'i + `git diff --stat`.
   Başı ve sonu farklıysa sonuç geçersizdir.
2. **Gürültü tabanı** (oturumda bir kez): aynı kodla A ve A2 koşulur; normalize fark **0**
   olmalıdır. HARD kapı dosyalarında fark kalırsa parity geçersizdir ve önce non-determinizm
   çözülür. SOFT dosyalarda kalan fark ancak belgelenmiş bir `noise` allowlist'ine girebilir.
3. Faz değişikliğinden **önce** A, sonra B koşulur ve faz allowlist'iyle `diff` alınır. M0, M1, M2,
   M5 ve M6'da allowlist **boştur**. M3 ve M4'te farklar koşudan önce yazılır ("beyan edilmiş fark"
   disiplini).
4. Kanıt repo dışında saklanır: `~/karadul_parity/<faz>/{A,B}/<binary>/` altında `meta.json` ve
   `diff_report.json`. Commit mesajına tek satır özet eklenir, ör. `parity: cat/cut/wc 0 fark
   (gürültü tabanı 0)`.
5. **İkincil kontroller:** `pytest tests/test_varname_f1_baseline.py -m benchmark` ve
   `scripts/mac_f1_eval.py cat cut wc` (F1 A == B olmalı; §00.3-D'deki `sys.path` notu geçerli).

**Karşılaştırılan çıktılar ve kapılar**

| Kapı | Dosyalar | Kural |
|---|---|---|
| HARD | `<clean>/naming_map.json`, `<ws>/reconstructed/src*/naming_map.json`, `<ws>/reconstructed/param_naming_map.json`, `<clean>/src/**`, `<ws>/reconstructed/project/**` | Normalize sonrası birebir aynı. Allowlist'e yalnız M3'teki override senaryosu girebilir |
| SOFT | `<ws>/reports/{report,pipeline_result}.json`, `report.sarif.json`, `report.md`, `<ws>/reconstructed/**` (ara dizinler dahil), `<ws>/static/**` | Normalize sonrası birebir aynı; fark yalnız faz allowlist'indeyse kabul edilir |
| HARİÇ | `*.log`, `<ws>/dynamic/**` (`--skip-dynamic`), gürültü tabanında normalize edilemediği kanıtlanan dosyalar (ör. gerekirse `report.html`) | Karşılaştırılmaz |

**Deterministik olmayan alanlar ve normalize kuralları**

Anahtar aileleri 2026-09-25 tarihli iki gerçek `cat` raporunun karşılaştırmasından ampirik olarak
çıkarıldı.

| Alan | Neden | Normalize |
|---|---|---|
| `total_duration`, `stages/*/duration_seconds`, `stats.*_duration_s`, `stats.timing_*`, `stats.ghidra_duration` | Süre | Değer → `<VOLATILE>` |
| `workspace_path`, `stages/*/artifacts/*`, metinlerdeki yollar | Zaman damgalı dizin: `<project_root>/workspaces/<ad>/<YYYYMMDD_HHMMSS>` | `<WS>`, `<OUT>`, `<CACHE>`, `<HOME>`, `<TMP>` |
| `report.json.generated_at`, ISO tarih-saat, `\d{8}_\d{6}` | Zaman | `<TS>` |
| `tempfile.mkdtemp` sonekleri | Rastgele | `<RND>` |
| UUID / `session_id` / `run_id` | Rastgele | `<UUID>`; `tests/test_stages_split_parity.py::_normalize_output` kuralları yeniden kullanılır |
| JSON anahtar sırası; bazı liste sıraları | `parallel_steps=True` (ThreadPool) tamamlanma sırası | `sort_keys=True`. Gürültü tabanında sıra farkı gösteren listeler adıyla `SET_LIKE` listesine alınıp sıralanır |
| Float kuyrukları | Toplama sırası | 6 ondalık basamak |
| `bsim_shadow.json` ve BSim sonuçları | Önbellek durumu (`bce0a2a` R2: ingest ile query farkı) | Her koşuya izole `KARADUL_CACHE_DIR`; `resolve_cache_root()` yalnız BSim DB'yi etkiliyor, LMDB imza DB'si `~/.karadul/signatures.lmdb`'de kalır. Yine farklıysa SOFT `noise` |
| Manuel override deposu | `~/.karadul/overrides/<sha256>.json`; env ile değiştirilemiyor | Ön kontrol: hedefin hash'i için dosya yoksa koş, varsa DUR. M3 senaryosu açık `--overrides` yolunu kullanır |

**Betik taslağı: `scripts/stages_parity_ab.py`** (M0'da yazılacak; burada yalnız taslak)

```python
#!/usr/bin/env python3
"""stages.py migrasyon fazları için davranış-nötrlük A/B (stages_split_plan.md §00.6).

  python scripts/stages_parity_ab.py run  --phase M1 --label A     # değişiklikten ÖNCE
  python scripts/stages_parity_ab.py run  --phase M1 --label B     # değişiklikten SONRA
  python scripts/stages_parity_ab.py diff --phase M1 --a A --b B [--allow allow_M4.json]
  # gürültü tabanı: aynı kodla --label A ve --label A2, sonra diff --a A --b A2
"""
REPO = Path(__file__).resolve().parents[1]
BINARIES = [Path(p).expanduser() for p in
            ("~/coreutils_gt/cat.stripped", "~/coreutils_gt/cut.stripped", "~/coreutils_gt/wc.stripped")]
ROOT = Path("~/karadul_parity").expanduser()                       # repo DIŞI

def code_fingerprint() -> dict: ...   # HEAD sha + karadul/**/*.py sha256 + `git diff --stat` hash

def run(phase, label, overrides=None):
    for b in BINARIES:
        d = ROOT / phase / label / b.stem; d.mkdir(parents=True)
        if not overrides:
            assert not (Path.home() / ".karadul/overrides" / f"{sha256(b)}.json").exists()
        # --output-dir KULLANMA: cfg.project_root'u değiştirir; HEAD'de sigs/, ngram DB ve
        # workspaces/ o kökten aranır. project_root = cwd = REPO (config varsayılanı).
        before = set((REPO / "workspaces").glob("*/*"))
        env = {**os.environ, "PYTHONHASHSEED": "0", "KARADUL_CACHE_DIR": str(d / "cache")}
        cmd = [sys.executable, "-m", "karadul", "analyze", str(b), "--skip-dynamic",
               "--output", str(d / "clean")] + (["--overrides", str(overrides)] if overrides else [])
        fp0 = code_fingerprint()
        subprocess.run(cmd, cwd=REPO, env=env, check=True, timeout=1800,
                       stdout=open(d / "run.log", "w"), stderr=subprocess.STDOUT)
        if code_fingerprint() != fp0:
            raise SystemExit("koşu sırasında kod değişti -> sonuç GEÇERSİZ")
        new = set((REPO / "workspaces").glob("*/*")) - before
        assert len(new) == 1, new                                   # sakin ağaç ön koşulu
        ws_orig = new.pop(); shutil.move(ws_orig, d / "ws")         # yalnız bu koşunun dizini
        write_json(d / "meta.json", {"phase": phase, "label": label, "binary_sha256": sha256(b),
                   "code": fp0, "cmd": cmd, "ws_orig": str(ws_orig),
                   "karadul_file": karadul.__file__, "wall_s": ...})

VOLATILE_KEY = re.compile(r"^(timing_.*|.*_duration_s|duration_seconds|total_duration|ghidra_duration|"
                          r"generated_at|timestamp|created_at|updated_at|started_at|completed_at|"
                          r"start_time|end_time|elapsed.*)$")

def norm_str(s, meta, d):
    s = s.replace(meta["ws_orig"], "<WS>").replace(str(d / "ws"), "<WS>")
    s = s.replace(str(d / "clean"), "<OUT>").replace(str(d / "cache"), "<CACHE>")
    s = s.replace(str(REPO), "<REPO>").replace(str(Path.home()), "<HOME>")
    s = re.sub(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:?\d{2})?", "<TS>", s)
    s = re.sub(r"\b\d{8}_\d{6}\b", "<TS>", s)
    s = UUID_RE.sub("<UUID>", s)                     # test_stages_split_parity.py'deki regex
    s = re.sub(r"(/(private/)?(tmp|var/folders)/)\S+", r"\1<TMP>", s)
    return s

def norm_json(o, meta, d):
    if isinstance(o, dict):
        return {k: ("<VOLATILE>" if VOLATILE_KEY.match(k) else norm_json(v, meta, d)) for k, v in o.items()}
    if isinstance(o, list):  return [norm_json(v, meta, d) for v in o]   # SET_LIKE adlılar sıralanır
    if isinstance(o, float): return round(o, 6)
    if isinstance(o, str):   return norm_str(o, meta, d)
    return o

def collect(d) -> dict:
    # <ws>/{static,deobfuscated,reconstructed,reports}/** + <clean>/** ; *.log ve dynamic/** hariç.
    # .json -> ("json", norm_json(...)) ; .c/.h/.md/.txt/.sarif -> ("text", norm_str(...)) ;
    # diğerleri -> ("sha256", ...). Anahtar: normalize göreli yol ("<WS>/...", "<OUT>/...").
    ...

HARD = [r"^<OUT>/naming_map\.json$", r"^<WS>/reconstructed/src(_iter\d+)?/naming_map\.json$",
        r"^<WS>/reconstructed/param_naming_map\.json$", r"^<OUT>/src/", r"^<WS>/reconstructed/project/"]

def diff(phase, a, b, allow):   # allow = {"files": [regex], "json_keys": ["<dosya-regex>::<anahtar-yolu-regex>"], "hard_ok": bool}
    fails, expected = [], []
    for bin_ in BINARIES:
        A, B = collect(ROOT / phase / a / bin_.stem), collect(ROOT / phase / b / bin_.stem)
        for rel in sorted(A.keys() | B.keys()):
            if A.get(rel) == B.get(rel):
                continue
            detail = json_key_paths_diff(A.get(rel), B.get(rel)) or unified_head(A.get(rel), B.get(rel))
            hard = any(re.search(p, rel) for p in HARD)
            ok = allowed(rel, detail, allow) and (not hard or allow.get("hard_ok", False))
            (expected if ok else fails).append((bin_.name, rel, detail))
    write_json(ROOT / phase / "diff_report.json", {"fail": fails, "expected": expected, ...})
    sys.exit(1 if fails else 0)
```

**M4 için allowlist örneği** (`allow_M4.json`):

```json
{"files": ["^<WS>/reconstructed/struct_recovered/(originals/.*|struct_recovery\\.json|types\\.h)$"],
 "json_keys": ["^<WS>/reports/(report|pipeline_result)\\.json$::(^|/)stats/(pipeline_iterations_run|pipeline_iteration_details.*|timing_pipeline_loop|cfg_iso_matched_functions|computation_fusion_(matches|accepted|injected)|computation_struct_.*|structs_enriched|field_access_rewrites)$"]}
```

### 00.7 Açık kararlar (Berke'ye sorulacak)

| # | Soru | Seçenekler | Öneri |
|---|---|---|---|
| K1 | Opt-in MaxSMT (`--maxsmt-struct`) adaylarını StructRecoveryEngine'e taşıyan tek yol L2+L3. L3 silinince bu özellik ne olacak? | A) `struct_recovery` step'ine opsiyonel girdi olarak taşı (~+25 satır). B) Opt-in ve deneysel olduğu için düşmesini kabul et | **A** |
| K2 | L2'nin başındaki yorum "HEM step registry HEM monolith desteklenir (Berke karari)" diyor, ama monolith yolu artık yok. L2 silinsin mi? | Evet / hayır | **Evet.** Step kopyaları zaten koşuyor ve enjeksiyonu tüketen yok |
| K3 | Bayrak emekliliği hangi biçimde olsun? | a) Bir sürüm boyunca deprecated no-op (alan + gizli CLI bayrağı + `Config.load` uyarısı), sonra silme. b) Hemen tam silme | **a** |
| K4 | MAJOR-1 port'u (M3) onaylanıyor mu, sırası ne olsun? | M1–M2'den sonra / hemen | **M1–M2'den sonra.** Sıfır-fark fazları önce dosyayı küçültür. Override kullanan biri varsa öne alınabilir; `~/.karadul/overrides` şu an boş |
| K5 | M4 rapordaki `pipeline_iterations_run` vb. sayıları değiştirecek (0 → gerçek). Kabul ediliyor mu? | Evet / hayır | **Evet.** Bu bir hata düzeltmesi ve kodda bu anahtarların tüketicisi yok. Not: `8d9a0e4`'ün A/B'sinde "guard açıkken =0" guard'ın çalıştığının kanıtı sayılmıştı, ama aynı değer maskelemenin de belirtisiydi |
| K6 | Bayat golden fixture ve iki yer tutucu test (`test_execute_binary_artifact_parity_golden`, `test_step_registry_vs_monolith_equivalence`) ne olacak? | Sil / tut | **Yer tutucuları sil**; işlevlerini A/B betiği üstleniyor. Fixture yalnız `test_prepare_workspace_parity` ve yapı testleri için kalsın ya da küçültülsün |
| K7 | M6 (opsiyonel temizlik) yapılsın mı; `_execute_binary` daha fazla bölünsün mü? | — | **M6 evet, ek bölme hayır** |
| K8 | A/B betiği repoya (`scripts/`) girsin mi, kanıtlar repo dışında `~/karadul_parity/` altında mı dursun? | — | **İkisine de evet** |

### 00.8 Ölçülemeyenler ve doğrulanmamış çıkarımlar

- **HEAD-vs-HEAD gürültü tabanı:** Bu analizde `karadul analyze` koşturulmadı (talimat gereği). M0'da
  ölçülecek.
- **Süre kazancı:** Z1, L2 ve L3'ün kaldırılmasının getireceği süre kazancı ölçülmedi.
- **L2 stats eşitliği:** L2'nin yazdığı stats değerlerinin (`cfg_iso_matched_functions`,
  `computation_fusion_*`) step değerleriyle eşit olup olmadığı ölçülmedi.
- **L3'ün `.c` etkisi:** L3'ün `field_access_rewrites > 0` olan binary'lerde `.c` çıktısını
  değiştirip değiştirmediği ölçülmedi. Cat'te rewrite 0 olduğu için orada fark beklenmez.
- **MAJOR-1 erimesi:** Gerçek bir binary'de oluşup oluşmadığı ölçülmedi.
- **Ghidra proje önbelleği:** `KARADUL_CACHE_DIR`'in bunu kapsayıp kapsamadığı doğrulanmadı.
  Kapsadığı bilinen tek şey BSim DB.
- **`scripts/mac_f1_eval.py`:** Bugün import hatası vermeden çalışıp çalışmadığı doğrulanmadı.
- **`--output-dir` ile alınmış geçmiş ölçümler** (ör. `~/karadul_meas/<bin>_ws*`): imza ve ngram
  DB'si olmadan koşmuş olabilirler. Bu yalnız kod okumasından bir çıkarım, doğrulanmadı.
- **`originals/` sızıntısı:** `inline_detection` ve `c_project_builder` `rglob` kullanıyor.
  Cat'te `project/` 147 `.c` içeriyor, yani orada sızıntı yok; genel durum ölçülmedi.
- **Kanıtın kalıcılığı:** Ampirik kanıtın kaynağı `/private/tmp/flirt_debug/...` geçici bir dizin;
  bu yüzden sayılar bu bölüme kopyalandı.

---

> Aşağıdaki üstbilgi ve bölümler (§0 ve §1–§10) 2026-04-22 ve 2026-07-16 tarihli **tarihsel
> kayıttır**. Güncel plan yukarıdaki §00'dır.

**Yazar:** Architect agent
**Tarih:** 2026-04-22
**Durum:** PLAN ONLY — kod değişikliği yok
**Hedef sürüm:** v1.12.0 (Phase 2 hot-path #2)
**Önceki referanslar:** v1.10.0 Step Registry (M1 T3.5), 2026-04-20 fiyaskosu
**ÖNEMLİ:** `karadul/stages.py` TABU dosyadır — bu planı yazan okudu, yazmadı. Uygulama aşamasında **tek developer + tek branch** kuralı geçerli (paralel ajan YASAK).

---

## 0. GÜNCEL DURUM (2026-07-16) — bu bölüm §1–§10'un ÜSTÜNDEDİR

> **Son güncelleme: 2026-07-16 (Cephe 3, developer).**
> Aşağıdaki §1–§10 **2026-04-22 (v1.12.0) anlık görüntüsüdür ve BAYATTIR** — satır
> aralıkları, dosya boyutu ve "18 metot önerisi" o günün planıdır. Tarihsel değer
> için korunuyor ama **gerçek durum bu bölümdür.** Çelişkide bu bölüm geçerlidir.

### Doğrulanmış güncel gerçek (filesystem + AST ile)

| Öğe | BAYAT değer (§1–§2) | GERÇEK (2026-07-16) |
|---|---|---|
| `karadul/stages.py` boyutu | 4906 satır | **6024 satır** |
| Canavar: `ReconstructionStage._execute_binary` | 1147–4319 (3173 s) | **2847–5494 (2648 satır)** |
| `DeobfuscationStage._execute_binary` (küçük kopya, kapsam dışı) | 753–834 | 797–821 |
| `use_step_registry` default | (o gün False'du) | **True** (config.py:619, cli.py:523) |

### Bugünkü split durumu (üç faz)

1. **Phase 1 (statik metadata) — TAŞINDI.** İki yol da temiz:
   - `use_step_registry=True`: `PipelineRunner` ile 15 step (binary_prep … assembly_analysis),
     `_execute_binary` satir 2886–2926.
   - `use_step_registry=False`: `_run_*` **yardımcı metotlarına** çıkarıldı
     (`_load_binary` [1232–1445], `_run_signature_matching` [1456–1510],
     `_run_byte_pattern_matching` [1512–1616], `_run_anti_debug_and_packer` [1618–1730],
     `_run_pcode_analysis` [1732–1824], `_run_cfg_analysis` [1826–1862],
     `_run_algorithm_engineering` [1864–1887]). Bu metotlar SADECE else-dalında
     (satir 3052–3104) çağrılır. Parity: `tests/test_stages_split_parity.py` (25 test).

2. **Phase 2 (feedback loop + struct recovery) — YARIM/ÇELİŞKİLİ (⚠️ DÜRÜSTLÜK NOTU).**
   - Bir `feedback_loop` **step'i VAR** (`steps/feedback_loop.py`, `_feedback_loop_iter`
     + `_feedback_helpers` + `_feedback_computation/_naming/_typing`) ve
     `use_step_registry=True` yolunda `runner_phase2` ile çalışır (satir 3005–3046).
   - AMA `_execute_binary` içindeki **monolith feedback loop `for _pipeline_iter …`
     (satir 3317–4563, ~1247 satır) `_use_step_registry` ile GUARD'LI DEĞİL** →
     yapısal olarak **HER İKİ modda** çalışır. Yani step-registry modunda feedback loop
     hem step olarak (runner_phase2) hem monolith olarak (3317) koşuyor gibi görünüyor
     (görünen **çift-çalışma / artık iş**). `pipeline_iterations` default = 3.
   - Header yorumu (satir 2879 "Phase 2 … eski yolda kalir") **BAYAT** — kod
     runner_phase2'yi step-registry dalında çalıştırdığı için yorumla çelişiyor.
   - **Bu cephede DOKUNULMADI** (Phase 2 taşıma ertelendi). Ayrı bir architect kararı
     gerekir: ya monolith loop `else`'e alınır ya feedback_loop step'i geri çekilir.
     Runtime maliyeti ÖLÇÜLMEDİ (2. geçiş convergence'ta erken `break` yapabilir).
   - `computation_fusion`/`cfg_iso`/`struct_recovery` monolith blokları (satir 4574–4836)
     **kasıtlı olarak her iki modda** desteklenir (satir 4575 "HEM step registry HEM
     monolith … Berke karari"); feature flag'ler kapalıyken no-op.

3. **Phase 3 (post-feedback, 10 adım) — TAŞINDI; inline monolith = ÖLÜ FALLBACK.**
   - `use_step_registry=True`: `runner_phase3` (10 step, satir 4897–4908) çalışır ve
     satir 4927'de **erken `return`** yapar.
   - `use_step_registry=False`: satir **4929–5494 (566 satır)** inline monolith çalışır.
   - Flag default True olduğundan **bu 566 satır prod'da ULAŞILMAZ = ÖLÜ.** stages.py'ye
     bu durumu açıklayan yorum bloğu eklendi (satir 4929 öncesi, 2026-07-16).

### Phase 3 monolith → step eşlemesi (10/10 DOĞRULANDI, eksik step YOK)

| Monolith alt-adım (4929–5494) | Step karşılığı | Sınıf/fonksiyon (birebir doğrulandı) |
|---|---|---|
| 3.5 Inline Detection | `steps/inline_detection.py` | `InlineDetector` |
| 3.7 Semantic Param Naming | `steps/semantic_naming.py` | `SemanticParameterNamer` |
| 3.6 Flow Simplify | `steps/flow_simplify.py` | `CFlowSimplifier` |
| 4 Comment Generation | `steps/comment_generation.py` | `CCommentGenerator` |
| 4.2 CAPA Annotation | `steps/capa_annotation.py` | `_inject_capa_comments` |
| 4.5 Engineering Block Annotation | `steps/engineering_annotation.py` | `CodeBlockAnnotator` |
| 5 Project Build | `steps/project_build.py` | `CProjectBuilder` |
| 6 Engineering Analysis | `steps/engineering_analysis.py` | `DomainClassifier` / `FormulaReconstructor` |
| 7 Deep Tracing | `steps/deep_tracing.py` | `_deep_tracing_helpers`: `VirtualDispatchResolver`, `InterProceduralDataFlow`, `AlgorithmCompositionAnalyzer`, `DeepCallChainTracer` |
| timing + return | `steps/finalize.py` | `StageResult` |

### `use_step_registry=False`'u egzersiz eden AKTİF test var mı? — HAYIR

| Test | Ne yapıyor | Durum |
|---|---|---|
| `test_pipeline_e2e.py:223` `test_step_registry_vs_monolith_equivalence` | flag=False set ediyor AMA satir 246 `pytest.skip` | **YER TUTUCU (skip)** |
| `test_step_registry.py:330` `test_yaml_override` | YAML'dan flag=False **yüklenişini** doğrular | Pipeline KOŞMUYOR (sadece config) |
| `test_stages_split_parity.py` (25 test) | `_run_*` Phase 1 metotlarını **izole** çağırır | Phase 3 monolith'e DOKUNMAZ |

Sonuç: flag=False monolith pipeline'ını uçtan uca koşan tek test yer tutucudur →
**Phase 3 monolith fiilen ölüdür.**

---

## Phase 3 ölü-kod silme önerisi

> **Durum: ÖNERİ — Berke onayı bekliyor. Bu cephede UYGULANMADI (büyük silme, geri
> dönüşü zor).** Onaylanırsa ayrı bir sprint'te tek-developer/tek-branch ile yapılır.

### Ne güvenle silinebilir?

`use_step_registry` flag'i **tamamen emekliye ayrılırsa** (step-registry TEK yol olur),
aşağıdaki **flag=False'a özgü** kod silinebilir. Toplam ~**1350 satır**:

| Blok | Satir aralığı | ~Satır | Açıklama |
|---|---|---|---|
| Phase 3 inline monolith | 4929–5494 | 566 | Ölü fallback (step'ler var) |
| Assembly analysis else-dalı | 3130–3215 | 86 | Phase 1 asm; step: `assembly_analysis` |
| Phase 1 else-dalı gövdesi (`_load_binary` + `_run_*` çağrıları) | 3047–3104 | 58 | Runner Phase 1 zaten yapıyor |
| `_load_binary` metodu | 1232–1445 | 214 | else-only |
| `_run_signature_matching` | 1456–1510 | 55 | else-only; step: `ghidra_metadata` sig |
| `_run_byte_pattern_matching` | 1512–1616 | 105 | else-only; step: `byte_pattern` |
| `_run_anti_debug_and_packer` | 1618–1730 | 113 | else-only; step: `anti_debug`+`packer_fingerprint` |
| `_run_pcode_analysis` | 1732–1824 | 93 | else-only; step: `pcode_cfg_analysis` |
| `_run_cfg_analysis` | 1826–1862 | 37 | else-only; step: `cfg_iso_match`/cfg |
| `_run_algorithm_engineering` | 1864–1887 | 24 | else-only; step: `algorithm_id`+`parallel_algo_eng`+`confidence_filter` |
| `_use_step_registry` dal ayrımı basitleşir | 2882–3128, 4844–4927 | ~(net kazanç) | `if/else` → tek yol |
| Flag tanımı + wiring | config.py:619, cli.py:523 | ~2 | `use_step_registry` alanı + CLI flag |

**NOT — `_prepare_workspace` [1197–1230] SİLİNMEZ** (her iki yolda `_execute_binary:2860`
çağrılır).

### Ne SİLİNMEZ (kritik)?

- **Monolith feedback loop [3317–4563]** — `_use_step_registry` guard'ı yok, her iki
  modda çalışıyor. Önce §0.2'deki çift-çalışma çelişkisi architect tarafından çözülmeli
  (loop `else`'e mi alınacak, step mi geri çekilecek). Silme DEĞİL, önce netleştirme.
- **computation_fusion / cfg_iso / struct_recovery monolith [4574–4836]** — kasıtlı
  olarak her iki modda destekleniyor (Berke kararı, satir 4575). Flag kapalıyken no-op.

### Minimal (flag korunarak) alternatif

Flag'i korumak istenirse: Phase 3 inline monolith [4929–5494] tek başına silinemez
(flag=False Phase 3'ü tamamen kaybeder). Bu durumda 4929–5494 yerine
`raise NotImplementedError("use_step_registry=False Phase 3 kaldirildi; True kullan")`
konur (566 satır → ~2 satır) ve flag=False yolu resmen deprecate edilir. Tercih:
**tam emeklilik daha temiz.**

### Etkilenen testler

| Test | Etki | Aksiyon |
|---|---|---|
| `test_pipeline_e2e.py:223` (placeholder, skip) | flag=False kavramı kalkar | **Sil veya güncelle** (artık karşılaştıracak monolith yok) |
| `test_step_registry.py:330` `test_yaml_override` | flag artık yoksa geçersiz | Flag tümden kalkarsa **sil**; kalırsa dokunma |
| `test_pipeline_e2e.py:317/322`, `test_step_registry.py:323` (default=True) | Flag kalkarsa anlamsız | Flag kalkarsa sil |
| `tests/test_stages_split_parity.py` (25 test) | **`_run_*` metotlarını doğrudan test ediyor** → o metotlar silinirse **KIRILIR** | Tam emeklilikte bu 25 testin ~11'i (`test_run_*`, `test_load_binary_*`) güncellenmeli/silinmeli. **Phase 3-only silmede ETKİLENMEZ** (parity Phase 1'i test ediyor, Phase 3'ü değil) |
| Golden SHA256 parity (`test_execute_binary_artifact_parity_golden`, @skip) | Zaten skip | Emeklilikte alakasız |

### Golden-parity etkisi

`test_stages_split_parity.py` içindeki gerçek golden testi (satir 292) **zaten
`@pytest.mark.skip`** ve golden fixture SHA256 karşılaştırması aktif değil. Dolayısıyla
silme bu testin durumunu değiştirmez. Aktif parity koruması `test_run_*_parity` (Phase 1
metotları) üzerindedir → yalnızca **tam flag emekliliğinde** güncelleme gerekir.

### Risk değerlendirmesi

| Risk | Seviye | Not |
|---|---|---|
| Phase 3-only silme (flag korunur, NotImplementedError) | **DÜŞÜK** | 566 satır ölü kod; aktif test etkilenmez; davranış aynen |
| Tam flag emekliliği (~1350 satır) | **ORTA** | 11 parity testi güncellenir; Phase 1 else-metotları gider; feedback-loop çelişkisi ÖNCE çözülmeli |
| Feedback-loop çelişkisine dokunmak | **YÜKSEK** | Kapsam dışı; ayrı ölçüm + architect kararı gerekir |

### Önerilen sıra (Berke "onaylıyorum" derse)

1. Önce Phase 2 feedback-loop çift-çalışma çelişkisini architect + ölçümle netleştir
   (bu silmeden bağımsız ama emeklilikten önce gelmeli).
2. `test_pipeline_e2e.py:223` placeholder'ını gerçek flag-parity testine dönüştür VEYA sil.
3. Flag'i emekliye ayır: else-dalları + `_run_*` metotları + Phase 3 monolith sil,
   config.py/cli.py flag'ini kaldır, `if _use_step_registry` dallarını tek yola indir.
4. 25 parity testini güncelle (Phase 1 metotları artık yok → runner-tabanlı teste geç).
5. Tam suite yeşil + `stages.py` ~6024 → ~4650 satır.

---

## 1. Durum Analizi (Audit)

| Metrik | Değer | Not |
|---|---|---|
| Dosya: `karadul/stages.py` | **4906 satır** | Brief'teki 4465 değeri güncel değil |
| Toplam `def` (metod + fonksiyon) | 30 | Grep count |
| Sınıf sayısı | 6 | Identify, StaticAnalysis, DynamicAnalysis, Deobfuscation, **Reconstruction**, Report |
| `_execute_binary` — küçük kopya | satır **753–834** (81 satır, DeobfuscationStage) | Bu plan kapsamında DEĞİL |
| `_execute_binary` — **hedef canavar** | satır **1147–4319** (**3173 satır**, ReconstructionStage) | Split edilecek olan budur |
| Canavar gövdesi | 3173 satır | Brief'te "300–800" tahmini çok düşüktü |
| Cyclomatic Complexity (iddia) | ~800 | Brief; bu plan CC'yi doğrulamadı, sadece guru sayar. 3173 satırda try/except derinliği 4+, for iç içe 3+, if ladder 10+ birleşince makul |
| Mevcut direkt birim test | **0** (ReconstructionStage sadece `import` ve `__init__` flag test edilmiş) | `tests/test_reconstruction.py` satır 911–925 |
| İlgili test dosyaları | `test_reconstruction.py` (44 test), `test_binary_reconstruction.py` (202 test) — toplam **246** | Büyük çoğunluğu alt-katman (reconstruction/) unit test, stage-level değil |

### Kritik bulgu: "Step Registry shim" zaten yarım tamam

`_execute_binary` içinde satır 1158–1169 arasında feature flag var: `context.config.pipeline.use_step_registry`. True ise **10 Phase-1 step**'i (binary_prep … assembly_analysis) `karadul.pipeline.runner.PipelineRunner` üzerinden çalıştırıp sonuçları local değişkenlere geri kopyalıyor. **Phase 2** (feedback_loop + struct_recovery) eski yolda kalıyor, **Phase 3** (satır 3677–3752) 10 post-step için ikinci bir runner üzerinden çalışıyor ve **early return** yapıyor.

Yani: stages.py'nin büyük kısmı (satır 1550–3670 arası ~2100 satır) **şu an bile** step registry flag açılırsa çalıştırılmayan kodun "eski monolith fallback"ı. v1.10.0 M4'te bile Berke HEM registry HEM monolith yolunu korumak istemiş (satır 3408 yorumu). **Split'in asıl işi bu "eski monolith" bloğunu step registry'ye tam devretmek** — sıfırdan 18 metot yazmak değil.

---

## 2. İç Yapı: 7 Mantıksal Bölüm

Canavarın 3173 satırı aşağıdaki **7 bölüme** ayrılıyor. Satır aralıkları grep ile doğrulandı.

| # | Bölüm | Satır aralığı | Satır sayısı | Ana iş |
|---|---|---|---|---|
| 1 | **Setup & Registry Shim** | 1147–1427 | ~280 | Workspace dizinleri, config parse, `_use_step_registry` dal ayrımı, Phase 1 runner çağrısı + artifact geri aktarımı |
| 2 | **Static Metadata (eski monolith Phase 1)** | 1428–2018 | ~590 | Sig DB matching, Byte pattern, P-Code, CFG, FID — **flag kapalıyken çalışır** |
| 3 | **Assembly Fallback** | 2019–2109 | ~90 | Ghidra decompiler fallback (flag kapalıyken) |
| 4 | **Feedback Loop (Phase 2 çekirdek)** | 2110–3397 | **~1290** | v1.7.5 iteratif computation → c_naming → name_merger → type_recovery. **Dosyanın en yoğun bölgesi.** Iç adımlar (1.4, 2.0, 2.4, 2.4b, 2.5, 3.0) sayılı yorumlarla ayrılmış |
| 5 | **Computation Fusion (M4 monolith)** | 3398–3593 | ~200 | CFG iso + signature fusion + MaxSMT struct recovery (monolith kopyası, flag-independent) |
| 6 | **Struct Recovery + Phase 3 Early Return** | 3594–3752 | ~160 | Engineering struct recovery; sonrasında `_use_step_registry` ise Phase 3 runner çalışır ve **return** |
| 7 | **Eski Monolith Phase 3 (post-feedback)** | 3753–4319 | ~570 | Inline detection, semantic naming, flow simplify, comment gen, capa annot, eng annot, project build, eng analysis, deep tracing, timing özeti, return StageResult |

### Bölüm bazlı side-effect haritası

| Bölüm | Dosya I/O | Subprocess | State mutation | Dependency (önce-sonra) |
|---|---|---|---|---|
| 1 Setup | workspace dirs oluştur | — | `artifacts`, `stats`, `errors` init | Giriş |
| 2 Static | JSON okuma/yazma (sig, byte_pattern, pcode, cfg) | — | `sig_matches`, `_pcode_result`, `cfg_result`, vs. → **local namespace**'e >20 ad eklenir | 1 sonra |
| 3 Assembly | Ghidra decomp yazma | **Ghidra headless (indirekt)** | `decompiled_dir` güncelleme | 2 sonra |
| 4 Feedback | çok sayıda `.c` dosyası okuma/yazma, symlink | — | `naming_result`, `type_rec_result`, `_computation_result`, `_prev_named_set`, `_iteration_stats` (loop invariant!) | 3 sonra, 5'ten önce |
| 5 Fusion | — | — | `_cfg_iso_matches_monolith`, `_fused_matches_monolith`, `_computation_struct_candidates` | 4 sonra |
| 6 Struct Recov | `.c` dosyaları düzenleme | — | `struct_recovery_result` | 5 sonra; `_use_step_registry` ise Phase 3 runner delegation sonra return |
| 7 Post-Monolith | çok sayıda `.c` dosyası yazma | — | inline_patterns, semantic_params, comments, capa annots, project dir, eng_analysis, deep_traces | 6 sonra |

### Kritik sıralama kuralları

1. **Phase 1 output → Phase 2 input**: `functions_json`, `strings_json`, `call_graph_json`, `xrefs_json`, `pcode_json`, `cfg_json`, `fid_json`, `decompiled_json` yolları Phase 1'de üretilir, Phase 2'den sonuna kadar gereklidir.
2. **Feedback loop stateful**: `_prev_named_set` her iterasyonda convergence kontrolü için lazım; loop-level değişkendir. Split'te loop'u fonksiyon parametresi olarak dışarıya çıkarsa bu state hala closure/attribute ile taşınmalı.
3. **`decompiled_dir` iterasyonlar arası değişir**: `_loop_decompiled_dir` her iter sonunda güncellenir; bir sonraki iter'de source olarak kullanılır.
4. **`file_cache` paylaşımlı**: `_file_cache: dict[str, str]` cache'i Phase 1'de doldurulur, feedback loop sırasında güncellenir, Phase 3'te de kullanılır (ör. satır 3769 `InlineDetector`).

---

## 3. 18 Alt Metot Önerisi

**Tasarım ilkeleri:**
- Her metot saf Python metod (sınıf üyesi) — modül-level fonksiyon değil (ReconstructionStage attribute'larına erişmesi gerekebilir).
- Ortak state için **`_ReconCtx` dataclass** önerisi (bkz §4). `ctx` objesi (PipelineContext) başka state taşıyor, karışmasın.
- Tüm metotlar `(self, ctx: PipelineContext, rc: _ReconCtx) -> None` signature'ı kullanır. Mutation `rc` üzerinden. Metod dönüş değeri yoktur → side-effect açık.
- Her metot için CC tahmini (optik şeref: branching/for-derinliği üzerinden kaba tahmin).

| # | Metot | Kapsadığı satır | Sorumluluk | Mutate ettiği `rc` alanı | CC tahmini |
|---|---|---|---|---|---|
| 1 | `_prepare_workspace` | 1147–1157 | Workspace dirs, artifacts/stats/errors init | `rc.artifacts`, `rc.stats`, `rc.errors`, `rc.dirs` | <5 |
| 2 | `_dispatch_phase1` | 1158–1427 | Step registry flag'e göre Phase 1'i runner ya da monolith ile çalıştır, artifact'ları `rc`'ye yükle | `rc.ph1_artifacts` (20+ path + data) | ~25 |
| 3 | `_run_signature_matching` | 1428–1470 (monolith kolu) | Sig DB matching — yalnızca flag kapalıysa çağrılır | `rc.sig_matches` | ~12 |
| 4 | `_run_byte_pattern` | 1471–1561 | Byte pattern matching | `rc.byte_pattern_matches` | ~15 |
| 5 | `_run_pcode_analysis` | 1562–1642 | P-Code dataflow (stats_only / jsonl / legacy) | `rc.pcode_result`, `rc.pcode_naming_candidates` | ~18 |
| 6 | `_run_cfg_analysis` | 1643–1831 | CFG analizi, function fingerprints, naming candidates | `rc.cfg_result`, `rc.cfg_naming` | ~22 |
| 7 | `_run_algorithm_engineering` | 1832–2018 | Confidence calibration + engineering + crypto merge + byte pattern enjekte + CAPA | `rc.algo_result`, `rc.eng_result`, `rc.extracted_names`, `rc.capa_capabilities` | ~30 |
| 8 | `_run_assembly_analysis` | 2019–2109 | Ghidra assembly fallback | `rc.asm_result` | ~15 |
| 9 | `_prepare_feedback_loop` | 2110–2209 | Loop state init: max_iterations, cg_neighbors, rglob cache, pre-instantiation (QW4) | `rc.loop_state` (iterator, caches, engines) | ~15 |
| 10 | `_feedback_iter_computation` | 2231–2363 (loop body kısmı 1) | Tek iter'in computation recovery adımı | `rc.loop_state.computation_result` | ~25 |
| 11 | `_feedback_iter_naming` | 2364–2443 | Tek iter'in C naming adımı | `rc.loop_state.naming_result` | ~18 |
| 12 | `_feedback_iter_bindiff_refdiff` | 2444–2706 | Tek iter'in BinDiff + ReferenceDiff adımları | `rc.loop_state.bindiff_matches`, `rc.loop_state.refdiff_matches` | ~30 |
| 13 | `_feedback_iter_name_merger` | 2707–2985 | Tek iter'in Name Merger adımı (en yoğun) | `rc.loop_state.merged_names`, `rc.extracted_names` | ~40 |
| 14 | `_feedback_iter_type_recovery` | 2986–3397 | Tek iter'in Type Recovery + convergence check + incremental file set güncelleme | `rc.loop_state.type_rec_result`, `rc.loop_state.prev_named_set` | ~35 |
| 15 | `_run_computation_fusion_monolith` | 3398–3593 | M4 monolith fusion (cfg_iso + signature fusion + MaxSMT) | `rc.fusion_result`, `rc.struct_candidates` | ~30 |
| 16 | `_run_struct_recovery` | 3594–3671 | Engineering struct recovery | `rc.struct_recovery_result` | ~18 |
| 17 | `_run_phase3_registry` | 3672–3752 | Flag açıksa Phase 3 runner, early return StageResult | (return) | ~10 |
| 18 | `_run_phase3_monolith` | 3753–4296 | Eski monolith Phase 3: inline, semantic, flow, comments, capa annot, eng annot, project build, eng analysis, deep tracing | `rc.stats["timing_*"]`, `rc.artifacts` | ~45 |
| + | `_finalize_result` | 4297–4319 | Timing özeti, StageResult döndür | (return StageResult) | <5 |

**Toplam:** 18 ana + 1 finalize = **19 metot**. Orijinal CC~800 yerine ortalama CC ~22, max CC ~45 (`_run_phase3_monolith`). Python-radon ile gerçek CC ölçümü v1.12.0-alpha1 kabul kriteri olmalı.

### Yeni `_execute_binary` nihai hali (~25 satır)

```python
def _execute_binary(self, context: PipelineContext, start: float) -> StageResult:
    """Binary reconstruction — yüksek seviye koordinatör (bkz: stages_split_plan.md v1.12.0)."""
    rc = _ReconCtx(start=start, stage_name=self.name)

    self._prepare_workspace(context, rc)

    phase1_ok = self._dispatch_phase1(context, rc)
    if not phase1_ok:
        return rc.as_failure()
    if rc.phase1_short_circuit:  # step registry + error
        return rc.phase1_early_return

    if not rc.used_step_registry:
        self._run_signature_matching(context, rc)
        self._run_byte_pattern(context, rc)
        self._run_pcode_analysis(context, rc)
        self._run_cfg_analysis(context, rc)
        self._run_algorithm_engineering(context, rc)
        self._run_assembly_analysis(context, rc)

    self._prepare_feedback_loop(context, rc)
    for iter_idx in range(rc.loop_state.max_iterations):
        rc.loop_state.iter_idx = iter_idx
        self._feedback_iter_computation(context, rc)
        self._feedback_iter_naming(context, rc)
        self._feedback_iter_bindiff_refdiff(context, rc)
        self._feedback_iter_name_merger(context, rc)
        converged = self._feedback_iter_type_recovery(context, rc)
        if converged:
            break

    self._run_computation_fusion_monolith(context, rc)
    self._run_struct_recovery(context, rc)

    if rc.used_step_registry:
        return self._run_phase3_registry(context, rc)

    self._run_phase3_monolith(context, rc)
    return self._finalize_result(context, rc)
```

Okunur, 15 dakikada yabancı bir geliştirici yapıyı kavrar. Her metot bağımsız test edilebilir.

---

## 4. State Flow / `_ReconCtx` Dataclass

3173 satırlık monolith'in bir nedeni: **>40 lokal değişken** fonksiyon scope'unda yaşıyor (ör. `sig_matches`, `algo_result`, `eng_result`, `_computation_result`, `naming_result`, `_prev_named_set`, `_iteration_stats`, `_loop_decompiled_dir`, `_file_cache`, `_cg_neighbors`, `_rglob_c_files`…). Split ederken bu state'i **açıkça geçirmek şart**.

### Çözüm: `karadul/pipeline/_recon_ctx.py` (yeni dosya)

```python
@dataclass
class _ReconLoopState:
    max_iterations: int
    iter_idx: int = 0
    prev_named_set: set[str] = field(default_factory=set)
    iteration_stats: list[dict] = field(default_factory=list)
    loop_decompiled_dir: Path | None = None
    cg_neighbors: dict[str, set[str]] = field(default_factory=dict)
    cfile_by_name: dict[str, Path] = field(default_factory=dict)
    incremental_files: list[Path] | None = None
    rglob_c_files: list[Path] = field(default_factory=list)
    rglob_cfile_map: dict[str, Path] = field(default_factory=dict)
    rglob_cached_dir: Path | None = None
    # pre-instantiated modules (QW4)
    pre_comp_engine: Any = None
    pre_c_namer: Any = None
    pre_type_rec: Any = None
    # iter-local
    computation_result: Any = None
    naming_result: Any = None
    bindiff_matches: dict = field(default_factory=dict)
    refdiff_matches: dict = field(default_factory=dict)
    merged_names: dict = field(default_factory=dict)
    type_rec_result: Any = None


@dataclass
class _ReconCtx:
    """`_execute_binary` içindeki tüm lokal state'in explicit konteyneri."""
    start: float
    stage_name: str
    artifacts: dict[str, Path] = field(default_factory=dict)
    stats: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    dirs: dict[str, Path] = field(default_factory=dict)     # static/deob/reconstructed
    # Phase 1 artifacts (runner veya monolith)
    ph1_artifacts: dict[str, Any] = field(default_factory=dict)
    # flags
    used_step_registry: bool = False
    phase1_short_circuit: bool = False
    phase1_early_return: StageResult | None = None
    # Analyzer results
    sig_matches: list = field(default_factory=list)
    byte_pattern_matches: list = field(default_factory=list)
    pcode_result: Any = None
    pcode_naming_candidates: list = field(default_factory=list)
    cfg_result: Any = None
    algo_result: Any = None
    eng_result: Any = None
    extracted_names: dict = field(default_factory=dict)
    capa_capabilities: dict = field(default_factory=dict)
    asm_result: Any = None
    # Loop + fusion
    loop_state: _ReconLoopState | None = None
    fusion_result: Any = None
    struct_candidates: list = field(default_factory=list)
    struct_recovery_result: Any = None
```

**Avantaj:**
- State mutation noktası **tek** (`rc.X`). Grep'lenebilir.
- Unit testlerde `rc` prefab'i hazırlanır, bir metot izole çağrılır, `rc`'nin sonraki hali assert edilir.
- Yeni alan eklemek için tek yerde değişiklik.

**Dezavantaj:**
- `rc.loop_state.computation_result` gibi nested erişim uzayabilir. Kabul edilebilir ödün.
- Dataclass serileşemeyen alanlar (engine instance'ları) içerir; pickle edilmemeli. Kısıtlamayı comment ile belgele.

### Pure vs Side-effect bölümü

18 metotun 1'i (`_finalize_result`) puredur. 17'si side-effect'li. Bu RE pipeline'ı için **normal**: binary analiz dosya okumadan/yazmadan imkansız. Hedef saf fonksiyonel mimari değil; hedef **her side-effect'i tek yere kapsüllemek**.

---

## 5. Test Stratejisi

### Mevcut durum (doğrulanmış)

- `test_reconstruction.py`: 44 test. `_execute_binary` **direkt çağrılmıyor**; sadece `ReconstructionStage()` ctor + flag testleri (satır 911–925).
- `test_binary_reconstruction.py`: 202 test. Çoğunluğu alt-modül (`reconstruction/`, `analyzers/`) birim testleri.
- Toplam **246 test** dolaylı kapsam sağlıyor. Feedback loop iterasyonu, incremental file set, convergence threshold — bunların **tamamı regression olarak test edilmiyor**. Tehlikeli boşluk.

### v1.12.0 test planı (üç katman)

1. **Coverage baseline (önce)** — split'ten ÖNCE `_execute_binary` üzerinden coverage raporu çıkar:
   ```bash
   pytest tests/ --cov=karadul.stages --cov-report=html:cov_before
   ```
   Branch coverage yüzdesi belgele. Split sonrası **düşmemeli**.

2. **Yeni unit testler (her metot için)** — 18 metot × en az 2 test = **36+ yeni test**:
   - Happy path: normal input → beklenen `rc` mutation.
   - Edge case: ilgili feature flag off / input dosyası yok / boş sonuç.
   - Bazıları (4, 5, 10, 13, 14) için 3+ test lazım (dallı kod).
   - **Fixture**: `_recon_ctx_factory()` — önceki metotların tamamlandığı varsayılan `rc` prefab'ı döndürür. Her test kendi metodunu izole çağırır.

3. **Regression integration test (tek, büyük)** — mevcut 246 testin split sonrası **tamamı geçmeli**. Ek olarak bir "altın binary" üzerinde tam pipeline (flag on + flag off iki varyant) E2E çalıştırılıp SHA256 karşılaştırmalı artifact diff:
   ```python
   def test_execute_binary_artifact_parity_golden():
       # Pre-split commit'teki çıktı imzasıyla karşılaştır
       ...
   ```
   Golden fixture `tests/golden/v1_11_execute_binary_output.json` olarak çek.

### Paralel ajan fiyaskosu korumalari (test-tarafi)

- Her metot commit'inde `pytest -x` green olmadan split ilerlemez.
- Her fazda `pytest --lf` (last failed) yeterli; tüm suite her commit'te gerekmez.
- CI pipeline'ında branch protection: stages.py değiştiren PR sadece tek reviewer kabul etmez, **iki reviewer + tester ajanı onayı** zorunlu olsun.

---

## 6. Migration Güvenlik Stratejisi (3 Faz)

### Faz 1 — v1.12.0-alpha1: **18 metot EKLE, orijinal kod bozulmadan**

**Yaklaşım: Strangler Fig.** 18 metot oluştur. Her metot **sadece orijinal kod aralığını olduğu gibi** içerir (kesme-yapıştır, hiçbir mantık değişikliği YOK). `_execute_binary` bu metotları sırayla çağırır. Hiçbir kod fiilen taşınmadı, sadece etiketlendi.

- Yeni dosya: `karadul/pipeline/_recon_ctx.py` (dataclass).
- `stages.py` satır 1147–4319 yerinde kalır ama **her mantıksal bölüm kendi `_run_XXX` metoduna delege eder**. Bölüm sayısı 18, aralık satır sayısı aynı.
- Örn. satır 1428–1470 arası kod olduğu gibi `_run_signature_matching` metoduna kopyalanır, orijinal satırlar `self._run_signature_matching(context, rc)` ile değiştirilir.
- **Net LOC artışı**: +400 satır (metot imza overhead + dataclass). Kabul edilebilir.
- **Davranış değişikliği**: 0 byte. Artifact SHA256 aynı.
- Git tag: `v1.12.0-alpha1-structural`. Rollback → `git revert`.

### Faz 2 — v1.12.0-alpha2: **Dead monolith yolunu kaldır**

Step Registry default'u `True` yap. `_use_step_registry=False` dalı (~2100 satır dead code) birkaç release boyunca `@deprecated` kalır. v1.12.0-alpha2'de kaldır:
- `_run_signature_matching` … `_run_assembly_analysis` (metot 3–8) silinebilir, çünkü Phase 1 step registry artık yapar.
- `_run_computation_fusion_monolith` (metot 15) silinebilir — step registry M4'ü zaten içeriyor.
- `_run_phase3_monolith` (metot 18) silinebilir — `_run_phase3_registry` hep çalışır.
- **Kalan:** Phase 2 feedback loop (metot 9–14) + struct recovery (metot 16). Feedback loop henüz step registry'e taşınmadı (brief: "Phase 2 hot-path #2"). Bu split'in asıl ödülü: Phase 2'yi step registry formatına hazırlayan temiz metot sınırları.
- **Net LOC azalışı**: ~-2100 satır.
- Git tag: `v1.12.0-alpha2-dead-code-removed`.

### Faz 3 — v1.12.0-beta: **Feedback loop'u step registry'ye taşı**

Metot 9–14 (`_prepare_feedback_loop` … `_feedback_iter_type_recovery`) her birini bir step haline getir:
- `karadul/pipeline/steps/feedback_loop_v2/` altında: `comp_recovery_step.py`, `c_naming_step.py`, `bindiff_step.py`, `name_merger_step.py`, `type_recovery_step.py`.
- Iteration mantığı `PipelineRunner` üzerinde yeni bir "loop step" abstraction'ı gerektirebilir. Alternatif: `FeedbackLoopOrchestrator` helper sınıfı (tek dosyada kalır, step registry dışı).
- Convergence threshold + incremental file set — loop state `PipelineContext.metadata["feedback_loop"]` altında.
- Git tag: `v1.12.0-beta-steps-migrated`.

### Faz 4 — v1.12.0 release

- `_execute_binary` tamamen koordinatör (~25 satır).
- `stages.py` ~4906 → ~2500 satıra iner.
- CHANGELOG, migration guide, ADR-006 ("Step Registry Full Migration") yazılır.

---

## 7. Risk Matrisi

| # | Risk | Önem | Olasılık | Mitigation |
|---|---|---|---|---|
| 1 | **Paralel ajan çakışması** — 2026-04-20 fiyaskosunun tekrarı | KRİTİK | ORTA (diskiplinsizlik durumunda) | Tek developer + tek branch, `CODEOWNERS` dosyasında `karadul/stages.py` için tek onaylayıcı. PR'a "[STAGES-SPLIT]" etiketi zorunlu. v1.12.0 süresince diğer ajanlar **asla** stages.py'ye PR açmaz |
| 2 | **Sessiz state mutation bug'ı** — `_ReconCtx` alanı split sırasında yanlış mutate edilir, 3 iterasyon sonra fark edilir | KRİTİK | ORTA | Faz 1'de 0 mantık değişikliği (sadece kesme-yapıştır). Her metot commit'inde `pytest` + golden artifact diff. Faz 2'ye geçmeden 1 tam hafta soak süresi |
| 3 | **Ghidra subprocess sıralama bozulması** | YÜKSEK | DÜŞÜK (Phase 1 zaten step registry'ye taşınmış) | Integration test golden binary üzerinde. Ghidra headless invocation order metot 2 (`_dispatch_phase1`) içinde kilitli |
| 4 | **Test coverage boşluğu** — `_execute_binary` direkt test edilmediği için split sonrası regresyon görünmez | YÜKSEK | YÜKSEK (mevcut durum) | Split'ten **önce** golden artifact fixture çıkar. 36+ yeni unit test (§5). Branch coverage ölçüsü baseline |
| 5 | **Feedback loop convergence değişikliği** — iterasyon state'i `_ReconLoopState`'e taşınırken default değer farklı olursa iter sayısı değişir, artifact farkı oluşur | YÜKSEK | ORTA | Dataclass `field(default_factory=...)` kullan, `__post_init__` validation. Golden fixture iter-by-iter stats diff kontrol |
| 6 | **LOC artışı (Faz 1 +400 satır)** reviewer'ı boğar | DÜŞÜK | YÜKSEK | Faz 1 PR'ı tek commit — kolay review. Faz 2/3 PR'ları LOC net negatif |
| 7 | **Step Registry API'sinde eksik feature** — feedback loop taşınamayabilir | ORTA | ORTA | Faz 3'e geçmeden Step Registry'e loop abstraction eklenmesi MİMAR gerektirir. Alternatif: `FeedbackLoopOrchestrator` helper (kısıtlı migration) |
| 8 | **Hafıza tüketimi** — `_ReconCtx` büyük dict'leri persistent tutar, GC ertelenebilir | DÜŞÜK | ORTA | Profile-guided. Gerekirse metot 14 sonunda büyük cache'leri (`file_cache`) explicit `.clear()` |

---

## 8. Zaman Tahmini

Tek developer, 1M context (uzun fonksiyonu başta-sonda akılda tutabilecek).

| Faz | İş | Süre |
|---|---|---|
| **Pre-work** | Coverage baseline, golden fixture | 1 gün |
| **Faz 1** | 18 metot + `_ReconCtx` (kesme-yapıştır, 0 mantık) | 2 gün |
| **Soak (Faz 1)** | Günde 1 kez tam suite, golden diff izle | 2-3 gün (passive) |
| **Faz 2** | Dead monolith kaldır, flag flip | 2 gün |
| **Faz 3** | Feedback loop step'leri | 3 gün |
| **Test** | 36+ unit test + E2E + CI entegrasyon | 2 gün |
| **Docs** | ADR-006, CHANGELOG, migration guide | 1 gün |
| **Toplam** | — | **~11 gün (1.5 hafta net)**; soak dahil **~2 hafta takvim** |

Brief'teki "1 hafta" çok iyimserdi — Faz 3 (feedback loop migration) hafife alınmış.

---

## 9. Kabul Kriterleri (Definition of Done)

- [ ] `_execute_binary` ≤ 50 satır (hedef: ~25).
- [ ] 18 metottan hiçbiri CC ≥ 50 (radon ile doğrula).
- [ ] 246 mevcut test + 36 yeni test = **≥ 282 test** geçer.
- [ ] Golden binary artifact SHA256 parity — pre/post split aynı.
- [ ] Branch coverage `karadul/stages.py` üzerinde **düşmez**.
- [ ] `stages.py` satır sayısı ≤ 2700 (mevcut 4906'dan ≥ %45 azalma).
- [ ] ADR-006 yazılı ve `docs/adr/` altında.
- [ ] CHANGELOG'da kullanıcı-yüzü değişiklik: **0** (iç refactor, davranış değişikliği yok).

---

## 10. Açık Sorular (Berke onayı gerekli)

1. **Step Registry default `True` ne zaman oluyor?** Faz 2 bu flag'i çevirmeye dayanıyor; Berke daha önce "HEM registry HEM monolith" istemişti (satır 3408 yorumu). Deprecation window kaç release?
2. **`_ReconCtx` private mi, export mi?** Dataclass'ı sadece stages.py içinde private (`__init__.py`'de yok) tutmayı öneriyorum — dış kullanıcılar `PipelineContext`'i bilmeli, bu iç detay.
3. **Feedback loop step abstraction** — yeni bir `LoopStep` base class'ı mı, yoksa `FeedbackLoopOrchestrator` helper'ı mı? Birincisi daha temiz ama Step Registry core'a dokunur (risk). İkincisi pragmatik.
4. **Paralel ajan yasağı ne kadar sert?** v1.12.0 süresince `stages.py` dokunan herhangi başka PR açıkça reddedilmeli. Git `pre-commit` hook ile engellenebilir.

---

**SON NOT:** Bu plan `docs/migrations/stages_split_plan.md` dosyasıdır. Uygulama, bu plan ile gelen PR'ı Berke explicit onayladıktan sonra başlar. Plan değişikliği istenirse önce bu dosya güncellenir, sonra kod. Diğer ajanlar bu dosyaya okuma yapar, **yazma yapmaz**.
