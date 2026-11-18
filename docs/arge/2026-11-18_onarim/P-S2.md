# P-S2 — `stages.py`: onaylı ölü kod silme (K-3 A1) ve çift koşan blok (K-3 A1b, BORU-01) — ilerleme

Brif: `ONARIM_BRIF.md`. Karar: K-3 (Berke, 2026-11-18 10:1x: "çöpler hangisiyse, asla kullanılmayacak olanlar hangisiyse onları sil"). Bulgular: BORU-12 (ölü kod haritası), BORU-01 (çift koşan blok), bağlam BORU-03 / BORU-04 (`kulvar_BORU.md`), P10.md § "P-S2'ye". Ön kayıt: `P-S2_on_kayit.md` (f4e9ae1, kod değişmeden önce).

- Taban: worktree `origin/main`'den (e9d2d08) açıldı; `git merge --ff-only main` → fa010ad, ardından main ilerledi → yeniden ff → **112350e**.
- `karadul.__file__` worktree yolunu gösteriyor.
- Ölçüm kökü: `~/karadul_olcum/runs/onarim-2026-11-18/P-S2/` — `taban_agac/` (112350e'nin `git clone --shared` kopyası, çalışma zamanı verisi symlink), `B0a/`, `B0b/` (taban, iki kez: gürültü), `A1/`, `A1b/`, karşılaştırıcı `karsilastir.py`, sonuçlar `*.json`.

| Kalem | Durum | Commit |
|---|---|---|
| 0 — ön kayıt | bitti | f4e9ae1 |
| 1 — A1 ölü monolit + `_execute_legacy` + yalnız onları sınayan testler | bitti | 7c5ed28 |
| 2 — A1b çift koşan blok (BORU-01) | bitti | 059cb4e |
| 3 — kalan çağrılmayan metotlar (silinmez, liste) | bitti | (bu commit, yalnız belge) |

## Gürültü tabanı (B0a ↔ B0b, aynı kod 112350e, `PYTHONHASHSEED=0`, `--paralel 1`)
Karşılaştırıcı: `out/` altındaki her dosya sha256; farklıysa JSON'da oynak alanlar (ön kayıttaki liste) atılıp, metinde zaman / süre / yol maskelenip yeniden; HTML istatistik tablosu ve README istatistik satırı sıralanarak (satır sırası adımların bitiş sırasına bağlı). Ayrıca `pipeline_result.json` aşama istatistikleri anahtar anahtar.

| ikili | `out/` dosya | bayt bayt aynı | yalnız oynak alanda farklı | gerçek fark |
|---|---|---|---|---|
| debian/coreutils/cat | 329 | 325 | 4 (README, report.html/json, compile_commands) | 0 |
| debian/tree/tree | 280 | 276 | 2 | 2: `report.json` + `report.html`'de `data_flow_edges` 120 ↔ 128 |
| debian/coreutils/expr | 336 | 332 | 4 | 0 |
| mac/htop | 850 | 846 | 4 | 0 |

- Bütün `.c` / `.h` / ad haritası dosyaları iki koşuda bayt bayt aynı. Tek gerçek gürültü: tree'de `reconstruct.stats.data_flow_edges` (120 ↔ 128; aynı kodla belirlenimci değil, bu paketin konusu değil → P12 / P18'e not).

## Kalem 1 — K-3 A1: ölü monolit, `_execute_legacy` ve yalnız onları sınayan testler

### Çağıran-yok kanıtı
- **`_use_step_registry` her zaman True:** 112350e'de `_execute_binary` girişinde `if not _use_step_registry: logger.warning(...); _use_step_registry = True` (satır 3330-3343). Sonrasında değişkene başka atama yok (AST: tek atama deyimi). Yani `if _use_step_registry: … else: …` dallarının `else` kolu (3528-3580 Faz 1, 3607-3692 assembly) ve `_loop_iterations = 0 if _use_step_registry else …` ile `range(0)` döngüsü (3812-5066) hiç koşmuyor; `if not _use_step_registry:` döngü sonu istatistiği (5071-5078) koşmuyor; Faz 3 dalı her zaman `return` ettiği için sondaki `raise NotImplementedError` (5452) ulaşılamaz.
- **`use_deep=False` kuran yok:** depoda (karadul/, ui/, scripts/) her `DeobfuscationStage(...)` çağrısı argümansız ya da `use_deep=True` (`scripts/cursor_3bundle_analysis.py:267`); `config.py:299 use_deep_deobfuscation` hiçbir yerde okunmuyor (grep: yalnız tanım). `_execute_legacy`'nin tek çağıranı `execute`'taki `if self._use_deep` yanlış kolu.
- **AST taraması** (`cagiran_tara.py` + `kanit_tablosu.py`, depo dışı, scratchpad): stages.py içindeki her atıf (Attribute / Name / tam eşleşen dizgi sabiti) bulunup bulunduğu yere göre sınıflandı; depo geneli (stages.py dışı, `.claude`/`node_modules` hariç) ayrıca tarandı. stages.py'de 2. argümanı sabit olmayan `getattr`/`setattr`/`hasattr`/`vars` ve `__dict__` kullanımı **0** (dinamik çağrı yolu yok). Etkin koddan atıf: **0** (aşağıda). stages.py dışı atıflar yalnız testler; `karadul/analyzers/cpp_rtti.py` atfı kendi sınıfının aynı adlı `_load_binary` metodu (başka sınıf).

| Silinen tanım | satır (112350e) | stages.py içi atıflar (sınıf) | etkin atıf | stages.py dışı atıf |
|---|---|---|---|---|
| `_match_budget_total` | 100-107 | silinen _apply_match_budget: 2675 | 0 | tests/test_stages_calibrate_split.py |
| `_collect_tagged_matches` | 110-121 | silinen _apply_match_budget: 2683 | 0 | tests/test_stages_calibrate_split.py |
| `_match_budget_sort_key` | 124-131 | silinen _apply_match_budget: 2684 | 0 | tests/test_stages_calibrate_split.py |
| `DeobfuscationStage._execute_legacy` | 1257-1285 | execute: `if self._use_deep` yanlış kolu (use_deep=False kuran yok): 1044 | 0 | tests/test_deobfuscation_routing.py |
| `ReconstructionStage._load_binary` | 1640-1853 | ana if'in else kolu (use_step_registry=False; değişken her zaman True'ya zorlanıyor): 3528 | 0 | tests/test_stages_split_parity.py, karadul/analyzers/cpp_rtti.py |
| `ReconstructionStage._run_signature_matching` | 1864-1920 | ana if'in else kolu (use_step_registry=False; değişken her zaman True'ya zorlanıyor): 3562 | 0 | tests/test_stages_split_parity.py, tests/test_cikti_hatalari.py |
| `ReconstructionStage._run_byte_pattern_matching` | 1922-2026 | ana if'in else kolu (use_step_registry=False; değişken her zaman True'ya zorlanıyor): 3564 | 0 | tests/test_stages_split_parity.py |
| `ReconstructionStage._run_anti_debug_and_packer` | 2028-2140 | ana if'in else kolu (use_step_registry=False; değişken her zaman True'ya zorlanıyor): 3569 | 0 | yok |
| `ReconstructionStage._run_pcode_analysis` | 2142-2234 | ana if'in else kolu (use_step_registry=False; değişken her zaman True'ya zorlanıyor): 3570 | 0 | tests/test_stages_split_parity.py |
| `ReconstructionStage._run_cfg_analysis` | 2236-2272 | ana if'in else kolu (use_step_registry=False; değişken her zaman True'ya zorlanıyor): 3573 | 0 | tests/test_stages_split_parity.py |
| `ReconstructionStage._run_algorithm_engineering` | 2274-2297 | ana if'in else kolu (use_step_registry=False; değişken her zaman True'ya zorlanıyor): 3575 | 0 | tests/test_stages_split_parity.py, tests/test_stages_algorithm_engineering_split.py |
| `ReconstructionStage._run_parallel_analysis` | 2299-2461 | silinen _run_algorithm_engineering: 2294 | 0 | tests/test_stages_algorithm_engineering_split.py |
| `ReconstructionStage._merge_analysis_results` | 2463-2512 | silinen _run_algorithm_engineering: 2295 | 0 | tests/test_stages_algorithm_engineering_split.py |
| `ReconstructionStage._calibrate_and_clamp` | 2514-2537 | silinen _run_algorithm_engineering: 2296 | 0 | tests/test_stages_algorithm_engineering_split.py, tests/test_stages_calibrate_split.py |
| `ReconstructionStage._run_confidence_calibration` | 2539-2626 | silinen _calibrate_and_clamp: 2535 | 0 | tests/test_stages_calibrate_split.py |
| `ReconstructionStage._write_merged_algorithms` | 2628-2655 | silinen _calibrate_and_clamp: 2536 | 0 | tests/test_stages_calibrate_split.py |
| `ReconstructionStage._apply_match_budget` | 2657-2698 | silinen _calibrate_and_clamp: 2537 | 0 | tests/test_stages_calibrate_split.py |
| `ReconstructionStage._apply_capa_naming` | 2700-2782 | silinen _run_algorithm_engineering: 2297 | 0 | tests/test_stages_algorithm_engineering_split.py |

### Silinenler (stages.py 5 985 → 3 153 satır, −2 832; ön kayıt H1a: ≤ 3 385 → tuttu)
- `ReconstructionStage`: yukarıdaki 14 metot (eski satırlar 1640-2783).
- Modül düzeyi: üç bütçe yardımcısı + başlık yorumu (91-133).
- `DeobfuscationStage`: `_execute_legacy` ve `__init__(*, use_deep)` (anahtarın tek işlevi legacy'yi seçmekti); `execute`'ta JS ailesi doğrudan `_execute_deep`.
- `_execute_binary`: Faz 1 `else` kolu; assembly `if _use_step_registry: pass else: …`; sıfır turluk döngü ve yalnız onu besleyen hazırlık (çağrı grafiği komşuluğu, `rglob` önbelleği, `CVariableNamer`/`CTypeRecoverer`/`ComputationRecoveryEngine` ön örnekleri — üçünün kurucusu yalnız örnek alanı yazıyor, modül düzeyi yan etki yok); döngü sonu istatistik bloğu; ulaşılamaz `raise`. İki `if _use_step_registry:` gövdesi 4 boşluk sola alındı; `_use_step_registry` artık yalnız uyarı koşulunda okunuyor (`use_step_registry=False` uyarısı korundu, metin aynı).
- Yalnız ölü yolun okuduğu köprü adları (`c_files`, `_file_cache`, `binary_for_byte_match`, `pcode_json`, `fid_json`, `decompiled_json`, `output_dir`, `byte_pattern_names`, `_cfg_result`, `_pcode_naming_candidates`, `calibrated_matches`, `target`) ve `_manual_overrides_map` ataması (dönüş değeri yalnız silinen döngüde okunuyordu; çağrı kaldı).
- Kullanılmaz kalan içe aktarımlar: `os`, `shutil`, `tempfile`, `ThreadPoolExecutor`/`as_completed`, `CPU_PERF_CORES`, `_TARGET_PLATFORM_MAP`, isteğe bağlı `NameMerger`/`NamingCandidate`. (Önceden de kullanılmayan `copy`, `TargetDetector` dokunulmadı.)
- **Etkin kodun değişmediği AST ile gösterildi** (`a1_dogrula.py`): kalan her tanım (docstring hariç) eskisiyle `ast.dump` düzeyinde aynı; `_execute_binary` 62 deyim → 78 deyim, eski gövdeye yukarıdaki dönüşümler uygulanarak kurulan beklenen deyim listesiyle birebir aynı (girinti değişikliği çok satırlı dizgileri de bozmadı); `DeobfuscationStage.execute` beklenen dönüşümle aynı.

### Testler
- **Silinen (yalnız ölü metotları sınıyordu):** `tests/test_stages_calibrate_split.py` (466 satır: `_calibrate_and_clamp`, `_run_confidence_calibration`, `_write_merged_algorithms`, `_apply_match_budget`, bütçe yardımcıları), `tests/test_stages_algorithm_engineering_split.py` (335 satır: `_run_algorithm_engineering`, `_run_parallel_analysis`, `_merge_analysis_results`, `_calibrate_and_clamp`, `_apply_capa_naming`).
- **Kısmen silinen:** `tests/test_stages_split_parity.py` (`_load_binary` ×2 ve `_run_*` ×6 testi + yardımcıları; `_prepare_workspace` ve `ReconstructionContext` testleri kaldı), `tests/test_cikti_hatalari.py` (iki "monolit yolu eşlik testi": `_run_signature_matching`), `tests/test_deobfuscation_routing.py` (legacy sütunu, `use_deep` parametrizasyonu, `test_js_bundle_legacy_equals_direct_legacy`), `tests/test_v192_fixes.py` (`_TARGET_PLATFORM_MAP` iki testi: sabit yalnız silinen `_run_signature_matching`'de okunuyordu; etkin okuyucu `ghidra_metadata` adımı).
- **Uyarlanan (ölü kodun metnini arıyordu):** `tests/test_saglamlik_onlemleri.py` (`auto_populate=_ref_dl_allowed(...)` yalnız ölü döngüdeydi → artık "stages.py'de `ReferenceDiffer` yok"), `tests/test_v160_fixes.py` (`TargetType` `_execute_binary`'de yalnız ölü assembly dalında okunuyordu; "yerel değil" denetimi kaldı), `tests/test_deobf_honest_success.py` (`use_deep=True` argümanı), `tests/test_manual_overrides.py` (yorum: dönen haritayı zorlayan tek yer ölü döngüydü → **B-C6 açık**).
- **Yeni kilit:** `tests/test_ps2_olu_kod.py` — 14 ölü metot + 3 yardımcı yok, `DeobfuscationStage(use_deep=False)` → `TypeError`, `_execute_binary`'de üst düzey döngü / `raise` / döngü adları yok, `_use_step_registry` tek okuma; `use_step_registry=False` uyarır ve üç fazı koşar, `True` uyarmaz. Eski koda (112350e) karşı: 21 testin 21'i kırmızı (son ikisi eski kodda sahte koşucunun vermediği `c_files` yüzünden — eski döngü hazırlığı `len(c_files)` okuyordu); yeni kodda 21/21 yeşil.
- İlgili test dosyaları (stages / aşama sınıflarını anan 44 dosya + yeni): 951 geçti, 1 atlandı; tek kırmızı kalem 2'nin testi (blok hâlâ yerindeyken beklenen).
- **Mutasyon** `scripts/measurement/mutation_specs_ps2.json` (bu kalem): 4/4 öldü (uyarı susar, uyarı koşulsuz, JS derin hatta gitmez, tur sayısı aşamada 0 ile ezilir).

### Başka paketlerin mutant tanımları (yama)
Girinti değişikliği 6 mutantın `find` metnini, silme 2 mutantın hedefini kaldırdı (`mutant_uygulanir_mi.py` ile bulundu). Yamalar (`git apply --check` temiz):
- `yamalar/P-S2__mutation_specs_adim3_hat.json.patch`: `stages_adim_listede_yok`, `stages_baglama_tohuma_verilmez`, `stages_kunye_tohum_cagrisina_verilmez`, `stages_kapaliyken_kunye_uretilir` 4 boşluk sola. Yamalı tanım yeni kodla **50/50 öldü**.
- `yamalar/P-S2__mutation_specs_ps1.json.patch`: `basari_yapit_sayisi_asama` 4 boşluk sola. **34/34**.
- `yamalar/P-S2__mutation_specs_rapor_sayaclari.json.patch`: `rs_tur_kosulsuz_ezilir`, `rs_tur_kosul_ters` çıkarıldı (hedefleri silinen döngü sonu bloğu; yerine `ps2_a1_tur_sayisi_ezilir`, aynı testler öldürüyor); `rs_neden_none_tohuma_girer` 4 boşluk sola. **13/13**.
- `yamalar/P-S2__cursor_3bundle_analysis.py.patch`: `DeobfuscationStage(use_deep=True)` → `DeobfuscationStage()` (parametre kalktı; betik yamasız `TypeError` verir).

### Çıktı-aynı denetimi (ön kayıt H1b–H1d) — A1 ↔ B0a ve A1 ↔ B0b
| ikili | `out/` dosya | A1↔B0a bayt aynı | A1↔B0a gerçek fark | A1↔B0b gerçek fark |
|---|---|---|---|---|
| debian/coreutils/cat | 329 | 325 | **0** | 0 |
| debian/tree/tree | 280 | 276 | **0** | 2 (`data_flow_edges` 120 ↔ 128 = gürültü; A1 = B0a = 120) |
| debian/coreutils/expr | 336 | 332 | **0** | 0 |
| mac/htop | 850 | 846 | **0** | 0 |

- Bayt bayt aynı olmayan 4 dosya her ikilide README / report.html / report.json / compile_commands.json; farkları yalnız oynak alanlarda (süre, zaman, yol, satır sırası).
- Aşama istatistiklerinin anahtar kümesi 4/4 ikilide aynı (`anahtar_kumesi.py`: fark 0); değerler oynak alanlar dışında aynı (H1c tuttu). Ad haritaları ve bütün `.c` / `.h` bayt bayt aynı (H1d tuttu).
- Sağlamlık denetimi (`saglamlik_denetle.py`): B0a ve A1 kusur tablosu aynı (eski_fonksiyon_adi_yorumda_kalan 25, fonksiyon_anahtari_ghidrada_yok 6, yerel_son_tur_baska_adla_fonksiyon 87, baslik_tanim_farkli 4, yerel_ilk_tur_baska_adla_fonksiyon 1).
- A1 koşusu worktree'den, kod kirli (commit'ten önce): künyede `f4e9ae1` + kirli `karadul/stages.py`; koşu sırasında yalnız test dosyaları değişti (`agac_degisti: true` bundan), `stages.py` koşu öncesi ve sonrası bayt bayt aynı (`cmp`).
- **Ön kayıt kalem 1: H1a–H1d tuttu.**

## Kalem 2 — K-3 A1b (BORU-01): "ESKİ monolith entegrasyon" bloğu

### Önce (A1 = 7c5ed28; blok yerinde, koşulsuz)
- Blok `_execute_binary`'de Faz 2'den sonra, Faz 3'ten önce, `_use_step_registry`'ye bakmadan koşuyordu: (a) `CFGAnalyzer().analyze(cfg_json)` + `HybridCFGMatcher` ile CFG-iso'yu baştan yapıp `stats.cfg_iso_matched_functions`'ı eziyordu; (b) `SignatureFuser` ile füzyonu baştan yapıp `computation_fusion_matches/accepted`'ı eziyordu (boş `fuse` sonucunu da sayarak); (c) bayrak açıkken MaxSMT çözücüsünü bütün ikili için ikinci kez koşturuyordu; (d) kabul edilen füzyon adlarını Faz 2 bittikten sonra `extracted_names`'e yazıp `computation_fusion_injected` sayıyordu (Faz 3 tohumunda `extracted_names` yok: hiçbir ada ulaşmıyordu, BORU-03); (e) `StructRecoveryEngine.recover`'ı girdi = çıktı = `struct_recovered` ile ikinci kez çağırıyordu (P10'dan beri motor bunu reddediyor) ve (f) koşulsuz `stats["timing_struct_recovery"]` yazıyordu.
- Ölçülen etki (4 ikili, B0a = A1): `timing_struct_recovery` **0,0** (4/4; adımın gerçek süresi 0,15–0,60 sn iken). CFG-iso ve füzyon ikili başına iki kez koşuyordu.

### Onarım
- Blok (13 deyim, eski 2271-2534) silindi; yalnız bloğun okuduğu köprü adları (`reconstructed_dir`, `ghidra_types_json`, `cfg_json`, `_pcode_result`) kalktı. Faz 2 yorumu güncellendi (MaxSMT adayları P10'dan beri `struct_recovery` adımında). AST karşılaştırması (`a1b_dogrula.py`): blok ve dört köprü adı dışında `_execute_binary` ve diğer 38 tanım eskisiyle aynı.
- stages.py 3 153 → **2 885** satır (A1 + A1b toplam: 5 985 → 2 885, −3 100).
- Neyin koptuğu (P10.md § "P-S2'ye" ile karşılaştırıldı): CFG-iso / füzyon / MaxSMT değerleri artık adımların değeri; `computation_fusion_injected` sayacı ve enjeksiyon gitti (davranış yoktu); `--maxsmt-struct` adım yolundan çalışmaya devam ediyor (P10 Kalem 1; `tests/test_p10_maxsmt.py` 8/8 yeşil); `timing_struct_recovery` adımın süresi.

### Sonra (A1b ↔ A1, 4 ikili) — ön kayıt H2a–H2c
| ikili | `timing_struct_recovery` önce → sonra | adım süresi `struct_recovery_duration_s` (A1b) | `computation_fusion_matches` önce → sonra | `cfg_iso_matched_functions` | `computation_fusion_accepted` | `out/` gerçek fark |
|---|---|---|---|---|---|---|
| debian/coreutils/cat | 0,0 → **0,1** | 0,1453 | 66 → 66 | 0 → 0 | 0 → 0 | **0** |
| debian/tree/tree | 0,0 → **0,2** | 0,1957 | 70 → 70 | 0 → 0 | 0 → 0 | **0** |
| debian/coreutils/expr | 0,0 → **0,2** | 0,1547 | 68 → 68 | 0 → 0 | 0 → 0 | **0** |
| mac/htop | 0,0 → **0,5** | 0,5219 | 196 → 196 | 0 → 0 | 0 → 0 | 2 (yalnız `data_flow_edges` 4 274 → 4 287: gürültü, aşağıda) |

- H2a: `timing_struct_recovery` = `round(adım süresi, 1)` 4/4 (sapma 0); `computation_fusion_matches` önce = sonra (4/4; ≤ beklentisi eşitlikle tuttu: bu ikililerde boş `fuse` sonucu yok); accepted / CFG-iso 0 = 0; `computation_fusion_injected` iki tarafta da yok; istatistik anahtar kümesi aynı (`anahtar_kumesi.py`: 0). Oynak alan dışında değişen tek anahtar htop `data_flow_edges` — **gürültü**: `reconstruct.stats.data_flow_edges` aynı kodla da değişiyor (B0a ↔ B0b tree 120 ↔ 128) ve kaynağı `karadul/reconstruction/engineering/data_flow.py:783-797` (`ThreadPoolExecutor` + `as_completed` ile `all_func_code.update` / kenar listesi birleştirme sırası). htop girdisiyle Ghidra'sız yeniden oynatma (`veri_akisi_tekrar.py`, aynı girdi 6 kez, A1b çalışma alanı `reconstructed/commented`): `total_edges` = 4 286, 4 286, 4 286, 4 286, **4 273**, 4 286 (13 kenarlık salınım; koşular arasındaki fark da 13). Bloğun veri akışına giden bir yolu yok (veri akışı Faz 3 `deep_tracing`'de diskteki `.c`'den okuyor; bütün `.c` iki koşuda bayt bayt aynı). **H2a tuttu** (gürültü notuyla).
- H2b: `out/` 4/4 ikilide oynak alan dışında aynı (htop'taki tek fark yukarıdaki gürültü sayacı; `.c` / `.h` / ad haritaları bayt bayt aynı). Çalışma alanında `reconstructed/struct_recovered/` (298 / 252 / 300 / 792 dosya) ve `struct_recovered_candidates/` A1 ↔ A1b oynak alan dışında aynı (`ws_yapi_karsilastir.py`: fark 0). B0a ↔ A1b de aynı sonuç (yalnız htop `data_flow_edges`). **H2b tuttu.**
- H2c: stages.py kodunda (yorum dışı, AST) `HybridCFGMatcher`, `SignatureFuser`, `StructLayoutSolver`, `StructRecoveryEngine`, `CFGAnalyzer`, `computation_fusion_injected` geçişi **0** (`test_stages_hesaplama_kollarini_icermez`). **H2c tuttu.**
- Aykırı öncül ("blok gerçekten etkisiz değil"): **çürütüldü** — bloğun silinmesi `out/`'ta ve yapı kurtarma ağacında hiçbir şeyi değiştirmedi; tek etkisi yanlış sayaçlardı (`timing_struct_recovery` 0,0).

### Testler ve mutasyon
- `tests/test_ps2_olu_kod.py::TestCiftKosuYok` (4 test): adımın `timing_struct_recovery` değeri (1,7) ve `computation_fusion_matches` (7) ezilmez, `computation_fusion_injected` yazılmaz; `StructRecoveryEngine.recover` ve `CFGAnalyzer.analyze` aşama kodundan hiç çağrılmaz; stages.py kodunda hesaplama kollarına atıf yok. A1 koduna (7c5ed28) karşı **4/4 kırmızı**, doğru nedenle (`0.0 == 1.7`, `1 == 7`, çağrılar `['cfg_analyze', 'struct_recover']`, yasak adlar bulundu).
- `tests/test_computation_integration.py`: `TestMaxSMTCandidatePassesToEngine` yeniden yazıldı (aday yolu `struct_recovery` adımının `requires`'ında, stages.py'de kopya yok; eski koda karşı kırmızı); `TestFusionInjectsExtractedNames` silindi (metin testiydi, davranış yoktu; gerekçe dosyada yorum olarak).
- `mutation_specs_ps2.json` son kodla **8/8 öldü** (A1 4 + A1b 4: süre ezilir, füzyon sayacı ezilir, yapı motoru geri gelir, CFG-iso geri gelir). P10 mutant tanımı son kodla **32/32**; yamalı başka paket tanımları son kodla 50/50, 34/34, 13/13.

## Kalem 3 — silmeden sonra stages.py'de kalan, çağrılmayan kod (SİLİNMEDİ; ayrı onay gerekir)
Yöntem: `cagiran_tara.py` son ağaçta yeniden koşuldu (iç çağıran + stages.py dışı üretim atfı; testler ayrı); dinamik `getattr` yok.

| Ne | Yer (son ağaç) | Durum | Not |
|---|---|---|---|
| `_collect_all_algorithms` (modül fonksiyonu) | stages.py:65-72 | üretimde çağıran **0** (tek çağıranı A1b bloğuydu) | Adımlar kendi kopyalarını kullanıyor (`semantic_naming.py:159` "step-local kopyası", `struct_recovery`, `deep_tracing`, `engineering_annotation`, `_engineering_helpers`); stages.py'den içe aktaran yok. Tek atıf `tests/test_v192_fixes.py::TestStagesModuleLevelHelpers` (4 test). |
| İkinci `_seed_recovery_pre_names` çağrısı (Faz 2 sonrası) | `_execute_binary` | çalışıyor, etkisiz | Yorumu "guard'lar sayesinde no-op" diyor (`test_main_gnulib_seed_ordering::test_second_call_changes_nothing`). Mutasyona uğrattığı `extracted_names`'i A1b'den sonra okuyan yok (Faz 3 tohumunda yok); dönüş değeri (elle ad haritası) A1'den sonra okunmuyor → **B-C6** ("elle ad birleştirme sonrası zorlanır") bugün hiçbir yerde uygulanmıyor; zorlayan tek yer silinen ölü döngüdeydi. |
| `deob_dir` yereli, `copy` / `TargetDetector` içe aktarımları, `DynamicAnalysisStage.execute`'ta `dynamic_dir` | stages.py | kullanılmıyor | Bu paketten önce de kullanılmıyordu (pyflakes tabanı); dokunulmadı. |

Bu paketin dosyası olmayan, ama silmeyle ilgili notlar (dokunulmadı):
- `karadul/pipeline/reconstruction_context.py`: `ReconstructionContext`'in 42 alanı / metodundan (41 alan + `ensure_loop_state`) üretim kodunda `rc.` ile kullanılan 8'i (`artifacts`, `stats`, `errors`, `dirs`, `workspace_dir`, `binary_path`, `static_dir`, `reconstructed_dir`); `start` / `stage_name` kurucu argümanı olarak veriliyor; kalan 32'si (`warnings`, `ph1_artifacts`, `phase1_*`, `sig_matches` … `loop_state`, `ensure_loop_state`) üretimde hiç okunmuyor ya da yazılmıyor (`rc_alanlari.py`). Testleri `tests/test_stages_split_parity.py`'de duruyor. Sahibi `karadul/pipeline/**` (P11).
- **K-3 "eski deobfuscation zinciri" düzeltmesine ek bulgu:** `DeobfuscationManager.run_chain` (synchrony / babel zinciri) yalnız `ElectronAnalyzer.deobfuscate()` (`analyzers/electron.py:537`) içinden çağrılıyor; `ElectronAnalyzer.deobfuscate()` ve `JavaScriptAnalyzer.deobfuscate()`'in analiz akışındaki tek çağıranı `_execute_legacy` idi (JS ailesi, `use_deep=False`). Yani zincir bu paketten ÖNCE de `karadul analyze`'da hiç koşmuyordu (`ElectronAnalyzer.__init__` yalnız `DeobfuscationManager(config)` kuruyor). Bu paket erişilebilirliği değiştirmedi. Zincirin A (kopya, `deep_pipeline.py` aynı işi yapıyor) mı B (bağlanacak) mı olduğu ayrı karar; `deobfuscators/**` ve `analyzers/**` bu paketin dosyası değil.
- `config.py:299 use_deep_deobfuscation` hiçbir yerde okunmuyor (A1 öncesi de); `DeobfuscationStage`'den `use_deep` kalktığı için artık hiçbir anlamı yok → P15a / BORU-13 listesine.

## Tam takım
`PYTHONDONTWRITEBYTECODE=1 python -m pytest -q -p no:cacheprovider` (son kod 059cb4e'deki hâl, çalışma zamanı verisi symlink'li): **9 143 geçti, 10 atlandı, 153 seçim dışı, 0 kaldı** (291 sn). Bu paketin test sayısına etkisi (`--collect-only`): dokunulan 11 eski dosyada 112350e'de 324 toplanan test → 255 (−69: ölü yolu ya da yalnız onun metnini sınayanlar; 2 dosya bütünüyle), artı yeni `tests/test_ps2_olu_kod.py` 25.

## Ana oturumun bilmesi gerekenler
1. **Yamalar uygulanmadan başka paketlerin mutant tanımlarında 8 mutant 'error' verir** (girinti değişti / hedef silindi): `yamalar/P-S2__mutation_specs_{adim3_hat,ps1,rapor_sayaclari}.json.patch` (yamalı hâlleri son kodla 50/50, 34/34, 13/13). `rs_tur_*` iki mutantın yerini `mutation_specs_ps2.json`'daki `ps2_a1_tur_sayisi_ezilir` tutuyor.
2. `DeobfuscationStage` artık argüman almıyor: `scripts/cursor_3bundle_analysis.py:267` yamasız `TypeError` verir → `yamalar/P-S2__cursor_3bundle_analysis.py.patch`.
3. **B-C6 açık:** elle verilen adı birleştirmeden sonra zorlayan tek kod ölü döngüdeydi; şimdi hiç yok (davranış değişmedi, zaten koşmuyordu). `_seed_recovery_pre_names`'in dönüş değeri okunmuyor.
4. **Eski deobfuscation zinciri:** K-3 düzeltmesindeki "Electron kullanıyor" yalnız kurucu için doğru; `DeobfuscationManager.run_chain` analiz akışında bu paketten önce de koşmuyordu (tek yol `_execute_legacy` idi). Ayrı karar (kalem 3 notu).
5. Gürültü: `reconstruct.stats.data_flow_edges` aynı kodla belirlenimci değil (`data_flow.py:783-797`, `as_completed` birleştirme sırası; tree 120 ↔ 128, htop 4 273 ↔ 4 286/4 287) → P12 / P18 (ya da veri akışının sahibi).
6. Ölçüm araçları depo dışında: `~/karadul_olcum/runs/onarim-2026-11-18/P-S2/{karsilastir.py, anahtar_kumesi.py, ws_yapi_karsilastir.py, veri_akisi_tekrar.py}`; AST kanıt betikleri oturum scratchpad'inde (`cagiran_tara.py`, `kanit_tablosu.py`, `a1_dogrula.py`, `a1b_dogrula.py`, `mutant_uygulanir_mi.py`) — kalıcı değil; sonuçları bu dosyada.
7. `taban_agac/` (112350e'nin `git clone --shared` kopyası; nesneleri ana depodan alternates ile okur, ana depoya yazmaz) ölçüm kökünde duruyor. Gerekmezse silinebilir (onaya bağlı).

## PAKET BİTTİ
