# P-S2 — `stages.py`: onaylı ölü kod silme (K-3 A1) ve çift koşan blok (K-3 A1b, BORU-01) — ilerleme

Brif: `ONARIM_BRIF.md`. Karar: K-3 (Berke, 2026-11-18 10:1x: "çöpler hangisiyse, asla kullanılmayacak olanlar hangisiyse onları sil"). Bulgular: BORU-12 (ölü kod haritası), BORU-01 (çift koşan blok), bağlam BORU-03 / BORU-04 (`kulvar_BORU.md`), P10.md § "P-S2'ye". Ön kayıt: `P-S2_on_kayit.md` (f4e9ae1, kod değişmeden önce).

- Taban: worktree `origin/main`'den (e9d2d08) açıldı; `git merge --ff-only main` → fa010ad, ardından main ilerledi → yeniden ff → **112350e**.
- `karadul.__file__` worktree yolunu gösteriyor.
- Ölçüm kökü: `~/karadul_olcum/runs/onarim-2026-11-18/P-S2/` — `taban_agac/` (112350e'nin `git clone --shared` kopyası, çalışma zamanı verisi symlink), `B0a/`, `B0b/` (taban, iki kez: gürültü), `A1/`, `A1b/`, karşılaştırıcı `karsilastir.py`, sonuçlar `*.json`.

| Kalem | Durum | Commit |
|---|---|---|
| 0 — ön kayıt | bitti | f4e9ae1 |
| 1 — A1 ölü monolit + `_execute_legacy` + yalnız onları sınayan testler | bitti | (bu commit) |
| 2 — A1b çift koşan blok (BORU-01) | bekliyor | |
| 3 — kalan çağrılmayan metotlar (silinmez, liste) | bekliyor | |

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
