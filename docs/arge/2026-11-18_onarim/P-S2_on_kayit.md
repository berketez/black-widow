# P-S2 ön kaydı — `stages.py` ölü monolit (K-3 A1) ve çift koşan blok (K-3 A1b, BORU-01) silme

Yazıldığı an: 2026-11-18, kod değişmeden ÖNCE (taban 112350e). Bu dosya kalem 1 ve 2'nin
commit'lerinden önce commit'lenir; sonradan değiştirilmez. Tutmayan madde olursa sonuç
dosyasına (`P-S2.md`) "tutmadı" diye yazılır, kural sonradan gevşetilmez.

## Ne siliniyor (metot adıyla; satırlar 112350e'deki yerler)
**A1 (çıktı değişmemeli):**
- `ReconstructionStage`: `_load_binary` (1640-1853), `_run_signature_matching`,
  `_run_byte_pattern_matching`, `_run_anti_debug_and_packer`, `_run_pcode_analysis`,
  `_run_cfg_analysis`, `_run_algorithm_engineering`, `_run_parallel_analysis`,
  `_merge_analysis_results`, `_calibrate_and_clamp`, `_run_confidence_calibration`,
  `_write_merged_algorithms`, `_apply_match_budget`, `_apply_capa_naming` (→ 2782).
- Modül düzeyi: `_match_budget_total`, `_collect_tagged_matches`, `_match_budget_sort_key`
  (100-131; yalnız `_apply_match_budget` kullanıyor).
- `_execute_binary` içinde: `if _use_step_registry:` dalının `else` kolu (eski Faz 1 yolu),
  assembly `else` kolu, sıfır turluk döngü (`_loop_iterations = 0 if _use_step_registry …`)
  ve yalnız o döngüyü besleyen hazırlık (çağrı grafiği komşuluğu, `rglob` önbelleği,
  `CVariableNamer` / `CTypeRecoverer` / `ComputationRecoveryEngine` ön örnekleri), döngü
  sonu istatistik bloğu (`if not _use_step_registry:`), ulaşılamaz `raise NotImplementedError`.
  `_use_step_registry` değişkeni kalkar; `use_step_registry=False` uyarısı korunur.
- `DeobfuscationStage._execute_legacy` (1257-1285) ve onu seçen `use_deep` anahtarı.
- Yalnız bunları sınayan testler (liste `P-S2.md`'de, çağıran-yok tablosuyla).

**A1b (çıktı bilerek değişir):** `_execute_binary`'deki "v1.10.0 M4 ESKI monolith
entegrasyon" bloğu ve ardından gelen "3.1. Engineering Struct Recovery" ikinci çağrısı
(5080-5343): CFG-iso yeniden koşusu, füzyon yeniden koşusu, MaxSMT yeniden koşusu,
`extracted_names` enjeksiyonu, `StructRecoveryEngine.recover` ikinci çağrısı,
koşulsuz `stats["timing_struct_recovery"]` yazımı.

## Ölçüm düzeni
- İkililer (4): `debian/coreutils/cat`, `debian/tree/tree`, `debian/coreutils/expr`, `mac/htop`.
- Koşu: `urun_kos.py --paralel 1`, `PYTHONHASHSEED=0`, `--taban-mac
  /Users/apple/Black_Widow/workspaces/olcum_mac/runs/ol7-c-b7faeac`. Kökler
  `~/karadul_olcum/runs/onarim-2026-11-18/P-S2/{B0a,B0b,A1,A1b}`.
- **Gürültü tabanı:** taban kodu (112350e, dondurulmuş klon `P-S2/taban_agac`) iki kez
  koşulur (B0a, B0b). B0a ↔ B0b farkı gürültüdür.
- Karşılaştırma (`P-S2/karsilastir.py`, depo dışı): ikili başına `out/` altındaki her
  dosyanın sha256'sı; farklı dosyalarda JSON ise zaman / süre / yol alanları atılıp yeniden
  karşılaştırılır; metin dosyalarında farklı satır sayısı. Ayrıca `pipeline_result.json`
  aşama istatistikleri anahtar anahtar.
- Oynak kabul edilen alanlar (önceden yazıldı): adı `timing_` ile başlayan, `_duration`,
  `_duration_s`, `duration_seconds`, `_s` ile biten süre alanları; zaman damgaları
  (`timestamp`, `generated_at`, `started_at`, `finished_at`, `date`), mutlak yollar.

## Önceden yazılan beklentiler
**A1 (kalem 1):**
- H1a: `stages.py` en az 2 600 satır kısalır (5 985 → ≤ 3 385).
- H1b: 4 ikilide `out/` dosya kümesi aynı; A1 ↔ B0a farklı dosyaları, B0a ↔ B0b farklı
  dosyalarının (gürültü) alt kümesi ya da oynak alan dışında farkı olmayan dosyalardır.
  Oynak alan dışı fark sayısı: **0**.
- H1c: `reconstruct` istatistiklerinde anahtar kümesi aynı; oynak alanlar dışında değerler
  aynı (gürültüde değişen anahtarlar hariç).
- H1d: `out/` altındaki ad haritası (`naming_map.json`) ikili başına gürültü dışında aynı.
- Karar: H1b–H1d'den biri tutmazsa kalem 1 commit'lenmez; fark açıklanana kadar durulur.

**A1b (kalem 2):**
- H2a: `reconstruct` istatistiklerinde yalnız şu anahtarlar değişebilir:
  - `timing_struct_recovery`: önce ~0,0 (blok, motor reddettiği için); sonra adımın değeri
    = `round(adım süresi, 1)`; `struct_recovery_duration_s`'in bir ondalığa yuvarlanmışından
    en çok 0,1 sapar.
  - `computation_fusion_matches`: sonra = `computation_fusion` adımının değeri; önce ≥ sonra
    (blok boş `fuse` sonucunu da sayıyordu, adım saymıyor). Eşitse fark yok.
  - `computation_fusion_accepted`: 0 = 0. `cfg_iso_matched_functions`: 0 = 0 (TIP-01).
  - `computation_fusion_injected`: iki tarafta da yok (kabul 0).
  - Başka anahtar değişirse (oynak alan / gürültü dışı) tutmadı.
- H2b: `out/` için H1b ölçütü aynen (A1b ↔ A1): oynak alan dışı fark **0**.
- H2c: `stages.py`'de `HybridCFGMatcher`, `SignatureFuser`, `StructLayoutSolver`,
  `StructRecoveryEngine` geçişi 0 (CFG-iso / füzyon / MaxSMT / yapı kurtarma yalnız adımlarda,
  ikili başına bir kez). Bir birim testi `_execute_binary` üç fazda koşarken
  `StructRecoveryEngine.recover`'ın aşama kodundan çağrılmadığını ve adımın
  `timing_struct_recovery` / `computation_fusion_matches` değerlerinin ezilmediğini sınar.
- Karar: H2a / H2b tutmazsa fark satır satır açıklanır; açıklanamayan fark varsa kalem 2
  commit'lenmez.

## Aykırı öncül (sınanacak)
"Blok gerçekten etkisiz değil": `extracted_names` enjeksiyonu (kabul 0 olduğu için bugün boş)
ve `decompiled_dir` yeniden atama (motor reddettiği için bugün yok) dışında, bloğun Faz 3'e
giden bir yan etkisi olabilir (ör. `struct_dir.mkdir`, modül düzeyi önbellek ısıtma). Bu
öncül H2b ile sınanır: `out/`'ta oynak alan dışı fark çıkarsa blok etkisiz değildi.
