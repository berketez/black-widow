# Karadul v1.11.0-beta Release Notes

**Tag:** v1.11.0-beta
**Tarih:** 2026-04-23
**Durum:** Beta (stabil 1.11.0 ve 1.12.0 roadmap'te)
**Önceki stabil:** v1.10.0 (2026-04-21, commit `37e647c`)

## Öne Çıkanlar

- **Jython sunset Faz 1 tamamlandı** — 10/10 Ghidra script'i PyGhidra 3.0'a
  (Python 3.10+) taşındı. Orijinaller `karadul/ghidra/scripts/legacy/`
  altında backup; acil rollback için `use_legacy_jython_scripts` feature
  flag'i korundu. Her script için AST + JSON schema + header parity testi
  yazıldı.
- **stages.py monolit parçalandı** — `_execute_binary` 3173 → 2520 satır
  (-650 LOC), cyclomatic complexity 800 → 523. Faz 2 + Faz 3 + Faz 6A
  tamamlandı; 382 satırlık `_run_algorithm_engineering` 24 satırlık
  coordinator'a düşürüldü (CC=73 → CC=1). 35 parity testiyle davranış
  değişmezliği doğrulandı.
- **sig_db modüler migrasyon (4/17 kategori, 1421 unique sembol)** —
  `sigdb_builtin/` altında crypto (621), compression (214), network (340),
  pe_runtime (246). `signature_db.py` 10242 LOC monolit override/loader
  ile köprülenip korunuyor (geriye uyumlu).
- **Gerçek stripped baseline** — macOS `strip` sahte-stripping yapıyor ve
  benchmark altyapısı bunları "exact match" sayıyordu (yanıltıcı F1=1.000).
  `_compare_maps` step 4 preserved/renamed ayrımıyla düzeltildi; Linux ELF
  `strip --strip-all` fixture'ı eklendi. Gerçek baseline: **F1=0.000**,
  **recovery=0%** (user fonksiyonları resolve edilemiyor — bu v1.12.0'ın
  öncelikli hedefi).
- **angr pipeline backend adapter iskelet** — Protocol tabanlı decompiler
  abstraction üzerinden angr ilk kez pipeline'a bağlandı.
- **`artifacts_pending` → `produce_artifact` API** — 14 step yeni
  `StepContext.produce_artifact(key, value)` API'sine çevrildi; stage-level
  side artifact'lar runner'ın `produces` contract'ını artık bypass etmiyor.
  Eski sözlük mirror'u v1.12.0'a kadar geriye uyumlu.
- **BSim shadow + opsiyonel fusion köprü** — `use_bsim_fusion` flag
  (default `False`) ile candidate + merger helper'ları entegre. 3 binary
  shadow dataset'i toplandı (2599 match). BSim native API erişilemediği
  için lite mode discrete similarity ile çalışıyor.
- **CI benchmark gate** — `.github/workflows/benchmark.yml` + floor kontrol
  scripti. Regresyon engelleme altyapısı kuruldu (şu an `renamed_f1 >= 0.0`
  floor'u, v1.13'te 0.5'e yükselecek).

## Breaking Changes

Yok — bu sürüm **tamamen geriye uyumludur**.

- `pc.metadata["artifacts_pending"]` mirror'u korunuyor (deprecated,
  v1.12.0'a kadar çalışır).
- `BenchmarkMetrics` eski alanlar değişmedi; yeni `preserved_*` ve
  `renamed_*` alanları eklendi. `preserved_names=0` iken davranış birebir
  v1.10.0 ile aynı.
- Feature flag `config.perf.use_legacy_jython_scripts` (default `False`)
  rollback sunuyor; `True` verildiğinde eski Jython 2.7 script'leri
  çalışır.

## Upgrade Notes

1. **Bağımlılık:** `pyproject.toml` `[ghidra]` extras'a
   `pyghidra>=3.0.0,<4.0` eklendi. Ghidra 11.3+ gereklidir (Jython 2.7
   bundle'ı Ghidra tarafında da deprecated).
2. **Ghidra sürümü:** Şu an **12.0_DEV** kullanılıyor. 12.0.4 stable
   kurulumu v1.12'ye ertelendi; beta'da 12.0_DEV ile test edildi.
3. **Opsiyonel bağımlılıklar:** `[trex]` extras yeni iskelet için
   eklendi; TRex P-code export henüz skeleton seviyesinde, production
   hazır değil.
4. **Benchmark metrikleri:** Eski run'larınızdaki F1 rakamları
   (özellikle macOS fixture'larında) yanıltıcı olabilir. Yeni
   `renamed_f1` alanını kullanın; `preserved_names` ile kaç sembolün
   zaten korunduğunu görün.
5. **LLM kullanımı:** Karadul mimarisi **LLM kullanmama kararı**
   üzerine kurulu (deterministik, CPU-only). v1.11.0-beta bu kararı
   sürdürüyor; naming/decompile'da LLM çağrısı yok.

## Bilinen Sınırlamalar

- **Stripped Linux ELF user fonksiyonları resolve edilemiyor**
  (`renamed_f1 = 0.000`, 6/6 missing). v1.12.0'ın birincil hedefi.
- **BSim native API** erişilemiyor; lite mode discrete similarity
  (`{1.0, 0.85, 0.65}`) devrede.
- **`_calibrate_and_clamp` CC=48** — Dalga 7'de iç split yapılacak.
- **`signature_db.py` 10242 LOC monolit** hâlâ duruyor (13/17 kategori
  migre bekliyor).
- Kapsam dışı bırakılanlar: iOS decryption, ARM64e PAC, dyld_shared_cache
  deep, il2cpp deep, Hermes, Flutter AOT, embedded firmware (bkz.
  CHANGELOG "Scope Lock").

## Metrikler

| Ölçüt | v1.10.0 | v1.11.0-beta |
|---|---|---|
| Test sayısı | 3241 | ~3800+ |
| Silent except fix | — | 34 |
| mypy fix | — | 102 |
| sig_db entry (modüler) | 0 | 1421 |
| Jython → PyGhidra | 0/10 | 10/10 |
| `_execute_binary` LOC | 3173 | 2520 |
| `_execute_binary` CC | 800 | 523 |
| Commit (bu sürüm) | — | 15 |
| Dosya değişimi | — | 170 dosya, +22479 / -1415 LOC |

## Full CHANGELOG

Detaylı liste için `CHANGELOG.md` dosyasındaki `[1.11.0-beta] - 2026-04-23`
bloğuna bakın. Her madde ilgili commit hash'i ile referanslandı.
