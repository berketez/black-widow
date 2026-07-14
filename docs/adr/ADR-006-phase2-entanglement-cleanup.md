# ADR-006: Phase 2 inline/step entanglement temizliği (god-function migrasyonu)

**Durum:** Kabul edildi (plan) — uygulama canlı-F1 oturumuna bekletiliyor
**Tarih:** 2026-07-14
**Bağlam kaynağı:** `_execute_binary` derin kontrol-akışı araştırması (read-only, kanıta dayalı)

## Bağlam

`karadul/stages.py:_execute_binary` (~`2816-5461`, ~2645 satır) "en büyük mimari borç"
olarak biliniyordu ve varsayım "monolith'i step'e taşı" idi. **Araştırma bu varsayımı
çürüttü:** step'ler zaten yazılı ve `use_step_registry=True` DEFAULT (`config.py:581`).
Gerçek borç *taşıma* değil, **iki paralel Phase 2 implementasyonunun (inline monolith +
step'ler) tehlikeli şekilde entangle olması ve eşdeğerliklerinin HİÇ doğrulanmamış olması.**

### Kesin kontrol-akışı (default mod, kanıtlı)

- `if _use_step_registry:` bloğu (`stages.py:2855`) içinde `runner_phase2` (`2961`) çalışır:
  `feedback_loop` + `computation_struct_recovery` + `struct_recovery` step'leri.
- `feedback_loop` step'inin ürettiği `naming_result` (`2982`) **HİÇ OKUNMUYOR** ve inline
  loop iter-0'da `naming_result = None` (`3444`) ile silinip `3485`'te yeniden hesaplanıyor.
  → **step naming ÇÖPE gidiyor; inline otoriter.**
- Blok `else` ile `3060`'ta biter; `3062-4809` arası **method-body seviyesi (indent=8),
  hiçbir `_use_step_registry` guard'ı YOK** → inline feedback loop (`3283`) KOŞULSUZ çalışır.
- Final `naming_map`/`decompiled_dir`/Phase 3 seed hepsi inline lokallerinden (`4010`,
  `4082`, `4816-4845`).
- **Nüans (ör. saf israf DEĞİL):** inline `decompiled_dir`'i step'in rename ettiği dizinden
  okur (`2989`) → substrate-stacking: inline zaten-isimlenmiş sembolleri görür, "isimsiz
  fonksiyon" sayımı/convergence bozulur.

### Eşdeğerlik boşluğu (migrasyonun gerçek riski)

Çoğu naming özelliği İKİ yolda da var (CVariableNamer, BinDiff, ReferenceDiffer,
NameMerger, FunctionID/Computation/P-Code candidate'ları). **Ama 4 özellik SADECE inline'da,
step path'te YOK** (`karadul/pipeline/` içinde sıfır referans):

| Özellik | inline | step |
|---|---|---|
| FIX-1 `_recover_main_from_entry` (`stages.py:3068`) | ✅ | ❌ |
| FIX-2 gnulib fingerprint + **disambiguation** (`3072`, `disambiguate`) | ✅ | ❌ |
| FIX-3 `_recover_elf_boilerplate` (`3076`) | ✅ | ❌ |
| FIX-5 manuel override seed (`3082`) + **post-merge MUTLAK force** (`4031-4033`) | ✅ | ❌ |

Bu 4 özellik `stages.py:2409-2765` metotlarında yaşar, `extracted_names`/`_manual_overrides_map`
üzerinden yalnız inline tüketir. Step'in aldığı `extracted_names` = FIX-seam'lerinden
(`3062-3082`) ÖNCEki Phase 1 sürümü. `_feedback_naming_merger.py`'de manuel override force yok.

## Karar

### Yön: inline'ı DEĞİL step'i otoriter yap — ama SIRAYLA

- **İnline'ı kapatmak (kısa yoldan) YANLIŞ:** step path FIX-1/2/3/5 + disambiguation'dan
  yoksun → default naming REGRESYONA girer (main yanlış, gnulib isimsiz, **analistin manuel
  override'ları + MAJOR-1 mutlak-öncelik force'u kaybolur**).
- **Step Phase 2'yi kapatmak (kısa yol) daha güvenli ama substrate'i değiştirir** →
  yine canlı F1 ölçümü ister.
- **Kod-only güvenli fix YOK:** entanglement'a her dokunuş substrate/naming'i değiştirir.

### Zorunlu sıra (her adım tek başına commit + geri alınabilir)

0. **Güvenlik ağı — parity testi (ÖN KOŞUL).** `tests/test_pipeline_e2e.py:246` placeholder
   `pytest.skip`'i GERÇEK teste çevir: step-mode vs legacy-mode `naming_map` aynı fixture'da
   eşit mi. **Engel:** golden fixture'da decompiled `.c` YOK + `binary_prep`/`ghidra_metadata`
   Ghidra çağırır. → ya decompiled-`.c` fixture eklenir + entry step'leri mock/seed'lenir,
   ya da canlı küçük ELF debug-build (coreutils) ile koşulur.
1. **FIX-1/2/3/5 + disambiguation'ı `feedback_loop` step'ine PORT et.** Step'in
   `extracted_names` seed'ine FIX-1/2/3 + disambiguation, merger'ına manuel-override post-force
   (`_feedback_naming_merger.py`). Parity testi bu adımdan sonra step==inline vermeli.
2. **Canlı F1 baseline** (before) al — `scripts/mac_f1_eval.py` + `~/coreutils_gt` veya Docker
   Linux ELF. ~24 dk/binary; en az 3-4 binary.
3. **İnline Phase 2'yi `if not _use_step_registry:` ile sar** (veya çıkar). Default mod artık
   yalnız step path. Canlı F1 (after) == baseline olmalı (regresyon yok).
4. Legacy inline Phase 1 (`3096-3183`) + Phase 3 (`4894-5461`) — default'ta ölü — ayrı
   "legacy retire" kararıyla (use_step_registry=False tüketicisi teyidi + Berke onayı) silinir.

## Sonuçlar

- **Neden bu oturumda uygulanmadı:** (1) kod-only güvenli fix yok → canlı F1 şart;
  (2) parity güvenlik ağı bile Ghidra/fixture altyapısı gerektiriyor; (3) `stages.py` Phase 2
  naming AYNI GÜN 2 kez değişti (override `a8b0acb`, disambiguation `18b0e6e`) → kalp
  ameliyatını taze değişiklik üstüne yığmak = bisect kaybı + risk çarpımı.
- **Risk (yapılmazsa):** double-execution CPU israfı + substrate-stacking naming'i sessizce
  bozuyor olabilir (F1 etkisi ölçülmedi). Correctness açığı DEĞİL (çıktı deterministik,
  inline otoriter), ama verimlilik + potansiyel naming-kalite kaybı.
- **Canlı koşu gerektiren belirsizlikler:** (a) herhangi bir Phase 3 step'i struct_recovery
  step artifact'ını `requires` ediyor mu (step Phase 2'yi kapatmak Phase 3'ü kırar mı);
  (b) substrate-stacking'in gerçek F1 farkı; (c) FIX-seam'leri step-mode'da dosya buluyor mu.

## İlgili dosyalar
- `karadul/stages.py` (`_execute_binary` 2816-5461; FIX-seam metotları 2409-2765;
  step Phase 2 2961-3002; inline loop 3183-4803; Phase 3 4810-4893)
- `karadul/pipeline/steps/feedback_loop.py`, `_feedback_naming.py`, `_feedback_naming_merger.py`
- `karadul/config.py:581`
- `tests/test_pipeline_e2e.py:246` (placeholder parity skip)
- `tests/fixtures/golden/sample_macho/static/` (Ghidra JSON var, decompiled `.c` YOK)
