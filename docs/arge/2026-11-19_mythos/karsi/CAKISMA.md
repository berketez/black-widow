# KARŞI hattı — dosya çakışma haritası ve dalga önerisi (2026-11-19)

- Kapsam: KİMLİK (PK-1 … PK-11), ÖZ KOD (ÖK-1 … ÖK-7, ÖK-V), ÖLÇÜ (P-Ö1 … P-Ö9), ÜST VERİ (P-ÜV0 … P-ÜV9), ÖLÇEK
  (ÖLÇ-0 / A / 1 / 2, ÖL-1 … ÖL-11), HIZ (HZ-0 … HZ-9; **yalnız dosya taraması**, içerik denetlenmedi), yayın kapısı
  §4–§5 (D1 … D7, G1 … G4), onarımın kalanı (P12d, P18, P10b, P08b, P03b, P23, P24 ve `OKU.md` "2026-11-19 sonrası").
- Bitiş çizgisi (KARARLAR A-7): bütün planlar uygulanmış, bekletilen katmanlar ölçülüp karara bağlanmış, uygulama
  Berke'nin makinesine kurulu, gerçek büyük bir uygulamada uçtan uca çalışmış. "Yayından önce / sonra" ayrımı yok.
- Üretim: `PYTHONDONTWRITEBYTECODE=1 python scripts/arge/karsi/plan_tara.py --json $V/plan_tara.json` (74 paket) ve
  `python scripts/arge/karsi/cakisma_tablo.py --json $V/cakisma.json > $V/cakisma_tablo.md`
  (`$V` = `~/karadul_olcum/runs/arge-2026-11-19/karsi`).
- **Okuma kuralı:** §1 tablosu plan metinlerinde ters tırnakla anılan yolların mekanik dökümüdür. "Paketler" sütunu
  dosyayı **anan** paketlerdir (yazan ya da okuyan); bir paket dosyayı yalnız "dokunmaz / değişmez / salt okur" geçen
  satırda anıyorsa son sütuna düşer. Kesin yazma kümesi her paketin kendi "Dokunacağı dosyalar" satırıdır; gönderimden
  önce o satırla karşılaştırılmalıdır. Onarım paketleri (P03b, P08b, P10b, P23, P24) `config.py` ve `stages.py`'ye
  yazmaz, `yamalar/` altına yama bırakır; yamayı ana oturum uygular (yine sıralı iş).

## 1. İki ve daha çok paketin andığı dosyalar (betik çıktısı)

| Dosya | Anan paket sayısı | Paketler (yazar ya da okur) | Yalnız "dokunmaz" diyenler |
|---|---|---|---|
| `karadul/config.py` | 17 | HIZ:HZ-5, KİMLİK:PK-4, KİMLİK:PK-5, KİMLİK:PK-7, ÖLÇEK:ÖL-1, ÖLÇEK:ÖL-10, ÖLÇEK:ÖL-11, ÖLÇEK:ÖL-2, ÖLÇEK:ÖL-5a, ÖLÇEK:ÖL-6, ÖLÇEK:ÖL-9, ÖZ KOD:ÖK-1, ÖZ KOD:ÖK-2, ÖZ KOD:ÖK-3, ÖZ KOD:ÖK-4b, ÖZ KOD:ÖK-6, ÜST VERİ:P-ÜV6 | KİMLİK:PK-1, ONARIM:P03b, ONARIM:P08b, ONARIM:P10b, ONARIM:P23, ONARIM:P24, ÜST VERİ:P-ÜV1 |
| `karadul/ghidra/headless.py` | 12 | HIZ:HZ-1, HIZ:HZ-3, HIZ:HZ-4a, HIZ:HZ-4b, HIZ:HZ-5, HIZ:HZ-8, KİMLİK:PK-8, ÖLÇEK:ÖL-1, ÖLÇEK:ÖL-10, ÖLÇEK:ÖL-2, ÖLÇEK:ÖL-3, ÖLÇEK:ÖL-6 | ÖLÇEK:ÖL-4 |
| `karadul/reconstruction/c_namer.py` | 6 | ONARIM:P12d, ÖZ KOD:ÖK-1, ÖZ KOD:ÖK-2, ÖZ KOD:ÖK-3, ÖZ KOD:ÖK-6, ÜST VERİ:P-ÜV6 | ONARIM:P18 |
| `karadul/analyzers/macho.py` | 5 | HIZ:HZ-1, ÖLÇEK:ÖL-10, ÖLÇEK:ÖL-3, ÖLÇEK:ÖL-3b, ÖLÇEK:ÖL-9 | ÖLÇEK:ÖL-1, ÖLÇEK:ÖL-2, ÖLÇEK:ÖL-5a |
| `karadul/stages.py` | 5 | ÖLÇEK:ÖL-10, ÖLÇEK:ÖL-5a, ÖZ KOD:ÖK-4b, ÜST VERİ:P-ÜV5, ÜST VERİ:P-ÜV6 | ONARIM:P03b, ONARIM:P08b, ONARIM:P10b, ONARIM:P18, ONARIM:P23, ÖZ KOD:ÖK-1, ÖZ KOD:ÖK-4a, ÜST VERİ:P-ÜV1 |
| `karadul/cli.py` | 4 | HIZ:HZ-5, KİMLİK:PK-10, ÖLÇEK:ÖL-4, ÖLÇEK:ÖL-5b | ONARIM:P24, ÖLÇEK:ÖL-1, ÖLÇEK:ÖL-5a |
| `karadul/core/naming_labels.py` | 4 | KİMLİK:PK-4, KİMLİK:PK-7, ÖZ KOD:ÖK-4b, ÜST VERİ:P-ÜV6 | ÜST VERİ:P-ÜV5 |
| `karadul/analyzers/app_bundle.py` | 3 | ÖLÇEK:ÖL-11, ÖLÇEK:ÖL-5a, ÖLÇEK:ÖL-5b | — |
| `karadul/analyzers/binary_intelligence.py` | 3 | HIZ:HZ-5, HIZ:HZ-6, ÖLÇEK:ÖL-3b | — |
| `karadul/core/pipeline.py` | 3 | ÖLÇEK:ÖL-1, ÖLÇEK:ÖL-5b, ÖLÇEK:ÖL-6 | ÖLÇEK:ÖL-4, ÖLÇEK:ÖL-5a |
| `karadul/core/workspace.py` | 3 | HIZ:HZ-8, ÖLÇEK:ÖL-5b, ÖLÇEK:ÖL-6 | — |
| `karadul/pipeline/steps/_feedback_naming_candidates.py` | 3 | KİMLİK:PK-5, ÜST VERİ:P-ÜV4, ÜST VERİ:P-ÜV6 | — |
| `karadul/reconstruction/tarif/alt_kanal.py` | 3 | ÖZ KOD:ÖK-1, ÖZ KOD:ÖK-3, ÜST VERİ:P-ÜV6 | — |
| `scripts/measurement/alt_kanal.py` | 3 | ÖZ KOD:ÖK-1, ÖZ KOD:ÖK-3, ÜST VERİ:P-ÜV6 | — |
| `scripts/measurement/urun_kos.py` | 3 | ÖLÇÜ:P-Ö6, ÖLÇÜ:P-Ö7, ÜST VERİ:P-ÜV5 | ÖLÇEK:ÖLÇ-A |
| `tests/test_p12a_on_ad_guveni.py` | 3 | KİMLİK:PK-1, KİMLİK:PK-4, ÖZ KOD:ÖK-4b | — |
| `tests/test_p16a_ghidra_sonuc.py` | 3 | HIZ:HZ-1, HIZ:HZ-4a, ÖLÇEK:ÖL-3 | — |
| `tests/test_p16c_analiz_suresi.py` | 3 | HIZ:HZ-1, HIZ:HZ-5, ÖLÇEK:ÖL-1 | — |
| `karadul/core/bilesen_sinifi.py` | 2 | ÖLÇEK:ÖL-11, ÖLÇEK:ÖL-5a | — |
| `karadul/ghidra/bsim.py` | 2 | HIZ:HZ-2, ÖLÇEK:ÖL-2 | ÖLÇEK:ÖL-1 |
| `karadul/lm/guard.py` | 2 | ONARIM:P24, ÜST VERİ:P-ÜV6 | — |
| `karadul/lm/tools/__init__.py` | 2 | ONARIM:P24, ÜST VERİ:P-ÜV6 | — |
| `karadul/pipeline/steps/_feedback_naming_bindiff.py` | 2 | KİMLİK:PK-1, KİMLİK:PK-4 | — |
| `karadul/pipeline/steps/_feedback_naming_merger.py` | 2 | KİMLİK:PK-5, ÜST VERİ:P-ÜV6 | — |
| `karadul/reconstruction/kimlik/kanal.py` | 2 | KİMLİK:PK-4, KİMLİK:PK-7 | — |
| `karadul/reconstruction/kimlik/olgu.py` | 2 | KİMLİK:PK-2, KİMLİK:PK-8 | — |
| `karadul/reconstruction/tarif/baglama.py` | 2 | ÖZ KOD:ÖK-4b, ÜST VERİ:P-ÜV6 | ÜST VERİ:P-ÜV5 |
| `karadul/reconstruction/tarif/kayit_cifti.py` | 2 | ÖZ KOD:ÖK-4a, ÖZ KOD:ÖK-4b | — |
| `karadul/reconstruction/tarif/veri_sozcukleri.py` | 2 | KİMLİK:PK-2, ÖZ KOD:ÖK-4a | — |
| `scripts/measurement/kimlik_ciftler.py` | 2 | KİMLİK:PK-11, KİMLİK:PK-6 | — |
| `scripts/measurement/ks1_olc.py` | 2 | ÜST VERİ:P-ÜV0, ÜST VERİ:P-ÜV4 | KİMLİK:PK-3, ÖLÇÜ:P-Ö1 |
| `scripts/measurement/olcek_kos.py` | 2 | HIZ:HZ-0, ÖLÇEK:ÖLÇ-A | — |
| `scripts/measurement/p09_olc.py` | 2 | ONARIM:P10b, ONARIM:P18 | — |
| `scripts/measurement/urun_olc.py` | 2 | ÖLÇÜ:P-Ö1, ÜST VERİ:P-ÜV6 | ÖZ KOD:ÖK-1, ÖZ KOD:ÖK-4b, ÜST VERİ:P-ÜV8 |
| `tests/test_p15a_etkisiz.py` | 2 | HIZ:HZ-5, ÜST VERİ:P-ÜV6 | — |
| `tests/test_p16b_bsim.py` | 2 | HIZ:HZ-2, ÖLÇEK:ÖL-2 | — |
| `tests/test_p16c_bsim_toplu.py` | 2 | HIZ:HZ-2, ÖLÇEK:ÖL-2 | — |
| `ui/server.py` | 2 | ÖLÇEK:ÖL-4, ÖLÇEK:ÖL-8 | — |

### 1.1 Betiğin göremediği çakışmalar (elle; kaynak satırı yanında)

| Dosya | Paketler | Kaynak |
|---|---|---|
| `karadul/analyzers/dotnet_binary.py` | yayın D1 (gömülü `*.props` / `*.targets`), P23 kalem 5 (MEK-14) | `YAYIN_KAPISI.md` §4; `P23.md` kalem 5 |
| `karadul/analyzers/binary_intelligence.py` | yayın D2 (IMZA-01 kalanı), ÖL-3b, HZ-5, HZ-6 | `YAYIN_KAPISI.md` §4; `olcek/PLAN.md` §1; `hiz/PLAN.md` |
| `karadul/core/target.py`, `karadul/analyzers/app_bundle.py` | yayın D3 = ÖL-5a → ÖL-5b → ÖL-11 | `olcek/PLAN.md` §1 |
| `karadul/core/naming_labels.py` + `tests/test_p12a_on_ad_guveni.py` | yayın D5 (gnulib satırı 0,706 → ölçülen), PK-4, PK-7, ÖK-4b, P-ÜV6 | `YAYIN_KAPISI.md` §4; `OKU.md` |
| `karadul/ghidra/headless.py` `_extract_xrefs` | ÖL-3, HZ-4a, PK-8 (aynı işlev) | `olcek/PLAN.md` §1; `hiz/PLAN.md` satır 179; `kimlik/PLAN.md` PK-8 |
| `karadul/ghidra/headless.py` + `karadul/config.py` (`Timeouts`) | yayın G1 / G2 / G3 = ÖL-1 (+ ÖL-4 gösterim) | `YAYIN_KAPISI.md` §5 |
| `karadul/analyzers/go_binary.py` | yayın G4 = P-ÜV1, P-ÜV6 | `YAYIN_KAPISI.md` §5 |
| `karadul/reconstruction/c_type_recoverer.py` | P18 yaması (+ 78 test), HZ-5 | `OKU.md`; `hiz/PLAN.md` satır 104 |
| `karadul/pipeline/steps/feedback_loop.py`, `_feedback_loop_iter.py` | ÖL-7 (ara kopyalar, `file_cache`), HZ-7 (yeniden kurma, süreç havuzları) | `olcek/PLAN.md` ÖL-7; `hiz/PLAN.md` satır 228–230 (HZ-7 metni 13:20'de yazılmamıştı: "Profil bitince yazılacak") |
| `karadul/reconstruction/c_project_builder.py`, `karadul/core/output_formatter.py`, `scripts/measurement/p09_olc.py` | P18 → P10b | `plan_tara.json` |
| `karadul/reconstruction/c_namer.py` `_strategy_string_context` | P12d → ÖK-1 → ÖK-2 → ÖK-3 (aynı işlev) | `ozkod/PLAN.md` §0 |
| Üç ayrı "ikili okuyucu" (aynı iş, üç yeni dosya) | P-ÜV0 `analyzers/ustveri/goruntu.py`; ÖK-4a `tarif/veri_sozcukleri.py`; PK-2 `kimlik/olgu.py` | `KARSI.md` İ-9 |
| `scripts/measurement/urun_olc.py` | P-Ö1 (biçim satırı), `OKU.md` "ölçüm aracı kusurları", P-ÜV6; ÖK-1 / ÖK-4b / P-ÜV8 okur | `plan_tara.json`; `OKU.md` |
| Tek Ghidra kuyruğu (dosya değil, kaynak) | ÖLÇ-1 (27 sa duvar), ÖLÇ-2, HZ-0, HZ-9, 119'luk birleşik ölçüm isteyen her ad paketi, PK-4 (4 tam koşu), PK-6, PK-11, ÖK-5 / ÖK-V koşuları, P-Ö6 / 7 / 8, P-ÜV5 (8 Mach-O × 2), P-ÜV8, P10b / P08b / P03b ölçümleri | her planın "aynı anda en çok 1 Ghidra koşusu" kuralı |

## 2. Çakışmayı azaltan üç yapısal öneri

1. **Bayrak ön paketi (yeni; tek ajan, ilk dalga).** Bütün planların `karadul/config.py`'ye ekleyeceği alanlar tek
   pakette, öntanımı kapalı ve `INERT_SETTINGS` kaydıyla eklenir (liste planlardan: `enable_anchored_reference_matching`,
   `enable_separate_debug_naming`, `debug_file_dirs`, `anchored_reference_witness_gate`, `oz_ad_verbatim`,
   `oz_ad_uniqueness_gate`, `enable_unique_identifier_names`, `enable_record_affix_names`,
   `enable_module_prefix_evidence`, `enable_go_metadata_recovery`, `enable_go_pclntab_naming`,
   `enable_go_metadata_integrity`, `enable_objc_metadata_recovery`, `enable_objc_metadata_naming`,
   `enable_swift_metadata_recovery`, `enable_swift_metadata_naming`, `enable_macho_entry_main`, ÖLÇEK'in
   `analysis.*`, `bsim.*`, `timeouts.ghidra_adim`, `paket.*`, `kaynak.*`, `onbellek.*`, `buyuk_ikili.*`,
   `reconstruct.ara_kopyalar` alanları ve HZ-5'in donanım künyesi). Aynı pakette ad eşiği sabiti tek yerde
   (`karadul/core/naming_labels.py`; `KARSI.md` İ-3). Sonraki paketler `config.py`'ye yazmaz, yalnız okur:
   17 sıralı yazma 1'e iner. Alan adları planlardaki adlarla aynı kalır; paketlerin metni değişmez.
2. **Ortak ikili okuyucu önce (P-ÜV0).** ÖK-4a ve PK-2, P-ÜV0'ın `Goruntu` arayüzünü kullanır (`KARSI.md` İ-9).
3. **Ghidra kuyruğu tek listede.** Ana oturum tutar; sıra: (a) kısa ve çok paketi açan ölçümler (119'luk birleşik
   ölçüm, 8 Mach-O), (b) erken risk ölçümleri (ÖK-5, PK-6, PK-11), (c) uzun ölçek koşuları gece. ÖLÇ-1'in T100 / T300 /
   PAKET duvarları 2 saate insin (`KARSI.md` İ-2). HZ-0 ve ÖLÇ-1 aynı hedefleri ölçüyor: tek koşuda birleşsin.

## 3. Dalga önerisi

Ölçütler: **bağımlılık** (kim kimi bekler), **risk** (tutmama olasılığı yüksek olan erken öğrenilir),
**doğrulanabilirlik** (öbürlerinin "önce" sayısını veren ölçüm önce). Aynı satırdaki `→` sıralı, `║` paralel.
Her dalgada en çok 4 kod ajanı; aynı dosyaya yazan iki paket aynı dalgada paralel gitmez.

### Dalga 0 — zemin ve "önce" sayıları (ürün davranışı değişmez)

| İş | Neden önce | Dosya kümesi |
|---|---|---|
| Onarım kapanışı: tam takım → son doğrulama mutasyonları → 9 bayat mutasyon tanımı → push kararı (ana oturum) | her şeyin tabanı; main origin'in önünde | yok (ölçüm) |
| Bayrak ön paketi (§2.1) | 17 paketin `config.py` sırasını kaldırır | `karadul/config.py`, `karadul/core/naming_labels.py` (yalnız sabit) |
| P-Ö1 (biçim satırı) → `OKU.md` ölçüm aracı kusurları (`ks1_olc` `BITTI`, `masum_kapi` `sarif`) | bütün ad paketlerinin "önce / sonra" sayısı bu araçtan | `scripts/measurement/urun_olc.py`, `ks1_olc.py`, `ad_bicimi.py` (yeni) |
| ÖLÇ-A ║ HZ-1 (ölçüm kancaları) → ÖLÇ-0 → ÖLÇ-1 + HZ-0 (birleşik; kısaltılmış duvar) | ÖLÇEK ve HIZ'ın bütün paketlerinin "önce" sayısı; bitiş koşulunun bugünkü durumu | `scripts/measurement/olcek_kos.py` (yeni); `headless.py` (HZ-1: `headless.py`'nin ilk yazarı) |
| P-ÜV8 kalem 1–3 (hedef seti: sembollü ikiliden GT) | hedef nüfusun "önce" sayısı (`KARSI.md` İ-1) | `scripts/measurement/ustveri_olc.py` (yeni) |
| P-ÜV9: Ghidra'nın gösteri çıktısındaki adları ve fonksiyon sınırları | üst veri kanallarının ürün etkisinin ön koşulu; koşu gerektirmez | yalnız okuma |
| **Erken risk ölçümleri, araştırma betikleriyle:** ÖK-5 (kör nüfus; veri indi), PK-6 + PK-11 (`scripts/arge/kimlik/`; veri V1 / V2 / V5) | tutmazsa PK-2 / 3 / 4 / 7 / 8 / 9 / 10 ve ÖK-3 / 4b / 6 yazılmaz (10 paket) | yalnız `scripts/arge/`, `scripts/measurement/kimlik_ciftler.py` |
| ÖL-10 tasarım turu (belge; kod yok) | bitiş koşulunun tek çaresi, en az belirlenmiş paket (`KARSI.md` İ-2) | yalnız belge |

### Dalga 1 — ölçülmüş kusur onarımları ve ortak altyapı (birbirinden bağımsız)

| Hat | Paketler | Ortak dosya |
|---|---|---|
| `c_namer` zinciri | P12d → ÖK-1 (aynı ajan, sırayla) | `karadul/reconstruction/c_namer.py` |
| Başvuru yolu | PK-1 | `_feedback_naming_bindiff.py`, `_feedback_naming_refdiff.py`, `_feedback_naming_candidates.py` (ilk yazar) |
| Okuyucu zemini | P-ÜV0 | yalnız yeni dosya |
| Köprü | ÖL-1 ║ ÖL-4 (ilerleme sözleşmesi `olcek/PLAN.md` §1'de sabit) | `headless.py` (HZ-1'den sonra), `cli.py`, `ui/` |
| `main` | P-ÜV5 | `stages.py` `_recover_main_from_entry` |
| Küçükler | D1 (`dotnet_binary.py`; P23'ten önce) ║ D4 ║ P24 (yalnız yeni dosya + yama) ║ P18 (yama + 78 test) | ayrık |

### Dalga 2 — okuyucular, bütçeler, bekletilen katmanların ölçümü

| Hat | Paketler | Ortak dosya |
|---|---|---|
| Üst veri okuyucuları | P-ÜV1 ║ P-ÜV2 ║ P-ÜV4 → P-ÜV3 ║ P-ÜV7 → P-ÜV8 kalem 4 | yalnız yeni dosya |
| Kayıt çifti / eşleyici (Dalga 0 hükmü tuttuysa) | ÖK-4a ║ PK-2 (ikisi de P-ÜV0 üstüne) → PK-3 | yalnız yeni dosya |
| Köprü zinciri | ÖL-2 → HZ-2 (`bsim.py`) ; ÖL-3 + HZ-4a (birleşik; `_extract_xrefs`) → HZ-3 → ÖL-6 | `headless.py`, `bsim.py`, `macho.py` |
| Paket yöneticisi | ÖL-5a (= D3) | `target.py`, `app_bundle.py`, `stages.py` `_execute_app_bundle`, `pipeline.py` |
| İstihbarat | D2 → ÖL-3b → HZ-6 | `binary_intelligence.py` |
| `c_namer` zinciri | ÖK-2 | `c_namer.py` |
| Bekletilen katmanlar (ölç ve karara bağla) | P10b (P18'den sonra) ║ P08b ║ P03b | kendi dosyaları; `config.py` / `stages.py` yamaları ana oturumda |

### Dalga 3 — kanal bağlama (ortak dosyaların yoğun olduğu dalga; tek sıra)

`_feedback_naming_candidates.py`, `_feedback_naming_merger.py`, `naming_labels.py`, `stages.py`, `baglama.py` üstünde
**tek sıra**: PK-5 → P-ÜV6 → PK-4 → PK-7 → ÖK-4b. `c_namer.py` üstünde: ÖK-3 → ÖK-6 (P-ÜV6 `c_namer.py`'ye de değiyorsa
ÖK-6'dan sonra). Paralel gidebilenler (ayrık dosya): ÖL-5b, ÖL-9, HZ-5 (bayrak ön paketi alanları eklediyse
`config.py`'ye yazmaz), HZ-8, PK-9. HZ-7 metni yazılınca ÖL-7 ile aynı dosyalarda (`feedback_loop.py`) sıraya girer.
Her kanal paketi iki sette ölçülür (119 + hedef seti); 119'da beklenti "yeni yanlış 0".

### Dalga 4 — büyük ikili, kapanış

ÖL-10 (tasarım turundan çıkan metinle; `headless.py`, `macho.py`, `stages.py`) → ÖL-7 ║ ÖL-8 ║ ÖL-11 ║ PK-8 (`_extract_xrefs`:
ÖL-3 / HZ-4a'dan sonra) ║ PK-10 → ÖLÇ-2 + HZ-9 (birleşik "sonra" ölçümü) → 119 birleşik ölçüm + hedef seti ölçümü →
K-1 / K-4 bayrak kararları (ölçümle; ana oturum + Berke) → P23 (son: silme, mypy, CI) → Y8 (uygulama derleme ve kurulum) →
Y7 (KaradulLM gerçek model duman listeleri) → Y6 (gerçek büyük uygulamada uçtan uca) → Y9 / Y10 (sürüm, günlük, kılavuz).

### Risk sırası (hangi sonuç erken öğrenilmeli)

| # | Soru | Öğreten iş | Tutmazsa ne değişir |
|---|---|---|---|
| 1 | Gösteri dilimi (T25) boş makinede ne kadarda bitiyor, hangi adım ne kadar? (yük altında: 7 761,6 sn, çıkış 3 "kısmi", 17 ad; `gosteri_oku.txt`) | ÖLÇ-0, ÖLÇ-1 / HZ-0 | bitiş koşulu; ÖL / HZ önceliği |
| 2 | Tembel kipte hangi ad kanalı ayakta kalır? | ÖL-10 tasarım turu | PK-4, P-ÜV6, ÖK-4b kabul ölçümleri |
| 3 | Çapalı eşleme başka programlarda, gömülü kitaplıkta ve C++'ta tutuyor mu? | PK-6, PK-11 (araştırma betikleriyle) | KİMLİK'in 7 ürün paketi |
| 4 | K1 / G1 kör nüfusta ve hedef setinde tutuyor mu? | ÖK-5 | ÖK-3, ÖK-4b, ÖK-6 |
| 5 | Ghidra, üst verinin gösterdiği adreslerde fonksiyon açıyor mu (Go ≥ 1.26)? | P-ÜV9 (gösteri çıktısı) | P-ÜV6'nın bağlama biçimi (ön ad tohumu mu, sonradan mı) |
| 6 | Yapı yeniden yazımı ölçümle açılabilir mi? | P10b | bekletilen katman kararı |

### Doğrulanabilirlik sırası (hangi ölçüm öbürlerinin "önce" sayısını verir)

1. 119'luk birleşik ölçüm, biçim satırıyla (P-Ö1): bütün ad paketleri.
2. Hedef seti ölçümü (P-ÜV8 kalem 1–3): P-ÜV1 … P-ÜV7, PK-11, ÖK-5'in hedef kolu.
3. ÖLÇ-1 / HZ-0 (ölçek ve hız tabanı): ÖL-1 … ÖL-11, HZ-1 … HZ-8.
4. `kimlik_olc` yeniden üretimi (PK-3): PK-4, PK-7, PK-8.
