# MUTBAKIM — 9 bayat mutasyon tanımının bakımı (ilerleme)

- Paket metni: `docs/arge/2026-11-20_dalga0/gonderim/MUTBAKIM.md`
- Taban: `b4e02be` (main, `git merge --ff-only main` sonrası)
- Geçici dosyalar: `~/karadul_olcum/runs/dalga0-2026-11-20/MUTBAKIM/`
- Ürün kodu ve var olan testler değişmez; yalnız 9 tanım + yeni `tests/test_mutbakim_*.py`.

## Kaynak (OKU.md, 2026-11-19 toplu koşu)

| Tanım | öldü | hayatta | hata |
|---|---|---|---|
| p20 | 25 | 1 | 0 |
| ps1 | 33 | 0 | 1 |
| adim3_hat | 47 | 0 | 3 |
| p13a | 21 | 1 | 0 |
| p12a | 14 | 0 | 1 |
| ad_gecerliligi | 51 | 0 | 2 |
| adim3_c_namer | 19 | 1 | 1 |
| p05 | 16 | 0 | 4 |
| adim3_ui | 27 | 0 | 3 |

Ana oturumun son doğrulaması (`~/karadul_olcum/runs/dalga0-2026-11-20/son_dogrulama/p20.log`, b6aceb9): p20 25 / 1 hayatta (`p20_k6_bayrak_ontanimli_acik`).

## Ortam ve yöntem

- Bağlar (ORTAK_D0 §2; commit'lenmez): `scripts/node_modules`, `sigs`, `vendor`, `signatures_homebrew.json`, `signatures_homebrew_bytes.json`, `sigs_macos_system.json`, `signatures.lmdb`. `scripts/node_modules` olmadan p20'nin 15 testi atlanıyordu.
  - Not: `scripts/node_modules`, `sigs`, `vendor` bağları `git status`'ta `??` görünüyor (`.gitignore` kalıpları dizin biçiminde, bağı kapsamıyor); dosyalar adıyla stage edildi, bağ commit'lenmedi.
- "Önce" koşusu: worktree'de `b4e02be` koduyla, 9 tanım sırayla (`~/karadul_olcum/runs/dalga0-2026-11-20/MUTBAKIM/once_*.log`). Dokuzunun sayıları OKU.md'dekiyle birebir aynı.
- Durağan denetim (`~/karadul_olcum/runs/dalga0-2026-11-20/MUTBAKIM/bin/denetle.py`): her `find`'in modüldeki eşleşme sayısı ve `find` / `replace` bayt uzunluğu. Probe birden çok eşleşmede hata vermiyor (ilkini değiştiriyor), bu yüzden tekillik ayrıca denetlendi. Önce: 15 eşleşmesiz, 1 çoklu (`cn_hepsi_sustu_sayilmaz`, 2 eşleşme), 5 aynı bayt uzunluklu replace. Sonra: 0 / 0 / 0.
- "Sonra" koşusu: aynı sırayla `sonra_*.log`.

## Tanımlar

### p20 — önce 25 öldü / 1 hayatta / 0 hata → sonra 27 / 0 / 0 (27 mutant)

- **Hayatta: `p20_k6_bayrak_ontanimli_acik` — karar: BAYAT (gerçek açık değil).**
  - Mutant `deep_pipeline._synchrony_prepass_enabled`'da `getattr(analysis, "deep_synchrony_prepass", False) is True` → `getattr(…, True) is not False` yapıyordu. Hedef test `test_prepass_is_off_by_default` `Config()` kuruyor.
  - Kanıt: `ba3bfee` (P20 yaması, `karadul/config.py`) alanı `AnalysisConfig`'e öntanım `False` ile ekledi. O günden beri `Config` ile kurulan her hatta alan var; `getattr`'ın yedek değeri (mutantın "öntanımlı açık" yarısı) erişilemez. `False is not False` → `False`: test haklı olarak geçiyor.
  - Mutantın iki niyeti ayrıldı:
    1. **Öntanımlı açık** (aynı kimlik `p20_k6_bayrak_ontanimli_acik`): öntanım artık `config.py`'de → `deep_synchrony_prepass: bool = False` → `= True`; test aynı (`test_prepass_is_off_by_default`). Öldü.
    2. **Dize 'false' açık sayılır** (yeni `p20_k6_dize_false_acik`): `is True` → `is not False`; test `test_prepass_flag_requires_true_not_truthy` (YAML'dan gelen `"false"` açılmamalı). Öldü.
  - Not: mutant `karadul/config.py`'yi yalnız koşu süresince değiştirir (probe geri yazar); `config.py`'ye kalıcı yazım yok (A-19).
- Kaldırılan mutant yok; yeni test yok.

### ps1 — önce 33 öldü / 0 hayatta / 1 hata → sonra 34 / 0 / 0 (34 mutant)

- **Hata: `kapsayici_js_hattina`** (P19: tanınan kapsayıcı yine JS hattına düşer). `find` eşleşmiyordu.
  - Kodu değiştiren commit: `715f024` (P-S4 / BICIM-10, "dürüst durumlar"): `ReconstructionStage`'deki `if target.target_type == TargetType.UNKNOWN and (…).get("container"):` koşulu genel `if target.target_type == TargetType.UNKNOWN:` dalına katıldı (kapsayıcısız UNKNOWN da atlanıyor).
  - Niyet korundu: mutant yalnız kapsayıcıyı dışarıda bırakır (`… == TargetType.UNKNOWN and not (target.metadata or {}).get("container")`), kapsayıcısız UNKNOWN atlanmaya devam eder; `find` üç satırlık tekil blok (`return StageResult(… skipped=True,` dahil; dosyada 4 `if target.target_type == TargetType.UNKNOWN:` var). Test aynı (`test_synthetic_wheel_is_skipped_not_js`). Öldü.
  - Not: `mutation_specs_ps4.json`'daki `ps4` mutantı aynı bloğu öbür yönde bozuyor (yalnız kapsayıcı atlanır); ikisi birlikte dalın iki yarısını kilitliyor.
- Kaldırılan mutant yok; yeni test yok.

### adim3_hat — önce 47 öldü / 0 hayatta / 3 hata → sonra 50 / 0 / 0 (50 mutant)

- **Hata: `hat_kunye_c_namera_gecmez`, `hat_kunye_yokken_de_gecer`** (`_feedback_naming.py`, ön ad künyesinin c_namer'a geçişi). Kodu değiştiren commit: `1811b8d` (AD-12, K-3 A5: ölü paralel ad koşucusu silindi). Künye iletimi eskiden paralel koşucunun `else` dalındaydı; dal silinince satırlar 4 boşluk sola kaydı. Niyet ve `replace` aynı, yalnız girinti güncellendi. İkisi de öldü.
- **Hata: `hat_merger_esik_uygulanmaz`** (`_feedback_naming_merger.py`, NameMerger çıktısına ürün eşiği). Kodu değiştiren commit: `2450c0e` (AD-04 / AD-05): eşik artık c_namer kararlarıyla birleşmiş `final_naming_map`'e değil, birleştiricinin kendi haritasına (`merged_map`) uygulanıyor. Mutant aynı çağrıda eşiği `None` yapar. Öldü.
- Kaldırılan mutant yok; yeni test yok.

### p13a — önce 21 öldü / 1 hayatta / 0 hata → sonra 22 / 0 / 0 (22 mutant)

- **Hayatta: `p13a_ad04_on_ad_iki_kez` — karar: GERÇEK TEST AÇIĞI (test fikstürü bayat).**
  - Mutant (`_feedback_naming_candidates.collect_candidates`): `if not pre_names_via_c_namer:` → `if pre_names_via_c_namer or True:`; c_namer koşmuşken ön ad (`binary_extractor`) birleştiriciye ikinci kez girer (AD-04). Davranış hâlâ üründe ve anlamlı.
  - Kanıt: `07d81e8` (P12c kalem 5 / AD-07) `_add_binary_extractor`'a ölçülmüş güven kuralını koydu: künyesiz (ölçülmemiş kanaldaki) ön ad birleştiriciye hiç girmez. Hedef test `test_ad04_bindiff_adi_on_ad_olarak_ikinci_kez_sayilmaz` künyesiz ön ad (`_ctx()` künyesiz) kullanıyor → mutantla da ön ad aday olmuyor, test boşa geçiyor. Aynı dosyadaki öbür testler o commit'te `_gnulib_kunyesi` ile güncellenmiş, bu test atlanmış.
  - Yeni kilit: `tests/test_mutbakim_p13a.py::test_ad04_olculmus_on_ad_bindiff_ile_iki_kaynak_sayilmaz` — aynı senaryo gnulib künyeli (ölçülmüş) ön adla: `exact_multi == 0`, `name_merger_total == 1`, harita `{"FUN_00104000": "ref_ad"}`. Bugünkü kodda yeşil, mutantla kırmızı. Tanımın testi buna çevrildi.
- **Aynı uzunluk (`.pyc` tuzağı) düzeltmesi:** `p13a_ad06_cift_ad` (`naming_map.get(orig)` → `naming_map.get(orig, None)`), `p13a_ad09_ihrac_dali` (`return bool(` → `return not not (`, eşdeğer). Niyet aynı; ikisi de öldü.
- Kaldırılan mutant yok.
