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

### p12a — önce 14 öldü / 0 hayatta / 1 hata → sonra 15 / 0 / 0 (15 mutant)

- **Hata: `p12a_kanal_turu_yok`** (AD-07: kanal anahtarına ön ad türü verilmez). Kodu değiştiren commit: `07d81e8` (ön ad güveni tek kuraldan): `{"strategy": strategy, "pre_name_kind": kind, …}` sözlüğü `c_namer.measured_pre_name_confidence(meta)`'ya taşındı, strateji `pre_name_strategy(meta)`. Niyet aynı (`pre_name_kind` → `None`); eski `replace` özgünüyle aynı uzunluktaydı (`kind` / `None`), şimdi `(None)`. c_namer'ın ön ad yolu (`pre_conf = measured_pre_name_confidence(meta)`) bu işlevi kullanıyor; test aynı. Öldü.
- Kaldırılan mutant yok; yeni test yok.

### ad_gecerliligi — önce 51 öldü / 0 hayatta / 2 hata → sonra 53 / 0 / 0 (53 mutant)

- **Hata: `cn_ek_var_olani_atlamaz`, `cn_ek_yerelde_de_atlar`** (çakışma eki ve var olan fonksiyon adları). Kodu değiştiren commit: `99df577` (AD-08: yerel adlar fonksiyon başına tekilleştiriliyor). Tek satırlık `() if self._is_local_name_key(key) else existing_functions,` iki dala ayrıldı: yerel dal `unique_name(best.new_name, _UsedNames(func_used, used_new_names))`, ikili kapsamlı dal `unique_name(best.new_name, used_new_names, existing_functions)`.
  - `cn_ek_var_olani_atlamaz`: ikili kapsamlı dalda `existing_functions` → `()`. Öldü.
  - `cn_ek_yerelde_de_atlar`: yerel dala `existing_functions` eklenir. Öldü.
- Kaldırılan mutant yok; yeni test yok.

### adim3_c_namer — önce 19 öldü / 1 hayatta / 1 hata → sonra 21 / 0 / 0 (21 mutant)

- **Hayatta: `cn_tam_ad_bicim_denetimsiz` — karar: GERÇEK TEST AÇIĞI (test iddiası zayıf kaldı).**
  - Mutant (`c_namer` ön ad yolu): `and re.fullmatch(EXACT_NAME_PATTERN, new_name)):` → `and new_name):`; tam ad iddialı (`exact`) ama geçerli tanımlayıcı olmayan ön ad temizlenmeden kalır.
  - Kanıt: `93a2956` (ad geçerliliği) ön ad yoluna `name_validity.reject_reason` koydu. Mutantla `"iki sozcuk"` artık koda yazılmıyor, `invalid_c_identifier` diye reddediliyor; anahtar başka bir adaydan ad alıyor. Hedef test `test_tam_ad_gecerli_tanimlayici_degilse_temizlenir` yalnız "adda boşluk yok ve ad ham metin değil" diyor → iki durumu ayırmıyor, geçiyor. Bugünkü davranış (temizle → `iki_sozcuk` → ön ad olarak ver) ile mutant davranışı (ön adı düşür) analistin gördüğü adı değiştiriyor: elle verilen ad kaybolur. Mutantın eski açıklaması ("olduğu gibi yazılır") artık olamıyor, açıklama güncellendi.
  - Yeni kilit: `tests/test_mutbakim_adim3_c_namer.py::test_gecersiz_tam_ad_temizlenip_on_ad_olarak_verilir` — ad `iki_sozcuk`, köken `pre_names`, `pre_name_kind == "elle"`, `invalid_c_identifier` reddi yok. Bugünkü kodda yeşil, mutantla kırmızı. Tanımın testi buna çevrildi.
- **Hata: `cn_ks1_stratejisi_yazilmaz`** (KS-1 ön adının stratejisi `binary_extract` yazılır). Kodu değiştiren commit: `07d81e8`: satır içi `STRATEGY_KS1 if kind == … else "binary_extract"` `pre_name_strategy(meta)` işlevine taşındı. Mutant ön ad yolundaki çağrı yerinde (`strategy = pre_name_strategy(meta)` → `strategy = "binary_extract"`); güven hesabı (`measured_pre_name_confidence`) etkilenmez, yalnız yazılan strateji bozulur. Öldü.
- **Çoklu eşleşme: `cn_hepsi_sustu_sayilmaz`.** `if not kept and prov is not None:` dosyada 2 kez (ikincisi `93a2956`'nın ad geçerliliği süzgecinde); probe ilkini (susturma süzgeci, doğru yer) değiştiriyordu. `find` sayaç adıyla (`"all_candidates_silenced"`) genişletilip tekilleştirildi. Öldü.
- Kaldırılan mutant yok.

### p05 — önce 16 öldü / 0 hayatta / 4 hata → sonra 20 / 0 / 0 (20 mutant)

- **Hata: `p05_k1_esik_yok`** (MUH-11: ürün eşiği uygulanmaz). Kodu değiştiren commit: `590c8c9` (P05c K1-K2): kanıtsız aday (`candidate_only`) dalı öne alındı, eşik satırı `if` → `elif` oldu. Niyet aynı. Öldü.
- **Hata: `p05_k1_bildirim_sarti_yok`** (MUH-01: çağıranda bildirilmemiş ad yayılır). Kodu değiştiren commit: `fe2e25e` (P05b K3: gerçek çağrılar dizgi ve yorum örtülü aranıyor): değişken `arg_name` → `arg`, girinti 4 az. Niyet aynı. Öldü.
- **Hata: `p05_k2_kanit_yok_paralel`, `p05_k2_kanit_yok_dizisel`** (MUH-02: `double *` şablonu kayan noktalı kanıt istemez). Kodu değiştiren commit: `711119b` (P05b K2): satır içi `tup.c_type == "double *" and not float_ok` denetimi `_pointer_template_evidence(…, float_ok)`'a taşındı (iki yol aynı işlevi çağırıyor). Mutant her yolun kendi çağrı yerinde `float_ok` yerine `True` verir (yalnız o yolu bozar; işlevin içini bozmak iki yolu birden bozardı). Test parametreli (`dizisel` / `paralel`), aynı. İkisi de öldü.
- **Aynı uzunluk düzeltmesi:** `p05_k1_adim_ilk_yineleme` (`max(` → `min(`; şimdi `sorted(…)[0][1]`, eşdeğer, kararlı sıralama eşitlikte ilkini verir), `p05_k1_adim_yazmaz` (`data.pop(…, None)` → `data.pop(…, {})`). İkisi de öldü.
- Kaldırılan mutant yok; yeni test yok.

### adim3_ui — önce 27 öldü / 0 hayatta / 3 hata → sonra 30 / 0 / 0 (30 mutant)

- **Hata: `ui8_bayat_liste_korumasiz`, `ui8_label_listeye_gecmez`, `ui8_label_alani_listede_yok`** (`ui/server.py` fonksiyon listesindeki etiket). Kodu değiştiren commit: `2be7e90` (ARAYUZ-11): Ghidra adlı fonksiyona etiket vermeyen koşul eklendi; ifade `"label": (_record_label(_name_record(cmap, addr, name))\n … if cls != "ghidra" else None)})` biçiminde iki satır oldu. Üç mutantın niyeti ve testi aynı; `find`'lar yeni iki satırlık ifadeye göre (birincisi yalnız ilk satırı, öbür ikisi bütün ifadeyi değiştirir). Üçü de öldü.
- `ui8_js_sozluk_yazimi` (`ui/index.html`): karakter sayısı aynı ama bayt uzunluğu farklı (`ğ`, `ı` iki bayt); HTML derlenmez, `.pyc` tuzağı yok → değiştirilmedi.
- Kaldırılan mutant yok; yeni test yok.
