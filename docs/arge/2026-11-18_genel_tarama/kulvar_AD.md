# Kulvar AD — bulgular
Kapsam: baştan sona okunan: `_feedback_naming.py`, `_feedback_naming_merger.py`, `_feedback_naming_candidates.py`, `_feedback_naming_parallel.py`, `name_merger.py`, `name_validity.py`, `core/naming_labels.py`, `tarif/alt_kanal.py`, `aho_replacer.py`, `gnulib_fingerprints.py`, `semantic_naming.py`, `confidence_filter.py`; kısmen: `c_namer.py` (`CVariableNamer` giriş/süzgeç/seçim/uygulama 1754-2527, `_strategy_string_context`, `_strategy_api_call`, `_strategy_api_param_propagation`, `_add_candidate`), `tarif/baglama.py` (1-354), `binary_name_extractor.py` (`extract`, `_merge_results`, `_strategy_debug_strings`, `_strategy_string_intelligence`), `api_param_db.py` (ters yayılım), `_feedback_naming_bindiff.py`/`_refdiff.py` (ön ad yazımı), `stages.py` 2576-2995 (ön ad tohumu), `output_formatter.py` 594-886, `parallel_algo_eng.py`, `_feedback_typing_extras.py` (n-gram). Gerçek çıktı: `~/karadul_olcum/runs/urun-yeni2-f30ac9a/` (119 ikili). Okunamayanlar: "Bakamadıklarım".
Özet: (1) En büyük yanlış ad kaynakları koddaki tasarım kusurları: `kebap_ad` seçenek/kanca adını fonksiyon adı yapıyor ve N0b'nin eski "belirsiz" kararıyla açık kalıyor (AD-01, tmux'ta 101 ad), `api_param_reverse` rol etiketini ad yapıyor (AD-02), gnulib parmak izi gnulib'siz programlarda, Mach-O'da bile ateşleniyor (AD-03). (2) Ön ad kanalı süzgeçlerin yan yolu: Faz 1 çıkarıcısının güven eşiği ve tekilleştirmesi boru hattında atlanıyor (AD-06), susan dizgi sinyalleri ön ad olarak geri geliyor (AD-09), bütün ön adlar ölçülmüş isabetinden bağımsız 0,95 güvenle yayımlanıyor (AD-07). (3) NameMerger fiilen etkisiz ama sayaçları sahte uzlaşma gösteriyor (AD-04) ve c_namer'ın reddettiği adı geri getiren süzgeçsiz bir yol taşıyor (AD-05); yerel adlar ikili genelinde sayaç eki alıyor (`buf_308`, AD-08).

## AD-01 — `kebap_ad` alt kanalı tasarım gereği yanlış ad üretiyor ve 0,80–0,85 güvenle "doğrulanmadı" etiketiyle yayımlanıyor
- Önem: KRİTİK
- Tür: hata (tasarım kusuru) + sahte/yanlış gösterim
- Yer: `karadul/reconstruction/tarif/alt_kanal.py:160-172` (karar tablosu, `SUB_KEBAB_NAME: DECISION_UNCERTAIN`), `karadul/reconstruction/c_namer.py:3278-3322` (klasik yol: ad ve güven)
- Etkin mi: evet (çağıran: `c_namer._run_heuristic_strategies` → `_strategy_string_context`, `c_namer.py:2907`; susturma `enable_subchannel_silencing=True`, `config.py:496`, ama `kebap_ad` susan kümede değil)
- Ne: `string_context` klasik yolu fonksiyonun referans verdiği dizgilerden en yüksek puanlıyı seçip anahtar sözcüklerini birleştirerek fonksiyona ad koyar. Tireli küçük harf dizgi (`monitor-silence`, `window-layout-changed`) neredeyse her zaman bir SEÇENEK, KOMUT ya da KANCA adıdır: fonksiyon onu bir getter'a (`options_get_number(oo, "monitor-silence")`) argüman olarak verir; dizgi fonksiyonun kimliği değil, okuduğu verinin adıdır. Tasarım bu ikisini karıştırıyor. Karar tablosu N0b'nin (az örnekli) "belirsiz" kararından sabit kopyalanmış; B-A1 ölçümündeki 239/0 sonucu tabloya geri beslenmemiş, kanal hâlâ ad veriyor. Güven `min(0.9, 0.7 + 0.05·k)` formülüyle yalnız anahtar sözcük sayısından türüyor (iki sözcük → 0,80; üç → 0,85); kanıt niteliğiyle ilgisi yok ve ürün eşiğinin (0,7) her zaman üstünde.
- Kanıt: Debian tmux köken kaydı (`~/karadul_olcum/runs/urun-yeni2-f30ac9a/debian/tmux/tmux/ws/workspaces/tmux/20261111_120536/reconstructed/src/naming_provenance.json`), `sub_channel == "kebap_ad"` olan 101 genel ad; ilk örnekler:
  ```
  FUN_0011edac monitor_silence   'monitor-silence'   0.80 doğrulanmadı
  FUN_0011f020 monitor_bell      'monitor-bell'      0.80 doğrulanmadı
  FUN_0011f1a8 monitor_activity  'monitor-activity'  0.80 doğrulanmadı
  FUN_001358a0 window_size       'window-size'       0.80 doğrulanmadı
  FUN_001375e0 after_select_window 'after-select-window' 0.85 doğrulanmadı
  ```
  (tmux'ta bu adlarda fonksiyon yok; seçenekleri okuyan fonksiyonlar `alerts_check_*` vb.)
- Etki: Analist tmux'ta 101 fonksiyonu, var olmayan ve davranışla ilgisiz adlarla görür; `naming_map.json` bunlara 0,80/0,85 güven yazar. Ürünün tek en büyük yanlış ad kaynağı (B-A1: 239 ad, 0 doğru).
- Güven: yüksek (kodu izledim, gerçek çıktıda gösterdim; GT karşılaştırmasını B-A1 ölçümünden alıyorum)
- Onarım kapsamı: `tarif/alt_kanal.py` karar tablosunda `kebap_ad` → `zayif` (S; `tests/test_tarif_alt_kanal.py` tabloyu `kesinlik_tablosu.json` ile karşılaştırdığı için o JSON'a yeni ölçüm kararı kaydı da gerekir — ölçüm/ürün ayrılığı kuralı). Uzun vadede `string_context` güven formülünü kanıt türüne bağlamak (M).
- Nasıl sınanır: tmux (Debian + Mac) yeniden koşusunda `sub_channel == kebap_ad` genel ad sayısı 0; `naming_silenced` içinde `kebap_ad` sayacı görünür.

## AD-02 — `api_param_reverse` fonksiyona özgün ad değil ROL etiketi veriyor (`compare_func_5`, `event_callback_17`); güven 0,75 eşiği geçiyor
- Önem: YÜKSEK
- Tür: hata (tasarım kusuru)
- Yer: `karadul/reconstruction/c_namer.py:3872-3881`, `karadul/reconstruction/api_param_db.py:481-556`
- Etkin mi: evet (çağıran: `c_namer.py:2912` `_strategy_api_param_propagation`)
- Ne: Bir FUN_ başka bir API'ye argüman olarak geçiyorsa (`qsort(..., FUN_x)`, `signal(.., FUN_x)`) callback tablosundaki genel rol adı (`compare_func`, `signal_handler`, `thread_start_routine`, `event_callback`) fonksiyon ADI olarak verilir. Aynı API'ye geçen her fonksiyon aynı rolü alır; `name_validity.unique_name` bunları `_2`, `_3` … ekiyle ayırır. Bu adlar yapı gereği hiçbir zaman özgün adla eşleşmez (B-A1: 84 yanlış). Rol bilgisi doğru olabilir ama yorum/etiket olarak taşınması gerekirken ad olarak yazılıyor; sabit 0,75 güven ürün eşiğini (0,7) her zaman geçiyor. İkinci dal (`api_param_db.py:547-554`) yalnız parametre adında `block`/`func`/`hook` geçtiği için de ad veriyor.
- Kanıt: 119 ikilinin köken kayıtlarında `strategy == "api_param_reverse"` 86 genel ad; en sık: `compare_func` 12, `compare_func_2` 5, `signal_handler` 4, `compare_func_3..5` 3'er, `event_callback_2..17` 2'şer.
- Etki: Analist sayısal ekli, birbirinin aynı jenerik adlar görür; `naming_map.json` 0,75 güven yazar. Aynı rolü taşıyan 17 farklı fonksiyon ayırt edilemez.
- Güven: yüksek (kodu izledim; gerçek çıktıdan saydım)
- Onarım kapsamı: `c_namer.py` (ters yolun adayı genel ad kanalı yerine yorum/rol etiketi olarak taşınmalı ya da güveni eşiğin altına çekilmeli; S-M). Tehlike: `kesin.py`/`baglama.py` aynı rol bilgisini kesin çapada kullanıyorsa ayrıştırılmalı.
- Nasıl sınanır: yeniden koşuda `api_param_reverse` stratejili genel ad 0; rol bilgisi fonksiyon yorumunda görünür.

## AD-03 — gnulib parmak izi ve çağrı şekli kanalı programa/platforma bakmadan HER ikilide ateşleniyor (Mach-O tmux'ta `close_stdout`)
- Önem: YÜKSEK
- Tür: hata
- Yer: `karadul/stages.py:2702-2877` (`_recover_gnulib_from_fingerprints`; çağıran `_seed_recovery_pre_names`, `stages.py:2631`), `karadul/analyzers/gnulib_fingerprints.py:131-144, 196-271`
- Etkin mi: evet (Faz 2 tohumu, `stages.py:3221` ve `:3347`; ön ad kanalı, öntanımlı açık)
- Ne: Parmak izleri coreutils 9.4 / gnulib 2023'e göre kurulmuş (`EXPECTED_COREUTILS = "9.4"`) ama bu sabit hiçbir yerde denetlenmiyor; ikilinin gnulib içerip içermediği, platformu (ELF/Mach-O), derleyicisi sorulmuyor. Yalnız "ikilide tek aday" kısıtı var. Sonuç: `write` çağıran 2-4 dallı TEK fonksiyon her programda `full_write`, `getopt_long` çağıran tek fonksiyon `parse_long_options`, "write error" dizgisi taşıyan tek fonksiyon `close_stdout` olur. B-A3 (LTO'suz Debian coreutils) bunun bir alt durumu; yeni olan, gnulib'i hiç kullanmayan programlar.
- Kanıt: urun-yeni2 `out/naming_map.json`'larında `channel == "on_ad:gnulib"` uygulanmış adlar, coreutils dışı:
  ```
  openssl/debian {'full_write': 1}      redis-tools/debian {'full_write': 1}
  tmux/debian {'close_stdout': 1}       zstd/debian {'usage': 1, 'close_stdout': 1}
  tmux/mac {'close_stdout': 1}          # Mach-O, gnulib yok
  ```
  ör. `debian/redis-tools/redis-cli/out/naming_map.json`: `FUN_00159c00 → full_write`, güven 0,95, kanal `on_ad:gnulib`.
- Etki: Analist, gnulib içermeyen bir programda gnulib fonksiyon adı görür; ön ad 0,95 güvenle yazılır ve c_namer'ın başka adaylarını ezer (`pre_named` elemesi).
- Güven: yüksek (kodu izledim; çıktıda gösterdim. Bu beş adın her birinin GT'ye göre yanlış olduğunu tek tek denetlemedim; Mach-O tmux'taki `close_stdout` için gnulib olmadığından eminim)
- Onarım kapsamı: `stages.py` `_recover_gnulib_from_fingerprints` başına koşul (ELF + gnulib varlık kanıtı, ör. birden çok bağımsız gnulib dizgisi/yapısı birlikte; S-M) ve `gnulib_fingerprints.py`'de koşul tablosu. Tehlike: coreutils kazanımını korumak için ölçümle seçilmeli.
- Nasıl sınanır: tmux (Mac+Debian), redis, openssl, zstd koşularında `on_ad:gnulib` 0; coreutils sayıları değişmez.

## AD-04 — NameMerger ön adı iki bağımsız kaynak sayıyor: aynı kanıt `binary_extractor` (0,85) + `c_namer` (0,95) → 0,99 ve sahte "exact_multi" sayacı
- Önem: ORTA
- Tür: sahte/yanlış gösterim
- Yer: `karadul/pipeline/steps/_feedback_naming_candidates.py:393-432` (`_add_binary_extractor`, `_add_c_namer`), `karadul/reconstruction/name_merger.py:283-300`, sayaç `_feedback_naming_merger.py:159-161`
- Etkin mi: evet (çağıran: `_feedback_naming.py:159` `run_name_merger`)
- Ne: `extracted_names` (ön adlar) hem doğrudan `binary_extractor` adayı olarak hem de c_namer onları `naming_map`'ine 0,95 güvenle koyduğu için `c_namer` adayı olarak NameMerger'a girer. Merger bunları iki bağımsız kaynak sayıp Bayes log-odds'u toplar (0,85 ⊕ 0,95 → 0,99) ve `bayesian_multi` (iki kaynaklı doğrulama) olarak işaretler. Kanıt tektir (ör. gnulib parmak izi). `stats["name_merger_exact_multi"]` bu yüzden "çok kaynaklı uzlaşma" gösteriyor: coreutils ikililerinde 13/13 (hepsi ön ad).
- Kanıt:
  ```
  $ PYTHONDONTWRITEBYTECODE=1 python -c "...collect_candidates(extracted_names={'FUN_00101000':'close_stdout'}, naming_result=<naming_map aynı ad, 0.95>)...; NameMerger(...).merge(c)"
  1) close_stdout 0.99 bayesian_multi ['c_namer', 'binary_extractor'] exact_multi= 1
  ```
  urun-yeni2 `debian/coreutils/*/out/report.json`: `name_merger_total 13`, `name_merger_exact_multi 13`.
- Etki: Rapordaki birleştirme sayaçları ve birleşik güven, olmayan bir bağımsız doğrulamayı gösterir. (Ad koda c_namer'dan zaten yazıldığı için koddaki ad değişmez; bkz. AD-05.)
- Güven: kesin (çalıştırıp gösterdim)
- Onarım kapsamı: `_feedback_naming_candidates.py` — ön adlar yalnız bir yoldan girmeli (c_namer'ın `strategy_map`'i `binary_extract`/`ks1` ise `binary_extractor` adayı eklenmemeli ya da tersi; S).
- Nasıl sınanır: aynı deneme `bayesian_single` ve 0,95 vermeli; coreutils raporunda `exact_multi` 0.

## AD-05 — NameMerger'ın kararı koda neredeyse hiç ulaşmıyor ve hiçbir yere kaydedilmiyor; ulaştığı tek yol c_namer süzgeçlerini atlayan bir yan yol
- Önem: ORTA (bugün etkisiz; açılınca YÜKSEK)
- Tür: ölü kod (fiilen) + sessiz hata (yan yol)
- Yer: `karadul/pipeline/steps/_feedback_naming_merger.py:151-187`, `_feedback_naming_candidates.py:393-402`, `karadul/core/output_formatter.py:594-776`
- Etkin mi: evet (her koşuda çalışıyor)
- Ne: (1) Merger'ın `final_naming_map`'i Aho ile `decompiled_dir`'e uygulanıyor, ama bu dizin c_namer'ın ZATEN yeniden adlandırdığı çıktı: c_namer'ın ad verdiği her `FUN_` metinde artık yok, merger'ın o anahtar için verdiği (belki farklı) ad hiçbir yere yazılmıyor. Bayes birleştirme, kaynak ağırlıkları ve `drop_below_threshold` eşiği yalnız c_namer'ın ad VERMEDİĞİ anahtarlarda etkili. (2) Tam da bu anahtarlar için merger c_namer'ın süzgeçlerini atlar: `_add_binary_extractor` ham `extracted_names`'i (sanitize edilmemiş, `name_validity`'den geçmemiş) sabit 0,85 ile ekler; tek kaynak 0,85 ≥ 0,7 eşiği geçer ve ad koda yazılır. c_namer'ın reddettiği ön ad (anahtar sözcük, tip adı, var olan fonksiyonla çakışma, `$` içeren ad) ya da "aynı ad daha öncelikli ön adda kullanıldı" diye düşürdüğü ön ad merger'dan geri gelir. Merger sonrası ad geçerliliği / çakışma denetimi yok. (3) `output_formatter._build_naming_map` merger'ın kararını okumuyor; merger'dan gelen bir ad kodda olur ama `naming_map.json`'da kanal/etiket/güven taşımaz.
- Kanıt: (2) için deneme:
  ```
  extracted_names={'FUN_00102000':'free','FUN_00103000':'_$s4main3FooV'}, c_namer naming_map={}
  → final_naming_map {'FUN_00102000': 'free', 'FUN_00103000': '_$s4main3FooV'}  (0.85, eşik altı düşen 0)
  ```
  (1) için: urun-yeni2'nin 119 ikilisinde `reconstructed/src` → `reconstructed/merged` arasında kaybolan `FUN_`/`DAT_` belirteci sayısı 0 (betik: `/private/tmp/claude-501/-Users-apple-Black-Widow/73131cd0-6f20-4b95-a731-285ec7e38fce/scratchpad/ad/merger_only.py`). Aynı koşuda `naming_rejected` 119 raporun hepsinde `{}`; yani yan yol bu koşuda tetiklenmedi.
- Etki: Bugün: merger'ın hesapladığı güven/çakışma sayaçları rapora gidiyor ama ürün adını belirlemiyor (yanıltıcı sayaçlar, boşa iş). c_namer süzgeci bir ön adı reddettiği gün (ör. Mach-O `$`'lı ad, çakışan gnulib adı) o ad merger üzerinden koda, kökensiz ve etiketsiz yazılır.
- Güven: kesin ((2) çalıştırıp gösterdim; (1) gerçek çıktıda saydım)
- Onarım kapsamı: `_feedback_naming_merger.py` — `final_naming_map`'e `name_validity.reject_reason` + `unique_name` (var olan fonksiyon adlarıyla) uygulanmalı ve c_namer'ın reddettiği anahtarlar dışlanmalı (S); merger kararının `naming_map.json`'a köken olarak yazılması ya da merger'ın kaldırılması kararı (M).
- Nasıl sınanır: c_namer'ın reddettiği bir ön ad için birim testi: merger çıktısında anahtar yok; `merged/`'de `FUN_` kalır.

## AD-06 — Faz 1 ad çıkarıcısının (BinaryNameExtractor) güven eşiği, "fonksiyon başına en iyi" seçimi ve çift ad temizliği boru hattında atlanıyor
- Önem: YÜKSEK
- Tür: hata (süzgeci delen yan yol)
- Yer: `karadul/pipeline/steps/parallel_algo_eng.py:139-142` (`names = {n.original_name: n.recovered_name for n in extract_result.names}`); atlanan süzgeç `karadul/reconstruction/binary_name_extractor.py:2582-2636` (`_merge_results` → `as_naming_map`)
- Etkin mi: evet (adım `parallel_algo_eng` kayıtlı, `pipeline/steps/__init__.py:75`; `enable_binary_name_extraction=True`, `config.py:462`; çıktı `confidence_filter.py:70` → `extracted_names` → c_namer ön adı)
- Ne: Çıkarıcı kendi içinde `min_naming_confidence` (0,7) altındaki adayları atar, fonksiyon başına en yüksek güvenliyi seçer, aynı adı iki fonksiyona vermez (`as_naming_map`). Boru hattı bu sonucu DEĞİL, bütün stratejilerin ham listesini (`extract_result.names`) sözlüğe çeviriyor: 0,35 (enum handler), 0,40 (build path yayılımı), 0,65 (vtable yakınlığı) güvenli adlar geçer; aynı fonksiyona birden çok öneri varsa listedeki SONUNCU (en güvenlisi değil) kazanır; aynı ad birden çok fonksiyona gider. Bu sözlük ön ad olur; c_namer ön adlara sabit 0,95 güven ve öncelik verir (`c_namer.py:2278`), susturma ve ürün eşiği ön adlara uygulanmaz. `binary_names.json` de aynı ham listeden (son kazanır) yazılıyor.
- Kanıt:
  ```
  r.names = [FUN_1 Foo_render rtti 0.90, FUN_1 handle_enum_x enum_handler 0.35,
             FUN_2 Foo_init build_path 0.40, FUN_3 Foo_init vtable_chain 0.65]
  as_naming_map  : {'FUN_1': 'Foo_render'}
  pipeline (L139): {'FUN_1': 'handle_enum_x', 'FUN_2': 'Foo_init', 'FUN_3': 'Foo_init'}
  ```
  urun-yeni2'de (C/ELF ağırlıklı küme) çıkarıcı yalnız 2 ad üretti (`debug_string`, ≥0,7); yani kusur bu ölçümde görünmedi. RTTI/vtable/Swift/enum stratejilerinin ateşlendiği C++, ObjC ve Swift ikililerinde doğrudan etkili.
- Etki: C++/Swift ikililerinde düşük güvenli, birbirinin aynı Faz 1 adları 0,95 güvenle ve en yüksek öncelikle koda yazılır; aynı fonksiyonda yüksek güvenli doğru öneri, listede sonra gelen zayıf öneriyle ezilir.
- Güven: kesin (çalıştırıp gösterdim)
- Onarım kapsamı: `parallel_algo_eng.py` — `extractor.as_naming_map()` kullanılmalı; `binary_names.json` için fonksiyon başına seçilen kayıt yazılmalı (S). Ölçüm kümesinde ad sayısı değişmez (yalnız 2 ad), C++ kümede değişir.
- Nasıl sınanır: yukarıdaki deneme boru hattı yolunda `{'FUN_1': 'Foo_render'}` vermeli; C++ bir ikilide `on_ad:faz1` adlarının hepsinin çıkarıcı güveni ≥ 0,7.

## AD-07 — Ön adların hepsine sabit 0,95 güven yazılıyor; ölçülmüş yanlış oranları (gnulib kabaca dörtte bir) analiste gösterilmiyor
- Önem: YÜKSEK
- Tür: sahte/yanlış gösterim
- Yer: `karadul/reconstruction/c_namer.py:2276-2279` (`confidence_map[old_name] = 0.95`), köken kaydına `prov.add_pre_name(..., confidence_map[old_name])` (`:2284-2288`), `output_formatter.py:763-770` (bu değer `naming_map.json`'a `confidence` olarak geçer)
- Etkin mi: evet
- Ne: Ön ad türü ne olursa olsun (gnulib parmak izi, ELF önyük, `main`, Faz 1 çıkarıcı, KS-1) c_namer güveni 0,95'e sabitliyor; gerçek kanıt gücü (çıkarıcının kendi güveni, parmak izinin ölçülmüş isabeti) taşınmıyor. B-A1'de gnulib ön adlarından 222'si yanlış; bu koşunun `out/naming_map.json`'larında uygulanmış `on_ad:gnulib` adı 843 (iki sayımın paydası aynı tanım değil; oran kabaca dörtte bir). `naming_map.json` bunların hepsine 0,95 yazıyor. Etiket "doğrulanmadı" olsa da sayı, eşikten çok yukarıda ve "kesin" KS-1 adlarıyla aynı görünür. (KS-1 ön adının güveni de aynı sabit 0,95; ölçülmüş isabeti ~%95 olduğundan orada sapma küçük.)
- Kanıt: `debian/redis-tools/redis-cli/out/naming_map.json`: `FUN_00159c00 → full_write, confidence 0.95, label doğrulanmadı, channel on_ad:gnulib` (AD-03: redis gnulib kullanmıyor). Kanal dağılımı (119 ikili, uygulanan): `on_ad:gnulib` 843, `on_ad:elf_onyuk` 234, `on_ad:main_giris` 111 — hepsi 0,95.
- Etki: Analist güven sütununa bakarak yanlış gnulib adını en güvenilir adlarla aynı sınıfta görür; "sahte güven değeri" (brif §1).
- Güven: yüksek (kodu izledim; çıktıda gördüm)
- Onarım kapsamı: `c_namer.py` ön ad dalı — güven künyeden (`pre_name_meta`) ya da türe göre ölçülmüş değerden gelmeli; yoksa `None` yazılmalı (output_formatter zaten `None`'ı destekliyor). S-M; tehlike: NameMerger `c_namer` adayını `confidence_map`'ten okuyor (AD-04/AD-05 ile birlikte ele alınmalı).
- Nasıl sınanır: `naming_map.json`'da `on_ad:gnulib` kayıtlarının güveni 0,95 değil; ölçülmüş değer ya da `null`.

## AD-08 — Yerel değişken/parametre adları ikili GENELİNDE tekilleştiriliyor: htop'ta yerel adların %93'ü `buf_308` türü sayaç eki taşıyor
- Önem: ORTA
- Tür: hata + belirlenimsizlik (sürümler/girdiler arası kararsızlık)
- Yer: `karadul/reconstruction/c_namer.py:2352-2360` (`unique_name(best.new_name, used_new_names, ...)` ve `used_new_names.add(new_name)` yerel anahtarlar için de çalışıyor)
- Etkin mi: evet
- Ne: `used_new_names` genel adlar için tutulan "bu koşuda verilmiş adlar" kümesi; ama döngü yerel anahtarları (`fonksiyon::param_1`) da aynı kümeye yazıyor ve aynı kümeyle tekilleştiriyor. Yerel adların yalnız kendi fonksiyonu içinde tekil olması gerekir. Sonuç: ilk fonksiyondaki `buf` eksiz kalır, ikilideki 308. `buf` `buf_308` olur. Sonek, anahtar sırasına (fonksiyonların `ghidra_functions.json` sırası) bağlı; bir fonksiyonun eklenip çıkması sonraki BÜTÜN fonksiyonların yerel adlarını değiştirir (B-A6'nın kalan kökü: aynı girdide belirlenimli, ama Ghidra sürümü/fonksiyon kümesi değişince bütün yerel adlar kayar).
- Kanıt: Debian htop `reconstructed/src/naming_map.json` `per_function`: 2 626 yerel adın 2 442'si sayısal ek taşıyor, en büyük `LibNl_readDelayAcctData: param_1 → buf_308`; fonksiyon içi çift ad 0 (yani ek fonksiyon içi çakışmadan değil, genel sayaçtan). Çıktıda: `out/src/src/subsystem_file_io/full_write.c:21: long full_write(int fd_7,void *buf_251,size_t count_18)`.
- Etki: Analist `buf_251` gibi adlardan ikilide 251 ayrı tampon olduğu, ya da bunların birbiriyle ilişkili olduğu izlenimine kapılır; iki sürüm arası fark (diff) her yerel adı değişmiş gösterir.
- Güven: kesin (gerçek çıktıda saydım; kodu izledim)
- Onarım kapsamı: `c_namer.py` — yerel anahtarlar için fonksiyon başına ayrı `used` kümesi (fonksiyonun genel adlarıyla ve gövdede çağrılan fonksiyon adlarıyla çakışmayı da denetleyerek); S. Tehlike: `per_function` haritasını okuyan testler ekli adları bekliyor olabilir.
- Nasıl sınanır: htop'ta yerel adların sayısal ek oranı fonksiyon içi çakışma oranına iner; bir fonksiyon silinmiş girdiyle koşuda öbür fonksiyonların yerel adları değişmez.

## AD-09 — Susturma yan yolu: c_namer'da susan dizgi sinyalleri (Class::Method "agresif", hata iletisi) Faz 1 çıkarıcısından ÖN AD olarak geçiyor
- Önem: ORTA (ölçülen C/ELF kümede tetiklenmedi; C++/ObjC'de YÜKSEK)
- Tür: hata (susturmayı delen yan yol)
- Yer: `karadul/reconstruction/binary_name_extractor.py:867-930` (`_strategy_debug_strings`: dizgideki `Class::Method` → onu referanslayan İLK `FUN_`'a `Class_Method`, güven 0,90/0,92), `:1887-2008` (`_strategy_string_intelligence`: assert/hata/protokol dizgisinden ad); susturma yalnız `c_namer._silence_candidates` (`c_namer.py:1833-1860`) içinde ve yalnız `strategy == "string_context"` adaylarına bakıyor
- Etkin mi: evet (Faz 1, `parallel_algo_eng`; çıktısı ön ad olur — AD-06)
- Ne: N0b, `string_context`'in `agresif` (Class::Method, ObjC seçici, URL…) ve `hata_iletisi` alt kanallarını ölçüp susturdu. Aynı sinyali (bir dizginin içeriğinden, onu referanslayan fonksiyona ad) Faz 1 çıkarıcısı da üretiyor; onun adları `extracted_names` → c_namer ön adı olarak susturma ve ürün eşiğinden geçmeden 0,95 güvenle yazılıyor. Örneğin bir günlük iletisi `"Foo::bar failed"` onu YAZAN fonksiyona (çoğu zaman `Foo::bar`'ı çağıran) `Foo_bar` adını verir.
- Kanıt: kod izlemesi (yukarıdaki satırlar). urun-yeni2'de `binary_names.json` yalnız 2 ikilide ve yalnız 2 `debug_string` adıyla var; yani ölçümde görünmedi.
- Etki: C++/ObjC ikililerinde, ölçülüp susturulmuş bir kanalın yanlışları "ön ad" olarak, en yüksek öncelik ve 0,95 güvenle geri gelir.
- Güven: yüksek (kod izlendi; gerçek bir C++ çıktısında gösteremedim)
- Onarım kapsamı: `parallel_algo_eng.py` / `binary_name_extractor.py` — `debug_string` (xref'siz dal ve "ilk referanslayan" dalı) ile `string_intel` adlarının ya ön ad kanalından çıkarılması ya da c_namer'a aday (strateji `string_context`, uygun `code_path`) olarak verilip aynı süzgeçten geçmesi (M).
- Nasıl sınanır: `"Foo::bar failed"` dizgisini referanslayan sentetik fonksiyon için ön ad üretilmez ya da `naming_silenced` sayacına düşer.

## AD-10 — N-gram yerel ad kanalı `--output-dir` ile hiç çalışmıyor (sessizce), çalıştığında ad süzgeçsiz ve kökensiz regex ile yazıyor
- Önem: ORTA
- Tür: okunmayan ayar / sessiz hata + hata
- Yer: `karadul/pipeline/steps/_feedback_typing_extras.py:183-259` (`run_ngram_naming`), `karadul/config.py:969` (`project_root = Path.cwd()`), `karadul/cli.py:638-639` (`--output-dir` verilince `cfg.project_root = output_dir`)
- Etkin mi: `enable_ngram_naming=True` (`config.py:469`) ama veritabanı yolu `project_root / "sigs" / "ngram_name_db"`; `--output-dir` ile bu yol çıktı dizinine, verilmezse çalışma dizinine düşer. Ölçüm koşusu (`--output-dir <d>/ws`) ve büyük olasılıkla uygulama kurulumu bu yüzden kanalı hiç koşmuyor.
- Ne: (1) Dizin yoksa adım `return` eder; istatistik yazılmaz, uyarı yok — bayrak "açık" görünür ama özellik yoktur. (2) Çalıştığında (`karadul` depo kökünden koşulursa) tahmini `re.subn(r"\bvar\b", ad, kod)` ile bütün dosyaya uygular: `name_validity` (anahtar sözcük/tip adı) yok, aynı fonksiyonda iki değişkene aynı adı verme denetimi yok, dizgi ve yorum içi de değişir, köken kaydı/`naming_map.json` kaydı yok. Yani aynı ürün koşusunun yerel adları, komutun hangi dizinden çalıştırıldığına bağlı.
- Kanıt: urun-yeni2 `kosu_kunyesi.json` komutu `python -m karadul analyze <girdi> --skip-dynamic --output-dir <d>/ws ...`; 119 raporun hiçbirinde `ngram_names_applied` yok; `ws/sigs/ngram_name_db` yok. Depoda `sigs/ngram_name_db/db_*.ngdb` var (git dışı).
- Etki: Analist yerel adları, aynı ikili için çalışma dizinine göre farklı görür; n-gram adları hiçbir kayıtta görünmez.
- Güven: yüksek ((1) kod + koşu künyesi; (2) kod izlemesi)
- Onarım kapsamı: `_feedback_typing_extras.py` — veritabanı yolu paket/kurulum köküne bağlanmalı, yoksa istatistikte "ngram_db_yok" yazılmalı; uygulama c_namer'ın yerel ad haritası üzerinden (süzgeç + fonksiyon içi tekillik + köken) yapılmalı (M). `signature_db.py:1769` ve `stages.py:1723` aynı `project_root/sigs` kalıbını kullanıyor (kulvar dışı; FLIRT için bilinen).
- Nasıl sınanır: aynı ikili depo kökünden ve başka dizinden `--output-dir` ile koşulduğunda yerel ad haritası aynı; rapor n-gram durumunu açıkça yazar.

## AD-11 — BinDiff / ReferenceDiffer adları ön ad sözlüğünü koşulsuz eziyor (`extracted_names.update`); elle verilen ad ve `main` sonraki yinelemede kaybolabilir, elle adı zorlayan aşama yalnız ölü monolitte
- Önem: ORTA (veri arkasında: referans ikili / `~/.cache/karadul/ref_db` gerekiyor)
- Tür: hata
- Yer: `karadul/pipeline/steps/_feedback_naming_bindiff.py:67-69`, `karadul/pipeline/steps/_feedback_naming_refdiff.py:74-75`; elle adı birleştirme SONRASI zorlayan kod yalnız `karadul/stages.py:4325-4327` (monolit, adım kipinde ölü — B-C1)
- Etkin mi: kod etkin (`_feedback_naming.py:137-155`, yineleme 0); ateşlemesi referans verisine bağlı (`reference_binary` boş öntanımlı; ref_db otomatik doldurma ağ iznine bağlı)
- Ne: `_seed_recovery_pre_names` önceliği "elle > main > KS-1 > …" diye tanımlıyor ve elle adın ikinci aşamada `final_naming_map`'e koşulsuz zorlanacağını söylüyor (`stages.py:2959-2965`). Adım kipinde bu ikinci aşama yok; üstelik BinDiff/RefDiff eşleşmeleri `extracted_names`'e `update` ile yazılıyor ve aynı anahtardaki elle/`main`/KS-1 adını eziyor. `LoopState.extracted_names` sonraki yinelemeye bu hâliyle gider; künye (`meta_for`) ad değiştiği için düşer, ad "doğrulanmadı" olur ve `src_iter1/naming_map.json` (çıktı haritasında son yineleme kazanır, `output_formatter.py:723-735`) elle adın yerine eşleşme adını kaydeder.
- Kanıt: kod izlemesi (yukarıdaki satırlar). urun-yeni2'de bindiff/refdiff eşleşmesi yok (raporlarda `bindiff_matches` yok), elle ad da yok; gerçek çıktıda gösteremedim.
- Etki: Analistin elle verdiği ad, referans eşleşmesi olan bir fonksiyonda sessizce başka adla değişebilir ya da haritadan düşebilir (B-C6'nın adım kipindeki karşılığı).
- Güven: yüksek (kod izlendi; çalıştırılmadı)
- Onarım kapsamı: iki dosyada `update` yerine "korunan türlere (elle, main, KS-1) dokunma" kuralı (`baglama.PROTECTED_KINDS` ile); `_feedback_naming_merger.py`'de elle haritanın birleştirme sonrası zorlanması (S-M).
- Nasıl sınanır: elle ad verilmiş ve bindiff eşleşmesi olan sentetik anahtar iki yineleme sonunda elle adı ve etiketsiz künyeyi korur.

## AD-12 — Paralel adlandırma koşucusu ölü kod: `CVariableNamer`'da beklenen dosya başı yöntemler yok
- Önem: DÜŞÜK
- Tür: ölü kod
- Yer: `karadul/pipeline/steps/_feedback_naming_parallel.py:28-45`, `karadul/naming/parallel_runner.py`
- Etkin mi: ölü (`perf.parallel_naming=False` öntanımlı, `config.py:786`; açılsa da `_should_use_parallel_runner` `rename_c_file`/`extract_names_from_file` arar, `CVariableNamer`'da ikisi de yok — `grep -rn "def rename_c_file\|def extract_names_from_file" karadul` boş — uyarı yazıp seri yola düşer)
- Ne: Yol hiçbir zaman çalışmıyor. Çalışabilseydi de `pre_name_meta`'yı geçirmiyor ve `label_map`/`confidence_map`/`strategy_map`/susturma/ad geçerliliği olmayan bir `CNamingResult` sentezliyor (köken ve etiket kaybı).
- Kanıt: yukarıdaki grep; `_run_with_parallel_runner` gövdesi (`:136-146`).
- Etki: Bakım yükü; bayrağı açan biri etiketsiz, süzgeçsiz bir yol bekler.
- Güven: kesin (grep)
- Onarım kapsamı: iki modül ve bayrak silinebilir (S) ya da açıkça "desteklenmiyor" diye işaretlenir.
- Nasıl sınanır: bayrak kaldırıldıktan sonra test takımı yeşil.

## Küçükler
- `name_merger.py:255-256`: `bayesian_single` (tek aday, çakışma yok) `conflicts_resolved` sayacına yazılıyor; rapordaki `name_merger_conflicts` aslında "tek kaynaklı" sayısı (ör. coreutils `[`: 1).
- `name_merger.py:302-331`: kısmi ve anlamsal birleştirme FARKLI adları birbirinin doğrulaması sayıp güveni yükseltiyor (`close` ⊕ `close_all` → kısa ad `close` seçilir, ithal `close` ile çakışabilir); yorum "w_i'leri 0.7x ile çarp" derken kod güveni 0,85 ile çarpıyor (`:317-320`). Bugün yalnız c_namer'ın ad vermediği anahtarlarda etkili (AD-05).
- `name_merger.py:283-300`: iki zayıf kaynağın uzlaştığı grup, tek güçlü adayın önüne geçiyor; Bayes 0,5 altı iki güveni birleştirince sonuç ikisinden de düşük çıkıp UNK'a düşüyor ve güçlü aday hiç denenmiyor (güçlü ad kaybı).
- `_feedback_naming_candidates.py:844-985`: aynı `AlgorithmMatch` hem `engineering_constant` hem `engineering_formula` adayı olarak (0,05 artışla) eklenip merger'da iki bağımsız kaynak sayılıyor (AD-04 ile aynı çift sayım türü). Tek kanıt 0,60 iken: 0,85·logit(0,60) + 0,88·logit(0,65) = 0,345 + 0,545 → σ(0,89) = 0,709, yani ürün eşiğini (0,7) geçer. Yalnız c_namer'ın ad vermediği anahtarlarda etkili (AD-05); elle hesap, çalıştırılmadı.
- `aho_replacer.py:60-104`: değiştirme sözcük sınırına bakıyor ama dizgi sabiti ve yorum içini ayırt etmiyor; genel harita bütün dosyalara uygulanıyor. Gerçek bir bozulma örneği bulmadım.
- `c_namer.py:2355-2357` + `name_validity.py:32-37`: yerel adın aynı gövdede ÇAĞRILAN bir fonksiyonu gölgelemesi engellenmiyor; 119 ikilide 2 örnek (`redis-check-aof/rdb killIOThreads: pVar3 → thread`), bu durumda `thread(...)` çağrısı derlenmez.
- `stages.py:2738` (gnulib dizgi parmak izi): `rglob` sırası dosya sistemi sırası; `ambiguous` listesi ve `extracted_names` ekleme sırası buna bağlı. Ad kümesi değişmez (tekil kısıt), yalnız sıra; ön adların "aynı ad iki anahtarda" düşmesi sıraya bağlı olduğundan teorik belirlenimsizlik.
- `stages.py:2803-2827, 2916-2940`: çağrı şekli ve ELF önyük kanalı ADI ZATEN BİLİNEN fonksiyonları da (`FUN_<adres>` yer tutucusuyla) aday sayıyor; bu hem "ikilide tek" sayımını tüketiyor (gerçek isimsiz aday belirsizliğe düşebilir) hem de `naming_map.json` `candidates`'ini `same_as_original`/uygulanmamış kayıtlarla dolduruyor (redis `_start`, htop `full_write`).
- `c_namer.py:3310`: `string_context` klasik güveni `min(0.9, 0.7 + 0.05·k)` her zaman ≥ 0,75; ürün eşiği (0,7) bu stratejiyi hiçbir zaman süzmüyor — eşik yalnız susturmayla birlikte anlamlı (AD-01'in güven tarafı).

## Bilinenlerin durumu
| Kalem | Durum | Kanıt |
|---|---|---|
| B-A1 (yanlış ad %29,7; kaynak dağılımı) | duruyor | `kebap_ad` hâlâ "belirsiz"/ad veriyor (`alt_kanal.py:167`; AD-01); gnulib kanalında program/platform koşulu yok (AD-03); `api_param_reverse` aynen (AD-02). urun-yeni2 uygulanan kanal sayıları: `on_ad:gnulib` 843, `ks1:func_kalibi` 259, `kebap_ad` 239, `elf_onyuk` 234, `oz_ad` 224, `main_giris` 111, `api_param_reverse` 86 |
| B-A2 (tam ad kapsamı %5,2; Mac htop 0) | bakılmadı | ölçüm konusu; kodda kapsamayı açan bir değişiklik görmedim |
| B-A3 (`version_etc`, `hard_locale`, `full_write` LTO'ya bağlı) | duruyor | `gnulib_fingerprints.py:69-76, 192-212` notla bırakılmış ("Kural gereği çıkarılmadı"); derleme/LTO koşulu yok. Genişlemesi AD-03 |
| B-A4 (yeni ad var olan fonksiyonla çakışıyor) | kapanmış (ürün tarafında); denetim yanlış alarm | urun-yeni2'de redis `_start` ve Debian htop `full_write` kayıtlarının ikisi de `candidates` içinde `reason: same_as_original`: anahtar `FUN_<adres>` yer tutucusu, o adresteki fonksiyonun Ghidra adı zaten aynı (`ghidra_functions.json`: `_start 00129d40 IMPORTED`, `full_write 001322e4 IMPORTED`); `c_namer._own_function_name` (`c_namer.py:1933-1943`) bunu çakışma saymıyor. Kök: önyük/çağrı şekli kanalları adı bilinen fonksiyonları da aday sayıyor (Küçükler). Merger yan yolu (AD-05) gelecekte gerçek çakışma üretebilir |
| B-A5 (yerel adlar 5 356 kusur) | duruyor (ayrıntıya bakılmadı) | kök neden adayı AD-08 (ikili genelinde tekilleştirme) ve AD-10 (süzgeçsiz n-gram) |
| B-A6 (yerel ad sonekleri belirlenimsiz) | kısmen | işçi sonuçları gönderim sırasıyla birleşiyor (`c_namer.py:2098-2159`), `api_call` sıralı; ama sonekler ikili genelinde sayıldığı için fonksiyon kümesi değişince bütün yerel adlar kayıyor (AD-08) |
| B-B1 (geçersiz C adı; `$`, signature_db) | kısmen (bu kulvarın payı) | c_namer yolunda süzgeç var (`c_namer.py:2227-2269`); `naming_map.json` geçersiz adı `candidates`'e ayırıyor (`output_formatter.py:876-880`); merger yolunda süzgeç YOK (AD-05). Başlık (`.h`) üretimi kulvar dışı, bakılmadı |
| B-C6 (manuel override'ın merge sonrası zorlanması) | duruyor | zorlama yalnız ölü monolitte (`stages.py:4325-4327`); adım kipinde yok ve bindiff/refdiff ön adı eziyor (AD-11) |
| B-D3 (FLIRT seçici değil, kapalı) | kulvar dışı | yalnız not: `signature_db.py:1769` `project_root/sigs` kalıbı AD-10'daki çalışma dizini sorunuyla aynı |
| B-E4 (kabul edilen ad `manual`/1.0 olursa ön ada sızar) | bakılmadı | elle ad yolu `_apply_manual_overrides` → ön ad; etiket `None` (`baglama.entry_label`); KaradulLM tarafına bakmadım |

## Bakamadıklarım
- `c_namer.py`'nin strateji gövdelerinin çoğu (`_strategy_call_graph`, `_strategy_dataflow`, `_strategy_type_based`, `_strategy_local_var_naming`, `_strategy_body_param_naming`, `_propagate_passthrough_params`, `_strategy_fortran_in_stack`) ve `c_namer_patterns.py` tabloları (yinelenen anahtar / birbirini ezen desen taraması yapılmadı).
- `tarif/kesin.py`, `tarif/evidence.py`, `tarif/rules.py`, `tarif/propagate.py`, `tarif/module.py`; `kesin_anchors.py`: yalnız `baglama.py`'nin etiket ve öncelik kısmını okudum. "kesin" etiketinin (~%97 doğru) çıkarım tarafındaki hatalar denetlenmedi.
- `string_intelligence.py`, `ngram_namer.py` (iç mantık), `dynamic_namer.py` (öntanımlı kapalı), `param_recovery.py`, `fortran_param_db.py`, `function_summary_patterns.py`, `elf_boilerplate.py` (katalog), `_confidence_helpers.py` (byte pattern + CAPA birleştirmesi; CAPA adlarının ön ad olarak süzgeçsiz girip girmediği AD-06/AD-09'la aynı soru, doğrulanmadı), `semantic_naming` adımının çağırdığı `engineering/semantic_namer.py` (kulvar listesinde değil; ad geçerliliği kullanmıyor — `grep name_validity` yalnız c_namer ve output_formatter'da).
- AD-03'teki beş coreutils dışı gnulib adının ve AD-01'deki tmux örneklerinin GT ile tek tek karşılaştırılması.
- Mac (Mach-O) çıktılarında `$`'lı adın hangi yoldan geldiği (B-B1'in başlık kısmı).

## KULVAR BİTTİ
