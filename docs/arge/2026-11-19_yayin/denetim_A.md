# Kapanış denetimi — Ajan A (BORU, AD, TIP, IMZA, MUH)

- Tarih: 2026-11-19. Denetlenen ağaç: ana ağaç, `main` HEAD `2381dce` (izlenmeyen yalnız `docs/arge/2026-11-19_mythos/*`, `scripts/arge/`; `karadul/` temiz).
- Salt okur: kod, test, belge değiştirilmedi; Ghidra ve tam takım koşulmadı. Kanıt sütunundaki `dosya:satır` değerleri bugünkü koddan (`grep -n` / okuma) alındı.
- Kulvar önekleri `DIZIN.md` ile aynı (BORU, AD, TIP, IMZA, MUH); fark yok.
- Kaynaklar: `docs/arge/2026-11-18_genel_tarama/kulvar_{BORU,AD,TIP,IMZA,MUH}.md`, `DIZIN.md`; `docs/arge/2026-11-18_onarim/DURUM.md`, `P*.md`, `gonderim/OKU.md`; `docs/arge/2026-11-19_birlesik_olcum/sonuc.md`; `git log` (onarım commit'lerinin iletisinde bulgu kimliği yazıyor; kimlik → commit eşlemesi `git log --oneline --since=2026-11-17 | grep -E "\bKİMLİK\b"` ile çıkarıldı).
- Durum sözlüğü: `kapandı` / `kısmen` / `bekletildi (K-n)` / `açık` / `gereksizleşti` / `doğrulanamadı`. Kayıt olmayan orta / düşük bulgu ve küçük kalem `açık` sayıldı.
- Kritik ve yüksek bulgularda "DURUM.md öyle diyor" yetmedi: her satırda bugünkü koddan doğrulama var.

---

## 1. Kulvar BORU (14 bulgu: Y 3, O 9, D 2; küçük kalem 11)

| Kimlik | Önem | Durum | Kanıt |
|---|---|---|---|
| BORU-01 | YÜKSEK | kapandı | P-S2 `c4ec241` (K-3 A1b), P10 `680b631`. **Kod:** `karadul/stages.py:2593-2603`: Faz 2 yalnız `feedback_loop`, `computation_struct_recovery`, `struct_recovery` adımlarını koşturuyor, yorum "ikinci kopya … silindi". `grep -n "\.recover(\|fuse\|CFGAnalyzer" karadul/stages.py`: yapı motoru, füzyon ya da CFG çağrısı yok; tek `.recover(` `stages.py:2903` (`param_recovery`). `stages.py` 5 985 → 3 366 satır. |
| BORU-02 | ORTA | kapandı | P10 `680b631` (yedek kaynak ağacın dışında, `rewritten_files` 40 016 → 0). |
| BORU-03 | ORTA | kapandı (ad kanalı bayrakla kapalı) | P11 `ade9f23`: füzyon adres anahtarlı, tek aday, ölçülmüş kesinlik. Tüketici artık var: `karadul/pipeline/steps/confidence_filter.py:47,120`. Öntanım `karadul/computation/config.py:79` `enable_fusion_naming = False` (yayın kapısı §2: bilerek kapalı). |
| BORU-04 | DÜŞÜK | kapandı | P10 `1a1b8a3`: `struct_recovery.py:107,130` `recovered_struct_candidates`'i `requires` ediyor. |
| BORU-05 | YÜKSEK | kapandı | P-S1 `1ca059b`; P14 / P-S4 ek. **Kod:** `karadul/pipeline/steps/finalize.py:72-101`: başarı = `project_dir` yapıtı VAR ve C adlandırma hatasız; hata varsa `partial`, durum `tam / kismi / basarisiz`. `karadul/stages.py:396-415` `_finalize_binary_outcome` bu sonucu aşamaya yazıyor, çağrı `stages.py:2723`. Eski `success = len(artifacts) > 0` satırı yok. `except RuntimeError` dalları da `reconstruct_status: basarisiz` yazıyor (`stages.py:2429-2442`). |
| BORU-06 | ORTA | kapandı | P14 `5d61d22`: belirlenimci hata tek koşu; `StepFailedError` iki kipte. |
| BORU-07 | ORTA | kısmen | P14 `beb0b37`, `084437d`; P15b `--config`. (1) başarı kuralı, (2) ayar yükleme, (3) işçi çökmesi kapandı. (4) geliştiricinin sabit hedef listesi duruyor: `karadul/batch.py:40` `/Applications/Discord.app/...`, `:48` `/Users/apple/.local/bin/claude`. Keyfi dosya verilemiyor. |
| BORU-08 | ORTA | kapandı | P-S4 `158984c` (.app ana bileşeni türe göre, JAR analizci hattına). Gerçek Java `.app` ile uçtan uca koşulmadı (P-S4 notu). |
| BORU-09 | ORTA | kapandı | P14 `56d0be0` (atomik `mkdir` + `_2` eki). |
| BORU-10 | ORTA | kapandı (sayaç); uygulama açık iş | P13b `dbb9944` (= MUH-08): sayaç uygulanan 0, adaylar ayrı alanda, `uygulanmadi` + neden. Yayılımın koda uygulanması yeni iş (`stages.py` + `project_build` + ölçüm; OKU "atanmamış"). |
| BORU-11 | ORTA | kapandı | P14 `c73be77` (yerinde yazan adım okuyucuyla aynı dalgada koşmuyor; `inline_detection` diskten okuyor). |
| BORU-12 | ORTA | kapandı | P-S2 `db1f3d6` (K-3 A1 ölü monolit + yalnız onu sınayan testler); P-S4 `_collect_all_algorithms` silindi (K-10). |
| BORU-13 | DÜŞÜK | kapandı | P15a `65e7a85` (okunmayan ayar uyarısı, `INERT_SETTINGS`), P15b `4cfb005`. `karadul/cli.py:672-674` `--experimental-step-registry` yardımı "Etkisiz (geriye uyum)" diyor; `karadul/config.py:671` `enable_rtti_recovery` yorumu "ETKİSİZ". Alanlar silinmedi, gerçeği söylüyor. |
| BORU-14 | YÜKSEK | kapandı (kanallar bayrakla; PDB açık, öbürleri K-4 gereği kapalı) | P13b `02a597e` (b), `a92b762` (a/c). **Kod:** `karadul/pipeline/steps/type_recovery_consumer.py:43-44` `requires=["binary_for_byte_match", *PRODUCER_ARTIFACTS]`. `karadul/pipeline/steps/_feedback_naming_merger.py:295-334` `k4_inputs` `binary_path`, `pdb_symbols`, `bn_functions`, `trex_structs`, `rtti_classes` topluyor; `:399-419` `collect_candidates(..., k4=k4_inputs(...))`. Bayraklar `karadul/config.py:679-685`: `enable_pdb_naming=True`, DWARF / Rust / Go / BN / TRex / RTTI `False`. Kalan: PDB / Go kanalı gerçek Ghidra koşusunda ölçülmedi; TRex girdisi üretilmiyor (`desteklenmiyor`). |

### BORU küçük kalemleri

| # | Kalem | Durum | Kanıt |
|---|---|---|---|
| K-BORU-1 | Ctrl+C "Yarım kalan workspace temizleniyor…" iletisi yalan | açık | `karadul/cli.py:216-226` ileti duruyor; `grep -rn pending_workspace karadul` yalnız okuyan satırı buluyor (yazan yok). |
| K-BORU-2 | Bozuk `overrides` JSON'u sessizce boş iskelet; sonraki `set_name` önceki adları siler | açık | `karadul/core/overrides.py:132-149` (`except … pass` → `_skeleton`). |
| K-BORU-3 | `--overrides` dosyası okunamazsa yalnız DEBUG | açık | `karadul/stages.py:2405-2407` `logger.debug("Acik override dosyasi okunamadi…")`. |
| K-BORU-4 | `overrides.set_param` / `params` ölü API | açık | `karadul/core/overrides.py:211` tanım; `karadul`/`ui` içinde çağıran yok. |
| K-BORU-5 | `_capa_comment_inject.py` kopya modül | açık | Dosya duruyor; etkin olan `stages._inject_capa_comments` (`capa_annotation.py:87`). |
| K-BORU-6 | CLI "Runnable project" / "Coverage" hep NO / N/A | kapandı | `karadul/cli.py:1080-1082` satırlar kaldırıldı (BICIM-12 / ARAYUZ-07). |
| K-BORU-7 | `pipeline_iteration_timeout` gerçek zaman aşımı değil | açık | `karadul/pipeline/steps/feedback_loop.py:181` tur BİTTİKTEN sonra `iter_duration > iter_timeout`. |
| K-BORU-8 | `filter_stages` bilinmeyen `stop_after`'da bütün aşamalar | açık | `karadul/cli_common.py` `except ValueError: pass` duruyor. |
| K-BORU-9 | 119 çıktıda hep boş dönen adımlar (gözlem) | gereksizleşti | Ayrı bulgulara dağıldı: yeniden yazım (TIP-07 / K-1), `dispatch_resolved` (MUH-06), mühendislik sabitleri (MUH-10), capa (IMZA-06). |
| K-BORU-10 | YARA MPRESS / ASPack / Delphi gözlemi | gereksizleşti | IMZA-05 kapandı (P03). |
| K-BORU-11 | `flirt_signature_sources` başka koşunun yolu (şüphe) | doğrulanamadı | Bugünkü çıktıya bakılmadı (Ghidra koşusu gerekir). FLIRT kanalı P15b'den beri her girişte bekletiliyor; şüphe büyük olasılıkla gereksizleşti ama ölçülmedi. |

---

## 2. Kulvar AD (12 bulgu: K 1, Y 4, O 6, D 1; küçük kalem 9)

| Kimlik | Önem | Durum | Kanıt |
|---|---|---|---|
| AD-01 | KRİTİK | kapandı (kanal ad vermiyor, kanıt satırı yazıyor; K-2 kararı Berke'de) | P12b `6a32d8f`. **Kod:** `karadul/reconstruction/tarif/alt_kanal.py:195-196` `SUB_KEBAB_NAME: DECISION_WEAK` (eski `belirsiz`); `karadul/reconstruction/c_namer.py:2398-2408` kebap dizgisinin rolü `string_roles` olarak köken kaydına gidiyor, `:4134-4150` `_kebab_string_roles`. **Ölçüm:** `docs/arge/2026-11-19_birlesik_olcum/sonuc.md:105` H5 `kebap_ad` adı = 0 tuttu; `:159` 239 yanlış → 0. K-2 ("isim üret") karşısında kanal artık ad üretmiyor; rol + nesne kuralı ölçümle kurulamadı (OKU "Berke'nin kararını bekleyenler"). |
| AD-02 | YÜKSEK | kapandı (rol kanıt olarak; ad kuralı kurulamadı) | P12a `45b1cf2`, P12b. **Kod:** `karadul/reconstruction/c_namer.py:4156-4176` `_split_role_candidates` `api_param_reverse` adaylarını ad listesinden çıkarıyor; çağrı `:2397`, kayıt `role_evidence` `:2407`. **Ölçüm:** `sonuc.md:106` H6 `api_param_reverse` adı = 0; `:160` 84 yanlış giderildi, 1 doğru (openssl `verify_callback`) kaybedildi (P12a'da kabul edilmiş bedel). |
| AD-03 | YÜKSEK | kapandı | P-S3 `36cd8a1`, P-S3b. **Kod:** `karadul/analyzers/gnulib_fingerprints.py:377` `MIN_PRESENCE_MODULES = 2`, `:496-519` `presence_evidence` (en az biri glibc ile ortak olmayan iki bağımsız modül); `karadul/stages.py:1998-2043` varlık kanıtı yetmezse ad yazılmıyor, aday `gnulib_candidates.json`'a. **Ölçüm:** `sonuc.md:104` H4 `on_ad:gnulib` 733 / 733 / 0; `:158` −222 yanlış. Mach-O Homebrew gnulib (P-S3b) 8 / 0. |
| AD-04 | ORTA | kapandı | P13a `2450c0e`, `0dcc8bb` (coreutils `exact_multi` 42 → 0). |
| AD-05 | ORTA | kapandı | P13a `2450c0e`, `0dcc8bb` (c_namer'ın reddettiği ön ad birleştiriciden geri gelmiyor; karar köken kaydında). |
| AD-06 | YÜKSEK | kapandı | P13a `c8bf547`. **Kod:** `karadul/pipeline/steps/parallel_algo_eng.py:146-158`: ön ad `extractor.as_pre_name_map()` (eşik, fonksiyon başına en iyi, tek ad); `binary_names.json` `selection_record()`. Ham `{n.original_name: n.recovered_name for n in extract_result.names}` satırı yok. |
| AD-07 | YÜKSEK | kapandı (gnulib satırı bayat, ihtiyatlı yönde) | P12a `70cafe8`, P12c `0f1a542`. **Kod:** `karadul/reconstruction/c_namer.py:2488-2494` ön ad güveni `measured_pre_name_confidence(meta)`, ölçülmemiş kanalda güven yazılmıyor; `karadul/core/naming_labels.py:48-56` `MEASURED_PRE_NAME_PRECISION`. Kalan: `on_ad:gnulib` satırı hâlâ `(621, 843, 0.706)` (`naming_labels.py:49`); birleşik ölçüm 733 / 733 ve 0,995 öneriyor (`sonuc.md:293`), koda yazılmadı (OKU). Analist bugün gnulib adlarını gerçek kesinliğinden düşük güvenle görür. |
| AD-08 | ORTA | kapandı | P12a `99df577` (açıklanamayan yerel ad eki 46 730 → 0). |
| AD-09 | ORTA | kapandı | P13a `8274d7e`, yama `0e190bd` (S808'de 81 öneri → 0 ön ad). |
| AD-10 | ORTA | kapandı (uygulamada n-gram `veri_yok`) | P09 `663deb7` (durum yazımı, süzgeçli uygulama) + P15b `Config.data_root` (GHIDRA-14); P05c `NGRAM_APPLY_NAMES = False` (adlar aday kipinde, kökenli). Uygulama paketi `sigs/` taşımıyor → n-gram uygulamada `veri_yok` (paketleme kararı Berke'de, OKU). |
| AD-11 | ORTA | kapandı | P13a `9404e3d` (+ B-C6). |
| AD-12 | DÜŞÜK | kapandı | P13a `1811b8d` (K-3 A5 silme). |

### AD küçük kalemleri

| # | Kalem | Durum | Kanıt |
|---|---|---|---|
| K-AD-1 | `bayesian_single` `conflicts_resolved`'a yazılıyor | açık | `karadul/reconstruction/name_merger.py:255-256`; dosyada 2026-11-17'den sonra commit yok. Etki AD-05'ten sonra daraldı (yalnız c_namer'ın ad vermediği anahtarlar). |
| K-AD-2 | Kısmi / anlamsal birleştirme farklı adları doğrulama sayıyor; yorum 0,7x, kod 0,85 | açık | `name_merger.py:318-320`. |
| K-AD-3 | İki zayıf kaynak tek güçlü adayı geçiyor | açık | `name_merger.py` değişmedi. |
| K-AD-4 | Aynı `AlgorithmMatch` hem `engineering_constant` hem `engineering_formula` | açık | Onarım kaydı yok (`_feedback_naming_candidates.py:1142-1183` iki kanal aynı listeden). |
| K-AD-5 | `aho_replacer` dizgi / yorum içini ayırt etmiyor | açık | Onarım kaydı yok; gerçek bozulma örneği yok. |
| K-AD-6 | Yerel ad, aynı gövdede çağrılan fonksiyonu gölgeliyor (`thread(...)` derlenmez) | açık | `karadul/reconstruction/name_validity.py:38-40` yerel gölgelemeyi "geçerli" sayıyor; çağrılan adla çakışma denetimi yok. |
| K-AD-7 | gnulib dizgi taraması `rglob` sırasına bağlı | kapandı | `karadul/stages.py:1936-1939` `sorted(decompiled_dir.rglob("*.c"))` (P-S3). |
| K-AD-8 | Önyük / çağrı şekli kanalı adı zaten bilinen fonksiyonu aday sayıyor | açık | Onarım kaydı yok; kodda ayrıca denetlenmedi. |
| K-AD-9 | `string_context` klasik güveni her zaman ≥ 0,75 | açık | `karadul/reconstruction/c_namer.py:3556` `min(0.9, 0.7 + len(best_keywords) * 0.05)`. Bugün susturma kararlarıyla sınırlı (yalnız `oz_ad` belirsiz, ad veriyor). |

---

## 3. Kulvar TIP (11 bulgu: Y 6, O 4, D 1; küçük kalem 9)

| Kimlik | Önem | Durum | Kanıt |
|---|---|---|---|
| TIP-01 | YÜKSEK | kapandı (kusur); eşleşme yeteneği bekletildi (K-1) | P11 `3b561dc`. **Kod:** `karadul/pipeline/steps/cfg_iso_match.py:9-19, 43-104`: düğüm histogramı `cfg.json` `blocks[].mnemonics`'ten (`mnemonic_histogram=dict(Counter(mnems))`, `:104`); döküm ya da uyumlu blok yoksa `desteklenmiyor` + neden (`:174-203`); fonksiyon hatası sayaçta (`fonksiyon_hatasi`, `:226-245`). Kalan: öntanımlı banka (8 elle x86 + 307 sentetik) AArch64'te eşleşemez → dürüst `desteklenmiyor`; gerçek koddan banka ön kaydı tutmadı (kesinlik 0,882 < 0,90), ürüne alınmadı (K-1). |
| TIP-02 | YÜKSEK | kapandı (ad kanalı bayrakla kapalı, K-1) | P11 `ade9f23`. **Kod:** `karadul/pipeline/steps/computation_fusion.py:1-26, 46-84`: anahtar iki kaynakta da adres, yalnız `FUN_` fonksiyonların imza kanıtı, olasılık ölçülmüş kesinlikten, ölçülmemişte `abstain`; 0,182 sabiti ve `cfg_hash` totolojisi yok. Tüketici `confidence_filter.py:47,120`, bayrak `computation/config.py:79` `enable_fusion_naming = False`. |
| TIP-03 | ORTA | kapandı | P11 `c137468` (433 olan erişim 173 882 → 0; DWARF B1 0,997 / B2 0,852). Bayrak (`enable_computation_struct_recovery`) öntanımda kapalı. |
| TIP-04 | ORTA | kapandı (yeniden yazım bekletildi, K-1) | P10 `3a10ea7` (Ghidra alan adı ezilmesi 4 722 / 21 888 → 0). `karadul/reconstruction/engineering/struct_recovery.py:995` `APPLY_REWRITES = False`; öneriler aday dizininde (`:1266-1271`). |
| TIP-05 | ORTA | kapandı | P10 `8a44cdc` (anahtar `(fonksiyon, değişken)`, ölçek, tip uyumu). |
| TIP-06 | YÜKSEK | kapandı | P09 `d007ef6`. **Kod:** `karadul/reconstruction/c_type_recoverer.py:191, 1207, 1732, 2461` kullanım etiketleri `(fonksiyon, değişken)` anahtarlı; `:214, 249` desenler dizgi ve yorumu örtülmüş kopyada; `:89` dizgideki sayı kayan nokta kanıtı değil. **Ölçüm (P09):** yeni `double` 5 / 21 → 0. Kalan, ayrı karar: `undefined8 → uint64_t` öntanımı DWARF'a göre %74 yanlış (P18 karar B); yama `_UNDEFINED_DEFAULTS = {}` 78 testi kırdığı için uygulanmadı (`gonderim/OKU.md:78`). |
| TIP-07 | YÜKSEK | kapandı (yapının koda bağlanması bekletildi, K-1) | P09 `5fd579f`, `f5e0734`, `e25da4a`. **Kod:** `karadul/reconstruction/c_type_recoverer.py:1495-1509` `types.h`'ye yalnız Ghidra'nın yapıları ve koda bağlanan Karadul yapıları; bağlanmayanlar `types_candidates.txt`'e (`:1158-1162`, `:3113-3123`); `:2507-2515` "Struct type application: YAZILMAZ (K-1, TIP-07)"; alan güveni desen kaynaklıda 0,0 (`:918-922`). **Ölçüm (P09):** 14 ikilide `types.h` yapı 4 109 → 0, örtüşen alan 582 → 0. |
| TIP-08 | ORTA | kapandı | P06 `422f38f` (`c_comment_generator.py:1829-1838, 2071`; kanca 15 → 0, kimlik 70 → 0). Kalan: 2 217 "By name only" etiketi (işaretli; kendi simgelerde yanıltıcı olabilir, `redisGitSHA1`). |
| TIP-09 | YÜKSEK | kapandı | P06 `ceda110`. **Kod:** `karadul/reconstruction/c_algorithm_id.py:535` yeni kanıt kuralları; `:1434-1459` desenler dizgi ve yorumu örtülmüş metinde, `min_kinds` farklı kanıt türü + `min_matches` şart. **Ölçüm (P06):** yapısal etiket 36 ikili / 216 → 2 / 2 (ikisi GT'ye göre doğru), Galois 172 → 0, PBKDF2 6 → 0. Bedel: içerikçe doğru 10 yapısal etiket de gitti. |
| TIP-10 | DÜŞÜK | kapandı | P15b `42c3144`, P15a `351ab44` (sabit 100 tabanı ve "debug'a göre %" kalktı). |
| TIP-11 | YÜKSEK | kapandı | P09 `d007ef6`. **Kod:** `karadul/pipeline/steps/_feedback_typing_extras.py:20-33` `xtride_replacement_ok`: `long` / `ulong` yalnız işaretçi tipiyle, `undefinedN` yalnız aynı genişlikle değişir; `karadul/reconstruction/xtride_typer.py:747, 1108-1123` kayan nokta kuralı yalnız sağ tarafı üst düzeyde kayan nokta sabiti olan atamada, dizgi örtülü. **Ölçüm (P09):** Ghidra'nın somut tipini ezen 781 / 1 254 → 0. |

### TIP küçük kalemleri

| # | Kalem | Durum | Kanıt |
|---|---|---|---|
| K-TIP-1 | `cfg_iso_vf2_node_cap` okunmuyor | kapandı (etkisiz olarak işaretli) | `karadul/config.py:856` "ETKİSİZ", `:1136` `INERT_SETTINGS` kaydı → yüklemede uyarı (P15a). Bağlanmadı. |
| K-TIP-2 | VF2 her çağrıda `spawn` süreci | kapandı | P11: süreç içi (`karadul/computation/cfg_iso/vf2_matcher.py:243`). Ölü `_vf2_worker` (`:155`) silmesi P23'te, Berke onayı bekliyor (K-10). |
| K-TIP-3 | `computation_struct_recovery` toplam süre sınırı yok | açık | `computation_struct_recovery.py:345` yalnız fonksiyon başına `struct_solver_timeout`; bayrak öntanımda kapalı. |
| K-TIP-4 | CFG-iso çapa `string_refs` alt dizgi semantiği | açık | `karadul/computation/cfg_iso/anchor_check.py:103-110` (`any(s in cs …)`). |
| K-TIP-5 | `_apply_per_func_replacements` dizgi içindeki ayracı sayıyor | açık | `karadul/reconstruction/c_type_recoverer.py:866-877` ham `{` / `}` sayımı; onarım kaydı yok. |
| K-TIP-6 | Her `.c` dosyası iki kez yazılıyor (`struct_recovered/` + `originals/`) | kapandı | P10: yedek yalnız değişen dosyada ve kaynak ağacın dışında (`engineering/struct_recovery.py:1091-1092, 1259-1263`). |
| K-TIP-7 | Ölü `inline_extractor.py`, `field_namer.py` | açık | İki dosya da duruyor. |
| K-TIP-8 | `cfg_iso_match` fonksiyon hatası yalnız DEBUG, sayaç yok | kapandı | `cfg_iso_match.py:226-245` `fonksiyon_hatasi` sayacı kol durumunda. |
| K-TIP-9 | `FusionWeights.load` eksik `bias`'ı 0,0 alıyor | gereksizleşti | P11'den sonra `computation/fusion/model.py` ölü (yeni yol `measured.py`); silmesi P23 / K-10'da, onay bekliyor. |

---

## 4. Kulvar IMZA (16 bulgu: K 4, Y 6, O 5, D 1; küçük kalem 7)

| Kimlik | Önem | Durum | Kanıt |
|---|---|---|---|
| IMZA-01 | KRİTİK | kısmen | P01 `4c07230`, P01b. **Kod:** `karadul/analyzers/binary_intelligence.py:11-27`: belirteç sınırı (`_` sınırdır), desen başına `case_sensitive` iki yolda, gürültü süzgeci, iki bağımsız kanıt; `:61-99` `evidence_kinds`. **Ölçüm (P01, masum kapı):** Bluetooth / OpenGL 119 → 0, Browser Engine 114 → 0, kernel riskli SIP / Kernel Extension 0; toplam iddia 2 267 → 646. **Kalan:** kalıntı alt sistem iddiaları (Version Control, Testing Framework, Terminal Emulator, Licensing): masum kapı eşiği `scripts/measurement/masum_kapi_esik.json` `esikler/dogrudan/bi/gelistirme/yanlis_toplam = 455` (119 ikili; coreutils ikilisi başına 3), macos 215, pe 22 (P01b). Kapı bunları gerileme sınırı olarak tutuyor, sıfırlamıyor. |
| IMZA-02 | KRİTİK | kapandı | P02 `494d6be`, P02b. **Kod:** `karadul/analyzers/anti_debug_detector.py:14-18` işlem kodu taraması yalnız x86 / x86-64 hedefte ve yürütülebilir bölgede, komut sınırı capstone ile; `:278, :314-336` PEB deseni bilgi düzeyi; P02b ithal tabanlı hükümler Ghidra çağrı yeri ve argümanına bağlı. **Ölçüm:** RDTSC 14 → 0; geliştirme MED / HIGH 8 → 0. Risk: PT_DENY_ATTACH / P_TRACED hükmü gerçek Ghidra çıktısında doğrulanmadı (P02b). |
| IMZA-03 | YÜKSEK | kapandı | P02 `8e41b76`. **Kod:** `anti_debug_detector.py:190-210` MSVC CRT ithal kümesi (`_CRT_COOKIE_*`, `_CRT_CONFIDENCE = 0.10`), `:76` tek ayırt edici olmayan kanıt zayıf. **Ölçüm (P02):** masum PE MED / HIGH 21 → 0. |
| IMZA-04 | YÜKSEK | kapandı | P02 `6a1b145`. **Kod:** `karadul/analyzers/packer_fingerprint.py:263-309` desen yalnız `AddressOfEntryPoint` dosya ofsetinde (`:388, :422-425`), en az 6 bayt (`FSG` `BB ?? ?? ?? ?? BF ?? ?? ?? ??`, `:301`); doğrulanmamış desenler `pattern_verified` (`:79`). **Ölçüm:** masum PE FSG 30 → 0, UPX 4 / 4 korundu. |
| IMZA-05 | KRİTİK | kapandı | P03 `907d775`, `a4d0f76`. **Kod:** `karadul/analyzers/yara_scanner.py:14-16` hüküm modeli; `:657-666` `MPRESS_Packed` yalnız PE bölüm tablosunda `.MPRESS1/.MPRESS2` (`condition=pe_section(...)`, `formats=["pe"]`); paketleyici kurallarında `formats=["pe"]` (`:613-711`); `:801` olağan çalışma zamanı API'leri (clock_gettime) anti-debug kuralından çıktı. **Ölçüm (P03):** yara yanlış geliştirme 70 → 0, macos 127 → 0, pe 71 → 0. |
| IMZA-06 | YÜKSEK | kapandı (kod beslemesi bekletildi, K-1) | P03 `3ccb51d`, P-S1. **Kod:** `karadul/analyzers/capa_scanner.py:700-754` arka uç biçime göre seçiliyor; `:42-49, :297-331` durum sözleşmesi (`calisti / arac_yok / hata / desteklenmiyor`). **Ölçüm (P03):** capa ilk kez çalışıyor (PE 19 / 21); AArch64 ELF / Mach-O / ARM64 PE `desteklenmiyor` + neden. Kalan: capa API yolunda zaman aşımı yok (decompile.exe 241 sn), kural regex kusurları (12 kesin yanlış: `/frida/i` ← "Friday"), CRT FLIRT imzaları yok → P03b (gönderilmedi). Koda yorum / ad beslemesi `enable_capa_code_feed = False` (K-1). |
| IMZA-07 | KRİTİK | kapandı (yeni VT dağıtımı yayın işi) | P08 `0fd1cf3`, `4a74b08`; P15b; P15c. **Kod:** `karadul/analyzers/signature_db.py:465-512` `_resolve_attribution`: şema 2 kaydında sağlayıcılar platformla süzülüyor, birden çok kitaplık ailesi kalırsa kitaplık BOŞ (uydurulmuyor); `:201-205` `libraries` listesi; ELF'te kitaplık iddiası ikilinin bağlanma kanıtından (`karadul/pipeline/steps/ghidra_metadata.py:223-227`, P15c). Eski şema 1 açılırsa uyarı + `sigdb_schema_warning` (`signature_db.py:1813-1833`). **Ölçüm:** kitaplık iddiası kesinliği 0,695 → 0,975, PyPI adıyla iddia 2 234 → 0 (P08); eski yanlış aileler 71 → 0 (P15b). **Kalan:** yeni VT (2,9 GB) depoda değil: ana ağaçta `signatures.lmdb → ~/karadul_olcum/sigdb/s2-20261118/signatures.lmdb` bağı; uygulamaya gömme `packaging/macos/build_mac_app.sh:96-221` (`--full`, şema 2 şartı) ama paket derlenmedi (Y8). Mach-O iki düzeyli bağlama ve ikilinin kendi tanımladığı simgelere verilen kitaplık iddiası (502) ele alınmadı (P15c açık). |
| IMZA-08 | ORTA | kapandı | P08 `e957153` (alt çizgisi silinmiş ad 5 797 → 0). |
| IMZA-09 | YÜKSEK | kapandı | P08 `278c0d6`. **Kod:** `signature_db.py:732-733` `_PROTOBUF_NAMESPACE = "google::protobuf::"`; `:2505-2516` kısmi eşleşme yalnız ad bu ad alanıyla başlıyorsa, `matched_name` özgün ad. `MyCache::Get` / `Init` artık eşleşmiyor. |
| IMZA-10 | ORTA | kapandı | P08 `e159620` (önbellek anahtarında platform ve LMDB durumu). |
| IMZA-11 | YÜKSEK | kapandı (veri dağıtımı K-5 / Y8) | P08 `f6bff68`, P15b, P15c. **Kod:** `karadul/pipeline/steps/ghidra_metadata.py:207-241, 281` `sigdb_status` (`matched / no_match / error / unavailable`) her koşuda + VT künyesi; `signature_db.py:3277-3335` künye (`sigdb_schema_version`, `sigdb_build_id`, `sigdb_schema_warning`, …); rapor `karadul/reporting/report_data.py:456-463`. "Eşleşme yok" ile "VT yok" artık ayrılıyor. Kaynaktan kuran kullanıcıda VT yine yok (yalnız yerleşik ~7,7 bin ad), ama çıktı bunu söylüyor. |
| IMZA-12 | ORTA | kapandı | P08 `7df0858` (+ `signature_db.py:493-497`). |
| IMZA-13 | YÜKSEK | kapandı (kanallar bayrakla) | P13b `a92b762` (= BORU-14 a/c). **Kod:** yukarıda BORU-14 satırı (`_feedback_naming_merger.py:295-334, 399-419`; `config.py:679-685`). C++ Itanium adları Rust sayılmıyor (P13b kalem 3). PDB ofset onaltılık hatası da onarıldı (libz3.dll 0 / 771 → 771 / 771). |
| IMZA-14 | ORTA | kapandı | P13b `0841afa` (legacy çözülmemiş kaçış 6 102 → 0; v0 10 / 10 llvm-cxxfilt ile aynı). |
| IMZA-15 | ORTA | kapandı | P-S1 `6e93cee`, `40b1a44`; P02b (durum dedektörün `scan()`'inden). |
| IMZA-16 | DÜŞÜK | kısmen | P13b `bf8fbd3`: RTTI kanal durumu dürüst (`desteklenmiyor`), ad kanalı hazır; `karadul/config.py:671` `enable_rtti_recovery` "ETKİSİZ" + `INERT_SETTINGS` uyarısı (`:1114`). Analiz akışında RTTI üretici adımı yok (P13b kalem 4 yapılmadı; `cpp_rtti.py` düşman girdiye denetlenmedi). |

### IMZA küçük kalemleri

| # | Kalem | Durum | Kanıt |
|---|---|---|---|
| K-IMZA-1 | `hacker_cli` uyarı anahtarları kökte aranıyor (ölü) | kapandı | P15a ("`hacker_cli` ölü kod düzeldi", DURUM P15a satırı). |
| K-IMZA-2 | SARIF `yara_matches` liste ↔ sayı; YARA paketleyici KRDL003 "(unknown)" | kapandı | P-S1 yapılandırılmış `yara_hits`; P07 (ARAYUZ-17: "(unknown)" 37 → 0, paket etiketli KRDL003 9 → 0). |
| K-IMZA-3 | Alt sistem eşiği tek kanıtı geçiriyor | kapandı | P01 (`binary_intelligence.py:1800` en az iki öğe kuralı). Kalıntı iddialar IMZA-01 satırında. |
| K-IMZA-4 | Dizgi katmanı adsız fonksiyonlara `copy_buffer`, `read_env_var` | kapandı | P15c: kayıtlar `claim = kimlik / davranis`, davranış güveni ölçülmüş Wilson alt sınırı; yanlış kimlik iddiası 236 → 0; koda uygulanan 0. |
| K-IMZA-5 | Anti-VM `(?i)vmtoolsd\|vmware`, `qemu-ga\|QEMU` dizgisi yardım metnini de tutar | açık | `karadul/analyzers/anti_debug_detector.py:303-304`; onarım kaydı yok (gerçek çıktıda rastlanmamıştı). |
| K-IMZA-6 | UPX 2 bayt / Petite 3 bayt giriş deseni | kapandı | `packer_fingerprint.py:296, 303` artık uzun maskeli desenler, yalnız giriş noktasında (P02). |
| K-IMZA-7 | Önbellekten kurulan örnekte FLIRT bayt imzaları yok (şüphe) | doğrulanamadı | FLIRT kanalı P15b'den beri her girişte bekletiliyor (P08b gönderilmedi); şüphe izlenmedi. |

---

## 5. Kulvar MUH (12 bulgu: K 2, Y 3, O 6, D 1; küçük kalem 11)

| Kimlik | Önem | Durum | Kanıt |
|---|---|---|---|
| MUH-01 | KRİTİK | kapandı | P05 `3d6858c`; P05b, P05c. **Kod:** `karadul/reconstruction/engineering/semantic_namer.py:214-266` tek ad kapısı (`name_validity.lexical_reject_reason(local=True)` + Ghidra ad biçimi + eşik); `:274-300` `_split_call_args` ayraç dengeli, dizgi içi sayılmıyor. **Salt okur deneme (bugün, `PYTHONDONTWRITEBYTECODE=1`):** `_sanitize_c_name('0xffffffffffffffff') → ''`; `_gate_name_reason`: `uint64_t → invalid_type_name`, `int / return / long → invalid_c_keyword`, `DAT_00130770 / local_100 → ghidra_generated_name`. **Ölçüm (P05):** kodda geçersiz / anahtar sözcük / tip adı parametre adı 119 ikilide 2 249 → 0. |
| MUH-02 | YÜKSEK | kapandı | P05 `45a4369`, P05b K2. **Kod:** `semantic_namer.py:1426` gerçek döngü iç içeliği, `:1460` kayan noktalı öğe kanıtı, `:2371` işaretçi şablonu yalnız öğe kanıtıyla. **Ölçüm (P05):** matris / vektör adı 390 → 0. |
| MUH-03 | KRİTİK | kapandı (adaylar bekletmede, K-1) | P04a `bacb7b8`. **Kod:** `karadul/reconstruction/engineering/composition_analyzer.py:738-829` kanıt kapısı (tam belirteç; `_dt_`, `_init_`, `_fini_`, `_itm_`, `__gmon`, `__cxa_`, `__libc_` gösterge dışı); `:78-129, 1083, 1159, 1260-1265` kapıdan geçmeyen şablon `pending_compositions`'a, rapora girmiyor. **Ölçüm (P04a):** raporlanan şablon 133 ikilide 533 → 0 (103 aday beklemede); CalculiX gerçek pozitif 19 → 1. Kalan: genel bileşimlerin (iterate / pipeline / fork-join) alan etiketi algoritma kategorisinden (`:3177-3190`). |
| MUH-04 | ORTA | kapandı | P04a `d148686`, yama `6e86eb7` (structural 226 → 0). |
| MUH-05 | ORTA | kapandı | P04b `7e30dc0`, `d7f0f4e` (K-3 A3 `confidence_calibration.py` silindi; sahte kalibre değerler kalktı). |
| MUH-06 | ORTA | kısmen | P04b `ceaa4df`: Ghidra vtable biçimi tanınıyor (çağrı yeri 0 → 767), doğrulanamayan yuva tahmini ve "her ad seçici" haritası kalktı; çağrının ÇÖZÜMÜ yok (vtable içeriği okunmuyor; yeni özellik). |
| MUH-07 | DÜŞÜK | kapandı | P04a `6898296` (Row-major 409 → 0). |
| MUH-08 | ORTA | kapandı (sayaç); uygulama açık iş | P13b `dbb9944` (= BORU-10). |
| MUH-09 | ORTA | kısmen | P04b `a6701ee`: (1) "requires … or later" sürüm sayılmıyor (sqlite '3.8.12' → 'unknown'), (2) `lookup_closest` önek eşleşmesi düzeldi; (4) `extracted_names.update` P13a `9404e3d` ile kapandı (AD-11). Açık: (3) boş `reference_db_path` ortak önbelleği kullanıyor, (5) indirilen kaynak arşivinde sha256 yok — ikisi de ağ + `allow_reference_download` arkasında, bugün etkisiz (P04b "kalan"). |
| MUH-10 | YÜKSEK | kapandı | P04b `3052400`. **Kod:** `karadul/reconstruction/engineering/analyzer.py:138-164` sabit ve yapısal katman kuralları (tam belirteç, ayırt edici sabit), `:605` Layer 1; `:983-984` alan kapısı `ghidra_functions.json` `functions` listesinden; Kiril harf yok (`analyzer.py`'de U+0400–04FF karakter taraması: 0). **Ölçüm (P04b):** kapı zorla açıkken masum 133 ikilide API dışı tespit 307 448 → 6. Kalan: `patterns.py` genel aritmetik desenleri iki yapısal kanıtla bile yanlış olabiliyor (simpsons_rule, power_iteration). |
| MUH-11 | YÜKSEK | kapandı (kanalın ölçülen kesinliği düşük) | P05 `3d6858c`, P05c. **Kod:** `semantic_namer.py:2557-2572` yerel ad eşiği ürün ayarından (`min_confidence.c_namer_apply`); `:2640-2654` köken bölümü (`naming_provenance.json`), `:2894` her adın kanalı / güveni / gerekçesi. **Kalan (yayın notu):** parametre adlarının DWARF'a göre kesinliği düşük: P05c'de %6,69 (22 ikili); birleşik ölçümde doğru 136 → 85, kesinlik %2,8 (`gonderim/OKU.md:83`, yeniden ölçüm sırada). |
| MUH-12 | ORTA | kapandı | P04b `1632a7a`, yamalar `7d3025c`, `485ea9f` (formül 13 → 2; kalan openssl PBKDF2 doğru). |

### MUH küçük kalemleri

| # | Kalem | Durum | Kanıt |
|---|---|---|---|
| K-MUH-1 | Rapor bileşim türünü `type`'tan okuyor (JSON'da `pattern`) | kapandı | P07: `karadul/reporting/sections_render.py:169` `c.get("pattern")`. |
| K-MUH-2 | Kökteki `crypto_algorithm_database.json`, `new_engineering_algorithms.json` ölü veri | açık | İki dosya da depoda duruyor; onarım kaydı yok (P23 adayı). |
| K-MUH-3 | `capa_annotation` enjeksiyon hatası yalnız DEBUG | açık | `karadul/pipeline/steps/capa_annotation.py:97-98`. capa kod beslemesi öntanımda kapalı (K-1), etki bayrakla. |
| K-MUH-4 | Mühendislik taramasında fonksiyon başına hata DEBUG ile yutuluyor | açık | `karadul/reconstruction/engineering/analyzer.py:590-594`. |
| K-MUH-5 | `_load_json` `{"total","program","functions"}` biçimini ad sözlüğü sanıyor (adres "unknown") | açık | `analyzer.py:1042-1062` dict'i olduğu gibi döndürüyor; alan kapısı ayrı yoldan düzeldi (MUH-10). `block_annotator.py` tarafı ayrıca denetlenmedi. |
| K-MUH-6 | `CALLER_NAME_HINTS` iki yönlü alt dizgi | kapandı | P05b K4: tam belirteç (`semantic_namer.py:1109` `_name_tokens`). |
| K-MUH-7 | `block_annotator` alan dalları ölü; `memory_op` / `loop_purpose` yorum gürültüsü | açık | Onarım kaydı yok. |
| K-MUH-8 | `deep_tracer` hedef seçimi (`main` seçilemiyor, öz döngü) | açık | Onarım kaydı yok (düşük değerli). |
| K-MUH-9 | `data_flow` kenarlarının çoğu düşük güvenli `struct_field` | açık | Gözlem; onarım kaydı yok. Belirlenimcilik ayrı onarıldı (P-S2 `ba167d7`). |
| K-MUH-10 | Güven aralığı taraması: [0,1] dışı / NaN yok | gereksizleşti | Kusur değil, gözlem. |
| K-MUH-11 | Başarım gözlemi (paket %5,4, asılma yok) | gereksizleşti | Kusur değil, gözlem. |

---

## 6. Yayını durduranlar (açık ya da kısmen kalan KRİTİK / YÜKSEK)

1. **IMZA-01 (KRİTİK, kısmen).** Kullanıcıya etkisi: raporun "Architecture Analysis" bölümünde masum ikililer hâlâ ikili başına birkaç kanıtı zayıf alt sistem iddiası taşıyor (geliştirme setinde 119 ikilide 455 iddia; P01b'nin saydığı türler Version Control, Testing Framework, Terminal Emulator, Licensing); ağır olanlar (Bluetooth, OpenGL, kernel düzeyli SIP / Kernel Extension, Browser Engine) artık 0. Onarım yeri `karadul/analyzers/binary_intelligence.py` (alt sistem desen tabloları ve iki kanıt kuralı) + `scripts/measurement/masum_kapi_esik.json` (eşiği sıfıra yakın çekmek). Gerekçeli erteleme seçeneği: alt sistem satırlarını raporda "zayıf ipucu, doğrulanmadı" diye etiketlemek (`karadul/reporting/report_data.py`, `sections_render.py`) ve yayın notuna yazmak.

Başka açık ya da kısmen kalan KRİTİK / YÜKSEK bulgu yok (29 bulgunun 28'i kapandı; aşağıdaki §8 notları kapanmış bulguların yayın notuna girmesi gereken kalanlarıdır).

## 7. Ertelenebilirler (yayın notu "bilinen kusurlar" için birer satır)

Açık ya da kısmen kalan ORTA / DÜŞÜK bulgular:
- **BORU-07:** `karadul batch analyze` yalnız geliştiricinin sabit hedef listesiyle çalışır (`karadul/batch.py:40-48`); keyfi dosya verilemez. Başarı / ayar / işçi çökmesi kusurları kapandı.
- **MUH-06:** C++ sanal çağrı yerleri bulunur ama hedefleri çözülmez; "Virtual Dispatch" bölümünde çözülen çağrı 0.
- **MUH-09:** Başvuru karşılaştırmasının indirme yolu (yalnız ağ ve `allow_reference_download` açıkken) indirilen kaynak arşivinin özetini doğrulamaz; boş `reference_db_path` ortak önbelleği kullanır.
- **IMZA-16:** `enable_rtti_recovery` etkisizdir (yüklemede uyarı verir); C++ RTTI sınıf adları analiz akışına girmez, yalnız `karadul rtti` komutuyla görülür.

Küçük kalemlerden kullanıcıya görünenler (açık):
- Ctrl+C'de "yarım kalan workspace temizleniyor" iletisi basılır ama hiçbir şey silinmez (K-BORU-1).
- Elle bozulmuş `~/.karadul/overrides/<hash>.json` sessizce boş sayılır; sonraki ad düzeltmesi önceki elle adları siler (K-BORU-2). `--overrides` ile verilen dosya okunamazsa yalnız DEBUG günlüğü (K-BORU-3).
- `pipeline_iteration_timeout` asılan turu kesmez, yalnız sonraki turları atlar (K-BORU-7).
- Yerel değişken adı aynı gövdede çağrılan fonksiyonun adını alabilir; o dosya derlenmez (K-AD-6).
- Anti-VM dizgi kuralı yardım metnindeki "qemu" / "vmware" sözcüğünü de tutar (K-IMZA-5).
- Ölü kod / veri: `_capa_comment_inject.py`, `overrides.set_param`, `inline_extractor.py`, `field_namer.py`, kökteki iki algoritma JSON'u (K-BORU-4/5, K-TIP-7, K-MUH-2).
- Kalan teknik borç (kullanıcıya doğrudan görünmez): NameMerger sayaç / birleştirme kuralları (K-AD-1…3), mühendislik çift aday (K-AD-4), Aho dizgi içi değiştirme (K-AD-5), önyük kanalı adlı fonksiyonu aday sayıyor (K-AD-8), `string_context` güven formülü (K-AD-9), MaxSMT toplam süre sınırı (K-TIP-3), CFG-iso çapa alt dizgisi (K-TIP-4), dizgi içindeki ayracı sayan tip yazımı (K-TIP-5), DEBUG'a düşen hatalar (K-MUH-3/4), `_load_json` biçimi (K-MUH-5), blok yorumu gürültüsü (K-MUH-7), `deep_tracer` hedefleri (K-MUH-8), `data_flow` kenarları (K-MUH-9), `filter_stages` (K-BORU-8).

## 8. Kapanmış bulguların yayın notuna girmesi gereken kalanları

- **Bekletilen yetenekler (K-1 / K-4; yayın kapısı §2 ile aynı):** CFG-iso eşleşmesi (AArch64'te `desteklenmiyor`, TIP-01), füzyon ad kanalı (TIP-02 / BORU-03), yapı adaylarının koda bağlanması ve yapı yeniden yazımı (TIP-07, TIP-04), bileşim şablonu adayları (MUH-03), capa kod beslemesi (IMZA-06), K-4 ad kanalları (PDB dışı; BORU-14 / IMZA-13). Hepsi bayrakla kapalı ve durumları dürüst.
- **PDB ad kanalı öntanımda AÇIK** (`karadul/config.py:679`), ama gerçek Ghidra koşusunda ölçülmedi (P13b; yalnız libz3.dll + .pdb ile ayrıştırıcı düzeyinde 771 / 771).
- **İmza veritabanı dağıtımı (IMZA-07, IMZA-11):** yeni şema 2 VT (2,9 GB) depoda değil; kaynaktan kuran kullanıcı yalnız yerleşik ~7,7 bin adla çalışır (künye bunu söyler). Uygulamaya gömme betikte hazır (`packaging/macos/build_mac_app.sh`, `--full`), paket derlenmedi (Y8). Mach-O iki düzeyli bağlama kanıtı yok (P15c açık).
- **Parametre adı kalitesi (MUH-11):** ad kapısı ve köken kaydı var, ama DWARF'a göre kesinlik %2,8–%6,7; yeniden ölçüm sırada (`gonderim/OKU.md:83`).
- **Tip öntanımı (TIP-06 yanı):** `undefined8 → uint64_t` öntanımı DWARF'a göre %74 yanlış; karar B ölçüldü, yama 78 testi kırdığı için uygulanmadı (`gonderim/OKU.md:78`).
- **capa süresi (IMZA-06):** API yolunda zaman aşımı yok (decompile.exe 241 sn); P03b gönderilmedi.
- **gnulib güveni (AD-07):** `naming_labels.py:49` hâlâ 0,706; ölçülen 733 / 733 (öneri 0,995) koda yazılmadı. Analist gnulib adlarını gerçek kesinliğinden düşük güvenle görür.
- **`@security` "By name only" etiketleri (TIP-08):** 2 217 etiket yalnız addan, işaretli.
- **Yeni gözlem (bu denetim):** evrensel Mach-O'da anti-debug dedektörü x86_64 dilimini tarıyor (`/usr/lib/dyld`: `RDTSC_Timing` 0,2, "x86_64 dilimi @0x4000", zayıf kanıt), ürün ise arm64e dilimini analiz ediyor (P16a). Hüküm düzeyi bilgi (< 0,4), yanlış değil ama analiz edilen dilimle tutarsız.
- **Kanıtın tarihi:** kod doğrulaması HEAD `2381dce`'de. `git diff --stat b4be6f3..HEAD -- karadul tests` boş (Y1 tam takım koşusundan beri kod değişmedi). Paket ölçümleri ve birleşik 119 ölçümü `a62f15e`'de; o commit'ten HEAD'e `karadul/`'da 36 commit var (P12c, P05c, P-S4, P20b, P18, P22c, P22h …), masum kapı main'de yeniden koşulmalı (Y4).

## 9. Bu denetimde koşulan salt okur denemeler

Hepsi ana ağacın koduyla, `PYTHONDONTWRITEBYTECODE=1`, çalışma dizini scratchpad; dosya yazan tek şey scratchpad'e `strings` / `nm` dökümü.
- MUH-01: `semantic_namer._sanitize_c_name` ve `_gate_name_reason` (sonuçlar MUH-01 satırında).
- IMZA-02: `AntiDebugDetector(...).detect()` → `/usr/bin/ssh` `[]`, `/usr/bin/top` `['sysctl_import']` (bilgi düzeyi), `/usr/lib/dyld` `RDTSC_Timing` 0,2 (x86_64 diliminde gerçek komut, zayıf kanıt; skor 0,2 < 0,4).
- IMZA-05: `YaraScanner` (38 kural, yara-python): `/bin/ls`, `/usr/bin/true`, `/usr/bin/vim` → eşleşme yok; `/usr/bin/ssh` → yalnız `Zlib_Library` (doğru).
- IMZA-01: `BinaryIntelligence.analyze` bulgudaki tetikleyici dizgilerle (`_ITM_deregisterTMCloneTable`, `GLIBC_2.17`, `bindtextdomain`, `siphash`, `maskModuleConfigFlags`, `sha256sum` …) → alt sistem / algoritma / güvenlik / protokol listelerinin dördü de boş. `/usr/bin/vim` dizgileriyle 9 alt sistem + Blowfish (vim'in `cryptmethod=blowfish2`'si gerçek); alt sistemlerin tek tek doğruluğu bu denemede değerlendirilmedi.

## 10. Sayım özeti

Bulgular (65; DIZIN.md ile aynı dağılım: K 7, Y 22, O 30, D 6):

| Önem | kapandı | kısmen | bekletildi | açık | gereksizleşti | doğrulanamadı | Toplam |
|---|---|---|---|---|---|---|---|
| KRİTİK | 6 | 1 | 0 | 0 | 0 | 0 | 7 |
| YÜKSEK | 22 | 0 | 0 | 0 | 0 | 0 | 22 |
| ORTA | 27 | 3 | 0 | 0 | 0 | 0 | 30 |
| DÜŞÜK | 5 | 1 | 0 | 0 | 0 | 0 | 6 |
| **Toplam** | **60** | **5** | **0** | **0** | **0** | **0** | **65** |

- `kısmen`: IMZA-01 (K), BORU-07, MUH-06, MUH-09 (O), IMZA-16 (D).
- `bekletildi` sütunu boş: bekletilen yeteneği olan bulgularda (BORU-03, BORU-14, TIP-01, TIP-02, TIP-04, TIP-07, IMZA-06, IMZA-13, MUH-03) bulgunun anlattığı kusur onarıldı, yalnız yetenek bayrakla kapalı → `kapandı` sayıldı, satırda not var.

Kulvar başına:

| Kulvar | K | Y | O | D | kapandı | kısmen |
|---|---|---|---|---|---|---|
| BORU | 0 | 3 | 9 | 2 | 13 | 1 |
| AD | 1 | 4 | 6 | 1 | 12 | 0 |
| TIP | 0 | 6 | 4 | 1 | 11 | 0 |
| IMZA | 4 | 6 | 5 | 1 | 14 | 2 |
| MUH | 2 | 3 | 6 | 1 | 10 | 2 |

Küçük kalemler (47):

| Kulvar | kapandı | açık | gereksizleşti | doğrulanamadı | Toplam |
|---|---|---|---|---|---|
| BORU | 1 | 7 | 2 | 1 | 11 |
| AD | 1 | 8 | 0 | 0 | 9 |
| TIP | 4 | 4 | 1 | 0 | 9 |
| IMZA | 5 | 1 | 0 | 1 | 7 |
| MUH | 2 | 7 | 2 | 0 | 11 |
| **Toplam** | **13** | **27** | **5** | **2** | **47** |

## DENETİM BİTTİ
