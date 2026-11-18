# P-S3 — `stages.py` 3. tur: gnulib ön ad kanalı kanıta bağlanır (AD-03, B-A3) + veri akışı belirlenimciliği — ilerleme

Brif: `ONARIM_BRIF.md`. Karar: K-2 (Berke: "amacımız isim üretmek; düzelt, yakın ve doğru isim üretmek, hesaplama ile"). Bulgular: AD-03 ve B-A3 (`docs/arge/2026-11-18_genel_tarama/kulvar_AD.md`), P-S2 bulgusu `data_flow_edges` (`P-S2.md` § Kalem 2). Ön kayıt: `P-S3_on_kayit.md` (**c4eab8b**, kod değişmeden önce).

- Taban: worktree `origin/main`'den (e9d2d08) açıldı; `git merge --ff-only main` → **097fdff** (yerel `main` ucu).
- `karadul.__file__` worktree yolunu gösteriyor. Çalışma zamanı verisi symlink (`sigs`, `vendor`, `signatures_homebrew*.json`, `sigs_macos_system.json`, `scripts/node_modules`; commit'lenmez).
- Ölçüm kökü: `~/karadul_olcum/runs/onarim-2026-11-18/P-S3/` (betikler ve çıktılar orada; aşağıda adlarıyla).

| Kalem | Durum | Commit |
|---|---|---|
| 0 — ön kayıt | bitti | c4eab8b |
| 1 — AD-03 / B-A3: gnulib kanalı kanıta bağlı | bitti (H1-H4, H6 tuttu; **H5 tutmadı**: Mach-O gnulib 2024+'ı tanımıyor) | 0a49fba |
| 2 — veri akışı belirlenimciliği | bitti (H7-H9 tuttu) | 19bc7fa |
| 3 — temizlik (kullanılmayan yereller / içe aktarımlar) | bitti | 2415625 |

- P12a'nın `stages.py` yaması (AD-07): `yamalar/` altında `P12a__stages*.patch` yok (yalnız `P12a__binary_name_extractor.py.patch`) → istem gereği geçildi.

## Kalem 1 — AD-03 ve B-A3

### a. Göster (önce)
- **Taban ürün çıktısı** (`urun-yeni2-f30ac9a`, 119 ikili, `out/naming_map.json`): `on_ad:gnulib` uygulanan **843** ad; coreutils dışı: openssl `full_write`, redis-cli `full_write`, Debian tmux `close_stdout`, zstd `usage` + `close_stdout`, Mac tmux `close_stdout` (kulvar_AD ile aynı). GT (`ks1_olc.capa_degerlendir`, P16a'nın `olc_taban.json`'u ile aynı): 621 doğru / 222 yanlış.
- **Ghidra'sız yeniden oynatma** (`gnulib_yeniden.py`): saklı `static/` üstünde ürünün `_recover_gnulib_from_fingerprints`'i, gnulib'den önceki ön adlar (main, KS-1, Faz 1, elle) köken kaydından. Taban kodla (`taban_kod/` = 097fdff'in `git archive`'ı) **119/119 ikilide köken kaydındaki gnulib adlarıyla anahtar ve ad olarak aynı** (sadakat). 844 ateşleme = 843 uygulanan + htop'ta Ghidra'nın zaten `full_write` adını verdiği fonksiyon (`same_as_original`, B-A4). Böylece kanal 119'un tamamında Ghidra'sız ölçülebiliyor.
- Kırılım (taban, yeniden oynatma, GT):

| Grup | Doğru | Yanlış | Yanlışların kaynağı |
|---|---|---|---|
| coreutils (106) | 620 | **217** | `version_etc` 104, `hard_locale` 104, `full_write` 9 (hepsi B-A3) |
| coreutils dışı (13) | 2 (zstd `usage`; htop `full_write`, uygulanmayan) | **5** | `close_stdout` ×3 (Debian tmux, Mac tmux, zstd), `full_write` ×2 (openssl, redis-cli) — AD-03 |

- Yani 222 yanlışın 217'si B-A3 (LTO yerleşimi), 5'i AD-03 (gnulib'siz program).
- **Sürüm koşulu gerekli mi (B-A3, GT ile):** `EXPECTED_COREUTILS = "9.4"` hiçbir yerde denetlenmiyor. Denetlenmesi de gerekmiyor: geliştirme seti coreutils **9.7** (gnulib 2025) ve öbür yedi girdi orada 620/620 doğru. Doğruluğu değişen üç girdi AYNI sürümde (9.4) yapıya göre değişiyor: Debian 9.4 (LTO'suz) 0/11, Ubuntu 9.4 (LTO'lu) 14/14 (2026-11-11 ölçümü, bu pakette yeniden oynatıldı: aşağıdaki tablo). Geliştirme seti coreutils'i LTO'suz: Debian 13 dbgsym DWARF'ında `<artificial>` (LTRANS) CU yok, üretici dizgisinde `-flto` yok (3 ikiliye bakıldı). Ayrım sürümle değil yerleşimle → sürüm denetimi eklenmedi, yerleşim koşulu eklendi.
- **Ölçüm setinde Mach-O gnulib'li ikili var mı:** geliştirme setinin Mac ikilileri yalnız htop ve tmux (ikisi de gnulib'siz). Makinedeki Homebrew coreutils 9.12 (`gcat`, simgeli Mach-O; `nm`'de `close_stdout`, `close_stream`, `__getopt_internal_r`, `emit_bug_reporting_address`) geliştirme seti DIŞINDAN doğrulama ikilisi olarak alındı (test seti kilidinde değil; `/usr/bin/strip`'li kopya, export trie boş, GT özgün `nm`'den: 137 fonksiyon, 125 program sınıfı).

### b. Onar
- `karadul/analyzers/gnulib_fingerprints.py`: `GNULIB_PRESENCE_MARKERS` (7 modül: progname, version-etc, argmatch, closein, xstrtol-error dizgileri; close-stream `__fpending`, freading `__freading` çağrıları; hepsi `vendor/gnulib-ref/lib/<kaynak>`'ta birebir), `MIN_PRESENCE_MODULES = 2`, `presence_evidence()`, `GnulibPresence.evidence_line()`; `LAYOUT_DEPENDENT_NAMES` (version_etc, hard_locale, full_write), `THIN_CALLER_MAX_CALLEES = 2`, `lto_less_layout()`. `EXPECTED_COREUTILS` yorumu GT bulgusuyla güncellendi (denetim eklenmedi).
- `karadul/stages.py` `_recover_gnulib_from_fingerprints`: üç katman (dizgi parmak izi, çağrı şekli, ayrıştırma) tek karar noktasından (`_offer`) geçer: (1) varlık kanıtı yetersizse ad yazılmaz (`gnulib_kaniti_yetersiz`); (2) üç yerleşime bağlı girdide ateşlenen fonksiyonun bütün çağıranları ince ise ad yazılmaz (`lto_yerlesimi`). Bir katmanın önerdiği anahtar (uygulansın, tutulsun) sonraki gnulib katmanlarına aday olmaz. Dizgiler, aynı taramada ikilinin bütün `.c` dizgi değişmezlerinden toplanır (yeni girdi yok); dosyalar sıralı taranır (Küçükler'deki `rglob` sırası belirsizliği). Başka adla dolu anahtar eskisi gibi ezilmez (`skipped` / `on_ad_dolu` olarak kayda geçer). İki kez çağrı idempotent (ad aynıysa yeniden yazılmaz; karar kaydı ve sayaçlar aynı).
- **Aday kaydı (K-2; biçimin gerekçesi):** `static/gnulib_candidates.json` (`karadul.gnulib_candidates`, sürüm 1): `presence` (yeterli mi, eşik, bulunan modüller ve eşleşen işaret, insan okur kanıt satırı), `layout_rule` (girdiler, eşik), `decisions` (her öneri: `key`, `name`, `channel` = `dizgi_parmak_izi` / `cagri_bicimi` / `ayristirma`, `decision` = `applied` / `withheld` / `skipped`, `reason`, `evidence`; tutulanlarda ek olarak `evidence_presence` ya da `caller_callee_counts` + `evidence_layout`), `ambiguous` (belirsiz adlar ve aday anahtarları). Neden ayrı yapıt: (i) kanalın girdisi `static/`'te ve karar static/ yapıtlarından hesaplanıyor, kayıt girdinin yanında kalıyor; (ii) `naming_map.json`'u yazan `output_formatter.py` ve c_namer bu paketin dosyası değil (P12a / P07) — rapora ve fonksiyon kartına taşınması onların işi; (iii) adlar anahtarla ve ürünün kendi verisiyle yazılıyor, GT yok; (iv) sayaçlar `stats["gnulib_evidence"]` (yeterli mi, modüller, eşik) ve `stats["gnulib_withheld"]` ile rapora da gidiyor.
- İç ad (`version_etc_arn`, `setlocale_null_r`, `safe_write`) ÜRETİLMEDİ: LTO'suz yapıda dizgiyi taşıyan fonksiyonun doğru adı gnulib sürümüne bağlı (2024 sonrası `setlocale_null_r_unlocked`), ayrı ön kayıtlı ölçüm ister. Kayıtta aday kendi dış adıyla ve yerleşim satırıyla duruyor.

### c. Yeniden say (Ghidra'sız, 119 + 12 ikili; GT)
Komut: `PYTHONPATH=<ağaç> python gnulib_yeniden.py --kok-debian urun-yeni2/debian --kok-mac urun-yeni2/mac --gt` (taban `taban_kod/`, yeni geliştirme kopyası; korpuslar `--korpus-kosu aday-f893d72 --korpus ~/karadul_olcum/corpus` ve `on-ad-onarimi-2026-11-11/ek_kosu`); özet `ozet_yeniden.py`. Çıktılar `yeniden_{taban,yeni}_{urun-yeni2,korpus,ek}.json`.

| Set | Grup | Önce doğru / yanlış | Sonra doğru / yanlış | Ön kayıt |
|---|---|---|---|---|
| geliştirme (119) | coreutils dışı 13 ikili | 2 / 5 (7 yazım) | **0 / 0** (7 aday tutuldu: `gnulib_kaniti_yetersiz`) | H1 tuttu |
| geliştirme | coreutils, yedi girdi | 620 / 0 | **620** / 0 | H2 tuttu |
| geliştirme | coreutils, üç yerleşim girdisi | 0 / 217 | 0 / **1** (216 tutuldu: `lto_yerlesimi`) | H3 tuttu (≤ 21) |
| Debian 9.4 (5, LTO'suz) | hepsi | 29 / 11 | **29 / 0** | H4 tuttu |
| Ubuntu 9.4 (5, LTO'lu) | hepsi | 36 / 0 | 35 / 0 (expr `hard_locale` tutuldu: çağıranı ince [2]) | H4b tuttu (bilinen kayıp) |
| Ubuntu 9.4 od / pr | hepsi | 14 / 1 | 14 / 1 (pr `mbslen`, kapsam dışı) | — |

- Varlık kanıtı: geliştirme setinin 106 coreutils ikilisinin 105'inde yeterli (3-6 modül; `test` 3: progname + `__fpending` + `__freading`, `version_etc` yok), `libstdbuf.so`'da 0 (zaten aday yok); coreutils dışı 13 ikilinin 13'ünde 0 modül. Korpusların 12'sinde 4-5 modül.
- Tutulan 216 yerleşim adayının çağıran çağrı sayıları: `version_etc` {1, 2} ×104, `hard_locale` {1} ×104, `full_write` {2} ×8. LTO'lu Ubuntu'da çağıranlar 12-54.
- Kalan tek yanlış: coreutils `sort`'ta `full_write` çağrı şekli (`strlen`, `write`, `_exit`, bir iç fonksiyon; çağıranlar 17 ve 19 çağrılı): gnulib `full_write` değil, `write` + `_exit` yapan bir hata yolu; yerleşim kuralının değil çağrı şeklinin yanlış pozitifi (taban kodda da yanlış). Ön kayıtta yok; kural sonradan değiştirilmedi. Öneri (sonraki paket): `full_write` şekline `_exit` dışlaması (gnulib `full-write.c` `_exit` çağırmaz), ayrı ölçümle.
- Kaybedilen doğru ad: coreutils'te 0; coreutils dışında 1 (zstd `usage`: zstd gnulib'siz, "Usage: %s" GNU / C geleneği; aday kayıtta). `usage` gnulib fonksiyonu değil (katalog notu da öyle diyor); gnulib'siz programlarda ayrı bir "gelenek" kanalı olarak ölçülebilir (öneri).
- Ad haritasına beklenen etki (119): `on_ad:gnulib` uygulanan 843 → 621 (620 doğru + `sort` 1 yanlış); kanal doğru adı 621 → 620 (zstd `usage`).
- **Ölçüm hijyeni notu:** yeni kodun ilk yeniden oynatması aday kaydını saklı koşunun `static/` dizinine yazdı: `urun-yeni2-f30ac9a`'nın 119 `static/` dizinine `gnulib_candidates.json` eklendi (13:1x). Hemen silindi (yalnız bu adla, yalnız bu koşudan sonra oluşan 119 dosya; sonrasında `find -newer` ile 0 doğrulandı); dizinlerin mtime'ı değişti, içerik eski hâlinde. Betik artık kaydı belleğe alıyor (`gnulib_yeniden.py` `YAKALANAN`); sonraki koşularda salt okur kökler 0 yeni dosya.

### Yeniden oynatmadan ürün ölçümüne öngörü (119 ikili; ürün koşusu DEĞİL)
Taban ürün ölçümü (`urun_olc.py olc`, P16a `olc_taban.json`): 2 261 ad, 1 589 doğru, 672 yanlış (%29,7). Gnulib kanalı tek başına değişirse ve tutulan anahtarlara başka kanal ad yazmazsa: 2 261 − 222 = **2 039 ad, 1 588 doğru, 451 yanlış (%22,1)**. İkinci koşul ürün koşusuyla sınanıyor (H6c, aykırı öncül 3); 119'luk ürün koşusu bu pakette yapılmadı (en çok 8 ikili).

## Gürültü tabanı (B0a ↔ B0b)
Aynı kod (097fdff), `PYTHONHASHSEED=0`, paralel 1, koşu başına ayrı `KARADUL_CACHE_DIR`; 7 geliştirme seti ikilisi (debian/tmux, mac/tmux, redis-cli, openssl, zstd, cat, expr) + gcat. B0a: `urun_kos.py --agac <worktree>` (worktree temiz; koşu sürerken `karadul/` dosyalarına dokunulmadı, geliştirme ayrı kopyada: `P-S3/gelistirme/`). B0b ve gcat: aynı kodun dondurulmuş kopyasından (`taban_kod/`, `karadul/` 337 dosyası worktree'yle sha256 düzeyinde aynı; `kopya_denetle.py`), urun_kos'un `isleri_topla` / `calistir` fonksiyonlarıyla (`kos_kopya.py`; urun_kos `--agac`'ta git istiyor, kopya git'siz).

## Kalem 2 — veri akışı belirlenimciliği

### a. Göster (önce; taban kodu, Ghidra'sız)
- `veri_akisi_kenar.py` (aynı girdiyle N koşu, kenar kümeleri ve aynı adı tanımlayan dosyalar) ve P-S2'nin `veri_akisi_tekrar.py`'si (10 tekrar):
  - htop (P-S2 A1b çalışma alanı, `reconstructed/commented`): `total_edges` 4 286 ×8, 4 273 ×2 (10 tekrar); iki farklı kenar kümesi, birbirinin alt kümesi (kesişim 4 273, birleşim 4 286). Oynayan **13 kenarın hepsi `struct_field`** ve hepsinin hedefi `thunk_FUN_10000a0f8`. Bu adı **üç dosya** tanımlıyor: `thunk_FUN_10000a0f8.c` ve `…_00009010.c` (hedef fonksiyonun tam gövdesi: `long thunk_FUN_10000a0f8(ulong *param_1, uint param_2)`, `*param_1`, `param_1[1]` okur) ve `…_000091e0.c` (`void thunk_FUN_10000a0f8(void) { FUN_10000a0f8(); }`).
  - tree (P-S2 B0a çalışma alanı): 123 ×6, 131 ×4; oynayan **8 kenarın hepsi `allocation_chain`**, hedefi `free`. 63 ad iki dosyada tanımlı (her ithal fonksiyon için PLT thunk'ı `ad.c` ve Ghidra'nın dış blok yer tutucusu `ad_00135xxx.c`). `free.c`: `free(__ptr);` (çağrıyı iletir); `free_00135198.c`: `halt_baddata();` (gövde yok, Ghidra'nın dış kayıt yer tutucusu).
- **Kaynak: yalnız sıra, iş parçacığı kaybı yok.** `analyze` dosyaları `ThreadPoolExecutor`'da çözümleyip `as_completed` (bitiş) sırasıyla `all_func_code.update` ediyordu; aynı adı tanımlayan dosyalardan SON biteni kazanıyordu. Çapraz fonksiyon kenarları (`_extract_cross_func_struct_flows`, `_extract_cross_func_alloc_chains`) çağrılanın gövdesine bakıyor: kazanan gövde gerçek gövdeyse kenarlar var, yer tutucuysa yok. Kenar listesinin birleşme sırası sayıyı değiştirmiyordu (tekilleştirme en yüksek güveni seçer); yalnız aynı ad çakışması sayıyı değiştiriyordu (oynayan kenarların 21/21'i çakışan ada varıyor, `oynak_uclar`).
- **Hangi sayı doğru:** büyük olanlar (htop 4 286, tree 131). Oynayan kenarlar gerçek veri akışını söylüyor: htop'ta çağıranlar yapı işaretçisini `thunk_FUN_10000a0f8`'e veriyor, üç thunk da aynı `FUN_10000a0f8`'e gidiyor ve o gövde alanları okuyor (`void` imzalı üçüncü dosya Ghidra'nın imzayı yaymadığı bir sarmalayıcı); tree'de ayrılan tampon `free`'ye gidiyor ve `free.c` gerçekten serbest bırakıyor; `free_00135198.c` gövdesi olmayan dış kayıt. Küçük sayılar yer tutucu gövde kazandığında çıkıyordu.

### b. Onar
- `karadul/reconstruction/engineering/data_flow.py` `analyze`: iş parçacığı sonuçları girdi sırasıyla (sıralı dosya listesi; `_collect_c_files` zaten sıralı) bir listeye yazılır, havuzdan sonra o sırayla birleşir. Aynı ad için İLK dosyanın gövdesi tutulur (`setdefault`): sıralı listede eksiz `ad.c` önce gelir (`.` < `_`) ve P16a'dan beri eksiz ad, aynı adlı fonksiyonlardan adres sırasında ilkine verilir (tree: PLT thunk'ı; dış blok yer tutucusu ekli dosyada). Hata iletileri de girdi sırasıyla. Kullanılmayan iki kilit kalktı.
- Dokunulmayan: `propagate_param_names` zaten sıralı ve iş parçacıksız; aynı adda SON dosyayı tutuyor (tutarlılık için ayrı karar; çıktısı yalnız parametre yayılımı sayaçları, bu pakette ölçülmedi).

### c. Yeniden say (Ghidra'sız; ön kayıt H7, H8)
| Girdi | Önce (10 tekrar, `veri_akisi_tekrar.py`) | Sonra (10 tekrar) | Kenar kümesi |
|---|---|---|---|
| htop (P-S2 A1b `commented`) | 4 286 ×8, 4 273 ×2 | **4 286 ×10** | eski 4 286 kümesiyle güvenler dahil aynı (sha `a4fdaecb…`) |
| tree (P-S2 B0a `commented`) | 123 ×6, 131 ×4 | **131 ×10** | eski 131 kümesiyle aynı (sha `76140737…`) |

- H7 tuttu (tek değer), H8 tuttu (htop 4 286; tree eski değerlerden biri, 131).

## Kalem 3 — temizlik (davranış değişmez)
- Taban pyflakes (`python -m pyflakes karadul/stages.py`, 097fdff): `copy` içe aktarımı kullanılmıyor (s.10), `TargetDetector` içe aktarımı kullanılmıyor (s.21; depoda `karadul.stages.TargetDetector`'a atıf ya da yama yok — `grep`), `DynamicAnalysisStage.execute`'ta `dynamic_dir` yereli atanıp okunmuyor, `_execute_binary`'de `deob_dir` yereli atanıp okunmuyor (P-S2 kalem 3 listesi).
- `dynamic_dir = context.workspace.get_stage_dir("dynamic")` satırının tek yan etkisi `dynamic/` dizinini oluşturmak; hemen ardından gelen `context.workspace.save_json("dynamic", …)` aynı `get_stage_dir("dynamic")`'i çağırıp dizini oluşturuyor (`workspace.py` `save_artifact`), bu yüzden satırın kalkması diskte bir şey değiştirmez. `deob_dir` yereli salt sözlük okuması.
- **SİLİNMEDİ (istem gereği):** `_collect_all_algorithms` ve ikinci `_seed_recovery_pre_names` çağrısı (Berke onayı / P13a).
- Doğrulama: pyflakes temiz; AST karşılaştırması (19bc7fa ↔ 2415625): yalnız bu dört düğüm (`import copy`, `TargetDetector` adı, `dynamic_dir` ve `deob_dir` atamaları) çıkarılınca modül AST'si birebir aynı; `stages` / `DynamicAnalysisStage` anan testler 1 144 geçti / 0 kaldı. Commit **2415625**.


## Testler ve mutasyon (kalem 1-2)
- `tests/test_ps3_gnulib_kanit.py` (15): varlık kanıtı (gnulib'siz ikilide `close_stdout` / `full_write` yok + aday kaydı; gnulib'li ikilide ad; tek modül yetmez; genel dizgiler sayılmaz; çağrı işaretleri sayılır; ikinci çağrı aynı), LTO yerleşimi (ince çağıranlarda yok; geniş çağıranda var; biri geniş yeter; çağıransız eski davranış; tutulan aday başka gnulib adı almaz; kural yalnız üç girdiye), saf fonksiyonlar ve işaretlerin upstream kaynakta birebir geçtiği. **Eski kodda 11 kırmızı**; kalan 4 aşırı tutmaya karşı bekçi (eski ve yeni kodda aynı davranış).
- `tests/test_main_gnulib_seed_ordering.py`: gnulib adı bekleyen 3 test gnulib'li ikili düzenine uyarlandı (`_gnulib_varlik`: progname + version-etc işaretli adlı fonksiyonlar; test silinmedi, beklenti değişmedi).
- `tests/test_ps3_veri_akisi.py` (3): bitiş sırası `as_completed` yamasıyla iki uca zorlanır; iki koşu aynı kenar kümesi, eksiz dosyanın gövdesinden çıkan kenar var, hata iletileri girdi sırasıyla. **Eski kodda 3/3 kırmızı.**
- İlgili test dosyaları (stages / gnulib / köken / ön ad anan 1 730 test) kalem 1'le geçti.
- **Mutasyon** `scripts/measurement/mutation_specs_ps3.json`: **17/17 öldü** (kalem 1: 14 — varlık kapısı kalkar, eşik 1, her işaret bulunur, çağrı işareti sayılmaz, işaret kaynakta yok, yerleşim kuralı kalkar, ince eşiği 99, `all`→`any`, çağıransız tutulur, kural her girdiye, tutulan aday yeniden aday, başka ön ad ezilir, tutulan 'applied' yazılır, aday kaydı yazılmaz; kalem 2: 3 — son gövde kazanır, ters sıra, bitiş sırası). Mutant metinlerinin uzunluğu özgününden farklı (`mutant_denetle.py`); koşum sonrası `karadul/` dondurulmuş A kopyasıyla sha256 düzeyinde aynı.

## Ürün koşusu (8 ikili; ön kayıt H5, H6)
Koşular: **B0a** (097fdff, worktree, `urun_kos.py`), **B0b** (097fdff, dondurulmuş `taban_kod/`), **A** (yeni kod: dondurulmuş `yeni_kod/`; `karadul/` 337 dosyası **19bc7fa**'nın `git archive`'ıyla sha256 düzeyinde aynı). Hepsi `PYTHONHASHSEED=0`, paralel 1, koşu başına önbellek. A, B0b ile **eşzamanlı** koştu (B0a tek başına): makine yükü iki kolda farklı; gürültü B0a ↔ B0b'de ölçüldü. Süreler (A): zstd 518, openssl 447, tmux 697, Mac tmux 867, redis-cli 262, cat 52, expr 55, gcat 88 sn.

### Ad ölçüsü, geliştirme setinin 7 ikilisi (`urun_olc.py olc` + `karsilastir --eksik-izinli`, B0a ↔ A; `fark_B0a_A.md`)
| Birim | B0a: ad / doğru / yanlış | A: ad / doğru / yanlış | Giderilen yanlış | Kaybedilen doğru | Yeni yanlış |
|---|---|---|---|---|---|
| debian/coreutils (cat, expr) | 26 / 21 / 5 | 21 / **21** / **0** | 5 (`version_etc` ×2, `hard_locale` ×2, `full_write`) | 0 | 0 |
| debian/openssl | 35 / 24 / 11 | 34 / 24 / 10 | 1 (`full_write`) | 0 | 0 |
| debian/redis-tools (redis-cli) | 7 / 3 / 4 | 6 / 3 / 3 | 1 (`full_write`) | 0 | 0 |
| debian/tmux | 295 / 148 / 147 | 294 / 148 / 146 | 1 (`close_stdout`) | 0 | 0 |
| debian/zstd | 65 / 9 / 56 | 63 / 8 / 55 | 1 (`close_stdout`) | 1 (`usage`) | 0 |
| mac/tmux | 395 / 205 / 190 | 394 / 205 / 189 | 1 (`close_stdout`) | 0 | 0 |
| **Toplam** | 823 / 410 / 413 | **812 / 409 / 403** | **10** | **1** | **0** |

- **H6a tuttu:** `on_ad:gnulib` uygulanan ad debian/tmux, mac/tmux, redis-cli, openssl, zstd'de 5 → **0** (`out/naming_map.json`).
- **H6b tuttu:** cat + expr'de gnulib kanalının doğru adı 21 → 21; yanlış 5 → 0.
- **Aykırı öncül 3 çürütüldü:** tutulan 11 anahtarın hiçbirine başka kanal ad yazmadı (`out/naming_map.json`'da anahtar yok: FUN_ kalıyor); yeni yanlış 0. Tabanın köken kaydında bu anahtarların ikincil adayları ürün eşiğinin (0,7) altında (ör. cat `full_write` ↔ `write_fd_6b40` 0,45, `hard_locale` ↔ `set_locale` 0,6, `version_etc` ↔ `calls_fputc_unlocked` 0,4).
- Kesin etiketli adlar değişmedi (262 / 249). Makro yanlış oranı %46,4 → %41,4.
- **Sağlamlık denetimi** (`saglamlik_denetle.py`, 7 ikili, B0a ↔ A): yalnız `eski_fonksiyon_adi_yorumda_kalan` 724 → 713 (−11 = tutulan 11 ad; yeniden adlanmayan fonksiyonun eski adı yorumda kalmıyor); öbür bütün kusur türleri aynı (`baslik_tanim_farkli` 3, `fonksiyon_anahtari_ghidrada_yok` 12, `yerel_son_tur_baska_adla_fonksiyon` 2 585 …). Not: `kos_kopya.py` künyesi urun_kos biçimine `kunye_uyumla.py` ile uyumlandı (denetim `agac` sözlüğü bekliyor).

### Mach-O gnulib doğrulama ikilisi gcat (H5) — **TUTMADI**
- A'da varlık kanıtı **yetersiz: 1 / 2 modül** (yalnız version-etc: "General help using GNU software"); kanal ad yazmadı, 3 aday tutuldu (`gcat_hukum.py`, GT `macho_f1`): `usage` (**GT'ye göre doğru**), `version_etc` (yanlış: ateşlendiği fonksiyon `version_etc_arn`; LTO'suz yerleşim), `close_stdout` (yanlış). Taban kod bu üçünü yazıyordu (1 doğru / 2 yanlış; B0a / B0b gcat aşağıda).
- **Neden:** (i) progname işareti ("A NULL argv[0] was passed through an exec system call") coreutils 9.12'nin gnulib'inde YOK (ikilinin `strings` çıktısında da yok; `set_program_name` var) — işaret 2023 gnulib'inden seçilmişti, sürüme bağlı çıktı; (ii) çağrı işaretleri (`__fpending`, `__freading`) glibc'ye özgü: macOS'ta gnulib bunları kendisi tanımlıyor (gcat `nm`: `___fpending` T, `_freading` T), soyulmuş ikilide adsız FUN_ oluyorlar. Aykırı öncül 1 ("işaretler gnulib'li başka bir yapıda bulunmaz, kanal gereksiz yere susar") **doğrulandı**.
- **Süreç sapması:** kalem 1 commit'i (0a49fba) Ghidra'sız ölçümler (H1–H4 tuttu) bittikten sonra ama H5 sonucu gelmeden atıldı; ön kayıt "H5 tutmazsa kural commit'lenmeden önce yeniden düşünülür" diyordu. Kural sonradan değiştirilmedi (ön kayıt gereği eşik / işaret listesi aynı kaldı). Değerlendirme: commit'lenen kural gcat'te 2 yanlışı 1 doğruyla birlikte kaldırıyor (kesinlik %33 → ad yok); geliştirme setinde ve dört GT'li korpusta doğru ad kaybı yok (zstd `usage` gnulib'siz). Yani kural güvenli tarafta, ama K-2'nin "gnulib'li ikilide doğru adları üretmeye devam eder" koşulunu gnulib 2024+ / Mach-O'da karşılamıyor.
- **Öneri (yeni ön kayıt gerekir, bu pakette uygulanmadı):** sürüm ve platformdan bağımsız işaretler. gcat'te bulunan gnulib'e özgü metinler: version-etc'nin birden çok ayrı fonksiyonu ("Written by %s, %s, and %s." version_etc_arn; "General help using GNU software" emit_bug_reporting_address — bugün tek modül sayılıyor), getopt.c (macOS'ta gnulib getopt'u derlenir: "%s: unrecognized option '%s%s'", "%s: option '%s%s' doesn't allow an argument"; glibc'li Linux'ta bu metinler ikilide değil libc'de), error.c ("Unknown system error"). Taze doğrulama: geliştirme seti dışından gnulib'li Mach-O GNU programları (Homebrew m4 1.4.21, gettext 1.0 araçları, coreutils'in başka ikilileri) ve gnulib'siz masum Mach-O'lar; bu pakette ürün koşusu bütçesi (8 ikili) doldu.
- gcat taban (B0a ve B0b, aynı): `on_ad:gnulib` 3 ad — `usage` doğru, `version_etc` ve `close_stdout` yanlış (`ad_karsilastir.py`). A: 0 ad, 3 aday kayıtta.

### Gürültü tabanı sonucu (B0a ↔ B0b, `karsilastir.py` → `gurultu_B0a_B0b.json`; `ad_karsilastir.py` → `ad_karsilastir.json`)
| İkili | `out/` gerçek fark (oynak alan dışı) | Ad haritası farkı |
|---|---|---|
| debian/tmux | `report.json` / `report.html`: `data_flow_edges` 83 813 ↔ 83 821 | 0 |
| debian/redis-cli | `report.html` / `algorithms.md`: algoritma satırlarının sırası (TLS read ↔ write) | 0 |
| debian/openssl | `report.html`, `algorithms.md`, `xref_index.md` ve 4 `.c` dosyasının "Callers:" yorumunda liste sırası | 0 |
| macgnu/gcat | `bsim_shadow_functions` 0 ↔ 61, `bsim_shadow_total` 0 ↔ 249 (BSim gölge kipi; ad kanalına bağlı değil) | 0 |
| mac/tmux, zstd, cat, expr | 0 | 0 |

- 8/8 ikilide ad haritası (`out/naming_map.json`) iki taban koşusunda aynı (gürültü anahtarı 0).

### A ↔ B0a (H6c, H6d; `fark_B0a_A_cikti.json`, `ad_karsilastir.json`)
- **H6c tuttu:** değişen genel ad anahtarı 14 (tmux 1, Mac tmux 1, redis-cli 1, openssl 1, zstd 2, cat 3, expr 2, gcat 3); 14'ünün de tabanda kanalı `on_ad:gnulib` ve A'da adı yok; başka değişen anahtar **0**. `.c` metnindeki farklar yalnız bu anahtarların adının FUN_ olarak kalması (ör. `bufferevent_new(…, FUN_00143ecc, …)`, cat `FUN_00106fa8` içinde `FUN_00106bc0()`), ve gürültüdeki gibi liste sıraları.
- **H6d tuttu:** `static/gnulib_candidates.json` 8/8 koşuda var; tutulan adaylar tabandaki gnulib adlarıyla anahtar ve ad olarak aynı, `taban − (tutulan + uygulanan) = ∅` (8/8).
- GT (gnulib kanalı, 8 ikili): taban 13 doğru / 12 yanlış → A **11 doğru / 0 yanlış**; kaybedilen doğru 2 (zstd `usage`, gcat `usage`).
- Rapor sayaçları: yeni `gnulib_evidence` (sözlük) ve `gnulib_withheld`; `gnulib_recovered` / `gnulib_callshape_recovered` / `name_merger_*` tutulan ad kadar azaldı. `enums_recovered` cat 6 → 5, expr 4 → 3, gcat 1 → 0; üçünde de `reconstructed/typed/types.h` B0a ile bayt bayt aynı (fark yalnız sayaçta: switch / karşılaştırma desenlerinden sentezlenen enum adayı, değişen yerel adlarla anahtarlanıyor; koda giren bir şey değişmedi).

### Veri akışı tüketicileri (H9)
| İkili | `data_flow_edges` B0a / B0b / A | `data_flow_pipelines` | `compositions` |
|---|---|---|---|
| debian/tmux | 83 813 / 83 821 / **83 821** | 257 / 257 / 257 | 0 / 0 / 0 |
| debian/redis-cli | 6 710 / 6 710 / **6 721** | 59 / 59 / 59 | 8 / 8 / 8 |
| debian/zstd | 16 374 / 16 374 / **16 437** | 52 / 52 / **51** | 0 / 0 / 0 |
| mac/tmux, openssl, cat, expr, gcat | aynı (75 273; 2 783; 42; 80; 78) | aynı | aynı (0; 35; 0; 0; 0) |

- **Kaynak ayrımı** (Ghidra'sız, ürünün girdisiyle: `reconstructed/annotated`, `veri_akisi_kenar.py`, 4 tekrar, taban kodu ↔ yeni kod, B0a ↔ A girdisi): zstd taban kodla 16 374 ↔ 16 437 oynuyor (63 kenar; iki girdide de), yeni kodla iki girdide de 16 437; redis-cli taban 6 710, yeni 6 721 (iki girdide); tmux taban 83 813 ↔ 83 821, yeni 83 821 (iki girdide). Yani A'daki veri akışı farkları **kalem 2'den** (belirlenimci birleştirme, büyük değer); kalem 1'in ad değişiklikleri kenar sayısını değiştirmiyor (aynı kod, B0a ↔ A girdisi aynı sayı). Bileşim çözümleyicisi (`compositions`) 8/8 aynı; zstd'de boru hattı sayısı 52 → 51 (kenar kümesi değişince). **H9 tuttu** (fark açıklandı).

## Ön kayıt hükümleri
| # | Hüküm | Not |
|---|---|---|
| H1 | tuttu | coreutils dışı 13 ikilide gnulib yazımı 7 → 0 |
| H2 | tuttu | coreutils doğru 620 → 620 |
| H3 | tuttu | coreutils yanlış 217 → 1 (≤ 21); kalan `sort` `full_write` çağrı şekli yanlış pozitifi |
| H4 | tuttu | Debian 9.4 yanlış 11 → 0, doğru 29 → 29 |
| H4b | tuttu | Ubuntu 9.4 + od/pr üç girdinin doğrusu 14 → 13 (bilinen expr kaybı) |
| H5 | **TUTMADI** | gcat'te varlık kanıtı 1 / 2 modül; kanal ad yazmadı (taban 1 doğru / 2 yanlış) |
| H6a | tuttu | 5 → 0 |
| H6b | tuttu | cat + expr doğru 21 → 21 (yanlış 5 → 0) |
| H6c | tuttu | başka değişen anahtar 0 |
| H6d | tuttu | 8/8 aday kaydı, kümeler tutarlı |
| H7 | tuttu | 10 tekrarda tek değer (htop, tree) |
| H8 | tuttu | htop 4 286, tree 131 |
| H9 | tuttu | tüketici farkları kalem 2'ye bağlandı; bileşim sayısı aynı |
| Aykırı öncül 1 | **doğrulandı** | işaretler gnulib 2024+ / Mach-O'da yetmiyor (H5) |
| Aykırı öncül 2 | çürütüldü | ince çağıran kuralı 9.7'de 216/217 yanlışı ayırdı |
| Aykırı öncül 3 | çürütüldü | tutulan anahtarlara başka ad yazılmadı |

## Tam takım
`PYTHONDONTWRITEBYTECODE=1 python -m pytest -q -p no:cacheprovider` (worktree, 2415625; çalışma zamanı verisi symlink'li; ürün koşularıyla eşzamanlı): **9 394 geçti, 10 atlandı, 153 seçim dışı, 0 kaldı** (488 sn).

## Ana oturumun bilmesi gerekenler
1. **H5 tutmadı ve kalem 1 H5'ten önce commit'lendi** (süreç sapması; yukarıda). Kural güvenli tarafta (gnulib'siz programda ve LTO'suz yerleşimde yanlış ad yok; geliştirme seti ve dört GT'li korpusta doğru ad kaybı 0, zstd `usage` hariç), ama gnulib 2024+ / Mach-O'da (Homebrew coreutils 9.12) varlığı tanımıyor: gcat'te 1 doğru ad (`usage`) da 2 yanlışla birlikte düştü. Öneri: sürümden ve platformdan bağımsız işaret listesi (getopt.c metinleri, version-etc'nin ayrı fonksiyonları, error.c) **yeni ön kayıtla** ve geliştirme seti dışı taze Mach-O gnulib programlarıyla (m4, gettext araçları) ölçülsün; bu pakette 8 ikililik ürün koşusu bütçesi doldu.
2. **Aday kaydı yalnız `static/gnulib_candidates.json`'da.** Rapora ya da `naming_map.json` `candidates`'ına taşınması (fonksiyon kartı) `output_formatter.py` / c_namer işi (P07 / P12a); bu paketin dosyası değil. Kayıtta tutulan her adayın kanıt satırı ve nedeni var.
3. **Kaybedilen doğru adlar:** zstd `usage` (gnulib'siz program; "Usage: %s" C / GNU geleneği) ve gcat `usage`. `usage` gnulib fonksiyonu değil; gelenek kanalı olarak ayrı ön kayıtla ölçülebilir.
4. **Kalan yanlış:** coreutils `sort`'ta `full_write` çağrı şekli (`write` + `_exit`); öneri `_exit` dışlaması (gnulib `full-write.c` `_exit` çağırmaz), ayrı ölçümle.
5. **İç adlar** (`version_etc_arn`, `setlocale_null_r`, `safe_write`): LTO'suz yapıda tutulan 216 adayın (geliştirme seti) "yakın ve doğru" adı bunlar olabilir (K-2); sürüme bağlı (`setlocale_null_r_unlocked`), ön kayıtlı ölçüm ister. Bugün üretilmiyor.
6. **Veri akışında tutarlılık:** `analyze` aynı adda İLK dosyanın gövdesini, `propagate_param_names` (dokunulmadı) SON dosyanınkini tutuyor. Aynı adlı thunk / dış kayıt fonksiyonlarının adla anahtarlanması kalıcı bir sınır (adres ile anahtarlanmalı); ayrı iş.
7. **Ölçüm hijyeni:** yeniden oynatma betiğinin ilk yeni kod koşusu `urun-yeni2-f30ac9a`'nın 119 `static/` dizinine `gnulib_candidates.json` yazdı; hemen silindi (yalnız bu 119 yeni dosya), dizin mtime'ları değişti, içerik eski hâlinde. Betik düzeltildi.
8. A koşusu B0b ile eşzamanlı koştu (B0a tek başına); ad haritasında gürültü 0 olduğu için kararları etkilemedi.
9. Ölçüm betikleri depo dışında: `~/karadul_olcum/runs/onarim-2026-11-18/P-S3/` (`gnulib_yeniden.py`, `ozellik_dok.py`, `ozet_yeniden.py`, `veri_akisi_kenar.py`, `kos_kopya.py`, `kos_gcat.sh`, `ad_karsilastir.py`, `gcat_hukum.py`, `karsilastir.py`, `kopya_denetle.py`, `mutant_denetle.py`, `kunye_uyumla.py`); dondurulmuş ağaçlar `taban_kod/` (097fdff), `yeni_kod/` (19bc7fa), `gelistirme/` (geliştirme kopyası; silinebilir, onaya bağlı); Mach-O doğrulama ikilisi `mac_gnulib/` (Homebrew gcat'in kopyası ve `/usr/bin/strip`'li hâli + GT).
10. `~/.claude/team-state/discussion.md`'ye yazılmadı (istem `~/.claude/**` yazmayı yasaklıyor).

## PAKET BİTTİ
