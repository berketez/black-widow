# P-S3 — `stages.py` 3. tur: gnulib ön ad kanalı kanıta bağlanır (AD-03, B-A3) + veri akışı belirlenimciliği — ilerleme

Brif: `ONARIM_BRIF.md`. Karar: K-2 (Berke: "amacımız isim üretmek; düzelt, yakın ve doğru isim üretmek, hesaplama ile"). Bulgular: AD-03 ve B-A3 (`docs/arge/2026-11-18_genel_tarama/kulvar_AD.md`), P-S2 bulgusu `data_flow_edges` (`P-S2.md` § Kalem 2). Ön kayıt: `P-S3_on_kayit.md` (**c4eab8b**, kod değişmeden önce).

- Taban: worktree `origin/main`'den (e9d2d08) açıldı; `git merge --ff-only main` → **097fdff** (yerel `main` ucu).
- `karadul.__file__` worktree yolunu gösteriyor. Çalışma zamanı verisi symlink (`sigs`, `vendor`, `signatures_homebrew*.json`, `sigs_macos_system.json`, `scripts/node_modules`; commit'lenmez).
- Ölçüm kökü: `~/karadul_olcum/runs/onarim-2026-11-18/P-S3/` (betikler ve çıktılar orada; aşağıda adlarıyla).

| Kalem | Durum | Commit |
|---|---|---|
| 0 — ön kayıt | bitti | c4eab8b |
| 1 — AD-03 / B-A3: gnulib kanalı kanıta bağlı | kod bitti; ürün koşusu (8 ikili) sürüyor | 0a49fba |
| 2 — veri akışı belirlenimciliği | kod bitti; ürün koşusunda tüketici denetimi sürüyor | 19bc7fa |
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
