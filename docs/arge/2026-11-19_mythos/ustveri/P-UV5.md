# P-ÜV5 — Mach-O `main` (`LC_MAIN` girişi) (ilerleme)

Gönderim metni: `docs/arge/2026-11-23_dalga1/gonderim/PUV5.md`. Ajan: Opus 5.5. Başlangıç 2026-11-23 19:36 (taban main `0b4d948`, `git merge --ff-only main` ile). Sert son 21:25.

Koşu kökü: `~/karadul_olcum/runs/dalga1-2026-11-23/PUV5/` (ölçüm özetleri `ozet/`).

## Durum

| Kalem | Durum | Commit |
|---|---|---|
| 1 ön kayıt | bitti | `bdd058f` |
| 2 kod + birim testleri + mutasyon | bitti: 32 test, 15 / 15 mutant öldü | `a731db6`, `caa14e3` |
| 3 Ghidra'sız yeniden oynatma (Mac 8, ELF 5, hedef seti) | bitti (aşağıda) | bu commit |
| 4 ürün koşusu (kuyruk) | bayrak açık 8 Mach-O kuyrukta (19:54'te başlatıldı) | — |
| 5 tam takım (yamasız) | başlamadı | — |

**Şu an bekleniyor (19:55):** bayrak açık ürün koşusu, 8 Mach-O (htop, tmux, gmktemp, idn2, gettext, envsubst, xz, gsort), ikili başına ayrı kuyruk çağrısı (`kos.sh acik …`, kök `PUV5/urun/acik`). Kuyruğun bir yuvası ana oturumun Ollama koşusunda; öbür yuva OL2 ile paylaşılıyor. TAHMİN bitiş 20:20–20:45 (P-S3b'de bu altı ikili 29–174 sn sürmüştü; yük altında, sıra beklemesi dahil). Beklerken yeniden oynatma ve belge.

## Kalem 2 — kod (`karadul/stages.py`)

- `_recover_main_from_entry(…, config=None)`: ELF kalıbı (`__libc_start_main(FUN_…`) önce, değişmeden. Kalıp bulunamazsa ve `_macho_entry_main_enabled(config)` (yalnız gerçek `True`) → `_recover_macho_entry_main`.
- `_recover_macho_entry_main`: `static/load_commands.txt` yoksa sessiz döner (Mach-O değil; kayıt da yazılmaz). Sonra sırayla: tek `LC_MAIN` `entryoff` (yoksa `lc_unixthread` / `lc_main_yok`; birden çoksa `lc_main_belirsiz`); `__TEXT` `vmaddr` ve Ghidra görüntü tabanı (`taban_okunamadi`); P-ÜV0 görüntüsü Mach-O (`ikili_okunamadi`) ve `MH_EXECUTE` (`mh_execute_degil`); `load_ghidra_index` (içe aktarıldı) + `delta = image_base − __TEXT vmaddr`; girişte Ghidra fonksiyonu (`ghidra_fonksiyonu_yok`), jenerik ad (`kesin.is_generic_name`: `entry` / `FUN_…`; değilse `ghidra_adli`), `<ad>.c` decompile çıktısında (`kodda_yok`); Go istisnası (`_go_entry_block`, ürünün `go_pclntab.oku`'su: `veri_yok` → engel yok; `calisti` → girişi kapsayan kaydın adı `main.main` değilse `go_giris_main_main_degil`, kapsayan yoksa `go_giris_pclntab_disinda`; başka durum → `go_okunamadi:<durum>`). Geçerse `extracted_names[<Ghidra adı>] = "main"`, `stats["main_recovered"]`; neden / kanıt `stats["macho_entry_main"]` (`durum`, `neden`, `giris`, `ghidra_adi`, `go_adi`, `kanit`).
- Künye: tohum sırasındaki `mark_changed(…, KIND_MAIN)` aynen → `main_giris` (kanal `on_ad:main_giris`); `üst veriden` kullanılmadı (gönderim hüküm 3).
- İkili görüntüsü: `static/universal_slice.json`'un seçtiği `raw/<ad>_<mimari>`, yoksa `raw/<ad>`, yoksa `target_info.path`; evrensel dosyada `goruntu.urun_dilimi`.

### Kapsam sapması (1; gerekçeli)

Gönderim "`stages.py`'de yalnız `_recover_main_from_entry` ve yardımcıları; başka yöntemler değişmez" diyor. `_recover_main_from_entry` ayar nesnesine erişemiyor (imzası `extracted_names, static_dir, stats`; `ReconstructionStage`'de `self.config` yok; aşamanın ayarı yalnız `_seed_recovery_pre_names`'in aldığı `context`'te). Bayrağı okumak için `_seed_recovery_pre_names`'teki iki çağrıya `getattr(context, "config", None)` argümanı eklendi (iki satır; mantık değişmedi). Bu olmadan bayrak üründe hiç okunamaz ve ürün koşusu (H1) yapılamazdı. Bu akşam `stages.py`'ye başka paket dokunmuyor (ORTAK_D1 §5 tablosu). Mutant `puv5_ayar_iletilmez` bu iletimi kilitler. Ana oturum istemezse geri alınabilir: o zaman kural yalnız birim düzeyinde kalır.

### Testler ve mutasyon

- `tests/test_puv5_macho_main.py`: 24 test fonksiyonu, parametrelerle 32 koşu (Mach-O + `LC_MAIN`; bayrak kapalı ×5 biçim; `LC_UNIXTHREAD`; ELF kalıbı önce; ELF biçimli görüntü; `load_commands.txt` yok; Go iç bağlayıcı `_rt0_arm64_darwin`; Go dış bağlayıcı `main` saplaması; Go `main.main`; Go okunamaz ×3; Go tablosu girişi kapsamaz; sembol adlı giriş ×3; `FUN_` adlı giriş; görüntü tabanı farkı; thunk; `MH_DYLIB`; ikili açılamaz; çoklu `LC_MAIN`; kodda tanım yok; girişte fonksiyon yok; önceki ad ezilir + ikinci çağrı; tohum künyesi `main_giris`; `otool -l` ayrıştırıcı; dilim seçimi).
- `scripts/measurement/mutation_specs_puv5.json`: **15 / 15 öldü** (günlük `PUV5/mutasyon.log`); sonrasında `git diff` temiz.
- İlgili 11 test dosyası: 427 geçti, 8 atlandı; tek kırmızı beklenen `test_p15a_etkisiz::test_inert_registry_is_accurate` ("kayıtta ama okunuyor: `binary_reconstruction.enable_macho_entry_main`", `karadul/stages.py`). (Worktree'de `vendor` bağı yokken iki P-S3b testi `vendor/gnulib-ref` bulamadı; bağ kurulunca geçti.)

### Yama

`docs/arge/2026-11-23_dalga1/yamalar/PUV5__config.py.patch`: INERT satırı (ve grup yorumu `# P-ÜV5 (Dalga 1)`) silinir; alan yorumu `okuyan: stages.py _recover_main_from_entry (P-ÜV5)`. `git apply --check` temiz; ağaca uygulanmadı (A-34).

## Kalem 3 — Ghidra'sız yeniden oynatma (19:57–19:58; yük altında)

Betik `PUV5/oynat.py` (koşu kökünde; ürün kodunu dalın ağacından yükler, `karadul.__file__` denetimli). Var olan çalışma alanlarının `static/` + `raw/` dizinleri `PUV5/oynat/<birim>/`'e kopyalandı (asıllar salt okundu; gnulib adımı `static/`'e yazdığı için). Tohum sırasının tamamı (`_seed_recovery_pre_names`: main → KS-1 → gnulib / `usage` → ELF önyük → elle), dört kol: **eski** (main `0b4d948`'in `stages.py`'si), **kapali** (dal, bayrak kapalı), **acik** (dal, bayrak açık), **yamali** (dal + `_main_caller` yaması, aşağıda). Karşılaştırılan: ad sözlüğü, künye, `stats`, yazılan `gnulib_candidates.json`. Çıktı `PUV5/ozet/oynat.json` (sayı / adres; GT adı yok).

| Birim | eski = kapali (H2) | açık ↔ kapalı değişen | Giriş (Ghidra) | GT `_main` adresi | `main` doğru | Nüfusta | Künye |
|---|---|---|---|---|---|---|---|
| mac/htop (a62f15e) | 4 / 4 alan aynı | yalnız `entry` | 0x100001780 (4 bayt thunk) | aynı | evet | hayır (thunk) | `main_giris` |
| mac/tmux (a62f15e) | aynı | yalnız `entry` | 0x100075f44 | aynı | evet | evet | `main_giris` |
| mac/tmux (S8 tabanı b6aceb9) | aynı | yalnız `entry` | 0x100075f44 | aynı | evet | evet | `main_giris` |
| mac/envsubst | aynı | yalnız `entry` | 0x100001b80 | aynı | evet | evet | `main_giris` |
| mac/gettext | aynı | yalnız `entry` | 0x100001b80 | aynı | evet | evet | `main_giris` |
| mac/gmktemp | aynı | yalnız `entry` | 0x100000ea8 | aynı | evet | evet | `main_giris` |
| mac/gsort | aynı | yalnız `entry` | 0x1000014b4 | aynı | evet | evet | `main_giris` |
| mac/idn2 | aynı | yalnız `entry` | 0x1000016c8 | aynı | evet | evet | `main_giris` |
| mac/xz | aynı | yalnız `entry` | 0x1000047ec | aynı | evet | evet | `main_giris` |
| elf/cat, expr, ls, tree, pzstd | aynı (5 / 5) | **0** (5 / 5) | — (ELF kalıbı `FUN_…` = `main`, değişmedi) | — | — | — | `main_giris` (eskisi gibi) |

- **H1 (kural düzeyi): 8 / 8** girişe `main`, 8 / 8 GT'ye göre doğru; yanlış `main` **0** (kollarda başka hiçbir anahtar `main` almadı).
- **H2 (kural düzeyi): 14 / 14** çalışma alanında (Mac 9 + ELF 5) bayrak kapalı dal = main'in kodu: ad sözlüğü, künye, `stats`, gnulib karar dosyası aynı.
- **H3 (kural düzeyi): 5 / 5** ELF'te bayrak açık ↔ kapalı değişen ad 0 (`stats`'ta yeni alan da yok; Mach-O kuralı `load_commands.txt` yoksa sessiz döner).
- **H5:** `usage_gelenegi` kararı dört kolda da **0** (Mac 9 + ELF 5). Neden: htop ve tmux'ta `Usage: %s` parmak izi adayı yok; GNU ikililerinde (gsort vb.) `usage` gnulib varlık kanıtı yeterli olduğu için olağan yoldan yazılıyor (`main`'den bağımsız; eski = açık). Yeni ad 0, yanlış 0; H5'in "yanlış 0" kısmı boş kümede tutuyor, sayı 0 (ilk ölçüm).
  - Ön kayıttaki öngörü (`_main_caller` `FUN_` anahtarı arıyor; Mach-O'da `main`'in anahtarı `entry`) koddan doğru; ama bu sekiz ikilide etkisi yok: yamalı kol (`_main_caller` çağıranın Ghidra adını da tanır; kaynak `PUV5/yamali/stages_yamali.py`) da 0. Bu yüzden `_main_caller` için yama **bırakılmadı** (ölçülmüş faydası yok); P-ÜV6b / P-ÜV9 kalem 7'ye not.
- **H6 (kural düzeyi):** htop'ta giriş thunk → nüfusta değil; öbür 7 ikilide giriş nüfusta ve `main` doğru → doğru ad kapsamı her birinde +1 (TUTTU, kural düzeyinde; ürün düzeyi kalem 4'te).

### Hedef seti ve H4 (`PUV5/hedef.py`, çıktı `ozet/hedef.json`)

| İkili | Girişte Ghidra adı | `pclntab` adı (girişte) | Kural | Hüküm |
|---|---|---|---|---|
| terminal-notifier 3.1.0 (PUV6a `urun/acik2` çalışma alanı) | `entry` (0x100000d60, 128 bayt) | Go yok (`veri_yok`) | `entry` → `main` | sembollü kopyada `_main` = 0x100000d60: **doğru** |
| Ollama arm64 (gösteri çalışma alanı) | `entry` (0x100081fb0) | `main` (Go dış bağlayıcı saplaması) | yazmaz (`go_giris_main_main_degil`) | gönderim hüküm 2; geliştiricinin `main.main`'i PUV6a Go kanalında `main_main` |
| gh 2.105.0 (H4; Ghidra yok, yalnız ikili okundu) | — | `_rt0_arm64_darwin` (0x100089440) | yazmaz (birim testi `test_go_ic_baglayici_girisi_main_yazilmaz`) | **H4 TUTTU** |

Hedef setinde ad bekleyen 40'lık terminal-notifier nüfusuna (HEDEF tanımı) etkisi ürün koşusunda ölçülmedi (terminal-notifier ürün koşusu bu paketin kuyruk sırasında yok); kural düzeyinde +1 doğru ad (`main`).

## Kalem 4 — ürün koşusu (kuyruk; yük altında)

Ürün ağacı `~/karadul_olcum/urun-caa14e3` (dalın `caa14e3` commit'i; altı çalışma verisi bağı; `agac_kunyesi` kirli 0). Komut `ustveri_urun.py kos` (`urun_kos.calistir` + `--config`), ikili başına ayrı kuyruk çağrısı (`PUV5/kos.sh`); bayrak yaml'ı `PUV5/bayraklar_acik.yaml` (yalnız `enable_macho_entry_main: true`; yamasız dalda "etkisiz" uyarısı basılır ama değer okunur — `stats` bunu gösteriyor). Ölçüm `PUV5/urun_olc_puv5.py` (c_namer'ın son haritası + köken kaydı, `out/naming_map.json`, `out/src` kodu, `pipeline_result.json`; GT ve nüfus `ks1_olc.gt_mac` kuralı). Çıktı `PUV5/ozet/urun_*.json`.

### Bayrak açık, 8 Mach-O (19:54–20:07; süre koşu künyesinden, 26,9–267,2 sn, yük 6,9–16,8) → H1 ürün düzeyi

| İkili | Süre (sn) | c_namer haritası `entry` → `main` | GT'ye göre | Nüfusta | Künye / etiket / güven | `out/src`'de `main(` tanımı | `out/naming_map.json`'da | `stats.macho_entry_main` |
|---|---|---|---|---|---|---|---|---|
| htop | 70,8 | evet | doğru | hayır (thunk) | `main_giris` / doğrulanmadı / 0,966 | 1 | **yok** | `yazildi` |
| tmux | 267,2 | evet | doğru | evet | aynı | 1 | yok | `yazildi` |
| gmktemp | 70,0 | evet | doğru | evet | aynı | 1 | yok | `yazildi` |
| idn2 | 26,9 | evet | doğru | evet | aynı | 1 | yok | `yazildi` |
| gettext | 32,4 | evet | doğru | evet | aynı | 1 | yok | `yazildi` |
| envsubst | 34,2 | evet | doğru | evet | aynı | 1 | yok | `yazildi` |
| xz | 80,9 | evet | doğru | evet | aynı | 1 | yok | `yazildi` |
| gsort | 182,7 | evet | doğru | evet | aynı | 1 | yok | `yazildi` |

- **H1 ürün düzeyi: `main` 8 / 8 (önce 0 / 8), GT'ye göre 8 / 8 doğru, yanlış `main` 0** (her ikilide `main` alan tek anahtar `entry`). Kodda (`out/src`) 8 / 8; künye 8 / 8 `main_giris`, güven `on_ad:main_giris` satırından (0,966).
- **Bulgu: `out/naming_map.json` `mappings`'te 0 / 8.** `output_formatter._build_naming_map` c_namer haritasından yalnız yer tutucu önekli anahtarları (`FUN_`, `DAT_`, `sub_`, `thunk_`) alıyor; `entry` öneki yok → ad kodda var, analistin ad haritasında yok (yanlış ad değil, görünmeyen ad). Yama: `docs/arge/2026-11-23_dalga1/yamalar/PUV5__output_formatter.py.patch` (`orig == "entry"` da kabul; `git apply --check` temiz; ağaca uygulanmadı). Yan etki sayımı: a62f15e'nin 119 çıktısında c_namer haritasında `entry` anahtarı **0** (ELF'te `entry` adlandırılmıyor) → bugünkü 119'da haritaya yeni satır girmez. Yamanın ürün koşusu: ölçülmedi.

### Hedef seti: terminal-notifier, bayrak açık (20:08–20:09; 58,3 sn)

Girdi `~/karadul_olcum/ustveri_set/terminal-notifier/bin/terminal-notifier` (PUV6a ile aynı soyulmuş kopya, sha256 `d352c10594f2…`), GT `ustveri_set/terminal-notifier/gt/`. `entry` → `main`, GT'ye göre doğru, nüfusta (ad bekleyen **40**; HEDEF tanımıyla aynı sayı); künye `main_giris`, kodda tanım 1, `out/naming_map.json`'da yok (yukarıdaki biçimlendirici bulgusu). **Ad bekleyen 40'ta doğru: 0 → 1** (bu koşuda yalnız `main` bayrağı açık; PUV6a'nın ObjC adıyla birlikte ölçülmedi).

### H2 ürün düzeyi ve `main`'den yayılan adlar (bayrak kapalı kol + bugünkü ürün tabanı)

Kök `PUV5/urun/kapali` (dal `caa14e3`, ayar dosyası yok) ve `PUV5/urun/taban` (ağaç `~/karadul_olcum/urun-152176b`, ayar dosyası yok); ikili başına kapalı → taban çifti (`kos_h2.sh`). Bayt karşılaştırması `PUV5/harita_bayt.py` (`out/naming_map.json`, `reconstructed/src*/naming_map.json`).

| İkili | kapalı ↔ taban (out / src / src_iter1) | açık ↔ kapalı c_namer haritası: değişen anahtar | `entry` dışında değişen | nüfusta doğru (açık / kapalı) |
|---|---|---|---|---|
| htop | **bayt aynı / aynı / aynı** | 1 (`entry`) | 0 | 0 / 0 (giriş thunk; nüfus dışı) |

**Kuyruk notu (20:13):** zincirim kuyruğun ikinci yuvasını OL2'den önce kapıyordu (yeni çağrı beklemesiz, bekleyen öbür çağrı 5 sn uykulu); OL2 20:08'den beri bekliyordu. Kuyruğun paket bekletme dosyasıyla (`ghidra_kuyruk.bekle.PUV5`) kendi yeni çağrılarımı OL2 bir iş başlatana dek durdurdum (20:10–20:13). Sonra OL2'nin S8 zinciri yuvayı aynı yolla tutuyor; benim kalan 7 çiftim sırada.
