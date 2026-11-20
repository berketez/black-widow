# HEDEF — P-ÜV8 kalem 1–4 (hedef seti, GT, "önce" sayısı) ║ P-ÜV9 kalem 1

Paket metni: `docs/arge/2026-11-20_dalga0/gonderim/HEDEF.md`. Ortak brif: `docs/arge/2026-11-20_dalga0/ORTAK_D0.md`.

- Başlangıç: 2026-11-20 09:2x. Taban commit: `233f199` (main; `git merge --ff-only main` ile).
- `karadul.__file__` worktree yolunu gösteriyor (doğrulandı).
- Veri kökü: `~/karadul_olcum/ustveri_set/` (set), `~/karadul_olcum/runs/dalga0-2026-11-20/HEDEF/` (koşular).
- **Ön kayıt:** `on_kayit_HEDEF.md`, commit `bbda937` (ölçümden önce).

## Durum

| Kalem | Durum |
|---|---|
| 1 set + GT + bölme | bitti (aşağıda) |
| 2 ad eşitliği | bitti (`c16a315`) |
| 3 kanal ölçümü | bitti: keşifte HK tuttu, H1 25 / 25 aynı |
| 4 bütçe + ürün "önce" sayısı | bitti: bütçe 16 / 16 aynı; ürün taban tablosu aşağıda (1 ikili koşuldu, 4'ü süre nedeniyle gece kuyruğuna) |
| 5 P-ÜV9 kalem 1 | bitti (`7f75192`): G1–G3 tuttu; G4 ObjC adı Ghidra'da yalnız seçici |
| 6 test + mutasyon | 23 test geçti; mutant 14 / 14 öldü (`a260351`) |

## Koşu listesi (Ghidra kuyruğu) ve TAHMİNİ süre

Ayrıntı ve dayanak: `on_kayit_HEDEF.md` §4 (güç yasası üssü 2,14; tmux 223 sn, gösteri 7 762 sn).

| İkili | TAHMİN | Karar |
|---|---|---|
| terminal-notifier (soyulmuş) | 1–5 dk (yük altında) | koşulur: `ghidra_kuyruk.sh HEDEF urun:terminal-notifier …`, süre sınırı 3 600 sn |
| llama-server arm64 | 164–215 dk | ölçülmedi: süre — gece kuyruğuna önerildi |
| docker-cli | 334–983 dk | ölçülmedi: süre — gece kuyruğuna önerildi |
| docker-compose | 859–7 378 dk | ölçülmedi: süre — gece kuyruğuna önerildi |
| iTerm2 arm64 | 1 046–11 219 dk | ölçülmedi: süre — gece kuyruğuna önerildi |

## Kalem 1 — set, GT, bölme (`scripts/measurement/ustveri_set.py hazirla`)

Veri: `~/karadul_olcum/ustveri_set/<ad>/{orig,bin,gt}`, künye `~/karadul_olcum/ustveri_set/manifest.json` (araç künyesi: `/usr/bin/strip` → CLT 27.2, sha256 `719f0aeb…`; `/usr/bin/nm` llvm-nm 21.0.0). Kilitli test setiyle kesişim 0. Süre 5,7 sn.

| Ad | Bölme | Dilim | Özgün dilim sha256 | Soyulmuş sha256 | Soyma temiz | GT fonksiyon adresi / ad | Ad türü (adres): objc / swift / cxx / diğer | GT RTTI adresi (typeinfo / vtable adı) |
|---|---|---|---|---|---|---|---|---|
| terminal-notifier | keşif | ince | `eaec53d59e9ed9ba56841379f6b54904092ba01ad5747c4add5305a64c77e91e` | `d352c10594f241191b344e48e6607bce73a5b5095722bb3b2216640d74f2cd03` | evet | 92 / 93 | 42 / 0 / 0 / 50 | 0 |
| docker-cli | keşif | ince | `1b2b4029ea6ba83b320faa14dbd2044b1bd05a9a9bea0921b10c39575e7ce717` | `4b6b084536de5c22fc7fd8a19f4b2d3b10ad8a6e1816da211a546fc8bacefe12` | evet | 35 050 / 35 051 | 0 / 0 / 0 / 35 050 | 0 |
| docker-compose | sınama | ince | `fc9b9e22a1134f55500699f703e790cda16b7ba56d9894ef9a80ddb3f5732bd9` | `9f39c96629894866376e5352c9bc1947dfe916ba8d21ad2e95b568e2ce2aebf4` | evet | 90 257 / 90 258 | 0 / 0 / 0 / 90 257 | 0 |
| iTerm2 | sınama | arm64 (kaynak `53b9badb…0d29`) | `9fc127adb7d2f18c669f6954a2850a0dd153f2af666cd7d820f1cc715269aa65` | `4c3e96a2593d00e69f9e32cdde9f59ee0cd093cc5125565042dac4797d98febe` | **hayır**: 5 dışa aktarım + 1 fonksiyon sembolü kaldı | 108 776 / 131 876 | 34 605 / 60 771 / 314 / 13 096 | 28 (18 / 10) |
| llama-server | sınama | arm64 (kaynak `3efd976f…58d4`) | `89a52344cd014129a1d849079730810a6190eec5eec6ff8547027a91ec9d7321` | `6ae2d57c0dae9715aa245bf8b41c1ce8e4481f0f3cdf93cc725bc915c67c782f` | **hayır**: 151 dışa aktarım + 63 fonksiyon sembolü kaldı | 17 210 / 19 601 | 0 / 0 / 14 878 / 2 333 | 3 323 (2 006 / 1 317) |

- Dilimler araştırma kopyalarıyla (`$V/hedef/iTerm2.arm64`, `llama-server.arm64`) aynı sha256.
- GT adres sayıları araştırma envanteriyle tutarlı: docker-cli 35 050 (= `ayrik_adres`), iTerm2 108 776 ve llama-server 17 210 (= sembollü başlangıç).
- **HS tutmadı (2 / 5):** `/usr/bin/strip` öntanımı, ikilinin dışa açtığı sembolleri bırakıyor (iTerm2 5, llama-server 151 dışa aktarım; 1 ve 63 `T` sembolü). Kanal ölçümü sembol okumaz (RTTI taramasının zayıf bağ çözümü hariç; H1 bunu sınar). Ürün koşusu bu iki ikilide zaten yok (süre); gece kuyruğunda koşulursa bu adlar Ghidra'ya sızar: ya kalan sembollerin adresleri ölçümden çıkarılmalı ya da `strip -x` değil, dışa aktarım bırakmayan bir yol aranmalı (karar ana oturumda).

## Kalem 2 — ad eşitliği (`scripts/measurement/ustveri_olc.py`, commit `c16a315`)

Kurallar tek yerde (`go_yazimi`, `objc_yazimi`, `swift_yazimi`, `rtti_yazimi`, `urun_esit`); ön kayıt §2 ile aynı. Sentetik testler: `tests/test_puv8_olcum.py` (23 test). Mutasyon `scripts/measurement/mutation_specs_puv8.json`: 13 / 13 öldü (`.abi0` kuralı her eki soyar; kategori kuralı sınıfı da soyar; payda GT'siz adresleri sayar; kesin ∪ sembol yerine toplam; Wilson'da n yerine k; çok adlı adreste tek eşleşme; sınama reddi kalkar; GT'siz yanlış sayılır; A-2 eşiği gevşer; nüfus thunk sayar; Mach-O öneki soyulmaz; dilim ofsetsiz; RTTI GT'sinde vtable düşer).

## Kalem 3 — kanal düzeyi ölçüm (keşif; **araştırma okuyucusu, ürün kanalı değil**)

Soyulmuş kopyada kanal çıktısı ↔ özgünün sembol tablosu (`ustveri_olc.py kanal`; çıktı `~/karadul_olcum/runs/dalga0-2026-11-20/HEDEF/kanal_<ad>.json`).

| İkili | Kanal | Ad verilen | Doğru | Yanlış | GT'siz | Yazım kırılımı | Kesinlik (Wilson %95) | A-2 (alt ≥ 0,909) |
|---|---|---|---|---|---|---|---|---|
| docker-cli | Go `pclntab` | 35 048 | 35 048 | 0 | 0 | birebir 34 710 / `.abi0` 328 / orta nokta 10 | %100 (%99,99–%100); alt 0,99989 | evet |
| terminal-notifier | ObjC yöntem | 32 | 32 | 0 | 0 | birebir 31 / kategori 1 | %100 (%89,3–%100); alt 0,892821 | **hayır (n = 32 küçük)** |

- Öbür kanallar iki keşif ikilisinde `veri_yok`. **HK tuttu** (sayılar ön kayıttaki gibi; A-2 "hayır" da ön kayıtta beklenen).
- **Araç araştırma çıktısını yeniden üretiyor:** özgün dilimde kanal listesi `$V/go/docker-cli.tsv` (35 048 adres) ve `$V/objc/terminal-notifier.tsv` (32) ile adres ve ad düzeyinde aynı: yalnız bir yanda 0, ad farkı 0 (`ustveri_olc.py yeniden-uret`; `…/HEDEF/yeniden_<ad>.json`).
- **Sınamada kanal kesinliği hesaplanmadı** (araç reddeder; Dalga 2).

### H1 — soyma kanal çıktısını değiştiriyor mu (5 ikili × 5 kanal; GT okunmadı)

`ustveri_olc.py h1` (`…/HEDEF/h1/<ad>.json`): özgün dilim ↔ soyulmuş kopya.

| İkili | Go | ObjC | Swift erişim | C++ typeinfo | C++ vtable | Fark |
|---|---|---|---|---|---|---|
| terminal-notifier | veri yok | 32 / 32 | veri yok | veri yok | veri yok | 0 |
| docker-cli | 35 048 / 35 048 | veri yok | veri yok | veri yok | veri yok | 0 |
| docker-compose | 90 077 / 90 077 | veri yok | veri yok | veri yok | veri yok | 0 |
| iTerm2 arm64 | veri yok | 41 305 / 41 305 | 3 659 / 3 659 | 18 / 18 | 10 / 10 | 0 |
| llama-server arm64 | veri yok | veri yok | veri yok | 1 994 / 1 994 | 1 317 / 1 317 | 0 |

**H1 tuttu: 25 / 25 kanal-ikili çiftinde durum ve adres → ad haritası aynı.** (iTerm2 ve llama-server soyulmuş kopyasında kalan dışa aktarımlar RTTI taramasının zayıf bağ çözümünü değiştirmedi.)

## Kalem 4 (plan) — bütçe (`ustveri_olc.py butce`)

- **Başvuruyla karşılaştırma (HB tuttu):** `$V/butce.json`'daki 16 hedefin 16'sında 13 sütunun (nüfus, Go, ObjC, Swift erişim, kesin, Swift yuva, RTTI yuva, yuva, sembol, kesin − sembol, kesin ∪ sembol, kalan, kalanın yuvalısı) hepsi aynı (`…/HEDEF/butce_basvuru.json`). Girdi: `$V/hedef/` kopyaları; htop / tmux `workspaces/olcum_mac/corpus/*/bin`, gsort / xz P-S3b kabul seti `bin` kopyaları.
- **Set ikililerinin soyulmuş kopyası** (`…/HEDEF/butce_set_soyulmus.json`):

| İkili | Nüfus (kaynak) | Go | ObjC | Swift erişim | Kesin | Yuva | Sembol | Kalan |
|---|---|---|---|---|---|---|---|---|
| terminal-notifier | 92 (LC_FUNCTION_STARTS) | 0 | 32 | 0 | 32 | 0 | 0 | 60 |
| docker-cli | 35 048 (`pclntab`; LC_FUNCTION_STARTS yok) | 35 048 | 0 | 0 | 35 048 | 0 | 0 | 0 |
| docker-compose | 90 257 | 90 077 | 0 | 0 | 90 077 | 0 | 0 | 180 |
| iTerm2 arm64 | 109 608 | 0 | 41 305 | 3 659 | 44 964 | 3 128 | 1 | 64 643 |
| llama-server arm64 | 17 211 | 0 | 0 | 0 | 0 | 7 053 | 63 | 17 148 |

- Sembol sütunu iTerm2'de 1, llama-server'da 63: soyma sonrası kalan fonksiyon sembolleri (kalem 1, HS).

## Bekleme (Ghidra kuyruğu)

- **09:40 — şu an bekliyorum:** `urun:terminal-notifier` kuyrukta (09:33:28'den beri; önde OK5 `postgresql-17:e00` 09:05:41'den beri koşuyor, HZ1 ve KIMLIK bekliyor). Kendi koşu TAHMİNİ 1–5 dk; kuyruk bekleyişi bilinmiyor (TAHMİN 20–90 dk). Bu arada P-ÜV9 kalem 1 (Ghidra'sız; gösteri çıktısı salt okur) yapılıyor.

## P-ÜV9 kalem 1 — özet (ayrıntı `../acik_olcum/PUV9_K1.md`, commit `7f75192`)

| Soru | Sonuç | Ön kayıt |
|---|---|---|
| G1 `LC_FUNCTION_STARTS` ↔ Ghidra | 12 916 / 12 952 başlangıç Ghidra'da fonksiyon (%99,72) | tuttu (≥ %99) |
| G2 Go girişi Ghidra'da jenerik adlı (kanal yazabilir) | 10 457 / 10 600 (%98,65); yok 28, thunk 112, adlı 3 | tuttu (≥ 9 540) |
| G3 Ghidra'nın Go girişine verdiği ad | 3 (thunk'larla 96; thunk adları libc hedefi, Go adıyla eşit 0) | tuttu (≤ %1) |
| G4 ObjC yöntemi (151) | Ghidra 148'ini adlandırıyor, adı yalnız seçici: kalem 2 eşitliği 0 / 148, seçici eşitliği 148 / 148 | açık soru → P-ÜV6'ya girdi |
| G5 Ghidra adlı ∩ üst veri | 245 (program 151, thunk 94); üst veri dışında 802 | açık soru |

## Ürün ölçüm aracının doğrulaması

- `ustveri_olc.urun_kayitlari` (süzgeç + hüküm) Mac tmux koşusunda (`~/karadul_olcum/runs/urun-onarim-a62f15e/mac/tmux`, GT `workspaces/olcum_mac/corpus/tmux/gt`) `urun_olc.degerlendir_elf` ile aynı sonucu verdi: 236 ad / 205 doğru, yalnız bir yanda 0, hüküm farkı 0 (commit `a260351`; ilk sürümde klon satırı kuralı yoktu, eklendi).
## Tam takım

- 1. koşu (09:42, `a260351`): 7 kaldı / 10 393 geçti — hepsi worktree'de çalışma verisi bağı olmamasından (`vendor/gnulib-ref` FileNotFoundError, `scripts/node_modules`, `sigs`); benim değişikliğimle ilgisiz.
- ORTAK_D0 §2'deki bağlar kuruldu (`sigs`, `vendor`, `signatures_homebrew*.json`, `sigs_macos_system.json`, `signatures.lmdb`, `scripts/node_modules`; commit'lenmez). 7 test yeniden: 25 / 25 geçti.
- **2. koşu (09:48, aynı kod): 10 505 geçti / 11 atlandı / 0 kaldı, 539 sn (yük altında: `load averages: 5.92 6.55 7.73`).** Günlük `~/karadul_olcum/runs/dalga0-2026-11-20/HEDEF/tam_takim/tam_takim2.log`.

## Bekleme (09:57)

- Kuyruk: OK5 bitti; KIMLIK `D0:kitaplik/libzstd` koşuyor, HZ1 S8 ikililerini tek tek kuyruğa sokuyor; `urun:terminal-notifier` 09:33:28'den beri bekliyor. TAHMİNİ başlama 10:00–11:00, koşu 1–5 dk.

## Kalem 4 — bugünkü ürünün "önce" sayısı (taban; P-ÜV8 kalem 5'in "bayrak kapalı" koluyla aynı tanım)

Koşu: `~/karadul_olcum/ghidra_kuyruk.sh HEDEF urun:terminal-notifier python scripts/measurement/ustveri_olc.py urun-kos …`; ürün ağacı `~/karadul_olcum/urun-b6aceb9` (commit `b6aceb9`, kirli dosya yok, `karadul` o ağaçtan; imza veritabanı `data_root:signatures.lmdb`); bayraklar öntanımlı; `PYTHONHASHSEED=0`; `KARADUL_CACHE_DIR=~/karadul_olcum/runs/dalga0-2026-11-20/HEDEF/urun/cache`; süre sınırı 3 600 sn. Kuyruk: 09:33:28 bekledi → 09:58:25 başladı → 09:59:19 bitti. Künye `…/HEDEF/urun/mac/terminal-notifier.kunye.json`; ölçüm `…/HEDEF/urun_terminal-notifier.json` (`ustveri_olc.py urun`).

| İkili | Durum | Süre | Ürünün ad verdiği fonksiyon | Doğru | Yanlış | GT'siz | Kanal kırılımı | Ad bekleyen nüfus → doğru kapsam | Ghidra'nın kendisi (GT'li 92 fonksiyonda) |
|---|---|---|---|---|---|---|---|---|---|
| terminal-notifier (soyulmuş) | tamam (`BITTI` 0) | 53,4 sn (yük altında; `load averages: 5.45 7.38 7.83`) | **0** (ad haritasının `global` bölümü boş) | 0 | 0 | 0 | — (ad yok) | 40 → 0 / 40 (Wilson üst %8,8) | 92 / 92'sinde fonksiyon açtı; 31'ine jenerik olmayan ad verdi: 31'i de ObjC yöntemi, ad **yalnız seçici** (kalem 2 eşitliği 0 / 31, seçici eşitliği 31 / 31) |
| llama-server arm64 | ölçülmedi: süre (TAHMİN 164–215 dk) — gece kuyruğuna önerildi | | | | | | | | |
| docker-cli | ölçülmedi: süre (TAHMİN 334–983 dk) — gece kuyruğuna önerildi | | | | | | | | |
| docker-compose | ölçülmedi: süre (TAHMİN 859–7 378 dk) — gece kuyruğuna önerildi | | | | | | | | |
| iTerm2 arm64 | ölçülmedi: süre (TAHMİN 1 046–11 219 dk) — gece kuyruğuna önerildi; ayrıca soyulmuş kopyada sembol kaldı (kalem 1) | | | | | | | | |

- **HÜ tuttu:** ürünün ad verdiği fonksiyon 0 (< 10); üst veri kanalından ad 0. Doğru ad 0 (ilk ölçüm).
- Ölçüm aracı tmux'ta `urun_olc` ile aynı hükmü verdiği için (yukarıda) bu sıfır araç hatası değil: ürünün bu ikilide hiçbir ad kanalı tetiklenmedi.
- **ObjC kanalı için önemli sayı (P-ÜV6'ya):** aynı koşuda (`acik_ghidra_ustveri.py`, `…/HEDEF/ghidra_ustveri_terminal-notifier.json`) yöntem listesindeki 32 IMP'nin 31'i Ghidra'da zaten adlı (yalnız seçiciyle), 1'i jenerik. P13b kuralı ("aday yalnız Ghidra'nın adsız bıraktığı fonksiyona") olduğu gibi kalırsa ObjC kanalı burada **1** ad yazar; P-ÜV6 ön kaydı H4'teki "32 yöntemin Ghidra'nın adsız bıraktıklarına ad yazar" beklentisi bu veriyle tutmaz (Ollama'da da 148 / 151 aynı durum). Ayrıca Ghidra 173 program fonksiyonunu `LC_FUNCTION_STARTS` dışında açmış (264 `ANALYSIS` adlı; GT `__text` dışında, ölçüme girmez).
