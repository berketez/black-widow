# KARŞI hattı — defter (2026-11-19)

Hat metni: `docs/arge/2026-11-19_mythos/HAT_KARSI.md`. Betikler `scripts/arge/karsi/`, veri
`~/karadul_olcum/runs/arge-2026-11-19/karsi/` (aşağıda `$V`). Komutlar depo kökünden,
`PYTHONDONTWRITEBYTECODE=1 python …`.

## 0. Başlangıç durumu (13:01)

- Okunanlar: `ORTAK_BRIF.md`, `KARARLAR.md`, `YON.md`, `HAT_KARSI.md`, `OLGU.md`, `olgu/SEMA.md`, `HAT_USTVERI.md`,
  dört hattın `BULGULAR.md`'si (KİMLİK, ÖZ KOD, ÖLÇÜ, ÜST VERİ), `birlesik_olcum/sonuc.md` §0–§4.
- ÖLÇEK: `olcek/PLAN.md` ve `BERKE.md` var (13:00) → denetime dahil. HIZ: 13:01'de yalnız `hiz/DEFTER.md` var;
  tur sonunda yeniden bakılacak.
- Sınırlar: Ghidra yok, `karadul analyze` yok, kilitli setler ve `~/karadul_olcum/ozkod_nufus/` açılmaz,
  git'te durum değiştiren komut yok, alt ajan / codex yok.
- Yöntem kararı (sayılara bakmadan): yeniden türetmede hatların betikleri içe aktarılmaz. Girdi: OLGU tablosu
  (`olgu.jsonl.gz`), ham koşu çıktıları (`static/*.json`, `naming_map.json`), ikililer (`nm`, `otool`), hatların
  **veri** dosyaları (etiket dosyaları, eşleme çıktıları) yalnız veri olarak. Wilson aralığını kendim yazarım
  (`scripts/arge/karsi/ortak.py`), `ks1_olc.oran` ile bir kez karşılaştırırım.

## 1. Ana oturumdan düzeltme (13:0x; Berke'nin sözü, ana oturum iletti)

- "Erken yayın" hedefi kalktı: her şey tam olunca yayın; kullanıcı tek kişi (Berke); uygulama onun makinesine kurulacak.
- Kalem 7 değişti: "yayından önce / sonra" ayrımı yok. Bitiş çizgisi tek: bütün planlar uygulanmış, bekletilen
  katmanlar (P10b, P08b, P03b, K-1 / K-4 bayrakları) ölçülüp karara bağlanmış, uygulama derlenip kurulmuş, gerçek
  büyük bir uygulamada uçtan uca çalışmış. İstenen: bağımlılık + risk + doğrulanabilirlik ölçütleriyle dalga sırası ve
  bitiş çizgisini en çok tehdit eden risk (tek paragraf).
- `YAYIN_KAPISI.md` §2 "yayına bilerek girmeyecekler" listesi geçersiz: o katmanlar da iş; çakışma haritasına girer.
- Kalem 4 bu gözle yazılır: hedef Berke'nin önüne gelen gerçek uygulamalar (Go / Swift / C++ / C karışık, 50 MB – birkaç GB).
- Not: hook `check-consistency.sh` `turet_ozkod.py`'deki `KESIF` adını `tests/test_lm_tools_v2.py`'deki aynı adlı
  (ilgisiz) sabitle karıştırdı; ad `OZKOD_KESIF_BIRIMLERI` yapıldı (sahte uyarı; değer çakışması yok).

## 2. Kalem 1 — yeniden türetme (kendi betiklerim; OLGU tablosu + hatların veri dosyaları)

Betikler: `ortak.py` (Wilson, belirteçleme, biçim anahtarı; hat betiklerinden bağımsız), `turet_taban.py`,
`turet_kimlik.py`, `turet_ozkod.py`. Çıktılar `$V/turet_*.txt|json`, `$V/yon_basina.txt`.

### 2.1 Taban ve ÖLÇÜ (`turet_taban.py`)

| İddia (hat belgesi) | Hattın sayısı | Benim sayım | Hüküm |
|---|---|---|---|
| nüfus / ad / doğru / yanlış / nüfusta doğru | 21 371 / 1 800 / 1 681 / 119 / 1 212 | aynı | doğrulandı |
| 119 yanlışın biçim farkı olanı | 40 (37 zstd + 3) | 40 (zstd 37, coreutils 1, openssl 1, mac/tmux 1); yalnız harf farkı 38, `_N` ekiyle +2 | doğrulandı |
| makro yanlış (program, n ≥ 10) | %31,0 → %19,1 | 0,3108 → 0,1917 | doğrulandı (%19,2'ye yuvarlanır; önemsiz) |
| tekil ad / doğru / biçim | 535 / 422 / 40 | aynı; yanlış 113 / 535 ve 73 / 535 | doğrulandı |
| kanal tekil düzeyi | gnulib 10 / 10, önyük 30 / 30, main 6 / 6 | aynı (alt 0,722 / 0,886 / 0,610) | doğrulandı |
| tekil nüfus | 9 257 | 9 257 | doğrulandı |
| `oz_ad` güven sınıfları | 0,80 → 22 / 76 (39 biçimle); 0,85 → 71 / 121 (94) | aynı | doğrulandı |

Yan gözlem (yön itirazı için): nüfus içi doğru ad coreutils 847 + tmux 341 = 1 188; **öbür altı programda 24 / 4 258**
(redis-tools 0 / 1 458, htop 0 / 819, sqlite3 1 / 389, zstd 4 / 919, tree 1 / 110, openssl 18 / 563).
Makro hedefin paydaları: sqlite3 12 ad, redis-tools 15, openssl 26, zstd 55 (sqlite3 7 / 12: Wilson %32–%81).

### 2.2 KİMLİK (`turet_kimlik.py`; yalnız OLGU'dan türetilebilenler)

| İddia | Hattın sayısı | Benim sayım | Hüküm |
|---|---|---|---|
| taban ürün tmux / htop nüfus içi doğru | 341 / 4 396; 0 / 819 | aynı | doğrulandı |
| A1: set içi kopya (ad + boyut) | 13 472 (%63,0) | coreutils 12 107 + redis 1 365 = 13 472 (+ zstd ↔ pzstd 335: hat pzstd'yi ölçü dışı saydı) | doğrulandı |
| A1: öbür platform / başvurusuz | 4 161 / 3 600 | 4 171 / 2 924 (+ zstd'nin pzstd kopyaları başvurusuzdan düşüyor) | doğrulandı (fark tanım: takma ad, pzstd) |
| tekil dizgi çapası, tmux iki yön | 737 / 54 = 0,932 | 738 / 55 = 0,931 [0,911–0,946] | doğrulandı (bağımsız gerçekleme) |
| tekil dizgi çapası, htop | 104 / 2 | 104 / 2 | doğrulandı |
| envanter tavan (tmux D→M / M→D) | 1 712 / 1 754 | 1 720 / 1 755 | doğrulandı (takma ad farkı) |

**Bulgu K-a (örnek ↔ tekil):** A1 payı tekil (program, GT adı) düzeyinde: set içi kopya %22,8 (+ yalnız ad %4,7), öbür
platform %31,8, başvurusuz **%40,7** (7 172 tekil). coreutils'siz örnek düzeyi: kopya %19,6, öbür platform %48,2,
başvurusuz %28,3 (n 8 654). "%82,5'in kodu set içinde başka yerde" cümlesi setin kuruluşunun (106 coreutils + iki
programın iki platform derlemesi) ürünü.

**Bulgu K-b (iki yön havuzu = çift sayım):** `yon_basina.py` → `$V/yon_basina.txt` (hattın `yayilim_*.json` `yonler` alanından). Eşleme
karşılıklı en iyi olduğu için iki yön aynı çiftleri sayıyor; Wilson n'si ~2 kat şişkin. Yön başına:
tmux sürüm farklı, tekil dizgi çapası 362 / 388 = 0,933 [**0,904**–0,954] ve 375 / 403 [**0,901**–0,951]; havuzda
737 / 791 [0,912–0,947]. PK-4'ün `naming_labels` satırı `basvuru:dizgi` (737, 791, 0,912) eşiği (0,909) yalnız çift
sayımla geçiyor. Yayılım aşaması yön başına 0,928 (geçiyor). `derleyici` yön başına 1 919 / 1 936 [0,986–0,995]
(sonuç değişmiyor).

### 2.3 ÖZ KOD (`turet_ozkod.py`)

| İddia | Hattın sayısı | Benim sayım | Hüküm |
|---|---|---|---|
| nüfus (117 ikili) | 20 747 | 20 747 | doğrulandı |
| `oz_ad` keşif / sınama (ad, doğru) | 141 / 92; 55 / 1 | aynı | doğrulandı |
| kanıt harfleriyle doğru; yanlıştan doğruya | 95 + 38 = 133; 40 | 95 + 37 = 132; 39 (1 zstd adının dizgisi fonksiyonun `dizgiler` listesinde yok); biçim yolundan 40 (§2.1) | doğrulandı |
| pencere çifti olan nüfus | 1 196 | 1 196; coreutils dışı 1 149 / 8 030 = %14,3 (hattın V ∪ C tanımıyla %15,8) | doğrulandı |
| K1, kâhin çapa, keşif | 740 / 754 = %98,1 | basit bağımsız gerçekleme (sabit adımlı yuva koşusu + δ): 475 / 484 = %98,1 | oran doğrulandı |
| K1, kâhin çapa, sınama | 103 / 126 = %81,7 | 140 / 155 = %90,3 [%84,6–%94,0] (redis 118 / 129, sqlite3 8 / 12, htop 14 / 14: sınıf nesnelerini gruplamıyorum) | yön doğrulandı; düzey gruplamaya duyarlı |
| doğrudan dizgi: ≥ 1 belirteç / hepsi | %12,1 / %5,4 | %12,1 / %5,4 | doğrulandı |
| "bugün" ≥ 1 / hepsi (program) | %52,1 / %13,4 | %48,0 / %12,7 (belirteçleme ve komşu tanımı farkı) | büyüklük doğrulandı |
| önek: adres komşuları / çağrı çoğunluğu | %96,4 / %55,2 | %96,5 / %54,4 | doğrulandı |
| ikiz yoğunluğu F1 ≥ 0,5 / ≥ 0,8 (ÖLÇÜ) | %76,3 / %32,7 | %78,3 / %32,7 | doğrulandı |

### 2.4 ÜST VERİ (`go_bagimsiz.py`; kendi asgari `pclntab` okuyucum + `nm`; `$V/go_bagimsiz.txt`)

| İddia | Hattın sayısı | Benim sayım | Hüküm |
|---|---|---|---|
| docker-cli: giriş; ad = sembol | 35 049; 34 710 + 328 + 10 (+ 1 adsız) | 35 049; 34 711 + 328 + 10, farklı 0 | doğrulandı |
| docker-compose | 90 078; 89 699 + 360 + 18 (+ 1) | 90 078; 89 700 + 360 + 18, farklı 0 | doğrulandı |
| `nfunc`: Ollama.arm64 / gh / limactl / colima | 10 601 / 40 384 / 40 321 / 13 082 | aynı | doğrulandı |
| Go ≥ 1.26 başlığında `textStart` = 0 | 9 dilim | baktığım 4'ünde 0 | doğrulandı |
| Mach-O `LC_MAIN` girişi = `_main` | 8 / 8; 1 169 / 1 169 | Homebrew tmux, htop, xz, gsort, btop: 5 / 5 (`lc_main.sh` → `$V/lc_main.txt`) | doğrulandı (örnek) |

Yeniden türetmediklerim: ObjC / Swift / RTTI sayıları, bozma deneyi, bütçe tablosu (okuyucu yazmak gerekir; zaman
değil bağlam sınırı). `_recover_main_from_entry` `karadul/stages.py:1816`'da ve canlı (1789, 1802'de çağrılıyor).

### 2.5 Yeniden türetmediklerim (açıkça)

- KİMLİK'in taze derleme sayıları (3 908 / 38 vb.): hattın `yayilim_*.json` çıktılarında eşleme çiftleri yok, yalnız
  sayaç var; eşleyiciyi yeniden yazmadım ve hattın betiğini koşmadım. Dolaylı denetim: aynı JSON'un yön başına
  alanları (K-b), tekil dizgi çapasının bağımsız gerçeklemesi (tmux, htop: aynı sayılar).
- ÖLÇÜ'nün AUC tabloları: etiket dosyasından yeniden hesaplamadım (sonuç olumsuz; çatlak aramanın getirisi düşük).

## 3. Kalem 2 — aşırı uyum ve sızıntı (bakılanlar)

- **Dosya zamanları** (`stat`): KİMLİK `ayar_htop_1.json` 10:41:41 → `yayilim_sinama_tmux.json` 10:46:01 →
  `hata_dok_kural.json` 10:51:32 → `yayilim_v2_hepsi.json` 11:06:19 → `yayilim_gcc.json` 12:30:25. `esle.py` son
  değişiklik 11:46:17 (ilk sınamadan sonra, GCC ölçümünden önce); `sinama_tmux` kural sayısı iki dosyada aynı
  (2 276 / 158). ÖZ KOD `ek_kurali.py` 10:43:53 → `ek_kurali_sinama.txt` 10:45:49; `oz_ad_kesif.txt` 10:53:27 →
  `oz_ad_sinama.txt` 10:56:14; G1 keşif 10:57:38 → sınama 10:58:03. Sıra defterlerle tutarlı; sınama öncesi kural
  değişikliği izi bulamadım.
- **Aynı kaynak iki yanda mı?** ÖZ KOD: debian/tmux + mac/tmux ikisi keşifte, debian/htop + mac/htop ikisi sınamada
  (temiz). KİMLİK: çift birimdir (temiz). ÖLÇÜ: AYAR (G4-L1-tmux) ve SINAMA C (G4-L3-tmux, L1 dışı öğeler) **aynı
  ikili** (Mac tmux); hat "tmux'suz sınama" satırını ayrıca veriyor ve hiçbir eşik seçilmedi (sonuç olumsuz) → zarar yok.
- **Bulgu K-c (program düzeyi bağımsızlık):** KİMLİK'in "taze veri, ön kayıtlı" sınamaları (`derleyici`, `-O3`, `-O0`)
  tmux'un yeni derlemeleri; başvuru ikilisi (mac/tmux) 10:46'da görülmüş sınama biriminin kendisi; `derleyici_htop`
  ayar programı. v2 (tablo yuvası) tmux hataları görüldükten sonra tasarlandı (hattın kendi "ikinci bakış" notu) ve
  "bağımsız sınaması" yine tmux + htop. Üçüncü program yok. G1'in eşiği (≥ 0,95) ön kayıttan önce bilinen tavan içi
  kesinlikle (0,985; 10:51) neredeyse belirlenmişti.
- **Ölçüm sonrası tanımlar:** ÖZ KOD "R1 + harf koruma 28 / 31" ve "nesne gevşek 152 / 175" açıkça işaretli; plan
  tablosunda da "ölçüm sonrası tanım" yazıyor. Bulgu gibi sunulmamış.
- **Sınama tarafı kaç kez görüldü:** ÖZ KOD K1 sınama 1 kez + 1 gevşek değişke (işaretli); ÖLÇÜ 3 kez (yazılı);
  KİMLİK tmux v1 1 kez, v2 "ikinci bakış" (yazılı).

## 4. Kalem 3 — çıkarım hataları (bakılanlar)

- Kâhin çapa: ÖZ KOD K1 843 doğru ad kâhin çapayla; ürünün bugünkü çapasıyla 95 (tek tablo, Mac tmux). BULGULAR ve
  BERKE.md bunu ayırıyor; PLAN §0 tablosu da. Ürün sayısı gibi yazılmamış. Ama 740 keşif doğrusunun 688'i tmux'un iki
  derlemesi (`ek_kurali_kesif.txt`: debian/tmux 316, mac/tmux 372, openssl 52): keşif 2 program, sınama 3 program.
- Örnek ↔ tekil: ÖLÇÜ §7 doğru yapıyor. KİMLİK A1 "%82,5" (K-a) ve iki yön havuzu (K-b) yapmıyor.
- Tek programdan genelleme: KİMLİK "aynı sürüm 0,990" = tmux; §9'da yazılı, BERKE.md'de "iki programda" yazılı.
- Wilson birimi: taban makro hedefi n = 12 / 15 / 26 / 55'lik programlarla hesaplanıyor (§2.1 yan gözlem).
- Karar eşiği: ÖLÇÜ kuralı `p > 1 − e / L` (L = 10, e = 1 → 0,900; `scripts/arge/olcu/karar.py:49`); KARARLAR A-2 ve
  KİMLİK / ÜST VERİ planları 0,909 (= L / (L + 1)) yazıyor. e ölçülmedi (e = 0,5 → 0,95).

## 5. Kalem 4–7 için toplanan olgular

- Set profili (`set_profili.py` → `$V/set_profili.txt`): 119 ikili, 66 983 fonksiyon, ortanca 312, en büyük 5 697; fonksiyon gövdesi
  toplam 10,4 MiB; nüfusun 18 229'u Debian ELF, 3 142'si Mac (2 ikili).
- Gösteri (salt okundu, 13:11): `~/karadul_olcum/runs/gosteri-2026-11-19/ollama/kosu.log` son satırları:
  "Ghidra'da bulunmayan çözümleyici adı (kapatılamadı): ['Objective-C Message']" ve "Pipeline iteration 1 took 1311s
  (> 600s timeout), skipping remaining 2 iteration(s)"; `BASLADI` 11:10, `CIKIS` yok (2 saat +, 26,6 MB dilim).
- ÖLÇÜ `PLAN.md` KARARLAR A-1'den sonra güncellenmemiş: P-Ö3 / P-Ö4 / P-Ö9 "insan etiket paketi", başlıktaki değişmez
  kural "İnsan etiketini model üretmez".
- Üç ayrı ikili okuyucu: P-ÜV0 `analyzers/ustveri/goruntu.py`, ÖK-4a `tarif/veri_sozcukleri.py`, PK-2
  `kimlik/olgu.py` (`isaretci_yuvalari`); yalnız PK-2 öbürünü anıyor.
- Plan taraması (`plan_tara.py`, `cakisma_tablo.py` → `$V/plan_tara.txt|json`, `$V/cakisma_tablo.md`, `$V/cakisma.json`):
  63 paket; `karadul/config.py`'yi 21 paket, `stages.py`'yi 10, `c_namer.py`'yi 7, `ghidra/headless.py`'yi 6 paket anıyor.
- Var denilen dosya ve semboller (`sembol_denet.sh` → `$V/sembol_denet.txt`: 59 sembol + 14 dosya; 57 sembol ve 14 dosya yerinde); iki küçük sapma: PK-5 `add_k4_channels`'ın
  çağrıldığı yeri `_feedback_naming_merger.py` diye yazıyor (çağrı `_feedback_naming_candidates.py:90`; merger'daki
  yer `k4_inputs`, satır 295–305; alıntılanan `flags = {…}` satırı doğru); PK-1 `_match_against_db` bugün
  `naming_map` ile çalışıyor, `matches` listesini okumuyor (plan zaten geçişi tarif ediyor).
- ÖLÇ-1: T25 3 sa + T100 8 sa + T300 8 sa + PAKET 8 sa = 27 saat tek Ghidra, "makine boşken"; ön kaydı üçünün
  bitmeyeceğini söylüyor. ÖLÇ-2 aynı duvarlar.
- Bakıldı, zayıf çıktı: Ollama'nın Go dışı kodu için makinede sembollü başvuru adayı (`llama-server`, 19 609 kod
  sembolü). `ollama-cli.arm64` dizgilerinde `ggml` 21, `llama_` 55, `mlx_` 1 555 satır: Go dışı kısım büyük olasılıkla
  MLX bağlayıcıları; hazır bir "gömülü kitaplık" çifti olarak önerilemez (ölçülmedi).

## 6. HIZ planı tur sonunda geldi (13:17–13:20)

- `hiz/PLAN.md` 13:17'de yazıldı (HZ-0 … HZ-9, 11 paket); `## PAKET BİTTİ` ve `BERKE.md` yok; HZ-7 metni boş ("Profil
  bitince yazılacak", satır 230). Kural gereği içerik denetlenmedi. `plan_tara.py` ve `cakisma_tablo.py` yeniden koşuldu
  (HIZ belge listesinde zaten vardı): toplam 74 paket; `config.py` 17, `ghidra/headless.py` 12 paket (HIZ 6: HZ-1, HZ-3,
  HZ-4a, HZ-4b, HZ-5, HZ-8). §5'teki "63 paket" HIZ'sız sayımdır.
- Elle doğrulama betikleri kalıcı yapıldı (satır içi komut yerine dosya): `set_profili.py`, `yon_basina.py`,
  `lc_main.sh`, `sembol_denet.sh`; çıktıları `$V/` altında.

## 6b. Gösteri koşusu bitti (13:20:12)

- `gosteri_oku.py` → `$V/gosteri_oku.txt`: `BASLADI` 11:10:50, `BITTI` 13:20:12, `CIKIS` 3 ("kısmi"; hata bildiren aşama
  `static`: evrensel dosyada Go analizcisi açmıyor), 7 761,62 sn, tepe RSS 4 680 646 656 B (ayak izi 5 827 663 560 B),
  13 160 fonksiyon + 399 thunk, `naming_map.json` `total_mappings` 17 (hepsi `FUN_` anahtarlı; `oz_ad` 9, `on_ad:faz1` 8;
  etiket 17 / 17 "doğrulanmadı"), `total_candidates` 1 142. Ad dökülmedi (yalnız sayım).
- §5'teki "13:11'de `CIKIS` yok" notu o anın durumudur; `KARSI.md` İ-1 ve §3 bitmiş sonuca göre yazıldı.

## 7. Kapanış

- Çıktılar: `KARSI.md` (13 itiraz + yön + risk + bulamadıklarım + doğrulananlar), `CAKISMA.md` (betik tablosu + elle
  ekler + üç yapısal öneri + dalga sırası), `BERKE.md`, bu defter.
- Betikler (`scripts/arge/karsi/`): `ortak.py`, `turet_taban.py`, `turet_kimlik.py`, `turet_ozkod.py`, `go_bagimsiz.py`,
  `yon_basina.py`, `set_profili.py`, `plan_tara.py`, `cakisma_tablo.py`, `lc_main.sh`, `sembol_denet.sh`.
- Yapılmayanlar (açıkça): KİMLİK eşleyicisinin bağımsız gerçeklemesi (taze derleme sayıları yeniden türetilmedi);
  ÖLÇÜ AUC tabloları; ÜST VERİ'nin ObjC / Swift / RTTI sayıları ve bozma deneyi; ÖLÇEK'in ölçek eğrileri; HIZ'ın
  tamamı; `P10b` / `P08b` / `P18` içerik denetimi. Ghidra koşulmadı; kilitli setlere ve kör nüfusa bakılmadı; hat
  belgeleri değiştirilmedi; git durumu değiştirilmedi.
- Yaratıcılık protokolü (tek satır): denetlenebilir soru — evet (her itirazın kanıtı betik çıktısı); uzlaşıyı kır —
  görevin kendisi; tek hat — evet (öbür hatların dosyalarına yazılmadı); seçim insanda — itirazların hangisinin
  uygulanacağına ana oturum karar verir.
