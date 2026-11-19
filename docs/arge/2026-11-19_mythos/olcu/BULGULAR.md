# ÖLÇÜ hattı — bulgular (tur 1, 2026-11-19)

- Taban: birleşik ölçüm a62f15e (119 ikili). Bütün veri geliştirme setindendir; kilitli setlere dokunulmadı.
- Betikler `scripts/arge/olcu/`, çıktılar `~/karadul_olcum/runs/arge-2026-11-19/olcu/` (aşağıda `$V`). Komutların hepsi depo kökünden, `PYTHONDONTWRITEBYTECODE=1` ile.
- Aralıklar Wilson %95 (`ks1_olc.oran`). AUC farklarının aralığı eşli tabakalı önyükleme (2 000 tekrar, tohum 20261119).
- Ön kayıtlar ve bölme kararı ölçümden önce `DEFTER.md` §2–§5, §7, §11'de yazıldı. Tutmayan beklentiler aşağıda duruyor.

## 0. Özet

1. **Depoda insan etiketi yok.** 1 319 (aday ad, GT adı, hüküm) üçlüsünün hepsi Claude Opus ajanlarının hükmü. Bu turda ölçülen "ölçü ↔ vekil (model) hüküm" uyumudur; insan uyumu iddiası yok (§1).
2. **Hiçbir sözcük ölçüsü "amacı doğru ad"ı sayamıyor.** Tam eşit olmayan çiftlerde en iyi AUC sınama havuzunda 0,79; iki vekil değerlendiricinin birbirini öngörme AUC'si 0,96–0,99. Ayar kümesinde hiçbir ölçünün hiçbir eşiği 0,90 kesinlik vermedi (§2).
3. **Yasak cevap ölçüldü ve tutmuyor.** "Belirteç F1 ≥ 0,5" kabul ettiği adların ayar kümesinde %23,3'ünü, sınama havuzunda %29,3'ünü doğru tutturuyor; kabul ettiklerinin %20–%27'si değerlendiriciye göre yanıltıcı (§2.3).
4. **Aykırı öncül 1 tutmadı.** Asimetrik kesinlik simetrik F1'den iyi değil (fark −0,002; ayırt edilemedi). Bütün belirteçleri GT'de olan adların %30'u ayar kümesinde "yanıltıcı" etiketli: eksik kalan tek belirteç fonksiyonu kardeşinden ayıran belirteç (§2.4).
5. **Aykırı öncül 2 tuttu, iki yönde de.** (a) Taban koşusunun 119 "yanlış"ının 40'ı GT adıyla yalnız biçimce farklı (büyük / küçük harf, `_2`, derleyici eki); rubriğin kendi tanımıyla bunlar `tam`. Makro yanlış oranı %31,0 → %19,1 (§4). (b) Ad bekleyen 21 371 fonksiyonun %76,3'ünün aynı ikilide adı F1 ≥ 0,5 benzeyen bir kardeşi var (§3).
6. **Mekanik olarak sayılabilen üç şey var:** tam eşitlik; biçim düzeyi (`harf_tam`); ve "örtüşme yok → büyük olasılıkla yanlış" (sınama havuzunda %80,5). Arada kalan bant insan etiketi ister; taban koşusunda bu bant 56 addır, örtüşmeyenlerle birlikte 79 (§4).
7. **Karar kuralı taslağı:** "yanlış ≤ %10" hedefi, yanlış adı eksik adın 10 katı saymaya denk. Bu oranda gnulib, ELF önyükü ve `main` kanalları (1 301 ad) ad düzeyinde kalıyor; `oz_ad` ve `assert_ust` kanıt satırına düşüyor (§5).
8. **Havuz sayıları yinelemeyle şişkin.** 1 800 ad yalnız 535 tekil addır (gnulib kanalının 733 adı 10 tekil ad). Tekil düzeyde yanlış oranı %21,1 (tam eşitlik) ve %13,6 (tam + biçim); ön ad kanallarının güven alt sınırları tekil düzeyde belirgin düşük (§7).
9. **Kanal çatışması ve kalibrasyon ölçüldü (§8).** 1 800 adın 1 300'ünde kazananla çatışan bir yedek aday var, ama kazananı yanlış olan 79 adın hiçbirinde yedek doğru değil; yedek kanallar (`api_call`, `callee_based`) 2 007 adayda 2 doğru. `oz_ad`'ın yazdığı güven (ortalama 0,83) gerçekleşen kesinliğin (0,47; biçimle 0,68) çok üstünde.

## 1. Etiket envanteri (kalem 1)

Komut: `python scripts/arge/olcu/etiket_topla.py --cikti $V` → `etiketler.jsonl`, `etiket_envanteri.json`.

| Küme | Program | Rubrik | Etiketçi | Kör | Üçlü (yemsiz) | tam / doğru tarif / yalnız alan / yanlış |
|---|---|---|---|---|---|---|
| G4-L1-tmux | tmux (Mac) | v2 | ajan L1 | evet | 385 | 46 / 30 / 134 / 175 |
| G4-L3-tmux | tmux (Mac) | v2 | ajan L3 | evet | 200 (88'i L1 ile ortak) | 16 / 15 / 75 / 94 |
| G4-L2-tmux-gt | tmux (Mac) | v2 | ajan L2 | hayır (GT görünür) | 200 (L3 ile aynı öğeler) | 16 / 17 / 52 / 115 |
| G4-L3-htop | htop (Mac) | v2 | ajan L3 | evet | 97 | 0 / 4 / 14 / 79 |
| P15c | 12 ikili, 8 program | v2 | P15c ajanı | hayır | 236 kayıt, 220 tekil çift | 0 / 24 / 44 / 168 |
| V1-ajan | tmux, htop (Mac) | v1 | ajan | evet | 100 + 101 | 13 / 16 / 30 / 41 ve 0 / 4 / 32 / 65 |

- Toplam 1 319 üçlü. İnsan etiketi 0: 15 Ekim dosyalarında insana ayrılmış `etiket` alanı 201 / 201 satırda boş.
- Hepsi geliştirme seti; kilitli sete ait etiket kümesine rastlanmadı.
- Değerlendiriciler ad kuralını yazan modelle aynı aileden; tmux ve htop bilinen programlar (ezber dışlanamaz).
- Bölme (önceden): AYAR = G4-L1-tmux; SINAMA A = G4-L3-htop, B = P15c tekil, C = G4-L3-tmux'un L1 dışı 112 öğesi; tavan = L1 ∩ L3.

## 2. Aday ölçüler ve vekil hükümle uyum (kalem 2)

Komutlar: `python scripts/arge/olcu/roc.py --etiketler $V/etiketler.jsonl --json $V/roc.json`; `bantlar.py` (aynı girdi → `bantlar.json`); `kimlik.py` ve `idf.py` (`--taban $V/taban_a62f15e.json` ile → `kimlik.json`, `idf.json`).

Ölçüler (`olcu.py`): belirteç kesinliği `P`, duyarlılığı `R`, `F1`, Jaccard `J`; sözlüklü `Ps`, `Rs`, `F1s` (181 kısaltma, 35 eşanlam kümesi; `sozluk.json`, kaynağı: bu ajanın önsel listesi, sha256 `85711dc6…`); düzenleme benzerliği `duz`; içerikli belirteç kesinliği `Pic`; zıt fiil vetolu `Pz`, `F1z`; asimetrik birleşik `as0`, `as5`; göreli `ayirt`, `kimlik`; idf ağırlıklı `Ridf`, `F1idf`. Hedefler: `yakin` (tam ya da doğru tarif), `yaniltmaz` (yanlış değil). Tam eşit çiftler çözümleme dışı.

### 2.1 AUC (tam eşit olmayan çiftler)

| Küme | n | `yakin` sayısı | `P` | `F1` | `F1s` | `Rs` | `duz` | `as5` | `kimlik` | `Ridf` |
|---|---|---|---|---|---|---|---|---|---|---|
| AYAR | 339 | 30 | 0,738 | 0,769 | 0,799 | 0,811 | 0,811 | 0,776 | 0,684 | 0,821 |
| A (htop) | 97 | 4 | 0,527 | 0,525 | 0,595 | 0,591 | 0,773 | 0,595 | 0,500 | 0,591 |
| B (P15c) | 220 | 22 | 0,744 | 0,743 | 0,787 | 0,786 | 0,723 | 0,793 | 0,641 | 0,780 |
| C (tmux, L3) | 104 | 11 | 0,821 | 0,851 | 0,906 | 0,921 | 0,725 | 0,897 | 0,674 | 0,929 |
| Sınama havuzu | 421 | 37 | 0,731 | 0,734 | 0,782 | 0,784 | 0,721 | 0,790 | 0,636 | 0,783 |
| Sınama, tmux'suz | 293 | 23 | 0,685 | 0,682 | 0,749 | 0,749 | 0,736 | 0,758 | 0,589 | 0,743 |

- `kimlik` ve `Ridf` sütunları 7 `pzstd` kaydı (GT listesi yok) çıkarılmış kümelerde (havuz n = 414).
- `yaniltmaz` hedefinde sınama havuzu AUC'leri 0,64–0,72 (`roc.json`).
- AUC aralıkları (`roc_egri.py` → `roc_egri.json`, ROC noktalarıyla): sınama havuzunda `yakin` için en iyi ölçü `as5` 0,790 (%95: 0,708–0,863), `F1` 0,734 (0,647–0,818), `P` 0,731 (0,644–0,814); AYAR'da `Rs` 0,811 (0,729–0,888). Hiçbir ölçünün üst ucu tavana ulaşmıyor.
- **Tavan:** L1 ∩ L3'ün tam eşit olmayan 80 öğesinde bir değerlendiricinin etiketiyle öbürünün `yakin` hükmünü öngörme AUC'si 0,961 ve 0,993 (kappa 0,88); `yaniltmaz` için 0,84 (kappa 0,67). Aynı 80 öğede ölçülerin `yakin` AUC'si 0,73–0,92.

### 2.2 Ön kayıtlı hükümler

| # | İddia | Ölçüt | Sonuç | Hüküm | Beklentim |
|---|---|---|---|---|---|
| Ö1 | AUC(`P`) > AUC(`F1`), `yakin` | sınama havuzu, fark aralığı > 0 | −0,002 (−0,010 … +0,005); AYAR'da −0,032 (−0,056 … −0,012) | **ayırt edilemedi** (AYAR'da tutmadı) | tutmaz |
| Ö2 | AUC(`P`) > AUC(`F1`), `yaniltmaz` | aynı | −0,002 (−0,005 … +0,002) | **ayırt edilemedi** | tutar ya da ayırt edilemez |
| Ö3 | 0,90 kesinlik veren eşik var, sınamada ≥ 0,85 | AYAR'da eşik seçimi | hiçbir ölçüde eşik yok | **ölçü elendi** | ölçülemez ya da tutmaz |
| Ö4 | puan 0 → `yanlis` (≥ %85, alt ≥ %80) | sınama havuzu, `Pic` | 240 / 300 (%80,0; %75,1–%84,1) | **tutmadı** | tutar |
| Ö5 | tam eşit olmayanların bir kısmı `yakin` (Wilson alt > %5, ≥ 2 küme) | küme başına oran | AYAR %8,8 (%6,3–%12,4); B %10,0 (%6,7–%14,7); C %10,6 (%6,0–%18,0); A %4,1 (%1,6–%10,1) | **tuttu** | tutar (htop hariç) |
| Ö6 | nüfusun ≥ %10'unun F1 ≥ eşik ikizi var | 21 371 fonksiyon | F1 ≥ 0,5: %76,3; F1 ≥ 0,8: %32,7 | **tuttu** | tutar |
| Ö7 | 119 yanlışın < %15'i "yakın", çoğu örtüşmesiz | taban koşusu | örtüşmesiz 23 / 119 (%19,3); F1s ≥ 0,5: 61 / 119 (%51,3) | **tutmadı** | < %15 |
| Ö8a | AUC(`kimlik`) > AUC(`F1s`) | sınama havuzu | −0,143 (−0,224 … −0,062) | **tutmadı** | tutar ya da ayırt edilemez |
| Ö8c | `kimlik` için 0,90 eşiği | AYAR | en yüksek kesinlik 0,43 | **eşik yok** | yok |
| Ö9a | AUC(`Ridf`) > AUC(`Rs`) | sınama havuzu | +0,001 (−0,007 … +0,008) | **ayırt edilemedi** | ayırt edilemez |
| Ö9b | `Ridf` için 0,90 eşiği | AYAR | en yüksek kesinlik 0,50 | **eşik yok** | yok |

Tutmayan beklentilerim: Ö4, Ö7, Ö8a.

### 2.3 Yasak cevabın ölçümü: "belirteç F1, eşik 0,5"

Tam eşit olmayan çiftlerde "F1 ≥ 0,5" kabulü (`bantlar.json` `esik`):

| Küme | Kabul | `yakin` | `yanlis` |
|---|---|---|---|
| AYAR | 90 | 21 (%23,3; %15,8–%33,1) | 24 (%26,7) |
| Sınama havuzu | 41 | 12 (%29,3; %17,6–%44,5) | 8 (%19,5) |
| Sınama, tmux'suz | 10 | 1 (%10,0; %1,8–%40,4) | 4 (%40,0) |

Sözlüklü `F1s ≥ 0,5`: AYAR 102 kabul, 24 `yakin` (%23,5); sınama havuzu 48 kabul, 17 `yakin` (%35,4; %23,4–%49,6). Eşik 0,8'e çıkınca da AYAR'da 46 kabulün 14'ü `yakin` (%30,4), 13'ü `yanlis`.

### 2.4 Aykırı öncül 1 neden tutmadı

Aday ile GT'nin belirteç kümesi ilişkisine göre vekil etiket (`bantlar.json` `kume_iliskisi`, sözlüklü):

| İlişki | AYAR: n / `yakin` / `yanlis` | Sınama havuzu: n / `yakin` / `yanlis` |
|---|---|---|
| aday ⊂ GT (kesinlik 1, duyarlılık < 1) | 64 / 14 (%21,9) / 19 (%29,7) | 27 / 8 (%29,6) / 7 (%25,9) |
| kısmi (ikisi de < 1) | 119 / 8 (%6,7) / 39 (%32,8) | 92 / 16 (%17,4) / 40 (%43,5) |
| ayrık (örtüşme yok) | 146 / 3 (%2,1) / 115 (%78,8) | 297 / 9 (%3,0) / 239 (%80,5) |

- Kesinliği tam olan adların %26–%30'u "yanıltıcı" etiketli. Ayar kümesinden örnekler: `window_pane_add` ↔ `window_pane_add_ref`, `cmd_run_shell` ↔ `cmd_run_shell_free`, `status_message` ↔ `status_message_set`, `input_csi_dispatch` ↔ `input_csi_dispatch_rm`. Değerlendiricinin gerekçesi: "işin kendisinin adı yardımcıya verilmiş" ya da "getter gibi okunuyor" (rubrik kural 3–4).
- Tersi de geçerli: GT'nin bütün belirteçlerini karşılayıp fazladan belirteç taşıyan adların yarısı `yakin` değil (`sixel_parse_attributes` ↔ `sixel_parse`).
- Örtüşmesi olmayan adların %3'ü yine de `yakin` (`utf_wctomb` ↔ `utf8_fromwc`): sözcük ölçüsü göremez.
- Göreli kapı (`kimlik`: aday en çok bu fonksiyona benziyor) `yakin`i sayamıyor ama `yanlis`i ayırıyor: örtüşen çiftlerde kapıdan geçenlerin yanlış oranı AYAR'da 3 / 33 (%9,1; %3,1–%23,6), geçmeyenlerde 57 / 160 (%35,6); sınama havuzunda 0 / 13 ve 47 / 110 (%42,7). Örneklem küçük: **yön gösterici**.

### 2.5 Sınırlar

- Hüküm kaynağı model. Bu bölümün hiçbir sayısı "insan böyle düşünür" demek değildir.
- `yakin` olumlu sayısı küçük (AYAR 30, sınama havuzu 37, htop 4); htop tek başına hüküm taşımaz.
- P15c etiketleri GT adı görülerek verildi (kör değil); sınama havuzunun tmux'suz hâli ayrıca verildi.
- Sınama kümeleri bu turda üç kez okundu (Ö1–Ö5, Ö8, Ö9). Eşik ya da ağırlık sınama kümesinden seçilmedi.
- Sözlük önsel ve küçük; CodeWordNet gibi öğrenilmiş bir sözlük indirilemediği için denenmedi.

## 3. İkiz yoğunluğu (etiketsiz, mekanik; Ö6)

Komut: `python scripts/arge/olcu/taban_puanla.py --taban $V/taban_a62f15e.json --json $V/taban_puan.json` (`ikiz` bölümü).

Soru: bir fonksiyona **aynı ikilideki başka bir fonksiyonun** GT adı verilse, ölçü bunu "yakın" sayar mı? Ad bekleyen nüfus, GT adlarının tam çift taraması, sözlüksüz F1:

| Birim | Nüfus | F1 ≥ 0,5 ikizi olan | F1 ≥ 0,8 ikizi olan | Kırpılmış adı başka fonksiyonun adı |
|---|---|---|---|---|
| Toplam | 21 371 | 16 305 (%76,3) | 6 987 (%32,7) | 6 995 (%32,7) |
| debian/coreutils | 12 717 | %65,2 | %30,1 | %33,5 |
| debian/tmux | 1 851 | %96,2 | %41,3 | %36,6 |
| mac/tmux | 2 545 | %96,7 | %43,3 | %36,5 |
| debian/zstd | 919 | %94,9 | %57,0 | %38,7 |
| debian/openssl | 563 | %86,7 | %18,1 | %29,8 |
| debian/sqlite3 | 389 | %84,8 | %16,2 | %15,4 |

Okuma: mutlak bir belirteç eşiği, nüfusun dörtte üçünde fonksiyonu kardeşinden ayıramaz. KİMLİK hattının "ikiz" sorunu ölçünün de sorunudur.

## 4. Taban koşusunun yeniden puanlanması (kalem 4)

Komut: `python scripts/arge/olcu/taban_dok.py …` (ürün ağacından; komut betiğin başında) → `taban_a62f15e.json`; sonra `taban_puanla.py`. Döküm `urun_olc` sayılarını yeniden üretiyor: 1 800 ad, 1 681 doğru, 119 yanlış, nüfus 21 371, makro yanlış %31,05.

Ayrık bölgeler: `tam` (bugünkü hüküm) → `bicim` (harf dizisi aynı: büyük / küçük harf, `_`, derleyici eki, `_N` çakışma eki; rubrik v2'nin `tam` tanımı) → `kimlik_adayi` (aday en çok bu fonksiyona benziyor ve F1s ≥ 0,5; hüküm değil, aday) → `ortusen_diger` → `ayrik`.

| Kanal | Ad | tam | biçim | kimlik adayı | örtüşen, öbür | ayrık |
|---|---|---|---|---|---|---|
| `on_ad:gnulib` | 733 | 733 | 0 | 0 | 0 | 0 |
| `on_ad:elf_onyuk` | 458 | 458 | 0 | 0 | 0 | 0 |
| `on_ad:main_giris` | 110 | 110 | 0 | 0 | 0 | 0 |
| `ks1:func_kalibi` | 259 | 246 | 0 | 4 | 9 | 0 |
| `ks1:func_aktarma` (+ birleşik) | 36 | 36 | 0 | 0 | 0 | 0 |
| `ks1:assert_ust` | 7 | 5 | 0 | 0 | 2 | 0 |
| `string_context/oz_ad` | 197 | 93 | 40 | 5 | 36 | 23 |
| **Toplam** | 1 800 | 1 681 | 40 | 9 | 47 | 23 |

**119 yanlışın dökümü:** biçim 40 (%33,6; %25,8–%42,5), kimlik adayı 9, örtüşen öbür 47, ayrık 23 (%19,3). Uzlaşı eşiği (F1s ≥ 0,5) 61'ini (%51,3) "yakın" sayardı; bu sayı ölçü olarak önerilmiyor (§2.3).

**Biçim düzeyinin etkisi (insan hükmü gerektirmez):**

| Hüküm | Havuz yanlış | Makro yanlış | zstd | sqlite3 | tmux | `oz_ad` kesinliği |
|---|---|---|---|---|---|---|
| tam eşitlik | 119 / 1 800 (%6,6; %5,5–%7,8) | %31,0 | %83,6 | %58,3 | %12,0 | 93 / 197 (%47,2; %40,4–%54,2) |
| tam + biçim | 79 / 1 800 (%4,4; %3,5–%5,4) | **%19,1** | %16,4 | %58,3 | %11,8 | 133 / 197 (%67,5; %60,7–%73,7) |

- 40 biçim farkının 37'si zstd: ürün adı GT adının küçük harfli hâli (`fse_builddtable_internal` ↔ `FSE_buildDTable_internal`). Kalan 3: `_2` çakışma eki ve derleyici eki.
- Hedef (makro yanlış ≤ %10) biçim düzeyiyle de tutmuyor (%19,1; sqlite3 %58,3, redis-tools %20,0).
- Kalan 79 adın kaçının "amaçça doğru" olduğu bu turda **söylenemez**: 56'sı örtüşen bantta, 23'ü ayrık. İki insan değerlendirici 79 adın tamamını etiketleyebilir (örnekleme gerekmez).

**Literatürle karşılaştırılabilir ölçü (kalem 3).** Komut: `python scripts/arge/olcu/literatur_olcusu.py --taban $V/taban_a62f15e.json --json $V/literatur_olcusu.json`.

| Tanım | Kaynak (doğrulama tarihi 2026-11-19) |
|---|---|
| Kesinlik / duyarlılık / F1 hedef alt belirteçler üstünde; büyük / küçük harf, sıra ve yineleme duyarsız; alfabetik olmayan karakterler yok sayılır. Örnek: GT "open file", tahmin "open" → kesinlik 1, duyarlılık 0,5. Bölme paket düzeyinde, kopyalar ayıklanmış. | NERO: David, Alon, Yahav, OOPSLA 2020; arXiv 1902.09122, değerlendirme bölümü |
| Sözcük düzeyi: tp = GT'de bulunan tahmin sözcükleri, fp = \|tahmin\| − tp, fn = \|GT\| − tp. Ön işleme: sözcüklere bölme, kök alma, rakam atma. Eşleşmeyen sözcük için CodeWordNet (gömme tabanlı) yakın sözcük arar; GT'de bulunursa doğru sayılır. Bölme ikili düzeyinde 8:1:1. | SymLM: Jin ve ark., CCS 2022, §5 "Evaluation Metrics" (denklem 16–17) |
| Aynı tp / fp / fn; CodeWordNet devralınmış. Örnek: `ftp_timeleft_accept` ↔ `get_time_left` → P 0,67, R 0,50, F1 0,57. | SymGen: Jiang, Jin, Lin, NDSS 2025, §VI-A ve Ek F |

Taban koşusu NERO tanımıyla: ad verilen 1 800 fonksiyonda mikro P 0,959 / R 0,930 / F1 0,944; **ad bekleyen 21 371 fonksiyonun tamamında** (ad verilmeyen = boş tahmin) mikro P 0,947 / R 0,049 / F1 0,094, makro F1 0,058.

Bizim nüfus tanımıyla farklar:
1. Literatür her sınama fonksiyonuna tahmin üretir (çekimserlik yok); biz ad vermeyebiliriz. Tek sayı (F1) kapsamı ve kesinliği karıştırır; iki sayı ayrı verilmeli.
2. Literatürün nüfusu sembollü bütün fonksiyonlar; bizimki Ghidra'nın jenerik bıraktığı ve GT'de adı olanlar (Ghidra'nın kendi adlandırdıkları ve CRT dışarıda).
3. CodeWordNet'li ölçüler gömme benzerliğiyle sözcük eşler: §2'nin gösterdiği yönde cömerttir ve zıt anlamlıları ayırmayabilir (`yontem_taramasi.md` §2.3, IdBench).
4. Toplama biçimi: SymLM denklem 18'de kesinlik ve duyarlılık **fonksiyon başına oranların ortalaması**, F1 bu iki ortalamanın harmonik ortalaması (doğrulandı, aynı PDF). SymGen aynı formülü fonksiyon başına verir ve "ortalama" raporlar. Bu toplamayla taban koşusu: ad verilen 1 800 fonksiyonda P 0,961 / R 0,955 / F1 0,958; nüfusun tamamında (ad verilmeyen fonksiyonun P ve R'si 0) P 0,059 / R 0,058 / F1 0,058 (`literatur_olcusu.json` `symlm_*`).
5. Punstrip'in üç düzeyi ve XFL'in tanımı bu turda birincil kaynaktan doğrulanmadı; `yontem_taramasi.md` §2.2–§2.3'teki ikincil kayıt geçerli.

## 5. Karar kuralı taslağı (kalem 5)

Komut: `python scripts/arge/olcu/karar.py --taban $V/taban_a62f15e.json --json $V/karar.json`.

**Kayıp modeli** (fonksiyon başına): doğru ad 0; boş 1; kanıt satırı e (0 < e ≤ 1; ölçülmedi, parametre); yanlış ad L; doğru aile a (0,25; parametre); yanlış aile L. p olarak kanal kesinliğinin Wilson alt sınırı.

**Kural (belirlenimci):**
1. Kanal c için beklenen kayıp: ad (1 − p_c)·L; aile p_aile·a + (1 − p_aile)·L; kanıt e.
2. En küçük kayıplı düzey seçilir; eşitlikte daha zayıf iddia (kanıt, aile, ad sırasıyla).
3. Kanıtı olan kanal boş yazmaz (K-2; e ≤ 1 olduğu için kanıt boşa baskın).
4. Ad düzeyi koşulu: p_c > 1 − e / L. e = 1'de başa baş oranı L* = 1 / (1 − p_c).
5. Çatışma (B5; geliştirme setinde oynatıldı, §8.1): iki kanal farklı ad veriyorsa p alt sınırı yüksek olan kazanır; ikisi de ad koşulunu sağlamıyorsa ikisi de kanıt satırı olur; iki ad aynı ailedense aile düzeyi yazılır; eşitlikte sabit kanal sırası.

| Kanal | n | tam (Wilson alt) | L* | tam + biçim (alt) | L* | aile, kardeş tanımı (alt) |
|---|---|---|---|---|---|---|
| `on_ad:gnulib` | 733 | 733 (0,995) | 192 | aynı | 192 | 0,995 |
| `on_ad:elf_onyuk` | 458 | 458 (0,992) | 120 | aynı | 120 | 0,992 |
| `on_ad:main_giris` | 110 | 110 (0,966) | 29,7 | aynı | 29,7 | 0,966 |
| `ks1:func_kalibi` | 259 | 246 (0,916) | 11,9 | aynı | 11,9 | 252 (0,945); önek tanımıyla 259 (0,985) |
| `ks1:func_aktarma` | 33 | 33 (0,896) | 9,6 | aynı | 9,6 | 0,896 |
| `string_context/oz_ad` | 197 | 93 (0,404) | 1,7 | 133 (0,607) | 2,5 | 143 (0,660) |
| `ks1:assert_ust` | 7 | 5 (0,359) | 1,6 | aynı | 1,6 | 0,359 |

Okuma:
- **"Yanlış ≤ %10" hedefi L = 10'a, "kesin ≥ %95" L = 20'ye denktir** (e = 1'de).
- L = 10, e = 1, tam + biçim: ad 1 301 (gnulib, ELF önyükü, `main`), aile 259 (`func_kalibi`), kanıt 240. L = 20'de `func_kalibi` de kanıta düşer (ad 1 301, kanıt 499). Kanıt satırı yarım iş görüyorsa (e = 0,5) L = 10'da da aynı sonuç.
- Aile düzeyi kapalı tutulursa (iki düzeyli kural: ad eğer alt sınır > 1 − 1 / L, değilse kanıt): L = 5'te ad 1 593 / kanıt 207; L = 10'da ad 1 560 / kanıt 240; L = 20'de ad 1 301 / kanıt 499 (`karar.json` alt sınırlarından).
- `oz_ad` ad düzeyinde ancak L < 2,5 ise kalır: yanlış ad eksik adın en fazla 2,5 katı zararlı sayılırsa. Hiçbir makul oranda ad kanalı değil; bugünkü hâliyle kanıt satırı kanalıdır. (Kanalın alt sınıfları ayrı ölçülürse bir kısmı ad düzeyine çıkabilir; bu ÖZ KOD hattının işi.)
- `func_aktarma` 33 / 33 doğru ama n küçük olduğu için alt sınırı 0,896: L = 10'da kıl payı kanıta düşüyor. Bu, kuralın "ölçüm azsa iddia zayıf" davranışıdır; daha çok ölçümle değişir.
- Aile düzeyi iki mekanik tanımla sayıldı; hiçbiri insan hükmüyle doğrulanmadı ve ürünün bugün "aile" yazan bir çıktısı yok. `a` ve `e` ölçülmedikçe aile / kanıt ayrımı parametreye bağlıdır.

## 6. Set dışı ölçüm tasarımı (kalem 6)

Ayrıntı ve indirme listesi `PLAN.md` §4'te. Bu turda yeni ikili koşulmadı (Ghidra koşusu ve indirme yok).

**Var olan set dışı kanıt (yalnız gnulib kanalı; onarım paketi P-S3b'nin Ghidra'sız yeniden oynatması, `docs/arge/2026-11-18_onarim/P-S3b.md` "Yamalı toplam" satırı; a62f15e birleşik koşusu değil):** Mach-O (Homebrew; taze gnulib'li 5 program + gcat) 13 doğru / 1 yanlış; korpus Debian 9.4 (GCC, LTO'suz) 35 / 0; korpus Ubuntu 9.4 (GCC 13, LTO'lu) 35 / 0; od / pr 14 / 1. Toplam 97 / 99 (%98,0; Wilson %92,9–%99,4; betik çıktısı `ks1_olc.oran(97, 99)`). Bu, gnulib kanalının başka derleme ve platformlarda da çalıştığının tek kanıtıdır; öbür kanallar için set dışı hiçbir ölçüm yok.

**Örnek sayısı** (`python scripts/arge/olcu/ornek_sayisi.py --bantlar $V/bantlar.json --json $V/ornek_sayisi.json`):

| Hedef | Varsayım | Gereken n |
|---|---|---|
| Oran, Wilson yarı genişlik ±0,05 | beklenen oran 0,10 / 0,30 / 0,50 | 141 / 320 / 381 |
| Oran, ±0,03 | 0,10 / 0,30 / 0,50 | 384 / 892 / 1 063 |
| Oran, ±0,10 (tabaka başına kaba okuma) | 0,10 / 0,30 / 0,50 | 34 / 78 / 93 |
| Kappa, ±0,10 | κ 0,8; olumlu payı 0,30 / 0,10 | 168 / 412 |
| Kappa, ±0,10 | κ 0,7; olumlu payı 0,30 / 0,10 | 240 / 606 |
| AUC standart hatası ≤ 0,03 | AUC 0,80; olumlu payı 0,10 / 0,30 | 826 / 308 |

- "Yakın" oranı (tam eşit olmayan adlarda ~%9) ±0,03 ile ölçülecekse basit rastgele 343, örtüşen / ayrık tabakalı (Neyman) 255 etiket yeter (vekil oranlarla; yön gösterici).
- İnsan etiketleme süresi hiç ölçülmedi (P15c ve G4 süreleri ajan süresidir); ilk 50 öğelik pilotla ölçülmeli.

## 7. Örnek / tekil ayrımı (OLGU ara tesliminden sonra eklendi)

Komut: `python scripts/arge/olcu/tekil.py --olgu ~/karadul_olcum/runs/arge-2026-11-19/olgu/olgu.jsonl.gz --taban $V/taban_a62f15e.json --json $V/tekil.json`. Tekil anahtar OLGU bütçesiyle aynı: (program, tanım dosyası, GT'nin ilk adı); betik bütçedeki 9 257 tekil nüfusu yeniden üretiyor. Tekil ad: (program, ürün adı, GT adı); 535 tekil ad `sonuc.md`'deki "tekil adla kesinlik 422 / 535" ile aynı.

**İkiz yoğunluğu** tekil düzeyde daha yüksek (gnulib yinelemesi sonucu aşağı çekiyormuş):

| | Örnek (21 371) | Tekil (9 257) | Tekil, gnulib dışı (8 720) |
|---|---|---|---|
| F1 ≥ 0,5 ikizi olan | %76,3 | %87,5 (%86,8–%88,2) | %88,7 |
| F1 ≥ 0,8 ikizi olan | %32,7 | %34,7 (%33,7–%35,7) | %35,5 |
| Kırpılmış adı başka fonksiyonun adı | %32,7 | %30,0 | %30,7 |

**Taban koşusunun adları** tekil düzeyde: 535 tekil ad; tam 422, biçim 40, kimlik adayı 9, örtüşen öbür 46, ayrık 18. Yanlış oranı: tam eşitlikte 113 / 535 (%21,1; %17,9–%24,8), tam + biçimde 73 / 535 (%13,6; %11,0–%16,8). İnsan etiketi bekleyen ad sayısı tekil düzeyde 73 (örnek düzeyinde 79).

**Kanal kesinliği tekil düzeyde** (karar kuralı §5'in duyarlılığı):

| Kanal | Örnek: doğru / ad (Wilson alt; L*) | Tekil: doğru / ad (Wilson alt; L*) |
|---|---|---|
| `on_ad:gnulib` | 733 / 733 (0,995; 192) | 10 / 10 (0,723; 3,6) |
| `on_ad:elf_onyuk` | 458 / 458 (0,992; 120) | 30 / 30 (0,887; 8,8) |
| `on_ad:main_giris` | 110 / 110 (0,966; 29,7) | 6 / 6 (0,610; 2,6) |
| `ks1:func_kalibi` | 246 / 259 (0,916; 11,9) | 246 / 259 (0,916; 11,9) |
| `ks1:func_aktarma` | 33 / 33 (0,896; 9,6) | 33 / 33 (0,896; 9,6) |
| `string_context/oz_ad` (tam + biçim) | 133 / 197 (0,607; 2,5) | 129 / 187 (0,620; 2,6) |

Okuma:
- Örnek düzeyi, aynı kuralın 106 ikilide aynı koda uygulanmasını 106 bağımsız gözlem sayar; tekil düzey hiç bağımsız saymaz. Gerçek ikisinin arasındadır (aynı kaynak, ama her ikili ayrı derleme ve ayrı eşleme). İkisi birlikte raporlanmalı.
- Tekil düzeyde L = 10'da **hiçbir ön ad kanalı** ad düzeyi koşulunu sağlamıyor (en yükseği `func_kalibi` 11,9 sağlıyor; ön adlar 2,6–8,8). Bu, kanalların kötü olduğunu değil, **bağımsız kanıtın az olduğunu** gösterir: gnulib kanalı 10 tekil adda, `main` 6 programda sınandı. `MEASURED_PRE_NAME_PRECISION`'ın 0,995'i bu gözle okunmalı; set dışı ölçümün (PLAN §4, P-Ö6–P-Ö8) birinci gerekçesi budur.
- §2'deki etiketli kümelerde yineleme yok (tmux ve htop tek ikili; P15c zaten tekil çiftle sayıldı).

## 8. Sonradan tamamlanan kalemler (zaman kısıtı kalkınca; ön kayıt `DEFTER.md` §14)

### 8.1 Kanal çatışması (B5)

Komut: `PYTHONPATH=~/karadul_olcum/urun-a62f15e python scripts/arge/olcu/catisma.py --agac ~/karadul_olcum/urun-a62f15e --kok ~/karadul_olcum/runs/urun-onarim-a62f15e --mac-veri $R/workspaces/olcum_mac --karar $V/karar.json --json $V/catisma.json`. Veri: köken kayıtlarındaki `runners_up` (uygulanan ad başına en çok 3 yedek aday). Ad verilmeyen fonksiyonların aday listesi kayıtta yok (yalnız sayaç): o taraf **ölçülemez** (açık ölçüm; PLAN §5).

| | Sayı |
|---|---|
| Uygulanan ad | 1 800 |
| Yedek aday (toplam / jenerik / kimlik iddialı) | 2 612 / 496 / 2 116 |
| En az bir çatışan (harf dizisi farklı, kimlik iddialı) yedeği olan ad | 1 300 (%72,2; %70,1–%74,2) |
| Kazananı yanlış (tam + biçim değil) | 79 |
| … bunlardan çatışan yedeği olan | 41 |
| … bunlardan yedeği doğru olan | **0** (Wilson üst %4,6) |

| Yedek strateji | Kimlik iddialı aday | Doğru (tam ya da biçim) | Kazananla aynı ad | Kesinlik |
|---|---|---|---|---|
| `api_call` | 1 298 | 1 | 1 | %0,08 (üst %0,44) |
| `callee_based` | 709 | 1 | 1 | %0,14 (üst %0,79) |
| `string_context` | 109 | 99 | 101 | %90,8 (%83,9–%94,9) |

- Ön kayıt: Ö10a beklentim "gerçek çatışma < 300" idi; **tutmadı** (1 300). Ö10b "≤ 5" **tuttu** (0). Ö10c **tuttu** yönünde: `api_call` ve `callee_based` < %1; `string_context` yedekleri ise %90,8 doğru (beklentim "< %50" idi; **tutmadı** — bu yedekler kazananla aynı adı veren ikinci kanıt).
- İki **ölçülmüş** kanalın çatıştığı durum yalnız 8 (KS-1 ya da `main` kazanan, `string_context` yedek); 8'inde de kazanan doğru.
- Kuralın oynatılması (Ö10d): ölçülmemiş yedek kanal p = 0 sayılınca değişen karar 0 (yeniden üretim). Yedek kanallara bu veride ölçülen kesinlik p olarak verilince değişen karar 1 (`ks1:assert_ust` 0,359 < `string_context` 0,839) ve o karar bir doğru adı kaybettiriyor; aynı veride ölçüm ve uygulama olduğu için **yön gösterici**.
- Okuma: geliştirme setinde birleştiricinin kazananı değiştirmesiyle kazanılacak doğru ad **yok**. B5'in "çatışan çiftlerde seçilen adın kesinliği" sorusu bu sette bugünkü sıralamayla zaten en iyi durumda; kuralın sınanabileceği gerçek çatışma (iki ölçülmüş kanal, farklı ad) ancak yeni ad kanalları açılınca ya da set dışı veride doğar. `api_call` / `callee_based` stratejilerinin ad kanalı olarak ölçülmüş kesinliği ≈ 0: K-2 gereği bunlar ad değil kanıt satırı kanalıdır.

### 8.2 Kalibrasyon (B2), geliştirme seti içi

Komut: `python scripts/arge/olcu/kalibrasyon.py --olgu ~/karadul_olcum/runs/arge-2026-11-19/olgu/olgu.jsonl.gz --json $V/kalibrasyon.json`. Güven = köken kaydının `confidence` alanı (OLGU `guven`); 1 800 adın hepsinde dolu.

| Kanal | n | Ortalama güven | Gerçekleşen (tam) | ECE (tam) | Gerçekleşen (tam + biçim) | ECE (tam + biçim) |
|---|---|---|---|---|---|---|
| `string_context/oz_ad` | 197 | 0,831 | 0,472 | 0,359 | 0,675 | 0,156 |
| `on_ad:gnulib` | 733 | 0,706 | 1,000 | 0,294 | 1,000 | 0,294 |
| `ks1:func_kalibi` | 259 | 0,916 | 0,950 | 0,034 | 0,950 | 0,034 |
| `ks1:func_aktarma` | 33 | 0,896 | 1,000 | 0,104 | 1,000 | 0,104 |
| `on_ad:elf_onyuk` | 458 | 0,992 | 1,000 | 0,008 | 1,000 | 0,008 |
| `on_ad:main_giris` | 110 | 0,966 | 1,000 | 0,034 | 1,000 | 0,034 |
| Toplam (örnek) | 1 800 | 0,840 | 0,934 | 0,125 | 0,956 | 0,122 |
| Toplam (tekil ad) | 535 | 0,876 | 0,789 | 0,138 | 0,864 | 0,063 |

- **Ö11 tutmadı** (beklendiği gibi): `oz_ad`'ın ECE'si 0,359 (tam) ve 0,156 (tam + biçim); eşik ≤ 0,10 idi. Kanal güveni aşırı iyimser.
- `oz_ad`'ın iki güven değeri sıralamayı doğru veriyor ama düzeyi yanlış: güven 0,80 → 76 adın 22'si tam (%28,9), biçimle 39'u (%51,3; %40,3–%62,2); güven 0,85 → 121 adın 71'i tam (%58,7), biçimle 94'ü (%77,7; %69,5–%84,2). Ölçülmüş güven önerisi (biçim hükmü kabul edilirse): 0,80 sınıfı → 0,403; 0,85 sınıfı → 0,695 (Wilson alt sınırları). İki sınıf da L = 10'da ad düzeyi koşulunu sağlamıyor (L* 1,7 ve 3,3).
- Ön ad kanallarında güven bu setin ölçülmüş alt sınırı olduğu için tablo döngüseldir; tek bilgi gnulib satırının bayat olduğudur (0,706 yazılı, 733 / 733 gerçekleşen). Güvenin set dışında tutup tutmadığı **açık ölçüm**dür (veri yok; PLAN P-Ö7, P-Ö8).

### 8.3 Önceki taban (1.22.1, f30ac9a) aynı düzenle

Komut: `taban_dok.py --agac ~/karadul_olcum/urun-f30ac9a --kok ~/karadul_olcum/runs/urun-yeni2-f30ac9a …` → `$V/taban_yeni2_f30ac9a.json`; `taban_puanla.py` → `$V/taban_puan_yeni2.json`. Döküm `urun_olc` sayılarını yeniden üretiyor (2 261 / 1 589 / 672).

| Kol | Ad | tam | biçim | kimlik adayı | örtüşen öbür | ayrık | GT'siz | Yanlış (tam) havuz / makro | Yanlış (tam + biçim) havuz / makro |
|---|---|---|---|---|---|---|---|---|---|
| 1.22.1 | 2 261 | 1 589 | 47 | 33 | 350 | 241 | 1 | %29,7 / %52,8 | %27,6 / %40,8 |
| a62f15e | 1 800 | 1 681 | 40 | 9 | 47 | 23 | 0 | %6,6 / %31,0 | %4,4 / %19,1 |

Onarımın etkisi bölgelerde: ayrık 241 → 23, örtüşen öbür 350 → 47; biçim farkı iki kolda da zstd'den (makroda zstd %86,2 → %20,0 ve %83,6 → %16,4).

### 8.4 KİMLİK hattının yanlış eşlemeleri aynı gözle (aykırı öncül 2b)

Komut: `python scripts/arge/olcu/kimlik_hatalari.py --dok ~/karadul_olcum/runs/arge-2026-11-19/kimlik/hata_dok_kural.json --json $V/kimlik_hatalari_kural.json` (ve `tutucu`). Girdi KİMLİK hattının hata dökümü (salt okundu). Dökümde sınıf sayımı 283 (kural) / 226 (tutucu); örnek listeleri kırpık olduğu için sayılabilen 174 / 135.

| Nokta | Yanlış eşleme (dökümde) | F1 ≥ 0,5 | F1 ≥ 0,8 | Örtüşme yok | Biçim |
|---|---|---|---|---|---|
| kural | 174 | 94 (%54,0; %46,6–%61,3) | 54 (%31,0) | 57 (%32,8) | 0 (üst %2,2) |
| tutucu | 135 | 88 (%65,2; %56,8–%72,7) | 55 (%40,7) | 33 (%24,4) | 0 (üst %2,8) |

- Kimlik eşlemesinin **yanlış** verdiği adların yarısından çoğu uzlaşı eşiğiyle "yakın" sayılırdı; eşleme sıkılaştıkça (tutucu) kalan yanlışlar daha da "benzer" (ikiz) oluyor.
- Biçim düzeyi bu yanlışların hiçbirini kabul etmiyor: `tam + biçim` kimlik eşlemesi için güvenli sayım düzeyidir.
- "Sürüm" bölümündeki 26 yanlışın 24'ü F1 ≥ 0,8: sürümler arası yeniden adlandırma (`DiskIOMeter_display` ↔ `DiskIORateMeter_display`). Bunların yanlış mı aynı fonksiyon mu olduğu GT tanımı sorusudur (KİMLİK hattının kararı).
