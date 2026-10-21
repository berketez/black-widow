# K1 ve K2 ön kaydı (TASLAK)

- **Tarih:** 2026-10-21. İlk taslak 49efb28; T0c güncellemesi aynı gün.
- **Durum:** Taslak. T0b (parametre hizalaması) ve T0c (çıplak Ghidra tabanı) tamamlandı.
  - Kalanlar: [seçim] maddeleri (§5) için Codex danışmanlığı ve Berke'nin kararları; Mac köken kuralının geliştirme setinde denenmesi; sürüm kilidi (§4).
  - Doğrulama setine bakılmadan kesinleşir ve commit'lenir.
- **Plan:** v2.2 §5 (Berke'nin kararı, 2026-10-21): eşikler %95, ölçü tanımları aşağıdaki gibi.
- **Dayanak ölçümler:**
  - T0a (`2026-10-21_g9_t0/dwarf_tip_notu.md` §4-§5);
  - T0b (`2026-10-21_g10_t0b/hizalama_notu.md` §9);
  - T0c (`2026-10-21_g11_t0c/t0c_notu.md`);
  - Onuncu Adam İ3-İ5 (`2026-10-21_v2_1/onuncu_adam.md`);
  - literatür taraması §3.2-§3.3 (`2026-10-21_literatur/yontem_taramasi.md`).
- **İşaretler:** **[seçim Sn]**, §5'teki numaralı madde.

## 1. Ortak zemin

- **Gerçek:** Debian 13 arm64 dbgsym DWARF'ı, `scripts/measurement/dwarf_tip.py` ile (dwz farkında; geliştirme setinde çözülen tip payı %100).
- **Birim:** Ghidra decompiler'ının parametre yuvası (`HighFunction`; C'deki `param_N`, yuva sırasıyla).
  - DWARF `formal_parameter`'a **depolamayla** eşlenir (T0b hizalaması); sırayla eşleme yasaktır.
  - Parametre `ghidra_functions.json`'dan değil decompiler'dan alınır. K1'in Ghidra koşusu Karadul'un C'siyle aynı olmalı: `ghidra_parametre.py` çıktısı ya da Karadul `decompiled/*.c` + yuva eşlemesi.
  - Ad kalıbına (`param_N`) güvenilmez, yuva kullanılır.
- **Dil:** yalnız C birimleri.
  - Birim dili DWARF'tan (`DW_AT_language`) okunur: `dwarf_tip.py`'de fonksiyon kaydının `dil` alanı, `parametre_hizala.py`'de C/C++ ayrımı.
  - Geliştirme setinde C++ olanlar pzstd'nin kendi kodu ve redis-check-aof'taki fast_float (155 parametre).
- **Fonksiyon düzeyinde dışlananlar** (sayıları raporlanır, karar ölçüsüne girmez):
  - adresle eşlenmemiş fonksiyon;
  - klonlar: sonek (`.isra`, `.constprop`, `.part`, `.cold`) VEYA `tekrar` VEYA `sira ≠ somut_sira` VEYA bildirimden düşen parametre. `abstract_origin` tek başına ölçüt değildir; LTO'da her şeyi işaretler;
  - Ghidra thunk'ı (C'si sıçrama; geliştirme setinde 178 fonksiyon);
  - dili C olmayan birim;
  - decompile'ı başarısız fonksiyon.
- **Parametre düzeyinde girme şartları:**
  - DWARF tip sınıfı `yapi*`;
  - depolama kaynağı DWARF (girişteki DWARF konumu);
  - eşleşme türü `tam`.
- **Parametre düzeyinde dışlananlar** (sayıları raporlanır):
  - ABI yedeğiyle eşlenenler, bölünen ve kısmi eşleşmeler. Geliştirme setinde uygun fonksiyonlardaki `yapi*` içinde yok;
  - konumsuz ya da hizalanamayan parametreler (T0b'nin "eşleşmeyen" sınıfları; uygun fonksiyonlarda `ghidra_az` 387, `yigin_eksik` 1);
  - `in_<yazmaç>` girdileri (C'de parametre değil);
  - değişken argümanlı fonksiyonların `...` kısmı ve fazla Ghidra yuvaları (adlı parametreleri girer);
  - değerle geçen yapılar (`yapi_degerle`);
  - kimliği çıkmayan kökler ("çok tanımlı ad", §2.1).
- **Nüfus** (geliştirme seti, T0c; `t0c_notu.md` §3.1):

  | Program | Uygun fonksiyonlarda `yapi*` | Hizalanan | K1 nüfusu |
  |---|---|---|---|
  | redis-tools (3 ikili) | 4 634 | 4 486 | 4 473 |
  | tmux | 2 136 | 2 066 | 2 066 |
  | zstd (2 ikili) | 1 182 | 1 121 | 1 121 |
  | htop | 577 | 547 | 547 |
  | coreutils (12 ikili) | 493 | 450 | 450 |
  | openssl | 397 | 387 | 387 |
  | sqlite3 | 372 | 349 | 349 |
  | tree | 30 | 27 | 27 |
  | **Toplam** | **9 821** | **9 433** (%96,0) | **9 420** |

- **Geliştirme / doğrulama:**
  - Kural ve sayısal alt sınırlar Debian 13 geliştirme setinde (8 program) belirlenir.
  - Kapı doğrulama setinde **tek okumayla** verilir (K1 G19, K2 G23).
  - Doğrulama setine bakarak kural ayarı yapılmaz (`dogrulama_seti_onkayit.md` §2 madde 2-4 ve §14).
  - Mac tarafı kapı gününde newlisp ve nagios dSYM'leriyle ayrıca okunur.
- **Ağırlık:** program başına hesaplanır, programlar arasında **makro ortalama** alınır (plan v2 §7). Geliştirme setinde redis K1 nüfusunun %47,5'i, tree 27 parametre.
  - Çiftler ikili içinde kurulur, program içinde toplanır; programlar arasında birleştirilmez.
- **Mac (dSYM):**
  - Aynı depolama hizalaması kullanılır; yükleme tabanı her ikilide yeniden ölçülür.
  - **ABI yedeği kapalıdır:** Apple arm64 kurallarıyla yeniden yazılmadan kullanılmaz.
  - Apple clang'ın soneksiz klonları (plan T0 (c)) ayrıca denetlenir.
  - Köken kuralının Apple SDK yolu (`.sdk/usr/include/`) sınanmadı (§4).
- **Sürüm kilidi:**
  - Ön kayıt `dwarf_tip.py`, `ghidra_parametre.py`, `parametre_hizala.py` ve `ghidra_tip_tabani.py`'nin commit'li sha256'larını yazar.
  - Hizalama belgesi (`karadul-parametre-hizalama/1`) betik ve Ghidra ikilisinin sha256'larını taşır.

## 2. K1: tip

### 2.1 "Aynı tip" (gerçek eşdeğerlik)

- **Kanonik tip:** typedef soyulur; `const`, `volatile` ve `restrict` atılır; işaretçi derinliği tutulur (araçta `kanonik`).
- **Yerleşim imzası** (`dwarf_tip.py` → `yerlesim`; tam tanım modül belgesinde): tanımın adsız fiziksel yerleşimi, `<tür>/<sizeof>/<öğeler>`.
  - Öğeler: yaprak (ofset, genişlik, skaler/işaretçi), bit alanı (bit ofseti, bit genişliği), dizi (tek öğe: eleman yerleşimi ve sayısı; çok boyutlu dizi katlanır) ve birlik (tek öğe: sıralı ve tekil seçenekler).
  - İç içe yapı düzleşir; statik üye atlanır. Kimlikte SHA-256 özeti (`ozet`) kullanılır.
- **Yapı kimliği (katı düzey;** `dwarf_tip.k1_kimligi`**):**
  - Tanımı olan adlı yapı: (tür, ad, yerleşim özeti). Aynı adlı farklı yerleşimler ayrı tiptir (redis/hiredis `dict`: 56 ve 48 bayt).
  - Tanımı olan anonim yapı: (tür, yerleşim özeti, en küçük takma ad). Takma ad, yalnız typedef ve niteleyici adımlarıyla (işaretçisiz) yapıya varan typedef'tir.
  - Yalnız bildirim (yerleşimsiz kök):
    - erişilen birimlerdeki tanımları tek yerleşimliyse **o tanımın kimliği** (geliştirme setinde 602 parametre);
    - hiç tanımı yoksa (tür, ad, "bildirim") (opak; 396 parametre);
    - aynı ikilide adın farklı yerleşimli birden çok tanımı varsa ("çok tanımlı ad") kök karar ölçüsünden çıkar ve ayrı raporlanır (13 parametre, hepsi redis).
- **Kalıtım ailesi (aile düzeyi;** `dwarf_tip.k1_aile_haritasi`**):**
  - X'in ilk statik olmayan üyesi 0. ofsette ve tipi değerle `struct Y` ise X → Y bağı kurulur (C++'ta 0. ofsetteki taban sınıf da).
  - Birlik X ile ilk üyesi dizi, birlik, işaretçi ya da bit alanı olan X bağ kurmaz.
  - Bağların bağlı bileşeni bir ailedir. Aynı ailedeki tipler aile düzeyinde aynı sayılır.
  - Yalnız tanımı olan yapılarda uygulanır. Geliştirme setinin en büyük ailesi: htop `Object_`, 19 kimlik, 280 parametre.
- **Eşdeğerlik düzeyleri:** K1 iki düzeyde, aynı tabloda raporlanır: **katı** (yapı kimliği) ve **aile** (kalıtım ailesi). **[seçim S1: karar düzeyi]**
- **Birlikler:** `yapi*` içindeki birlikler (K1 nüfusunda 24: redis 21, zstd 2, tmux 1) **[seçim S2: karar ölçüsüne dahil mi]**.
- **Karar ölçüsünün dışında, ayrı raporlanan sınıflar:** `void *` (joker), `char *`, skalerler.

### 2.2 Ölçü

Kümeler Karadul'un tip sınıflarıdır (T3). Program başına, yalnız `yapi*` parametreleri üzerinden; çiftler ikili içinde:

- **Çift kesinliği (karar ölçüsü):** aynı kümeye konan parametre çiftlerinden gerçekte aynı tipte olanların payı. Tek elemanlı kümelerin çifti yoktur; saflığı şişiremezler. Az çiftli program **[seçim S6]**.
- **Çift duyarlılığı:** gerçekte aynı tipte olan çiftlerden aynı kümeye konanların payı.
- **Kapsam:** en az iki üyeli bir kümeye düşen `yapi*` parametrelerinin payı.
  - Kapının paydası **[seçim S4]**.
  - Üç payda yan yana raporlanır: K1 nüfusu, uygun fonksiyonlardaki `yapi*` ve DWARF'taki bütün `yapi*`.
- **Kâhin kapsamı** (tavan, yanında raporlanır): gerçek sınıfı ikilide en az iki üyeli parametrelerin payı, yani kusursuz kümelemenin kapsamı.
- **Tabakalar:** kütüphane kökenli yapılar (`dwarf_tip.py` → `koken`: `sistem` başlığı ya da gnulib) ve program yapıları ayrı tabloda. Kural **[seçim S3]**.
- **Ek (karar dışı):**
  - B-cubed kesinlik ve duyarlılık **[seçim S14: tekillerin tanımı]**;
  - küme başına saflık;
  - değişken başına adlı yapı doğruluğu (literatür §3.2 madde 1; çıplak Ghidra'da §2.3).

### 2.3 Tabanlar (T0c, geliştirme seti; makro)

| Taban | Kapsam (payda K1 nüfusu) | Çift kesinliği katı / aile | Duyarlılık katı |
|---|---|---|---|
| Çıplak Ghidra (adlı yapı tipi = küme) | %6,9 (programlarda %0,0-%32,0) | %100,0 / %100,0 (7 program) | %5,2 |
| Çıplak Ghidra, kütüphane tabakası (`decl_file` kuralı) | %21,7 | %100,0 / %100,0 (6 program) | %12,9 |
| Çıplak Ghidra, program tabakası (`decl_file` kuralı) | %4,4 (yalnız openssl'de sıfırdan büyük) | %100,0 / %100,0 (1 program) | %4,7 |
| `tekil` (her parametre ayrı) | %0,0 | tanımsız | %0,0 |
| `tek_sinif` (ikilideki bütün `yapi*` tek sınıfta = yalnız işaretçi boyutu; şans) | %100,0 | %12,3 / %15,3 (htop %5,7 / %28,5) | %100,0 |
| `kahin_boyut` (bilgi: yapının gerçek `sizeof`'u; araç bilemez) | %85,5 | %75,3 / %75,7 | %82,7 |
| Kâhin tavanı (kusursuz kümeleme) | %95,0 (programlarda %85,2-%98,9) | %100,0 | %100,0 |
| Hizalama tavanı (payda uygun `yapi*`) | %94,5 (toplam %96,0) | — | — |

- Çıplak Ghidra'nın değişken başına adlı tip doğruluğu (makro): `yapi*` %7,7, `char*` %31,3, `void*` %21,1, skaler %44,1, diğer %14,5.
- Ghidra hiçbir parametrede tipi kilitlemiyor (0/25 318).
- Raporda bu tablo K1 sonucunun yanında aynen verilir.

### 2.4 Negatif kontrol

- Küme etiketleri **ikili içinde** karıştırılır **[seçim S8]**. Küme boyut dağılımı korunur; tohumlu, 1 000 kez. Tohum ve yüzdelik yöntemi **[seçim S9]**.
- **Geçme ölçütü [seçim S7]:** gözlenen makro çift kesinliği, karıştırılmış dağılımın %99 yüzdeliğinin en az 0,30 puan üstünde.
- T0c'de geliştirme setinin değerleri:
  - çıplak Ghidra katı 1,000'e karşı 0,385 (fark 0,615), aile 1,000'e karşı 0,478 (fark 0,522);
  - `kahin_boyut` fark 0,600;
  - `tek_sinif` fark 0 (tek küme karıştırmada değişmez).

### 2.5 Kapı

- Doğrulama setinde, makro: çift kesinliği ≥ %95 (S1'de seçilen düzeyde).
- **Kapsam ≥ [seçim S5: alt sınır].**
  - T0c tabanı: çıplak Ghidra %6,9. Tavan: kâhin %95,0.
  - **Öneri %50.** Alt sınır %6,9'un altında kalırsa çıplak Ghidra K1'den geçer: kesinliği %100, negatif kontrol farkı 0,615.
- Negatif kontrol geçer.
- **Tutmazsa** (plan v2.2 §5): tip izi ölçülen hâliyle raporlanır, ürün tip yazmaz (yalnız ad). Düzeltme geliştirme setinde yapılır; doğrulama bir sonraki kapı gününde yeniden okunur.

## 3. K2: yapı

### 3.1 Birim ve gerçek

- **Birim:** T5'te mühürlenen ölçüte göre "doğrulanmış" sayılan yerleşimler. Mühür, P/R hesaplanmadan önce commit'lenir.
- **Sınıfın gerçek tipi:** sınıfa hizalanan parametrelerin çoğunluk DWARF yapısı (K1 katı kimliği) **[seçim S15: çoğunluk eşiği, öneri > %50]**. Çoğunluk yoksa yerleşim değerlendirilemez ve sayısı raporlanır.
- **Yaprak alanlar:** `dwarf_tip.py` yerleşim imzasının öğeleri (iç içe yapılar düzleşmiş, statik üyeler yok).
  - Diziler **[seçim S16]**: eleman düzeyinde ya da tek alan.
  - Birlikler: üyelerden biriyle (bir seçenekle) eşleşme yeter.
  - Bit alanları **[seçim S17]**.

### 3.2 Ölçü

- **Kesinlik (karar ölçüsü):** kurtarılan alanlardan, gerçekte aynı ofsette aynı genişlikte ve aynı işaretçi/skaler sınıfında bir yaprağa denk gelenlerin payı. Program başına hesaplanır, makro ortalama alınır.
- **Şans tabanı:** her kurtarılan alan için, aynı hizalamadaki rastgele bir ofsetin bir yaprağa aynı genişlik ve sınıfla denk gelme olasılığı (analitik). Kesinlikle birlikte raporlanır.
- **Kontroller:**
  - yanlış yapı kimliği: aynı boyut sınıfından rastgele başka bir yapıya karşı puan;
  - yalnız ofset 0: yalnız 0. ofsetteki alanların payı.
- **Kapsam:** alan kapsamı (gerçek yapraklardan kurtarılanların payı) ve sizeof doğruluğu.
- **Ek (karar dışı):**
  - yapı başına "tam doğru yerleşim" oranı **[seçim S19: eşleşme tanımı]** (XTRIDE, ReSym);
  - TRex tarzı öncelikli puan: işaretçi mi → düzey → yapı mı → genişlik → işaret **[seçim S20]**;
  - Ghidra'nın "Auto Fill in Structure" çıktısı uygulayıcı tabanı olarak (T4'te ölçülür).

### 3.3 Kapı

- Doğrulama setinde, makro: alan kesinliği ≥ %95.
- Şans tabanı ve kontroller raporlanır **[seçim S18: şans tabanı üstü için alt sınır]**.
- **Tutmazsa:** geri yazma yalnız ad kipinde kalır; yapı izi raporlanır.

## 4. Kesinleşmeden önce

1. ~~T0b: hangi parametreler hizalanıyor, eşleşmeyenlerin dağılımı.~~ Tamam (`hizalama_notu.md`).
2. ~~T0c: çıplak Ghidra'nın adlı tip doğruluğu ve geliştirme setinde kapsam tabanı.~~ Tamam (`t0c_notu.md`).
3. ~~Araç: `DW_AT_language` ve yerleşim imzası çıktısı.~~ Tamam: `dil` (T0b); `yerlesim`, `ilk_uye`, `takma_adlar`, `koken` ve K1 kimlik fonksiyonları (T0c).
4. **[seçim]** maddeleri (§5) için Codex danışmanlığı. Berke'nin kararları özellikle S1 (plan v2.2 §5'in kalıtım cümlesiyle ilişkisi), S3 ve S5'te.
5. Mac: köken kuralı (Apple SDK yolu) ve ABI yedeğinin kapalı çalışması Mac'in dSYM'li **geliştirme** ikililerinde denenir. Doğrulama setinin newlisp ve nagios'una bakılmaz.
6. Sürüm kilidi: betiklerin commit'li sha256'ları §1'e yazılır. Negatif kontrolün K1 tohum metni (S9) yazılır.
7. Sonra bu belge "TASLAK" ibaresinden çıkarılıp commit'lenir; ancak ondan sonra doğrulama setine bakılır.

## 5. [seçim] maddeleri: öneri ve gerekçe

Öneriler geliştirme setine dayanır (T0b, T0c); doğrulama setine bakılmadı. Karar Berke'nin; maddeler Codex'e danışılacak.

| No | Madde | Seçenekler | Öneri | Gerekçe (tek cümle) |
|---|---|---|---|---|
| S1 | K1 karar düzeyi (§2.1) | katı · aile | **katı**; aile aynı tabloda | Aile düzeyinde şans kesinliği htop'ta %5,7'den %28,5'e çıkıyor (19 kimlik, 280 parametrelik `Object_` ailesi), hiyerarşiyi tek sınıfa toplayan bir T3 ödüllendirilir ve geri yazmada yanlış yerleşim üretir. Not: plan v2.2 §5 "kalıtım ailesi tek aile sayılır" diyor; katı seçilirse aile düzeyi ek ölçü olur ve T3'te önek ilişkisi birleştirmeyle değil alt tip kenarıyla kurulur (literatür §1 madde 3). |
| S2 | Birlikler karar ölçüsüne dahil mi (§2.1) | dahil · ayrı sınıf | **dahil** | Kimlikleri yapılarla aynı kuralla tanımlı ve nüfusun %0,25'i (24/9 420); ayrı kural yalnız karmaşıklık ekler. |
| S3 | Kütüphane tabakasının kuralı (§2.2) | yalnız `decl_file` (sistem + gnulib) · `decl_file` + opak tip kütüphane (`tanimsiz_dis`) | **`decl_file` + opak tip kütüphane**; gömülü bağımlılıklar (redis `deps/`, tmux `compat/`) program | İkilide tanımı olmayan tipin yerleşimi programın dışındadır. openssl ve sqlite3 CLI'ları kütüphanelerinin kaynak ağacında derlendiği için `decl_file` kuralı 272 + 110 API parametresini "program" sayıyor; bu kuralla "bilinmiyor" tabakası (38) da sıfırlanıyor. |
| S4 | Kapsamın kapı paydası (§2.2) | K1 nüfusu · uygun fonksiyonlardaki `yapi*` · DWARF'taki bütün `yapi*` | **K1 nüfusu**; öbür ikisi raporlanır | Hizalama kaybı (%4,0) Ghidra'nın parametreyi görmemesinden geliyor (T0b); kapı tip kümelemesini ölçmeli. |
| S5 | Kapsam alt sınırı (§2.5) | %25 · %37 · **%50** · kâhin tavanına göre oran | **%50** (makro, payda K1 nüfusu) | Taban (%6,9) ile kâhin tavanı (%95,0) arasındaki açığın yarısı: (0,069 + 0,950) / 2 ≈ 0,51. Seçenekler: %37 (taban + 0,30, negatif kontrolle aynı pay); %25 (tabanın ~3,5 katı, en gevşek); program başına kâhin kapsamına oran ≥ 0,5. Program tabakası için ayrı alt sınır önerilmiyor (tek karar ölçüsü; Ghidra'nın program tabakası kapsamı %4,4 raporlanır). |
| S6 | Az çiftli program (§2.2) | ≥ 1 çift · ≥ 10 çift | **≥ 10 çift** kesinlik makrosuna girer; dışarıda kalanlar listelenir; kapsam bütün programlarda sayılır | Tabanda htop, tree ve zstd tek çiftle %100 ve karıştırılmış %99 yüzdeliği 1,0; tek çiftlik bir program makroyu 1/8 oynatıyor. |
| S7 | Negatif kontrol geçme ölçütü (§2.4) | fark ≥ 0,30 · başka pay | **fark ≥ 0,30** | Bilgi taşıyan kümelemeler bu payı iki katı aşıyor (Ghidra 0,615, `kahin_boyut` 0,600); tek küme 0 farkla düşüyor. |
| S8 | Karıştırma birimi (§2.4) | ikili içinde · program içinde | **ikili içinde** | Çiftler ikili içinde tanımlı; program içi karıştırma ikililer arası küme kurar. |
| S9 | Tohum ve yüzdelik (§2.4) | — | K1 kapısı için önceden yazılmış ayrı tohum metni (öneri: `karadul-k1-negatif-kontrol`), tek `random.Random` akışı, ikililer sıralı, 1 000 karıştırma; yüzdelik en yakın sıra `v[⌈0,99·n⌉ − 1]` | Kapı günü hesabı belirlenimci ve T0c koşusundan bağımsız olur. |
| S10 | "Çok tanımlı ad"ın anlamı (§2.1) | birden çok tanım · farklı yerleşimli birden çok tanım | **farklı yerleşimli birden çok tanım** | Aynı yerleşimli kopyalar aynı tiptir. Geliştirme setinde dışarıda kalan yalnız redis'in 4 adı (13 parametre); `iovec`'in iki aynı yerleşimli tanımı tek kimlik oluyor. |
| S11 | Bildirim kökü tanıma çözülür mü (§2.1) | evet · hayır | **evet** (tek yerleşimli tanım varsa) | Çözülmezse aynı tip 602 parametrede "bildirim" ve "tanım" diye iki kimliğe bölünür. |
| S12 | Anonim yapı kimliği (§2.1) | yalnız yerleşim · yerleşim + en küçük takma ad · konum | **yerleşim + en küçük takma ad** | Aynı anonim yapının kopyaları aynı kimliği alır (T0a: 31 grup); aynı yerleşimli farklı typedef'li anonim yapılar ayrılır. |
| S13 | Kalıtım bağının tanımı (§2.1) | 0. ofsette değerle gömülü yapı · fiziksel önek ilişkisi (yerleşim öneki) | **gömme bağı** | Saf önek ilişkisi, tek işaretçili küçük yapıları her işaretçiyle başlayan yapının ailesine rastlantıyla sokar. |
| S14 | B-cubed'de tekiller (§2.2) | — | kesinlik en az iki üyeli kümelerdeki öğelerde, duyarlılık gerçek sınıfı en az iki üyeli öğelerde ortalanır | Tekil küme kesinliği, tekil gerçek sınıf duyarlılığı kendiliğinden 1 yapıp şişirir. |
| S15 | K2: sınıfın gerçek tipi için çoğunluk eşiği (§3.1) | > %50 · çokluk | **> %50** | Çokluk (plurality) karışık bir sınıfta azınlıktaki yapıyı gerçek sayabilir; çoğunluk yoksa yerleşim değerlendirilemez sayılır. |
| S16 | K2: diziler (§3.1) | eleman düzeyinde · tek alan · karma | **karma**: kesinlikte dizinin bir elemanına (ya da bütün diziye) denk gelen alan doğru; kapsamda dizi tek yaprak | Dizi elemanına erişim doğru bir alan kurtarımıdır; eleman başına yaprak saymak 4 096 baytlık bir arabelleği kapsamda 4 096 yaprak yapar. |
| S17 | K2: bit alanları (§3.1) | bit düzeyinde yaprak · depolama birimi | **depolama birimi**: bit alanları üye tipinin boyutunda hizalı birime toplanır, birim tek skaler yaprak | Makine kodu bit alanlarına depolama birimini okuyarak erişir; bit düzeyi bayt erişiminden kurtarılamaz. |
| S18 | K2: şans tabanı üstü alt sınır (§3.3) | — | **kesinlik − şans tabanı ≥ 0,30** | K1'in negatif kontrol payıyla aynı; şans tabanı T4 öncesi hesaplanamıyor, sayısal taban bu yüzden yok. |
| S19 | K2: "tam doğru yerleşim" eşleşmesi (§3.2) | — | yapı başına kurtarılan yaprak kümesi, dolgu hariç gerçek yaprak kümesine eşit (dizi ve bit alanı S16 ve S17'deki gibi); ek ölçü | Literatürdeki "tam doğru yerleşim" oranının (XTRIDE, ReSym) bu imzayla belirlenimci karşılığı. |
| S20 | K2: TRex öncelikli puanı (§3.2) | ek ölçü · yok | **ek ölçü**, karar dışı | TRex kıyası için gerekli; karar ölçüsü tek kalır. |

## 6. Değişiklik kaydı

- **2026-10-21, ilk taslak** (49efb28).
- **2026-10-21, T0c güncellemesi.** Her değişikliğin gerekçesi (bulgu ya da kaynak):

| # | Yer | Değişiklik | Gerekçe |
|---|---|---|---|
| D1 | §1 Birim | Eşleme birimi yuva; depolamayla eşleme; sırayla eşleme yasak; kaynak decompiler | T0b §9 madde 1-2: sırayla eşleme 498 parametreyi yanlış bağlıyor (100'ü klon dışı `yapi*`); `ghidra_functions.json` parametre taşımıyor (§4.3) |
| D2 | §1 Dil | "[T0c] araca eklenecek" kalktı | T0b'de yapıldı: `dil` alanı (`DW_AT_language`), C++ 155 parametre (T0b §9) |
| D3 | §1 Dışlananlar | Ghidra thunk'ı ve decompile'ı başarısız fonksiyon eklendi | T0b §9 madde 3 (178 thunk fonksiyonu; C'si sıçrama) |
| D4 | §1 Dışlananlar | Klon tanımına "bildirimden düşen parametre" eklendi | T0b §9: yalnız bu nedenle klon sayılan 20 fonksiyonun hepsi pzstd'de (C++), nüfus değişmiyor |
| D5 | §1 Parametre | Girme şartları (`yapi*`, DWARF depolaması, `tam`); ABI yedeği, bölünen ve kısmi eşleşmeler, `in_<yazmaç>`, fazla yuvalar dışarıda; değişken argümanlı fonksiyonların adlı parametreleri içeride | T0b §9 madde 3 ve 6 |
| D6 | §1 Nüfus | Program başına tablo: 9 821 uygun, 9 433 hizalanan (%96,0), 9 420 K1 | T0c §3.1 (T0b §9 madde 4-5 aynen yeniden üretildi) |
| D7 | §1 Mac | ABI yedeği kapalı; yükleme tabanı ölçülür; soneksiz klonlar denetlenir | T0b §9 madde 8 (Apple'da değişken argümanlar yığında, yığın argümanları paketli) |
| D8 | §1 Sürüm kilidi | Dört betiğin sha256'sı ön kayda girer | T0b §9 madde 7 |
| D9 | §2.1 | Yerleşim imzasının tanımı (adsız, düzleşmiş; dizi ve birlik tek öğe) | Görev T0c madde 1; tanım ve gerekçe `t0c_notu.md` §1.1; bağımsız hesap 704/704 aynı |
| D10 | §2.1 | Bildirim kökü, tek yerleşimli tanımı varsa o tanımın kimliğini alır | T0c bulgusu: 602 parametre; taslaktaki (tür, ad, "bildirim") kimliği aynı tipi ikiye bölüyordu |
| D11 | §2.1 | "Çok tanımlı ad" = farklı yerleşimli birden çok tanım | T0c: aynı yerleşimli kopyalar aynı tip (`iovec`); dışarıda kalan 13 parametre (redis `dict` ailesi) |
| D12 | §2.1 | Anonim yapı kimliğindeki typedef adı "en küçük takma ad" olarak tanımlandı | T0c takma ad dizini; T0a §5 madde 2 (ofset kimliği anonim tipleri böler) |
| D13 | §2.1 | Kalıtım bağının ayrıntısı: birlik ve dizi, işaretçi, bit alanı ilk üye bağ kurmaz; C++ taban sınıf; zincir | T0c uygulaması; literatür §2.1 (c) fiziksel alt tipleme |
| D14 | §2.1-§2.2 | Katı ve aile düzeyi aynı tabloda; karar düzeyi S1 | Literatür §3.2 madde 2 (TRex: izdüşüm tanımı sonucu bir mertebe değiştirebiliyor); T0c: aile düzeyi htop'ta şans kesinliğini %5,7'den %28,5'e çıkarıyor |
| D15 | §2.2 | Kütüphane ve program tabakaları; köken kuralı `dwarf_tip.py` → `koken` | Literatür §3.2 madde 3 (SURE'25 decompiler yapı başarısını adlı kütüphane yapılarında ölçebildi); T0c: çıplak Ghidra'nın bütün kapsamı kütüphane prototiplerinden geliyor |
| D16 | §2.2 | Kapsamın üç paydası ve kâhin kapsamı | T0b §9 madde 5; T0c §3.6 |
| D17 | §2.3 (yeni) | Tabanlar tablosu: çıplak Ghidra, `tekil`, `tek_sinif`, `kahin_boyut`, iki tavan | Literatür §3.2 madde 4; T0c §3.2-§3.6 |
| D18 | §2.2 | B-cubed'de tekillerin tanımı (S14) | T0c uygulaması; Amigó+ 2009 (literatür §2.3) |
| D19 | §2.4 | Karıştırma birimi "program içinde" yerine "ikili içinde" | T0c: çiftler ikili içinde kurulduğu için (T0b §9 madde 4) program içi karıştırma tanımsız çift üretir |
| D20 | §2.4 | T0c değerleri eklendi; tohum ve yüzdelik yöntemi S9 | T0c §3.5 |
| D21 | §2.5 | Kapsam alt sınırı için taban, tavan ve öneri | T0c §3.6; karar Berke'nin (S5) |
| D22 | §3.1 | Yapraklar yerleşim imzasının öğeleri; bit alanları maddesi (S17) | T0c: imza bit alanını bit düzeyinde tutuyor; K2'de karşılaştırma birimi seçilmeli |
| D23 | §3.2 | Ek ölçüler: tam doğru yerleşim (S19), TRex öncelikli puanı (S20), Ghidra "Auto Fill in Structure" tabanı | Literatür §3.3 madde 1-2 |
| D24 | §4 | Tamamlanan maddeler işaretlendi; Mac köken kuralının geliştirme setinde denenmesi ve tohum metni eklendi | T0c §4 (Apple SDK yolu sınanmadı) |
