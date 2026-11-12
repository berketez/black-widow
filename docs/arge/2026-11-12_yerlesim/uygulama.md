# Yerleşimde adres sırası: uygulama, sayım ve geliştirme setinde yeniden üretim

- **Tarih:** 2026-11-12.
- **Durum:** ürün kodu bayrak arkasında, öntanımlı KAPALI. **Bu belgedeki uyum sayıları GELİŞTİRME SETİNDENDİR ve ön kayıtsızdır; ürün iddiası değildir.** Eşik (16) ve hizalama (32) dünkü keşifte bu sette seçilmişti; burada yeniden ayarlanmadı.
- **Dayanak:** `docs/arge/2026-11-11_harita/harita_sonuc.md` (ön kayıtlı ölçüm; ürün 0,097, B1 0,424) ve `yerlesim_kesfi.md` (ön kayıtsız keşif; S2 0,705).
- Bu belgede fonksiyon adı ve kaynak dosya adı geçmez. Etiketler: **[hesap]** = JSON'daki sayılardan elle türetildi; **[yön gösterici]** = doğrulayıcısı yok.

## 1. Özet

| Soru | Cevap | Sayının kaynağı |
|---|---|---|
| Bayrak kapalıyken çıktı değişti mi? | Hayır. 119 saklı çalışma alanının 119'unda yeniden kurulum, saklı proje ağacıyla bayt bayt aynı. | `kurulum_denetimi.md` |
| Ürün, keşfin 0,705'ini üretiyor mu? | Evet. Bayrak açık ürün çıktısı, 114 ikilinin 114'ünde keşifle aynı ARI'yi (6 hane) ve aynı bölmeyi veriyor; makro 0,705. | `gelistirme_yeniden_uretim.md` |
| Sinyal her ikilide var mı? | Hayır. Debian 13 / GCC 14 ikililerinin 117'sinde var. GCC 13 ile derlenmiş 10 ikilinin 6'sında ve iki Mach-O ikilisinin 1'inde yok; kalan 5'inde yalnız başıboş 1–2 dolgu var. | `dolgu_sayimi.md` |
| Eşik neden 16? | GCC 14'ün AArch64 öntanımlı ayarı fonksiyonu 32'ye, en çok 15 bayt atlayarak hizalar; bağlayıcı nesne dosyasını 32'ye tamamlar. 16–28 baytlık dolgu yalnız nesne sınırında oluşur. | §5; GCC ve binutils kaynağı |
| Nerede bozuluyor? | Başka derleyici sürümünde (GCC 13: bant 12 bayttır, 16'da görünmez), Mach-O / clang'da (dolgu yok), LTO'da (sınır LTO bölümüdür). | §3, §7 |

## 2. Ürün bugün ne yapıyor (bayrak kapalı)

`karadul/reconstruction/c_project_builder.py`, `build()`:

1. Her fonksiyon `_classify_subsystem` ile sınıflanır: çağırdığı içe aktarılmış adlar ve kendi adı, sekiz API kural kümesiyle (network, crypto, file_io, concurrency, memory, process, objc_runtime, ui) eşleşirse puan alır; en yüksek puanlı küme kazanır. Eşleşme yoksa `misc`.
2. `misc` kalanlar `_detect_communities` ile çağrı grafında etiket yayılımına girer (en çok 20 tur). En az 3 üyeli topluluklar `group_N` olur; kalanlar `misc`'te kalır.
3. Giriş noktası adlı fonksiyonlar `src/main.c`'ye yazılır.
4. Her grup bir `src/subsystem_<ad>/` dizinidir. Fonksiyon başına bir dosya; kısa fonksiyonlar (10 satırdan az) ve `thunk_` adlılar dizinin `thunks_and_stubs.c` dosyasında toplanır.

- **Dizin sayısı seçilmez, ortaya çıkar:** en çok 8 kural dizini + topluluk sayısı + `misc`.
- **Adres hiç kullanılmaz.** Kurucu yalnız `ghidra_call_graph.json` okur.

## 3. GT'siz mekanizma denetimi: dolgu sayımı

- Betik: `scripts/measurement/yerlesim_dolgu_say.py`. Çıktı: `dolgu_sayimi.json` / `.md` (ikili başına tablo orada).
- Okunan: `ghidra_functions.json` (adres, boyut, thunk) ve `ghidra_combined_results.json` (bellek blokları). Hata ayıklama bilgisi, GT ve ürünün modül ataması okunmaz.
- Dolgu: aynı bellek bloğundaki ardışık iki fonksiyon arasında, öncekinin bitişinden sonrakinin başına; yalnız yürütülebilir blokta ölçülür.
- Kaynaklar: `urun-yeni-93a2956` (Debian 13: 117 ELF; Mac: 2 Mach-O) ve `aday-f893d72` (Debian coreutils 9.4-3: 5 ELF; Ubuntu 24.04 coreutils, LTO: 5 ELF). Ubuntu / LTO koşusu olarak elde yalnız bu vardı.

### 3.1 Dağılım

| Grup | Derleyici | İkili | Ölçülen çift | negatif | 0 | 1–15 | 16–31 | ≥ 32 | Sinyalsiz ikili |
|---|---|---|---|---|---|---|---|---|---|
| Debian 13 coreutils | GCC 14.2 | 106 | 28 488 | 126 | 14 855 | 11 332 | 2 002 | 173 | 0 |
| Debian 13 htop | GCC 14.2 | 1 | 964 | 0 | 501 | 416 | 45 | 2 | 0 |
| Debian 13 openssl | GCC 14.2 | 1 | 3 962 | 8 | 1 994 | 1 917 | 42 | 1 | 0 |
| Debian 13 redis-tools (LTO) | GCC 14.2 | 4 | 12 462 | 7 | 7 312 | 5 015 | 109 | 19 | 0 |
| Debian 13 sqlite3 | GCC 14.2 | 1 | 899 | 4 | 482 | 410 | 3 | 0 | 0 |
| Debian 13 tmux | GCC 14.2 | 1 | 2 360 | 0 | 1 323 | 968 | 67 | 2 | 0 |
| Debian 13 tree | GCC 14.2 | 1 | 180 | 0 | 129 | 40 | 10 | 1 | 0 |
| Debian 13 zstd (pzstd dahil) | GCC 14.2 | 2 | 2 377 | 1 | 1 324 | 971 | 58 | 23 | 0 |
| Mach-O (htop, tmux) | clang | 2 | 3 605 | 18 | 3 568 | 12 | 2 | 5 | 1 (htop) |
| Debian coreutils 9.4-3 | GCC 13.2 | 5 | 841 | 0 | 585 | 252 | 2 | 2 | 3 |
| Ubuntu 24.04 coreutils (LTO) | GCC 13.2 | 5 | 457 | 0 | 375 | 78 | 2 | 2 | 3 |

- Derleyici sürümü ikililerin hata ayıklama dosyalarındaki `GCC:` satırından okundu (`tree`, eski Debian `cat`, Ubuntu `cat`); grubun öbür ikilileri için varsayımdır. Mach-O'da derleyici sürümü okunmadı.
- **Debian 13:** 117 ikilinin hepsinde bant dolu. Coreutils'te ikili başına 12–53 (tek istisna 34 fonksiyonluk `libstdbuf.so`: 1). En seyrek: sqlite3 (3; birkaç kaynak dosyalı program).
- **Mach-O:** htop'ta 604 ana kod çiftinin 604'ünde dolgu 0. tmux'ta 2 598 çiftin 2 561'inde 0; bantta 2 dolgu var (16 ve 20 bayt). Fonksiyon başlangıçları 32'ye göre sekiz kalana eşit dağılıyor: hizalama 4 bayt, dolgu yok.
- **GCC 13 (iki grup):** dolgular 0, 4, 8, 12. Bantta toplam 4 dolgu var (10 ikilide); bunlar rejimin parçası değil.

### 3.2 "Sinyal yok" tanımı (ürüne giren)

- **Tanım:** yürütülebilir bloklarda 16 ≤ dolgu < 32 olan hiç çift yoksa ikilide dolgu sinyali yoktur. Parametresizdir (eşik ve hizalama dışında sayı içermez).
- **Bu tanımla sinyalsiz:** 129 ikiliden 7: Mach-O htop; eski Debian `comm`, `expr`, `wc`; Ubuntu `cat`, `comm`, `cut`.
- Üst uç neden dışarıda: ≥ 32 baytlık aralık dolgu değildir. Varsayılan rejimde dolgu 28 baytı geçemez (§5); bu aralıklar düzensiz boydadır (36, 40, …, 4 100) ve büyük olasılıkla Ghidra'nın fonksiyon saymadığı kod ya da veridir **[yön gösterici]**. Yalnız böyle aralığı olan ikili sinyalli sayılmaz.
- Dilimleme kuralı ise dünkü S2'dir: sınır dolgu ≥ 16 iken konur (≥ 32 dahil). Değiştirilmedi.

### 3.3 Tanımın zayıf yeri: başıboş dolgu

- Rejimi farklı 12 ikiliden 5'i bantta 1–2 başıboş dolgu taşıyor ve tanıma göre "sinyalli": Mach-O tmux (2), eski Debian `cat` (1), `cut` (1), Ubuntu `expr` (1), `wc` (1).
- Bayrak açıkken bu ikililer adres yerleşimine giriyor ve kod bloğu neredeyse bölünmüyor: eski Debian `cat`, `cut` ve Ubuntu `wc`'de `.text` 2 gruba, Ubuntu `expr`'de 3 gruba ayrılıyor; Mach-O tmux'ta `__text` 8 gruba ayrılıyor ve en büyük grup birimlerin 0,616'sını taşıyor (`kurulum_denetimi.md`).
- Bu ikililerde GT yok ya da okunmadı; yerleşimin ne kadar kötü olduğu ölçülmedi. Tek grupluk bir bölmenin ARI'si tanım gereği 0'dır.
- **Aday rejim göstergesi (GT'siz; ürüne GİRMEDİ):** ana kod bloğunda "yasak kalanlı" başlangıç payı. Kalanı (32'ye göre) 16'dan büyük olan başlangıç, varsayılan rejimde oluşmaz: derleyici oraya gelmişse sınıra kadar doldurur.

| Grup | Yasak kalanlı başlangıç payı (ikili başına en az – en çok) | Pozitif dolgudan sonra 32'ye hizalı başlangıç |
|---|---|---|
| Debian 13, GCC 14.2 (117 ikili) | 0,000 – 0,029 | 0,981 – 1,000 (program başına) |
| Debian coreutils 9.4-3, GCC 13.2 (5) | 0,124 – 0,146 | 0,510 |
| Ubuntu 24.04, GCC 13.2, LTO (5) | 0,100 – 0,167 | 0,468 |
| Mach-O (2) | 0,346 – 0,367 | 0,211 |

- Gruplar ayrık. Beklenen değerler mekanizmadan: varsayılan rejimde 0; 16'ya hizalı rejimde 1/8; hizalamasız kodda 3/8 **[hesap]**. Gözlenenler bunlarla uyumlu.
- Bir kapı (ör. pay < 1/16) başıboş beş ikilinin beşini de eski yerleşime döndürür ve geliştirme setinde hiçbir sonucu değiştirmez. Uygulanmadı: yeni bir sayı getirir, seçim ana oturumundur (`onkayit_taslak.md` §6).
- Denenip bırakılan parametresiz seçenek: "yasak kalanlı başlangıç sayısı < bant dolgusu sayısı". Geliştirme setinde zstd'yi yanlış eler (26 ↔ 23).

### 3.4 PLT girişleri (keşif belgesi §7'deki uyarı)

- Keşifte PLT girişi ile metin içi sarmalayıcı GT'siz ayrılamamıştı. Üründe ayrım Ghidra'nın bellek bloklarıyla yapılır (`ghidra_combined_results.json` → `program_info.memory_blocks`): dilim blok sınırını aşamaz.
- Sonuç: PLT girişleri (`.plt`, Mach-O'da `__stubs`) ve dış fonksiyon yer tutucuları (`EXTERNAL`) kendi gruplarında kalır; metin içi sarmalayıcı adres komşularıyla aynı gruptadır. Ad listesi kullanılmaz; yalnız blok sınırı ve yürütme izni.
- `EXTERNAL` yürütülemez bloktur; içindeki aralıklar dolgu sayılmaz, blok tek gruptur.
- Sayım: 129 ikilinin 129'unda blok bilgisi var. Thunk'ların yeri (Debian 13 coreutils): ana kod bloğunda 482, başka yürütülebilir blokta 14 310, yürütülemez blokta 7 661.
- Ana kod bloğu dışında bant dolgusu yok: 129 ikilinin 129'unda banttaki bütün dolgular ana kod bloğunda (ör. openssl'in PLT bloğu: 3 362 fonksiyon; dolgular 0, 4, 8).
- Blok kuralı geliştirme setinde nüfusun bölmesini değiştirmedi: 114 ikilinin 114'ünde bloklu ve bloksuz dilimleme aynı (§4.2). Nedeni: nüfustaki fonksiyonların hepsi `.text`'te.
- Blok bilgisi yoksa sınır yalnız dolguyla konur ve günlüğe uyarı yazılır; PLT o zaman komşu koddan yalnız dolguyla ayrılır.

## 4. Geliştirme setinde yeniden üretim

- Betik: `scripts/measurement/yerlesim_urun_olc.py`. Çıktı: `gelistirme_yeniden_uretim.json` / `.md` (ikili başına tablo orada).
- Yöntem: kurucu, saklı çalışma alanındaki gerçek girdisiyle (`reconstructed/annotated`) geçici dizine yeniden çalıştırılır. Bayrak açık ağaç, ön kayıtlı ölçümün okuyucusuyla (`harita_olc.urun_oku`) okunur ve aynı ölçüyle (`harita_olc.olculer`, `makro`) değerlendirilir. Nüfus ve GT sınıf kodları `harita_olcumu.json`'dan (`ogeler`) alınır; GT yeniden okunmaz.
- Sağlama (bulunan = beklenen): ürün-eski 0,097077 = 0,097077; B1 0,423659 = 0,423659; keşif S2 0,704539 = 0,704539.

### 4.1 Program başına ARI (dosya düzeyi)

| Satır | Makro | coreutils | htop | openssl | redis-tools (LTO) | tmux | tree | zstd |
|---|---|---|---|---|---|---|---|---|
| Ürün, eski (bayrak kapalı) | 0,097 | 0,335 | 0,019 | 0,083 | 0,078 | 0,009 | 0,077 | 0,079 |
| B1 (adres sırası, eşit bölme) | 0,424 | 0,296 | 0,515 | 0,412 | 0,354 | 0,432 | 0,492 | 0,464 |
| Keşif S2 (`s2_dolgu16`) | 0,705 | 0,605 | 0,650 | 0,877 | 0,385 | 0,793 | 0,911 | 0,710 |
| **Ürün, yeni (bayrak açık)** | **0,705** | 0,605 | 0,650 | 0,877 | 0,385 | 0,793 | 0,911 | 0,710 |
| Duyarlılık: sınır yalnız [16, 32) bandında | 0,699 | 0,613 | 0,637 | 0,877 | 0,354 | 0,793 | 0,911 | 0,710 |

- Yeni ürün − B1, program başına: +0,309; +0,135; +0,465; +0,031; +0,362; +0,419; +0,246. Makro +0,281; yedi programın yedisinde pozitif. Dünkü ön kaydın karar kuralıyla (0,05; 2/3) okunursa `urun_gecer`. **Bu bir karar değildir:** kural bu soruya ön kayıtlı değildi ve yöntem bu sette seçildi.
- İkili düzeyinde yeni ürün B1'in altında kalan: 114'te 2, ikisi de LTO'lu (redis-benchmark −0,125; redis-cli −0,026).
- Duyarlılık satırı seçilmedi. ≥ 32'de kesmemek makroyu değiştirmiyor (0,699 ↔ 0,705).

### 4.2 Fark var mı?

Yok. Ayrıntı:

| Karşılaştırma | Sonuç |
|---|---|
| Yeni ürün ↔ keşif S2, ARI (6 hane) | 114 / 114 ikilide aynı |
| Yeni ürün ↔ `slice_by_padding` (doğrudan işlev), nüfusun bölmesi | 114 / 114 aynı |
| Bloklu ↔ bloksuz dilimleme, nüfusun bölmesi | 114 / 114 aynı |
| Bayrak açık kurulum | 114 / 114 adres yerleşimi; geri düşüş 0; başarısız kurulum 0; adressiz birim 0 |

- Üründe keşfe göre üç ek var: blok sınırı, giriş noktasının `main.c`'ye ayrılması, sinyalsiz ikilide geri düşüş. Üçü de bu sette nüfusun bölmesini değiştirmedi.
- Giriş noktası: nüfustan 5 fonksiyon `main.c`'ye gitti (htop ve dört redis ikilisi; her birinde 1). Bölme yine aynı çıktı, çünkü bu beş fonksiyon S2'de de tek başına bir dilimdi. Bu bir güvence değil, bu setin özelliğidir: giriş noktası başka fonksiyonlarla aynı dilimde olsaydı ARI az da olsa değişirdi.

### 4.3 Uçtan uca koşu (Ghidra dahil)

Koşu kökü: `~/karadul_olcum/runs/yerlesim-2026-11-12/` (`kos.py`, `denetle.py`, `denetim.json`, `kosu_kunyesi.json`; yineleme `son/` altında). Künye ve denetim çıktılarının kopyası bu dizinde: `uctan_uca_kunye*.json`, `uctan_uca_denetim*.json`. İki ikili.

| İş | Commit | Süre | Sonuç |
|---|---|---|---|
| Debian 13 `tree`, bayrak açık | 17e7e7c | 60,1 sn | Adres yerleşimi; 16 grup (11 dolgu, 4 blok sınırı); rapor: 250 fonksiyon, yerleşen 250, eksik 0, çift 0 |
| Debian 13 `tree`, bayrak kapalı | 17e7e7c | 58,4 sn | Eski yerleşim; `placement.json` yok; README'de "Placement" yok |
| Mach-O `htop`, bayrak açık | 17e7e7c | 196,3 sn | `no_padding_signal`; eski yerleşim; README'de ve `out/src/analysis/placement.json`'da not var |
| Debian 13 `tree`, bayrak açık (yineleme) | 36d40f4 | 54,8 sn | Aynı; README düzeltmesi yerinde |

- `tree`, açık ↔ kapalı: 250 fonksiyonun 250'sinde C metni aynı (başlıktaki adresle eşlendi); ad haritası (`naming_map.json`) bayt bayt aynı. Fark yalnız yerleşimde ve ona bağlı dosyalarda (README, `subsystem_map.md`, `compile_commands.json`, dizinler).
  - `include/types.h` da farklı çıktı: satırlar sıralanınca fark kalmıyor. Yapı numarası sırası koşudan koşuya değişiyor; bayrakla ilgisi yok (bilinen durum, `c_type_recoverer.py`).
- `tree`, açık: tam koşunun ağacı ön kayıtlı okuyucuyla okundu. ARI 0,911061; yeniden üretimdeki değerle aynı. Bölme `slice_by_padding` ile aynı. Ghidra'nın fonksiyon adresleri saklı koşuyla aynı (250).
- Mach-O `htop`, açık: 790 fonksiyonun 790'ı saklı koşudaki (bayrak yok, sürüm 1.21.1) modülüyle aynı modülde; 48 modül.

## 5. Mekanizma: dolgu neden nesne sınırını gösteriyor

| Adım | Kaynak |
|---|---|
| GCC 14, AArch64'te öntanımlı işlemci `generic-armv8-a`'dır. | `gcc/config/aarch64/aarch64.h` 887–888 (releases/gcc-14): `TARGET_CPU_DEFAULT TARGET_CPU_generic_armv8_a` |
| Bu ayarın fonksiyon hizalaması "32:16"dır. | `gcc/config/aarch64/tuning_models/generic_armv8_a.h` 171 |
| "N:M": N'ye hizala, ama en çok M−1 bayt atlayarak. "32:16" = 32'ye, en çok 15 baytla. | `gcc/toplev.cc` 1134–1150 ("-falign-foo=N:M means M-1 max bytes of padding") |
| Derleyici bunu `.p2align 5,,15` olarak yazar; yalnız hız için derlenen fonksiyonlarda. | `gcc/varasm.cc` 1953–1975; `gcc/config/aarch64/aarch64-elf.h` 56–67 |
| Çevirici, atlama sınırı aşılıp dolgu konmasa da bölümün hizalamasını 32 olarak kaydeder. | binutils `gas/read.c`, `do_align` (2.44 dalı, 825–874): `record_alignment` koşulsuz |
| Bağlayıcı her girdi bölümünü kendi hizalamasına tamamlar. | Standart ELF davranışı (`sh_addralign`); bu oturumda kaynaktan okunmadı |

Kaynak dosyalar 2026-11-12'de GCC'nin GitHub yansısından ve sourceware'den okundu. Debian'ın GCC'yi hangi yapılandırma seçenekleriyle derlediği ayrıca okunmadı; aşağıdaki GT'siz gözlemler kaynakla uyumlu.

Sonuç:

- **Dosya içinde:** fonksiyonun önündeki dolgu 0, 4, 8 ya da 12 bayttır (AArch64'te komut 4 bayt). 16 ve üstü gerekiyorsa derleyici hiç doldurmaz.
- **Nesne dosyası sınırında:** bağlayıcı 0–28 bayt doldurur. 16, 20, 24, 28 yalnız burada oluşur.
- **Eşik 16 = en çok atlama + 1.** Hizalama 32 = bölüm hizalaması.

GT'siz denetim (Debian 13, ana kod bloğu; `dolgu_sayimi.json`):

| Öngörü | Gözlem |
|---|---|
| Bütün dolgular 4'ün katıdır | 30 478 çiftin 30 478'inde **[hesap]** |
| Banttaki değerler yalnız 16, 20, 24, 28 | 514, 763, 685, 374; başka değer yok |
| Pozitif dolgudan sonra başlangıç 32'nin katıdır | program başına 0,981 – 1,000 |
| Başlangıç kalanı 20, 24, 28 olmaz | pay 0,000 – 0,029 |
| ≥ 32 dolgu oluşmaz | 221 aralık var; boyları düzensiz (dolgu değil) |

- **Sinyal sınırların yaklaşık yarısını görür:** bağlayıcının dolgusu, önceki fonksiyonun bittiği yere göre 0–28 arasında dağılır; yalnız ≥ 16 olanı ayırt edilir. Eşit dağılım varsayımıyla beklenen pay 1/2 **[hesap]**; dünkü keşifte 0,512 ölçülmüştü (program başına 0,345–0,800). Kalan yarı dolgudan görünmez; bu, yöntemin yapısal sınırıdır.
- **Derleyici sürümü değişince bant kayar:** GCC 12 ve 13'te öntanımlı ayar `generic`, hizalama "16:12"dir (`aarch64.h` 728–729, `aarch64.cc` 1342 (gcc-13), 1347 (gcc-12)). Dosya içinde dolgu 4 ve 8; nesne sınırında 0–12. Ayırt edici değer yalnız 12'dir. Eldeki GCC 13 ikililerinde başlangıç kalanları 16'ya göre yalnız 0 ve 4; dolgular 0, 4, 8, 12 (§3.1): kaynakla uyumlu. **12 baytlık dolgunun gerçekten nesne sınırına düştüğü GT ile sınanmadı.**
- **x86-64, GCC:** genel ayarda fonksiyon hizalaması "16"dır, atlama sınırı yoktur (`gcc/config/i386/x86-tune-costs.h` 3767, gcc-14). Dosya içi ve nesne sınırı dolgusu aynı aralıktadır (0–15); ayırt edici bant yoktur. **Öngörüdür; x86-64 ikilisinde sayılmadı.**
- **Mach-O / clang:** eldeki iki ikilide dolgu yok (§3.1). Nedeni (clang'ın hizalama ayarı, `ld64`'ün davranışı) kaynaktan doğrulanmadı.

## 6. Ne yapıldı

### 6.1 Ürün (`karadul/reconstruction/c_project_builder.py`, `karadul/config.py`)

- **Bayrak:** `binary_reconstruction.enable_address_placement`, öntanımlı `False`. YAML ile açılır. Bayrak yalnız `True` ise açık sayılır (sahte yapılandırma nesnesi açmaz).
- **Sayılar tek yerde:** `address_placement_padding_threshold = 16`, `address_placement_alignment = 32` (`config.py`). Kurucuda gömülü sayı yok.
- **Yeni girdi:** `static/ghidra_functions.json` (adres, boyut) ve `static/ghidra_combined_results.json` (bellek blokları). İkisi de çalışma alanında zaten vardı; kurucu okumuyordu.
- **Kural (`slice_by_padding`):** Ghidra'nın bütün fonksiyonları tam sayı adrese göre dizilir. Yeni dilim: bellek bloğu değişince, ya da yürütülebilir blokta dolgu ≥ eşik olunca. Dilimleme birimi olmayan fonksiyonu da sayar; yoksa komşuları arasındaki aralık dolgu sanılırdı.
- **Çıktı:** her dilim `src/subsystem_addr_<ilk fonksiyonun adresi>/` dizinidir. Dizin içi düzen değişmedi (fonksiyon başına dosya, `thunks_and_stubs.c`). Giriş noktaları yine `main.c`'de. Adresi okunamayan birimler `subsystem_addr_unknown`'a gider ve sayılır.
- **API kuralı etiketi kaybolmaz:** `analysis/subsystem_map.md`'de her grubun yanında üyelerinin kural etiketlerinin sayımı yazılır; dizini belirlemez.
- **Geri düşüş (eski yerleşim) ve nedenleri:** `no_padding_signal`, `no_function_data`, `no_addressed_unit`, `invalid_parameters`. Karar dört yere yazılır: README'nin "Placement" bölümü, `analysis/placement.json`, günlük (uyarı), sonuç nesnesi (`placement_strategy`, `placement_fallback_reason`).
- **README:** adres yerleşiminde yöntemi ve sayıları anlatır; grupların kaynak dosyaları yansıttığını iddia etmez ("not a verified reconstruction").
- **Belirlenimlilik:** sıralama tam sayı adrese göre; grup adı adresten; küme dolaşımına ya da karma tohumuna bağlı adım yok.

### 6.2 Betikler (`scripts/measurement/`)

| Betik | İş | GT |
|---|---|---|
| `yerlesim_dolgu_say.py` | Dolgu dağılımı, sinyal, rejim göstergeleri | Kullanmaz |
| `yerlesim_kurulum_denetle.py` | Bayrak kapalı eşitlik; bayrak açık kurulumun özeti | Kullanmaz |
| `yerlesim_urun_olc.py` | Geliştirme setinde yeniden üretim | Yalnız `harita_olcumu.json`'daki sınıf kodları |

Tanımlar ürün kodundan içe aktarılır; eşik ve hizalama `config.py`'den okunur. `harita_olc.py` değişmedi (sha256 `1a205ca42d4d9e3d…`, ön kayıttaki dosya).

### 6.3 Bayrak kapalıyken çıktının değişmediğinin kanıtı

1. **Saklı çıktıyla bayt karşılaştırması:** ölçülen koşunun (`urun-yeni-93a2956`; commit 93a2956) 119 çalışma alanında kurucu, bugünkü kodla ve bayrak kapalı yeniden çalıştırıldı. 119 / 119'unda proje ağacı saklı ağaçla bayt bayt aynı.
   - `compile_commands.json` proje kökünün mutlak yolunu içerir; yalnız o yol çevrildi.
   - `analysis/algorithms.md` karşılaştırma dışı: kurucuya verilen algoritma sonucunun `detection_method` alanı çalışma alanında saklı değil. O işlev değişmedi.
   - Kurucunun kodu 93a2956 ile 2be12ed arasında değişmemişti (`git diff` boş).
   - Eski koşunun 10 çalışma alanı (`aday-f893d72`) eşit çıkmadı; onlar kurucunun daha eski bir sürümüyle üretilmişti. İddiaya girmez.
2. **Uçtan uca:** `tree`'de bayrak kapalı koşu `placement.json` yazmıyor; README'de "Placement" yok.
3. **Test:** yapılandırma yok / öntanımlı / bayrak açıkça kapalı üç kurulumun ağacı aynı. Öntanımlı değeri açığa çeviren mutant ölüyor.

### 6.4 Test ve mutant

- `tests/test_yerlesim_adres.py`: 50 test (ürün). `tests/test_yerlesim_betikleri.py`: 13 test (betikler). 63 / 63 geçti.
- Dokunulan dosyaların öbür testleri: `test_c_project_builder_saglamlik`, `test_step_project_build`, `test_harita_olc`, `test_binary_reconstruction`, `test_temiz_harita`, `test_output_formatter`, `test_v157_fixes`, `test_config_adim3_bayraklari`. Toplam 464 / 464 geçti. Tam test takımı koşulmadı (görev kuralı).
- Mutant: `scripts/measurement/mutation_specs_yerlesim.json`, 69 mutant (ürün 53: kurucu 49, yapılandırma 4; betikler 16). **69 / 69 öldü.** 67'si test doğrulamasının (assert) düşmesiyle; 2'si, bir koruma kaldırılınca ürün kodunun istisna atmasıyla (`yr_adressiz_devam`, `yr_birimsiz_fonksiyon_sirada_degil`).
- İlk koşuda (66 mutant) 3'ü istisnayla ölmüştü. Biri (API etiketi) doğrulamayla ölen iki mutanta çevrildi; sıralama mutantı eski test girdisinde eşdeğer kalacağı için girdi değiştirildi (etiket sayıları eşit olmayan bir grup eklendi).

## 7. Nerede bozuluyor

| # | Durum | Kanıt | Ürün ne yapıyor |
|---|---|---|---|
| 1 | GCC 13 ve öncesi, AArch64 | Bant 12 bayttır; 16'da görünmez (§5). 10 ikilide bantta toplam 4 dolgu. | 6'sında eski yerleşim; 4'ünde başıboş dolguyla adres yerleşimi, kod bloğu 2–3 grup |
| 2 | Mach-O / clang | htop'ta dolgu 0; tmux'ta 2 başıboş dolgu | htop'ta eski yerleşim; tmux'ta adres yerleşimi, en büyük grup birimlerin 0,616'sı |
| 3 | LTO | redis-tools 0,385 (B1 0,354); iki ikilide B1'in altında | Adres yerleşimi; sınır kaynak dosyayı değil LTO bölümünü gösterir |
| 4 | x86-64, GCC | Öngörü: ayırt edici bant yok (§5) | Sayılmadı |
| 5 | Sınırların yarısı | Yapısal: bağlayıcı dolgusunun yarısı 16'nın altında (§5) | Görünmeyen sınırda dosyalar birleşir (duyarlılık yüksek, kesinlik düşük) |
| 6 | ≥ 32 baytlık aralık | Dünkü keşif: coreutils'te 117'si sınıf değiştirmiyor, 8'i değiştiriyor | Yine de keser (dondurulmuş kural). Kesmeyince makro 0,699 |
| 7 | `-Os`, `-falign-functions=…`, elle yazılmış birleştirici kodu | Sayılmadı | Bilinmiyor |

**Eşiğin ikiliden kestirilmesi (uygulanmadı; ayrı iş kalemi):** §5'teki mekanizma, hizalamanın ve atlama sınırının başlangıç kalanlarından GT'siz okunabileceğini düşündürüyor (GCC 14: kalanlar 0–16; GCC 13: 16'ya göre 0 ve 4). Bu yeni bir yöntemdir: önce geliştirme setinde keşif, sonra ayrı ön kayıt ister. **[yön gösterici]**

## 8. Doğrulanmayanlar

- Doğrulama seti yok. Bu belgedeki bütün uyum sayıları geliştirme setindendir; eşik bu sette seçildi.
- GCC 13'te 12 baytlık dolgunun nesne sınırı olduğu GT ile sınanmadı.
- x86-64 ve Linux'ta clang için hiçbir ikili sayılmadı.
- Mach-O'da neden dolgu olmadığı kaynaktan doğrulanmadı; Mach-O için GT yok.
- Bağlayıcının girdi bölümünü hizalamaya tamamladığı kaynaktan okunmadı (veriyle uyumlu).
- ≥ 32 baytlık aralıkların ne olduğu incelenmedi.
- Başıboş dolgulu beş ikilide yerleşimin kalitesi ölçülmedi.
- Dizin düzeyi ölçülmedi.
- Adres yerleşiminin arayüzde (`ui/`) nasıl göründüğüne bakılmadı; `ui/` ve rapor üreticileri değişmedi. Rapor istatistiklerine (`report.json`) yerleşim stratejisi taşınmıyor: `pipeline/steps/project_build.py` bu görevin izin listesinde değildi.
- Tam test takımı koşulmadı.
- Uçtan uca koşu iki ikiliyle sınırlı (görev kuralı).

## 9. Komutlar ve künye

```
K=~/karadul_olcum/runs/urun-yeni-93a2956
E=~/karadul_olcum/runs/aday-f893d72
D=docs/arge/2026-11-12_yerlesim

# GT'siz dolgu sayımı (§3)
python -m scripts.measurement.yerlesim_dolgu_say --kok debian13=$K --kok eski=$E \
    --json $D/dolgu_sayimi.json --md $D/dolgu_sayimi.md

# GT'siz kurulum denetimi (§3.3, §6.3)
python -m scripts.measurement.yerlesim_kurulum_denetle --kok debian13=$K --kok eski=$E \
    --json $D/kurulum_denetimi.json --md $D/kurulum_denetimi.md

# geliştirme setinde yeniden üretim (§4)
python -m scripts.measurement.yerlesim_urun_olc --kosu $K \
    --olcum docs/arge/2026-11-11_harita/harita_olcumu.json \
    --kesif docs/arge/2026-11-11_harita/yerlesim_kesfi.json \
    --json $D/gelistirme_yeniden_uretim.json --md $D/gelistirme_yeniden_uretim.md

# testler ve mutantlar (§6.4)
PYTHONDONTWRITEBYTECODE=1 python -m pytest tests/test_yerlesim_adres.py tests/test_yerlesim_betikleri.py -q
PYTHONDONTWRITEBYTECODE=1 python scripts/mutation_probe.py --spec scripts/measurement/mutation_specs_yerlesim.json

# uçtan uca (§4.3); <ağaç> = ürünün yüklendiği git ağacı
python ~/karadul_olcum/runs/yerlesim-2026-11-12/kos.py <ağaç>
python ~/karadul_olcum/runs/yerlesim-2026-11-12/kos.py <ağaç> son acik/debian/tree
python ~/karadul_olcum/runs/yerlesim-2026-11-12/denetle.py <ağaç> [son]
```

- Üç betiğin çıktıları commit 36d40f4'te üretildi (ürün kodunun son hâli). sha256 (ilk 16 hane): `c_project_builder.py` `fc7d79d8e11b3d3d`; `config.py` `7bd51169375d46a9`; `harita_olc.py` `1a205ca42d4d9e3d`; `dolgu_sayimi.json` `7a570927a7c7c269`; `gelistirme_yeniden_uretim.json` `9d8b21b2745c20f1`; `kurulum_denetimi.json` `b4f5bedd7ddcc0b1`.
- Commit'ler: 8c3aff7 (özellik ve testleri), 17e7e7c (betikler, testleri, mutant belirtimi), 36d40f4 (README düzeltmesi).
- Saklı koşular yalnız okundu. `urun-yeni2-f30ac9a` okunmadı. Hiçbir şey silinmedi. Ürün ağacına, Ghidra koşusu için ana depodaki çalışma zamanı verisine beş simgesel bağ eklendi (`sigs`, `vendor`, üç imza dosyası; git'e girmedi).
- Yaratıcılık protokolü (dört kural): (1) her iddia bir sayıya bağlandı, doğrulayıcısı olmayanlar etiketlendi: uygulandı. (2) uzlaşı bilerek kırıldı: beklenen cevap değil bozulduğu yer arandı; ön kayıt taslağının aykırı öncülü budur: uygulandı; farklı model ailesi ve Onuncu Adam kullanılmadı (görev kuralı: alt ajan yok). (3) tek hatta kalındı; olumsuzlar kayıtta (§3.3, §7): uygulandı. (4) insan uzman seçimi: uygulanmadı; "bu yerleşim tersine mühendis için daha mı kullanışlı" sorusunu kimse değerlendirmedi.
