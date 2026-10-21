# G11 / T0c: çıplak Ghidra'nın tip tabanı — sonuç notu

- **Tarih:** 2026-10-21
- **Plan:** v2.2 §4 T0 (d) ve (e); §5 K1 ve K2. Önceki adımlar: T0a (`2026-10-21_g9_t0/dwarf_tip_notu.md`), T0b (`2026-10-21_g10_t0b/hizalama_notu.md`).
- **Araçlar** (commit'siz; sha256'ları `kosu.json`'da):
  - `scripts/measurement/dwarf_tip.py` (genişletildi): yerleşim imzası, 0. ofset bağı, takma adlar, köken; K1 kimliği için saf fonksiyonlar.
  - `scripts/measurement/ghidra_tip_tabani.py` (yeni): adlı tip doğruluğu, Ghidra kümeleriyle K1 ölçüleri, önemsiz tabanlar, negatif kontrol, kapsam tavanı.
- **HEAD:** görev a10fde3'te başladı; sırada HEAD 75fc455'e ilerledi. Aradaki üç commit yalnız `docs/`'a dokunuyor.
- **Testler:** `tests/test_dwarf_tip.py` (64 → 98), `tests/test_ghidra_tip_tabani.py` (49, yeni). 147/147 geçti.
- **Mutantlar:** `mutation_specs_dwarf_tip.json` 36/36 öldü (T0a 8 + T0b 7 + T0c 21); `mutation_specs_ghidra_tip_tabani.json` 22/22 öldü.
- **Kapsam:** Debian 13 geliştirme setinin 8 programı, T0b'nin 22 ikilisi. Doğrulama setine, ağa ve `karadul/`'a dokunulmadı; Ghidra yeniden koşulmadı (T0b'nin `ghidra_2/` çıktısı kullanıldı).
- **Veri:** `~/karadul_olcum/runs/t0c-a10fde3/`: `dwarf/` (yeni sürümle 116 `.debug`), `taban/` (`taban.json`, parametre başına `parametreler.jsonl`).

## 1. DWARF tarafı: yerleşim imzası, aile bağı, köken (`dwarf_tip.py`)

### 1.1 Yerleşim imzası

Tanımı olan her yapı ve birlik için adsız, kanonik bir fiziksel yerleşim: `<tür>/<sizeof>/<öğeler>`. Öğeler ofsete göre sıralanır, virgülle ayrılır; öğe yoksa `-`.

| Öğe | Biçim | Örnek |
|---|---|---|
| yaprak | `<ofset>:<genişlik><s\|p>` (`s` skaler: temel tip ve enum; `p` işaretçi: veri, fonksiyon, C++ başvurusu) | `8:8p` |
| bit alanı | `b<bit ofseti>:<bit genişliği>` (yapının başından, bit cinsinden) | `b320:3` |
| dizi | `<ofset>:[<sayı>x<eleman boyu>{<eleman öğeleri>}]` | `16:[16x1{0:1s}]` |
| birlik | `<ofset>:u<sizeof>{<seçenek>\|<seçenek>…}` | `32:u8{0:4s\|0:8p}` |

- **İç içe yapı düzleşir.** Değerle üye (C++'ta taban sınıf) öğelerini üst yapıya ofsetini ekleyerek katar. Örnek: `struct stat`'ın `st_atim`'i (`struct timespec`) `72:8s,80:8s` olur.
- **Statik üye atlanır** (`DW_AT_declaration` ya da `DW_AT_external` taşıyan üye).
- **Bildirim tipli değerle üye.** Adının erişilen birimlerdeki tanımına gidilir. Tanım yoksa ya da farklı yerleşimli birden çok tanım varsa imza çıkmaz (`durum: eksik`). Geliştirme setinde eksik imza **0**.
- **Özet:** imzanın SHA-256'sının ilk 16 hex basamağı (`ozet`). K1 kimliği bunu kullanır.
- **Diziler: tek öğe (öneri ve gerekçe).**
  - Dizi, eleman yerleşimi ve sayısıyla tek öğedir. Çok boyutlu dizi ve dizi dizisi (`typedef int row[4]; row m[3]`) aynı fiziksel diziye katlanır: `int[3][4]` ile `row[3]` ikisi de `[12x4{0:4s}]`.
  - Gerekçe: eleman başına yaprak 4 096 baytlık bir arabelleği 4 096 yaprak yapar; imza şişer, kimlik değişmez. Kimlik için gereken bilgi (eleman yerleşimi, sayı) tek öğede tam olarak duruyor.
  - K2'de dizinin nasıl sayılacağı ayrı bir seçimdir (taslak §3.1, S16).
- **Birlikler: sıralı ve tekil seçenekler (öneri ve gerekçe).**
  - Birlik, seçeneklerinin kümesiyle tek öğedir. Her seçenek bir üyenin düzleşmiş öğeleri; seçenekler sözlükçe sıralanır, yinelenenler atılır.
  - Gerekçe: üye sırası ve adı birliğin fiziksel yerleşimini değiştirmez. Birliği tek yaprağa (ofset, sizeof) indirmek ise farklı içerikli aynı boyutlu birlikleri birleştirirdi.
  - K2'nin "üyelerden biriyle eşleşme yeter" kuralı bu biçimden okunabilir.
- **Eski yapısal imzayla fark.** T0a'nın `yerlesim_imzasi`'sı üye adlarını ve kanonik tipleri taşıyor; değişmedi ve `kimlik_denetimi` onu kullanmaya devam ediyor. Yeni imza adsız ve fizikseldir.
  - Sonuç: redis-check-aof'ta T0a'nın "aynı adlı farklı yerleşim" saydığı 5 addan biri (`struct iovec`: iki tanım, aynı fiziksel yerleşim) yeni imzada tek kimlik oluyor.
  - Kalan dördü gerçekten farklı yerleşimli: `dict`, `dictEntry`, `dictIterator`, `dictType` (redis ile gömülü hiredis).

### 1.2 0. ofset bağı (kalıtım ailesi)

- X'in ilk statik olmayan üyesi 0. ofsette ve tipi, typedef ve niteleyiciler soyulduktan sonra değerle `struct Y` ise **X → Y**.
- Zincir sürer: Y → Z … En çok 16 adım; döngüde durur. Her adımda tür, ad, tanıma çözülmüş konum, `ozet` ve takma ad yazılır.
- Bağ kurmayanlar: birlik X; ilk üyesi işaretçi, dizi, bit alanı ya da birlik olan X.
- Aile, bağların bağlı bileşenidir; temsilcisi sözlükçe en küçük kimlik (`k1_aile_haritasi`).
- **En büyük aile:** htop'ta `Object_` hiyerarşisi. Tek ailede 19 kimlik, 280 `yapi*` parametresi (htop'un K1 nüfusunun %51'i).

### 1.3 Takma adlar ve köken (kütüphane kökenli tanımı)

- **Takma adlar** (`takma_adlar`): erişilen birimlerde, yalnız typedef ve niteleyici adımlarıyla (işaretçisiz) o yapıya varan typedef adları. Örnek: `FILE` → `struct _IO_FILE`. `typedef struct foo *foo_p` takma ad değildir.
- **Kaynak dosya** (`koken.dosya`): `DW_AT_decl_file`, birimin satır tablosundaki yola çevrilir. Satır tablosu DWARF 5'te 0 tabanlı, DWARF 2-4'te 1 tabanlı; yol `normpath` ile sadeleşir.
- **Kendi `decl_file`'ı yoksa** önce adın tanımına bakılır (tanımda: aynı yerleşimli öbür tanım), sonra takma adın typedef DIE'sine.
  - GCC yalnız bildirim DIE'lerine `decl_file` yazmıyor (openssl'de 191 bildirimin hepsi).
  - dwz ek dosyasında birleştirilmiş kimi tanımlarda da yok (redis-check-aof `ek:0x1942f redisObject`).
- **Köken sınıfı** (`koken.sinif`, `koken_sinifi`):
  - `sistem`: mutlak yol `/usr/include/`, `/usr/lib/gcc/`, `/usr/local/include/`, `/usr/lib/clang/`, `/usr/lib/llvm` altında ya da Apple SDK'sında (`.sdk/usr/include/`, sınanmadı). Ayrıca derleyicinin `<built-in>`'i (`__va_list`).
  - `gnulib`: yol, ikilinin gnulib dizinlerinden birinin altında.
    - Gnulib dizini: ikilinin derleme birimi adları arasında, aynı dizinde en az iki farklı gnulib'e özgü modül kaynağı derlenmiş olmalı. Modüller `xmalloc`, `quotearg`, `version-etc`, `progname`, `exitfail`, `closeout` vb.; liste `GNULIB_ISARETCILERI`'nde.
    - coreutils'te bu dizin `lib`. zstd'nin kendi `lib/`'i gnulib sayılmaz: işaretçi modül yok.
  - `program`: geri kalan. Gömülü üçüncü taraf kodu da buraya girer: redis `deps/` (lua, hiredis, hdr_histogram, linenoise), tmux `compat/`.
  - Boş: yol bulunamadı.
- **`tanimsiz`:** bildirim, ve adın erişilen birimlerde hiç tanımı yok (opak).
- **K1'de kütüphane kökenli:** `sistem` ya da `gnulib`. Duyarlılık kuralı `tanimsiz_dis`: opak tip, `decl_file`'a bakılmadan kütüphane sayılır. Kural seçimi ön kayıtta S3'tür.

K1 nüfusunun köken dağılımı (kök başına, tanıma çözülmüş; `taban_ozeti.json` → `nufus`):

| Program | kütüphane | program | bilinmiyor | `tanimsiz_dis` ile kütüphane |
|---|---|---|---|---|
| coreutils | 433 (gnulib 329, sistem 104) | 17 | 0 | 433 |
| htop | 5 | 541 | 1 | 6 |
| openssl | 1 | 356 | 30 | 273 |
| redis-tools | 41 | 4 432 | 0 | 43 |
| sqlite3 | 10 | 339 | 0 | 120 |
| tmux | 29 | 2 030 | 7 | 36 |
| tree | 5 | 22 | 0 | 5 |
| zstd | 38 | 1 083 | 0 | 39 |

- **openssl ve sqlite3 kuralın sınırı.** İki CLI kendi kütüphanesinin kaynak ağacında derleniyor. API tipleri (`BIO`, `SSL`, `sqlite3`, `sqlite3_stmt` …) ağaç içi başlıklarda (`../include/openssl`, `sqlite3.h`) ve ikilide tanımsız (opak).
  - `decl_file` kuralı bunları `program` sayıyor; takma adı olmayan `STACK_OF` tipleri ise `bilinmiyor`.
  - `tanimsiz_dis` kuralı ikisini de kütüphaneye alıyor ve `bilinmiyor` tabakası sıfırlanıyor. tmux'ta bilinmeyen 7 parametre libevent'in opak `evbuffer` ve `event_base`'i.

### 1.4 K1 kimliği (`k1_kimligi`)

| Durum | Kimlik | K1 nüfusunda |
|---|---|---|
| `tanim` | adlı: (tür, ad, `ozet`); anonim: (tür, `ozet`, en küçük takma ad) | 8 422 |
| `bildirim_cozuldu` | erişilen birimlerdeki tanımları tek yerleşimliyse o tanımın kimliği | 602 |
| `opak` | (tür, ad, "bildirim"): ikilide hiç tanımı yok | 396 (openssl 272, sqlite3 110) |
| `cok_tanimli` | yok: farklı yerleşimli birden çok tanım. Karar ölçüsünden çıkar | 13 (redis: `dict`, `dictEntry`, `dictIterator`, `dictType`) |
| `yerlesim_eksik`, `hata` | yok | 0 |

- Bildirim kökünün tanıma çözülmesi taslakta yoktu. Çözülmeseydi 602 parametrede aynı tip "bildirim" ve "tanım" diye iki kimliğe bölünürdü.
- K1 nüfusunda birlik kökü 24 (redis 21, zstd 2, tmux 1); anonim kök 647.

### 1.5 Davranış korunumu ve bağımsız doğrulama

- **Mevcut alanlar değişmedi.** T0b dizinindeki 116 `.debug` belgesi yeni sürümle yeniden üretildi. `arac` künyesi ve yapı kayıtlarına eklenen dört alan atılınca **116/116 belge** eskisiyle aynı (JSON eşitliği). Parametre sayıları T0a ile aynı.
- **İmzanın bağımsız hesabı** (`capraz_yerlesim.py`):
  - dwz'siz beş programda (tree, tmux, htop, sqlite3, openssl) ana dosyadaki tanımlar alındı.
  - İmza, pyelftools'un kendi DIE arayüzüyle sıfırdan yeniden hesaplandı. `dwarf_tip.py`'nin çözücüsü ve yardımcıları kullanılmadı; dilbilgisi modül belgesindeki tanım.
  - Sonuç: **704/704 tanımda imza aynı** (tree 7, tmux 494, htop 133, sqlite3 32, openssl 38).
  - Sınır: dwz'li programlar (zstd, redis, coreutils) bu yoldan denetlenemiyor; pyelftools ek dosya başvurularını çözmüyor.

## 2. Ghidra tarafı: yöntem (`ghidra_tip_tabani.py`)

- **Uygun fonksiyon:** adresle eşlenmiş, klonsuz, Ghidra thunk'ı değil, birimi C, decompile başarılı (T0b §9 madde 3).
- **Nüfus (a):** uygun fonksiyonlarda `depolama_kaynagi == "dwarf"` ve `eslesme == "tam"` olan 25 318 parametre. Ghidra parametresi `decompile.parametreler[depolama_ortagi − 1]` (sıra değil, depolama).
- **Ghidra tip dizgisi** (`str(DataType)`) (ad, derinlik) adaylarına çevrilir:
  - Yerleşik ad GCC adına çevrilir: `ulong` → `long unsigned int`, `uint` → `unsigned int`, `byte`/`uchar` → `unsigned char` …
  - `typedef AD TABAN` biçiminde hem AD (derinlik 0) hem TABAN'ın adayları aday olur.
  - `undefinedN`, dizi ve `code` aday vermez.
  - Ghidra'nın kendi `typedef` dizgilerinden 43 adlık bir harita kuruldu (çakışan yok). Haritada yerleşiğe inen ad (`size_t *`, `socklen_t *`) skaler sayılır.
- **DWARF'ın kabul ettiği çiftler:**
  - zincirdeki her typedef adı, önündeki işaretçi sayısıyla;
  - kökün adı (temel tip, yapı, birlik, enum, `void`), tam derinlikle;
  - kök yapının takma adları (aynı (tür, ad)'lı bütün kayıtların birleşimi).
- **Adlı tip doğru** = Ghidra adaylarıyla DWARF çiftlerinin kesişimi boş değil. Tanım katı:
  - `long` ↔ `long long int` ve `int` ↔ `enum quoting_style`, LP64'te fiziksel olarak aynı olsa da yanlış sayılır;
  - `SHA256_CTX` ↔ `struct sha256_ctx` de yanlıştır (ad farklı).
- **Ghidra kümesi (K1):**
  - Etiket: derinlik 1'de verilen, yerleşik olmayan ve haritada yerleşiğe inmeyen ad (`FILE`, `BIO`, `mbstate_t`, `stat` …). Aynı ikilide aynı etiketi alanlar bir kümedir; etiketsiz parametre tekildir.
  - Etiket listesi `taban_ozeti.json`'da. Hepsi yapı adı; skaler typedef sızmadı.
- **K1 ölçüleri:**
  - Çiftler ikili içinde kurulur, sayılar program içinde toplanır, oran program başına alınır. Programlar arasında makro ortalama; oranı tanımsız program ortalamaya girmez.
  - Ölçüler: çift kesinliği, çift duyarlılığı, kapsam, B-cubed; katı ve aile düzeyinde.
  - **Kâhin kapsamı:** gerçek sınıfı ikilide en az iki üyeli parametrelerin payı, yani kusursuz kümelemenin kapsamı.
- **Önemsiz tabanlar:** `tekil` (kapsam 0); `tek_sinif` (ikilideki bütün `yapi*`'lar tek kümede).
  - Ghidra'nın yalnız işaretçi boyutunu (8) gördüğü durumda "aynı boyuttaki bütün yapı işaretçileri tek sınıfta" tabanı budur; çift kesinliği şans düzeyidir.
  - Bilgi için `kahin_boyut`: etiket, gösterilen yapının DWARF `sizeof`'u. Hiçbir araç bunu bilemez; yalnız boyut bilgisinin ne kadar ayırt ettiğini gösterir.
- **Negatif kontrol (taslak §2.3):**
  - Her ikilide küme etiketleri parametreler arasında karıştırılır; küme boyutu dağılımı aynen korunur.
  - 1 000 kez, tek tohumlu `random.Random` (`karadul-g11-t0c-negatif-kontrol-2026-10-21`). Her karıştırmada makro çift kesinliği hesaplanır.
  - %99 yüzdeliği en yakın sıra yöntemiyle: `v[⌈0,99·n⌉ − 1]`.
  - Karıştırma "program içinde" değil **ikili içinde** yapıldı: çiftler ikili içinde tanımlı, program içi karıştırma ikililer arası küme kurardı.

## 3. Sonuçlar

### 3.1 (e) Nüfus ve kapsam tavanı: T0b'nin sayıları yeniden üretildi

| Program | DWARF `yapi*` (hepsi) | Uygun fonksiyonlarda | Hizalanan (K1 adayı) | Tavan | Dışarıda (`ghidra_az` / `yigin_eksik`) | K1 nüfusu |
|---|---|---|---|---|---|---|
| coreutils (12 ikili) | 515 | 493 | 450 | %91,3 | 43 / 0 | 450 |
| htop | 600 | 577 | 547 | %94,8 | 30 / 0 | 547 |
| openssl | 438 | 397 | 387 | %97,5 | 10 / 0 | 387 |
| redis-tools (3 ikili) | 4 799 | 4 634 | 4 486 | %96,8 | 148 / 0 | 4 473 |
| sqlite3 | 398 | 372 | 349 | %93,8 | 23 / 0 | 349 |
| tmux | 2 220 | 2 136 | 2 066 | %96,7 | 69 / 1 | 2 066 |
| tree | 30 | 30 | 27 | %90,0 | 3 / 0 | 27 |
| zstd (2 ikili) | 1 537 | 1 182 | 1 121 | %94,8 | 61 / 0 | 1 121 |
| **Toplam** | **10 537** | **9 821** | **9 433** | **%96,0** | 387 / 1 | **9 420** |
| Makro | | | | %94,5 | | |

- T0b §9'un **9 433** nüfusu ve **%96,0** tavanı aynen çıktı; program başına sayılar T0b §9 madde 4 ile aynı.
- Uygun fonksiyonlarda ABI yedeğiyle ya da kısmi eşlenen `yapi*` yok.
- Tutarlılık denetimi: hizalama belgesindeki DWARF tipi ile yeni DWARF belgesindeki tip 25 318/25 318 parametrede aynı; bulunamayan fonksiyon ya da parametre yok.
- K1 nüfusu = hizalanan − 13 çok tanımlı kök (redis).

### 3.2 (a) Adlı tip doğruluğu

Program başına pay (parametre sayısı):

| Program | `yapi*` | `char*` | `void*` | skaler | diğer |
|---|---|---|---|---|---|
| coreutils | %15,8 (450) | %19,9 (849) | %28,1 (356) | %35,4 (1 241) | %27,9 (222) |
| htop | %0,5 (547) | %38,3 (81) | %11,9 (42) | %40,6 (276) | %8,6 (58) |
| openssl | %35,7 (387) | %39,1 (330) | %3,7 (109) | %48,5 (297) | %9,2 (207) |
| redis-tools | %0,3 (4 486) | %26,9 (1 422) | %10,3 (603) | %46,9 (2 837) | %11,3 (1 041) |
| sqlite3 | %1,4 (349) | %25,2 (115) | %0,0 (35) | %41,8 (158) | %3,9 (102) |
| tmux | %0,1 (2 066) | %35,6 (340) | %7,3 (178) | %40,0 (984) | %16,5 (248) |
| tree | %7,4 (27) | %45,6 (57) | %100,0 (1) | %54,7 (64) | %9,1 (33) |
| zstd | %0,6 (1 121) | %19,4 (356) | %7,4 (917) | %45,3 (1 787) | %29,1 (539) |
| **Makro** | **%7,7** | **%31,3** | **%21,1** | **%44,1** | **%14,5** |
| Toplam | %2,6 (243/9 433) | %27,0 | %11,3 | %43,6 | %16,7 |

- **`tip_kilitli` ayrımı boş.** 25 318 parametrenin hiçbirinde Ghidra tipi kilitli değil (prototipten gelen tip yok). Karadul'un ayarlarında iç fonksiyonlara prototip uygulanmıyor; T0b §4.3'te imza kaynağı da 13 144/13 151 fonksiyonda `DEFAULT`. Kilitli sütunu bu yüzden boş, bütün sayılar kilitsiz.
- **Adlı yapıların kaynağı.** Ghidra'nın adlı yapı tipleri iç fonksiyonlara içe aktarılan kütüphane prototiplerinden yayılıyor. Örnek: openssl'de `imza_kaynagi: IMPORTED` olan PLT thunk'larında 1 352 `BIO`/`SSL`/`X509` parametresi var.
- **Ghidra'nın `yapi*` parametrelerine verdiği tip türleri (toplam 9 433):**
  - temel skaler 4 293 (çoğu `long`: 4 244);
  - `undefinedN` 2 071;
  - temel işaretçi 1 694 (`long *`, `uint *` …);
  - `undefinedN *` 983;
  - adlı işaretçi 246 (243'ü doğru; yanlış 3'ü `SHA256_CTX` ↔ `struct sha256_ctx`);
  - `void *` 111, `char *`/`byte *` 27, dizi işaretçisi 6, typedef'li skaler 2.
  - Yani yapı işaretçilerinin %45'ini Ghidra tamsayı (`long`) olarak görüyor.
- **İşaretçi derinliği doğru payı** (makro): `yapi*` %35,8, `char*` %47,1, `void*` %52,7, skaler %99,8, diğer %40,5.
- Program farkı kütüphane payından geliyor: openssl (OpenSSL API tipleri) %35,7 ve coreutils (`FILE`, gnulib dışı libc tipleri) %15,8; program yapısı ağırlıklı redis, tmux, zstd ve htop'ta %0,1-%0,6.

### 3.3 (b) Ghidra kümeleriyle K1 ölçüleri (tabaka: hepsi)

| Program | Kapsam | Çift | Kesinlik katı | Kesinlik aile | Duyarlılık katı | Duyarlılık aile | Kâhin kapsamı (katı) |
|---|---|---|---|---|---|---|---|
| coreutils | %13,3 | 98 | %100,0 | %100,0 | %4,6 | %4,6 | %95,1 |
| htop | %0,4 | 1 | %100,0 | %100,0 | %0,0 | %0,0 | %98,0 |
| openssl | %32,0 | 1 074 | %100,0 | %100,0 | %36,3 | %36,2 | %90,2 |
| redis-tools | %0,2 | 9 | %100,0 | %100,0 | %0,0 | %0,0 | %98,6 |
| sqlite3 | %1,4 | 10 | %100,0 | %100,0 | %0,2 | %0,2 | %98,0 |
| tmux | %0,0 | 0 | — | — | %0,0 | %0,0 | %98,9 |
| tree | %7,4 | 1 | %100,0 | %100,0 | %0,6 | %0,6 | %85,2 |
| zstd | %0,2 | 1 | %100,0 | %100,0 | %0,0 | %0,0 | %96,3 |
| **Makro** | **%6,9** | | **%100,0** (7 program) | **%100,0** | **%5,2** | **%5,2** | **%95,0** |

- **Ghidra'nın kümeleri saf.** Her kümede gerçek kimlik tek; bağımsız yeniden toplamada saf olmayan küme yok.
  - En büyükleri: openssl `BIO` 38, `SSL` 22, `X509` 10, `SSL_CTX` 8; coreutils'te her ikilide `FILE` (4-6).
  - Aynı yapıya iki etiket düştüğünde (OpenSSL'de `ASN1_INTEGER` ile `ASN1_OCTET_STRING` ikisi de `struct asn1_string_st`) yalnız duyarlılık düşüyor.
- **Kapsamın üç paydası** (makro): K1 nüfusu %6,9; uygun fonksiyonlardaki `yapi*` %6,5; DWARF'taki bütün `yapi*` %6,1.
- **B-cubed** (makro): kesinlik %100,0, duyarlılık %12,9.
- **Tabakalar** (makro, katı):

  | Tabaka | Kural | Kapsam | Kesinlik | Duyarlılık | Kâhin kapsamı | Not |
  |---|---|---|---|---|---|---|
  | kütüphane | `decl_file` | %21,7 | %100,0 (6 program) | %12,9 | %75,3 | |
  | kütüphane | `tanimsiz_dis` | %19,5 | %100,0 (7) | %13,4 | %85,4 | |
  | program | `decl_file` | %4,4 | %100,0 (1) | %4,7 | %93,8 | Kümenin hepsi openssl'in ağaç içi OpenSSL tiplerinden |
  | program | `tanimsiz_dis` | %2,7 | %100,0 (1) | %2,1 | %93,7 | |

  - Program tabakasında openssl dışındaki yedi programda Ghidra kapsamı tam olarak **0**.
  - Çıplak Ghidra'nın K1 başarısı bütünüyle kütüphane prototiplerinden geliyor.

### 3.4 (c) Önemsiz tabanlar

| Taban | Kapsam (makro) | Kesinlik katı | Kesinlik aile | Duyarlılık |
|---|---|---|---|---|
| `tekil` | %0,0 | tanımsız (0 program) | tanımsız | %0,0 |
| `tek_sinif` (şans) | %100,0 | **%12,3** | **%15,3** | %100,0 |
| `kahin_boyut` (bilgi; araç bilemez) | %85,5 | %75,3 | %75,7 | %82,7 (katı) |

- `tek_sinif` program başına kesinlik (katı/aile): coreutils %15,8/%15,8; htop **%5,7/%28,5**; openssl %4,0/%4,0; redis %6,3/%6,3; sqlite3 %7,2/%7,7; tmux %3,5/%3,6; tree %50,4/%50,4; zstd %5,7/%5,9.
- **Aile düzeyi şans tabanını yükseltiyor.** htop'ta `Object_` ailesi yüzünden şans kesinliği beş katına çıkıyor. Literatürdeki "yalnız aile tanımı K1'i şişirir" uyarısının geliştirme setindeki karşılığı bu.
- **Yalnız boyut bilgisi %95'e yetmiyor.** `kahin_boyut`, yapının gerçek `sizeof`'unu bilse bile makro %75,3 kesinlikte kalıyor; kütüphane tabakasında %93,3.

### 3.5 (d) Negatif kontrol (1 000 karıştırma)

| Kümeleme | Gözlenen makro kesinlik | Karıştırılmış %99 yüzdeliği | Karıştırılmış ortalama | Fark |
|---|---|---|---|---|
| Ghidra, katı | 1,000 | 0,385 | 0,161 | **0,615** |
| Ghidra, aile | 1,000 | 0,478 | 0,196 | **0,522** |
| `kahin_boyut`, katı (bilgi) | 0,753 | 0,153 | 0,129 | 0,600 |
| `tek_sinif` | — | — | — | 0 (tek küme karıştırmada değişmez) |

- Taslağın ölçütüyle (fark ≥ 0,30) Ghidra iki düzeyde de geçiyor; tek küme tanım gereği geçemiyor.
- **Tek çiftli programlar.** htop, tree ve zstd'de tek çift var; karıştırılmış %99 yüzdeliği bu programlarda 1,0. Az çiftli program makroyu ve yüzdeliği oynatıyor (ön kayıt S6).

### 3.6 Kapsam alt sınırı için taban ve tavan

| Nokta | Kapsam (makro, payda K1 nüfusu) | Kesinlik (katı) |
|---|---|---|
| Çıplak Ghidra | %6,9 (programlarda %0,0-%32,0) | %100,0 |
| Çıplak Ghidra, program tabakası | %4,4 (`tanimsiz_dis` ile %2,7) | %100,0 (yalnız openssl) |
| `tek_sinif` | %100,0 | %12,3 |
| `kahin_boyut` (bilgi) | %85,5 | %75,3 |
| Kâhin tavanı (kusursuz kümeleme) | %95,0 (programlarda %85,2-%98,9) | %100,0 |
| Hizalama tavanı (payda uygun `yapi*`) | %94,5 makro, %96,0 toplam | — |

**Bu tablonun sonucu:** kapsam alt sınırı tabanın (%6,9) altında konursa, çıplak Ghidra K1'den geçer: kesinliği %100, negatif kontrolde farkı 0,615. Öneri ve seçenekler ön kayıt taslağında (S5). Karar Berke'nin.

## 4. Bilinen sınırlar

- **Yalnız Debian 13 arm64, gcc -O2.** Mac (Apple SDK yolu, dSYM) kuralları sınanmadı.
- **Adlı tip doğruluğu katı.** LP64'te aynı boyut ve işaretteki farklı adlar yanlış sayılıyor (`long` ↔ `long long int`, `int` ↔ enum). Boyut ve işaret düzeyinde gevşek bir ölçü hesaplanmadı. Tür dağılımı tabloda.
- **Ghidra'nın yapı adlarının türü bilinmiyor.** Ghidra çıktısı yalnız `str(DataType)` taşıyor. "Yapı etiketi" ad biçiminden ve Ghidra'nın kendi typedef haritasından çıkarıldı; skaler bir typedef'in yalnız `X *` biçiminde görünmesi onu yapı sanmaya yol açabilir. Geliştirme setinde bu olmadı.
- **Aynı yapıya düşen farklı Ghidra adları ayrı kümedir.** `FILE` ile `_IO_FILE`, `ASN1_INTEGER` ile `ASN1_OCTET_STRING` ayrı sayılıyor. Ghidra'nın kendi typedef grafiği okunmadı; DWARF'tan çözmek gerçeği tabana sızdırırdı.
- **Bağımsız imza denetimi** yalnız dwz'siz beş programda yapıldı.
- **Köken kuralı ağaç içi kütüphane başlıklarını ayırt etmiyor** (openssl, sqlite3; §1.3). Gömülü bağımlılıklar (redis `deps/`) `program` sayılıyor.
- **Az nüfuslu programlar** (tree 27, htop kütüphane tabakası 5) makro ortalamada tam ağırlık taşıyor.
- **coreutils'in 12 ikilisi bağımsız değil** (gnulib tekrarı; T0b §8).

## 5. Yeniden üretme

```sh
R=~/karadul_olcum/runs; D=~/karadul_olcum/downloads/debian13
python3 -I scripts/measurement/dwarf_tip.py toplu "$D/x_tmux-dbgsym_3.5a-3_arm64/usr/lib/debug" --ikili-kok "$D/x_tmux_3.5a-3_arm64" -o $R/t0c-<commit>/dwarf/tmux   # öbür 7 paket aynı kalıpla (~30 sn toplam)
python3 -I scripts/measurement/ghidra_tip_tabani.py olc --hizalama $R/t0b-1acba60/hizalama --ghidra $R/t0b-1acba60/ghidra_2 --dwarf $R/t0c-<commit>/dwarf -o $R/t0c-<commit>/taban   # ~18 sn
python3 -I docs/arge/2026-10-21_g11_t0c/bagimsiz_toplama.py
python3 docs/arge/2026-10-21_g11_t0c/capraz_yerlesim.py tree=<debug>=<dwarf json> …   # 5 dwz'siz program
PYTHONDONTWRITEBYTECODE=1 python scripts/mutation_probe.py --spec scripts/measurement/mutation_specs_dwarf_tip.json
PYTHONDONTWRITEBYTECODE=1 python scripts/mutation_probe.py --spec scripts/measurement/mutation_specs_ghidra_tip_tabani.json
```

## 6. Bu dizindeki kanıtlar

- `taban_ozeti.json`: `ghidra_tip_tabani.py olc` çıktısının kendisi (`taban.json`). İçinde nüfus ve tavan, (a)-(d) tabloları, tabakalar, iki tabaka kuralı, kapsam paydaları ve en büyük Ghidra kümeleri var.
- `bagimsiz_toplama.py`: ana sayıların `ghidra_tip_tabani.py` kullanılmadan yeniden toplanması.
- `capraz_yerlesim.py` + `capraz_yerlesim_sonuc.json`: yerleşim imzasının pyelftools'la bağımsız hesabı (704/704).
- `kosu.json`: betik sha256'ları, komutlar, süreler, davranış korunumu (116/116), testler ve mutantlar.

## Ana oturumun bağımsız denetimi (2026-10-21)

- **Testler ve mutantlar:**
  - `test_dwarf_tip.py` ve `test_ghidra_tip_tabani.py`: 147/147 geçti.
  - `dwarf_tip` 36/36 mutant öldü, `ghidra_tip_tabani` 22/22 öldü (`PYTHONDONTWRITEBYTECODE=1`).
- **Kapsam ve kesinlik ham parametre dosyasından yeniden hesaplandı.** Girdi `~/karadul_olcum/runs/t0c-a10fde3/taban/parametreler.jsonl`. Betiğin ve `bagimsiz_toplama.py`'nin kodu kullanılmadı.
  - Yöntem:
    - nüfus: `grup == "yapi*"` ve `k1_durum != "cok_tanimli"`;
    - küme: aynı ikilide aynı `ghidra_etiketi`;
    - çift kesinliği `kimlik` eşitliğiyle.
  - Sonuçlar:
    - K1 nüfusu 9 420.
    - Program başına kapsam tabloyla aynı (coreutils %13,3 … tmux %0).
    - Makro kapsam %6,9.
    - Çifti olan 7 programda katı kesinlik %100.
  - htop, tree ve zstd'de yalnız birer çift var. Kesinlik makrosu için en az 10 çift önerisi (S6) bu yüzden gerekli.
