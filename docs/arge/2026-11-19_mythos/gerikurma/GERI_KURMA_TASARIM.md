# GK-0 — Geri kurma hattının tasarımı

**Durum (2026-11-24 14:5x): bütün bölümler yazıldı.** Ölçümler bitti (§1); denetleyicinin hata oranları, B2 ve model katmanı bu turda ölçülmedi ve öyle işaretli. Belgedeki `‹…›` işaretleri bilerek bırakılmış yer tutuculardır (şema örneği, ön kayıt taslağı, README cümlesi, tip gösterimi örneği).

Karar: `KARARLAR.md` A-41 (Berke, 2026-11-24). İş emri: `docs/arge/2026-11-23_dalga1/gonderim/GK0.md`. Ölçüm betiği: `scripts/arge/gerikurma/derlenebilirlik.py`. Koşu kökü: `~/karadul_olcum/runs/dalga1-2026-11-23/GK0/` (özet `ozet/`).

Bu belge ürün kodu içermez. Ölçülmeyen her sayı "ölçülmedi" ya da "TAHMİN" diye işaretlidir.

## 0. Özet

### Berke için

1. **Bugün derlenen dosya sayısı sıfır.** S8'in 8 ikilisinde 7 127 `.c` dosyasının 0'ı, Ollama'da ölçülen 1 000 dosyalık örneklemin (13 159 dosyadan; tohum yazılı) 0'ı tek başına derleniyor. İşlev düzeyinde de 0. Kurulan proje uçtan uca derlenmiyor (§1.2, §1.4).
2. **Neden tek yerde:** her dosyanın içerdiği `types.h` kendisi derlenmiyor (dosya başına 159–2 559 hata; bütün hataların S8'de %92,8'i, Ollama örnekleminde %97,5'i başlıkta). Bu bilgi eksikliği değil, üretici kusuru: Ghidra'nın temel tip adları tanımlanmamış, enum sabitleri birbiriyle çakışıyor, yapı üyelerinde Ghidra'nın iç gösterimi kalmış (§1.2, §8.2).
3. **Başlık devre dışı bırakılınca** (karşı olgu ölçümü; ürün değil): S8'de dosyaların %12,3'ü (işlevlerin %8,5'i), Ollama'da %6,5'i derleniyor. S8'de kalan hataların %82,4'ü eksik bildirim: `.c` dosyaları, P18'in düzelttiği başlıkları hiç içermiyor (§1.3, §1.4).
4. **Go ayrı bir sorun:** Ollama'da dosyaların yalnız %27,6'sı C sözdizimi olarak bile geçerli (C ikililerinde %89–97); en büyük sınıf (%42,7) Ghidra'nın çözemediği yazmaç girişleri. "Eski hâline dönmek" Go / Swift / ObjC / C++'ta "C olarak derlenen ve denetlenen kod" demek olmalı; aynı dilde kaynak yalnız C'de hedef (§2.3, K-7).
5. **Eşdeğerlik için ilk işaret (keşif, ön kayıtsız, S8'in 8 ikilisi):** başlık devre dışıyken derlenen 877 işlev gerçekten derlenip özgün komutlarla karşılaştırıldı. mac/tmux'ta 299 işlevin 178'i (%59,5), Debian'ın 7 ikilisinde 578 işlevin 146'sı (%25,3) özgünle aynı komut dizisini verdi; Debian'da yalnız en çok 8 komutluk işlevler (9 komut ve üstü: 0 / 274). Yani komut eşitliği gerçek bir kanıt kaynağı, ama kapsamı ikiliye çok bağlı; tutmadığı yerde yük öykünmeye kalıyor. Özgün derleyiciler bu turda saptanmadı; farkın derleyici ailesinden geldiği bir yorumdur, ölçüm değil (§1.5).
6. **Tasarım:** beş basamak (B0 sözdizimi → B1 derlenir → B2 bağlanır → B3 denetlenmiş eşdeğer → B4 bayt eşit). Denetleyici üç kanıt türünü sırayla dener: komut dizisi eşitliği (Ghidra'sız; tuttuğunda en sağlam kanıt), simgesel ispat (küçük işlev), P-code öykünmesinde davranış farkı (genel, olasılık hükmü). BSim ve CFG eşbiçimliliği denetleyici **olamaz** (KİMLİK ölçümü: derleyici değişince 0,61 ve 0 eşleşme). Her kanıt türü, kaynağı elde olan ikililerde bozulmuş işlevlerle ölçülmeden etiket yazamaz (§3).
7. **Model önerir, hesap karar verir:** KaradulLM'in gövde önerisi B1 + B3'ü geçmeden çıktıya girmez; "derleniyor ama doğrulanmadı" diye de girmez. Model derleme ya da denetim başlatmaz; denetleyicinin girdi vektörlerini görmez (§3.6, §5).
8. **Plan:** 14 alt paket; ilk üçü (GK-A ölçüm kapısı, GK-B `types.h` onarımı, GK-C bildirim üretimi) ve GK-D (etiketli çift kümesi + komut eşitliği) bugün gönderilebilir, hiçbiri Ghidra ya da model istemez. TAHMİN 6–9 oturum + 1–2 gece, var olan plana eklenir (§8).
9. **Senden beklenen kararlar** (§9.3): K-2 (P-code öykünmesi "çalıştırma" sayılır mı — önerim: sayılmaz, beş koşulla), K-3 ("eşdeğer" etiketinin eşiği — önerim: yanlış kabul üst sınırı ≤ %1), K-5 (ürün çalışma anında derleyici çağırsın mı), K-7 (dil başına hedef), K-8 (model önerisinin çıktıya giriş yolu). Kalanı öneriyle yürür.

### Dürüst sınır

"Eski hâline döndü" cümlesi hiçbir zaman kurulamaz: özgün kaynak metni ikilide yok, program düzeyinde eşdeğerlik ispatlanamaz, hedef çalıştırılmadığı için uçtan uca sınanamaz. Kurulabilecek en güçlü cümle: "işlevlerin şu kadarı derleniyor ve özgün işlevle eşdeğerlik denetiminden şu kanıtla geçti" (§9.1). Bugün o cümledeki ilk sayı 0 (ölçüldü); ikincisi ölçülmedi (hiçbir birim derlenmezken verilemez).

## 1. Bugünkü durumun ölçümü

### 1.1 Yöntem ve künye

- **Betik:** `scripts/arge/gerikurma/derlenebilirlik.py` (commit `0cbac05c`; sha256 `f30a2753…`, koşu künyelerinde tam). Her `.c` dosyasını `clang -fsyntax-only -std=c11 -I<proje>/include -ferror-limit=0` ile dener; nesne dosyası üretmez, hiçbir şeyi çalıştırmaz; girdi köklerine yazmaz.
- **Derleyici:** `/usr/bin/clang` = Apple clang 21.0.0 (clang-2100.4.1.1), hedef `arm64-apple-darwin27.2.0`. ELF çıktıları da bu ana makine üçlüsüyle derlendi (hedef üçlüsüyle ölçüm GK-A'nın kalemi; etkisi aşağıda `sdk_cakismasi` sınıfı olarak sayıldı).
- **Girdiler (salt okundu):** S8 tabanının 8 çıktısı (`ANA/s8_taban_534e252b`, ürün `534e252b`) ve dünkü Ollama çıktısı (`ANA/ollama_ba_kapali/out`, ürün `152176b`, üst veri bayrakları açık, blok açıklama ve BSim kapalı).
- **Kipler:** K = derleyicinin öntanımlı hata kümesi. G = aynı koşuda `[-W…]` etiketi taşıyan (hataya yükseltilmiş uyarı) hatalar sayılmazsa; türetilmiş sütun, ayrı koşu değil. Projenin kendi derleme dosyaları `-std=c11 -w -Iinclude` kullanıyor; **`-w` bu clang sürümünde hataya yükseltilmiş uyarıları susturmuyor**: 20 286 dosyada (önsöz kipi, 9 çıktı) ve 1 089 dosyada (ürün kipi, 4 çıktı) gerçek `-w` koşusunun hükmü ve hata sayısı K ile birebir aynı. Yani "projenin kendi bayraklarıyla" sütunu = K sütunu.
- **İşlev düzeyi:** işlev sınırı sezgiseldir (üst düzeyde `)` ardından açılan küme ayracı); iki sayı verilir: "dosyası geçen işlev" (katı) ve "kendi satır aralığında hata olmayan işlev" (gövdesi temiz; başlıktan gelen hatalar hariç). İkincisi derleyicinin hata kurtarmasına bağlıdır, yaklaşık sayıdır.
- **Hata sınıfı:** derleyicinin iletisinden mekanik (tırnak içi adlar ve sayılar silinir), kaba sınıf + tanımsız adlarda ad ailesi. Dosya başına ilk 400 hata sınıflanır; sayımlar hepsini kapsar.
- **Süre ve örneklem:** eşzamanlı 4 iş. Ürün kipinde Ollama için tohumu yazılı (20261124) belirlenimci örneklem; ayrıntı 1.2'de. Önsöz kipinde 13 159 dosyanın hepsi (464 sn).
- **Koşu kökü:** `~/karadul_olcum/runs/dalga1-2026-11-23/GK0/` — `urun_s8/`, `urun_ollama/`, `onsoz/`, `urun_ilk4_dogrula_w/` (ilk düzenin `-w` doğrulamalı dört çıktısı), `yoklama/`, özet `ozet/`.

### 1.2 Ürün kipi: bugünkü `out/src` olduğu gibi

**Sonuç: hiçbir dosya derlenmiyor.** S8'in 8 çıktısında 7 127 `.c` dosyasının 0'ı; Ollama'da ölçülen 1 000 dosyanın 0'ı. İşlev düzeyinde "dosyası geçen işlev" de 0.

| Çıktı | `.c` (ölçülen / toplam) | işlev | dosya geçer K (= projenin kendi bayrakları) | işlev: dosyası geçer | hata toplam | başlıkta (pay) | dosya başına başlık hatası | kendi satırlarında hatasız dosya | kendi satırlarında ayrıştırma hatasız dosya |
|---|---|---|---|---|---|---|---|---|---|
| debian/cat | 109 / 109 | 296 | 0 (%0,0) | 0 (%0,0) | 20 582 | 17 876 (%86,9) | 164 | 4 (%3,7) | 100 (%91,7) |
| debian/sort | 247 / 247 | 625 | 0 (%0,0) | 0 (%0,0) | 77 688 | 69 160 (%89,0) | 280 | 16 (%6,5) | 201 (%81,4) |
| debian/tree | 120 / 120 | 250 | 0 (%0,0) | 0 (%0,0) | 22 689 | 19 080 (%84,1) | 159 | 8 (%6,7) | 89 (%74,2) |
| debian/htop | 613 / 613 | 1 148 | 0 (%0,0) | 0 (%0,0) | 326 887 | 312 630 (%95,6) | 510 | 39 (%6,4) | 405 (%66,1) |
| debian/sqlite3 | 434 / 434 | 1 144 | 0 (%0,0) | 0 (%0,0) | 143 753 | 128 030 (%89,1) | 295 | 46 (%10,6) | 328 (%75,6) |
| debian/zstd | 1 089 / 1 089 | 1 444 | 0 (%0,0) | 0 (%0,0) | 577 769 | 417 087 (%72,2) | 383 | 90 (%8,3) | 647 (%59,4) |
| debian/tmux | 1 925 / 1 925 | 2 588 | 0 (%0,0) | 0 (%0,0) | 1 292 035 | 1 243 550 (%96,2) | 646 | 169 (%8,8) | 1 240 (%64,4) |
| mac/tmux | 2 590 / 2 590 | 2 821 | 0 (%0,0) | 0 (%0,0) | 1 779 246 | 1 727 530 (%97,1) | 667 | 198 (%7,6) | 1 621 (%62,6) |
| **S8 toplam** | 7 127 / 7 127 | 10 316 | **0 (%0,0)** | **0 (%0,0)** | 4 240 649 | 3 934 943 (%92,8) | 552 | 570 (%8,0) | 4 631 (%65,0) |
| mac/Ollama (örneklem) | 1 000 / 13 159 | 1 000 | **0 (%0,0)** | **0 (%0,0)** | 2 623 871 | 2 559 000 (%97,5) | 2 559 | 31 (%3,1) | 131 (%13,1) |

- **Ollama örneklemi:** 13 159 dosyanın tohumlu (20261124) karıştırmasının ilk 1 000'i; 454,7 sn. Tamamı ölçülmedi (dosya başına 2 559 başlık hatası ayrıştırılıyor; 13 159 dosya TAHMİN 100 dk sürerdi). Örneklemde geçen 0 / 1 000 → tüm kümede geçme oranının %95 Wilson üst sınırı %0,4. Başlık bütün dosyalarda aynı olduğu için tam kümede de 0 beklenir; yine de "0 / 13 159" **ölçülmedi**.
- "Kendi satırlarında hatasız dosya" sütunu başlık onarımının etkisinin tahmini **değildir**: bozuk başlık, gövdede de tip hatası üretir (karşılaştır: 1.3'te aynı çıktılarda geçen dosya sayısı daha yüksek).
- Hata toplamı sütunu derleyicinin hata kurtarmasına bağlıdır (aynı kusur dosya başına yüzlerce ileti üretir); büyüklük karşılaştırması için değil, payların paydası olarak okunmalı.

**En büyük sınıflar (ürün kipi; hata sayısı payı; kaynak `ozet/havuz_urun_s8.json`, `ozet/havuz_urun_ollama.json`):**

| Sıra | S8 havuzu (4 240 649 hata) | pay | Ollama örneklemi (2 623 871 hata) | pay |
|---|---|---|---|---|
| 1 | başlıkta yeniden tanım (enum sabiti, yinelenen üye) | %42,9 | başlıkta ayrıştırma hatası (`expected …` %35,8 + öbür %15,5) | %51,3 |
| 2 | başlıkta bilinmeyen tip adı (Ghidra temel tip adları %17,1 + öbür adlar %7,0 + SDK çakışmalı %0,2) | %24,3 | başlıkta yeniden tanım | %37,4 |
| 3 | başlıkta ayrıştırma hatası (`expected …` %15,2 + öbür %8,9) | %24,1 | başlıkta bilinmeyen tip adı | %8,2 |
| 4 | gövdede tanımsız tanımlayıcı (bozuk başlığın düşürdüğü tipler dahil) | %5,4 | gövdede tanımsız tanımlayıcı | %1,8 |
| 5 | gövdede eksik işlev bildirimi | %1,0 | gövdede eksik işlev bildirimi | %0,2 |

İlk üç sınıf başlıktadır, her dosyada (%100) görülür ve hataların S8'de %91,3'ünü, Ollama örnekleminde %96,9'unu oluşturur. Her dosyanın **ilk** hatası da başlıktadır: S8'de 3 568 dosyada enum sabitinin yeniden tanımı, 2 590 dosyada (mac/tmux'un tamamı) ayrıştırma hatası, 969 dosyada (cat, sort, htop'un tamamı) ana makine SDK'sıyla tip çakışması; Ollama örnekleminde 1 000 / 1 000 dosyada ayrıştırma hatası.

### 1.3 Karşı olgu: `types.h` devre dışı, yerine Ghidra temel tip önsözü

"Başlık onarılsa gövdeler ne durumda" sorusunun ölçümü. Projenin `types.h` dosyası başlık korumasıyla (`-D_TYPES_H_`) devre dışı bırakıldı; yerine yalnız Ghidra'nın temel tip adlarını tanımlayan 19 satırlık önsöz verildi (betikte `ONSOZ_METNI`: kurtarılmış tip, işlev bildirimi, p-code işleci **içermez**). **Bu tablo ürün çıktısının derlenebilirliği değildir**; GK-B'nin beklenen etkisinin ilk tahminidir (kurtarılmış yapılar geri gelince bir kısım dosya daha geçebilir ya da yeni çakışma çıkabilir: ölçülmedi; GK-B ön kaydı H2 bunu sınar).

| Çıktı | `.c` (ölçülen / toplam) | işlev | dosya geçer K | dosya geçer G | ayrıştırma hatasız dosya (B0) | işlev: dosyası geçer K | işlev: gövdesi temiz K | gövdesi temiz G | hata K |
|---|---|---|---|---|---|---|---|---|---|
| debian/cat | 109 / 109 | 296 | 5 (%4,6) | 39 (%35,8) | 104 (%95,4) | 5 (%1,7) | 49 (%16,6) | 129 (%43,6) | 987 |
| debian/sort | 247 / 247 | 625 | 32 (%13,0) | 108 (%43,7) | 227 (%91,9) | 32 (%5,1) | 104 (%16,6) | 255 (%40,8) | 3 592 |
| debian/tree | 120 / 120 | 250 | 8 (%6,7) | 19 (%15,8) | 107 (%89,2) | 8 (%3,2) | 49 (%19,6) | 63 (%25,2) | 2 527 |
| debian/htop | 613 / 613 | 1 148 | 69 (%11,3) | 290 (%47,3) | 560 (%91,4) | 69 (%6,0) | 191 (%16,6) | 537 (%46,8) | 7 368 |
| debian/sqlite3 | 434 / 434 | 1 144 | 57 (%13,1) | 186 (%42,9) | 391 (%90,1) | 57 (%5,0) | 268 (%23,4) | 602 (%52,6) | 6 530 |
| debian/zstd | 1 089 / 1 089 | 1 444 | 164 (%15,1) | 477 (%43,8) | 1 011 (%92,8) | 164 (%11,4) | 238 (%16,5) | 633 (%43,8) | 28 437 |
| debian/tmux | 1 925 / 1 925 | 2 588 | 243 (%12,6) | 1 027 (%53,4) | 1 851 (%96,2) | 243 (%9,4) | 397 (%15,3) | 1 335 (%51,6) | 19 406 |
| mac/tmux | 2 590 / 2 590 | 2 821 | 299 (%11,5) | 1 754 (%67,7) | 2 522 (%97,4) | 299 (%10,6) | 306 (%10,8) | 1 764 (%62,5) | 18 958 |
| **S8 toplam** | 7 127 / 7 127 | 10 316 | 877 (%12,3) | 3 900 (%54,7) | 6 773 (%95,0) | 877 (%8,5) | 1 602 (%15,5) | 5 318 (%51,6) | 87 805 |
| mac/Ollama | 13 159 / 13 159 | 13 554 | 852 (%6,5) | 1 589 (%12,1) | 3 634 (%27,6) | 852 (%6,3) | 853 (%6,3) | 1 602 (%11,8) | 470 819 |

Bu kipte hataların tamamı `.c` dosyalarının kendi satırlarındadır (başlık kaynaklı 0). Sınıf dağılımı (hata sayısı payı; parantezde sınıfın görüldüğü dosya payı; kaynak `ozet/havuz_onsoz.json`):

| Sıra | S8 havuzu (87 805 hata) | pay | Ollama (470 819 hata) | pay |
|---|---|---|---|---|
| 1 | eksik işlev bildirimi, adlı işlev | %24,9 (%60,3) | tanımsız tanımlayıcı, Ghidra yazmaç değişkeni (`in_`, `unaff_`, `register0x…`) | %42,7 (%69,6) |
| 2 | eksik işlev bildirimi, `FUN_<adres>` | %23,9 (%63,3) | tanımsız tanımlayıcı, `DAT_` / `PTR_` | %16,2 (%61,6) |
| 3 | tanımsız tanımlayıcı, adlı veri | %18,2 (%24,5) | eksik işlev bildirimi, adlı işlev | %14,2 (%79,8) |
| 4 | tanımsız tanımlayıcı, `DAT_` / `PTR_` | %15,4 (%28,9) | üye erişimi tip hatası (parça erişimi) | %10,6 (%34,9) |
| 5 | üye erişimi tip hatası | %4,5 (%3,8) | değer / tip uyuşmazlığı | %4,7 (%58,1) |
| 6 | değer / tip uyuşmazlığı | %4,3 (%27,6) | tanımsız tanımlayıcı, adlı veri | %3,1 (%71,9) |
| 7 | eksik işlev bildirimi, p-code işleci | %2,0 (%6,2) | sözdizimi (`expected …`) | %2,5 (%70,0) |
| 8 | tanımsız tip adı | %1,5 (%1,9) | eksik işlev bildirimi, `FUN_<adres>` | %2,3 (%11,2) |
| 9 | tanımsız tanımlayıcı, yığın değişkeni | %1,5 (%2,7) | eksik işlev bildirimi, p-code işleci | %1,4 (%18,5) |
| 10 | sözdizimi (`expected …`) | %1,3 (%4,8) | çağrı tip hatası (argüman sayısı) | %1,1 (%14,6) |

İlk 20 sınıfın tamamı, çıktı başına, `ozet/derlenebilirlik_onsoz.md` ve `ozet/derlenebilirlik_urun_*.md` dosyalarındadır (üçüncü taraf adı içermez: yalnız sınıf ve sayı).

### 1.4 Ölçümün yan bulguları

1. **`.c` dosyaları alt sistem başlıklarını içermiyor.** S8'in ve Ollama'nın bütün `.c` dosyalarındaki `#include` satırları yalnız `"types.h"`'dir (sayıldı: S8'in 8 çıktısında 10 316 / 10 316, Ollama'da 13 554 / 13 554 satır; bu sayılar betiğin sezgisel işlev sayımıyla 9 / 9 çıktıda birebir aynı, yani her işlev kendi `#include` satırıyla geliyor). P18'in tutarlı hâle getirdiği `include/subsystem_*.h` bildirimleri hiçbir derleme birimine girmiyor; 1.3'teki ilk iki sınıfın (S8'de hataların %48,8'i) nedeni budur.
2. **`types.h` kendi başına derlenmiyor.** Tek başına derlendiğinde hata sayısı: debian/cat 164, debian/zstd 383, Ollama 2 559. Her `.c` dosyası bu hataları yeniden üretir; 1.2'deki "başlıkta" sütunu bunun toplamıdır.
3. **Kurulan proje uçtan uca derlenmiyor.** `make` / `cmake` koşulmadı (gerek kalmadı): projenin kendi bayraklarıyla tek tek derlenen dosya sayısı her çıktıda 0 olduğundan ilk dosyada durur. Bağlama (B2) bu yüzden ölçülemedi.
4. **Ana makine SDK'sı ile çakışma** (`+sdk_cakismasi` etiketli sınıflar): `types.h` barındırılan sistem başlıklarını çektiği için hedefin tip adları Mac SDK'sının tanımlarıyla çakışıyor; üç Debian çıktısında (cat, sort, htop; 969 dosya) her dosyanın **ilk** hatası budur. Hedef üçlüsü + `-ffreestanding` ile ölçüm GK-A'da.
5. **G sütunu yanıltıcı iyimserdir** (§2.2): önsöz kipinde S8'de K ile %12,3, G ile %54,7 dosya geçiyor; aradaki 3 023 dosya bildirimsiz çağrıyı `int` döndüren işlev sayarak "geçiyor".

### 1.5 Ön yoklama: K1 bugünkü çıktıda kaç işlevde tutuyor? (keşif; ön kayıtsız)

Tasarımın en büyük riski B3'ün kapsamıdır (§9.2). Bu yüzden, ölçüm bittikten sonra kalan sürede küçük bir **keşif** yapıldı: önsöz kipinde hatasız geçen dosyalar (S8'in 8 çıktısında 877 dosya = 877 işlev; hepsi tek işlevli) gerçekten nesne dosyasına derlendi (`clang -c`, beş profil: `-O0`, `-O1`, `-O2`, `-Os`, `-O3`; hedefin üçlüsüyle; ELF için ek bayrak `-ffreestanding -mbranch-protection=standard`) ve her işlevin komut dizisi, özgün ikilideki aynı adresteki işlevin komut dizisiyle karşılaştırıldı (`/usr/bin/objdump` ile durağan çözme; hiçbir şey çalıştırılmadı; nesne dosyaları koşu kökünde). Karşılaştırma K1'in kaba bir ilk sürümüdür: komut adı + işlenenler; çağrı hedefi, sayfa adresi ve sayfa içi ofset maskeli; işlev içi dallar başa göre bağıl.

**Sınırları:** ön kayıtsız; yeniden yerleştirme **hedefleri** denetlenmedi (bu yüzden "komut eş adayı"; B4 değil); nüfus, hiçbir bildirim olmadan derlenebilen dosyalardır — küçük yaprak işlevlere yanlıdır (877 işlevin 455'i en çok 8 komut), oranlar kalan işlevlere taşınamaz; Ollama (Go) koşulmadı. Betikler koşu kökünde (`GK0/yoklama/k1_yoklama.py`, `k1_karsi_denetim.py`; özetler `ozet/yoklama_*.json`), depoda değil; GK-D yeniden ve sınamalı yazar.

| Çıktı | derlenen işlev | komut sayısı eşit | komut adı dizisi eşit | **komut eş adayı** (en az bir profilde) | özgün ≤ 8 komut | 9–32 komut | > 32 komut | çıktının bütün işlevlerine oranı |
|---|---|---|---|---|---|---|---|---|
| mac/tmux (Mach-O arm64) | 299 | 249 (%83,3) | 209 (%69,9) | **178 (%59,5)** | 139 / 151 | 39 / 119 | 0 / 29 | 178 / 2 821 = %6,3 |
| debian/cat | 5 | 0 | 0 | **0** | 0 / 2 | 0 / 3 | — | 0 / 296 |
| debian/sort | 32 | 8 (%25,0) | 8 (%25,0) | **6 (%18,8)** | 6 / 13 | 0 / 12 | 0 / 7 | 6 / 625 = %1,0 |
| debian/tree | 8 | 3 (%37,5) | 3 (%37,5) | **3 (%37,5)** | 3 / 6 | 0 / 2 | — | 3 / 250 = %1,2 |
| debian/htop | 69 | 40 (%58,0) | 27 (%39,1) | **14 (%20,3)** | 14 / 34 | 0 / 32 | 0 / 3 | 14 / 1 148 = %1,2 |
| debian/sqlite3 | 57 | 33 (%57,9) | 16 (%28,1) | **5 (%8,8)** | 5 / 39 | 0 / 9 | 0 / 9 | 5 / 1 144 = %0,4 |
| debian/zstd | 164 | 113 (%68,9) | 99 (%60,4) | **70 (%42,7)** | 70 / 106 | 0 / 42 | 0 / 16 | 70 / 1 444 = %4,8 |
| debian/tmux | 243 | 150 (%61,7) | 85 (%35,0) | **48 (%19,8)** | 48 / 104 | 0 / 100 | 0 / 39 | 48 / 2 588 = %1,9 |
| **Debian 7 ikili (ELF aarch64)** | 578 | 347 (%60,0) | 238 (%41,2) | **146 (%25,3)** | 146 / 304 | **0 / 200** | **0 / 74** | 146 / 7 495 = %1,9 |

- **Profil başına:** mac/tmux'ta `-Os` 178, `-O1` 171, `-O2` 170, `-O3` 169, `-O0` 3. Debian'ın 7 ikilisinde `-O1` = `-O2` = `-Os` = `-O3` (toplam 131), `-O0` 28; "en az bir profilde" 146.
- **Karşı denetim (`-Os`):** her yeniden derlenen işlev, kümedeki **başka** işlevlerin özgün dizisiyle de karşılaştırıldı. mac/tmux: 89 102 çapraz çiftte 84 eşleşme (74'ünde iki özgün dizi zaten birbirinin aynısı); kendi özgünüyle eşleşen 178 işlevin 142'sinde özgün dizi kümede tekil. Debian 7 ikili: 394 çapraz eşleşme; `-Os`'ta kendi özgünüyle eşleşen 131 işlevin 66'sında özgün dizi tekil. Çapraz eşleşme karşılaştırıcının hatası değildir (diziler gerçekten aynı); en küçük işlevlerde aynı komut dizisinin ne kadar yaygın olduğunu gösterir. Sonucu: eşleşme "aynı davranış" kanıtıdır, "aynı işlev" kanıtı değil; ve §3.4'teki N2 kümesi özgün dizileri aynı olan çiftleri dışlamalıdır.

Okuma (hüküm değil, yön):

1. **K1 kâğıt üstünde bir fikir değil.** Mach-O ikilisinde derlenebilen işlevlerin %59,5'i yeniden derlenince özgünle aynı komut dizisini verdi; 9–32 komutluk işlevlerde 39 / 119.
2. **Derleyici tutmayınca K1 yalnız en küçük işlevlerde kalıyor.** Debian'ın 7 ELF ikilisinde (özgün derleyici saptanamadı: ikililerde derleyici izi yok, §4 D6; clang ile yeniden derlendi) 9 komut ve üstündeki 274 işlevin **hiçbiri** eşleşmedi; eşleşen 146 işlevin hepsi en çok 8 komutluk. Bu, §3.3'teki sıralamanın (K1 → K3 → K2) ve K-4'ün (derleyici profili kümesi, ELF için GCC) ölçülmüş gerekçesidir: ELF tarafında B3'ün yükünü K2 taşıyacak ya da özgün derleyici ailesi kurulacak.
3. **Derleyici profili ölçümle bulunabilir (D6):** mac/tmux'ta `-Os` öbür düzeylerden fazla eşleşme verdi (178 ↔ 169–171); fark küçük, tek ikili — iddia değil, GK-D'nin ölçeceği şey.
4. **Bugünkü ürün için anlamı:** hiçbir şey. Bu işlevler ürün çıktısında derlenmiyor (1.2); sayı, GK-B + GK-C'den sonra K1'in bulacağı zeminin ilk işaretidir.

### 1.6 Bu turda ölçülmeyenler

- B2 (bağlama) ve B3 (eşdeğerlik; 1.5'teki keşif dışında): ölçülmedi.
- Hedef üçlüsüyle derleme (ELF çıktıları Linux üçlüsüyle): ölçülmedi.
- C++ ikilisi, terminal-notifier (ObjC), Swift ikilisi: ölçülmedi. 119'luk setin kalan 111 ikilisi: ölçülmedi.
- Ara aşamaların (ham Ghidra çıktısı, `reconstructed/…`) derlenebilirliği: ölçülmedi (boru hattının derlenebilirliği artırıp azalttığı bilinmiyor).
- İşlev başına yalıtılmış birim derlemesi (bugün dosya düzeyi; çok işlevli dosyalarda işlev düzeyi sayı yaklaşık): GK-A.
- Yerel model: bu tur hiç koşmadı.

## 2. Boşluk sınıflaması

"Boşluk" = bir işlevin B*k*'den B*k+1*'e çıkmasını engelleyen şey. Büyüklükler §1'in ölçümünden; "pay" sütunları **önsöz kipindeki** hata sayısı payıdır (başlık devre dışıyken `.c` dosyalarının kendi hataları; S8 = 8 ikili havuzu, 87 805 hata; Ollama 470 819 hata; kaynak `GK0/ozet/havuz_onsoz.json`). Ürün kipinde bunların hepsinin önünde A sınıfı durur.

### 2.1 Sınıflar

| Kod | Boşluk | S8 payı (hata; görüldüğü dosya) | Ollama payı | Belirlenimci onarılır mı | Model gerekir mi | Kurtarılamaz mı | Paket |
|---|---|---|---|---|---|---|---|
| **A** | Tip başlığı (`types.h`) derlenmiyor: Ghidra temel tip adları tanımsız, enum sabit çakışması ve geçersiz adlar, yapı üyesinde tip kategorisi yolu ve typedef gösterimi, hedefin sistem tipleri, ana makine SDK'sıyla çakışma | ürün kipinde her dosyanın ilk hatası (§1.2) | aynı | **evet, tamamı** (hepsi üretici hatası; bilgi eksik değil) | hayır | hayır | GK-B |
| **B** | Çağrılan işlevin bildirimi yok: adlı işlev (içe aktarım, kurtarılmış ad) %24,9; `FUN_<adres>` %23,9 | %48,8; adlı %60,3, `FUN_` %63,3 dosyada | %14,2 + %2,3 | **evet**: program işlevinin imzası tanımından, içe aktarımınki Ghidra'nın imzasından. İmza kaynağı yoksa (Ghidra `undefined` döndürmüşse) bildirim yazılabilir ama doğruluğu bilinmez | yalnız imzası bilinmeyen içe aktarımda (tip önerisi) | hayır | GK-C |
| **C** | Veri simgesinin bildirimi yok: `DAT_` / `PTR_` %15,4; adlı veri (içe aktarılan değişken, kurtarılmış genel değişken) %18,2 | %33,6 | %16,2 + %3,1 | **kısmen**: adres ve ad belli; tip Ghidra'nın o adresteki veri tipiyse yazılır, `undefinedN` ise yalnız genişlik bilinir | tip önerisi (yapı mı, dizi mi) | tipin **adı** ve alan adları kurtarılamaz; yerleşim (genişlik, ofset) kullanımından çıkar | GK-C, GK-J |
| **D** | Ghidra'nın sahte değişkenleri: çözülememiş yazmaç girişi (`in_`, `unaff_`, `extraout_`, `register0x…`), yığın artığı | %0,1 + %1,5 | **%42,7** (dosyaların %69,6'sında; %48'inde ilk hata) | C'de: çoğu yanlış kurtarılmış parametre sayısı / çağrı düzeni → imza onarımı (belirlenimci aday; ölçülmedi). Go'da: dilin çağrı düzeni ve yığın büyütme önsözü → dile özgü uyarlayıcı | imza önerisi | hayır (bilgi ikilide var; decompiler çözememiş) | GK-G, GK-L |
| **E** | P-code işleçleri (`CONCATxy`, `SUBxy`, `ZEXT`, `SEXT`, `CARRY`, `SBORROW` …) | %2,0 | %1,4 (dosyaların %18,5'i) | **evet, tamamı** (anlamı tanımlı; başlık) | hayır | hayır | GK-G |
| **F** | Parça erişimi ve tip uyuşmazlığı: dizi / tamsayı üstünde alan erişimi (Ghidra'nın `._ofset_boyut_` parça gösterimi), atanamayan dizi, işaretçi ↔ tamsayı, argüman sayısı | %4,5 + %4,3 + %0,7 | %10,6 + %4,7 + %1,1 | parça erişimi **evet** (kaydırma + maske ifadesine mekanik çeviri); kalan tip uyuşmazlıkları tip kurtarmanın kalitesine bağlı (kısmen) | **evet**: tip seçimi (hangi yapı, hangi imza) modelin en doğal görevi; B3 denetler | hayır | GK-G, GK-J |
| **G** | C sözdizimi olarak geçersiz çıktı: `expected …`; dizi döndüren işlev bildirimi | %1,3 (dosyaların %4,8'i) | %2,5 hata ama dosyaların **%70,0**'ı; dizi döndüren işlev 2 794 dosya | Go kaynaklı olanlar (yığın büyütme döngüsü, çok değerli dönüş) dile özgü kuralla; C'dekiler tek tek sınıflanmadı | belki | hayır | GK-L |
| **H** | Tanımsız tip adı (gövdede) | %1,5 | %0,1 | A onarılınca büyük kısmı kalkar (önsöz kipi kurtarılmış tipleri vermiyor); kalan = hedefin sistem tipleri | hayır | hayır | GK-B |
| **I** | Aynı birimde yeniden tanım | %0,8 (dosyaların %0,3'ü) | ≈ 0 | evet (birleştirme hatası) | hayır | hayır | GK-B / ÇA |
| **J** | Bağlama: çift tanım, çözülmeyen simge, çağıran ↔ tanım imza farkı | **ölçülmedi** (B1 = 0 iken ölçülemez) | ölçülmedi | büyük ölçüde evet | imza seçimi | hayır | GK-H |
| **K** | Derleniyor ama eşdeğer değil: decompiler hatası (yanlış genişlik, kaybolan yan etki, yanlış dal), tip hatasının davranışa yansıması | **ölçülmedi**; ön yoklama §1.5 | ölçülmedi | kısmen (bilinen decompiler kalıpları) | **evet**: karşı örnekle onarım (§5.1 `onar_esdegerlik`) | hayır (özgün baytlar hep elde) | GK-E, GK-J |
| **L** | Gövde yok: decompile edilmemiş (tembel kip), decompile başarısız | bu turda sayılmadı | sayılmadı | tembel kipte "istenince decompile" (ÖL-10) | başarısız decompile'da model komut listesinden gövde önerebilir; B3 denetler | hayır | ÖL-10, GK-J |
| **M** | İkilide olmayan bilgi: özgün adlar, yorumlar, makrolar, tip adları, dosya düzeni, satır içine alınmış işlevlerin sınırı | — | — | hayır | **uydurabilir** (A-41 buna izin veriyor: "kendi isimlendirmeleri ile") ama doğrulanamaz; etiket `model önerisi` | **evet** | — |

Okuma: (1) S8'de (C) başlık onarıldıktan sonra kalan hataların %82,4'ü iki bildirim sınıfıdır (B + C) ve ikisi de belirlenimci kapatılır; model gerekmez. (2) Ollama'da (çoğu Go) tablo başka: en büyük sınıf D'dir ve dile özgüdür. (3) Modelin gerçekten gerektiği yer F ve K'dir; ikisinin de büyüklüğü, önündeki belirlenimci sınıflar kapanmadan ölçülemez. Bu yüzden sıra: GK-B → GK-C → GK-G, sonra model.

### 2.2 "Derlenir kılmak" ile "kurtarmak" arasındaki fark

§1'in G sütunu (hataya yükseltilmiş uyarılar sayılmazsa geçenler) bir uyarıdır: önsöz kipinde S8'de K ile 877 dosya geçerken G ile 3 900 dosya "geçiyor" (§1.3). Aradaki fark, bildirimi olmayan işlevi `int f()` sayan derleyici kolaylığıdır; o kod bağlanınca ya da çalışınca yanlıştır (dönüş genişliği, argüman aktarımı). Bu hatta B1 **K ile** tanımlıdır; G yalnız "bildirim gelince kaç dosya daha geçmeye aday" tahmini olarak kullanılır (GK-C ön kaydı H2).

### 2.3 Dil başına: "eski hâline dönmek" ne demek

| Dil | Ölçülen (bu tur) | "Eski hâline dönmek" (öneri; K-7) | Dile özgü boşluklar |
|---|---|---|---|
| **C** | S8'in 8 ikilisi: ürün kipinde 0 dosya; önsöz kipinde K %4,6–%15,1 | Aynı dilde: C. Hedefin çağrı düzeniyle derlenir; B0–B4'ün hepsi anlamlı | A–F; satır içine alma (işlev kümesi ikilininki) |
| **C++** | **ölçülmedi** (S8'de C++ ikilisi yok; 119'da var, bu turda koşulmadı) | C olarak: sınıflar yapı, yöntemler `this` parametreli işlev, sanal çağrı işlev işaretçisi. Aynı dilde (sınıf bildirimiyle) çıktı bu planda yok | C'de yazılamayan adlar (P18: nitelikli adlar yorumla yazılıyor), sanal tablolar, **istisna yolları** (C çıktısında yok: B3 yalnız istisnasız yollar), şablon örneklemeleri |
| **Go** | Ollama dilimi (ad haritasında 10 475 Go adı): ürün kipinde 0; önsöz kipinde K %6,5; **ayrıştırma hatasız dosya yalnız %27,6** (S8'de %89,2–%97,4) | C olarak. Go kaynağı hedef değil: goroutine, arayüz, çöp toplayıcı yazma engeli, yığın büyütme çalışma zamanı çağrısı olarak görünür; C'ye çevrilen şey o çağrılardır | Yazmaç tabanlı çağrı düzeni (D sınıfı: %42,7), yığın büyütme önsözü (G), çok değerli dönüş (dizi döndüren işlev: 2 794 dosya), çalışma zamanı işlevleri (decompile edilmezse bildirim yeter: A-33 K-5) |
| **ObjC** | Ayrı ölçüm yok (Ollama'da 151 yöntem; `objc` ad ailesi 339 hata; terminal-notifier bu turda ölçülmedi) | C + çalışma zamanı çağrıları (ileti gönderimi işlev çağrısı olarak). Sınıf iskeleti üst veriden biliniyor: `.m` biçiminde çıktı ayrı ve sonraki bir karar | Seçici ve sınıf simgeleri, blok yapıları, ARC çağrıları |
| **Swift** | **ölçülmedi** | C olarak; Go ile aynı gerekçe (tanık tabloları, genel tipler, ARC) | Çağrı düzeni (hata ve bağlam yazmaçları), ayıklanmış adların C'de yazılamaması |

Bu tablonun sonucu: "eski hâline dönmek" her dilde **C sözdiziminde, hedefin çağrı düzenine uyarlanmış, denetleyiciden geçmiş kod** demektir. Aynı dilde kaynak yalnız C'de hedeftir.

## 3. Denetleyicinin tasarımı

Denetleyici bu hattın kalbidir: motorun ya da modelin ürettiği her parça için "geçti / geçmedi / hükümsüz" cevabını **makine** verir. Bu bölümdeki hata oranlarının (yanlış kabul, yanlış ret) hiçbiri ölçülmedi; hepsi GK-D ve GK-E'nin ön kayıtlı ölçümüdür. Ölçülmüş olan yalnız şunlardır: (a) bugünkü çıktının B0 / B1 sayıları (§1) ve K1'in keşif ölçümü (§1.5), (b) makinedeki derleyicinin başka hedefler için nesne dosyası üretebildiği (aşağıda 3.2), (c) KİMLİK hattının derleyiciler arası benzerlik sayıları (3.3'te taban olarak anılır).

### 3.1 Basamaklar ve "ne zaman tuttu sayılır"

| Basamak | Tanım | Birim | "Tuttu" ölçütü (makinenin cevabı) | Ölçen |
|---|---|---|---|---|
| **B0** sözdizimi geçerli | Derleyicinin ayrıştırıcısı metni kabul eder | dosya, işlev | `clang -fsyntax-only` çıktısında `Parse Issue` ve `Lexical or Preprocessor Issue` kategorisinde hata 0 | `derlenebilirlik.py` (bugün var) |
| **B1** tek başına derlenir | Birim (işlev gövdesi + üretilmiş önsözü) hedefin mimarisi için nesne dosyası verir | dosya, işlev | Öntanımlı hata kümesiyle hata 0 (`-w` ya da `-Wno-error=…` yok); nesne dosyasında işlevin simgesi tanımlı | `derlenebilirlik.py` (bugün `-fsyntax-only`; GK-A nesne kipini ekler) |
| **B2** projeyle bağlanır | Bütün birimler B1'de ve yeniden yerleştirilebilir bağlama hatasız | program; işlev için "imza tutarlı" | (a) çift tanımlı simge 0; (b) çözülmeyen simge kümesi ⊆ özgün ikilinin içe aktarım tablosu ∪ adresi bilinen veri simgeleri; (c) her çağrı noktasındaki bildirim, projedeki tek tanımın imzasıyla aynı. Çalıştırılabilir dosya üretilmesi gerekmez; üretilirse de çalıştırılmaz | GK-H |
| **B3** işlev düzeyinde eşdeğer | Yeniden derlenen işlev, özgün ikilideki aynı adresteki işlevle aynı gözlenebilir davranışı verir | işlev | Kabul eden kanıt türünün **ölçülmüş** yanlış kabul oranının Wilson üst sınırı eşiğin altında (3.5). Üç kanıt türü: `komut_eş` (3.3 K1), `öykünme` (K2), `smt` (K3) | GK-D, GK-E, GK-F |
| **B4** bayt eşit | Yeniden derlenen işlevin makine kodu özgün işlevin baytlarına eşit (yeniden yerleştirme alanları maskelenir, hedefleri ayrıca eşlenir) | işlev | Bayt karşılaştırması; kanıt türü `bayt_eş` | GK-D |

Program düzeyi sayılar her basamak için oran olarak verilir: işlev sayısıyla ve kod baytı ağırlığıyla (büyük işlevler küçüklerin arkasına saklanmasın). "Program eşdeğer" diye tek bir hüküm verilmez; verilebilecek en güçlü cümle "N işlevin M'si B3'te, kalan N − M için hüküm yok / geçmedi"dir.

İki not:

1. **B4 yalnız üst basamak değil, en ucuz ve yanlış kabulü olmayan denetleyicidir.** Bayt eşitliği tuttuğu yerde eşdeğerlik tanım gereği tutar; öykünmeye ya da SMT'ye gerek kalmaz. Bu yüzden denetim sırası ucuzdan pahalıya ve sağlamdan olasılığa doğrudur: `bayt_eş` → `komut_eş` → `smt` → `öykünme`. Kapsamı ön kayıtlı biçimde ölçülmedi; keşif ölçümü §1.5'te (derlenebilen işlevlerde mac/tmux %59,5, Debian'ın 7 ikilisi %25,3; derleyici ailesi tutmayınca yalnız en küçük işlevler).
2. **B3 bir olasılık hükmüdür, ispat değil** (`smt` ve `bayt_eş` dışında). Çıktıda her işlev hangi kanıt türüyle geçtiğini ve o türün ölçülmüş hata sınırını taşır (§5.5 etiket şeması).

### 3.2 Yalıtılmış birim ve derleme

Denetleyicinin girdisi tek işlevdir; çıktının tamamının derlenmesini beklemez (bugün 0 dosya derleniyor; §1).

1. **Birim:** aday işlevin C metni + üretilmiş **birim önsözü**: o işlevin kullandığı tipler, çağırdığı işlevlerin bildirimleri, başvurduğu veri simgelerinin `extern` bildirimleri (§4 GK-C). Önsöz belirlenimci üretilir; modelin yazdığı metinde önişlemci yönergesi (`#…`) bulunamaz (bekçi kuralı, §5.6).
2. **Derleme:** hedefin mimarisi ve nesne biçimi için `clang -c`. Bu turda denendi (kendi yazdığım iki satırlık bir C dosyasıyla, hedef kodla değil): `Apple clang 21.0.0` aynı makinede `--target=aarch64-unknown-linux-gnu -ffreestanding` ile ELF aarch64, `--target=x86_64-unknown-linux-gnu -ffreestanding` ile ELF x86-64, `--target=arm64-apple-macos` ile Mach-O arm64 nesne dosyası üretti; `/usr/bin/objdump` ELF aarch64 nesnesini çözdü (`GK0/capraz_deneme/`). Sistem başlıkları gerekmediği için (`-ffreestanding` + kendi önsözümüz) Linux hedefinde sysroot gerekmez. Bağlama (B2) için hedef kitaplıkları gerekmez: yalnız yeniden yerleştirilebilir bağlama yapılır.
3. **Derleyici profili:** özgün derleyici ve bayraklar bilinmediğinden birim küçük bir profil kümesiyle derlenir (öneri: `clang` `-O0`, `-O1`, `-O2`, `-Os`, `-O3`; makinede Homebrew GCC 16.2.0 var ama yalnız Mach-O hedefli, ELF için GCC çapraz derleyicisi yok → ELF'te GCC profili bugün kurulamaz, "ölçülemedi" yazılır). Karşılaştırıcılar her profile uygulanır; biri geçerse işlev geçer ve geçen profil kayda yazılır. Profil sayısı yanlış kabul fırsatını çoğaltır: ölçüm (3.4) aynı profil kümesiyle yapılır, eşik o kümeyle birlikte geçerlidir.
4. **Tanımsız davranış:** decompiler çıktısı C standardına göre tanımsız davranış içerir (işaretli taşma, tip üstünden erişim, işaretçi ↔ tamsayı). Derleyici bunları makine anlamından farklı derleyebilir. Bu yüzden (a) birim her profilde `-fwrapv -fno-strict-aliasing -fno-delete-null-pointer-checks` ile derlenir (makine anlamına en yakın C), (b) B3 hükmü **o profille derlenmiş nesne** için verilir ve profil etikette yazar; "kaynak metni her derleyicide eşdeğerdir" iddiası yapılmaz.
5. **Güvenlik:** derleme hedef kodu çalıştırmaz. Modelin yazdığı metni derlemek ayrı bir risktir (dosya içerme, derleyici eklentisi): önsöz dışında önişlemci yönergesi yasak, `-nostdinc` + yalnız kendi önsöz dizini, derleme `sandbox-exec` ile ağ kapalı ve yazma yalnız koşu dizinine (KİMLİK V1 derlemesindeki düzenin aynısı; `kimlik/PK-6.md` "V1 derlemesi"). Derlemeyi model değil denetleyici başlatır: KaradulLM'in araç kayıt defterinde süreç başlatan araç yine yoktur (`2026-11-18_karadullm_v2/TASARIM.md` §3.9).

### 3.3 Karşılaştırıcılar (hüküm 4'ün adayları)

| Kod | Aday | Ne karşılaştırır | Güçlü yanı | Zayıf yanı | Ghidra | Maliyet (ölçülmedi) | Hangi basamak |
|---|---|---|---|---|---|---|---|
| **K1** | Bayt / normalize komut dizisi eşitliği | Yeniden derlenen işlevin komutları ↔ özgün işlevin komutları; yeniden yerleştirme alanları maskelenir, çağrı ve veri hedefleri simge ↔ adres eşlemesiyle ayrıca karşılaştırılır | Tuttuğunda yanlış kabul yok (yapım gereği); Ghidra gerektirmez (`/usr/bin/objdump` + özgün baytlar adres + boyuttan) | Derleyici / bayrak tutmazsa hiç tutmaz; kapsamı derleyici profiline bağlı | hayır | TAHMİN işlev × profil başına 10–100 ms | B4 (`bayt_eş`), B3 (`komut_eş`: yazmaç adı ve eşdeğer komut seçimi normalize edilmiş) |
| **K2** | P-code öykünmesinde davranış farkı | İki işlev aynı başlangıç durumundan (yazmaçlar + tembel bellek) N girdi vektörüyle yorumlanır; dönüş değeri, yazılan bellek kümesi ve çağrı izi (hedef + argümanlar) karşılaştırılır | Derleyiciden bağımsız; bir vektörde fark = somut karşı örnek (ret sağlam) | "Fark görülmedi" ispat değildir; dış çağrı ve bellek modeli hükmü etkiler; döngü / adım sınırı; öykünücü sadakati | evet (özgün program + nesne dosyası; başsız betik) | TAHMİN işlev başına 0,1–2 sn (N = 64) | B3 (`öykünme`) |
| **K3** | Simgesel eşdeğerlik (SMT) | İki işlevin P-code'u bit vektörü formülüne çevrilir; çıktıların her girdide eşit olduğu çözücüye sorulur (`z3` 4.16.0 makinede kurulu) | İspat verir; yanlış kabul yalnız çeviri hatasından | Yalnız döngüsüz ve küçük işlevler (döngüde sınırlı açma = ispat değil); çağrılar yorumlanmamış işlev; bellek kuramı pahalı | evet (P-code) | TAHMİN küçük işlevde < 1 sn, zaman aşımı 10 sn | B3 (`smt`) |
| **K4** | BSim benzerliği | Ghidra'nın işlev öznitelik vektörleri | Hazır (`karadul/ghidra/bsim.py`) | **Denetleyici olarak önerilmiyor:** KİMLİK ölçümünde derleyici değişince en iyi aday kesinliği 0,610 [0,580–0,639] (tmux), 0,634 (htop); eşiği yükseltmek düzeltmedi (≥ 0,7: 0,610; = 1,0: 0,561); `-O0` ↔ `-O2` 0,592 (`kimlik/BULGULAR.md` §0 madde 5, §2.3, §3.8). Benzerlik "aynı işlev mi" sorusunu bile eşiğin altında cevaplıyor; "aynı davranış mı" sorusunu hiç cevaplamaz (tek sabiti değişmiş işlev benzer kalır) | evet | — | hiçbiri; yalnız **ön süzgeç** (çok düşük benzerlik = erken ret, zaman kazancı) |
| **K5** | CFG eşbiçimliliği + komut kümesi | `karadul/pipeline/steps/cfg_iso_match.py` (`attributed_cfg`) | Hazır | Aynı ölçümde derleyiciler ve derleyici sürümleri arasında 0 eşleşme; aynı derleyicide `-O3` ↔ `-O2` 1 216 / 2 ama kapsam %26,5 (`kimlik/BULGULAR.md` §3.8). Sabitleri ve işleçleri görmez: sınır koşulu değişmiş işlevi kabul eder | hayır (döküm var: `static/ghidra_cfg.json`) | — | hiçbiri; ön süzgeç |
| **K6** | Kendi derlediğimiz iki ikilinin karşılaştırması | Kaynağı elde olan geliştirme ikililerinde (A-23) doğru kaynaktan derleme ↔ yeniden kurulan koddan derleme | Etiketli zemin verir: K1–K3'ün hata oranları burada ölçülür (3.4) | Ürün yolu değil, ölçüm yolu | K2 / K3 için evet | — | ölçüm düzeni |

**Önerilen bileşim:** B4 ve B3 için sırayla K1 → K3 → K2; K4 / K5 yalnız erken ret süzgeci. Her karşılaştırıcının üç cevabı vardır: `geçti`, `geçmedi` (K2'de karşı örnek vektörüyle), `hükümsüz` (adım sınırı, desteklenmeyen komut, çözülemeyen simge, çözücü zaman aşımı). `hükümsüz` hiçbir zaman `geçti` sayılmaz.

**K2'nin modeli (tasarım; GK-E ayrıntılandırır):**

- Özgün program Ghidra'da açıktır. Yeniden derlenen işlevin baytları öykünücünün bellek durumunda boş bir adrese yazılır; yeniden yerleştirmeleri özgün adreslere çözülür (`DAT_<adres>` ve `FUN_<adres>` adları adresi zaten taşır; adlandırılmış simgeler ad haritasından adrese döner). Böylece iki koşuda da işlevin dışındaki her şey **aynı özgün bellek görüntüsüdür**; fark yalnız sınanan işlevden gelebilir.
- Çağrılar yürütülmez: her çağrı noktasında hedef ve argüman yazmaçları ize yazılır, dönüş değeri (tohum, çağrı sırası, hedef)'ten türetilen sözde rastgele sayıdır; iki tarafta aynı sırada aynı değer. Yani denetlenen şey "çağrılanların davranışı aynıyken bu işlev aynı mı"dır (işlev içi eşdeğerlik).
- Okunan ama ilklenmemiş bellek (yığın üstü, işaretçi argümanların gösterdiği bölgeler) adresten türetilen sözde rastgele içerikle tembel doldurulur; iki tarafta aynıdır. İşaretçi argümanlar ayrı sahte bölgelere bakar.
- Karşılaştırılan gözlenebilirler: dönüş yazmaçları, giriş yığın işaretçisinin üstüne ve yığın dışına yapılan yazmalar, çağrı izi. Yığın çerçevesinin içi karşılaştırılmaz (derleyiciye göre değişir).
- Girdi vektörleri: sınır değerleri (0, 1, −1, en büyük / en küçük, işlevdeki sabitler ve ±1 komşuları) + tohumlu rastgele; N ve tohum ön kayıtta yazılır.
- Sistem çağrısı / kesme komutu, dolaylı dallanmanın bilinmeyen hedefe gitmesi, adım sınırı → `hükümsüz`.
- Bilinen güçlükler (GK-E'nin ilk kalemleri; hiçbiri ölçülmedi): (1) yeniden derlenen birimin dizgi ve sabit havuzu başka adrestedir → işaretçi değerleri doğrudan karşılaştırılamaz; sabit veriye bakan işaretçiler gösterdikleri içerikle kanonikleştirilir; (2) yapı döndürme ve kayan nokta / vektör yazmaçları gözlenebilir kümesine girer; (3) dönmeyen çağrılar (`abort`, `exit` türü) izde son olaydır; (4) yığın koruması ve dal koruması komutları (Debian arm64 ikililerinde işlev girişinde `paciasp` görüldü) derleyici bayrağına bağlıdır, gözlenebilir değildir; (5) dolaylı çağrının hedefi izde değer olarak karşılaştırılır; (6) özgün işlevin başka bir işlevin ortasına atlaması (kuyruk birleştirme) → `hükümsüz`.

**"Çalıştırma yasağı" ve öykünme (karar maddesi K-2, §9):** P-code öykünmesinde hedefin hiçbir komutu işlemcide koşmaz; komutlar JVM içinde yorumlanır, bellek bir kopyadır, dış çağrı ve sistem çağrısı yürütülmez. Önerim: bu, "hedef ikili çalıştırılmaz" kuralının kapsamı dışında sayılsın, şu koşullarla yazılı olarak: (1) yalnız yorumlama (yerel koda çeviri, hata ayıklayıcı, süreç başlatma yok); (2) tek işlev, yalıtılmış; (3) dış çağrı ve sistem çağrısı hiçbir zaman yürütülmez; (4) adım, bellek ve süre bütçesi; (5) durağan sınama: denetleyici kodunda süreç başlatan tek çağrı derleyici ve Ghidra'dır. Karar Berke'nindir; kabul edilmezse B3 yalnız K1 + K3 ile verilir (kapsam ölçülmedi; daha dar olacağı kesin).

### 3.4 Yanlış kabul / yanlış ret nasıl ölçülür

Denetleyici, çıktıya bağlanmadan önce kendisi ölçülür. Zemin: kaynağı elde olan ve bizim derlediğimiz ikililer (A-23; `~/karadul_olcum/kimlik_v1/`: tree, libzstd, sqlite3, redis; çıktılar çalıştırılmaz).

| Küme | Nasıl kurulur | Gerçek etiket | Ne ölçer |
|---|---|---|---|
| **P (pozitif)** | Aynı kaynak işlevinin iki ayrı derlemesi: (a) aynı derleyici, farklı düzey; (b) farklı derleyici (GCC ↔ clang; Mach-O'da ikisi de var); (c) aynı derleyici ve bayrak (denetim: K1 burada %100 vermelidir) | eşdeğer (derleyicinin doğruluğu varsayılır) | yanlış ret, karşılaştırıcı × derleme uzaklığı başına |
| **N1 (bozulmuş)** | Kaynak işlevine tek mutasyon (karşılaştırma işleci, sabit ±1, sınır, argüman sırası, işaret / genişlik, bir atamanın silinmesi, dal koşulunun değillenmesi) + derleme | eşdeğer değil; **üst sınır:** eşdeğer mutantlar ayıklanamaz, yalnız nesne kodu bozulmamış hâliyle bayt eşit olan mutantlar atılır | yanlış kabulün üst sınırı |
| **N2 (yabancı)** | Aynı imza biçimine sahip başka bir işlevle eşleştirme; özgün komut dizileri aynı olan çiftler dışlanır (§1.5 karşı denetimi) | eşdeğer değil | kolay yanlış kabul (ayrı satır; N1 ile havuzlanmaz) |
| **A (gerçek aday)** | Aynı ikililerin Karadul çıktısındaki işlevler, B1'e getirilebilenler | bilinmiyor | hüküm dağılımı ve `hükümsüz` payı (hata oranı değil) |

- Sayım A-14 düzeniyle: örnek düzeyi ve tekil kaynak işlevi düzeyi; en az 3 bağımsız program; Wilson aralığı. Kümeler tohumla seçilir, tohum ön kayıtta.
- Geliştirme / sınama ayrımı: mutasyon işleçleri ve K2'nin gözlenebilir tanımı iki programda (tree, libzstd) geliştirilir, dondurulur (dondurma commit'i yazılır), sonra kalan programlarda (sqlite3, redis) bir kez ölçülür. Kilitli setler açılmaz.
- "Yeni yanlış"ın bu hattaki tanımı (§6): denetleyiciden `geçti` alıp gerçekte eşdeğer olmayan işlev. Ölçümde N1 ∪ N2 üstünde sayılır; üründe sayılamaz (gerçek bilinmez), bu yüzden eşik ölçüm kümesinden gelir.

### 3.5 Eşik (A-13 / A-14 düzeni)

- A-13'ün sayısı (0,909 = L / (L + 1), L = 10; `karadul/core/naming_labels.py` `AD_ESIGI`, `MALIYET_ORANI_L`) **ad** için verilmiş bir hükümdür: yanlış ad, eksik adın 10 katı kötü. "Eşdeğer" etiketi için maliyet oranı ayrı bir karardır (K-3, §9). Önerim: bir kanıt türü `geçti` etiketi yazabilsin ancak ve ancak (i) N1 üstünde yanlış kabul oranının Wilson **üst** sınırı ≤ 0,01, (ii) en az 3 bağımsız programda ölçülmüş, (iii) P üstünde yanlış reddi raporlanmış (eşik yok; yalnız kapsam kaybıdır). Gerekçe: "eşdeğer" etiketi analistin o işlevi bir daha okumayacağı anlamına gelir; yanlış ad okuyanı yanıltır, yanlış "eşdeğer" ise okutmaz.
- Karar gelene kadar asgari sınır A-13'ün kendisidir: kabul edilenlerin kesinliğinin Wilson alt sınırı ≥ `AD_ESIGI`. Yeni sabit tanımlanırsa tek yerde (`karadul/core/naming_labels.py`'nin yanında, GK-I) tanımlanır ve içe aktarılır; hiçbir pakette sayı yazılmaz.
- Eşiği sağlamayan kanıt türü etiket yazmaz; hükmü **kanıt satırı** olur (A-14'teki "bayrak arkasında kalır ya da kanıt satırı yazar" kuralının aynısı).
- `bayt_eş` için eşik gerekmez (yanlış kabul yapım gereği yok); yine de N1 üstünde 0 verdiği ölçülür (uygulama hatasına karşı).

### 3.6 Model dolgusunun denetimi

Denetleyici, parçanın kimden geldiğine bakmaz: motorun çıkardığı gövde de modelin onardığı gövde de aynı kapıdan geçer. Modelin önerebileceği parça türleri ve her birinin kapısı:

| Parça | Kapı (hepsi makinenin cevabı) |
|---|---|
| Ad (işlev, değişken, alan) | Ad davranışı değiştirmez: yeniden derlenen birimin nesne kodu ad değişmeden önceki nesne koduyla **bayt eşit** olmalı (simge tablosu dışında). Adın doğruluğu bu hattın konusu değildir; `model önerisi` etiketiyle kalır (ad kapıları: `karadul/lm/guard.py` `check_proposal`) |
| Tip / bildirim | Birim B1'e çıkmalı ve B2'nin imza tutarlılığı bozulmamalı; işlev daha önce B3'teyse B3'te kalmalı (aynı karşılaştırıcı yeniden koşar) |
| Gövde onarımı (derlenmeyen işlevi derlenir yapmak) | B1 + B3. B3 alamayan onarım çıktıya **girmez**; "derleniyor ama doğrulanmadı" diye de girmez. Kanıt satırı olur |
| Eksik işlev gövdesi (decompile edilememiş) | B1 + B3 (özgün baytlar var olduğu sürece denetlenebilir) |
| Yorum / açıklama | Kod değildir; var olan özet bekçisi (`check_summary`) |

Bu tablo hüküm 2'nin ("denetimden geçmeyen öneri çıktıya girmez") mekanik karşılığıdır.

## 4. Belirlenimci katman

Hüküm 3: motor LLM'siz kalır, tek başına koşar ve tek başına ölçülür. Bu katmanın her adımı ya ikiliden okunan bir olguya ya da derleyicinin cevabına dayanır; hiçbir adım "derlensin diye" bilgi uydurmaz. Sıra, §1'de ölçülen hata paylarının sırasıdır.

| Adım | Kapattığı boşluk (§2 sınıfı) | Üstüne kurulduğu var olan kod | Paket |
|---|---|---|---|
| **D1** Tip başlığının derlenir üretilmesi | `types.h`'nin kendi hataları: Ghidra temel tip adları, enum sabit çakışması ve geçersiz adlar, üye bildirimleri, sistem tipleri, SDK çakışması | `c_project_builder.py` `_build_types_h`, `GHIDRA_TYPEDEF_LINES`; `c_type_recoverer.py` `CTypeRecoverer`; çıktıya kopyalayan `output_formatter.py` (`_copy_project_tree`; `_build_types_h` çağrısı) | GK-B |
| **D2** Bildirim üretimi (birim önsözü) | Eksik işlev bildirimi, eksik veri simgesi bildirimi | `c_project_builder.py` `definition_signatures`, `_build_subsystem_header` (P18: bildirim tanımdan kopyalanıyor), `_load_thunk_addresses`; `static/ghidra_functions.json` | GK-C |
| **D3** Ghidra artıklarının çevrilmesi | P-code işleç çağrıları (`CONCATxy`, `SUBxy`, `ZEXT`, `SEXT`, `CARRY`, `SBORROW` …): anlamı tanımlı, başlık olarak yazılabilir. Sahte değişkenler (`in_`, `unaff_`, `extraout_`), kurtarılamayan atlama tablosu, etiket adları: **anlamı eksik**; bildirimle derlenir kılınabilir ama eşdeğerliği yalnız B3 söyler | `c_flow_simplifier.py` (var olan akış sadeleştirme); `karadul/lm/tools/read.py` `ghidra_warnings` (Ghidra uyarı satırlarını zaten sayıyor) | GK-G |
| **D4** Tip birleştirme | Aynı simgenin birimler arasında farklı tiple görünmesi; çağıran ↔ tanım imza farkı; yapı alanı çakışmaları | `pipeline/steps/struct_recovery.py`, `type_recovery_consumer.py`, `reconstruction/type_inferrer.py`, `computation/struct_recovery/solver.py` (kısıt çözücüyle yapı yerleşimi) | GK-H (ölçer), sonra GK-G / ayrı kalem (onarır) |
| **D5** Bağlama denetimi | Çift tanım, çözülmeyen simge, içe aktarım tablosuyla mutabakat | `_load_thunk_addresses` (içe aktarım taslakları `src/import_thunks/`'ta ayrı; P18 kalem 4) | GK-H |
| **D6** Derleyici profili | Özgün derleyici / bayrak tahmini (K1 kapsamı için) | Üründe genel bir derleyici tespiti **yok** (bakıldı: yalnız `analyzers/delphi_binary.py` ve `reconstruction/reference_populator.py`'de dar kullanımlar). İkilinin kendisi de söylemiyor (bu turda bakıldı, durağan okuma): S8'in 7 Debian ikilisinin hiçbirinde `.comment` bölümü ya da derleyici dizgisi yok; mac/tmux'ta derleme sürümü yük komutu yalnız platformu, SDK'yı ve bağlayıcıyı veriyor, derleyici dizgisi yok. Yani profil bu ikililerde yalnız ölçümle bulunabilir. İlk sürüm: sabit profil kümesi (§3.2); geçen profilin sayımı ikili başına tek profile yakınsıyorsa sonraki işlevlerde o profil önce denenir (ölçülen sıklıkla, uydurma etiketle değil) | GK-D |
| **D7** Dil çalışma zamanı bildirimleri | ObjC ileti gönderimi, Go / Swift çalışma zamanı çağrıları, C++ adlarının C'de yazılamaması | Üst veri okuyucuları (`karadul/analyzers/ustveri/`; main'de), `analyzers/cpp_rtti.py`, ayıklayıcılar | GK-L |
| **D8** Veri bölümlerinin taşınması | Geri kurulan kod özgün verisine (`.data`, `.rodata`, sabit dizgiler, işlev işaretçisi tabloları) muhtaçtır; bugün çıktı yalnız kod içerir, veri simgeleri bildirimsiz adreslerdir | Baytlar ikilide; veri içindeki işaretçilerin (yeniden yerleştirme) simgeye çevrilmesi gerekir. Üründe karşılığı **yok** (bakıldı: `c_project_builder.py` yalnız kod birimi yazar) | GK-H (ölçer: kaç veri simgesi bölüme düşüyor), sonra ayrı kalem |

İlkeler:

1. **Bildirim bir iddiadır.** Üretilen her bildirimin kaynağı kayda geçer (tanımdan kopya / Ghidra imzası / üst veri / bilinmiyor → yer tutucu). Kaynağı "bilinmiyor" olan bildirimle derlenen birim B1'i "yapay bildirimle" etiketiyle alır.
2. **Motor kendi çıktısını da denetler.** B3 yalnız model dolgusu için değil, Ghidra'nın gövdesi için de koşar: decompiler hataları (yanlış tip genişliği, kaybolan yan etki) "derleniyor" görünür ama B3'te düşer. Bu, bugün hiç ölçülmeyen bir sayıdır: "Ghidra + Karadul gövdelerinin yüzde kaçı özgün işlevle eşdeğer" (ölçülmedi; GK-E'den sonra).
3. **Ad hattına dokunulmaz.** Belirlenimci katman adları değiştirmez; S8 ad haritası her pakette bayt eşit kalır (kabul ölçütü).
4. **Çıktı iki biçimde kalır:** okunan çıktı (bugünkü `out/src`; ÇA ile yeniden düzenlenecek) ve derleme birimi (önsöz + gövde). İkincisi birincisinden belirlenimci türetilir; analistin okuduğu dosyaya derleme iskelesi gömülmez (K-8 ile birlikte GK-M'de kesinleşir).

## 5. KaradulLM katmanı

Bu tur model koşturmadı. Aşağıdaki sayılardan yalnız "ölçüldü" denenler ölçümdür (kaynak: `2026-11-11_karadullm/zemin/zemin_olcumu.md`); kalanı tasarımdır.

### 5.1 Modelin görevi

Model, belirlenimci katmandan **sonra** kalan boşluklarda öneri yazar. §2'nin sınıflamasına göre:

| Görev | Girdi durumu | Modelden istenen | Kapı (§3.6) |
|---|---|---|---|
| `onar_derleme` | İşlev B0'da ya da B1'de değil; belirlenimci katman hatayı kapatamadı | Aynı işlevin derlenen C'si (yalnız gövde + yerel bildirimler) | B1 + B3 |
| `onar_esdegerlik` | İşlev B1'de ama B3'te `geçmedi` (karşı örnek var) | Karşı örneği gideren gövde | B3 |
| `tip_oner` | Tipi bilinmeyen veri simgesi / `undefinedN` parametre | Tip bildirimi | B1 korunur + (varsa) B3 korunur |
| `adlandir` | Adsız işlev / değişken (var olan görev) | Ad | Nesne kodu bayt eşit kalır; ad `model önerisi` |
| `acikla` | Var olan görev (özet) | Metin | Kod değil; özet bekçisi |

Modelden **istenmeyen:** yeni işlev uydurmak (ikilide adresi olmayan kod), önişlemci yönergesi, derleme bayrağı, "eşdeğer" hükmü (hükmü yalnız denetleyici verir).

### 5.2 Girdi bağlamı

Var olan araçlar yeter; yeni okuma aracı gerekmez: `get_decompiled` (işlev metni), `get_function_facts` (boyut, parametre sayısı, çağrı düzeni), `get_xrefs` / `get_call_graph` (çağıranlar, çağrılanlar), `get_types` (kurtarılan tipler), `get_evidence` ve `get_name_provenance` (kanıt satırları, ad kökeni), `search_code`. Eklenen tek girdi türü denetleyicinin çıktısıdır: derleyici hata iletileri (ilk k tanesi; dosya yolu arındırılmış) ve B3'ün `geçmedi` hükmünde **tek** karşı örnek (girdi yazmaçları + beklenen ↔ gözlenen). Girdi vektör kümesi ve tohumu modele gösterilmez (§9.2 risk 3).

Bağlam bütçesi var olan tasarımın sınırıdır (16K yerel bağlam; `2026-11-18_karadullm_v2/TASARIM.md` §3.7): işlev metni + önsözün yalnız o işlevin kullandığı satırları + hata iletileri. Bağlama sığmayan işlev (TAHMİN: birkaç yüz satırın üstü; ölçülmedi) model görevine alınmaz, "bağlama sığmadı" diye sayılır.

### 5.3 Döngü

```
aday (motor ya da önceki deneme)
  → derle (B1)  ── hata → iletiler modele → yeni aday        (en çok D deneme)
  → denetle (B3) ── geçmedi → tek karşı örnek modele → yeni aday
                 ── hükümsüz → dur; kanıt satırı
                 ── geçti → kabul vektör kümesiyle yeniden denetle → geçti ise çıktıya (etiketli)
```

- Deneme sınırı D ve işlev başına süre bütçesi ön kayıtta yazılır (öneri: D = 3; süre bütçesi ölçümden sonra). Sınır dolunca son aday çıktıya **girmez**; en iyi derleyici / denetleyici cevabıyla kanıt satırı olur.
- Kabul için ikinci, modele hiç gösterilmemiş vektör kümesi kullanılır.
- Döngüyü ajan değil denetleyici sürücüsü yürütür (belirlenimci program); model yalnız metin üretir. Derleme ve Ghidra çağrısı modelin araç kaydında yoktur.
- Sıra: işlevler çağrı grafında yapraklardan köke (var olan `karadul/lm/order.py` katman sıralayıcısı); bir işlevin önerisi kabul edilirse çağıranların önsözü yenilenir.

### 5.4 Yerel model, bellek, süre

| Ölçü | Değer | Durum |
|---|---|---|
| Eldeki model | Qwen3.8-27B Q4_K_M (LM Studio dizininde; `llama-server` ile) | ölçüldü: K-1 … K-5 kapıları geçti |
| Bellek tepesi | 17,63 GiB (sınır 20) | ölçüldü (zemin ölçümünün bellek denemeleri); 16K bağlamın tepesi **ölçülmedi** (v2 tasarımı §12) |
| Hız | önek 106,8 jeton / sn, üretim 10,1 jeton / sn | ölçüldü, **yük altında** (boş makine hızı ölçülmedi) |
| Bu modelin C gövdesi onarma başarısı | — | **ölçülmedi** (model ad önerme ve özet için seçildi; `2026-10-19_g6_pilot/model_secimi.md`) |
| İşlev başına süre | TAHMİN 1–4 dk (100–300 satırlık gövde ≈ 1 500–4 000 üretim jetonu ÷ 10 jeton / sn, × ≤ 3 deneme; derleme ve denetim hariç) | TAHMİN |
| Büyük ikili | 13 159 işlevin tamamı için model görevi gerçekçi değil: TAHMİN 200–900 saat. Model katmanı **seçilen kümede** koşar (analistin istediği işlevler / B1'e en yakın işlevler; ÖL-10'un seçim kuralıyla aynı mantık) | TAHMİN |
| Donanım | Ayarlar tek işlemciye göre yazılmaz (A-9): model boyutu çalışma anında ölçülen boş bellekten seçilir (`karadul/lm/memory_guard.py` var); bellek yetmezse model katmanı "atlandı: bellek" der | tasarım |

### 5.5 Etiket ve köken kaydı şeması

İşlev başına bir kayıt; çıktıda `geri_kurma.json` (GK-I). Alan adları öneridir; şemayı GK-I dondurur.

```json
{
  "adres": "00104080",
  "birim": "src/…/FUN_00104080.c",
  "basamak": "B3",
  "kanit": {"tur": "oykunme", "vektor": 64, "tohum_ozeti": "sha256:…",
            "profil": "clang-O2", "yanlis_kabul_ust_siniri": "‹GK-E ölçümü›",
            "olcum_kunyesi": "‹ön kayıt commit'i›"},
  "govde_kaynagi": "motor | model_onerisi",
  "bildirimler": {"tanimdan": 4, "ghidra_imzasi": 2, "ust_veri": 0, "yapay": 0},
  "model": null,
  "denemeler": [],
  "kanit_satirlari": []
}
```

- `govde_kaynagi = model_onerisi` ise `model` alanı dolar: model dosyasının sha256'sı, istem sürümü, deneme sayısı, her denemenin derleyici / denetleyici cevabı (var olan koşu künyesi alanları: v2 tasarımı §8.3).
- `basamak` yalnız denetleyicinin verdiği en yüksek basamaktır; `kanit.tur` ∈ {`bayt_es`, `komut_es`, `smt`, `oykunme`, `yok`}. `yapay` bildirim sayısı > 0 ise B1 "yapay bildirimle" diye gösterilir.
- Reddedilen öneriler `kanit_satirlari`'na düşer (ne önerildi, hangi kapıda kaldı); çıktı koduna girmez.
- Gösterimde (rapor, arayüz, MCP) "kurtarıldı" sözcüğü yoktur; sütunlar: derlenir (B1), bağlanır (B2), denetlendi (B3: kanıt türü), bayt eşit (B4), gövde kaynağı. Veri yoksa "ölçülmedi" (sahte veri yasağı; v2 tasarımı §4.7'deki mekanik sınamanın aynısı bu sütunlara uygulanır).

### 5.6 Analistin onayı ve bekçi

- **A-33 K-6 ile ilişki:** orada hüküm "KaradulLM decompile'ı kendisi başlatmaz, öneri açar; onay analistte". Aynı çizgi: model derleme ya da denetim **başlatmaz**; onarım görevini analist (ya da analistin açtığı toplu görev) başlatır. Kabul yolu K-8'de: denetimden geçen öneri ayrı katmana etiketiyle yazılır; motorun gövdesinin yerine geçmesi analistin onayıyladır (var olan kabul yolu: `karadul/core/overrides.py`).
- **Bekçi (`karadul/lm/guard.py`):** bugün ad önerisi (`check_proposal`), özet (`check_summary`) ve genel cevap (`check_answer`) kurallarını taşıyor; düşmanca metin taraması (`hostile_texts`, `injection_hits`) ikilideki dizgilerden gelen yönlendirmeyi yakalıyor. Gövde önerisi için eklenecek kurallar (GK-J; yeni işlev `check_patch` önerisi — bugün **yok**): (1) metinde önişlemci yönergesi, satır içi derleme (`asm`), derleyici özniteliğiyle bölüm / takma ad tanımı → ret; (2) önsözde olmayan dış simgeye başvuru → ret (model yeni bağımlılık uyduramaz); (3) işlev adı ve imzası hedefle aynı değilse → ret; (4) gövde, kanıt zarflarındaki düşmanca metni yorum ya da dizgi olarak taşıyorsa → işaret; (5) boyut sınırı. Bekçi **ön** kapıdır: geçmek çıktıya girmek değildir; çıktıya giriş yalnız §3.6 tablosuyla olur.
- **Sahte veri bekçisi:** model çıktısı hiçbir sayaçta "motorun kurtardığı" sütununa yazılamaz; `geri_kurma.json` doğrulayıcısı `govde_kaynagi = model_onerisi` olan kaydın `model` alanı boşsa ya da `kanit.tur = yok` iken `basamak ≥ B3` ise dosyayı reddeder (GK-I testi + mutant).

## 6. Ölçüm düzeni ve ön kayıt

### 6.1 Setler (hepsi var olan setler; yeni set açılmaz, kilitli setlere dokunulmaz)

| Rol | Set | Bu hatta kullanımı |
|---|---|---|
| **Denetleyici geliştirme** | Kaynağı elde olan, bizim derlediğimiz ikililer (A-23; `~/karadul_olcum/kimlik_v1/`): tree, libzstd | K1–K3'ün tanımı, mutasyon işleçleri, K2'nin gözlenebilirleri burada geliştirilir |
| **Denetleyici sınama** | Aynı kökün kalanı: sqlite3, redis (`deps/lua` dışarıda; A-23) | Dondurmadan sonra bir kez; yanlış kabul / ret oranları buradan |
| **Ürün geliştirme (B0–B2)** | S8'in 8 ikilisi (taban `ANA/s8_taban_534e252b`) + geliştirme setinin 119 ikilisi (yeniden oynatmayla) | Belirlenimci katmanın her paketi; "geriye gitme yok": geçen birim kümesi tabanın üst kümesi |
| **Hedef (gerçek uygulama; A-17, A-27)** | Keşif: terminal-notifier, docker-cli, Ollama dilimi | Raporların **ilk satırı** buradan (ORTAK_D1 §1); dil başına oranlar |
| **Kör sınama** | docker-compose, iTerm2, llama-server | Kural / uyarlayıcı dondurulduktan sonra bir kez (ORTAK_D1 §3) |
| **Kilitli** | Doğrulama seti, test seti, ÖK-V'nin kör tarafı | **Açılmaz.** Bu hattın hiçbir paketi okumaz |

Kaynağı elde olan dört programın bu hattın etiketli zemini olması bir sınır getirir: hepsi C. C++ / Go / Swift / ObjC'de denetleyicinin hata oranı için etiketli zemin bugün yok; kurulması GK-L'nin kalemidir (Go derleyicisi izni A-23'te verilmiş; indirme o paket sıraya girince).

### 6.2 Raporun biçimi

Her ölçüm aynı tabloyu verir; satır = çıktı (ikili), sütunlar:

| işlev (toplam / decompile edilen) | B0 | B1 (yapay bildirimsiz / yapay bildirimle) | B2 | B3 `bayt_eş` | B3 `komut_eş` | B3 `smt` | B3 `öykünme` | `geçmedi` | `hükümsüz` | — motor tek başına — | + KaradulLM (ayrı sütun grubu) |

- Oranlar işlev sayısıyla ve kod baytı ağırlığıyla, ikisi de.
- **Motor ve model ayrı sütunlarda** (hüküm 3): model katmanının katkısı = modelsiz koşuda B3'te olmayıp modelli koşuda B3'e giren işlevler; toplam sütunu yazılırsa yanında ayrışımı durur. Hiçbir başlıkta ikisi toplanıp "kurtarılan" denmez.
- Her B3 sayısının yanında kanıt türünün ölçülmüş yanlış kabul üst sınırı ve ölçüm künyesi.
- Payda açık yazılır: decompile edilmeyen (tembel kip), taslak (thunk), "bağlama sığmadı", `hükümsüz`.

### 6.3 "Yeni yanlış"ın bu hattaki tanımı

- **Yanlış kabul:** denetleyiciden `geçti` alan ama gerçekte eşdeğer olmayan işlev. Yalnız etiketli zeminde (§3.4 N1, N2) sayılabilir; üründe gerçek bilinmez.
- **Yeni yanlış (paket düzeyi):** bir paket main'e girmeden önce, sınama kümesinde, o paketin eklediği kanıt türü ya da onarımın kabul ettirdiği eşdeğer-olmayan çift sayısı. Beklenti her pakette ön kayıtla yazılır; `bayt_eş`, `komut_eş`, `smt` için **0**, `öykünme` için eşik (K-3).
- **Geriye gitme:** daha önce B*k*'de olan bir işlevin, paket sonrası daha düşük basamakta olması. S8 ve 119'da 0 beklenir; istisna yalnız "yapay bildirimle B1" → "B1 değil" (yapay bildirimi kaldıran dürüstlük onarımı), sayılır ve ayrı yazılır.
- **Model için ek sayaç:** kabul edilen model önerilerinin, kaynağı elde olan ikilide, doğru kaynağın derlemesiyle bağımsız karşılaştırmada (geniş vektör kümesi / K3) düşen payı.

### 6.4 Ön kayıt düzeni

ORTAK_D0 / D1'deki düzen aynen: ön kayıt ölçümden önce ayrı commit; tutmayan beklenti silinmez, eşik sonradan değişmez; tohumlar, vektör sayısı, profil kümesi, clang sürümü ön kayıtta yazılır. Paket başına ön kayıt çekirdekleri §8.1–8.4'te.

**GK-K (modelli ölçüm) ön kayıt taslağı — kesinleşmedi; GK-J bitince ana oturum yazar:**

- Nüfus: denetleyici sınama programlarında (sqlite3, redis) motorun B1'e getiremediği ya da B3'te `geçmedi` aldığı işlevlerden tohumlu örneklem (boyut bütçeye göre; TAHMİN 100–200 işlev ≈ 3–13 saat model zamanı).
- Kollar: (0) motor tek başına; (1) + KaradulLM `onar_derleme`; (2) + `onar_esdegerlik`.
- Ölçüler: kol başına B1 ve B3'e giren işlev; deneme sayısı dağılımı; süre, üretim jetonu, bellek tepesi; kabul edilen önerilerde bağımsız karşılaştırmada düşen pay.
- Hipotezler (sayıları yazan doldurur): H1 kol 1'de B1'e giren pay ≥ ‹eşik›; H2 kabul edilen önerilerde bağımsız karşılaştırmada düşen pay ≤ K-3 eşiği; H3 bekçi kurallarını atlayan öneri 0.
- Model koşusu paket ajanlarına yasak; ana oturum koşar (v2 tasarımı §8.3). Künye: Karadul commit'i, model sha256, `llama-server` sha256, istem sürümü, bağlam.

## 7. Önceki çalışmalarla ilişki

Bu bölüm yenilik iddiası taşımaz; yalnız konumlandırır. Kaynak: depodaki literatür notları (aşağıda dosya adlarıyla). Ağa çıkılmadı; notlarda olmayan her şey **"ana oturum kaynak taraması yapacak"** diye işaretlidir.

| Akraba | Depodaki not ne diyor | Bu hatla ilişkisi |
|---|---|---|
| **Yeniden çalıştırılabilirlik ölçütlü decompile modelleri** | LLM4Decompile (Tan vd., EMNLP 2024): 1,3B–33B açık modeller; HumanEval ve ExeBench'te "yeniden çalıştırılabilirlik oranı" ölçütü; Ghidra çıktısını iyileştiren sürüm (`2026-10-15_makale/tersine_derleme_sinirlari.md` §4.6). Model seçimi notunda: "derleme kodunu ya da Ghidra sözde kodunu derlenebilir C'ye çeviriyor"; yalnız Linux x86-64; fonksiyon adı önermiyor (`2026-10-19_g6_pilot/model_secimi.md` K14) | En yakın akraba: ölçüt aynı aileden (derlenir + davranış). Fark iki yerde: (a) onların ölçütü derlenen kodu **çalıştırıp** sınamayla karşılaştırır; burada hedef çalıştırılmaz, denetim çalıştırmadan yapılır; (b) orada model çeviriyi yapar, burada model yalnız boşluk doldurur ve her dolgu denetleyiciden geçer. Bu modellerin arm64 / Mach-O'da ve gerçek uygulama ölçeğinde davranışı notlarda yok → kaynak taraması |
| **Sinirsel ad / tip kurtarma** | DIRE, DIRTY: görülen ↔ görülmeyen kodda ad isabeti %85,5 → %35,3 ve %87,1 → %36,9; SymGen (NDSS 2025) x86-64 F1 0,351–0,397; REFORGE (2026): 7 LLM'de ortalama token F1 0,18–0,29, medyan 0; ReSym (CCS 2024): LLM + Prolog tabanlı tutarlılık denetimi (`tersine_derleme_sinirlari.md` §4.6–4.7; `2026-10-15_makale/veri_setleri.md`) | Ad hattının akrabaları; bu hat adın doğruluğunu ölçmez (A-41: "kendi isimlendirmeleri ile yazsa bile"). ReSym'in "model önerir, simgesel denetim eler" kalıbı hüküm 2 ile aynı ailedendir; orada denetlenen tip tutarlılığı, burada davranış eşdeğerliği |
| **Decompiler doğruluğunu sınayan çalışmalar** | Not: "1 423 hata tetikleyen girdi", "Ghidra'nın fonksiyon, değişken ve tip çıkarımının DWARF'a karşı ölçümü" (`tersine_derleme_sinirlari.md` §4.5, §4.7; künyeler o belgenin kaynakçasında) | §4 ilke 2'nin dayanağı: decompiler çıktısı "derleniyor" olsa da yanlış olabilir; bu yüzden motorun kendi gövdesi de B3'ten geçer |
| **Kuramsal sınır** | Çok-bire eşleme, kararsızlık sonuçları, derleyici aşaması başına kayıp (`tersine_derleme_sinirlari.md` §2–§3) | §9.1'in dayanağı: hedef "özgün kaynak" olamaz; "aynı davranışı veren derlenebilir kaynak" olabilir |
| **Eşleşen yeniden derleme toplulukları** (oyun ve gömülü yazılımda, işlev işlev bayt eşit yeniden yazım) | **Depoda not yok** | B4 ve K1 (`bayt_eş`), o toplulukların ölçütünün aynısıdır; orada işi insan yapar ve özgün derleyici bilinir. Araçları, ölçütleri, derleyici tespiti yolları → **ana oturum kaynak taraması yapacak** |
| **Yeniden derlenebilir decompile / ikili kaldırma (binary lifting) araçları, çeviri doğrulama (translation validation), ikili eşdeğerlik denetimi** | **Depoda not yok** (RetDec yalnız özellik envanterinde anılıyor: `docs/FEATURE_ADOPTION_PLAN.md`) | K2 / K3'ün doğrudan akrabaları. Hangi çalışmaların P-code / IR düzeyinde işlev eşdeğerliğini hangi kapsamla gösterdiği → **ana oturum kaynak taraması yapacak** (GK-E'den önce; yöntemi baştan yazmamak için) |
| **LLM'li decompile onarımında derleyici geri bildirimi döngüsü** | **Depoda not yok** | §5.3'ün döngüsü bu ailedendir → **ana oturum kaynak taraması yapacak** |
| **Kendi ölçümlerimiz** | KİMLİK: derleyiciler arası BSim 0,610, CFG 0 eşleşme, çapalı yayılım 0,990 (`kimlik/BULGULAR.md`) | §3.3'te K4 / K5'in neden denetleyici olmadığının ölçülmüş gerekçesi |

Yaratıcılık protokolünün (CLAUDE.md §29) dört kuralı için tek satır: (1) denetlenebilir soru — evet, hattın tamamı makine cevabına indirgenmiş (B0–B4); (2) uzlaşıyı kırma — bu turda tek ajan çalıştı, karşı görüş alınmadı: K2'nin kör noktaları için Onuncu Adam turu GK-E'den **önce** önerilir; (3) tek hatta kalma — §8 çok dalgalı tek hat; (4) insan uzman — yok (A-1); eşik kararları (K-2, K-3) Berke'de.

## 8. Uygulama planı

### 8.0 Paketler, sıra, zincirler

14 alt paket. "Kim" sütunu A-40 düzeniyle: planı ve ölçümü belli yazma işi Opus, ağır mühendislik Mythos. "Bugün" = önkoşulu olmayan, 2026-11-24'te gönderilebilir.

| Paket | Tema | Kim | Ghidra | Model | Derleyici | Önkoşul | Bugün |
|---|---|---|---|---|---|---|---|
| **GK-A** | Ölçüm aracı, taban ve "geriye gitme yok" kapısı | Opus | hayır | hayır | clang | — | evet |
| **GK-B** | `types.h` onarımı (başlık kaynaklı hatalar) | Opus | hayır (yeniden oynatma) | hayır | clang (yalnız ölçüm) | — (dosya zinciri: ÇA paketleriyle sıralı) | evet |
| **GK-C** | Birim önsözü: bildirim üretimi (yeni modül, bağlamasız) | Opus | hayır (yeniden oynatma) | hayır | clang (yalnız ölçüm) | — | evet |
| **GK-D** | Etiketli çift kümesi + K1 (`bayt_eş`, `komut_eş`) | Mythos | hayır | hayır | clang, GCC 16 (Mach-O) | — (A-23 kaynakları yerinde) | evet |
| **GK-E** | K2: P-code öykünme karşılaştırıcısı | Mythos | evet (kuyruk) | hayır | clang | GK-D (çift kümesi), karar K-2 | hayır |
| **GK-F** | K3: SMT eşdeğerliği (küçük, döngüsüz işlev) | Mythos | evet (P-code) | hayır | clang | GK-E'nin nesne → P-code köprüsü | hayır |
| **GK-G** | Ghidra artıklarının çevrilmesi (p-code işleçleri, sahte değişkenler, etiketler) | Opus | hayır | hayır | clang (ölçüm) | GK-B, GK-C | hayır |
| **GK-H** | B2: yeniden yerleştirilebilir bağlama ve simge mutabakatı | Opus | hayır | hayır | clang, `/usr/bin/ld`, `/usr/bin/nm` | GK-B, GK-C | hayır |
| **GK-I** | Etiket / köken şeması, `geri_kurma.json`, rapor sütunları | Opus | hayır | hayır | — | GK-A (alan adları), karar K-3 | hayır |
| **GK-J** | KaradulLM `onar` görevi (döngü, bağlam, bekçi kuralları; sahte arka uçla sınanır) | Mythos | hayır | hayır (pakette model koşmaz) | clang | GK-C, GK-D ya da GK-E (en az bir B3 kanıtı), GK-I; `karadul/lm` zinciri | hayır |
| **GK-K** | Modelli ölçüm (ön kayıtlı; ana oturum koşar) | ana oturum | evet | **evet** (yerel) | clang | GK-J, makine boş | hayır |
| **GK-L** | Dil uyarlamaları: C++ / ObjC / Go / Swift (çalışma zamanı bildirimleri, çağrı düzeni uyarlayıcısı) + hedef setinde kapsam | Mythos | evet | hayır | clang | GK-E, üst veri okuyucuları (main'de) | hayır |
| **GK-M** | Boru hattına bağlama: `geri_kurma` adımı (bayrak arkasında, öntanım kapalı), CLI, arayüz ve MCP görünümü | Opus | hayır | hayır | clang (çalışma anında, isteğe bağlı) | GK-B, GK-C, GK-G, GK-H, GK-I; karar K-5 | hayır |
| **GK-N** | Kapanış ölçümü: hedef seti + 119 + S8, ön kayıtlı son sayılar; README amaç cümlesi | ana oturum + Opus | evet | isteğe bağlı sütun | clang | hepsi | hayır |

**Zincirler (aynı dosya; sıralı gider):**

1. `karadul/reconstruction/c_project_builder.py`: GK-B → ÇA paketleri (A-39; sırayı ana oturum belirler, ikisi aynı anda gitmez) → GK-G'nin bağlaması → GK-M. GK-B yalnız `GHIDRA_TYPEDEF_LINES`, `_build_types_h` ve üç derleme dosyası üreticisine dokunur; ÇA yerleşim ve adlandırma işlevlerine. İşlev kümeleri ayrık ama dosya aynı: CLAUDE.md §2 kuralı gereği **sıralı**.
2. `karadul/reconstruction/c_type_recoverer.py`: GK-B (enum sabit adları, `types.h` metni) — bugün başka paketin listesinde değil (HZ7a `c_namer.py` ve `api_param_db.py`'de; `gonderim/HZ7a.md`).
3. `karadul/lm/**`: P22'nin kalanları → GK-J. GK-J yeni dosyada (`karadul/lm/onar.py`) yaşar; `agent.py`, `protocol.py`, `guard.py`'ye dokunuşu yama ya da zincir sırasıyla.
4. Ghidra köprüsü: GK-E ve GK-F `karadul/ghidra/headless.py`'ye **dokunmaz** (ÖL-3 / HZ-4a zinciri orada); ayrı, tek amaçlı başsız betik yazar (`karadul/ghidra/scripts/` altında yeni dosya) ve kuyruğa ad / kimlik koşusu gibi girer (A-31).
5. `karadul/config.py`: kimse yazmaz (A-19, A-34). Bayrak alanları (GK-M) yama olarak bırakılır.

**Serbest (yalnız yeni dosya):** GK-A, GK-C, GK-D, GK-H, GK-I.

**Önkoşul olarak bağlanan var olan paketler (hüküm 7):**

| Var olan iş | Bu hatla ilişkisi |
|---|---|
| P18 (alt sistem başlıkları; main'de) | Başlıklar tanımla tutarlı hâle geldi (36 078 çelişkili bildirim → 0) ama `.c` dosyaları onları **içermiyor** (§1.4): GK-C bu boşluğu kapatır. P18'in "kalan"ı (`analysis/xref_index.md`, `subsystem_map.md` eski adlar) bu hattı etkilemez |
| Tip kurtarma (`c_type_recoverer.py`, `struct_recovery`, `type_recovery_consumer`) | `types.h`'nin içeriğini üretir; bugün derlenmiyor (§1.2, §1.4). GK-B onarır; tip **doğruluğu** B3'le dolaylı denetlenir (yanlış alan genişliği davranışı değiştirir) |
| ÇA (çıktı ağacı, A-39) | Adres ↔ dosya dizini GK'nin birim bulma yoludur: GK paketleri dosya yoluna değil adrese bağlanır (`// Address:` satırı bugün; ÇA'nın dizini gelince o). ÇA dosya adlarını değiştirince GK-A tabanı adres anahtarlı olduğu için bozulmaz |
| ÖL-10 (tembel derinlik) | Decompile edilmemiş işlevin adayı yoktur: B düzeyleri "decompile edilmedi" paydasını ayrı gösterir (`static/tembel_durum.json` sayacı; `olcek/OL10_TASARIM.md` §4) |
| P22 (KaradulLM altyapısı) | Olay akışı, kipler, oturum, araç kaydı v2 ağaçta (`karadul/lm/events.py`, `modes.py`, `session.py`, `tools/read_more.py`); arayüz ve ölçüm paketlerinin durumu bu turda denetlenmedi. GK-J bunların üstüne kurulur |
| P24 (MCP) | GK-M'in MCP görünümü P24'ün sunucusuna bir araç ekler (`geri_kurma_durumu`: salt okur); P24'ten önce yazılmaz |
| HZ hattı | Derleme ve denetim süresi HZ ölçümlerine yeni satır olarak girer; gündüz süre ölçümü yapılmaz (ORTAK_D1 §2) |

### 8.1 GK-A — ölçüm aracı, taban, kapı (Opus; bugün)

- **Amaç:** `scripts/arge/gerikurma/derlenebilirlik.py`'yi kalıcı ölçüm aracına çevirmek ve §1'in sayılarını taban olarak kilitlemek.
- **Kalemler:** (1) aracı `scripts/measurement/gk_derlenebilirlik.py`'ye taşı (arge betiği durur; yeni araç onu içe aktarmaz, kopyalar ve sınar); (2) hedef seçimi: çıktının `report.json`'ındaki biçim / mimariden derleyici üçlüsü (`--target`) ve `-ffreestanding`; iki kip yan yana raporlanır (ana makine üçlüsü = bugünkü ölçüm; hedef üçlüsü); (3) nesne kipi (`-c`, çıktı koşu kökünde; B1'in tam tanımı); (4) adres anahtarlı kayıt: her birim `// Address:` satırıyla anahtarlanır, dosya yolu ikincil; (5) işlev sınırı sezgiseli `definition_signatures` (`c_project_builder.py`) sayımıyla karşılaştırılır, fark raporlanır; (6) taban dosyası `ozet/gk_taban.json` (9 çıktı) + karşılaştırma kipi: "geçen birim kümesi tabanın üst kümesi mi"; (7) testler (yapay C dosyaları: her hata sınıfına bir örnek) + mutasyon tanımı.
- **Dosyalar:** yeni `scripts/measurement/gk_derlenebilirlik.py`, `tests/test_gk_derlenebilirlik.py`, `scripts/measurement/mutation_specs_gk_a.json`, `docs/arge/2026-11-19_mythos/gerikurma/GK-A.md`, `GK-A_on_kayit.md`.
- **Ön kayıt (ölçümden önce commit):** H1: yeni araç ana makine üçlüsünde §1.2 ve §1.3 tablolarının dosya ve hata sayılarını **birebir** yeniden üretir (9 / 9 çıktı; aynı clang sürümü). H2: hedef üçlüsünde ELF çıktılarında `+sdk_cakismasi` sınıfı 0'a iner. H3: işlev sayısı farkı (sezgisel ↔ `definition_signatures`) her çıktıda ≤ %2. H4: mutant ≥ 6, hepsi ölür.
- **Kabul:** H1–H4; tam takım yeşil; araç hiçbir girdi köküne yazmaz (sınama: girdi kökü salt okunur bağlanmış geçici kopyada koşu).

### 8.2 GK-B — `types.h` onarımı (Opus; bugün; `c_project_builder.py` zincirinin başı)

- **Amaç:** §1.2'nin bulgusu: her çıktıda bütün hataların büyük çoğunluğu ve her dosyanın ilk hatası `types.h`'den geliyor; başlık derlenmediği için hiçbir dosya derlenmiyor.
- **Kalemler (hepsi §1.2'de ölçülmüş sınıflar):** (1) Ghidra'nın temel tip adları (`byte`, `word`, `dword`, `qword`, `uint`, `ulong`, `ushort`, `longlong`, …) `GHIDRA_TYPEDEF_LINES`'a; (2) enum sabit adları: geçersiz tanımlayıcı (eksi işaretli değerden üretilen ad) ve enum'lar arası çakışan sabit adı (`c_type_recoverer.py`'de `VAL_<değer>` üretimi) → sabit adı enum adıyla öneklenir, geçersiz karakter çevrilir; (3) yapı üyesi bildirimlerindeki ayrıştırma hataları — bakıldı, iki üretici kusuru: Ghidra'nın tip kategorisi yolu üye tipinde kalıyor (`/‹kategori›/‹tip› alan;`) ve Ghidra'nın typedef gösterimi üye tipi diye yazılıyor (`typedef ‹A› ‹B› alan;`); ikisi de tipin çözülmüş adıyla yazılır, yinelenen üye adları ayrıca sayılır; (4) hedef platformun kendi sistem tipleri (`__off_t` ailesi): Ghidra'nın tip dökümünde (`static/ghidra_types.json`) tanımı varsa oradan, yoksa "tanımsız tip" olarak **yorumla** yazılır, uydurulmaz; (5) ana makine SDK'sıyla çakışan adlar (`sdk_cakismasi` sınıfı): `types.h` barındırılan başlıkları çekmeyecek biçimde kurulur ve projenin derleme dosyaları (`_build_makefile`, `_build_cmake`, `_build_compile_commands`) hedef üçlüsünü ve `-ffreestanding`'i yazar; (6) derleme dosyalarındaki `-w` bayrağına bu pakette dokunulmaz (karar K-6); ölçülen: bu clang sürümünde `-w` hataya yükseltilmiş uyarıları susturmuyor (§1.1); (7) testler: üretilen `types.h`'nin `clang -fsyntax-only`'den geçtiği, clang yoksa atlanan sınama + mutasyon.
- **Dosyalar:** `karadul/reconstruction/c_project_builder.py` (yalnız `GHIDRA_TYPEDEF_LINES`, `_build_types_h`, üç derleme dosyası üreticisi), `karadul/reconstruction/c_type_recoverer.py` (yalnız enum sabit adı ve `types.h` metnini üreten işlevler), yeni `tests/test_gk_b_types_h.py`, `scripts/measurement/mutation_specs_gk_b.json`, `gerikurma/GK-B.md`, `GK-B_on_kayit.md`. **Dokunma:** yerleşim ve dosya adlandırma işlevleri (ÇA), `output_formatter.py` (PUV6b).
- **Ölçüm yolu:** Ghidra'sız yeniden oynatma (P18'in yöntemi: `CProjectBuilder` çalışma alanının `reconstructed/annotated/` girdisiyle yeniden koşar; P18'de `out/src` ile bayt bayt aynı çıktı verdiği gösterildi).
- **Ön kayıt:** H1: 9 / 9 çıktıda başlık kaynaklı hata 0 (bugün: §1.2 tablosunun "başlıkta" sütunu). H2: ürün kipinde K ile geçen dosya sayısı her çıktıda ≥ bugünkü önsöz kipindeki sayı (§1.3 tablosu); tutmayan çıktı nedenleriyle yazılır, eşik değişmez. H3: `.c` dosyalarının gövdesi ve ad haritası değişmez (S8 8 / 8 bayt eşit; fark yalnız `include/types.h` ve derleme dosyalarında). H4: 119 ikilinin yeniden oynatmasında `types.h` tek başına `clang -fsyntax-only`'den 119 / 119 geçer.
- **Kabul:** H1, H3, H4 tutar; H2'nin sonucu yazılır; tam takım yeşil; mutant ≥ 6.

### 8.3 GK-C — birim önsözü: bildirim üretimi (Opus; bugün; yalnız yeni dosya)

- **Amaç:** §1.3'te başlık devre dışıyken kalan hataların en büyük sınıfı eksik bildirim (çağrılan işlev, veri simgesi). `.c` dosyaları yalnız `types.h`'yi içeriyor; P18'in düzelttiği alt sistem başlıkları hiçbir dosyaya girmiyor.
- **Kalemler:** (1) envanter: her eksik bildirim ailesi için bildirimin kaynağı var mı — program işlevleri: `definition_signatures`; içe aktarımlar ve taslaklar: `static/ghidra_functions.json` (`return_type`, `parameters`, `is_thunk`); veri simgeleri (`DAT_`, `PTR_`, dizgi simgeleri): adres + tip dökümü **yok** (bu turda bakıldı: debian/htop ve mac/tmux çalışma alanlarının beş statik dökümünde — işlevler, xref, tipler, dizgiler, simgeler — `DAT_` adı 0 kez geçiyor; `symbols.json` yalnız dinamik simgeleri, yani içe aktarılan veriyi veriyor) → adlı içe aktarılan veri `symbols.json`'dan, iç veri kalem 4'ten; (2) saf işlev: (birimler, statik dökümler) → birim başına önsöz metni; yalnız o birimin kullandığı adlar (kullanım kümesi derleyicinin "undeclared" iletilerinden değil, metnin belirteç taramasından çıkar); (3) çelişki kuralı: aynı ad için iki farklı imza kaynağı varsa bildirim yazılmaz, sayılır (P18'in kuralı); (4) veri simgesinin tipi bilinmiyorsa `extern undefined1 AD[];` (adres alma ve dizinleme derlenir; değer olarak kullanım derlenmez ve "tipi bilinmeyen veri" sınıfında sayılır) — veri simgelerinin adres + tip dökümü ÖL-3 zincirine kalem olarak **önerilir** (ana oturum karar verir), bu pakette `headless.py`'ye dokunulmaz; (5) ölçüm: GK-A aracıyla, üretilen önsöz `-include` ile verilerek (ürün çıktısı değişmeden); (6) testler + mutasyon.
- **Dosyalar:** yeni `karadul/reconstruction/gerikurma/__init__.py`, `karadul/reconstruction/gerikurma/bildirim.py`, `tests/test_gk_c_bildirim.py`, `scripts/arge/gerikurma/onsoz_olc.py`, `scripts/measurement/mutation_specs_gk_c.json`, `gerikurma/GK-C.md`, `GK-C_on_kayit.md`.
- **Ön kayıt:** H1: önsöz kipi + üretilen bildirimlerle `eksik_bildirim_islev` sınıfının hata sayısı her çıktıda §1.3'teki değerin ≤ %10'una iner. H2: K ile geçen dosya oranı her çıktıda §1.3'teki G oranına ulaşır ya da geçer (G = örtük bildirim hataları sayılmadığında geçenler; bildirim gelince bu dosyaların geçmesi beklenir). H3: üretilen bildirimlerden doğan **yeni** hata (`tip_celiskisi_bildirim`) sayılır; payı raporlanır (eşik yok: bu sayı tip kurtarmanın imza hatasını ölçer). H4: önsöz belirlenimci (iki koşu bayt eşit).
- **Kabul:** H1, H4 tutar; H2, H3 yazılır; ürün davranışı değişmez (bağlama GK-M'de).

### 8.4 Sonraki paketlerin kabul ölçütleri (kısa)

| Paket | Kabul ölçütü ve ön kayıt çekirdeği |
|---|---|
| **GK-D** | Çift kümesi dondurulur (sha256 dökümü; ≥ 3 program; P ≥ 300 çift, N1 ≥ 1 000 mutant, tohum yazılı). P(c) (aynı derleyici, aynı bayrak) üstünde `bayt_eş` %100; N1 ∪ N2 üstünde `bayt_eş` ve `komut_eş` kabulü **0**; P(a), P(b) üstünde yanlış ret oranı raporlanır (eşik yok). Hiçbir derleme çıktısı çalıştırılmaz. Dosyalar: yeni `karadul/reconstruction/gerikurma/karsilastir_komut.py`, `scripts/arge/gerikurma/{cift_kumesi,mutasyon_c,k1_olc}.py`, testler |
| **GK-E** | Geliştirme programlarında (tree, libzstd) gözlenebilir tanımı ve girdi üreteci dondurulur; sınama programlarında (sqlite3, redis) bir kez: N1 üstünde yanlış kabul Wilson üst sınırı ≤ eşik (K-3) ise `öykünme` kanıtı etiket yazar, değilse kanıt satırı. `hükümsüz` payı ve nedenleri raporlanır. Durağan sınama: betikte sistem çağrısı yürüten yol yok |
| **GK-F** | Yalnız döngüsüz, ≤ ön kayıtlı P-code işlem sayılı işlevler; N1 üstünde kabul 0 (ispat iddiası); P üstünde kapsam raporlanır; çözücü zaman aşımı `hükümsüz` |
| **GK-G** | Önsöz kipi + GK-C + işleç başlığıyla `ghidra_pcode_isleci` sınıfı 0; sahte değişken sınıfları (`in_`, `unaff_`, `extraout_`) **bildirimle susturulmaz** — derlenir kılınan her işlev "B1: yapay bildirimle" etiketini taşır ve B3'e gitmeden "kurtarıldı" sayılmaz |
| **GK-H** | S8 çıktılarında `ld -r`: çift tanım sayısı, çözülmeyen simge kümesinin içe aktarım tablosuyla farkı; B2 tuttu / tutmadı program başına |
| **GK-I** | Şema (§5.5) + doğrulayıcı; rapor sütunları yalnız gerçek sayılardan dolar, veri yoksa "ölçülmedi" (sahte veri yasağı sınaması: şemada varsayılan sayı yok) |
| **GK-J** | Sahte arka uçla: (a) denetimden geçmeyen öneri çıktıya giremez (mutant: kapıyı atlayan yol → test ölür); (b) deneme sınırı ve süre bütçesi aşılmaz; (c) modelin metninde önişlemci yönergesi → ret; (d) her öneri köken kaydı üretir |
| **GK-K** | §6.4'teki ön kayıt taslağı (ana oturum kesinleştirir) |
| **GK-L** | Dil başına B0–B3 oranı hedef setinde; uyarlayıcı kapsamı (kaç işlevin çağrı düzeni C'ye çevrilebildi) sayıyla |
| **GK-M** | Bayrak kapalıyken S8 çıktısı bayt eşit; bayrak açıkken `geri_kurma.json` üretilir, süre ayrı satır; clang yoksa adım "atlandı: derleyici yok" der (uydurma sonuç yok) |
| **GK-N** | Ön kayıtlı son tablo: çıktı × basamak × (motor tek başına / + KaradulLM) |

### 8.5 Süre (TAHMİN; ölçüm değil)

Dayanak: iki uygulama oturumunda ölçülen hız yaklaşık 2,8 paket / saat (4–5 ajanla; `2026-11-23_dalga1/DURUM.md` "Oturum kapanışı"). GK paketlerinin altısı (D, E, F, J, L, N) o ortalamadan ağır.

- GK-A, B, C, D birlikte: TAHMİN 1 oturum (3–5 saat).
- GK-E, F, G, H, I: TAHMİN 2–3 oturum; GK-E Ghidra kuyruğuna bağlı.
- GK-J, K, L, M, N: TAHMİN 3–5 oturum + 1–2 gece (modelli ölçüm ve hedef seti).
- Toplam: TAHMİN 6–9 oturum (25–40 oturum saati) + 1–2 gece. Var olan plana (kalan yaklaşık 81 paket, 40–55 oturum saati) **eklenir**; en çok oynatacak belirsizlik K2'nin `hükümsüz` payıdır (ölçülmedi).

## 9. Riskler, dürüst sınırlar, karar listesi

### 9.1 Ulaşılamayan (bilgi ikilide yok ya da bugünkü yolla geri gelmez)

| Ne | Neden | Sonucu |
|---|---|---|
| Özgün adlar, yorumlar, makrolar, dosya ve dizin düzeni (üst verisi olmayan C / C++) | Derleme siler (`2026-10-15_makale/tersine_derleme_sinirlari.md` §3) | Geri kurulan kod **başka adlarla** yazılır; A-41 bunu açıkça kabul ediyor. Ad doğruluğu bu hattın ölçüsü değildir |
| Özgün kaynak **metni** | Çok-bire eşleme: aynı makine kodunu veren sonsuz kaynak var | Hedef "özgün kaynak" değil "aynı davranışı veren derlenebilir kaynak"tır. Belgelerde "eski hâline döndü" yerine "yeniden derlenebilir ve denetlenmiş eşdeğer" yazılmalı |
| Bayt eşit yeniden derleme (genel durumda) | Özgün derleyici, sürüm, bayraklar, bağlama sırası bilinmiyor; LTO ve profil yönlendirmeli derleme yeniden üretilemez | B4 hedef değil, tuttuğu yerde bedava kanıt |
| Satır içine alınmış işlevlerin sınırları | Derleyici gömmüş; ikilide ayrı işlev yok (KİMLİK'te yanlışların ana sınıfı: `kimlik/BULGULAR.md` §0 madde 3) | Geri kurulan işlev kümesi ikilinin işlev kümesidir, kaynağınki değil |
| Kullanılmayan (bağlayıcının attığı) kod, koşullu derlemenin öbür dalları | İkilide yok | Kapsam "ikilide olan kod"dur |
| Program düzeyinde davranış eşdeğerliğinin **ispatı** | Kararsız (genel durumda); hedef çalıştırılmadığı için uçtan uca sınama da yok | En güçlü cümle: "işlevlerin şu kadarı işlev içi eşdeğerlik denetiminden geçti" |
| Go / Swift'te aynı dilde kaynak | Dil yapıları (goroutine, arayüz, genel tip örneklemesi, ARC) çalışma zamanı çağrılarına indirgenmiş; C sözdizimi çıktısı dilin çağrı düzenini ifade etmez | §2.3: bu dillerde hedef "C olarak derlenen + uyarlayıcıyla denetlenen" koddur; aynı dilde geri kurma bu planda yok (K-7) |
| C++ istisna yolları | Ghidra'nın C çıktısı açma tablolarını göstermez | B3 yalnız istisnasız yollar için söylenebilir; etiket bunu yazar |

### 9.2 En büyük üç risk

1. **B3'ün kapsamı küçük çıkabilir.** K1 derleyici tutmayınca tutmaz; K3 yalnız küçük işlevlerde; K2'nin `hükümsüz` payı ve ölçülecek yanlış kabulü bilinmiyor. KİMLİK ölçümü yapısal benzerliğin derleyiciler arasında çöktüğünü gösterdi (BSim 0,61; CFG 0 eşleşme) — K2 de beklentiyi karşılamazsa hattın söyleyebildiği "derleniyor ama eşdeğerliği gösterilemedi" olur. İlk işaret §1.5'te: komut eşitliği mac/tmux'ta derlenebilen işlevlerin %59,5'inde, Debian'ın 7 ikilisinde %25,3'ünde (9 komut ve üstünde 0 / 274). Erken ölçüm: GK-D (Ghidra'sız, bugün) ve GK-E'nin ilk 100 çifti; ikisi de üründen önce.
2. **B1'e giden yol "derlenir kılmak için uydurma"ya kayabilir.** Eksik bildirimi `int f()` ile, sahte değişkeni boş yerel değişkenle doldurmak derleme sayısını yükseltir ama kodu yanlış yapar. Bugünkü G sütunu (§1) tam olarak bu sahte iyileşmenin büyüklüğünü gösteriyor. Koruma: B1 tek başına hiçbir yerde "kurtarıldı" diye raporlanmaz; yapay bildirimle derlenen birim etiketlidir (GK-G); model dolgusu B3 almadan çıktıya girmez (§3.6).
3. **Modelin onardığı gövde denetleyicinin kör noktasına oturabilir.** Model, K2'nin girdi vektörlerinde aynı davranan ama genelde farklı kod yazabilir (özellikle vektörleri görürse). Koruma: model girdi vektörlerini ve tohumu görmez; kabul için kullanılan vektör kümesi onarım döngüsündekinden ayrıdır (döngüde geri bildirim yalnız derleyici hatası ve "geçmedi" + tek karşı örnek); yanlış kabul, model önerileri üstünde ayrıca ölçülür (GK-K: kaynağı elde olan ikilide modelin geçen önerileri doğru kaynağın derlemesiyle K3 / geniş vektörle yeniden sınanır).

Ek riskler: çıkış süresi (13 159 işlev × 5 profil × K2; ölçülmedi); ana makine ↔ hedef platform farkı (ELF çıktısı Mac'te derleniyor: §1'de `sdk_cakismasi` sınıfı olarak ölçüldü; hedef üçlüsüyle giderilir, GK-A H2); yerel modelin bellek tavanı (ölçülen tepe 17,63 GiB; aynı anda Ghidra + derleyici koşarsa bütçe: ölçülmedi).

### 9.3 Karar listesi (Berke / ana oturum)

| No | Karar | Önerim |
|---|---|---|
| **K-1** | Basamak tanımları (B0–B4, §3.1) ve program düzeyinde tek "eşdeğer" hükmü verilmemesi | Kabul. Raporlar basamak başına oran verir |
| **K-2** | P-code öykünmesi "hedef ikili çalıştırılmaz" kuralına girer mi? | **Girmez**, §3.3'teki beş koşulla ve yazılı olarak. Kabul edilmezse B3 yalnız K1 + K3 ile (dar kapsam) |
| **K-3** | "Eşdeğer" etiketinin eşiği: A-13'ün sayısı mı (kesinlik alt sınırı ≥ 0,909), ayrı ve daha sıkı bir sayı mı | Ayrı sabit: yanlış kabulün Wilson üst sınırı ≤ 0,01, ≥ 3 program; karar gelene kadar A-13 asgari sınır |
| **K-4** | Derleyici profili kümesi (kaç bayrak / derleyici denenecek) ve ELF için GCC çapraz derleyicisi kurulsun mu (paket kurma izni gerekir) | Önce yalnız clang 5 profil; GCC çapraz derleyicisi GK-D'nin ölçümünden sonra, K1 kapsamı ELF'te düşük çıkarsa Berke'ye sorulur |
| **K-5** | Ürün çalışma anında derleyici çağırsın mı (`geri_kurma` adımı clang ister) | Evet, isteğe bağlı adım olarak, öntanım kapalı; clang yoksa "atlandı: derleyici yok". Paketlemede (Y8) Xcode komut satırı araçları **bağımlılık olarak yazılır**, gömülmez |
| **K-6** | Projenin kendi derleme dosyalarındaki `-w` ve hedef üçlüsü | `-w` kalır (okuyanı uyarı selinden korur) ama README'deki derleme iddiası ölçülen B1 oranıyla değişir; hedef üçlüsü ve `-ffreestanding` yazılır |
| **K-7** | Go / Swift / ObjC / C++'ta "eski hâline dönmek" = C olarak derlenen ve denetlenen kod; aynı dilde kaynak bu planda yok | Kabul; ObjC'de `.m` çıktısı (C gövdeli) ayrı ve sonraki bir karar |
| **K-8** | KaradulLM'in gövde önerisi çıktıya nasıl girer: denetimden geçince kendiliğinden mi, analistin onayıyla mı (A-33 K-6 ile ilişki) | Denetimden geçen öneri **ayrı katmana** kendiliğinden yazılır (`model önerisi` + kanıt türü etiketiyle; motorun çıktısının üstüne yazılmaz); motor çıktısının yerine geçmesi analistin onayıyla. Model kendi başına decompile ya da derleme başlatmaz |
| **K-9** | İlk üç paket (GK-A, GK-B, GK-C) ve GK-D bugün gönderilsin mi; `c_project_builder.py` zincirinde GK-B ↔ ÇA sırası | Evet; GK-B önce (küçük ve ölçümü hazır), ÇA paketleri arkasından |
| **K-10** | README'deki amaç cümlesi (aşağıda 9.4) ne zaman girer | GK-B + GK-C main'e girip §1 tablosu yenilenince; o güne kadar README değişmez |
| **K-11** | Model katmanının ölçümünde (GK-K) kullanılacak yerel model: bugünkü Qwen3.8-27B Q4_K_M mi, kod onarımına ayrı bir model mi | Önce eldeki modelle (indirme yok); ayrı model ancak ölçüm yetersiz çıkarsa ve Berke'nin indirme izniyle |

### 9.4 Proje belgelerindeki ana amaç cümlesi (öneri; iddia değil HEDEF)

> **Amaç.** Karadul, derlenmiş bir programdan **yeniden derlenebilen ve özgün programla aynı davranan** kaynak kodu çıkarmayı hedefler. Motor, ikilide bulunan bilgiyi belirlenimci hesapla kurtarır; kalan boşlukları isteğe bağlı yerel model (KaradulLM) önerir; her parça bir denetleyiciden geçer ve hangi denetimden geçtiğini üstünde taşır. Adlar özgün olmayabilir; kod denetlenebilir olmalıdır.
>
> **Bugün neredeyiz (‹tarih›, ‹commit›; ölçüm: `gk_derlenebilirlik`):** çıktıdaki `.c` dosyalarının %‹B1› kadarı tek başına derleniyor; işlevlerin %‹B3› kadarı özgün işlevle eşdeğerlik denetiminden geçti (‹kanıt türü dağılımı›); bayt eşit %‹B4›. Hedef ikili hiçbir aşamada çalıştırılmaz.

Yer tutucular GK-A'nın tabanından dolar. Bugünkü değerlerle (§1) cümle "‹B1› = 0" diye yazılırdı; bu yüzden cümlenin README'ye girişi K-10'a bağlandı. "Kurtarıldı", "geri kazanıldı", "özgün kaynak" sözcükleri kullanılmaz.

## Ek A. Atıf doğrulaması

Bu belgedeki dosya ve işlev atıfları yazıldıktan sonra ağaçta (`58715681`, worktree) mekanik olarak arandı.

| Tür | Sayı | Yöntem | Sonuç |
|---|---|---|---|
| Dosya : işlev / sınıf / sabit atfı | 31 | Her biri için dosyada `def ad`, `class ad` ya da sabit adı satırı arandı (`grep` eşdeğeri; betik oturumun geçici dizininde) | 31 / 31 bulundu |
| Ters tırnaklı yol atfı (belgeden otomatik çıkarıldı) | 93 | Yol, depo kökü ve belge dizinlerine göre arandı | 56 ağaçta var (4'ü yalnız dosya adıyla anılan belge); 37 ağaçta yok |
| Ağaçta olmayan 37 yolun dökümü | — | Elle sınıflandı | 20 planlanan yeni dosya (GK paketleri; "yeni" diye yazılı) · 1 ÖL-10 tasarımının planladığı dosya (`static/tembel_durum.json`) · 8 çalışma alanı / çıktı yolu (depo yolu değil; S8 çalışma alanında var olduğu görüldü) · 8 bu turun koşu kökü yolu (`GK0/…`, `ozet/…`; diskte var) |
| Başka belgelerden alınan sayı / ifade | 29 | Kaynak belgede metin olarak arandı | 29 / 29 bulundu (KARARLAR A-13, A-33; `kimlik/BULGULAR.md` §0, §2.3, §3.8; `zemin_olcumu.md`; `2026-11-23_dalga1/DURUM.md`; P18.md; `tersine_derleme_sinirlari.md` §4.6–4.7; `veri_setleri.md`; `model_secimi.md` K14) |

"Bakıldı, yok" diye yazılan üç olumsuz atıf da arandı: `karadul/lm/guard.py`'de `check_patch` yok (0 eşleşme); üründe genel derleyici tespiti yok (yalnız iki dar işlev bulundu); `c_project_builder.py`'de veri bölümü yazan kod yok (0 eşleşme).

Doğrulanmayan / bakılmayan (belgede de öyle işaretli): P22'nin arayüz ve ölçüm paketlerinin durumu; özgün derleyicilerin kimliği (ikililerde derleyici izi bulunmadı: §4 D6).

## PAKET BİTTİ
