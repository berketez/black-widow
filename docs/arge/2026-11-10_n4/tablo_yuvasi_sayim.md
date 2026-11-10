# N4 §5 A1: veri tablolarındaki fonksiyon yuvaları (GT'siz tavan sayımı)

- **Tarih:** 2026-11-10. **Depo:** `main`, HEAD `fa99144`. Ürün kodu değişmedi; yalnız sayım.
- **Soru:** Ad bekleyen fonksiyonların ne kadarı bir veri tablosundan gösteriliyor? Bunların ne kadarının kaydında ad kanıtı olabilecek bir dizgi var? (`onuncu_adam.md` §0 madde 3, §5 A1.)
- **Dosyalar:** `tablo_yuvasi_sayim.py` (betik), `tablo_yuvasi_sayim.json` (bütün sayılar), `tests/test_n4_tablo_yuvasi_sayim.py` (tanımların testleri).
- **Girdi:** 117 Debian 13 arm64 ELF (`~/karadul_olcum/n1_debian13`) ve 2 Mac Mach-O (`workspaces/olcum_mac/runs/ol7-a-9a36142/{tmux,htop}`). Her ikili için saklı koşunun `raw/<ikili>` kopyası, `static/` Ghidra çıktısı ve `reconstructed/src/naming_map.json` dosyasının yalnız `global` anahtarları okundu.
- **GT'siz:** simge doğrusu, dbgsym, DWARF, `macho_score.json` ve kilitli dizinler açılmadı. Karadul ve Ghidra koşulmadı.
- **Dosyalarda:** fonksiyon adı, dizgi içeriği ve `FUN_` anahtarı yok. Yalnız sayılar, sınıflar, program, ikili ve bölüm adları var.
- **İşaretler:** **[hesap]** dosyadaki sayılardan aritmetik. **[tahmin]** ölçülmemiş bir varsayıma dayanır.

## 0. Kısa sonuç

1. **Çağıransız fonksiyonların çoğu bir veri yuvasından ya da koddan adresi alınarak gösteriliyor; "tablo" tanımına uyanı daha az.**
   - Debian htop'ta çağıransız 186 fonksiyonun %68,3'ü bir veri yuvasında, %30,6'sının adresi yalnız kodda alınıyor; açıklanamayan %1,1.
   - Mac htop'ta aynı paylar %61,6, %25,5 ve %13,0.
   - Tablo kaydından gösterilen pay: Mac htop %10,9, Debian htop %26,8, havuz %8,8.
2. **Üst sınır küçük ve çoğu tmux'ta (708'in 530'u).**
   - Üst sınır: kaydında tanımlayıcı ya da kısa ad biçimli dizgi olan ve bugün ad almayan ad bekleyen fonksiyon. Gevşek okumayla Mac tmux 274 (%10,6), Debian tmux 256 (%13,4), Debian htop 23 (%9,6), redis-tools 120 (%5,7), Mac htop 18 (%3,0), sqlite3 11 (%2,6), openssl 1 (%0,2), coreutils ve zstd 0.
   - Havuz: 708 / 23 963 (%3,0). Birim ortalaması (makro): %4,9.
   - Bunun 233'ü (%32,9) birden çok fonksiyon yuvalı kayıtlardan gelir. Orada dizgi yuvayı değil, kaydı adlandırır. Kaydı tek bir fonksiyonu adlandıranlarla havuz 475 (%2,0), Mac tmux 166 (%6,4), Mac htop 6 (%1,0) **[hesap]**.
   - Bu sayılar erişim tavanıdır. Bir "tablo rolü" kanalının doğruluğu ölçülmedi.
3. **Erişilen fonksiyonlar çoğunlukla N4'ün ulaşamadığı I sınıfında.**
   - I sınıfı: kütüphane çağırmayan, yalnız iç fonksiyon çağıran.
   - Üst sınır içindeki pay: Mac tmux 215/274, Debian tmux 215/256, Mac htop 10/18.
   - Yani bu kaynak, N4'ün K ∪ Y tavanına eklenir; onunla örtüşmez.
4. **A1'in GT'siz öldürme ölçütü (a) harfiyen okunursa bu kaynak Mac htop'ta bırakılır.**
   - Ölçütün eşiği: Mac htop'ta yalnız tablolardan başvurulan pay < %15 ise bırak.
   - Ölçülen: çağıransız ve tablo kaydında 59/597 (%9,9). Tanımı "herhangi bir veri yuvası"na genişletirsek 133/597 (%22,3).
   - Karar Berke'nindir; iki okuma da aşağıda.
5. **Tablo tanımının en büyük zayıflığı adım 8 baytlık "gösterici dizileri".**
   - Elle okunan 30 tablonun 19'u adım 8 baytlıktı. Bunların hepsi tek bir nesnenin ardışık yöntem yuvalarıydı (vtable benzeri). Hiçbiri gerçek bir dizi değildi.
   - Adımı 8 baytı aşan 11 tablonun 2'si yanlış (bir nesnenin içinde düzenli desen).
   - Kayıt dizgisi elle okunan 10 dizgili tablonun hiçbirinde kesin okumada yanlış değildi. Gevşek okumada 1 tabloda yanlış dizgi de girdi.

## 1. Tanımlar (sayımdan önce yazıldı; sonradan eklenenler işaretli)

| Kavram | Tanım |
|---|---|
| Sözcük | Veri bölümünde 8 bayt hizalı sözcük. |
| Veri bölümü | ELF: yazılabilir, yer kaplayan bölümler (`.data.rel.ro`, `.data`; `.got`, `.got.plt` ve `.dynamic` hariç). Mach-O: `__DATA*` ve `__AUTH*` segmentlerindeki bölümler (`__got`, `__la_symbol_ptr` vb. ve zerofill hariç). |
| Başlatma dizisi | `.init_array`, `.fini_array` ve `.preinit_array` ile `__mod_init_func`. Ayrı sayılır, "fonksiyon yuvası" sayımına girmez. |
| Sözcüğün değeri | ELF PIE: `R_AARCH64_RELATIVE` addend'i; `R_AARCH64_ABS64` için simge değeri + addend. Tanımsız simgede STT_FUNC ise içe aktarılan fonksiyon (X), değilse dış veri. Mach-O: chained fixup rebase hedefi (lief ile çözülür ve her biri elle de çözülüp karşılaştırılır) ve bind. Yer değişimi olmayan sözcük ham değeriyle Z (sıfır) ya da V (sayı) olur. |
| **Fonksiyon yuvası** | Değeri bir Ghidra iç fonksiyon girişi (F) ya da içe aktarılan fonksiyon (X) olan sözcük. Ghidra adresi = ELF sanal adresi + (`image_base` − en küçük `PT_LOAD`). Bu kayma, `.text` bloğuyla denetlenir. |
| **Dizgi yuvası** | Değeri salt okunur, yürütülemeyen bir bölümde NUL sonlu, yazdırılabilir UTF-8 bir dizgiyi gösteren sözcük. Bölümler: ELF'te PROGBITS, `.eh_frame*` hariç; Mach-O'da `__TEXT` içinde komut içermeyen bölümler. Dizginin ortasını göstermesi serbesttir. Boş dizgi ayrı türdür (E) ve kanıt sayılmaz. |
| Öbür göstericiler | Metin içinde ama fonksiyon girişi değil (T); başka her yer (D). |
| **Tablo** | Aynı bölümde aynı adımla yinelenen en az 3 kayıt. Her kayıtta aynı ofsette fonksiyon yuvası olur ("sütun koşusu"). |
| Adımın çıkarılması | 1-64 sözcük denenir. Daha küçük bir böleninin koşusunun alt örneği olan koşu atılır; ardışık göstericilerde adım en küçük dönemdir. Aynı adımlı, aynı kayıt sayılı ve başlangıçları < adım uzak koşular tek aday tablodur. Aday sırası: en çok yuvalı önce. Kabul edilen tablonun bütün kayıt bölgesi alınır; sonraki adaylar bu bölgenin dışına kırpılır. |
| Adım belirsizliği | Aynı puanda, farklı adımlı ve bölgeleri kesişen adayların hiçbiri tablo sayılmaz ("adım belirsiz"). |
| Faz (kayıt başlangıcı) | Puan sırası: (1) kayıt başlangıcına düşen çapa sayısı; (2) bütün kayıtlarda aynı kaba sınıfı taşıyan sütun sayısı; (3) daha az kayıt. Çapa: koddan hesaplanan adres (`adrp`+`add`, `adr`) ya da herhangi bir yer değişiminin hedefi. Eşit en iyi fazlar birlikte tutulur ("faz belirsiz"). |
| *Benzerlik süzgeci (sonradan eklendi)* | Ardışık iki kayıtta, en az birinde gösterici olan sütunlar içinde kaba sınıfı aynı olanların payı. Kaba sınıflar: F/X, S/E, D, T; Z ile V tek sınıf. Çiftlerin ortalaması < 0,9 ise aday, eşiğin altındaki çiftlerden bölünür. Ortalama geçse de kenar çifti < 0,5 ise o kenar kaydı atılır. Bu iki kural Debian htop'un ilk dökümünde büyük adımlı sahte tablolar görüldükten sonra eklendi (§7 madde 5). |
| **Kayıt dizgisi** | Fonksiyon yuvasıyla aynı kayıt penceresindeki dizgi yuvası. **Kesin:** bütün eşit fazlarda aynı kayıtta olan dizgiler (kesişim). **Gevşek:** birleşim. |
| Tablo kaydında | Fonksiyon, kabul edilmiş bir tablonun kayıt bölgesindeki bir F yuvasından gösteriliyor. Sütun dışındaki F'ler de buna dahildir. |
| Tablo sınıfı | Adım 8 bayt: "gösterici dizisi". Baytlardan dizi mi, yalnız göstericili yapı (vtable) mı ayırt edilemez. Daha büyük adımda: kayıtta en çok fonksiyon yuvası (1 ya da ≥ 2) × tam dizgi sütunu var mı. |
| Dizgi biçim sınıfı | Öncelik sırasıyla: tanımlayıcı (`[A-Za-z_][A-Za-z0-9_]*`, tam eşleşme); kısa ad (`[A-Za-z0-9_]+([-.][A-Za-z0-9_]+)+`, ≤ 40 karakter, en az bir harf); biçim (`%` içerir); boşluklu metin; öbür. |
| **Üst sınır** | Ad bekleyen; tablo kaydında; kayıt dizgilerinden en az biri tanımlayıcı ya da kısa ad; `naming_map.json` `global` anahtarlarında yok. |
| Nüfus ve çağıran | `on_sayim.py`'deki tanımın aynısı. Thunk ve dış olmayan, adı `FUN_<onaltılık>` olan fonksiyon. Çağıran: çözülmüş iç kenarlar ∪ xrefs `called_by`. K/I/Y sınıfı da `on_sayim.py`'deki gibidir. |
| Kodda adresi alınan | Disassembly'de `adrp`+`add` ya da `adr` ile hesaplanan adres bir fonksiyon girişi. Ayrıca ELF'te bir `.got` girdisinin RELATIVE hedefi. |

## 2. Nüfus denetimi

Betik `on_sayim.py`'yi içe aktarır ve `on_sayim.json`'ın `betik_sha256` değerini dosyayla karşılaştırır. Her birimde ad bekleyen sayısı, çağıransız sayısı ve K/I/Y sayıları `on_sayim.json` ile birebir tutmazsa betik durur. Bu koşuda on birimin hepsi tuttu. Örnekler: Mac tmux 2 587 / 787, Mac htop 597 / 216, Debian htop 239 / 186; havuz 23 963. Ayrıntı her birimin `on_sayim_denetimi` alanında.

## 3. Sonuçlar

Birim: platform/program. Havuz: on birimin toplamı. Oranların makro ortalaması JSON'da `makro_birim_ortalamasi` alanındadır.

### 3.1 Gösterilme (madde 1)

| birim | ad bekleyen | çağıranı yok | ≥ 1 fonksiyon yuvası | tablo kaydında | adım > 8 tablo kaydında | çapalı tablo kaydında | çağıransızların tablo kaydında olanı |
|---|---:|---:|---:|---:|---:|---:|---:|
| mac/htop | 597 | 216 (%36,2) | 148 (%24,8) | 65 (%10,9) | 33 (%5,5) | 26 (%4,4) | 59 (%27,3) |
| mac/tmux | 2 587 | 787 (%30,4) | 464 (%17,9) | 445 (%17,2) | 420 (%16,2) | 415 (%16,0) | 435 (%55,3) |
| debian/htop | 239 | 186 (%77,8) | 128 (%53,6) | 64 (%26,8) | 48 (%20,1) | 40 (%16,7) | 63 (%33,9) |
| debian/tmux | 1 916 | 630 (%32,9) | 383 (%20,0) | 376 (%19,6) | 348 (%18,2) | 342 (%17,8) | 363 (%57,6) |
| debian/sqlite3 | 425 | 227 (%53,4) | 148 (%34,8) | 137 (%32,2) | 14 (%3,3) | 0 (%0,0) | 132 (%58,1) |
| debian/openssl | 588 | 243 (%41,3) | 56 (%9,5) | 56 (%9,5) | 56 (%9,5) | 54 (%9,2) | 55 (%22,6) |
| debian/redis-tools | 2 103 | 937 (%44,6) | 695 (%33,0) | 558 (%26,5) | 281 (%13,4) | 371 (%17,6) | 546 (%58,3) |
| debian/zstd | 1 908 | 692 (%36,3) | 129 (%6,8) | 129 (%6,8) | 0 (%0,0) | 111 (%5,8) | 116 (%16,8) |
| debian/tree | 115 | 51 (%44,3) | 38 (%33,0) | 37 (%32,2) | 5 (%4,3) | 33 (%28,7) | 37 (%72,5) |
| debian/coreutils | 13 485 | 6 853 (%50,8) | 269 (%2,0) | 232 (%1,7) | 0 (%0,0) | 136 (%1,0) | 188 (%2,7) |
| havuz (10 birim) | 23 963 | 10 822 (%45,2) | 2 458 (%10,3) | 2 099 (%8,8) | 1 205 (%5,0) | 1 528 (%6,4) | 1 994 (%18,4) |
| havuz Debian | 20 779 | 9 819 (%47,3) | 1 846 (%8,9) | 1 589 (%7,6) | 752 (%3,6) | 1 087 (%5,2) | 1 500 (%15,3) |
| havuz Mac | 3 184 | 1 003 (%31,5) | 612 (%19,2) | 510 (%16,0) | 453 (%14,2) | 441 (%13,9) | 494 (%49,3) |

- "Çapalı tablo": kayıt başlangıçlarından en az biri çapa olan tablo.
- "Adım > 8": "gösterici dizisi" sınıfı dışındaki tablolar. §6'ya göre adım 8 baytlık "tabloların" elle okunanlarının hepsi vtable benzeri yapı içiydi; kayıt tablosu iddiası için bu sütun kullanılmalı.

### 3.2 Çağıransızlar neyle açıklanıyor?

| birim | çağıranı yok | veri yuvası | yuvasız, kodda adresi alınan | hiçbiri |
|---|---:|---:|---:|---:|
| mac/htop | 216 | 133 (%61,6) | 55 (%25,5) | 28 (%13,0) |
| mac/tmux | 787 | 450 (%57,2) | 201 (%25,5) | 136 (%17,3) |
| debian/htop | 186 | 127 (%68,3) | 57 (%30,6) | 2 (%1,1) |
| debian/tmux | 630 | 369 (%58,6) | 167 (%26,5) | 94 (%14,9) |
| debian/sqlite3 | 227 | 142 (%62,6) | 57 (%25,1) | 28 (%12,3) |
| debian/openssl | 243 | 55 (%22,6) | 175 (%72,0) | 13 (%5,3) |
| debian/redis-tools | 937 | 675 (%72,0) | 241 (%25,7) | 21 (%2,2) |
| debian/zstd | 692 | 116 (%16,8) | 32 (%4,6) | 544 (%78,6) |
| debian/tree | 51 | 37 (%72,5) | 5 (%9,8) | 9 (%17,6) |
| debian/coreutils | 6 853 | 219 (%3,2) | 523 (%7,6) | 6 111 (%89,2) |
| havuz (10 birim) | 10 822 | 2 323 (%21,5) | 1 513 (%14,0) | 6 986 (%64,6) |

- coreutils ve zstd'de çağıransızların çoğu hiçbir yolla açıklanmıyor. Bunlar büyük olasılıkla Ghidra'nın çağrı kenarı kuramadığı ya da ölü koddur **[tahmin]**; bu belge bunu ayırmadı.
- htop türünde tablo dışı veri yuvaları da önemli bir kanal. Debian htop'ta 128 fonksiyon bir yuvada, 64'ü tablo kaydında. Aradaki fark, aynı türden ama bitişik olmayan sınıf nesnelerinin yuvalarıdır (§7 madde 2).

### 3.3 Kayıt dizgisi ve üst sınır (madde 2, 4, 5)

| birim | tablo kaydında | kaydında dizgi (kesin / gevşek) | 1 / 2+ dizgi (kesin) | ad kanıtı sınıfı (kesin / gevşek) | bugün ad alıyor | üst sınır kesin | **üst sınır gevşek** | üst sınır, çapalı tablo (kesin) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| mac/htop | 65 | 26 / 26 (%40,0 / %40,0) | 9 / 17 | 24 / 24 | 11 (%16,9) | 18 (%3,0) | **18 (%3,0)** | 14 (%2,3) |
| mac/tmux | 445 | 406 / 413 (%91,2 / %92,8) | 344 / 62 | 406 / 413 | 148 (%33,3) | 270 (%10,4) | **274 (%10,6)** | 270 (%10,4) |
| debian/htop | 64 | 34 / 34 (%53,1 / %53,1) | 9 / 25 | 32 / 32 | 16 (%25,0) | 23 (%9,6) | **23 (%9,6)** | 19 (%7,9) |
| debian/tmux | 376 | 340 / 340 (%90,4 / %90,4) | 269 / 71 | 340 / 340 | 96 (%25,5) | 256 (%13,4) | **256 (%13,4)** | 256 (%13,4) |
| debian/sqlite3 | 137 | 0 / 14 (%0,0 / %10,2) | 0 / 0 | 0 / 14 | 30 (%21,9) | 0 (%0,0) | **11 (%2,6)** | 0 (%0,0) |
| debian/openssl | 56 | 56 / 56 (%100,0 / %100,0) | 56 / 0 | 56 / 56 | 55 (%98,2) | 1 (%0,2) | **1 (%0,2)** | 0 (%0,0) |
| debian/redis-tools | 558 | 277 / 277 (%49,6 / %49,6) | 230 / 47 | 277 / 277 | 257 (%46,1) | 120 (%5,7) | **120 (%5,7)** | 76 (%3,6) |
| debian/zstd | 129 | 0 / 0 | 0 / 0 | 0 / 0 | 49 (%38,0) | 0 | **0** | 0 |
| debian/tree | 37 | 0 / 5 (%0,0 / %13,5) | 0 / 0 | 0 / 5 | 17 (%45,9) | 0 | **5 (%4,3)** | 0 |
| debian/coreutils | 232 | 0 / 0 | 0 / 0 | 0 / 0 | 7 (%3,0) | 0 | **0** | 0 |
| havuz (10 birim) | 2 099 | 1 139 / 1 165 (%54,3 / %55,5) | 917 / 222 | 1 135 / 1 161 | 686 (%32,7) | 688 (%2,9) | **708 (%3,0)** | 635 (%2,6) |
| havuz Debian | 1 589 | 707 / 726 (%44,5 / %45,7) | 564 / 143 | 705 / 724 | 527 (%33,2) | 400 (%1,9) | **416 (%2,0)** | 351 (%1,7) |
| havuz Mac | 510 | 432 / 439 (%84,7 / %86,1) | 353 / 79 | 430 / 437 | 159 (%31,2) | 288 (%9,0) | **292 (%9,2)** | 284 (%8,9) |

- **Makro (birim ortalaması):** üst sınır gevşek %4,9, kesin %4,2; tablo kaydında %18,3.
- **Bugün ad alıyor:** fonksiyonun `FUN_` adı `naming_map.json` `global` anahtarlarında var. Yeni adın kendisine bakılmadı.
  - openssl'de tablo kanıtlı 56 fonksiyonun 55'i bugün zaten ad alıyor.
  - Havuzda bu pay %32,7.
- **KS-1 çapası:** saklı koşular `fa99144`'ten önceki `a10fde3` ile koşuldu. `reconstructed/kesin_capalar.json` yok; bu örtüşme atlandı.
- **Kesin ile gevşek arasındaki fark yalnız faz belirsiz tablolardan gelir.**
  - sqlite3'te tek dizgili tablonun fazı belirsiz. Kesin okuma 0 verir; gevşek okumada kayıtta doğru ad ile bir sonraki kaydın adı birlikte durur (§6).
- **Kayıtta birden çok fonksiyon yuvası olan kayıtlardan gelen üst sınır** (gevşek; §7 madde 7):
  - Havuz: 233/708 (%32,9). Mac tmux 108/274, Mac htop 12/18, Debian htop 17/23, Debian tmux 20/256, redis-tools 76/120.
  - Bunlar çıkarılınca, kaydı tek bir fonksiyonu adlandıran üst sınır kalır **[hesap]**: havuz 475 (%2,0), Mac tmux 166 (%6,4), Mac htop 6 (%1,0), Debian tmux 236 (%12,3), Debian htop 6 (%2,5), redis-tools 44 (%2,1).

### 3.4 Dizgi biçim sınıfı (gevşek; bir fonksiyon birden çok sınıfta olabilir)

| birim | tanımlayıcı | kısa ad | boşluklu | biçim | öbür |
|---|---:|---:|---:|---:|---:|
| mac/htop | 24 | 0 | 16 | 0 | 0 |
| mac/tmux | 308 | 187 | 62 | 0 | 60 |
| debian/htop | 32 | 0 | 25 | 0 | 2 |
| debian/tmux | 245 | 160 | 70 | 0 | 68 |
| debian/sqlite3 | 14 | 0 | 0 | 0 | 0 |
| debian/openssl | 56 | 2 | 0 | 0 | 2 |
| debian/redis-tools | 219 | 95 | 19 | 0 | 2 |
| havuz (10 birim) | 903 | 444 | 192 | 0 | 134 |

- Biçim dizgisi (`%`) hiçbir tablo kaydında yok.
- tmux'taki kısa adlar komut adlarıdır. Bu tanımın elle okunan örneklerinden gelen bir gözlemdir; içerik dosyaya yazılmadı.

### 3.5 K/I/Y kırılımı (N4 ile örtüşme)

| birim | nüfus K / I / Y | tablo kaydında K / I / Y | üst sınır (gevşek) K / I / Y |
|---|---:|---:|---:|
| mac/htop | 230 / 265 / 102 | 17 / 39 / 9 | 7 / 10 / 1 |
| mac/tmux | 951 / 1 220 / 416 | 105 / 302 / 38 | 27 / 215 / 32 |
| debian/htop | 103 / 107 / 29 | 21 / 39 / 4 | 5 / 16 / 2 |
| debian/tmux | 766 / 850 / 300 | 95 / 260 / 21 | 22 / 215 / 19 |
| debian/sqlite3 | 297 / 30 / 98 | 69 / 2 / 66 | 11 / 0 / 0 |
| debian/redis-tools | 727 / 1 115 / 261 | 192 / 316 / 50 | 18 / 92 / 10 |
| havuz (10 birim) | 12 698 / 7 305 / 3 960 | 829 / 1 070 / 200 | 96 / 548 / 64 |

### 3.6 Yapı (madde 3)

| birim | tablo | çapalı | faz belirsiz | gösterici dizisi (adım 8) | çok fn, dizgisiz | tek fn, dizgili | çok fn, dizgili | tek fn, dizgisiz | kayıt 3 / 4-7 / 8-15 / 16-63 / ≥ 64 | adım belirsiz aday |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---|---:|
| mac/htop | 17 | 4 | 1 | 11 | 1 | 2 | 2 | 1 | 10 / 4 / 3 / 0 / 0 | 0 |
| mac/tmux | 28 | 12 | 8 | 7 | 1 | 6 | 4 | 10 | 13 / 10 / 2 / 1 / 2 | 0 |
| debian/htop | 18 | 5 | 2 | 10 | 2 | 2 | 2 | 2 | 11 / 3 / 4 / 0 / 0 | 0 |
| debian/tmux | 24 | 6 | 5 | 9 | 0 | 3 | 2 | 10 | 12 / 9 / 0 / 0 / 3 | 0 |
| debian/sqlite3 | 15 | 0 | 2 | 13 | 0 | 2 | 0 | 0 | 2 / 6 / 4 / 3 / 0 | 4 |
| debian/openssl | 2 | 1 | 1 | 0 | 0 | 2 | 0 | 0 | 0 / 1 / 0 / 0 / 1 | 0 |
| debian/redis-tools | 136 | 46 | 57 | 44 | 8 | 70 | 10 | 4 | 60 / 46 / 17 / 11 / 2 | 12 |
| debian/zstd | 14 | 11 | 0 | 14 | 0 | 0 | 0 | 0 | 3 / 6 / 3 / 2 / 0 | 0 |
| debian/tree | 2 | 1 | 1 | 1 | 0 | 1 | 0 | 0 | 0 / 1 / 0 / 1 / 0 | 0 |
| debian/coreutils | 14 | 11 | 0 | 14 | 0 | 0 | 0 | 0 | 6 / 1 / 0 / 7 / 0 | 0 |
| havuz (10 birim) | 270 | 97 | 77 | 123 | 12 | 88 | 20 | 27 | 117 / 87 / 33 / 25 / 8 | 16 |

- **Adım dağılımı (havuz, bayt):** 8: 123, 16: 24, 24: 32, 32: 6, 40-64: 7, 72-128: 7, 136-256: 11, 264-512: 60.
  - 264-512 baytın 60'ı redis-tools'tan gelir: büyük komut tablosu benzemeyen kayıt çiftlerinden bölünüyor (§7 madde 3).
- **Sınıf payları (havuz, 270 tablo):**
  - gösterici dizisi (adım 8): %45,6;
  - ad + işleyici (tek fn, dizgili): %32,6;
  - sınıf/vtable benzeri (çok fn, dizgisiz): %4,4;
  - çok fn ve dizgili (sınıf nesnesi, komut yapısı): %7,4;
  - tek fn, dizgisiz: %10,0 **[hesap]**.
  - redis-tools hariç (134 tablo): gösterici dizisi %59,0, ad + işleyici %13,4 **[hesap]**.

## 4. Bu kaynağın N4'ün üç ailesine göre büyüklüğü (yalnız erişim; doğruluk yok)

Mac sayıları `fiil_onkayit_taslak.md` §4.2 ve §6.8'den, tablo sayıları bu belgeden alındı.

| Kaynak | Mac tmux | Mac htop | Not |
|---|---:|---:|---|
| F-API: ayırt edici API, iç çağrı ≤ 3 | %8,9 | %13,7 | taslak §6.8 |
| F-ETKİ aday havuzu: yaprak + yalnız bellek/dizgi | %16,1 + %18,9 | %17,1 + %18,9 | taslak §6.8; ilk sürümde yalnız `create`/`destroy` |
| F-ROL | sayılmadı | sayılmadı | taslak §4.2 |
| **Tablo kaydı + ad biçimli kayıt dizgisi, bugün adsız (gevşek)** | **%10,6** | **%3,0** | bu belge |
| — bunun I sınıfında olanı | %8,3 (215) | %1,7 (10) | **[hesap]** N4'ün erişemediği nüfus |
| Tablo kaydında (dizgi şartı yok; yuva rolü için erişim) | %17,2 | %10,9 | bu belge |
| Herhangi bir veri yuvası | %17,9 | %24,8 | bu belge |

- **tmux türünde** bu kaynak F-API ile aynı büyüklüktedir ve neredeyse tümüyle N4'ün dışındaki I sınıfına düşer. Kusursuz bir tablo rolü kanalının N4 tavanına (K ∪ Y %52,8) ekleyebileceği en çok pay %8,3'tür **[hesap]**.
- **htop türünde** bu kaynak küçüktür (%3,0). Taslağın "htop'un açığı tablolardan gelir" beklentisi bu tanımla doğrulanmadı.
  - Mac htop'ta çağıransızların %61,6'sı bir veri yuvasında, ama yalnız %27,3'ü tablo kaydında.
  - Yuvaların çoğu bitişik olmayan sınıf nesnelerinde (§7 madde 2).
- **A1 öldürme ölçütü (a):** `onuncu_adam.md` §5'te eşik "Mac htop'ta yalnız tablolardan başvurulan pay < %15 ise bırak".
  - Tablo kaydında ve çağıransız: 59/597 (%9,9). Bu okuma ölçütü tetikler.
  - Herhangi bir veri yuvasında ve çağıransız: 133/597 (%22,3). Bu okuma tetiklemez.
  - Hangi okumanın kastedildiği Berke'nin kararıdır.

## 5. Ghidra çapraz denetimi

Saklı `static/` çıktısında açık bir veri→fonksiyon başvuru listesi yok. `karadul/ghidra/headless.py` `_extract_xrefs` yalnız çağrı başvurularını ve dizgi veri başvurularını yazıyor. Bu yüzden çapraz denetim üç dolaylı kaynakla yapıldı:

| Denetim | Sonuç (on birim toplamı) |
|---|---|
| Metin bölümüne düşen veri göstericisi Ghidra fonksiyon girişi mi? | 6 107 fonksiyon yuvası (5 865 veri + 242 başlatma dizisi), metin içinde fonksiyon girişi olmayan gösterici (T) **0**. Ayrışma yok. |
| Decompile edilmiş koddaki `PTR_<önek>_<adres>` etiketleri | Jenerik fonksiyon önekli 140 etiketin 140'ı bu sayımda F. Kod etiketi önekli (LAB) 0. Adlı simge önekli 214 etiket: 163 D, 43 X, 8 F (ihraç edilen veri ve fonksiyon simgeleri). Dizgi önekli 1 943 etiketin 1 930'u S, 11'i E, 2'si D: Mac tmux'ta yazdırılamayan karakterli dizgi; bu tanımda dizgi sayılmaz. Tanımsız veri önekli 676 etiketin 428'i bu sayımda S: Ghidra'nın tanımlamadığı kısa dizgiler. |
| Dizgi yuvası hedefi Ghidra dizgisi mi? | 34 605 dizgi yuvasından (S + E) 25 987'si bir Ghidra dizgisinin başı, 2 248'i bir Ghidra dizgisinin içi, 6 370'i (%18,4) Ghidra'da dizgi değil. Debian htop'ta bu 314 yuvanın 312'sinde önceki bayt NUL: gerçek dizgi başı. Çoğu 1-4 karakter ya da çok baytlı UTF-8 (çizgi karakterleri). Ghidra'nın varsayılan en kısa dizgi uzunluğunun altında kaldıkları için tanımlanmamışlar **[tahmin]**. |

- Mach-O chained fixup'larının her biri lief'in hedefiyle elle çözülen değer karşılaştırılarak doğrulandı (`DYLD_CHAINED_PTR_64_OFFSET`); uyuşmazlık betiği durdurur, çıkmadı.
- ELF'te Ghidra'nın `.text` bloğu, ELF `.text` adresi + kayma ile denetlendi.

## 6. Elle okuma: yanlış pozitif oranı

- **Yöntem:** Debian htop, tmux ve sqlite3'te tablolar `random.Random(20261110)` ile 10'ar seçildi. Her tablo ham bayt ve yer değişiminden uçbirimde döküldü: kayıt sözcükleri, F'ler için Ghidra adı, S'ler için dizgi.
- **Bakılanlar:** kaydın aynı türden yinelenen nesne olup olmadığı, tablonun öncesi ve sonrası, gerektiğinde disassembly'deki erişim. Döküm aracı depo dışında (§10). Dökümde görülen adlar ve dizgiler bu belgeye yazılmadı.
- **Sınıflar:**
  - **G:** gerçek kayıt tablosu (dizi ya da bitişik, aynı türden nesneler).
  - **V:** tek bir nesnenin ardışık yöntem yuvaları (vtable benzeri; adım 8).
  - **Y:** tek bir nesnenin içindeki düzenli desen ya da farklı türden nesneler.

| İkili (tablo sayısı) | Örnek | G | V | Y | Not |
|---|---|---:|---:|---:|---|
| Debian htop (18) | 10 | 2 | 6 | 2 | Y'ler adım 24 ve 16: sınıf nesnesi içinde Z/F dönüşümlü alanlar |
| Debian tmux (24) | 10 | 6 | 4 | 0 | G'lerin 3'ünde faz bir sözcük kaymış, 1'inde belirsiz (dizgisiz; sayıyı etkilemez); büyük bir komut tablosu 85 kayıtla doğru |
| Debian sqlite3 (15) | 10 | 1 | 9 | 0 | V'ler sanal tablo ve G/Ç yöntem yapıları |
| **Toplam** | **30** | **9** | **19** | **2** | |

- **Tablo tanımının yanlış pozitif oranı:**
  - Katı okuma (V ve Y yanlış): 21/30 (%70).
  - V'yi ayrı bir sınıf sayan okuma: 2/30 (%6,7).
  - Adımı 8 baytı aşan tablolarda 2/11 (%18); adım 8 baytlık tablolarda kayıt tablosu olarak 19/19 yanlış.
- **Kayıt dizgisi tanımı:** üç ikilinin bütün dizgili tabloları okundu (htop 4, tmux 5, sqlite3 1; toplam 10).
  - **Kesin:** 10 tablonun hiçbirinde yanlış kayda ait dizgi yok. 9 tabloda dizgiler aynı kayıtta, sqlite3'teki 1 tabloda kesin küme boş (faz belirsiz).
  - **Gevşek:** 1/10 tabloda (sqlite3) her fonksiyonun kümesine bir sonraki kaydın adı da giriyor.
- **Örnek dışı gözlem (redis-cli, 2 dizgili tablo):** birinde çapa, önceki nesnenin bir alanına düştüğü için faz 2 sözcük kaydı. Kesin kümede doğru ad ile birlikte 2 yabancı dizgi var. Örneklem dışı olduğu için orana katılmadı. redis-tools'un %5,7'lik üst sınırı bu tür kaymaları içerebilir.

## 7. Tanımların zayıf yanları

1. **Adım 8 bayt ayırt edilemez.** Ardışık gösterici dizisi ile bir yapının ardışık yöntem alanları bayt düzeyinde aynıdır. Elle okunan 19 örneğin hepsi yapı içiydi. "Tablo kaydında" sayısı bunları içerir; kayıt tablosu için "adım > 8" sütunu kullanılmalı.
2. **Bitişiklik şartı.** Aynı türden ama arada başka nesneler olan sınıf nesneleri (htop'ta sayaç sınıfları gibi) tablo sayılmaz. Bu nesnelerin yuvaları A1'in "aynı yerleşimli yapının aynı yuvası" fikrine uyar, ama bu tanım onları kaçırır.
   - Debian htop: yuva 128, tablo kaydı 64. Mac htop: 148'e 65.
   - Nesneleri türlerine göre (ör. ortak sınıf göstericisi) gruplamak ölçülmedi.
3. **Boş olabilen alanlar tabloyu böler.** Benzerlik süzgeci D/Z farkını cezalandırır. tmux'un girdi durum tabloları 3-5 kayıtlık parçalara, redis'in komut tablosu ~60 parçaya bölündü. 3 kayıttan kısa kalan parçalar kaybolur. Bu bir eksik saymadır; tavan aşağı yanlıdır.
4. **Faz.**
   - 270 tablonun 77'sinde faz belirsiz. Çapa ile seçilen faz da yanılabilir (§6 redis-cli).
   - Kod çapası alan ofseti katlanmış bir adrese düşerse fazı kaydırır.
5. **Eşikler veriye bakılarak kondu.** Benzerlik 0,9 ve kenar 0,5, Debian htop'un ilk dökümünde büyük adımlı sahte tablolar (360-504 bayt) görüldükten sonra eklendi. htop'un elle okuma oranı bu yüzden iyimserdir; tmux ve sqlite3 daha tazedir. Eşiklerin duyarlılığı ölçülmedi.
6. **Dizgi tanımı geniştir.** Herhangi bir NUL sonlu, yazdırılabilir dizi dizgi sayılır. Tek karakterlik dizgiler de "tanımlayıcı" sınıfına girer.
   - Ghidra'nın dizgi saymadığı yuvalar %18,4.
   - Ad kanıtı sınıfı yalnız biçime bakar; dizginin fonksiyonun adı olup olmadığına bakmaz.
7. **Dizgi kaydı adlandırır, yuvayı değil.** Birden çok fonksiyon yuvalı kayıtlarda (sınıf nesnesi, komut yapısı) aynı dizgi o kaydın bütün fonksiyonlarına "kanıt" sayılır. Üst sınırda (gevşek) bu durumdaki fonksiyonlar 233/708; Mac htop'ta 12/18 (§3.3). Bir kanal bunlara ancak "kayıt adı + yuva rolü" biçiminde ad verebilir.
8. **Kapsam dışı:** göreli ofset tabloları (int32 ofset dizileri, switch tabloları), PIE dışı ikililerde `.rodata` içi gösterici tabloları (bu veri setinde PIE dışı ikili yok) ve hizasız göstericiler.

## 8. Doğrulayamadıklarım

- Bu kaynaktan türetilecek adların doğruluğu. GT açılmadı; tavan yalnız erişimdir.
- Kayıt dizgisinin gerçekten fonksiyonun adını (ya da kaydın adını) taşıdığı. Elle okunan tmux ve htop örneklerinde öyle görünüyor, ama sayılmadı.
- Elle okuma yalnız üç Debian ikilisinde yapıldı (30 tablo + 10 dizgili tablo). Mac, redis-tools, openssl, zstd ve coreutils tabloları elle okunmadı; redis-cli'ye kısa bir bakış dışında.
- KS-1 çapasıyla örtüşme: saklı koşularda `kesin_capalar.json` yok.
- Plan v2.2'deki T1'in (işaretçi haritası) çıktısıyla karşılaştırma: bu çalışmada T1 çıktısı kullanılmadı.
- coreutils ve zstd'de çağıransızların %89,2 ve %78,6'sının neden açıklanamadığı.

## 9. Yeniden üretim ve denetim

```
python3 -I -B docs/arge/2026-11-10_n4/tablo_yuvasi_sayim.py \
  --mac-kosu ~/Black_Widow/workspaces/olcum_mac/runs/ol7-a-9a36142 \
  --debian-kosu ~/karadul_olcum/n1_debian13 \
  --on-sayim docs/arge/2026-11-10_n4/on_sayim.json \
  --cikti docs/arge/2026-11-10_n4/tablo_yuvasi_sayim.json
```

- **Süre:** yaklaşık 40 sn. Python 3.12.7, pyelftools 0.32, lief 0.17.6.
- **Belirlenimcilik:** `PYTHONHASHSEED=1` ve `PYTHONHASHSEED=4242` ile çıktı bayt bayt aynı (`cmp`). JSON SHA-256: `77f05265e81c9b36af737d7cdf22e5926df96ba5208c2cf33d5001178fcb6ed2`.
- **Testler:** `tests/test_n4_tablo_yuvasi_sayim.py`, 20 test, sentetik baytlarla.
  - Kapsananlar: dizgi ve sınıflar, sözcük türleri, hiza, tablo ve adım kuralları, alt örnek, kayıt içi gösterici, benzerlik ve kenar, belirsiz adım, faz ve çapa, kesin/gevşek, kodda adres, naming_map anahtarları, ön sayım denetimi.
- **Mutasyon:** 12 elle mutant, her biri ayrı kopyada (`PYTHONDONTWRITEBYTECODE=1`, eski ve yeni metin farklı uzunlukta). 12/12 öldü. Mutantlar:
  - yazdırılabilirlik denetimi, kısa ad uzunluk sınırı, en az kayıt sayısı, alt örnek kuralı;
  - çapa önceliği, kesin = kesişim, sıfır sözcük türü, fonksiyon girişinin metin içinden önce gelmesi;
  - ortalama benzerlik eşiği, farklı adım belirsizliği, saklama komutunun yazmacı silmemesi, kenar kaydı eşiği.

## 10. Diskte bırakılanlar

- **Depoda (yeni, izlenmeyen):** `docs/arge/2026-11-10_n4/tablo_yuvasi_sayim.{py,json,md}`, `tests/test_n4_tablo_yuvasi_sayim.py`. Commit yok.
- **`~/karadul_olcum/runs/n4-tablo-yuvasi-2026-11-10/`:**
  - keşif betikleri (`kesif*.py`);
  - elle okuma dökümü aracı `tablo_dok.py` (çıktısı yalnız uçbirime);
  - `profil.py`, `ozet.py`, `md_tablo.py`;
  - mutasyon koşucusu `mutant_kos.py` ve `mutant/` kopyaları;
  - ara JSON'lar (`deneme*.json`, `tohum*.json`);
  - yama betikleri (`yama*.py`, `tablo_blok.py`).
  - Ara JSON'larda ad ya da dizgi yok. Döküm aracı adları yalnız uçbirime basar.
