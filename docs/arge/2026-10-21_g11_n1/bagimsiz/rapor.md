# KS-1 adım 2: bağımsız yeniden hesap

- **Tarih:** 2026-11-10.
- **Sınanan:** `ks1_olcum.json` ve `ks1_olcum.md` (commit 5d0b528); ölçümün puanlaması.
- **Tanımların kaynağı:** `ks1_onkayit.md` (a22d833) §3-§9 ve `ks1_sapma_1.md` (0da58cf) S1.
- **Betik ve çıktı:** `yeniden_hesap.py`, `yeniden_hesap.json`. Bu rapordaki her sayı o dosyadandır; "ölçüm" sütunları `ks1_olcum.json`'dan okunmuştur.
- **Çıktılarda fonksiyon adı yoktur:** yalnız sayılar, birim ve ikili adları, adresler.

## Hüküm

Kesinlik sayıları, kararlar ve rapor satırları ölçümle birebir tutuyor (1 690 hücrede 0 fark); fark yalnız kapsam paydasında (ad bekleyen nüfus, 178 hücrenin 132'si), dört birimde, belgenin tanımlamadığı iki ayrıntıdan geliyor ve hiçbir kararı etkilemiyor. Betikte hata bulunmadı.

## 1. Bağımsızlık

| Konu | Durum |
|---|---|
| Okunmayan, içe aktarılmayan | `ks1_olc.py`, `function_f1.py`, `macho_f1.py`, `macho_measure.py`, `tests/test_ks1_olc.py` |
| Çapalar | `kesin.py` dosya yolundan yüklendi, `extract_anchors` (sha256 ön kayıttakiyle aynı; sınanan çıkarıcı değil) |
| ELF GT'si | dbgsym `.debug` dosyasının `.symtab`'ı, pyelftools ile; build-id'yle bulundu |
| Mac GT'si | strip'siz özgün ikilide `/usr/bin/nm`; hazır `*.gt.json` yalnız karşılaştırıldı |
| Koşturulmayan | Karadul, Ghidra, test takımı, ölçüm betiği; başka model ya da ajan |
| Kazara görülen | Depodaki tutarlılık kancası (`check-consistency.sh`) bu betik yazılırken `ks1_olc.py`'den dört sabit satırını ekrana bastı: üç satır adı listesi ve zenginlik eşiği. Puanlama mantığı içermiyor; dosya açılmadı |

## 2. Tanım listesi

| # | Tanım | Belgedeki yer | Belge yeterli mi |
|---|---|---|---|
| T1 | Birimler ve birim başına ELF sayısı (10 birim, 119 ikili) | §7 | evet |
| T2 | Türler ve roller (`kendi`, `ust`, `parca`) çıkarıcıdan gelir | §3, §4 | evet |
| T3 | Karar satırları: `assert` (rol `kendi`), `assert_ust`, `func_kalibi`, `func_aktarma`; çok türlü çapa her satırında sayılır | §8 | evet (bkz. B8) |
| T4 | Rapor satırları: `export`, `dizgi_turleri` (çapa başına bir); karar hesaplanmaz | §8 | evet |
| T5 | ELF GT'si: `.debug` dosyasının `.symtab`'ı; aynı adresteki adlar takma ad | §6 | kısmen (B5) |
| T6 | Mac GT'si: nm; analiz edilen dosya strip'li kopya | §6 | kısmen (B5) |
| T7 | Adres: Mac'te VM adresi; ELF'te dosya adresi + (görüntü tabanı − en düşük `PT_LOAD`), iki çapraz denetimle | §6, sapma S1 | evet |
| T8 | Ad karşılaştırması: takma adlardan birine tam eşitlik; Mach-O'da baştaki tek `_` soyulur | §6 | evet |
| T9 | Klon satırı: bütün takma adlar derleyici ekliyse taban eşitliği; `OUTLINED_FUNCTION_N` tabansız | §6 | evet |
| T10 | Eşlenemeyen çapa yanlış sayılır | §6 | evet |
| T11 | Parça çapaları ayrı sayılır, kesinliğe girmez | §4, §6 | kısmen (B6) |
| T12 | Tekil: birim içinde (satır, ad), bütün örnekleri doğruysa doğru; örnek düzeyi: her çapa | §7 [karar 16], §8 | evet |
| T13 | C++ ikili kesinlik dışı | §7 | kısmen (B1) |
| T14 | Ad bekleyen nüfus (Mac, ELF) | §7 | hayır (B2, B3, B4, B7) |
| T15 | Kapsam: nüfusta çapalanan / nüfus, örnek düzeyinde; export'ta pay ve payda dışa aktarılan GT | §8, §9 | evet |
| T16 | Wilson %95 aralığı, z = 1,96 | §8 madde 1 | evet |
| T17 | Giren birim: tekil n ≥ 10 | §8 madde 2 | evet |
| T18 | Program kesinliği: aynı programın giren birimlerinin ortalaması; en az 2 farklı program, yoksa `yetersiz` | §8 madde 3 | evet |
| T19 | Makro: program kesinliklerinin eşit ağırlıklı ortalaması, iki görünümde ayrı | §8 madde 4 | evet |
| T20 | `kesin`: min(tekil makro, örnek makro) ≥ %95 (kesirle) ve iki görünümde giren hiçbir birimin Wilson üst sınırı %95'in altında değil | §8 madde 5 | evet |
| T21 | Havuz: bütün birimler üzerinden Σ doğru / Σ n | §8 madde 6 | evet |
| T22 | Duyarlılık: yalnız ana satır, tek türlü | §6 | evet |
| T23 | Program sınıfı: dizgi zenginliği (eşik 0,05), ELF ortancası ve boyut tabakası | §9 | evet |

## 3. Karşılaştırma

Ölçüm çıktısıyla hücre hücre (`karsilastirma`):

| Grup | Hücre | Tutan | Farklı |
|---|---|---|---|
| Birim × satır: tekil, örnek, yalnız ana, tek türlü, klon, eşlenemeyen, parça, kapsam payı, aralıklar | 1 020 | 1 020 | 0 |
| Karar: giren birim ve programlar, program kesinlikleri, makrolar, Wilson ihlalleri, karar, havuz | 80 | 80 | 0 |
| Rapor satırları (`export`, `dizgi_turleri`) | 12 | 12 | 0 |
| İkili künyesi: çapa sayısı, GT fonksiyon sayısı, ofset, ofset kaynağı | 468 | 468 | 0 |
| Birim: ELF sayısı, C++ dışarıda kalan, export GT | 30 | 30 | 0 |
| Export kapsam paydası | 10 | 10 | 0 |
| Program sınıfı (eş değişken) | 70 | 70 | 0 |
| Ad bekleyen nüfus (kapsam paydası) | 178 | 46 | 132 |
| **Toplam** | 1 868 | 1 736 | 132 |

- `ks1_olcum.md`'nin "Birim başına" tablosu da okundu: 19 satır, 190 hücre, 0 fark.
- Nüfus tanımına §4'teki iki ek yapılınca (duyarlılık `nufus_uzlastirma`) 1 868 hücrenin hepsi tutuyor.

Sıfır olmayan birim × satır hücreleri (iki hesapta aynı; yalnız son iki sütun ayrışıyor):

| Birim | Satır | Tekil (doğru/n) | Örnek (doğru/n) | Klon (doğru/n) | Eşlenemeyen | Parça (doğru/n) | Kapsam payı | Nüfus: bağımsız | Nüfus: ölçüm |
|---|---|---|---|---|---|---|---|---|---|
| debian/coreutils | `assert` | 29/34 | 61/67 | 2/2 | 0 | 0/0 | 65 | 12 822 | 12 717 |
| debian/coreutils | `export` | 3/3 | 211/211 | 0/0 | 0 | 0/0 | 211 | 211 | 211 |
| debian/coreutils | `dizgi_turleri` | 29/34 | 61/67 | 2/2 | 0 | 0/0 | 65 | 12 822 | 12 717 |
| debian/htop | `export` | 366/366 | 366/366 | 0/0 | 0 | 0/0 | 366 | 373 | 373 |
| debian/openssl | `func_kalibi` | 15/15 | 15/15 | 1/1 | 0 | 0/0 | 14 | 563 | 563 |
| debian/openssl | `dizgi_turleri` | 15/15 | 15/15 | 1/1 | 0 | 0/0 | 14 | 563 | 563 |
| debian/redis-tools | `assert` | 22/30 | 47/56 | 2/5 | 0 | 0/0 | 51 | 1 459 | 1 458 |
| debian/redis-tools | `export` | 3855/3855 | 8394/8394 | 0/0 | 0 | 0/0 | 8 394 | 8 539 | 8 539 |
| debian/redis-tools | `dizgi_turleri` | 22/30 | 47/56 | 2/5 | 0 | 0/0 | 51 | 1 459 | 1 458 |
| debian/tmux | `func_kalibi` | 91/97 | 91/97 | 8/9 | 0 | 0/0 | 88 | 1 851 | 1 851 |
| debian/tmux | `func_aktarma` | 15/15 | 15/15 | 0/0 | 0 | 0/0 | 15 | 1 851 | 1 851 |
| debian/tmux | `dizgi_turleri` | 105/111 | 105/111 | 8/9 | 0 | 0/0 | 102 | 1 851 | 1 851 |
| debian/zstd | `assert` | 137/164 | 137/164 | 18/20 | 0 | 0/0 | 144 | 913 | 919 |
| debian/zstd | `assert_ust` | 2/4 | 2/4 | 0/0 | 0 | 4/4 | 4 | 913 | 919 |
| debian/zstd | `dizgi_turleri` | 139/168 | 139/168 | 18/20 | 0 | 4/4 | 148 | 913 | 919 |
| mac/tmux | `assert_ust` | 3/3 | 3/3 | 0/0 | 0 | 14/14 | 3 | 2 545 | 2 545 |
| mac/tmux | `func_kalibi` | 143/150 | 143/150 | 0/0 | 0 | 0/0 | 150 | 2 545 | 2 545 |
| mac/tmux | `func_aktarma` | 21/21 | 21/21 | 0/0 | 0 | 0/0 | 21 | 2 545 | 2 545 |
| mac/tmux | `dizgi_turleri` | 165/172 | 165/172 | 0/0 | 0 | 14/14 | 172 | 2 545 | 2 545 |

Rapor satırları: `export` tekil 4224/4224, örnek 8971/8971; `dizgi_turleri` tekil 475/530, örnek 532/589. Ölçümle aynı.

## 4. Fark tablosu

Farkların hepsi ad bekleyen nüfusta (kapsam paydası). Satırdan bağımsızdır: birimin beş dizgi satırında aynı payda kullanılır. Kapsam payları (çapalanan sayısı) iki hesapta aynıdır.

| Birim | Bağımsız | Ölçüm | Fark | Farklı hücre | Neden | Sınıf |
|---|---|---|---|---|---|---|
| debian/coreutils | 12 822 | 12 717 | +105 | 111 (1 birim, 105 ELF, 5 satır) | 105 ELF'in her birinde bir GT fonksiyonu: libc'nin statik bağlanan parçasından gelen çıkış işleyicisi kayıt sarmalayıcısı. Ölçüm onu CRT sayıp dışarıda bırakıyor; bu hesabın CRT listesi yalnız başlangıç kodunu içeriyor. Örnek: `[` ikilisinde Ghidra adresi `1081e0` | belge belirsiz (B2) |
| debian/redis-tools | 1 459 | 1 458 | +1 | 7 | aynı fonksiyon; `redis-cli`, Ghidra adresi `15f720` | belge belirsiz (B2) |
| debian/sqlite3 | 390 | 389 | +1 | 7 | aynı fonksiyon; Ghidra adresi `138f60` | belge belirsiz (B2) |
| debian/zstd | 913 | 919 | −6 | 7 | Ghidra'nın `caseD_N` diye adlandırdığı 6 fonksiyon (`1cb840`, `1cd0e0`, `1d1da0`, `1d3640`, `1d938c`, `1da060`). Ölçüm bunları ad bekleyen sayıyor; §5 K5'teki jenerik ad listesinde `caseD_` yok | belge ↔ kod farkı (B3) |

Etki: `dizgi_turleri` kapsamı zstd'de %16,21 (148/913) ve %16,10 (148/919); coreutils'te iki paydayla da %0,51; redis-tools'ta %3,50. Kesinlik ve kararlar paydadan bağımsızdır.

## 5. "Belge belirsiz" bulguları

| # | Konu | Belge | Bu hesabın yorumu | Sonuç |
|---|---|---|---|---|
| B1 | C++ işaretinin kaynağı | §7 "içe aktarılan adlar"; anlatım Ghidra'nın adları üzerinden | Ghidra'nın thunk ve dış fonksiyon adları | Ölçümle aynı: yalnız `pzstd`. İkilinin kendi içe aktarma tablosuyla bakılınca `redis-check-aof` ve `redis-check-rdb` de C++ çıkıyor (aşağıda) |
| B2 | CRT fonksiyonlarının listesi | §7; liste yok | başlangıç kodu simgeleri (12 ad; betikte özet olarak) | 107 ELF'te nüfus 1 fazla (§4) |
| B3 | Nüfusta "adı jenerik" | §7; liste yalnız §5 K5'te | K5 listesi | zstd'de nüfus 6 eksik (§4) |
| B4 | Ghidra'nın `code` sınıfı | §7; tanım yok | dış olmayan, çalıştırılabilir ve `.plt` dışı blokta | Etkisiz: koşulsuz ve "yalnız `.text`" yorumları da her birimde aynı sayıyı veriyor |
| B5 | GT'ye giren simgeler | §6; yardımcıya havale | ELF: tanımlı `STT_FUNC`; Mac: `(__TEXT,__text)` içindeki simgeler | 118 ikilinin hepsinde GT fonksiyon sayısı ölçümle aynı; Mac'te hazır GT ile adres ve ad kümesi birebir |
| B6 | Parça çapasının doğruluk ölçütü | §6; yazılmamış | öbür çapalarla aynı (klon satırında taban eşitliği) | 18/18, ölçümle aynı |
| B7 | Mac'te `cold` ve `outlined` sınıfı | §7; yardımcıya havale | ad kalıbından | Hazır GT'deki sınıflarla aynı; nüfus aynı |
| B8 | Çok türlü, rolü `kendi` olan çapanın assert kanıtı yalnız kaldırılmışsa satırı | §4 rolü çapa düzeyinde tanımlıyor | rol neyse o | Etkisiz: veri setinde böyle çapa yok (0) |

**B1 ayrıntısı.** `redis-check-aof` ve `redis-check-rdb` 326 ad içe aktarıyor; bunlardan 1'i `_Z` ile başlıyor ve ikili `libstdc++`'a bağlı. Ghidra bu adı açtığı ve `__gxx_personality` ya da `__cxa_*` işaretleri içe aktarılmadığı için §7'deki işaret listesi ikiliyi yakalamıyor. İkilinin 4 758 GT fonksiyonundan 7'sinin adı mangled; 9 dizgi çapasının hiçbiri onlara düşmüyor. Yani kural yazıldığı gibi uygulanmış, ama "C++ ikili" amacını bu ikilide kaçırıyor. İçe aktarma tablosuna göre dışarıda bırakılırsa (`duyarlilik.cpp_ikili_tablosu`): redis-tools `assert` tekil 22/29, örnek 31/38; `assert` makrosu tekil %81,56, örnek %85,39; karar yine `kesin_degil`. Öbür üç karar değişmiyor. Bu hesabın ilk koşusu tabloya göre yapılmıştı; ayrışma oradan bulundu.

**Belirsizlik olmayan, ama bilinmesi gereken.** `redis-check-aof` ile `redis-check-rdb` bayt bayt aynı dosya (sha256 aynı); ön kayıt §7 ikisini ayrı ELF sayıyor. Tekil görünüm etkilenmiyor; örnek düzeyi ve kapsam aynı ikiliyi iki kez sayıyor. Tek sayılırsa (`duyarlilik.yinelenen_ikili_tek`): redis-tools `assert` örnek 39/47 (ölçümde 47/56), nüfus 835, export GT 4 697; `assert` örnek makrosu %85,85; kararlar aynı.

## 6. Kararların elle doğrulaması

Program kesinliği, makro (kesirle) ve Wilson üst sınırı (z = 1,96). Üst sınırlar betikteki işlevden ayrı, kapalı biçimle de hesaplandı; aynı.

| Satır | Görünüm | Giren birim: kesinlik (Wilson üst sınırı) | Program kesinliği | Makro |
|---|---|---|---|---|
| `assert` | tekil | coreutils 29/34 (%93,55), redis-tools 22/30 (%85,82), zstd 137/164 (%88,43) | %85,29; %73,33; %83,54 | 101273/125460 = %80,72 |
| `assert` | örnek | coreutils 61/67 (%95,83), redis-tools 47/56 (%91,31), zstd 137/164 (%88,43) | %91,04; %83,93; %83,54 | 132557/153832 = %86,17 |
| `func_kalibi` | tekil ve örnek (aynı) | openssl 15/15 (%100), debian/tmux 91/97 (%97,13), mac/tmux 143/150 (%97,72) | openssl %100; tmux 27521/29100 = %94,57 | 56621/58200 = %97,29 |
| `func_aktarma` | tekil ve örnek (aynı) | debian/tmux 15/15 (%100), mac/tmux 21/21 (%100) | tmux %100 | %100 |
| `assert_ust` | — | giren birim yok; küçük: debian/zstd 2/4, mac/tmux 3/3 | — | — |

| Satır | Giren program | Karar makrosu ≥ %95 | Wilson ihlali | Karar | Ölçüm |
|---|---|---|---|---|---|
| `assert` | 3 | hayır (%80,72) | tekil: üç birim; örnek: redis-tools, zstd | `kesin_degil` | aynı |
| `assert_ust` | 0 | — | — | `yetersiz` | aynı |
| `func_kalibi` | 2 | evet (%97,29) | yok | `kesin` | aynı |
| `func_aktarma` | 1 | evet (%100), ama program sayısı 2'nin altında | yok | `yetersiz` | aynı |

Havuz: `assert` 188/228, `assert_ust` 5/7, `func_kalibi` 249/262 (%95,04), `func_aktarma` 36/36. Ölçümle aynı.

**İnceleyici notu (kural dışı, okuma yardımı; `kirilganlik`).** `func_kalibi` kararı kurala göre doğru, ama dar bir zemine dayanıyor: tmux'un program kesinliği tek başına %94,57 ile eşiğin altında; makroyu eşiğin üstüne openssl'in 15/15'i taşıyor. openssl'de tek bir çapa yanlış olsaydı makro 18227/19400 = %93,95 olur ve karar bozulurdu. debian/tmux'ta 4, mac/tmux'ta 6 ek yanlış kararı Wilson koşulundan bozardı.

## 7. Göz denetimi (30 + 30)

Ölçüm çıktısı öğe düzeyinde hüküm taşımıyor. Örnek, ölçümle bütün hücrelerde tutan bağımsız hesabın hükümlerinden çekildi. Havuz: karar satırlarına giren dizgi çapaları (parça ve export dışarıda): 532 doğru, 57 yanlış. Tohum 20261110. Seçilenlerin birim, ikili ve adresleri `goz_denetimi.secilen` altında.

| Küme | Bakılan | Katılıyorum | Katılmıyorum |
|---|---|---|---|
| Doğru sayılanlar | 30 | 30 | 0 |
| Yanlış sayılanlar | 30 | 30 | 0 |

- Doğru sayılan 30'un hepsi ana satırda: çapa adı GT adına harfi harfine eşit.
- Yanlış sayılan 30'un 28'i ana satırda, 2'si klon satırında. 30'unda da çapa adı başka bir fonksiyonun adı; takma ad, ek ya da yazım farkından doğan yanlış yok. 2'sinde GT programın giriş fonksiyonu; 2'si aynı çapanın bayt bayt aynı iki ikilideki kopyası.
- Ek olarak bakılanlar (hepsine katılıyorum): örnek dışında kalan 27 yanlış, klon satırına düşen 37 çapa, 18 parça çapası, 7 kaldırılmış çapa.

## 8. Bütünlük denetimleri

| Denetim | Sonuç |
|---|---|
| Analiz edilen dosyanın sha256'sı koşu künyesindekiyle aynı | 119/119 |
| ELF: ikili strip'li; hata ayıklama dosyasının build-id'si aynı | 116/116 (C++ sayılan `pzstd` için GT okunmadı) |
| ELF adres eşlemesi: giriş adresinde GT fonksiyonu var | 115/115 (giriş adresi olan ikililer) |
| ELF adres eşlemesi: `.dynsym`'de tanımlı fonksiyon simgesinin adı, GT'nin aynı adresteki adlarından biri | 9123/9123 |
| ELF ofseti ve kaynağı ölçümün künyesiyle aynı | 116/116 |
| Mac: özgün ve strip'li ikilide `__text` bölümü aynı (adres, boyut, içerik) | 2/2 |
| Mac: nm'den çıkan GT hazır GT ile aynı (adres ve ad kümesi, sınıf) | 2/2 |
| Belgedeki jenerik ad listesi ile çıkarıcının tanımı Ghidra adlarında ayrışıyor mu | 0 ad |
| Önbellekli ve önbelleksiz koşu | çıktı bayt bayt aynı |

## 9. Bu veri setinde çalışmayan kurallar

İki hesabın tutması, veride hiç çalışmayan bir kuralı doğrulamaz: o kuralı yanlış uygulayan bir betik de aynı sayıyı verirdi (`kural_yollari`).

| Kural | Veride kaç kez çalıştı |
|---|---|
| Eşlenemeyen çapa yanlış sayılır (§6) | 0 çapa |
| Tekil öğe, bütün örnekleri doğruysa doğrudur (§7) | çok örnekli 21 öğe var, ama örnekleri karışık hükümlü öğe 0: "hepsi" ile "herhangi biri" burada aynı sayıyı verir |
| Takma adlardan birine eşitlik (§6), dizgi çapalarında | 0 çapa (export'ta 4) |
| Klon satırında taban eşitliği (§6) | 37 çapa |
| Çok türlü çapa her satırında sayılır (§8) | 3 çapa |

İlk üç kural doğrulama setinde ilk kez çalışabilir.

## 10. Emin olunmayan noktalar

1. Eşitlik hücre düzeyindedir. Ölçüm öğe düzeyinde hüküm yazmadığı için iki hesabın aynı çapalara aynı hükmü verdiği doğrudan gösterilemedi; her birim × satırda tekil, örnek, klon, eşlenemeyen ve kapsam sayılarının hepsi tuttuğu için ayrışma olasılığı düşük.
2. §4'teki uzlaştırma, farkı sıfırlayan en küçük iki ektir. Ölçümün gerçek CRT ve jenerik ad tanımları (okunmadı) daha geniş olabilir; başka bir veri setinde başka adlar çıkabilir.
3. `proje_normallestirmesi` duyarlılık satırı yeniden hesaplanmadı: tanımı okunması yasak yardımcıda, karar dışı.
4. Çıkarıcı (`kesin.py`) sınanmadı. İki hesap aynı çapaları ve aynı GT kaynağını kullanıyor; çıkarıcıdaki ya da GT'deki ortak bir hata bu karşılaştırmada görünmez.
5. Betikteki CRT listesi ad olarak değil, adların sha256 özetleri olarak duruyor (çıktılarda fonksiyon adı geçmesin diye). Liste araç zincirinin başlangıç simgeleridir.
