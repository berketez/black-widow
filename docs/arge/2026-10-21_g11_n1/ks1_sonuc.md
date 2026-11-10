# KS-1 kesin çapalar: adım 2 sonucu

- **Tarih:** 2026-11-10.
- **Ön kayıt:** `ks1_onkayit.md` (a22d833), sapma kaydı `ks1_sapma_1.md` (0da58cf).
- **Ölçüm:** `ks1_olcum.json`, `ks1_olcum.md` (5d0b528). 8 açık kaynak program, 119 ikili (Debian 13 arm64: 117 ELF; Mac arm64: tmux, htop), Ghidra 12.1.2. Ad karşılaştırması tam eşitlik.
- **Bağımsız yeniden hesap:** `bagimsiz/rapor.md`. Puanlama kodu okunmadan, belgeden yazılan ayrı bir betikle.
- Bu belgede fonksiyon adı geçmez.

## 1. Karar

| Satır | Doğru / n (tekil, havuz) | Makro (tekil / örnek) | Karar |
|---|---|---|---|
| `func_kalibi` (günlük çağrısındaki `__func__`) | 249 / 262 | %97,3 / %97,3 | **`kesin`** |
| `func_aktarma` | 36 / 36 | %100 / %100 | `yetersiz` (tek program: tmux) |
| `assert` (çapa kendi gövdesinde) | 188 / 228 | %80,7 / %86,2 | **`kesin_degil`** |
| `assert_ust` (parçadan kaldırılmış) | 5 / 7 | — | `yetersiz` |

Yalnız raporlananlar: `export` 4 224 / 4 224 (Ghidra'nın dinamik simge tablosundan verdiği ad; KS-1 iddiası değil), `dizgi_turleri` 475 / 530.

`assert_ust` ve `func_aktarma`'nın `yetersiz` çıkacağı ölçümden önce aday sayılarından biliniyordu (ön kayıt §8).

## 2. Program ve boyut başına

| Birim | Boyut tabakası | Satır | n (tekil) | Kesinlik | Kapsam (ad bekleyen nüfusa göre) |
|---|---|---|---|---|---|
| debian/openssl | orta | `func_kalibi` | 15 | %100 | %2,5 |
| debian/tmux | orta | `func_kalibi` | 97 | %93,8 | %4,8 |
| mac/tmux | büyük | `func_kalibi` | 150 | %95,3 | %5,9 |
| debian/tmux | orta | `func_aktarma` | 15 | %100 | %0,8 |
| mac/tmux | büyük | `func_aktarma` | 21 | %100 | %0,8 |
| debian/coreutils (106 ELF) | küçük | `assert` | 34 | %85,3 | %0,5 |
| debian/redis-tools (4 ELF) | büyük | `assert` | 30 | %73,3 | %3,5 |
| debian/zstd | orta | `assert` | 164 | %83,5 | %15,7 |
| debian/htop, debian/sqlite3, debian/tree, mac/htop | orta, küçük, küçük, orta | — | 0 | — | 0 |

- Dört birimde hiçbir dizgi türünde yuva yok: bu programlar ne `__func__` günlüğü ne assert taşıyor. KS-1 onlara ad veremez.
- Boyutla düzenli bir ilişki görünmüyor; belirleyici olan programın kaynak alışkanlığı (günlük öneki, assert).

## 3. Okuma

**`func_kalibi` kesin, ama dar bir zeminde.**
- Karar iki programa dayanıyor. tmux'un program kesinliği (iki platformun ortalaması) %94,57 ile eşiğin altında; makroyu eşiğin üstüne openssl'in 15/15'i taşıyor. openssl'de tek bir çapa yanlış olsaydı makro %93,95 olur ve karar bozulurdu. Havuz %95,04.
- Yani "≥ %95" bugün sınırda tutuyor. Doğrulama setindeki tek okuma (Kapı 2) bunu ayrıca sınayacak; o okumaya kadar kural değişmez.

**`assert` kesin değil ve nedeni ön kayıtta yazılan risk.**
- Ölçümden sonra, geliştirme setinde yanlış 42 `assert` çapasına bakıldı (keşif; ön kayıtlı bir sınama değil). 40'ında çapanın adı ikilide ayrı bir fonksiyon olarak hiç yok: o fonksiyon çağırana tümüyle inline edilmiş ve assert'i çağıranın gövdesinde kalmış. Kalan 2'sinde çapanın adını taşıyan ayrı bir fonksiyon da var.
- Bu, ön kayıt §13.1'in "beklenen başlıca yanlış kaynağı" dediği durumdur: gövdenin kendi adı bir yuvada değilse K3 onu yakalayamaz.
- coreutils'teki yanlışların çoğunda ölçülen fonksiyon programın `main`'i. Üründe `main`, yükleyici bilgisinden ayrıca kurtarılıyor ve KS-1'den önceliklidir; bu yanlışlar ürüne geçmez. Bu gözlem kuralı değiştirmez: KS-1'in kendi başına kesinliği ölçülen sayıdır.
- zstd'deki yanlışların bir bölümünde iki ad iç içe (bir gövde fonksiyonu ile onu saran sürüm). Tam eşitlikte yanlış; gevşek ölçütte "yakın" sayılabilir. Bu ölçüm onu saymaz.

**Kapsam küçük.** Kesin çıkan satır, ad bekleyen fonksiyonların tmux'ta ≈ %5-6'sını, openssl'de %2,5'ini kapsıyor; dört birimde sıfır. KS-1 ürünün ad kapsamını tek başına taşıyamaz; bu, N2 taslağının öngörüsüyle (tmux ≈ %4,7, htop ≈ %0) uyumlu. Kapsamı büyütecek adım N4'tür (davranıştan fiil).

## 4. Bağımsız yeniden hesabın sonucu

- Kesinlik, karar ve rapor satırlarında ölçümle fark yok: kapsam paydası dışındaki 1 690 hücrede 0 fark; dört karar elle de doğrulandı.
- Fark yalnız ad bekleyen nüfusta, dört birimde (+105, +1, +1, −6) ve belgenin tanımlamadığı iki ayrıntıdan geliyor: CRT sayılan fonksiyonların listesi ve nüfustaki "jenerik ad" ölçütü (`caseD_` adları). Hiçbir kararı etkilemiyor; zstd'nin birleşik kapsamı %16,1 yerine %16,2 olurdu.
- 30 "doğru" ve 30 "yanlış" çapa gözle denetlendi: 60'ında da ölçümün hükmü doğru. Yanlışların hepsinde çapa adı başka bir fonksiyonun adı; takma ad, ek ya da yazım farkından doğan yanlış yok.

**Bilinmesi gerekenler:**
1. `redis-check-aof` ve `redis-check-rdb` bayt bayt aynı dosya; ön kayıt ikisini ayrı ELF sayıyor. Tek sayılırsa redis-tools `assert` örnek düzeyi 47/56 yerine 39/47 olur; kararlar aynı kalır.
2. Bu iki ikili libstdc++'a bağlı ve bir C++ adı içe aktarıyor; Ghidra adı açtığı için C++ işareti yakalamıyor. Dışarıda bırakılırsa `assert` yine `kesin_degil` (makro %81,6 / %85,4).
3. Üç kural bu veride hiç çalışmadı, yani doğrulanmış sayılmaz: eşlenemeyen çapa (0), örnekleri karışık hükümlü tekil öğe (0), çok takma adlı GT'ye düşen dizgi çapası (0). Doğrulama setinde ilk kez çalışabilirler.
4. İki hesap aynı çıkarıcıyı (`kesin.py`) ve aynı GT kaynağını kullanıyor; oradaki bir hata bu karşılaştırmada görünmez.

## 5. Ürüne etkisi (adım 3)

Satır durumu, ölçümden önce yazılan geçiş kuralıyla belirlenir (`karadul/reconstruction/tarif/baglama.py`, `row_status_from_measurement`; N0b ile aynı ölçüt: `kesin` çıkmayan satırda havuzlanmış yanlış oranının Wilson alt sınırı > %10 ise satır susar):

| Satır | Yanlış / n | Wilson alt sınırı | Üründe |
|---|---|---|---|
| `func_kalibi` | 13 / 262 | — | Ad verir, etiket "kesin" |
| `func_aktarma` | 0 / 36 | %0 | Ad verir, etiket "doğrulanmadı" |
| `assert_ust` | 2 / 7 | %8,2 | Ad verir, etiket "doğrulanmadı" |
| `assert` | 40 / 228 | %13,2 | Ad vermez |

- Kuralın küçük n davranışı gözle ters duruyor: 7 öğeli `assert_ust` ad verirken %82 doğru `assert` susuyor. Kural ölçümden önce yazıldı ve olduğu gibi uygulanıyor; `assert_ust` yalnız iki birimde toplam 7 çapa.
- `assert` çapaları ad olarak susar, ama taşıdıkları bilgi doğrudur: "bu gövdede şu fonksiyonun assert'i var (kendisi ya da inline edilmiş hâli)". Bunun ad yerine kanıt yorumu olarak gösterilmesi ayrı bir karardır.

## 6. Sonraki sınama için notlar (kural değişikliği değil)

Aşağıdakiler geliştirme setindeki keşiften çıkan fikirlerdir. Biri uygulanırsa yeni bir KS-1 sürümü, yeni bir ön kayıt ve taze veride (doğrulama seti) sınama gerekir.
1. `main` olarak kurtarılan fonksiyona çapa yazılmaması (coreutils'teki yanlışların çoğunu kapatır).
2. Aynı sha256'lı ikililerin tek sayılması.
3. C++ işaretinin ikilinin kendi içe aktarma tablosundan okunması.
4. Belgedeki iki açık tanımın yazılması: CRT listesi ve nüfustaki jenerik ad ölçütü.
5. `olc`'ye GT'ye dokunmadan yalnız ön koşulları sınayan kuru kip (sapma kaydı 1'in dersi).
