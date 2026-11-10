# Kalan ad kanallarının dökümü: yanlış sınıfları ve kesinliği ayıran koşullar

> **Uyarı.** Keşif çözümlemesi: bütün sayılar geliştirme setindendir. Kural adayları taze veride (doğrulama seti) sınanmadan iddia sayılmaz; aralıklar çoklu karşılaştırmaya göre düzeltilmemiştir.

- Kökler: Debian `/Users/apple/karadul_olcum/n1_debian13`, Mac `/Users/apple/Black_Widow/workspaces/olcum_mac/runs/ol7-a-9a36142`; 118 ikili (C++ dışarıda: debian/zstd/pzstd).
- Betik sha256 `43a36f474b4c1e0d…`; `urun_olc.py` `06131cdc55f752bc…`; `ks1_olc.py` `975c4d1265d8610e…`; HEAD `fa99144`.
- Hüküm taban ölçümünkiyle aynıdır (tam eşitlik; `urun_olc.degerlendir_elf`). Bu belgede fonksiyon adı, ürün adı, GT adı, anahtar ve dizgi geçmez; katalog girdileri ürün kodundaki sıra numarasıyla gösterilir.
- Taban denetimi (`docs/arge/2026-11-10_n1_adim3/urun_olcumu_taban.json`): `api_param_reverse` 0/55; `binary_extract` 963/1420; `butun` 1184/6394; `kalan` 1170/2073; `string_context/kebap_ad` 0/266; `string_context/oz_ad` 207/332 → tutuyor.
- Kural adayı kararı [seçim, sayımdan önce]: `oneri` = kesinlik ≥ %95,0 ve Wilson %95 alt sınırı ≥ %95,0 ve en az 2 farklı programda n ≥ 10; `yetersiz` = kesinlik eşiği tutuyor ama öbür iki koşuldan biri tutmuyor; `tutmuyor` = kesinlik eşiğin altında.

## 0. Özet

- **Kalan kanallar:** 2073 ad; ön adlar 963/1420 (%67,8), `oz_ad` 207/332 (%62,3), `kebap_ad` 0/266 (%0,0), `api_param_reverse` 0/55 (%0,0).
- **Ön adlar, tür başına:** `main_giris` 110/110 (%100,0); `elf_onyuk` 232/458 (%50,7); gnulib (üç katman) 621/852 (%72,9). Olduğu hâliyle karar: `elf_onyuk` `tutmuyor`, `gnulib/ayristirma` `yetersiz` (Wilson alt sınırı < %95; tek program), `gnulib/cagri_bicimi` `tutmuyor`, `gnulib/dizgi_parmak_izi` `tutmuyor`, `main_giris` `yetersiz` (tek program).
- **ELF önyükü:** yanlışların tamamı (226) ad temizleyicinin baştaki alt çizgiyi atmasından. Ad temizlenmeden yazılsa 458/458 (%100,0), Wilson alt sınırı %99,2 → `oneri`. Bu adların hepsi CRT fonksiyonudur (ad bekleyen nüfusa girmez; kesinliği yükseltir, kapsamı değiştirmez).
- **gnulib:** 231 yanlışın sınıfı: ad ikilide BAŞKA bir fonksiyona ait (`baska_fonksiyonun_adi`) 216, ad ikilinin GT'sinde hiç yok (`katalog_adi`) 15. Yanlışlar katalog girdisine bağlı: 3 girdi (`gnulib/cagri_bicimi#1`, `gnulib/cagri_bicimi#2`, `gnulib/dizgi_parmak_izi#0`) toplam 219 adın hiçbirinde doğru değil. Bu girdiler çıkarılırsa 621/633 (%98,1) (`yetersiz` (tek program); girdi seçimi aynı veride). coreutils dışındaki programlarda gnulib adları 1/6; ikilide dizgi parmak izi isabeti 3'ten az olan ikililerde 16/26 (%61,5).
- **`oz_ad` yanlışları (125):** yalnız harf farkı 45, çakışma eki 8, ikilideki başka bir fonksiyonun adı 17, içe aktarılan adı 1, önek/sonek farkı 5, ilgisiz 49. Kanıt dizgisi olduğu gibi (küçük harfe çevrilmeden, eksiz) yazılsa 260/332 (%78,3): eşiğin altında.
- **`oz_ad` ve KS-1:** 168 adda aynı adreste KS-1 çapası var; çapa aynı adı veriyorsa KS-1 adı 127/129 (%98,4; %94,5-%99,6), farklı ad veriyorsa KS-1 adı 38/39 (%97,4; %86,8-%99,6) doğru. Çapası olmayan 164 adda `oz_ad` 85/164 (%51,8); kanıt dizgisi olduğu gibi yazılsa 103/164 (%62,8). KS-1 açıldığında `oz_ad`'a kalan kısım budur.
- **`kebap_ad`:** 266 adın hiçbiri doğru değil ve hiçbiri normalleştirilince de eşit değil; ürün adı ikilinin GT'sinde hiçbir adreste yok (tam eşit 0). Yalnız 8 adda GT adı "önek + ürün adı" biçiminde; çakışma ekli ad 114 (aynı dizgi birçok fonksiyonda). Mekanik bir dönüşümle kurtarılamaz; ürünün kendi kuralıyla `sus`.
- **`api_param_reverse`:** 55 adın hiçbiri doğru değil; adlar geri çağrı ROLÜ adı (`ilgisiz` 53, önek/sonek 2), çakışma ekli ad 35. Fonksiyon adı olarak kurtarılamaz; ürünün kendi kuralıyla `sus`.
- **Kural adayları:** 195 koşul denendi; `oneri` 1, `yetersiz` 21 (§6). `oneri` çıkan her koşul da geliştirme setinde bulunmuştur.

## 1. Kanal grubu başına

| Grup | Ad | Doğru | Yanlış | Kesinlik (%95) | Program başına (doğru/n) |
|---|---|---|---|---|---|
| `on_ad` | 1420 | 963 | 457 | 963/1420 (%67,8; %65,3-%70,2) | coreutils 937/1374, htop 2/3, openssl 3/6, redis-tools 8/13, sqlite3 3/5, tmux 3/7, tree 3/5, zstd 4/7 |
| `oz_ad` | 332 | 207 | 125 | 207/332 (%62,3; %57,0-%67,4) | coreutils 27/40, htop 0/1, openssl 3/7, redis-tools 0/3, sqlite3 0/7, tmux 176/222, zstd 1/52 |
| `kebap_ad` | 266 | 0 | 266 | 0/266 (%0,0; %0,0-%1,4) | openssl 0/2, sqlite3 0/1, tmux 0/263 |
| `api_param_reverse` | 55 | 0 | 55 | 0/55 (%0,0; %0,0-%6,5) | coreutils 0/6, htop 0/1, openssl 0/4, redis-tools 0/11, sqlite3 0/5, tmux 0/25, zstd 0/3 |

Birim (platform/program) başına:

| Grup | Birim | Ad | Doğru | Kesinlik (%95) |
|---|---|---|---|---|
| `on_ad` | debian/coreutils | 1374 | 937 | 937/1374 (%68,2; %65,7-%70,6) |
| `on_ad` | debian/htop | 3 | 2 | 2/3 (%66,7; %20,8-%93,8) |
| `on_ad` | debian/openssl | 6 | 3 | 3/6 (%50,0; %18,8-%81,2) |
| `on_ad` | debian/redis-tools | 13 | 8 | 8/13 (%61,5; %35,5-%82,3) |
| `on_ad` | debian/sqlite3 | 5 | 3 | 3/5 (%60,0; %23,1-%88,2) |
| `on_ad` | debian/tmux | 6 | 3 | 3/6 (%50,0; %18,8-%81,2) |
| `on_ad` | debian/tree | 5 | 3 | 3/5 (%60,0; %23,1-%88,2) |
| `on_ad` | debian/zstd | 7 | 4 | 4/7 (%57,1; %25,1-%84,2) |
| `on_ad` | mac/tmux | 1 | 0 | 0/1 (%0,0; %0,0-%79,3) |
| `oz_ad` | debian/coreutils | 40 | 27 | 27/40 (%67,5; %52,0-%79,9) |
| `oz_ad` | debian/htop | 1 | 0 | 0/1 (%0,0; %0,0-%79,3) |
| `oz_ad` | debian/openssl | 7 | 3 | 3/7 (%42,9; %15,8-%75,0) |
| `oz_ad` | debian/redis-tools | 3 | 0 | 0/3 (%0,0; %0,0-%56,1) |
| `oz_ad` | debian/sqlite3 | 7 | 0 | 0/7 (%0,0; %0,0-%35,4) |
| `oz_ad` | debian/tmux | 96 | 80 | 80/96 (%83,3; %74,6-%89,5) |
| `oz_ad` | debian/zstd | 52 | 1 | 1/52 (%1,9; %0,3-%10,1) |
| `oz_ad` | mac/tmux | 126 | 96 | 96/126 (%76,2; %68,0-%82,8) |
| `kebap_ad` | debian/openssl | 2 | 0 | 0/2 (%0,0; %0,0-%65,8) |
| `kebap_ad` | debian/sqlite3 | 1 | 0 | 0/1 (%0,0; %0,0-%79,3) |
| `kebap_ad` | debian/tmux | 115 | 0 | 0/115 (%0,0; %0,0-%3,2) |
| `kebap_ad` | mac/tmux | 148 | 0 | 0/148 (%0,0; %0,0-%2,5) |
| `api_param_reverse` | debian/coreutils | 6 | 0 | 0/6 (%0,0; %0,0-%39,0) |
| `api_param_reverse` | debian/htop | 1 | 0 | 0/1 (%0,0; %0,0-%79,3) |
| `api_param_reverse` | debian/openssl | 4 | 0 | 0/4 (%0,0; %0,0-%49,0) |
| `api_param_reverse` | debian/redis-tools | 11 | 0 | 0/11 (%0,0; %0,0-%25,9) |
| `api_param_reverse` | debian/sqlite3 | 5 | 0 | 0/5 (%0,0; %0,0-%43,5) |
| `api_param_reverse` | debian/tmux | 13 | 0 | 0/13 (%0,0; %0,0-%22,8) |
| `api_param_reverse` | debian/zstd | 3 | 0 | 0/3 (%0,0; %0,0-%56,1) |
| `api_param_reverse` | mac/tmux | 12 | 0 | 0/12 (%0,0; %0,0-%24,2) |

GT fonksiyonunun türü başına (`gt_yok`: o adreste GT fonksiyonu yok; `crt`: bütün adları CRT adı; `klon`: bütün adları derleyici ekli; `export`: dışa aktarılan; `parca`: Mach-O soğuk / dışlanmış parça):

| Grup | GT türü | Ad | Doğru |
|---|---|---|---|
| `on_ad` | `crt` | 458 | 232 |
| `on_ad` | `klon` | 1 | 0 |
| `on_ad` | `program` | 961 | 731 |
| `oz_ad` | `klon` | 23 | 8 |
| `oz_ad` | `program` | 309 | 199 |
| `kebap_ad` | `gt_yok` | 1 | 0 |
| `kebap_ad` | `klon` | 4 | 0 |
| `kebap_ad` | `program` | 261 | 0 |
| `api_param_reverse` | `klon` | 6 | 0 |
| `api_param_reverse` | `program` | 49 | 0 |

## 2. Yanlış sınıfları

Sınıflar sayımdan önce ürün kodu okunarak yazıldı; ilk tutan kazanır. N: ürünün yazdığı ad; R: ham ad (temizlenmeden / çakışma eki eklenmeden önce).

| Sınıf | Tanım |
|---|---|
| `gt_yok` | GT'de o adreste fonksiyon yok (eşlenemeyen adres); ürün yine de ad yazdı |
| `temizleyici_farki` | R ≠ N ve R tek başına doğru hüküm alırdı: ad temizleyici (`_sanitize_c_name`: baştaki/sondaki alt çizgiyi atar, küçük harfe çevirir) doğru adı bozdu |
| `carpisma_eki` | R ≠ N, N = R + `_<sayı>` ve R tek başına doğru hüküm alırdı: çakışma eki doğru adı bozdu (aynı ad ikilide daha önce başka bir anahtara verilmişti) |
| `sonek_farki` | N ya da R, bir GT adının ilk `.` ya da `@`'den sonrası atılmış hâline eşit (hükmün tanımadığı derleyici / sürüm soneki) |
| `harf_altcizgi_farki` | N ya da R ile bir GT adı yalnız büyük/küçük harf ve alfasayısal olmayan karakterlerde ayrışıyor |
| `baska_fonksiyonun_adi` | N ya da R, aynı ikilide BAŞKA bir adresteki GT fonksiyonunun adı (klon tabanı dahil); alt sınıf o fonksiyonla ilişki: `cagrilan`, `cagiran`, `komsu` (adres sırasında bitişik), `uzak` |
| `ice_aktarilan_adi` | N ya da R, ikilinin içe aktardığı (thunk / dış) bir fonksiyonun adı; alt sınıf: bu fonksiyon onu çağırıyor mu |
| `katalog_adi` | N ya da R, tohum kataloglarındaki (gnulib parmak izi, çağrı biçimi, ayrıştırma, ELF önyükü) bir ad, ama ikilinin GT'sinde hiçbir adreste yok (yanlış parmak izi) |
| `onek_sonek_farki` | N'nin belirteç dizisi bir GT adınınkinin başı ya da sonu (ya da tersi): yalnız önek / sonek farkı |
| `ilgisiz` | yukarıdakilerin hiçbiri |

| Sınıf | `on_ad` | `oz_ad` | `kebap_ad` | `api_param_reverse` | Toplam |
|---|---|---|---|---|---|
| `gt_yok` | 0 | 0 | 1 | 0 | 1 |
| `temizleyici_farki` | 226 | 0 | 0 | 0 | 226 |
| `carpisma_eki` | 0 | 8 | 0 | 0 | 8 |
| `sonek_farki` | 0 | 0 | 0 | 0 | 0 |
| `harf_altcizgi_farki` | 0 | 45 | 0 | 0 | 45 |
| `baska_fonksiyonun_adi` | 216 | 17 | 0 | 0 | 233 |
| `ice_aktarilan_adi` | 0 | 1 | 0 | 0 | 1 |
| `katalog_adi` | 15 | 0 | 0 | 0 | 15 |
| `onek_sonek_farki` | 0 | 5 | 8 | 2 | 15 |
| `ilgisiz` | 0 | 49 | 257 | 53 | 359 |
| **Toplam** | 457 | 125 | 266 | 55 | 903 |

Alt sınıflar, program ve GT türü (grup başına; yalnız dolu sınıflar). Sayım örnek düzeyindedir (ikili başına ad): coreutils'in 106 ikilisi aynı kitaplık fonksiyonlarını taşıdığı için tek bir katalog hatası yüzü aşkın kez sayılır; `Tekil ad` sütunu program başına farklı ham ad sayısıdır.

| Grup | Sınıf | n | Tekil ad | Alt sınıf | Program | GT türü | Proje norm. ile doğru |
|---|---|---|---|---|---|---|---|
| `on_ad` | `temizleyici_farki` | 226 | 14 | bas_son_alt_cizgi 226 | coreutils 211, htop 1, openssl 2, redis-tools 4, sqlite3 2, tmux 2, tree 2, zstd 2 | crt 226 | 226 |
| `on_ad` | `baska_fonksiyonun_adi` | 216 | 3 | cagiran 112, uzak 104 | coreutils 216 | program 216 | 0 |
| `on_ad` | `katalog_adi` | 15 | 6 | katalog 15 | coreutils 10, openssl 1, redis-tools 1, tmux 2, zstd 1 | klon 1, program 14 | 0 |
| `oz_ad` | `carpisma_eki` | 8 | 5 | ek 8 | coreutils 4, tmux 4 | program 8 | 8 |
| `oz_ad` | `harf_altcizgi_farki` | 45 | 45 | yalniz_harf 45 | openssl 2, zstd 43 | klon 10, program 35 | 1 |
| `oz_ad` | `baska_fonksiyonun_adi` | 17 | 12 | cagiran 1, cagrilan 3, komsu 1, uzak 12 | coreutils 4, tmux 9, zstd 4 | program 17 | 0 |
| `oz_ad` | `ice_aktarilan_adi` | 1 | 1 | cagirmiyor 1 | openssl 1 | program 1 | 0 |
| `oz_ad` | `onek_sonek_farki` | 5 | 4 | urunde_sonek_fazla 5 | tmux 3, zstd 2 | program 5 | 0 |
| `oz_ad` | `ilgisiz` | 49 | 35 | ilgisiz 49 | coreutils 5, htop 1, openssl 1, redis-tools 3, sqlite3 7, tmux 30, zstd 2 | klon 5, program 44 | 0 |
| `kebap_ad` | `gt_yok` | 1 | 1 | diger 1 | tmux 1 | gt_yok 1 | 0 |
| `kebap_ad` | `onek_sonek_farki` | 8 | 5 | urunde_onek_eksik 8 | tmux 8 | program 8 | 0 |
| `kebap_ad` | `ilgisiz` | 257 | 102 | ilgisiz 257 | openssl 2, sqlite3 1, tmux 254 | klon 4, program 253 | 0 |
| `api_param_reverse` | `onek_sonek_farki` | 2 | 2 | urunde_onek_eksik 1, urunde_onek_fazla 1 | sqlite3 2 | program 2 | 0 |
| `api_param_reverse` | `ilgisiz` | 53 | 13 | ilgisiz 53 | coreutils 6, htop 1, openssl 4, redis-tools 11, sqlite3 3, tmux 25, zstd 3 | klon 6, program 47 | 0 |

## 3. Ön adlar: tür başına

Saklı koşuların köken kaydında tür yazılı değil; tür, ürünün tohum fonksiyonları saklı `static/` çıktısında yeniden çağrılarak bulundu. Yeniden üretim 117 ikilide yapıldı: koşunun kendi sayaçlarıyla 117 ikilide, giriş fonksiyonunun anahtarıyla 117 ikilide tutuyor; türü belirlenemeyen ad 0. Tabloda olmayan türler bu veride ad vermedi: Faz 1 (BinaryNameExtractor, byte pattern, CAPA) ölçüye giren hiçbir `FUN_` anahtarına ad yazmadı, elle verilmiş ad yok.

| Tür | Ad | Doğru | Kesinlik (%95) | Karar | Temizlenmeden yazılsa (%95) | Karar | Program başına (doğru/n) | Yanlış sınıfları |
|---|---|---|---|---|---|---|---|---|
| `elf_onyuk` | 458 | 232 | 232/458 (%50,7; %46,1-%55,2) | `tutmuyor` | 458/458 (%100,0; %99,2-%100,0) | `oneri` | coreutils 212/423, htop 2/3, openssl 2/4, redis-tools 8/12, sqlite3 2/4, tmux 2/4, tree 2/4, zstd 2/4 | temizleyici_farki 226 |
| `gnulib/ayristirma` | 22 | 22 | 22/22 (%100,0; %85,1-%100,0) | `yetersiz` (Wilson alt sınırı < %95; tek program) | 22/22 (%100,0; %85,1-%100,0) | `yetersiz` (Wilson alt sınırı < %95; tek program) | coreutils 22/22 | — |
| `gnulib/cagri_bicimi` | 426 | 311 | 311/426 (%73,0; %68,6-%77,0) | `tutmuyor` | 311/426 (%73,0; %68,6-%77,0) | `tutmuyor` | coreutils 311/424, openssl 0/1, redis-tools 0/1 | baska_fonksiyonun_adi 112, katalog_adi 3 |
| `gnulib/dizgi_parmak_izi` | 404 | 288 | 288/404 (%71,3; %66,7-%75,5) | `tutmuyor` | 288/404 (%71,3; %66,7-%75,5) | `tutmuyor` | coreutils 287/400, tmux 0/2, zstd 1/2 | baska_fonksiyonun_adi 104, katalog_adi 12 |
| `main_giris` | 110 | 110 | 110/110 (%100,0; %96,6-%100,0) | `yetersiz` (tek program) | 110/110 (%100,0; %96,6-%100,0) | `yetersiz` (tek program) | coreutils 105/105, openssl 1/1, sqlite3 1/1, tmux 1/1, tree 1/1, zstd 1/1 | — |

Ana tür (gnulib katmanları birleşik):

| Ana tür | Ad | Doğru | Kesinlik (%95) | Karar | Temizlenmeden yazılsa (%95) | Karar |
|---|---|---|---|---|---|---|
| `elf_onyuk` | 458 | 232 | 232/458 (%50,7; %46,1-%55,2) | `tutmuyor` | 458/458 (%100,0; %99,2-%100,0) | `oneri` |
| `gnulib` | 852 | 621 | 621/852 (%72,9; %69,8-%75,8) | `tutmuyor` | 621/852 (%72,9; %69,8-%75,8) | `tutmuyor` |
| `main_giris` | 110 | 110 | 110/110 (%100,0; %96,6-%100,0) | `yetersiz` (tek program) | 110/110 (%100,0; %96,6-%100,0) | `yetersiz` (tek program) |

Bütün ön adlar temizlenmeden yazılsaydı: 1189/1420 (%83,7; %81,7-%85,6) (`tutmuyor`).

Tür × GT türü (ad sayısı):

| Tür | GT türü dağılımı |
|---|---|
| `elf_onyuk` | crt 458 |
| `gnulib/ayristirma` | program 22 |
| `gnulib/cagri_bicimi` | klon 1, program 425 |
| `gnulib/dizgi_parmak_izi` | program 404 |
| `main_giris` | program 110 |

### Ön ad özellikleri (GT'siz)

| Özellik | Tanım |
|---|---|
| `tur` | ön adın türü (tohum katmanı) |
| `katalog_girdisi` | adı veren katalog girdisinin ürün kodundaki sıra numarası (`GNULIB_FINGERPRINTS[i]`, `GNULIB_CALL_SHAPES[i]`, `GNULIB_DISAMBIGUATORS[i]`, `ELF_BOILERPLATE_SHAPES[i]`) |
| `temizleyici_degistirdi` | ham ad temizlenince değişti mi (R ≠ N) |
| `ikilide_gnulib_dizgi_isabeti` | ikilide dizgi parmak iziyle kurtarılan gnulib adı sayısı: 0 | 1 | 2 | 3+ |
| `ad_ghidra_adli` | ham ad, ikilide Ghidra'nın zaten adlandırdığı bir fonksiyonun adı mı |
| `ks1_capasi` | aynı adreste KS-1 çapası: `yok` | `ayni_ad` | `farkli_ad` |

| Özellik | Değer | Ad | Doğru | Kesinlik (%95) | Kapsam | Doğru adların payı | Program başına | Karar |
|---|---|---|---|---|---|---|---|---|
| `tur` | `elf_onyuk` | 458 | 232 | 232/458 (%50,7; %46,1-%55,2) | %32,3 | %24,1 | coreutils 212/423, htop 2/3, openssl 2/4, redis-tools 8/12, sqlite3 2/4, tmux 2/4, tree 2/4, zstd 2/4 | `tutmuyor` |
| `tur` | `gnulib/ayristirma` | 22 | 22 | 22/22 (%100,0; %85,1-%100,0) | %1,5 | %2,3 | coreutils 22/22 | `yetersiz` (Wilson alt sınırı < %95; tek program) |
| `tur` | `gnulib/cagri_bicimi` | 426 | 311 | 311/426 (%73,0; %68,6-%77,0) | %30,0 | %32,3 | coreutils 311/424, openssl 0/1, redis-tools 0/1 | `tutmuyor` |
| `tur` | `gnulib/dizgi_parmak_izi` | 404 | 288 | 288/404 (%71,3; %66,7-%75,5) | %28,5 | %29,9 | coreutils 287/400, tmux 0/2, zstd 1/2 | `tutmuyor` |
| `tur` | `main_giris` | 110 | 110 | 110/110 (%100,0; %96,6-%100,0) | %7,7 | %11,4 | coreutils 105/105, openssl 1/1, sqlite3 1/1, tmux 1/1, tree 1/1, zstd 1/1 | `yetersiz` (tek program) |
| `katalog_girdisi` | `elf_onyuk#0` | 116 | 116 | 116/116 (%100,0; %96,8-%100,0) | %8,2 | %12,0 | coreutils 106/106, htop 1/1, openssl 1/1, redis-tools 4/4, sqlite3 1/1, tmux 1/1, tree 1/1, zstd 1/1 | `yetersiz` (tek program) |
| `katalog_girdisi` | `elf_onyuk#1` | 116 | 116 | 116/116 (%100,0; %96,8-%100,0) | %8,2 | %12,0 | coreutils 106/106, htop 1/1, openssl 1/1, redis-tools 4/4, sqlite3 1/1, tmux 1/1, tree 1/1, zstd 1/1 | `yetersiz` (tek program) |
| `katalog_girdisi` | `elf_onyuk#2` | 116 | 0 | 0/116 (%0,0; %0,0-%3,2) | %8,2 | %0,0 | coreutils 0/106, htop 0/1, openssl 0/1, redis-tools 0/4, sqlite3 0/1, tmux 0/1, tree 0/1, zstd 0/1 | `tutmuyor` |
| `katalog_girdisi` | `elf_onyuk#3` | 110 | 0 | 0/110 (%0,0; %0,0-%3,4) | %7,7 | %0,0 | coreutils 0/105, openssl 0/1, sqlite3 0/1, tmux 0/1, tree 0/1, zstd 0/1 | `tutmuyor` |
| `katalog_girdisi` | `gnulib/ayristirma#0` | 22 | 22 | 22/22 (%100,0; %85,1-%100,0) | %1,5 | %2,3 | coreutils 22/22 | `yetersiz` (Wilson alt sınırı < %95; tek program) |
| `katalog_girdisi` | `gnulib/cagri_bicimi#0` | 105 | 105 | 105/105 (%100,0; %96,5-%100,0) | %7,4 | %10,9 | coreutils 105/105 | `yetersiz` (tek program) |
| `katalog_girdisi` | `gnulib/cagri_bicimi#1` | 104 | 0 | 0/104 (%0,0; %0,0-%3,6) | %7,3 | %0,0 | coreutils 0/104 | `tutmuyor` |
| `katalog_girdisi` | `gnulib/cagri_bicimi#2` | 11 | 0 | 0/11 (%0,0; %0,0-%25,9) | %0,8 | %0,0 | coreutils 0/9, openssl 0/1, redis-tools 0/1 | `tutmuyor` |
| `katalog_girdisi` | `gnulib/cagri_bicimi#3` | 105 | 105 | 105/105 (%100,0; %96,5-%100,0) | %7,4 | %10,9 | coreutils 105/105 | `yetersiz` (tek program) |
| `katalog_girdisi` | `gnulib/cagri_bicimi#5` | 101 | 101 | 101/101 (%100,0; %96,3-%100,0) | %7,1 | %10,5 | coreutils 101/101 | `yetersiz` (tek program) |
| `katalog_girdisi` | `gnulib/dizgi_parmak_izi#0` | 104 | 0 | 0/104 (%0,0; %0,0-%3,6) | %7,3 | %0,0 | coreutils 0/104 | `tutmuyor` |
| `katalog_girdisi` | `gnulib/dizgi_parmak_izi#1` | 98 | 98 | 98/98 (%100,0; %96,2-%100,0) | %6,9 | %10,2 | coreutils 98/98 | `yetersiz` (tek program) |
| `katalog_girdisi` | `gnulib/dizgi_parmak_izi#2` | 86 | 83 | 83/86 (%96,5; %90,2-%98,8) | %6,1 | %8,6 | coreutils 83/83, tmux 0/2, zstd 0/1 | `yetersiz` (Wilson alt sınırı < %95; tek program) |
| `katalog_girdisi` | `gnulib/dizgi_parmak_izi#4` | 9 | 0 | 0/9 (%0,0; %0,0-%29,9) | %0,6 | %0,0 | coreutils 0/9 | `tutmuyor` |
| `katalog_girdisi` | `gnulib/dizgi_parmak_izi#5` | 5 | 5 | 5/5 (%100,0; %56,5-%100,0) | %0,4 | %0,5 | coreutils 5/5 | `yetersiz` (Wilson alt sınırı < %95; tek program) |
| `katalog_girdisi` | `gnulib/dizgi_parmak_izi#6` | 102 | 102 | 102/102 (%100,0; %96,4-%100,0) | %7,2 | %10,6 | coreutils 101/101, zstd 1/1 | `yetersiz` (tek program) |
| `katalog_girdisi` | `main_giris#-` | 110 | 110 | 110/110 (%100,0; %96,6-%100,0) | %7,7 | %11,4 | coreutils 105/105, openssl 1/1, sqlite3 1/1, tmux 1/1, tree 1/1, zstd 1/1 | `yetersiz` (tek program) |
| `temizleyici_degistirdi` | `evet` | 226 | 0 | 0/226 (%0,0; %0,0-%1,7) | %15,9 | %0,0 | coreutils 0/211, htop 0/1, openssl 0/2, redis-tools 0/4, sqlite3 0/2, tmux 0/2, tree 0/2, zstd 0/2 | `tutmuyor` |
| `temizleyici_degistirdi` | `hayir` | 1194 | 963 | 963/1194 (%80,7; %78,3-%82,8) | %84,1 | %100,0 | coreutils 937/1163, htop 2/2, openssl 3/4, redis-tools 8/9, sqlite3 3/3, tmux 3/5, tree 3/3, zstd 4/5 | `tutmuyor` |
| `ikilide_gnulib_dizgi_isabeti` | `0` | 35 | 21 | 21/35 (%60,0; %43,6-%74,5) | %2,5 | %2,2 | coreutils 2/3, htop 2/3, openssl 3/6, redis-tools 8/13, sqlite3 3/5, tree 3/5 | `tutmuyor` |
| `ikilide_gnulib_dizgi_isabeti` | `1` | 7 | 3 | 3/7 (%42,9; %15,8-%75,0) | %0,5 | %0,3 | tmux 3/7 | `tutmuyor` |
| `ikilide_gnulib_dizgi_isabeti` | `2` | 42 | 28 | 28/42 (%66,7; %51,5-%79,0) | %3,0 | %2,9 | coreutils 24/35, zstd 4/7 | `tutmuyor` |
| `ikilide_gnulib_dizgi_isabeti` | `3+` | 1336 | 911 | 911/1336 (%68,2; %65,6-%70,6) | %94,1 | %94,6 | coreutils 911/1336 | `tutmuyor` |
| `ad_ghidra_adli` | `hayir` | 1420 | 963 | 963/1420 (%67,8; %65,3-%70,2) | %100,0 | %100,0 | coreutils 937/1374, htop 2/3, openssl 3/6, redis-tools 8/13, sqlite3 3/5, tmux 3/7, tree 3/5, zstd 4/7 | `tutmuyor` |
| `ks1_capasi` | `ayni_ad` | 1 | 1 | 1/1 (%100,0; %20,6-%100,0) | %0,1 | %0,1 | coreutils 1/1 | `yetersiz` (Wilson alt sınırı < %95; tek program) |
| `ks1_capasi` | `farkli_ad` | 4 | 4 | 4/4 (%100,0; %51,0-%100,0) | %0,3 | %0,4 | coreutils 4/4 | `yetersiz` (Wilson alt sınırı < %95; tek program) |
| `ks1_capasi` | `yok` | 1415 | 958 | 958/1415 (%67,7; %65,2-%70,1) | %99,6 | %99,5 | coreutils 932/1369, htop 2/3, openssl 3/6, redis-tools 8/13, sqlite3 3/5, tmux 3/7, tree 3/5, zstd 4/7 | `tutmuyor` |

Katalog girdisi başına, ad temizlenmeden yazılsaydı:

| Katalog girdisi | Ad | Doğru (ham adla) | Kesinlik (%95) | Program başına | Karar |
|---|---|---|---|---|---|
| `elf_onyuk#0` | 116 | 116 | 116/116 (%100,0; %96,8-%100,0) | coreutils 106/106, htop 1/1, openssl 1/1, redis-tools 4/4, sqlite3 1/1, tmux 1/1, tree 1/1, zstd 1/1 | `yetersiz` (tek program) |
| `elf_onyuk#1` | 116 | 116 | 116/116 (%100,0; %96,8-%100,0) | coreutils 106/106, htop 1/1, openssl 1/1, redis-tools 4/4, sqlite3 1/1, tmux 1/1, tree 1/1, zstd 1/1 | `yetersiz` (tek program) |
| `elf_onyuk#2` | 116 | 116 | 116/116 (%100,0; %96,8-%100,0) | coreutils 106/106, htop 1/1, openssl 1/1, redis-tools 4/4, sqlite3 1/1, tmux 1/1, tree 1/1, zstd 1/1 | `yetersiz` (tek program) |
| `elf_onyuk#3` | 110 | 110 | 110/110 (%100,0; %96,6-%100,0) | coreutils 105/105, openssl 1/1, sqlite3 1/1, tmux 1/1, tree 1/1, zstd 1/1 | `yetersiz` (tek program) |
| `gnulib/ayristirma#0` | 22 | 22 | 22/22 (%100,0; %85,1-%100,0) | coreutils 22/22 | `yetersiz` (Wilson alt sınırı < %95; tek program) |
| `gnulib/cagri_bicimi#0` | 105 | 105 | 105/105 (%100,0; %96,5-%100,0) | coreutils 105/105 | `yetersiz` (tek program) |
| `gnulib/cagri_bicimi#1` | 104 | 0 | 0/104 (%0,0; %0,0-%3,6) | coreutils 0/104 | `tutmuyor` |
| `gnulib/cagri_bicimi#2` | 11 | 0 | 0/11 (%0,0; %0,0-%25,9) | coreutils 0/9, openssl 0/1, redis-tools 0/1 | `tutmuyor` |
| `gnulib/cagri_bicimi#3` | 105 | 105 | 105/105 (%100,0; %96,5-%100,0) | coreutils 105/105 | `yetersiz` (tek program) |
| `gnulib/cagri_bicimi#5` | 101 | 101 | 101/101 (%100,0; %96,3-%100,0) | coreutils 101/101 | `yetersiz` (tek program) |
| `gnulib/dizgi_parmak_izi#0` | 104 | 0 | 0/104 (%0,0; %0,0-%3,6) | coreutils 0/104 | `tutmuyor` |
| `gnulib/dizgi_parmak_izi#1` | 98 | 98 | 98/98 (%100,0; %96,2-%100,0) | coreutils 98/98 | `yetersiz` (tek program) |
| `gnulib/dizgi_parmak_izi#2` | 86 | 83 | 83/86 (%96,5; %90,2-%98,8) | coreutils 83/83, tmux 0/2, zstd 0/1 | `yetersiz` (Wilson alt sınırı < %95; tek program) |
| `gnulib/dizgi_parmak_izi#4` | 9 | 0 | 0/9 (%0,0; %0,0-%29,9) | coreutils 0/9 | `tutmuyor` |
| `gnulib/dizgi_parmak_izi#5` | 5 | 5 | 5/5 (%100,0; %56,5-%100,0) | coreutils 5/5 | `yetersiz` (Wilson alt sınırı < %95; tek program) |
| `gnulib/dizgi_parmak_izi#6` | 102 | 102 | 102/102 (%100,0; %96,4-%100,0) | coreutils 101/101, zstd 1/1 | `yetersiz` (tek program) |
| `main_giris#-` | 110 | 110 | 110/110 (%100,0; %96,6-%100,0) | coreutils 105/105, openssl 1/1, sqlite3 1/1, tmux 1/1, tree 1/1, zstd 1/1 | `yetersiz` (tek program) |

Sonradan eklenen koşullar (tür tablosu görüldükten sonra; gnulib adları):

| Koşul | Ad | Doğru | Kesinlik (%95) | Kapsam | Program başına | Karar |
|---|---|---|---|---|---|---|
| gnulib adı ve ikilide dizgi parmak izi isabeti 3+. | 826 | 605 | 605/826 (%73,2; %70,1-%76,1) | %58,2 | coreutils 605/826 | `tutmuyor` |
| gnulib adı ve ikilide dizgi parmak izi isabeti 3+ değil. | 26 | 16 | 16/26 (%61,5; %42,5-%77,6) | %1,8 | coreutils 15/20, openssl 0/1, redis-tools 0/1, tmux 0/2, zstd 1/2 | `tutmuyor` |
| gnulib adı; bu veride n ≥ 10 iken hiç doğru vermeyen katalog girdileri hariç (girdi seçimi aynı veride). Hariç tutulan: `gnulib/cagri_bicimi#1`, `gnulib/cagri_bicimi#2`, `gnulib/dizgi_parmak_izi#0`. | 633 | 621 | 621/633 (%98,1; %96,7-%98,9) | %44,6 | coreutils 620/629, tmux 0/2, zstd 1/2 | `yetersiz` (tek program) |
| gnulib adı; hiç doğru vermeyen katalog girdileri hariç ve ikilide dizgi parmak izi isabeti 3+ (girdi seçimi aynı veride). Hariç tutulan: `gnulib/cagri_bicimi#1`, `gnulib/cagri_bicimi#2`, `gnulib/dizgi_parmak_izi#0`. | 614 | 605 | 605/614 (%98,5; %97,2-%99,2) | %43,2 | coreutils 605/614 | `yetersiz` (tek program) |

## 4. `oz_ad`: kesinliği ayıran GT'siz özellikler

| Özellik | Tanım |
|---|---|
| `kanit_kaynagi` | kanıt dizgisi nereden okundu: `string_ref` (dizgi tablosu) | `body_literal` |
| `carpisma_eki` | ada çakışma eki eklendi mi (aynı ad ikilide daha önce verilmişti) |
| `dizgiyi_kullanan_fonksiyon` | kanıt dizgisini (aynı değer) kullanan fonksiyon sayısı (`ghidra_xrefs`): 0 | 1 | 2 | 3+ |
| `ayni_adi_oneren_fonksiyon` | ikilide aynı ham adı kazanan aday olarak alan fonksiyon sayısı: 1 | 2+ |
| `govdede_gecis` | kanıt dizgisinin fonksiyonun ham decompile gövdesinde literal olarak geçiş sayısı: 0 | 1 | 2+ |
| `cagri_argumani` | ilk geçişin yeri: `arg<k>/<ic|dis>` (çağrının k. argümanı; çağrılan `FUN_` ise ic) | `cagri_disi` | `govdede_yok` |
| `oz_ad_bicimli_dizgi` | fonksiyonun kullandığı, oz_ad biçimli (alt çizgili, küçük harfli tanımlayıcı) farklı dizgi sayısı: 1 | 2 | 3+ |
| `fonksiyonun_dizgi_sayisi` | fonksiyonun kullandığı dizgi sayısı (`strings_used`): 0 | 1 | 2-3 | 4+ |
| `ad_ghidra_adli` | ham ad, ikilide Ghidra'nın zaten adlandırdığı bir fonksiyonun (içe/dışa aktarım) adı mı |
| `dizgide_buyuk_harf` | kanıt dizgisinde büyük harf var mı (ad küçük harfe çevrildi) |
| `ikili_adi_onekli` | ham adın ilk belirteci ikili ya da program adının ilk belirtecine eşit mi |
| `ks1_capasi` | aynı adreste KS-1 çapası: `yok` | `ayni_ad` | `farkli_ad` (dizgi türü çapalar; parça dahil) |
| `aday_sayisi` | anahtarın aday sayısı (`n_candidates`): 1 | 2 | 3+ |

`oz_ad` adı, kanıt dizgisinin küçük harfe çevrilmiş hâlidir (gerekirse çakışma ekiyle). "Kanıt dizgisi olduğu gibi yazılsa" sütunu, aynı adlar için dizginin kendisi (özgün harfler, eksiz) yazılsaydı alınacak hükümdür (dönüşüm; GT'siz uygulanabilir).

| Özellik | Değer | Ad | Doğru | Kesinlik (%95) | Kanıt dizgisi olduğu gibi yazılsa (%95) | Kapsam | Doğru adların payı | Program başına (doğru / dönüşümle doğru / n) | Karar | Karar (dönüşümle) |
|---|---|---|---|---|---|---|---|---|---|---|
| `kanit_kaynagi` | `body_literal` | 8 | 0 | 0/8 (%0,0; %0,0-%32,4) | 1/8 (%12,5; %2,2-%47,1) | %2,4 | %0,0 | coreutils 0/0/4, openssl 0/0/1, tmux 0/0/1, zstd 0/1/2 | `tutmuyor` | `tutmuyor` |
| `kanit_kaynagi` | `string_ref` | 324 | 207 | 207/324 (%63,9; %58,5-%68,9) | 259/324 (%79,9; %75,2-%83,9) | %97,6 | %100,0 | coreutils 27/31/36, htop 0/0/1, openssl 3/5/6, redis-tools 0/0/3, sqlite3 0/0/7, tmux 176/180/221, zstd 1/43/50 | `tutmuyor` | `tutmuyor` |
| `carpisma_eki` | `evet` | 22 | 0 | 0/22 (%0,0; %0,0-%14,9) | 9/22 (%40,9; %23,3-%61,3) | %6,6 | %0,0 | coreutils 0/4/4, openssl 0/0/1, sqlite3 0/0/2, tmux 0/4/12, zstd 0/1/3 | `tutmuyor` | `tutmuyor` |
| `carpisma_eki` | `hayir` | 310 | 207 | 207/310 (%66,8; %61,4-%71,8) | 251/310 (%81,0; %76,2-%85,0) | %93,4 | %100,0 | coreutils 27/27/36, htop 0/0/1, openssl 3/5/6, redis-tools 0/0/3, sqlite3 0/0/5, tmux 176/176/210, zstd 1/43/49 | `tutmuyor` | `tutmuyor` |
| `dizgiyi_kullanan_fonksiyon` | `0` | 2 | 0 | 0/2 (%0,0; %0,0-%65,8) | 1/2 (%50,0; %9,4-%90,5) | %0,6 | %0,0 | openssl 0/0/1, zstd 0/1/1 | `tutmuyor` | `tutmuyor` |
| `dizgiyi_kullanan_fonksiyon` | `1` | 291 | 199 | 199/291 (%68,4; %62,8-%73,5) | 248/291 (%85,2; %80,7-%88,8) | %87,7 | %96,1 | coreutils 27/31/40, htop 0/0/1, openssl 3/5/5, redis-tools 0/0/1, sqlite3 0/0/2, tmux 168/172/198, zstd 1/40/44 | `tutmuyor` | `tutmuyor` |
| `dizgiyi_kullanan_fonksiyon` | `2` | 27 | 8 | 8/27 (%29,6; %15,8-%48,5) | 10/27 (%37,0; %21,5-%55,8) | %8,1 | %3,9 | openssl 0/0/1, sqlite3 0/0/3, tmux 8/8/20, zstd 0/2/3 | `tutmuyor` | `tutmuyor` |
| `dizgiyi_kullanan_fonksiyon` | `3+` | 12 | 0 | 0/12 (%0,0; %0,0-%24,2) | 1/12 (%8,3; %1,5-%35,4) | %3,6 | %0,0 | redis-tools 0/0/2, sqlite3 0/0/2, tmux 0/0/4, zstd 0/1/4 | `tutmuyor` | `tutmuyor` |
| `ayni_adi_oneren_fonksiyon` | `1` | 295 | 200 | 200/295 (%67,8; %62,3-%72,9) | 243/295 (%82,4; %77,6-%86,3) | %88,9 | %96,6 | coreutils 27/27/35, htop 0/0/1, openssl 3/5/6, redis-tools 0/0/3, sqlite3 0/0/3, tmux 169/169/200, zstd 1/42/47 | `tutmuyor` | `tutmuyor` |
| `ayni_adi_oneren_fonksiyon` | `2+` | 37 | 7 | 7/37 (%18,9; %9,5-%34,2) | 17/37 (%45,9; %31,0-%61,6) | %11,1 | %3,4 | coreutils 0/4/5, openssl 0/0/1, sqlite3 0/0/4, tmux 7/11/22, zstd 0/2/5 | `tutmuyor` | `tutmuyor` |
| `govdede_gecis` | `0` | 76 | 62 | 62/76 (%81,6; %71,4-%88,7) | 64/76 (%84,2; %74,4-%90,7) | %22,9 | %30,0 | coreutils 0/0/2, sqlite3 0/0/1, tmux 62/64/72, zstd 0/0/1 | `tutmuyor` | `tutmuyor` |
| `govdede_gecis` | `1` | 196 | 110 | 110/196 (%56,1; %49,1-%62,9) | 147/196 (%75,0; %68,5-%80,5) | %59,0 | %53,1 | coreutils 18/19/23, htop 0/0/1, openssl 2/2/4, redis-tools 0/0/3, sqlite3 0/0/6, tmux 89/91/120, zstd 1/35/39 | `tutmuyor` | `tutmuyor` |
| `govdede_gecis` | `2+` | 60 | 35 | 35/60 (%58,3; %45,7-%69,9) | 49/60 (%81,7; %70,1-%89,4) | %18,1 | %16,9 | coreutils 9/12/15, openssl 1/3/3, tmux 25/25/30, zstd 0/9/12 | `tutmuyor` | `tutmuyor` |
| `cagri_argumani` | `arg0/dis` | 7 | 1 | 1/7 (%14,3; %2,6-%51,3) | 1/7 (%14,3; %2,6-%51,3) | %2,1 | %0,5 | coreutils 0/0/3, redis-tools 0/0/2, sqlite3 0/0/1, tmux 1/1/1 | `tutmuyor` | `tutmuyor` |
| `cagri_argumani` | `arg0/ic` | 4 | 0 | 0/4 (%0,0; %0,0-%49,0) | 0/4 (%0,0; %0,0-%49,0) | %1,2 | %0,0 | tmux 0/0/4 | `tutmuyor` | `tutmuyor` |
| `cagri_argumani` | `arg1/dis` | 6 | 0 | 0/6 (%0,0; %0,0-%39,0) | 0/6 (%0,0; %0,0-%39,0) | %1,8 | %0,0 | htop 0/0/1, sqlite3 0/0/5 | `tutmuyor` | `tutmuyor` |
| `cagri_argumani` | `arg1/ic` | 105 | 75 | 75/105 (%71,4; %62,2-%79,2) | 76/105 (%72,4; %63,1-%80,0) | %31,6 | %36,2 | redis-tools 0/0/1, tmux 75/76/104 | `tutmuyor` | `tutmuyor` |
| `cagri_argumani` | `arg2+/dis` | 88 | 31 | 31/88 (%35,2; %26,1-%45,6) | 80/88 (%90,9; %83,1-%95,3) | %26,5 | %15,0 | coreutils 27/31/32, openssl 3/5/5, zstd 1/44/51 | `tutmuyor` | `tutmuyor` |
| `cagri_argumani` | `arg2+/ic` | 39 | 36 | 36/39 (%92,3; %79,7-%97,4) | 37/39 (%94,9; %83,1-%98,6) | %11,7 | %17,4 | openssl 0/0/1, tmux 36/37/38 | `tutmuyor` | `tutmuyor` |
| `cagri_argumani` | `cagri_disi` | 7 | 2 | 2/7 (%28,6; %8,2-%64,1) | 2/7 (%28,6; %8,2-%64,1) | %2,1 | %1,0 | coreutils 0/0/3, openssl 0/0/1, tmux 2/2/3 | `tutmuyor` | `tutmuyor` |
| `cagri_argumani` | `govdede_yok` | 76 | 62 | 62/76 (%81,6; %71,4-%88,7) | 64/76 (%84,2; %74,4-%90,7) | %22,9 | %30,0 | coreutils 0/0/2, sqlite3 0/0/1, tmux 62/64/72, zstd 0/0/1 | `tutmuyor` | `tutmuyor` |
| `oz_ad_bicimli_dizgi` | `1` | 283 | 193 | 193/283 (%68,2; %62,6-%73,4) | 244/283 (%86,2; %81,7-%89,8) | %85,2 | %93,2 | coreutils 25/29/35, htop 0/0/1, openssl 3/5/5, redis-tools 0/0/3, sqlite3 0/0/4, tmux 164/168/187, zstd 1/42/48 | `tutmuyor` | `tutmuyor` |
| `oz_ad_bicimli_dizgi` | `2` | 25 | 9 | 9/25 (%36,0; %20,2-%55,5) | 11/25 (%44,0; %26,7-%62,9) | %7,5 | %4,3 | coreutils 2/2/5, openssl 0/0/2, sqlite3 0/0/3, tmux 7/7/13, zstd 0/2/2 | `tutmuyor` | `tutmuyor` |
| `oz_ad_bicimli_dizgi` | `3+` | 24 | 5 | 5/24 (%20,8; %9,2-%40,5) | 5/24 (%20,8; %9,2-%40,5) | %7,2 | %2,4 | tmux 5/5/22, zstd 0/0/2 | `tutmuyor` | `tutmuyor` |
| `fonksiyonun_dizgi_sayisi` | `0` | 4 | 0 | 0/4 (%0,0; %0,0-%49,0) | 0/4 (%0,0; %0,0-%49,0) | %1,2 | %0,0 | coreutils 0/0/3, zstd 0/0/1 | `tutmuyor` | `tutmuyor` |
| `fonksiyonun_dizgi_sayisi` | `1` | 56 | 45 | 45/56 (%80,4; %68,2-%88,7) | 46/56 (%82,1; %70,2-%90,0) | %16,9 | %21,7 | coreutils 0/0/1, htop 0/0/1, redis-tools 0/0/2, sqlite3 0/0/3, tmux 45/45/48, zstd 0/1/1 | `tutmuyor` | `tutmuyor` |
| `fonksiyonun_dizgi_sayisi` | `2-3` | 163 | 116 | 116/163 (%71,2; %63,8-%77,6) | 146/163 (%89,6; %83,9-%93,4) | %49,1 | %56,0 | coreutils 15/16/16, openssl 3/5/5, redis-tools 0/0/1, sqlite3 0/0/4, tmux 97/99/109, zstd 1/26/28 | `tutmuyor` | `tutmuyor` |
| `fonksiyonun_dizgi_sayisi` | `4+` | 109 | 46 | 46/109 (%42,2; %33,4-%51,6) | 68/109 (%62,4; %53,0-%70,9) | %32,8 | %22,2 | coreutils 12/15/20, openssl 0/0/2, tmux 34/36/65, zstd 0/17/22 | `tutmuyor` | `tutmuyor` |
| `ad_ghidra_adli` | `hayir` | 332 | 207 | 207/332 (%62,3; %57,0-%67,4) | 260/332 (%78,3; %73,6-%82,4) | %100,0 | %100,0 | coreutils 27/31/40, htop 0/0/1, openssl 3/5/7, redis-tools 0/0/3, sqlite3 0/0/7, tmux 176/180/222, zstd 1/44/52 | `tutmuyor` | `tutmuyor` |
| `dizgide_buyuk_harf` | `evet` | 56 | 0 | 0/56 (%0,0; %0,0-%6,4) | 45/56 (%80,4; %68,2-%88,7) | %16,9 | %0,0 | coreutils 0/0/2, openssl 0/2/3, zstd 0/43/51 | `tutmuyor` | `tutmuyor` |
| `dizgide_buyuk_harf` | `hayir` | 276 | 207 | 207/276 (%75,0; %69,6-%79,7) | 215/276 (%77,9; %72,6-%82,4) | %83,1 | %100,0 | coreutils 27/31/38, htop 0/0/1, openssl 3/3/4, redis-tools 0/0/3, sqlite3 0/0/7, tmux 176/180/222, zstd 1/1/1 | `tutmuyor` | `tutmuyor` |
| `ikili_adi_onekli` | `evet` | 28 | 1 | 1/28 (%3,6; %0,6-%17,7) | 22/28 (%78,6; %60,5-%89,8) | %8,4 | %0,5 | coreutils 1/2/3, zstd 0/20/25 | `tutmuyor` | `tutmuyor` |
| `ikili_adi_onekli` | `hayir` | 304 | 206 | 206/304 (%67,8; %62,3-%72,8) | 238/304 (%78,3; %73,3-%82,6) | %91,6 | %99,5 | coreutils 26/29/37, htop 0/0/1, openssl 3/5/7, redis-tools 0/0/3, sqlite3 0/0/7, tmux 176/180/222, zstd 1/24/27 | `tutmuyor` | `tutmuyor` |
| `ks1_capasi` | `ayni_ad` | 129 | 122 | 122/129 (%94,6; %89,2-%97,4) | 127/129 (%98,4; %94,5-%99,6) | %38,9 | %58,9 | coreutils 24/25/25, tmux 98/102/104 | `tutmuyor` | `yetersiz` (Wilson alt sınırı < %95) |
| `ks1_capasi` | `farkli_ad` | 39 | 0 | 0/39 (%0,0; %0,0-%9,0) | 30/39 (%76,9; %61,7-%87,4) | %11,7 | %0,0 | coreutils 0/0/3, tmux 0/0/4, zstd 0/30/32 | `tutmuyor` | `tutmuyor` |
| `ks1_capasi` | `yok` | 164 | 85 | 85/164 (%51,8; %44,2-%59,4) | 103/164 (%62,8; %55,2-%69,8) | %49,4 | %41,1 | coreutils 3/6/12, htop 0/0/1, openssl 3/5/7, redis-tools 0/0/3, sqlite3 0/0/7, tmux 78/78/114, zstd 1/14/20 | `tutmuyor` | `tutmuyor` |
| `aday_sayisi` | `1` | 25 | 23 | 23/25 (%92,0; %75,0-%97,8) | 23/25 (%92,0; %75,0-%97,8) | %7,5 | %11,1 | tmux 23/23/25 | `tutmuyor` | `tutmuyor` |
| `aday_sayisi` | `2` | 87 | 69 | 69/87 (%79,3; %69,7-%86,5) | 77/87 (%88,5; %80,1-%93,6) | %26,2 | %33,3 | coreutils 13/13/13, sqlite3 0/0/2, tmux 56/58/65, zstd 0/6/7 | `tutmuyor` | `tutmuyor` |
| `aday_sayisi` | `3+` | 220 | 115 | 115/220 (%52,3; %45,7-%58,8) | 160/220 (%72,7; %66,5-%78,2) | %66,3 | %55,6 | coreutils 14/18/27, htop 0/0/1, openssl 3/5/7, redis-tools 0/0/3, sqlite3 0/0/5, tmux 97/99/132, zstd 1/38/45 | `tutmuyor` | `tutmuyor` |

Bileşik koşullar (önceden yazılmış):

| Bileşik | Koşul | Ad | Doğru | Kesinlik (%95) | Kanıt dizgisi olduğu gibi yazılsa (%95) | Kapsam | Doğru adların payı | Program başına (doğru / dönüşümle doğru / n) | Karar | Karar (dönüşümle) |
|---|---|---|---|---|---|---|---|---|---|---|
| `tek_fonksiyon_ve_eksiz` | `dizgiyi_kullanan_fonksiyon` ∈ {1} ve `carpisma_eki` ∈ {hayir} | 282 | 199 | 199/282 (%70,6; %65,0-%75,6) | 239/282 (%84,8; %80,1-%88,5) | %84,9 | %96,1 | coreutils 27/27/36, htop 0/0/1, openssl 3/5/5, redis-tools 0/0/1, sqlite3 0/0/2, tmux 168/168/194, zstd 1/39/43 | `tutmuyor` | `tutmuyor` |
| `tek_fonksiyon_ve_tek_oz_ad_dizgisi` | `dizgiyi_kullanan_fonksiyon` ∈ {1} ve `oz_ad_bicimli_dizgi` ∈ {1} ve `carpisma_eki` ∈ {hayir} | 242 | 185 | 185/242 (%76,4; %70,7-%81,3) | 224/242 (%92,6; %88,5-%95,2) | %72,9 | %89,4 | coreutils 25/25/31, htop 0/0/1, openssl 3/5/5, redis-tools 0/0/1, tmux 156/156/164, zstd 1/38/40 | `tutmuyor` | `tutmuyor` |
| `ks1_ayni_ad` | `ks1_capasi` ∈ {ayni_ad} | 129 | 122 | 122/129 (%94,6; %89,2-%97,4) | 127/129 (%98,4; %94,5-%99,6) | %38,9 | %58,9 | coreutils 24/25/25, tmux 98/102/104 | `tutmuyor` | `yetersiz` (Wilson alt sınırı < %95) |
| `ks1_yok_ve_tek_fonksiyon` | `ks1_capasi` ∈ {yok} ve `dizgiyi_kullanan_fonksiyon` ∈ {1} ve `carpisma_eki` ∈ {hayir} | 119 | 77 | 77/119 (%64,7; %55,8-%72,7) | 87/119 (%73,1; %64,5-%80,3) | %35,8 | %37,2 | coreutils 3/3/9, htop 0/0/1, openssl 3/5/5, redis-tools 0/0/1, sqlite3 0/0/2, tmux 70/70/90, zstd 1/9/11 | `tutmuyor` | `tutmuyor` |
| `ks1_yok` | `ks1_capasi` ∈ {yok} | 164 | 85 | 85/164 (%51,8; %44,2-%59,4) | 103/164 (%62,8; %55,2-%69,8) | %49,4 | %41,1 | coreutils 3/6/12, htop 0/0/1, openssl 3/5/7, redis-tools 0/0/3, sqlite3 0/0/7, tmux 78/78/114, zstd 1/14/20 | `tutmuyor` | `tutmuyor` |

Bileşik koşullar (SONRADAN: tek özellik tabloları görüldükten sonra yazıldı; aynı veride seçildi):

| Bileşik | Koşul | Ad | Doğru | Kesinlik (%95) | Kanıt dizgisi olduğu gibi yazılsa (%95) | Kapsam | Doğru adların payı | Program başına (doğru / dönüşümle doğru / n) | Karar | Karar (dönüşümle) |
|---|---|---|---|---|---|---|---|---|---|---|
| `tek_tek_eksiz_ve_ks1_yok` | `dizgiyi_kullanan_fonksiyon` ∈ {1} ve `oz_ad_bicimli_dizgi` ∈ {1} ve `carpisma_eki` ∈ {hayir} ve `ks1_capasi` ∈ {yok} | 94 | 70 | 70/94 (%74,5; %64,8-%82,2) | 80/94 (%85,1; %76,5-%90,9) | %28,3 | %33,8 | coreutils 1/1/7, htop 0/0/1, openssl 3/5/5, redis-tools 0/0/1, tmux 65/65/71, zstd 1/9/9 | `tutmuyor` | `tutmuyor` |
| `tek_tek_eksiz_ve_az_dizgi` | `dizgiyi_kullanan_fonksiyon` ∈ {1} ve `oz_ad_bicimli_dizgi` ∈ {1} ve `carpisma_eki` ∈ {hayir} ve `fonksiyonun_dizgi_sayisi` ∈ {1, 2-3} | 186 | 151 | 151/186 (%81,2; %75,0-%86,2) | 176/186 (%94,6; %90,4-%97,0) | %56,0 | %72,9 | coreutils 15/15/16, htop 0/0/1, openssl 3/5/5, redis-tools 0/0/1, tmux 132/132/139, zstd 1/24/24 | `tutmuyor` | `tutmuyor` |
| `sonraki_arguman` | `cagri_argumani` ∈ {arg1/ic, arg2+/dis, arg2+/ic} | 232 | 142 | 142/232 (%61,2; %54,8-%67,2) | 193/232 (%83,2; %77,8-%87,5) | %69,9 | %68,6 | coreutils 27/31/32, openssl 3/5/6, redis-tools 0/0/1, tmux 111/113/142, zstd 1/44/51 | `tutmuyor` | `tutmuyor` |
| `sonraki_arguman_ve_ks1_yok` | `cagri_argumani` ∈ {arg1/ic, arg2+/dis, arg2+/ic} ve `ks1_capasi` ∈ {yok} | 123 | 70 | 70/123 (%56,9; %48,1-%65,3) | 88/123 (%71,5; %63,0-%78,8) | %37,0 | %33,8 | coreutils 3/6/7, openssl 3/5/6, redis-tools 0/0/1, tmux 63/63/90, zstd 1/14/19 | `tutmuyor` | `tutmuyor` |
| `tek_tek_eksiz_ve_sonraki_arguman` | `dizgiyi_kullanan_fonksiyon` ∈ {1} ve `oz_ad_bicimli_dizgi` ∈ {1} ve `carpisma_eki` ∈ {hayir} ve `cagri_argumani` ∈ {arg1/ic, arg2+/dis, arg2+/ic} | 172 | 127 | 127/172 (%73,8; %66,8-%79,8) | 166/172 (%96,5; %92,6-%98,4) | %51,8 | %61,4 | coreutils 25/25/26, openssl 3/5/5, redis-tools 0/0/1, tmux 98/98/100, zstd 1/38/40 | `tutmuyor` | `yetersiz` (Wilson alt sınırı < %95) |
| `tek_tek_eksiz_ve_sonraki_arguman_ve_ks1_yok` | `dizgiyi_kullanan_fonksiyon` ∈ {1} ve `oz_ad_bicimli_dizgi` ∈ {1} ve `carpisma_eki` ∈ {hayir} ve `cagri_argumani` ∈ {arg1/ic, arg2+/dis, arg2+/ic} ve `ks1_capasi` ∈ {yok} | 73 | 60 | 60/73 (%82,2; %71,9-%89,3) | 70/73 (%95,9; %88,6-%98,6) | %22,0 | %29,0 | coreutils 1/1/2, openssl 3/5/5, redis-tools 0/0/1, tmux 55/55/56, zstd 1/9/9 | `tutmuyor` | `yetersiz` (Wilson alt sınırı < %95; tek program) |

Bütün kanal için dönüşümler (karşı olgu):

| Dönüşüm | Doğru olurdu (%95) | Program başına | Karar |
|---|---|---|---|
| karşı olgu: ad küçük harfe çevrilmeden ve çakışma eki eklenmeden, kanıt dizgisi olduğu gibi yazılsaydı | 260/332 (%78,3; %73,6-%82,4) | coreutils 31/40, htop 0/1, openssl 5/7, redis-tools 0/3, sqlite3 0/7, tmux 180/222, zstd 44/52 | `tutmuyor` |
| karşı olgu: yalnız çakışma eki eklenmeseydi (küçük harf kalır) | 215/332 (%64,8; %59,5-%69,7) | coreutils 31/40, htop 0/1, openssl 3/7, redis-tools 0/3, sqlite3 0/7, tmux 180/222, zstd 1/52 | `tutmuyor` |

### KS-1'den sonra `oz_ad`'a kalan kısım (SONRADAN eklenen katmanlama)

KS-1 ön adı `oz_ad` adayının önüne geçer. Aynı adreste KS-1 çapası olan `oz_ad` adlarında KS-1 adının hükmü: çapa aynı adı veriyorsa 127/129 (%98,4; %94,5-%99,6), farklı ad veriyorsa 38/39 (%97,4; %86,8-%99,6) (KS-1'in hangi satırlarının üründe ad vereceği ayrı bir karardır; burada yalnız çapanın varlığına bakıldı). Çapası OLMAYAN adlar: 85/164 (%51,8; %44,2-%59,4); kanıt dizgisi olduğu gibi yazılsa 103/164 (%62,8; %55,2-%69,8). Aşağıdaki tablo yalnız bu alt kümedir (kapsam ve pay alt kümeye göre).

| Özellik | Değer | Ad | Doğru | Kesinlik (%95) | Kanıt dizgisi olduğu gibi yazılsa (%95) | Kapsam | Doğru adların payı | Program başına (doğru / dönüşümle doğru / n) | Karar | Karar (dönüşümle) |
|---|---|---|---|---|---|---|---|---|---|---|
| `kanit_kaynagi` | `body_literal` | 7 | 0 | 0/7 (%0,0; %0,0-%35,4) | 1/7 (%14,3; %2,6-%51,3) | %4,3 | %0,0 | coreutils 0/0/4, openssl 0/0/1, tmux 0/0/1, zstd 0/1/1 | `tutmuyor` | `tutmuyor` |
| `kanit_kaynagi` | `string_ref` | 157 | 85 | 85/157 (%54,1; %46,3-%61,7) | 102/157 (%65,0; %57,2-%72,0) | %95,7 | %100,0 | coreutils 3/6/8, htop 0/0/1, openssl 3/5/6, redis-tools 0/0/3, sqlite3 0/0/7, tmux 78/78/113, zstd 1/13/19 | `tutmuyor` | `tutmuyor` |
| `carpisma_eki` | `evet` | 17 | 0 | 0/17 (%0,0; %0,0-%18,4) | 4/17 (%23,5; %9,6-%47,3) | %10,4 | %0,0 | coreutils 0/3/3, openssl 0/0/1, sqlite3 0/0/2, tmux 0/0/8, zstd 0/1/3 | `tutmuyor` | `tutmuyor` |
| `carpisma_eki` | `hayir` | 147 | 85 | 85/147 (%57,8; %49,7-%65,5) | 99/147 (%67,3; %59,4-%74,4) | %89,6 | %100,0 | coreutils 3/3/9, htop 0/0/1, openssl 3/5/6, redis-tools 0/0/3, sqlite3 0/0/5, tmux 78/78/106, zstd 1/13/17 | `tutmuyor` | `tutmuyor` |
| `dizgiyi_kullanan_fonksiyon` | `0` | 2 | 0 | 0/2 (%0,0; %0,0-%65,8) | 1/2 (%50,0; %9,4-%90,5) | %1,2 | %0,0 | openssl 0/0/1, zstd 0/1/1 | `tutmuyor` | `tutmuyor` |
| `dizgiyi_kullanan_fonksiyon` | `1` | 123 | 77 | 77/123 (%62,6; %53,8-%70,7) | 91/123 (%74,0; %65,6-%80,9) | %75,0 | %90,6 | coreutils 3/6/12, htop 0/0/1, openssl 3/5/5, redis-tools 0/0/1, sqlite3 0/0/2, tmux 70/70/90, zstd 1/10/12 | `tutmuyor` | `tutmuyor` |
| `dizgiyi_kullanan_fonksiyon` | `2` | 27 | 8 | 8/27 (%29,6; %15,8-%48,5) | 10/27 (%37,0; %21,5-%55,8) | %16,5 | %9,4 | openssl 0/0/1, sqlite3 0/0/3, tmux 8/8/20, zstd 0/2/3 | `tutmuyor` | `tutmuyor` |
| `dizgiyi_kullanan_fonksiyon` | `3+` | 12 | 0 | 0/12 (%0,0; %0,0-%24,2) | 1/12 (%8,3; %1,5-%35,4) | %7,3 | %0,0 | redis-tools 0/0/2, sqlite3 0/0/2, tmux 0/0/4, zstd 0/1/4 | `tutmuyor` | `tutmuyor` |
| `ayni_adi_oneren_fonksiyon` | `1` | 134 | 79 | 79/134 (%59,0; %50,5-%66,9) | 92/134 (%68,7; %60,4-%75,9) | %81,7 | %92,9 | coreutils 3/3/8, htop 0/0/1, openssl 3/5/6, redis-tools 0/0/3, sqlite3 0/0/3, tmux 72/72/97, zstd 1/12/16 | `tutmuyor` | `tutmuyor` |
| `ayni_adi_oneren_fonksiyon` | `2+` | 30 | 6 | 6/30 (%20,0; %9,5-%37,3) | 11/30 (%36,7; %21,9-%54,5) | %18,3 | %7,1 | coreutils 0/3/4, openssl 0/0/1, sqlite3 0/0/4, tmux 6/6/17, zstd 0/2/4 | `tutmuyor` | `tutmuyor` |
| `govdede_gecis` | `0` | 25 | 15 | 15/25 (%60,0; %40,7-%76,6) | 15/25 (%60,0; %40,7-%76,6) | %15,2 | %17,6 | coreutils 0/0/2, sqlite3 0/0/1, tmux 15/15/21, zstd 0/0/1 | `tutmuyor` | `tutmuyor` |
| `govdede_gecis` | `1` | 110 | 59 | 59/110 (%53,6; %44,4-%62,7) | 70/110 (%63,6; %54,3-%72,0) | %67,1 | %69,4 | coreutils 1/1/2, htop 0/0/1, openssl 2/2/4, redis-tools 0/0/3, sqlite3 0/0/6, tmux 55/55/80, zstd 1/12/14 | `tutmuyor` | `tutmuyor` |
| `govdede_gecis` | `2+` | 29 | 11 | 11/29 (%37,9; %22,7-%56,0) | 18/29 (%62,1; %44,0-%77,3) | %17,7 | %12,9 | coreutils 2/5/8, openssl 1/3/3, tmux 8/8/13, zstd 0/2/5 | `tutmuyor` | `tutmuyor` |
| `cagri_argumani` | `arg0/dis` | 3 | 0 | 0/3 (%0,0; %0,0-%56,1) | 0/3 (%0,0; %0,0-%56,1) | %1,8 | %0,0 | redis-tools 0/0/2, sqlite3 0/0/1 | `tutmuyor` | `tutmuyor` |
| `cagri_argumani` | `arg0/ic` | 2 | 0 | 0/2 (%0,0; %0,0-%65,8) | 0/2 (%0,0; %0,0-%65,8) | %1,2 | %0,0 | tmux 0/0/2 | `tutmuyor` | `tutmuyor` |
| `cagri_argumani` | `arg1/dis` | 6 | 0 | 0/6 (%0,0; %0,0-%39,0) | 0/6 (%0,0; %0,0-%39,0) | %3,7 | %0,0 | htop 0/0/1, sqlite3 0/0/5 | `tutmuyor` | `tutmuyor` |
| `cagri_argumani` | `arg1/ic` | 55 | 28 | 28/55 (%50,9; %38,1-%63,6) | 28/55 (%50,9; %38,1-%63,6) | %33,5 | %32,9 | redis-tools 0/0/1, tmux 28/28/54 | `tutmuyor` | `tutmuyor` |
| `cagri_argumani` | `arg2+/dis` | 31 | 7 | 7/31 (%22,6; %11,4-%39,8) | 25/31 (%80,6; %63,7-%90,8) | %18,9 | %8,2 | coreutils 3/6/7, openssl 3/5/5, zstd 1/14/19 | `tutmuyor` | `tutmuyor` |
| `cagri_argumani` | `arg2+/ic` | 37 | 35 | 35/37 (%94,6; %82,3-%98,5) | 35/37 (%94,6; %82,3-%98,5) | %22,6 | %41,2 | openssl 0/0/1, tmux 35/35/36 | `tutmuyor` | `tutmuyor` |
| `cagri_argumani` | `cagri_disi` | 5 | 0 | 0/5 (%0,0; %0,0-%43,5) | 0/5 (%0,0; %0,0-%43,5) | %3,0 | %0,0 | coreutils 0/0/3, openssl 0/0/1, tmux 0/0/1 | `tutmuyor` | `tutmuyor` |
| `cagri_argumani` | `govdede_yok` | 25 | 15 | 15/25 (%60,0; %40,7-%76,6) | 15/25 (%60,0; %40,7-%76,6) | %15,2 | %17,6 | coreutils 0/0/2, sqlite3 0/0/1, tmux 15/15/21, zstd 0/0/1 | `tutmuyor` | `tutmuyor` |
| `oz_ad_bicimli_dizgi` | `1` | 130 | 78 | 78/130 (%60,0; %51,4-%68,0) | 95/130 (%73,1; %64,9-%80,0) | %79,3 | %91,8 | coreutils 1/4/10, htop 0/0/1, openssl 3/5/5, redis-tools 0/0/3, sqlite3 0/0/4, tmux 73/73/90, zstd 1/13/17 | `tutmuyor` | `tutmuyor` |
| `oz_ad_bicimli_dizgi` | `2` | 17 | 7 | 7/17 (%41,2; %21,6-%64,0) | 8/17 (%47,1; %26,2-%69,0) | %10,4 | %8,2 | coreutils 2/2/2, openssl 0/0/2, sqlite3 0/0/3, tmux 5/5/9, zstd 0/1/1 | `tutmuyor` | `tutmuyor` |
| `oz_ad_bicimli_dizgi` | `3+` | 17 | 0 | 0/17 (%0,0; %0,0-%18,4) | 0/17 (%0,0; %0,0-%18,4) | %10,4 | %0,0 | tmux 0/0/15, zstd 0/0/2 | `tutmuyor` | `tutmuyor` |
| `fonksiyonun_dizgi_sayisi` | `0` | 3 | 0 | 0/3 (%0,0; %0,0-%56,1) | 0/3 (%0,0; %0,0-%56,1) | %1,8 | %0,0 | coreutils 0/0/3 | `tutmuyor` | `tutmuyor` |
| `fonksiyonun_dizgi_sayisi` | `1` | 56 | 45 | 45/56 (%80,4; %68,2-%88,7) | 46/56 (%82,1; %70,2-%90,0) | %34,1 | %52,9 | coreutils 0/0/1, htop 0/0/1, redis-tools 0/0/2, sqlite3 0/0/3, tmux 45/45/48, zstd 0/1/1 | `tutmuyor` | `tutmuyor` |
| `fonksiyonun_dizgi_sayisi` | `2-3` | 56 | 32 | 32/56 (%57,1; %44,1-%69,2) | 41/56 (%73,2; %60,4-%83,0) | %34,1 | %37,6 | coreutils 1/1/1, openssl 3/5/5, redis-tools 0/0/1, sqlite3 0/0/4, tmux 27/27/35, zstd 1/8/10 | `tutmuyor` | `tutmuyor` |
| `fonksiyonun_dizgi_sayisi` | `4+` | 49 | 8 | 8/49 (%16,3; %8,5-%29,0) | 16/49 (%32,7; %21,2-%46,6) | %29,9 | %9,4 | coreutils 2/5/7, openssl 0/0/2, tmux 6/6/31, zstd 0/5/9 | `tutmuyor` | `tutmuyor` |
| `ad_ghidra_adli` | `hayir` | 164 | 85 | 85/164 (%51,8; %44,2-%59,4) | 103/164 (%62,8; %55,2-%69,8) | %100,0 | %100,0 | coreutils 3/6/12, htop 0/0/1, openssl 3/5/7, redis-tools 0/0/3, sqlite3 0/0/7, tmux 78/78/114, zstd 1/14/20 | `tutmuyor` | `tutmuyor` |
| `dizgide_buyuk_harf` | `evet` | 24 | 0 | 0/24 (%0,0; %0,0-%13,8) | 15/24 (%62,5; %42,7-%78,8) | %14,6 | %0,0 | coreutils 0/0/2, openssl 0/2/3, zstd 0/13/19 | `tutmuyor` | `tutmuyor` |
| `dizgide_buyuk_harf` | `hayir` | 140 | 85 | 85/140 (%60,7; %52,4-%68,4) | 88/140 (%62,9; %54,6-%70,4) | %85,4 | %100,0 | coreutils 3/6/10, htop 0/0/1, openssl 3/3/4, redis-tools 0/0/3, sqlite3 0/0/7, tmux 78/78/114, zstd 1/1/1 | `tutmuyor` | `tutmuyor` |
| `ikili_adi_onekli` | `evet` | 12 | 1 | 1/12 (%8,3; %1,5-%35,4) | 7/12 (%58,3; %31,9-%80,7) | %7,3 | %1,2 | coreutils 1/1/2, zstd 0/6/10 | `tutmuyor` | `tutmuyor` |
| `ikili_adi_onekli` | `hayir` | 152 | 84 | 84/152 (%55,3; %47,3-%62,9) | 96/152 (%63,2; %55,2-%70,4) | %92,7 | %98,8 | coreutils 2/5/10, htop 0/0/1, openssl 3/5/7, redis-tools 0/0/3, sqlite3 0/0/7, tmux 78/78/114, zstd 1/8/10 | `tutmuyor` | `tutmuyor` |
| `aday_sayisi` | `1` | 10 | 8 | 8/10 (%80,0; %49,0-%94,3) | 8/10 (%80,0; %49,0-%94,3) | %6,1 | %9,4 | tmux 8/8/10 | `tutmuyor` | `tutmuyor` |
| `aday_sayisi` | `2` | 40 | 27 | 27/40 (%67,5; %52,0-%79,9) | 31/40 (%77,5; %62,5-%87,7) | %24,4 | %31,8 | coreutils 1/1/1, sqlite3 0/0/2, tmux 26/26/32, zstd 0/4/5 | `tutmuyor` | `tutmuyor` |
| `aday_sayisi` | `3+` | 114 | 50 | 50/114 (%43,9; %35,1-%53,0) | 64/114 (%56,1; %47,0-%64,9) | %69,5 | %58,8 | coreutils 2/5/11, htop 0/0/1, openssl 3/5/7, redis-tools 0/0/3, sqlite3 0/0/5, tmux 44/44/72, zstd 1/10/15 | `tutmuyor` | `tutmuyor` |

## 5. `kebap_ad` ve `api_param_reverse`: yakın mı, ilgisiz mi

Yakınlık, yanlış adın o adresteki GT adına en yakın ölçüsüdür (sırayla ilk tutan):

| Ölçü | Tanım |
|---|---|
| `norm_esit` | küçük harf + alfasayısal olmayanlar atılınca eşit |
| `belirtec_kumesi_esit` | belirteç kümeleri eşit (sıra farklı olabilir) |
| `urun_belirtecleri_gt_icinde` | ürün adının bütün belirteçleri GT adında var (GT'de fazlası var) |
| `gt_belirtecleri_urun_icinde` | GT adının bütün belirteçleri ürün adında var |
| `alt_dizi` | normalleştirilmiş adlardan biri öbürünün alt dizgisi (kısa olan ≥ 4 karakter) |
| `belirtec_kesisimi_var` | en az bir ortak belirteç (≥ 3 karakter) |
| `ortak_belirtec_yok` | ortak belirteç yok |
| `gt_yok` | o adreste GT fonksiyonu yok |

| Kanal | Yanlış | `norm_esit` | `belirtec_kumesi_esit` | `urun_belirtecleri_gt_icinde` | `gt_belirtecleri_urun_icinde` | `alt_dizi` | `belirtec_kesisimi_var` | `ortak_belirtec_yok` | `gt_yok` |
|---|---|---|---|---|---|---|---|---|---|
| `kebap_ad` | 266 | 0 | 0 | 10 | 0 | 0 | 150 | 105 | 1 |
| `api_param_reverse` | 55 | 0 | 0 | 1 | 1 | 0 | 25 | 28 | 0 |

Belirteç kümesi Jaccard benzerliği (belirteç ≥ 3 karakter; GT'si olan yanlışlar):

| Kanal | `0` | `(0;0,5)` | `[0,5;1)` | `1` | GT yok |
|---|---|---|---|---|---|
| `kebap_ad` | 105 | 145 | 15 | 0 | 1 |
| `api_param_reverse` | 28 | 25 | 2 | 0 | 0 |

Ürün adı ikilinin GT'sinde HERHANGİ bir adreste var mı (dönüştürerek kurtarma için üst sınır):

| Kanal | Ad | Tam eşit | Normalleştirilince eşit | Yalnız sonek olarak | Çakışma ekli |
|---|---|---|---|---|---|
| `kebap_ad` | 266 | 0 | 0 | 48 | 114 |
| `api_param_reverse` | 55 | 0 | 0 | 1 | 35 |

Program başına yakınlık:

| Kanal | Program | Dağılım |
|---|---|---|
| `kebap_ad` | openssl | belirtec_kesisimi_var 1, ortak_belirtec_yok 1 |
| `kebap_ad` | sqlite3 | ortak_belirtec_yok 1 |
| `kebap_ad` | tmux | belirtec_kesisimi_var 149, gt_yok 1, ortak_belirtec_yok 103, urun_belirtecleri_gt_icinde 10 |
| `api_param_reverse` | coreutils | belirtec_kesisimi_var 5, ortak_belirtec_yok 1 |
| `api_param_reverse` | htop | ortak_belirtec_yok 1 |
| `api_param_reverse` | openssl | ortak_belirtec_yok 4 |
| `api_param_reverse` | redis-tools | belirtec_kesisimi_var 6, ortak_belirtec_yok 5 |
| `api_param_reverse` | sqlite3 | belirtec_kesisimi_var 2, gt_belirtecleri_urun_icinde 1, ortak_belirtec_yok 1, urun_belirtecleri_gt_icinde 1 |
| `api_param_reverse` | tmux | belirtec_kesisimi_var 9, ortak_belirtec_yok 16 |
| `api_param_reverse` | zstd | belirtec_kesisimi_var 3 |

## 6. Kural adayları

Bütün tek özellik değerleri, önceden yazılmış bileşikler ve dönüşümler (karşı olgu) aynı kuralla karara bağlandı. `donusum`: adın yazılış biçimini değiştiren kural (kesinlik, dönüşüm uygulansaydı doğru sayılacak adlardan); `sus_kalan`: koşulu tutan adlar kalır, tutmayanlar susar.

### Öneri (üç koşul da tutuyor)

| Kanal | Koşul | Tür | Sonradan | Doğru/n | Kesinlik | Wilson alt sınırı | Kapsam (kanalın adları) | n ≥ 10 olan programlar | En büyük program dışı (doğru/n) | Neden |
|---|---|---|---|---|---|---|---|---|---|---|
| `on_ad` | tur = elf_onyuk; ad temizlenmeden yazılır | `donusum` | — | 458/458 | %100,0 | %99,2 | %32,3 | coreutils, redis-tools | 35/35 | — |

### Yetersiz (kesinlik ≥ %95 ama n ya da program çeşitliliği yetmiyor)

| Kanal | Koşul | Tür | Sonradan | Doğru/n | Kesinlik | Wilson alt sınırı | Kapsam (kanalın adları) | n ≥ 10 olan programlar | En büyük program dışı (doğru/n) | Neden |
|---|---|---|---|---|---|---|---|---|---|---|
| `on_ad` | gnulib adı; bu veride n ≥ 10 iken hiç doğru vermeyen katalog girdileri hariç (girdi seçimi aynı veride) | `sus_kalan` | evet | 621/633 | %98,1 | %96,7 | %44,6 | coreutils | 1/4 | tek program |
| `on_ad` | gnulib adı; hiç doğru vermeyen katalog girdileri hariç ve ikilide dizgi parmak izi isabeti 3+ (girdi seçimi aynı veride) | `sus_kalan` | evet | 605/614 | %98,5 | %97,2 | %43,2 | coreutils | 0/0 | tek program |
| `on_ad` | katalog_girdisi = elf_onyuk#0 | `sus_kalan` | — | 116/116 | %100,0 | %96,8 | %8,2 | coreutils | 10/10 | tek program |
| `on_ad` | katalog_girdisi = elf_onyuk#1 | `sus_kalan` | — | 116/116 | %100,0 | %96,8 | %8,2 | coreutils | 10/10 | tek program |
| `on_ad` | katalog_girdisi = elf_onyuk#2; ad temizlenmeden yazılır | `donusum` | — | 116/116 | %100,0 | %96,8 | %8,2 | coreutils | 10/10 | tek program |
| `on_ad` | katalog_girdisi = elf_onyuk#3; ad temizlenmeden yazılır | `donusum` | — | 110/110 | %100,0 | %96,6 | %7,7 | coreutils | 5/5 | tek program |
| `on_ad` | tur = main_giris | `sus_kalan` | — | 110/110 | %100,0 | %96,6 | %7,7 | coreutils | 5/5 | tek program |
| `on_ad` | katalog_girdisi = gnulib/cagri_bicimi#0 | `sus_kalan` | — | 105/105 | %100,0 | %96,5 | %7,4 | coreutils | 0/0 | tek program |
| `on_ad` | katalog_girdisi = gnulib/cagri_bicimi#3 | `sus_kalan` | — | 105/105 | %100,0 | %96,5 | %7,4 | coreutils | 0/0 | tek program |
| `on_ad` | katalog_girdisi = gnulib/dizgi_parmak_izi#6 | `sus_kalan` | — | 102/102 | %100,0 | %96,4 | %7,2 | coreutils | 1/1 | tek program |
| `on_ad` | katalog_girdisi = gnulib/cagri_bicimi#5 | `sus_kalan` | — | 101/101 | %100,0 | %96,3 | %7,1 | coreutils | 0/0 | tek program |
| `on_ad` | katalog_girdisi = gnulib/dizgi_parmak_izi#1 | `sus_kalan` | — | 98/98 | %100,0 | %96,2 | %6,9 | coreutils | 0/0 | tek program |
| `on_ad` | katalog_girdisi = gnulib/dizgi_parmak_izi#2 | `sus_kalan` | — | 83/86 | %96,5 | %90,2 | %6,1 | coreutils | 0/3 | Wilson alt sınırı < %95; tek program |
| `on_ad` | katalog_girdisi = gnulib/ayristirma#0 | `sus_kalan` | — | 22/22 | %100,0 | %85,1 | %1,5 | coreutils | 0/0 | Wilson alt sınırı < %95; tek program |
| `on_ad` | tur = gnulib/ayristirma | `sus_kalan` | — | 22/22 | %100,0 | %85,1 | %1,5 | coreutils | 0/0 | Wilson alt sınırı < %95; tek program |
| `on_ad` | katalog_girdisi = gnulib/dizgi_parmak_izi#5 | `sus_kalan` | — | 5/5 | %100,0 | %56,5 | %0,4 | — | 0/0 | Wilson alt sınırı < %95; tek program |
| `on_ad` | ks1_capasi = farkli_ad | `sus_kalan` | — | 4/4 | %100,0 | %51,0 | %0,3 | — | 0/0 | Wilson alt sınırı < %95; tek program |
| `on_ad` | ks1_capasi = ayni_ad | `sus_kalan` | — | 1/1 | %100,0 | %20,6 | %0,1 | — | 0/0 | Wilson alt sınırı < %95; tek program |
| `oz_ad` | bileşik: dizgiyi_kullanan_fonksiyon ∈ {1} ve oz_ad_bicimli_dizgi ∈ {1} ve carpisma_eki ∈ {hayir} ve cagri_argumani ∈ {arg1/ic, arg2+/dis, arg2+/ic}; kanıt dizgisi olduğu gibi yazılır | `donusum` | evet | 166/172 | %96,5 | %92,6 | %51,8 | coreutils, tmux, zstd | 68/72 | Wilson alt sınırı < %95 |
| `oz_ad` | ks1_capasi = ayni_ad; kanıt dizgisi olduğu gibi yazılır | `donusum` | — | 127/129 | %98,4 | %94,5 | %38,9 | coreutils, tmux | 25/25 | Wilson alt sınırı < %95 |
| `oz_ad` | bileşik: dizgiyi_kullanan_fonksiyon ∈ {1} ve oz_ad_bicimli_dizgi ∈ {1} ve carpisma_eki ∈ {hayir} ve cagri_argumani ∈ {arg1/ic, arg2+/dis, arg2+/ic} ve ks1_capasi ∈ {yok}; kanıt dizgisi olduğu gibi yazılır | `donusum` | evet | 70/73 | %95,9 | %88,6 | %22,0 | tmux | 15/17 | Wilson alt sınırı < %95; tek program |

Kesinlik eşiğini tutmayan koşul: 173 (hepsi §3-§5 tablolarında ve JSON'da). Denenen koşul sayısı: 195; bu kadar koşul aynı veride denendiği için tek tek aralıklar iyimserdir.

### Susturma (ürünün kendi kuralıyla)

Ürünün alt kanal kararı "yalnız zayıflar" kuralıdır (N0b; `baglama.row_status_from_measurement` aynı eşiği kullanır): yanlış oranının Wilson %95 alt sınırı hedefin (%10,0) üstündeyse `sus`. Aynı kural kalan kanallara, ön ad türlerine, katalog girdilerine ve `oz_ad`'ın KS-1 katmanlarına uygulandı:

| Kapsam | Ad | Yanlış | Yanlış oranı (%95) | Karar |
|---|---|---|---|---|
| kanal: on_ad | 1420 | 457 | 457/1420 (%32,2; %29,8-%34,7) | `sus` |
| kanal: oz_ad | 332 | 125 | 125/332 (%37,7; %32,6-%43,0) | `sus` |
| kanal: kebap_ad | 266 | 266 | 266/266 (%100,0; %98,6-%100,0) | `sus` |
| kanal: api_param_reverse | 55 | 55 | 55/55 (%100,0; %93,5-%100,0) | `sus` |
| ön ad türü: elf_onyuk | 458 | 226 | 226/458 (%49,3; %44,8-%53,9) | `sus` |
| ön ad türü: elf_onyuk; ad temizlenmeden yazılır | 458 | 0 | 0/458 (%0,0; %0,0-%0,8) | `kalir` |
| ön ad türü: gnulib/ayristirma | 22 | 0 | 0/22 (%0,0; %0,0-%14,9) | `kalir` |
| ön ad türü: gnulib/cagri_bicimi | 426 | 115 | 115/426 (%27,0; %23,0-%31,4) | `sus` |
| ön ad türü: gnulib/dizgi_parmak_izi | 404 | 116 | 116/404 (%28,7; %24,5-%33,3) | `sus` |
| ön ad türü: main_giris | 110 | 0 | 0/110 (%0,0; %0,0-%3,4) | `kalir` |
| katalog girdisi: elf_onyuk#0; ad temizlenmeden yazılır | 116 | 0 | 0/116 (%0,0; %0,0-%3,2) | `kalir` |
| katalog girdisi: elf_onyuk#1; ad temizlenmeden yazılır | 116 | 0 | 0/116 (%0,0; %0,0-%3,2) | `kalir` |
| katalog girdisi: elf_onyuk#2; ad temizlenmeden yazılır | 116 | 0 | 0/116 (%0,0; %0,0-%3,2) | `kalir` |
| katalog girdisi: elf_onyuk#3; ad temizlenmeden yazılır | 110 | 0 | 0/110 (%0,0; %0,0-%3,4) | `kalir` |
| katalog girdisi: gnulib/ayristirma#0; ad temizlenmeden yazılır | 22 | 0 | 0/22 (%0,0; %0,0-%14,9) | `kalir` |
| katalog girdisi: gnulib/cagri_bicimi#0; ad temizlenmeden yazılır | 105 | 0 | 0/105 (%0,0; %0,0-%3,5) | `kalir` |
| katalog girdisi: gnulib/cagri_bicimi#1; ad temizlenmeden yazılır | 104 | 104 | 104/104 (%100,0; %96,4-%100,0) | `sus` |
| katalog girdisi: gnulib/cagri_bicimi#2; ad temizlenmeden yazılır | 11 | 11 | 11/11 (%100,0; %74,1-%100,0) | `sus` |
| katalog girdisi: gnulib/cagri_bicimi#3; ad temizlenmeden yazılır | 105 | 0 | 0/105 (%0,0; %0,0-%3,5) | `kalir` |
| katalog girdisi: gnulib/cagri_bicimi#5; ad temizlenmeden yazılır | 101 | 0 | 0/101 (%0,0; %0,0-%3,7) | `kalir` |
| katalog girdisi: gnulib/dizgi_parmak_izi#0; ad temizlenmeden yazılır | 104 | 104 | 104/104 (%100,0; %96,4-%100,0) | `sus` |
| katalog girdisi: gnulib/dizgi_parmak_izi#1; ad temizlenmeden yazılır | 98 | 0 | 0/98 (%0,0; %0,0-%3,8) | `kalir` |
| katalog girdisi: gnulib/dizgi_parmak_izi#2; ad temizlenmeden yazılır | 86 | 3 | 3/86 (%3,5; %1,2-%9,8) | `kalir` |
| katalog girdisi: gnulib/dizgi_parmak_izi#4; ad temizlenmeden yazılır | 9 | 9 | 9/9 (%100,0; %70,1-%100,0) | `sus` |
| katalog girdisi: gnulib/dizgi_parmak_izi#5; ad temizlenmeden yazılır | 5 | 0 | 0/5 (%0,0; %0,0-%43,5) | `kalir` |
| katalog girdisi: gnulib/dizgi_parmak_izi#6; ad temizlenmeden yazılır | 102 | 0 | 0/102 (%0,0; %0,0-%3,6) | `kalir` |
| oz_ad; ks1_capasi = ayni_ad | 129 | 7 | 7/129 (%5,4; %2,6-%10,8) | `kalir` |
| oz_ad; ks1_capasi = ayni_ad; kanıt dizgisi olduğu gibi yazılır | 129 | 2 | 2/129 (%1,6; %0,4-%5,5) | `kalir` |
| oz_ad; ks1_capasi = farkli_ad | 39 | 39 | 39/39 (%100,0; %91,0-%100,0) | `sus` |
| oz_ad; ks1_capasi = farkli_ad; kanıt dizgisi olduğu gibi yazılır | 39 | 9 | 9/39 (%23,1; %12,7-%38,3) | `sus` |
| oz_ad; ks1_capasi = yok | 164 | 79 | 79/164 (%48,2; %40,6-%55,8) | `sus` |
| oz_ad; ks1_capasi = yok; kanıt dizgisi olduğu gibi yazılır | 164 | 61 | 61/164 (%37,2; %30,2-%44,8) | `sus` |
| oz_ad; bileşik `tek_fonksiyon_ve_eksiz` | 282 | 83 | 83/282 (%29,4; %24,4-%35,0) | `sus` |
| oz_ad; bileşik `tek_fonksiyon_ve_eksiz`; kanıt dizgisi olduğu gibi yazılır | 282 | 43 | 43/282 (%15,2; %11,5-%19,9) | `sus` |
| oz_ad; bileşik `tek_fonksiyon_ve_tek_oz_ad_dizgisi` | 242 | 57 | 57/242 (%23,6; %18,6-%29,3) | `sus` |
| oz_ad; bileşik `tek_fonksiyon_ve_tek_oz_ad_dizgisi`; kanıt dizgisi olduğu gibi yazılır | 242 | 18 | 18/242 (%7,4; %4,8-%11,5) | `kalir` |
| oz_ad; bileşik `ks1_yok_ve_tek_fonksiyon` | 119 | 42 | 42/119 (%35,3; %27,3-%44,2) | `sus` |
| oz_ad; bileşik `ks1_yok_ve_tek_fonksiyon`; kanıt dizgisi olduğu gibi yazılır | 119 | 32 | 32/119 (%26,9; %19,7-%35,5) | `sus` |
| oz_ad; bileşik `tek_tek_eksiz_ve_ks1_yok` (sonradan) | 94 | 24 | 24/94 (%25,5; %17,8-%35,2) | `sus` |
| oz_ad; bileşik `tek_tek_eksiz_ve_ks1_yok` (sonradan); kanıt dizgisi olduğu gibi yazılır | 94 | 14 | 14/94 (%14,9; %9,1-%23,5) | `kalir` |
| oz_ad; bileşik `tek_tek_eksiz_ve_az_dizgi` (sonradan) | 186 | 35 | 35/186 (%18,8; %13,9-%25,0) | `sus` |
| oz_ad; bileşik `tek_tek_eksiz_ve_az_dizgi` (sonradan); kanıt dizgisi olduğu gibi yazılır | 186 | 10 | 10/186 (%5,4; %2,9-%9,6) | `kalir` |
| oz_ad; bileşik `sonraki_arguman_ve_ks1_yok` (sonradan) | 123 | 53 | 53/123 (%43,1; %34,7-%51,9) | `sus` |
| oz_ad; bileşik `sonraki_arguman_ve_ks1_yok` (sonradan); kanıt dizgisi olduğu gibi yazılır | 123 | 35 | 35/123 (%28,5; %21,2-%37,0) | `sus` |
| oz_ad; bileşik `tek_tek_eksiz_ve_sonraki_arguman` (sonradan) | 172 | 45 | 45/172 (%26,2; %20,2-%33,2) | `sus` |
| oz_ad; bileşik `tek_tek_eksiz_ve_sonraki_arguman` (sonradan); kanıt dizgisi olduğu gibi yazılır | 172 | 6 | 6/172 (%3,5; %1,6-%7,4) | `kalir` |
| oz_ad; bileşik `tek_tek_eksiz_ve_sonraki_arguman_ve_ks1_yok` (sonradan) | 73 | 13 | 13/73 (%17,8; %10,7-%28,1) | `sus` |
| oz_ad; bileşik `tek_tek_eksiz_ve_sonraki_arguman_ve_ks1_yok` (sonradan); kanıt dizgisi olduğu gibi yazılır | 73 | 3 | 3/73 (%4,1; %1,4-%11,4) | `kalir` |

## 7. Tanımda sonradan yapılan değişiklikler

1. Sınıflama: `oz_ad`'da `baska_fonksiyonun_adi`, `ice_aktarilan_adi`, `katalog_adi` ve `gt_yok` alt sınıfı sınamalarına kanıt dizgisinin kendisi (özgün harfleriyle) de aday olarak eklendi. İlk tanım yalnız ürün adına (küçük harf) bakıyordu; elle denetimde `oz_ad` / `ilgisiz` sınıfındaki 53 adın 4'ünün, harf farkıyla, ikilideki başka bir fonksiyonun (3) ya da içe aktarılan bir fonksiyonun (1) adı olduğu, `oz_ad` / `onek_sonek_farki` sınıfındaki 6 adın 1'inin de yine harf farkıyla başka bir fonksiyonun adı olduğu görüldü. Öbür sınıfların tanımı ve sırası değişmedi.
2. `oz_ad` tablolarına ikinci hüküm sütunu eklendi (kanıt dizgisi olduğu gibi yazılsa): yanlışların en büyük sınıfının yalnız harf farkı olduğu görüldükten sonra.
3. `oz_ad` için altı bileşik koşul (`OZ_AD_SONRADAN`) ve "KS-1 çapası yok" katmanlaması, ön adlar için gnulib koşulları (`on_ad.sonradan`) tek özellik tabloları görüldükten sonra yazıldı. Bu satırlar çıktıda `sonradan` diye işaretlidir; aynı veride seçildikleri için en iyimser satırlardır.
4. Sınıf tablosuna `Tekil ad` sütunu eklendi (örnek düzeyi sayımın coreutils'te aynı hatayı yüzü aşkın kez saydığı görüldükten sonra).

## 8. Elle denetim

Her sınıftan en az 10 örnek (sınıf küçükse hepsi; belirlenimci seçim: `ornek` alt komutu) uçbirimde okundu; adlar dosyaya yazılmadı. Sayılar betiğe elle girildi (`ELLE_DENETIM`).

| Sınıf | İncelenen | Sınıflayıcının yanlış koyduğu |
|---|---|---|
| `baska_fonksiyonun_adi` | 27 | 0 |
| `carpisma_eki` | 8 | 0 |
| `gt_yok` | 1 | 0 |
| `harf_altcizgi_farki` | 45 | 0 |
| `ilgisiz` | 144 | 4 |
| `katalog_adi` | 15 | 0 |
| `onek_sonek_farki` | 16 | 1 |
| `temizleyici_farki` | 10 | 0 |
| **Toplam** | 266 | 5 |

- Kapsam: `on_ad` `temizleyici_farki` 10, `baska_fonksiyonun_adi` 14, `katalog_adi` 15 (hepsi); `oz_ad` yanlışlarının tamamı (125); `kebap_ad` 40 örnek + `onek_sonek_farki` 8 (hepsi) + `gt_yok` 1 (hepsi); `api_param_reverse` yanlışlarının tamamı (55). `sonek_farki` ve `ice_aktarilan_adi` ilk tanımda boştu.
- Yanlış konan 5 adın hepsi `oz_ad`'daydı (`ilgisiz` 4, `onek_sonek_farki` 1): tanım değişikliği 1 ile `baska_fonksiyonun_adi` (4) ve `ice_aktarilan_adi` (1) sınıflarına geçtiler; değişiklikten sonra bu 5 ad yeniden okundu, yeni sınıfları doğru. Tablodaki sayılar ilk tanımla yapılan denetimindir.
- `ilgisiz` mekanik bir artık sınıftır, anlam sınıfı değildir. Okunan örneklerde üç ayrı şey var: (a) `oz_ad`'da GT'de simgesi olmayan (satır içine alınmış) bir fonksiyonun adı ya da bir değişken / biçim anahtarı adı; (b) `kebap_ad`'da seçenek ve kanca adları; (c) `api_param_reverse`'te geri çağrı rolü adları (karşılaştırıcı, sinyal işleyici, olay geri çağrısı). (a)'nın iki alt durumu GT simgesinden ayırt edilemez; sayılmadı.
- `baska_fonksiyonun_adi` alt sınıfı (`cagrilan` / `cagiran` / `komsu` / `uzak`) yalnız doğrudan çağrı kenarına bakar; iki adım uzaktaki çağıran `uzak` görünür (ön adlarda 104 örnek böyle).

## 9. Sınırlar ve doğrulanamayanlar

- Ön ad türü köken kaydından okunmadı (saklı koşularda yazılı değil); tohum fonksiyonları BUGÜNKÜ kodla (HEAD) saklı `static/` çıktısında yeniden çağrıldı. Yeniden üretimin koşudakiyle aynı olduğu iki yoldan denetlendi (koşunun sayaçları, köken kaydındaki ham ad); anahtar düzeyinde başka kanıt yok.
- `ks1_capasi` özelliği KS-1 çıkarıcısının (`kesin.py`) bugünkü çıktısıdır: çapanın VARLIĞI. Üründe hangi karar satırlarının ad vereceği (`baglama.ROW_STATUS`) bu çözümlemenin dışında; bugün dört satır da susuyor.
- "Kanıt dizgisi olduğu gibi yazılsa" ve "çakışma eki eklenmese" karşı olguları ad tekliğini yok sayar: aynı ad ikilide iki fonksiyona yazılamaz. Çakışma ekli adlarda bu hüküm ulaşılabilir olanın üst sınırıdır; `carpisma_eki = hayir` koşulunu taşıyan satırlarda bu sorun yoktur.
- `cagri_argumani` ve `govdede_gecis` ham decompile metninde basit bir ayrıştırmayla bulunur (literali saran ilk açık parantez). Belirlenimci seçilen 24 `oz_ad` örneğinde elle bakıldı: 24 örnekte de doğru; 6 örnek `govdede_yok` idi ve hepsi Mach-O. Mach-O'da dizgi gövdede çoğu kez literal değil simge olarak geçiyor (`govdede_yok`: mac/tmux 70/126, debian birimleri toplamı 6/206); bu iki özellik Mac'te zayıf.
- Kanal başına veri dengesiz (§1): ön adlarda coreutils'in payı %96,8 (106 ikili, ortak kitaplık); tmux'un payı `oz_ad`'da %66,9, `kebap_ad`'da %98,9 (aynı programın iki platform birimi). "Tek program" notu bu yüzden sık; program düzeyi genelleme bu veriyle yapılamaz.
- Elle denetimi tek kişi (bu çözümlemeyi yapan) yaptı; ikinci değerlendirici yok.
- Doğrulama ve test setleri açılmadı; hiçbir koşul taze veride sınanmadı.
