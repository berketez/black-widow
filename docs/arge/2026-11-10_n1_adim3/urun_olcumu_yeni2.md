# Ürün adlarının ölçümü: yeni2

- Kökler: Debian `/Users/apple/karadul_olcum/runs/urun-yeni2-f30ac9a/debian`, Mac `/Users/apple/karadul_olcum/runs/urun-yeni2-f30ac9a/mac`.
- `urun_olc.py` sha256 `06131cdc55f752bc…`; `ks1_olc.py` sha256 `975c4d1265d8610e…`; HEAD `2be12ed`; Ghidra 12.1.2 (119 ikili).
- İkililer: 119 bitti; sorunlar: yok.
- Kol kimliği (köken kaydından; C++ dışı ikili sayısı): `{"genel_esik": 0.7, "koken_var": true, "susturma": true}` × 118.
- Hüküm tam eşitliktir (Mach-O'da baştaki tek `_` soyulur; klon ekli GT'de taban eşitliği; GT'de karşılığı olmayan ad yanlış). Sayım örnek düzeyindedir (ikili başına ad). Bu belgede fonksiyon adı geçmez.

## Toplam (fonksiyon adları)

| | Ad verilen | Doğru | Yanlış | Kesinlik (%95) | Yanlış oranı (%95) | Kapsam (%95) | Tam ad kapsamı (%95) |
|---|---|---|---|---|---|---|---|
| Havuz | 2261 | 1589 | 672 | 1589/2261 (%70,3; %68,4-%72,1) | 672/2261 (%29,7; %27,9-%31,6) | 1764/21371 (%8,3; %7,9-%8,6) | 1120/21371 (%5,2; %5,0-%5,5) |

| Program düzeyi makro | Kesinlik | Yanlış oranı | Kapsam | Tam ad kapsamı |
|---|---|---|---|---|
| Bütün birimler | %47,2 | %52,8 | %4,9 | %2,3 |

Makroya paydası ≥ 10 olan birimler girer; aynı programın platform birimleri önce ortalanır. Duyarlılık (karar dışı), havuz: yalnız ad bekleyen nüfustaki adların kesinliği 1120/1764 (%63,5; %61,2-%65,7); proje normalleştirmesiyle doğru 1592/2261 (%70,4; %68,5-%72,3); tekil adla kesinlik 425/868 (%49,0; %45,6-%52,3).

## Kararlar (bu kol tek başına)

| Karar | Ölçü | Makro | Eşik | Giren programlar | Küçük birimler | Sonuç |
|---|---|---|---|---|---|---|
| (a) yanlış ad oranı | yanlış / ad verilen | %52,8 | ≤ %10,0 | coreutils, openssl, redis-tools, sqlite3, tmux, zstd | debian/htop, debian/tree | `tutmuyor` |
| (b) "kesin" etiketli adlar | doğru / "kesin" etiketli | %97,3 | ≥ %95,0 | openssl, tmux | — | `tutuyor` |

## Birim başına (küçükten büyüğe)

| Birim | İkili | Boyut | Zenginlik | Ad bekleyen | Ad verilen | Doğru | Yanlış | Kesinlik (%95) | Yanlış oranı (%95) | Kapsam (%95) | Tam ad kapsamı (%95) | Nüfus içi kesinlik | Proje norm. | Klon (doğru/n) | Eşlenemeyen |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| debian/coreutils | 106 | `kucuk` | `yoksul` | 12717 | 1411 | 1178 | 233 | 1178/1411 (%83,5; %81,5-%85,3) | 233/1411 (%16,5; %14,7-%18,5) | 987/12717 (%7,8; %7,3-%8,2) | 754/12717 (%5,9; %5,5-%6,3) | %76,4 | %83,6 | 1/1 | 0 |
| debian/tree | 1 | `kucuk` | `yoksul` | 110 | 5 | 5 | 0 | 5/5 (%100,0; %56,5-%100,0) | 0/5 (%0,0; %0,0-%43,5) | 1/110 (%0,9; %0,2-%5,0) | 1/110 (%0,9; %0,2-%5,0) | %100,0 | %100,0 | 0/0 | 0 |
| debian/sqlite3 | 1 | `kucuk` | `zengin` | 389 | 20 | 5 | 15 | 5/20 (%25,0; %11,2-%46,9) | 15/20 (%75,0; %53,1-%88,8) | 15/389 (%3,9; %2,4-%6,3) | 1/389 (%0,3; %0,1-%1,4) | %6,7 | %25,0 | 0/1 | 0 |
| debian/openssl | 1 | `orta` | `zengin` | 563 | 35 | 24 | 11 | 24/35 (%68,6; %52,0-%81,5) | 11/35 (%31,4; %18,6-%48,0) | 29/563 (%5,2; %3,6-%7,3) | 19/563 (%3,4; %2,2-%5,2) | %65,5 | %68,6 | 1/2 | 0 |
| mac/htop | 1 | `orta` | `zengin` | 597 | 0 | 0 | 0 | — | — | 0/597 (%0,0; %0,0-%0,6) | 0/597 (%0,0; %0,0-%0,6) | — | — | 0/0 | 0 |
| debian/htop | 1 | `orta` | `zengin` | 222 | 6 | 3 | 3 | 3/6 (%50,0; %18,8-%81,2) | 3/6 (%50,0; %18,8-%81,2) | 3/222 (%1,4; %0,5-%3,9) | 0/222 (%0,0; %0,0-%1,7) | %0,0 | %50,0 | 0/0 | 0 |
| debian/zstd | 1 | `orta` | `yoksul` | 919 | 65 | 9 | 56 | 9/65 (%13,8; %7,5-%24,3) | 56/65 (%86,2; %75,7-%92,5) | 49/919 (%5,3; %4,1-%7,0) | 4/919 (%0,4; %0,2-%1,1) | %8,2 | %15,4 | 1/12 | 0 |
| debian/tmux | 1 | `orta` | `zengin` | 1851 | 295 | 148 | 147 | 148/295 (%50,2; %44,5-%55,8) | 147/295 (%49,8; %44,2-%55,5) | 279/1851 (%15,1; %13,5-%16,8) | 136/1851 (%7,3; %6,2-%8,6) | %48,7 | %50,2 | 8/12 | 0 |
| mac/tmux | 1 | `buyuk` | `zengin` | 2545 | 395 | 205 | 190 | 205/395 (%51,9; %47,0-%56,8) | 190/395 (%48,1; %43,2-%53,0) | 393/2545 (%15,4; %14,1-%16,9) | 205/2545 (%8,1; %7,1-%9,2) | %52,2 | %52,2 | 0/1 | 1 |
| debian/redis-tools | 4 | `buyuk` | `yoksul` | 1458 | 29 | 12 | 17 | 12/29 (%41,4; %25,5-%59,3) | 17/29 (%58,6; %40,7-%74,5) | 8/1458 (%0,5; %0,3-%1,1) | 0/1458 (%0,0; %0,0-%0,3) | %0,0 | %41,4 | 0/9 | 0 |

## Etiket başına (havuz ve program düzeyi makro)

| Etiket | Ad verilen | Doğru | Yanlış | Kesinlik (%95) | Yanlış oranı (%95) | Kapsam (%95) | Tam ad kapsamı (%95) | Makro kesinlik | Makro yanlış | Makro kapsam |
|---|---|---|---|---|---|---|---|---|---|---|
| `doğrulanmadı` | 1999 | 1340 | 659 | 1340/1999 (%67,0; %64,9-%69,1) | 659/1999 (%33,0; %30,9-%35,1) | 1512/21371 (%7,1; %6,7-%7,4) | 880/21371 (%4,1; %3,9-%4,4) | %39,3 | %60,7 | %4,0 |
| `kesin` | 262 | 249 | 13 | 249/262 (%95,0; %91,7-%97,1) | 13/262 (%5,0; %2,9-%8,3) | 252/21371 (%1,2; %1,0-%1,3) | 240/21371 (%1,1; %1,0-%1,3) | %97,3 | %2,7 | %1,0 |

## Kanal başına (havuz ve program düzeyi makro)

| Kanal | Ad verilen | Doğru | Yanlış | Kesinlik (%95) | Yanlış oranı (%95) | Kapsam (%95) | Tam ad kapsamı (%95) | Makro kesinlik | Makro yanlış | Makro kapsam |
|---|---|---|---|---|---|---|---|---|---|---|
| `api_param_reverse` | 85 | 1 | 84 | 1/85 (%1,2; %0,2-%6,4) | 84/85 (%98,8; %93,6-%99,8) | 79/21371 (%0,4; %0,3-%0,5) | 1/21371 (%0,0; %0,0-%0,0) | %0,0 | %100,0 | %0,6 |
| `ks1:assert_ust` | 7 | 5 | 2 | 5/7 (%71,4; %35,9-%91,8) | 2/7 (%28,6; %8,2-%64,1) | 7/21371 (%0,0; %0,0-%0,1) | 5/21371 (%0,0; %0,0-%0,1) | — | — | %0,1 |
| `ks1:func_aktarma` | 33 | 33 | 0 | 33/33 (%100,0; %89,6-%100,0) | 0/33 (%0,0; %0,0-%10,4) | 33/21371 (%0,2; %0,1-%0,2) | 33/21371 (%0,2; %0,1-%0,2) | %100,0 | %0,0 | %0,1 |
| `ks1:func_kalibi` | 259 | 246 | 13 | 246/259 (%95,0; %91,6-%97,0) | 13/259 (%5,0; %3,0-%8,4) | 249/21371 (%1,2; %1,0-%1,3) | 237/21371 (%1,1; %1,0-%1,3) | %97,3 | %2,7 | %1,0 |
| `ks1:func_kalibi+func_aktarma` | 3 | 3 | 0 | 3/3 (%100,0; %43,9-%100,0) | 0/3 (%0,0; %0,0-%56,1) | 3/21371 (%0,0; %0,0-%0,0) | 3/21371 (%0,0; %0,0-%0,0) | — | — | %0,0 |
| `on_ad:elf_onyuk` | 458 | 458 | 0 | 458/458 (%100,0; %99,2-%100,0) | 0/458 (%0,0; %0,0-%0,8) | 0/21371 (%0,0; %0,0-%0,0) | 0/21371 (%0,0; %0,0-%0,0) | %100,0 | %0,0 | %0,0 |
| `on_ad:gnulib` | 843 | 621 | 222 | 621/843 (%73,7; %70,6-%76,5) | 222/843 (%26,3; %23,5-%29,4) | 842/21371 (%3,9; %3,7-%4,2) | 621/21371 (%2,9; %2,7-%3,1) | %74,1 | %25,9 | %0,9 |
| `on_ad:main_giris` | 110 | 110 | 0 | 110/110 (%100,0; %96,6-%100,0) | 0/110 (%0,0; %0,0-%3,4) | 110/21371 (%0,5; %0,4-%0,6) | 110/21371 (%0,5; %0,4-%0,6) | %100,0 | %0,0 | %0,3 |
| `string_context/kebap_ad` | 239 | 0 | 239 | 0/239 (%0,0; %0,0-%1,6) | 239/239 (%100,0; %98,4-%100,0) | 234/21371 (%1,1; %1,0-%1,2) | 0/21371 (%0,0; %0,0-%0,0) | %0,0 | %100,0 | %0,7 |
| `string_context/oz_ad` | 224 | 112 | 112 | 112/224 (%50,0; %43,5-%56,5) | 112/224 (%50,0; %43,5-%56,5) | 207/21371 (%1,0; %0,9-%1,1) | 110/21371 (%0,5; %0,4-%0,6) | %48,5 | %51,5 | %1,3 |

## Kanal grubu başına (havuz ve program düzeyi makro)

`susan`: ürünün karar tablosunda susan `string_context` alt kanalları; `kalan`: öbür bütün kanallar. Susturması kapalı bir kolda `kalan` satırı, susturmanın tek başına bırakacağı adların öngörüsüdür (KS-1'in ekleyeceği adlar ve halefler dışında).

| Kanal grubu | Ad verilen | Doğru | Yanlış | Kesinlik (%95) | Yanlış oranı (%95) | Kapsam (%95) | Tam ad kapsamı (%95) | Makro kesinlik | Makro yanlış | Makro kapsam |
|---|---|---|---|---|---|---|---|---|---|---|
| `kalan` | 2261 | 1589 | 672 | 1589/2261 (%70,3; %68,4-%72,1) | 672/2261 (%29,7; %27,9-%31,6) | 1764/21371 (%8,3; %7,9-%8,6) | 1120/21371 (%5,2; %5,0-%5,5) | %47,2 | %52,8 | %4,9 |

## Etiket × kanal (havuz)

| Etiket | Kanal | Ad verilen | Doğru |
|---|---|---|---|
| `doğrulanmadı` | `api_param_reverse` | 85 | 1 |
| `doğrulanmadı` | `ks1:assert_ust` | 7 | 5 |
| `doğrulanmadı` | `ks1:func_aktarma` | 33 | 33 |
| `doğrulanmadı` | `on_ad:elf_onyuk` | 458 | 458 |
| `doğrulanmadı` | `on_ad:gnulib` | 843 | 621 |
| `doğrulanmadı` | `on_ad:main_giris` | 110 | 110 |
| `doğrulanmadı` | `string_context/kebap_ad` | 239 | 0 |
| `doğrulanmadı` | `string_context/oz_ad` | 224 | 112 |
| `kesin` | `ks1:func_kalibi` | 259 | 246 |
| `kesin` | `ks1:func_kalibi+func_aktarma` | 3 | 3 |

## Birim × etiket

| Birim | Etiket | Ad verilen | Doğru | Yanlış | Kesinlik (%95) | Yanlış oranı (%95) | Kapsam (%95) | Tam ad kapsamı (%95) |
|---|---|---|---|---|---|---|---|---|
| debian/coreutils | `doğrulanmadı` | 1411 | 1178 | 233 | 1178/1411 (%83,5; %81,5-%85,3) | 233/1411 (%16,5; %14,7-%18,5) | 987/12717 (%7,8; %7,3-%8,2) | 754/12717 (%5,9; %5,5-%6,3) |
| debian/tree | `doğrulanmadı` | 5 | 5 | 0 | 5/5 (%100,0; %56,5-%100,0) | 0/5 (%0,0; %0,0-%43,5) | 1/110 (%0,9; %0,2-%5,0) | 1/110 (%0,9; %0,2-%5,0) |
| debian/sqlite3 | `doğrulanmadı` | 20 | 5 | 15 | 5/20 (%25,0; %11,2-%46,9) | 15/20 (%75,0; %53,1-%88,8) | 15/389 (%3,9; %2,4-%6,3) | 1/389 (%0,3; %0,1-%1,4) |
| debian/openssl | `doğrulanmadı` | 20 | 9 | 11 | 9/20 (%45,0; %25,8-%65,8) | 11/20 (%55,0; %34,2-%74,2) | 15/563 (%2,7; %1,6-%4,3) | 5/563 (%0,9; %0,4-%2,1) |
| debian/openssl | `kesin` | 15 | 15 | 0 | 15/15 (%100,0; %79,6-%100,0) | 0/15 (%0,0; %0,0-%20,4) | 14/563 (%2,5; %1,5-%4,1) | 14/563 (%2,5; %1,5-%4,1) |
| debian/htop | `doğrulanmadı` | 6 | 3 | 3 | 3/6 (%50,0; %18,8-%81,2) | 3/6 (%50,0; %18,8-%81,2) | 3/222 (%1,4; %0,5-%3,9) | 0/222 (%0,0; %0,0-%1,7) |
| debian/zstd | `doğrulanmadı` | 65 | 9 | 56 | 9/65 (%13,8; %7,5-%24,3) | 56/65 (%86,2; %75,7-%92,5) | 49/919 (%5,3; %4,1-%7,0) | 4/919 (%0,4; %0,2-%1,1) |
| debian/tmux | `doğrulanmadı` | 198 | 57 | 141 | 57/198 (%28,8; %22,9-%35,4) | 141/198 (%71,2; %64,5-%77,1) | 191/1851 (%10,3; %9,0-%11,8) | 53/1851 (%2,9; %2,2-%3,7) |
| debian/tmux | `kesin` | 97 | 91 | 6 | 91/97 (%93,8; %87,2-%97,1) | 6/97 (%6,2; %2,9-%12,8) | 88/1851 (%4,8; %3,9-%5,8) | 83/1851 (%4,5; %3,6-%5,5) |
| mac/tmux | `doğrulanmadı` | 245 | 62 | 183 | 62/245 (%25,3; %20,3-%31,1) | 183/245 (%74,7; %68,9-%79,7) | 243/2545 (%9,5; %8,5-%10,8) | 62/2545 (%2,4; %1,9-%3,1) |
| mac/tmux | `kesin` | 150 | 143 | 7 | 143/150 (%95,3; %90,7-%97,7) | 7/150 (%4,7; %2,3-%9,3) | 150/2545 (%5,9; %5,0-%6,9) | 143/2545 (%5,6; %4,8-%6,6) |
| debian/redis-tools | `doğrulanmadı` | 29 | 12 | 17 | 12/29 (%41,4; %25,5-%59,3) | 17/29 (%58,6; %40,7-%74,5) | 8/1458 (%0,5; %0,3-%1,1) | 0/1458 (%0,0; %0,0-%0,3) |

## Birim × kanal grubu

| Birim | Kanal grubu | Ad verilen | Doğru | Yanlış | Kesinlik (%95) | Yanlış oranı (%95) | Kapsam (%95) | Tam ad kapsamı (%95) |
|---|---|---|---|---|---|---|---|---|
| debian/coreutils | `kalan` | 1411 | 1178 | 233 | 1178/1411 (%83,5; %81,5-%85,3) | 233/1411 (%16,5; %14,7-%18,5) | 987/12717 (%7,8; %7,3-%8,2) | 754/12717 (%5,9; %5,5-%6,3) |
| debian/tree | `kalan` | 5 | 5 | 0 | 5/5 (%100,0; %56,5-%100,0) | 0/5 (%0,0; %0,0-%43,5) | 1/110 (%0,9; %0,2-%5,0) | 1/110 (%0,9; %0,2-%5,0) |
| debian/sqlite3 | `kalan` | 20 | 5 | 15 | 5/20 (%25,0; %11,2-%46,9) | 15/20 (%75,0; %53,1-%88,8) | 15/389 (%3,9; %2,4-%6,3) | 1/389 (%0,3; %0,1-%1,4) |
| debian/openssl | `kalan` | 35 | 24 | 11 | 24/35 (%68,6; %52,0-%81,5) | 11/35 (%31,4; %18,6-%48,0) | 29/563 (%5,2; %3,6-%7,3) | 19/563 (%3,4; %2,2-%5,2) |
| debian/htop | `kalan` | 6 | 3 | 3 | 3/6 (%50,0; %18,8-%81,2) | 3/6 (%50,0; %18,8-%81,2) | 3/222 (%1,4; %0,5-%3,9) | 0/222 (%0,0; %0,0-%1,7) |
| debian/zstd | `kalan` | 65 | 9 | 56 | 9/65 (%13,8; %7,5-%24,3) | 56/65 (%86,2; %75,7-%92,5) | 49/919 (%5,3; %4,1-%7,0) | 4/919 (%0,4; %0,2-%1,1) |
| debian/tmux | `kalan` | 295 | 148 | 147 | 148/295 (%50,2; %44,5-%55,8) | 147/295 (%49,8; %44,2-%55,5) | 279/1851 (%15,1; %13,5-%16,8) | 136/1851 (%7,3; %6,2-%8,6) |
| mac/tmux | `kalan` | 395 | 205 | 190 | 205/395 (%51,9; %47,0-%56,8) | 190/395 (%48,1; %43,2-%53,0) | 393/2545 (%15,4; %14,1-%16,9) | 205/2545 (%8,1; %7,1-%9,2) |
| debian/redis-tools | `kalan` | 29 | 12 | 17 | 12/29 (%41,4; %25,5-%59,3) | 17/29 (%58,6; %40,7-%74,5) | 8/1458 (%0,5; %0,3-%1,1) | 0/1458 (%0,0; %0,0-%0,3) |

## Boyut tabakası başına

| Boyut tabakası | Birimler | Ad verilen | Doğru | Yanlış | Kesinlik (%95) | Yanlış oranı (%95) | Kapsam (%95) | Tam ad kapsamı (%95) | Makro kesinlik | Makro yanlış | Makro kapsam | Makro tam ad kapsamı |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `kucuk` | debian/coreutils, debian/sqlite3, debian/tree | 1436 | 1188 | 248 | 1188/1436 (%82,7; %80,7-%84,6) | 248/1436 (%17,3; %15,4-%19,3) | 1003/13216 (%7,6; %7,1-%8,1) | 756/13216 (%5,7; %5,3-%6,1) | %54,2 | %45,8 | %4,2 | %2,4 |
| `orta` | debian/htop, debian/openssl, debian/tmux, debian/zstd, mac/htop | 401 | 184 | 217 | 184/401 (%45,9; %41,1-%50,8) | 217/401 (%54,1; %49,2-%58,9) | 360/4152 (%8,7; %7,8-%9,6) | 159/4152 (%3,8; %3,3-%4,5) | %44,2 | %55,8 | %6,6 | %2,8 |
| `buyuk` | debian/redis-tools, mac/tmux | 424 | 217 | 207 | 217/424 (%51,2; %46,4-%55,9) | 207/424 (%48,8; %44,1-%53,6) | 401/4003 (%10,0; %9,1-%11,0) | 205/4003 (%5,1; %4,5-%5,9) | %46,6 | %53,4 | %8,0 | %4,0 |

## Zenginlik sınıfı başına

| Zenginlik sınıfı | Birimler | Ad verilen | Doğru | Yanlış | Kesinlik (%95) | Yanlış oranı (%95) | Kapsam (%95) | Tam ad kapsamı (%95) | Makro kesinlik | Makro yanlış | Makro kapsam | Makro tam ad kapsamı |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `yoksul` | debian/coreutils, debian/redis-tools, debian/tree, debian/zstd | 1510 | 1204 | 306 | 1204/1510 (%79,7; %77,6-%81,7) | 306/1510 (%20,3; %18,3-%22,4) | 1045/15204 (%6,9; %6,5-%7,3) | 759/15204 (%5,0; %4,7-%5,3) | %46,2 | %53,8 | %3,6 | %1,8 |
| `zengin` | debian/htop, debian/openssl, debian/sqlite3, debian/tmux, mac/htop, mac/tmux | 751 | 385 | 366 | 385/751 (%51,3; %47,7-%54,8) | 366/751 (%48,7; %45,2-%52,3) | 719/6167 (%11,7; %10,9-%12,5) | 361/6167 (%5,9; %5,3-%6,5) | %48,2 | %51,8 | %6,2 | %2,8 |

## Anahtar sayımı (ad haritasının `global` girişleri)

| Birim | `FUN_` anahtarı | Ölçülen ad | `ozdes` | `ghidra_yok` | `ghidra_adli` | `jenerik_ad` | Veri anahtarı | Veri adı | Öbür anahtar | Alt kanal: kayıttan / sonradan / uyuşmuyor |
|---|---|---|---|---|---|---|---|---|---|---|
| debian/coreutils | 1411 | 1411 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 40 / 0 / 0 |
| debian/tree | 5 | 5 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 / 0 / 0 |
| debian/sqlite3 | 20 | 20 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 8 / 0 / 0 |
| debian/openssl | 35 | 35 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 9 / 0 / 0 |
| mac/htop | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 / 0 / 0 |
| debian/htop | 8 | 6 | 0 | 0 | 2 | 0 | 0 | 0 | 0 | 1 / 0 / 0 |
| debian/zstd | 65 | 65 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 51 / 0 / 0 |
| debian/tmux | 295 | 295 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 152 / 0 / 0 |
| mac/tmux | 395 | 395 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 199 / 0 / 0 |
| debian/redis-tools | 33 | 29 | 0 | 0 | 4 | 0 | 0 | 0 | 2 | 3 / 0 / 0 |

C++ (ölçü dışı): debian/zstd: pzstd.

Aynı dosyayı gösteren ikililer (ayrı sayıldı): debian/redis-tools/redis-check-aof = debian/redis-tools/redis-check-rdb.
