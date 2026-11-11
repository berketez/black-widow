# Ürün adlarının ölçümü: yeni

- Kökler: Debian `/Users/apple/karadul_olcum/runs/urun-yeni-93a2956/debian`, Mac `/Users/apple/karadul_olcum/runs/urun-yeni-93a2956/mac`.
- `urun_olc.py` sha256 `06131cdc55f752bc…`; `ks1_olc.py` sha256 `975c4d1265d8610e…`; HEAD `07c3f86`; Ghidra 12.1.2 (119 ikili).
- İkililer: 119 bitti; sorunlar: yok.
- Kol kimliği (köken kaydından; C++ dışı ikili sayısı): `{"genel_esik": 0.7, "koken_var": true, "susturma": true}` × 118.
- Hüküm tam eşitliktir (Mach-O'da baştaki tek `_` soyulur; klon ekli GT'de taban eşitliği; GT'de karşılığı olmayan ad yanlış). Sayım örnek düzeyindedir (ikili başına ad). Bu belgede fonksiyon adı geçmez.

## Toplam (fonksiyon adları)

| | Ad verilen | Doğru | Yanlış | Kesinlik (%95) | Yanlış oranı (%95) | Kapsam (%95) | Tam ad kapsamı (%95) |
|---|---|---|---|---|---|---|---|
| Havuz | 2270 | 1363 | 907 | 1363/2270 (%60,0; %58,0-%62,0) | 907/2270 (%40,0; %38,0-%42,0) | 1773/21371 (%8,3; %7,9-%8,7) | 1120/21371 (%5,2; %5,0-%5,5) |

| Program düzeyi makro | Kesinlik | Yanlış oranı | Kapsam | Tam ad kapsamı |
|---|---|---|---|---|
| Bütün birimler | %39,2 | %60,8 | %4,9 | %2,3 |

Makroya paydası ≥ 10 olan birimler girer; aynı programın platform birimleri önce ortalanır. Duyarlılık (karar dışı), havuz: yalnız ad bekleyen nüfustaki adların kesinliği 1120/1773 (%63,2; %60,9-%65,4); proje normalleştirmesiyle doğru 1592/2270 (%70,1; %68,2-%72,0); tekil adla kesinlik 411/869 (%47,3; %44,0-%50,6).

## Kararlar (bu kol tek başına)

| Karar | Ölçü | Makro | Eşik | Giren programlar | Küçük birimler | Sonuç |
|---|---|---|---|---|---|---|
| (a) yanlış ad oranı | yanlış / ad verilen | %60,8 | ≤ %10,0 | coreutils, openssl, redis-tools, sqlite3, tmux, zstd | debian/htop, debian/tree | `tutmuyor` |
| (b) "kesin" etiketli adlar | doğru / "kesin" etiketli | %97,3 | ≥ %95,0 | openssl, tmux | — | `tutuyor` |

## Birim başına (küçükten büyüğe)

| Birim | İkili | Boyut | Zenginlik | Ad bekleyen | Ad verilen | Doğru | Yanlış | Kesinlik (%95) | Yanlış oranı (%95) | Kapsam (%95) | Tam ad kapsamı (%95) | Nüfus içi kesinlik | Proje norm. | Klon (doğru/n) | Eşlenemeyen |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| debian/coreutils | 106 | `kucuk` | `yoksul` | 12717 | 1420 | 967 | 453 | 967/1420 (%68,1; %65,6-%70,5) | 453/1420 (%31,9; %29,5-%34,4) | 996/12717 (%7,8; %7,4-%8,3) | 754/12717 (%5,9; %5,5-%6,3) | %75,7 | %83,0 | 1/1 | 0 |
| debian/tree | 1 | `kucuk` | `yoksul` | 110 | 5 | 3 | 2 | 3/5 (%60,0; %23,1-%88,2) | 2/5 (%40,0; %11,8-%76,9) | 1/110 (%0,9; %0,2-%5,0) | 1/110 (%0,9; %0,2-%5,0) | %100,0 | %100,0 | 0/0 | 0 |
| debian/sqlite3 | 1 | `kucuk` | `zengin` | 389 | 20 | 3 | 17 | 3/20 (%15,0; %5,2-%36,0) | 17/20 (%85,0; %64,0-%94,8) | 15/389 (%3,9; %2,4-%6,3) | 1/389 (%0,3; %0,1-%1,4) | %6,7 | %25,0 | 0/1 | 0 |
| debian/openssl | 1 | `orta` | `zengin` | 563 | 35 | 22 | 13 | 22/35 (%62,9; %46,3-%76,8) | 13/35 (%37,1; %23,2-%53,7) | 29/563 (%5,2; %3,6-%7,3) | 19/563 (%3,4; %2,2-%5,2) | %65,5 | %68,6 | 1/2 | 0 |
| mac/htop | 1 | `orta` | `zengin` | 597 | 0 | 0 | 0 | — | — | 0/597 (%0,0; %0,0-%0,6) | 0/597 (%0,0; %0,0-%0,6) | — | — | 0/0 | 0 |
| debian/htop | 1 | `orta` | `zengin` | 222 | 6 | 2 | 4 | 2/6 (%33,3; %9,7-%70,0) | 4/6 (%66,7; %30,0-%90,3) | 3/222 (%1,4; %0,5-%3,9) | 0/222 (%0,0; %0,0-%1,7) | %0,0 | %50,0 | 0/0 | 0 |
| debian/zstd | 1 | `orta` | `yoksul` | 919 | 65 | 7 | 58 | 7/65 (%10,8; %5,3-%20,6) | 58/65 (%89,2; %79,4-%94,7) | 49/919 (%5,3; %4,1-%7,0) | 4/919 (%0,4; %0,2-%1,1) | %8,2 | %15,4 | 1/12 | 0 |
| debian/tmux | 1 | `orta` | `zengin` | 1851 | 295 | 146 | 149 | 146/295 (%49,5; %43,8-%55,2) | 149/295 (%50,5; %44,8-%56,2) | 279/1851 (%15,1; %13,5-%16,8) | 136/1851 (%7,3; %6,2-%8,6) | %48,7 | %50,2 | 8/12 | 0 |
| mac/tmux | 1 | `buyuk` | `zengin` | 2545 | 395 | 205 | 190 | 205/395 (%51,9; %47,0-%56,8) | 190/395 (%48,1; %43,2-%53,0) | 393/2545 (%15,4; %14,1-%16,9) | 205/2545 (%8,1; %7,1-%9,2) | %52,2 | %52,2 | 0/1 | 1 |
| debian/redis-tools | 4 | `buyuk` | `yoksul` | 1458 | 29 | 8 | 21 | 8/29 (%27,6; %14,7-%45,7) | 21/29 (%72,4; %54,3-%85,3) | 8/1458 (%0,5; %0,3-%1,1) | 0/1458 (%0,0; %0,0-%0,3) | %0,0 | %41,4 | 0/9 | 0 |

## Etiket başına (havuz ve program düzeyi makro)

| Etiket | Ad verilen | Doğru | Yanlış | Kesinlik (%95) | Yanlış oranı (%95) | Kapsam (%95) | Tam ad kapsamı (%95) | Makro kesinlik | Makro yanlış | Makro kapsam |
|---|---|---|---|---|---|---|---|---|---|---|
| `doğrulanmadı` | 2008 | 1114 | 894 | 1114/2008 (%55,5; %53,3-%57,6) | 894/2008 (%44,5; %42,4-%46,7) | 1521/21371 (%7,1; %6,8-%7,5) | 880/21371 (%4,1; %3,9-%4,4) | %30,5 | %69,5 | %4,0 |
| `kesin` | 262 | 249 | 13 | 249/262 (%95,0; %91,7-%97,1) | 13/262 (%5,0; %2,9-%8,3) | 252/21371 (%1,2; %1,0-%1,3) | 240/21371 (%1,1; %1,0-%1,3) | %97,3 | %2,7 | %1,0 |

## Kanal başına (havuz ve program düzeyi makro)

| Kanal | Ad verilen | Doğru | Yanlış | Kesinlik (%95) | Yanlış oranı (%95) | Kapsam (%95) | Tam ad kapsamı (%95) | Makro kesinlik | Makro yanlış | Makro kapsam |
|---|---|---|---|---|---|---|---|---|---|---|
| `api_param_reverse` | 85 | 1 | 84 | 1/85 (%1,2; %0,2-%6,4) | 84/85 (%98,8; %93,6-%99,8) | 79/21371 (%0,4; %0,3-%0,5) | 1/21371 (%0,0; %0,0-%0,0) | %0,0 | %100,0 | %0,6 |
| `ks1:assert_ust` | 7 | 5 | 2 | 5/7 (%71,4; %35,9-%91,8) | 2/7 (%28,6; %8,2-%64,1) | 7/21371 (%0,0; %0,0-%0,1) | 5/21371 (%0,0; %0,0-%0,1) | — | — | %0,1 |
| `ks1:func_aktarma` | 33 | 33 | 0 | 33/33 (%100,0; %89,6-%100,0) | 0/33 (%0,0; %0,0-%10,4) | 33/21371 (%0,2; %0,1-%0,2) | 33/21371 (%0,2; %0,1-%0,2) | %100,0 | %0,0 | %0,1 |
| `ks1:func_kalibi` | 259 | 246 | 13 | 246/259 (%95,0; %91,6-%97,0) | 13/259 (%5,0; %3,0-%8,4) | 249/21371 (%1,2; %1,0-%1,3) | 237/21371 (%1,1; %1,0-%1,3) | %97,3 | %2,7 | %1,0 |
| `ks1:func_kalibi+func_aktarma` | 3 | 3 | 0 | 3/3 (%100,0; %43,9-%100,0) | 0/3 (%0,0; %0,0-%56,1) | 3/21371 (%0,0; %0,0-%0,0) | 3/21371 (%0,0; %0,0-%0,0) | — | — | %0,0 |
| `on_ad:elf_onyuk` | 458 | 232 | 226 | 232/458 (%50,7; %46,1-%55,2) | 226/458 (%49,3; %44,8-%53,9) | 0/21371 (%0,0; %0,0-%0,0) | 0/21371 (%0,0; %0,0-%0,0) | %58,4 | %41,6 | %0,0 |
| `on_ad:gnulib` | 852 | 621 | 231 | 621/852 (%72,9; %69,8-%75,8) | 231/852 (%27,1; %24,2-%30,2) | 851/21371 (%4,0; %3,7-%4,2) | 621/21371 (%2,9; %2,7-%3,1) | %73,3 | %26,7 | %0,9 |
| `on_ad:main_giris` | 110 | 110 | 0 | 110/110 (%100,0; %96,6-%100,0) | 0/110 (%0,0; %0,0-%3,4) | 110/21371 (%0,5; %0,4-%0,6) | 110/21371 (%0,5; %0,4-%0,6) | %100,0 | %0,0 | %0,3 |
| `string_context/kebap_ad` | 239 | 0 | 239 | 0/239 (%0,0; %0,0-%1,6) | 239/239 (%100,0; %98,4-%100,0) | 234/21371 (%1,1; %1,0-%1,2) | 0/21371 (%0,0; %0,0-%0,0) | %0,0 | %100,0 | %0,7 |
| `string_context/oz_ad` | 224 | 112 | 112 | 112/224 (%50,0; %43,5-%56,5) | 112/224 (%50,0; %43,5-%56,5) | 207/21371 (%1,0; %0,9-%1,1) | 110/21371 (%0,5; %0,4-%0,6) | %48,5 | %51,5 | %1,3 |

## Kanal grubu başına (havuz ve program düzeyi makro)

`susan`: ürünün karar tablosunda susan `string_context` alt kanalları; `kalan`: öbür bütün kanallar. Susturması kapalı bir kolda `kalan` satırı, susturmanın tek başına bırakacağı adların öngörüsüdür (KS-1'in ekleyeceği adlar ve halefler dışında).

| Kanal grubu | Ad verilen | Doğru | Yanlış | Kesinlik (%95) | Yanlış oranı (%95) | Kapsam (%95) | Tam ad kapsamı (%95) | Makro kesinlik | Makro yanlış | Makro kapsam |
|---|---|---|---|---|---|---|---|---|---|---|
| `kalan` | 2270 | 1363 | 907 | 1363/2270 (%60,0; %58,0-%62,0) | 907/2270 (%40,0; %38,0-%42,0) | 1773/21371 (%8,3; %7,9-%8,7) | 1120/21371 (%5,2; %5,0-%5,5) | %39,2 | %60,8 | %4,9 |

## Etiket × kanal (havuz)

| Etiket | Kanal | Ad verilen | Doğru |
|---|---|---|---|
| `doğrulanmadı` | `api_param_reverse` | 85 | 1 |
| `doğrulanmadı` | `ks1:assert_ust` | 7 | 5 |
| `doğrulanmadı` | `ks1:func_aktarma` | 33 | 33 |
| `doğrulanmadı` | `on_ad:elf_onyuk` | 458 | 232 |
| `doğrulanmadı` | `on_ad:gnulib` | 852 | 621 |
| `doğrulanmadı` | `on_ad:main_giris` | 110 | 110 |
| `doğrulanmadı` | `string_context/kebap_ad` | 239 | 0 |
| `doğrulanmadı` | `string_context/oz_ad` | 224 | 112 |
| `kesin` | `ks1:func_kalibi` | 259 | 246 |
| `kesin` | `ks1:func_kalibi+func_aktarma` | 3 | 3 |

## Birim × etiket

| Birim | Etiket | Ad verilen | Doğru | Yanlış | Kesinlik (%95) | Yanlış oranı (%95) | Kapsam (%95) | Tam ad kapsamı (%95) |
|---|---|---|---|---|---|---|---|---|
| debian/coreutils | `doğrulanmadı` | 1420 | 967 | 453 | 967/1420 (%68,1; %65,6-%70,5) | 453/1420 (%31,9; %29,5-%34,4) | 996/12717 (%7,8; %7,4-%8,3) | 754/12717 (%5,9; %5,5-%6,3) |
| debian/tree | `doğrulanmadı` | 5 | 3 | 2 | 3/5 (%60,0; %23,1-%88,2) | 2/5 (%40,0; %11,8-%76,9) | 1/110 (%0,9; %0,2-%5,0) | 1/110 (%0,9; %0,2-%5,0) |
| debian/sqlite3 | `doğrulanmadı` | 20 | 3 | 17 | 3/20 (%15,0; %5,2-%36,0) | 17/20 (%85,0; %64,0-%94,8) | 15/389 (%3,9; %2,4-%6,3) | 1/389 (%0,3; %0,1-%1,4) |
| debian/openssl | `doğrulanmadı` | 20 | 7 | 13 | 7/20 (%35,0; %18,1-%56,7) | 13/20 (%65,0; %43,3-%81,9) | 15/563 (%2,7; %1,6-%4,3) | 5/563 (%0,9; %0,4-%2,1) |
| debian/openssl | `kesin` | 15 | 15 | 0 | 15/15 (%100,0; %79,6-%100,0) | 0/15 (%0,0; %0,0-%20,4) | 14/563 (%2,5; %1,5-%4,1) | 14/563 (%2,5; %1,5-%4,1) |
| debian/htop | `doğrulanmadı` | 6 | 2 | 4 | 2/6 (%33,3; %9,7-%70,0) | 4/6 (%66,7; %30,0-%90,3) | 3/222 (%1,4; %0,5-%3,9) | 0/222 (%0,0; %0,0-%1,7) |
| debian/zstd | `doğrulanmadı` | 65 | 7 | 58 | 7/65 (%10,8; %5,3-%20,6) | 58/65 (%89,2; %79,4-%94,7) | 49/919 (%5,3; %4,1-%7,0) | 4/919 (%0,4; %0,2-%1,1) |
| debian/tmux | `doğrulanmadı` | 198 | 55 | 143 | 55/198 (%27,8; %22,0-%34,4) | 143/198 (%72,2; %65,6-%78,0) | 191/1851 (%10,3; %9,0-%11,8) | 53/1851 (%2,9; %2,2-%3,7) |
| debian/tmux | `kesin` | 97 | 91 | 6 | 91/97 (%93,8; %87,2-%97,1) | 6/97 (%6,2; %2,9-%12,8) | 88/1851 (%4,8; %3,9-%5,8) | 83/1851 (%4,5; %3,6-%5,5) |
| mac/tmux | `doğrulanmadı` | 245 | 62 | 183 | 62/245 (%25,3; %20,3-%31,1) | 183/245 (%74,7; %68,9-%79,7) | 243/2545 (%9,5; %8,5-%10,8) | 62/2545 (%2,4; %1,9-%3,1) |
| mac/tmux | `kesin` | 150 | 143 | 7 | 143/150 (%95,3; %90,7-%97,7) | 7/150 (%4,7; %2,3-%9,3) | 150/2545 (%5,9; %5,0-%6,9) | 143/2545 (%5,6; %4,8-%6,6) |
| debian/redis-tools | `doğrulanmadı` | 29 | 8 | 21 | 8/29 (%27,6; %14,7-%45,7) | 21/29 (%72,4; %54,3-%85,3) | 8/1458 (%0,5; %0,3-%1,1) | 0/1458 (%0,0; %0,0-%0,3) |

## Birim × kanal grubu

| Birim | Kanal grubu | Ad verilen | Doğru | Yanlış | Kesinlik (%95) | Yanlış oranı (%95) | Kapsam (%95) | Tam ad kapsamı (%95) |
|---|---|---|---|---|---|---|---|---|
| debian/coreutils | `kalan` | 1420 | 967 | 453 | 967/1420 (%68,1; %65,6-%70,5) | 453/1420 (%31,9; %29,5-%34,4) | 996/12717 (%7,8; %7,4-%8,3) | 754/12717 (%5,9; %5,5-%6,3) |
| debian/tree | `kalan` | 5 | 3 | 2 | 3/5 (%60,0; %23,1-%88,2) | 2/5 (%40,0; %11,8-%76,9) | 1/110 (%0,9; %0,2-%5,0) | 1/110 (%0,9; %0,2-%5,0) |
| debian/sqlite3 | `kalan` | 20 | 3 | 17 | 3/20 (%15,0; %5,2-%36,0) | 17/20 (%85,0; %64,0-%94,8) | 15/389 (%3,9; %2,4-%6,3) | 1/389 (%0,3; %0,1-%1,4) |
| debian/openssl | `kalan` | 35 | 22 | 13 | 22/35 (%62,9; %46,3-%76,8) | 13/35 (%37,1; %23,2-%53,7) | 29/563 (%5,2; %3,6-%7,3) | 19/563 (%3,4; %2,2-%5,2) |
| debian/htop | `kalan` | 6 | 2 | 4 | 2/6 (%33,3; %9,7-%70,0) | 4/6 (%66,7; %30,0-%90,3) | 3/222 (%1,4; %0,5-%3,9) | 0/222 (%0,0; %0,0-%1,7) |
| debian/zstd | `kalan` | 65 | 7 | 58 | 7/65 (%10,8; %5,3-%20,6) | 58/65 (%89,2; %79,4-%94,7) | 49/919 (%5,3; %4,1-%7,0) | 4/919 (%0,4; %0,2-%1,1) |
| debian/tmux | `kalan` | 295 | 146 | 149 | 146/295 (%49,5; %43,8-%55,2) | 149/295 (%50,5; %44,8-%56,2) | 279/1851 (%15,1; %13,5-%16,8) | 136/1851 (%7,3; %6,2-%8,6) |
| mac/tmux | `kalan` | 395 | 205 | 190 | 205/395 (%51,9; %47,0-%56,8) | 190/395 (%48,1; %43,2-%53,0) | 393/2545 (%15,4; %14,1-%16,9) | 205/2545 (%8,1; %7,1-%9,2) |
| debian/redis-tools | `kalan` | 29 | 8 | 21 | 8/29 (%27,6; %14,7-%45,7) | 21/29 (%72,4; %54,3-%85,3) | 8/1458 (%0,5; %0,3-%1,1) | 0/1458 (%0,0; %0,0-%0,3) |

## Boyut tabakası başına

| Boyut tabakası | Birimler | Ad verilen | Doğru | Yanlış | Kesinlik (%95) | Yanlış oranı (%95) | Kapsam (%95) | Tam ad kapsamı (%95) | Makro kesinlik | Makro yanlış | Makro kapsam | Makro tam ad kapsamı |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `kucuk` | debian/coreutils, debian/sqlite3, debian/tree | 1445 | 973 | 472 | 973/1445 (%67,3; %64,9-%69,7) | 472/1445 (%32,7; %30,3-%35,1) | 1012/13216 (%7,7; %7,2-%8,1) | 756/13216 (%5,7; %5,3-%6,1) | %41,5 | %58,5 | %4,2 | %2,4 |
| `orta` | debian/htop, debian/openssl, debian/tmux, debian/zstd, mac/htop | 401 | 177 | 224 | 177/401 (%44,1; %39,4-%49,0) | 224/401 (%55,9; %51,0-%60,6) | 360/4152 (%8,7; %7,8-%9,6) | 159/4152 (%3,8; %3,3-%4,5) | %41,0 | %59,0 | %6,6 | %2,8 |
| `buyuk` | debian/redis-tools, mac/tmux | 424 | 213 | 211 | 213/424 (%50,2; %45,5-%55,0) | 211/424 (%49,8; %45,0-%54,5) | 401/4003 (%10,0; %9,1-%11,0) | 205/4003 (%5,1; %4,5-%5,9) | %39,7 | %60,3 | %8,0 | %4,0 |

## Zenginlik sınıfı başına

| Zenginlik sınıfı | Birimler | Ad verilen | Doğru | Yanlış | Kesinlik (%95) | Yanlış oranı (%95) | Kapsam (%95) | Tam ad kapsamı (%95) | Makro kesinlik | Makro yanlış | Makro kapsam | Makro tam ad kapsamı |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `yoksul` | debian/coreutils, debian/redis-tools, debian/tree, debian/zstd | 1519 | 985 | 534 | 985/1519 (%64,8; %62,4-%67,2) | 534/1519 (%35,2; %32,8-%37,6) | 1054/15204 (%6,9; %6,5-%7,3) | 759/15204 (%5,0; %4,7-%5,3) | %35,5 | %64,5 | %3,7 | %1,8 |
| `zengin` | debian/htop, debian/openssl, debian/sqlite3, debian/tmux, mac/htop, mac/tmux | 751 | 378 | 373 | 378/751 (%50,3; %46,8-%53,9) | 373/751 (%49,7; %46,1-%53,2) | 719/6167 (%11,7; %10,9-%12,5) | 361/6167 (%5,9; %5,3-%6,5) | %42,9 | %57,1 | %6,2 | %2,8 |

## Anahtar sayımı (ad haritasının `global` girişleri)

| Birim | `FUN_` anahtarı | Ölçülen ad | `ozdes` | `ghidra_yok` | `ghidra_adli` | `jenerik_ad` | Veri anahtarı | Veri adı | Öbür anahtar | Alt kanal: kayıttan / sonradan / uyuşmuyor |
|---|---|---|---|---|---|---|---|---|---|---|
| debian/coreutils | 1420 | 1420 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 40 / 0 / 0 |
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
