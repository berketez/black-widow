# Ürün adlarının ölçümü: onarim

- Kökler: Debian `/Users/apple/karadul_olcum/runs/urun-onarim-a62f15e/debian`, Mac `/Users/apple/karadul_olcum/runs/urun-onarim-a62f15e/mac`.
- `urun_olc.py` sha256 `06131cdc55f752bc…`; `ks1_olc.py` sha256 `975c4d1265d8610e…`; HEAD `a62f15e`; Ghidra 12.1.2 (119 ikili).
- İkililer: 119 bitti; sorunlar: yok.
- Kol kimliği (köken kaydından; C++ dışı ikili sayısı): `{"genel_esik": 0.7, "koken_var": true, "susturma": true}` × 118.
- Hüküm tam eşitliktir (Mach-O'da baştaki tek `_` soyulur; klon ekli GT'de taban eşitliği; GT'de karşılığı olmayan ad yanlış). Sayım örnek düzeyindedir (ikili başına ad). Bu belgede fonksiyon adı geçmez.

## Toplam (fonksiyon adları)

| | Ad verilen | Doğru | Yanlış | Kesinlik (%95) | Yanlış oranı (%95) | Kapsam (%95) | Tam ad kapsamı (%95) |
|---|---|---|---|---|---|---|---|
| Havuz | 1800 | 1681 | 119 | 1681/1800 (%93,4; %92,2-%94,5) | 119/1800 (%6,6; %5,5-%7,8) | 1315/21371 (%6,2; %5,8-%6,5) | 1212/21371 (%5,7; %5,4-%6,0) |

| Program düzeyi makro | Kesinlik | Yanlış oranı | Kapsam | Tam ad kapsamı |
|---|---|---|---|---|
| Bütün birimler | %69,0 | %31,0 | %3,3 | %2,4 |

Makroya paydası ≥ 10 olan birimler girer; aynı programın platform birimleri önce ortalanır. Duyarlılık (karar dışı), havuz: yalnız ad bekleyen nüfustaki adların kesinliği 1212/1315 (%92,2; %90,6-%93,5); proje normalleştirmesiyle doğru 1684/1800 (%93,6; %92,3-%94,6); tekil adla kesinlik 422/535 (%78,9; %75,2-%82,1).

## Kararlar (bu kol tek başına)

| Karar | Ölçü | Makro | Eşik | Giren programlar | Küçük birimler | Sonuç |
|---|---|---|---|---|---|---|
| (a) yanlış ad oranı | yanlış / ad verilen | %31,0 | ≤ %10,0 | coreutils, openssl, redis-tools, sqlite3, tmux, zstd | debian/htop, debian/tree | `tutmuyor` |
| (b) "kesin" etiketli adlar | doğru / "kesin" etiketli | %97,3 | ≥ %95,0 | openssl, tmux | — | `tutuyor` |

## Birim başına (küçükten büyüğe)

| Birim | İkili | Boyut | Zenginlik | Ad bekleyen | Ad verilen | Doğru | Yanlış | Kesinlik (%95) | Yanlış oranı (%95) | Kapsam (%95) | Tam ad kapsamı (%95) | Nüfus içi kesinlik | Proje norm. | Klon (doğru/n) | Eşlenemeyen |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| debian/coreutils | 106 | `kucuk` | `yoksul` | 12717 | 1281 | 1271 | 10 | 1271/1281 (%99,2; %98,6-%99,6) | 10/1281 (%0,8; %0,4-%1,4) | 857/12717 (%6,7; %6,3-%7,2) | 847/12717 (%6,7; %6,2-%7,1) | %98,8 | %99,3 | 1/1 | 0 |
| debian/tree | 1 | `kucuk` | `yoksul` | 110 | 5 | 5 | 0 | 5/5 (%100,0; %56,5-%100,0) | 0/5 (%0,0; %0,0-%43,5) | 1/110 (%0,9; %0,2-%5,0) | 1/110 (%0,9; %0,2-%5,0) | %100,0 | %100,0 | 0/0 | 0 |
| debian/sqlite3 | 1 | `kucuk` | `zengin` | 389 | 12 | 5 | 7 | 5/12 (%41,7; %19,3-%68,0) | 7/12 (%58,3; %31,9-%80,7) | 7/389 (%1,8; %0,9-%3,7) | 1/389 (%0,3; %0,1-%1,4) | %14,3 | %41,7 | 0/1 | 0 |
| debian/openssl | 1 | `orta` | `zengin` | 563 | 26 | 23 | 3 | 23/26 (%88,5; %71,0-%96,0) | 3/26 (%11,5; %4,0-%29,0) | 21/563 (%3,7; %2,5-%5,6) | 18/563 (%3,2; %2,0-%5,0) | %85,7 | %88,5 | 1/1 | 0 |
| mac/htop | 1 | `orta` | `zengin` | 597 | 0 | 0 | 0 | — | — | 0/597 (%0,0; %0,0-%0,6) | 0/597 (%0,0; %0,0-%0,6) | — | — | 0/0 | 0 |
| debian/htop | 1 | `orta` | `zengin` | 222 | 4 | 3 | 1 | 3/4 (%75,0; %30,1-%95,4) | 1/4 (%25,0; %4,6-%69,9) | 1/222 (%0,5; %0,1-%2,5) | 0/222 (%0,0; %0,0-%1,7) | %0,0 | %75,0 | 0/0 | 0 |
| debian/zstd | 1 | `orta` | `yoksul` | 919 | 55 | 9 | 46 | 9/55 (%16,4; %8,9-%28,3) | 46/55 (%83,6; %71,7-%91,1) | 39/919 (%4,2; %3,1-%5,8) | 4/919 (%0,4; %0,2-%1,1) | %10,3 | %18,2 | 1/12 | 0 |
| debian/tmux | 1 | `orta` | `zengin` | 1851 | 166 | 148 | 18 | 148/166 (%89,2; %83,5-%93,0) | 18/166 (%10,8; %7,0-%16,5) | 153/1851 (%8,3; %7,1-%9,6) | 136/1851 (%7,3; %6,2-%8,6) | %88,9 | %89,2 | 8/9 | 0 |
| mac/tmux | 1 | `buyuk` | `zengin` | 2545 | 236 | 205 | 31 | 205/236 (%86,9; %82,0-%90,6) | 31/236 (%13,1; %9,4-%18,0) | 235/2545 (%9,2; %8,2-%10,4) | 205/2545 (%8,1; %7,1-%9,2) | %87,2 | %87,3 | 0/1 | 0 |
| debian/redis-tools | 4 | `buyuk` | `yoksul` | 1458 | 15 | 12 | 3 | 12/15 (%80,0; %54,8-%93,0) | 3/15 (%20,0; %7,0-%45,2) | 1/1458 (%0,1; %0,0-%0,4) | 0/1458 (%0,0; %0,0-%0,3) | %0,0 | %80,0 | 0/2 | 0 |

## Etiket başına (havuz ve program düzeyi makro)

| Etiket | Ad verilen | Doğru | Yanlış | Kesinlik (%95) | Yanlış oranı (%95) | Kapsam (%95) | Tam ad kapsamı (%95) | Makro kesinlik | Makro yanlış | Makro kapsam |
|---|---|---|---|---|---|---|---|---|---|---|
| `doğrulanmadı` | 1538 | 1432 | 106 | 1432/1538 (%93,1; %91,7-%94,3) | 106/1538 (%6,9; %5,7-%8,3) | 1063/21371 (%5,0; %4,7-%5,3) | 972/21371 (%4,5; %4,3-%4,8) | %64,6 | %35,4 | %2,3 |
| `kesin` | 262 | 249 | 13 | 249/262 (%95,0; %91,7-%97,1) | 13/262 (%5,0; %2,9-%8,3) | 252/21371 (%1,2; %1,0-%1,3) | 240/21371 (%1,1; %1,0-%1,3) | %97,3 | %2,7 | %1,0 |

## Kanal başına (havuz ve program düzeyi makro)

| Kanal | Ad verilen | Doğru | Yanlış | Kesinlik (%95) | Yanlış oranı (%95) | Kapsam (%95) | Tam ad kapsamı (%95) | Makro kesinlik | Makro yanlış | Makro kapsam |
|---|---|---|---|---|---|---|---|---|---|---|
| `ks1:assert_ust` | 7 | 5 | 2 | 5/7 (%71,4; %35,9-%91,8) | 2/7 (%28,6; %8,2-%64,1) | 7/21371 (%0,0; %0,0-%0,1) | 5/21371 (%0,0; %0,0-%0,1) | — | — | %0,1 |
| `ks1:func_aktarma` | 33 | 33 | 0 | 33/33 (%100,0; %89,6-%100,0) | 0/33 (%0,0; %0,0-%10,4) | 33/21371 (%0,2; %0,1-%0,2) | 33/21371 (%0,2; %0,1-%0,2) | %100,0 | %0,0 | %0,1 |
| `ks1:func_kalibi` | 259 | 246 | 13 | 246/259 (%95,0; %91,6-%97,0) | 13/259 (%5,0; %3,0-%8,4) | 249/21371 (%1,2; %1,0-%1,3) | 237/21371 (%1,1; %1,0-%1,3) | %97,3 | %2,7 | %1,0 |
| `ks1:func_kalibi+func_aktarma` | 3 | 3 | 0 | 3/3 (%100,0; %43,9-%100,0) | 0/3 (%0,0; %0,0-%56,1) | 3/21371 (%0,0; %0,0-%0,0) | 3/21371 (%0,0; %0,0-%0,0) | — | — | %0,0 |
| `on_ad:elf_onyuk` | 458 | 458 | 0 | 458/458 (%100,0; %99,2-%100,0) | 0/458 (%0,0; %0,0-%0,8) | 0/21371 (%0,0; %0,0-%0,0) | 0/21371 (%0,0; %0,0-%0,0) | %100,0 | %0,0 | %0,0 |
| `on_ad:gnulib` | 733 | 733 | 0 | 733/733 (%100,0; %99,5-%100,0) | 0/733 (%0,0; %0,0-%0,5) | 733/21371 (%3,4; %3,2-%3,7) | 733/21371 (%3,4; %3,2-%3,7) | %100,0 | %0,0 | %0,7 |
| `on_ad:main_giris` | 110 | 110 | 0 | 110/110 (%100,0; %96,6-%100,0) | 0/110 (%0,0; %0,0-%3,4) | 110/21371 (%0,5; %0,4-%0,6) | 110/21371 (%0,5; %0,4-%0,6) | %100,0 | %0,0 | %0,3 |
| `string_context/oz_ad` | 197 | 93 | 104 | 93/197 (%47,2; %40,4-%54,2) | 104/197 (%52,8; %45,8-%59,6) | 180/21371 (%0,8; %0,7-%1,0) | 91/21371 (%0,4; %0,4-%0,5) | %41,3 | %58,7 | %1,2 |

## Kanal grubu başına (havuz ve program düzeyi makro)

`susan`: ürünün karar tablosunda susan `string_context` alt kanalları; `kalan`: öbür bütün kanallar. Susturması kapalı bir kolda `kalan` satırı, susturmanın tek başına bırakacağı adların öngörüsüdür (KS-1'in ekleyeceği adlar ve halefler dışında).

| Kanal grubu | Ad verilen | Doğru | Yanlış | Kesinlik (%95) | Yanlış oranı (%95) | Kapsam (%95) | Tam ad kapsamı (%95) | Makro kesinlik | Makro yanlış | Makro kapsam |
|---|---|---|---|---|---|---|---|---|---|---|
| `kalan` | 1800 | 1681 | 119 | 1681/1800 (%93,4; %92,2-%94,5) | 119/1800 (%6,6; %5,5-%7,8) | 1315/21371 (%6,2; %5,8-%6,5) | 1212/21371 (%5,7; %5,4-%6,0) | %69,0 | %31,0 | %3,3 |

## Etiket × kanal (havuz)

| Etiket | Kanal | Ad verilen | Doğru |
|---|---|---|---|
| `doğrulanmadı` | `ks1:assert_ust` | 7 | 5 |
| `doğrulanmadı` | `ks1:func_aktarma` | 33 | 33 |
| `doğrulanmadı` | `on_ad:elf_onyuk` | 458 | 458 |
| `doğrulanmadı` | `on_ad:gnulib` | 733 | 733 |
| `doğrulanmadı` | `on_ad:main_giris` | 110 | 110 |
| `doğrulanmadı` | `string_context/oz_ad` | 197 | 93 |
| `kesin` | `ks1:func_kalibi` | 259 | 246 |
| `kesin` | `ks1:func_kalibi+func_aktarma` | 3 | 3 |

## Birim × etiket

| Birim | Etiket | Ad verilen | Doğru | Yanlış | Kesinlik (%95) | Yanlış oranı (%95) | Kapsam (%95) | Tam ad kapsamı (%95) |
|---|---|---|---|---|---|---|---|---|
| debian/coreutils | `doğrulanmadı` | 1281 | 1271 | 10 | 1271/1281 (%99,2; %98,6-%99,6) | 10/1281 (%0,8; %0,4-%1,4) | 857/12717 (%6,7; %6,3-%7,2) | 847/12717 (%6,7; %6,2-%7,1) |
| debian/tree | `doğrulanmadı` | 5 | 5 | 0 | 5/5 (%100,0; %56,5-%100,0) | 0/5 (%0,0; %0,0-%43,5) | 1/110 (%0,9; %0,2-%5,0) | 1/110 (%0,9; %0,2-%5,0) |
| debian/sqlite3 | `doğrulanmadı` | 12 | 5 | 7 | 5/12 (%41,7; %19,3-%68,0) | 7/12 (%58,3; %31,9-%80,7) | 7/389 (%1,8; %0,9-%3,7) | 1/389 (%0,3; %0,1-%1,4) |
| debian/openssl | `doğrulanmadı` | 11 | 8 | 3 | 8/11 (%72,7; %43,4-%90,2) | 3/11 (%27,3; %9,8-%56,6) | 7/563 (%1,2; %0,6-%2,5) | 4/563 (%0,7; %0,3-%1,8) |
| debian/openssl | `kesin` | 15 | 15 | 0 | 15/15 (%100,0; %79,6-%100,0) | 0/15 (%0,0; %0,0-%20,4) | 14/563 (%2,5; %1,5-%4,1) | 14/563 (%2,5; %1,5-%4,1) |
| debian/htop | `doğrulanmadı` | 4 | 3 | 1 | 3/4 (%75,0; %30,1-%95,4) | 1/4 (%25,0; %4,6-%69,9) | 1/222 (%0,5; %0,1-%2,5) | 0/222 (%0,0; %0,0-%1,7) |
| debian/zstd | `doğrulanmadı` | 55 | 9 | 46 | 9/55 (%16,4; %8,9-%28,3) | 46/55 (%83,6; %71,7-%91,1) | 39/919 (%4,2; %3,1-%5,8) | 4/919 (%0,4; %0,2-%1,1) |
| debian/tmux | `doğrulanmadı` | 69 | 57 | 12 | 57/69 (%82,6; %72,0-%89,8) | 12/69 (%17,4; %10,2-%28,0) | 65/1851 (%3,5; %2,8-%4,5) | 53/1851 (%2,9; %2,2-%3,7) |
| debian/tmux | `kesin` | 97 | 91 | 6 | 91/97 (%93,8; %87,2-%97,1) | 6/97 (%6,2; %2,9-%12,8) | 88/1851 (%4,8; %3,9-%5,8) | 83/1851 (%4,5; %3,6-%5,5) |
| mac/tmux | `doğrulanmadı` | 86 | 62 | 24 | 62/86 (%72,1; %61,8-%80,5) | 24/86 (%27,9; %19,5-%38,2) | 85/2545 (%3,3; %2,7-%4,1) | 62/2545 (%2,4; %1,9-%3,1) |
| mac/tmux | `kesin` | 150 | 143 | 7 | 143/150 (%95,3; %90,7-%97,7) | 7/150 (%4,7; %2,3-%9,3) | 150/2545 (%5,9; %5,0-%6,9) | 143/2545 (%5,6; %4,8-%6,6) |
| debian/redis-tools | `doğrulanmadı` | 15 | 12 | 3 | 12/15 (%80,0; %54,8-%93,0) | 3/15 (%20,0; %7,0-%45,2) | 1/1458 (%0,1; %0,0-%0,4) | 0/1458 (%0,0; %0,0-%0,3) |

## Birim × kanal grubu

| Birim | Kanal grubu | Ad verilen | Doğru | Yanlış | Kesinlik (%95) | Yanlış oranı (%95) | Kapsam (%95) | Tam ad kapsamı (%95) |
|---|---|---|---|---|---|---|---|---|
| debian/coreutils | `kalan` | 1281 | 1271 | 10 | 1271/1281 (%99,2; %98,6-%99,6) | 10/1281 (%0,8; %0,4-%1,4) | 857/12717 (%6,7; %6,3-%7,2) | 847/12717 (%6,7; %6,2-%7,1) |
| debian/tree | `kalan` | 5 | 5 | 0 | 5/5 (%100,0; %56,5-%100,0) | 0/5 (%0,0; %0,0-%43,5) | 1/110 (%0,9; %0,2-%5,0) | 1/110 (%0,9; %0,2-%5,0) |
| debian/sqlite3 | `kalan` | 12 | 5 | 7 | 5/12 (%41,7; %19,3-%68,0) | 7/12 (%58,3; %31,9-%80,7) | 7/389 (%1,8; %0,9-%3,7) | 1/389 (%0,3; %0,1-%1,4) |
| debian/openssl | `kalan` | 26 | 23 | 3 | 23/26 (%88,5; %71,0-%96,0) | 3/26 (%11,5; %4,0-%29,0) | 21/563 (%3,7; %2,5-%5,6) | 18/563 (%3,2; %2,0-%5,0) |
| debian/htop | `kalan` | 4 | 3 | 1 | 3/4 (%75,0; %30,1-%95,4) | 1/4 (%25,0; %4,6-%69,9) | 1/222 (%0,5; %0,1-%2,5) | 0/222 (%0,0; %0,0-%1,7) |
| debian/zstd | `kalan` | 55 | 9 | 46 | 9/55 (%16,4; %8,9-%28,3) | 46/55 (%83,6; %71,7-%91,1) | 39/919 (%4,2; %3,1-%5,8) | 4/919 (%0,4; %0,2-%1,1) |
| debian/tmux | `kalan` | 166 | 148 | 18 | 148/166 (%89,2; %83,5-%93,0) | 18/166 (%10,8; %7,0-%16,5) | 153/1851 (%8,3; %7,1-%9,6) | 136/1851 (%7,3; %6,2-%8,6) |
| mac/tmux | `kalan` | 236 | 205 | 31 | 205/236 (%86,9; %82,0-%90,6) | 31/236 (%13,1; %9,4-%18,0) | 235/2545 (%9,2; %8,2-%10,4) | 205/2545 (%8,1; %7,1-%9,2) |
| debian/redis-tools | `kalan` | 15 | 12 | 3 | 12/15 (%80,0; %54,8-%93,0) | 3/15 (%20,0; %7,0-%45,2) | 1/1458 (%0,1; %0,0-%0,4) | 0/1458 (%0,0; %0,0-%0,3) |

## Boyut tabakası başına

| Boyut tabakası | Birimler | Ad verilen | Doğru | Yanlış | Kesinlik (%95) | Yanlış oranı (%95) | Kapsam (%95) | Tam ad kapsamı (%95) | Makro kesinlik | Makro yanlış | Makro kapsam | Makro tam ad kapsamı |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `kucuk` | debian/coreutils, debian/sqlite3, debian/tree | 1298 | 1281 | 17 | 1281/1298 (%98,7; %97,9-%99,2) | 17/1298 (%1,3; %0,8-%2,1) | 865/13216 (%6,5; %6,1-%7,0) | 849/13216 (%6,4; %6,0-%6,9) | %70,4 | %29,6 | %3,1 | %2,6 |
| `orta` | debian/htop, debian/openssl, debian/tmux, debian/zstd, mac/htop | 251 | 183 | 68 | 183/251 (%72,9; %67,1-%78,0) | 68/251 (%27,1; %22,0-%32,9) | 214/4152 (%5,2; %4,5-%5,9) | 158/4152 (%3,8; %3,3-%4,4) | %64,7 | %35,3 | %4,1 | %2,7 |
| `buyuk` | debian/redis-tools, mac/tmux | 251 | 217 | 34 | 217/251 (%86,5; %81,7-%90,1) | 34/251 (%13,5; %9,9-%18,3) | 236/4003 (%5,9; %5,2-%6,7) | 205/4003 (%5,1; %4,5-%5,9) | %83,4 | %16,6 | %4,7 | %4,0 |

## Zenginlik sınıfı başına

| Zenginlik sınıfı | Birimler | Ad verilen | Doğru | Yanlış | Kesinlik (%95) | Yanlış oranı (%95) | Kapsam (%95) | Tam ad kapsamı (%95) | Makro kesinlik | Makro yanlış | Makro kapsam | Makro tam ad kapsamı |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `yoksul` | debian/coreutils, debian/redis-tools, debian/tree, debian/zstd | 1356 | 1297 | 59 | 1297/1356 (%95,6; %94,4-%96,6) | 59/1356 (%4,4; %3,4-%5,6) | 898/15204 (%5,9; %5,5-%6,3) | 852/15204 (%5,6; %5,2-%6,0) | %65,2 | %34,8 | %3,0 | %2,0 |
| `zengin` | debian/htop, debian/openssl, debian/sqlite3, debian/tmux, mac/htop, mac/tmux | 444 | 384 | 60 | 384/444 (%86,5; %83,0-%89,4) | 60/444 (%13,5; %10,6-%17,0) | 417/6167 (%6,8; %6,2-%7,4) | 360/6167 (%5,8; %5,3-%6,5) | %72,7 | %27,3 | %3,6 | %2,8 |

## Anahtar sayımı (ad haritasının `global` girişleri)

| Birim | `FUN_` anahtarı | Ölçülen ad | `ozdes` | `ghidra_yok` | `ghidra_adli` | `jenerik_ad` | Veri anahtarı | Veri adı | Öbür anahtar | Alt kanal: kayıttan / sonradan / uyuşmuyor |
|---|---|---|---|---|---|---|---|---|---|---|
| debian/coreutils | 1281 | 1281 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 21 / 0 / 0 |
| debian/tree | 5 | 5 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 / 0 / 0 |
| debian/sqlite3 | 12 | 12 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 7 / 0 / 0 |
| debian/openssl | 26 | 26 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 6 / 0 / 0 |
| mac/htop | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 / 0 / 0 |
| debian/htop | 5 | 4 | 0 | 0 | 1 | 0 | 0 | 0 | 0 | 1 / 0 / 0 |
| debian/zstd | 55 | 55 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 45 / 0 / 0 |
| debian/tmux | 166 | 166 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 50 / 0 / 0 |
| mac/tmux | 236 | 236 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 64 / 0 / 0 |
| debian/redis-tools | 19 | 15 | 0 | 0 | 4 | 0 | 0 | 0 | 0 | 3 / 0 / 0 |

C++ (ölçü dışı): debian/zstd: pzstd.

Aynı dosyayı gösteren ikililer (ayrı sayıldı): debian/redis-tools/redis-check-aof = debian/redis-tools/redis-check-rdb.
