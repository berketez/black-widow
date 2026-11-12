# Ürün adlarının ölçümü: taban ve yeni kol

- taban: `taban`; HEAD `fa99144`; kol kimliği `{"genel_esik": null, "koken_var": true, "susturma": null}` × 118.
- yeni: `yeni2`; HEAD `2be12ed`; kol kimliği `{"genel_esik": 0.7, "koken_var": true, "susturma": true}` × 118.
- Ghidra sürümleri iki kolda aynı: evet; eşleme sorunları: yok.
- Öğeler birim, ikili ve adresle eşlenir. Bu belgede fonksiyon adı geçmez.

## Yan yana (fonksiyon adları)

| Kol | Ad verilen | Doğru | Yanlış | Kesinlik (%95) | Yanlış oranı (%95) | Kapsam (%95) | Tam ad kapsamı (%95) | Makro kesinlik | Makro yanlış | Makro kapsam | Makro tam ad kapsamı |
|---|---|---|---|---|---|---|---|---|---|---|---|
| taban | 6394 | 1185 | 5209 | 1185/6394 (%18,5; %17,6-%19,5) | 5209/6394 (%81,5; %80,5-%82,4) | 5381/21371 (%25,2; %24,6-%25,8) | 945/21371 (%4,4; %4,2-%4,7) | %7,8 | %92,2 | %37,6 | %1,5 |
| yeni | 2261 | 1589 | 672 | 1589/2261 (%70,3; %68,4-%72,1) | 672/2261 (%29,7; %27,9-%31,6) | 1764/21371 (%8,3; %7,9-%8,6) | 1120/21371 (%5,2; %5,0-%5,5) | %47,2 | %52,8 | %4,9 | %2,3 |

| Kol | "kesin" etiketli ad | Doğru | Kesinlik (havuz) | Makro kesinlik | Kapsam (havuz) |
|---|---|---|---|---|---|
| taban | 0 | 0 | — | — | — |
| yeni | 262 | 249 | 249/262 (%95,0; %91,7-%97,1) | %97,3 | 252/21371 (%1,2; %1,0-%1,3) |

## Kararlar

| Karar | Taban | Yeni |
|---|---|---|
| (a) yanlış ad oranı (makro) | %92,2 → `tutmuyor` | %52,8 → `tutmuyor` |
| (b) "kesin" etiketli adların kesinliği (makro) | — → `yetersiz` | %97,3 → `tutuyor` |

(c) Kaybedilen doğru ad (havuz): 16/1185 (%1,4; %0,8-%2,2); sınır > %15,0 → `beklenen_aralikta`. Sınırı aşan birimler: yok. Program düzeyi makro: %3,3.

Yön: iki kolda da en az 10 ad verilen birimlerde (debian/coreutils, debian/openssl, debian/redis-tools, debian/sqlite3, debian/tmux, debian/zstd, mac/tmux) yeni kolun yanlış oranı tabanınkinden düşük olmayanlar: yok → `beklenen_aralikta`.

## Birim başına farklar

| Birim | İkili | Taban: ad / doğru / yanlış | Yeni: ad / doğru / yanlış | Yanlış oranı taban → yeni | Kaybedilen doğru (silinen + yanlışa dönen) | Kayıp oranı | Kazanılan doğru | Giderilen yanlış | Yeni yanlış |
|---|---|---|---|---|---|---|---|---|---|
| debian/coreutils | 106 | 2652 / 967 / 1685 | 1411 / 1178 / 233 | %63,5 → %16,5 | 3 (3 + 0) | 3/967 (%0,3; %0,1-%0,9) | 214 | 1452 | 0 |
| debian/htop | 1 | 72 / 2 / 70 | 6 / 3 / 3 | %97,2 → %50,0 | 0 (0 + 0) | 0/2 (%0,0; %0,0-%65,8) | 1 | 67 | 0 |
| debian/openssl | 1 | 372 / 7 / 365 | 35 / 24 / 11 | %98,1 → %31,4 | 1 (1 + 0) | 1/7 (%14,3; %2,6-%51,3) | 18 | 354 | 0 |
| debian/redis-tools | 4 | 891 / 8 / 883 | 29 / 12 / 17 | %99,1 → %58,6 | 0 (0 + 0) | 0/8 (%0,0; %0,0-%32,4) | 4 | 866 | 0 |
| debian/sqlite3 | 1 | 151 / 3 / 148 | 20 / 5 / 15 | %98,0 → %75,0 | 0 (0 + 0) | 0/3 (%0,0; %0,0-%56,1) | 2 | 133 | 0 |
| debian/tmux | 1 | 636 / 88 / 548 | 295 / 148 / 147 | %86,2 → %49,8 | 5 (5 + 0) | 5/88 (%5,7; %2,5-%12,6) | 65 | 401 | 0 |
| debian/tree | 1 | 50 / 3 / 47 | 5 / 5 / 0 | %94,0 → %0,0 | 0 (0 + 0) | 0/3 (%0,0; %0,0-%56,1) | 2 | 47 | 0 |
| debian/zstd | 1 | 594 / 5 / 589 | 65 / 9 / 56 | %99,2 → %86,2 | 0 (0 + 0) | 0/5 (%0,0; %0,0-%43,5) | 4 | 534 | 1 |
| mac/htop | 1 | 101 / 0 / 101 | 0 / 0 / 0 | %100,0 → — | 0 (0 + 0) | — | 0 | 101 | 0 |
| mac/tmux | 1 | 875 / 102 / 773 | 395 / 205 / 190 | %88,3 → %48,1 | 7 (6 + 1) | 7/102 (%6,9; %3,4-%13,5) | 110 | 584 | 1 |
| **Toplam** | 118 | 6394 / 1185 / 5209 | 2261 / 1589 / 672 | %81,5 → %29,7 | 16 (15 + 1) | 16/1185 (%1,4; %0,8-%2,2) | 420 | 4539 | 2 |

## Kaybedilen ve kazanılan doğru adların kanalı

| Yön | Kanal | Ad |
|---|---|---|
| kaybedilen (taban kanalı) | `string_context/bicim_dizgisi` | 2 |
| kaybedilen (taban kanalı) | `string_context/hata_iletisi` | 1 |
| kaybedilen (taban kanalı) | `string_context/oz_ad` | 1 |
| kaybedilen (taban kanalı) | `string_context/tanimlayici` | 1 |
| kaybedilen (taban kanalı) | `string_context/tek_sozcuk` | 11 |
| kazanılan (yeni kanalı) | `api_param_reverse` | 1 |
| kazanılan (yeni kanalı) | `ks1:assert_ust` | 5 |
| kazanılan (yeni kanalı) | `ks1:func_aktarma` | 28 |
| kazanılan (yeni kanalı) | `ks1:func_kalibi` | 153 |
| kazanılan (yeni kanalı) | `ks1:func_kalibi+func_aktarma` | 3 |
| kazanılan (yeni kanalı) | `on_ad:elf_onyuk` | 226 |
| kazanılan (yeni kanalı) | `string_context/oz_ad` | 4 |
