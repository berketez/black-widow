# Ürün adlarının ölçümü: taban ve yeni kol

- taban: `taban`; HEAD `fa99144`; kol kimliği `{"genel_esik": null, "koken_var": true, "susturma": null}` × 118.
- yeni: `yeni`; HEAD `07c3f86`; kol kimliği `{"genel_esik": 0.7, "koken_var": true, "susturma": true}` × 118.
- Ghidra sürümleri iki kolda aynı: evet; eşleme sorunları: yok.
- Öğeler birim, ikili ve adresle eşlenir. Bu belgede fonksiyon adı geçmez.

## Yan yana (fonksiyon adları)

| Kol | Ad verilen | Doğru | Yanlış | Kesinlik (%95) | Yanlış oranı (%95) | Kapsam (%95) | Tam ad kapsamı (%95) | Makro kesinlik | Makro yanlış | Makro kapsam | Makro tam ad kapsamı |
|---|---|---|---|---|---|---|---|---|---|---|---|
| taban | 6394 | 1185 | 5209 | 1185/6394 (%18,5; %17,6-%19,5) | 5209/6394 (%81,5; %80,5-%82,4) | 5381/21371 (%25,2; %24,6-%25,8) | 945/21371 (%4,4; %4,2-%4,7) | %7,8 | %92,2 | %37,6 | %1,5 |
| yeni | 2270 | 1363 | 907 | 1363/2270 (%60,0; %58,0-%62,0) | 907/2270 (%40,0; %38,0-%42,0) | 1773/21371 (%8,3; %7,9-%8,7) | 1120/21371 (%5,2; %5,0-%5,5) | %39,2 | %60,8 | %4,9 | %2,3 |

| Kol | "kesin" etiketli ad | Doğru | Kesinlik (havuz) | Makro kesinlik | Kapsam (havuz) |
|---|---|---|---|---|---|
| taban | 0 | 0 | — | — | — |
| yeni | 262 | 249 | 249/262 (%95,0; %91,7-%97,1) | %97,3 | 252/21371 (%1,2; %1,0-%1,3) |

## Kararlar

| Karar | Taban | Yeni |
|---|---|---|
| (a) yanlış ad oranı (makro) | %92,2 → `tutmuyor` | %60,8 → `tutmuyor` |
| (b) "kesin" etiketli adların kesinliği (makro) | — → `yetersiz` | %97,3 → `tutuyor` |

(c) Kaybedilen doğru ad (havuz): 16/1185 (%1,4; %0,8-%2,2); sınır > %15,0 → `beklenen_aralikta`. Sınırı aşan birimler: yok. Program düzeyi makro: %3,3.

Yön: iki kolda da en az 10 ad verilen birimlerde (debian/coreutils, debian/openssl, debian/redis-tools, debian/sqlite3, debian/tmux, debian/zstd, mac/tmux) yeni kolun yanlış oranı tabanınkinden düşük olmayanlar: yok → `beklenen_aralikta`.

## Birim başına farklar

| Birim | İkili | Taban: ad / doğru / yanlış | Yeni: ad / doğru / yanlış | Yanlış oranı taban → yeni | Kaybedilen doğru (silinen + yanlışa dönen) | Kayıp oranı | Kazanılan doğru | Giderilen yanlış | Yeni yanlış |
|---|---|---|---|---|---|---|---|---|---|
| debian/coreutils | 106 | 2652 / 967 / 1685 | 1420 / 967 / 453 | %63,5 → %31,9 | 3 (3 + 0) | 3/967 (%0,3; %0,1-%0,9) | 3 | 1232 | 0 |
| debian/htop | 1 | 72 / 2 / 70 | 6 / 2 / 4 | %97,2 → %66,7 | 0 (0 + 0) | 0/2 (%0,0; %0,0-%65,8) | 0 | 66 | 0 |
| debian/openssl | 1 | 372 / 7 / 365 | 35 / 22 / 13 | %98,1 → %37,1 | 1 (1 + 0) | 1/7 (%14,3; %2,6-%51,3) | 16 | 352 | 0 |
| debian/redis-tools | 4 | 891 / 8 / 883 | 29 / 8 / 21 | %99,1 → %72,4 | 0 (0 + 0) | 0/8 (%0,0; %0,0-%32,4) | 0 | 862 | 0 |
| debian/sqlite3 | 1 | 151 / 3 / 148 | 20 / 3 / 17 | %98,0 → %85,0 | 0 (0 + 0) | 0/3 (%0,0; %0,0-%56,1) | 0 | 131 | 0 |
| debian/tmux | 1 | 636 / 88 / 548 | 295 / 146 / 149 | %86,2 → %50,5 | 5 (5 + 0) | 5/88 (%5,7; %2,5-%12,6) | 63 | 399 | 0 |
| debian/tree | 1 | 50 / 3 / 47 | 5 / 3 / 2 | %94,0 → %40,0 | 0 (0 + 0) | 0/3 (%0,0; %0,0-%56,1) | 0 | 45 | 0 |
| debian/zstd | 1 | 594 / 5 / 589 | 65 / 7 / 58 | %99,2 → %89,2 | 0 (0 + 0) | 0/5 (%0,0; %0,0-%43,5) | 2 | 532 | 1 |
| mac/htop | 1 | 101 / 0 / 101 | 0 / 0 / 0 | %100,0 → — | 0 (0 + 0) | — | 0 | 101 | 0 |
| mac/tmux | 1 | 875 / 102 / 773 | 395 / 205 / 190 | %88,3 → %48,1 | 7 (6 + 1) | 7/102 (%6,9; %3,4-%13,5) | 110 | 584 | 1 |
| **Toplam** | 118 | 6394 / 1185 / 5209 | 2270 / 1363 / 907 | %81,5 → %40,0 | 16 (15 + 1) | 16/1185 (%1,4; %0,8-%2,2) | 194 | 4304 | 2 |

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
| kazanılan (yeni kanalı) | `string_context/oz_ad` | 4 |
