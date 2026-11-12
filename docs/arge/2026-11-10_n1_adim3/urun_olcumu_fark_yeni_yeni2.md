# Ürün adlarının ölçümü: taban ve yeni kol

- taban: `yeni`; HEAD `07c3f86`; kol kimliği `{"genel_esik": 0.7, "koken_var": true, "susturma": true}` × 118.
- yeni: `yeni2`; HEAD `2be12ed`; kol kimliği `{"genel_esik": 0.7, "koken_var": true, "susturma": true}` × 118.
- Ghidra sürümleri iki kolda aynı: evet; eşleme sorunları: yok.
- Öğeler birim, ikili ve adresle eşlenir. Bu belgede fonksiyon adı geçmez.

## Yan yana (fonksiyon adları)

| Kol | Ad verilen | Doğru | Yanlış | Kesinlik (%95) | Yanlış oranı (%95) | Kapsam (%95) | Tam ad kapsamı (%95) | Makro kesinlik | Makro yanlış | Makro kapsam | Makro tam ad kapsamı |
|---|---|---|---|---|---|---|---|---|---|---|---|
| taban | 2270 | 1363 | 907 | 1363/2270 (%60,0; %58,0-%62,0) | 907/2270 (%40,0; %38,0-%42,0) | 1773/21371 (%8,3; %7,9-%8,7) | 1120/21371 (%5,2; %5,0-%5,5) | %39,2 | %60,8 | %4,9 | %2,3 |
| yeni | 2261 | 1589 | 672 | 1589/2261 (%70,3; %68,4-%72,1) | 672/2261 (%29,7; %27,9-%31,6) | 1764/21371 (%8,3; %7,9-%8,6) | 1120/21371 (%5,2; %5,0-%5,5) | %47,2 | %52,8 | %4,9 | %2,3 |

| Kol | "kesin" etiketli ad | Doğru | Kesinlik (havuz) | Makro kesinlik | Kapsam (havuz) |
|---|---|---|---|---|---|
| taban | 262 | 249 | 249/262 (%95,0; %91,7-%97,1) | %97,3 | 252/21371 (%1,2; %1,0-%1,3) |
| yeni | 262 | 249 | 249/262 (%95,0; %91,7-%97,1) | %97,3 | 252/21371 (%1,2; %1,0-%1,3) |

## Kararlar

| Karar | Taban | Yeni |
|---|---|---|
| (a) yanlış ad oranı (makro) | %60,8 → `tutmuyor` | %52,8 → `tutmuyor` |
| (b) "kesin" etiketli adların kesinliği (makro) | %97,3 → `tutuyor` | %97,3 → `tutuyor` |

(c) Kaybedilen doğru ad (havuz): 0/1363 (%0,0; %0,0-%0,3); sınır > %15,0 → `beklenen_aralikta`. Sınırı aşan birimler: yok. Program düzeyi makro: %0,0.

Yön: iki kolda da en az 10 ad verilen birimlerde (debian/coreutils, debian/openssl, debian/redis-tools, debian/sqlite3, debian/tmux, debian/zstd, mac/tmux) yeni kolun yanlış oranı tabanınkinden düşük olmayanlar: mac/tmux → `incele`.

## Birim başına farklar

| Birim | İkili | Taban: ad / doğru / yanlış | Yeni: ad / doğru / yanlış | Yanlış oranı taban → yeni | Kaybedilen doğru (silinen + yanlışa dönen) | Kayıp oranı | Kazanılan doğru | Giderilen yanlış | Yeni yanlış |
|---|---|---|---|---|---|---|---|---|---|
| debian/coreutils | 106 | 1420 / 967 / 453 | 1411 / 1178 / 233 | %31,9 → %16,5 | 0 (0 + 0) | 0/967 (%0,0; %0,0-%0,4) | 211 | 220 | 0 |
| debian/htop | 1 | 6 / 2 / 4 | 6 / 3 / 3 | %66,7 → %50,0 | 0 (0 + 0) | 0/2 (%0,0; %0,0-%65,8) | 1 | 1 | 0 |
| debian/openssl | 1 | 35 / 22 / 13 | 35 / 24 / 11 | %37,1 → %31,4 | 0 (0 + 0) | 0/22 (%0,0; %0,0-%14,9) | 2 | 2 | 0 |
| debian/redis-tools | 4 | 29 / 8 / 21 | 29 / 12 / 17 | %72,4 → %58,6 | 0 (0 + 0) | 0/8 (%0,0; %0,0-%32,4) | 4 | 4 | 0 |
| debian/sqlite3 | 1 | 20 / 3 / 17 | 20 / 5 / 15 | %85,0 → %75,0 | 0 (0 + 0) | 0/3 (%0,0; %0,0-%56,1) | 2 | 2 | 0 |
| debian/tmux | 1 | 295 / 146 / 149 | 295 / 148 / 147 | %50,5 → %49,8 | 0 (0 + 0) | 0/146 (%0,0; %0,0-%2,6) | 2 | 2 | 0 |
| debian/tree | 1 | 5 / 3 / 2 | 5 / 5 / 0 | %40,0 → %0,0 | 0 (0 + 0) | 0/3 (%0,0; %0,0-%56,1) | 2 | 2 | 0 |
| debian/zstd | 1 | 65 / 7 / 58 | 65 / 9 / 56 | %89,2 → %86,2 | 0 (0 + 0) | 0/7 (%0,0; %0,0-%35,4) | 2 | 2 | 0 |
| mac/htop | 1 | 0 / 0 / 0 | 0 / 0 / 0 | — → — | 0 (0 + 0) | — | 0 | 0 | 0 |
| mac/tmux | 1 | 395 / 205 / 190 | 395 / 205 / 190 | %48,1 → %48,1 | 0 (0 + 0) | 0/205 (%0,0; %0,0-%1,8) | 0 | 0 | 0 |
| **Toplam** | 118 | 2270 / 1363 / 907 | 2261 / 1589 / 672 | %40,0 → %29,7 | 0 (0 + 0) | 0/1363 (%0,0; %0,0-%0,3) | 226 | 235 | 0 |

## Kaybedilen ve kazanılan doğru adların kanalı

| Yön | Kanal | Ad |
|---|---|---|
| kazanılan (yeni kanalı) | `on_ad:elf_onyuk` | 226 |
