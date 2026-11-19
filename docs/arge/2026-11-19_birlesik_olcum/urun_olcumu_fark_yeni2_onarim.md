# Ürün adlarının ölçümü: taban ve yeni kol

- taban: `yeni2`; HEAD `2be12ed`; kol kimliği `{"genel_esik": 0.7, "koken_var": true, "susturma": true}` × 118.
- yeni: `onarim`; HEAD `a62f15e`; kol kimliği `{"genel_esik": 0.7, "koken_var": true, "susturma": true}` × 118.
- Ghidra sürümleri iki kolda aynı: evet; eşleme sorunları: yok.
- Öğeler birim, ikili ve adresle eşlenir. Bu belgede fonksiyon adı geçmez.

## Yan yana (fonksiyon adları)

| Kol | Ad verilen | Doğru | Yanlış | Kesinlik (%95) | Yanlış oranı (%95) | Kapsam (%95) | Tam ad kapsamı (%95) | Makro kesinlik | Makro yanlış | Makro kapsam | Makro tam ad kapsamı |
|---|---|---|---|---|---|---|---|---|---|---|---|
| taban | 2261 | 1589 | 672 | 1589/2261 (%70,3; %68,4-%72,1) | 672/2261 (%29,7; %27,9-%31,6) | 1764/21371 (%8,3; %7,9-%8,6) | 1120/21371 (%5,2; %5,0-%5,5) | %47,2 | %52,8 | %4,9 | %2,3 |
| yeni | 1800 | 1681 | 119 | 1681/1800 (%93,4; %92,2-%94,5) | 119/1800 (%6,6; %5,5-%7,8) | 1315/21371 (%6,2; %5,8-%6,5) | 1212/21371 (%5,7; %5,4-%6,0) | %69,0 | %31,0 | %3,3 | %2,4 |

| Kol | "kesin" etiketli ad | Doğru | Kesinlik (havuz) | Makro kesinlik | Kapsam (havuz) |
|---|---|---|---|---|---|
| taban | 262 | 249 | 249/262 (%95,0; %91,7-%97,1) | %97,3 | 252/21371 (%1,2; %1,0-%1,3) |
| yeni | 262 | 249 | 249/262 (%95,0; %91,7-%97,1) | %97,3 | 252/21371 (%1,2; %1,0-%1,3) |

## Kararlar

| Karar | Taban | Yeni |
|---|---|---|
| (a) yanlış ad oranı (makro) | %52,8 → `tutmuyor` | %31,0 → `tutmuyor` |
| (b) "kesin" etiketli adların kesinliği (makro) | %97,3 → `tutuyor` | %97,3 → `tutuyor` |

(c) Kaybedilen doğru ad (havuz): 20/1589 (%1,3; %0,8-%1,9); sınır > %15,0 → `beklenen_aralikta`. Sınırı aşan birimler: yok. Program düzeyi makro: %1,4.

Yön: iki kolda da en az 10 ad verilen birimlerde (debian/coreutils, debian/openssl, debian/redis-tools, debian/sqlite3, debian/tmux, debian/zstd, mac/tmux) yeni kolun yanlış oranı tabanınkinden düşük olmayanlar: yok → `beklenen_aralikta`.

## Birim başına farklar

| Birim | İkili | Taban: ad / doğru / yanlış | Yeni: ad / doğru / yanlış | Yanlış oranı taban → yeni | Kaybedilen doğru (silinen + yanlışa dönen) | Kayıp oranı | Kazanılan doğru | Giderilen yanlış | Yeni yanlış |
|---|---|---|---|---|---|---|---|---|---|
| debian/coreutils | 106 | 1411 / 1178 / 233 | 1281 / 1271 / 10 | %16,5 → %0,8 | 19 (19 + 0) | 19/1178 (%1,6; %1,0-%2,5) | 112 | 223 | 0 |
| debian/htop | 1 | 6 / 3 / 3 | 4 / 3 / 1 | %50,0 → %25,0 | 0 (0 + 0) | 0/3 (%0,0; %0,0-%56,1) | 0 | 2 | 0 |
| debian/openssl | 1 | 35 / 24 / 11 | 26 / 23 / 3 | %31,4 → %11,5 | 1 (1 + 0) | 1/24 (%4,2; %0,7-%20,2) | 0 | 8 | 0 |
| debian/redis-tools | 4 | 29 / 12 / 17 | 15 / 12 / 3 | %58,6 → %20,0 | 0 (0 + 0) | 0/12 (%0,0; %0,0-%24,2) | 0 | 14 | 0 |
| debian/sqlite3 | 1 | 20 / 5 / 15 | 12 / 5 / 7 | %75,0 → %58,3 | 0 (0 + 0) | 0/5 (%0,0; %0,0-%43,5) | 0 | 8 | 0 |
| debian/tmux | 1 | 295 / 148 / 147 | 166 / 148 / 18 | %49,8 → %10,8 | 0 (0 + 0) | 0/148 (%0,0; %0,0-%2,5) | 0 | 129 | 0 |
| debian/tree | 1 | 5 / 5 / 0 | 5 / 5 / 0 | %0,0 → %0,0 | 0 (0 + 0) | 0/5 (%0,0; %0,0-%43,5) | 0 | 0 | 0 |
| debian/zstd | 1 | 65 / 9 / 56 | 55 / 9 / 46 | %86,2 → %83,6 | 0 (0 + 0) | 0/9 (%0,0; %0,0-%29,9) | 0 | 10 | 0 |
| mac/htop | 1 | 0 / 0 / 0 | 0 / 0 / 0 | — → — | 0 (0 + 0) | — | 0 | 0 | 0 |
| mac/tmux | 1 | 395 / 205 / 190 | 236 / 205 / 31 | %48,1 → %13,1 | 0 (0 + 0) | 0/205 (%0,0; %0,0-%1,8) | 0 | 159 | 0 |
| **Toplam** | 118 | 2261 / 1589 / 672 | 1800 / 1681 / 119 | %29,7 → %6,6 | 20 (20 + 0) | 20/1589 (%1,3; %0,8-%1,9) | 112 | 553 | 0 |

## Kaybedilen ve kazanılan doğru adların kanalı

| Yön | Kanal | Ad |
|---|---|---|
| kaybedilen (taban kanalı) | `api_param_reverse` | 1 |
| kaybedilen (taban kanalı) | `string_context/oz_ad` | 19 |
| kazanılan (yeni kanalı) | `on_ad:gnulib` | 112 |
