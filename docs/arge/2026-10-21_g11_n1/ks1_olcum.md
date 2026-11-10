# KS-1 ölçümü (adım 2)

- Ön kayıt commit'i: `a22d833cfea4095d8ebb51a1d7b6c25c76ad1779`; sapma kaydı commit'i: `0da58cfdcd3f10061a00df230db69eff8d3ce7f4`; `kesin.py` sha256 `2a412e8a4467cff1…`; `ks1_olc.py` sha256 `975c4d1265d8610e…`; Ghidra `12.1.2`.
- Nüfus: 119 ELF bitti; sorunlar: yok.
- Seçimler: N_MIN = 10, en az 2 farklı program, eşik %95,0; karar makrosu = tekil ve örnek düzeyi makrolarının küçüğü; giren hiçbir birimin Wilson üst sınırı eşiğin altında olamaz.

## Karar

| Satır | Makro (tekil) | Makro (örnek) | Karar makrosu | Giren programlar | Giren birimler | Küçük birimler | Wilson ihlali | Havuz (tekil) | Karar |
|---|---|---|---|---|---|---|---|---|---|
| `assert` | %80,7 | %86,2 | %80,7 | coreutils, redis-tools, zstd | debian/coreutils, debian/redis-tools, debian/zstd | — | debian/coreutils, debian/redis-tools, debian/zstd | 188/228 (%77,0-%86,8) | `kesin_degil` |
| `assert_ust` | — | — | — | — | — | debian/zstd, mac/tmux | — | 5/7 (%35,9-%91,8) | `yetersiz` |
| `func_kalibi` | %97,3 | %97,3 | %97,3 | openssl, tmux | debian/openssl, debian/tmux, mac/tmux | — | — | 249/262 (%91,7-%97,1) | `kesin` |
| `func_aktarma` | %100,0 | %100,0 | %100,0 | tmux | debian/tmux, mac/tmux | — | — | 36/36 (%90,4-%100,0) | `yetersiz` |

## Yalnız raporlanan satırlar (karar yok)

| Satır | Havuz (tekil) | %95 aralık | Havuz (örnek) |
|---|---|---|---|
| `export` | 4224/4224 (%100,0) | %99,9-%100,0 | 8971/8971 (%100,0) |
| `dizgi_turleri` | 475/530 (%89,6) | %86,7-%91,9 | 532/589 (%90,3) |

## Birim başına

| Birim | Satır | n (tekil) | Kesinlik | %95 aralık | Örnek düzeyi | Yalnız ana | Tek türlü | Proje norm. | Klon (doğru/n) | Eşlenemeyen | Parça (doğru/n) | Kapsam | Tam ad kapsamı |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| debian/coreutils | `assert` | 34 | %85,3 | %69,9-%93,5 | 61/67 | 27/32 | 29/34 | 29/34 | 2/2 | 0 | 0/0 | %0,5 (65/12717) | %0,5 |
| debian/coreutils | `export` | 3 | %100,0 | %43,9-%100,0 | 211/211 | 3/3 | 3/3 | 3/3 | 0/0 | 0 | 0/0 | %100,0 (211/211) | %100,0 |
| debian/coreutils | `dizgi_turleri` | 34 | %85,3 | %69,9-%93,5 | 61/67 | 27/32 | 29/34 | 29/34 | 2/2 | 0 | 0/0 | %0,5 (65/12717) | %0,5 |
| debian/htop | `export` | 366 | %100,0 | %99,0-%100,0 | 366/366 | 366/366 | 366/366 | 366/366 | 0/0 | 0 | 0/0 | %98,1 (366/373) | %98,1 |
| debian/openssl | `func_kalibi` | 15 | %100,0 | %79,6-%100,0 | 15/15 | 14/14 | 15/15 | 15/15 | 1/1 | 0 | 0/0 | %2,5 (14/563) | %2,5 |
| debian/openssl | `dizgi_turleri` | 15 | %100,0 | %79,6-%100,0 | 15/15 | 14/14 | 15/15 | 15/15 | 1/1 | 0 | 0/0 | %2,5 (14/563) | %2,5 |
| debian/redis-tools | `assert` | 30 | %73,3 | %55,5-%85,8 | 47/56 | 20/25 | 22/30 | 22/30 | 2/5 | 0 | 0/0 | %3,5 (51/1458) | %3,1 |
| debian/redis-tools | `export` | 3855 | %100,0 | %99,9-%100,0 | 8394/8394 | 3855/3855 | 3855/3855 | 3855/3855 | 0/0 | 0 | 0/0 | %98,3 (8394/8539) | %98,3 |
| debian/redis-tools | `dizgi_turleri` | 30 | %73,3 | %55,5-%85,8 | 47/56 | 20/25 | 22/30 | 22/30 | 2/5 | 0 | 0/0 | %3,5 (51/1458) | %3,1 |
| debian/tmux | `func_kalibi` | 97 | %93,8 | %87,2-%97,1 | 91/97 | 83/88 | 90/96 | 91/97 | 8/9 | 0 | 0/0 | %4,8 (88/1851) | %4,5 |
| debian/tmux | `func_aktarma` | 15 | %100,0 | %79,6-%100,0 | 15/15 | 15/15 | 14/14 | 15/15 | 0/0 | 0 | 0/0 | %0,8 (15/1851) | %0,8 |
| debian/tmux | `dizgi_turleri` | 111 | %94,6 | %88,7-%97,5 | 105/111 | 97/102 | 104/110 | 105/111 | 8/9 | 0 | 0/0 | %5,5 (102/1851) | %5,2 |
| debian/zstd | `assert` | 164 | %83,5 | %77,1-%88,4 | 137/164 | 119/144 | 137/164 | 137/164 | 18/20 | 0 | 0/0 | %15,7 (144/919) | %12,9 |
| debian/zstd | `assert_ust` | 4 | %50,0 | %15,0-%85,0 | 2/4 | 2/4 | 2/4 | 2/4 | 0/0 | 0 | 4/4 | %0,4 (4/919) | %0,2 |
| debian/zstd | `dizgi_turleri` | 168 | %82,7 | %76,3-%87,7 | 139/168 | 121/148 | 139/168 | 139/168 | 18/20 | 0 | 4/4 | %16,1 (148/919) | %13,2 |
| mac/tmux | `assert_ust` | 3 | %100,0 | %43,9-%100,0 | 3/3 | 3/3 | 3/3 | 3/3 | 0/0 | 0 | 14/14 | %0,1 (3/2545) | %0,1 |
| mac/tmux | `func_kalibi` | 150 | %95,3 | %90,7-%97,7 | 143/150 | 143/150 | 141/148 | 143/150 | 0/0 | 0 | 0/0 | %5,9 (150/2545) | %5,6 |
| mac/tmux | `func_aktarma` | 21 | %100,0 | %84,5-%100,0 | 21/21 | 21/21 | 19/19 | 21/21 | 0/0 | 0 | 0/0 | %0,8 (21/2545) | %0,8 |
| mac/tmux | `dizgi_turleri` | 172 | %95,9 | %91,8-%98,0 | 165/172 | 165/172 | 163/170 | 165/172 | 0/0 | 0 | 14/14 | %6,8 (172/2545) | %6,5 |

## Program sınıfı (eş değişken, GT'siz)

| Birim | Dizgi zenginliği | Zenginlik sınıfı | Boyut tabakası |
|---|---|---|---|
| debian/coreutils | 0,007 | `yoksul` | `kucuk` |
| debian/htop | 0,186 | `zengin` | `orta` |
| debian/openssl | 0,682 | `zengin` | `orta` |
| debian/redis-tools | 0,021 | `yoksul` | `buyuk` |
| debian/sqlite3 | 0,198 | `zengin` | `kucuk` |
| debian/tmux | 0,258 | `zengin` | `orta` |
| debian/tree | 0,000 | `yoksul` | `kucuk` |
| debian/zstd | 0,003 | `yoksul` | `orta` |
| mac/htop | 0,097 | `zengin` | `orta` |
| mac/tmux | 0,381 | `zengin` | `buyuk` |

C++ (kesinlik dışı): debian/zstd: pzstd.
