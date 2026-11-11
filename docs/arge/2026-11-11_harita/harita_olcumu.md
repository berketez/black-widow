# Harita ölçümü: ürün modülü ↔ kaynak dosya

- Ön kayıt commit'i: `fdb4d800238c119f2ba8adb3b97753f59a5d7f01`; `harita_olc.py` sha256 `1a205ca42d4d9e3d…`; Ghidra `12.1.2`.
- Nüfus: 119 ikili bitti; sorunlar: yok; GT etiketi olmayan (ölçülmeyen): 2.
- Koşu künyesi: ürün commit'i `93a29569e4c3b61123b322af70b8c32e4d48e520`, sürüm 1.21.1, kirli dosya 0.
- Seçimler: N_MIN = 10, en az 2 program, B0 200 karma, fark eşiği 0,05, çoğunluk 0,67; karar ölçüsü ARI, karar düzeyi `dosya`.
- LTO'lu ikili taşıyan birimler: debian/redis-tools.

## Düzey: dosya

- Giren ikili: 114; dışarıda: gt_tek_sinif 1, kucuk 1.
- Rastgeleye karşı: `rastgeleden_iyi` (7/7 programda ürün B0'ın 95. yüzdeliğinin üstünde; gerekli 5).
- B1'e karşı: `taban_gecer` (makro fark -0,327; pozitif 1, negatif 6, gerekli 5).

| Satır | ARI | Çift kesinliği | Çift duyarlılığı | Çift F1 | Türdeşlik | Tamlık | V |
|---|---|---|---|---|---|---|---|
| `urun` | 0,097 | 0,153 | 0,418 | 0,185 | 0,286 | 0,462 | 0,341 |
| `b0` | -0,000 | 0,076 | 0,267 | 0,100 | 0,143 | 0,223 | 0,169 |
| `b1` | 0,424 | 0,538 | 0,447 | 0,458 | 0,733 | 0,793 | 0,756 |
| `b1_gt` | 0,299 | 0,702 | 0,222 | 0,323 | 0,854 | 0,707 | 0,772 |
| `tek_modul` | 0,000 | 0,076 | 1,000 | 0,138 | 0,000 | 1,000 | 0,000 |
| `hepsi_ayri` | 0,000 | — | 0,000 | 0,000 | 1,000 | 0,511 | 0,675 |
| `urun_misc_tekil` | 0,098 | 0,159 | 0,406 | 0,185 | 0,349 | 0,485 | 0,393 |

| Program | ARI ürün | ARI B0 ort. | ARI B0 p95 | ARI B1 | ARI B1-GT | Fark (ürün − B1) |
|---|---|---|---|---|---|---|
| coreutils | 0,335 | 0,000 | 0,032 | 0,296 | 0,174 | 0,039 |
| htop | 0,019 | 0,000 | 0,005 | 0,515 | 0,407 | -0,497 |
| openssl | 0,083 | 0,000 | 0,009 | 0,412 | 0,200 | -0,329 |
| redis-tools | 0,078 | 0,000 | 0,006 | 0,354 | 0,289 | -0,276 |
| tmux | 0,009 | -0,000 | 0,003 | 0,432 | 0,237 | -0,422 |
| tree | 0,077 | -0,002 | 0,035 | 0,492 | 0,452 | -0,415 |
| zstd | 0,079 | 0,000 | 0,005 | 0,464 | 0,336 | -0,385 |

GT bitişikliği (sınıf / adres sırasındaki öbek; 1: her sınıf tek öbek), makro 0,860; program başına: coreutils 0,998, htop 1,000, openssl 0,987, redis-tools 0,338, tmux 0,993, tree 1,000, zstd 0,705.

| Modül türü | Modül | Fonksiyon | Aynı modülde çift | Bunlardan aynı sınıfta | Çift kesinliği |
|---|---|---|---|---|---|
| `giris` | 5 | 5 | 0 | 0 | — |
| `kural` | 268 | 5385 | 227391 | 29105 | 0,128 |
| `topluluk` | 1546 | 19624 | 10936342 | 442221 | 0,040 |
| `misc` | 114 | 3186 | 347012 | 19386 | 0,056 |
| `diger` | 0 | 0 | 0 | 0 | — |

## Düzey: dizin

- Giren ikili: 113; dışarıda: gt_tek_sinif 2, kucuk 1.
- Rastgeleye karşı: `rastgeleden_iyi` (4/6 programda ürün B0'ın 95. yüzdeliğinin üstünde; gerekli 4).
- B1'e karşı: `ayrismiyor` (makro fark 0,014; pozitif 3, negatif 3, gerekli 4).

| Satır | ARI | Çift kesinliği | Çift duyarlılığı | Çift F1 | Türdeşlik | Tamlık | V |
|---|---|---|---|---|---|---|---|
| `urun` | 0,085 | 0,699 | 0,320 | 0,407 | 0,289 | 0,105 | 0,139 |
| `b0` | -0,000 | 0,633 | 0,277 | 0,358 | 0,077 | 0,017 | 0,024 |
| `b1` | 0,070 | 0,942 | 0,085 | 0,151 | 0,848 | 0,191 | 0,291 |
| `b1_gt` | 0,247 | 0,836 | 0,484 | 0,591 | 0,470 | 0,302 | 0,351 |
| `tek_modul` | 0,000 | 0,633 | 1,000 | 0,749 | 0,000 | 1,000 | 0,000 |
| `hepsi_ayri` | 0,000 | — | 0,000 | 0,000 | 1,000 | 0,101 | 0,177 |
| `urun_misc_tekil` | 0,084 | 0,701 | 0,311 | 0,398 | 0,366 | 0,110 | 0,155 |

| Program | ARI ürün | ARI B0 ort. | ARI B0 p95 | ARI B1 | ARI B1-GT | Fark (ürün − B1) |
|---|---|---|---|---|---|---|
| coreutils | 0,009 | 0,000 | 0,015 | 0,012 | 0,040 | -0,003 |
| htop | 0,005 | -0,001 | 0,011 | 0,021 | 0,134 | -0,016 |
| openssl | 0,111 | 0,000 | 0,004 | 0,084 | 0,621 | 0,028 |
| redis-tools | 0,215 | 0,000 | 0,016 | 0,049 | 0,213 | 0,165 |
| tmux | 0,028 | -0,000 | 0,013 | 0,011 | 0,010 | 0,017 |
| zstd | 0,139 | 0,000 | 0,009 | 0,245 | 0,464 | -0,106 |

GT bitişikliği (sınıf / adres sırasındaki öbek; 1: her sınıf tek öbek), makro 0,690; program başına: coreutils 0,649, htop 0,800, openssl 0,500, redis-tools 0,593, tmux 1,000, zstd 0,600.

| Modül türü | Modül | Fonksiyon | Aynı modülde çift | Bunlardan aynı sınıfta | Çift kesinliği |
|---|---|---|---|---|---|
| `giris` | 5 | 5 | 0 | 0 | — |
| `kural` | 266 | 5360 | 227245 | 165459 | 0,728 |
| `topluluk` | 1539 | 19548 | 10935278 | 9550671 | 0,873 |
| `misc` | 113 | 3177 | 346976 | 258395 | 0,745 |
| `diger` | 0 | 0 | 0 | 0 | — |

GT etiketi olmayan ikililer: mac/htop/htop (mac_gt_derleme_birimi_tasimiyor), mac/tmux/tmux (mac_gt_derleme_birimi_tasimiyor).

C++ (ölçü dışı): debian/zstd: pzstd.
