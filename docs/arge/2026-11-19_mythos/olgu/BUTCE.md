# Kapsam bütçesi (A1) — taban a62f15e, 119 ikili

- Kaynak: olgu tablosu `/Users/apple/karadul_olcum/runs/arge-2026-11-19/olgu/olgu.jsonl.gz` (sha256 `c9fa66cb02a04eac…`, 66 983 satır).
- Üreten: `scripts/arge/olgu/olgu_tablosu.py butce` (bu belgedeki her sayı bu komutun çıktısı); tablo `olgu_tablosu.py uret` ile. Alanlar `SEMA.md`'de.
- Tutarlılık kapısı: **tuttu** (`olgu_tablosu.py dogrula`; nüfus 21 371, ad verilen 1 800, doğru 1 681, yanlış 119, nüfusta doğru 1 212, birim başına sayılar ve öğe düzeyi hükümler taban ölçümüyle birebir).
- Bu belgede GT'den fonksiyon adı geçmez; yalnız sayılar, sınıf, dizin ve kanal adları.
- Oranların aralığı Wilson %95 (`ks1_olc.oran`). Geliştirme seti içi sayım; genelleme iddiası değil.

## 1. Kaynak sınıfı başına (ana tablo)

Sınıf tanımları `SEMA.md` §4. *Nüfus*: ad bekleyen fonksiyonlar (Ghidra'nın jenerik bıraktığı, GT'de adı olan, CRT / dışa aktarılan / klon olmayan; C++ ikili dışarıda). *Nüfusta adsız*: nüfusta olup ölçüye giren adı olmayan. *Tümü* sütunları taban ölçümünün havuzudur (nüfus dışındaki adlar dahil).

| Sınıf | Satır | İç fonksiyon | Nüfus | Nüfus payı | Nüfusta ad | Nüfusta doğru | Nüfusta yanlış | Nüfusta adsız | Doğru ad kapsamı (%95) | Ad (tümü) | Doğru (tümü) | Yanlış (tümü) |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `gnulib` | 11 567 | 11 567 | 11 393 | %53,3 | 639 | 634 | 5 | 10 754 | %5,6 (%5,2–%6,0) | 639 | 634 | 5 |
| `ucuncu_taraf` | 1 937 | 1 937 | 881 | %4,1 | 0 | 0 | 0 | 881 | %0,0 (%0,0–%0,4) | 0 | 0 | 0 |
| `uyumluluk` | 95 | 95 | 95 | %0,4 | 0 | 0 | 0 | 95 | %0,0 (%0,0–%3,9) | 0 | 0 | 0 |
| `proje_kitapligi` | 1 565 | 1 565 | 720 | %3,4 | 23 | 0 | 23 | 697 | %0,0 (%0,0–%0,5) | 29 | 0 | 29 |
| `program` | 13 548 | 13 548 | 4 977 | %23,3 | 418 | 373 | 45 | 4 559 | %7,5 (%6,8–%8,3) | 438 | 384 | 54 |
| `sistem` | 258 | 258 | 0 | %0,0 | 0 | 0 | 0 | 0 | — | 0 | 0 | 0 |
| `derleyici` | 1 082 | 1 082 | 153 | %0,7 | 0 | 0 | 0 | 153 | %0,0 (%0,0–%2,5) | 458 | 458 | 0 |
| `ice_aktarim` | 33 547 | 0 | 0 | %0,0 | 0 | 0 | 0 | 0 | — | 0 | 0 | 0 |
| `bilinmiyor` | 3 384 | 3 384 | 3 152 | %14,7 | 235 | 205 | 30 | 2 917 | %6,5 (%5,7–%7,4) | 236 | 205 | 31 |
| **Toplam** | 66 983 | 33 436 | 21 371 | %100 | 1 315 | 1 212 | 103 | 20 056 | %5,7 (%5,4–%6,0) | 1 800 | 1 681 | 119 |

Tekil kaynak fonksiyonu (nüfus): aynı programda aynı tanım dosyası ve aynı GT adı bir sayılır (coreutils'in 106 ikilisindeki gnulib kopyaları, redis-tools'un 4 ikilisindeki ortak kod tek sayılır). Mac'te tanım dosyası yok: anahtar program + GT adı.

| Sınıf | Nüfus (örnek) | Tekil | Örnek / tekil | Tekilde her örneği doğru | Tekilde en az bir örneği doğru |
|---|---|---|---|---|---|
| `gnulib` | 11 393 | 537 | 21,22 | 8 | 10 |
| `ucuncu_taraf` | 881 | 401 | 2,20 | 0 | 0 |
| `uyumluluk` | 95 | 95 | 1,00 | 0 | 0 |
| `proje_kitapligi` | 720 | 713 | 1,01 | 0 | 0 |
| `program` | 4 977 | 4 325 | 1,15 | 340 | 340 |
| `derleyici` | 153 | 39 | 3,92 | 0 | 0 |
| `bilinmiyor` | 3 152 | 3 147 | 1,00 | 205 | 205 |
| **Toplam** | 21 371 | 9 257 | 2,31 | 553 | 555 |

## 2. Sınıf × kanıt (sınıfın hangi olgudan geldiği)

| Sınıf | Kanıt | İç fonksiyon | Nüfus | Nüfusta doğru |
|---|---|---|---|---|
| `gnulib` | `aranges_birimi` | 11 | 11 | 0 |
| `gnulib` | `tanim_dosyasi` | 11 556 | 11 382 | 634 |
| `ucuncu_taraf` | `derleme_birimi` | 2 | 0 | 0 |
| `ucuncu_taraf` | `tanim_dosyasi` | 1 935 | 881 | 0 |
| `uyumluluk` | `tanim_dosyasi` | 95 | 95 | 0 |
| `proje_kitapligi` | `aranges_birimi` | 41 | 20 | 0 |
| `proje_kitapligi` | `tanim_dosyasi` | 1 524 | 700 | 0 |
| `program` | `aranges_birimi` | 11 | 11 | 0 |
| `program` | `tanim_dosyasi` | 13 537 | 4 966 | 373 |
| `sistem` | `tanim_dosyasi` | 258 | 0 | 0 |
| `derleyici` | `dwarf_yok` | 157 | 153 | 0 |
| `derleyici` | `gt_crt_adi` | 925 | 0 | 0 |
| `ice_aktarim` | `ice_aktarim` | 0 | 0 | 0 |
| `bilinmiyor` | `aranges_lto` | 82 | 10 | 0 |
| `bilinmiyor` | `dwarf_yok_gt_yok` | 117 | 0 | 0 |
| `bilinmiyor` | `mac_dwarf_yok` | 3 185 | 3 142 | 205 |

## 3. Sınıf × kanal (ölçüye giren adlar)

| Sınıf | Kanal | Ad (tümü) | Doğru | Yanlış | Nüfusta ad | Nüfusta doğru |
|---|---|---|---|---|---|---|
| `gnulib` | `on_ad:gnulib` | 630 | 630 | 0 | 630 | 630 |
| `gnulib` | `string_context/oz_ad` | 9 | 4 | 5 | 9 | 4 |
| `proje_kitapligi` | `string_context/oz_ad` | 27 | 0 | 27 | 21 | 0 |
| `proje_kitapligi` | `ks1:assert_ust` | 2 | 0 | 2 | 2 | 0 |
| `program` | `ks1:func_kalibi` | 111 | 105 | 6 | 101 | 96 |
| `program` | `on_ad:main_giris` | 110 | 110 | 0 | 110 | 110 |
| `program` | `on_ad:gnulib` | 103 | 103 | 0 | 103 | 103 |
| `program` | `string_context/oz_ad` | 97 | 49 | 48 | 87 | 47 |
| `program` | `ks1:func_aktarma` | 14 | 14 | 0 | 14 | 14 |
| `program` | `ks1:assert_ust` | 2 | 2 | 0 | 2 | 2 |
| `program` | `ks1:func_kalibi+func_aktarma` | 1 | 1 | 0 | 1 | 1 |
| `derleyici` | `on_ad:elf_onyuk` | 458 | 458 | 0 | 0 | 0 |
| `bilinmiyor` | `ks1:func_kalibi` | 148 | 141 | 7 | 148 | 141 |
| `bilinmiyor` | `string_context/oz_ad` | 64 | 40 | 24 | 63 | 40 |
| `bilinmiyor` | `ks1:func_aktarma` | 19 | 19 | 0 | 19 | 19 |
| `bilinmiyor` | `ks1:assert_ust` | 3 | 3 | 0 | 3 | 3 |
| `bilinmiyor` | `ks1:func_kalibi+func_aktarma` | 2 | 2 | 0 | 2 | 2 |

## 4. Birim × sınıf (nüfus / nüfusta doğru)

| Birim | `gnulib` | `ucuncu_taraf` | `uyumluluk` | `proje_kitapligi` | `program` | `sistem` | `derleyici` | `ice_aktarim` | `bilinmiyor` | Toplam |
|---|---|---|---|---|---|---|---|---|---|---|
| debian/coreutils | 11 393 / 634 | — | — | — | 1 223 / 213 | — | 101 / 0 | — | — | 12 717 / 847 |
| debian/htop | — | — | — | — | 222 / 0 | — | — | — | — | 222 / 0 |
| debian/openssl | — | — | — | — | 563 / 18 | — | — | — | — | 563 / 18 |
| debian/redis-tools | — | 881 / 0 | — | — | 515 / 0 | — | 52 / 0 | — | 10 / 0 | 1 458 / 0 |
| debian/sqlite3 | — | — | — | — | 389 / 1 | — | — | — | — | 389 / 1 |
| debian/tmux | — | — | 95 / 0 | — | 1 756 / 136 | — | — | — | — | 1 851 / 136 |
| debian/tree | — | — | — | — | 110 / 1 | — | — | — | — | 110 / 1 |
| debian/zstd | — | — | — | 720 / 0 | 199 / 4 | — | — | — | — | 919 / 4 |
| mac/htop | — | — | — | — | — | — | — | — | 597 / 0 | 597 / 0 |
| mac/tmux | — | — | — | — | — | — | — | — | 2 545 / 205 | 2 545 / 205 |

Birim satırları (bütün sütunlar):

| Birim | Satır | İç fonksiyon | Nüfus | Nüfus payı | Nüfusta ad | Nüfusta doğru | Nüfusta yanlış | Nüfusta adsız | Doğru ad kapsamı (%95) | Ad (tümü) | Doğru (tümü) | Yanlış (tümü) |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| debian/coreutils | 36 573 | 14 120 | 12 717 | %59,5 | 857 | 847 | 10 | 11 860 | %6,7 (%6,2–%7,1) | 1 281 | 1 271 | 10 |
| debian/htop | 1 148 | 609 | 222 | %1,0 | 1 | 0 | 1 | 221 | %0,0 (%0,0–%1,7) | 4 | 3 | 1 |
| debian/openssl | 5 672 | 592 | 563 | %2,6 | 21 | 18 | 3 | 542 | %3,2 (%2,0–%5,0) | 26 | 23 | 3 |
| debian/redis-tools | 13 397 | 10 531 | 1 458 | %6,8 | 1 | 0 | 1 | 1 457 | %0,0 (%0,0–%0,3) | 15 | 12 | 3 |
| debian/sqlite3 | 1 144 | 429 | 389 | %1,8 | 7 | 1 | 6 | 382 | %0,3 (%0,1–%1,4) | 12 | 5 | 7 |
| debian/tmux | 2 588 | 1 920 | 1 851 | %8,7 | 153 | 136 | 17 | 1 698 | %7,3 (%6,2–%8,6) | 166 | 148 | 18 |
| debian/tree | 250 | 119 | 110 | %0,5 | 1 | 1 | 0 | 109 | %0,9 (%0,2–%5,0) | 5 | 5 | 0 |
| debian/zstd | 2 600 | 1 931 | 919 | %4,3 | 39 | 4 | 35 | 880 | %0,4 (%0,2–%1,1) | 55 | 9 | 46 |
| mac/htop | 790 | 597 | 597 | %2,8 | 0 | 0 | 0 | 597 | %0,0 (%0,0–%0,6) | 0 | 0 | 0 |
| mac/tmux | 2 821 | 2 588 | 2 545 | %11,9 | 235 | 205 | 30 | 2 310 | %8,1 (%7,1–%9,2) | 236 | 205 | 31 |
| **Toplam** | 66 983 | 33 436 | 21 371 | %100 | 1 315 | 1 212 | 103 | 20 056 | %5,7 (%5,4–%6,0) | 1 800 | 1 681 | 119 |

## 5. Boyut dilimi (Ghidra gövde baytı)

| Boyut (bayt) | Satır | İç fonksiyon | Nüfus | Nüfus payı | Nüfusta ad | Nüfusta doğru | Nüfusta yanlış | Nüfusta adsız | Doğru ad kapsamı (%95) | Ad (tümü) | Doğru (tümü) | Yanlış (tümü) |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `<16` | 23 817 | 1 210 | 722 | %3,4 | 0 | 0 | 0 | 722 | %0,0 (%0,0–%0,5) | 0 | 0 | 0 |
| `16-63` | 19 125 | 8 185 | 5 365 | %25,1 | 4 | 3 | 1 | 5 361 | %0,1 (%0,0–%0,2) | 357 | 347 | 10 |
| `64-255` | 15 104 | 15 104 | 10 418 | %48,7 | 681 | 653 | 28 | 9 737 | %6,3 (%5,8–%6,8) | 804 | 771 | 33 |
| `256-1023` | 7 111 | 7 111 | 3 804 | %17,8 | 474 | 421 | 53 | 3 330 | %11,1 (%10,1–%12,1) | 481 | 428 | 53 |
| `1024-4095` | 1 526 | 1 526 | 830 | %3,9 | 128 | 108 | 20 | 702 | %13,0 (%10,9–%15,5) | 129 | 108 | 21 |
| `>=4096` | 300 | 300 | 232 | %1,1 | 28 | 27 | 1 | 204 | %11,6 (%8,1–%16,4) | 29 | 27 | 2 |
| **Toplam** | 66 983 | 33 436 | 21 371 | %100 | 1 315 | 1 212 | 103 | 20 056 | %5,7 (%5,4–%6,0) | 1 800 | 1 681 | 119 |

Sınıf × boyut (nüfus / nüfusta doğru):

| Sınıf | `<16` | `16-63` | `64-255` | `256-1023` | `1024-4095` | `>=4096` |
|---|---|---|---|---|---|---|
| `gnulib` | 290 / 0 | 3 704 / 0 | 6 180 / 523 | 976 / 111 | 133 / 0 | 110 / 0 |
| `ucuncu_taraf` | 16 / 0 | 112 / 0 | 439 / 0 | 263 / 0 | 47 / 0 | 4 / 0 |
| `uyumluluk` | 7 / 0 | 17 / 0 | 54 / 0 | 16 / 0 | 1 / 0 | — |
| `proje_kitapligi` | 36 / 0 | 129 / 0 | 184 / 0 | 221 / 0 | 108 / 0 | 42 / 0 |
| `program` | 154 / 0 | 707 / 3 | 2 081 / 50 | 1 573 / 203 | 392 / 92 | 70 / 25 |
| `derleyici` | 10 / 0 | 22 / 0 | 52 / 0 | 41 / 0 | 28 / 0 | — |
| `bilinmiyor` | 209 / 0 | 674 / 0 | 1 428 / 80 | 714 / 107 | 121 / 16 | 6 / 2 |

## 6. Alt sınıf (dizin) başına nüfus — en büyük 20

| Birim | Sınıf | Dizin | Nüfus | Nüfusta doğru | Nüfusta adsız |
|---|---|---|---|---|---|
| debian/coreutils | `gnulib` | `lib` | 11 366 | 634 | 10 727 |
| mac/tmux | `bilinmiyor` | — | 2 545 | 205 | 2 310 |
| debian/tmux | `program` | `.` | 1 756 | 136 | 1 603 |
| debian/coreutils | `program` | `src` | 1 189 | 213 | 971 |
| debian/redis-tools | `ucuncu_taraf` | `deps/lua` | 714 | 0 | 714 |
| mac/htop | `bilinmiyor` | — | 597 | 0 | 597 |
| debian/redis-tools | `program` | `src` | 499 | 0 | 498 |
| debian/sqlite3 | `program` | `.` | 389 | 1 | 382 |
| debian/zstd | `proje_kitapligi` | `lib/compress` | 332 | 0 | 315 |
| debian/openssl | `program` | `apps` | 278 | 15 | 263 |
| debian/openssl | `program` | `apps/lib` | 277 | 3 | 271 |
| debian/zstd | `program` | `programs` | 199 | 4 | 183 |
| debian/htop | `program` | `.` | 178 | 0 | 178 |
| debian/zstd | `proje_kitapligi` | `lib/legacy` | 165 | 0 | 165 |
| debian/redis-tools | `ucuncu_taraf` | `deps/hiredis` | 140 | 0 | 140 |
| debian/zstd | `proje_kitapligi` | `lib/decompress` | 112 | 0 | 107 |
| debian/tree | `program` | `.` | 110 | 1 | 109 |
| debian/coreutils | `derleyici` | `dwarf_yok` | 101 | 0 | 101 |
| debian/tmux | `uyumluluk` | `compat` | 95 | 0 | 95 |
| debian/redis-tools | `derleyici` | `dwarf_yok` | 52 | 0 | 52 |
| (kalan 17 dizin) | | | 277 | 0 | 275 |

## 7. Nüfusta `DW_AT_external` (dışa açık bildirim) × sınıf

| Sınıf | `DW_AT_external` | Nüfus | Nüfusta doğru |
|---|---|---|---|
| `gnulib` | hayır | 968 | 0 |
| `gnulib` | — | 11 | 0 |
| `gnulib` | evet | 10 414 | 634 |
| `ucuncu_taraf` | hayır | 633 | 0 |
| `ucuncu_taraf` | evet | 248 | 0 |
| `uyumluluk` | hayır | 1 | 0 |
| `uyumluluk` | evet | 94 | 0 |
| `proje_kitapligi` | hayır | 182 | 0 |
| `proje_kitapligi` | — | 20 | 0 |
| `proje_kitapligi` | evet | 518 | 0 |
| `program` | hayır | 3 010 | 69 |
| `program` | — | 11 | 0 |
| `program` | evet | 1 956 | 304 |
| `derleyici` | — | 153 | 0 |
| `bilinmiyor` | — | 3 152 | 205 |

## 8. Yaprak var / yok × sınıf

Yaprak: çağrı grafiğinde çağırdığı fonksiyon yok ve P-code'da `CALLIND` yok.

| Sınıf | Yaprak | Nüfus | Nüfusta doğru | Nüfusta yanlış | Nüfusta adsız | Doğru ad kapsamı (%95) |
|---|---|---|---|---|---|---|
| gnulib | evet | 1 464 | 0 | 0 | 1 464 | %0,0 (%0,0–%0,3) |
| gnulib | hayır | 9 929 | 634 | 5 | 9 290 | %6,4 (%5,9–%6,9) |
| ucuncu_taraf | evet | 58 | 0 | 0 | 58 | %0,0 (%0,0–%6,2) |
| ucuncu_taraf | hayır | 823 | 0 | 0 | 823 | %0,0 (%0,0–%0,5) |
| uyumluluk | evet | 20 | 0 | 0 | 20 | %0,0 (%0,0–%16,1) |
| uyumluluk | hayır | 75 | 0 | 0 | 75 | %0,0 (%0,0–%4,9) |
| proje_kitapligi | evet | 121 | 0 | 0 | 121 | %0,0 (%0,0–%3,1) |
| proje_kitapligi | hayır | 599 | 0 | 23 | 576 | %0,0 (%0,0–%0,6) |
| program | evet | 569 | 0 | 0 | 569 | %0,0 (%0,0–%0,7) |
| program | hayır | 4 408 | 373 | 45 | 3 990 | %8,5 (%7,7–%9,3) |
| derleyici | evet | 57 | 0 | 0 | 57 | %0,0 (%0,0–%6,3) |
| derleyici | hayır | 96 | 0 | 0 | 96 | %0,0 (%0,0–%3,9) |
| bilinmiyor | evet | 496 | 0 | 0 | 496 | %0,0 (%0,0–%0,8) |
| bilinmiyor | hayır | 2 656 | 205 | 30 | 2 421 | %7,7 (%6,8–%8,8) |
| **Toplam** | evet | 2 785 | 0 | 0 | 2 785 | %0,0 (%0,0–%0,1) |
| **Toplam** | hayır | 18 586 | 1 212 | 103 | 17 271 | %6,5 (%6,2–%6,9) |

## 9. Doğrudan dizgi var / yok × sınıf

Doğrudan dizgi: Ghidra'nın bu fonksiyona bağladığı en az bir dizgi.

| Sınıf | Doğrudan dizgi | Nüfus | Nüfusta doğru | Nüfusta yanlış | Nüfusta adsız | Doğru ad kapsamı (%95) |
|---|---|---|---|---|---|---|
| gnulib | var | 1 368 | 315 | 5 | 1 048 | %23,0 (%20,9–%25,3) |
| gnulib | yok | 10 025 | 319 | 0 | 9 706 | %3,2 (%2,9–%3,5) |
| ucuncu_taraf | var | 311 | 0 | 0 | 311 | %0,0 (%0,0–%1,2) |
| ucuncu_taraf | yok | 570 | 0 | 0 | 570 | %0,0 (%0,0–%0,7) |
| uyumluluk | var | 5 | 0 | 0 | 5 | %0,0 (%0,0–%43,5) |
| uyumluluk | yok | 90 | 0 | 0 | 90 | %0,0 (%0,0–%4,1) |
| proje_kitapligi | var | 346 | 0 | 22 | 324 | %0,0 (%0,0–%1,1) |
| proje_kitapligi | yok | 374 | 0 | 1 | 373 | %0,0 (%0,0–%1,0) |
| program | var | 2 116 | 371 | 42 | 1 703 | %17,5 (%16,0–%19,2) |
| program | yok | 2 861 | 2 | 3 | 2 856 | %0,1 (%0,0–%0,2) |
| derleyici | yok | 153 | 0 | 0 | 153 | %0,0 (%0,0–%2,5) |
| bilinmiyor | var | 1 202 | 202 | 30 | 970 | %16,8 (%14,8–%19,0) |
| bilinmiyor | yok | 1 950 | 3 | 0 | 1 947 | %0,2 (%0,1–%0,4) |
| **Toplam** | var | 5 348 | 888 | 99 | 4 361 | %16,6 (%15,6–%17,6) |
| **Toplam** | yok | 16 023 | 324 | 4 | 15 695 | %2,0 (%1,8–%2,2) |

## 10. Veri yeri var / yok × sınıf

Veri yeri: adresi bir veri yuvasında duruyor (yeniden konumlandırma / fixup).

| Sınıf | Veri yeri | Nüfus | Nüfusta doğru | Nüfusta yanlış | Nüfusta adsız | Doğru ad kapsamı (%95) |
|---|---|---|---|---|---|---|
| gnulib | var | 230 | 102 | 0 | 128 | %44,3 (%38,1–%50,8) |
| gnulib | yok | 11 163 | 532 | 5 | 10 626 | %4,8 (%4,4–%5,2) |
| ucuncu_taraf | var | 308 | 0 | 0 | 308 | %0,0 (%0,0–%1,2) |
| ucuncu_taraf | yok | 573 | 0 | 0 | 573 | %0,0 (%0,0–%0,7) |
| uyumluluk | yok | 95 | 0 | 0 | 95 | %0,0 (%0,0–%3,9) |
| proje_kitapligi | var | 67 | 0 | 0 | 67 | %0,0 (%0,0–%5,4) |
| proje_kitapligi | yok | 653 | 0 | 23 | 630 | %0,0 (%0,0–%0,6) |
| program | var | 1 299 | 126 | 3 | 1 170 | %9,7 (%8,2–%11,4) |
| program | yok | 3 678 | 247 | 42 | 3 389 | %6,7 (%5,9–%7,6) |
| derleyici | var | 4 | 0 | 0 | 4 | %0,0 (%0,0–%49,0) |
| derleyici | yok | 149 | 0 | 0 | 149 | %0,0 (%0,0–%2,5) |
| bilinmiyor | var | 622 | 19 | 2 | 601 | %3,1 (%2,0–%4,7) |
| bilinmiyor | yok | 2 530 | 186 | 28 | 2 316 | %7,4 (%6,4–%8,4) |
| **Toplam** | var | 2 530 | 247 | 5 | 2 278 | %9,8 (%8,7–%11,0) |
| **Toplam** | yok | 18 841 | 965 | 98 | 17 778 | %5,1 (%4,8–%5,5) |

## 11. Kayıt çifti var / yok × sınıf

Kayıt çifti: veri yuvasının ± 4 komşusunda en az bir dizgi işaretçisi.

| Sınıf | Kayıt çifti | Nüfus | Nüfusta doğru | Nüfusta yanlış | Nüfusta adsız | Doğru ad kapsamı (%95) |
|---|---|---|---|---|---|---|
| gnulib | var | 31 | 0 | 0 | 31 | %0,0 (%0,0–%11,0) |
| gnulib | yok | 11 362 | 634 | 5 | 10 723 | %5,6 (%5,2–%6,0) |
| ucuncu_taraf | var | 248 | 0 | 0 | 248 | %0,0 (%0,0–%1,5) |
| ucuncu_taraf | yok | 633 | 0 | 0 | 633 | %0,0 (%0,0–%0,6) |
| uyumluluk | yok | 95 | 0 | 0 | 95 | %0,0 (%0,0–%3,9) |
| proje_kitapligi | var | 9 | 0 | 0 | 9 | %0,0 (%0,0–%29,9) |
| proje_kitapligi | yok | 711 | 0 | 23 | 688 | %0,0 (%0,0–%0,5) |
| program | var | 540 | 11 | 1 | 528 | %2,0 (%1,1–%3,6) |
| program | yok | 4 437 | 362 | 44 | 4 031 | %8,2 (%7,4–%9,0) |
| derleyici | var | 3 | 0 | 0 | 3 | %0,0 (%0,0–%56,1) |
| derleyici | yok | 150 | 0 | 0 | 150 | %0,0 (%0,0–%2,5) |
| bilinmiyor | var | 499 | 16 | 2 | 481 | %3,2 (%2,0–%5,1) |
| bilinmiyor | yok | 2 653 | 189 | 28 | 2 436 | %7,1 (%6,2–%8,2) |
| **Toplam** | var | 1 330 | 27 | 3 | 1 300 | %2,0 (%1,4–%2,9) |
| **Toplam** | yok | 20 041 | 1 185 | 100 | 18 756 | %5,9 (%5,6–%6,2) |

## 12. Çağrı dizgisi var / yok × sınıf

Çağrı dizgisi: kendi içindeki bir `CALL`'a dizgi sabiti geçiyor (P-code).

| Sınıf | Çağrı dizgisi | Nüfus | Nüfusta doğru | Nüfusta yanlış | Nüfusta adsız | Doğru ad kapsamı (%95) |
|---|---|---|---|---|---|---|
| gnulib | var | 1 186 | 315 | 5 | 866 | %26,6 (%24,1–%29,1) |
| gnulib | yok | 10 207 | 319 | 0 | 9 888 | %3,1 (%2,8–%3,5) |
| ucuncu_taraf | var | 325 | 0 | 0 | 325 | %0,0 (%0,0–%1,2) |
| ucuncu_taraf | yok | 556 | 0 | 0 | 556 | %0,0 (%0,0–%0,7) |
| uyumluluk | var | 5 | 0 | 0 | 5 | %0,0 (%0,0–%43,5) |
| uyumluluk | yok | 90 | 0 | 0 | 90 | %0,0 (%0,0–%4,1) |
| proje_kitapligi | var | 348 | 0 | 22 | 326 | %0,0 (%0,0–%1,1) |
| proje_kitapligi | yok | 372 | 0 | 1 | 371 | %0,0 (%0,0–%1,0) |
| program | var | 2 264 | 373 | 41 | 1 850 | %16,5 (%15,0–%18,1) |
| program | yok | 2 713 | 0 | 4 | 2 709 | %0,0 (%0,0–%0,1) |
| derleyici | yok | 153 | 0 | 0 | 153 | %0,0 (%0,0–%2,5) |
| bilinmiyor | var | 1 044 | 202 | 30 | 812 | %19,3 (%17,1–%21,9) |
| bilinmiyor | yok | 2 108 | 3 | 0 | 2 105 | %0,1 (%0,1–%0,4) |
| **Toplam** | var | 5 172 | 890 | 98 | 4 184 | %17,2 (%16,2–%18,3) |
| **Toplam** | yok | 16 199 | 322 | 5 | 15 872 | %2,0 (%1,8–%2,2) |
