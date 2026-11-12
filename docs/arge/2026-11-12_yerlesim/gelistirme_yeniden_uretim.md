# Yerleşim: yeni ürün işlevinin geliştirme setinde yeniden üretimi

- **Durum: GELİŞTİRME SETİ, ön kayıtsız. Sayılar ürün iddiası değildir.** Eşik ve hizalama bu sette seçilmişti; burada yeniden ayarlanmadı.
- Eşik 16 bayt, hizalama 32 bayt (`karadul/config.py`). Ölçü: dosya düzeyi ARI, program düzeyi makro (`harita_olc.py`'nin işlevleri).
- İkili: 114; ölçülen: 114. Bayrak kapalı kurulumu saklı proje ağacıyla bayt bayt aynı çıkan: 114. Kurucunun girdi dizini: `annotated` 114.
- Sağlama (bulunan = beklenen): `urun_eski` 0,097077 = 0,097077; `b1` 0,423659 = 0,423659; `kesif_s2` 0,704539 = 0,704539 — tuttu.
- Bayrak açık kurulum: strateji `address_padding` 114; geri düşüş `None` 114; başarısız kurulum 0; adressiz birim 0; nüfustan `main.c`'ye giden fonksiyon 5.
- Bölme eşitliği (ikili sayısı): `urun_yeni` = `s2_islev` 114; `s2_islev` = `s2_bloksuz` 114. ARI eşitliği (6 hane): `urun_yeni` = `kesif_s2` 114; `s2_bloksuz` = `kesif_s2` 114.
- Ön kayıtlı ölçümün karar kuralıyla (0,05; 2/3) `urun_yeni` ↔ `b1`, GELİŞTİRME SETİNDE: `urun_gecer` (makro fark 0,281; pozitif 7, negatif 0, gerekli 5). Karar değildir; doğrulama seti gerekir.

| Satır | Makro | coreutils | htop | openssl | redis-tools | tmux | tree | zstd |
|---|---|---|---|---|---|---|---|---|
| `urun_eski` | 0,097 | 0,335 | 0,019 | 0,083 | 0,078 | 0,009 | 0,077 | 0,079 |
| `b1` | 0,424 | 0,296 | 0,515 | 0,412 | 0,354 | 0,432 | 0,492 | 0,464 |
| `kesif_s2` | 0,705 | 0,605 | 0,650 | 0,877 | 0,385 | 0,793 | 0,911 | 0,710 |
| `urun_yeni` | 0,705 | 0,605 | 0,650 | 0,877 | 0,385 | 0,793 | 0,911 | 0,710 |
| `s2_islev` | 0,705 | 0,605 | 0,650 | 0,877 | 0,385 | 0,793 | 0,911 | 0,710 |
| `s2_bloksuz` | 0,705 | 0,605 | 0,650 | 0,877 | 0,385 | 0,793 | 0,911 | 0,710 |
| `duyarlilik_bant` | 0,699 | 0,613 | 0,637 | 0,877 | 0,354 | 0,793 | 0,911 | 0,710 |

`duyarlilik_bant` yalnız duyarlılıktır; seçilmedi, ürün kuralı değildir.

## İkili başına

| İkili | n | Grup | `urun_eski` | `b1` | `kesif_s2` | `urun_yeni` | `s2_islev` | `s2_bloksuz` | Nüfustan `main.c`'ye | Geri düşüş |
|---|---|---|---|---|---|---|---|---|---|---|
| `debian/coreutils/[` | 102 | 21 | 0,273 | 0,208 | 0,458 | 0,458 | 0,458 | 0,458 | 0 | — |
| `debian/coreutils/arch` | 91 | 20 | 0,255 | 0,209 | 0,444 | 0,444 | 0,444 | 0,444 | 0 | — |
| `debian/coreutils/b2sum` | 112 | 27 | 0,401 | 0,300 | 0,851 | 0,851 | 0,851 | 0,851 | 0 | — |
| `debian/coreutils/base32` | 104 | 22 | 0,453 | 0,303 | 0,485 | 0,485 | 0,485 | 0,485 | 0 | — |
| `debian/coreutils/base64` | 104 | 23 | 0,240 | 0,272 | 0,492 | 0,492 | 0,492 | 0,492 | 0 | — |
| `debian/coreutils/basename` | 95 | 20 | 0,254 | 0,279 | 0,458 | 0,458 | 0,458 | 0,458 | 0 | — |
| `debian/coreutils/basenc` | 145 | 24 | 0,365 | 0,321 | 0,661 | 0,661 | 0,661 | 0,661 | 0 | — |
| `debian/coreutils/cat` | 101 | 23 | 0,485 | 0,267 | 0,757 | 0,757 | 0,757 | 0,757 | 0 | — |
| `debian/coreutils/chcon` | 171 | 29 | 0,228 | 0,402 | 0,667 | 0,667 | 0,667 | 0,667 | 0 | — |
| `debian/coreutils/chgrp` | 164 | 28 | 0,189 | 0,354 | 0,658 | 0,658 | 0,658 | 0,658 | 0 | — |
| `debian/coreutils/chmod` | 159 | 27 | 0,163 | 0,498 | 0,611 | 0,611 | 0,611 | 0,611 | 0 | — |
| `debian/coreutils/chown` | 164 | 28 | 0,186 | 0,354 | 0,658 | 0,658 | 0,658 | 0,658 | 0 | — |
| `debian/coreutils/chroot` | 99 | 23 | 0,462 | 0,289 | 0,801 | 0,801 | 0,801 | 0,801 | 0 | — |
| `debian/coreutils/cksum` | 185 | 36 | 0,253 | 0,344 | 0,733 | 0,733 | 0,733 | 0,733 | 0 | — |
| `debian/coreutils/comm` | 112 | 29 | 0,376 | 0,309 | 0,828 | 0,828 | 0,828 | 0,828 | 0 | — |
| `debian/coreutils/cp` | 292 | 56 | 0,040 | 0,413 | 0,745 | 0,745 | 0,745 | 0,745 | 0 | — |
| `debian/coreutils/csplit` | 118 | 26 | 0,234 | 0,352 | 0,821 | 0,821 | 0,821 | 0,821 | 0 | — |
| `debian/coreutils/cut` | 106 | 24 | 0,446 | 0,271 | 0,486 | 0,486 | 0,486 | 0,486 | 0 | — |
| `debian/coreutils/date` | 133 | 26 | 0,392 | 0,302 | 0,432 | 0,432 | 0,432 | 0,432 | 0 | — |
| `debian/coreutils/dd` | 138 | 26 | 0,212 | 0,361 | 0,624 | 0,624 | 0,624 | 0,624 | 0 | — |
| `debian/coreutils/df` | 177 | 42 | 0,076 | 0,400 | 0,571 | 0,571 | 0,571 | 0,571 | 0 | — |
| `debian/coreutils/dir` | 304 | 36 | 0,124 | 0,183 | 0,904 | 0,904 | 0,904 | 0,904 | 0 | — |
| `debian/coreutils/dircolors` | 104 | 22 | 0,486 | 0,326 | 0,488 | 0,488 | 0,488 | 0,488 | 0 | — |
| `debian/coreutils/dirname` | 94 | 20 | 0,451 | 0,280 | 0,456 | 0,456 | 0,456 | 0,456 | 0 | — |
| `debian/coreutils/du` | 218 | 37 | 0,149 | 0,423 | 0,575 | 0,575 | 0,575 | 0,575 | 0 | — |
| `debian/coreutils/echo` | 91 | 19 | 0,545 | 0,297 | 0,442 | 0,442 | 0,442 | 0,442 | 0 | — |
| `debian/coreutils/env` | 98 | 20 | 0,322 | 0,281 | 0,433 | 0,433 | 0,433 | 0,433 | 0 | — |
| `debian/coreutils/expand` | 103 | 23 | 0,272 | 0,248 | 0,485 | 0,485 | 0,485 | 0,485 | 0 | — |
| `debian/coreutils/expr` | 106 | 21 | 0,486 | 0,261 | 0,476 | 0,476 | 0,476 | 0,476 | 0 | — |
| `debian/coreutils/factor` | 124 | 20 | 0,432 | 0,310 | 0,512 | 0,512 | 0,512 | 0,512 | 0 | — |
| `debian/coreutils/false` | 90 | 19 | 0,287 | 0,239 | 0,439 | 0,439 | 0,439 | 0,439 | 0 | — |
| `debian/coreutils/fmt` | 106 | 22 | 0,446 | 0,282 | 0,501 | 0,501 | 0,501 | 0,501 | 0 | — |
| `debian/coreutils/fold` | 97 | 21 | 0,409 | 0,281 | 0,464 | 0,464 | 0,464 | 0,464 | 0 | — |
| `debian/coreutils/groups` | 94 | 20 | 0,375 | 0,315 | 0,453 | 0,453 | 0,453 | 0,453 | 0 | — |
| `debian/coreutils/head` | 104 | 20 | 0,310 | 0,280 | 0,471 | 0,471 | 0,471 | 0,471 | 0 | — |
| `debian/coreutils/hostid` | 92 | 18 | 0,401 | 0,298 | 0,446 | 0,446 | 0,446 | 0,446 | 0 | — |
| `debian/coreutils/id` | 100 | 24 | 0,522 | 0,253 | 0,800 | 0,800 | 0,800 | 0,800 | 0 | — |
| `debian/coreutils/install` | 309 | 58 | 0,038 | 0,391 | 0,717 | 0,717 | 0,717 | 0,717 | 0 | — |
| `debian/coreutils/join` | 131 | 31 | 0,337 | 0,330 | 0,839 | 0,839 | 0,839 | 0,839 | 0 | — |
| `debian/coreutils/link` | 92 | 19 | 0,451 | 0,273 | 0,446 | 0,446 | 0,446 | 0,446 | 0 | — |
| `debian/coreutils/ln` | 175 | 37 | 0,080 | 0,396 | 0,818 | 0,818 | 0,818 | 0,818 | 0 | — |
| `debian/coreutils/logname` | 92 | 18 | 0,454 | 0,228 | 0,446 | 0,446 | 0,446 | 0,446 | 0 | — |
| `debian/coreutils/ls` | 304 | 36 | 0,124 | 0,183 | 0,904 | 0,904 | 0,904 | 0,904 | 0 | — |
| `debian/coreutils/md5sum` | 100 | 25 | 0,483 | 0,296 | 0,837 | 0,837 | 0,837 | 0,837 | 0 | — |
| `debian/coreutils/mkdir` | 191 | 33 | 0,160 | 0,419 | 0,728 | 0,728 | 0,728 | 0,728 | 0 | — |
| `debian/coreutils/mkfifo` | 178 | 32 | 0,257 | 0,398 | 0,728 | 0,728 | 0,728 | 0,728 | 0 | — |
| `debian/coreutils/mknod` | 179 | 33 | 0,191 | 0,378 | 0,727 | 0,727 | 0,727 | 0,727 | 0 | — |
| `debian/coreutils/mktemp` | 102 | 23 | 0,385 | 0,272 | 0,737 | 0,737 | 0,737 | 0,737 | 0 | — |
| `debian/coreutils/mv` | 298 | 59 | 0,062 | 0,418 | 0,752 | 0,752 | 0,752 | 0,752 | 0 | — |
| `debian/coreutils/nice` | 91 | 20 | 0,286 | 0,188 | 0,857 | 0,857 | 0,857 | 0,857 | 0 | — |
| `debian/coreutils/nl` | 103 | 25 | 0,483 | 0,263 | 0,483 | 0,483 | 0,483 | 0,483 | 0 | — |
| `debian/coreutils/nohup` | 98 | 24 | 0,475 | 0,242 | 0,470 | 0,470 | 0,470 | 0,470 | 0 | — |
| `debian/coreutils/nproc` | 96 | 20 | 0,430 | 0,265 | 0,461 | 0,461 | 0,461 | 0,461 | 0 | — |
| `debian/coreutils/numfmt` | 108 | 25 | 0,352 | 0,321 | 0,494 | 0,494 | 0,494 | 0,494 | 0 | — |
| `debian/coreutils/od` | 143 | 28 | 0,290 | 0,293 | 0,553 | 0,553 | 0,553 | 0,553 | 0 | — |
| `debian/coreutils/paste` | 97 | 21 | 0,379 | 0,289 | 0,466 | 0,466 | 0,466 | 0,466 | 0 | — |
| `debian/coreutils/pathchk` | 92 | 21 | 0,256 | 0,246 | 0,447 | 0,447 | 0,447 | 0,447 | 0 | — |
| `debian/coreutils/pinky` | 104 | 22 | 0,435 | 0,282 | 0,714 | 0,714 | 0,714 | 0,714 | 0 | — |
| `debian/coreutils/pr` | 143 | 31 | 0,228 | 0,299 | 0,829 | 0,829 | 0,829 | 0,829 | 0 | — |
| `debian/coreutils/printenv` | 90 | 18 | 0,631 | 0,296 | 0,438 | 0,438 | 0,438 | 0,438 | 0 | — |
| `debian/coreutils/printf` | 116 | 26 | 0,316 | 0,318 | 0,420 | 0,420 | 0,420 | 0,420 | 0 | — |
| `debian/coreutils/ptx` | 112 | 24 | 0,232 | 0,289 | 0,773 | 0,773 | 0,773 | 0,773 | 0 | — |
| `debian/coreutils/pwd` | 94 | 21 | 0,245 | 0,290 | 0,833 | 0,833 | 0,833 | 0,833 | 0 | — |
| `debian/coreutils/readlink` | 127 | 22 | 0,289 | 0,293 | 0,570 | 0,570 | 0,570 | 0,570 | 0 | — |
| `debian/coreutils/realpath` | 130 | 23 | 0,181 | 0,298 | 0,577 | 0,577 | 0,577 | 0,577 | 0 | — |
| `debian/coreutils/rm` | 177 | 30 | 0,253 | 0,404 | 0,628 | 0,628 | 0,628 | 0,628 | 0 | — |
| `debian/coreutils/rmdir` | 95 | 22 | 0,459 | 0,215 | 0,459 | 0,459 | 0,459 | 0,459 | 0 | — |
| `debian/coreutils/runcon` | 96 | 18 | 0,426 | 0,255 | 0,360 | 0,360 | 0,360 | 0,360 | 0 | — |
| `debian/coreutils/seq` | 100 | 23 | 0,352 | 0,313 | 0,457 | 0,457 | 0,457 | 0,457 | 0 | — |
| `debian/coreutils/sha1sum` | 100 | 25 | 0,483 | 0,296 | 0,837 | 0,837 | 0,837 | 0,837 | 0 | — |
| `debian/coreutils/sha224sum` | 111 | 24 | 0,430 | 0,319 | 0,820 | 0,820 | 0,820 | 0,820 | 0 | — |
| `debian/coreutils/sha256sum` | 111 | 24 | 0,434 | 0,319 | 0,820 | 0,820 | 0,820 | 0,820 | 0 | — |
| `debian/coreutils/sha384sum` | 111 | 24 | 0,428 | 0,362 | 0,820 | 0,820 | 0,820 | 0,820 | 0 | — |
| `debian/coreutils/sha512sum` | 111 | 24 | 0,422 | 0,362 | 0,820 | 0,820 | 0,820 | 0,820 | 0 | — |
| `debian/coreutils/shred` | 134 | 33 | 0,447 | 0,270 | 0,665 | 0,665 | 0,665 | 0,665 | 0 | — |
| `debian/coreutils/shuf` | 151 | 30 | 0,207 | 0,284 | 0,669 | 0,669 | 0,669 | 0,669 | 0 | — |
| `debian/coreutils/sleep` | 97 | 21 | 0,466 | 0,247 | 0,463 | 0,463 | 0,463 | 0,463 | 0 | — |
| `debian/coreutils/sort` | 235 | 41 | 0,163 | 0,273 | 0,658 | 0,658 | 0,658 | 0,658 | 0 | — |
| `debian/coreutils/split` | 126 | 34 | 0,185 | 0,339 | 0,830 | 0,830 | 0,830 | 0,830 | 0 | — |
| `debian/coreutils/stat` | 156 | 37 | 0,302 | 0,351 | 0,354 | 0,354 | 0,354 | 0,354 | 0 | — |
| `debian/coreutils/stdbuf` | 102 | 26 | 0,405 | 0,243 | 0,482 | 0,482 | 0,482 | 0,482 | 0 | — |
| `debian/coreutils/stty` | 106 | 23 | 0,423 | 0,248 | 0,502 | 0,502 | 0,502 | 0,502 | 0 | — |
| `debian/coreutils/sum` | 110 | 27 | 0,408 | 0,298 | 0,831 | 0,831 | 0,831 | 0,831 | 0 | — |
| `debian/coreutils/sync` | 91 | 21 | 0,436 | 0,248 | 0,444 | 0,444 | 0,444 | 0,444 | 0 | — |
| `debian/coreutils/tac` | 103 | 24 | 0,452 | 0,264 | 0,801 | 0,801 | 0,801 | 0,801 | 0 | — |
| `debian/coreutils/tail` | 168 | 34 | 0,248 | 0,349 | 0,760 | 0,760 | 0,760 | 0,760 | 0 | — |
| `debian/coreutils/tee` | 113 | 24 | 0,348 | 0,329 | 0,805 | 0,805 | 0,805 | 0,805 | 0 | — |
| `debian/coreutils/test` | 95 | 21 | 0,456 | 0,243 | 0,540 | 0,540 | 0,540 | 0,540 | 0 | — |
| `debian/coreutils/timeout` | 101 | 23 | 0,433 | 0,239 | 0,444 | 0,444 | 0,444 | 0,444 | 0 | — |
| `debian/coreutils/touch` | 129 | 22 | 0,159 | 0,371 | 0,426 | 0,426 | 0,426 | 0,426 | 0 | — |
| `debian/coreutils/tr` | 109 | 23 | 0,405 | 0,311 | 0,481 | 0,481 | 0,481 | 0,481 | 0 | — |
| `debian/coreutils/true` | 90 | 19 | 0,287 | 0,239 | 0,439 | 0,439 | 0,439 | 0,439 | 0 | — |
| `debian/coreutils/truncate` | 93 | 21 | 0,276 | 0,243 | 0,452 | 0,452 | 0,452 | 0,452 | 0 | — |
| `debian/coreutils/tsort` | 104 | 20 | 0,460 | 0,293 | 0,432 | 0,432 | 0,432 | 0,432 | 0 | — |
| `debian/coreutils/tty` | 90 | 18 | 0,476 | 0,239 | 0,438 | 0,438 | 0,438 | 0,438 | 0 | — |
| `debian/coreutils/uname` | 91 | 20 | 0,255 | 0,209 | 0,444 | 0,444 | 0,444 | 0,444 | 0 | — |
| `debian/coreutils/unexpand` | 103 | 22 | 0,346 | 0,335 | 0,483 | 0,483 | 0,483 | 0,483 | 0 | — |
| `debian/coreutils/uniq` | 113 | 22 | 0,363 | 0,250 | 0,491 | 0,491 | 0,491 | 0,491 | 0 | — |
| `debian/coreutils/unlink` | 92 | 18 | 0,332 | 0,223 | 0,446 | 0,446 | 0,446 | 0,446 | 0 | — |
| `debian/coreutils/users` | 100 | 21 | 0,374 | 0,274 | 0,767 | 0,767 | 0,767 | 0,767 | 0 | — |
| `debian/coreutils/vdir` | 304 | 36 | 0,124 | 0,183 | 0,904 | 0,904 | 0,904 | 0,904 | 0 | — |
| `debian/coreutils/wc` | 129 | 27 | 0,244 | 0,320 | 0,784 | 0,784 | 0,784 | 0,784 | 0 | — |
| `debian/coreutils/who` | 105 | 22 | 0,445 | 0,238 | 0,702 | 0,702 | 0,702 | 0,702 | 0 | — |
| `debian/coreutils/whoami` | 92 | 18 | 0,455 | 0,246 | 0,446 | 0,446 | 0,446 | 0,446 | 0 | — |
| `debian/coreutils/yes` | 94 | 20 | 0,529 | 0,212 | 0,435 | 0,435 | 0,435 | 0,435 | 0 | — |
| `debian/htop/htop` | 608 | 51 | 0,019 | 0,515 | 0,650 | 0,650 | 0,650 | 0,650 | 1 | — |
| `debian/openssl/openssl` | 596 | 48 | 0,083 | 0,412 | 0,877 | 0,877 | 0,877 | 0,877 | 0 | — |
| `debian/redis-tools/redis-benchmark` | 479 | 10 | 0,151 | 0,340 | 0,216 | 0,216 | 0,216 | 0,216 | 1 | — |
| `debian/redis-tools/redis-check-aof` | 4675 | 62 | 0,021 | 0,373 | 0,510 | 0,510 | 0,510 | 0,510 | 1 | — |
| `debian/redis-tools/redis-check-rdb` | 4675 | 62 | 0,021 | 0,373 | 0,510 | 0,510 | 0,510 | 0,510 | 1 | — |
| `debian/redis-tools/redis-cli` | 637 | 14 | 0,119 | 0,332 | 0,306 | 0,306 | 0,306 | 0,306 | 1 | — |
| `debian/tmux/tmux` | 1911 | 74 | 0,009 | 0,432 | 0,793 | 0,793 | 0,793 | 0,793 | 0 | — |
| `debian/tree/tree` | 110 | 16 | 0,077 | 0,492 | 0,911 | 0,911 | 0,911 | 0,911 | 0 | — |
| `debian/zstd/zstd` | 1079 | 28 | 0,079 | 0,464 | 0,710 | 0,710 | 0,710 | 0,710 | 0 | — |
