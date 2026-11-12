# Yerleşim: fonksiyonlar arası dolgu sayımı (GT'siz)

- Eşik 16 bayt, hizalama 32 bayt (`karadul/config.py`); sinyal bandı `16-31`.
- Dolgu yalnız yürütülebilir bellek bloklarında, aynı bloktaki ardışık fonksiyonlar arasında ölçülür. Uyum ölçüsü ve ad içermez.
- Kökler: `debian13` = `/Users/apple/karadul_olcum/runs/urun-yeni-93a2956`; `eski` = `/Users/apple/karadul_olcum/runs/aday-f893d72`.

| Grup | İkili | Biçim | Ana kod bloğu | Fonksiyon | Ölçülen çift | `negatif` | `0` | `1-15` | `16-31` | `>=32` | Sinyalsiz ikili | Sinyal yoğunluğu (en az / ortanca / en çok) | Pozitif dolgudan sonra hizalı başlangıç | Yasak kalanlı başlangıç payı (en az / en çok) |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| debian13/debian/coreutils | 106 | Executable and Linking Format (ELF) | .text | 36573 | 28488 | 126 | 14855 | 11332 | 2002 | 173 | 0 | 0,0478 / 0,0698 / 0,0996 | 5987 / 6100 (0,981) | 0,0000 / 0,0294 |
| debian13/debian/htop | 1 | Executable and Linking Format (ELF) | .text | 1148 | 964 | 0 | 501 | 416 | 45 | 2 | 0 | 0,0467 / 0,0467 / 0,0467 | 287 / 287 (1,000) | 0,0016 / 0,0016 |
| debian13/debian/openssl | 1 | Executable and Linking Format (ELF) | .text | 5672 | 3962 | 8 | 1994 | 1917 | 42 | 1 | 0 | 0,0106 / 0,0106 / 0,0106 | 272 / 272 (1,000) | 0,0017 / 0,0017 |
| debian13/debian/redis-tools | 4 | Executable and Linking Format (ELF) | .text | 13397 | 12462 | 7 | 7312 | 5015 | 109 | 19 | 0 | 0,0066 / 0,0087 / 0,0089 | 4213 / 4234 (0,995) | 0,0004 / 0,0020 |
| debian13/debian/sqlite3 | 1 | Executable and Linking Format (ELF) | .text | 1144 | 899 | 4 | 482 | 410 | 3 | 0 | 0 | 0,0033 / 0,0033 / 0,0033 | 174 / 174 (1,000) | 0,0023 / 0,0023 |
| debian13/debian/tmux | 1 | Executable and Linking Format (ELF) | .text | 2588 | 2360 | 0 | 1323 | 968 | 67 | 2 | 0 | 0,0284 / 0,0284 / 0,0284 | 815 / 815 (1,000) | 0,0005 / 0,0005 |
| debian13/debian/tree | 1 | Executable and Linking Format (ELF) | .text | 250 | 180 | 0 | 129 | 40 | 10 | 1 | 0 | 0,0556 / 0,0556 / 0,0556 | 50 / 50 (1,000) | 0,0085 / 0,0085 |
| debian13/debian/zstd | 2 | Executable and Linking Format (ELF) | .text | 2600 | 2377 | 1 | 1324 | 971 | 58 | 23 | 0 | 0,0173 / 0,0253 / 0,0333 | 837 / 843 (0,993) | 0,0012 / 0,0234 |
| debian13/mac | 2 | Mac OS X Mach-O | __text | 3611 | 3605 | 18 | 3568 | 12 | 2 | 5 | 1 | 0,0000 / 0,0004 / 0,0007 | 4 / 19 (0,211) | 0,3455 / 0,3674 |
| eski/debian-9.4-3 | 5 | Executable and Linking Format (ELF) | .text | 1192 | 841 | 0 | 585 | 252 | 2 | 2 | 3 | 0,0000 / 0,0000 / 0,0064 | 128 / 251 (0,510) | 0,1240 / 0,1458 |
| eski/ubuntu-9.4-3ubuntu6 | 5 | Executable and Linking Format (ELF) | .text | 794 | 457 | 0 | 375 | 78 | 2 | 2 | 3 | 0,0000 / 0,0000 / 0,0106 | 36 / 77 (0,468) | 0,1000 / 0,1667 |

Sinyal bandında hiç dolgusu olmayan ikili: 7 / 129: `debian13/mac/htop`, `eski/debian-9.4-3/comm`, `eski/debian-9.4-3/expr`, `eski/debian-9.4-3/wc`, `eski/ubuntu-9.4-3ubuntu6/cat`, `eski/ubuntu-9.4-3ubuntu6/comm`, `eski/ubuntu-9.4-3ubuntu6/cut`.

## Thunk'ların yeri (blok türüne göre)

| Grup | Thunk: ana kod bloğunda | Thunk: başka yürütülebilir blokta | Thunk: yürütülemez blokta | Blok bilgisi olmayan ikili |
|---|---|---|---|---|
| debian13/debian/coreutils | 482 | 14310 | 7661 | 0 |
| debian13/debian/htop | 9 | 350 | 180 | 0 |
| debian13/debian/openssl | 13 | 3361 | 1706 | 0 |
| debian13/debian/redis-tools | 142 | 1805 | 919 | 0 |
| debian13/debian/sqlite3 | 3 | 471 | 241 | 0 |
| debian13/debian/tmux | 2 | 442 | 224 | 0 |
| debian13/debian/tree | 1 | 64 | 66 | 0 |
| debian13/debian/zstd | 43 | 411 | 215 | 0 |
| debian13/mac | 19 | 405 | 2 | 0 |
| eski/debian-9.4-3 | 9 | 316 | 331 | 0 |
| eski/ubuntu-9.4-3ubuntu6 | 5 | 302 | 317 | 0 |

## İkili başına (sinyal bandı ve komşu kutular)

| İkili | Fonksiyon | Ölçülen çift | `negatif` | `0` | `1-15` | `16-31` | `>=32` | Sinyal | Dilim |
|---|---|---|---|---|---|---|---|---|---|
| `debian13/debian/coreutils/[` | 278 | 216 | 1 | 112 | 87 | 14 | 2 | var | 21 |
| `debian13/debian/coreutils/arch` | 246 | 191 | 1 | 101 | 74 | 13 | 2 | var | 20 |
| `debian13/debian/coreutils/b2sum` | 314 | 243 | 1 | 127 | 93 | 20 | 2 | var | 27 |
| `debian13/debian/coreutils/base32` | 301 | 232 | 1 | 124 | 90 | 16 | 1 | var | 22 |
| `debian13/debian/coreutils/base64` | 298 | 230 | 1 | 123 | 88 | 17 | 1 | var | 23 |
| `debian13/debian/coreutils/basename` | 247 | 193 | 1 | 103 | 74 | 14 | 1 | var | 20 |
| `debian13/debian/coreutils/basenc` | 343 | 274 | 1 | 147 | 107 | 17 | 2 | var | 24 |
| `debian13/debian/coreutils/cat` | 296 | 227 | 1 | 118 | 90 | 17 | 1 | var | 23 |
| `debian13/debian/coreutils/chcon` | 446 | 351 | 1 | 184 | 142 | 21 | 3 | var | 29 |
| `debian13/debian/coreutils/chgrp` | 403 | 320 | 1 | 170 | 126 | 22 | 1 | var | 28 |
| `debian13/debian/coreutils/chmod` | 365 | 293 | 1 | 157 | 113 | 21 | 1 | var | 27 |
| `debian13/debian/coreutils/chown` | 403 | 320 | 1 | 170 | 126 | 22 | 1 | var | 28 |
| `debian13/debian/coreutils/chroot` | 311 | 237 | 1 | 124 | 94 | 17 | 1 | var | 23 |
| `debian13/debian/coreutils/cksum` | 479 | 381 | 1 | 198 | 151 | 29 | 2 | var | 36 |
| `debian13/debian/coreutils/comm` | 296 | 231 | 1 | 118 | 88 | 23 | 1 | var | 29 |
| `debian13/debian/coreutils/cp` | 746 | 587 | 3 | 294 | 239 | 49 | 2 | var | 56 |
| `debian13/debian/coreutils/csplit` | 347 | 267 | 2 | 136 | 108 | 20 | 1 | var | 26 |
| `debian13/debian/coreutils/cut` | 313 | 240 | 1 | 124 | 96 | 17 | 2 | var | 24 |
| `debian13/debian/coreutils/date` | 376 | 291 | 1 | 152 | 117 | 18 | 3 | var | 26 |
| `debian13/debian/coreutils/dd` | 388 | 304 | 1 | 161 | 121 | 19 | 2 | var | 26 |
| `debian13/debian/coreutils/df` | 472 | 373 | 1 | 186 | 149 | 35 | 2 | var | 42 |
| `debian13/debian/coreutils/dir` | 665 | 540 | 2 | 276 | 231 | 28 | 3 | var | 36 |
| `debian13/debian/coreutils/dircolors` | 283 | 220 | 1 | 116 | 86 | 16 | 1 | var | 22 |
| `debian13/debian/coreutils/dirname` | 249 | 194 | 1 | 103 | 75 | 14 | 1 | var | 20 |
| `debian13/debian/coreutils/du` | 532 | 425 | 2 | 218 | 173 | 30 | 2 | var | 37 |
| `debian13/debian/coreutils/echo` | 246 | 191 | 1 | 101 | 75 | 12 | 2 | var | 19 |
| `debian13/debian/coreutils/env` | 318 | 241 | 2 | 127 | 97 | 13 | 2 | var | 20 |
| `debian13/debian/coreutils/expand` | 284 | 220 | 1 | 116 | 85 | 15 | 3 | var | 23 |
| `debian13/debian/coreutils/expr` | 298 | 227 | 1 | 122 | 88 | 14 | 2 | var | 21 |
| `debian13/debian/coreutils/factor` | 383 | 293 | 2 | 162 | 114 | 14 | 1 | var | 20 |
| `debian13/debian/coreutils/false` | 239 | 186 | 1 | 100 | 71 | 13 | 1 | var | 19 |
| `debian13/debian/coreutils/fmt` | 293 | 227 | 1 | 121 | 88 | 15 | 2 | var | 22 |
| `debian13/debian/coreutils/fold` | 284 | 218 | 1 | 114 | 87 | 15 | 1 | var | 21 |
| `debian13/debian/coreutils/groups` | 270 | 208 | 1 | 110 | 82 | 14 | 1 | var | 20 |
| `debian13/debian/coreutils/head` | 292 | 226 | 1 | 121 | 89 | 13 | 2 | var | 20 |
| `debian13/debian/coreutils/hostid` | 247 | 192 | 1 | 104 | 74 | 12 | 1 | var | 18 |
| `debian13/debian/coreutils/id` | 306 | 234 | 1 | 121 | 93 | 17 | 2 | var | 24 |
| `debian13/debian/coreutils/install` | 815 | 639 | 2 | 318 | 266 | 51 | 2 | var | 58 |
| `debian13/debian/coreutils/join` | 330 | 260 | 1 | 134 | 99 | 23 | 3 | var | 31 |
| `debian13/debian/coreutils/libstdbuf.so` | 34 | 17 | 0 | 13 | 3 | 1 | 0 | var | 6 |
| `debian13/debian/coreutils/link` | 247 | 192 | 1 | 103 | 74 | 13 | 1 | var | 19 |
| `debian13/debian/coreutils/ln` | 421 | 335 | 3 | 176 | 124 | 30 | 2 | var | 37 |
| `debian13/debian/coreutils/logname` | 250 | 194 | 1 | 105 | 75 | 12 | 1 | var | 18 |
| `debian13/debian/coreutils/ls` | 665 | 540 | 2 | 276 | 231 | 28 | 3 | var | 36 |
| `debian13/debian/coreutils/md5sum` | 299 | 229 | 1 | 118 | 90 | 18 | 2 | var | 25 |
| `debian13/debian/coreutils/mkdir` | 514 | 403 | 1 | 210 | 164 | 27 | 1 | var | 33 |
| `debian13/debian/coreutils/mkfifo` | 471 | 370 | 1 | 194 | 148 | 26 | 1 | var | 32 |
| `debian13/debian/coreutils/mknod` | 481 | 377 | 1 | 197 | 151 | 26 | 2 | var | 33 |
| `debian13/debian/coreutils/mktemp` | 285 | 220 | 3 | 112 | 87 | 16 | 2 | var | 23 |
| `debian13/debian/coreutils/mv` | 753 | 594 | 3 | 296 | 241 | 53 | 1 | var | 59 |
| `debian13/debian/coreutils/nice` | 258 | 199 | 1 | 106 | 77 | 13 | 2 | var | 20 |
| `debian13/debian/coreutils/nl` | 299 | 230 | 1 | 120 | 89 | 18 | 2 | var | 25 |
| `debian13/debian/coreutils/nohup` | 274 | 212 | 1 | 111 | 81 | 18 | 1 | var | 24 |
| `debian13/debian/coreutils/nproc` | 275 | 212 | 1 | 113 | 83 | 14 | 1 | var | 20 |
| `debian13/debian/coreutils/numfmt` | 312 | 245 | 1 | 127 | 97 | 18 | 2 | var | 25 |
| `debian13/debian/coreutils/od` | 380 | 299 | 1 | 154 | 121 | 21 | 2 | var | 28 |
| `debian13/debian/coreutils/paste` | 278 | 214 | 1 | 115 | 82 | 15 | 1 | var | 21 |
| `debian13/debian/coreutils/pathchk` | 259 | 200 | 1 | 105 | 78 | 15 | 1 | var | 21 |
| `debian13/debian/coreutils/pinky` | 402 | 299 | 1 | 157 | 124 | 15 | 2 | var | 22 |
| `debian13/debian/coreutils/pr` | 377 | 294 | 2 | 147 | 119 | 23 | 3 | var | 31 |
| `debian13/debian/coreutils/printenv` | 245 | 190 | 1 | 102 | 74 | 12 | 1 | var | 18 |
| `debian13/debian/coreutils/printf` | 310 | 242 | 1 | 125 | 95 | 19 | 2 | var | 26 |
| `debian13/debian/coreutils/ptx` | 335 | 257 | 2 | 136 | 100 | 17 | 2 | var | 24 |
| `debian13/debian/coreutils/pwd` | 285 | 218 | 1 | 115 | 86 | 14 | 2 | var | 21 |
| `debian13/debian/coreutils/readlink` | 300 | 239 | 1 | 130 | 91 | 16 | 1 | var | 22 |
| `debian13/debian/coreutils/realpath` | 306 | 244 | 1 | 132 | 93 | 15 | 3 | var | 23 |
| `debian13/debian/coreutils/rm` | 395 | 319 | 1 | 173 | 120 | 24 | 1 | var | 30 |
| `debian13/debian/coreutils/rmdir` | 274 | 211 | 1 | 110 | 83 | 16 | 1 | var | 22 |
| `debian13/debian/coreutils/runcon` | 307 | 232 | 1 | 124 | 94 | 12 | 1 | var | 18 |
| `debian13/debian/coreutils/seq` | 297 | 230 | 1 | 118 | 93 | 17 | 1 | var | 23 |
| `debian13/debian/coreutils/sha1sum` | 299 | 229 | 1 | 118 | 90 | 19 | 1 | var | 25 |
| `debian13/debian/coreutils/sha224sum` | 323 | 249 | 1 | 131 | 98 | 18 | 1 | var | 24 |
| `debian13/debian/coreutils/sha256sum` | 323 | 249 | 1 | 131 | 98 | 18 | 1 | var | 24 |
| `debian13/debian/coreutils/sha384sum` | 323 | 249 | 1 | 129 | 100 | 18 | 1 | var | 24 |
| `debian13/debian/coreutils/sha512sum` | 323 | 249 | 1 | 129 | 100 | 18 | 1 | var | 24 |
| `debian13/debian/coreutils/shred` | 393 | 306 | 1 | 154 | 123 | 27 | 1 | var | 33 |
| `debian13/debian/coreutils/shuf` | 377 | 298 | 1 | 154 | 118 | 23 | 2 | var | 30 |
| `debian13/debian/coreutils/sleep` | 263 | 204 | 1 | 107 | 80 | 15 | 1 | var | 21 |
| `debian13/debian/coreutils/sort` | 625 | 492 | 2 | 247 | 207 | 32 | 4 | var | 41 |
| `debian13/debian/coreutils/split` | 396 | 302 | 1 | 149 | 123 | 26 | 3 | var | 34 |
| `debian13/debian/coreutils/stat` | 471 | 361 | 2 | 175 | 152 | 30 | 2 | var | 37 |
| `debian13/debian/coreutils/stdbuf` | 286 | 221 | 2 | 112 | 86 | 20 | 1 | var | 26 |
| `debian13/debian/coreutils/stty` | 309 | 238 | 1 | 127 | 92 | 16 | 2 | var | 23 |
| `debian13/debian/coreutils/sum` | 314 | 245 | 1 | 123 | 99 | 20 | 2 | var | 27 |
| `debian13/debian/coreutils/sync` | 261 | 201 | 1 | 106 | 78 | 14 | 2 | var | 21 |
| `debian13/debian/coreutils/tac` | 306 | 235 | 1 | 121 | 94 | 18 | 1 | var | 24 |
| `debian13/debian/coreutils/tail` | 412 | 327 | 1 | 168 | 129 | 26 | 3 | var | 34 |
| `debian13/debian/coreutils/tee` | 306 | 238 | 1 | 126 | 92 | 18 | 1 | var | 24 |
| `debian13/debian/coreutils/test` | 268 | 207 | 1 | 106 | 84 | 15 | 1 | var | 21 |
| `debian13/debian/coreutils/timeout` | 333 | 252 | 1 | 131 | 102 | 17 | 1 | var | 23 |
| `debian13/debian/coreutils/touch` | 361 | 280 | 1 | 150 | 112 | 15 | 2 | var | 22 |
| `debian13/debian/coreutils/tr` | 299 | 232 | 1 | 120 | 93 | 15 | 3 | var | 23 |
| `debian13/debian/coreutils/true` | 239 | 186 | 1 | 100 | 71 | 13 | 1 | var | 19 |
| `debian13/debian/coreutils/truncate` | 266 | 205 | 1 | 107 | 81 | 14 | 2 | var | 21 |
| `debian13/debian/coreutils/tsort` | 279 | 217 | 1 | 116 | 85 | 14 | 1 | var | 20 |
| `debian13/debian/coreutils/tty` | 251 | 194 | 1 | 104 | 76 | 12 | 1 | var | 18 |
| `debian13/debian/coreutils/uname` | 246 | 191 | 1 | 101 | 74 | 13 | 2 | var | 20 |
| `debian13/debian/coreutils/unexpand` | 287 | 222 | 1 | 118 | 86 | 15 | 2 | var | 22 |
| `debian13/debian/coreutils/uniq` | 309 | 240 | 1 | 129 | 93 | 16 | 1 | var | 22 |
| `debian13/debian/coreutils/unlink` | 247 | 192 | 1 | 104 | 74 | 12 | 1 | var | 18 |
| `debian13/debian/coreutils/users` | 363 | 272 | 1 | 146 | 109 | 15 | 1 | var | 21 |
| `debian13/debian/coreutils/vdir` | 665 | 540 | 2 | 276 | 231 | 28 | 3 | var | 36 |
| `debian13/debian/coreutils/wc` | 355 | 276 | 1 | 143 | 110 | 20 | 2 | var | 27 |
| `debian13/debian/coreutils/who` | 403 | 300 | 1 | 155 | 127 | 15 | 2 | var | 22 |
| `debian13/debian/coreutils/whoami` | 253 | 196 | 1 | 106 | 76 | 12 | 1 | var | 18 |
| `debian13/debian/coreutils/yes` | 249 | 194 | 1 | 103 | 75 | 13 | 2 | var | 20 |
| `debian13/debian/htop/htop` | 1148 | 964 | 0 | 501 | 416 | 45 | 2 | var | 52 |
| `debian13/debian/openssl/openssl` | 5672 | 3962 | 8 | 1994 | 1917 | 42 | 1 | var | 48 |
| `debian13/debian/redis-tools/redis-benchmark` | 892 | 753 | 2 | 415 | 331 | 5 | 0 | var | 10 |
| `debian13/debian/redis-tools/redis-check-aof` | 5697 | 5379 | 2 | 3176 | 2144 | 48 | 9 | var | 62 |
| `debian13/debian/redis-tools/redis-check-rdb` | 5697 | 5379 | 2 | 3176 | 2144 | 48 | 9 | var | 62 |
| `debian13/debian/redis-tools/redis-cli` | 1111 | 951 | 1 | 545 | 396 | 8 | 1 | var | 14 |
| `debian13/debian/sqlite3/sqlite3` | 1144 | 899 | 4 | 482 | 410 | 3 | 0 | var | 8 |
| `debian13/debian/tmux/tmux` | 2588 | 2360 | 0 | 1323 | 968 | 67 | 2 | var | 74 |
| `debian13/debian/tree/tree` | 250 | 180 | 0 | 129 | 40 | 10 | 1 | var | 16 |
| `debian13/debian/zstd/pzstd` | 1156 | 1050 | 0 | 557 | 435 | 35 | 23 | var | 63 |
| `debian13/debian/zstd/zstd` | 1444 | 1327 | 1 | 767 | 536 | 23 | 0 | var | 28 |
| `debian13/mac/htop` | 790 | 787 | 0 | 787 | 0 | 0 | 0 | YOK | 3 |
| `debian13/mac/tmux` | 2821 | 2818 | 18 | 2781 | 12 | 2 | 5 | var | 10 |
| `eski/debian-9.4-3/cat` | 223 | 156 | 0 | 109 | 46 | 1 | 0 | var | 6 |
| `eski/debian-9.4-3/comm` | 229 | 165 | 0 | 114 | 50 | 0 | 1 | YOK | 6 |
| `eski/debian-9.4-3/cut` | 239 | 167 | 0 | 119 | 47 | 1 | 0 | var | 6 |
| `eski/debian-9.4-3/expr` | 233 | 162 | 0 | 113 | 48 | 0 | 1 | YOK | 6 |
| `eski/debian-9.4-3/wc` | 268 | 191 | 0 | 130 | 61 | 0 | 0 | YOK | 5 |
| `eski/ubuntu-9.4-3ubuntu6/cat` | 147 | 82 | 0 | 72 | 9 | 0 | 1 | YOK | 6 |
| `eski/ubuntu-9.4-3ubuntu6/comm` | 144 | 84 | 0 | 69 | 15 | 0 | 0 | YOK | 5 |
| `eski/ubuntu-9.4-3ubuntu6/cut` | 157 | 90 | 0 | 74 | 16 | 0 | 0 | YOK | 5 |
| `eski/ubuntu-9.4-3ubuntu6/expr` | 165 | 94 | 0 | 77 | 15 | 1 | 1 | var | 7 |
| `eski/ubuntu-9.4-3ubuntu6/wc` | 181 | 107 | 0 | 83 | 23 | 1 | 0 | var | 6 |
