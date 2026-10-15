#!/bin/zsh
set -u
B=/Library/Developer/CommandLineTools/usr/bin
D=${0:A:h}; cd $D
O=out
# E1 satıriçi açma
for L in 0 1 2 3 s z; do
  clang -O$L -c src/inline.c -o $O/inline_O$L.o 2>/dev/null
  echo "inline.c -O$L .o sembolleri: $($B/nm $O/inline_O$L.o | grep -v ltmp | awk '{print $(NF-1)":"$NF}' | tr '\n' ' ')"
done > $O/E1_inline.txt
# E2 IPO imza değişimi
for L in 2 3; do
  echo "== ipo.c -O$L IR tanımları"; clang -O$L -S -emit-llvm src/ipo.c -o - | grep -E '^define' 
  clang -O$L -c src/ipo.c -o $O/ipo_O$L.o; echo "== nm"; $B/nm $O/ipo_O$L.o | grep -v ltmp
  echo "== otool"; $B/otool -tV $O/ipo_O$L.o | sed -n '1,200p'
done > $O/E2_ipo.txt 2>&1
# E3 function specialization
for L in 2 3 s; do
  echo "== funcspec.c -O$L"; clang -O$L -S -emit-llvm src/funcspec.c -o - | grep -E '^define|call .*@'
  clang -O$L -c src/funcspec.c -o $O/funcspec_O$L.o; $B/nm $O/funcspec_O$L.o | grep -v ltmp
done > $O/E3_funcspec.txt 2>&1
# E4 hot/cold splitting
for L in 0 1 2 3 s z; do
  clang -O$L src/coldsplit.c -o $O/cold_O$L 2>/dev/null
  echo "coldsplit -O$L: $($B/nm $O/cold_O$L | awk '{print $(NF-1)":"$NF}' | tr '\n' ' ')"
done > $O/E4_cold.txt
clang -O2 -mllvm -hot-cold-split=false src/coldsplit.c -o $O/cold_O2_nosplit; echo "coldsplit -O2 -hot-cold-split=false: $($B/nm $O/cold_O2_nosplit | awk '{print $(NF-1)":"$NF}' | tr '\n' ' ')" >> $O/E4_cold.txt
$B/otool -tV $O/cold_O2 | sed -n '1,80p' >> $O/E4_cold.txt
# E11 vektörleme
for L in 1 2 3 s z; do
  clang -O$L -c src/vec.c -o $O/vec_O$L.o
  echo "== vec.c -O$L: $($B/otool -tV $O/vec_O$L.o | grep -c -E '\bv[0-9]+\.(4s|2s|8h|16b)|ld1|addv|fmla') NEON benzeri satır, toplam $($B/otool -tV $O/vec_O$L.o | grep -c '^0') komut"
done > $O/E11_vec.txt
$B/otool -tV $O/vec_O2.o | sed -n '1,60p' >> $O/E11_vec.txt
echo bitti
