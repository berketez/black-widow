#!/bin/zsh
set -u
B=/Library/Developer/CommandLineTools/usr/bin
DI=/usr/bin/dyld_info
D=${0:A:h}; cd $D; O=out
# E3b funcspec: ipsccp sonrası IR
{ echo "== -O3 print-after=ipsccp"; clang -O3 -c src/funcspec.c -o /dev/null -mllvm -print-after=ipsccp 2>&1 | grep -E '^define'
  echo "== -O3 -fno-inline print-after=ipsccp"; clang -O3 -fno-inline -c src/funcspec.c -o /dev/null -mllvm -print-after=ipsccp 2>&1 | grep -E '^define'
  echo "== -O3 funcspec-min-function-size=1 print-after=ipsccp"; clang -O3 -c src/funcspec.c -o /dev/null -mllvm -print-after=ipsccp -mllvm -funcspec-min-function-size=1 2>&1 | grep -E '^define'
} > $O/E3b_funcspec.txt 2>&1
# E5 dedup
for L in 0 2; do clang -O$L src/dedup.c -o $O/dedup_O$L; echo "== dedup -O$L"; $B/nm -n $O/dedup_O$L | grep -v ' U '; done > $O/E5_dedup.txt
{ echo "== -O2 -Wl,-no_deduplicate"; clang -O2 -Wl,-no_deduplicate src/dedup.c -o $O/dedup_O2_nodedup; $B/nm -n $O/dedup_O2_nodedup | grep -v ' U '; } >> $O/E5_dedup.txt
for L in 0 1 2 s z; do echo "-O$L link satırı: $(clang -O$L -### src/dedup.c -o /dev/null 2>&1 | tail -1 | tr ' ' '\n' | grep -E 'no_deduplicate|dead_strip|"-O|lto|platform_version' | tr '\n' ' ')"; done >> $O/E5_dedup.txt
echo "-O2 sadece link (.o'dan): $(clang -O2 -### $O/inline_O2.o -o /dev/null 2>&1 | tail -1 | tr ' ' '\n' | grep -c no_deduplicate)" >> $O/E5_dedup.txt
echo "argümansız (derle+bağla): $(clang -### src/dedup.c -o /dev/null 2>&1 | tail -1 | tr ' ' '\n' | grep -c no_deduplicate)" >> $O/E5_dedup.txt
# E6 strip
clang -O2 src/inline.c -o $O/s_plain
clang -O2 -Wl,-x src/inline.c -o $O/s_Wlx
clang -O2 -Wl,-S src/inline.c -o $O/s_WlS
clang -O2 -Wl,-dead_strip src/inline.c -o $O/s_deadstrip
clang -O2 -g src/inline.c -o $O/s_g
cp $O/s_plain $O/s_strip; $B/strip $O/s_strip
cp $O/s_plain $O/s_stripx; $B/strip -x $O/s_stripx
cp $O/s_plain $O/s_stripS; $B/strip -S $O/s_stripS
for f in s_plain s_g s_Wlx s_WlS s_deadstrip s_strip s_stripx s_stripS; do
  echo "== $f  boyut=$(stat -f %z $O/$f)"
  echo "  nm: $($B/nm $O/$f | awk '{print $(NF-1)":"$NF}' | tr '\n' ' ')"
  echo "  stab(N_OSO/N_FUN vs.): $($B/nm -a $O/$f | grep -c -E ' - ')"
  echo "  exports: $($DI -exports $O/$f | tail -n +3 | awk '{print $NF}' | tr '\n' ' ')"
  echo "  function_starts: $($DI -function_starts $O/$f | tail -n +3 | wc -l | tr -d ' ')"
  echo "  codesign: $(codesign -v $O/$f 2>&1 | head -1)"
done > $O/E6_strip.txt 2>&1
$DI -function_starts $O/s_strip >> $O/E6_strip.txt
# E7 ABI
clang -O2 src/abi.c -o $O/abi_O2
$B/otool -tV $O/abi_O2 > $O/E7_abi.txt
clang -O2 -arch arm64e src/abi.c -o $O/abi_O2_e
$B/otool -tV $O/abi_O2_e > $O/E7_abi_arm64e.txt
{ $B/otool -l $O/abi_O2_e | grep -A2 -E 'sectname __auth|sectname __stubs|sectname __got'; $B/otool -l $O/abi_O2 | grep -A2 -E 'sectname __stubs|sectname __got|sectname __la_symbol|sectname __stub_helper'; } > $O/E7_sections.txt
# E9 fixups
{ $B/otool -l $O/abi_O2 | grep -E 'cmd LC_' | sort | uniq -c; echo "== fixups"; $DI -fixups $O/abi_O2; echo "== fixup_chains"; $DI -fixup_chains $O/abi_O2; echo "== stubs"; $B/otool -v -s __TEXT __stubs $O/abi_O2; $B/llvm-objdump -d --section=__stubs $O/abi_O2 | tail -12; } > $O/E9_fixups.txt 2>&1
echo bitti
