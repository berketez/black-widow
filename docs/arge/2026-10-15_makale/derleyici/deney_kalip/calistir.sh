#!/bin/bash
# Kalıp deneyini baştan üretir. Ortam: Apple clang 21.0.0 (clang-2100.3.34.2), Ghidra 12.1.2.
# Kullanım: bash calistir.sh   (bu klasörün içinden)
set -euo pipefail
D="$(cd "$(dirname "$0")" && pwd)"
cd "$D"
mkdir -p bin asm decomp gin ghidra_proj

# 1) Ana deney: 4 yapı (arm64/x86_64 x O0/O2) + iki karşılaştırma yapısı
for arch in arm64 x86_64; do
  for O in O0 O2; do
    clang -target ${arch}-apple-macos13 -$O -g0 kaliplar.c -o bin/k_${arch}_${O}
    objdump -d --no-show-raw-insn --print-imm-hex bin/k_${arch}_${O} > asm/k_${arch}_${O}.s
    python3 -I annot.py bin/k_${arch}_${O} asm/k_${arch}_${O}.s asm/k_${arch}_${O}.ann.s
  done
done
clang -target arm64-apple-macos13 -O2 -D_FORTIFY_SOURCE=0 kaliplar.c -o bin/k_arm64_O2_nofortify
clang -target arm64-apple-macos13 -O2 -fno-stack-protector kaliplar.c -o bin/k_arm64_O2_nossp

# 2) Linux hedefli nesne dosyaları (sysroot gerekmez): atlama tablosu, yığın koruyucu, errno
for t in arm64-apple-macos13 x86_64-apple-macos13 x86_64-linux-gnu aarch64-linux-gnu; do
  clang -target $t -O2 -fstack-protector-strong -c k2.c -o bin/k2_$t.o
  objdump -dr --no-show-raw-insn --print-imm-hex bin/k2_$t.o > asm/k2_$t.s
done

# 3) Atlama tablosu eşiği: N vakalı switch, her vaka farklı dış çağrı
for n in 4 5 6 7 8 9 10 11; do
  python3 -c "
n=$n
print(' '.join(f'extern int h{i}(int);' for i in range(n)))
print('int d(int op,int v){switch(op){')
for i in range(n): print(f'case {i}: return h{i}(v);')
print('default: return -1;}}')" > bin/jt_$n.c
  a=$(clang -target aarch64-linux-gnu -O2 -c bin/jt_$n.c -o - | objdump -d --no-show-raw-insn - | grep -cE '\bbr\b' || true)
  x=$(clang -target x86_64-linux-gnu -O2 -c bin/jt_$n.c -o - | objdump -d --no-show-raw-insn - | grep -cE 'jmpq\s+\*' || true)
  echo "vaka=$n aarch64_atlama_tablosu=$a x86_64_atlama_tablosu=$x"
done

# 4) Ghidra decompile (headless)
cp bin/k_arm64_O0 bin/k_arm64_O2 bin/k_x86_64_O0 bin/k_x86_64_O2 gin/
G=/Users/apple/Library/BlackWidowBuild/ghidra_12.1.2_PUBLIC/support/analyzeHeadless
"$G" "$D/ghidra_proj" deney -import "$D/gin" -recursive -overwrite \
  -scriptPath "$D/ghidra_scripts" -postScript DumpDecomp.java "$D/decomp" -deleteProject
