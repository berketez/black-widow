#!/bin/bash
# KİMLİK hattı — GCC derlemelerinin ürün koşusu (DEFTER.md §5.9). kos_bsim.sh bitene kadar bekler (aynı anda
# tek Ghidra koşum). Ürün ağacı ve komut taban koşusuyla aynı.
set -u
A="$HOME/karadul_olcum/urun-a62f15e"
G="$HOME/karadul_olcum/runs/arge-2026-11-19/kimlik/gcc"
while pgrep -f "kos_bsim.sh" >/dev/null 2>&1; do sleep 15; done
for b in htop tmux; do
  D="$G/kosu/$b"
  if [ -f "$D/BITTI" ]; then echo "$b zaten bitti"; continue; fi
  mkdir -p "$D" "$G/cache"
  t0=$(date +%s)
  ( cd "$A" && GHIDRA_INSTALL_DIR="$HOME/Library/BlackWidowBuild/ghidra_12.1.2_PUBLIC" PYTHONPATH="$A" \
      PYTHONHASHSEED=0 PYTHONDONTWRITEBYTECODE=1 KARADUL_CACHE_DIR="$G/cache" \
      /opt/anaconda3/bin/python -m karadul analyze "$G/corpus/$b/bin/$b" --skip-dynamic --output-dir "$D/ws" --output "$D/out" \
      > "$D/kosu.log" 2>&1 )
  echo $? > "$D/BITTI"
  echo "gcc/$b $(( $(date +%s) - t0 )) sn çıkış $(cat "$D/BITTI")"
done
echo BITTI_HEPSI
