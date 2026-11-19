#!/bin/bash
# KİMLİK hattı — -O0 / -O3 GCC derlemelerinin ürün koşusu (DEFTER.md §5.11). Öbür koşu betikleri bitene kadar bekler.
set -u
A="$HOME/karadul_olcum/urun-a62f15e"
G="$HOME/karadul_olcum/runs/arge-2026-11-19/kimlik/gcc"
while pgrep -f "kos_bsim.sh|kos_gcc.sh|kos_ek.sh" >/dev/null 2>&1; do sleep 15; done
for b in tmuxO3 tmuxO0; do
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
