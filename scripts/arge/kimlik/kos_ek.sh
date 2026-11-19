#!/bin/bash
# KİMLİK hattı — ek ürün koşuları (DEFTER.md §5.10): (1) Homebrew coreutils ikilileri a62f15e ağacıyla (aynı kuşak),
# (2) Mac tmux'un SEMBOLLÜ analizi (başvuru). kos_bsim.sh ve kos_gcc.sh bitene kadar bekler; sıralı.
set -u
A="$HOME/karadul_olcum/urun-a62f15e"
E="$HOME/karadul_olcum/runs/arge-2026-11-19/kimlik/ek"
O="$HOME/karadul_olcum/runs/onarim-2026-11-18"
while pgrep -f "kos_bsim.sh|kos_gcc.sh" >/dev/null 2>&1; do sleep 15; done

kos() {  # kos <dizin> <ikili>
  local D="$E/$1"
  if [ -f "$D/BITTI" ]; then echo "$1 zaten bitti"; return; fi
  mkdir -p "$D" "$E/cache"
  local t0; t0=$(date +%s)
  ( cd "$A" && GHIDRA_INSTALL_DIR="$HOME/Library/BlackWidowBuild/ghidra_12.1.2_PUBLIC" PYTHONPATH="$A" \
      PYTHONHASHSEED=0 PYTHONDONTWRITEBYTECODE=1 KARADUL_CACHE_DIR="$E/cache" \
      /opt/anaconda3/bin/python -m karadul analyze "$2" --skip-dynamic --output-dir "$D/ws" --output "$D/out" \
      > "$D/kosu.log" 2>&1 )
  echo $? > "$D/BITTI"
  echo "ek/$1 $(( $(date +%s) - t0 )) sn çıkış $(cat "$D/BITTI")"
}

kos macgnu2/gcat    "$O/P-S3/mac_gnulib/corpus/gcat/bin/gcat"
kos macgnu2/gsort   "$O/P-S3b/mac_kabul/corpus/gsort/bin/gsort"
kos macgnu2/gmktemp "$O/P-S3b/mac_kabul/corpus/gmktemp/bin/gmktemp"
kos macsym/tmux     "$HOME/Black_Widow/workspaces/olcum_mac/corpus/tmux/orig/tmux"
echo BITTI_HEPSI
