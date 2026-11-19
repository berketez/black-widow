#!/bin/bash
# KİMLİK hattı — ek ürün koşularının tek kuyruğu (kos_gcc.sh, kos_ek.sh, kos_duzey.sh'in yerine; onlar hiç koşu
# başlatmadan durduruldu). Fark: `--stage static` — eşleyici yalnız static/ çıktılarını okuyor; makine yükü çok
# yüksek olduğu için (yük ortalaması ~40) sonraki aşamalar koşulmuyor. İlk adım denetimdir: Debian htop
# `--stage static` ile koşulur ve static/ dosyaları taban koşusununkilerle karşılaştırılır (son_olcum.sh denetim).
# kos_bsim.sh bitene kadar bekler (aynı anda tek Ghidra koşum). Sıra: önce en önemli ölçüm (GCC tmux).
set -u
A="$HOME/karadul_olcum/urun-a62f15e"
K="$HOME/karadul_olcum/runs/arge-2026-11-19/kimlik"
G="$K/gcc"
O="$HOME/karadul_olcum/runs/onarim-2026-11-18"
while pgrep -f "kos_bsim.sh" >/dev/null 2>&1; do sleep 15; done

kos() {  # kos <çıktı dizini> <önbellek dizini> <ikili>
  local D="$1"
  if [ -f "$D/BITTI" ]; then echo "$D zaten bitti"; return; fi
  mkdir -p "$D" "$2"
  local t0; t0=$(date +%s)
  ( cd "$A" && GHIDRA_INSTALL_DIR="$HOME/Library/BlackWidowBuild/ghidra_12.1.2_PUBLIC" PYTHONPATH="$A" \
      PYTHONHASHSEED=0 PYTHONDONTWRITEBYTECODE=1 KARADUL_CACHE_DIR="$2" \
      /opt/anaconda3/bin/python -m karadul analyze "$3" --skip-dynamic --stage static --output-dir "$D/ws" --output "$D/out" \
      > "$D/kosu.log" 2>&1 )
  echo $? > "$D/BITTI"
  echo "${D#$K/} $(( $(date +%s) - t0 )) sn çıkış $(cat "$D/BITTI")"
}

kos "$K/denetim/htop_static" "$K/denetim/cache" "$HOME/karadul_olcum/n1_debian13/htop/htop/ws/workspaces/htop/20261021_092848/raw/htop"
kos "$G/kosu/tmux"   "$G/cache" "$G/corpus/tmux/bin/tmux"
kos "$G/kosu/htop"   "$G/cache" "$G/corpus/htop/bin/htop"
kos "$K/ek/macsym/tmux"     "$K/ek/cache" "$HOME/Black_Widow/workspaces/olcum_mac/corpus/tmux/orig/tmux"
kos "$G/kosu/tmuxO3" "$G/cache" "$G/corpus/tmuxO3/bin/tmuxO3"
kos "$G/kosu/tmuxO0" "$G/cache" "$G/corpus/tmuxO0/bin/tmuxO0"
kos "$K/ek/macgnu2/gcat"    "$K/ek/cache" "$O/P-S3/mac_gnulib/corpus/gcat/bin/gcat"
kos "$K/ek/macgnu2/gsort"   "$K/ek/cache" "$O/P-S3b/mac_kabul/corpus/gsort/bin/gsort"
kos "$K/ek/macgnu2/gmktemp" "$K/ek/cache" "$O/P-S3b/mac_kabul/corpus/gmktemp/bin/gmktemp"
echo BITTI_HEPSI
