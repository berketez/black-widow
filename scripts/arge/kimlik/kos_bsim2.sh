#!/bin/bash
# KİMLİK hattı — temiz BSim koşularının kalanı (DEFTER.md §5.14): kos_bsim.sh tmux adımlarında durduruldu
# (makine yükü; tam koşu 25+ dk). Kalan üç koşu `--stage static` ile (BSim sorgusu statik aşamada yapılır;
# ghidra_bsim.json o aşamada yazılır). kos_kuyruk.sh bitene kadar bekler (aynı anda tek Ghidra koşum).
# tmux_md deposunda Mac tmux statik aşaması (BSim'e ekleme dahil) kos_bsim.sh'in yarım koşusunda tamamlandı.
set -u
A="$HOME/karadul_olcum/urun-a62f15e"
K="$HOME/karadul_olcum/runs/arge-2026-11-19/kimlik/bsim"
DEB="$HOME/karadul_olcum/n1_debian13"
MAC="$HOME/Black_Widow/workspaces/olcum_mac/runs/ol7-c-b7faeac"
D_TMUX="$DEB/tmux/tmux/ws/workspaces/tmux/20261021_092848/raw/tmux"
M_TMUX="$MAC/tmux/ws/workspaces/tmux/20261021_085320/raw/tmux"
while pgrep -f "kos_kuyruk.sh" >/dev/null 2>&1; do sleep 15; done
kos() {  # kos <depo> <sıra_ad> <ikili>
  local D="$K/$1/$2"
  if [ -f "$D/BITTI" ]; then echo "$1/$2 zaten bitti"; return; fi
  mkdir -p "$D" "$K/$1/cache"
  local t0; t0=$(date +%s)
  ( cd "$A" && GHIDRA_INSTALL_DIR="$HOME/Library/BlackWidowBuild/ghidra_12.1.2_PUBLIC" PYTHONPATH="$A" \
      PYTHONHASHSEED=0 PYTHONDONTWRITEBYTECODE=1 KARADUL_CACHE_DIR="$K/$1/cache" \
      /opt/anaconda3/bin/python -m karadul analyze "$3" --skip-dynamic --stage static --output-dir "$D/ws" --output "$D/out" \
      > "$D/kosu.log" 2>&1 )
  echo $? > "$D/BITTI"
  echo "$1/$2 $(( $(date +%s) - t0 )) sn çıkış $(cat "$D/BITTI")"
}
kos tmux_md 2_debian "$D_TMUX"
kos tmux_dm 1_debian "$D_TMUX"; kos tmux_dm 2_mac "$M_TMUX"
echo BITTI_HEPSI
