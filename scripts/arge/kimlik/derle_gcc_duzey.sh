#!/bin/bash
# KİMLİK hattı — tmux 3.8'in GCC 16 ile -O0 ve -O3 derlemeleri (iyileştirme düzeyi etkisi; DEFTER.md §5.11).
# Kaynak: K/gcc/src/tmux-3.8'in ayrı kopyaları (ilk derlemenin ağacına dokunulmaz).
set -u
G="$HOME/karadul_olcum/runs/arge-2026-11-19/kimlik/gcc"
S="$HOME/Black_Widow/workspaces/2026-10-15_oturum_scratchpad/src"
B=/opt/homebrew
export PKG_CONFIG_PATH="$B/opt/libevent/lib/pkgconfig:$B/opt/ncurses/lib/pkgconfig:$B/opt/utf8proc/lib/pkgconfig"
export PATH="$B/bin:/usr/bin:/bin:/usr/sbin:/sbin"
for d in O0 O3; do
  if [ ! -d "$G/src/tmux-3.8-$d" ]; then cp -R "$S/tmux-dl/tmux-3.8" "$G/src/tmux-3.8-$d"; fi
  ( cd "$G/src/tmux-3.8-$d" && ./configure CC=gcc-16 CFLAGS="-$d" --enable-utf8proc --enable-sixel \
      > "$G/tmux${d}_configure.log" 2>&1 && make -j2 > "$G/tmux${d}_make.log" 2>&1 && cp tmux "$G/ozgun/tmux$d" )
  echo "tmux$d çıkış $?"
done
shasum -a 256 "$G/ozgun/tmuxO0" "$G/ozgun/tmuxO3"
