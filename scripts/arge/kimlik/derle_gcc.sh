#!/bin/bash
# KİMLİK hattı — aynı sürümün GCC derlemesi (DEFTER.md §5.9). İndirme yok; kaynak diskteki ağaçtan kopyalanır.
# Çıktı: ~/karadul_olcum/runs/arge-2026-11-19/kimlik/gcc/ozgun/{tmux,htop} (sembollü ikililer) + derleme günlükleri.
set -u
G="$HOME/karadul_olcum/runs/arge-2026-11-19/kimlik/gcc"
S="$HOME/Black_Widow/workspaces/2026-10-15_oturum_scratchpad/src"
B=/opt/homebrew
export PKG_CONFIG_PATH="$B/opt/libevent/lib/pkgconfig:$B/opt/ncurses/lib/pkgconfig:$B/opt/utf8proc/lib/pkgconfig"
export PATH="$B/bin:/usr/bin:/bin:/usr/sbin:/sbin"

kopyala() {  # kopyala <kaynak dizin> <ad>
  if [ ! -d "$G/src/$2" ]; then cp -R "$1" "$G/src/$2"; fi
}

kopyala "$S/tmux-dl/tmux-3.8" tmux-3.8
kopyala "$S/htop-dl/htop-3.5.3" htop-3.5.3

( cd "$G/src/tmux-3.8" && ./configure CC=gcc-16 CFLAGS="-O2" --enable-utf8proc --enable-sixel \
    > "$G/tmux_configure.log" 2>&1 && make -j4 > "$G/tmux_make.log" 2>&1 && cp tmux "$G/ozgun/tmux" )
echo "tmux çıkış $?"
( cd "$G/src/htop-3.5.3" && ./configure CC=gcc-16 CFLAGS="-O2" \
    CPPFLAGS="-I$B/opt/ncurses/include" LDFLAGS="-L$B/opt/ncurses/lib" \
    > "$G/htop_configure.log" 2>&1 && make -j4 > "$G/htop_make.log" 2>&1 && cp htop "$G/ozgun/htop" )
echo "htop çıkış $?"
ls -la "$G/ozgun"
