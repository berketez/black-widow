#!/bin/zsh
# Mach-O LC_MAIN girişi = _main sembolü mü? (hiçbir ikili çalıştırılmaz; otool + nm)
# Komut: zsh scripts/arge/karsi/lc_main.sh > $V/lc_main.txt
for b in /opt/homebrew/bin/tmux /opt/homebrew/bin/htop /opt/homebrew/bin/xz /opt/homebrew/bin/gsort /opt/homebrew/bin/btop; do
  [ -e "$b" ] || { echo "$b yok"; continue; }
  e=$(/usr/bin/otool -arch arm64 -l "$b" | awk '/LC_MAIN/{f=1} f&&/entryoff/{print $2; exit}')
  m=$(/usr/bin/nm -arch arm64 "$b" 2>/dev/null | awk '$3=="_main"{print $1}')
  python3 -c "
e=int('$e' or 0); m='$m'
print('$b', 'entryoff', hex(e), '_main', m or 'yok', 'AYNI' if m and int(m,16)==0x100000000+e else 'FARKLI')"
done
