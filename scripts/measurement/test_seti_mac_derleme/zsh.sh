#!/bin/bash
# zsh 5.9.2 (formül zsh 5.9.2; şişe arm64_tahoe) — kaynaktan, yerel sembolleri koruyarak,
# -g ile derleme. Formül: ../zsh/indirilen/formul-sise-zsh.rb (şişedeki .brew/zsh.rb;
# homebrew-core bf7ada6 ile derleme adımları aynı). Ölçülen ikili yalnız bin/zsh.
set -euo pipefail
source "$(dirname "$0")/ortam.sh"

P=${P_OVERRIDE:-$KOK/zsh}   # P_OVERRIDE: yeniden derleme denemesi için ayrı dizin
BAGIMLILIKLAR="ncurses pcre2 texinfo"   # texinfo yalnız build (macOS ventura+), install.info için
KEG_ONLY="ncurses"
PY_BAGIMLILIK=""
SDE=1783881774                           # şişe tab: source_modified_time
FORMUL_ONEK=$HB/Cellar/zsh/5.9.2
KAYNAK=$P/src
GUNLUK=$P/log/superenv
PKGSHARE=$FORMUL_ONEK/share/zsh

# 0) Ön koşullar
for d in ncurses pcre2; do [ -d "$HB/opt/$d" ] || { echo "EKSİK bağımlılık: $d"; exit 2; }; done
[ -d "$HB/opt/texinfo" ] || echo "NOT: texinfo kurulu değil; yalnız 'make install.info' (belge) atlanır, ikiliyi etkilemez."
[ -e "$HB/Cellar/zsh" ] && { echo "HATA: $HB/Cellar/zsh mevcut; DESTDIR denetimi için temiz olmalı"; exit 3; }
if [ -z "$(ls -A "$KAYNAK")" ]; then
  /usr/bin/tar -xJf "$P/indirilen/zsh-5.9.2.tar.xz" -C "$KAYNAK" --strip-components=1
fi
[ -f "$KAYNAK/config.status" ] && { echo "HATA: kaynak zaten yapılandırılmış; temiz kaynak gerekli"; exit 5; }

superenv_ozet > "$P/log/ortam.txt"

# 1) Formül: ./configure *args *std_configure_args DL_EXT=bundle
#    Tek fark: LDFLAGS tanımlı ama boş. configure LDFLAGS tanımsızsa darwin'de
#    LDFLAGS=-Wl,-x koyuyor (yerel semboller atılıyor; şişedeki nlocalsym=0'ın sebebi).
superenv_calistir /usr/bin/env LDFLAGS= ./configure \
  "--enable-fndir=$PKGSHARE/functions" \
  "--enable-scriptdir=$PKGSHARE/scripts" \
  "--enable-site-fndir=$HB/share/zsh/site-functions" \
  "--enable-site-scriptdir=$HB/share/zsh/site-scripts" \
  "--enable-runhelpdir=$PKGSHARE/help" \
  --enable-maildir-support \
  --enable-multibyte \
  --enable-pcre \
  --enable-zsh-secure-free \
  --enable-unicode9 \
  --enable-etcdir=/etc \
  --with-tcsetpgrp \
  --disable-debug --disable-dependency-tracking \
  "--prefix=$FORMUL_ONEK" "--libdir=$FORMUL_ONEK/lib" \
  DL_EXT=bundle > "$P/log/configure.log" 2>&1

# 2) Formül: inreplace ["Makefile", "Src/Makefile"], "$(libdir)/$(tzsh)/$(VERSION)", "$(libdir)"
/usr/bin/python3 -I - "$KAYNAK/Makefile" "$KAYNAK/Src/Makefile" <<'EOF'
import sys
eski, yeni = "$(libdir)/$(tzsh)/$(VERSION)", "$(libdir)"
for p in sys.argv[1:]:
    s = open(p).read()
    if eski not in s:
        sys.exit("inreplace: dizgi bulunamadı: " + p)
    open(p, "w").write(s.replace(eski, yeni))
print("inreplace: 2 dosya")
EOF

# 3) Formül: make install  (DESTDIR ile bizim öneke; STRIPFLAGS zaten boş, açıkça boş verildi)
#    "make install.info" (texinfo) ve htmldoc kaynağı belge; atlandı.
superenv_calistir make install "DESTDIR=$P/prefix" STRIPFLAGS= > "$P/log/make_install.log" 2>&1

[ -e "$HB/Cellar/zsh" ] && { echo "HATA: kurulum $HB/Cellar/zsh altına yazdı"; exit 6; }

# 4) GT + dSYM + analiz kopyası
KURULU=$P/prefix$FORMUL_ONEK/bin/zsh
/bin/cp -p "$KURULU" "$P/gt/zsh"
/usr/bin/dsymutil "$P/gt/zsh" -o "$P/gt/zsh.dSYM" > "$P/log/dsymutil.log" 2>&1
/bin/cp -p "$P/gt/zsh" "$P/analiz/zsh"
/usr/bin/strip "$P/analiz/zsh"
echo "zsh: tamam"
