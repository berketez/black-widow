#!/bin/bash
# vim 9.2.1150 (formül vim 9.2.1150; şişe arm64_tahoe, rebuild 0, python@3.14 dönemi) —
# kaynaktan, sembolleri koruyarak, -g ile derleme. Ölçülen ikili yalnız bin/vim.
# Formül: ../vim/indirilen/formul-sise-vim.rb (şişedeki .brew/vim.rb). homebrew-core
# 8bebb800c2da ("vim: update 9.2.1150 bottle.", 2026-09-30) ile bottle bloğu dışında aynı;
# o commit'teki arm64_tahoe sha256'sı sabitlenen şişeninkiyle (4ec75a2d…) aynı.
# Kaynak: indirilen/vim-9.2.1150.tar.gz (sha256 formülle eşleşti).
#
# DURUM (2026-10-19): lua 5.5.1 ve ruby 4.0.7_1 ana oturum tarafından (Berke onayıyla)
# kuruldu. Şişe döneminde (2026-09-29/30) homebrew-core'da lua 5.5.1, ruby 4.0.7 (openssl@3),
# python@3.14 3.14.7 vardı; bugün ruby 4.0.7_1 (openssl@4), python@3.14 3.14.8_2.
set -euo pipefail
source "$(dirname "$0")/ortam.sh"

P=${P_OVERRIDE:-$KOK/vim}   # P_OVERRIDE: kıyas denemesi için ayrı dizin
BAGIMLILIKLAR="gettext lua python@3.14 ruby libsodium ncurses json-c libunistring"
KEG_ONLY="ncurses"
PY_BAGIMLILIK="python@3.14"
SDE=1790706006                           # şişe tab: source_modified_time
FORMUL_ONEK=$HB/Cellar/vim/9.2.1150
KAYNAK=$P/src
GUNLUK=$P/log/superenv

# 0) Ön koşullar
eksik=""
for d in gettext lua python@3.14 ruby libsodium ncurses; do [ -d "$HB/opt/$d" ] || eksik="$eksik $d"; done
if [ -n "$eksik" ]; then
  echo "EKSİK bağımlılık:$eksik — kurulmadı (görev kuralı). Derleme yapılmadı."
  exit 2
fi
[ -e "$HB/Cellar/vim" ] && { echo "HATA: $HB/Cellar/vim mevcut"; exit 3; }
if [ -z "$(ls -A "$KAYNAK")" ]; then
  /usr/bin/tar -xzf "$P/indirilen/vim-9.2.1150.tar.gz" -C "$KAYNAK" --strip-components=1
fi
[ -f "$KAYNAK/src/auto/config.status" ] && { echo "HATA: kaynak zaten yapılandırılmış"; exit 5; }

superenv_ozet > "$P/log/ortam.txt"

# 1) Formül: ENV.prepend_path "PATH", opt_libexec(python@3.14)/bin  (ortam.sh PY_BAGIMLILIK ile
#    PATH'e zaten giriyor; formül onu en öne alıyor -> burada da en öne)
#    extra_deps (build+test: lua, python@3.14, ruby) için LDFLAGS += -Wl,-rpath,<@loader_path göreli>
#    rpath(target: opt_lib) = @loader_path/<bin'den opt/<dep>/lib'e göreli yol>
RP=""
for d in lua python@3.14 ruby; do RP="$RP -Wl,-rpath,@loader_path/../../../../opt/$d/lib"; done
RP=${RP# }
PYBIN=$HB/opt/python@3.14/libexec/bin

superenv_calistir /bin/sh -c 'PATH="$0:$PATH" exec /usr/bin/env "LDFLAGS=$1" ./configure \
  --prefix=/opt/homebrew \
  --mandir=/opt/homebrew/Cellar/vim/9.2.1150/share/man \
  --enable-multibyte \
  --with-tlib=ncurses \
  --with-compiledby=Homebrew \
  --enable-cscope \
  --enable-terminal \
  --enable-perlinterp \
  --enable-python3interp=dynamic \
  --enable-rubyinterp=dynamic \
  --disable-gui \
  --without-x \
  --enable-luainterp=dynamic \
  --with-lua-prefix=/opt/homebrew/opt/lua' "$PYBIN" "$RP" > "$P/log/configure.log" 2>&1

# 2) Formül: make ; ENV.deparallelize ; make install prefix=#{prefix}
superenv_calistir /bin/sh -c 'PATH="$0:$PATH" exec /usr/bin/env "LDFLAGS=$1" make' "$PYBIN" "$RP" \
  > "$P/log/make.log" 2>&1
#    Tek fark: STRIP=true (install hedefi "$(STRIP) $(DEST_BIN)/$(VIMTARGET)" ile soyuyor).
superenv_calistir /bin/sh -c 'PATH="$0:$PATH" exec /usr/bin/env "LDFLAGS=$1" MAKEFLAGS= HOMEBREW_MAKE_JOBS=1 \
  make install "prefix=/opt/homebrew/Cellar/vim/9.2.1150" "DESTDIR=$2" STRIP=true' "$PYBIN" "$RP" "$P/prefix" \
  > "$P/log/make_install.log" 2>&1

[ -e "$HB/Cellar/vim" ] && { echo "HATA: kurulum $HB/Cellar/vim altına yazdı"; exit 6; }

# 3) GT + dSYM + analiz kopyası (yalnız vim)
/bin/cp -p "$P/prefix$FORMUL_ONEK/bin/vim" "$P/gt/vim"
/usr/bin/dsymutil "$P/gt/vim" -o "$P/gt/vim.dSYM" > "$P/log/dsymutil.log" 2>&1
/bin/cp -p "$P/gt/vim" "$P/analiz/vim"
/usr/bin/strip "$P/analiz/vim"
echo "vim: tamam"
