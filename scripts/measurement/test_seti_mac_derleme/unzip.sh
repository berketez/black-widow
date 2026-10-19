#!/bin/bash
# unzip 6.0 (formül unzip 6.0_8; şişe arm64_tahoe rebuild 1) — kaynaktan, sembolleri
# koruyarak, -g ile derleme. Formül: ../unzip/indirilen/formul-sise-unzip.rb
# (şişenin içindeki .brew/unzip.rb; homebrew-core bf7ada6 ile derleme adımları aynı).
set -euo pipefail
source "$(dirname "$0")/ortam.sh"

P=${P_OVERRIDE:-$KOK/unzip}   # P_OVERRIDE: yeniden derleme denemesi için ayrı dizin
BAGIMLILIKLAR=""          # uses_from_macos "bzip2" -> macOS'taki libbz2; başka bağımlılık yok
KEG_ONLY=""
PY_BAGIMLILIK=""
SDE=1240192822            # şişe tab: source_modified_time
FORMUL_ONEK=$HB/Cellar/unzip/6.0_8
KAYNAK=$P/src
GUNLUK=$P/log/superenv

# 0) Kaynak + 29 Ubuntu yaması (formüldeki apply listesi, sırayla; patch -g 0 -f -p1)
if [ -z "$(ls -A "$KAYNAK")" ]; then
  /usr/bin/tar -xzf "$P/indirilen/unzip60.tar.gz" -C "$KAYNAK" --strip-components=1
  mkdir -p "$P/yama"
  /usr/bin/tar -xJf "$P/indirilen/unzip_6.0-28ubuntu4.1.debian.tar.xz" -C "$P/yama"
  /usr/bin/python3 -I -c "
import re
s=open('$P/indirilen/formul-sise-unzip.rb').read()
print('\n'.join(re.search(r'apply %w\[(.*?)\]', s, re.S).group(1).split()))" > "$P/log/yama_listesi.txt"
  : > "$P/log/yama_uygulama.log"
  while read -r y; do
    (cd "$KAYNAK" && /usr/bin/sed "s|@@HOMEBREW_PREFIX@@|/opt/homebrew|g" "$P/yama/debian/$y" \
       | /usr/bin/patch -g 0 -f -p1 >> "$P/log/yama_uygulama.log" 2>&1)
  done < "$P/log/yama_listesi.txt"
  echo "29 yama uygulandı" > "$KAYNAK/.yamalar_uygulandi"
fi
[ -f "$KAYNAK/.yamalar_uygulandi" ] || { echo "HATA: yamalar uygulanmamış görünüyor"; exit 4; }
[ -e "$KAYNAK/unzip" ] && { echo "HATA: kaynak dizininde önceki derleme var; temiz kaynak gerekli"; exit 5; }

superenv_ozet > "$P/log/ortam.txt"

# 1) Formül: make -f unix/Makefile CC=clang CFLAGS= LOC=... D_USE_BZ2=... L_BZ2=-lbz2 LFLAGS1=-liconv macosx
#    Tek ek: STRIP=true -> macosx hedefinin "$(STRIP) $(UNZIPS)" adımı soymaz.
#    (Bağlamada -s yok: macosx hedefi LF2="" veriyor.)
LOC="-DLARGE_FILE_SUPPORT -DUNICODE_SUPPORT -DUNICODE_WCHAR -DUTF8_MAYBE_NATIVE -DNO_WORKING_ISPRINT"
superenv_calistir make -f unix/Makefile CC=clang CFLAGS= "LOC=$LOC" D_USE_BZ2=-DUSE_BZIP2 L_BZ2=-lbz2 \
  LFLAGS1=-liconv macosx STRIP=true > "$P/log/make.log" 2>&1

# 2) Formül: make -f unix/Makefile prefix=#{prefix} MANDIR=#{man1} install  (install = cp, soymaz)
superenv_calistir make -f unix/Makefile "prefix=$P/prefix" "MANDIR=$P/prefix/share/man/man1" install \
  > "$P/log/make_install.log" 2>&1

# 3) GT + dSYM + analiz kopyası
/bin/cp -p "$P/prefix/bin/unzip" "$P/gt/unzip"
/usr/bin/dsymutil "$P/gt/unzip" -o "$P/gt/unzip.dSYM" > "$P/log/dsymutil.log" 2>&1
/bin/cp -p "$P/gt/unzip" "$P/analiz/unzip"
/usr/bin/strip "$P/analiz/unzip"
echo "unzip: tamam"
