#!/bin/bash
# newlisp 10.7.5 (formül newlisp 10.7.5; şişe arm64_tahoe rebuild 0) — doğrulama seti K3:
# kaynaktan, sembolleri koruyarak, -g ile derleme (ön kayıt §4.4; yöntem test_seti_kilidi.md §4.5).
# Formül: ../newlisp/indirilen/formul-sise-newlisp.rb (şişedeki .brew/newlisp.rb; homebrew-core
# bf7ada6 ile derleme adımları aynı). Ölçülen ikili: bin/newlisp (-> newlisp-10.7.5).
#
# Kaynak: formüldeki adres (www.newlisp.org) 2026-10-19'da DNS'te çözülmedi; aynı sha256'lı
# dosya MacPorts distfiles ve Debian orig'den alındı (indirilen/KAYNAK.txt). Güncel formülün
# mirror'ı da Debian orig.
set -euo pipefail
source "$(dirname "$0")/ortam.sh"

P=${P_OVERRIDE:-$KOK/newlisp}   # P_OVERRIDE: kıyas denemesi için ayrı dizin
BAGIMLILIKLAR="readline"
KEG_ONLY="readline"
PY_BAGIMLILIK=""
SDE=1557679457                  # şişe tab: source_modified_time
FORMUL_ONEK=$HB/Cellar/newlisp/10.7.5
KAYNAK=$P/src
GUNLUK=$P/log/superenv
# Formül: ENV.append_to_cflags "-DNEWCONFIG -c" (superenv'de CFLAGS/CXXFLAGS/OBJCFLAGS/OBJCXXFLAGS)
CF="-DNEWCONFIG -c"

# 0) Ön koşullar
[ -d "$HB/opt/readline" ] || { echo "EKSİK bağımlılık: readline"; exit 2; }
[ -e "$HB/Cellar/newlisp" ] && { echo "HATA: $HB/Cellar/newlisp mevcut"; exit 3; }
if [ -z "$(ls -A "$KAYNAK")" ]; then
  /usr/bin/tar -xzf "$P/indirilen/newlisp-10.7.5.tgz" -C "$KAYNAK" --strip-components=1
fi
[ -f "$KAYNAK/makefile_build" ] && { echo "HATA: kaynak zaten yapılandırılmış"; exit 5; }

superenv_ozet > "$P/log/ortam.txt"

# 1) Formül: ./configure-alt --prefix=#{prefix} --mandir=#{man}
superenv_calistir /usr/bin/env "CFLAGS=$CF" "CXXFLAGS=$CF" "OBJCFLAGS=$CF" "OBJCXXFLAGS=$CF" \
  ./configure-alt "--prefix=$FORMUL_ONEK" "--mandir=$FORMUL_ONEK/share/man" > "$P/log/configure.log" 2>&1

# 2) Formül: make. Tek fark: STRIP=true (makefile_build bağlamadan sonra "$(STRIP) $(TARG)" çalıştırıyor).
superenv_calistir /usr/bin/env "CFLAGS=$CF" "CXXFLAGS=$CF" "OBJCFLAGS=$CF" "OBJCXXFLAGS=$CF" \
  make STRIP=true > "$P/log/make.log" 2>&1

# 3) Formül: make check — ATLANDI (derlenen ikiliyi çalıştırıyor; ikiliyi etkilemez).

# 4) Formül: make install (makefile_install DESTDIR'i destekliyor; hatalar "-" ile yutulduğu için
#    kurulan dosya ayrıca denetlenir).
superenv_calistir /usr/bin/env "CFLAGS=$CF" "CXXFLAGS=$CF" "OBJCFLAGS=$CF" "OBJCXXFLAGS=$CF" \
  make install "DESTDIR=$P/prefix" > "$P/log/make_install.log" 2>&1

[ -e "$HB/Cellar/newlisp" ] && { echo "HATA: kurulum $HB/Cellar/newlisp altına yazdı"; exit 6; }
KURULU=$P/prefix$FORMUL_ONEK/bin/newlisp-10.7.5
[ -f "$KURULU" ] || { echo "HATA: kurulan ikili yok: $KURULU"; exit 7; }

# 5) GT + dSYM + analiz kopyası
/bin/cp -p "$KURULU" "$P/gt/newlisp"
/usr/bin/dsymutil "$P/gt/newlisp" -o "$P/gt/newlisp.dSYM" > "$P/log/dsymutil.log" 2>&1
/bin/cp -p "$P/gt/newlisp" "$P/analiz/newlisp"
/usr/bin/strip "$P/analiz/newlisp"
echo "newlisp: tamam"
