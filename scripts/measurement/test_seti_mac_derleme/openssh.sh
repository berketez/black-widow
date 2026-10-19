#!/bin/bash
# openssh 10.6p1 (formül openssh 10.6p1_1; şişe arm64_tahoe) — kaynaktan, sembolleri
# koruyarak, -g ile derleme. Ölçülen ikili yalnız bin/ssh.
# Formül: ../openssh/indirilen/formul-sise-openssh.rb (şişedeki .brew/openssh.rb;
# homebrew-core bf7ada6 ile derleme adımları aynı).
#
# DURUM (2026-10-19): ÇALIŞTIRILMADI. ldns, libfido2 (ve libcbor) kurulu değil;
# görev kuralı gereği kurulmadı. Bağımlılıklar kurulunca bu betik olduğu gibi çalışır.
# Derlenen ssh ÇALIŞTIRILMAZ; "make install" yerine "make install-nokeys" kullanılır
# (install hedefi host anahtarı üretimi ve kurulu sshd ile config denetimi çalıştırıyor;
# ikilileri etkilemez).
set -euo pipefail
source "$(dirname "$0")/ortam.sh"

P=$KOK/openssh
# superenv sırası (DFS): build -> pkgconf; ldns -> openssl@4 (ca-certificates), python@3.x
# (mpdecimal, readline, sqlite, xz, lz4, zstd); libfido2 -> libcbor
BAGIMLILIKLAR="pkgconf ca-certificates openssl@4 mpdecimal readline sqlite xz lz4 zstd python@3.14 ldns libcbor libfido2"
KEG_ONLY="readline sqlite"
PY_BAGIMLILIK="python@3.14"
SDE=1791276331                           # şişe tab: source_modified_time
FORMUL_ONEK=$HB/Cellar/openssh/10.6p1_1
KAYNAK=$P/src
GUNLUK=$P/log/superenv

# 0) Ön koşullar (ssh ikilisinin bağlandığı / configure'un aradığı bağımlılıklar)
eksik=""
for d in pkgconf openssl@4 ldns libfido2 libcbor; do [ -d "$HB/opt/$d" ] || eksik="$eksik $d"; done
if [ -n "$eksik" ]; then
  echo "EKSİK bağımlılık:$eksik — kurulmadı (görev kuralı). Derleme yapılmadı."
  exit 2
fi
[ -e "$HB/Cellar/openssh" ] && { echo "HATA: $HB/Cellar/openssh mevcut"; exit 3; }
if [ -z "$(ls -A "$KAYNAK")" ]; then
  /usr/bin/tar -xzf "$P/indirilen/openssh-10.6p1.tar.gz" -C "$KAYNAK" --strip-components=1
fi
[ -f "$KAYNAK/config.status" ] && { echo "HATA: kaynak zaten yapılandırılmış"; exit 5; }

superenv_ozet > "$P/log/ortam.txt"

# 1) Formül: ENV.append "CPPFLAGS", "-D__APPLE_SANDBOX_NAMED_EXTERNAL__"
#    ./configure --sysconfdir=#{etc}/ssh --with-ldns --with-libedit --with-kerberos5 --with-pam
#                --with-ssl-dir=#{opt openssl@4} --with-security-key-builtin *std_configure_args
superenv_calistir /usr/bin/env CPPFLAGS=-D__APPLE_SANDBOX_NAMED_EXTERNAL__ ./configure \
  "--sysconfdir=$HB/etc/ssh" \
  --with-ldns --with-libedit --with-kerberos5 --with-pam \
  "--with-ssl-dir=$HB/opt/openssl@4" \
  --with-security-key-builtin \
  --disable-debug --disable-dependency-tracking \
  "--prefix=$FORMUL_ONEK" "--libdir=$FORMUL_ONEK/lib" > "$P/log/configure.log" 2>&1

# 2) Formül: make ; ENV.deparallelize ; make install
superenv_calistir /usr/bin/env CPPFLAGS=-D__APPLE_SANDBOX_NAMED_EXTERNAL__ make > "$P/log/make.log" 2>&1
#    Tek fark: STRIP_OPT= (varsayılan -s; install -s soyardı).
superenv_calistir /usr/bin/env CPPFLAGS=-D__APPLE_SANDBOX_NAMED_EXTERNAL__ MAKEFLAGS= HOMEBREW_MAKE_JOBS=1 \
  make install-nokeys "DESTDIR=$P/prefix" STRIP_OPT= > "$P/log/make_install.log" 2>&1

[ -e "$HB/Cellar/openssh" ] && { echo "HATA: kurulum $HB/Cellar/openssh altına yazdı"; exit 6; }

# 3) GT + dSYM + analiz kopyası (yalnız ssh)
/bin/cp -p "$P/prefix$FORMUL_ONEK/bin/ssh" "$P/gt/ssh"
/usr/bin/dsymutil "$P/gt/ssh" -o "$P/gt/ssh.dSYM" > "$P/log/dsymutil.log" 2>&1
/bin/cp -p "$P/gt/ssh" "$P/analiz/ssh"
/usr/bin/strip "$P/analiz/ssh"
echo "openssh (ssh): tamam"
