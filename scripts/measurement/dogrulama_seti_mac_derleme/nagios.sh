#!/bin/bash
# nagios 4.5.14 (formül nagios 4.5.14; şişe arm64_tahoe rebuild 0) — doğrulama seti K3:
# kaynaktan, sembolleri koruyarak, -g ile derleme (ön kayıt §4.4; yöntem test_seti_kilidi.md §4.5).
# Formül: ../nagios/indirilen/formul-sise-nagios.rb (şişedeki .brew/nagios.rb). homebrew-core
# cc475e638cb4 ("nagios: update 4.5.14 bottle.", 2026-08-05) ile bottle bloğu dışında aynı; o
# commit'teki arm64_tahoe sha256'sı sabitlenen şişeninki. Ölçülen ikili: bin/nagios.
#
# gd 2.3.3_6 (ve libavif 1.4.2) 2026-10-19'da ana oturum tarafından Berke'nin onayıyla kuruldu.
# Derlenen nagios ÇALIŞTIRILMAZ (arka plan hizmeti); kurulum adımları da çalıştırmıyor
# (install-unstripped, install-config, install-webconf yalnız dosya kopyalıyor).
set -euo pipefail
source "$(dirname "$0")/ortam.sh"

P=${P_OVERRIDE:-$KOK/nagios}   # P_OVERRIDE: kıyas denemesi için ayrı dizin
# Şişe tab'ındaki çalışma bağımlılıkları, tab sırasıyla (şişe dönemi kümesi)
BAGIMLILIKLAR="libpng freetype json-c libunistring gettext fontconfig jpeg-turbo libvmaf aom dav1d libavif giflib webp xz lz4 zstd libtiff gd ca-certificates openssl@4"
KEG_ONLY=""
PY_BAGIMLILIK=""
SDE=1785941675                  # şişe tab: source_modified_time
FORMUL_ONEK=$HB/Cellar/nagios/4.5.14
KAYNAK=$P/src
GUNLUK=$P/log/superenv
KULLANICI=$(/usr/bin/id -un)    # formül: Utils.safe_popen_read("id", "-un")
GRUP=$(/usr/bin/id -gn)         # formül: Utils.safe_popen_read("id", "-gn")

# 0) Ön koşullar
eksik=""
for d in gd libpng jpeg-turbo openssl@4; do [ -d "$HB/opt/$d" ] || eksik="$eksik $d"; done
[ -z "$eksik" ] || { echo "EKSİK bağımlılık:$eksik"; exit 2; }
[ -e "$HB/Cellar/nagios" ] && { echo "HATA: $HB/Cellar/nagios mevcut"; exit 3; }
if [ -z "$(ls -A "$KAYNAK")" ]; then
  /usr/bin/tar -xzf "$P/indirilen/nagios-4.5.14.tar.gz" -C "$KAYNAK" --strip-components=1
fi
[ -f "$KAYNAK/config.status" ] && { echo "HATA: kaynak zaten yapılandırılmış"; exit 5; }

superenv_ozet > "$P/log/ortam.txt"

# 1) Formül: ./configure *std_configure_args *args (macOS: --with-command-group=_www)
#    --with-nagios-group='#{group}': tırnaklar formüldeki gibi argümanın parçası.
superenv_calistir ./configure \
  --disable-debug --disable-dependency-tracking \
  "--prefix=$FORMUL_ONEK" "--libdir=$FORMUL_ONEK/lib" \
  "--sbindir=$FORMUL_ONEK/cgi-bin" \
  "--sysconfdir=$HB/etc/nagios" \
  "--localstatedir=$HB/var/lib/nagios" \
  "--datadir=$FORMUL_ONEK/share/nagios/htdocs" \
  "--libexecdir=$HB/sbin" \
  --with-cgiurl=/nagios/cgi-bin \
  --with-htmurl=/nagios \
  "--with-nagios-user=$KULLANICI" \
  "--with-nagios-group='$GRUP'" \
  "--with-command-user=$KULLANICI" \
  "--with-httpd-conf=$FORMUL_ONEK/share" \
  "--with-ssl=$HB/opt/openssl@4" \
  --disable-libtool \
  --with-command-group=_www > "$P/log/configure.log" 2>&1

# 2) Formül: make all
superenv_calistir make all > "$P/log/make.log" 2>&1

# 3) Formül: make install. Tek fark: "install-unstripped" (aynı hedef, base/'deki "install -s" olmadan).
superenv_calistir make install-unstripped "DESTDIR=$P/prefix" > "$P/log/make_install.log" 2>&1
#    Formül: make install-config ; make install-webconf (yalnız dosya kopyalar; ikiliyi etkilemez)
superenv_calistir make install-config "DESTDIR=$P/prefix" > "$P/log/make_install_config.log" 2>&1
superenv_calistir make install-webconf "DESTDIR=$P/prefix" > "$P/log/make_install_webconf.log" 2>&1

[ -e "$HB/Cellar/nagios" ] && { echo "HATA: kurulum $HB/Cellar/nagios altına yazdı"; exit 6; }
KURULU=$P/prefix$FORMUL_ONEK/bin/nagios
[ -f "$KURULU" ] || { echo "HATA: kurulan ikili yok: $KURULU"; exit 7; }

# 4) GT + dSYM + analiz kopyası
/bin/cp -p "$KURULU" "$P/gt/nagios"
/usr/bin/dsymutil "$P/gt/nagios" -o "$P/gt/nagios.dSYM" > "$P/log/dsymutil.log" 2>&1
/bin/cp -p "$P/gt/nagios" "$P/analiz/nagios"
/usr/bin/strip "$P/analiz/nagios"
echo "nagios: tamam"
