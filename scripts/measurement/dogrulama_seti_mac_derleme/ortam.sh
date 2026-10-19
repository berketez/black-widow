#!/bin/bash
# Homebrew superenv (macOS 26, arm64, CLT) derleme ortamının temiz kopyası.
#
# Kaynaklar (yerel Homebrew 7.0.9 kodu, okunarak çıkarıldı):
#   Library/Homebrew/extend/ENV/super.rb, extend/os/mac/extend/ENV/super.rb,
#   extend/ENV/shared.rb, build.rb, bin/brew, utils/os.sh,
#   shims/super/cc, shims/mac/super/bin/{make,xcrun,pkg-config}
#
# Superenv'den bilinçli sapmalar (gerekçeleri test_seti_kilidi.md §4.5'te):
#   1. HOMEBREW_CCCFG'ye "D" eklendi (Homebrew'un --debug-symbols kipi): derleyici
#      sarmalayıcısı -g ekler; -ffile-prefix-map ve -Wl,-oso_prefix eklenmez.
#   2. /opt/homebrew/include ve /opt/homebrew/lib yerine yalnız bağımlılıkların
#      opt/ dizinleri verilir. Şişeler yalnız bağımlılıkların kurulu olduğu CI
#      makinesinde derlendi; bu makinede /opt/homebrew/include 850+ girdi içeriyor.
#   3. CC yine "clang" (superenv kabuğu); kabuk, xcrun kabuğu üzerinden
#      /usr/bin/clang'ı çağırır. Ortam env -i ile sıfırlanır; conda yolu yoktur.
#
# Kullanım: ortam.sh içindeki superenv_calistir fonksiyonu, program betiğinin
# tanımladığı değişkenlerle komut çalıştırır:
#   BAGIMLILIKLAR   tüm bağımlılıklar (build dahil), superenv sırasıyla
#   KEG_ONLY        keg-only bağımlılıklar
#   PY_BAGIMLILIK   python@X bağımlılığı varsa adı (yoksa boş)
#   SDE             SOURCE_DATE_EPOCH (şişe tab'ındaki source_modified_time)
#   FORMUL_ONEK     Homebrew keg öneki (ör. /opt/homebrew/Cellar/zsh/5.9.2)
#   KAYNAK          derleme dizini (src/)
#   GUNLUK          superenv cc günlüğü öneki

set -euo pipefail

KOK=/Users/apple/Black_Widow/targets/dogrulama_seti/mac_kaynaktan   # doğrulama seti (test setindeki ortam.sh kopyası, 2026-10-19)
HB=/opt/homebrew
SHIMS=$HB/Library/Homebrew/shims/mac/super/bin
SDK=/Library/Developer/CommandLineTools/SDKs/MacOSX26.sdk
OGL_H=$SDK/System/Library/Frameworks/OpenGL.framework/Versions/Current/Headers
OGL_L=$SDK/System/Library/Frameworks/OpenGL.framework/Versions/Current/Libraries
HB_RUBY=$HB/Library/Homebrew/vendor/portable-ruby/current/bin/ruby
MAC_PKGCONFIG=$HB/Library/Homebrew/os/mac/pkgconfig/26
IS_SAYISI=6   # make -j üst sınırı (başka ajanlar da makineyi kullanıyor)

_yol_ekle() {  # $1 = mevcut liste, $2 = eklenecek dizin (varsa)
  if [ -d "$2" ]; then
    if [ -z "$1" ]; then printf '%s' "$2"; else printf '%s:%s' "$1" "$2"; fi
  else
    printf '%s' "$1"
  fi
}

_keg_only_mu() {
  local d
  for d in ${KEG_ONLY:-}; do [ "$d" = "$1" ] && return 0; done
  return 1
}

superenv_ortami_kur() {
  local d yol pcp isys inc lib deps
  # PATH: kabuklar + bağımlılıkların opt/bin'i + python libexec/bin + sistem
  yol=$SHIMS
  for d in ${BAGIMLILIKLAR:-}; do yol=$(_yol_ekle "$yol" "$HB/opt/$d/bin"); done
  if [ -n "${PY_BAGIMLILIK:-}" ]; then yol=$(_yol_ekle "$yol" "$HB/opt/$PY_BAGIMLILIK/libexec/bin"); fi
  yol="$yol:/usr/bin:/bin:/usr/sbin:/sbin"

  # PKG_CONFIG_PATH: önce tüm lib/pkgconfig, sonra tüm share/pkgconfig
  pcp=""
  for d in ${BAGIMLILIKLAR:-}; do pcp=$(_yol_ekle "$pcp" "$HB/opt/$d/lib/pkgconfig"); done
  for d in ${BAGIMLILIKLAR:-}; do pcp=$(_yol_ekle "$pcp" "$HB/opt/$d/share/pkgconfig"); done

  # -isystem: CI'daki /opt/homebrew/include = bağlı (keg-only olmayan) bağımlılıklar
  isys=""; inc=""; lib=""
  for d in ${BAGIMLILIKLAR:-}; do
    if _keg_only_mu "$d"; then
      inc=$(_yol_ekle "$inc" "$HB/opt/$d/include")
    else
      isys=$(_yol_ekle "$isys" "$HB/opt/$d/include")
    fi
  done
  isys=$(_yol_ekle "$isys" "$OGL_H")
  # -L: keg-only kütüphaneler, sonra CI'daki /opt/homebrew/lib karşılığı, sonra OpenGL
  for d in ${BAGIMLILIKLAR:-}; do _keg_only_mu "$d" && lib=$(_yol_ekle "$lib" "$HB/opt/$d/lib"); done
  for d in ${BAGIMLILIKLAR:-}; do _keg_only_mu "$d" || lib=$(_yol_ekle "$lib" "$HB/opt/$d/lib"); done
  lib=$(_yol_ekle "$lib" "$OGL_L")
  deps=$(printf '%s' "${BAGIMLILIKLAR:-}" | tr ' ' ',' )

  mkdir -p "$KOK/.tmp"
  ORTAM=(
    HOME="$HOME"
    PATH="$yol"
    TMPDIR="$KOK/.tmp" TEMP="$KOK/.tmp" TMP="$KOK/.tmp"
    LC_ALL=en_US.UTF-8
    TZ=UTC0
    SOURCE_DATE_EPOCH="$SDE"
    ZERO_AR_DATE=1
    am_cv_func_iconv_works=yes
    MAKEFLAGS="-j$IS_SAYISI"
    CC=clang CXX=clang++ OBJC=clang OBJCXX=clang++
    PKG_CONFIG_PATH="$pcp"
    PKG_CONFIG_LIBDIR="/usr/lib/pkgconfig:$MAC_PKGCONFIG"
    HOMEBREW_ENV=super
    HOMEBREW_CC=clang
    HOMEBREW_CCCFG="${CCCFG_OVERRIDE:-fD}"   # CCCFG_OVERRIDE=f: şişe kipi (-g yok, yol eşlemesi var), yalnız kıyas denemesi için
    HOMEBREW_OPTIMIZATION_LEVEL=Os
    HOMEBREW_OPTFLAGS=
    HOMEBREW_MAKE_JOBS="$IS_SAYISI"
    HOMEBREW_PREFIX=$HB
    HOMEBREW_CELLAR=$HB/Cellar
    HOMEBREW_OPT=$HB/opt
    HOMEBREW_LIBRARY=$HB/Library
    HOMEBREW_CACHE="$HOME/Library/Caches/Homebrew"
    HOMEBREW_TEMP=/private/tmp
    HOMEBREW_RUBY_PATH="$HB_RUBY"
    HOMEBREW_SDKROOT="$SDK"
    HOMEBREW_DEVELOPER_DIR=/Library/Developer/CommandLineTools
    HOMEBREW_PREFER_CLT_PROXIES=1
    HOMEBREW_MACOS_OLDEST_ALLOWED=11
    HOMEBREW_PROCESSOR=arm64
    HOMEBREW_PHYSICAL_PROCESSOR=arm64
    HOMEBREW_ISYSTEM_PATHS="$isys"
    HOMEBREW_INCLUDE_PATHS="$inc"
    HOMEBREW_LIBRARY_PATHS="$lib"
    HOMEBREW_DEPENDENCIES="$deps"
    HOMEBREW_FORMULA_PREFIX="$FORMUL_ONEK"
    HOMEBREW_FORMULA_BUILDPATH="$KAYNAK"
    HOMEBREW_CC_LOG_PATH="$GUNLUK"
  )
}

# Koruma: derleme ve kurulum /opt/homebrew altına YAZAMAZ (sistem Homebrew'u değişmez);
# gizli dizinler okunamaz. Kurallar sandbox-exec ile çekirdek düzeyinde uygulanır.
# (2026-10-19, nagios) sandbox-exec, "(allow default)" altında bile setuid/setgid bitini
# (ör. "chmod g+s") reddediyor. Homebrew'un kendi derleme sandbox'ı yazılabilir yollarda
# file-write-setugid ve file-write-mode'a açıkça izin veriyor (Library/Homebrew/sandbox.rb,
# allow_write); aynısı yalnız kendi derleme ağacımız ($KOK) için verildi.
SANDBOX_PROFIL="(version 1)(allow default)
(allow file-write-setugid (subpath \"$KOK\"))
(allow file-write-mode (subpath \"$KOK\"))
(deny file-write* (subpath \"/opt/homebrew\"))
(deny file-read* (subpath \"$HOME/.ssh\") (subpath \"$HOME/.aws\") (subpath \"$HOME/.config/gh\"))"

superenv_calistir() {  # superenv_calistir <komut> [arg...]  (cwd = $KAYNAK)
  superenv_ortami_kur
  (cd "$KAYNAK" && /usr/bin/sandbox-exec -p "$SANDBOX_PROFIL" /usr/bin/env -i "${ORTAM[@]}" "$@")
}

superenv_ozet() {  # ortamı (yol ve bayrak değişkenleri) günlüğe yazar
  superenv_ortami_kur
  printf '%s\n' "${ORTAM[@]}" | grep -vE '^HOME='
}
