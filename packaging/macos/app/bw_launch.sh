#!/bin/bash
# Black Widow .app başlatma script'i (arm64 stub bunu çağırır).
# HRMA reçetesinden uyarlandı: App Translocation yönlendirme + quarantine
# temizliği + bundle python ile pencereyi ÖN PLANDA aç (süreç = uygulama ömrü).
set -u

SELF_DIR="$(cd "$(dirname "$0")" && pwd)"                 # .../Contents/MacOS
APP_BUNDLE="$(dirname "$(dirname "$SELF_DIR")")"          # .../Black Widow.app
RES="$APP_BUNDLE/Contents/Resources"

find_real_app() {
  local CAND
  for CAND in "/Applications/Black Widow.app" "$HOME/Applications/Black Widow.app"; do
    [ -d "$CAND" ] && { echo "$CAND"; return 0; }
  done
  # mdfind KULLANMA: repo'daki dist/Black Widow.app'i bulup açar; DMG'yi test
  # ederken farkında olmadan dev build çalışır ("DMG çalışıyor" yanlış sonucu).
  return 1
}

# DMG / App Translocation (read-only) altından çalıştırıldıysa gerçek kuruluma
# yönlen. Tespit YOLA göre değil, mount'un SALT-OKUNUR oluşuna göre yapılır:
# "/Volumes/*" deseni harici diske kurulumu da yanlışlıkla reddediyordu.
_is_readonly_mount() {
  local MNT
  MNT="$(df -P "$APP_BUNDLE" 2>/dev/null | awk 'NR==2{print $6}')"
  [ -n "$MNT" ] && mount | grep -q "on ${MNT} .*read-only"
}
if _is_readonly_mount || case "$APP_BUNDLE" in *AppTranslocation*) true;; *) false;; esac; then
  REAL="$(find_real_app || true)"
  if [ -n "$REAL" ] && [ -d "$REAL" ] && [ "$REAL" != "$APP_BUNDLE" ]; then
    xattr -dr com.apple.quarantine "$REAL" 2>/dev/null || true
    exec open -n "$REAL"
  fi
  osascript -e 'display dialog "Lütfen Black Widow simgesini önce Applications (Uygulamalar) klasörüne sürükleyin, sonra oradan açın." buttons {"Tamam"} with icon caution with title "Black Widow"' >/dev/null 2>&1
  exit 1
fi

# İlk açılıştan sonra karantinayı ARKA PLANDA temizle (açılışı bekletmez).
if xattr -p com.apple.quarantine "$APP_BUNDLE" >/dev/null 2>&1; then
  ( xattr -dr com.apple.quarantine "$APP_BUNDLE" 2>/dev/null || true ) &
fi

# Yazılabilir veri dizini (bundle Resources READ-ONLY) -> server.py bunu okur
export KARADUL_DATA_DIR="${KARADUL_DATA_DIR:-$HOME/Library/Application Support/BlackWidow}"
mkdir -p "$KARADUL_DATA_DIR"

# Analiz araçları SADECE bundle'da varsa (full build); yoksa app yine de açılır
[ -d "$RES/ghidra" ] && export GHIDRA_INSTALL_DIR="$RES/ghidra"
# Ghidra ClassJar.ignoreJar(): yolunda "caches"/"ExternalLibraries"/"flatrepo" geçen
# jar'ları atlar -> uygulama açılır ama analiz "extension point" hatasıyla ölür.
# Sessiz başarısızlık yerine kullanıcıyı uyar (ör. app'i böyle bir klasöre koymuşsa).
case "$(echo "$APP_BUNDLE" | tr '[:upper:]' '[:lower:]')" in
  *caches*|*externallibraries*|*flatrepo*)
    osascript -e 'display dialog "Black Widow bu klasörden analiz yapamaz (klasör adında \"Caches\" geçiyor; Ghidra bu yollardaki bileşenleri yok sayar).\n\nUygulamayı Applications klasörüne taşıyıp oradan açın." buttons {"Tamam"} with icon caution with title "Black Widow"' >/dev/null 2>&1
    ;;
esac
if [ -x "$RES/jdk/Contents/Home/bin/java" ]; then
  export JAVA_HOME="$RES/jdk/Contents/Home"
  export PATH="$JAVA_HOME/bin:$PATH"
fi
# İmza DB'sini DOĞRUDAN göster. Eski yöntem ~/.karadul/signatures.lmdb symlink'i
# kurmaya çalışıyordu; HOME'da gerçek bir DB varsa guard atlıyor ve bundle'daki
# 2GB hiç kullanılmıyordu (üstelik eski/bozuk DB sessizce gölgeliyordu).
[ -e "$RES/signatures.lmdb" ] && export KARADUL_SIG_LMDB_PATH="$RES/signatures.lmdb"

PY="$RES/python/bin/python3.12"
LAUNCH="$RES/ui/app_window.py"
LOG="$KARADUL_DATA_DIR/app.log"
export PYTHONUNBUFFERED=1
# Bundle'a .pyc YAZMA: yazarsa ad-hoc imza mührü kırılır -> macOS "damaged" der.
# (build_mac_app.sh stdlib'i önceden derliyor; bu ikinci emniyet kemeri.)
export PYTHONDONTWRITEBYTECODE=1

# Kurulum bozuksa sessizce ölme: çift tıkta "hiçbir şey olmadı" teşhis edilemez.
if [ ! -x "$PY" ] || [ ! -f "$LAUNCH" ]; then
  osascript -e 'display dialog "Black Widow kurulumu bozuk görünüyor (Python çekirdeği eksik). DMG'"'"'den yeniden kurun." buttons {"Tamam"} with icon stop with title "Black Widow"' >/dev/null 2>&1
  exit 1
fi

# ÖN PLANDA çalıştır: pencere pywebview ile açılır, pencere kapanınca app kapanır.
exec "$PY" "$LAUNCH" >> "$LOG" 2>&1
# Buraya yalnızca exec BAŞARISIZ olursa gelinir.
osascript -e 'display dialog "Black Widow başlatılamadı. Ayrıntı: ~/Library/Application Support/BlackWidow/app.log" buttons {"Tamam"} with icon stop with title "Black Widow"' >/dev/null 2>&1
exit 1
