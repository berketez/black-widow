#!/bin/bash
# Black Widow — İlk Açılış yardımcısı (DMG içinde dağıtılır).
#
# Kullanıcı bunu çift tıklarsa: /Applications (veya ~/Applications) altındaki
# "Black Widow.app"in karantina bayrağını temizler ve uygulamayı açar. İMZA
# GEREKMEZ (düz shell) — self-hosted dağıtımda Gatekeeper'ın "doğrulanamıyor"
# uyarısını tek adımda aşmanın en kolay yolu. Notarization YOK (self-hosted karar
# 2026-07-19: Berke uygulamayı Apple'a yayımlamıyor, kendi sitesinden dağıtıyor).
#
# NOT: app-arama deseni bw_launch.sh:find_real_app'ten uyarlandı (mdfind YOK —
# dev build'i yanlışlıkla bulup açmasın).
set -u

find_installed_app() {
  local CAND
  for CAND in "/Applications/Black Widow.app" "$HOME/Applications/Black Widow.app"; do
    [ -d "$CAND" ] && { printf '%s\n' "$CAND"; return 0; }
  done
  return 1
}

APP="$(find_installed_app || true)"

if [ -z "$APP" ]; then
  # App henüz kurulmamış: kullanıcıyı önce sürükle-bırak kurulumuna yönlendir.
  # (Dialog metninde ASCII kesme işareti YOK — tek tırnaklı osascript'i bozar.)
  osascript -e 'display dialog "Önce Black Widow uygulamasını bu DMG içinden Applications (Uygulamalar) klasörüne sürükleyin, sonra bu İlk Açılış dosyasını yeniden çalıştırın." buttons {"Tamam"} with icon caution with title "Black Widow"' >/dev/null 2>&1
  exit 1
fi

# Karantina bayrağını (com.apple.quarantine) özyinelemeli temizle. Bu, macOS'un
# ad-hoc imzalı / notarize edilmemiş uygulamayı ilk açılışta bloklamasını önler.
xattr -dr com.apple.quarantine "$APP" 2>/dev/null || true

osascript -e 'display dialog "Karantina temizlendi. Black Widow açılıyor…" buttons {"Tamam"} default button "Tamam" with title "Black Widow" giving up after 4' >/dev/null 2>&1

open "$APP"
exit 0
