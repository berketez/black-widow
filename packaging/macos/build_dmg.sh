#!/usr/bin/env bash
# build_dmg.sh -- "Black Widow.app"'i sürükle-Applications DMG'ye paketle.
# Önce build_app.sh (dev veya --full) çalıştırılmış olmalı. Çıktı macOS-only (exe değil).
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
DIST="$REPO/dist"
APP="$DIST/Black Widow.app"
VER="1.20.0"
DMG="$DIST/BlackWidow-$VER.dmg"

[ -d "$APP" ] || { echo "!! $APP yok — önce build_app.sh çalıştır" >&2; exit 1; }

STAGE="$(mktemp -d)"
cp -R "$APP" "$STAGE/"
ln -s /Applications "$STAGE/Applications"      # sürükle-bırak kurulum kısayolu
rm -f "$DMG"
# UDBZ = yüksek sıkıştırma (bundle GB ise önemli)
hdiutil create -volname "Black Widow" -srcfolder "$STAGE" -ov -format UDBZ "$DMG"
rm -rf "$STAGE"

echo "[build_dmg] hazır -> $DMG"
ls -lah "$DMG"
echo "NOT: imzasız/notarize edilmemiş. İlk açılışta sağ-tık > Aç (bir kez),"
echo "     veya: xattr -dr com.apple.quarantine \"/Applications/Black Widow.app\""
