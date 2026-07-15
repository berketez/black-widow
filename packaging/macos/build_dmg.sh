#!/usr/bin/env bash
# build_dmg.sh -- "Black Widow.app"'i sürükle-Applications DMG'ye paketle.
# Önce build_mac_app.sh (CORE veya --full) çalıştırılmış olmalı. Çıktı macOS-only (exe değil).
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
# .app iCloud dışında üretilir (bkz. build_mac_app.sh); DMG de orada üretilip
# repo dist/'e kopyalanır -- imaj tek dosya, içindeki imza taşınmaktan etkilenmez.
# Not: build dizini "caches" içeremez (bkz. build_mac_app.sh) -> Ghidra jar'ları atlar.
BUILD_ROOT="${KARADUL_BUILD_DIR:-$HOME/Library/BlackWidowBuild}"
APP="${KARADUL_APP:-$BUILD_ROOT/Black Widow.app}"
DIST="$REPO/dist"
mkdir -p "$DIST"

# Sürüm tek kaynaktan: pyproject.toml (elle tutulan sürüm kayar).
VER="$(python3 -c "
import tomllib
print(tomllib.load(open('$REPO/pyproject.toml','rb'))['project']['version'])
" 2>/dev/null || echo "1.20.0")"
DMG="$DIST/BlackWidow-$VER.dmg"
TMP_DMG="$BUILD_ROOT/BlackWidow-$VER.dmg"      # iCloud dışında üret, sonra kopyala

[ -d "$APP" ] || { echo "!! $APP yok — önce: packaging/macos/build_mac_app.sh --full" >&2; exit 1; }
# Bozuk imzalı bundle'ı sessizce paketleyip dağıtmayalım.
codesign --verify --deep --strict "$APP" 2>/dev/null \
  || { echo "!! $APP imzası geçersiz — DMG üretilmedi (build_mac_app.sh'ı tekrar çalıştır)" >&2; exit 1; }

STAGE="$(mktemp -d)"                            # /var/folders -> iCloud kapsamı dışı
trap 'rm -rf "$STAGE" "$TMP_DMG"' EXIT
# -c = APFS clonefile: 3.5GB anında, ek disk yemez (düz kopya dakikalar sürüyordu).
cp -Rc "$APP" "$STAGE/" 2>/dev/null || cp -R "$APP" "$STAGE/"
ln -s /Applications "$STAGE/Applications"      # sürükle-bırak kurulum kısayolu
rm -f "$DMG" "$TMP_DMG"

# ULMO (LZMA) = en iyi sıkıştırma; bundle GB'larca olduğu için kazanç büyük.
# Eski macOS'ta ULMO okunamazsa UDBZ'ye düş (LSMinimumSystemVersion 12.0 -> ULMO güvenli).
hdiutil create -volname "Black Widow" -srcfolder "$STAGE" -ov -format ULMO "$TMP_DMG" \
  || hdiutil create -volname "Black Widow" -srcfolder "$STAGE" -ov -format UDBZ "$TMP_DMG"
cp "$TMP_DMG" "$DMG"

echo "[build_dmg] hazır -> $DMG"
ls -lah "$DMG"
cat <<'EOT'
NOT: imzasız/notarize edilmemiş. Başka makinede ilk açılış (macOS 15+):
  1) Uygulamayı /Applications'a sürükle
  2) Aç -> engellenir -> Sistem Ayarları > Gizlilik ve Güvenlik > "Yine de Aç"
     (macOS 15+'ta eski "sağ-tık > Aç" kestirmesi ARTIK YOK)
  Alternatif tek komut:
     xattr -dr com.apple.quarantine "/Applications/Black Widow.app"
EOT
