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

# --- İmza imajın İÇİNDE dağıtılır (Berke 2026-07-16: "dağıtım zamanı DMG tek başına
# --- her şeyi kursun"). Üç katman: (1) app'in mührü zaten bundle'ın içinde ve kopyalanmakla
# --- taşınır; (2) DMG'nin KENDİSİ imzalanır; (3) notarization bileti DMG'ye STAPLE'lanır
# --- ki hedef makine internetsizken bile Gatekeeper bileti imajın içinde bulsun.
SIGN_ID="${KARADUL_CODESIGN_ID:-}"
if [ -z "$SIGN_ID" ]; then
  SIGN_ID="$(security find-identity -v -p codesigning 2>/dev/null \
             | grep -m1 'Developer ID Application' | sed -n 's/.*"\(.*\)".*/\1/p' || true)"
fi
if [ -n "$SIGN_ID" ]; then
  codesign --force --timestamp -s "$SIGN_ID" "$TMP_DMG" || { echo "!! DMG imzalanamadı" >&2; exit 1; }
  echo "[build_dmg] DMG imzalandı: $SIGN_ID"
else
  codesign --force -s - "$TMP_DMG" || { echo "!! DMG ad-hoc imzalanamadı" >&2; exit 1; }
  echo "[build_dmg] DMG ad-hoc imzalandı (Developer ID yok)"
fi

# Notarization: profil VARSA otomatik, yoksa sessizce atla. Sertifika alındığı gün
# tek komut devreye girer -- o güne kadar akış bozulmasın.
#   xcrun notarytool store-credentials "$KARADUL_NOTARY_PROFILE" --apple-id ... --team-id ... --password ...
NOTARY_PROFILE="${KARADUL_NOTARY_PROFILE:-}"
if [ -n "$NOTARY_PROFILE" ] && [ -n "$SIGN_ID" ]; then
  echo "[build_dmg] notarize ediliyor (Apple'a yükleniyor, birkaç dakika sürebilir)..."
  if xcrun notarytool submit "$TMP_DMG" --keychain-profile "$NOTARY_PROFILE" --wait; then
    # staple = bileti imajın İÇİNE göm. Bu olmadan hedef makine bileti Apple'dan
    # çevrimiçi sormak zorunda kalır; internetsiz/kısıtlı ağda app açılmaz.
    xcrun stapler staple "$TMP_DMG" || { echo "!! staple başarısız (bilet gömülemedi)" >&2; exit 1; }
    xcrun stapler validate "$TMP_DMG" || { echo "!! staple doğrulanamadı" >&2; exit 1; }
    echo "[build_dmg] notarize + staple OK -> bilet DMG'nin içinde, internetsiz açılır"
  else
    echo "!! notarize BAŞARISIZ -> 'xcrun notarytool log <id> --keychain-profile $NOTARY_PROFILE'" >&2
    exit 1
  fi
elif [ -n "$SIGN_ID" ]; then
  echo "[build_dmg] notarize ATLANDI (KARADUL_NOTARY_PROFILE tanımlı değil)"
fi

cp "$TMP_DMG" "$DMG"

# --- Kurulum simülasyonu: DMG'yi mount et, app'i DIŞARI kopyala (sürükle-bırakın
# --- birebir aynısı) ve mührü ORADA doğrula. "DMG'de imza vardı" yetmez; imzanın
# --- kopyalanmaktan sağ çıktığını kanıtlamak lazım -- kullanıcının yaşadığı şey bu.
echo "[build_dmg] kurulum simülasyonu (mount -> kopyala -> mührü doğrula)"
_V="$(mktemp -d)"; _I="$(mktemp -d)"
trap 'hdiutil detach "$_V" >/dev/null 2>&1 || true; rm -rf "$_V" "$_I" "$STAGE" "$TMP_DMG"' EXIT
hdiutil attach -nobrowse -readonly -mountpoint "$_V" "$DMG" >/dev/null \
  || { echo "!! DMG mount edilemedi -- imaj bozuk" >&2; exit 1; }
cp -Rc "$_V/Black Widow.app" "$_I/" 2>/dev/null || cp -R "$_V/Black Widow.app" "$_I/"
hdiutil detach "$_V" >/dev/null 2>&1 || true
codesign --verify --deep --strict "$_I/Black Widow.app" \
  || { echo "!! KURULUMDAN SONRA MÜHÜR GEÇERSİZ -- bu DMG dağıtılamaz" >&2; exit 1; }
echo "    kurulan kopyanın mührü GEÇERLİ"
if xcrun stapler validate "$_I/Black Widow.app" >/dev/null 2>&1; then
  echo "    notarization bileti app'e staple'lı -> Gatekeeper sessizce açar"
else
  # spctl ad-hoc/notarize-siz app'i REDDEDER ve exit 3 döner; set -e + pipefail
  # bunu ölümcül sanıp script'i düşürüyordu (mühür zaten yukarıda GEÇERLİ doğrulandı).
  # Bu satır yalnız BİLGİ amaçlı -> hatası yutulur.
  _SPCTL="$(spctl -a -t exec -vv "$_I/Black Widow.app" 2>&1 | head -1 || true)"
  echo "    Gatekeeper: ${_SPCTL#*: } (ad-hoc: başka makinede 'Yine de Aç' beklenir)"
fi

echo "[build_dmg] hazır -> $DMG"
ls -lah "$DMG"
if [ -n "$SIGN_ID" ] && [ -n "$NOTARY_PROFILE" ]; then
cat <<'EOT'
DAĞITIMA HAZIR: imza + notarization bileti imajın içinde. Kullanıcı DMG'yi açar,
uygulamayı Applications'a sürükler, çift tıklar. Uyarı yok, ek adım yok, internet gerekmez.
EOT
else
cat <<'EOT'
NOT: ad-hoc imza, notarize DEĞİL. Kendi makinende çalışır; BAŞKA makinede ilk açılış:
  1) Uygulamayı /Applications'a sürükle
  2) Aç -> engellenir -> Sistem Ayarları > Gizlilik ve Güvenlik > "Yine de Aç"
     (macOS 15+'ta eski "sağ-tık > Aç" kestirmesi ARTIK YOK)
Dağıtım için: Apple Developer Program üyeliği + Developer ID Application sertifikası,
sonra:  xcrun notarytool store-credentials bw-notary --apple-id <id> --team-id <team> --password <app-specific>
        KARADUL_NOTARY_PROFILE=bw-notary packaging/macos/build_dmg.sh
Sertifika keychain'de görünür görünmez build_mac_app.sh ve build_dmg.sh onu KENDİLİĞİNDEN
kullanır (KARADUL_CODESIGN_ID ile de zorlanabilir).
EOT
fi
