#!/usr/bin/env bash
# Black Widow.app kurucu (macOS arm64) -- HRMA reçetesinden uyarlandı.
#   (varsayılan) CORE : stub + relocatable python + karadul + ui + pywebview.
#                       Çift-tıkla AÇILIR (TCC yok, her şey bundle içinde). Analiz
#                       için Ghidra gerekir (bu modda yok) ama uygulama açılır.
#   --full            : + Ghidra + JDK (yerel Homebrew) + signatures.lmdb -> analiz çalışır.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
# .app ASLA iCloud senkronlu bir dizinde üretilmez (repo Desktop'ta ve "Desktop &
# Documents" senkronu açık): FileProvider bundle'a com.apple.FinderInfo iliştirir,
# xattr -c silmesine izin VERMEZ, codesign da "resource fork, Finder information,
# or similar detritus not allowed" ile reddeder -> imzasız/bozuk app.
# ~/Library iCloud kapsamı dışında. Repo dist/ yalnızca DMG çıktısı için kullanılır.
DIST="${KARADUL_BUILD_DIR:-$HOME/Library/BlackWidowBuild}"; APP="$DIST/Black Widow.app"
# TUZAK: Ghidra'nın ClassJar.ignoreJar() yolunda "caches" / "ExternalLibraries" /
# "flatrepo" geçen TÜM jar'ları 3rd-party sayıp atlar -> extension point bulunamaz
# -> "Unable to locate extension points!" ile başlamaz. Yani bundle ~/Library/Caches
# altında üretilirse analiz sessizce ölür. Bu yüzden build dizini asla "caches"
# içeremez (kurulum hedefi /Applications zaten temiz).
case "$(echo "$DIST" | tr '[:upper:]' '[:lower:]')" in
  *caches*|*externallibraries*|*flatrepo*)
    echo "!! build dizini 'caches/ExternalLibraries/flatrepo' içeremez (Ghidra jar'ları"
    echo "   atlar, analiz çalışmaz): $DIST"; exit 1;;
esac
RES="$APP/Contents/Resources"; MACOS="$APP/Contents/MacOS"
PBS="${KARADUL_PBS:-$HOME/Desktop/dosyalar/HRMA/packaging/runtime/pbs-mac.tar.gz}"
# Ghidra kaynağı: env > indirilen resmi sürüm (en yenisi) > yerel DEV derlemesi.
# Sabit "ghidra_12.0_DEV" yolu sürüm yükseltmesinde sessizce eskiyi paketliyordu.
_ghidra_default() {
  local C
  [ -n "${GHIDRA_INSTALL_DIR:-}" ] && { echo "$GHIDRA_INSTALL_DIR"; return; }
  # ghidra_<sürüm>_PUBLIC dizinleri arasından en yenisini seç (sürüm sıralı)
  C="$(ls -d "$DIST"/ghidra_*_PUBLIC 2>/dev/null | sort -t_ -k2,2V | tail -1)"
  [ -n "$C" ] && { echo "$C"; return; }
  echo "$HOME/Desktop/dosyalar/uygulamalar/ghidra/build/dist/ghidra_12.0_DEV"
}
GH="$(_ghidra_default)"
JDK_SRC="/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk"
LMDB="$HOME/.karadul/signatures.lmdb"
FULL=0; [ "${1:-}" = "--full" ] && FULL=1
mkdir -p "$DIST"

echo "[1/8] iskelet + arm64 stub (bash değil -> mimari/çift-tık sorunu yok)"
rm -rf "$APP"; mkdir -p "$MACOS" "$RES"
cp "$HERE/app/Info.plist" "$APP/Contents/Info.plist"
# Sürüm tek kaynaktan (pyproject.toml); plist elle tutulunca kayıyordu.
# CFBundleVersion sayısal olmak zorunda -> "1.20.0-pre" -> "1.20.0".
VER="$(python3 -c "import tomllib;print(tomllib.load(open('$REPO/pyproject.toml','rb'))['project']['version'])" 2>/dev/null || echo "")"
if [ -n "$VER" ]; then
  /usr/libexec/PlistBuddy -c "Set :CFBundleVersion ${VER%%-*}" \
                          -c "Set :CFBundleShortVersionString $VER" "$APP/Contents/Info.plist" >/dev/null
  echo "    sürüm: $VER"
fi
cp "$HERE/app/bw_launch.sh" "$MACOS/bw_launch.sh"; chmod +x "$MACOS/bw_launch.sh"
clang -arch arm64 -O2 -o "$MACOS/BlackWidow" "$HERE/app/bw_stub.c"
cp "$HERE/icon/Karadul.icns" "$RES/Karadul.icns"

echo "[2/8] relocatable Python (pbs cache, indirme yok)"
[ -f "$PBS" ] || { echo "!! pbs yok: $PBS (KARADUL_PBS ile ver)"; exit 1; }
tar xzf "$PBS" -C "$RES"                 # 'python/' kökünü açar
PY="$RES/python/bin/python3.12"
echo "    $("$PY" --version)"

echo "[3/8] karadul + deps (pip -> bundle python site-packages)"
# Yavaş/kesintili ağa dayanıklılık: uzun timeout + çok deneme, ilerleme çubuğu kapalı (log şişmesin).
PIP_NET=(--retries 10 --timeout 120 --progress-bar off)
"$PY" -m pip install --no-input --disable-pip-version-check -q "${PIP_NET[@]}" --upgrade pip 2>/dev/null || true
# Tamamı tırnak içinde: köşeli parantez bash'te karakter sınıfı, tırnaksız
# bırakılırsa pathname expansion pip argümanını bozabilir.
"$PY" -m pip install --no-input --disable-pip-version-check "${PIP_NET[@]}" "$REPO[ghidra,perf,computation,app]"
"$PY" -c "import karadul, webview; print('    karadul + pywebview OK')"
SP="$RES/python/lib/python3.12/site-packages"
[ -d "$SP/webview/js" ] || { echo "!! webview/js eksik (pencere çöker)"; exit 1; }

echo "[4/8] ui/"
rm -rf "$RES/ui"; /usr/bin/rsync -a --exclude='__pycache__' "$REPO/ui/" "$RES/ui/"

if [ $FULL = 1 ]; then
  echo "[5/8] Ghidra (yerel kopya)"
  [ -d "$GH" ] || { echo "!! Ghidra yok: $GH (GHIDRA_INSTALL_DIR ile ver)"; exit 1; }
  echo "    kaynak: $GH"
  echo "    sürüm : $(grep -m1 '^application.version=' "$GH/Ghidra/application.properties" 2>/dev/null | cut -d= -f2)"
  cp -R "$GH" "$RES/ghidra"
  echo "[6/8] JDK 21 (yerel Homebrew, indirme yok)"
  [ -d "$RES/jdk" ] || cp -R "$JDK_SRC" "$RES/jdk"
  echo "[7/8] signatures.lmdb (~2GB)"
  # Sessiz yutma YOK: yarım kopyalanmış DB ile "DONE" demek, app'i kötü
  # isimlendirmeyle ship etmek demek. Kaynak yoksa app yine kurulur ama uyarır.
  if [ -e "$LMDB" ]; then
    cp -R "$LMDB" "$RES/signatures.lmdb" || { echo "!! signatures.lmdb kopyalanamadı"; exit 1; }
    echo "    kopyalandı ($(du -sh "$RES/signatures.lmdb" | cut -f1))"
  else
    echo "    !! UYARI: $LMDB yok -> app imza DB'siz gidiyor (isimlendirme zayıflar)"
  fi
else
  echo "[5-7/8] ATLANDI (CORE build; analiz için: build_mac_app.sh --full)"
fi

echo "[8/8] bytecode + ad-hoc codesign"
# stdlib DAHİL derle: eksik .pyc kalırsa Python onları ÇALIŞMA ZAMANINDA bundle'a
# yazar -> imza mührü kırılır -> macOS "damaged" der. (bw_launch.sh ayrıca
# PYTHONDONTWRITEBYTECODE=1 ile ikinci emniyet kemerini takar.)
"$PY" -m compileall -q -j 0 "$RES/python/lib/python3.12" "$SP" "$RES/ui" >/dev/null 2>&1 || true
# Homebrew JDK / Ghidra kopyaları salt-okunur gelir; codesign yazamaz -> u+w şart.
chmod -R u+w "$APP"
# codesign "resource fork, Finder information, or similar detritus" ile reddeder:
# xattr (com.apple.provenance vb.) + AppleDouble/.DS_Store artıkları temizlenmeli.
xattr -cr "$APP" 2>/dev/null || true
find "$APP" \( -name '._*' -o -name '.DS_Store' \) -delete 2>/dev/null || true
# --deep: bundle içinde nested Mach-O var (python, Ghidra native, JDK).
# arm64'te imzasız bundle Gatekeeper'a "damaged" görünür -> ad-hoc imza şart.
codesign --force --deep -s - "$APP" || { echo "!! codesign BAŞARISIZ"; exit 1; }
codesign --verify --deep --strict "$APP" || { echo "!! imza doğrulanamadı"; exit 1; }
echo "    imza OK (adhoc, --strict doğrulandı)"

echo "DONE ($([ $FULL = 1 ] && echo FULL || echo CORE)): $(du -sh "$APP" 2>/dev/null | cut -f1) -> $APP"
