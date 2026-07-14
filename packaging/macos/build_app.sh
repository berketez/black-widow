#!/usr/bin/env bash
# build_app.sh -- "Black Widow.app" macOS bundle üret.
#
# İKİ MOD:
#   (varsayılan) DEV   : hafif .app (Info.plist + launcher + icon). Launcher mevcut
#                        repo + anaconda python'a düşer. Berke'nin makinesinde ANINDA
#                        çift-tıkla çalışır. GB değil.
#   --full             : TAM self-contained bundle (~3.5 GB): relocatable Python +
#                        karadul + tüm deps + Ghidra + JDK + signatures.lmdb. Offline.
#                        Uzun sürer (indirme + 3.5 GB kopya). Codesign/notarization
#                        AYRI adım (ADR/README'ye bakın).
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
DIST="$REPO/dist"
APP="$DIST/Black Widow.app"
RES="$APP/Contents/Resources"
MACOS="$APP/Contents/MacOS"
FULL=0; [ "${1:-}" = "--full" ] && FULL=1

echo "[build_app] REPO=$REPO  MODE=$([ $FULL = 1 ] && echo FULL || echo DEV)"
rm -rf "$APP"; mkdir -p "$RES" "$MACOS"

# --- Ortak iskelet: Info.plist + launcher + icon ---
cp "$HERE/app/Info.plist" "$APP/Contents/Info.plist"
cp "$HERE/app/karadul-launch" "$MACOS/karadul-launch"; chmod +x "$MACOS/karadul-launch"
cp "$HERE/icon/Karadul.icns" "$RES/Karadul.icns"

if [ $FULL = 0 ]; then
  echo "[build_app] DEV .app hazır -> $APP (launcher repo+anaconda'ya düşer)"
  echo "[build_app] Test: open \"$APP\""
  exit 0
fi

# ======================= FULL self-contained assembly =======================
echo "[build_app] FULL: self-contained bundle assemble ediliyor (~3.5 GB)..."

# 1) Relocatable Python (python-build-standalone, arm64 install_only)
PY_URL="${KARADUL_PYSTANDALONE_URL:-}"
if [ -z "$PY_URL" ]; then
  echo "!! KARADUL_PYSTANDALONE_URL set edilmeli (github.com/astral-sh/python-build-standalone"
  echo "   release'inden cpython-3.12.x-aarch64-apple-darwin-install_only.tar.gz)"; exit 1
fi
echo "[build_app] Python indiriliyor: $PY_URL"
curl -fsSL "$PY_URL" -o "$DIST/py.tar.gz"
mkdir -p "$RES/python"; tar xzf "$DIST/py.tar.gz" -C "$RES/python" --strip-components=1
rm -f "$DIST/py.tar.gz"

# 2) karadul + tüm runtime deps (arm64 wheel'ler)
"$RES/python/bin/python3" -m pip install --no-input "$REPO"[ghidra,perf,computation,app]

# 3) Ghidra (taşınabilir, Apache 2.0) — GHIDRA_INSTALL_DIR'den kopyala
GH="${GHIDRA_INSTALL_DIR:-$HOME/Desktop/dosyalar/uygulamalar/ghidra/build/dist/ghidra_12.0_DEV}"
echo "[build_app] Ghidra kopyalanıyor: $GH (~797 MB)"
cp -R "$GH" "$RES/ghidra"

# 4) JDK 21 (Temurin arm64) — Ghidra JRE içermiyor
JDK_URL="${KARADUL_JDK_URL:-}"
if [ -z "$JDK_URL" ]; then
  echo "!! KARADUL_JDK_URL set edilmeli (adoptium.net Temurin 21 JDK aarch64 mac .tar.gz)"; exit 1
fi
echo "[build_app] JDK indiriliyor: $JDK_URL"
curl -fsSL "$JDK_URL" -o "$DIST/jdk.tar.gz"
mkdir -p "$RES/jdk"; tar xzf "$DIST/jdk.tar.gz" -C "$RES/jdk" --strip-components=1
rm -f "$DIST/jdk.tar.gz"

# 5) İmza DB (signatures.lmdb, ~2 GB) — Berke'nin lokal artifact'i
LMDB="${KARADUL_SIG_LMDB:-$HOME/.karadul/signatures.lmdb}"
if [ -e "$LMDB" ]; then
  echo "[build_app] LMDB kopyalanıyor (~2 GB, en uzun adım)..."
  cp -R "$LMDB" "$RES/signatures.lmdb"
else
  echo "!! signatures.lmdb bulunamadı ($LMDB) — bundle imza DB'siz olur"
fi

# 6) ui/ + koşullu naming verisi
cp -R "$REPO/ui" "$RES/ui"
if [ -d "$REPO/sigs/ngram_name_db" ]; then
  mkdir -p "$RES/karadul-data/sigs"
  cp -R "$REPO/sigs/ngram_name_db" "$RES/karadul-data/sigs/"
  [ -f "$REPO/sigs/tuned_weights.json" ] && cp "$REPO/sigs/tuned_weights.json" "$RES/karadul-data/sigs/"
fi

# 7) Ad-hoc codesign (Apple Silicon ZORUNLU, yoksa Killed:9). Dağıtım için
#    Developer ID + notarytool AYRI (README).
echo "[build_app] ad-hoc codesign..."
codesign --force --deep --sign - "$APP" || echo "!! codesign başarısız — dağıtımda Gatekeeper sorunu olabilir"

echo "[build_app] FULL bundle hazır -> $APP"
du -sh "$APP" 2>/dev/null || true
