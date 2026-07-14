#!/usr/bin/env bash
# fetch_gnulib_ref.sh -- vendor/gnulib-ref'i SABİT bir gnulib commit'ine getir.
#
# NEDEN VAR:
#   vendor/gnulib-ref/ dizini .gitignore'da (repo'ya dahil değil, submodule de değil).
#   Bu yüzden fingerprint leakage-oracle'ının HANGİ gnulib sürümüne dayandığının
#   TEK kalıcı kaydı bu betiktir. gnulib_fingerprints.py string-anchor'larının
#   "leakage-safe" olduğu iddiası, oracle'ın (vendor kaynağı) ölçüm binary'lerinin
#   (coreutils 9.4) gnulib sürümüyle AYNI çağda olmasına bağlıdır.
#
# SÜRÜM GEREKÇESİ (2026-07-14 pin):
#   Ölçüm binary'leri: tests/fixtures/coreutils/ -> Ubuntu 24.04 apt coreutils 9.4
#   (çıkış 2023-08-29). coreutils v9.4 tag'inin gnulib submodule pointer'ı:
#       bb5bb43a1ebb9f502b5ce38c0b8c8778d13b9f6e   (gnulib master, 2023-08-27)
#   Bu commit'e pin -> leakage-oracle ölçüm hedefiyle hizalı. Önceki durum:
#   vendor 2026-07 master (0d56c8d) idi -> oracle 3 yıl ileri, sessiz call-shape
#   drift riski (naming denetimi 2026-07-13 bulgusu).
#
# coreutils_9.4 -> gnulib commit'i şuradan doğrulanır:
#   curl -s "https://api.github.com/repos/coreutils/coreutils/contents/gnulib?ref=v9.4"
#   (JSON "sha" alanı = gnulib submodule commit'i)
set -euo pipefail

PIN_COMMIT="bb5bb43a1ebb9f502b5ce38c0b8c8778d13b9f6e"
GNULIB_URL="https://git.savannah.gnu.org/git/gnulib.git"
DEST="$(cd "$(dirname "$0")/.." && pwd)/vendor/gnulib-ref"

echo "[fetch_gnulib_ref] hedef commit: $PIN_COMMIT"
echo "[fetch_gnulib_ref] dizin:        $DEST"

if [ -d "$DEST/.git" ]; then
    echo "[fetch_gnulib_ref] mevcut checkout bulundu -> hedefli fetch"
    git -C "$DEST" fetch --depth 1 origin "$PIN_COMMIT"
    git -C "$DEST" checkout "$PIN_COMMIT"
else
    echo "[fetch_gnulib_ref] taze klon (shallow, tek commit)"
    rm -rf "$DEST"
    git clone --no-checkout "$GNULIB_URL" "$DEST"
    git -C "$DEST" fetch --depth 1 origin "$PIN_COMMIT"
    git -C "$DEST" checkout "$PIN_COMMIT"
fi

HEAD_NOW="$(git -C "$DEST" rev-parse HEAD)"
if [ "$HEAD_NOW" != "$PIN_COMMIT" ]; then
    echo "[fetch_gnulib_ref] HATA: HEAD ($HEAD_NOW) beklenen pin ($PIN_COMMIT) ile eşleşmiyor" >&2
    exit 1
fi
echo "[fetch_gnulib_ref] OK -> HEAD $HEAD_NOW ($(git -C "$DEST" log -1 --format=%ci))"
