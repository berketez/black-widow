#!/usr/bin/env bash
# pycdc (Decompyle++) kurulum scripti -- Python .pyc deterministik decompile.
#
# pycdc, C++ ile yazilmis, versiyon-bagimsiz bir Python bytecode decompiler'idir
# (pip'te YOK, kaynaktan derlenir). Karadul PYTHON_PACKED reconstruction'da
# .pyc -> .py icin birincil deterministik motordur (LLM/ML KULLANILMAZ).
#   https://github.com/zrax/pycdc
#
# Kurulum ozeti:
#   1. git + cmake + make + C++ derleyici kontrolu
#   2. zrax/pycdc repo'yu klonla
#   3. CMake ile derle (pycdc + pycdas)
#   4. Uretilen binary'leri vendor/pycdc/ altina kopyala
#      (python_binary.py resolve_tool ile buradan bulur)
#
# Kurulu degilse karadul yine calisir: decompile zinciri bytecode
# disassembly (stdlib dis) fallback'ine duser -- yalniz kalite duser.
#
# Kullanim:
#   bash scripts/setup_pycdc.sh
#   KARADUL_PYCDC_BUILD=/tmp/pycdc-build bash scripts/setup_pycdc.sh

set -euo pipefail

# ---------------------------------------------------------------------------
# Yapilandirma
# ---------------------------------------------------------------------------
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENDOR_DIR="$REPO_ROOT/vendor/pycdc"
BUILD_DIR="${KARADUL_PYCDC_BUILD:-$HOME/.karadul/pycdc-build}"
PYCDC_REPO="https://github.com/zrax/pycdc.git"

# ---------------------------------------------------------------------------
# Yardimci fonksiyonlar
# ---------------------------------------------------------------------------
die() { echo "[HATA] $*" >&2; exit 1; }
info() { echo "[INFO] $*"; }
warn() { echo "[UYARI] $*" >&2; }

check_command() {
    local cmd="$1"
    command -v "$cmd" >/dev/null 2>&1 || die "'$cmd' bulunamadi. Once kurun (git/cmake/make/C++ derleyici gerekir)."
}

# ---------------------------------------------------------------------------
# 1. On kosullar
# ---------------------------------------------------------------------------
info "On kosullar kontrol ediliyor..."
check_command git
check_command cmake
check_command make

# ---------------------------------------------------------------------------
# 2. Klonla / guncelle
# ---------------------------------------------------------------------------
mkdir -p "$BUILD_DIR"
if [ -d "$BUILD_DIR/pycdc/.git" ]; then
    info "Mevcut pycdc klonu guncelleniyor: $BUILD_DIR/pycdc"
    git -C "$BUILD_DIR/pycdc" pull --ff-only || warn "git pull basarisiz, mevcut kaynak kullanilacak"
else
    info "pycdc klonlaniyor: $PYCDC_REPO"
    git clone --depth 1 "$PYCDC_REPO" "$BUILD_DIR/pycdc"
fi

# ---------------------------------------------------------------------------
# 3. Derle
# ---------------------------------------------------------------------------
info "CMake ile derleniyor..."
cmake -S "$BUILD_DIR/pycdc" -B "$BUILD_DIR/pycdc/build" -DCMAKE_BUILD_TYPE=Release
cmake --build "$BUILD_DIR/pycdc/build" --config Release -j "$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)"

# ---------------------------------------------------------------------------
# 4. Binary'leri vendor/pycdc'ye kopyala
# ---------------------------------------------------------------------------
mkdir -p "$VENDOR_DIR"
copied=0
for name in pycdc pycdas; do
    # Derleme cikti yeri platforma gore degisebilir; genis ara.
    bin_path="$(find "$BUILD_DIR/pycdc/build" -maxdepth 3 -type f -name "$name" -perm -u+x 2>/dev/null | head -n1 || true)"
    if [ -z "$bin_path" ]; then
        # Windows/MSVC: .exe uzantisi
        bin_path="$(find "$BUILD_DIR/pycdc/build" -maxdepth 3 -type f -name "$name.exe" 2>/dev/null | head -n1 || true)"
    fi
    if [ -n "$bin_path" ]; then
        cp "$bin_path" "$VENDOR_DIR/"
        chmod +x "$VENDOR_DIR/$(basename "$bin_path")" 2>/dev/null || true
        info "Kopyalandi: $(basename "$bin_path") -> $VENDOR_DIR/"
        copied=$((copied + 1))
    else
        warn "$name derleme ciktisinda bulunamadi"
    fi
done

[ "$copied" -gt 0 ] || die "Hicbir binary uretilmedi -- derleme basarisiz olabilir."

info "Tamamlandi. pycdc/pycdas: $VENDOR_DIR"
info "Karadul artik .pyc dosyalarini gercek kaynaga decompile edebilir."
