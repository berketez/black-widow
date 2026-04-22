#!/usr/bin/env bash
# TypeForge kurulum scripti (karadul v1.11.0)
#
# TypeForge, Java tabanli bir Ghidra Extension'idir (Rust CLI degil).
# IEEE S&P 2025: "Synthesizing and Selecting Best-Fit Composite Data Types
# for Stripped Binaries" -- https://github.com/noobone123/TypeForge
#
# Kurulum ozeti:
#   1. Java 17+ kontrolu
#   2. Gradle kontrolu (veya Gradle Wrapper indir)
#   3. Ghidra installation dizinini tespit et / kullanicidan al
#   4. TypeForge repo'yu klonla
#   5. Ghidra Extension olarak derle (gradle buildExtension)
#   6. Extension'i Ghidra dizinine kopyala
#   7. Ghidra headless calistirilabilir bir wrapper script yaz
#
# Kullanim:
#   GHIDRA_INSTALL_DIR=/opt/ghidra_11.0.3 bash scripts/setup_typeforge.sh
#   KARADUL_TYPEFORGE_DIR=$HOME/.karadul/typeforge bash scripts/setup_typeforge.sh

set -euo pipefail

# ---------------------------------------------------------------------------
# Yapilandirma
# ---------------------------------------------------------------------------
INSTALL_DIR="${KARADUL_TYPEFORGE_DIR:-$HOME/.karadul/typeforge}"
GHIDRA_DIR="${GHIDRA_INSTALL_DIR:-}"
TYPEFORGE_REPO="https://github.com/noobone123/TypeForge.git"
TYPEFORGE_MIN_JAVA=17
WRAPPER_NAME="typeforge"

# ---------------------------------------------------------------------------
# Yardimci fonksiyonlar
# ---------------------------------------------------------------------------
die() { echo "[HATA] $*" >&2; exit 1; }
info() { echo "[INFO] $*"; }
warn() { echo "[UYARI] $*" >&2; }

check_command() {
    local cmd="$1"
    local hint="$2"
    command -v "$cmd" >/dev/null 2>&1 || die "'$cmd' bulunamadi. $hint"
}

# ---------------------------------------------------------------------------
# Java kontrolu (17+ zorunlu)
# ---------------------------------------------------------------------------
check_java() {
    check_command java "Kurulum: macOS -> 'brew install openjdk@17', Ubuntu -> 'apt install openjdk-17-jdk'"
    local ver
    ver=$(java -version 2>&1 | awk -F '"' '/version/ {print $2}' | cut -d'.' -f1)
    # Java 1.8 -> "1.x" sorununu ele al
    if [[ "$ver" == "1" ]]; then
        ver=$(java -version 2>&1 | awk -F '"' '/version/ {print $2}' | cut -d'.' -f2)
    fi
    if [[ "$ver" -lt "$TYPEFORGE_MIN_JAVA" ]]; then
        die "Java $TYPEFORGE_MIN_JAVA+ gerekli, mevcut: $ver. 'brew install openjdk@17' ile guncelleyin."
    fi
    info "Java $ver bulundu: $(which java)"
}

# ---------------------------------------------------------------------------
# Gradle kontrolu (repo icinde gradlew yoksa sistem gradle'i ara)
# ---------------------------------------------------------------------------
check_gradle() {
    # gradlew indirilecek; yoksa gradle system-wide aranir
    if ! command -v gradle >/dev/null 2>&1; then
        warn "Sistem gradle yok. Gradle Wrapper (gradlew) kullanilacak -- repo icerisinde olmasi gerekiyor."
        warn "Yoksa: macOS 'brew install gradle', Ubuntu 'apt install gradle'"
    else
        info "Gradle bulundu: $(gradle --version | head -1)"
    fi
}

# ---------------------------------------------------------------------------
# Ghidra dizini tespiti
# ---------------------------------------------------------------------------
find_ghidra() {
    if [[ -n "$GHIDRA_DIR" ]] && [[ -d "$GHIDRA_DIR" ]]; then
        info "Ghidra: $GHIDRA_DIR (GHIDRA_INSTALL_DIR)"
        return 0
    fi

    # Yaygin konumlar
    local candidates=(
        "/opt/ghidra"
        "$HOME/ghidra"
        "$HOME/tools/ghidra"
        "/Applications/ghidra"
    )

    # Versiyonlu dizinleri de dene (ghidra_11*)
    for base in /opt "$HOME" "$HOME/tools" /Applications; do
        while IFS= read -r d; do
            candidates+=("$d")
        done < <(find "$base" -maxdepth 1 -type d -name "ghidra_*" 2>/dev/null || true)
    done

    for d in "${candidates[@]}"; do
        if [[ -f "$d/support/analyzeHeadless" ]] || [[ -f "$d/support/analyzeHeadless.bat" ]]; then
            GHIDRA_DIR="$d"
            info "Ghidra bulundu: $GHIDRA_DIR"
            return 0
        fi
    done

    die "Ghidra kurulum dizini bulunamadi.
Cozum:
  1. https://ghidra-sre.org/ adresinden Ghidra 11.0.3+ indirin, bir yere acin
  2. GHIDRA_INSTALL_DIR=/path/to/ghidra_11.0.3 olarak cevre degiskeni tanimlayip scripti tekrar calistirin"
}

# ---------------------------------------------------------------------------
# TypeForge klonla + derle
# ---------------------------------------------------------------------------
install_typeforge() {
    mkdir -p "$INSTALL_DIR"

    local repo_dir="$INSTALL_DIR/TypeForge"

    if [[ -d "$repo_dir/.git" ]]; then
        info "Mevcut TypeForge repo guncelleniyor: $repo_dir"
        git -C "$repo_dir" pull --ff-only
    else
        info "TypeForge klonlaniyor: $TYPEFORGE_REPO -> $repo_dir"
        git clone "$TYPEFORGE_REPO" "$repo_dir"
    fi

    # build.gradle icinde ghidraInstallDir'i guncelle
    local build_gradle="$repo_dir/build.gradle"
    if [[ ! -f "$build_gradle" ]]; then
        die "build.gradle bulunamadi: $build_gradle -- repo yapisi beklendigi gibi degil."
    fi

    info "build.gradle guncelleniyor (ghidraInstallDir=$GHIDRA_DIR)"
    # Satiri yerinde degistir (macOS + GNU sed uyumu)
    if sed --version >/dev/null 2>&1; then
        sed -i "s|ghidraInstallDir = .*|ghidraInstallDir = \"${GHIDRA_DIR}\"|" "$build_gradle"
    else
        sed -i '' "s|ghidraInstallDir = .*|ghidraInstallDir = \"${GHIDRA_DIR}\"|" "$build_gradle"
    fi

    info "Ghidra Extension derleniyor (gradle buildExtension)..."
    pushd "$repo_dir" >/dev/null
    if [[ -f "./gradlew" ]]; then
        chmod +x ./gradlew
        ./gradlew buildExtension
    elif command -v gradle >/dev/null 2>&1; then
        gradle buildExtension
    else
        die "Gradle bulunamadi. 'brew install gradle' veya sistem paket yoneticisi ile kurun."
    fi
    popd >/dev/null

    # Extension zip'i bul ve Ghidra Extensions dizinine kopyala
    local ext_zip
    ext_zip=$(find "$repo_dir/dist" -name "*.zip" 2>/dev/null | head -1)
    if [[ -z "$ext_zip" ]]; then
        die "Extension zip bulunamadi: $repo_dir/dist/. Derleme basarisiz olabilir."
    fi

    local ghidra_ext_dir="$GHIDRA_DIR/Extensions/Ghidra"
    mkdir -p "$ghidra_ext_dir"
    cp "$ext_zip" "$ghidra_ext_dir/"
    info "Extension kopyalandi: $ghidra_ext_dir/$(basename "$ext_zip")"

    # Extension'i Ghidra'ya yaz (headless modda otomatik yuklenir)
    # Ghidra GUI'sinde: File -> Install Extensions -> TypeForge
    info "Extension ZIP hazir. Ghidra GUI ile kurmak icin: File -> Install Extensions -> TypeForge."
    info "Headless modda otomatik yuklenir (install klasoru Ghidra Extensions)."
}

# ---------------------------------------------------------------------------
# analyzeHeadless wrapper yaz
# ---------------------------------------------------------------------------
write_wrapper() {
    local wrapper_path="$INSTALL_DIR/$WRAPPER_NAME"
    local headless_script="$GHIDRA_DIR/support/analyzeHeadless"

    cat > "$wrapper_path" <<EOF
#!/usr/bin/env bash
# karadul TypeForge wrapper -- otomatik uretildi (setup_typeforge.sh)
# Kullanim: typeforge --binary <binary> --output-dir <dir> [--llvm-ir <ir>]
#
# TypeForge, Ghidra headless modunda calisir.
# Argümanlar: --binary <yol> --output-dir <cikis_dizini> [--llvm-ir <yol>]

set -euo pipefail

BINARY=""
OUTPUT_DIR=""
LLVM_IR=""

while [[ \$# -gt 0 ]]; do
    case "\$1" in
        --binary)   BINARY="\$2";     shift 2 ;;
        --output-dir) OUTPUT_DIR="\$2"; shift 2 ;;
        --llvm-ir)  LLVM_IR="\$2";    shift 2 ;;
        --json)     shift ;;  # karadul compat flag -- ignored, output hep JSON
        *)
            echo "Bilinmeyen arguman: \$1" >&2
            exit 1
            ;;
    esac
done

[[ -z "\$BINARY" ]]     && { echo "[HATA] --binary gerekli" >&2; exit 1; }
[[ -z "\$OUTPUT_DIR" ]] && OUTPUT_DIR=\$(mktemp -d)

mkdir -p "\$OUTPUT_DIR"
PROJ_DIR=\$(mktemp -d)
PROJ_NAME="karadul_tf_\$\$"

HEADLESS="${headless_script}"
[[ -x "\$HEADLESS" ]] || { echo "[HATA] Ghidra headless script bulunamadi: \$HEADLESS" >&2; exit 1; }

SCRIPT_ARGS="output=\${OUTPUT_DIR}"
[[ -n "\$LLVM_IR" ]] && SCRIPT_ARGS+=" llvmir=\${LLVM_IR}"

"\$HEADLESS" "\$PROJ_DIR" "\$PROJ_NAME" \\
    -deleteProject \\
    -import "\$BINARY" \\
    -postScript TypeForge.java "\$SCRIPT_ARGS" \\
    -log "\$OUTPUT_DIR/typeforge.log"

# TypeForge JSON ciktisini stdout'a don (karadul JSON protokolu)
RESULT_JSON="\$OUTPUT_DIR/typeforge_result.json"
if [[ -f "\$RESULT_JSON" ]]; then
    cat "\$RESULT_JSON"
else
    # Bos sonuc (hata yoksa)
    echo '{"structs":[]}'
fi

rm -rf "\$PROJ_DIR"
EOF

    chmod +x "$wrapper_path"
    info "Wrapper yazildi: $wrapper_path"
    info ""
    info "PATH'e eklemek icin ~/.zshrc veya ~/.bashrc dosyasina:"
    info "  export PATH=\"${INSTALL_DIR}:\$PATH\""
    info "  export KARADUL_TYPEFORGE_PATH=\"${wrapper_path}\""
}

# ---------------------------------------------------------------------------
# Ana akis
# ---------------------------------------------------------------------------
main() {
    info "=== TypeForge Kurulum (karadul v1.11.0) ==="
    info "Kurulum dizini: $INSTALL_DIR"

    check_command git "Kurulum: macOS 'xcode-select --install', Ubuntu 'apt install git'"
    check_java
    check_gradle
    find_ghidra
    install_typeforge
    write_wrapper

    info ""
    info "=== Kurulum tamamlandi ==="
    info "Dogrulama:"
    info "  ${INSTALL_DIR}/${WRAPPER_NAME} --binary /path/to/binary --output-dir /tmp/tf_out"
    info ""
    info "karadul entegrasyonu:"
    info "  export KARADUL_TYPEFORGE_PATH='${INSTALL_DIR}/${WRAPPER_NAME}'"
    info "  karadul analyze --binary /path/to/binary"
}

main "$@"
