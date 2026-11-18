#!/usr/bin/env bash
# P02 gerçek pozitif setini üretir (ikililer depo DIŞINDA):
#   ~/karadul_olcum/runs/onarim-2026-11-18/P02/pozitif/
# Worktree kökünden: bash scripts/measurement/p02_pozitif/uret.sh
# Araçlar: Apple clang (x86_64 + arm64 Mach-O, x86_64/aarch64 ELF nesnesi), /opt/homebrew/bin/upx,
# capstone (PE denetimi). Kaynaklar masum ikililerin KOPYASINI paketler; özgünlere dokunmaz.
set -euo pipefail

KOK="$(cd "$(dirname "$0")" && pwd)"
CIKTI="${HOME}/karadul_olcum/runs/onarim-2026-11-18/P02/pozitif"
UPX=/opt/homebrew/bin/upx
PY=/opt/anaconda3/bin/python
mkdir -p "$CIKTI"

# 1) macOS: ptrace(PT_DENY_ATTACH) + sysctl(KERN_PROC_PID, P_TRACED) + rdtsc (x86-64)
clang -arch x86_64 -O1 -o "$CIKTI/ad_macos_x86_64" "$KOK/antidebug_macos.c"
clang -arch arm64  -O1 -o "$CIKTI/ad_macos_arm64"  "$KOK/antidebug_macos.c"
lipo -create -output "$CIKTI/ad_macos_evrensel" "$CIKTI/ad_macos_x86_64" "$CIKTI/ad_macos_arm64"

# 2) Linux ELF nesnesi (bağlayıcı yok): ptrace(PTRACE_TRACEME) + /proc/self/status + rdtsc
clang -target x86_64-unknown-linux-gnu -O1 -ffreestanding -c -o "$CIKTI/ad_linux_x86_64.o" "$KOK/antidebug_linux.c"
clang -target aarch64-unknown-linux-gnu -O1 -ffreestanding -c -o "$CIKTI/ad_linux_aarch64.o" "$KOK/antidebug_linux.c"

# 3) Elle kurulmuş PE: IsDebuggerPresent + CheckRemoteDebuggerPresent (+ NtQueryInformationProcess, x64)
"$PY" "$KOK/pe_sentetik.py" --mimari x86_64 --cikti "$CIKTI/ad_pe_x64.exe"
"$PY" "$KOK/pe_sentetik.py" --mimari x86    --cikti "$CIKTI/ad_pe_x86.exe"

# 4) UPX ile paketlenmiş kopyalar (masum özgünler değişmez)
DISTLIB=/opt/anaconda3/lib/python3.12/site-packages/pip/_vendor/distlib
FASTLIST=/opt/homebrew/lib/node_modules/pnpm/dist/vendor/fastlist-0.3.0-x64.exe
PWD_ELF="${HOME}/karadul_olcum/n1_debian13/coreutils/pwd/ws/workspaces/pwd/20261021_103050/raw/pwd"
paketle() {  # $1 kaynak, $2 hedef ad
  cp "$1" "$CIKTI/$2"
  chmod u+w "$CIKTI/$2"
  "$UPX" -q -9 "$CIKTI/$2" >/dev/null || { echo "UPX paketleyemedi: $1" >&2; rm -f "$CIKTI/$2"; }
}
paketle "$DISTLIB/w32.exe" upx_w32.exe
paketle "$FASTLIST" upx_fastlist_x64.exe
paketle "$DISTLIB/t64-arm.exe" upx_t64_arm.exe
paketle "$PWD_ELF" upx_pwd_aarch64

ls -l "$CIKTI"
shasum -a 256 "$CIKTI"/* > "$CIKTI/../pozitif_sha256.txt"
