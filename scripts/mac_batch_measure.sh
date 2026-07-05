#!/bin/bash
# Mac-native tam F1 ölçümü — fix'li kod (stages.py final_decompiled_dir seed).
# Küçükten büyüğe sıralı, 3 paralel. cat zaten ölçüldü (cat_ws2), buraya dahil değil.
set -u
cd /Users/apple/Desktop/black-widow
MEAS="$HOME/karadul_meas"
PROG="$MEAS/batch_progress.log"

# fonksiyon sayısına göre küçük -> büyük (uzun sürenler sona)
BINS="head cut tr expr wc date stat sort du mv cp"

run_one() {
  b="$1"
  t0=$(date +%s)
  python3 -m karadul analyze "$HOME/coreutils_gt/${b}.stripped" \
    --skip-dynamic --lmdb-sigdb \
    --output-dir "$HOME/karadul_meas/${b}_wsf" \
    --output "$HOME/karadul_meas/${b}_cleanf" \
    > "$HOME/karadul_meas/${b}_f.log" 2>&1
  ec=$?
  t1=$(date +%s)
  # reconstruct OK mu?
  rec="?"
  grep -q "OK reconstruct\|\[OK\] reconstruct" "$HOME/karadul_meas/${b}_f.log" 2>/dev/null && rec="OK"
  grep -q "FAIL reconstruct\|\[FAIL\] reconstruct" "$HOME/karadul_meas/${b}_f.log" 2>/dev/null && rec="FAIL"
  echo "$b: exit=$ec reconstruct=$rec sure=$(( (t1-t0)/60 ))dk bitis=$(date +%H:%M)" >> "$PROG"
}
export -f run_one
export HOME

echo "=== BATCH START $(date +%H:%M) — 11 binary, 3 paralel ===" > "$PROG"
echo "$BINS" | tr ' ' '\n' | xargs -P 3 -I{} bash -c 'run_one "$@"' _ {}
echo "=== BATCH DONE $(date +%H:%M) ===" >> "$PROG"
