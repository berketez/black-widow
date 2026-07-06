#!/bin/bash
# Fix'li ölçüm — worktree kod (18 bug fix). Baseline ile karşılaştırma için
# aynı 9 binary. Çıktı _wsf2/_cleanf2 (baseline _wsf'den ayrı, find_naming_map
# {b}_ws* glob'u en yeniyi = fix'liyi seçer). PROG run_one içinde hardcoded
# (önceki script'te export edilmeyip boş path'e yazıyordu — kozmetik bug).
set -u
WT="/Users/apple/Desktop/black-widow/.claude/worktrees/bugfix-naming-keys"
PROG="$HOME/karadul_meas/batch_fixed_progress.log"
BINS="cat head cut tr expr wc date stat sort"

run_one() {
  b="$1"
  t0=$(date +%s)
  cd "/Users/apple/Desktop/black-widow/.claude/worktrees/bugfix-naming-keys"
  python3 -m karadul analyze "$HOME/coreutils_gt/${b}.stripped" \
    --skip-dynamic --lmdb-sigdb \
    --output-dir "$HOME/karadul_meas/${b}_wsf2" \
    --output "$HOME/karadul_meas/${b}_cleanf2" \
    > "$HOME/karadul_meas/${b}_f2.log" 2>&1
  ec=$?
  t1=$(date +%s)
  rec="?"
  grep -q "\[OK\] reconstruct" "$HOME/karadul_meas/${b}_f2.log" 2>/dev/null && rec="OK"
  grep -q "\[FAIL\] reconstruct" "$HOME/karadul_meas/${b}_f2.log" 2>/dev/null && rec="FAIL"
  echo "$b: exit=$ec reconstruct=$rec sure=$(( (t1-t0)/60 ))dk $(date +%H:%M)" \
    >> "$HOME/karadul_meas/batch_fixed_progress.log"
}
export -f run_one
export HOME

echo "=== FIXED BATCH START $(date +%H:%M) — 9 binary, 3 paralel (worktree kod) ===" > "$PROG"
echo "$BINS" | tr ' ' '\n' | xargs -P 3 -I{} bash -c 'run_one "$@"' _ {}
echo "=== FIXED BATCH DONE $(date +%H:%M) ===" >> "$PROG"
