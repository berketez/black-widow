#!/bin/bash
# KİMLİK hattı — ek koşular bittikten sonra bütün ek ölçümleri sırayla üretir (DEFTER.md §5.9–§5.11).
# Kullanım: bash scripts/arge/kimlik/son_olcum.sh <aşama>   aşama ∈ {bsim, gcc, ek, duzey}
set -u
cd "$HOME/Black_Widow" || exit 1
K="$HOME/karadul_olcum/runs/arge-2026-11-19/kimlik"
A=scripts/arge/kimlik
export PYTHONDONTWRITEBYTECODE=1
olc() {  # olc <etiket> <grup>...
  local e="$1"; shift
  python $A/envanter.py "$@" --json "$K/envanter_$e.json" > "$K/envanter_$e.txt" 2>&1
  python $A/yayilim_olc.py "$@" --egri --json "$K/yayilim_$e.json" > "$K/yayilim_$e.txt" 2>&1
  for n in kural tutucu kural_v2 tutucu_v2; do
    python $A/hata_dok.py "$@" --nokta $n --json "$K/hata_${e}_$n.json" > "$K/hata_${e}_$n.txt" 2>&1
  done
  python $A/ciplak.py "$@" --json "$K/ciplak_$e.json" > "$K/ciplak_$e.txt" 2>&1
}
case "$1" in
  bsim)  python $A/bsim_temiz.py --json "$K/bsim_temiz.json" > "$K/bsim_temiz.txt" 2>&1 ;;
  gcc)   olc gcc derleyici derleyici_htop surum_gcc ;;
  ek)    olc ek sinama_cu_mac2 sembollu ;;
  duzey) olc duzey iyilestirme_o3 iyilestirme_o0 ;;
esac
echo "son_olcum $1 bitti"
