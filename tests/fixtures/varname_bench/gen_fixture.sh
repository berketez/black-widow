#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# varname_bench fixture uretici
# ---------------------------------------------------------------------------
# Degisken-adi F1 olcumu icin DWARF ground-truth'lu bir arm64 Mach-O binary
# uretir. Kaynak: gnulib'in GERCEK kripto/hash implementasyonlari (sha1,
# sha256, md5, crc) + kucuk bir surucu. Bu kod TEMSILI DEGIL — gercekten
# calisan, gercek insan-yazimi degisken isimlerine sahip uretim kodu.
#
# Uretilen dosyalar (OUT dizinine):
#   hashbench_O0            -- debug (isim korunmus) executable, -g -O0
#   hashbench_O0.dSYM       -- DWARF debug bundle (VARIABLE ground truth)
#   hashbench_O0.stripped   -- gercek stripped (analiz hedefi, isim yok)
#   ayni set O2 icin de.
#
# Ground truth (fonksiyon + parametre + lokal isimleri) hashbench_O0.dSYM
# icindedir; karadul.analyzers.dwarf_extractor.DwarfExtractor ile okunur.
#
# Tekrar uretilebilirlik: bu script + src/ altindaki kaynaklar repoda.
# Baska bir makinede sadece `bash gen_fixture.sh` yeter (Apple clang + dsymutil).
#
# LISANS: src/ altindaki sha*.c/.h, md5.c/.h, crc.c/.h dosyalari gnulib'den
# alinmistir (Free Software Foundation, LGPL 2.1+). Lisans basliklari
# dosyalarda korunmustur. config.h/byteswap.h/hashdriver.c bu benchmark icin
# yazilmis kucuk yardimci/surucu dosyalaridir.
# ---------------------------------------------------------------------------
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="$HERE/src"
OUT="${1:-$HERE/build}"
mkdir -p "$OUT"

if ! command -v clang >/dev/null 2>&1; then
  echo "HATA: clang bulunamadi (Xcode Command Line Tools kurulu mu?)" >&2
  exit 1
fi

UNITS="sha1 sha256 md5 crc hashdriver"

for OPT in O0 O2; do
  BIN="$OUT/hashbench_$OPT"
  OBJ="$OUT/obj_$OPT"
  mkdir -p "$OBJ"
  echo "[gen] derleniyor: -g -$OPT -> $BIN"
  # KRITIK: her .c'yi KALICI .o'ya derle. Tek-adımlı derlemede gecici .o'lar
  # link sonrasi silinir ve dsymutil DWARF'i .o'lardan cekemeyip BOS dSYM
  # uretir (deterministik olmayan, sessiz bug). Ayri .o -> dsymutil kalici
  # .o'lardan okur -> DWARF garanti.
  objs=""
  for u in $UNITS; do
    clang -g -"$OPT" -std=gnu11 -I"$SRC" -c "$SRC/$u.c" -o "$OBJ/$u.o"
    objs="$objs $OBJ/$u.o"
  done
  clang -g -"$OPT" $objs -o "$BIN"

  echo "[gen] dSYM (DWARF ground truth) uretiliyor"
  dsymutil "$BIN" -o "$BIN.dSYM"
  ntag=$(dwarfdump --debug-info "$BIN.dSYM" 2>/dev/null | grep -c DW_TAG_subprogram || true)
  echo "[gen] dSYM DW_TAG_subprogram: $ntag"
  if [ "${ntag:-0}" -lt 5 ]; then
    echo "[gen] HATA: dSYM bos (DWARF cekilemedi) — .o dosyalari korunmadi mi?" >&2
    exit 2
  fi

  echo "[gen] stripped kopya (analiz hedefi)"
  cp "$BIN" "$BIN.stripped"
  strip "$BIN.stripped" 2>/dev/null || true

  # Dogruluk saglamasi: uretilen binary gercek/dogru hash uretiyor mu?
  got="$("$BIN" | awk -F': ' '/^sha256/{print $2}')"
  ref="$(printf '%s' 'The quick brown fox jumps over the lazy dog' | shasum -a 256 | awk '{print $1}')"
  if [ "$got" = "$ref" ]; then
    echo "[gen] $OPT sha256 saglamasi: OK"
  else
    echo "[gen] UYARI: $OPT sha256 uyusmadi ($got != $ref)" >&2
  fi
  echo "[gen] stripped sembol sayisi (T/t): $(nm "$BIN.stripped" 2>/dev/null | grep -cE ' [Tt] ' || true)"
done

echo "[gen] tamam. Cikti: $OUT"
