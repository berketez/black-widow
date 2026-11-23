#!/bin/bash
# Karadul P-ÜV3: yerel Swift örneklerini derle (sembollü + soyulmuş kopya). Derleme çıktısı ÇALIŞTIRILMAZ,
# depoya girmez; yalnız kaynak, sayı ve sha256 depoya yazılır.
#
# Kullanım: scripts/arge/ustveri/swift_ornek/derle.sh [çıktı dizini]
#   öntanım: ~/karadul_olcum/runs/dalga1-2026-11-23/PUV3/ornek
# Her derleme biçimi için (O: -O; Onone: -Onone; Oanon: -O + adsız bağlam karışık adları
# `-Xfrontend -enable-anonymous-context-mangled-names`, öntanımda kapalı olan biçim):
#   <dizin>/ornek_<biçim>        sembollü (bağlayıcının yerel sembolleri dahil)
#   <dizin>/ornek_<biçim>.strip  /usr/bin/strip ile soyulmuş kopya
#   <dizin>/sha256.txt
set -euo pipefail
KAYNAK="$(cd "$(dirname "$0")" && pwd)"
CIKTI="${1:-$HOME/karadul_olcum/runs/dalga1-2026-11-23/PUV3/ornek}"
mkdir -p "$CIKTI"
derle() {
  local ad="$1"; shift
  /usr/bin/xcrun swiftc "$@" -module-name Ornek \
    -import-objc-header "$KAYNAK/ornek.h" \
    -Xlinker -undefined -Xlinker dynamic_lookup \
    "$KAYNAK/main.swift" "$KAYNAK/gizli.swift" "$KAYNAK/uzanti.swift" "$KAYNAK/ice_aktarim.swift" \
    "$KAYNAK/cf_tipleri.swift" \
    -o "$CIKTI/$ad"
  cp "$CIKTI/$ad" "$CIKTI/$ad.strip"
  /usr/bin/strip "$CIKTI/$ad.strip"
}
derle ornek_O -O
derle ornek_Onone -Onone
derle ornek_Oanon -O -Xfrontend -enable-anonymous-context-mangled-names
( cd "$CIKTI" && /usr/bin/shasum -a 256 ornek_O ornek_O.strip ornek_Onone ornek_Onone.strip \
    ornek_Oanon ornek_Oanon.strip > sha256.txt )
cat "$CIKTI/sha256.txt"
