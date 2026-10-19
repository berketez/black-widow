#!/bin/bash
# Kaynaktan derlenen ikiliyi doğrular. YALNIZ sayı, evet/hayır, sha256, UUID ve
# kütüphane yolu basar; hiçbir fonksiyon/sembol adı basmaz (test seti yalıtımı).
#
# Kullanım: dogrula.sh <program-dizini> <ikili-adı> <şişedeki-ikili>
set -euo pipefail
P=$1; AD=$2; SISE=$3
GT=$P/gt/$AD; DSYM=$P/gt/$AD.dSYM; AN=$P/analiz/$AD

say_tT() {  # nm -U: toplam, t, T
  /usr/bin/nm -U "$1" | /usr/bin/awk '{n++} $2=="t"{t++} $2=="T"{T++} END{printf "toplam=%d t=%d T=%d", n, t+0, T+0}'
}
build_ver() {
  /usr/bin/otool -l "$1" | /usr/bin/awk '
    /cmd LC_BUILD_VERSION/{f=1}
    f&&$1=="minos"{m=$2} f&&$1=="sdk"{s=$2}
    f&&$1=="tool"{tl=$2} f&&$1=="version"&&tl!=""&&v==""{v=$2}
    f&&$1=="cmd"&&$2!="LC_BUILD_VERSION"{f=0}
    END{printf "minos=%s sdk=%s ld=%s", m, s, v}'
}
text_boyut_py() {
  /usr/bin/otool -l "$1" | /usr/bin/python3 -I -c '
import sys
lines=[l.split() for l in sys.stdin]
for i,l in enumerate(lines):
    if len(l)==2 and l[0]=="sectname" and l[1]=="__text" and lines[i+1][1]=="__TEXT":
        size=next(x for x in lines[i+1:i+6] if x and x[0]=="size")
        print(int(size[1],16)); break'
}
kutuphaneler() {
  /usr/bin/otool -L "$1" | /usr/bin/tail -n +2 | /usr/bin/awk '{print $1}' | /usr/bin/sed 's|@@HOMEBREW_PREFIX@@|/opt/homebrew|' | /usr/bin/sort
}

echo "== $AD"
echo "mimari (gt):            $(/usr/bin/lipo -archs "$GT")"
echo "mimari (analiz):        $(/usr/bin/lipo -archs "$AN")"
echo "boyut bayt gt/analiz:   $(/usr/bin/stat -f %z "$GT") / $(/usr/bin/stat -f %z "$AN")"
echo "nm -U gt:               $(say_tT "$GT")"
echo "nm -U analiz:           $(say_tT "$AN")"
echo "nm -U şişe:             $(say_tT "$SISE")"
echo "nm -u (dış) gt/şişe:    $(/usr/bin/nm -u "$GT" | /usr/bin/wc -l | tr -d ' ') / $(/usr/bin/nm -u "$SISE" | /usr/bin/wc -l | tr -d ' ')"
echo "debug map (N_OSO) gt:   $(/usr/bin/nm -ap "$GT" | /usr/bin/grep -c ' OSO ' || true)"
echo "debug map (N_OSO) anlz: $(/usr/bin/nm -ap "$AN" | /usr/bin/grep -c ' OSO ' || true)"
U_GT=$(/usr/bin/dwarfdump --uuid "$GT" | /usr/bin/awk '{print $2}')
U_DS=$(/usr/bin/dwarfdump --uuid "$DSYM" | /usr/bin/awk '{print $2}')
U_AN=$(/usr/bin/dwarfdump --uuid "$AN" | /usr/bin/awk '{print $2}')
echo "UUID gt:                $U_GT"
echo "UUID dSYM:              $U_DS"
echo "UUID analiz:            $U_AN"
[ "$U_GT" = "$U_DS" ] && echo "dSYM UUID eşleşmesi:    evet" || echo "dSYM UUID eşleşmesi:    HAYIR"
[ "$U_GT" = "$U_AN" ] && echo "analiz UUID = gt UUID:  evet" || echo "analiz UUID = gt UUID:  HAYIR"
DWF=$P/gt/$AD.dSYM/Contents/Resources/DWARF/$AD
echo "dSYM DWARF CU sayısı:   $(/usr/bin/dwarfdump --debug-info "$DWF" 2>/dev/null | /usr/bin/grep -c 'DW_TAG_compile_unit' || true)"
echo "dSYM DW_TAG_subprogram: $(/usr/bin/dwarfdump --debug-info "$DWF" 2>/dev/null | /usr/bin/grep -c 'DW_TAG_subprogram' || true)"
EX_GT=$(/usr/bin/xcrun dyld_info -exports "$GT" | /usr/bin/awk 'NR>3' | /usr/bin/grep -c . || true)
EX_AN=$(/usr/bin/xcrun dyld_info -exports "$AN" | /usr/bin/awk 'NR>3' | /usr/bin/grep -c . || true)
EX_AN_MH=$(/usr/bin/xcrun dyld_info -exports "$AN" | /usr/bin/awk 'NR>3' | /usr/bin/grep -c '__mh_execute_header' || true)
echo "export trie gt (girdi): $EX_GT"
echo "export trie analiz:     $EX_AN (bunların __mh_execute_header olanı: $EX_AN_MH)"
[ "$EX_AN" = "1" ] && [ "$EX_AN_MH" = "1" ] && echo "export trie boş mu:     evet (yalnız __mh_execute_header)" || echo "export trie boş mu:     HAYIR"
echo "LC_BUILD_VERSION gt:    $(build_ver "$GT")"
echo "LC_BUILD_VERSION şişe:  $(build_ver "$SISE")"
echo "__TEXT,__text gt/şişe:  $(text_boyut_py "$GT") / $(text_boyut_py "$SISE") bayt"
echo "sha256 gt:              $(/usr/bin/shasum -a 256 "$GT" | /usr/bin/awk '{print $1}')"
echo "sha256 analiz:          $(/usr/bin/shasum -a 256 "$AN" | /usr/bin/awk '{print $1}')"
echo "otool -L gt:"
kutuphaneler "$GT" | /usr/bin/sed 's/^/    /'
echo "otool -L şişe (@@HOMEBREW_PREFIX@@ -> /opt/homebrew):"
kutuphaneler "$SISE" | /usr/bin/sed 's/^/    /'
if diff <(kutuphaneler "$GT") <(kutuphaneler "$SISE") >/dev/null; then echo "kütüphane kümesi şişeyle aynı: evet"; else echo "kütüphane kümesi şişeyle aynı: HAYIR"; fi
if kutuphaneler "$GT" | /usr/bin/grep -qiE 'anaconda|conda|/usr/local'; then echo "conda//usr/local yolu: VAR (GEÇERSİZ)"; else echo "conda//usr/local yolu: yok"; fi
