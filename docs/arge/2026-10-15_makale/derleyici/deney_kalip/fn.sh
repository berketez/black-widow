#!/bin/bash
# kullanım: fn.sh <asm dosyası> <fonksiyon adı>
awk -v f="<_$2>:" '$0 ~ f {p=1; print; next} p && /^[0-9a-f]+ <_/ {p=0} p' "$1"
