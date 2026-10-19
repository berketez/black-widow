#!/usr/bin/python3 -I
"""İki ya da daha çok Mach-O dosyasının bölümlerini boyut ve sha256 eşitliğiyle kıyaslar.

İçerik BASILMAZ; yalnız bölüm adı, boyutlar ve "aynı/farklı" basılır.
Kullanım: bolum_kiyas.py <referans> <aday> [<aday> ...]
"""
import hashlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from bolum_ozeti import bolumler  # noqa: E402


def ozet(yol):
    veri = open(yol, "rb").read()
    sonuc = {}
    for seg, sect, size, offset, flags in bolumler(veri):
        zerofill = (flags & 0xFF) in (0x1, 0xC, 0x12)
        h = None if zerofill else hashlib.sha256(veri[offset:offset + size]).hexdigest()
        sonuc[f"{seg},{sect}"] = (size, h)
    return sonuc


def main():
    ref = ozet(sys.argv[1])
    adaylar = [ozet(y) for y in sys.argv[2:]]
    for ad, (boy, h) in ref.items():
        hucreler = []
        for a in adaylar:
            if ad not in a:
                hucreler.append("yok")
                continue
            ab, ah = a[ad]
            if ab == boy and ah == h:
                hucreler.append(f"{ab} aynı")
            elif ab == boy:
                hucreler.append(f"{ab} boyut aynı, içerik farklı")
            else:
                hucreler.append(f"{ab} ({ab - boy:+d}) farklı")
        print(f"{ad:30s} ref={boy:9d} | " + " | ".join(hucreler))


if __name__ == "__main__":
    main()
