#!/usr/bin/python3 -I
"""superenv cc günlüğünden etkin derleyici bayraklarının özeti.

Dosya adı, nesne adı ve -o hedefi BASILMAZ (test seti yalıtımı); yalnız bayrak
sayıları ve dosya adından arındırılmış bayrak kümeleri basılır.
Kullanım: bayrak_ozeti.py <superenv.cc.log> [--kume]
"""
import collections
import sys

DOSYA_UZANTILARI = (".c", ".o", ".m", ".s", ".S", ".a", ".cc", ".cpp", ".bundle", ".dylib", ".so", ".i")


def bayraklar(satir):
    t = satir.split()
    arac, args = t[0], t[1:]
    temiz, atla = [], False
    for a in args:
        if atla:
            atla = False
            continue
        if a in ("-o", "-MF", "-MT", "-MQ"):
            atla = True
            continue
        if a.endswith(DOSYA_UZANTILARI) or (not a.startswith("-") and "/" not in a and "." in a):
            continue
        temiz.append(a)
    return arac, temiz


def main():
    yol = sys.argv[1]
    kume = "--kume" in sys.argv
    hepsi = [l[len("superenv executed: "):].strip()
             for l in open(yol, encoding="utf-8", errors="replace")
             if l.startswith("superenv executed: ")]
    # configure denemeleri (conftest*) ikiliye girmez; ayrı sayılır
    calistirilan = [c for c in hepsi if "conftest" not in c]
    print(f"configure denemesi (conftest, ayrı tutuldu)={len(hepsi) - len(calistirilan)}")
    derleme = [bayraklar(c)[1] for c in calistirilan if " -c " in f" {c} "]
    baglama = [bayraklar(c)[1] for c in calistirilan if " -c " not in f" {c} " and " -E " not in f" {c} "]
    print(f"çağrı toplam={len(calistirilan)} derleme(-c)={len(derleme)} bağlama/diğer={len(baglama)}")

    def say(liste, kosul):
        return sum(1 for b in liste if any(kosul(x) for x in b))

    for ad, liste in (("derleme", derleme), ("bağlama", baglama)):
        print(f"[{ad}] -Os: {say(liste, lambda x: x == '-Os')}"
              f"  -g: {say(liste, lambda x: x == '-g')}"
              f"  -w: {say(liste, lambda x: x == '-w')}"
              f"  -O0/-O1/-O2/-O3/-Ofast: {say(liste, lambda x: x in ('-O0', '-O1', '-O2', '-O3', '-Ofast', '-O'))}"
              f"  -isysroot(MacOSX26.sdk): {say(liste, lambda x: x.startswith('-isysroot') and 'MacOSX26.sdk' in x)}"
              f"  -Wl,-x: {say(liste, lambda x: x == '-Wl,-x')}"
              f"  -Wl,-S: {say(liste, lambda x: x == '-Wl,-S')}"
              f"  -s: {say(liste, lambda x: x == '-s')}"
              f"  -ffile-prefix-map: {say(liste, lambda x: x.startswith('-ffile-prefix-map'))}"
              f"  -Wl,-oso_prefix: {say(liste, lambda x: x.startswith('-Wl,-oso_prefix'))}"
              f"  conda/usr/local yolu: {say(liste, lambda x: 'conda' in x or '/usr/local' in x)}")
    if kume:
        sayac = collections.Counter(" ".join(b) for b in derleme)
        print("derleme bayrak kümeleri (dosya adları çıkarılmış):")
        for k, n in sayac.most_common():
            print(f"  {n:4d} × {k}")
        sayac = collections.Counter(" ".join(b) for b in baglama)
        print("bağlama bayrak kümeleri (dosya adları çıkarılmış):")
        for k, n in sayac.most_common():
            print(f"  {n:4d} × {k}")


if __name__ == "__main__":
    main()
