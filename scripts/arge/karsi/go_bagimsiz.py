"""Kalem 1 (ÜST VERİ): Go pclntab iddiasının bağımsız denetimi.

Hattın `go_pclntab.py` okuyucusu kullanılmaz. Asgari okuyucu: başlık imzasını (0xfffffff1) dosyada arar,
`nfunc` alanını okur; sembollü ikilide (Go <= 1.25: başlıkta textStart dolu) ftab + _func.nameOff ile
(adres, ad) çıkarır ve `nm` çıktısıyla karşılaştırır. Hiçbir ikili çalıştırılmaz.

Komut: PYTHONDONTWRITEBYTECODE=1 python scripts/arge/karsi/go_bagimsiz.py <ikili> [...]
"""
from __future__ import annotations

import mmap
import struct
import subprocess
import sys

IMZA = b"\xf1\xff\xff\xff\x00\x00"


def basliklar(m):
    i = 0
    while True:
        i = m.find(IMZA, i)
        if i < 0:
            return
        min_lc, ptr = m[i + 6], m[i + 7]
        if min_lc in (1, 2, 4) and ptr == 8:
            yield i
        i += 1


def cstr(m, o):
    j = m.find(b"\0", o)
    return m[o:j].decode("utf-8", "replace")


def main() -> None:
    for yol in sys.argv[1:]:
        with open(yol, "rb") as f:
            m = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        bulunan = list(basliklar(m))
        print(f"\n{yol}: imza adayı {len(bulunan)}")
        for b in bulunan:
            nfunc, nfiles, text_start, o_name, o_cu, o_file, o_pc, o_pcln = struct.unpack_from("<8Q", m, b + 8)
            if not (0 < nfunc < 5_000_000 and o_name < o_pcln < 1 << 31):
                continue
            print(f"  başlık @0x{b:x}: nfunc {nfunc} nfiles {nfiles} textStart 0x{text_start:x}")
            ftab = b + o_pcln
            adlar = {}
            adsiz = 0
            for k in range(nfunc):
                entry_off, func_off = struct.unpack_from("<II", m, ftab + 8 * k)
                e2, name_off = struct.unpack_from("<Ii", m, ftab + func_off)
                ad = cstr(m, b + o_name + name_off) if name_off >= 0 else ""
                if not ad:
                    adsiz += 1
                adlar[text_start + entry_off] = ad
            print(f"    okunan giriş {len(adlar)} (adsız {adsiz})")
            if text_start == 0:
                print("    textStart 0 (Go >= 1.26): adres karşılaştırması yapılamaz; yalnız sayım")
                continue
            # nm: sembollü ikili
            try:
                c = subprocess.run(["nm", "-arch", "arm64", yol], capture_output=True, text=True, timeout=300)
            except Exception as h:  # noqa: BLE001
                print("    nm çalışmadı:", h)
                continue
            sem = {}
            for s in c.stdout.splitlines():
                p = s.split(" ", 2)
                if len(p) == 3 and p[1] in ("T", "t"):
                    sem.setdefault(int(p[0], 16), []).append(p[2])
            ortak = ayni = ek_abi = orta_nokta = farkli = 0
            ornek = []
            for adr, ad in adlar.items():
                if adr not in sem:
                    continue
                ortak += 1
                ss = [x[1:] if x.startswith("_") else x for x in sem[adr]]
                if ad in ss:
                    ayni += 1
                elif any(x == ad + ".abi0" for x in ss):
                    ek_abi += 1
                elif any(x.replace(".", "") == ad.replace("·", "").replace(".", "") for x in ss):
                    orta_nokta += 1
                else:
                    farkli += 1
                    if len(ornek) < 5:
                        ornek.append((hex(adr), ad, ss[:2]))
            print(f"    nm kod sembolü {len(sem)} adres; pclntab girişiyle aynı adreste {ortak}:"
                  f" ad birebir {ayni}, .abi0 ekiyle {ek_abi}, nokta yazımıyla {orta_nokta}, farklı {farkli}")
            for o in ornek:
                print("      farklı örnek:", o)


if __name__ == "__main__":
    main()
