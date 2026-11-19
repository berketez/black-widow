#!/usr/bin/env python3
"""HIZ kalem 3 ek: bir cProfile dosyasında verilen işlevlerin çağıranları ve ilk N tablo.

Kullanım:
    python scripts/arge/hiz/profil_cagiranlar.py --prof <C_yeniden_kurma.prof> \
        --islev "_io.open" --islev "re/__init__.py:280" --n 12
    python scripts/arge/hiz/profil_cagiranlar.py --prof <...> --ilk 20     # öz süreye göre ilk 20
    python scripts/arge/hiz/profil_cagiranlar.py --prof <...> --karadul 25 # karadul/ işlevleri, kümülatif
"""

from __future__ import annotations

import argparse
import pstats


def _ad(k) -> str:
    fn, line, name = k
    fn = fn.split("/Black_Widow/", 1)[-1]
    fn = fn.split("/lib/python3.12/", 1)[-1]
    return "%s:%d(%s)" % (fn, line, name)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--prof", required=True)
    ap.add_argument("--islev", action="append", default=[])
    ap.add_argument("--n", type=int, default=10)
    ap.add_argument("--ilk", type=int, default=0)
    ap.add_argument("--karadul", type=int, default=0)
    a = ap.parse_args()
    st = pstats.Stats(a.prof)
    toplam = st.total_tt
    print("toplam: %.1f sn" % toplam)
    if a.ilk:
        rows = sorted(st.stats.items(), key=lambda kv: -kv[1][2])[: a.ilk]
        print("\n| # | işlev | çağrı | öz sn | öz pay | kümülatif sn |")
        print("|---|---|---|---|---|---|")
        for i, (k, (cc, nc, tt, ct, _)) in enumerate(rows, 1):
            print("| %d | `%s` | %d | %.1f | %.1f %% | %.1f |" % (i, _ad(k), nc, tt, 100 * tt / toplam, ct))
    if a.karadul:
        rows = [(k, v) for k, v in st.stats.items() if "/karadul/" in k[0]]
        rows.sort(key=lambda kv: -kv[1][3])
        print("\n| # | karadul işlevi | çağrı | öz sn | kümülatif sn | kümülatif pay |")
        print("|---|---|---|---|---|---|")
        for i, (k, (cc, nc, tt, ct, _)) in enumerate(rows[: a.karadul], 1):
            print("| %d | `%s` | %d | %.1f | %.1f | %.1f %% |" % (i, _ad(k), nc, tt, ct, 100 * ct / toplam))
    for hedef in a.islev:
        for k, (cc, nc, tt, ct, callers) in st.stats.items():
            if hedef in _ad(k) or hedef == k[2]:
                print("\n## %s: çağrı %d, öz %.1f sn, kümülatif %.1f sn" % (_ad(k), nc, tt, ct))
                cl = sorted(callers.items(), key=lambda kv: -kv[1][3])[: a.n]
                print("| çağıran | çağrı | kümülatif sn (bu çağırandan) |")
                print("|---|---|---|")
                for ck, cv in cl:
                    print("| `%s` | %d | %.1f |" % (_ad(ck), cv[1], cv[3]))


if __name__ == "__main__":
    main()
