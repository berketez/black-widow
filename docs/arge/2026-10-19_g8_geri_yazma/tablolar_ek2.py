"""rapor.md §11 tabloları: sonuc_ek2.json + önceki ölçümlerden (Türkçe ondalık virgülü).

Her hücre: havuzlanmış oranın göreli değişimi / fonksiyon başına ortalama göreli değişim.
A'da taban 0: havuz oranı önce → sonra / fonksiyon başına ortalama oran (sonra).
Kullanım: python3 -I -B tablolar_ek2.py > workspaces/2026-10-19_g8/veri/rapor_tablolari_ek2.md
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ozet  # noqa: E402
import ozet_ek  # noqa: E402
import ozet_ek2  # noqa: E402
from tablolar import s  # noqa: E402

SATIRLAR = [("C2", "C0", "C2 ad + prototip, opak yapı"), ("K2", "C0", "K2 ad + prototip, `void *`"),
            ("K4", "C0", "**K4 yalnız ad, Ghidra tipleri**"), ("C3", "C0", "C3 ad + prototip + yapı"),
            ("K4p", "C0", "**K4' yalnız ad + bilinen yerleşimde tip**"),
            ("K4", "C2", "K4 ↔ C2"), ("K4", "K2", "K4 ↔ K2"), ("K4p", "C3", "K4' ↔ C3")]
BIR = [a for a, _, _ in ozet.BIRINCIL]


def hucre(v: dict, fo: dict, a: str) -> str:
    if a == "ok_erisim_100" and v["havuz_once"] == 0:
        t = f"{s(v['havuz_once'])} → {s(v['havuz_sonra'])} / ort. {s(fo['sonra_ortalama_oran'])}"
    else:
        g = v["havuz_goreli_degisim"]
        gh = "—" if isinstance(g, str) else s(100 * g, 1, True) + "%"
        fg = fo["ortalama_goreli"]
        gf = "—" if fg is None else s(100 * fg, 0, True) + "%"
        t = f"{gh} / {gf}"
    return f"**{t}**" if v["anlamli_kazanc"] else t


def main() -> None:
    O = {k: ozet_ek.yukle(k) for k in ("C0", "C2", "C3", "K2", "K4", "K4p")}
    for rol, baslik in (("hedef", "20 hedef"), ("cagiran", "49 doğrudan çağıran")):
        print(f"\n**{baslik}: havuz göreli değişim / fonksiyon başına ortalama göreli değişim** "
              f"(anlamlı kazanç kalın; A: havuz önce → sonra / fonksiyon başına ortalama oran)\n")
        print("| Karşılaştırma | U | P1 | C | A | D | Anlamlı (5'te) |")
        print("|---|---|---|---|---|---|---|")
        for sonra, once, ad in SATIRLAR:
            ciftler = ozet.esle(O[once]["fonksiyonlar"], O[sonra]["fonksiyonlar"], rol)
            hs = []
            n = 0
            for a, sayi, yon in ozet.BIRINCIL:
                v = ozet.olcut_ozeti(ciftler, a, sayi, yon, True)
                n += v["anlamli_kazanc"]
                hs.append(hucre(v, ozet_ek2.fonksiyon_ortalamasi(ciftler, a), a))
            etiket = ad if once == "C0" else ad
            print(f"| {etiket}{' ↔ C0' if once == 'C0' else ''} | " + " | ".join(hs) + f" | {n} |")


if __name__ == "__main__":
    main()
