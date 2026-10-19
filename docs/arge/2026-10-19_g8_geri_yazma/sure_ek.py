"""G8 ek süre ölçümü (ön kayıt dışı, tanımlayıcı).

deney.py'de koşullar aynı süreçte C0 → C4 sırasıyla ölçüldü. İlk koşul (C0) JVM ve
decompiler ısınmasından etkilenmiş olabilir: tip yazılmayan C1 ve C2, C0'dan hızlı çıktı.
Bu betik kaydedilmiş koşul projelerini (projeler/C0, C1, C3, C4; değiştirmeden) iki blokta,
ters sıralarla açar: [C0, C1, C3, C4] ve [C4, C3, C1, C0]. Her açılışta önce bütün küme bir
kez ısınma için decompile edilir, sonra 3 ölçüm turu yapılır. Fonksiyon başına 6 ölçümün
medyanı alınır. Projeler kaydedilmez.

Çıktı: workspaces/2026-10-19_g8/veri/sure_ek.json
"""

from __future__ import annotations

import json
import statistics
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ortak  # noqa: E402

BLOKLAR = [["C0", "C1", "C3", "C4"], ["C4", "C3", "C1", "C0"]]
TUR = 3


def main() -> None:
    secim = json.loads((ortak.VERI / "secim.json").read_text())
    ogeler = [("hedef", h["adres"]) for h in secim["hedefler"]] + [("cagiran", c["adres"]) for c in secim["cagiranlar"]]
    ortak.jvm_baslat()
    olcum: dict[str, dict[str, list[float]]] = {}
    for blok in BLOKLAR:
        for k in blok:
            proje, program = ortak.proje_ac(ortak.PROJELER / k)
            try:
                fm = program.getFunctionManager()
                dec = ortak.Decompiler(program)
                fonk = [(rol, adr, fm.getFunctionAt(ortak.adres(program, adr))) for rol, adr in ogeler]
                for a in secim["isinma"]:
                    dec.c(fm.getFunctionAt(ortak.adres(program, a)))
                for _, _, f in fonk:
                    dec.c(f)
                for _ in range(TUR):
                    for rol, adr, f in fonk:
                        _, t, _ = dec.c(f)
                        olcum.setdefault(k, {}).setdefault(adr, []).append(t)
                dec.kapat()
            finally:
                proje.close()
    rol_of = {adr: rol for rol, adr in ogeler}
    ozet = {}
    for k, d in olcum.items():
        for rol in ("hedef", "cagiran"):
            med = [statistics.median(v) for a, v in d.items() if rol_of[a] == rol]
            ozet.setdefault(k, {})[rol] = {"fonksiyon_medyanlarinin_toplami_ms": round(1000 * sum(med), 1),
                                          "fonksiyon_medyanlarinin_medyani_ms": round(1000 * statistics.median(med), 2)}
    oranlar = {}
    for rol in ("hedef", "cagiran"):
        for k in ("C3", "C4"):
            for taban in ("C0", "C1"):
                oranlar[f"{rol}_{k}/{taban}_toplam"] = round(
                    ozet[k][rol]["fonksiyon_medyanlarinin_toplami_ms"] / ozet[taban][rol]["fonksiyon_medyanlarinin_toplami_ms"], 2)
    cikti = {"kunye": ortak.kunye(), "bloklar": BLOKLAR, "tur": TUR, "ozet": ozet, "oranlar": oranlar,
             "ham_ms": {k: {a: [round(1000 * x, 3) for x in v] for a, v in d.items()} for k, d in olcum.items()}}
    ortak.json_yaz(ortak.VERI / "sure_ek.json", cikti)
    print(json.dumps({"ozet": ozet, "oranlar": oranlar}, ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()
