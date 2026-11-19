#!/usr/bin/env python3
"""HIZ kalem 2: paralel decompile'da statik parçalamanın yük dengesizliği (var olan dosyalardan).

``headless.py:1211-1264``: fonksiyonlar adres sırasıyla listelenir, ``chunk_size = n // n_threads``
ardışık parçaya bölünür, her parça bir iş parçacığında baştan sona koşar. Her fonksiyonun
``.c`` dosyası decompile bitince yazılır (``:1497-1502``); başlıktaki ``// Address:`` satırı
fonksiyonu adrese bağlar. Böylece parça başına bitiş zamanı dosya zamanından okunur.

Ölçü: parça süresi = parçanın son ``.c`` zamanı − decompile başlangıcı (``call_graph.json``
değişme zamanı; decompile ondan hemen sonra başlar, ``headless.py:379-409``).
  adım süresi ≈ en uzun parça; ideal (kusursuz dağıtım) ≈ parça süreleri toplamı / iş parçacığı.
  dengesizlik oranı = en uzun / ideal  (yalnız sıralama kaynaklı kaybın ÜST sınırı; iş
  parçacıkları aynı anda koşmadıysa — yük — oran şişer).

Kullanım:
    python scripts/arge/hiz/decompile_dengesi.py --is-parcacigi 10 <ad>=<static/ghidra_output dizini> ...
"""

from __future__ import annotations

import argparse
import json
import os
import re
import statistics
from pathlib import Path

_ADRES = re.compile(r"^// Address:\s*(\S+)", re.M)


def _adres_anahtari(a: str) -> tuple[str, int]:
    alan, _, ofs = a.rpartition(":")
    try:
        return alan, int(ofs, 16)
    except ValueError:
        return alan, -1


def olc(go: Path, n_threads: int) -> dict:
    d = go / "decompiled"
    bas = (go / "call_graph.json").stat().st_mtime
    kay = []
    for e in os.scandir(d):
        if not e.name.endswith(".c"):
            continue
        with open(e.path, encoding="utf-8", errors="replace") as fh:
            bas_satir = fh.read(400)
        m = _ADRES.search(bas_satir)
        if not m:
            continue
        kay.append((_adres_anahtari(m.group(1)), e.stat().st_mtime, e.stat().st_size))
    durum = json.loads((go.parent / "ghidra_status.json").read_text()) if (go.parent / "ghidra_status.json").exists() else {}
    n_tum = (durum.get("decompile") or {}).get("total_attempted") or len(kay)
    kay.sort()
    chunk = max(1, n_tum // n_threads)
    parcalar: dict[int, list[tuple[float, int]]] = {}
    # Başarısız fonksiyonların .c'si yok; konum yaklaşık (en çok başarısız sayısı kadar kayma).
    for i, (_, t, sz) in enumerate(kay):
        parcalar.setdefault(i // chunk, []).append((t, sz))
    sure = {k: max(t for t, _ in v) - bas for k, v in parcalar.items()}
    bayt = {k: sum(s for _, s in v) for k, v in parcalar.items()}
    toplam = sum(sure.values())
    ideal = toplam / n_threads
    en_uzun = max(sure.values())
    return {"fonksiyon_c": len(kay), "fonksiyon_tum": n_tum, "parca_boyu": chunk, "parca_sayisi": len(parcalar),
            "adim_sn": en_uzun, "ideal_sn": ideal, "dengesizlik": en_uzun / ideal if ideal else None,
            "parca_sn": [round(sure[k], 1) for k in sorted(sure)],
            "parca_mb": [round(bayt[k] / 1e6, 2) for k in sorted(bayt)],
            "ortanca_parca_sn": statistics.median(sure.values())}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--is-parcacigi", type=int, required=True,
                    help="koşunun CPU_PERF_CORES değeri (ölçüm makinesinde 10)")
    ap.add_argument("--cikti", type=Path)
    ap.add_argument("girdiler", nargs="+")
    a = ap.parse_args()
    out = {}
    print("| İkili | fn | parça | adım (en uzun parça) sn | ideal sn | dengesizlik | parça süreleri (sn) |")
    print("|---|---|---|---|---|---|---|")
    for g in a.girdiler:
        ad, yol = g.split("=", 1)
        r = olc(Path(os.path.expanduser(yol)), a.is_parcacigi)
        out[ad] = r
        print("| %s | %d | %d × %d | %.1f | %.1f | %.2f | %s |" % (
            ad, r["fonksiyon_tum"], r["parca_sayisi"], r["parca_boyu"], r["adim_sn"], r["ideal_sn"],
            r["dengesizlik"], ", ".join("%.0f" % x for x in r["parca_sn"])))
    if a.cikti:
        c = a.cikti.expanduser()
        c.parent.mkdir(parents=True, exist_ok=True)
        c.write_text(json.dumps(out, indent=1, ensure_ascii=False))


if __name__ == "__main__":
    main()
