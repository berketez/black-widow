"""Bu koşunun (2026-11-11) sunucu günlüğünden önek ve üretim hızı; tasarım Ek A'nın yöntemiyle.

Ek A ile tek fark: `llama_server.log` yalnız bu koşunun eklediği satırlardan (`--bas` satırından sonrası)
okunur, ilerleme kaydı da yalnız bu koşunun satırlarından (`--ilerleme-bas`). Model çalıştırılmaz.

Kullanım (depo kökünde):
  python3 -I docs/arge/2026-11-11_karadullm/zemin/hiz_ozeti.py --bas 1282 --ilerleme-bas 111 \
      --bekci docs/arge/2026-11-11_karadullm/zemin/bekci_kapilar.json --cikti docs/arge/2026-11-11_karadullm/zemin/hiz_kapilar.json
"""
from __future__ import annotations

import argparse
import json
import re
import statistics
from pathlib import Path

K = Path("workspaces/2026-10-19_g6_pilot")


def hiz(pe, ev):
    return {"cagri": len(pe), "istem_jetonu": sum(n for _, n in pe), "uretilen_jeton": sum(n for _, n in ev),
            "onek_jeton_sn": round(1000 * sum(n for _, n in pe) / sum(t for t, _ in pe), 1) if pe else None,
            "uretim_jeton_sn": round(1000 * sum(n for _, n in ev) / sum(t for t, _ in ev), 1) if ev else None}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--bas", type=int, required=True, help="günlükte bu koşudan önceki satır sayısı")
    ap.add_argument("--ilerleme-bas", type=int, required=True, help="ilerleme.jsonl'de önceki satır sayısı")
    ap.add_argument("--bekci", type=Path, required=True)
    ap.add_argument("--cikti", type=Path, required=True)
    ns = ap.parse_args()
    satirlar = (K / "llama_server.log").read_text(errors="replace").splitlines()[ns.bas:]
    pe, ev, keep = [], [], 0
    for l in satirlar:
        m = re.search(r"prompt eval time =\s*([\d.]+) ms /\s*(\d+) tokens", l)
        if m:
            pe.append((float(m[1]), int(m[2])))
            continue
        m = re.search(r"\beval time =\s*([\d.]+) ms /\s*(\d+) tokens", l)
        if m:
            ev.append((float(m[1]), int(m[2])))
        keep += "f_keep" in l
    rows = [json.loads(l) for l in (K / "ilerleme.jsonl").read_text().splitlines()[ns.ilerleme_bas:] if l.strip()]
    out = {"gunluk_satir_bas": ns.bas, "ilerleme_satir_bas": ns.ilerleme_bas, "toplam": hiz(pe, ev),
           "ilerleme_girdi_jetonu": sum(r["girdi_jeton"] or 0 for r in rows), "ilerleme_satiri": len(rows),
           "ortak_onek_bulunan_cagri": keep, "kume_kosul": {}}
    # Günlükteki çağrılar ilerleme satırlarıyla aynı sıradadır (tek yuva, sıralı çağrı); jeton sayısı eşleşmesiyle denetlenir.
    eslesme = len(rows) == len(pe) and all(r["girdi_jeton"] == n for r, (_, n) in zip(rows, pe))
    out["siralama_eslesmesi"] = eslesme
    if eslesme:
        gruplar: dict[str, tuple[list, list]] = {}
        for r, a, b in zip(rows, pe, ev):
            g = gruplar.setdefault(f'{r["kume"]}/{r["kosul"]}', ([], []))
            g[0].append(a)
            g[1].append(b)
        out["kume_kosul"] = {k: hiz(*v) for k, v in gruplar.items()}
        out["cagri_basina"] = [{"kume": r["kume"], "kosul": r["kosul"], "istem": a[1],
                                "onek_jeton_sn": round(1000 * a[1] / a[0], 1), "uretilen": b[1],
                                "uretim_jeton_sn": round(1000 * b[1] / b[0], 1) if b[0] else None,
                                "sure_sn": r["sure_sn"]} for r, a, b in zip(rows, pe, ev)]
    bek = json.loads(ns.bekci.read_text())
    yuk1 = [y[1] for y in bek["yuk"]]
    out["yuk_ortalamasi_1dk"] = {"ornek": len(yuk1), "ortalama": round(statistics.mean(yuk1), 2),
                                 "en_az": min(yuk1), "en_cok": max(yuk1), "ilk_zaman": bek["yuk"][0][0],
                                 "son_zaman": bek["yuk"][-1][0]}
    out["bekci_tepe"] = bek["tepe"]
    out["bekci_olaylar"] = bek["olaylar"]
    ns.cikti.write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding="utf-8")
    print(json.dumps({k: out[k] for k in ("toplam", "kume_kosul", "yuk_ortalamasi_1dk", "bekci_tepe",
                                          "siralama_eslesmesi", "ilerleme_girdi_jetonu")}, ensure_ascii=False, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
