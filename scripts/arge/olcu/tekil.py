#!/usr/bin/env python3
"""ÖLÇÜ hattı: örnek / tekil ayrımı — ikiz yoğunluğu ve taban yeniden puanlaması tekil kaynak fonksiyonunda.

Ad bekleyen 21 371 fonksiyonun 11 393'ü coreutils'in 106 ikilisindeki gnulib kopyasıdır (OLGU bütçesi);
havuz sayıları bu yinelemeyle ağırlıklıdır. Bu betik §3 (ikiz) ve §4 (yeniden puanlama) sayılarını OLGU
tablosunun tekil anahtarıyla yeniden sayar: (birim programı, tanım dosyası, GT'nin ilk adı); Mac'te tanım
dosyası yok, anahtar program + GT adı (``scripts/arge/olgu/olgu_butce.py`` ile aynı kural).
Tekil fonksiyonun ikizi var: örneklerinden en az birinde var. Tekil adın bölgesi: (program, ürün adı, GT adı).

Kullanım:
    PYTHONDONTWRITEBYTECODE=1 python scripts/arge/olcu/tekil.py \
        --olgu ~/karadul_olcum/runs/arge-2026-11-19/olgu/olgu.jsonl.gz \
        --taban ~/karadul_olcum/runs/arge-2026-11-19/olcu/taban_a62f15e.json \
        --json ~/karadul_olcum/runs/arge-2026-11-19/olcu/tekil.json
"""
from __future__ import annotations

import argparse
import gzip
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

BURASI = Path(__file__).resolve().parent
sys.path.insert(0, str(BURASI))
sys.path.insert(0, str(BURASI.parents[2] / "scripts" / "measurement"))

import ks1_olc  # noqa: E402
import kimlik as kimlik_modulu  # noqa: E402
import olcu  # noqa: E402
import taban_puanla  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--olgu", type=Path, required=True)
    ap.add_argument("--taban", type=Path, required=True)
    ap.add_argument("--json", type=Path, required=True)
    a = ap.parse_args()
    taban = json.loads(a.taban.read_text(encoding="utf-8"))["ikililer"]
    # ikili başına ikiz bayrakları (örnek düzeyi), adres → {esik: bool}
    ikiz_bayrak: dict[str, dict[str, dict]] = {}
    for anahtar, ik in taban.items():
        gt, bayraklar = ik["gt"], {}
        for adres in ik["nufus_adresleri"]:
            c = taban_puanla.ikiz({**gt}, [adres])
            bayraklar[adres] = {k: bool(v) for k, v in c.items() if k != "nufus"}
        ikiz_bayrak[anahtar] = bayraklar
    tekil_ikiz: dict[tuple, dict[str, bool]] = {}
    sinif_tekil: dict[str, set] = defaultdict(set)
    ornek = Counter()
    ad_bolge: dict[tuple, str] = {}
    ad_kanal: dict[tuple, str] = {}
    gt_onbellek: dict[str, kimlik_modulu.IkiliGt] = {}
    with gzip.open(a.olgu, "rt", encoding="utf-8") as f:
        for satir in f:
            s = json.loads(satir)
            anahtar = f"{s['birim']}::{s['ikili']}"
            if s["nufusta"]:
                tk = (s["program"], s.get("dw_tanim_dosyasi"), s["gt_adlari"][0])
                b = ikiz_bayrak[anahtar][s["adres_hex"]]
                ornek["nufus"] += 1
                hedef = tekil_ikiz.setdefault(tk, {})
                for k, v in b.items():
                    ornek[k] += v
                    hedef[k] = hedef.get(k, False) or v
                sinif_tekil[s["kaynak_sinifi"]].add(tk)
            if s["urun_olcude"]:
                ik = taban[anahtar]
                if anahtar not in gt_onbellek:
                    gt_onbellek[anahtar] = kimlik_modulu.IkiliGt(ik["gt"])
                k = next(x for x in ik["adlar"] if x["adres"] == s["adres_hex"])
                bolge = taban_puanla.bolgeler(k, gt_onbellek[anahtar])["bolge"]
                ak = (s["program"], s["urun_adi"], (s["gt_adlari"] or [None])[0])
                ad_bolge[ak] = bolge
                ad_kanal[ak] = s["kanal"]
                ornek[f"ad:{bolge}"] += 1
    n_tekil = len(tekil_ikiz)
    ikiz_tekil = Counter()
    for d in tekil_ikiz.values():
        for k, v in d.items():
            ikiz_tekil[k] += v
    gnulib_disi = [tk for sinif, kume in sinif_tekil.items() if sinif != "gnulib" for tk in kume]
    ikiz_gd = Counter()
    for tk in gnulib_disi:
        for k, v in tekil_ikiz[tk].items():
            ikiz_gd[k] += v
    bolge_tekil = Counter(ad_bolge.values())
    kanal_bolge: dict[str, Counter] = defaultdict(Counter)
    for ak, b in ad_bolge.items():
        kanal_bolge[ad_kanal[ak]][b] += 1
    n_ad = len(ad_bolge)
    sonuc = {
        "sema": "karadul-arge-olcu-tekil/1",
        "nufus": {"ornek": ornek["nufus"], "tekil": n_tekil, "tekil_gnulib_disi": len(gnulib_disi)},
        "ikiz_ornek": {k: ks1_olc.oran(ornek[k], ornek["nufus"]) for k in sorted(ikiz_tekil)},
        "ikiz_tekil": {k: ks1_olc.oran(v, n_tekil) for k, v in sorted(ikiz_tekil.items())},
        "ikiz_tekil_gnulib_disi": {k: ks1_olc.oran(v, len(gnulib_disi)) for k, v in sorted(ikiz_gd.items())},
        "ad_ornek": {k[3:]: v for k, v in sorted(ornek.items()) if k.startswith("ad:")},
        "ad_tekil": {"n": n_ad, **dict(sorted(bolge_tekil.items()))},
        "ad_tekil_kanal": {k: dict(sorted(c.items())) for k, c in sorted(kanal_bolge.items())},
        "yanlis_tekil": {"tam": ks1_olc.oran(n_ad - bolge_tekil["tam"], n_ad),
                         "tam+bicim": ks1_olc.oran(n_ad - bolge_tekil["tam"] - bolge_tekil["bicim"], n_ad)}}
    a.json.write_text(json.dumps(sonuc, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    print(json.dumps(sonuc, ensure_ascii=False, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
