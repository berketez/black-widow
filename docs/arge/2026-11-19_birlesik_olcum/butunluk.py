#!/usr/bin/env python3
"""Birleşik ölçümün GT'siz bütünlük denetimi (ön kayıt §2, B1–B8). GT ve ad haritası okunmaz.

Bir ``urun_kos.py`` koşu kökünü (``<kök>/debian/<program>/<ikili>``, ``<kök>/mac/<ikili>``) taban
kolun kökü ile karşılaştırır:

- B1 eksiksizlik: ikili sayısı, ``BITTI`` var mı ve içeriği (``0`` tam, ``3`` kısmi; P15a'dan beri
  ``urun_kos`` kısmi koşuya da ``BITTI`` yazar), künyedeki ``sonuclar`` / ``bitmeyen``.
- B2 ağaç: künyede commit, kirli dosya yok, ``karadul`` ağaçtan yükleniyor, sürüm, koşu boyunca
  ağaç değişmedi, ``PYTHONHASHSEED``.
- B3 girdi: her ikilinin ``raw/target_info.json`` ``file_hash``'i taban kolunkiyle aynı.
- B4 imza VT: rapordaki ``sigdb_*`` künyesi (şema, ad sayısı, build_id, yol kaynağı, uyarı yok).
- B5 Ghidra: rapordaki sürüm ve sabitlenen sürümle eşleşme.
- B8 geçersiz kılma deposu (``~/.karadul/overrides``) boş mu (denetim anı).

Kullanım:
    python3 butunluk.py --kok <yeni kök> --taban-kok <taban kök> --commit <tam sha> \
        --surum 1.24.1 --json <çıktı>
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any

BEKLENEN_IKILI = 119
SIGDB_BEKLENEN = {"sigdb_schema_version": "2", "sigdb_lmdb_symbol_count": 9092473,
                  "sigdb_build_id": "s2-b32ee9f65b1a-20261118",
                  "sigdb_path_source": "data_root:signatures.lmdb",
                  "sigdb_schema_warning": None, "sigdb_lmdb_error": None}
GHIDRA_SURUMU = "12.1.2"


def _json(yol: Path) -> Any:
    return json.loads(yol.read_text(encoding="utf-8"))


def isler(kok: Path) -> dict[str, Path]:
    out = {}
    for prog in sorted(p for p in (kok / "debian").iterdir() if p.is_dir()):
        for d in sorted(p for p in prog.iterdir() if p.is_dir()):
            out[f"debian/{prog.name}/{d.name}"] = d
    for d in sorted(p for p in (kok / "mac").iterdir() if p.is_dir()):
        out[f"mac/{d.name}"] = d
    return out


def calisma_alani(d: Path) -> Path | None:
    adaylar = sorted(p for p in (d / "ws" / "workspaces").glob("*/*") if (p / "static").is_dir())
    return adaylar[0] if len(adaylar) == 1 else None


def topla_anahtar(o: Any, onek: str, out: dict[str, list]) -> None:
    if isinstance(o, dict):
        for k, v in o.items():
            if k.startswith(onek):
                out.setdefault(k, []).append(v)
            topla_anahtar(v, onek, out)
    elif isinstance(o, list):
        for v in o:
            topla_anahtar(v, onek, out)


def ikili_denetle(d: Path, taban_d: Path | None) -> dict[str, Any]:
    s: dict[str, Any] = {}
    bitti = d / "BITTI"
    s["bitti"] = bitti.read_text(encoding="utf-8").strip() if bitti.is_file() else None
    ca = calisma_alani(d)
    s["calisma_alani"] = ca is not None
    if ca is None:
        return s
    hedef = ca / "raw" / "target_info.json"
    s["file_hash"] = _json(hedef).get("file_hash") if hedef.is_file() else None
    if taban_d is not None:
        tca = calisma_alani(taban_d)
        th = tca / "raw" / "target_info.json" if tca else None
        s["taban_file_hash"] = _json(th).get("file_hash") if th and th.is_file() else None
    rapor = ca / "reports" / "report.json"
    if rapor.is_file():
        r = _json(rapor)
        g = (r.get("environment") or {}).get("ghidra") or {}
        s["ghidra"] = [g.get("version"), g.get("matches_pinned")]
        bulunan: dict[str, list] = {}
        topla_anahtar(r, "sigdb_", bulunan)
        s["sigdb"] = {k: (bulunan[k][0] if k in bulunan else "YOK") for k in SIGDB_BEKLENEN}
        s["sigdb_tutarsiz_tekrar"] = sorted(k for k in SIGDB_BEKLENEN
                                            if k in bulunan and len({json.dumps(v) for v in bulunan[k]}) > 1)
    else:
        s["ghidra"] = None
        s["sigdb"] = None
    return s


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--kok", type=Path, required=True)
    ap.add_argument("--taban-kok", type=Path, required=True)
    ap.add_argument("--commit", required=True, help="beklenen tam commit")
    ap.add_argument("--surum", required=True, help="beklenen karadul sürümü")
    ap.add_argument("--json", type=Path, required=True)
    a = ap.parse_args()
    kok, taban = a.kok.expanduser(), a.taban_kok.expanduser()

    kunye = _json(kok / "kosu_kunyesi.json")
    ag = kunye.get("agac") or {}
    agac = str(ag.get("agac") or "")
    b2 = {"commit": ag.get("commit") == a.commit, "kirli_yok": ag.get("kirli") == [],
          "karadul_agactan": str(ag.get("karadul_dosyasi") or "").startswith(agac + "/"),
          "surum": ag.get("karadul_surumu") == a.surum,
          "agac_degismedi": kunye.get("agac_degisti") is False,
          "PYTHONHASHSEED": kunye.get("PYTHONHASHSEED"),
          "bitis_var": "bitis" in kunye,
          "tabandaki_is": kunye.get("tabandaki_is"), "secilen_is": kunye.get("secilen_is")}
    sonuc_durum = Counter(s.get("durum") for s in kunye.get("sonuclar") or [])
    bitmeyen = [s.get("anahtar") + ":" + str(s.get("durum")) for s in kunye.get("bitmeyen") or []]

    yeni_isler, taban_isler = isler(kok), isler(taban)
    satirlar = {k: ikili_denetle(d, taban_isler.get(k)) for k, d in yeni_isler.items()}
    bitti = Counter(str(s["bitti"]) for s in satirlar.values())
    b3_farkli = sorted(k for k, s in satirlar.items()
                       if s.get("file_hash") is None or s.get("file_hash") != s.get("taban_file_hash"))
    b4_farkli = sorted(k for k, s in satirlar.items()
                       if s.get("sigdb") is None or any(s["sigdb"].get(x) != v for x, v in SIGDB_BEKLENEN.items())
                       or s.get("sigdb_tutarsiz_tekrar"))
    b5_farkli = sorted(k for k, s in satirlar.items() if s.get("ghidra") != [GHIDRA_SURUMU, True])
    overrides = Path.home() / ".karadul" / "overrides"
    b8 = sorted(p.name for p in overrides.iterdir()) if overrides.is_dir() else []

    belge = {
        "kok": str(kok), "taban_kok": str(taban),
        "B1": {"ikili": len(yeni_isler), "beklenen": BEKLENEN_IKILI,
               "taban_ikili": len(taban_isler), "anahtarlar_ayni": sorted(yeni_isler) == sorted(taban_isler),
               "bitti_icerik": dict(sorted(bitti.items())),
               "kismi": sorted(k for k, s in satirlar.items() if s["bitti"] == "3"),
               "bittisiz": sorted(k for k, s in satirlar.items() if s["bitti"] is None),
               "kunye_sonuc_durumu": dict(sorted((str(k), v) for k, v in sonuc_durum.items())),
               "kunye_bitmeyen": bitmeyen},
        "B2": b2,
        "B3": {"girdi_ozeti_farkli": b3_farkli},
        "B4": {"beklenen": SIGDB_BEKLENEN, "farkli": b4_farkli,
               "ornek": next((s.get("sigdb") for s in satirlar.values()), None)},
        "B5": {"farkli": b5_farkli},
        "B8": {"overrides_dosyalari": b8},
        "ikililer": satirlar,
    }
    gecti = (belge["B1"]["ikili"] == BEKLENEN_IKILI and belge["B1"]["anahtarlar_ayni"]
             and bitti.get("0", 0) == BEKLENEN_IKILI and all(v is True for k, v in b2.items()
                                                             if k in ("commit", "kirli_yok", "karadul_agactan",
                                                                      "surum", "agac_degismedi", "bitis_var"))
             and b2["PYTHONHASHSEED"] == "0" and not b3_farkli and not b4_farkli and not b5_farkli and not b8)
    belge["hepsi_tuttu"] = gecti
    a.json.write_text(json.dumps(belge, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    print(json.dumps({k: v for k, v in belge.items() if k != "ikililer"}, ensure_ascii=False, indent=1)[:4000])
    return 0 if gecti else 1


if __name__ == "__main__":
    raise SystemExit(main())
