#!/usr/bin/env python3
"""Yerleşim: saklı çalışma alanlarında kurulum denetimi (GT'siz; ölçüm değil).

Her çalışma alanında proje kurucu, saklı girdisiyle iki kez yeniden çalıştırılır (çıktı geçici
dizine; saklı koşu yalnız okunur):

- **Bayrak kapalı:** çıktı, saklı proje ağacıyla bayt bayt aynı mı (``yerlesim_urun_olc.girdiyi_bul``;
  ``analysis/algorithms.md`` dışında, ``compile_commands.json``'da yalnız kök yolu çevrilerek).
- **Bayrak açık:** hangi strateji uygulandı, eski yerleşime dönüldüyse nedeni, kaç grup çıktı, en büyük
  grup birimlerin ne kadarını taşıyor; kurucunun değişmez denetimi (eksik / çift fonksiyon) tuttu mu.

Hata ayıklama bilgisi ve kaynak dosya etiketi okunmaz; uyum ölçüsü hesaplanmaz; çıktıda ad yoktur.

Kullanım
--------
    python -m scripts.measurement.yerlesim_kurulum_denetle \\
        --kok debian13=~/karadul_olcum/runs/urun-yeni-93a2956 \\
        --json docs/arge/2026-11-12_yerlesim/kurulum_denetimi.json \\
        --md docs/arge/2026-11-12_yerlesim/kurulum_denetimi.md
"""
from __future__ import annotations

import argparse
import json
import sys
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any, Optional

REPO = Path(__file__).resolve().parents[2]
_BURASI = Path(__file__).resolve().parent
for _yol in (str(_BURASI), str(REPO)):
    if _yol not in sys.path:
        sys.path.insert(0, _yol)

import yerlesim_dolgu_say as dolgu  # noqa: E402
import yerlesim_urun_olc as urun  # noqa: E402

SEMA = "karadul-yerlesim-kurulum-denetimi/1"
ONDALIK = urun.ONDALIK
YERLESIM_RAPORU = Path("analysis") / "placement.json"


def alan_denetimi(kosu: Path) -> dict[str, Any]:
    """Bir çalışma alanı: bayrak kapalı eşitlik ve bayrak açık kurulumun özeti."""
    with tempfile.TemporaryDirectory(prefix="yerlesim_kurulum_") as gecici:
        girdi = urun.girdiyi_bul(kosu, Path(gecici))
        out: dict[str, Any] = {"girdi": girdi}
        # girdi bulunamadıysa (eski sürümün ağacı) son adayla yine de kurulur; eşitlik iddiası yoktur
        aday = girdi["kaynak"] or (girdi["denenen"][0] if girdi["denenen"] else None)
        if aday is None:
            return out
        proje = Path(gecici) / "acik" / urun.RECONSTRUCTED / urun.PROJE
        sonuc = urun.kur(Path(kosu) / urun.RECONSTRUCTED / aday, kosu, proje, acik=True)
        rapor = json.loads((proje / YERLESIM_RAPORU).read_text(encoding="utf-8"))
        gruplar = rapor.get("groups") or []
        birim = sum(g["units"] for g in gruplar)
        out["acik"] = {
            "girdi_dizini": aday, "basarili": bool(sonuc.success),
            "strateji": sonuc.placement_strategy, "geri_dusus": sonuc.placement_fallback_reason or None,
            "eksik": sonuc.functions_missing, "cift": sonuc.functions_duplicated, "hata": len(sonuc.errors),
            "birim": rapor.get("units"), "giris_birimi": rapor.get("entry_units"),
            "adressiz_birim": rapor.get("units_without_address"),
            "sinyal_dolgu": rapor.get("signal_gaps"), "dolgu_siniri": rapor.get("padding_cuts"),
            "blok_siniri": rapor.get("block_cuts"), "blok_bilgisi": rapor.get("memory_blocks_known"),
            "grup": len(gruplar),
            "en_buyuk_grup_payi": (round(max(g["units"] for g in gruplar) / birim, ONDALIK)
                                   if birim else None),
            "blok_gruplari": dict(sorted(Counter(str(g["memory_block"]) for g in gruplar).items())),
        }
        return out


def denetle(kokler: dict[str, Path]) -> dict[str, Any]:
    alanlar: dict[str, dict[str, Any]] = {}
    for etiket, kok in kokler.items():
        for anahtar, static in dolgu.calisma_alanlari(kok).items():
            alanlar[f"{etiket}/{anahtar}"] = alan_denetimi(static.parent)
    acik = [a["acik"] for a in alanlar.values() if "acik" in a]
    return {"sema": SEMA, "uyari": "GT'siz kurulum denetimi; uyum ölçüsü içermez",
            "kokler": {e: str(k) for e, k in kokler.items()},
            "ozet": {
                "alan": len(alanlar),
                "kapali_sakliyla_ayni": sum(1 for a in alanlar.values() if a["girdi"]["ayni"]),
                "kapali_farkli": sorted(k for k, a in alanlar.items() if not a["girdi"]["ayni"]),
                "acik_kurulan": len(acik),
                "acik_basarisiz": sum(1 for a in acik if not a["basarili"]),
                "eksik": sum(a["eksik"] for a in acik), "cift": sum(a["cift"] for a in acik),
                "strateji": dict(sorted(Counter(a["strateji"] for a in acik).items())),
                "geri_dusus": dict(sorted(Counter(str(a["geri_dusus"]) for a in acik).items())),
                "adressiz_birim": sum(a["adressiz_birim"] or 0 for a in acik),
            },
            "alanlar": alanlar}


def markdown(s: dict[str, Any]) -> str:
    o = s["ozet"]
    satirlar = ["# Yerleşim: kurulum denetimi (GT'siz)", "",
                "- Kökler: " + "; ".join(f"`{e}` = `{k}`" for e, k in s["kokler"].items()) + ".",
                f"- Çalışma alanı: {o['alan']}. Bayrak KAPALI kurulumu saklı proje ağacıyla bayt bayt aynı: "
                f"{o['kapali_sakliyla_ayni']}"
                + (" (farklı: " + ", ".join(f"`{k}`" for k in o["kapali_farkli"]) + ")"
                   if o["kapali_farkli"] else "") + ".",
                f"- Bayrak AÇIK kurulum: {o['acik_kurulan']} alan; başarısız {o['acik_basarisiz']}; eksik "
                f"fonksiyon {o['eksik']}, çift fonksiyon {o['cift']}; adressiz birim {o['adressiz_birim']}; "
                "strateji " + ", ".join(f"`{a}` {n}" for a, n in o["strateji"].items())
                + "; geri düşüş " + ", ".join(f"`{a}` {n}" for a, n in o["geri_dusus"].items()) + ".", "",
                "| Çalışma alanı | Kapalı = saklı | Strateji (açık) | Geri düşüş | Birim | Grup | "
                "Sinyal dolgusu | Dolgu sınırı | Blok sınırı | En büyük grubun payı |",
                "|---|---|---|---|---|---|---|---|---|---|"]
    for anahtar, a in s["alanlar"].items():
        ac = a.get("acik")
        if ac is None:
            satirlar.append(f"| `{anahtar}` | {'evet' if a['girdi']['ayni'] else 'HAYIR'} | girdi yok | | | | | | | |")
            continue
        pay = "—" if ac["en_buyuk_grup_payi"] is None else f"{ac['en_buyuk_grup_payi']:.3f}".replace(".", ",")
        satirlar.append(
            f"| `{anahtar}` | {'evet' if a['girdi']['ayni'] else 'HAYIR'} | `{ac['strateji']}` | "
            f"{ac['geri_dusus'] or '—'} | {ac['birim']} | {ac['grup']} | {ac['sinyal_dolgu']} | "
            f"{ac['dolgu_siniri']} | {ac['blok_siniri']} | {pay} |")
    return "\n".join(satirlar) + "\n"


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--kok", action="append", required=True, metavar="ETİKET=YOL",
                    help="çalışma alanlarının kökü (yinelenebilir); yalnız okunur")
    ap.add_argument("--json", type=Path, required=True)
    ap.add_argument("--md", type=Path, default=None)
    a = ap.parse_args(argv)
    kokler: dict[str, Path] = {}
    for girdi in a.kok:
        etiket, ayrac, yol = girdi.partition("=")
        if not ayrac or not etiket or not yol:
            ap.error(f"--kok ETİKET=YOL biçiminde olmalı: {girdi}")
        kok = Path(yol).expanduser()
        if not kok.is_dir():
            print(f"DURDU: {kok}: dizin yok", file=sys.stderr)
            return 2
        kokler[etiket] = kok
    sonuc = denetle(kokler)
    a.json.parent.mkdir(parents=True, exist_ok=True)
    a.json.write_text(json.dumps(sonuc, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    if a.md:
        a.md.write_text(markdown(sonuc), encoding="utf-8")
    o = sonuc["ozet"]
    print(f"kurulum denetimi: {o['alan']} alan; kapalı = saklı {o['kapali_sakliyla_ayni']}; açık kurulum "
          f"başarısız {o['acik_basarisiz']}; geri düşüş {o['geri_dusus']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
