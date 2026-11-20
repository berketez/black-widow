"""P-ÜV9 kalem 1 — Ghidra ↔ üst veri (gösteri koşusunun çalışma alanından; salt okur).

Sorular (ön kayıt `docs/arge/2026-11-19_mythos/ustveri/olcum/on_kayit_HEDEF.md` §5, G1–G5):
  G1  Ghidra'nın fonksiyonları ↔ `LC_FUNCTION_STARTS`.
  G2  `pclntab`'ın adlı girişlerinde Ghidra'nın durumu: fonksiyon yok / jenerik adlı (kanal yazabilir) / adlı.
  G3  Ghidra'nın Go girişlerine verdiği jenerik olmayan ad sayısı (Go 1.26 "Untested Go version" sonrası).
  G4  ObjC yöntemlerinde aynı kırılım.
  G5  Ghidra'nın jenerik olmayan adları ∩ üst veri adresleri; o kesişimde ad eşitliği
      (`scripts/measurement/ustveri_olc.py` kalem 2 kuralları).

Üst veri, araştırma okuyucularıyla aynı dilimden okunur (çalışma alanının `raw/` kopyası). Ghidra
koşulmaz; hiçbir hedef ikili çalıştırılmaz. Çıktı yalnız sayı (ad listesi yazılmaz).

Kullanım (depo kökünden):
    PYTHONDONTWRITEBYTECODE=1 python scripts/arge/ustveri/acik_ghidra_ustveri.py \
        --ws ~/karadul_olcum/runs/gosteri-2026-11-19/ollama/ws/workspaces/Ollama/20261119_081103 \
        --ikili-adi Ollama_arm64 --cikti <json>
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

DEPO = Path(__file__).resolve().parents[3]
for _y in (str(DEPO / "scripts" / "measurement"), str(Path(__file__).resolve().parent), str(DEPO)):
    if _y not in sys.path:
        sys.path.insert(0, _y)

import function_f1 as f1  # noqa: E402
import macho  # noqa: E402
import ustveri_olc as uo  # noqa: E402

DURUM_YOK = "ghidra_fonksiyonu_yok"
DURUM_THUNK = "ghidra_thunk"
DURUM_JENERIK = "ghidra_jenerik"     # kanal buraya ad yazabilir (P13b kuralı: yalnız adsız fonksiyona)
DURUM_ADLI = "ghidra_adli"


def ghidra_oku(static: Path) -> tuple[dict[int, dict], int]:
    """Ghidra fonksiyonları (adres → kayıt; `source` dahil) ve görüntü tabanı."""
    ham = json.loads((static / "ghidra_functions.json").read_text(encoding="utf-8"))
    kaynak = {int(str(f["address"]), 16): f.get("source") for f in ham.get("functions", []) if f.get("address")}
    gf = {g["addr"]: {**g, "source": kaynak.get(g["addr"])} for g in f1.load_ghidra_functions(static / "ghidra_functions.json")}
    birlesik = json.loads((static / "ghidra_combined_results.json").read_text(encoding="utf-8"))
    taban = ((birlesik.get("program_info") or birlesik.get("summary", {}).get("program") or {}).get("image_base"))
    return gf, int(str(taban), 16)


def jenerik_mi(g: dict) -> bool:
    return f1.is_generic_name(g["name"], [g["addr"]])


def durum(adres: int, gf: dict[int, dict]) -> str:
    g = gf.get(adres)
    if g is None:
        return DURUM_YOK
    if g["is_thunk"]:
        return DURUM_THUNK
    return DURUM_JENERIK if jenerik_mi(g) else DURUM_ADLI


def objc_secici(ad: str) -> str | None:
    """``-[Sınıf seçici]`` → ``seçici`` (Ghidra ObjC yöntemini sınıf ad alanında yalnız seçiciyle adlandırır)."""
    if ad.startswith(("-[", "+[")) and ad.endswith("]") and " " in ad:
        return ad[ad.index(" ") + 1:-1]
    return None


def kanal_kirilimi(kanal: str, adlar: dict[int, set[str]], gf: dict[int, dict]) -> dict:
    sayac = Counter(durum(a, gf) for a in adlar)
    adli = [a for a in adlar if durum(a, gf) == DURUM_ADLI]
    esit = Counter()
    secici = 0
    for a in adli:
        gad = gf[a]["name"]
        y = [uo.yazim(kanal, k, gad) for k in adlar[a]] if kanal in (uo.KANAL_GO, uo.KANAL_OBJC) else []
        esit["esit" if y and all(v is not None for v in y) else "farkli"] += 1
        if kanal == uo.KANAL_OBJC and all(objc_secici(k) == gad for k in adlar[a]):
            secici += 1
    kaynak = Counter(gf[a]["source"] for a in adli)
    thunk_adli = [a for a in adlar if durum(a, gf) == DURUM_THUNK and not jenerik_mi(gf[a])]
    thunk_esit = sum(1 for a in thunk_adli if kanal in (uo.KANAL_GO, uo.KANAL_OBJC)
                     and all(uo.yazim(kanal, k, gf[a]["name"]) is not None for k in adlar[a]))
    out = {"girdi": len(adlar), **{d: sayac.get(d, 0) for d in (DURUM_YOK, DURUM_THUNK, DURUM_JENERIK, DURUM_ADLI)},
           "thunk_adli": len(thunk_adli), "thunk_adli_ad_esit": thunk_esit,
           "adli_ad_esit": esit.get("esit", 0), "adli_ad_farkli": esit.get("farkli", 0),
           "adli_kaynak": dict(kaynak)}
    if kanal == uo.KANAL_OBJC:
        out["adli_yalniz_secici_esit"] = secici
    return out


def olc(ws: Path, ikili_adi: str) -> dict:
    static = ws / "static"
    gf, taban = ghidra_oku(static)
    ikili = ws / "raw" / ikili_adi
    m = macho.load(str(ikili))
    if taban != m.image_base:
        raise SystemExit(f"Ghidra görüntü tabanı {taban:#x} ≠ Mach-O __TEXT {m.image_base:#x}: adres eşlemesi kanıtsız")
    lfs = set(m.function_starts() or [])
    program = {a for a, g in gf.items() if not g["is_thunk"]}
    thunk = {a for a, g in gf.items() if g["is_thunk"]}
    g1 = {"LC_FUNCTION_STARTS": len(lfs), "ghidra_fonksiyon": len(gf), "ghidra_program": len(program),
          "ghidra_thunk": len(thunk), "lfs_ghidrada": len(lfs & set(gf)), "lfs_ghidrada_program": len(lfs & program),
          "lfs_ghidrada_yok": len(lfs - set(gf)), "ghidra_program_lfs_disi": len(program - lfs),
          "ghidra_thunk_lfs_icinde": len(thunk & lfs)}
    adli = {a for a, g in gf.items() if not jenerik_mi(g)}
    g_adli = {"jenerik_olmayan": len(adli), "jenerik_olmayan_program": len(adli & program),
              "jenerik_olmayan_thunk": len(adli & thunk),
              "kaynak": dict(Counter(gf[a]["source"] for a in adli))}
    cikti = uo.kanal_ciktisi(ikili)
    kanallar = {k: kanal_kirilimi(k, v["adlar"], gf) for k, v in cikti["kanallar"].items()
                if uo.KANAL_GT_TURU[k] == uo.GT_FONKSIYON}
    ust_adres = set().union(*(set(cikti["kanallar"][k]["adlar"]) for k in kanallar))
    g5 = {"ust_veri_fonksiyon_adresi": len(ust_adres), "ghidra_adli_ust_veri_adresinde": len(adli & ust_adres),
          "ghidra_adli_ust_veri_adresinde_program": len(adli & ust_adres & program),
          "ghidra_adli_ust_veri_adresinde_thunk": len(adli & ust_adres & thunk),
          "ghidra_adli_ust_veri_disinda": len(adli - ust_adres),
          "ghidra_adli_ust_veri_disinda_program": len((adli - ust_adres) & program),
          "ust_veri_disi_ghidra_adli_kaynak": dict(Counter(gf[a]["source"] for a in adli - ust_adres))}
    return {"ws": str(ws), "ikili": str(ikili), "sha256": cikti["sha256"], "goruntu_tabani": hex(taban),
            "etiket": uo.ETIKET_ARASTIRMA, "G1": g1, "ghidra_adlari": g_adli,
            "kanallar": kanallar, "G5": g5,
            "kanal_durumu": {k: v["durum"] for k, v in cikti["kanallar"].items()}}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ws", type=Path, required=True)
    ap.add_argument("--ikili-adi", required=True)
    ap.add_argument("--cikti", type=Path)
    a = ap.parse_args()
    r = olc(a.ws.expanduser(), a.ikili_adi)
    s = json.dumps(r, ensure_ascii=False, indent=1)
    if a.cikti:
        a.cikti.parent.mkdir(parents=True, exist_ok=True)
        a.cikti.write_text(s + "\n", encoding="utf-8")
    print(s)


if __name__ == "__main__":
    main()
