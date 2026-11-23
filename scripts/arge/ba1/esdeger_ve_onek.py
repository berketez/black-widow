"""BA-1: eski / yeni bellek kalıplarının gerçek satırlarda eşdeğerliği + önekli ad sayımı.

Girdi: çalışma alanı oturum dizinleri (``…/workspaces/<ad>/<zaman>``); her
birinin ``reconstructed/commented/*.c`` dosyalarında (blok açıklama adımının
girdisi) ``memcpy`` / ``memset`` / ``memmove`` geçen bütün satırlar
``strip()`` edilip (adımın yaptığı gibi) toplanır.

1. Eşdeğerlik: her (satır, ad) için eski ve yeni kalıbın ``search`` sonucu
   (span + gruplar) karşılaştırılır. Kalıplar AYRI SÜREÇTE koşar; çocuk her
   sonucu bir satır olarak yazar, ebeveyn ilerlemeyi izler; bir satırda
   ``--satir-zaman-asimi`` sn ilerleme yoksa çocuğu SIGKILL ile öldürür,
   o satırı ``zaman_asimi`` diye işaretler ve sonraki satırdan yeni çocuk açar.
2. Önekli ad sayımı (hüküm 5; kod değişmez): yeni kalıbın eşleştiği her
   satırda eşleşmenin başındaki adın önü (aynı tanımlayıcıya ait ``\\w``
   karakterleri): çıplak / tek alt çizgi / başka önek (en sık 10).

Satır metinleri depoya girmez (üçüncü taraf kodundan çıkarılmış adlar):
tam döküm ``--cikti`` altında, depoya yalnız sayı ve dosya:satır.

Kullanım (worktree kökünden):

    python scripts/arge/ba1/esdeger_ve_onek.py --cikti <dizin> \
        --ws ollama=<oturum> --ws s8_cat=<oturum> ...
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path

KOK = Path(__file__).resolve().parents[3]
if str(KOK) not in sys.path:
    sys.path.insert(0, str(KOK))

BELLEK_ADLARI = ("memcpy", "memset", "memmove")
ESKI = {
    ad: ad + r"\s*\(\s*(\w+)\s*,\s*(\w+)\s*,\s*((?:[^()]+|\([^)]*\))+)\s*\)"
    for ad in BELLEK_ADLARI
}

_COCUK = r"""
import json, re, sys, time
kaliplar = {k: re.compile(v) for k, v in json.loads(sys.argv[1]).items()}
girdi = json.load(open(sys.argv[2], encoding="utf-8"))
with open(sys.argv[3], "w", encoding="utf-8") as out:
    for ad, metin in girdi:
        t0 = time.perf_counter()
        m = kaliplar[ad].search(metin)
        s = time.perf_counter() - t0
        r = None if m is None else [list(m.span()), list(m.groups())]
        out.write(json.dumps({"r": r, "s": s}) + "\n")
        out.flush()
"""


def yeni_kaliplar() -> dict[str, str]:
    from karadul.reconstruction.engineering.block_annotator import MEMORY_PATTERNS

    out = {}
    for pat, _t, _c in MEMORY_PATTERNS:
        for ad in BELLEK_ADLARI:
            if pat.pattern.startswith(ad):
                out[ad] = pat.pattern
    return out


def ilerlemeli_ara(kaliplar: dict[str, str], isler: list[tuple[str, str]],
                   is_dizini: Path, satir_zaman_asimi: float) -> list[dict]:
    """``isler`` = [(ad, metin)]; her biri için {"r", "s"} ya da {"zaman_asimi": True}."""
    sonuc: list[dict] = []
    i = 0
    tur = 0
    while i < len(isler):
        tur += 1
        gdosya = is_dizini / f"girdi_{tur}.json"
        odosya = is_dizini / f"cikti_{tur}.jsonl"
        gdosya.write_text(json.dumps(isler[i:]), encoding="utf-8")
        p = subprocess.Popen([sys.executable, "-I", "-c", _COCUK, json.dumps(kaliplar),
                              str(gdosya), str(odosya)])
        son_boyut = -1
        son_degisim = time.monotonic()
        olduruldu = False
        while p.poll() is None:
            time.sleep(0.05)
            boyut = odosya.stat().st_size if odosya.exists() else 0
            if boyut != son_boyut:
                son_boyut = boyut
                son_degisim = time.monotonic()
            elif time.monotonic() - son_degisim > satir_zaman_asimi:
                p.kill()  # SIGKILL: C düzeyindeki eşleşme SIGTERM'e yanıt vermez
                p.wait()
                olduruldu = True
                break
        satirlar = odosya.read_text(encoding="utf-8").splitlines() if odosya.exists() else []
        for s in satirlar:
            sonuc.append(json.loads(s))
        i += len(satirlar)
        if olduruldu:
            sonuc.append({"zaman_asimi": True, "s": satir_zaman_asimi})
            i += 1
        elif p.returncode != 0:
            raise RuntimeError(f"çocuk süreç çıkışı {p.returncode}")
        gdosya.unlink()
        odosya.unlink(missing_ok=True)
    return sonuc


def satirlari_topla(ws_ad: str, ws: Path) -> list[dict]:
    kayit = []
    for f in sorted((ws / "reconstructed" / "commented").rglob("*.c")):
        metin = f.read_text(encoding="utf-8", errors="replace")
        if not any(ad in metin for ad in BELLEK_ADLARI):
            continue
        for no, satir in enumerate(metin.splitlines(), 1):
            st = satir.strip()
            if not st or st.startswith("//") or st.startswith("/*"):
                continue
            for ad in BELLEK_ADLARI:
                if ad in st:
                    kayit.append({"ws": ws_ad, "dosya": f.name, "satir": no,
                                  "ad": ad, "metin": st})
    return kayit


def onek(metin: str, bas: int) -> str:
    j = bas
    while j > 0 and (metin[j - 1].isalnum() or metin[j - 1] == "_"):
        j -= 1
    return metin[j:bas]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--ws", action="append", required=True, help="ad=oturum_dizini")
    ap.add_argument("--cikti", required=True)
    ap.add_argument("--satir-zaman-asimi", type=float, default=2.0)
    args = ap.parse_args(argv)
    cikti = Path(args.cikti)
    cikti.mkdir(parents=True, exist_ok=True)
    is_dizini = cikti / "_is"
    is_dizini.mkdir(exist_ok=True)

    kayit: list[dict] = []
    for s in args.ws:
        ad, yol = s.split("=", 1)
        kayit.extend(satirlari_topla(ad, Path(yol)))
    isler = [(k["ad"], k["metin"]) for k in kayit]
    print(f"{len(kayit)} (satır, ad) çifti")

    t0 = time.perf_counter()
    yeni = ilerlemeli_ara(yeni_kaliplar(), isler, is_dizini, args.satir_zaman_asimi)
    t_yeni = time.perf_counter() - t0
    t0 = time.perf_counter()
    eski = ilerlemeli_ara(ESKI, isler, is_dizini, args.satir_zaman_asimi)
    t_eski = time.perf_counter() - t0
    is_dizini.rmdir()

    ozet: dict = {"cift": len(kayit), "duvar_yeni_sn": round(t_yeni, 1),
                  "duvar_eski_sn": round(t_eski, 1), "ws": {}}
    for k, y, e in zip(kayit, yeni, eski):
        k["yeni"] = y
        k["eski"] = e
        w = ozet["ws"].setdefault(k["ws"], Counter())
        w["cift"] += 1
        if y.get("zaman_asimi"):
            w["yeni_zaman_asimi"] += 1
        if e.get("zaman_asimi"):
            w["eski_zaman_asimi"] += 1
            if y.get("r") is not None:
                w["eski_zaman_asimi_yeni_eslesti"] += 1
            continue
        w["eski_bitti"] += 1
        if e["r"] == y.get("r"):
            w["ayni"] += 1
            if e["r"] is not None:
                w["ayni_eslesme_var"] += 1
        else:
            w["farkli"] += 1
    ozet["ws"] = {a: dict(c) for a, c in ozet["ws"].items()}

    # Önekli ad sayımı (yeni kalıbın eşleştiği satırlar; satır başına ilk ad
    # MEMORY_PATTERNS sırasıyla: memcpy, memset, memmove).
    onekler: dict = {}
    for ws_ad in ozet["ws"]:
        gorulen: set = set()
        say = Counter()
        diger = Counter()
        for k in kayit:
            if k["ws"] != ws_ad or k["yeni"].get("r") is None:
                continue
            anahtar = (k["dosya"], k["satir"])
            if anahtar in gorulen:
                continue
            gorulen.add(anahtar)
            o = onek(k["metin"], k["yeni"]["r"][0][0])
            if o == "":
                say["ciplak"] += 1
            elif o == "_":
                say["tek_alt_cizgi"] += 1
            else:
                say["baska_onek"] += 1
                diger[o] += 1
            say[f"ad_{k['ad']}"] += 1
        onekler[ws_ad] = {"satir": len(gorulen), **dict(say),
                          "en_sik_10_onek": diger.most_common(10)}
    ozet["onekli_ad"] = onekler

    (cikti / "esdeger_dokum.json").write_text(
        json.dumps(kayit, ensure_ascii=False), encoding="utf-8")
    (cikti / "esdeger_ozet.json").write_text(
        json.dumps(ozet, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(ozet, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
