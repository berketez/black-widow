"""Kalem 5–6: plan paketlerinin andığı dosya yolları ve semboller gerçekten var mı; hangi paket hangi dosyaya değiyor.

Girdi: plan belgeleri (salt okur). Çıktı: $V/plan_tara.json + metin özet.
- Paket = belgedeki paket kimliği taşıyan başlık (PK-1, ÖK-4a, P-Ö1, P-ÜV0, ÖL-1, ÖLÇ-0 …) ile sonraki başlık arası;
  `gonderim/P*.md` dosyaları tek pakettir.
- Yol = ters tırnak içindeki, `karadul/`, `tests/`, `scripts/`, `karadul-ghidra/`, `resources/` ile başlayan dizgi.
  "yeni" = yolun önündeki 60 karakterde "yeni" sözcüğü ya da paket metninde "(yeni)" ile birlikte geçmesi.
- Sembol = ters tırnak içindeki Python tanımlayıcısı (alt çizgili ya da büyük harfli; en az 6 karakter);
  depo dizininde (karadul/, scripts/measurement/, tests/ altındaki izlenen .py dosyaları) aranır.

Komut: PYTHONDONTWRITEBYTECODE=1 python scripts/arge/karsi/plan_tara.py --json $V/plan_tara.json
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
from collections import defaultdict
from pathlib import Path

KOK = Path(__file__).resolve().parents[3]
M = KOK / "docs/arge/2026-11-19_mythos"
G = KOK / "docs/arge/2026-11-18_onarim/gonderim"
BELGELER = [
    ("KİMLİK", M / "kimlik/PLAN.md"), ("ÖZ KOD", M / "ozkod/PLAN.md"), ("ÖLÇÜ", M / "olcu/PLAN.md"),
    ("ÜST VERİ", M / "ustveri/PLAN.md"), ("ÖLÇEK", M / "olcek/PLAN.md"), ("HIZ", M / "hiz/PLAN.md"),
    ("YAYIN", KOK / "docs/arge/2026-11-19_yayin/YAYIN_KAPISI.md"),
    ("ONARIM", G / "P12d.md"), ("ONARIM", G / "P24.md"), ("ONARIM", G / "P10b.md"), ("ONARIM", G / "P08b.md"),
    ("ONARIM", G / "P03b.md"), ("ONARIM", G / "P23.md"), ("ONARIM", G / "P18.md"),
]
KIMLIK = re.compile(r"\b(PK-\d+|ÖK-(?:\d+[ab]?|V)|P-Ö\d+|P-ÜV\d+|ÖL-\d+[ab]?|ÖLÇ-[0-9A]|HZ-\d+[ab]?|H-\d+[ab]?)\b")
BASLIK = re.compile(r"^(#{2,4})\s+(.*)$")
TIRNAK = re.compile(r"`([^`\n]+)`")
YOL = re.compile(r"^(?:R/)?((?:karadul|tests|scripts|karadul-ghidra|resources|ui|app)/[A-Za-z0-9_./\-*{},<>]+)$")
SEMBOL = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*(?:\(\))?$")


def paketlere_bol(metin: str, dosya_adi: str) -> list[tuple[str, str]]:
    if dosya_adi.startswith("P") and dosya_adi[1:3].isdigit():
        return [(dosya_adi[:-3], metin)]
    satirlar = metin.split("\n")
    parcalar: list[tuple[str, list[str]]] = []
    simdiki = None
    for s in satirlar:
        m = BASLIK.match(s)
        if m:
            k = KIMLIK.search(m.group(2))
            # paket başlığı: kimlik başlığın başında (ilk 12 karakter içinde)
            if k and k.start() <= 2:
                simdiki = (k.group(1), [])
                parcalar.append(simdiki)
                continue
            if len(m.group(1)) == 2:
                simdiki = None
        if simdiki is not None:
            simdiki[1].append(s)
    return [(k, "\n".join(v)) for k, v in parcalar]


def depo_dizini() -> tuple[set[str], str]:
    c = subprocess.run(["git", "-C", str(KOK), "ls-files", "karadul", "tests", "scripts/measurement", "scripts/arge",
                        "karadul-ghidra", "resources"], capture_output=True, text=True, check=True)
    dosyalar = set(c.stdout.split("\n"))
    # izlenmeyen arge betikleri de say
    for p in (KOK / "scripts/arge").rglob("*"):
        if p.is_file():
            dosyalar.add(str(p.relative_to(KOK)))
    govde = []
    for d in dosyalar:
        if d.endswith(".py") and (d.startswith("karadul/") or d.startswith("scripts/measurement/") or d.startswith("tests/")):
            try:
                govde.append((KOK / d).read_text(encoding="utf-8", errors="replace"))
            except OSError:
                pass
    return dosyalar, "\n".join(govde)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json")
    a = ap.parse_args()
    dosyalar, govde = depo_dizini()
    tanimlayicilar = set(re.findall(r"[A-Za-z_][A-Za-z0-9_]{5,}", govde))
    sonuc = []
    for hat, yol in BELGELER:
        if not yol.exists():
            print(f"[yok] {yol}")
            continue
        metin = yol.read_text(encoding="utf-8")
        for kimlik, govde_p in paketlere_bol(metin, yol.name):
            var, yeni, yok, sembol_yok = set(), set(), set(), set()
            for m in TIRNAK.finditer(govde_p):
                t = m.group(1).strip().rstrip(".,;:")
                ym = YOL.match(t.split(":")[0].split(" ")[0])
                if ym:
                    y = ym.group(1).rstrip("/")
                    onceki = govde_p[max(0, m.start() - 60):m.start()].lower()
                    joker = any(c in y for c in "*{}<>")
                    if y in dosyalar or (KOK / y).exists():
                        var.add(y)
                    elif joker:
                        continue
                    elif "yeni" in onceki or re.search(r"yeni[^`\n]{0,80}`" + re.escape(t), govde_p) or re.search(re.escape(t) + r"`\s*\((?:yeni|yok)", govde_p):
                        yeni.add(y)
                    else:
                        yok.add(y)
                    continue
                if SEMBOL.match(t) and len(t) >= 6 and ("_" in t or any(c.isupper() for c in t[1:])):
                    son = t.rstrip("()").split(".")[-1]
                    if len(son) >= 6 and son not in tanimlayicilar:
                        sembol_yok.add(t)
            sonuc.append({"hat": hat, "belge": str(yol.relative_to(KOK)), "paket": kimlik, "var": sorted(var),
                          "yeni": sorted(yeni), "yok": sorted(yok), "sembol_yok": sorted(sembol_yok),
                          "kabul_sayisal": bool(re.search(r"(Kabul|kabul)[^\n]{0,200}\d", govde_p)),
                          "on_kayit": bool(re.search(r"[Öö]n kayıt", govde_p))})
    # aynı kimlik birden çok kez geçtiyse birleştir
    birles: dict[tuple[str, str], dict] = {}
    for s in sonuc:
        k = (s["hat"], s["paket"])
        if k not in birles:
            birles[k] = s
        else:
            for alan in ("var", "yeni", "yok", "sembol_yok"):
                birles[k][alan] = sorted(set(birles[k][alan]) | set(s[alan]))
            birles[k]["kabul_sayisal"] |= s["kabul_sayisal"]
            birles[k]["on_kayit"] |= s["on_kayit"]
    liste = list(birles.values())
    for s in liste:
        print(f"\n[{s['hat']}] {s['paket']}  kabul sayısal: {s['kabul_sayisal']}  ön kayıt: {s['on_kayit']}")
        print("  var :", ", ".join(s["var"]) or "—")
        if s["yeni"]:
            print("  yeni:", ", ".join(s["yeni"]))
        if s["yok"]:
            print("  YOK (yeni denmemiş):", ", ".join(s["yok"]))
        if s["sembol_yok"]:
            print("  depoda bulunmayan sembol:", ", ".join(s["sembol_yok"]))
    # çakışma: var olan ürün / ölçüm / test dosyası → paketler
    harita = defaultdict(set)
    for s in liste:
        for y in s["var"] + s["yeni"]:
            if y.startswith(("karadul/", "scripts/measurement/", "tests/")) and "." in y.rsplit("/", 1)[-1]:
                harita[y].add(f"{s['hat']}:{s['paket']}")
    print("\n\n=== İKİ VE DAHA ÇOK PAKETİN ANDIĞI DOSYALAR ===")
    cok = {y: sorted(p) for y, p in harita.items() if len(p) >= 2}
    for y in sorted(cok, key=lambda k: (-len(cok[k]), k)):
        print(f"{len(cok[y]):2d} {y}: {', '.join(cok[y])}")
    if a.json:
        with open(a.json, "w", encoding="utf-8") as f:
            json.dump({"paketler": liste, "cok_paketli": cok, "harita": {k: sorted(v) for k, v in harita.items()}},
                      f, ensure_ascii=False, indent=1)


if __name__ == "__main__":
    main()
