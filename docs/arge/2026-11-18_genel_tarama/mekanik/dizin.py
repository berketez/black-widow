"""Kulvar dosyalarından bulgu dizini çıkarır: kimlik | önem | güven | etkin | başlık."""
import re, sys
from pathlib import Path
D = Path(__file__).resolve().parent.parent
sira = {"KRİTİK": 0, "YÜKSEK": 1, "ORTA": 2, "DÜŞÜK": 3}
rows = []
for p in sorted(D.glob("kulvar_*.md")):
    t = p.read_text(encoding="utf-8")
    for m in re.finditer(r"^## ([A-Z]+-\d+) — (.+?)\n(.*?)(?=^## |\Z)", t, re.S | re.M):
        kid, baslik, govde = m.group(1), m.group(2).strip(), m.group(3)
        def al(etiket):
            x = re.search(r"^- %s:\s*(.+)$" % etiket, govde, re.M)
            return x.group(1).strip() if x else ""
        onem = al("Önem"); o1 = re.match(r"(KRİTİK|YÜKSEK|ORTA|DÜŞÜK)", onem)
        guven = al("Güven").split(" ")[0].strip("(,") if al("Güven") else ""
        etkin = al("Etkin mi")
        e1 = "ölü" if etkin.startswith("ölü") else ("bayrak" if "bayrak arkasında" in etkin[:40] else ("bağlı değil" if etkin.startswith("bağlı değil") else ("evet" if etkin.startswith("evet") else etkin[:14])))
        rows.append((sira.get(o1.group(1) if o1 else "", 9), kid, o1.group(1) if o1 else "?", guven, e1, baslik))
rows.sort(key=lambda r: (r[0], r[1].split("-")[0], int(r[1].split("-")[1])))
if "--say" in sys.argv:
    from collections import Counter
    print(Counter(r[2] for r in rows), len(rows)); print(Counter(r[1].split("-")[0] for r in rows))
else:
    for r in rows: print("| %s | %s | %s | %s | %s |" % (r[1], r[2], r[3], r[4], r[5]))
