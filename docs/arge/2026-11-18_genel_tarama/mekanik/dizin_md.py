"""DIZIN.md üretir. Kullanım: python mekanik/dizin_md.py  (tarama dizininde)."""
import subprocess
from collections import Counter, defaultdict
# Ana oturumun koddan ya da gerçek çıktıdan ayrıca doğruladığı bulgular (MEK kulvarının tamamı ayrıca eklenir).
D = set("""BORU-01 BORU-05 LM-01 LM-02 LM-06 AD-01 AD-06 AD-07 AD-08 AD-11 TIP-01 TIP-06 TIP-07 TIP-08 TIP-09 TIP-11
ARAYUZ-01 ARAYUZ-03 ARAYUZ-06 ARAYUZ-12 ARAYUZ-17 IMZA-01 IMZA-04 IMZA-05 IMZA-06 IMZA-07 MUH-01 MUH-03 BICIM-01 BICIM-04 BICIM-07
GHIDRA-01 GHIDRA-07 GHIDRA-11""".split())
KUCUK = 105
out = subprocess.run(["python", "mekanik/dizin.py"], capture_output=True, text=True).stdout.strip().splitlines()
rows = []
for l in out:
    p = [x.strip() for x in l.strip().strip("|").split("|")]
    kid = p[0]
    if kid.startswith("MEK-"): D.add(kid)
    rows.append((kid, p[1], p[2], p[3], " | ".join(p[4:]).strip()))
c = Counter(r[1] for r in rows); k = defaultdict(Counter)
for r in rows: k[r[0].split("-")[0]][r[1]] += 1
L = ["# Bulgu dizini — Karadul genel tarama 2026-11-18", "",
     "Üretici: `mekanik/dizin_md.py` (kulvar dosyalarından). **D** = ana oturum bulguyu koddan ya da gerçek çıktıdan ayrıca doğruladı; boş = ajan bulgusu (onarımdan önce \"Nasıl sınanır\" denemesiyle görülmeli).", "",
     "\"Etkin\" sütunu: evet = bugünkü öntanımlı akışta çalışan kod; bayrak = öntanımlı kapalı bayrağın arkasında; bağlı değil = KaradulLM (hiçbir giriş noktasına bağlı değil); ölü = hiç çağrılmıyor.", "",
     f"Toplam **{len(rows)}** bulgu: KRİTİK {c['KRİTİK']}, YÜKSEK {c['YÜKSEK']}, ORTA {c['ORTA']}, DÜŞÜK {c['DÜŞÜK']}. Ana oturumun doğruladığı: {sum(1 for r in rows if r[0] in D)}. Ayrıca kulvar dosyalarının \"Küçükler\" bölümlerinde tek satırlık {KUCUK} kalem var.", "",
     "| Kulvar | KRİTİK | YÜKSEK | ORTA | DÜŞÜK | Toplam |", "|---|---|---|---|---|---|"]
for ad in ("MEK", "BORU", "AD", "TIP", "IMZA", "ARAYUZ", "MUH", "BICIM", "GHIDRA", "LM"):
    x = k[ad]; L.append(f"| {ad} | {x['KRİTİK']} | {x['YÜKSEK']} | {x['ORTA']} | {x['DÜŞÜK']} | {sum(x.values())} |")
for onem in ("KRİTİK", "YÜKSEK", "ORTA", "DÜŞÜK"):
    L += ["", f"## {onem}", "", "| Kimlik | D | Güven | Etkin | Başlık |", "|---|---|---|---|---|"]
    for r in rows:
        if r[1] == onem:
            g = r[2] if r[2] in ("kesin", "yüksek", "şüphe") else "bkz. dosya"
            e = r[3] if r[3] in ("evet", "bayrak", "ölü", "bağlı değil") else "bkz. dosya"
            L.append(f"| {r[0]} | {'D' if r[0] in D else ''} | {g} | {e} | {r[4]} |")
open("DIZIN.md", "w", encoding="utf-8").write("\n".join(L) + "\n")
print(len(rows), dict(c), "D:", sum(1 for r in rows if r[0] in D))
