"""config.py'deki her dataclass alanı için: karadul/ ve ui/ içinde (config.py dışında) '.alan' erişimi kaç kez geçiyor?"""
import ast, re, subprocess
from pathlib import Path
kok = Path("/Users/apple/Black_Widow")
src = (kok/"karadul/config.py").read_text(encoding="utf-8")
t = ast.parse(src)
alanlar = []
for n in t.body:
    if isinstance(n, ast.ClassDef):
        for s in n.body:
            if isinstance(s, ast.AnnAssign) and isinstance(s.target, ast.Name):
                alanlar.append((n.name, s.target.id, s.lineno))
metin = {}
for d in ("karadul", "ui"):
    for p in (kok/d).rglob("*.py"):
        if "__pycache__" in p.parts or p.name == "config.py" and p.parent.name == "karadul": continue
        metin[str(p.relative_to(kok))] = p.read_text(encoding="utf-8", errors="replace")
html = (kok/"ui/index.html").read_text(encoding="utf-8", errors="replace")
hepsi = "\n".join(metin.values())
okunmayan = []
for sinif, alan, satir in alanlar:
    # öznitelik erişimi ya da dize anahtarı (getattr / yaml anahtarı)
    n_attr = len(re.findall(r"\.%s\b" % re.escape(alan), hepsi))
    n_str = len(re.findall(r"[\"']%s[\"']" % re.escape(alan), hepsi))
    # config.py içinde (tanım dışı) kullanım
    n_ic = len(re.findall(r"\.%s\b" % re.escape(alan), src))
    if n_attr == 0:
        okunmayan.append((sinif, alan, satir, n_str, n_ic, alan in html))
print(f"toplam alan: {len(alanlar)}; paket içinde '.alan' erişimi 0 olan: {len(okunmayan)}")
for o in okunmayan:
    print("  %-28s %-42s config.py:%-5d dize=%d config_içi=%d arayüz_html=%s" % o)
