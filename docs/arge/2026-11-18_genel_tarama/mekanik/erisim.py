"""Ürün giriş noktalarından (karadul.cli, karadul.__main__, ui/server.py, ui/app_window.py) statik içe aktarma kapanışı."""
import ast
from pathlib import Path
kok = Path("/Users/apple/Black_Widow")
mods = {}
for p in (kok / "karadul").rglob("*.py"):
    if "__pycache__" in p.parts: continue
    rel = p.relative_to(kok).with_suffix("")
    ad = ".".join(rel.parts)
    paket = ad.endswith(".__init__")
    if paket: ad = ad[: -len(".__init__")]
    mods[ad] = (p, paket)
def akt(p, modad, paket_mi):
    try: t = ast.parse(p.read_text(encoding="utf-8", errors="replace"))
    except SyntaxError: return set()
    out = set()
    for n in ast.walk(t):
        if isinstance(n, ast.Import):
            for a in n.names: out.add(a.name)
        elif isinstance(n, ast.ImportFrom):
            if n.level:
                parca = modad.split("."); taban = parca if paket_mi else parca[:-1]
                taban = taban[: len(taban) - (n.level - 1)]
                b = ".".join(taban + ([n.module] if n.module else []))
            else: b = n.module or ""
            out.add(b)
            for a in n.names: out.add(b + "." + a.name)
        elif isinstance(n, ast.Call):
            f = n.func; fa = getattr(f, "attr", None) or getattr(f, "id", None)
            if fa in ("import_module", "__import__") and n.args and isinstance(n.args[0], ast.Constant) and isinstance(n.args[0].value, str):
                out.add(n.args[0].value)
    return out
def coz(a):
    r = set()
    while a:
        if a in mods: r.add(a)   # modül + bütün üst paketleri (üst __init__ çalışır)
        a = a.rpartition(".")[0]
    return r
gorulen = set(); kuyruk = []
for giris in ("karadul.cli", "karadul.__main__", "karadul"):
    if giris in mods: kuyruk.append(giris)
dis = set()
for p in (kok/"ui"/"server.py", kok/"ui"/"app_window.py"):
    for a in akt(p, "ui."+p.stem, False): dis |= coz(a)
kuyruk += list(dis)
while kuyruk:
    m = kuyruk.pop()
    if m in gorulen: continue
    gorulen.add(m)
    p, paket = mods[m]
    for a in akt(p, m, paket):
        for c in coz(a):
            if c not in gorulen: kuyruk.append(c)
olu = sorted(set(mods) - gorulen)
top = 0
for m in olu:
    if ".ghidra.scripts" in m: continue
    n = sum(1 for _ in open(mods[m][0], encoding="utf-8", errors="replace")); top += n
    print(f"{m:72s} {n:5d}")
print("TOPLAM erişilmeyen:", len(olu), "modül;", top, "satır (ghidra betikleri hariç)")
