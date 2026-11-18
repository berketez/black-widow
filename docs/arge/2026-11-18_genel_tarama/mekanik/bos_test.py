"""Hiçbir doğrulama içermeyen test fonksiyonları (assert / raises / warns / assert_* çağrısı / fail yok)."""
import ast
from pathlib import Path
kok = Path("/Users/apple/Black_Widow/tests")
bos = []; toplam = 0
for p in sorted(kok.rglob("test_*.py")):
    try: t = ast.parse(p.read_text(encoding="utf-8", errors="replace"))
    except SyntaxError: continue
    for n in ast.walk(t):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name.startswith("test"):
            toplam += 1
            var = False
            for s in ast.walk(n):
                if isinstance(s, ast.Assert): var = True; break
                if isinstance(s, ast.Call):
                    f = s.func
                    ad = getattr(f, "attr", None) or getattr(f, "id", None) or ""
                    if ad in ("raises", "warns", "fail", "skip", "xfail", "deprecated_call") or ad.startswith("assert") or ad.startswith("_assert") or ad.startswith("check") or ad.startswith("_check") or ad.startswith("expect") or ad.startswith("verify") or ad.startswith("_dogrula") or ad.startswith("dogrula"):
                        var = True; break
            if not var:
                bos.append((str(p.relative_to(kok.parent)), n.lineno, n.name, n.end_lineno - n.lineno + 1))
print("toplam test fonksiyonu:", toplam, "| doğrulamasız:", len(bos))
from collections import Counter
c = Counter(b[0] for b in bos)
for f, k in c.most_common(25): print(f"  {k:3d}  {f}")
print("örnekler:")
for b in bos[:25]: print("  ", b)
