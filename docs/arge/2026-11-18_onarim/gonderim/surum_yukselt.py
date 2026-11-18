"""1.23.1 → 1.24.1: sürüm adının geçtiği her yer (pyproject, __init__, public API testi, kılavuz, Info.plist yedek değerleri)."""
import re, sys
from pathlib import Path
K = Path("/Users/apple/Black_Widow")
E, Y = "1.23.1", "1.24.1"
degisim = [
    ("pyproject.toml", f'version = "{E}"', f'version = "{Y}"'),
    ("karadul/__init__.py", f'__version__ = "{E}"', f'__version__ = "{Y}"'),
    ("tests/test_public_api.py", f'== "{E}"', f'== "{Y}"'),
    ("docs/kullanim_kilavuzu.md", f"Sürüm {E} için.", f"Sürüm {Y} için."),
]
for dosya, eski, yeni in degisim:
    p = K / dosya
    s = p.read_text(encoding="utf-8")
    assert s.count(eski) == 1, (dosya, s.count(eski))
    p.write_text(s.replace(eski, yeni), encoding="utf-8")
plist = K / "packaging/macos/app/Info.plist"
s = plist.read_text(encoding="utf-8")
n = s.count("1.21.1")
assert n == 3, n
plist.write_text(s.replace("1.21.1", Y), encoding="utf-8")
print("tamam")
