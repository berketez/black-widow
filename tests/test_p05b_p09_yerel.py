"""P05b kalem 5: P09 ölçüm betiğinin yerel bildirim deseni (``_YEREL``).

Eski desen tip ile ad arasında boşluk istemiyordu (``\\s*``): ``  return;`` satırı ``retur`` tipli
``n`` yereli sayılıyor, aynı fonksiyonda gerçek bir ``n`` yereli varsa onun tipinin üstüne
yazılıyordu (tip değişimi ölçüden düşüyordu).
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts" / "measurement"))

import p09_olc  # noqa: E402

KOD = (
    "int f(int a)\n{\n"
    "  int x;\n"
    "  char *p;\n"
    "  char* q;\n"
    "  uint8_t **pp;\n"
    "  undefined1 auStack_58 [16];\n"
    "  long n;\n"
    "  return;\n"
    "  break;\n"
    "}\n"
)


def test_deyim_yerel_bildirim_sayilmaz():
    tipler = p09_olc.bildirimler(KOD)["tipler"]
    assert tipler == {
        ("f", "a"): "int", ("f", "x"): "int", ("f", "p"): "char *", ("f", "q"): "char *",
        ("f", "pp"): "uint8_t **", ("f", "auStack_58"): "undefined1", ("f", "n"): "long",
    }


def test_gercek_yerelin_tip_degisimi_ortulmez(tmp_path: Path):
    merged, typed = tmp_path / "merged", tmp_path / "typed"
    merged.mkdir()
    typed.mkdir()
    (merged / "f.c").write_text(KOD, encoding="utf-8")
    (typed / "f.c").write_text(KOD.replace("  long n;", "  double n;"), encoding="utf-8")
    sayac = p09_olc.degisim_say(merged, typed)["sayac"]
    assert sayac["degisen"] == 1
    assert sayac["double_yeni"] == 1
