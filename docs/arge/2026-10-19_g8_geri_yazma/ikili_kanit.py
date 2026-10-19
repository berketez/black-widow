"""G8 yerleşim doğrulaması, ikili kanıtlar (ön kayıt §4, madde 2 ve 3).

2. Şişedeki ikilide sizeof(struct window_pane): `xcalloc` çağrısından önce w1/x1'e
   yüklenen sabit.
3. 20 hedef fonksiyonun bellek erişim ofsetleri: şişe (orig/tmux) ile aynı
   seçeneklerle `-g -Os` derlenen tmux (build_g/tmux) karşılaştırılır. Yığın (sp)
   ve çerçeve (x29) göreli erişimler alan erişimi olmadığı için dışarıda tutulur.

Çıktı: workspaces/2026-10-19_g8/veri/ikili_kanit.json
"""

from __future__ import annotations

import collections
import json
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ortak  # noqa: E402

RE_FONK = re.compile(r"^([0-9a-f]+) <(.+)>:$")
RE_KOMUT = re.compile(r"^\s*([0-9a-f]+):\s+(\S+)\s*(.*)$")
RE_BELLEK = re.compile(r"\[(x\d+|sp|x29)(?:, #(-?0x[0-9a-f]+|-?\d+))?\]")


def disasm(ikili: Path) -> dict[str, list[tuple[str, str]]]:
    r = subprocess.run(["/usr/bin/objdump", "-d", "--no-show-raw-insn", str(ikili)],
                       capture_output=True, text=True, timeout=600)
    fonk: dict[str, list[tuple[str, str]]] = {}
    cur = None
    for s in r.stdout.splitlines():
        m = RE_FONK.match(s)
        if m:
            cur = m.group(2)
            fonk[cur] = []
            continue
        m = RE_KOMUT.match(s)
        if m and cur is not None:
            fonk[cur].append((m.group(2), m.group(3)))
    return fonk


def ofsetler(komutlar: list[tuple[str, str]]) -> collections.Counter:
    c = collections.Counter()
    for op, arg in komutlar:
        if not (op.startswith("ld") or op.startswith("st")):
            continue
        for m in RE_BELLEK.finditer(arg):
            taban, ofs = m.group(1), m.group(2)
            if taban in ("sp", "x29"):
                continue
            c[int(ofs, 0) if ofs else 0] += 1
    return c


def sizeof_kaniti(fonk: dict) -> list[dict]:
    out = []
    for ad, komutlar in fonk.items():
        for i, (op, arg) in enumerate(komutlar):
            if op == "bl" and "<_xcalloc>" in arg:
                for op2, arg2 in komutlar[max(0, i - 4):i]:
                    m = re.match(r"(w1|x1), #(0x[0-9a-f]+)", arg2)
                    if op2 == "mov" and m and int(m.group(2), 16) == 0x6E0:
                        out.append({"fonksiyon": ad, "komut": f"{op2} {arg2}"})
    return out


def main() -> None:
    secim = json.loads((ortak.VERI / "secim.json").read_text())
    sise = disasm(ortak.ORIG_TMUX)
    bizim = disasm(ortak.BUILD_G / "tmux")
    hedefler = []
    for h in secim["hedefler"]:
        ad = "_" + h["ad"]
        a, b = sise.get(ad), bizim.get(ad)
        if a is None or b is None:
            hedefler.append({"ad": h["ad"], "durum": "bizim derlemede yok" if b is None else "şişede yok"})
            continue
        oa, ob = ofsetler(a), ofsetler(b)
        ka, kb = set(oa), set(ob)
        hedefler.append({
            "ad": h["ad"], "komut_sise": len(a), "komut_bizim": len(b),
            "ofset_sise": sorted(ka), "ofset_bizim": sorted(kb),
            "ortak": len(ka & kb), "yalniz_sise": sorted(ka - kb), "yalniz_bizim": sorted(kb - ka),
            "jaccard": round(len(ka & kb) / len(ka | kb), 3) if (ka | kb) else 1.0,
        })
    cikti = {"kunye": ortak.kunye(), "sizeof_window_pane_0x6e0": sizeof_kaniti(sise),
             "hedef_ofset_karsilastirmasi": hedefler}
    ortak.json_yaz(ortak.VERI / "ikili_kanit.json", cikti)
    print("sizeof kanıtı:", cikti["sizeof_window_pane_0x6e0"])
    for x in hedefler:
        print(x.get("ad"), x.get("jaccard"), "yalnız şişe:", x.get("yalniz_sise"), "yalnız bizim:", x.get("yalniz_bizim"))


if __name__ == "__main__":
    main()
