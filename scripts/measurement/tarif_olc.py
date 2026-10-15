#!/usr/bin/env python3
"""Tarif katmanını bir Karadul koşusu üzerinde çalıştırır (ölçüm; mevcut hatta bağlı değil).

Kullanım:
    tarif_olc.py <koşu_dizini> <strip'li_ikili> <çıktı.json>

<koşu_dizini>: `karadul analyze --output-dir <koşu>/ws` çıktısının kökü. İçinde
`macho_score.json` (isim bekleyen fonksiyonlar, scratchpad puanlayıcısı) beklenir.

Kesin isimler köprüsü: Karadul'un mevcut isimlerinden yalnız ikilide aynen geçen
tanımlayıcılar (ölçülen kesinlik ~0,74). Ürüne entegrasyonda (plan G4) bunun yerini
doğrudan kendi-adı tespiti alacak.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from karadul.reconstruction.tarif import build_evidence, run_tarif  # noqa: E402

_IDENT = re.compile(r"[a-z][a-z0-9]*(_[a-z0-9]+)+")


def reliable_names(run_dir: Path, binary: Path) -> dict[str, str]:
    nm = json.loads(next(run_dir.glob("ws/workspaces/*/*/reconstructed/src/naming_map.json")).read_text())
    strs = set(subprocess.run(["strings", "-n", "4", str(binary)], capture_output=True, text=True).stdout.split("\n"))
    out = {}
    for old, new in nm.get("global", {}).items():
        if not old.startswith("FUN_"):
            continue
        base = re.sub(r"_\d+$", "", new)
        if new == base and base in strs and _IDENT.fullmatch(base) and len(base) >= 8:
            out[old[4:].lower()] = base
    return out


def main() -> int:
    run_dir, binary, out = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3])
    static_dir = next(run_dir.glob("ws/workspaces/*/*/static"))
    rows = json.loads((run_dir / "macho_score.json").read_text())["rows"]
    population = {r["addr"].replace("0x", "").lower() for r in rows}
    packs = build_evidence(static_dir)
    kesin = reliable_names(run_dir, binary)
    names = run_tarif(packs, kesin, population)
    out.write_text(json.dumps({a: {"isim": n.name, "kaynak": n.source, "puan": n.score}
                               for a, n in sorted(names.items())}, ensure_ascii=False, indent=1),
                   encoding="utf-8")
    kinds = Counter(n.source.split(":")[0].split("+")[0] for n in names.values())
    named = sum(1 for n in names.values() if not n.is_hint)
    hints = sum(1 for n in names.values() if n.is_hint)
    print(f"{binary.name}: isim bekleyen {len(population)}; isim {named}, ipucu {hints}, "
          f"isimsiz {len(population) - named - hints}; kaynaklar {dict(kinds)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
