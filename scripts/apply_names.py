#!/usr/bin/env python3
"""Karadul -> Claude semantic naming koprusu: APPLY tarafi (saf I/O, LLM yok).

Claude'un ``dump_for_naming.py`` ciktisindan urettigi ``{FUN_addr: isim}`` JSON'unu
karadul'un ``naming_map.json``'una merge eder. Deterministik motorun zaten
isimlendirdigi fonksiyonlar EZILMEZ (deterministik oncelik korunur); yalnizca
FUN_xxx kalanlar Claude'un semantic isimleriyle doldurulur.

Mimari: karadul cekirdegi degismez. Bu, dis Claude EKLENTISININ ciktisini
karadul'un kalici ciktisina (naming_map) geri besleyen koprudur -- karadul'u
guclendirir. (src/*.c yeniden yazimi opsiyonel gelistirme; su an naming_map
guncellenir, F1/rapor bunu okur.)

Kullanim:
    python3 scripts/apply_names.py <workspace_dir> <claude_names.json>
"""
from __future__ import annotations

import json
import sys
from pathlib import Path


def main() -> None:
    if len(sys.argv) < 3:
        print("kullanim: apply_names.py <workspace_dir> <claude_names.json>")
        sys.exit(1)
    ws, names_path = sys.argv[1], sys.argv[2]

    nm_path = next(iter(Path(ws).rglob("reconstructed/src/naming_map.json")), None)
    if not nm_path:
        print("HATA: naming_map.json bulunamadi")
        sys.exit(1)

    names = json.load(open(names_path))
    nm = json.load(open(nm_path))
    g = nm.setdefault("global", {})

    applied = skipped = 0
    for fun, name in names.items():
        if not (fun.startswith("FUN_") and isinstance(name, str) and name):
            continue
        # Deterministik oncelik: karadul zaten isimlendirdiyse (value FUN_ ile
        # baslamiyor) DOKUNMA -- Claude yalnizca isimsiz kalanlari doldurur.
        cur = g.get(fun)
        if cur is not None and not cur.startswith("FUN_"):
            skipped += 1
            continue
        g[fun] = name
        applied += 1

    json.dump(nm, open(nm_path, "w"), indent=2, ensure_ascii=False)
    print(f"APPLY: {applied} Claude ismi merge edildi, {skipped} atlandi "
          f"(karadul zaten isimli) -> {nm_path}")


if __name__ == "__main__":
    main()
