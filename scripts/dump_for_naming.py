#!/usr/bin/env python3
"""Karadul -> Claude semantic naming koprusu: DUMP tarafi (saf I/O, LLM yok).

Karadul bir binary'yi analiz ettikten sonra, deterministik motorun isimsiz
biraktigi FUN_xxx fonksiyonlarini + decompiled C'lerini + karadul'un zaten verdigi
isimleri (baglam) tek bir JSON'a toplar. Bu JSON dis bir Claude oturumuna/ajanina
verilir; Claude SADECE decompiled'dan semantic isim onerir (GT/kaynak yasak);
sonuc ``apply_names.py`` ile geri beslenir.

Mimari: karadul cekirdegi LLM'siz KALIR. Bu script sadece export yapar; Claude
ayri bir EKLENTI katmanidir. Amac karadul'un ciktisini guclendirmek.

Kullanim:
    python3 scripts/dump_for_naming.py <workspace_dir> [out.json]
"""
from __future__ import annotations

import glob
import json
import os
import sys
from pathlib import Path


def find_workspace_files(ws: str) -> tuple[Path | None, Path | None]:
    """Workspace icinde naming_map.json ve decompiled dizinini bul."""
    wsp = Path(ws)
    nm = next(iter(wsp.rglob("reconstructed/src/naming_map.json")), None)
    # Ghidra decompiled dizini: ghidra_output/decompiled veya deobfuscated/decompiled
    dec = None
    for d in wsp.rglob("decompiled"):
        if d.is_dir() and list(d.glob("FUN_*.c")):
            dec = d
            if "ghidra" in str(d):  # ham Ghidra ciktisi tercih
                break
    return nm, dec


def main() -> None:
    if len(sys.argv) < 2:
        print("kullanim: dump_for_naming.py <workspace_dir> [out.json]")
        sys.exit(1)
    ws = sys.argv[1]
    out = sys.argv[2] if len(sys.argv) > 2 else "dump_for_naming.json"

    nm_path, dec = find_workspace_files(ws)
    if not nm_path or not dec:
        print(f"HATA: naming_map veya decompiled bulunamadi (nm={nm_path}, dec={dec})")
        sys.exit(1)

    g = json.load(open(nm_path)).get("global", {})
    named = {k for k in g if k.startswith("FUN_")}
    allfun = {os.path.basename(f)[:-2] for f in glob.glob(f"{dec}/FUN_*.c")}
    unnamed = sorted(allfun - named)

    payload: dict = {
        "workspace": str(ws),
        "decompiled_dir": str(dec),
        # Karadul'un zaten isimlendirdigi fonksiyonlar -- Claude baglam icin
        # bunlara guvenebilir (deterministik kurtarma, yuksek guven).
        "already_named": {k: g[k] for k in named},
        "to_name": [],  # isimsiz FUN_ + decompiled icerik
    }
    for u in unnamed:
        try:
            src = (Path(dec) / f"{u}.c").read_text(errors="ignore")
        except OSError:
            src = ""
        payload["to_name"].append({"fun": u, "decompiled": src})

    json.dump(payload, open(out, "w"), indent=2, ensure_ascii=False)
    print(f"DUMP: {len(unnamed)} isimsiz fonksiyon, {len(named)} baglam-isim -> {out}")


if __name__ == "__main__":
    main()
