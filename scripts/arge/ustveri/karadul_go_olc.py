"""Karadul'un VAR OLAN Go kodu aynı ikililerde ne veriyor? (ürün kodu yalnız çağrılır, değiştirilmez)

Ölçülenler (Ghidra koşmadan):
1. `TargetDetector.detect` → hedef türü.
2. `GoBinaryAnalyzer._extract_gopclntab` → hangi yöntem (go tool objdump / nm / strings+regex), kaç ad,
   adların kaçı adres taşıyor, kaçı `pclntab`'daki gerçek fonksiyon adı.
3. K-4 Go kanalının girdisi: `_extract_binary_symbols` (nm -P) + `is_go_symbol` + `demangle`;
   kaç sembol `pclntab` girişine denk geliyor (kanal ancak bunlara aday üretebilir).

Kullanım:
    PYTHONDONTWRITEBYTECODE=1 python scripts/arge/ustveri/karadul_go_olc.py <ikili> [--dilim arm64]
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import go_pclntab as G  # noqa: E402
import macho  # noqa: E402


def olc(path: str, dilim: str | None):
    from karadul.analyzers.go_binary import GoBinaryAnalyzer
    from karadul.analyzers.go_demangler import demangle as go_demangle, is_go_symbol
    from karadul.config import Config
    from karadul.core.target import TargetDetector
    from karadul.pipeline.steps._feedback_naming_candidates import _extract_binary_symbols

    m = macho.load(path, dilim)
    p = G.PclnTab(m)
    fs = p.funcs()
    adlar = {f.name for f in fs if f.name}
    girisler = {f.entry: f.name for f in fs}

    r = {"ikili": path, "pclntab_fonksiyon": len(fs), "pclntab_ayrik_ad": len(adlar)}
    ti = TargetDetector().detect(path)
    r["hedef_turu"] = ti.target_type.value
    r["dil"] = ti.language.value if ti.language else None
    r["metadata"] = {k: v for k, v in (ti.metadata or {}).items() if k in ("go_slice", "native_format")}

    cfg = Config()
    an = GoBinaryAnalyzer(cfg)
    r["go_araci_var"] = an._check_go_available()
    g = an._extract_gopclntab(Path(path))
    if g:
        fn = g.get("functions", [])
        urun_adlari = [f.get("name", "") for f in fn]
        soyulmus = [a[1:] if a.startswith("_") else a for a in urun_adlari]
        r["gopclntab"] = {
            "yontem": g.get("extraction_method"), "ad": len(fn),
            "adresli": sum(1 for f in fn if f.get("address")),
            "pclntab_adi_olan": sum(1 for a in soyulmus if a in adlar),
            "pclntab_adi_olmayan": sum(1 for a in soyulmus if a not in adlar),
            "pclntab_adlarinin_bulunani": len(adlar & set(soyulmus)),
            "kaynak_dosya": len(g.get("source_files", [])),
        }
    else:
        r["gopclntab"] = None
    # K-4 Go kanalının girdisi
    syms = _extract_binary_symbols(Path(path))
    go = []
    for name, addr in syms:
        try:
            if is_go_symbol(name):
                go.append((name, addr, go_demangle(name)))
        except Exception:
            pass
    r["k4_go_kanali"] = {
        "nm_sembolu": len(syms), "go_sembolu": len(go),
        "pclntab_girisinde": sum(1 for _n, a, _d in go if a in girisler),
        "cozulen": sum(1 for _n, _a, d in go if d),
        "pclntab_girisi_kapsami": f"{len({a for _n, a, _d in go if a in girisler})} / {len(girisler)}",
    }
    return r


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("ikili")
    ap.add_argument("--dilim")
    ap.add_argument("--cikti")
    a = ap.parse_args()
    r = olc(a.ikili, a.dilim)
    s = json.dumps(r, ensure_ascii=False, indent=1)
    if a.cikti:
        Path(a.cikti).write_text(s + "\n")
    print(s)


if __name__ == "__main__":
    main()
