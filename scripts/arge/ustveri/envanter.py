"""Kalem 1 — hedef envanteri: dilim, soyulma, sembol tablosu, üst veri bölümleri, Go sürümü.

Kullanım:
    PYTHONDONTWRITEBYTECODE=1 python scripts/arge/ustveri/envanter.py <ikili> [<ikili> …] --cikti x.json
Evrensel ikilide her dilim ayrı satırdır. İkilileri çalıştırmaz.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import go_pclntab as G  # noqa: E402
import macho  # noqa: E402

IZLENEN = ("__gopclntab", "__go_buildinfo", "__typelink", "__itablink", "__go_type", "__go_func",
           "__objc_classlist", "__objc_catlist", "__objc_methlist", "__objc_methname", "__objc_selrefs",
           "__objc_protolist", "__swift5_types", "__swift5_proto", "__swift5_protos", "__swift5_fieldmd",
           "__swift5_reflstr", "__gcc_except_tab", "__eh_frame", "__unwind_info")


def dilim_bilgisi(m: macho.MachO):
    syms = m.symbols()
    stab = sum(1 for s in syms if s.n_type & macho.N_STAB)
    tanimli = [s for s in syms if not (s.n_type & macho.N_STAB) and (s.n_type & macho.N_TYPE) == macho.N_SECT]
    tsec = {t.index for t in m.text_sections()}
    kod_sembolu = [s for s in tanimli if s.n_sect in tsec]
    fs = m.function_starts()
    kod_adres = {s.value for s in kod_sembolu}
    r = {
        "dilim": m.cpu, "dosya_turu": m.filetype, "boyut": len(m.data),
        "kod_baytı": sum(t.size for t in m.text_sections()),
        "LC_MAIN": m.entryoff is not None, "giris": hex(m.entry_vm) if m.entry_vm else None,
        "zincirli_duzeltme": m.chained_fixups_cmd is not None,
        "duzeltme_yeri": len(m.fixups()), "ice_aktarim": len(m.imports()),
        "yeniden_konumlama": sum(1 for e in m.fixups().values() if e[0] == "rebase"),
        "LC_FUNCTION_STARTS": len(fs) if fs is not None else None,
        "sembol": len(syms), "hata_ayiklama_sembolu": stab, "tanimli_sembol": len(tanimli),
        "kod_sembolu": len(kod_sembolu), "kod_sembollu_adres": len(kod_adres),
        "tanimsiz_sembol": sum(1 for s in syms if not (s.n_type & macho.N_STAB)
                               and (s.n_type & macho.N_TYPE) == macho.N_UNDF),
        "bagli_kitaplik": len(m.dylibs),
        "bolum": {s.sectname: s.size for s in m.sections if s.sectname in IZLENEN},
    }
    if fs:
        r["baslangici_sembollu"] = sum(1 for a in fs if a in kod_adres)
    # dil işaretleri
    diller = []
    if m.secs_named("__gopclntab"):
        diller.append("Go")
    if m.secs_named("__objc_classlist") or m.secs_named("__objc_catlist"):
        diller.append("Objective-C")
    if m.secs_named("__swift5_types"):
        diller.append("Swift")
    if any("libc++" in d for d in m.dylibs):
        diller.append("C++ (libc++ bağlı)")
    if any("libswiftCore" in d for d in m.dylibs) and "Swift" not in diller:
        diller.append("Swift (kitaplık bağlı)")
    r["dil_isareti"] = diller
    bi = G.buildinfo(m)
    if bi:
        r["go"] = {"surum": bi.get("surum"), "ana_paket": bi.get("path"), "modul": bi.get("mod"),
                   "bagimlilik": bi.get("dep"), "ldflags": (bi.get("build") or {}).get("-ldflags"),
                   "CGO_ENABLED": (bi.get("build") or {}).get("CGO_ENABLED")}
        sec = m.secs_named("__gopclntab")
        if sec:
            b = m.read(sec[0].addr, 8)
            r["go"]["pclntab_imzasi"] = hex(int.from_bytes(b[:4], "little"))
    return r


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("ikili", nargs="+")
    ap.add_argument("--cikti")
    a = ap.parse_args()
    out = []
    for yol in a.ikili:
        raw = Path(yol).read_bytes()
        kayit = {"ikili": yol, "sha256": hashlib.sha256(raw).hexdigest(), "boyut": len(raw), "dilimler": []}
        for m in macho.load_all(yol):
            kayit["dilimler"].append(dilim_bilgisi(m))
        out.append(kayit)
    s = json.dumps(out, ensure_ascii=False, indent=1)
    if a.cikti:
        Path(a.cikti).write_text(s + "\n")
    print(s)


if __name__ == "__main__":
    main()
