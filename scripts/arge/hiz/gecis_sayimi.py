#!/usr/bin/env python3
"""HIZ kalem 2: Ghidra döküm adımlarında Python ↔ Java geçiş sayısının tahmini.

Her adımın döngü yapısı ``karadul/ghidra/headless.py``'den okunmuştur; öğe sayıları
(fonksiyon, gövde adresi, blok, kenar, komut, pcode op, varnode) ``ghidra_output/``
dosyalarından sayılır. Geçiş = Python'dan bir Java yöntemi çağrısı ya da Java
yineleyicisinin ``hasNext`` / ``next`` adımı ya da Java nesnesinin ``str()``'ı.
Çarpanlar (öğe başına geçiş) satır numaralarıyla aşağıda; alt sınır olarak sayılır
(ör. her adres için ``getReferencesFrom`` dönen dizi boşsa yineleme geçişi 0 sayılır).

Kullanım:
    python scripts/arge/hiz/gecis_sayimi.py --go <ws>/static/ghidra_output [--ad Ollama]
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def _yukle(p: Path):
    return json.loads(p.read_text(encoding="utf-8"))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--go", required=True, type=Path, help="static/ghidra_output dizini")
    ap.add_argument("--ad", default="")
    ap.add_argument("--cikti", type=Path)
    a = ap.parse_args()
    go = a.go.expanduser()

    fn = _yukle(go / "functions.json")
    funcs = fn["functions"]
    n_fn = len(funcs)
    adres = sum(int(f.get("size") or 0) for f in funcs)  # body.getNumAddresses() toplamı
    n_param = sum(len(f.get("parameters") or []) for f in funcs)

    cg = _yukle(go / "call_graph.json")
    cg_callers = sum(n["caller_count"] for n in cg["nodes"].values())
    cg_edges_raw = cg["total_edges"]

    cfg = _yukle(go / "cfg.json")
    n_blok = cfg["total_blocks"]
    n_kenar = cfg["total_edges"]
    n_komut = sum(b["instruction_count"] for f in cfg["functions"] for b in f["blocks"])

    xr = _yukle(go / "xrefs.json")
    n_str_kul = sum(len(v["strings_used"]) for v in xr["function_xrefs"].values())
    n_glob = xr["statistics"]["total_globals_with_xrefs"]

    n_op = 0
    n_vn = 0
    n_var = 0
    pj = go / "pcode.jsonl"
    if pj.exists():
        with pj.open(encoding="utf-8") as fh:
            for line in fh:
                r = json.loads(line)
                for op in r["ops"]:
                    n_op += 1
                    n_vn += (1 if op[1] is not None else 0) + len(op[2])
                n_var += len(r["vars"])
    pc = _yukle(go / "pcode.json")
    toplam_op_tum = None  # seçici olmayan op'lar da yinelenir; sayı bilinmiyor (alt sınır)

    # Çarpanlar (alt sınır), satırlar headless.py:
    gecis = {}
    # _extract_functions 759-784: fonksiyon başına ~12 + parametre başına ~4
    gecis["functions (759-784)"] = n_fn * 12 + n_param * 4
    # _extract_call_graph 890-930: fonksiyon başına ~6 (+ çağıran başına ~6);
    # gövdedeki HER ADRES için hasNext + next + getReferencesFrom = 3 (911-913)
    gecis["call_graph (890-930)"] = n_fn * 6 + cg_callers * 6 + adres * 3 + cg_edges_raw * 8
    # decompile içinde fonksiyon başına (1390-1579):
    #  _extract_disassembly 986-1022: komut başına hasNext,next,getMnemonicString,getAddress,str,
    #     getNumOperands, + işlenen başına 1, str(cu) → ~8
    #  _extract_func_xrefs 1062-1079: adres başına 3
    #  pcode seçici 1530-1558: TÜM op'lar için hasNext,next,getMnemonic (3; seçilmeyen op da)
    #     + seçilen op başına getOutput,getNumInputs (+ varnode başına getInput,getAddress,
    #     getAddressSpace,getName,str,getOffset,getSize ≈ 6)
    gecis["decompile: disassembly (986-1022)"] = n_komut * 8
    gecis["decompile: func xrefs (1062-1079)"] = adres * 3 + n_fn * 4
    gecis["decompile: pcode seçici (1530-1558, alt sınır)"] = n_op * (3 + 2) + n_vn * 6 + n_var * 8
    # _extract_xrefs 1737-1803: adres başına 3; dizgi başvurusu başına ~8; sembol başına ~4
    gecis["xrefs (1737-1803, sembol döngüsü hariç alt sınır)"] = adres * 3 + n_str_kul * 8 + n_glob * 4
    # _extract_cfg 2045-2111: blok başına ~10; komut başına hasNext,next,getMnemonicString,str = 4;
    # kenar başına ~9
    gecis["cfg (2045-2111)"] = n_blok * 10 + n_komut * 4 + n_kenar * 9

    sonuc = {
        "ad": a.ad, "fonksiyon": n_fn, "govde_adresi_toplami": adres, "parametre": n_param,
        "cg_kenar": cg_edges_raw, "cfg_blok": n_blok, "cfg_kenar": n_kenar, "komut": n_komut,
        "pcode_secici_op": n_op, "pcode_varnode": n_vn, "pcode_degisken": n_var,
        "xref_dizgi_kullanimi": n_str_kul, "xref_global": n_glob,
        "pcode_json_toplam_op": pc.get("total_pcode_ops"),
        "gecis_alt_sinir": gecis,
    }
    print("## %s: öğe sayıları" % a.ad)
    for k, v in sonuc.items():
        if k not in ("gecis_alt_sinir", "ad"):
            print("- %s: %s" % (k, v))
    print()
    print("| Adım (headless.py satırları) | geçiş (alt sınır, milyon) |")
    print("|---|---|")
    for k, v in gecis.items():
        print("| %s | %.1f |" % (k, v / 1e6))
    print("| TOPLAM | %.1f |" % (sum(gecis.values()) / 1e6))
    if a.cikti:
        c = a.cikti.expanduser()
        c.parent.mkdir(parents=True, exist_ok=True)
        c.write_text(json.dumps(sonuc, indent=1, ensure_ascii=False))


if __name__ == "__main__":
    main()
