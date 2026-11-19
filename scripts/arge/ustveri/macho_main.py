"""I2: Mach-O'da `LC_MAIN` girişi `main` mi? (ARGE, ÜST VERİ hattı; ürün kodu değil)

İki ölçüm:
A. Geliştirme setinin Mach-O ikilileri + P-S3b Mach-O kabul seti (GT'li, ürün koşusu var):
   soyulmuş ikilinin `LC_MAIN` giriş adresi ↔ GT'deki `_main`; Ghidra'nın o adresteki adı; ürünün verdiği ad;
   `stats.main_recovered`; decompile çıktısında `__libc_start_main` geçiyor mu.
B. Geniş nüfus: verilen dizinlerdeki sembollü Mach-O çalıştırılabilirlerinde `LC_MAIN` giriş adresi ↔ `_main` sembolü.

Kullanım:
    PYTHONDONTWRITEBYTECODE=1 python scripts/arge/ustveri/macho_main.py gt --cikti x.json
    PYTHONDONTWRITEBYTECODE=1 python scripts/arge/ustveri/macho_main.py nufus /opt/homebrew/Cellar --cikti y.json
İkilileri çalıştırmaz.
"""
from __future__ import annotations

import argparse
import collections
import json
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import macho  # noqa: E402

EV = Path.home()
DEPO = Path(__file__).resolve().parents[3]

GT_BIRIMLERI = [
    # (ad, korpus kökü, ürün koşusunun ws kökü)
    ("htop", DEPO / "workspaces/olcum_mac/corpus", EV / "karadul_olcum/runs/urun-onarim-a62f15e/mac/htop/ws"),
    ("tmux", DEPO / "workspaces/olcum_mac/corpus", EV / "karadul_olcum/runs/urun-onarim-a62f15e/mac/tmux/ws"),
] + [
    (ad, EV / "karadul_olcum/runs/onarim-2026-11-18/P-S3b/mac_kabul/corpus",
     EV / f"karadul_olcum/runs/onarim-2026-11-18/P-S3b/B/macgnu/{ad}/ws")
    for ad in ("gettext", "envsubst", "idn2", "gsort", "gmktemp", "xz")
]


def _son_kosu(ws: Path):
    adaylar = sorted(ws.glob("workspaces/*/*/static/ghidra_functions.json"))
    return adaylar[-1].parent.parent if adaylar else None


def gt_olc():
    satirlar = []
    for ad, korpus, ws in GT_BIRIMLERI:
        r = {"ikili": ad}
        soyulmus = korpus / ad / "bin" / ad
        gt_yol = korpus / ad / "gt" / f"{ad}.gt.json"
        if not soyulmus.is_file() or not gt_yol.is_file():
            r["durum"] = "veri yok"
            satirlar.append(r)
            continue
        m = macho.load_all(soyulmus)[-1] if len(macho.fat_slices(soyulmus.read_bytes())) > 1 else macho.load(soyulmus)
        giris = m.entry_vm
        gt = json.loads(gt_yol.read_text())
        gt_ad = {int(f["addr"], 16): f["names"] for f in gt["functions"]}
        main_adr = [a for a, n in gt_ad.items() if "_main" in n]
        r.update({
            "dilim": m.cpu, "LC_MAIN": m.entryoff is not None, "giris": hex(giris) if giris else None,
            "gt_main": hex(main_adr[0]) if main_adr else None,
            "giris_gt_main_mi": bool(main_adr) and giris == main_adr[0],
            "gt_giristeki_ad": gt_ad.get(giris),
            "soyulmus_sembol": len(m.symbols()),
        })
        kosu = _son_kosu(ws)
        if kosu is None:
            r["urun_kosusu"] = "yok"
            satirlar.append(r)
            continue
        gf = json.loads((kosu / "static/ghidra_functions.json").read_text())
        gf = gf["functions"] if isinstance(gf, dict) else gf
        g_adr = {int(f["address"], 16): f for f in gf}
        g = g_adr.get(giris)
        r["ghidra_giristeki_ad"] = g["name"] if g else None
        r["ghidra_giris_thunk"] = bool(g and g.get("is_thunk"))
        r["ghidra_giris_boyut"] = g.get("size") if g else None
        r["ghidra_main_adli"] = [f["address"] for f in gf if f["name"] in ("main", "_main")]
        # ürünün ad haritası: `entry` anahtarına ad verilmiş mi; `main` adı herhangi bir fonksiyona verilmiş mi
        harita = None
        for aday in ("reconstructed/naming_map.json", "deobfuscated/naming_map.json", "static/naming_map.json"):
            p = kosu / aday
            if p.is_file():
                harita = json.loads(p.read_text())
                r["ad_haritasi"] = aday
                break
        if harita is None:
            bul = sorted(kosu.rglob("naming_map.json"))
            if bul:
                harita = json.loads(bul[0].read_text())
                r["ad_haritasi"] = str(bul[0].relative_to(kosu))
        if harita is not None:
            es = harita.get("mappings", harita)
            r["urun_entry_adi"] = es.get("entry")
            r["urun_main_verilen"] = [k for k, v in es.items() if v == "main"][:3]
        # stats.main_recovered ve decompile çıktısında __libc_start_main
        rapor = None
        for p in sorted(kosu.rglob("report.json")):
            rapor = p
            break
        if rapor:
            metin = rapor.read_text(errors="ignore")
            mm = re.search(r'"main_recovered"\s*:\s*"([^"]+)"', metin)
            r["main_recovered"] = mm.group(1) if mm else None
        dec = kosu / "static/ghidra_output/decompiled"
        if dec.is_dir():
            n = 0
            for c in dec.rglob("*.c"):
                if "__libc_start_main" in c.read_text(errors="ignore"):
                    n += 1
            r["libc_start_main_gecen_dosya"] = n
        satirlar.append(r)
    return satirlar


def nufus_olc(kokler):
    say = collections.Counter()
    ornek = collections.defaultdict(list)
    gorulen = set()
    for kok in kokler:
        for dizin, _alt, dosyalar in os.walk(kok):
            if "/bin" not in dizin and not dizin.endswith("/bin") and "/MacOS" not in dizin:
                continue
            for d in dosyalar:
                yol = os.path.join(dizin, d)
                if os.path.islink(yol) or not os.path.isfile(yol):
                    continue
                try:
                    with open(yol, "rb") as f:
                        bas = f.read(4)
                    if bas not in (b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe"):
                        continue
                    ger = os.path.realpath(yol)
                    if ger in gorulen:
                        continue
                    gorulen.add(ger)
                    dilimler = macho.load_all(yol)
                except Exception:
                    say["okunamadi"] += 1
                    continue
                m = next((x for x in dilimler if x.cpu == "arm64"), dilimler[0])
                if m.filetype != 2:  # MH_EXECUTE
                    continue
                say["calistirilabilir"] += 1
                if m.entryoff is None:
                    say["LC_MAIN_yok"] += 1
                    continue
                giris = m.entry_vm
                adlar = collections.defaultdict(set)
                main_adr = None
                for s in m.defined_symbols():
                    adlar[s.value].add(s.name)
                    if s.name == "_main":
                        main_adr = s.value
                if main_adr is None:
                    say["main_sembolu_yok"] += 1
                    go = bool(m.secs_named("__gopclntab"))
                    say["main_sembolu_yok_go" if go else "main_sembolu_yok_diger"] += 1
                    continue
                say["main_sembollu"] += 1
                if giris == main_adr:
                    say["giris_main"] += 1
                else:
                    say["giris_main_degil"] += 1
                    if len(ornek["giris_main_degil"]) < 8:
                        ornek["giris_main_degil"].append((yol, sorted(adlar.get(giris, []))[:2]))
    return {"sayim": dict(say), "ornek": dict(ornek)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("kip", choices=["gt", "nufus"])
    ap.add_argument("kok", nargs="*")
    ap.add_argument("--cikti")
    a = ap.parse_args()
    r = gt_olc() if a.kip == "gt" else nufus_olc(a.kok)
    s = json.dumps(r, ensure_ascii=False, indent=1)
    if a.cikti:
        Path(a.cikti).write_text(s + "\n")
    print(s)


if __name__ == "__main__":
    main()
