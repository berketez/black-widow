"""Kalem 7 — hedef başına üst veri bütçesi.

Fonksiyon nüfusu: `LC_FUNCTION_STARTS` (yoksa Go `pclntab` girişleri; tabloda işaretlenir).
Sütunlar (adres kümeleri, hepsi nüfusla kesiştirilir):
  kesin        = Go `pclntab` adı ∪ ObjC yöntem listesi IMP'i ∪ Swift tip erişim fonksiyonu
  yuva         = Swift vtable / geçersiz kılma / tanık yuvası ∪ C++ vtable yuvası (tip adı + yuva sırası; yöntem adı yok)
  sembol       = ikilinin kendi sembol tablosunda kod sembolü olan başlangıçlar (soyulmuş hâliyle)
  kalan        = nüfus − kesin − sembol

Kullanım:
    PYTHONDONTWRITEBYTECODE=1 python scripts/arge/ustveri/butce.py --cikti x.json <ad=yol[:dilim]> …
İkilileri çalıştırmaz.
"""
from __future__ import annotations

import argparse
import collections
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import cpp_rtti_tara  # noqa: E402
import go_pclntab as G  # noqa: E402
import macho  # noqa: E402
import objc_meta  # noqa: E402
import swift_meta  # noqa: E402


def wilson(k: int, n: int, z: float = 1.959964):
    """Wilson %95 aralığı (scripts/measurement/ks1_olc.py `oran` ile aynı formül)."""
    if n == 0:
        return None
    ph = k / n
    payda = 1 + z * z / n
    orta = (ph + z * z / (2 * n)) / payda
    yari = z * ((ph * (1 - ph) / n + z * z / (4 * n * n)) ** 0.5) / payda
    return [round(max(0.0, orta - yari), 4), round(min(1.0, orta + yari), 4)]


def butce(ad, yol, dilim):
    m = macho.load(yol, dilim)
    r = {"ad": ad, "dilim": m.cpu}
    go_ad = {}
    go_sinif = {}
    if m.secs_named("__gopclntab"):
        p = G.PclnTab(m)
        bi = G.buildinfo(m) or {}
        modul = bi.get("mod") or ("/".join(bi["path"].split("/")[:3]) if bi.get("path") else None)
        for f in p.funcs():
            if f.name:
                go_ad[f.entry] = f.name
                go_sinif[f.entry] = G.sinif(G.pkg_of(f.name), modul)
        r["go_surumu"] = bi.get("surum")
    fs = m.function_starts()
    if fs is None:
        nufus = set(go_ad) | ({m.entry_vm} if m.entry_vm else set())
        r["nufus_kaynagi"] = "pclntab girişleri (LC_FUNCTION_STARTS yok)"
    else:
        nufus = set(fs)
        r["nufus_kaynagi"] = "LC_FUNCTION_STARTS"
    # ObjC
    objc = set()
    if m.secs_named("__objc_classlist") or m.secs_named("__objc_catlist"):
        _o, _s, _k, _p, satirlar = objc_meta.yontemler(m)
        objc = {s["imp"] for s in satirlar if s["imp"] and s["sinif"] and s["secici"]}
    # Swift
    sw_erisim = set()
    sw_yuva = set()
    if m.secs_named("__swift5_types"):
        sw = swift_meta.Swift(m)
        tipler = sw.types()
        sw_erisim = {t["erisim"] for t in tipler if t["erisim"]}
        for t in tipler:
            for y in t["yontem"]:
                if y[4]:
                    sw_yuva.add(y[4])
            for a in t["gecersiz_kilma"]:
                if a:
                    sw_yuva.add(a)
        text = m.text_sections()
        wt = {}
        for u in sw.conformances():
            if u["wt"] and m.ptr(u["wt"]) == u["adres"]:
                wt[u["wt"]] = u
        for w, u in wt.items():
            sinir = m.u32(u["protokol_adres"] + 16) if u["protokol_adres"] else None
            j = 1
            while True:
                if sinir is not None and j > sinir:
                    break
                a = w + 8 * j
                if sinir is None and (a in wt or j > 512):
                    break
                pv = m.ptr(a)
                if isinstance(pv, int) and any(t.addr <= pv < t.addr + t.size for t in text):
                    sw_yuva.add(pv)
                elif sinir is None:
                    break
                j += 1
    # C++ RTTI
    rtti = set()
    rtti_sinif = 0
    try:
        sonuc = cpp_rtti_tara.tara(m)
    except Exception:
        sonuc = None
    if sonuc:
        ti, vt = sonuc
        rtti_sinif = len(ti)
        for v in vt:
            for h in v["yuva"]:
                if h:
                    rtti.add(h)
    tsec = {t.index for t in m.text_sections()}
    sembol = {s.value for s in m.defined_symbols() if s.n_sect in tsec}

    go = set(go_ad) & nufus
    objc &= nufus
    sw_erisim &= nufus
    kesin = go | objc | sw_erisim
    yuva = ((sw_yuva | rtti) & nufus) - kesin
    sembol &= nufus
    n = len(nufus)
    r.update({
        "nufus": n,
        "go_adi": len(go), "objc_yontemi": len(objc), "swift_erisim": len(sw_erisim),
        "kesin": len(kesin), "kesin_oran": round(len(kesin) / n, 4) if n else None,
        "kesin_wilson95": wilson(len(kesin), n),
        "swift_yuva": len((sw_yuva & nufus) - kesin), "rtti_yuva": len((rtti & nufus) - kesin),
        "rtti_sinif_adi": rtti_sinif,
        "yuva": len(yuva),
        "sembol": len(sembol),
        "kesin_sembolsuz": len(kesin - sembol),
        "kesin_veya_sembol": len(kesin | sembol),
        "kalan": len(nufus - kesin - sembol),
        "kalanin_yuvalisi": len(yuva - sembol),
        "kalan_oran": round(len(nufus - kesin - sembol) / n, 4) if n else None,
    })
    if go_sinif:
        c = collections.Counter(go_sinif[a] for a in go)
        r["go_sinif"] = dict(c)
        r["go_disi_nufus"] = len(nufus - set(go_ad))
        r["go_disi_kesin"] = len((objc | sw_erisim) - set(go_ad))
        r["go_disi_sembol"] = len(sembol - set(go_ad))
        r["go_disi_kalan"] = len(nufus - set(go_ad) - objc - sw_erisim - sembol)
    return r


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("hedef", nargs="+", help="ad=yol[:dilim]")
    ap.add_argument("--cikti")
    a = ap.parse_args()
    out = []
    for h in a.hedef:
        ad, yol = h.split("=", 1)
        dilim = None
        if ":" in yol:
            yol, dilim = yol.rsplit(":", 1)
        out.append(butce(ad, yol, dilim))
    s = json.dumps(out, ensure_ascii=False, indent=1)
    if a.cikti:
        Path(a.cikti).write_text(s + "\n")
    for r in out:
        print(json.dumps(r, ensure_ascii=False))


if __name__ == "__main__":
    main()
