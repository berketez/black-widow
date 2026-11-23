#!/usr/bin/env python3
"""ÖL-10 kuru seçim aracı (OL10A; ``OL10_TASARIM.md`` §7.1 adım 5). Salt okur; Ghidra yok.

Var olan bir çalışma alanının K1 çıktılarıyla (``static/ghidra_{functions,strings,call_graph}.json``)
seçim kuralını koşar: sınıf / basamak sayımı, gövde baytı, seçim sha256'sı.

    python scripts/measurement/tembel_kuru.py --ws <çalışma alanı> [--ikili <dilim>] [--dilim arm64]
        [--ust-sinir N] [--cikti <json>] [--xref-denetle] [--permutasyon 20]
        [--ad-haritasi <naming_map.json>]
    python scripts/measurement/tembel_kuru.py --k0 <ikili> [--dilim arm64] [--cikti <json>]
    python scripts/measurement/tembel_kuru.py --sentetik 163141 [--tohum 0] [--cikti <json>]

- ``--xref-denetle``: türetilen (``tembel_xref.turet``) ↔ dökülen ``function_xrefs``; alan
  bazında fark sayımı; ``called_by`` ham ve sıra-normal ayrı.
- ``--permutasyon K``: girdi belgeleri 0 … K−1 tohumlarıyla karıştırılır; her tohumda sha256.
- ``--ad-haritasi``: ``global`` haritasının ``FUN_`` anahtarlarından kaçı ``⌊P/2⌋`` (P = program
  fonksiyonu) ve ``⌊N/2⌋`` (N = bütün fonksiyonlar) kesimlerinde seçili.
- ``--k0``: Ghidra çıktısı olmayan hedefte yalnız üst veri sınıf sayımı (TASLAK K0'da yoktur).
- ``--sentetik N``: N fonksiyonluk rastgele girdide ``sec`` süresi (H-A7).
"""
from __future__ import annotations

import argparse
import collections
import dataclasses
import json
import random
import sys
import time
from pathlib import Path
from typing import Any

DEPO = Path(__file__).resolve().parents[2]
if str(DEPO) not in sys.path:
    sys.path.insert(0, str(DEPO))  # betik olarak koşulunca bu ağacın karadul'u yüklensin

from karadul.core import tembel_girdi, tembel_secim, tembel_xref  # noqa: E402


def _oku(yol: Path) -> Any:
    return json.loads(Path(yol).read_text(encoding="utf-8", errors="replace"))


def _static(ws: Path) -> Path:
    s = Path(ws) / "static"
    return s if s.is_dir() else Path(ws)


def _goruntu_ac(ikili: str | None, dilim: str | None):
    if not ikili:
        return None
    from karadul.analyzers.ustveri import goruntu

    return goruntu.ac(ikili, dilim)


def _ust_veri(g):
    if g is None:
        return None, None
    from karadul.analyzers.ustveri import go_pclntab, objc

    return go_pclntab.oku(g), objc.oku(g)


def secim_ozeti(girdi: tembel_secim.SecimGirdisi, sonuc: tembel_secim.SecimSonucu) -> dict:
    sinif = tembel_secim.siniflandir(girdi)
    taslak = girdi.taslak
    program = [a for a in girdi.boyut if a not in taslak]
    program_bayt = sum(girdi.boyut[a] for a in program)
    basamak_bayt = collections.Counter()
    for o in sonuc.sira:
        basamak_bayt[o.basamak] += girdi.boyut.get(o.adres, 0)
    return {
        "kunye": sonuc.kunye(),
        "girdi_kunyesi": dict(girdi.kunye),
        "program_fonksiyonu": len(program),
        "program_govde_bayt": program_bayt,
        "basamak_govde_bayt": {b: basamak_bayt.get(b, 0) for b in tembel_secim.BASAMAKLAR},
        "secilmeyen_govde_bayt": sum(girdi.boyut.get(a, 0) for a in sonuc.secilmeyen),
        "giris_kumesi": [{"adres": f"{a:x}", "sinif": sinif[a]} for a in sorted(girdi.giris)
                         if a in sinif],
        "b1_sinif": dict(collections.Counter(o.sinif for o in sonuc.sira
                                             if o.basamak == tembel_secim.BASAMAK_GIRIS)),
    }


def _karistir(docs: tuple, rng: random.Random) -> tuple:
    fdoc, sdoc, cdoc = (json.loads(json.dumps(d)) for d in docs)
    rng.shuffle(fdoc["functions"])
    ss = sdoc.get("strings") or []
    for s in ss:
        if isinstance(s.get("xrefs"), list):
            rng.shuffle(s["xrefs"])
    rng.shuffle(ss)
    nodes = list((cdoc.get("nodes") or {}).items())
    rng.shuffle(nodes)
    for _k, n in nodes:
        for alan in ("callers", "callees"):
            if isinstance(n.get(alan), list):
                rng.shuffle(n[alan])
    cdoc["nodes"] = dict(nodes)
    return fdoc, sdoc, cdoc


def _karistir_ust_veri(go_s, objc_s, rng: random.Random):
    if go_s is not None and getattr(go_s, "fonksiyonlar", None):
        fs = list(go_s.fonksiyonlar)
        rng.shuffle(fs)
        go_s = dataclasses.replace(go_s, fonksiyonlar=fs)
    if objc_s is not None and getattr(objc_s, "yontemler", None):
        ys = list(objc_s.yontemler)
        rng.shuffle(ys)
        objc_s = dataclasses.replace(objc_s, yontemler=ys)
    return go_s, objc_s


def xref_denetle(static: Path, docs: tuple) -> dict:
    """Türetilen ↔ dökülen ``ghidra_xrefs.json`` (alan bazında fark sayımı)."""
    dokum = _oku(static / "ghidra_xrefs.json")
    tur = tembel_xref.turet(*docs)
    a, b = dokum.get("function_xrefs") or {}, tur["function_xrefs"]
    sayim = collections.Counter()
    for k in set(a) | set(b):
        x, y = a.get(k), b.get(k)
        if x is None or y is None:
            sayim["yalniz_dokumde" if y is None else "yalniz_turetilende"] += 1
            continue
        esit = True
        if x.get("name") != y.get("name"):
            sayim["name"] += 1
            esit = False
        if x.get("address") != y.get("address"):
            sayim["address"] += 1
            esit = False
        su_x, su_y = x.get("strings_used") or [], y.get("strings_used") or []
        if su_x != su_y:
            esit = False
            ax = [s.get("address") for s in su_x]
            ay = [s.get("address") for s in su_y]
            if set(ax) != set(ay):
                sayim["strings_used_kume"] += 1
            elif ax != ay:
                sayim["strings_used_sira"] += 1
            else:
                sayim["strings_used_value"] += 1
        if (x.get("functions_called") or []) != (y.get("functions_called") or []):
            esit = False
            kx = {(c.get("address"), c.get("name")) for c in x.get("functions_called") or []}
            ky = {(c.get("address"), c.get("name")) for c in y.get("functions_called") or []}
            sayim["functions_called_kume" if kx != ky else "functions_called_sira"] += 1
        cx, cy = x.get("called_by") or [], y.get("called_by") or []
        if cx != cy:
            sayim["called_by_ham"] += 1
        norm = (lambda L: sorted(((c.get("address") or ""), (c.get("name") or "")) for c in L))
        if norm(cx) != norm(cy):
            sayim["called_by_sira_normal"] += 1
            esit = False
        if esit:
            sayim["esit_sira_normal"] += 1
        if esit and cx == cy:
            sayim["esit_ham"] += 1
    st_d, st_t = dokum.get("statistics") or {}, tur["statistics"]
    return {
        "fonksiyon_dokum": len(a),
        "fonksiyon_turetilen": len(b),
        "sayim": dict(sayim),
        "statistics": {k: {"dokum": st_d.get(k), "turetilen": st_t.get(k)}
                       for k in ("total_functions", "total_strings_with_xrefs",
                                 "total_globals_with_xrefs")},
        "json_esit_sira_normal": sayim["esit_sira_normal"] == len(a) == len(b),
        "json_esit_ham": sayim["esit_ham"] == len(a) == len(b),
    }


def ad_haritasi_denetle(girdi, sonuc, harita_yolu: Path) -> dict:
    harita = _oku(harita_yolu).get("global") or {}
    program = {a for a in girdi.boyut if a not in girdi.taslak}
    adli, eslenmeyen = [], 0
    for k in harita:
        if not k.startswith("FUN_"):
            continue
        try:
            a = int(k[4:], 16)
        except ValueError:
            eslenmeyen += 1
            continue
        if a in program:
            adli.append(a)
        else:
            eslenmeyen += 1
    sonuc_d = {"fun_anahtari": len(adli) + eslenmeyen, "eslenen": len(adli),
               "eslenmeyen": eslenmeyen, "program_fonksiyonu": len(program),
               "fonksiyon": len(girdi.boyut)}
    for ad, n in (("yari_program", len(program) // 2), ("yari_hepsi", len(girdi.boyut) // 2)):
        secili = set(tembel_secim.kes(sonuc, n).adresler()) if n > 0 else set()
        sonuc_d[ad] = {"ust_sinir": n, "secili_adli": sum(1 for a in adli if a in secili)}
    return sonuc_d


def ws_kos(args) -> dict:
    static = _static(Path(args.ws))
    docs = tuple(_oku(static / f"ghidra_{ad}.json") for ad in ("functions", "strings", "call_graph"))
    g = _goruntu_ac(args.ikili, args.dilim)
    delta = tembel_girdi.taban_farki(static / "ghidra_functions.json", args.ikili) if args.ikili else 0
    go_s, objc_s = _ust_veri(g)
    girdi = tembel_girdi.girdiden_kur(*docs, g, delta=delta, go_sonuc=go_s, objc_sonuc=objc_s)
    t0 = time.perf_counter()
    sonuc = tembel_secim.sec(girdi)
    sure = time.perf_counter() - t0
    kesik = tembel_secim.kes(sonuc, args.ust_sinir)
    cikti = {"ws": str(args.ws), "ikili": args.ikili, "dilim": args.dilim,
             "sec_sure_sn": round(sure, 4), **secim_ozeti(girdi, sonuc)}
    if args.ust_sinir:
        cikti["kesim"] = kesik.kunye()
    if args.permutasyon:
        shalar = []
        for tohum in range(args.permutasyon):
            rng = random.Random(tohum)
            pdocs = _karistir(docs, rng)
            pg, po = _karistir_ust_veri(go_s, objc_s, rng)
            pgirdi = tembel_girdi.girdiden_kur(*pdocs, g, delta=delta, go_sonuc=pg, objc_sonuc=po)
            shalar.append(tembel_secim.sec(pgirdi).sha256)
        cikti["permutasyon"] = {"tohum": args.permutasyon, "farkli_sha": len(set(shalar)),
                                "hepsi_ayni_ve_esit": set(shalar) == {sonuc.sha256}}
    if args.xref_denetle:
        cikti["xref"] = xref_denetle(static, docs)
    if args.ad_haritasi:
        cikti["ad_haritasi"] = ad_haritasi_denetle(girdi, sonuc, Path(args.ad_haritasi))
    return cikti


def k0_kos(args) -> dict:
    g = _goruntu_ac(args.k0, args.dilim)
    go_s, objc_s = _ust_veri(g)
    adresler = set(g.fonksiyon_baslangiclari() or [])
    go_adres = {int(f.giris) for f in getattr(go_s, "fonksiyonlar", None) or []}
    objc_adres = {int(y.imp) for y in getattr(objc_s, "yontemler", None) or []
                  if isinstance(y.imp, int) and y.imp}
    tum = sorted(adresler | go_adres | objc_adres)
    fdoc = {"functions": [{"address": f"{a:x}", "size": 0, "name": ""} for a in tum]}
    girdi = tembel_girdi.girdiden_kur(fdoc, None, None, g, go_sonuc=go_s, objc_sonuc=objc_s)
    sinif = tembel_secim.siniflandir(girdi)
    ust_veri = go_adres | objc_adres
    sayim_ust = collections.Counter(sinif[a] for a in ust_veri if a in sinif)
    toplam_ust = sum(sayim_ust.values())
    return {
        "k0": str(args.k0), "dilim": args.dilim,
        "fonksiyon_baslangici": len(adresler),
        "adres_birlesimi": len(tum),
        "go_durum": getattr(go_s, "durum", None),
        "go_fonksiyon": len(go_adres),
        "go_ham_sinif": dict(collections.Counter(f.sinif for f in getattr(go_s, "fonksiyonlar", None) or [])),
        "objc_durum": getattr(objc_s, "durum", None),
        "objc_imp_adresi": len(objc_adres),
        "objc_kendi": sum(1 for a in objc_adres if sinif.get(a) == tembel_secim.SECIM_KENDI),
        "ust_veri_sinif": dict(sayim_ust),
        "ust_veri_toplam": toplam_ust,
        "standart_payi": (round(sayim_ust.get(tembel_secim.SECIM_STANDART, 0) / toplam_ust, 4)
                          if toplam_ust else None),
        "tum_sinif": dict(collections.Counter(sinif.values())),
        "girdi_kunyesi": dict(girdi.kunye),
    }


def sentetik_girdi(n: int, tohum: int = 0) -> tembel_secim.SecimGirdisi:
    """N fonksiyonluk rastgele girdi (üst veri yok; %10 taslak; ortalama 4 çağrı, 0,3 dizgi)."""
    rng = random.Random(tohum)
    adres = [0x100000 + 16 * i for i in range(n)]
    taslak = frozenset(a for a in adres if rng.random() < 0.10)
    cagrilan = {a: frozenset(rng.choice(adres) for _ in range(rng.randint(0, 8))) for a in adres}
    dizgiler = {a: frozenset(0x9000000 + rng.randrange(n) for _ in range(rng.randint(0, 1)))
                for a in adres if rng.random() < 0.3}
    return tembel_secim.SecimGirdisi(
        boyut={a: rng.randint(4, 400) for a in adres}, taslak=taslak, dizgiler=dizgiler,
        cagrilan=cagrilan, giris=frozenset({adres[0]}))


def sentetik_kos(args) -> dict:
    girdi = sentetik_girdi(args.sentetik, args.tohum)
    t0 = time.perf_counter()
    sonuc = tembel_secim.sec(girdi)
    sure = time.perf_counter() - t0
    return {"sentetik": args.sentetik, "tohum": args.tohum, "sec_sure_sn": round(sure, 3),
            "kunye": sonuc.kunye()}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--ws")
    p.add_argument("--ikili")
    p.add_argument("--dilim")
    p.add_argument("--ust-sinir", type=int, default=0)
    p.add_argument("--cikti")
    p.add_argument("--xref-denetle", action="store_true")
    p.add_argument("--permutasyon", type=int, default=0)
    p.add_argument("--ad-haritasi")
    p.add_argument("--k0")
    p.add_argument("--sentetik", type=int, default=0)
    p.add_argument("--tohum", type=int, default=0)
    args = p.parse_args(argv)
    if args.ws:
        cikti = ws_kos(args)
    elif args.k0:
        cikti = k0_kos(args)
    elif args.sentetik:
        cikti = sentetik_kos(args)
    else:
        p.error("--ws, --k0 ya da --sentetik gerekli")
        return 2
    metin = json.dumps(cikti, ensure_ascii=False, indent=1)
    if args.cikti:
        Path(args.cikti).write_text(metin + "\n", encoding="utf-8")
    print(metin)
    return 0


if __name__ == "__main__":
    sys.exit(main())
