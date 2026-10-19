#!/usr/bin/env python3
"""G7 alıcı tip kümeleri: kümeleri kurar, ölçütleri hesaplar, sonuc.json yazar.

Kullanım:
    python3 -B deney.py <veri_dizini> <sonuc.json>

<veri_dizini>: cikar.py çıktıları (<program>_cikti.json). Küme üyelikleri ayrıca
<veri_dizini>/<program>_<değişken>_kumeler.json olarak yazılır (git dışı).
Tanımlar: onkayit.md; ölçütler: olcut.py.
"""
from __future__ import annotations

import datetime as dt
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from olcut import (LEVELS, PURITY_THRESHOLD, UnionFind, bootstrap_purity,  # noqa: E402
                   cluster_purity, clusters_from, members_by_cluster, prefix_set,
                   propagate, purity_table, rate, seed_for, shuffle_control, weighted_rate)

PROGRAMS = ("tmux", "htop")
VARIANTS = ("V1", "V1-N", "V2", "V1+T")
PRIMARY = "V1"
SIZE_BINS_ALL = [(2, 2), (3, 5), (6, 10), (11, 50), (51, 200), (201, 10 ** 9)]


def build(data: dict, variant: str) -> UnionFind:
    uf = UnionFind()
    funcs = data["funcs"]
    if variant in ("V1", "V1-N", "V1+T"):
        for a, b in data["v1"]:
            if variant == "V1-N" and not funcs[b].get("p1_alan"):
                continue
            uf.union((a, 1), (b, 1))
    if variant == "V2":
        for a, k, b, j in data["v2"]:
            uf.union((a, k), (b, j))
    if variant == "V1+T":
        for run in data["tablo_kosulari"]:
            fs = [f for f in run if funcs[f]["params"]]
            for x in fs[1:]:
                uf.union((fs[0], 1), (x, 1))
    return uf


def anchor_sets(data: dict) -> dict[str, dict[str, str]]:
    funcs = data["funcs"]
    g = {a: funcs[a]["ad"] for a in data["capa_g"]}
    kplus = {a: n for a, n in data["capa_k"].items()
             if funcs[a]["pop"] and n in (funcs[a]["gt"] or [])}
    return {
        "Ç-G": dict(g),
        "Ç-O": {**data["capa_o"], **g},
        "Ç-K": {**data["capa_k"], **g},
        "Ç-K+": {**kplus, **g},
    }


def worst_clusters(members: dict[int, list[str]], data: dict, gt_sets: dict, level: int,
                   k: int = 5) -> list[dict]:
    funcs = data["funcs"]
    cand = []
    for c, ms in members.items():
        ev = [f for f in ms if funcs[f]["pop"] and gt_sets[f]]
        if len(ev) < 2:
            continue
        best, n, cnt = cluster_purity([gt_sets[f] for f in ev])
        if best / n < PURITY_THRESHOLD:
            cand.append((-n, best / n, min(ms), c, ev, cnt))
    cand.sort()
    out = []
    for negn, pur, _, c, ev, cnt in cand[:k]:
        top = cnt.most_common(8)
        out.append({
            "uye": -negn, "boyut": len(members[c]), "saflik": pur,
            "onekler": [[p, n] for p, n in top],
            "diger_onek_sayisi": max(0, len(cnt) - len(top)),
            "ornek": {p: sorted(funcs[f]["gt"][0] for f in ev if p in gt_sets[f])[:4]
                      for p, _ in top[:4]},
        })
    return out


def measure(data: dict, variant: str, veri: Path) -> dict:
    funcs = data["funcs"]
    universe = sorted(funcs)
    pop = sorted(a for a in universe if funcs[a]["pop"])
    insn = {a: funcs[a]["insn"] for a in universe}
    uf = build(data, variant)
    cl = clusters_from(uf, universe)
    members = members_by_cluster(cl)
    size = {a: len(members[cl[a]]) for a in universe}
    prog = data["program"]

    in_cluster = [f for f in pop if size[f] >= 2]
    multi = [ms for ms in members.values() if len(ms) >= 2]
    largest = max((len(ms) for ms in multi), default=0)
    largest_pop = max((sum(1 for f in ms if funcs[f]["pop"]) for ms in multi), default=0)
    res: dict = {
        "kume_sayisi_2plus": len(multi),
        "boyut_dagilimi": [{"dilim": f"{lo}-{hi}" if hi < 10 ** 9 else f"{lo}+",
                            "kume": sum(1 for ms in multi if lo <= len(ms) <= hi)}
                           for lo, hi in SIZE_BINS_ALL],
        "en_buyuk_kume": largest,
        "tek_kumedeki_en_buyuk_bekleyen_payi": largest_pop / len(pop),
        "kumeye_dusen": rate(len(in_cluster), len(pop)),
        "kumeye_dusen_talimat_agirlikli": weighted_rate(in_cluster, pop, insn),
        "tekil": rate(len(pop) - len(in_cluster), len(pop)),
        "capali": {},
        "duzey": {},
    }
    anchors = anchor_sets(data)
    for name, anc in anchors.items():
        sel = [f for f in pop if any(g != f and g in anc for g in members[cl[f]])]
        res["capali"][name] = {
            "capa_sayisi": len(anc), "capa_bekleyen_icinde": sum(1 for a in anc if a in pop),
            "kapsam": rate(len(sel), len(pop)),
            "kapsam_talimat_agirlikli": weighted_rate(sel, pop, insn),
        }
    for level in LEVELS:
        gt_sets = {f: prefix_set(funcs[f]["gt"], level) for f in pop}
        groups, pure_clusters = [], set()
        for c, ms in members.items():
            ev = [gt_sets[f] for f in ms if funcs[f]["pop"] and gt_sets[f]]
            if len(ev) >= 2:
                groups.append(ev)
                best, n, _ = cluster_purity(ev)
                if best / n >= PURITY_THRESHOLD:
                    pure_clusters.add(c)
        d = {
            "saflik": purity_table(groups),
            "saflik_bootstrap_ci95": bootstrap_purity(groups, seed_for(prog, variant, level, "b")),
            "negatif_kontrol": shuffle_control(groups, seed_for(prog, variant, level, "k")),
            "oneksiz_bekleyen": sum(1 for f in pop if not gt_sets[f]),
            "saf_kumedeki_bekleyen": rate(sum(1 for f in pop if cl[f] in pure_clusters), len(pop)),
            "saf_ve_capali": {},
            "yayilim": {},
            "en_kotu_5": worst_clusters(members, data, gt_sets, level),
        }
        for name, anc in anchors.items():
            sel = [f for f in pop if cl[f] in pure_clusters
                   and any(g != f and g in anc for g in members[cl[f]])]
            d["saf_ve_capali"][name] = rate(len(sel), len(pop))
            d["yayilim"][name] = propagate(pop, cl, members, anc, gt_sets, level)
        res["duzey"][f"Ö{level}"] = d

    dump = {"program": prog, "degisken": variant,
            "kumeler": [[{"adres": f, "gt": funcs[f]["gt"], "bekleyen": funcs[f]["pop"]}
                         for f in ms] for ms in sorted(multi, key=lambda m: (-len(m), m[0]))]}
    (veri / f"{prog}_{variant.replace('+', 'p')}_kumeler.json").write_text(
        json.dumps(dump, ensure_ascii=False, indent=0), encoding="utf-8")
    return res


def reading(per: dict) -> dict:
    """Ön kayıt §8: G8 karar kuralının mekanik okuması (birincil değişken V1)."""
    out = {}
    for prog, r in per.items():
        v = r["degiskenler"][PRIMARY]["duzey"]
        o1, o2 = v["Ö1"], v["Ö2"]
        p1, p2 = o1["saflik"]["agirlikli"], o2["saflik"]["agirlikli"]
        c1, c2 = o1["negatif_kontrol"]["gecerli"], o2["negatif_kontrol"]["gecerli"]
        if p1 is None:
            verdict = "değerlendirilemedi (değerlendirilen küme yok)"
        elif p1 < PURITY_THRESHOLD:
            verdict = "saf değil"
        elif not c1:
            verdict = "geçersiz (Ö1 saflığı negatif kontrolün belirgin üstünde değil)"
        elif p2 is not None and p2 >= PURITY_THRESHOLD and c2:
            verdict = "saf"
        else:
            verdict = "yalnız Ö1 düzeyinde saf"
        out[prog] = {"o1_agirlikli": p1, "o2_agirlikli": p2, "o1_kontrol": c1,
                     "o2_kontrol": c2, "karar": verdict}
    both = {x["karar"] for x in out.values()}
    out["genel"] = ("saf (iki programda da)" if both == {"saf"} else
                    "programa bağlı" if len(both) > 1 else next(iter(both)))
    return out


def main() -> int:
    veri, out_path = Path(sys.argv[1]), Path(sys.argv[2])
    started = dt.datetime.now().astimezone().isoformat(timespec="seconds")
    per = {}
    for prog in PROGRAMS:
        data = json.loads((veri / f"{prog}_cikti.json").read_text())
        funcs = data["funcs"]
        pop = [a for a in funcs if funcs[a]["pop"]]
        score = json.loads((Path(__file__).resolve().parents[3]
                            / "workspaces/olcum_mac/runs/taban-v2-62ad154" / prog
                            / "macho_score.json").read_text())
        prog_cls = score["summary"]["siniflar"]["program"]
        assert len(pop) == prog_cls["population"], (prog, len(pop), prog_cls["population"])
        kk = [a for a in data["capa_k"] if funcs[a]["pop"]]
        per[prog] = {
            "kunye": data["kunye"],
            "evren": data["evren"], "bekleyen": len(pop),
            "c_durum": data["c_durum"],
            "p1_olmayan_bekleyen": sum(1 for a in pop if not funcs[a]["params"]),
            "p1_degisen_bekleyen": sum(1 for a in pop if funcs[a]["params"]
                                       and funcs[a]["params"][0][2]),
            "dogrudan_ic_cagri": data["dogrudan_ic_cagri"],
            "cozulmeyen_FUN_cagri": data["cozulmeyen_FUN_cagri"],
            "v1_kenar": len(data["v1"]),
            "v1_kenar_tekil_cift": len({tuple(sorted(e)) for e in data["v1"]}),
            "v1n_kenar": sum(1 for a, b in data["v1"] if funcs[b].get("p1_alan")),
            "v2_kenar": len(data["v2"]),
            "tablo_kosusu": len(data["tablo_kosulari"]),
            "tablo_kosusundaki_fonksiyon": len({f for r in data["tablo_kosulari"] for f in r}),
            "pcode_v1_uyum": rate(*data["pcode_v1_uyum"]),
            "capa_k_kesinlik": rate(sum(1 for a in kk if data["capa_k"][a] in funcs[a]["gt"]),
                                    len(kk)),
            "karadul_bugun_isim_verdigi": rate(prog_cls["named"], prog_cls["population"]),
            "degiskenler": {v: measure(data, v, veri) for v in VARIANTS},
        }
    result = {
        "deney": "G7 alıcı tip kümesi saflığı (plan v2 §5 G7, G8 karar kuralı 3. satır)",
        "on_kayit": "docs/arge/2026-10-19_g7_alici_tip/onkayit.md",
        "baslangic": started,
        "bitis": dt.datetime.now().astimezone().isoformat(timespec="seconds"),
        "birincil_degisken": PRIMARY,
        "programlar": per,
        "g8_okuma": reading(per),
    }
    out_path.write_text(json.dumps(result, ensure_ascii=False, indent=1), encoding="utf-8")
    print(json.dumps(result["g8_okuma"], ensure_ascii=False, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
