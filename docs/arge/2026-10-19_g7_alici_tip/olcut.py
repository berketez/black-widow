#!/usr/bin/env python3
"""G7 alıcı tip kümeleri: ölçüt tanımları (ön kayıt §5-§8 ile birlikte mühürlenir).

Bu modül yalnız saf fonksiyonlar içerir; girdi okumaz, dosya yazmaz.
- önek: Ö1 (ilk parça), Ö2 (son parça hariç, en çok iki parça); tek parçalı adların öneki yok
- küme saflığı: en sık önekin payı; ağırlıklı (mikro) ortalama, medyan, boyut dilimleri
- kapsam: kümeye düşme, çapalı kümeye düşme (Wilson %95), talimat ağırlıklı
- yayılım benzetimi: çapaların oybirliğiyle önerdiği önek; çelişkide öneri yok
- negatif kontrol: boyutlar korunarak karıştırılmış kümelerin saflığı
"""
from __future__ import annotations

import hashlib
import math
import random
from collections import Counter
from collections.abc import Iterable

SEED_BASE = "karadul-g7-alici-tip-2026-10-19"
R_SHUFFLE = 1000
B_BOOT = 1000
PURITY_THRESHOLD = 0.90          # plan v2 G8 karar kuralı
CONTROL_P_MAX = 0.01             # negatif kontrol: p < 0,01
CONTROL_MIN_GAP = 0.10           # ve gerçek − karışık ortalama ≥ 10 puan
SIZE_BINS = [(2, 2), (3, 5), (6, 10), (11, 50), (51, 200), (201, 10 ** 9)]
LEVELS = (1, 2)


def seed_for(*parts: object) -> int:
    key = "-".join([SEED_BASE, *map(str, parts)])
    return int(hashlib.sha256(key.encode()).hexdigest()[:16], 16)


# --------------------------------------------------------------------------- önek

def tokens(name: str) -> list[str]:
    return [t for t in name.split("_") if t]


def prefix(name: str, level: int) -> str | None:
    """Ö1: ilk parça. Ö2: son parça hariç en çok iki parça. Tek parçalı: None."""
    t = tokens(name)
    if len(t) < 2:
        return None
    if level == 1:
        return t[0]
    return "_".join(t[: min(2, len(t) - 1)])


def prefix_set(names: Iterable[str] | None, level: int) -> frozenset[str]:
    if not names:
        return frozenset()
    return frozenset(p for p in (prefix(n, level) for n in names) if p is not None)


# --------------------------------------------------------------------------- birleştirme

class UnionFind:
    def __init__(self) -> None:
        self.parent: dict = {}

    def find(self, x):
        self.parent.setdefault(x, x)
        root = x
        while self.parent[root] != root:
            root = self.parent[root]
        while self.parent[x] != root:
            self.parent[x], x = root, self.parent[x]
        return root

    def union(self, a, b) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            if repr(ra) < repr(rb):
                self.parent[rb] = ra
            else:
                self.parent[ra] = rb


def clusters_from(uf: UnionFind, universe: Iterable[str]) -> dict[str, int]:
    """Her fonksiyona küme kimliği: (f,1) düğümünün kökü; düğümü olmayan tekildir."""
    roots: dict = {}
    out: dict[str, int] = {}
    for f in sorted(universe):
        node = (f, 1)
        key = uf.find(node) if node in uf.parent else ("tekil", f)
        out[f] = roots.setdefault(key, len(roots))
    return out


def members_by_cluster(cl: dict[str, int]) -> dict[int, list[str]]:
    out: dict[int, list[str]] = {}
    for f, c in cl.items():
        out.setdefault(c, []).append(f)
    return out


# --------------------------------------------------------------------------- saflık

def cluster_purity(prefsets: list[frozenset[str]]) -> tuple[int, int, Counter]:
    """(en sık önekli üye sayısı, değerlendirilen üye sayısı, önek sayımı)."""
    cnt: Counter = Counter()
    for ps in prefsets:
        for p in ps:
            cnt[p] += 1
    best = max(cnt.values()) if cnt else 0
    return best, len(prefsets), cnt


def purity_table(groups: list[list[frozenset[str]]]) -> dict:
    """groups: değerlendirilen kümelerin (≥ 2 önekli üye) üye önek kümeleri."""
    rows = [cluster_purity(g) for g in groups]
    tot_best = sum(b for b, _, _ in rows)
    tot_n = sum(n for _, n, _ in rows)
    vals = sorted(b / n for b, n, _ in rows)
    out = {
        "kume_sayisi": len(rows),
        "uye": tot_n,
        "agirlikli": tot_best / tot_n if tot_n else None,
        "makro": sum(vals) / len(vals) if vals else None,
        "medyan": median(vals),
        "ceyrekler": quantiles(vals),
        "esik_ustu_kume_payi": (sum(1 for v in vals if v >= PURITY_THRESHOLD) / len(vals)
                                if vals else None),
        "boyut_dilimleri": [],
    }
    for lo, hi in SIZE_BINS:
        sel = [(b, n) for b, n, _ in rows if lo <= n <= hi]
        if sel:
            out["boyut_dilimleri"].append({
                "dilim": f"{lo}-{hi}" if hi < 10 ** 9 else f"{lo}+",
                "kume": len(sel), "uye": sum(n for _, n in sel),
                "agirlikli": sum(b for b, _ in sel) / sum(n for _, n in sel)})
    return out


def median(vals: list[float]) -> float | None:
    if not vals:
        return None
    m = len(vals) // 2
    return vals[m] if len(vals) % 2 else (vals[m - 1] + vals[m]) / 2


def quantiles(vals: list[float]) -> list[float] | None:
    if not vals:
        return None
    def q(p: float) -> float:
        k = (len(vals) - 1) * p
        lo, hi = math.floor(k), math.ceil(k)
        return vals[lo] + (vals[hi] - vals[lo]) * (k - lo)
    return [vals[0], q(0.25), q(0.5), q(0.75), vals[-1]]


def shuffle_control(groups: list[list[frozenset[str]]], seed: int) -> dict:
    """Boyutlar korunarak üyeler rastgele kümelere dağıtılır; ağırlıklı saflık yeniden ölçülür."""
    real = purity_table(groups)["agirlikli"]
    sizes = [len(g) for g in groups]
    pool = [ps for g in groups for ps in g]
    rng = random.Random(seed)
    vals = []
    for _ in range(R_SHUFFLE):
        rng.shuffle(pool)
        i, best = 0, 0
        for s in sizes:
            best += cluster_purity(pool[i:i + s])[0]
            i += s
        vals.append(best / len(pool))
    vals.sort()
    mean = sum(vals) / len(vals)
    p = (1 + sum(1 for v in vals if v >= real)) / (1 + len(vals))
    return {
        "gercek": real, "karisik_ortalama": mean,
        "karisik_2_5": vals[int(0.025 * len(vals))], "karisik_97_5": vals[int(0.975 * len(vals)) - 1],
        "karisik_en_buyuk": vals[-1], "p": p, "fark": real - mean,
        "gecerli": bool(p < CONTROL_P_MAX and real - mean >= CONTROL_MIN_GAP),
    }


def bootstrap_purity(groups: list[list[frozenset[str]]], seed: int) -> list[float] | None:
    """Küme düzeyinde yeniden örneklemeyle ağırlıklı saflığın %95 aralığı."""
    if not groups:
        return None
    rows = [cluster_purity(g)[:2] for g in groups]
    rng = random.Random(seed)
    vals = []
    for _ in range(B_BOOT):
        smp = [rows[rng.randrange(len(rows))] for _ in rows]
        n = sum(x[1] for x in smp)
        vals.append(sum(x[0] for x in smp) / n)
    vals.sort()
    return [vals[int(0.025 * B_BOOT)], vals[int(0.975 * B_BOOT) - 1]]


# --------------------------------------------------------------------------- kapsam

def wilson(k: int, n: int, z: float = 1.959964) -> list[float] | None:
    if n == 0:
        return None
    p = k / n
    den = 1 + z * z / n
    mid = (p + z * z / (2 * n)) / den
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / den
    return [max(0.0, mid - half), min(1.0, mid + half)]


def rate(k: int, n: int) -> dict:
    return {"k": k, "n": n, "oran": k / n if n else None, "ci95": wilson(k, n)}


def weighted_rate(sel: Iterable[str], pop: list[str], w: dict[str, int]) -> float | None:
    tot = sum(w.get(f) or 0 for f in pop)
    return sum(w.get(f) or 0 for f in sel) / tot if tot else None


def propagate(pop: list[str], cl: dict[str, int], members: dict[int, list[str]],
              anchors: dict[str, str], gt_sets: dict[str, frozenset[str]], level: int) -> dict:
    """Çapa adlarının önekleri oybirliğiyle kümedeki çapasız isim bekleyenlere önerilir.

    anchors: adres → çapanın adı (Ç-O: GT adı; Ç-K: Karadul adı).
    gt_sets: adres → GT önek kümesi (bu düzeyde). Öneri yalnız puanlanır, GT öneriyi etkilemez.
    """
    proposed = correct = scored = conflict = no_prefix_anchor = 0
    for f in pop:
        if f in anchors:
            continue
        peers = [g for g in members[cl[f]] if g != f and g in anchors]
        if not peers:
            continue
        props = {p for p in (prefix(anchors[g], level) for g in peers) if p is not None}
        if not props:
            no_prefix_anchor += 1
            continue
        if len(props) > 1:
            conflict += 1
            continue
        proposed += 1
        (p,) = props
        if gt_sets[f]:
            scored += 1
            correct += p in gt_sets[f]
    return {"oneri": rate(proposed, len(pop)), "kesinlik": rate(correct, scored),
            "dogru_oneri_kapsami": rate(correct, len(pop)),
            "celiski_sustu": conflict, "oneksiz_capa": no_prefix_anchor,
            "puanlanamayan_oneri": proposed - scored}
