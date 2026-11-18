"""karadul/lm/order.py: aşağıdan yukarı özet zincirinin katman sıralayıcısı (P22b kalem 2).

Tasarım: ``docs/arge/2026-11-18_karadullm_v2/TASARIM.md`` §3.6 madde 1 ve 5. Kilitlenen davranışlar:
yapraklar önce; güçlü bağlı bileşenin üyeleri aynı katmanda; kapanış derinliği; belirlenimcilik
(``PYTHONHASHSEED`` ve girdi sırasından bağımsız); bağımsız kaba kuvvet hesabıyla eşitlik.

Mutasyon koruması: ``scripts/measurement/mutation_specs_lm_ozet.json`` (``or_*``).
"""
from __future__ import annotations

import json
import os
import random
import subprocess
import sys
from pathlib import Path

import pytest

from karadul.lm import order as O

KOK = Path(__file__).resolve().parents[1]


def h(n: int) -> str:
    return f"{n:x}"


def test_dag_katmanlari_yapraklar_once():
    # 10 → 20 → 30 ; 10 → 40 ; 50 yalnız
    e = {"10": {"20", "40"}, "20": {"30"}}
    assert O.layers(["10", "20", "30", "40", "50"], e) == [("30", "40", "50"), ("20",), ("10",)]
    assert O.layer_of(O.layers(["10", "20", "30", "40"], e)) == {"30": 0, "40": 0, "20": 1, "10": 2}


def test_dongu_ayni_katmanda_cagirani_ustte():
    # 20 ↔ 30 döngü; 10 onu çağırır; 30 → 40 yaprak; 50 kendini çağırır
    e = {"10": ["20"], "20": ["30"], "30": ["20", "40"], "50": ["50"]}
    sccs = O.strongly_connected_components(["10", "20", "30", "40", "50"], e)
    assert sorted(sccs) == [("10",), ("20", "30"), ("40",), ("50",)]
    assert O.layers(["10", "20", "30", "40", "50"], e) == [("40", "50"), ("20", "30"), ("10",)]
    # Tarjan sırası: bir bileşenin ardılları ondan önce
    pos = {c: i for i, c in enumerate(sccs)}
    assert pos[("40",)] < pos[("20", "30")] < pos[("10",)]


def test_dugum_kumesi_disindaki_kenar_yok_sayilir_ve_bos():
    e = {"10": ["20", "ff"], "20": []}
    assert O.layers(["10", "20"], e) == [("20",), ("10",)]
    assert O.layers([], e) == [] and O.strongly_connected_components([], e) == []
    with pytest.raises(ValueError):
        O.layers(["10", "xyz"], {})
    with pytest.raises(ValueError):
        O.callee_closure({}, "zz")


def test_kapanis_derinligi():
    e = {"1": ["2", "5"], "2": ["3"], "3": ["4"], "5": ["1"]}
    assert O.DEFAULT_CLOSURE_DEPTH == 2
    assert O.callee_closure(e, "1", 0) == ["1"]
    assert O.callee_closure(e, "1", 1) == ["1", "2", "5"]
    assert O.callee_closure(e, "1") == ["1", "2", "3", "5"]          # derinlik 2: 4 dışarıda
    assert O.callee_closure(e, "1", 3) == ["1", "2", "3", "4", "5"]
    for bozuk in (-1, True, 1.0):
        with pytest.raises(ValueError):
            O.callee_closure(e, "1", bozuk)
    # Kapanışın katmanları: yalnız kapanış kenarları (3 → 4 kenarı kapanış dışında)
    assert O.bottom_up_layers(e, "1") == [("3",), ("2",), ("1", "5")]
    assert O.bottom_up_layers(None, "1") == [("1",)]                 # grafik yok: yalnız kök
    with pytest.raises(ValueError):
        O.bottom_up_layers(None, "q")


def _kaba(nodes: list[str], edges: dict) -> list[tuple[str, ...]]:
    """Bağımsız hesap: erişilebilirlik kapanışından bileşenler, en uzun yoldan katman."""
    reach = {a: {a} for a in nodes}
    changed = True
    while changed:
        changed = False
        for a in nodes:
            for b in list(reach[a]):
                for c in edges.get(b, ()):
                    if c in reach and c not in reach[a]:
                        reach[a].add(c)
                        changed = True
    comp = {a: frozenset(b for b in nodes if b in reach[a] and a in reach[b]) for a in nodes}
    memo: dict = {}

    def lvl(c):
        if c not in memo:
            deps = {comp[y] for x in c for y in edges.get(x, ()) if y in comp and comp[y] != c}
            memo[c] = 1 + max(lvl(d) for d in deps) if deps else 0
        return memo[c]

    out: dict[int, list[str]] = {}
    for a in nodes:
        out.setdefault(lvl(comp[a]), []).append(a)
    return [tuple(sorted(out[i], key=lambda x: int(x, 16))) for i in range(len(out))]


@pytest.mark.parametrize("tohum", range(25))
def test_rastgele_grafiklerde_kaba_kuvvetle_ayni(tohum):
    rnd = random.Random(tohum)
    n = rnd.randint(1, 30)
    nodes = [h(rnd.randint(0x1000, 0x1fff)) for _ in range(n)]
    nodes = sorted(set(nodes), key=lambda x: int(x, 16))
    edges = {a: {rnd.choice(nodes) for _ in range(rnd.randint(0, 4))} for a in nodes}
    beklenen = _kaba(nodes, edges)
    assert O.layers(nodes, edges) == beklenen
    # Girdi sırası (düğüm listesi, sözlük ve küme sırası) sonucu değiştirmez
    ters = {a: list(reversed(sorted(edges[a]))) for a in reversed(nodes)}
    assert O.layers(list(reversed(nodes)), ters) == beklenen


_ALT_SUREC = r"""
import json, random, sys
from karadul.lm import order as O
rnd = random.Random(7)
nodes = sorted({f"{rnd.randint(0x400000, 0x4fffff):x}" for _ in range(300)}, key=lambda x: int(x, 16))
edges = {a: {rnd.choice(nodes) for _ in range(rnd.randint(0, 5))} for a in nodes}
print(json.dumps([O.layers(nodes, edges), O.strongly_connected_components(nodes, edges),
                  O.bottom_up_layers(edges, nodes[0], 3)]))
"""


def test_pythonhashseed_bagimsiz():
    ciktilar = set()
    for tohum in ("0", "1", "12345", "random"):
        env = dict(os.environ, PYTHONHASHSEED=tohum, PYTHONPATH=str(KOK), PYTHONDONTWRITEBYTECODE="1")
        r = subprocess.run([sys.executable, "-c", _ALT_SUREC], cwd=KOK, env=env, capture_output=True, text=True,
                           timeout=120, check=True)
        ciktilar.add(r.stdout)
    assert len(ciktilar) == 1 and json.loads(next(iter(ciktilar)))[0]


def test_derin_zincir_ozyinelemesiz():
    n = 20000
    nodes = [h(0x10000 + i) for i in range(n)]
    edges = {nodes[i]: [nodes[i + 1]] for i in range(n - 1)}
    lay = O.layers(nodes, edges)
    assert len(lay) == n and lay[0] == (nodes[-1],) and lay[-1] == (nodes[0],)
    edges[nodes[-1]] = [nodes[0]]                       # tek büyük döngü
    assert O.layers(nodes, edges) == [tuple(nodes)]


def test_modul_ice_aktarma_siniri():
    import ast
    agac = ast.parse((KOK / "karadul" / "lm" / "order.py").read_text(encoding="utf-8"))
    adlar = {a.name.split(".")[0] for d in ast.walk(agac) if isinstance(d, ast.Import) for a in d.names}
    adlar |= {d.module.split(".")[0] for d in ast.walk(agac) if isinstance(d, ast.ImportFrom) and d.module}
    assert adlar <= {"__future__", "typing"}
