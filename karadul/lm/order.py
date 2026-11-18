"""Aşağıdan yukarı özet zincirinin katman sıralayıcısı (KaradulLM v2 tasarımı §3.6 madde 1, madde 5).

Girdi çağrı grafiğidir (``Workspace.call_edges``: adres → çağırdığı adresler). Güçlü bağlı bileşenler
(Tarjan) tek düğüme yoğunlaştırılır; yoğun grafik döngüsüzdür ve katmanlara ayrılır:

- **Katman 0**: başka bir bileşeni çağırmayan bileşenler (yapraklar; kendini çağıran fonksiyon da).
- **Katman k**: çağırdığı bileşenlerin en yükseği k - 1 olan bileşen.

Bir bileşenin bütün üyeleri aynı katmandadır: döngüdeki fonksiyonlar birbirinin özetini görmez (özet
yalnız alt katmanlardan pakete girer). Aynı katmanda farklı bileşenler arasında kenar yoktur.

**Belirlenimcilik:** aynı girdi → aynı çıktı. Hiçbir sonuç küme ya da sözlük yineleme sırasına bağlı
değildir: düğümler ve ardılları adresin sayı değerine göre sıralanır (``PYTHONHASHSEED``'den bağımsız;
testle kilitli). Özyineleme yoktur (derin grafiklerde yığın taşmaz).

Kapanış (§3.6 madde 5 (a), Berke kararı 2 (a)): seçili fonksiyon ve çağırdıklarının derinlik
``DEFAULT_CLOSURE_DEPTH``'e kadarki kümesi; sıralama yalnız bu kümenin kenarlarıyla yapılır.

Bu modül dosya okumaz, süreç açmaz, ağa bağlanmaz.
"""
from __future__ import annotations

from typing import Iterable, Mapping, Optional, Sequence

# [seçim] Tasarım §3.6 madde 5 (a): isteğe bağlı özetin kapanış derinliği (önceki tasarımın D4
# kapanış derinliğiyle aynı; Berke kararı 2 (a)). Paketin sabit dosyası (``karadul/lm/__init__.py``)
# bu pakette yazılabilir değildi; tek tanım burasıdır, ajan buradan alır (P22b.md "taşınacaklar").
DEFAULT_CLOSURE_DEPTH = 2

Edges = Mapping[str, Iterable[str]]


def _key(a: str) -> tuple[int, str]:
    """Sıralama anahtarı: adresin sayı değeri (eşitlikte yazımı). Onaltılık olmayan adres hata."""
    if not isinstance(a, str):
        raise ValueError("adres dizgi olmalı")
    try:
        return int(a, 16), a
    except ValueError:
        raise ValueError(f"onaltılık olmayan adres: {a!r}") from None


def _sorted(nodes: Iterable[str]) -> list[str]:
    return sorted(set(nodes), key=_key)


def _successors(edges: Edges, nodes: set[str]) -> dict[str, list[str]]:
    """Yalnız ``nodes`` içindeki kenarlar; ardıllar sıralı, yinelenmesiz."""
    return {a: _sorted(b for b in edges.get(a, ()) if b in nodes) for a in nodes}


def strongly_connected_components(nodes: Iterable[str], edges: Edges) -> list[tuple[str, ...]]:
    """Güçlü bağlı bileşenler (Tarjan, yinelemeli). Bileşen üyeleri adrese göre sıralı; bileşenler
    Tarjan'ın bitirme sırasıyla (bir bileşenin ardılları ondan önce gelir). ``nodes`` dışındaki uçlar
    yok sayılır."""
    order = _sorted(nodes)
    node_set = set(order)
    succ = _successors(edges, node_set)
    index: dict[str, int] = {}
    low: dict[str, int] = {}
    on_stack: set[str] = set()
    stack: list[str] = []
    out: list[tuple[str, ...]] = []
    counter = 0
    for start in order:
        if start in index:
            continue
        work: list[tuple[str, int]] = [(start, 0)]
        index[start] = low[start] = counter
        counter += 1
        stack.append(start)
        on_stack.add(start)
        while work:
            v, i = work[-1]
            nexts = succ[v]
            if i < len(nexts):
                work[-1] = (v, i + 1)
                w = nexts[i]
                if w not in index:
                    index[w] = low[w] = counter
                    counter += 1
                    stack.append(w)
                    on_stack.add(w)
                    work.append((w, 0))
                elif w in on_stack:
                    low[v] = min(low[v], index[w])
                continue
            work.pop()
            if work:
                parent = work[-1][0]
                low[parent] = min(low[parent], low[v])
            if low[v] == index[v]:
                comp: list[str] = []
                while True:
                    w = stack.pop()
                    on_stack.discard(w)
                    comp.append(w)
                    if w == v:
                        break
                out.append(tuple(_sorted(comp)))
    return out


def layers(nodes: Iterable[str], edges: Edges) -> list[tuple[str, ...]]:
    """Katmanlar (yapraklar önce). Her katman adrese göre sıralı bir demettir; bir bileşenin üyeleri aynı
    katmandadır. ``nodes`` boşsa boş liste."""
    comps = strongly_connected_components(nodes, edges)
    if not comps:
        return []
    owner = {a: i for i, comp in enumerate(comps) for a in comp}
    level: list[int] = [0] * len(comps)
    # Tarjan bir bileşeni ardıllarından SONRA verir: bu sırayla gezmek her ardılın katmanını önceden bilir.
    for i, comp in enumerate(comps):
        deps = {owner[b] for a in comp for b in edges.get(a, ()) if b in owner and owner[b] != i}
        level[i] = 1 + max(level[j] for j in deps) if deps else 0
    out: list[list[str]] = [[] for _ in range(max(level) + 1)]
    for i, comp in enumerate(comps):
        out[level[i]].extend(comp)
    return [tuple(_sorted(layer)) for layer in out]


def callee_closure(edges: Edges, root: str, depth: int = DEFAULT_CLOSURE_DEPTH) -> list[str]:
    """``root`` ve çağırdıklarının en çok ``depth`` adım derinliğe kadarki kümesi (adrese göre sıralı)."""
    if not isinstance(depth, int) or isinstance(depth, bool) or depth < 0:
        raise ValueError("derinlik eksi olmayan tamsayı olmalı")
    _key(root)
    seen = {root}
    frontier = [root]
    for _ in range(depth):
        nxt: list[str] = []
        for a in frontier:
            for b in _sorted(edges.get(a, ())):
                if b not in seen:
                    seen.add(b)
                    nxt.append(b)
        frontier = nxt
    return _sorted(seen)


def bottom_up_layers(edges: Optional[Edges], root: str,
                     depth: int = DEFAULT_CLOSURE_DEPTH) -> list[tuple[str, ...]]:
    """Seçili fonksiyonun kapanışının katmanları (yapraklar önce). Çağrı grafiği yoksa (``None``) yalnız
    kök: komşu bilgisi uydurulmaz."""
    if edges is None:
        _key(root)
        return [(root,)]
    nodes = callee_closure(edges, root, depth)
    return layers(nodes, edges)


def layer_of(layered: Sequence[Sequence[str]]) -> dict[str, int]:
    """Adres → katman numarası."""
    return {a: i for i, layer in enumerate(layered) for a in layer}
