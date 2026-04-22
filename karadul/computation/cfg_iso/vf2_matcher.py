"""VF2 tabanlı subgraph isomorphism wrapper'ı (networkx).

NetworkX ``GraphMatcher``, VF2 algoritmasını uygular. Yeterince küçük
CFG'lerde (<50 node) milisaniye-altı çalışır; LSH'in ürettiği top-K aday
için bu maliyet kabul edilebilir.

NOT: NetworkX içinde "VF2++" ismi altında direct bir scheduler yok; fakat
``GraphMatcher.subgraph_is_isomorphic`` VF2 ile çalışır ve küçük
graflarda pratik olarak yeterli.  Paket ismini ``vf2_matcher`` bıraktık
(API referansıyla uyumlu).

v1.10.0 C1 (perf fix): VF2 NP-complete; büyük/yogun graflarda pipeline'i
sonsuza kilitleyebilir.

v1.10.0 Batch 6A (Codex math audit): Eski thread-based timeout süresi
dolduğunda işi terk ediyor ama VF2 arka planda çalışmaya devam ediyordu
(Python'da interrupt yok). Büyük graflarda kaynak sızıntısı + DoS riski.
Fix: ``multiprocessing.Process`` ile HARD-STOP — timeout sonrası
``terminate()`` + ``kill()`` ile process sonlandırılır, CPU geri alınır.
Ayrıca **node cap**: graph > VF2_NODE_CAP ise direkt atla (LSH/WL yeter).
"""

from __future__ import annotations

import multiprocessing
import os
import threading
from typing import Callable, TYPE_CHECKING

try:
    import networkx as nx
    from networkx.algorithms.isomorphism import DiGraphMatcher
    _NX_AVAILABLE = True
except Exception:  # pragma: no cover - dep yoksa graceful
    nx = None  # type: ignore[assignment]
    DiGraphMatcher = None  # type: ignore[assignment]
    _NX_AVAILABLE = False

if TYPE_CHECKING:  # pragma: no cover
    from .fingerprint import AttributedCFG, CFGNode

# v1.10.0 Batch 6A: Node cap fallback. VF2 > 500 node'da pratik olarak
# saatler surebilir; bu esigin ustunde VF2 atlanir ve LSH+WL sonucuna
# guvenilir. Override icin env ``KARADUL_VF2_NODE_CAP``.
try:
    _VF2_NODE_CAP = int(os.environ.get("KARADUL_VF2_NODE_CAP", "500"))
except ValueError:  # pragma: no cover - env corrupted
    _VF2_NODE_CAP = 500

# Module-level override (test hook + config pass-through):
# ``vf2_matcher._VF2_NODE_CAP = N`` patch edilebilir.


def is_networkx_available() -> bool:
    """NetworkX import edildiyse True. Test ve caller'lar için fallback."""
    return _NX_AVAILABLE


def to_networkx(cfg: "AttributedCFG"):  # -> nx.DiGraph
    """AttributedCFG → networkx DiGraph çevirimi.

    Düğüm attribute'ları: ``mnemonic_histogram``, ``is_entry``, ``is_exit``.
    Edge attribute yok (CFG kenarları tipik olarak unlabelled).
    """
    if not _NX_AVAILABLE:
        raise RuntimeError(
            "networkx kurulu degil -- VF2 kullanimi icin 'pip install networkx' gerekir"
        )
    G = nx.DiGraph()
    for node in cfg.nodes:
        G.add_node(
            node.id,
            mnemonic_histogram=dict(node.mnemonic_histogram),
            is_entry=bool(node.is_entry),
            is_exit=bool(node.is_exit),
        )
    for src, dst in cfg.edges:
        G.add_edge(src, dst)
    return G


def _default_node_match(attrs_a: dict, attrs_b: dict) -> bool:
    """Varsayılan node eşleştirici -- mnemonic histogram "aynı yapı" testi.

    Histogram eşitliği çok katıdır ve gerçek binary'de gürültülü olabilir;
    bu nedenle mnemonic'lerin AYNI *anahtar seti*ni paylaşmasını ve
    sayıların +/- 1 aralığında olmasını istiyoruz. Çok küçük bloklarda
    (1-3 mnemonic) tam eşitlik uygulanır.

    Entry/exit bayrakları eşit olmalı -- topolojik rol farklıysa match
    kabul etmiyoruz (false-positive kesici).
    """
    if bool(attrs_a.get("is_entry")) != bool(attrs_b.get("is_entry")):
        return False
    if bool(attrs_a.get("is_exit")) != bool(attrs_b.get("is_exit")):
        return False
    h_a: dict = attrs_a.get("mnemonic_histogram") or {}
    h_b: dict = attrs_b.get("mnemonic_histogram") or {}
    keys_a = set(h_a.keys())
    keys_b = set(h_b.keys())
    if keys_a != keys_b:
        return False
    total_a = sum(h_a.values())
    total_b = sum(h_b.values())
    # Küçük bloklarda tam eşitlik
    if total_a <= 3 or total_b <= 3:
        return h_a == h_b
    # Orta/büyük: count'lar yakın olsun (tolerans: max(1, %20))
    for key in keys_a:
        va = h_a.get(key, 0)
        vb = h_b.get(key, 0)
        tol = max(1, int(0.2 * max(va, vb)))
        if abs(va - vb) > tol:
            return False
    return True


def vf2_match(
    cfg_a: "AttributedCFG",
    cfg_b: "AttributedCFG",
    node_match_fn: Callable[[dict, dict], bool] | None = None,
) -> bool:
    """cfg_a, cfg_b'nin subgraph izomorfik olup olmadığı.

    cfg_b'nin cfg_a içinde subgraph olarak bulunup bulunmadığını test eder
    (template = cfg_b tipik). Tam eşleşme isteniyorsa ikisi de eşit node
    sayısında verilmelidir -- o zaman ``is_isomorphic()`` kullanılır.

    Args:
        cfg_a: Büyük (host) graf.
        cfg_b: Aranan (pattern) graf.
        node_match_fn: Özel node karşılaştırıcı. None → ``_default_node_match``.

    Returns:
        bool -- izomorfik subgraph var mı.

    Raises:
        RuntimeError: networkx kurulu değilse.
    """
    if not _NX_AVAILABLE:
        raise RuntimeError(
            "networkx kurulu degil -- VF2 kullanimi icin 'pip install networkx' gerekir"
        )
    matcher_fn = node_match_fn or _default_node_match
    G_a = to_networkx(cfg_a)
    G_b = to_networkx(cfg_b)
    if G_a.number_of_nodes() == 0 or G_b.number_of_nodes() == 0:
        return False
    gm = DiGraphMatcher(G_a, G_b, node_match=matcher_fn)
    if G_a.number_of_nodes() == G_b.number_of_nodes():
        if gm.is_isomorphic():
            return True
    return gm.subgraph_is_isomorphic()


def _vf2_worker(queue, nodes_a, edges_a, nodes_b, edges_b) -> None:
    """Multiprocessing VF2 worker -- izole process icinde calisir.

    Sadelestirilmis graph serialize/deserialize: networkx DiGraph'i
    process sinirinda dogrudan pickle etmek yavas, ayrica node_match_fn
    kullanici tarafindan lambda/closure verilirse pickle basarisiz olur.
    Bu yuzden burada DEFAULT matcher'i kullaniyoruz ve node/edge bilgisini
    primitif tuple+dict seklinde gonderiyoruz.
    """
    try:
        import networkx as _nx
        from networkx.algorithms.isomorphism import (
            DiGraphMatcher as _DiGraphMatcher,
        )
        G_a = _nx.DiGraph()
        for node_id, attrs in nodes_a:
            G_a.add_node(node_id, **attrs)
        G_a.add_edges_from(edges_a)
        G_b = _nx.DiGraph()
        for node_id, attrs in nodes_b:
            G_b.add_node(node_id, **attrs)
        G_b.add_edges_from(edges_b)
        gm = _DiGraphMatcher(G_a, G_b, node_match=_default_node_match)
        if G_a.number_of_nodes() == G_b.number_of_nodes():
            if gm.is_isomorphic():
                queue.put(("ok", True))
                return
        queue.put(("ok", bool(gm.subgraph_is_isomorphic())))
    except Exception as exc:  # pragma: no cover
        queue.put(("error", str(exc)))


def _serialize_graph(G) -> tuple[list, list]:
    """DiGraph -> (nodes, edges) primitif liste. Process sinirinda pickle."""
    nodes = [(n, dict(G.nodes[n])) for n in G.nodes]
    edges = list(G.edges)
    return nodes, edges


def vf2_match_with_timeout(
    cfg_a: "AttributedCFG",
    cfg_b: "AttributedCFG",
    node_match_fn: Callable[[dict, dict], bool] | None = None,
    timeout_s: float = 30.0,
) -> tuple[bool, bool]:
    """VF2 subgraph/is_isomorphic kontrolü, HARD-STOP timeout korumasıyla.

    v1.10.0 C1 (eski): thread + daemon join(timeout). Thread arka planda
    ölmez, VF2 aramayı bitirene kadar CPU tüketmeye devam ediyordu.

    v1.10.0 Batch 6A (Codex math audit): ``multiprocessing.Process`` ile
    hard-stop. Timeout dolduysa ``terminate()`` + ``kill()`` ile worker
    sonlandırılır, kaynak sızıntısı olmaz. Ayrıca node cap: graph > cap
    ise VF2 direkt atlanır (LSH+WL yeterli, false-positive kabul).

    GEÇİŞ NOTU: custom ``node_match_fn`` parametre olarak geliyorsa,
    multiprocessing pickle yetersizliğinden dolayi thread-based fallback'a
    düşülür (default matcher ile çalışıldığında multiprocessing kullanılır
    — yaygın durum). Default harici matcher'da eski davranış korunur.

    Args:
        cfg_a: Host CFG.
        cfg_b: Pattern CFG.
        node_match_fn: Özel node karşılaştırıcı. None → default
            (multiprocessing path). Non-default → thread fallback.
        timeout_s: Saniye cinsinden maksimum süre. ``<=0`` → timeout yok.

    Returns:
        ``(matched, timed_out)``.
    """
    if not _NX_AVAILABLE:
        raise RuntimeError(
            "networkx kurulu degil -- VF2 kullanimi icin 'pip install networkx' gerekir"
        )

    G_a = to_networkx(cfg_a)
    G_b = to_networkx(cfg_b)
    if G_a.number_of_nodes() == 0 or G_b.number_of_nodes() == 0:
        return False, False

    # Node cap: buyuk graflar direkt atlansin.
    if (
        G_a.number_of_nodes() > _VF2_NODE_CAP
        or G_b.number_of_nodes() > _VF2_NODE_CAP
    ):
        # Explicit "node-cap skip" isareti yok; caller pipeline'da WL+LSH
        # kullandigindan false return VF2'yi devre disi birakir, LSH
        # sonucu nihai cevap olur. Timed_out=True sinyali caller'a
        # "VF2 atlandi, LSH'e guvenin" diyor.
        return False, True

    # Multiprocessing path (default matcher): HARD-STOP mumkun.
    if node_match_fn is None and timeout_s is not None and timeout_s > 0:
        nodes_a, edges_a = _serialize_graph(G_a)
        nodes_b, edges_b = _serialize_graph(G_b)
        # spawn context: macOS/Linux/Windows uyumlu, fork overhead'den
        # kacinir ve child state izolasyonu saglar.
        ctx = multiprocessing.get_context("spawn")
        queue = ctx.Queue()
        proc = ctx.Process(
            target=_vf2_worker,
            args=(queue, nodes_a, edges_a, nodes_b, edges_b),
            daemon=True,
        )
        try:
            proc.start()
            proc.join(timeout=timeout_s)
            if proc.is_alive():
                # HARD-STOP: terminate -> kill ladder.
                proc.terminate()
                proc.join(1.0)
                if proc.is_alive():  # pragma: no cover - terminate genelde yeter
                    proc.kill()
                    proc.join(1.0)
                return False, True
            try:
                status, result = queue.get_nowait()
            except Exception:
                return False, True
            if status == "ok":
                return bool(result), False
            return False, False  # error path -> no match
        finally:
            try:
                queue.close()
            except Exception:  # pragma: no cover
                pass

    # Thread-fallback (custom matcher veya timeout kapali):
    # custom matcher'i pickle edemeyiz. Eski thread-based semantik korundu
    # ama artik UYARI loglayalim (caller node_match_fn default'ta birakmali).
    matcher_fn = node_match_fn or _default_node_match
    result = [False]

    def _run() -> None:
        try:
            gm = DiGraphMatcher(G_a, G_b, node_match=matcher_fn)
            if G_a.number_of_nodes() == G_b.number_of_nodes():
                if gm.is_isomorphic():
                    result[0] = True
                    return
            result[0] = bool(gm.subgraph_is_isomorphic())
        except Exception:  # pragma: no cover
            result[0] = False

    if timeout_s is None or timeout_s <= 0:
        _run()
        return result[0], False

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    t.join(timeout=timeout_s)
    if t.is_alive():
        # Thread arka planda kalir; custom matcher ile multiprocess desteklenemez.
        return False, True
    return result[0], False


def exact_match_confidence(
    cfg_a: "AttributedCFG",
    cfg_b: "AttributedCFG",
    node_match_fn: Callable[[dict, dict], bool] | None = None,
    timeout_s: float | None = None,
) -> float:
    """Basit exact-match skoru: eşleşme bulundu → 1.0, yoksa 0.0.

    v1.10.0 C1: ``timeout_s`` verilirse ``vf2_match_with_timeout`` kullanilir.
    Timeout olursa 0.0 döner (eşleşme yok kabul).

    İleri sürümlerde *edit distance* bazlı yumuşak skor eklenebilir; bu
    sürümde hibrit matcher zaten MinHash Jaccard ile rank skorunu
    sağlıyor.
    """
    if timeout_s is not None and timeout_s > 0:
        matched, _timed_out = vf2_match_with_timeout(
            cfg_a, cfg_b, node_match_fn, timeout_s=timeout_s,
        )
        return 1.0 if matched else 0.0
    return 1.0 if vf2_match(cfg_a, cfg_b, node_match_fn) else 0.0
