"""Attributed CFG dataclass + Weisfeiler-Lehman hash fingerprint.

WL hash, iterasyonel olarak her node'un rengini komşularının ve kendi
niteliklerinin (mnemonic histogram) fonksiyonu olarak günceller.
İzomorfik grafikler (attribute uyumu dahil) aynı hash'i döndürür; zayıf
bir kanonik form değildir (WL'nin bilinen sınırı) ama uygulamamızda LSH
aday üretimi için yeterli.

Determinizm kritik -- tüm hash girdileri sırayı koruyarak seri-hale
getirilir, blake2b (stdlib) 16-byte digest kullanılır.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Iterable


def _stable_histogram_repr(histogram: dict[str, int]) -> str:
    """Mnemonic histogram'ı deterministik string'e çevir (sorted-keys)."""
    if not histogram:
        return ""
    items = sorted(histogram.items())
    return ";".join(f"{k}:{v}" for k, v in items)


@dataclass
class CFGNode:
    """Atribütlü CFG düğümü.

    Attributes:
        id: Benzersiz düğüm kimliği (örn. ``"bb_0x1000"``).
        mnemonic_histogram: Temel bloktaki mnemonic sayımları, örn.
            ``{"mov": 5, "cmp": 2, "jmp": 1}``.
        in_degree: Gelen kenar sayısı (grafik oluşturulurken doldurulur).
        out_degree: Giden kenar sayısı.
        is_entry: Fonksiyon entry block mu.
        is_exit: Fonksiyon exit/return block mu.
    """
    id: str
    mnemonic_histogram: dict[str, int] = field(default_factory=dict)
    in_degree: int = 0
    out_degree: int = 0
    is_entry: bool = False
    is_exit: bool = False

    def initial_color(self) -> str:
        """WL iterasyon 0 rengi -- sadece node'un kendi nitelikleri.

        Kenar/derece bilgisi iterasyonda komşulardan gelir; bu seviyede
        yalnızca "intrinsic" özellikler kullanılır.
        """
        hist = _stable_histogram_repr(self.mnemonic_histogram)
        flags = f"e={int(self.is_entry)};x={int(self.is_exit)}"
        return f"hist=[{hist}]|{flags}"


@dataclass
class AttributedCFG:
    """Atribütlü kontrol akış grafiği.

    Attributes:
        nodes: CFGNode listesi. id'ler benzersiz olmalı.
        edges: ``(src_id, dst_id)`` kenar listesi (yönlü).
        api_calls: Fonksiyon içinde çağrılan API/lib isimleri (anchor için).
        string_refs: Literal string referansları (anchor için).
    """
    nodes: list[CFGNode] = field(default_factory=list)
    edges: list[tuple[str, str]] = field(default_factory=list)
    api_calls: list[str] = field(default_factory=list)
    string_refs: list[str] = field(default_factory=list)

    def node_count(self) -> int:
        return len(self.nodes)

    def edge_count(self) -> int:
        return len(self.edges)

    def build_adjacency(self) -> tuple[dict[str, list[str]], dict[str, list[str]]]:
        """Komşuluk sözlükleri -- (out_neighbors, in_neighbors).

        Kendi kendine kenar ve duplicate edge'ler korunur (WL input'u
        olarak multiset semantiği önemli).
        """
        out_map: dict[str, list[str]] = {n.id: [] for n in self.nodes}
        in_map: dict[str, list[str]] = {n.id: [] for n in self.nodes}
        known = set(out_map.keys())
        for src, dst in self.edges:
            if src in known and dst in known:
                out_map[src].append(dst)
                in_map[dst].append(src)
        return out_map, in_map

    def recompute_degrees(self) -> None:
        """Kenar listesinden in_degree/out_degree'yi yeniden hesapla."""
        out_map, in_map = self.build_adjacency()
        for n in self.nodes:
            n.out_degree = len(out_map.get(n.id, []))
            n.in_degree = len(in_map.get(n.id, []))


def _blake2b_16(payload: str) -> str:
    """Stable 16-byte blake2b hex digest (deterministik)."""
    h = hashlib.blake2b(payload.encode("utf-8"), digest_size=16)
    return h.hexdigest()


def _hash_color(payload: str) -> str:
    """WL renk string'i için kısa blake2b (8 byte → 16 hex karakter).

    Kısa tutma amacı: iteratif renkler birbirinin içine girmesin, payload
    patlamasın.
    """
    h = hashlib.blake2b(payload.encode("utf-8"), digest_size=8)
    return h.hexdigest()


def _wl_iterate(
    colors: dict[str, str],
    out_map: dict[str, list[str]],
    in_map: dict[str, list[str]],
    mnemonic_by_id: dict[str, str],
) -> dict[str, str]:
    """Tek bir WL iterasyonu: her node için yeni renk hesapla.

    Formül:
        new_color(v) = hash(
            current_color(v),
            sorted(colors of out-neighbors),
            sorted(colors of in-neighbors),
            mnemonic_histogram(v),
        )

    Yönlü CFG için in ve out komşuları ayrı ele alınır (bilgi korumak için).
    """
    new_colors: dict[str, str] = {}
    for node_id, current in colors.items():
        out_colors = sorted(colors[nb] for nb in out_map.get(node_id, []))
        in_colors = sorted(colors[nb] for nb in in_map.get(node_id, []))
        payload = (
            f"c={current}|"
            f"out=[{','.join(out_colors)}]|"
            f"in=[{','.join(in_colors)}]|"
            f"mn={mnemonic_by_id.get(node_id, '')}"
        )
        new_colors[node_id] = _hash_color(payload)
    return new_colors


def weisfeiler_lehman_hash(
    cfg: AttributedCFG,
    num_iterations: int = 3,
) -> str:
    """Atribütlü WL hash -- deterministik graf parmak izi.

    İzomorfik (node-attribute uyumlu) grafikler aynı hash'i döner. Farklı
    grafikler ~1/2^128 kolizyon olasılığıyla farklı hash'e gider (blake2b
    16-byte).

    Args:
        cfg: Giriş grafiği.
        num_iterations: WL iterasyon sayısı. Pratik olarak 3 küçük-orta
            CFG'ler için yeterli; büyütmek ayırt ediciliği artırır ama
            maliyeti lineerdir.

    Returns:
        32 karakterlik hex string (16-byte blake2b digest).
    """
    if cfg.node_count() == 0:
        return _blake2b_16("empty")

    out_map, in_map = cfg.build_adjacency()
    mnemonic_by_id = {n.id: _stable_histogram_repr(n.mnemonic_histogram) for n in cfg.nodes}
    # Iterasyon 0: intrinsic node color
    colors: dict[str, str] = {n.id: _hash_color(n.initial_color()) for n in cfg.nodes}
    for _ in range(max(0, int(num_iterations))):
        colors = _wl_iterate(colors, out_map, in_map, mnemonic_by_id)

    # Nihai: tüm color'ların sorted multiset'i → tek hash
    final_multiset = sorted(colors.values())
    payload = "|".join(final_multiset) + f"|n={cfg.node_count()}|e={cfg.edge_count()}"
    return _blake2b_16(payload)


def wl_color_multiset(
    cfg: AttributedCFG,
    num_iterations: int = 3,
) -> list[str]:
    """WL son renk multiset'i -- LSH için MinHash girdisi.

    Aynı multiset → aynı hash; ama multiset seviyesinde Jaccard similarity
    hesaplanabilir.
    """
    if cfg.node_count() == 0:
        return []
    out_map, in_map = cfg.build_adjacency()
    mnemonic_by_id = {n.id: _stable_histogram_repr(n.mnemonic_histogram) for n in cfg.nodes}
    colors: dict[str, str] = {n.id: _hash_color(n.initial_color()) for n in cfg.nodes}
    for _ in range(max(0, int(num_iterations))):
        colors = _wl_iterate(colors, out_map, in_map, mnemonic_by_id)
    return sorted(colors.values())


def shingle_features(multiset: Iterable[str]) -> frozenset[str]:
    """MinHash için "shingle" -- multiset elemanları featuretir.

    Multiset olduğu için çift geçen rengi tek feature sayıyoruz; LSH
    Jaccard benzerlik için bu yeterli (MinHash'in standart semantiği).
    """
    return frozenset(multiset)
