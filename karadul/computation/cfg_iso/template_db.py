"""Elle kurulu algoritma CFG template bank'ı (v1.10.0 M4 beta).

Her template:
    - name: "quicksort", "BFS" vb.
    - family: "sort" | "search" | "graph" | "hashmap" | "memory" | "string"
    - cfg: Tipik control-flow topolojisi + mnemonic histogram (yaklaşık)
    - anchors: Recursion / api_calls / string_refs / flavor flag'leri

Gerçek binary'den çıkarılmış template'ler FAZ 2 (bu sprint değil).

Template CFG'leri kasıtlı olarak "sentetik" — gerçek derlenmiş kodun
blok yapısını *temsil eder*, birebir üretmez. Hybrid pipeline'da exact
eşleşme şu an daha çok "compile edilmemiş iç test fixture"ları için
anlamlı; gerçek binary CFG'lerine karşı LSH Jaccard skoru + anchor
ağırlıklı karar verir.

v1.10.0 Batch 5A: `known_algorithms.json` (310 algoritma) JSON loader
eklendi. Elle kurulmuş 8 template'i bu JSON ile birleştirir.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from .fingerprint import AttributedCFG, CFGNode

logger = logging.getLogger(__name__)


@dataclass
class AlgorithmTemplate:
    """Bir algoritmanın CFG fingerprint'i + anchor tanımları."""
    name: str
    cfg: AttributedCFG
    anchors: dict[str, Any] = field(default_factory=dict)
    family: str = "generic"


def _build_cfg(
    prefix: str,
    blocks: list[tuple[str, dict[str, int]]],
    edges: list[tuple[int, int]],
    entry_idx: int = 0,
    exit_indices: tuple[int, ...] = (-1,),
    api_calls: list[str] | None = None,
    string_refs: list[str] | None = None,
) -> AttributedCFG:
    """Kompakt CFG kurucu: (label, histogram) bloklari + indeks edge'leri.

    Args:
        prefix: Node id prefix'i, benzersiz olmali.
        blocks: (short_label, mnemonic_histogram) listesi.
        edges: (src_idx, dst_idx) tuple listesi (index'ler blocks'a).
        entry_idx: Giris blok indeksi.
        exit_indices: Cikis blok indeksleri (negatif -> sondan).
        api_calls: CFG seviye api cagri listesi (anchor icin).
        string_refs: Literal string referanslar (anchor icin).
    """
    n = len(blocks)
    abs_exit = {(i if i >= 0 else n + i) for i in exit_indices}
    nodes: list[CFGNode] = []
    for i, (label, hist) in enumerate(blocks):
        nodes.append(CFGNode(
            id=f"{prefix}_{label}",
            mnemonic_histogram=dict(hist),
            is_entry=(i == entry_idx),
            is_exit=(i in abs_exit),
        ))
    edge_list = [(nodes[s].id, nodes[d].id) for s, d in edges]
    cfg = AttributedCFG(
        nodes=nodes,
        edges=edge_list,
        api_calls=list(api_calls or []),
        string_refs=list(string_refs or []),
    )
    cfg.recompute_degrees()
    return cfg


def _quicksort_cfg() -> AttributedCFG:
    return _build_cfg(
        "qs",
        [
            ("entry", {"push": 2, "mov": 3, "cmp": 1, "jge": 1}),
            ("init", {"mov": 4, "xor": 1, "cmp": 1}),
            ("loop", {"mov": 3, "cmp": 2, "jl": 1, "jg": 1}),
            ("swap", {"mov": 6, "xchg": 1}),
            ("rec_l", {"call": 1, "mov": 2, "sub": 1}),
            ("rec_r", {"call": 1, "mov": 2, "add": 1}),
            ("ret", {"pop": 2, "ret": 1}),
        ],
        edges=[(0, 1), (0, 6), (1, 2), (2, 3), (3, 2), (2, 4), (4, 5), (5, 6)],
        exit_indices=(6,),
        api_calls=["quicksort"],
    )


def _mergesort_cfg() -> AttributedCFG:
    return _build_cfg(
        "ms",
        [
            ("entry", {"push": 2, "mov": 3, "cmp": 1, "jle": 1}),
            ("mid", {"mov": 3, "add": 1, "shr": 1}),
            ("rec_l", {"call": 1, "mov": 2}),
            ("rec_r", {"call": 1, "mov": 2}),
            ("m_init", {"mov": 4, "xor": 2}),
            ("m_loop", {"mov": 4, "cmp": 2, "jl": 1}),
            ("m_copy", {"mov": 3, "add": 1}),
            ("ret", {"pop": 2, "ret": 1}),
        ],
        edges=[(0, 1), (0, 7), (1, 2), (2, 3), (3, 4), (4, 5), (5, 6), (6, 5), (5, 7)],
        exit_indices=(7,),
        api_calls=["mergesort", "memcpy"],
    )


def _heapsort_cfg() -> AttributedCFG:
    return _build_cfg(
        "hs",
        [
            ("entry", {"push": 2, "mov": 3}),
            ("build", {"mov": 3, "call": 1, "sub": 1}),
            ("sift", {"cmp": 2, "jl": 1, "mov": 3}),
            ("swap", {"mov": 4, "xchg": 1}),
            ("extr", {"mov": 3, "sub": 1}),
            ("ret", {"pop": 2, "ret": 1}),
        ],
        edges=[(0, 1), (1, 2), (2, 3), (3, 2), (2, 4), (4, 2), (4, 5)],
        exit_indices=(5,),
        api_calls=["heapify"],
    )


def _bfs_cfg() -> AttributedCFG:
    return _build_cfg(
        "bfs",
        [
            ("entry", {"push": 2, "mov": 3, "call": 1}),
            ("enq_src", {"mov": 3, "call": 1}),
            ("while", {"test": 1, "jz": 1, "call": 1}),
            ("deq", {"mov": 3, "call": 1}),
            ("for_nb", {"mov": 4, "cmp": 2, "jl": 1}),
            ("mark", {"mov": 3, "or": 1}),
            ("enq_nb", {"mov": 3, "call": 1}),
            ("ret", {"pop": 2, "ret": 1}),
        ],
        edges=[(0, 1), (1, 2), (2, 3), (3, 4), (4, 5), (5, 6), (6, 4), (4, 2), (2, 7)],
        exit_indices=(7,),
        api_calls=["queue_push", "queue_pop", "bfs"],
        string_refs=["bfs", "visited"],
    )


def _dfs_cfg() -> AttributedCFG:
    return _build_cfg(
        "dfs",
        [
            ("entry", {"push": 2, "mov": 3, "test": 1, "jnz": 1}),
            ("mark", {"mov": 3, "or": 1}),
            ("for_nb", {"mov": 4, "cmp": 1, "jl": 1}),
            ("rec", {"call": 1, "mov": 2}),
            ("ret", {"pop": 2, "ret": 1}),
        ],
        edges=[(0, 1), (0, 4), (1, 2), (2, 3), (3, 2), (2, 4)],
        exit_indices=(4,),
        api_calls=["dfs"],
        string_refs=["visited"],
    )


def _hashmap_insert_cfg() -> AttributedCFG:
    return _build_cfg(
        "hm",
        [
            ("entry", {"push": 2, "mov": 3, "call": 1}),
            ("hash", {"mov": 2, "xor": 2, "shl": 1, "and": 1}),
            ("probe", {"mov": 3, "cmp": 2, "je": 1, "jne": 1}),
            ("cmp_k", {"mov": 3, "call": 1, "test": 1, "jz": 1}),
            ("store", {"mov": 4}),
            ("ret", {"pop": 2, "ret": 1}),
        ],
        edges=[(0, 1), (1, 2), (2, 3), (3, 2), (3, 4), (2, 4), (4, 5)],
        exit_indices=(5,),
        api_calls=["hash", "strcmp"],
    )


def _memcpy_cfg() -> AttributedCFG:
    return _build_cfg(
        "mc",
        [
            ("entry", {"push": 1, "mov": 3, "test": 1, "jz": 1}),
            ("check", {"mov": 2, "cmp": 1, "jl": 1}),
            ("loop", {"mov": 3, "add": 2, "dec": 1, "jnz": 1}),
            ("ret", {"pop": 1, "ret": 1}),
        ],
        edges=[(0, 1), (1, 2), (2, 2), (2, 3)],
        exit_indices=(3,),
    )


def _strcmp_cfg() -> AttributedCFG:
    return _build_cfg(
        "sc",
        [
            ("entry", {"push": 1, "mov": 2}),
            ("cmp", {"mov": 2, "cmp": 2, "jne": 1, "test": 1, "jz": 1}),
            ("inc", {"inc": 2, "jmp": 1}),
            ("ret", {"sub": 1, "pop": 1, "ret": 1}),
        ],
        edges=[(0, 1), (1, 2), (2, 1), (1, 3)],
        exit_indices=(3,),
    )


def _builtin_template_bank() -> list[AlgorithmTemplate]:
    """Sprint kapsamındaki varsayılan template seti (8 algoritma).

    FAZ 2'de gerçek binary'den çıkarılmış template'ler eklenecek.
    Her template'in CFG'si bağımsız olarak kurulmuş.
    """
    return [
        AlgorithmTemplate(
            name="quicksort",
            cfg=_quicksort_cfg(),
            anchors={"recursion": True, "swap_pattern": True, "divide_and_conquer": True},
            family="sort",
        ),
        AlgorithmTemplate(
            name="mergesort",
            cfg=_mergesort_cfg(),
            anchors={"recursion": True, "divide_and_conquer": True, "api_calls": ["memcpy"]},
            family="sort",
        ),
        AlgorithmTemplate(
            name="heapsort",
            cfg=_heapsort_cfg(),
            anchors={"swap_pattern": True, "api_calls": ["heapify"]},
            family="sort",
        ),
        AlgorithmTemplate(
            name="BFS",
            cfg=_bfs_cfg(),
            anchors={"api_calls": ["queue_push", "queue_pop", "bfs"], "string_refs": ["bfs"]},
            family="graph",
        ),
        AlgorithmTemplate(
            name="DFS",
            cfg=_dfs_cfg(),
            anchors={"recursion": True, "api_calls": ["dfs"]},
            family="graph",
        ),
        AlgorithmTemplate(
            name="hashmap_insert",
            cfg=_hashmap_insert_cfg(),
            anchors={"api_calls": ["hash", "strcmp"], "probe_loop": True},
            family="hashmap",
        ),
        AlgorithmTemplate(
            name="memcpy",
            cfg=_memcpy_cfg(),
            anchors={"copy_pattern": True},
            family="memory",
        ),
        AlgorithmTemplate(
            name="strcmp",
            cfg=_strcmp_cfg(),
            anchors={"string_refs": ["strcmp"]},
            family="string",
        ),
    ]


# ---------------------------------------------------------------------------
# v1.10.0 Batch 5A: JSON tabanli template loader
# ---------------------------------------------------------------------------

# `reconstruction/recovery_layers/templates/known_algorithms.json` formati:
# [
#   {
#     "name": "bubble_sort",
#     "category": "sorting",
#     "fingerprint": [24 float — heuristic statistics],
#     "structure_hash": "wl_bsort_0001",
#     "description": "...",
#     "expected_params": {"arr": "void*", "n": "int"},
#     "expected_return": "void"
#   },
#   ...
# ]
# Bu formatta ATTRIBUTED CFG YOK -- sadece "fingerprint" (24 heuristic)
# var. Bu sebeple JSON'dan gercek attributed CFG REKONSTRUKSIYONU mumkun
# degil. Yaklasim: her JSON entry'si icin yapay bir CFG olustur, fingerprint
# hash'i anchor olarak kullan. Boylece LSH query'de match yapar ama VF2
# exact match sentetik CFG'ye karsi.

_DEFAULT_JSON_PATH = (
    Path(__file__).resolve().parent.parent.parent
    / "reconstruction"
    / "recovery_layers"
    / "templates"
    / "known_algorithms.json"
)


def _json_entry_to_template(entry: dict[str, Any]) -> Optional[AlgorithmTemplate]:
    """JSON entry'yi AlgorithmTemplate'e cevir.

    JSON'daki `fingerprint` 24-float statik heuristik — gercek CFG
    topolojisi yok. Bu sebeple sentetik minimal CFG kuruyoruz (entry+exit)
    ve fingerprint'i mnemonic histogramina yazarak hash'e yansitiyoruz.
    Bu tam VF2 matching saglamiyor ama LSH aday uretimi + anchor kontrolu
    icin yeterli.

    Returns:
        AlgorithmTemplate veya None (geçersiz/eksik entry için).
    """
    name = entry.get("name", "")
    if not name:
        return None

    category = entry.get("category", "generic")
    fingerprint = entry.get("fingerprint", [])
    structure_hash = entry.get("structure_hash", "")

    # Fingerprint'ten sentetik bir mnemonic histogram uret.
    # Her float'i bir mnemonic "slot"a atayalim (24 slot -> tipik x86 mnemonic).
    _MNEMONIC_SLOTS = [
        "mov", "cmp", "jmp", "jz", "jnz", "jl", "jg", "je", "jne",
        "call", "ret", "push", "pop", "add", "sub", "and", "or",
        "xor", "shl", "shr", "test", "lea", "nop", "inc",
    ]
    histogram: dict[str, int] = {}
    for idx, val in enumerate(fingerprint[:len(_MNEMONIC_SLOTS)]):
        if not isinstance(val, (int, float)) or val <= 0:
            continue
        mnemonic = _MNEMONIC_SLOTS[idx]
        # Float'i counter'a çevir (0-1 arasi olan degerleri 100 ile carp)
        count = max(1, int(float(val) * 100))
        histogram[mnemonic] = count

    # Minimal CFG: entry -> body -> exit
    entry_node = CFGNode(
        id=f"{name}_entry",
        mnemonic_histogram={},
        is_entry=True,
    )
    body_node = CFGNode(
        id=f"{name}_body",
        mnemonic_histogram=histogram,
    )
    exit_node = CFGNode(
        id=f"{name}_exit",
        mnemonic_histogram={},
        is_exit=True,
    )

    cfg = AttributedCFG(
        nodes=[entry_node, body_node, exit_node],
        edges=[
            (entry_node.id, body_node.id),
            (body_node.id, exit_node.id),
            (body_node.id, body_node.id),  # self-loop (icsel dongu temsilen)
        ],
        api_calls=[],
        string_refs=[structure_hash] if structure_hash else [],
    )
    cfg.recompute_degrees()

    anchors: dict[str, Any] = {
        "category": category,
        "structure_hash": structure_hash,
        "expected_params": entry.get("expected_params", {}),
    }

    return AlgorithmTemplate(
        name=name,
        cfg=cfg,
        anchors=anchors,
        family=category,
    )


def load_from_json(
    json_path: Optional[Path] = None,
) -> list[AlgorithmTemplate]:
    """`known_algorithms.json`'dan template listesi yukle.

    Args:
        json_path: JSON yolu. None ise varsayilan
            `reconstruction/recovery_layers/templates/known_algorithms.json`.

    Returns:
        AlgorithmTemplate listesi. Hata durumunda bos liste + log uyarisi.
    """
    path = Path(json_path) if json_path else _DEFAULT_JSON_PATH
    if not path.exists():
        logger.warning("known_algorithms.json bulunamadi: %s", path)
        return []

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        logger.error("JSON parse hatasi (%s): %s", path, exc)
        return []

    if not isinstance(data, list):
        logger.error("JSON root list olmali, %s geldi", type(data).__name__)
        return []

    templates: list[AlgorithmTemplate] = []
    for entry in data:
        if not isinstance(entry, dict):
            continue
        tmpl = _json_entry_to_template(entry)
        if tmpl is not None:
            templates.append(tmpl)

    logger.info("JSON'dan %d template yuklendi: %s", len(templates), path.name)
    return templates


def default_template_bank(
    *,
    include_json: bool = True,
    json_path: Optional[Path] = None,
) -> list[AlgorithmTemplate]:
    """Varsayilan template bank = elle yazilan 8 + JSON'daki 310.

    Args:
        include_json: JSON yuklemesini atla (test/benchmark icin).
        json_path: Alternative JSON yolu.

    Returns:
        Birlesik template listesi. JSON hata verirse sadece 8 builtin
        dondurulur.
    """
    bank = _builtin_template_bank()
    if include_json:
        json_templates = load_from_json(json_path)
        # Isim cakismalari: builtin oncelikli, JSON sadece eksik olanlari ekler.
        builtin_names = {t.name for t in bank}
        for tmpl in json_templates:
            if tmpl.name not in builtin_names:
                bank.append(tmpl)
                builtin_names.add(tmpl.name)
    return bank
