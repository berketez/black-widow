"""v1.6.5: GPU device yonetimi ve tensor islemleri.

Tek noktadan device secimi. cfg_fingerprint ve signature_fusion
bu modulu kullanir.

Torch opsiyonel: yuklu degilse tum fonksiyonlar CPU fallback dondurur.
Import sirasinda hata vermez.
"""

from __future__ import annotations

import logging
import math
from typing import Any, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Lazy torch import -- torch yoksa _torch = None, hata yok
# ---------------------------------------------------------------------------
_torch: Any = None
_torch_import_attempted: bool = False


def _ensure_torch() -> Any:
    """Torch'u lazy yukle. Yuklu degilse None dondur."""
    global _torch, _torch_import_attempted
    if _torch_import_attempted:
        return _torch
    _torch_import_attempted = True
    try:
        import torch
        _torch = torch
    except ImportError:
        _torch = None
        logger.debug("torch yuklu degil, GPU islemleri devre disi")
    return _torch


# ---------------------------------------------------------------------------
# Device cache -- ilk cagri detect eder, sonrakiler cache'den alir
# ---------------------------------------------------------------------------
_cached_device: Optional[tuple[str, Any]] = None


def get_device(preference: str = "auto") -> tuple[str, Any]:
    """GPU device sec.

    Args:
        preference: "auto", "mps", "cuda", "cpu".
            "auto" sirasyla MPS > CUDA > CPU dener.

    Returns:
        (device_name, torch_device_or_None) tuple.
        torch yuklu degilse ("cpu", None) doner.
    """
    global _cached_device

    # Cache hit -- ayni preference icin tekrar detect etme
    if _cached_device is not None:
        return _cached_device

    torch = _ensure_torch()
    if torch is None:
        result = ("cpu", None)
        _cached_device = result
        logger.info("GPU device: cpu (torch yuklu degil)")
        return result

    if preference == "cpu":
        device = torch.device("cpu")
        result = ("cpu", device)
        _cached_device = result
        logger.info("GPU device: cpu (kullanici tercihi)")
        return result

    if preference == "mps":
        if hasattr(torch.backends, "mps") and torch.backends.mps.is_available():
            device = torch.device("mps")
            result = ("mps", device)
        else:
            logger.warning("MPS istendi ama kullanilabilir degil, CPU'ya donuluyor")
            device = torch.device("cpu")
            result = ("cpu", device)
        _cached_device = result
        logger.info("GPU device: %s", result[0])
        return result

    if preference == "cuda":
        if torch.cuda.is_available():
            device = torch.device("cuda")
            result = ("cuda", device)
        else:
            logger.warning("CUDA istendi ama kullanilabilir degil, CPU'ya donuluyor")
            device = torch.device("cpu")
            result = ("cpu", device)
        _cached_device = result
        logger.info("GPU device: %s", result[0])
        return result

    # auto: MPS > CUDA > CPU
    if hasattr(torch.backends, "mps") and torch.backends.mps.is_available():
        device = torch.device("mps")
        result = ("mps", device)
    elif torch.cuda.is_available():
        device = torch.device("cuda")
        result = ("cuda", device)
    else:
        device = torch.device("cpu")
        result = ("cpu", device)

    _cached_device = result
    logger.info("GPU device: %s (auto-detect)", result[0])
    return result


def reset_device_cache() -> None:
    """Device cache'ini sifirla. Test'lerde kullanilir."""
    global _cached_device
    _cached_device = None


def is_gpu_available() -> bool:
    """GPU (MPS veya CUDA) kullanilabilir mi?

    Torch yuklu degilse False doner.
    """
    torch = _ensure_torch()
    if torch is None:
        return False
    mps_ok = hasattr(torch.backends, "mps") and torch.backends.mps.is_available()
    cuda_ok = torch.cuda.is_available()
    return mps_ok or cuda_ok


# ---------------------------------------------------------------------------
# Tensor islemleri -- torch yoksa None / pure-Python fallback
# ---------------------------------------------------------------------------

def to_tensor(
    data: list[list[float]],
    device: Any = None,
) -> Any:
    """Python nested list -> torch.FloatTensor.

    Args:
        data: (N, D) boyutunda nested list.
        device: torch.device veya None (auto-detect).

    Returns:
        torch.Tensor veya None (torch yuklu degilse).
    """
    torch = _ensure_torch()
    if torch is None:
        return None
    if device is None:
        _, device = get_device()
    if device is None:
        return None
    return torch.tensor(data, dtype=torch.float32, device=device)


def batch_cosine_similarity(
    a_matrix: Any,
    b_matrix: Any,
    device: Any = None,
) -> Any:
    """(N,D) x (M,D) -> (N,M) cosine similarity matrix.

    GPU varsa torch ile, yoksa pure Python ile hesaplar.

    Args:
        a_matrix: (N, D) tensor veya nested list.
        b_matrix: (M, D) tensor veya nested list.
        device: torch.device veya None.

    Returns:
        torch.Tensor (N, M) veya list[list[float]] (torch yoksa).
    """
    torch = _ensure_torch()

    if torch is not None:
        # Torch path
        if device is None:
            _, device = get_device()

        if not isinstance(a_matrix, torch.Tensor):
            a_matrix = torch.tensor(a_matrix, dtype=torch.float32, device=device)
        if not isinstance(b_matrix, torch.Tensor):
            b_matrix = torch.tensor(b_matrix, dtype=torch.float32, device=device)

        # Ayni device'a tasi
        if device is not None:
            a_matrix = a_matrix.to(device)
            b_matrix = b_matrix.to(device)

        # L2 normalize
        a_norm = torch.nn.functional.normalize(a_matrix, p=2, dim=1)
        b_norm = torch.nn.functional.normalize(b_matrix, p=2, dim=1)

        # Cosine similarity: (N,D) @ (D,M) -> (N,M)
        return torch.mm(a_norm, b_norm.t())

    # Pure Python fallback
    return _cosine_similarity_python(a_matrix, b_matrix)


def _cosine_similarity_python(
    a: list[list[float]],
    b: list[list[float]],
) -> list[list[float]]:
    """Pure Python cosine similarity. Torch yokken fallback."""

    def _norm(vec: list[float]) -> float:
        return math.sqrt(sum(x * x for x in vec))

    def _dot(v1: list[float], v2: list[float]) -> float:
        return sum(x * y for x, y in zip(v1, v2))

    result: list[list[float]] = []
    a_norms = [_norm(row) for row in a]
    b_norms = [_norm(row) for row in b]

    for i, a_row in enumerate(a):
        row_sim: list[float] = []
        an = a_norms[i]
        for j, b_row in enumerate(b):
            bn = b_norms[j]
            if an == 0.0 or bn == 0.0:
                row_sim.append(0.0)
            else:
                row_sim.append(_dot(a_row, b_row) / (an * bn))
        result.append(row_sim)
    return result


def sparse_adjacency(
    edges: dict[str, list[str]],
    node_index: dict[str, int],
    device: Any = None,
) -> Any:
    """Call graph'ten sparse adjacency matrix olustur.

    Args:
        edges: {caller: [callee, ...]} seklinde kenar listesi.
        node_index: {node_name: index} seklinde node -> int esleme.
        device: torch.device veya None.

    Returns:
        torch sparse tensor (N, N) veya None (torch yoksa / MPS ise).
        MPS sparse desteklemiyor, bu durumda CPU'ya tasir veya None doner.
    """
    torch = _ensure_torch()
    if torch is None:
        return None

    if device is None:
        _, device = get_device()

    n = len(node_index)
    if n == 0:
        return None

    # Kenar listesi olustur
    row_indices: list[int] = []
    col_indices: list[int] = []
    for src, targets in edges.items():
        src_idx = node_index.get(src)
        if src_idx is None:
            continue
        for tgt in targets:
            tgt_idx = node_index.get(tgt)
            if tgt_idx is None:
                continue
            row_indices.append(src_idx)
            col_indices.append(tgt_idx)

    if not row_indices:
        # Kenar yok, bos sparse tensor dondur (CPU'da)
        indices = torch.zeros((2, 0), dtype=torch.long)
        values = torch.zeros(0, dtype=torch.float32)
        return torch.sparse_coo_tensor(indices, values, (n, n))

    indices = torch.tensor([row_indices, col_indices], dtype=torch.long)
    values = torch.ones(len(row_indices), dtype=torch.float32)

    # MPS sparse tensor desteklemiyor -- CPU'da olustur
    device_name, _ = get_device()
    if device_name == "mps":
        logger.debug(
            "MPS sparse tensor desteklemiyor, adjacency CPU'da olusturuluyor "
            "(dense islemler icin .to_dense().to('mps') kullanin)"
        )
        return torch.sparse_coo_tensor(indices, values, (n, n)).coalesce()

    # CUDA veya CPU -- device'a tasi
    sparse = torch.sparse_coo_tensor(indices, values, (n, n))
    if device is not None:
        sparse = sparse.to(device)
    return sparse.coalesce()
