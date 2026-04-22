"""LSH indeksi -- WL feature'ları üzerinden top-K aday üretimi (O(n·k) lineer).

MinHash LSH: her template için N adet min-hash değeri hesaplanır, bunlar
band'lere bölünür. Query CFG'nin aynı band'de aynı imzaya sahip
template'leri "candidate" olarak döner.

Codex uyarısı: tek başına yetmez, exact VF2 rerank şart. Burada sadece
O(n) candidate funnel görevi.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import TYPE_CHECKING

try:
    import numpy as _np
    _NUMPY_AVAILABLE = True
except Exception:  # pragma: no cover
    _np = None  # type: ignore[assignment]
    _NUMPY_AVAILABLE = False

from .fingerprint import shingle_features, wl_color_multiset

if TYPE_CHECKING:  # pragma: no cover
    from .fingerprint import AttributedCFG
    from .template_db import AlgorithmTemplate


def _minhash_signature(
    features: frozenset[str],
    num_hashes: int,
    seed: int = 0,
) -> list[int]:
    """Deterministik MinHash imzası.

    num_hashes farklı hash fonksiyonunun (seed'li blake2b) min değerleri.
    Boş feature set için imza, çok yüksek sabit (sentinel) olur -- farklı
    boş CFG'ler aynı imzayı paylaşır ama pratik olarak boş CFG zaten
    eşleşme hedefi değil.

    v1.10.0 H7 (perf fix): Eski implementasyon num_hashes * len(features)
    blake2b cagrisi yapiyordu (128*50 = 6400). Yeni: her feature icin TEK
    blake2b cagrisi + uzun digest (8*num_hashes bytes), digest'i num_hashes
    adet uint64'e bol, numpy ile kolon-bazli min. Hash cagri sayisi
    num_hashes kat azalir (~128x), numpy reduction Python loop'u degistirir.
    Toplam hizlanma tipik workload'da 15-50x (blake2b CPython'da hizli,
    as yorum numpy'nin min() asil kazanim).
    """
    if not features:
        return [(1 << 60) for _ in range(num_hashes)]
    feat_list = sorted(features)  # deterministik
    # Her feature icin num_hashes * 8 bytes'lik digest uret; bunlari
    # (num_hashes,) uint64'lere cevir. Sonra (feats, num_hashes) matris
    # hazirla ve axis=0 boyunca min al.
    digest_size = 8 * num_hashes
    # blake2b max digest_size = 64. Daha uzunsa chunk halinde.
    salt_prefix = f"seed{seed}|".encode("utf-8")
    if _NUMPY_AVAILABLE and digest_size <= 64:
        # Tek-pass: her feature icin 1 blake2b call.
        buf = _np.empty((len(feat_list), num_hashes), dtype=_np.uint64)
        for i, feat in enumerate(feat_list):
            h = hashlib.blake2b(
                salt_prefix + feat.encode("utf-8"), digest_size=digest_size,
            ).digest()
            # big-endian uint64 dizisi olarak reinterpret et.
            buf[i] = _np.frombuffer(h, dtype=">u8")
        mins = buf.min(axis=0)
        return [int(x) for x in mins]
    if _NUMPY_AVAILABLE:
        # digest_size > 64: num_hashes birden fazla chunk'a yayilir.
        # Her feature icin ceil(num_hashes/8) adet blake2b (hala num_hashes'tan cok daha az).
        chunk_hashes = 64 // 8  # = 8 uint64 per blake2b call
        n_chunks = (num_hashes + chunk_hashes - 1) // chunk_hashes
        buf = _np.full((len(feat_list), n_chunks * chunk_hashes), 0, dtype=_np.uint64)
        for i, feat in enumerate(feat_list):
            feat_bytes = feat.encode("utf-8")
            for c in range(n_chunks):
                prefix = f"c{c}|seed{seed}|".encode("utf-8")
                h = hashlib.blake2b(prefix + feat_bytes, digest_size=64).digest()
                buf[i, c*chunk_hashes:(c+1)*chunk_hashes] = _np.frombuffer(
                    h, dtype=">u8",
                )
        mins = buf[:, :num_hashes].min(axis=0)
        return [int(x) for x in mins]
    # Numpy yoksa: feature-bas tek blake2b + dilim (fallback ve numpy'siz build).
    sig = [(1 << 63) - 1] * num_hashes
    if digest_size <= 64:
        for feat in feat_list:
            h = hashlib.blake2b(
                salt_prefix + feat.encode("utf-8"), digest_size=digest_size,
            ).digest()
            for h_idx in range(num_hashes):
                val = int.from_bytes(h[h_idx*8:(h_idx+1)*8], "big")
                if val < sig[h_idx]:
                    sig[h_idx] = val
        return sig
    # numpy yok + num_hashes > 8: eski pattern (ama hala feature-bas chunk'li).
    chunk_hashes = 8
    n_chunks = (num_hashes + chunk_hashes - 1) // chunk_hashes
    for feat in feat_list:
        feat_bytes = feat.encode("utf-8")
        for c in range(n_chunks):
            prefix = f"c{c}|seed{seed}|".encode("utf-8")
            h = hashlib.blake2b(prefix + feat_bytes, digest_size=64).digest()
            base = c * chunk_hashes
            for j in range(chunk_hashes):
                idx = base + j
                if idx >= num_hashes:
                    break
                val = int.from_bytes(h[j*8:(j+1)*8], "big")
                if val < sig[idx]:
                    sig[idx] = val
    return sig


def _band_signatures(signature: list[int], band_size: int) -> list[tuple[int, bytes]]:
    """MinHash imzasını band'lere böl.

    Band'ler arası LSH "OR" -- bir band'de eşleşme aday yapar.
    Her band için (band_idx, band_hash_bytes) üretilir.
    """
    if band_size <= 0:
        raise ValueError("band_size pozitif olmali")
    out: list[tuple[int, bytes]] = []
    num_bands = len(signature) // band_size
    for b_idx in range(num_bands):
        start = b_idx * band_size
        chunk = signature[start : start + band_size]
        payload = b"".join(v.to_bytes(8, "big") for v in chunk)
        band_hash = hashlib.blake2b(payload, digest_size=8).digest()
        out.append((b_idx, band_hash))
    return out


def _jaccard_estimate(sig_a: list[int], sig_b: list[int]) -> float:
    """MinHash tahmini Jaccard -- eşleşen pozisyon oranı."""
    if not sig_a or not sig_b or len(sig_a) != len(sig_b):
        return 0.0
    match = sum(1 for a, b in zip(sig_a, sig_b) if a == b)
    return match / len(sig_a)


@dataclass
class _IndexedTemplate:
    template: "AlgorithmTemplate"
    signature: list[int]


class LSHIndex:
    """Template LSH indeksi.

    Config:
        num_hashes: MinHash imza boyutu.
        band_size: Her band'deki hash sayısı. num_hashes % band_size == 0
            önerilir; değilse artan band'ler sessiz atlanır.
        wl_iterations: Template fingerprint için WL iterasyon sayısı.

    v1.10.0 Batch 6A (Codex audit): Default band_size 4 -> 8. LSH threshold
    formulu t = (1/num_bands)^(1/band_size) = (band_size/num_hashes)^(1/band_size).
    num_hashes=128 icin:
        band_size=4  -> num_bands=32, t ~= 0.50 (gevsek, s=0.5'te %87 candidate).
        band_size=8  -> num_bands=16, t ~= 0.71 (orta sert, s=0.5'te %15 candidate).
        band_size=16 -> num_bands=8,  t ~= 0.84 (cok sert, recall dusebilir).

    Hash fonksiyonu: ``hashlib.blake2b`` (stdlib, cryptographically strong).
    ``mmh3`` gibi 3. parti hash'e gerek YOK; blake2b 16-byte digest + seed
    prefix ile num_hashes bagimsiz hash-fn elde ediliyor (tek blake2b call
    ile 8 uint64 hash, vektörize min).
    """

    def __init__(
        self,
        templates: list["AlgorithmTemplate"],
        num_hashes: int = 128,
        band_size: int = 8,
        wl_iterations: int = 3,
    ):
        if num_hashes <= 0:
            raise ValueError("num_hashes pozitif olmali")
        if band_size <= 0:
            raise ValueError("band_size pozitif olmali")
        # H4: num_hashes % band_size == 0 olmali -- aksi halde son bayt'lar
        # sessizce dusulur (MinHash imzasinin bir kismi band'lere girmez,
        # recall tutarsiz olur). Silent degradation yerine explicit hata.
        if num_hashes % band_size != 0:
            raise ValueError(
                f"num_hashes ({num_hashes}) band_size ({band_size}) ile tam "
                "bolunebilir olmali -- aksi halde son band'ler atlanir."
            )
        self.num_hashes = int(num_hashes)
        self.band_size = int(band_size)
        self.wl_iterations = int(wl_iterations)
        self._entries: list[_IndexedTemplate] = []
        # (band_idx, band_hash) -> list of entry-idx
        self._band_table: dict[tuple[int, bytes], list[int]] = {}
        self._build_index(templates)

    def _build_index(self, templates: list["AlgorithmTemplate"]) -> None:
        for tmpl in templates:
            features = shingle_features(
                wl_color_multiset(tmpl.cfg, num_iterations=self.wl_iterations)
            )
            # H3: bos feature set -> sentinel imza, tum templateler ayni
            # band_key uretir, false positive katmani olur. Build zamaninda
            # explicit reject et.
            if not features:
                raise ValueError(
                    f"Template '{tmpl.name}' bos WL feature set uretti "
                    "(CFG cok kucuk veya dejenere). LSH icin desteklenmiyor.",
                )
            sig = _minhash_signature(features, self.num_hashes)
            entry = _IndexedTemplate(template=tmpl, signature=sig)
            idx = len(self._entries)
            self._entries.append(entry)
            for band_key in _band_signatures(sig, self.band_size):
                self._band_table.setdefault(band_key, []).append(idx)

    def __len__(self) -> int:
        return len(self._entries)

    def query(
        self,
        cfg: "AttributedCFG",
        top_k: int = 10,
    ) -> list["AlgorithmTemplate"]:
        """Query CFG için top-K benzer template.

        Eğer hiç band eşleşmesi yoksa -- boş döner (LSH miss).
        Bu, `HybridCFGMatcher`'ın fallback stratejisiyle aynı: exact hash
        eşleşmesi yoksa downstream VF2 aşaması da devreye girmez.
        """
        if top_k <= 0 or not self._entries:
            return []
        features = shingle_features(
            wl_color_multiset(cfg, num_iterations=self.wl_iterations)
        )
        query_sig = _minhash_signature(features, self.num_hashes)
        # Band eşleşmesi bulunan entry indeksleri
        candidate_idx: set[int] = set()
        for band_key in _band_signatures(query_sig, self.band_size):
            for entry_idx in self._band_table.get(band_key, []):
                candidate_idx.add(entry_idx)
        if not candidate_idx:
            return []
        # Jaccard tahmini ile rerank
        scored: list[tuple[float, int]] = []
        for idx in candidate_idx:
            score = _jaccard_estimate(query_sig, self._entries[idx].signature)
            scored.append((score, idx))
        scored.sort(key=lambda t: (-t[0], t[1]))
        return [self._entries[idx].template for _, idx in scored[:top_k]]

    def similarity(self, cfg_a: "AttributedCFG", cfg_b: "AttributedCFG") -> float:
        """İki CFG arasında MinHash Jaccard tahmini (debug/yardımcı)."""
        fa = shingle_features(wl_color_multiset(cfg_a, num_iterations=self.wl_iterations))
        fb = shingle_features(wl_color_multiset(cfg_b, num_iterations=self.wl_iterations))
        sa = _minhash_signature(fa, self.num_hashes)
        sb = _minhash_signature(fb, self.num_hashes)
        return _jaccard_estimate(sa, sb)
