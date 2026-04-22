"""Access pattern -> aday struct layout sentezleyici.

Heuristikler (sirayla):
    1. **Consecutive offsets with matching width**: Ardisik offset'ler
       uzun bir alan haritasi olusturur. Ornek: offset 0/4/8, width 4
       -> 3 alanli struct (0:4, 4:4, 8:4), size 12.
    2. **Max-offset + width -> size**: Gorulen en buyuk offset+width,
       struct boyutunun alt sinirini verir. 4/8/16 bayt alignment'a
       yuvarlanir.
    3. **Power-of-2 aligned size**: Struct tipik olarak 2^n'a yuvarli
       (cache-friendly). Alt sinir uzerine 2. aday uretilir.
    4. **Common stride -> array element candidate**: Hepsi ayni stride
       ile artiyorsa array element (henuz implemente edilmedi, notu
       birakiyor — T25 sonrasi eklenebilir).

Sonuc: `struct_max_candidates` ile sinirli aday listesi. Deterministik
(ayni girdi ayni cikti).

Magic number'lar YOK — tum limitler ComputationConfig'den gelir.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from typing import Optional

from karadul.computation.config import ComputationConfig
from karadul.computation.struct_recovery.types import (
    MemoryAccess,
    StructCandidate,
    StructField,
)

logger = logging.getLogger(__name__)


# Bellek hizalama icin standart sinirlar. Bunlar magic number DEGIL —
# C/C++ ABI gercegi (16/8/4/2/1 bayt align). Konfigurasyon disinda.
_ALIGNMENTS: tuple[int, ...] = (16, 8, 4, 2, 1)


def _round_up(x: int, align: int) -> int:
    if align <= 1:
        return x
    return ((x + align - 1) // align) * align


def _width_to_type_hint(width: int) -> Optional[str]:
    """Width -> genel tip ipucu. Tek basina belirleyici DEGIL."""
    return {1: "int8", 2: "int16", 4: "int32", 8: "int64"}.get(width)


class CandidateSynthesizer:
    """Access pattern'lerinden aday struct layout'lari uretir."""

    def __init__(self, config: Optional[ComputationConfig] = None) -> None:
        self.config = config or ComputationConfig()

    def synthesize(
        self,
        accesses: list[MemoryAccess],
    ) -> list[StructCandidate]:
        """Erisim listesinden aday struct layout'lari.

        Args:
            accesses: Bir alias class'ina ait erisimler. Farkli class'lar
                icin ayri ayri cagrilmalidir (solver aday havuzunu tum
                class'lar icin paylasir ama semantik beklenti budur).

        Returns:
            En fazla ``config.struct_max_candidates`` aday. Bos girdi
            bos liste dondurur.
        """
        if not accesses:
            return []

        # 1) Offset -> max width haritasi. Ayni offset'te farkli width
        # goruluyorsa buyugu secilir (genelde tum alan okunuyor demektir).
        offset_to_width: dict[int, int] = {}
        for a in accesses:
            offset_to_width[a.offset] = max(
                offset_to_width.get(a.offset, 0), a.width,
            )

        offsets_sorted = sorted(offset_to_width.keys())
        max_end = max(o + offset_to_width[o] for o in offsets_sorted)

        candidates: list[StructCandidate] = []

        # --- Heuristik 1 & 2: Direkt alan haritasi ---
        fields_direct: list[StructField] = []
        for off in offsets_sorted:
            w = offset_to_width[off]
            fields_direct.append(
                StructField(offset=off, size=w, type_hint=_width_to_type_hint(w)),
            )

        # Cakisan alanlari temizle (heuristik: kucuk alan buyugun icinde
        # kalirsa, buyugu koru — union duruumlari encoder'da penalize edilir).
        fields_direct = self._drop_subsumed(fields_direct)

        for align in _ALIGNMENTS:
            size = _round_up(max_end, align)
            name = f"cand_direct_a{align}_s{size}"
            try:
                cand = StructCandidate(
                    name=name, size=size, fields=list(fields_direct),
                )
            except ValueError:
                # Alan struct disina tasiyor — bu hizalama uygunsuz.
                continue
            if not any(c.name == cand.name for c in candidates):
                candidates.append(cand)
            if len(candidates) >= self.config.struct_max_candidates:
                return candidates[: self.config.struct_max_candidates]

        # --- Heuristik 3: Power-of-2 boyutlu uber-struct ---
        pow2 = 1
        while pow2 < max_end:
            pow2 *= 2
        if pow2 > max_end and not any(c.size == pow2 for c in candidates):
            try:
                candidates.append(
                    StructCandidate(
                        name=f"cand_pow2_s{pow2}",
                        size=pow2,
                        fields=list(fields_direct),
                    ),
                )
            except ValueError:
                pass

        # --- Heuristik 4: Ortak stride (array element) notu ---
        stride = self._detect_common_stride(offsets_sorted)
        if stride is not None and stride > 0 and stride <= max_end:
            # Tek alanli array element adayi. Stride uygun.
            w = offset_to_width[offsets_sorted[0]]
            try:
                candidates.append(
                    StructCandidate(
                        name=f"cand_stride_{stride}",
                        size=stride,
                        fields=[
                            StructField(
                                offset=0, size=w,
                                type_hint=_width_to_type_hint(w),
                            ),
                        ],
                    ),
                )
            except ValueError as exc:
                # M4: stride-aday insa hatasi yutmak yerine debug'a
                # logla. Genelde width>stride durumu (alan boyut stride'a
                # sigmiyor) — neden sessiz reject ediliyor gorunur olsun.
                logger.debug(
                    "Stride adayi atlandi (stride=%d, w=%d): %s",
                    stride, w, exc,
                )

        return candidates[: self.config.struct_max_candidates]

    @staticmethod
    def _drop_subsumed(fields: list[StructField]) -> list[StructField]:
        """Daha buyuk alan icinde kalan kucukleri at. Ayni offset'te
        buyugu tut. Cakisan ama birbirini icermeyenleri BIRAK (encoder
        bunlari union olarak penalize edecek)."""
        fields_sorted = sorted(fields, key=lambda f: (f.offset, -f.size))
        out: list[StructField] = []
        for fld in fields_sorted:
            subsumed = False
            for kept in out:
                if (kept.offset <= fld.offset and
                        fld.end <= kept.end and
                        (kept.offset, kept.size) != (fld.offset, fld.size)):
                    subsumed = True
                    break
            if not subsumed:
                # Ayni offset+size varsa atla.
                if not any(
                    k.offset == fld.offset and k.size == fld.size for k in out
                ):
                    out.append(fld)
        return sorted(out, key=lambda f: f.offset)

    @staticmethod
    def _detect_common_stride(offsets: list[int]) -> Optional[int]:
        """Eger tum ardisik offset farklari esitse stride dondur.

        Ornek: [0, 16, 32, 48] -> 16. [0, 4, 12] -> None.
        """
        if len(offsets) < 2:
            return None
        diffs = {offsets[i + 1] - offsets[i] for i in range(len(offsets) - 1)}
        if len(diffs) == 1:
            d = next(iter(diffs))
            return d if d > 0 else None
        return None

    def synthesize_per_family(
        self,
        accesses_by_family: dict[str, list[MemoryAccess]],
    ) -> dict[str, list[StructCandidate]]:
        """type_family -> aday struct listesi.

        Solver'in ayni aileye tek aday secmesi icin kullanilir.
        """
        out: dict[str, list[StructCandidate]] = {}
        for family, accs in accesses_by_family.items():
            out[family] = self.synthesize(accs)
        return out


# Modul seviye collector — tum paketlere ortak aday havuzu olusturmak icin.
def collect_accesses_per_family(
    accesses: list[MemoryAccess],
    var_to_family: dict[str, str],
) -> dict[str, list[MemoryAccess]]:
    """Erisimleri type_family bazinda grupla. Aile bilinmeyen var'lar atlanir."""
    out: dict[str, list[MemoryAccess]] = defaultdict(list)
    for a in accesses:
        if a.var_name in var_to_family:
            out[var_to_family[a.var_name]].append(a)
    return dict(out)
