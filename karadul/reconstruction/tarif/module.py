"""Adres komşuluğundan modül çıkarımı.

Derleyici ve bağlayıcı bir derleme biriminin fonksiyonlarını ikilide yan yana dizer.
İki güvenilir (kesin) isimli komşunun ortak token öneki, aradaki fonksiyonun modülüdür.
Önek, en az ``MIN_MODULE_COUNT`` kesin ismin paylaştığı bir modül önekine kırpılır
(ör. ``control_write`` → ``control``).

Ölçüm (2026-10-15, tmux): isimsiz fonksiyonların %22'sinde önek bulundu, %96'sı doğru.
Kullanım (ölçüme göre):
  - isimsiz fonksiyona modül ipucu (yorum olarak gösterilir)
  - bağlamsız geri çağrı rolüne önek (``on_timer`` → ``tty_on_timer``)
Log kaynaklı isimlere önek eklenmez: önekli log isimleri %32, öneksizler %49 başarıda kaldı.
"""

from __future__ import annotations

import bisect
from collections import Counter
from collections.abc import Mapping

from karadul.reconstruction.tarif.rules import Naming

MIN_MODULE_COUNT = 3
_ROLE_PREFIXES = ("on_", "compare_for_", "handle_signal")


def module_vocabulary(kesin: Mapping[str, str]) -> set[str]:
    """Kesin isimlerin 1 ve 2 token'lık öneklerinden en az ``MIN_MODULE_COUNT`` kez geçenler."""
    counts: Counter[str] = Counter()
    for name in kesin.values():
        tokens = name.split("_")
        for k in (1, 2):
            if len(tokens) > k:
                counts["_".join(tokens[:k])] += 1
    return {p for p, c in counts.items() if c >= MIN_MODULE_COUNT}


def _common_prefix(x: str, y: str) -> list[str]:
    out = []
    for a, b in zip(x.split("_"), y.split("_")):
        if a != b:
            break
        out.append(a)
    return out


class ModuleLocator:
    """Adresi iki kesin isimli komşunun arasına yerleştirip modül önekini bulur."""

    def __init__(self, kesin: Mapping[str, str]) -> None:
        self._modules = module_vocabulary(kesin)
        self._anchors = sorted((int(a, 16), n) for a, n in kesin.items())
        self._keys = [a for a, _ in self._anchors]

    def module_of(self, address: str) -> str | None:
        i = bisect.bisect_left(self._keys, int(address, 16))
        if not 0 < i < len(self._anchors):
            return None
        cp = _common_prefix(self._anchors[i - 1][1], self._anchors[i][1])
        for k in (2, 1):  # bilinen en uzun modül öneki
            if len(cp) >= k and "_".join(cp[:k]) in self._modules:
                return "_".join(cp[:k])
        return None


def apply_modules(
    names: dict[str, Naming],
    kesin: Mapping[str, str],
    population: set[str],
) -> dict[str, Naming]:
    """Modül önekini ölçümün desteklediği yerlere ekler; ``names`` yerinde güncellenir."""
    locator = ModuleLocator(kesin)
    for a in population:
        if a in kesin:
            continue
        mod = locator.module_of(a)
        if not mod:
            continue
        cur = names.get(a)
        if cur is None:
            names[a] = Naming(mod, "ipucu:modul", 2.0)
        elif cur.name.startswith(_ROLE_PREFIXES):
            names[a] = Naming(f"{mod}_{cur.name}", cur.source + "+modul", cur.score)
    return names
