#!/usr/bin/env python3
"""Ad biçimi düzeyi: tam eşitliğin yanında "yalnız biçim farkı" hükmü (ÖLÇÜ planı P-Ö1).

Rubrik sürüm 2'nin ``tam`` tanımının mekanik karşılığıdır: ürün adı GT adlarından biriyle harf
dizisi olarak aynıysa (büyük / küçük harf, ``_``, derleyici eki, sondaki ``_<rakam>`` çakışma eki
dışında fark yoksa) ad "tam + biçim" düzeyinde doğrudur (KARARLAR A-3). İnsan ya da model hükmü
gerektirmez; belirteçlemeden ve sözlükten bağımsızdır.

Üç işlev ``scripts/arge/olcu/olcu.py``'den aynen taşındı (``ek_soy``, ``harf_dizisi``,
``harf_tam``; kaynak sha256 ``b915ece9…``). Derleyici eki ifadesi kopyalanmaz:
``ks1_olc.KLON_EKI_RE`` içe aktarılır (KS-1 ön kaydıyla sabit tanım).

Bu düzey karar ölçütlerine girmez: ``urun_olc.py`` onu yalnız duyarlılık satırı olarak yazar.
"""
from __future__ import annotations

import re
import sys
from functools import lru_cache
from pathlib import Path
from typing import Iterable

_BURASI = Path(__file__).resolve().parent
if str(_BURASI) not in sys.path:
    sys.path.insert(0, str(_BURASI))

from ks1_olc import KLON_EKI_RE  # noqa: E402  (tek tanım; kopyalanmaz)


def ek_soy(ad: str) -> str:
    """Derleyici eklerini soy (birden çok ek art arda olabilir)."""
    cur = ad
    while True:
        yeni = KLON_EKI_RE.sub("", cur)
        if yeni == cur or not yeni:
            return cur
        cur = yeni


@lru_cache(maxsize=None)
def harf_dizisi(ad: str) -> str:
    """Biçimden bağımsız harf dizisi: derleyici eki ve çakışma eki (``_N``) soyulur, küçük harfe çevrilir,
    harf ve rakam dışındaki her şey atılır. Rubrik sürüm 2'nin ``tam`` tanımının mekanik karşılığı
    ("yalnız biçim farkı: alt çizgi, büyük/küçük harf, ``_2`` gibi çakışma eki"); belirteçlemeden
    bağımsızdır (``FSE_buildDTable`` ile ``fse_builddtable`` aynı dizidir)."""
    govde = re.sub(r"_\d+$", "", ek_soy(ad))
    return re.sub(r"[^a-z0-9]", "", govde.lower())


def harf_tam(aday: str, gt_adlari: Iterable[str]) -> bool:
    """Aday, GT adlarından biriyle harf dizisi olarak aynı mı (boş dizi eşleşmez)."""
    h = harf_dizisi(aday)
    return bool(h) and any(h == harf_dizisi(g) for g in gt_adlari)
