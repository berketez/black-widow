"""KARŞI hattı ortak yardımcıları.

Öbür hatların betikleri içe aktarılmaz; Wilson aralığı, belirteçleme ve biçim
normalleştirmesi burada bağımsız yazılmıştır.
"""
from __future__ import annotations

import gzip
import json
import math
import os
import re
from pathlib import Path

ARGE = Path(os.path.expanduser("~/karadul_olcum/runs/arge-2026-11-19"))
OLGU = ARGE / "olgu" / "olgu.jsonl.gz"
VERI = ARGE / "karsi"
TABAN = Path(os.path.expanduser("~/karadul_olcum/runs/urun-onarim-a62f15e"))

Z95 = 1.959963984540054


def wilson(k: int, n: int) -> tuple[float, float, float]:
    """(oran, alt, üst); n == 0 ise (nan, 0, 1)."""
    if n == 0:
        return (float("nan"), 0.0, 1.0)
    p = k / n
    z2 = Z95 * Z95
    payda = 1 + z2 / n
    merkez = (p + z2 / (2 * n)) / payda
    yari = Z95 * math.sqrt(p * (1 - p) / n + z2 / (4 * n * n)) / payda
    return (p, max(0.0, merkez - yari), min(1.0, merkez + yari))


def yaz(k: int, n: int) -> str:
    p, a, u = wilson(k, n)
    if n == 0:
        return f"{k} / {n}"
    return f"{k} / {n} = {p:.3f} [{a:.3f}–{u:.3f}]"


def olgu_oku(alanlar: set[str] | None = None):
    """OLGU tablosunu satır satır verir; alanlar verilirse yalnız onları tutar."""
    with gzip.open(OLGU, "rt", encoding="utf-8") as f:
        for satir in f:
            r = json.loads(satir)
            if alanlar is not None:
                r = {k: r.get(k) for k in alanlar}
            yield r


_KLON = re.compile(r"\.(?:isra|part|constprop|cold|lto_priv|localalias)(?:\.\d+)?")
_CAKISMA = re.compile(r"_\d+$")


def klon_soy(ad: str) -> str:
    """Derleyici ekini (`.isra.0`, `.part.1`, `.constprop.0`, `.cold` …) soyar."""
    return _KLON.sub("", ad)


def bicim_anahtari(ad: str, cakisma_soy: bool = False) -> str:
    """Harf dizisi: baştaki `_` ve derleyici eki soyulur, küçük harf, `_` atılır."""
    a = klon_soy(ad)
    if cakisma_soy:
        a = _CAKISMA.sub("", a)
    return a.replace("_", "").lower()


_PARCA = re.compile(r"[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[A-Z]+|\d+")


def belirtecler(ad: str, rakam: bool = False, en_az: int = 1) -> list[str]:
    """Ad → küçük harfli belirteç listesi (`_`, deve hörgücü, rakam sınırı)."""
    cikti = []
    for parca in re.split(r"[^A-Za-z0-9]+", klon_soy(ad)):
        for m in _PARCA.findall(parca):
            if m.isdigit() and not rakam:
                continue
            if len(m) < en_az:
                continue
            cikti.append(m.lower())
    return cikti


def f1_kume(a: list[str], b: list[str]) -> float:
    """Küme düzeyi belirteç F1'i (yineleme ve sıra duyarsız)."""
    sa, sb = set(a), set(b)
    if not sa or not sb:
        return 0.0
    ortak = len(sa & sb)
    if ortak == 0:
        return 0.0
    p = ortak / len(sa)
    r = ortak / len(sb)
    return 2 * p * r / (p + r)


def program(birim: str) -> str:
    return birim.split("/", 1)[1]
