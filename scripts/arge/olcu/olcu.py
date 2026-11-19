#!/usr/bin/env python3
"""ÖLÇÜ hattı: aday ad benzerliği ölçüleri (belirlenimci; model yok, gömme yok).

Girdi: (aday ad, GT adları). Çıktı: ölçü adı → [0, 1] puan. GT'nin birden çok takma adı varsa
her ölçü için en yüksek puan alınır. Tanımlar ``docs/arge/2026-11-19_mythos/olcu/DEFTER.md`` §3'te
ayar kümesine bakılmadan donduruldu; sözlük ``sozluk.json`` (kaynağı dosyanın ``kaynak`` alanında).

Normalleştirme (``belirtecler``):
  1. derleyici ekleri soyulur (``.isra.N``, ``.constprop.N``, ``.part.N``, ``.cold``, ``.lto_priv.N`` …;
     ifade ``scripts/measurement/ks1_olc.py`` ``KLON_EKI_RE`` ile aynı);
  2. ``_`` ve deve yazımı sınırlarından bölünür (``fooBar`` → foo, bar; ``HTTPServer`` → http, server);
     rakamlar bitişik oldukları harf öbeğinde kalır (``sha256``, ``utf8``);
  3. küçük harfe çevrilir; boş parçalar atılır (baştaki ``_`` böylece düşer: Mach-O);
  4. sondaki salt rakam belirteç atılır (çakışma eki ``_2``; rubrik kural 2).

Sözlüklü eşleşme (``kanon``): hafif kök alma (çoğul ``s``, ``ing``, ``ed``) → kısaltma açılımı →
eşanlam kümesi kimlikleri. İki belirteç, kanon kümeleri kesişiyorsa ya da biri (≥ 4 harf) öbürünün
öneki ise eşleşir. Zıt fiiller hiçbir kümede birleşmez.
"""
from __future__ import annotations

import hashlib
import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Iterable

BURASI = Path(__file__).resolve().parent
SOZLUK_YOLU = BURASI / "sozluk.json"
SOZLUK = json.loads(SOZLUK_YOLU.read_text(encoding="utf-8"))
SOZLUK_SHA256 = hashlib.sha256(SOZLUK_YOLU.read_bytes()).hexdigest()

KLON_EKI_RE = re.compile(r"\.(?:isra|constprop|part|cold|lto_priv|clone|llvm|__uniq)(?:\.\d+)*$")
_DEVE_RE = re.compile(r"[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z0-9]+|[A-Z0-9]+")
AD_ONEK_EN_AZ = 4

_KISALTMA: dict[str, str] = SOZLUK["kisaltma"]
_SINIF: dict[str, set[int]] = {}
for _i, _kume in enumerate(SOZLUK["esanlam"]):
    for _w in _kume:
        _SINIF.setdefault(_w, set()).add(_i)
_GENEL = frozenset(SOZLUK["genel"])
AD_OLCULERI = ("tam", "norm_tam", "P", "R", "F1", "J", "Ps", "Rs", "F1s", "duz", "Pic", "Pz", "F1z", "as0", "as5")
SUREKLI_AD_OLCULERI = tuple(o for o in AD_OLCULERI if o not in ("tam", "norm_tam"))


def ek_soy(ad: str) -> str:
    """Derleyici eklerini soy (birden çok ek art arda olabilir)."""
    cur = ad
    while True:
        yeni = KLON_EKI_RE.sub("", cur)
        if yeni == cur or not yeni:
            return cur
        cur = yeni


@lru_cache(maxsize=None)
def belirtecler(ad: str) -> tuple[str, ...]:
    """Normalleştirilmiş belirteç dizisi (sıra korunur)."""
    parcalar: list[str] = []
    for kisim in re.split(r"[^A-Za-z0-9]+", ek_soy(ad)):
        if kisim:
            parcalar.extend(m.group(0).lower() for m in _DEVE_RE.finditer(kisim))
    if len(parcalar) > 1 and parcalar[-1].isdigit():
        parcalar.pop()
    return tuple(parcalar)


@lru_cache(maxsize=None)
def kok(b: str) -> str:
    """Hafif kök alma: yalnız çekim ekleri (çoğul, -ing, -ed)."""
    if len(b) > 4 and b.endswith("ies"):
        return b[:-3] + "y"
    if len(b) > 5 and b.endswith("ing"):
        return b[:-3]
    if len(b) > 4 and b.endswith("ed") and not b.endswith("eed"):
        return b[:-2]
    if len(b) > 3 and b.endswith("s") and not b.endswith(("ss", "us", "is")):
        return b[:-1]
    return b


@lru_cache(maxsize=None)
def acik(b: str) -> str:
    """Kısaltması açılmış, kökü alınmış belirteç."""
    if b in _KISALTMA:
        return _KISALTMA[b]
    k = kok(b)
    return _KISALTMA.get(k, k)


@lru_cache(maxsize=None)
def kanon(b: str) -> frozenset:
    """Belirtecin kanon kümesi: eşanlam kümesi kimlikleri (varsa) + açık biçim."""
    a = acik(b)
    return frozenset({a} | {f"#{i}" for i in _SINIF.get(a, ())} | {f"#{i}" for i in _SINIF.get(b, ())})


def _zit_kur() -> frozenset:
    ciftler = set()
    for a, b in SOZLUK["zit"]:
        for x in kanon(a):
            for y in kanon(b):
                if x != y:
                    ciftler.add((x, y))
                    ciftler.add((y, x))
    return frozenset(ciftler)


_ZIT = _zit_kur()
_FIIL_KANON = frozenset(k for kume in SOZLUK["esanlam"][:17] + SOZLUK["esanlam"][22:] for w in kume
                        for k in kanon(w) if k.startswith("#")) | frozenset(
    x for a, b in SOZLUK["zit"] for w in (a, b) for x in kanon(w))


def eslesir(a: str, b: str) -> bool:
    """Sözlüklü belirteç eşleşmesi."""
    if a == b or kanon(a) & kanon(b):
        return True
    kisa, uzun = (a, b) if len(a) <= len(b) else (b, a)
    return len(kisa) >= AD_ONEK_EN_AZ and uzun.startswith(kisa) and not kisa.isdigit()


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


def _prf(tp_aday: int, n_aday: int, tp_gt: int, n_gt: int) -> tuple[float, float, float]:
    p = tp_aday / n_aday if n_aday else 0.0
    r = tp_gt / n_gt if n_gt else 0.0
    return p, r, (2 * p * r / (p + r) if p + r else 0.0)


def duzenleme_uzakligi(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a or not b:
        return len(a) or len(b)
    onceki = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        simdi = [i]
        for j, cb in enumerate(b, 1):
            simdi.append(min(onceki[j] + 1, simdi[j - 1] + 1, onceki[j - 1] + (ca != cb)))
        onceki = simdi
    return onceki[-1]


def zit_var(aday: Iterable[str], gt: Iterable[str]) -> bool:
    """Adayda GT'deki bir fiilin zıttı var mı (ve aynı zıt GT'de yok mu)."""
    ka = set().union(*(kanon(t) for t in aday)) if aday else set()
    kg = set().union(*(kanon(t) for t in gt)) if gt else set()
    for x in ka - kg:
        for y in kg - ka:
            if (x, y) in _ZIT:
                return True
    return False


def gt_cekirdegi(gt: tuple[str, ...]) -> list[str]:
    """GT adının amaç taşıyan belirteçleri: sözlükteki fiiller; fiil yoksa son belirteç."""
    fiiller = [t for t in gt if kanon(t) & _FIIL_KANON]
    return fiiller or list(gt[-1:])


def puanla_tek(aday: str, gt: str) -> dict[str, float]:
    ta, tg = belirtecler(aday), belirtecler(gt)
    sa, sg = set(ta), set(tg)
    s: dict[str, float] = {"tam": float(aday == gt), "norm_tam": float(bool(ta) and ta == tg)}
    if not sa or not sg:
        s.update({o: 0.0 for o in SUREKLI_AD_OLCULERI})
        return s
    ortak = sa & sg
    s["P"], s["R"], s["F1"] = _prf(len(ortak), len(sa), len(ortak), len(sg))
    s["J"] = len(ortak) / len(sa | sg)
    es_a = {a for a in sa if any(eslesir(a, g) for g in sg)}
    es_g = {g for g in sg if any(eslesir(a, g) for a in sa)}
    s["Ps"], s["Rs"], s["F1s"] = _prf(len(es_a), len(sa), len(es_g), len(sg))
    ja, jg = "_".join(ta), "_".join(tg)
    s["duz"] = 1.0 - duzenleme_uzakligi(ja, jg) / max(len(ja), len(jg))
    icerikli = {a for a in sa if acik(a) not in _GENEL and a not in _GENEL}
    s["Pic"] = len(icerikli & es_a) / len(icerikli) if icerikli else 0.0
    zit = zit_var(sa, sg)
    s["Pz"] = 0.0 if zit else s["Ps"]
    s["F1z"] = 0.0 if zit else s["F1s"]
    cekirdek = gt_cekirdegi(tg)
    karsilandi = any(eslesir(a, c) for a in sa for c in cekirdek)
    s["as0"] = s["Pz"] if karsilandi else 0.0
    s["as5"] = s["Pz"] if karsilandi else 0.5 * s["Pz"]
    return s


def puanla(aday: str, gt_adlari: Iterable[str]) -> dict[str, float]:
    """GT'nin takma adları üstünde ölçü başına en yüksek puan. GT yoksa hepsi 0."""
    en: dict[str, float] = {o: 0.0 for o in AD_OLCULERI}
    for g in gt_adlari:
        for o, v in puanla_tek(aday, g.lstrip("_") if g.startswith("_") and not g.startswith("__") else g).items():
            if v > en[o]:
                en[o] = v
    return en


if __name__ == "__main__":
    import sys
    print("sozluk sha256", SOZLUK_SHA256)
    for cift in sys.argv[1:]:
        a, g = cift.split("|", 1)
        print(a, g, belirtecler(a), belirtecler(g), {k: round(v, 3) for k, v in puanla(a, [g]).items()})
