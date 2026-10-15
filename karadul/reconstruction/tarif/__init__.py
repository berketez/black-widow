"""Tarif katmanı: özgün ad bulunamadığında fonksiyonun ne yaptığını davranışından anlatan isim.

"Gevşek mod" ölçütü: isim fonksiyonun amacını okuyana yakın doğrulukla anlatıyorsa başarıdır
(seramik duvar → "fayans duvar" doğru, "pencere" yanlış). Deterministik ve LLM'siz.
Plan ve ölçümler: docs/arge/2026-10-15_isimlendirme_plani.md, rehber: docs/arge/etiket_rehberi.md

Kullanım:
    packs = build_evidence(static_dir)
    names = run_tarif(packs, kesin, population)
"""

from __future__ import annotations

from collections.abc import Mapping

from karadul.reconstruction.tarif.evidence import EvidencePack, build_evidence
from karadul.reconstruction.tarif.module import apply_modules
from karadul.reconstruction.tarif.propagate import propagate
from karadul.reconstruction.tarif.rules import Naming, find_logger, name_function

__all__ = ["EvidencePack", "Naming", "build_evidence", "run_tarif"]


def run_tarif(
    packs: Mapping[str, EvidencePack],
    kesin: Mapping[str, str],
    population: set[str],
) -> dict[str, Naming]:
    """İsim bekleyen fonksiyonlara (``population``) kesin + tarif + ipucu isimleri verir.

    ``kesin``: adres → binary'deki kanıttan gelen özgün ad (ör. log'da kendi adını yazan fonksiyon).
    Dönen sözlükte isim alamayan adres yer almaz.
    """
    logger = find_logger(packs)
    names: dict[str, Naming] = {}
    for a in population:
        if a in kesin:
            names[a] = Naming(kesin[a], "kesin:dize", 7.4)
            continue
        p = packs.get(a)
        if p is None:
            continue
        n = name_function(p, packs, kesin, logger)
        if n is not None:
            names[a] = n
    propagate(names, packs, population)
    apply_modules(names, kesin, population)
    return names
