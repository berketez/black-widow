"""Mutasyon-oldurucu testler: field_namer._default_merge Bayesian birlesim.

Faz-1 mutasyon denetimi 3 GERCEK deligi (tam-suite survived) buldu:

  A1  field_namer.py:291  `if len(name_sources[name]) >= 2:`  -> `>= 3:`
  A2  field_namer.py:292  `name_scores[name] *= 1.2`          -> `*= 1.0`
  A3  field_namer.py:286  `... = name_scores.get(...) + c.confidence`
                          -> `= max(name_scores.get(...), c.confidence)`

Tek senaryo ucunu de oldurur: cok-kaynakli bir isim (2 kaynak, her biri 0.4)
capraz-kaynak bonusu (x1.2) ile toplam 0.96'ya cikip tek-kaynakli guclu bir
adayi (0.9) GECMELIDIR. Mutantlarin her biri toplama/bonusu bozar -> secim
tek-kaynakli adaya kayar -> assert patlar (KILLED).

Kanit (mutation_probe, TUM suite'e karsi):
  python scripts/mutation_probe.py --spec docs/mutation_specs.json \
      --id a1_default_merge_source_ge2,a2_default_merge_cross_bonus,\
a3_default_merge_sum_to_max
"""
from __future__ import annotations

from karadul.computation.struct_recovery.field_namer import (
    FieldNameCandidate,
    FieldNamer,
)


def test_default_merge_cross_source_sum_beats_single_strong() -> None:
    """2-kaynakli zayif isim (0.4+0.4=0.8 x1.2=0.96) > 1-kaynakli guclu (0.9).

    Bu tek assert A1/A2/A3 mutantlarinin UCUNU de oldurur:
      * A1 (>=2 -> >=3): 2-kaynak bonusu alamaz -> buf 0.8 < tmp 0.9 -> "tmp"
      * A2 (*1.2 -> *1.0): bonus etkisiz -> buf 0.8 < tmp 0.9 -> "tmp"
      * A3 (topla -> max): buf 0.4x1.2=0.48 < tmp 0.9 -> "tmp"
    Dogru kodda hepsi "buf" verir.
    """
    candidates = [
        # Ayni isim, iki AYRI kaynak, her biri 0.4 -> toplam 0.8, bonusla 0.96.
        FieldNameCandidate(name="buf", confidence=0.4, source="flirt"),
        FieldNameCandidate(name="buf", confidence=0.4, source="struct_context"),
        # Farkli isim, tek kaynak, yuksek guven 0.9.
        FieldNameCandidate(name="tmp", confidence=0.9, source="rtti"),
    ]

    result = FieldNamer._default_merge(candidates)

    assert result == "buf", (
        f"Cok-kaynakli 'buf' (0.4+0.4=0.8 x1.2=0.96) tek-kaynakli 'tmp' (0.9) "
        f"adayini gecmeliydi; donen: {result!r}"
    )


def test_default_merge_single_source_no_bonus_keeps_highest() -> None:
    """Kontrol: TEK kaynakli adaylar arasinda bonus YOK, en yuksek kazanir.

    Bu, bonusun yalnizca cok-kaynakli isimlere uygulandigini kilitler
    (A1/A2 icin ek regresyon guvencesi -- yanlislikla tek-kaynaga bonus
    verilirse 0.5x1.2=0.6 > 0.55 olur, bu senaryo onu yakalamaz ama
    dogru davranisi belgeler).
    """
    candidates = [
        FieldNameCandidate(name="alpha", confidence=0.55, source="flirt"),
        FieldNameCandidate(name="beta", confidence=0.50, source="rtti"),
    ]
    assert FieldNamer._default_merge(candidates) == "alpha"
